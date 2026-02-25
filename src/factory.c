#include "superscalar/factory.h"
#include "superscalar/channel.h"
#include "superscalar/shachain.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void sha256(const unsigned char *, size_t, unsigned char *);
extern void sha256_tagged(const char *, const unsigned char *, size_t,
                           unsigned char *);
extern void reverse_bytes(unsigned char *, size_t);

/* ---- Internal helpers ---- */

/* Compute taproot-tweaked xonly pubkey.
   merkle_root = NULL for key-path only, non-NULL to include script tree. */
static int taproot_tweak_pubkey(
    const secp256k1_context *ctx,
    secp256k1_xonly_pubkey *tweaked_out,
    int *parity_out,
    const secp256k1_xonly_pubkey *internal_key,
    const unsigned char *merkle_root
) {
    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, internal_key))
        return 0;

    unsigned char tweak[32];
    if (merkle_root) {
        /* TapTweak = tagged_hash("TapTweak", internal_key || merkle_root) */
        unsigned char tweak_data[64];
        memcpy(tweak_data, internal_ser, 32);
        memcpy(tweak_data + 32, merkle_root, 32);
        sha256_tagged("TapTweak", tweak_data, 64, tweak);
    } else {
        sha256_tagged("TapTweak", internal_ser, 32, tweak);
    }

    secp256k1_pubkey tweaked_full;
    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked_full, internal_key, tweak))
        return 0;

    int parity = 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, tweaked_out, &parity, &tweaked_full))
        return 0;

    if (parity_out)
        *parity_out = parity;

    return 1;
}

/* Build P2TR spk from a set of pubkeys via MuSig aggregate + taproot tweak.
   merkle_root = NULL for key-path only, non-NULL to include script tree. */
static int build_musig_p2tr_spk(
    const secp256k1_context *ctx,
    unsigned char *spk_out34,
    secp256k1_xonly_pubkey *tweaked_out,
    int *parity_out,
    musig_keyagg_t *keyagg_out,
    const secp256k1_pubkey *pubkeys,
    size_t n_pubkeys,
    const unsigned char *merkle_root
) {
    if (!musig_aggregate_keys(ctx, keyagg_out, pubkeys, n_pubkeys))
        return 0;

    if (!taproot_tweak_pubkey(ctx, tweaked_out, parity_out,
                               &keyagg_out->agg_pubkey, merkle_root))
        return 0;

    build_p2tr_script_pubkey(spk_out34, tweaked_out);
    return 1;
}

/* Build P2TR spk for a single pubkey (no MuSig). */
static int build_single_p2tr_spk(
    const secp256k1_context *ctx,
    unsigned char *spk_out34,
    secp256k1_xonly_pubkey *tweaked_out,
    const secp256k1_pubkey *pubkey
) {
    secp256k1_xonly_pubkey internal;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &internal, NULL, pubkey))
        return 0;

    if (!taproot_tweak_pubkey(ctx, tweaked_out, NULL, &internal, NULL))
        return 0;

    build_p2tr_script_pubkey(spk_out34, tweaked_out);
    return 1;
}

/* Get nSequence for a node based on its type and DW layer.
   When per-leaf mode is enabled, leaf state nodes use their independent
   per-leaf DW layer instead of the global counter. Uses leaf_node_indices[]
   for arity-agnostic lookup. */
static uint32_t node_nsequence(const factory_t *f, const factory_node_t *node) {
    if (node->type == NODE_KICKOFF)
        return NSEQUENCE_DISABLE_BIP68;
    if (f->per_leaf_enabled) {
        int node_idx = (int)(node - f->nodes);
        for (int i = 0; i < f->n_leaf_nodes; i++) {
            if ((int)f->leaf_node_indices[i] == node_idx)
                return dw_current_nsequence(&f->leaf_layers[i]);
        }
    }
    return dw_current_nsequence(&f->counter.layers[node->dw_layer_index]);
}

/* Add a node to the factory. Returns node index or -1 on error.
   node_cltv: if > 0, build CLTV timeout taptree for this node's spending_spk. */
static int add_node(
    factory_t *f,
    factory_node_type_t type,
    const uint32_t *signer_indices,
    size_t n_signers,
    int parent_index,
    uint32_t parent_vout,
    int dw_layer_index,
    uint32_t node_cltv
) {
    if (f->n_nodes >= FACTORY_MAX_NODES) return -1;

    int idx = (int)f->n_nodes++;
    factory_node_t *node = &f->nodes[idx];
    memset(node, 0, sizeof(*node));

    node->type = type;
    node->n_signers = n_signers;
    memcpy(node->signer_indices, signer_indices, n_signers * sizeof(uint32_t));
    node->parent_index = parent_index;
    node->parent_vout = parent_vout;
    node->dw_layer_index = dw_layer_index;
    node->has_taptree = (node_cltv > 0) ? 1 : 0;
    node->cltv_timeout = node_cltv;

    tx_buf_init(&node->unsigned_tx, 256);
    tx_buf_init(&node->signed_tx, 512);

    /* Aggregate keys and compute tweaked pubkey + spending SPK */
    secp256k1_pubkey pks[FACTORY_MAX_SIGNERS];
    for (size_t i = 0; i < n_signers; i++)
        pks[i] = f->pubkeys[signer_indices[i]];

    if (node->has_taptree) {
        /* Build CLTV timeout script leaf using LSP pubkey (index 0) */
        secp256k1_xonly_pubkey lsp_xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(f->ctx, &lsp_xonly, NULL, &f->pubkeys[0]))
            return -1;

        tapscript_build_cltv_timeout(&node->timeout_leaf, node_cltv,
                                      &lsp_xonly, f->ctx);
        tapscript_merkle_root(node->merkle_root, &node->timeout_leaf, 1);

        /* Tweak internal key with merkle root */
        if (!build_musig_p2tr_spk(f->ctx, node->spending_spk, &node->tweaked_pubkey,
                                   &node->output_parity, &node->keyagg, pks, n_signers,
                                   node->merkle_root))
            return -1;
    } else {
        if (!build_musig_p2tr_spk(f->ctx, node->spending_spk, &node->tweaked_pubkey,
                                   NULL, &node->keyagg, pks, n_signers, NULL))
            return -1;
    }

    node->spending_spk_len = 34;

    /* Link to parent */
    if (parent_index >= 0) {
        factory_node_t *parent = &f->nodes[parent_index];
        parent->child_indices[parent->n_children++] = idx;
    }

    return idx;
}

/* Build L-stock scriptPubKey.
   If shachain is enabled: P2TR with key-path = LSP, script-path = hashlock.
   If not: simple P2TR of LSP key. */
static int build_l_stock_spk(const factory_t *f, unsigned char *spk_out34) {
    if (f->has_shachain) {
        /* Get current epoch's shachain secret and compute SHA256 hash */
        uint64_t sc_index = shachain_epoch_to_index(f->counter.current_epoch);
        unsigned char secret[32];
        shachain_from_seed(f->shachain_seed, sc_index, secret);

        unsigned char hash[32];
        sha256(secret, 32, hash);
        memset(secret, 0, 32);

        /* Build hashlock leaf */
        tapscript_leaf_t hashlock_leaf;
        tapscript_build_hashlock(&hashlock_leaf, hash);

        /* Compute merkle root from single leaf */
        unsigned char merkle_root[32];
        tapscript_merkle_root(merkle_root, &hashlock_leaf, 1);

        /* Get LSP's xonly pubkey as internal key */
        secp256k1_xonly_pubkey lsp_internal;
        if (!secp256k1_xonly_pubkey_from_pubkey(f->ctx, &lsp_internal, NULL,
                                                  &f->pubkeys[0]))
            return 0;

        /* Tweak with merkle root */
        secp256k1_xonly_pubkey tweaked;
        if (!tapscript_tweak_pubkey(f->ctx, &tweaked, NULL,
                                     &lsp_internal, merkle_root))
            return 0;

        build_p2tr_script_pubkey(spk_out34, &tweaked);
    } else {
        secp256k1_xonly_pubkey tw;
        if (!build_single_p2tr_spk(f->ctx, spk_out34, &tw, &f->pubkeys[0]))
            return 0;
    }
    return 1;
}

/* Update L-stock outputs on leaf state nodes after epoch change.
   Called by factory_advance() after counter advance.
   L-stock is always the last output of a leaf node. */
static int update_l_stock_outputs(factory_t *f) {
    if (!f->has_shachain)
        return 1;  /* nothing to update */

    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *node = &f->nodes[i];
        /* Leaf state nodes: type == STATE and no children */
        if (node->type != NODE_STATE || node->n_children > 0)
            continue;

        if (node->n_outputs < 2)
            continue;

        /* L-stock is always the last output */
        if (!build_l_stock_spk(f, node->outputs[node->n_outputs - 1].script_pubkey))
            return 0;
    }
    return 1;
}

/* Set up leaf outputs for a leaf state node. */
static int setup_leaf_outputs(
    factory_t *f,
    factory_node_t *node,
    uint32_t client_a_idx,
    uint32_t client_b_idx,
    uint64_t input_amount
) {
    uint64_t output_total = input_amount - f->fee_per_tx;
    uint64_t per_output = output_total / 3;
    uint64_t remainder = output_total - per_output * 3;

    if (per_output < CHANNEL_DUST_LIMIT_SATS) {
        fprintf(stderr, "Factory: output %llu below dust limit\n",
                (unsigned long long)per_output);
        return 0;
    }

    node->n_outputs = 3;

    /* Channel A: MuSig(client_a, LSP) */
    {
        secp256k1_pubkey pks[2] = { f->pubkeys[client_a_idx], f->pubkeys[0] };
        musig_keyagg_t ka;
        secp256k1_xonly_pubkey tw;
        if (!build_musig_p2tr_spk(f->ctx, node->outputs[0].script_pubkey,
                                   &tw, NULL, &ka, pks, 2, NULL))
            return 0;
        node->outputs[0].script_pubkey_len = 34;
        node->outputs[0].amount_sats = per_output;
    }

    /* Channel B: MuSig(client_b, LSP) */
    {
        secp256k1_pubkey pks[2] = { f->pubkeys[client_b_idx], f->pubkeys[0] };
        musig_keyagg_t ka;
        secp256k1_xonly_pubkey tw;
        if (!build_musig_p2tr_spk(f->ctx, node->outputs[1].script_pubkey,
                                   &tw, NULL, &ka, pks, 2, NULL))
            return 0;
        node->outputs[1].script_pubkey_len = 34;
        node->outputs[1].amount_sats = per_output;
    }

    /* L stock: LSP only, optionally with hashlock burn path */
    if (!build_l_stock_spk(f, node->outputs[2].script_pubkey))
        return 0;
    node->outputs[2].script_pubkey_len = 34;
    node->outputs[2].amount_sats = per_output + remainder;

    return 1;
}

/* Build all unsigned transactions top-down. Nodes must be in top-down order. */
static int build_all_unsigned_txs(factory_t *f) {
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *node = &f->nodes[i];
        unsigned char display_txid[32];

        /* Determine input */
        const unsigned char *input_txid;
        uint32_t input_vout;

        if (node->parent_index < 0) {
            input_txid = f->funding_txid;
            input_vout = f->funding_vout;
        } else {
            factory_node_t *parent = &f->nodes[node->parent_index];
            input_txid = parent->txid;  /* internal byte order */
            input_vout = node->parent_vout;
        }

        node->nsequence = node_nsequence(f, node);

        if (!build_unsigned_tx(&node->unsigned_tx, display_txid,
                               input_txid, input_vout,
                               node->nsequence,
                               node->outputs, node->n_outputs))
            return 0;

        /* Convert display-order txid to internal byte order */
        memcpy(node->txid, display_txid, 32);
        reverse_bytes(node->txid, 32);

        node->is_built = 1;
        node->is_signed = 0;
    }
    return 1;
}

/* Compute BIP-341 sighash for a factory node's input. */
static int compute_node_sighash(const factory_t *f, const factory_node_t *node,
                                 unsigned char *sighash_out) {
    const unsigned char *prev_spk;
    size_t prev_spk_len;
    uint64_t prev_amount;

    if (node->parent_index < 0) {
        prev_spk = f->funding_spk;
        prev_spk_len = f->funding_spk_len;
        prev_amount = f->funding_amount_sats;
    } else {
        const factory_node_t *parent = &f->nodes[node->parent_index];
        prev_spk = parent->outputs[node->parent_vout].script_pubkey;
        prev_spk_len = parent->outputs[node->parent_vout].script_pubkey_len;
        prev_amount = parent->outputs[node->parent_vout].amount_sats;
    }

    return compute_taproot_sighash(sighash_out,
                                    node->unsigned_tx.data, node->unsigned_tx.len,
                                    0, prev_spk, prev_spk_len,
                                    prev_amount, node->nsequence);
}

/* ---- Public API ---- */

void factory_init(factory_t *f, secp256k1_context *ctx,
                  const secp256k1_keypair *keypairs, size_t n_participants,
                  uint16_t step_blocks, uint32_t states_per_layer) {
    memset(f, 0, sizeof(*f));
    f->ctx = ctx;
    f->n_participants = n_participants;
    f->step_blocks = step_blocks;
    f->states_per_layer = states_per_layer;
    f->fee_per_tx = 200;  /* 1 sat/vB floor for ~200 vB tx; overridden by factory_build_tree */

    for (size_t i = 0; i < n_participants; i++) {
        int ok;
        f->keypairs[i] = keypairs[i];
        ok = secp256k1_keypair_pub(ctx, &f->pubkeys[i], &keypairs[i]);
        (void)ok;
    }

    /* Default arity-2: 2 DW layers, 2 leaf nodes */
    f->leaf_arity = FACTORY_ARITY_2;
    f->n_leaf_nodes = 2;
    dw_counter_init(&f->counter, 2, step_blocks, states_per_layer);

    /* Per-leaf layers mirror global layer 1 initially */
    for (int i = 0; i < 2; i++)
        dw_layer_init(&f->leaf_layers[i], step_blocks, states_per_layer);
    f->per_leaf_enabled = 0;
}

void factory_init_from_pubkeys(factory_t *f, secp256k1_context *ctx,
                               const secp256k1_pubkey *pubkeys, size_t n_participants,
                               uint16_t step_blocks, uint32_t states_per_layer) {
    memset(f, 0, sizeof(*f));
    f->ctx = ctx;
    f->n_participants = n_participants;
    f->step_blocks = step_blocks;
    f->states_per_layer = states_per_layer;
    f->fee_per_tx = 200;  /* 1 sat/vB floor for ~200 vB tx; overridden by factory_build_tree */

    for (size_t i = 0; i < n_participants; i++)
        f->pubkeys[i] = pubkeys[i];
    /* keypairs left zeroed — signing requires split-round API */

    /* Default arity-2: 2 DW layers, 2 leaf nodes */
    f->leaf_arity = FACTORY_ARITY_2;
    f->n_leaf_nodes = 2;
    dw_counter_init(&f->counter, 2, step_blocks, states_per_layer);

    for (int i = 0; i < 2; i++)
        dw_layer_init(&f->leaf_layers[i], step_blocks, states_per_layer);
    f->per_leaf_enabled = 0;
}

void factory_set_arity(factory_t *f, factory_arity_t arity) {
    f->leaf_arity = arity;
    int n_layers = (arity == FACTORY_ARITY_1) ? 3 : 2;
    dw_counter_init(&f->counter, n_layers, f->step_blocks, f->states_per_layer);
    f->n_leaf_nodes = (arity == FACTORY_ARITY_1) ? 4 : 2;
    for (int i = 0; i < f->n_leaf_nodes; i++)
        dw_layer_init(&f->leaf_layers[i], f->step_blocks, f->states_per_layer);
    f->per_leaf_enabled = 0;
}

void factory_set_funding(factory_t *f,
                         const unsigned char *txid, uint32_t vout,
                         uint64_t amount_sats,
                         const unsigned char *spk, size_t spk_len) {
    memcpy(f->funding_txid, txid, 32);
    f->funding_vout = vout;
    f->funding_amount_sats = amount_sats;
    memcpy(f->funding_spk, spk, spk_len);
    f->funding_spk_len = spk_len;
}

/* Set up single-client leaf outputs: 1 channel + 1 L-stock */
static int setup_single_leaf_outputs(
    factory_t *f,
    factory_node_t *node,
    uint32_t client_idx,
    uint64_t input_amount
) {
    uint64_t output_total = input_amount - f->fee_per_tx;
    uint64_t per_output = output_total / 2;
    uint64_t remainder = output_total - per_output * 2;

    if (per_output < CHANNEL_DUST_LIMIT_SATS) {
        fprintf(stderr, "Factory: single leaf output %llu below dust limit\n",
                (unsigned long long)per_output);
        return 0;
    }

    node->n_outputs = 2;

    /* Channel: MuSig(client, LSP) */
    {
        secp256k1_pubkey pks[2] = { f->pubkeys[client_idx], f->pubkeys[0] };
        musig_keyagg_t ka;
        secp256k1_xonly_pubkey tw;
        if (!build_musig_p2tr_spk(f->ctx, node->outputs[0].script_pubkey,
                                   &tw, NULL, &ka, pks, 2, NULL))
            return 0;
        node->outputs[0].script_pubkey_len = 34;
        node->outputs[0].amount_sats = per_output;
    }

    /* L stock: LSP only, optionally with hashlock burn path */
    if (!build_l_stock_spk(f, node->outputs[1].script_pubkey))
        return 0;
    node->outputs[1].script_pubkey_len = 34;
    node->outputs[1].amount_sats = per_output + remainder;

    return 1;
}

static int factory_build_tree_arity2(factory_t *f) {
    /* Participant indices: LSP=0, A=1, B=2, C=3, D=4 */
    uint32_t all[] = {0, 1, 2, 3, 4};
    uint32_t left_set[] = {0, 1, 2};       /* L, A, B */
    uint32_t right_set[] = {0, 3, 4};      /* L, C, D */

    /* ---- Phase 1: Setup nodes (top-down order) ---- */
    /* Staggered CLTVs: leaves expire first, root last.
       TIMEOUT_STEP_BLOCKS between levels. */
#define TIMEOUT_STEP_BLOCKS 5
    uint32_t cltv = f->cltv_timeout;
    uint32_t step = TIMEOUT_STEP_BLOCKS;
    uint32_t root_cltv = cltv;                           /* longest */
    uint32_t mid_cltv  = (cltv > step) ? cltv - step : 0;
    uint32_t leaf_cltv = (cltv > 2*step) ? cltv - 2*step : 0;

    int kr  = add_node(f, NODE_KICKOFF, all, 5,        -1, 0, -1, 0);          /* no timeout */
    int sr  = add_node(f, NODE_STATE,   all, 5,        kr, 0,  0, root_cltv);  /* longest */
    int kl  = add_node(f, NODE_KICKOFF, left_set, 3,   sr, 0, -1, mid_cltv);   /* mid */
    int kri = add_node(f, NODE_KICKOFF, right_set, 3,  sr, 1, -1, mid_cltv);   /* mid */
    int sl  = add_node(f, NODE_STATE,   left_set, 3,   kl, 0,  1, leaf_cltv);  /* shortest */
    int sri = add_node(f, NODE_STATE,   right_set, 3, kri, 0,  1, leaf_cltv);  /* shortest */

    if (kr < 0 || sr < 0 || kl < 0 || kri < 0 || sl < 0 || sri < 0)
        return 0;

    /* Record leaf node indices */
    f->leaf_node_indices[0] = (size_t)sl;
    f->leaf_node_indices[1] = (size_t)sri;

    /* ---- Phase 2: Setup outputs and amounts ---- */
    uint64_t fee = f->fee_per_tx;
    uint64_t kr_out = f->funding_amount_sats - fee;
    uint64_t sr_per_child = (kr_out - fee) / 2;
    uint64_t kl_out = sr_per_child - fee;
    uint64_t kri_out = sr_per_child - fee;

    /* kickoff_root -> 1 output: state_root */
    f->nodes[kr].n_outputs = 1;
    f->nodes[kr].outputs[0].amount_sats = kr_out;
    memcpy(f->nodes[kr].outputs[0].script_pubkey, f->nodes[sr].spending_spk, 34);
    f->nodes[kr].outputs[0].script_pubkey_len = 34;
    f->nodes[kr].input_amount = f->funding_amount_sats;

    /* state_root -> 2 outputs: kickoff_left, kickoff_right */
    f->nodes[sr].n_outputs = 2;
    f->nodes[sr].outputs[0].amount_sats = sr_per_child;
    memcpy(f->nodes[sr].outputs[0].script_pubkey, f->nodes[kl].spending_spk, 34);
    f->nodes[sr].outputs[0].script_pubkey_len = 34;
    f->nodes[sr].outputs[1].amount_sats = sr_per_child;
    memcpy(f->nodes[sr].outputs[1].script_pubkey, f->nodes[kri].spending_spk, 34);
    f->nodes[sr].outputs[1].script_pubkey_len = 34;
    f->nodes[sr].input_amount = kr_out;

    /* kickoff_left -> 1 output: state_left */
    f->nodes[kl].n_outputs = 1;
    f->nodes[kl].outputs[0].amount_sats = kl_out;
    memcpy(f->nodes[kl].outputs[0].script_pubkey, f->nodes[sl].spending_spk, 34);
    f->nodes[kl].outputs[0].script_pubkey_len = 34;
    f->nodes[kl].input_amount = sr_per_child;

    /* kickoff_right -> 1 output: state_right */
    f->nodes[kri].n_outputs = 1;
    f->nodes[kri].outputs[0].amount_sats = kri_out;
    memcpy(f->nodes[kri].outputs[0].script_pubkey, f->nodes[sri].spending_spk, 34);
    f->nodes[kri].outputs[0].script_pubkey_len = 34;
    f->nodes[kri].input_amount = sr_per_child;

    /* state_left -> 3 leaf outputs: chan_A, chan_B, L_stock */
    f->nodes[sl].input_amount = kl_out;
    if (!setup_leaf_outputs(f, &f->nodes[sl], 1, 2, kl_out))
        return 0;

    /* state_right -> 3 leaf outputs: chan_C, chan_D, L_stock */
    f->nodes[sri].input_amount = kri_out;
    if (!setup_leaf_outputs(f, &f->nodes[sri], 3, 4, kri_out))
        return 0;

    /* ---- Phase 3: Build unsigned txs top-down ---- */
    return build_all_unsigned_txs(f);
}

static int factory_build_tree_arity1(factory_t *f) {
    /*
     * Arity-1 tree (14 nodes, 3 DW layers):
     *   kickoff_root[0] (5-of-5) → state_root[1] (5-of-5, DW L0)
     *     ├─ kickoff_left[2] (3-of-3) → state_left[4] (3-of-3, DW L1)
     *     │    ├─ kickoff_A[6] (2-of-2) → state_A[10] (2-of-2, DW L2) → [chan_A, L_stock]
     *     │    └─ kickoff_B[7] (2-of-2) → state_B[11] (2-of-2, DW L2) → [chan_B, L_stock]
     *     └─ kickoff_right[3] (3-of-3) → state_right[5] (3-of-3, DW L1)
     *          ├─ kickoff_C[8] (2-of-2) → state_C[12] (2-of-2, DW L2) → [chan_C, L_stock]
     *          └─ kickoff_D[9] (2-of-2) → state_D[13] (2-of-2, DW L2) → [chan_D, L_stock]
     */

    /* Minimum funding validation: from funding to each leaf output, there are
       6 fee deductions along the path (kr,sr,kl/kri,sl/sri,ka-kd,sa-sd).
       Each leaf output = (funding - 14*fee) / 8 (integer math, worst case).
       Each leaf needs at least 2*dust (channel + L-stock) = 2*546 = 1092 sats.
       So: (funding - 14*fee) / 8 >= 1092 ⟹ funding >= 14*fee + 8*1092. */
    uint64_t min_funding = 14 * f->fee_per_tx + 8 * 1092;
    if (f->funding_amount_sats < min_funding) {
        fprintf(stderr, "factory_build_tree_arity1: funding %lu sats below minimum %lu\n",
                (unsigned long)f->funding_amount_sats, (unsigned long)min_funding);
        return 0;
    }

    uint32_t all[] = {0, 1, 2, 3, 4};
    uint32_t left_set[] = {0, 1, 2};       /* L, A, B */
    uint32_t right_set[] = {0, 3, 4};      /* L, C, D */
    uint32_t set_a[] = {0, 1};             /* L, A */
    uint32_t set_b[] = {0, 2};             /* L, B */
    uint32_t set_c[] = {0, 3};             /* L, C */
    uint32_t set_d[] = {0, 4};             /* L, D */

    /* Staggered CLTVs: 5 tiers with TIMEOUT_STEP_BLOCKS between each position.
       Root has longest timeout, leaves have shortest. Each child must have a
       strictly shorter CLTV than its parent to ensure bottom-up timeout ordering.
       Positions: sr > kl/kri > sl/sri > ka-kd > sa-sd */
    uint32_t cltv = f->cltv_timeout;
    uint32_t step = TIMEOUT_STEP_BLOCKS;
    uint32_t root_cltv      = cltv;
    uint32_t mid_ko_cltv    = (cltv > step)   ? cltv - step   : 0;  /* level-1 kickoffs */
    uint32_t mid_st_cltv    = (cltv > 2*step) ? cltv - 2*step : 0;  /* level-1 states */
    uint32_t leaf_ko_cltv   = (cltv > 3*step) ? cltv - 3*step : 0;  /* level-2 kickoffs */
    uint32_t leaf_st_cltv   = (cltv > 4*step) ? cltv - 4*step : 0;  /* level-2 states */

    /* Level 0: root (5-of-5) */
    int kr  = add_node(f, NODE_KICKOFF, all, 5,         -1, 0, -1, 0);
    int sr  = add_node(f, NODE_STATE,   all, 5,         kr, 0,  0, root_cltv);

    /* Level 1: mid (3-of-3) */
    int kl  = add_node(f, NODE_KICKOFF, left_set, 3,    sr, 0, -1, mid_ko_cltv);
    int kri = add_node(f, NODE_KICKOFF, right_set, 3,   sr, 1, -1, mid_ko_cltv);
    int sl  = add_node(f, NODE_STATE,   left_set, 3,    kl, 0,  1, mid_st_cltv);
    int sri = add_node(f, NODE_STATE,   right_set, 3,  kri, 0,  1, mid_st_cltv);

    /* Level 2: per-client (2-of-2) */
    int ka  = add_node(f, NODE_KICKOFF, set_a, 2,       sl, 0, -1, leaf_ko_cltv);
    int kb  = add_node(f, NODE_KICKOFF, set_b, 2,       sl, 1, -1, leaf_ko_cltv);
    int kc  = add_node(f, NODE_KICKOFF, set_c, 2,      sri, 0, -1, leaf_ko_cltv);
    int kd  = add_node(f, NODE_KICKOFF, set_d, 2,      sri, 1, -1, leaf_ko_cltv);
    int sa  = add_node(f, NODE_STATE,   set_a, 2,       ka, 0,  2, leaf_st_cltv);
    int sb  = add_node(f, NODE_STATE,   set_b, 2,       kb, 0,  2, leaf_st_cltv);
    int sc  = add_node(f, NODE_STATE,   set_c, 2,       kc, 0,  2, leaf_st_cltv);
    int sd  = add_node(f, NODE_STATE,   set_d, 2,       kd, 0,  2, leaf_st_cltv);

    if (kr < 0 || sr < 0 || kl < 0 || kri < 0 || sl < 0 || sri < 0 ||
        ka < 0 || kb < 0 || kc < 0 || kd < 0 ||
        sa < 0 || sb < 0 || sc < 0 || sd < 0)
        return 0;

    /* Record leaf node indices: A=0, B=1, C=2, D=3 */
    f->leaf_node_indices[0] = (size_t)sa;
    f->leaf_node_indices[1] = (size_t)sb;
    f->leaf_node_indices[2] = (size_t)sc;
    f->leaf_node_indices[3] = (size_t)sd;

    /* ---- Outputs and amounts ---- */
    uint64_t fee = f->fee_per_tx;

    /* Level 0 amounts */
    uint64_t kr_out = f->funding_amount_sats - fee;
    uint64_t sr_per_child = (kr_out - fee) / 2;

    /* Level 1 amounts */
    uint64_t kl_out = sr_per_child - fee;
    uint64_t kri_out = sr_per_child - fee;
    uint64_t sl_per_child = (kl_out - fee) / 2;
    uint64_t sri_per_child = (kri_out - fee) / 2;

    /* Level 2 amounts */
    uint64_t ka_out = sl_per_child - fee;
    uint64_t kb_out = sl_per_child - fee;
    uint64_t kc_out = sri_per_child - fee;
    uint64_t kd_out = sri_per_child - fee;

    /* kickoff_root → state_root */
    f->nodes[kr].n_outputs = 1;
    f->nodes[kr].outputs[0].amount_sats = kr_out;
    memcpy(f->nodes[kr].outputs[0].script_pubkey, f->nodes[sr].spending_spk, 34);
    f->nodes[kr].outputs[0].script_pubkey_len = 34;
    f->nodes[kr].input_amount = f->funding_amount_sats;

    /* state_root → kickoff_left, kickoff_right */
    f->nodes[sr].n_outputs = 2;
    f->nodes[sr].outputs[0].amount_sats = sr_per_child;
    memcpy(f->nodes[sr].outputs[0].script_pubkey, f->nodes[kl].spending_spk, 34);
    f->nodes[sr].outputs[0].script_pubkey_len = 34;
    f->nodes[sr].outputs[1].amount_sats = sr_per_child;
    memcpy(f->nodes[sr].outputs[1].script_pubkey, f->nodes[kri].spending_spk, 34);
    f->nodes[sr].outputs[1].script_pubkey_len = 34;
    f->nodes[sr].input_amount = kr_out;

    /* kickoff_left → state_left */
    f->nodes[kl].n_outputs = 1;
    f->nodes[kl].outputs[0].amount_sats = kl_out;
    memcpy(f->nodes[kl].outputs[0].script_pubkey, f->nodes[sl].spending_spk, 34);
    f->nodes[kl].outputs[0].script_pubkey_len = 34;
    f->nodes[kl].input_amount = sr_per_child;

    /* kickoff_right → state_right */
    f->nodes[kri].n_outputs = 1;
    f->nodes[kri].outputs[0].amount_sats = kri_out;
    memcpy(f->nodes[kri].outputs[0].script_pubkey, f->nodes[sri].spending_spk, 34);
    f->nodes[kri].outputs[0].script_pubkey_len = 34;
    f->nodes[kri].input_amount = sr_per_child;

    /* state_left → 2 child outputs: kickoff_A, kickoff_B */
    f->nodes[sl].n_outputs = 2;
    f->nodes[sl].outputs[0].amount_sats = sl_per_child;
    memcpy(f->nodes[sl].outputs[0].script_pubkey, f->nodes[ka].spending_spk, 34);
    f->nodes[sl].outputs[0].script_pubkey_len = 34;
    f->nodes[sl].outputs[1].amount_sats = sl_per_child;
    memcpy(f->nodes[sl].outputs[1].script_pubkey, f->nodes[kb].spending_spk, 34);
    f->nodes[sl].outputs[1].script_pubkey_len = 34;
    f->nodes[sl].input_amount = kl_out;

    /* state_right → 2 child outputs: kickoff_C, kickoff_D */
    f->nodes[sri].n_outputs = 2;
    f->nodes[sri].outputs[0].amount_sats = sri_per_child;
    memcpy(f->nodes[sri].outputs[0].script_pubkey, f->nodes[kc].spending_spk, 34);
    f->nodes[sri].outputs[0].script_pubkey_len = 34;
    f->nodes[sri].outputs[1].amount_sats = sri_per_child;
    memcpy(f->nodes[sri].outputs[1].script_pubkey, f->nodes[kd].spending_spk, 34);
    f->nodes[sri].outputs[1].script_pubkey_len = 34;
    f->nodes[sri].input_amount = kri_out;

    /* Per-client kickoff → state nodes.
       Left-side (A,B) parents are state_left → input_amount = sl_per_child.
       Right-side (C,D) parents are state_right → input_amount = sri_per_child. */
    struct { int ko; int st; uint64_t ko_out; uint64_t parent_per_child; } leaf_pairs[] = {
        { ka, sa, ka_out, sl_per_child },
        { kb, sb, kb_out, sl_per_child },
        { kc, sc, kc_out, sri_per_child },
        { kd, sd, kd_out, sri_per_child },
    };
    uint32_t client_indices[] = { 1, 2, 3, 4 };

    for (int i = 0; i < 4; i++) {
        int ko = leaf_pairs[i].ko;
        int st = leaf_pairs[i].st;
        uint64_t ko_out = leaf_pairs[i].ko_out;

        f->nodes[ko].n_outputs = 1;
        f->nodes[ko].outputs[0].amount_sats = ko_out;
        memcpy(f->nodes[ko].outputs[0].script_pubkey, f->nodes[st].spending_spk, 34);
        f->nodes[ko].outputs[0].script_pubkey_len = 34;
        f->nodes[ko].input_amount = leaf_pairs[i].parent_per_child;

        f->nodes[st].input_amount = ko_out;
        if (!setup_single_leaf_outputs(f, &f->nodes[st], client_indices[i], ko_out))
            return 0;
    }

    /* ---- Build unsigned txs top-down ---- */
    return build_all_unsigned_txs(f);
}

int factory_build_tree(factory_t *f) {
    if (f->n_participants != 5) return 0;  /* 4 clients + 1 LSP */

    /* Override fee_per_tx from fee estimator if available */
    if (f->fee) {
        f->fee_per_tx = fee_for_factory_tx(f->fee, 3);
    }

    if (f->leaf_arity == FACTORY_ARITY_1)
        return factory_build_tree_arity1(f);
    return factory_build_tree_arity2(f);
}

/* --- Split-round signing API --- */

int factory_find_signer_slot(const factory_t *f, size_t node_idx,
                              uint32_t participant_idx) {
    if (node_idx >= f->n_nodes) return -1;
    const factory_node_t *node = &f->nodes[node_idx];
    for (size_t i = 0; i < node->n_signers; i++) {
        if (node->signer_indices[i] == participant_idx)
            return (int)i;
    }
    return -1;
}

int factory_sessions_init(factory_t *f) {
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *node = &f->nodes[i];
        if (!node->is_built) return 0;
        musig_session_init(&node->signing_session, &node->keyagg, node->n_signers);
        node->partial_sigs_received = 0;
    }
    return 1;
}

int factory_session_set_nonce(factory_t *f, size_t node_idx, size_t signer_slot,
                               const secp256k1_musig_pubnonce *pubnonce) {
    if (node_idx >= f->n_nodes) return 0;
    return musig_session_set_pubnonce(&f->nodes[node_idx].signing_session,
                                      signer_slot, pubnonce);
}

int factory_sessions_finalize(factory_t *f) {
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *node = &f->nodes[i];

        unsigned char sighash[32];
        if (!compute_node_sighash(f, node, sighash))
            return 0;

        const unsigned char *mr = node->has_taptree ? node->merkle_root : NULL;
        if (!musig_session_finalize_nonces(f->ctx, &node->signing_session,
                                            sighash, mr, NULL))
            return 0;
    }
    return 1;
}

int factory_session_set_partial_sig(factory_t *f, size_t node_idx,
                                     size_t signer_slot,
                                     const secp256k1_musig_partial_sig *psig) {
    if (node_idx >= f->n_nodes) return 0;
    factory_node_t *node = &f->nodes[node_idx];
    if (signer_slot >= node->n_signers) return 0;

    node->partial_sigs[signer_slot] = *psig;
    node->partial_sigs_received++;
    return 1;
}

int factory_sessions_complete(factory_t *f) {
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *node = &f->nodes[i];

        if (node->partial_sigs_received != (int)node->n_signers)
            return 0;

        unsigned char sig[64];
        if (!musig_aggregate_partial_sigs(f->ctx, sig, &node->signing_session,
                                           node->partial_sigs, node->n_signers))
            return 0;

        if (!finalize_signed_tx(&node->signed_tx,
                                 node->unsigned_tx.data, node->unsigned_tx.len,
                                 sig))
            return 0;

        node->is_signed = 1;
    }
    return 1;
}

int factory_sign_all(factory_t *f) {
    /* Step 1: Initialize sessions */
    if (!factory_sessions_init(f))
        return 0;

    /* Count total (node, signer) slots for secnonce storage */
    size_t total_slots = 0;
    for (size_t i = 0; i < f->n_nodes; i++)
        total_slots += f->nodes[i].n_signers;

    /* Allocate secnonces: indexed as [node_offset + signer_slot] */
    secp256k1_musig_secnonce *secnonces =
        (secp256k1_musig_secnonce *)calloc(total_slots,
                                            sizeof(secp256k1_musig_secnonce));
    if (!secnonces) return 0;

    /* Step 2: Generate nonces and set pubnonces */
    size_t offset = 0;
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *node = &f->nodes[i];
        for (size_t j = 0; j < node->n_signers; j++) {
            uint32_t participant = node->signer_indices[j];
            unsigned char seckey[32];
            secp256k1_pubkey pk;

            if (!secp256k1_keypair_sec(f->ctx, seckey, &f->keypairs[participant]))
                goto fail;
            if (!secp256k1_keypair_pub(f->ctx, &pk, &f->keypairs[participant]))
                goto fail;

            secp256k1_musig_pubnonce pubnonce;
            if (!musig_generate_nonce(f->ctx, &secnonces[offset + j], &pubnonce,
                                       seckey, &pk, &node->keyagg.cache))
                goto fail;

            memset(seckey, 0, 32);

            if (!factory_session_set_nonce(f, i, j, &pubnonce))
                goto fail;
        }
        offset += node->n_signers;
    }

    /* Step 3: Finalize nonces (compute sighash + aggregate nonces + tweak) */
    if (!factory_sessions_finalize(f))
        goto fail;

    /* Step 4: Create partial sigs */
    offset = 0;
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *node = &f->nodes[i];
        for (size_t j = 0; j < node->n_signers; j++) {
            uint32_t participant = node->signer_indices[j];
            secp256k1_musig_partial_sig psig;

            if (!musig_create_partial_sig(f->ctx, &psig,
                                           &secnonces[offset + j],
                                           &f->keypairs[participant],
                                           &node->signing_session))
                goto fail;

            if (!factory_session_set_partial_sig(f, i, j, &psig))
                goto fail;
        }
        offset += node->n_signers;
    }

    /* Step 5: Complete (aggregate + finalize witness) */
    if (!factory_sessions_complete(f)) goto fail;

    memset(secnonces, 0, total_slots * sizeof(secp256k1_musig_secnonce));
    free(secnonces);
    return 1;

fail:
    memset(secnonces, 0, total_slots * sizeof(secp256k1_musig_secnonce));
    free(secnonces);
    return 0;
}

int factory_advance(factory_t *f) {
    if (!dw_counter_advance(&f->counter))
        return 0;

    if (!update_l_stock_outputs(f))
        return 0;

    if (!build_all_unsigned_txs(f))
        return 0;

    return factory_sign_all(f);
}

int factory_reset_epoch(factory_t *f) {
    dw_counter_reset(&f->counter);

    /* Reset per-leaf layers too */
    for (int i = 0; i < f->n_leaf_nodes; i++)
        dw_layer_init(&f->leaf_layers[i], f->step_blocks, f->states_per_layer);
    f->per_leaf_enabled = 0;

    if (!update_l_stock_outputs(f))
        return 0;
    if (!build_all_unsigned_txs(f))
        return 0;
    return factory_sign_all(f);
}

/* Rebuild unsigned tx for a single node. */
static int rebuild_node_tx(factory_t *f, size_t node_idx) {
    if (node_idx >= f->n_nodes) return 0;
    factory_node_t *node = &f->nodes[node_idx];
    unsigned char display_txid[32];

    const unsigned char *input_txid;
    uint32_t input_vout;

    if (node->parent_index < 0) {
        input_txid = f->funding_txid;
        input_vout = f->funding_vout;
    } else {
        factory_node_t *parent = &f->nodes[node->parent_index];
        input_txid = parent->txid;
        input_vout = node->parent_vout;
    }

    node->nsequence = node_nsequence(f, node);

    if (!build_unsigned_tx(&node->unsigned_tx, display_txid,
                           input_txid, input_vout,
                           node->nsequence,
                           node->outputs, node->n_outputs))
        return 0;

    memcpy(node->txid, display_txid, 32);
    reverse_bytes(node->txid, 32);

    node->is_built = 1;
    node->is_signed = 0;
    return 1;
}

/* Sign a single node (local-only, all keypairs available). */
int factory_sign_node(factory_t *f, size_t node_idx) {
    if (node_idx >= f->n_nodes) return 0;
    factory_node_t *node = &f->nodes[node_idx];
    if (!node->is_built) return 0;

    /* Init session */
    musig_session_init(&node->signing_session, &node->keyagg, node->n_signers);
    node->partial_sigs_received = 0;

    /* Allocate secnonces */
    secp256k1_musig_secnonce *secnonces =
        (secp256k1_musig_secnonce *)calloc(node->n_signers,
                                            sizeof(secp256k1_musig_secnonce));
    if (!secnonces) return 0;

    /* Generate nonces */
    for (size_t j = 0; j < node->n_signers; j++) {
        uint32_t participant = node->signer_indices[j];
        unsigned char seckey[32];
        secp256k1_pubkey pk;

        if (!secp256k1_keypair_sec(f->ctx, seckey, &f->keypairs[participant]))
            goto fail;
        if (!secp256k1_keypair_pub(f->ctx, &pk, &f->keypairs[participant]))
            goto fail;

        secp256k1_musig_pubnonce pubnonce;
        if (!musig_generate_nonce(f->ctx, &secnonces[j], &pubnonce,
                                   seckey, &pk, &node->keyagg.cache))
            goto fail;

        memset(seckey, 0, 32);

        if (!musig_session_set_pubnonce(&node->signing_session, j, &pubnonce))
            goto fail;
    }

    /* Finalize nonces (sighash + aggregate + tweak) */
    {
        unsigned char sighash[32];
        if (!compute_node_sighash(f, node, sighash))
            goto fail;

        const unsigned char *mr = node->has_taptree ? node->merkle_root : NULL;
        if (!musig_session_finalize_nonces(f->ctx, &node->signing_session,
                                            sighash, mr, NULL))
            goto fail;
    }

    /* Create partial sigs */
    for (size_t j = 0; j < node->n_signers; j++) {
        uint32_t participant = node->signer_indices[j];
        secp256k1_musig_partial_sig psig;

        if (!musig_create_partial_sig(f->ctx, &psig,
                                       &secnonces[j],
                                       &f->keypairs[participant],
                                       &node->signing_session))
            goto fail;

        node->partial_sigs[j] = psig;
        node->partial_sigs_received++;
    }

    /* Aggregate + finalize */
    {
        unsigned char sig[64];
        if (!musig_aggregate_partial_sigs(f->ctx, sig, &node->signing_session,
                                           node->partial_sigs, node->n_signers))
            goto fail;

        if (!finalize_signed_tx(&node->signed_tx,
                                 node->unsigned_tx.data, node->unsigned_tx.len,
                                 sig))
            goto fail;
    }

    node->is_signed = 1;
    memset(secnonces, 0, node->n_signers * sizeof(secp256k1_musig_secnonce));
    free(secnonces);
    return 1;

fail:
    memset(secnonces, 0, node->n_signers * sizeof(secp256k1_musig_secnonce));
    free(secnonces);
    return 0;
}

/* Update L-stock output for a specific leaf node after per-leaf advance.
   L-stock is always the last output. */
static int update_l_stock_for_leaf(factory_t *f, size_t node_idx) {
    if (!f->has_shachain)
        return 1;  /* nothing to update */

    factory_node_t *node = &f->nodes[node_idx];
    if (node->type != NODE_STATE || node->n_children > 0)
        return 1;  /* not a leaf */
    if (node->n_outputs < 2)
        return 1;

    return build_l_stock_spk(f, node->outputs[node->n_outputs - 1].script_pubkey);
}

int factory_advance_leaf(factory_t *f, int leaf_side) {
    if (leaf_side < 0 || leaf_side >= f->n_leaf_nodes) return 0;

    f->per_leaf_enabled = 1;

    /* Advance per-leaf counter */
    if (!dw_advance(&f->leaf_layers[leaf_side])) {
        /* Leaf exhausted — advance root layer, reset all leaf layers */
        if (!dw_advance(&f->counter.layers[0]))
            return 0;  /* fully exhausted */
        f->counter.current_epoch++;
        for (int i = 0; i < f->n_leaf_nodes; i++)
            dw_layer_init(&f->leaf_layers[i], f->step_blocks, f->states_per_layer);
        /* Full rebuild needed when root advances */
        if (!update_l_stock_outputs(f)) return 0;
        if (!build_all_unsigned_txs(f)) return 0;
        return factory_sign_all(f);
    }

    /* Only rebuild + re-sign the leaf node */
    size_t node_idx = f->leaf_node_indices[leaf_side];
    if (!update_l_stock_for_leaf(f, node_idx)) return 0;
    if (!rebuild_node_tx(f, node_idx)) return 0;
    return factory_sign_node(f, node_idx);
}

int factory_advance_leaf_unsigned(factory_t *f, int leaf_side) {
    if (leaf_side < 0 || leaf_side >= f->n_leaf_nodes) return 0;

    f->per_leaf_enabled = 1;

    /* Advance per-leaf counter */
    if (!dw_advance(&f->leaf_layers[leaf_side])) {
        /* Leaf exhausted — advance root layer, reset all leaf layers */
        if (!dw_advance(&f->counter.layers[0]))
            return 0;  /* fully exhausted */
        f->counter.current_epoch++;
        for (int i = 0; i < f->n_leaf_nodes; i++)
            dw_layer_init(&f->leaf_layers[i], f->step_blocks, f->states_per_layer);
        /* Full rebuild needed when root advances */
        if (!update_l_stock_outputs(f)) return 0;
        if (!build_all_unsigned_txs(f)) return 0;
        return -1;  /* caller must do full re-sign */
    }

    /* Only rebuild the leaf node (no signing) */
    size_t node_idx = f->leaf_node_indices[leaf_side];
    if (!update_l_stock_for_leaf(f, node_idx)) return 0;
    if (!rebuild_node_tx(f, node_idx)) return 0;
    return 1;
}

/* --- Per-node split-round signing helpers --- */

int factory_session_init_node(factory_t *f, size_t node_idx) {
    if (node_idx >= f->n_nodes) return 0;
    factory_node_t *node = &f->nodes[node_idx];
    if (!node->is_built) return 0;
    musig_session_init(&node->signing_session, &node->keyagg, node->n_signers);
    node->partial_sigs_received = 0;
    return 1;
}

int factory_session_finalize_node(factory_t *f, size_t node_idx) {
    if (node_idx >= f->n_nodes) return 0;
    factory_node_t *node = &f->nodes[node_idx];

    unsigned char sighash[32];
    if (!compute_node_sighash(f, node, sighash))
        return 0;

    const unsigned char *mr = node->has_taptree ? node->merkle_root : NULL;
    return musig_session_finalize_nonces(f->ctx, &node->signing_session,
                                          sighash, mr, NULL);
}

int factory_session_complete_node(factory_t *f, size_t node_idx) {
    if (node_idx >= f->n_nodes) return 0;
    factory_node_t *node = &f->nodes[node_idx];

    if (node->partial_sigs_received != (int)node->n_signers)
        return 0;

    unsigned char sig[64];
    if (!musig_aggregate_partial_sigs(f->ctx, sig, &node->signing_session,
                                       node->partial_sigs, node->n_signers))
        return 0;

    if (!finalize_signed_tx(&node->signed_tx,
                             node->unsigned_tx.data, node->unsigned_tx.len,
                             sig))
        return 0;

    node->is_signed = 1;
    return 1;
}

void factory_set_shachain_seed(factory_t *f, const unsigned char *seed32) {
    memcpy(f->shachain_seed, seed32, 32);
    f->has_shachain = 1;
}

int factory_get_revocation_secret(const factory_t *f, uint32_t epoch,
                                    unsigned char *secret_out32) {
    if (!f->has_shachain)
        return 0;
    uint64_t sc_index = shachain_epoch_to_index(epoch);
    shachain_from_seed(f->shachain_seed, sc_index, secret_out32);
    return 1;
}

int factory_build_burn_tx(const factory_t *f, tx_buf_t *burn_tx_out,
                           const unsigned char *l_stock_txid,
                           uint32_t l_stock_vout,
                           uint64_t l_stock_amount,
                           uint32_t epoch) {
    (void)l_stock_amount;
    if (!f->has_shachain)
        return 0;

    /* 1. Derive shachain secret for the given epoch */
    uint64_t sc_index = shachain_epoch_to_index(epoch);
    unsigned char secret[32];
    shachain_from_seed(f->shachain_seed, sc_index, secret);

    /* 2. Compute SHA256(secret) -> hashlock hash */
    unsigned char hash[32];
    sha256(secret, 32, hash);

    /* 3. Build hashlock tapscript leaf */
    tapscript_leaf_t hashlock_leaf;
    tapscript_build_hashlock(&hashlock_leaf, hash);

    /* 4. Compute merkle root from single leaf */
    unsigned char merkle_root[32];
    tapscript_merkle_root(merkle_root, &hashlock_leaf, 1);

    /* 5. Get LSP's xonly pubkey (internal key), tweak, get parity */
    secp256k1_xonly_pubkey lsp_internal;
    if (!secp256k1_xonly_pubkey_from_pubkey(f->ctx, &lsp_internal, NULL,
                                              &f->pubkeys[0]))
        return 0;

    secp256k1_xonly_pubkey tweaked;
    int parity = 0;
    if (!tapscript_tweak_pubkey(f->ctx, &tweaked, &parity,
                                 &lsp_internal, merkle_root))
        return 0;

    /* 6. Build control block (33 bytes: leaf_version|parity || internal_key) */
    unsigned char control_block[33];
    size_t cb_len = 0;
    if (!tapscript_build_control_block(control_block, &cb_len, parity,
                                        &lsp_internal, f->ctx))
        return 0;

    /* 7. Build unsigned burn tx:
       Input: L-stock outpoint, nSequence = 0xFFFFFFFE
       Output: OP_RETURN with hashlock hash as data (ensures stripped tx >= 82 bytes) */
    tx_output_t burn_output;
    burn_output.amount_sats = 0;
    burn_output.script_pubkey[0] = 0x6a;  /* OP_RETURN */
    burn_output.script_pubkey[1] = 0x20;  /* OP_PUSHBYTES_32 */
    memcpy(burn_output.script_pubkey + 2, hash, 32);
    burn_output.script_pubkey_len = 34;

    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 128);
    if (!build_unsigned_tx(&unsigned_tx, NULL,
                            l_stock_txid, l_stock_vout,
                            0xFFFFFFFEu,
                            &burn_output, 1)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* 8. Build witness: 3 items [preimage(32), script(37), control_block(33)] */
    tx_buf_reset(burn_tx_out);

    /* nVersion */
    tx_buf_write_bytes(burn_tx_out, unsigned_tx.data, 4);
    /* segwit marker + flag */
    tx_buf_write_u8(burn_tx_out, 0x00);
    tx_buf_write_u8(burn_tx_out, 0x01);
    /* inputs + outputs (between nVersion and nLockTime) */
    tx_buf_write_bytes(burn_tx_out, unsigned_tx.data + 4,
                        unsigned_tx.len - 8);
    /* witness: 3 items */
    tx_buf_write_varint(burn_tx_out, 3);
    /* Item 1: preimage (32 bytes) */
    tx_buf_write_varint(burn_tx_out, 32);
    tx_buf_write_bytes(burn_tx_out, secret, 32);
    /* Item 2: script */
    tx_buf_write_varint(burn_tx_out, hashlock_leaf.script_len);
    tx_buf_write_bytes(burn_tx_out, hashlock_leaf.script, hashlock_leaf.script_len);
    /* Item 3: control block */
    tx_buf_write_varint(burn_tx_out, cb_len);
    tx_buf_write_bytes(burn_tx_out, control_block, cb_len);
    /* nLockTime */
    tx_buf_write_bytes(burn_tx_out, unsigned_tx.data + unsigned_tx.len - 4, 4);

    tx_buf_free(&unsigned_tx);
    memset(secret, 0, 32);
    return 1;
}

int factory_build_cooperative_close(
    factory_t *f,
    tx_buf_t *close_tx_out,
    unsigned char *txid_out32,
    const tx_output_t *outputs,
    size_t n_outputs)
{
    /* 1. Build unsigned tx spending the funding UTXO */
    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 256);
    unsigned char display_txid[32];

    if (!build_unsigned_tx(&unsigned_tx, txid_out32 ? display_txid : NULL,
                            f->funding_txid, f->funding_vout,
                            0xFFFFFFFEu,
                            outputs, n_outputs)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    if (txid_out32) {
        memcpy(txid_out32, display_txid, 32);
        reverse_bytes(txid_out32, 32);  /* display -> internal */
    }

    /* 2. Compute BIP-341 key-path sighash */
    unsigned char sighash[32];
    if (!compute_taproot_sighash(sighash, unsigned_tx.data, unsigned_tx.len,
                                  0, f->funding_spk, f->funding_spk_len,
                                  f->funding_amount_sats, 0xFFFFFFFEu)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* 3. Sign with N-of-N MuSig (key-path, same aggregate key as kickoff_root) */
    musig_keyagg_t keyagg_copy = f->nodes[0].keyagg;
    unsigned char sig64[64];
    if (!musig_sign_taproot(f->ctx, sig64, sighash, f->keypairs,
                             f->n_participants, &keyagg_copy, NULL)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* 4. Finalize */
    if (!finalize_signed_tx(close_tx_out, unsigned_tx.data, unsigned_tx.len,
                              sig64)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    tx_buf_free(&unsigned_tx);
    return 1;
}

int factory_build_cooperative_close_unsigned(
    factory_t *f,
    tx_buf_t *unsigned_tx_out,
    unsigned char *sighash_out32,
    const tx_output_t *outputs,
    size_t n_outputs)
{
    unsigned char display_txid[32];
    if (!build_unsigned_tx(unsigned_tx_out, display_txid,
                            f->funding_txid, f->funding_vout,
                            0xFFFFFFFEu,
                            outputs, n_outputs))
        return 0;

    if (!compute_taproot_sighash(sighash_out32,
                                  unsigned_tx_out->data, unsigned_tx_out->len,
                                  0, f->funding_spk, f->funding_spk_len,
                                  f->funding_amount_sats, 0xFFFFFFFEu))
        return 0;

    return 1;
}

/* --- Factory lifecycle (Phase 8) --- */

void factory_set_lifecycle(factory_t *f, uint32_t created_block,
                           uint32_t active_blocks, uint32_t dying_blocks) {
    f->created_block = created_block;
    f->active_blocks = active_blocks;
    f->dying_blocks = dying_blocks;
}

factory_state_t factory_get_state(const factory_t *f, uint32_t current_block) {
    if (f->active_blocks == 0)
        return FACTORY_EXPIRED;  /* not configured */

    uint32_t dying_start = f->created_block + f->active_blocks;
    uint32_t expired_start = dying_start + f->dying_blocks;

    if (current_block < dying_start)
        return FACTORY_ACTIVE;
    if (current_block < expired_start)
        return FACTORY_DYING;
    return FACTORY_EXPIRED;
}

int factory_is_active(const factory_t *f, uint32_t current_block) {
    return factory_get_state(f, current_block) == FACTORY_ACTIVE;
}

int factory_is_dying(const factory_t *f, uint32_t current_block) {
    return factory_get_state(f, current_block) == FACTORY_DYING;
}

int factory_is_expired(const factory_t *f, uint32_t current_block) {
    return factory_get_state(f, current_block) == FACTORY_EXPIRED;
}

uint32_t factory_blocks_until_dying(const factory_t *f, uint32_t current_block) {
    uint32_t dying_start = f->created_block + f->active_blocks;
    if (current_block >= dying_start)
        return 0;
    return dying_start - current_block;
}

uint32_t factory_blocks_until_expired(const factory_t *f, uint32_t current_block) {
    uint32_t expired_start = f->created_block + f->active_blocks + f->dying_blocks;
    if (current_block >= expired_start)
        return 0;
    return expired_start - current_block;
}

int factory_build_distribution_tx(
    factory_t *f,
    tx_buf_t *dist_tx_out,
    unsigned char *txid_out32,
    const tx_output_t *outputs,
    size_t n_outputs,
    uint32_t nlocktime)
{
    /* Build unsigned tx with nLockTime spending the funding UTXO.
       nSequence = 0xFFFFFFFE to enable nLockTime. */
    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 256);
    unsigned char display_txid[32];

    if (!build_unsigned_tx_with_locktime(&unsigned_tx,
                                          txid_out32 ? display_txid : NULL,
                                          f->funding_txid, f->funding_vout,
                                          0xFFFFFFFEu, nlocktime,
                                          outputs, n_outputs)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    if (txid_out32) {
        memcpy(txid_out32, display_txid, 32);
        reverse_bytes(txid_out32, 32);
    }

    /* Compute BIP-341 key-path sighash */
    unsigned char sighash[32];
    if (!compute_taproot_sighash(sighash, unsigned_tx.data, unsigned_tx.len,
                                  0, f->funding_spk, f->funding_spk_len,
                                  f->funding_amount_sats, 0xFFFFFFFEu)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* Sign with N-of-N MuSig (same aggregate key as kickoff_root) */
    musig_keyagg_t keyagg_copy = f->nodes[0].keyagg;
    unsigned char sig64[64];
    if (!musig_sign_taproot(f->ctx, sig64, sighash, f->keypairs,
                             f->n_participants, &keyagg_copy, NULL)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* Finalize */
    if (!finalize_signed_tx(dist_tx_out, unsigned_tx.data, unsigned_tx.len,
                              sig64)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    tx_buf_free(&unsigned_tx);
    return 1;
}

void factory_free(factory_t *f) {
    for (size_t i = 0; i < f->n_nodes; i++) {
        tx_buf_free(&f->nodes[i].unsigned_tx);
        tx_buf_free(&f->nodes[i].signed_tx);
    }
}
