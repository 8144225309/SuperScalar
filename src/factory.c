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

        if (!tapscript_build_cltv_timeout(&node->timeout_leaf, node_cltv,
                                          &lsp_xonly, f->ctx))
            return -1;
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
        /* Get current epoch's revocation secret and compute SHA256 hash */
        unsigned char secret[32];
        if (f->use_flat_secrets) {
            uint32_t epoch = f->counter.current_epoch;
            if (epoch >= f->n_revocation_secrets) return 0;
            memcpy(secret, f->revocation_secrets[epoch], 32);
        } else {
            uint64_t sc_index = shachain_epoch_to_index(f->counter.current_epoch);
            shachain_from_seed(f->shachain_seed, sc_index, secret);
        }

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

/* Forward declarations for helpers used in init/set_arity */
static int compute_tree_depth(size_t n_clients, factory_arity_t arity);
static int compute_leaf_count(size_t n_clients, factory_arity_t arity);

/* ---- Public API ---- */

int factory_init(factory_t *f, secp256k1_context *ctx,
                 const secp256k1_keypair *keypairs, size_t n_participants,
                 uint16_t step_blocks, uint32_t states_per_layer) {
    memset(f, 0, sizeof(*f));
    f->ctx = ctx;
    f->n_participants = n_participants;
    f->step_blocks = step_blocks;
    f->states_per_layer = states_per_layer;
    f->fee_per_tx = 200;  /* 1 sat/vB floor for ~200 vB tx; overridden by factory_build_tree */

    for (size_t i = 0; i < n_participants; i++) {
        f->keypairs[i] = keypairs[i];
        if (!secp256k1_keypair_pub(ctx, &f->pubkeys[i], &keypairs[i]))
            return 0;
    }

    /* Default arity-2: compute layers/leaves from n_participants */
    f->leaf_arity = FACTORY_ARITY_2;
    size_t nc = (n_participants > 1) ? n_participants - 1 : 1;
    int n_leaves = compute_leaf_count(nc, FACTORY_ARITY_2);
    int n_layers = compute_tree_depth(nc, FACTORY_ARITY_2) + 1;
    f->n_leaf_nodes = n_leaves;
    dw_counter_init(&f->counter, n_layers, step_blocks, states_per_layer);

    for (int i = 0; i < n_leaves; i++)
        dw_layer_init(&f->leaf_layers[i], step_blocks, states_per_layer);
    f->per_leaf_enabled = 0;
    return 1;
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

    /* Default arity-2: compute layers/leaves from n_participants */
    f->leaf_arity = FACTORY_ARITY_2;
    size_t nc = (n_participants > 1) ? n_participants - 1 : 1;
    int n_leaves = compute_leaf_count(nc, FACTORY_ARITY_2);
    int n_layers = compute_tree_depth(nc, FACTORY_ARITY_2) + 1;
    f->n_leaf_nodes = n_leaves;
    dw_counter_init(&f->counter, n_layers, step_blocks, states_per_layer);

    for (int i = 0; i < n_leaves; i++)
        dw_layer_init(&f->leaf_layers[i], step_blocks, states_per_layer);
    f->per_leaf_enabled = 0;
}

void factory_set_arity(factory_t *f, factory_arity_t arity) {
    f->leaf_arity = arity;
    size_t nc = (f->n_participants > 1) ? f->n_participants - 1 : 1;
    int n_leaves = compute_leaf_count(nc, arity);
    int n_layers = compute_tree_depth(nc, arity) + 1;
    f->n_leaf_nodes = n_leaves;
    dw_counter_init(&f->counter, n_layers, f->step_blocks, f->states_per_layer);
    for (int i = 0; i < n_leaves; i++)
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

/* ---- Generalized N-participant tree builder ---- */

#define TIMEOUT_STEP_BLOCKS 5

/* Compute tree depth (number of binary splits above the leaves).
   n_clients = n_participants - 1 (excluding LSP).
   Arity-2: each leaf holds 2 clients → ceil(log2(ceil(n_clients/2))) splits.
   Arity-1: each leaf holds 1 client → ceil(log2(n_clients)) splits.
   Returns 0 for a single leaf (1 or 2 clients depending on arity). */
static int compute_tree_depth(size_t n_clients, factory_arity_t arity) {
    size_t n_leaves;
    if (arity == FACTORY_ARITY_1)
        n_leaves = n_clients;
    else
        n_leaves = (n_clients + 1) / 2;  /* ceil(n_clients / 2) */

    if (n_leaves <= 1) return 0;
    int depth = 0;
    size_t v = n_leaves - 1;
    while (v > 0) { depth++; v >>= 1; }
    return depth;
}

/* Compute number of leaf nodes.
   Arity-2: ceil(n_clients / 2).  Arity-1: n_clients. */
static int compute_leaf_count(size_t n_clients, factory_arity_t arity) {
    if (arity == FACTORY_ARITY_1)
        return (int)n_clients;
    return (int)((n_clients + 1) / 2);
}

/* Compute total tree nodes: each logical node = kickoff + state pair.
   Internal nodes = 2 * (total_logical - leaves) pairs, leaf nodes = leaves pairs.
   total_logical = 2*n_leaves - 1 (full binary tree with padding).
   Actually: total_nodes = 2 * (2*n_leaves - 1) for full binary,
   but we use actual recursion count. For the general case with
   unbalanced splits we just let build_subtree count. This is used
   only for validation. */
static int compute_total_nodes_upper_bound(size_t n_clients, factory_arity_t arity) {
    int n_leaves = compute_leaf_count(n_clients, arity);
    /* Full binary tree: 2*n_leaves - 1 logical nodes, each = kickoff+state pair */
    return 2 * (2 * n_leaves - 1);
}

/* Recursive subtree builder.
   client_indices: array of 1-based participant indices for clients in this subtree.
   n_clients: number of clients in this subtree.
   parent_state_idx: index of the parent state node (-1 for root kickoff's parent).
   parent_vout: which output of parent this subtree's kickoff spends.
   depth: 0 = root level, increases going down.
   max_depth: total depth of the tree (for DW layer assignment).
   input_amount: sats budget from parent output for this subtree's kickoff.
   leaf_counter: running counter of leaves found (for leaf_node_indices). */
static int build_subtree(
    factory_t *f,
    const uint32_t *client_indices,
    size_t n_clients,
    int parent_state_idx,
    uint32_t parent_vout,
    int depth,
    int max_depth,
    uint64_t input_amount,
    int *leaf_counter
) {
    if (n_clients == 0) return 0;

    /* Build signer set: {0 (LSP)} ∪ all client_indices in this subtree */
    uint32_t signers[FACTORY_MAX_SIGNERS];
    size_t n_signers = 0;
    signers[n_signers++] = 0;  /* LSP always signs */
    for (size_t i = 0; i < n_clients; i++)
        signers[n_signers++] = client_indices[i];

    /* Compute CLTVs from depth.
       Root kickoff gets cltv=0 (no timeout). Root state gets longest CLTV.
       Each subsequent level gets progressively shorter CLTVs.
       ko_cltv = base - (2*depth - 1) * step   (for depth > 0)
       st_cltv = base - (2*depth) * step */
    uint32_t cltv = f->cltv_timeout;
    uint32_t step = TIMEOUT_STEP_BLOCKS;
    uint32_t ko_cltv, st_cltv;

    if (depth == 0) {
        ko_cltv = 0;  /* root kickoff has no timeout */
        st_cltv = cltv;  /* root state gets longest CLTV */
    } else {
        uint32_t ko_offset = (uint32_t)(2 * depth - 1) * step;
        uint32_t st_offset = (uint32_t)(2 * depth) * step;
        ko_cltv = (cltv > ko_offset) ? cltv - ko_offset : 0;
        st_cltv = (cltv > st_offset) ? cltv - st_offset : 0;
    }

    /* DW layer index for state nodes: depth maps to layer.
       Kickoff nodes get dw_layer_index = -1. */
    int dw_layer = depth;
    if (dw_layer >= (int)f->counter.n_layers)
        dw_layer = (int)f->counter.n_layers - 1;

    /* Add kickoff node */
    int ko_idx = add_node(f, NODE_KICKOFF, signers, n_signers,
                          parent_state_idx, parent_vout, -1, ko_cltv);
    if (ko_idx < 0) return 0;

    /* Add state node */
    int st_idx = add_node(f, NODE_STATE, signers, n_signers,
                          ko_idx, 0, dw_layer, st_cltv);
    if (st_idx < 0) return 0;

    /* Wire kickoff → state output */
    uint64_t fee = f->fee_per_tx;
    uint64_t ko_out_amount = input_amount - fee;

    f->nodes[ko_idx].n_outputs = 1;
    f->nodes[ko_idx].outputs[0].amount_sats = ko_out_amount;
    memcpy(f->nodes[ko_idx].outputs[0].script_pubkey,
           f->nodes[st_idx].spending_spk, 34);
    f->nodes[ko_idx].outputs[0].script_pubkey_len = 34;
    f->nodes[ko_idx].input_amount = input_amount;

    /* Determine if this is a leaf */
    int is_leaf;
    if (f->leaf_arity == FACTORY_ARITY_1)
        is_leaf = (n_clients <= 1);
    else
        is_leaf = (n_clients <= 2);

    if (is_leaf) {
        /* Leaf node: set up channel outputs */
        f->nodes[st_idx].input_amount = ko_out_amount;

        if (n_clients == 1) {
            if (!setup_single_leaf_outputs(f, &f->nodes[st_idx],
                                           client_indices[0], ko_out_amount))
                return 0;
        } else {
            /* n_clients == 2 (arity-2 leaf) */
            if (!setup_leaf_outputs(f, &f->nodes[st_idx],
                                    client_indices[0], client_indices[1],
                                    ko_out_amount))
                return 0;
        }

        /* Record leaf index */
        if (*leaf_counter >= FACTORY_MAX_LEAVES) return 0;
        f->leaf_node_indices[*leaf_counter] = (size_t)st_idx;
        (*leaf_counter)++;
    } else {
        /* Internal node: split clients in half, recurse */
        size_t left_n, right_n;
        if (f->leaf_arity == FACTORY_ARITY_1) {
            left_n = n_clients / 2;
            right_n = n_clients - left_n;
        } else {
            /* Arity-2: split in pairs. Left gets floor(n/2) clients rounded
               to even, right gets the rest. Actually: split into two groups
               that will each become subtrees. Each leaf holds 2 clients,
               so split to balance leaf count. */
            size_t left_leaves = compute_leaf_count(n_clients, f->leaf_arity) / 2;
            left_n = left_leaves * 2;
            if (left_n > n_clients) left_n = n_clients;
            right_n = n_clients - left_n;
        }

        /* State node gets 2 outputs for left and right children */
        uint64_t state_budget = ko_out_amount - fee;
        uint64_t left_budget = state_budget / 2;
        uint64_t right_budget = state_budget - left_budget;

        f->nodes[st_idx].input_amount = ko_out_amount;
        f->nodes[st_idx].n_outputs = 2;
        /* Outputs will be filled after children are created (need their spk) */

        /* Recurse left */
        size_t saved_n_nodes = f->n_nodes;
        if (!build_subtree(f, client_indices, left_n,
                           st_idx, 0, depth + 1, max_depth,
                           left_budget, leaf_counter))
            return 0;

        /* The left child's kickoff is the first node added */
        int left_ko_idx = (int)saved_n_nodes;

        /* Recurse right */
        saved_n_nodes = f->n_nodes;
        if (!build_subtree(f, client_indices + left_n, right_n,
                           st_idx, 1, depth + 1, max_depth,
                           right_budget, leaf_counter))
            return 0;

        int right_ko_idx = (int)saved_n_nodes;

        /* Now wire state outputs to children's spending_spks */
        f->nodes[st_idx].outputs[0].amount_sats = left_budget;
        memcpy(f->nodes[st_idx].outputs[0].script_pubkey,
               f->nodes[left_ko_idx].spending_spk, 34);
        f->nodes[st_idx].outputs[0].script_pubkey_len = 34;

        f->nodes[st_idx].outputs[1].amount_sats = right_budget;
        memcpy(f->nodes[st_idx].outputs[1].script_pubkey,
               f->nodes[right_ko_idx].spending_spk, 34);
        f->nodes[st_idx].outputs[1].script_pubkey_len = 34;
    }

    return 1;
}

int factory_build_tree(factory_t *f) {
    size_t n_clients = f->n_participants - 1;

    /* Validate participant count */
    if (f->n_participants < 3 || f->n_participants > FACTORY_MAX_SIGNERS)
        return 0;

    /* Arity-2 needs at least 2 clients */
    if (f->leaf_arity == FACTORY_ARITY_2 && n_clients < 2)
        return 0;

    /* Override fee_per_tx from fee estimator if available */
    if (f->fee) {
        f->fee_per_tx = fee_for_factory_tx(f->fee, 3);
    }

    /* Compute tree metrics */
    int tree_depth = compute_tree_depth(n_clients, f->leaf_arity);
    int n_leaves = compute_leaf_count(n_clients, f->leaf_arity);
    int n_dw_layers = tree_depth + 1;
    int total_nodes_ub = compute_total_nodes_upper_bound(n_clients, f->leaf_arity);

    if (total_nodes_ub > FACTORY_MAX_NODES) return 0;
    if (n_leaves > FACTORY_MAX_LEAVES) return 0;
    if (n_dw_layers > DW_MAX_LAYERS) return 0;

    /* Reinitialize DW counter with correct layer count */
    dw_counter_init(&f->counter, n_dw_layers, f->step_blocks, f->states_per_layer);
    f->n_leaf_nodes = n_leaves;
    for (int i = 0; i < n_leaves; i++)
        dw_layer_init(&f->leaf_layers[i], f->step_blocks, f->states_per_layer);

    /* Minimum funding validation */
    uint64_t min_funding = (uint64_t)total_nodes_ub * f->fee_per_tx +
                           (uint64_t)n_leaves * 1092;
    if (f->funding_amount_sats < min_funding) {
        fprintf(stderr, "factory_build_tree: funding %lu sats below minimum %lu\n",
                (unsigned long)f->funding_amount_sats, (unsigned long)min_funding);
        return 0;
    }

    /* Build client index array [1, 2, ..., n_clients] */
    uint32_t clients[FACTORY_MAX_SIGNERS];
    for (size_t i = 0; i < n_clients; i++)
        clients[i] = (uint32_t)(i + 1);

    /* Build the tree recursively */
    f->n_nodes = 0;
    int leaf_counter = 0;
    if (!build_subtree(f, clients, n_clients,
                       -1, 0, 0, tree_depth,
                       f->funding_amount_sats, &leaf_counter))
        return 0;

    /* Build all unsigned transactions top-down */
    return build_all_unsigned_txs(f);
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

int factory_generate_flat_secrets(factory_t *f, size_t n_epochs) {
    if (!f || n_epochs == 0 || n_epochs > FACTORY_MAX_EPOCHS) return 0;

    FILE *urandom = fopen("/dev/urandom", "rb");
    if (!urandom) return 0;

    for (size_t i = 0; i < n_epochs; i++) {
        if (fread(f->revocation_secrets[i], 1, 32, urandom) != 32) {
            fclose(urandom);
            memset(f->revocation_secrets, 0, sizeof(f->revocation_secrets));
            return 0;
        }
    }
    fclose(urandom);

    f->n_revocation_secrets = n_epochs;
    f->use_flat_secrets = 1;
    f->has_shachain = 1;  /* reuse shachain infrastructure for L-stock */
    return 1;
}

void factory_set_flat_secrets(factory_t *f,
                               const unsigned char secrets[][32],
                               size_t n_secrets) {
    if (!f || !secrets || n_secrets == 0) return;
    if (n_secrets > FACTORY_MAX_EPOCHS) n_secrets = FACTORY_MAX_EPOCHS;
    memcpy(f->revocation_secrets, secrets, n_secrets * 32);
    f->n_revocation_secrets = n_secrets;
    f->use_flat_secrets = 1;
    f->has_shachain = 1;
}

int factory_get_revocation_secret(const factory_t *f, uint32_t epoch,
                                    unsigned char *secret_out32) {
    if (!f->has_shachain)
        return 0;
    if (f->use_flat_secrets) {
        if (epoch >= f->n_revocation_secrets) return 0;
        memcpy(secret_out32, f->revocation_secrets[epoch], 32);
        return 1;
    }
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

    /* 1. Derive revocation secret for the given epoch */
    unsigned char secret[32];
    if (f->use_flat_secrets) {
        if (epoch >= f->n_revocation_secrets) return 0;
        memcpy(secret, f->revocation_secrets[epoch], 32);
    } else {
        uint64_t sc_index = shachain_epoch_to_index(epoch);
        shachain_from_seed(f->shachain_seed, sc_index, secret);
    }

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

    /* cppcheck-suppress legacyUninitvar ; display_txid only passed when txid_out32 != NULL */
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
                                          /* cppcheck-suppress legacyUninitvar */
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
