#include "superscalar/factory.h"
#include "superscalar/channel.h"
#include "superscalar/shachain.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* --- Placement sort context (passed via global for qsort) --- */
static const factory_t *g_sort_factory = NULL;

/* Inward: highest contribution_sats first (descending) */
static int cmp_balance_desc(const void *a, const void *b) {
    uint32_t ia = *(const uint32_t *)a;
    uint32_t ib = *(const uint32_t *)b;
    uint64_t ba = g_sort_factory->profiles[ia].contribution_sats;
    uint64_t bb = g_sort_factory->profiles[ib].contribution_sats;
    if (ba > bb) return -1;
    if (ba < bb) return 1;
    return 0;
}

/* Timezone cluster: group same-timezone clients, reliable clients first within group */
static int cmp_timezone_cluster(const void *a, const void *b) {
    uint32_t ia = *(const uint32_t *)a;
    uint32_t ib = *(const uint32_t *)b;
    uint8_t ta = g_sort_factory->profiles[ia].timezone_bucket;
    uint8_t tb = g_sort_factory->profiles[ib].timezone_bucket;
    if (ta < tb) return -1;
    if (ta > tb) return 1;
    /* Secondary: highest uptime first (descending) — reliable clients grouped first */
    float ua = g_sort_factory->profiles[ia].uptime_score;
    float ub = g_sort_factory->profiles[ib].uptime_score;
    if (ua > ub) return -1;
    if (ua < ub) return 1;
    return 0;
}

/* Outward: lowest uptime first (ascending), then lowest contribution (ascending) */
static int cmp_uptime_asc(const void *a, const void *b) {
    uint32_t ia = *(const uint32_t *)a;
    uint32_t ib = *(const uint32_t *)b;
    float ua = g_sort_factory->profiles[ia].uptime_score;
    float ub = g_sort_factory->profiles[ib].uptime_score;
    if (ua < ub) return -1;
    if (ua > ub) return 1;
    /* Secondary: lowest contribution first */
    uint64_t ba = g_sort_factory->profiles[ia].contribution_sats;
    uint64_t bb = g_sort_factory->profiles[ib].contribution_sats;
    if (ba < bb) return -1;
    if (ba > bb) return 1;
    return 0;
}

#include "superscalar/sha256.h"
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
   PS leaf state nodes always use 0xFFFFFFFE (BIP-68 disabled, anti-fee-snipe
   enabled) — their state ordering is enforced by TX chaining, not nSequence.
   When per-leaf mode is enabled, non-PS leaf state nodes use their independent
   per-leaf DW layer instead of the global counter. */
static uint32_t node_nsequence(const factory_t *f, const factory_node_t *node) {
    /* Static-near-root: kickoff-only nodes (no paired state) have no DW
       counter contribution; spend uses CLTV timeout only.  BIP-68 must be
       enabled (nsequence < 0xFFFFFFFE) so the CLTV (nLockTime) takes effect.
       Check BEFORE the generic NODE_KICKOFF branch which would return
       0xFFFFFFFF (BIP-68 disabled). */
    if (node->is_static_only)
        return 0xFFFFFFFEu;
    if (node->type == NODE_KICKOFF)
        return NSEQUENCE_DISABLE_BIP68;
    if (node->is_ps_leaf)
        return 0xFFFFFFFEu;
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
    if (f->n_nodes >= f->config.max_nodes) return -1;

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
        unsigned char hash[32];
        uint32_t epoch = f->counter.current_epoch;

        /* Use pre-computed hash if available (client side has hashes
           but not secrets), otherwise derive from secret (LSP side). */
        if (f->n_l_stock_hashes > 0) {
            if (epoch >= f->n_l_stock_hashes) return 0;
            memcpy(hash, f->l_stock_hashes[epoch], 32);
        } else {
            unsigned char secret[32];
            if (f->use_flat_secrets) {
                if (epoch >= f->n_revocation_secrets) return 0;
                memcpy(secret, f->revocation_secrets[epoch], 32);
            } else {
                uint64_t sc_index = shachain_epoch_to_index(epoch);
                shachain_from_seed(f->shachain_seed, sc_index, secret);
            }
            sha256(secret, 32, hash);
            memset(secret, 0, 32);
        }

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

    /*
     * Build the CLTV recovery merkle root for channel outputs (once, reused
     * for both channels on this leaf node).  When cltv_timeout > 0 we embed a
     * single-leaf taptree whose script is:
     *   <cltv_timeout> OP_CLTV OP_DROP <lsp_xonly> OP_CHECKSIG
     * so the LSP can sweep the output unilaterally after the factory expires,
     * without requiring the client to cooperate.  When cltv_timeout == 0 the
     * outputs remain key-path-only (pure MuSig2 spend).
     */
    unsigned char chan_cltv_merkle[32];
    tapscript_leaf_t chan_cltv_leaf;
    const unsigned char *chan_merkle_root = NULL;
    if (f->cltv_timeout > 0) {
        secp256k1_xonly_pubkey lsp_xonly;
        if (secp256k1_xonly_pubkey_from_pubkey(f->ctx, &lsp_xonly, NULL, &f->pubkeys[0]) &&
            tapscript_build_cltv_timeout(&chan_cltv_leaf, f->cltv_timeout,
                                         &lsp_xonly, f->ctx)) {
            tapscript_merkle_root(chan_cltv_merkle, &chan_cltv_leaf, 1);
            chan_merkle_root = chan_cltv_merkle;
        }
    }

    /* Channel A: MuSig(client_a, LSP) [+ CLTV recovery leaf] */
    {
        secp256k1_pubkey pks[2] = { f->pubkeys[client_a_idx], f->pubkeys[0] };
        musig_keyagg_t ka;
        secp256k1_xonly_pubkey tw;
        if (!build_musig_p2tr_spk(f->ctx, node->outputs[0].script_pubkey,
                                   &tw, NULL, &ka, pks, 2, chan_merkle_root))
            return 0;
        node->outputs[0].script_pubkey_len = 34;
        node->outputs[0].amount_sats = per_output;
    }

    /* Channel B: MuSig(client_b, LSP) [+ CLTV recovery leaf] */
    {
        secp256k1_pubkey pks[2] = { f->pubkeys[client_b_idx], f->pubkeys[0] };
        musig_keyagg_t ka;
        secp256k1_xonly_pubkey tw;
        if (!build_musig_p2tr_spk(f->ctx, node->outputs[1].script_pubkey,
                                   &tw, NULL, &ka, pks, 2, chan_merkle_root))
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

/* Compute BIP-341 sighash for a factory node's input.
   PS leaf chain advances (ps_chain_len > 0) spend the channel output (vout 0)
   of the previous chain TX rather than the parent KO node's output. */
static int compute_node_sighash(const factory_t *f, const factory_node_t *node,
                                 unsigned char *sighash_out) {
    const unsigned char *prev_spk;
    size_t prev_spk_len;
    uint64_t prev_amount;

    if (node->is_ps_leaf && node->ps_chain_len > 0) {
        /* Spending vout 0 (channel output) of the previous chain TX.
           Channel SPK is node->outputs[0] (unchanged between advances). */
        prev_spk = node->outputs[0].script_pubkey;
        prev_spk_len = node->outputs[0].script_pubkey_len;
        prev_amount = node->ps_prev_chan_amount;
    } else if (node->parent_index < 0) {
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

/* Compute the DW counter n_layers given a tree depth and the static-near-root
   threshold (Phase 3 of mixed-arity plan).  Depths [0, threshold) are
   kickoff-only and contribute no DW layers; depths [threshold, depth] each
   get a DW layer.  Caps at DW_MAX_LAYERS.  Always returns >= 1 to keep the
   counter array valid (a degenerate fully-static tree leaves a single unused
   layer slot rather than 0). */
static int dw_n_layers_for(int tree_depth, uint32_t static_threshold) {
    int t = (int)static_threshold;
    if (t < 0) t = 0;
    if (t > tree_depth + 1) t = tree_depth + 1;
    int n = tree_depth - t + 1;
    if (n < 1) n = 1;
    if (n > (int)DW_MAX_LAYERS) n = (int)DW_MAX_LAYERS;
    return n;
}

/* ---- Public API ---- */

void factory_config_default(factory_config_t *cfg) {
    cfg->max_signers = FACTORY_MAX_SIGNERS;
    cfg->max_nodes = FACTORY_MAX_NODES;
    cfg->max_leaves = FACTORY_MAX_LEAVES;
    cfg->max_outputs_per_node = FACTORY_MAX_OUTPUTS;
    cfg->dust_limit_sats = 546;
}

int factory_init_with_config(factory_t *f, secp256k1_context *ctx,
                              const secp256k1_keypair *keypairs, size_t n_participants,
                              uint16_t step_blocks, uint32_t states_per_layer,
                              const factory_config_t *cfg) {
    memset(f, 0, sizeof(*f));
    f->ctx = ctx;
    f->n_participants = n_participants;
    f->step_blocks = step_blocks;
    f->states_per_layer = states_per_layer;
    f->fee_per_tx = 200;

    /* Store config */
    if (cfg)
        f->config = *cfg;
    else
        factory_config_default(&f->config);

    if (n_participants > f->config.max_signers)
        return 0;

    for (size_t i = 0; i < n_participants; i++) {
        f->keypairs[i] = keypairs[i];
        if (!secp256k1_keypair_pub(ctx, &f->pubkeys[i], &keypairs[i]))
            return 0;
    }

    f->leaf_arity = FACTORY_ARITY_2;
    size_t nc = (n_participants > 1) ? n_participants - 1 : 1;
    int n_leaves = compute_leaf_count(nc, FACTORY_ARITY_2);
    int n_layers = compute_tree_depth(nc, FACTORY_ARITY_2) + 1;
    f->n_leaf_nodes = n_leaves;
    dw_counter_init(&f->counter, n_layers, step_blocks, states_per_layer);

    for (int i = 0; i < n_leaves; i++)
        dw_layer_init(&f->leaf_layers[i], step_blocks, states_per_layer);
    f->per_leaf_enabled = 0;
    f->placement_mode = PLACEMENT_TIMEZONE_CLUSTER;
    return 1;
}

int factory_init(factory_t *f, secp256k1_context *ctx,
                 const secp256k1_keypair *keypairs, size_t n_participants,
                 uint16_t step_blocks, uint32_t states_per_layer) {
    return factory_init_with_config(f, ctx, keypairs, n_participants,
                                     step_blocks, states_per_layer, NULL);
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
    factory_config_default(&f->config);

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
    f->placement_mode = PLACEMENT_TIMEZONE_CLUSTER;
}

void factory_set_arity(factory_t *f, factory_arity_t arity) {
    f->leaf_arity = arity;
    f->n_level_arity = 0;  /* clear variable arity */
    size_t nc = (f->n_participants > 1) ? f->n_participants - 1 : 1;
    int n_leaves = compute_leaf_count(nc, arity);
    int tree_depth = compute_tree_depth(nc, arity);
    /* For arity-only (no variable arity set), threshold defaults to 0
       so this is a no-op for backward compat. */
    int n_layers = dw_n_layers_for(tree_depth, f->static_threshold_depth);
    f->n_leaf_nodes = n_leaves;
    dw_counter_init(&f->counter, n_layers, f->step_blocks, f->states_per_layer);
    for (int i = 0; i < n_leaves; i++)
        dw_layer_init(&f->leaf_layers[i], f->step_blocks, f->states_per_layer);
    f->per_leaf_enabled = 0;
}

/* Return the arity at a given tree depth. If variable arity is set,
   look up level_arity[depth]; if depth >= n_level_arity, use the last entry.
   If variable arity is not set, use uniform leaf_arity. */
static int arity_at_depth(const factory_t *f, int depth) {
    if (f->n_level_arity == 0)
        return (int)f->leaf_arity;
    if (depth < (int)f->n_level_arity)
        return (int)f->level_arity[depth];
    return (int)f->level_arity[f->n_level_arity - 1];
}

/* Determine if a subtree of `nc` clients is a leaf at a level whose arity is `a`. */
static int subtree_is_leaf(int a, size_t nc) {
    /* arity-1 / PS: 1 client per leaf */
    if (a == 1 || a == FACTORY_ARITY_PS) return (nc <= 1);
    /* arity-A (A >= 2): up to A clients per leaf */
    return (nc <= (size_t)a);
}

/* Split `nc` clients into N children at a level whose arity is `a`.
   Writes the per-child client counts into out[] (length n_children) and
   returns the number of children produced (1..a).

   Backwards-compat invariant: when `a == 2`, this MUST produce the SAME
   shape as the legacy binary `build_subtree` algorithm so that
   uniform arity-2 deployments are bit-identical to today's tree.

   For arity A > 2: distribute clients into A children, each child getting
   roughly the same number of leaves' worth of clients. We compute how many
   leaves at the next level will fit per child (target_leaves_per_child) and
   pack clients greedily. */
static size_t split_clients_for_arity(int a, size_t nc, size_t out[]) {
    if (a == 1 || a == FACTORY_ARITY_PS) {
        /* Binary split (matches legacy arity-1/PS behavior) */
        out[0] = nc / 2;
        out[1] = nc - out[0];
        return 2;
    }
    if (a == 2) {
        /* EXACT legacy arity-2 binary split — preserves backwards compat */
        size_t total_leaves_est = (nc + 1) / 2;
        size_t left_leaves = total_leaves_est / 2;
        size_t left_n = left_leaves * 2;
        if (left_n > nc) left_n = nc;
        size_t right_n = nc - left_n;
        out[0] = left_n;
        out[1] = right_n;
        return 2;
    }
    /* arity A >= 3 (true N-way): split into up to A children, each getting up
       to A clients (the next level's leaf capacity). For simplicity we use
       the SAME arity for the next level when computing capacity — which is
       true for uniform arity but may slightly mis-estimate for mixed-arity.
       The estimator is only used to bound the split; the actual leaf shape
       is determined by recursion. */
    size_t children = 0;
    size_t remaining = nc;
    /* Distribute as: pack `a` clients into each child until <=a remain;
       then everything goes into the last child. */
    while (remaining > 0 && children < (size_t)a) {
        size_t this_child;
        size_t children_left = (size_t)a - children;
        /* Spread remaining evenly: ceil(remaining / children_left) */
        this_child = (remaining + children_left - 1) / children_left;
        if (this_child > remaining) this_child = remaining;
        out[children++] = this_child;
        remaining -= this_child;
    }
    /* Any remaining (shouldn't happen if a covers nc) — append to last */
    if (remaining > 0 && children > 0)
        out[children - 1] += remaining;
    return children;
}

/* Simulate the variable-arity tree to compute leaf count and max depth.
   Returns leaf count via *leaves_out and max depth via *depth_out. */
typedef struct { size_t nc; int depth; } simulate_frame_t;

static void simulate_tree(const factory_t *f, size_t n_clients,
                           int *depth_out, int *leaves_out) {
    /* Recursive simulation via stack */
    int leaves = 0;
    int max_depth = 0;
    simulate_frame_t stack[FACTORY_MAX_NODES];
    int sp = 0;
    stack[sp].nc = n_clients;
    stack[sp].depth = 0;
    sp++;
    while (sp > 0) {
        size_t nc = stack[sp - 1].nc;
        int d = stack[sp - 1].depth;
        sp--;
        if (nc == 0) continue;
        if (d > max_depth) max_depth = d;
        int a = arity_at_depth(f, d);
        if (subtree_is_leaf(a, nc)) {
            leaves++;
        } else {
            size_t parts[FACTORY_MAX_OUTPUTS];
            size_t n_parts = split_clients_for_arity(a, nc, parts);
            for (size_t k = 0; k < n_parts; k++) {
                if (sp + 1 > FACTORY_MAX_NODES) {
                    fprintf(stderr, "simulate_tree: stack overflow (sp=%d)\n", sp);
                    break;
                }
                stack[sp].nc = parts[k];
                stack[sp].depth = d + 1;
                sp++;
            }
        }
    }
    *depth_out = max_depth;
    *leaves_out = leaves;
}

void factory_set_level_arity(factory_t *f, const uint8_t *arities, size_t n) {
    if (n > FACTORY_MAX_LEVELS) n = FACTORY_MAX_LEVELS;
    memcpy(f->level_arity, arities, n);
    f->n_level_arity = n;
    /* Set leaf_arity to the last entry for backward-compat code paths */
    f->leaf_arity = (factory_arity_t)arities[n - 1];

    size_t nc = (f->n_participants > 1) ? f->n_participants - 1 : 1;
    int depth, n_leaves;
    simulate_tree(f, nc, &depth, &n_leaves);
    int n_layers = dw_n_layers_for(depth, f->static_threshold_depth);
    f->n_leaf_nodes = n_leaves;
    dw_counter_init(&f->counter, n_layers, f->step_blocks, f->states_per_layer);
    for (int i = 0; i < n_leaves; i++)
        dw_layer_init(&f->leaf_layers[i], f->step_blocks, f->states_per_layer);
    f->per_leaf_enabled = 0;
}

void factory_set_static_near_root(factory_t *f, uint32_t threshold) {
    f->static_threshold_depth = threshold;
    /* Recompute n_layers based on current arity/level configuration, since
       the threshold shrinks the DW counter shape. */
    size_t nc = (f->n_participants > 1) ? f->n_participants - 1 : 1;
    int depth, n_leaves;
    if (f->n_level_arity > 0) {
        simulate_tree(f, nc, &depth, &n_leaves);
    } else {
        depth = compute_tree_depth(nc, f->leaf_arity);
        n_leaves = compute_leaf_count(nc, f->leaf_arity);
    }
    int n_layers = dw_n_layers_for(depth, threshold);
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
    if (spk_len > sizeof(f->funding_spk)) {
        fprintf(stderr, "factory_set_funding: spk_len %zu exceeds buffer\n", spk_len);
        return;
    }
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

    /* CLTV recovery leaf (same construction as setup_leaf_outputs) */
    unsigned char chan_cltv_merkle[32];
    tapscript_leaf_t chan_cltv_leaf;
    const unsigned char *chan_merkle_root = NULL;
    if (f->cltv_timeout > 0) {
        secp256k1_xonly_pubkey lsp_xonly;
        if (secp256k1_xonly_pubkey_from_pubkey(f->ctx, &lsp_xonly, NULL, &f->pubkeys[0]) &&
            tapscript_build_cltv_timeout(&chan_cltv_leaf, f->cltv_timeout,
                                         &lsp_xonly, f->ctx)) {
            tapscript_merkle_root(chan_cltv_merkle, &chan_cltv_leaf, 1);
            chan_merkle_root = chan_cltv_merkle;
        }
    }

    /* Channel: MuSig(client, LSP) [+ CLTV recovery leaf] */
    {
        secp256k1_pubkey pks[2] = { f->pubkeys[client_idx], f->pubkeys[0] };
        musig_keyagg_t ka;
        secp256k1_xonly_pubkey tw;
        if (!build_musig_p2tr_spk(f->ctx, node->outputs[0].script_pubkey,
                                   &tw, NULL, &ka, pks, 2, chan_merkle_root))
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

/* Set up pseudo-Spilman leaf outputs.
   vout 0 (channel): uses node->spending_spk — the factory-consensus N-party
   MuSig P2TR already set by add_node().  This is critical: factory_sign_node()
   signs chain[1]+ with node->keyagg (= the same N-party key), so the channel
   output must commit to that same key for on-chain signature verification.
   vout 1 (L-stock): standard LSP-only P2TR. */
static int setup_ps_leaf_outputs(
    factory_t *f,
    factory_node_t *node,
    uint32_t client_idx,
    uint64_t input_amount
) {
    (void)client_idx;  /* PS leaves use the factory consensus key for vout 0 */

    uint64_t output_total = input_amount > f->fee_per_tx
                            ? input_amount - f->fee_per_tx : 0;
    uint64_t per_output  = output_total / 2;
    uint64_t remainder   = output_total - per_output * 2;

    if (per_output < CHANNEL_DUST_LIMIT_SATS) {
        fprintf(stderr, "Factory: PS leaf output %llu below dust limit\n",
                (unsigned long long)per_output);
        return 0;
    }

    node->n_outputs = 2;

    /* vout 0: channel output — factory-consensus key so chain[1]+ signatures
       (signed with node->keyagg) verify correctly on-chain. */
    memcpy(node->outputs[0].script_pubkey, node->spending_spk,
           node->spending_spk_len);
    node->outputs[0].script_pubkey_len = node->spending_spk_len;
    node->outputs[0].amount_sats = per_output;

    /* vout 1: L-stock */
    if (!build_l_stock_spk(f, node->outputs[1].script_pubkey))
        return 0;
    node->outputs[1].script_pubkey_len = 34;
    node->outputs[1].amount_sats = per_output + remainder;

    node->is_ps_leaf = 1;
    node->ps_chain_len = 0;
    memset(node->ps_prev_txid, 0, 32);
    node->ps_prev_chan_amount = 0;
    return 1;
}

/* ---- Generalized N-participant tree builder ---- */

#define TIMEOUT_STEP_BLOCKS 5

/* Compute tree depth (number of binary splits above the leaves).
   n_clients = n_participants - 1 (excluding LSP).
   Arity-2:  each leaf holds 2 clients → ceil(log2(ceil(n_clients/2))) splits.
   Arity-1:  each leaf holds 1 client  → ceil(log2(n_clients)) splits.
   Arity-PS: same as arity-1 (1 client per leaf, PS chain replaces leaf DW layer).
   Returns 0 for a single leaf (1 or 2 clients depending on arity). */
static int compute_tree_depth(size_t n_clients, factory_arity_t arity) {
    size_t n_leaves;
    if (arity == FACTORY_ARITY_1 || arity == FACTORY_ARITY_PS)
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
   Arity-2: ceil(n_clients / 2).  Arity-1 / Arity-PS: n_clients. */
static int compute_leaf_count(size_t n_clients, factory_arity_t arity) {
    if (arity == FACTORY_ARITY_1 || arity == FACTORY_ARITY_PS)
        return (int)n_clients;
    return (int)((n_clients + 1) / 2);
}

/* Set up N-way leaf outputs for arity A >= 2.
   Produces n_outputs = n_client + 1: one MuSig(client_i, LSP) channel per
   client, plus one L-stock output at the LAST index.  Each channel output
   may include the CLTV recovery script-path leaf (when f->cltv_timeout > 0). */
static int setup_nway_leaf_outputs(
    factory_t *f,
    factory_node_t *node,
    const uint32_t *client_indices,
    size_t n_client,
    uint64_t input_amount
) {
    /* Need n_client + 1 outputs (channels + L-stock); +1 division slot for fee */
    size_t n_outputs = n_client + 1;
    if (n_outputs > f->config.max_outputs_per_node) {
        fprintf(stderr, "Factory: n-way leaf needs %zu outputs > max %u\n",
                n_outputs, f->config.max_outputs_per_node);
        return 0;
    }

    if (input_amount <= f->fee_per_tx) return 0;
    uint64_t output_total = input_amount - f->fee_per_tx;
    uint64_t per_output = output_total / n_outputs;
    uint64_t remainder = output_total - per_output * n_outputs;

    if (per_output < CHANNEL_DUST_LIMIT_SATS) {
        fprintf(stderr, "Factory: n-way leaf output %llu below dust limit\n",
                (unsigned long long)per_output);
        return 0;
    }

    node->n_outputs = n_outputs;

    /* Build CLTV recovery merkle root for channel outputs (reused across all
       channels on this leaf). */
    unsigned char chan_cltv_merkle[32];
    tapscript_leaf_t chan_cltv_leaf;
    const unsigned char *chan_merkle_root = NULL;
    if (f->cltv_timeout > 0) {
        secp256k1_xonly_pubkey lsp_xonly;
        if (secp256k1_xonly_pubkey_from_pubkey(f->ctx, &lsp_xonly, NULL, &f->pubkeys[0]) &&
            tapscript_build_cltv_timeout(&chan_cltv_leaf, f->cltv_timeout,
                                         &lsp_xonly, f->ctx)) {
            tapscript_merkle_root(chan_cltv_merkle, &chan_cltv_leaf, 1);
            chan_merkle_root = chan_cltv_merkle;
        }
    }

    /* One channel per client: vout 0..n_client-1 = MuSig(client_i, LSP). */
    for (size_t i = 0; i < n_client; i++) {
        secp256k1_pubkey pks[2] = { f->pubkeys[client_indices[i]], f->pubkeys[0] };
        musig_keyagg_t ka;
        secp256k1_xonly_pubkey tw;
        if (!build_musig_p2tr_spk(f->ctx, node->outputs[i].script_pubkey,
                                   &tw, NULL, &ka, pks, 2, chan_merkle_root))
            return 0;
        node->outputs[i].script_pubkey_len = 34;
        node->outputs[i].amount_sats = per_output;
    }

    /* L-stock at LAST output (vout n_client) */
    if (!build_l_stock_spk(f, node->outputs[n_client].script_pubkey))
        return 0;
    node->outputs[n_client].script_pubkey_len = 34;
    node->outputs[n_client].amount_sats = per_output + remainder;

    return 1;
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

    /* DW layer index for state nodes: depth maps to (depth - static_threshold).
       Kickoff nodes get dw_layer_index = -1.
       When static-near-root is enabled, depths in [0, threshold) become
       kickoff-only with no paired NODE_STATE — handled below.  This
       remapping ensures that depth=threshold is the FIRST DW layer (index 0). */
    int dw_layer = depth - (int)f->static_threshold_depth;
    if (dw_layer < 0) dw_layer = -1;
    if (dw_layer >= (int)f->counter.n_layers)
        dw_layer = (int)f->counter.n_layers - 1;

    /* Determine if this depth is "static" (kickoff-only, no DW state).
       Static depths still fan out their arity-many children — those children
       spend the kickoff's vout 0..N-1 directly (no state intermediary). */
    int is_static = (depth < (int)f->static_threshold_depth);

    /* Determine if this is a leaf (using per-level arity).  Static nodes
       cannot themselves be leaves — leaves always need a state node to host
       channels + L-stock; the threshold should never be set to swallow the
       entire tree.  Guard against misconfiguration: if a static node has
       only enough clients to be a leaf, we fall back to the non-static
       state-paired path. */
    int cur_arity = arity_at_depth(f, depth);
    int is_leaf = subtree_is_leaf(cur_arity, n_clients);
    if (is_leaf) is_static = 0;

    if (is_static) {
        /* ---- Static (kickoff-only) interior node ---- */
        /* Split clients into N children FIRST so we can size kickoff outputs. */
        size_t parts[FACTORY_MAX_OUTPUTS];
        size_t n_parts = split_clients_for_arity(cur_arity, n_clients, parts);
        if (n_parts < 2 || n_parts > f->config.max_outputs_per_node) {
            fprintf(stderr, "build_subtree(static): invalid n_parts %zu (max %u) at depth %d arity %d\n",
                    n_parts, f->config.max_outputs_per_node, depth, cur_arity);
            return 0;
        }

        /* Create the kickoff node ONLY (no paired state).  No DW layer. */
        int ko_idx = add_node(f, NODE_KICKOFF, signers, n_signers,
                              parent_state_idx, parent_vout, -1, ko_cltv);
        if (ko_idx < 0) return 0;
        f->nodes[ko_idx].is_static_only = 1;
        f->nodes[ko_idx].input_amount = input_amount;

        /* Kickoff has n_parts outputs, one per child.  Distribute the input
           amount minus one fee evenly among children. */
        uint64_t fee = f->fee_per_tx;
        if (input_amount <= fee) return 0;
        uint64_t kickoff_budget = input_amount - fee;
        uint64_t per_child_budget = kickoff_budget / n_parts;
        uint64_t budget_remainder = kickoff_budget - per_child_budget * n_parts;

        f->nodes[ko_idx].n_outputs = n_parts;
        /* Outputs will be filled after children are created (need their spk). */

        /* Recurse into each child, remembering its kickoff node index. */
        int child_ko_indices[FACTORY_MAX_OUTPUTS];
        size_t client_offset = 0;
        for (size_t k = 0; k < n_parts; k++) {
            uint64_t child_budget = per_child_budget;
            if (k == n_parts - 1) child_budget += budget_remainder;

            size_t saved_n_nodes = f->n_nodes;
            if (parts[k] == 0) {
                f->nodes[ko_idx].n_outputs--;
                continue;
            }
            if (!build_subtree(f, client_indices + client_offset, parts[k],
                               ko_idx, (uint32_t)k, depth + 1, max_depth,
                               child_budget, leaf_counter))
                return 0;
            child_ko_indices[k] = (int)saved_n_nodes;
            client_offset += parts[k];
        }

        /* Wire kickoff outputs to each child's spending_spk.  When the child
           is itself a static node, its first node is the static kickoff;
           when it's a regular subtree, its first node is the regular kickoff.
           Either way we point at child_ko_indices[k]->spending_spk. */
        for (size_t k = 0; k < f->nodes[ko_idx].n_outputs; k++) {
            uint64_t child_budget = per_child_budget;
            if (k == f->nodes[ko_idx].n_outputs - 1) child_budget += budget_remainder;
            f->nodes[ko_idx].outputs[k].amount_sats = child_budget;
            memcpy(f->nodes[ko_idx].outputs[k].script_pubkey,
                   f->nodes[child_ko_indices[k]].spending_spk, 34);
            f->nodes[ko_idx].outputs[k].script_pubkey_len = 34;
        }
        return 1;
    }

    /* ---- Regular (kickoff/state pair) node ---- */

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
    if (input_amount <= fee) return 0;
    uint64_t ko_out_amount = input_amount - fee;

    f->nodes[ko_idx].n_outputs = 1;
    f->nodes[ko_idx].outputs[0].amount_sats = ko_out_amount;
    memcpy(f->nodes[ko_idx].outputs[0].script_pubkey,
           f->nodes[st_idx].spending_spk, 34);
    f->nodes[ko_idx].outputs[0].script_pubkey_len = 34;
    f->nodes[ko_idx].input_amount = input_amount;

    if (is_leaf) {
        /* Leaf node: set up channel outputs */
        f->nodes[st_idx].input_amount = ko_out_amount;

        if (cur_arity == FACTORY_ARITY_PS) {
            /* Pseudo-Spilman leaf: 1 client, chained TXs instead of DW nSequence */
            if (!setup_ps_leaf_outputs(f, &f->nodes[st_idx],
                                       client_indices[0], ko_out_amount))
                return 0;
        } else if (n_clients == 1) {
            if (!setup_single_leaf_outputs(f, &f->nodes[st_idx],
                                           client_indices[0], ko_out_amount))
                return 0;
        } else if (cur_arity == 2 && n_clients == 2) {
            /* Arity-2 leaf: keep legacy code path (bit-identical for backwards compat) */
            if (!setup_leaf_outputs(f, &f->nodes[st_idx],
                                    client_indices[0], client_indices[1],
                                    ko_out_amount))
                return 0;
        } else {
            /* True N-way leaf (arity >= 2 with N >= 2 clients).  Used when
               cur_arity > 2 OR when cur_arity == 2 but with the generalized
               builder.  Produces n_clients channels + 1 L-stock output. */
            if (!setup_nway_leaf_outputs(f, &f->nodes[st_idx],
                                         client_indices, n_clients,
                                         ko_out_amount))
                return 0;
        }

        /* Record leaf index */
        if (*leaf_counter >= FACTORY_MAX_LEAVES) return 0;
        f->leaf_node_indices[*leaf_counter] = (size_t)st_idx;
        (*leaf_counter)++;
    } else {
        /* Internal node: split clients into N children per arity */
        size_t parts[FACTORY_MAX_OUTPUTS];
        size_t n_parts = split_clients_for_arity(cur_arity, n_clients, parts);
        if (n_parts < 2 || n_parts > f->config.max_outputs_per_node) {
            fprintf(stderr, "build_subtree: invalid n_parts %zu (max %u) at depth %d arity %d\n",
                    n_parts, f->config.max_outputs_per_node, depth, cur_arity);
            return 0;
        }

        /* State node has n_parts outputs, one per child */
        if (ko_out_amount <= fee) return 0;
        uint64_t state_budget = ko_out_amount - fee;
        /* Distribute state budget evenly among children, with remainder to last */
        uint64_t per_child_budget = state_budget / n_parts;
        uint64_t budget_remainder = state_budget - per_child_budget * n_parts;

        f->nodes[st_idx].input_amount = ko_out_amount;
        f->nodes[st_idx].n_outputs = n_parts;
        /* Outputs will be filled after children are created (need their spk) */

        /* Recurse into each child, remembering its kickoff node index */
        int child_ko_indices[FACTORY_MAX_OUTPUTS];
        size_t client_offset = 0;
        for (size_t k = 0; k < n_parts; k++) {
            uint64_t child_budget = per_child_budget;
            if (k == n_parts - 1) child_budget += budget_remainder;

            size_t saved_n_nodes = f->n_nodes;
            if (parts[k] == 0) {
                /* Empty child: shouldn't happen with split_clients_for_arity,
                   but guard against it. Drop the slot. */
                f->nodes[st_idx].n_outputs--;
                continue;
            }
            if (!build_subtree(f, client_indices + client_offset, parts[k],
                               st_idx, (uint32_t)k, depth + 1, max_depth,
                               child_budget, leaf_counter))
                return 0;
            child_ko_indices[k] = (int)saved_n_nodes;
            client_offset += parts[k];
        }

        /* Wire state outputs to each child's kickoff spending_spk */
        for (size_t k = 0; k < f->nodes[st_idx].n_outputs; k++) {
            uint64_t child_budget = per_child_budget;
            if (k == f->nodes[st_idx].n_outputs - 1) child_budget += budget_remainder;
            f->nodes[st_idx].outputs[k].amount_sats = child_budget;
            memcpy(f->nodes[st_idx].outputs[k].script_pubkey,
                   f->nodes[child_ko_indices[k]].spending_spk, 34);
            f->nodes[st_idx].outputs[k].script_pubkey_len = 34;
        }
    }

    return 1;
}

int factory_build_tree(factory_t *f) {
    size_t n_clients = f->n_participants - 1;

    /* Validate participant count */
    if (f->n_participants < 2 || f->n_participants > f->config.max_signers) {
        fprintf(stderr, "factory_build_tree: invalid participant count %zu (need 2..%u)\n",
                f->n_participants, f->config.max_signers);
        return 0;
    }

    /* Arity-2 needs at least 2 clients (paired leaves) */
    if (f->leaf_arity == FACTORY_ARITY_2 && n_clients < 2) {
        fprintf(stderr, "factory_build_tree: arity-2 requires at least 2 clients, got %zu\n",
                n_clients);
        return 0;
    }

    /* Override fee_per_tx from fee estimator if available */
    if (f->fee) {
        f->fee_per_tx = fee_for_factory_tx(f->fee, 3);
    }

    /* Compute tree metrics (variable arity uses simulation) */
    int tree_depth, n_leaves;
    if (f->n_level_arity > 0) {
        simulate_tree(f, n_clients, &tree_depth, &n_leaves);
    } else {
        tree_depth = compute_tree_depth(n_clients, f->leaf_arity);
        n_leaves = compute_leaf_count(n_clients, f->leaf_arity);
    }
    /* Phase 3: respect static_threshold_depth — only non-static depths get
       DW layers. */
    int n_dw_layers = dw_n_layers_for(tree_depth, f->static_threshold_depth);
    int total_nodes_ub = 2 * (2 * n_leaves - 1);  /* kickoff+state per logical node */

    if (total_nodes_ub > (int)f->config.max_nodes) return 0;
    if (n_leaves > (int)f->config.max_leaves) return 0;
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

    /* Apply placement strategy */
    if (f->placement_mode == PLACEMENT_INWARD && n_clients > 1) {
        g_sort_factory = f;
        qsort(clients, n_clients, sizeof(uint32_t), cmp_balance_desc);
        g_sort_factory = NULL;
    } else if (f->placement_mode == PLACEMENT_OUTWARD && n_clients > 1) {
        g_sort_factory = f;
        qsort(clients, n_clients, sizeof(uint32_t), cmp_uptime_asc);
        g_sort_factory = NULL;
    } else if (f->placement_mode == PLACEMENT_TIMEZONE_CLUSTER && n_clients > 1) {
        g_sort_factory = f;
        qsort(clients, n_clients, sizeof(uint32_t), cmp_timezone_cluster);
        g_sort_factory = NULL;
    }

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

size_t factory_count_nodes_for_participant(const factory_t *f,
                                            uint32_t participant_idx) {
    size_t count = 0;
    for (size_t i = 0; i < f->n_nodes; i++) {
        for (size_t s = 0; s < f->nodes[i].n_signers; s++) {
            if (f->nodes[i].signer_indices[s] == participant_idx) {
                count++;
                break;
            }
        }
    }
    return count;
}

/* --- Path-scoped signing implementation --- */

int factory_sessions_init_path(factory_t *f, int leaf_node_idx) {
    int path[FACTORY_MAX_NODES];
    size_t n = factory_collect_path_to_root(f, leaf_node_idx, path, FACTORY_MAX_NODES);
    if (n == 0) return 0;

    for (size_t i = 0; i < n; i++) {
        factory_node_t *node = &f->nodes[path[i]];
        if (!node->is_built) return 0;
        musig_session_init(&node->signing_session, &node->keyagg, node->n_signers);
        node->partial_sigs_received = 0;
    }
    return 1;
}

int factory_sessions_finalize_path(factory_t *f, int leaf_node_idx) {
    int path[FACTORY_MAX_NODES];
    size_t n = factory_collect_path_to_root(f, leaf_node_idx, path, FACTORY_MAX_NODES);
    if (n == 0) return 0;

    for (size_t i = 0; i < n; i++) {
        factory_node_t *node = &f->nodes[path[i]];

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

int factory_sessions_complete_path(factory_t *f, int leaf_node_idx) {
    int path[FACTORY_MAX_NODES];
    size_t n = factory_collect_path_to_root(f, leaf_node_idx, path, FACTORY_MAX_NODES);
    if (n == 0) return 0;

    for (size_t i = 0; i < n; i++) {
        factory_node_t *node = &f->nodes[path[i]];

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

int factory_rebuild_path_unsigned(factory_t *f, int leaf_node_idx) {
    int path[FACTORY_MAX_NODES];
    size_t n = factory_collect_path_to_root(f, leaf_node_idx, path, FACTORY_MAX_NODES);
    if (n == 0) return 0;

    /* Rebuild unsigned txs for path nodes only (root-first order) */
    for (size_t i = 0; i < n; i++) {
        factory_node_t *node = &f->nodes[path[i]];

        /* Determine input */
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

        unsigned char display_txid[32];
        tx_buf_t utx;
        tx_buf_init(&utx, 256);
        if (!build_unsigned_tx(&utx, display_txid,
                                input_txid, input_vout,
                                node->nsequence,
                                node->outputs, node->n_outputs)) {
            tx_buf_free(&utx);
            return 0;
        }

        /* Update node */
        tx_buf_free(&node->unsigned_tx);
        node->unsigned_tx = utx;
        node->is_signed = 0;

        /* Convert display-order txid to internal byte order */
        memcpy(node->txid, display_txid, 32);
        reverse_bytes(node->txid, 32);
    }
    return 1;
}

int factory_advance_and_rebuild_path(factory_t *f, int leaf_side) {
    int ret = factory_advance_leaf_unsigned(f, leaf_side);
    if (ret == 0) return -2;  /* fully exhausted */
    if (ret < 0) {
        /* Leaf exhausted, root layer advanced — rebuild path */
        int leaf_state_idx = (int)f->leaf_node_indices[leaf_side];
        if (!factory_rebuild_path_unsigned(f, leaf_state_idx))
            return -1;
        return leaf_state_idx;
    }
    /* Normal advance, only leaf node changed */
    return (int)f->leaf_node_indices[leaf_side];
}


int factory_verify_all(factory_t *f) {
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *node = &f->nodes[i];
        if (!node->is_signed) continue;

        unsigned char sighash[32];
        if (!compute_node_sighash(f, node, sighash))
            return 0;

        /* Sig is 64 bytes before the 4-byte nLockTime */
        if (node->signed_tx.len < 70) return 0;
        unsigned char sig[64];
        memcpy(sig, node->signed_tx.data + node->signed_tx.len - 68, 64);

        if (!secp256k1_schnorrsig_verify(f->ctx, sig, sighash, 32,
                                          &node->tweaked_pubkey)) {
            fprintf(stderr, "factory_verify_all: node %zu sig INVALID\n", i);
            return 0;
        }
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

/* Rebuild unsigned tx for a single node.
   PS leaf chain advances (ps_chain_len > 0) spend the channel output of the
   previous chain TX (ps_prev_txid:0) rather than the parent KO's output. */
static int rebuild_node_tx(factory_t *f, size_t node_idx) {
    if (node_idx >= f->n_nodes) return 0;
    factory_node_t *node = &f->nodes[node_idx];
    unsigned char display_txid[32];

    const unsigned char *input_txid;
    uint32_t input_vout;

    if (node->is_ps_leaf && node->ps_chain_len > 0) {
        input_txid = node->ps_prev_txid;
        input_vout = 0;
    } else if (node->parent_index < 0) {
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

/* Public wrapper for rebuild_node_tx. */
int factory_rebuild_node_tx(factory_t *f, size_t node_idx) {
    return rebuild_node_tx(f, node_idx);
}

#define DUST_LIMIT_SATS 546

int factory_set_leaf_amounts(factory_t *f, int leaf_side,
                              const uint64_t *amounts, size_t n_amounts) {
    if (leaf_side < 0 || leaf_side >= f->n_leaf_nodes) return 0;
    size_t node_idx = f->leaf_node_indices[leaf_side];
    factory_node_t *node = &f->nodes[node_idx];

    if (n_amounts != node->n_outputs) return 0;

    /* Compute current output total */
    uint64_t current_total = 0;
    for (size_t i = 0; i < node->n_outputs; i++)
        current_total += node->outputs[i].amount_sats;

    /* Validate new amounts sum = current total (conservation of funds) */
    uint64_t new_total = 0;
    for (size_t i = 0; i < n_amounts; i++) {
        if (amounts[i] < DUST_LIMIT_SATS) return 0;
        new_total += amounts[i];
    }
    if (new_total != current_total) return 0;

    /* Update amounts */
    for (size_t i = 0; i < n_amounts; i++)
        node->outputs[i].amount_sats = amounts[i];

    /* Rebuild unsigned tx with new amounts */
    return rebuild_node_tx(f, node_idx);
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

    size_t node_idx = f->leaf_node_indices[leaf_side];
    factory_node_t *node = &f->nodes[node_idx];

    /* PS leaf: append a new TX to the chain rather than decrement nSequence.
       chain[1]+: single channel output (full input minus fee). The L-stock was
       committed once at chain[0] and already exists as a separate on-chain UTXO;
       we must not re-split it here or call update_l_stock_for_leaf (which would
       overwrite outputs[0].script_pubkey when n_outputs==1). */
    if (node->is_ps_leaf) {
        memcpy(node->ps_prev_txid, node->txid, 32);
        node->ps_prev_chan_amount = node->outputs[0].amount_sats;
        node->ps_chain_len++;
        if (node->ps_prev_chan_amount <= f->fee_per_tx) return 0;
        uint64_t out_total = node->ps_prev_chan_amount - f->fee_per_tx;
        if (out_total < CHANNEL_DUST_LIMIT_SATS) return 0;
        node->n_outputs = 1;
        node->outputs[0].amount_sats = out_total;
        /* outputs[0].script_pubkey unchanged — still node->spending_spk */
        if (!rebuild_node_tx(f, node_idx)) return 0;
        return factory_sign_node(f, node_idx);
    }

    f->per_leaf_enabled = 1;

    /* DW leaf: advance per-leaf counter */
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
    if (!update_l_stock_for_leaf(f, node_idx)) return 0;
    if (!rebuild_node_tx(f, node_idx)) return 0;
    return factory_sign_node(f, node_idx);
}

int factory_advance_leaf_unsigned(factory_t *f, int leaf_side) {
    if (leaf_side < 0 || leaf_side >= f->n_leaf_nodes) return 0;

    size_t node_idx = f->leaf_node_indices[leaf_side];
    factory_node_t *node = &f->nodes[node_idx];

    /* PS leaf: chain advance, no DW counter. Same passthrough logic as the
       signed variant — single channel output, no L-stock re-split. */
    if (node->is_ps_leaf) {
        memcpy(node->ps_prev_txid, node->txid, 32);
        node->ps_prev_chan_amount = node->outputs[0].amount_sats;
        node->ps_chain_len++;
        if (node->ps_prev_chan_amount <= f->fee_per_tx) return 0;
        uint64_t out_total = node->ps_prev_chan_amount - f->fee_per_tx;
        if (out_total < CHANNEL_DUST_LIMIT_SATS) return 0;
        node->n_outputs = 1;
        node->outputs[0].amount_sats = out_total;
        if (!rebuild_node_tx(f, node_idx)) return 0;
        return 1;
    }

    f->per_leaf_enabled = 1;

    /* DW leaf: advance per-leaf counter */
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
    if (!compute_node_sighash(f, node, sighash)) {
        fprintf(stderr, "finalize_node %zu: compute_node_sighash failed\n", node_idx);
        return 0;
    }

    const unsigned char *mr = node->has_taptree ? node->merkle_root : NULL;
    int ok = musig_session_finalize_nonces(f->ctx, &node->signing_session,
                                            sighash, mr, NULL);
    if (!ok)
        fprintf(stderr, "finalize_node %zu: musig_session_finalize_nonces failed "
                "(n_signers=%zu, nonces_collected=%d, has_taptree=%d)\n",
                node_idx, node->n_signers,
                node->signing_session.nonces_collected, node->has_taptree);
    return ok;
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

    /* Pre-compute L-stock hashlock hashes: SHA256(secret) per epoch.
       These are sent to clients so they can build matching taptrees. */
    for (size_t i = 0; i < n_epochs; i++)
        sha256(f->revocation_secrets[i], 32, f->l_stock_hashes[i]);
    f->n_l_stock_hashes = n_epochs;

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
    /* Also compute hashes for wire protocol / client matching */
    for (size_t i = 0; i < n_secrets; i++)
        sha256(f->revocation_secrets[i], 32, f->l_stock_hashes[i]);
    f->n_l_stock_hashes = n_secrets;
}

void factory_set_l_stock_hashes(factory_t *f,
                                 const unsigned char hashes[][32],
                                 size_t n_hashes) {
    if (!f || !hashes || n_hashes == 0) return;
    if (n_hashes > FACTORY_MAX_EPOCHS) n_hashes = FACTORY_MAX_EPOCHS;
    memcpy(f->l_stock_hashes, hashes, n_hashes * 32);
    f->n_l_stock_hashes = n_hashes;
    f->has_shachain = 1;  /* enable hashlock taptree in build_l_stock_spk */
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
    size_t n_outputs,
    uint32_t current_height)
{
    /* 1. Build unsigned tx spending the funding UTXO.
       nLockTime = current_height for BIP anti-fee-sniping. */
    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 256);
    unsigned char display_txid[32] = {0};

    if (!build_unsigned_tx_with_locktime(&unsigned_tx,
                            txid_out32 ? display_txid : NULL,
                            f->funding_txid, f->funding_vout,
                            0xFFFFFFFEu, current_height,
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
    size_t n_outputs,
    uint32_t current_height)
{
    unsigned char display_txid[32];
    if (!build_unsigned_tx_with_locktime(unsigned_tx_out, display_txid,
                            f->funding_txid, f->funding_vout,
                            0xFFFFFFFEu, current_height,
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
    /* Build augmented output array with P2A anchor appended.
       Anchor cost deducted from first output (LSP's share). */
    if (n_outputs == 0 || n_outputs > f->n_participants) return 0;
    tx_output_t *aug_outputs = (tx_output_t *)calloc(n_outputs + 1, sizeof(tx_output_t));
    if (!aug_outputs) return 0;
    size_t aug_n = n_outputs;

    for (size_t i = 0; i < n_outputs; i++)
        aug_outputs[i] = outputs[i];

    /* Add P2A anchor output for CPFP fee bumping.
       Skip at sub-1-sat/vB rates where the 240-sat anchor would cost more
       than the entire TX fee, making CPFP uneconomical. */
    if (fee_should_use_anchor(f->fee) &&
        aug_outputs[0].amount_sats > ANCHOR_OUTPUT_AMOUNT) {
        aug_outputs[0].amount_sats -= ANCHOR_OUTPUT_AMOUNT;
        memcpy(aug_outputs[aug_n].script_pubkey, P2A_SPK, P2A_SPK_LEN);
        aug_outputs[aug_n].script_pubkey_len = P2A_SPK_LEN;
        aug_outputs[aug_n].amount_sats = ANCHOR_OUTPUT_AMOUNT;
        aug_n++;
    }

    /* Build unsigned tx with nLockTime spending the funding UTXO.
       nSequence = 0xFFFFFFFE to enable nLockTime. */
    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 256);
    unsigned char display_txid[32] = {0};

    if (!build_unsigned_tx_with_locktime(&unsigned_tx,
                                          txid_out32 ? display_txid : NULL,
                                          f->funding_txid, f->funding_vout,
                                          0xFFFFFFFEu, nlocktime,
                                          aug_outputs, aug_n)) {
        tx_buf_free(&unsigned_tx);
        free(aug_outputs);
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
        free(aug_outputs);
        return 0;
    }

    /* Sign with N-of-N MuSig (same aggregate key as kickoff_root) */
    musig_keyagg_t keyagg_copy = f->nodes[0].keyagg;
    unsigned char sig64[64];
    if (!musig_sign_taproot(f->ctx, sig64, sighash, f->keypairs,
                             f->n_participants, &keyagg_copy, NULL)) {
        tx_buf_free(&unsigned_tx);
        free(aug_outputs);
        return 0;
    }

    /* Finalize */
    if (!finalize_signed_tx(dist_tx_out, unsigned_tx.data, unsigned_tx.len,
                              sig64)) {
        tx_buf_free(&unsigned_tx);
        free(aug_outputs);
        return 0;
    }

    tx_buf_free(&unsigned_tx);
    free(aug_outputs);
    return 1;
}

/* --- Distribution TX (unsigned, for distributed MuSig2 ceremony) --- */

int factory_build_distribution_tx_unsigned(
    factory_t *f,
    const tx_output_t *outputs,
    size_t n_outputs,
    uint32_t nlocktime)
{
    if (!f || !outputs || n_outputs == 0 || n_outputs > f->n_participants)
        return 0;

    /* Build augmented output array with P2A anchor appended */
    tx_output_t *aug_outputs = (tx_output_t *)calloc(n_outputs + 1, sizeof(tx_output_t));
    if (!aug_outputs) return 0;
    size_t aug_n = n_outputs;
    for (size_t i = 0; i < n_outputs; i++)
        aug_outputs[i] = outputs[i];

    if (fee_should_use_anchor(f->fee) &&
        aug_outputs[0].amount_sats > ANCHOR_OUTPUT_AMOUNT) {
        aug_outputs[0].amount_sats -= ANCHOR_OUTPUT_AMOUNT;
        memcpy(aug_outputs[aug_n].script_pubkey, P2A_SPK, P2A_SPK_LEN);
        aug_outputs[aug_n].script_pubkey_len = P2A_SPK_LEN;
        aug_outputs[aug_n].amount_sats = ANCHOR_OUTPUT_AMOUNT;
        aug_n++;
    }

    /* Build unsigned TX with nLockTime */
    tx_buf_free(&f->dist_unsigned_tx);
    tx_buf_init(&f->dist_unsigned_tx, 256);

    if (!build_unsigned_tx_with_locktime(&f->dist_unsigned_tx, NULL,
                                          f->funding_txid, f->funding_vout,
                                          0xFFFFFFFEu, nlocktime,
                                          aug_outputs, aug_n)) {
        tx_buf_free(&f->dist_unsigned_tx);
        free(aug_outputs);
        return 0;
    }

    /* Compute BIP-341 key-path sighash */
    if (!compute_taproot_sighash(f->dist_sighash,
                                  f->dist_unsigned_tx.data,
                                  f->dist_unsigned_tx.len,
                                  0, f->funding_spk, f->funding_spk_len,
                                  f->funding_amount_sats, 0xFFFFFFFEu)) {
        tx_buf_free(&f->dist_unsigned_tx);
        free(aug_outputs);
        return 0;
    }

    free(aug_outputs);
    f->dist_tx_ready = 1;
    return 1;
}

/* Inversion-of-timeout-default: the distribution TX spends the factory
   funding UTXO directly and pays everything to the clients, with nLockTime
   set to the factory's CLTV timeout. The LSP gets NOTHING — no output,
   not even dust. This is the load-bearing security property that makes
   LSP uptime a hard financial obligation (ZmnSCPxj, "SuperScalar" Delving
   post, §"Inversion of Timeout Default"). If the LSP fails to cooperatively
   close or rotate its clients before the CLTV expires, the clients can
   broadcast the distribution TX and recover the full factory funding,
   punishing the LSP for going dark.

   Emits exactly (n_participants - 1) client outputs. Output index 0
   corresponds to participant 1 (first client), index 1 → participant 2,
   etc. The LSP (participant 0) is deliberately skipped. */
size_t factory_compute_distribution_outputs(
    const factory_t *f,
    tx_output_t *outputs_out,
    size_t max_outputs,
    uint64_t fee_sats)
{
    if (!f || !outputs_out || f->n_participants < 2) return 0;
    size_t n_clients = f->n_participants - 1;
    if (max_outputs < n_clients) return 0;
    if (f->funding_amount_sats <= fee_sats) return 0;

    uint64_t budget = f->funding_amount_sats - fee_sats;
    uint64_t per_client = budget / n_clients;
    uint64_t remainder = budget - per_client * n_clients;

    size_t n = 0;
    for (size_t i = 1; i < f->n_participants && n < n_clients; i++) {
        /* Key-path-only P2TR: TapTweak(key, empty) */
        secp256k1_xonly_pubkey xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(f->ctx, &xonly, NULL,
                                                 &f->pubkeys[i]))
            continue;
        unsigned char ser[32];
        if (!secp256k1_xonly_pubkey_serialize(f->ctx, ser, &xonly))
            continue;
        unsigned char tweak[32];
        sha256_tagged("TapTweak", ser, 32, tweak);
        secp256k1_pubkey tweaked_full;
        if (!secp256k1_xonly_pubkey_tweak_add(f->ctx, &tweaked_full,
                                                &xonly, tweak))
            continue;
        secp256k1_xonly_pubkey tweaked;
        if (!secp256k1_xonly_pubkey_from_pubkey(f->ctx, &tweaked, NULL,
                                                 &tweaked_full))
            continue;

        build_p2tr_script_pubkey(outputs_out[n].script_pubkey, &tweaked);
        outputs_out[n].script_pubkey_len = 34;
        outputs_out[n].amount_sats = per_client;
        n++;
    }

    /* Fold integer-division remainder into the first client's output so
       the total never underpays — if any sats would be left stranded by
       the division, the first client eats the surplus. */
    if (n > 0 && remainder > 0)
        outputs_out[0].amount_sats += remainder;

    return n;
}

/* client_amounts are interpreted as per-client account_limits (channel
   capacity), not current balances. On inversion, clients get their
   contracted capacity regardless of how much of it they're holding in
   their local_amount at the time — that's the whole point of the
   property. For homogeneous capacity this is equivalent to the equal-
   split path; the API is kept separate to prepare for heterogeneous-
   capacity factories later. The LSP still gets nothing. */
size_t factory_compute_distribution_outputs_balanced(
    const factory_t *f,
    tx_output_t *outputs_out,
    size_t max_outputs,
    uint64_t fee_sats,
    const uint64_t *client_amounts,
    size_t n_client_amounts)
{
    /* No per-client amounts → equal-split inversion. */
    if (!client_amounts || n_client_amounts == 0)
        return factory_compute_distribution_outputs(f, outputs_out, max_outputs, fee_sats);

    if (!f || !outputs_out || f->n_participants < 2) return 0;
    size_t n_clients = f->n_participants - 1;
    if (max_outputs < n_clients) return 0;
    if (f->funding_amount_sats <= fee_sats) return 0;

    /* Sum requested client amounts; if they add up to less than the
       budget, split the surplus equally across clients (this absorbs the
       leaf L-stock shares that the account_limits don't account for).
       If they add up to MORE than the budget (over-commit bug at factory
       creation), scale proportionally so nothing overflows the funding. */
    uint64_t requested = 0;
    for (size_t ci = 0; ci < n_client_amounts && ci < n_clients; ci++)
        requested += client_amounts[ci];

    uint64_t budget = f->funding_amount_sats - fee_sats;

    size_t n = 0;
    for (size_t i = 1; i < f->n_participants && n < n_clients; i++) {
        secp256k1_xonly_pubkey xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(f->ctx, &xonly, NULL,
                                                 &f->pubkeys[i]))
            continue;
        unsigned char ser[32];
        if (!secp256k1_xonly_pubkey_serialize(f->ctx, ser, &xonly))
            continue;
        unsigned char tweak[32];
        sha256_tagged("TapTweak", ser, 32, tweak);
        secp256k1_pubkey tweaked_full;
        if (!secp256k1_xonly_pubkey_tweak_add(f->ctx, &tweaked_full,
                                                &xonly, tweak))
            continue;
        secp256k1_xonly_pubkey tweaked;
        if (!secp256k1_xonly_pubkey_from_pubkey(f->ctx, &tweaked, NULL,
                                                 &tweaked_full))
            continue;

        build_p2tr_script_pubkey(outputs_out[n].script_pubkey, &tweaked);
        outputs_out[n].script_pubkey_len = 34;

        size_t ci = i - 1;
        uint64_t amt = (ci < n_client_amounts) ? client_amounts[ci] : 0;
        if (requested > budget && requested > 0) {
            amt = (amt * budget) / requested;  /* proportional scale-down */
        }
        outputs_out[n].amount_sats = amt;
        n++;
    }

    /* Spread any surplus (budget > Σ client_amounts — the L-stock share)
       equally across clients. Remainder of that division goes to first. */
    if (n > 0 && requested <= budget) {
        uint64_t surplus = budget - requested;
        uint64_t per = surplus / n;
        uint64_t rem = surplus - per * n;
        for (size_t j = 0; j < n; j++)
            outputs_out[j].amount_sats += per;
        if (rem > 0)
            outputs_out[0].amount_sats += rem;
    }

    return n;
}

/* --- Tree navigation helpers --- */

size_t factory_collect_path_to_root(const factory_t *f, int start_idx,
                                     int *path_out, size_t max_path) {
    if (!f || start_idx < 0 || (size_t)start_idx >= f->n_nodes || max_path == 0)
        return 0;

    /* Walk parent chain, storing in reverse order */
    int tmp[FACTORY_MAX_NODES];
    size_t count = 0;
    int idx = start_idx;
    while (idx >= 0 && count < FACTORY_MAX_NODES) {
        tmp[count++] = idx;
        idx = f->nodes[idx].parent_index;
    }

    /* Reverse into path_out (root-first) */
    size_t written = count < max_path ? count : max_path;
    for (size_t i = 0; i < written; i++)
        path_out[i] = tmp[count - 1 - i];
    return written;
}

size_t factory_get_subtree_clients(const factory_t *f, int node_idx,
                                    uint32_t *clients_out, size_t max_clients) {
    if (!f || node_idx < 0 || (size_t)node_idx >= f->n_nodes)
        return 0;

    const factory_node_t *node = &f->nodes[node_idx];
    size_t count = 0;
    for (size_t i = 0; i < node->n_signers && count < max_clients; i++) {
        if (node->signer_indices[i] != 0)  /* skip LSP */
            clients_out[count++] = node->signer_indices[i];
    }
    return count;
}

int factory_find_leaf_for_client(const factory_t *f, uint32_t client_idx) {
    if (!f || client_idx == 0)
        return -1;

    for (int i = 0; i < f->n_leaf_nodes; i++) {
        size_t ni = f->leaf_node_indices[i];
        const factory_node_t *node = &f->nodes[ni];
        for (size_t s = 0; s < node->n_signers; s++) {
            if (node->signer_indices[s] == client_idx)
                return (int)ni;
        }
    }
    return -1;
}

int factory_build_timeout_spend_tx(
    const factory_t *f,
    const unsigned char *parent_txid,
    uint32_t parent_vout,
    uint64_t spend_amount,
    int target_node_idx,
    const secp256k1_keypair *lsp_keypair,
    const unsigned char *dest_spk,
    size_t dest_spk_len,
    uint64_t fee_sats,
    tx_buf_t *signed_tx_out)
{
    if (!f || !parent_txid || !lsp_keypair || !dest_spk || !signed_tx_out)
        return 0;
    if (target_node_idx < 0 || (size_t)target_node_idx >= f->n_nodes)
        return 0;

    const factory_node_t *target = &f->nodes[target_node_idx];
    if (!target->has_taptree)
        return 0;
    if (fee_sats >= spend_amount)
        return 0;

    /* Build output */
    tx_output_t tout;
    tout.amount_sats = spend_amount - fee_sats;
    memcpy(tout.script_pubkey, dest_spk, dest_spk_len);
    tout.script_pubkey_len = dest_spk_len;

    /* Build unsigned tx with locktime = CLTV timeout */
    tx_buf_t utx;
    tx_buf_init(&utx, 256);
    if (!build_unsigned_tx_with_locktime(&utx, NULL,
            parent_txid, parent_vout, 0xFFFFFFFEu,
            target->cltv_timeout, &tout, 1)) {
        tx_buf_free(&utx);
        return 0;
    }

    /* Compute tapscript sighash */
    unsigned char sighash[32];
    compute_tapscript_sighash(sighash, utx.data, utx.len, 0,
        target->spending_spk, target->spending_spk_len,
        spend_amount, 0xFFFFFFFEu, &target->timeout_leaf);

    /* Sign with LSP keypair (single signer, NOT MuSig) */
    unsigned char sig[64], aux[32];
    memset(aux, 0, 32);
    if (!secp256k1_schnorrsig_sign32(f->ctx, sig, sighash,
                                       lsp_keypair, aux)) {
        tx_buf_free(&utx);
        return 0;
    }

    /* Build control block */
    unsigned char cb[65];
    size_t cb_len;
    tapscript_build_control_block(cb, &cb_len,
        target->output_parity,
        &target->keyagg.agg_pubkey, f->ctx);

    /* Finalize script-path tx */
    if (!finalize_script_path_tx(signed_tx_out, utx.data, utx.len, sig,
            target->timeout_leaf.script, target->timeout_leaf.script_len,
            cb, cb_len)) {
        tx_buf_free(&utx);
        return 0;
    }

    tx_buf_free(&utx);
    return 1;
}

uint32_t factory_early_warning_time(const factory_t *f) {
    /* Worst-case blocks to fully unwind the factory from the oldest DW state.
       For each DW layer: step_blocks * (max_states - 1).
       PS leaves contribute 0 blocks — their ordering is enforced by TX chaining
       (each confirmation is ~10 minutes, negligible vs. DW layer delays). */
    uint32_t ewt = 0;
    for (uint32_t i = 0; i < f->counter.n_layers; i++) {
        const dw_layer_t *layer = &f->counter.layers[i];
        if (layer->config.max_states > 1)
            ewt += (uint32_t)layer->config.step_blocks * (layer->config.max_states - 1);
    }

    /* If any leaf is a PS leaf, subtract one leaf-layer's worth of blocks.
       The leaf DW layer is the innermost counter layer (index n_layers-1). */
    int has_ps = 0;
    for (int i = 0; i < f->n_leaf_nodes; i++) {
        const factory_node_t *node = &f->nodes[f->leaf_node_indices[i]];
        if (node->is_ps_leaf) { has_ps = 1; break; }
    }
    if (has_ps && f->counter.n_layers > 0) {
        const dw_layer_t *leaf_layer = &f->counter.layers[f->counter.n_layers - 1];
        uint32_t leaf_cost = (uint32_t)leaf_layer->config.step_blocks *
                             (leaf_layer->config.max_states > 1
                              ? leaf_layer->config.max_states - 1 : 0);
        ewt = (ewt > leaf_cost) ? ewt - leaf_cost : 0;
    }
    return ewt;
}

/* Phase 4 (mixed-arity plan): pure-math ewt simulator for a hypothetical
   shape, used by CLI validation BEFORE we commit to building anything.
   Mirrors arity_at_depth + subtree_is_leaf + split_clients_for_arity +
   dw_n_layers_for + factory_early_warning_time, but operates on raw
   inputs (no factory_t needed). */
static int arity_at_depth_raw(const uint8_t *level_arities,
                              size_t n_level_arity,
                              factory_arity_t leaf_arity,
                              int depth) {
    if (n_level_arity == 0)
        return (int)leaf_arity;
    if (depth < (int)n_level_arity)
        return (int)level_arities[depth];
    return (int)level_arities[n_level_arity - 1];
}

uint32_t factory_compute_ewt_for_shape(
    const uint8_t *level_arities, size_t n_level_arity,
    factory_arity_t leaf_arity,
    size_t n_clients,
    uint32_t static_threshold,
    uint16_t step_blocks,
    uint32_t states_per_layer)
{
    if (n_clients == 0) return 0;

    /* Walk the tree to find max depth. Same algorithm as simulate_tree
       but without needing a factory_t. Stack-based DFS. */
    typedef struct { size_t nc; int depth; } frame_t;
    frame_t stack[FACTORY_MAX_NODES];
    int sp = 0;
    int max_depth = 0;
    int has_ps_leaf = 0;
    stack[sp].nc = n_clients;
    stack[sp].depth = 0;
    sp++;
    while (sp > 0) {
        size_t nc = stack[sp - 1].nc;
        int d = stack[sp - 1].depth;
        sp--;
        if (nc == 0) continue;
        if (d > max_depth) max_depth = d;
        int a = arity_at_depth_raw(level_arities, n_level_arity, leaf_arity, d);
        /* subtree_is_leaf logic */
        int is_leaf;
        if (a == 1 || a == FACTORY_ARITY_PS) is_leaf = (nc <= 1);
        else                                  is_leaf = (nc <= (size_t)a);
        if (is_leaf) {
            if (a == FACTORY_ARITY_PS) has_ps_leaf = 1;
            continue;
        }
        /* split_clients_for_arity logic — distribute */
        size_t parts[FACTORY_MAX_OUTPUTS];
        size_t n_parts;
        if (a == 1 || a == FACTORY_ARITY_PS) {
            parts[0] = nc / 2;
            parts[1] = nc - parts[0];
            n_parts = 2;
        } else if (a == 2) {
            size_t total_leaves_est = (nc + 1) / 2;
            size_t left_leaves = total_leaves_est / 2;
            size_t left_n = left_leaves * 2;
            if (left_n > nc) left_n = nc;
            size_t right_n = nc - left_n;
            parts[0] = left_n;
            parts[1] = right_n;
            n_parts = 2;
        } else {
            size_t children = 0;
            size_t remaining = nc;
            while (remaining > 0 && children < (size_t)a) {
                size_t children_left = (size_t)a - children;
                size_t this_child = (remaining + children_left - 1) / children_left;
                if (this_child > remaining) this_child = remaining;
                parts[children++] = this_child;
                remaining -= this_child;
            }
            if (remaining > 0 && children > 0)
                parts[children - 1] += remaining;
            n_parts = children;
        }
        for (size_t k = 0; k < n_parts; k++) {
            if (sp + 1 > FACTORY_MAX_NODES) break;
            stack[sp].nc = parts[k];
            stack[sp].depth = d + 1;
            sp++;
        }
    }

    /* dw_n_layers_for logic */
    int t = (int)static_threshold;
    if (t < 0) t = 0;
    if (t > max_depth + 1) t = max_depth + 1;
    int n_layers = max_depth - t + 1;
    if (n_layers < 1) n_layers = 1;
    if (n_layers > (int)DW_MAX_LAYERS) n_layers = (int)DW_MAX_LAYERS;

    /* factory_early_warning_time logic: each layer contributes
       step_blocks * (states_per_layer - 1). */
    uint32_t per_layer = 0;
    if (states_per_layer > 1)
        per_layer = (uint32_t)step_blocks * (states_per_layer - 1);
    uint32_t ewt = (uint32_t)n_layers * per_layer;

    /* PS leaves contribute 0 blocks (TX chaining, not nSequence) — subtract
       one leaf-layer's worth if any leaf is PS.  When leaf_arity is uniform,
       check leaf_arity itself; for mixed arity, has_ps_leaf is set during
       the walk above. */
    int leaf_is_ps = has_ps_leaf || (n_level_arity == 0 && leaf_arity == FACTORY_ARITY_PS);
    if (leaf_is_ps && n_layers > 0) {
        ewt = (ewt > per_layer) ? ewt - per_layer : 0;
    }
    return ewt;
}

void factory_free(factory_t *f) {
    for (size_t i = 0; i < f->n_nodes; i++) {
        tx_buf_free(&f->nodes[i].unsigned_tx);
        tx_buf_free(&f->nodes[i].signed_tx);
    }
    /* Zero node count so a second factory_free is a no-op (idempotent). */
    f->n_nodes = 0;
}

uint64_t factory_derive_scid(const factory_t *f, int leaf_index, uint32_t output_index) {
    uint64_t epoch = (uint64_t)dw_counter_epoch(&f->counter);
    return (epoch << 40) | ((uint64_t)(leaf_index & 0xFFFFFF) << 16) | (output_index & 0xFFFF);
}

void factory_detach_txbufs(factory_t *f) {
    for (size_t i = 0; i < f->n_nodes; i++) {
        memset(&f->nodes[i].unsigned_tx, 0, sizeof(tx_buf_t));
        memset(&f->nodes[i].signed_tx, 0, sizeof(tx_buf_t));
    }
}
