#ifndef SUPERSCALAR_FACTORY_H
#define SUPERSCALAR_FACTORY_H

#include "types.h"
#include "dw_state.h"
#include "musig.h"
#include "tx_builder.h"
#include "tapscript.h"
#include "shachain.h"
#include "fee.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#define FACTORY_MAX_NODES   512
/* FACTORY_MAX_OUTPUTS: max outputs per tree node. Sized for arity-15 leaves
 * (15 client channels + 1 L-stock = 16 outputs) under the upcoming N-way
 * mixed-arity work (Phase 2 of mixed-arity implementation plan). Internal
 * state nodes use up to N child outputs. Memory cost: per-node growth from
 * 8 × tx_output_t to 16 × tx_output_t; at 506 nodes (max PS factory at
 * N=128) that's ~50KB extra per factory_t — acceptable. */
#define FACTORY_MAX_OUTPUTS 16
#define FACTORY_MAX_SIGNERS 128
#define FACTORY_MAX_LEAVES  128

#define NSEQUENCE_DISABLE_BIP68 0xFFFFFFFFu

typedef enum {
    FACTORY_ARITY_2  = 2,   /* 2 clients per leaf (3-of-3), 2 DW layers */
    FACTORY_ARITY_1  = 1,   /* 1 client per leaf (2-of-2), 3 DW layers */
    FACTORY_ARITY_PS = 3,   /* pseudo-Spilman: 1 client per leaf, chained TXs replace leaf DW layer */
} factory_arity_t;

/* Client placement strategies for tree construction */
typedef enum {
    PLACEMENT_SEQUENTIAL = 0,  /* current: [1,2,3,...,N] */
    PLACEMENT_INWARD     = 1,  /* highest balance closest to root (lower exit cost) */
    PLACEMENT_OUTWARD    = 2,  /* lowest uptime at leaves (reduces operator exposure) */
    PLACEMENT_TIMEZONE_CLUSTER = 3,  /* group same-timezone clients on same leaf */
} placement_mode_t;

/* Economic fee distribution model */
typedef enum {
    ECON_LSP_TAKES_ALL  = 0,  /* LSP keeps all routing fees (current behavior) */
    ECON_PROFIT_SHARED  = 1,  /* fees redistributed per profit_share_bps */
} economic_mode_t;

/* Per-participant profile for placement and economics */
typedef struct {
    uint32_t participant_idx;     /* 0=LSP, 1..N=clients */
    uint64_t contribution_sats;   /* capital contributed */
    uint16_t profit_share_bps;    /* basis points (0-10000) */
    float    uptime_score;        /* 0.0-1.0 historical uptime */
    uint8_t  timezone_bucket;     /* 0-23 hour of peak activity */
} participant_profile_t;

/* Runtime-configurable limits (Mainnet Gap #6).
   Pass to factory_init_with_config(). NULL = defaults (same as #define values). */
typedef struct {
    uint32_t max_signers;           /* default FACTORY_MAX_SIGNERS */
    uint32_t max_nodes;             /* default FACTORY_MAX_NODES */
    uint32_t max_leaves;            /* default FACTORY_MAX_LEAVES */
    uint32_t max_outputs_per_node;  /* default FACTORY_MAX_OUTPUTS — per tree node */
    uint64_t dust_limit_sats;       /* default 546 */
} factory_config_t;

/* Fill config with compiled-in defaults. */
void factory_config_default(factory_config_t *cfg);

typedef enum { NODE_KICKOFF, NODE_STATE } factory_node_type_t;

/* Factory lifecycle states (Phase 8) */
typedef enum {
    FACTORY_ACTIVE,     /* Normal operation */
    FACTORY_DYING,      /* Migration window, no new liquidity purchases */
    FACTORY_EXPIRED,    /* CLTV timeout reached */
} factory_state_t;

typedef struct {
    factory_node_type_t type;

    /* Signers for this node's N-of-N */
    uint32_t signer_indices[FACTORY_MAX_SIGNERS];
    size_t n_signers;
    musig_keyagg_t keyagg;

    /* Tweaked output key and P2TR scriptPubKey */
    secp256k1_xonly_pubkey tweaked_pubkey;
    unsigned char spending_spk[34];
    size_t spending_spk_len;

    /* Transaction */
    tx_buf_t unsigned_tx;
    tx_buf_t signed_tx;
    unsigned char txid[32];   /* internal byte order */
    uint32_t nsequence;
    int is_built;
    int is_signed;

    /* Outputs */
    tx_output_t outputs[FACTORY_MAX_OUTPUTS];
    size_t n_outputs;

    /* DW layer index into factory counter (-1 for kickoff nodes) */
    int dw_layer_index;

    /* Tree links */
    int parent_index;         /* -1 for root */
    uint32_t parent_vout;
    int child_indices[FACTORY_MAX_OUTPUTS];
    size_t n_children;

    /* Input amount from parent output */
    uint64_t input_amount;

    /* Timeout script path (staggered per-node CLTV) */
    int has_taptree;
    uint32_t cltv_timeout;    /* per-node absolute CLTV for timeout script-path */
    tapscript_leaf_t timeout_leaf;
    unsigned char merkle_root[32];
    int output_parity;        /* parity of tweaked output key */

    /* Split-round signing state */
    musig_signing_session_t signing_session;
    secp256k1_musig_partial_sig partial_sigs[FACTORY_MAX_SIGNERS];
    int partial_sigs_received;

    /* Pseudo-Spilman leaf state (is_ps_leaf == 1 only) */
    int is_ps_leaf;              /* 1 if this leaf uses PS chaining instead of DW nSequence */
    int ps_chain_len;            /* number of state advances (0 = initial state) */
    unsigned char ps_prev_txid[32];    /* txid (internal byte order) of the prior chain TX */
    uint64_t ps_prev_chan_amount;      /* amount_sats of the channel output spent by current TX */

    /* Static-near-root variant (Phase 3 of mixed-arity plan).
       1 = kickoff-only node, no paired NODE_STATE, no DW counter contribution.
       Children spend this kickoff's vout 0..N-1 directly.
       The CLTV timeout is the sole escape mechanism for static nodes
       (nsequence == 0xFFFFFFFE, no BIP-68 CSV). */
    int is_static_only;
} factory_node_t;

typedef struct {
    secp256k1_context *ctx;

    /* Participants: 0 = LSP, 1..N = clients */
    secp256k1_keypair keypairs[FACTORY_MAX_SIGNERS];
    secp256k1_pubkey pubkeys[FACTORY_MAX_SIGNERS];
    size_t n_participants;

    /* Flat node array */
    factory_node_t nodes[FACTORY_MAX_NODES];
    size_t n_nodes;

    /* Funding UTXO */
    unsigned char funding_txid[32];  /* internal byte order */
    uint32_t funding_vout;
    uint64_t funding_amount_sats;
    unsigned char funding_spk[34];
    size_t funding_spk_len;

    /* DW counter */
    dw_counter_t counter;
    uint16_t step_blocks;
    uint32_t states_per_layer;

    /* Fee per transaction */
    uint64_t fee_per_tx;
    fee_estimator_t *fee;  /* if set, overrides fee_per_tx with computed fees */

    /* CLTV timeout (absolute block height) */
    uint32_t cltv_timeout;

    /* Shachain for L-output invalidation */
    unsigned char shachain_seed[32];
    int has_shachain;

    /* Flat revocation secrets (Phase 2: item 2.8).
       ZmnSCPxj recommends flat secrets for multi-signer: each epoch gets
       an independent random 32-byte secret. Storage: 4096*32 = 128KB. */
    #define FACTORY_MAX_EPOCHS 4096
    unsigned char revocation_secrets[FACTORY_MAX_EPOCHS][32];
    size_t n_revocation_secrets;
    int use_flat_secrets;  /* 1 = flat, 0 = shachain (legacy) */

    /* L-stock hashlock hashes: SHA256(revocation_secret) per epoch.
       Sent to clients in FACTORY_PROPOSE so both sides build identical
       L-stock taptrees without sharing the actual secrets. */
    unsigned char l_stock_hashes[FACTORY_MAX_EPOCHS][32];
    size_t n_l_stock_hashes;

    /* Per-leaf DW layers (for independent leaf advance) */
    dw_layer_t leaf_layers[FACTORY_MAX_LEAVES];
    int n_leaf_nodes;              /* number of leaf state nodes */
    size_t leaf_node_indices[FACTORY_MAX_LEAVES];

    int per_leaf_enabled;          /* activated after first leaf advance */
    factory_arity_t leaf_arity;    /* FACTORY_ARITY_2 (default) or FACTORY_ARITY_1 */

    /* Variable arity per tree level (4A): overrides leaf_arity when set.
       level_arity[d] = arity at depth d (1 or 2). The last entry applies
       to all deeper levels. n_level_arity == 0 means uniform leaf_arity. */
    #define FACTORY_MAX_LEVELS 8
    uint8_t level_arity[FACTORY_MAX_LEVELS];
    size_t n_level_arity;

    /* Static-near-root variant (Phase 3 of mixed-arity plan).
       Depths < this threshold are kickoff-only (no paired NODE_STATE,
       no DW counter, no per-state nSequence). Only the per-node CLTV
       timeout escapes a static layer.
       0 = no static, full DW everywhere (default for backward compat).
       Per `arity_at_depth` semantics, this is independent of arity:
       a static depth still has its arity_at_depth fan-out, but the
       fan-out happens directly off the kickoff TX (no state intermediary). */
    uint32_t static_threshold_depth;

    /* Lifecycle (Phase 8) */
    uint32_t created_block;        /* block height when funding confirmed */
    uint32_t active_blocks;        /* duration of active period (default: 4320 = 30*144) */
    uint32_t dying_blocks;         /* duration of dying period (default: 432 = 3*144) */

    /* Placement + Economics */
    placement_mode_t placement_mode;  /* client ordering strategy */
    economic_mode_t  economic_mode;   /* fee distribution model */
    participant_profile_t profiles[FACTORY_MAX_SIGNERS];

    /* Runtime config (Mainnet Gap #6) — stored limits for this factory */
    factory_config_t config;

    /* Distribution TX (signed during ceremony, timelocked to cltv_timeout).
       The "inverted timeout default": if nobody acts, clients get money. */
    tx_buf_t dist_unsigned_tx;     /* unsigned distribution TX */
    unsigned char dist_sighash[32]; /* BIP-341 sighash for distributed signing */
    int dist_tx_ready;             /* 1 = unsigned TX built + sighash computed */
} factory_t;

int factory_init(factory_t *f, secp256k1_context *ctx,
                  const secp256k1_keypair *keypairs, size_t n_participants,
                  uint16_t step_blocks, uint32_t states_per_layer);

/* Initialize with custom config. NULL config = defaults. */
int factory_init_with_config(factory_t *f, secp256k1_context *ctx,
                              const secp256k1_keypair *keypairs, size_t n_participants,
                              uint16_t step_blocks, uint32_t states_per_layer,
                              const factory_config_t *cfg);

/* Initialize factory from pubkeys only (no keypairs).
   Used by clients who know all participants' pubkeys but only their own secret key.
   The keypairs array is zeroed — signing requires the split-round API. */
void factory_init_from_pubkeys(factory_t *f, secp256k1_context *ctx,
                               const secp256k1_pubkey *pubkeys, size_t n_participants,
                               uint16_t step_blocks, uint32_t states_per_layer);

/* Set factory arity. Must be called after init, before build_tree.
   Reinitializes DW counter with correct layer count for the arity. */
void factory_set_arity(factory_t *f, factory_arity_t arity);

/* Set variable arity per tree level (4A). arities[0]=root level, etc.
   Last entry applies to all deeper levels. Clears uniform leaf_arity.
   Must be called after init, before build_tree. */
void factory_set_level_arity(factory_t *f, const uint8_t *arities, size_t n);

/* Map a 0-based client index to its (leaf-node, vout) position in the
   built tree.  Returns 1 on success, 0 if the client_idx is out of range
   or doesn't appear in any leaf's signer_indices.

   Behavior is arity-aware:

   - Mixed-arity factories (n_level_arity > 0): walks
     factory->leaf_node_indices[] and matches my_index = client_idx + 1
     against each leaf's signer_indices[].  vout = position in
     signer_indices minus 1 (signer_indices[0] == 0 is the LSP).  This
     is the only correct mapping when leaves can hold > 2 channels.

   - Uniform ARITY_1 and ARITY_PS: each client owns its own leaf at
     vout 0.  PS leaves are built 1-client-per-leaf (n_signers=2 = LSP +
     1 client) with chained TXs replacing the per-state DW machine; the
     mapping is identical to arity-1 here.

   - Uniform ARITY_2: 2 clients per leaf, layout [vout 0 = client A's
     channel, vout 1 = client B's channel, vout 2 = L-stock]; client_idx
     i maps to (leaf i/2, vout i%2).

   Use this from any code that previously open-coded the mapping
   (src/client.c::client_init_channel, src/lsp_channels.c::client_to_leaf,
   etc.) to keep the two sides of the wire ceremony in sync. */
int factory_client_to_leaf(const factory_t *f, size_t client_idx,
                            size_t *node_idx_out, uint32_t *vout_out);

/* Configure the static-near-root threshold (Phase 3 of mixed-arity plan).
   Depths in [0, threshold) become kickoff-only (no paired NODE_STATE, no
   DW counter, no per-state nSequence — only the per-node CLTV timeout
   escapes that layer). Pass 0 (the default) to disable static-near-root
   and keep full DW state pairs at every depth.
   Must be called after factory_set_arity / factory_set_level_arity
   (which initialize the DW counter), before factory_build_tree.
   Reinitializes the DW counter so n_layers reflects only the non-static
   depths, capped at DW_MAX_LAYERS. */
void factory_set_static_near_root(factory_t *f, uint32_t threshold);

void factory_set_funding(factory_t *f,
                         const unsigned char *txid, uint32_t vout,
                         uint64_t amount_sats,
                         const unsigned char *spk, size_t spk_len);

int factory_build_tree(factory_t *f);
int factory_sign_all(factory_t *f);
int factory_verify_all(factory_t *f);
int factory_advance(factory_t *f);

/* Advance only one leaf subtree. leaf_side: 0..n_leaf_nodes-1.
   Rebuilds + re-signs only the affected state node.
   Returns 0 if fully exhausted (need factory rotation). */
int factory_advance_leaf(factory_t *f, int leaf_side);

/* Advance leaf DW counter + rebuild unsigned tx, but do NOT sign.
   Use for split-round signing: call this, then use factory_session_*_node()
   to exchange nonces and partial sigs with the counterparty.
   Returns 0 if fully exhausted (need factory rotation).
   Returns -1 if leaf exhausted and root advanced (full rebuild needed). */
int factory_advance_leaf_unsigned(factory_t *f, int leaf_side);

/* Compute the factory_early_warning_time (blocks) per BLIP-56.
   This is the worst-case blocks needed for full unilateral close from
   the current state. PS leaves contribute 0 blocks (no nSequence at leaf level). */
uint32_t factory_early_warning_time(const factory_t *f);

/* Compute the worst-case factory_early_warning_time (blocks) for a given
   tree-shape configuration WITHOUT building or signing anything.  Pure
   math based on tree depth (computed from arity + n_clients), DW layer
   count (with static_threshold applied), and step_blocks/states_per_layer.
   Used by CLI validation (Phase 4 of mixed-arity plan) to reject shapes
   that would exceed BOLT's 2016-block final_cltv_expiry ceiling.

   - level_arities: per-level arity array; NULL or n_level_arity==0 means
     uniform leaf_arity
   - leaf_arity: used when level_arities is NULL/empty (3 = PS, 1/2 = DW)
   - n_clients: client count (excludes LSP, so factory_clients_only)
   - static_threshold: top N tree depths are kickoff-only (Phase 3)
   - step_blocks / states_per_layer: per-DW-layer config (mainnet 144 / 4)
   Returns ewt in blocks.  Treats PS leaves as 0-cost at the leaf layer
   when leaf arity == FACTORY_ARITY_PS. */
uint32_t factory_compute_ewt_for_shape(
    const uint8_t *level_arities, size_t n_level_arity,
    factory_arity_t leaf_arity,
    size_t n_clients,
    uint32_t static_threshold,
    uint16_t step_blocks,
    uint32_t states_per_layer);

/* Sign a single node (local-only, all keypairs available). */
int factory_sign_node(factory_t *f, size_t node_idx);

/* Per-node split-round signing helpers (for leaf advance in daemon mode). */
int factory_session_init_node(factory_t *f, size_t node_idx);
int factory_session_finalize_node(factory_t *f, size_t node_idx);
int factory_session_complete_node(factory_t *f, size_t node_idx);

/* Set custom output amounts on a leaf state node.
   leaf_side: 0..n_leaf_nodes-1.  amounts must sum to current output total.
   No amount may be below dust (546 sats).  Rebuilds the unsigned tx. */
int factory_set_leaf_amounts(factory_t *f, int leaf_side,
                              const uint64_t *amounts, size_t n_amounts);

/* Rebuild a single node's unsigned tx (public wrapper around internal helper). */
int factory_rebuild_node_tx(factory_t *f, size_t node_idx);

void factory_free(factory_t *f);

/* Derive a short channel ID (SCID) for a factory leaf channel.
   Format: (epoch << 40) | (leaf_index << 16) | output_index.
   This creates unique, deterministic SCIDs for route hints in BOLT #11 invoices.
   Factory channels are off-chain, so full BOLT #7 gossip is impossible. */
uint64_t factory_derive_scid(const factory_t *f, int leaf_index, uint32_t output_index);

/* Detach tx_buf heap data from a factory so it can be used as a read-only
   shallow copy without risk of double-free.  Zeroes all tx_buf data pointers
   while preserving metadata (n_nodes, keypairs, lifecycle, etc.).  The factory
   must NOT be used for signing or TX building after this call. */
void factory_detach_txbufs(factory_t *f);

/* Shachain L-output invalidation API */

/* Enable shachain-based L-output invalidation. Call before factory_build_tree. */
void factory_set_shachain_seed(factory_t *f, const unsigned char *seed32);

/* Flat revocation secrets API (Phase 2: item 2.8).
   Enable flat secrets mode. Generates n random 32-byte secrets.
   Call before factory_build_tree. New factories should use this. */
int factory_generate_flat_secrets(factory_t *f, size_t n_epochs);

/* Set pre-loaded flat secrets (for persistence reload). */
void factory_set_flat_secrets(factory_t *f,
                               const unsigned char secrets[][32],
                               size_t n_secrets);

/* Set L-stock hashlock hashes (client side — no secrets needed).
   Enables clients to build matching L-stock taptrees. */
void factory_set_l_stock_hashes(factory_t *f,
                                 const unsigned char hashes[][32],
                                 size_t n_hashes);

/* Get the revocation secret for a given epoch (for sharing with clients). */
int factory_get_revocation_secret(const factory_t *f, uint32_t epoch,
                                    unsigned char *secret_out32);

/* Build a burn tx spending an old-state L-stock output via hashlock script path. */
int factory_build_burn_tx(const factory_t *f, tx_buf_t *burn_tx_out,
                           const unsigned char *l_stock_txid,
                           uint32_t l_stock_vout,
                           uint64_t l_stock_amount,
                           uint32_t epoch);

/* Cooperative close: single tx bypassing the entire tree.
   current_height = tip block height for nLockTime anti-fee-sniping (BIP). */
int factory_build_cooperative_close(
    factory_t *f,
    tx_buf_t *close_tx_out,
    unsigned char *txid_out32,   /* can be NULL */
    const tx_output_t *outputs,
    size_t n_outputs,
    uint32_t current_height);

/* Build unsigned cooperative close tx + compute its sighash.
   Used for distributed signing: each party signs their partial sig separately.
   current_height = tip block height for nLockTime anti-fee-sniping (BIP). */
int factory_build_cooperative_close_unsigned(
    factory_t *f,
    tx_buf_t *unsigned_tx_out,
    unsigned char *sighash_out32,
    const tx_output_t *outputs,
    size_t n_outputs,
    uint32_t current_height);

/* Split-round signing API (multi-party orchestration) */

/* Find signer_slot for participant_idx in a node. Returns slot index or -1. */
int factory_find_signer_slot(const factory_t *f, size_t node_idx,
                              uint32_t participant_idx);

/* Initialize signing sessions for all nodes. Resets partial_sigs_received. */
int factory_sessions_init(factory_t *f);

/* Set a signer's pubnonce for a specific node. */
int factory_session_set_nonce(factory_t *f, size_t node_idx, size_t signer_slot,
                               const secp256k1_musig_pubnonce *pubnonce);

/* Finalize nonces for all nodes: compute sighash, apply tweak, create sessions. */
int factory_sessions_finalize(factory_t *f);

/* Set a signer's partial sig for a specific node. */
int factory_session_set_partial_sig(factory_t *f, size_t node_idx,
                                     size_t signer_slot,
                                     const secp256k1_musig_partial_sig *psig);

/* Complete signing: aggregate partial sigs, finalize witness for all nodes. */
int factory_sessions_complete(factory_t *f);

/* Count how many nodes a participant signs on. */
size_t factory_count_nodes_for_participant(const factory_t *f,
                                            uint32_t participant_idx);

/* --- Path-scoped signing API --- */

/* Initialize signing sessions for nodes on path from leaf to root only. */
int factory_sessions_init_path(factory_t *f, int leaf_node_idx);

/* Finalize sessions (sighash + aggnonce) for path nodes only. */
int factory_sessions_finalize_path(factory_t *f, int leaf_node_idx);

/* Aggregate partial sigs + finalize witness for path nodes only. */
int factory_sessions_complete_path(factory_t *f, int leaf_node_idx);

/* Rebuild unsigned txs for path nodes only (after DW advance). */
int factory_rebuild_path_unsigned(factory_t *f, int leaf_node_idx);

/* Advance leaf DW counter. If leaf exhausted, advance root layer and
   rebuild+resign only the affected path. Returns leaf_node_idx on success,
   -1 on error, -2 if fully exhausted (need factory rotation). */
int factory_advance_and_rebuild_path(factory_t *f, int leaf_side);

/* --- Tree navigation helpers --- */

/* Collect node indices from start_idx up to root (node 0), stored root-first.
   Returns count written. Caller provides path_out[max_path]. */
size_t factory_collect_path_to_root(const factory_t *f, int start_idx,
                                     int *path_out, size_t max_path);

/* Get client participant indices in a node's signer set (excluding LSP=0).
   Returns count written. */
size_t factory_get_subtree_clients(const factory_t *f, int node_idx,
                                    uint32_t *clients_out, size_t max_clients);

/* Find the leaf state node index for a client participant index.
   Returns leaf state node index, or -1 if not found. */
int factory_find_leaf_for_client(const factory_t *f, uint32_t client_idx);

/* Build a signed timeout script-path spend for a factory node.
   Spends parent_txid:parent_vout via target_node's CLTV timeout leaf.
   LSP signs alone: <cltv> OP_CLTV OP_DROP <LSP_key> OP_CHECKSIG.
   Returns 1 on success. */
int factory_build_timeout_spend_tx(
    const factory_t *f,
    const unsigned char *parent_txid,   /* 32 bytes, internal order */
    uint32_t parent_vout,
    uint64_t spend_amount,              /* sats on the output being spent */
    int target_node_idx,                /* node whose spending_spk is the output */
    const secp256k1_keypair *lsp_keypair,
    const unsigned char *dest_spk,      /* destination P2TR scriptPubKey */
    size_t dest_spk_len,
    uint64_t fee_sats,
    tx_buf_t *signed_tx_out);

/* --- Factory lifecycle (Phase 8) --- */

void factory_set_lifecycle(factory_t *f, uint32_t created_block,
                           uint32_t active_blocks, uint32_t dying_blocks);

factory_state_t factory_get_state(const factory_t *f, uint32_t current_block);
int factory_is_active(const factory_t *f, uint32_t current_block);
int factory_is_dying(const factory_t *f, uint32_t current_block);
int factory_is_expired(const factory_t *f, uint32_t current_block);
uint32_t factory_blocks_until_dying(const factory_t *f, uint32_t current_block);
uint32_t factory_blocks_until_expired(const factory_t *f, uint32_t current_block);

/* Pre-sign a distribution tx at factory creation time.
   nLockTime = cltv_timeout, outputs = per-client settlement amounts.
   This is the "inverted timelock default": if nobody acts, clients get money.
   Requires all keypairs (single-party signing — use for tests only). */
int factory_build_distribution_tx(
    factory_t *f,
    tx_buf_t *dist_tx_out,
    unsigned char *txid_out32,
    const tx_output_t *outputs,
    size_t n_outputs,
    uint32_t nlocktime);

/* Build the unsigned distribution TX and compute its sighash.
   Used during distributed MuSig2 ceremony — both LSP and client call this
   to produce the identical unsigned TX for distributed signing.
   Stores result in f->dist_unsigned_tx and f->dist_sighash.
   Returns 1 on success. */
int factory_build_distribution_tx_unsigned(
    factory_t *f,
    const tx_output_t *outputs,
    size_t n_outputs,
    uint32_t nlocktime);

/* Compute distribution TX outputs: each participant gets P2TR(their_pubkey).
   LSP (pubkeys[0]) gets funding_amount - sum(client_amounts) - fee.
   Clients get their initial channel capacity (per_output from leaf setup).
   Returns number of outputs written. */
size_t factory_compute_distribution_outputs(
    const factory_t *f,
    tx_output_t *outputs_out,
    size_t max_outputs,
    uint64_t fee_sats);

/* Balance-aware distribution outputs: each client gets their actual channel
   balance (client_amounts[0..n_clients-1]) instead of equal split.
   LSP gets funding - sum(client_amounts) - fee.
   client_amounts may be NULL to fall back to equal split. */
size_t factory_compute_distribution_outputs_balanced(
    const factory_t *f,
    tx_output_t *outputs_out,
    size_t max_outputs,
    uint64_t fee_sats,
    const uint64_t *client_amounts,
    size_t n_client_amounts);

#endif /* SUPERSCALAR_FACTORY_H */
