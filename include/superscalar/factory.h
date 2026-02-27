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

#define FACTORY_MAX_NODES   64
#define FACTORY_MAX_OUTPUTS  8
#define FACTORY_MAX_SIGNERS 16
#define FACTORY_MAX_LEAVES  16

#define NSEQUENCE_DISABLE_BIP68 0xFFFFFFFFu

typedef enum {
    FACTORY_ARITY_2 = 2,    /* 2 clients per leaf (3-of-3), 6 nodes, 2 DW layers */
    FACTORY_ARITY_1 = 1,    /* 1 client per leaf (2-of-2), 14 nodes, 3 DW layers */
} factory_arity_t;

/* Client placement strategies for tree construction */
typedef enum {
    PLACEMENT_SEQUENTIAL = 0,  /* current: [1,2,3,...,N] */
    PLACEMENT_ALTRUISTIC = 1,  /* highest balance closest to root (lower exit cost) */
    PLACEMENT_GREEDY     = 2,  /* lowest uptime deepest in tree (LSP-favorable) */
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
       an independent random 32-byte secret. Storage: 256*32 = 8KB. */
    #define FACTORY_MAX_EPOCHS 256
    unsigned char revocation_secrets[FACTORY_MAX_EPOCHS][32];
    size_t n_revocation_secrets;
    int use_flat_secrets;  /* 1 = flat, 0 = shachain (legacy) */

    /* Per-leaf DW layers (for independent leaf advance) */
    dw_layer_t leaf_layers[FACTORY_MAX_LEAVES];
    int n_leaf_nodes;              /* number of leaf state nodes */
    size_t leaf_node_indices[FACTORY_MAX_LEAVES];

    int per_leaf_enabled;          /* activated after first leaf advance */
    factory_arity_t leaf_arity;    /* FACTORY_ARITY_2 (default) or FACTORY_ARITY_1 */

    /* Lifecycle (Phase 8) */
    uint32_t created_block;        /* block height when funding confirmed */
    uint32_t active_blocks;        /* duration of active period (default: 4320 = 30*144) */
    uint32_t dying_blocks;         /* duration of dying period (default: 432 = 3*144) */

    /* Placement + Economics */
    placement_mode_t placement_mode;  /* client ordering strategy */
    economic_mode_t  economic_mode;   /* fee distribution model */
    participant_profile_t profiles[FACTORY_MAX_SIGNERS];
} factory_t;

int factory_init(factory_t *f, secp256k1_context *ctx,
                  const secp256k1_keypair *keypairs, size_t n_participants,
                  uint16_t step_blocks, uint32_t states_per_layer);

/* Initialize factory from pubkeys only (no keypairs).
   Used by clients who know all participants' pubkeys but only their own secret key.
   The keypairs array is zeroed — signing requires the split-round API. */
void factory_init_from_pubkeys(factory_t *f, secp256k1_context *ctx,
                               const secp256k1_pubkey *pubkeys, size_t n_participants,
                               uint16_t step_blocks, uint32_t states_per_layer);

/* Set factory arity. Must be called after init, before build_tree.
   Reinitializes DW counter with correct layer count for the arity. */
void factory_set_arity(factory_t *f, factory_arity_t arity);

void factory_set_funding(factory_t *f,
                         const unsigned char *txid, uint32_t vout,
                         uint64_t amount_sats,
                         const unsigned char *spk, size_t spk_len);

int factory_build_tree(factory_t *f);
int factory_sign_all(factory_t *f);
int factory_advance(factory_t *f);

/* Reset DW counter to epoch 0, rebuild all unsigned txs, re-sign.
   Reclaims all N^2 states. Requires all signers to participate. */
int factory_reset_epoch(factory_t *f);

/* Reset DW counter to epoch 0, rebuild all unsigned txs, but do NOT sign.
   Use for distributed signing: call this, then use factory_sessions_*()
   to exchange nonces and partial sigs with participants. */
int factory_reset_epoch_unsigned(factory_t *f);

/* Advance only one leaf subtree. leaf_side: 0..n_leaf_nodes-1.
   Rebuilds + re-signs only the affected state node.
   Returns 0 if fully exhausted (need cooperative epoch reset). */
int factory_advance_leaf(factory_t *f, int leaf_side);

/* Advance leaf DW counter + rebuild unsigned tx, but do NOT sign.
   Use for split-round signing: call this, then use factory_session_*_node()
   to exchange nonces and partial sigs with the counterparty.
   Returns 0 if fully exhausted (need cooperative epoch reset).
   Returns -1 if leaf exhausted and root advanced (full rebuild needed). */
int factory_advance_leaf_unsigned(factory_t *f, int leaf_side);

/* Sign a single node (local-only, all keypairs available). */
int factory_sign_node(factory_t *f, size_t node_idx);

/* Per-node split-round signing helpers (for leaf advance in daemon mode). */
int factory_session_init_node(factory_t *f, size_t node_idx);
int factory_session_finalize_node(factory_t *f, size_t node_idx);
int factory_session_complete_node(factory_t *f, size_t node_idx);

void factory_free(factory_t *f);

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

/* Get the revocation secret for a given epoch (for sharing with clients). */
int factory_get_revocation_secret(const factory_t *f, uint32_t epoch,
                                    unsigned char *secret_out32);

/* Build a burn tx spending an old-state L-stock output via hashlock script path. */
int factory_build_burn_tx(const factory_t *f, tx_buf_t *burn_tx_out,
                           const unsigned char *l_stock_txid,
                           uint32_t l_stock_vout,
                           uint64_t l_stock_amount,
                           uint32_t epoch);

/* Cooperative close: single tx bypassing the entire tree */
int factory_build_cooperative_close(
    factory_t *f,
    tx_buf_t *close_tx_out,
    unsigned char *txid_out32,   /* can be NULL */
    const tx_output_t *outputs,
    size_t n_outputs);

/* Build unsigned cooperative close tx + compute its sighash.
   Used for distributed signing: each party signs their partial sig separately. */
int factory_build_cooperative_close_unsigned(
    factory_t *f,
    tx_buf_t *unsigned_tx_out,
    unsigned char *sighash_out32,
    const tx_output_t *outputs,
    size_t n_outputs);

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
   -1 on error, -2 if fully exhausted (need epoch reset). */
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
   This is the "inverted timelock default": if nobody acts, clients get money. */
int factory_build_distribution_tx(
    factory_t *f,
    tx_buf_t *dist_tx_out,
    unsigned char *txid_out32,
    const tx_output_t *outputs,
    size_t n_outputs,
    uint32_t nlocktime);

#endif /* SUPERSCALAR_FACTORY_H */
