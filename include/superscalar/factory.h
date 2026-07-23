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
/* FACTORY_MAX_SIGNERS = size of the keyagg/pubkey ARRAYS and the upper bound
 * on the MuSig2 signing group (LSP + clients).  The signing limit is
 * MUSIG_SESSION_MAX_SIGNERS, now also 256 (LSP + up to 255 clients).  The old
 * comment here claimed >128 signers was "NOT signable"; that was overly
 * conservative — MuSig2/Schnorr aggregate + sign + verify cleanly to 2048
 * signers, and the distributed session path is valgrind-clean at 256 (see
 * tools/test_musig_scale.c, tools/test_musig_session_scale.c).  NOTE: running
 * 255 client daemons is memory-heavy (~70 MB RSS each); a large-factory
 * deployment is RAM-bound, and shrinking factory_t (dynamic leaf_layers) is a
 * worthwhile follow-up. */
#define FACTORY_MAX_SIGNERS 256
/* FACTORY_MAX_LEAVES: one channel (leaf) per client, so this bounds the client
 * count.  Raised 128 -> 256 to support up to 255-client factories.  Cost:
 * leaf_layers[FACTORY_MAX_LEAVES] is embedded in factory_t, so this enlarges
 * factory_t for all factories (dynamic sizing is the future optimization). */
#define FACTORY_MAX_LEAVES  256

#define NSEQUENCE_DISABLE_BIP68 0xFFFFFFFFu

/* Default CSV (BIP-68 relative locktime) on the L-stock SPK's L&CSV
   script-path leaf, in blocks.  Spec source: ZmnSCPxj's t/1242 doesn't
   pin a value; the rationale is "long enough that watchtowers / clients
   can broadcast the pre-signed L-stock poison TX before the LSP can
   spend L-stock alone via the script-path."  144 blocks ≈ 1 day on
   mainnet — generous reaction window, manageable on regtest.

   The CSV value is per-factory configurable via factory_set_l_stock_csv()
   (see below).  Override before factory_build_tree(). */
#define L_STOCK_CSV_DEFAULT_BLOCKS 144u

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

/* Node types in a factory tree.

   NODE_KICKOFF / NODE_STATE — the canonical Decker-Wattenhofer kickoff
     + state pair that interior factory nodes use.

   NODE_PS_SUBFACTORY — Pseudo-Spilman sub-factory child of a PS leaf
     (only used when ps_subfactory_arity > 1, the canonical k² shape
     from t/1242).  Spends one of the parent leaf's vouts.  Its own
     outputs are k client channels + 1 sales-stock output that the LSP
     can chain into new client channels via the dynamic extension
     ceremony (Phase 2 of docs/ps-subfactories.md).
     For k=1 (current default), this type is unused — PS leaves
     remain 1-client-per-leaf and the leaf node directly owns the
     channel + L-stock outputs. */
typedef enum {
    NODE_KICKOFF,
    NODE_STATE,
    NODE_PS_SUBFACTORY
} factory_node_type_t;

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

    /* Wire-ceremony poison TX state — second MuSig session per node so a
       multi-process LSP can co-sign the L-stock / sales-stock poison TX
       alongside the new state TX during the same advance ceremony.
       MUST use independent nonces from `signing_session` (MuSig2 demands
       fresh nonces per signed message).  Lifetime: populated when the
       LSP and clients run a state-advance with poison-TX bundling; the
       `poison_signed_tx` is then handed to the watchtower so it can
       broadcast the poison TX on breach detection.  Closes the SECURITY
       GAP documented in docs/poison-tx.md. */
    musig_signing_session_t poison_signing_session;
    secp256k1_musig_partial_sig poison_partial_sigs[FACTORY_MAX_SIGNERS];
    int poison_partial_sigs_received;
    unsigned char poison_sighash[32];
    tx_buf_t poison_unsigned_tx;
    tx_buf_t poison_signed_tx;
    int poison_is_signed;
    /* internal byte order; txid of the poison TX (signed txid == unsigned txid,
       witness-stripped).  Captured at build time so the trustless wt_db response
       can be keyed on the poison (G1 #44) without a txid-from-bytes helper. */
    unsigned char poison_txid[32];

    /* #53 hashlock-gated poison: per-(leaf,state) revocation hash H_s = SHA256(secret_s)
       committed into THIS leaf state's L-stock output (Leaf P of the taptree).  When
       has_l_stock_hash==1 the L-stock SPK is the 2-leaf {poison, LSP-CSV} tree and the
       poison must be spent via the Leaf-P script-path with the revealed secret_s as the
       witness preimage — so a non-revoked (live) state's poison has no satisfying witness
       (closes Scenario B).  Set during leaf-state construction when flat secrets are
       active; the secret_s itself stays LSP-private until revealed on advance. */
    unsigned char l_stock_hash[32];
    int has_l_stock_hash;
    /* #53-B: per-leaf monotonic L-stock state index, bumped every time this
       leaf's L-stock SPK is (re)built (initial setup + each epoch advance / JIT
       L-stock change).  Combined with the leaf's agg pubkey it forms the unique
       per-(leaf, state) secret index, so independently-advancing leaves never
       collide.  state s's revealed secret is derived at the value this had when
       state s's L-stock output was built. */
    uint32_t l_stock_state_counter;

    /* Tier-B poison fix (gap-scan #105): snapshot of the SUPERSEDED state, captured in
       update_l_stock_outputs BEFORE the counter bump + hash re-commit (and before
       build_all_unsigned_txs overwrites node->txid).  The epoch-boundary ceremony
       (lsp_run_state_advance_stateless) reads these to arm the L-stock poison against
       the OLD output -- without them it read the already-rebuilt node (dead had_old). */
    int prev_epoch_valid;                  /* the superseded state was signed */
    unsigned char prev_epoch_txid[32];     /* internal byte order */
    uint32_t prev_epoch_l_vout;            /* anchor-aware L-stock output index */
    uint64_t prev_epoch_l_amount;
    unsigned char prev_epoch_l_hash[32];   /* H_old for the poison override_hash32 */
    int prev_epoch_has_l_hash;
    uint64_t prev_epoch_chain_amount;
    unsigned char prev_epoch_chain_spk[34];
    size_t prev_epoch_chain_spk_len;
    uint32_t prev_epoch_csv_delay;

    /* #53-B3a: script-path (Leaf-P) poison ceremony state.  When the leaf carries a
       hashlock (has_l_stock_hash), the multi-process poison ceremony signs the Leaf-P
       script path against the UNTWEAKED agg key (not the key path = Scenario B); the
       aggregated 64-byte sig + these witness components are combined with the revealed
       secret at broadcast via factory_assemble_poison_with_secret. */
    int poison_is_scriptpath;
    int poison_has_agg_sig;
    unsigned char poison_agg_sig[64];
    unsigned char poison_leaf_script[128];   /* TAPSCRIPT_MAX_SCRIPT; Leaf-P = 73 bytes */
    size_t poison_leaf_script_len;
    unsigned char poison_control_block[65];
    size_t poison_control_block_len;
    /* The Leaf-P hash THIS poison was built to spend (the superseded state's H_old,
       or the node's current hash when poisoning the live output).  assemble verifies
       the revealed secret against THIS, not l_stock_hash, which may have advanced. */
    unsigned char poison_l_stock_hash[32];

    /* Pseudo-Spilman leaf state (is_ps_leaf == 1 only) */
    int is_ps_leaf;              /* 1 if this leaf uses PS chaining instead of DW nSequence */
    int ps_chain_len;            /* number of state advances (0 = initial state) */
    unsigned char ps_prev_txid[32];    /* txid (internal byte order) of the prior chain TX */
    uint64_t ps_prev_chan_amount;      /* amount_sats of the channel output spent by current TX
                                          (legacy 1-input shape; for multi-input PS sub-factory
                                          chain advances see ps_prev_amounts[] below) */
    /* #146: height-aware reset.  Block height at which the latest chain
       entry was observed confirmed (0 = unset / legacy).  Used by
       factory_reset_subfactory_chains_above_height to leave chain state
       intact through reorgs that don't go deep enough to bury this
       entry. */
    uint32_t ps_chain_confirmed_height;

    /* Multi-input PS sub-factory chain advance state (#207).
       When a NODE_PS_SUBFACTORY chain extends, the new TX consumes ALL
       k+1 outputs of the previous chain TX (not just sales-stock).  These
       arrays cache the per-input prev_amount + prev_scriptpubkey captured
       before factory_subfactory_chain_advance_unsigned mutates outputs[].
       Each index i in [0, ps_n_prev_outputs) corresponds to chain[N-1]'s
       output i (vout i becomes input i of chain[N]).
       Only populated when ps_chain_len > 0 && type == NODE_PS_SUBFACTORY. */
    size_t ps_n_prev_outputs;                                     /* 0 = single-input */
    uint64_t ps_prev_amounts[FACTORY_MAX_OUTPUTS];
    unsigned char ps_prev_spks[FACTORY_MAX_OUTPUTS][34];
    size_t ps_prev_spk_lens[FACTORY_MAX_OUTPUTS];

    /* Per-input MuSig sessions for multi-input nodes.  Heap-allocated on
       first factory_session_init_node_input call; freed in factory_free.
       Length equals ps_n_prev_outputs (= n_inputs).  Only used by
       advanced PS sub-factory nodes per #207. */
    musig_signing_session_t *input_signing_sessions;        /* length n_input_sessions */
    secp256k1_musig_partial_sig *input_partial_sigs;        /* length n_input_sessions * FACTORY_MAX_SIGNERS */
    int input_partial_sigs_received[FACTORY_MAX_OUTPUTS];   /* per-input count */
    size_t n_input_sessions;

    /* SF-MULTI-KEYAGG (#283): per-input keyagg metadata.  Each input of a
       multi-input chain advance spends a different prev-output: channel
       outputs (2-of-2 {client_i, LSP} + factory_cltv merkle) for inputs
       0..k-1, and the sub-factory sales-stock output (N-of-N, no merkle)
       for input k.  These arrays are allocated by ensure_input_sessions_alloc
       alongside input_signing_sessions and parallel-indexed by input_idx. */
    musig_keyagg_t   *input_keyaggs;          /* length n_input_sessions */
    uint32_t          input_signer_indices[FACTORY_MAX_OUTPUTS][FACTORY_MAX_SIGNERS];
    size_t            input_n_signers[FACTORY_MAX_OUTPUTS];
    unsigned char     input_merkle_root[FACTORY_MAX_OUTPUTS][32];
    int               input_has_merkle_root[FACTORY_MAX_OUTPUTS];

    /* PS sub-factory wiring (only used when ps_subfactory_arity > 1, the
       canonical k² shape from t/1242).

       On a PS LEAF node (is_ps_leaf == 1) with k>1: n_subfactories == k
       and subfactory_node_indices[0..k-1] point into f->nodes[] at the
       k sub-factory child nodes.  The leaf node's outputs[0..k-1] are
       the entry-point SPKs for each sub-factory, and outputs[k] is the
       leaf-level L-stock.

       On a NODE_PS_SUBFACTORY node: n_subfactories == 0, parent_index
       points back to the leaf, parent_vout indicates which leaf vout
       this sub-factory occupies.  The sub-factory's own outputs[0..k-1]
       are the per-client channel SPKs and outputs[k] is the sub-factory's
       sales-stock SPK.

       For k=1 (default) both fields are 0. */
    int n_subfactories;
    int subfactory_node_indices[FACTORY_MAX_OUTPUTS];

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

    /* #53-B: revocation-gated (hashlock) L-stock poison.  When enabled, each
       leaf state's L-stock output commits H_s = SHA256(secret(leaf, state)) into
       Leaf P of its taptree (see build_l_stock_taptree).  The secret is derived
       PER-(leaf, state) from shachain_seed — keyed on the leaf's agg pubkey AND a
       per-leaf monotonic counter — so revealing one leaf's revoked-state secret
       can NEVER unlock another leaf's (or a later state's) live poison (the
       cross-leaf leak of the old global-epoch index).  LSP-private; revealed to
       the leaf's clients only when the state is superseded (#53-B3). */
    int use_hashlock_poison;

    /* #53-B3b.2a: CLIENT MIRROR.  The client has no shachain_seed, so it cannot
       DERIVE the per-(leaf,state) L-stock hash — it receives each leaf node's
       committed H from the LSP over the wire and stores it here (indexed by node
       index).  When has_node_l_stock_hashes is set, apply_l_stock_hashlock uses
       node_l_stock_hashes[idx] (the shipped H) instead of deriving, so the client
       builds the SAME 2-leaf L-stock SPK as the LSP (else the leaf-state tx bytes
       diverge and the MuSig co-sign fails). */
    unsigned char node_l_stock_hashes[FACTORY_MAX_NODES][32];
    int node_l_stock_hash_valid[FACTORY_MAX_NODES];
    int has_node_l_stock_hashes;

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

    /* CSV (BIP-68 relative locktime) on the L-stock SPK's L&CSV
       script-path leaf, in blocks.  See L_STOCK_CSV_DEFAULT_BLOCKS for
       rationale and default. */
    uint32_t l_stock_csv_blocks;

    /* #56: append a keyless P2A CPFP anchor to every tree node tx so the
       force-close cascade can be fee-bumped under fee pressure (the shared
       cascade txs are pre-signed at a fixed fee and otherwise unbumpable).
       Negotiated like a feature bit -- BOTH the LSP and all clients must build
       the factory with the SAME value or the tree's co-signed sighashes diverge.
       Default 0 (raw factory_init / unit / legacy); production sets it on. */
    int use_tree_anchor;

    /* PS sub-factory arity (k) for the canonical k² PS leaf shape from
       t/1242 (docs/ps-subfactories.md, Gap E followup, task #181).

       k=1 (default): 1-client-per-PS-leaf, no sub-factories — current
                      historical behavior, preserves all existing tests.
       k>1: each PS leaf hosts k sub-factories of k clients each (k²
            clients per leaf total).  Each sub-factory is a unidirectional
            PS chain rooted at one of the leaf's vouts, with the LSP
            holding "sales-stock" that can be dynamically chained into
            new client channels.

       Only meaningful when leaf_arity == FACTORY_ARITY_PS.  Phase 1 of
       the implementation (this PR) builds the structure + signs the
       initial state; Phase 2 adds the dynamic chain extension ceremony. */
    uint32_t ps_subfactory_arity;

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
    int dist_tx_ready;             /* 1 = unsigned TX built + sighash computed;
                                      2 = fully co-signed (#54 G1) */
    /* #54 G1: distributed MuSig co-signing of the distribution TX, so the
       offline-forever recovery net (dist TX, nLockTime = cltv_timeout) exists in
       the stateless creation path.  Key-path spend of the funding output over
       nodes[0].keyagg (no taptree), message = dist_sighash.  Mirrors the per-node
       session helpers but targets the funding output instead of a tree node. */
    musig_signing_session_t dist_signing_session;
    secp256k1_musig_partial_sig dist_partial_sigs[FACTORY_MAX_SIGNERS];
    int dist_partial_sigs_received;
    tx_buf_t dist_signed_tx;       /* fully-signed distribution TX (dist_tx_ready==2) */
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

/* Override the default L-stock CSV (BIP-68) blocks.  Must be called
   before factory_build_tree() — otherwise the L-stock SPK is already
   committed.  Pass 0 to keep the L_STOCK_CSV_DEFAULT_BLOCKS default. */
void factory_set_l_stock_csv(factory_t *f, uint32_t csv_blocks);

/* Set PS sub-factory arity k for the canonical k² PS leaf shape from
   t/1242.  k=1 (default) preserves 1-client-per-PS-leaf behavior; k>1
   makes each PS leaf host k sub-factories of k clients each (k²
   clients per leaf total).  Only meaningful for FACTORY_ARITY_PS;
   ignored otherwise.  Must be called before factory_build_tree().
   Bounded by FACTORY_MAX_OUTPUTS-1 (need room for the leaf-level
   L-stock output as the last vout). */
void factory_set_ps_subfactory_arity(factory_t *f, uint32_t k);

/* Build the unsigned L-stock POISON TRANSACTION for a leaf state.
   Spends the L-stock UTXO (`l_stock_txid:l_stock_vout` carrying
   `l_stock_amount_sats`) and pays each non-LSP signer in the leaf an
   equal share of `(l_stock_amount_sats - fee)` to a P2TR output keyed on
   that signer's xonly pubkey.

   Implements ZmnSCPxj's t/1242 "poison transaction" cheating-recovery
   mechanism: pre-signed at leaf-state-advance time, broadcast (by any
   client / watchtower) if the LSP publishes the corresponding stale
   leaf state on chain.  See docs/poison-tx.md (added in this PR) for
   the full security argument.

   Returns 1 on success.  Caller must initialize *poison_tx_out and
   free it after use.  Sets *sighash_out32 to the BIP-341 key-path
   sighash that signers must MuSig over to authorize the spend. */
int factory_build_l_stock_poison_tx_unsigned(
    const factory_t *f,
    const factory_node_t *leaf_node,
    const unsigned char *l_stock_txid32,
    uint32_t l_stock_vout,
    uint64_t l_stock_amount_sats,
    uint64_t fee_sats,
    tx_buf_t *poison_tx_out,
    unsigned char *sighash_out32,
    unsigned char *txid_out32);

/* Single-process variant: builds + N-of-N MuSig-co-signs + assembles
   the witness for the L-stock poison TX.  Requires that f->keypairs[]
   holds the seckey for every leaf signer (only true in the unit-test
   builder; the wire ceremony will use a multi-round equivalent in a
   follow-up PR).  Returns the fully-witnessed poison TX in *signed_out. */
int factory_sign_l_stock_poison_tx(
    factory_t *f,
    const factory_node_t *leaf_node,
    const unsigned char *l_stock_txid32,
    uint32_t l_stock_vout,
    uint64_t l_stock_amount_sats,
    uint64_t fee_sats,
    tx_buf_t *signed_out);

/* #53-B: enable revocation-gated (hashlock) L-stock poison.  Requires the
   factory seed to be set first (factory_set_shachain_seed); thereafter every
   leaf-state L-stock output (initial build + each advance) commits a per-(leaf,
   state) hash and the key-path poison is refused in favour of the script-path
   poison.  Returns 1 on success, 0 if no seed is set. */
int factory_enable_hashlock_poison(factory_t *f);

/* #59 / restart-resume: derive the per-factory L-stock poison MASTER seed
   deterministically from the LSP's master secret + the factory's funding outpoint:
   seed = tagged_hash("SS/LStockPoison/seed/v1", master32 || funding_txid32 ||
   funding_vout_le32).  Deterministic => survives LSP restart + backup-restore
   (re-derived, never stored as an independent secret — the elite "derive, don't
   store" rule).  Domain-separated from signing-key use (the tag) and per-factory
   (the funding outpoint binds it).  Trust-model-invisible: the client only verifies
   SHA256(secret)==committed H, so the LSP's seed derivation is internal.  One-way:
   leaking the derived seed never reveals `master32`. */
void factory_derive_lstock_seed(const unsigned char *master32,
                                const unsigned char *funding_txid32,
                                uint32_t funding_vout,
                                unsigned char *seed_out32);

/* #53-B: derive the LSP-private per-(leaf, state) L-stock revocation secret.
   secret = tagged_hash("SS/LStockPoison/v1", seed32 || leaf_agg_xonly32 ||
   state_counter_le32).  Deterministic + crash-recoverable (re-derivable from the
   persisted seed + the leaf's agg key + the state counter).  The matching hash
   H_s = SHA256(secret) is what Leaf P commits to; the secret is revealed to the
   leaf's clients only once state `state_counter` is superseded.  Returns 1 on
   success, 0 if the factory has no seed. */
int factory_derive_l_stock_secret(const factory_t *f,
                                  const factory_node_t *leaf_node,
                                  uint32_t state_counter,
                                  unsigned char secret_out32[32]);

/* #53-B3b.2a: CLIENT-side — record the LSP-shipped per-node L-stock hash so the
   client builds the matching 2-leaf L-stock SPK without the (LSP-private) seed.
   Call once per leaf node BEFORE factory_build_tree (and update before each advance
   when the new state's H arrives over the wire).  Sets the factory into mirror mode
   (apply_l_stock_hashlock then uses these hashes instead of deriving). */
void factory_set_node_l_stock_hash(factory_t *f, size_t node_idx,
                                   const unsigned char *h32);

/* Build the L-stock output scriptPubKey (P2TR) for a leaf state node — the
   2-leaf {poison, LSP-CSV} taptree when the node carries a per-state hash
   (#53), else the legacy single LSP-CSV leaf.  Exposed for tests and the
   reveal/recourse wiring; spk_out34 receives the 34-byte P2TR SPK. */
int build_l_stock_spk(const factory_t *f, const factory_node_t *leaf_node,
                      unsigned char *spk_out34);

/* Recovery helper: L-stock taptree merkle root for a leaf/sub node (the taptweak
   to key-path-spend that L-stock output in an offline residual sweep). */
int factory_l_stock_merkle(const factory_t *f, const factory_node_t *node,
                           unsigned char merkle_out32[32]);

/* #53: hashlock-gated L-stock poison over the Leaf-P SCRIPT-path (replaces the
   key-path poison, which is vulnerable to Scenario B).  Builds the per-client
   redistribution outputs, N-of-N MuSig-signs the UNtweaked agg key over the
   Leaf-P script-path sighash, and finalizes a complete consensus-valid witness
   tx using `secret32` (= the revealed revocation secret) as the hashlock preimage.
   Requires leaf_node->has_l_stock_hash; fails fast unless SHA256(secret32) equals
   the leaf's committed l_stock_hash.  Single-process (needs f->keypairs[] for every
   leaf signer); the multi-process wire ceremony co-signs the same Leaf-P sighash
   and supplies the preimage at broadcast (#53-B).  `poison_txid_out32` (optional,
   internal byte order) receives the poison txid. */
int factory_build_l_stock_poison_scriptpath(
    factory_t *f,
    const factory_node_t *leaf_node,
    const unsigned char *l_stock_txid32,
    uint32_t l_stock_vout,
    uint64_t l_stock_amount_sats,
    uint64_t fee_sats,
    const unsigned char *secret32,
    tx_buf_t *signed_out,
    unsigned char *poison_txid_out32);

/* #53-B3a: build the unsigned hashlock poison + its Leaf-P script-path sighash and
   witness components (Leaf-P script, 2-leaf control block), WITHOUT signing.  Used by
   the multi-process poison ceremony (which signs the sighash via the poison MuSig
   session) and by the single-process builder above.  The aggregated 64-byte Schnorr
   sig + the revealed secret are combined with these components at broadcast time via
   finalize_script_path_tx_preimage.  leaf_p_script_out (>= TAPSCRIPT_MAX_SCRIPT) and
   control_block_out (>= 65) are optional.  Requires has_l_stock_hash. */
int factory_build_l_stock_poison_scriptpath_unsigned(
    const factory_t *f,
    const factory_node_t *leaf_node,
    const unsigned char *l_stock_txid32,
    uint32_t l_stock_vout,
    uint64_t l_stock_amount_sats,
    uint64_t fee_sats,
    const unsigned char *override_hash32,  /* NULL = node's current hash; else the
                                              superseded state's H_old (#53-B3b) */
    tx_buf_t *unsigned_tx_out,
    unsigned char *sighash_out32,
    unsigned char *poison_txid_out32,
    unsigned char *leaf_p_script_out,
    size_t *leaf_p_script_len_out,
    unsigned char *control_block_out,
    size_t *control_block_len_out);

/* Cooperative N-of-N spend of an L-stock UTXO to a caller-specified
   output distribution.  The poison TX is a special case of this where
   outputs are the per-client equal split; the same helper is used for
   any legitimate cooperative L-stock spend (e.g. routing L-stock back
   to the LSP's wallet during a planned close, with all clients having
   agreed to the new distribution).

   Like factory_sign_l_stock_poison_tx, requires f->keypairs[] to hold
   the seckey for every leaf signer.  Multi-process wire-ceremony
   equivalent is a follow-up PR. */
int factory_sign_l_stock_cooperative_spend(
    factory_t *f,
    const factory_node_t *leaf_node,
    const unsigned char *l_stock_txid32,
    uint32_t l_stock_vout,
    uint64_t l_stock_amount_sats,
    const tx_output_t *outputs,
    size_t n_outputs,
    tx_buf_t *signed_out);

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

/* Bounded fresh-nonce retry (#48): max sign+verify attempts per ceremony before
   abort. Each attempt re-draws fresh nonces (never reused — see
   docs/p6-bounded-nonce-retry.md), so retry is nonce-reuse-safe. */
#define SS_NONCE_RETRY_MAX 3
int factory_sign_all_with_retry(factory_t *f, int max_attempts);
/* #48: ceremony-time verify of a cooperative-close aggregate sig (see factory.c). */
int factory_verify_close_sig(const factory_t *f, const unsigned char sig64[64],
                             const unsigned char sighash[32]);
extern int g_factory_test_force_verify_fail;   /* TEST-ONLY seam; always 0 in production */

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

/* Tick the root DW counter forward (PS Tier B trigger).  For PS factories,
   leaf advances are chain extension (no counter) — root rollover is driven
   by block-height progression instead.  Caller (LSP) wires this into a
   block-polling loop and runs Tier B on rc=-1.
   Returns -1 on epoch rollover (trees rebuilt; run Tier B);
   0 otherwise (no rollover or fully exhausted). */
int factory_tick_root(factory_t *f);

/* Sub-factory chain extension (Gap E followup Phase 2, t/1242 k² PS).

   Drives the canonical "buy liquidity from sales-stock" operation:
   the client at `channel_idx_in_sub` within sub-factory
   `sub_idx_in_leaf` of `leaf_side` gains `delta_sats` of inbound
   capacity by moving that amount out of the sub-factory's
   sales-stock vout.  Increments the sub-factory's ps_chain_len and
   rebuilds its unsigned_tx spending the prior chain TX's
   sales-stock vout.

   Caller drives the multi-party MuSig ceremony to re-sign the
   sub-factory node (LSP + k clients in this sub-factory) using the
   existing factory_session_*_node helpers.

   Phase 2 ships the unsigned-state primitive here; the wire
   ceremony driver (lsp_run_subfactory_advance) and client handler
   are Phase 2b — see docs/ps-subfactories.md.

   Returns 1 on success, 0 on failure (range checks, dust limit,
   sales-stock too small).  Pre-condition: factory_set_ps_subfactory_arity
   was set to k>1 and factory_build_tree completed. */
int factory_subfactory_chain_advance_unsigned(
    factory_t *f, int leaf_side, int sub_idx_in_leaf,
    int channel_idx_in_sub, uint64_t delta_sats);

/* Reset in-memory sub-factory chain advance state on chain reorg.

   Walks f->nodes[] for NODE_PS_SUBFACTORY entries and zeroes any node
   whose ps_chain_len > 0 (i.e., has been advanced).  After the reset,
   force-close falls back to chain[0] (the v23/PR #144 path), which spends
   the factory leaf output directly and is unaffected by reorg of chain[N]
   parent UTXOs.

   The on-disk ps_subfactory_chains rows are preserved for forensics
   (operator audit, dashboard observability) — only the in-memory state
   is reset.  This is a conservative response: a deep reorg of a confirmed
   chain[N-1] invalidates chain[N]'s prev-output reference, so signing or
   broadcasting chain[N] from the divergent in-memory state would fail.

   Returns the count of sub-factories reset (for observability). */
int factory_reset_all_subfactory_chains(factory_t *f);

/* #146: height-aware variant.  Only resets sub-factory chain state for
   nodes whose ps_chain_confirmed_height > reorg_max_safe_height (i.e.,
   their latest confirmation is no longer on the active chain).  Nodes
   with ps_chain_confirmed_height == 0 (legacy / unset) are reset
   conservatively (matches pre-#146 behavior) so a missing confirmation
   record never silently leaves stale state.  Returns the count reset.

   reorg_max_safe_height is the highest block height that's still
   confirmed on the new tip — typically the new tip height itself minus
   a safety buffer.  Anything strictly above that may have been reorged
   out and needs invalidation. */
int factory_reset_subfactory_chains_above_height(factory_t *f,
                                                  uint32_t reorg_max_safe_height);

/* #146: record the height at which a sub-factory chain entry was
   observed confirmed.  Stamped by the reorg detector / heartbeat when
   it sees the latest chain TX in a block, so subsequent reorgs can use
   factory_reset_subfactory_chains_above_height to avoid wiping
   still-confirmed state.  No-op when the node isn't a PS sub-factory or
   has ps_chain_len == 0. */
void factory_set_subfactory_chain_confirmed_height(factory_t *f,
                                                    size_t node_idx,
                                                    uint32_t confirmed_height);

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

/* --- Multi-input per-input split-round signing helpers (#207) ---
   Used for advanced PS sub-factory chain extensions where the new TX
   has k+1 inputs (one per chain[N-1] vout).  Each input gets its own
   MuSig session because BIP-341 sighashes differ per input.  All k+1
   sigs are then assembled into a single segwit signed_tx via
   factory_session_assemble_signed_tx_multi.

   Lifecycle for each input_idx in [0, n_inputs):
     1. factory_session_init_node_input  — fresh session for this input
     2. factory_session_set_nonce_input  — per-signer pubnonce
     3. factory_session_finalize_node_input — compute per-input sighash
        + run musig_session_finalize_nonces
     4. factory_session_set_partial_sig_input — per-signer partial sig
     5. factory_session_complete_node_input — aggregate to 64-byte sig
        + store internally
   Then once per node:
     6. factory_session_assemble_signed_tx_multi — emit segwit signed_tx
        with all k+1 witnesses */
int factory_session_init_node_input(factory_t *f, size_t node_idx, size_t input_idx);
int factory_session_set_nonce_input(factory_t *f, size_t node_idx, size_t input_idx,
                                      size_t signer_slot,
                                      const secp256k1_musig_pubnonce *pubnonce);
int factory_session_finalize_node_input(factory_t *f, size_t node_idx, size_t input_idx);
int factory_session_set_partial_sig_input(factory_t *f, size_t node_idx, size_t input_idx,
                                            size_t signer_slot,
                                            const secp256k1_musig_partial_sig *psig);
int factory_session_complete_node_input(factory_t *f, size_t node_idx, size_t input_idx);
int factory_session_assemble_signed_tx_multi(factory_t *f, size_t node_idx);

/* Helper: returns 1 if node_idx is an advanced PS sub-factory node that
   uses the multi-input chain advance path (i.e. n_inputs > 1).  Used by
   callers to dispatch between single-input and multi-input session APIs. */
int factory_node_uses_multi_input(const factory_t *f, size_t node_idx);

/* --- Wire-ceremony poison TX dual-signing helpers (closes SECURITY GAP) ---
   These mirror the per-node session helpers above but operate on the
   `poison_signing_session` slot, allowing the LSP to coordinate a
   second MuSig2 round across all signers for the OLD state's L-stock /
   sales-stock poison TX in lockstep with the new state advance.
   Critical: each helper uses INDEPENDENT nonces from the state-advance
   session — MuSig2 mandates fresh nonces per signed message.

   Lifecycle:
     1. factory_session_prepare_poison_tx_subfactory — builds the unsigned
        poison TX bytes against the OLD chain[N-1] sales-stock UTXO and
        records its sighash on the node.
     2. factory_session_init_node_poison — fresh musig session.
     3. factory_session_set_nonce_poison — set each signer's pubnonce.
     4. factory_session_finalize_node_poison — compute aggnonce against
        the stored poison_sighash.
     5. factory_session_set_partial_sig_poison — collect partial sigs.
     6. factory_session_complete_node_poison — aggregate + finalize a
        64-byte witness, finalize signed_tx in poison_signed_tx. */
int factory_session_prepare_poison_tx_subfactory(
    factory_t *f, size_t sub_node_idx,
    const unsigned char *old_chain_txid32, uint32_t old_sstock_vout,
    uint64_t old_sstock_amount_sats, uint64_t fee_sats,
    const unsigned char *override_hash32);  /* #53-B3b: superseded state's H_old; NULL = node's current */

/* Same as the subfactory variant but for a DW / PS LEAF node — used by
   the lsp_advance_leaf wire ceremony to bundle a poison TX over the
   OLD state's L-stock UTXO alongside the new state TX advance. */
int factory_session_prepare_poison_tx_leaf(
    factory_t *f, size_t leaf_node_idx,
    const unsigned char *old_leaf_txid32, uint32_t old_l_stock_vout,
    uint64_t old_l_stock_amount_sats, uint64_t fee_sats,
    const unsigned char *override_hash32);  /* #53-B3b: superseded state's H_old; NULL = node's current */
int factory_session_init_node_poison(factory_t *f, size_t node_idx);
int factory_session_set_nonce_poison(factory_t *f, size_t node_idx,
                                       size_t signer_slot,
                                       const secp256k1_musig_pubnonce *pubnonce);
int factory_session_finalize_node_poison(factory_t *f, size_t node_idx);
int factory_session_set_partial_sig_poison(factory_t *f, size_t node_idx,
                                             size_t signer_slot,
                                             const secp256k1_musig_partial_sig *psig);
int factory_session_complete_node_poison(factory_t *f, size_t node_idx);

/* #53-B3a: assemble the broadcastable hashlock poison from the ceremony-aggregated
   sig + the revealed secret (Leaf-P witness preimage).  Only valid for a script-path
   poison node (poison_is_scriptpath + poison_has_agg_sig) whose secret matches the
   committed hash.  `out` receives the complete witness tx.  Returns 1 on success. */
int factory_assemble_poison_with_secret(factory_t *f, size_t node_idx,
                                        const unsigned char *secret32,
                                        tx_buf_t *out);

/* #53 Phase 4a: standalone L-stock poison assembly from PERSISTED template fields
   (no live factory_node needed) — the crash-resilient / standalone recourse entry
   point.  A client (or the watchtower it feeds) loads its l_stock_poison_reveals
   row (unsigned tx + aggregated Leaf-P sig + leaf script + control block + the
   superseded state's committed hash + the LSP-revealed secret) and assembles the
   broadcastable witness here.  Verifies SHA256(secret32)==target_hash32
   (fail-closed) before building [agg_sig, secret, Leaf-P script, control block].
   factory_assemble_poison_with_secret delegates to this.  Returns 1 on success,
   0 on hash-mismatch / bad input. */
int factory_assemble_poison_from_template(
    const unsigned char *unsigned_tx, size_t unsigned_tx_len,
    const unsigned char *agg_sig64,
    const unsigned char *secret32,
    const unsigned char *target_hash32,
    const unsigned char *leaf_script, size_t leaf_script_len,
    const unsigned char *control_block, size_t control_block_len,
    tx_buf_t *out);

/* Reset poison state on a node (free the unsigned/signed tx buffers + clear
   sighash + reset received counter).  Safe to call on a never-prepared
   node.  Used during cleanup and after the poison TX is handed to the
   watchtower. */
void factory_session_reset_poison(factory_t *f, size_t node_idx);

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

/* Build the L-stock POISON TX for a stale leaf state (canonical t/1242
   design — supersedes the legacy OP_RETURN burn-as-fee approach).  Thin
   wrapper around factory_sign_l_stock_poison_tx; kept for source
   compatibility with the existing watchtower call site.

   `leaf_node` identifies which leaf's L-stock is being poisoned (its
   keyagg + signers determine the SPK and the per-client distribution).
   `l_stock_txid32` / `l_stock_vout` / `l_stock_amount` describe the
   on-chain UTXO of the OLD stale state being recovered from.

   The `epoch` parameter is unused — the new design's authority is the
   leaf signers' N-of-N MuSig, not a per-epoch hashlock secret. */
int factory_build_burn_tx(factory_t *f, tx_buf_t *burn_tx_out,
                           const factory_node_t *leaf_node,
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

/* SF-MULTI-KEYAGG (#283): per-input signer-slot helpers.  Multi-input
   sub-factory chain advance nodes use a per-input keyagg whose signer set
   differs from the node-level signer set (channel inputs sign 2-of-2;
   sales-stock input signs N-of-N).  These helpers expose the
   participant->slot mapping so the wire layer can dispatch correctly. */
int factory_session_get_input_signer_slot(const factory_t *f,
                                            size_t node_idx,
                                            size_t input_idx,
                                            uint32_t participant_idx);
int factory_session_input_signs(const factory_t *f,
                                  size_t node_idx,
                                  size_t input_idx,
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

/* #54 G1: distributed MuSig co-signing of the distribution TX (the offline-forever
   recovery net) so it exists in the stateless creation path.  The dist TX is a
   key-path spend of the funding output over nodes[0].keyagg (same agg key as the
   root kickoff, no taptree), message = f->dist_sighash.  Requires
   factory_build_distribution_tx_unsigned() to have run first (dist_tx_ready>=1).
   Usage (per signer, mirroring the per-node session helpers):
     1. factory_session_init_dist          — init the all-N session
     2. factory_session_set_nonce_dist      — set each signer's pubnonce (slot order)
     3. factory_session_finalize_dist       — nonce_process over dist_sighash
     4. factory_session_set_partial_sig_dist— set each signer's partial sig
     5. factory_session_complete_dist       — aggregate -> finalize f->dist_signed_tx,
                                              set dist_tx_ready=2
   All return 1 on success, 0 on failure. */
int factory_session_init_dist(factory_t *f);
int factory_session_set_nonce_dist(factory_t *f, size_t signer_slot,
                                   const secp256k1_musig_pubnonce *pubnonce);
int factory_session_finalize_dist(factory_t *f);
int factory_session_set_partial_sig_dist(factory_t *f, size_t signer_slot,
                                         const secp256k1_musig_partial_sig *psig);
int factory_session_complete_dist(factory_t *f);

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
