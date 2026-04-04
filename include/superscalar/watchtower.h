#ifndef SUPERSCALAR_WATCHTOWER_H
#define SUPERSCALAR_WATCHTOWER_H

#include "channel.h"
#include "persist.h"
#include "regtest.h"
#include "fee.h"
#include "chain_backend.h"
#include "wallet_source.h"
#include "htlc_fee_bump.h"
#include <secp256k1.h>

#define WATCHTOWER_MAX_WATCH 128

typedef enum {
    WATCH_COMMITMENT,      /* Channel commitment breach — build penalty tx */
    WATCH_FACTORY_NODE,    /* Factory state breach — broadcast latest state tx */
    WATCH_FORCE_CLOSE      /* Force-close: sweep expired HTLC timeout outputs */
} watchtower_entry_type_t;

typedef struct watchtower_htlc {
    uint32_t htlc_vout;
    uint64_t htlc_amount;
    unsigned char htlc_spk[34];
    htlc_direction_t direction;
    unsigned char payment_hash[32];
    uint32_t cltv_expiry;
    char sweep_txid[65];          /* hex txid of broadcast timeout sweep (empty = not yet swept) */
} watchtower_htlc_t;

typedef struct {
    watchtower_entry_type_t type;
    uint32_t channel_id;          /* channel index (commitment) or node index (factory) */
    uint64_t commit_num;          /* commitment number or DW epoch */
    unsigned char txid[32];       /* txid to watch for (internal byte order) */
    int32_t registered_height;    /* chain height when this entry was registered;
                                     skip if confirmed tx predates this height */

    /* WATCH_COMMITMENT fields */
    uint32_t to_local_vout;
    uint64_t to_local_amount;
    unsigned char to_local_spk[34];
    size_t to_local_spk_len;

    /* HTLC outputs on the breached commitment (for penalty sweep) */
    watchtower_htlc_t *htlc_outputs;
    size_t n_htlc_outputs;
    size_t htlc_outputs_cap;

    /* PTLC outputs on the breached commitment (for penalty sweep) */
    watchtower_htlc_t *ptlc_outputs;   /* reuses watchtower_htlc_t layout */
    size_t n_ptlc_outputs;

    /* WATCH_FACTORY_NODE fields */
    unsigned char *response_tx;   /* heap-allocated latest state tx to broadcast */
    size_t response_tx_len;
    unsigned char *burn_tx;       /* heap-allocated pre-built L-stock burn tx */
    size_t burn_tx_len;

    /* Reorg resistance: penalty broadcast tracking.
       After penalty broadcast, entry is KEPT (not removed) until penalty
       has safe confirmations. If penalty tx disappears (reorg), the entry
       reverts to normal watching and re-detects the breach. */
    int penalty_broadcast;        /* 1 = penalty has been broadcast */
    char penalty_txid[65];        /* hex txid of broadcast penalty */
} watchtower_entry_t;

#define WATCHTOWER_MAX_CHANNELS 32
#define WATCHTOWER_MAX_PENDING 16
#define WATCHTOWER_ANCHOR_AMOUNT ANCHOR_OUTPUT_AMOUNT

/* Pending penalty tx awaiting confirmation (for CPFP bump) */
typedef struct {
    char txid[65];              /* penalty tx we broadcast */
    uint32_t anchor_vout;       /* anchor output index (always 1) */
    uint64_t anchor_amount;     /* 240 sats (P2A) */
    int cycles_in_mempool;      /* how many 5s cycles it's been stuck */
    htlc_fee_bump_t fee_bump;   /* deadline-aware fee escalation (replaces bump_count) */
} watchtower_pending_t;

typedef struct {
    watchtower_entry_t *entries;
    size_t n_entries;
    size_t entries_cap;
    channel_t **channels;  /* pointers to channels by index */
    size_t n_channels;
    size_t channels_cap;
    chain_backend_t *chain;        /* chain queries + tx broadcast (abstract) */
    chain_backend_t _chain_regtest_wrapper; /* embedded storage when backed by regtest_t */
    regtest_t *rt;                 /* regtest handle for mining / compat (may be NULL) */
    fee_estimator_t *fee;
    wallet_source_t *wallet;       /* UTXO selection + signing for CPFP (may be NULL) */
    wallet_source_rpc_t _wallet_rpc_default; /* auto-init'd when rt != NULL */
    persist_t *db;

    /* P2A anchor SPK for CPFP fee bumping (anyone-can-spend, no keys needed) */
    unsigned char anchor_spk[P2A_SPK_LEN];
    size_t anchor_spk_len;

    /* Pending penalty txs awaiting confirmation */
    watchtower_pending_t *pending;
    size_t n_pending;
    size_t pending_cap;
} watchtower_t;

/* Initialize watchtower. Load old commitments from DB if available.
   If rt is non-NULL, automatically wraps it as the chain backend. */
int watchtower_init(watchtower_t *wt, size_t n_channels,
                      regtest_t *rt, fee_estimator_t *fee, persist_t *db);

/* Override the chain backend (e.g. plug in a BIP 158 light client).
   Must be called after watchtower_init. The caller owns the backend lifetime. */
void watchtower_set_chain_backend(watchtower_t *wt, chain_backend_t *backend);

/* Override the wallet source (e.g. plug in a hardware wallet or mobile wallet).
   Must be called after watchtower_init. The caller owns the wallet lifetime.
   Pass NULL to disable CPFP (watchtower_build_cpfp_tx will return 0). */
void watchtower_set_wallet(watchtower_t *wt, wallet_source_t *wallet);

/* Set channel pointer for a given index. */
void watchtower_set_channel(watchtower_t *wt, size_t idx, channel_t *ch);

/* Add an old commitment to watch for. */
int watchtower_watch(watchtower_t *wt, uint32_t channel_id,
                       uint64_t commit_num, const unsigned char *txid32,
                       uint32_t to_local_vout, uint64_t to_local_amount,
                       const unsigned char *to_local_spk, size_t spk_len);

/* Check chain for breaches. For each detected breach:
   1. Build penalty tx via channel_build_penalty_tx()
   2. Broadcast via regtest_send_raw_tx()
   Returns number of penalties broadcast. */
int watchtower_check(watchtower_t *wt);

/* After receiving a revocation, register the old commitment with the watchtower.
   Rebuilds the old commitment tx to get its txid and to_local output info.
   old_htlcs/old_n_htlcs: snapshot of HTLC state at the time of the old commitment.
   Pass NULL/0 if HTLC state is not available (HTLC outputs won't be watched). */
void watchtower_watch_revoked_commitment(watchtower_t *wt, channel_t *ch,
                                           uint32_t channel_id,
                                           uint64_t old_commit_num,
                                           uint64_t old_local, uint64_t old_remote,
                                           const htlc_t *old_htlcs, size_t old_n_htlcs);

/* Remove entries for a channel (e.g., after cooperative close). */
void watchtower_remove_channel(watchtower_t *wt, uint32_t channel_id);

/* Watch for an old factory state node. If detected, broadcast latest state tx
   and burn tx (if provided). Both are copied (caller can free theirs).
   burn_tx may be NULL (no L-stock burn). */
int watchtower_watch_factory_node(watchtower_t *wt, uint32_t node_idx,
                                    const unsigned char *old_txid32,
                                    const unsigned char *response_tx,
                                    size_t response_tx_len,
                                    const unsigned char *burn_tx,
                                    size_t burn_tx_len);

/* Register a force-closed commitment for HTLC timeout sweeping.
   After a legitimate force-close (not breach), HTLCs need to be swept
   via timeout txs once their CLTV expires. The watchtower monitors
   block height and auto-broadcasts timeout txs.
   commitment_txid: the on-chain commitment tx (internal byte order).
   htlcs/n_htlcs: pending HTLCs on the commitment. */
int watchtower_watch_force_close(watchtower_t *wt, uint32_t channel_id,
                                  const unsigned char *commitment_txid,
                                  const watchtower_htlc_t *htlcs, size_t n_htlcs);

/* Free heap-allocated response_tx buffers in factory entries. */
void watchtower_cleanup(watchtower_t *wt);

/* Clear all watchtower entries (e.g., after factory rotation).
   Frees any allocated data and resets the entry count to 0. */
void watchtower_clear_entries(watchtower_t *wt);

/* Re-validate watchtower state after a detected reorg.
   Resets penalty_broadcast for entries whose penalty tx is no longer
   confirmed or in mempool, allowing re-detection on the next cycle. */
void watchtower_on_reorg(watchtower_t *wt, int new_tip, int old_tip);

/* Build a CPFP child tx to bump a stuck penalty tx.
   Uses anchor output from penalty tx + wallet UTXO.
   Returns 1 on success, 0 on failure. */
int watchtower_build_cpfp_tx(watchtower_t *wt,
                               tx_buf_t *cpfp_tx_out,
                               const char *parent_txid,
                               uint32_t anchor_vout,
                               uint64_t anchor_amount);

/* Phase L: register any broadcast tx for CPFP monitoring.
   Mirrors what penalty-tx broadcast does internally. Returns 1 on success.
   Returns 0 if table full or wt/txid_hex is NULL. */
int watchtower_add_pending_tx(watchtower_t *wt,
                               const char *txid_hex,
                               uint32_t anchor_vout,
                               uint64_t anchor_amount);

#endif /* SUPERSCALAR_WATCHTOWER_H */
