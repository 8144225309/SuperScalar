#ifndef SUPERSCALAR_WATCHTOWER_H
#define SUPERSCALAR_WATCHTOWER_H

#include "channel.h"
#include "persist.h"
#include "regtest.h"
#include "fee.h"
#include <secp256k1.h>

#define WATCHTOWER_MAX_WATCH 64

typedef enum {
    WATCH_COMMITMENT,      /* Channel commitment breach — build penalty tx */
    WATCH_FACTORY_NODE     /* Factory state breach — broadcast latest state tx */
} watchtower_entry_type_t;

typedef struct watchtower_htlc {
    uint32_t htlc_vout;
    uint64_t htlc_amount;
    unsigned char htlc_spk[34];
    htlc_direction_t direction;
    unsigned char payment_hash[32];
    uint32_t cltv_expiry;
} watchtower_htlc_t;

typedef struct {
    watchtower_entry_type_t type;
    uint32_t channel_id;          /* channel index (commitment) or node index (factory) */
    uint64_t commit_num;          /* commitment number or DW epoch */
    unsigned char txid[32];       /* txid to watch for (internal byte order) */

    /* WATCH_COMMITMENT fields */
    uint32_t to_local_vout;
    uint64_t to_local_amount;
    unsigned char to_local_spk[34];
    size_t to_local_spk_len;

    /* HTLC outputs on the breached commitment (for penalty sweep) */
    watchtower_htlc_t htlc_outputs[MAX_HTLCS];
    size_t n_htlc_outputs;

    /* WATCH_FACTORY_NODE fields */
    unsigned char *response_tx;   /* heap-allocated latest state tx to broadcast */
    size_t response_tx_len;
} watchtower_entry_t;

#define WATCHTOWER_MAX_CHANNELS 8
#define WATCHTOWER_MAX_PENDING 16
#define WATCHTOWER_ANCHOR_AMOUNT ANCHOR_OUTPUT_AMOUNT

/* Pending penalty tx awaiting confirmation (for CPFP bump) */
typedef struct {
    char txid[65];              /* penalty tx we broadcast */
    uint32_t anchor_vout;       /* anchor output index (always 1) */
    uint64_t anchor_amount;     /* 240 sats (P2A) */
    int cycles_in_mempool;      /* how many 5s cycles it's been stuck */
    int bump_count;             /* how many CPFP bumps attempted (max 3) */
    int cycles_since_bump;      /* cycles since last bump attempt */
} watchtower_pending_t;

typedef struct {
    watchtower_entry_t entries[WATCHTOWER_MAX_WATCH];
    size_t n_entries;
    channel_t *channels[WATCHTOWER_MAX_CHANNELS];  /* pointers to channels by index */
    size_t n_channels;
    regtest_t *rt;                 /* for chain queries + broadcasting */
    fee_estimator_t *fee;
    persist_t *db;

    /* P2A anchor SPK for CPFP fee bumping (anyone-can-spend, no keys needed) */
    unsigned char anchor_spk[P2A_SPK_LEN];
    size_t anchor_spk_len;

    /* Pending penalty txs awaiting confirmation */
    watchtower_pending_t pending[WATCHTOWER_MAX_PENDING];
    size_t n_pending;
} watchtower_t;

/* Initialize watchtower. Load old commitments from DB if available. */
int watchtower_init(watchtower_t *wt, size_t n_channels,
                      regtest_t *rt, fee_estimator_t *fee, persist_t *db);

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

/* Watch for an old factory state node. If detected, broadcast latest state tx.
   response_tx is copied (caller can free theirs). */
int watchtower_watch_factory_node(watchtower_t *wt, uint32_t node_idx,
                                    const unsigned char *old_txid32,
                                    const unsigned char *response_tx,
                                    size_t response_tx_len);

/* Free heap-allocated response_tx buffers in factory entries. */
void watchtower_cleanup(watchtower_t *wt);

/* Build a CPFP child tx to bump a stuck penalty tx.
   Uses anchor output from penalty tx + wallet UTXO.
   Returns 1 on success, 0 on failure. */
int watchtower_build_cpfp_tx(watchtower_t *wt,
                               tx_buf_t *cpfp_tx_out,
                               const char *parent_txid,
                               uint32_t anchor_vout,
                               uint64_t anchor_amount);

#endif /* SUPERSCALAR_WATCHTOWER_H */
