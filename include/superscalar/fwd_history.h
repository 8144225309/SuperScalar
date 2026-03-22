#ifndef SUPERSCALAR_FWD_HISTORY_H
#define SUPERSCALAR_FWD_HISTORY_H

/*
 * fwd_history.h — HTLC forwarding history and channel statistics
 *
 * Records every settled HTLC relay with in/out amounts, SCIDs, and timestamps.
 * Used for:
 *   - LSP fee income reporting (CLN: listforwards, LND: fwdinghistory)
 *   - Channel utilization analysis (which channels route the most)
 *   - Network health monitoring
 *   - Automatic rebalancing decisions
 *
 * Reference:
 *   CLN: forwarding.c (listforwards), plugins/bookkeeper/
 *   LND: routing/payment_lifecycle.go, lnrpc.ForwardingHistory
 *   LDK: lightning/src/routing/scoring.rs (channel usage)
 */

#include <stdint.h>
#include <stddef.h>

#define FWD_HISTORY_MAX    2048   /* ring buffer size */

typedef enum {
    FWD_STATUS_SETTLED   = 0,   /* HTLC fulfilled (fee collected) */
    FWD_STATUS_FAILED    = 1,   /* HTLC failed (no fee) */
    FWD_STATUS_LOCAL     = 2,   /* final hop — payment to us, not a relay */
} fwd_status_t;

typedef struct {
    uint64_t        scid_in;           /* inbound short_channel_id */
    uint64_t        scid_out;          /* outbound short_channel_id (0 if local) */
    uint64_t        in_amount_msat;    /* amount arriving on inbound HTLC */
    uint64_t        out_amount_msat;   /* amount forwarded on outbound HTLC */
    uint64_t        fee_msat;          /* fee collected = in - out */
    uint32_t        resolved_at;       /* Unix timestamp when settled/failed */
    unsigned char   payment_hash[32];  /* identifies the payment */
    fwd_status_t    status;
} fwd_history_entry_t;

typedef struct {
    fwd_history_entry_t entries[FWD_HISTORY_MAX];
    int   count;          /* total entries stored (wraps at FWD_HISTORY_MAX) */
    int   head;           /* next write position (ring buffer) */
    uint64_t total_settled;  /* cumulative settled count since init */
    uint64_t total_failed;   /* cumulative failed count since init */
} fwd_history_t;

/* Initialise an empty history table. */
void fwd_history_init(fwd_history_t *h);

/*
 * Record a forwarding result.
 * scid_out = 0 for final-hop (local payment, not relay).
 * Overwrites oldest entry when the ring buffer is full.
 */
void fwd_history_add(fwd_history_t *h,
                     uint64_t scid_in, uint64_t scid_out,
                     uint64_t in_amount_msat, uint64_t out_amount_msat,
                     uint32_t resolved_at,
                     const unsigned char payment_hash[32],
                     fwd_status_t status);

/*
 * Total fees earned from successful forwards in time range [since, until].
 * Pass 0 for since/until to include all entries.
 */
uint64_t fwd_history_fee_total(const fwd_history_t *h,
                                uint32_t since, uint32_t until);

/*
 * Total forwarded volume (out_amount_msat) for a specific outbound scid
 * in time range [since, until].
 * scid_out = 0 → sum over all channels.
 */
uint64_t fwd_history_volume(const fwd_history_t *h,
                              uint64_t scid_out,
                              uint32_t since, uint32_t until);

/*
 * Count of settled forwards for a specific inbound scid in [since, until].
 * scid_in = 0 → count over all channels.
 */
int fwd_history_count(const fwd_history_t *h,
                       uint64_t scid_in,
                       uint32_t since, uint32_t until);

/*
 * Average fee in msat per settled forward in [since, until].
 * Returns 0 if no settled forwards in range.
 */
uint64_t fwd_history_avg_fee(const fwd_history_t *h,
                              uint32_t since, uint32_t until);

/*
 * Find the channel pair with the highest fee income in [since, until].
 * Sets scid_in_out and scid_out_out to the winning pair.
 * Returns total fee for that pair, 0 if history is empty.
 */
uint64_t fwd_history_top_channel(const fwd_history_t *h,
                                  uint32_t since, uint32_t until,
                                  uint64_t *scid_in_out,
                                  uint64_t *scid_out_out);

/*
 * Remove all entries older than cutoff_unix.
 * Returns count of entries removed.
 */
int fwd_history_prune(fwd_history_t *h, uint32_t cutoff_unix);

#endif /* SUPERSCALAR_FWD_HISTORY_H */
