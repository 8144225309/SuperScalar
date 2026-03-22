#ifndef SUPERSCALAR_ROUTE_POLICY_H
#define SUPERSCALAR_ROUTE_POLICY_H

/*
 * route_policy.h — Per-channel HTLC forwarding policy enforcement
 *
 * Every routing node must check forwarding constraints before relaying an HTLC:
 *   - Fee: (in_amount - out_amount) >= base_fee + out_amount * fee_ppm / 1_000_000
 *   - CLTV delta: (in_cltv - out_cltv) >= cltv_expiry_delta
 *   - HTLC minimum: out_amount >= htlc_minimum_msat
 *   - HTLC maximum: out_amount <= htlc_maximum_msat (if set)
 *   - Channel not disabled
 *
 * Reference:
 *   BOLT #7 §channel_update, BOLT #4 §forwarding-htlcs
 *   LDK: lightning/src/routing/router.rs (ChannelUsage)
 *   CLN: channeld/channeld.c (check_htlc_send)
 *   LND: routing/payment_lifecycle.go
 */

#include <stdint.h>
#include <stddef.h>

/* Return codes from route_policy_check() */
#define POLICY_OK                  0
#define POLICY_FEE_INSUFFICIENT    1   /* fee not enough */
#define POLICY_HTLC_TOO_SMALL      2   /* amount below htlc_minimum_msat */
#define POLICY_HTLC_TOO_LARGE      3   /* amount above htlc_maximum_msat */
#define POLICY_CLTV_TOO_SMALL      4   /* CLTV delta below required */
#define POLICY_CHANNEL_DISABLED    5   /* channel is disabled */
#define POLICY_EXPIRY_TOO_SOON     6   /* absolute CLTV expiry too close to chain tip */
#define POLICY_AMOUNT_ZERO         7   /* zero amount rejected */

/* BOLT #4: minimum remaining blocks before we forward (prevent expiry races) */
#define POLICY_MIN_FINAL_CLTV_DELTA  18u  /* conservative minimum */

/* channel_update wire flags */
#define POLICY_FLAG_DISABLED       0x0002  /* direction disabled bit */
#define POLICY_FLAG_HTLC_MAX_SET   0x0001  /* htlc_maximum_msat present */

#define POLICY_TABLE_MAX           256     /* max tracked channel-direction pairs */

typedef struct {
    uint64_t scid;                  /* short channel ID */
    int      direction;             /* 0 = node1→node2, 1 = node2→node1 */
    uint32_t fee_base_msat;         /* base fee in msat */
    uint32_t fee_ppm;               /* fee proportional to amount (per-million) */
    uint16_t cltv_expiry_delta;     /* minimum CLTV delta required */
    uint64_t htlc_minimum_msat;     /* minimum HTLC size (0 = any) */
    uint64_t htlc_maximum_msat;     /* maximum HTLC size (0 = unlimited) */
    int      disabled;              /* 1 if channel direction is disabled */
    uint32_t last_update;           /* Unix timestamp of last channel_update */
} route_policy_t;

typedef struct {
    route_policy_t entries[POLICY_TABLE_MAX];
    int            count;
} route_policy_table_t;

/* ---- Policy check ---- */

/*
 * Compute the minimum fee required to forward out_amount_msat.
 * fee = fee_base_msat + (out_amount_msat * fee_ppm) / 1_000_000
 * Rounds up to ensure fee collection is never under-estimated.
 */
uint64_t route_policy_compute_fee(const route_policy_t *policy,
                                   uint64_t out_amount_msat);

/*
 * Validate an HTLC forward against policy.
 *
 * policy:          channel policy for this (scid, direction).
 * in_amount_msat:  amount arriving on the inbound HTLC.
 * out_amount_msat: amount to be forwarded on the outbound HTLC.
 * in_cltv:         absolute CLTV of inbound HTLC.
 * out_cltv:        absolute CLTV to be set on outbound HTLC.
 * chain_height:    current best block height (for expiry check; 0 = skip).
 *
 * Returns POLICY_OK or an error code.
 */
int route_policy_check(const route_policy_t *policy,
                       uint64_t in_amount_msat,
                       uint64_t out_amount_msat,
                       uint32_t in_cltv,
                       uint32_t out_cltv,
                       uint32_t chain_height);

/* ---- Wire encode/decode ---- */

/*
 * Build a channel_update wire message (type 258) into buf.
 * sig: 64-byte Schnorr/ECDSA signature over the unsigned hash.
 * chain_hash: 32-byte chain genesis hash.
 * Returns bytes written, 0 on error (buffer too small).
 */
size_t route_policy_build_channel_update(const route_policy_t *policy,
                                          const unsigned char sig[64],
                                          const unsigned char chain_hash[32],
                                          uint32_t timestamp,
                                          unsigned char *buf, size_t buf_cap);

/*
 * Parse a channel_update wire message (type 258) into a policy struct.
 * Fills scid, direction, fee_base, fee_ppm, cltv_expiry_delta,
 * htlc_minimum_msat, htlc_maximum_msat, disabled, last_update.
 * Returns 1 on success, 0 on parse error.
 */
int route_policy_parse_channel_update(const unsigned char *msg, size_t msg_len,
                                       route_policy_t *out);

/* ---- Policy table ---- */

/*
 * Upsert a policy entry (scid, direction) in the table.
 * Replaces existing entry if present; appends if new (table full → oldest evicted).
 */
void route_policy_upsert(route_policy_table_t *tbl, const route_policy_t *policy);

/*
 * Find a policy by (scid, direction). Returns pointer or NULL.
 */
const route_policy_t *route_policy_find(const route_policy_table_t *tbl,
                                         uint64_t scid, int direction);

/*
 * Set disabled flag for (scid, direction). Returns 1 if found, 0 if not.
 */
int route_policy_set_disabled(route_policy_table_t *tbl,
                               uint64_t scid, int direction, int disabled);

#endif /* SUPERSCALAR_ROUTE_POLICY_H */
