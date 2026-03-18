/*
 * probe.h — Fake-HTLC channel liquidity probing
 *
 * Probing sends an update_add_htlc with a random payment hash that has
 * no corresponding preimage.  The response reveals whether a channel has
 * sufficient liquidity for a given amount:
 *
 *   UNKNOWN_PAYMENT_HASH (0x000F) → probe reached destination; route is liquid
 *   TEMPORARY_CHANNEL_FAILURE (0x1007) → a hop had insufficient balance
 *   AMOUNT_BELOW_MINIMUM (0x100B) → amount is below a hop's htlc_minimum_msat
 *   CHANNEL_DISABLED (0x1006)    → a hop's channel is offline
 *   UNKNOWN_NEXT_PEER (0x1009)   → a hop's next peer is unknown (channel gone)
 *
 * Reference: BOLT #4 §failure-messages, CLN probe plugin, LND probing.
 */

#ifndef SUPERSCALAR_PROBE_H
#define SUPERSCALAR_PROBE_H

#include <stdint.h>
#include <stddef.h>

/* BOLT #4 failure codes relevant to probing */
#define PROBE_ERR_UNKNOWN_PAYMENT_HASH      0x000F  /* destination reached */
#define PROBE_ERR_TEMPORARY_CHANNEL_FAILURE 0x1007  /* hop liquidity insufficient */
#define PROBE_ERR_CHANNEL_DISABLED          0x1006  /* channel offline */
#define PROBE_ERR_UNKNOWN_NEXT_PEER         0x1009  /* next hop unknown */
#define PROBE_ERR_AMOUNT_BELOW_MINIMUM      0x100B  /* amount below htlc_min */
#define PROBE_ERR_FEE_INSUFFICIENT          0x100C  /* fee is too low */
#define PROBE_ERR_INCORRECT_CLTV_EXPIRY     0x100D  /* wrong CLTV */
#define PROBE_ERR_EXPIRY_TOO_SOON           0x100E  /* CLTV too close */
#define PROBE_ERR_FINAL_EXPIRY_TOO_SOON     0x0011  /* CLTV too close at dest */

typedef enum {
    PROBE_RESULT_LIQUID,       /* route had enough liquidity (UNKNOWN_PAYMENT_HASH) */
    PROBE_RESULT_LIQUIDITY_FAIL, /* a hop rejected due to insufficient balance */
    PROBE_RESULT_CHANNEL_FAIL,   /* channel disabled or next peer unknown */
    PROBE_RESULT_POLICY_FAIL,    /* policy rejection (fee, CLTV, min amount) */
    PROBE_RESULT_UNKNOWN         /* unrecognised failure code */
} probe_result_t;

/*
 * Fill buf with 32 random bytes to use as a probe payment hash.
 * Uses /dev/urandom. Returns 1 on success, 0 on failure.
 */
int probe_build_payment_hash(unsigned char buf[32]);

/*
 * Classify a BOLT #4 failure code into a probe_result_t.
 */
probe_result_t probe_classify_failure(uint16_t bolt4_failure_code);

/*
 * Convenience: returns 1 if the failure code means the probe reached
 * the destination (i.e. the route had enough liquidity).
 */
int probe_is_success_failure(uint16_t bolt4_failure_code);

/*
 * Convenience: returns 1 if the failure code means a hop had
 * insufficient balance (TEMPORARY_CHANNEL_FAILURE).
 */
int probe_is_liquidity_failure(uint16_t bolt4_failure_code);

#endif /* SUPERSCALAR_PROBE_H */
