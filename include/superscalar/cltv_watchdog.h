/*
 * cltv_watchdog.h — HTLC expiry watchdog for inbound BOLT #2 HTLCs
 *
 * BOLT #2 §3: a forwarding node MUST force-close the upstream channel if an
 * inbound HTLC cannot be resolved before its cltv_expiry.  The safety margin
 * ("expiry delta") is the number of blocks before expiry at which we must act.
 *
 * This module provides:
 *   cltv_watchdog_check   — count inbound HTLCs within expiry_delta of expiry
 *   cltv_watchdog_expire  — fail all HTLCs that have already expired (wraps
 *                           channel_check_htlc_timeouts)
 *   cltv_watchdog_earliest_expiry — lowest cltv_expiry across active inbound HTLCs
 *
 * Typical usage (called from the block-processing loop):
 *
 *   cltv_watchdog_t wd;
 *   cltv_watchdog_init(&wd, ch, 0);           // 0 = use default delta
 *   int at_risk = cltv_watchdog_check(&wd, current_height);
 *   if (at_risk > 0) {
 *       // force-close upstream channel
 *   }
 *   cltv_watchdog_expire(&wd, current_height); // fail truly-expired HTLCs
 */

#ifndef SUPERSCALAR_CLTV_WATCHDOG_H
#define SUPERSCALAR_CLTV_WATCHDOG_H

#include <stdint.h>
#include "channel.h"

/* Default safety margin: 18 blocks (BOLT #2 minimum CLTV expiry delta). */
#define CLTV_EXPIRY_DELTA  18

typedef struct {
    channel_t *ch;
    uint32_t   expiry_delta;  /* blocks before expiry at which we must act */
    int        triggered;     /* 1 if check() has found at-risk HTLCs */
} cltv_watchdog_t;

/*
 * Initialize the watchdog.
 * expiry_delta == 0 → use CLTV_EXPIRY_DELTA default.
 */
void cltv_watchdog_init(cltv_watchdog_t *wd, channel_t *ch,
                         uint32_t expiry_delta);

/*
 * Count inbound HTLCs whose cltv_expiry <= current_height + expiry_delta.
 * Sets wd->triggered = 1 if count > 0.
 * Returns the count.
 */
int cltv_watchdog_check(cltv_watchdog_t *wd, uint32_t current_height);

/*
 * Fail all active HTLCs whose cltv_expiry <= current_height
 * (wraps channel_check_htlc_timeouts).
 * Returns count of HTLCs failed.
 */
int cltv_watchdog_expire(cltv_watchdog_t *wd, uint32_t current_height);

/*
 * Return the lowest cltv_expiry across all active inbound (HTLC_RECEIVED)
 * HTLCs.  Returns UINT32_MAX if there are no active inbound HTLCs.
 */
uint32_t cltv_watchdog_earliest_expiry(const channel_t *ch);

#endif /* SUPERSCALAR_CLTV_WATCHDOG_H */
