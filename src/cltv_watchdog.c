/*
 * cltv_watchdog.c — HTLC expiry watchdog for inbound BOLT #2 HTLCs
 *
 * See cltv_watchdog.h for the full API description.
 */

#include "superscalar/cltv_watchdog.h"
#include "superscalar/channel.h"
#include <stdint.h>

void cltv_watchdog_init(cltv_watchdog_t *wd, channel_t *ch,
                         uint32_t expiry_delta)
{
    wd->ch            = ch;
    wd->expiry_delta  = expiry_delta ? expiry_delta : CLTV_EXPIRY_DELTA;
    wd->triggered     = 0;
}

int cltv_watchdog_check(cltv_watchdog_t *wd, uint32_t current_height)
{
    int count = 0;
    channel_t *ch = wd->ch;
    uint32_t threshold = current_height + wd->expiry_delta;

    for (size_t i = 0; i < ch->n_htlcs; i++) {
        htlc_t *h = &ch->htlcs[i];
        if (h->state    != HTLC_STATE_ACTIVE)  continue;
        if (h->direction != HTLC_RECEIVED)      continue;
        if (h->cltv_expiry == 0)                continue;
        if (h->cltv_expiry <= threshold)
            count++;
    }

    if (count > 0)
        wd->triggered = 1;
    return count;
}

int cltv_watchdog_expire(cltv_watchdog_t *wd, uint32_t current_height)
{
    return channel_check_htlc_timeouts(wd->ch, current_height);
}

uint32_t cltv_watchdog_earliest_expiry(const channel_t *ch)
{
    uint32_t earliest = UINT32_MAX;

    for (size_t i = 0; i < ch->n_htlcs; i++) {
        const htlc_t *h = &ch->htlcs[i];
        if (h->state    != HTLC_STATE_ACTIVE) continue;
        if (h->direction != HTLC_RECEIVED)    continue;
        if (h->cltv_expiry == 0)              continue;
        if (h->cltv_expiry < earliest)
            earliest = h->cltv_expiry;
    }

    return earliest;
}
