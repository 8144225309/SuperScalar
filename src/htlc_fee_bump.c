/*
 * htlc_fee_bump.c — Deadline-aware fee bumping for HTLC sweep transactions
 */

#include "superscalar/htlc_fee_bump.h"
#include <string.h>

/* -----------------------------------------------------------------------
 * Initialise
 * --------------------------------------------------------------------- */

int htlc_fee_bump_init(htlc_fee_bump_t *fb,
                        uint32_t start_block,
                        uint32_t deadline_block,
                        uint64_t htlc_value_sat,
                        int      budget_pct,
                        uint32_t tx_vsize,
                        uint64_t start_feerate)
{
    if (!fb) return 0;
    if (deadline_block <= start_block) return 0;
    if (tx_vsize == 0) return 0;
    if (budget_pct < 1 || budget_pct > 100) return 0;
    if (start_feerate < HTLC_FEE_BUMP_FLOOR_SAT_PER_KVB) return 0;

    memset(fb, 0, sizeof(*fb));
    fb->start_block    = start_block;
    fb->deadline_block = deadline_block;
    fb->budget_sat     = (htlc_value_sat * (uint64_t)budget_pct) / 100;
    fb->tx_vsize       = tx_vsize;
    fb->start_feerate  = start_feerate;
    fb->last_feerate   = 0; /* not yet broadcast */
    fb->last_bump_block = 0;
    fb->confirmed      = 0;
    fb->confirm_block  = 0;
    return 1;
}

/* -----------------------------------------------------------------------
 * Budget-limited maximum fee rate
 * --------------------------------------------------------------------- */

uint64_t htlc_fee_bump_max_feerate(const htlc_fee_bump_t *fb)
{
    if (!fb || fb->tx_vsize == 0) return HTLC_FEE_BUMP_FLOOR_SAT_PER_KVB;
    /* budget_sat * 1000 / tx_vsize (converting sat/vB to sat/kvB) */
    uint64_t max = (fb->budget_sat * 1000) / fb->tx_vsize;
    if (max < fb->start_feerate) max = fb->start_feerate;
    return max;
}

/* -----------------------------------------------------------------------
 * Scheduled fee rate at a given block
 * --------------------------------------------------------------------- */

uint64_t htlc_fee_bump_calc_feerate(const htlc_fee_bump_t *fb,
                                     uint32_t current_block)
{
    if (!fb) return HTLC_FEE_BUMP_FLOOR_SAT_PER_KVB;

    uint64_t max_feerate = htlc_fee_bump_max_feerate(fb);

    /* At or before start → use start_feerate */
    if (current_block <= fb->start_block)
        return fb->start_feerate;

    /* At or past deadline → use max_feerate */
    if (current_block >= fb->deadline_block)
        return max_feerate;

    /* Linear interpolation:
     *   feerate = start + elapsed * (max - start) / window
     * Use 64-bit arithmetic to avoid overflow at high values. */
    uint64_t window   = fb->deadline_block - fb->start_block;
    uint64_t elapsed  = current_block - fb->start_block;
    uint64_t span     = max_feerate > fb->start_feerate
                         ? max_feerate - fb->start_feerate : 0;

    uint64_t feerate = fb->start_feerate + (elapsed * span) / window;

    if (feerate < fb->start_feerate) feerate = fb->start_feerate;
    if (feerate > max_feerate)       feerate = max_feerate;
    return feerate;
}

/* -----------------------------------------------------------------------
 * Should we broadcast / RBF right now?
 * --------------------------------------------------------------------- */

int htlc_fee_bump_should_bump(const htlc_fee_bump_t *fb,
                               uint32_t current_block)
{
    if (!fb) return 0;
    if (fb->confirmed) return 0;
    if (current_block >= fb->deadline_block) return 0; /* already expired */

    /* Never broadcast → bump immediately */
    if (fb->last_feerate == 0) return 1;

    /* In urgent window → bump every block */
    if (htlc_fee_bump_is_urgent(fb, current_block)) return 1;

    /* Check if scheduled feerate has risen enough to justify RBF */
    uint64_t new_feerate = htlc_fee_bump_calc_feerate(fb, current_block);
    uint64_t threshold   = fb->last_feerate
                           + (fb->last_feerate * HTLC_FEE_BUMP_RBF_PCT) / 100;
    return (new_feerate >= threshold) ? 1 : 0;
}

/* -----------------------------------------------------------------------
 * Record broadcast
 * --------------------------------------------------------------------- */

void htlc_fee_bump_record_broadcast(htlc_fee_bump_t *fb,
                                     uint32_t block,
                                     uint64_t feerate_used)
{
    if (!fb) return;
    fb->last_feerate    = feerate_used;
    fb->last_bump_block = block;
}

/* -----------------------------------------------------------------------
 * Record confirmation
 * --------------------------------------------------------------------- */

void htlc_fee_bump_record_confirm(htlc_fee_bump_t *fb,
                                   uint32_t block)
{
    if (!fb) return;
    fb->confirmed     = 1;
    fb->confirm_block = block;
}

/* -----------------------------------------------------------------------
 * Predicates
 * --------------------------------------------------------------------- */

int htlc_fee_bump_is_confirmed(const htlc_fee_bump_t *fb)
{
    if (!fb) return 0;
    return fb->confirmed;
}

int htlc_fee_bump_is_urgent(const htlc_fee_bump_t *fb,
                              uint32_t current_block)
{
    if (!fb) return 0;
    if (fb->confirmed) return 0;
    if (current_block >= fb->deadline_block) return 0;
    return (fb->deadline_block - current_block) <= HTLC_FEE_BUMP_URGENT_BLOCKS;
}

uint32_t htlc_fee_bump_blocks_remaining(const htlc_fee_bump_t *fb,
                                         uint32_t current_block)
{
    if (!fb) return 0;
    if (current_block >= fb->deadline_block) return 0;
    return fb->deadline_block - current_block;
}

int htlc_fee_bump_is_expired(const htlc_fee_bump_t *fb,
                               uint32_t current_block)
{
    if (!fb) return 0;
    if (fb->confirmed) return 0;
    return (current_block >= fb->deadline_block) ? 1 : 0;
}

/* -----------------------------------------------------------------------
 * Fee computation helper
 * --------------------------------------------------------------------- */

uint64_t htlc_fee_bump_fee_sat(uint64_t feerate_sat_per_kvb, uint32_t tx_vsize)
{
    uint64_t fee = (feerate_sat_per_kvb * tx_vsize) / 1000;
    return (fee < 1) ? 1 : fee;
}
