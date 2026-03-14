#include "superscalar/fee_estimator.h"
#include <string.h>
#include <stdlib.h>

/* -----------------------------------------------------------------------
 * Sorting helper for median / percentile calculation
 * --------------------------------------------------------------------- */
static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static uint64_t blocks_get_rate(fee_estimator_t *self, fee_target_t target)
{
    fee_estimator_blocks_t *fe = (fee_estimator_blocks_t *)self;
    uint64_t floor = fe->feefilter_floor > 0 ? fe->feefilter_floor : 1000;

    if (fe->n_samples == 0) {
        /* No block data yet — return floor for all targets */
        return floor;
    }

    /* Copy samples into a sorted temporary array */
    int n = fe->n_samples < FEE_BLOCKS_SAMPLES ? fe->n_samples : FEE_BLOCKS_SAMPLES;
    uint64_t sorted[FEE_BLOCKS_SAMPLES];
    for (int i = 0; i < n; i++) {
        /* Read from ring buffer: most recent = cursor-1, oldest = cursor-n (mod) */
        int idx = ((fe->cursor - n + i) + FEE_BLOCKS_SAMPLES) % FEE_BLOCKS_SAMPLES;
        sorted[i] = fe->samples[idx];
    }
    qsort(sorted, (size_t)n, sizeof(uint64_t), cmp_u64);

    uint64_t rate;
    switch (target) {
        case FEE_TARGET_URGENT:
            /* Max of last 3 samples × 1.5, floored at feefilter */
            {
                int last = n < 3 ? n : 3;
                uint64_t mx = 0;
                for (int i = n - last; i < n; i++)
                    if (sorted[i] > mx) mx = sorted[i];
                rate = mx + mx / 2;  /* × 1.5 */
            }
            break;
        case FEE_TARGET_NORMAL:
            /* Median */
            rate = sorted[n / 2];
            break;
        case FEE_TARGET_ECONOMY:
            /* 25th percentile */
            rate = sorted[n / 4];
            break;
        case FEE_TARGET_MINIMUM:
        default:
            /* feefilter floor (or minimum 1000 if unknown) */
            return floor;
    }

    return rate > floor ? rate : floor;
}

void fee_estimator_blocks_init(fee_estimator_blocks_t *fe)
{
    if (!fe) return;
    memset(fe, 0, sizeof(*fe));
    fe->base.get_rate = blocks_get_rate;
    fe->base.update   = NULL;
    fe->base.free     = NULL;
}

void fee_estimator_blocks_add_sample(fee_estimator_blocks_t *fe,
                                      uint64_t sat_per_kvb)
{
    if (!fe || sat_per_kvb == 0) return;
    fe->samples[fe->cursor % FEE_BLOCKS_SAMPLES] = sat_per_kvb;
    fe->cursor = (fe->cursor + 1) % FEE_BLOCKS_SAMPLES;
    if (fe->n_samples < FEE_BLOCKS_SAMPLES)
        fe->n_samples++;
}

void fee_estimator_blocks_set_floor(fee_estimator_blocks_t *fe,
                                     uint64_t floor_sat_per_kvb)
{
    if (!fe) return;
    fe->feefilter_floor = floor_sat_per_kvb;
}
