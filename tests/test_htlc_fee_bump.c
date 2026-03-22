/*
 * test_htlc_fee_bump.c — Tests for deadline-aware HTLC fee bumping
 *
 * PR #49: Deadline-Aware HTLC Fee Bumper (LND LinearFeeFunction compatible)
 */

#include "superscalar/htlc_fee_bump.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* Common test parameters */
#define START_BLOCK    800000u
#define DEADLINE_BLOCK 800144u   /* 144 blocks = ~1 day */
#define HTLC_VALUE     100000u   /* 100,000 sat */
#define BUDGET_PCT     50        /* 50% = 50,000 sat budget */
#define TX_VSIZE       180u      /* typical HTLC-timeout tx */
#define START_FEERATE  1000u     /* 1 sat/vB = 1000 sat/kvB */

/* -----------------------------------------------------------------------
 * HFB1: init sets fields correctly
 * --------------------------------------------------------------------- */
int test_hfb_init_fields(void)
{
    htlc_fee_bump_t fb;
    ASSERT(htlc_fee_bump_init(&fb, START_BLOCK, DEADLINE_BLOCK,
                               HTLC_VALUE, BUDGET_PCT, TX_VSIZE, START_FEERATE),
           "HFB1: init ok");

    ASSERT(fb.start_block    == START_BLOCK,    "start_block set");
    ASSERT(fb.deadline_block == DEADLINE_BLOCK, "deadline_block set");
    ASSERT(fb.budget_sat     == 50000u,         "budget = 50% of 100000");
    ASSERT(fb.tx_vsize       == TX_VSIZE,       "tx_vsize set");
    ASSERT(fb.start_feerate  == START_FEERATE,  "start_feerate set");
    ASSERT(fb.last_feerate   == 0,              "last_feerate = 0 (unbroadcast)");
    ASSERT(fb.confirmed      == 0,              "not confirmed");
    return 1;
}

/* -----------------------------------------------------------------------
 * HFB2: calc_feerate at start_block → start_feerate
 * --------------------------------------------------------------------- */
int test_hfb_feerate_at_start(void)
{
    htlc_fee_bump_t fb;
    htlc_fee_bump_init(&fb, START_BLOCK, DEADLINE_BLOCK,
                        HTLC_VALUE, BUDGET_PCT, TX_VSIZE, START_FEERATE);

    uint64_t rate = htlc_fee_bump_calc_feerate(&fb, START_BLOCK);
    ASSERT(rate == START_FEERATE, "HFB2: at start_block → start_feerate");
    return 1;
}

/* -----------------------------------------------------------------------
 * HFB3: calc_feerate at deadline_block → budget-limited max
 * --------------------------------------------------------------------- */
int test_hfb_feerate_at_deadline(void)
{
    htlc_fee_bump_t fb;
    htlc_fee_bump_init(&fb, START_BLOCK, DEADLINE_BLOCK,
                        HTLC_VALUE, BUDGET_PCT, TX_VSIZE, START_FEERATE);

    /* max_feerate = budget_sat * 1000 / tx_vsize = 50000 * 1000 / 180 = 277777 sat/kvB */
    uint64_t expected_max = (50000ULL * 1000) / 180;  /* = 277777 */
    uint64_t rate = htlc_fee_bump_calc_feerate(&fb, DEADLINE_BLOCK);
    ASSERT(rate == expected_max, "HFB3: at deadline → max feerate");
    return 1;
}

/* -----------------------------------------------------------------------
 * HFB4: calc_feerate at midpoint → linear interpolation
 * --------------------------------------------------------------------- */
int test_hfb_feerate_midpoint(void)
{
    htlc_fee_bump_t fb;
    htlc_fee_bump_init(&fb, START_BLOCK, DEADLINE_BLOCK,
                        HTLC_VALUE, BUDGET_PCT, TX_VSIZE, START_FEERATE);

    uint32_t midpoint = START_BLOCK + (DEADLINE_BLOCK - START_BLOCK) / 2;  /* +72 */
    uint64_t max_rate = htlc_fee_bump_max_feerate(&fb);
    uint64_t rate     = htlc_fee_bump_calc_feerate(&fb, midpoint);

    /* Should be roughly between start and max */
    ASSERT(rate >= START_FEERATE, "HFB4: midpoint >= start_feerate");
    ASSERT(rate <= max_rate,      "HFB4: midpoint <= max_feerate");
    /* Specifically: start + 72/144 * (max - start) = ~midpoint */
    uint64_t expected = START_FEERATE + 72ULL * (max_rate - START_FEERATE) / 144;
    ASSERT(rate == expected, "HFB4: exact linear interpolation");
    return 1;
}

/* -----------------------------------------------------------------------
 * HFB5: calc_feerate past deadline → clamped to max
 * --------------------------------------------------------------------- */
int test_hfb_feerate_past_deadline(void)
{
    htlc_fee_bump_t fb;
    htlc_fee_bump_init(&fb, START_BLOCK, DEADLINE_BLOCK,
                        HTLC_VALUE, BUDGET_PCT, TX_VSIZE, START_FEERATE);

    uint64_t max_rate = htlc_fee_bump_max_feerate(&fb);
    uint64_t rate1    = htlc_fee_bump_calc_feerate(&fb, DEADLINE_BLOCK + 10);
    uint64_t rate2    = htlc_fee_bump_calc_feerate(&fb, DEADLINE_BLOCK + 1000);

    ASSERT(rate1 == max_rate, "HFB5: +10 clamped to max");
    ASSERT(rate2 == max_rate, "HFB5: +1000 clamped to max");
    return 1;
}

/* -----------------------------------------------------------------------
 * HFB6: should_bump before first broadcast → 1
 * --------------------------------------------------------------------- */
int test_hfb_should_bump_initial(void)
{
    htlc_fee_bump_t fb;
    htlc_fee_bump_init(&fb, START_BLOCK, DEADLINE_BLOCK,
                        HTLC_VALUE, BUDGET_PCT, TX_VSIZE, START_FEERATE);

    ASSERT(htlc_fee_bump_should_bump(&fb, START_BLOCK) == 1,
           "HFB6: never broadcast → should_bump=1");
    return 1;
}

/* -----------------------------------------------------------------------
 * HFB7: should_bump after recent broadcast, small feerate increase → 0
 * --------------------------------------------------------------------- */
int test_hfb_should_bump_recent(void)
{
    htlc_fee_bump_t fb;
    htlc_fee_bump_init(&fb, START_BLOCK, DEADLINE_BLOCK,
                        HTLC_VALUE, BUDGET_PCT, TX_VSIZE, START_FEERATE);

    /* Record broadcast at START_BLOCK with start_feerate */
    htlc_fee_bump_record_broadcast(&fb, START_BLOCK, START_FEERATE);

    /* At START_BLOCK+1 the feerate barely changes — below 25% threshold */
    /* calc_feerate at +1: start + 1/144 * (max-start) ≈ start + small delta */
    /* 25% of 1000 = 250 → threshold = 1250; new rate at block+1 ≈ 1000 + ~1900 = ~2900 */
    /* Actually at block+1: 1000 + 1/144 * (277777-1000) = 1000 + 1921 = 2921 > 1250 */
    /* So should bump. Let's test mid-window where increase is small */

    /* After broadcasting at mid-window feerate, one block later is less than 25% */
    uint32_t mid = START_BLOCK + 72;
    uint64_t mid_rate = htlc_fee_bump_calc_feerate(&fb, mid);
    htlc_fee_bump_record_broadcast(&fb, mid, mid_rate);

    /* One block after mid: barely moved, should be < 25% increase */
    /* Rate at mid+1 vs mid: delta = (max-start)/144 per block */
    /* For this to be < 25%, we need small window. Let's check: */
    uint64_t next_rate = htlc_fee_bump_calc_feerate(&fb, mid + 1);
    uint64_t threshold = mid_rate + (mid_rate * HTLC_FEE_BUMP_RBF_PCT) / 100;
    int expected_bump = (next_rate >= threshold) ? 1 : 0;

    ASSERT(htlc_fee_bump_should_bump(&fb, mid + 1) == expected_bump,
           "HFB7: should_bump matches threshold calculation");
    return 1;
}

/* -----------------------------------------------------------------------
 * HFB8: should_bump in urgent window → always 1
 * --------------------------------------------------------------------- */
int test_hfb_should_bump_urgent(void)
{
    htlc_fee_bump_t fb;
    htlc_fee_bump_init(&fb, START_BLOCK, DEADLINE_BLOCK,
                        HTLC_VALUE, BUDGET_PCT, TX_VSIZE, START_FEERATE);

    /* Broadcast with max feerate (no further fee increase possible) */
    uint64_t max_rate = htlc_fee_bump_max_feerate(&fb);
    htlc_fee_bump_record_broadcast(&fb, DEADLINE_BLOCK - 10, max_rate);

    /* Enter urgent window (within 6 blocks of deadline) */
    uint32_t urgent_block = DEADLINE_BLOCK - HTLC_FEE_BUMP_URGENT_BLOCKS;
    ASSERT(htlc_fee_bump_should_bump(&fb, urgent_block) == 1,
           "HFB8: urgent window → should_bump=1 even at max feerate");
    return 1;
}

/* -----------------------------------------------------------------------
 * HFB9: is_urgent within 6 blocks → 1; outside → 0
 * --------------------------------------------------------------------- */
int test_hfb_is_urgent(void)
{
    htlc_fee_bump_t fb;
    htlc_fee_bump_init(&fb, START_BLOCK, DEADLINE_BLOCK,
                        HTLC_VALUE, BUDGET_PCT, TX_VSIZE, START_FEERATE);

    ASSERT(!htlc_fee_bump_is_urgent(&fb, START_BLOCK),          "HFB9: far away → not urgent");
    ASSERT(!htlc_fee_bump_is_urgent(&fb, DEADLINE_BLOCK - 7),   "HFB9: 7 blocks away → not urgent");
    ASSERT(htlc_fee_bump_is_urgent(&fb, DEADLINE_BLOCK - 6),    "HFB9: 6 blocks away → urgent");
    ASSERT(htlc_fee_bump_is_urgent(&fb, DEADLINE_BLOCK - 1),    "HFB9: 1 block away → urgent");
    ASSERT(!htlc_fee_bump_is_urgent(&fb, DEADLINE_BLOCK),       "HFB9: at deadline → not urgent (expired)");
    return 1;
}

/* -----------------------------------------------------------------------
 * HFB10: blocks_remaining at various heights
 * --------------------------------------------------------------------- */
int test_hfb_blocks_remaining(void)
{
    htlc_fee_bump_t fb;
    htlc_fee_bump_init(&fb, START_BLOCK, DEADLINE_BLOCK,
                        HTLC_VALUE, BUDGET_PCT, TX_VSIZE, START_FEERATE);

    ASSERT(htlc_fee_bump_blocks_remaining(&fb, START_BLOCK)    == 144, "HFB10: at start → 144");
    ASSERT(htlc_fee_bump_blocks_remaining(&fb, START_BLOCK+72) == 72,  "HFB10: midpoint → 72");
    ASSERT(htlc_fee_bump_blocks_remaining(&fb, DEADLINE_BLOCK-1) == 1, "HFB10: -1 → 1");
    ASSERT(htlc_fee_bump_blocks_remaining(&fb, DEADLINE_BLOCK)  == 0,  "HFB10: at deadline → 0");
    ASSERT(htlc_fee_bump_blocks_remaining(&fb, DEADLINE_BLOCK+5) == 0, "HFB10: past deadline → 0");
    return 1;
}

/* -----------------------------------------------------------------------
 * HFB11: record_confirm → is_confirmed=1; should_bump=0; is_urgent=0
 * --------------------------------------------------------------------- */
int test_hfb_confirm(void)
{
    htlc_fee_bump_t fb;
    htlc_fee_bump_init(&fb, START_BLOCK, DEADLINE_BLOCK,
                        HTLC_VALUE, BUDGET_PCT, TX_VSIZE, START_FEERATE);

    ASSERT(!htlc_fee_bump_is_confirmed(&fb),                  "HFB11: not confirmed initially");
    htlc_fee_bump_record_confirm(&fb, START_BLOCK + 3);
    ASSERT(htlc_fee_bump_is_confirmed(&fb),                   "HFB11: is_confirmed=1");
    ASSERT(fb.confirm_block == START_BLOCK + 3,               "HFB11: confirm_block set");
    ASSERT(!htlc_fee_bump_should_bump(&fb, START_BLOCK + 4),  "HFB11: confirmed → no bump");
    ASSERT(!htlc_fee_bump_is_urgent(&fb, DEADLINE_BLOCK - 1), "HFB11: confirmed → not urgent");
    return 1;
}

/* -----------------------------------------------------------------------
 * HFB12: budget_pct limits max_feerate; smaller budget → lower cap
 * --------------------------------------------------------------------- */
int test_hfb_budget_limits_max(void)
{
    htlc_fee_bump_t fb1, fb2;
    /* 10% budget = 10,000 sat / 180 vB * 1000 = 55,555 sat/kvB */
    htlc_fee_bump_init(&fb1, START_BLOCK, DEADLINE_BLOCK,
                        HTLC_VALUE, 10, TX_VSIZE, START_FEERATE);
    /* 90% budget = 90,000 sat / 180 vB * 1000 = 500,000 sat/kvB */
    htlc_fee_bump_init(&fb2, START_BLOCK, DEADLINE_BLOCK,
                        HTLC_VALUE, 90, TX_VSIZE, START_FEERATE);

    uint64_t max1 = htlc_fee_bump_max_feerate(&fb1);
    uint64_t max2 = htlc_fee_bump_max_feerate(&fb2);

    ASSERT(max1 < max2, "HFB12: smaller budget → lower max feerate");

    /* Verify calc: 10,000*1000/180 = 55555 */
    ASSERT(max1 == 10000ULL * 1000 / 180, "HFB12: 10% budget exact");
    /* Verify calc: 90,000*1000/180 = 500000 */
    ASSERT(max2 == 90000ULL * 1000 / 180, "HFB12: 90% budget exact");
    return 1;
}

/* -----------------------------------------------------------------------
 * HFB13: NULL safety
 * --------------------------------------------------------------------- */
int test_hfb_null_safety(void)
{
    ASSERT(!htlc_fee_bump_init(NULL, START_BLOCK, DEADLINE_BLOCK,
                                HTLC_VALUE, BUDGET_PCT, TX_VSIZE, START_FEERATE),
           "HFB13: NULL fb → 0");
    /* deadline <= start → 0 */
    htlc_fee_bump_t fb;
    ASSERT(!htlc_fee_bump_init(&fb, START_BLOCK, START_BLOCK,
                                HTLC_VALUE, BUDGET_PCT, TX_VSIZE, START_FEERATE),
           "HFB13: deadline == start → 0");
    ASSERT(!htlc_fee_bump_init(&fb, START_BLOCK, START_BLOCK - 1,
                                HTLC_VALUE, BUDGET_PCT, TX_VSIZE, START_FEERATE),
           "HFB13: deadline < start → 0");
    /* invalid budget_pct → 0 */
    ASSERT(!htlc_fee_bump_init(&fb, START_BLOCK, DEADLINE_BLOCK,
                                HTLC_VALUE, 0, TX_VSIZE, START_FEERATE),
           "HFB13: budget_pct=0 → 0");
    ASSERT(!htlc_fee_bump_init(&fb, START_BLOCK, DEADLINE_BLOCK,
                                HTLC_VALUE, 101, TX_VSIZE, START_FEERATE),
           "HFB13: budget_pct=101 → 0");
    /* tx_vsize=0 → 0 */
    ASSERT(!htlc_fee_bump_init(&fb, START_BLOCK, DEADLINE_BLOCK,
                                HTLC_VALUE, BUDGET_PCT, 0, START_FEERATE),
           "HFB13: tx_vsize=0 → 0");
    /* feerate below floor → 0 */
    ASSERT(!htlc_fee_bump_init(&fb, START_BLOCK, DEADLINE_BLOCK,
                                HTLC_VALUE, BUDGET_PCT, TX_VSIZE, 100),
           "HFB13: feerate below floor → 0");

    /* NULL calls → no crash */
    ASSERT(htlc_fee_bump_calc_feerate(NULL, 0) == HTLC_FEE_BUMP_FLOOR_SAT_PER_KVB,
           "HFB13: calc_feerate NULL → floor");
    ASSERT(htlc_fee_bump_should_bump(NULL, 0)    == 0, "HFB13: should_bump NULL → 0");
    ASSERT(htlc_fee_bump_is_confirmed(NULL)      == 0, "HFB13: is_confirmed NULL → 0");
    ASSERT(htlc_fee_bump_is_urgent(NULL, 0)      == 0, "HFB13: is_urgent NULL → 0");
    ASSERT(htlc_fee_bump_is_expired(NULL, 0)     == 0, "HFB13: is_expired NULL → 0");
    ASSERT(htlc_fee_bump_blocks_remaining(NULL, 0) == 0, "HFB13: blocks_remaining NULL → 0");
    ASSERT(htlc_fee_bump_max_feerate(NULL) == HTLC_FEE_BUMP_FLOOR_SAT_PER_KVB,
           "HFB13: max_feerate NULL → floor");
    htlc_fee_bump_record_broadcast(NULL, 0, 0); /* no crash */
    htlc_fee_bump_record_confirm(NULL, 0);       /* no crash */
    return 1;
}
