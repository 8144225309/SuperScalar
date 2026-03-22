/*
 * test_mission_control.c — Tests for payment failure channel scoring
 *
 * PR #41: Mission Control (LDK-style payment failure tracking)
 */

#include "superscalar/mission_control.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

#define NOW  1700000000u  /* fixed base timestamp */

/* MC1: mc_init produces clean table */
int test_mc_init(void)
{
    mc_table_t mc;
    mc_init(&mc);
    ASSERT(mc.count == 0, "count = 0 after init");
    ASSERT(mc_find(&mc, 12345, 0) == NULL, "no entries after init");
    return 1;
}

/* MC2: mc_record_failure stores entry */
int test_mc_record_failure_stores(void)
{
    mc_table_t mc;
    mc_init(&mc);
    mc_record_failure(&mc, 1000, 0, 50000, NOW);
    ASSERT(mc.count == 1, "one entry added");
    const mc_entry_t *e = mc_find(&mc, 1000, 0);
    ASSERT(e != NULL, "entry found");
    ASSERT(e->fail_time == NOW, "fail_time set");
    ASSERT(e->min_fail_msat == 50000, "min_fail_msat set");
    ASSERT(e->fail_count == 1, "fail_count = 1");
    return 1;
}

/* MC3: mc_is_penalized returns 1 for recent failure */
int test_mc_is_penalized_recent(void)
{
    mc_table_t mc;
    mc_init(&mc);
    mc_record_failure(&mc, 2000, 1, 100000, NOW);
    /* Query immediately after — should be penalized */
    ASSERT(mc_is_penalized(&mc, 2000, 1, 100000, NOW), "penalized immediately after failure");
    /* Query with amount >= min_fail_msat still penalized */
    ASSERT(mc_is_penalized(&mc, 2000, 1, 200000, NOW), "penalized for larger amount");
    return 1;
}

/* MC4: mc_is_penalized returns 0 after decay */
int test_mc_is_penalized_decayed(void)
{
    mc_table_t mc;
    mc_init(&mc);
    mc_record_failure(&mc, 3000, 0, 75000, NOW);
    /* Query after full decay period */
    ASSERT(!mc_is_penalized(&mc, 3000, 0, 75000, NOW + MC_DECAY_SECS),
           "not penalized after full decay");
    /* Just before decay: still penalized */
    ASSERT(mc_is_penalized(&mc, 3000, 0, 75000, NOW + MC_DECAY_SECS - 1),
           "still penalized just before decay");
    return 1;
}

/* MC5: mc_record_success clears penalty */
int test_mc_success_clears_penalty(void)
{
    mc_table_t mc;
    mc_init(&mc);
    mc_record_failure(&mc, 4000, 0, 50000, NOW);
    ASSERT(mc_is_penalized(&mc, 4000, 0, 50000, NOW), "penalized before success");

    mc_record_success(&mc, 4000, 0, 50000, NOW + 100);
    ASSERT(!mc_is_penalized(&mc, 4000, 0, 50000, NOW + 100), "not penalized after success");
    return 1;
}

/* MC6: amount-based penalty — small amount not penalized */
int test_mc_amount_threshold(void)
{
    mc_table_t mc;
    mc_init(&mc);
    mc_record_failure(&mc, 5000, 0, 100000, NOW);  /* failed at 100k msat */

    /* Amount below failure threshold: not penalized */
    ASSERT(!mc_is_penalized(&mc, 5000, 0, 50000, NOW),
           "smaller amount not penalized");
    /* Amount at threshold: penalized */
    ASSERT(mc_is_penalized(&mc, 5000, 0, 100000, NOW),
           "exact failure amount penalized");
    return 1;
}

/* MC7: different direction not penalized */
int test_mc_direction_independent(void)
{
    mc_table_t mc;
    mc_init(&mc);
    mc_record_failure(&mc, 6000, 0, 50000, NOW);  /* direction 0 fails */

    ASSERT(mc_is_penalized(&mc, 6000, 0, 50000, NOW), "dir 0 penalized");
    ASSERT(!mc_is_penalized(&mc, 6000, 1, 50000, NOW), "dir 1 not penalized");
    return 1;
}

/* MC8: mc_get_penalty_msat decreases over time */
int test_mc_penalty_decays(void)
{
    mc_table_t mc;
    mc_init(&mc);
    mc_record_failure(&mc, 7000, 0, 50000, NOW);

    uint64_t p0 = mc_get_penalty_msat(&mc, 7000, 0, 50000, NOW);
    uint64_t p1 = mc_get_penalty_msat(&mc, 7000, 0, 50000, NOW + MC_DECAY_SECS / 2);
    uint64_t p2 = mc_get_penalty_msat(&mc, 7000, 0, 50000, NOW + MC_DECAY_SECS);

    ASSERT(p0 > 0, "penalty > 0 at t=0");
    ASSERT(p1 < p0, "penalty decreases at half decay");
    ASSERT(p2 == 0, "penalty = 0 at full decay");
    return 1;
}

/* MC9: mc_prune_stale removes expired entries */
int test_mc_prune_stale(void)
{
    mc_table_t mc;
    mc_init(&mc);
    mc_record_failure(&mc, 8000, 0, 50000, NOW);
    mc_record_failure(&mc, 9000, 1, 80000, NOW);
    ASSERT(mc.count == 2, "2 entries before prune");

    /* Prune after full decay — both should be removed */
    int pruned = mc_prune_stale(&mc, NOW + MC_DECAY_SECS + 1);
    ASSERT(pruned == 2, "2 entries pruned");
    ASSERT(mc.count == 0, "table empty after prune");
    return 1;
}

/* MC10: prune keeps entry with success after failure */
int test_mc_prune_keeps_success(void)
{
    mc_table_t mc;
    mc_init(&mc);
    mc_record_failure(&mc, 10000, 0, 50000, NOW);
    mc_record_success(&mc, 10000, 0, 50000, NOW + 100);

    /* After decay, entry still tracked because success was recorded */
    int pruned = mc_prune_stale(&mc, NOW + MC_DECAY_SECS + 1);
    /* success_time > fail_time → not pruned */
    ASSERT(pruned == 0, "not pruned when success after failure");
    return 1;
}

/* MC11: multiple failures increase fail_count */
int test_mc_multiple_failures(void)
{
    mc_table_t mc;
    mc_init(&mc);
    mc_record_failure(&mc, 11000, 0, 100000, NOW);
    mc_record_failure(&mc, 11000, 0, 100000, NOW + 10);
    mc_record_failure(&mc, 11000, 0, 50000,  NOW + 20);

    const mc_entry_t *e = mc_find(&mc, 11000, 0);
    ASSERT(e != NULL, "entry found");
    ASSERT(e->fail_count == 3, "fail_count = 3");
    /* min_fail_msat should be 50000 (smallest failure) */
    ASSERT(e->min_fail_msat == 50000, "min_fail_msat updated to smallest");
    return 1;
}

/* MC12: penalty scales with fail_count */
int test_mc_penalty_scales_with_count(void)
{
    mc_table_t mc;
    mc_init(&mc);
    mc_record_failure(&mc, 12000, 0, 100000, NOW);
    uint64_t p1 = mc_get_penalty_msat(&mc, 12000, 0, 100000, NOW);

    mc_record_failure(&mc, 12000, 0, 100000, NOW + 1);
    uint64_t p2 = mc_get_penalty_msat(&mc, 12000, 0, 100000, NOW + 1);

    ASSERT(p2 > p1, "penalty increases with fail_count");
    return 1;
}

/* MC13: unknown channel returns 0 penalty */
int test_mc_unknown_channel(void)
{
    mc_table_t mc;
    mc_init(&mc);

    ASSERT(!mc_is_penalized(&mc, 99999, 0, 50000, NOW), "unknown = not penalized");
    ASSERT(mc_get_penalty_msat(&mc, 99999, 0, 50000, NOW) == 0,
           "unknown = 0 penalty");
    return 1;
}

/* MC14: NULL safety */
int test_mc_null_safety(void)
{
    /* These should not crash */
    mc_init(NULL);
    mc_record_failure(NULL, 1, 0, 100, NOW);
    mc_record_success(NULL, 1, 0, 100, NOW);
    mc_is_penalized(NULL, 1, 0, 100, NOW);
    mc_get_penalty_msat(NULL, 1, 0, 100, NOW);
    mc_prune_stale(NULL, NOW);
    mc_find(NULL, 1, 0);
    return 1;
}
