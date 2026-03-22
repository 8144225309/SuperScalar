/*
 * test_fwd_history.c — Tests for forwarding history and channel statistics
 *
 * PR #43: Forwarding History (CLN listforwards / LND fwdinghistory)
 */

#include "superscalar/fwd_history.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

#define NOW  1700000000u

static unsigned char zero_hash[32] = {0};

/* FH1: init produces empty table */
int test_fwd_history_init(void)
{
    fwd_history_t h;
    fwd_history_init(&h);
    ASSERT(h.count == 0, "count = 0 after init");
    ASSERT(h.total_settled == 0, "total_settled = 0");
    ASSERT(h.total_failed == 0, "total_failed = 0");
    return 1;
}

/* FH2: add settled entry increments counters */
int test_fwd_history_add_settled(void)
{
    fwd_history_t h;
    fwd_history_init(&h);
    fwd_history_add(&h, 100, 200, 110000, 100000, NOW, zero_hash, FWD_STATUS_SETTLED);
    ASSERT(h.count == 1, "count = 1");
    ASSERT(h.total_settled == 1, "total_settled = 1");
    ASSERT(h.entries[0].fee_msat == 10000, "fee_msat = 10000");
    return 1;
}

/* FH3: add failed entry */
int test_fwd_history_add_failed(void)
{
    fwd_history_t h;
    fwd_history_init(&h);
    fwd_history_add(&h, 100, 200, 50000, 50000, NOW, zero_hash, FWD_STATUS_FAILED);
    ASSERT(h.total_failed == 1, "total_failed = 1");
    ASSERT(h.entries[0].fee_msat == 0, "no fee for failed");
    return 1;
}

/* FH4: fee_total sums correctly */
int test_fwd_history_fee_total(void)
{
    fwd_history_t h;
    fwd_history_init(&h);
    fwd_history_add(&h, 1, 2, 110000, 100000, NOW,       zero_hash, FWD_STATUS_SETTLED); /* fee=10000 */
    fwd_history_add(&h, 1, 2, 220000, 200000, NOW + 100, zero_hash, FWD_STATUS_SETTLED); /* fee=20000 */
    fwd_history_add(&h, 1, 2,  50000,  50000, NOW + 200, zero_hash, FWD_STATUS_FAILED);  /* no fee */

    uint64_t total = fwd_history_fee_total(&h, 0, 0);
    ASSERT(total == 30000, "total fee = 30000");

    /* Time range filter */
    uint64_t half = fwd_history_fee_total(&h, NOW + 50, 0);
    ASSERT(half == 20000, "fee from t+50 = 20000");
    return 1;
}

/* FH5: volume sums correctly */
int test_fwd_history_volume(void)
{
    fwd_history_t h;
    fwd_history_init(&h);
    fwd_history_add(&h, 1, 10, 110000, 100000, NOW,       zero_hash, FWD_STATUS_SETTLED);
    fwd_history_add(&h, 2, 10, 210000, 200000, NOW + 100, zero_hash, FWD_STATUS_SETTLED);
    fwd_history_add(&h, 3, 20, 310000, 300000, NOW + 200, zero_hash, FWD_STATUS_SETTLED);

    /* All scids */
    uint64_t all = fwd_history_volume(&h, 0, 0, 0);
    ASSERT(all == 600000, "total volume = 600000");

    /* Only scid_out=10 */
    uint64_t chan10 = fwd_history_volume(&h, 10, 0, 0);
    ASSERT(chan10 == 300000, "chan10 volume = 300000");
    return 1;
}

/* FH6: count per scid_in */
int test_fwd_history_count(void)
{
    fwd_history_t h;
    fwd_history_init(&h);
    fwd_history_add(&h, 5, 10, 100000, 100000, NOW,       zero_hash, FWD_STATUS_SETTLED);
    fwd_history_add(&h, 5, 10, 100000, 100000, NOW + 100, zero_hash, FWD_STATUS_SETTLED);
    fwd_history_add(&h, 6, 10, 100000, 100000, NOW + 200, zero_hash, FWD_STATUS_SETTLED);
    fwd_history_add(&h, 5, 10, 100000, 100000, NOW + 300, zero_hash, FWD_STATUS_FAILED); /* failed */

    ASSERT(fwd_history_count(&h, 5, 0, 0) == 2, "scid_in=5 settled count = 2");
    ASSERT(fwd_history_count(&h, 6, 0, 0) == 1, "scid_in=6 settled count = 1");
    ASSERT(fwd_history_count(&h, 0, 0, 0) == 3, "all settled = 3");
    return 1;
}

/* FH7: avg_fee */
int test_fwd_history_avg_fee(void)
{
    fwd_history_t h;
    fwd_history_init(&h);
    fwd_history_add(&h, 1, 2, 110000, 100000, NOW,       zero_hash, FWD_STATUS_SETTLED); /* 10000 */
    fwd_history_add(&h, 1, 2, 130000, 100000, NOW + 100, zero_hash, FWD_STATUS_SETTLED); /* 30000 */

    uint64_t avg = fwd_history_avg_fee(&h, 0, 0);
    ASSERT(avg == 20000, "avg fee = 20000");

    /* Empty → 0 */
    fwd_history_t h2;
    fwd_history_init(&h2);
    ASSERT(fwd_history_avg_fee(&h2, 0, 0) == 0, "empty → 0");
    return 1;
}

/* FH8: top_channel identifies highest-income pair */
int test_fwd_history_top_channel(void)
{
    fwd_history_t h;
    fwd_history_init(&h);
    /* Channel pair (100, 200): 3 × 1000 fee = 3000 total */
    fwd_history_add(&h, 100, 200, 101000, 100000, NOW,       zero_hash, FWD_STATUS_SETTLED);
    fwd_history_add(&h, 100, 200, 101000, 100000, NOW + 100, zero_hash, FWD_STATUS_SETTLED);
    fwd_history_add(&h, 100, 200, 101000, 100000, NOW + 200, zero_hash, FWD_STATUS_SETTLED);
    /* Channel pair (300, 400): 1 × 500 fee = 500 total */
    fwd_history_add(&h, 300, 400, 100500, 100000, NOW + 300, zero_hash, FWD_STATUS_SETTLED);

    uint64_t si, so;
    uint64_t top = fwd_history_top_channel(&h, 0, 0, &si, &so);
    ASSERT(top == 3000, "top fee = 3000");
    ASSERT(si == 100 && so == 200, "top pair = (100, 200)");
    return 1;
}

/* FH9: prune removes old entries */
int test_fwd_history_prune(void)
{
    fwd_history_t h;
    fwd_history_init(&h);
    fwd_history_add(&h, 1, 2, 100000, 100000, NOW - 1000, zero_hash, FWD_STATUS_SETTLED);
    fwd_history_add(&h, 1, 2, 100000, 100000, NOW + 100,  zero_hash, FWD_STATUS_SETTLED);
    ASSERT(h.count == 2, "2 entries before prune");

    int pruned = fwd_history_prune(&h, NOW);
    ASSERT(pruned == 1, "1 entry pruned");
    ASSERT(h.count == 1, "1 entry remains");
    ASSERT(h.entries[0].resolved_at == NOW + 100, "recent entry kept");
    return 1;
}

/* FH10: ring buffer wraps correctly */
int test_fwd_history_ring_wrap(void)
{
    fwd_history_t h;
    fwd_history_init(&h);
    /* Add more than FWD_HISTORY_MAX... not practical to test fully,
       but test that adding a lot doesn't crash and count caps at MAX */
    for (int i = 0; i < FWD_HISTORY_MAX + 10; i++) {
        fwd_history_add(&h, (uint64_t)i, (uint64_t)(i + 1),
                         100000, 99000, NOW + i, zero_hash, FWD_STATUS_SETTLED);
    }
    ASSERT(h.count == FWD_HISTORY_MAX, "count caps at FWD_HISTORY_MAX");
    return 1;
}

/* FH11: time range [since=0, until=0] means all entries */
int test_fwd_history_range_all(void)
{
    fwd_history_t h;
    fwd_history_init(&h);
    fwd_history_add(&h, 1, 2, 101000, 100000, 1, zero_hash, FWD_STATUS_SETTLED);
    fwd_history_add(&h, 1, 2, 101000, 100000, UINT32_MAX, zero_hash, FWD_STATUS_SETTLED);
    uint64_t total = fwd_history_fee_total(&h, 0, 0);
    ASSERT(total == 2000, "range [0,0] includes all entries");
    return 1;
}

/* FH12: NULL safety */
int test_fwd_history_null_safety(void)
{
    fwd_history_init(NULL);
    fwd_history_add(NULL, 1, 2, 1000, 1000, NOW, NULL, FWD_STATUS_SETTLED);
    fwd_history_fee_total(NULL, 0, 0);
    fwd_history_volume(NULL, 0, 0, 0);
    fwd_history_count(NULL, 0, 0, 0);
    fwd_history_avg_fee(NULL, 0, 0);
    fwd_history_prune(NULL, 0);
    /* top_channel with NULL */
    fwd_history_top_channel(NULL, 0, 0, NULL, NULL);
    fwd_history_t h; fwd_history_init(&h);
    fwd_history_top_channel(&h, 0, 0, NULL, NULL);  /* empty + NULL outs → ok */
    return 1;
}
