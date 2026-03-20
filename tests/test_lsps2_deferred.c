/*
 * test_lsps2_deferred.c — LSPS2 deferred funding broadcast (PR #19 Commit 5)
 */

#include "superscalar/lsps.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* Helper: fill a pending table with one entry */
static void make_pending(lsps2_pending_table_t *tbl, uint64_t scid,
                          uint64_t amount_msat, uint64_t fee_msat) {
    memset(tbl, 0, sizeof(*tbl));
    lsps2_pending_t *e = &tbl->entries[0];
    e->active      = 1;
    e->scid        = scid;
    e->amount_msat = amount_msat;
    e->fee_msat    = fee_msat;
    e->cost_msat   = fee_msat;  /* cost = fee for the LSP */
    e->collected_msat = 0;
    e->created_at  = (uint32_t)time(NULL);
    tbl->count     = 1;
}

/* -----------------------------------------------------------------------
 * buy creates pending entry — no channel yet (nothing broadcast)
 * ----------------------------------------------------------------------- */

int test_lsps2_deferred_no_immediate_channel(void) {
    lsps2_pending_table_t tbl;
    make_pending(&tbl, 0xDEADBEEF00000001ULL, 1000000, 5000);

    /* First HTLC arrives but doesn't cover cost (3000 < 5000) */
    int ret = lsps2_handle_intercept_htlc(&tbl, 0xDEADBEEF00000001ULL,
                                           3000, NULL, NULL);
    ASSERT(ret == 0, "HTLC below cost: no broadcast yet");
    ASSERT(tbl.entries[0].active == 1, "pending entry still active");
    ASSERT(tbl.entries[0].collected_msat == 3000, "collected 3000 msat");

    return 1;
}

/* -----------------------------------------------------------------------
 * HTLC coverage triggers channel creation
 * ----------------------------------------------------------------------- */

int test_lsps2_deferred_coverage_triggers_channel(void) {
    lsps2_pending_table_t tbl;
    uint64_t scid = 0xAB01020304050607ULL;
    make_pending(&tbl, scid, 500000, 10000);

    /* First HTLC: partial (6000 of 10000) */
    int r1 = lsps2_handle_intercept_htlc(&tbl, scid, 6000, NULL, NULL);
    ASSERT(r1 == 0, "partial coverage: not yet triggered");

    /* Second HTLC: total collected = 6000 + 5000 = 11000 >= 10000 */
    int r2 = lsps2_handle_intercept_htlc(&tbl, scid, 5000, NULL, NULL);
    ASSERT(r2 == 1, "full coverage: broadcast triggered");

    /* Entry should be de-activated */
    ASSERT(tbl.entries[0].active == 0, "pending entry deactivated after trigger");
    ASSERT(tbl.count == 0, "table count decremented");

    return 1;
}

/* -----------------------------------------------------------------------
 * Unknown SCID returns 0 (not found)
 * ----------------------------------------------------------------------- */

int test_lsps2_unknown_scid(void) {
    lsps2_pending_table_t tbl;
    make_pending(&tbl, 0x1111111111111111ULL, 500000, 10000);

    /* Wrong SCID */
    int ret = lsps2_handle_intercept_htlc(&tbl, 0x2222222222222222ULL,
                                           50000, NULL, NULL);
    ASSERT(ret == 0, "unknown SCID returns 0");

    /* Original entry unchanged */
    ASSERT(tbl.entries[0].collected_msat == 0, "unrelated entry not modified");

    return 1;
}

/* -----------------------------------------------------------------------
 * L2D4: lsps2_pending_expire evicts stale entries (created_at old)
 * ----------------------------------------------------------------------- */
int test_lsps2_expire_evicts_stale(void) {
    lsps2_pending_table_t tbl;
    make_pending(&tbl, 0xAAAAAAAAAAAAAAAAULL, 500000, 10000);

    /* Backdate created_at so it's past LSPS2_HTLC_WAIT_SECS (5 s) */
    tbl.entries[0].created_at = (uint32_t)time(NULL) - 10;

    lsps2_pending_expire(&tbl);

    ASSERT(tbl.entries[0].active == 0, "L2D4: stale entry evicted");
    ASSERT(tbl.count == 0, "L2D4: count decremented to 0");

    return 1;
}

/* -----------------------------------------------------------------------
 * L2D5: lsps2_pending_expire does NOT evict fresh entries
 * ----------------------------------------------------------------------- */
int test_lsps2_expire_keeps_fresh(void) {
    lsps2_pending_table_t tbl;
    make_pending(&tbl, 0xBBBBBBBBBBBBBBBBULL, 500000, 10000);

    /* created_at = now → not expired yet */
    tbl.entries[0].created_at = (uint32_t)time(NULL);

    lsps2_pending_expire(&tbl);

    ASSERT(tbl.entries[0].active == 1, "L2D5: fresh entry not evicted");
    ASSERT(tbl.count == 1, "L2D5: count still 1");

    return 1;
}

/* -----------------------------------------------------------------------
 * L2D6: exact cost coverage in single HTLC triggers broadcast
 * ----------------------------------------------------------------------- */
int test_lsps2_exact_cost_triggers(void) {
    lsps2_pending_table_t tbl;
    uint64_t scid = 0xCCCCCCCCCCCCCCCCULL;
    make_pending(&tbl, scid, 500000, 8000);

    /* Send exactly cost_msat = 8000 */
    int ret = lsps2_handle_intercept_htlc(&tbl, scid, 8000, NULL, NULL);
    ASSERT(ret == 1, "L2D6: exact cost triggers broadcast");
    ASSERT(tbl.entries[0].active == 0, "L2D6: entry deactivated");

    return 1;
}

/* -----------------------------------------------------------------------
 * L2D7: multi-HTLC accumulation: 3 HTLCs sum to >= cost
 * ----------------------------------------------------------------------- */
int test_lsps2_multi_htlc_accumulation(void) {
    lsps2_pending_table_t tbl;
    uint64_t scid = 0xDDDDDDDDDDDDDDDDULL;
    make_pending(&tbl, scid, 1000000, 12000);

    ASSERT(lsps2_handle_intercept_htlc(&tbl, scid, 4000, NULL, NULL) == 0,
           "L2D7: htlc1 (4000) no trigger");
    ASSERT(tbl.entries[0].collected_msat == 4000, "L2D7: 4000 collected");

    ASSERT(lsps2_handle_intercept_htlc(&tbl, scid, 4000, NULL, NULL) == 0,
           "L2D7: htlc2 (4000) no trigger");
    ASSERT(tbl.entries[0].collected_msat == 8000, "L2D7: 8000 collected");

    /* Third HTLC: 8000 + 5000 = 13000 >= 12000 */
    ASSERT(lsps2_handle_intercept_htlc(&tbl, scid, 5000, NULL, NULL) == 1,
           "L2D7: htlc3 triggers broadcast");

    return 1;
}

/* -----------------------------------------------------------------------
 * L2D8: table full (LSPS2_PENDING_MAX entries) — lookup still works
 * ----------------------------------------------------------------------- */
int test_lsps2_table_full_lookup(void) {
    lsps2_pending_table_t tbl;
    memset(&tbl, 0, sizeof(tbl));

    /* Fill all 16 slots */
    for (int i = 0; i < LSPS2_PENDING_MAX; i++) {
        tbl.entries[i].active       = 1;
        tbl.entries[i].scid         = (uint64_t)(0x1000 + i);
        tbl.entries[i].cost_msat    = 5000;
        tbl.entries[i].collected_msat = 0;
        tbl.entries[i].created_at   = (uint32_t)time(NULL);
        tbl.count++;
    }
    ASSERT(tbl.count == LSPS2_PENDING_MAX, "L2D8: table full");

    /* Lookup last slot SCID */
    uint64_t last_scid = (uint64_t)(0x1000 + LSPS2_PENDING_MAX - 1);
    lsps2_pending_t *found = lsps2_pending_lookup(&tbl, last_scid);
    ASSERT(found != NULL, "L2D8: lookup in full table succeeds");
    ASSERT(found->scid == last_scid, "L2D8: correct entry returned");

    /* HTLC on first slot should accumulate */
    int ret = lsps2_handle_intercept_htlc(&tbl, 0x1000, 3000, NULL, NULL);
    ASSERT(ret == 0, "L2D8: partial HTLC in full table works");
    ASSERT(tbl.entries[0].collected_msat == 3000, "L2D8: collected 3000");

    return 1;
}

/* -----------------------------------------------------------------------
 * L2D9: two independent entries — HTLCs don't bleed between entries
 * ----------------------------------------------------------------------- */
int test_lsps2_two_independent_entries(void) {
    lsps2_pending_table_t tbl;
    memset(&tbl, 0, sizeof(tbl));

    uint64_t scid_a = 0xAAAA000000000001ULL;
    uint64_t scid_b = 0xBBBB000000000002ULL;

    /* Entry A: cost 6000 */
    tbl.entries[0].active       = 1;
    tbl.entries[0].scid         = scid_a;
    tbl.entries[0].cost_msat    = 6000;
    tbl.entries[0].collected_msat = 0;
    tbl.entries[0].created_at   = (uint32_t)time(NULL);

    /* Entry B: cost 9000 */
    tbl.entries[1].active       = 1;
    tbl.entries[1].scid         = scid_b;
    tbl.entries[1].cost_msat    = 9000;
    tbl.entries[1].collected_msat = 0;
    tbl.entries[1].created_at   = (uint32_t)time(NULL);

    tbl.count = 2;

    /* HTLC on B: partial */
    ASSERT(lsps2_handle_intercept_htlc(&tbl, scid_b, 5000, NULL, NULL) == 0,
           "L2D9: B partial");
    ASSERT(tbl.entries[0].collected_msat == 0, "L2D9: A not touched");
    ASSERT(tbl.entries[1].collected_msat == 5000, "L2D9: B has 5000");

    /* HTLC on A: enough to trigger A */
    ASSERT(lsps2_handle_intercept_htlc(&tbl, scid_a, 7000, NULL, NULL) == 1,
           "L2D9: A triggers");
    ASSERT(tbl.entries[0].active == 0, "L2D9: A deactivated");

    /* B still active, still has 5000 */
    ASSERT(tbl.entries[1].active == 1, "L2D9: B still active");
    ASSERT(tbl.entries[1].collected_msat == 5000, "L2D9: B still 5000");

    return 1;
}
