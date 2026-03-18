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
