/*
 * test_pathfind_exclude.c — Tests for pathfind exclusion list
 *
 * PR #46: Pathfind Exclusion List (channel exclusion for payment retry)
 */

#include "superscalar/pathfind_exclude.h"
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

#define NOW  1700000000u

/* -----------------------------------------------------------------------
 * PE1: add entries → is_excluded returns true
 * --------------------------------------------------------------------- */
int test_pe_add_is_excluded(void)
{
    pathfind_exclude_t ex;
    pathfind_exclude_init(&ex);

    ASSERT(!pathfind_exclude_is_excluded(&ex, 1234, 0), "empty: not excluded");

    pathfind_exclude_add(&ex, 1234, 0);
    ASSERT(pathfind_exclude_is_excluded(&ex, 1234, 0), "dir=0 excluded");
    ASSERT(!pathfind_exclude_is_excluded(&ex, 1234, 1), "dir=1 not excluded");
    ASSERT(!pathfind_exclude_is_excluded(&ex, 9999, 0), "different scid not excluded");

    ASSERT(pathfind_exclude_count(&ex) == 1, "count == 1");
    return 1;
}

/* -----------------------------------------------------------------------
 * PE2: remove entry → is_excluded returns false
 * --------------------------------------------------------------------- */
int test_pe_remove(void)
{
    pathfind_exclude_t ex;
    pathfind_exclude_init(&ex);

    pathfind_exclude_add(&ex, 100, 0);
    pathfind_exclude_add(&ex, 200, 1);
    ASSERT(pathfind_exclude_count(&ex) == 2, "count 2");

    int r = pathfind_exclude_remove(&ex, 100, 0);
    ASSERT(r == 1, "remove returned 1");
    ASSERT(!pathfind_exclude_is_excluded(&ex, 100, 0), "100/dir0 no longer excluded");
    ASSERT(pathfind_exclude_is_excluded(&ex, 200, 1), "200/dir1 still excluded");
    ASSERT(pathfind_exclude_count(&ex) == 1, "count 1 after remove");

    /* Remove non-existent → returns 0 */
    r = pathfind_exclude_remove(&ex, 9999, 0);
    ASSERT(r == 0, "remove non-existent returns 0");
    return 1;
}

/* -----------------------------------------------------------------------
 * PE3: direction-specific: add dir=0 only → dir=1 is not excluded
 * --------------------------------------------------------------------- */
int test_pe_direction_specific(void)
{
    pathfind_exclude_t ex;
    pathfind_exclude_init(&ex);

    uint64_t scid = 555;
    pathfind_exclude_add(&ex, scid, 0);

    ASSERT(pathfind_exclude_is_excluded(&ex, scid, 0), "dir=0 excluded");
    ASSERT(!pathfind_exclude_is_excluded(&ex, scid, 1), "dir=1 not excluded");
    return 1;
}

/* -----------------------------------------------------------------------
 * PE4: direction -1 (both): both directions excluded
 * --------------------------------------------------------------------- */
int test_pe_direction_both(void)
{
    pathfind_exclude_t ex;
    pathfind_exclude_init(&ex);

    uint64_t scid = 777;
    pathfind_exclude_add(&ex, scid, -1);

    ASSERT(pathfind_exclude_is_excluded(&ex, scid, 0), "dir=0 excluded via dir=-1");
    ASSERT(pathfind_exclude_is_excluded(&ex, scid, 1), "dir=1 excluded via dir=-1");
    ASSERT(!pathfind_exclude_is_excluded(&ex, scid + 1, 0), "different scid ok");
    return 1;
}

/* -----------------------------------------------------------------------
 * PE5: clear removes all entries
 * --------------------------------------------------------------------- */
int test_pe_clear(void)
{
    pathfind_exclude_t ex;
    pathfind_exclude_init(&ex);

    for (int i = 0; i < 10; i++)
        pathfind_exclude_add(&ex, (uint64_t)(i + 1), 0);
    ASSERT(pathfind_exclude_count(&ex) == 10, "10 entries");

    pathfind_exclude_clear(&ex);
    ASSERT(pathfind_exclude_count(&ex) == 0, "count 0 after clear");

    for (int i = 0; i < 10; i++)
        ASSERT(!pathfind_exclude_is_excluded(&ex, (uint64_t)(i + 1), 0),
               "nothing excluded after clear");
    return 1;
}

/* -----------------------------------------------------------------------
 * PE6: from_mc — penalized channel is added to exclude list
 * --------------------------------------------------------------------- */
int test_pe_from_mc_penalized(void)
{
    mc_table_t mc;
    mc_init(&mc);

    uint64_t scid = 42;
    mc_record_failure(&mc, scid, 0, 100000, NOW);

    pathfind_exclude_t ex;
    pathfind_exclude_init(&ex);

    /* Amount >= min_fail_msat: should be excluded */
    int added = pathfind_exclude_from_mc(&ex, &mc, 100000, NOW + 1);
    ASSERT(added == 1, "PE6: 1 entry added from penalized mc");
    ASSERT(pathfind_exclude_is_excluded(&ex, scid, 0), "scid excluded");
    return 1;
}

/* -----------------------------------------------------------------------
 * PE7: from_mc — non-penalized channel is not added
 * --------------------------------------------------------------------- */
int test_pe_from_mc_clean(void)
{
    mc_table_t mc;
    mc_init(&mc);

    uint64_t scid = 43;
    /* No failures recorded */

    pathfind_exclude_t ex;
    pathfind_exclude_init(&ex);

    int added = pathfind_exclude_from_mc(&ex, &mc, 100000, NOW);
    ASSERT(added == 0, "PE7: no entries added for clean mc");
    ASSERT(!pathfind_exclude_is_excluded(&ex, scid, 0), "scid not excluded");
    return 1;
}

/* -----------------------------------------------------------------------
 * PE8: from_mc — success-cleared channel is not added
 * --------------------------------------------------------------------- */
int test_pe_from_mc_success_cleared(void)
{
    mc_table_t mc;
    mc_init(&mc);

    uint64_t scid = 44;
    mc_record_failure(&mc, scid, 0, 100000, NOW);
    /* Success after failure clears the penalty */
    mc_record_success(&mc, scid, 0, 100000, NOW + 10);

    pathfind_exclude_t ex;
    pathfind_exclude_init(&ex);

    int added = pathfind_exclude_from_mc(&ex, &mc, 100000, NOW + 10);
    ASSERT(added == 0, "PE8: success-cleared channel not excluded");
    return 1;
}

/* -----------------------------------------------------------------------
 * PE9: from_mc — amount threshold: channel not excluded if amount below fail amount
 * --------------------------------------------------------------------- */
int test_pe_from_mc_amount_threshold(void)
{
    mc_table_t mc;
    mc_init(&mc);

    uint64_t scid = 45;
    /* Failure at 100000 msat */
    mc_record_failure(&mc, scid, 0, 100000, NOW);

    pathfind_exclude_t ex;
    pathfind_exclude_init(&ex);

    /* Amount below failure threshold — should NOT be excluded */
    int added = pathfind_exclude_from_mc(&ex, &mc, 50000, NOW + 1);
    ASSERT(added == 0, "PE9: amount below threshold, not excluded");
    ASSERT(!pathfind_exclude_is_excluded(&ex, scid, 0), "not excluded");

    /* Amount at failure threshold — should be excluded */
    int added2 = pathfind_exclude_from_mc(&ex, &mc, 100000, NOW + 1);
    ASSERT(added2 == 1, "at threshold, excluded");
    ASSERT(pathfind_exclude_is_excluded(&ex, scid, 0), "scid excluded at threshold");
    return 1;
}

/* -----------------------------------------------------------------------
 * PE10: table full — oldest entry evicted when new entry added
 * --------------------------------------------------------------------- */
int test_pe_table_full(void)
{
    pathfind_exclude_t ex;
    pathfind_exclude_init(&ex);

    /* Fill the table */
    for (int i = 0; i < PATHFIND_EXCLUDE_MAX; i++)
        pathfind_exclude_add(&ex, (uint64_t)(i + 100), 0);
    ASSERT(pathfind_exclude_count(&ex) == PATHFIND_EXCLUDE_MAX, "table full");

    /* Add one more — should evict lowest scid (100) */
    pathfind_exclude_add(&ex, 9999999, 0);
    ASSERT(pathfind_exclude_count(&ex) == PATHFIND_EXCLUDE_MAX, "count unchanged");
    ASSERT(pathfind_exclude_is_excluded(&ex, 9999999, 0), "new entry present");
    /* Entry with lowest scid (100) should be gone */
    ASSERT(!pathfind_exclude_is_excluded(&ex, 100, 0), "lowest scid evicted");
    return 1;
}

/* -----------------------------------------------------------------------
 * PE11: duplicate add — not duplicated in list
 * --------------------------------------------------------------------- */
int test_pe_no_duplicate(void)
{
    pathfind_exclude_t ex;
    pathfind_exclude_init(&ex);

    pathfind_exclude_add(&ex, 888, 0);
    pathfind_exclude_add(&ex, 888, 0); /* duplicate */
    pathfind_exclude_add(&ex, 888, 0); /* duplicate again */

    ASSERT(pathfind_exclude_count(&ex) == 1, "PE11: no duplicates");
    return 1;
}

/* -----------------------------------------------------------------------
 * PE12: NULL safety
 * --------------------------------------------------------------------- */
int test_pe_null_safety(void)
{
    pathfind_exclude_init(NULL);
    ASSERT(pathfind_exclude_add(NULL, 1, 0) == 0, "NULL add returns 0");
    ASSERT(pathfind_exclude_remove(NULL, 1, 0) == 0, "NULL remove returns 0");
    ASSERT(pathfind_exclude_is_excluded(NULL, 1, 0) == 0, "NULL is_excluded returns 0");
    pathfind_exclude_clear(NULL);
    ASSERT(pathfind_exclude_count(NULL) == 0, "NULL count returns 0");
    ASSERT(pathfind_exclude_from_mc(NULL, NULL, 0, 0) == 0, "NULL from_mc returns 0");

    /* from_mc with valid ex but NULL mc */
    pathfind_exclude_t ex;
    pathfind_exclude_init(&ex);
    ASSERT(pathfind_exclude_from_mc(&ex, NULL, 0, 0) == 0, "NULL mc returns 0");
    return 1;
}

/* -----------------------------------------------------------------------
 * PE13: empty exclusion list — nothing excluded
 * --------------------------------------------------------------------- */
int test_pe_empty_excludes_nothing(void)
{
    pathfind_exclude_t ex;
    pathfind_exclude_init(&ex);

    for (uint64_t scid = 1; scid <= 20; scid++) {
        ASSERT(!pathfind_exclude_is_excluded(&ex, scid, 0), "dir=0 not excluded");
        ASSERT(!pathfind_exclude_is_excluded(&ex, scid, 1), "dir=1 not excluded");
    }
    ASSERT(pathfind_exclude_count(&ex) == 0, "count zero");
    return 1;
}
