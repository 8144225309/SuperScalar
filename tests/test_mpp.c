/*
 * test_mpp.c — Multi-path payment aggregation unit tests (PR #19 Commit 5)
 */

#include "superscalar/mpp.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

static void make_secret(unsigned char out[32], int seed) {
    memset(out, seed & 0xFF, 32);
    out[0] = (unsigned char)(seed >> 8);
}

/* -----------------------------------------------------------------------
 * Single-part payment: one HTLC at full amount → immediately complete
 * ----------------------------------------------------------------------- */

int test_mpp_single_part(void) {
    mpp_table_t tbl;
    mpp_init(&tbl);

    unsigned char secret[32];
    make_secret(secret, 1);

    int ret = mpp_add_part(&tbl, secret, 1001, 50000, 50000, 700000);
    ASSERT(ret == 1, "single-part at full amount → complete");

    uint64_t ids[MPP_MAX_PARTS];
    int n = mpp_get_parts(&tbl, secret, ids, MPP_MAX_PARTS);
    ASSERT(n == 1, "one part stored");
    ASSERT(ids[0] == 1001, "correct htlc_id");

    mpp_remove(&tbl, secret);
    ASSERT(mpp_get_parts(&tbl, secret, ids, MPP_MAX_PARTS) == 0,
           "entry removed after mpp_remove");

    return 1;
}

/* -----------------------------------------------------------------------
 * Three parts summing to total → complete on 3rd
 * ----------------------------------------------------------------------- */

int test_mpp_three_parts(void) {
    mpp_table_t tbl;
    mpp_init(&tbl);

    unsigned char secret[32];
    make_secret(secret, 2);

    uint64_t total = 120000;
    int r1 = mpp_add_part(&tbl, secret, 2001, 40000, total, 700000);
    ASSERT(r1 == 0, "first part (40k/120k) → still collecting");

    int r2 = mpp_add_part(&tbl, secret, 2002, 40000, total, 700001);
    ASSERT(r2 == 0, "second part (80k/120k) → still collecting");

    int r3 = mpp_add_part(&tbl, secret, 2003, 40000, total, 700002);
    ASSERT(r3 == 1, "third part (120k/120k) → complete");

    uint64_t ids[MPP_MAX_PARTS];
    int n = mpp_get_parts(&tbl, secret, ids, MPP_MAX_PARTS);
    ASSERT(n == 3, "three htlc_ids stored");

    return 1;
}

/* -----------------------------------------------------------------------
 * Timeout: incomplete after MPP_TIMEOUT_SECS → all parts failed
 * ----------------------------------------------------------------------- */

int test_mpp_timeout(void) {
    mpp_table_t tbl;
    mpp_init(&tbl);

    unsigned char secret[32];
    make_secret(secret, 3);

    uint32_t now = 1800000000u;

    /* Add partial payment (only half collected) */
    mpp_add_part(&tbl, secret, 3001, 30000, 100000, 700000);
    mpp_add_part(&tbl, secret, 3002, 30000, 100000, 700001);

    /* Force the received timestamp to the past */
    for (int i = 0; i < MPP_MAX_PAYMENTS; i++) {
        if (tbl.entries[i].active &&
            memcmp(tbl.entries[i].payment_secret, secret, 32) == 0) {
            tbl.entries[i].first_received_unix = now - MPP_TIMEOUT_SECS - 1;
            break;
        }
    }

    uint64_t failed[MPP_MAX_PAYMENTS * MPP_MAX_PARTS];
    int n = mpp_check_timeouts(&tbl, now, failed, (int)(sizeof(failed)/sizeof(failed[0])));
    ASSERT(n == 2, "both parts returned as timed-out htlc_ids");
    ASSERT(failed[0] == 3001 || failed[1] == 3001, "htlc 3001 in failed list");
    ASSERT(failed[0] == 3002 || failed[1] == 3002, "htlc 3002 in failed list");

    /* Entry must be gone from table */
    uint64_t ids[MPP_MAX_PARTS];
    ASSERT(mpp_get_parts(&tbl, secret, ids, MPP_MAX_PARTS) == 0,
           "timed-out entry removed");

    return 1;
}

/* -----------------------------------------------------------------------
 * Overpayment guard: collected > 2 * total → rejected
 * ----------------------------------------------------------------------- */

int test_mpp_overpayment_guard(void) {
    mpp_table_t tbl;
    mpp_init(&tbl);

    unsigned char secret[32];
    make_secret(secret, 4);

    uint64_t total = 50000;
    /* Pay exactly total → OK */
    mpp_add_part(&tbl, secret, 4001, total, total, 700000);
    mpp_remove(&tbl, secret);

    /* Re-add and try paying 2*total + 1 in one shot → should fail */
    int ret = mpp_add_part(&tbl, secret, 4002, 2 * total + 1, total, 700001);
    ASSERT(ret == -1, "overpayment (> 2x total) rejected");

    return 1;
}

/* -----------------------------------------------------------------------
 * Table full: 32 concurrent payments, 33rd rejected
 * ----------------------------------------------------------------------- */

int test_mpp_table_full(void) {
    mpp_table_t tbl;
    mpp_init(&tbl);

    /* Fill table with MPP_MAX_PAYMENTS distinct payments */
    for (int i = 0; i < MPP_MAX_PAYMENTS; i++) {
        unsigned char secret[32];
        make_secret(secret, 10 + i);
        /* Make each unique by adding the index */
        secret[31] = (unsigned char)i;
        int ret = mpp_add_part(&tbl, secret, (uint64_t)(5000 + i),
                                100000, 100000, 700000);
        ASSERT(ret == 1, "payment added (single-part fills immediately)");
        /* Do NOT remove — keep the entry active by re-adding new parts */
    }

    /* 33rd payment with a brand-new secret → table full → -1 */
    unsigned char extra[32];
    make_secret(extra, 255);
    /* These entries are all complete, so they're still active until removed.
     * We need an incomplete set to keep entries. Let's use a 2-part scenario. */

    /* Re-test: fill with incomplete 2-part sets */
    mpp_init(&tbl);
    for (int i = 0; i < MPP_MAX_PAYMENTS; i++) {
        unsigned char secret[32];
        make_secret(secret, 10 + i);
        secret[31] = (unsigned char)i;
        /* Add only first part (incomplete, 1/2 collected) */
        int ret = mpp_add_part(&tbl, secret, (uint64_t)(6000 + i),
                                50000, 100000, 700000);
        ASSERT(ret == 0, "first partial part stored");
    }

    /* Now 33rd distinct secret is rejected */
    int ret = mpp_add_part(&tbl, extra, 7000, 100000, 100000, 700000);
    ASSERT(ret == -1, "33rd concurrent payment rejected (table full)");

    return 1;
}
