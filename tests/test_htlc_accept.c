/*
 * test_htlc_accept.c — Tests for final-hop HTLC acceptance validation
 *
 * PR #44: HTLC Inbound Acceptance (BOLT #4 final-hop validation)
 */

#include "superscalar/htlc_accept.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

#define NOW   1700000000u
#define CLTV  (1000u + HTLC_ACCEPT_MIN_FINAL_CLTV + 5u)  /* safely above min */

static void fill_hash(unsigned char h[32], unsigned char seed) {
    memset(h, seed, 32);
}

/* HA1: HTLC_ACCEPT_OK for valid invoice */
int test_htlc_accept_ok(void)
{
    htlc_accept_table_t tbl;
    htlc_accept_init(&tbl);

    unsigned char ph[32], ps[32];
    fill_hash(ph, 0x11);
    fill_hash(ps, 0x22);
    ASSERT(htlc_accept_add(&tbl, ph, ps, 100000, NOW, 3600), "add ok");

    int r = htlc_accept_check(&tbl, ph, ps, 100000, CLTV, 1000, NOW + 100);
    ASSERT(r == HTLC_ACCEPT_OK, "result = OK");
    ASSERT(htlc_accept_result_str(r) != NULL, "result_str not null");
    return 1;
}

/* HA2: HTLC_ACCEPT_UNKNOWN_HASH for missing invoice */
int test_htlc_accept_unknown_hash(void)
{
    htlc_accept_table_t tbl;
    htlc_accept_init(&tbl);

    unsigned char ph[32];
    fill_hash(ph, 0x42);

    int r = htlc_accept_check(&tbl, ph, NULL, 100000, CLTV, 1000, NOW);
    ASSERT(r == HTLC_ACCEPT_UNKNOWN_HASH, "unknown hash");
    return 1;
}

/* HA3: HTLC_ACCEPT_EXPIRED for expired invoice */
int test_htlc_accept_expired(void)
{
    htlc_accept_table_t tbl;
    htlc_accept_init(&tbl);

    unsigned char ph[32];
    fill_hash(ph, 0x33);
    ASSERT(htlc_accept_add(&tbl, ph, NULL, 100000, NOW, 3600), "add");

    /* Check 1 second after expiry */
    int r = htlc_accept_check(&tbl, ph, NULL, 100000, CLTV, 1000, NOW + 3601);
    ASSERT(r == HTLC_ACCEPT_EXPIRED, "expired");
    return 1;
}

/* HA4: HTLC_ACCEPT_AMOUNT_LOW when amount below invoice */
int test_htlc_accept_amount_low(void)
{
    htlc_accept_table_t tbl;
    htlc_accept_init(&tbl);

    unsigned char ph[32];
    fill_hash(ph, 0x44);
    ASSERT(htlc_accept_add(&tbl, ph, NULL, 100000, NOW, 3600), "add");

    int r = htlc_accept_check(&tbl, ph, NULL, 50000, CLTV, 1000, NOW + 100);
    ASSERT(r == HTLC_ACCEPT_AMOUNT_LOW, "amount too low");
    return 1;
}

/* HA5: Any-amount invoice accepts any positive amount */
int test_htlc_accept_any_amount(void)
{
    htlc_accept_table_t tbl;
    htlc_accept_init(&tbl);

    unsigned char ph[32];
    fill_hash(ph, 0x55);
    ASSERT(htlc_accept_add(&tbl, ph, NULL, 0 /* any */, NOW, 3600), "add any-amount");

    int r = htlc_accept_check(&tbl, ph, NULL, 1, CLTV, 1000, NOW + 100);
    ASSERT(r == HTLC_ACCEPT_OK, "any-amount with 1 msat ok");
    return 1;
}

/* HA6: HTLC_ACCEPT_WRONG_SECRET when payment_secret missing */
int test_htlc_accept_missing_secret(void)
{
    htlc_accept_table_t tbl;
    htlc_accept_init(&tbl);

    unsigned char ph[32], ps[32];
    fill_hash(ph, 0x66); fill_hash(ps, 0x77);
    ASSERT(htlc_accept_add(&tbl, ph, ps, 100000, NOW, 3600), "add with secret");

    /* No secret provided */
    int r = htlc_accept_check(&tbl, ph, NULL, 100000, CLTV, 1000, NOW + 100);
    ASSERT(r == HTLC_ACCEPT_WRONG_SECRET, "missing secret");
    return 1;
}

/* HA7: HTLC_ACCEPT_WRONG_SECRET when secret is wrong */
int test_htlc_accept_wrong_secret(void)
{
    htlc_accept_table_t tbl;
    htlc_accept_init(&tbl);

    unsigned char ph[32], ps[32], wrong_ps[32];
    fill_hash(ph, 0x88); fill_hash(ps, 0x99); fill_hash(wrong_ps, 0xAA);
    ASSERT(htlc_accept_add(&tbl, ph, ps, 100000, NOW, 3600), "add");

    int r = htlc_accept_check(&tbl, ph, wrong_ps, 100000, CLTV, 1000, NOW + 100);
    ASSERT(r == HTLC_ACCEPT_WRONG_SECRET, "wrong secret");
    return 1;
}

/* HA8: HTLC_ACCEPT_ALREADY_PAID on second payment */
int test_htlc_accept_already_paid(void)
{
    htlc_accept_table_t tbl;
    htlc_accept_init(&tbl);

    unsigned char ph[32];
    fill_hash(ph, 0xBB);
    ASSERT(htlc_accept_add(&tbl, ph, NULL, 100000, NOW, 3600), "add");

    /* First payment */
    ASSERT(htlc_accept_check(&tbl, ph, NULL, 100000, CLTV, 1000, NOW + 100)
           == HTLC_ACCEPT_OK, "first payment ok");

    /* Second payment — should fail */
    int r = htlc_accept_check(&tbl, ph, NULL, 100000, CLTV, 1000, NOW + 200);
    ASSERT(r == HTLC_ACCEPT_ALREADY_PAID, "double payment rejected");
    return 1;
}

/* HA9: HTLC_ACCEPT_CLTV_TOO_LOW when cltv below minimum */
int test_htlc_accept_cltv_too_low(void)
{
    htlc_accept_table_t tbl;
    htlc_accept_init(&tbl);

    unsigned char ph[32];
    fill_hash(ph, 0xCC);
    ASSERT(htlc_accept_add(&tbl, ph, NULL, 100000, NOW, 3600), "add");

    /* chain_height=1000, htlc_cltv=1010 — only 10 blocks, below HTLC_ACCEPT_MIN_FINAL_CLTV=18 */
    int r = htlc_accept_check(&tbl, ph, NULL, 100000, 1010, 1000, NOW + 100);
    ASSERT(r == HTLC_ACCEPT_CLTV_TOO_LOW, "cltv too low");
    return 1;
}

/* HA10: chain_height=0 skips CLTV check */
int test_htlc_accept_no_cltv_check(void)
{
    htlc_accept_table_t tbl;
    htlc_accept_init(&tbl);

    unsigned char ph[32];
    fill_hash(ph, 0xDD);
    ASSERT(htlc_accept_add(&tbl, ph, NULL, 100000, NOW, 3600), "add");

    /* chain_height=0 → skip CLTV check */
    int r = htlc_accept_check(&tbl, ph, NULL, 100000, 1, 0, NOW + 100);
    ASSERT(r == HTLC_ACCEPT_OK, "chain_height=0 skips cltv check");
    return 1;
}

/* HA11: htlc_accept_find returns correct entry */
int test_htlc_accept_find(void)
{
    htlc_accept_table_t tbl;
    htlc_accept_init(&tbl);

    unsigned char ph[32];
    fill_hash(ph, 0xEE);
    ASSERT(htlc_accept_add(&tbl, ph, NULL, 50000, NOW, 7200), "add");

    htlc_accept_invoice_t *e = htlc_accept_find(&tbl, ph);
    ASSERT(e != NULL, "found");
    ASSERT(e->amount_msat == 50000, "amount correct");
    ASSERT(e->expiry == 7200, "expiry correct");

    unsigned char unknown[32]; fill_hash(unknown, 0x00);
    ASSERT(htlc_accept_find(&tbl, unknown) == NULL, "unknown → NULL");
    return 1;
}

/* HA12: prune removes settled and expired */
int test_htlc_accept_prune(void)
{
    htlc_accept_table_t tbl;
    htlc_accept_init(&tbl);

    unsigned char ph1[32], ph2[32], ph3[32];
    fill_hash(ph1, 0x01); fill_hash(ph2, 0x02); fill_hash(ph3, 0x03);

    ASSERT(htlc_accept_add(&tbl, ph1, NULL, 100, NOW, 60), "add ph1 (expires soon)");
    ASSERT(htlc_accept_add(&tbl, ph2, NULL, 100, NOW, 3600), "add ph2 (valid)");
    ASSERT(htlc_accept_add(&tbl, ph3, NULL, 100, NOW, 3600), "add ph3 (will settle)");

    /* Settle ph3 */
    htlc_accept_check(&tbl, ph3, NULL, 100, CLTV, 0, NOW + 10);

    /* Prune at NOW+61: ph1 expired, ph3 settled */
    int removed = htlc_accept_prune(&tbl, NOW + 61);
    ASSERT(removed == 2, "2 removed (expired + settled)");
    ASSERT(tbl.count == 1, "1 remaining");
    ASSERT(htlc_accept_find(&tbl, ph2) != NULL, "ph2 still present");
    return 1;
}

/* HA13: NULL safety */
int test_htlc_accept_null_safety(void)
{
    htlc_accept_init(NULL);
    ASSERT(htlc_accept_add(NULL, NULL, NULL, 0, 0, 0) == 0, "NULL tbl");
    ASSERT(htlc_accept_check(NULL, NULL, NULL, 0, 0, 0, 0) == HTLC_ACCEPT_UNKNOWN_HASH,
           "NULL check → UNKNOWN_HASH");
    ASSERT(htlc_accept_find(NULL, NULL) == NULL, "NULL find");
    ASSERT(htlc_accept_prune(NULL, 0) == 0, "NULL prune");
    ASSERT(htlc_accept_result_str(-1) != NULL, "unknown result str");
    return 1;
}
