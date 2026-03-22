/*
 * test_hold_invoice.c — Tests for hold invoice async payment delivery.
 *
 * PR #36: Hold invoices for LSP async HTLC handling
 */

#include "superscalar/hold_invoice.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <openssl/sha.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* Helper: compute SHA256 of a 32-byte preimage */
static void make_payment_hash(const unsigned char preimage[32],
                               unsigned char hash[32])
{
    SHA256(preimage, 32, hash);
}

/* HI1: hold_invoice_init creates empty table */
int test_hold_invoice_init(void)
{
    hold_invoice_table_t tbl;
    hold_invoice_init(&tbl);
    ASSERT(tbl.count == 0, "initial count=0");
    ASSERT(hold_invoice_count_by_state(&tbl, HOLD_INVOICE_PENDING) == 0,
           "no pending");
    hold_invoice_init(NULL);  /* no crash */
    return 1;
}

/* HI2: hold_invoice_add creates pending invoice */
int test_hold_invoice_add(void)
{
    hold_invoice_table_t tbl;
    hold_invoice_init(&tbl);

    unsigned char preimage[32]; memset(preimage, 0x11, 32);
    unsigned char payment_hash[32]; make_payment_hash(preimage, payment_hash);
    unsigned char payment_secret[32]; memset(payment_secret, 0x22, 32);

    ASSERT(hold_invoice_add(&tbl, payment_hash, payment_secret,
                             10000, 3600, "test invoice"), "add ok");
    ASSERT(tbl.count == 1, "count=1");
    ASSERT(hold_invoice_count_by_state(&tbl, HOLD_INVOICE_PENDING) == 1,
           "one pending");

    hold_invoice_entry_t *e = hold_invoice_find(&tbl, payment_hash);
    ASSERT(e != NULL, "found");
    ASSERT(e->state == HOLD_INVOICE_PENDING, "state=PENDING");
    ASSERT(e->amount_msat == 10000, "amount preserved");
    ASSERT(strcmp(e->description, "test invoice") == 0, "description ok");
    return 1;
}

/* HI3: table full returns 0 */
int test_hold_invoice_table_full(void)
{
    hold_invoice_table_t tbl;
    hold_invoice_init(&tbl);

    unsigned char ph[32], ps[32];
    int i;
    for (i = 0; i < HOLD_INVOICE_TABLE_MAX; i++) {
        memset(ph, (unsigned char)i, 32);
        memset(ps, (unsigned char)(i+1), 32);
        ASSERT(hold_invoice_add(&tbl, ph, ps, 1000, 0, NULL),
               "add succeeds up to max");
    }
    memset(ph, 0xFF, 32);
    memset(ps, 0xFE, 32);
    ASSERT(!hold_invoice_add(&tbl, ph, ps, 1000, 0, NULL),
           "add fails when full");
    return 1;
}

/* HI4: hold_invoice_on_htlc transitions PENDING → ACCEPTED */
int test_hold_invoice_accept(void)
{
    hold_invoice_table_t tbl;
    hold_invoice_init(&tbl);

    unsigned char preimage[32]; memset(preimage, 0x33, 32);
    unsigned char ph[32]; make_payment_hash(preimage, ph);
    unsigned char ps[32]; memset(ps, 0x44, 32);

    ASSERT(hold_invoice_add(&tbl, ph, ps, 5000, 3600, "hold"), "add ok");
    ASSERT(hold_invoice_on_htlc(&tbl, ph, 5000, 42, 0), "on_htlc ok");

    hold_invoice_entry_t *e = hold_invoice_find(&tbl, ph);
    ASSERT(e->state == HOLD_INVOICE_ACCEPTED, "state=ACCEPTED");
    ASSERT(e->htlc_id == 42, "htlc_id stored");
    ASSERT(e->peer_idx == 0, "peer_idx stored");
    ASSERT(e->htlc_amount_msat == 5000, "amount stored");
    return 1;
}

/* HI5: on_htlc rejects underpayment */
int test_hold_invoice_underpay(void)
{
    hold_invoice_table_t tbl;
    hold_invoice_init(&tbl);

    unsigned char preimage[32]; memset(preimage, 0x55, 32);
    unsigned char ph[32]; make_payment_hash(preimage, ph);
    unsigned char ps[32]; memset(ps, 0x66, 32);

    ASSERT(hold_invoice_add(&tbl, ph, ps, 10000, 3600, NULL), "add ok");
    ASSERT(!hold_invoice_on_htlc(&tbl, ph, 9999, 1, 0), "underpayment rejected");
    ASSERT(hold_invoice_count_by_state(&tbl, HOLD_INVOICE_PENDING) == 1,
           "still pending");
    return 1;
}

/* HI6: hold_invoice_settle transitions ACCEPTED → SETTLED */
int test_hold_invoice_settle(void)
{
    hold_invoice_table_t tbl;
    hold_invoice_init(&tbl);

    unsigned char preimage[32]; memset(preimage, 0x77, 32);
    unsigned char ph[32]; make_payment_hash(preimage, ph);
    unsigned char ps[32]; memset(ps, 0x88, 32);

    ASSERT(hold_invoice_add(&tbl, ph, ps, 1000, 3600, NULL), "add ok");
    ASSERT(hold_invoice_on_htlc(&tbl, ph, 1000, 1, 0), "accept ok");
    ASSERT(hold_invoice_settle(&tbl, ph, preimage), "settle ok");

    hold_invoice_entry_t *e = hold_invoice_find(&tbl, ph);
    ASSERT(e->state == HOLD_INVOICE_SETTLED, "state=SETTLED");
    ASSERT(memcmp(e->preimage, preimage, 32) == 0, "preimage stored");
    return 1;
}

/* HI7: settle with wrong preimage rejected */
int test_hold_invoice_settle_wrong_preimage(void)
{
    hold_invoice_table_t tbl;
    hold_invoice_init(&tbl);

    unsigned char preimage[32]; memset(preimage, 0x99, 32);
    unsigned char ph[32]; make_payment_hash(preimage, ph);
    unsigned char ps[32]; memset(ps, 0xAA, 32);

    ASSERT(hold_invoice_add(&tbl, ph, ps, 500, 3600, NULL), "add ok");
    ASSERT(hold_invoice_on_htlc(&tbl, ph, 500, 1, 0), "accept ok");

    unsigned char wrong_preimage[32]; memset(wrong_preimage, 0xBB, 32);
    ASSERT(!hold_invoice_settle(&tbl, ph, wrong_preimage), "wrong preimage rejected");
    ASSERT(hold_invoice_count_by_state(&tbl, HOLD_INVOICE_ACCEPTED) == 1,
           "still accepted");
    return 1;
}

/* HI8: settle already-settled rejected (no double-settle) */
int test_hold_invoice_double_settle(void)
{
    hold_invoice_table_t tbl;
    hold_invoice_init(&tbl);

    unsigned char preimage[32]; memset(preimage, 0xCC, 32);
    unsigned char ph[32]; make_payment_hash(preimage, ph);
    unsigned char ps[32]; memset(ps, 0xDD, 32);

    ASSERT(hold_invoice_add(&tbl, ph, ps, 200, 3600, NULL), "add ok");
    ASSERT(hold_invoice_on_htlc(&tbl, ph, 200, 1, 0), "accept ok");
    ASSERT(hold_invoice_settle(&tbl, ph, preimage), "first settle ok");
    ASSERT(!hold_invoice_settle(&tbl, ph, preimage), "double settle rejected");
    return 1;
}

/* HI9: hold_invoice_cancel transitions PENDING or ACCEPTED → CANCELLED */
int test_hold_invoice_cancel(void)
{
    hold_invoice_table_t tbl;
    hold_invoice_init(&tbl);

    unsigned char ph[32]; memset(ph, 0xEE, 32);
    unsigned char ps[32]; memset(ps, 0xFF, 32);

    ASSERT(hold_invoice_add(&tbl, ph, ps, 100, 3600, NULL), "add ok");
    ASSERT(hold_invoice_cancel(&tbl, ph), "cancel pending ok");
    ASSERT(hold_invoice_count_by_state(&tbl, HOLD_INVOICE_CANCELLED) == 1,
           "state=CANCELLED");

    /* Can't cancel again */
    ASSERT(!hold_invoice_cancel(&tbl, ph), "double cancel rejected");
    return 1;
}

/* HI10: cancel settled invoice fails */
int test_hold_invoice_cancel_after_settle(void)
{
    hold_invoice_table_t tbl;
    hold_invoice_init(&tbl);

    unsigned char preimage[32]; memset(preimage, 0x12, 32);
    unsigned char ph[32]; make_payment_hash(preimage, ph);
    unsigned char ps[32]; memset(ps, 0x34, 32);

    ASSERT(hold_invoice_add(&tbl, ph, ps, 100, 3600, NULL), "add ok");
    ASSERT(hold_invoice_on_htlc(&tbl, ph, 100, 1, 0), "accept ok");
    ASSERT(hold_invoice_settle(&tbl, ph, preimage), "settle ok");
    ASSERT(!hold_invoice_cancel(&tbl, ph), "cancel after settle rejected");
    return 1;
}

/* HI11: on_htlc for unknown payment_hash */
int test_hold_invoice_unknown_htlc(void)
{
    hold_invoice_table_t tbl;
    hold_invoice_init(&tbl);

    unsigned char ph[32]; memset(ph, 0x56, 32);
    ASSERT(!hold_invoice_on_htlc(&tbl, ph, 1000, 1, 0), "unknown hash rejected");
    return 1;
}

/* HI12: hold_invoice_remove frees settled/cancelled slots */
int test_hold_invoice_remove(void)
{
    hold_invoice_table_t tbl;
    hold_invoice_init(&tbl);

    unsigned char preimage[32]; memset(preimage, 0x78, 32);
    unsigned char ph[32]; make_payment_hash(preimage, ph);
    unsigned char ps[32]; memset(ps, 0x90, 32);

    ASSERT(hold_invoice_add(&tbl, ph, ps, 100, 3600, NULL), "add ok");
    ASSERT(hold_invoice_on_htlc(&tbl, ph, 100, 1, 0), "accept ok");
    ASSERT(hold_invoice_settle(&tbl, ph, preimage), "settle ok");

    ASSERT(tbl.count == 1, "count=1 before remove");
    hold_invoice_remove(&tbl, ph);
    ASSERT(tbl.count == 0, "count=0 after remove");
    ASSERT(hold_invoice_find(&tbl, ph) == NULL, "not found after remove");
    return 1;
}

/* HI13: NULL safety checks */
int test_hold_invoice_null_safety(void)
{
    hold_invoice_table_t tbl;
    hold_invoice_init(&tbl);
    unsigned char ph[32]; memset(ph, 0, 32);
    unsigned char ps[32]; memset(ps, 0, 32);
    unsigned char pre[32]; memset(pre, 0, 32);

    ASSERT(!hold_invoice_add(NULL, ph, ps, 100, 0, NULL), "NULL tbl rejected");
    ASSERT(!hold_invoice_add(&tbl, NULL, ps, 100, 0, NULL), "NULL ph rejected");
    ASSERT(!hold_invoice_add(&tbl, ph, NULL, 100, 0, NULL), "NULL ps rejected");
    ASSERT(!hold_invoice_on_htlc(NULL, ph, 100, 1, 0), "NULL tbl on_htlc");
    ASSERT(!hold_invoice_settle(NULL, ph, pre), "NULL tbl settle");
    ASSERT(!hold_invoice_cancel(NULL, ph), "NULL tbl cancel");
    ASSERT(hold_invoice_find(NULL, ph) == NULL, "NULL tbl find");
    hold_invoice_remove(NULL, ph);  /* no crash */
    return 1;
}

/* HI14: any-amount invoice accepts any non-zero payment */
int test_hold_invoice_any_amount(void)
{
    hold_invoice_table_t tbl;
    hold_invoice_init(&tbl);

    unsigned char preimage[32]; memset(preimage, 0xAB, 32);
    unsigned char ph[32]; make_payment_hash(preimage, ph);
    unsigned char ps[32]; memset(ps, 0xCD, 32);

    /* amount_msat=0 means any amount */
    ASSERT(hold_invoice_add(&tbl, ph, ps, 0, 3600, NULL), "any-amount add ok");
    ASSERT(hold_invoice_on_htlc(&tbl, ph, 1, 1, 0), "1 msat accepted");
    return 1;
}
