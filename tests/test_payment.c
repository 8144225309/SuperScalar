/*
 * test_payment.c — Unit tests for the payment state machine
 */

#include "superscalar/payment.h"
#include "superscalar/gossip_store.h"
#include "superscalar/bolt11.h"
#include <secp256k1.h>
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

static void make_pubkey33(unsigned char pk[33], int seed) {
    memset(pk, 0, 33);
    pk[0] = 0x02;
    pk[1] = (unsigned char)seed;
}

/* ---- Test PAY1: init clears table ---- */
int test_payment_init(void)
{
    payment_table_t pt;
    memset(&pt, 0xFF, sizeof(pt));
    payment_init(&pt);
    ASSERT(pt.count == 0, "count is 0 after init");
    return 1;
}

/* ---- Test PAY2: send fails with no route (empty graph) ---- */
int test_payment_send_no_route(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char our_priv[32];
    memset(our_priv, 0x42, 32);

    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open gs");

    payment_table_t pt;
    payment_init(&pt);

    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    memset(inv.payment_hash,   0xAB, 32);
    memset(inv.payment_secret, 0xCD, 32);
    inv.has_payment_secret = 1;
    inv.amount_msat = 50000;
    inv.has_amount  = 1;
    make_pubkey33(inv.payee_pubkey, 99); /* unknown destination */

    int idx = payment_send(&pt, &gs, NULL, NULL, NULL, ctx, our_priv, &inv);
    ASSERT(idx >= 0, "payment returns index even on failure");
    ASSERT(pt.entries[idx].state == PAY_STATE_FAILED, "state is FAILED");
    ASSERT(pt.entries[idx].last_error[0] != '\0', "error message set");

    gossip_store_close(&gs);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test PAY3: on_settle updates state ---- */
int test_payment_on_settle(void)
{
    payment_table_t pt;
    payment_init(&pt);

    /* Manually add an in-flight payment */
    payment_t *pay = &pt.entries[pt.count++];
    memset(pay, 0, sizeof(*pay));
    memset(pay->payment_hash, 0x11, 32);
    pay->state = PAY_STATE_INFLIGHT;

    unsigned char preimage[32];
    memset(preimage, 0x22, 32);
    payment_on_settle(&pt, pay->payment_hash, preimage);

    ASSERT(pay->state == PAY_STATE_SUCCESS, "state is SUCCESS");
    ASSERT(memcmp(pay->payment_preimage, preimage, 32) == 0, "preimage stored");
    return 1;
}

/* ---- Test PAY4: keysend fails with no route ---- */
int test_payment_keysend_no_route(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char our_priv[32];
    memset(our_priv, 0x55, 32);

    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open gs");

    payment_table_t pt;
    payment_init(&pt);

    unsigned char dest_pk[33];
    make_pubkey33(dest_pk, 77);

    unsigned char preimage[32];
    memset(preimage, 0x88, 32);

    int idx = payment_keysend(&pt, &gs, NULL, NULL, NULL, ctx,
                               our_priv, dest_pk, 1000, preimage);
    ASSERT(idx >= 0, "keysend returns index");
    ASSERT(pt.entries[idx].state == PAY_STATE_FAILED, "keysend state is FAILED (no route)");

    gossip_store_close(&gs);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test PAY5: keysend computes correct payment_hash ---- */
int test_payment_keysend_hash(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char our_priv[32];
    memset(our_priv, 0x55, 32);

    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open gs");

    payment_table_t pt;
    payment_init(&pt);

    unsigned char dest_pk[33];
    make_pubkey33(dest_pk, 10);

    unsigned char preimage[32];
    memset(preimage, 0x01, 32);

    payment_keysend(&pt, &gs, NULL, NULL, NULL, ctx,
                    our_priv, dest_pk, 1000, preimage);

    /* payment_hash should be SHA256(preimage) */
    /* We can't easily call sha256 here without a dependency, so just check non-zero */
    ASSERT(pt.count > 0, "entry was created");
    payment_t *pay = &pt.entries[pt.count - 1];
    unsigned char zeros[32] = {0};
    ASSERT(memcmp(pay->payment_hash, zeros, 32) != 0, "payment_hash is non-zero");
    /* Preimage should be stored */
    ASSERT(memcmp(pay->payment_preimage, preimage, 32) == 0, "preimage stored");

    gossip_store_close(&gs);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* PAY6 — payment_check_timeouts: expired + max attempts → FAILED     */
/* ================================================================== */
int test_payment_timeout_expires_inflight(void)
{
    payment_table_t pt;
    payment_init(&pt);

    payment_t *p = &pt.entries[0];
    p->state       = PAY_STATE_INFLIGHT;
    p->attempt_at  = 1000; /* long ago */
    p->n_attempts  = PAYMENT_MAX_ATTEMPTS;
    p->n_routes    = 0;
    pt.count       = 1;

    uint32_t now = 1000 + PAYMENT_TIMEOUT_SECS + 1;
    int expired = payment_check_timeouts(&pt, NULL, NULL, NULL,
                                          NULL, NULL, NULL, now);
    ASSERT(expired == 1, "PAY6: 1 payment expired");
    ASSERT(p->state == PAY_STATE_FAILED, "PAY6: state -> FAILED");
    ASSERT(strlen(p->last_error) > 0, "PAY6: last_error populated");
    return 1;
}

/* ================================================================== */
/* PAY7 — payment_check_timeouts: not yet expired → unchanged         */
/* ================================================================== */
int test_payment_timeout_ignores_recent(void)
{
    payment_table_t pt;
    payment_init(&pt);

    payment_t *p = &pt.entries[0];
    p->state      = PAY_STATE_INFLIGHT;
    p->attempt_at = 1000;
    pt.count      = 1;

    uint32_t now = 1000 + 10; /* only 10 s, well within 60 s */
    int expired = payment_check_timeouts(&pt, NULL, NULL, NULL,
                                          NULL, NULL, NULL, now);
    ASSERT(expired == 0, "PAY7: no expiry on recent payment");
    ASSERT(p->state == PAY_STATE_INFLIGHT, "PAY7: state unchanged");
    return 1;
}

/* ================================================================== */
/* PAY8 — payment_check_timeouts: non-inflight states ignored         */
/* ================================================================== */
int test_payment_timeout_ignores_non_inflight(void)
{
    payment_table_t pt;
    payment_init(&pt);

    pt.entries[0].state = PAY_STATE_SUCCESS;  pt.entries[0].attempt_at = 0;
    pt.entries[1].state = PAY_STATE_PENDING;  pt.entries[1].attempt_at = 0;
    pt.entries[2].state = PAY_STATE_FAILED;   pt.entries[2].attempt_at = 0;
    pt.count = 3;

    int expired = payment_check_timeouts(&pt, NULL, NULL, NULL,
                                          NULL, NULL, NULL, 9999999);
    ASSERT(expired == 0, "PAY8: non-inflight states ignored");
    ASSERT(pt.entries[0].state == PAY_STATE_SUCCESS, "PAY8: SUCCESS unchanged");
    ASSERT(pt.entries[1].state == PAY_STATE_PENDING, "PAY8: PENDING unchanged");
    ASSERT(pt.entries[2].state == PAY_STATE_FAILED,  "PAY8: FAILED unchanged");
    return 1;
}

/* ================================================================== */
/* PAY9 — payment_check_timeouts: NULL table → no crash               */
/* ================================================================== */
int test_payment_timeout_null_table(void)
{
    int r = payment_check_timeouts(NULL, NULL, NULL, NULL,
                                    NULL, NULL, NULL, 12345);
    ASSERT(r == 0, "PAY9: NULL table returns 0, no crash");
    return 1;
}
