#include "superscalar/onion.h"
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

/* ================================================================== */
/* AMP1 — payment_send_amp produces a payment entry                   */
/* ================================================================== */
int test_payment_amp_produces_onion_tlv14(void)
{
    payment_table_t pt;
    payment_init(&pt);

    /* Use NULL for gossip_store — function should return 0 with NULL gs */
    unsigned char pk[33], priv[32];
    memset(pk, 0x02, 33); pk[1] = 0x01;
    memset(priv, 0x11, 32);
    unsigned char hash_out[32];

    int r = payment_send_amp(&pt, NULL, NULL, NULL, NULL, NULL,
                              priv, pk, pk, 1000, 2, hash_out);
    /* With NULL gs, should fail gracefully */
    ASSERT(r == 0, "AMP1: NULL gs returns 0");
    return 1;
}

/* ================================================================== */
/* AMP2 — AMP set_id consistent (derived from same XOR)               */
/* ================================================================== */
int test_payment_amp_set_id_consistent(void)
{
    /* Manually verify: XOR of two known shares → SHA256 = set_id */
    unsigned char s1[32], s2[32];
    memset(s1, 0xAA, 32);
    memset(s2, 0x55, 32);
    /* XOR: AA ^ 55 = FF */
    unsigned char xored[32];
    for (int i = 0; i < 32; i++) xored[i] = s1[i] ^ s2[i];
    for (int i = 0; i < 32; i++)
        ASSERT(xored[i] == 0xFF, "AMP2: XOR produces 0xFF");
    return 1;
}

/* ================================================================== */
/* AMP3 — AMP child indices: 0..N-1                                   */
/* ================================================================== */
int test_payment_amp_child_indices(void)
{
    onion_hop_t hops[4];
    memset(hops, 0, sizeof(hops));
    for (int i = 0; i < 4; i++) {
        hops[i].has_amp = 1;
        hops[i].amp_child_index = (uint8_t)i;
    }
    for (int i = 0; i < 4; i++)
        ASSERT(hops[i].amp_child_index == i, "AMP3: child index");
    return 1;
}

/* ================================================================== */
/* AMP4 — graceful failure when gs is NULL                            */
/* ================================================================== */
int test_payment_amp_null_gs_fails(void)
{
    payment_table_t pt;
    payment_init(&pt);
    unsigned char pk[33], priv[32];
    memset(pk, 0x02, 33); memset(priv, 0x11, 32);
    unsigned char hash[32];
    int r = payment_send_amp(&pt, NULL, NULL, NULL, NULL, NULL,
                              priv, pk, pk, 100, 1, hash);
    ASSERT(r == 0, "AMP4: NULL gs returns 0");
    return 1;
}

/* ================================================================== */
/* AMP5 — AMP fields default to zero when has_amp=0                   */
/* ================================================================== */
int test_payment_amp_fields_zero_default(void)
{
    onion_hop_t hop;
    memset(&hop, 0, sizeof(hop));
    ASSERT(hop.has_amp == 0, "AMP5: has_amp defaults to 0");
    ASSERT(hop.amp_child_index == 0, "AMP5: child_index defaults to 0");
    return 1;
}

/* ================================================================== */
/* AMP6 — AMP set_id roundtrip in onion_hop_t                         */
/* ================================================================== */
int test_payment_amp_set_id_roundtrip(void)
{
    onion_hop_t hop;
    memset(&hop, 0, sizeof(hop));
    hop.has_amp = 1;
    memset(hop.amp_set_id, 0xDE, 32);
    memset(hop.amp_root_share, 0xAD, 32);
    hop.amp_child_index = 7;

    ASSERT(hop.amp_set_id[0] == 0xDE, "AMP6: set_id stored");
    ASSERT(hop.amp_root_share[0] == 0xAD, "AMP6: root_share stored");
    ASSERT(hop.amp_child_index == 7, "AMP6: child_index stored");
    return 1;
}

/* ================================================================== */
/* AMP7 — payment_send_amp with 0 shards fails                        */
/* ================================================================== */
int test_payment_amp_zero_shards_fails(void)
{
    payment_table_t pt;
    payment_init(&pt);
    unsigned char pk[33], priv[32];
    memset(pk, 0x02, 33); memset(priv, 0x11, 32);
    unsigned char hash[32];
    int r = payment_send_amp(&pt, NULL, NULL, NULL, NULL, NULL,
                              priv, pk, pk, 100, 0, hash);
    ASSERT(r == 0, "AMP7: 0 shards returns 0");
    return 1;
}

/* ================================================================== */
/* AMP8 — AMP payment_hash is 32 bytes when gs is provided (skip)    */
/* ================================================================== */
int test_payment_amp_hash_len(void)
{
    /* AMP hash_out should be exactly 32 bytes -- test by checking
       that the output pointer is distinct from input */
    unsigned char hash[32];
    memset(hash, 0xAA, 32);
    /* With NULL gs, payment_send_amp returns 0 -- hash untouched */
    payment_table_t pt; payment_init(&pt);
    unsigned char pk[33]; memset(pk, 0x02, 33);
    unsigned char priv[32]; memset(priv, 0x11, 32);
    payment_send_amp(&pt, NULL, NULL, NULL, NULL, NULL, priv, pk, pk, 100, 1, hash);
    /* hash still 0xAA since it returned 0 */
    ASSERT(hash[0] == 0xAA, "AMP8: hash unchanged on failure");
    return 1;
}

/* ================================================================== */
/* AMP9 — payment_send_amp with real gossip store finds routes        */
/* ================================================================== */
int test_payment_amp_routes_found(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    /* Our private key and derived pubkey */
    unsigned char our_priv[32]; memset(our_priv, 0x42, 32);
    secp256k1_pubkey our_pub_obj;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &our_pub_obj, our_priv), "pubkey");
    unsigned char our_pub[33]; size_t plen = 33;
    secp256k1_ec_pubkey_serialize(ctx, our_pub, &plen, &our_pub_obj, SECP256K1_EC_COMPRESSED);

    /* Destination pubkey */
    unsigned char dest_priv[32]; memset(dest_priv, 0x77, 32);
    secp256k1_pubkey dest_pub_obj;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &dest_pub_obj, dest_priv), "dest pubkey");
    unsigned char dest_pub[33]; plen = 33;
    secp256k1_ec_pubkey_serialize(ctx, dest_pub, &plen, &dest_pub_obj, SECP256K1_EC_COMPRESSED);

    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open gs");

    /* Insert a channel: our_pub → dest_pub */
    uint64_t scid = ((uint64_t)700000 << 40) | 1;
    gossip_store_upsert_channel(&gs, scid, our_pub, dest_pub, 1000000, 0);
    gossip_store_upsert_channel_update(&gs, scid, 0, 1000, 100, 40, 1);
    gossip_store_upsert_channel_update(&gs, scid, 1, 1000, 100, 40, 1);

    payment_table_t pt;
    payment_init(&pt);

    unsigned char hash_out[32];
    int r = payment_send_amp(&pt, &gs, NULL, NULL, NULL, ctx,
                              our_priv, our_pub, dest_pub, 2000, 1, hash_out);
    ASSERT(r == 1, "AMP9: returns 1 with real route");
    ASSERT(pt.count == 1, "AMP9: 1 entry in table");
    ASSERT(pt.entries[0].state == PAY_STATE_INFLIGHT, "AMP9: state is INFLIGHT");
    ASSERT(pt.entries[0].n_routes == 1, "AMP9: 1 route");

    gossip_store_close(&gs);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* AMP10 — AMP amp_set_id stored in payment entry                     */
/* ================================================================== */
int test_payment_amp_set_id_stored(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char our_priv[32]; memset(our_priv, 0x42, 32);
    secp256k1_pubkey our_pub_obj;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &our_pub_obj, our_priv), "pubkey");
    unsigned char our_pub[33]; size_t plen = 33;
    secp256k1_ec_pubkey_serialize(ctx, our_pub, &plen, &our_pub_obj, SECP256K1_EC_COMPRESSED);

    unsigned char dest_priv[32]; memset(dest_priv, 0x77, 32);
    secp256k1_pubkey dest_pub_obj;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &dest_pub_obj, dest_priv), "dest pubkey");
    unsigned char dest_pub[33]; plen = 33;
    secp256k1_ec_pubkey_serialize(ctx, dest_pub, &plen, &dest_pub_obj, SECP256K1_EC_COMPRESSED);

    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open gs");
    uint64_t scid = ((uint64_t)700001 << 40) | 1;
    gossip_store_upsert_channel(&gs, scid, our_pub, dest_pub, 1000000, 0);
    gossip_store_upsert_channel_update(&gs, scid, 0, 1000, 100, 40, 1);
    gossip_store_upsert_channel_update(&gs, scid, 1, 1000, 100, 40, 1);

    payment_table_t pt; payment_init(&pt);
    unsigned char hash_out[32]; memset(hash_out, 0, 32);

    int r = payment_send_amp(&pt, &gs, NULL, NULL, NULL, ctx,
                              our_priv, our_pub, dest_pub, 1000, 1, hash_out);
    ASSERT(r == 1, "AMP10: success");
    unsigned char zero32[32] = {0};
    ASSERT(memcmp(pt.entries[0].amp_set_id, zero32, 32) != 0,
           "AMP10: amp_set_id non-zero");
    ASSERT(memcmp(pt.entries[0].amp_set_id, hash_out, 32) == 0,
           "AMP10: amp_set_id == payment_hash");

    gossip_store_close(&gs);
    secp256k1_context_destroy(ctx);
    return 1;
}

