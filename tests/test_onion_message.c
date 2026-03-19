/*
 * test_onion_message.c — PR #29 Onion Messages + BOLT #12 Production Path
 *
 * OM1:  test_onion_msg_parse_valid        — parse valid type-513 wire bytes
 * OM2:  test_onion_msg_parse_bad_type     — wrong type prefix returns 0
 * OM3:  test_onion_msg_parse_too_short    — truncated buffer returns 0
 * OM4:  test_onion_msg_build_and_parse    — build → parse → same blinding_point
 * OM5:  test_onion_msg_decrypt_roundtrip  — build → decrypt → payload matches
 * OM6:  test_onion_msg_dispatch_type513   — ln_dispatch type 513 returns 0x0201
 * OM7:  test_onion_msg_dispatch_short     — type 513 too short returns -1
 * OFR1: test_offer_create_node_id         — offer_create → node_id matches pubkey
 * OFR2: test_offer_create_encode_lno      — offer_create + encode → starts "lno1"
 * OFR3: test_offer_create_with_amount     — has_amount==1, amount_msat set
 * OFR4: test_offer_create_no_amount       — amount_msat=0 → has_amount==0
 * AR21: test_admin_rpc_createoffer_lno    — createoffer → offer starts with "lno1"
 */

#include "superscalar/onion_message.h"
#include "superscalar/bolt12.h"
#include "superscalar/ln_dispatch.h"
#include "superscalar/admin_rpc.h"
#include "superscalar/fee_estimator.h"
#include <secp256k1.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

static secp256k1_context *make_ctx(void)
{
    return secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

/* Derive compressed pubkey from a 32-byte secret */
static int derive_pubkey(secp256k1_context *ctx, const unsigned char sk[32],
                          unsigned char pk33[33])
{
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(ctx, &pub, sk)) return 0;
    size_t plen = 33;
    secp256k1_ec_pubkey_serialize(ctx, pk33, &plen, &pub, SECP256K1_EC_COMPRESSED);
    return 1;
}

/* Build a minimal type-513 wire buffer manually for parse tests */
static size_t make_type513(unsigned char *buf, size_t cap,
                            const unsigned char blinding[33],
                            const unsigned char *onion, uint16_t onion_len)
{
    if (cap < (size_t)(2 + 33 + 2 + onion_len)) return 0;
    buf[0] = 0x02; buf[1] = 0x01;
    memcpy(buf + 2, blinding, 33);
    buf[35] = (unsigned char)(onion_len >> 8);
    buf[36] = (unsigned char)(onion_len);
    if (onion && onion_len > 0) memcpy(buf + 37, onion, onion_len);
    return 2 + 33 + 2 + onion_len;
}

/* ------------------------------------------------------------------ */
/* Onion message parse/build tests                                     */
/* ------------------------------------------------------------------ */

int test_onion_msg_parse_valid(void)
{
    unsigned char blinding[33];
    memset(blinding, 0x02, 33);
    blinding[0] = 0x02; /* valid compressed pubkey prefix */

    unsigned char onion_data[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    unsigned char buf[128];
    size_t blen = make_type513(buf, sizeof(buf), blinding, onion_data, 8);
    ASSERT(blen == 37 + 8, "OM1: expected wire length");

    onion_msg_t msg;
    int r = onion_msg_parse(buf, blen, &msg);
    ASSERT(r == 1, "OM1: parse returns 1");
    ASSERT(memcmp(msg.blinding_point, blinding, 33) == 0, "OM1: blinding_point matches");
    ASSERT(msg.onion_len == 8, "OM1: onion_len == 8");
    ASSERT(memcmp(msg.onion_bytes, onion_data, 8) == 0, "OM1: onion_bytes match");
    return 1;
}

int test_onion_msg_parse_bad_type(void)
{
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x00; buf[1] = 0x80; /* type 128, not 513 */
    buf[35] = 0x00; buf[36] = 0x08;

    onion_msg_t msg;
    int r = onion_msg_parse(buf, sizeof(buf), &msg);
    ASSERT(r == 0, "OM2: wrong type returns 0");
    return 1;
}

int test_onion_msg_parse_too_short(void)
{
    unsigned char buf[10];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x02; buf[1] = 0x01;

    onion_msg_t msg;
    int r = onion_msg_parse(buf, sizeof(buf), &msg); /* only 10 bytes, need ≥37 */
    ASSERT(r == 0, "OM3: too short returns 0");
    return 1;
}

int test_onion_msg_build_and_parse(void)
{
    secp256k1_context *ctx = make_ctx();
    ASSERT(ctx != NULL, "OM4: secp context");

    /* Recipient key */
    unsigned char dest_sk[32], dest_pk[33];
    memset(dest_sk, 0x44, 32);
    ASSERT(derive_pubkey(ctx, dest_sk, dest_pk), "OM4: derive dest_pk");

    /* Session key */
    unsigned char session_key[32];
    memset(session_key, 0x55, 32);

    const unsigned char payload[] = "hello onion world";
    unsigned char out[512];
    size_t out_len = onion_msg_build(ctx, dest_pk, payload, sizeof(payload) - 1,
                                     session_key, out, sizeof(out));
    ASSERT(out_len > 37, "OM4: build returns > 37 bytes");

    /* Verify type */
    ASSERT(out[0] == 0x02 && out[1] == 0x01, "OM4: type 513 prefix");

    /* Parse the built message */
    onion_msg_t msg;
    ASSERT(onion_msg_parse(out, out_len, &msg) == 1, "OM4: parse built msg");

    /* blinding_point should be session_key * G */
    secp256k1_pubkey ephem;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &ephem, session_key), "OM4: ephem");
    unsigned char expected_bp[33]; size_t bplen = 33;
    secp256k1_ec_pubkey_serialize(ctx, expected_bp, &bplen, &ephem, SECP256K1_EC_COMPRESSED);
    ASSERT(memcmp(msg.blinding_point, expected_bp, 33) == 0, "OM4: blinding_point matches session_key*G");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_onion_msg_decrypt_roundtrip(void)
{
    secp256k1_context *ctx = make_ctx();
    ASSERT(ctx != NULL, "OM5: secp context");

    unsigned char dest_sk[32], dest_pk[33];
    memset(dest_sk, 0x77, 32);
    ASSERT(derive_pubkey(ctx, dest_sk, dest_pk), "OM5: derive dest_pk");

    unsigned char session_key[32];
    memset(session_key, 0x88, 32);

    const char *original = "invoice_request_bytes";
    size_t orig_len = strlen(original);

    unsigned char wire[512];
    size_t wire_len = onion_msg_build(ctx, dest_pk,
                                      (const unsigned char *)original, orig_len,
                                      session_key, wire, sizeof(wire));
    ASSERT(wire_len > 0, "OM5: build succeeds");

    /* Parse */
    onion_msg_t msg;
    ASSERT(onion_msg_parse(wire, wire_len, &msg) == 1, "OM5: parse succeeds");

    /* Decrypt at recipient using dest_sk */
    unsigned char recovered[512];
    size_t rec_len = onion_msg_decrypt_final(&msg, ctx, dest_sk,
                                              recovered, sizeof(recovered));
    ASSERT(rec_len == orig_len, "OM5: recovered length matches");
    ASSERT(memcmp(recovered, original, orig_len) == 0, "OM5: payload round-trips");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_onion_msg_dispatch_type513(void)
{
    /* Build a valid type-513 message */
    unsigned char blinding[33];
    memset(blinding, 0x03, 33);
    unsigned char onion_bytes[8] = {0};
    unsigned char buf[128];
    size_t blen = make_type513(buf, sizeof(buf), blinding, onion_bytes, 8);

    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));

    int r = ln_dispatch_process_msg(&d, 0, buf, blen);
    ASSERT(r == 0x0201, "OM6: type 513 dispatch returns 0x0201 (513)");
    return 1;
}

int test_onion_msg_dispatch_short(void)
{
    /* Too-short type-513 message (only 5 bytes) */
    unsigned char buf[5] = {0x02, 0x01, 0x00, 0x00, 0x00};

    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));

    int r = ln_dispatch_process_msg(&d, 0, buf, sizeof(buf));
    ASSERT(r == -1, "OM7: short type-513 returns -1");
    return 1;
}

/* ------------------------------------------------------------------ */
/* Offer creation tests                                                */
/* ------------------------------------------------------------------ */

int test_offer_create_node_id(void)
{
    secp256k1_context *ctx = make_ctx();
    ASSERT(ctx, "OFR1: ctx");

    unsigned char sk[32], pk[33];
    memset(sk, 0x11, 32);
    ASSERT(derive_pubkey(ctx, sk, pk), "OFR1: derive pk");

    offer_t o;
    int r = offer_create(&o, ctx, sk, pk, 1000, "test", 0);
    ASSERT(r == 1, "OFR1: offer_create returns 1");
    ASSERT(memcmp(o.node_id, pk, 33) == 0, "OFR1: node_id == our pubkey");
    ASSERT(memcmp(o.signing_key, sk, 32) == 0, "OFR1: signing_key stored");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_offer_create_encode_lno(void)
{
    secp256k1_context *ctx = make_ctx();
    ASSERT(ctx, "OFR2: ctx");

    unsigned char sk[32], pk[33];
    memset(sk, 0x22, 32);
    ASSERT(derive_pubkey(ctx, sk, pk), "OFR2: derive pk");

    offer_t o;
    ASSERT(offer_create(&o, ctx, sk, pk, 5000, "pay me", 0) == 1, "OFR2: create");

    char bech32m[512];
    ASSERT(offer_encode(&o, bech32m, sizeof(bech32m)) == 1, "OFR2: encode");
    ASSERT(strncmp(bech32m, "lno1", 4) == 0, "OFR2: starts with lno1");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_offer_create_with_amount(void)
{
    secp256k1_context *ctx = make_ctx();
    ASSERT(ctx, "OFR3: ctx");

    unsigned char sk[32], pk[33];
    memset(sk, 0x33, 32);
    ASSERT(derive_pubkey(ctx, sk, pk), "OFR3: derive pk");

    offer_t o;
    offer_create(&o, ctx, sk, pk, 21000, "21k sats", 0);
    ASSERT(o.has_amount   == 1,     "OFR3: has_amount set");
    ASSERT(o.amount_msat  == 21000, "OFR3: amount_msat stored");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_offer_create_no_amount(void)
{
    secp256k1_context *ctx = make_ctx();
    ASSERT(ctx, "OFR4: ctx");

    unsigned char sk[32], pk[33];
    memset(sk, 0x44, 32);
    ASSERT(derive_pubkey(ctx, sk, pk), "OFR4: derive pk");

    offer_t o;
    offer_create(&o, ctx, sk, pk, 0, "any amount", 0);
    ASSERT(o.has_amount == 0, "OFR4: has_amount == 0 for any-amount offer");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Admin RPC createoffer test                                          */
/* ------------------------------------------------------------------ */

int test_admin_rpc_createoffer_lno(void)
{
    secp256k1_context *ctx = make_ctx();
    ASSERT(ctx, "AR21: ctx");

    unsigned char sk[32];
    memset(sk, 0xAA, 32);

    admin_rpc_t rpc;
    memset(&rpc, 0, sizeof(rpc));
    rpc.ctx = ctx;
    memcpy(rpc.node_privkey, sk, 32);

    const char *req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"createoffer\","
                      "\"params\":{\"amount_msat\":1000,\"description\":\"test offer\"}}";
    char resp[1024];
    size_t n = admin_rpc_handle_request(&rpc, req, resp, sizeof(resp));
    ASSERT(n > 0, "AR21: handle_request returns > 0");

    /* Response should contain "lno1" in the offer field */
    ASSERT(strstr(resp, "lno1") != NULL, "AR21: response contains lno1 offer string");
    ASSERT(strstr(resp, "error") == NULL || strstr(resp, "\"result\"") != NULL,
           "AR21: response is a result, not error");

    secp256k1_context_destroy(ctx);
    return 1;
}
