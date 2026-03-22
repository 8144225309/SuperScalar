/*
 * test_onion_msg.c — Tests for BOLT #12 onion messages (type 513)
 *
 * PR #40: Onion Messages for BOLT #12 offer protocol
 */

#include "superscalar/onion_msg.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <secp256k1.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        secp256k1_context_destroy(s_ctx); \
        return 0; \
    } \
} while(0)

#define ASSERT_NOCTX(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

static secp256k1_context *s_ctx = NULL;

static void make_privkey(unsigned char priv[32], unsigned char seed)
{
    memset(priv, seed, 32);
    priv[0] = 0x01; /* ensure non-zero */
}

static int make_pubkey(const unsigned char priv[32], unsigned char pub[33])
{
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(s_ctx, &pk, priv)) return 0;
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(s_ctx, pub, &len, &pk, SECP256K1_EC_COMPRESSED);
    return 1;
}

/* OM1: Wire encode produces correct type 0x0201 */
int test_onion_msg_encode_type(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char path_key[33]; memset(path_key, 0x55, 33); path_key[0] = 0x02;
    unsigned char pkt[16]; memset(pkt, 0xAB, sizeof(pkt));
    unsigned char out[256];

    size_t len = onion_msg_encode(path_key, pkt, sizeof(pkt), out, sizeof(out));
    ASSERT(len == 2 + 33 + 2 + 16, "correct total length");
    ASSERT(out[0] == 0x02 && out[1] == 0x01, "type = 0x0201");
    ASSERT(out[2] == 0x02, "path_key compressed prefix");
    ASSERT(out[35] == 0x00 && out[36] == 16, "pkt_len=16");
    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* OM2: Wire decode roundtrip */
int test_onion_msg_decode_roundtrip(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char path_key[33]; memset(path_key, 0x33, 33); path_key[0] = 0x03;
    unsigned char pkt[20]; memset(pkt, 0xCC, sizeof(pkt));
    unsigned char wire[256];

    size_t wire_len = onion_msg_encode(path_key, pkt, sizeof(pkt), wire, sizeof(wire));
    ASSERT(wire_len > 0, "encode ok");

    unsigned char pk_out[33];
    const unsigned char *pkt_out = NULL;
    size_t pkt_out_len = 0;
    ASSERT(onion_msg_decode(wire, wire_len, pk_out, &pkt_out, &pkt_out_len), "decode ok");
    ASSERT(pkt_out_len == 20, "pkt_len preserved");
    ASSERT(memcmp(pk_out, path_key, 33) == 0, "path_key preserved");
    ASSERT(memcmp(pkt_out, pkt, 20) == 0, "packet bytes preserved");
    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* OM3: Wrong type rejected by decode */
int test_onion_msg_decode_wrong_type(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char msg[64]; memset(msg, 0, sizeof(msg));
    msg[0] = 0x00; msg[1] = 0x10; /* type = 16, not 513 */

    unsigned char pk_out[33];
    const unsigned char *pkt_out;
    size_t pkt_len;
    ASSERT(!onion_msg_decode(msg, sizeof(msg), pk_out, &pkt_out, &pkt_len),
           "wrong type rejected");
    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* OM4: Truncated message rejected by decode */
int test_onion_msg_decode_truncated(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    /* Less than minimum 37 bytes */
    unsigned char msg[30]; memset(msg, 0, sizeof(msg));
    msg[0] = 0x02; msg[1] = 0x01; /* type = 513 */

    unsigned char pk_out[33];
    const unsigned char *pkt_out;
    size_t pkt_len;
    ASSERT(!onion_msg_decode(msg, sizeof(msg), pk_out, &pkt_out, &pkt_len),
           "truncated msg rejected");
    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* OM5: Single-hop build + recv_final roundtrip */
int test_onion_msg_build_recv_roundtrip(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char dest_priv[32], dest_pub[33], session_key[32];
    make_privkey(dest_priv, 0x42);
    ASSERT(make_pubkey(dest_priv, dest_pub), "dest pubkey created");
    make_privkey(session_key, 0x7A);

    const char *msg = "hello onion message";
    size_t msg_len  = strlen(msg);

    unsigned char path_key[33];
    unsigned char pkt[2048];
    size_t pkt_len = onion_msg_build(s_ctx, session_key, dest_pub,
                                      (const unsigned char *)msg, msg_len,
                                      ONION_MSG_TLV_INVOICE_REQUEST,
                                      path_key, pkt, sizeof(pkt));
    ASSERT(pkt_len > 0, "build ok");

    unsigned char app_out[256];
    size_t app_len = 0;
    uint64_t tlv_type = 0;
    ASSERT(onion_msg_recv_final(s_ctx, dest_priv, path_key,
                                 pkt, pkt_len,
                                 app_out, sizeof(app_out),
                                 &app_len, &tlv_type),
           "recv_final ok");
    ASSERT(app_len == msg_len, "payload length preserved");
    ASSERT(memcmp(app_out, msg, msg_len) == 0, "payload content preserved");
    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* OM6: app_tlv_type preserved in roundtrip */
int test_onion_msg_tlv_type_preserved(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char dest_priv[32], dest_pub[33], session_key[32];
    make_privkey(dest_priv, 0x11);
    make_pubkey(dest_priv, dest_pub);
    make_privkey(session_key, 0x22);

    unsigned char data[10]; memset(data, 0xBE, sizeof(data));
    unsigned char path_key[33], pkt[2048];
    size_t pkt_len = onion_msg_build(s_ctx, session_key, dest_pub,
                                      data, sizeof(data),
                                      ONION_MSG_TLV_INVOICE,
                                      path_key, pkt, sizeof(pkt));
    ASSERT(pkt_len > 0, "build ok");

    unsigned char app_out[64];
    size_t app_len;
    uint64_t tlv_type;
    ASSERT(onion_msg_recv_final(s_ctx, dest_priv, path_key, pkt, pkt_len,
                                 app_out, sizeof(app_out), &app_len, &tlv_type),
           "recv ok");
    ASSERT(tlv_type == ONION_MSG_TLV_INVOICE, "tlv_type=2 (invoice) preserved");
    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* OM7: invoice_error TLV type preserved */
int test_onion_msg_invoice_error_type(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char dest_priv[32], dest_pub[33], session_key[32];
    make_privkey(dest_priv, 0x33);
    make_pubkey(dest_priv, dest_pub);
    make_privkey(session_key, 0x44);

    unsigned char data[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
    unsigned char path_key[33], pkt[2048];
    size_t pkt_len = onion_msg_build(s_ctx, session_key, dest_pub,
                                      data, sizeof(data),
                                      ONION_MSG_TLV_INVOICE_ERROR,
                                      path_key, pkt, sizeof(pkt));
    ASSERT(pkt_len > 0, "build ok");

    unsigned char app_out[64];
    size_t app_len;
    uint64_t tlv_type;
    ASSERT(onion_msg_recv_final(s_ctx, dest_priv, path_key, pkt, pkt_len,
                                 app_out, sizeof(app_out), &app_len, &tlv_type),
           "recv ok");
    ASSERT(tlv_type == ONION_MSG_TLV_INVOICE_ERROR, "tlv_type=3 preserved");
    ASSERT(app_len == 5 && memcmp(app_out, data, 5) == 0, "data preserved");
    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* OM8: Wrong private key in recv_final → HMAC failure */
int test_onion_msg_wrong_privkey(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char dest_priv[32], dest_pub[33], session_key[32];
    make_privkey(dest_priv, 0x55);
    make_pubkey(dest_priv, dest_pub);
    make_privkey(session_key, 0x66);

    unsigned char data[8]; memset(data, 0xAA, sizeof(data));
    unsigned char path_key[33], pkt[2048];
    size_t pkt_len = onion_msg_build(s_ctx, session_key, dest_pub,
                                      data, sizeof(data),
                                      ONION_MSG_TLV_INVOICE_REQUEST,
                                      path_key, pkt, sizeof(pkt));
    ASSERT(pkt_len > 0, "build ok");

    /* Use wrong private key */
    unsigned char wrong_priv[32];
    make_privkey(wrong_priv, 0x99);
    unsigned char app_out[64];
    size_t app_len;
    uint64_t tlv_type;
    ASSERT(!onion_msg_recv_final(s_ctx, wrong_priv, path_key, pkt, pkt_len,
                                  app_out, sizeof(app_out), &app_len, &tlv_type),
           "wrong priv → HMAC fail");
    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* OM9: Version byte ≠ 0 rejected */
int test_onion_msg_bad_version(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char dest_priv[32], dest_pub[33], session_key[32];
    make_privkey(dest_priv, 0x77);
    make_pubkey(dest_priv, dest_pub);
    make_privkey(session_key, 0x88);

    unsigned char data[4] = {1, 2, 3, 4};
    unsigned char path_key[33], pkt[2048];
    size_t pkt_len = onion_msg_build(s_ctx, session_key, dest_pub,
                                      data, sizeof(data),
                                      ONION_MSG_TLV_INVOICE,
                                      path_key, pkt, sizeof(pkt));
    ASSERT(pkt_len > 0, "build ok");

    /* Corrupt version byte */
    pkt[0] = 0x01;

    unsigned char app_out[64];
    size_t app_len;
    uint64_t tlv_type;
    ASSERT(!onion_msg_recv_final(s_ctx, dest_priv, path_key, pkt, pkt_len,
                                  app_out, sizeof(app_out), &app_len, &tlv_type),
           "bad version rejected");
    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* OM10: Full wire roundtrip (encode → decode → recv_final) */
int test_onion_msg_full_wire_roundtrip(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char dest_priv[32], dest_pub[33], session_key[32];
    make_privkey(dest_priv, 0xAA);
    make_pubkey(dest_priv, dest_pub);
    make_privkey(session_key, 0xBB);

    const char *payload = "invoice_request:lno1...";
    size_t payload_len  = strlen(payload);

    /* Build inner packet */
    unsigned char path_key[33], pkt[2048];
    size_t pkt_len = onion_msg_build(s_ctx, session_key, dest_pub,
                                      (const unsigned char *)payload, payload_len,
                                      ONION_MSG_TLV_INVOICE_REQUEST,
                                      path_key, pkt, sizeof(pkt));
    ASSERT(pkt_len > 0, "build ok");

    /* Encode wire frame */
    unsigned char wire[4096];
    size_t wire_len = onion_msg_encode(path_key, pkt, pkt_len, wire, sizeof(wire));
    ASSERT(wire_len > 0, "wire encode ok");

    /* Decode wire frame */
    unsigned char pk_out[33];
    const unsigned char *pkt_dec;
    size_t pkt_dec_len;
    ASSERT(onion_msg_decode(wire, wire_len, pk_out, &pkt_dec, &pkt_dec_len), "wire decode ok");
    ASSERT(pkt_dec_len == pkt_len, "pkt length matches");
    ASSERT(memcmp(pk_out, path_key, 33) == 0, "path_key matches");

    /* Decrypt final hop */
    unsigned char app_out[256];
    size_t app_len;
    uint64_t tlv_type;
    ASSERT(onion_msg_recv_final(s_ctx, dest_priv, pk_out, pkt_dec, pkt_dec_len,
                                 app_out, sizeof(app_out), &app_len, &tlv_type),
           "recv_final ok");
    ASSERT(app_len == payload_len, "payload len preserved");
    ASSERT(memcmp(app_out, payload, payload_len) == 0, "payload bytes preserved");
    ASSERT(tlv_type == ONION_MSG_TLV_INVOICE_REQUEST, "tlv_type preserved");
    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* OM11: NULL safety in encode */
int test_onion_msg_encode_null_safety(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char pk[33]; memset(pk, 0x02, 33);
    unsigned char pkt[10]; memset(pkt, 0, 10);
    unsigned char out[256];

    ASSERT(onion_msg_encode(NULL, pkt, 10, out, sizeof(out)) == 0, "NULL path_key");
    ASSERT(onion_msg_encode(pk, NULL, 10, out, sizeof(out)) == 0, "NULL pkt");
    ASSERT(onion_msg_encode(pk, pkt, 10, NULL, sizeof(out)) == 0, "NULL out");
    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* OM12: NULL safety in decode */
int test_onion_msg_decode_null_safety(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char msg[64]; memset(msg, 0, sizeof(msg));
    unsigned char pk[33];
    const unsigned char *pkt;
    size_t plen;

    ASSERT(!onion_msg_decode(NULL, 64, pk, &pkt, &plen), "NULL msg rejected");
    ASSERT(!onion_msg_decode(msg, 64, NULL, &pkt, &plen), "NULL pk_out rejected");
    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* OM13: NULL safety in build */
int test_onion_msg_build_null_safety(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char priv[32], pub[33], skey[32];
    make_privkey(priv, 0x01);
    make_pubkey(priv, pub);
    make_privkey(skey, 0x02);
    unsigned char data[4] = {1,2,3,4};
    unsigned char pk_out[33], pkt[2048];

    ASSERT(onion_msg_build(NULL, skey, pub, data, 4, 1, pk_out, pkt, sizeof(pkt)) == 0,
           "NULL ctx");
    ASSERT(onion_msg_build(s_ctx, NULL, pub, data, 4, 1, pk_out, pkt, sizeof(pkt)) == 0,
           "NULL session_key");
    ASSERT(onion_msg_build(s_ctx, skey, NULL, data, 4, 1, pk_out, pkt, sizeof(pkt)) == 0,
           "NULL dest_pub");
    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* OM14: Buffer too small in encode → 0 */
int test_onion_msg_encode_small_buf(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char pk[33]; memset(pk, 0x02, 33);
    unsigned char pkt[100]; memset(pkt, 0xAA, sizeof(pkt));
    unsigned char tiny[10];

    ASSERT(onion_msg_encode(pk, pkt, sizeof(pkt), tiny, sizeof(tiny)) == 0,
           "small buffer returns 0");
    secp256k1_context_destroy(s_ctx);
    return 1;
}
