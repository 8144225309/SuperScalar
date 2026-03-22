/*
 * test_onion_msg_relay.c — Tests for multi-hop onion message relay
 *
 * PR #48: Onion Message Relay (BOLT #7 / BOLT #12 multi-hop forwarding)
 */

#include "superscalar/onion_msg_relay.h"
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

#define ASSERT_NC(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

static secp256k1_context *s_ctx = NULL;

static void make_privkey(unsigned char priv[32], unsigned char seed)
{
    memset(priv, seed, 32);
    priv[0] = 0x01; /* ensure scalar is non-zero */
}

static int make_pubkey(const unsigned char priv[32], unsigned char pub[33])
{
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(s_ctx, &pk, priv)) return 0;
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(s_ctx, pub, &len, &pk, SECP256K1_EC_COMPRESSED);
    return 1;
}

/* -----------------------------------------------------------------------
 * OMR1: relay_peel on single-hop final-hop packet → is_final=1, app data ok
 * --------------------------------------------------------------------- */
int test_omr_peel_final_hop(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char dest_priv[32], dest_pub[33], session_key[32];
    make_privkey(dest_priv, 0x42);
    ASSERT(make_pubkey(dest_priv, dest_pub), "dest pubkey");
    make_privkey(session_key, 0x7A);

    const char *payload = "omr1-test";
    unsigned char path_key[33], pkt[2048];
    size_t pkt_len = onion_msg_build(s_ctx, session_key, dest_pub,
                                      (const unsigned char *)payload, strlen(payload),
                                      ONION_MSG_TLV_INVOICE_REQUEST,
                                      path_key, pkt, sizeof(pkt));
    ASSERT(pkt_len > 0, "build ok");

    onion_msg_relay_result_t result;
    ASSERT(onion_msg_relay_peel(s_ctx, dest_priv, path_key, pkt, pkt_len, &result),
           "peel ok");
    ASSERT(result.is_final == 1, "is_final == 1");
    ASSERT(result.app_data_len == strlen(payload), "app_len matches");
    ASSERT(memcmp(result.app_data, payload, strlen(payload)) == 0, "app_data matches");
    ASSERT(result.app_tlv_type == ONION_MSG_TLV_INVOICE_REQUEST, "tlv_type=1");

    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * OMR2: relay_build_hop_payload produces TLV4 + TLV6
 * --------------------------------------------------------------------- */
int test_omr_build_hop_payload(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char next_node[33]; memset(next_node, 0x55, 33); next_node[0] = 0x02;
    unsigned char inner[20];     memset(inner, 0xAB, sizeof(inner));
    unsigned char out[256];

    size_t len = onion_msg_relay_build_hop_payload(next_node, inner, sizeof(inner),
                                                    out, sizeof(out));
    ASSERT(len > 0, "build_hop_payload ok");

    /* First byte should be TLV type 4 (NEXT_NODE) */
    ASSERT(out[0] == ONION_MSG_RELAY_TLV_NEXT_NODE, "TLV4 first");
    /* Second byte should be length 33 */
    ASSERT(out[1] == 33, "TLV4 len=33");
    /* Bytes 2..34 should be next_node_id */
    ASSERT(memcmp(out + 2, next_node, 33) == 0, "next_node_id matches");
    /* Byte 35 should be TLV type 6 (INNER_PKT) */
    ASSERT(out[35] == ONION_MSG_RELAY_TLV_INNER_PKT, "TLV6 after TLV4");

    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * OMR3: relay_peel on relay hop → is_final=0, next_node_id and inner_pkt set
 * --------------------------------------------------------------------- */
int test_omr_peel_relay_hop(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char relay_priv[32], relay_pub[33], session_key[32];
    unsigned char dest_pub[33];
    make_privkey(relay_priv, 0x11);
    ASSERT(make_pubkey(relay_priv, relay_pub), "relay pubkey");
    memset(dest_pub, 0x22, 33); dest_pub[0] = 0x02;
    make_privkey(session_key, 0x33);

    /* Build a fake inner packet */
    unsigned char inner_pkt[16]; memset(inner_pkt, 0xCC, sizeof(inner_pkt));

    /* Build relay hop payload */
    unsigned char relay_payload[256];
    size_t relay_payload_len = onion_msg_relay_build_hop_payload(
        dest_pub, inner_pkt, sizeof(inner_pkt), relay_payload, sizeof(relay_payload));
    ASSERT(relay_payload_len > 0, "relay payload built");

    /* Build outer packet using onion_msg_build with raw payload as data */
    /* We use the relay payload as the "app data" of type ONION_MSG_RELAY_TLV_NEXT_NODE=4 */
    /* But this won't work directly — use relay_build2 for proper nesting */
    /* For this test, use onion_msg_build with the raw TLV wrapped as type 0 */
    /* Instead, use relay_build2 with minimal dest_pub / app_data */
    unsigned char dest_priv[32];
    make_privkey(dest_priv, 0x44);
    ASSERT(make_pubkey(dest_priv, dest_pub), "dest pubkey");

    unsigned char sk_relay[32], sk_final[32];
    make_privkey(sk_relay, 0x55);
    make_privkey(sk_final, 0x66);

    unsigned char outer_path_key[33], outer_pkt[4096];
    const char *app = "relay-test";
    size_t outer_pkt_len = onion_msg_relay_build2(s_ctx, sk_relay, sk_final,
                                                    relay_pub, dest_pub,
                                                    (const unsigned char *)app, strlen(app),
                                                    ONION_MSG_TLV_INVOICE_REQUEST,
                                                    outer_path_key, outer_pkt, sizeof(outer_pkt));
    ASSERT(outer_pkt_len > 0, "relay_build2 ok");

    /* Relay node peels */
    onion_msg_relay_result_t result;
    ASSERT(onion_msg_relay_peel(s_ctx, relay_priv, outer_path_key, outer_pkt, outer_pkt_len,
                                 &result), "peel ok");
    ASSERT(result.is_final == 0, "is_final == 0 (relay hop)");
    ASSERT(memcmp(result.next_node_id, dest_pub, 33) == 0, "next_node_id = dest_pub");
    ASSERT(result.inner_pkt_len > 0, "inner_pkt present");

    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * OMR4: Full 2-hop relay: build2 → peel at relay → recv_final at dest
 * --------------------------------------------------------------------- */
int test_omr_full_2hop_roundtrip(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char relay_priv[32], relay_pub[33];
    unsigned char dest_priv[32],  dest_pub[33];
    unsigned char sk_relay[32],   sk_final[32];

    make_privkey(relay_priv, 0xAA);
    ASSERT(make_pubkey(relay_priv, relay_pub), "relay pub");
    make_privkey(dest_priv,  0xBB);
    ASSERT(make_pubkey(dest_priv,  dest_pub),  "dest pub");
    make_privkey(sk_relay, 0xCC);
    make_privkey(sk_final, 0xDD);

    const char *app = "hello-2hop";
    unsigned char outer_path_key[33], outer_pkt[4096];
    size_t outer_pkt_len = onion_msg_relay_build2(
        s_ctx, sk_relay, sk_final, relay_pub, dest_pub,
        (const unsigned char *)app, strlen(app),
        ONION_MSG_TLV_INVOICE_REQUEST,
        outer_path_key, outer_pkt, sizeof(outer_pkt));
    ASSERT(outer_pkt_len > 0, "build2 ok");

    /* Relay node peels outer layer */
    onion_msg_relay_result_t result;
    ASSERT(onion_msg_relay_peel(s_ctx, relay_priv, outer_path_key,
                                 outer_pkt, outer_pkt_len, &result), "peel ok");
    ASSERT(result.is_final == 0, "relay hop");
    ASSERT(result.inner_pkt_len > 0, "inner_pkt present");
    ASSERT(result.inner_pkt_len >= 67, "inner_pkt minimum size");

    /* Dest node decrypts inner packet.
     * The inner_pkt has the ephemeral key embedded at [1..33].
     * Extract it to use as path_key for recv_final. */
    ASSERT(result.inner_pkt[0] == 0x00, "inner version=0");
    unsigned char inner_path_key[33];
    memcpy(inner_path_key, result.inner_pkt + 1, 33);

    unsigned char app_out[128];
    size_t app_out_len = 0;
    uint64_t tlv_type = 0;
    ASSERT(onion_msg_recv_final(s_ctx, dest_priv, inner_path_key,
                                 result.inner_pkt, result.inner_pkt_len,
                                 app_out, sizeof(app_out),
                                 &app_out_len, &tlv_type), "recv_final ok");
    ASSERT(app_out_len == strlen(app), "app length preserved");
    ASSERT(memcmp(app_out, app, strlen(app)) == 0, "app content preserved");
    ASSERT(tlv_type == ONION_MSG_TLV_INVOICE_REQUEST, "tlv_type preserved");

    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * OMR5: HMAC tamper → relay_peel returns 0
 * --------------------------------------------------------------------- */
int test_omr_hmac_tamper(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char relay_priv[32], relay_pub[33], dest_priv[32], dest_pub[33];
    unsigned char sk_relay[32], sk_final[32];
    make_privkey(relay_priv, 0x11); make_pubkey(relay_priv, relay_pub);
    make_privkey(dest_priv,  0x22); make_pubkey(dest_priv,  dest_pub);
    make_privkey(sk_relay, 0x33);   make_privkey(sk_final, 0x44);

    unsigned char outer_path_key[33], outer_pkt[4096];
    const char *app = "hmac-test";
    size_t outer_pkt_len = onion_msg_relay_build2(
        s_ctx, sk_relay, sk_final, relay_pub, dest_pub,
        (const unsigned char *)app, strlen(app),
        ONION_MSG_TLV_INVOICE, outer_path_key, outer_pkt, sizeof(outer_pkt));
    ASSERT(outer_pkt_len > 0, "build ok");

    /* Tamper with the last byte (inside the HMAC) */
    outer_pkt[outer_pkt_len - 1] ^= 0xFF;

    onion_msg_relay_result_t result;
    ASSERT(!onion_msg_relay_peel(s_ctx, relay_priv, outer_path_key,
                                  outer_pkt, outer_pkt_len, &result),
           "tampered HMAC → peel fails");

    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * OMR6: relay_next_path_key changes the path_key deterministically
 * --------------------------------------------------------------------- */
int test_omr_next_path_key_changes(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char priv[32], path_key[33];
    make_privkey(priv, 0x55);
    /* path_key = priv * G */
    secp256k1_pubkey pk;
    secp256k1_ec_pubkey_create(s_ctx, &pk, priv);
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(s_ctx, path_key, &len, &pk, SECP256K1_EC_COMPRESSED);

    unsigned char next1[33], next2[33];
    ASSERT(onion_msg_relay_next_path_key(s_ctx, priv, path_key, next1), "next_path_key ok");
    ASSERT(onion_msg_relay_next_path_key(s_ctx, priv, path_key, next2), "next_path_key ok 2");

    /* Deterministic */
    ASSERT(memcmp(next1, next2, 33) == 0, "deterministic");

    /* Changed from original */
    ASSERT(memcmp(next1, path_key, 33) != 0, "next != original");

    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * OMR7: Different private keys → different next_path_keys
 * --------------------------------------------------------------------- */
int test_omr_next_path_key_key_domain(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char priv1[32], priv2[32];
    make_privkey(priv1, 0x11);
    make_privkey(priv2, 0x22);

    /* Use a real curve point as path_key */
    unsigned char path_key_priv[32], path_key[33];
    make_privkey(path_key_priv, 0x33);
    ASSERT(make_pubkey(path_key_priv, path_key), "path_key from privkey");

    unsigned char next1[33], next2[33];
    ASSERT(onion_msg_relay_next_path_key(s_ctx, priv1, path_key, next1), "priv1 ok");
    ASSERT(onion_msg_relay_next_path_key(s_ctx, priv2, path_key, next2), "priv2 ok");

    ASSERT(memcmp(next1, next2, 33) != 0, "different privkeys → different next_path_keys");

    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * OMR8: relay_build_hop_payload with inner_pkt too large → returns 0
 * --------------------------------------------------------------------- */
int test_omr_hop_payload_too_large(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char next_node[33]; memset(next_node, 0x02, 33);
    unsigned char huge_inner[4096]; memset(huge_inner, 0xAA, sizeof(huge_inner));
    unsigned char tiny_out[64]; /* too small for huge inner */

    size_t len = onion_msg_relay_build_hop_payload(next_node, huge_inner, sizeof(huge_inner),
                                                    tiny_out, sizeof(tiny_out));
    ASSERT(len == 0, "too-large inner → returns 0");

    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * OMR9: Wrong private key at relay node → HMAC failure
 * --------------------------------------------------------------------- */
int test_omr_wrong_relay_privkey(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char relay_priv[32], relay_pub[33], wrong_priv[32];
    unsigned char dest_priv[32], dest_pub[33];
    unsigned char sk_relay[32], sk_final[32];

    make_privkey(relay_priv, 0x77); make_pubkey(relay_priv, relay_pub);
    make_privkey(wrong_priv, 0x88); /* wrong key */
    make_privkey(dest_priv,  0x99); make_pubkey(dest_priv,  dest_pub);
    make_privkey(sk_relay, 0xAA);   make_privkey(sk_final, 0xBB);

    unsigned char outer_path_key[33], outer_pkt[4096];
    const char *app = "wrong-key";
    size_t outer_pkt_len = onion_msg_relay_build2(
        s_ctx, sk_relay, sk_final, relay_pub, dest_pub,
        (const unsigned char *)app, strlen(app),
        ONION_MSG_TLV_INVOICE, outer_path_key, outer_pkt, sizeof(outer_pkt));
    ASSERT(outer_pkt_len > 0, "build2 ok");

    onion_msg_relay_result_t result;
    ASSERT(!onion_msg_relay_peel(s_ctx, wrong_priv, outer_path_key,
                                  outer_pkt, outer_pkt_len, &result),
           "wrong privkey → HMAC fail");

    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * OMR10: relay_peel with truncated packet → returns 0
 * --------------------------------------------------------------------- */
int test_omr_peel_truncated(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char priv[32]; make_privkey(priv, 0x01);
    unsigned char path_key[33]; memset(path_key, 0x02, 33);

    /* Packet too short */
    unsigned char short_pkt[30]; memset(short_pkt, 0, sizeof(short_pkt));
    short_pkt[0] = 0x00; /* version */

    onion_msg_relay_result_t result;
    ASSERT(!onion_msg_relay_peel(s_ctx, priv, path_key, short_pkt, sizeof(short_pkt), &result),
           "truncated → 0");

    /* Empty packet */
    ASSERT(!onion_msg_relay_peel(s_ctx, priv, path_key, NULL, 0, &result),
           "NULL pkt → 0");

    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * OMR11: relay_build_hop_payload NULL inputs → returns 0
 * --------------------------------------------------------------------- */
int test_omr_build_hop_null_safety(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char node[33]; memset(node, 0x02, 33);
    unsigned char inner[8]; memset(inner, 0xAA, sizeof(inner));
    unsigned char out[256];

    ASSERT_NC(onion_msg_relay_build_hop_payload(NULL, inner, 8, out, sizeof(out)) == 0,
              "NULL node → 0");
    ASSERT_NC(onion_msg_relay_build_hop_payload(node, NULL, 8, out, sizeof(out)) == 0,
              "NULL inner → 0");
    ASSERT_NC(onion_msg_relay_build_hop_payload(node, inner, 8, NULL, sizeof(out)) == 0,
              "NULL out → 0");

    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * OMR12: relay_peel NULL inputs → returns 0
 * --------------------------------------------------------------------- */
int test_omr_peel_null_safety(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char priv[32], path_key[33], pkt[128];
    make_privkey(priv, 0x01);
    memset(path_key, 0x02, 33);
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x00;

    onion_msg_relay_result_t result;

    ASSERT(!onion_msg_relay_peel(NULL, priv, path_key, pkt, sizeof(pkt), &result),
           "NULL ctx → 0");
    ASSERT(!onion_msg_relay_peel(s_ctx, NULL, path_key, pkt, sizeof(pkt), &result),
           "NULL priv → 0");
    ASSERT(!onion_msg_relay_peel(s_ctx, priv, NULL, pkt, sizeof(pkt), &result),
           "NULL path_key → 0");
    ASSERT(!onion_msg_relay_peel(s_ctx, priv, path_key, NULL, sizeof(pkt), &result),
           "NULL pkt → 0");
    ASSERT(!onion_msg_relay_peel(s_ctx, priv, path_key, pkt, sizeof(pkt), NULL),
           "NULL result → 0");

    secp256k1_context_destroy(s_ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * OMR13: relay_next_path_key NULL inputs → returns 0
 * --------------------------------------------------------------------- */
int test_omr_next_path_key_null_safety(void)
{
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char priv[32], path_key[33], out[33];
    make_privkey(priv, 0x01);
    memset(path_key, 0x02, 33);

    ASSERT(!onion_msg_relay_next_path_key(NULL, priv, path_key, out),  "NULL ctx → 0");
    ASSERT(!onion_msg_relay_next_path_key(s_ctx, NULL, path_key, out), "NULL priv → 0");
    ASSERT(!onion_msg_relay_next_path_key(s_ctx, priv, NULL, out),     "NULL path_key → 0");
    ASSERT(!onion_msg_relay_next_path_key(s_ctx, priv, path_key, NULL),"NULL out → 0");

    secp256k1_context_destroy(s_ctx);
    return 1;
}
