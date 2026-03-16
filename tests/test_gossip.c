/*
 * test_gossip.c — Unit tests for BOLT #7 gossip message construction and gossip_store
 */

#include "superscalar/gossip.h"
#include "superscalar/gossip_store.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* Test G1: node_announcement build + verify round-trip */
int test_gossip_node_announcement_sign_verify(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "ctx");

    unsigned char priv[32];
    memset(priv, 0x11, 32);

    unsigned char rgb[3] = {0xFF, 0x80, 0x00};

    unsigned char buf[512];
    size_t len = gossip_build_node_announcement(
        buf, sizeof(buf), ctx, priv,
        1700000000, rgb, "TestNode", "1.2.3.4", 9735);
    ASSERT(len > 0, "build returned > 0");

    /* Type field must be 257 */
    uint16_t msg_type = ((uint16_t)buf[0] << 8) | buf[1];
    ASSERT(msg_type == 257, "type == 257 (node_announcement)");

    /* Signature is at bytes 2..65 — must not be all zeros */
    int all_zero = 1;
    for (int i = 2; i < 66; i++) if (buf[i]) { all_zero = 0; break; }
    ASSERT(!all_zero, "signature is not all zeros");

    /* Verify the signature */
    int ok = gossip_verify_node_announcement(ctx, buf, len);
    ASSERT(ok == 1, "verify_node_announcement succeeds");

    /* Tamper with a byte inside the signed region (after sig) and re-verify */
    buf[100] ^= 0x01;
    int bad = gossip_verify_node_announcement(ctx, buf, len);
    ASSERT(bad == 0, "tampered message fails verify");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test G2: channel_announcement_unsigned fields */
int test_gossip_channel_announcement_fields(void)
{
    unsigned char node1[33], node2[33], btc1[33], btc2[33];
    memset(node1, 0x02, 33);
    memset(node2, 0x03, 33);
    memset(btc1,  0x02, 33);
    memset(btc2,  0x03, 33);

    uint64_t scid = ((uint64_t)700000 << 40) | ((uint64_t)5 << 16) | 0;

    unsigned char buf[512];
    size_t len = gossip_build_channel_announcement_unsigned(
        buf, sizeof(buf),
        GOSSIP_CHAIN_HASH_MAINNET, scid,
        node1, node2, btc1, btc2);

    /* type(2) + 4×sig(64) + flen(2) + chain_hash(32) + scid(8) + 4×33 */
    size_t expected = 2 + 4*64 + 2 + 32 + 8 + 4*33;
    ASSERT(len == expected, "channel_announcement length correct");

    /* Type == 256 */
    uint16_t msg_type = ((uint16_t)buf[0] << 8) | buf[1];
    ASSERT(msg_type == 256, "type == 256 (channel_announcement)");

    /* All 4 signatures are zero (unsigned) */
    int all_zero = 1;
    for (int i = 2; i < 2 + 4*64; i++) if (buf[i]) { all_zero = 0; break; }
    ASSERT(all_zero, "all four signatures are zero (unsigned)");

    /* chain_hash starts at byte 2+4*64+2 = 260 */
    size_t ch_off = 2 + 4*64 + 2;
    ASSERT(memcmp(buf + ch_off, GOSSIP_CHAIN_HASH_MAINNET, 32) == 0,
           "chain_hash is mainnet");

    /* scid at byte 260+32 = 292 */
    size_t scid_off = ch_off + 32;
    uint64_t scid_read = 0;
    for (int i = 0; i < 8; i++)
        scid_read = (scid_read << 8) | buf[scid_off + i];
    ASSERT(scid_read == scid, "scid round-trips");

    /* node_id_1 at scid_off + 8 */
    ASSERT(memcmp(buf + scid_off + 8, node1, 33) == 0, "node_id_1 correct");

    return 1;
}

/* Test G3: channel_update construction and type */
int test_gossip_channel_update_construction(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "ctx");

    unsigned char priv[32];
    memset(priv, 0x22, 32);

    uint64_t scid = 0x000AE22000050000ULL;
    uint8_t  mflags = GOSSIP_UPDATE_MSGFLAG_HTLC_MAX;
    uint8_t  cflags = GOSSIP_UPDATE_CHANFLAG_DIRECTION; /* node2→node1 direction */

    unsigned char buf[256];
    size_t len = gossip_build_channel_update(
        buf, sizeof(buf), ctx, priv,
        GOSSIP_CHAIN_HASH_MAINNET, scid,
        1700000001, mflags, cflags,
        40,          /* cltv_expiry_delta */
        1000,        /* htlc_minimum_msat */
        1000,        /* fee_base_msat */
        100,         /* fee_proportional_millionths */
        1000000000   /* htlc_maximum_msat */
    );

    /* type(2) + sig(64) + chain(32) + scid(8) + ts(4) + mf(1) + cf(1) + cltv(2)
       + htlc_min(8) + fee_base(4) + fee_ppm(4) + htlc_max(8) = 138 */
    ASSERT(len == 138, "channel_update with htlc_max length == 138");

    uint16_t msg_type = ((uint16_t)buf[0] << 8) | buf[1];
    ASSERT(msg_type == 258, "type == 258 (channel_update)");

    /* Signature not all zeros */
    int all_zero = 1;
    for (int i = 2; i < 66; i++) if (buf[i]) { all_zero = 0; break; }
    ASSERT(!all_zero, "channel_update signature is non-zero");

    /* message_flags at offset 2+64+32+8+4 = 110 */
    ASSERT(buf[110] == mflags, "message_flags correct");
    ASSERT(buf[111] == cflags, "channel_flags correct");

    /* Without HTLC_MAX flag: length should be 130 */
    size_t len2 = gossip_build_channel_update(
        buf, sizeof(buf), ctx, priv,
        GOSSIP_CHAIN_HASH_MAINNET, scid,
        1700000002, 0, 0,
        40, 1000, 1000, 100, 0);
    ASSERT(len2 == 130, "channel_update without htlc_max length == 130");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test G4: gossip_store round-trip (node + channel + update) */
int test_gossip_store_roundtrip(void)
{
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open in-memory store");

    /* Insert a node */
    unsigned char pk1[33];
    memset(pk1, 0x02, 33);
    ASSERT(gossip_store_upsert_node(&gs, pk1, "NodeA", "10.0.0.1:9735", 1700000000),
           "upsert node");

    char alias[GOSSIP_STORE_ALIAS_MAX];
    char addr[GOSSIP_STORE_ADDR_MAX];
    uint32_t ts = 0;
    ASSERT(gossip_store_get_node(&gs, pk1, alias, sizeof(alias), addr, sizeof(addr), &ts),
           "get node found");
    ASSERT(strcmp(alias, "NodeA") == 0, "alias matches");
    ASSERT(strcmp(addr, "10.0.0.1:9735") == 0, "address matches");
    ASSERT(ts == 1700000000, "last_seen matches");

    /* Upsert a second node */
    unsigned char pk2[33];
    memset(pk2, 0x03, 33);
    ASSERT(gossip_store_upsert_node(&gs, pk2, "NodeB", NULL, 1700000001),
           "upsert second node");

    /* Insert a channel */
    uint64_t scid = 0x000AE22000050000ULL;
    ASSERT(gossip_store_upsert_channel(&gs, scid, pk1, pk2, 1000000, 1700000002),
           "upsert channel");

    unsigned char n1_out[33], n2_out[33];
    uint64_t cap = 0;
    uint32_t lu = 0;
    ASSERT(gossip_store_get_channel(&gs, scid, n1_out, n2_out, &cap, &lu),
           "get channel found");
    ASSERT(memcmp(n1_out, pk1, 33) == 0, "node1 pubkey matches");
    ASSERT(memcmp(n2_out, pk2, 33) == 0, "node2 pubkey matches");
    ASSERT(cap == 1000000, "capacity matches");
    ASSERT(lu == 1700000002, "last_update matches");

    /* Unknown channel returns 0 */
    unsigned char dummy[33];
    ASSERT(!gossip_store_get_channel(&gs, 0xDEADBEEF, dummy, dummy, NULL, NULL),
           "unknown scid returns 0");

    gossip_store_close(&gs);
    return 1;
}

/* Test G5: channel_update store round-trip + timestamp_filter message */
int test_gossip_channel_update_store_and_filter(void)
{
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open store");

    /* Seed channel so FK-like constraints pass (gossip_channel_updates has no FK) */
    uint64_t scid = 0x000AE22000050001ULL;

    ASSERT(gossip_store_upsert_channel_update(&gs, scid, 0,
           1000, 500, 40, 1700000010), "upsert update dir0");
    ASSERT(gossip_store_upsert_channel_update(&gs, scid, 1,
           2000, 800, 80, 1700000020), "upsert update dir1");

    uint32_t fb, fp;
    uint16_t cltv;
    uint32_t ts;

    ASSERT(gossip_store_get_channel_update(&gs, scid, 0, &fb, &fp, &cltv, &ts),
           "get update dir0");
    ASSERT(fb == 1000, "fee_base dir0");
    ASSERT(fp == 500,  "fee_ppm dir0");
    ASSERT(cltv == 40, "cltv_delta dir0");
    ASSERT(ts == 1700000010, "timestamp dir0");

    ASSERT(gossip_store_get_channel_update(&gs, scid, 1, &fb, &fp, &cltv, &ts),
           "get update dir1");
    ASSERT(fb == 2000, "fee_base dir1");
    ASSERT(fp == 800,  "fee_ppm dir1");
    ASSERT(cltv == 80, "cltv_delta dir1");

    /* Upsert overwrites */
    ASSERT(gossip_store_upsert_channel_update(&gs, scid, 0,
           5000, 1000, 50, 1700000099), "overwrite update dir0");
    ASSERT(gossip_store_get_channel_update(&gs, scid, 0, &fb, &fp, &cltv, &ts),
           "get overwritten");
    ASSERT(fb == 5000, "overwritten fee_base");
    ASSERT(ts == 1700000099, "overwritten timestamp");

    /* Verify gossip_timestamp_filter message */
    unsigned char buf[64];
    size_t len = gossip_build_timestamp_filter(
        buf, sizeof(buf), GOSSIP_CHAIN_HASH_MAINNET, 1700000000, 0xFFFFFFFF);
    /* type(2) + chain(32) + first_ts(4) + range(4) = 42 */
    ASSERT(len == 42, "timestamp_filter length == 42");
    uint16_t msg_type = ((uint16_t)buf[0] << 8) | buf[1];
    ASSERT(msg_type == 265, "type == 265 (timestamp_filter)");
    ASSERT(memcmp(buf + 2, GOSSIP_CHAIN_HASH_MAINNET, 32) == 0, "chain_hash in filter");

    gossip_store_close(&gs);
    return 1;
}
