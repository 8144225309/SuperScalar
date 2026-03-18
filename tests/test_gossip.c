/*
 * test_gossip.c — Unit tests for BOLT #7 gossip message construction and gossip_store
 */

#include "superscalar/gossip.h"
#include "superscalar/gossip_store.h"
#include "superscalar/ln_dispatch.h"
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

/* ================================================================== */
/* GQ1 — parse query_short_channel_ids (type 261)                     */
/* ================================================================== */
int test_gossip_parse_query_scids(void)
{
    /* type(2) + chain_hash(32) + encoded_len(2) + encoding_type(1) + scids(2*8) */
    unsigned char msg[2 + 32 + 2 + 1 + 16];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0x01; msg[1] = 0x05; /* type 261 */
    /* chain_hash: zeros */
    /* encoded_len = 17 (1 + 2*8) */
    msg[34] = 0; msg[35] = 17;
    msg[36] = 0x00; /* encoding_type = uncompressed */
    /* scid1 = 0x0102030405060708 */
    msg[37]=0x01; msg[38]=0x02; msg[39]=0x03; msg[40]=0x04;
    msg[41]=0x05; msg[42]=0x06; msg[43]=0x07; msg[44]=0x08;
    /* scid2 = 0x0102030405060709 */
    msg[45]=0x01; msg[46]=0x02; msg[47]=0x03; msg[48]=0x04;
    msg[49]=0x05; msg[50]=0x06; msg[51]=0x07; msg[52]=0x09;
    uint64_t scids[10];
    int n = gossip_parse_query_scids(msg, sizeof(msg), NULL, scids, 10);
    ASSERT(n == 2, "GQ1: 2 SCIDs parsed");
    ASSERT(scids[0] == 0x0102030405060708ULL, "GQ1: scid[0] correct");
    ASSERT(scids[1] == 0x0102030405060709ULL, "GQ1: scid[1] correct");
    return 1;
}

/* ================================================================== */
/* GQ2 — build reply_short_channel_ids_end (type 262)                 */
/* ================================================================== */
int test_gossip_build_reply_scids_end(void)
{
    unsigned char buf[64];
    size_t len = gossip_build_reply_scids_end(buf, sizeof(buf),
                                               GOSSIP_CHAIN_HASH_MAINNET, 1);
    ASSERT(len == 35, "GQ2: length == 35");
    uint16_t t = ((uint16_t)buf[0] << 8) | buf[1];
    ASSERT(t == 262, "GQ2: type == 262");
    ASSERT(memcmp(buf + 2, GOSSIP_CHAIN_HASH_MAINNET, 32) == 0, "GQ2: chain_hash matches");
    ASSERT(buf[34] == 1, "GQ2: complete == 1");
    return 1;
}

/* ================================================================== */
/* GQ3 — parse query_channel_range (type 263)                         */
/* ================================================================== */
int test_gossip_parse_query_range(void)
{
    unsigned char msg[42];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0x01; msg[1] = 0x07; /* type 263 */
    /* chain_hash zeros */
    /* first_blocknum = 700000 = 0x000AAE60 */
    msg[34] = 0x00; msg[35] = 0x0A; msg[36] = 0xAE; msg[37] = 0x60;
    /* num_blocks = 1000 = 0x000003E8 */
    msg[38] = 0x00; msg[39] = 0x00; msg[40] = 0x03; msg[41] = 0xE8;

    unsigned char ch32[32];
    uint32_t first_block = 0, num_blocks = 0;
    int r = gossip_parse_query_range(msg, sizeof(msg), ch32, &first_block, &num_blocks);
    ASSERT(r == 1, "GQ3: parse succeeded");
    ASSERT(first_block == 700000, "GQ3: first_blocknum == 700000");
    ASSERT(num_blocks == 1000, "GQ3: num_blocks == 1000");
    return 1;
}

/* ================================================================== */
/* GQ4 — build reply_channel_range (type 264)                         */
/* ================================================================== */
int test_gossip_build_reply_range(void)
{
    uint64_t scids[2] = {0xABCDEF0012345678ULL, 0x0000001000020000ULL};
    unsigned char buf[256];
    size_t len = gossip_build_reply_range(buf, sizeof(buf),
                                           GOSSIP_CHAIN_HASH_MAINNET,
                                           700000, 1000,
                                           scids, 2, 1);
    /* type(2)+chain(32)+first_block(4)+num_blocks(4)+complete(1)+enc_len(2)+enc_type(1)+2*8 */
    size_t expected = 2 + 32 + 4 + 4 + 1 + 2 + 1 + 16;
    ASSERT(len == expected, "GQ4: length correct");
    uint16_t t = ((uint16_t)buf[0] << 8) | buf[1];
    ASSERT(t == 264, "GQ4: type == 264");
    ASSERT(buf[42] == 1, "GQ4: complete == 1");
    /* Parse back first SCID */
    uint64_t s = 0;
    for (int i = 0; i < 8; i++) s = (s << 8) | buf[46 + i];
    ASSERT(s == scids[0], "GQ4: scid[0] roundtrips");
    return 1;
}

/* ================================================================== */
/* GQ5 — gossip_store get_channels_by_scids found / not found         */
/* ================================================================== */
static uint64_t g_bysc_scid = 0;
static int g_bysc_count = 0;
static void bysc_cb(uint64_t scid, const unsigned char *n1, const unsigned char *n2, void *ud)
{
    (void)n1; (void)n2; (void)ud;
    g_bysc_scid = scid;
    g_bysc_count++;
}
int test_gossip_store_get_channels_by_scids(void)
{
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open store");

    unsigned char pk1[33], pk2[33];
    memset(pk1, 0x02, 33); memset(pk2, 0x03, 33);
    uint64_t scid = 0x000100020003ULL;
    gossip_store_upsert_channel(&gs, scid, pk1, pk2, 1000000, 1700000000);

    g_bysc_count = 0;
    g_bysc_scid = 0;
    int n = gossip_store_get_channels_by_scids(&gs, &scid, 1, bysc_cb, NULL);
    ASSERT(n == 1, "GQ5: found 1 channel");
    ASSERT(g_bysc_scid == scid, "GQ5: correct scid returned");

    /* Not found */
    uint64_t missing = 0xDEADBEEFULL;
    g_bysc_count = 0;
    int m = gossip_store_get_channels_by_scids(&gs, &missing, 1, bysc_cb, NULL);
    ASSERT(m == 0, "GQ5: missing scid returns 0");

    gossip_store_close(&gs);
    return 1;
}

/* Simple accumulator callback for range test */
static uint64_t g_range_scids[64];
static int g_range_count = 0;
static void range_cb(uint64_t scid, const unsigned char *n1, const unsigned char *n2, void *ud)
{
    (void)n1; (void)n2; (void)ud;
    if (g_range_count < 64) g_range_scids[g_range_count++] = scid;
}

/* ================================================================== */
/* GQ6 — gossip_store get_channels_in_range                           */
/* ================================================================== */
int test_gossip_store_get_channels_in_range(void)
{
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open store");

    unsigned char pk1[33], pk2[33];
    memset(pk1, 0x02, 33); memset(pk2, 0x03, 33);
    /* block 700 = 0x2BC, SCID = (700 << 40) | tx<<16 | out */
    uint64_t scid1 = ((uint64_t)700 << 40) | (1 << 16) | 0;
    uint64_t scid2 = ((uint64_t)800 << 40) | (1 << 16) | 0; /* outside range */
    gossip_store_upsert_channel(&gs, scid1, pk1, pk2, 1000000, 1700000000);
    gossip_store_upsert_channel(&gs, scid2, pk1, pk2, 1000000, 1700000000);

    g_range_count = 0;
    int n = gossip_store_get_channels_in_range(&gs, 600, 200, range_cb, NULL);
    ASSERT(n == 1, "GQ6: one channel in range [600,800)");
    ASSERT(g_range_scids[0] == scid1, "GQ6: correct scid");

    gossip_store_close(&gs);
    return 1;
}

/* ================================================================== */
/* GQ7 — gossip_store get_channels_in_range empty                     */
/* ================================================================== */
int test_gossip_store_range_empty(void)
{
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open store");

    g_range_count = 0;
    int n = gossip_store_get_channels_in_range(&gs, 0, 1000000, range_cb, NULL);
    ASSERT(n == 0, "GQ7: empty store returns 0");
    gossip_store_close(&gs);
    return 1;
}

/* ================================================================== */
/* GQ8 — dispatch type 261 (query_scids) no gs → returns 261 no crash */
/* ================================================================== */
int test_ln_dispatch_routes_query_scids(void)
{
    /* Build minimal query_scids: type(2)+chain(32)+enc_len(2)+enc_type(1)+no scids */
    unsigned char msg[37];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0x01; msg[1] = 0x05; /* type 261 */
    msg[35] = 1; /* enc_len = 1 (just encoding type, no scids) */
    msg[36] = 0x00;
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.gs = NULL; /* no gs */
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 261, "GQ8: type 261 routes correctly");
    return 1;
}

/* ================================================================== */
/* GQ9 — dispatch type 263 (query_range) no gs → returns 263          */
/* ================================================================== */
int test_ln_dispatch_routes_query_range(void)
{
    unsigned char msg[42];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0x01; msg[1] = 0x07; /* type 263 */
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.gs = NULL;
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 263, "GQ9: type 263 routes correctly");
    return 1;
}

/* ================================================================== */
/* GQ10 — dispatch type 264 (reply_range) → returns 264               */
/* ================================================================== */
int test_ln_dispatch_routes_reply_range(void)
{
    unsigned char msg[50];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0x01; msg[1] = 0x08; /* type 264 */
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 264, "GQ10: type 264 routes correctly");
    return 1;
}

/* ================================================================== */
/* GQ11 — dispatch type 261 with NULL gs doesn't crash                */
/* ================================================================== */
int test_ln_dispatch_gossip_no_gs_no_crash(void)
{
    unsigned char msg[37];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0x01; msg[1] = 0x05;
    msg[35] = 1; msg[36] = 0x00;
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    /* gs = NULL, pmgr = NULL */
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 261, "GQ11: no crash without gs");
    return 1;
}

/* ================================================================== */
/* GQ12 — parse query_scids: too short returns -1                     */
/* ================================================================== */
int test_gossip_parse_query_scids_too_short(void)
{
    unsigned char msg[10]; memset(msg, 0, sizeof(msg));
    msg[0] = 0x01; msg[1] = 0x05;
    int n = gossip_parse_query_scids(msg, sizeof(msg), NULL, NULL, 0);
    ASSERT(n == -1, "GQ12: too short returns -1");
    return 1;
}

/* ================================================================== */
/* GQ13 — build reply_scids_end with complete=0                       */
/* ================================================================== */
int test_gossip_build_reply_scids_end_incomplete(void)
{
    unsigned char buf[64];
    size_t len = gossip_build_reply_scids_end(buf, sizeof(buf), NULL, 0);
    ASSERT(len == 35, "GQ13: length == 35");
    ASSERT(buf[34] == 0, "GQ13: complete == 0");
    return 1;
}

/* ================================================================== */
/* GQ14 — parse query_range: too short returns 0                      */
/* ================================================================== */
int test_gossip_parse_query_range_too_short(void)
{
    unsigned char msg[20]; memset(msg, 0, sizeof(msg));
    msg[0] = 0x01; msg[1] = 0x07;
    int r = gossip_parse_query_range(msg, sizeof(msg), NULL, NULL, NULL);
    ASSERT(r == 0, "GQ14: too short returns 0");
    return 1;
}

/* ================================================================== */
/* GQ15 — channel_announcement for SCID in gossip store has type 256  */
/* ================================================================== */
int test_gossip_query_scids_real_data(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char priv1[32]; memset(priv1, 0x11, 32);
    unsigned char priv2[32]; memset(priv2, 0x22, 32);
    secp256k1_pubkey pk1, pk2;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &pk1, priv1), "pk1");
    ASSERT(secp256k1_ec_pubkey_create(ctx, &pk2, priv2), "pk2");
    unsigned char node1[33], node2[33]; size_t plen = 33;
    secp256k1_ec_pubkey_serialize(ctx, node1, &plen, &pk1, SECP256K1_EC_COMPRESSED);
    plen = 33;
    secp256k1_ec_pubkey_serialize(ctx, node2, &plen, &pk2, SECP256K1_EC_COMPRESSED);

    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open gs");
    uint64_t scid = ((uint64_t)700100 << 40) | 1;
    gossip_store_upsert_channel(&gs, scid, node1, node2, 500000, 0);
    gossip_store_upsert_channel_update(&gs, scid, 0, 1000, 200, 40, 1);
    gossip_store_upsert_channel_update(&gs, scid, 1, 1000, 200, 40, 1);

    /* Verify channel_announcement builder produces type 256 */
    /* type(2)+4*sig(64)+flen(2)+chain(32)+scid(8)+4*key(33)=432 bytes */
    unsigned char ann[512];
    size_t ann_len = gossip_build_channel_announcement_unsigned(
        ann, sizeof(ann), GOSSIP_CHAIN_HASH_MAINNET, scid, node1, node2, node1, node2);
    ASSERT(ann_len > 0, "GQ15: announcement built");
    uint16_t ann_type = ((uint16_t)ann[0] << 8) | ann[1];
    ASSERT(ann_type == 256, "GQ15: type is 256");

    /* Verify channel_update builder produces type 258 */
    unsigned char upd[160];
    size_t upd_len = gossip_build_channel_update(
        upd, sizeof(upd), ctx, priv1, GOSSIP_CHAIN_HASH_MAINNET, scid,
        1, GOSSIP_UPDATE_MSGFLAG_HTLC_MAX, 0, 40, 1, 1000, 200, 0);
    ASSERT(upd_len > 0, "GQ15: channel_update built");
    uint16_t upd_type = ((uint16_t)upd[0] << 8) | upd[1];
    ASSERT(upd_type == 258, "GQ15: type is 258");

    gossip_store_close(&gs);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* GQ16 — reply_channel_range with real SCIDs has type 264            */
/* ================================================================== */
int test_gossip_query_range_real_scids(void)
{
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open gs");

    unsigned char n1[33]; memset(n1, 0x02, 33); n1[1] = 0xAA;
    unsigned char n2[33]; memset(n2, 0x03, 33); n2[1] = 0xBB;
    uint64_t scid = ((uint64_t)700200 << 40) | 2;
    gossip_store_upsert_channel(&gs, scid, n1, n2, 100000, 0);

    /* Verify channel is retrievable by range */
    unsigned char node1_out[33], node2_out[33];
    uint64_t cap; uint32_t ts;
    int r = gossip_store_get_channel(&gs, scid, node1_out, node2_out, &cap, &ts);
    ASSERT(r == 1, "GQ16: channel found");
    ASSERT(cap == 100000, "GQ16: capacity correct");

    /* Build reply_range with SCID and verify type 264 */
    uint64_t scids_out[1] = {scid};
    unsigned char reply[128];
    size_t rlen = gossip_build_reply_range(reply, sizeof(reply),
        GOSSIP_CHAIN_HASH_MAINNET, 700000, 1000, scids_out, 1, 1);
    ASSERT(rlen > 0, "GQ16: reply_range built");
    uint16_t rtype = ((uint16_t)reply[0] << 8) | reply[1];
    ASSERT(rtype == 264, "GQ16: type is 264");

    gossip_store_close(&gs);
    return 1;
}
