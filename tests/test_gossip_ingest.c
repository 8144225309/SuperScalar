/*
 * test_gossip_ingest.c — Tests for BOLT #7 gossip ingest pipeline
 *
 * PR #45: Gossip Ingest (verify + store incoming types 256/257/258/265)
 */

#include "superscalar/gossip_ingest.h"
#include "superscalar/gossip.h"
#include "superscalar/gossip_store.h"
#include "superscalar/sha256.h"
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

#define NOW  1700000000u

/* -----------------------------------------------------------------------
 * Helper: derive compressed pubkey from private key
 * --------------------------------------------------------------------- */
static void make_pubkey(secp256k1_context *ctx,
                         const unsigned char priv[32],
                         unsigned char pub33[33])
{
    secp256k1_pubkey pk;
    secp256k1_ec_pubkey_create(ctx, &pk, priv);
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, pub33, &len, &pk,
                                   SECP256K1_EC_COMPRESSED);
}

/* -----------------------------------------------------------------------
 * Helper: build a fully signed channel_announcement (type 256)
 *
 * channel_announcement signed data = SHA256(SHA256(type(2) || msg[258..]))
 * All 4 sigs are at offsets 2, 66, 130, 194.
 * --------------------------------------------------------------------- */
static size_t build_signed_channel_ann(secp256k1_context *ctx,
                                        unsigned char *out, size_t cap,
                                        const unsigned char node1_priv[32],
                                        const unsigned char node2_priv[32],
                                        const unsigned char btc1_priv[32],
                                        const unsigned char btc2_priv[32],
                                        uint64_t scid)
{
    unsigned char n1[33], n2[33], b1[33], b2[33];
    make_pubkey(ctx, node1_priv, n1);
    make_pubkey(ctx, node2_priv, n2);
    make_pubkey(ctx, btc1_priv,  b1);
    make_pubkey(ctx, btc2_priv,  b2);

    size_t len = gossip_build_channel_announcement_unsigned(
        out, cap, GOSSIP_CHAIN_HASH_MAINNET, scid, n1, n2, b1, b2);
    if (len < 432) return 0;

    /* Compute signed digest: SHA256(SHA256(type(2) || msg[258..])) */
    size_t tail_len = len - 258;
    size_t sd_len   = 2 + tail_len;
    unsigned char *sd = (unsigned char *)malloc(sd_len);
    if (!sd) return 0;
    memcpy(sd, out, 2);              /* type */
    memcpy(sd + 2, out + 258, tail_len);

    unsigned char digest[32];
    sha256_double(sd, sd_len, digest);
    free(sd);

    /* Sign with all 4 keys */
    unsigned char sig[64];
    secp256k1_keypair kp;

#define SIGN_SLOT(priv32, offset) do {                                   \
    secp256k1_keypair_create(ctx, &kp, (priv32));                         \
    secp256k1_schnorrsig_sign32(ctx, sig, digest, &kp, NULL);             \
    memcpy(out + (offset), sig, 64);                                      \
    memset(&kp, 0, sizeof(kp));                                           \
} while (0)

    SIGN_SLOT(node1_priv,  2);
    SIGN_SLOT(node2_priv,  66);
    SIGN_SLOT(btc1_priv,  130);
    SIGN_SLOT(btc2_priv,  194);
#undef SIGN_SLOT

    return len;
}

/* -----------------------------------------------------------------------
 * GI1: channel_announcement accepted with valid sigs → OK, store updated
 * --------------------------------------------------------------------- */
int test_gossip_ingest_channel_ann_ok(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    gossip_store_t gs;
    gossip_store_open_in_memory(&gs);

    gossip_ingest_t gi;
    gossip_ingest_init(&gi, ctx, &gs);

    unsigned char msg[512];
    unsigned char n1p[32], n2p[32], b1p[32], b2p[32];
    memset(n1p, 0x11, 32); memset(n2p, 0x22, 32);
    memset(b1p, 0x33, 32); memset(b2p, 0x44, 32);
    uint64_t scid = ((uint64_t)700000 << 40) | ((uint64_t)1 << 16) | 0;

    size_t len = build_signed_channel_ann(ctx, msg, sizeof(msg),
                                           n1p, n2p, b1p, b2p, scid);
    ASSERT(len >= 432, "built channel_ann");

    int r = gossip_ingest_channel_announcement(&gi, msg, len, NOW);
    ASSERT(r == GOSSIP_INGEST_OK, "GI1: channel_ann accepted");
    ASSERT(gi.n_channel_ann == 1, "n_channel_ann == 1");

    /* Channel should be in the store */
    unsigned char got_n1[33], got_n2[33];
    uint64_t cap; uint32_t lu;
    int found = gossip_store_get_channel(&gs, scid, got_n1, got_n2, &cap, &lu);
    ASSERT(found, "channel in gossip_store");

    gossip_store_close(&gs);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * GI2: channel_announcement bad sig → BAD_SIG
 * --------------------------------------------------------------------- */
int test_gossip_ingest_channel_ann_bad_sig(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    gossip_ingest_t gi;
    gossip_ingest_init(&gi, ctx, NULL);

    unsigned char msg[512];
    unsigned char n1p[32], n2p[32], b1p[32], b2p[32];
    memset(n1p, 0x11, 32); memset(n2p, 0x22, 32);
    memset(b1p, 0x33, 32); memset(b2p, 0x44, 32);
    uint64_t scid = ((uint64_t)700000 << 40) | ((uint64_t)2 << 16) | 0;

    size_t len = build_signed_channel_ann(ctx, msg, sizeof(msg),
                                           n1p, n2p, b1p, b2p, scid);
    ASSERT(len >= 432, "built");

    /* Corrupt node_sig_1 */
    msg[5] ^= 0xFF;

    int r = gossip_ingest_channel_announcement(&gi, msg, len, NOW);
    ASSERT(r == GOSSIP_INGEST_BAD_SIG, "GI2: bad sig rejected");
    ASSERT(gi.n_rejected_sig == 1, "n_rejected_sig == 1");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * GI3: node_announcement accepted → OK, store updated
 * --------------------------------------------------------------------- */
int test_gossip_ingest_node_ann_ok(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    gossip_store_t gs;
    gossip_store_open_in_memory(&gs);

    gossip_ingest_t gi;
    gossip_ingest_init(&gi, ctx, &gs);

    unsigned char priv[32];
    memset(priv, 0x55, 32);
    unsigned char rgb[3] = {0, 0, 0};

    unsigned char msg[512];
    size_t len = gossip_build_node_announcement(
        msg, sizeof(msg), ctx, priv, NOW, rgb, "TestNode", NULL, 0);
    ASSERT(len > 0, "built node_ann");

    int r = gossip_ingest_node_announcement(&gi, msg, len, NOW);
    ASSERT(r == GOSSIP_INGEST_OK, "GI3: node_ann accepted");
    ASSERT(gi.n_node_ann == 1, "n_node_ann == 1");

    /* Node should be in the store */
    unsigned char pub[33];
    memset(pub, 0x55, 33); /* placeholder — real check via API */
    make_pubkey(ctx, priv, pub);
    char alias_out[33], addr_out[64];
    uint32_t ls;
    int found = gossip_store_get_node(&gs, pub, alias_out, sizeof(alias_out),
                                       addr_out, sizeof(addr_out), &ls);
    ASSERT(found, "node in gossip_store");

    gossip_store_close(&gs);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * GI4: node_announcement bad sig → BAD_SIG
 * --------------------------------------------------------------------- */
int test_gossip_ingest_node_ann_bad_sig(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    gossip_ingest_t gi;
    gossip_ingest_init(&gi, ctx, NULL);

    unsigned char priv[32];
    memset(priv, 0x66, 32);
    unsigned char rgb[3] = {0, 0, 0};

    unsigned char msg[512];
    size_t len = gossip_build_node_announcement(
        msg, sizeof(msg), ctx, priv, NOW, rgb, "BadNode", NULL, 0);
    ASSERT(len > 0, "built");

    /* Corrupt the signature */
    msg[10] ^= 0xFF;

    int r = gossip_ingest_node_announcement(&gi, msg, len, NOW);
    ASSERT(r == GOSSIP_INGEST_BAD_SIG, "GI4: bad sig rejected");
    ASSERT(gi.n_rejected_sig == 1, "n_rejected_sig == 1");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * GI5: channel_update accepted → OK, policy stored
 * Setup: ingest a channel_ann first so the scid is known, then update
 * --------------------------------------------------------------------- */
int test_gossip_ingest_chan_update_ok(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    gossip_store_t gs;
    gossip_store_open_in_memory(&gs);

    gossip_ingest_t gi;
    gossip_ingest_init(&gi, ctx, &gs);

    unsigned char n1p[32], n2p[32], b1p[32], b2p[32];
    memset(n1p, 0x11, 32); memset(n2p, 0x22, 32);
    memset(b1p, 0x33, 32); memset(b2p, 0x44, 32);
    uint64_t scid = ((uint64_t)700001 << 40) | ((uint64_t)1 << 16) | 0;

    /* First: ingest channel_announcement to register the scid */
    unsigned char ann[512];
    size_t ann_len = build_signed_channel_ann(ctx, ann, sizeof(ann),
                                               n1p, n2p, b1p, b2p, scid);
    ASSERT(ann_len >= 432, "built channel_ann");
    ASSERT(gossip_ingest_channel_announcement(&gi, ann, ann_len, NOW)
           == GOSSIP_INGEST_OK, "channel_ann accepted");

    /* Now ingest channel_update for direction 0 (node1 signs) */
    unsigned char upd[200];
    size_t upd_len = gossip_build_channel_update(
        upd, sizeof(upd), ctx, n1p,
        GOSSIP_CHAIN_HASH_MAINNET, scid, NOW,
        0 /* msg_flags */, 0 /* chan_flags: dir=0 */,
        40 /* cltv */, 1000 /* htlc_min */, 100 /* fee_base */, 200 /* fee_ppm */,
        0);
    ASSERT(upd_len >= 130, "built channel_update");

    int r = gossip_ingest_channel_update(&gi, upd, upd_len, NOW);
    ASSERT(r == GOSSIP_INGEST_OK, "GI5: channel_update accepted");
    ASSERT(gi.n_chan_update == 1, "n_chan_update == 1");

    /* Verify stored policy */
    uint32_t fb, fp; uint16_t cd; uint32_t ts;
    int found = gossip_store_get_channel_update(&gs, scid, 0, &fb, &fp, &cd, &ts);
    ASSERT(found, "channel_update in store");
    ASSERT(fb == 100, "fee_base == 100");
    ASSERT(fp == 200, "fee_ppm == 200");

    gossip_store_close(&gs);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * GI6: channel_update bad sig → BAD_SIG
 * --------------------------------------------------------------------- */
int test_gossip_ingest_chan_update_bad_sig(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    gossip_store_t gs;
    gossip_store_open_in_memory(&gs);

    gossip_ingest_t gi;
    gossip_ingest_init(&gi, ctx, &gs);

    unsigned char n1p[32], n2p[32], b1p[32], b2p[32];
    memset(n1p, 0x11, 32); memset(n2p, 0x22, 32);
    memset(b1p, 0x33, 32); memset(b2p, 0x44, 32);
    uint64_t scid = ((uint64_t)700002 << 40) | ((uint64_t)1 << 16) | 0;

    /* Ingest channel_ann first */
    unsigned char ann[512];
    size_t ann_len = build_signed_channel_ann(ctx, ann, sizeof(ann),
                                               n1p, n2p, b1p, b2p, scid);
    gossip_ingest_channel_announcement(&gi, ann, ann_len, NOW);

    /* Build channel_update then corrupt sig */
    unsigned char upd[200];
    size_t upd_len = gossip_build_channel_update(
        upd, sizeof(upd), ctx, n1p,
        GOSSIP_CHAIN_HASH_MAINNET, scid, NOW,
        0, 0, 40, 1000, 100, 200, 0);
    ASSERT(upd_len >= 130, "built");

    /* Corrupt the signature */
    upd[5] ^= 0xFF;

    int r = gossip_ingest_channel_update(&gi, upd, upd_len, NOW);
    ASSERT(r == GOSSIP_INGEST_BAD_SIG, "GI6: bad sig rejected");
    ASSERT(gi.n_rejected_sig == 1, "n_rejected_sig == 1");

    gossip_store_close(&gs);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * GI7: channel_update for unknown channel → ORPHAN
 * --------------------------------------------------------------------- */
int test_gossip_ingest_chan_update_orphan(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    gossip_store_t gs;
    gossip_store_open_in_memory(&gs);

    gossip_ingest_t gi;
    gossip_ingest_init(&gi, ctx, &gs);

    unsigned char n1p[32];
    memset(n1p, 0x11, 32);
    uint64_t scid = ((uint64_t)999999 << 40) | 1; /* not in store */

    unsigned char upd[200];
    size_t upd_len = gossip_build_channel_update(
        upd, sizeof(upd), ctx, n1p,
        GOSSIP_CHAIN_HASH_MAINNET, scid, NOW,
        0, 0, 40, 1000, 100, 200, 0);
    ASSERT(upd_len >= 130, "built");

    int r = gossip_ingest_channel_update(&gi, upd, upd_len, NOW);
    ASSERT(r == GOSSIP_INGEST_ORPHAN, "GI7: orphan update rejected");
    ASSERT(gi.n_rejected_orphan == 1, "n_rejected_orphan == 1");

    gossip_store_close(&gs);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * GI8: rate limit — second update within MIN_INTERVAL → RATE_LIMITED
 * --------------------------------------------------------------------- */
int test_gossip_ingest_rate_limit(void)
{
    gossip_ingest_t gi;
    gossip_ingest_init(&gi, NULL, NULL); /* no verify, no store */

    unsigned char priv[32];
    memset(priv, 0x77, 32);
    unsigned char rgb[3] = {0, 0, 0};

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    unsigned char msg[512];
    size_t len = gossip_build_node_announcement(
        msg, sizeof(msg), ctx, priv, NOW, rgb, "RateTest", NULL, 0);
    ASSERT(len > 0, "built");

    /* First ingest — should be admitted */
    int r1 = gossip_ingest_node_announcement(&gi, msg, len, NOW);
    ASSERT(r1 == GOSSIP_INGEST_NO_VERIFY, "first accepted (no verify)");

    /* Second ingest within interval — rate limited */
    int r2 = gossip_ingest_node_announcement(&gi, msg, len, NOW + 30);
    ASSERT(r2 == GOSSIP_INGEST_RATE_LIMITED, "GI8: rate limited");
    ASSERT(gi.n_rejected_rate == 1, "n_rejected_rate == 1");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * GI9: rate limit expired — update after MIN_INTERVAL → accepted
 * --------------------------------------------------------------------- */
int test_gossip_ingest_rate_limit_expired(void)
{
    gossip_ingest_t gi;
    gossip_ingest_init(&gi, NULL, NULL);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    unsigned char priv[32];
    memset(priv, 0x88, 32);
    unsigned char rgb[3] = {0, 0, 0};

    unsigned char msg[512];
    size_t len = gossip_build_node_announcement(
        msg, sizeof(msg), ctx, priv, NOW, rgb, "RateExp", NULL, 0);
    ASSERT(len > 0, "built");

    /* First ingest */
    gossip_ingest_node_announcement(&gi, msg, len, NOW);

    /* Ingest after interval expires — should be accepted */
    int r = gossip_ingest_node_announcement(&gi, msg, len,
                                             NOW + GOSSIP_INGEST_MIN_INTERVAL + 1);
    ASSERT(r == GOSSIP_INGEST_NO_VERIFY, "GI9: rate limit expired, accepted");
    ASSERT(gi.n_rejected_rate == 0, "no rate rejections");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * GI10: timestamp_filter parsed correctly
 * --------------------------------------------------------------------- */
int test_gossip_ingest_timestamp_filter(void)
{
    gossip_ingest_t gi;
    gossip_ingest_init(&gi, NULL, NULL);

    unsigned char msg[42];
    /* Build type 265 manually */
    msg[0] = 0x01; msg[1] = 0x09;  /* type 265 */
    memcpy(msg + 2, GOSSIP_CHAIN_HASH_MAINNET, 32);
    /* first_timestamp = 1700000000 */
    msg[34] = 0x65; msg[35] = 0x53; msg[36] = 0xF1; msg[37] = 0x00;
    /* range = 86400 */
    msg[38] = 0x00; msg[39] = 0x01; msg[40] = 0x51; msg[41] = 0x80;

    unsigned char chain[32];
    uint32_t first = 0, rng = 0;
    int r = gossip_ingest_timestamp_filter(&gi, msg, sizeof(msg),
                                            chain, &first, &rng);
    ASSERT(r == GOSSIP_INGEST_OK, "GI10: timestamp_filter ok");
    ASSERT(memcmp(chain, GOSSIP_CHAIN_HASH_MAINNET, 32) == 0, "chain_hash matches");
    ASSERT(first == 1700000000u, "first_timestamp correct");
    ASSERT(rng == 86400u, "range correct");
    return 1;
}

/* -----------------------------------------------------------------------
 * GI11: gossip_ingest_message dispatches to correct handler
 * --------------------------------------------------------------------- */
int test_gossip_ingest_message_dispatch(void)
{
    gossip_ingest_t gi;
    gossip_ingest_init(&gi, NULL, NULL);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    unsigned char priv[32];
    memset(priv, 0xAA, 32);
    unsigned char rgb[3] = {0, 0, 0};

    unsigned char msg[512];
    size_t len = gossip_build_node_announcement(
        msg, sizeof(msg), ctx, priv, NOW, rgb, "Dispatch", NULL, 0);
    ASSERT(len > 0, "built");

    /* Dispatch should route type 257 to node_announcement handler */
    int r = gossip_ingest_message(&gi, msg, len, NOW);
    ASSERT(r == GOSSIP_INGEST_NO_VERIFY || r == GOSSIP_INGEST_OK,
           "GI11: dispatch handled type 257");
    ASSERT(gi.n_node_ann == 1, "n_node_ann == 1");

    /* Unknown type should return UNKNOWN_TYPE */
    unsigned char unknown[4] = {0x04, 0x00, 0xAB, 0xCD};
    r = gossip_ingest_message(&gi, unknown, 4, NOW);
    ASSERT(r == GOSSIP_INGEST_UNKNOWN_TYPE, "unknown type handled");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * GI12: malformed message (truncated) → MALFORMED
 * --------------------------------------------------------------------- */
int test_gossip_ingest_malformed(void)
{
    gossip_ingest_t gi;
    gossip_ingest_init(&gi, NULL, NULL);

    /* channel_announcement but too short */
    unsigned char short_msg[10];
    short_msg[0] = 0x01; short_msg[1] = 0x00; /* type 256 */
    memset(short_msg + 2, 0, 8);

    int r = gossip_ingest_channel_announcement(&gi, short_msg, sizeof(short_msg), NOW);
    ASSERT(r == GOSSIP_INGEST_MALFORMED, "GI12: truncated channel_ann → malformed");

    /* node_announcement too short */
    unsigned char short_node[10];
    short_node[0] = 0x01; short_node[1] = 0x01; /* type 257 */
    memset(short_node + 2, 0, 8);
    r = gossip_ingest_node_announcement(&gi, short_node, sizeof(short_node), NOW);
    ASSERT(r == GOSSIP_INGEST_MALFORMED, "truncated node_ann → malformed");

    /* timestamp_filter too short */
    unsigned char short_ts[10];
    short_ts[0] = 0x01; short_ts[1] = 0x09; /* type 265 */
    memset(short_ts + 2, 0, 8);
    r = gossip_ingest_timestamp_filter(&gi, short_ts, sizeof(short_ts), NULL, NULL, NULL);
    ASSERT(r == GOSSIP_INGEST_MALFORMED, "truncated timestamp_filter → malformed");

    return 1;
}

/* -----------------------------------------------------------------------
 * GI13: NULL safety
 * --------------------------------------------------------------------- */
int test_gossip_ingest_null_safety(void)
{
    /* All NULL gi */
    gossip_ingest_channel_announcement(NULL, NULL, 0, 0);
    gossip_ingest_node_announcement(NULL, NULL, 0, 0);
    gossip_ingest_channel_update(NULL, NULL, 0, 0);
    gossip_ingest_timestamp_filter(NULL, NULL, 0, NULL, NULL, NULL);
    gossip_ingest_message(NULL, NULL, 0, 0);
    gossip_ingest_init(NULL, NULL, NULL);

    /* result_str for all codes */
    ASSERT(gossip_ingest_result_str(GOSSIP_INGEST_OK)           != NULL, "ok str");
    ASSERT(gossip_ingest_result_str(GOSSIP_INGEST_BAD_SIG)      != NULL, "bad_sig str");
    ASSERT(gossip_ingest_result_str(GOSSIP_INGEST_RATE_LIMITED) != NULL, "rate_limited str");
    ASSERT(gossip_ingest_result_str(GOSSIP_INGEST_ORPHAN)       != NULL, "orphan str");
    ASSERT(gossip_ingest_result_str(GOSSIP_INGEST_MALFORMED)    != NULL, "malformed str");
    ASSERT(gossip_ingest_result_str(GOSSIP_INGEST_UNKNOWN_TYPE) != NULL, "unknown_type str");
    ASSERT(gossip_ingest_result_str(GOSSIP_INGEST_NO_VERIFY)    != NULL, "no_verify str");
    ASSERT(gossip_ingest_result_str(-99)                         != NULL, "unknown str");

    return 1;
}
