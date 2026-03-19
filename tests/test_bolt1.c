/*
 * test_bolt1.c — Tests for BOLT #1 fundamental message handling.
 *
 * PR #33: BOLT #1 peer protocol (init, ping/pong, error, warning)
 * Reference: lightning/bolts BOLT #1, BOLT #9
 */

#include "superscalar/bolt1.h"
#include "superscalar/ln_dispatch.h"
#include "superscalar/channel.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* BL1: bolt1_build_init + parse round-trip */
int test_bolt1_init_roundtrip(void)
{
    uint64_t feat = BOLT1_OUR_FEATURES;
    unsigned char buf[64];
    size_t len = bolt1_build_init(feat, buf, sizeof(buf));
    ASSERT(len >= 6, "init message >= 6 bytes");
    ASSERT(buf[0] == 0x00 && buf[1] == 0x10, "type=16");

    bolt1_init_t parsed;
    ASSERT(bolt1_parse_init(buf, len, &parsed), "parse succeeds");
    ASSERT(parsed.local_features == feat, "local features preserved");
    return 1;
}

/* BL2: parse reads gflen and lflen correctly */
int test_bolt1_init_parse_fields(void)
{
    /* Manually build: type(2)+gflen(2)=0+lflen(2)=1+feat=0x80 */
    unsigned char msg[7] = {0x00, 0x10,  /* type=16 */
                             0x00, 0x00,  /* gflen=0 */
                             0x00, 0x01,  /* lflen=1 */
                             0x80};        /* features: bit 7 set */
    bolt1_init_t out;
    ASSERT(bolt1_parse_init(msg, sizeof(msg), &out), "parse ok");
    ASSERT(out.global_features == 0, "no global features");
    /* bit 7 in byte 0 (len=1) → bit position 7 */
    ASSERT(bolt1_has_feature(out.local_features, 7), "bit 7 set from wire 0x80");
    return 1;
}

/* BL3: bolt1_build_ping produces correct structure */
int test_bolt1_ping_build(void)
{
    unsigned char buf[32];
    size_t len = bolt1_build_ping(32, buf, sizeof(buf));
    ASSERT(len == 6, "ping is 6 bytes (no padding)");
    uint16_t mtype = ((uint16_t)buf[0] << 8) | buf[1];
    ASSERT(mtype == BOLT1_MSG_PING, "type=18");
    uint16_t npb = ((uint16_t)buf[2] << 8) | buf[3];
    ASSERT(npb == 32, "num_pong_bytes=32");
    return 1;
}

/* BL4: bolt1_build_pong echoes byteslen */
int test_bolt1_pong_build(void)
{
    unsigned char buf[64];
    size_t len = bolt1_build_pong(16, buf, sizeof(buf));
    ASSERT(len == 20, "pong = 4 header + 16 bytes");
    uint16_t mtype = ((uint16_t)buf[0] << 8) | buf[1];
    ASSERT(mtype == BOLT1_MSG_PONG, "type=19");
    uint16_t byteslen = ((uint16_t)buf[2] << 8) | buf[3];
    ASSERT(byteslen == 16, "byteslen=16");
    return 1;
}

/* BL5: bolt1_build_error includes channel_id and data */
int test_bolt1_error_build(void)
{
    unsigned char cid[32]; memset(cid, 0xAB, 32);
    unsigned char buf[128];
    size_t len = bolt1_build_error(cid, "test error", buf, sizeof(buf));
    ASSERT(len == 2 + 32 + 2 + 10, "error length = 46");
    uint16_t mtype = ((uint16_t)buf[0] << 8) | buf[1];
    ASSERT(mtype == BOLT1_MSG_ERROR, "type=17");
    ASSERT(memcmp(buf + 2, cid, 32) == 0, "channel_id matches");
    ASSERT(buf[34] == 0 && buf[35] == 10, "data_len=10");
    ASSERT(memcmp(buf + 36, "test error", 10) == 0, "data matches");
    /* Wait - data_len at offset 34-35 */
    bolt1_error_t e;
    ASSERT(bolt1_parse_error(buf, len, &e), "parse ok");
    ASSERT(memcmp(e.channel_id, cid, 32) == 0, "parsed cid");
    ASSERT(strcmp(e.data, "test error") == 0, "parsed data");
    return 1;
}

/* BL6: bolt1_build_warning uses type=1 */
int test_bolt1_warning_build(void)
{
    unsigned char cid[32]; memset(cid, 0, 32);
    unsigned char buf[64];
    size_t len = bolt1_build_warning(cid, "channel stale", buf, sizeof(buf));
    ASSERT(len > 0, "warning built");
    uint16_t mtype = ((uint16_t)buf[0] << 8) | buf[1];
    ASSERT(mtype == BOLT1_MSG_WARNING, "type=1");
    bolt1_error_t w;
    ASSERT(bolt1_parse_error(buf, len, &w), "parse succeeds");
    ASSERT(strcmp(w.data, "channel stale") == 0, "data matches");
    return 1;
}

/* BL7: ln_dispatch handles type 16 (init) → returns 16 */
int test_bolt1_dispatch_init(void)
{
    ln_dispatch_t d; memset(&d, 0, sizeof(d));
    unsigned char buf[32];
    size_t len = bolt1_build_init(BOLT1_OUR_FEATURES, buf, sizeof(buf));
    ASSERT(len > 0, "init built");
    int r = ln_dispatch_process_msg(&d, 0, buf, len);
    ASSERT(r == BOLT1_MSG_INIT, "dispatch returns 16");
    return 1;
}

/* BL8: ln_dispatch handles type 17 (error) → returns 17 */
int test_bolt1_dispatch_error(void)
{
    ln_dispatch_t d; memset(&d, 0, sizeof(d));
    unsigned char cid[32]; memset(cid, 0, 32);
    unsigned char buf[64];
    size_t len = bolt1_build_error(cid, "test", buf, sizeof(buf));
    int r = ln_dispatch_process_msg(&d, 0, buf, len);
    ASSERT(r == BOLT1_MSG_ERROR, "dispatch returns 17");
    return 1;
}

/* BL9: ln_dispatch handles type 1 (warning) → returns 1 */
int test_bolt1_dispatch_warning(void)
{
    ln_dispatch_t d; memset(&d, 0, sizeof(d));
    unsigned char cid[32]; memset(cid, 0, 32);
    unsigned char buf[64];
    size_t len = bolt1_build_warning(cid, "warn", buf, sizeof(buf));
    int r = ln_dispatch_process_msg(&d, 0, buf, len);
    ASSERT(r == BOLT1_MSG_WARNING, "dispatch returns 1");
    return 1;
}

/* BL10: ln_dispatch handles type 18 (ping) → sends pong, returns 18 */
int test_bolt1_dispatch_ping(void)
{
    ln_dispatch_t d; memset(&d, 0, sizeof(d));
    unsigned char buf[16];
    size_t len = bolt1_build_ping(4, buf, sizeof(buf));
    int r = ln_dispatch_process_msg(&d, 0, buf, len);
    ASSERT(r == BOLT1_MSG_PING, "dispatch returns 18");
    return 1;
}

/* BL11: bolt1_has_feature checks individual bits */
int test_bolt1_has_feature(void)
{
    uint64_t f = BOLT1_OUR_FEATURES;
    ASSERT(bolt1_has_feature(f, BOLT9_PAYMENT_SECRET), "payment_secret set");
    ASSERT(bolt1_has_feature(f, BOLT9_BASIC_MPP), "basic_mpp set");
    ASSERT(bolt1_has_feature(f, BOLT9_STATIC_REMOTE_KEY), "static_remote_key set");
    ASSERT(!bolt1_has_feature(f, BOLT9_ANCHOR_OUTPUTS), "anchor_outputs not set");
    ASSERT(!bolt1_has_feature(f, BOLT9_ZEROCONF), "zeroconf not set");
    return 1;
}

/* BL12: bolt1_check_mandatory_features detects unknown even bits */
int test_bolt1_mandatory_feature_check(void)
{
    /* All-known bits → OK */
    uint64_t known = BOLT1_OUR_FEATURES;
    ASSERT(bolt1_check_mandatory_features(known, known), "known bits OK");

    /* Unknown odd bit 11 → OK (odd = optional) */
    uint64_t with_odd = known | (UINT64_C(1) << 11);
    ASSERT(bolt1_check_mandatory_features(with_odd, known), "odd unknown OK");

    /* Unknown even bit 20 → FAIL (even = mandatory) */
    uint64_t with_even = known | (UINT64_C(1) << 20);
    ASSERT(!bolt1_check_mandatory_features(with_even, known),
           "unknown even bit → disconnect");
    return 1;
}

/* BL13: bolt1_parse_init rejects wrong type */
int test_bolt1_init_wrong_type(void)
{
    unsigned char buf[8] = {0x00, 0x11, 0x00, 0x00, 0x00, 0x00};  /* type=17 */
    bolt1_init_t out;
    ASSERT(!bolt1_parse_init(buf, 6, &out), "wrong type rejected");
    ASSERT(!bolt1_parse_init(NULL, 6, &out), "NULL rejected");
    ASSERT(!bolt1_parse_init(buf, 3, &out), "too short rejected");
    return 1;
}

/* BL14: bolt1_build_init with zero features */
int test_bolt1_init_zero_features(void)
{
    unsigned char buf[32];
    size_t len = bolt1_build_init(0, buf, sizeof(buf));
    ASSERT(len == 6, "zero-features init is 6 bytes");
    bolt1_init_t out;
    ASSERT(bolt1_parse_init(buf, len, &out), "parse ok");
    ASSERT(out.local_features == 0, "zero features preserved");
    return 1;
}
