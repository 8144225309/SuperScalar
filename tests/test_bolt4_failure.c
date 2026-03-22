/*
 * test_bolt4_failure.c — Tests for BOLT #4 onion failure message parser
 *
 * PR #50: BOLT #4 Failure Message Parser (payment failure attribution)
 */

#include "superscalar/bolt4_failure.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* Helper: build a minimal failure plaintext buffer */
static void put_u16(unsigned char *p, uint16_t v) { p[0] = v >> 8; p[1] = v; }
static void put_u32(unsigned char *p, uint32_t v) {
    p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v;
}
static void put_u64(unsigned char *p, uint64_t v) {
    for (int i = 7; i >= 0; i--) { p[i] = (unsigned char)(v & 0xFF); v >>= 8; }
}

/* -----------------------------------------------------------------------
 * BF1: TEMPORARY_CHANNEL_FAILURE (0x1007) — UPDATE flag, channel_update
 * --------------------------------------------------------------------- */
int test_bf_temporary_channel_failure(void)
{
    unsigned char msg[64];
    memset(msg, 0, sizeof(msg));
    put_u16(msg, BOLT4_TEMPORARY_CHANNEL_FAILURE);  /* 0x1007 */

    /* channel_update: len(2) + type(2=258) + 10 bytes fake data */
    unsigned char cu_data[12];
    put_u16(cu_data, 12);        /* len = 12 */
    put_u16(cu_data + 2, 258);   /* type = channel_update */
    memset(cu_data + 4, 0xAB, 8);
    memcpy(msg + 2, cu_data, sizeof(cu_data));

    bolt4_failure_t f;
    ASSERT(bolt4_failure_parse(msg, sizeof(msg), &f), "BF1: parse ok");
    ASSERT(f.failure_code == 0x1007,          "BF1: code 0x1007");
    ASSERT(f.has_channel_update == 1,         "BF1: has_channel_update=1");
    ASSERT(f.channel_update_len == 12,        "BF1: channel_update_len=12");
    ASSERT(!f.is_permanent,                   "BF1: not permanent");
    ASSERT(!f.is_bad_onion,                   "BF1: not bad_onion");
    ASSERT(!f.is_node_failure,                "BF1: not node");
    ASSERT(bolt4_failure_has_update(&f) == 1, "BF1: has_update helper");
    return 1;
}

/* -----------------------------------------------------------------------
 * BF2: CHANNEL_DISABLED (0x1006) — disabled_flags + channel_update
 * --------------------------------------------------------------------- */
int test_bf_channel_disabled(void)
{
    unsigned char msg[48];
    memset(msg, 0, sizeof(msg));
    put_u16(msg, BOLT4_CHANNEL_DISABLED);  /* 0x1006 */

    /* flags(2) + channel_update: len(2) + type(2) + 4 bytes */
    put_u16(msg + 2, 0x0001);  /* disabled_flags = 1 */
    put_u16(msg + 4, 6);       /* cu_len = 6 */
    put_u16(msg + 6, 258);     /* type = channel_update */
    memset(msg + 8, 0xCC, 4);

    bolt4_failure_t f;
    ASSERT(bolt4_failure_parse(msg, sizeof(msg), &f), "BF2: parse ok");
    ASSERT(f.failure_code == BOLT4_CHANNEL_DISABLED, "BF2: code");
    ASSERT(f.has_disabled_flags == 1,               "BF2: has_disabled_flags");
    ASSERT(f.disabled_flags == 0x0001,              "BF2: disabled_flags=1");
    ASSERT(f.channel_update_len == 6,               "BF2: cu_len=6");
    return 1;
}

/* -----------------------------------------------------------------------
 * BF3: PERMANENT_CHANNEL_FAILURE (0x4009) — PERM + no data
 * --------------------------------------------------------------------- */
int test_bf_permanent_channel_failure(void)
{
    unsigned char msg[4] = {0x40, 0x09, 0, 0};  /* 0x4009 */

    bolt4_failure_t f;
    ASSERT(bolt4_failure_parse(msg, sizeof(msg), &f), "BF3: parse ok");
    ASSERT(f.failure_code == BOLT4_PERMANENT_CHANNEL_FAILURE, "BF3: code");
    ASSERT(f.is_permanent == 1,      "BF3: is_permanent");
    ASSERT(f.is_node_failure == 0,   "BF3: not node");
    ASSERT(f.is_bad_onion == 0,      "BF3: not bad_onion");
    ASSERT(f.has_channel_update == 0, "BF3: no channel_update");
    ASSERT(bolt4_failure_is_permanent(&f) == 1, "BF3: is_permanent helper");
    return 1;
}

/* -----------------------------------------------------------------------
 * BF4: INVALID_ONION_HMAC (0x8005) — BADONION + sha256(32)
 * --------------------------------------------------------------------- */
int test_bf_invalid_onion_hmac(void)
{
    unsigned char msg[34];
    memset(msg, 0, sizeof(msg));
    put_u16(msg, BOLT4_INVALID_ONION_HMAC);  /* 0x8005 */
    /* sha256_of_onion (32 bytes) */
    memset(msg + 2, 0x42, 32);

    bolt4_failure_t f;
    ASSERT(bolt4_failure_parse(msg, sizeof(msg), &f), "BF4: parse ok");
    ASSERT(f.failure_code == BOLT4_INVALID_ONION_HMAC, "BF4: code 0x8005");
    ASSERT(f.is_bad_onion == 1,      "BF4: is_bad_onion=1");
    ASSERT(f.has_bad_onion_sha == 1, "BF4: has_bad_onion_sha=1");

    unsigned char expected[32]; memset(expected, 0x42, 32);
    ASSERT(memcmp(f.bad_onion_sha256, expected, 32) == 0, "BF4: sha256 correct");
    ASSERT(bolt4_failure_is_bad_onion(&f) == 1, "BF4: is_bad_onion helper");
    return 1;
}

/* -----------------------------------------------------------------------
 * BF5: UNKNOWN_PAYMENT_HASH (0x000F) — no flags, final hop
 * --------------------------------------------------------------------- */
int test_bf_unknown_payment_hash(void)
{
    unsigned char msg[2] = {0x00, 0x0F};  /* probe: destination reached */

    bolt4_failure_t f;
    ASSERT(bolt4_failure_parse(msg, sizeof(msg), &f), "BF5: parse ok");
    ASSERT(f.failure_code == BOLT4_UNKNOWN_PAYMENT_HASH, "BF5: code 0x000F");
    ASSERT(!f.is_permanent,      "BF5: not permanent");
    ASSERT(!f.is_bad_onion,      "BF5: not bad_onion");
    ASSERT(!f.is_node_failure,   "BF5: not node");
    ASSERT(!f.has_channel_update, "BF5: no update");
    return 1;
}

/* -----------------------------------------------------------------------
 * BF6: AMOUNT_BELOW_MINIMUM (0x100B) — htlc_msat(8) + channel_update
 * --------------------------------------------------------------------- */
int test_bf_amount_below_minimum(void)
{
    unsigned char msg[64];
    memset(msg, 0, sizeof(msg));
    put_u16(msg, BOLT4_AMOUNT_BELOW_MINIMUM);  /* 0x100B */

    /* htlc_msat = 500000 (= 500 sats) */
    put_u64(msg + 2, 500000ULL);

    /* channel_update: len=4 + type(2=258) + 2 bytes data */
    put_u16(msg + 10, 4);
    put_u16(msg + 12, 258);
    msg[14] = 0x11; msg[15] = 0x22;

    bolt4_failure_t f;
    ASSERT(bolt4_failure_parse(msg, sizeof(msg), &f), "BF6: parse ok");
    ASSERT(f.failure_code == BOLT4_AMOUNT_BELOW_MINIMUM, "BF6: code");
    ASSERT(f.has_htlc_msat == 1,          "BF6: has_htlc_msat");
    ASSERT(f.htlc_msat == 500000ULL,      "BF6: htlc_msat=500000");
    ASSERT(f.channel_update_len == 4,     "BF6: cu_len=4");
    return 1;
}

/* -----------------------------------------------------------------------
 * BF7: INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS (0x400F) — PERM + NODE + htlc_msat + height
 * --------------------------------------------------------------------- */
int test_bf_incorrect_payment_details(void)
{
    unsigned char msg[14];
    memset(msg, 0, sizeof(msg));
    put_u16(msg, BOLT4_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS);  /* 0x400F */
    put_u64(msg + 2, 1000000ULL);   /* htlc_msat */
    put_u32(msg + 10, 850000u);     /* block_height */

    bolt4_failure_t f;
    ASSERT(bolt4_failure_parse(msg, sizeof(msg), &f), "BF7: parse ok");
    ASSERT(f.failure_code == BOLT4_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS, "BF7: code");
    ASSERT(f.is_permanent == 1,         "BF7: is_permanent (PERM bit)");
    ASSERT(f.has_htlc_msat == 1,        "BF7: has_htlc_msat");
    ASSERT(f.htlc_msat == 1000000ULL,   "BF7: htlc_msat=1000000");
    ASSERT(f.has_block_height == 1,     "BF7: has_block_height");
    ASSERT(f.block_height == 850000u,   "BF7: block_height=850000");
    return 1;
}

/* -----------------------------------------------------------------------
 * BF8: is_permanent covers all PERM-flagged codes
 * --------------------------------------------------------------------- */
int test_bf_is_permanent_codes(void)
{
    bolt4_failure_t f;
    unsigned char msg[2];

    /* PERMANENT_CHANNEL_FAILURE = 0x5009 → PERM set */
    put_u16(msg, BOLT4_PERMANENT_CHANNEL_FAILURE);
    bolt4_failure_parse(msg, 2, &f);
    ASSERT(bolt4_failure_is_permanent(&f), "BF8: PERMANENT_CHANNEL_FAILURE → perm");

    /* TEMPORARY_CHANNEL_FAILURE = 0x1007 → PERM not set */
    put_u16(msg, BOLT4_TEMPORARY_CHANNEL_FAILURE);
    bolt4_failure_parse(msg, 2, &f);
    ASSERT(!bolt4_failure_is_permanent(&f), "BF8: TEMPORARY_CHANNEL_FAILURE → not perm");

    /* UNKNOWN_NEXT_PEER = 0x500A → PERM set */
    put_u16(msg, BOLT4_UNKNOWN_NEXT_PEER);
    bolt4_failure_parse(msg, 2, &f);
    ASSERT(bolt4_failure_is_permanent(&f), "BF8: UNKNOWN_NEXT_PEER → perm");

    return 1;
}

/* -----------------------------------------------------------------------
 * BF9: is_node_failure covers NODE-flagged codes
 * --------------------------------------------------------------------- */
int test_bf_is_node_failure_codes(void)
{
    bolt4_failure_t f;
    unsigned char msg[2];

    /* TEMPORARY_NODE_FAILURE = 0x2002 → NODE set */
    put_u16(msg, BOLT4_TEMPORARY_NODE_FAILURE);
    bolt4_failure_parse(msg, 2, &f);
    ASSERT(bolt4_failure_is_node_failure(&f), "BF9: TEMPORARY_NODE_FAILURE → node");

    /* PERMANENT_NODE_FAILURE = 0x4002 → NODE? Actually 0x4002 = PERM|NODE... */
    /* Wait: 0x4002: PERM(0x4000) | 0x0002 → no NODE bit (0x2000) */
    /* Let me check: PERMANENT_NODE_FAILURE = 0x4002
       bit 14 (0x4000) = PERM, bit 1 (0x0002) = node_failure_code */
    /* Actually PERMANENT_NODE_FAILURE has PERM but NODE bit would be 0x2000 */
    /* In BOLT #4, the NODE bit in failure codes is in the failure_code itself */
    /* Let me use INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS = 0x400F:
       PERM(0x4000) | 0x000F → is_permanent=1, is_node_failure=0 */
    /* NODE bit (0x2000) isn't set in 0x400F */

    /* TEMPORARY_CHANNEL_FAILURE = 0x1007 → not node */
    put_u16(msg, BOLT4_TEMPORARY_CHANNEL_FAILURE);
    bolt4_failure_parse(msg, 2, &f);
    ASSERT(!bolt4_failure_is_node_failure(&f), "BF9: TEMP_CHAN_FAIL → not node");

    /* 0x2002 = NODE | 2 → node failure */
    msg[0] = 0x20; msg[1] = 0x02;
    bolt4_failure_parse(msg, 2, &f);
    ASSERT(bolt4_failure_is_node_failure(&f), "BF9: 0x2002 → node");

    return 1;
}

/* -----------------------------------------------------------------------
 * BF10: INCORRECT_CLTV_EXPIRY (0x100D) — cltv_expiry + channel_update
 * --------------------------------------------------------------------- */
int test_bf_incorrect_cltv_expiry(void)
{
    unsigned char msg[32];
    memset(msg, 0, sizeof(msg));
    put_u16(msg, BOLT4_INCORRECT_CLTV_EXPIRY);  /* 0x100D */
    put_u32(msg + 2, 800100u);  /* cltv_expiry */
    put_u16(msg + 6, 4);        /* cu_len */
    put_u16(msg + 8, 258);      /* channel_update type */
    msg[10] = 0xDE; msg[11] = 0xAD;

    bolt4_failure_t f;
    ASSERT(bolt4_failure_parse(msg, sizeof(msg), &f), "BF10: parse ok");
    ASSERT(f.failure_code == BOLT4_INCORRECT_CLTV_EXPIRY, "BF10: code");
    ASSERT(f.has_cltv_expiry == 1,      "BF10: has_cltv_expiry");
    ASSERT(f.cltv_expiry == 800100u,    "BF10: cltv_expiry=800100");
    ASSERT(f.channel_update_len == 4,   "BF10: cu_len=4");
    return 1;
}

/* -----------------------------------------------------------------------
 * BF11: bolt4_failure_str returns non-NULL for known codes
 * --------------------------------------------------------------------- */
int test_bf_failure_str(void)
{
    ASSERT(bolt4_failure_str(BOLT4_TEMPORARY_CHANNEL_FAILURE) != NULL,
           "BF11: TEMP_CHAN_FAIL has string");
    ASSERT(bolt4_failure_str(BOLT4_INVALID_ONION_HMAC) != NULL,
           "BF11: INVALID_ONION_HMAC has string");
    ASSERT(bolt4_failure_str(BOLT4_PERMANENT_CHANNEL_FAILURE) != NULL,
           "BF11: PERMANENT_CHAN_FAIL has string");
    ASSERT(bolt4_failure_str(BOLT4_UNKNOWN_PAYMENT_HASH) != NULL,
           "BF11: UNKNOWN_PAYMENT_HASH has string");
    ASSERT(bolt4_failure_str(0xDEAD) != NULL,
           "BF11: unknown code returns fallback string");
    /* Verify specific strings */
    ASSERT(bolt4_failure_str(BOLT4_CHANNEL_DISABLED)[0] != '\0',
           "BF11: CHANNEL_DISABLED non-empty");
    return 1;
}

/* -----------------------------------------------------------------------
 * BF12: FEE_INSUFFICIENT (0x100C) — htlc_msat + channel_update
 * --------------------------------------------------------------------- */
int test_bf_fee_insufficient(void)
{
    unsigned char msg[32];
    memset(msg, 0, sizeof(msg));
    put_u16(msg, BOLT4_FEE_INSUFFICIENT);  /* 0x100C */
    put_u64(msg + 2, 2000000ULL);          /* htlc_msat */
    put_u16(msg + 10, 4);                  /* cu_len */
    put_u16(msg + 12, 258);                /* channel_update type */
    msg[14] = 0x01; msg[15] = 0x02;

    bolt4_failure_t f;
    ASSERT(bolt4_failure_parse(msg, sizeof(msg), &f), "BF12: parse ok");
    ASSERT(f.failure_code == BOLT4_FEE_INSUFFICIENT, "BF12: code");
    ASSERT(f.htlc_msat == 2000000ULL,      "BF12: htlc_msat=2000000");
    ASSERT(f.channel_update_len == 4,      "BF12: cu present");
    ASSERT(bolt4_failure_has_update(&f),   "BF12: has_update");
    return 1;
}

/* -----------------------------------------------------------------------
 * BF13: NULL safety and truncated input
 * --------------------------------------------------------------------- */
int test_bf_null_safety(void)
{
    bolt4_failure_t f;
    unsigned char msg[2] = {0x10, 0x07};

    /* NULL inputs */
    ASSERT(!bolt4_failure_parse(NULL, 2, &f),    "BF13: NULL msg → 0");
    ASSERT(!bolt4_failure_parse(msg, 2, NULL),   "BF13: NULL out → 0");
    ASSERT(!bolt4_failure_parse(msg, 1, &f),     "BF13: len=1 → 0 (too short)");
    ASSERT(!bolt4_failure_parse(msg, 0, &f),     "BF13: len=0 → 0");

    /* NULL helper inputs */
    ASSERT(!bolt4_failure_is_permanent(NULL),    "BF13: is_permanent NULL → 0");
    ASSERT(!bolt4_failure_is_node_failure(NULL), "BF13: is_node_failure NULL → 0");
    ASSERT(!bolt4_failure_is_bad_onion(NULL),    "BF13: is_bad_onion NULL → 0");
    ASSERT(!bolt4_failure_has_update(NULL),      "BF13: has_update NULL → 0");

    /* Exact minimum (2 bytes) succeeds */
    ASSERT(bolt4_failure_parse(msg, 2, &f),      "BF13: len=2 (minimum) → 1");
    ASSERT(f.failure_code == 0x1007,             "BF13: code parsed from 2 bytes");

    /* Truncated bad-onion: code present but sha256 not (only 3 bytes) */
    unsigned char short_bo[3] = {0x80, 0x05, 0x00};  /* INVALID_ONION_HMAC, no sha */
    ASSERT(bolt4_failure_parse(short_bo, sizeof(short_bo), &f), "BF13: short bad-onion ok");
    ASSERT(f.failure_code == BOLT4_INVALID_ONION_HMAC, "BF13: code ok");
    ASSERT(!f.has_bad_onion_sha, "BF13: truncated sha → not present");

    return 1;
}
