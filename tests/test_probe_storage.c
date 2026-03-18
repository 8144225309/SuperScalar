/*
 * test_probe_storage.c — Unit tests for probe.c and peer_storage.c
 *
 * PB1: test_probe_build_hash            — probe hash generation (32 non-zero bytes)
 * PB2: test_probe_success_failure       — UNKNOWN_PAYMENT_HASH → liquid
 * PB3: test_probe_liquidity_failure     — TEMPORARY_CHANNEL_FAILURE → liquidity
 * PB4: test_probe_classify_all_codes    — classify each BOLT #4 code
 * PS1: test_peer_storage_build_type7    — peer_storage (type 7) layout
 * PS2: test_peer_storage_build_type9    — your_peer_storage (type 9) layout
 * PS3: test_peer_storage_parse_roundtrip — build then parse
 * PS4: test_peer_storage_parse_errors   — truncated / wrong type rejected
 */

#include "superscalar/probe.h"
#include "superscalar/peer_storage.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

static uint16_t rd16(const unsigned char *b) {
    return ((uint16_t)b[0] << 8) | b[1];
}

/* ================================================================== */
/* PB1 — probe_build_payment_hash produces 32 bytes                   */
/* ================================================================== */
int test_probe_build_hash(void)
{
    unsigned char hash[32];
    memset(hash, 0, 32);

    int ok = probe_build_payment_hash(hash);
    ASSERT(ok == 1, "probe_build_payment_hash should succeed");

    /* Verify at least some bytes are non-zero (probability of all-zero is 2^-256) */
    int nonzero = 0;
    for (int i = 0; i < 32; i++) if (hash[i]) nonzero = 1;
    ASSERT(nonzero, "probe hash should have non-zero bytes");

    return 1;
}

/* ================================================================== */
/* PB2 — UNKNOWN_PAYMENT_HASH means probe is a success                */
/* ================================================================== */
int test_probe_success_failure(void)
{
    ASSERT(probe_is_success_failure(PROBE_ERR_UNKNOWN_PAYMENT_HASH),
           "UNKNOWN_PAYMENT_HASH should indicate success");
    ASSERT(!probe_is_success_failure(PROBE_ERR_TEMPORARY_CHANNEL_FAILURE),
           "TEMPORARY_CHANNEL_FAILURE is not a success");
    ASSERT(!probe_is_success_failure(0x0000),
           "zero code is not a success");
    return 1;
}

/* ================================================================== */
/* PB3 — TEMPORARY_CHANNEL_FAILURE means liquidity failure            */
/* ================================================================== */
int test_probe_liquidity_failure(void)
{
    ASSERT(probe_is_liquidity_failure(PROBE_ERR_TEMPORARY_CHANNEL_FAILURE),
           "TEMPORARY_CHANNEL_FAILURE should indicate liquidity failure");
    ASSERT(!probe_is_liquidity_failure(PROBE_ERR_UNKNOWN_PAYMENT_HASH),
           "UNKNOWN_PAYMENT_HASH is not a liquidity failure");
    ASSERT(!probe_is_liquidity_failure(PROBE_ERR_CHANNEL_DISABLED),
           "CHANNEL_DISABLED is not a liquidity failure");
    return 1;
}

/* ================================================================== */
/* PB4 — probe_classify_failure covers all expected codes             */
/* ================================================================== */
int test_probe_classify_all_codes(void)
{
    ASSERT(probe_classify_failure(PROBE_ERR_UNKNOWN_PAYMENT_HASH)
           == PROBE_RESULT_LIQUID,
           "UNKNOWN_PAYMENT_HASH → LIQUID");

    ASSERT(probe_classify_failure(PROBE_ERR_TEMPORARY_CHANNEL_FAILURE)
           == PROBE_RESULT_LIQUIDITY_FAIL,
           "TEMPORARY_CHANNEL_FAILURE → LIQUIDITY_FAIL");

    ASSERT(probe_classify_failure(PROBE_ERR_CHANNEL_DISABLED)
           == PROBE_RESULT_CHANNEL_FAIL,
           "CHANNEL_DISABLED → CHANNEL_FAIL");

    ASSERT(probe_classify_failure(PROBE_ERR_UNKNOWN_NEXT_PEER)
           == PROBE_RESULT_CHANNEL_FAIL,
           "UNKNOWN_NEXT_PEER → CHANNEL_FAIL");

    ASSERT(probe_classify_failure(PROBE_ERR_AMOUNT_BELOW_MINIMUM)
           == PROBE_RESULT_POLICY_FAIL,
           "AMOUNT_BELOW_MINIMUM → POLICY_FAIL");

    ASSERT(probe_classify_failure(PROBE_ERR_FEE_INSUFFICIENT)
           == PROBE_RESULT_POLICY_FAIL,
           "FEE_INSUFFICIENT → POLICY_FAIL");

    ASSERT(probe_classify_failure(PROBE_ERR_INCORRECT_CLTV_EXPIRY)
           == PROBE_RESULT_POLICY_FAIL,
           "INCORRECT_CLTV_EXPIRY → POLICY_FAIL");

    ASSERT(probe_classify_failure(PROBE_ERR_EXPIRY_TOO_SOON)
           == PROBE_RESULT_POLICY_FAIL,
           "EXPIRY_TOO_SOON → POLICY_FAIL");

    ASSERT(probe_classify_failure(0xDEAD)
           == PROBE_RESULT_UNKNOWN,
           "unknown code → UNKNOWN");

    return 1;
}

/* ================================================================== */
/* PS1 — peer_storage (type 7) message layout                         */
/* ================================================================== */
int test_peer_storage_build_type7(void)
{
    unsigned char blob[16]; memset(blob, 0xAB, 16);
    unsigned char buf[200];

    size_t len = peer_storage_build(BOLT9_PEER_STORAGE, blob, 16,
                                     buf, sizeof(buf));

    ASSERT(len == 4 + 16, "peer_storage length = 20");
    ASSERT(rd16(buf) == BOLT9_PEER_STORAGE, "type = 7");
    ASSERT(rd16(buf + 2) == 16, "blob_len = 16 at offset 2");
    ASSERT(memcmp(buf + 4, blob, 16) == 0, "blob at offset 4");

    return 1;
}

/* ================================================================== */
/* PS2 — your_peer_storage (type 9) message layout                    */
/* ================================================================== */
int test_peer_storage_build_type9(void)
{
    unsigned char blob[34]; memset(blob, 0xCD, 34);
    unsigned char buf[200];

    size_t len = peer_storage_build(BOLT9_YOUR_PEER_STORAGE, blob, 34,
                                     buf, sizeof(buf));

    ASSERT(len == 4 + 34, "your_peer_storage length = 38");
    ASSERT(rd16(buf) == BOLT9_YOUR_PEER_STORAGE, "type = 9");
    ASSERT(rd16(buf + 2) == 34, "blob_len = 34 at offset 2");
    ASSERT(memcmp(buf + 4, blob, 34) == 0, "blob at offset 4");

    return 1;
}

/* ================================================================== */
/* PS3 — parse roundtrip for both types                               */
/* ================================================================== */
int test_peer_storage_parse_roundtrip(void)
{
    unsigned char blob[50]; memset(blob, 0xEF, 50);
    unsigned char buf[200];

    /* Build and parse type 7 */
    size_t len = peer_storage_build(BOLT9_PEER_STORAGE, blob, 50,
                                     buf, sizeof(buf));
    ASSERT(len == 54, "built length = 54");

    uint16_t type_out = 0;
    unsigned char parsed[100];
    uint16_t parsed_len = 0;
    int ok = peer_storage_parse(buf, len, &type_out, parsed, &parsed_len,
                                  sizeof(parsed));
    ASSERT(ok == 1, "parse type 7 succeeds");
    ASSERT(type_out == BOLT9_PEER_STORAGE, "type = 7");
    ASSERT(parsed_len == 50, "blob_len = 50");
    ASSERT(memcmp(parsed, blob, 50) == 0, "blob round-trips");

    /* Build and parse type 9 */
    len = peer_storage_build(BOLT9_YOUR_PEER_STORAGE, blob, 50,
                              buf, sizeof(buf));
    ok = peer_storage_parse(buf, len, &type_out, parsed, &parsed_len,
                              sizeof(parsed));
    ASSERT(ok == 1, "parse type 9 succeeds");
    ASSERT(type_out == BOLT9_YOUR_PEER_STORAGE, "type = 9");

    return 1;
}

/* ================================================================== */
/* PS4 — parse rejects malformed/truncated messages                   */
/* ================================================================== */
int test_peer_storage_parse_errors(void)
{
    unsigned char blob[10]; memset(blob, 0x55, 10);
    unsigned char buf[200];
    size_t len = peer_storage_build(BOLT9_PEER_STORAGE, blob, 10,
                                     buf, sizeof(buf));

    uint16_t type_out;
    unsigned char parsed[100];
    uint16_t parsed_len;

    /* Truncated to 3 bytes (< minimum 4) */
    int ok = peer_storage_parse(buf, 3, &type_out, parsed, &parsed_len,
                                  sizeof(parsed));
    ASSERT(ok == 0, "truncated message rejected");

    /* Wrong type (use 0x0080 = update_add_htlc) */
    buf[0] = 0x00; buf[1] = 0x80;
    ok = peer_storage_parse(buf, len, &type_out, parsed, &parsed_len,
                              sizeof(parsed));
    ASSERT(ok == 0, "wrong type rejected");

    /* Restore type 7, but make blob_len larger than actual message */
    buf[0] = 0x00; buf[1] = 0x07;  /* type = 7 */
    buf[2] = 0x01; buf[3] = 0x00;  /* blob_len = 256, actual only 10 bytes */
    ok = peer_storage_parse(buf, len, &type_out, parsed, &parsed_len,
                              sizeof(parsed));
    ASSERT(ok == 0, "blob_len > message length rejected");

    /* Correct message but blob_buf_cap too small */
    size_t len2 = peer_storage_build(BOLT9_PEER_STORAGE, blob, 10,
                                      buf, sizeof(buf));
    ok = peer_storage_parse(buf, len2, &type_out, parsed, &parsed_len, 5);
    ASSERT(ok == 0, "blob_len > buf_cap rejected");

    return 1;
}
