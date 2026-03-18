/*
 * test_splice_wire.c — Unit tests for splice wire protocol (Phase 5)
 */

#include "superscalar/splice.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* ---- Test SW1: splice_init round-trip ---- */
int test_splice_wire_init_roundtrip(void)
{
    unsigned char chan_id[32];
    memset(chan_id, 0xAA, 32);
    int64_t relative_sats = 500000;
    uint32_t feerate = 2000;
    unsigned char funding_pk[33];
    memset(funding_pk, 0x02, 33);
    funding_pk[1] = 0x42;

    unsigned char buf[128];
    size_t len = splice_build_splice_init(chan_id, relative_sats, feerate,
                                           funding_pk, buf, sizeof(buf));
    ASSERT(len == 79, "splice_init is 79 bytes");

    /* Check wire type */
    uint16_t msg_type = ((uint16_t)buf[0] << 8) | buf[1];
    ASSERT(msg_type == SPLICE_MSG_SPLICE_INIT, "correct message type");

    /* Parse back */
    unsigned char chan_id_out[32];
    int64_t rel_out;
    uint32_t feerate_out;
    unsigned char pk_out[33];
    ASSERT(splice_parse_splice_init(buf, len, chan_id_out, &rel_out,
                                     &feerate_out, pk_out),
           "parse succeeds");
    ASSERT(memcmp(chan_id_out, chan_id, 32) == 0, "channel_id matches");
    ASSERT(rel_out == relative_sats, "relative_satoshis matches");
    ASSERT(feerate_out == feerate, "feerate matches");
    ASSERT(memcmp(pk_out, funding_pk, 33) == 0, "funding_pubkey matches");

    return 1;
}

/* ---- Test SW2: splice_ack round-trip ---- */
int test_splice_wire_ack(void)
{
    unsigned char chan_id[32];
    memset(chan_id, 0xBB, 32);
    int64_t rel = -100000; /* decrease */
    unsigned char pk[33];
    memset(pk, 0x03, 33);

    unsigned char buf[128];
    size_t len = splice_build_splice_ack(chan_id, rel, pk, buf, sizeof(buf));
    ASSERT(len == 75, "splice_ack is 75 bytes");

    uint16_t msg_type = ((uint16_t)buf[0] << 8) | buf[1];
    ASSERT(msg_type == SPLICE_MSG_SPLICE_ACK, "correct ack type");

    return 1;
}

/* ---- Test SW3: splice_locked round-trip ---- */
int test_splice_wire_locked(void)
{
    unsigned char chan_id[32];
    memset(chan_id, 0xCC, 32);
    unsigned char splice_txid[32];
    memset(splice_txid, 0x11, 32);
    splice_txid[0] = 0xAB;

    unsigned char buf[128];
    size_t len = splice_build_splice_locked(chan_id, splice_txid, buf, sizeof(buf));
    ASSERT(len == 66, "splice_locked is 66 bytes");

    uint16_t msg_type = ((uint16_t)buf[0] << 8) | buf[1];
    ASSERT(msg_type == SPLICE_MSG_SPLICE_LOCKED, "correct locked type");

    unsigned char chan_id_out[32], txid_out[32];
    ASSERT(splice_parse_splice_locked(buf, len, chan_id_out, txid_out),
           "parse locked succeeds");
    ASSERT(memcmp(chan_id_out, chan_id, 32) == 0, "channel_id matches");
    ASSERT(memcmp(txid_out, splice_txid, 32) == 0, "splice_txid matches");

    return 1;
}

/* ---- Test SW4: stfu build/parse ---- */
int test_splice_wire_stfu(void)
{
    size_t len_out = 0;
    unsigned char *payload = splice_build_stfu(42, &len_out);
    ASSERT(payload != NULL, "stfu build succeeds");
    ASSERT(len_out == 4, "stfu payload is 4 bytes");

    uint32_t chan_id_out = 0;
    ASSERT(splice_parse_stfu_ack(payload, len_out, &chan_id_out),
           "stfu parse succeeds");
    ASSERT(chan_id_out == 42, "channel_id matches");

    free(payload);
    return 1;
}

/* ---- Test SW5: buffer too small returns 0 ---- */
int test_splice_wire_buffer_small(void)
{
    unsigned char chan_id[32] = {0};
    unsigned char pk[33] = {0};
    unsigned char buf[10];

    ASSERT(splice_build_splice_init(chan_id, 0, 0, pk, buf, sizeof(buf)) == 0,
           "splice_init returns 0 for small buffer");
    ASSERT(splice_build_splice_ack(chan_id, 0, pk, buf, sizeof(buf)) == 0,
           "splice_ack returns 0 for small buffer");
    ASSERT(splice_build_splice_locked(chan_id, chan_id, buf, sizeof(buf)) == 0,
           "splice_locked returns 0 for small buffer");
    return 1;
}

/* ---- Test SW6: splice_ack build → parse roundtrip ---- */
int test_splice_wire_parse_ack(void)
{
    unsigned char chan_id[32];
    memset(chan_id, 0xDD, 32);
    int64_t rel = -250000;
    unsigned char pk[33];
    memset(pk, 0x03, 33);
    pk[1] = 0x77;

    unsigned char buf[128];
    size_t len = splice_build_splice_ack(chan_id, rel, pk, buf, sizeof(buf));
    ASSERT(len == 75, "splice_ack is 75 bytes");

    unsigned char chan_id_out[32];
    int64_t rel_out = 0;
    unsigned char pk_out[33];
    ASSERT(splice_parse_splice_ack(buf, len, chan_id_out, &rel_out, pk_out),
           "parse_splice_ack succeeds");
    ASSERT(memcmp(chan_id_out, chan_id, 32) == 0, "channel_id matches");
    ASSERT(rel_out == rel, "relative_satoshis matches");
    ASSERT(memcmp(pk_out, pk, 33) == 0, "funding_pubkey matches");

    return 1;
}

/* ---- Test SW7: splicing_signed build → parse roundtrip ---- */
int test_splice_wire_splicing_signed(void)
{
    unsigned char chan_id[32];
    memset(chan_id, 0xEE, 32);
    unsigned char sig[64];
    memset(sig, 0x55, 64);
    sig[0] = 0xAB; sig[63] = 0xCD;

    unsigned char buf[128];
    size_t len = splice_build_splicing_signed(chan_id, sig, buf, sizeof(buf));
    ASSERT(len == 98, "splicing_signed is 98 bytes");

    uint16_t msg_type = ((uint16_t)buf[0] << 8) | buf[1];
    ASSERT(msg_type == MSG_SPLICING_SIGNED, "correct wire type 0x004b");

    unsigned char chan_id_out[32], sig_out[64];
    ASSERT(splice_parse_splicing_signed(buf, len, chan_id_out, sig_out),
           "parse splicing_signed succeeds");
    ASSERT(memcmp(chan_id_out, chan_id, 32) == 0, "channel_id matches");
    ASSERT(memcmp(sig_out, sig, 64) == 0, "partial_sig matches");

    return 1;
}

/* ---- Test SW8: parse rejects wrong message type ---- */
int test_splice_wire_wrong_type(void)
{
    unsigned char chan_id[32] = {0};
    unsigned char sig[64] = {0};
    unsigned char buf[128];

    /* Build a valid splice_ack, then try to parse as splicing_signed */
    unsigned char pk[33] = {0x02};
    size_t len = splice_build_splice_ack(chan_id, 0, pk, buf, sizeof(buf));
    ASSERT(len > 0, "build succeeds");
    ASSERT(!splice_parse_splicing_signed(buf, len, chan_id, sig),
           "wrong type rejected by splicing_signed parser");

    /* Build valid splicing_signed, try to parse as splice_ack */
    len = splice_build_splicing_signed(chan_id, sig, buf, sizeof(buf));
    ASSERT(len > 0, "build succeeds");
    unsigned char pk_out[33];
    int64_t rel_out = 0;
    ASSERT(!splice_parse_splice_ack(buf, len, chan_id, &rel_out, pk_out),
           "wrong type rejected by splice_ack parser");

    return 1;
}

/* ---- Test SW9: parse rejects truncated message ---- */
int test_splice_wire_truncated(void)
{
    unsigned char chan_id[32] = {0};
    unsigned char sig[64] = {0};
    unsigned char buf[128];

    /* splicing_signed requires 98 bytes; truncate to 50 */
    size_t len = splice_build_splicing_signed(chan_id, sig, buf, sizeof(buf));
    ASSERT(len == 98, "full build succeeded");
    ASSERT(!splice_parse_splicing_signed(buf, 50, chan_id, sig),
           "truncated splicing_signed rejected");

    /* splice_ack requires 75 bytes; truncate to 40 */
    unsigned char pk[33] = {0x02};
    len = splice_build_splice_ack(chan_id, 0, pk, buf, sizeof(buf));
    ASSERT(len == 75, "full ack build succeeded");
    int64_t rel_out = 0;
    ASSERT(!splice_parse_splice_ack(buf, 40, chan_id, &rel_out, pk),
           "truncated splice_ack rejected");

    return 1;
}
