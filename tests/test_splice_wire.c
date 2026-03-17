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
