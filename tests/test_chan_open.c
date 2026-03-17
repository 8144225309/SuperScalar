/*
 * test_chan_open.c — Unit tests for BOLT #2 channel open/accept message builders
 */

#include "superscalar/chan_open.h"
#include "superscalar/peer_mgr.h"
#include <secp256k1.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

static uint16_t get_u16(const unsigned char *b) {
    return ((uint16_t)b[0] << 8) | b[1];
}
static uint64_t get_u64(const unsigned char *b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

/* ---- Test CO1: open_channel message builds correctly ---- */
int test_chan_open_build_open_channel(void)
{
    chan_open_params_t p;
    memset(&p, 0, sizeof(p));
    p.funding_sats         = 1000000;
    p.push_msat            = 0;
    p.feerate_per_kw       = 1000;
    p.to_self_delay        = 144;
    p.max_htlc_value_msat  = 990000000ULL;
    p.channel_reserve_sats = 10000;
    p.htlc_minimum_msat    = 1;
    p.max_accepted_htlcs   = 483;
    p.announce_channel     = 1;
    memset(p.funding_pubkey, 0x02, 33);
    memset(p.revocation_basepoint, 0x03, 33);
    memset(p.payment_basepoint, 0x02, 33); p.payment_basepoint[1] = 1;
    memset(p.delayed_payment_basepoint, 0x02, 33); p.delayed_payment_basepoint[1] = 2;
    memset(p.htlc_basepoint, 0x02, 33); p.htlc_basepoint[1] = 3;
    memset(p.first_per_commitment_point, 0x02, 33); p.first_per_commitment_point[1] = 4;

    unsigned char temp_id[32];
    memset(temp_id, 0xAA, 32);

    unsigned char buf[400];
    size_t len = chan_build_open_channel(NULL, temp_id, &p, buf, sizeof(buf));
    ASSERT(len == 321, "open_channel is 321 bytes");
    ASSERT(get_u16(buf) == CHAN_MSG_OPEN_CHANNEL, "type is open_channel");
    ASSERT(memcmp(buf + 34, temp_id, 32) == 0, "temp_chan_id present");
    ASSERT(get_u64(buf + 66) == 1000000, "funding_sats correct");

    return 1;
}

/* ---- Test CO2: accept_channel message builds correctly ---- */
int test_chan_open_build_accept_channel(void)
{
    chan_open_params_t p;
    memset(&p, 0, sizeof(p));
    p.funding_sats         = 1000000;
    p.max_htlc_value_msat  = 990000000ULL;
    p.channel_reserve_sats = 10000;
    p.htlc_minimum_msat    = 1;
    p.to_self_delay        = 144;
    p.max_accepted_htlcs   = 483;
    memset(p.funding_pubkey, 0x02, 33);
    memset(p.revocation_basepoint, 0x02, 33); p.revocation_basepoint[1] = 1;
    memset(p.payment_basepoint, 0x02, 33); p.payment_basepoint[1] = 2;
    memset(p.delayed_payment_basepoint, 0x02, 33);
    memset(p.htlc_basepoint, 0x02, 33);
    memset(p.first_per_commitment_point, 0x02, 33);

    unsigned char temp_id[32];
    memset(temp_id, 0xBB, 32);

    unsigned char buf[300];
    size_t len = chan_build_accept_channel(temp_id, &p, buf, sizeof(buf));
    ASSERT(len == 272, "accept_channel is 272 bytes");
    ASSERT(get_u16(buf) == CHAN_MSG_ACCEPT_CHANNEL, "type is accept_channel");
    ASSERT(memcmp(buf + 2, temp_id, 32) == 0, "temp_chan_id matches");

    return 1;
}

/* ---- Test CO3: buffer too small returns 0 ---- */
int test_chan_open_buffer_too_small(void)
{
    chan_open_params_t p;
    memset(&p, 0, sizeof(p));
    unsigned char temp_id[32] = {0};
    unsigned char buf[10]; /* too small */

    size_t len = chan_build_open_channel(NULL, temp_id, &p, buf, sizeof(buf));
    ASSERT(len == 0, "returns 0 for undersized buffer");

    len = chan_build_accept_channel(temp_id, &p, buf, sizeof(buf));
    ASSERT(len == 0, "accept returns 0 for undersized buffer");

    return 1;
}
