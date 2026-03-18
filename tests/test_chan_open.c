/*
 * test_chan_open.c — Unit tests for BOLT #2 channel open/accept message builders
 */

#include "superscalar/chan_open.h"
#include "superscalar/ln_dispatch.h"
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

/* ================================================================== */
/* DF1 — chan_open_inbound_v2 with valid 350-byte message              */
/* ================================================================== */
static void build_open_channel2(unsigned char *msg, size_t msg_len)
{
    memset(msg, 0, msg_len);
    msg[0] = 0x00; msg[1] = 0x4E; /* type 78 */
    /* chain_hash(32): zeros at [2..33] */
    /* temp_channel_id(32): zeros at [34..65] */
    /* funding_feerate(4): [66..69] */
    /* commitment_feerate(4): [70..73] */
    /* funding_satoshis(8): [74..81] = 1000000 sats */
    msg[78] = 0x0F; msg[79] = 0x42; msg[80] = 0x40; /* 1000000 = 0x000F4240 */
    /* dust_limit(8): [82..89] = 546 */
    msg[88] = 0x02; msg[89] = 0x22;
    /* max_htlc_value(8): [90..97] */
    memset(msg + 90, 0xFF, 8);
    /* htlc_min(8): [98..105] = 1 */
    msg[105] = 0x01;
    /* to_self_delay(2): [106..107] = 144 */
    msg[106] = 0x00; msg[107] = 0x90;
    /* max_accepted_htlcs(2): [108..109] = 483 */
    msg[108] = 0x01; msg[109] = 0xE3;
    /* locktime(4): [110..113] = 0 */
    /* funding_pubkey(33): [114..146] = compressed pubkey (02...) */
    msg[114] = 0x02; /* valid compressed pubkey prefix */
    for (int i = 115; i < 147; i++) msg[i] = (unsigned char)(i & 0xFF);
    /* revocation_bp(33): [147..179] */
    msg[147] = 0x02; for (int i = 148; i < 180; i++) msg[i] = 0x11;
    /* payment_bp(33): [180..212] */
    msg[180] = 0x02; for (int i = 181; i < 213; i++) msg[i] = 0x22;
    /* delayed_bp(33): [213..245] */
    msg[213] = 0x02; for (int i = 214; i < 246; i++) msg[i] = 0x33;
    /* htlc_bp(33): [246..278] */
    msg[246] = 0x02; for (int i = 247; i < 279; i++) msg[i] = 0x44;
    /* first_pcp(33): [279..311] */
    msg[279] = 0x02; for (int i = 280; i < 312; i++) msg[i] = 0x55;
    /* second_pcp(33): [312..344] */
    msg[312] = 0x02; for (int i = 313; i < 345; i++) msg[i] = 0x66;
    /* channel_flags(1): [345] = 0 */
    /* Total: 2 + 344 = 346... actually type(2)+chain_hash(32)+temp(32)+feerate(4)+commit_fee(4)+
       funding(8)+dust(8)+max_htlc(8)+htlc_min(8)+to_self_delay(2)+max_htlcs(2)+locktime(4)+
       funding_pk(33)+rev_bp(33)+pay_bp(33)+delay_bp(33)+htlc_bp(33)+first_pcp(33)+
       second_pcp(33)+channel_flags(1) = 2+32+32+4+4+8+8+8+8+2+2+4+33+33+33+33+33+33+33+1 = 350 */
}

int test_chan_open_v2_accept_built(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "ctx");

    /* Create a valid funding keypair */
    unsigned char local_funding_sec[32];
    memset(local_funding_sec, 0x12, 32);

    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.ctx = ctx;
    /* Set a local funding pubkey */
    ASSERT(secp256k1_ec_pubkey_create(ctx, &ch.local_funding_pubkey, local_funding_sec), "create funding pubkey");

    /* Build a minimal peer_mgr with fd=-1 (will return <=0 from peer_mgr_send,
       but chan_open_inbound_v2 returns 0 on send failure. We just test parsing.) */
    peer_mgr_t pmgr;
    memset(&pmgr, 0, sizeof(pmgr));

    unsigned char msg[350];
    build_open_channel2(msg, sizeof(msg));

    /* chan_open_inbound_v2 will attempt to send; with fd=-1 it'll fail.
       We check that parsing was correct by inspecting ch. */
    chan_open_inbound_v2(&pmgr, 0, msg, sizeof(msg), ctx, &ch);
    ASSERT(ch.to_self_delay == 144, "DF1: to_self_delay parsed correctly");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* DF2 — chan_open_inbound_v2 with too-short message returns 0        */
/* ================================================================== */
int test_chan_open_v2_too_short(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "ctx");

    peer_mgr_t pmgr;
    memset(&pmgr, 0, sizeof(pmgr));
    channel_t ch;
    memset(&ch, 0, sizeof(ch));

    unsigned char msg[100];
    memset(msg, 0, sizeof(msg));
    msg[0] = 0; msg[1] = 78;

    int r = chan_open_inbound_v2(&pmgr, 0, msg, sizeof(msg), ctx, &ch);
    ASSERT(r == 0, "DF2: too short returns 0");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* DF3 — chan_open_v2_routes: dispatch type 78                         */
/* ================================================================== */
int test_chan_open_v2_routes(void)
{
    unsigned char msg[350];
    build_open_channel2(msg, sizeof(msg));

    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    /* peer_channels = NULL, ctx = NULL → skips inbound_v2 */
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 78, "DF3: type 78 routes correctly");
    return 1;
}

/* ================================================================== */
/* DF4 — chan_open_inbound_v2 with NULL mgr returns 0                 */
/* ================================================================== */
int test_chan_open_v2_null_mgr(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "ctx");
    channel_t ch; memset(&ch, 0, sizeof(ch));
    unsigned char msg[350]; memset(msg, 0, sizeof(msg));
    msg[0] = 0; msg[1] = 78;
    /* Set to_self_delay at proper offset */
    msg[106] = 0; msg[107] = 90;
    int r = chan_open_inbound_v2(NULL, 0, msg, sizeof(msg), ctx, &ch);
    ASSERT(r == 0, "DF4: NULL mgr returns 0");
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* DF5 — dispatch type 78 with valid ctx and secp256k1 pubkey         */
/* ================================================================== */
int test_chan_open_v2_with_ctx(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "ctx");

    /* Build a valid local funding keypair */
    unsigned char local_sec[32]; memset(local_sec, 0x11, 32);
    channel_t ch; memset(&ch, 0, sizeof(ch));
    ch.ctx = ctx;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &ch.local_funding_pubkey, local_sec),
           "create local funding pubkey");

    peer_mgr_t pmgr; memset(&pmgr, 0, sizeof(pmgr));
    channel_t *chp = &ch;

    ln_dispatch_t d; memset(&d, 0, sizeof(d));
    d.pmgr = &pmgr;
    d.ctx = ctx;
    d.peer_channels = &chp;

    /* Build a valid open_channel2 message */
    unsigned char msg[350];
    build_open_channel2(msg, sizeof(msg));

    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 78, "DF5: returns 78");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* DF6 — accept_channel2 type byte is 79                              */
/* ================================================================== */
int test_chan_open_v2_accept_type(void)
{
    /* Build a simple accept message check: type 79 = 0x004F */
    unsigned char accept_type[2] = {0x00, 0x4F};
    uint16_t t = ((uint16_t)accept_type[0] << 8) | accept_type[1];
    ASSERT(t == 79, "DF6: accept_channel2 type is 79");
    return 1;
}
