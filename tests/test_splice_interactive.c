/*
 * test_splice_interactive.c — Tests for BOLT #2 interactive tx construction
 * and ln_dispatch splice message handling (PR #30).
 * Reference: CLN dual_open_control.c, LDK channel.rs, Eclair ChannelTypes.scala
 */

#include "superscalar/splice.h"
#include "superscalar/ln_dispatch.h"
#include "superscalar/channel.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* SP10: tx_add_input build/parse round-trip */
int test_splice_tx_add_input(void)
{
    unsigned char cid[32], txid[32], cid_out[32], txid_out[32];
    memset(cid, 0xAA, 32); memset(txid, 0xBB, 32);
    uint64_t serial = 0x123456789ABCDEFULL;
    uint32_t vout = 2, seq = 0xFFFFFFFD;
    unsigned char buf[128];
    size_t len = splice_build_tx_add_input(cid, serial, txid, vout, seq, buf, sizeof(buf));
    ASSERT(len == 82, "tx_add_input is 82 bytes");
    uint16_t mtype = ((uint16_t)buf[0] << 8) | buf[1];
    ASSERT(mtype == MSG_TX_ADD_INPUT, "correct type 66");
    uint64_t so = 0; uint32_t vo = 0, sqo = 0;
    ASSERT(splice_parse_tx_add_input(buf, len, cid_out, &so, txid_out, &vo, &sqo), "parse ok");
    ASSERT(memcmp(cid_out, cid, 32) == 0, "cid match");
    ASSERT(so == serial, "serial match");
    ASSERT(memcmp(txid_out, txid, 32) == 0, "txid match");
    ASSERT(vo == vout, "vout match");
    ASSERT(sqo == seq, "seq match");
    return 1;
}

/* SP11: tx_add_output build/parse round-trip */
int test_splice_tx_add_output(void)
{
    unsigned char cid[32]; memset(cid, 0xCC, 32);
    unsigned char script[34]; script[0]=0x51; script[1]=0x20; memset(script+2,0xEE,32);
    uint64_t serial = 2, sats = 500000;
    unsigned char buf[256];
    size_t len = splice_build_tx_add_output(cid, serial, sats, script, 34, buf, sizeof(buf));
    ASSERT(len == 86, "tx_add_output length 52+34=86");
    uint16_t mtype = ((uint16_t)buf[0] << 8) | buf[1];
    ASSERT(mtype == MSG_TX_ADD_OUTPUT, "correct type 67");
    unsigned char co[32], so2[34]; uint64_t se2=0, sa2=0; uint16_t sl2=0;
    ASSERT(splice_parse_tx_add_output(buf, len, co, &se2, &sa2, so2, &sl2), "parse ok");
    ASSERT(memcmp(co, cid, 32) == 0, "cid match");
    ASSERT(se2 == serial, "serial match");
    ASSERT(sa2 == sats, "sats match");
    ASSERT(sl2 == 34 && memcmp(so2, script, 34) == 0, "script match");
    return 1;
}

/* SP12: tx_remove_input build/parse round-trip */
int test_splice_tx_remove_input(void)
{
    unsigned char cid[32], co[32]; memset(cid, 0xDD, 32);
    uint64_t serial = 7, so = 0;
    unsigned char buf[64];
    size_t len = splice_build_tx_remove_input(cid, serial, buf, sizeof(buf));
    ASSERT(len == 42, "tx_remove_input is 42 bytes");
    uint16_t mtype = ((uint16_t)buf[0] << 8) | buf[1];
    ASSERT(mtype == MSG_TX_REMOVE_INPUT, "correct type 68");
    ASSERT(splice_parse_tx_remove(buf, len, MSG_TX_REMOVE_INPUT, co, &so), "parse ok");
    ASSERT(memcmp(co, cid, 32) == 0, "cid match");
    ASSERT(so == serial, "serial match");
    return 1;
}

/* SP13: tx_remove_output build/parse round-trip */
int test_splice_tx_remove_output(void)
{
    unsigned char cid[32], co[32]; memset(cid, 0xEE, 32);
    uint64_t serial = 5, so = 0;
    unsigned char buf[64];
    size_t len = splice_build_tx_remove_output(cid, serial, buf, sizeof(buf));
    ASSERT(len == 42, "tx_remove_output is 42 bytes");
    uint16_t mtype = ((uint16_t)buf[0] << 8) | buf[1];
    ASSERT(mtype == MSG_TX_REMOVE_OUTPUT, "correct type 69");
    ASSERT(splice_parse_tx_remove(buf, len, MSG_TX_REMOVE_OUTPUT, co, &so), "parse ok");
    ASSERT(so == serial, "serial match");
    return 1;
}

/* SP14: tx_complete build/parse round-trip */
int test_splice_tx_complete(void)
{
    unsigned char cid[32], co[32]; memset(cid, 0xFF, 32);
    unsigned char buf[64];
    size_t len = splice_build_tx_complete(cid, buf, sizeof(buf));
    ASSERT(len == 34, "tx_complete is 34 bytes");
    uint16_t mtype = ((uint16_t)buf[0] << 8) | buf[1];
    ASSERT(mtype == MSG_TX_COMPLETE, "correct type 70");
    ASSERT(splice_parse_tx_complete(buf, len, co), "parse ok");
    ASSERT(memcmp(co, cid, 32) == 0, "cid match");
    return 1;
}

/* SP15: tx_signatures build/parse round-trip */
int test_splice_tx_signatures(void)
{
    unsigned char cid[32], txid[32]; memset(cid,0x11,32); memset(txid,0x22,32);
    unsigned char witness[64]; memset(witness, 0x33, 64);
    unsigned char buf[256];
    size_t len = splice_build_tx_signatures(cid, txid, witness, 64, buf, sizeof(buf));
    ASSERT(len == 132, "tx_signatures length 68+64=132");
    uint16_t mtype = ((uint16_t)buf[0] << 8) | buf[1];
    ASSERT(mtype == MSG_TX_SIGNATURES, "correct type 71");
    unsigned char co[32], to[32], wo[64]; uint16_t wl=0;
    ASSERT(splice_parse_tx_signatures(buf, len, co, to, wo, &wl), "parse ok");
    ASSERT(memcmp(co, cid, 32) == 0, "cid match");
    ASSERT(memcmp(to, txid, 32) == 0, "txid match");
    ASSERT(wl == 64 && memcmp(wo, witness, 64) == 0, "witness match");
    return 1;
}

/* SP16: buffer too small returns 0 */
int test_splice_tx_buf_small(void)
{
    unsigned char cid[32]; memset(cid,0,32);
    unsigned char txid[32]; memset(txid,0,32);
    unsigned char buf[10];
    ASSERT(splice_build_tx_add_input(cid,0,txid,0,0,buf,sizeof(buf))==0, "add_input small=0");
    ASSERT(splice_build_tx_remove_input(cid,0,buf,sizeof(buf))==0, "remove_input small=0");
    ASSERT(splice_build_tx_complete(cid,buf,sizeof(buf))==0, "tx_complete small=0");
    ASSERT(splice_build_tx_signatures(cid,txid,NULL,0,buf,sizeof(buf))==0, "tx_sigs small=0");
    return 1;
}

/* SP17: truncated message parse returns 0 */
int test_splice_tx_truncated(void)
{
    unsigned char cid[32]; memset(cid,0,32);
    unsigned char txid[32]; memset(txid,0,32);
    unsigned char buf[128];
    size_t len = splice_build_tx_add_input(cid,0,txid,0,0,buf,sizeof(buf));
    ASSERT(len == 82, "full build ok");
    ASSERT(!splice_parse_tx_add_input(buf,40,NULL,NULL,NULL,NULL,NULL), "truncated add_input=0");
    ASSERT(!splice_parse_tx_complete(buf,10,NULL), "truncated complete=0");
    ASSERT(!splice_parse_tx_signatures(buf,50,NULL,NULL,NULL,NULL), "truncated sigs=0");
    return 1;
}

/* SP18: wrong type rejected */
int test_splice_tx_wrong_type(void)
{
    unsigned char cid[32]; memset(cid,0,32);
    unsigned char txid[32]; memset(txid,0,32);
    unsigned char buf[128];
    splice_build_tx_complete(cid, buf, sizeof(buf));
    ASSERT(!splice_parse_tx_add_input(buf,34,NULL,NULL,NULL,NULL,NULL), "wrong type add_input=0");
    splice_build_tx_add_input(cid, 0, txid, 0, 0, buf, sizeof(buf));
    ASSERT(!splice_parse_tx_remove(buf,82,MSG_TX_REMOVE_INPUT,NULL,NULL), "wrong type remove=0");
    return 1;
}

/* SP19: ln_dispatch STFU (0x68) sets channel_quiescent=1 */
int test_splice_dispatch_stfu(void)
{
    channel_t ch; memset(&ch, 0, sizeof(ch));
    channel_t *chans[1] = { &ch };
    ln_dispatch_t d; memset(&d, 0, sizeof(d));
    d.peer_channels = chans;
    unsigned char msg[6] = {0x00, 0x68, 0x00, 0x00, 0x00, 0x01};
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == (int)SPLICE_MSG_STFU, "STFU returns 0x68");
    ASSERT(ch.channel_quiescent == 1, "channel_quiescent=1");
    return 1;
}

/* SP20: ln_dispatch splice_init (78) in quiescent channel */
int test_splice_dispatch_splice_init_quiescent(void)
{
    channel_t ch; memset(&ch, 0, sizeof(ch));
    ch.channel_quiescent = 1;
    channel_t *chans[1] = { &ch };
    ln_dispatch_t d; memset(&d, 0, sizeof(d));
    d.peer_channels = chans;
    unsigned char cid[32]; memset(cid,0,32);
    unsigned char pk[33]; memset(pk,0x02,33);
    unsigned char msg[128];
    size_t len = splice_build_splice_init(cid, 500000, 2000, pk, msg, sizeof(msg));
    ASSERT(len == 79, "splice_init 79 bytes");
    int r = ln_dispatch_process_msg(&d, 0, msg, len);
    ASSERT(r == SPLICE_MSG_SPLICE_INIT, "splice_init returns 78");
    ASSERT(ch.channel_quiescent == SPLICE_STATE_PENDING, "state=PENDING");
    return 1;
}

/* SP21: ln_dispatch splice_ack (79) */
int test_splice_dispatch_splice_ack(void)
{
    ln_dispatch_t d; memset(&d, 0, sizeof(d));
    unsigned char cid[32]; memset(cid,0,32);
    unsigned char pk[33]; memset(pk,0x02,33);
    unsigned char msg[128];
    size_t len = splice_build_splice_ack(cid, -100000LL, pk, msg, sizeof(msg));
    ASSERT(len == 75, "splice_ack 75 bytes");
    int r = ln_dispatch_process_msg(&d, 0, msg, len);
    ASSERT(r == SPLICE_MSG_SPLICE_ACK, "splice_ack returns 79");
    return 1;
}

/* SP22: ln_dispatch splice_locked (80) triggers channel_apply_splice_update */
int test_splice_dispatch_splice_locked(void)
{
    channel_t ch; memset(&ch, 0, sizeof(ch));
    ch.channel_quiescent = 1; ch.funding_amount = 500000;
    channel_t *chans[1] = { &ch };
    ln_dispatch_t d; memset(&d, 0, sizeof(d));
    d.peer_channels = chans;
    unsigned char cid[32]; memset(cid,0,32);
    unsigned char splice_txid[32]; memset(splice_txid,0x77,32);
    unsigned char msg[128];
    size_t len = splice_build_splice_locked(cid, splice_txid, msg, sizeof(msg));
    ASSERT(len == 66, "splice_locked 66 bytes");
    int r = ln_dispatch_process_msg(&d, 0, msg, len);
    ASSERT(r == SPLICE_MSG_SPLICE_LOCKED, "splice_locked returns 80");
    ASSERT(ch.channel_quiescent == 0, "quiescence cleared");
    ASSERT(memcmp(ch.funding_txid, splice_txid, 32) == 0, "funding_txid updated");
    return 1;
}

/* SP23: ln_dispatch tx_complete (70) sets channel_quiescent=2 */
int test_splice_dispatch_tx_complete(void)
{
    channel_t ch; memset(&ch, 0, sizeof(ch));
    ch.channel_quiescent = 1;
    channel_t *chans[1] = { &ch };
    ln_dispatch_t d; memset(&d, 0, sizeof(d));
    d.peer_channels = chans;
    unsigned char cid[32]; memset(cid,0,32);
    unsigned char msg[64];
    size_t len = splice_build_tx_complete(cid, msg, sizeof(msg));
    ASSERT(len == 34, "tx_complete 34 bytes");
    int r = ln_dispatch_process_msg(&d, 0, msg, len);
    ASSERT(r == MSG_TX_COMPLETE, "tx_complete returns 70");
    ASSERT(ch.channel_quiescent == 2, "state=2 after tx_complete");
    return 1;
}

/* SP24: ln_dispatch tx_add_input (66) passes through */
int test_splice_dispatch_tx_add_input(void)
{
    ln_dispatch_t d; memset(&d, 0, sizeof(d));
    unsigned char cid[32]; memset(cid,0,32);
    unsigned char txid[32]; memset(txid,0x42,32);
    unsigned char msg[128];
    size_t len = splice_build_tx_add_input(cid, 1, txid, 0, 0xFFFFFFFD, msg, sizeof(msg));
    ASSERT(len == 82, "tx_add_input 82 bytes");
    int r = ln_dispatch_process_msg(&d, 0, msg, len);
    ASSERT(r == MSG_TX_ADD_INPUT, "tx_add_input returns 66");
    return 1;
}
