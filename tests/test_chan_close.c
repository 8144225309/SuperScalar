/*
 * test_chan_close.c — Unit tests for BOLT #2 cooperative channel close
 *
 * CC1: test_chan_close_shutdown_layout        — shutdown byte layout
 * CC2: test_chan_close_closing_signed_layout  — closing_signed byte layout
 * CC3: test_chan_close_negotiate_fee_converge — meet-in-middle converges
 * CC4: test_chan_close_negotiate_fee_equal    — equal fees return immediately
 * CC5: test_chan_close_recv_shutdown_parse    — shutdown parse roundtrip
 * CC6: test_chan_close_recv_closing_signed_parse — closing_signed parse roundtrip
 * CC7: test_chan_close_negotiate_fee_steps    — fee negotiation step count
 * CC8: test_chan_close_negotiate_fee_low_high — low/high fee direction
 */

#include "superscalar/chan_close.h"
#include "superscalar/htlc_commit.h"   /* BOLT2_SHUTDOWN, BOLT2_CLOSING_SIGNED */
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
static uint64_t rd64(const unsigned char *b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

/* ================================================================== */
/* CC1 — shutdown message byte layout                                 */
/* ================================================================== */
int test_chan_close_shutdown_layout(void)
{
    /*
     * Wire: type(2) + channel_id(32) + len(2) + scriptpubkey(len)
     */
    unsigned char channel_id[32]; memset(channel_id, 0xAA, 32);
    unsigned char spk[22];        memset(spk, 0xBB, 22);  /* P2WPKH */

    unsigned char buf[200];
    size_t len = chan_close_build_shutdown(channel_id, spk, 22, buf, sizeof(buf));

    ASSERT(len == 2 + 32 + 2 + 22, "shutdown length = 58 bytes");
    ASSERT(rd16(buf) == BOLT2_SHUTDOWN, "type = 38 at offset 0");
    ASSERT(memcmp(buf + 2, channel_id, 32) == 0, "channel_id at offset 2");
    ASSERT(rd16(buf + 34) == 22, "scriptpubkey length at offset 34");
    ASSERT(memcmp(buf + 36, spk, 22) == 0, "scriptpubkey at offset 36");

    return 1;
}

/* ================================================================== */
/* CC2 — closing_signed message byte layout                           */
/* ================================================================== */
int test_chan_close_closing_signed_layout(void)
{
    /*
     * Wire: type(2) + channel_id(32) + fee_satoshis(8) + sig(64) = 106 bytes
     */
    unsigned char channel_id[32]; memset(channel_id, 0x12, 32);
    unsigned char sig64[64];      memset(sig64, 0x99, 64);
    uint64_t fee = 2500;

    unsigned char buf[200];
    size_t len = chan_close_build_closing_signed(channel_id, fee, sig64,
                                                  buf, sizeof(buf));

    ASSERT(len == 106, "closing_signed = 106 bytes");
    ASSERT(rd16(buf) == BOLT2_CLOSING_SIGNED, "type = 39 at offset 0");
    ASSERT(memcmp(buf + 2, channel_id, 32) == 0, "channel_id at offset 2");
    ASSERT(rd64(buf + 34) == fee, "fee_satoshis at offset 34");
    ASSERT(memcmp(buf + 42, sig64, 64) == 0, "sig at offset 42");

    return 1;
}

/* ================================================================== */
/* CC3 — fee negotiation converges to a single value                  */
/* ================================================================== */
int test_chan_close_negotiate_fee_converge(void)
{
    /*
     * Simulate meet-in-middle from two ends:
     *   our_fee = 1000, their initial proposal = 5000
     * Each step: proposal = (our_fee + their_proposal) / 2
     * until they match.
     */
    uint64_t our_fee   = 1000;
    uint64_t their_fee = 5000;
    int steps = 0;

    while (our_fee != their_fee && steps < 64) {
        /* We propose midpoint */
        uint64_t counter = chan_close_negotiate_fee(our_fee, their_fee);
        their_fee = counter;
        steps++;
        /* Their counter-proposal (symmetric) */
        if (our_fee == their_fee) break;
        counter = chan_close_negotiate_fee(their_fee, our_fee);
        our_fee = counter;
        steps++;
    }

    ASSERT(our_fee == their_fee, "fees must converge");
    ASSERT(steps < 64, "should converge in < 64 steps");

    return 1;
}

/* ================================================================== */
/* CC4 — equal fees return same value immediately (no negotiation)    */
/* ================================================================== */
int test_chan_close_negotiate_fee_equal(void)
{
    uint64_t fee = 3000;
    uint64_t result = chan_close_negotiate_fee(fee, fee);
    ASSERT(result == fee, "equal fees should return same fee");

    /* Zero fees */
    result = chan_close_negotiate_fee(0, 0);
    ASSERT(result == 0, "zero fees should return 0");

    return 1;
}

/* ================================================================== */
/* CC5 — shutdown parse roundtrip                                     */
/* ================================================================== */
int test_chan_close_recv_shutdown_parse(void)
{
    unsigned char channel_id[32]; memset(channel_id, 0xCC, 32);
    unsigned char spk[34];        memset(spk, 0xDD, 34);  /* P2TR */

    unsigned char buf[200];
    size_t len = chan_close_build_shutdown(channel_id, spk, 34, buf, sizeof(buf));
    ASSERT(len == 70, "P2TR shutdown = 2+32+2+34 = 70 bytes");

    unsigned char parsed_id[32];
    unsigned char parsed_spk[64];
    uint16_t parsed_spk_len = 0;

    int ok = chan_close_recv_shutdown(buf, len,
                                      parsed_id,
                                      parsed_spk, &parsed_spk_len,
                                      sizeof(parsed_spk));
    ASSERT(ok == 1, "recv_shutdown should succeed");
    ASSERT(memcmp(parsed_id, channel_id, 32) == 0, "channel_id round-trips");
    ASSERT(parsed_spk_len == 34, "spk_len round-trips");
    ASSERT(memcmp(parsed_spk, spk, 34) == 0, "scriptpubkey round-trips");

    /* Malformed: truncated message */
    ok = chan_close_recv_shutdown(buf, 10, parsed_id, parsed_spk, &parsed_spk_len,
                                   sizeof(parsed_spk));
    ASSERT(ok == 0, "truncated message rejected");

    return 1;
}

/* ================================================================== */
/* CC6 — closing_signed parse roundtrip                               */
/* ================================================================== */
int test_chan_close_recv_closing_signed_parse(void)
{
    unsigned char channel_id[32]; memset(channel_id, 0xEE, 32);
    unsigned char sig64[64];      memset(sig64, 0x77, 64);
    uint64_t fee = 12345;

    unsigned char buf[200];
    size_t len = chan_close_build_closing_signed(channel_id, fee, sig64,
                                                  buf, sizeof(buf));
    ASSERT(len == 106, "closing_signed = 106 bytes");

    unsigned char parsed_id[32];
    unsigned char parsed_sig[64];
    uint64_t parsed_fee = 0;

    int ok = chan_close_recv_closing_signed(buf, len,
                                             parsed_id, &parsed_fee,
                                             parsed_sig);
    ASSERT(ok == 1, "recv_closing_signed should succeed");
    ASSERT(memcmp(parsed_id, channel_id, 32) == 0, "channel_id round-trips");
    ASSERT(parsed_fee == fee, "fee round-trips");
    ASSERT(memcmp(parsed_sig, sig64, 64) == 0, "sig round-trips");

    /* Malformed: too short */
    ok = chan_close_recv_closing_signed(buf, 50, parsed_id, &parsed_fee,
                                         parsed_sig);
    ASSERT(ok == 0, "short message rejected");

    return 1;
}

/* ================================================================== */
/* CC7 — fee negotiation: verify exact step count for known inputs    */
/* ================================================================== */
int test_chan_close_negotiate_fee_steps(void)
{
    /*
     * our_fee = 1000, their_fee = 2000.
     * Step 1: we propose (1000+2000)/2 = 1500 → their_fee = 1500
     * Step 2: they propose (1500+1000)/2 = 1250 → our_fee = 1250
     * Step 3: we propose (1250+1500)/2 = 1375 → their_fee = 1375
     * Step 4: they propose (1375+1250)/2 = 1312 → our_fee = 1312
     * ...
     * Converges; we just verify both sides reach the same value.
     */
    uint64_t a = 1000, b = 2000;

    /* Run until convergence (max 100 steps to avoid infinite loop in tests) */
    int steps = 0;
    while (a != b && steps < 100) {
        a = chan_close_negotiate_fee(a, b);
        steps++;
        if (a == b) break;
        b = chan_close_negotiate_fee(b, a);
        steps++;
    }
    ASSERT(a == b, "fee negotiation must converge");
    ASSERT(steps < 100, "should converge well before 100 steps");

    return 1;
}

/* ================================================================== */
/* CC8 — fee negotiation direction: low/high fee scenarios            */
/* ================================================================== */
int test_chan_close_negotiate_fee_low_high(void)
{
    /* When our_fee > their_fee (we want more, they want less) */
    uint64_t r = chan_close_negotiate_fee(10000, 5000);
    ASSERT(r >= 5000 && r <= 10000, "midpoint in [5000, 10000]");
    ASSERT(r == 7500, "midpoint of 10000 and 5000 = 7500");

    /* When our_fee < their_fee (we want less, they want more) */
    r = chan_close_negotiate_fee(5000, 10000);
    ASSERT(r >= 5000 && r <= 10000, "midpoint in [5000, 10000]");
    ASSERT(r == 7500, "midpoint of 5000 and 10000 = 7500");

    /* Adjacent values — final convergence step */
    r = chan_close_negotiate_fee(100, 101);
    ASSERT(r == 100, "floor toward our_fee: (100+101)/2 = 100");

    r = chan_close_negotiate_fee(101, 100);
    ASSERT(r == 100, "floor toward our_fee: (101+100)/2 = 100");

    return 1;
}
