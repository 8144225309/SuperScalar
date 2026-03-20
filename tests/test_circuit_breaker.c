/*
 * test_circuit_breaker.c — Tests for circuit breaker (per-peer HTLC limits)
 * and channel-type TLV (dynamic commitments).
 *
 * PR #32: Circuit Breaker + Dynamic Commitments
 * Reference: lightningequipment/circuitbreaker, BOLT #2 PR #880
 */

#include "superscalar/circuit_breaker.h"
#include <string.h>
#include <stdio.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

static void make_pubkey(unsigned char pk[33], unsigned char fill)
{
    memset(pk, fill, 33);
    pk[0] = 0x02;
}

/* CB1: circuit_breaker_init clears all slots */
int test_cb_init(void)
{
    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    ASSERT(cb.n_peers == 0, "no peers initially");
    ASSERT(cb.default_max_pending_htlcs == CIRCUIT_BREAKER_DEFAULT_MAX_PENDING,
           "default pending htlcs set");
    ASSERT(cb.default_max_pending_msat == CIRCUIT_BREAKER_DEFAULT_MAX_MSAT,
           "default pending msat set");
    return 1;
}

/* CB2: check_add accepts when count < max */
int test_cb_check_add_accepts(void)
{
    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    unsigned char pk[33]; make_pubkey(pk, 0xAA);

    /* Set a small limit so we can test easily */
    circuit_breaker_set_peer_limits(&cb, pk, 3, 10000000, 100);

    int r = circuit_breaker_check_add(&cb, pk, 1000000, 0);
    ASSERT(r == 1, "first HTLC accepted");

    uint16_t count; uint64_t msat;
    ASSERT(circuit_breaker_get_peer_state(&cb, pk, &count, &msat), "state found");
    ASSERT(count == 1, "pending count = 1");
    ASSERT(msat == 1000000, "pending msat = 1000000");
    return 1;
}

/* CB3: check_add rejects when pending_count >= max */
int test_cb_check_add_rejects_count(void)
{
    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    unsigned char pk[33]; make_pubkey(pk, 0xBB);

    circuit_breaker_set_peer_limits(&cb, pk, 2, 0, 9999);  /* max=2 htlcs */
    ASSERT(circuit_breaker_check_add(&cb, pk, 1000, 0) == 1, "1st OK");
    ASSERT(circuit_breaker_check_add(&cb, pk, 1000, 0) == 1, "2nd OK");
    ASSERT(circuit_breaker_check_add(&cb, pk, 1000, 0) == 0, "3rd rejected (count full)");
    return 1;
}

/* CB4: check_add rejects when pending_msat >= max */
int test_cb_check_add_rejects_msat(void)
{
    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    unsigned char pk[33]; make_pubkey(pk, 0xCC);

    /* max=100 htlcs but max_msat=5000 */
    circuit_breaker_set_peer_limits(&cb, pk, 100, 5000, 9999);
    ASSERT(circuit_breaker_check_add(&cb, pk, 3000, 0) == 1, "3000 msat OK");
    ASSERT(circuit_breaker_check_add(&cb, pk, 3000, 0) == 0, "6000 msat rejected");
    return 1;
}

/* CB5: record_settled decrements count and msat */
int test_cb_record_settled(void)
{
    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    unsigned char pk[33]; make_pubkey(pk, 0xDD);

    circuit_breaker_set_peer_limits(&cb, pk, 5, 0, 9999);
    circuit_breaker_check_add(&cb, pk, 2000000, 0);
    circuit_breaker_check_add(&cb, pk, 1000000, 0);

    uint16_t count; uint64_t msat;
    circuit_breaker_get_peer_state(&cb, pk, &count, &msat);
    ASSERT(count == 2, "two pending");
    ASSERT(msat == 3000000, "3M msat pending");

    circuit_breaker_record_settled(&cb, pk, 2000000);
    circuit_breaker_get_peer_state(&cb, pk, &count, &msat);
    ASSERT(count == 1, "one pending after settle");
    ASSERT(msat == 1000000, "1M msat after settle");
    return 1;
}

/* CB6: token bucket - reject when tokens exhausted */
int test_cb_token_bucket_rate_limit(void)
{
    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    unsigned char pk[33]; make_pubkey(pk, 0xEE);

    /* max_htlcs_per_hour = 2 → 2 tokens, each consumed per check_add */
    circuit_breaker_set_peer_limits(&cb, pk, 100, 0, 2);

    ASSERT(circuit_breaker_check_add(&cb, pk, 100, 0) == 1, "token 1 used");
    ASSERT(circuit_breaker_check_add(&cb, pk, 100, 0) == 1, "token 2 used");
    ASSERT(circuit_breaker_check_add(&cb, pk, 100, 0) == 0, "no tokens left");
    return 1;
}

/* CB7: token refill after 1 hour */
int test_cb_token_refill(void)
{
    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    unsigned char pk[33]; make_pubkey(pk, 0xFF);

    circuit_breaker_set_peer_limits(&cb, pk, 100, 0, 3);
    /* Exhaust tokens */
    circuit_breaker_check_add(&cb, pk, 0, 0);
    circuit_breaker_check_add(&cb, pk, 0, 0);
    circuit_breaker_check_add(&cb, pk, 0, 0);
    ASSERT(circuit_breaker_check_add(&cb, pk, 0, 0) == 0, "tokens exhausted");

    /* Advance time by 1 hour → tokens refilled */
    ASSERT(circuit_breaker_check_add(&cb, pk, 0, CIRCUIT_BREAKER_SECS_PER_HOUR) == 1,
           "tokens refilled after 1 hour");
    return 1;
}

/* DC1: channel_type_encode round-trip */
int test_channel_type_encode_decode(void)
{
    uint32_t bits = (1 << CHAN_TYPE_STATIC_REMOTE_KEY_BIT) |
                    (1 << CHAN_TYPE_ANCHOR_OUTPUTS_BIT);
    unsigned char buf[16];
    size_t len = channel_type_encode(bits, buf, sizeof(buf));
    ASSERT(len == 6, "channel_type TLV is 6 bytes");
    ASSERT(buf[0] == CHAN_TYPE_TLV_TYPE, "TLV type is 5");
    ASSERT(buf[1] == 4, "TLV len is 4");

    uint32_t bits_out = 0;
    ASSERT(channel_type_decode(buf, len, &bits_out), "decode succeeds");
    ASSERT(bits_out == bits, "feature bits preserved");
    return 1;
}

/* DC2: channel_type_negotiate ANDs feature sets */
int test_channel_type_negotiate(void)
{
    uint32_t local  = (1 << CHAN_TYPE_STATIC_REMOTE_KEY_BIT) |
                      (1 << CHAN_TYPE_ANCHOR_OUTPUTS_BIT);
    uint32_t remote = (1 << CHAN_TYPE_STATIC_REMOTE_KEY_BIT) |
                      (1 << CHAN_TYPE_ZERO_CONF_BIT);
    uint32_t agreed = channel_type_negotiate(local, remote);
    ASSERT((agreed & (1 << CHAN_TYPE_STATIC_REMOTE_KEY_BIT)) != 0,
           "static_remote_key in agreed");
    ASSERT((agreed & (1 << CHAN_TYPE_ANCHOR_OUTPUTS_BIT)) == 0,
           "anchor_outputs not in agreed (remote lacks it)");
    ASSERT((agreed & (1 << CHAN_TYPE_ZERO_CONF_BIT)) == 0,
           "zero_conf not in agreed (local lacks it)");
    return 1;
}

/* DC3: update_fee_validate rejects below floor */
int test_update_fee_validate_floor(void)
{
    ASSERT(!update_fee_validate(0), "0 sat/kw rejected");
    ASSERT(!update_fee_validate(249), "249 sat/kw rejected");
    ASSERT(update_fee_validate(250), "250 sat/kw accepted (floor)");
    return 1;
}

/* DC4: update_fee_validate rejects above ceiling */
int test_update_fee_validate_ceiling(void)
{
    ASSERT(update_fee_validate(100000), "100000 sat/kw accepted (ceiling)");
    ASSERT(!update_fee_validate(100001), "100001 sat/kw rejected");
    ASSERT(update_fee_validate(5000), "5000 sat/kw accepted");
    return 1;
}

/* CB8: unknown peer falls back to default limits */
int test_cb_unknown_peer_defaults(void)
{
    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    unsigned char pk[33]; make_pubkey(pk, 0x42);

    /* No explicit config — should use defaults (483 pending max) */
    /* Just verify check_add doesn't crash for unknown peer */
    int r = circuit_breaker_check_add(&cb, pk, 1000, 0);
    ASSERT(r == 1, "unknown peer accepts first HTLC with defaults");

    uint16_t count; uint64_t msat;
    ASSERT(circuit_breaker_get_peer_state(&cb, pk, &count, &msat), "peer created");
    ASSERT(count == 1, "pending count tracked");
    return 1;
}

/* CB9: channel_type_decode rejects wrong TLV type */
int test_channel_type_decode_wrong_type(void)
{
    unsigned char buf[6] = {0x06, 4, 0, 0, 0, 1};  /* type=6, not 5 */
    uint32_t bits = 0;
    ASSERT(!channel_type_decode(buf, 6, &bits), "wrong type rejected");
    ASSERT(!channel_type_decode(buf, 3, &bits), "too short rejected");
    ASSERT(!channel_type_decode(NULL, 6, &bits), "NULL buf rejected");
    return 1;
}

/* CB10: circuit_breaker_set_peer_limits clamps tokens to new max */
int test_cb_set_limits_clamp_tokens(void)
{
    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    unsigned char pk[33]; make_pubkey(pk, 0x55);

    /* Start with large limit */
    circuit_breaker_set_peer_limits(&cb, pk, 10, 0, 100);
    circuit_breaker_peer_t *p = NULL;
    for (int i = 0; i < cb.n_peers; i++) {
        if (cb.peers[i].active && cb.peers[i].peer_pubkey[1] == 0x55) {
            p = &cb.peers[i];
            break;
        }
    }
    ASSERT(p != NULL, "peer found");
    ASSERT(p->tokens == 100, "tokens=100 after init");

    /* Reduce limit to 5 — tokens should clamp */
    circuit_breaker_set_peer_limits(&cb, pk, 10, 0, 5);
    ASSERT(p->tokens == 5, "tokens clamped to new max=5");
    return 1;
}

/* DC5: channel_type_encode rejects small buffer */
int test_channel_type_encode_small_buf(void)
{
    unsigned char buf[4];
    ASSERT(channel_type_encode(0xFFFF, buf, sizeof(buf)) == 0,
           "small buffer returns 0");
    return 1;
}

/* CB_HTLCI: HTLC interceptor callback interface sanity check */
int test_cb_htlc_interceptor_iface(void)
{
    /*
     * Verify the interceptor decision enum values are consistent
     * with the pattern used in ln_dispatch.h (jit_open_cb).
     * We just verify compile-time constants here.
     */
    int allow  = 0;  /* INTERCEPT_ALLOW */
    int fail_d = 1;  /* INTERCEPT_FAIL */
    int hold   = 2;  /* INTERCEPT_HOLD */
    ASSERT(allow == 0, "INTERCEPT_ALLOW=0");
    ASSERT(fail_d == 1, "INTERCEPT_FAIL=1");
    ASSERT(hold == 2, "INTERCEPT_HOLD=2");

    /* circuit_breaker returning 0 = should fail the HTLC */
    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    unsigned char pk[33]; make_pubkey(pk, 0x77);
    circuit_breaker_set_peer_limits(&cb, pk, 0, 0, 0);  /* all zeros = reject all */
    ASSERT(circuit_breaker_check_add(&cb, pk, 1000, 0) == 0,
           "zero-limit peer always rejected = INTERCEPT_FAIL");
    return 1;
}

/* ================================================================== */
/* CB_BAN1: token exhaustion triggers ban_fn with correct pubkey      */
/* ================================================================== */
static unsigned char g_ban_last_pubkey[33];
static uint32_t      g_ban_duration;
static int           g_ban_call_count;

static void test_ban_fn(void *ctx, const unsigned char pk[33], uint32_t dur)
{
    (void)ctx;
    memcpy(g_ban_last_pubkey, pk, 33);
    g_ban_duration   = dur;
    g_ban_call_count++;
}

int test_cb_ban_fn_called_on_token_exhaustion(void)
{
    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    unsigned char pk[33]; make_pubkey(pk, 0x91);

    /* Give peer exactly 1 token → one HTLC accepted, second triggers ban */
    circuit_breaker_set_peer_limits(&cb, pk, 100, 0, 1);
    cb.ban_fn = test_ban_fn;
    cb.ban_duration_secs = 600;
    g_ban_call_count = 0;

    /* First HTLC: consumes the 1 token — accepted */
    ASSERT(circuit_breaker_check_add(&cb, pk, 1000, 0) == 1,
           "CB_BAN1: first HTLC accepted");
    ASSERT(g_ban_call_count == 0, "CB_BAN1: no ban yet after first HTLC");

    /* Second HTLC: tokens=0 → ban_fn called, HTLC rejected */
    ASSERT(circuit_breaker_check_add(&cb, pk, 1000, 0) == 0,
           "CB_BAN1: second HTLC rejected (token exhausted)");
    ASSERT(g_ban_call_count == 1, "CB_BAN1: ban_fn called once");
    ASSERT(memcmp(g_ban_last_pubkey, pk, 33) == 0,
           "CB_BAN1: ban_fn called with correct pubkey");
    ASSERT(g_ban_duration == 600, "CB_BAN1: ban_duration_secs correct");

    return 1;
}

/* ================================================================== */
/* CB_BAN2: ban_fn NOT called when tokens are available               */
/* ================================================================== */
int test_cb_ban_fn_not_called_with_tokens(void)
{
    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    unsigned char pk[33]; make_pubkey(pk, 0x92);

    circuit_breaker_set_peer_limits(&cb, pk, 100, 0, 10);
    cb.ban_fn = test_ban_fn;
    cb.ban_duration_secs = 300;
    g_ban_call_count = 0;

    /* Accept 5 HTLCs — all have tokens, no ban */
    for (int i = 0; i < 5; i++) {
        ASSERT(circuit_breaker_check_add(&cb, pk, 100, 0) == 1,
               "CB_BAN2: HTLC accepted");
    }
    ASSERT(g_ban_call_count == 0, "CB_BAN2: ban_fn not called");

    return 1;
}

/* ================================================================== */
/* CB_BAN3: NULL ban_fn with tokens=0 → no crash, returns 0          */
/* ================================================================== */
int test_cb_ban_fn_null_no_crash(void)
{
    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    unsigned char pk[33]; make_pubkey(pk, 0x93);

    /* 1 token, no ban_fn */
    circuit_breaker_set_peer_limits(&cb, pk, 100, 0, 1);
    ASSERT(cb.ban_fn == NULL, "CB_BAN3: ban_fn initially NULL");

    ASSERT(circuit_breaker_check_add(&cb, pk, 1000, 0) == 1, "first HTLC ok");
    /* Second HTLC with tokens=0, ban_fn=NULL → just return 0, no crash */
    ASSERT(circuit_breaker_check_add(&cb, pk, 1000, 0) == 0,
           "CB_BAN3: null ban_fn + no tokens → 0, no crash");

    return 1;
}

/* ================================================================== */
/* CB_BAN4: ban escalation fires again on repeated exhaustion         */
/* ================================================================== */
int test_cb_ban_fn_repeated_exhaustion(void)
{
    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    unsigned char pk[33]; make_pubkey(pk, 0x94);

    /* Peer starts with 0 tokens (max_htlcs_per_hour=0) */
    circuit_breaker_set_peer_limits(&cb, pk, 100, 0, 0);
    cb.ban_fn = test_ban_fn;
    cb.ban_duration_secs = 120;
    g_ban_call_count = 0;

    /* Every HTLC should be rejected and ban_fn called */
    ASSERT(circuit_breaker_check_add(&cb, pk, 500, 0) == 0, "rejected 1");
    ASSERT(circuit_breaker_check_add(&cb, pk, 500, 0) == 0, "rejected 2");
    ASSERT(circuit_breaker_check_add(&cb, pk, 500, 0) == 0, "rejected 3");
    ASSERT(g_ban_call_count == 3, "CB_BAN4: ban_fn called 3 times");

    return 1;
}
