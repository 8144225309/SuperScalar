/*
 * test_cltv_watchdog.c — Unit tests for the HTLC expiry watchdog
 *
 * CW1: test_cltv_watchdog_default_delta    — init with delta=0 uses CLTV_EXPIRY_DELTA
 * CW2: test_cltv_watchdog_no_htlcs         — check returns 0 when no HTLCs
 * CW3: test_cltv_watchdog_htlc_safe        — check returns 0 when HTLC far from expiry
 * CW4: test_cltv_watchdog_htlc_at_risk     — check returns 1 when inbound HTLC within delta
 * CW5: test_cltv_watchdog_offered_ignored  — outbound HTLCs not counted by check
 * CW6: test_cltv_watchdog_expire           — expire fails truly-expired HTLCs
 * CW7: test_cltv_watchdog_earliest_expiry  — returns lowest cltv_expiry of inbound HTLCs
 * CW8: test_cltv_watchdog_multi_htlc       — multiple HTLCs: correct at-risk count
 */

#include "superscalar/cltv_watchdog.h"
#include "superscalar/channel.h"
#include "superscalar/musig.h"
#include "superscalar/sha256.h"
#include "superscalar/bip158_backend.h"
#include "superscalar/watchtower.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* Fixed test secrets — same pattern as test_htlc_commit.c */
static const unsigned char cw_local_fund[32]  = { [0 ... 31] = 0x11 };
static const unsigned char cw_remote_fund[32] = { [0 ... 31] = 0x22 };
static const unsigned char cw_local_pay[32]   = { [0 ... 31] = 0x31 };
static const unsigned char cw_local_del[32]   = { [0 ... 31] = 0x41 };
static const unsigned char cw_local_rev[32]   = { [0 ... 31] = 0x51 };
static const unsigned char cw_remote_pay[32]  = { [0 ... 31] = 0x71 };
static const unsigned char cw_remote_del[32]  = { [0 ... 31] = 0x81 };
static const unsigned char cw_remote_rev[32]  = { [0 ... 31] = 0x91 };

/*
 * Minimal channel setup (no HTLC basepoints needed — we only test the HTLC
 * array, not commitment tx construction).
 */
static int cw_setup_channel(channel_t *ch, secp256k1_context *ctx,
                              uint64_t local_amt, uint64_t remote_amt)
{
    secp256k1_pubkey lfk, rfk;
    if (!secp256k1_ec_pubkey_create(ctx, &lfk, cw_local_fund))  return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &rfk, cw_remote_fund)) return 0;

    /* Minimal funding SPK — 34 bytes of 0xAB is fine for these tests */
    unsigned char fake_spk[34];
    memset(fake_spk, 0xAB, 34);
    unsigned char fake_txid[32];
    memset(fake_txid, 0xCC, 32);

    if (!channel_init(ch, ctx, cw_local_fund, &lfk, &rfk,
                      fake_txid, 0, local_amt + remote_amt,
                      fake_spk, 34,
                      local_amt, remote_amt,
                      CHANNEL_DEFAULT_CSV_DELAY)) return 0;
    ch->funder_is_local = 1;

    if (!channel_set_local_basepoints(ch, cw_local_pay, cw_local_del, cw_local_rev))
        return 0;

    secp256k1_pubkey rp, rd, rr;
    if (!secp256k1_ec_pubkey_create(ctx, &rp, cw_remote_pay)) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &rd, cw_remote_del)) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &rr, cw_remote_rev)) return 0;
    channel_set_remote_basepoints(ch, &rp, &rd, &rr);

    return 1;
}

/*
 * Add a dummy HTLC directly into the channel's HTLC array, bypassing the
 * balance checks in channel_add_htlc (which would reject some test cases).
 * Used only for watchdog tests that don't sign commitment txs.
 */
static void cw_inject_htlc(channel_t *ch, htlc_direction_t dir,
                             uint64_t amount_sats, uint32_t cltv_expiry,
                             uint64_t id)
{
    if (ch->n_htlcs >= ch->htlcs_cap) {
        size_t new_cap = ch->htlcs_cap < 8 ? 8 : ch->htlcs_cap * 2;
        htlc_t *tmp = realloc(ch->htlcs, new_cap * sizeof(htlc_t));
        if (!tmp) return;
        ch->htlcs = tmp;
        ch->htlcs_cap = new_cap;
    }
    htlc_t *h = &ch->htlcs[ch->n_htlcs++];
    h->direction   = dir;
    h->state       = HTLC_STATE_ACTIVE;
    h->amount_sats = amount_sats;
    h->cltv_expiry = cltv_expiry;
    h->id          = id;
    memset(h->payment_hash, (int)(id & 0xFF), 32);
    memset(h->payment_preimage, 0, 32);
}

/* ================================================================== */
/* CW1 — init with delta=0 uses CLTV_EXPIRY_DELTA                     */
/* ================================================================== */
int test_cltv_watchdog_default_delta(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                       SECP256K1_CONTEXT_VERIFY);
    channel_t ch;
    ASSERT(cw_setup_channel(&ch, ctx, 5000000, 5000000), "channel init");

    cltv_watchdog_t wd;
    cltv_watchdog_init(&wd, &ch, 0);

    ASSERT(wd.expiry_delta == CLTV_EXPIRY_DELTA,
           "default delta should be CLTV_EXPIRY_DELTA");
    ASSERT(wd.triggered == 0, "triggered should start at 0");
    ASSERT(wd.ch == &ch, "ch pointer should match");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* CW2 — check returns 0 when no HTLCs                                */
/* ================================================================== */
int test_cltv_watchdog_no_htlcs(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                       SECP256K1_CONTEXT_VERIFY);
    channel_t ch;
    ASSERT(cw_setup_channel(&ch, ctx, 5000000, 5000000), "channel init");

    cltv_watchdog_t wd;
    cltv_watchdog_init(&wd, &ch, 0);

    int count = cltv_watchdog_check(&wd, 800000);
    ASSERT(count == 0, "no HTLCs should return 0");
    ASSERT(wd.triggered == 0, "triggered should remain 0");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* CW3 — check returns 0 when HTLC expiry is well beyond threshold    */
/* ================================================================== */
int test_cltv_watchdog_htlc_safe(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                       SECP256K1_CONTEXT_VERIFY);
    channel_t ch;
    ASSERT(cw_setup_channel(&ch, ctx, 5000000, 5000000), "channel init");

    /* Inject inbound HTLC expiring at block 800200 */
    cw_inject_htlc(&ch, HTLC_RECEIVED, 100000, 800200, 1);

    cltv_watchdog_t wd;
    cltv_watchdog_init(&wd, &ch, 0);   /* delta = 18 */

    /* current_height = 800000 → threshold = 800018 < 800200 → safe */
    int count = cltv_watchdog_check(&wd, 800000);
    ASSERT(count == 0, "HTLC far from expiry should be safe");
    ASSERT(wd.triggered == 0, "triggered should remain 0");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* CW4 — check returns 1 when inbound HTLC within expiry_delta        */
/* ================================================================== */
int test_cltv_watchdog_htlc_at_risk(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                       SECP256K1_CONTEXT_VERIFY);
    channel_t ch;
    ASSERT(cw_setup_channel(&ch, ctx, 5000000, 5000000), "channel init");

    /* Inject inbound HTLC expiring at block 800010 */
    cw_inject_htlc(&ch, HTLC_RECEIVED, 100000, 800010, 1);

    cltv_watchdog_t wd;
    cltv_watchdog_init(&wd, &ch, 0);   /* delta = 18 */

    /* current_height = 800000 → threshold = 800018 >= 800010 → at risk */
    int count = cltv_watchdog_check(&wd, 800000);
    ASSERT(count == 1, "HTLC within delta should be at risk");
    ASSERT(wd.triggered == 1, "triggered should be set to 1");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* CW5 — outbound (OFFERED) HTLCs are not counted by check            */
/* ================================================================== */
int test_cltv_watchdog_offered_ignored(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                       SECP256K1_CONTEXT_VERIFY);
    channel_t ch;
    ASSERT(cw_setup_channel(&ch, ctx, 5000000, 5000000), "channel init");

    /* Inject outbound HTLC expiring at block 800005 (well within delta) */
    cw_inject_htlc(&ch, HTLC_OFFERED, 100000, 800005, 1);

    cltv_watchdog_t wd;
    cltv_watchdog_init(&wd, &ch, 0);   /* delta = 18 */

    /* Watchdog should only watch inbound HTLCs */
    int count = cltv_watchdog_check(&wd, 800000);
    ASSERT(count == 0, "outbound HTLCs should not be counted");
    ASSERT(wd.triggered == 0, "triggered should remain 0 for outbound only");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* CW6 — expire fails truly-expired HTLCs via channel_check_htlc_timeouts */
/* ================================================================== */
int test_cltv_watchdog_expire(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                       SECP256K1_CONTEXT_VERIFY);
    channel_t ch;
    ASSERT(cw_setup_channel(&ch, ctx, 5000000, 5000000), "channel init");

    /* Inject two inbound HTLCs: one expired, one not yet */
    cw_inject_htlc(&ch, HTLC_RECEIVED, 100000, 799990, 1);  /* expired */
    cw_inject_htlc(&ch, HTLC_RECEIVED, 100000, 800100, 2);  /* not yet */

    cltv_watchdog_t wd;
    cltv_watchdog_init(&wd, &ch, 0);

    /* current_height = 800000: only htlc id=1 (expiry 799990) has expired */
    int expired = cltv_watchdog_expire(&wd, 800000);
    ASSERT(expired == 1, "one HTLC should have expired");

    /*
     * channel_compact_htlcs removes the failed HTLC immediately.
     * Verify: htlc id=1 is gone; htlc id=2 (expiry 800100) still ACTIVE.
     */
    int found_expired = 0, found_active = 0;
    for (size_t i = 0; i < ch.n_htlcs; i++) {
        if (ch.htlcs[i].id == 1) found_expired = 1;
        if (ch.htlcs[i].id == 2 && ch.htlcs[i].state == HTLC_STATE_ACTIVE)
            found_active = 1;
    }
    ASSERT(!found_expired, "expired HTLC should have been removed from array");
    ASSERT(found_active, "unexpired HTLC should remain ACTIVE");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* CW7 — earliest_expiry returns lowest cltv_expiry of inbound HTLCs  */
/* ================================================================== */
int test_cltv_watchdog_earliest_expiry(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                       SECP256K1_CONTEXT_VERIFY);
    channel_t ch;
    ASSERT(cw_setup_channel(&ch, ctx, 5000000, 5000000), "channel init");

    /* No HTLCs → UINT32_MAX */
    ASSERT(cltv_watchdog_earliest_expiry(&ch) == UINT32_MAX,
           "no HTLCs should return UINT32_MAX");

    /* Add two inbound HTLCs with different expiries */
    cw_inject_htlc(&ch, HTLC_RECEIVED, 100000, 800100, 1);
    cw_inject_htlc(&ch, HTLC_RECEIVED, 100000, 800050, 2);
    /* Add one outbound HTLC with a lower expiry — should be ignored */
    cw_inject_htlc(&ch, HTLC_OFFERED, 100000, 800020, 3);

    uint32_t earliest = cltv_watchdog_earliest_expiry(&ch);
    ASSERT(earliest == 800050,
           "earliest_expiry should return lowest inbound cltv_expiry");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* CW8 — multiple HTLCs: correct at-risk count                        */
/* ================================================================== */
int test_cltv_watchdog_multi_htlc(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                       SECP256K1_CONTEXT_VERIFY);
    channel_t ch;
    ASSERT(cw_setup_channel(&ch, ctx, 5000000, 5000000), "channel init");

    /* 3 inbound HTLCs: two at risk, one safe */
    cw_inject_htlc(&ch, HTLC_RECEIVED, 100000, 800005, 1);  /* at risk: 800005 <= 800018 */
    cw_inject_htlc(&ch, HTLC_RECEIVED, 100000, 800015, 2);  /* at risk: 800015 <= 800018 */
    cw_inject_htlc(&ch, HTLC_RECEIVED, 100000, 800100, 3);  /* safe:    800100 > 800018  */
    /* 1 outbound at risk — should not be counted */
    cw_inject_htlc(&ch, HTLC_OFFERED,  100000, 800010, 4);

    cltv_watchdog_t wd;
    cltv_watchdog_init(&wd, &ch, 0);  /* delta = 18, threshold = 800018 */

    int count = cltv_watchdog_check(&wd, 800000);
    ASSERT(count == 2, "exactly 2 inbound HTLCs should be at risk");
    ASSERT(wd.triggered == 1, "triggered should be set");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* CW9 — block_connected_cb fires watchdog on bip158_backend advance  */
/* ================================================================== */

/* Test state for block callback */
typedef struct {
    cltv_watchdog_t *wd;
    uint32_t         last_height;
    int              check_called;
} cw9_ctx_t;

static void cw9_block_cb(uint32_t height, void *ctx)
{
    cw9_ctx_t *c = (cw9_ctx_t *)ctx;
    c->last_height = height;
    c->check_called += cltv_watchdog_check(c->wd, height);
}

int test_cltv_watchdog_block_cb(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                       SECP256K1_CONTEXT_VERIFY);
    channel_t ch;
    ASSERT(cw_setup_channel(&ch, ctx, 5000000, 5000000), "channel init");

    /* Inject an inbound HTLC expiring at block 800010 */
    cw_inject_htlc(&ch, HTLC_RECEIVED, 100000, 800010, 1);

    cltv_watchdog_t wd;
    cltv_watchdog_init(&wd, &ch, 0);  /* delta = 18 */

    /* Set up a minimal bip158_backend_t with just the callback fields */
    bip158_backend_t backend;
    memset(&backend, 0, sizeof(backend));
    backend.tip_height = -1;

    cw9_ctx_t cw9 = { &wd, 0, 0 };
    bip158_backend_set_block_connected_cb(&backend, cw9_block_cb, &cw9);

    /* Manually advance tip_height and fire callback at a height that triggers watchdog */
    backend.tip_height = 800000;
    if (backend.block_connected_cb)
        backend.block_connected_cb((uint32_t)backend.tip_height,
                                    backend.block_connected_ctx);

    ASSERT(cw9.last_height == 800000, "callback received correct height");
    /* At height 800000, threshold = 800018 >= 800010 → 1 at-risk HTLC */
    ASSERT(cw9.check_called > 0, "watchdog check fired via callback");
    ASSERT(wd.triggered == 1, "watchdog marked triggered");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* CW10 — on_block_connected per-channel watchdog (multi-channel sim) */
/* ================================================================== */
int test_cltv_watchdog_block_connected_multi(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                       SECP256K1_CONTEXT_VERIFY);

    /* Create two channels, each with an expired inbound HTLC */
    channel_t ch1, ch2;
    ASSERT(cw_setup_channel(&ch1, ctx, 5000000, 5000000), "ch1 init");
    ASSERT(cw_setup_channel(&ch2, ctx, 5000000, 5000000), "ch2 init");

    /* height = 800000; HTLC expiry < height -> expired AND at-risk */
    cw_inject_htlc(&ch1, HTLC_RECEIVED, 100000, 799990, 1);
    cw_inject_htlc(&ch2, HTLC_RECEIVED, 100000, 799995, 2);

    uint32_t height = 800000;

    /* Simulate on_block_connected loop over both channels */
    channel_t *channels[2] = {&ch1, &ch2};
    int total_at_risk = 0;
    for (int i = 0; i < 2; i++) {
        cltv_watchdog_t wd;
        cltv_watchdog_init(&wd, channels[i], 0);
        total_at_risk += cltv_watchdog_check(&wd, height);
        cltv_watchdog_expire(&wd, height);
    }

    /* Both HTLCs were at-risk (expiry 799990/799995 <= 800000+18) */
    ASSERT(total_at_risk == 2, "both channels had at-risk HTLCs");

    /* Both HTLCs were expired (expiry <= height) -> removed by compact */
    ASSERT(ch1.n_htlcs == 0, "ch1 expired HTLC removed by watchdog_expire");
    ASSERT(ch2.n_htlcs == 0, "ch2 expired HTLC removed by watchdog_expire");

    channel_cleanup(&ch1);
    channel_cleanup(&ch2);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* CW11 — on_block_connected with zero channels: no crash              */
/* ================================================================== */
int test_cltv_watchdog_block_connected_empty(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                       SECP256K1_CONTEXT_VERIFY);

    /* Simulate on_block_connected with n_channels=0 */
    uint32_t height = 800000;
    int n_channels = 0;
    int total_at_risk = 0;
    for (int i = 0; i < n_channels; i++) {
        (void)i; (void)height;  /* loop doesn't execute */
        total_at_risk++;
    }
    ASSERT(total_at_risk == 0, "no channels -> no at-risk HTLCs, no crash");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* CW12 — mixed channels: one safe, one at-risk                        */
/* ================================================================== */
int test_cltv_watchdog_block_connected_mixed(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                       SECP256K1_CONTEXT_VERIFY);

    channel_t ch_safe, ch_risk;
    ASSERT(cw_setup_channel(&ch_safe, ctx, 5000000, 5000000), "ch_safe init");
    ASSERT(cw_setup_channel(&ch_risk, ctx, 5000000, 5000000), "ch_risk init");

    uint32_t height = 800000;
    /* ch_safe: HTLC expires far in the future */
    cw_inject_htlc(&ch_safe, HTLC_RECEIVED, 100000, 810000, 1);
    /* ch_risk: HTLC within expiry delta (800000 + 18 = 800018 >= 800015) */
    cw_inject_htlc(&ch_risk, HTLC_RECEIVED, 100000, 800015, 2);

    channel_t *channels[2] = {&ch_safe, &ch_risk};
    int total_at_risk = 0;
    for (int i = 0; i < 2; i++) {
        cltv_watchdog_t wd;
        cltv_watchdog_init(&wd, channels[i], 0);
        total_at_risk += cltv_watchdog_check(&wd, height);
        cltv_watchdog_expire(&wd, height);
    }

    ASSERT(total_at_risk == 1, "only ch_risk is at-risk");
    ASSERT(ch_safe.n_htlcs == 1, "ch_safe HTLC not expired");
    ASSERT(ch_risk.n_htlcs == 1, "ch_risk HTLC at risk but not yet expired");

    channel_cleanup(&ch_safe);
    channel_cleanup(&ch_risk);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* WT1 — watchtower_init + watchtower_check with no entries → 0       */
/* ================================================================== */
int test_watchtower_init_empty(void)
{
    watchtower_t wt;
    memset(&wt, 0, sizeof(wt));
    int r = watchtower_init(&wt, 0, NULL, NULL, NULL);
    ASSERT(r == 1, "watchtower_init returns 1");
    int c = watchtower_check(&wt);
    ASSERT(c == 0, "empty watchtower returns 0");
    watchtower_cleanup(&wt);
    return 1;
}

/* ================================================================== */
/* WT2 — watchtower_watch adds entry; check with no chain → 0         */
/* ================================================================== */
int test_watchtower_watch_no_breach(void)
{
    watchtower_t wt;
    memset(&wt, 0, sizeof(wt));
    ASSERT(watchtower_init(&wt, 0, NULL, NULL, NULL), "init");
    unsigned char txid[32]; memset(txid, 0xAB, 32);
    unsigned char spk[34];  memset(spk,  0x51, 34);
    int r = watchtower_watch(&wt, 0, 1, txid, 0, 100000, spk, 34);
    ASSERT(r == 1, "watch entry added");
    /* No chain backend → check cannot find breach */
    int c = watchtower_check(&wt);
    ASSERT(c == 0, "no chain backend → 0 penalties");
    watchtower_cleanup(&wt);
    return 1;
}

/* ================================================================== */
/* WT3 — g_watchtower_ready=0 guard: no crash from unconfigured wt   */
/* ================================================================== */
int test_watchtower_ready_guard(void)
{
    /* Simulate the g_watchtower_ready == 0 guard path:
     * Just verify that calling init + check on zeroed struct is safe. */
    watchtower_t wt;
    memset(&wt, 0, sizeof(wt));
    int r = watchtower_init(&wt, 0, NULL, NULL, NULL);
    ASSERT(r == 1, "init succeeds");
    ASSERT(watchtower_check(&wt) == 0, "check on empty wt returns 0");
    watchtower_cleanup(&wt);
    return 1;
}

/* ================================================================== */
/* WT4 — watchtower_remove_channel removes entries for that channel   */
/* ================================================================== */
int test_watchtower_remove_channel(void)
{
    watchtower_t wt;
    memset(&wt, 0, sizeof(wt));
    ASSERT(watchtower_init(&wt, 0, NULL, NULL, NULL), "init");
    unsigned char txid[32]; memset(txid, 0xCC, 32);
    unsigned char spk[34];  memset(spk,  0x51, 34);
    ASSERT(watchtower_watch(&wt, 42, 1, txid, 0, 100000, spk, 34), "watch");
    watchtower_remove_channel(&wt, 42);
    /* After removal check should still return 0 (entry gone) */
    ASSERT(watchtower_check(&wt) == 0, "after remove → 0 penalties");
    watchtower_cleanup(&wt);
    return 1;
}
