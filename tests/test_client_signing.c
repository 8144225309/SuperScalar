/* Checks a client applies before co-signing transactions proposed by the LSP.
 *
 * A client's signature is the only thing standing between the LSP and the
 * client's funds, so each handler must verify, from the client's own state,
 * that the transaction it is asked to sign still pays the client what it is
 * owed.  These tests drive the client handlers with both honest and
 * dishonest proposals.
 */
#include "superscalar/factory.h"
#include "superscalar/wire.h"
#include "superscalar/lsp.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/client.h"
#include "superscalar/channel.h"
#include "superscalar/musig.h"
#include "superscalar/regtest.h"
#include "superscalar/tx_builder.h"
#include "superscalar/sha256.h"
#include "superscalar/persist.h"
#include "superscalar/ptlc_commit.h"
#include "cJSON.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <errno.h>
#include <time.h>
#include <sqlite3.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

/* ---- Hard deadlines ----

   The ceremony tests talk over sockets to forked clients or to an LSP.  If a
   message that one side waits for never comes, a test would sit in recv() or
   accept() and the whole suite with it.  Each such test therefore runs in a
   process of its own, in its own process group, under a deadline: when the
   deadline passes the group is killed and the test FAILS.  The group is also
   killed after a normal finish, so nothing a test started outlives it.

   SS_TEST_NO_DEADLINE=1 runs the bodies in the calling process instead, for
   a debugger or a leak checker. */

static double cs_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int cs_run_with_deadline(int (*body)(void), int seconds,
                                const char *name) {
    const char *inproc = getenv("SS_TEST_NO_DEADLINE");
    if (inproc && inproc[0] == '1') return body();

    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) {
        printf("  FAIL: %s: fork failed\n", name);
        return 0;
    }
    if (pid == 0) {
        setpgid(0, 0);
        int ok = body();
        fflush(stdout);
        fflush(stderr);
        _exit(ok ? 0 : 1);
    }
    setpgid(pid, pid);   /* from this side too: no window before the kill */

    int status = 0, finished = 0;
    double deadline = cs_now() + (double)seconds;
    for (;;) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) { finished = 1; break; }
        if (r < 0 && errno != EINTR) break;
        if (cs_now() >= deadline) break;
        usleep(20000);
    }
    /* The body, and every process it started that is still around. */
    kill(-pid, SIGKILL);
    if (!finished) {
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        printf("  FAIL: %s: no result within %d s; test processes killed\n",
               name, seconds);
        return 0;
    }
    if (!WIFEXITED(status)) {
        printf("  FAIL: %s: test process ended abnormally (signal %d)\n",
               name, WIFSIGNALED(status) ? WTERMSIG(status) : 0);
        return 0;
    }
    return WEXITSTATUS(status) == 0;
}

/* A test with a deadline is written as a body, `static int NAME_body(void)`,
   and gets its public entry point from CS_DEADLINE_ENTRY(NAME, seconds) in
   the list at the end of this file.  The entry points are kept apart from
   the bodies, one to a line, so that no two functions start on the same
   source line: coverage tools identify a function by the line it starts on. */
#define CS_DEADLINE_ENTRY(name, seconds) \
    int name(void) { return cs_run_with_deadline(name##_body, seconds, #name); }

#define CS_UNIT_DEADLINE_SEC 120
#define CS_REGTEST_DEADLINE_SEC 600

/* How long forked clients get to finish once the LSP side is done. */
#define CS_REAP_GRACE_SEC 20

/* Reap n children.  A child still running when the grace period ends is
   killed and counts as failed.  exit_codes_out (may be NULL) receives each
   exit status, or -1 for a child that was killed or died of a signal.
   Returns how many exited 0. */
static int cs_reap(const pid_t *pids, int n, int grace_sec,
                   int *exit_codes_out) {
    int done[16] = {0}, n_ok = 0, n_left = n;
    double deadline = cs_now() + (double)grace_sec;
    if (n > 16) n = n_left = 16;
    for (int c = 0; c < n; c++)
        if (exit_codes_out) exit_codes_out[c] = -1;
    while (n_left > 0) {
        int expired = cs_now() >= deadline;
        for (int c = 0; c < n; c++) {
            if (done[c]) continue;
            int status = 0;
            if (expired) kill(pids[c], SIGKILL);
            pid_t r = waitpid(pids[c], &status, expired ? 0 : WNOHANG);
            if (r == 0) continue;
            if (r < 0 && errno == EINTR) continue;
            done[c] = 1;
            n_left--;
            if (r == pids[c] && WIFEXITED(status)) {
                if (exit_codes_out) exit_codes_out[c] = WEXITSTATUS(status);
                if (WEXITSTATUS(status) == 0) n_ok++;
            }
        }
        if (n_left > 0 && !expired) usleep(20000);
    }
    return n_ok;
}

#define CS_N 5              /* LSP + 4 clients */
#define CS_FUNDING 1000000  /* sats */

static const unsigned char cs_seckeys[CS_N][32] = {
    { [0 ... 31] = 0x10 },  /* LSP */
    { [0 ... 31] = 0x21 },
    { [0 ... 31] = 0x32 },
    { [0 ... 31] = 0x43 },
    { [0 ... 31] = 0x54 },
};

static secp256k1_context *cs_ctx(void) {
    return secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

static int cs_keys(secp256k1_context *ctx, secp256k1_keypair *kps,
                   secp256k1_pubkey *pks) {
    for (int i = 0; i < CS_N; i++) {
        if (!secp256k1_keypair_create(ctx, &kps[i], cs_seckeys[i])) return 0;
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }
    return 1;
}

/* P2TR of the taptweaked N-of-N aggregate key: the factory funding script. */
static int cs_funding_spk(secp256k1_context *ctx, const secp256k1_pubkey *pks,
                          unsigned char *spk_out34,
                          unsigned char *tweaked_xonly_out32) {
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks, CS_N)) return 0;
    unsigned char internal_ser[32], tweak[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey))
        return 0;
    sha256_tagged("TapTweak", internal_ser, 32, tweak);
    musig_keyagg_t tmp = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &tmp.cache,
                                                 tweak))
        return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL,
                                             &tweaked_pk))
        return 0;
    build_p2tr_script_pubkey(spk_out34, &tweaked_xonly);
    if (tweaked_xonly_out32 &&
        !secp256k1_xonly_pubkey_serialize(ctx, tweaked_xonly_out32,
                                           &tweaked_xonly))
        return 0;
    return 1;
}

/* Build a 5-party factory over a made-up funding outpoint. */
static int cs_build_factory(factory_t *f, secp256k1_context *ctx,
                            const secp256k1_keypair *kps,
                            const secp256k1_pubkey *pks) {
    unsigned char fund_spk[34], fake_txid[32];
    if (!cs_funding_spk(ctx, pks, fund_spk, NULL)) return 0;
    memset(fake_txid, 0xAA, 32);
    factory_init(f, ctx, kps, CS_N, 2, 4);
    factory_set_funding(f, fake_txid, 0, CS_FUNDING, fund_spk, 34);
    return factory_build_tree(f);
}

static void cs_output(tx_output_t *o, uint64_t amount, const unsigned char *spk34) {
    memset(o, 0, sizeof(*o));
    o->amount_sats = amount;
    memcpy(o->script_pubkey, spk34, 34);
    o->script_pubkey_len = 34;
}

/* ---- Cooperative close ---- */

#define CS_CHAN_FUNDING 400000  /* sats in the leaf output funding a channel */
#define CS_COMMIT_FEE 167       /* base commitment fee at 1000 sat/kvB (167 vB) */

/* A channel whose state adds up: the client holds `local`, the LSP the rest
   of the funding output. */
static void cs_channel(channel_t *ch, uint64_t local) {
    memset(ch, 0, sizeof(*ch));
    ch->funding_amount = CS_CHAN_FUNDING;
    ch->fee_rate_sat_per_kvb = 1000;
    ch->commit_fee_rate_sat_per_kvb = 1000;
    ch->local_amount = local;
    ch->remote_amount = CS_CHAN_FUNDING - CS_COMMIT_FEE - local;
}

/* The acceptance rule itself: only outputs to the client's own script count
   toward its balance, and nothing is signed while an HTLC is in flight. */
int test_client_close_outputs_acceptable(void) {
    secp256k1_context *ctx = cs_ctx();
    secp256k1_keypair kps[CS_N];
    secp256k1_pubkey pks[CS_N];
    TEST_ASSERT(cs_keys(ctx, kps, pks), "keys");

    unsigned char spk[CS_N][34];
    for (int i = 0; i < CS_N; i++)
        TEST_ASSERT(client_close_script(ctx, &pks[i], spk[i]), "close script");
    TEST_ASSERT(memcmp(spk[1], spk[2], 34) != 0, "scripts are per-client");
    TEST_ASSERT(spk[1][0] == 0x51 && spk[1][1] == 0x20, "script is P2TR");
    {
        /* The script commits to the client's own key and nothing else. */
        secp256k1_xonly_pubkey xo;
        unsigned char ser[32];
        TEST_ASSERT(secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &pks[1]) &&
                    secp256k1_xonly_pubkey_serialize(ctx, ser, &xo), "xonly");
        TEST_ASSERT(memcmp(spk[1] + 2, ser, 32) == 0, "output key is own key");
    }

    const uint64_t balance = 100000;
    channel_t ch;
    cs_channel(&ch, balance);

    tx_output_t outs[3];

    /* Everything to the LSP, amount far above the client's balance. */
    cs_output(&outs[0], CS_FUNDING - 1000, spk[0]);
    TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 1),
                "single output to the LSP key must be refused");

    /* Enough sats, but to another client's script. */
    cs_output(&outs[0], 500000, spk[0]);
    cs_output(&outs[1], balance, spk[2]);
    TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 2),
                "output to another client's script must be refused");

    /* The factory funding script is not the client's either. */
    unsigned char fund_spk[34];
    TEST_ASSERT(cs_funding_spk(ctx, pks, fund_spk, NULL), "funding spk");
    cs_output(&outs[1], balance, fund_spk);
    TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 2),
                "output to the funding script must be refused");

    /* Own script, one sat short. */
    cs_output(&outs[1], balance - 1, spk[1]);
    TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 2),
                "own script but short amount must be refused");

    /* Own script with a truncated length does not match. */
    cs_output(&outs[1], balance, spk[1]);
    outs[1].script_pubkey_len = 33;
    TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 2),
                "truncated script must be refused");

    /* Honest: own script, exact balance. */
    cs_output(&outs[1], balance, spk[1]);
    TEST_ASSERT(client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 2),
                "own script with full balance is accepted");
    cs_output(&outs[1], balance + 5, spk[1]);
    TEST_ASSERT(client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 2),
                "own script with more than the balance is accepted");
    TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[2], &ch, outs, 2),
                "the same proposal does not satisfy a different client");

    /* An HTLC in flight is not covered by any output.  The client offered
       1000 sats: they left its balance and sit in the HTLC, so the state
       still adds up and only the pending-HTLC rule can refuse. */
    htlc_t pending;
    memset(&pending, 0, sizeof(pending));
    pending.state = HTLC_STATE_ACTIVE;
    pending.amount_sats = 1000;
    ch.local_amount -= pending.amount_sats;
    ch.htlcs = &pending;
    ch.n_htlcs = 1;
    TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 2),
                "close with a pending HTLC must be refused");
    /* Once it has failed back, the balance is whole again. */
    pending.state = HTLC_STATE_FAILED;
    ch.local_amount += pending.amount_sats;
    TEST_ASSERT(client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 2),
                "a resolved HTLC does not block the close");
    ch.htlcs = NULL;
    ch.n_htlcs = 0;

    /* A PTLC in flight is no different: it has no output either. */
    ptlc_t pending_ptlc;
    memset(&pending_ptlc, 0, sizeof(pending_ptlc));
    pending_ptlc.state = PTLC_STATE_ACTIVE;
    pending_ptlc.amount_sats = 2000;
    ch.local_amount -= pending_ptlc.amount_sats;
    ch.ptlcs = &pending_ptlc;
    ch.n_ptlcs = 1;
    TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 2),
                "close with a pending PTLC must be refused");
    pending_ptlc.state = PTLC_STATE_FAILED;
    ch.local_amount += pending_ptlc.amount_sats;
    TEST_ASSERT(client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 2),
                "a resolved PTLC does not block the close");
    ch.ptlcs = NULL;
    ch.n_ptlcs = 0;

    /* A balance below the dust limit cannot have an output. */
    cs_channel(&ch, CHANNEL_DUST_LIMIT_SATS - 1);
    TEST_ASSERT(client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 1),
                "sub-dust balance needs no output");
    cs_channel(&ch, CHANNEL_DUST_LIMIT_SATS);
    TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 1),
                "a balance at the dust limit needs its output");

    /* No channel, no balance. */
    TEST_ASSERT(client_close_outputs_acceptable(ctx, &pks[1], NULL, outs, 1),
                "client without a channel has nothing to verify");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* A close is only signed for a channel whose state accounts for the whole
   funding output.  An HTLC that is missing from the HTLC list (the list is
   not restored when a channel is reloaded) shows up as an amount that is in
   neither balance; a close paying local_amount in full would give that
   amount to the LSP. */
int test_client_close_refuses_unbalanced_channel(void) {
    secp256k1_context *ctx = cs_ctx();
    secp256k1_keypair kps[CS_N];
    secp256k1_pubkey pks[CS_N];
    TEST_ASSERT(cs_keys(ctx, kps, pks), "keys");

    unsigned char lsp_spk[34], my_spk[34];
    TEST_ASSERT(client_close_script(ctx, &pks[0], lsp_spk), "lsp script");
    TEST_ASSERT(client_close_script(ctx, &pks[1], my_spk), "client script");

    const uint64_t balance = 100000, htlc_amount = 30000;
    channel_t ch;
    tx_output_t outs[2];

    /* Baseline: state adds up, proposal pays the balance. */
    cs_channel(&ch, balance);
    cs_output(&outs[0], CS_FUNDING - 1000 - balance, lsp_spk);
    cs_output(&outs[1], balance, my_spk);
    TEST_ASSERT(client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 2),
                "balanced channel paid in full is accepted");

    /* An outgoing HTLC left the client's balance and is not in the list.
       The proposal pays the remaining local_amount exactly. */
    cs_channel(&ch, balance);
    ch.local_amount -= htlc_amount;
    cs_output(&outs[0], CS_FUNDING - 1000 - ch.local_amount, lsp_spk);
    cs_output(&outs[1], ch.local_amount, my_spk);
    TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 2),
                "missing outgoing HTLC amount must be refused");

    /* The same HTLC, listed and active: the state adds up again and the
       pending-HTLC rule refuses instead. */
    htlc_t h;
    memset(&h, 0, sizeof(h));
    h.state = HTLC_STATE_ACTIVE;
    h.amount_sats = htlc_amount;
    ch.htlcs = &h;
    ch.n_htlcs = 1;
    TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 2),
                "listed pending HTLC is refused");
    ch.htlcs = NULL;
    ch.n_htlcs = 0;

    /* An incoming HTLC left the LSP's balance and is not in the list. */
    cs_channel(&ch, balance);
    ch.remote_amount -= htlc_amount;
    cs_output(&outs[1], balance, my_spk);
    TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 2),
                "missing incoming HTLC amount must be refused");

    /* The missing amount took the balance below dust: no output would be
       required, and the close must still be refused. */
    cs_channel(&ch, htlc_amount + 100);
    ch.local_amount -= htlc_amount;
    TEST_ASSERT(ch.local_amount < CHANNEL_DUST_LIMIT_SATS, "sub-dust remainder");
    TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 1),
                "sub-dust balance does not excuse a missing amount");

    /* Balances that claim more than the funding output holds. */
    cs_channel(&ch, balance);
    ch.remote_amount += 1;
    TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 2),
                "state exceeding the funding output must be refused");

    /* No funding amount to check against. */
    cs_channel(&ch, balance);
    ch.funding_amount = 0;
    TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 2),
                "channel without a funding amount must be refused");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* The balance must arrive in one output to the client's own script, at or
   above the dust limit.  Outputs below the dust limit are not counted, and a
   payout spread over several outputs is refused whatever it adds up to. */
int test_client_close_single_payout_output(void) {
    secp256k1_context *ctx = cs_ctx();
    secp256k1_keypair kps[CS_N];
    secp256k1_pubkey pks[CS_N];
    TEST_ASSERT(cs_keys(ctx, kps, pks), "keys");

    unsigned char spk[CS_N][34];
    for (int i = 0; i < CS_N; i++)
        TEST_ASSERT(client_close_script(ctx, &pks[i], spk[i]), "close script");

    const uint64_t balance = 100000;
    const uint64_t dust = CHANNEL_DUST_LIMIT_SATS;
    channel_t ch;
    cs_channel(&ch, balance);
    tx_output_t outs[8];
    uint64_t paid = 0;
    size_t n_paying = 0;

    /* One output, among others that are not the client's. */
    cs_output(&outs[0], 500000, spk[0]);
    cs_output(&outs[1], balance, spk[1]);
    cs_output(&outs[2], 250000, spk[2]);
    TEST_ASSERT(client_close_amount_to_client(ctx, &pks[1], outs, 3, &paid,
                                               &n_paying) &&
                paid == balance && n_paying == 1, "one paying output");
    TEST_ASSERT(client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 3),
                "balance in one output is accepted");

    /* The same amount in two outputs. */
    cs_output(&outs[1], 60000, spk[1]);
    cs_output(&outs[3], 40000, spk[1]);
    TEST_ASSERT(client_close_amount_to_client(ctx, &pks[1], outs, 4, &paid,
                                               &n_paying) &&
                paid == balance && n_paying == 2, "two paying outputs");
    TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 4),
                "balance split over two outputs is refused");

    /* More than the balance, still in two outputs. */
    cs_output(&outs[3], 90000, spk[1]);
    TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 4),
                "a generous split is refused as well");

    /* Dust split: the last part of the balance in an output below dust. */
    cs_output(&outs[1], balance - (dust - 1), spk[1]);
    cs_output(&outs[3], dust - 1, spk[1]);
    TEST_ASSERT(client_close_amount_to_client(ctx, &pks[1], outs, 4, &paid,
                                               &n_paying) &&
                paid == balance - (dust - 1) && n_paying == 1,
                "sub-dust output is not counted");
    TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 4),
                "balance completed by a sub-dust output is refused");

    /* The whole balance as a pile of sub-dust outputs. */
    {
        channel_t small;
        cs_channel(&small, 5 * (dust - 1));
        for (int i = 0; i < 5; i++) cs_output(&outs[i], dust - 1, spk[1]);
        cs_output(&outs[5], 500000, spk[0]);
        TEST_ASSERT(client_close_amount_to_client(ctx, &pks[1], outs, 6, &paid,
                                                   &n_paying) &&
                    paid == 0 && n_paying == 0, "sub-dust outputs pay nothing");
        TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[1], &small,
                                                      outs, 6),
                    "balance paid only in sub-dust outputs is refused");
    }

    /* One full output; a stray sub-dust output to the same script changes
       nothing. */
    cs_output(&outs[0], 500000, spk[0]);
    cs_output(&outs[1], balance, spk[1]);
    cs_output(&outs[2], dust - 1, spk[1]);
    TEST_ASSERT(client_close_amount_to_client(ctx, &pks[1], outs, 3, &paid,
                                               &n_paying) &&
                paid == balance && n_paying == 1, "stray dust is ignored");
    TEST_ASSERT(client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 3),
                "full output plus stray dust is accepted");

    /* An output at exactly the dust limit counts. */
    cs_output(&outs[2], dust, spk[1]);
    TEST_ASSERT(client_close_amount_to_client(ctx, &pks[1], outs, 3, &paid,
                                               &n_paying) &&
                paid == balance + dust && n_paying == 2,
                "output at the dust limit is counted");
    TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 3),
                "a second output at the dust limit is a split");

    /* Another client's output, or a truncated script, is not this client's. */
    cs_output(&outs[1], balance - 10000, spk[1]);
    cs_output(&outs[2], 10000, spk[2]);
    TEST_ASSERT(client_close_amount_to_client(ctx, &pks[1], outs, 3, &paid,
                                               &n_paying) &&
                paid == balance - 10000 && n_paying == 1,
                "another client's output is not counted");
    TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 3),
                "balance completed by another script is refused");
    cs_output(&outs[2], 10000, spk[1]);
    outs[2].script_pubkey_len = 33;
    TEST_ASSERT(client_close_amount_to_client(ctx, &pks[1], outs, 3, &paid,
                                               &n_paying) &&
                paid == balance - 10000 && n_paying == 1,
                "truncated script is not counted");
    TEST_ASSERT(client_close_amount_to_client(ctx, &pks[3], outs, 3, &paid,
                                               &n_paying) &&
                paid == 0 && n_paying == 0,
                "a client with no output is paid nothing");

    /* A total that overflows cannot be trusted. */
    cs_output(&outs[1], UINT64_MAX, spk[1]);
    cs_output(&outs[2], dust, spk[1]);
    TEST_ASSERT(!client_close_amount_to_client(ctx, &pks[1], outs, 3, &paid,
                                                &n_paying),
                "overflowing total is an error");
    TEST_ASSERT(!client_close_outputs_acceptable(ctx, &pks[1], &ch, outs, 3),
                "overflowing total is refused");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* One message of a scripted LSP. */
typedef struct {
    uint8_t type;
    cJSON *json;
} cs_lsp_msg_t;

static cs_lsp_msg_t cs_msg_propose(const tx_output_t *outs, size_t n_outs,
                                   uint32_t locktime) {
    cs_lsp_msg_t m = { MSG_CLOSE_PROPOSE,
                       wire_build_close_propose(outs, n_outs, locktime) };
    return m;
}

/* CLOSE_ALL_NONCES with a well-formed public nonce in every signer slot. */
static cs_lsp_msg_t cs_msg_all_nonces(secp256k1_context *ctx,
                                      const secp256k1_pubkey *pks) {
    unsigned char ser[CS_N][66];
    for (int i = 0; i < CS_N; i++) {
        secp256k1_musig_secnonce sec;
        secp256k1_musig_pubnonce pub;
        musig_generate_nonce(ctx, &sec, &pub, cs_seckeys[i], &pks[i], NULL);
        musig_pubnonce_serialize(ctx, ser[i], &pub);
    }
    cs_lsp_msg_t m = { MSG_CLOSE_ALL_NONCES,
                       wire_build_close_all_nonces(
                           (const unsigned char (*)[66])ser, CS_N) };
    return m;
}

static cs_lsp_msg_t cs_msg_done(void) {
    static const unsigned char tx[4] = { 0x02, 0x00, 0x00, 0x00 };
    cs_lsp_msg_t m = { MSG_CLOSE_DONE, wire_build_close_done(tx, sizeof(tx)) };
    return m;
}

static cs_lsp_msg_t cs_msg_error(void) {
    cs_lsp_msg_t m = { MSG_ERROR, wire_build_error("close failed") };
    return m;
}

#define CS_MAX_SENT 8

/* Run the client side of the close ceremony against a scripted LSP.  All
   LSP messages are queued and the stream is ended before the client starts,
   so a client that waits for more than the script holds sees end of stream
   and the test stays finite.  Records the type of every message the client
   wrote back.  Takes ownership of the messages. */
static int cs_run_client_close_script(secp256k1_context *ctx,
                                      const secp256k1_keypair *kp,
                                      const secp256k1_pubkey *pk, factory_t *f,
                                      const channel_t *ch,
                                      client_close_state_t *cs, uint32_t tip,
                                      cs_lsp_msg_t *msgs, size_t n_msgs,
                                      int *client_rc_out,
                                      uint8_t sent_out[CS_MAX_SENT],
                                      size_t *n_sent_out) {
    int sv[2];
    int ok = (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    for (size_t i = 0; i < n_msgs; i++) {
        if (ok && (!msgs[i].json ||
                   !wire_send(sv[0], msgs[i].type, msgs[i].json)))
            ok = 0;
        if (msgs[i].json) cJSON_Delete(msgs[i].json);
    }
    if (!ok) return 0;
    shutdown(sv[0], SHUT_WR);

    *client_rc_out = client_do_close_ceremony(sv[1], ctx, kp, pk, f, CS_N,
                                               NULL, tip, ch, cs, 0);
    close(sv[1]);

    *n_sent_out = 0;
    memset(sent_out, 0, CS_MAX_SENT);
    wire_msg_t reply;
    memset(&reply, 0, sizeof(reply));
    while (*n_sent_out < CS_MAX_SENT && wire_recv(sv[0], &reply)) {
        sent_out[(*n_sent_out)++] = reply.msg_type;
        if (reply.json) cJSON_Delete(reply.json);
        memset(&reply, 0, sizeof(reply));
    }
    close(sv[0]);
    return 1;
}

/* Run the client side of the close ceremony against one proposal (nLockTime
   0) and report what the client did.  *sent_type_out is the type of the
   first message the client wrote back (0 if none). */
static int cs_run_client_close(secp256k1_context *ctx,
                               const secp256k1_keypair *kp,
                               const secp256k1_pubkey *pk, factory_t *f,
                               const channel_t *ch,
                               const tx_output_t *outs, size_t n_outs,
                               int *client_rc_out, uint8_t *sent_type_out) {
    cs_lsp_msg_t msgs[1] = { cs_msg_propose(outs, n_outs, 0) };
    uint8_t sent[CS_MAX_SENT];
    size_t n_sent = 0;
    if (!cs_run_client_close_script(ctx, kp, pk, f, ch, NULL, 0, msgs, 1,
                                     client_rc_out, sent, &n_sent))
        return 0;
    *sent_type_out = n_sent > 0 ? sent[0] : 0;
    return 1;
}

/* A proposal that does not pay the client is refused before the client
   reveals a nonce; one that does pay it gets a nonce. */
static int test_client_close_refuses_unpaid_proposal_body(void) {
    secp256k1_context *ctx = cs_ctx();
    secp256k1_keypair kps[CS_N];
    secp256k1_pubkey pks[CS_N];
    TEST_ASSERT(cs_keys(ctx, kps, pks), "keys");

    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f != NULL, "alloc");
    TEST_ASSERT(cs_build_factory(f, ctx, kps, pks), "build factory");

    unsigned char lsp_spk[34], my_spk[34];
    TEST_ASSERT(client_close_script(ctx, &pks[0], lsp_spk), "lsp script");
    TEST_ASSERT(client_close_script(ctx, &pks[1], my_spk), "client script");

    const uint64_t balance = 120000;
    channel_t ch;
    cs_channel(&ch, balance);

    tx_output_t outs[2];
    int rc = -1;
    uint8_t sent = 0;

    /* The whole factory to a key only the LSP holds. */
    cs_output(&outs[0], CS_FUNDING - 1000, lsp_spk);
    TEST_ASSERT(cs_run_client_close(ctx, &kps[1], &pks[1], f, &ch, outs, 1,
                                     &rc, &sent), "run");
    TEST_ASSERT(sent != MSG_CLOSE_NONCE, "client reveals no nonce");
    TEST_ASSERT(rc == 0, "client refuses a close paying only the LSP");
    TEST_ASSERT(sent == MSG_ERROR, "client reports the refusal");

    /* Right script, wrong amount. */
    cs_output(&outs[0], CS_FUNDING - 1000 - (balance - 1), lsp_spk);
    cs_output(&outs[1], balance - 1, my_spk);
    TEST_ASSERT(cs_run_client_close(ctx, &kps[1], &pks[1], f, &ch, outs, 2,
                                     &rc, &sent), "run");
    TEST_ASSERT(rc == 0, "client refuses a short payout");
    TEST_ASSERT(sent == MSG_ERROR, "client reports the refusal");

    /* Fully paid, but an HTLC is still pending. */
    cs_output(&outs[0], CS_FUNDING - 1000 - balance, lsp_spk);
    cs_output(&outs[1], balance, my_spk);
    htlc_t pending;
    memset(&pending, 0, sizeof(pending));
    pending.state = HTLC_STATE_ACTIVE;
    pending.amount_sats = 5000;
    ch.remote_amount -= pending.amount_sats;   /* offered by the LSP */
    ch.htlcs = &pending;
    ch.n_htlcs = 1;
    TEST_ASSERT(cs_run_client_close(ctx, &kps[1], &pks[1], f, &ch, outs, 2,
                                     &rc, &sent), "run");
    TEST_ASSERT(rc == 0, "client refuses to close over a pending HTLC");
    TEST_ASSERT(sent == MSG_ERROR, "client reports the refusal");
    ch.remote_amount += pending.amount_sats;
    ch.htlcs = NULL;
    ch.n_htlcs = 0;

    /* Same outputs with nothing pending: the client proceeds to the nonce
       round (the ceremony then ends because the test sends nothing more). */
    TEST_ASSERT(cs_run_client_close(ctx, &kps[1], &pks[1], f, &ch, outs, 2,
                                     &rc, &sent), "run");
    TEST_ASSERT(sent == MSG_CLOSE_NONCE, "client signs on to an honest close");

    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A client with no channel signs any close: it is owed nothing.  But if its
   own database holds a channel for this factory, it was started without its
   state and must refuse rather than sign its balance away. */
static int test_client_close_without_channel_body(void) {
    secp256k1_context *ctx = cs_ctx();
    secp256k1_keypair kps[CS_N];
    secp256k1_pubkey pks[CS_N];
    TEST_ASSERT(cs_keys(ctx, kps, pks), "keys");

    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f != NULL, "alloc");
    TEST_ASSERT(cs_build_factory(f, ctx, kps, pks), "build factory");

    unsigned char lsp_spk[34];
    TEST_ASSERT(client_close_script(ctx, &pks[0], lsp_spk), "lsp script");
    tx_output_t all_to_lsp;
    cs_output(&all_to_lsp, CS_FUNDING - 1000, lsp_spk);

    int rc = -1;
    uint8_t sent = 0;

    /* No database, no channel: nothing is owed, the client takes part. */
    client_set_persist(NULL);
    TEST_ASSERT(cs_run_client_close(ctx, &kps[1], &pks[1], f, NULL,
                                     &all_to_lsp, 1, &rc, &sent), "run");
    TEST_ASSERT(sent == MSG_CLOSE_NONCE, "client without a channel signs");

    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open in-memory db");
    client_set_persist(&db);

    /* The factory is on record, with no channel in it. */
    TEST_ASSERT(persist_save_factory(&db, f, ctx, 0), "save factory");
    TEST_ASSERT(!persist_factory_has_channel(&db, f->funding_txid,
                                              f->funding_vout),
                "no channel on record");
    int ok = cs_run_client_close(ctx, &kps[1], &pks[1], f, NULL,
                                  &all_to_lsp, 1, &rc, &sent);
    int signed_without_record = ok && sent == MSG_CLOSE_NONCE;

    /* A channel is on record for this factory. */
    channel_t ch;
    cs_channel(&ch, 100000);
    int saved = persist_save_channel(&db, &ch, 0, 0);
    int has = persist_factory_has_channel(&db, f->funding_txid,
                                           f->funding_vout);
    int rc2 = -1;
    uint8_t sent2 = 0;
    int ok2 = cs_run_client_close(ctx, &kps[1], &pks[1], f, NULL,
                                   &all_to_lsp, 1, &rc2, &sent2);

    /* The record is for a different factory: this one has no channel. */
    unsigned char other_txid[32];
    memset(other_txid, 0xBB, 32);
    int has_other = persist_factory_has_channel(&db, other_txid,
                                                 f->funding_vout);
    int has_other_vout = persist_factory_has_channel(&db, f->funding_txid,
                                                      f->funding_vout + 1);

    client_set_persist(NULL);
    persist_close(&db);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);

    TEST_ASSERT(signed_without_record,
                "client signs when its records hold no channel");
    TEST_ASSERT(saved && has, "channel on record for this factory");
    TEST_ASSERT(ok2, "run");
    TEST_ASSERT(sent2 != MSG_CLOSE_NONCE, "client reveals no nonce");
    TEST_ASSERT(rc2 == 0 && sent2 == MSG_ERROR,
                "client started without its recorded channel refuses");
    TEST_ASSERT(!has_other && !has_other_vout,
                "a channel of another factory does not count");
    return 1;
}

/* Build client 1's channel on its leaf output the way the client does. */
static int cs_client_channel(channel_t *ch, secp256k1_context *ctx,
                             const factory_t *f, const secp256k1_keypair *kps,
                             const secp256k1_pubkey *pks) {
    static const unsigned char sec[4][32] = {
        { [0 ... 31] = 0x61 }, { [0 ... 31] = 0x62 },
        { [0 ... 31] = 0x63 }, { [0 ... 31] = 0x64 },
    };
    /* Any valid points serve as the LSP's basepoints here. */
    return client_init_channel(ch, ctx, f, &kps[1], 1,
                                &pks[0], &pks[2], &pks[3], &pks[4],
                                sec[0], sec[1], sec[2], sec[3], NULL);
}

/* Reload the channel as a reconnecting client does: rebuild it from the
   factory, then overwrite balances and commitment number with the stored
   ones.  HTLCs are not part of what is stored or restored. */
static int cs_client_channel_reload(channel_t *ch, secp256k1_context *ctx,
                                    const factory_t *f,
                                    const secp256k1_keypair *kps,
                                    const secp256k1_pubkey *pks,
                                    persist_t *db) {
    uint64_t local = 0, remote = 0, cn = 0;
    if (!cs_client_channel(ch, ctx, f, kps, pks)) return 0;
    if (!persist_load_channel_state(db, 0, &local, &remote, &cn)) return 0;
    ch->local_amount = local;
    ch->remote_amount = remote;
    ch->commitment_number = cn;
    return 1;
}

/* A close attempted after a reconnect.  The client offered an HTLC, saved
   its balances and reconnected: the reloaded channel has the reduced balance
   and an empty HTLC list.  A proposal that pays that balance exactly must be
   refused, or the HTLC amount would go to the LSP. */
static int test_client_close_after_reconnect_with_htlc_in_flight_body(void) {
    secp256k1_context *ctx = cs_ctx();
    secp256k1_keypair kps[CS_N];
    secp256k1_pubkey pks[CS_N];
    TEST_ASSERT(cs_keys(ctx, kps, pks), "keys");
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f != NULL, "alloc");
    TEST_ASSERT(cs_build_factory(f, ctx, kps, pks), "build factory");

    unsigned char lsp_spk[34], my_spk[34];
    TEST_ASSERT(client_close_script(ctx, &pks[0], lsp_spk), "lsp script");
    TEST_ASSERT(client_close_script(ctx, &pks[1], my_spk), "client script");

    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open in-memory db");
    TEST_ASSERT(persist_save_factory(&db, f, ctx, 0), "save factory");

    int pass = 1;
#define CS_CHECK(cond, msg) do { \
        if (pass && !(cond)) { \
            printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
            pass = 0; \
        } \
    } while (0)

    channel_t live;
    CS_CHECK(cs_client_channel(&live, ctx, f, kps, pks), "open channel");
    const uint64_t balance_before = live.local_amount;
    CS_CHECK(balance_before > 50000, "client holds a balance");
    CS_CHECK(persist_save_channel(&db, &live, 0, 0), "save channel");

    tx_output_t outs[2];
    int rc = -1;
    uint8_t sent = 0;

    /* Control: reconnect with nothing in flight, close paying the balance. */
    {
        channel_t reloaded;
        CS_CHECK(cs_client_channel_reload(&reloaded, ctx, f, kps, pks, &db),
                 "reload channel");
        CS_CHECK(reloaded.local_amount == balance_before, "balance restored");
        cs_output(&outs[0], CS_FUNDING - 1000 - reloaded.local_amount, lsp_spk);
        cs_output(&outs[1], reloaded.local_amount, my_spk);
        CS_CHECK(cs_run_client_close(ctx, &kps[1], &pks[1], f, &reloaded,
                                      outs, 2, &rc, &sent), "run");
        CS_CHECK(sent == MSG_CLOSE_NONCE,
                 "reconnected client with nothing in flight signs");
        channel_cleanup(&reloaded);
    }

    /* The client offers an HTLC and stores its new balances. */
    const uint64_t htlc_amount = 20000;
    unsigned char payment_hash[32];
    memset(payment_hash, 0x5A, 32);
    uint64_t htlc_id = 0;
    CS_CHECK(channel_add_htlc(&live, HTLC_OFFERED, htlc_amount, payment_hash,
                               500, &htlc_id), "offer HTLC");
    CS_CHECK(live.local_amount < balance_before, "HTLC left the balance");
    CS_CHECK(persist_update_channel_balance(&db, 0, live.local_amount,
                                             live.remote_amount,
                                             live.commitment_number),
             "store balances");

    /* While still connected, the pending-HTLC rule refuses. */
    cs_output(&outs[0], CS_FUNDING - 1000 - live.local_amount, lsp_spk);
    cs_output(&outs[1], live.local_amount, my_spk);
    CS_CHECK(cs_run_client_close(ctx, &kps[1], &pks[1], f, &live, outs, 2,
                                  &rc, &sent), "run");
    CS_CHECK(rc == 0 && sent == MSG_ERROR,
             "connected client refuses over the pending HTLC");

    /* Reconnect: the HTLC is gone from the channel, its amount from the
       balance. */
    {
        channel_t reloaded;
        CS_CHECK(cs_client_channel_reload(&reloaded, ctx, f, kps, pks, &db),
                 "reload channel");
        size_t n_active = 0;
        for (size_t i = 0; i < reloaded.n_htlcs; i++)
            if (reloaded.htlcs[i].state == HTLC_STATE_ACTIVE) n_active++;
        CS_CHECK(n_active == 0, "no HTLC restored on reconnect");
        CS_CHECK(reloaded.local_amount == live.local_amount &&
                 reloaded.local_amount < balance_before,
                 "reloaded balance excludes the HTLC amount");

        /* The LSP offers exactly that reduced balance. */
        cs_output(&outs[0], CS_FUNDING - 1000 - reloaded.local_amount, lsp_spk);
        cs_output(&outs[1], reloaded.local_amount, my_spk);
        CS_CHECK(cs_run_client_close(ctx, &kps[1], &pks[1], f, &reloaded,
                                      outs, 2, &rc, &sent), "run");
        CS_CHECK(sent != MSG_CLOSE_NONCE, "client reveals no nonce");
        CS_CHECK(rc == 0 && sent == MSG_ERROR,
                 "reconnected client refuses a close that drops its HTLC");
        channel_cleanup(&reloaded);
    }
#undef CS_CHECK

    channel_cleanup(&live);
    persist_close(&db);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return pass;
}

/* The nLockTime of a proposed close must be near the client's own chain tip,
   and cannot be judged at all without one. */
static int test_client_close_locktime_bound_body(void) {
    const uint32_t tip = 800000;
    const uint32_t margin = CLIENT_CLOSE_LOCKTIME_MARGIN;

    TEST_ASSERT(client_close_locktime_acceptable(0, 0), "no lock, no tip");
    TEST_ASSERT(client_close_locktime_acceptable(0, tip), "no lock");
    TEST_ASSERT(client_close_locktime_acceptable(tip, tip), "lock at the tip");
    TEST_ASSERT(client_close_locktime_acceptable(tip - 1000, tip),
                "lock below the tip");
    TEST_ASSERT(client_close_locktime_acceptable(tip + margin, tip),
                "lock at the margin");
    TEST_ASSERT(!client_close_locktime_acceptable(tip + margin + 1, tip),
                "lock one block past the margin");
    TEST_ASSERT(!client_close_locktime_acceptable(tip + 100000, tip),
                "lock far in the future");
    TEST_ASSERT(!client_close_locktime_acceptable(tip, 0),
                "a height cannot be judged without a tip");
    TEST_ASSERT(!client_close_locktime_acceptable(1, 0),
                "any height needs a tip");
    TEST_ASSERT(!client_close_locktime_acceptable(500000000u, 499999999u),
                "time-based lock");
    TEST_ASSERT(!client_close_locktime_acceptable(0xFFFFFFFFu, 0xFFFFFFFFu),
                "time-based lock, maximum value");

    /* The ceremony applies the rule before revealing a nonce. */
    secp256k1_context *ctx = cs_ctx();
    secp256k1_keypair kps[CS_N];
    secp256k1_pubkey pks[CS_N];
    TEST_ASSERT(cs_keys(ctx, kps, pks), "keys");
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f != NULL, "alloc");
    TEST_ASSERT(cs_build_factory(f, ctx, kps, pks), "build factory");

    unsigned char lsp_spk[34], my_spk[34];
    TEST_ASSERT(client_close_script(ctx, &pks[0], lsp_spk), "lsp script");
    TEST_ASSERT(client_close_script(ctx, &pks[1], my_spk), "client script");
    const uint64_t balance = 120000;
    channel_t ch;
    cs_channel(&ch, balance);
    tx_output_t outs[2];
    cs_output(&outs[0], CS_FUNDING - 1000 - balance, lsp_spk);
    cs_output(&outs[1], balance, my_spk);

    enum { CS_REFUSES, CS_SIGNS, CS_CANNOT_VERIFY };
    struct { uint32_t locktime, tip; int expect; } cases[] = {
        { tip + margin + 1, tip, CS_REFUSES },        /* too far ahead */
        { 500000000u,       tip, CS_REFUSES },        /* time-based */
        { 500000000u,       0,   CS_REFUSES },        /* time-based, no tip */
        { tip,              0,   CS_CANNOT_VERIFY },  /* client has no tip */
        { tip + margin,     tip, CS_SIGNS },
        { tip,              tip, CS_SIGNS },
        { 0,                0,   CS_SIGNS },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        client_close_state_t cs;
        client_close_state_init(&cs, NULL, f);
        cs_lsp_msg_t msgs[1] = { cs_msg_propose(outs, 2, cases[i].locktime) };
        int rc = -1;
        uint8_t sent[CS_MAX_SENT];
        size_t n_sent = 0;
        TEST_ASSERT(cs_run_client_close_script(ctx, &kps[1], &pks[1], f, &ch,
                                                &cs, cases[i].tip, msgs, 1,
                                                &rc, sent, &n_sent), "run");
        if (cases[i].expect == CS_SIGNS) {
            TEST_ASSERT(n_sent >= 1 && sent[0] == MSG_CLOSE_NONCE,
                        "acceptable nLockTime: client takes part");
            TEST_ASSERT(!cs.refused && !cs.unverifiable, "no refusal recorded");
        } else {
            TEST_ASSERT(rc == 0 && n_sent == 1 && sent[0] == MSG_ERROR,
                        "nLockTime not accepted: error sent, no nonce");
            TEST_ASSERT(!cs.signed_close, "nothing was signed");
            if (cases[i].expect == CS_REFUSES)
                TEST_ASSERT(cs.refused && !cs.unverifiable,
                            "unacceptable nLockTime is a refusal");
            else
                TEST_ASSERT(cs.unverifiable && !cs.refused,
                            "no tip: cannot verify, not a refusal");
        }
    }

    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A scripted chain tip source: answers cs_tip_before for the first
   cs_tip_changes_after queries and cs_tip_after from then on. */
static int cs_tip_calls;
static int cs_tip_changes_after;
static uint32_t cs_tip_before, cs_tip_after;
static uint32_t cs_tip_source(void *ctx) {
    (void)ctx;
    cs_tip_calls++;
    return cs_tip_calls > cs_tip_changes_after ? cs_tip_after : cs_tip_before;
}

/* The chain backend may be unreachable for a moment or a few blocks behind.
   The client asks again for a bounded time.  If it still has no tip it says
   "cannot verify, try again" and neither signs nor records anything; that is
   not a refusal.  A tip that is known and stays too low is a refusal. */
static int test_client_close_tip_retry_body(void) {
    const uint32_t tip = 800000;
    const int attempts = 4;
    secp256k1_context *ctx = cs_ctx();
    secp256k1_keypair kps[CS_N];
    secp256k1_pubkey pks[CS_N];
    TEST_ASSERT(cs_keys(ctx, kps, pks), "keys");
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f != NULL, "alloc");
    TEST_ASSERT(cs_build_factory(f, ctx, kps, pks), "build factory");

    unsigned char lsp_spk[34], my_spk[34];
    TEST_ASSERT(client_close_script(ctx, &pks[0], lsp_spk), "lsp script");
    TEST_ASSERT(client_close_script(ctx, &pks[1], my_spk), "client script");
    const uint64_t balance = 120000;
    channel_t ch;
    cs_channel(&ch, balance);
    tx_output_t outs[2];
    cs_output(&outs[0], CS_FUNDING - 1000 - balance, lsp_spk);
    cs_output(&outs[1], balance, my_spk);

    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open in-memory db");
    client_set_chain_tip_source(cs_tip_source, NULL);
    client_set_chain_tip_retry((unsigned)attempts, 5);

    /* { tip before, tip after, changes after n queries, nLockTime,
         expected: 1 signs, 0 refuses, 2 cannot verify, expected queries } */
    struct { uint32_t before, after; int changes_after; uint32_t locktime;
             int expect, queries; } cases[] = {
        { 0,        tip, 2,   tip, 1, 3 },         /* backend comes back */
        { 0,        0,   0,   tip, 2, attempts },  /* never comes back */
        { tip - 20, tip, 2,   tip, 1, 3 },         /* behind, catches up */
        { tip - 20, tip - 20, 0, tip, 0, attempts },  /* stays behind */
        { tip - 3,  tip - 3,  0, tip, 1, 1 },      /* behind within margin */
        { 0,        0,   0,   0,   1, 0 },         /* no lock: tip not needed */
        { 0,        0,   0,   500000000u, 0, 0 },  /* time lock: no point */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        cs_tip_calls = 0;
        cs_tip_before = cases[i].before;
        cs_tip_after = cases[i].after;
        cs_tip_changes_after = cases[i].changes_after;

        client_close_state_t cs;
        client_close_state_init(&cs, &db, f);
        cs_lsp_msg_t msgs[1] = { cs_msg_propose(outs, 2, cases[i].locktime) };
        int rc = -1;
        uint8_t sent[CS_MAX_SENT];
        size_t n_sent = 0;
        /* The caller's own reading of the tip was 0 as well. */
        TEST_ASSERT(cs_run_client_close_script(ctx, &kps[1], &pks[1], f, &ch,
                                                &cs, 0, msgs, 1, &rc, sent,
                                                &n_sent), "run");
        if (cs_tip_calls != cases[i].queries)
            printf("  case %zu: %d tip queries, expected %d\n", i,
                   cs_tip_calls, cases[i].queries);
        TEST_ASSERT(cs_tip_calls == cases[i].queries,
                    "tip is asked for a bounded number of times");
        if (cases[i].expect == 1) {
            TEST_ASSERT(n_sent >= 1 && sent[0] == MSG_CLOSE_NONCE,
                        "client takes part once the tip allows it");
            TEST_ASSERT(!cs.refused && !cs.unverifiable, "no refusal");
        } else {
            TEST_ASSERT(rc == 0 && n_sent == 1 && sent[0] == MSG_ERROR,
                        "error sent, no nonce");
            if (cases[i].expect == 2)
                TEST_ASSERT(cs.unverifiable && !cs.refused,
                            "no tip after retrying: cannot verify");
            else
                TEST_ASSERT(cs.refused && !cs.unverifiable,
                            "known tip too low or time lock: refused");
        }
        /* Nothing is signed in any of these runs (the script ends after the
           proposal), so nothing may be on record and nothing is frozen. */
        TEST_ASSERT(!cs.signed_close, "nothing signed");
        TEST_ASSERT(persist_load_close_signed(&db, f->funding_txid,
                                               f->funding_vout, NULL,
                                               NULL) == 0,
                    "nothing recorded");
    }

    client_set_chain_tip_source(NULL, NULL);
    client_set_chain_tip_retry(CLIENT_CHAIN_TIP_ATTEMPTS,
                               CLIENT_CHAIN_TIP_RETRY_MS);
    persist_close(&db);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Once the client has released a partial signature for a close, the LSP may
   complete that close whenever it likes.  The client remembers it: it signs
   a later proposal only if that pays at least as much, and takes part in no
   leaf or state advance of the factory. */
static int test_client_close_records_signed_close_body(void) {
    secp256k1_context *ctx = cs_ctx();
    secp256k1_keypair kps[CS_N];
    secp256k1_pubkey pks[CS_N];
    TEST_ASSERT(cs_keys(ctx, kps, pks), "keys");
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f != NULL, "alloc");
    TEST_ASSERT(cs_build_factory(f, ctx, kps, pks), "build factory");

    unsigned char lsp_spk[34], my_spk[34];
    TEST_ASSERT(client_close_script(ctx, &pks[0], lsp_spk), "lsp script");
    TEST_ASSERT(client_close_script(ctx, &pks[1], my_spk), "client script");

    const uint64_t balance = 120000, generous = balance + 500;
    channel_t ch;
    cs_channel(&ch, balance);
    tx_output_t pay_generous[2], pay_exact[2];
    cs_output(&pay_generous[0], CS_FUNDING - 1000 - generous, lsp_spk);
    cs_output(&pay_generous[1], generous, my_spk);
    cs_output(&pay_exact[0], CS_FUNDING - 1000 - balance, lsp_spk);
    cs_output(&pay_exact[1], balance, my_spk);

    client_close_state_t cs;
    client_close_state_init(&cs, NULL, f);
    TEST_ASSERT(!cs.signed_close, "nothing signed yet");
    int rc = -1;
    uint8_t sent[CS_MAX_SENT];
    size_t n_sent = 0;

    /* A refused proposal leaves no record. */
    {
        tx_output_t all_to_lsp;
        cs_output(&all_to_lsp, CS_FUNDING - 1000, lsp_spk);
        cs_lsp_msg_t msgs[1] = { cs_msg_propose(&all_to_lsp, 1, 0) };
        TEST_ASSERT(cs_run_client_close_script(ctx, &kps[1], &pks[1], f, &ch,
                        &cs, 0, msgs, 1, &rc, sent, &n_sent), "run");
        TEST_ASSERT(rc == 0 && cs.refused && !cs.signed_close,
                    "refusal records no signed close");
    }

    /* The client signs, then the LSP reports that the close failed. */
    {
        cs_lsp_msg_t msgs[3] = { cs_msg_propose(pay_generous, 2, 0),
                                 cs_msg_all_nonces(ctx, pks),
                                 cs_msg_error() };
        TEST_ASSERT(cs_run_client_close_script(ctx, &kps[1], &pks[1], f, &ch,
                        &cs, 0, msgs, 3, &rc, sent, &n_sent), "run");
        TEST_ASSERT(n_sent == 2 && sent[0] == MSG_CLOSE_NONCE &&
                    sent[1] == MSG_CLOSE_PSIG, "client signed the close");
        TEST_ASSERT(rc == 0 && !cs.refused, "ceremony failed, not refused");
        TEST_ASSERT(cs.signed_close && cs.paid_sats == generous,
                    "the signed close is on record with what it pays");
        unsigned char zero[32] = {0};
        TEST_ASSERT(memcmp(cs.sighash, zero, 32) != 0, "sighash on record");
    }

    /* A new proposal that covers the balance but pays less than the close
       already signed is refused. */
    {
        cs_lsp_msg_t msgs[2] = { cs_msg_propose(pay_exact, 2, 0),
                                 cs_msg_all_nonces(ctx, pks) };
        TEST_ASSERT(cs_run_client_close_script(ctx, &kps[1], &pks[1], f, &ch,
                        &cs, 0, msgs, 2, &rc, sent, &n_sent), "run");
        TEST_ASSERT(rc == 0 && n_sent == 1 && sent[0] == MSG_ERROR,
                    "lower-paying replacement refused, no nonce");
        TEST_ASSERT(cs.refused && cs.paid_sats == generous,
                    "record unchanged by the refusal");
    }

    /* A leaf or state advance arriving in the ceremony is refused. */
    {
        const uint8_t advance_types[3] = { MSG_LEAF_ADVANCE_PROPOSE,
                                           MSG_STATE_ADVANCE_PROPOSE,
                                           MSG_STATE_ADV_PROPOSE_INTENT };
        for (int t = 0; t < 3; t++) {
            cs_lsp_msg_t msgs[1] = { { advance_types[t], cJSON_CreateObject() } };
            TEST_ASSERT(cs_run_client_close_script(ctx, &kps[1], &pks[1], f,
                            &ch, &cs, 0, msgs, 1, &rc, sent, &n_sent), "run");
            TEST_ASSERT(rc == 0 && cs.refused && n_sent == 1 &&
                        sent[0] == MSG_ERROR,
                        "advance after a signed close is refused");
        }
        /* The same advance arriving between the nonce and the signature of a
           re-proposed close. */
        cs_lsp_msg_t msgs[2] = { cs_msg_propose(pay_generous, 2, 0),
                                 { MSG_LEAF_ADVANCE_PROPOSE,
                                   cJSON_CreateObject() } };
        TEST_ASSERT(cs_run_client_close_script(ctx, &kps[1], &pks[1], f, &ch,
                        &cs, 0, msgs, 2, &rc, sent, &n_sent), "run");
        TEST_ASSERT(rc == 0 && cs.refused && n_sent == 2 &&
                    sent[0] == MSG_CLOSE_NONCE && sent[1] == MSG_ERROR,
                    "advance during a re-proposed close is refused");
    }

    /* A proposal paying at least as much is signed, and can complete. */
    {
        cs_lsp_msg_t msgs[3] = { cs_msg_propose(pay_generous, 2, 0),
                                 cs_msg_all_nonces(ctx, pks),
                                 cs_msg_done() };
        TEST_ASSERT(cs_run_client_close_script(ctx, &kps[1], &pks[1], f, &ch,
                        &cs, 0, msgs, 3, &rc, sent, &n_sent), "run");
        TEST_ASSERT(rc == 1 && n_sent == 2 && sent[1] == MSG_CLOSE_PSIG,
                    "equal-paying replacement signed and completed");
        TEST_ASSERT(!cs.refused && cs.signed_close, "still on record");
    }

    /* Within one ceremony: the LSP re-proposes after the client signed, with
       a lower payout.  The first round is signed, the second refused. */
    {
        client_close_state_t fresh;
        client_close_state_init(&fresh, NULL, f);
        cs_lsp_msg_t msgs[4] = { cs_msg_propose(pay_generous, 2, 0),
                                 cs_msg_all_nonces(ctx, pks),
                                 cs_msg_propose(pay_exact, 2, 0),
                                 cs_msg_all_nonces(ctx, pks) };
        TEST_ASSERT(cs_run_client_close_script(ctx, &kps[1], &pks[1], f, &ch,
                        &fresh, 0, msgs, 4, &rc, sent, &n_sent), "run");
        TEST_ASSERT(rc == 0 && n_sent == 3 && sent[0] == MSG_CLOSE_NONCE &&
                    sent[1] == MSG_CLOSE_PSIG && sent[2] == MSG_ERROR,
                    "lower-paying re-proposal refused after signing");
        TEST_ASSERT(fresh.refused && fresh.paid_sats == generous,
                    "record keeps the close that was signed");
    }

    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* After the client signed, the LSP may propose different outputs.  What
   matters to the client stays the same: its one output must pay at least
   what the signed close pays. */
static int test_client_close_repropose_changed_outputs_body(void) {
    secp256k1_context *ctx = cs_ctx();
    secp256k1_keypair kps[CS_N];
    secp256k1_pubkey pks[CS_N];
    TEST_ASSERT(cs_keys(ctx, kps, pks), "keys");
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f != NULL, "alloc");
    TEST_ASSERT(cs_build_factory(f, ctx, kps, pks), "build factory");

    unsigned char spk[CS_N][34];
    for (int i = 0; i < CS_N; i++)
        TEST_ASSERT(client_close_script(ctx, &pks[i], spk[i]), "close script");

    const uint64_t balance = 120000, first = balance + 500;
    channel_t ch;
    cs_channel(&ch, balance);

    tx_output_t original[2];
    cs_output(&original[0], CS_FUNDING - 1000 - first, spk[0]);
    cs_output(&original[1], first, spk[1]);

    /* Different fee, another party's output added, the client's own output
       moved and raised. */
    tx_output_t changed[3];
    cs_output(&changed[0], first + 200, spk[1]);
    cs_output(&changed[1], 300000, spk[2]);
    cs_output(&changed[2], CS_FUNDING - 3000 - 300000 - first - 200, spk[0]);

    /* Same total for the client, now in two outputs. */
    tx_output_t split[3];
    cs_output(&split[0], CS_FUNDING - 1000 - first, spk[0]);
    cs_output(&split[1], first - 20000, spk[1]);
    cs_output(&split[2], 20000, spk[1]);

    /* Other outputs changed, the client's output one sat lower: still above
       its balance, below what it already signed for. */
    tx_output_t lower[3];
    cs_output(&lower[0], CS_FUNDING - 2000 - first, spk[0]);
    cs_output(&lower[1], first - 1, spk[1]);
    cs_output(&lower[2], 800, spk[3]);

    int rc = -1;
    uint8_t sent[CS_MAX_SENT];
    size_t n_sent = 0;

    {
        client_close_state_t cs;
        client_close_state_init(&cs, NULL, f);
        cs_lsp_msg_t msgs[5] = { cs_msg_propose(original, 2, 0),
                                 cs_msg_all_nonces(ctx, pks),
                                 cs_msg_propose(changed, 3, 0),
                                 cs_msg_all_nonces(ctx, pks),
                                 cs_msg_done() };
        TEST_ASSERT(cs_run_client_close_script(ctx, &kps[1], &pks[1], f, &ch,
                        &cs, 0, msgs, 5, &rc, sent, &n_sent), "run");
        TEST_ASSERT(rc == 1 && n_sent == 4 && sent[0] == MSG_CLOSE_NONCE &&
                    sent[1] == MSG_CLOSE_PSIG && sent[2] == MSG_CLOSE_NONCE &&
                    sent[3] == MSG_CLOSE_PSIG,
                    "changed outputs paying more in one output are signed");
        TEST_ASSERT(cs.signed_close && cs.paid_sats == first + 200,
                    "record follows the close signed last");
    }
    {
        client_close_state_t cs;
        client_close_state_init(&cs, NULL, f);
        cs_lsp_msg_t msgs[4] = { cs_msg_propose(original, 2, 0),
                                 cs_msg_all_nonces(ctx, pks),
                                 cs_msg_propose(split, 3, 0),
                                 cs_msg_all_nonces(ctx, pks) };
        TEST_ASSERT(cs_run_client_close_script(ctx, &kps[1], &pks[1], f, &ch,
                        &cs, 0, msgs, 4, &rc, sent, &n_sent), "run");
        TEST_ASSERT(rc == 0 && n_sent == 3 && sent[1] == MSG_CLOSE_PSIG &&
                    sent[2] == MSG_ERROR && cs.refused,
                    "re-proposal splitting the payout is refused");
        TEST_ASSERT(cs.paid_sats == first, "record unchanged");
    }
    {
        client_close_state_t cs;
        client_close_state_init(&cs, NULL, f);
        cs_lsp_msg_t msgs[4] = { cs_msg_propose(original, 2, 0),
                                 cs_msg_all_nonces(ctx, pks),
                                 cs_msg_propose(lower, 3, 0),
                                 cs_msg_all_nonces(ctx, pks) };
        TEST_ASSERT(cs_run_client_close_script(ctx, &kps[1], &pks[1], f, &ch,
                        &cs, 0, msgs, 4, &rc, sent, &n_sent), "run");
        TEST_ASSERT(rc == 0 && n_sent == 3 && sent[1] == MSG_CLOSE_PSIG &&
                    sent[2] == MSG_ERROR && cs.refused,
                    "re-proposal paying one sat less is refused");
        TEST_ASSERT(cs.paid_sats == first, "record unchanged");
    }

    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* When the client's own records cannot be read it must not act as if they
   were empty: it signs no close and takes part in no advance. */
static int test_client_close_record_unreadable_body(void) {
    secp256k1_context *ctx = cs_ctx();
    secp256k1_keypair kps[CS_N];
    secp256k1_pubkey pks[CS_N];
    TEST_ASSERT(cs_keys(ctx, kps, pks), "keys");
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f != NULL, "alloc");
    TEST_ASSERT(cs_build_factory(f, ctx, kps, pks), "build factory");

    unsigned char lsp_spk[34], my_spk[34];
    TEST_ASSERT(client_close_script(ctx, &pks[0], lsp_spk), "lsp script");
    TEST_ASSERT(client_close_script(ctx, &pks[1], my_spk), "client script");
    const uint64_t balance = 120000;
    channel_t ch;
    cs_channel(&ch, balance);
    tx_output_t outs[2];
    cs_output(&outs[0], CS_FUNDING - 1000 - balance, lsp_spk);
    cs_output(&outs[1], balance, my_spk);

    int rc = -1;
    uint8_t sent[CS_MAX_SENT];
    size_t n_sent = 0;

    /* 1. The table of signed closes is gone. */
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open in-memory db");
    TEST_ASSERT(persist_load_close_signed(&db, f->funding_txid,
                                           f->funding_vout, NULL, NULL) == 0,
                "readable and empty: no record");
    TEST_ASSERT(sqlite3_exec(db.db, "DROP TABLE client_close_signed;",
                             NULL, NULL, NULL) == SQLITE_OK, "drop table");
    TEST_ASSERT(persist_load_close_signed(&db, f->funding_txid,
                                           f->funding_vout, NULL, NULL) == -1,
                "unreadable is reported as an error, not as no record");

    client_close_state_t cs;
    client_close_state_init(&cs, &db, f);
    TEST_ASSERT(cs.record_error && !cs.signed_close, "state knows it is blind");
    TEST_ASSERT(client_close_state_frozen(&cs, f) == 1,
                "a factory whose close record cannot be read is frozen");
    TEST_ASSERT(cs.record_error && !cs.signed_close,
                "still blind after looking again");
    TEST_ASSERT(!client_close_frozen_allows_msg(MSG_UPDATE_ADD_HTLC) &&
                !client_close_frozen_allows_msg(MSG_COMMITMENT_SIGNED) &&
                !client_close_frozen_allows_msg(MSG_LEAF_ADVANCE_PROPOSE) &&
                client_close_frozen_allows_msg(MSG_CLOSE_PROPOSE),
                "a frozen factory acts on a close proposal, not on updates");
    {
        cs_lsp_msg_t msgs[2] = { cs_msg_propose(outs, 2, 0),
                                 cs_msg_all_nonces(ctx, pks) };
        TEST_ASSERT(cs_run_client_close_script(ctx, &kps[1], &pks[1], f, &ch,
                        &cs, 0, msgs, 2, &rc, sent, &n_sent), "run");
        TEST_ASSERT(rc == 0 && n_sent == 1 && sent[0] == MSG_ERROR,
                    "no nonce and no signature without the record");
        TEST_ASSERT(cs.unverifiable && !cs.refused && !cs.signed_close,
                    "ends as cannot-verify");
    }
    /* A caller that passes no state reads through client_set_persist. */
    client_set_persist(&db);
    {
        cs_lsp_msg_t msgs[2] = { cs_msg_propose(outs, 2, 0),
                                 cs_msg_all_nonces(ctx, pks) };
        TEST_ASSERT(cs_run_client_close_script(ctx, &kps[1], &pks[1], f, &ch,
                        NULL, 0, msgs, 2, &rc, sent, &n_sent), "run");
        TEST_ASSERT(rc == 0 && n_sent == 1 && sent[0] == MSG_ERROR,
                    "same without a caller-supplied state");
    }
    TEST_ASSERT(client_close_signed_for_factory(f) == 1,
                "the freeze applies when the record cannot be read");
    {
        int sv[2];
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
        wire_msg_t propose;
        memset(&propose, 0, sizeof(propose));
        propose.msg_type = MSG_LEAF_ADVANCE_PROPOSE;
        propose.json = cJSON_CreateObject();
        shutdown(sv[0], SHUT_WR);
        int hrc = client_handle_leaf_advance(sv[1], ctx, &kps[1], f, 1, &propose);
        cJSON_Delete(propose.json);
        close(sv[1]);
        wire_msg_t reply;
        memset(&reply, 0, sizeof(reply));
        uint8_t got = 0;
        if (wire_recv(sv[0], &reply)) {
            got = reply.msg_type;
            if (reply.json) cJSON_Delete(reply.json);
        }
        close(sv[0]);
        TEST_ASSERT(hrc == 0 && got == MSG_ERROR,
                    "leaf advance is refused when the record cannot be read");
    }
    client_set_persist(NULL);

    /* The error passes: the table is back.  Looking again lifts the freeze
       when nothing was signed, and finds the record when something was. */
    {
        static const char *recreate =
            "CREATE TABLE client_close_signed ("
            "  funding_txid BLOB NOT NULL, funding_vout INTEGER NOT NULL,"
            "  paid_sats INTEGER NOT NULL, sighash BLOB NOT NULL,"
            "  PRIMARY KEY (funding_txid, funding_vout));";
        TEST_ASSERT(sqlite3_exec(db.db, recreate, NULL, NULL, NULL) ==
                    SQLITE_OK, "table back");
        client_close_state_t blind = cs;   /* record_error still set */
        TEST_ASSERT(blind.record_error, "state was blind");
        TEST_ASSERT(client_close_state_frozen(&blind, f) == 0 &&
                    !blind.record_error && !blind.signed_close,
                    "readable and empty: the freeze lifts");

        unsigned char sighash[32];
        memset(sighash, 0x77, 32);
        TEST_ASSERT(persist_save_close_signed(&db, f->funding_txid,
                                               f->funding_vout, 123456,
                                               sighash), "save a record");
        client_close_state_t blind2 = cs;
        TEST_ASSERT(client_close_state_frozen(&blind2, f) == 1 &&
                    blind2.signed_close && blind2.paid_sats == 123456 &&
                    !blind2.record_error,
                    "readable with a record: frozen as signed");
        client_close_state_t fresh;
        client_close_state_init(&fresh, &db, f);
        TEST_ASSERT(client_close_state_frozen(&fresh, f) == 1, "frozen");
        client_close_state_t none;
        client_close_state_init(&none, NULL, f);
        TEST_ASSERT(client_close_state_frozen(&none, f) == 0,
                    "no database, nothing signed: not frozen");
    }
    persist_close(&db);

    /* 2. The channel records are gone and the client runs without a
       channel: it cannot tell whether it has one. */
    persist_t db2;
    TEST_ASSERT(persist_open(&db2, NULL), "open in-memory db");
    TEST_ASSERT(persist_factory_has_channel(&db2, f->funding_txid,
                                             f->funding_vout) == 0,
                "readable and empty: no channel");
    TEST_ASSERT(sqlite3_exec(db2.db, "PRAGMA foreign_keys=OFF;"
                                     "DROP TABLE channels;",
                             NULL, NULL, NULL) == SQLITE_OK, "drop table");
    TEST_ASSERT(persist_factory_has_channel(&db2, f->funding_txid,
                                             f->funding_vout) == -1,
                "unreadable is reported as an error, not as no channel");
    {
        client_close_state_t cs2;
        client_close_state_init(&cs2, &db2, f);
        TEST_ASSERT(!cs2.record_error, "close record itself is readable");
        tx_output_t all_to_lsp;
        cs_output(&all_to_lsp, CS_FUNDING - 1000, lsp_spk);
        cs_lsp_msg_t msgs[2] = { cs_msg_propose(&all_to_lsp, 1, 0),
                                 cs_msg_all_nonces(ctx, pks) };
        TEST_ASSERT(cs_run_client_close_script(ctx, &kps[1], &pks[1], f, NULL,
                        &cs2, 0, msgs, 2, &rc, sent, &n_sent), "run");
        TEST_ASSERT(rc == 0 && n_sent == 1 && sent[0] == MSG_ERROR,
                    "no channel and unreadable channel records: no nonce");
        TEST_ASSERT(cs2.unverifiable && !cs2.refused, "ends as cannot-verify");
    }
    persist_close(&db2);

    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* The record of a signed close is written to the client's database before
   the signature is sent, and a restarted client finds it there. */
static int test_client_close_record_survives_restart_body(void) {
    secp256k1_context *ctx = cs_ctx();
    secp256k1_keypair kps[CS_N];
    secp256k1_pubkey pks[CS_N];
    TEST_ASSERT(cs_keys(ctx, kps, pks), "keys");
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f != NULL, "alloc");
    TEST_ASSERT(cs_build_factory(f, ctx, kps, pks), "build factory");

    unsigned char lsp_spk[34], my_spk[34];
    TEST_ASSERT(client_close_script(ctx, &pks[0], lsp_spk), "lsp script");
    TEST_ASSERT(client_close_script(ctx, &pks[1], my_spk), "client script");
    const uint64_t balance = 120000, generous = balance + 500;
    channel_t ch;
    cs_channel(&ch, balance);
    tx_output_t pay_generous[2], pay_exact[2];
    cs_output(&pay_generous[0], CS_FUNDING - 1000 - generous, lsp_spk);
    cs_output(&pay_generous[1], generous, my_spk);
    cs_output(&pay_exact[0], CS_FUNDING - 1000 - balance, lsp_spk);
    cs_output(&pay_exact[1], balance, my_spk);

    /* A database file, closed and opened again between the two runs. */
    char db_path[] = "/tmp/ss_close_record_XXXXXX";
    int db_fd = mkstemp(db_path);
    TEST_ASSERT(db_fd >= 0, "temporary database file");
    close(db_fd);
    persist_t db;
    TEST_ASSERT(persist_open(&db, db_path), "open database file");
    int rc = -1;
    uint8_t sent[CS_MAX_SENT];
    size_t n_sent = 0;
    int pass = 1;
#define CS_CHECK(cond, msg) do { \
        if (pass && !(cond)) { \
            printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
            pass = 0; \
        } \
    } while (0)

    /* First run: the client signs, the LSP reports failure. */
    client_close_state_t cs;
    client_close_state_init(&cs, &db, f);
    CS_CHECK(!cs.signed_close, "no record before signing");
    {
        cs_lsp_msg_t msgs[3] = { cs_msg_propose(pay_generous, 2, 0),
                                 cs_msg_all_nonces(ctx, pks),
                                 cs_msg_error() };
        CS_CHECK(cs_run_client_close_script(ctx, &kps[1], &pks[1], f, &ch,
                     &cs, 0, msgs, 3, &rc, sent, &n_sent), "run");
        CS_CHECK(n_sent == 2 && sent[1] == MSG_CLOSE_PSIG, "client signed");
    }

    /* Restart: the database is closed, opened again from the file, and a
       fresh state is loaded from it. */
    persist_close(&db);
    memset(&db, 0, sizeof(db));
    CS_CHECK(persist_open(&db, db_path), "reopen database file");
    client_close_state_t reloaded;
    client_close_state_init(&reloaded, &db, f);
    CS_CHECK(!reloaded.record_error, "record readable after reopening");
    CS_CHECK(reloaded.signed_close, "record found after restart");
    CS_CHECK(reloaded.paid_sats == generous, "payout on record");
    CS_CHECK(memcmp(reloaded.sighash, cs.sighash, 32) == 0, "sighash on record");

    /* It is the record of this factory only. */
    {
        unsigned char saved_txid[32];
        memcpy(saved_txid, f->funding_txid, 32);
        memset(f->funding_txid, 0xBB, 32);
        client_close_state_t other;
        client_close_state_init(&other, &db, f);
        CS_CHECK(!other.signed_close, "another factory has no record");
        memcpy(f->funding_txid, saved_txid, 32);
    }

    /* A caller that passes no state gets the record through the database
       set with client_set_persist: the lower-paying proposal is refused. */
    client_set_persist(&db);
    {
        cs_lsp_msg_t msgs[2] = { cs_msg_propose(pay_exact, 2, 0),
                                 cs_msg_all_nonces(ctx, pks) };
        CS_CHECK(cs_run_client_close_script(ctx, &kps[1], &pks[1], f, &ch,
                     NULL, 0, msgs, 2, &rc, sent, &n_sent), "run");
        CS_CHECK(rc == 0 && n_sent == 1 && sent[0] == MSG_ERROR,
                 "restarted client refuses a lower-paying close");
    }

    /* The advance handlers refuse on the strength of the record alone. */
    for (int which = 0; which < 3; which++) {
        int sv[2];
        CS_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
        wire_msg_t propose;
        memset(&propose, 0, sizeof(propose));
        propose.json = cJSON_CreateObject();
        shutdown(sv[0], SHUT_WR);
        int hrc;
        if (which == 0) {
            propose.msg_type = MSG_LEAF_ADVANCE_PROPOSE;
            hrc = client_handle_leaf_advance(sv[1], ctx, &kps[1], f, 1, &propose);
        } else if (which == 1) {
            propose.msg_type = MSG_STATE_ADV_PROPOSE_INTENT;
            hrc = client_handle_state_advance(sv[1], ctx, &kps[1], f, 1, &propose);
        } else {
            propose.msg_type = MSG_SUBFACTORY_PROPOSE_INTENT;
            hrc = client_handle_subfactory_advance(sv[1], ctx, &kps[1], f, 1,
                                                    &propose);
        }
        cJSON_Delete(propose.json);
        close(sv[1]);
        wire_msg_t reply;
        memset(&reply, 0, sizeof(reply));
        uint8_t got = 0;
        if (wire_recv(sv[0], &reply)) {
            got = reply.msg_type;
            if (reply.json) cJSON_Delete(reply.json);
        }
        close(sv[0]);
        CS_CHECK(hrc == 0 && got == MSG_ERROR,
                 "advance of a factory with a signed close is refused");
    }
    client_set_persist(NULL);

    /* A higher-paying close replaces the record. */
    {
        tx_output_t pay_more[2];
        cs_output(&pay_more[0], CS_FUNDING - 1000 - generous - 100, lsp_spk);
        cs_output(&pay_more[1], generous + 100, my_spk);
        cs_lsp_msg_t msgs[3] = { cs_msg_propose(pay_more, 2, 0),
                                 cs_msg_all_nonces(ctx, pks),
                                 cs_msg_done() };
        CS_CHECK(cs_run_client_close_script(ctx, &kps[1], &pks[1], f, &ch,
                     &reloaded, 0, msgs, 3, &rc, sent, &n_sent), "run");
        CS_CHECK(rc == 1, "higher-paying close signed and completed");
        client_close_state_t again;
        client_close_state_init(&again, &db, f);
        CS_CHECK(again.signed_close && again.paid_sats == generous + 100,
                 "record updated to the close signed last");
    }
#undef CS_CHECK

    persist_close(&db);
    {
        static const char *suffix[] = { "", "-wal", "-shm", "-journal" };
        for (size_t i = 0; i < sizeof(suffix) / sizeof(suffix[0]); i++) {
            char file[sizeof(db_path) + 16];
            snprintf(file, sizeof(file), "%s%s", db_path, suffix[i]);
            unlink(file);
        }
    }
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return pass;
}

/* Full ceremony: the LSP proposes each party's balance at its own script and
   every client co-signs. */
static int test_client_close_honest_ceremony_body(void) {
    secp256k1_context *ctx = cs_ctx();
    secp256k1_keypair kps[CS_N];
    secp256k1_pubkey pks[CS_N];
    TEST_ASSERT(cs_keys(ctx, kps, pks), "keys");

    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    TEST_ASSERT(lsp != NULL, "alloc");
    TEST_ASSERT(lsp_init(lsp, ctx, &kps[0], 0, CS_N - 1), "lsp init");
    TEST_ASSERT(cs_build_factory(&lsp->factory, ctx, kps, pks), "build factory");

    /* Client 4 is below the dust limit and gets no output. */
    const uint64_t balances[CS_N - 1] = { 100000, 250000, 40000, 300 };
    const uint64_t fee = 500;
    tx_output_t outs[CS_N];
    size_t n_outs = 1;
    uint64_t client_total = 0;
    for (int c = 0; c < CS_N - 1; c++) {
        if (balances[c] < CHANNEL_DUST_LIMIT_SATS) continue;
        unsigned char spk[34];
        TEST_ASSERT(client_close_script(ctx, &pks[c + 1], spk), "client script");
        cs_output(&outs[n_outs++], balances[c], spk);
        client_total += balances[c];
    }
    unsigned char lsp_spk[34];
    TEST_ASSERT(client_close_script(ctx, &pks[0], lsp_spk), "lsp script");
    cs_output(&outs[0], CS_FUNDING - fee - client_total, lsp_spk);

    pid_t pids[CS_N - 1];
    for (int c = 0; c < CS_N - 1; c++) {
        int sv[2];
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
        fflush(stdout);
        pid_t pid = fork();
        TEST_ASSERT(pid >= 0, "fork");
        if (pid == 0) {
            close(sv[0]);
            for (int p = 0; p < c; p++) close(lsp->client_fds[p]);
            channel_t ch;
            cs_channel(&ch, balances[c]);
            int ok = client_do_close_ceremony(sv[1], ctx, &kps[c + 1],
                                               &pks[c + 1], &lsp->factory,
                                               CS_N, NULL, 0, &ch, NULL, 0);
            _exit(ok ? 0 : 1);
        }
        close(sv[1]);
        lsp->client_fds[c] = sv[0];
        pids[c] = pid;
    }
    lsp->n_clients = CS_N - 1;

    /* If a client drops out, fail the assertions below rather than die on
       SIGPIPE when the LSP writes to its closed socket. */
    void (*old_sigpipe)(int) = signal(SIGPIPE, SIG_IGN);
    tx_buf_t close_tx;
    tx_buf_init(&close_tx, 512);
    int close_rc = lsp_run_cooperative_close(lsp, &close_tx, outs, n_outs, 0);
    size_t close_len = close_tx.len;
    tx_buf_free(&close_tx);
    lsp_cleanup(lsp);
    free(lsp);
    signal(SIGPIPE, old_sigpipe);

    int clients_ok =
        cs_reap(pids, CS_N - 1, CS_REAP_GRACE_SEC, NULL) == CS_N - 1;
    secp256k1_context_destroy(ctx);

    TEST_ASSERT(close_rc == 1, "honest cooperative close completes");
    TEST_ASSERT(close_len > 0, "signed close transaction produced");
    TEST_ASSERT(clients_ok, "every client completed the ceremony");
    return 1;
}

/* Client callback that does nothing, so the client goes straight from an
   open channel to the cooperative close ceremony. */
static int cs_idle_cb(int fd, channel_t *ch, uint32_t my_index,
                      secp256k1_context *ctx, const secp256k1_keypair *kp,
                      factory_t *f, size_t n, void *ud) {
    (void)fd; (void)ch; (void)my_index; (void)ctx; (void)kp; (void)f; (void)n;
    (void)ud;
    return 1;
}

/* Open the LSP's listening socket on a port the kernel picks and report the
   port.  Done before any client is forked: a client that connects before the
   LSP reaches accept() then simply waits in the backlog, instead of being
   refused because nobody listens yet.  accept() gets a timeout so a client
   that never arrives is an error, not a wait without end. */
static int cs_lsp_listen(lsp_t *lsp, int *port_out) {
    int fd = wire_listen("127.0.0.1", 0);
    if (fd < 0) return 0;
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    if (getsockname(fd, (struct sockaddr *)&addr, &len) != 0 ||
        ntohs(addr.sin_port) == 0) {
        close(fd);
        return 0;
    }
    lsp->listen_fd = fd;
    lsp->port = (int)ntohs(addr.sin_port);
    lsp->accept_timeout_sec = 30;
    *port_out = lsp->port;
    return 1;
}

/* Fork the four clients; each runs client_run_with_channels against the
   LSP's port and exits 0 if it finished the close.  The LSP must already be
   listening.  Returns 0 if a fork fails; clients started before that are
   killed and reaped. */
static int cs_fork_channel_clients(const lsp_t *lsp, int port,
                                   pid_t child[CS_N - 1]) {
    fflush(stdout);
    fflush(stderr);
    for (int c = 0; c < CS_N - 1; c++) {
        pid_t pid = fork();
        if (pid < 0) {
            cs_reap(child, c, 0, NULL);
            return 0;
        }
        if (pid == 0) {
            close(lsp->listen_fd);
            secp256k1_context *cc = cs_ctx();
            secp256k1_keypair ck;
            if (!secp256k1_keypair_create(cc, &ck, cs_seckeys[c + 1])) _exit(2);
            int ok = client_run_with_channels(cc, &ck, "127.0.0.1", port,
                                               cs_idle_cb, NULL, NULL, NULL);
            secp256k1_context_destroy(cc);
            _exit(ok ? 0 : 1);
        }
        child[c] = pid;
    }
    return 1;
}

/* Run an LSP and four clients over loopback TCP, on a made-up funding
   outpoint: factory creation, channel open, then one close proposal.  The
   clients run client_run_with_channels, so the channel each of them opened
   is what its close check sees.  With honest != 0 the LSP proposes every
   party's balance at its own script, otherwise one output paying everything
   to the LSP.  Reports the LSP's close result and how many clients finished
   the ceremony.  Returns 1 if factory and channels were set up. */
static int cs_run_inprocess_close(int honest, int *close_rc_out,
                                  int *n_clients_done_out,
                                  int *balances_ok_out) {
    *close_rc_out = -1;
    *n_clients_done_out = 0;
    *balances_ok_out = 0;

    secp256k1_context *ctx = cs_ctx();
    secp256k1_keypair kps[CS_N];
    secp256k1_pubkey pks[CS_N];
    unsigned char fund_spk[34], fund_txid[32];
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    int port = 0;
    if (!lsp || !cs_keys(ctx, kps, pks) ||
        !cs_funding_spk(ctx, pks, fund_spk, NULL) ||
        !lsp_init(lsp, ctx, &kps[0], 0, CS_N - 1)) {
        free(lsp);
        secp256k1_context_destroy(ctx);
        return 0;
    }
    memset(fund_txid, 0xAA, 32);
    factory_alloc_default_arrays(&lsp->factory);

    /* A client that refuses hangs up; nobody may die of SIGPIPE.  Set
       before forking so the clients inherit it. */
    void (*old_sigpipe)(int) = signal(SIGPIPE, SIG_IGN);

    pid_t child[CS_N - 1];
    int setup_ok = cs_lsp_listen(lsp, &port);
    int forked = setup_ok && cs_fork_channel_clients(lsp, port, child);
    if (!forked) setup_ok = 0;

    if (setup_ok && !lsp_accept_clients(lsp)) setup_ok = 0;
    if (setup_ok && !lsp_run_factory_creation(lsp, fund_txid, 0, CS_FUNDING,
                                               fund_spk, 34, 10, 4, 0))
        setup_ok = 0;

    lsp_channel_mgr_t ch_mgr;
    memset(&ch_mgr, 0, sizeof(ch_mgr));
    if (setup_ok && !lsp_channels_init(&ch_mgr, ctx, &lsp->factory,
                                        cs_seckeys[0], CS_N - 1))
        setup_ok = 0;
    if (setup_ok && !lsp_channels_exchange_basepoints(&ch_mgr, lsp)) setup_ok = 0;
    if (setup_ok && !lsp_channels_send_ready(&ch_mgr, lsp)) setup_ok = 0;

    *balances_ok_out = setup_ok;
    for (size_t c = 0; setup_ok && c < ch_mgr.n_channels; c++)
        if (ch_mgr.entries[c].channel.remote_amount < CHANNEL_DUST_LIMIT_SATS)
            *balances_ok_out = 0;

    if (setup_ok) {
        tx_output_t outs[CS_N];
        size_t n_outs;
        if (honest) {
            n_outs = lsp_channels_build_close_outputs(&ch_mgr, &lsp->factory,
                                                       outs, 500, NULL, 0);
        } else {
            unsigned char lsp_spk[34];
            client_close_script(ctx, &pks[0], lsp_spk);
            cs_output(&outs[0], CS_FUNDING - 1000, lsp_spk);
            n_outs = 1;
        }
        tx_buf_t close_tx;
        tx_buf_init(&close_tx, 512);
        if (n_outs > 0)
            *close_rc_out = lsp_run_cooperative_close(lsp, &close_tx, outs,
                                                       n_outs, 0);
        tx_buf_free(&close_tx);
    }

    /* Hanging up ends whatever a client is still waiting for; one that does
       not leave within the grace period is killed.  Every path that forked
       comes through here. */
    lsp_channels_cleanup(&ch_mgr);
    lsp_cleanup(lsp);
    free(lsp);
    if (forked)
        *n_clients_done_out = cs_reap(child, CS_N - 1,
                                       setup_ok ? CS_REAP_GRACE_SEC : 0, NULL);
    signal(SIGPIPE, old_sigpipe);
    secp256k1_context_destroy(ctx);
    return setup_ok;
}

/* client_run_with_channels hands the channel it opened to the close
   ceremony.  Clients that went through the real factory creation and channel
   open complete a close that pays them, and all refuse one whose single
   output pays the LSP; without the channel they would sign either. */
static int test_client_run_with_channels_checks_close_body(void) {
    int close_rc = -1, n_done = -1, balances_ok = 0;

    TEST_ASSERT(cs_run_inprocess_close(1, &close_rc, &n_done, &balances_ok),
                "factory and channels set up (honest close)");
    TEST_ASSERT(balances_ok, "every client holds a non-dust balance");
    TEST_ASSERT(close_rc == 1, "close paying every client completes");
    TEST_ASSERT(n_done == CS_N - 1, "every client completed the honest close");

    TEST_ASSERT(cs_run_inprocess_close(0, &close_rc, &n_done, &balances_ok),
                "factory and channels set up (close paying only the LSP)");
    TEST_ASSERT(balances_ok, "every client holds a non-dust balance");
    TEST_ASSERT(close_rc == 0, "close paying only the LSP does not complete");
    TEST_ASSERT(n_done == 0, "no client completed the dishonest close");
    return 1;
}

/* End to end on regtest: real clients with open channels are offered a close
   whose single output pays the LSP.  No client signs, the ceremony fails, and
   the factory funding output stays unspent. */
static int test_regtest_coop_close_refuses_lsp_payee_body(void) {
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: regtest not available\n");
        return 0;
    }
    if (!regtest_create_wallet(&rt, "test_client_signing")) {
        char *lr = regtest_exec(&rt, "loadwallet", "\"test_client_signing\"");
        if (lr) free(lr);
        strncpy(rt.wallet, "test_client_signing", sizeof(rt.wallet) - 1);
    }

    secp256k1_context *ctx = cs_ctx();
    secp256k1_keypair kps[CS_N];
    secp256k1_pubkey pks[CS_N];
    TEST_ASSERT(cs_keys(ctx, kps, pks), "keys");

    unsigned char fund_spk[34], tweaked_ser[32];
    TEST_ASSERT(cs_funding_spk(ctx, pks, fund_spk, tweaked_ser), "funding spk");

    char mine_addr[128], fund_addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)),
                "mine address");
    TEST_ASSERT(regtest_derive_p2tr_address(&rt, tweaked_ser, fund_addr,
                                             sizeof(fund_addr)),
                "funding address");
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    char fund_txid_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, fund_addr, 0.002, fund_txid_hex),
                "fund factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    unsigned char fund_txid[32];
    hex_decode(fund_txid_hex, fund_txid, 32);
    reverse_bytes(fund_txid, 32);
    uint64_t fund_amount = 0;
    uint32_t fund_vout = 0;
    int found_vout = 0;
    for (uint32_t v = 0; v < 2 && !found_vout; v++) {
        unsigned char spk[256];
        size_t spk_len = 0;
        uint64_t amt = 0;
        if (regtest_get_tx_output(&rt, fund_txid_hex, v, &amt, spk, &spk_len) &&
            spk_len == 34 && memcmp(spk, fund_spk, 34) == 0) {
            fund_vout = v;
            fund_amount = amt;
            found_vout = 1;
        }
    }
    TEST_ASSERT(found_vout && fund_amount > 0, "funding output located");

    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    TEST_ASSERT(lsp != NULL, "alloc");
    TEST_ASSERT(lsp_init(lsp, ctx, &kps[0], 0, CS_N - 1), "lsp init");
    factory_alloc_default_arrays(&lsp->factory);

    /* The clients hang up as soon as they refuse; the LSP's abort notice to
       them must not take anyone down with SIGPIPE. */
    void (*old_sigpipe)(int) = signal(SIGPIPE, SIG_IGN);

    int port = 0;
    pid_t child[CS_N - 1];
    int setup_ok = cs_lsp_listen(lsp, &port);
    int forked = setup_ok && cs_fork_channel_clients(lsp, port, child);
    if (!forked) setup_ok = 0;
    if (setup_ok && !lsp_accept_clients(lsp)) setup_ok = 0;
    if (setup_ok && !lsp_run_factory_creation(lsp, fund_txid, fund_vout,
                                               fund_amount, fund_spk, 34,
                                               10, 4, 0))
        setup_ok = 0;

    lsp_channel_mgr_t ch_mgr;
    memset(&ch_mgr, 0, sizeof(ch_mgr));
    if (setup_ok && !lsp_channels_init(&ch_mgr, ctx, &lsp->factory,
                                        cs_seckeys[0], CS_N - 1))
        setup_ok = 0;
    if (setup_ok && !lsp_channels_exchange_basepoints(&ch_mgr, lsp)) setup_ok = 0;
    if (setup_ok && !lsp_channels_send_ready(&ch_mgr, lsp)) setup_ok = 0;

    /* Every client now holds a channel with a non-dust balance. */
    int balances_ok = setup_ok;
    for (size_t c = 0; balances_ok && c < ch_mgr.n_channels; c++)
        if (ch_mgr.entries[c].channel.remote_amount < CHANNEL_DUST_LIMIT_SATS)
            balances_ok = 0;

    int close_rc = -1;
    if (setup_ok) {
        unsigned char lsp_spk[34];
        client_close_script(ctx, &pks[0], lsp_spk);
        tx_output_t all_to_lsp;
        cs_output(&all_to_lsp, fund_amount - 1000, lsp_spk);

        tx_buf_t close_tx;
        tx_buf_init(&close_tx, 512);
        close_rc = lsp_run_cooperative_close(lsp, &close_tx, &all_to_lsp, 1, 0);
        tx_buf_free(&close_tx);
    }

    lsp_channels_cleanup(&ch_mgr);
    lsp_cleanup(lsp);
    free(lsp);
    signal(SIGPIPE, old_sigpipe);

    int n_signed = forked
        ? cs_reap(child, CS_N - 1, setup_ok ? CS_REAP_GRACE_SEC : 0, NULL)
        : 0;

    regtest_mine_blocks(&rt, 1, mine_addr);
    int unspent = regtest_outpoint_unspent(&rt, fund_txid_hex, fund_vout);
    secp256k1_context_destroy(ctx);

    TEST_ASSERT(setup_ok, "factory and channels set up");
    TEST_ASSERT(balances_ok, "every client holds a non-dust balance");
    TEST_ASSERT(close_rc == 0, "close paying only the LSP does not complete");
    TEST_ASSERT(n_signed == 0, "no client completed the dishonest close");
    TEST_ASSERT(unspent == 1, "factory funding output is still unspent");
    return 1;
}

/* ---- Leaf reallocation ---- */

/* Reallocatable outputs of a leaf: everything but a trailing P2A anchor. */
static size_t cs_leaf_n_realloc(const factory_node_t *leaf) {
    size_t n = leaf->n_outputs;
    if (n >= 1 && leaf->outputs[n - 1].script_pubkey_len == P2A_SPK_LEN &&
        memcmp(leaf->outputs[n - 1].script_pubkey, P2A_SPK, P2A_SPK_LEN) == 0)
        n--;
    return n;
}

static size_t cs_leaf_amounts(const factory_node_t *leaf, uint64_t *amounts) {
    size_t n = cs_leaf_n_realloc(leaf);
    for (size_t i = 0; i < n; i++) amounts[i] = leaf->outputs[i].amount_sats;
    return n;
}

/* The amount rule: a client's own channel output, found from its own tree,
   may grow but never shrink, and the leaf total is conserved.  Passing it is
   not enough to sign; see the handler tests below. */
int test_client_leaf_realloc_acceptable(void) {
    secp256k1_context *ctx = cs_ctx();
    secp256k1_keypair kps[CS_N];
    secp256k1_pubkey pks[CS_N];
    TEST_ASSERT(cs_keys(ctx, kps, pks), "keys");

    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f != NULL, "alloc");
    TEST_ASSERT(cs_build_factory(f, ctx, kps, pks), "build factory");

    /* Leaf 0 holds the channels of clients 1 and 2 plus the LSP's L-stock. */
    const factory_node_t *leaf = &f->nodes[f->leaf_node_indices[0]];
    uint64_t cur[FACTORY_MAX_OUTPUTS], amts[FACTORY_MAX_OUTPUTS];
    size_t n = cs_leaf_amounts(leaf, cur);
    TEST_ASSERT(n == 3, "two channel outputs and the L-stock");
    size_t node; uint32_t vout;
    TEST_ASSERT(factory_client_to_leaf(f, 0, &node, &vout) &&
                node == f->leaf_node_indices[0] && vout == 0,
                "client 1 owns output 0");
    TEST_ASSERT(factory_client_to_leaf(f, 1, &node, &vout) &&
                node == f->leaf_node_indices[0] && vout == 1,
                "client 2 owns output 1");
    TEST_ASSERT(cur[0] > 2 * CHANNEL_DUST_LIMIT_SATS &&
                cur[2] > 2 * CHANNEL_DUST_LIMIT_SATS, "amounts above dust");

    /* Client 1's output cut to dust, the difference moved to the L-stock. */
    memcpy(amts, cur, sizeof(cur));
    amts[2] += amts[0] - CHANNEL_DUST_LIMIT_SATS;
    amts[0] = CHANNEL_DUST_LIMIT_SATS;
    TEST_ASSERT(!client_leaf_realloc_acceptable(f, 1, 0, amts, n),
                "client refuses its output being cut to dust");
    TEST_ASSERT(client_leaf_realloc_acceptable(f, 2, 0, amts, n),
                "the other client's own output is untouched");

    /* One sat is enough. */
    memcpy(amts, cur, sizeof(cur));
    amts[0] -= 1; amts[2] += 1;
    TEST_ASSERT(!client_leaf_realloc_acceptable(f, 1, 0, amts, n),
                "client refuses a one-sat reduction");

    /* Taking from one client to give to the other. */
    memcpy(amts, cur, sizeof(cur));
    amts[1] -= 1000; amts[0] += 1000;
    TEST_ASSERT(!client_leaf_realloc_acceptable(f, 2, 0, amts, n),
                "client refuses funding another channel from its output");

    /* Honest: L-stock moves into client 1's channel. */
    memcpy(amts, cur, sizeof(cur));
    amts[2] -= 1000; amts[0] += 1000;
    TEST_ASSERT(client_leaf_realloc_acceptable(f, 1, 0, amts, n),
                "stock moving to own channel passes the rule");
    TEST_ASSERT(client_leaf_realloc_acceptable(f, 2, 0, amts, n),
                "stock moving to the neighbour's channel passes the rule");
    TEST_ASSERT(client_leaf_realloc_acceptable(f, 1, 0, cur, n),
                "unchanged amounts pass the rule");

    /* Amounts must conserve the leaf total and stay above dust. */
    memcpy(amts, cur, sizeof(cur));
    amts[0] += 1000;
    TEST_ASSERT(!client_leaf_realloc_acceptable(f, 1, 0, amts, n),
                "amounts that do not conserve the total are refused");
    memcpy(amts, cur, sizeof(cur));
    amts[0] += amts[2] - 1; amts[2] = 1;
    TEST_ASSERT(!client_leaf_realloc_acceptable(f, 1, 0, amts, n),
                "a dust output is refused");
    TEST_ASSERT(!client_leaf_realloc_acceptable(f, 1, 0, cur, n - 1),
                "a short amount list is refused");
    TEST_ASSERT(!client_leaf_realloc_acceptable(f, 1, 0, cur, n + 1),
                "a long amount list is refused");

    /* A leaf the client does not sign, or that does not exist. */
    TEST_ASSERT(!client_leaf_realloc_acceptable(f, 3, 0, cur, n),
                "a client of another leaf refuses");
    TEST_ASSERT(!client_leaf_realloc_acceptable(f, 1, 1, cur, n),
                "client refuses a leaf that is not its own");
    TEST_ASSERT(!client_leaf_realloc_acceptable(f, 1, -1, cur, n) &&
                !client_leaf_realloc_acceptable(f, 1, f->n_leaf_nodes, cur, n),
                "out-of-range leaf is refused");
    TEST_ASSERT(!client_leaf_realloc_acceptable(f, 0, 0, cur, n),
                "participant 0 is the LSP, not a client");

    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* The conservation invariant counts, for every HTLC and PTLC in flight, both
   its amount and the commitment fee taken from the funder when it was
   added.  The HTLC and the PTLC here are added with the channel's own
   functions, so the fees are the ones the channel really deducts. */
int test_conservation_counts_ptlc_fee(void) {
    secp256k1_context *ctx = cs_ctx();
    secp256k1_keypair kps[CS_N];
    secp256k1_pubkey pks[CS_N];
    TEST_ASSERT(cs_keys(ctx, kps, pks), "keys");
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f != NULL, "alloc");
    TEST_ASSERT(cs_build_factory(f, ctx, kps, pks), "build factory");

    channel_t ch;
    TEST_ASSERT(cs_client_channel(&ch, ctx, f, kps, pks), "open channel");
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.entries = calloc(1, sizeof(lsp_channel_entry_t));
    TEST_ASSERT(mgr.entries != NULL, "alloc");
    mgr.n_channels = 1;
    int pass = 1;
#define CS_CHECK(cond, msg) do { \
        if (pass && !(cond)) { \
            printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
            pass = 0; \
        } \
    } while (0)
/* The LSP-side check reads the same channel state. */
#define CS_LSP_VIEW_OK() \
    (mgr.entries[0].channel = ch, lsp_channels_check_conservation(&mgr) == 1)

    CS_CHECK(client_channel_balanced(&ch), "fresh channel adds up");
    CS_CHECK(CS_LSP_VIEW_OK(), "fresh channel adds up (LSP check)");

    unsigned char payment_hash[32];
    memset(payment_hash, 0x5A, 32);
    uint64_t htlc_id = 0, ptlc_id = 0;
    CS_CHECK(channel_add_htlc(&ch, HTLC_OFFERED, 20000, payment_hash, 500,
                               &htlc_id), "offer HTLC");
    CS_CHECK(client_channel_balanced(&ch), "adds up with an HTLC in flight");
    CS_CHECK(CS_LSP_VIEW_OK(), "adds up with an HTLC in flight (LSP check)");

    uint64_t before = ch.local_amount + ch.remote_amount;
    CS_CHECK(channel_add_ptlc(&ch, PTLC_OFFERED, 10000, &pks[2], 500,
                               &ptlc_id), "offer PTLC");
    CS_CHECK(ch.n_ptlcs == 1 && ch.ptlcs[0].fee_at_add > 0,
             "the PTLC carries a commitment fee");
    CS_CHECK(before - (ch.local_amount + ch.remote_amount) ==
             10000 + ch.ptlcs[0].fee_at_add,
             "amount and fee both left the balances");
    CS_CHECK(client_channel_balanced(&ch), "adds up with a PTLC in flight");
    CS_CHECK(CS_LSP_VIEW_OK(), "adds up with a PTLC in flight (LSP check)");

    /* A sat missing is still noticed. */
    ch.remote_amount -= 1;
    CS_CHECK(!client_channel_balanced(&ch), "one sat short does not add up");
    CS_CHECK(!CS_LSP_VIEW_OK(), "one sat short does not add up (LSP check)");
    ch.remote_amount += 1;
#undef CS_LSP_VIEW_OK
#undef CS_CHECK

    free(mgr.entries);
    channel_cleanup(&ch);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return pass;
}

/* Build a REALLOC_PROPOSE carrying a well-formed LSP nonce. */
static cJSON *cs_realloc_propose(secp256k1_context *ctx,
                                 const secp256k1_keypair *lsp_kp,
                                 const secp256k1_pubkey *lsp_pk,
                                 factory_t *f, int leaf_side,
                                 const uint64_t *amounts, size_t n) {
    secp256k1_musig_secnonce secnonce;
    secp256k1_musig_pubnonce pubnonce;
    unsigned char sk[32], ser[66];
    if (!secp256k1_keypair_sec(ctx, sk, lsp_kp)) return NULL;
    if (!musig_generate_nonce(ctx, &secnonce, &pubnonce, sk, lsp_pk,
            &f->nodes[f->leaf_node_indices[leaf_side]].keyagg.cache))
        return NULL;
    musig_pubnonce_serialize(ctx, ser, &pubnonce);
    return wire_build_leaf_realloc_propose(leaf_side, amounts, n, ser, NULL);
}

/* What a client must still hold after a reallocation proposal: the same
   signed leaf at the same state. */
typedef struct {
    unsigned char txid[32];
    uint32_t state;
    uint32_t nsequence;
    uint64_t amounts[FACTORY_MAX_OUTPUTS];
    size_t n_amounts;
} cs_leaf_snapshot_t;

static void cs_leaf_snapshot(const factory_t *f, int leaf_side,
                             cs_leaf_snapshot_t *snap) {
    const factory_node_t *leaf = &f->nodes[f->leaf_node_indices[leaf_side]];
    memcpy(snap->txid, leaf->txid, 32);
    snap->state = f->leaf_layers[leaf_side].current_state;
    snap->nsequence = leaf->nsequence;
    snap->n_amounts = cs_leaf_amounts(leaf, snap->amounts);
}

/* 1 if the leaf is still signed and identical to the snapshot. */
static int cs_leaf_intact(const factory_t *f, int leaf_side,
                          const cs_leaf_snapshot_t *snap) {
    const factory_node_t *leaf = &f->nodes[f->leaf_node_indices[leaf_side]];
    uint64_t now[FACTORY_MAX_OUTPUTS];
    if (cs_leaf_amounts(leaf, now) != snap->n_amounts) return 0;
    if (memcmp(now, snap->amounts, snap->n_amounts * sizeof(uint64_t)) != 0)
        return 0;
    if (memcmp(leaf->txid, snap->txid, 32) != 0) return 0;
    if (f->leaf_layers[leaf_side].current_state != snap->state) return 0;
    if (leaf->nsequence != snap->nsequence) return 0;
    return leaf->is_signed && leaf->signed_tx.len > 0;
}

/* The handler refuses every proposal, whatever the amounts: it reveals no
   nonce and its signed leaf is left exactly as it was. */
static int test_client_leaf_realloc_handler_refuses_all_body(void) {
    secp256k1_context *ctx = cs_ctx();
    secp256k1_keypair kps[CS_N];
    secp256k1_pubkey pks[CS_N];
    TEST_ASSERT(cs_keys(ctx, kps, pks), "keys");

    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f != NULL, "alloc");
    TEST_ASSERT(cs_build_factory(f, ctx, kps, pks), "build factory");
    TEST_ASSERT(factory_sign_all(f), "sign tree");

    cs_leaf_snapshot_t snap;
    cs_leaf_snapshot(f, 0, &snap);
    size_t n = snap.n_amounts;
    TEST_ASSERT(n == 3, "two channel outputs and the L-stock");
    TEST_ASSERT(cs_leaf_intact(f, 0, &snap), "leaf signed before the proposal");

    /* 0: client 1's output cut to dust in favour of the L-stock.
       1: L-stock moved into client 1's output.
       2: amounts unchanged. */
    for (int variant = 0; variant < 3; variant++) {
        uint64_t amts[FACTORY_MAX_OUTPUTS];
        memcpy(amts, snap.amounts, sizeof(amts));
        if (variant == 0) {
            amts[2] += amts[0] - CHANNEL_DUST_LIMIT_SATS;
            amts[0] = CHANNEL_DUST_LIMIT_SATS;
        } else if (variant == 1) {
            amts[0] += 5000;
            amts[2] -= 5000;
        }
        if (variant != 0)
            TEST_ASSERT(client_leaf_realloc_acceptable(f, 1, 0, amts, n),
                        "amounts pass the amount rule");

        int sv[2];
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
        wire_msg_t propose;
        memset(&propose, 0, sizeof(propose));
        propose.msg_type = MSG_LEAF_REALLOC_PROPOSE;
        propose.json = cs_realloc_propose(ctx, &kps[0], &pks[0], f, 0, amts, n);
        TEST_ASSERT(propose.json != NULL, "build proposal");
        /* Nothing follows the proposal: a client that went on to sign would
           block on the next ceremony message, so end the stream. */
        shutdown(sv[0], SHUT_WR);

        int rc = client_handle_leaf_realloc(sv[1], ctx, &kps[1], f, 1, &propose);
        cJSON_Delete(propose.json);
        close(sv[1]);

        wire_msg_t reply;
        memset(&reply, 0, sizeof(reply));
        uint8_t sent = 0;
        if (wire_recv(sv[0], &reply)) {
            sent = reply.msg_type;
            if (reply.json) cJSON_Delete(reply.json);
        }
        close(sv[0]);

        TEST_ASSERT(sent != MSG_LEAF_REALLOC_NONCE, "client reveals no nonce");
        TEST_ASSERT(rc == 0, "client refuses the reallocation");
        TEST_ASSERT(sent == MSG_ERROR, "client reports the refusal");
        TEST_ASSERT(cs_leaf_intact(f, 0, &snap),
                    "client still holds its signed leaf, unchanged");
    }

    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Exit codes of a client child in cs_run_realloc_ceremony. */
#define CS_REALLOC_REFUSED_INTACT   0  /* refused, signed leaf unchanged */
#define CS_REALLOC_SETUP_FAILED     2
#define CS_REALLOC_ACCEPTED_SIGNED  3  /* took part, holds a signed leaf */
#define CS_REALLOC_ACCEPTED_NO_SIG  4  /* took part, left with no signed leaf */
#define CS_REALLOC_REFUSED_CHANGED  5  /* refused, but its leaf was modified */

/* Drive lsp_realloc_leaf on leaf 0 against the real client handler in both
   clients of that leaf.  Reports the LSP's return value, each client's exit
   code and whether the LSP came out on the same signed leaf it went in
   with, which is the leaf the clients still hold. */
static int cs_run_realloc_ceremony(const int64_t *deltas, int *lsp_rc_out,
                                   int client_code_out[2],
                                   int *lsp_leaf_intact_out) {
    secp256k1_context *ctx = cs_ctx();
    secp256k1_keypair kps[CS_N];
    secp256k1_pubkey pks[CS_N];
    if (!cs_keys(ctx, kps, pks)) return 0;

    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    if (!lsp) return 0;
    if (!lsp_init(lsp, ctx, &kps[0], 0, CS_N - 1)) return 0;
    factory_t *f = &lsp->factory;
    if (!cs_build_factory(f, ctx, kps, pks)) return 0;
    if (!factory_sign_all(f)) return 0;

    cs_leaf_snapshot_t snap;
    cs_leaf_snapshot(f, 0, &snap);
    size_t n = snap.n_amounts;
    if (n != 3) return 0;
    uint64_t amts[FACTORY_MAX_OUTPUTS];
    for (size_t i = 0; i < n; i++)
        amts[i] = (uint64_t)((int64_t)snap.amounts[i] + deltas[i]);

    /* One connection per client; only the two clients of leaf 0 are asked. */
    int peer_fd[CS_N - 1];
    for (int c = 0; c < CS_N - 1; c++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 0;
        lsp->client_fds[c] = sv[0];
        peer_fd[c] = sv[1];
    }
    lsp->n_clients = CS_N - 1;

    /* The LSP gives up at the first refusal and hangs up while the other
       client may still be writing its own; neither side may die of SIGPIPE
       (the client tool ignores it too).  Set before forking so the clients
       inherit it. */
    void (*old_sigpipe)(int) = signal(SIGPIPE, SIG_IGN);

    pid_t pids[2];
    fflush(stdout);
    for (int c = 0; c < 2; c++) {
        pid_t pid = fork();
        if (pid < 0) return 0;
        if (pid == 0) {
            for (int p = 0; p < CS_N - 1; p++) {
                close(lsp->client_fds[p]);
                if (p != c) close(peer_fd[p]);
            }
            uint32_t my_index = (uint32_t)(c + 1);
            wire_msg_t msg;
            if (!wire_recv(peer_fd[c], &msg) ||
                msg.msg_type != MSG_LEAF_REALLOC_PROPOSE)
                _exit(CS_REALLOC_SETUP_FAILED);
            /* The child works on its own copy of the tree. */
            int ok = client_handle_leaf_realloc(peer_fd[c], ctx, &kps[my_index],
                                                 f, my_index, &msg);
            const factory_node_t *my_leaf = &f->nodes[f->leaf_node_indices[0]];
            if (ok)
                _exit(my_leaf->is_signed ? CS_REALLOC_ACCEPTED_SIGNED
                                         : CS_REALLOC_ACCEPTED_NO_SIG);
            _exit(cs_leaf_intact(f, 0, &snap) ? CS_REALLOC_REFUSED_INTACT
                                              : CS_REALLOC_REFUSED_CHANGED);
        }
        pids[c] = pid;
    }
    for (int c = 0; c < 2; c++) close(peer_fd[c]);

    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.bridge_fd = -1;
    *lsp_rc_out = lsp_realloc_leaf(&mgr, lsp, 0, amts, n);

    *lsp_leaf_intact_out = cs_leaf_intact(f, 0, &snap);

    for (int c = 2; c < CS_N - 1; c++) close(peer_fd[c]);
    lsp_cleanup(lsp);
    free(lsp);
    signal(SIGPIPE, old_sigpipe);

    cs_reap(pids, 2, CS_REAP_GRACE_SEC, client_code_out);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Full ceremony, L-stock moved into a client's channel output: the amounts
   satisfy the amount rule, and the clients still refuse.  The LSP's ceremony
   fails and puts its own leaf back as it was. */
static int test_client_leaf_realloc_ceremony_refused_body(void) {
    const int64_t deltas[3] = { 5000, 0, -5000 };
    int lsp_rc = -1, codes[2] = { -1, -1 }, lsp_leaf_intact = -1;
    TEST_ASSERT(cs_run_realloc_ceremony(deltas, &lsp_rc, codes,
                                         &lsp_leaf_intact),
                "run ceremony");
    if (codes[0] != CS_REALLOC_REFUSED_INTACT ||
        codes[1] != CS_REALLOC_REFUSED_INTACT)
        printf("  client exit codes: %d %d\n", codes[0], codes[1]);
    TEST_ASSERT(codes[0] == CS_REALLOC_REFUSED_INTACT &&
                codes[1] == CS_REALLOC_REFUSED_INTACT,
                "both clients refuse and keep their signed leaf");
    TEST_ASSERT(lsp_rc == 0, "the LSP's reallocation does not complete");
    TEST_ASSERT(lsp_leaf_intact == 1,
                "the LSP is back on the signed leaf its clients hold");
    return 1;
}

/* A reallocation that changes no amount still replaces the leaf transaction.
   A client that co-signed it would be left without a signed leaf while the
   LSP held one that supersedes the client's commitments, so it is refused
   like any other. */
static int test_client_leaf_realloc_identity_refused_body(void) {
    const int64_t deltas[3] = { 0, 0, 0 };
    int lsp_rc = -1, codes[2] = { -1, -1 }, lsp_leaf_intact = -1;
    TEST_ASSERT(cs_run_realloc_ceremony(deltas, &lsp_rc, codes,
                                         &lsp_leaf_intact),
                "run ceremony");
    if (codes[0] != CS_REALLOC_REFUSED_INTACT ||
        codes[1] != CS_REALLOC_REFUSED_INTACT)
        printf("  client exit codes: %d %d, LSP rc %d, LSP leaf intact: %d\n",
               codes[0], codes[1], lsp_rc, lsp_leaf_intact);
    TEST_ASSERT(codes[0] == CS_REALLOC_REFUSED_INTACT &&
                codes[1] == CS_REALLOC_REFUSED_INTACT,
                "both clients refuse and keep their signed leaf");
    TEST_ASSERT(lsp_rc == 0, "the LSP's reallocation does not complete");
    TEST_ASSERT(lsp_leaf_intact == 1,
                "the LSP is back on the signed leaf its clients hold");
    return 1;
}

/* Selling L-stock to a client needs a leaf reallocation, so the LSP refuses
   the request before anything happens: no message to any client, and its
   leaf exactly as it was. */
static int test_lsp_buy_liquidity_refused_body(void) {
    secp256k1_context *ctx = cs_ctx();
    secp256k1_keypair kps[CS_N];
    secp256k1_pubkey pks[CS_N];
    TEST_ASSERT(cs_keys(ctx, kps, pks), "keys");

    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    TEST_ASSERT(lsp != NULL, "alloc");
    TEST_ASSERT(lsp_init(lsp, ctx, &kps[0], 0, CS_N - 1), "lsp init");
    factory_t *f = &lsp->factory;
    TEST_ASSERT(cs_build_factory(f, ctx, kps, pks), "build factory");
    TEST_ASSERT(factory_sign_all(f), "sign tree");

    int peer_fd[CS_N - 1];
    for (int c = 0; c < CS_N - 1; c++) {
        int sv[2];
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
        lsp->client_fds[c] = sv[0];
        peer_fd[c] = sv[1];
    }
    lsp->n_clients = CS_N - 1;

    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.bridge_fd = -1;
    mgr.n_channels = CS_N - 1;

    cs_leaf_snapshot_t snap;
    cs_leaf_snapshot(f, 0, &snap);
    TEST_ASSERT(cs_leaf_intact(f, 0, &snap), "leaf signed before the request");

    int rc = lsp_channels_buy_liquidity(&mgr, lsp, 0, 1000);
    int intact = cs_leaf_intact(f, 0, &snap);

    /* Nothing may have been written to any client. */
    int silent = 1;
    for (int c = 0; c < CS_N - 1; c++) {
        unsigned char byte;
        ssize_t got = recv(peer_fd[c], &byte, 1, MSG_DONTWAIT);
        if (got > 0) silent = 0;
        close(peer_fd[c]);
    }
    lsp_cleanup(lsp);
    free(lsp);
    secp256k1_context_destroy(ctx);

    TEST_ASSERT(rc == 0, "buy_liquidity is refused");
    TEST_ASSERT(intact, "the LSP's leaf is untouched");
    TEST_ASSERT(silent, "no client was contacted");
    return 1;
}

/* ---- Entry points of the tests that run under a deadline ---- */

CS_DEADLINE_ENTRY(test_client_close_refuses_unpaid_proposal, CS_UNIT_DEADLINE_SEC)
CS_DEADLINE_ENTRY(test_client_close_without_channel, CS_UNIT_DEADLINE_SEC)
CS_DEADLINE_ENTRY(test_client_close_after_reconnect_with_htlc_in_flight, CS_UNIT_DEADLINE_SEC)
CS_DEADLINE_ENTRY(test_client_close_locktime_bound, CS_UNIT_DEADLINE_SEC)
CS_DEADLINE_ENTRY(test_client_close_tip_retry, CS_UNIT_DEADLINE_SEC)
CS_DEADLINE_ENTRY(test_client_close_records_signed_close, CS_UNIT_DEADLINE_SEC)
CS_DEADLINE_ENTRY(test_client_close_repropose_changed_outputs, CS_UNIT_DEADLINE_SEC)
CS_DEADLINE_ENTRY(test_client_close_record_unreadable, CS_UNIT_DEADLINE_SEC)
CS_DEADLINE_ENTRY(test_client_close_record_survives_restart, CS_UNIT_DEADLINE_SEC)
CS_DEADLINE_ENTRY(test_client_close_honest_ceremony, CS_UNIT_DEADLINE_SEC)
CS_DEADLINE_ENTRY(test_client_run_with_channels_checks_close, CS_UNIT_DEADLINE_SEC)
CS_DEADLINE_ENTRY(test_regtest_coop_close_refuses_lsp_payee, CS_REGTEST_DEADLINE_SEC)
CS_DEADLINE_ENTRY(test_client_leaf_realloc_handler_refuses_all, CS_UNIT_DEADLINE_SEC)
CS_DEADLINE_ENTRY(test_client_leaf_realloc_ceremony_refused, CS_UNIT_DEADLINE_SEC)
CS_DEADLINE_ENTRY(test_client_leaf_realloc_identity_refused, CS_UNIT_DEADLINE_SEC)
CS_DEADLINE_ENTRY(test_lsp_buy_liquidity_refused, CS_UNIT_DEADLINE_SEC)
