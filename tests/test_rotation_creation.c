/* Regression tests for the rotation crash (factory creation over a factory_t
   whose dynamic arrays were released by factory_free() or never allocated)
   and for the ladder's distribution-TX slot (signed copy only).

   Before the fix, lsp_run_factory_creation_stateless memcpy'd 8 KiB of
   participant profiles out of f->profiles while it was NULL: rotation calls it
   right after factory_free(&lsp->factory), so the LSP SIGSEGV'd after the old
   factory had been closed on-chain and the replacement funded, leaving the
   replacement unsigned.  The creation tests run the REAL ceremony in-process:
   four forked clients over loopback TCP and a placeholder funding outpoint
   (the ceremony itself needs no chain). */
#include "superscalar/factory.h"
#include "superscalar/lsp.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/client.h"
#include "superscalar/ladder.h"
#include "superscalar/musig.h"
#include "superscalar/sha256.h"
#include "superscalar/tx_builder.h"
#include <secp256k1_schnorrsig.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

/* LSP + 4 clients (distinct from the other suites' keys). */
static const unsigned char rc_seckeys[5][32] = {
    { [0 ... 31] = 0x61 },
    { [0 ... 31] = 0x62 },
    { [0 ... 31] = 0x63 },
    { [0 ... 31] = 0x64 },
    { [0 ... 31] = 0x65 },
};

static secp256k1_context *rc_ctx(void) {
    return secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

/* P2TR(MuSig(all 5) + BIP-86 tweak) -- the factory funding SPK. */
static int rc_funding_spk(secp256k1_context *ctx, const secp256k1_keypair *kps,
                          unsigned char *spk34, secp256k1_xonly_pubkey *tweaked_out) {
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++)
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, 5);
    unsigned char internal[32], tweak[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal, &ka.agg_pubkey)) return 0;
    sha256_tagged("TapTweak", internal, 32, tweak);
    musig_keyagg_t kc = ka;
    secp256k1_pubkey tpk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tpk, &kc.cache, tweak)) return 0;
    secp256k1_xonly_pubkey txo;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &txo, NULL, &tpk)) return 0;
    build_p2tr_script_pubkey(spk34, &txo);
    if (tweaked_out) *tweaked_out = txo;
    return 1;
}

/* Participant profiles as tools/superscalar_lsp.c sets them before creation. */
static void rc_set_profiles(factory_t *f, size_t n, uint16_t client_bps) {
    for (size_t i = 0; i < n; i++) {
        f->profiles[i].participant_idx = (uint32_t)i;
        f->profiles[i].contribution_sats = 1000 + i;
        f->profiles[i].profit_share_bps = i == 0 ? (uint16_t)(10000 - 4 * client_bps)
                                                 : client_bps;
        f->profiles[i].uptime_score = 0.5f + 0.01f * (float)i;
        f->profiles[i].timezone_bucket = (uint8_t)(i % 7);
    }
}

static int rc_profiles_match(const factory_t *f, size_t n, uint16_t client_bps) {
    if (!f->profiles) return 0;
    for (size_t i = 0; i < n; i++) {
        const participant_profile_t *p = &f->profiles[i];
        uint16_t want_bps = i == 0 ? (uint16_t)(10000 - 4 * client_bps) : client_bps;
        if (p->participant_idx != i || p->contribution_sats != 1000 + i ||
            p->profit_share_bps != want_bps ||
            p->uptime_score != 0.5f + 0.01f * (float)i ||
            p->timezone_bucket != (uint8_t)(i % 7))
            return 0;
    }
    return 1;
}

#define RC_NEVER_ALLOCATED 0   /* no shape setter ran: every array NULL */
#define RC_AFTER_FREE      1   /* configured, then factory_free'd (old rotation) */
#define RC_PREALLOCATED    2   /* configured, arrays live */
#define RC_REFUSED         3   /* clients refuse the terms: the failed attempt */
#define RC_DIGEST          4   /* dry-run digest == the delivered tree's digest */
#define RC_HOOK_REFUSES    5   /* before_factory_ready refuses: no FACTORY_READY */
#define RC_READY_SEND_FAILS 6  /* hook ran, the first FACTORY_READY send fails */

static int rc_hook_calls;
static unsigned char rc_hook_digest[32];
static int rc_hook_refuse;
static int rc_hook_break_ready;
static int rc_hook(void *lsp, const factory_t *f, void *ctx) {
    (void)ctx;
    rc_hook_calls++;
    if (!lsp_factory_tree_digest(f, rc_hook_digest)) return 0;
    if (rc_hook_break_ready)            /* the first FACTORY_READY send will fail */
        shutdown(((lsp_t *)lsp)->client_fds[0], SHUT_RDWR);
    return !rc_hook_refuse;
}

static int rc_port(int mode) {
    return 21000 + (int)(getpid() % 2000) * 4 + mode;
}

/* Fork 4 clients (each running the stock client ceremony), run
   lsp_run_factory_creation against them, then a cooperative close so the
   clients exit cleanly.  Returns 1 if every assertion for `mode` held. */
static int rc_run_creation(int mode) {
    secp256k1_context *ctx = rc_ctx();
    secp256k1_keypair kps[5];
    for (int i = 0; i < 5; i++)
        TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[i], rc_seckeys[i]), "keypair");
    unsigned char spk[34];
    TEST_ASSERT(rc_funding_spk(ctx, kps, spk, NULL), "funding spk");
    unsigned char fake_txid[32];
    memset(fake_txid, 0xC3, 32);
    const uint64_t amount = 1000000;
    int port = rc_port(mode);

    fflush(stdout);
    fflush(stderr);
    pid_t kids[4];
    for (int c = 0; c < 4; c++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(90);                      /* never outlive a broken parent */
            usleep(100000 * (c + 1));
            secp256k1_context *cctx = rc_ctx();
            secp256k1_keypair ckp;
            if (!secp256k1_keypair_create(cctx, &ckp, rc_seckeys[c + 1])) _exit(2);
            if (mode == RC_REFUSED)
                client_set_min_profit_bps(100);
            int ok = client_run_ceremony(cctx, &ckp, "127.0.0.1", port);
            secp256k1_context_destroy(cctx);
            _exit(ok ? 0 : 1);
        }
        kids[c] = pid;
    }

    /* The daemons ignore SIGPIPE; do the same here, or a write to a client
       that already hung up (the refusing clients) kills the test process. */
    void (*old_pipe)(int) = signal(SIGPIPE, SIG_IGN);
    const char *fail = NULL;
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    if (!lsp || !lsp_init(lsp, ctx, &kps[0], port, 4)) fail = "lsp_init";
    if (!fail && !lsp_accept_clients(lsp)) fail = "accept clients";

    uint8_t arities[2] = { 2, 4 };
    if (!fail) {
        if (mode == RC_NEVER_ALLOCATED) {
            if (lsp->factory.profiles || lsp->factory.nodes || lsp->factory.pubkeys)
                fail = "precondition: arrays never allocated";
        } else {
            factory_set_level_arity(&lsp->factory, arities, 2);
            factory_set_static_near_root(&lsp->factory, 1);
            if (!lsp->factory.profiles) fail = "setters allocated profiles";
            else rc_set_profiles(&lsp->factory, 5, mode == RC_REFUSED ? 0 : 150);
            if (mode == RC_AFTER_FREE) {
                factory_free(&lsp->factory);
                if (lsp->factory.profiles) fail = "precondition: profiles freed";
            }
        }
    }

    unsigned char dry_digest[32], dry_again[32];
    rc_hook_calls = 0;
    rc_hook_refuse = (mode == RC_HOOK_REFUSES);
    rc_hook_break_ready = (mode == RC_READY_SEND_FAILS);
    if (!fail && (mode == RC_DIGEST || mode == RC_HOOK_REFUSES ||
                  mode == RC_READY_SEND_FAILS)) {
        /* The digest of the tree the ceremony WILL build, from a dry run --
           twice, to show two in-process builds are byte-identical. */
        if (!lsp_factory_creation_digest(lsp, lsp->client_pubkeys, 4, fake_txid, 0,
                                         amount, spk, 34, 10, 4, 500, dry_digest) ||
            !lsp_factory_creation_digest(lsp, lsp->client_pubkeys, 4, fake_txid, 0,
                                         amount, spk, 34, 10, 4, 500, dry_again))
            fail = "dry-run digest";
        else if (memcmp(dry_digest, dry_again, 32) != 0)
            fail = "two in-process builds differ";
        lsp->before_factory_ready = rc_hook;
    }

    int created = 0;
    if (!fail)
        created = lsp_run_factory_creation(lsp, fake_txid, 0, amount, spk, 34,
                                           10, 4, /*cltv*/ 500);
    factory_t *f = lsp ? &lsp->factory : NULL;
    if (!fail && mode == RC_READY_SEND_FAILS) {
        /* The hook ran (a caller would have recorded SIGNING_READY), then the
           very first FACTORY_READY send failed: the ceremony fails with
           ceremony_ready_sent == 0 -- rotation must still not lower its marker
           (lsp_rotation_ceremony_failed). */
        if (created) fail = "a failed FACTORY_READY send must fail the ceremony";
        else if (rc_hook_calls != 1) fail = "hook not called exactly once";
        else if (lsp->ceremony_ready_sent != 0) fail = "ceremony_ready_sent";
    } else if (!fail && mode == RC_HOOK_REFUSES) {
        /* Refused right before delivery: the ceremony fails and no client
           ever received FACTORY_READY. */
        if (created) fail = "a refusing hook must abort the ceremony";
        else if (rc_hook_calls != 1) fail = "hook not called exactly once";
        else if (lsp->ceremony_ready_sent != 0) fail = "FACTORY_READY was sent";
        else if (memcmp(rc_hook_digest, dry_digest, 32) != 0)
            fail = "hook saw a different tree than the dry run";
    } else if (!fail && mode == RC_REFUSED) {
        /* The ceremony must fail (clients refuse 0 bps) and leave the
           caller's template behind -- arrays allocated, same shape and
           profiles -- so the caller's retry rebuilds the same factory. */
        if (created) fail = "refused terms must fail creation";
        else if (!f->profiles || !f->nodes || !f->pubkeys || !f->leaf_node_indices)
            fail = "failed attempt left NULL factory arrays";
        else if (!rc_profiles_match(f, 5, 0)) fail = "failed attempt lost the profiles";
        else if (f->n_level_arity != 2 || f->level_arity[0] != 2 ||
                 f->level_arity[1] != 4 || f->static_threshold_depth != 1)
            fail = "failed attempt lost the shape";
    } else if (!fail) {
        if (!created) fail = "lsp_run_factory_creation failed";
        else if (f->n_nodes == 0 || !f->nodes || !f->profiles) fail = "no tree / arrays";
        else if (f->n_participants != 5) fail = "participant count";
        else if (f->dist_tx_ready != 2 || f->dist_signed_tx.len == 0)
            fail = "distribution TX not co-signed";
        else if (mode != RC_NEVER_ALLOCATED &&
                 (f->n_level_arity != 2 || f->level_arity[0] != 2 ||
                  f->level_arity[1] != 4 || f->static_threshold_depth != 1))
            fail = "shape (level arity / static-near-root) not carried";
        else if (mode == RC_PREALLOCATED && !rc_profiles_match(f, 5, 150))
            fail = "participant profiles not carried across creation";
        else if (mode == RC_NEVER_ALLOCATED && f->profiles[1].profit_share_bps != 0)
            fail = "fresh profiles must start zeroed";
        else if (mode == RC_DIGEST) {
            unsigned char built[32];
            if (rc_hook_calls != 1) fail = "hook not called exactly once";
            else if (lsp->ceremony_ready_sent != 4) fail = "FACTORY_READY not sent to all 4";
            else if (memcmp(rc_hook_digest, dry_digest, 32) != 0)
                fail = "delivered tree differs from the dry run";
            else if (!lsp_factory_tree_digest(f, built) || memcmp(built, dry_digest, 32) != 0)
                fail = "created factory differs from the dry run";
        }
        if (!fail) {
            /* Let the clients finish: sign (not broadcast) a cooperative close. */
            uint64_t per = (amount - 500) / 5;
            tx_output_t outs[5];
            for (int i = 0; i < 5; i++) {
                outs[i].amount_sats = per;
                memcpy(outs[i].script_pubkey, spk, 34);
                outs[i].script_pubkey_len = 34;
            }
            outs[4].amount_sats = amount - 500 - per * 4;
            tx_buf_t close_tx;
            tx_buf_init(&close_tx, 512);
            if (!lsp_run_cooperative_close(lsp, &close_tx, outs, 5, 0))
                fail = "cooperative close";
            tx_buf_free(&close_tx);
        }
    }
    if (lsp) {
        lsp_cleanup(lsp);
        free(lsp);
    }
    int kids_ok = 1;
    for (int c = 0; c < 4; c++) {
        int st = 0;
        if (fail) kill(kids[c], SIGKILL);
        waitpid(kids[c], &st, 0);
        int want_ok = (mode != RC_REFUSED && mode != RC_HOOK_REFUSES &&
                       mode != RC_READY_SEND_FAILS);
        int ok = WIFEXITED(st) && WEXITSTATUS(st) == 0;
        if (!fail && want_ok && !ok) kids_ok = 0;
    }
    secp256k1_context_destroy(ctx);
    signal(SIGPIPE, old_pipe);
    if (fail) {
        printf("  FAIL: %s (mode %d): %s\n", __func__, mode, fail);
        return 0;
    }
    TEST_ASSERT(kids_ok, "all clients completed the ceremony");
    return 1;
}

/* Rotation's old order: factory_free(&lsp->factory), then creation. */
int test_rotation_creation_after_factory_free(void) {
    return rc_run_creation(RC_AFTER_FREE);
}

/* No shape setter ever ran (e.g. --arity 2 --static-near-root 0). */
int test_rotation_creation_arrays_never_allocated(void) {
    return rc_run_creation(RC_NEVER_ALLOCATED);
}

/* Live arrays: shape + every participant profile carried into the factory. */
int test_rotation_creation_carries_profiles(void) {
    return rc_run_creation(RC_PREALLOCATED);
}

/* A failed ceremony (clients refuse the terms) must leave the caller's
   template -- arrays allocated, shape, profiles -- so a retry (the initial
   creation retry loop, a rotation retry) neither crashes nor loses them. */
int test_rotation_creation_failure_keeps_template(void) {
    return rc_run_creation(RC_REFUSED);
}

/* The tree a dry run predicts is exactly the one the real ceremony signs and
   hands to the before_factory_ready hook (shape: level arity 2,4 +
   static-near-root 1), and two in-process builds are byte-identical. */
int test_rotation_creation_digest_matches_ceremony(void) {
    return rc_run_creation(RC_DIGEST);
}

/* The hook ran and then the first FACTORY_READY send failed. */
int test_rotation_creation_ready_send_fails(void) {
    return rc_run_creation(RC_READY_SEND_FAILS);
}

/* before_factory_ready refusing aborts the ceremony with no FACTORY_READY sent. */
int test_rotation_creation_hook_refusal_aborts(void) {
    return rc_run_creation(RC_HOOK_REFUSES);
}

/* lsp_factory_creation_digest: byte-identical across builds with the same
   inputs, different with any recorded parameter changed.  Across an LSP
   restart the template comes from the DB, so identity there also needs the
   factory shape restored as it was -- reloading a factory from the DB does not
   restore its per-level arity or static-near-root today. */
int test_rotation_creation_digest_stable(void) {
    secp256k1_context *ctx = rc_ctx();
    secp256k1_keypair kps[5];
    for (int i = 0; i < 5; i++)
        TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[i], rc_seckeys[i]), "keypair");
    unsigned char spk[34];
    TEST_ASSERT(rc_funding_spk(ctx, kps, spk, NULL), "funding spk");
    secp256k1_pubkey cpks[4];
    for (int i = 0; i < 4; i++)
        TEST_ASSERT(secp256k1_keypair_pub(ctx, &cpks[i], &kps[i + 1]), "pub");
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    TEST_ASSERT(lsp && lsp_init(lsp, ctx, &kps[0], 0, 4), "lsp_init");
    uint8_t arities[2] = { 2, 4 };
    factory_set_level_arity(&lsp->factory, arities, 2);
    factory_set_static_near_root(&lsp->factory, 1);
    unsigned char txid[32], txid2[32];
    memset(txid, 0xC3, 32);
    memset(txid2, 0xC4, 32);
    uint64_t amounts[4] = { 200000, 200000, 200000, 200000 };
    lsp->dist_client_amounts = amounts;
    lsp->dist_n_client_amounts = 4;
    unsigned char d1[32], d2[32], d3[32], d4[32], d5[32];
    TEST_ASSERT(lsp_factory_creation_digest(lsp, cpks, 4, txid, 0, 1000000, spk, 34,
                                            10, 4, 500, d1), "build 1");
    TEST_ASSERT(lsp_factory_creation_digest(lsp, cpks, 4, txid, 0, 1000000, spk, 34,
                                            10, 4, 500, d2), "build 2");
    TEST_ASSERT(memcmp(d1, d2, 32) == 0, "same inputs: byte-identical tree");
    TEST_ASSERT(lsp_factory_creation_digest(lsp, cpks, 4, txid, 0, 1000000, spk, 34,
                                            10, 4, 501, d3) && memcmp(d1, d3, 32) != 0,
                "a different CLTV is a different tree");
    TEST_ASSERT(lsp_factory_creation_digest(lsp, cpks, 4, txid2, 0, 1000000, spk, 34,
                                            10, 4, 500, d4) && memcmp(d1, d4, 32) != 0,
                "a different funding outpoint is a different tree");
    amounts[2] = 150000;
    TEST_ASSERT(lsp_factory_creation_digest(lsp, cpks, 4, txid, 0, 1000000, spk, 34,
                                            10, 4, 500, d5) && memcmp(d1, d5, 32) != 0,
                "different distribution amounts are a different tree");
    lsp->dist_client_amounts = NULL;
    lsp->dist_n_client_amounts = 0;
    lsp_cleanup(lsp);
    free(lsp);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* lsp_rotation_signed_tree_matches: the SIGNING_READY gate.  A ceremony may
   run again only if the tree rebuilt from the recorded funding, CLTV and
   amounts has the recorded digest. */
int test_rotation_signed_tree_matches(void) {
    secp256k1_context *ctx = rc_ctx();
    secp256k1_keypair kps[5];
    for (int i = 0; i < 5; i++)
        TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[i], rc_seckeys[i]), "keypair");
    unsigned char spk[34];
    TEST_ASSERT(rc_funding_spk(ctx, kps, spk, NULL), "funding spk");
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    TEST_ASSERT(lsp && lsp_init(lsp, ctx, &kps[0], 0, 4), "lsp_init");
    TEST_ASSERT(lsp->client_pubkeys, "client key array");
    for (int i = 0; i < 4; i++)
        TEST_ASSERT(secp256k1_keypair_pub(ctx, &lsp->client_pubkeys[i], &kps[i + 1]), "pub");
    lsp->n_clients = 4;
    lsp_channel_mgr_t *mgr = calloc(1, sizeof(lsp_channel_mgr_t));
    TEST_ASSERT(mgr, "mgr");
    memcpy(mgr->rot_fund_spk, spk, 34);
    mgr->rot_fund_spk_len = 34;
    mgr->rot_step_blocks = 10;
    mgr->rot_states_per_layer = 4;
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    unsigned char txid[32];
    memset(txid, 0xC3, 32);
    unsigned char rb[32];
    for (int i = 0; i < 32; i++) rb[i] = txid[31 - i];
    hex_encode(rb, 32, rp->new_funding_txid);
    rp->new_funding_vout = 0;
    rp->new_funding_amount = 1000000;
    rp->new_cltv = 500;
    rp->n_dist_amounts = 4;
    for (int i = 0; i < 4; i++) rp->dist_amounts[i] = 200000;

    TEST_ASSERT(lsp_rotation_signed_tree_matches(mgr, lsp) == -1, "no digest recorded");
    unsigned char d[32];
    lsp->dist_client_amounts = rp->dist_amounts;
    lsp->dist_n_client_amounts = 4;
    TEST_ASSERT(lsp_factory_creation_digest(lsp, lsp->client_pubkeys, 4, txid, 0, 1000000,
                                            spk, 34, 10, 4, 500, d), "digest");
    lsp->dist_client_amounts = NULL;
    lsp->dist_n_client_amounts = 0;
    hex_encode(d, 32, rp->tree_digest);
    TEST_ASSERT(lsp_rotation_signed_tree_matches(mgr, lsp) == 1,
                "the recorded parameters rebuild the delivered tree");
    rp->new_cltv = 501;
    TEST_ASSERT(lsp_rotation_signed_tree_matches(mgr, lsp) == 0,
                "a different CLTV must not pass (it would be a second, different tree)");
    rp->new_cltv = 500;
    uint8_t arities[2] = { 2, 4 };
    factory_set_level_arity(&lsp->factory, arities, 2);
    TEST_ASSERT(lsp_rotation_signed_tree_matches(mgr, lsp) == 0,
                "a different factory shape must not pass");
    free(mgr);
    lsp_cleanup(lsp);
    free(lsp);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* lsp_factory_creation_preflight: the dry run rotation performs before its
   irreversible close.  No clients / sockets needed. */
int test_rotation_creation_preflight(void) {
    secp256k1_context *ctx = rc_ctx();
    secp256k1_keypair kps[5];
    for (int i = 0; i < 5; i++)
        TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[i], rc_seckeys[i]), "keypair");
    unsigned char spk[34];
    TEST_ASSERT(rc_funding_spk(ctx, kps, spk, NULL), "funding spk");
    secp256k1_pubkey cpks[4];
    for (int i = 0; i < 4; i++)
        TEST_ASSERT(secp256k1_keypair_pub(ctx, &cpks[i], &kps[i + 1]), "pub");

    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    TEST_ASSERT(lsp && lsp_init(lsp, ctx, &kps[0], 0, 4), "lsp_init");

    /* 1. arrays never allocated: succeeds, leaves lsp->factory untouched. */
    TEST_ASSERT(lsp_factory_creation_preflight(lsp, cpks, 4, 1000000, spk, 34,
                                               10, 4, 500) == 1,
                "preflight on a never-allocated factory");
    TEST_ASSERT(lsp->factory.profiles == NULL && lsp->factory.n_nodes == 0,
                "preflight must not touch lsp->factory");

    /* 2. configured shape + profiles: succeeds, live factory unchanged. */
    uint8_t arities[2] = { 2, 4 };
    factory_set_level_arity(&lsp->factory, arities, 2);
    factory_set_static_near_root(&lsp->factory, 1);
    rc_set_profiles(&lsp->factory, 5, 150);
    TEST_ASSERT(lsp_factory_creation_preflight(lsp, cpks, 4, 1000000, spk, 34,
                                               10, 4, 500) == 1,
                "preflight on a configured factory");
    TEST_ASSERT(rc_profiles_match(&lsp->factory, 5, 150) &&
                lsp->factory.n_level_arity == 2 && lsp->factory.n_nodes == 0,
                "configured factory unchanged by preflight");

    /* 3. after factory_free (what rotation used to do): no crash. */
    factory_free(&lsp->factory);
    TEST_ASSERT(lsp_factory_creation_preflight(lsp, cpks, 4, 1000000, spk, 34,
                                               10, 4, 500) == 1,
                "preflight on a factory_free'd factory");

    /* 4. a replacement that cannot be built (funding below the tree's
          minimum) is caught BEFORE anything irreversible. */
    TEST_ASSERT(lsp_factory_creation_preflight(lsp, cpks, 4, 1000, spk, 34,
                                               10, 4, 500) == 0,
                "preflight rejects an unbuildable replacement");
    TEST_ASSERT(lsp_factory_creation_preflight(lsp, cpks, 0, 1000000, spk, 34,
                                               10, 4, 500) == 0,
                "preflight rejects an empty participant set");

    lsp_cleanup(lsp);
    free(lsp);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Bug B: the ladder slot's distribution TX (what the LSP auto-broadcasts at
   EXPIRED) must be the co-signed one.  dist_unsigned_tx carries an empty
   witness -- bitcoind: "Witness program was passed an empty witness". */
int test_ladder_distribution_tx_signed_only(void) {
    secp256k1_context *ctx = rc_ctx();
    secp256k1_keypair kps[5];
    for (int i = 0; i < 5; i++)
        TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[i], rc_seckeys[i]), "keypair");
    unsigned char spk[34];
    secp256k1_xonly_pubkey fund_key;
    TEST_ASSERT(rc_funding_spk(ctx, kps, spk, &fund_key), "funding spk");
    unsigned char fake_txid[32];
    memset(fake_txid, 0x5E, 32);

    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f, "alloc");
    TEST_ASSERT(factory_init(f, ctx, kps, 5, 2, 4), "factory_init");
    factory_set_funding(f, fake_txid, 0, 200000, spk, 34);
    TEST_ASSERT(factory_build_tree(f), "build tree");
    tx_output_t outs[6];
    size_t n_out = factory_compute_distribution_outputs_balanced(f, outs, 6, 500, NULL, 0);
    TEST_ASSERT(n_out > 0, "dist outputs");
    TEST_ASSERT(factory_build_distribution_tx_unsigned(f, outs, n_out, 5000), "unsigned dist");
    TEST_ASSERT(f->dist_tx_ready == 1, "dist_tx_ready == 1 (unsigned only)");

    ladder_factory_t *lf = calloc(1, sizeof(ladder_factory_t));
    TEST_ASSERT(lf, "alloc slot");
    /* Unsigned only: nothing is stored (an unrelayable TX must never be). */
    TEST_ASSERT(ladder_factory_store_distribution_tx(lf, f) == 0, "unsigned not stored");
    TEST_ASSERT(lf->distribution_tx.len == 0, "slot empty with only an unsigned TX");

    /* Co-sign it the way the stateless ceremony does (each party separately). */
    TEST_ASSERT(factory_session_init_dist(f), "init dist session");
    secp256k1_musig_secnonce sn[5];
    for (size_t j = 0; j < 5; j++) {
        unsigned char sk[32];
        secp256k1_pubkey pk;
        secp256k1_musig_pubnonce pn;
        TEST_ASSERT(secp256k1_keypair_sec(ctx, sk, &kps[j]) &&
                    secp256k1_keypair_pub(ctx, &pk, &kps[j]), "keys");
        TEST_ASSERT(musig_generate_nonce(ctx, &sn[j], &pn, sk, &pk,
                                         &f->nodes[0].keyagg.cache), "nonce");
        memset(sk, 0, 32);
        TEST_ASSERT(factory_session_set_nonce_dist(f, j, &pn), "set nonce");
    }
    TEST_ASSERT(factory_session_finalize_dist(f), "finalize dist");
    for (size_t j = 0; j < 5; j++) {
        secp256k1_musig_partial_sig ps;
        TEST_ASSERT(musig_create_partial_sig(ctx, &ps, &sn[j], &kps[j],
                                             &f->dist_signing_session), "psig");
        TEST_ASSERT(factory_session_set_partial_sig_dist(f, j, &ps), "set psig");
    }
    TEST_ASSERT(factory_session_complete_dist(f), "complete dist");
    TEST_ASSERT(f->dist_tx_ready == 2, "dist_tx_ready == 2 (signed)");

    TEST_ASSERT(ladder_factory_store_distribution_tx(lf, f) == 1, "signed stored");
    const tx_buf_t *d = &lf->distribution_tx;
    TEST_ASSERT(d->len == f->dist_signed_tx.len &&
                memcmp(d->data, f->dist_signed_tx.data, d->len) == 0,
                "slot holds exactly dist_signed_tx");
    TEST_ASSERT(d->len != f->dist_unsigned_tx.len ||
                memcmp(d->data, f->dist_unsigned_tx.data, d->len) != 0,
                "slot does NOT hold dist_unsigned_tx");
    /* Segwit serialization with a 1-item, 64-byte key-path witness right
       before nLockTime, valid against the funding output key. */
    TEST_ASSERT(d->len >= 80 && d->data[4] == 0x00 && d->data[5] == 0x01,
                "segwit marker/flag present");
    TEST_ASSERT(d->data[d->len - 70] == 0x01 && d->data[d->len - 69] == 0x40,
                "witness present: 1 item of 64 bytes");
    TEST_ASSERT(secp256k1_schnorrsig_verify(ctx, d->data + d->len - 68,
                                            f->dist_sighash, 32, &fund_key) == 1,
                "stored distribution TX signature verifies");

    /* Replacing: a later factory with only an unsigned TX clears the slot. */
    f->dist_tx_ready = 1;
    TEST_ASSERT(ladder_factory_store_distribution_tx(lf, f) == 0 &&
                lf->distribution_tx.len == 0, "slot cleared when no signed TX");

    tx_buf_free(&lf->distribution_tx);
    free(lf);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}
