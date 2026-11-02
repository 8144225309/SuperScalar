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

    int created = 0;
    if (!fail)
        created = lsp_run_factory_creation(lsp, fake_txid, 0, amount, spk, 34,
                                           10, 4, /*cltv*/ 500);
    factory_t *f = lsp ? &lsp->factory : NULL;
    if (!fail && mode == RC_REFUSED) {
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
        int want_ok = (mode != RC_REFUSED);
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
