/* Regression tests for factory creation over a factory_t whose dynamic
   arrays were released by factory_free() or never allocated.

   Before the fix, lsp_run_factory_creation_stateless memcpy'd 8 KiB of
   participant profiles out of f->profiles while it was NULL.  That crashed
   the initial ceremony when no shape setter had allocated the arrays
   (test_regtest_wire_factory), the initial-creation retry after a failed
   ceremony (fail_pre freed the factory), and rotation, which calls it right
   after factory_free(&lsp->factory).  The tests run the REAL ceremony
   in-process: four forked clients over loopback TCP and a placeholder
   funding outpoint (the ceremony itself needs no chain). */
#include "superscalar/factory.h"
#include "superscalar/lsp.h"
#include "superscalar/client.h"
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
/* Profiles that every reordering placement mode sorts to clients 4,3,2,1,
   funded at lsp_compute_funding_spk. */
#define RC_REORDER_INWARD  4
#define RC_REORDER_OUTWARD 5
#define RC_REORDER_TZ      6

static int rc_reordering(int mode) { return mode >= RC_REORDER_INWARD; }

static placement_mode_t rc_reorder_placement(int mode) {
    return mode == RC_REORDER_INWARD  ? PLACEMENT_INWARD :
           mode == RC_REORDER_OUTWARD ? PLACEMENT_OUTWARD :
                                        PLACEMENT_TIMEZONE_CLUSTER;
}

/* Inward sorts contribution down, outward uptime up, timezone cluster the
   bucket up: each puts the clients in reverse participant order. */
static void rc_set_reordering_profiles(factory_t *f) {
    for (size_t i = 1; i < 5; i++) {
        f->profiles[i].contribution_sats = 1000 + i;
        f->profiles[i].uptime_score = 0.9f - 0.1f * (float)i;
        f->profiles[i].timezone_bucket = (uint8_t)(10 - i);
    }
}

static int rc_port(int mode) {
    return 21000 + (int)(getpid() % 2000) * 8 + mode;
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
            usleep(100000 * (4 - c));  /* reverse key order: the hint decides */
            /* The LSP orders members by this hint, not by connection order. */
            client_set_slot_hint(c + 1);
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
            if (!fail && rc_reordering(mode)) {
                rc_set_reordering_profiles(&lsp->factory);
                if (!factory_set_placement_mode(&lsp->factory,
                                                rc_reorder_placement(mode)))
                    fail = "placement";
            }
            if (mode == RC_AFTER_FREE) {
                factory_free(&lsp->factory);
                if (lsp->factory.profiles) fail = "precondition: profiles freed";
            }
        }
    }

    if (!fail && rc_reordering(mode)) {
        /* The root aggregates the clients in placement order, not in
           participant order: fund the key creation will build. */
        unsigned char index_order[34];
        memcpy(index_order, spk, 34);
        if (!lsp_compute_funding_spk(lsp, spk)) fail = "lsp_compute_funding_spk";
        else if (memcmp(spk, index_order, 34) == 0)
            fail = "precondition: placement must reorder the root signers";
    }

    int created = 0;
    /* the agreed tree rate (factory_free cleared it) */
    if (lsp) lsp->factory.tree_fee_rate = FACTORY_DEFAULT_TREE_FEE_RATE;
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
        else if (rc_reordering(mode) &&
                 (f->nodes[0].n_signers != 5 || f->nodes[0].signer_indices[1] != 4 ||
                  f->nodes[0].signer_indices[4] != 1))
            fail = "root signers not in placement order";
        else if (rc_reordering(mode) && memcmp(f->funding_spk, spk, 34) != 0)
            fail = "factory funding script";
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

/* A placement mode that reorders the clients: the factory is funded at
   lsp_compute_funding_spk (the key the daemon derives its funding address
   from) and the whole ceremony runs over it, for every reordering mode. */
int test_rotation_creation_placement_funding(void) {
    static const int modes[] = { RC_REORDER_INWARD, RC_REORDER_OUTWARD,
                                 RC_REORDER_TZ };
    for (size_t m = 0; m < sizeof(modes) / sizeof(modes[0]); m++)
        if (!rc_run_creation(modes[m])) return 0;
    return 1;
}
