/* Channel opening terms: each member's channel capacity and the opening
   balance split are fixed in FACTORY_PROPOSE, before anyone signs, and a
   member refuses a factory or a CHANNEL_READY that does not match them.

   The tests run the real ceremony in-process: four forked members
   (client_run_with_channels) over loopback TCP and a placeholder funding
   outpoint (creation and channel opening need no chain), then a
   cooperative close so the members exit cleanly. */
#include "superscalar/factory.h"
#include "superscalar/lsp.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/client.h"
#include "superscalar/channel.h"
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

/* LSP + 4 members (distinct from the other suites' keys). */
static const unsigned char ot_seckeys[5][32] = {
    { [0 ... 31] = 0x71 },
    { [0 ... 31] = 0x72 },
    { [0 ... 31] = 0x73 },
    { [0 ... 31] = 0x74 },
    { [0 ... 31] = 0x75 },
};

#define OT_HONEST       0   /* default tree, split as proposed */
#define OT_TAMPER_SPLIT 1   /* LSP sends member 2 a split other than proposed */
#define OT_CAPACITY     2   /* unequal capacities, each member expects its own */
#define OT_CAP_REFUSE   3   /* member 3's minimum is above its capacity */
#define OT_CAP_DIST     4   /* LSP sends dist_amounts other than the capacity rule */
#define OT_MAX_PCT      5   /* member 4 accepts at most 60% for the LSP */

/* Channel capacities of members 1..4 (OT_CAPACITY / OT_CAP_REFUSE). */
static const uint64_t ot_caps[4] = { 40000, 90000, 150000, 65000 };
#define OT_STOCK 30000

/* The LSP's share of each channel at opening. */
#define OT_LSP_PCT 70

static secp256k1_context *ot_ctx(void) {
    return secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

static int ot_port(int mode) {
    return 25000 + (int)(getpid() % 1000) * 8 + mode;
}

static int ot_member_cb(int fd, channel_t *ch, uint32_t my_index,
                        secp256k1_context *ctx, const secp256k1_keypair *kp,
                        factory_t *f, size_t n, void *ud) {
    (void)fd; (void)ch; (void)my_index; (void)ctx; (void)kp; (void)f; (void)n; (void)ud;
    return 1;   /* straight to the cooperative close */
}

/* Run creation + channel opening + cooperative close for `mode`.
   member_ok[c] receives whether member c+1 completed. */
static int ot_run(int mode, int member_ok[4], const char **fail_out) {
    secp256k1_context *ctx = ot_ctx();
    secp256k1_keypair kps[5];
    for (int i = 0; i < 5; i++)
        if (!secp256k1_keypair_create(ctx, &kps[i], ot_seckeys[i])) return 0;
    unsigned char fake_txid[32];
    memset(fake_txid, 0xD4, 32);
    int port = ot_port(mode);

    fflush(stdout);
    fflush(stderr);
    pid_t kids[4];
    for (int c = 0; c < 4; c++) {
        pid_t pid = fork();
        if (pid == 0) {
            alarm(120);
            usleep(100000 * (c + 1));
            secp256k1_context *cctx = ot_ctx();
            secp256k1_keypair ckp;
            if (!secp256k1_keypair_create(cctx, &ckp, ot_seckeys[c + 1])) _exit(2);
            if (mode == OT_CAPACITY || mode == OT_CAP_REFUSE || mode == OT_CAP_DIST)
                client_set_capacity_terms(ot_caps[c], 0);
            if (mode == OT_MAX_PCT && c == 3)
                client_set_max_lsp_balance_pct(60);
            if (mode == OT_CAP_REFUSE && c == 2)
                client_set_capacity_terms(0, ot_caps[c] + 1);
            int ok = client_run_with_channels(cctx, &ckp, "127.0.0.1", port,
                                              ot_member_cb, NULL, NULL, NULL);
            secp256k1_context_destroy(cctx);
            _exit(ok ? 0 : 1);
        }
        kids[c] = pid;
    }

    void (*old_pipe)(int) = signal(SIGPIPE, SIG_IGN);
    const char *fail = NULL;
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    lsp_channel_mgr_t *mgr = calloc(1, sizeof(lsp_channel_mgr_t));
    if (!lsp || !mgr || !lsp_init(lsp, ctx, &kps[0], port, 4)) fail = "lsp_init";
    if (!fail && !lsp_accept_clients(lsp)) fail = "accept clients";
    uint64_t amount = 1000000;
    if (!fail) {
        lsp->lsp_balance_pct = OT_LSP_PCT;
        if (mode == OT_CAP_DIST) {
            /* The bare capacities: short of the capacity rule's stock shares. */
            lsp->dist_client_amounts = ot_caps;
            lsp->dist_n_client_amounts = 4;
        }
        if (mode == OT_CAPACITY || mode == OT_CAP_REFUSE || mode == OT_CAP_DIST) {
            lsp->member_capacities = ot_caps;
            lsp->n_member_capacities = 4;
            lsp->leaf_stock_sats = OT_STOCK;
            if (!lsp_compute_funding_amount(lsp, &amount)) fail = "funding amount";
        }
    }
    unsigned char spk[34];
    if (!fail && !lsp_compute_funding_spk(lsp, spk)) fail = "funding spk";
    int created = !fail && lsp_run_factory_creation(lsp, fake_txid, 0, amount, spk, 34,
                                                    10, 4, /*cltv*/ 500);
    if (!fail && (mode == OT_CAP_REFUSE || mode == OT_CAP_DIST || mode == OT_MAX_PCT)) {
        if (created) fail = "creation succeeded over a member's refusal";
        else fail = "refused";   /* expected: stop here */
    } else if (!fail && !created) {
        fail = "lsp_run_factory_creation";
    }
    if (!fail && mode == OT_CAPACITY) {
        factory_t *f = &lsp->factory;
        if (f->funding_amount_sats != amount) fail = "funding amount";
        for (size_t c = 0; !fail && c < 4; c++) {
            size_t ni;
            uint32_t vout;
            if (!factory_client_to_leaf(f, c, &ni, &vout) ||
                f->nodes[ni].outputs[vout].amount_sats != ot_caps[c])
                fail = "channel output is not the member's capacity";
        }
        tx_output_t douts[8];
        size_t nd = factory_compute_distribution_outputs_balanced(f, douts, 8, 500, NULL, 0);
        uint64_t dsum = 0;
        if (nd != 4) fail = "distribution outputs";
        for (size_t c = 0; !fail && c < nd; c++) {
            dsum += douts[c].amount_sats;
            if (douts[c].amount_sats < ot_caps[c]) fail = "distribution below capacity";
        }
        if (!fail && dsum != amount - 500) fail = "distribution total";
        if (!fail && f->dist_tx_ready != 2) fail = "distribution TX not co-signed";
    }
    int mgr_live = 0;
    if (!fail) {
        mgr->lsp_balance_pct = OT_LSP_PCT;
        if (!lsp_channels_init(mgr, ctx, &lsp->factory, ot_seckeys[0], 4))
            fail = "lsp_channels_init";
        else
            mgr_live = 1;
    }
    if (!fail && mode == OT_CAPACITY) {
        for (size_t c = 0; !fail && c < 4; c++)
            if (mgr->entries[c].channel.funding_amount != ot_caps[c])
                fail = "channel funding amount is not the capacity";
    }
    if (!fail && mode == OT_TAMPER_SPLIT) {
        /* A split other than the proposed one, with the same total. */
        channel_t *ch = &mgr->entries[1].channel;
        ch->local_amount += 1000;
        ch->remote_amount -= 1000;
    }
    if (!fail && !lsp_channels_exchange_basepoints(mgr, lsp)) fail = "basepoints";
    if (!fail && !lsp_channels_send_ready(mgr, lsp)) fail = "send ready";
    if (!fail) {
        tx_output_t outs[8];
        size_t n_close = lsp_channels_build_close_outputs(mgr, &lsp->factory,
                                                          outs, 500, NULL, 0);
        tx_buf_t close_tx;
        tx_buf_init(&close_tx, 512);
        if (n_close == 0 || !lsp_run_cooperative_close(lsp, &close_tx, outs, n_close, 0))
            fail = "cooperative close";
        tx_buf_free(&close_tx);
    }
    if (mgr_live) lsp_channels_cleanup(mgr);
    free(mgr);
    if (lsp) {
        lsp_cleanup(lsp);
        free(lsp);
    }
    for (int c = 0; c < 4; c++) {
        int st = 0;
        waitpid(kids[c], &st, 0);
        member_ok[c] = WIFEXITED(st) && WEXITSTATUS(st) == 0;
    }
    secp256k1_context_destroy(ctx);
    signal(SIGPIPE, old_pipe);
    *fail_out = fail;
    return 1;
}

/* The proposed split opens every channel and every member completes; the
   LSP then opens member 2's channel with another split of the same total:
   that member refuses it. */
int test_open_terms_split_bound(void) {
    int ok[4];
    const char *fail = NULL;
    TEST_ASSERT(ot_run(OT_HONEST, ok, &fail), "run");
    if (fail) printf("  (honest run: %s)\n", fail);
    TEST_ASSERT(!fail, "honest run");
    for (int c = 0; c < 4; c++) TEST_ASSERT(ok[c], "member completed the proposed split");
    TEST_ASSERT(ot_run(OT_TAMPER_SPLIT, ok, &fail), "run");
    TEST_ASSERT(!ok[1], "member 2 accepted a split other than the proposed one");
    return 1;
}

/* Unequal per-member capacities: each channel output, channel and the
   co-signed distribution TX carry the member's full capacity, and each
   member (checking its expected capacity) completes.  A member whose minimum
   is above its capacity refuses before signing, and creation fails. */
int test_open_terms_capacity(void) {
    int ok[4];
    const char *fail = NULL;
    TEST_ASSERT(ot_run(OT_CAPACITY, ok, &fail), "run");
    if (fail) printf("  (capacity run: %s)\n", fail);
    TEST_ASSERT(!fail, "capacity run");
    for (int c = 0; c < 4; c++) TEST_ASSERT(ok[c], "member completed");
    TEST_ASSERT(ot_run(OT_CAP_REFUSE, ok, &fail), "run");
    TEST_ASSERT(fail && strcmp(fail, "refused") == 0, "creation refused");
    TEST_ASSERT(!ok[2], "member 3 refused a capacity below its minimum");
    return 1;
}

/* Member policy: with capacities, distribution amounts other than the
   capacity rule's are refused; a member bounding the LSP's opening share
   refuses a larger one.  Either refusal stops the creation. */
int test_open_terms_member_policy(void) {
    int ok[4];
    const char *fail = NULL;
    TEST_ASSERT(ot_run(OT_CAP_DIST, ok, &fail), "run");
    TEST_ASSERT(fail && strcmp(fail, "refused") == 0, "dist amounts: creation refused");
    for (int c = 0; c < 4; c++) TEST_ASSERT(!ok[c], "member refused the dist amounts");
    TEST_ASSERT(ot_run(OT_MAX_PCT, ok, &fail), "run");
    TEST_ASSERT(fail && strcmp(fail, "refused") == 0, "max pct: creation refused");
    TEST_ASSERT(!ok[3], "member 4 refused a 70% LSP share");
    return 1;
}
