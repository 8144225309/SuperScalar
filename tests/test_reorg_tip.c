/*
 * test_reorg_tip.c — R1 reorg detector: tip snapshot + classification.
 *
 * Unit tests drive lsp_reorg_classify() / lsp_reorg_state_advance() (pure)
 * against a simulated chain.  The pre-fix detector logic (two-RPC tip read,
 * inline classification) is reproduced here as legacy_* helpers to show
 * the cases it got wrong.
 *
 * Regtest tests: (1) sample the tip while a child process mines, and check
 * every regtest_get_tip() pair is consistent; (2) replace blocks around the
 * detector's polls and check lsp_reorg_poll() reports each reorg once.
 */

#include "superscalar/lsp_channels.h"
#include "superscalar/regtest.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

/* ---- simulated chain ---------------------------------------------------- */

#define SIM_MAX 256
typedef struct {
    int  height;
    char hash[SIM_MAX][65];
} sim_chain_t;

static void sim_set(sim_chain_t *c, int h, char branch) {
    snprintf(c->hash[h], 65, "%c%063x", branch, (unsigned)h);
}

static void sim_init(sim_chain_t *c, int height, char branch) {
    memset(c, 0, sizeof(*c));
    for (int h = 0; h <= height; h++) sim_set(c, h, branch);
    c->height = height;
}

static void sim_mine(sim_chain_t *c, char branch) {
    c->height++;
    sim_set(c, c->height, branch);
}

/* Replace everything above fork_height with branch `b` up to new_height. */
static void sim_reorg(sim_chain_t *c, int fork_height, int new_height, char b) {
    for (int h = fork_height + 1; h <= new_height; h++) sim_set(c, h, b);
    for (int h = new_height + 1; h < SIM_MAX; h++) c->hash[h][0] = '\0';
    c->height = new_height;
}

/* Pre-fix read: getblockcount, then (a block may connect here)
   getbestblockhash, stored as a pair. */
static void legacy_read_tip(sim_chain_t *c, int block_between,
                            int *h_out, char hash_out[65]) {
    *h_out = c->height;                         /* getblockcount    */
    if (block_between) sim_mine(c, 'a');        /* block connects   */
    memcpy(hash_out, c->hash[c->height], 65);   /* getbestblockhash */
}

/* Post-fix read: one getblockchaininfo.  bitcoind fills "blocks" and
   "bestblockhash" from the same tip under cs_main, so a concurrent block
   lands either entirely before or entirely after the snapshot. */
static void snapshot_read_tip(sim_chain_t *c, int block_during,
                              int *h_out, char hash_out[65]) {
    if (block_during) sim_mine(c, 'a');
    *h_out = c->height;
    memcpy(hash_out, c->hash[c->height], 65);
}

/* Pre-fix classification as it was inline in lsp_channels.c (daemon loop
   and heartbeat), with getblockhash(last_height) answered by the sim. */
static int legacy_classify(int32_t daemon_last_height,
                           const char *daemon_last_tip_hash,
                           int height, const char *cur_tip_hash,
                           const sim_chain_t *c) {
    int reorg_kind = 0;
    if (daemon_last_height > 0 && height > 0 &&
        height < daemon_last_height) {
        reorg_kind = 1;
    } else if (daemon_last_height > 0 && height == daemon_last_height &&
               daemon_last_tip_hash[0] && cur_tip_hash[0] &&
               strcmp(cur_tip_hash, daemon_last_tip_hash) != 0) {
        reorg_kind = 2;
    } else if (daemon_last_height > 0 && height > daemon_last_height &&
               daemon_last_tip_hash[0]) {
        const char *prev_hash_now = c->hash[daemon_last_height];
        if (prev_hash_now[0] &&
            strcmp(prev_hash_now, daemon_last_tip_hash) != 0) {
            reorg_kind = 3;
        }
    }
    return reorg_kind;
}

static void st_set(lsp_reorg_state_t *st, int h, const char *hash) {
    memset(st, 0, sizeof(*st));
    st->height = h;
    snprintf(st->hash, sizeof(st->hash), "%s", hash);
}

static const regtest_chain_tip_t no_tips[1];   /* "read, nothing stale" */

/* Classify with the reads lsp_reorg_poll() would do answered by the sim. */
static lsp_reorg_kind_t sim_classify(const lsp_reorg_state_t *st,
                                     int cur_h, const char *cur_hash,
                                     const sim_chain_t *c,
                                     const regtest_chain_tip_t *tips,
                                     size_t n_tips) {
    lsp_reorg_view_t v = {0};
    if (lsp_reorg_needs_hash_at_last(st, cur_h)) {
        v.hash_at_last = c->hash[st->height];
        v.hash_at_next = c->hash[st->height + 1];
    }
    if (lsp_reorg_needs_tips(st, cur_h, cur_hash)) {
        v.tips = tips ? tips : no_tips;
        v.n_tips = tips ? n_tips : 0;
    }
    return lsp_reorg_classify(st, cur_h, cur_hash, &v);
}

/* The race: a block connects between the two tip RPCs, the daemon stores
   (H, hash of H+1), the chain then grows normally to H+3.  No reorg ever
   happened, so nothing may be reported. */
int test_reorg_tip_race_no_false_forward(void) {
    sim_chain_t c;
    const int H = 100;

    /* Before: two-call read + pre-fix classification -> FORWARD_REORG. */
    sim_init(&c, H, 'a');
    int last_h; char last_hash[65];
    legacy_read_tip(&c, 1, &last_h, last_hash);
    TEST_ASSERT(last_h == H, "legacy read height is H");
    TEST_ASSERT(strcmp(last_hash, c.hash[H + 1]) == 0,
                "legacy read stored the hash of H+1 next to height H");
    sim_mine(&c, 'a'); sim_mine(&c, 'a');            /* tip H+3 */
    int cur_h; char cur_hash[65];
    legacy_read_tip(&c, 0, &cur_h, cur_hash);
    TEST_ASSERT(cur_h == H + 3, "tip advanced to H+3");
    int old_kind = legacy_classify(last_h, last_hash, cur_h, cur_hash, &c);
    printf("\n    before: stored (%d, hash@%d), tip %d -> legacy kind=%d (%s)\n",
           last_h, H + 1, cur_h, old_kind,
           old_kind == 3 ? "FORWARD_REORG, false positive" : "?");
    TEST_ASSERT(old_kind == 3, "pre-fix logic reports a false FORWARD_REORG");

    /* After (1): the classifier, given the same mismatched pair, sees the
       stored hash at H+1 and reports nothing. */
    lsp_reorg_state_t st;
    st_set(&st, last_h, last_hash);
    lsp_reorg_kind_t k = sim_classify(&st, cur_h, cur_hash, &c, NULL, 0);
    printf("    after:  same stored pair, classifier -> %s\n",
           k == LSP_REORG_NONE ? "NONE" : lsp_reorg_kind_str(k));
    TEST_ASSERT(k == LSP_REORG_NONE, "race pair classifies as no reorg");

    /* After (2): the snapshot read stores a consistent pair whichever side
       of the snapshot the block lands on. */
    for (int during = 0; during <= 1; during++) {
        sim_init(&c, H, 'a');
        snapshot_read_tip(&c, during, &last_h, last_hash);
        TEST_ASSERT(strcmp(last_hash, c.hash[last_h]) == 0,
                    "snapshot pair is consistent");
        while (c.height < H + 3) sim_mine(&c, 'a');
        snapshot_read_tip(&c, 0, &cur_h, cur_hash);
        st_set(&st, last_h, last_hash);
        TEST_ASSERT(sim_classify(&st, cur_h, cur_hash, &c, NULL, 0) ==
                    LSP_REORG_NONE, "snapshot pipeline: no reorg");
        TEST_ASSERT(legacy_classify(last_h, last_hash, cur_h, cur_hash, &c) == 0,
                    "consistent pair: pre-fix logic agrees (no reorg)");
    }
    printf("    after:  snapshot read -> consistent pair -> NONE\n   ");
    return 1;
}

/* Real reorgs are still detected as before; failed reads are INCONCLUSIVE. */
int test_reorg_classify_detects_real_reorgs(void) {
    sim_chain_t c;
    lsp_reorg_state_t st;
    int lh, ch; char lhash[65], chash[65];

    /* HEIGHT_REGRESSION: tip 100 -> invalidate two blocks -> 98. */
    sim_init(&c, 100, 'a');
    snapshot_read_tip(&c, 0, &lh, lhash);
    sim_reorg(&c, 98, 98, 'b');
    snapshot_read_tip(&c, 0, &ch, chash);
    st_set(&st, lh, lhash);
    TEST_ASSERT(sim_classify(&st, ch, chash, &c, NULL, 0) ==
                LSP_REORG_HEIGHT_REGRESSION, "height regression");
    TEST_ASSERT(legacy_classify(lh, lhash, ch, chash, &c) == 1, "legacy agrees");

    /* SAME_HEIGHT: tip 100 replaced by a competing block 100'. */
    sim_init(&c, 100, 'a');
    snapshot_read_tip(&c, 0, &lh, lhash);
    sim_reorg(&c, 99, 100, 'b');
    snapshot_read_tip(&c, 0, &ch, chash);
    st_set(&st, lh, lhash);
    TEST_ASSERT(sim_classify(&st, ch, chash, &c, NULL, 0) ==
                LSP_REORG_SAME_HEIGHT, "same-height replacement");
    TEST_ASSERT(legacy_classify(lh, lhash, ch, chash, &c) == 2, "legacy agrees");

    /* FORWARD_REORG: stored 100, fork at 97 wins and is now at 103. */
    sim_init(&c, 100, 'a');
    snapshot_read_tip(&c, 0, &lh, lhash);
    sim_reorg(&c, 97, 103, 'b');
    snapshot_read_tip(&c, 0, &ch, chash);
    st_set(&st, lh, lhash);
    TEST_ASSERT(sim_classify(&st, ch, chash, &c, NULL, 0) ==
                LSP_REORG_FORWARD, "forward reorg, deep fork");
    TEST_ASSERT(legacy_classify(lh, lhash, ch, chash, &c) == 3, "legacy agrees");

    /* FORWARD_REORG: 1-block fork at the stored tip, new branch one longer. */
    sim_init(&c, 100, 'a');
    snapshot_read_tip(&c, 0, &lh, lhash);
    sim_reorg(&c, 99, 101, 'b');
    snapshot_read_tip(&c, 0, &ch, chash);
    st_set(&st, lh, lhash);
    TEST_ASSERT(sim_classify(&st, ch, chash, &c, NULL, 0) ==
                LSP_REORG_FORWARD, "forward reorg, 1-block fork + 1");
    TEST_ASSERT(legacy_classify(lh, lhash, ch, chash, &c) == 3, "legacy agrees");

    /* The next-height check does not mask a real fork. */
    sim_init(&c, 100, 'a');
    snapshot_read_tip(&c, 0, &lh, lhash);
    sim_reorg(&c, 99, 102, 'b');
    st_set(&st, lh, lhash);
    TEST_ASSERT(sim_classify(&st, 102, c.hash[102], &c, NULL, 0) ==
                LSP_REORG_FORWARD, "next-height check does not mask a fork");

    /* No reorg: normal growth, unchanged tip, first observation. */
    sim_init(&c, 100, 'a');
    snapshot_read_tip(&c, 0, &lh, lhash);
    sim_mine(&c, 'a');
    snapshot_read_tip(&c, 0, &ch, chash);
    st_set(&st, lh, lhash);
    TEST_ASSERT(sim_classify(&st, ch, chash, &c, NULL, 0) == LSP_REORG_NONE,
                "normal growth");
    TEST_ASSERT(lsp_reorg_classify(&st, lh, lhash, NULL) == LSP_REORG_NONE,
                "unchanged tip needs no reads");
    lsp_reorg_state_t empty;
    memset(&empty, 0, sizeof(empty));
    TEST_ASSERT(lsp_reorg_classify(&empty, ch, chash, NULL) == LSP_REORG_NONE,
                "first observation");

    /* INCONCLUSIVE: a read the check needs is missing. */
    TEST_ASSERT(lsp_reorg_classify(&st, -1, "", NULL) == LSP_REORG_INCONCLUSIVE,
                "failed tip read");
    lsp_reorg_view_t v = {0};
    v.tips = no_tips;
    TEST_ASSERT(lsp_reorg_classify(&st, ch, chash, &v) == LSP_REORG_INCONCLUSIVE,
                "getblockhash(last) failed");
    sim_init(&c, 100, 'a');
    snapshot_read_tip(&c, 0, &lh, lhash);
    sim_reorg(&c, 99, 103, 'b');
    st_set(&st, lh, lhash);
    v.hash_at_last = c.hash[100];
    v.hash_at_next = NULL;
    TEST_ASSERT(lsp_reorg_classify(&st, 103, c.hash[103], &v) ==
                LSP_REORG_INCONCLUSIVE, "getblockhash(last+1) failed");
    sim_init(&c, 100, 'a');
    snapshot_read_tip(&c, 0, &lh, lhash);
    sim_mine(&c, 'a');
    st_set(&st, lh, lhash);
    v.hash_at_last = c.hash[100];
    v.hash_at_next = c.hash[101];
    v.tips = NULL;
    TEST_ASSERT(lsp_reorg_classify(&st, 101, c.hash[101], &v) ==
                LSP_REORG_INCONCLUSIVE, "getchaintips failed");

    TEST_ASSERT(strcmp(lsp_reorg_kind_str(LSP_REORG_FORWARD),
                       "FORWARD_REORG") == 0, "kind str forward");
    TEST_ASSERT(strcmp(lsp_reorg_kind_str(LSP_REORG_SAME_HEIGHT),
                       "SAME_HEIGHT") == 0, "kind str same");
    TEST_ASSERT(strcmp(lsp_reorg_kind_str(LSP_REORG_HEIGHT_REGRESSION),
                       "HEIGHT_REGRESSION") == 0, "kind str regress");
    TEST_ASSERT(strcmp(lsp_reorg_kind_str(LSP_REORG_INCONCLUSIVE),
                       "INCONCLUSIVE") == 0, "kind str inconclusive");
    TEST_ASSERT(lsp_reorg_kind_str(LSP_REORG_NONE)[0] == '\0', "kind str none");
    return 1;
}

static void tip_set(regtest_chain_tip_t *t, int height, int branchlen,
                    const char *status, const char *hash) {
    memset(t, 0, sizeof(*t));
    t->height = height;
    t->branchlen = branchlen;
    snprintf(t->status, sizeof(t->status), "%s", status);
    snprintf(t->hash, sizeof(t->hash), "%s", hash);
}

/* Reorgs of blocks the detector never sampled, and no repeat reports. */
int test_reorg_classify_unseen_block_reorg(void) {
    sim_chain_t c;
    lsp_reorg_state_t st;
    int lh, ch; char lhash[65], chash[65];
    regtest_chain_tip_t tips[2];

    /* Poll sees 100.  Then a101 is mined, replaced by b101, b102. */
    sim_init(&c, 100, 'a');
    snapshot_read_tip(&c, 0, &lh, lhash);
    sim_mine(&c, 'a');                      /* a101, never sampled */
    char a101[65];
    memcpy(a101, c.hash[101], 65);
    sim_reorg(&c, 100, 102, 'b');           /* b101, b102 */
    snapshot_read_tip(&c, 0, &ch, chash);
    st_set(&st, lh, lhash);

    TEST_ASSERT(legacy_classify(lh, lhash, ch, chash, &c) == 0,
                "pre-fix logic misses it (block at 100 unchanged)");
    TEST_ASSERT(sim_classify(&st, ch, chash, &c, NULL, 0) == LSP_REORG_NONE,
                "without a stale tip there is nothing to see");

    tip_set(&tips[0], 102, 0, "active", chash);
    tip_set(&tips[1], 101, 1, "invalid", a101);
    lsp_reorg_kind_t k = sim_classify(&st, ch, chash, &c, tips, 2);
    printf("\n    unseen a101 replaced: legacy=0 (missed), with chain tips -> %s\n   ",
           lsp_reorg_kind_str(k));
    TEST_ASSERT(k == LSP_REORG_UNSEEN_BLOCK, "invalid stale tip above sample");
    snprintf(tips[1].status, sizeof(tips[1].status), "valid-fork");
    TEST_ASSERT(sim_classify(&st, ch, chash, &c, tips, 2) ==
                LSP_REORG_UNSEEN_BLOCK, "valid-fork stale tip above sample");

    /* Not reported: */
    snprintf(tips[1].status, sizeof(tips[1].status), "valid-headers");
    TEST_ASSERT(sim_classify(&st, ch, chash, &c, tips, 2) == LSP_REORG_NONE,
                "headers-only competing branch");
    snprintf(tips[1].status, sizeof(tips[1].status), "valid-fork");
    tips[1].height = 99; tips[1].branchlen = 3;
    TEST_ASSERT(sim_classify(&st, ch, chash, &c, tips, 2) == LSP_REORG_NONE,
                "stale branch that forked below the stored tip");
    tips[1].height = 101; tips[1].branchlen = 1;

    /* The race-pair path falls through to the chain-tips check. */
    lsp_reorg_state_t race;
    st_set(&race, 99, c.hash[100]);        /* (99, hash of 100) */
    TEST_ASSERT(sim_classify(&race, ch, chash, &c, NULL, 0) == LSP_REORG_NONE,
                "race pair alone: no reorg");
    TEST_ASSERT(sim_classify(&race, ch, chash, &c, tips, 2) ==
                LSP_REORG_UNSEEN_BLOCK, "race pair still sees the stale tip");

    /* After the report, the next poll does not report it again. */
    lsp_reorg_state_advance(&st, ch, chash, tips, 2);
    sim_mine(&c, 'b');
    TEST_ASSERT(sim_classify(&st, c.height, c.hash[c.height], &c, tips, 2) ==
                LSP_REORG_NONE, "no repeat after UNSEEN_BLOCK");

    /* HEIGHT_REGRESSION, then the next block: the invalidated branch is
       accounted for and not reported again as UNSEEN_BLOCK. */
    sim_init(&c, 100, 'a');
    char a100[65];
    memcpy(a100, c.hash[100], 65);
    st_set(&st, 100, a100);
    sim_reorg(&c, 99, 99, 'a');            /* a100 invalidated, tip 99 */
    tip_set(&tips[0], 99, 0, "active", c.hash[99]);
    tip_set(&tips[1], 100, 1, "invalid", a100);
    TEST_ASSERT(sim_classify(&st, 99, c.hash[99], &c, tips, 2) ==
                LSP_REORG_HEIGHT_REGRESSION, "regression reported");
    /* Without the seen set, the next block would re-report a100: */
    lsp_reorg_state_t naive;
    st_set(&naive, 99, c.hash[99]);
    sim_mine(&c, 'b');                      /* b100 */
    tip_set(&tips[0], 100, 0, "active", c.hash[100]);
    TEST_ASSERT(sim_classify(&naive, 100, c.hash[100], &c, tips, 2) ==
                LSP_REORG_UNSEEN_BLOCK, "naive state would report it twice");
    lsp_reorg_state_advance(&st, 99, c.hash[99], tips, 2);
    TEST_ASSERT(st.n_seen == 1 && strcmp(st.seen[0], a100) == 0,
                "advance records the invalidated branch");
    TEST_ASSERT(sim_classify(&st, 100, c.hash[100], &c, tips, 2) ==
                LSP_REORG_NONE, "no repeat after HEIGHT_REGRESSION");

    /* Stored tip reorged out while the height went up: FORWARD_REORG. */
    sim_init(&c, 100, 'a');
    snapshot_read_tip(&c, 0, &lh, lhash);
    sim_reorg(&c, 99, 102, 'b');
    snapshot_read_tip(&c, 0, &ch, chash);
    st_set(&st, lh, lhash);
    tip_set(&tips[1], 100, 1, "invalid", lhash);
    TEST_ASSERT(sim_classify(&st, ch, chash, &c, tips, 2) == LSP_REORG_FORWARD,
                "stored tip reorged out, height up");
    TEST_ASSERT(strcmp(lsp_reorg_kind_str(LSP_REORG_UNSEEN_BLOCK),
                       "UNSEEN_BLOCK_REORG") == 0, "kind str unseen");
    return 1;
}

/* Fork height of reported reorgs (pure). */
int test_reorg_fork_height(void) {
    lsp_reorg_state_t prev;
    regtest_chain_tip_t tips[2];
    lsp_reorg_view_t v = {0};
    char ha[65], hb[65], hc[65];
    snprintf(ha, sizeof(ha), "a%063x", 100u);
    snprintf(hb, sizeof(hb), "b%063x", 102u);
    snprintf(hc, sizeof(hc), "c%063x", 101u);
    st_set(&prev, 100, ha);

    TEST_ASSERT(lsp_reorg_fork_height(&prev, LSP_REORG_NONE, 101, NULL) == -1,
                "no reorg -> -1");
    /* Stored tip 100 is now a stale branch of length 2 (99, 100 replaced). */
    tip_set(&tips[0], 102, 0, "active", hb);
    tip_set(&tips[1], 100, 2, "valid-fork", prev.hash);
    v.tips = tips; v.n_tips = 2;
    TEST_ASSERT(lsp_reorg_fork_height(&prev, LSP_REORG_FORWARD, 102, &v) == 98,
                "exact fork from the stored tip's stale branch");
    /* Without that branch: one below the lower tip. */
    v.n_tips = 1;
    TEST_ASSERT(lsp_reorg_fork_height(&prev, LSP_REORG_FORWARD, 102, &v) == 99,
                "fallback: forward");
    TEST_ASSERT(lsp_reorg_fork_height(&prev, LSP_REORG_HEIGHT_REGRESSION, 97, NULL) == 96,
                "fallback: regression");
    /* UNSEEN_BLOCK: the reported branch's fork point. */
    tip_set(&tips[1], 101, 1, "invalid", hc);
    v.n_tips = 2;
    TEST_ASSERT(lsp_reorg_fork_height(&prev, LSP_REORG_UNSEEN_BLOCK, 102, &v) == 100,
                "unseen block: fork at the stored tip");
    return 1;
}

/* The reorg handler's sub-factory step (lsp_reorg_rollback_subfactory_chains,
   called with the detector's fork height). */
static int handler_subfactory_step(factory_t *f, int32_t fork_height) {
    return lsp_reorg_rollback_subfactory_chains(f, fork_height);
}

/* A shallow reorg must leave an advanced, off-chain sub-factory chain
   intact; only an entry observed confirmed above the fork is rolled back. */
int test_reorg_subfactory_chain_kept_on_shallow_reorg(void) {
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f, "alloc");
    factory_alloc_default_arrays(f);
    f->n_nodes = 2;
    factory_node_t *sub = &f->nodes[1];
    sub->type = NODE_PS_SUBFACTORY;
    sub->ps_chain_len = 3;
    sub->ps_n_prev_outputs = 2;
    memset(sub->ps_prev_txid, 0xAA, 32);
    unsigned char prev_txid[32];
    memset(prev_txid, 0xAA, 32);
    int ok = 1;

    /* Off-chain chain (never observed confirmed), 1-block reorg at 100. */
    int n = handler_subfactory_step(f, 100);
    printf("\n    off-chain chain[3], reorg fork 100: rolled back %d, "
           "chain_len now %d\n   ", n, sub->ps_chain_len);
    if (n != 0 || sub->ps_chain_len != 3 || sub->ps_n_prev_outputs != 2 ||
        memcmp(sub->ps_prev_txid, prev_txid, 32) != 0) ok = 0;

    /* Observed confirmed below the fork: still confirmed, kept. */
    sub->ps_chain_confirmed_height = 95;
    if (handler_subfactory_step(f, 100) != 0 || sub->ps_chain_len != 3) ok = 0;

    /* Observed confirmed above the fork: its block was disconnected. */
    sub->ps_chain_confirmed_height = 105;
    if (handler_subfactory_step(f, 100) != 1 || sub->ps_chain_len != 0 ||
        sub->ps_chain_confirmed_height != 0) ok = 0;

    f->n_nodes = 0;
    factory_free(f);
    free(f);
    TEST_ASSERT(ok, "only entries confirmed above the fork are rolled back");
    return 1;
}

/* ---- regtest: tip snapshot consistency under concurrent mining ---------- */

#define TIP_MINER_BLOCKS 300

/* Pre-fix detector logic against real RPCs (getblockcount,
   getbestblockhash, getblockhash(last_height)).  Returns its kind 0..3. */
static int legacy_detect_rpc(regtest_t *rt, int32_t last_h, const char *last_hash) {
    int height = regtest_get_block_height(rt);
    char cur[65] = {0};
    regtest_get_best_block_hash(rt, cur);
    if (last_h > 0 && height > 0 && height < last_h) return 1;
    if (last_h > 0 && height == last_h && last_hash[0] && cur[0] &&
        strcmp(cur, last_hash) != 0) return 2;
    if (last_h > 0 && height > last_h && last_hash[0]) {
        char prev[65] = {0};
        if (regtest_get_block_hash(rt, last_h, prev, sizeof(prev)) &&
            prev[0] && strcmp(prev, last_hash) != 0) return 3;
    }
    return 0;
}

static int rpc_hash_arg(regtest_t *rt, const char *method, const char *hash) {
    char p[96];
    snprintf(p, sizeof(p), "\"%s\"", hash);
    char *r = regtest_exec(rt, method, p);
    if (!r) return 0;
    free(r);
    return 1;
}

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int test_regtest_reorg_tip_snapshot_consistent(void) {
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        return 2;
    }
    regtest_create_wallet(&rt, "tip_snapshot");
    char addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, addr, sizeof(addr)), "address");

    int h0 = -1; char hash0[65];
    TEST_ASSERT(regtest_get_tip(&rt, &h0, hash0), "initial regtest_get_tip");
    int bc = regtest_get_block_height(&rt);
    char bb[65];
    TEST_ASSERT(regtest_get_best_block_hash(&rt, bb), "best hash");
    TEST_ASSERT(h0 == bc && strcmp(hash0, bb) == 0,
                "quiet chain: snapshot equals getblockcount/getbestblockhash");

    fflush(stdout);
    pid_t miner = fork();
    TEST_ASSERT(miner >= 0, "fork miner");
    if (miner == 0) {
        regtest_t mrt = rt;
        for (int i = 0; i < TIP_MINER_BLOCKS; i++)
            regtest_mine_blocks(&mrt, 1, addr);
        _exit(0);
    }

    int new_samples = 0, new_bad = 0;
    int old_samples = 0, old_bad = 0, old_false_forward = 0;
    int first_h = -1, last_h = -1;
    double t_end = now_s() + 60.0;
    int miner_done = 0;
    while (!miner_done && now_s() < t_end) {
        /* regtest_get_tip, then check it against the chain. */
        int h; char hash[65];
        if (regtest_get_tip(&rt, &h, hash)) {
            char at[65] = {0};
            if (regtest_get_block_hash(&rt, h, at, sizeof(at))) {
                new_samples++;
                if (strcmp(at, hash) != 0) new_bad++;
                if (first_h < 0) first_h = h;
                last_h = h;
            }
        }
        /* Two-call read for comparison (reported, not asserted). */
        int oh = regtest_get_block_height(&rt);
        char ohash[65] = {0};
        if (oh > 0 && regtest_get_best_block_hash(&rt, ohash)) {
            char at[65] = {0};
            if (regtest_get_block_hash(&rt, oh, at, sizeof(at))) {
                old_samples++;
                if (strcmp(at, ohash) != 0) {
                    old_bad++;
                    if (legacy_detect_rpc(&rt, oh, ohash) == 3)
                        old_false_forward++;
                }
            }
        }
        int st;
        if (waitpid(miner, &st, WNOHANG) == miner) miner_done = 1;
    }
    if (!miner_done) { kill(miner, SIGKILL); waitpid(miner, NULL, 0); }

    printf("\n    heights %d..%d while sampling\n", first_h, last_h);
    printf("    regtest_get_tip:            %d samples, %d inconsistent\n",
           new_samples, new_bad);
    printf("    getblockcount+getbestblock: %d samples, %d inconsistent, "
           "%d would be reported as FORWARD_REORG by the pre-fix check\n   ",
           old_samples, old_bad, old_false_forward);

    TEST_ASSERT(last_h - first_h >= 50, "tip advanced during sampling");
    TEST_ASSERT(new_samples >= 30, "enough snapshot samples");
    TEST_ASSERT(new_bad == 0, "every regtest_get_tip pair is consistent");
    return 1;
}

/* ---- regtest: reorgs around the detector's polls ------------------------ */

/* Three reorgs, one lsp_reorg_poll() each:
     1. a block mined after the last poll is invalidated and replaced by two
        (the detector never sampled it)   -> UNSEEN_BLOCK_REORG, once;
     2. the sampled tip is invalidated, 2 mined          -> FORWARD_REORG;
     3. the sampled tip is invalidated (tip goes back)   -> HEIGHT_REGRESSION,
        and the next blocks are not reported again as UNSEEN_BLOCK.
   Every invalidated block is reconsidered at the end. */
int test_regtest_reorg_unseen_tip_block_detected(void) {
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        return 2;
    }
    regtest_create_wallet(&rt, "unseen_reorg");
    char a1[128], a2[128];
    TEST_ASSERT(regtest_get_new_address(&rt, a1, sizeof(a1)), "address 1");
    TEST_ASSERT(regtest_get_new_address(&rt, a2, sizeof(a2)), "address 2");
    TEST_ASSERT(regtest_mine_blocks(&rt, 2, a1), "mine");

    lsp_reorg_state_t st;
    memset(&st, 0, sizeof(st));
    int32_t h; char hash[65];
    char invalidated[3][65];
    lsp_reorg_kind_t k;

    TEST_ASSERT(lsp_reorg_poll(&rt, &st, &h, hash) == LSP_REORG_NONE, "poll 0");

    /* 1. Unsampled block replaced. */
    int32_t last_h = st.height; char last_hash[65];
    memcpy(last_hash, st.hash, 65);
    TEST_ASSERT(regtest_mine_blocks(&rt, 1, a1), "mine H+1");
    TEST_ASSERT(regtest_get_best_block_hash(&rt, invalidated[0]), "H+1 hash");
    TEST_ASSERT(rpc_hash_arg(&rt, "invalidateblock", invalidated[0]), "invalidate H+1");
    TEST_ASSERT(regtest_mine_blocks(&rt, 2, a2), "mine 2 replacement blocks");
    int legacy = legacy_detect_rpc(&rt, last_h, last_hash);
    k = lsp_reorg_poll(&rt, &st, &h, hash);
    printf("\n    unsampled H+1=%.16s replaced, tip %d -> %d: legacy kind=%d%s, "
           "fixed -> %s\n", invalidated[0], last_h, h, legacy,
           legacy ? "" : " (missed)", lsp_reorg_kind_str(k));
    TEST_ASSERT(h == last_h + 2, "tip is H+2");
    TEST_ASSERT(legacy == 0, "pre-fix detector logic misses this reorg");
    TEST_ASSERT(k == LSP_REORG_UNSEEN_BLOCK, "reported as UNSEEN_BLOCK_REORG");
    TEST_ASSERT(regtest_mine_blocks(&rt, 1, a1), "mine one more");
    TEST_ASSERT(lsp_reorg_poll(&rt, &st, &h, hash) == LSP_REORG_NONE,
                "not reported again on the next poll");

    /* 2. Sampled tip invalidated, 2 mined. */
    last_h = st.height; memcpy(last_hash, st.hash, 65);
    memcpy(invalidated[1], st.hash, 65);
    TEST_ASSERT(rpc_hash_arg(&rt, "invalidateblock", invalidated[1]), "invalidate tip");
    TEST_ASSERT(regtest_mine_blocks(&rt, 2, a2), "mine 2");
    legacy = legacy_detect_rpc(&rt, last_h, last_hash);
    k = lsp_reorg_poll(&rt, &st, &h, hash);
    printf("    sampled tip %d invalidated, 2 mined: legacy kind=%d, fixed -> %s\n",
           last_h, legacy, lsp_reorg_kind_str(k));
    TEST_ASSERT(legacy == 3, "pre-fix logic sees a reorg of the sampled tip");
    TEST_ASSERT(k == LSP_REORG_FORWARD, "FORWARD_REORG");

    /* 3. Sampled tip invalidated, tip goes back; then one new block. */
    memcpy(invalidated[2], st.hash, 65);
    TEST_ASSERT(rpc_hash_arg(&rt, "invalidateblock", invalidated[2]), "invalidate tip");
    k = lsp_reorg_poll(&rt, &st, &h, hash);
    TEST_ASSERT(k == LSP_REORG_HEIGHT_REGRESSION, "HEIGHT_REGRESSION");
    /* Two blocks, so the branch is longer than the invalidated one and the
       reconsiderblock below cannot switch back on an equal-work tie.  Paid
       to a1: the invalidated tip paid a2, and a block mined in the same
       second to the same address would be that same (invalid) block. */
    TEST_ASSERT(regtest_mine_blocks(&rt, 2, a1), "mine replacements");
    k = lsp_reorg_poll(&rt, &st, &h, hash);
    printf("    tip invalidated -> HEIGHT_REGRESSION; next blocks -> %s\n",
           k == LSP_REORG_NONE ? "NONE (not re-reported)" : lsp_reorg_kind_str(k));
    TEST_ASSERT(k == LSP_REORG_NONE, "invalidated branch not re-reported");

    /* Put the invalidated blocks back.  Each lost on work / first-seen, so
       the active chain stays and nothing is reported. */
    for (int i = 0; i < 3; i++)
        TEST_ASSERT(rpc_hash_arg(&rt, "reconsiderblock", invalidated[i]),
                    "reconsiderblock");
    char tip_after[65];
    TEST_ASSERT(regtest_get_best_block_hash(&rt, tip_after), "tip after");
    TEST_ASSERT(strcmp(tip_after, st.hash) == 0, "active chain unchanged");
    TEST_ASSERT(lsp_reorg_poll(&rt, &st, &h, hash) == LSP_REORG_NONE,
                "nothing reported after reconsiderblock");
    printf("   ");
    return 1;
}
