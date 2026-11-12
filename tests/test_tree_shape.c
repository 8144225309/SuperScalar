/* Tree-shape regression tests: pinned tree txids for representative shapes,
   DW layer count of deep trees, leaves inside the static levels, early-warning
   time against the built transactions, CPFP anchor room, leaf kind on
   mixed-arity levels, client L-stock mirror on large trees, placement order
   and the per-level arity list bound. */
#if defined(__linux__)
#define _GNU_SOURCE
#endif
#include "superscalar/factory.h"
#include "superscalar/channel.h"
#include "superscalar/dw_state.h"
#include "superscalar/tx_builder.h"
#include "superscalar/sha256.h"
#include <secp256k1_schnorrsig.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__GLIBC__)
#include <dlfcn.h>
#endif

extern void hex_encode(const unsigned char *data, size_t len, char *out);

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define TEST_ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { \
        printf("  FAIL: %s (line %d): %s (got %ld, expected %ld)\n", \
               __func__, __LINE__, msg, (long)(a), (long)(b)); \
        return 0; \
    } \
} while(0)

#define TS_STEP   144
#define TS_STATES 4
#define TS_LOCK   ((uint32_t)TS_STEP * (TS_STATES - 1))   /* 432 blocks */

/* A test qsort that reverses its input before sorting, so equal elements come
   out in the opposite order to the stable glibc sort.  Off except inside
   test_tree_shape_placement_order. */
#if defined(__GLIBC__)
static int g_ts_qsort_reverse = 0;
typedef void (*ts_qsort_fn)(void *, size_t, size_t,
                            int (*)(const void *, const void *));
void qsort(void *base, size_t n, size_t size,
           int (*cmp)(const void *, const void *)) {
    static ts_qsort_fn real = NULL;
    if (!real) {
        void *sym = dlsym(RTLD_NEXT, "qsort");
        memcpy(&real, &sym, sizeof(real));
    }
    if (g_ts_qsort_reverse && size <= 64 && n > 1) {
        unsigned char tmp[64];
        unsigned char *b = base;
        for (size_t i = 0, j = n - 1; i < j; i++, j--) {
            memcpy(tmp, b + i * size, size);
            memcpy(b + i * size, b + j * size, size);
            memcpy(b + j * size, tmp, size);
        }
    }
    real(base, n, size, cmp);
}
#endif

typedef struct {
    const char *name;
    size_t n_clients;
    uint8_t arities[FACTORY_MAX_LEVELS];  /* one entry = uniform arity */
    size_t n_arities;                     /* 0 = leave factory_init's default */
    uint32_t static_thr;
    int anchor;
    uint32_t cltv;
    uint32_t ps_k;
    int tz_profiles;   /* timezone buckets i % 3, equal uptime: ties inside a bucket */
} ts_shape_t;

static secp256k1_context *ts_ctx(void) {
    return secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

/* Deterministic keypairs: seckey i = SHA256("tree-shape-key" || i). */
static secp256k1_keypair *ts_keys(secp256k1_context *ctx, size_t n) {
    secp256k1_keypair *kps = calloc(n, sizeof(*kps));
    if (!kps) return NULL;
    for (size_t i = 0; i < n; i++) {
        unsigned char buf[18], sk[32];
        memcpy(buf, "tree-shape-key", 14);
        buf[14] = (unsigned char)(i >> 24); buf[15] = (unsigned char)(i >> 16);
        buf[16] = (unsigned char)(i >> 8);  buf[17] = (unsigned char)i;
        sha256(buf, sizeof(buf), sk);
        if (!secp256k1_keypair_create(ctx, &kps[i], sk)) { free(kps); return NULL; }
    }
    return kps;
}

/* Funding script for a factory of these participants (default placement,
   no profiles): what factory_compute_funding_spk gives once they are in a
   factory.  For tests that hand keys to a constructor (ladder, LSP). */
int test_funding_spk_from_pubkeys(secp256k1_context *ctx, const secp256k1_pubkey *pks,
                                  size_t n, unsigned char spk[34]) {
    factory_t *f = calloc(1, sizeof(*f));
    if (!f) return 0;
    factory_init_from_pubkeys(f, ctx, pks, n, 10, 4);
    int ok = factory_compute_funding_spk(f, spk);
    factory_free(f);
    free(f);
    return ok;
}

int test_funding_spk_from_keys(secp256k1_context *ctx, const secp256k1_keypair *lsp_kp,
                               const secp256k1_keypair *client_kps, size_t n_clients,
                               unsigned char spk[34]) {
    secp256k1_pubkey *pks = calloc(n_clients + 1, sizeof(*pks));
    if (!pks) return 0;
    int ok = secp256k1_keypair_pub(ctx, &pks[0], lsp_kp);
    for (size_t i = 0; ok && i < n_clients; i++)
        ok = secp256k1_keypair_pub(ctx, &pks[i + 1], &client_kps[i]);
    ok = ok && test_funding_spk_from_pubkeys(ctx, pks, n_clients + 1, spk);
    free(pks);
    return ok;
}

/* Initialize and shape a factory (no build).  Returns 0 on setup failure. */
static int ts_setup(factory_t *f, secp256k1_context *ctx, const secp256k1_keypair *kps,
                    const ts_shape_t *s) {
    size_t np = s->n_clients + 1;
    if (!factory_init(f, ctx, kps, np, TS_STEP, TS_STATES)) return 0;
    if (s->n_arities == 1)
        factory_set_arity(f, (factory_arity_t)s->arities[0]);
    else if (s->n_arities > 1 && !factory_set_level_arity(f, s->arities, s->n_arities))
        return 0;
    if (s->ps_k > 1) factory_set_ps_subfactory_arity(f, s->ps_k);
    if (s->static_thr) factory_set_static_near_root(f, s->static_thr);
    f->use_tree_anchor = s->anchor;
    f->cltv_timeout = s->cltv;
    if (s->tz_profiles) {
        for (size_t i = 1; i < np; i++) {
            f->profiles[i].timezone_bucket = (uint8_t)(i % 3);
            f->profiles[i].uptime_score = 0.5f;
        }
    }
    unsigned char txid[32], spk[34];
    memset(txid, 0xAA, 32);
    if (!factory_compute_funding_spk(f, spk)) return 0;
    return factory_set_funding(f, txid, 0, (uint64_t)s->n_clients * 200000 + 1000000, spk, 34);
}

typedef struct {
    secp256k1_context *ctx;
    secp256k1_keypair *kps;
    factory_t *f;
    int built;
} ts_tree_t;

/* Set up a shape and, if `build`, build it (t->built says whether
   factory_build_tree passed). */
static int ts_open_b(ts_tree_t *t, const ts_shape_t *s, int build) {
    memset(t, 0, sizeof(*t));
    t->ctx = ts_ctx();
    t->kps = ts_keys(t->ctx, s->n_clients + 1);
    t->f = calloc(1, sizeof(factory_t));
    if (!t->kps || !t->f || !ts_setup(t->f, t->ctx, t->kps, s)) return 0;
    t->built = build ? factory_build_tree(t->f) : 0;
    return 1;
}

static int ts_open(ts_tree_t *t, const ts_shape_t *s) { return ts_open_b(t, s, 1); }

static void ts_close(ts_tree_t *t) {
    if (t->f) { factory_free(t->f); free(t->f); }
    free(t->kps);
    if (t->ctx) secp256k1_context_destroy(t->ctx);
    memset(t, 0, sizeof(*t));
}

/* SHA256 over n_nodes (4 bytes LE) || every node txid, as hex. */
static void ts_digest(const factory_t *f, char hex_out[65]) {
    size_t len = 4 + 32 * f->n_nodes;
    unsigned char *buf = malloc(len), d[32];
    if (!buf) { hex_out[0] = '\0'; return; }
    buf[0] = (unsigned char)f->n_nodes; buf[1] = (unsigned char)(f->n_nodes >> 8);
    buf[2] = (unsigned char)(f->n_nodes >> 16); buf[3] = (unsigned char)(f->n_nodes >> 24);
    for (size_t i = 0; i < f->n_nodes; i++)
        memcpy(buf + 4 + 32 * i, f->nodes[i].txid, 32);
    sha256(buf, len, d);
    free(buf);
    hex_encode(d, 32, hex_out);
}

/* Build a shape and return its digest; 0 if the build failed. */
static int ts_build_digest(const ts_shape_t *s, char hex_out[65]) {
    ts_tree_t t;
    int ok = ts_open(&t, s) && t.built;
    if (ok) ts_digest(t.f, hex_out);
    ts_close(&t);
    return ok;
}

/* Relative lock (blocks) of a node's tx, read from the serialized unsigned
   tx's single input: version(4) | n_in(1) | txid(32) | vout(4) | script(1) |
   nSequence(4).  -1 if the bytes are not that, or the lock is time-based. */
static long ts_tx_relative_lock(const factory_node_t *node) {
    const tx_buf_t *tx = &node->unsigned_tx;
    if (tx->len < 46 || tx->data[4] != 1 || tx->data[41] != 0) return -1;
    uint32_t seq = (uint32_t)tx->data[42] | ((uint32_t)tx->data[43] << 8) |
                   ((uint32_t)tx->data[44] << 16) | ((uint32_t)tx->data[45] << 24);
    if (seq != node->nsequence) return -1;
    if (seq & (1u << 31)) return 0;          /* BIP-68 disabled */
    if (seq & (1u << 22)) return -1;         /* time-based: not used by the tree */
    return (long)(seq & 0xFFFFu);
}

/* Largest sum of tx relative locks over all root-to-node paths. */
static long ts_tx_path_max(const factory_t *f) {
    long best = 0;
    for (size_t i = 0; i < f->n_nodes; i++) {
        long sum = 0;
        for (int j = (int)i; j >= 0; j = f->nodes[j].parent_index) {
            long l = ts_tx_relative_lock(&f->nodes[j]);
            if (l < 0) return -1;
            sum += l;
        }
        if (sum > best) best = sum;
    }
    return best;
}

static uint32_t ts_shape_ewt(const ts_shape_t *s) {
    const uint8_t *la = s->n_arities > 1 ? s->arities : NULL;
    factory_arity_t leaf = s->n_arities == 1 ? (factory_arity_t)s->arities[0]
                         : s->n_arities > 1 ? (factory_arity_t)s->arities[s->n_arities - 1]
                         : FACTORY_ARITY_2;
    return factory_compute_ewt_for_shape(la, s->n_arities > 1 ? s->n_arities : 0, leaf,
                                         s->ps_k, s->n_clients, s->static_thr, TS_STEP, TS_STATES);
}

/* ---- Pinned tree txids ---- */

/* Shapes valid and correct before the tree-shape fixes, with the digest of
   their tree txids computed on the parent commit.  Any change here changes a
   pre-signed tree. */
static const struct { ts_shape_t s; const char *digest; } ts_pinned[] = {
    { { "N=4 arity 2", 4, {2}, 1, 0, 0, 0, 0, 0 },
      "7e71097b7f9c82214a54e4320ca437ede0e18ebc20c030b7574e33c4734011ca" },
    { { "N=4 arity 2 anchors cltv", 4, {2}, 1, 0, 1, 1000, 0, 0 },
      "21827ef8c63d382504344cb5fe8bd19ec46bd5e6902b6e182bade0cb4b886f07" },
    { { "N=4 arity 1", 4, {1}, 1, 0, 0, 0, 0, 0 },
      "5de4bda50947eff1f2b8ffd7edd3fe154fdb8ad6a4ada71f6fa2e30e143ea433" },
    { { "N=16 PS", 16, {3}, 1, 0, 0, 0, 0, 0 },
      "31d37e9c569b53cdefd98b40d741e1b5dd68cf298fc6d8ebc48f7c5bd1bb0ad0" },
    { { "N=16 PS anchors cltv", 16, {3}, 1, 0, 1, 1000, 0, 0 },
      "9207fd44692b9a924868674384739074758bec06724699e74397b97d03623fbb" },
    { { "N=8 PS k=2", 8, {3}, 1, 0, 1, 1000, 2, 0 },
      "47462529fe4b39bc117d6230c42a68fbb71a4abe820688c3567d63f6a44265c0" },
    { { "N=64 8,7,3 static 2", 64, {8, 7, 3}, 3, 2, 0, 0, 0, 0 },
      "6f54cb8326268a07f160f092b131fe8d2a9d597e29be5c87f0e80279dfdf2a37" },
    { { "N=64 8,7,3 static 2 anchors", 64, {8, 7, 3}, 3, 2, 1, 1000, 0, 0 },
      "6f986a0677ffd1abd6f56c484f46fd3c8cac40a4bdaa537f8fddc2a135f13f99" },
    { { "N=128 2,4,8 static 2", 128, {2, 4, 8}, 3, 2, 0, 0, 0, 0 },
      "c91ceae6be824903b7af299914d5044e570407a1ed393a7cef7d4928b3c903ec" },
    { { "N=7 3,4 static 1", 7, {3, 4}, 2, 1, 1, 1000, 0, 0 },
      "9f4d4a47d85998de1939982483234b74be9cc4ac31b48da02bdb6419d37c8150" },
    { { "N=12 2,4 static 1", 12, {2, 4}, 2, 1, 0, 0, 0, 0 },
      "402d433582f149a93a4e33d60f5b76d07a9a794ae0bde46bf22a3ac898871a34" },
    { { "N=12 timezone ties", 12, {2}, 1, 0, 0, 0, 0, 1 },
      "97bcf891efa4e86590ae2209f9ded01d0b342e779666cdf68dbe25f2c11feb07" },
    { { "N=257 factory_init default", 257, {0}, 0, 0, 0, 0, 0, 0 },
      "9f0c10facc67acfdf79d750237770266362a74bd701add5b589a1d60a4162127" },
    { { "N=300 PS", 300, {3}, 1, 0, 1, 1000, 0, 0 },
      "0db45178004e1291dfe6afdeb67267ce489173768df5fd503ccbd8fb0d9eddbc" },
    { { "N=300 arity 2", 300, {2}, 1, 0, 1, 1000, 0, 0 },
      "b9c53205b2dc3790b03a2c679cce748a33b8006785c616c2660bbba85eaea01e" },
};

int test_tree_shape_txids_pinned(void) {
    int bad = 0;
    for (size_t i = 0; i < sizeof(ts_pinned) / sizeof(ts_pinned[0]); i++) {
        char hex[65];
        if (!ts_build_digest(&ts_pinned[i].s, hex)) {
            printf("\n    %s: build failed", ts_pinned[i].s.name);
            bad++;
            continue;
        }
        if (strcmp(hex, ts_pinned[i].digest) != 0) {
            printf("\n    %s: digest %s", ts_pinned[i].s.name, hex);
            bad++;
        }
    }
    if (bad) printf("\n");
    TEST_ASSERT_EQ(bad, 0, "pinned tree txids");
    return 1;
}

/* ---- DW layer count of deep trees ---- */

/* factory_init / factory_init_from_pubkeys size the DW counter for the
   default arity-2 tree.  From 257 clients that tree has 9 DW depths; the
   counter holds DW_MAX_LAYERS, the deepest depths share the innermost layer,
   and nothing past layers[DW_MAX_LAYERS - 1] is written. */
int test_tree_shape_dw_layers_deep(void) {
    static const size_t ns[] = { 256, 257, 512, 1000 };
    secp256k1_context *ctx = ts_ctx();
    secp256k1_keypair *kps = ts_keys(ctx, 1001);
    TEST_ASSERT(kps, "keys");
    secp256k1_pubkey *pks = calloc(1001, sizeof(*pks));
    TEST_ASSERT(pks, "pubkeys");
    for (size_t i = 0; i < 1001; i++)
        TEST_ASSERT(secp256k1_keypair_pub(ctx, &pks[i], &kps[i]), "pub");
    for (size_t k = 0; k < sizeof(ns) / sizeof(ns[0]); k++) {
        for (int from_pubkeys = 0; from_pubkeys < 2; from_pubkeys++) {
            factory_t *f = calloc(1, sizeof(*f));
            TEST_ASSERT(f, "alloc");
            if (from_pubkeys)
                factory_init_from_pubkeys(f, ctx, pks, ns[k] + 1, TS_STEP, TS_STATES);
            else
                TEST_ASSERT(factory_init(f, ctx, kps, ns[k] + 1, TS_STEP, TS_STATES), "init");
            /* arity-2 leaves = ceil(n/2); depth = ceil(log2(leaves)) */
            size_t leaves = (ns[k] + 1) / 2;
            uint32_t depth = 0;
            for (size_t v = leaves - 1; v > 0; v >>= 1) depth++;
            uint32_t want = depth + 1 < DW_MAX_LAYERS ? depth + 1 : DW_MAX_LAYERS;
            TEST_ASSERT_EQ(f->counter.n_layers, want, "counter layers");
            uint32_t total = 1;
            for (uint32_t i = 0; i < want; i++) total *= TS_STATES;
            TEST_ASSERT_EQ(f->counter.total_states, total, "counter total states");
            TEST_ASSERT_EQ(f->counter.current_epoch, 0, "counter epoch");
            factory_free(f);
            free(f);
        }
    }
    free(pks);
    free(kps);
    secp256k1_context_destroy(ctx);

    /* dw_counter_init refuses a layer count the counter cannot hold. */
    dw_counter_t c, before;
    memset(&c, 0x5C, sizeof(c));
    before = c;
    TEST_ASSERT(!dw_counter_init(&c, DW_MAX_LAYERS + 1, TS_STEP, TS_STATES), "9 layers refused");
    TEST_ASSERT(memcmp(&c, &before, sizeof(c)) == 0, "counter unchanged");
    TEST_ASSERT(!dw_counter_init(&c, 0, TS_STEP, TS_STATES), "0 layers refused");
    TEST_ASSERT(dw_counter_init(&c, DW_MAX_LAYERS, TS_STEP, TS_STATES), "8 layers");
    TEST_ASSERT_EQ(c.n_layers, DW_MAX_LAYERS, "8 layers set");
    return 1;
}

/* ---- Leaves inside the static levels ---- */

/* A subtree that is a leaf at a static depth is a kickoff/state pair; its
   state counts down on DW layer 0 (it read layers[-1] before). */
int test_tree_shape_static_leaf(void) {
    static const ts_shape_t shapes[] = {
        { "N=2 arity 2 static 1", 2, {2}, 1, 1, 1, 1000, 0, 0 },
        { "N=4 2,4,8 static 2", 4, {2, 4, 8}, 3, 2, 0, 0, 0, 0 },
        { "N=4 arity 2 static 2", 4, {2}, 1, 2, 1, 1000, 0, 0 },
    };
    for (size_t k = 0; k < sizeof(shapes) / sizeof(shapes[0]); k++) {
        ts_tree_t t;
        TEST_ASSERT(ts_open(&t, &shapes[k]) && t.built, shapes[k].name);
        factory_t *f = t.f;
        int static_leaves = 0;
        for (int i = 0; i < f->n_leaf_nodes; i++) {
            const factory_node_t *leaf = &f->nodes[f->leaf_node_indices[i]];
            const factory_node_t *ko = &f->nodes[leaf->parent_index];
            int depth = 0;
            for (int j = ko->parent_index; j >= 0; j = f->nodes[j].parent_index)
                if (f->nodes[j].type == NODE_KICKOFF) depth++;
            if (depth >= (int)shapes[k].static_thr) continue;
            static_leaves++;
            TEST_ASSERT(!leaf->is_ps_leaf, "DW leaf");
            TEST_ASSERT_EQ(leaf->dw_layer_index, 0, "static-depth leaf on layer 0");
            TEST_ASSERT_EQ(leaf->nsequence, TS_LOCK, "static-depth leaf nSequence");
        }
        TEST_ASSERT(static_leaves > 0, "shape has leaves inside the static depths");
        long tx_max = ts_tx_path_max(f);
        TEST_ASSERT(tx_max > 0, "tx path max");
        TEST_ASSERT_EQ(factory_early_warning_time(f), tx_max, "ewt vs txs");
        TEST_ASSERT_EQ(ts_shape_ewt(&shapes[k]), tx_max, "shape ewt vs txs");
        ts_close(&t);
    }
    return 1;
}

/* ---- Early-warning time vs the built transactions ---- */

int test_tree_shape_ewt_matches_tx(void) {
    static const struct { ts_shape_t s; uint32_t ewt; } cases[] = {
        /* two-way PS: 8, 9, 10 timed levels beyond the 8-layer counter */
        { { "N=255 PS", 255, {3}, 1, 0, 0, 0, 0, 0 }, 8 * TS_LOCK },
        { { "N=512 PS", 512, {3}, 1, 0, 0, 0, 0, 0 }, 9 * TS_LOCK },
        { { "N=1000 PS", 1000, {3}, 1, 0, 0, 0, 0, 0 }, 10 * TS_LOCK },
        { { "N=16 PS", 16, {3}, 1, 0, 0, 0, 0, 0 }, 4 * TS_LOCK },
        { { "N=300 arity 2", 300, {2}, 1, 0, 1, 1000, 0, 0 }, 9 * TS_LOCK },
        { { "N=4 arity 1", 4, {1}, 1, 0, 0, 0, 0, 0 }, 3 * TS_LOCK },
        { { "N=64 8,7,3 static 2", 64, {8, 7, 3}, 3, 2, 0, 0, 0, 0 }, 1 * TS_LOCK },
        { { "N=128 2,4,8 static 2", 128, {2, 4, 8}, 3, 2, 0, 0, 0, 0 }, 2 * TS_LOCK },
        { { "N=12 2,4 static 1", 12, {2, 4}, 2, 1, 0, 0, 0, 0 }, 2 * TS_LOCK },
        { { "N=256 16,16,3", 256, {16, 16, 3}, 3, 0, 0, 0, 0, 0 }, 2 * TS_LOCK },
        { { "N=1000 15,8,3 static 1", 1000, {15, 8, 3}, 3, 1, 1, 1000, 0, 0 }, 5 * TS_LOCK },
    };
    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        const ts_shape_t *s = &cases[k].s;
        ts_tree_t t;
        TEST_ASSERT(ts_open(&t, s) && t.built, s->name);
        long tx_max = ts_tx_path_max(t.f);
        uint32_t ewt = factory_early_warning_time(t.f);
        uint32_t shape = ts_shape_ewt(s);
        if (tx_max != (long)cases[k].ewt || ewt != cases[k].ewt || shape != cases[k].ewt)
            printf("\n    %s: txs %ld ewt %u shape %u expected %u\n",
                   s->name, tx_max, ewt, shape, cases[k].ewt);
        TEST_ASSERT_EQ(tx_max, cases[k].ewt, "tx path max");
        TEST_ASSERT_EQ(ewt, tx_max, "factory_early_warning_time");
        TEST_ASSERT_EQ(shape, tx_max, "factory_compute_ewt_for_shape");
        ts_close(&t);
    }
    return 1;
}

/* ---- CPFP anchor room ---- */

static int ts_has_anchor(const factory_node_t *n) {
    return n->n_outputs > 0 &&
           n->outputs[n->n_outputs - 1].script_pubkey_len == P2A_SPK_LEN &&
           memcmp(n->outputs[n->n_outputs - 1].script_pubkey, P2A_SPK, P2A_SPK_LEN) == 0;
}

/* With anchors on, a fan-out node reserves the anchor amount out of its
   input, so it needs an output slot for it: 16 children are refused, 15
   build, and every kickoff and fan-out node carries the anchor it paid for. */
int test_tree_shape_anchor_room(void) {
    ts_shape_t s16 = { "N=32 16,2 anchors", 32, {16, 2}, 2, 0, 1, 1000, 0, 0 };
    ts_tree_t t;
    TEST_ASSERT(ts_open(&t, &s16), "setup 16");
    TEST_ASSERT(!t.built, "16 children + anchor refused");
    ts_close(&t);

    s16.anchor = 0;
    TEST_ASSERT(ts_open(&t, &s16) && t.built, "16 children without anchors");
    TEST_ASSERT_EQ(t.f->nodes[1].n_outputs, 16, "root state 16 outputs");
    ts_close(&t);

    ts_shape_t s15 = { "N=30 15,2 anchors", 30, {15, 2}, 2, 0, 1, 1000, 0, 0 };
    TEST_ASSERT(ts_open(&t, &s15) && t.built, "15 children + anchor");
    factory_t *f = t.f;
    TEST_ASSERT_EQ(f->nodes[1].n_outputs, 16, "root state 15 + anchor");
    for (size_t i = 0; i < f->n_nodes; i++) {
        const factory_node_t *n = &f->nodes[i];
        int fanout = n->type == NODE_KICKOFF ||
                     (n->type == NODE_STATE && n->n_children > 0);
        if (fanout) TEST_ASSERT(ts_has_anchor(n), "kickoff / fan-out node has its anchor");
    }
    ts_close(&t);
    return 1;
}

/* ---- Leaf kind on mixed-arity levels ---- */

static int ts_count_ps_leaves(const factory_t *f) {
    int n = 0;
    for (int i = 0; i < f->n_leaf_nodes; i++)
        if (f->nodes[f->leaf_node_indices[i]].is_ps_leaf) n++;
    return n;
}

/* Leaves are always of the kind of the last arity entry. */
int test_tree_shape_leaf_kind(void) {
    /* PS leaves under wide DW levels: a 16-way level meeting 16 clients fans
       out to 16 PS leaves (was one 16-client DW leaf, which did not fit). */
    ts_shape_t a = { "N=256 16,16,3", 256, {16, 16, 3}, 3, 0, 0, 0, 0, 0 };
    ts_tree_t t;
    TEST_ASSERT(ts_open(&t, &a) && t.built, a.name);
    TEST_ASSERT_EQ(t.f->n_leaf_nodes, 256, "256 leaves");
    TEST_ASSERT_EQ(ts_count_ps_leaves(t.f), 256, "all PS");
    ts_close(&t);

    /* 5 clients under an 8-way root: 5 PS leaves (was one 5-client DW leaf). */
    ts_shape_t b = { "N=5 8,3", 5, {8, 3}, 2, 0, 1, 1000, 0, 0 };
    TEST_ASSERT(ts_open(&t, &b) && t.built, b.name);
    TEST_ASSERT_EQ(t.f->n_leaf_nodes, 5, "5 leaves");
    TEST_ASSERT_EQ(ts_count_ps_leaves(t.f), 5, "all PS");
    ts_close(&t);

    /* k=2 PS leaves under a 16-way root: a subtree of k^2 clients is one PS
       leaf (was a 4-client DW leaf). */
    ts_shape_t c = { "N=64 16,3 k=2", 64, {16, 3}, 2, 0, 0, 0, 2, 0 };
    TEST_ASSERT(ts_open(&t, &c) && t.built, c.name);
    TEST_ASSERT_EQ(t.f->n_leaf_nodes, 16, "16 leaves");
    TEST_ASSERT_EQ(ts_count_ps_leaves(t.f), t.f->n_leaf_nodes, "all PS");
    ts_close(&t);

    /* DW leaves under a PS binary level: one client is a DW leaf, not PS. */
    ts_shape_t d = { "N=1 3,4", 1, {3, 4}, 2, 0, 0, 0, 0, 0 };
    TEST_ASSERT(ts_open(&t, &d) && t.built, d.name);
    TEST_ASSERT_EQ(t.f->n_leaf_nodes, 1, "1 leaf");
    TEST_ASSERT_EQ(ts_count_ps_leaves(t.f), 0, "DW leaf");
    ts_close(&t);

    /* DW leaves under a PS level with k=2: 4 clients fit one k^2 PS leaf and
       one 4-way DW leaf; the leaf is DW (was a k^2 PS leaf). */
    ts_shape_t d2 = { "N=4 3,4 k=2", 4, {3, 4}, 2, 0, 0, 0, 2, 0 };
    TEST_ASSERT(ts_open(&t, &d2) && t.built, d2.name);
    TEST_ASSERT_EQ(t.f->n_leaf_nodes, 1, "1 leaf");
    TEST_ASSERT_EQ(ts_count_ps_leaves(t.f), 0, "DW leaf");
    TEST_ASSERT_EQ(t.f->nodes[t.f->leaf_node_indices[0]].n_outputs, 5, "4 channels + L-stock");
    ts_close(&t);

    /* Same kind: a 7-way DW level still takes up to 7 clients as one leaf
       above 4-way leaves. */
    ts_shape_t e = { "N=7 7,4", 7, {7, 4}, 2, 0, 0, 0, 0, 0 };
    TEST_ASSERT(ts_open(&t, &e) && t.built, e.name);
    TEST_ASSERT_EQ(t.f->n_leaf_nodes, 1, "one 7-client leaf");
    TEST_ASSERT_EQ(t.f->nodes[t.f->leaf_node_indices[0]].n_outputs, 8, "7 channels + L-stock");
    ts_close(&t);
    return 1;
}

/* ---- Client L-stock mirror on large trees ---- */

/* A host-supplied leaf hash is used for every node index of the (dynamic)
   node array, including indices >= 512. */
int test_tree_shape_mirror_hash_high_index(void) {
    ts_shape_t s = { "N=300 arity 2", 300, {2}, 1, 0, 1, 1000, 0, 0 };
    ts_tree_t t;
    TEST_ASSERT(ts_open(&t, &s) && t.built, "probe build");
    size_t lo = SIZE_MAX, hi = SIZE_MAX;
    for (int i = 0; i < t.f->n_leaf_nodes; i++) {
        size_t idx = t.f->leaf_node_indices[i];
        if (idx < 512 && lo == SIZE_MAX) lo = idx;
        if (idx >= 512) hi = idx;
    }
    ts_close(&t);
    TEST_ASSERT(lo != SIZE_MAX && hi != SIZE_MAX, "leaves on both sides of 512");

    unsigned char h_lo[32], h_hi[32];
    memset(h_lo, 0x11, 32);
    memset(h_hi, 0x22, 32);
    memset(&t, 0, sizeof(t));
    t.ctx = ts_ctx();
    t.kps = ts_keys(t.ctx, s.n_clients + 1);
    t.f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(t.kps && t.f && ts_setup(t.f, t.ctx, t.kps, &s), "setup");
    factory_set_node_l_stock_hash(t.f, lo, h_lo);
    factory_set_node_l_stock_hash(t.f, hi, h_hi);
    TEST_ASSERT(factory_build_tree(t.f), "build with mirror hashes");
    TEST_ASSERT(t.f->nodes[lo].has_l_stock_hash, "low index hash applied");
    TEST_ASSERT(memcmp(t.f->nodes[lo].l_stock_hash, h_lo, 32) == 0, "low index hash");
    TEST_ASSERT(t.f->nodes[hi].has_l_stock_hash, "index >= 512 hash applied");
    TEST_ASSERT(memcmp(t.f->nodes[hi].l_stock_hash, h_hi, 32) == 0, "index >= 512 hash");
    ts_close(&t);
    return 1;
}

/* ---- Placement order ---- */

/* The placement sort's result depends on the comparator only: with a qsort
   that sees the clients in reverse, every placement mode with equal profiles
   gives the same tree as the stable glibc sort of 1..N. */
int test_tree_shape_placement_order(void) {
#if defined(__GLIBC__)
    static const placement_mode_t modes[] = {
        PLACEMENT_TIMEZONE_CLUSTER, PLACEMENT_INWARD, PLACEMENT_OUTWARD
    };
    static const ts_shape_t shapes[] = {
        { "N=12 arity 2", 12, {2}, 1, 0, 0, 0, 0, 0 },
        { "N=12 timezone ties", 12, {2}, 1, 0, 0, 0, 0, 1 },
        { "N=64 8,7,3 static 2", 64, {8, 7, 3}, 3, 2, 0, 0, 0, 0 },
    };
    for (size_t k = 0; k < sizeof(shapes) / sizeof(shapes[0]); k++) {
        for (size_t m = 0; m < sizeof(modes) / sizeof(modes[0]); m++) {
            char want[65] = "", got[65] = "";
            for (int rev = 0; rev < 2; rev++) {
                ts_tree_t t;
                TEST_ASSERT(ts_open_b(&t, &shapes[k], 0), "setup");
                factory_t *f = t.f;
                TEST_ASSERT(factory_set_placement_mode(f, modes[m]), "placement");
                if (modes[m] != PLACEMENT_TIMEZONE_CLUSTER) {
                    /* equal contributions / uptimes: clients stay in index order */
                    unsigned char spk[34], txid[32];
                    memset(txid, 0xAA, 32);
                    TEST_ASSERT(factory_compute_funding_spk(f, spk) &&
                                factory_set_funding(f, txid, 0, f->funding_amount_sats, spk, 34),
                                "index-order funding");
                }
                g_ts_qsort_reverse = rev;
                int ok = factory_build_tree(f);
                g_ts_qsort_reverse = 0;
                TEST_ASSERT(ok, "build");
                ts_digest(f, rev ? got : want);
                if (!shapes[k].tz_profiles) {
                    /* Equal profiles: clients 1..N in leaf order. */
                    uint32_t next = 1;
                    for (int i = 0; i < f->n_leaf_nodes; i++) {
                        const factory_node_t *leaf = &f->nodes[f->leaf_node_indices[i]];
                        for (size_t sgn = 1; sgn < leaf->n_signers; sgn++)
                            TEST_ASSERT_EQ(leaf->signer_indices[sgn], next++, "leaf order 1..N");
                    }
                }
                ts_close(&t);
            }
            TEST_ASSERT(strcmp(want, got) == 0, "tree independent of qsort input order");
        }
    }
    /* The pinned digest of the timezone-tie shape is the glibc order. */
    char hex[65];
    TEST_ASSERT(ts_build_digest(&shapes[1], hex), "tz build");
    TEST_ASSERT(strcmp(hex, ts_pinned[11].digest) == 0, "tz ties = pinned glibc order");
    return 1;
#else
    return 2;  /* TEST_SKIP_CODE: needs the glibc qsort interposer */
#endif
}

/* ---- Per-level arity list bound ---- */

int test_tree_shape_level_list_bound(void) {
    secp256k1_context *ctx = ts_ctx();
    secp256k1_keypair *kps = ts_keys(ctx, 65);
    factory_t *f = calloc(1, sizeof(*f));
    TEST_ASSERT(kps && f, "alloc");
    TEST_ASSERT(factory_init(f, ctx, kps, 65, TS_STEP, TS_STATES), "init");
    uint8_t nine[FACTORY_MAX_LEVELS + 1] = { 2, 2, 2, 2, 2, 2, 2, 2, 4 };
    TEST_ASSERT(!factory_set_level_arity(f, nine, FACTORY_MAX_LEVELS + 1), "9 levels refused");
    TEST_ASSERT_EQ(f->n_level_arity, 0, "shape unchanged");
    TEST_ASSERT_EQ(f->leaf_arity, FACTORY_ARITY_2, "leaf arity unchanged");
    TEST_ASSERT(!factory_set_level_arity(f, nine, 0), "0 levels refused");
    uint8_t zero[2] = { 0, 2 }, big[2] = { FACTORY_MAX_OUTPUTS + 1, 2 };
    TEST_ASSERT(!factory_set_level_arity(f, zero, 2), "arity 0 refused");
    TEST_ASSERT(!factory_set_level_arity(f, big, 2), "arity 17 refused");
    TEST_ASSERT_EQ(f->n_level_arity, 0, "shape unchanged");
    TEST_ASSERT(factory_set_level_arity(f, nine, FACTORY_MAX_LEVELS), "8 levels");
    TEST_ASSERT_EQ(f->n_level_arity, FACTORY_MAX_LEVELS, "8 levels set");
    TEST_ASSERT_EQ(f->leaf_arity, 2, "last entry is the leaf arity");
    factory_free(f);
    free(f);
    free(kps);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Scale: build + sign one-client PS leaves under wide upper levels ---- */

/* Verify every node's key-path signature against its parent output. */
static int ts_verify_all(const factory_t *f) {
    for (size_t i = 0; i < f->n_nodes; i++) {
        const factory_node_t *node = &f->nodes[i];
        if (!node->is_signed) return 0;
        const unsigned char *spk;
        size_t spk_len;
        uint64_t amt;
        if (node->parent_index < 0) {
            spk = f->funding_spk; spk_len = f->funding_spk_len; amt = f->funding_amount_sats;
        } else {
            const factory_node_t *p = &f->nodes[node->parent_index];
            spk = p->outputs[node->parent_vout].script_pubkey;
            spk_len = p->outputs[node->parent_vout].script_pubkey_len;
            amt = p->outputs[node->parent_vout].amount_sats;
        }
        unsigned char sighash[32];
        if (!compute_taproot_sighash(sighash, node->unsigned_tx.data, node->unsigned_tx.len,
                                     0, spk, spk_len, amt, node->nsequence))
            return 0;
        if (!secp256k1_schnorrsig_verify(f->ctx, node->signed_tx.data + node->unsigned_tx.len,
                                         sighash, 32, &node->tweaked_pubkey))
            return 0;
    }
    return 1;
}

int test_tree_shape_scale_sign_ewt(void) {
    static const ts_shape_t shapes[] = {
        { "N=256 15,8,3", 256, {15, 8, 3}, 3, 0, 1, 1000, 0, 0 },
        { "N=257 15,8,3", 257, {15, 8, 3}, 3, 0, 1, 1000, 0, 0 },
        { "N=512 15,8,3", 512, {15, 8, 3}, 3, 0, 1, 1000, 0, 0 },
        { "N=1000 15,8,3", 1000, {15, 8, 3}, 3, 0, 1, 1000, 0, 0 },
        { "N=256 PS", 256, {3}, 1, 0, 1, 1000, 0, 0 },
        { "N=257 PS", 257, {3}, 1, 0, 1, 1000, 0, 0 },
        { "N=512 PS", 512, {3}, 1, 0, 1, 1000, 0, 0 },
        { "N=1000 PS", 1000, {3}, 1, 0, 1, 1000, 0, 0 },
    };
    for (size_t k = 0; k < sizeof(shapes) / sizeof(shapes[0]); k++) {
        const ts_shape_t *s = &shapes[k];
        ts_tree_t t;
        TEST_ASSERT(ts_open(&t, s) && t.built, s->name);
        TEST_ASSERT_EQ(ts_count_ps_leaves(t.f), (int)s->n_clients, "one client per PS leaf");
        TEST_ASSERT(factory_sign_all(t.f), "sign all");
        TEST_ASSERT(ts_verify_all(t.f), "every signature verifies");
        long tx_max = ts_tx_path_max(t.f);
        uint32_t ewt = factory_early_warning_time(t.f);
        printf("\n    %s: %zu nodes, deepest-path nSequence sum %ld, ewt %u, shape ewt %u",
               s->name, t.f->n_nodes, tx_max, ewt, ts_shape_ewt(s));
        TEST_ASSERT_EQ(ewt, tx_max, "ewt = deepest-path nSequence sum");
        TEST_ASSERT_EQ(ts_shape_ewt(s), tx_max, "shape ewt = deepest-path nSequence sum");
        ts_close(&t);
    }
    printf("\n");
    return 1;
}

/* ---- Shape early-warning time with k^2 PS leaves ---- */

int test_tree_shape_ewt_ps_k(void) {
    static const struct { ts_shape_t s; uint32_t ewt; } cases[] = {
        { { "N=8 PS k=2", 8, {3}, 1, 0, 1, 1000, 2, 0 }, 1 * TS_LOCK },
        { { "N=16 PS k=2", 16, {3}, 1, 0, 1, 1000, 2, 0 }, 2 * TS_LOCK },
        { { "N=18 PS k=3", 18, {3}, 1, 0, 1, 1000, 3, 0 }, 1 * TS_LOCK },
        { { "N=36 PS k=3", 36, {3}, 1, 0, 1, 1000, 3, 0 }, 2 * TS_LOCK },
        { { "N=64 16,3 k=2", 64, {16, 3}, 2, 0, 0, 0, 2, 0 }, 1 * TS_LOCK },
    };
    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        const ts_shape_t *s = &cases[k].s;
        ts_tree_t t;
        TEST_ASSERT(ts_open(&t, s) && t.built, s->name);
        long tx_max = ts_tx_path_max(t.f);
        uint32_t shape = ts_shape_ewt(s);
        if (tx_max != (long)cases[k].ewt || shape != cases[k].ewt)
            printf("\n    %s: txs %ld shape %u expected %u\n", s->name, tx_max, shape, cases[k].ewt);
        TEST_ASSERT_EQ(tx_max, cases[k].ewt, "tx path max");
        TEST_ASSERT_EQ(factory_early_warning_time(t.f), tx_max, "factory_early_warning_time");
        TEST_ASSERT_EQ(shape, tx_max, "factory_compute_ewt_for_shape honours k");
        ts_close(&t);
    }
    return 1;
}

/* ---- Per-leaf rollover ---- */

/* A per-leaf rollover advances counter layer 0 and resets the leaf to its
   longest delay.  For a leaf with no DW state above it on layer 0 the reset
   state would spend the same outpoint as the superseded nSequence-0 state,
   which would win; such a leaf refuses to roll over and keeps its last
   state.  Leaves with such an ancestor roll over onto a new outpoint. */
int test_tree_shape_per_leaf_rollover(void) {
    static const struct { ts_shape_t s; int rolls; } cases[] = {
        { { "N=2 arity 2 static 1", 2, {2}, 1, 1, 1, 1000, 0, 0 }, 0 },
        { { "N=4 arity 2 static 1", 4, {2}, 1, 1, 1, 1000, 0, 0 }, 0 },
        { { "N=2 arity 2 (root leaf)", 2, {2}, 1, 0, 1, 1000, 0, 0 }, 0 },
        { { "N=4 arity 2", 4, {2}, 1, 0, 1, 1000, 0, 0 }, 1 },
        { { "N=8 arity 2 static 1", 8, {2}, 1, 1, 1, 1000, 0, 0 }, 1 },
    };
    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        for (int sign = 0; sign < 2; sign++) {
            ts_tree_t t;
            TEST_ASSERT(ts_open(&t, &cases[k].s) && t.built, cases[k].s.name);
            factory_t *f = t.f;
            if (sign) TEST_ASSERT(factory_sign_all(f), "sign");
            size_t L = f->leaf_node_indices[0];
            for (int i = 1; i < TS_STATES; i++) {
                int rc = sign ? factory_advance_leaf(f, 0) : factory_advance_leaf_unsigned(f, 0);
                TEST_ASSERT_EQ(rc, 1, "advance within the leaf layer");
            }
            TEST_ASSERT_EQ(f->nodes[L].nsequence, 0, "leaf at its last state");
            unsigned char old_txid[32], old_in[32];
            memcpy(old_txid, f->nodes[L].txid, 32);
            memcpy(old_in, f->nodes[f->nodes[L].parent_index].txid, 32);
            int rc = sign ? factory_advance_leaf(f, 0) : factory_advance_leaf_unsigned(f, 0);
            if (cases[k].rolls) {
                TEST_ASSERT_EQ(rc, sign ? 1 : -1, "rollover");
                TEST_ASSERT(memcmp(old_in, f->nodes[f->nodes[L].parent_index].txid, 32) != 0,
                            "rolled-over leaf spends a new outpoint");
                TEST_ASSERT_EQ(f->counter.current_epoch, 1, "epoch moved");
            } else {
                TEST_ASSERT_EQ(rc, 0, "rollover refused");
                TEST_ASSERT(memcmp(old_txid, f->nodes[L].txid, 32) == 0, "leaf state kept");
                TEST_ASSERT_EQ(f->nodes[L].nsequence, 0, "leaf nSequence kept");
                TEST_ASSERT_EQ(f->counter.current_epoch, 0, "epoch kept");
            }
            ts_close(&t);
        }
    }
    return 1;
}

/* ---- Funding script ---- */

/* The root kickoff spends the funding output by key path: a script other
   than the key-path P2TR of the root signers' MuSig2 key is refused (at
   factory_set_funding for its form, at factory_build_tree for its key) and
   nothing is built or signed over it. */
int test_tree_shape_funding_script(void) {
    ts_shape_t s = { "N=4 arity 2", 4, {2}, 1, 0, 1, 1000, 0, 0 };
    ts_tree_t t;
    TEST_ASSERT(ts_open_b(&t, &s, 0), "setup");
    factory_t *f = t.f;
    unsigned char good[34], txid[32], keep[34];
    memset(txid, 0xAA, 32);
    TEST_ASSERT(factory_compute_funding_spk(f, good), "funding spk");
    TEST_ASSERT(memcmp(f->funding_spk, good, 34) == 0, "setup used the factory's own key");
    memcpy(keep, f->funding_spk, 34);

    unsigned char p2wpkh[22] = { 0x00, 0x14 };
    TEST_ASSERT(!factory_set_funding(f, txid, 0, 1800000, p2wpkh, 22), "22-byte script refused");
    unsigned char not_tr[34];
    memcpy(not_tr, good, 34); not_tr[0] = 0x00;
    TEST_ASSERT(!factory_set_funding(f, txid, 0, 1800000, not_tr, 34), "non-P2TR 34-byte script refused");
    TEST_ASSERT(!factory_set_funding(f, txid, 0, 1800000, NULL, 34), "NULL script refused");
    TEST_ASSERT(memcmp(f->funding_spk, keep, 34) == 0 && f->funding_spk_len == 34,
                "refused script changes nothing");

    unsigned char wrong[34];
    memcpy(wrong, good, 34); wrong[33] ^= 1;
    TEST_ASSERT(factory_set_funding(f, txid, 0, 1800000, wrong, 34), "P2TR form accepted");
    TEST_ASSERT(!factory_build_tree(f), "build refused over another key");
    TEST_ASSERT_EQ(f->n_nodes, 0, "nothing built");

    TEST_ASSERT(factory_set_funding(f, txid, 0, 1800000, good, 34), "own key");
    TEST_ASSERT(factory_build_tree(f), "build over the factory's own key");
    TEST_ASSERT(memcmp(f->nodes[0].spending_spk, good, 34) == 0, "root spends the funding script");
    TEST_ASSERT(factory_sign_all(f), "sign");
    ts_close(&t);
    return 1;
}

/* ---- Session re-initialisation ---- */

/* Re-initialising a node's signing session releases the previous one (the
   21-signer root uses a heap nonce array; LSan reports it otherwise). */
int test_tree_shape_session_reinit(void) {
    ts_shape_t s = { "N=20 arity 2", 20, {2}, 1, 0, 0, 0, 0, 0 };
    ts_tree_t t;
    TEST_ASSERT(ts_open(&t, &s) && t.built, "build");
    TEST_ASSERT(t.f->nodes[0].n_signers > MUSIG_SESSION_SMALL, "root uses a heap nonce array");
    for (int i = 0; i < 3; i++)
        TEST_ASSERT(factory_session_init_node(t.f, 0), "session init");
    for (int i = 0; i < 3; i++)
        TEST_ASSERT(factory_sign_node(t.f, 0), "sign node");
    ts_close(&t);
    return 1;
}

/* ---- Placement setter ---- */

int test_tree_shape_placement_setter(void) {
    ts_shape_t s = { "N=4 arity 2", 4, {2}, 1, 0, 0, 0, 0, 0 };
    ts_tree_t t;
    TEST_ASSERT(ts_open_b(&t, &s, 0), "setup");
    TEST_ASSERT_EQ(t.f->placement_mode, PLACEMENT_TIMEZONE_CLUSTER, "default placement");
    static const placement_mode_t ok[] = {
        PLACEMENT_SEQUENTIAL, PLACEMENT_INWARD, PLACEMENT_OUTWARD, PLACEMENT_TIMEZONE_CLUSTER
    };
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        TEST_ASSERT(factory_set_placement_mode(t.f, ok[i]), "known mode");
        TEST_ASSERT_EQ(t.f->placement_mode, ok[i], "mode set");
    }
    TEST_ASSERT(!factory_set_placement_mode(t.f, (placement_mode_t)4), "mode 4 refused");
    TEST_ASSERT(!factory_set_placement_mode(t.f, (placement_mode_t)-1), "mode -1 refused");
    TEST_ASSERT_EQ(t.f->placement_mode, PLACEMENT_TIMEZONE_CLUSTER, "refused mode changes nothing");
    TEST_ASSERT(factory_build_tree(t.f), "build");
    ts_close(&t);
    return 1;
}


/* ---- Member to leaf under placement ---- */

/* factory_client_to_leaf finds each member's channel where the placement
   put it: the leaf (or PS sub-factory) whose signers include the member,
   at the member's slot.  Profiles here make the timezone-cluster placement
   reverse the members. */
int test_tree_shape_client_to_leaf_placement(void) {
    static const ts_shape_t shapes[] = {
        { "N=6 arity 2", 6, {2}, 1, 0, 1, 1000, 0, 0 },
        { "N=5 arity 2", 5, {2}, 1, 0, 0, 0, 0, 0 },
        { "N=4 arity 1", 4, {1}, 1, 0, 1, 1000, 0, 0 },
        { "N=4 PS", 4, {3}, 1, 0, 1, 1000, 0, 0 },
        { "N=8 PS k=2", 8, {3}, 1, 0, 1, 1000, 2, 0 },
        { "N=8 2,4", 8, {2, 4}, 2, 0, 1, 1000, 0, 0 },
    };
    for (size_t i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++) {
        const ts_shape_t *s = &shapes[i];
        ts_tree_t t;
        TEST_ASSERT(ts_open_b(&t, s, 0), s->name);
        factory_t *f = t.f;
        for (size_t p = 1; p < f->n_participants; p++)
            f->profiles[p].timezone_bucket = (uint8_t)(20 - p);
        unsigned char spk[34], txid[32];
        memset(txid, 0xAA, 32);
        TEST_ASSERT(factory_set_placement_mode(f, PLACEMENT_TIMEZONE_CLUSTER) &&
                    factory_compute_funding_spk(f, spk) &&
                    factory_set_funding(f, txid, 0, f->funding_amount_sats, spk, 34),
                    "fund");
        TEST_ASSERT(factory_build_tree(f), s->name);
        for (size_t c = 0; c < s->n_clients; c++) {
            size_t ni;
            uint32_t vout;
            if (!factory_client_to_leaf(f, c, &ni, &vout)) {
                printf("  %s: member %zu not found\n", s->name, c + 1);
                return 0;
            }
            const factory_node_t *n = &f->nodes[ni];
            if (vout + 1 >= n->n_signers || n->signer_indices[vout + 1] != c + 1) {
                printf("  %s: member %zu mapped to node %zu vout %u (signer %u)\n",
                       s->name, c + 1, ni, vout,
                       vout + 1 < n->n_signers ? n->signer_indices[vout + 1] : 0);
                return 0;
            }
        }
        ts_close(&t);
    }
    return 1;
}
