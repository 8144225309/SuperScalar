/* The advanceless default tree: the shape rule, the built tree (no DW state
   anywhere, one member per pseudo-Spilman leaf), the refusal of every
   refresh-in-place entry point, and a reload from the DB that rebuilds the
   signed tree byte for byte (and refuses one that does not match). */
#include "superscalar/factory.h"
#include "superscalar/persist.h"
#include "superscalar/sha256.h"
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define TEST_ASSERT_EQ(a, b, msg) do { \
    if ((long)(a) != (long)(b)) { \
        printf("  FAIL: %s (line %d): %s (got %ld, expected %ld)\n", \
               __func__, __LINE__, msg, (long)(a), (long)(b)); \
        return 0; \
    } \
} while(0)

/* Records a failure and goes on, so each refusal case reports on its own. */
#define AL_CHECK(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        failed = 1; \
    } \
} while(0)

#define AL_STEP   10
#define AL_STATES 4

static void al_shape_str(const uint8_t *a, size_t n, char *out, size_t len) {
    out[0] = '\0';
    for (size_t i = 0; i < n; i++) {
        size_t off = strlen(out);
        snprintf(out + off, len - off, "%s%u", i ? "," : "", (unsigned)a[i]);
    }
}

/* Deterministic keypairs: seckey i = SHA256("advanceless-key" || i). */
static secp256k1_keypair *al_keys(secp256k1_context *ctx, size_t n) {
    secp256k1_keypair *kps = calloc(n, sizeof(*kps));
    if (!kps) return NULL;
    for (size_t i = 0; i < n; i++) {
        unsigned char buf[19], sk[32];
        memcpy(buf, "advanceless-key", 15);
        buf[15] = (unsigned char)(i >> 24); buf[16] = (unsigned char)(i >> 16);
        buf[17] = (unsigned char)(i >> 8);  buf[18] = (unsigned char)i;
        sha256(buf, sizeof(buf), sk);
        if (!secp256k1_keypair_create(ctx, &kps[i], sk)) { free(kps); return NULL; }
    }
    return kps;
}

/* Init a factory of n_clients + 1 with the given shape (n_arities 1 =
   uniform), funded, and build its tree. */
/* Agreed tree rate (sat/kvB) the al_build trees are built at. */
static uint64_t g_al_tree_rate = FACTORY_DEFAULT_TREE_FEE_RATE;

static int al_build(factory_t *f, secp256k1_context *ctx, const secp256k1_keypair *kps,
                    size_t n_clients, const uint8_t *arities, size_t n_arities,
                    uint32_t static_thr) {
    if (!factory_init(f, ctx, kps, n_clients + 1, AL_STEP, AL_STATES)) return 0;
    f->tree_fee_rate = g_al_tree_rate;
    if (n_arities == 1)
        factory_set_arity(f, (factory_arity_t)arities[0]);
    else if (!factory_set_level_arity(f, arities, n_arities))
        return 0;
    if (static_thr) factory_set_static_near_root(f, static_thr);
    f->use_tree_anchor = 1;
    f->cltv_timeout = 1000;
    unsigned char txid[32], spk[34];
    memset(txid, 0x5A, 32);
    if (!factory_compute_funding_spk(f, spk)) return 0;
    if (!factory_set_funding(f, txid, 1, (uint64_t)n_clients * 200000 + 1000000, spk, 34))
        return 0;
    return factory_build_tree(f);
}

static int al_build_default(factory_t *f, secp256k1_context *ctx,
                            const secp256k1_keypair *kps, size_t n_clients) {
    uint8_t a[FACTORY_MAX_LEVELS];
    size_t n = 0;
    uint32_t st = 0;
    if (!factory_advanceless_shape(n_clients, a, &n, &st)) return 0;
    return al_build(f, ctx, kps, n_clients, a, n, st);
}

/* ---- the shape rule ---- */

int test_advanceless_shape_rule(void) {
    static const struct { size_t n; const char *arity; uint32_t st; } want[] = {
        {   1, "3",       0 },
        {   2, "4,3",     1 },
        {   4, "4,3",     1 },
        {  15, "15,3",    1 },
        {  16, "4,4,3",   2 },
        {  64, "8,8,3",   2 },
        { 128, "12,12,3", 2 },
        { 225, "15,15,3", 2 },
        { 226, "7,7,7,3", 3 },
        { 255, "7,7,7,3", 3 },
    };
    for (size_t k = 0; k < sizeof(want) / sizeof(want[0]); k++) {
        uint8_t a[FACTORY_MAX_LEVELS];
        size_t n = 0;
        uint32_t st = 99;
        char got[64];
        TEST_ASSERT(factory_advanceless_shape(want[k].n, a, &n, &st), "shape");
        al_shape_str(a, n, got, sizeof(got));
        if (strcmp(got, want[k].arity) != 0) {
            printf("  FAIL: N=%zu arity %s, expected %s\n", want[k].n, got, want[k].arity);
            return 0;
        }
        TEST_ASSERT_EQ(st, want[k].st, "static-near-root = leaf depth");
        TEST_ASSERT_EQ(factory_compute_ewt_for_shape(n > 1 ? a : NULL, n > 1 ? n : 0,
                           FACTORY_ARITY_PS, 1, want[k].n, st, 144, 4), 0,
                       "no DW delay on any path");
    }
    uint8_t a[FACTORY_MAX_LEVELS];
    size_t n;
    uint32_t st;
    TEST_ASSERT(!factory_advanceless_shape(0, a, &n, &st), "zero clients refused");
    return 1;
}

/* ---- the built default tree at N = 2, 4, 16, 64, 128, 255 ---- */

int test_advanceless_default_tree(void) {
    static const struct { size_t n; size_t nodes; } sizes[] = {
        { 2, 5 }, { 4, 9 }, { 16, 37 }, { 64, 137 }, { 128, 269 }, { 255, 567 },
    };
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair *kps = al_keys(ctx, 256);
    TEST_ASSERT(kps, "keys");
    for (size_t k = 0; k < sizeof(sizes) / sizeof(sizes[0]); k++) {
        size_t nc = sizes[k].n;
        uint8_t a[FACTORY_MAX_LEVELS];
        size_t na = 0;
        uint32_t depth = 0;
        TEST_ASSERT(factory_advanceless_shape(nc, a, &na, &depth), "shape");
        factory_t *f = calloc(1, sizeof(*f));
        TEST_ASSERT(f && al_build(f, ctx, kps, nc, a, na, depth), "build");

        TEST_ASSERT_EQ(f->n_nodes, sizes[k].nodes, "node count");
        TEST_ASSERT_EQ(f->n_leaf_nodes, nc, "one leaf per member");
        TEST_ASSERT(!factory_has_dw_state(f), "no DW state node");
        TEST_ASSERT_EQ(factory_early_warning_time(f), 0, "ewt 0");
        size_t n_static = 0;
        for (size_t i = 0; i < f->n_nodes; i++) {
            const factory_node_t *node = &f->nodes[i];
            TEST_ASSERT(node->n_outputs <= FACTORY_MAX_OUTPUTS, "outputs fit");
            if (node->is_static_only) {
                n_static++;
                TEST_ASSERT_EQ(node->nsequence, 0xFFFFFFFEu, "static kickoff nSequence");
            } else if (node->type == NODE_KICKOFF) {
                TEST_ASSERT_EQ(node->nsequence, 0xFFFFFFFFu, "leaf kickoff nSequence");
            } else {
                TEST_ASSERT(node->is_ps_leaf, "every state node is a PS leaf");
                TEST_ASSERT_EQ(node->nsequence, 0xFFFFFFFEu, "PS leaf nSequence");
            }
        }
        TEST_ASSERT_EQ(f->n_nodes, n_static + 2 * nc, "static kickoffs + leaf pairs");
        uint32_t max_depth = 0;
        for (int li = 0; li < f->n_leaf_nodes; li++) {
            const factory_node_t *leaf = &f->nodes[f->leaf_node_indices[li]];
            TEST_ASSERT(leaf->is_ps_leaf, "PS leaf");
            TEST_ASSERT_EQ(leaf->n_signers, 2, "one member + LSP per leaf");
            uint32_t d = 0;
            for (int j = f->nodes[leaf->parent_index].parent_index; j >= 0;
                 j = f->nodes[j].parent_index) {
                TEST_ASSERT(f->nodes[j].is_static_only, "every ancestor is static");
                d++;
            }
            if (d > max_depth) max_depth = d;
        }
        TEST_ASSERT_EQ(max_depth, depth, "leaf depth = --static-near-root");
        factory_free(f);
        free(f);
    }
    free(kps);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- refresh in place is refused; a DW shape still ticks ---- */

int test_advanceless_refuses_refresh(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair *kps = al_keys(ctx, 5);
    TEST_ASSERT(kps, "keys");

    factory_t *f = calloc(1, sizeof(*f));
    TEST_ASSERT(f && al_build_default(f, ctx, kps, 4), "build default N=4");
    unsigned char root_txid[32];
    memcpy(root_txid, f->nodes[0].txid, 32);
    uint32_t epoch = f->counter.current_epoch;
    uint32_t st0 = f->counter.layers[0].current_state;

    TEST_ASSERT(factory_refuses_refresh_in_place(f, "test"), "refusal helper");
    for (int i = 0; i < AL_STATES + 2; i++)
        TEST_ASSERT_EQ(factory_tick_root(f), 0, "root tick refused");
    TEST_ASSERT_EQ(f->counter.current_epoch, epoch, "epoch unchanged");
    TEST_ASSERT_EQ(f->counter.layers[0].current_state, st0, "layer unchanged");
    TEST_ASSERT(memcmp(f->nodes[0].txid, root_txid, 32) == 0, "tree unchanged");
    TEST_ASSERT(!factory_advance(f), "whole-counter advance refused");
    TEST_ASSERT_EQ(f->counter.current_epoch, epoch, "epoch unchanged");

    /* A PS chain at states_per_layer would roll the root over: refused
       before the leaf is touched. */
    size_t li = f->leaf_node_indices[0];
    f->nodes[li].ps_chain_len = (int)f->states_per_layer;
    unsigned char leaf_txid[32];
    memcpy(leaf_txid, f->nodes[li].txid, 32);
    TEST_ASSERT_EQ(factory_advance_leaf_unsigned(f, 0), 0, "PS rollover refused");
    TEST_ASSERT_EQ(f->nodes[li].ps_chain_len, (int)f->states_per_layer, "chain untouched");
    TEST_ASSERT(memcmp(f->nodes[li].txid, leaf_txid, 32) == 0, "leaf untouched");
    TEST_ASSERT_EQ(f->counter.current_epoch, epoch, "epoch unchanged");
    factory_free(f);
    free(f);

    /* Contrast: the uniform PS tree keeps DW state on its interior levels,
       and its root still ticks and rolls over. */
    f = calloc(1, sizeof(*f));
    const uint8_t ps[1] = { FACTORY_ARITY_PS };
    TEST_ASSERT(f && al_build(f, ctx, kps, 4, ps, 1, 0), "build uniform PS");
    TEST_ASSERT(factory_has_dw_state(f), "DW state present");
    TEST_ASSERT(!factory_refuses_refresh_in_place(f, "test"), "not refused");
    int rc = 0, ticks = 0;
    while (ticks < AL_STATES + 2 && (rc = factory_tick_root(f)) == 0) ticks++;
    TEST_ASSERT_EQ(rc, -1, "DW shape rolls over");
    TEST_ASSERT_EQ(f->counter.current_epoch, 1, "epoch advanced");
    factory_free(f);
    free(f);

    TEST_ASSERT(strstr(FACTORY_EXTEND_REFUSED_MSG, "rotat") != NULL,
                "the refusal points to rotation");
    free(kps);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- reload rebuilds the signed tree; a mismatch is refused ---- */

static int al_reload_matches(persist_t *db, secp256k1_context *ctx, const factory_t *f) {
    factory_t *g = calloc(1, sizeof(*g));
    if (!g) return 0;
    int ok = persist_load_factory(db, 0, g, ctx);
    if (ok) {
        ok = g->n_nodes == f->n_nodes &&
             g->n_level_arity == f->n_level_arity &&
             memcmp(g->level_arity, f->level_arity, f->n_level_arity) == 0 &&
             g->static_threshold_depth == f->static_threshold_depth;
        for (size_t i = 0; ok && i < f->n_nodes; i++)
            ok = memcmp(g->nodes[i].txid, f->nodes[i].txid, 32) == 0;
        factory_free(g);
    }
    free(g);
    return ok;
}

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern void reverse_bytes(unsigned char *data, size_t len);

/* Store, as the row of leaf state `node_idx`, a self-consistent variant of its
   signed tx: 1000 sats moved out of its first output (so the row differs from
   the rebuild, as an advanced leaf's does) and its input pointed at
   prev_txid:prev_vout (internal order; NULL keeps the parent output).  The
   row's txid, amounts and signed bytes agree with each other; its signature
   is not checked here.  Writes the new txid (internal order) to txid_out. */
static int al_craft_leaf_row(persist_t *db, const factory_t *f, size_t node_idx,
                             const unsigned char *prev_txid, uint32_t prev_vout,
                             unsigned char txid_out[32]) {
    const factory_node_t *node = &f->nodes[node_idx];
    size_t len = node->signed_tx.len;
    if (len < 60) return 0;
    unsigned char *b = malloc(len);
    if (!b) return 0;
    memcpy(b, node->signed_tx.data, len);
    /* version | 00 01 | n_in=1 | prev(32) vout(4) | script 0 | seq(4) | n_out */
    if (b[4] != 0 || b[5] != 1 || b[6] != 1 || b[43] != 0 || b[48] > 16) { free(b); return 0; }
    if (prev_txid) {
        memcpy(b + 7, prev_txid, 32);
        for (int k = 0; k < 4; k++) b[39 + k] = (unsigned char)(prev_vout >> (8 * k));
    }
    uint64_t a0 = 0;
    for (int k = 0; k < 8; k++) a0 |= (uint64_t)b[49 + k] << (8 * k);
    a0 -= 1000;
    for (int k = 0; k < 8; k++) b[49 + k] = (unsigned char)(a0 >> (8 * k));
    size_t pos = 49;
    for (int o = 0; o < b[48]; o++) {
        pos += 8;
        if (b[pos] >= 0xFD) { free(b); return 0; }
        pos += 1 + b[pos];
    }
    size_t nw_len = 4 + (pos - 6) + 4;
    unsigned char *nw = malloc(nw_len);
    if (!nw) { free(b); return 0; }
    memcpy(nw, b, 4);
    memcpy(nw + 4, b + 6, pos - 6);
    memcpy(nw + 4 + (pos - 6), b + len - 4, 4);
    sha256_double(nw, nw_len, txid_out);
    free(nw);
    char amounts[16 * 21 + 1] = "";
    for (size_t o = 0; o < node->n_outputs; o++) {
        size_t off = strlen(amounts);
        snprintf(amounts + off, sizeof(amounts) - off, "%s%llu", o ? "," : "",
                 (unsigned long long)(o == 0 ? a0 : node->outputs[o].amount_sats));
    }
    unsigned char disp[32];
    memcpy(disp, txid_out, 32);
    reverse_bytes(disp, 32);
    char txid_hex[65];
    hex_encode(disp, 32, txid_hex);
    char *tx_hex = malloc(len * 2 + 1);
    if (!tx_hex) { free(b); return 0; }
    hex_encode(b, len, tx_hex);
    free(b);
    sqlite3_stmt *st;
    int ok = sqlite3_prepare_v2(db->db, "UPDATE tree_nodes SET txid = ?, signed_tx_hex = ?, "
                                "output_amounts = ? WHERE factory_id = 0 AND node_index = ?;",
                                -1, &st, NULL) == SQLITE_OK;
    if (ok) {
        sqlite3_bind_text(st, 1, txid_hex, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, tx_hex, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, amounts, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 4, (int)node_idx);
        ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db->db) == 1;
        sqlite3_finalize(st);
    }
    free(tx_hex);
    return ok;
}

/* Load and return the in-memory txid of node `idx` (0 if the load fails). */
static int al_load_node_txid(persist_t *db, secp256k1_context *ctx, size_t idx,
                             unsigned char out[32]) {
    factory_t *g = calloc(1, sizeof(*g));
    if (!g) return 0;
    int ok = persist_load_factory(db, 0, g, ctx) && idx < g->n_nodes;
    if (ok) memcpy(out, g->nodes[idx].txid, 32);
    if (g->nodes) factory_free(g);
    free(g);
    return ok;
}

static int al_load_refused(persist_t *db, secp256k1_context *ctx) {
    factory_t *g = calloc(1, sizeof(*g));
    if (!g) return 0;
    int loaded = persist_load_factory(db, 0, g, ctx);
    if (loaded) factory_free(g);
    free(g);
    return !loaded;
}

int test_advanceless_persist_reload(void) {
    int failed = 0;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair *kps = al_keys(ctx, 65);
    TEST_ASSERT(kps, "keys");
    static const struct { size_t n; uint8_t a[4]; size_t na; uint32_t st; } shapes[] = {
        { 64, { 0 }, 0, 0 },              /* the advanceless default */
        {  4, { 0 }, 0, 0 },
        {  6, { 2, 4 }, 2, 1 },           /* mixed, DW leaves below one static level */
        {  4, { FACTORY_ARITY_PS }, 1, 0 },   /* uniform PS, DW interior */
    };
    for (size_t k = 0; k < sizeof(shapes) / sizeof(shapes[0]); k++) {
        factory_t *f = calloc(1, sizeof(*f));
        TEST_ASSERT(f, "alloc");
        if (shapes[k].na == 0)
            TEST_ASSERT(al_build_default(f, ctx, kps, shapes[k].n), "build default");
        else
            TEST_ASSERT(al_build(f, ctx, kps, shapes[k].n, shapes[k].a, shapes[k].na,
                                 shapes[k].st), "build");
        TEST_ASSERT(factory_sign_all(f), "sign the tree");
        persist_t db;
        TEST_ASSERT(persist_open(&db, NULL), "open in-memory");
        TEST_ASSERT_EQ(persist_schema_version(&db), PERSIST_SCHEMA_VERSION, "current schema");
        TEST_ASSERT(persist_save_factory(&db, f, ctx, 0), "save factory");
        TEST_ASSERT(persist_save_tree_nodes(&db, f, 0), "save tree");
        TEST_ASSERT(al_reload_matches(&db, ctx, f), "reload = signed tree");

        if (k == 0) {
            /* Shape lost (a pre-v40 row): the default-shape rebuild is not the
               signed tree and the load is refused. */
            TEST_ASSERT(sqlite3_exec(db.db, "UPDATE factories SET level_arity = NULL, "
                                     "static_threshold_depth = 0;", NULL, NULL, NULL) == SQLITE_OK,
                        "drop the shape");
            TEST_ASSERT(al_load_refused(&db, ctx), "shape mismatch refused");
            TEST_ASSERT(persist_save_factory(&db, f, ctx, 0), "re-save factory");
            TEST_ASSERT(al_reload_matches(&db, ctx, f), "reload after re-save");
            /* A signed txid that the rebuild does not reproduce. */
            TEST_ASSERT(sqlite3_exec(db.db, "UPDATE tree_nodes SET txid = "
                                     "'00000000000000000000000000000000000000000000000000000000000000ff' "
                                     "WHERE node_index = 3;", NULL, NULL, NULL) == SQLITE_OK,
                        "tamper txid");
            TEST_ASSERT(al_load_refused(&db, ctx), "txid mismatch refused");
            TEST_ASSERT(persist_save_tree_nodes(&db, f, 0), "re-save tree");
            /* A different static depth for the same arity list. */
            TEST_ASSERT(sqlite3_exec(db.db, "UPDATE factories SET static_threshold_depth = 1;",
                                     NULL, NULL, NULL) == SQLITE_OK, "change static");
            TEST_ASSERT(al_load_refused(&db, ctx), "static depth mismatch refused");
            TEST_ASSERT(sqlite3_exec(db.db, "UPDATE factories SET level_arity = '8,x';",
                                     NULL, NULL, NULL) == SQLITE_OK, "corrupt list");
            TEST_ASSERT(al_load_refused(&db, ctx), "corrupt level_arity refused");
            TEST_ASSERT(persist_save_factory(&db, f, ctx, 0), "re-save factory");
            TEST_ASSERT(al_reload_matches(&db, ctx, f), "reload after re-save");

            /* One edited nSequence: the row no longer matches its signed tx,
               and a kickoff never moves on. */
            TEST_ASSERT(sqlite3_exec(db.db, "UPDATE tree_nodes SET nsequence = nsequence - 1 "
                                     "WHERE node_index = 0;", NULL, NULL, NULL) == SQLITE_OK,
                        "edit root nSequence");
            AL_CHECK(al_load_refused(&db, ctx), "edited nSequence refused");
            TEST_ASSERT(persist_save_tree_nodes(&db, f, 0), "re-save tree");
            /* A leaf state's nSequence edited too. */
            char q[128];
            snprintf(q, sizeof(q), "UPDATE tree_nodes SET nsequence = 5 WHERE node_index = %zu;",
                     f->leaf_node_indices[0]);
            TEST_ASSERT(sqlite3_exec(db.db, q, NULL, NULL, NULL) == SQLITE_OK, "edit leaf");
            AL_CHECK(al_load_refused(&db, ctx), "edited leaf nSequence refused");
            TEST_ASSERT(persist_save_tree_nodes(&db, f, 0), "re-save tree");
            /* Fee-rule drift: every rebuilt amount differs from the signed tree,
               from the root down (the tree is built at the agreed rate). */
            TEST_ASSERT(sqlite3_exec(db.db, "UPDATE factories SET tree_fee_rate = tree_fee_rate + 1000;",
                                     NULL, NULL, NULL) == SQLITE_OK, "drift fee");
            AL_CHECK(al_load_refused(&db, ctx), "changed root amounts refused");
            TEST_ASSERT(persist_save_factory(&db, f, ctx, 0), "re-save factory");
            TEST_ASSERT(al_reload_matches(&db, ctx, f), "reload after re-save");
            /* A signed tx that is not the row's: the root row's bytes swapped
               for the next node's. */
            TEST_ASSERT(sqlite3_exec(db.db, "UPDATE tree_nodes SET signed_tx_hex = "
                                     "(SELECT signed_tx_hex FROM tree_nodes WHERE node_index = 1) "
                                     "WHERE node_index = 0;", NULL, NULL, NULL) == SQLITE_OK,
                        "swap signed tx");
            AL_CHECK(al_load_refused(&db, ctx), "foreign signed tx refused");
            TEST_ASSERT(persist_save_tree_nodes(&db, f, 0), "re-save tree");
            /* No stored tree at all. */
            TEST_ASSERT(sqlite3_exec(db.db, "DELETE FROM tree_nodes;", NULL, NULL, NULL) == SQLITE_OK,
                        "drop the tree");
            AL_CHECK(al_load_refused(&db, ctx), "factory without a tree refused");
            TEST_ASSERT(persist_save_tree_nodes(&db, f, 0), "re-save tree");
            TEST_ASSERT(al_reload_matches(&db, ctx, f), "reload after re-save");

            /* A leaf state that moved on: what it may spend. */
            size_t leaf = f->leaf_node_indices[1];
            unsigned char crafted[32], loaded[32];
            /* its parent's output (a re-allocation): loaded from its bytes */
            TEST_ASSERT(al_craft_leaf_row(&db, f, leaf, NULL, 0, crafted), "craft (parent)");
            AL_CHECK(al_load_node_txid(&db, ctx, leaf, loaded) &&
                     memcmp(loaded, crafted, 32) == 0, "leaf spending its parent loads");
            /* its own creation state (a chain advance) */
            TEST_ASSERT(al_craft_leaf_row(&db, f, leaf, f->nodes[leaf].txid, 0, crafted),
                        "craft (own chain)");
            AL_CHECK(al_load_node_txid(&db, ctx, leaf, loaded) &&
                     memcmp(loaded, crafted, 32) == 0, "leaf spending its own state loads");
            /* anything else: another leaf's state, or an unknown outpoint */
            TEST_ASSERT(al_craft_leaf_row(&db, f, leaf, f->nodes[f->leaf_node_indices[2]].txid,
                                          0, crafted), "craft (other leaf)");
            AL_CHECK(al_load_refused(&db, ctx), "leaf spending another leaf refused");
            unsigned char junk[32];
            memset(junk, 0x42, 32);
            TEST_ASSERT(al_craft_leaf_row(&db, f, leaf, junk, 3, crafted), "craft (junk)");
            AL_CHECK(al_load_refused(&db, ctx), "leaf spending an unknown output refused");
            /* the parent's txid at another of its outputs */
            TEST_ASSERT(al_craft_leaf_row(&db, f, leaf, f->nodes[f->nodes[leaf].parent_index].txid,
                                          f->nodes[leaf].parent_vout + 1, crafted),
                        "craft (wrong vout)");
            AL_CHECK(al_load_refused(&db, ctx), "leaf spending its parent's other output refused");
            TEST_ASSERT(persist_save_tree_nodes(&db, f, 0), "re-save tree");
            TEST_ASSERT(al_reload_matches(&db, ctx, f), "reload after re-save");
        }
        if (k == 3) {
            /* A legitimate refresh of a DW tree: the advanced signed states
               are loaded from their signed transactions. */
            TEST_ASSERT(factory_advance(f), "advance the DW tree");
            TEST_ASSERT(persist_save_tree_nodes(&db, f, 0), "save advanced tree");
            factory_t *g = calloc(1, sizeof(*g));
            TEST_ASSERT(g && persist_load_factory(&db, 0, g, ctx), "advanced tree loads");
            for (size_t i = 0; i < f->n_nodes; i++)
                TEST_ASSERT(memcmp(g->nodes[i].txid, f->nodes[i].txid, 32) == 0,
                            "loaded node is the advanced signed one");
            factory_free(g);
            free(g);
            /* The advanced root state's row pointed at another output of the
               root kickoff: its signed tx does not spend it. */
            TEST_ASSERT(sqlite3_exec(db.db, "UPDATE tree_nodes SET parent_vout = 1 "
                                     "WHERE node_index = 1;", NULL, NULL, NULL) == SQLITE_OK,
                        "repoint the advanced state");
            TEST_ASSERT(al_load_refused(&db, ctx), "advanced state off its parent refused");
        }
        persist_close(&db);
        factory_free(f);
        free(f);
    }
    free(kps);
    secp256k1_context_destroy(ctx);
    return !failed;
}

/* The agreed tree rate is part of the signed tree.  A factory saved at rate
   100 and one saved at rate 0 reload with that rate applied before the
   rebuild, and the rebuilt tree passes the check against the stored signed
   transactions; the same row holding the other rate rebuilds a tree nobody
   signed and is refused. */
int test_advanceless_reload_tree_rate(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair *kps = al_keys(ctx, 5);
    TEST_ASSERT(kps, "keys");
    static const uint64_t rates[2] = { 100, 0 };
    for (int k = 0; k < 2; k++) {
        factory_t *f = calloc(1, sizeof(*f));
        TEST_ASSERT(f, "alloc");
        g_al_tree_rate = rates[k];
        int built = al_build_default(f, ctx, kps, 4);
        g_al_tree_rate = FACTORY_DEFAULT_TREE_FEE_RATE;
        TEST_ASSERT(built, "build default");
        TEST_ASSERT_EQ(f->tree_fee_rate, rates[k], "built at the rate");
        TEST_ASSERT(factory_sign_all(f), "sign the tree");
        persist_t db;
        TEST_ASSERT(persist_open(&db, NULL), "open in-memory");
        TEST_ASSERT(persist_save_factory(&db, f, ctx, 0), "save factory");
        TEST_ASSERT(persist_save_tree_nodes(&db, f, 0), "save tree");

        factory_t *g = calloc(1, sizeof(*g));
        TEST_ASSERT(g, "alloc");
        TEST_ASSERT(persist_load_factory(&db, 0, g, ctx), "reload passes the tree check");
        TEST_ASSERT_EQ(g->tree_fee_rate, rates[k], "rate restored");
        for (size_t i = 0; i < f->n_nodes; i++) {
            TEST_ASSERT(memcmp(g->nodes[i].txid, f->nodes[i].txid, 32) == 0,
                        "rebuilt txid = signed txid");
            TEST_ASSERT_EQ(g->nodes[i].fee_sats, f->nodes[i].fee_sats, "same fee");
        }
        factory_free(g);
        free(g);
        TEST_ASSERT(al_reload_matches(&db, ctx, f), "reload = signed tree");

        /* the row says another rate: its rebuild is not the signed tree */
        TEST_ASSERT(sqlite3_exec(db.db, k == 0 ? "UPDATE factories SET tree_fee_rate = 0;"
                                               : "UPDATE factories SET tree_fee_rate = 100;",
                                 NULL, NULL, NULL) == SQLITE_OK, "change the rate");
        TEST_ASSERT(al_load_refused(&db, ctx), "a different rate is refused");

        persist_close(&db);
        factory_free(f);
        free(f);
    }
    free(kps);
    secp256k1_context_destroy(ctx);
    return 1;
}
