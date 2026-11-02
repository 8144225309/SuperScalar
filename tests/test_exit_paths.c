/* Exit-path tests: factory force-close at scale and after advances, distribution
 * TX retry, cooperative-close ordering, recoverfactory gating.
 *
 * Unit tests use a mock chain backend (no bitcoind).  Regtest tests need a
 * bitcoind -regtest node (run inside a sandbox).
 *
 * Every test in the first section is written against APIs that also exist
 * without these fixes, so it can be run against an unfixed build to show the bug
 * (except the cooperative-close test's lsp->closing check, a field the fix
 * adds).
 * The second section ("fix-only") exercises new APIs.
 */
#include "superscalar/regtest.h"
#include "superscalar/factory.h"
#include "superscalar/factory_recovery.h"
#include "superscalar/persist.h"
#include "superscalar/chain_backend.h"
#include "superscalar/musig.h"
#include "superscalar/sha256.h"
#include "superscalar/tx_builder.h"
#include "superscalar/lsp.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/client.h"
#include "superscalar/wire.h"
#include "superscalar/ladder.h"
#include "superscalar/watchtower.h"
#include "superscalar/admin_rpc.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_musig.h>
#include <sqlite3.h>
#include <cJSON.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <poll.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int  hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);
extern void chain_backend_regtest_init(chain_backend_t *backend, regtest_t *rt);

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while (0)

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static void ex_seckey(size_t i, unsigned char sk[32]) {
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "exit-path-key-%zu", i);
    sha256((const unsigned char *)buf, (size_t)n, sk);
}

static int ex_keys(secp256k1_context *ctx, size_t n, secp256k1_keypair *kps,
                   secp256k1_pubkey *pks) {
    for (size_t i = 0; i < n; i++) {
        unsigned char sk[32];
        ex_seckey(i, sk);
        if (!secp256k1_keypair_create(ctx, &kps[i], sk)) return 0;
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }
    return 1;
}

static int ex_funding_spk(secp256k1_context *ctx, const secp256k1_pubkey *pks,
                          size_t n, unsigned char spk[34], unsigned char tw_ser[32]) {
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks, n)) return 0;
    unsigned char agg_ser[32], tweak[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, agg_ser, &ka.agg_pubkey)) return 0;
    sha256_tagged("TapTweak", agg_ser, 32, tweak);
    musig_keyagg_t k2 = ka;
    secp256k1_pubkey tw;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tw, &k2.cache, tweak)) return 0;
    secp256k1_xonly_pubkey x;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &x, NULL, &tw)) return 0;
    build_p2tr_script_pubkey(spk, &x);
    if (tw_ser && !secp256k1_xonly_pubkey_serialize(ctx, tw_ser, &x)) return 0;
    return 1;
}

/* When set, ex_build_factory gives the factory this L-stock seed, so leaf
   L-stock outputs are hashlocked and their state counter advances. */
static const unsigned char *g_ex_seed;

static int ex_build_factory(secp256k1_context *ctx, factory_t *f,
                            const secp256k1_keypair *kps, size_t n,
                            factory_arity_t arity,
                            const unsigned char fund_txid[32], uint32_t vout,
                            uint64_t amount, const unsigned char spk[34],
                            uint16_t step, uint32_t states, int sign) {
    /* factory_init zeroes the struct and allocates its own arrays. */
    if (!factory_init(f, ctx, kps, n, step, states)) return 0;
    if (g_ex_seed) factory_set_shachain_seed(f, g_ex_seed);
    factory_set_arity(f, arity);
    f->fee_per_tx = 1000;
    factory_set_funding(f, fund_txid, vout, amount, spk, 34);
    if (!factory_build_tree(f)) return 0;
    if (sign && !factory_sign_all(f)) return 0;
    return 1;
}

static void ex_txid_hex(const unsigned char internal[32], char out[65]) {
    unsigned char d[32];
    memcpy(d, internal, 32);
    reverse_bytes(d, 32);
    hex_encode(d, 32, out);
}

static void ex_db_path(char *out, size_t cap, const char *tag) {
    snprintf(out, cap, "/tmp/ss_exit_%s_%d.db", tag, (int)getpid());
    char p[300];
    unlink(out);
    snprintf(p, sizeof(p), "%s-wal", out); unlink(p);
    snprintf(p, sizeof(p), "%s-shm", out); unlink(p);
}

static int ex_persist_factory(persist_t *db, const char *path, factory_t *f,
                              secp256k1_context *ctx) {
    if (!persist_open(db, path)) return 0;
    if (!persist_save_factory(db, f, ctx, 0)) return 0;
    if (!persist_save_tree_nodes(db, f, 0)) return 0;
    return 1;
}

static __attribute__((unused)) int ex_sql_int(persist_t *db, const char *sql) {
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int v = (sqlite3_step(st) == SQLITE_ROW) ? sqlite3_column_int(st, 0) : -1;
    sqlite3_finalize(st);
    return v;
}

static void ex_sql_text(persist_t *db, const char *sql, char *out, size_t cap) {
    out[0] = '\0';
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db->db, sql, -1, &st, NULL) != SQLITE_OK) return;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *t = (const char *)sqlite3_column_text(st, 0);
        snprintf(out, cap, "%s", t ? t : "");
    }
    sqlite3_finalize(st);
}

/* txid (display hex) of a raw TX: double-SHA256 of the non-witness form. */
static int ex_rd_varint(const unsigned char *b, size_t len, size_t *pos, uint64_t *v) {
    if (*pos >= len) return 0;
    unsigned char c = b[(*pos)++];
    size_t n = c < 0xFD ? 0 : c == 0xFD ? 2 : c == 0xFE ? 4 : 8;
    if (n == 0) { *v = c; return 1; }
    if (*pos + n > len) return 0;
    uint64_t x = 0;
    for (size_t i = 0; i < n; i++) x |= (uint64_t)b[*pos + i] << (8 * i);
    *pos += n;
    *v = x;
    return 1;
}

static int ex_txid_of_hex(const char *hex, char out[65]) {
    size_t hl = strlen(hex);
    if (hl < 20 || (hl & 1)) return 0;
    size_t len = hl / 2;
    unsigned char *b = malloc(len);
    if (!b || hex_decode(hex, b, len) != (int)len) { free(b); return 0; }
    size_t pos = 4;
    int seg = (b[4] == 0 && b[5] == 1);
    if (seg) pos += 2;
    size_t body = pos;
    uint64_t nin, nout, v;
    int ok = 0;
    do {
        if (!ex_rd_varint(b, len, &pos, &nin)) break;
        int bad = 0;
        for (uint64_t i = 0; i < nin && !bad; i++) {
            pos += 36;
            if (!ex_rd_varint(b, len, &pos, &v)) { bad = 1; break; }
            pos += (size_t)v + 4;
        }
        if (bad || !ex_rd_varint(b, len, &pos, &nout)) break;
        for (uint64_t o = 0; o < nout && !bad; o++) {
            pos += 8;
            if (!ex_rd_varint(b, len, &pos, &v)) { bad = 1; break; }
            pos += (size_t)v;
        }
        if (bad) break;
        size_t body_end = pos;
        if (seg) {
            for (uint64_t i = 0; i < nin && !bad; i++) {
                uint64_t items;
                if (!ex_rd_varint(b, len, &pos, &items)) { bad = 1; break; }
                for (uint64_t k = 0; k < items; k++) {
                    if (!ex_rd_varint(b, len, &pos, &v)) { bad = 1; break; }
                    pos += (size_t)v;
                }
            }
        }
        if (bad || pos + 4 != len) break;
        size_t sl = 8 + (body_end - body);
        unsigned char *s = malloc(sl);
        if (!s) break;
        memcpy(s, b, 4);
        memcpy(s + 4, b + body, body_end - body);
        memcpy(s + 4 + (body_end - body), b + pos, 4);
        unsigned char h[32];
        sha256_double(s, sl, h);
        free(s);
        ex_txid_hex(h, out);
        ok = 1;
    } while (0);
    free(b);
    return ok;
}

/* ------------------------------------------------------------------ */
/* Mock chain backend: accepts every TX, "mines" on request.            */
/* ------------------------------------------------------------------ */

#define EX_MOCK_MAX 8192
static struct {
    char   txid[EX_MOCK_MAX][65];
    int    confs[EX_MOCK_MAX];
    size_t n;
    int    height;
    char   funding_txid[65];
    int    funding_confs;
    int    n_send_calls;
    int    n_send_ok;
    char   spent_prev[65];      /* outpoint reported spent by is_outpoint_unspent */
    int    reject_sends;        /* send_raw_tx fails (node rejects the TX) */
} g_mk;

static int mk_find(const char *txid) {
    for (size_t i = 0; i < g_mk.n; i++)
        if (strcasecmp(g_mk.txid[i], txid) == 0) return (int)i;
    return -1;
}
static int mk_height(chain_backend_t *s) { (void)s; return g_mk.height; }
static int mk_confs(chain_backend_t *s, const char *txid) {
    (void)s;
    if (g_mk.funding_txid[0] && strcasecmp(txid, g_mk.funding_txid) == 0)
        return g_mk.funding_confs;
    int i = mk_find(txid);
    return i < 0 ? -1 : g_mk.confs[i];
}
static int mk_batch(chain_backend_t *s, const char **t, size_t n, int *out) {
    for (size_t i = 0; i < n; i++) out[i] = mk_confs(s, t[i]);
    return 1;
}
static bool mk_mempool(chain_backend_t *s, const char *txid) {
    return mk_confs(s, txid) == 0;
}
static int mk_unspent(chain_backend_t *s, const char *txid, uint32_t vout) {
    (void)s; (void)vout;
    return (g_mk.spent_prev[0] && strcasecmp(txid, g_mk.spent_prev) == 0) ? 0 : 1;
}
static int mk_send(chain_backend_t *s, const char *hex, char *txid_out) {
    (void)s;
    g_mk.n_send_calls++;
    if (g_mk.reject_sends) return 0;
    char txid[65];
    if (!ex_txid_of_hex(hex, txid)) return 0;
    int at = mk_find(txid);
    if (at < 0 && g_mk.n < EX_MOCK_MAX) {
        memcpy(g_mk.txid[g_mk.n], txid, 65);
        g_mk.confs[g_mk.n] = 0;
        g_mk.n++;
    } else if (at >= 0 && g_mk.confs[at] < 0) {
        g_mk.confs[at] = 0;                 /* evicted earlier: back in mempool */
    }
    g_mk.n_send_ok++;
    if (txid_out) memcpy(txid_out, txid, 65);
    return 1;
}
static void mk_mine(void) {
    g_mk.height++;
    for (size_t i = 0; i < g_mk.n; i++)
        if (g_mk.confs[i] >= 0) g_mk.confs[i]++;
}
static void mk_set(const char *txid, int confs) {
    int i = mk_find(txid);
    if (i < 0) {
        if (g_mk.n >= EX_MOCK_MAX) return;
        i = (int)g_mk.n++;
        memcpy(g_mk.txid[i], txid, 65);
    }
    g_mk.confs[i] = confs;
}
static void mk_init(chain_backend_t *cb, const unsigned char fund_txid[32]) {
    memset(&g_mk, 0, sizeof(g_mk));
    g_mk.height = 1000;
    g_mk.funding_confs = 50;
    if (fund_txid) ex_txid_hex(fund_txid, g_mk.funding_txid);
    memset(cb, 0, sizeof(*cb));
    cb->get_block_height = mk_height;
    cb->get_confirmations = mk_confs;
    cb->get_confirmations_batch = mk_batch;
    cb->is_in_mempool = mk_mempool;
    cb->is_outpoint_unspent = mk_unspent;
    cb->send_raw_tx = mk_send;
    cb->is_regtest = 1;
    conf_targets_default(&cb->conf);
}

/* Run force-close passes, mining one mock block after each, until no new TX is
   accepted for `quiet` consecutive passes. Returns the last pass's rc. */
static int ex_mock_force_close(persist_t *db, chain_backend_t *cb, int max_passes,
                           int quiet, int *first_rc, char *st, size_t cap) {
    int rc = 0, idle = 0;
    for (int it = 0; it < max_passes && idle < quiet; it++) {
        int before = g_mk.n_send_ok;
        rc = factory_recovery_run(db, cb, 0, st, cap);
        if (it == 0 && first_rc) *first_rc = rc;
        idle = (g_mk.n_send_ok == before) ? idle + 1 : 0;
        mk_mine();
    }
    return rc;
}

/* ================================================================== */
/* Section 1 — reproduce without the fixes                              */
/* ================================================================== */

/* a 64-client arity-1 factory (> 128 tree nodes).  Every node must be
   published, including the leaves at index >= 128. */
int test_exit_force_close_publishes_nodes_past_128(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    const size_t N = 65;
    secp256k1_keypair *kps = calloc(N, sizeof(*kps));
    secp256k1_pubkey  *pks = calloc(N, sizeof(*pks));
    TEST_ASSERT(kps && pks && ex_keys(ctx, N, kps, pks), "keys");
    unsigned char spk[34], fund_txid[32];
    TEST_ASSERT(ex_funding_spk(ctx, pks, N, spk, NULL), "spk");
    memset(fund_txid, 0x42, 32);

    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f, "alloc");
    TEST_ASSERT(ex_build_factory(ctx, f, kps, N, FACTORY_ARITY_1, fund_txid, 0,
                                 64ULL * 400000ULL, spk, 1, 2, 1),
                "build + sign 65-signer factory");
    printf("  factory: %zu tree nodes, %d leaves\n", f->n_nodes, f->n_leaf_nodes);
    TEST_ASSERT(f->n_nodes > 128, "shape crosses 128 nodes");

    char path[256];
    ex_db_path(path, sizeof(path), "past128");
    persist_t db;
    TEST_ASSERT(ex_persist_factory(&db, path, f, ctx), "persist");

    chain_backend_t cb;
    mk_init(&cb, fund_txid);
    char st[512];
    int rc = ex_mock_force_close(&db, &cb, 400, 5, NULL, st, sizeof(st));
    printf("  last pass rc=%d: %s\n", rc, st);

    size_t missing = 0, first_missing = 0, max_leaf = 0;
    for (size_t i = 0; i < f->n_nodes; i++) {
        char tx[65];
        ex_txid_hex(f->nodes[i].txid, tx);
        if (mk_confs(&cb, tx) < 1) {
            if (!missing) first_missing = i;
            missing++;
        }
    }
    for (int l = 0; l < f->n_leaf_nodes; l++)
        if (f->leaf_node_indices[l] > max_leaf) max_leaf = f->leaf_node_indices[l];
    printf("  %zu of %zu nodes never published (first: %zu); highest leaf index %zu\n",
           missing, f->n_nodes, missing ? first_missing : 0, max_leaf);
    /* Walk the highest-index leaf's path to the root. */
    int path_ok = 1, depth = 0;
    for (int i = (int)max_leaf; i >= 0; i = f->nodes[i].parent_index, depth++) {
        char tx[65];
        ex_txid_hex(f->nodes[i].txid, tx);
        if (mk_confs(&cb, tx) < 1) path_ok = 0;
    }
    printf("  path of leaf %zu (%d TXs) fully published: %s\n",
           max_leaf, depth, path_ok ? "yes" : "NO");
    TEST_ASSERT(max_leaf >= 128, "a client leaf sits at index >= 128");
    TEST_ASSERT(path_ok, "client path including nodes >= 128 published");
    TEST_ASSERT(missing == 0, "every tree node published");
    TEST_ASSERT(rc == 1, "a settled pass reports success");

    persist_close(&db);
    unlink(path);
    factory_free(f); free(f); free(kps); free(pks);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* a needed node that cannot be published is a reported failure. */
int test_exit_force_close_reports_unpublishable_node(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    const size_t N = 5;
    secp256k1_keypair kps[5];
    secp256k1_pubkey pks[5];
    TEST_ASSERT(ex_keys(ctx, N, kps, pks), "keys");
    unsigned char spk[34], fund_txid[32];
    TEST_ASSERT(ex_funding_spk(ctx, pks, N, spk, NULL), "spk");
    memset(fund_txid, 0x43, 32);
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(ex_build_factory(ctx, f, kps, N, FACTORY_ARITY_2, fund_txid, 0,
                                 2000000, spk, 1, 2, 1), "build");
    char path[256];
    ex_db_path(path, sizeof(path), "unpub");
    persist_t db;
    TEST_ASSERT(ex_persist_factory(&db, path, f, ctx), "persist");
    char sql[160];
    int leaf = f->leaf_node_indices[f->n_leaf_nodes - 1];
    snprintf(sql, sizeof(sql),
             "UPDATE tree_nodes SET signed_tx_hex=NULL WHERE factory_id=0 AND node_index=%d",
             leaf);
    TEST_ASSERT(sqlite3_exec(db.db, sql, NULL, NULL, NULL) == SQLITE_OK, "drop leaf bytes");

    chain_backend_t cb;
    mk_init(&cb, fund_txid);
    char st[512];
    int first_rc = -1;
    int rc = ex_mock_force_close(&db, &cb, 100, 4, &first_rc, st, sizeof(st));
    printf("  first pass rc=%d, last pass rc=%d: %s\n", first_rc, rc, st);
    TEST_ASSERT(first_rc == 0, "pass with an unpublishable node reports failure");
    TEST_ASSERT(rc == 0, "still failing once everything else is published");

    persist_close(&db);
    unlink(path);
    factory_free(f); free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* a fully confirmed tree marks the factory closed (leaf match uses the
   types persist_save_tree_nodes actually writes). */
int test_exit_scan_marks_settled_factory_closed(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    const size_t N = 5;
    secp256k1_keypair kps[5];
    secp256k1_pubkey pks[5];
    TEST_ASSERT(ex_keys(ctx, N, kps, pks), "keys");
    unsigned char spk[34], fund_txid[32];
    TEST_ASSERT(ex_funding_spk(ctx, pks, N, spk, NULL), "spk");
    memset(fund_txid, 0x44, 32);
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(ex_build_factory(ctx, f, kps, N, FACTORY_ARITY_2, fund_txid, 0,
                                 2000000, spk, 1, 2, 1), "build");
    char path[256];
    ex_db_path(path, sizeof(path), "settled");
    persist_t db;
    TEST_ASSERT(ex_persist_factory(&db, path, f, ctx), "persist");

    chain_backend_t cb;
    mk_init(&cb, fund_txid);
    for (size_t i = 0; i < f->n_nodes; i++) {
        char tx[65];
        ex_txid_hex(f->nodes[i].txid, tx);
        mk_set(tx, 10);
    }
    cJSON *list = factory_recovery_list(&db, &cb);
    cJSON *f0 = cJSON_GetArrayItem(list, 0);
    int n_leaf = f0 ? cJSON_GetObjectItem(f0, "n_leaf")->valueint : -1;
    int n_leaf_conf = f0 ? cJSON_GetObjectItem(f0, "n_leaf_confirmed")->valueint : -1;
    cJSON_Delete(list);
    printf("  listfactories: n_leaf=%d n_leaf_confirmed=%d (tree has %d leaves)\n",
           n_leaf, n_leaf_conf, f->n_leaf_nodes);

    factory_recovery_scan(&db, &cb);
    char state[32];
    ex_sql_text(&db, "SELECT state FROM factories WHERE id=0", state, sizeof(state));
    printf("  factory state after scan: %s\n", state);
    TEST_ASSERT(n_leaf == f->n_leaf_nodes, "leaves recognised");
    TEST_ASSERT(n_leaf_conf == f->n_leaf_nodes, "confirmed leaves counted");
    TEST_ASSERT(strcmp(state, "closed") == 0, "settled factory auto-closed");

    persist_close(&db);
    unlink(path);
    factory_free(f); free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* an advanced PS leaf is published as chain[0..N]
   from ps_initial_signed_states + ps_leaf_chains, the rows the LSP writes. */
int test_exit_force_close_publishes_full_ps_chain(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    const size_t N = 3;
    secp256k1_keypair kps[3];
    secp256k1_pubkey pks[3];
    TEST_ASSERT(ex_keys(ctx, N, kps, pks), "keys");
    unsigned char spk[34], fund_txid[32];
    TEST_ASSERT(ex_funding_spk(ctx, pks, N, spk, NULL), "spk");
    memset(fund_txid, 0x45, 32);
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(ex_build_factory(ctx, f, kps, N, FACTORY_ARITY_PS, fund_txid, 0,
                                 2000000, spk, 1, 2, 1), "build PS factory");
    char path[256];
    ex_db_path(path, sizeof(path), "pschain");
    persist_t db;
    TEST_ASSERT(ex_persist_factory(&db, path, f, ctx), "persist");
    TEST_ASSERT(lsp_persist_ps_chain0_all(&db, f) > 0, "chain[0] rows (creation)");

    size_t leaf = f->leaf_node_indices[0];
    char chain_txid[3][65];
    ex_txid_hex(f->nodes[leaf].txid, chain_txid[0]);
    for (int k = 1; k <= 2; k++) {
        TEST_ASSERT(factory_advance_leaf(f, 0), "PS leaf advance");
        factory_node_t *nd = &f->nodes[leaf];
        unsigned char disp[32];
        memcpy(disp, nd->txid, 32);
        reverse_bytes(disp, 32);
        /* what the LSP's leaf-advance Step 11 writes */
        TEST_ASSERT(persist_save_ps_chain_entry(&db, 0, (uint32_t)leaf,
                        nd->ps_chain_len - 1, f->counter.current_epoch, disp,
                        nd->signed_tx.data, nd->signed_tx.len,
                        nd->outputs[0].amount_sats, NULL, 0), "chain row");
        ex_txid_hex(nd->txid, chain_txid[k]);
    }

    chain_backend_t cb;
    mk_init(&cb, fund_txid);
    char st[512];
    int rc = ex_mock_force_close(&db, &cb, 100, 4, NULL, st, sizeof(st));
    printf("  last pass rc=%d: %s\n", rc, st);
    for (int k = 0; k <= 2; k++)
        printf("  chain[%d] %.16s... confs=%d\n", k, chain_txid[k],
               mk_confs(&cb, chain_txid[k]));
    TEST_ASSERT(mk_confs(&cb, chain_txid[0]) >= 1, "chain[0] published");
    TEST_ASSERT(mk_confs(&cb, chain_txid[1]) >= 1, "chain[1] published");
    TEST_ASSERT(mk_confs(&cb, chain_txid[2]) >= 1, "chain[2] (current state) published");

    persist_close(&db);
    unlink(path);
    factory_free(f); free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* recoverfactory needs an explicit factory_id and is a dry run unless
   dry_run:false is passed. */
int test_exit_recoverfactory_is_gated(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    const size_t N = 5;
    secp256k1_keypair kps[5];
    secp256k1_pubkey pks[5];
    TEST_ASSERT(ex_keys(ctx, N, kps, pks), "keys");
    unsigned char spk[34], fund_txid[32];
    TEST_ASSERT(ex_funding_spk(ctx, pks, N, spk, NULL), "spk");
    memset(fund_txid, 0x46, 32);
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(ex_build_factory(ctx, f, kps, N, FACTORY_ARITY_2, fund_txid, 0,
                                 2000000, spk, 1, 2, 1), "build");
    char path[256];
    ex_db_path(path, sizeof(path), "rpcgate");
    persist_t db;
    TEST_ASSERT(ex_persist_factory(&db, path, f, ctx), "persist");

    chain_backend_t cb;
    mk_init(&cb, fund_txid);
    watchtower_t *wt = calloc(1, sizeof(*wt));
    lsp_channel_mgr_t *mgr = calloc(1, sizeof(*mgr));
    TEST_ASSERT(wt && mgr, "alloc");
    wt->chain = &cb;
    mgr->watchtower = wt;
    mgr->persist = &db;
    admin_rpc_t rpc;
    memset(&rpc, 0, sizeof(rpc));
    rpc.listen_fd = -1;
    rpc.channel_mgr = mgr;

    char out[2048];
    admin_rpc_handle_request(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"recoverfactory\","
        "\"params\":{\"factory_id\":0}}", out, sizeof(out));
    printf("  {factory_id:0} -> %s\n", out);
    int sends_default = g_mk.n_send_calls;
    TEST_ASSERT(sends_default == 0, "default call broadcasts nothing (dry run)");

    admin_rpc_handle_request(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"recoverfactory\","
        "\"params\":{}}", out, sizeof(out));
    printf("  {} -> %s\n", out);
    cJSON *r = cJSON_Parse(out);
    int is_err = r && cJSON_IsObject(cJSON_GetObjectItem(r, "error"));
    cJSON_Delete(r);
    TEST_ASSERT(is_err, "missing factory_id is an error");
    TEST_ASSERT(g_mk.n_send_calls == 0, "missing factory_id broadcasts nothing");

    admin_rpc_handle_request(&rpc,
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"recoverfactory\","
        "\"params\":{\"factory_id\":0,\"dry_run\":false}}", out, sizeof(out));
    printf("  {factory_id:0, dry_run:false} -> %s\n", out);
    TEST_ASSERT(g_mk.n_send_calls > 0, "explicit dry_run:false broadcasts");

    persist_close(&db);
    unlink(path);
    free(wt); free(mgr);
    factory_free(f); free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Regtest helpers                                                      */
/* ------------------------------------------------------------------ */

static int ex_rt_setup(regtest_t *rt, const char *wallet, char *mine_addr, size_t cap) {
    if (!regtest_init(rt)) return 0;
    regtest_create_wallet(rt, wallet);
    rt->scan_depth = 400;
    if (!regtest_get_new_address(rt, mine_addr, cap)) return 0;
    if (!regtest_fund_from_faucet(rt, 2.0))
        regtest_mine_blocks(rt, 101, mine_addr);
    return 1;
}

static int ex_rt_fund(regtest_t *rt, secp256k1_context *ctx,
                      const secp256k1_pubkey *pks, size_t n, double btc,
                      const char *mine_addr, unsigned char spk[34],
                      unsigned char txid_internal[32], char txid_hex[65],
                      uint32_t *vout, uint64_t *amount) {
    unsigned char tw[32];
    if (!ex_funding_spk(ctx, pks, n, spk, tw)) return 0;
    char addr[128];
    if (!regtest_derive_p2tr_address(rt, tw, addr, sizeof(addr))) return 0;
    if (!regtest_fund_address(rt, addr, btc, txid_hex)) return 0;
    regtest_mine_blocks(rt, 1, mine_addr);
    *vout = UINT32_MAX;
    for (uint32_t v = 0; v < 4; v++) {
        uint64_t a = 0; unsigned char s[64]; size_t sl = 0;
        if (regtest_get_tx_output(rt, txid_hex, v, &a, s, &sl) &&
            sl == 34 && memcmp(s, spk, 34) == 0) {
            *vout = v; *amount = a; break;
        }
    }
    if (*vout == UINT32_MAX) return 0;
    if (!hex_decode(txid_hex, txid_internal, 32)) return 0;
    reverse_bytes(txid_internal, 32);
    return 1;
}

/* On regtest: 64 clients, 254-node tree.  The client whose leaf has the
   highest node index self-exits with factory_recovery_run (as
   superscalar_client --force-close does); its whole path must confirm and its
   channel output must land in the UTXO set. */
int test_regtest_exit_client_path_past_128(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    char mine_addr[128];
    if (!ex_rt_setup(&rt, "exit_past128", mine_addr, sizeof(mine_addr))) {
        printf("  FAIL: bitcoind not available\n");
        return 0;
    }
    const size_t N = 65;
    secp256k1_keypair *kps = calloc(N, sizeof(*kps));
    secp256k1_pubkey  *pks = calloc(N, sizeof(*pks));
    TEST_ASSERT(kps && pks && ex_keys(ctx, N, kps, pks), "keys");
    unsigned char spk[34], fund_txid[32];
    char fund_hex[65];
    uint32_t vout; uint64_t amount;
    TEST_ASSERT(ex_rt_fund(&rt, ctx, pks, N, 0.5, mine_addr, spk, fund_txid,
                           fund_hex, &vout, &amount), "fund");
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(ex_build_factory(ctx, f, kps, N, FACTORY_ARITY_1, fund_txid, vout,
                                 amount, spk, 1, 2, 1), "build + sign");
    printf("  factory: %zu tree nodes, %d leaves\n", f->n_nodes, f->n_leaf_nodes);
    TEST_ASSERT(f->n_nodes > 128, "> 128 nodes");

    size_t leaf = 0;
    for (int l = 0; l < f->n_leaf_nodes; l++)
        if (f->leaf_node_indices[l] > leaf) leaf = f->leaf_node_indices[l];
    TEST_ASSERT(leaf >= 128, "target leaf index >= 128");
    char leaf_txid[65];
    ex_txid_hex(f->nodes[leaf].txid, leaf_txid);
    uint32_t client = f->nodes[leaf].signer_indices[1];
    printf("  client %u: leaf node %zu (%.16s...)\n", client, leaf, leaf_txid);

    /* The client's DB holds the same signed tree (FACTORY_READY). */
    char path[256];
    ex_db_path(path, sizeof(path), "rt_past128");
    persist_t db;
    TEST_ASSERT(ex_persist_factory(&db, path, f, ctx), "persist");

    chain_backend_t cb;
    chain_backend_regtest_init(&cb, &rt);
    char st[512] = {0};
    int rc = 0, iters = 0;
    for (; iters < 80; iters++) {
        rc = factory_recovery_run(&db, &cb, 0, st, sizeof(st));
        if (iters < 3 || iters % 10 == 0)
            printf("  pass %d rc=%d: %s\n", iters, rc, st);
        if (regtest_get_confirmations(&rt, leaf_txid) >= 1) break;
        regtest_mine_blocks(&rt, 1, mine_addr);
    }
    printf("  after %d passes (rc=%d): %s\n", iters, rc, st);

    int path_ok = 1, depth = 0;
    for (int i = (int)leaf; i >= 0; i = f->nodes[i].parent_index, depth++) {
        char tx[65];
        ex_txid_hex(f->nodes[i].txid, tx);
        int c = regtest_get_confirmations(&rt, tx);
        if (c < 1) { path_ok = 0; printf("  path node %d not confirmed\n", i); }
    }
    TEST_ASSERT(path_ok, "every TX on the client's path confirmed");

    /* The client's channel output (leaf vout for this client) is on chain,
       unspent, paying the leaf's channel SPK. */
    uint32_t cvout = 0;
    size_t cnode = 0;
    TEST_ASSERT(factory_client_to_leaf(f, client - 1, &cnode, &cvout), "client_to_leaf");
    TEST_ASSERT(cnode == leaf, "client maps to that leaf");
    uint64_t amt = 0; unsigned char s[64]; size_t sl = 0;
    TEST_ASSERT(regtest_get_tx_output(&rt, leaf_txid, cvout, &amt, s, &sl),
                "leaf output exists");
    TEST_ASSERT(sl == f->nodes[leaf].outputs[cvout].script_pubkey_len &&
                memcmp(s, f->nodes[leaf].outputs[cvout].script_pubkey, sl) == 0,
                "output pays the client's channel SPK");
    TEST_ASSERT(amt == f->nodes[leaf].outputs[cvout].amount_sats, "output amount");
    TEST_ASSERT(regtest_outpoint_unspent(&rt, leaf_txid, cvout) == 1,
                "client's channel output unspent in the UTXO set");
    printf("  client %u channel output %s:%u = %llu sats on chain (path of %d TXs)\n",
           client, leaf_txid, cvout, (unsigned long long)amt, depth);

    persist_close(&db);
    unlink(path);
    factory_free(f); free(f); free(kps); free(pks);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Socketpair client for the LSP's real leaf-advance ceremony. */
typedef struct {
    int fd;
    secp256k1_context *ctx;
    secp256k1_keypair kp;
    factory_t *f;
    uint32_t my_index;
    int n_expected;
    int ok;
} ex_client_t;

static void *ex_client_thread(void *arg) {
    ex_client_t *c = (ex_client_t *)arg;
    int done = 0;
    c->ok = 1;
    while (c->n_expected < 0 || done < c->n_expected) {
        wire_msg_t msg;
        memset(&msg, 0, sizeof(msg));
        if (!wire_recv(c->fd, &msg)) { c->ok = 0; break; }
        wire_msg_t pm = { .msg_type = msg.msg_type, .json = msg.json };
        if (msg.msg_type == MSG_LEAF_ADVANCE_PROPOSE) {
            /* The stateless handler runs the whole ceremony, including the
               LSP's LEAF_ADVANCE_DONE. */
            if (client_handle_leaf_advance(c->fd, c->ctx, &c->kp, c->f,
                                           c->my_index, &pm))
                done++;
            else
                c->ok = 0;
        } else if (msg.msg_type == MSG_LEAF_REALLOC_PROPOSE) {
            if (client_handle_leaf_realloc(c->fd, c->ctx, &c->kp, c->f,
                                           c->my_index, &pm))
                done++;
            else
                c->ok = 0;
        } else if (msg.msg_type == MSG_STATE_ADV_PROPOSE_INTENT ||
                   msg.msg_type == MSG_STATE_ADVANCE_PROPOSE) {
            /* Tier B rollover: the stateless handler runs the whole re-sign
               ceremony; PATH_SIGN_DONE follows as a separate message. */
            if (client_handle_state_advance(c->fd, c->ctx, &c->kp, c->f,
                                            c->my_index, &pm))
                done++;
            else
                c->ok = 0;
        } else if (msg.msg_type == MSG_PATH_SIGN_DONE) {
            /* end-of-Tier-B notification; nothing to sign */
        }
        if (msg.json) cJSON_Delete(msg.json);
        if (!c->ok) break;
    }
    return NULL;
}

/* drive the LSP's real leaf-advance ceremony n times against a client
   thread, then force-close from the LSP DB and check that the published leaf
   state is the latest one. */
static int ex_run_advance_then_force_close(factory_arity_t arity, const char *wallet,
                                       int n_adv) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    char mine_addr[128];
    if (!ex_rt_setup(&rt, wallet, mine_addr, sizeof(mine_addr))) {
        printf("  FAIL: bitcoind not available\n");
        return 0;
    }
    const size_t N = 3;
    secp256k1_keypair kps[3];
    secp256k1_pubkey pks[3];
    TEST_ASSERT(ex_keys(ctx, N, kps, pks), "keys");
    unsigned char spk[34], fund_txid[32];
    char fund_hex[65];
    uint32_t vout; uint64_t amount;
    TEST_ASSERT(ex_rt_fund(&rt, ctx, pks, N, 0.01, mine_addr, spk, fund_txid,
                           fund_hex, &vout, &amount), "fund");

    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    TEST_ASSERT(lsp && lsp_init(lsp, ctx, &kps[0], 0, 2), "lsp_init");
    factory_t *lf = &lsp->factory;
    TEST_ASSERT(ex_build_factory(ctx, lf, kps, N, arity, fund_txid, vout, amount,
                                 spk, 2, 4, 1), "LSP factory");
    factory_t *cf = calloc(1, sizeof(factory_t));
    /* The client holds the same signed tree (FACTORY_READY). */
    TEST_ASSERT(cf && ex_build_factory(ctx, cf, kps, N, arity, fund_txid, vout,
                                       amount, spk, 2, 4, 1), "client factory copy");

    /* Creation-time persistence, as tools/superscalar_lsp.c does it. */
    char path[256];
    ex_db_path(path, sizeof(path), wallet);
    persist_t db;
    TEST_ASSERT(ex_persist_factory(&db, path, lf, ctx), "persist creation");
    if (arity == FACTORY_ARITY_PS) lsp_persist_ps_chain0_all(&db, lf);

    size_t leaf = lf->leaf_node_indices[0];
    char old_txid[65];
    ex_txid_hex(lf->nodes[leaf].txid, old_txid);

    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    {   /* a protocol mismatch fails the test instead of hanging it */
        struct timeval tv = { .tv_sec = 180, .tv_usec = 0 };
        setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    lsp->client_fds[0] = sv[0];
    lsp->client_fds[1] = -1;
    lsp->n_clients = 2;
    lsp->client_pubkeys[0] = pks[1];
    lsp->client_pubkeys[1] = pks[2];

    lsp_channel_mgr_t *mgr = calloc(1, sizeof(*mgr));
    TEST_ASSERT(mgr, "mgr");
    mgr->ctx = ctx;
    mgr->persist = &db;
    mgr->bridge_fd = -1;
    /* With a watchtower the LSP co-signs the superseded state's poison, as
       production does; the client expects it. */
    watchtower_t *wt = calloc(1, sizeof(watchtower_t));
    TEST_ASSERT(wt && watchtower_init(wt, 2, &rt, NULL, &db), "watchtower");
    mgr->watchtower = wt;

    alarm(900);   /* hang guard */
    ex_client_t cl = { .fd = sv[1], .ctx = ctx, .kp = kps[1], .f = cf,
                       .my_index = 1, .n_expected = n_adv, .ok = 0 };
    pthread_t th;
    TEST_ASSERT(pthread_create(&th, NULL, ex_client_thread, &cl) == 0, "thread");
    int adv_ok = 1;
    for (int k = 0; k < n_adv && adv_ok; k++)
        adv_ok = (lsp_channels_advance_ps_leaf(mgr, lsp, 0) == 1);
    if (!adv_ok) shutdown(sv[0], SHUT_RDWR);
    pthread_join(th, NULL);
    TEST_ASSERT(adv_ok, "LSP leaf advance ceremony");
    TEST_ASSERT(cl.ok, "client side of the ceremony");

    char new_txid[65];
    ex_txid_hex(lf->nodes[leaf].txid, new_txid);
    printf("  leaf node %zu: creation state %.16s..., after %d advance(s) %.16s...\n",
           leaf, old_txid, n_adv, new_txid);
    TEST_ASSERT(strcmp(old_txid, new_txid) != 0, "advance changed the leaf TX");

    /* LSP force-close from its DB. */
    chain_backend_t cb;
    chain_backend_regtest_init(&cb, &rt);
    char st[512] = {0};
    int rc = 0, it = 0;
    for (; it < 60; it++) {
        rc = factory_recovery_run(&db, &cb, 0, st, sizeof(st));
        if (regtest_get_confirmations(&rt, new_txid) >= 1) break;
        if (arity != FACTORY_ARITY_PS &&
            regtest_get_confirmations(&rt, old_txid) >= 1) break;
        regtest_mine_blocks(&rt, 1, mine_addr);
    }
    int c_new = regtest_get_confirmations(&rt, new_txid);
    int c_old = regtest_get_confirmations(&rt, old_txid);
    printf("  after %d passes (rc=%d): %s\n", it, rc, st);
    printf("  latest state confs=%d, creation-era state confs=%d\n", c_new, c_old);
    alarm(0);
    TEST_ASSERT(c_new >= 1, "force-close published the latest signed leaf state");
    if (arity != FACTORY_ARITY_PS)
        TEST_ASSERT(c_old < 1, "the superseded DW state was not published");

    close(sv[1]);
    lsp_cleanup(lsp);
    free(lsp);
    factory_free(cf); free(cf);
    watchtower_cleanup(wt); free(wt);
    free(mgr);
    persist_close(&db);
    unlink(path);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_regtest_exit_after_dw_leaf_advance(void) {
    return ex_run_advance_then_force_close(FACTORY_ARITY_1, "exit_dw_adv", 2);
}

int test_regtest_exit_after_ps_leaf_advance(void) {
    return ex_run_advance_then_force_close(FACTORY_ARITY_PS, "exit_ps_adv", 2);
}

/* the LSP daemon's EXPIRED trigger fires before the distribution TX's
   nLockTime; the TX must still be broadcast once final and confirm. */
static volatile sig_atomic_t g_ex_dist_shutdown = 0;
typedef struct {
    regtest_t rt;
    char mine_addr[128];
    char dist_txid[65];
    int  confirmed_height;
    int  max_secs;
} ex_dist_helper_t;

static void *ex_dist_helper(void *arg) {
    ex_dist_helper_t *h = (ex_dist_helper_t *)arg;
    time_t start = time(NULL);
    while (time(NULL) - start < h->max_secs) {
        sleep(3);
        if (regtest_get_confirmations(&h->rt, h->dist_txid) >= 1) {
            h->confirmed_height = regtest_get_block_height(&h->rt);
            break;
        }
        regtest_mine_blocks(&h->rt, 1, h->mine_addr);
    }
    g_ex_dist_shutdown = 1;
    return NULL;
}

int test_regtest_exit_distribution_tx_retried_after_locktime(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    char mine_addr[128];
    if (!ex_rt_setup(&rt, "exit_dist", mine_addr, sizeof(mine_addr))) {
        printf("  FAIL: bitcoind not available\n");
        return 0;
    }
    const size_t N = 3;
    secp256k1_keypair kps[3];
    secp256k1_pubkey pks[3];
    TEST_ASSERT(ex_keys(ctx, N, kps, pks), "keys");
    unsigned char spk[34], fund_txid[32];
    char fund_hex[65];
    uint32_t vout; uint64_t amount;
    TEST_ASSERT(ex_rt_fund(&rt, ctx, pks, N, 0.01, mine_addr, spk, fund_txid,
                           fund_hex, &vout, &amount), "fund");
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(ex_build_factory(ctx, f, kps, N, FACTORY_ARITY_2, fund_txid, vout,
                                 amount, spk, 1, 2, 1), "build");

    int h0 = regtest_get_block_height(&rt);
    uint32_t nlocktime = (uint32_t)h0 + 8;
    tx_output_t outs[3];
    uint64_t per = (amount - 1000) / 3;
    for (int i = 0; i < 3; i++) {
        secp256k1_xonly_pubkey x;
        secp256k1_xonly_pubkey_from_pubkey(ctx, &x, NULL, &pks[i]);
        build_p2tr_script_pubkey(outs[i].script_pubkey, &x);
        outs[i].script_pubkey_len = 34;
        outs[i].amount_sats = per;
    }
    tx_buf_t dist;
    tx_buf_init(&dist, 512);
    TEST_ASSERT(factory_build_distribution_tx(f, &dist, NULL, outs, 3, nlocktime),
                "build distribution TX");
    char *dhex = malloc(dist.len * 2 + 1);
    hex_encode(dist.data, dist.len, dhex);
    char dist_txid[65];
    TEST_ASSERT(ex_txid_of_hex(dhex, dist_txid), "dist txid");
    free(dhex);

    /* Ladder: one factory that turns EXPIRED two blocks from now, i.e. six
       blocks before the distribution TX is final (the non-regtest ordering). */
    ladder_t *lad = calloc(1, sizeof(ladder_t));
    TEST_ASSERT(lad, "ladder alloc");
    lad->ctx = ctx;
    lad->n_factories = 1;
    lad->current_block = (uint32_t)h0;
    ladder_factory_t *lfac = &lad->factories[0];
    lfac->factory_id = 0;
    lfac->is_initialized = 1;
    lfac->is_funded = 1;
    factory_set_lifecycle(&lfac->factory, (uint32_t)h0 - 8, 5, 5);
    lfac->cached_state = factory_get_state(&lfac->factory, (uint32_t)h0);
    tx_buf_init(&lfac->distribution_tx, (int)dist.len);
    memcpy(lfac->distribution_tx.data, dist.data, dist.len);
    lfac->distribution_tx.len = dist.len;
    TEST_ASSERT(lfac->cached_state == FACTORY_DYING, "starts DYING");

    char path[256];
    ex_db_path(path, sizeof(path), "dist");
    persist_t db;
    TEST_ASSERT(persist_open(&db, path), "db");

    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    TEST_ASSERT(lsp && lsp_init(lsp, ctx, &kps[0], 0, 1), "lsp_init");
    lsp->client_fds[0] = sv[0];
    lsp->n_clients = 1;

    watchtower_t *wt = calloc(1, sizeof(watchtower_t));
    TEST_ASSERT(wt && watchtower_init(wt, 1, &rt, NULL, &db), "watchtower");
    chain_backend_t cb;
    chain_backend_regtest_init(&cb, &rt);

    lsp_channel_mgr_t *mgr = calloc(1, sizeof(*mgr));
    TEST_ASSERT(mgr, "mgr");
    mgr->ctx = ctx;
    mgr->entries = calloc(1, sizeof(lsp_channel_entry_t));
    mgr->entries_cap = 1;
    mgr->n_channels = 1;
    /* The idle socketpair client must not be dropped as offline: with no fd
       left to poll the daemon loop skips its periodic (height) block. */
    mgr->entries[0].last_message_time = time(NULL) + 3600;
    mgr->bridge_fd = -1;
    mgr->persist = &db;
    mgr->watchtower = wt;
    mgr->chain_be = &cb;
    mgr->ladder = lad;

    ex_dist_helper_t *h = calloc(1, sizeof(*h));
    h->rt = rt;
    memcpy(h->mine_addr, mine_addr, sizeof(h->mine_addr));
    memcpy(h->dist_txid, dist_txid, 65);
    h->max_secs = 300;   /* slow (sanitizer) builds tick slower */
    g_ex_dist_shutdown = 0;
    pthread_t th;
    TEST_ASSERT(pthread_create(&th, NULL, ex_dist_helper, h) == 0, "helper");
    printf("  height %d: EXPIRED at %d, distribution TX nLockTime %u (%.16s...)\n",
           h0, h0 + 2, nlocktime, dist_txid);
    lsp_channels_run_daemon_loop(mgr, lsp, &g_ex_dist_shutdown);
    pthread_join(th, NULL);

    int confs = regtest_get_confirmations(&rt, dist_txid);
    int tip = regtest_get_block_height(&rt);
    int included = confs >= 1 ? tip - confs + 1 : -1;
    printf("  distribution TX confs=%d, included at height %d (nLockTime %u)\n",
           confs, included, nlocktime);
    TEST_ASSERT(confs >= 1, "distribution TX confirmed after its nLockTime");
    TEST_ASSERT(included > (int)nlocktime, "and not before it");

    close(sv[1]);
    free(h);
    watchtower_cleanup(wt); free(wt);
    free(mgr->entries); free(mgr);
    lsp_cleanup(lsp); free(lsp);
    tx_buf_free(&lfac->distribution_tx);
    free(lad);
    tx_buf_free(&dist);
    factory_free(f); free(f);
    persist_close(&db);
    unlink(path);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* when lsp_run_cooperative_close returns, the clients already hold the
   fully signed close.  The DB must say 'closing' and hold the close TX for
   re-broadcast BEFORE the LSP broadcasts anything. */
int test_regtest_exit_coop_close_persisted_before_done(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    char mine_addr[128];
    if (!ex_rt_setup(&rt, "exit_coop", mine_addr, sizeof(mine_addr))) {
        printf("  FAIL: bitcoind not available\n");
        return 0;
    }
    const size_t N = 5;
    secp256k1_keypair kps[5];
    secp256k1_pubkey pks[5];
    TEST_ASSERT(ex_keys(ctx, N, kps, pks), "keys");
    unsigned char spk[34], fund_txid[32];
    char fund_hex[65];
    uint32_t vout; uint64_t amount;
    TEST_ASSERT(ex_rt_fund(&rt, ctx, pks, N, 0.001, mine_addr, spk, fund_txid,
                           fund_hex, &vout, &amount), "fund");

    alarm(900);   /* hang guard: a stuck ceremony kills the run, not the box */
    int port = 21735 + (getpid() % 1000);
    /* Listen before the clients start so a slow DB open cannot make them
       miss the LSP. */
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    TEST_ASSERT(lsp && lsp_init(lsp, ctx, &kps[0], port, 4), "lsp_init");
    TEST_ASSERT(factory_alloc_default_arrays(&lsp->factory), "factory arrays");
    lsp->listen_fd = wire_listen(NULL, port);
    TEST_ASSERT(lsp->listen_fd >= 0, "listen");
    pid_t kids[4];
    for (int c = 0; c < 4; c++) {
        pid_t pid = fork();
        if (pid == 0) {
            usleep(100000 * (c + 1));
            secp256k1_context *cctx = secp256k1_context_create(
                SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
            int ok = client_run_ceremony(cctx, &kps[c + 1], "127.0.0.1", port);
            secp256k1_context_destroy(cctx);
            _exit(ok ? 0 : 1);
        }
        kids[c] = pid;
    }

    char path[256];
    ex_db_path(path, sizeof(path), "coop");
    persist_t db;
    TEST_ASSERT(persist_open(&db, path), "db");
    int ok = lsp_accept_clients(lsp) &&
             lsp_run_factory_creation(lsp, fund_txid, vout, amount, spk, 34,
                                      10, 4, 0);
    /* The factory row as the LSP writes it after creation; the close is what
       this test is about, so the DB handle is attached for the close only. */
    if (ok) ok = persist_save_factory(&db, &lsp->factory, ctx, 0);
    lsp->db = &db;

    char state[32] = {0};
    int queued_close = -1;
    char close_hex_q[16] = {0};
    if (ok) {
        uint64_t total = amount - 500, per = total / 5;
        tx_output_t outs[5];
        for (int i = 0; i < 5; i++) {
            outs[i].amount_sats = per;
            memcpy(outs[i].script_pubkey, spk, 34);
            outs[i].script_pubkey_len = 34;
        }
        outs[4].amount_sats = total - per * 4;
        tx_buf_t close_tx;
        tx_buf_init(&close_tx, 512);
        ok = lsp_run_cooperative_close(lsp, &close_tx, outs, 5, 0) == 1;
        if (ok) {
            /* Nothing has been broadcast yet. */
            ex_sql_text(&db, "SELECT state FROM factories WHERE id=0", state,
                        sizeof(state));
            char *chex = malloc(close_tx.len * 2 + 1);
            hex_encode(close_tx.data, close_tx.len, chex);
            sqlite3_stmt *stq;
            if (sqlite3_prepare_v2(db.db,
                    "SELECT COUNT(*) FROM broadcast_log WHERE raw_hex=? AND "
                    "result='queued'", -1, &stq, NULL) == SQLITE_OK) {
                sqlite3_bind_text(stq, 1, chex, -1, SQLITE_TRANSIENT);
                if (sqlite3_step(stq) == SQLITE_ROW)
                    queued_close = sqlite3_column_int(stq, 0);
                sqlite3_finalize(stq);
            }
            snprintf(close_hex_q, sizeof(close_hex_q), "%.8s", chex);
            free(chex);
        }
        tx_buf_free(&close_tx);
    }
    int lsp_closing = lsp->closing;
    lsp_cleanup(lsp);
    free(lsp);
    int kids_ok = 1;
    for (int c = 0; c < 4; c++) {
        int status;
        waitpid(kids[c], &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) kids_ok = 0;
    }
    printf("  close signed=%d clients_ok=%d; DB before broadcast: state=%s, "
           "queued close rows=%d\n", ok, kids_ok, state, queued_close);
    TEST_ASSERT(ok, "factory created + cooperative close signed");
    TEST_ASSERT(strcmp(state, "closing") == 0,
                "factory marked 'closing' before CLOSE_DONE / broadcast");
    TEST_ASSERT(queued_close == 1, "signed close queued for re-broadcast");
    TEST_ASSERT(lsp_closing, "the LSP stopped serving once the signed close was out");
    alarm(0);

    persist_close(&db);
    unlink(path);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* Section 2 — fix-only APIs                                            */
/* ================================================================== */

/* force-close dry run reports without sending; run_ex counters. */
int test_exit_force_close_dry_run_sends_nothing(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    const size_t N = 5;
    secp256k1_keypair kps[5];
    secp256k1_pubkey pks[5];
    TEST_ASSERT(ex_keys(ctx, N, kps, pks), "keys");
    unsigned char spk[34], fund_txid[32];
    TEST_ASSERT(ex_funding_spk(ctx, pks, N, spk, NULL), "spk");
    memset(fund_txid, 0x47, 32);
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(ex_build_factory(ctx, f, kps, N, FACTORY_ARITY_2, fund_txid, 0,
                                 2000000, spk, 1, 2, 1), "build");
    char path[256];
    ex_db_path(path, sizeof(path), "dry");
    persist_t db;
    TEST_ASSERT(ex_persist_factory(&db, path, f, ctx), "persist");
    chain_backend_t cb;
    mk_init(&cb, fund_txid);

    factory_recovery_result_t res;
    char st[512];
    int ok = factory_recovery_run_ex(&db, &cb, 0, 1, &res, st, sizeof(st));
    printf("  dry run: %s\n", st);
    TEST_ASSERT(ok == 1 && res.dry_run == 1, "dry run ok");
    TEST_ASSERT(g_mk.n_send_calls == 0, "dry run sends nothing");
    TEST_ASSERT(res.n_broadcast >= 1, "dry run reports what it would send");
    TEST_ASSERT(res.n_txs == (int)f->n_nodes, "every node counted");

    ok = factory_recovery_run_ex(&db, &cb, 0, 0, &res, st, sizeof(st));
    printf("  real run: %s\n", st);
    TEST_ASSERT(ok == 1 && g_mk.n_send_ok == res.n_broadcast &&
                res.n_broadcast >= 1, "real run sends");
    TEST_ASSERT(res.n_waiting > 0, "children of unconfirmed parents wait");
    TEST_ASSERT(res.n_failed == 0, "no failure");

    persist_close(&db);
    unlink(path);
    factory_free(f); free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Client-side exit persistence: the client DB ends up with chain[0..N] and a
   restart-time unsigned node never wipes a stored signature. */
int test_exit_client_persist_exit_state(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    const size_t N = 3;
    secp256k1_keypair kps[3];
    secp256k1_pubkey pks[3];
    TEST_ASSERT(ex_keys(ctx, N, kps, pks), "keys");
    unsigned char spk[34], fund_txid[32];
    TEST_ASSERT(ex_funding_spk(ctx, pks, N, spk, NULL), "spk");
    memset(fund_txid, 0x48, 32);
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(ex_build_factory(ctx, f, kps, N, FACTORY_ARITY_PS, fund_txid, 0,
                                 2000000, spk, 1, 2, 1), "build PS");
    char path[256];
    ex_db_path(path, sizeof(path), "clientps");
    persist_t db;
    TEST_ASSERT(persist_open(&db, path), "db");
    TEST_ASSERT(persist_save_factory(&db, f, ctx, 0), "factory row");
    /* as the client's initial save does */
    TEST_ASSERT(persist_save_tree_nodes(&db, f, 0) &&
                client_persist_exit_state(&db, f), "initial exit state");

    size_t leaf = f->leaf_node_indices[0];
    char chain_txid[4][65];
    ex_txid_hex(f->nodes[leaf].txid, chain_txid[0]);
    for (int k = 1; k <= 3; k++) {
        TEST_ASSERT(factory_advance_leaf(f, 0), "advance");
        TEST_ASSERT(client_persist_exit_state(&db, f), "persist after advance");
        ex_txid_hex(f->nodes[leaf].txid, chain_txid[k]);
    }

    /* A node that is unsigned in memory (as after a restart) is not wiped. */
    size_t other = f->leaf_node_indices[1];
    f->nodes[other].is_signed = 0;
    TEST_ASSERT(client_persist_exit_state(&db, f), "persist with an unsigned node");
    char sql[160];
    snprintf(sql, sizeof(sql),
             "SELECT length(signed_tx_hex) FROM tree_nodes WHERE factory_id=0 "
             "AND node_index=%zu", other);
    TEST_ASSERT(ex_sql_int(&db, sql) > 0, "stored signature kept");
    f->nodes[other].is_signed = 1;

    chain_backend_t cb;
    mk_init(&cb, fund_txid);
    char st[512];
    int rc = ex_mock_force_close(&db, &cb, 100, 4, NULL, st, sizeof(st));
    printf("  client self-exit: rc=%d %s\n", rc, st);
    for (int k = 0; k <= 3; k++)
        TEST_ASSERT(mk_confs(&cb, chain_txid[k]) >= 1, "chain entry published");
    TEST_ASSERT(rc == 1, "self-exit reports success");

    persist_close(&db);
    unlink(path);
    factory_free(f); free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Broadcast queue: not before nLockTime, re-sent while unconfirmed, closed on
   confirmation or when its input is spent elsewhere. */
static void ex_dummy_tx(const unsigned char prev[32], uint32_t locktime,
                        char *hex_out) {
    unsigned char b[128];
    size_t p = 0;
    b[p++] = 2; b[p++] = 0; b[p++] = 0; b[p++] = 0;      /* version */
    b[p++] = 1;                                          /* 1 input */
    memcpy(b + p, prev, 32); p += 32;
    b[p++] = 0; b[p++] = 0; b[p++] = 0; b[p++] = 0;      /* vout */
    b[p++] = 0;                                          /* scriptSig */
    b[p++] = 0xFE; b[p++] = 0xFF; b[p++] = 0xFF; b[p++] = 0xFF;  /* nSequence */
    b[p++] = 1;                                          /* 1 output */
    uint64_t amt = 10000;
    for (int i = 0; i < 8; i++) b[p++] = (unsigned char)(amt >> (8 * i));
    b[p++] = 34; b[p++] = 0x51; b[p++] = 0x20;
    memset(b + p, 0x33, 32); p += 32;
    for (int i = 0; i < 4; i++) b[p++] = (unsigned char)(locktime >> (8 * i));
    hex_encode(b, p, hex_out);
}

int test_exit_broadcast_queue_waits_for_locktime(void) {
    char path[256];
    ex_db_path(path, sizeof(path), "queue");
    persist_t db;
    TEST_ASSERT(persist_open(&db, path), "db");
    chain_backend_t cb;
    mk_init(&cb, NULL);
    g_mk.height = 100;

    unsigned char prev[32];
    memset(prev, 0x21, 32);
    char hex[400], txid[65];
    ex_dummy_tx(prev, 110, hex);
    TEST_ASSERT(persist_queue_broadcast(&db, "dist_test", hex, txid), "queue");
    TEST_ASSERT(persist_queue_broadcast(&db, "dist_test", hex, NULL), "idempotent");
    TEST_ASSERT(ex_sql_int(&db, "SELECT COUNT(*) FROM broadcast_log WHERE result='queued'") == 1,
                "one queue entry");

    TEST_ASSERT(persist_service_queued_broadcasts(&db, &cb) == 1, "pending");
    TEST_ASSERT(g_mk.n_send_calls == 0, "not sent before nLockTime");
    g_mk.height = 109;
    persist_service_queued_broadcasts(&db, &cb);
    TEST_ASSERT(g_mk.n_send_calls == 0, "not sent at nLockTime-1");
    g_mk.height = 110;
    persist_service_queued_broadcasts(&db, &cb);
    TEST_ASSERT(g_mk.n_send_calls == 1, "sent once final");
    persist_service_queued_broadcasts(&db, &cb);
    TEST_ASSERT(g_mk.n_send_calls == 1, "not re-sent while in the mempool");
    mk_set(txid, -1);                                   /* evicted */
    persist_service_queued_broadcasts(&db, &cb);
    TEST_ASSERT(g_mk.n_send_calls == 1, "at most one send per block");
    g_mk.height++;
    persist_service_queued_broadcasts(&db, &cb);
    TEST_ASSERT(g_mk.n_send_calls == 2, "re-sent after eviction (next block)");
    mk_mine();
    TEST_ASSERT(persist_service_queued_broadcasts(&db, &cb) == 0, "confirmed");
    TEST_ASSERT(ex_sql_int(&db, "SELECT COUNT(*) FROM broadcast_log WHERE result='confirmed'") == 1,
                "entry closed as confirmed");

    /* Input spent by something else: entry dropped, never sent. */
    unsigned char prev2[32];
    memset(prev2, 0x22, 32);
    char hex2[400], txid2[65];
    ex_dummy_tx(prev2, 0, hex2);
    TEST_ASSERT(persist_queue_broadcast(&db, "dist_test2", hex2, txid2), "queue 2");
    ex_txid_hex(prev2, g_mk.spent_prev);
    int calls = g_mk.n_send_calls;
    TEST_ASSERT(persist_service_queued_broadcasts(&db, &cb) == 0, "nothing pending");
    TEST_ASSERT(g_mk.n_send_calls == calls, "not sent");
    TEST_ASSERT(ex_sql_int(&db, "SELECT COUNT(*) FROM broadcast_log WHERE result='input_spent'") == 1,
                "entry closed as input_spent");

    /* A TX the node keeps rejecting: one send per block, one log row updated
       in place (the queue row plus one attempt row), however many ticks. */
    unsigned char prev3[32];
    memset(prev3, 0x23, 32);
    char hex3[400], txid3[65], cnt_sql[200];
    ex_dummy_tx(prev3, 0, hex3);
    TEST_ASSERT(persist_queue_broadcast(&db, "dist_test3", hex3, txid3), "queue 3");
    snprintf(cnt_sql, sizeof(cnt_sql),
             "SELECT COUNT(*) FROM broadcast_log WHERE txid='%s'", txid3);
    g_mk.reject_sends = 1;
    calls = g_mk.n_send_calls;
    for (int t = 0; t < 5; t++) persist_service_queued_broadcasts(&db, &cb);
    TEST_ASSERT(g_mk.n_send_calls == calls + 1, "rejected TX: one send this block");
    g_mk.height++;
    for (int t = 0; t < 5; t++) persist_service_queued_broadcasts(&db, &cb);
    TEST_ASSERT(g_mk.n_send_calls == calls + 2, "and one more the next block");
    printf("  rejected TX: %d sends over 10 ticks in 2 blocks, %d log rows\n",
           g_mk.n_send_calls - calls, ex_sql_int(&db, cnt_sql));
    TEST_ASSERT(ex_sql_int(&db, cnt_sql) == 2, "queue row + one attempt row");
    g_mk.reject_sends = 0;
    g_mk.height++;
    persist_service_queued_broadcasts(&db, &cb);
    TEST_ASSERT(ex_sql_int(&db, cnt_sql) == 2, "accepted send updates the same row");
    char res3[32];
    char res_sql[200];
    snprintf(res_sql, sizeof(res_sql), "SELECT result FROM broadcast_log WHERE "
             "txid='%s' AND raw_hex IS NULL", txid3);
    ex_sql_text(&db, res_sql, res3, sizeof(res3));
    TEST_ASSERT(strcmp(res3, "ok") == 0, "attempt row says ok");

    /* factory state helpers used by the cooperative-close ordering */
    TEST_ASSERT(sqlite3_exec(db.db, "INSERT INTO factories (id, n_participants) "
                             "VALUES (7, 3)", NULL, NULL, NULL) == SQLITE_OK, "row");
    char state[16];
    TEST_ASSERT(persist_set_factory_state(&db, 7, "closing"), "set closing");
    TEST_ASSERT(persist_get_factory_state(&db, 7, state, sizeof(state)) &&
                strcmp(state, "closing") == 0, "read closing");
    TEST_ASSERT(!persist_get_factory_state(&db, 8, state, sizeof(state)), "absent row");

    persist_close(&db);
    unlink(path);
    return 1;
}

/* ------------------------------------------------------------------ */
/* LSP + one client over a socketpair, no chain (fake funding outpoint) */
/* ------------------------------------------------------------------ */

typedef struct {
    secp256k1_context *ctx;
    secp256k1_keypair kps[3];
    secp256k1_pubkey pks[3];
    unsigned char fund_txid[32];
    unsigned char spk[34];
    lsp_t *lsp;
    factory_t *cf;                  /* the client's copy of the tree */
    lsp_channel_mgr_t *mgr;
    persist_t db;
    int db_open;
    char path[256];
    persist_t cdb;                  /* a client-side DB (no dw_counter_state) */
    int cdb_open;
    char cpath[256];
    int sv[2];
} ex_rig_t;

static int ex_rig_init_ex(ex_rig_t *r, factory_arity_t arity, const char *tag,
                          int hashlocked_l_stock, uint32_t states) {
    static const unsigned char seed[32] = {
        0x5e, 0xed, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e };
    memset(r, 0, sizeof(*r));
    r->sv[0] = r->sv[1] = -1;
    r->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                      SECP256K1_CONTEXT_VERIFY);
    if (!ex_keys(r->ctx, 3, r->kps, r->pks)) return 0;
    if (!ex_funding_spk(r->ctx, r->pks, 3, r->spk, NULL)) return 0;
    memset(r->fund_txid, 0x5a, 32);
    g_ex_seed = hashlocked_l_stock ? seed : NULL;
    r->lsp = calloc(1, sizeof(lsp_t));
    r->cf = calloc(1, sizeof(factory_t));
    int ok = r->lsp && r->cf && lsp_init(r->lsp, r->ctx, &r->kps[0], 0, 2) &&
             ex_build_factory(r->ctx, &r->lsp->factory, r->kps, 3, arity,
                              r->fund_txid, 0, 1000000, r->spk, 2, states, 1) &&
             ex_build_factory(r->ctx, r->cf, r->kps, 3, arity, r->fund_txid, 0,
                              1000000, r->spk, 2, states, 1);
    g_ex_seed = NULL;
    if (!ok) return 0;
    ex_db_path(r->path, sizeof(r->path), tag);
    if (!ex_persist_factory(&r->db, r->path, &r->lsp->factory, r->ctx)) return 0;
    r->db_open = 1;
    if (arity == FACTORY_ARITY_PS)
        lsp_persist_ps_chain0_all(&r->db, &r->lsp->factory);
    ex_db_path(r->cpath, sizeof(r->cpath), tag);
    strncat(r->cpath, "c", sizeof(r->cpath) - strlen(r->cpath) - 1);
    if (!persist_open(&r->cdb, r->cpath) ||
        !persist_save_factory(&r->cdb, r->cf, r->ctx, 0) ||
        !client_persist_exit_state(&r->cdb, r->cf))
        return 0;
    r->cdb_open = 1;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, r->sv) != 0) return 0;
    struct timeval tv = { .tv_sec = 120, .tv_usec = 0 };
    setsockopt(r->sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(r->sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    r->lsp->client_fds[0] = r->sv[0];
    r->lsp->client_fds[1] = -1;
    r->lsp->n_clients = 2;
    r->lsp->client_pubkeys[0] = r->pks[1];
    r->lsp->client_pubkeys[1] = r->pks[2];
    r->mgr = calloc(1, sizeof(*r->mgr));
    if (!r->mgr) return 0;
    r->mgr->ctx = r->ctx;
    r->mgr->persist = &r->db;
    r->mgr->bridge_fd = -1;
    r->mgr->entries = calloc(1, sizeof(lsp_channel_entry_t));
    if (!r->mgr->entries) return 0;
    r->mgr->entries_cap = 1;
    r->mgr->n_channels = 1;
    return 1;
}

static int ex_rig_init(ex_rig_t *r, factory_arity_t arity, const char *tag,
                       int hashlocked_l_stock) {
    return ex_rig_init_ex(r, arity, tag, hashlocked_l_stock, 4);
}

static void ex_rig_free(ex_rig_t *r) {
    if (r->lsp) { lsp_cleanup(r->lsp); free(r->lsp); }
    if (r->sv[1] >= 0) close(r->sv[1]);
    if (r->cf) { factory_free(r->cf); free(r->cf); }
    if (r->mgr) { free(r->mgr->entries); free(r->mgr); }
    if (r->db_open) persist_close(&r->db);
    if (r->cdb_open) persist_close(&r->cdb);
    if (r->path[0]) unlink(r->path);
    if (r->cpath[0]) unlink(r->cpath);
    if (r->ctx) secp256k1_context_destroy(r->ctx);
}

/* Drive one real LSP leaf/PS/Tier-B advance of leaf 0 against a one-shot
   client thread, then persist the client's resulting view to the client DB.
   Returns the lsp_channels_advance_ps_leaf rc. */
static int ex_rig_ps_advance(ex_rig_t *r, int *client_ok) {
    ex_client_t cl = { .fd = r->sv[1], .ctx = r->ctx, .kp = r->kps[1],
                       .f = r->cf, .my_index = 1, .n_expected = 1, .ok = 0 };
    pthread_t th;
    if (pthread_create(&th, NULL, ex_client_thread, &cl) != 0) return 0;
    int rc = lsp_channels_advance_ps_leaf(r->mgr, r->lsp, 0);
    if (rc != 1) shutdown(r->sv[0], SHUT_RDWR);
    pthread_join(th, NULL);
    *client_ok = cl.ok;
    if (rc == 1 && r->cdb_open)
        client_persist_exit_state(&r->cdb, r->cf);
    return rc;
}

/* Run the LSP's real realloc ceremony for leaf 0 against the client thread. */
static int ex_rig_realloc(ex_rig_t *r, const uint64_t *amounts, size_t n,
                          int *client_ok) {
    ex_client_t cl = { .fd = r->sv[1], .ctx = r->ctx, .kp = r->kps[1],
                       .f = r->cf, .my_index = 1, .n_expected = 1, .ok = 0 };
    pthread_t th;
    if (pthread_create(&th, NULL, ex_client_thread, &cl) != 0) return 0;
    int rc = lsp_realloc_leaf(r->mgr, r->lsp, 0, amounts, n);
    if (rc != 1) shutdown(r->sv[0], SHUT_RDWR);   /* unblock the client */
    pthread_join(th, NULL);
    *client_ok = cl.ok;
    return rc;
}

/* Move `delta` sats from the leaf's L-stock (last non-anchor output) to the
   client's channel output (vout 0).  Returns the amount count. */
static size_t ex_realloc_amounts(const factory_node_t *ln, uint64_t delta,
                                 uint64_t *amts) {
    size_t n = ln->n_outputs;
    if (n >= 1 && ln->outputs[n - 1].script_pubkey_len == P2A_SPK_LEN &&
        memcmp(ln->outputs[n - 1].script_pubkey, P2A_SPK, P2A_SPK_LEN) == 0)
        n--;
    for (size_t i = 0; i < n; i++) amts[i] = ln->outputs[i].amount_sats;
    amts[0] += delta;
    amts[n - 1] -= delta;
    return n;
}

/* Send MSG_LSTOCK_REVEAL_REQUEST for (node, state) through the LSP's message
   handler.  Returns the number of secrets revealed (0 = refused), -1 on a
   handler / wire error. */
static int ex_request_reveal(ex_rig_t *r, uint32_t node, uint32_t state) {
    cJSON *req = wire_build_lstock_reveal_request(&node, &state, 1);
    if (!req) return -1;
    wire_msg_t m;
    memset(&m, 0, sizeof(m));
    m.msg_type = MSG_LSTOCK_REVEAL_REQUEST;
    m.json = req;
    int hrc = lsp_channels_handle_msg(r->mgr, r->lsp, 0, &m);
    cJSON_Delete(req);
    if (!hrc) return -1;
    struct pollfd pf = { .fd = r->sv[1], .events = POLLIN, .revents = 0 };
    if (poll(&pf, 1, 500) <= 0) return 0;
    wire_msg_t in;
    memset(&in, 0, sizeof(in));
    if (!wire_recv(r->sv[1], &in)) return -1;
    int n = -1;
    if (in.msg_type == MSG_LSTOCK_REVEAL) {
        uint32_t nn[4], ss[4];
        unsigned char sec[4][32];
        size_t cnt = 0;
        if (wire_parse_lstock_reveal(in.json, nn, ss, sec, 4, &cnt))
            n = (int)cnt;
    }
    if (in.json) cJSON_Delete(in.json);
    return n;
}

/* A PS leaf's realloc is a chain advance with a single output.  One shaped
   like buy_liquidity's (channel + L-stock amounts) cannot work and must be
   refused before the leaf changes; it used to fail half-way, after
   ps_chain_len was bumped, leaving an unsigned chain entry nobody else has. */
int test_exit_ps_realloc_refused_leaf_unchanged(void) {
    ex_rig_t r;
    TEST_ASSERT(ex_rig_init(&r, FACTORY_ARITY_PS, "psrealloc_bad", 0), "rig");
    factory_t *lf = &r.lsp->factory;
    factory_node_t *ln = &lf->nodes[lf->leaf_node_indices[0]];
    char chain0[65], after[65];
    ex_txid_hex(ln->txid, chain0);
    TEST_ASSERT(ln->ps_chain_len == 0 && ln->n_outputs >= 2,
                "PS leaf at chain[0] with an L-stock output");
    uint64_t amts[FACTORY_MAX_OUTPUTS];
    size_t na = ex_realloc_amounts(ln, 1000, amts);
    int rc = lsp_realloc_leaf(r.mgr, r.lsp, 0, amts, na);
    ex_txid_hex(ln->txid, after);
    printf("  %zu-amount PS realloc rc=%d: ps_chain_len=%d is_signed=%d, txid %s\n",
           na, rc, ln->ps_chain_len, ln->is_signed,
           strcmp(after, chain0) == 0 ? "unchanged" : "CHANGED");
    TEST_ASSERT(rc == 0, "refused");
    TEST_ASSERT(ln->ps_chain_len == 0 && ln->is_signed &&
                strcmp(after, chain0) == 0, "leaf unchanged by the refused realloc");
    ex_rig_free(&r);
    return 1;
}

/* A PS realloc writes its chain entry: a force-close from the DB publishes
   the reallocated state, and persist_load_factory restores the chain at its
   full length with the reallocated tip, so the next chain TX is built on
   chain[1] rather than being a second, conflicting chain[1].  (Advancing a
   reloaded factory is covered by the test_reload_* tests.) */
int test_exit_ps_realloc_persists_chain_entry(void) {
    ex_rig_t r;
    TEST_ASSERT(ex_rig_init(&r, FACTORY_ARITY_PS, "psrealloc", 0), "rig");
    alarm(300);   /* hang guard */
    factory_t *lf = &r.lsp->factory;
    size_t leaf = lf->leaf_node_indices[0];
    factory_node_t *ln = &lf->nodes[leaf];
    char chain0[65], chain1[65];
    ex_txid_hex(ln->txid, chain0);

    uint64_t one[1] = { ln->outputs[0].amount_sats - lf->fee_per_tx };
    int client_ok = 0;
    int rc = ex_rig_realloc(&r, one, 1, &client_ok);
    TEST_ASSERT(rc == 1 && client_ok, "PS realloc ceremony");
    ex_txid_hex(ln->txid, chain1);
    int rows = ex_sql_int(&r.db, "SELECT COUNT(*) FROM ps_leaf_chains");
    printf("  realloc: ps_chain_len=%d, chain[1] %.16s..., ps_leaf_chains rows=%d\n",
           ln->ps_chain_len, chain1, rows);
    TEST_ASSERT(ln->ps_chain_len == 1, "realloc advanced the chain");
    TEST_ASSERT(rows == 1, "realloc wrote its chain entry");

    /* restart: restore the factory from the DB */
    factory_t *f2 = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f2 && persist_load_factory(&r.db, 0, f2, r.ctx), "restore from the DB");
    factory_node_t *n2 = &f2->nodes[leaf];
    char tip[65];
    ex_txid_hex(n2->txid, tip);
    printf("  after restart: ps_chain_len=%d, tip %.16s...\n", n2->ps_chain_len, tip);
    TEST_ASSERT(n2->ps_chain_len == 1 && strcmp(tip, chain1) == 0,
                "restore gives the full chain with the reallocated tip");
    factory_free(f2); free(f2);

    chain_backend_t cb;
    mk_init(&cb, r.fund_txid);
    char st[512];
    /* step 2 x 4 states: up to 6 blocks of relative timelock per level */
    rc = ex_mock_force_close(&r.db, &cb, 300, 12, NULL, st, sizeof(st));
    printf("  force-close rc=%d: %s\n", rc, st);
    printf("  chain[0] confs=%d, reallocated chain[1] confs=%d\n",
           mk_confs(&cb, chain0), mk_confs(&cb, chain1));
    alarm(0);
    TEST_ASSERT(mk_confs(&cb, chain1) >= 1, "force-close published the reallocated state");
    ex_rig_free(&r);
    return 1;
}

/* After a failed exit-path write the DB still holds the state that the
   in-memory L-stock counter already calls superseded, so an on-request reveal
   must not hand out its secret.  Once a later write succeeds it may. */
int test_exit_reveal_request_after_failed_write(void) {
    ex_rig_t r;
    TEST_ASSERT(ex_rig_init(&r, FACTORY_ARITY_1, "reveal", 1), "rig");
    alarm(300);   /* hang guard */
    factory_t *lf = &r.lsp->factory;
    size_t leaf = lf->leaf_node_indices[0];
    factory_node_t *ln = &lf->nodes[leaf];
    TEST_ASSERT(lf->has_shachain && ln->n_outputs >= 2,
                "leaf with a hashlocked L-stock");
    uint32_t s0 = ln->l_stock_state_counter;

    /* the DB now refuses tree-node writes (disk full, I/O error, ...) */
    TEST_ASSERT(sqlite3_exec(r.db.db,
        "CREATE TRIGGER ex_fail_tn BEFORE INSERT ON tree_nodes "
        "BEGIN SELECT RAISE(ABORT, 'test: write refused'); END;",
        NULL, NULL, NULL) == SQLITE_OK, "failing-write trigger");
    uint64_t amts[FACTORY_MAX_OUTPUTS];
    size_t na = ex_realloc_amounts(ln, 1000, amts);
    int client_ok = 0;
    TEST_ASSERT(ex_rig_realloc(&r, amts, na, &client_ok) == 1 && client_ok,
                "realloc whose write fails");
    uint32_t s1 = ln->l_stock_state_counter;
    TEST_ASSERT(s1 == s0 + 1, "realloc moved to the next L-stock state");

    lf->use_hashlock_poison = 1;    /* only the reveal handler looks at it */
    int got_s0 = ex_request_reveal(&r, (uint32_t)leaf, s0);
    lf->use_hashlock_poison = 0;
    printf("  L-stock state %u -> %u, DB write failed; request for state %u: %s\n",
           s0, s1, s0, got_s0 > 0 ? "REVEALED" : got_s0 == 0 ? "refused" : "error");
    TEST_ASSERT(got_s0 == 0, "the state still in the DB is not revealed");

    TEST_ASSERT(sqlite3_exec(r.db.db, "DROP TRIGGER ex_fail_tn;", NULL, NULL,
                             NULL) == SQLITE_OK, "drop trigger");
    na = ex_realloc_amounts(ln, 1000, amts);
    TEST_ASSERT(ex_rig_realloc(&r, amts, na, &client_ok) == 1 && client_ok,
                "realloc whose write succeeds");
    uint32_t s2 = ln->l_stock_state_counter;
    lf->use_hashlock_poison = 1;
    int a = ex_request_reveal(&r, (uint32_t)leaf, s0);
    int b = ex_request_reveal(&r, (uint32_t)leaf, s1);
    int c = ex_request_reveal(&r, (uint32_t)leaf, s2);
    lf->use_hashlock_poison = 0;
    alarm(0);
    printf("  after a durable write (state %u): states %u/%u revealed %d/%d, "
           "current state %u revealed %d\n", s2, s0, s1, a, b, s2, c);
    TEST_ASSERT(a == 1 && b == 1, "superseded states revealed once the DB moved on");
    TEST_ASSERT(c == 0, "the current state is never revealed");
    ex_rig_free(&r);
    return 1;
}

/* A signed node whose TX does not spend what the DB holds for its parent (an
   advance computed on a stale in-memory tree) is refused, and the stored row
   survives. */
int test_exit_tree_write_refuses_stale_parent(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kps[3];
    secp256k1_pubkey pks[3];
    TEST_ASSERT(ex_keys(ctx, 3, kps, pks), "keys");
    unsigned char spk[34], fund_txid[32];
    TEST_ASSERT(ex_funding_spk(ctx, pks, 3, spk, NULL), "spk");
    memset(fund_txid, 0x47, 32);
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f && ex_build_factory(ctx, f, kps, 3, FACTORY_ARITY_1, fund_txid,
                                      0, 1000000, spk, 2, 4, 1), "factory");
    char path[256];
    ex_db_path(path, sizeof(path), "staleparent");
    persist_t db;
    TEST_ASSERT(ex_persist_factory(&db, path, f, ctx), "persist");

    size_t leaf = f->leaf_node_indices[0];
    int parent = f->nodes[leaf].parent_index;
    char sql[256], before[8192], after[8192], parent_txid[65];
    snprintf(sql, sizeof(sql), "SELECT signed_tx_hex FROM tree_nodes WHERE "
             "factory_id=0 AND node_index=%zu", leaf);
    ex_sql_text(&db, sql, before, sizeof(before));
    ex_txid_hex(f->nodes[parent].txid, parent_txid);
    TEST_ASSERT(before[0] && factory_advance_leaf(f, 0), "local leaf advance");

    /* The DB's parent moved on (a state this in-memory tree never saw). */
    char upd[256];
    snprintf(upd, sizeof(upd), "UPDATE tree_nodes SET txid='%064d' WHERE "
             "factory_id=0 AND node_index=%d", 7, parent);
    TEST_ASSERT(sqlite3_exec(db.db, upd, NULL, NULL, NULL) == SQLITE_OK, "tamper");
    int one = persist_save_tree_node(&db, f, 0, leaf);
    ex_sql_text(&db, sql, after, sizeof(after));
    printf("  single-node write over a mismatched parent: %s, stored row %s\n",
           one ? "ACCEPTED" : "refused", strcmp(before, after) == 0 ? "kept" : "REPLACED");
    TEST_ASSERT(!one, "write refused");
    TEST_ASSERT(strcmp(before, after) == 0, "stored row kept");

    /* Batch write of a rebuilt tree whose parent is unsigned in memory. */
    f->nodes[parent].is_signed = 0;
    int batch = persist_save_signed_tree_nodes(&db, f, 0);
    f->nodes[parent].is_signed = 1;
    ex_sql_text(&db, sql, after, sizeof(after));
    printf("  batch write: rc=%d, stored row %s\n", batch,
           strcmp(before, after) == 0 ? "kept" : "REPLACED");
    TEST_ASSERT(batch < 0 && strcmp(before, after) == 0, "batch refused, row kept");

    /* Control: once the stored parent is the one the node spends, it is written. */
    snprintf(upd, sizeof(upd), "UPDATE tree_nodes SET txid='%s' WHERE "
             "factory_id=0 AND node_index=%d", parent_txid, parent);
    TEST_ASSERT(sqlite3_exec(db.db, upd, NULL, NULL, NULL) == SQLITE_OK, "restore");
    TEST_ASSERT(persist_save_tree_node(&db, f, 0, leaf) == 1, "accepted when it matches");
    ex_sql_text(&db, sql, after, sizeof(after));
    TEST_ASSERT(strcmp(before, after) != 0, "advanced state stored");

    persist_close(&db);
    unlink(path);
    factory_free(f); free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A restarted LSP never serves a 'closing' factory.  It re-sends the queued
   close; --force-close-from-db (force_close) publishes the signed tree as the
   way out when the close does not confirm; the factory is marked closed only
   when the close itself confirmed, and stays 'closing' when the funding was
   spent by something else (the tree), pointing at the escape. */
int test_exit_closing_factory_on_restart(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kps[3];
    secp256k1_pubkey pks[3];
    TEST_ASSERT(ex_keys(ctx, 3, kps, pks), "keys");
    unsigned char spk[34], fund_txid[32];
    TEST_ASSERT(ex_funding_spk(ctx, pks, 3, spk, NULL), "spk");
    memset(fund_txid, 0x48, 32);
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f && ex_build_factory(ctx, f, kps, 3, FACTORY_ARITY_1, fund_txid,
                                      0, 1000000, spk, 2, 4, 1), "factory");
    char path[256], path2[256];
    ex_db_path(path, sizeof(path), "closing");
    ex_db_path(path2, sizeof(path2), "closing2");
    persist_t db, db2;
    TEST_ASSERT(ex_persist_factory(&db, path, f, ctx), "persist");
    chain_backend_t cb;
    mk_init(&cb, fund_txid);
    char st[768], state[16];

    TEST_ASSERT(lsp_resume_closing_factory(&db, &cb, 0, 0, st, sizeof(st)) ==
                LSP_CLOSING_NOT, "an active factory is served normally");

    char close_hex[400], close_txid[65], root_txid[65];
    ex_dummy_tx(fund_txid, 0, close_hex);
    TEST_ASSERT(persist_queue_broadcast(&db, "cooperative_close", close_hex,
                                        close_txid) &&
                persist_set_factory_state(&db, 0, "closing"),
                "signed close queued, factory 'closing'");
    int calls = g_mk.n_send_calls;
    int cr = lsp_resume_closing_factory(&db, &cb, 0, 0, st, sizeof(st));
    printf("  restart: rc=%d: %s\n", cr, st);
    TEST_ASSERT(cr == LSP_CLOSING_PENDING, "not served");
    TEST_ASSERT(g_mk.n_send_calls == calls + 1 && mk_confs(&cb, close_txid) == 0,
                "queued close re-broadcast");

    /* The close is stuck (evicted, fee too low): the operator's way out. */
    ex_txid_hex(f->nodes[0].txid, root_txid);
    mk_set(close_txid, -1);
    g_mk.height++;
    cr = lsp_resume_closing_factory(&db, &cb, 0, 1, st, sizeof(st));
    printf("  --force-close-from-db: rc=%d: %s\n", cr, st);
    TEST_ASSERT(cr == LSP_CLOSING_PENDING, "force-close pass ran without a failure");
    TEST_ASSERT(mk_confs(&cb, root_txid) >= 0, "signed tree root published");
    TEST_ASSERT(persist_get_factory_state(&db, 0, state, sizeof(state)) &&
                strcmp(state, "closing") == 0, "still 'closing'");

    /* The close confirms after all. */
    mk_set(close_txid, 6);
    cr = lsp_resume_closing_factory(&db, &cb, 0, 0, st, sizeof(st));
    printf("  close confirmed: rc=%d: %s\n", cr, st);
    TEST_ASSERT(cr == LSP_CLOSING_DONE, "close confirmed");
    TEST_ASSERT(persist_get_factory_state(&db, 0, state, sizeof(state)) &&
                strcmp(state, "closed") == 0, "factory marked closed");
    persist_close(&db);
    unlink(path);

    /* Second DB: the funding output was spent by another TX (the tree). */
    TEST_ASSERT(ex_persist_factory(&db2, path2, f, ctx), "persist 2");
    TEST_ASSERT(persist_queue_broadcast(&db2, "cooperative_close", close_hex, NULL) &&
                persist_set_factory_state(&db2, 0, "closing"), "closing 2");
    mk_init(&cb, fund_txid);
    ex_txid_hex(fund_txid, g_mk.spent_prev);
    cr = lsp_resume_closing_factory(&db2, &cb, 0, 0, st, sizeof(st));
    printf("  funding spent elsewhere: rc=%d: %s\n", cr, st);
    TEST_ASSERT(cr == LSP_CLOSING_PENDING && strstr(st, "--force-close-from-db"),
                "stays 'closing' and points at --force-close-from-db");
    TEST_ASSERT(persist_get_factory_state(&db2, 0, state, sizeof(state)) &&
                strcmp(state, "closing") == 0, "not marked closed");
    persist_close(&db2);
    unlink(path2);

    factory_free(f); free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Once a signed cooperative close is out (lsp->closing), the daemon loop stops
   serving the factory without a shutdown request. */
int test_exit_closing_stops_daemon_loop(void) {
    ex_rig_t r;
    TEST_ASSERT(ex_rig_init(&r, FACTORY_ARITY_1, "closingloop", 0), "rig");
    r.lsp->closing = 1;
    volatile sig_atomic_t stop = 0;
    alarm(60);   /* hang guard */
    time_t t0 = time(NULL);
    int rc = lsp_channels_run_daemon_loop(r.mgr, r.lsp, &stop);
    alarm(0);
    TEST_ASSERT(rc == 1 && time(NULL) - t0 < 30,
                "daemon loop returned without a shutdown request");
    ex_rig_free(&r);
    return 1;
}

/* A consistent signed tree reloads and clears the advance refusal; a tree
   whose stored rows contradict the counter (or each other) stays refused. */
int test_exit_reload_consistent_and_corrupted(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kps[3];
    secp256k1_pubkey pks[3];
    TEST_ASSERT(ex_keys(ctx, 3, kps, pks), "keys");
    unsigned char spk[34], fund_txid[32];
    TEST_ASSERT(ex_funding_spk(ctx, pks, 3, spk, NULL), "spk");
    memset(fund_txid, 0x51, 32);
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f && ex_build_factory(ctx, f, kps, 3, FACTORY_ARITY_1, fund_txid,
                                      0, 1000000, spk, 2, 4, 1), "factory");
    char path[256];
    ex_db_path(path, sizeof(path), "reload_ok");
    persist_t db;
    TEST_ASSERT(ex_persist_factory(&db, path, f, ctx), "persist tree");
    TEST_ASSERT(persist_save_factory_dw_state(&db, 0, f), "persist dw state");
    size_t leaf = f->leaf_node_indices[0];

    /* consistent -> reload clears the flag, advance allowed */
    factory_t *g = calloc(1, sizeof(factory_t));
    TEST_ASSERT(g && persist_load_factory(&db, 0, g, ctx), "load");
    printf("  consistent reload: tree_rebuilt_on_load=%d\n", g->tree_rebuilt_on_load);
    TEST_ASSERT(!g->tree_rebuilt_on_load, "consistent tree -> refusal cleared");
    TEST_ASSERT(!factory_advance_refused(g), "refusal cleared");
    TEST_ASSERT(factory_advance_leaf_unsigned(g, 0) == 1, "advance allowed");
    factory_free(g); free(g);

    /* corrupt the leaf's stored nSequence -> counter/tree disagree -> refused */
    char sql[256];
    snprintf(sql, sizeof(sql), "UPDATE tree_nodes SET nsequence=12345 WHERE "
             "factory_id=0 AND node_index=%zu", leaf);
    TEST_ASSERT(sqlite3_exec(db.db, sql, NULL, NULL, NULL) == SQLITE_OK, "tamper nseq");
    g = calloc(1, sizeof(factory_t));
    TEST_ASSERT(g && persist_load_factory(&db, 0, g, ctx), "load 2");
    printf("  bad nSequence: tree_rebuilt_on_load=%d\n", g->tree_rebuilt_on_load);
    TEST_ASSERT(g->tree_rebuilt_on_load, "mismatched nSequence -> still refused");
    TEST_ASSERT(factory_advance_refused(g), "advance refused (flag set)");
    TEST_ASSERT(factory_advance_leaf_unsigned(g, 0) == FACTORY_ADVANCE_REFUSED,
                "advance returns FACTORY_ADVANCE_REFUSED");
    factory_free(g); free(g);

    /* restore nSequence, break the input chain (wrong parent txid) -> refused */
    snprintf(sql, sizeof(sql), "UPDATE tree_nodes SET nsequence=("
             "SELECT nsequence FROM tree_nodes WHERE factory_id=0 AND node_index=%zu"
             ") WHERE 0", leaf);  /* no-op; just re-persist the real tree below */
    (void)sql;
    TEST_ASSERT(persist_save_tree_nodes(&db, f, 0), "re-save real tree");
    int parent = f->nodes[leaf].parent_index;
    snprintf(sql, sizeof(sql), "UPDATE tree_nodes SET txid='%064d' WHERE "
             "factory_id=0 AND node_index=%d", 9, parent);
    TEST_ASSERT(sqlite3_exec(db.db, sql, NULL, NULL, NULL) == SQLITE_OK, "tamper parent txid");
    g = calloc(1, sizeof(factory_t));
    TEST_ASSERT(g && persist_load_factory(&db, 0, g, ctx), "load 3");
    printf("  broken input chain: tree_rebuilt_on_load=%d\n", g->tree_rebuilt_on_load);
    TEST_ASSERT(g->tree_rebuilt_on_load, "broken input chain -> still refused");
    factory_free(g); free(g);

    persist_close(&db);
    unlink(path);
    factory_free(f); free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* DW leaf advance -> restart -> the reload clears the refusal, restores the
   advanced leaf state, and the next advance builds on it.  The stored DW
   counter and the stored tree agree (they are written in one transaction, so
   a restart never sees state k in the tree with the counter at k-1). */
int test_exit_dw_advance_reload_then_advance(void) {
    ex_rig_t r;
    TEST_ASSERT(ex_rig_init(&r, FACTORY_ARITY_1, "dwreload", 0), "rig");
    alarm(300);
    size_t leaf = r.lsp->factory.leaf_node_indices[0];
    int client_ok = 0;
    TEST_ASSERT(ex_rig_ps_advance(&r, &client_ok) == 1 && client_ok, "DW leaf advance");
    uint32_t adv_state = r.lsp->factory.leaf_layers[0].current_state;
    TEST_ASSERT(adv_state == 1, "leaf advanced to state 1");

    factory_t *g = calloc(1, sizeof(factory_t));
    TEST_ASSERT(g && persist_load_factory(&r.db, 0, g, r.ctx), "reload");
    printf("  reload: flag=%d, leaf0 state=%u (advanced=%u)\n",
           g->tree_rebuilt_on_load, g->leaf_layers[0].current_state, adv_state);
    TEST_ASSERT(!g->tree_rebuilt_on_load, "refusal cleared");
    TEST_ASSERT(g->leaf_layers[0].current_state == 1,
                "reloaded leaf state matches the DB (tree and counter agree)");
    TEST_ASSERT(factory_node_nsequence(g, leaf) ==
                dw_current_nsequence(&g->leaf_layers[0]), "node nseq matches counter");
    TEST_ASSERT(factory_advance_leaf_unsigned(g, 0) == 1, "next advance builds (not refused)");
    TEST_ASSERT(g->leaf_layers[0].current_state == 2, "next advance moved to state 2");
    alarm(0);
    factory_free(g); free(g);
    ex_rig_free(&r);
    return 1;
}

/* Advance leaf 0 in memory (the test holds every key, so the signed variant
   re-signs the whole tree on a rollover, exactly as Tier B does) until the
   root rolls over to a new epoch.  Returns the new epoch, or 0 on no rollover. */
static uint32_t ex_local_rollover(factory_t *f, int max_adv) {
    /* The unsigned variant carries the PS Tier B rollover (returns -1); the
       signed one does not.  Sign each step here (the test holds every key). */
    for (int i = 0; i < max_adv; i++) {
        int rc = factory_advance_leaf_unsigned(f, 0);
        if (rc == -1) {
            if (!factory_sign_all(f)) return 0;          /* re-sign the new epoch */
            return f->counter.current_epoch;
        }
        if (rc == 0) return 0;
        if (!factory_sign_node(f, f->leaf_node_indices[0])) return 0;
    }
    return 0;
}

/* Persist a re-signed tree the way the Tier B save does: the whole signed
   tree, the DW counter and the new-epoch PS chain[0], in one transaction.
   With dw_state = 0 (a client DB) the counter row is left out, as a client's
   DB has none. */
static int ex_persist_tierb(persist_t *db, factory_t *f, int dw_state) {
    if (!persist_begin(db)) return 0;
    int ok = persist_save_signed_tree_nodes(db, f, 0) >= 0 &&
             (!dw_state || persist_save_factory_dw_state(db, 0, f)) &&
             client_persist_exit_state(db, f);   /* PS chain[0] + chains */
    if (ok) return persist_commit(db);
    persist_rollback(db);
    return 0;
}

/* PS Tier B rollover -> restart -> the reload clears the refusal, restores the
   new epoch, and a further advance builds on the reloaded tree. */
int test_exit_tierb_reload_then_advance(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kps[3];
    secp256k1_pubkey pks[3];
    TEST_ASSERT(ex_keys(ctx, 3, kps, pks), "keys");
    unsigned char spk[34], fund_txid[32];
    TEST_ASSERT(ex_funding_spk(ctx, pks, 3, spk, NULL), "spk");
    memset(fund_txid, 0x52, 32);
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f && ex_build_factory(ctx, f, kps, 3, FACTORY_ARITY_PS, fund_txid,
                                      0, 1000000, spk, 2, 2, 1), "factory");
    char path[256];
    ex_db_path(path, sizeof(path), "tierb");
    persist_t db;
    TEST_ASSERT(ex_persist_factory(&db, path, f, ctx), "persist");
    TEST_ASSERT(lsp_persist_ps_chain0_all(&db, f) > 0, "chain0");
    TEST_ASSERT(persist_save_factory_dw_state(&db, 0, f), "dw state");

    uint32_t epoch = ex_local_rollover(f, 10);
    TEST_ASSERT(epoch > 0, "a rollover happened");
    TEST_ASSERT(ex_persist_tierb(&db, f, 1), "persist the re-signed epoch tree");
    printf("  rolled to epoch %u and persisted\n", epoch);

    factory_t *g = calloc(1, sizeof(factory_t));
    TEST_ASSERT(g && persist_load_factory(&db, 0, g, ctx), "reload");
    printf("  reload: flag=%d, epoch=%u (expected %u)\n",
           g->tree_rebuilt_on_load, g->counter.current_epoch, epoch);
    TEST_ASSERT(!g->tree_rebuilt_on_load, "refusal cleared after Tier B");
    TEST_ASSERT(g->counter.current_epoch == epoch, "epoch reloaded from the tree/chains");
    TEST_ASSERT(!factory_advance_refused(g) &&
                factory_advance_leaf_unsigned(g, 0) != FACTORY_ADVANCE_REFUSED,
                "advance not refused after reload");
    factory_free(g); free(g);

    persist_close(&db);
    unlink(path);
    factory_free(f); free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A restarted CLIENT must not block the factory's next Tier B.  A client DB
   (no dw_counter_state row) holding a post-rollover tree reloads with the
   refusal cleared and the epoch recovered from the PS chain rows, so the
   restarted client can take part in the next ceremony instead of blocking it. */
int test_exit_client_reload_then_tierb(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kps[3];
    secp256k1_pubkey pks[3];
    TEST_ASSERT(ex_keys(ctx, 3, kps, pks), "keys");
    unsigned char spk[34], fund_txid[32];
    TEST_ASSERT(ex_funding_spk(ctx, pks, 3, spk, NULL), "spk");
    memset(fund_txid, 0x53, 32);
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f && ex_build_factory(ctx, f, kps, 3, FACTORY_ARITY_PS, fund_txid,
                                      0, 1000000, spk, 2, 2, 1), "factory");
    /* a client-side DB: factory params + signed tree + PS chain[0], and NO
       dw_counter_state row (clients never write one). */
    char cpath[256];
    ex_db_path(cpath, sizeof(cpath), "clireload");
    persist_t cdb;
    TEST_ASSERT(persist_open(&cdb, cpath), "client db");
    TEST_ASSERT(persist_save_factory(&cdb, f, ctx, 0), "client factory row");
    TEST_ASSERT(client_persist_exit_state(&cdb, f), "client creation persist");

    uint32_t epoch = ex_local_rollover(f, 10);
    TEST_ASSERT(epoch > 0, "a rollover happened");
    TEST_ASSERT(ex_persist_tierb(&cdb, f, 0), "client persists the post-rollover tree");

    factory_t *cf2 = calloc(1, sizeof(factory_t));
    TEST_ASSERT(cf2 && persist_load_factory(&cdb, 0, cf2, ctx), "client reload");
    printf("  client reload: flag=%d, epoch=%u (expected %u), no dw_counter_state row\n",
           cf2->tree_rebuilt_on_load, cf2->counter.current_epoch, epoch);
    TEST_ASSERT(!cf2->tree_rebuilt_on_load,
                "client reload clears the refusal (does not block Tier B)");
    TEST_ASSERT(cf2->counter.current_epoch == epoch,
                "epoch recovered from the PS chain rows (no dw_counter_state)");
    TEST_ASSERT(!factory_advance_refused(cf2) &&
                factory_advance_leaf_unsigned(cf2, 0) != FACTORY_ADVANCE_REFUSED,
                "the restarted client can advance (would take part in Tier B)");
    factory_free(cf2); free(cf2);

    persist_close(&cdb);
    unlink(cpath);
    factory_free(f); free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Tree reload: the L-stock state counter, PS chains across a root      */
/* rollover, and signed-state reservations                              */
/* ------------------------------------------------------------------ */

static const unsigned char g_rl_seed[32] = {
    0x7a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
    0xbb, 0xcc, 0xdd, 0xee, 0xf0, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56,
    0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf1 };

/* "Sign" a node for a persistence-only test: the stored bytes are the
   unsigned TX (same txid), which is all the reload checks look at. */
static void rl_fake_sign(factory_node_t *n) {
    tx_buf_free(&n->signed_tx);
    tx_buf_init(&n->signed_tx, (int)n->unsigned_tx.len);
    memcpy(n->signed_tx.data, n->unsigned_tx.data, n->unsigned_tx.len);
    n->signed_tx.len = n->unsigned_tx.len;
    n->is_signed = 1;
}

/* A factory with the hashlock L-stock: the seed and the flag are set before
   the tree is built, so every L-stock commits to H(secret(node, state)). */
static int rl_build_hashlock(secp256k1_context *ctx, factory_t *f,
                             const secp256k1_keypair *kps, size_t n,
                             factory_arity_t arity, uint32_t sub_arity,
                             const unsigned char fund_txid[32],
                             const unsigned char spk[34], uint32_t states) {
    if (!factory_init(f, ctx, kps, n, 2, states)) return 0;
    factory_set_shachain_seed(f, g_rl_seed);
    if (!factory_enable_hashlock_poison(f)) return 0;
    factory_set_arity(f, arity);
    if (sub_arity > 1) factory_set_ps_subfactory_arity(f, sub_arity);
    f->fee_per_tx = 1000;
    factory_set_funding(f, fund_txid, 0, 2000000, spk, 34);
    if (!factory_build_tree(f)) return 0;
    if (!factory_sign_all(f)) return 0;
    /* factory_sign_all leaves the k^2 sub-factory nodes to their own
       ceremony; for these persistence tests their bytes are enough */
    for (size_t i = 0; i < f->n_nodes; i++)
        if (f->nodes[i].is_built && !f->nodes[i].is_signed)
            rl_fake_sign(&f->nodes[i]);
    return 1;
}

static int rl_lstock_hash_of(factory_t *f, size_t idx, uint32_t state,
                             unsigned char out[32]) {
    unsigned char sec[32];
    if (!factory_derive_l_stock_secret(f, &f->nodes[idx], state, sec)) return 0;
    sha256(sec, 32, out);
    memset(sec, 0, 32);
    return 1;
}

/* Persist one advanced node the way the LSP does before DONE: the tree row
   (which carries the L-stock counter) and the DW counter in one transaction. */
static int rl_persist_node(persist_t *db, factory_t *f, size_t idx) {
    if (!persist_begin(db)) return 0;
    int ok = persist_save_tree_node(db, f, 0, idx) &&
             persist_save_factory_dw_state(db, 0, f);
    if (ok) return persist_commit(db);
    persist_rollback(db);
    return 0;
}

/* Hashlock DW leaf, three advances, restart: the reloaded L-stock state
   counter is the stored one, so the next state's L-stock commits to a fresh
   secret, not to one of the superseded states' secrets the LSP has revealed.
   A missing counter row fails the reload closed; a tampered one fails the
   LSP's post-seed check. */
int test_reload_lstock_counter_dw(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kps[3];
    secp256k1_pubkey pks[3];
    TEST_ASSERT(ex_keys(ctx, 3, kps, pks), "keys");
    unsigned char spk[34], fund[32];
    TEST_ASSERT(ex_funding_spk(ctx, pks, 3, spk, NULL), "spk");
    memset(fund, 0x61, 32);
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f && rl_build_hashlock(ctx, f, kps, 3, FACTORY_ARITY_1, 0, fund,
                                       spk, 8), "hashlock factory");
    char path[256];
    ex_db_path(path, sizeof(path), "rl_lstock");
    persist_t db;
    TEST_ASSERT(ex_persist_factory(&db, path, f, ctx), "persist");
    TEST_ASSERT(persist_save_factory_dw_state(&db, 0, f), "dw state");
    size_t leaf = f->leaf_node_indices[0];
    TEST_ASSERT(f->nodes[leaf].has_l_stock_hash, "leaf L-stock is hashlocked");

    for (int a = 0; a < 3; a++) {
        TEST_ASSERT(factory_advance_leaf(f, 0) == 1, "leaf advance");
        TEST_ASSERT(rl_persist_node(&db, f, leaf), "persist the advance");
    }
    uint32_t c = f->nodes[leaf].l_stock_state_counter;
    TEST_ASSERT(c == 3, "three L-stock states superseded");
    /* the LSP reveals the secret of every superseded state 0..c-1 */
    unsigned char revealed[3][32];
    for (uint32_t s = 0; s < c; s++)
        TEST_ASSERT(rl_lstock_hash_of(f, leaf, s, revealed[s]), "revealed hash");

    /* restart */
    factory_t *g = calloc(1, sizeof(factory_t));
    TEST_ASSERT(g && persist_load_factory(&db, 0, g, ctx), "reload");
    factory_set_shachain_seed(g, g_rl_seed);       /* LSP recovery re-derives it */
    TEST_ASSERT(factory_enable_hashlock_poison(g), "re-enable hashlock");
    int verified = factory_verify_l_stock_state(g);
    factory_node_t *gl = &g->nodes[leaf];
    printf("  reload: flag=%d, L-stock counter %u (stored %u), verified=%d\n",
           g->tree_rebuilt_on_load, gl->l_stock_state_counter, c, verified);
    uint32_t restored = gl->l_stock_state_counter;
    int adv = factory_advance_leaf_unsigned(g, 0);
    int reused = -1;
    for (uint32_t s = 0; s < c; s++)
        if (memcmp(gl->l_stock_hash, revealed[s], 32) == 0) reused = (int)s;
    printf("  next state: counter %u, its L-stock hash %s", gl->l_stock_state_counter,
           reused >= 0 ? "IS the hash of revealed state " : "is fresh\n");
    if (reused >= 0) printf("%d's secret\n", reused);
    TEST_ASSERT(!g->tree_rebuilt_on_load, "reload verified");
    TEST_ASSERT(restored == c, "L-stock counter restored");
    TEST_ASSERT(verified, "restored counter agrees with the seed and the L-stock output");
    TEST_ASSERT(adv == 1, "next advance");
    TEST_ASSERT(reused < 0, "the new L-stock is not hashlocked to a revealed secret");
    unsigned char want[32];
    TEST_ASSERT(rl_lstock_hash_of(g, leaf, c + 1, want), "hash of the next state");
    TEST_ASSERT(memcmp(gl->l_stock_hash, want, 32) == 0,
                "the new L-stock commits to the next state's secret");
    factory_free(g); free(g);

    /* a DB without the counter rows (written by an older build) */
    TEST_ASSERT(sqlite3_exec(db.db, "DELETE FROM tree_node_lstock", NULL, NULL,
                             NULL) == SQLITE_OK, "drop counter rows");
    g = calloc(1, sizeof(factory_t));
    TEST_ASSERT(g && persist_load_factory(&db, 0, g, ctx), "reload without counters");
    printf("  no counter rows: flag=%d\n", g->tree_rebuilt_on_load);
    TEST_ASSERT(g->tree_rebuilt_on_load, "advanced node without its counter -> refused");
    factory_free(g); free(g);

    /* a tampered counter */
    TEST_ASSERT(persist_save_tree_nodes(&db, f, 0), "rewrite the rows");
    char sql[160];
    snprintf(sql, sizeof(sql), "UPDATE tree_node_lstock SET state_counter=1 "
             "WHERE factory_id=0 AND node_index=%zu", leaf);
    TEST_ASSERT(sqlite3_exec(db.db, sql, NULL, NULL, NULL) == SQLITE_OK, "tamper");
    g = calloc(1, sizeof(factory_t));
    TEST_ASSERT(g && persist_load_factory(&db, 0, g, ctx), "reload tampered");
    factory_set_shachain_seed(g, g_rl_seed);
    factory_enable_hashlock_poison(g);
    verified = factory_verify_l_stock_state(g);
    printf("  tampered counter: verified=%d\n", verified);
    TEST_ASSERT(!verified, "a counter that does not match the stored hash is caught");
    factory_free(g); free(g);

    persist_close(&db);
    unlink(path);
    factory_free(f); free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Hashlock DW leaf on the LSP and on a seedless client that mirrors the
   LSP's per-node hashes (as it is sent them in PROPOSE): two advances, both
   persisted (the client through client_persist_exit_state), both restarted.
   Each restores the leaf's L-stock counter and current hash, the LSP's next
   state commits to a fresh secret, and the restarted client builds the
   identical TX. */
int test_reload_lstock_counter_client(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kps[3];
    secp256k1_pubkey pks[3];
    TEST_ASSERT(ex_keys(ctx, 3, kps, pks), "keys");
    unsigned char spk[34], fund[32];
    TEST_ASSERT(ex_funding_spk(ctx, pks, 3, spk, NULL), "spk");
    memset(fund, 0x62, 32);
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f && rl_build_hashlock(ctx, f, kps, 3, FACTORY_ARITY_1, 0, fund,
                                       spk, 8), "LSP factory");
    size_t leaf = f->leaf_node_indices[0];

    /* the client: no seed, mirrors the per-node hashes it was sent */
    factory_t *c = calloc(1, sizeof(factory_t));
    TEST_ASSERT(c && factory_init(c, ctx, kps, 3, 2, 8), "client init");
    factory_set_arity(c, FACTORY_ARITY_1);
    c->fee_per_tx = 1000;
    for (size_t i = 0; i < f->n_nodes; i++)
        if (f->nodes[i].has_l_stock_hash)
            factory_set_node_l_stock_hash(c, i, f->nodes[i].l_stock_hash);
    factory_set_funding(c, fund, 0, 2000000, spk, 34);
    TEST_ASSERT(factory_build_tree(c) && factory_sign_all(c), "client tree");
    TEST_ASSERT(memcmp(c->nodes[leaf].txid, f->nodes[leaf].txid, 32) == 0,
                "client and LSP agree at creation");

    char path[256], cpath[256];
    ex_db_path(path, sizeof(path), "rl_lsc");
    ex_db_path(cpath, sizeof(cpath), "rl_lscc");
    persist_t db, cdb;
    TEST_ASSERT(ex_persist_factory(&db, path, f, ctx), "LSP persist");
    TEST_ASSERT(persist_save_factory_dw_state(&db, 0, f), "dw");
    TEST_ASSERT(persist_open(&cdb, cpath) && persist_save_factory(&cdb, c, ctx, 0) &&
                client_persist_exit_state(&cdb, c), "client persist");

    for (int a = 0; a < 2; a++) {
        TEST_ASSERT(factory_advance_leaf_unsigned(f, 0) == 1, "LSP advance");
        factory_set_node_l_stock_hash(c, leaf, f->nodes[leaf].l_stock_hash);
        TEST_ASSERT(factory_advance_leaf_unsigned(c, 0) == 1, "client advance");
        int same = memcmp(c->nodes[leaf].txid, f->nodes[leaf].txid, 32) == 0;
        printf("  advance %d: client builds the same state as the LSP: %s\n", a + 1,
               same ? "yes" : "NO");
        TEST_ASSERT(same, "same leaf state");
        TEST_ASSERT(factory_sign_node(f, leaf) && factory_sign_node(c, leaf), "sign");
        TEST_ASSERT(rl_persist_node(&db, f, leaf), "LSP persists the advance");
        TEST_ASSERT(client_persist_exit_state(&cdb, c), "client persists the advance");
    }
    uint32_t cnt = f->nodes[leaf].l_stock_state_counter;
    TEST_ASSERT(cnt == 2, "two L-stock states superseded");
    unsigned char revealed[3][32];
    for (uint32_t s2 = 0; s2 <= cnt; s2++)
        TEST_ASSERT(rl_lstock_hash_of(f, leaf, s2, revealed[s2]), "hashes");

    /* both restart */
    factory_t *g = calloc(1, sizeof(factory_t));
    factory_t *h = calloc(1, sizeof(factory_t));
    TEST_ASSERT(g && persist_load_factory(&db, 0, g, ctx), "LSP reload");
    TEST_ASSERT(h && persist_load_factory(&cdb, 0, h, ctx), "client reload");
    factory_set_shachain_seed(g, g_rl_seed);
    TEST_ASSERT(factory_enable_hashlock_poison(g), "LSP re-enables hashlock");
    int verified = factory_verify_l_stock_state(g);
    printf("  reload: LSP flag=%d counter=%u verified=%d; client flag=%d counter=%u\n",
           g->tree_rebuilt_on_load, g->nodes[leaf].l_stock_state_counter, verified,
           h->tree_rebuilt_on_load, h->nodes[leaf].l_stock_state_counter);
    TEST_ASSERT(!g->tree_rebuilt_on_load && !h->tree_rebuilt_on_load, "both reloads verified");
    TEST_ASSERT(verified, "LSP counter agrees with the seed");
    TEST_ASSERT(g->nodes[leaf].l_stock_state_counter == cnt &&
                h->nodes[leaf].l_stock_state_counter == cnt, "both counters restored");
    TEST_ASSERT(h->nodes[leaf].has_l_stock_hash &&
                memcmp(h->nodes[leaf].l_stock_hash, revealed[cnt], 32) == 0,
                "client restored the current state's hash (the next poison's target)");

    TEST_ASSERT(factory_advance_leaf_unsigned(g, 0) == 1, "LSP advance after restart");
    int reused = -1;
    for (uint32_t s2 = 0; s2 <= cnt; s2++)
        if (memcmp(g->nodes[leaf].l_stock_hash, revealed[s2], 32) == 0) reused = (int)s2;
    printf("  LSP next state: counter %u, hash %s\n", g->nodes[leaf].l_stock_state_counter,
           reused >= 0 ? "REUSES an earlier state's hash" : "fresh");
    TEST_ASSERT(reused < 0, "new L-stock hash is not an earlier (revealed) one");
    factory_set_node_l_stock_hash(h, leaf, g->nodes[leaf].l_stock_hash);
    TEST_ASSERT(factory_advance_leaf_unsigned(h, 0) == 1, "client advance after restart");
    int agree = memcmp(h->nodes[leaf].txid, g->nodes[leaf].txid, 32) == 0;
    printf("  client after restart: counter %u, same TX as the LSP: %s\n",
           h->nodes[leaf].l_stock_state_counter, agree ? "yes" : "NO");
    TEST_ASSERT(agree, "the restarted client builds the identical TX");
    TEST_ASSERT(h->nodes[leaf].l_stock_state_counter == cnt + 1, "client counter agrees");

    factory_free(g); free(g); factory_free(h); free(h);
    persist_close(&db); persist_close(&cdb);
    unlink(path); unlink(cpath);
    factory_free(f); free(f); factory_free(c); free(c);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Persist one PS leaf chain advance the way the LSP does before DONE. */
static int rl_persist_ps_leaf(persist_t *db, factory_t *f, size_t leaf) {
    factory_node_t *n = &f->nodes[leaf];
    unsigned char disp[32];
    memcpy(disp, n->txid, 32);
    reverse_bytes(disp, 32);
    if (!persist_begin(db)) return 0;
    int ok = persist_save_ps_chain_entry(db, 0, (uint32_t)leaf,
                 n->ps_chain_len - 1, f->counter.current_epoch, disp,
                 n->signed_tx.data, n->signed_tx.len,
                 n->outputs[0].amount_sats, NULL, 0) &&
             persist_save_tree_node(db, f, 0, leaf) &&
             persist_save_factory_dw_state(db, 0, f);
    if (ok) return persist_commit(db);
    persist_rollback(db);
    return 0;
}

/* A root rollover after a PS chain longer than the new epoch's: the old
   epoch's rows at higher positions stay in ps_leaf_chains.  The reload must
   take the new epoch's tip (and chain[0] of the new epoch), and the next
   advance must spend it. */
int test_reload_ps_chain_after_rollover(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kps[3];
    secp256k1_pubkey pks[3];
    TEST_ASSERT(ex_keys(ctx, 3, kps, pks), "keys");
    unsigned char spk[34], fund[32];
    TEST_ASSERT(ex_funding_spk(ctx, pks, 3, spk, NULL), "spk");
    memset(fund, 0x63, 32);
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f && ex_build_factory(ctx, f, kps, 3, FACTORY_ARITY_PS, fund, 0,
                                      1000000, spk, 2, 3, 1), "PS factory");
    char path[256];
    ex_db_path(path, sizeof(path), "rl_psroll");
    persist_t db;
    TEST_ASSERT(ex_persist_factory(&db, path, f, ctx), "persist");
    TEST_ASSERT(lsp_persist_ps_chain0_all(&db, f) > 0, "chain[0]");
    TEST_ASSERT(persist_save_factory_dw_state(&db, 0, f), "dw");
    size_t leaf = f->leaf_node_indices[0];

    /* epoch 0: chain[1..3], then the rollover */
    int rolled = 0, n_old = 0;
    for (int a = 0; a < 10 && !rolled; a++) {
        int rc = factory_advance_leaf_unsigned(f, 0);
        if (rc == -1) {
            TEST_ASSERT(factory_sign_all(f), "re-sign the new epoch");
            TEST_ASSERT(ex_persist_tierb(&db, f, 1), "persist the Tier B");
            rolled = 1;
            break;
        }
        TEST_ASSERT(rc == 1 && factory_sign_node(f, leaf), "chain advance");
        TEST_ASSERT(rl_persist_ps_leaf(&db, f, leaf), "persist chain entry");
        n_old++;
    }
    TEST_ASSERT(rolled && f->counter.current_epoch == 1, "rolled over to epoch 1");
    /* epoch 1: one advance */
    TEST_ASSERT(factory_advance_leaf_unsigned(f, 0) == 1 && factory_sign_node(f, leaf),
                "epoch-1 chain advance");
    TEST_ASSERT(rl_persist_ps_leaf(&db, f, leaf), "persist epoch-1 entry");
    char tip[65], prev[65];
    ex_txid_hex(f->nodes[leaf].txid, tip);
    ex_txid_hex(f->nodes[leaf].ps_prev_txid, prev);
    printf("  epoch 0 chain had %d entries; epoch 1 chain has 1 (tip %.16s...); "
           "ps_leaf_chains rows: %d\n", n_old, tip,
           ex_sql_int(&db, "SELECT COUNT(*) FROM ps_leaf_chains"));

    factory_t *g = calloc(1, sizeof(factory_t));
    TEST_ASSERT(g && persist_load_factory(&db, 0, g, ctx), "reload");
    factory_node_t *gl = &g->nodes[leaf];
    char gtip[65], gprev[65];
    ex_txid_hex(gl->txid, gtip);
    ex_txid_hex(gl->ps_prev_txid, gprev);
    printf("  reload: flag=%d epoch=%u chain_len=%d tip %.16s... (%s)\n",
           g->tree_rebuilt_on_load, g->counter.current_epoch, gl->ps_chain_len,
           gtip, strcmp(gtip, tip) == 0 ? "the epoch-1 tip" : "WRONG");
    TEST_ASSERT(!g->tree_rebuilt_on_load, "reload verified");
    TEST_ASSERT(gl->ps_chain_len == 1, "chain length of the current epoch");
    TEST_ASSERT(strcmp(gtip, tip) == 0, "tip is the epoch-1 entry");
    TEST_ASSERT(strcmp(gprev, prev) == 0, "it spends the epoch-1 chain[0]");
    TEST_ASSERT(factory_advance_leaf_unsigned(g, 0) == 1, "next advance");
    char nprev[65];
    ex_txid_hex(gl->ps_prev_txid, nprev);
    TEST_ASSERT(strcmp(nprev, tip) == 0, "the next chain TX spends the epoch-1 tip");
    factory_free(g); free(g);

    /* chain[0] row of the wrong epoch -> fail closed */
    TEST_ASSERT(sqlite3_exec(db.db, "UPDATE ps_initial_signed_states SET epoch=0",
                             NULL, NULL, NULL) == SQLITE_OK, "tamper epoch");
    g = calloc(1, sizeof(factory_t));
    TEST_ASSERT(g && persist_load_factory(&db, 0, g, ctx), "reload tampered");
    printf("  chain[0] of the old epoch: flag=%d\n", g->tree_rebuilt_on_load);
    TEST_ASSERT(g->tree_rebuilt_on_load, "epoch mismatch -> refused");
    factory_free(g); free(g);

    persist_close(&db);
    unlink(path);
    factory_free(f); free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* The chain loaders (leaf and sub-factory) skip other epochs' rows and stop
   at a row that does not spend the previous entry. */
int test_reload_ps_chain_loaders_filter_epoch(void) {
    char path[256];
    ex_db_path(path, sizeof(path), "rl_loaders");
    persist_t db;
    TEST_ASSERT(persist_open(&db, path), "db");
    unsigned char p0[32];
    memset(p0, 0x11, 32);
    char c0hex[256], c0id[65];
    ex_dummy_tx(p0, 0, c0hex);
    TEST_ASSERT(ex_txid_of_hex(c0hex, c0id), "chain[0] txid");
    unsigned char c0b[128], c0disp[32], c0int[32];
    size_t c0len = strlen(c0hex) / 2;
    hex_decode(c0hex, c0b, c0len);
    hex_decode(c0id, c0disp, 32);
    memcpy(c0int, c0disp, 32);
    reverse_bytes(c0int, 32);
    /* row 0 of epoch 1 spends chain[0]; rows 1-2 are a longer epoch-0 chain */
    char r0hex[256], r0id[65], s1hex[256], s1id[65], s2hex[256], s2id[65];
    ex_dummy_tx(c0int, 0, r0hex);
    ex_txid_of_hex(r0hex, r0id);
    unsigned char junk[32];
    memset(junk, 0x22, 32);
    ex_dummy_tx(junk, 1, s1hex);
    ex_txid_of_hex(s1hex, s1id);
    memset(junk, 0x23, 32);
    ex_dummy_tx(junk, 2, s2hex);
    ex_txid_of_hex(s2hex, s2id);
    for (int table = 0; table < 2; table++) {
        uint32_t node = table ? 9 : 5;
        TEST_ASSERT(persist_save_ps_initial_signed_state(&db, 0, node, 1, c0disp,
                                                         c0b, c0len), "chain[0] row");
        const char *hx[3] = { r0hex, s1hex, s2hex };
        const char *id[3] = { r0id, s1id, s2id };
        uint32_t ep[3] = { 1, 0, 0 };
        for (int k = 0; k < 3; k++) {
            unsigned char b[128], d[32];
            size_t bl = strlen(hx[k]) / 2;
            hex_decode(hx[k], b, bl);
            hex_decode(id[k], d, 32);
            uint64_t ch[1] = { 5000 };
            int ok = table
                ? persist_save_subfactory_chain_entry(&db, 0, node, k, ep[k], d, b, bl,
                                                      1000, ch, 1, NULL, 0)
                : persist_save_ps_chain_entry(&db, 0, node, k, ep[k], d, b, bl,
                                              5000, NULL, 0);
            TEST_ASSERT(ok, "chain row");
        }
        tx_buf_t txs[8];
        unsigned char ids[8][32];
        uint64_t a1[8], a16[8][16];
        int nch[8];
        memset(txs, 0, sizeof(txs));
        int n = table
            ? persist_load_subfactory_chain(&db, 0, node, txs, ids, a1, a16, nch, NULL, 8)
            : persist_load_ps_chain(&db, 0, node, txs, ids, a1, NULL, 8);
        printf("  %s chain: 1 row of the current epoch + 2 older rows -> loaded %d\n",
               table ? "sub-factory" : "leaf", n);
        for (int k = 0; k < n; k++) tx_buf_free(&txs[k]);
        TEST_ASSERT(n == 1, "only the current epoch's linked rows");

        /* a same-epoch row that does not spend the previous entry ends it */
        unsigned char b1[128], d1[32];
        size_t bl1 = strlen(s1hex) / 2;
        hex_decode(s1hex, b1, bl1);
        hex_decode(s1id, d1, 32);
        uint64_t ch1[1] = { 5000 };
        TEST_ASSERT(table
            ? persist_save_subfactory_chain_entry(&db, 0, node, 1, 1, d1, b1, bl1,
                                                  1000, ch1, 1, NULL, 0)
            : persist_save_ps_chain_entry(&db, 0, node, 1, 1, d1, b1, bl1, 5000,
                                          NULL, 0), "unlinked row");
        memset(txs, 0, sizeof(txs));
        n = table
            ? persist_load_subfactory_chain(&db, 0, node, txs, ids, a1, a16, nch, NULL, 8)
            : persist_load_ps_chain(&db, 0, node, txs, ids, a1, NULL, 8);
        for (int k = 0; k < n; k++) tx_buf_free(&txs[k]);
        TEST_ASSERT(n == 1, "an unlinked row is not part of the chain");
    }
    persist_close(&db);
    unlink(path);
    return 1;
}

/* Forwards the wire between the LSP and a client, except one message type
   from the client, which it swallows before closing both sides. */
typedef struct {
    int lsp_fd, cli_fd;
    uint8_t drop_type;
    int dropped;
} rl_proxy_t;

static void *rl_proxy_thread(void *arg) {
    rl_proxy_t *x = (rl_proxy_t *)arg;
    for (;;) {
        struct pollfd pf[2] = { { .fd = x->lsp_fd, .events = POLLIN },
                                { .fd = x->cli_fd, .events = POLLIN } };
        if (poll(pf, 2, 130000) <= 0) break;
        int from_cli = (pf[1].revents & (POLLIN | POLLHUP)) ? 1 : 0;
        int src = from_cli ? x->cli_fd : x->lsp_fd;
        int dst = from_cli ? x->lsp_fd : x->cli_fd;
        wire_msg_t m;
        memset(&m, 0, sizeof(m));
        if (!wire_recv(src, &m)) break;
        if (from_cli && m.msg_type == x->drop_type) {
            x->dropped = 1;
            if (m.json) cJSON_Delete(m.json);
            break;
        }
        int sent = wire_send(dst, m.msg_type, m.json);
        if (m.json) cJSON_Delete(m.json);
        if (!sent) break;
    }
    shutdown(x->lsp_fd, SHUT_RDWR);
    shutdown(x->cli_fd, SHUT_RDWR);
    return NULL;
}

/* Fresh LSP <-> client socketpair for the rig (the old one may be shut). */
static int rl_rig_reconnect(ex_rig_t *r) {
    if (r->sv[0] >= 0) close(r->sv[0]);
    if (r->sv[1] >= 0) close(r->sv[1]);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, r->sv) != 0) return 0;
    struct timeval tv = { .tv_sec = 120, .tv_usec = 0 };
    setsockopt(r->sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(r->sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    r->lsp->client_fds[0] = r->sv[0];
    return 1;
}

/* LSP restart: the factory is reloaded from the LSP DB. */
static int rl_rig_restart_lsp(ex_rig_t *r) {
    factory_free(&r->lsp->factory);
    memset(&r->lsp->factory, 0, sizeof(r->lsp->factory));
    return persist_load_factory(&r->db, 0, &r->lsp->factory, r->ctx) &&
           !r->lsp->factory.tree_rebuilt_on_load;
}

/* Client restart: its factory is reloaded from the client DB. */
static int rl_rig_restart_client(ex_rig_t *r) {
    factory_free(r->cf);
    memset(r->cf, 0, sizeof(*r->cf));
    return persist_load_factory(&r->cdb, 0, r->cf, r->ctx);
}

/* One leaf advance in which the client's FINAL never reaches the LSP: the
   client completes the new state with the LSP's partial sig, then the
   connection drops.  out_txid gets the state the client holds. */
static int rl_withheld_final(ex_rig_t *r, unsigned char out_txid[32],
                             int *lsp_rc) {
    int q[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, q) != 0) return 0;
    rl_proxy_t px = { .lsp_fd = r->sv[1], .cli_fd = q[0],
                      .drop_type = MSG_LEAF_ADVANCE_FINAL, .dropped = 0 };
    ex_client_t cl = { .fd = q[1], .ctx = r->ctx, .kp = r->kps[1],
                       .f = r->cf, .my_index = 1, .n_expected = 1, .ok = 0 };
    pthread_t tp, tc;
    if (pthread_create(&tp, NULL, rl_proxy_thread, &px) != 0) return 0;
    if (pthread_create(&tc, NULL, ex_client_thread, &cl) != 0) return 0;
    *lsp_rc = lsp_channels_advance_ps_leaf(r->mgr, r->lsp, 0);
    shutdown(r->sv[0], SHUT_RDWR);
    pthread_join(tp, NULL);
    pthread_join(tc, NULL);
    close(q[0]); close(q[1]);
    size_t leaf = r->cf->leaf_node_indices[0];
    memcpy(out_txid, r->cf->nodes[leaf].txid, 32);
    return px.dropped && r->cf->nodes[leaf].is_signed;
}

/* DW leaf: the LSP releases its partial sig, the client completes state 1
   and withholds FINAL, the LSP restarts at state 0.  A different state 1 (a
   realloc at the same nSequence) must be refused; the identical state 1 may
   be signed again. */
int test_reload_withheld_final_dw(void) {
    /* a side that refuses hangs up; a write to it must not kill the run */
    signal(SIGPIPE, SIG_IGN);
    ex_rig_t r;
    TEST_ASSERT(ex_rig_init(&r, FACTORY_ARITY_1, "rl_wfdw", 0), "rig");
    alarm(300);
    size_t leaf = r.lsp->factory.leaf_node_indices[0];
    char stored0[65], sql[200];
    snprintf(sql, sizeof(sql), "SELECT txid FROM tree_nodes WHERE factory_id=0 "
             "AND node_index=%zu", leaf);
    ex_sql_text(&r.db, sql, stored0, sizeof(stored0));

    unsigned char t1[32];
    int lrc = -1;
    TEST_ASSERT(rl_withheld_final(&r, t1, &lrc), "client holds state 1, FINAL withheld");
    char t1hex[65], stored[65];
    ex_txid_hex(t1, t1hex);
    ex_sql_text(&r.db, sql, stored, sizeof(stored));
    printf("  withheld FINAL: LSP rc=%d, client holds state 1 %.16s..., LSP DB "
           "still at state 0: %s\n", lrc, t1hex,
           strcmp(stored, stored0) == 0 ? "yes" : "no");
    TEST_ASSERT(lrc == 0 && strcmp(stored, stored0) == 0, "the LSP stored nothing");

    /* LSP restart; a client at state 0 that signs whatever it is sent */
    TEST_ASSERT(rl_rig_restart_lsp(&r), "LSP reload");
    TEST_ASSERT(r.lsp->factory.leaf_layers[0].current_state == 0, "LSP back at state 0");
    TEST_ASSERT(rl_rig_restart_client(&r) && rl_rig_reconnect(&r), "client at state 0");
    uint64_t amts[FACTORY_MAX_OUTPUTS];
    size_t na = ex_realloc_amounts(&r.lsp->factory.nodes[leaf], 1000, amts);
    int client_ok = 0;
    int rc = ex_rig_realloc(&r, amts, na, &client_ok);
    char t1b[65];
    ex_txid_hex(r.lsp->factory.nodes[leaf].txid, t1b);
    printf("  after the restart, a realloc to a different state 1: rc=%d (%s)\n", rc,
           rc == 1 ? "a SECOND state 1 was signed" : "refused");
    if (rc == 1)
        printf("  two signed states with nSequence %u: %.16s... and %.16s...\n",
               r.lsp->factory.nodes[leaf].nsequence, t1hex, t1b);
    TEST_ASSERT(rc == 0, "a different state 1 is not signed");

    /* the identical state 1 is signed again */
    TEST_ASSERT(rl_rig_restart_lsp(&r), "LSP reload 2");
    TEST_ASSERT(rl_rig_restart_client(&r) && rl_rig_reconnect(&r), "client reload 2");
    rc = ex_rig_ps_advance(&r, &client_ok);
    char again[65];
    ex_txid_hex(r.lsp->factory.nodes[leaf].txid, again);
    printf("  plain leaf advance after the restart: rc=%d, state 1 %.16s... (%s)\n",
           rc, again, strcmp(again, t1hex) == 0 ? "identical" : "DIFFERENT");
    TEST_ASSERT(rc == 1 && client_ok, "the identical state is re-signed");
    TEST_ASSERT(strcmp(again, t1hex) == 0, "and it is the state the client held");
    alarm(0);
    ex_rig_free(&r);
    return 1;
}

/* PS leaf: same, for chain[1].  Only the identical chain[1] may be signed
   for chain[0]'s output; a record of a different chain[1] refuses it. */
int test_reload_withheld_final_ps(void) {
    /* a side that refuses hangs up; a write to it must not kill the run */
    signal(SIGPIPE, SIG_IGN);
    ex_rig_t r;
    TEST_ASSERT(ex_rig_init(&r, FACTORY_ARITY_PS, "rl_wfps", 0), "rig");
    alarm(300);
    size_t leaf = r.lsp->factory.leaf_node_indices[0];
    unsigned char t1[32];
    int lrc = -1;
    TEST_ASSERT(rl_withheld_final(&r, t1, &lrc), "client holds chain[1], FINAL withheld");
    char t1hex[65];
    ex_txid_hex(t1, t1hex);
    int nres = ex_sql_int(&r.db, "SELECT COUNT(*) FROM signed_state_reservations");
    printf("  withheld FINAL: LSP rc=%d, client holds chain[1] %.16s..., "
           "reservations=%d\n", lrc, t1hex, nres);
    TEST_ASSERT(lrc == 0, "the LSP did not complete");
    TEST_ASSERT(nres >= 1, "the LSP reserved chain[1] before releasing its partial sig");

    /* a record of a different chain[1] for the same output refuses it */
    TEST_ASSERT(sqlite3_exec(r.db.db, "UPDATE signed_state_reservations SET txid="
        "'00000000000000000000000000000000000000000000000000000000000000aa'",
        NULL, NULL, NULL) == SQLITE_OK, "swap the record");
    TEST_ASSERT(rl_rig_restart_lsp(&r), "LSP reload");
    TEST_ASSERT(rl_rig_restart_client(&r) && rl_rig_reconnect(&r), "client reload");
    int client_ok = 0;
    int rc = ex_rig_ps_advance(&r, &client_ok);
    printf("  chain[1] with another TX recorded for chain[0]'s output: rc=%d\n", rc);
    TEST_ASSERT(rc == 0, "refused");

    /* with the real record, the identical chain[1] is signed again */
    char upd[200];
    snprintf(upd, sizeof(upd), "UPDATE signed_state_reservations SET txid='%s'", t1hex);
    TEST_ASSERT(sqlite3_exec(r.db.db, upd, NULL, NULL, NULL) == SQLITE_OK, "restore");
    TEST_ASSERT(rl_rig_restart_lsp(&r), "LSP reload 2");
    TEST_ASSERT(rl_rig_restart_client(&r) && rl_rig_reconnect(&r), "client reload 2");
    rc = ex_rig_ps_advance(&r, &client_ok);
    char again[65];
    ex_txid_hex(r.lsp->factory.nodes[leaf].txid, again);
    printf("  restart, identical chain[1]: rc=%d %.16s... (%s)\n", rc, again,
           strcmp(again, t1hex) == 0 ? "identical" : "DIFFERENT");
    TEST_ASSERT(rc == 1 && client_ok && strcmp(again, t1hex) == 0,
                "the identical chain[1] is re-signed");
    alarm(0);
    ex_rig_free(&r);
    return 1;
}

/* The client thread, then hang up (a refusing client stops answering; the
   LSP should not sit out its receive timeout). */
static void *rl_client_thread_closing(void *arg) {
    ex_client_thread(arg);
    shutdown(((ex_client_t *)arg)->fd, SHUT_RDWR);
    return NULL;
}

/* Client side: the client completes state 1 with the LSP (it sends FINAL)
   and crashes before storing it; after its restart (state 0), an LSP that
   reloaded an old state proposes a different state 1.  The client must
   refuse to sign it. */
int test_reload_client_refuses_conflicting_state(void) {
    /* a side that refuses hangs up; a write to it must not kill the run */
    signal(SIGPIPE, SIG_IGN);
    ex_rig_t r;
    TEST_ASSERT(ex_rig_init(&r, FACTORY_ARITY_1, "rl_cli", 0), "rig");
    alarm(300);
    size_t leaf = r.lsp->factory.leaf_node_indices[0];
    client_set_persist(&r.cdb);

    ex_client_t cl = { .fd = r.sv[1], .ctx = r.ctx, .kp = r.kps[1],
                       .f = r.cf, .my_index = 1, .n_expected = 1, .ok = 0 };
    pthread_t th;
    TEST_ASSERT(pthread_create(&th, NULL, ex_client_thread, &cl) == 0, "thread");
    int rc = lsp_channels_advance_ps_leaf(r.mgr, r.lsp, 0);
    pthread_join(th, NULL);
    TEST_ASSERT(rc == 1 && cl.ok, "state 1 signed by both");
    char t1[65];
    ex_txid_hex(r.lsp->factory.nodes[leaf].txid, t1);
    /* the client crashes before client_persist_exit_state */
    TEST_ASSERT(rl_rig_restart_client(&r), "client reload (state 0)");

    /* an LSP back at state 0 (an old backup, no reservations) */
    persist_t *keep = r.mgr->persist;
    r.mgr->persist = NULL;
    factory_free(&r.lsp->factory);
    TEST_ASSERT(ex_build_factory(r.ctx, &r.lsp->factory, r.kps, 3, FACTORY_ARITY_1,
                                 r.fund_txid, 0, 1000000, r.spk, 2, 4, 1),
                "LSP at state 0");
    TEST_ASSERT(rl_rig_reconnect(&r), "reconnect");
    uint64_t amts[FACTORY_MAX_OUTPUTS];
    size_t na = ex_realloc_amounts(&r.lsp->factory.nodes[leaf], 1000, amts);
    ex_client_t cl2 = { .fd = r.sv[1], .ctx = r.ctx, .kp = r.kps[1],
                        .f = r.cf, .my_index = 1, .n_expected = 1, .ok = 0 };
    TEST_ASSERT(pthread_create(&th, NULL, rl_client_thread_closing, &cl2) == 0,
                "thread 2");
    rc = lsp_realloc_leaf(r.mgr, r.lsp, 0, amts, na);
    if (rc != 1) shutdown(r.sv[0], SHUT_RDWR);
    pthread_join(th, NULL);
    int client_ok = cl2.ok;
    char t1b[65];
    ex_txid_hex(r.lsp->factory.nodes[leaf].txid, t1b);
    printf("  restarted client asked for a different state 1: rc=%d client_ok=%d (%s)\n",
           rc, client_ok, rc == 1 ? "the client SIGNED a second state 1" : "refused");
    if (rc == 1)
        printf("  the LSP holds two signed states 1: %.16s... and %.16s...\n", t1, t1b);
    client_set_persist(NULL);
    r.mgr->persist = keep;
    alarm(0);
    TEST_ASSERT(rc == 0 && !client_ok, "the client refuses a different state 1");
    ex_rig_free(&r);
    return 1;
}

/* After a reload the on-request reveal is capped at the stored L-stock state:
   superseded states are still handed out, the stored one is not, and a
   ceremony that moved the in-memory counter but stored nothing (the client
   stopped answering) does not raise the cap. */
int test_reload_reveal_cap_after_reload(void) {
    /* a side that refuses hangs up; a write to it must not kill the run */
    signal(SIGPIPE, SIG_IGN);
    ex_rig_t r;
    TEST_ASSERT(ex_rig_init(&r, FACTORY_ARITY_1, "rl_cap", 1), "rig");
    alarm(300);
    size_t leaf = r.lsp->factory.leaf_node_indices[0];
    uint64_t amts[FACTORY_MAX_OUTPUTS];
    int client_ok = 0;
    for (int a = 0; a < 2; a++) {
        size_t na = ex_realloc_amounts(&r.lsp->factory.nodes[leaf], 1000, amts);
        TEST_ASSERT(ex_rig_realloc(&r, amts, na, &client_ok) == 1 && client_ok,
                    "durable realloc");
        TEST_ASSERT(client_persist_exit_state(&r.cdb, r.cf), "client persists");
    }
    uint32_t c = r.lsp->factory.nodes[leaf].l_stock_state_counter;
    TEST_ASSERT(c == 2, "two states superseded");
    TEST_ASSERT(rl_rig_restart_lsp(&r), "LSP reload");
    {   /* the rig's L-stock seed, re-set as LSP recovery does */
        unsigned char seed[32] = { 0x5e, 0xed };
        for (int i = 2; i < 32; i++) seed[i] = (unsigned char)(i - 1);
        factory_set_shachain_seed(&r.lsp->factory, seed);
    }
    factory_node_t *ln = &r.lsp->factory.nodes[leaf];
    TEST_ASSERT(ln->l_stock_state_counter == c, "counter restored");
    r.lsp->factory.use_hashlock_poison = 1;   /* only the reveal handler reads it */
    int a1 = ex_request_reveal(&r, (uint32_t)leaf, c - 1);
    int a2 = ex_request_reveal(&r, (uint32_t)leaf, c);
    r.lsp->factory.use_hashlock_poison = 0;
    printf("  after reload (stored state %u): state %u revealed %d, state %u revealed %d\n",
           c, c - 1, a1, c, a2);
    TEST_ASSERT(a1 == 1, "a superseded state is still revealed");
    TEST_ASSERT(a2 == 0, "the stored state is not");

    /* a realloc the client never answers: the counter moves, nothing is stored */
    shutdown(r.sv[1], SHUT_RDWR);
    size_t na = ex_realloc_amounts(ln, 1000, amts);
    int rc = lsp_realloc_leaf(r.mgr, r.lsp, 0, amts, na);
    TEST_ASSERT(rc == 0 && ln->l_stock_state_counter == c + 1,
                "ceremony stopped after the counter moved");
    TEST_ASSERT(rl_rig_reconnect(&r), "reconnect");
    r.lsp->factory.use_hashlock_poison = 1;
    int a3 = ex_request_reveal(&r, (uint32_t)leaf, c);
    r.lsp->factory.use_hashlock_poison = 0;
    printf("  after a ceremony that stored nothing (in memory %u): state %u revealed %d\n",
           ln->l_stock_state_counter, c, a3);
    alarm(0);
    TEST_ASSERT(a3 == 0, "the state still in the DB is not revealed");
    ex_rig_free(&r);
    return 1;
}

/* A DW-only (arity-1) client DB records no epoch: no dw_counter_state row and
   no PS chain rows.  After a root rollover the reload cannot tell the epoch
   and must stay refused rather than reload it as 0. */
int test_reload_dw_client_epoch_unknown(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kps[3];
    secp256k1_pubkey pks[3];
    TEST_ASSERT(ex_keys(ctx, 3, kps, pks), "keys");
    unsigned char spk[34], fund[32];
    TEST_ASSERT(ex_funding_spk(ctx, pks, 3, spk, NULL), "spk");
    memset(fund, 0x64, 32);
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f && ex_build_factory(ctx, f, kps, 3, FACTORY_ARITY_1, fund, 0,
                                      1000000, spk, 2, 2, 1), "DW factory");
    char cpath[256];
    ex_db_path(cpath, sizeof(cpath), "rl_dwcli");
    persist_t cdb;
    TEST_ASSERT(persist_open(&cdb, cpath) && persist_save_factory(&cdb, f, ctx, 0) &&
                client_persist_exit_state(&cdb, f), "client DB");

    /* before any rollover the client reloads normally */
    factory_t *g = calloc(1, sizeof(factory_t));
    TEST_ASSERT(g && persist_load_factory(&cdb, 0, g, ctx), "reload");
    TEST_ASSERT(!g->tree_rebuilt_on_load, "epoch 0: reload verified");
    factory_free(g); free(g);

    uint32_t epoch = ex_local_rollover(f, 10);
    TEST_ASSERT(epoch > 0, "rolled over");
    TEST_ASSERT(ex_persist_tierb(&cdb, f, 0), "client persists the new epoch");
    g = calloc(1, sizeof(factory_t));
    TEST_ASSERT(g && persist_load_factory(&cdb, 0, g, ctx), "reload after rollover");
    printf("  DW-only client DB after a rollover to epoch %u: flag=%d (epoch reloaded as %u)\n",
           epoch, g->tree_rebuilt_on_load, g->counter.current_epoch);
    TEST_ASSERT(g->tree_rebuilt_on_load, "epoch unknown -> refused, not reloaded as 0");
    factory_free(g); free(g);

    persist_close(&cdb);
    unlink(cpath);
    factory_free(f); free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}
