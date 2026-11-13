/* Channel-update engine tests: the state machine, the reconciliation
   table, crash and restart at every persist and send point, queueing of
   messages that arrive mid-round, and the lost revoke_and_ack case.

   Two engines (host and member) run in one process, each on its own
   SQLite file.  A "crash" stops a call at a named point and drops the
   engine and its connection; the side restarts from its file. */

#include "superscalar/chan_update.h"
#include "superscalar/persist.h"
#include "superscalar/sha256.h"
#include <secp256k1.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

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

/* ------------------------------------------------------------------ */
/* Fake commitment layer: deterministic transactions and signatures     */
/* ------------------------------------------------------------------ */

typedef struct {
    int side;
    unsigned char key[2][32];     /* both sides' signing keys (fake) */
    uint32_t my_nonce_next;       /* own pool, per connection */
    uint32_t peer_nonce_next;     /* next peer nonce index expected */
    int fail_penalty;
} fake_t;

static void put64(unsigned char **p, uint64_t v) { for (int i = 7; i >= 0; i--) *(*p)++ = (unsigned char)(v >> (8 * i)); }

static void state_hash(const cu_state_t *s, unsigned char out[32]) {
    static unsigned char buf[64 + CU_HTLC_CAP * 64];
    unsigned char *p = buf;
    put64(&p, s->host_msat); put64(&p, s->member_msat); put64(&p, s->feerate_per_kvb);
    put64(&p, s->fee_msat); put64(&p, s->next_htlc_id[0]); put64(&p, s->next_htlc_id[1]);
    put64(&p, s->n_htlcs);
    for (size_t i = 0; i < s->n_htlcs; i++) {
        put64(&p, s->htlcs[i].id); *p++ = s->htlcs[i].offerer; put64(&p, s->htlcs[i].amount_msat);
        memcpy(p, s->htlcs[i].payment_hash, 32); p += 32; put64(&p, s->htlcs[i].cltv_expiry);
    }
    sha256(buf, (size_t)(p - buf), out);
}

static secp256k1_context *g_secp;

static int f_build(void *ctx, cu_side_t holder, uint64_t n, const cu_state_t *st,
                   const secp256k1_pubkey *pt, unsigned char *tx, size_t *len, unsigned char txid[32]) {
    (void)ctx;
    unsigned char *p = tx;
    if (*len < 4 + 1 + 8 + 33 + 32) return 0;
    memcpy(p, "CUTX", 4); p += 4;
    *p++ = (unsigned char)holder;
    put64(&p, n);
    size_t pl = 33;
    secp256k1_ec_pubkey_serialize(g_secp, p, &pl, pt, SECP256K1_EC_COMPRESSED); p += 33;
    state_hash(st, p); p += 32;
    *len = (size_t)(p - tx);
    sha256(tx, *len, txid);
    return 1;
}

static uint64_t f_fee(void *ctx, const cu_state_t *st) {
    (void)ctx;
    return (200 + 43 * (uint64_t)st->n_htlcs) * st->feerate_per_kvb;   /* vB * sat/kvB = msat */
}

static void f_psig(const unsigned char key[32], const unsigned char *tx, size_t len, uint32_t idx,
                   unsigned char out[32]) {
    unsigned char buf[32 + 32 + 4], txid[32];
    sha256(tx, len, txid);
    memcpy(buf, key, 32); memcpy(buf + 32, txid, 32);
    buf[64] = (unsigned char)(idx >> 24); buf[65] = (unsigned char)(idx >> 16);
    buf[66] = (unsigned char)(idx >> 8); buf[67] = (unsigned char)idx;
    sha256(buf, sizeof(buf), out);
}

static int f_sign(void *ctx, uint64_t n, const unsigned char *tx, size_t len,
                  unsigned char psig[32], uint32_t *idx) {
    fake_t *f = ctx;
    (void)n;
    *idx = f->my_nonce_next++;
    f_psig(f->key[f->side], tx, len, *idx, psig);
    return 1;
}

static int f_verify(void *ctx, uint64_t n, const unsigned char *tx, size_t len,
                    const unsigned char psig[32], uint32_t idx, unsigned char sig64[64]) {
    fake_t *f = ctx;
    unsigned char want[32];
    (void)n;
    if (idx != f->peer_nonce_next) return 0;      /* only the next unused index */
    f->peer_nonce_next++;
    f_psig(f->key[1 - f->side], tx, len, idx, want);
    if (memcmp(want, psig, 32) != 0) return 0;
    memcpy(sig64, psig, 32);
    f_psig(f->key[f->side], tx, len, 0xffffffffu, sig64 + 32);
    return 1;
}

static int f_penalty(void *ctx, persist_t *db, uint64_t n, const unsigned char secret[32],
                     const unsigned char *tx, size_t len) {
    fake_t *f = ctx;
    unsigned char txid[32];
    sqlite3_stmt *st;
    if (f->fail_penalty) return 0;
    sha256(tx, len, txid);
    if (sqlite3_prepare_v2(db->db, "INSERT OR IGNORE INTO test_watch (commit_num, txid, secret)"
                                   " VALUES (?,?,?);", -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)n);
    sqlite3_bind_blob(st, 2, txid, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, secret, 32, SQLITE_TRANSIENT);
    int ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static int f_claim(void *ctx, persist_t *db, uint64_t n, const cu_htlc_t *h, const unsigned char pre[32]) {
    sqlite3_stmt *st;
    (void)ctx; (void)n;
    if (sqlite3_prepare_v2(db->db, "INSERT OR IGNORE INTO test_claim (offerer, htlc_id, preimage)"
                                   " VALUES (?,?,?);", -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int(st, 1, h->offerer);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)h->id);
    sqlite3_bind_blob(st, 3, pre, 32, SQLITE_TRANSIENT);
    int ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static void f_reset(void *ctx) {
    fake_t *f = ctx;
    f->my_nonce_next = 0;
    f->peer_nonce_next = 0;
}

static void f_skip(void *ctx, uint32_t idx) {
    fake_t *f = ctx;
    if (idx == f->peer_nonce_next) f->peer_nonce_next++;
}

static const cu_ops_t FAKE_OPS = { f_build, f_fee, f_sign, f_verify, f_penalty, f_claim, f_reset, f_skip };

/* ------------------------------------------------------------------ */
/* Two-engine network                                                  */
/* ------------------------------------------------------------------ */

#define PIPE_CAP 512
#define CAPACITY_MSAT 1000000000ull
#define TIP 500

struct net;
typedef struct {
    struct net *net;
    int idx;
    char path[256];
    persist_t db;
    cu_chan_t *c;
    fake_t f;
    cu_config_t cfg;
    cu_event_t evlog[512];
    size_t n_evlog;
} side_t;

typedef struct net {
    side_t s[2];                  /* 0 host, 1 member */
    cu_msg_t pipe[2][PIPE_CAP];   /* pipe[i]: messages to side i */
    size_t n_pipe[2];
    size_t delivered;             /* messages delivered since reset */
    int crash_side, crash_point, crash_ret, crash_fired;
    int early_release;            /* a dependent message in the outbox at a persist point */
    int drop_type[2];             /* drop the next message of this type sent to side i */
} net_t;

static int g_dbseq = 0;
static char g_template[256];

static int copy_file(const char *from, const char *to);

/* A migrated, empty database, copied for every side: running every
   migration on every fresh file costs a commit each. */
static int fresh_db(const char *path) {
    mode_t old = umask(077);       /* restored: other tests depend on the process umask */
    int ok = 1;
    if (!g_template[0]) {
        persist_t t;
        snprintf(g_template, sizeof(g_template), "/tmp/test_cu_%d_template.db", (int)getpid());
        unlink(g_template);
        if (!persist_open(&t, g_template)) { g_template[0] = 0; ok = 0; }
        else {
            sqlite3_exec(t.db, "PRAGMA wal_checkpoint(TRUNCATE);", NULL, NULL, NULL);
            persist_close(&t);
        }
    }
    ok = ok && copy_file(g_template, path);
    umask(old);
    return ok;
}

/* INV-22: when a write is committing, the signature or secret it protects
   is not yet in the outbox. */
static void check_not_released(side_t *s, int point) {
    const cu_chan_t *c = s->c;
    uint64_t n = c->rec.held;      /* not yet advanced at the hook */
    for (size_t k = 0; k < c->n_out; k++) {
        const cu_msg_t *m = &c->out[k];
        int cs = m->type == CU_MSG_COMMIT_SIG && m->n == n + 1;
        int raa = m->type == CU_MSG_REVOKE && m->n == n;
        if (((point == CU_CP_SENT_BEFORE || point == CU_CP_SENT_AFTER) && cs)
            || ((point == CU_CP_RESP_HOLDS_BEFORE || point == CU_CP_RESP_HOLDS_AFTER) && (cs || raa))
            || ((point == CU_CP_PROP_HOLDS_BEFORE || point == CU_CP_PROP_HOLDS_AFTER) && raa))
            s->net->early_release++;
    }
}

static int crash_hook(void *ctx, int point) {
    side_t *s = ctx;
    net_t *n = s->net;
    check_not_released(s, point);
    if (!n->crash_fired && n->crash_side == s->idx && n->crash_point == point) {
        n->crash_fired = 1;
        return n->crash_ret;
    }
    return 0;
}

static void collect(net_t *n, int i) {
    side_t *s = &n->s[i];
    int to = 1 - i;
    for (size_t k = 0; k < s->c->n_out; k++) {
        if (n->drop_type[to] && s->c->out[k].type == n->drop_type[to]) {
            n->drop_type[to] = 0;
            continue;
        }
        if (n->n_pipe[to] < PIPE_CAP) n->pipe[to][n->n_pipe[to]++] = s->c->out[k];
    }
    for (size_t k = 0; k < s->c->n_ev && s->n_evlog < 512; k++) s->evlog[s->n_evlog++] = s->c->ev[k];
    cu_clear_outputs(s->c);
}

static int open_side(side_t *s) {
    mode_t old = umask(077);
    int opened = persist_open(&s->db, s->path);
    umask(old);
    if (!opened) return 0;
    /* The crashes here are in-process; OS-level sync only costs time. */
    sqlite3_exec(s->db.db, "PRAGMA synchronous=OFF;", NULL, NULL, NULL);
    if (sqlite3_exec(s->db.db,
            "CREATE TABLE IF NOT EXISTS test_watch (commit_num INTEGER, txid BLOB, secret BLOB,"
            " PRIMARY KEY (commit_num, txid));"
            "CREATE TABLE IF NOT EXISTS test_claim (offerer INTEGER, htlc_id INTEGER, preimage BLOB,"
            " PRIMARY KEY (offerer, htlc_id));", NULL, NULL, NULL) != SQLITE_OK)
        return 0;
    return 1;
}

static int load_side(side_t *s) {
    if (!s->c) s->c = calloc(1, sizeof(cu_chan_t));
    if (!s->c) return 0;
    if (cu_load(s->c, &s->db, &s->cfg, &FAKE_OPS, &s->f, g_secp) != CU_OK) return 0;
    s->c->crash_hook = crash_hook;
    s->c->crash_ctx = s;
    cu_on_block(s->c, TIP);
    cu_clear_outputs(s->c);
    return 1;
}

static void cfg_init(cu_config_t *cfg, cu_side_t side) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->side = side;
    cfg->channel_id = 7;
    memset(cfg->funding_txid, 0xab, 32);
    cfg->funding_vout = 1;
    cfg->capacity_msat = CAPACITY_MSAT;
    cfg->host_reserve_msat = 1000000;
    cfg->max_htlcs = 30;
    cfg->fee_min_per_kvb = 253;
    cfg->fee_max_per_kvb = 50000;
    cfg->cltv_deadline = 10000;
    cfg->min_cltv_headroom = 40;
    cfg->onchain_margin = 10;
}

static void initial_state(cu_state_t *st) {
    memset(st, 0, sizeof(*st));
    st->feerate_per_kvb = 1000;
    st->fee_msat = f_fee(NULL, st);
    st->member_msat = 400000000;
    st->host_msat = CAPACITY_MSAT - st->member_msat - st->fee_msat;
}

static void rand32(unsigned char out[32], unsigned seed) {
    unsigned char b[8] = { 'c', 'u', 's', 0, (unsigned char)(seed >> 24), (unsigned char)(seed >> 16),
                           (unsigned char)(seed >> 8), (unsigned char)seed };
    sha256(b, 8, out);
}

static int net_init(net_t *n) {
    memset(n, 0, sizeof(*n));
    n->crash_side = -1;
    unsigned char s0[2][32], s1[2][32];
    secp256k1_pubkey p0[2], p1[2];
    int seq = g_dbseq++;
    for (int i = 0; i < 2; i++) {
        side_t *s = &n->s[i];
        s->net = n;
        s->idx = i;
        snprintf(s->path, sizeof(s->path), "/tmp/test_cu_%d_%d_%d.db", (int)getpid(), seq, i);
        unlink(s->path);
        if (!fresh_db(s->path)) return 0;
        cfg_init(&s->cfg, (cu_side_t)i);
        s->f.side = i;
        rand32(s->f.key[0], 1000);
        rand32(s->f.key[1], 1001);
        rand32(s0[i], (unsigned)(seq * 10 + i * 2));
        rand32(s1[i], (unsigned)(seq * 10 + i * 2 + 1));
        if (!secp256k1_ec_pubkey_create(g_secp, &p0[i], s0[i])) return 0;
        if (!secp256k1_ec_pubkey_create(g_secp, &p1[i], s1[i])) return 0;
        if (!open_side(s)) return 0;
    }
    cu_state_t *st = malloc(sizeof(*st));
    if (!st) return 0;
    initial_state(st);
    for (int i = 0; i < 2; i++) {
        unsigned char tx[256], ptx[256], txid[32], ptxid[32], sig[64];
        size_t len = sizeof(tx), plen = sizeof(ptx);
        f_build(NULL, (cu_side_t)i, 0, st, &p0[i], tx, &len, txid);
        f_build(NULL, (cu_side_t)(1 - i), 0, st, &p0[1 - i], ptx, &plen, ptxid);
        memset(sig, 0x11, 64);
        if (cu_create(&n->s[i].db, &n->s[i].cfg, st, s0[i], s1[i], &p0[1 - i], &p1[1 - i],
                      tx, len, sig, ptxid) != CU_OK) { free(st); return 0; }
        if (!load_side(&n->s[i])) { free(st); return 0; }
    }
    free(st);
    return 1;
}

static void unlink_aux(const char *path) {
    char p[300];
    snprintf(p, sizeof(p), "%s-wal", path); unlink(p);
    snprintf(p, sizeof(p), "%s-shm", path); unlink(p);
    snprintf(p, sizeof(p), "%s-journal", path); unlink(p);
}

static void net_free(net_t *n) {
    for (int i = 0; i < 2; i++) {
        free(n->s[i].c);
        n->s[i].c = NULL;
        persist_close(&n->s[i].db);
        unlink(n->s[i].path);
        unlink_aux(n->s[i].path);
    }
}

/* Crash: the engine and its connection are gone; restart from the file. */
static int restart(net_t *n, int i) {
    side_t *s = &n->s[i];
    persist_rollback(&s->db);
    persist_close(&s->db);
    free(s->c);
    s->c = NULL;
    f_reset(&s->f);
    if (!open_side(s)) return 0;
    return load_side(s);
}

static void disconnect(net_t *n) {
    n->n_pipe[0] = n->n_pipe[1] = 0;
    for (int i = 0; i < 2; i++) {
        cu_on_disconnect(n->s[i].c);
        cu_clear_outputs(n->s[i].c);
    }
}

#define RUN_CRASHED 1000

/* Deliver until both pipes are empty.  Returns CU_OK, RUN_CRASHED with
   *who set, or the first other error. */
static int deliver_one(net_t *n, int to, int *who) {
    cu_msg_t m = n->pipe[to][0];
    memmove(&n->pipe[to][0], &n->pipe[to][1], (n->n_pipe[to] - 1) * sizeof(cu_msg_t));
    n->n_pipe[to]--;
    n->delivered++;
    int rc = cu_on_message(n->s[to].c, &m);
    if (rc == CU_ERR_CRASHED) { if (who) *who = to; return RUN_CRASHED; }
    collect(n, to);
    if (rc != CU_OK && who) *who = to;
    return rc;
}

static int run(net_t *n, int max_msgs, int *who) {
    int turn = 0;
    while (n->n_pipe[0] || n->n_pipe[1]) {
        if (max_msgs >= 0 && (int)n->delivered >= max_msgs) return CU_OK;
        int to = n->n_pipe[turn] ? turn : 1 - turn;
        turn = 1 - turn;
        int rc = deliver_one(n, to, who);
        if (rc != CU_OK) return rc;
    }
    return CU_OK;
}

static int reconnect(net_t *n) {
    disconnect(n);
    for (int i = 0; i < 2; i++) {
        cu_msg_t m;
        if (cu_reestablish_msg(n->s[i].c, &m) != CU_OK) return CU_ERR_DB;
        n->pipe[1 - i][n->n_pipe[1 - i]++] = m;
    }
    return run(n, -1, NULL);
}

static void mk_add(cu_update_t *u, uint64_t id, uint64_t amount_msat, unsigned seed) {
    unsigned char pre[32];
    memset(u, 0, sizeof(*u));
    u->kind = CU_UPD_ADD;
    u->id = id;
    u->amount_msat = amount_msat;
    rand32(pre, seed);
    sha256(pre, 32, u->payment_hash);
    u->cltv_expiry = TIP + 100;
}

static void mk_fulfil(cu_update_t *u, uint64_t id, unsigned seed) {
    memset(u, 0, sizeof(*u));
    u->kind = CU_UPD_FULFILL;
    u->id = id;
    rand32(u->preimage, seed);
}

static void mk_fail(cu_update_t *u, uint64_t id) {
    memset(u, 0, sizeof(*u));
    u->kind = CU_UPD_FAIL;
    u->id = id;
    u->reason = 0x2002;
}

static int g_who = -1;   /* side a propose() call stopped on */

/* The host opens the round with every pending member request. */
static int host_carries_requests(net_t *n) {
    size_t nr = 0;
    const cu_update_t *r = cu_requests(n->s[CU_HOST].c, &nr);
    if (nr == 0) return CU_ERR_ARG;
    cu_update_t copy[CU_MAX_UPDATES];
    memcpy(copy, r, nr * sizeof(cu_update_t));
    int rc = cu_propose(n->s[CU_HOST].c, copy, nr);
    g_who = CU_HOST;
    if (rc == CU_ERR_CRASHED) return rc;
    collect(n, CU_HOST);
    return rc;
}

/* Host: open a round with u.  Member: offer u, deliver the offers, and let
   the host carry them. */
static int propose(net_t *n, int i, const cu_update_t *u, size_t k) {
    g_who = i;
    if (i == CU_HOST) {
        int rc = cu_propose(n->s[CU_HOST].c, u, k);
        if (rc == CU_ERR_CRASHED) return rc;
        collect(n, CU_HOST);
        return rc;
    }
    int rc = cu_offer(n->s[CU_MEMBER].c, u, k);
    if (rc == CU_ERR_CRASHED) return rc;
    collect(n, CU_MEMBER);
    if (rc != CU_OK) return rc;
    while (n->n_pipe[CU_HOST]) {
        rc = deliver_one(n, CU_HOST, &g_who);
        if (rc != CU_OK) return rc == RUN_CRASHED ? CU_ERR_CRASHED : rc;
    }
    return host_carries_requests(n);
}

static int same_state(const cu_state_t *a, const cu_state_t *b) {
    unsigned char ha[32], hb[32];
    state_hash(a, ha);
    state_hash(b, hb);
    return memcmp(ha, hb, 32) == 0;
}

static int watch_count(side_t *s, int64_t n) {
    sqlite3_stmt *st;
    int c = -1;
    if (sqlite3_prepare_v2(s->db.db, "SELECT COUNT(*) FROM test_watch WHERE commit_num=?;", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, n);
    if (sqlite3_step(st) == SQLITE_ROW) c = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return c;
}

/* Both sides at rest on the same number and state; every durable check
   holds; every revoked number is watched on both sides. */
static int at_rest(net_t *n, uint64_t want_held, char *why, size_t wl) {
    for (int i = 0; i < 2; i++) {
        cu_chan_t *c = n->s[i].c;
        if (c->rec.phase != CU_PHASE_IDLE) { snprintf(why, wl, "side %d phase %d", i, c->rec.phase); return 0; }
        if (c->rec.held != want_held) { snprintf(why, wl, "side %d held %llu want %llu", i,
                                                 (unsigned long long)c->rec.held, (unsigned long long)want_held); return 0; }
        if (c->rec.revoked != (int64_t)want_held - 1 || c->rec.peer_revoked != (int64_t)want_held - 1) {
            snprintf(why, wl, "side %d revoked %lld peer_revoked %lld", i,
                     (long long)c->rec.revoked, (long long)c->rec.peer_revoked);
            return 0;
        }
        if (!cu_check_invariants(&n->s[i].db, c->cfg.channel_id, CAPACITY_MSAT, why, wl)) return 0;
        if (c->n_offered) { snprintf(why, wl, "side %d holds %zu offers", i, c->n_offered); return 0; }
        for (uint64_t k = 0; k < want_held; k++)
            if (watch_count(&n->s[i], (int64_t)k) < 1) { snprintf(why, wl, "side %d: no watch for %llu", i, (unsigned long long)k); return 0; }
    }
    if (!same_state(&n->s[0].c->st, &n->s[1].c->st)) { snprintf(why, wl, "states differ"); return 0; }
    return 1;
}

static int has_event(side_t *s, uint8_t type) {
    for (size_t i = 0; i < s->n_evlog; i++) if (s->evlog[i].type == type) return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

static void init_secp(void) {
    if (!g_secp) g_secp = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
}

int test_cu_schema_v46(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");
    TEST_ASSERT_EQ(persist_schema_version(&db), PERSIST_SCHEMA_VERSION, "schema version");
    const char *tables[] = { "chan_update_channel", "chan_update_commitment", "chan_update_signed",
                             "chan_update_signed_void", "chan_update_secret", "chan_update_peer_point",
                             "chan_update_peer_secret", "chan_update_offer", "chan_update_claim" };
    for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
        sqlite3_stmt *st;
        TEST_ASSERT(sqlite3_prepare_v2(db.db, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?;",
                                       -1, &st, NULL) == SQLITE_OK, "prepare");
        sqlite3_bind_text(st, 1, tables[i], -1, SQLITE_STATIC);
        TEST_ASSERT(sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int(st, 0) == 1, tables[i]);
        sqlite3_finalize(st);
    }
    persist_close(&db);
    return 1;
}

int test_cu_apply_rules(void) {
    init_secp();
    cu_config_t cfg;
    cfg_init(&cfg, CU_HOST);
    cu_state_t *in = malloc(sizeof(*in)), *out = malloc(sizeof(*out));
    TEST_ASSERT(in && out, "alloc");
    initial_state(in);
    cu_update_t u;
    int ok = 1;
#define EXPECT(proposer, rc_want, msg) do { \
        int _rc = cu_apply(&cfg, &FAKE_OPS, NULL, TIP, proposer, in, &u, 1, out); \
        if (_rc != (rc_want)) { printf("  FAIL: %s: %s (rc %d)\n", __func__, msg, _rc); ok = 0; goto done; } \
    } while (0)

    mk_add(&u, 0, 1000000, 1); u.sender = CU_HOST;
    EXPECT(CU_HOST, CU_OK, "host add");
    TEST_ASSERT(out->n_htlcs == 1 && out->htlcs[0].offerer == CU_HOST, "htlc offered by host");
    u.sender = CU_MEMBER;
    mk_add(&u, 0, 1000000, 1); u.sender = CU_MEMBER;
    EXPECT(CU_HOST, CU_OK, "a host round carries a member request");
    TEST_ASSERT(out->htlcs[0].offerer == CU_MEMBER && out->member_msat == in->member_msat - 1000000,
                "the member's add debits the member (INV-28)");
    u.sender = CU_HOST;
    EXPECT(CU_MEMBER, CU_ERR_INVALID, "a member offer cannot act for the host");
    mk_add(&u, 1, 1000000, 1); u.sender = CU_HOST;
    EXPECT(CU_HOST, CU_ERR_INVALID, "id not the next one");
    mk_add(&u, 0, 500000000, 1); u.sender = CU_MEMBER;
    EXPECT(CU_MEMBER, CU_ERR_INVALID, "member pays more than it has");
    mk_add(&u, 0, 1000000, 1); u.sender = CU_HOST; u.cltv_expiry = cfg.cltv_deadline;
    EXPECT(CU_HOST, CU_ERR_INVALID, "expiry not before T0 - R");
    u.cltv_expiry = TIP + cfg.min_cltv_headroom - 1;
    EXPECT(CU_HOST, CU_ERR_INVALID, "headroom below the minimum");
    u.cltv_expiry = TIP + 100;
    if (cu_apply(&cfg, &FAKE_OPS, NULL, 0, CU_HOST, in, &u, 1, out) != CU_ERR_INVALID) {
        printf("  FAIL: %s: add accepted with an unknown tip\n", __func__); ok = 0; goto done;
    }
    memset(u.payment_hash, 0, 32);
    EXPECT(CU_HOST, CU_ERR_INVALID, "zero payment hash");
    mk_add(&u, 0, in->host_msat - 1000, 1); u.sender = CU_HOST;
    EXPECT(CU_HOST, CU_ERR_INVALID, "host below its reserve (INV-34)");

    /* An HTLC from the host to the member, then its removals. */
    mk_add(&u, 0, 1000000, 77); u.sender = CU_HOST;
    EXPECT(CU_HOST, CU_OK, "add");
    *in = *out;
    mk_fulfil(&u, 0, 77); u.sender = CU_HOST;
    EXPECT(CU_HOST, CU_ERR_INVALID, "the offerer cannot fulfil its own HTLC");
    mk_fulfil(&u, 0, 78); u.sender = CU_MEMBER;
    EXPECT(CU_MEMBER, CU_ERR_INVALID, "wrong preimage");
    mk_fail(&u, 0); u.sender = CU_HOST;
    EXPECT(CU_HOST, CU_ERR_INVALID, "the offerer cannot fail its own HTLC");
    uint64_t member_before = in->member_msat;
    mk_fulfil(&u, 0, 77); u.sender = CU_MEMBER;
    EXPECT(CU_MEMBER, CU_OK, "member fulfils");
    TEST_ASSERT(out->member_msat == member_before + 1000000 && out->n_htlcs == 0, "member credited");
    mk_fail(&u, 0); u.sender = CU_MEMBER;
    EXPECT(CU_MEMBER, CU_OK, "member fails");
    TEST_ASSERT(out->member_msat == member_before && out->n_htlcs == 0, "host refunded");

    memset(&u, 0, sizeof(u)); u.kind = CU_UPD_FEE; u.feerate_per_kvb = 2000; u.sender = CU_MEMBER;
    EXPECT(CU_MEMBER, CU_ERR_INVALID, "member cannot set the fee");
    u.sender = CU_HOST; u.feerate_per_kvb = cfg.fee_max_per_kvb + 1;
    EXPECT(CU_HOST, CU_ERR_INVALID, "fee above the proposal's bound");
    u.feerate_per_kvb = 2000;
    EXPECT(CU_HOST, CU_OK, "fee update");
    TEST_ASSERT(out->feerate_per_kvb == 2000 && out->fee_msat == f_fee(NULL, out), "fee recomputed");

    const uint8_t later[] = { CU_UPD_REANCHOR, CU_UPD_TREE_MOVE, CU_UPD_REALLOC, CU_UPD_SPLICE, CU_UPD_JIT_OPEN };
    for (size_t i = 0; i < sizeof(later); i++) {
        memset(&u, 0, sizeof(u)); u.kind = later[i]; u.sender = CU_HOST;
        EXPECT(CU_HOST, CU_ERR_KIND, "later-release kind refused");
    }
    /* HTLC cap (INV-33). */
    {
        cu_update_t many[CU_MAX_UPDATES];
        cfg.max_htlcs = (uint32_t)in->n_htlcs + 3;
        for (int i = 0; i < 4; i++) {
            mk_add(&many[i], in->next_htlc_id[CU_HOST] + (uint64_t)i, 1000000, 200 + (unsigned)i);
            many[i].sender = CU_HOST;
        }
        TEST_ASSERT(cu_apply(&cfg, &FAKE_OPS, NULL, TIP, CU_HOST, in, many, 3, out) == CU_OK, "3 fit");
        TEST_ASSERT(cu_apply(&cfg, &FAKE_OPS, NULL, TIP, CU_HOST, in, many, 4, out) == CU_ERR_INVALID, "4th refused");
    }
#undef EXPECT
done:
    free(in); free(out);
    return ok;
}

int test_cu_round_add_fulfil(void) {
    init_secp();
    net_t *n = malloc(sizeof(*n));
    char why[256] = "";
    TEST_ASSERT(n && net_init(n), "init");
    cu_update_t u;
    uint64_t member0 = n->s[1].c->st.member_msat;

    mk_add(&u, 0, 5000000, 42);
    TEST_ASSERT_EQ(propose(n, CU_HOST, &u, 1), CU_OK, "host proposes add");
    TEST_ASSERT_EQ(n->s[0].c->rec.phase, CU_PHASE_SENT, "host SENT");
    TEST_ASSERT_EQ(propose(n, CU_HOST, &u, 1), CU_ERR_BUSY, "one round at a time");
    TEST_ASSERT_EQ(run(n, -1, NULL), CU_OK, "round");
    TEST_ASSERT(at_rest(n, 1, why, sizeof(why)), why);
    TEST_ASSERT(has_event(&n->s[1], CU_EV_HTLC_ADDED), "member saw the add");

    mk_fulfil(&u, 0, 42);
    TEST_ASSERT_EQ(propose(n, CU_MEMBER, &u, 1), CU_OK, "member fulfils");
    /* INV-30: the claim was armed in the SENT write. */
    {
        sqlite3_stmt *st;
        sqlite3_prepare_v2(n->s[1].db.db, "SELECT COUNT(*) FROM test_claim;", -1, &st, NULL);
        TEST_ASSERT(sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int(st, 0) == 1, "claim armed before release");
        sqlite3_finalize(st);
    }
    TEST_ASSERT_EQ(run(n, -1, NULL), CU_OK, "round");
    TEST_ASSERT(at_rest(n, 2, why, sizeof(why)), why);
    TEST_ASSERT_EQ(n->s[1].c->st.member_msat, member0 + 5000000, "member paid");
    TEST_ASSERT(has_event(&n->s[0], CU_EV_HTLC_FULFILLED), "host learned the preimage");

    /* INV-23: the latest commitment is unrevoked. */
    unsigned char tx[256], sig[64];
    size_t len = sizeof(tx);
    uint64_t num = 99;
    TEST_ASSERT_EQ(cu_latest_commitment(n->s[1].c, tx, &len, sig, &num), CU_OK, "latest");
    TEST_ASSERT_EQ(num, 2, "latest number");
    net_free(n); free(n);
    return 1;
}

int test_cu_round_fail_and_fee(void) {
    init_secp();
    net_t *n = malloc(sizeof(*n));
    char why[256] = "";
    TEST_ASSERT(n && net_init(n), "init");
    cu_update_t u[2];
    uint64_t member0 = n->s[1].c->st.member_msat;
    mk_add(&u[0], 0, 3000000, 5);
    mk_add(&u[1], 1, 2000000, 6);
    TEST_ASSERT_EQ(propose(n, CU_MEMBER, u, 2), CU_OK, "member adds two");
    TEST_ASSERT_EQ(run(n, -1, NULL), CU_OK, "round 1");
    TEST_ASSERT(at_rest(n, 1, why, sizeof(why)), why);

    mk_fail(&u[0], 0);
    memset(&u[1], 0, sizeof(u[1]));
    u[1].kind = CU_UPD_FEE;
    u[1].feerate_per_kvb = 1500;
    TEST_ASSERT_EQ(propose(n, CU_HOST, u, 2), CU_OK, "host fails one and sets the fee");
    TEST_ASSERT_EQ(run(n, -1, NULL), CU_OK, "round 2");
    TEST_ASSERT(at_rest(n, 2, why, sizeof(why)), why);
    TEST_ASSERT_EQ(n->s[1].c->st.member_msat, member0 - 2000000, "member refunded the failed HTLC");
    TEST_ASSERT_EQ(n->s[1].c->st.feerate_per_kvb, 1500, "fee rate");
    /* INV-29: the member learns the removal at DONE. */
    TEST_ASSERT(has_event(&n->s[1], CU_EV_HTLC_FAILED), "fail event at DONE");

    memset(&u[0], 0, sizeof(u[0]));
    u[0].kind = CU_UPD_FEE;
    u[0].feerate_per_kvb = 1200;
    TEST_ASSERT_EQ(propose(n, CU_MEMBER, u, 1), CU_ERR_INVALID, "member may not send update_fee");
    TEST_ASSERT_EQ(n->s[1].c->rec.phase, CU_PHASE_IDLE, "refusal changes nothing");
    net_free(n); free(n);
    return 1;
}

/* A verification failure aborts the round, sends error, stores nothing;
   reconnect then completes it. */
int test_cu_verify_failures(void) {
    init_secp();
    char why[256] = "";
    for (int variant = 0; variant < 3; variant++) {
        net_t *n = malloc(sizeof(*n));
        TEST_ASSERT(n && net_init(n), "init");
        cu_update_t u;
        mk_add(&u, 0, 1000000, 9);
        TEST_ASSERT_EQ(propose(n, CU_HOST, &u, 1), CU_OK, "propose");
        /* pipe[1]: add, commitment_signed */
        if (variant == 0) n->pipe[1][1].digest[0] ^= 1;          /* digest */
        if (variant == 1) n->pipe[1][1].psig[0] ^= 1;            /* host signature */
        int rc = run(n, variant == 2 ? 2 : -1, NULL);
        if (variant == 2) {
            /* member answered; corrupt its revocation secret */
            TEST_ASSERT_EQ(rc, CU_OK, "partial");
            TEST_ASSERT_EQ(n->n_pipe[0], 2, "member sent cs + raa");
            n->pipe[0][1].secret[5] ^= 1;
            rc = run(n, -1, NULL);
            TEST_ASSERT_EQ(rc, CU_ERR_VERIFY, "bad secret refused (INV-25)");
            TEST_ASSERT_EQ(n->s[0].c->rec.phase, CU_PHASE_SENT, "host still SENT");
            TEST_ASSERT_EQ(watch_count(&n->s[0], 0), 0, "nothing armed");
        } else {
            TEST_ASSERT_EQ(rc, CU_ERR_VERIFY, "verification failure");
            TEST_ASSERT_EQ(n->s[1].c->rec.held, 0, "member stored nothing");
        }
        TEST_ASSERT_EQ(reconnect(n), CU_OK, "reconnect");
        TEST_ASSERT(at_rest(n, 1, why, sizeof(why)), why);
        net_free(n); free(n);
    }
    return 1;
}

/* ---- reconciliation table ---- */

typedef struct { const char *name; int row; unsigned acts; } cell_t;

static void view_at(cu_view_t *v, cu_side_t side, int phase, int role, uint64_t n,
                    const unsigned char sec[8][32], const unsigned char digest[32]) {
    memset(v, 0, sizeof(*v));
    v->side = side;
    v->phase = (uint8_t)phase;
    v->round_role = (uint8_t)role;
    if (phase == CU_PHASE_HOLDS) {
        v->held = n + 1; v->revoked = (int64_t)n; v->signed_max = n + 1;
        v->peer_revoked = role == CU_PROPOSER ? (int64_t)n : (int64_t)n - 1;
    } else {
        v->held = n; v->revoked = (int64_t)n - 1; v->peer_revoked = (int64_t)n - 1;
        v->signed_max = phase == CU_PHASE_SENT ? n + 1 : n;
    }
    if (phase != CU_PHASE_IDLE) memcpy(v->digest, digest, 32);
    for (int64_t k = v->revoked - 3; k <= v->revoked + 4; k++) {
        if (k < 0 || k >= 8) continue;
        v->secret_num[v->n_secrets] = k;
        memcpy(v->secret[v->n_secrets++], sec[k], 32);
    }
}

static void claim(cu_reestablish_t *re, uint64_t H, int64_t V, const unsigned char *last_secret,
                  const unsigned char *digest) {
    memset(re, 0, sizeof(*re));
    re->next_commitment_number = H + 1;
    re->next_revocation_number = (uint64_t)(V + 1);
    if (last_secret) memcpy(re->last_remote_secret, last_secret, 32);
    if (digest) memcpy(re->sent_digest, digest, 32);
}

int test_cu_reconcile_table(void) {
    unsigned char sec[8][32], dmine[32], dpeer[32], junk[32];
    for (int i = 0; i < 8; i++) rand32(sec[i], 500 + (unsigned)i);
    memset(dmine, 0x5a, 32);
    memset(dpeer, 0xa5, 32);
    memset(junk, 0x77, 32);
    const uint64_t n = 4;            /* both at rest at n: (4, 3) */
    /* My states: idle, proposer SENT(n+1), responder HOLDS(n+1), proposer HOLDS(n+1).
       Peer claims, each built from what an honest peer in that state sends,
       plus the anomalies of rows 8 to 11. */
    enum { M_IDLE, M_SENT, M_RHOLDS, M_PHOLDS, M_COUNT };
    enum { P_IDLE, P_IDLE_LACKS, P_SENT_MINE, P_SENT_OTHER, P_RHOLDS, P_PHOLDS, P_PHOLDS_LACKS,
           P_AHEAD2, P_SECRET_NEWER, P_LOST, P_FAR, P_JUNK, P_COUNT };
    static const char *mname[M_COUNT] = { "idle", "sent", "resp-holds", "prop-holds" };
    static const char *pname[P_COUNT] = { "idle", "idle-lacks-my-raa", "sent-same-digest", "sent-other-digest",
        "resp-holds", "prop-holds", "prop-holds-lacks", "ahead-2", "secret-newer", "lost-data", "far-behind", "junk-secret" };
    /* Expected (row, actions) for the host; the member differs only in row 12. */
    const int W = CU_ACT_WAIT, RR = CU_ACT_RESEND_ROUND, RA = CU_ACT_RESEND_RAA, RC = CU_ACT_RESEND_CS,
              MD = CU_ACT_MARK_DONE, F = CU_ACT_FAIL, DL = CU_ACT_DATA_LOSS, PL = CU_ACT_PEER_LOST;
    struct { int row; unsigned acts; } want[M_COUNT][P_COUNT] = {
        /* idle at (n, n-1) */
        { {1, 0}, {5, RA}, {1, W}, {1, W}, {8, F}, {9, DL}, {8, F}, {8, F}, {9, DL}, {10, PL}, {10, PL}, {0, F} },
        /* proposer SENT(n+1) at (n, n-1) */
        { {2, RR}, {2, RA | RR}, {2, RR}, {12, RR}, {3, W}, {9, DL}, {3, W}, {8, F}, {9, DL}, {10, PL}, {10, PL}, {0, F} },
        /* responder HOLDS(n+1) at (n+1, n) */
        { {10, PL}, {10, PL}, {4, RC | RA}, {0, F}, {6, W}, {6, W}, {6, W}, {8, F}, {9, DL}, {10, PL}, {10, PL}, {0, F} },
        /* proposer HOLDS(n+1) at (n+1, n) */
        { {10, PL}, {10, PL}, {10, PL}, {10, PL}, {5, RA | MD}, {7, MD}, {5, RA | MD}, {8, F}, {9, DL}, {10, PL}, {10, PL}, {0, F} },
    };
    int cells = 0;
    for (int side = 0; side < 2; side++) {
        for (int m = 0; m < M_COUNT; m++) {
            cu_view_t v;
            int phase = m == M_IDLE ? CU_PHASE_IDLE : m == M_SENT ? CU_PHASE_SENT : CU_PHASE_HOLDS;
            int role = m == M_RHOLDS ? CU_RESPONDER : CU_PROPOSER;
            view_at(&v, (cu_side_t)side, phase, role, n, sec, dmine);
            for (int p = 0; p < P_COUNT; p++) {
                cu_reestablish_t re;
                /* The secret the peer holds of mine: honest = my newest revoked. */
                const unsigned char *mine_newest = v.revoked >= 0 ? sec[v.revoked] : NULL;
                const unsigned char *mine_prev = v.revoked >= 1 ? sec[v.revoked - 1] : NULL;
                int64_t H = (int64_t)v.held;
                switch (p) {
                /* Peer states are described relative to the round from n to n+1. */
                case P_IDLE:         claim(&re, n, (int64_t)n - 1, m == M_IDLE || m == M_SENT ? mine_newest : sec[n - 1], NULL); break;
                case P_IDLE_LACKS:   claim(&re, n, (int64_t)n - 1, m == M_IDLE || m == M_SENT ? mine_prev : sec[n - 2], NULL); break;
                case P_SENT_MINE:    claim(&re, n, (int64_t)n - 1, m == M_IDLE || m == M_SENT ? mine_newest : sec[n - 1], dmine); break;
                case P_SENT_OTHER:   claim(&re, n, (int64_t)n - 1, m == M_IDLE || m == M_SENT ? mine_newest : sec[n - 1], dpeer); break;
                case P_RHOLDS:       claim(&re, n + 1, (int64_t)n, m == M_IDLE || m == M_SENT ? mine_newest : sec[n - 1], NULL); break;
                case P_PHOLDS:       claim(&re, n + 1, (int64_t)n, sec[n], NULL); break;
                case P_PHOLDS_LACKS: claim(&re, n + 1, (int64_t)n, sec[n - 1], NULL); break;
                case P_AHEAD2:       claim(&re, (uint64_t)H + 2, H + 1, mine_newest, NULL); break;
                case P_SECRET_NEWER: claim(&re, (uint64_t)H, H - 1, sec[v.revoked + 1], NULL); break;
                case P_LOST:         claim(&re, n - 2, (int64_t)n - 3, sec[n - 3], NULL); break;
                case P_FAR:          claim(&re, n - 3, (int64_t)n - 4, sec[n - 4], NULL); break;
                case P_JUNK:         claim(&re, (uint64_t)H, H - 1, junk, NULL); break;
                }
                cu_reconcile_t r = cu_reconcile(&v, &re);
                int row = want[m][p].row;
                unsigned acts = want[m][p].acts;
                if (side == CU_MEMBER && m == M_SENT && p == P_SENT_OTHER) acts = CU_ACT_DROP_SENT | CU_ACT_WAIT;
                /* Claims that are honest only for the other states are judged by the table too. */
                if (r.row != row || r.actions != acts) {
                    printf("  FAIL: %s: %s mine=%s peer=%s: row %d acts 0x%x, want row %d acts 0x%x\n",
                           __func__, side ? "member" : "host", mname[m], pname[p], r.row, r.actions, row, acts);
                    return 0;
                }
                cells++;
            }
        }
    }
    TEST_ASSERT_EQ(cells, 2 * M_COUNT * P_COUNT, "every cell checked");
    /* Commitment 0: nothing revoked yet, zeros as the last secret. */
    {
        cu_view_t v;
        cu_reestablish_t re;
        view_at(&v, CU_HOST, CU_PHASE_IDLE, CU_PROPOSER, 0, sec, dmine);
        claim(&re, 0, -1, NULL, NULL);
        cu_reconcile_t r = cu_reconcile(&v, &re);
        TEST_ASSERT(r.row == 1 && r.actions == 0, "fresh channel in step");
        claim(&re, 0, 0, NULL, NULL);
        r = cu_reconcile(&v, &re);
        TEST_ASSERT(r.actions == CU_ACT_FAIL, "revoked number above held is invalid");
        claim(&re, 0, -1, NULL, NULL);
        re.next_commitment_number = 0;
        r = cu_reconcile(&v, &re);
        TEST_ASSERT(r.actions == CU_ACT_FAIL, "zero next_commitment_number is invalid");
    }
    return 1;
}

/* ---- crash at every persist point ---- */

static int expected_after_round(net_t *n, int proposer, uint64_t held) {
    /* The round is either in effect on both sides or on neither. */
    return n->s[proposer].c->rec.held == held + 1;
}

static int crash_case(int proposer, int crash_side, int point, int ret) {
    char why[256] = "";
    net_t *n = malloc(sizeof(*n));
    TEST_ASSERT(n && net_init(n), "init");
    cu_update_t u;
    /* a settled HTLC first, so the crash round is a fulfil on a live channel */
    mk_add(&u, 0, 7000000, 300);
    TEST_ASSERT_EQ(propose(n, proposer == CU_HOST ? CU_MEMBER : CU_HOST, &u, 1), CU_OK, "setup add");
    TEST_ASSERT_EQ(run(n, -1, NULL), CU_OK, "setup round");
    TEST_ASSERT(at_rest(n, 1, why, sizeof(why)), why);

    mk_fulfil(&u, 0, 300);
    n->crash_side = crash_side;
    n->crash_point = point;
    n->crash_ret = ret;
    int who = -1;
    int rc = propose(n, proposer, &u, 1);
    if (rc == CU_ERR_CRASHED || rc == CU_ERR_DB) who = g_who;
    else {
        TEST_ASSERT_EQ(rc, CU_OK, "propose");
        rc = run(n, -1, &who);
    }
    if (rc == RUN_CRASHED || rc == CU_ERR_CRASHED) {
        TEST_ASSERT(restart(n, who), "restart");
    } else if (rc == CU_ERR_DB) {
        /* A failed write released nothing. */
        TEST_ASSERT_EQ(n->s[who].c->n_out, 0, "nothing sent after a failed write");
    } else {
        TEST_ASSERT_EQ(rc, CU_OK, "run");
    }
    rc = reconnect(n);
    if (rc != CU_OK) { printf("  FAIL: reconnect rc %d (proposer %d crash side %d point %d ret %d)\n", rc, proposer, crash_side, point, ret); return 0; }
    if (!expected_after_round(n, CU_HOST, 1)) {
        TEST_ASSERT_EQ(n->s[CU_HOST].c->rec.phase, CU_PHASE_IDLE, "idle");
        if (n->s[CU_MEMBER].c->n_offered) {
            /* The member's offer is durable and was offered again. */
            TEST_ASSERT_EQ(host_carries_requests(n), CU_OK, "host carries the offer");
        } else {
            /* Nothing durable happened: propose again. */
            TEST_ASSERT_EQ(propose(n, proposer, &u, 1), CU_OK, "re-propose");
        }
        TEST_ASSERT_EQ(run(n, -1, NULL), CU_OK, "round");
    }
    if (!at_rest(n, 2, why, sizeof(why))) {
        printf("  FAIL: proposer %d crash side %d point %d ret %d: %s\n", proposer, crash_side, point, ret, why);
        return 0;
    }
    TEST_ASSERT_EQ(n->s[0].c->st.n_htlcs, 0, "HTLC settled exactly once");
    TEST_ASSERT_EQ(n->early_release, 0, "nothing released before its write committed (INV-22)");
    net_free(n); free(n);
    return 1;
}

int test_cu_crash_every_point(void) {
    init_secp();
    int cases = 0;
    for (int proposer = 0; proposer < 2; proposer++)
        for (int side = 0; side < 2; side++)
            for (int pt = 1; pt < CU_CP_COUNT; pt++)
                for (int ret = 1; ret <= 2; ret++) {
                    if (!crash_case(proposer, side, pt, ret)) return 0;
                    cases++;
                }
    TEST_ASSERT_EQ(cases, 2 * 2 * (CU_CP_COUNT - 1) * 2, "cases");
    return 1;
}

/* ---- disconnect / restart after every message ---- */

int test_cu_disconnect_every_send(void) {
    init_secp();
    char why[256] = "";
    for (int proposer = 0; proposer < 2; proposer++) {
        for (int k = 0; k <= 5; k++) {          /* a round is 5 messages: add, cs; cs, raa; raa */
            for (int rs = 0; rs < 4; rs++) {     /* restart: none, host, member, both */
                net_t *n = malloc(sizeof(*n));
                TEST_ASSERT(n && net_init(n), "init");
                cu_update_t u;
                mk_add(&u, 0, 2500000, 400 + (unsigned)k);
                TEST_ASSERT_EQ(propose(n, proposer, &u, 1), CU_OK, "propose");
                n->delivered = 0;
                TEST_ASSERT_EQ(run(n, k, NULL), CU_OK, "partial round");
                if (rs & 1) TEST_ASSERT(restart(n, 0), "restart host");
                if (rs & 2) TEST_ASSERT(restart(n, 1), "restart member");
                TEST_ASSERT_EQ(reconnect(n), CU_OK, "reconnect");
                if (!at_rest(n, 1, why, sizeof(why))) {
                    printf("  FAIL: proposer %d after %d messages restart %d: %s\n", proposer, k, rs, why);
                    return 0;
                }
                TEST_ASSERT_EQ(n->s[0].c->st.n_htlcs, 1, "added exactly once");
                net_free(n); free(n);
            }
        }
    }
    return 1;
}

/* ---- the lost revoke_and_ack ---- */

int test_cu_lost_raa_reconciles(void) {
    init_secp();
    char why[256] = "";
    for (int proposer = 0; proposer < 2; proposer++) {
        net_t *n = malloc(sizeof(*n));
        TEST_ASSERT(n && net_init(n), "init");
        cu_update_t u;
        mk_add(&u, 0, 1500000, 600);
        /* The host opens every round; its final revoke_and_ack never arrives.
           (proposer = who asked for the update.) */
        n->drop_type[CU_MEMBER] = CU_MSG_REVOKE;
        TEST_ASSERT_EQ(propose(n, proposer, &u, 1), CU_OK, "propose");
        int rc = run(n, -1, NULL);
        TEST_ASSERT_EQ(rc, CU_OK, "round");
        TEST_ASSERT_EQ(n->s[CU_HOST].c->rec.phase, CU_PHASE_IDLE, "host done");
        TEST_ASSERT_EQ(n->s[CU_MEMBER].c->rec.phase, CU_PHASE_HOLDS, "member waits");
        TEST_ASSERT_EQ(n->s[CU_MEMBER].c->rec.held, n->s[CU_HOST].c->rec.held, "same number");

        /* The next round opens meanwhile; the member queues it. */
        mk_add(&u, 1, 1000000, 601);
        TEST_ASSERT_EQ(propose(n, proposer, &u, 1), CU_OK, "next round");
        TEST_ASSERT_EQ(run(n, -1, NULL), CU_OK, "queued, not dropped");
        TEST_ASSERT(n->s[CU_MEMBER].c->n_deferred == 2, "update and signature queued");

        /* Restart the member too, for good measure, then reconnect. */
        TEST_ASSERT(restart(n, CU_MEMBER), "restart member");
        TEST_ASSERT_EQ(reconnect(n), CU_OK, "reconnect");
        if (!at_rest(n, 2, why, sizeof(why))) { printf("  FAIL: proposer %d: %s\n", proposer, why); return 0; }
        TEST_ASSERT_EQ(n->s[0].c->st.n_htlcs, 2, "both HTLCs, once each");
        net_free(n); free(n);
    }
    return 1;
}

/* ---- messages that arrive mid-round ---- */

int test_cu_mid_round_queued(void) {
    init_secp();
    char why[256] = "";
    net_t *n = malloc(sizeof(*n));
    TEST_ASSERT(n && net_init(n), "init");
    cu_update_t hu, mu;
    mk_add(&hu, 0, 4000000, 700);
    mk_add(&mu, 0, 3000000, 701);
    /* Host opens a round; before it reaches the member, the member offers an update. */
    TEST_ASSERT_EQ(propose(n, CU_HOST, &hu, 1), CU_OK, "host proposes");
    TEST_ASSERT_EQ(cu_offer(n->s[1].c, &mu, 1), CU_OK, "member offers");
    collect(n, 1);
    /* Deliver the member's offer to the host first: it arrives mid-round. */
    cu_msg_t m = n->pipe[0][0];
    n->n_pipe[0] = 0;
    TEST_ASSERT_EQ(cu_on_message(n->s[0].c, &m), CU_OK, "host takes it");
    TEST_ASSERT_EQ(n->s[0].c->n_deferred, 1, "queued");
    TEST_ASSERT_EQ(n->s[0].c->n_peer_updates, 0, "not in the open round");
    TEST_ASSERT_EQ(run(n, -1, NULL), CU_OK, "host round completes");
    TEST_ASSERT_EQ(n->s[0].c->n_deferred, 0, "queue drained after the round");
    TEST_ASSERT_EQ(n->s[0].c->n_peer_updates, 1, "member's update now pending");
    TEST_ASSERT(n->s[0].c->rec.phase == CU_PHASE_IDLE && n->s[1].c->rec.phase == CU_PHASE_IDLE
                && n->s[0].c->rec.held == 1 && n->s[1].c->rec.held == 1, "host round done");
    TEST_ASSERT_EQ(n->s[1].c->n_offered, 1, "the offer is still the member's");
    TEST_ASSERT_EQ(host_carries_requests(n), CU_OK, "host carries the member's request");
    TEST_ASSERT_EQ(run(n, -1, NULL), CU_OK, "round with the request");
    TEST_ASSERT(at_rest(n, 2, why, sizeof(why)), why);
    TEST_ASSERT_EQ(n->s[0].c->st.n_htlcs, 2, "both HTLCs");

    /* The per-peer queue: a burst queued while the caller was busy. */
    mk_add(&hu, 1, 1000000, 702);
    TEST_ASSERT_EQ(propose(n, CU_HOST, &hu, 1), CU_OK, "host proposes");
    cu_queue_t *q = calloc(1, sizeof(*q));
    TEST_ASSERT(q != NULL, "alloc");
    for (size_t i = 0; i < n->n_pipe[1]; i++) TEST_ASSERT(cu_queue_push(q, &n->pipe[1][i]), "push");
    n->n_pipe[1] = 0;
    cu_chan_t *chans[1] = { n->s[1].c };
    TEST_ASSERT_EQ(cu_queue_drain(q, chans, 1), CU_OK, "drain");
    collect(n, 1);
    TEST_ASSERT_EQ(run(n, -1, NULL), CU_OK, "rest of the round");
    TEST_ASSERT(at_rest(n, 3, why, sizeof(why)), why);
    /* A full queue is an error for the caller, never a silent drop. */
    cu_msg_t dummy;
    memset(&dummy, 0, sizeof(dummy));
    size_t pushed = 0;
    while (cu_queue_push(q, &dummy)) pushed++;
    TEST_ASSERT_EQ(pushed, CU_QUEUE_CAP, "bounded");
    free(q);
    net_free(n); free(n);
    return 1;
}

/* ---- only the host opens a round ----
   With either side opening rounds, simultaneous proposals need a rule
   (protocol 6.2 row 12, still answered by cu_reconcile) and leave the member
   with a signature over a second host commitment for one number.  The host
   opens every round, so a member message that would open one is refused. */

int test_cu_member_cannot_open_round(void) {
    init_secp();
    char why[256] = "";
    net_t *n = malloc(sizeof(*n));
    TEST_ASSERT(n && net_init(n), "init");
    cu_update_t mu;
    mk_add(&mu, 0, 2000000, 801);
    TEST_ASSERT_EQ(cu_propose(n->s[CU_MEMBER].c, &mu, 1), CU_ERR_ROLE, "member cannot open a round");
    TEST_ASSERT_EQ(cu_offer(n->s[CU_HOST].c, &mu, 1), CU_ERR_ROLE, "the host does not offer");
    TEST_ASSERT_EQ(n->s[CU_MEMBER].c->n_out, 0, "nothing sent");

    /* A member commitment_signed that opens a round: refused, nothing stored. */
    cu_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = CU_MSG_ADD;
    m.channel_id = n->s[0].cfg.channel_id;
    m.upd = mu;
    TEST_ASSERT_EQ(cu_on_message(n->s[CU_HOST].c, &m), CU_OK, "an add is a request");
    memset(&m, 0, sizeof(m));
    m.type = CU_MSG_COMMIT_SIG;
    m.channel_id = n->s[0].cfg.channel_id;
    m.n = 1;
    cu_digest(&mu, 1, m.digest);
    TEST_ASSERT_EQ(cu_on_message(n->s[CU_HOST].c, &m), CU_ERR_ROLE, "member signature refused");
    TEST_ASSERT_EQ(n->s[CU_HOST].c->rec.held, 0, "host unchanged");
    TEST_ASSERT_EQ(n->s[CU_HOST].c->rec.phase, CU_PHASE_IDLE, "no round");
    cu_clear_outputs(n->s[CU_HOST].c);

    /* While the host's round is open, a member signature over anything else. */
    cu_update_t hu;
    mk_add(&hu, 0, 4000000, 800);
    TEST_ASSERT_EQ(propose(n, CU_HOST, &hu, 1), CU_OK, "host opens");
    m.digest[0] ^= 1;
    TEST_ASSERT_EQ(cu_on_message(n->s[CU_HOST].c, &m), CU_ERR_ROLE, "refused mid-round too");
    TEST_ASSERT_EQ(n->s[CU_HOST].c->rec.phase, CU_PHASE_SENT, "host round stands");
    TEST_ASSERT_EQ(reconnect(n), CU_OK, "reconnect");
    TEST_ASSERT(at_rest(n, 1, why, sizeof(why)), why);

    /* A round update that acts for the member must be its own offer (INV-28). */
    memset(&m, 0, sizeof(m));
    m.type = CU_MSG_ADD;
    m.channel_id = n->s[1].cfg.channel_id;
    mk_add(&m.upd, 0, 1000000, 805);
    m.upd.sender = CU_MEMBER;
    TEST_ASSERT_EQ(cu_on_message(n->s[CU_MEMBER].c, &m), CU_ERR_PROTOCOL, "a made-up member update is refused");
    net_free(n); free(n);
    return 1;
}

/* ---- requests: refusal, and offers that survive a restart ---- */

int test_cu_refuse_offer(void) {
    init_secp();
    char why[256] = "";
    net_t *n = malloc(sizeof(*n));
    TEST_ASSERT(n && net_init(n), "init");
    cu_update_t mu;
    mk_add(&mu, 0, 2000000, 900);
    TEST_ASSERT_EQ(cu_offer(n->s[1].c, &mu, 1), CU_OK, "member offers");
    collect(n, 1);
    TEST_ASSERT_EQ(run(n, -1, NULL), CU_OK, "offer arrives");
    TEST_ASSERT(has_event(&n->s[0], CU_EV_UPDATE_RECEIVED), "host sees it");
    TEST_ASSERT_EQ(cu_refuse(n->s[0].c, CU_UPD_ADD, 0, 17), CU_OK, "host refuses");
    collect(n, 0);
    TEST_ASSERT_EQ(run(n, -1, NULL), CU_OK, "refusal arrives");
    TEST_ASSERT(has_event(&n->s[1], CU_EV_REFUSED), "member told");
    TEST_ASSERT_EQ(n->s[1].c->n_offered, 0, "offer removed");
    TEST_ASSERT(restart(n, CU_MEMBER), "restart member");
    TEST_ASSERT_EQ(n->s[1].c->n_offered, 0, "removal is durable");
    TEST_ASSERT(at_rest(n, 0, why, sizeof(why)), why);
    TEST_ASSERT_EQ(cu_refuse(n->s[1].c, CU_UPD_ADD, 0, 17), CU_ERR_ROLE, "the member refuses nothing");

    /* An offer the host cannot take is refused at once. */
    mk_add(&mu, 0, 900000000, 901);
    TEST_ASSERT_EQ(cu_offer(n->s[1].c, &mu, 1), CU_ERR_INVALID, "member checks its own offer");

    /* A carried request is no longer the host's to refuse. */
    mk_add(&mu, 0, 2000000, 902);
    TEST_ASSERT_EQ(propose(n, CU_MEMBER, &mu, 1), CU_OK, "request carried");
    TEST_ASSERT_EQ(cu_refuse(n->s[0].c, CU_UPD_ADD, 0, 17), CU_ERR_ARG, "not pending any more");
    TEST_ASSERT_EQ(run(n, -1, NULL), CU_OK, "round");
    TEST_ASSERT(at_rest(n, 1, why, sizeof(why)), why);

    /* An offer survives a member restart and a lost connection. */
    mk_add(&mu, 1, 1000000, 903);
    TEST_ASSERT_EQ(cu_offer(n->s[1].c, &mu, 1), CU_OK, "offer");
    n->n_pipe[0] = 0;                                   /* lost on the way */
    cu_clear_outputs(n->s[1].c);
    TEST_ASSERT(restart(n, CU_MEMBER), "restart member");
    TEST_ASSERT_EQ(n->s[1].c->n_offered, 1, "offer durable");
    TEST_ASSERT_EQ(reconnect(n), CU_OK, "reconnect offers it again");
    size_t nr = 0;
    cu_requests(n->s[0].c, &nr);
    TEST_ASSERT_EQ(nr, 1, "host has the request");
    TEST_ASSERT_EQ(host_carries_requests(n), CU_OK, "carried");
    TEST_ASSERT_EQ(run(n, -1, NULL), CU_OK, "round");
    TEST_ASSERT(at_rest(n, 2, why, sizeof(why)), why);
    TEST_ASSERT_EQ(n->s[0].c->st.n_htlcs, 2, "both, once each");

    /* The host cannot make up a member update (INV-28). */
    mk_add(&mu, 2, 1000000, 904);
    mu.sender = CU_MEMBER;
    TEST_ASSERT_EQ(cu_propose(n->s[0].c, &mu, 1), CU_ERR_INVALID, "not a request");
    net_free(n); free(n);
    return 1;
}

/* ---- data loss, INV-23, INV-75, deadlines ---- */

static int copy_file(const char *from, const char *to) {
    FILE *a = fopen(from, "rb"), *b = fopen(to, "wb");
    char buf[8192];
    size_t k;
    if (!a || !b) { if (a) fclose(a); if (b) fclose(b); return 0; }
    while ((k = fread(buf, 1, sizeof(buf), a)) > 0) fwrite(buf, 1, k, b);
    fclose(a); fclose(b);
    return 1;
}

int test_cu_data_loss(void) {
    init_secp();
    net_t *n = malloc(sizeof(*n));
    TEST_ASSERT(n && net_init(n), "init");
    cu_update_t u;
    char backup[300];
    mk_add(&u, 0, 1000000, 950);
    TEST_ASSERT_EQ(propose(n, CU_HOST, &u, 1), CU_OK, "r1");
    TEST_ASSERT_EQ(run(n, -1, NULL), CU_OK, "r1 run");
    snprintf(backup, sizeof(backup), "%s.bak", n->s[0].path);
    sqlite3_exec(n->s[0].db.db, "PRAGMA wal_checkpoint(TRUNCATE);", NULL, NULL, NULL);
    {
        mode_t old = umask(077);
        int copied = copy_file(n->s[0].path, backup);
        umask(old);
        TEST_ASSERT(copied, "backup host at 1");
    }
    mk_add(&u, 1, 1000000, 951);
    TEST_ASSERT_EQ(propose(n, CU_HOST, &u, 1), CU_OK, "r2");
    TEST_ASSERT_EQ(run(n, -1, NULL), CU_OK, "r2 run");
    mk_add(&u, 2, 1000000, 952);
    TEST_ASSERT_EQ(propose(n, CU_HOST, &u, 1), CU_OK, "r3");
    TEST_ASSERT_EQ(run(n, -1, NULL), CU_OK, "r3 run");
    /* The host restores the old database. */
    persist_close(&n->s[0].db);
    unlink_aux(n->s[0].path);
    {
        mode_t old = umask(077);
        int copied = copy_file(backup, n->s[0].path);
        umask(old);
        TEST_ASSERT(copied, "restore");
    }
    unlink(backup);
    TEST_ASSERT(open_side(&n->s[0]) && load_side(&n->s[0]), "reload");
    reconnect(n);
    while (n->n_pipe[0] || n->n_pipe[1]) run(n, -1, NULL);
    TEST_ASSERT_EQ(n->s[0].c->rec.halted, CU_HALT_DATA_LOSS, "host knows it is behind");
    TEST_ASSERT_EQ(n->s[1].c->rec.halted, CU_HALT_PEER_LOST, "member knows the host lost data");
    unsigned char tx[256], sig[64];
    size_t len = sizeof(tx);
    TEST_ASSERT_EQ(cu_latest_commitment(n->s[0].c, tx, &len, sig, NULL), CU_ERR_HALTED,
                   "the host never broadcasts after data loss");
    len = sizeof(tx);
    TEST_ASSERT_EQ(cu_latest_commitment(n->s[1].c, tx, &len, sig, NULL), CU_OK, "the member exits");
    net_free(n); free(n);
    return 1;
}

int test_cu_no_txn_across_calls(void) {
    init_secp();
    net_t *n = malloc(sizeof(*n));
    TEST_ASSERT(n && net_init(n), "init");
    cu_update_t u;
    mk_add(&u, 0, 1000000, 960);
    TEST_ASSERT(persist_begin(&n->s[0].db), "outside transaction open");
    TEST_ASSERT_EQ(cu_propose(n->s[0].c, &u, 1), CU_ERR_DB, "refused inside another transaction");
    persist_rollback(&n->s[0].db);
    TEST_ASSERT_EQ(propose(n, CU_HOST, &u, 1), CU_OK, "fine after");
    TEST_ASSERT(!persist_in_transaction(&n->s[0].db), "no transaction left open by the engine");
    TEST_ASSERT_EQ(run(n, -1, NULL), CU_OK, "round");
    TEST_ASSERT(!persist_in_transaction(&n->s[0].db) && !persist_in_transaction(&n->s[1].db), "none open");
    TEST_ASSERT(sqlite3_get_autocommit(n->s[0].db.db) && sqlite3_get_autocommit(n->s[1].db.db), "sqlite agrees");
    net_free(n); free(n);
    return 1;
}

int test_cu_deadline_goes_onchain(void) {
    init_secp();
    net_t *n = malloc(sizeof(*n));
    TEST_ASSERT(n && net_init(n), "init");
    cu_update_t u;
    mk_add(&u, 0, 1000000, 970);
    TEST_ASSERT_EQ(propose(n, CU_HOST, &u, 1), CU_OK, "add");
    TEST_ASSERT_EQ(run(n, -1, NULL), CU_OK, "round");
    TEST_ASSERT_EQ(cu_on_block(n->s[0].c, TIP + 50), 0, "not yet");
    TEST_ASSERT_EQ(cu_on_block(n->s[0].c, TIP + 95), 1, "within the margin");
    TEST_ASSERT_EQ(n->s[0].c->st.n_htlcs, 1, "never removed locally (INV-31)");
    collect(n, 0);
    TEST_ASSERT(has_event(&n->s[0], CU_EV_GO_ONCHAIN), "go on chain");
    net_free(n); free(n);
    return 1;
}

int test_cu_penalty_failure_aborts(void) {
    init_secp();
    char why[256] = "";
    net_t *n = malloc(sizeof(*n));
    TEST_ASSERT(n && net_init(n), "init");
    cu_update_t u;
    mk_add(&u, 0, 1000000, 980);
    n->s[0].f.fail_penalty = 1;
    TEST_ASSERT_EQ(propose(n, CU_HOST, &u, 1), CU_OK, "propose");
    int rc = run(n, -1, NULL);
    TEST_ASSERT_EQ(rc, CU_ERR_DB, "tower write failed");
    TEST_ASSERT_EQ(n->s[0].c->rec.phase, CU_PHASE_SENT, "host did not advance");
    TEST_ASSERT_EQ(n->s[0].c->rec.revoked, -1, "and released nothing");
    n->s[0].f.fail_penalty = 0;
    TEST_ASSERT_EQ(reconnect(n), CU_OK, "reconnect");
    TEST_ASSERT(at_rest(n, 1, why, sizeof(why)), why);
    net_free(n); free(n);
    return 1;
}

/* INV-20: a number this side signed is never signed again with other bytes. */
static int set_signed_txid(side_t *s, uint64_t n, const unsigned char txid[32], int insert) {
    sqlite3_stmt *st;
    const char *sql = insert
        ? "INSERT INTO chan_update_signed (channel_id, commit_num, funding_txid, funding_vout, txid)"
          " VALUES (?, ?, ?, ?, ?);"
        : "UPDATE chan_update_signed SET txid=?5 WHERE channel_id=?1 AND commit_num=?2"
          " AND funding_txid=?3 AND funding_vout=?4;";
    if (sqlite3_prepare_v2(s->db.db, sql, -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int64(st, 1, s->cfg.channel_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)n);
    sqlite3_bind_blob(st, 3, s->cfg.funding_txid, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, s->cfg.funding_vout);
    sqlite3_bind_blob(st, 5, txid, 32, SQLITE_TRANSIENT);
    int ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(s->db.db) == 1;
    sqlite3_finalize(st);
    return ok;
}

int test_cu_one_commitment_per_number(void) {
    init_secp();
    net_t *n = malloc(sizeof(*n));
    TEST_ASSERT(n && net_init(n), "init");
    cu_update_t u;
    unsigned char other[32];
    memset(other, 0x3c, 32);
    mk_add(&u, 0, 1000000, 990);
    /* The host already signed a different commitment 1. */
    TEST_ASSERT(set_signed_txid(&n->s[0], 1, other, 1), "plant");
    TEST_ASSERT_EQ(cu_propose(n->s[0].c, &u, 1), CU_ERR_PROTOCOL, "refused");
    TEST_ASSERT_EQ(n->s[0].c->n_out, 0, "nothing sent");
    TEST_ASSERT_EQ(n->s[0].c->rec.phase, CU_PHASE_IDLE, "no round");
    net_free(n);

    /* A retransmission must rebuild the bytes it signed. */
    TEST_ASSERT(net_init(n), "init 2");
    TEST_ASSERT_EQ(propose(n, CU_HOST, &u, 1), CU_OK, "propose");
    TEST_ASSERT(set_signed_txid(&n->s[0], 1, other, 0), "corrupt the record");
    disconnect(n);
    cu_msg_t re;
    TEST_ASSERT_EQ(cu_reestablish_msg(n->s[1].c, &re), CU_OK, "member claim");
    TEST_ASSERT_EQ(cu_on_message(n->s[0].c, &re), CU_ERR_PROTOCOL, "host will not re-sign other bytes");
    for (size_t k = 0; k < n->s[0].c->n_out; k++)
        TEST_ASSERT(n->s[0].c->out[k].type != CU_MSG_COMMIT_SIG, "no signature left");
    net_free(n); free(n);
    if (g_template[0]) { unlink(g_template); unlink_aux(g_template); g_template[0] = 0; }
    return 1;
}
