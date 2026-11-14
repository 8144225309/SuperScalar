/* Channel-update engine: see include/superscalar/chan_update.h and
   docs/security/channel-update-protocol.md. */

#include "superscalar/chan_update.h"
#include "superscalar/channel.h"
#include "superscalar/crash_inject.h"
#include "superscalar/sha256.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Serialization (canonical, big-endian)                               */
/* ------------------------------------------------------------------ */

#define UPD_SER_LEN   98   /* 1+1+8+8+32+32+4+4+8 */
#define HTLC_SER_LEN  53   /* 8+1+8+32+4 */
#define STATE_HDR_LEN 52   /* 4*8 + 2*8 + 4 */
#define STATE_SER_MAX (STATE_HDR_LEN + CU_HTLC_CAP * HTLC_SER_LEN)
#define ROUND_SER_MAX (2 + CU_MAX_UPDATES * UPD_SER_LEN)

typedef struct { const unsigned char *p; size_t left; int ok; } rd_t;

static void put_u8(unsigned char **p, uint8_t v) { *(*p)++ = v; }
static void put_u16(unsigned char **p, uint16_t v) { put_u8(p, (uint8_t)(v >> 8)); put_u8(p, (uint8_t)v); }
static void put_u32(unsigned char **p, uint32_t v) { for (int i = 3; i >= 0; i--) put_u8(p, (uint8_t)(v >> (8 * i))); }
static void put_u64(unsigned char **p, uint64_t v) { for (int i = 7; i >= 0; i--) put_u8(p, (uint8_t)(v >> (8 * i))); }
static void put_bytes(unsigned char **p, const unsigned char *b, size_t n) { memcpy(*p, b, n); *p += n; }

static uint64_t get_uN(rd_t *r, int bytes) {
    if (!r->ok || r->left < (size_t)bytes) { r->ok = 0; return 0; }
    uint64_t v = 0;
    for (int i = 0; i < bytes; i++) v = (v << 8) | r->p[i];
    r->p += bytes; r->left -= (size_t)bytes;
    return v;
}
static void get_bytes(rd_t *r, unsigned char *out, size_t n) {
    if (!r->ok || r->left < n) { r->ok = 0; memset(out, 0, n); return; }
    memcpy(out, r->p, n); r->p += n; r->left -= n;
}

static void ser_update(const cu_update_t *u, unsigned char **p) {
    put_u8(p, u->kind);
    put_u8(p, u->sender);
    put_u64(p, u->id);
    put_u64(p, u->amount_msat);
    put_bytes(p, u->payment_hash, 32);
    put_bytes(p, u->preimage, 32);
    put_u32(p, u->cltv_expiry);
    put_u32(p, u->reason);
    put_u64(p, u->feerate_per_kvb);
}

static void de_update(rd_t *r, cu_update_t *u) {
    memset(u, 0, sizeof(*u));
    u->kind = (uint8_t)get_uN(r, 1);
    u->sender = (uint8_t)get_uN(r, 1);
    u->id = get_uN(r, 8);
    u->amount_msat = get_uN(r, 8);
    get_bytes(r, u->payment_hash, 32);
    get_bytes(r, u->preimage, 32);
    u->cltv_expiry = (uint32_t)get_uN(r, 4);
    u->reason = (uint32_t)get_uN(r, 4);
    u->feerate_per_kvb = get_uN(r, 8);
}

static size_t ser_round(const cu_update_t *u, size_t n, unsigned char *out) {
    unsigned char *p = out;
    put_u16(&p, (uint16_t)n);
    for (size_t i = 0; i < n; i++) ser_update(&u[i], &p);
    return (size_t)(p - out);
}

static int de_round(const unsigned char *b, size_t len, cu_update_t *u, size_t *n) {
    rd_t r = { b, len, 1 };
    size_t cnt = (size_t)get_uN(&r, 2);
    if (!r.ok || cnt > CU_MAX_UPDATES) return 0;
    for (size_t i = 0; i < cnt; i++) de_update(&r, &u[i]);
    if (!r.ok || r.left != 0) return 0;
    *n = cnt;
    return 1;
}

void cu_digest(const cu_update_t *u, size_t n, unsigned char out[32]) {
    unsigned char buf[ROUND_SER_MAX];
    if (n > CU_MAX_UPDATES) n = CU_MAX_UPDATES;
    size_t len = ser_round(u, n, buf);
    sha256(buf, len, out);
}

static size_t ser_state(const cu_state_t *s, unsigned char *out) {
    unsigned char *p = out;
    put_u64(&p, s->host_msat);
    put_u64(&p, s->member_msat);
    put_u64(&p, s->feerate_per_kvb);
    put_u64(&p, s->fee_msat);
    put_u64(&p, s->next_htlc_id[0]);
    put_u64(&p, s->next_htlc_id[1]);
    put_u32(&p, (uint32_t)s->n_htlcs);
    for (size_t i = 0; i < s->n_htlcs; i++) {
        const cu_htlc_t *h = &s->htlcs[i];
        put_u64(&p, h->id);
        put_u8(&p, h->offerer);
        put_u64(&p, h->amount_msat);
        put_bytes(&p, h->payment_hash, 32);
        put_u32(&p, h->cltv_expiry);
    }
    return (size_t)(p - out);
}

static int de_state(const unsigned char *b, size_t len, cu_state_t *s) {
    rd_t r = { b, len, 1 };
    memset(s, 0, sizeof(*s));
    s->host_msat = get_uN(&r, 8);
    s->member_msat = get_uN(&r, 8);
    s->feerate_per_kvb = get_uN(&r, 8);
    s->fee_msat = get_uN(&r, 8);
    s->next_htlc_id[0] = get_uN(&r, 8);
    s->next_htlc_id[1] = get_uN(&r, 8);
    size_t n = (size_t)get_uN(&r, 4);
    if (!r.ok || n > CU_HTLC_CAP) return 0;
    for (size_t i = 0; i < n; i++) {
        cu_htlc_t *h = &s->htlcs[i];
        h->id = get_uN(&r, 8);
        h->offerer = (uint8_t)get_uN(&r, 1);
        h->amount_msat = get_uN(&r, 8);
        get_bytes(&r, h->payment_hash, 32);
        h->cltv_expiry = (uint32_t)get_uN(&r, 4);
    }
    s->n_htlcs = n;
    return r.ok && r.left == 0;
}

/* ------------------------------------------------------------------ */
/* Pure state transition                                               */
/* ------------------------------------------------------------------ */

static int is_zero(const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; i++) if (b[i]) return 0;
    return 1;
}

static long find_htlc(const cu_state_t *s, uint8_t offerer, uint64_t id) {
    for (size_t i = 0; i < s->n_htlcs; i++)
        if (s->htlcs[i].offerer == offerer && s->htlcs[i].id == id) return (long)i;
    return -1;
}

static void remove_htlc(cu_state_t *s, size_t idx) {
    memmove(&s->htlcs[idx], &s->htlcs[idx + 1], (s->n_htlcs - idx - 1) * sizeof(cu_htlc_t));
    s->n_htlcs--;
}

static uint64_t *bal_of(cu_state_t *s, uint8_t side) {
    return side == CU_HOST ? &s->host_msat : &s->member_msat;
}

static int add_ok(uint64_t *a, uint64_t b) {
    if (*a > UINT64_MAX - b) return 0;
    *a += b;
    return 1;
}

static int conserves(const cu_state_t *s, uint64_t capacity) {
    uint64_t sum = 0;
    if (!add_ok(&sum, s->host_msat) || !add_ok(&sum, s->member_msat) || !add_ok(&sum, s->fee_msat))
        return 0;
    for (size_t i = 0; i < s->n_htlcs; i++)
        if (!add_ok(&sum, s->htlcs[i].amount_msat)) return 0;
    return sum == capacity;
}

/* check_tip = 0 rebuilds a state from this side's own durable round
   record, whose adds passed the CLTV checks when they were proposed. */
static int apply_ex(const cu_config_t *cfg, const cu_ops_t *ops, void *ops_ctx,
                    uint32_t tip, int check_tip, cu_side_t proposer, const cu_state_t *in,
                    const cu_update_t *u, size_t n, cu_state_t *out) {
    if (!cfg || !ops || !in || !u || !out) return CU_ERR_ARG;
    if (n == 0 || n > CU_MAX_UPDATES) return CU_ERR_INVALID;
    if (!conserves(in, cfg->capacity_msat)) return CU_ERR_INVALID;
    *out = *in;
    for (size_t i = 0; i < n; i++) {
        const cu_update_t *x = &u[i];
        /* INV-28: an update acts for its sender.  The member opens no
           round; its updates reach a round only inside the host's. */
        if (x->sender > CU_MEMBER) return CU_ERR_INVALID;
        cu_side_t who = (cu_side_t)x->sender;
        if (who != proposer && !(proposer == CU_HOST && who == CU_MEMBER))
            return CU_ERR_INVALID;
        switch (x->kind) {
        case CU_UPD_ADD: {
            if (x->id != out->next_htlc_id[who]) return CU_ERR_INVALID;
            if (x->amount_msat == 0 || x->amount_msat > cfg->capacity_msat) return CU_ERR_INVALID;
            if (is_zero(x->payment_hash, 32)) return CU_ERR_INVALID;
            if (out->n_htlcs >= cfg->max_htlcs || out->n_htlcs >= CU_HTLC_CAP) return CU_ERR_INVALID;
            /* INV-32: inside the factory, with headroom from a known tip. */
            if (x->cltv_expiry >= cfg->cltv_deadline) return CU_ERR_INVALID;
            if (check_tip) {
                if (tip == 0) return CU_ERR_INVALID;
                if (x->cltv_expiry < tip || x->cltv_expiry - tip < cfg->min_cltv_headroom)
                    return CU_ERR_INVALID;
            }
            uint64_t *b = bal_of(out, (uint8_t)who);
            if (*b < x->amount_msat) return CU_ERR_INVALID;
            *b -= x->amount_msat;
            cu_htlc_t *h = &out->htlcs[out->n_htlcs++];
            memset(h, 0, sizeof(*h));
            h->id = x->id;
            h->offerer = (uint8_t)who;
            h->amount_msat = x->amount_msat;
            memcpy(h->payment_hash, x->payment_hash, 32);
            h->cltv_expiry = x->cltv_expiry;
            out->next_htlc_id[who]++;
            break;
        }
        case CU_UPD_FULFILL: {
            /* Only the side the HTLC pays removes it. */
            long k = find_htlc(out, (uint8_t)CU_OTHER(who), x->id);
            if (k < 0) return CU_ERR_INVALID;
            unsigned char h[32];
            sha256(x->preimage, 32, h);
            if (memcmp(h, out->htlcs[k].payment_hash, 32) != 0) return CU_ERR_INVALID;
            if (!add_ok(bal_of(out, (uint8_t)who), out->htlcs[k].amount_msat)) return CU_ERR_INVALID;
            remove_htlc(out, (size_t)k);
            break;
        }
        case CU_UPD_FAIL: {
            long k = find_htlc(out, (uint8_t)CU_OTHER(who), x->id);
            if (k < 0) return CU_ERR_INVALID;
            if (!add_ok(bal_of(out, out->htlcs[k].offerer), out->htlcs[k].amount_msat)) return CU_ERR_INVALID;
            remove_htlc(out, (size_t)k);
            break;
        }
        case CU_UPD_FEE:
            if (who != CU_HOST) return CU_ERR_INVALID;
            if (x->feerate_per_kvb < cfg->fee_min_per_kvb || x->feerate_per_kvb > cfg->fee_max_per_kvb)
                return CU_ERR_INVALID;
            out->feerate_per_kvb = x->feerate_per_kvb;
            break;
        case CU_UPD_REANCHOR: case CU_UPD_TREE_MOVE: case CU_UPD_REALLOC:
        case CU_UPD_SPLICE: case CU_UPD_JIT_OPEN:
            return CU_ERR_KIND;
        default:
            return CU_ERR_INVALID;
        }
    }
    /* The host funds the channel and pays the commitment fee. */
    uint64_t fee = ops->commit_fee_msat(ops_ctx, out);
    if (fee > out->fee_msat) {
        uint64_t d = fee - out->fee_msat;
        if (out->host_msat < d) return CU_ERR_INVALID;
        out->host_msat -= d;
    } else if (!add_ok(&out->host_msat, out->fee_msat - fee)) {
        return CU_ERR_INVALID;
    }
    out->fee_msat = fee;
    /* INV-34: a round may not take the host below its reserve. */
    if (out->host_msat < cfg->host_reserve_msat && out->host_msat < in->host_msat)
        return CU_ERR_INVALID;
    /* INV-27 */
    if (!conserves(out, cfg->capacity_msat)) return CU_ERR_INVALID;
    return CU_OK;
}

int cu_apply(const cu_config_t *cfg, const cu_ops_t *ops, void *ops_ctx,
             uint32_t tip, cu_side_t proposer, const cu_state_t *in,
             const cu_update_t *u, size_t n, cu_state_t *out) {
    return apply_ex(cfg, ops, ops_ctx, tip, 1, proposer, in, u, n, out);
}

/* ------------------------------------------------------------------ */
/* Database access                                                     */
/* ------------------------------------------------------------------ */

static int prep(persist_t *db, const char *sql, sqlite3_stmt **st) {
    return sqlite3_prepare_v2(db->db, sql, -1, st, NULL) == SQLITE_OK;
}

static int step_done(sqlite3_stmt *st) {
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

static void bind_fund(sqlite3_stmt *st, int i, const cu_config_t *cfg) {
    sqlite3_bind_blob(st, i, cfg->funding_txid, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, i + 1, (sqlite3_int64)cfg->funding_vout);
}

static int rec_store(persist_t *db, const cu_config_t *cfg, const cu_rec_t *r) {
    sqlite3_stmt *st;
    unsigned char rb[ROUND_SER_MAX];
    size_t rl = ser_round(r->round, r->n_round, rb);
    if (!prep(db,
            "INSERT OR REPLACE INTO chan_update_channel (channel_id, side, funding_txid,"
            " funding_vout, capacity_msat, phase, round_role, halted, held, revoked,"
            " peer_revoked, round_updates, round_digest)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);", &st))
        return 0;
    sqlite3_bind_int64(st, 1, cfg->channel_id);
    sqlite3_bind_int(st, 2, (int)cfg->side);
    bind_fund(st, 3, cfg);
    sqlite3_bind_int64(st, 5, (sqlite3_int64)cfg->capacity_msat);
    sqlite3_bind_int(st, 6, r->phase);
    sqlite3_bind_int(st, 7, r->round_role);
    sqlite3_bind_int(st, 8, r->halted);
    sqlite3_bind_int64(st, 9, (sqlite3_int64)r->held);
    sqlite3_bind_int64(st, 10, r->revoked);
    sqlite3_bind_int64(st, 11, r->peer_revoked);
    sqlite3_bind_blob(st, 12, rb, (int)rl, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 13, r->digest, 32, SQLITE_TRANSIENT);
    return step_done(st);
}

static int rec_load(persist_t *db, const cu_config_t *cfg, cu_rec_t *r) {
    sqlite3_stmt *st;
    if (!prep(db,
            "SELECT side, funding_txid, funding_vout, capacity_msat, phase, round_role,"
            " halted, held, revoked, peer_revoked, round_updates, round_digest"
            " FROM chan_update_channel WHERE channel_id = ?;", &st))
        return 0;
    sqlite3_bind_int64(st, 1, cfg->channel_id);
    int ok = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        memset(r, 0, sizeof(*r));
        const void *ft = sqlite3_column_blob(st, 1);
        const void *rb = sqlite3_column_blob(st, 10);
        const void *dg = sqlite3_column_blob(st, 11);
        ok = sqlite3_column_int(st, 0) == (int)cfg->side
          && ft && sqlite3_column_bytes(st, 1) == 32
          && memcmp(ft, cfg->funding_txid, 32) == 0
          && (uint32_t)sqlite3_column_int64(st, 2) == cfg->funding_vout
          && (uint64_t)sqlite3_column_int64(st, 3) == cfg->capacity_msat
          && dg && sqlite3_column_bytes(st, 11) == 32;
        if (ok) {
            r->phase = (uint8_t)sqlite3_column_int(st, 4);
            r->round_role = (uint8_t)sqlite3_column_int(st, 5);
            r->halted = (uint8_t)sqlite3_column_int(st, 6);
            r->held = (uint64_t)sqlite3_column_int64(st, 7);
            r->revoked = sqlite3_column_int64(st, 8);
            r->peer_revoked = sqlite3_column_int64(st, 9);
            memcpy(r->digest, dg, 32);
            ok = rb && de_round(rb, (size_t)sqlite3_column_bytes(st, 10), r->round, &r->n_round);
        }
    }
    sqlite3_finalize(st);
    return ok;
}

/* Own commitment n: one per (channel, number, funding outpoint). */
static int commitment_put(persist_t *db, const cu_config_t *cfg, uint64_t n,
                          const cu_state_t *s, const unsigned char *tx, size_t len,
                          const unsigned char sig[64]) {
    unsigned char sb[STATE_SER_MAX];
    size_t sl = ser_state(s, sb);
    sqlite3_stmt *st;
    if (!prep(db, "SELECT tx FROM chan_update_commitment WHERE channel_id=? AND commit_num=?"
                  " AND funding_txid=? AND funding_vout=?;", &st))
        return 0;
    sqlite3_bind_int64(st, 1, cfg->channel_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)n);
    bind_fund(st, 3, cfg);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        int same = (size_t)sqlite3_column_bytes(st, 0) == len
                && memcmp(sqlite3_column_blob(st, 0), tx, len) == 0;
        sqlite3_finalize(st);
        return same;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return 0;
    if (!prep(db, "INSERT INTO chan_update_commitment (channel_id, commit_num, funding_txid,"
                  " funding_vout, state, tx, sig) VALUES (?,?,?,?,?,?,?);", &st))
        return 0;
    sqlite3_bind_int64(st, 1, cfg->channel_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)n);
    bind_fund(st, 3, cfg);
    sqlite3_bind_blob(st, 5, sb, (int)sl, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 6, tx, (int)len, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 7, sig, 64, SQLITE_TRANSIENT);
    return step_done(st);
}

/* A revoked own commitment keeps its state and transaction but loses its
   signature in the transaction that releases its secret: nothing revoked
   can be broadcast from this side's records (INV-23). */
static int commitment_drop_sig(persist_t *db, const cu_config_t *cfg, uint64_t n) {
    sqlite3_stmt *st;
    if (!prep(db, "UPDATE chan_update_commitment SET sig=X'' WHERE channel_id=? AND commit_num=?"
                  " AND funding_txid=? AND funding_vout=?;", &st))
        return 0;
    sqlite3_bind_int64(st, 1, cfg->channel_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)n);
    bind_fund(st, 3, cfg);
    return step_done(st) && sqlite3_changes(db->db) == 1;
}

static int commitment_get(persist_t *db, const cu_config_t *cfg, uint64_t n, cu_state_t *s,
                          unsigned char *tx, size_t *len, unsigned char sig[64]) {
    sqlite3_stmt *st;
    if (!prep(db, "SELECT state, tx, sig FROM chan_update_commitment WHERE channel_id=?"
                  " AND commit_num=? AND funding_txid=? AND funding_vout=?;", &st))
        return 0;
    sqlite3_bind_int64(st, 1, cfg->channel_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)n);
    bind_fund(st, 3, cfg);
    int ok = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        ok = !s || de_state(sqlite3_column_blob(st, 0), (size_t)sqlite3_column_bytes(st, 0), s);
        size_t tl = (size_t)sqlite3_column_bytes(st, 1);
        if (ok && tx && len) {
            if (tl > *len) ok = 0;
            else { memcpy(tx, sqlite3_column_blob(st, 1), tl); *len = tl; }
        }
        if (ok && sig) {
            if (sqlite3_column_bytes(st, 2) != 64) ok = 0;
            else memcpy(sig, sqlite3_column_blob(st, 2), 64);
        }
    }
    sqlite3_finalize(st);
    return ok;
}

/* Peer commitments this side has signed (INV-20). */
static int signed_get(persist_t *db, const cu_config_t *cfg, uint64_t n, unsigned char txid[32]) {
    sqlite3_stmt *st;
    if (!prep(db, "SELECT txid FROM chan_update_signed WHERE channel_id=? AND commit_num=?"
                  " AND funding_txid=? AND funding_vout=?;", &st))
        return 0;
    sqlite3_bind_int64(st, 1, cfg->channel_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)n);
    bind_fund(st, 3, cfg);
    int ok = 0;
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 32) {
        memcpy(txid, sqlite3_column_blob(st, 0), 32);
        ok = 1;
    }
    sqlite3_finalize(st);
    return ok;
}

static int signed_put(persist_t *db, const cu_config_t *cfg, uint64_t n, const unsigned char txid[32]) {
    unsigned char old[32];
    if (signed_get(db, cfg, n, old)) return memcmp(old, txid, 32) == 0;
    sqlite3_stmt *st;
    if (!prep(db, "INSERT INTO chan_update_signed (channel_id, commit_num, funding_txid,"
                  " funding_vout, txid) VALUES (?,?,?,?,?);", &st))
        return 0;
    sqlite3_bind_int64(st, 1, cfg->channel_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)n);
    bind_fund(st, 3, cfg);
    sqlite3_bind_blob(st, 5, txid, 32, SQLITE_TRANSIENT);
    return step_done(st);
}

static int signed_max(persist_t *db, const cu_config_t *cfg, uint64_t *out) {
    sqlite3_stmt *st;
    if (!prep(db, "SELECT MAX(commit_num) FROM chan_update_signed WHERE channel_id=?"
                  " AND funding_txid=? AND funding_vout=?;", &st))
        return 0;
    sqlite3_bind_int64(st, 1, cfg->channel_id);
    bind_fund(st, 2, cfg);
    int ok = 0;
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL) {
        *out = (uint64_t)sqlite3_column_int64(st, 0);
        ok = 1;
    }
    sqlite3_finalize(st);
    return ok;
}

/* A signature given for a proposal that lost to a simultaneous one: kept,
   so the penalty for that number covers it too. */
static int signed_void(persist_t *db, const cu_config_t *cfg, uint64_t n,
                       const unsigned char *tx, size_t len) {
    sqlite3_stmt *st;
    unsigned char txid[32];
    if (!signed_get(db, cfg, n, txid)) return 1;
    if (!prep(db, "INSERT OR IGNORE INTO chan_update_signed_void (channel_id, commit_num,"
                  " funding_txid, funding_vout, txid, tx) VALUES (?,?,?,?,?,?);", &st))
        return 0;
    sqlite3_bind_int64(st, 1, cfg->channel_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)n);
    bind_fund(st, 3, cfg);
    sqlite3_bind_blob(st, 5, txid, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 6, tx, (int)len, SQLITE_TRANSIENT);
    if (!step_done(st)) return 0;
    if (!prep(db, "DELETE FROM chan_update_signed WHERE channel_id=? AND commit_num=?"
                  " AND funding_txid=? AND funding_vout=?;", &st))
        return 0;
    sqlite3_bind_int64(st, 1, cfg->channel_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)n);
    bind_fund(st, 3, cfg);
    return step_done(st);
}

static int secret_get(persist_t *db, uint32_t ch, uint64_t n, unsigned char s[32], int *released) {
    sqlite3_stmt *st;
    if (!prep(db, "SELECT secret, released FROM chan_update_secret WHERE channel_id=? AND commit_num=?;", &st))
        return 0;
    sqlite3_bind_int64(st, 1, ch);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)n);
    int ok = 0;
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 32) {
        memcpy(s, sqlite3_column_blob(st, 0), 32);
        if (released) *released = sqlite3_column_int(st, 1);
        ok = 1;
    }
    sqlite3_finalize(st);
    return ok;
}

static int secret_insert(persist_t *db, uint32_t ch, uint64_t n, const unsigned char s[32]) {
    sqlite3_stmt *st;
    if (!prep(db, "INSERT INTO chan_update_secret (channel_id, commit_num, secret, released)"
                  " VALUES (?,?,?,0);", &st))
        return 0;
    sqlite3_bind_int64(st, 1, ch);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)n);
    sqlite3_bind_blob(st, 3, s, 32, SQLITE_TRANSIENT);
    return step_done(st);
}

/* The secret for n: the stored one, or a fresh one stored now (INV-26:
   durable before its point can leave). */
static int secret_ensure(persist_t *db, uint32_t ch, uint64_t n, unsigned char s[32]) {
    if (secret_get(db, ch, n, s, NULL)) return 1;
    do {
        if (!channel_read_random_bytes(s, 32)) return 0;
    } while (is_zero(s, 32));
    return secret_insert(db, ch, n, s);
}

static int secret_release(persist_t *db, uint32_t ch, uint64_t n) {
    sqlite3_stmt *st;
    if (!prep(db, "UPDATE chan_update_secret SET released=1 WHERE channel_id=? AND commit_num=?;", &st))
        return 0;
    sqlite3_bind_int64(st, 1, ch);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)n);
    if (!step_done(st)) return 0;
    return sqlite3_changes(db->db) == 1;
}

static int peer_point_get(persist_t *db, uint32_t ch, uint64_t n, unsigned char out[33]) {
    sqlite3_stmt *st;
    if (!prep(db, "SELECT point FROM chan_update_peer_point WHERE channel_id=? AND commit_num=?;", &st))
        return 0;
    sqlite3_bind_int64(st, 1, ch);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)n);
    int ok = 0;
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 33) {
        memcpy(out, sqlite3_column_blob(st, 0), 33);
        ok = 1;
    }
    sqlite3_finalize(st);
    return ok;
}

static int peer_point_put(persist_t *db, uint32_t ch, uint64_t n, const unsigned char p[33]) {
    unsigned char old[33];
    if (peer_point_get(db, ch, n, old)) return memcmp(old, p, 33) == 0;
    sqlite3_stmt *st;
    if (!prep(db, "INSERT INTO chan_update_peer_point (channel_id, commit_num, point) VALUES (?,?,?);", &st))
        return 0;
    sqlite3_bind_int64(st, 1, ch);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)n);
    sqlite3_bind_blob(st, 3, p, 33, SQLITE_TRANSIENT);
    return step_done(st);
}

static int peer_secret_get(persist_t *db, uint32_t ch, uint64_t n, unsigned char s[32]) {
    sqlite3_stmt *st;
    if (!prep(db, "SELECT secret FROM chan_update_peer_secret WHERE channel_id=? AND commit_num=?;", &st))
        return 0;
    sqlite3_bind_int64(st, 1, ch);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)n);
    int ok = 0;
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 32) {
        memcpy(s, sqlite3_column_blob(st, 0), 32);
        ok = 1;
    }
    sqlite3_finalize(st);
    return ok;
}

static int peer_secret_put(persist_t *db, uint32_t ch, uint64_t n, const unsigned char s[32]) {
    unsigned char old[32];
    if (peer_secret_get(db, ch, n, old)) return memcmp(old, s, 32) == 0;
    sqlite3_stmt *st;
    if (!prep(db, "INSERT INTO chan_update_peer_secret (channel_id, commit_num, secret) VALUES (?,?,?);", &st))
        return 0;
    sqlite3_bind_int64(st, 1, ch);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)n);
    sqlite3_bind_blob(st, 3, s, 32, SQLITE_TRANSIENT);
    return step_done(st);
}

/* The member's offers, in order (the whole list is rewritten). */
static int offers_store(persist_t *db, uint32_t ch, const cu_update_t *u, size_t n) {
    sqlite3_stmt *st;
    if (!prep(db, "DELETE FROM chan_update_offer WHERE channel_id=?;", &st)) return 0;
    sqlite3_bind_int64(st, 1, ch);
    if (!step_done(st)) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char b[UPD_SER_LEN], *p = b;
        ser_update(&u[i], &p);
        if (!prep(db, "INSERT INTO chan_update_offer (channel_id, seq, upd) VALUES (?,?,?);", &st))
            return 0;
        sqlite3_bind_int64(st, 1, ch);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)i);
        sqlite3_bind_blob(st, 3, b, UPD_SER_LEN, SQLITE_TRANSIENT);
        if (!step_done(st)) return 0;
    }
    return 1;
}

static int offers_load(persist_t *db, uint32_t ch, cu_update_t *u, size_t *n) {
    sqlite3_stmt *st;
    *n = 0;
    if (!prep(db, "SELECT upd FROM chan_update_offer WHERE channel_id=? ORDER BY seq;", &st)) return 0;
    sqlite3_bind_int64(st, 1, ch);
    int ok = 1;
    while (ok && sqlite3_step(st) == SQLITE_ROW) {
        rd_t r = { sqlite3_column_blob(st, 0), (size_t)sqlite3_column_bytes(st, 0), 1 };
        if (*n >= CU_MAX_UPDATES) { ok = 0; break; }
        de_update(&r, &u[*n]);
        ok = r.ok && r.left == 0;
        if (ok) (*n)++;
    }
    sqlite3_finalize(st);
    return ok;
}

static int same_update(const cu_update_t *a, const cu_update_t *b) {
    unsigned char x[UPD_SER_LEN], y[UPD_SER_LEN], *p = x, *q = y;
    ser_update(a, &p);
    ser_update(b, &q);
    return memcmp(x, y, UPD_SER_LEN) == 0;
}

static long find_update(const cu_update_t *list, size_t n, const cu_update_t *u) {
    for (size_t i = 0; i < n; i++) if (same_update(&list[i], u)) return (long)i;
    return -1;
}

/* ------------------------------------------------------------------ */
/* Engine internals                                                    */
/* ------------------------------------------------------------------ */

/* The state after this side's own open round, from its durable record. */
static int rebuild_round(const cu_chan_t *c, cu_state_t *out) {
    return apply_ex(&c->cfg, c->ops, c->ops_ctx, 0, 0, c->cfg.side, &c->st,
                    c->rec.round, c->rec.n_round, out);
}

static int hook(cu_chan_t *c, int pt) {
    return c->crash_hook ? c->crash_hook(c->crash_ctx, pt) : 0;
}

static int txn_begin(cu_chan_t *c) {
    return persist_begin(c->db) ? CU_OK : CU_ERR_DB;
}

static int txn_abort(cu_chan_t *c, int rc) {
    persist_rollback(c->db);
    return rc;
}

/* Commit one durable write.  Nothing that depends on it is in the outbox
   yet; it is added by the caller only on CU_OK. */
static int txn_finish(cu_chan_t *c, int before, int after, const char *name) {
    int h = hook(c, before);
    if (h) return txn_abort(c, h == 2 ? CU_ERR_DB : CU_ERR_CRASHED);
    if (!persist_commit(c->db)) {
        persist_rollback(c->db);
        return CU_ERR_DB;
    }
    lsp_crash_checkpoint(name);
    if (hook(c, after)) return CU_ERR_CRASHED;
    return CU_OK;
}

static int out_push(cu_chan_t *c, const cu_msg_t *m) {
    if (c->n_out >= CU_OUTBOX_CAP) return CU_ERR_QUEUE_FULL;
    c->out[c->n_out] = *m;
    c->out[c->n_out].channel_id = c->cfg.channel_id;
    c->n_out++;
    return CU_OK;
}

static void ev_push(cu_chan_t *c, const cu_event_t *e) {
    /* Events mirror durable state; the cap holds one call's worth. */
    if (c->n_ev < CU_EVENT_CAP) c->ev[c->n_ev++] = *e;
}

static void ev_simple(cu_chan_t *c, uint8_t type, uint64_t n, int32_t code) {
    cu_event_t e;
    memset(&e, 0, sizeof(e));
    e.type = type; e.n = n; e.code = code;
    ev_push(c, &e);
}

static int send_error(cu_chan_t *c, int32_t code) {
    cu_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = CU_MSG_ERROR;
    m.code = code;
    return out_push(c, &m);
}

static uint8_t msg_type_of(uint8_t kind) {
    switch (kind) {
    case CU_UPD_ADD: return CU_MSG_ADD;
    case CU_UPD_FULFILL: return CU_MSG_FULFILL;
    case CU_UPD_FAIL: return CU_MSG_FAIL;
    case CU_UPD_FEE: return CU_MSG_FEE;
    default: return 0;
    }
}

static int push_updates(cu_chan_t *c, const cu_update_t *u, size_t n) {
    for (size_t i = 0; i < n; i++) {
        cu_msg_t m;
        memset(&m, 0, sizeof(m));
        m.type = msg_type_of(u[i].kind);
        if (!m.type) return CU_ERR_KIND;
        m.upd = u[i];
        int rc = out_push(c, &m);
        if (rc != CU_OK) return rc;
    }
    return CU_OK;
}

static int my_point(cu_chan_t *c, uint64_t n, secp256k1_pubkey *pt) {
    unsigned char s[32];
    if (!secret_get(c->db, c->cfg.channel_id, n, s, NULL)) return 0;
    int ok = secp256k1_ec_pubkey_create(c->secp, pt, s);
    memset(s, 0, 32);
    return ok;
}

static int my_point_ser(cu_chan_t *c, uint64_t n, unsigned char out[33]) {
    secp256k1_pubkey pt;
    size_t len = 33;
    if (!my_point(c, n, &pt)) return 0;
    return secp256k1_ec_pubkey_serialize(c->secp, out, &len, &pt, SECP256K1_EC_COMPRESSED);
}

static int peer_point(cu_chan_t *c, uint64_t n, secp256k1_pubkey *pt) {
    unsigned char b[33];
    if (!peer_point_get(c->db, c->cfg.channel_id, n, b)) return 0;
    return secp256k1_ec_pubkey_parse(c->secp, pt, b, 33);
}

static int build_for(cu_chan_t *c, cu_side_t holder, uint64_t n, const cu_state_t *st,
                     unsigned char *tx, size_t *len, unsigned char txid[32]) {
    secp256k1_pubkey pt;
    int ok = holder == c->cfg.side ? my_point(c, n, &pt) : peer_point(c, n, &pt);
    if (!ok) return 0;
    *len = CU_TX_MAX;
    return c->ops->build_commitment(c->ops_ctx, holder, n, st, &pt, tx, len, txid);
}

/* INV-25: the one place a counterparty revocation secret is checked. */
static int verify_peer_secret(cu_chan_t *c, uint64_t n, const unsigned char s[32]) {
    secp256k1_pubkey want, got;
    unsigned char a[33], b[33];
    size_t la = 33, lb = 33;
    if (!peer_point(c, n, &want)) return 0;
    if (!secp256k1_ec_seckey_verify(c->secp, s)) return 0;
    if (!secp256k1_ec_pubkey_create(c->secp, &got, s)) return 0;
    secp256k1_ec_pubkey_serialize(c->secp, a, &la, &want, SECP256K1_EC_COMPRESSED);
    secp256k1_ec_pubkey_serialize(c->secp, b, &lb, &got, SECP256K1_EC_COMPRESSED);
    return memcmp(a, b, 33) == 0;
}

static int valid_point(cu_chan_t *c, const unsigned char p[33]) {
    secp256k1_pubkey pt;
    return secp256k1_ec_pubkey_parse(c->secp, &pt, p, 33);
}

/* Revocation of the peer's commitment n: store the secret and next point
   and arm the penalty for every commitment n this side signed, inside the
   caller's open transaction. */
static int store_peer_revocation(cu_chan_t *c, uint64_t n, const cu_state_t *st_n,
                                 const unsigned char secret[32], const unsigned char next_point[33]) {
    unsigned char *tx = malloc(CU_TX_MAX);
    unsigned char txid[32], want[32];
    size_t len;
    int ok = tx != NULL;
    ok = ok && build_for(c, CU_OTHER(c->cfg.side), n, st_n, tx, &len, txid);
    /* The commitment being revoked is the one this side signed. */
    ok = ok && signed_get(c->db, &c->cfg, n, want) && memcmp(want, txid, 32) == 0;
    ok = ok && peer_secret_put(c->db, c->cfg.channel_id, n, secret);
    ok = ok && peer_point_put(c->db, c->cfg.channel_id, n + 2, next_point);
    ok = ok && c->ops->arm_penalty(c->ops_ctx, c->db, n, secret, tx, len, st_n) == 1;
    if (ok) {
        sqlite3_stmt *st;
        ok = prep(c->db, "SELECT tx FROM chan_update_signed_void WHERE channel_id=? AND commit_num=?"
                         " AND funding_txid=? AND funding_vout=?;", &st);
        if (ok) {
            sqlite3_bind_int64(st, 1, c->cfg.channel_id);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)n);
            bind_fund(st, 3, &c->cfg);
            while (ok && sqlite3_step(st) == SQLITE_ROW)
                ok = c->ops->arm_penalty(c->ops_ctx, c->db, n, secret,
                                         sqlite3_column_blob(st, 0),
                                         (size_t)sqlite3_column_bytes(st, 0), NULL) == 1;
            sqlite3_finalize(st);
        }
    }
    free(tx);
    return ok;
}

static int raa_msg(cu_chan_t *c, uint64_t n_revoked, cu_msg_t *m) {
    int released = 0;
    memset(m, 0, sizeof(*m));
    m->type = CU_MSG_REVOKE;
    m->n = n_revoked;
    if (!secret_get(c->db, c->cfg.channel_id, n_revoked, m->secret, &released) || !released)
        return 0;
    return my_point_ser(c, n_revoked + 2, m->next_point);
}

static void events_holds(cu_chan_t *c, const cu_state_t *prev, const cu_update_t *u, size_t n, uint64_t nn) {
    for (size_t i = 0; i < n; i++) {
        cu_event_t e;
        memset(&e, 0, sizeof(e));
        e.n = nn;
        e.upd = u[i];
        if (u[i].kind == CU_UPD_ADD) {
            e.type = CU_EV_HTLC_ADDED;
            e.htlc.id = u[i].id;
            e.htlc.offerer = u[i].sender;
            e.htlc.amount_msat = u[i].amount_msat;
            memcpy(e.htlc.payment_hash, u[i].payment_hash, 32);
            e.htlc.cltv_expiry = u[i].cltv_expiry;
        } else if (u[i].kind == CU_UPD_FULFILL) {
            long k = find_htlc(prev, (uint8_t)CU_OTHER((cu_side_t)u[i].sender), u[i].id);
            e.type = CU_EV_HTLC_FULFILLED;
            if (k >= 0) e.htlc = prev->htlcs[k];
            memcpy(e.preimage, u[i].preimage, 32);
        } else if (u[i].kind == CU_UPD_FEE) {
            e.type = CU_EV_FEE_CHANGED;
        } else {
            continue;
        }
        ev_push(c, &e);
    }
}

/* At DONE the removal is in every commitment either side holds unrevoked,
   which is when an upstream fail may follow (INV-29). */
static void events_done(cu_chan_t *c, const cu_update_t *u, size_t n, uint64_t nn) {
    cu_state_t *prev = malloc(sizeof(*prev));
    int have = prev && nn > 0 && commitment_get(c->db, &c->cfg, nn - 1, prev, NULL, NULL, NULL);
    for (size_t i = 0; i < n; i++) {
        if (u[i].kind != CU_UPD_FAIL) continue;
        cu_event_t e;
        memset(&e, 0, sizeof(e));
        e.type = CU_EV_HTLC_FAILED;
        e.n = nn;
        e.upd = u[i];
        if (have) {
            long k = find_htlc(prev, (uint8_t)CU_OTHER((cu_side_t)u[i].sender), u[i].id);
            if (k >= 0) e.htlc = prev->htlcs[k];
        }
        ev_push(c, &e);
    }
    free(prev);
    ev_simple(c, CU_EV_ROUND_DONE, nn, 0);
}

static int halt(cu_chan_t *c, uint8_t code) {
    cu_rec_t r = c->rec;
    r.halted = code;
    int rc = txn_begin(c);
    if (rc != CU_OK) return rc;
    if (!rec_store(c->db, &c->cfg, &r)) return txn_abort(c, CU_ERR_DB);
    if (!persist_commit(c->db)) return txn_abort(c, CU_ERR_DB);
    c->rec = r;
    ev_simple(c, CU_EV_HALTED, c->rec.held, code);
    send_error(c, code);
    return CU_ERR_HALTED;
}

/* ---- proposer: start a round ---- */

static int round_start(cu_chan_t *c, const cu_update_t *u, size_t n) {
    if (c->cfg.side != CU_HOST) return CU_ERR_ROLE;
    if (c->rec.halted) return CU_ERR_HALTED;
    if (persist_in_transaction(c->db)) return CU_ERR_DB;
    if (c->rec.phase != CU_PHASE_IDLE) return CU_ERR_BUSY;
    if (n == 0 || n > CU_MAX_UPDATES) return CU_ERR_ARG;

    cu_update_t ups[CU_MAX_UPDATES];
    long req_idx[CU_MAX_UPDATES];
    memcpy(ups, u, n * sizeof(cu_update_t));
    /* A member update is one of its requests, used once; the rest are the
       host's own. */
    for (size_t i = 0; i < n; i++) {
        req_idx[i] = -1;
        if (ups[i].sender == CU_MEMBER) {
            req_idx[i] = find_update(c->peer_updates, c->n_peer_updates, &ups[i]);
            if (req_idx[i] < 0) return CU_ERR_INVALID;
            for (size_t j = 0; j < i; j++) if (req_idx[j] == req_idx[i]) return CU_ERR_INVALID;
        } else {
            ups[i].sender = CU_HOST;
        }
    }

    cu_state_t *next = malloc(sizeof(*next));
    unsigned char *tx = malloc(CU_TX_MAX);
    int rc = CU_ERR_DB;
    if (!next || !tx) goto out;
    rc = cu_apply(&c->cfg, c->ops, c->ops_ctx, c->tip, c->cfg.side, &c->st, ups, n, next);
    if (rc != CU_OK) goto out;

    uint64_t nn = c->rec.held + 1;
    unsigned char txid[32], old[32], psig[32], digest[32], s2[32];
    size_t len;
    uint32_t idx = 0;
    rc = CU_ERR_PROTOCOL;
    if (!build_for(c, CU_OTHER(c->cfg.side), nn, next, tx, &len, txid)) goto out;
    /* INV-20: one commitment per number; a different one is never signed. */
    if (signed_get(c->db, &c->cfg, nn, old) && memcmp(old, txid, 32) != 0) goto out;
    rc = CU_ERR_VERIFY;
    if (!c->ops->sign_peer(c->ops_ctx, nn, tx, len, psig, &idx)) goto out;
    cu_digest(ups, n, digest);

    cu_rec_t r = c->rec;
    r.phase = CU_PHASE_SENT;
    r.round_role = CU_PROPOSER;
    r.n_round = n;
    memcpy(r.round, ups, n * sizeof(cu_update_t));
    memcpy(r.digest, digest, 32);

    rc = txn_begin(c);
    if (rc != CU_OK) goto out;
    int ok = signed_put(c->db, &c->cfg, nn, txid)
          && secret_ensure(c->db, c->cfg.channel_id, nn + 1, s2);
    /* INV-30: the claim is armed before the preimage leaves. */
    for (size_t i = 0; ok && i < n; i++) {
        if (ups[i].kind != CU_UPD_FULFILL || ups[i].sender != (uint8_t)c->cfg.side) continue;
        long k = find_htlc(&c->st, (uint8_t)CU_OTHER(c->cfg.side), ups[i].id);
        ok = k >= 0 && c->ops->arm_claim(c->ops_ctx, c->db, nn, &c->st.htlcs[k], ups[i].preimage) == 1;
    }
    ok = ok && rec_store(c->db, &c->cfg, &r);
    memset(s2, 0, 32);
    if (!ok) { rc = txn_abort(c, CU_ERR_DB); goto out; }
    rc = txn_finish(c, CU_CP_SENT_BEFORE, CU_CP_SENT_AFTER, "cu_sent");
    if (rc != CU_OK) goto out;
    c->rec = r;
    c->have_peer_cs = 0;
    {
        /* The requests this round carries are no longer pending. */
        size_t k = 0;
        for (size_t i = 0; i < c->n_peer_updates; i++) {
            int used = 0;
            for (size_t j = 0; j < n; j++) if (req_idx[j] == (long)i) used = 1;
            if (!used) c->peer_updates[k++] = c->peer_updates[i];
        }
        c->n_peer_updates = k;
    }

    rc = push_updates(c, ups, n);
    if (rc != CU_OK) goto out;
    cu_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = CU_MSG_COMMIT_SIG;
    m.n = nn;
    memcpy(m.psig, psig, 32);
    m.nonce_index = idx;
    memcpy(m.digest, digest, 32);
    rc = out_push(c, &m);
out:
    free(next);
    free(tx);
    return rc;
}

/* ---- responder: the proposer's commitment_signed ---- */

static int responder_cs(cu_chan_t *c, const cu_msg_t *m) {
    uint64_t n = c->rec.held, nn = n + 1;
    cu_state_t *next = malloc(sizeof(*next));
    unsigned char *mytx = malloc(CU_TX_MAX), *ptx = malloc(CU_TX_MAX);
    unsigned char mytxid[32], ptxid[32], old[32], sig[64], psig[32], digest[32], s2[32];
    size_t mylen, plen;
    uint32_t idx = 0;
    int rc = CU_ERR_DB;
    cu_update_t ups[CU_MAX_UPDATES];
    size_t nu = c->n_peer_updates;
    memcpy(ups, c->peer_updates, nu * sizeof(cu_update_t));
    c->n_peer_updates = 0;   /* used by this round, or void if it fails */
    if (!next || !mytx || !ptx) goto out;

    rc = CU_ERR_PROTOCOL;
    if (m->n != nn || nu == 0) goto fail;
    cu_digest(ups, nu, digest);
    rc = CU_ERR_VERIFY;
    if (memcmp(digest, m->digest, 32) != 0) goto fail;
    rc = cu_apply(&c->cfg, c->ops, c->ops_ctx, c->tip, CU_OTHER(c->cfg.side), &c->st, ups, nu, next);
    if (rc != CU_OK) goto fail;
    rc = CU_ERR_PROTOCOL;
    if (!build_for(c, c->cfg.side, nn, next, mytx, &mylen, mytxid)) goto fail;
    rc = CU_ERR_VERIFY;
    if (!c->ops->verify_aggregate(c->ops_ctx, nn, mytx, mylen, m->psig, m->nonce_index, sig)) goto fail;
    rc = CU_ERR_PROTOCOL;
    if (!build_for(c, CU_OTHER(c->cfg.side), nn, next, ptx, &plen, ptxid)) goto fail;
    if (signed_get(c->db, &c->cfg, nn, old) && memcmp(old, ptxid, 32) != 0) goto fail;
    rc = CU_ERR_VERIFY;
    if (!c->ops->sign_peer(c->ops_ctx, nn, ptx, plen, psig, &idx)) goto fail;

    cu_rec_t r = c->rec;
    r.phase = CU_PHASE_HOLDS;
    r.round_role = CU_RESPONDER;
    r.held = nn;
    r.revoked = (int64_t)n;
    r.n_round = nu;
    memcpy(r.round, ups, nu * sizeof(cu_update_t));
    memcpy(r.digest, digest, 32);

    /* The member's offers this round carries are settled by it. */
    cu_update_t left[CU_MAX_UPDATES];
    size_t n_left = 0;
    for (size_t i = 0; i < c->n_offered; i++)
        if (find_update(ups, nu, &c->offered[i]) < 0) left[n_left++] = c->offered[i];

    rc = txn_begin(c);
    if (rc != CU_OK) goto out;
    int ok = commitment_put(c->db, &c->cfg, nn, next, mytx, mylen, sig)
          && signed_put(c->db, &c->cfg, nn, ptxid)
          && secret_ensure(c->db, c->cfg.channel_id, nn + 1, s2)
          && secret_release(c->db, c->cfg.channel_id, n)
          && commitment_drop_sig(c->db, &c->cfg, n)
          && (n_left == c->n_offered || offers_store(c->db, c->cfg.channel_id, left, n_left))
          && rec_store(c->db, &c->cfg, &r);
    memset(s2, 0, 32);
    if (!ok) { rc = txn_abort(c, CU_ERR_DB); goto out; }
    rc = txn_finish(c, CU_CP_RESP_HOLDS_BEFORE, CU_CP_RESP_HOLDS_AFTER, "cu_resp_holds");
    if (rc != CU_OK) goto out;

    cu_state_t *prev = malloc(sizeof(*prev));
    if (prev) *prev = c->st;
    c->rec = r;
    c->st = *next;
    memcpy(c->offered, left, n_left * sizeof(cu_update_t));
    c->n_offered = n_left;
    if (prev) { events_holds(c, prev, ups, nu, nn); free(prev); }

    cu_msg_t cs;
    memset(&cs, 0, sizeof(cs));
    cs.type = CU_MSG_COMMIT_SIG;
    cs.n = nn;
    memcpy(cs.psig, psig, 32);
    cs.nonce_index = idx;
    memcpy(cs.digest, digest, 32);
    rc = out_push(c, &cs);
    if (rc == CU_OK) {
        cu_msg_t ra;
        rc = raa_msg(c, n, &ra) ? out_push(c, &ra) : CU_ERR_DB;
    }
    goto out;
fail:
    send_error(c, rc);
out:
    free(next); free(mytx); free(ptx);
    return rc;
}

/* ---- proposer: the responder's commitment_signed ---- */

static int proposer_cs(cu_chan_t *c, const cu_msg_t *m) {
    uint64_t nn = c->rec.held + 1;
    cu_state_t *next = malloc(sizeof(*next));
    unsigned char *tx = malloc(CU_TX_MAX);
    unsigned char txid[32];
    size_t len;
    int rc = CU_ERR_DB;
    if (!next || !tx) goto out;
    rc = CU_ERR_PROTOCOL;
    if (m->n != nn || c->have_peer_cs) goto fail;
    rc = rebuild_round(c, next);
    if (rc != CU_OK) goto fail;
    rc = CU_ERR_PROTOCOL;
    if (!build_for(c, c->cfg.side, nn, next, tx, &len, txid)) goto fail;
    rc = CU_ERR_VERIFY;
    if (!c->ops->verify_aggregate(c->ops_ctx, nn, tx, len, m->psig, m->nonce_index, c->peer_cs_sig))
        goto fail;
    c->have_peer_cs = 1;
    rc = CU_OK;
    goto out;
fail:
    send_error(c, rc);
out:
    free(next); free(tx);
    return rc;
}

static int finish_done(cu_chan_t *c, int before, int after, const char *name) {
    cu_rec_t r = c->rec;
    cu_update_t ups[CU_MAX_UPDATES];
    size_t nu = r.n_round;
    memcpy(ups, r.round, nu * sizeof(cu_update_t));
    r.phase = CU_PHASE_IDLE;
    r.round_role = CU_PROPOSER;
    r.n_round = 0;
    memset(r.digest, 0, 32);
    int rc = txn_begin(c);
    if (rc != CU_OK) return rc;
    if (!rec_store(c->db, &c->cfg, &r)) return txn_abort(c, CU_ERR_DB);
    rc = txn_finish(c, before, after, name);
    if (rc != CU_OK) return rc;
    c->rec = r;
    events_done(c, ups, nu, r.held);
    return CU_OK;
}

/* ---- proposer: the responder's revoke_and_ack ---- */

static int proposer_raa(cu_chan_t *c, const cu_msg_t *m) {
    uint64_t n = c->rec.held, nn = n + 1;
    cu_state_t *next = malloc(sizeof(*next));
    unsigned char *tx = malloc(CU_TX_MAX);
    unsigned char txid[32];
    size_t len;
    int rc = CU_ERR_DB;
    if (!next || !tx) goto out;
    rc = CU_ERR_PROTOCOL;
    if (!c->have_peer_cs || m->n != n || !valid_point(c, m->next_point)) goto fail;
    rc = CU_ERR_VERIFY;
    if (!verify_peer_secret(c, n, m->secret)) goto fail;
    rc = rebuild_round(c, next);
    if (rc != CU_OK) goto fail;
    rc = CU_ERR_PROTOCOL;
    if (!build_for(c, c->cfg.side, nn, next, tx, &len, txid)) goto fail;

    cu_rec_t r = c->rec;
    r.phase = CU_PHASE_HOLDS;
    r.round_role = CU_PROPOSER;
    r.held = nn;
    r.revoked = (int64_t)n;
    r.peer_revoked = (int64_t)n;

    rc = txn_begin(c);
    if (rc != CU_OK) goto out;
    int ok = commitment_put(c->db, &c->cfg, nn, next, tx, len, c->peer_cs_sig)
          && store_peer_revocation(c, n, &c->st, m->secret, m->next_point)
          && secret_release(c->db, c->cfg.channel_id, n)
          && commitment_drop_sig(c->db, &c->cfg, n)
          && rec_store(c->db, &c->cfg, &r);
    if (!ok) { rc = txn_abort(c, CU_ERR_DB); goto fail; }
    rc = txn_finish(c, CU_CP_PROP_HOLDS_BEFORE, CU_CP_PROP_HOLDS_AFTER, "cu_prop_holds");
    if (rc != CU_OK) goto out;

    cu_state_t *prev = malloc(sizeof(*prev));
    if (prev) *prev = c->st;
    c->rec = r;
    c->st = *next;
    c->have_peer_cs = 0;
    if (prev) { events_holds(c, prev, r.round, r.n_round, nn); free(prev); }

    cu_msg_t ra;
    rc = raa_msg(c, n, &ra) ? out_push(c, &ra) : CU_ERR_DB;
    if (rc == CU_OK)
        rc = finish_done(c, CU_CP_PROP_DONE_BEFORE, CU_CP_PROP_DONE_AFTER, "cu_prop_done");
    goto out;
fail:
    send_error(c, rc);
out:
    free(next); free(tx);
    return rc;
}

/* ---- responder: the proposer's revoke_and_ack ---- */

static int responder_raa(cu_chan_t *c, const cu_msg_t *m) {
    cu_state_t *prev = malloc(sizeof(*prev));
    uint64_t n = c->rec.held ? c->rec.held - 1 : 0;
    int rc = CU_ERR_DB;
    if (!prev) return rc;
    rc = CU_ERR_PROTOCOL;
    if (c->rec.held == 0 || m->n != n || !valid_point(c, m->next_point)) goto fail;
    rc = CU_ERR_VERIFY;
    if (!verify_peer_secret(c, n, m->secret)) goto fail;
    rc = CU_ERR_DB;
    if (!commitment_get(c->db, &c->cfg, n, prev, NULL, NULL, NULL)) goto fail;

    /* One transaction: the secret, the next point, the penalty and DONE. */
    cu_rec_t d = c->rec;
    cu_update_t ups[CU_MAX_UPDATES];
    size_t nu = d.n_round;
    memcpy(ups, d.round, nu * sizeof(cu_update_t));
    d.peer_revoked = (int64_t)n;
    d.phase = CU_PHASE_IDLE;
    d.round_role = CU_PROPOSER;
    d.n_round = 0;
    memset(d.digest, 0, 32);
    rc = txn_begin(c);
    if (rc != CU_OK) goto out;
    if (!store_peer_revocation(c, n, prev, m->secret, m->next_point)
        || !rec_store(c->db, &c->cfg, &d)) {
        rc = txn_abort(c, CU_ERR_DB);
        goto fail;
    }
    rc = txn_finish(c, CU_CP_RESP_DONE_BEFORE, CU_CP_RESP_DONE_AFTER, "cu_resp_done");
    if (rc != CU_OK) goto out;
    c->rec = d;
    events_done(c, ups, nu, d.held);
    goto out;
fail:
    send_error(c, rc);
out:
    free(prev);
    return rc;
}

/* The member's own proposal lost to the host's (protocol 6.2 row 12). */
static int drop_sent(cu_chan_t *c) {
    cu_state_t *next = malloc(sizeof(*next));
    unsigned char *tx = malloc(CU_TX_MAX);
    unsigned char txid[32];
    size_t len = 0;
    int rc = CU_ERR_DB;
    if (!next || !tx) goto out;
    uint64_t nn = c->rec.held + 1;
    int have_tx = rebuild_round(c, next) == CU_OK
               && build_for(c, CU_OTHER(c->cfg.side), nn, next, tx, &len, txid);
    cu_rec_t r = c->rec;
    cu_update_t ups[CU_MAX_UPDATES];
    size_t nu = r.n_round;
    memcpy(ups, r.round, nu * sizeof(cu_update_t));
    r.phase = CU_PHASE_IDLE;
    r.n_round = 0;
    memset(r.digest, 0, 32);
    rc = txn_begin(c);
    if (rc != CU_OK) goto out;
    int ok = (!have_tx || signed_void(c->db, &c->cfg, nn, tx, len))
          && rec_store(c->db, &c->cfg, &r);
    if (!ok) { rc = txn_abort(c, CU_ERR_DB); goto out; }
    if (!persist_commit(c->db)) { rc = txn_abort(c, CU_ERR_DB); goto out; }
    c->rec = r;
    c->have_peer_cs = 0;
    for (size_t i = 0; i < nu; i++) {
        cu_event_t e;
        memset(&e, 0, sizeof(e));
        e.type = CU_EV_PROPOSAL_DROPPED;
        e.n = nn;
        e.upd = ups[i];
        ev_push(c, &e);
    }
    rc = CU_OK;
out:
    free(next); free(tx);
    return rc;
}

/* ---- dispatch and queueing ---- */

static int would_defer(const cu_chan_t *c, const cu_msg_t *m) {
    switch (m->type) {
    case CU_MSG_ADD: case CU_MSG_FULFILL: case CU_MSG_FAIL: case CU_MSG_FEE:
        return c->rec.phase != CU_PHASE_IDLE;
    case CU_MSG_COMMIT_SIG:
        return c->rec.phase == CU_PHASE_HOLDS;
    default:
        return 0;
    }
}

static int defer(cu_chan_t *c, const cu_msg_t *m) {
    if (c->n_deferred >= CU_QUEUE_CAP) {
        send_error(c, CU_ERR_QUEUE_FULL);
        return CU_ERR_QUEUE_FULL;
    }
    c->deferred[c->n_deferred++] = *m;
    return CU_OK;
}

static int dispatch(cu_chan_t *c, const cu_msg_t *m);

static int drain_deferred(cu_chan_t *c) {
    while (c->n_deferred > 0 && !would_defer(c, &c->deferred[0])) {
        cu_msg_t m = c->deferred[0];
        memmove(&c->deferred[0], &c->deferred[1], (c->n_deferred - 1) * sizeof(cu_msg_t));
        c->n_deferred--;
        int rc = dispatch(c, &m);
        if (rc != CU_OK) return rc;
    }
    return CU_OK;
}

static int refuse_msg(cu_chan_t *c, const cu_update_t *u, int32_t reason) {
    cu_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = CU_MSG_REFUSE;
    m.upd = *u;
    m.code = reason;
    return out_push(c, &m);
}

static int peer_update(cu_chan_t *c, const cu_msg_t *m) {
    if (c->n_peer_updates >= CU_MAX_UPDATES) {
        send_error(c, CU_ERR_QUEUE_FULL);
        return CU_ERR_QUEUE_FULL;
    }
    cu_update_t u = m->upd;
    if (msg_type_of(u.kind) != m->type) {
        send_error(c, CU_ERR_PROTOCOL);
        return CU_ERR_PROTOCOL;
    }
    if (c->cfg.side == CU_HOST) {
        /* A member request.  INV-28: it acts for the member, whatever the
           message says. */
        u.sender = CU_MEMBER;
        /* Offered again after a reconnect: once is enough. */
        if (find_update(c->peer_updates, c->n_peer_updates, &u) >= 0) return CU_OK;
        cu_update_t all[CU_MAX_UPDATES];
        memcpy(all, c->peer_updates, c->n_peer_updates * sizeof(cu_update_t));
        all[c->n_peer_updates] = u;
        cu_state_t *chk = malloc(sizeof(*chk));
        if (!chk) return CU_ERR_DB;
        int rc = cu_apply(&c->cfg, c->ops, c->ops_ctx, c->tip, CU_MEMBER, &c->st,
                          all, c->n_peer_updates + 1, chk);
        free(chk);
        if (rc != CU_OK) return refuse_msg(c, &u, rc);
    } else {
        /* An update of the host's round.  One that acts for the member must
           be one of the member's own offers. */
        if (u.sender == CU_MEMBER) {
            if (find_update(c->offered, c->n_offered, &u) < 0) {
                send_error(c, CU_ERR_PROTOCOL);
                return CU_ERR_PROTOCOL;
            }
        } else if (u.sender != CU_HOST) {
            send_error(c, CU_ERR_PROTOCOL);
            return CU_ERR_PROTOCOL;
        }
    }
    c->peer_updates[c->n_peer_updates++] = u;
    cu_event_t e;
    memset(&e, 0, sizeof(e));
    e.type = CU_EV_UPDATE_RECEIVED;
    e.upd = u;
    ev_push(c, &e);
    return CU_OK;
}

static int on_commit_sig(cu_chan_t *c, const cu_msg_t *m) {
    /* Only the host opens a round: a member signature that does not answer
       the host's open round is refused. */
    if (c->cfg.side == CU_HOST
        && (c->rec.phase != CU_PHASE_SENT || memcmp(m->digest, c->rec.digest, 32) != 0)) {
        send_error(c, CU_ERR_ROLE);
        return CU_ERR_ROLE;
    }
    if (c->rec.phase == CU_PHASE_IDLE) return responder_cs(c, m);
    /* phase SENT */
    if (memcmp(m->digest, c->rec.digest, 32) == 0) return proposer_cs(c, m);
    /* Both proposed at once.  Unreachable while only the host opens rounds;
       kept so the alternative stays defined: the host's round wins. */
    if (c->cfg.side == CU_HOST) {
        size_t k = 0;
        for (size_t i = 0; i < c->n_deferred; i++)
            if (c->deferred[i].type == CU_MSG_COMMIT_SIG || c->deferred[i].type == CU_MSG_REVOKE
                || c->deferred[i].type == CU_MSG_REFUSE)
                c->deferred[k++] = c->deferred[i];
        c->n_deferred = k;
        c->n_peer_updates = 0;
        if (c->ops->skip_signature) c->ops->skip_signature(c->ops_ctx, m->nonce_index);
        return CU_OK;
    }
    int rc = drop_sent(c);
    if (rc != CU_OK) return rc;
    rc = drain_deferred(c);
    if (rc != CU_OK) return rc;
    return responder_cs(c, m);
}

/* Member: the host refused one of its offers. */
static int on_refuse(cu_chan_t *c, const cu_msg_t *m) {
    if (c->cfg.side != CU_MEMBER) {
        send_error(c, CU_ERR_PROTOCOL);
        return CU_ERR_PROTOCOL;
    }
    cu_update_t u = m->upd;
    u.sender = CU_MEMBER;
    long k = find_update(c->offered, c->n_offered, &u);
    /* A refusal of an offer already settled (offered again after a
       reconnect) changes nothing. */
    if (k < 0) return CU_OK;
    cu_update_t left[CU_MAX_UPDATES];
    size_t n_left = 0;
    for (size_t i = 0; i < c->n_offered; i++) if ((long)i != k) left[n_left++] = c->offered[i];
    int rc = txn_begin(c);
    if (rc != CU_OK) return rc;
    if (!offers_store(c->db, c->cfg.channel_id, left, n_left)) return txn_abort(c, CU_ERR_DB);
    if (!persist_commit(c->db)) return txn_abort(c, CU_ERR_DB);
    cu_event_t e;
    memset(&e, 0, sizeof(e));
    e.type = CU_EV_REFUSED;
    e.upd = c->offered[k];
    e.code = m->code;
    memcpy(c->offered, left, n_left * sizeof(cu_update_t));
    c->n_offered = n_left;
    ev_push(c, &e);
    return CU_OK;
}

static int on_reestablish(cu_chan_t *c, const cu_reestablish_t *re);

static int dispatch(cu_chan_t *c, const cu_msg_t *m) {
    if (m->type != CU_MSG_ERROR && c->rec.halted) return CU_ERR_HALTED;
    if (m->type != CU_MSG_REESTABLISH && m->type != CU_MSG_ERROR && would_defer(c, m))
        return defer(c, m);
    int rc;
    switch (m->type) {
    case CU_MSG_ADD: case CU_MSG_FULFILL: case CU_MSG_FAIL: case CU_MSG_FEE:
        return peer_update(c, m);
    case CU_MSG_COMMIT_SIG:
        rc = on_commit_sig(c, m);
        break;
    case CU_MSG_REVOKE:
        if (c->rec.phase == CU_PHASE_SENT && c->rec.round_role == CU_PROPOSER)
            rc = proposer_raa(c, m);
        else if (c->rec.phase == CU_PHASE_HOLDS && c->rec.round_role == CU_RESPONDER)
            rc = responder_raa(c, m);
        else {
            send_error(c, CU_ERR_PROTOCOL);
            rc = CU_ERR_PROTOCOL;
        }
        break;
    case CU_MSG_REFUSE:
        return on_refuse(c, m);
    case CU_MSG_REESTABLISH:
        rc = on_reestablish(c, &m->re);
        break;
    case CU_MSG_ERROR:
        ev_simple(c, CU_EV_PEER_ERROR, c->rec.held, m->code);
        return CU_OK;
    default:
        send_error(c, CU_ERR_PROTOCOL);
        return CU_ERR_PROTOCOL;
    }
    if (rc != CU_OK) return rc;
    return drain_deferred(c);
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

int cu_create(persist_t *db, const cu_config_t *cfg, const cu_state_t *initial,
              const unsigned char my_s0[32], const unsigned char my_s1[32],
              const secp256k1_pubkey *peer_p0, const secp256k1_pubkey *peer_p1,
              const unsigned char *my_c0_tx, size_t my_c0_len,
              const unsigned char my_c0_sig[64],
              const unsigned char peer_c0_txid[32]) {
    if (!db || !db->db || !cfg || !initial || !my_s0 || !my_s1 || !peer_p0 || !peer_p1
        || !my_c0_tx || !my_c0_sig || !peer_c0_txid)
        return CU_ERR_ARG;
    if (persist_in_transaction(db)) return CU_ERR_DB;
    if (!conserves(initial, cfg->capacity_msat) || cfg->max_htlcs > CU_HTLC_CAP)
        return CU_ERR_INVALID;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    unsigned char p0[33], p1[33];
    size_t l0 = 33, l1 = 33;
    int ok = ctx
          && secp256k1_ec_pubkey_serialize(ctx, p0, &l0, peer_p0, SECP256K1_EC_COMPRESSED)
          && secp256k1_ec_pubkey_serialize(ctx, p1, &l1, peer_p1, SECP256K1_EC_COMPRESSED);
    if (ctx) secp256k1_context_destroy(ctx);
    if (!ok) return CU_ERR_ARG;

    cu_rec_t r;
    memset(&r, 0, sizeof(r));
    r.revoked = -1;
    r.peer_revoked = -1;
    if (!persist_begin(db)) return CU_ERR_DB;
    ok = rec_store(db, cfg, &r)
      && commitment_put(db, cfg, 0, initial, my_c0_tx, my_c0_len, my_c0_sig)
      && signed_put(db, cfg, 0, peer_c0_txid)
      && secret_insert(db, cfg->channel_id, 0, my_s0)
      && secret_insert(db, cfg->channel_id, 1, my_s1)
      && peer_point_put(db, cfg->channel_id, 0, p0)
      && peer_point_put(db, cfg->channel_id, 1, p1);
    if (!ok) { persist_rollback(db); return CU_ERR_DB; }
    if (!persist_commit(db)) { persist_rollback(db); return CU_ERR_DB; }
    return CU_OK;
}

int cu_load(cu_chan_t *c, persist_t *db, const cu_config_t *cfg,
            const cu_ops_t *ops, void *ops_ctx, secp256k1_context *secp) {
    if (!c || !db || !db->db || !cfg || !ops || !secp) return CU_ERR_ARG;
    if (cfg->max_htlcs > CU_HTLC_CAP) return CU_ERR_ARG;
    memset(c, 0, sizeof(*c));
    c->cfg = *cfg;
    c->ops = ops;
    c->ops_ctx = ops_ctx;
    c->db = db;
    c->secp = secp;
    if (!rec_load(db, cfg, &c->rec)) return CU_ERR_DB;
    if (!commitment_get(db, cfg, c->rec.held, &c->st, NULL, NULL, NULL)) return CU_ERR_DB;
    if (!conserves(&c->st, cfg->capacity_msat)) return CU_ERR_DB;
    if (cfg->side == CU_MEMBER && !offers_load(db, cfg->channel_id, c->offered, &c->n_offered))
        return CU_ERR_DB;
    return CU_OK;
}

int cu_propose(cu_chan_t *c, const cu_update_t *u, size_t n) {
    if (!c || !u) return CU_ERR_ARG;
    return round_start(c, u, n);
}

int cu_offer(cu_chan_t *c, const cu_update_t *u, size_t n) {
    if (!c || !u || n == 0) return CU_ERR_ARG;
    if (c->cfg.side != CU_MEMBER) return CU_ERR_ROLE;
    if (c->rec.halted) return CU_ERR_HALTED;
    if (persist_in_transaction(c->db)) return CU_ERR_DB;
    if (c->n_offered + n > CU_MAX_UPDATES) return CU_ERR_BUSY;
    /* A preimage leaves only once the host's revocation of every earlier
       commitment is stored: the host can then close only on a commitment
       that already pays the member. */
    for (size_t i = 0; i < n; i++)
        if (u[i].kind == CU_UPD_FULFILL
            && (c->rec.phase != CU_PHASE_IDLE || c->rec.peer_revoked + 1 != (int64_t)c->rec.held))
            return CU_ERR_BUSY;
    cu_update_t all[CU_MAX_UPDATES];
    memcpy(all, c->offered, c->n_offered * sizeof(cu_update_t));
    for (size_t i = 0; i < n; i++) {
        all[c->n_offered + i] = u[i];
        all[c->n_offered + i].sender = CU_MEMBER;
    }
    cu_state_t *chk = malloc(sizeof(*chk));
    if (!chk) return CU_ERR_DB;
    int rc = cu_apply(&c->cfg, c->ops, c->ops_ctx, c->tip, CU_MEMBER, &c->st,
                      all, c->n_offered + n, chk);
    free(chk);
    if (rc != CU_OK) return rc;
    rc = txn_begin(c);
    if (rc != CU_OK) return rc;
    int ok = offers_store(c->db, c->cfg.channel_id, all, c->n_offered + n);
    /* INV-30: a fulfil's claim is armed before its preimage leaves. */
    for (size_t i = c->n_offered; ok && i < c->n_offered + n; i++) {
        if (all[i].kind != CU_UPD_FULFILL) continue;
        long k = find_htlc(&c->st, CU_HOST, all[i].id);
        ok = k >= 0 && c->ops->arm_claim(c->ops_ctx, c->db, c->rec.held + 1,
                                         &c->st.htlcs[k], all[i].preimage) == 1;
    }
    if (!ok) return txn_abort(c, CU_ERR_DB);
    rc = txn_finish(c, CU_CP_OFFER_BEFORE, CU_CP_OFFER_AFTER, "cu_offer");
    if (rc != CU_OK) return rc;
    size_t first = c->n_offered;
    memcpy(c->offered, all, (first + n) * sizeof(cu_update_t));
    c->n_offered = first + n;
    return push_updates(c, &c->offered[first], n);
}

const cu_update_t *cu_requests(const cu_chan_t *c, size_t *n) {
    if (!c || !n) return NULL;
    *n = c->cfg.side == CU_HOST ? c->n_peer_updates : 0;
    return c->peer_updates;
}

int cu_refuse(cu_chan_t *c, uint8_t kind, uint64_t id, int32_t reason) {
    if (!c) return CU_ERR_ARG;
    if (c->cfg.side != CU_HOST) return CU_ERR_ROLE;
    for (size_t i = 0; i < c->n_peer_updates; i++) {
        if (c->peer_updates[i].kind == kind && c->peer_updates[i].id == id) {
            cu_update_t u = c->peer_updates[i];
            memmove(&c->peer_updates[i], &c->peer_updates[i + 1],
                    (c->n_peer_updates - i - 1) * sizeof(cu_update_t));
            c->n_peer_updates--;
            return refuse_msg(c, &u, reason);
        }
    }
    return CU_ERR_ARG;
}

int cu_on_message(cu_chan_t *c, const cu_msg_t *m) {
    if (!c || !m) return CU_ERR_ARG;
    if (m->channel_id != c->cfg.channel_id) return CU_ERR_ARG;
    /* INV-75: every write is opened and committed inside this call. */
    if (persist_in_transaction(c->db)) return CU_ERR_DB;
    return dispatch(c, m);
}

void cu_on_disconnect(cu_chan_t *c) {
    if (!c) return;
    c->n_peer_updates = 0;
    if (c->cfg.side == CU_HOST) c->n_offered = 0;   /* the member's offers are durable */
    c->have_peer_cs = 0;
    c->n_deferred = 0;
    c->n_out = 0;
    if (c->ops->reset_nonces) c->ops->reset_nonces(c->ops_ctx);
}

int cu_reestablish_msg(cu_chan_t *c, cu_msg_t *out) {
    if (!c || !out) return CU_ERR_ARG;
    memset(out, 0, sizeof(*out));
    out->type = CU_MSG_REESTABLISH;
    out->channel_id = c->cfg.channel_id;
    out->re.next_commitment_number = c->rec.held + 1;
    out->re.next_revocation_number = (uint64_t)(c->rec.revoked + 1);
    if (c->rec.peer_revoked >= 0
        && !peer_secret_get(c->db, c->cfg.channel_id, (uint64_t)c->rec.peer_revoked,
                            out->re.last_remote_secret))
        return CU_ERR_DB;
    if (!my_point_ser(c, c->rec.held, out->re.my_current_point)) return CU_ERR_DB;
    if (c->rec.phase == CU_PHASE_SENT) memcpy(out->re.sent_digest, c->rec.digest, 32);
    return CU_OK;
}

int cu_view(cu_chan_t *c, cu_view_t *v) {
    if (!c || !v) return CU_ERR_ARG;
    memset(v, 0, sizeof(*v));
    v->side = c->cfg.side;
    v->phase = c->rec.phase;
    v->round_role = c->rec.round_role;
    v->held = c->rec.held;
    v->revoked = c->rec.revoked;
    v->peer_revoked = c->rec.peer_revoked;
    memcpy(v->digest, c->rec.digest, 32);
    if (!signed_max(c->db, &c->cfg, &v->signed_max)) return CU_ERR_DB;
    for (int64_t k = c->rec.revoked - 3; k <= c->rec.revoked + 4 && v->n_secrets < CU_VIEW_SECRETS; k++) {
        if (k < 0) continue;
        if (secret_get(c->db, c->cfg.channel_id, (uint64_t)k, v->secret[v->n_secrets], NULL))
            v->secret_num[v->n_secrets++] = k;
    }
    return CU_OK;
}

cu_reconcile_t cu_reconcile(const cu_view_t *v, const cu_reestablish_t *p) {
    cu_reconcile_t r = { 0, CU_ACT_FAIL };
    if (!v || !p) return r;
    if (p->next_commitment_number == 0 || p->next_commitment_number > (uint64_t)INT64_MAX
        || p->next_revocation_number > (uint64_t)INT64_MAX)
        return r;
    int64_t Hp = (int64_t)p->next_commitment_number - 1;
    int64_t Vp = (int64_t)p->next_revocation_number - 1;
    int64_t H = (int64_t)v->held, V = v->revoked;

    /* Name the newest secret of mine the peer holds. */
    int64_t rnum = -2;
    if (is_zero(p->last_remote_secret, 32)) rnum = -1;
    else
        for (size_t i = 0; i < v->n_secrets; i++)
            if (memcmp(v->secret[i], p->last_remote_secret, 32) == 0) rnum = v->secret_num[i];
    /* Row 9 first: a side that lost data must not act on anything else. */
    if (rnum > V) { r.row = 9; r.actions = CU_ACT_DATA_LOSS; return r; }
    if (Vp < v->peer_revoked) { r.row = 10; r.actions = CU_ACT_PEER_LOST; return r; }
    if (rnum == -2) return r;                                             /* unverifiable claim */
    if (rnum < V - 1) { r.row = 10; r.actions = CU_ACT_PEER_LOST; return r; }
    if (Hp > (int64_t)v->signed_max) { r.row = 8; r.actions = CU_ACT_FAIL; return r; }
    if (Vp != Hp - 1) return r;
    if (Hp < H - 1 || Hp > H + 1) { r.row = 11; r.actions = CU_ACT_FAIL; return r; }

    int lacks = V >= 0 && rnum == V - 1;          /* my newest revocation did not arrive */
    int peer_sent = !is_zero(p->sent_digest, 32);
    int same_digest = memcmp(p->sent_digest, v->digest, 32) == 0;

    if (v->phase == CU_PHASE_IDLE) {
        if (Hp != H) return r;
        if (lacks) { r.row = 5; r.actions = CU_ACT_RESEND_RAA | (peer_sent ? CU_ACT_WAIT : 0); return r; }
        r.row = 1;
        r.actions = peer_sent ? CU_ACT_WAIT : CU_ACT_NONE;
        return r;
    }
    if (v->phase == CU_PHASE_SENT) {
        unsigned extra = lacks ? CU_ACT_RESEND_RAA : 0;
        if (Hp == H) {
            if (!peer_sent || same_digest) { r.row = 2; r.actions = extra | CU_ACT_RESEND_ROUND; return r; }
            r.row = 12;
            r.actions = extra | (v->side == CU_HOST ? CU_ACT_RESEND_ROUND : (CU_ACT_DROP_SENT | CU_ACT_WAIT));
            return r;
        }
        if (Hp == H + 1 && !lacks) { r.row = 3; r.actions = CU_ACT_WAIT; return r; }
        return r;
    }
    if (v->round_role == CU_RESPONDER) {               /* HOLDS(H) as responder */
        if (Hp == H - 1) {
            if (peer_sent && same_digest) { r.row = 4; r.actions = CU_ACT_RESEND_CS | CU_ACT_RESEND_RAA; return r; }
            if (!peer_sent) { r.row = 10; r.actions = CU_ACT_PEER_LOST; return r; }
            return r;
        }
        if (Hp == H) { r.row = 6; r.actions = CU_ACT_WAIT; return r; }
        return r;
    }
    /* HOLDS(H) as proposer */
    if (Hp != H) return r;
    if (lacks) { r.row = 5; r.actions = CU_ACT_RESEND_RAA | CU_ACT_MARK_DONE; return r; }
    r.row = 7;
    r.actions = CU_ACT_MARK_DONE;
    return r;
}

static int resend_round(cu_chan_t *c) {
    cu_state_t *next = malloc(sizeof(*next));
    unsigned char *tx = malloc(CU_TX_MAX);
    unsigned char txid[32], want[32], psig[32];
    size_t len;
    uint32_t idx = 0;
    uint64_t nn = c->rec.held + 1;
    int rc = CU_ERR_DB;
    if (!next || !tx) goto out;
    rc = rebuild_round(c, next);
    if (rc != CU_OK) goto out;
    rc = CU_ERR_PROTOCOL;
    if (!build_for(c, CU_OTHER(c->cfg.side), nn, next, tx, &len, txid)) goto out;
    /* INV-20: the retransmission signs the same bytes. */
    if (!signed_get(c->db, &c->cfg, nn, want) || memcmp(want, txid, 32) != 0) goto out;
    rc = CU_ERR_VERIFY;
    if (!c->ops->sign_peer(c->ops_ctx, nn, tx, len, psig, &idx)) goto out;
    rc = push_updates(c, c->rec.round, c->rec.n_round);
    if (rc != CU_OK) goto out;
    cu_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = CU_MSG_COMMIT_SIG;
    m.n = nn;
    memcpy(m.psig, psig, 32);
    m.nonce_index = idx;
    memcpy(m.digest, c->rec.digest, 32);
    rc = out_push(c, &m);
out:
    free(next); free(tx);
    return rc;
}

static int resend_cs(cu_chan_t *c) {
    unsigned char *tx = malloc(CU_TX_MAX);
    unsigned char txid[32], want[32], psig[32];
    size_t len;
    uint32_t idx = 0;
    int rc = CU_ERR_PROTOCOL;
    if (!tx) return CU_ERR_DB;
    if (!build_for(c, CU_OTHER(c->cfg.side), c->rec.held, &c->st, tx, &len, txid)) goto out;
    if (!signed_get(c->db, &c->cfg, c->rec.held, want) || memcmp(want, txid, 32) != 0) goto out;
    rc = CU_ERR_VERIFY;
    if (!c->ops->sign_peer(c->ops_ctx, c->rec.held, tx, len, psig, &idx)) goto out;
    cu_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = CU_MSG_COMMIT_SIG;
    m.n = c->rec.held;
    memcpy(m.psig, psig, 32);
    m.nonce_index = idx;
    memcpy(m.digest, c->rec.digest, 32);
    rc = out_push(c, &m);
out:
    free(tx);
    return rc;
}

static int on_reestablish(cu_chan_t *c, const cu_reestablish_t *re) {
    cu_view_t v;
    int rc = cu_view(c, &v);
    if (rc != CU_OK) return rc;
    cu_reconcile_t r = cu_reconcile(&v, re);
    unsigned a = r.actions;
    if (a & CU_ACT_DATA_LOSS) return halt(c, CU_HALT_DATA_LOSS);
    if (a & CU_ACT_PEER_LOST) return halt(c, CU_HALT_PEER_LOST);
    if (a & CU_ACT_FAIL) return halt(c, CU_HALT_FAILED);
    if (a & CU_ACT_RESEND_CS) {
        rc = resend_cs(c);
        if (rc != CU_OK) return rc;
    }
    if (a & CU_ACT_RESEND_RAA) {
        cu_msg_t m;
        uint64_t nrev = c->rec.revoked >= 0 ? (uint64_t)c->rec.revoked : 0;
        if (!raa_msg(c, nrev, &m)) return CU_ERR_DB;
        rc = out_push(c, &m);
        if (rc != CU_OK) return rc;
    }
    if (a & CU_ACT_DROP_SENT) {
        rc = drop_sent(c);
        if (rc != CU_OK) return rc;
    }
    if (a & CU_ACT_RESEND_ROUND) {
        rc = resend_round(c);
        if (rc != CU_OK) return rc;
    }
    if (a & CU_ACT_MARK_DONE) {
        rc = finish_done(c, CU_CP_PROP_DONE_BEFORE, CU_CP_PROP_DONE_AFTER, "cu_prop_done");
        if (rc != CU_OK) return rc;
    }
    /* The host keeps no requests across a connection: offer them again. */
    if (c->cfg.side == CU_MEMBER && c->n_offered)
        return push_updates(c, c->offered, c->n_offered);
    return CU_OK;
}

int cu_begin_exit(cu_chan_t *c) {
    if (!c) return CU_ERR_ARG;
    if (persist_in_transaction(c->db)) return CU_ERR_DB;
    if (c->rec.halted == CU_HALT_EXITING) return CU_OK;
    cu_rec_t r = c->rec;
    r.halted = CU_HALT_EXITING;
    int rc = txn_begin(c);
    if (rc != CU_OK) return rc;
    if (!rec_store(c->db, &c->cfg, &r)) return txn_abort(c, CU_ERR_DB);
    if (!persist_commit(c->db)) return txn_abort(c, CU_ERR_DB);
    c->rec = r;
    /* Nothing of this connection leaves after the decision. */
    c->n_out = 0;
    c->n_deferred = 0;
    c->n_peer_updates = 0;
    c->have_peer_cs = 0;
    ev_simple(c, CU_EV_HALTED, c->rec.held, CU_HALT_EXITING);
    return CU_OK;
}

int cu_on_block(cu_chan_t *c, uint32_t height) {
    if (!c) return CU_ERR_ARG;
    c->tip = height;
    int cnt = 0;
    for (size_t i = 0; i < c->st.n_htlcs; i++) {
        const cu_htlc_t *h = &c->st.htlcs[i];
        if ((uint64_t)h->cltv_expiry <= (uint64_t)height + c->cfg.onchain_margin) {
            cu_event_t e;
            memset(&e, 0, sizeof(e));
            e.type = CU_EV_GO_ONCHAIN;
            e.n = c->rec.held;
            e.htlc = *h;
            ev_push(c, &e);
            cnt++;
        }
    }
    return cnt;
}

int cu_latest_commitment(cu_chan_t *c, unsigned char *tx, size_t *tx_len,
                         unsigned char sig64[64], uint64_t *n_out) {
    if (!c || !tx || !tx_len || !sig64) return CU_ERR_ARG;
    if (c->rec.halted == CU_HALT_DATA_LOSS) return CU_ERR_HALTED;
    unsigned char s[32];
    int released = 1;
    /* INV-23 */
    if (!secret_get(c->db, c->cfg.channel_id, c->rec.held, s, &released) || released)
        return CU_ERR_HALTED;
    memset(s, 0, 32);
    if (!commitment_get(c->db, &c->cfg, c->rec.held, NULL, tx, tx_len, sig64)) return CU_ERR_DB;
    if (n_out) *n_out = c->rec.held;
    return CU_OK;
}

int cu_queue_push(cu_queue_t *q, const cu_msg_t *m) {
    if (!q || !m || q->len >= CU_QUEUE_CAP) return 0;
    q->q[(q->head + q->len) % CU_QUEUE_CAP] = *m;
    q->len++;
    return 1;
}

int cu_queue_drain(cu_queue_t *q, cu_chan_t **chans, size_t n_chans) {
    if (!q || (!chans && n_chans)) return CU_ERR_ARG;
    while (q->len > 0) {
        cu_msg_t m = q->q[q->head];
        q->head = (q->head + 1) % CU_QUEUE_CAP;
        q->len--;
        cu_chan_t *c = NULL;
        for (size_t i = 0; i < n_chans; i++)
            if (chans[i] && chans[i]->cfg.channel_id == m.channel_id) c = chans[i];
        if (!c) return CU_ERR_PROTOCOL;
        int rc = cu_on_message(c, &m);
        if (rc != CU_OK) return rc;
    }
    return CU_OK;
}

int cu_check_invariants(persist_t *db, uint32_t channel_id, uint64_t capacity_msat,
                        char *why, size_t why_len) {
#define CU_BAD(...) do { if (why && why_len) snprintf(why, why_len, __VA_ARGS__); ok = 0; goto out; } while (0)
    int ok = 1;
    sqlite3_stmt *st = NULL;
    cu_state_t *s = malloc(sizeof(*s));
    int64_t held = -1, peer_revoked = -1, revoked = -1;
    int phase = 0, n_round_ok = 1;
    if (!s) return 0;
    if (!prep(db, "SELECT held, revoked, peer_revoked, phase, round_updates FROM chan_update_channel"
                  " WHERE channel_id=?;", &st))
        CU_BAD("query channel");
    sqlite3_bind_int64(st, 1, channel_id);
    if (sqlite3_step(st) != SQLITE_ROW) CU_BAD("no channel record");
    held = sqlite3_column_int64(st, 0);
    revoked = sqlite3_column_int64(st, 1);
    peer_revoked = sqlite3_column_int64(st, 2);
    phase = sqlite3_column_int(st, 3);
    {
        cu_update_t u[CU_MAX_UPDATES];
        size_t n = 0;
        n_round_ok = de_round(sqlite3_column_blob(st, 4), (size_t)sqlite3_column_bytes(st, 4), u, &n)
                  && ((phase == CU_PHASE_IDLE) == (n == 0));
    }
    sqlite3_finalize(st); st = NULL;
    if (!n_round_ok) CU_BAD("round record does not match phase %d", phase);
    if (revoked != held - 1) CU_BAD("revoked %lld, held %lld", (long long)revoked, (long long)held);

    /* INV-27 on every stored state. */
    if (!prep(db, "SELECT commit_num, state, length(sig) FROM chan_update_commitment WHERE channel_id=?;", &st))
        CU_BAD("query commitments");
    sqlite3_bind_int64(st, 1, channel_id);
    int have_held = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        int64_t n = sqlite3_column_int64(st, 0);
        if (!de_state(sqlite3_column_blob(st, 1), (size_t)sqlite3_column_bytes(st, 1), s))
            CU_BAD("state %lld unreadable", (long long)n);
        if (!conserves(s, capacity_msat)) CU_BAD("state %lld does not conserve value", (long long)n);
        if (n == held && sqlite3_column_int(st, 2) == 64) have_held = 1;
        if (n > held) CU_BAD("commitment %lld above held %lld", (long long)n, (long long)held);
    }
    sqlite3_finalize(st); st = NULL;
    if (!have_held) CU_BAD("held commitment %lld not stored signed", (long long)held);

    /* INV-23: held number above every released secret. */
    if (!prep(db, "SELECT MAX(commit_num) FROM chan_update_secret WHERE channel_id=? AND released=1;", &st))
        CU_BAD("query secrets");
    sqlite3_bind_int64(st, 1, channel_id);
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL
        && sqlite3_column_int64(st, 0) + 1 > held)
        CU_BAD("secret %lld released while holding %lld", (long long)sqlite3_column_int64(st, 0), (long long)held);
    sqlite3_finalize(st); st = NULL;

    /* INV-20: one signed txid per (channel, number, outpoint), and no gaps. */
    if (!prep(db, "SELECT COUNT(*), COUNT(DISTINCT commit_num || '/' || hex(funding_txid) || '/' || funding_vout),"
                  " MAX(commit_num) FROM chan_update_signed WHERE channel_id=?;", &st))
        CU_BAD("query signed");
    sqlite3_bind_int64(st, 1, channel_id);
    if (sqlite3_step(st) != SQLITE_ROW || sqlite3_column_int64(st, 0) != sqlite3_column_int64(st, 1))
        CU_BAD("two signed commitments for one number");
    if (sqlite3_column_int64(st, 2) < held)
        CU_BAD("held %lld but signed only up to %lld", (long long)held, (long long)sqlite3_column_int64(st, 2));
    sqlite3_finalize(st); st = NULL;

    /* INV-24: every revoked peer number has its secret. */
    if (!prep(db, "SELECT COUNT(*) FROM chan_update_peer_secret WHERE channel_id=? AND commit_num<=?;", &st))
        CU_BAD("query peer secrets");
    sqlite3_bind_int64(st, 1, channel_id);
    sqlite3_bind_int64(st, 2, peer_revoked);
    if (sqlite3_step(st) != SQLITE_ROW || sqlite3_column_int64(st, 0) != peer_revoked + 1)
        CU_BAD("peer revoked %lld but secrets missing", (long long)peer_revoked);
out:
    if (st) sqlite3_finalize(st);
    free(s);
    return ok;
#undef CU_BAD
}
