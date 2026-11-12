/* The channel-update engine's commitment layer over channel_t: see
   include/superscalar/chan_update_ops.h. */

#include "superscalar/chan_update_ops.h"
#include "superscalar/fee.h"
#include "superscalar/persist.h"
#include "superscalar/sha256.h"
#include "superscalar/tx_builder.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- nonces ---- */

static void own_clear(cu_chops_t *o) {
    for (int i = 0; i < 2; i++) {
        memset(&o->own[i].pool, 0, sizeof(o->own[i].pool));   /* secret nonces gone */
        o->own[i].count = 0;
        o->own[i].base = 0;
    }
}

static int own_generate(cu_chops_t *o, int slot, uint32_t base) {
    cu_own_nonces_t *s = &o->own[slot];
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(o->ch->ctx, &pk, o->ch->local_funding_secret)) return 0;
    if (!musig_nonce_pool_generate(o->ch->ctx, &s->pool, CU_NONCE_BATCH,
                                   o->ch->local_funding_secret, &pk,
                                   &o->ch->funding_keyagg.cache))
        return 0;
    s->base = base;
    s->count = CU_NONCE_BATCH;
    return 1;
}

static int own_pub(cu_chops_t *o, int slot, unsigned char pub[][66], size_t *n) {
    cu_own_nonces_t *s = &o->own[slot];
    for (size_t i = 0; i < s->count; i++)
        if (!musig_pubnonce_serialize(o->ch->ctx, pub[i], &s->pool.nonces[i].pubnonce)) return 0;
    *n = s->count;
    return 1;
}

/* Draw this side's secret nonce for index idx: nonces are used in index
   order, each once. */
static secp256k1_musig_secnonce *own_draw(cu_chops_t *o, uint32_t idx,
                                          secp256k1_musig_pubnonce *pub) {
    for (int i = 0; i < 2; i++) {
        cu_own_nonces_t *s = &o->own[i];
        if (!s->count || idx < s->base || idx >= s->base + s->count) continue;
        if (s->pool.next_unused != idx - s->base) return NULL;
        secp256k1_musig_secnonce *sec = NULL;
        if (!musig_nonce_pool_next(&s->pool, &sec, pub)) return NULL;
        return sec;
    }
    return NULL;
}

static const unsigned char *peer_pub(const cu_chops_t *o, uint32_t idx) {
    for (int i = 0; i < 2; i++) {
        const cu_peer_nonces_t *s = &o->peer[i];
        if (s->count && idx >= s->base && idx < s->base + s->count) return s->pub[idx - s->base];
    }
    return NULL;
}

int cu_chops_init(cu_chops_t *o, channel_t *ch, cu_side_t side, uint32_t channel_id,
                  watchtower_t *wt) {
    if (!o || !ch) return 0;
    memset(o, 0, sizeof(*o));
    o->ch = ch;
    o->side = side;
    o->channel_id = channel_id;
    o->wt = wt;
    return 1;
}

int cu_chops_connect(cu_chops_t *o, unsigned char pub[][66], size_t *n) {
    if (!o || !pub || !n) return 0;
    own_clear(o);
    memset(o->peer, 0, sizeof(o->peer));
    o->next = 0;
    o->peer_end = 0;
    if (!own_generate(o, 0, 0)) return 0;
    o->own_end = CU_NONCE_BATCH;
    return own_pub(o, 0, pub, n);
}

int cu_chops_topup(cu_chops_t *o, uint32_t *first, unsigned char pub[][66], size_t *n) {
    if (!o || !first || !pub || !n) return 0;
    *n = 0;
    if (o->own_end - o->next >= CU_NONCE_LOW) return 1;
    /* Replace the slot whose indices are all used. */
    int slot = -1;
    for (int i = 0; i < 2; i++)
        if (!o->own[i].count || o->own[i].base + o->own[i].count <= o->next) slot = i;
    if (slot < 0) return 0;
    if (!own_generate(o, slot, o->own_end)) return 0;
    *first = o->own_end;
    o->own_end += CU_NONCE_BATCH;
    return own_pub(o, slot, pub, n);
}

int cu_chops_peer_nonces(cu_chops_t *o, uint32_t first, const unsigned char pub[][66], size_t n) {
    if (!o || !pub || n == 0 || n > CU_NONCE_BATCH) return 0;
    if (first != o->peer_end) return 0;
    int slot = -1;
    for (int i = 0; i < 2; i++)
        if (!o->peer[i].count || o->peer[i].base + o->peer[i].count <= o->next) slot = i;
    if (slot < 0) return 0;
    for (size_t i = 0; i < n; i++) {
        secp256k1_musig_pubnonce chk;
        if (!musig_pubnonce_parse(o->ch->ctx, &chk, pub[i])) return 0;
        memcpy(o->peer[slot].pub[i], pub[i], 66);
    }
    o->peer[slot].base = first;
    o->peer[slot].count = n;
    o->peer_end = first + (uint32_t)n;
    return 1;
}

/* ---- signing ---- */

static int sighash_of(const cu_chops_t *o, const unsigned char *tx, size_t len,
                      unsigned char out[32]) {
    const channel_t *ch = o->ch;
    return compute_taproot_sighash(out, tx, len, 0, ch->funding_spk, ch->funding_spk_len,
                                   ch->funding_amount, 0xFFFFFFFE);
}

/* One MuSig2 session at index idx: this side's nonce and the peer's. */
static int session_at(cu_chops_t *o, uint32_t idx, const unsigned char *tx, size_t len,
                      musig_signing_session_t *session, secp256k1_musig_secnonce **sec,
                      secp256k1_musig_pubnonce *peer_nonce) {
    unsigned char msg[32];
    secp256k1_musig_pubnonce mine;
    const unsigned char *pp = peer_pub(o, idx);
    if (!pp || !sighash_of(o, tx, len, msg)) return 0;
    if (!musig_pubnonce_parse(o->ch->ctx, peer_nonce, pp)) return 0;
    *sec = own_draw(o, idx, &mine);
    if (!*sec) return 0;
    musig_session_init(session, &o->ch->funding_keyagg, 2);
    int me = o->ch->local_funding_signer_idx;
    musig_session_set_pubnonce(session, (size_t)me, &mine);
    musig_session_set_pubnonce(session, (size_t)(1 - me), peer_nonce);
    const unsigned char *mr = o->ch->has_chan_merkle_root ? o->ch->chan_merkle_root : NULL;
    return musig_session_finalize_nonces(o->ch->ctx, session, msg, mr, NULL);
}

static int op_sign(void *ctx, uint64_t n, const unsigned char *tx, size_t len,
                   unsigned char psig[32], uint32_t *nonce_index) {
    cu_chops_t *o = ctx;
    musig_signing_session_t session;
    secp256k1_musig_secnonce *sec = NULL;
    secp256k1_musig_pubnonce peer_nonce;
    secp256k1_musig_partial_sig ps;
    (void)n;
    uint32_t idx = o->next;
    /* The index is used whatever happens next: a nonce is never reused. */
    o->next++;
    if (!session_at(o, idx, tx, len, &session, &sec, &peer_nonce)) return 0;
    if (!musig_create_partial_sig(o->ch->ctx, &ps, sec, &o->ch->local_funding_keypair, &session))
        return 0;
    if (!musig_partial_sig_serialize(o->ch->ctx, psig, &ps)) return 0;
    *nonce_index = idx;
    return 1;
}

static int op_verify(void *ctx, uint64_t n, const unsigned char *tx, size_t len,
                     const unsigned char psig[32], uint32_t nonce_index,
                     unsigned char sig64[64]) {
    cu_chops_t *o = ctx;
    musig_signing_session_t session;
    secp256k1_musig_secnonce *sec = NULL;
    secp256k1_musig_pubnonce peer_nonce;
    secp256k1_musig_partial_sig peer_ps, my_ps, sigs[2];
    (void)n;
    /* Only the next unused index. */
    if (nonce_index != o->next) return 0;
    o->next++;
    if (!session_at(o, nonce_index, tx, len, &session, &sec, &peer_nonce)) return 0;
    if (!musig_partial_sig_parse(o->ch->ctx, &peer_ps, psig)) return 0;
    if (!musig_verify_partial_sig(o->ch->ctx, &peer_ps, &peer_nonce,
                                  &o->ch->remote_funding_pubkey, &session))
        return 0;
    if (!musig_create_partial_sig(o->ch->ctx, &my_ps, sec, &o->ch->local_funding_keypair, &session))
        return 0;
    int me = o->ch->local_funding_signer_idx;
    sigs[me] = my_ps;
    sigs[1 - me] = peer_ps;
    return musig_aggregate_partial_sigs(o->ch->ctx, sig64, &session, sigs, 2);
}

static void op_skip(void *ctx, uint32_t idx) {
    cu_chops_t *o = ctx;
    secp256k1_musig_pubnonce unused;
    if (idx != o->next) return;
    own_draw(o, idx, &unused);
    o->next++;
}

static void op_reset(void *ctx) {
    cu_chops_t *o = ctx;
    own_clear(o);
    memset(o->peer, 0, sizeof(o->peer));
    o->next = o->own_end = o->peer_end = 0;
}

/* ---- commitments ---- */

uint64_t cu_chops_commit_fee_msat(void *ctx, const cu_state_t *st) {
    (void)ctx;
    size_t n = 0;
    for (size_t i = 0; i < st->n_htlcs; i++)
        if (st->htlcs[i].amount_msat / 1000 >= CHANNEL_DUST_LIMIT_SATS) n++;
    return fee_commitment_tx_at(st->feerate_per_kvb, n) * 1000;
}

static int op_build(void *ctx, cu_side_t holder, uint64_t n, const cu_state_t *st,
                    const secp256k1_pubkey *holder_point,
                    unsigned char *tx, size_t *tx_len, unsigned char txid[32]) {
    cu_chops_t *o = ctx;
    cu_side_t me = o->side;
    channel_t v = *o->ch;
    htlc_t *h = NULL;
    if (st->n_htlcs) {
        h = calloc(st->n_htlcs, sizeof(htlc_t));
        if (!h) return 0;
    }
    /* BOLT 3: whole satoshis, rounded down; the rest is fee. */
    v.local_amount = (me == CU_HOST ? st->host_msat : st->member_msat) / 1000;
    v.remote_amount = (me == CU_HOST ? st->member_msat : st->host_msat) / 1000;
    for (size_t i = 0; i < st->n_htlcs; i++) {
        h[i].direction = st->htlcs[i].offerer == (uint8_t)me ? HTLC_OFFERED : HTLC_RECEIVED;
        h[i].state = HTLC_STATE_ACTIVE;
        h[i].amount_sats = st->htlcs[i].amount_msat / 1000;
        memcpy(h[i].payment_hash, st->htlcs[i].payment_hash, 32);
        h[i].cltv_expiry = st->htlcs[i].cltv_expiry;
        h[i].id = st->htlcs[i].id;
    }
    v.htlcs = h;
    v.n_htlcs = st->n_htlcs;
    v.htlcs_cap = st->n_htlcs;
    v.n_ptlcs = 0;
    v.commitment_number = n;
    v.commit_fee_rate_sat_per_kvb = st->feerate_per_kvb;
    tx_buf_t b;
    tx_buf_init(&b, 1024);
    int ok = channel_build_commitment_at(&v, holder != me, holder_point, holder == CU_HOST,
                                         &b, txid)
          && !b.oom && b.len <= *tx_len;
    if (ok) {
        memcpy(tx, b.data, b.len);
        *tx_len = b.len;
    }
    tx_buf_free(&b);
    free(h);
    return ok;
}

/* Output vout of an unsigned transaction (no witness). */
static int read_varint(const unsigned char *p, size_t len, size_t *off, uint64_t *v) {
    if (*off >= len) return 0;
    unsigned char b = p[(*off)++];
    int k = b < 0xfd ? 0 : b == 0xfd ? 2 : b == 0xfe ? 4 : 8;
    if (k == 0) { *v = b; return 1; }
    if (*off + (size_t)k > len) return 0;
    *v = 0;
    for (int i = k - 1; i >= 0; i--) *v = (*v << 8) | p[*off + (size_t)i];
    *off += (size_t)k;
    return 1;
}

static int tx_output(const unsigned char *tx, size_t len, uint32_t vout, uint64_t *amount,
                     const unsigned char **spk, size_t *spk_len) {
    size_t off = 4;
    uint64_t n, l;
    if (!read_varint(tx, len, &off, &n)) return 0;
    for (uint64_t i = 0; i < n; i++) {
        off += 36;
        if (!read_varint(tx, len, &off, &l)) return 0;
        off += (size_t)l + 4;
        if (off > len) return 0;
    }
    if (!read_varint(tx, len, &off, &n) || vout >= n) return 0;
    for (uint64_t i = 0; i <= vout; i++) {
        if (off + 8 > len) return 0;
        uint64_t a = 0;
        for (int k = 7; k >= 0; k--) a = (a << 8) | tx[off + (size_t)k];
        off += 8;
        if (!read_varint(tx, len, &off, &l) || off + l > len) return 0;
        if (i == vout) { *amount = a; *spk = tx + off; *spk_len = (size_t)l; return 1; }
        off += (size_t)l;
    }
    return 0;
}

/* The revoked commitment's to_local output (output 0) goes to this side by
   the revocation key; the penalty and its tower row are written inside the
   engine's transaction.  Every write is checked: a watch is never dropped
   silently (INV-45). */
static int op_penalty(void *ctx, persist_t *db, uint64_t n, const unsigned char secret[32],
                      const unsigned char *tx, size_t len) {
    cu_chops_t *o = ctx;
    channel_t *ch = o->ch;
    uint64_t amount;
    const unsigned char *spk;
    size_t spk_len;
    unsigned char txid[32];
    if (!tx_output(tx, len, 0, &amount, &spk, &spk_len) || spk_len > 34) return 0;
    {
        /* The txid of the revoked commitment, internal byte order. */
        unsigned char h1[32];
        sha256(tx, len, h1);
        sha256(h1, 32, txid);
    }
    /* The engine verified the secret against the point it committed to
       (INV-25); the channel_t, which builds the penalty, learns that point. */
    secp256k1_pubkey pt;
    if (!secp256k1_ec_pubkey_create(ch->ctx, &pt, secret)) return 0;
    channel_set_remote_pcp(ch, n, &pt);
    void *saved = ch->persist_db;
    ch->persist_db = NULL;                 /* written below, in this transaction */
    int ok = channel_receive_revocation_flat(ch, n, secret);
    ch->persist_db = saved;
    if (!ok) return 0;
    tx_buf_t pen;
    tx_buf_init(&pen, 512);
    ok = channel_build_penalty_tx(ch, &pen, txid, 0, amount, spk, spk_len, n, NULL, 0) && !pen.oom;
    ok = ok && persist_save_revocation(db, o->channel_id, n, secret)
            && persist_save_old_commitment(db, o->channel_id, n, txid, 0, amount, spk, spk_len)
            && persist_save_old_commitment_csv_delay(db, o->channel_id, n, ch->to_self_delay)
            && persist_save_old_commitment_witness(db, o->channel_id, n, pen.data, pen.len);
    if (ok && o->wt) {
        persist_t *wdb = o->wt->db;
        o->wt->db = NULL;                  /* rows written above */
        ok = watchtower_watch_oracular(o->wt, o->channel_id, n, txid, 0, amount, spk, spk_len,
                                       pen.data, pen.len);
        o->wt->db = wdb;
    }
    tx_buf_free(&pen);
    return ok;
}

static int op_claim(void *ctx, persist_t *db, uint64_t n, const cu_htlc_t *h,
                    const unsigned char preimage[32]) {
    cu_chops_t *o = ctx;
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db->db,
            "INSERT OR REPLACE INTO chan_update_claim (channel_id, offerer, htlc_id, commit_num,"
            " amount_msat, payment_hash, cltv_expiry, preimage) VALUES (?,?,?,?,?,?,?,?);",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int64(st, 1, o->channel_id);
    sqlite3_bind_int(st, 2, h->offerer);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)h->id);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)n);
    sqlite3_bind_int64(st, 5, (sqlite3_int64)h->amount_msat);
    sqlite3_bind_blob(st, 6, h->payment_hash, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 7, h->cltv_expiry);
    sqlite3_bind_blob(st, 8, preimage, 32, SQLITE_TRANSIENT);
    int ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

const cu_ops_t CU_CHANNEL_OPS = {
    op_build, cu_chops_commit_fee_msat, op_sign, op_verify, op_penalty, op_claim,
    op_reset, op_skip,
};

/* ---- commitment 0 ---- */

int cu_open_sign(cu_chops_t *o, const cu_state_t *initial, const secp256k1_pubkey *peer_p0,
                 unsigned char psig[32], uint32_t *idx, unsigned char peer_c0_txid[32]) {
    unsigned char *tx = malloc(CU_TX_MAX);
    size_t len = CU_TX_MAX;
    int ok = tx && op_build(o, CU_OTHER(o->side), 0, initial, peer_p0, tx, &len, peer_c0_txid)
          && op_sign(o, 0, tx, len, psig, idx);
    free(tx);
    return ok;
}

int cu_open_verify(cu_chops_t *o, const cu_state_t *initial, const unsigned char s0[32],
                   const unsigned char peer_psig[32], uint32_t idx,
                   unsigned char *tx, size_t *tx_len, unsigned char sig64[64]) {
    secp256k1_pubkey p0;
    unsigned char txid[32];
    return secp256k1_ec_pubkey_create(o->ch->ctx, &p0, s0)
        && op_build(o, o->side, 0, initial, &p0, tx, tx_len, txid)
        && op_verify(o, 0, tx, *tx_len, peer_psig, idx, sig64);
}

int cu_chops_finalize(const unsigned char *tx, size_t len, const unsigned char sig64[64],
                      tx_buf_t *out) {
    return finalize_signed_tx(out, tx, len, sig64);
}
