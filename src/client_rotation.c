/* Client side of a rotation by a co-signed close into the new factory.
   See include/superscalar/client_rotation.h. */
#include "superscalar/client_rotation.h"
#include "superscalar/client.h"
#include "superscalar/factory_keys.h"
#include "superscalar/tx_builder.h"
#include "superscalar/types.h"
#include "superscalar/sha256.h"
#include "cJSON.h"
#include <secp256k1_schnorrsig.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

/* --- Capability, chain source, freeze --- */

static int g_cin_capable = 0;
static regtest_t *g_cin_rt = NULL;
static int g_cin_depth = 1;
static int g_cin_frozen = 0;
static char g_cin_frozen_old[65];      /* the old funding (display hex) it is for */

void client_cin_set_capable(int capable) { g_cin_capable = capable ? 1 : 0; }
int client_cin_capable(void) { return g_cin_capable; }

void client_cin_set_chain(regtest_t *rt, int safe_depth) {
    g_cin_rt = rt;
    g_cin_depth = safe_depth >= 1 ? safe_depth : 1;
}
int client_cin_safe_depth(void) { return g_cin_depth; }

int client_cin_frozen(void) { return g_cin_frozen; }

static void txid_display(const unsigned char *txid32, char out[65]);

int client_cin_frozen_for(const unsigned char *funding_txid32) {
    if (!g_cin_frozen) return 0;
    if (!funding_txid32) return 1;
    char d[65];
    txid_display(funding_txid32, d);
    return strcmp(d, g_cin_frozen_old) == 0;
}

static int state_is_signed(const char *state) {
    return state && (strcmp(state, "close_signed") == 0 || strcmp(state, "closed") == 0);
}

void client_cin_refresh_frozen(persist_t *db) {
    g_cin_frozen = 0;
    g_cin_frozen_old[0] = '\0';
    if (!db) return;
    persist_client_rotation_t row;
    memset(&row, 0, sizeof(row));
    if (persist_client_rotation_load_open(db, &row) == 1 && state_is_signed(row.state)) {
        g_cin_frozen = 1;
        snprintf(g_cin_frozen_old, sizeof(g_cin_frozen_old), "%s", row.old_txid);
    }
    free(row.close_hex);
}

static int msg_is_cin_rotation(const wire_msg_t *m, const char *outer) {
    const cJSON *o = outer ? cJSON_GetObjectItemCaseSensitive(m->json, outer) : m->json;
    const cJSON *mode = o ? cJSON_GetObjectItemCaseSensitive(o, "mode") : NULL;
    return cJSON_IsString(mode) && strcmp(mode->valuestring, "close_into_new") == 0;
}

int client_cin_refuse_while_frozen(const wire_msg_t *m, const unsigned char *funding_txid32) {
    if (!m || !client_cin_frozen_for(funding_txid32)) return 0;
    switch (m->msg_type) {
    case MSG_UPDATE_ADD_HTLC:
    case MSG_PTLC_PRESIG:
        return 1;
    case MSG_ROTATION_BEGIN:
        return !(m->json && msg_is_cin_rotation(m, NULL));
    case MSG_FACTORY_PROPOSE:
        return !(m->json && msg_is_cin_rotation(m, "rotation"));
    default:
        return 0;
    }
}

int client_cin_check_close_height(uint32_t close_height, int tip) {
    return tip > 0 && (uint64_t)close_height <= (uint64_t)tip + 1;
}

static void txid_display(const unsigned char *txid32, char out[65]) {
    unsigned char r[32];
    memcpy(r, txid32, 32);
    reverse_bytes(r, 32);
    hex_encode(r, 32, out);
}

/* HEX is a transaction whose txid (display hex) is TXID. */
static int hex_tx_has_txid(const char *hex, const char *txid) {
    if (!hex || !txid || strlen(txid) != 64) return 0;
    size_t hl = strlen(hex);
    if (hl < 20 || hl % 2 != 0 || hl > 400000) return 0;
    unsigned char *raw = malloc(hl / 2);
    if (!raw) return 0;
    unsigned char t[32];
    char disp[65];
    int ok = hex_decode(hex, raw, hl / 2) == (int)(hl / 2) &&
             tx_txid_from_bytes(raw, hl / 2, t);
    free(raw);
    if (!ok) return 0;
    txid_display(t, disp);
    return strcmp(disp, txid) == 0;
}

static int pk_eq(const secp256k1_context *ctx, const secp256k1_pubkey *a,
                 const secp256k1_pubkey *b) {
    unsigned char sa[33], sb[33];
    size_t la = 33, lb = 33;
    return secp256k1_ec_pubkey_serialize(ctx, sa, &la, a, SECP256K1_EC_COMPRESSED) &&
           secp256k1_ec_pubkey_serialize(ctx, sb, &lb, b, SECP256K1_EC_COMPRESSED) &&
           memcmp(sa, sb, 33) == 0;
}

client_cin_action_t client_cin_resolve_action(const char *state, int close_confs,
                                              int has_close_hex) {
    if (!state) return CLIENT_CIN_NONE;
    /* A signed close (or one the LSP called confirmed) switches only once the
       client's own chain source shows it at the safe depth.  The replacement
       of a tree we signed is kept until then, whatever the state. */
    if (state_is_signed(state)) {
        if (close_confs >= g_cin_depth) return CLIENT_CIN_PROMOTE;
        return has_close_hex ? CLIENT_CIN_BROADCAST : CLIENT_CIN_WAIT;
    }
    return CLIENT_CIN_NONE;
}

int client_cin_check_close(const secp256k1_context *ctx, const factory_t *old_f,
                           const secp256k1_pubkey *pks, size_t n,
                           const unsigned char *funding_spk, size_t spk_len,
                           uint64_t funding_amount, uint32_t funding_vout,
                           const unsigned char funding_txid32[32], uint32_t close_height,
                           const char **why) {
    const char *dummy;
    if (!why) why = &dummy;
    *why = NULL;
    if (!ctx || !old_f || !pks || n < 2 || !funding_spk || !funding_txid32) {
        *why = "bad arguments";
        return 0;
    }
    if (!pk_eq(ctx, &pks[0], &old_f->pubkeys[0])) { *why = "slot 0 is not the LSP key"; return 0; }
    for (size_t i = 1; i < n; i++)
        for (size_t j = 0; j < old_f->n_participants; j++)
            if (pk_eq(ctx, &pks[i], &old_f->pubkeys[j])) {
                *why = "a replacement key is reused from the old factory";
                return 0;
            }
    unsigned char spk[34];
    if (!factory_funding_spk_for(ctx, pks, n, spk) || spk_len != 34 ||
        memcmp(spk, funding_spk, 34) != 0) {
        *why = "the funding output is not the participants' aggregate key";
        return 0;
    }
    if (funding_vout != 0) { *why = "the funding is not output 0 of the close"; return 0; }
    uint64_t old_amt = old_f->funding_amount_sats;
    if (funding_amount == 0 || funding_amount >= old_amt ||
        old_amt - funding_amount > old_amt / 50) {
        *why = "the close fee is out of range";
        return 0;
    }
    tx_output_t out;
    memset(&out, 0, sizeof(out));
    out.amount_sats = funding_amount;
    memcpy(out.script_pubkey, spk, 34);
    out.script_pubkey_len = 34;
    tx_buf_t tx;
    tx_buf_init(&tx, 256);
    unsigned char sighash[32], txid[32];
    int ok = factory_build_cooperative_close_unsigned((factory_t *)old_f, &tx, sighash,
                                                      &out, 1, close_height) &&
             tx_txid_from_bytes(tx.data, tx.len, txid);
    tx_buf_free(&tx);
    if (!ok || memcmp(txid, funding_txid32, 32) != 0) {
        *why = "the funding is not the close of the old factory";
        return 0;
    }
    return 1;
}

static int rd_varint(const unsigned char *t, size_t len, size_t *off, uint64_t *v) {
    if (*off >= len) return 0;
    unsigned char b = t[(*off)++];
    if (b < 0xfd) { *v = b; return 1; }
    size_t n = b == 0xfd ? 2 : (b == 0xfe ? 4 : 8);
    if (*off + n > len) return 0;
    *v = 0;
    for (size_t i = 0; i < n; i++) *v |= (uint64_t)t[*off + i] << (8 * i);
    *off += n;
    return 1;
}

/* An unsigned distribution TX (T, LEN) spends NF's funding output and pays
   this client's (BIP-86 tweaked) factory key at least MIN_AMOUNT. */
static int check_distribution_tx(const secp256k1_context *ctx, const factory_t *nf,
                                 const unsigned char *t, size_t len,
                                 const secp256k1_pubkey *my_pk, uint64_t min_amount) {
    size_t off = 4;
    if (!t || len < 10) return 0;
    if (t[4] == 0x00 && t[5] == 0x01) off = 6;
    uint64_t n_in, n_out;
    if (!rd_varint(t, len, &off, &n_in) || n_in != 1 || off + 36 > len) return 0;
    if (memcmp(t + off, nf->funding_txid, 32) != 0) return 0;
    uint32_t vout = (uint32_t)t[off + 32] | ((uint32_t)t[off + 33] << 8) |
                    ((uint32_t)t[off + 34] << 16) | ((uint32_t)t[off + 35] << 24);
    if (vout != nf->funding_vout) return 0;
    off += 36;
    uint64_t sl;
    if (!rd_varint(t, len, &off, &sl) || sl > len || off + sl + 4 > len) return 0;
    off += sl + 4;
    secp256k1_xonly_pubkey x, tw;
    unsigned char xs[32], tweak[32], want[34];
    secp256k1_pubkey twfull;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &x, NULL, my_pk) ||
        !secp256k1_xonly_pubkey_serialize(ctx, xs, &x))
        return 0;
    sha256_tagged("TapTweak", xs, 32, tweak);
    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &twfull, &x, tweak) ||
        !secp256k1_xonly_pubkey_from_pubkey(ctx, &tw, NULL, &twfull))
        return 0;
    build_p2tr_script_pubkey(want, &tw);
    if (!rd_varint(t, len, &off, &n_out)) return 0;
    for (uint64_t i = 0; i < n_out; i++) {
        if (off + 8 > len) return 0;
        uint64_t amt = 0;
        for (int b = 0; b < 8; b++) amt |= (uint64_t)t[off + b] << (8 * b);
        off += 8;
        if (!rd_varint(t, len, &off, &sl) || sl > len || off + sl > len) return 0;
        if (sl == 34 && memcmp(t + off, want, 34) == 0 && amt >= min_amount) return 1;
        off += sl;
    }
    return 0;
}

/* SIGNED is exactly UNSIGNED finalized with one key-path signature, and that
   signature is valid for SIGHASH under KEY. */
static int signed_is_keypath_of(const secp256k1_context *ctx, const tx_buf_t *signed_tx,
                                const unsigned char *unsigned_tx, size_t unsigned_len,
                                const unsigned char sighash[32],
                                const secp256k1_xonly_pubkey *key) {
    if (!signed_tx || !signed_tx->data || signed_tx->len < 70 || !unsigned_tx) return 0;
    unsigned char sig[64];
    memcpy(sig, signed_tx->data + signed_tx->len - 68, 64);
    tx_buf_t want;
    tx_buf_init(&want, unsigned_len + 80);
    int ok = finalize_signed_tx(&want, unsigned_tx, unsigned_len, sig) &&
             want.len == signed_tx->len && memcmp(want.data, signed_tx->data, want.len) == 0;
    tx_buf_free(&want);
    if (ok && sighash && key)
        ok = secp256k1_schnorrsig_verify(ctx, sig, sighash, 32, key);
    return ok;
}

/* Every signed node of NF is a transaction of the tree the client built
   (same txid as its own unsigned node); single-input nodes are exactly the
   unsigned node plus the (verified) key-path signature. */
static int nodes_match_local(const secp256k1_context *ctx, const factory_t *nf) {
    for (size_t i = 0; i < nf->n_nodes; i++) {
        const factory_node_t *nd = &nf->nodes[i];
        if (!nd->is_signed || nd->signed_tx.len == 0 || nd->unsigned_tx.len == 0) return 0;
        unsigned char a[32], b[32];
        if (!tx_txid_from_bytes(nd->unsigned_tx.data, nd->unsigned_tx.len, a) ||
            !tx_txid_from_bytes(nd->signed_tx.data, nd->signed_tx.len, b) ||
            memcmp(a, b, 32) != 0)
            return 0;
        size_t off = 4;
        uint64_t n_in = 0;
        if (rd_varint(nd->unsigned_tx.data, nd->unsigned_tx.len, &off, &n_in) && n_in == 1 &&
            !signed_is_keypath_of(ctx, &nd->signed_tx, nd->unsigned_tx.data,
                                  nd->unsigned_tx.len, NULL, NULL))
            return 0;
    }
    return 1;
}

int client_cin_tree_digest(const factory_t *f, char out_hex[65]) {
    if (!f || !out_hex || f->n_nodes == 0) return 0;
    size_t total = 4;
    for (size_t i = 0; i < f->n_nodes; i++) {
        if (!f->nodes[i].unsigned_tx.data || f->nodes[i].unsigned_tx.len == 0) return 0;
        total += 4 + f->nodes[i].unsigned_tx.len;
    }
    unsigned char *buf = malloc(total);
    if (!buf) return 0;
    size_t off = 0;
    uint32_t n = (uint32_t)f->n_nodes;
    for (int b = 0; b < 4; b++) buf[off++] = (unsigned char)(n >> (8 * b));
    for (size_t i = 0; i < f->n_nodes; i++) {
        uint32_t l = (uint32_t)f->nodes[i].unsigned_tx.len;
        for (int b = 0; b < 4; b++) buf[off++] = (unsigned char)(l >> (8 * b));
        memcpy(buf + off, f->nodes[i].unsigned_tx.data, l);
        off += l;
    }
    unsigned char d[32];
    sha256(buf, total, d);
    free(buf);
    hex_encode(d, 32, out_hex);
    return 1;
}

int client_cin_bind_tree(persist_t *db, const char *close_txid, const factory_t *f) {
    char dg[65];
    if (!db || !close_txid || !client_cin_tree_digest(f, dg)) return 0;
    return persist_client_rotation_bind_tree(db, close_txid, dg) == 1;
}

static int root_secret(secp256k1_context *ctx, unsigned char out[32]) {
    const secp256k1_keypair *id = client_identity_keypair();
    return id && secp256k1_keypair_sec(ctx, out, id);
}

int client_cin_on_begin(int fd, secp256k1_context *ctx, persist_t *db,
                        const factory_t *old_f, const cJSON *begin) {
    if (!db || !old_f || !begin || !client_cin_capable()) {
        fprintf(stderr, "Client: close-into-new rotation needs --db, a pinned --lsp-pubkey "
                "and a chain source; refusing\n");
        return 0;
    }
    unsigned char dt[32], nn[32];
    uint64_t ep = 0;
    if (!wire_parse_rotation_begin(begin, dt, nn, &ep) ||
        memcmp(dt, old_f->funding_txid, 32) != 0) {
        fprintf(stderr, "Client: ROTATION_BEGIN is not for our factory\n");
        return 0;
    }
    char old_hex[65];
    txid_display(old_f->funding_txid, old_hex);
    unsigned char root[32], sk[32];
    if (!root_secret(ctx, root)) return 0;
    persist_client_rotation_t row;
    memset(&row, 0, sizeof(row));
    int rc = persist_client_rotation_load(db, old_hex, &row);
    int ok = 0;
    uint32_t idx = 0;
    if (rc < 0) goto out;
    if (rc == 1 && strcmp(row.state, "done") != 0 && strcmp(row.state, "abandoned") != 0) {
        /* A retry of the same rotation: the same key (and so the same close).
           Any tree over that close must be the one already signed. */
        idx = row.key_index;
        ok = factory_key_derive_stored(db, ctx, root, idx, sk);
    } else {
        ok = factory_key_reserve_next(db, ctx, root, client_factory_key_ctx(), sk, &idx);
        if (ok) {
            free(row.close_hex);
            memset(&row, 0, sizeof(row));
            snprintf(row.old_txid, sizeof(row.old_txid), "%s", old_hex);
            row.old_vout = old_f->funding_vout;
            row.key_index = idx;
            snprintf(row.state, sizeof(row.state), "key_sent");
            ok = persist_client_rotation_save(db, &row);
        }
    }
    if (ok) {
        secp256k1_pubkey pk;
        ok = secp256k1_ec_pubkey_create(ctx, &pk, sk);
        if (ok) {
            cJSON *k = wire_build_rotation_key(ctx, &pk, old_f->funding_txid);
            ok = k && wire_send(fd, MSG_ROTATION_KEY, k);
            cJSON_Delete(k);
        }
        if (ok) printf("Client: replacement factory key index %u sent\n", idx);
    }
out:
    secure_zero(root, sizeof(root));
    secure_zero(sk, sizeof(sk));
    free(row.close_hex);
    if (!ok) fprintf(stderr, "Client: could not prepare the replacement factory key\n");
    return ok;
}

/* Next message that is not a ping. */
static int recv_skip(int fd, wire_msg_t *m, int timeout) {
    for (int i = 0; i < 1024; i++) {
        memset(m, 0, sizeof(*m));
        if (!wire_recv_timeout(fd, m, timeout)) return 0;
        if (m->msg_type == MSG_PING) {
            cJSON *pong = cJSON_CreateObject();
            wire_send(fd, MSG_PONG, pong);
            cJSON_Delete(pong);
            cJSON_Delete(m->json);
            continue;
        }
        if (m->msg_type == MSG_PONG) { cJSON_Delete(m->json); continue; }
        return 1;
    }
    return 0;
}

static void fsync_dir_of(const char *path) {
    char dir[700];
    snprintf(dir, sizeof(dir), "%s", path);
    char *sl = strrchr(dir, '/');
    if (sl) { if (sl == dir) sl[1] = '\0'; else *sl = '\0'; }
    else snprintf(dir, sizeof(dir), ".");
    int fd = open(dir, O_RDONLY);
    if (fd >= 0) { (void)fsync(fd); close(fd); }
}

/* Checkpoint and close an open DB at PATH; 1 if nothing is left in a WAL
   file (so the main file alone is the whole DB). */
static int db_flush_close(persist_t *s, const char *path) {
    if (s->db) sqlite3_exec(s->db, "PRAGMA wal_checkpoint(TRUNCATE);", NULL, NULL, NULL);
    persist_close(s);
    char wal[720], shm[720];
    snprintf(wal, sizeof(wal), "%s-wal", path);
    snprintf(shm, sizeof(shm), "%s-shm", path);
    struct stat st;
    if (stat(wal, &st) == 0) {
        if (st.st_size > 0) return 0;
        (void)unlink(wal);
    }
    (void)unlink(shm);
    return 1;
}

/* The verified replacement goes to a copy of the main DB, written beside it
   and moved into place in one rename (an earlier copy stays until then). */
static int write_side_db(persist_t *db, const char *side, secp256k1_context *ctx,
                         factory_t *nf, channel_t *nc, uint32_t my_index,
                         const persist_client_rotation_t *row, uint32_t key_idx) {
    char tmp[720];
    if (strlen(side) > 600) return 0;
    snprintf(tmp, sizeof(tmp), "%s.tmp", side);
    unlink(tmp);
    if (!persist_snapshot_to(db, tmp)) return 0;
    persist_t s;
    if (!persist_open(&s, tmp)) { unlink(tmp); return 0; }
    uint32_t cidx = my_index - 1;
    char sql[256];
    snprintf(sql, sizeof(sql),
             "DELETE FROM local_pcs WHERE channel_id IN (0, %u);"
             "DELETE FROM remote_pcps WHERE channel_id IN (0, %u);", cidx, cidx);
    sqlite3_exec(s.db, sql, NULL, NULL, NULL);
    int ok = persist_begin(&s);
    ok = ok && persist_save_factory(&s, nf, ctx, 0) && persist_save_tree_nodes(&s, nf, 0) &&
         persist_save_channel(&s, nc, 0, cidx) && persist_save_basepoints(&s, cidx, nc);
    if (ok && nf->dist_tx_ready && nf->dist_unsigned_tx.len > 0)
        ok = persist_save_distribution_tx(&s, 0, nf->dist_unsigned_tx.data,
                                          nf->dist_unsigned_tx.len);
    for (uint64_t cn = 0; ok && cn < nc->n_local_pcs; cn++) {
        unsigned char pcs[32];
        if (channel_get_local_pcs(nc, cn, pcs))
            ok = persist_save_local_pcs(&s, 0, cn, pcs);
        secure_zero(pcs, sizeof(pcs));
    }
    for (uint64_t cn = 0; ok && cn <= 1; cn++) {
        secp256k1_pubkey pcp;
        unsigned char ser[33];
        size_t len = 33;
        if (channel_get_remote_pcp(nc, cn, &pcp) &&
            secp256k1_ec_pubkey_serialize(ctx, ser, &len, &pcp, SECP256K1_EC_COMPRESSED))
            ok = persist_save_remote_pcp(&s, 0, cn, ser);
    }
    if (ok && nc->has_latest_commitment_sig) {
        tx_buf_t ut, st;
        unsigned char txid[32];
        tx_buf_init(&ut, 512);
        tx_buf_init(&st, 512);
        ok = channel_build_commitment_tx(nc, &ut, txid) &&
             finalize_signed_tx(&st, ut.data, ut.len, nc->latest_commitment_sig) &&
             persist_save_commitment_sig(&s, 0, nc->commitment_number,
                                         nc->latest_commitment_sig, st.data, st.len);
        if (ok && cidx != 0)
            ok = persist_save_commitment_sig(&s, cidx, nc->commitment_number,
                                             nc->latest_commitment_sig, st.data, st.len);
        tx_buf_free(&ut);
        tx_buf_free(&st);
    }
    ok = ok && persist_factory_key_set_state(&s, key_idx, FACTORY_KEY_STATE_ACTIVE, 0);
    if (ok) {
        persist_client_rotation_t done = *row;
        done.close_hex = NULL;
        snprintf(done.state, sizeof(done.state), "done");
        done.side_db[0] = '\0';
        ok = persist_client_rotation_save(&s, &done);
    }
    if (ok) ok = persist_commit(&s);
    else if (persist_in_transaction(&s)) persist_rollback(&s);
    ok = db_flush_close(&s, tmp) && ok;
    if (ok) ok = rename(tmp, side) == 0;
    if (ok) fsync_dir_of(side);
    else unlink(tmp);
    return ok;
}

/* What the client checked and is signing in this rotation (sign guard). */
typedef struct {
    persist_t *db;
    secp256k1_context *ctx;
    const factory_t *old_f;
    const client_funding_bind_t *bind;
    const char *close_disp;
    const secp256k1_pubkey *npk;
    uint64_t min_amount;
    int tree_bound;
    int dist_captured;
    tx_buf_t dist_unsigned;
    unsigned char dist_sighash[32];
} cin_guard_t;

static int cin_funding_is_bound(const factory_t *f, const client_funding_bind_t *b) {
    return f && b && memcmp(f->funding_txid, b->txid, 32) == 0 && f->funding_vout == b->vout &&
           f->funding_amount_sats == b->amount && f->funding_spk_len == 34 &&
           memcmp(f->funding_spk, b->spk, 34) == 0;
}

static int cin_sign_guard(void *arg, factory_t *f, int phase) {
    cin_guard_t *g = (cin_guard_t *)arg;
    if (!g || !f || !cin_funding_is_bound(f, g->bind)) {
        fprintf(stderr, "Client: REFUSING to sign: the tree does not spend the checked "
                "funding\n");
        return 0;
    }
    if (phase == 0) {
        if (f->cltv_timeout <= g->old_f->cltv_timeout) {
            fprintf(stderr, "Client: REFUSING to sign: the replacement expires no later "
                    "than the old factory\n");
            return 0;
        }
        if (!client_cin_bind_tree(g->db, g->close_disp, f)) {
            fprintf(stderr, "Client: REFUSING to sign: a different replacement tree was "
                    "already signed over close %s\n", g->close_disp);
            return 0;
        }
        g->tree_bound = 1;
        return 1;
    }
    if (!g->tree_bound || f->dist_tx_ready < 1 || f->dist_unsigned_tx.len == 0 ||
        !check_distribution_tx(g->ctx, f, f->dist_unsigned_tx.data, f->dist_unsigned_tx.len,
                               g->npk, g->min_amount)) {
        fprintf(stderr, "Client: REFUSING to sign the distribution TX: it does not pay our "
                "new key our balance\n");
        return 0;
    }
    tx_buf_free(&g->dist_unsigned);
    tx_buf_init(&g->dist_unsigned, f->dist_unsigned_tx.len);
    memcpy(g->dist_unsigned.data, f->dist_unsigned_tx.data, f->dist_unsigned_tx.len);
    g->dist_unsigned.len = f->dist_unsigned_tx.len;
    memcpy(g->dist_sighash, f->dist_sighash, 32);
    g->dist_captured = 1;
    return 1;
}

int client_cin_run(int fd, secp256k1_context *ctx, persist_t *db, const char *db_path,
                   const secp256k1_keypair *old_kp, factory_t *old_f, channel_t *old_ch,
                   uint32_t my_index, const wire_msg_t *propose) {
    if (!db || !db_path || !old_kp || !old_f || !old_ch || !propose || my_index < 1 ||
        !client_cin_capable() || !g_cin_rt) {
        fprintf(stderr, "Client: close-into-new rotation needs --db, a pinned --lsp-pubkey "
                "and a chain source; refusing\n");
        return 0;
    }
    const cJSON *pj = propose->json;
    if (!wire_json_unambiguous(pj)) {
        fprintf(stderr, "Client: REFUSING the rotation: keys that differ only in case\n");
        return 0;
    }
    const cJSON *rot = cJSON_GetObjectItemCaseSensitive(pj, "rotation");
    const cJSON *pka = rot ? cJSON_GetObjectItemCaseSensitive(rot, "pubkeys") : NULL;
    uint64_t ch64 = 0;
    if (!cJSON_IsArray(pka) || !wire_json_get_uint(rot, "close_height", UINT32_MAX, &ch64)) {
        fprintf(stderr, "Client: malformed close-into-new proposal\n");
        return 0;
    }
    uint32_t close_height = (uint32_t)ch64;
    int tip = regtest_get_block_height(g_cin_rt);
    if (!client_cin_check_close_height(close_height, tip)) {
        fprintf(stderr, "Client: REFUSING the rotation: close height %u is not at our tip "
                "(%d)\n", close_height, tip);
        return 0;
    }
    if (!client_cin_old_funding_unspent(g_cin_rt, old_f)) {
        fprintf(stderr, "Client: REFUSING the rotation: our factory's funding is already "
                "spent (or cannot be checked)\n");
        return 0;
    }
    size_t n = (size_t)cJSON_GetArraySize(pka);
    if (n < 2 || n > FACTORY_MAX_SIGNERS || n != old_f->n_participants || my_index >= n) {
        fprintf(stderr, "Client: bad participant list in the rotation proposal\n");
        return 0;
    }
    secp256k1_pubkey *pks = calloc(n, sizeof(secp256k1_pubkey));
    if (!pks) return 0;
    for (size_t i = 0; i < n; i++) {
        const cJSON *e = cJSON_GetArrayItem(pka, (int)i);
        unsigned char b[33];
        if (!cJSON_IsString(e) || hex_decode(e->valuestring, b, 33) != 33 ||
            !secp256k1_ec_pubkey_parse(ctx, &pks[i], b, 33)) {
            free(pks);
            return 0;
        }
    }

    char old_hex[65];
    txid_display(old_f->funding_txid, old_hex);
    persist_client_rotation_t row;
    memset(&row, 0, sizeof(row));
    int ok = 0, result = 0;
    factory_t *nf = NULL;
    channel_t *nc = NULL;
    unsigned char root[32], nsk[32];
    secp256k1_keypair nkp;
    memset(&nkp, 0, sizeof(nkp));
    cin_guard_t guard;
    memset(&guard, 0, sizeof(guard));
    client_funding_bind_t bind;
    memset(&bind, 0, sizeof(bind));
    const char *why = NULL;
    if (persist_client_rotation_load(db, old_hex, &row) != 1) {
        fprintf(stderr, "Client: no replacement key was reserved for this rotation\n");
        goto out;
    }
    if (!root_secret(ctx, root) || !factory_key_derive_stored(db, ctx, root, row.key_index, nsk) ||
        !secp256k1_keypair_create(ctx, &nkp, nsk))
        goto out;
    secp256k1_pubkey npk, id_pk;
    if (!secp256k1_keypair_pub(ctx, &npk, &nkp) ||
        !secp256k1_keypair_pub(ctx, &id_pk, client_identity_keypair()))
        goto out;

    /* The proposal: our fresh key in our slot, fresh keys only, and the
       funding is the old factory's close rebuilt here.  Parsed once; the
       ceremony builds the tree over exactly these values. */
    uint64_t fv64 = 0, fa64 = 0;
    if (!wire_json_get_uint(pj, "funding_vout", UINT32_MAX, &fv64) ||
        !wire_json_get_uint(pj, "funding_amount", 2100000000000000ULL, &fa64) ||
        wire_json_get_hex(pj, "funding_txid", bind.txid, 32) != 32 ||
        wire_json_get_hex(pj, "funding_spk", bind.spk, 34) != 34) {
        why = "malformed funding";
    } else {
        reverse_bytes(bind.txid, 32);
        bind.vout = (uint32_t)fv64;
        bind.amount = fa64;
        if (!factory_key_check_participants(ctx, db, &id_pk, &npk, my_index, pks, n, &why) ||
            !client_cin_check_close(ctx, old_f, pks, n, bind.spk, 34, bind.amount, bind.vout,
                                    bind.txid, close_height, &why)) {
            /* why set */
        } else {
            why = NULL;
        }
    }
    if (why) {
        fprintf(stderr, "Client: REFUSING the rotation: %s\n", why);
        goto out;
    }
    char close_disp[65];
    txid_display(bind.txid, close_disp);
    if (row.close_txid[0] && strcmp(row.close_txid, close_disp) != 0 &&
        state_is_signed(row.state)) {
        fprintf(stderr, "Client: REFUSING a second, different close of our old factory "
                "(signed %s, offered %s)\n", row.close_txid, close_disp);
        goto out;
    }
    snprintf(row.close_txid, sizeof(row.close_txid), "%s", close_disp);
    row.close_height = close_height;
    if (!state_is_signed(row.state) && strcmp(row.state, "verified") != 0)
        snprintf(row.state, sizeof(row.state), "key_sent");
    if (!persist_client_rotation_save(db, &row)) goto out;
    printf("Client %u: rotation proposal checked: close %s of our factory funds the "
           "replacement; signing the replacement tree\n", my_index, close_disp);
    fflush(stdout);

    /* The replacement tree and channel (signed with the fresh key).  The
       guard binds the tree to this close before our first signature. */
    nf = calloc(1, sizeof(*nf));
    nc = calloc(1, sizeof(*nc));
    if (!nf || !nc) goto out;
    nc->local_amount = old_ch->local_amount;   /* checked as carried */
    guard.db = db;
    guard.ctx = ctx;
    guard.old_f = old_f;
    guard.bind = &bind;
    guard.close_disp = close_disp;
    guard.npk = &npk;
    guard.min_amount = old_ch->local_amount;
    tx_buf_init(&guard.dist_unsigned, 16);
    client_set_sign_guard(cin_sign_guard, &guard);
    int rok = client_do_factory_rotation_bound(fd, ctx, &nkp, my_index, n, pks, nf, nc,
                                               propose, &bind);
    client_set_sign_guard(NULL, NULL);
    if (!rok) {
        fprintf(stderr, "Client: replacement ceremony failed\n");
        goto out;
    }
    int all_signed = nf->n_nodes > 0;
    for (size_t i = 0; i < nf->n_nodes; i++)
        if (!nf->nodes[i].is_signed) all_signed = 0;
    if (!all_signed || !guard.tree_bound || !cin_funding_is_bound(nf, &bind) ||
        !factory_verify_all(nf) || !nodes_match_local(ctx, nf) ||
        nf->cltv_timeout <= old_f->cltv_timeout || nc->local_amount < old_ch->local_amount ||
        !client_channel_amounts_exact(nc)) {
        fprintf(stderr, "Client: REFUSING the rotation: the replacement is not the tree we "
                "signed, not fully signed, or does not carry our balance\n");
        goto out;
    }
    /* The distribution TX we hold is the one we checked and signed, with a
       valid aggregate signature. */
    if (nf->dist_tx_ready != 2 || !guard.dist_captured ||
        !signed_is_keypath_of(ctx, &nf->dist_unsigned_tx, guard.dist_unsigned.data,
                              guard.dist_unsigned.len, guard.dist_sighash,
                              &nf->nodes[0].tweaked_pubkey) ||
        !check_distribution_tx(ctx, nf, nf->dist_unsigned_tx.data, nf->dist_unsigned_tx.len,
                               &npk, old_ch->local_amount)) {
        fprintf(stderr, "Client: REFUSING the rotation: the replacement's distribution TX "
                "is not the one we signed, or its signature is invalid\n");
        goto out;
    }

    /* The LSP-signed initial commitment of the new channel. */
    {
        wire_msg_t m;
        if (!recv_skip(fd, &m, 120) || m.msg_type != MSG_COMMITMENT_SIGNED) {
            fprintf(stderr, "Client: expected the initial commitment signature\n");
            if (m.json) cJSON_Delete(m.json);
            goto out;
        }
        uint32_t cid, nidx;
        uint64_t cn;
        unsigned char psig[32], full[64];
        int cok = wire_parse_commitment_signed(m.json, &cid, &cn, psig, &nidx) && cn == 0 &&
                  nc->commitment_number == 0 &&
                  channel_verify_and_aggregate_commitment_sig(nc, psig, nidx, full);
        cJSON_Delete(m.json);
        if (!cok) {
            fprintf(stderr, "Client: REFUSING the rotation: bad initial commitment signature\n");
            goto out;
        }
        memcpy(nc->latest_commitment_sig, full, 64);
        nc->has_latest_commitment_sig = 1;
    }

    /* Store the replacement before signing anything that funds it. */
    char side[200];
    if (strlen(db_path) > sizeof(side) - 16) {
        fprintf(stderr, "Client: DB path too long for the rotation side DB\n");
        goto out;
    }
    snprintf(side, sizeof(side), "%s.rotation", db_path);
    if (!write_side_db(db, side, ctx, nf, nc, my_index, &row, row.key_index)) {
        fprintf(stderr, "Client: could not store the replacement -- not signing the close\n");
        goto out;
    }
    snprintf(row.side_db, sizeof(row.side_db), "%s", side);
    if (!state_is_signed(row.state)) snprintf(row.state, sizeof(row.state), "verified");
    if (!persist_client_rotation_save(db, &row)) goto out;
    printf("Client %u: replacement verified and stored (exit path, balance %llu, initial "
           "commitment, distribution TX); waiting for the close\n", my_index,
           (unsigned long long)nc->local_amount);
    fflush(stdout);

    /* C4: sign exactly the close we rebuilt, with the OLD key. */
    {
        wire_msg_t m;
        if (!recv_skip(fd, &m, 300) || m.msg_type != MSG_CLOSE_PROPOSE) {
            fprintf(stderr, "Client: expected CLOSE_PROPOSE for the rotation close\n");
            if (m.json) cJSON_Delete(m.json);
            goto out;
        }
        const cJSON *outs = cJSON_GetObjectItemCaseSensitive(m.json, "outputs");
        const cJSON *o0 = cJSON_IsArray(outs) && cJSON_GetArraySize(outs) == 1
                              ? cJSON_GetArrayItem(outs, 0) : NULL;
        uint64_t amt = 0, ht = 0;
        unsigned char ospk[34];
        int same = wire_json_unambiguous(m.json) && o0 &&
                   wire_json_get_uint(o0, "amount", 2100000000000000ULL, &amt) &&
                   wire_json_get_uint(m.json, "current_height", UINT32_MAX, &ht) &&
                   amt == bind.amount && (uint32_t)ht == close_height &&
                   wire_json_get_hex(o0, "spk", ospk, 34) == 34 &&
                   memcmp(ospk, bind.spk, 34) == 0;
        if (!same) {
            fprintf(stderr, "Client: REFUSING the close: it is not the verified close\n");
            cJSON_Delete(m.json);
            goto out;
        }
        /* Write-ahead: from here a full signature may exist; the old channel
           stays frozen until the close resolves. */
        snprintf(row.state, sizeof(row.state), "close_signed");
        if (!persist_client_rotation_save(db, &row)) { cJSON_Delete(m.json); goto out; }
        g_cin_frozen = 1;
        snprintf(g_cin_frozen_old, sizeof(g_cin_frozen_old), "%s", old_hex);
        secp256k1_pubkey opk;
        secp256k1_keypair_pub(ctx, &opk, old_kp);
        tx_output_t eo;
        memset(&eo, 0, sizeof(eo));
        eo.amount_sats = bind.amount;
        memcpy(eo.script_pubkey, bind.spk, 34);
        eo.script_pubkey_len = 34;
        client_set_expected_close(&eo, close_height);
        int cok = client_do_close_ceremony(fd, ctx, old_kp, &opk, old_f, old_f->n_participants,
                                           &m, close_height, NULL, 0);
        client_set_expected_close(NULL, 0);
        cJSON_Delete(m.json);
        char *hex = client_take_last_close_hex();
        if (hex && hex_tx_has_txid(hex, row.close_txid)) {
            free(row.close_hex);
            row.close_hex = hex;
            (void)persist_client_rotation_save(db, &row);
        } else {
            free(hex);
        }
        if (!cok) {
            fprintf(stderr, "Client: the rotation close ceremony failed (keeping the "
                    "stored replacement until the old factory is resolved)\n");
            goto out;
        }
        printf("Client %u: rotation close %s signed with the old key; waiting for "
               "it to confirm\n", my_index, close_disp);
        fflush(stdout);
    }

    /* The LSP reports the close; the switch waits for our own chain source. */
    {
        wire_msg_t m;
        if (!recv_skip(fd, &m, 7200) || m.msg_type != MSG_ROTATION_DONE) {
            fprintf(stderr, "Client: no ROTATION_DONE (the close resolves on reconnect)\n");
            if (m.json) cJSON_Delete(m.json);
            goto out;
        }
        char ct[65];
        char *hex = NULL;
        int conf = 0;
        int dok = wire_parse_rotation_done(m.json, ct, &hex, &conf) &&
                  strcmp(ct, row.close_txid) == 0;
        cJSON_Delete(m.json);
        if (dok && hex && !row.close_hex && hex_tx_has_txid(hex, row.close_txid)) {
            row.close_hex = hex;
            hex = NULL;
            (void)persist_client_rotation_save(db, &row);
        }
        free(hex);
        int confs = -1, other = -1;
        if (dok) client_cin_chain_view(g_cin_rt, db, &row, &confs, &other);
        (void)other;
        result = dok && confs >= g_cin_depth;
        if (result)
            printf("Client %u: rotation close %s confirmed (%d); switching to the new "
                   "factory\n", my_index, row.close_txid, confs);
        else if (dok)
            printf("Client %u: the LSP reports rotation close %s %s; waiting for %d "
                   "confirmation(s) on our chain source\n", my_index, row.close_txid,
                   conf ? "confirmed" : "pending", g_cin_depth);
    }
    ok = 1;
out:
    (void)ok;
    client_set_sign_guard(NULL, NULL);
    tx_buf_free(&guard.dist_unsigned);
    secure_zero(root, sizeof(root));
    secure_zero(nsk, sizeof(nsk));
    secure_zero(&nkp, sizeof(nkp));
    free(row.close_hex);
    free(pks);
    if (nf) { factory_free(nf); free(nf); }
    if (nc) { channel_cleanup(nc); free(nc); }
    return result;
}

/* The blocks still to look at for one close (from its height up), kept
   across calls so a long absence is scanned once. */
static char g_scan_close[65];
static uint32_t g_scan_next = 0;
#define CIN_SCAN_MAX_BLOCKS 2016
#define CIN_SCAN_REORG_MARGIN 6

static char *rpc_trim(char *s) {
    while (*s == ' ' || *s == '\n' || *s == '"') s++;
    size_t l = strlen(s);
    while (l > 0 && (s[l - 1] == ' ' || s[l - 1] == '\n' || s[l - 1] == '"' || s[l - 1] == '\r'))
        s[--l] = '\0';
    return s;
}

/* Scan blocks from ROW's close height for the close itself or another
   transaction spending the old funding. */
static void cin_scan_blocks(regtest_t *rt, const persist_client_rotation_t *row, int tip,
                            int *close_confs, int *other_confs) {
    if (strcmp(g_scan_close, row->close_txid) != 0) {
        snprintf(g_scan_close, sizeof(g_scan_close), "%s", row->close_txid);
        g_scan_next = row->close_height;
    }
    uint32_t from = g_scan_next > CIN_SCAN_REORG_MARGIN ? g_scan_next - CIN_SCAN_REORG_MARGIN : 0;
    if (from < row->close_height) from = row->close_height;
    uint32_t to = (uint32_t)tip;
    if (to >= from + CIN_SCAN_MAX_BLOCKS) to = from + CIN_SCAN_MAX_BLOCKS - 1;
    /* Blocks below the prune height are gone: skip them (the known
       transactions were looked up before this scan) instead of stopping. */
    uint32_t prune_below = 0;
    {
        char *ci = regtest_exec(rt, "getblockchaininfo", "");
        cJSON *cj = ci ? cJSON_Parse(ci) : NULL;
        free(ci);
        const cJSON *pr = cj ? cJSON_GetObjectItemCaseSensitive(cj, "pruned") : NULL;
        const cJSON *ph = cj ? cJSON_GetObjectItemCaseSensitive(cj, "pruneheight") : NULL;
        if (cJSON_IsTrue(pr) && cJSON_IsNumber(ph) && ph->valuedouble > 0)
            prune_below = (uint32_t)ph->valuedouble;
        cJSON_Delete(cj);
    }
    uint32_t skipped_from = 0, n_skipped = 0;
    int hit = 0;
    for (uint32_t h = from; h <= to; h++) {
        char params[96];
        snprintf(params, sizeof(params), "%u", h);
        char *hr = regtest_exec(rt, "getblockhash", params);
        if (!hr) return;
        char hash[80];
        snprintf(hash, sizeof(hash), "%s", rpc_trim(hr));
        free(hr);
        snprintf(params, sizeof(params), "\"%s\" 2", hash);
        char *br = regtest_exec(rt, "getblock", params);
        cJSON *b = br ? cJSON_Parse(br) : NULL;
        free(br);
        if (!b) {
            if (h >= prune_below) return;          /* not pruned: try again later */
            if (n_skipped++ == 0) skipped_from = h;
            g_scan_next = h + 1;
            continue;
        }
        const cJSON *txs = cJSON_GetObjectItemCaseSensitive(b, "tx");
        int found = 0;
        const cJSON *tx;
        cJSON_ArrayForEach(tx, txs) {
            const cJSON *id = cJSON_GetObjectItemCaseSensitive(tx, "txid");
            if (cJSON_IsString(id) && strcmp(id->valuestring, row->close_txid) == 0) {
                *close_confs = tip - (int)h + 1;
                found = 1;
                break;
            }
            const cJSON *vin = cJSON_GetObjectItemCaseSensitive(tx, "vin");
            const cJSON *in;
            cJSON_ArrayForEach(in, vin) {
                const cJSON *pt = cJSON_GetObjectItemCaseSensitive(in, "txid");
                const cJSON *pv = cJSON_GetObjectItemCaseSensitive(in, "vout");
                if (cJSON_IsString(pt) && cJSON_IsNumber(pv) &&
                    strcmp(pt->valuestring, row->old_txid) == 0 &&
                    (uint32_t)pv->valuedouble == row->old_vout) {
                    *other_confs = tip - (int)h + 1;
                    found = 1;
                    break;
                }
            }
            if (found) break;
        }
        cJSON_Delete(b);
        if (found) { g_scan_next = h; hit = 1; break; }
    }
    if (n_skipped)
        fprintf(stderr, "Client: WARNING: blocks %u..%u are pruned on this node; the "
                "rotation close %s could not be looked for there (only its known "
                "transactions were checked)\n", skipped_from, skipped_from + n_skipped - 1,
                row->close_txid);
    if (!hit) g_scan_next = to + 1;
}

/* The depth of a transaction the client knows by txid, without txindex: the
   node's own lookup (mempool or txindex), then any of its outputs still in
   the UTXO set.  -1 if not seen. */
static int known_tx_confs(regtest_t *rt, const char *txid, uint32_t n_out) {
    int best = -1;
    char params[128];
    snprintf(params, sizeof(params), "\"%s\" true", txid);
    char *r = regtest_exec(rt, "getrawtransaction", params);
    cJSON *j = r ? cJSON_Parse(r) : NULL;
    free(r);
    const cJSON *c = j ? cJSON_GetObjectItemCaseSensitive(j, "confirmations") : NULL;
    if (cJSON_IsNumber(c)) best = (int)c->valuedouble;
    cJSON_Delete(j);
    if (n_out > 16) n_out = 16;
    for (uint32_t v = 0; v < n_out; v++) {
        snprintf(params, sizeof(params), "\"%s\" %u false", txid, v);
        r = regtest_exec(rt, "gettxout", params);
        j = r ? cJSON_Parse(r) : NULL;
        free(r);
        c = j ? cJSON_GetObjectItemCaseSensitive(j, "confirmations") : NULL;
        if (cJSON_IsNumber(c) && (int)c->valuedouble > best) best = (int)c->valuedouble;
        cJSON_Delete(j);
    }
    return best;
}

/* The deepest of the factory-0 tree transactions in DB (ROOTS_ONLY: the
   ones spending the funding output).  -1 if none is seen. */
static int tree_txs_confs(regtest_t *rt, persist_t *db, int roots_only) {
    if (!db || !db->db) return -1;
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db->db,
            "SELECT txid, n_outputs, parent_index FROM tree_nodes WHERE factory_id = 0 "
            "LIMIT 256;", -1, &st, NULL) != SQLITE_OK)
        return -1;
    int best = -1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *t = (const char *)sqlite3_column_text(st, 0);
        int parent = sqlite3_column_type(st, 2) == SQLITE_NULL ? -1 : sqlite3_column_int(st, 2);
        if (!t || strlen(t) != 64 || (roots_only && parent >= 0)) continue;
        int c = known_tx_confs(rt, t, (uint32_t)sqlite3_column_int(st, 1));
        if (c > best) best = c;
    }
    sqlite3_finalize(st);
    return best;
}

/* The old factory's own spenders the client knows: its tree root and its
   distribution TX (main DB). */
static int old_spenders_confs(regtest_t *rt, persist_t *db) {
    int best = tree_txs_confs(rt, db, 1);
    unsigned char *buf = malloc(100000);
    size_t len = 0;
    if (buf && persist_load_distribution_tx(db, 0, buf, &len, 100000) && len > 0) {
        unsigned char t[32];
        char disp[65];
        if (tx_txid_from_bytes(buf, len, t)) {
            txid_display(t, disp);
            int c = known_tx_confs(rt, disp, 4);
            if (c > best) best = c;
        }
    }
    free(buf);
    return best;
}

/* The replacement's tree transactions (side DB): each spends the close or
   one of its descendants, so its depth bounds the close's. */
static int replacement_txs_confs(regtest_t *rt, const char *side) {
    if (!side || !side[0] || access(side, F_OK) != 0) return -1;
    persist_t s;
    memset(&s, 0, sizeof(s));
    if (!persist_open_readonly(&s, side)) return -1;
    int c = tree_txs_confs(rt, &s, 0);
    persist_close(&s);
    return c;
}

int client_cin_old_funding_unspent(regtest_t *rt, const factory_t *old_f) {
    if (!rt || !old_f) return 0;
    char d[65];
    txid_display(old_f->funding_txid, d);
    return regtest_outpoint_unspent(rt, d, old_f->funding_vout) == 1;
}

void client_cin_chain_view(regtest_t *rt, persist_t *db,
                           const persist_client_rotation_t *row,
                           int *close_confs, int *other_confs) {
    *close_confs = -1;
    *other_confs = -1;
    if (!rt || !row || !row->close_txid[0]) return;
    *close_confs = regtest_get_confirmations(rt, row->close_txid);
    if (*close_confs >= g_cin_depth) return;
    /* Nothing more to learn while the old funding is unspent. */
    if (regtest_outpoint_unspent(rt, row->old_txid, row->old_vout) != 0) return;
    /* The close's output (the replacement funding) in the UTXO set: no
       txindex needed, however long ago it confirmed. */
    char params[128];
    snprintf(params, sizeof(params), "\"%s\" 0 false", row->close_txid);
    char *r = regtest_exec(rt, "gettxout", params);
    if (r) {
        cJSON *j = cJSON_Parse(r);
        free(r);
        const cJSON *c = j ? cJSON_GetObjectItemCaseSensitive(j, "confirmations") : NULL;
        if (cJSON_IsNumber(c) && (int)c->valuedouble > *close_confs)
            *close_confs = (int)c->valuedouble;
        cJSON_Delete(j);
    }
    if (*close_confs >= g_cin_depth) return;
    /* Transactions known by txid: the replacement's tree (descendants of the
       close) and the old factory's root and distribution TX (other spends of
       its funding). */
    int rc = replacement_txs_confs(rt, row->side_db);
    if (rc > *close_confs) *close_confs = rc;
    if (*close_confs >= g_cin_depth) return;
    if (db) {
        int oc = old_spenders_confs(rt, db);
        if (oc > *other_confs) *other_confs = oc;
        if (*other_confs >= g_cin_depth) return;
    }
    /* Otherwise the blocks since the close's height: the close (its output
       already spent) or another spend of the old funding. */
    int tip = regtest_get_block_height(rt);
    if (tip > 0 && (uint32_t)tip >= row->close_height)
        cin_scan_blocks(rt, row, tip, close_confs, other_confs);
}

/* Make SIDE the DB at DB_PATH.  The old DB gets a second name first, and the
   replacement then takes DB_PATH in one rename, so DB_PATH always holds a
   complete DB. */
static int promote(persist_t *db, const char *db_path, const char *side) {
    char pre[700];
    if (strlen(db_path) > 600) return 0;
    snprintf(pre, sizeof(pre), "%s.pre-rotation", db_path);
    for (int i = 1; access(pre, F_OK) == 0 && i < 1000; i++)
        snprintf(pre, sizeof(pre), "%s.pre-rotation.%d", db_path, i);
    if (access(side, F_OK) != 0) return 0;
    int ok = db_flush_close(db, db_path);
    if (ok) ok = link(db_path, pre) == 0;
    if (ok) {
        fsync_dir_of(db_path);
        ok = rename(side, db_path) == 0;
        if (!ok) (void)unlink(pre);
    }
    if (ok) fsync_dir_of(db_path);
    if (!persist_open(db, db_path)) {
        fprintf(stderr, "Client: CRITICAL: cannot open %s after the rotation switch (the "
                "old DB is %s)\n", db_path, pre);
        return 0;
    }
    if (ok)
        printf("Client: switched to the replacement factory (previous DB kept as %s)\n", pre);
    return ok;
}

int client_cin_resolve(persist_t *db, const char *db_path, regtest_t *rt) {
    if (!db || !db_path) return 0;
    client_cin_refresh_frozen(db);
    persist_client_rotation_t row;
    memset(&row, 0, sizeof(row));
    if (persist_client_rotation_load_open(db, &row) != 1) return 0;
    int confs = -1, other = -1;
    if (state_is_signed(row.state)) client_cin_chain_view(rt, db, &row, &confs, &other);
    if (confs < g_cin_depth && other >= g_cin_depth) {
        /* The old factory was resolved without the close (which can now
           never confirm): the rotation is over and the freeze lifted. */
        snprintf(row.state, sizeof(row.state), "abandoned");
        free(row.close_hex);
        row.close_hex = NULL;
        if (persist_client_rotation_save(db, &row))
            printf("Client: the old factory's funding was spent by another transaction "
                   "(%d confirmations); rotation close %s abandoned\n", other, row.close_txid);
        client_cin_refresh_frozen(db);
        return 0;
    }
    client_cin_action_t a = client_cin_resolve_action(row.state, confs, row.close_hex != NULL);
    int promoted = 0;
    switch (a) {
    case CLIENT_CIN_BROADCAST:
        if (rt && row.close_hex && hex_tx_has_txid(row.close_hex, row.close_txid)) {
            char t[65] = {0};
            if (regtest_send_raw_tx(rt, row.close_hex, t))
                printf("Client: broadcast the signed rotation close %s\n", row.close_txid);
        }
        break;
    case CLIENT_CIN_PROMOTE: {
        char side[256];
        snprintf(side, sizeof(side), "%s", row.side_db);
        free(row.close_hex);
        row.close_hex = NULL;
        promoted = side[0] && promote(db, db_path, side);
        if (promoted) client_cin_refresh_frozen(db);
        break;
    }
    default:
        break;
    }
    free(row.close_hex);
    return promoted;
}

void client_cin_reconnect_fields(persist_t *db, cJSON *reconnect) {
    if (!reconnect) return;
    if (client_cin_capable() && db)
        cJSON_AddNumberToObject(reconnect, "rotation_v", 1);
    if (!db) return;
    persist_client_rotation_t row;
    memset(&row, 0, sizeof(row));
    if (persist_client_rotation_load_open(db, &row) != 1) return;
    if (state_is_signed(row.state) && row.close_txid[0])
        cJSON_AddStringToObject(reconnect, "rotation_pending", row.close_txid);
    free(row.close_hex);
}

int client_cin_on_rotation_done(persist_t *db, const cJSON *done) {
    if (!db || !done) return 0;
    persist_client_rotation_t row;
    memset(&row, 0, sizeof(row));
    if (persist_client_rotation_load_open(db, &row) != 1) return 0;
    char ct[65];
    char *hex = NULL;
    int conf = 0;
    int ok = wire_parse_rotation_done(done, ct, &hex, &conf) &&
             strcmp(ct, row.close_txid) == 0 && state_is_signed(row.state);
    if (ok) {
        /* Only the signed close itself is taken (it lets us broadcast); the
           confirmation is ours to see. */
        if (hex && !row.close_hex && hex_tx_has_txid(hex, row.close_txid)) {
            row.close_hex = hex;
            hex = NULL;
            ok = persist_client_rotation_save(db, &row);
        }
        printf("Client: the LSP reports rotation close %s %s\n", ct,
               conf ? "confirmed" : "pending");
    }
    free(hex);
    free(row.close_hex);
    return ok;
}
