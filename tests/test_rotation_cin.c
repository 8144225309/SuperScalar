/* Rotation by a co-signed close into the new factory: key freshness, the
   balance carry, the close check a client runs before signing, the resume
   and resolve decisions, the records, and the wire messages. */
#include "superscalar/lsp_channels.h"
#include "superscalar/client_rotation.h"
#include "superscalar/factory_keys.h"
#include "superscalar/persist.h"
#include "superscalar/factory.h"
#include "superscalar/tx_builder.h"
#include "superscalar/wire.h"
#include "superscalar/fee_estimator.h"
#include "cJSON.h"
#include <stdio.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include "superscalar/client.h"

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern void reverse_bytes(unsigned char *data, size_t len);

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while (0)

static secp256k1_context *cin_ctx(void) {
    static secp256k1_context *c = NULL;
    if (!c) c = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    return c;
}

static int mk_pk(secp256k1_pubkey *pk, unsigned char b) {
    unsigned char s[32];
    memset(s, b, 32);
    return secp256k1_ec_pubkey_create(cin_ctx(), pk, s);
}

/* Who moves in a partial rotation: connected, able ("rotation_v" >= 2),
   not marked offline. */
int test_part_lsp_set(void) {
    lsp_t lsp;
    memset(&lsp, 0, sizeof(lsp));
    int fds[3] = { 5, 6, -1 };
    uint8_t rv[3] = { 2, 1, 2 };
    secp256k1_pubkey fpk[3], ipk[3];
    for (int i = 0; i < 3; i++)
        TEST_ASSERT(mk_pk(&fpk[i], (unsigned char)(0x21 + i)) &&
                    mk_pk(&ipk[i], (unsigned char)(0x31 + i)), "keys");
    lsp.ctx = cin_ctx();
    lsp.client_fds = fds;
    lsp.client_rotation_v = rv;
    lsp.client_pubkeys = fpk;
    lsp.client_identity_pubkeys = ipk;
    lsp.n_clients = 3;
    lsp_channel_mgr_t *mgr = calloc(1, sizeof(*mgr));
    TEST_ASSERT(mgr, "mgr");
    lsp_channel_entry_t entries[3];
    memset(entries, 0, sizeof(entries));
    mgr->entries = entries;
    mgr->n_channels = 3;
    unsigned char set[3];
    TEST_ASSERT(lsp_rotation_partial_set(mgr, &lsp, set) == 1 && set[0] && !set[1] && !set[2],
                "only the connected client that can release safely");
    ipk[0] = fpk[0];
    TEST_ASSERT(lsp_rotation_partial_set(mgr, &lsp, set) == 0 && !set[0],
                "a legacy client (factory key = identity key) never moves");
    ipk[0] = fpk[1];
    TEST_ASSERT(lsp_rotation_partial_set(mgr, &lsp, set) == 1, "a per-factory key moves");
    TEST_ASSERT(lsp_rotation_any_upgraded(&lsp), "upgraded clients: never the old turnover");
    entries[0].offline_detected = 1;
    TEST_ASSERT(lsp_rotation_partial_set(mgr, &lsp, set) == 0, "marked offline");
    rv[0] = rv[1] = rv[2] = 0;
    TEST_ASSERT(!lsp_rotation_any_upgraded(&lsp), "no upgraded client");
    free(mgr);
    return 1;
}

/* Every marker maps to the right next step. */
int test_cin_resume_action(void) {
    TEST_ASSERT(lsp_rotation_cin_resume_action(LSP_ROT_PROGRESS_CLOSED, -1, 0, 1) ==
                LSP_CIN_RESUME_NONE, "old-protocol marker");
    int pre[] = { LSP_ROT_PROGRESS_CIN_CLOSE_BUILT, LSP_ROT_PROGRESS_CIN_SIGNING,
                  LSP_ROT_PROGRESS_CIN_SIGNING_READY, LSP_ROT_PROGRESS_CIN_CLOSE_SIGNING };
    for (size_t i = 0; i < sizeof(pre) / sizeof(pre[0]); i++) {
        TEST_ASSERT(lsp_rotation_cin_resume_action(pre[i], -1, 0, 1) == LSP_CIN_RESUME_RERUN,
                    "before the close is signed: rerun over the recorded close");
        TEST_ASSERT(lsp_rotation_cin_resume_action(pre[i], -1, 0, 0) == LSP_CIN_RESUME_WAIT,
                    "... but only with every client online");
    }
    TEST_ASSERT(lsp_rotation_cin_resume_action(LSP_ROT_PROGRESS_CIN_CLOSING, 0, 0, 0) ==
                LSP_CIN_RESUME_REBROADCAST, "signed close off the network: rebroadcast");
    TEST_ASSERT(lsp_rotation_cin_resume_action(LSP_ROT_PROGRESS_CIN_CLOSING, 0, 1, 0) ==
                LSP_CIN_RESUME_WAIT, "in the mempool: wait");
    TEST_ASSERT(lsp_rotation_cin_resume_action(LSP_ROT_PROGRESS_CIN_CLOSING, 1, 0, 0) ==
                LSP_CIN_RESUME_FINISH, "confirmed: finish");
    TEST_ASSERT(lsp_rotation_cin_resume_action(LSP_ROT_PROGRESS_CIN_CLOSED, -1, 0, 0) ==
                LSP_CIN_RESUME_FINISH, "closed: finish");
    return 1;
}

/* Replacement keys must be fresh. */
int test_cin_check_keys(void) {
    secp256k1_context *ctx = cin_ctx();
    secp256k1_pubkey lsp, old[3], ids[2], fresh[2], bad[2];
    TEST_ASSERT(mk_pk(&lsp, 0x10) && mk_pk(&old[0], 0x10) && mk_pk(&old[1], 0x11) &&
                mk_pk(&old[2], 0x12) && mk_pk(&ids[0], 0x21) && mk_pk(&ids[1], 0x22) &&
                mk_pk(&fresh[0], 0x31) && mk_pk(&fresh[1], 0x32), "keys");
    const char *why = NULL;
    TEST_ASSERT(lsp_rotation_cin_check_keys(ctx, &lsp, old, 3, ids, fresh, 2, &why), "fresh ok");
    bad[0] = fresh[0]; bad[1] = old[2];
    TEST_ASSERT(!lsp_rotation_cin_check_keys(ctx, &lsp, old, 3, ids, bad, 2, &why) &&
                strstr(why, "old factory"), "old key refused");
    bad[1] = ids[0];
    TEST_ASSERT(!lsp_rotation_cin_check_keys(ctx, &lsp, old, 3, ids, bad, 2, &why) &&
                strstr(why, "identity"), "identity refused");
    bad[1] = fresh[0];
    TEST_ASSERT(!lsp_rotation_cin_check_keys(ctx, &lsp, old, 3, ids, bad, 2, &why) &&
                strstr(why, "same key"), "duplicate refused");
    bad[1] = lsp;
    TEST_ASSERT(!lsp_rotation_cin_check_keys(ctx, &lsp, old, 3, ids, bad, 2, &why) &&
                strstr(why, "LSP"), "LSP key refused");
    return 1;
}

/* The client keeps exactly its balance; a smaller replacement comes out of
   the LSP side. */
/* A close into the new factory that is not signed yet never holds back the
   retry limit or the distribution-TX fallback, and is dropped after it. */
int test_cin_preclose_fallback(void) {
    lsp_channel_mgr_t *mgr = calloc(1, sizeof(*mgr));
    TEST_ASSERT(mgr, "mgr");
    unsigned char d[32], other[32];
    memset(d, 0x33, 32);
    memset(other, 0x44, 32);
    memcpy(mgr->rot_progress.dying_funding_txid, d, 32);
    int pre[] = { LSP_ROT_PROGRESS_CIN_CLOSE_BUILT, LSP_ROT_PROGRESS_CIN_SIGNING,
                  LSP_ROT_PROGRESS_CIN_SIGNING_READY, LSP_ROT_PROGRESS_CIN_CLOSE_SIGNING };
    for (size_t i = 0; i < sizeof(pre) / sizeof(pre[0]); i++) {
        mgr->rot_progress.phase = pre[i];
        TEST_ASSERT(!lsp_rotation_progress_pending(mgr), "not past the close");
        TEST_ASSERT(lsp_rotation_progress_resumable(mgr), "still re-run");
        TEST_ASSERT(lsp_rotation_cin_preclose(mgr, d), "unsigned close of this factory");
        TEST_ASSERT(!lsp_rotation_cin_preclose(mgr, other), "not of another factory");
    }
    mgr->rot_progress.phase = LSP_ROT_PROGRESS_CIN_CLOSING;
    TEST_ASSERT(lsp_rotation_progress_pending(mgr) && !lsp_rotation_cin_preclose(mgr, d),
                "a recorded signed close is past the close");
    mgr->rot_progress.phase = LSP_ROT_PROGRESS_CIN_CLOSED;
    TEST_ASSERT(lsp_rotation_progress_pending(mgr), "confirmed close: finish");

    lsp_rotation_progress_t rp;
    memset(&rp, 0, sizeof(rp));
    TEST_ASSERT(lsp_rotation_cin_note_failure(&rp, 100, 3, 2) && rp.cin_next_try_height == 104,
                "first failure: retry after the backoff");
    TEST_ASSERT(lsp_rotation_cin_note_failure(&rp, 104, 3, 2) && rp.cin_next_try_height == 112,
                "second failure: longer backoff");
    TEST_ASSERT(lsp_rotation_cin_note_failure(&rp, 112, 3, 2), "third failure: one more try");
    TEST_ASSERT(!lsp_rotation_cin_note_failure(&rp, 128, 3, 2), "retry limit reached");

    mgr->rot_progress.phase = LSP_ROT_PROGRESS_CIN_SIGNING;
    TEST_ASSERT(!lsp_rotation_cin_abandon(mgr, other), "only its own factory's marker");
    TEST_ASSERT(lsp_rotation_cin_abandon(mgr, d) && mgr->rot_progress.phase == 0,
                "the unsigned close is dropped");
    memcpy(mgr->rot_progress.dying_funding_txid, d, 32);
    mgr->rot_progress.phase = LSP_ROT_PROGRESS_CIN_CLOSING;
    TEST_ASSERT(!lsp_rotation_cin_abandon(mgr, d), "never once the close is signed");
    lsp_rotation_progress_clear(mgr);
    free(mgr);
    return 1;
}

/* A dropped (never fully signed) close of a factory is the close a new
   attempt runs over; new channels never get a commitment fee rate below the
   anchor minimum. */
int test_cin_reuse_recorded_close(void) {
    char path[] = "/tmp/ss_cin_rr_XXXXXX";
    int fd = mkstemp(path);
    TEST_ASSERT(fd >= 0, "mkstemp");
    close(fd);
    unlink(path);
    persist_t db;
    TEST_ASSERT(persist_open(&db, path), "open");
    lsp_channel_mgr_t *mgr = calloc(1, sizeof(*mgr));
    TEST_ASSERT(mgr, "mgr");
    mgr->persist = &db;
    unsigned char d[32];
    memset(d, 0x55, 32);
    char dh[65];
    hex_encode(d, 32, dh);                  /* all 0x55: same in either byte order */
    secp256k1_pubkey a, b;
    TEST_ASSERT(mk_pk(&a, 0x21) && mk_pk(&b, 0x22), "pks");
    unsigned char sa[33], sb[33];
    size_t la = 33, lb = 33;
    secp256k1_ec_pubkey_serialize(cin_ctx(), sa, &la, &a, SECP256K1_EC_COMPRESSED);
    secp256k1_ec_pubkey_serialize(cin_ctx(), sb, &lb, &b, SECP256K1_EC_COMPRESSED);
    char parts[133];
    hex_encode(sa, 33, parts);
    hex_encode(sb, 33, parts + 66);
    const char *x = "8888888888888888888888888888888888888888888888888888888888888888";
    persist_rotation_progress_t r;
    memset(&r, 0, sizeof(r));
    r.dying_funding_vout = 1;
    r.phase = LSP_ROT_PROGRESS_DONE;          /* what an abandon leaves */
    snprintf(r.close_txid, sizeof(r.close_txid), "%s", x);
    snprintf(r.new_funding_txid, sizeof(r.new_funding_txid), "%s", x);
    r.new_funding_amount = 99000;
    TEST_ASSERT(persist_save_rotation_cin(&db, dh, parts, 700, NULL), "record");
    TEST_ASSERT(persist_save_rotation_progress(&db, dh, &r), "dropped marker");
    TEST_ASSERT(!lsp_rotation_cin_reload_recorded(mgr, d, 0, 7), "another output: nothing");
    TEST_ASSERT(lsp_rotation_cin_reload_recorded(mgr, d, 1, 7), "the dropped close is reloaded");
    TEST_ASSERT(mgr->rot_progress.phase == LSP_ROT_PROGRESS_CIN_CLOSE_BUILT &&
                strcmp(mgr->rot_progress.close_txid, x) == 0 &&
                mgr->rot_progress.cin_close_height == 700 &&
                mgr->rot_progress.new_funding_amount == 99000 &&
                mgr->rot_progress.n_cin_pubkeys == 2 &&
                mgr->rot_progress.dying_factory_id == 7,
                "same close, same height, same participants");
    TEST_ASSERT(lsp_rotation_cin_preclose(mgr, d), "a marker again: the next attempt re-runs it");
    lsp_rotation_progress_clear(mgr);
    TEST_ASSERT(persist_save_rotation_cin(&db, dh, parts, 700, "0200"), "signed record");
    TEST_ASSERT(persist_save_rotation_progress(&db, dh, &r), "marker");
    TEST_ASSERT(!lsp_rotation_cin_reload_recorded(mgr, d, 1, 7),
                "a fully signed close is not a dropped attempt");

    fee_estimator_static_t fe;
    fee_estimator_static_init(&fe, 253);
    TEST_ASSERT(lsp_rotation_commit_fee_rate(&fe.base) == CHANNEL_COMMIT_FEE_RATE_MIN,
                "a low estimate is raised to the anchor minimum");
    fee_estimator_static_init(&fe, 5000);
    TEST_ASSERT(lsp_rotation_commit_fee_rate(&fe.base) == 5000, "a normal estimate");
    fee_estimator_static_init(&fe, 10000000);
    TEST_ASSERT(lsp_rotation_commit_fee_rate(&fe.base) == CHANNEL_COMMIT_FEE_RATE_MAX,
                "capped");
    TEST_ASSERT(lsp_rotation_commit_fee_rate(NULL) == CHANNEL_COMMIT_FEE_RATE_MIN, "none");
    lsp_rotation_progress_clear(mgr);
    free(mgr);
    persist_close(&db);
    unlink(path);
    return 1;
}

int test_cin_carry(void) {
    uint64_t l = 0, c = 0;
    TEST_ASSERT(lsp_rotation_cin_carry(19038, 5038, 24076, 0, &l, &c) && l == 19038 && c == 5038,
                "same size: unchanged");
    TEST_ASSERT(lsp_rotation_cin_carry(19038, 5038, 24000, 0, &l, &c) && l == 18962 && c == 5038,
                "smaller: LSP pays the difference");
    TEST_ASSERT(!lsp_rotation_cin_carry(100, 5038, 5000, 0, &l, &c), "client balance must fit");
    TEST_ASSERT(!lsp_rotation_cin_carry(100, 5000, 5050, 100, &l, &c), "LSP side above reserve");
    return 1;
}

int test_cin_client_resolve_action(void) {
    TEST_ASSERT(client_cin_resolve_action("key_sent", -1, 0) == CLIENT_CIN_NONE, "key_sent");
    TEST_ASSERT(client_cin_resolve_action("verified", 5, 1) == CLIENT_CIN_NONE,
                "a stored replacement is kept");
    TEST_ASSERT(client_cin_resolve_action("close_signed", 0, 0) == CLIENT_CIN_WAIT, "wait");
    TEST_ASSERT(client_cin_resolve_action("close_signed", -1, 1) == CLIENT_CIN_BROADCAST,
                "broadcast the held close");
    TEST_ASSERT(client_cin_resolve_action("close_signed", 1, 0) == CLIENT_CIN_PROMOTE,
                "confirmed on chain: promote");
    TEST_ASSERT(client_cin_resolve_action("closed", -1, 0) == CLIENT_CIN_WAIT,
                "the LSP's word alone does not switch");
    TEST_ASSERT(client_cin_resolve_action("closed", 1, 0) == CLIENT_CIN_PROMOTE,
                "confirmed on our chain source: promote");
    TEST_ASSERT(client_cin_resolve_action("done", 9, 1) == CLIENT_CIN_NONE, "done");
    return 1;
}

static factory_t *old_factory(secp256k1_pubkey *pks) {
    for (int i = 0; i < 3; i++) if (!mk_pk(&pks[i], (unsigned char)(0x40 + i))) return NULL;
    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return NULL;
    factory_init_from_pubkeys(f, cin_ctx(), pks, 3, 10, 4);
    unsigned char txid[32], spk[34];
    memset(txid, 0x07, 32);
    if (!factory_funding_spk_for(cin_ctx(), pks, 3, spk)) return NULL;
    factory_set_funding(f, txid, 1, 100000, spk, 34);
    return f;
}

/* What a client checks before signing anything in a close into the new
   factory. */
int test_cin_client_check_close(void) {
    secp256k1_context *ctx = cin_ctx();
    secp256k1_pubkey opk[3], npk[3];
    factory_t *f = old_factory(opk);
    TEST_ASSERT(f, "old factory");
    npk[0] = opk[0];                                  /* same LSP */
    TEST_ASSERT(mk_pk(&npk[1], 0x51) && mk_pk(&npk[2], 0x52), "fresh keys");
    unsigned char spk[34];
    TEST_ASSERT(factory_funding_spk_for(ctx, npk, 3, spk), "new spk");
    tx_output_t out;
    memset(&out, 0, sizeof(out));
    out.amount_sats = 99800;
    memcpy(out.script_pubkey, spk, 34);
    out.script_pubkey_len = 34;
    tx_buf_t tx;
    tx_buf_init(&tx, 256);
    unsigned char sighash[32], txid[32];
    TEST_ASSERT(factory_build_cooperative_close_unsigned(f, &tx, sighash, &out, 1, 500) &&
                tx_txid_from_bytes(tx.data, tx.len, txid), "close");
    tx_buf_free(&tx);
    const char *why = NULL;
    TEST_ASSERT(client_cin_check_close(ctx, f, npk, 3, spk, 34, 99800, 0, txid, 500, &why),
                "the real close passes");
    TEST_ASSERT(!client_cin_check_close(ctx, f, npk, 3, spk, 34, 99800, 0, txid, 501, &why),
                "another height: another txid");
    TEST_ASSERT(!client_cin_check_close(ctx, f, npk, 3, spk, 34, 99800, 1, txid, 500, &why),
                "funding must be output 0");
    TEST_ASSERT(!client_cin_check_close(ctx, f, npk, 3, spk, 34, 90000, 0, txid, 500, &why) &&
                strstr(why, "fee"), "fee above 2 percent refused");
    unsigned char wrong[34];
    memcpy(wrong, spk, 34);
    wrong[10] ^= 1;
    TEST_ASSERT(!client_cin_check_close(ctx, f, npk, 3, wrong, 34, 99800, 0, txid, 500, &why),
                "funding must be the participants' key");
    secp256k1_pubkey reuse[3] = { opk[0], npk[1], opk[2] };
    TEST_ASSERT(!client_cin_check_close(ctx, f, reuse, 3, spk, 34, 99800, 0, txid, 500, &why) &&
                strstr(why, "reused"), "old key reuse refused");
    secp256k1_pubkey nolsp[3] = { npk[1], npk[2], npk[1] };
    TEST_ASSERT(!client_cin_check_close(ctx, f, nolsp, 3, spk, 34, 99800, 0, txid, 500, &why),
                "slot 0 must be the LSP");
    factory_free(f);
    free(f);
    return 1;
}

static int tmp_db(char *path, persist_t *db) {
    int fd = mkstemp(path);
    if (fd < 0) return 0;
    close(fd);
    unlink(path);
    return persist_open(db, path);
}

static void touch(const char *p) {
    FILE *f = fopen(p, "w");
    if (f) { fputs("x", f); fclose(f); }
}

/* A malicious LSP reports the close confirmed (and sends a bogus close):
   without its own confirmation the client neither switches nor stops
   guarding the old factory, and keeps it frozen. */
int test_cin_client_no_switch_on_lsp_word(void) {
    char path[] = "/tmp/ss_cin_lw_XXXXXX";
    persist_t db;
    TEST_ASSERT(tmp_db(path, &db), "db");
    char side[64], pre[64];
    snprintf(side, sizeof(side), "%s.rotation", path);
    snprintf(pre, sizeof(pre), "%s.pre-rotation", path);
    touch(side);
    const char *x = "3333333333333333333333333333333333333333333333333333333333333333";
    persist_client_rotation_t r;
    memset(&r, 0, sizeof(r));
    snprintf(r.old_txid, sizeof(r.old_txid), "%s", "4444444444444444444444444444444444444444444444444444444444444444");
    snprintf(r.close_txid, sizeof(r.close_txid), "%s", x);
    snprintf(r.state, sizeof(r.state), "close_signed");
    snprintf(r.side_db, sizeof(r.side_db), "%s", side);
    TEST_ASSERT(persist_client_rotation_save(&db, &r), "row");
    cJSON *done = cJSON_CreateObject();
    cJSON_AddStringToObject(done, "close_txid", x);
    cJSON_AddStringToObject(done, "close_hex", "0200000000010000000000");
    cJSON_AddBoolToObject(done, "confirmed", 1);
    TEST_ASSERT(client_cin_on_rotation_done(&db, done) == 1, "matches the pending close");
    cJSON_Delete(done);
    persist_client_rotation_t b;
    memset(&b, 0, sizeof(b));
    TEST_ASSERT(persist_client_rotation_load_open(&db, &b) == 1 && b.close_hex == NULL &&
                strcmp(b.state, "close_signed") == 0,
                "a close whose txid is not the close is not kept; the state stays");
    free(b.close_hex);
    TEST_ASSERT(client_cin_resolve(&db, path, NULL) == 0, "no switch on the LSP's word");
    TEST_ASSERT(access(pre, F_OK) != 0 && access(side, F_OK) == 0, "both DBs untouched");
    TEST_ASSERT(client_cin_frozen(), "the old channel is frozen");

    client_cin_set_capable(0);
    cJSON *rc = cJSON_CreateObject();
    client_cin_reconnect_fields(&db, rc);
    TEST_ASSERT(!cJSON_GetObjectItemCaseSensitive(rc, "rotation_v") &&
                cJSON_GetObjectItemCaseSensitive(rc, "rotation_pending"),
                "no rotation_v without a chain source; the pending close is reported");
    cJSON_Delete(rc);
    client_cin_set_capable(1);
    rc = cJSON_CreateObject();
    client_cin_reconnect_fields(&db, rc);
    TEST_ASSERT(cJSON_GetObjectItemCaseSensitive(rc, "rotation_v"), "able: rotation_v");
    cJSON_Delete(rc);
    client_cin_set_capable(0);
    client_cin_refresh_frozen(NULL);
    persist_close(&db);
    unlink(side);
    unlink(path);
    return 1;
}

static factory_t *repl_factory(const secp256k1_pubkey *pks, uint64_t fee_per_tx) {
    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return NULL;
    factory_init_from_pubkeys(f, cin_ctx(), pks, 3, 10, 4);
    unsigned char txid[32], spk[34];
    memset(txid, 0x09, 32);
    if (!factory_funding_spk_for(cin_ctx(), pks, 3, spk)) return NULL;
    factory_set_funding(f, txid, 0, 100000, spk, 34);
    f->cltv_timeout = 2000;
    f->fee_per_tx = fee_per_tx;
    if (!factory_build_tree(f)) { factory_free(f); free(f); return NULL; }
    return f;
}

/* A malicious LSP gets a second, different tree signed over the same close:
   the client signs only the first tree over each close, and a stored
   replacement is never dropped while the old factory is unresolved. */
int test_cin_client_one_tree_per_close(void) {
    char path[] = "/tmp/ss_cin_ot_XXXXXX";
    persist_t db;
    TEST_ASSERT(tmp_db(path, &db), "db");
    char side[64];
    snprintf(side, sizeof(side), "%s.rotation", path);
    touch(side);
    persist_client_rotation_t r;
    memset(&r, 0, sizeof(r));
    snprintf(r.old_txid, sizeof(r.old_txid), "%s", "5555555555555555555555555555555555555555555555555555555555555555");
    snprintf(r.close_txid, sizeof(r.close_txid), "%s", "6666666666666666666666666666666666666666666666666666666666666666");
    snprintf(r.state, sizeof(r.state), "verified");
    snprintf(r.side_db, sizeof(r.side_db), "%s", side);
    TEST_ASSERT(persist_client_rotation_save(&db, &r), "row");
    (void)client_cin_resolve(&db, path, NULL);
    persist_client_rotation_t b;
    memset(&b, 0, sizeof(b));
    TEST_ASSERT(access(side, F_OK) == 0, "the replacement of a signed tree is kept");
    TEST_ASSERT(persist_client_rotation_load_open(&db, &b) == 1 &&
                strcmp(b.state, "verified") == 0 && strcmp(b.side_db, side) == 0,
                "the row still points at it");
    free(b.close_hex);

    secp256k1_pubkey pks[3];
    for (int i = 0; i < 3; i++) TEST_ASSERT(mk_pk(&pks[i], (unsigned char)(0x70 + i)), "pk");
    factory_t *t1 = repl_factory(pks, 200), *t2 = repl_factory(pks, 300);
    TEST_ASSERT(t1 && t2, "two trees over the same funding");
    char d1[65], d2[65];
    TEST_ASSERT(client_cin_tree_digest(t1, d1) && client_cin_tree_digest(t2, d2) &&
                strcmp(d1, d2) != 0, "the trees differ");
    const char *x = r.close_txid;
    TEST_ASSERT(client_cin_bind_tree(&db, x, t1), "the first tree over the close");
    TEST_ASSERT(client_cin_bind_tree(&db, x, t1), "the same tree again (a re-run)");
    TEST_ASSERT(!client_cin_bind_tree(&db, x, t2), "a different tree over the same close");
    factory_free(t1); free(t1);
    factory_free(t2); free(t2);
    persist_close(&db);
    unlink(side);
    unlink(path);
    return 1;
}

/* After its close signature is out the client's old channel takes no
   payment and no other rotation; the close may not be dated in the future. */
int test_cin_client_freeze(void) {
    TEST_ASSERT(client_cin_check_close_height(100, 99), "at the tip + 1");
    TEST_ASSERT(!client_cin_check_close_height(101, 99), "a future locktime is refused");
    TEST_ASSERT(!client_cin_check_close_height(5, -1), "no tip: refused");
    char path[] = "/tmp/ss_cin_fz_XXXXXX";
    persist_t db;
    TEST_ASSERT(tmp_db(path, &db), "db");
    persist_client_rotation_t r;
    memset(&r, 0, sizeof(r));
    snprintf(r.old_txid, sizeof(r.old_txid), "%s", "7777777777777777777777777777777777777777777777777777777777777777");
    snprintf(r.state, sizeof(r.state), "verified");
    TEST_ASSERT(persist_client_rotation_save(&db, &r), "row");
    client_cin_refresh_frozen(&db);
    wire_msg_t m;
    memset(&m, 0, sizeof(m));
    m.msg_type = MSG_UPDATE_ADD_HTLC;
    m.json = cJSON_CreateObject();
    unsigned char oldf[32], otherf[32];
    memset(oldf, 0x77, 32);
    memset(otherf, 0x78, 32);
    TEST_ASSERT(!client_cin_frozen() && !client_cin_refuse_while_frozen(&m, oldf),
                "nothing signed: the channel is live");
    snprintf(r.state, sizeof(r.state), "close_signed");
    TEST_ASSERT(persist_client_rotation_save(&db, &r), "row");
    client_cin_refresh_frozen(&db);
    TEST_ASSERT(client_cin_frozen() && client_cin_refuse_while_frozen(&m, oldf),
                "signed: an incoming payment is refused");
    TEST_ASSERT(!client_cin_frozen_for(otherf) && !client_cin_refuse_while_frozen(&m, otherf),
                "another factory is not frozen");
    m.msg_type = MSG_PTLC_PRESIG;
    TEST_ASSERT(client_cin_refuse_while_frozen(&m, oldf), "and a key turnover");
    m.msg_type = MSG_FACTORY_PROPOSE;
    TEST_ASSERT(client_cin_refuse_while_frozen(&m, oldf), "and another rotation");
    cJSON *rot = cJSON_AddObjectToObject(m.json, "rotation");
    cJSON_AddStringToObject(rot, "mode", "close_into_new");
    TEST_ASSERT(!client_cin_refuse_while_frozen(&m, oldf), "the same close may be re-run");
    m.msg_type = MSG_ROTATION_BEGIN;
    TEST_ASSERT(client_cin_refuse_while_frozen(&m, oldf), "a legacy rotation begin");
    cJSON_AddStringToObject(m.json, "mode", "close_into_new");
    TEST_ASSERT(!client_cin_refuse_while_frozen(&m, oldf), "the close-into-new begin");
    cJSON_Delete(m.json);
    client_cin_refresh_frozen(NULL);
    persist_close(&db);
    unlink(path);
    return 1;
}

/* A malicious LSP's CHANNEL_READY balances that overrun the leaf output (or
   leave out the commitment fee) give a commitment that cannot be mined. */
int test_cin_channel_amounts_exact(void) {
    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.funding_amount = 24214;
    ch.fee_rate_sat_per_kvb = 1000;
    ch.local_amount = 19022;
    ch.remote_amount = 5038;
    TEST_ASSERT(client_channel_amounts_exact(&ch), "balances + 154 sat fee = funding");
    ch.local_amount = 19023;
    TEST_ASSERT(!client_channel_amounts_exact(&ch), "outputs above the leaf");
    ch.local_amount = 19021;
    TEST_ASSERT(!client_channel_amounts_exact(&ch), "not exact");
    ch.fee_rate_sat_per_kvb = 2000;
    ch.local_amount = 19022 - 154;
    TEST_ASSERT(client_channel_amounts_exact(&ch), "the fee follows the rate");
    ch.n_htlcs = 1;
    TEST_ASSERT(!client_channel_amounts_exact(&ch), "no HTLC on a new channel");
    ch.n_htlcs = 0;
    ch.local_amount = UINT64_MAX - 3;
    TEST_ASSERT(!client_channel_amounts_exact(&ch), "no overflow");
    ch.fee_rate_sat_per_kvb = 0;
    ch.local_amount = 24214 - 5038;
    TEST_ASSERT(!client_channel_amounts_exact(&ch),
                "rate 0: a commitment with no fee and no anchor is refused");
    ch.fee_rate_sat_per_kvb = 999;
    ch.local_amount = 19022;
    TEST_ASSERT(!client_channel_amounts_exact(&ch), "rate 999: no anchor, refused");
    ch.fee_rate_sat_per_kvb = CHANNEL_COMMIT_FEE_RATE_MAX + 1;
    ch.local_amount = 24214 - 5038 - (((uint64_t)CHANNEL_COMMIT_FEE_RATE_MAX + 1) * 154 + 999) / 1000;
    TEST_ASSERT(!client_channel_amounts_exact(&ch), "above the cap, refused");
    return 1;
}

/* A malicious LSP's proposal with case-variant funding keys: the client
   never builds (or signs) a tree over a funding other than the checked one. */
int test_cin_client_ambiguous_proposal(void) {
    secp256k1_context *ctx = cin_ctx();
    secp256k1_pubkey pks[3];
    unsigned char sec[32];
    memset(sec, 0x71, 32);
    secp256k1_keypair kp;
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kp, sec), "kp");
    TEST_ASSERT(mk_pk(&pks[0], 0x70) && mk_pk(&pks[1], 0x71) && mk_pk(&pks[2], 0x72), "pks");
    unsigned char spk[34], txid[32];
    TEST_ASSERT(factory_funding_spk_for(ctx, pks, 3, spk), "spk");
    memset(txid, 0x09, 32);
    char spk_hex[69], txid_hex[65];
    hex_encode(spk, 34, spk_hex);
    unsigned char rev[32];
    memcpy(rev, txid, 32);
    reverse_bytes(rev, 32);
    hex_encode(rev, 32, txid_hex);
    char js[1024];
    snprintf(js, sizeof(js),
             "{\"FUNDING_AMOUNT\":150000,\"Funding_Vout\":1,\"funding_amount\":200000,"
             "\"funding_vout\":0,\"funding_txid\":\"%s\",\"funding_spk\":\"%s\","
             "\"step_blocks\":10,\"states_per_layer\":4,\"cltv_timeout\":2000,"
             "\"fee_per_tx\":200}", txid_hex, spk_hex);
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    shutdown(sv[1], SHUT_WR);
    wire_msg_t m;
    memset(&m, 0, sizeof(m));
    m.msg_type = MSG_FACTORY_PROPOSE;
    m.json = cJSON_Parse(js);
    factory_t *nf = calloc(1, sizeof(factory_t));
    channel_t *nc = calloc(1, sizeof(channel_t));
    TEST_ASSERT(m.json && nf && nc, "setup");
    int r = client_do_factory_rotation(sv[0], ctx, &kp, 1, 3, pks, nf, nc, &m);
    TEST_ASSERT(r == 0, "refused");
    TEST_ASSERT(nf->funding_vout != 1 && nf->funding_amount_sats != 150000,
                "no tree over the case-variant funding");
    factory_free(nf);
    cJSON_Delete(m.json);

    /* A lying proposal with a bound funding: the tree is built over the
       checked funding, whatever the proposal says. */
    snprintf(js, sizeof(js),
             "{\"funding_amount\":150000,\"funding_vout\":1,\"funding_txid\":\"%s\","
             "\"funding_spk\":\"%s\",\"step_blocks\":10,\"states_per_layer\":4,"
             "\"cltv_timeout\":2000,\"fee_per_tx\":200}", txid_hex, spk_hex);
    m.json = cJSON_Parse(js);
    client_funding_bind_t bind;
    memset(&bind, 0, sizeof(bind));
    memcpy(bind.txid, txid, 32);
    bind.vout = 0;
    bind.amount = 200000;
    memcpy(bind.spk, spk, 34);
    memset(nf, 0, sizeof(*nf));
    r = client_do_factory_rotation_bound(sv[0], ctx, &kp, 1, 3, pks, nf, nc, &m, &bind);
    TEST_ASSERT(r == 0, "no LSP on the other end");
    TEST_ASSERT(nf->funding_vout == 0 && nf->funding_amount_sats == 200000 &&
                memcmp(nf->funding_txid, txid, 32) == 0, "built over the checked funding");
    factory_free(nf);
    free(nf);
    free(nc);
    cJSON_Delete(m.json);
    close(sv[0]);
    close(sv[1]);
    return 1;
}

/* A stand-in bitcoin-cli: block hashes are the height in hex, one block
   (SS_FAKE_HEIGHT) holds SS_FAKE_BLOCK, gettxout answers SS_FAKE_TXOUT for
   SS_FAKE_TXOUT_FOR and "spent" otherwise; no wallet, no txindex. */
static int fake_cli(char *path) {
    int fd = mkstemp(path);
    if (fd < 0) return 0;
    const char *sh =
        "#!/bin/sh\n"
        "set -- $(for a in \"$@\"; do case \"$a\" in -*) ;; *) printf '%s\\n' \"$a\";; esac; done)\n"
        "m=$1; shift\n"
        "case \"$m\" in\n"
        "getblockcount) echo \"$SS_FAKE_TIP\";;\n"
        "getblockchaininfo) echo \"${SS_FAKE_CHAININFO:-{}}\";;\n"
        "getblockhash) printf '%064x\\n' \"$1\";;\n"
        "getblock) h=$(echo \"$1\" | tr -d '\"'); n=$((0x$(echo \"$h\" | cut -c57-64)));\n"
        "  if [ -n \"$SS_FAKE_PRUNED_BELOW\" ] && [ \"$n\" -lt \"$SS_FAKE_PRUNED_BELOW\" ]; then exit 1; fi;\n"
        "  if [ \"$n\" = \"$SS_FAKE_HEIGHT\" ]; then echo \"$SS_FAKE_BLOCK\"; else echo '{\"tx\":[]}'; fi;;\n"
        "gettxout) if [ -n \"$SS_FAKE_TXOUT_FOR\" ] && echo \"$1\" | grep -q \"$SS_FAKE_TXOUT_FOR\"; then echo \"$SS_FAKE_TXOUT\"; else echo null; fi;;\n"
        "*) exit 1;;\n"
        "esac\n";
    int ok = write(fd, sh, strlen(sh)) == (ssize_t)strlen(sh);
    close(fd);
    return ok && chmod(path, 0700) == 0;
}

/* The client finds its close (or another spend of the old funding) however
   long it was away, without txindex: a close mined 110 blocks ago whose
   output is spent too, the close's output still unspent, and the old funding
   taken by another transaction (the rotation ends and the freeze lifts). */
int test_cin_client_chain_view(void) {
    char cli[] = "/tmp/ss_cin_cli_XXXXXX";
    TEST_ASSERT(fake_cli(cli), "fake cli");
    regtest_t rt;
    memset(&rt, 0, sizeof(rt));
    snprintf(rt.cli_path, sizeof(rt.cli_path), "%s", cli);
    snprintf(rt.network, sizeof(rt.network), "regtest");
    const char *old = "9999999999999999999999999999999999999999999999999999999999999999";
    const char *x = "aaaa999999999999999999999999999999999999999999999999999999999999";
    persist_client_rotation_t r;
    memset(&r, 0, sizeof(r));
    snprintf(r.old_txid, sizeof(r.old_txid), "%s", old);
    r.old_vout = 1;
    snprintf(r.close_txid, sizeof(r.close_txid), "%s", x);
    snprintf(r.state, sizeof(r.state), "close_signed");
    r.close_height = 5;
    char blk[512];
    snprintf(blk, sizeof(blk), "{\"tx\":[{\"txid\":\"%s\",\"vin\":[{\"txid\":\"%s\",\"vout\":1}]}]}",
             x, old);
    setenv("SS_FAKE_TIP", "120", 1);
    setenv("SS_FAKE_HEIGHT", "10", 1);
    setenv("SS_FAKE_BLOCK", blk, 1);
    unsetenv("SS_FAKE_TXOUT_FOR");
    int cc = -1, oc = -1;
    client_cin_chain_view(&rt, NULL, &r, &cc, &oc);
    TEST_ASSERT(cc == 111 && oc == -1, "a close 110 blocks deep (its output spent) is found");

    setenv("SS_FAKE_TXOUT_FOR", x, 1);
    setenv("SS_FAKE_TXOUT", "{\"confirmations\": 50}", 1);
    setenv("SS_FAKE_HEIGHT", "0", 1);
    client_cin_chain_view(&rt, NULL, &r, &cc, &oc);
    TEST_ASSERT(cc == 50, "the close's output in the UTXO set gives its depth");
    unsetenv("SS_FAKE_TXOUT_FOR");

    char path[] = "/tmp/ss_cin_cv_XXXXXX";
    persist_t db;
    TEST_ASSERT(tmp_db(path, &db), "db");
    char side[64];
    snprintf(side, sizeof(side), "%s.rotation", path);
    touch(side);
    snprintf(r.side_db, sizeof(r.side_db), "%s", side);
    TEST_ASSERT(persist_client_rotation_save(&db, &r), "row");
    snprintf(blk, sizeof(blk), "{\"tx\":[{\"txid\":\"%s\",\"vin\":[{\"txid\":\"%s\",\"vout\":1}]}]}",
             "bbbb999999999999999999999999999999999999999999999999999999999999", old);
    setenv("SS_FAKE_BLOCK", blk, 1);
    setenv("SS_FAKE_HEIGHT", "100", 1);
    client_cin_refresh_frozen(&db);
    TEST_ASSERT(client_cin_frozen(), "frozen while the close may confirm");
    TEST_ASSERT(client_cin_resolve(&db, path, &rt) == 0, "no switch");
    persist_client_rotation_t b;
    memset(&b, 0, sizeof(b));
    TEST_ASSERT(persist_client_rotation_load(&db, old, &b) == 1 &&
                strcmp(b.state, "abandoned") == 0 && b.close_height == 5,
                "the old funding spent by another transaction: rotation abandoned");
    free(b.close_hex);
    TEST_ASSERT(!client_cin_frozen(), "and the old channel unfrozen");
    TEST_ASSERT(access(side, F_OK) == 0, "the stored replacement stays on disk");
    unsetenv("SS_FAKE_TIP");
    unsetenv("SS_FAKE_HEIGHT");
    unsetenv("SS_FAKE_BLOCK");
    unsetenv("SS_FAKE_TXOUT");
    persist_close(&db);
    unlink(side);
    unlink(path);
    unlink(cli);
    return 1;
}

/* On a pruned node, after a long absence, with the close's output already
   spent by the replacement's kickoff: the pruned blocks are skipped, the
   close is still found in a later block, and the transactions the client
   knows by txid (the replacement's tree, the old tree's root) are looked up
   directly.  A proposal whose old funding is already spent is refused. */
int test_cin_client_chain_view_pruned(void) {
    char cli[] = "/tmp/ss_cin_cli_XXXXXX";
    TEST_ASSERT(fake_cli(cli), "fake cli");
    regtest_t rt;
    memset(&rt, 0, sizeof(rt));
    snprintf(rt.cli_path, sizeof(rt.cli_path), "%s", cli);
    snprintf(rt.network, sizeof(rt.network), "regtest");
    const char *old = "9898989898989898989898989898989898989898989898989898989898989898";
    const char *x = "cccc989898989898989898989898989898989898989898989898989898989898";
    persist_client_rotation_t r;
    memset(&r, 0, sizeof(r));
    snprintf(r.old_txid, sizeof(r.old_txid), "%s", old);
    r.old_vout = 1;
    snprintf(r.close_txid, sizeof(r.close_txid), "%s", x);
    snprintf(r.state, sizeof(r.state), "close_signed");
    r.close_height = 5;
    char blk[512];
    snprintf(blk, sizeof(blk), "{\"tx\":[{\"txid\":\"%s\",\"vin\":[{\"txid\":\"%s\",\"vout\":1}]}]}",
             x, old);
    setenv("SS_FAKE_TIP", "120", 1);
    setenv("SS_FAKE_HEIGHT", "60", 1);
    setenv("SS_FAKE_BLOCK", blk, 1);
    setenv("SS_FAKE_PRUNED_BELOW", "50", 1);
    setenv("SS_FAKE_CHAININFO", "{\"pruned\":true,\"pruneheight\":50}", 1);
    unsetenv("SS_FAKE_TXOUT_FOR");
    int cc = -1, oc = -1;
    client_cin_chain_view(&rt, NULL, &r, &cc, &oc);
    TEST_ASSERT(cc == 61, "pruned blocks are skipped and the close is found after them");

    /* The close's block is pruned too, but the replacement's root (side DB)
       has an unspent output. */
    setenv("SS_FAKE_PRUNED_BELOW", "100", 1);
    setenv("SS_FAKE_CHAININFO", "{\"pruned\":true,\"pruneheight\":100}", 1);
    char side[] = "/tmp/ss_cin_sd_XXXXXX";
    persist_t s;
    TEST_ASSERT(tmp_db(side, &s), "side db");
    secp256k1_pubkey pks[3];
    for (int i = 0; i < 3; i++) TEST_ASSERT(mk_pk(&pks[i], (unsigned char)(0x30 + i)), "pk");
    factory_t *f = repl_factory(pks, 200);
    TEST_ASSERT(f && persist_save_tree_nodes(&s, f, 0), "the replacement's tree");
    unsigned char t[32], rv[32];
    char root[65];
    TEST_ASSERT(tx_txid_from_bytes(f->nodes[0].unsigned_tx.data, f->nodes[0].unsigned_tx.len, t),
                "root txid");
    memcpy(rv, t, 32);
    reverse_bytes(rv, 32);
    hex_encode(rv, 32, root);
    persist_close(&s);
    factory_free(f);
    free(f);
    snprintf(r.side_db, sizeof(r.side_db), "%s", side);
    setenv("SS_FAKE_TXOUT_FOR", root, 1);
    setenv("SS_FAKE_TXOUT", "{\"confirmations\": 40}", 1);
    cc = oc = -1;
    client_cin_chain_view(&rt, NULL, &r, &cc, &oc);
    TEST_ASSERT(cc == 40, "the replacement's root gives the close's depth");

    /* The old tree's root (main DB) spent the old funding instead. */
    char mainp[] = "/tmp/ss_cin_md_XXXXXX";
    persist_t m;
    TEST_ASSERT(tmp_db(mainp, &m), "main db");
    for (int i = 0; i < 3; i++) TEST_ASSERT(mk_pk(&pks[i], (unsigned char)(0x38 + i)), "pk");
    f = repl_factory(pks, 300);
    TEST_ASSERT(f && persist_save_tree_nodes(&m, f, 0), "the old tree");
    TEST_ASSERT(tx_txid_from_bytes(f->nodes[0].unsigned_tx.data, f->nodes[0].unsigned_tx.len, t),
                "old root txid");
    memcpy(rv, t, 32);
    reverse_bytes(rv, 32);
    char oroot[65];
    hex_encode(rv, 32, oroot);
    factory_free(f);
    free(f);
    r.side_db[0] = '\0';
    setenv("SS_FAKE_TXOUT_FOR", oroot, 1);
    setenv("SS_FAKE_TXOUT", "{\"confirmations\": 30}", 1);
    cc = oc = -1;
    client_cin_chain_view(&rt, &m, &r, &cc, &oc);
    TEST_ASSERT(cc < 1 && oc == 30, "the old tree's root is another spend of the old funding");
    persist_close(&m);

    /* A proposal over an already spent old funding is refused. */
    factory_t of;
    memset(&of, 0, sizeof(of));
    memset(of.funding_txid, 0x98, 32);
    of.funding_vout = 1;
    setenv("SS_FAKE_TXOUT_FOR", old, 1);
    setenv("SS_FAKE_TXOUT", "{\"confirmations\": 9, \"value\": 0.001}", 1);
    TEST_ASSERT(client_cin_old_funding_unspent(&rt, &of), "unspent: the rotation may run");
    unsetenv("SS_FAKE_TXOUT_FOR");
    TEST_ASSERT(!client_cin_old_funding_unspent(&rt, &of), "spent: refused");

    unsetenv("SS_FAKE_TIP");
    unsetenv("SS_FAKE_HEIGHT");
    unsetenv("SS_FAKE_BLOCK");
    unsetenv("SS_FAKE_TXOUT");
    unsetenv("SS_FAKE_PRUNED_BELOW");
    unsetenv("SS_FAKE_CHAININFO");
    unlink(side);
    unlink(mainp);
    unlink(cli);
    return 1;
}

/* No rotation while an HTLC is in flight, on either side. */
int test_cin_htlc_quiescence(void) {
    lsp_channel_mgr_t *mgr = calloc(1, sizeof(*mgr));
    TEST_ASSERT(mgr, "mgr");
    lsp_channel_entry_t entries[2];
    memset(entries, 0, sizeof(entries));
    htlc_t h[1];
    memset(h, 0, sizeof(h));
    h[0].state = HTLC_STATE_ACTIVE;
    entries[1].channel.htlcs = h;
    entries[1].channel.n_htlcs = 1;
    mgr->entries = entries;
    mgr->n_channels = 2;
    TEST_ASSERT(!lsp_rotation_channels_quiet(mgr, NULL), "an HTLC in flight: wait");
    unsigned char set[2] = { 1, 0 };
    TEST_ASSERT(lsp_rotation_channels_quiet(mgr, set), "not a channel of the rotation");
    TEST_ASSERT(!client_cin_channel_quiet(&entries[1].channel), "client: refused");
    TEST_ASSERT(client_cin_channel_quiet(&entries[0].channel), "client: no HTLC");
    TEST_ASSERT(!client_cin_channel_quiet(NULL), "client: no channel");
    h[0].state = HTLC_STATE_FULFILLED;
    TEST_ASSERT(lsp_rotation_channels_quiet(mgr, NULL) &&
                client_cin_channel_quiet(&entries[1].channel), "settled: go");
    free(mgr);
    return 1;
}

/* The partial rotation's messages, its release binding, and released keys
   sealed at rest. */
int test_part_records(void) {
    unsigned char t[32], b[32], sig[64], t2[32], b2[32], sig2[64], sk[32], sk2[32];
    memset(t, 0x11, 32); memset(b, 0x22, 32); memset(sig, 0x33, 64); memset(sk, 0x44, 32);
    cJSON *j = wire_build_rotation_release_req(t, b, sig);
    TEST_ASSERT(j && wire_parse_rotation_release_req(j, t2, b2, sig2) &&
                memcmp(t, t2, 32) == 0 && memcmp(b, b2, 32) == 0 && memcmp(sig, sig2, 64) == 0,
                "release request round trip");
    cJSON_Delete(j);
    j = wire_build_rotation_release(b, sk);
    TEST_ASSERT(j && wire_parse_rotation_release(j, b2, sk2) && memcmp(sk, sk2, 32) == 0,
                "release round trip");
    cJSON_Delete(j);

    unsigned char pk[33], d[32], r1[32], r2[32];
    memset(pk, 0x02, 33); memset(d, 0x55, 32);
    factory_release_binding(t, 1, b, 0, d, pk, 5000, 2, r1);
    factory_release_binding(t, 1, b, 0, d, pk, 5000, 2, r2);
    TEST_ASSERT(memcmp(r1, r2, 32) == 0, "deterministic");
    factory_release_binding(t, 1, b, 0, d, pk, 4999, 2, r2);
    TEST_ASSERT(memcmp(r1, r2, 32) != 0, "bound to the carried balance");
    factory_release_binding(t, 1, b, 0, d, pk, 5000, 3, r2);
    TEST_ASSERT(memcmp(r1, r2, 32) != 0, "bound to the slot");

    char path[] = "/tmp/ss_part_rec_XXXXXX";
    int fd = mkstemp(path);
    TEST_ASSERT(fd >= 0, "mkstemp");
    close(fd);
    unlink(path);
    persist_t db;
    TEST_ASSERT(persist_open(&db, path), "open");
    unsigned char seal[32];
    memset(seal, 0x66, 32);
    persist_set_departed_seal_key(&db, seal);
    TEST_ASSERT(persist_save_departed_client(&db, 3, 1, sk), "save a released key");
    sqlite3_stmt *st;
    TEST_ASSERT(sqlite3_prepare_v2(db.db, "SELECT extracted_key FROM departed_clients;", -1,
                                   &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW,
                "row");
    char stored[256];
    snprintf(stored, sizeof(stored), "%s", (const char *)sqlite3_column_text(st, 0));
    sqlite3_finalize(st);
    char plain[65];
    hex_encode(sk, 32, plain);
    TEST_ASSERT(strncmp(stored, "dk1:", 4) == 0 && !strstr(stored, plain), "sealed, not plaintext");
    int dep[4] = {0};
    unsigned char keys[4][32];
    memset(keys, 0, sizeof(keys));
    TEST_ASSERT(persist_load_departed_clients(&db, 3, dep, keys, 4) == 1 && dep[1] &&
                memcmp(keys[1], sk, 32) == 0, "unsealed on load");
    persist_close(&db);
    unlink(path);
    return 1;
}

/* The LSP and client records, and the DB snapshot. */
int test_cin_records(void) {
    char path[] = "/tmp/ss_cin_rec_XXXXXX";
    int fd = mkstemp(path);
    TEST_ASSERT(fd >= 0, "mkstemp");
    close(fd);
    unlink(path);
    persist_t db;
    TEST_ASSERT(persist_open(&db, path), "open");
    const char *dying = "11111111111111111111111111111111111111111111111111111111111111aa";
    const char *newf = "22222222222222222222222222222222222222222222222222222222222222bb";
    TEST_ASSERT(persist_save_rotation_cin(&db, dying, "02abcd", 777, NULL), "save cin");
    char *ph = NULL, *sh = NULL;
    uint32_t h = 0;
    TEST_ASSERT(persist_load_rotation_cin(&db, dying, &ph, &h, &sh) == 1 && ph &&
                strcmp(ph, "02abcd") == 0 && h == 777 && sh == NULL, "load cin");
    free(ph);
    TEST_ASSERT(persist_save_rotation_cin(&db, dying, "02abcd", 777, "0200aa"), "signed close");
    TEST_ASSERT(persist_load_rotation_cin(&db, dying, NULL, NULL, &sh) == 1 && sh &&
                strcmp(sh, "0200aa") == 0, "signed close kept");
    free(sh);
    persist_rotation_progress_t r;
    memset(&r, 0, sizeof(r));
    r.phase = LSP_ROT_PROGRESS_CLOSING;
    snprintf(r.new_funding_txid, 65, "%s", newf);
    snprintf(r.close_txid, 65, "%s", newf);
    TEST_ASSERT(persist_save_rotation_progress(&db, dying, &r), "progress");
    char found[65];
    TEST_ASSERT(persist_find_rotation_by_new_funding(&db, newf, found) == 1 &&
                strcmp(found, dying) == 0, "found by the replacement funding");
    TEST_ASSERT(persist_find_rotation_by_new_funding(&db, dying, found) == 0, "none");

    persist_client_rotation_t c;
    memset(&c, 0, sizeof(c));
    snprintf(c.old_txid, 65, "%s", dying);
    c.old_vout = 1;
    c.key_index = 3;
    snprintf(c.state, sizeof(c.state), "key_sent");
    TEST_ASSERT(persist_client_rotation_save(&db, &c), "client row");
    persist_client_rotation_t b;
    memset(&b, 0, sizeof(b));
    TEST_ASSERT(persist_client_rotation_load_open(&db, &b) == 1 && b.key_index == 3 &&
                strcmp(b.state, "key_sent") == 0 && b.close_hex == NULL, "open row");
    snprintf(c.state, sizeof(c.state), "close_signed");
    snprintf(c.close_txid, 65, "%s", newf);
    c.close_hex = "0200";
    TEST_ASSERT(persist_client_rotation_save(&db, &c), "update");
    memset(&b, 0, sizeof(b));
    TEST_ASSERT(persist_client_rotation_load(&db, dying, &b) == 1 &&
                strcmp(b.close_txid, newf) == 0 && b.close_hex &&
                strcmp(b.close_hex, "0200") == 0, "reload");
    free(b.close_hex);
    snprintf(c.state, sizeof(c.state), "done");
    c.close_hex = NULL;
    TEST_ASSERT(persist_client_rotation_save(&db, &c), "done");
    TEST_ASSERT(persist_client_rotation_load_open(&db, &b) == 0, "no open row when done");

    char snap[64];
    snprintf(snap, sizeof(snap), "%s.snap", path);
    unlink(snap);
    TEST_ASSERT(persist_snapshot_to(&db, snap), "snapshot");
    persist_t s2;
    TEST_ASSERT(persist_open(&s2, snap), "open snapshot");
    TEST_ASSERT(persist_load_rotation_cin(&s2, dying, NULL, NULL, NULL) == 1, "snapshot holds rows");
    persist_close(&s2);
    persist_close(&db);
    unlink(snap);
    unlink(path);
    return 1;
}

/* A client binds the first tree it signs over a replacement funding. */
int test_cin_tree_bind_record(void) {
    char path[] = "/tmp/ss_cin_tb_XXXXXX";
    int fd = mkstemp(path);
    TEST_ASSERT(fd >= 0, "mkstemp");
    close(fd);
    unlink(path);
    persist_t db;
    TEST_ASSERT(persist_open(&db, path), "open");
    const char *x = "1111111111111111111111111111111111111111111111111111111111111111";
    const char *y = "2222222222222222222222222222222222222222222222222222222222222222";
    TEST_ASSERT(persist_client_rotation_bind_tree(&db, x, "aa") == 1, "the first tree binds");
    TEST_ASSERT(persist_client_rotation_bind_tree(&db, x, "aa") == 1, "the same tree again");
    TEST_ASSERT(persist_client_rotation_bind_tree(&db, x, "bb") == 0,
                "another tree over the same close is refused");
    TEST_ASSERT(persist_client_rotation_bind_tree(&db, y, "bb") == 1,
                "another close binds its own tree");
    persist_close(&db);
    unlink(path);
    return 1;
}

/* Keys that differ only in case, and numbers out of range. */
int test_cin_json_strict(void) {
    cJSON *j = cJSON_Parse("{\"FUNDING_AMOUNT\":111,\"Funding_Vout\":1,"
                           "\"funding_amount\":222,\"funding_vout\":0}");
    TEST_ASSERT(j && !wire_json_unambiguous(j), "case variants refused");
    cJSON_Delete(j);
    j = cJSON_Parse("{\"a\":{\"x\":1,\"X\":2}}");
    TEST_ASSERT(j && !wire_json_unambiguous(j), "nested case variants refused");
    cJSON_Delete(j);
    j = cJSON_Parse("{\"a\":[{\"k\":1},{\"k\":2}],\"b\":{\"k\":3},\"n\":7,\"neg\":-1,"
                    "\"frac\":1.5,\"big\":1e300,\"s\":\"5\",\"w\":4294967296}");
    TEST_ASSERT(j && wire_json_unambiguous(j), "distinct keys pass");
    uint64_t v = 0;
    TEST_ASSERT(wire_json_get_uint(j, "n", 10, &v) && v == 7, "in range");
    TEST_ASSERT(!wire_json_get_uint(j, "n", 6, &v), "above the maximum");
    TEST_ASSERT(!wire_json_get_uint(j, "neg", 10, &v), "negative");
    TEST_ASSERT(!wire_json_get_uint(j, "frac", 10, &v), "fraction");
    TEST_ASSERT(!wire_json_get_uint(j, "big", UINT64_MAX, &v), "huge");
    TEST_ASSERT(!wire_json_get_uint(j, "s", 10, &v), "a string");
    TEST_ASSERT(!wire_json_get_uint(j, "w", UINT32_MAX, &v), "past 32 bits");
    TEST_ASSERT(!wire_json_get_uint(j, "N", 10, &v), "exact case only");
    cJSON_Delete(j);
    return 1;
}

int test_cin_wire_roundtrip(void) {
    secp256k1_context *ctx = cin_ctx();
    secp256k1_pubkey pk, back;
    TEST_ASSERT(mk_pk(&pk, 0x61), "pk");
    unsigned char d[32], d2[32];
    memset(d, 0x5a, 32);
    cJSON *k = wire_build_rotation_key(ctx, &pk, d);
    TEST_ASSERT(k && wire_parse_rotation_key(k, ctx, &back, d2) && memcmp(d, d2, 32) == 0,
                "rotation key");
    unsigned char a[33], b[33];
    size_t la = 33, lb = 33;
    secp256k1_ec_pubkey_serialize(ctx, a, &la, &pk, SECP256K1_EC_COMPRESSED);
    secp256k1_ec_pubkey_serialize(ctx, b, &lb, &back, SECP256K1_EC_COMPRESSED);
    TEST_ASSERT(memcmp(a, b, 33) == 0, "same key");
    cJSON_Delete(k);
    const char *t = "33333333333333333333333333333333333333333333333333333333333333cc";
    cJSON *dn = wire_build_rotation_done(t, "0200ff", 1);
    char tt[65];
    char *hex = NULL;
    int conf = 0;
    TEST_ASSERT(dn && wire_parse_rotation_done(dn, tt, &hex, &conf) && strcmp(tt, t) == 0 &&
                hex && strcmp(hex, "0200ff") == 0 && conf == 1, "rotation done");
    free(hex);
    cJSON_Delete(dn);
    return 1;
}

/* A rotation reserves a NEW key; the active key stays the one in use. */
int test_cin_reserve_next_key(void) {
    secp256k1_context *ctx = cin_ctx();
    unsigned char root[32], lctx[33], zero[33], sk[32], nsk[32];
    memset(root, 0x42, 32);
    memset(lctx, 0x77, 33);
    lctx[0] = 0x02;
    memset(zero, 0, 33);
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    uint32_t idx = 9, nidx = 9;
    factory_key_source_t src;
    TEST_ASSERT(factory_key_select(&db, ctx, root, lctx, sk, &idx, &src) && idx == 0, "first");
    TEST_ASSERT(persist_factory_key_set_state(&db, 0, FACTORY_KEY_STATE_ACTIVE, 0), "active");
    TEST_ASSERT(!factory_key_reserve_next(&db, ctx, root, zero, nsk, &nidx), "zero ctx refused");
    TEST_ASSERT(factory_key_reserve_next(&db, ctx, root, lctx, nsk, &nidx) && nidx == 1 &&
                memcmp(sk, nsk, 32) != 0, "a new index");
    TEST_ASSERT(factory_key_select(&db, ctx, root, lctx, sk, &idx, &src) && idx == 0 &&
                src == FACTORY_KEY_RELOADED, "the active key stays current");
    unsigned char again[32];
    TEST_ASSERT(factory_key_derive_stored(&db, ctx, root, 1, again) &&
                memcmp(again, nsk, 32) == 0, "the reserved key re-derives");
    TEST_ASSERT(persist_factory_key_set_state(&db, 1, FACTORY_KEY_STATE_ACTIVE, 0), "promoted");
    TEST_ASSERT(factory_key_select(&db, ctx, root, lctx, sk, &idx, &src) && idx == 1,
                "after the switch the replacement key is current");
    persist_close(&db);
    return 1;
}

/* Eligibility: every client connected, announced the protocol, not offline. */
int test_cin_eligible(void) {
    lsp_t lsp;
    memset(&lsp, 0, sizeof(lsp));
    int fds[2] = { 5, 6 };
    uint8_t rv[2] = { 1, 1 };
    lsp.client_fds = fds;
    lsp.client_rotation_v = rv;
    lsp.n_clients = 2;
    lsp_channel_mgr_t *mgr = calloc(1, sizeof(*mgr));
    TEST_ASSERT(mgr, "mgr");
    lsp_channel_entry_t entries[2];
    memset(entries, 0, sizeof(entries));
    mgr->entries = entries;
    mgr->n_channels = 2;
    TEST_ASSERT(lsp_rotation_cin_eligible(mgr, &lsp), "all online and able");
    rv[1] = 0;
    TEST_ASSERT(!lsp_rotation_cin_eligible(mgr, &lsp), "an older client");
    rv[1] = 1;
    fds[0] = -1;
    TEST_ASSERT(!lsp_rotation_cin_eligible(mgr, &lsp), "a client offline");
    fds[0] = 5;
    entries[1].offline_detected = 1;
    TEST_ASSERT(!lsp_rotation_cin_eligible(mgr, &lsp), "marked offline");
    lsp.client_rotation_v = NULL;
    entries[1].offline_detected = 0;
    TEST_ASSERT(!lsp_rotation_cin_eligible(mgr, &lsp), "no capability array");
    free(mgr);
    return 1;
}
