/* Rotation by a co-signed close into the new factory: key freshness, the
   balance carry, the close check a client runs before signing, the resume
   and resolve decisions, the records, and the wire messages. */
#include "superscalar/lsp_channels.h"
#include "superscalar/ladder.h"
#include "superscalar/client_rotation.h"
#include "superscalar/factory_keys.h"
#include "superscalar/persist.h"
#include "superscalar/factory.h"
#include "superscalar/tx_builder.h"
#include "superscalar/wire.h"
#include "superscalar/watchtower.h"
#include "superscalar/fee_estimator.h"
#include "cJSON.h"
#include <stdio.h>
#include <secp256k1_schnorrsig.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include "superscalar/client.h"

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
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

/* A malicious LSP asks for the old key in a partial rotation: each release
   condition the client checks refuses on its own. */
int test_part_release_check(void) {
    secp256k1_context *ctx = cin_ctx();
    char cli[] = "/tmp/ss_cin_cli_XXXXXX";
    TEST_ASSERT(fake_cli(cli), "fake cli");
    regtest_t rt;
    memset(&rt, 0, sizeof(rt));
    snprintf(rt.cli_path, sizeof(rt.cli_path), "%s", cli);
    snprintf(rt.network, sizeof(rt.network), "regtest");
    char path[] = "/tmp/ss_part_rc_XXXXXX";
    persist_t db;
    TEST_ASSERT(tmp_db(path, &db), "db");

    /* Identity, LSP, the old per-factory key (a row with a pinned context). */
    unsigned char isk[32], lsk[32], root[32], osk[32], c33[33];
    memset(isk, 0x61, 32); memset(lsk, 0x62, 32); memset(root, 0x61, 32);
    secp256k1_keypair ikp, lkp, okp;
    TEST_ASSERT(secp256k1_keypair_create(ctx, &ikp, isk) &&
                secp256k1_keypair_create(ctx, &lkp, lsk), "keys");
    client_set_identity_keypair(&ikp);
    secp256k1_pubkey lpk;
    secp256k1_keypair_pub(ctx, &lpk, &lkp);
    size_t l33 = 33;
    secp256k1_ec_pubkey_serialize(ctx, c33, &l33, &lpk, SECP256K1_EC_COMPRESSED);
    uint32_t oidx = 99;
    TEST_ASSERT(factory_key_reserve_next(&db, ctx, root, c33, osk, &oidx) &&
                secp256k1_keypair_create(ctx, &okp, osk), "old per-factory key");

    /* The replacement we signed and its funding. */
    secp256k1_pubkey pks[3];
    pks[0] = lpk;
    TEST_ASSERT(mk_pk(&pks[1], 0x73) && mk_pk(&pks[2], 0x74), "pks");
    factory_t *nf = repl_factory(pks, 200);
    TEST_ASSERT(nf, "replacement");
    client_funding_bind_t bind;
    memset(&bind, 0, sizeof(bind));
    memcpy(bind.txid, nf->funding_txid, 32);
    bind.vout = nf->funding_vout;
    bind.amount = nf->funding_amount_sats;
    memcpy(bind.spk, nf->funding_spk, 34);
    factory_t old_f;
    memset(&old_f, 0, sizeof(old_f));
    memset(old_f.funding_txid, 0x5a, 32);
    old_f.funding_vout = 1;
    channel_t och;
    memset(&och, 0, sizeof(och));
    och.local_amount = 5000;
    uint64_t carried = 5000;
    uint32_t slot = 1;

    /* What an honest LSP sends. */
    unsigned char digest[32], npk33[33], bind_ok[32], receipt[64], aux[32], out[32];
    l33 = 33;
    secp256k1_ec_pubkey_serialize(ctx, npk33, &l33, &pks[1], SECP256K1_EC_COMPRESSED);
    TEST_ASSERT(factory_tree_digest(nf, digest), "digest");
    factory_release_binding(old_f.funding_txid, 1, bind.txid, bind.vout, digest, npk33, carried,
                            slot, bind_ok);
    memset(aux, 0x01, 32);
    TEST_ASSERT(secp256k1_schnorrsig_sign32(ctx, receipt, bind_ok, &lkp, aux), "receipt");
    char ftx[65], spkh[69], txo[512];
    unsigned char rv[32];
    memcpy(rv, bind.txid, 32);
    reverse_bytes(rv, 32);
    hex_encode(rv, 32, ftx);
    hex_encode(bind.spk, 34, spkh);
    snprintf(txo, sizeof(txo), "{\"confirmations\":2,\"value\":%.8f,\"scriptPubKey\":{\"hex\":\"%s\"}}",
             (double)bind.amount / 1e8, spkh);
    setenv("SS_FAKE_TXOUT_FOR", ftx, 1);
    setenv("SS_FAKE_TXOUT", txo, 1);
    client_part_set_jit_active(0);
#define RC(kp, ch, b, rcpt, c) client_part_release_check(&rt, &db, ctx, &old_f, &lpk, kp, ch, nf, \
        &bind, &pks[1], slot, c, bind.txid, b, rcpt, out, &oidx)
    TEST_ASSERT(RC(&okp, &och, bind_ok, receipt, carried) == NULL, "an honest request: release");

    unsigned char bad[64];
    memcpy(bad, receipt, 64);
    bad[5] ^= 1;
    TEST_ASSERT(RC(&okp, &och, bind_ok, bad, carried) != NULL, "a forged receipt");
    unsigned char other[32];
    factory_release_binding(old_f.funding_txid, 1, bind.txid, bind.vout, digest, npk33,
                            carried - 1, slot, other);
    unsigned char r2[64];
    TEST_ASSERT(secp256k1_schnorrsig_sign32(ctx, r2, other, &lkp, aux), "receipt 2");
    TEST_ASSERT(RC(&okp, &och, other, r2, carried) != NULL,
                "a binding (and receipt) for less than our balance");
    TEST_ASSERT(RC(&okp, &och, other, receipt, carried) != NULL,
                "a binding that is not our position, with a receipt over ours");
    TEST_ASSERT(RC(&ikp, &och, bind_ok, receipt, carried) != NULL,
                "the identity key (a legacy factory) is never released");
    client_part_set_jit_active(1);
    TEST_ASSERT(RC(&okp, &och, bind_ok, receipt, carried) != NULL, "a JIT channel is open");
    client_part_set_jit_active(0);
    och.local_amount = 5001;
    TEST_ASSERT(RC(&okp, &och, bind_ok, receipt, carried) != NULL,
                "our old balance rose after the check");
    och.local_amount = 5000;
    snprintf(txo, sizeof(txo), "{\"confirmations\":0,\"value\":%.8f,\"scriptPubKey\":{\"hex\":\"%s\"}}",
             (double)bind.amount / 1e8, spkh);
    setenv("SS_FAKE_TXOUT", txo, 1);
    TEST_ASSERT(RC(&okp, &och, bind_ok, receipt, carried) != NULL, "funding not confirmed");
    snprintf(txo, sizeof(txo), "{\"confirmations\":2,\"value\":%.8f,\"scriptPubKey\":{\"hex\":\"%s\"}}",
             (double)(bind.amount - 1) / 1e8, spkh);
    setenv("SS_FAKE_TXOUT", txo, 1);
    TEST_ASSERT(RC(&okp, &och, bind_ok, receipt, carried) != NULL, "funding amount differs");
    snprintf(txo, sizeof(txo), "{\"confirmations\":2,\"value\":%.8f,\"scriptPubKey\":{\"hex\":\"5120%s\"}}",
             (double)bind.amount / 1e8, "1111111111111111111111111111111111111111111111111111111111111111");
    setenv("SS_FAKE_TXOUT", txo, 1);
    TEST_ASSERT(RC(&okp, &och, bind_ok, receipt, carried) != NULL,
                "the funding output pays another script");
    unsetenv("SS_FAKE_TXOUT_FOR");
    TEST_ASSERT(RC(&okp, &och, bind_ok, receipt, carried) != NULL, "funding not on our chain");
#undef RC

    /* A key row with the zero context (not bound to this LSP) is never released. */
    sqlite3_exec(db.db, "UPDATE factory_keys SET lsp_ctx = "
                 "'000000000000000000000000000000000000000000000000000000000000000000';",
                 NULL, NULL, NULL);
    TEST_ASSERT(!client_part_key_releasable(&db, ctx, &okp, &oidx), "a zero-context key");
    unsetenv("SS_FAKE_TXOUT");
    client_set_identity_keypair(NULL);
    factory_free(nf);
    free(nf);
    persist_close(&db);
    unlink(path);
    unlink(cli);
    return 1;
}

/* After a partial rotation the old factory's channel rows move under the
   retired factory's own ids (so the LSP can still defend it), and a client
   that stayed is recognised.  A partial rotation waits for every channel of
   the old factory, the stayers' included. */
int test_part_retired_rows(void) {
    char path[] = "/tmp/ss_part_rr_XXXXXX";
    persist_t db;
    TEST_ASSERT(tmp_db(path, &db), "db");
    unsigned char pcs[32], got[32];
    memset(pcs, 0x31, 32);
    TEST_ASSERT(persist_save_local_pcs(&db, 1, 0, pcs) && persist_save_local_pcs(&db, 2, 0, pcs),
                "per-channel rows for slots 1 and 2");
    TEST_ASSERT(sqlite3_exec(db.db, "INSERT INTO channels (id, factory_id, slot, local_amount, "
                             "remote_amount, funding_amount, commitment_number) VALUES "
                             "(1, 0, 1, 10, 20, 31, 0);", NULL, NULL, NULL) == SQLITE_OK,
                "a channel row (its id is its slot)");
    uint32_t rf = LSP_RETIRED_FACTORY_ID(7), cid = LSP_RETIRED_CHANNEL_ID(7, 1);
    TEST_ASSERT(persist_retire_channel_rows(&db, 0, rf, 1, cid), "retire slot 1");
    sqlite3_stmt *st;
    int n_slot1 = -1, n_cid = -1, n_slot2 = -1;
    if (sqlite3_prepare_v2(db.db, "SELECT (SELECT COUNT(*) FROM local_pcs WHERE channel_id = 1),"
                           "(SELECT COUNT(*) FROM local_pcs WHERE channel_id = ?),"
                           "(SELECT COUNT(*) FROM local_pcs WHERE channel_id = 2);",
                           -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, cid);
        if (sqlite3_step(st) == SQLITE_ROW) {
            n_slot1 = sqlite3_column_int(st, 0);
            n_cid = sqlite3_column_int(st, 1);
            n_slot2 = sqlite3_column_int(st, 2);
        }
        sqlite3_finalize(st);
    }
    TEST_ASSERT(n_slot1 == 0 && n_cid == 1 && n_slot2 == 1,
                "slot 1's rows moved to the retired id, slot 2 untouched");
    TEST_ASSERT(sqlite3_exec(db.db, "INSERT OR REPLACE INTO channels (id, factory_id, slot, "
                             "local_amount, remote_amount, funding_amount, commitment_number) "
                             "VALUES (1, 0, 1, 1, 2, 3, 0);", NULL, NULL, NULL) == SQLITE_OK,
                "the replacement's channel at the same slot");
    int n_kept = -1;
    if (sqlite3_prepare_v2(db.db, "SELECT COUNT(*) FROM channels WHERE factory_id = ? AND "
                           "slot = 1;", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, rf);
        if (sqlite3_step(st) == SQLITE_ROW) n_kept = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
    TEST_ASSERT(n_kept == 1, "the old channel row survives the new one at its slot");
    memset(got, 0, 32);
    (void)got;
    persist_close(&db);
    unlink(path);

    lsp_channel_mgr_t *mgr = calloc(1, sizeof(*mgr));
    TEST_ASSERT(mgr, "mgr");
    mgr->ctx = cin_ctx();
    secp256k1_pubkey a, b;
    TEST_ASSERT(mk_pk(&a, 0x41) && mk_pk(&b, 0x42), "pks");
    mgr->part_retired_ids[0] = a;
    mgr->n_part_retired = 1;
    TEST_ASSERT(lsp_rotation_part_is_retired(mgr, &a) && !lsp_rotation_part_is_retired(mgr, &b),
                "a client that stayed is recognised");

    lsp_channel_entry_t entries[2];
    memset(entries, 0, sizeof(entries));
    htlc_t h[1];
    memset(h, 0, sizeof(h));
    h[0].state = HTLC_STATE_ACTIVE;
    entries[1].channel.htlcs = h;       /* the stayer's channel */
    entries[1].channel.n_htlcs = 1;
    mgr->entries = entries;
    mgr->n_channels = 2;
    TEST_ASSERT(!lsp_rotation_partial_may_start(mgr), "a stayer's HTLC in flight: wait");
    h[0].state = HTLC_STATE_FULFILLED;
    TEST_ASSERT(lsp_rotation_partial_may_start(mgr), "settled: go");
    free(mgr);
    return 1;
}

/* A release still owed is asked for again when the client reconnects, and
   taken only for its old factory key. */
int test_part_release_again(void) {
    secp256k1_context *ctx = cin_ctx();
    lsp_channel_mgr_t *mgr = calloc(1, sizeof(*mgr));
    TEST_ASSERT(mgr, "mgr");
    mgr->ctx = ctx;
    memset(mgr->rot_lsp_seckey, 0x62, 32);
    unsigned char osk[32];
    memset(osk, 0x63, 32);
    secp256k1_pubkey opk, npk;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &opk, osk) && mk_pk(&npk, 0x64), "keys");
    size_t l = 33;
    secp256k1_ec_pubkey_serialize(ctx, mgr->part_rel.old_pk[0], &l, &opk, SECP256K1_EC_COMPRESSED);
    l = 33;
    secp256k1_ec_pubkey_serialize(ctx, mgr->part_rel.new_pk[0], &l, &npk, SECP256K1_EC_COMPRESSED);
    memset(mgr->part_rel.old_txid, 0x01, 32);
    memset(mgr->part_rel.new_txid, 0x02, 32);
    memset(mgr->part_rel.digest, 0x03, 32);
    mgr->part_rel.carried[0] = 5000;
    mgr->part_rel.m = 1;
    mgr->part_rel.valid = 1;
    mgr->part_rel.funded = 1;
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    lsp_t lsp;
    memset(&lsp, 0, sizeof(lsp));
    int fds[1] = { sv[0] };
    lsp.client_fds = fds;
    lsp.n_clients = 1;
    TEST_ASSERT(lsp_rotation_part_on_reconnect(mgr, &lsp, 0), "asked again on reconnect");
    wire_msg_t m;
    memset(&m, 0, sizeof(m));
    TEST_ASSERT(wire_recv_timeout(sv[1], &m, 5) && m.msg_type == MSG_ROTATION_RELEASE_REQ,
                "the client gets the request");
    unsigned char ft[32], bind[32], rc[64];
    TEST_ASSERT(wire_parse_rotation_release_req(m.json, ft, bind, rc), "request parses");
    cJSON_Delete(m.json);
    unsigned char wrong[32];
    memset(wrong, 0x65, 32);
    cJSON *r = wire_build_rotation_release(bind, wrong);
    TEST_ASSERT(!lsp_rotation_part_on_release(mgr, &lsp, 0, r), "another key is not taken");
    cJSON_Delete(r);
    r = wire_build_rotation_release(bind, osk);
    TEST_ASSERT(lsp_rotation_part_on_release(mgr, &lsp, 0, r) && mgr->part_rel.released[0],
                "its old factory key is taken");
    cJSON_Delete(r);
    TEST_ASSERT(!lsp_rotation_part_on_reconnect(mgr, &lsp, 0), "not asked once released");
    close(sv[0]);
    close(sv[1]);
    free(mgr);

    /* A client that signed but was never asked switches once the funding is
       at the safe depth, keeping its old key. */
    TEST_ASSERT(client_cin_resolve_action("part_signed", 1, 0) == CLIENT_CIN_PROMOTE,
                "funded at the safe depth: switch");
    TEST_ASSERT(client_cin_resolve_action("part_signed", 0, 0) == CLIENT_CIN_NONE,
                "not yet: stay");
    char cli[] = "/tmp/ss_cin_cli_XXXXXX";
    TEST_ASSERT(fake_cli(cli), "fake cli");
    regtest_t rt;
    memset(&rt, 0, sizeof(rt));
    snprintf(rt.cli_path, sizeof(rt.cli_path), "%s", cli);
    snprintf(rt.network, sizeof(rt.network), "regtest");
    char path[] = "/tmp/ss_part_ps_XXXXXX";
    persist_t db;
    TEST_ASSERT(tmp_db(path, &db), "db");
    char side[64];
    snprintf(side, sizeof(side), "%s.rotation", path);
    persist_t sd;
    TEST_ASSERT(persist_open(&sd, side), "side db");
    persist_close(&sd);
    const char *ftx = "5656565656565656565656565656565656565656565656565656565656565656";
    persist_client_rotation_t row;
    memset(&row, 0, sizeof(row));
    snprintf(row.old_txid, sizeof(row.old_txid), "%s", "5757575757575757575757575757575757575757575757575757575757575757");
    snprintf(row.close_txid, sizeof(row.close_txid), "%s", ftx);
    snprintf(row.state, sizeof(row.state), "part_signed");
    snprintf(row.side_db, sizeof(row.side_db), "%s", side);
    row.close_height = 0;
    TEST_ASSERT(persist_client_rotation_save(&db, &row), "row");
    setenv("SS_FAKE_TXOUT_FOR", ftx, 1);
    setenv("SS_FAKE_TXOUT", "{\"confirmations\": 0}", 1);
    TEST_ASSERT(client_cin_resolve(&db, path, &rt) == 0, "funding unconfirmed: no switch");
    setenv("SS_FAKE_TXOUT", "{\"confirmations\": 3}", 1);
    TEST_ASSERT(client_cin_resolve(&db, path, &rt) == 1, "funded: switched without a release");
    unsetenv("SS_FAKE_TXOUT_FOR");
    unsetenv("SS_FAKE_TXOUT");
    persist_close(&db);
    char pre[64];
    snprintf(pre, sizeof(pre), "%s.pre-rotation", path);
    unlink(pre);
    unlink(path);
    unlink(cli);
    return 1;
}

/* Released keys: a sealed blob cannot be moved to another row, and nothing
   is stored in the clear without a seal. */
int test_part_seal_rows(void) {
    char path[] = "/tmp/ss_part_sr_XXXXXX";
    persist_t db;
    TEST_ASSERT(tmp_db(path, &db), "db");
    unsigned char sk[32];
    memset(sk, 0x44, 32);
    TEST_ASSERT(!persist_save_departed_client(&db, 3, 1, sk), "no seal: refused");
    unsigned char seal[32];
    memset(seal, 0x66, 32);
    persist_set_departed_seal_key(&db, seal);
    TEST_ASSERT(persist_save_departed_client(&db, 3, 1, sk), "sealed");
    sqlite3_exec(db.db, "INSERT INTO departed_clients (factory_id, client_idx, extracted_key) "
                 "SELECT factory_id, 2, extracted_key FROM departed_clients WHERE client_idx = 1;",
                 NULL, NULL, NULL);
    int dep[4] = {0};
    unsigned char keys[4][32];
    memset(keys, 0, sizeof(keys));
    size_t nd = persist_load_departed_clients(&db, 3, dep, keys, 4);
    TEST_ASSERT(memcmp(keys[1], sk, 32) == 0, "its own row unseals");
    TEST_ASSERT(memcmp(keys[2], sk, 32) != 0, "a copied blob does not unseal in another row");
    TEST_ASSERT(nd == 1 && dep[1] && !dep[2], "a key that does not unseal is no departure");
    persist_close(&db);
    unlink(path);
    return 1;
}

/* A release asked for later must never hand over the key the client signs
   its current factory with: the probe a legacy client (old key = identity
   key) whose replacement key is index 0 and whose row records index 0. */
int test_part_release_leak(void) {
    secp256k1_context *ctx = cin_ctx();
    char cli[] = "/tmp/ss_cin_cli_XXXXXX";
    TEST_ASSERT(fake_cli(cli), "fake cli");
    regtest_t rt;
    memset(&rt, 0, sizeof(rt));
    snprintf(rt.cli_path, sizeof(rt.cli_path), "%s", cli);
    snprintf(rt.network, sizeof(rt.network), "regtest");
    char path[] = "/tmp/ss_part_lk_XXXXXX";
    persist_t db;
    TEST_ASSERT(tmp_db(path, &db), "db");
    unsigned char isk[32], lsk[32], c33[33], k0[32], k1[32];
    memset(isk, 0x71, 32); memset(lsk, 0x72, 32);
    secp256k1_keypair ikp, lkp, kp0, kp1;
    TEST_ASSERT(secp256k1_keypair_create(ctx, &ikp, isk) &&
                secp256k1_keypair_create(ctx, &lkp, lsk), "keys");
    client_set_identity_keypair(&ikp);
    secp256k1_pubkey lpk, pk0, pk1, other;
    secp256k1_keypair_pub(ctx, &lpk, &lkp);
    size_t l = 33;
    secp256k1_ec_pubkey_serialize(ctx, c33, &l, &lpk, SECP256K1_EC_COMPRESSED);
    uint32_t i0 = 99, i1 = 99;
    TEST_ASSERT(factory_key_reserve_next(&db, ctx, isk, c33, k0, &i0) &&
                secp256k1_keypair_create(ctx, &kp0, k0), "index 0: the replacement key");
    secp256k1_keypair_pub(ctx, &pk0, &kp0);
    client_set_factory_keypair(&kp0);           /* switched: our current key */
    TEST_ASSERT(persist_factory_key_set_state(&db, i0, FACTORY_KEY_STATE_ACTIVE, 0), "active");
    TEST_ASSERT(mk_pk(&other, 0x75), "other");
    secp256k1_pubkey pks[3] = { lpk, pk0, other };
    factory_t *f = repl_factory(pks, 200);
    TEST_ASSERT(f, "the replacement (our factory now)");
    char ftx[65], spkh[69], txo[512];
    unsigned char rv[32];
    memcpy(rv, f->funding_txid, 32);
    reverse_bytes(rv, 32);
    hex_encode(rv, 32, ftx);
    hex_encode(f->funding_spk, 34, spkh);
    snprintf(txo, sizeof(txo), "{\"confirmations\":2,\"value\":%.8f,\"scriptPubKey\":{\"hex\":\"%s\"}}",
             (double)f->funding_amount_sats / 1e8, spkh);
    setenv("SS_FAKE_TXOUT_FOR", ftx, 1);
    setenv("SS_FAKE_TXOUT", txo, 1);
    client_part_set_jit_active(0);
    client_cin_set_chain(&rt, 1);

    /* An honest-format request for our position. */
    const char *oldtx = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
    unsigned char old32[32], digest[32], npk33[33], bind[32], rc[64], aux[32];
    TEST_ASSERT(hex_decode(oldtx, old32, 32) == 32, "old txid");
    reverse_bytes(old32, 32);
    l = 33;
    secp256k1_ec_pubkey_serialize(ctx, npk33, &l, &pk0, SECP256K1_EC_COMPRESSED);
    TEST_ASSERT(factory_tree_digest(f, digest), "digest");
    factory_release_binding(old32, 1, f->funding_txid, f->funding_vout, digest, npk33, 5000, 1, bind);
    memset(aux, 0x02, 32);
    TEST_ASSERT(secp256k1_schnorrsig_sign32(ctx, rc, bind, &lkp, aux), "receipt");
    cJSON *req = wire_build_rotation_release_req(f->funding_txid, bind, rc);

    persist_client_rotation_t row;
    memset(&row, 0, sizeof(row));
    snprintf(row.old_txid, sizeof(row.old_txid), "%s", oldtx);
    row.old_vout = 1;
    snprintf(row.close_txid, sizeof(row.close_txid), "%s", ftx);
    snprintf(row.state, sizeof(row.state), "part_switched");
    row.close_height = f->funding_vout;
    row.old_key_index = 0;
    row.carried = 5000;
    TEST_ASSERT(persist_client_rotation_save(&db, &row), "row (no old key recorded)");
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
#define SENT_RELEASE() ({ wire_msg_t m_; memset(&m_, 0, sizeof(m_)); int r_ = 0; \
        if (wire_recv_timeout(sv[1], &m_, 1)) { r_ = m_.msg_type == MSG_ROTATION_RELEASE; \
        cJSON_Delete(m_.json); } r_; })
    TEST_ASSERT(client_part_on_release_req(sv[0], ctx, &db, f, req) == 0 && !SENT_RELEASE(),
                "no recorded old key: nothing released");

    char h0[67];
    unsigned char s0[33];
    l = 33;
    secp256k1_ec_pubkey_serialize(ctx, s0, &l, &pk0, SECP256K1_EC_COMPRESSED);
    hex_encode(s0, 33, h0);
    snprintf(row.old_pubkey, sizeof(row.old_pubkey), "%s", h0);
    TEST_ASSERT(persist_client_rotation_save(&db, &row), "row (the current key recorded)");
    TEST_ASSERT(client_part_on_release_req(sv[0], ctx, &db, f, req) == 0 && !SENT_RELEASE(),
                "never the current factory key");
    /* Even if its key row were not active any more. */
    TEST_ASSERT(persist_factory_key_set_state(&db, i0, FACTORY_KEY_STATE_RETIRED, 0), "retired");
    TEST_ASSERT(client_part_on_release_req(sv[0], ctx, &db, f, req) == 0 && !SENT_RELEASE(),
                "never the current factory key, whatever its key row says");
    TEST_ASSERT(persist_factory_key_set_state(&db, i0, FACTORY_KEY_STATE_ACTIVE, 0), "active");
    char st[16];
    unsigned char kc[33], kpk[33];
    TEST_ASSERT(persist_factory_key_get_row(&db, i0, kc, kpk, st) == 1 &&
                strcmp(st, FACTORY_KEY_STATE_ACTIVE) == 0, "the current key is not marked released");

    /* The real old key: index 1, recorded, retired: released. */
    TEST_ASSERT(factory_key_reserve_next(&db, ctx, isk, c33, k1, &i1) &&
                secp256k1_keypair_create(ctx, &kp1, k1), "index 1: the old key");
    secp256k1_keypair_pub(ctx, &pk1, &kp1);
    unsigned char s1[33];
    char h1[67];
    l = 33;
    secp256k1_ec_pubkey_serialize(ctx, s1, &l, &pk1, SECP256K1_EC_COMPRESSED);
    hex_encode(s1, 33, h1);
    row.old_key_index = i1;
    snprintf(row.old_pubkey, sizeof(row.old_pubkey), "%s", h1);
    TEST_ASSERT(persist_client_rotation_save(&db, &row), "row (the old key)");
    TEST_ASSERT(client_part_on_release_req(sv[0], ctx, &db, f, req) == 0 && !SENT_RELEASE(),
                "the old key still active: refused");
    TEST_ASSERT(persist_factory_key_set_state(&db, i1, FACTORY_KEY_STATE_RETIRED, 0), "retired");
    snprintf(row.state, sizeof(row.state), "done");
    TEST_ASSERT(persist_client_rotation_save(&db, &row), "row done");
    TEST_ASSERT(client_part_on_release_req(sv[0], ctx, &db, f, req) == 0 && !SENT_RELEASE(),
                "not a signed, unreleased partial rotation: refused");
    snprintf(row.state, sizeof(row.state), "part_switched");
    TEST_ASSERT(persist_client_rotation_save(&db, &row), "row again");
    TEST_ASSERT(client_part_on_release_req(sv[0], ctx, &db, f, req) == 1 && SENT_RELEASE(),
                "the recorded old key is released");
#undef SENT_RELEASE
    persist_client_rotation_t chk;
    memset(&chk, 0, sizeof(chk));
    TEST_ASSERT(persist_client_rotation_load(&db, oldtx, &chk) == 1 &&
                strcmp(chk.state, "done") == 0, "released after the switch: the row is closed");
    free(chk.close_hex);
    snprintf(row.state, sizeof(row.state), "part_switched");
    TEST_ASSERT(persist_client_rotation_save(&db, &row), "an unreleased switched row");
    (void)client_cin_resolve(&db, path, &rt);       /* the old funding is spent (not in the UTXO set) */
    memset(&chk, 0, sizeof(chk));
    TEST_ASSERT(persist_client_rotation_load(&db, oldtx, &chk) == 1 &&
                strcmp(chk.state, "done") == 0, "closed once the old funding is spent");
    free(chk.close_hex);
    cJSON_Delete(req);
    close(sv[0]);
    close(sv[1]);

    /* Who may take part at all. */
    factory_t of;
    memset(&of, 0, sizeof(of));
    secp256k1_pubkey opks[3] = { lpk, pk1, other };
    of.pubkeys = opks;
    of.n_participants = 3;
    uint32_t oi = 0;
    char oh[67];
    TEST_ASSERT(client_part_old_key_ok(&db, ctx, &kp1, &of, &oi, oh) && oi == i1 &&
                strcmp(oh, h1) == 0, "a per-factory key of the old factory");
    TEST_ASSERT(!client_part_old_key_ok(&db, ctx, &ikp, &of, &oi, oh),
                "the identity key (a legacy factory): refused before signing");
    opks[1] = other;
    TEST_ASSERT(!client_part_old_key_ok(&db, ctx, &kp1, &of, &oi, oh),
                "a key that is not ours in the old factory");
    of.pubkeys = NULL;

    client_set_factory_keypair(NULL);
    client_set_identity_keypair(NULL);
    client_cin_set_chain(NULL, 1);
    unsetenv("SS_FAKE_TXOUT_FOR");
    unsetenv("SS_FAKE_TXOUT");
    factory_free(f);
    free(f);
    persist_close(&db);
    unlink(path);
    unlink(cli);
    return 1;
}

/* After an LSP restart the watch entries of a retired channel are loaded
   again, and a client that stayed is still recognised. */
int test_part_retired_restart(void) {
    char path[] = "/tmp/ss_part_rs_XXXXXX";
    persist_t db;
    TEST_ASSERT(tmp_db(path, &db), "db");
    uint32_t rcid = LSP_RETIRED_CHANNEL_ID(3, 2), rf = LSP_RETIRED_FACTORY_ID(3);
    unsigned char txid[32], spk[34];
    memset(txid, 0x7a, 32);
    memset(spk, 0x51, 34);
    TEST_ASSERT(persist_save_old_commitment(&db, rcid, 4, txid, 0, 1000, spk, 34),
                "a revoked commitment of the retired channel");
    secp256k1_pubkey id;
    TEST_ASSERT(mk_pk(&id, 0x7b), "identity");
    unsigned char id33[33];
    size_t l = 33;
    secp256k1_ec_pubkey_serialize(cin_ctx(), id33, &l, &id, SECP256K1_EC_COMPRESSED);
    TEST_ASSERT(persist_save_retired_channel(&db, rcid, rf, 2, id33), "retired channel");
    watchtower_t *wt = calloc(1, sizeof(*wt));
    TEST_ASSERT(wt && watchtower_init(wt, 2, NULL, NULL, &db), "watchtower");
    int found = 0;
    for (size_t i = 0; i < wt->n_entries; i++)
        if (wt->entries[i].channel_id == rcid && wt->entries[i].commit_num == 4) found = 1;
    TEST_ASSERT(found, "the retired channel's entry is watched again");
    watchtower_cleanup(wt);
    free(wt);
    lsp_channel_mgr_t *mgr = calloc(1, sizeof(*mgr));
    TEST_ASSERT(mgr, "mgr");
    mgr->ctx = cin_ctx();
    mgr->persist = &db;
    TEST_ASSERT(lsp_rotation_part_is_retired(mgr, &id), "the stayer is recognised from the DB");
    free(mgr);
    persist_close(&db);
    unlink(path);
    return 1;
}

static int g_queued[8];
static size_t g_n_queued;
static void capture_queue(void *arg, const wire_msg_t *m) {
    (void)arg;
    if (g_n_queued < 8) g_queued[g_n_queued++] = m->msg_type;
    cJSON_Delete(m->json);
}

/* A malicious LSP slips the old key turnover into a payment: while the
   client waits for COMMITMENT_SIGNED it sends a ROTATION_BEGIN of its own and
   a PTLC_PRESIG.  Nothing is adapted or sent but a refusal; the begin goes to
   the daemon loop, which checks it. */
int test_inline_turnover_refused(void) {
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    unsigned char d[32], nn[32], presig[64], tm[32];
    memset(d, 0x11, 32); memset(nn, 0x12, 32); memset(presig, 0x13, 64); memset(tm, 0x14, 32);
    cJSON *rb = wire_build_rotation_begin(d, nn, 7);
    cJSON *ps = wire_build_ptlc_presig(presig, 0, tm);
    cJSON *cs = cJSON_CreateObject();
    TEST_ASSERT(rb && ps && cs && wire_send(sv[1], MSG_ROTATION_BEGIN, rb) &&
                wire_send(sv[1], MSG_PTLC_PRESIG, ps) && wire_send(sv[1], MSG_COMMITMENT_SIGNED, cs),
                "the LSP's messages");
    cJSON_Delete(rb); cJSON_Delete(ps); cJSON_Delete(cs);
    g_n_queued = 0;
    wire_msg_t m;
    TEST_ASSERT(client_recv_expected(sv[0], &m, 5, MSG_COMMITMENT_SIGNED, capture_queue, NULL),
                "the payment flow gets its COMMITMENT_SIGNED");
    cJSON_Delete(m.json);
    TEST_ASSERT(g_n_queued == 1 && g_queued[0] == MSG_ROTATION_BEGIN,
                "the begin is left for the daemon loop; the pre-signature is not passed on");
    wire_msg_t r;
    memset(&r, 0, sizeof(r));
    TEST_ASSERT(wire_recv_timeout(sv[1], &r, 2) && r.msg_type == MSG_ERROR,
                "the pre-signature is refused");
    cJSON_Delete(r.json);
    memset(&r, 0, sizeof(r));
    TEST_ASSERT(!wire_recv_timeout(sv[1], &r, 1) || r.msg_type != MSG_PTLC_ADAPTED_SIG,
                "no adapted signature (no key) ever goes back");
    if (r.json) cJSON_Delete(r.json);
    wire_msg_t pm;
    memset(&pm, 0, sizeof(pm));
    pm.msg_type = MSG_PTLC_PRESIG;
    TEST_ASSERT(client_refuse_key_turnover(-1, &pm), "the daemon loop uses the same gate");
    close(sv[0]);
    close(sv[1]);
    return 1;
}

/* Every open rotation row counts: an older signed close freezes its factory
   and still switches, whatever row is newer. */
int test_cin_all_open_rows(void) {
    char path[] = "/tmp/ss_cin_ao_XXXXXX";
    persist_t db;
    TEST_ASSERT(tmp_db(path, &db), "db");
    persist_client_rotation_t a, b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    snprintf(a.old_txid, sizeof(a.old_txid), "%s", "6161616161616161616161616161616161616161616161616161616161616161");
    snprintf(a.close_txid, sizeof(a.close_txid), "%s", "6262626262626262626262626262626262626262626262626262626262626262");
    snprintf(a.state, sizeof(a.state), "close_signed");
    TEST_ASSERT(persist_client_rotation_save(&db, &a), "older: a signed close");
    sqlite3_exec(db.db, "UPDATE client_rotations SET updated_at = 1;", NULL, NULL, NULL);
    snprintf(b.old_txid, sizeof(b.old_txid), "%s", "6363636363636363636363636363636363636363636363636363636363636363");
    snprintf(b.state, sizeof(b.state), "key_sent");
    TEST_ASSERT(persist_client_rotation_save(&db, &b), "newer: only a key sent");
    client_cin_refresh_frozen(&db);
    unsigned char fa[32];
    memset(fa, 0x61, 32);
    TEST_ASSERT(client_cin_frozen() && client_cin_frozen_for(fa),
                "the older signed close still freezes its factory");
    cJSON *rc = cJSON_CreateObject();
    client_cin_reconnect_fields(&db, rc);
    const cJSON *pend = cJSON_GetObjectItemCaseSensitive(rc, "rotation_pending");
    TEST_ASSERT(cJSON_IsString(pend) && strcmp(pend->valuestring, a.close_txid) == 0,
                "and is reported as pending");
    cJSON_Delete(rc);
    client_cin_refresh_frozen(NULL);
    persist_close(&db);
    unlink(path);
    return 1;
}

/* The partial rotation's record: what is owed for the old factory survives
   a restart, and retired ids never repeat. */
int test_part_record_rows(void) {
    char path[] = "/tmp/ss_part_rr_XXXXXX";
    persist_t db;
    TEST_ASSERT(tmp_db(path, &db), "db");
    TEST_ASSERT(persist_next_retired_index(&db) == 0, "first retired index");
    persist_part_rotation_t *r = calloc(1, sizeof(*r));
    persist_part_rotation_t *back = calloc(2, sizeof(*back));
    TEST_ASSERT(r && back, "alloc");
    snprintf(r->old_txid, sizeof(r->old_txid), "%s", "7171717171717171717171717171717171717171717171717171717171717171");
    snprintf(r->new_txid, sizeof(r->new_txid), "%s", "7272727272727272727272727272727272727272727272727272727272727272");
    r->old_vout = 1;
    r->new_vout = 2;
    r->retired_id = LSP_RETIRED_FACTORY_ID(0);
    r->n_old = 2;
    r->m = 2;
    r->old_amount = 200000;
    r->old_cltv = 900;
    memset(r->digest, 0x73, 32);
    for (int i = 0; i < 3; i++) { r->old_pks[i][0] = 0x02; memset(r->old_pks[i] + 1, 0x10 + i, 32); }
    snprintf(r->state, sizeof(r->state), "releasing");
    TEST_ASSERT(persist_save_part_rotation(&db, r), "saved");
    for (uint32_t j = 0; j < 2; j++) {
        persist_part_release_t rel;
        memset(&rel, 0, sizeof(rel));
        rel.j = j;
        rel.old_slot = j + 1;
        rel.old_pk[0] = rel.new_pk[0] = 0x03;
        rel.carried = 1000 + j;
        TEST_ASSERT(persist_save_part_release(&db, r->old_txid, &rel), "release row");
    }
    TEST_ASSERT(persist_next_retired_index(&db) == 1, "the next retired index moves on");
    TEST_ASSERT(persist_set_part_released(&db, r->old_txid, 1), "released");
    TEST_ASSERT(!persist_set_part_released(&db, r->old_txid, 5), "no such row");
    TEST_ASSERT(persist_load_part_rotations(&db, back, 2, 1) == 1, "one open row");
    TEST_ASSERT(strcmp(back[0].old_txid, r->old_txid) == 0 && back[0].n_old == 2 &&
                back[0].m == 2 && back[0].old_amount == 200000 && back[0].old_cltv == 900 &&
                memcmp(back[0].old_pks, r->old_pks, 3 * 33) == 0 &&
                memcmp(back[0].digest, r->digest, 32) == 0 && !back[0].close_hex,
                "the row comes back");
    persist_part_release_t rels[4];
    TEST_ASSERT(persist_load_part_releases(&db, r->old_txid, rels, 4) == 2 &&
                !rels[0].released && rels[1].released && rels[1].old_slot == 2 &&
                rels[1].carried == 1001, "and what is owed");
    snprintf(r->state, sizeof(r->state), "done");
    TEST_ASSERT(persist_save_part_rotation(&db, r) &&
                persist_load_part_rotations(&db, back, 2, 1) == 0 &&
                persist_load_part_rotations(&db, back, 2, 0) == 1, "done: no longer open");
    /* Deleting the released keys of one retired factory only. */
    unsigned char seal[32], sk[32];
    memset(seal, 0x66, 32);
    memset(sk, 0x44, 32);
    persist_set_departed_seal_key(&db, seal);
    TEST_ASSERT(persist_save_departed_client(&db, r->retired_id, 1, sk) &&
                persist_save_departed_client(&db, r->retired_id + 1, 1, sk), "keys");
    TEST_ASSERT(persist_delete_departed_clients(&db, r->retired_id), "deleted");
    int dep[4] = {0};
    TEST_ASSERT(persist_load_departed_clients(&db, r->retired_id, dep, NULL, 4) == 0 &&
                persist_load_departed_clients(&db, r->retired_id + 1, dep, NULL, 4) == 1,
                "only that factory's");
    free(r);
    free(back);
    persist_close(&db);
    unlink(path);
    return 1;
}

/* A release is stored under the old factory's retired id at the client's
   PARTICIPANT index (slot + 1), marks the owed row, and reaches the ladder
   at that index: the LSP alone can then close the old factory. */
int test_part_release_slot(void) {
    secp256k1_context *ctx = cin_ctx();
    char path[] = "/tmp/ss_part_rs_XXXXXX";
    persist_t db;
    TEST_ASSERT(tmp_db(path, &db), "db");
    unsigned char seal[32];
    memset(seal, 0x66, 32);
    persist_set_departed_seal_key(&db, seal);
    lsp_channel_mgr_t *mgr = calloc(1, sizeof(*mgr));
    ladder_t *lad = calloc(1, sizeof(*lad));
    TEST_ASSERT(mgr && lad, "alloc");
    mgr->ctx = ctx;
    mgr->persist = &db;
    mgr->ladder = lad;
    memset(mgr->rot_lsp_seckey, 0x62, 32);
    unsigned char osk[32];
    memset(osk, 0x63, 32);
    secp256k1_pubkey opk, npk;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &opk, osk) && mk_pk(&npk, 0x64), "keys");
    size_t l = 33;
    secp256k1_ec_pubkey_serialize(ctx, mgr->part_rel.old_pk[0], &l, &opk, SECP256K1_EC_COMPRESSED);
    l = 33;
    secp256k1_ec_pubkey_serialize(ctx, mgr->part_rel.new_pk[0], &l, &npk, SECP256K1_EC_COMPRESSED);
    memset(mgr->part_rel.old_txid, 0x01, 32);
    mgr->part_rel.old_vout = 0;
    memset(mgr->part_rel.new_txid, 0x02, 32);
    memset(mgr->part_rel.digest, 0x03, 32);
    mgr->part_rel.old_slot[0] = 1;          /* the old factory's second client */
    mgr->part_rel.carried[0] = 5000;
    mgr->part_rel.m = 1;
    mgr->part_rel.n_old = 2;
    mgr->part_rel.retired_id = LSP_RETIRED_FACTORY_ID(4);
    mgr->part_rel.valid = 1;
    mgr->part_rel.funded = 1;
    char otx[65];
    {
        unsigned char rb[32];
        for (int i = 0; i < 32; i++) rb[i] = mgr->part_rel.old_txid[31 - i];
        hex_encode(rb, 32, otx);
    }
    persist_part_release_t rel;
    memset(&rel, 0, sizeof(rel));
    rel.old_slot = 1;
    TEST_ASSERT(persist_save_part_release(&db, otx, &rel), "owed row");
    ladder_factory_t *lf = &lad->factories[0];
    lf->is_initialized = 1;
    lf->factory_id = 9;
    lf->factory.n_participants = 3;
    memcpy(lf->factory.funding_txid, mgr->part_rel.old_txid, 32);
    lad->n_factories = 1;
    unsigned char bind[32];
    factory_release_binding(mgr->part_rel.old_txid, 0, mgr->part_rel.new_txid, 0,
                            mgr->part_rel.digest, mgr->part_rel.new_pk[0], 5000, 1, bind);
    cJSON *r = wire_build_rotation_release(bind, osk);
    lsp_t lsp;
    memset(&lsp, 0, sizeof(lsp));
    TEST_ASSERT(lsp_rotation_part_on_release(mgr, &lsp, 0, r), "taken");
    cJSON_Delete(r);
    int dep[4] = {0};
    unsigned char keys[4][32];
    memset(keys, 0, sizeof(keys));
    TEST_ASSERT(persist_load_departed_clients(&db, LSP_RETIRED_FACTORY_ID(4), dep, keys, 4) == 1 &&
                dep[2] && !dep[1] && memcmp(keys[2], osk, 32) == 0,
                "stored at participant index 2 under the retired id");
    persist_part_release_t back[2];
    TEST_ASSERT(persist_load_part_releases(&db, otx, back, 2) == 1 && back[0].released,
                "no longer owed");
    TEST_ASSERT(lf->client_departed[2] && !lf->client_departed[1] &&
                memcmp(lf->extracted_keys[2], osk, 32) == 0 && lf->n_departed == 1,
                "the ladder has it at the participant index");
    free(lad);
    free(mgr);
    persist_close(&db);
    unlink(path);
    return 1;
}

/* After a restart: the replacement's marker resumes, what is owed comes
   back, and a rotation that stopped before its record is dropped. */
int test_part_load_restart(void) {
    char path[] = "/tmp/ss_part_lr_XXXXXX";
    persist_t db;
    TEST_ASSERT(tmp_db(path, &db), "db");
    const char *old_hex = "8181818181818181818181818181818181818181818181818181818181818181";
    const char *new_hex = "8282828282828282828282828282828282828282828282828282828282828282";
    const char *other_hex = "8383838383838383838383838383838383838383838383838383838383838383";
    persist_rotation_progress_t row;
    memset(&row, 0, sizeof(row));
    row.phase = LSP_ROT_PROGRESS_PART_FUNDING;
    row.dying_funding_vout = 0;
    snprintf(row.new_funding_txid, sizeof(row.new_funding_txid), "%s", new_hex);
    row.new_funding_hex = (char *)"0200";
    row.new_funding_vout = 1;
    row.new_funding_amount = 150000;
    TEST_ASSERT(persist_save_rotation_progress(&db, old_hex, &row), "marker");
    persist_part_rotation_t *r = calloc(1, sizeof(*r));
    TEST_ASSERT(r, "alloc");
    snprintf(r->old_txid, sizeof(r->old_txid), "%s", old_hex);
    snprintf(r->new_txid, sizeof(r->new_txid), "%s", new_hex);
    r->new_vout = 1;
    r->retired_id = LSP_RETIRED_FACTORY_ID(2);
    r->n_old = 3;
    r->m = 2;
    for (int i = 0; i < 4; i++) r->old_pks[i][0] = 0x02;
    snprintf(r->state, sizeof(r->state), "releasing");
    TEST_ASSERT(persist_save_part_rotation(&db, r), "record");
    for (uint32_t j = 0; j < 2; j++) {
        persist_part_release_t rel;
        memset(&rel, 0, sizeof(rel));
        rel.j = j;
        rel.old_slot = 2 - j;
        rel.old_pk[0] = 0x02;
        rel.old_pk[1] = (unsigned char)j;
        rel.carried = 700 + j;
        rel.released = j == 0;
        TEST_ASSERT(persist_save_part_release(&db, old_hex, &rel), "owed");
    }
    /* A second factory whose rotation stopped at PART_SIGNING. */
    memset(&row, 0, sizeof(row));
    row.phase = LSP_ROT_PROGRESS_PART_SIGNING;
    row.dying_funding_vout = 1;
    snprintf(row.new_funding_txid, sizeof(row.new_funding_txid), "%s", other_hex);
    lsp_channel_mgr_t *mgr = calloc(1, sizeof(*mgr));
    TEST_ASSERT(mgr, "mgr");
    mgr->ctx = cin_ctx();
    mgr->persist = &db;
    unsigned char live[32];
    TEST_ASSERT(hex_decode(new_hex, live, 32) == 32, "hex");
    reverse_bytes(live, 32);
    /* The live factory is the replacement (and, for the second marker, the
       old factory of a rotation that never got recorded). */
    TEST_ASSERT(persist_save_rotation_progress(&db, new_hex, &row), "stopped marker");
    TEST_ASSERT(lsp_rotation_part_load(mgr, NULL, live, 1), "loaded");
    persist_rotation_progress_t chk;
    memset(&chk, 0, sizeof(chk));
    TEST_ASSERT(persist_load_rotation_progress(&db, new_hex, &chk, 0) &&
                chk.phase == LSP_ROT_PROGRESS_DONE, "the unrecorded rotation is dropped");
    free(chk.new_funding_hex);
    free(chk.dist_tx_hex);
    TEST_ASSERT(mgr->rot_progress.phase == LSP_ROT_PROGRESS_PART_FUNDING &&
                strcmp(mgr->rot_progress.new_funding_txid, new_hex) == 0 &&
                mgr->rot_progress.new_funding_hex &&
                strcmp(mgr->rot_progress.new_funding_hex, "0200") == 0 &&
                lsp_rotation_progress_resumable(mgr),
                "the replacement's marker resumes with its recorded funding");
    unsigned char o32[32];
    hex_decode(old_hex, o32, 32);
    reverse_bytes(o32, 32);
    TEST_ASSERT(mgr->part_rel.valid && mgr->part_rel.m == 2 && mgr->part_rel.n_old == 3 &&
                mgr->part_rel.retired_id == LSP_RETIRED_FACTORY_ID(2) &&
                memcmp(mgr->part_rel.old_txid, o32, 32) == 0 &&
                mgr->part_rel.released[0] && !mgr->part_rel.released[1] &&
                mgr->part_rel.old_slot[1] == 1 && mgr->part_rel.carried[1] == 701 &&
                mgr->part_rel.old_pk[1][1] == 1,
                "what is owed comes back");
    lsp_rotation_progress_clear(mgr);
    free(mgr);
    free(r);
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
