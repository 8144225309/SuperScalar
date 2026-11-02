/* Pseudo-Spilman record-and-refuse: failure semantics of the client's signing
 * refusal (client_handle_leaf_advance_stateless, src/client.c).
 *
 * PS leaves are non-revocable.  The only thing stopping the LSP from getting a
 * stale leaf state confirmed is each signer's refusal to co-sign a second,
 * conflicting spend of the same chain parent, which the client enforces with
 * the client_ps_signed_inputs table.  These tests pin down what happens when
 * that machinery itself fails or races.  Each one asserts on whether
 * MSG_LEAF_ADVANCE_FINAL -- the message that carries the client's signature
 * out of the process -- was sent:
 *
 *   t1  injected error on the pre-sign check        -> refused, nothing sent
 *   t2  injected error on the record insert         -> aborted before FINAL
 *   t3  sighash computation failure                 -> refused, nothing sent
 *   t4  conflicting record (different sighash)      -> refused (regression)
 *   t5  identical record (same sighash)             -> idempotent, succeeds
 *   t6  two ceremonies pass the check, one record   -> exactly one signature
 *   drill: crash before / between / after the record, then restart
 *
 * Harness: the client runs in a forked child over a socketpair, against a real
 * on-disk persist DB (the record has to outlive the child).  The parent plays
 * the LSP the way lsp_advance_leaf_stateless does for the state TX: the child
 * consumes a stateless-shape PROPOSE, the parent reads CLIENT_PUBNONCE, makes
 * its nonce + partial sig on a mirrored factory, sends LSP_RESPONSE, then
 * waits for FINAL (verified like the LSP does) and answers DONE.  No poison
 * fields are sent, so the client degrades its poison sub-ceremony, which a
 * non-hashlock leaf allows.  Both sides build the identical 3-party PS factory
 * from fixed keys, so the chain parent and the sighash are the same in every
 * ceremony: a second ceremony on a fresh factory IS the retry-after-restart
 * case, with the same DB file carrying the record across.
 */
#include "superscalar/factory.h"
#include "superscalar/wire.h"
#include "superscalar/client.h"
#include "superscalar/musig.h"
#include "superscalar/persist.h"
#include "superscalar/crash_inject.h"
#include "superscalar/sha256.h"
#include "superscalar/tx_builder.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <time.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

/* ---------------------------------------------------------------- factory */

/* 3-party PS factory: LSP (idx 0) + 2 clients (idx 1, 2).  Fixed keys and a
   fixed funding outpoint, so every build is byte-identical. */
static int build_ps_factory(secp256k1_context *ctx, secp256k1_keypair kps[3],
                            factory_t **out) {
    const size_t N = 3;
    for (size_t i = 0; i < N; i++) {
        unsigned char sk[32] = {0};
        sk[31] = (unsigned char)(i + 1);
        sk[0]  = 0x99;
        if (!secp256k1_keypair_create(ctx, &kps[i], sk)) return 0;
    }
    unsigned char fund_spk[34];
    {
        secp256k1_pubkey pks[3];
        for (size_t i = 0; i < N; i++)
            secp256k1_keypair_pub(ctx, &pks[i], &kps[i]);
        musig_keyagg_t ka;
        musig_aggregate_keys(ctx, &ka, pks, N);
        unsigned char ser[32];
        secp256k1_xonly_pubkey_serialize(ctx, ser, &ka.agg_pubkey);
        unsigned char tweak[32];
        sha256_tagged("TapTweak", ser, 32, tweak);
        secp256k1_pubkey tw_pk;
        secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tw_pk, &ka.cache, tweak);
        secp256k1_xonly_pubkey tw_xo;
        secp256k1_xonly_pubkey_from_pubkey(ctx, &tw_xo, NULL, &tw_pk);
        build_p2tr_script_pubkey(fund_spk, &tw_xo);
    }
    unsigned char fake_fund_txid[32];
    memset(fake_fund_txid, 0x7A, 32);

    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;
    /* factory_init zeroes *f and allocates its own arrays (no
       factory_alloc_default_arrays first: that allocation would leak). */
    factory_init(f, ctx, kps, N, 6, 10);
    factory_set_arity(f, FACTORY_ARITY_PS);
    factory_set_funding(f, fake_fund_txid, 0, 500000, fund_spk, 34);
    if (!factory_build_tree(f) || !factory_sign_all(f)) {
        factory_free(f);
        free(f);
        return 0;
    }
    *out = f;
    return 1;
}

/* ------------------------------------------------------------ DB helpers */

/* Every DB path a test creates, so a failing TEST_ASSERT (which returns
   early, skipping the test's own db_drop) still has its files removed:
   see with_db_cleanup. */
static char g_test_dbs[8][256];
static int g_n_test_dbs = 0;

static void db_path_fresh(char *buf, size_t n, const char *tag) {
    snprintf(buf, n, "/tmp/ss_ps_refusal_%s_%d.db", tag, (int)getpid());
    if (g_n_test_dbs < 8) {
        snprintf(g_test_dbs[g_n_test_dbs], sizeof g_test_dbs[0], "%s", buf);
        g_n_test_dbs++;
    }
    char side[320];
    unlink(buf);
    snprintf(side, sizeof side, "%s-wal", buf); unlink(side);
    snprintf(side, sizeof side, "%s-shm", buf); unlink(side);
}

static void db_drop(const char *path) {
    char side[320];
    unlink(path);
    snprintf(side, sizeof side, "%s-wal", path); unlink(side);
    snprintf(side, sizeof side, "%s-shm", path); unlink(side);
}

/* Run one test body, then remove every DB it created -- also when it failed. */
static int with_db_cleanup(int (*body)(void)) {
    g_n_test_dbs = 0;
    int ok = body();
    for (int i = 0; i < g_n_test_dbs; i++)
        db_drop(g_test_dbs[i]);
    g_n_test_dbs = 0;
    return ok;
}

/* Number of rows in client_ps_signed_inputs, or -1. */
static long db_rows(const char *path) {
    persist_t db;
    if (!persist_open(&db, path)) return -1;
    long n = -1;
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db.db, "SELECT COUNT(*) FROM client_ps_signed_inputs;",
                           -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW) n = (long)sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    persist_close(&db);
    return n;
}

/* What the client recorded for (parent, 0): -1 error, 0 none, 1 found. */
static int db_lookup(const char *path, const unsigned char parent[32],
                     unsigned char out_sighash[32]) {
    persist_t db;
    if (!persist_open(&db, path)) return -1;
    int rc = persist_check_ps_signed_input(&db, 0, parent, 0, out_sighash);
    persist_close(&db);
    return rc;
}

/* Make the stored record for (parent, 0) carry `sighash`, replacing whatever
   is there.  From the client's point of view this is exactly "the LSP now
   proposes a different spend of the same parent than the one we recorded":
   the client only ever compares the sighash it computes with the stored one. */
static int db_seed(const char *path, const unsigned char parent[32],
                   const unsigned char sighash[32]) {
    persist_t db;
    if (!persist_open(&db, path)) return 0;
    sqlite3_exec(db.db, "DELETE FROM client_ps_signed_inputs;", NULL, NULL, NULL);
    unsigned char psig[36];
    memset(psig, 0x66, 36);
    int rc = persist_save_ps_signed_input(&db, 0, 0, parent, 0, sighash, psig);
    persist_close(&db);
    return rc == PS_SAVE_RECORDED;
}

/* ------------------------------------------------------------ the harness */

typedef struct {
    int fail_point;                     /* PERSIST_TEST_PS_* to fail once, or 0 */
    const char *crash_at;               /* client crash checkpoint to abort at, or NULL */
    const unsigned char *race_sighash;  /* if set: at the SAVE point a second connection
                                           records this sighash for the same parent
                                           first -- the "other" ceremony winning */
} ceremony_opts_t;

typedef struct {
    int child_rc;        /* 1 handler succeeded, 0 handler failed, -1 died by signal */
    int child_signal;    /* when child_rc == -1 */
    int got_pubnonce;    /* CLIENT_PUBNONCE reached the LSP (nonces were generated) */
    int got_final;       /* MSG_LEAF_ADVANCE_FINAL reached the LSP and verified */
    unsigned char parent_txid[32];  /* the chain parent: txid of the pre-advance leaf state */
    unsigned char sighash[32];      /* the sighash the LSP side signed (session msg32) */
} ceremony_result_t;

typedef struct {
    const ceremony_opts_t *o;
    const char *dbpath;
    int leaf_idx;
    int fired;
    unsigned char parent_txid[32];
} child_hook_state_t;

static int child_hook(int point, void *user) {
    child_hook_state_t *st = (child_hook_state_t *)user;
    if (st->fired) return 0;
    if (st->o->race_sighash && point == PERSIST_TEST_PS_SAVE) {
        /* Another ceremony for the same parent passed its pre-sign check too
           and records first.  Simulate it through a second connection, then
           let this ceremony's own insert run -- and lose. */
        st->fired = 1;
        persist_t other;
        if (persist_open(&other, st->dbpath)) {
            unsigned char psig[36];
            memset(psig, 0xC0, 36);
            (void)persist_save_ps_signed_input(&other, 0, st->leaf_idx,
                                               st->parent_txid, 0,
                                               st->o->race_sighash, psig);
            persist_close(&other);
        }
        return 0;
    }
    if (st->o->fail_point && point == st->o->fail_point) {
        st->fired = 1;
        return 1;  /* inject the failure, once */
    }
    return 0;
}

static int wait_child(pid_t pid, ceremony_result_t *r) {
    int status = 0;
    for (int i = 0; i < 600; i++) {  /* up to 60 s, then give up */
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) {
            if (WIFEXITED(status)) {
                r->child_rc = (WEXITSTATUS(status) == 0) ? 1 : 0;
                return 1;
            }
            if (WIFSIGNALED(status)) {
                r->child_rc = -1;
                r->child_signal = WTERMSIG(status);
                return 1;
            }
            return 0;
        }
        if (w < 0) return 0;
        struct timespec ts = { 0, 100 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    return 0;
}

/* Run one leaf-0 advance ceremony against dbpath.  Returns 1 when the harness
   itself worked (the ceremony's outcome is in *r), 0 on a harness error. */
static int run_ceremony(const char *dbpath, const ceremony_opts_t *o,
                        ceremony_result_t *r) {
    memset(r, 0, sizeof *r);
    signal(SIGPIPE, SIG_IGN);  /* a child that aborts after FINAL leaves us writing DONE to a dead peer */

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kps[3];
    factory_t *f = NULL;
    if (!build_ps_factory(ctx, kps, &f)) {
        secp256k1_context_destroy(ctx);
        return 0;
    }
    size_t leaf_idx = f->leaf_node_indices[0];
    memcpy(r->parent_txid, f->nodes[leaf_idx].txid, 32);

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        factory_free(f); free(f); secp256k1_context_destroy(ctx);
        return 0;
    }
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) {
        close(sv[0]); close(sv[1]);
        factory_free(f); free(f); secp256k1_context_destroy(ctx);
        return 0;
    }
    if (pid == 0) {
        /* ---- child: the client ---- */
        close(sv[0]);
        persist_t db;
        if (!persist_open(&db, dbpath)) _exit(3);
        client_set_persist(&db);
        child_hook_state_t st;
        memset(&st, 0, sizeof st);
        st.o = o;
        st.dbpath = dbpath;
        st.leaf_idx = (int)leaf_idx;
        memcpy(st.parent_txid, r->parent_txid, 32);
        if (o->fail_point || o->race_sighash)
            persist_test_set_ps_hook(child_hook, &st);
        if (o->crash_at) {
            /* The drill abort()s on purpose: drop no core files. */
            struct rlimit no_core = { 0, 0 };
            (void)setrlimit(RLIMIT_CORE, &no_core);
            lsp_crash_set_target(o->crash_at);
        }
        /* The PROPOSE the LSP would have sent: stateless shape, no nonce. */
        wire_msg_t propose;
        memset(&propose, 0, sizeof propose);
        propose.msg_type = MSG_LEAF_ADVANCE_PROPOSE;
        propose.json = wire_build_leaf_advance_propose(0, NULL, NULL);
        int rc = client_handle_leaf_advance(sv[1], ctx, &kps[1], f, 1, &propose);
        cJSON_Delete(propose.json);
        client_set_persist(NULL);
        persist_test_set_ps_hook(NULL, NULL);
        persist_close(&db);
        close(sv[1]);
        _exit(rc ? 0 : 1);
    }

    /* ---- parent: the LSP (state TX only, as lsp_advance_leaf_stateless) ---- */
    close(sv[1]);
    int ok = 1;
    do {
        if (factory_advance_leaf_unsigned(f, 0) <= 0) { ok = 0; break; }
        size_t node_idx = f->leaf_node_indices[0];
        wire_set_timeout(sv[0], 20);

        wire_msg_t cpn;
        if (!wire_recv(sv[0], &cpn)) break;  /* EOF: the client refused before any nonce */
        if (cpn.msg_type != MSG_LEAF_ADVANCE_CLIENT_PUBNONCE) {
            cJSON_Delete(cpn.json); ok = 0; break;
        }
        r->got_pubnonce = 1;
        unsigned char client_pn_ser[66];
        int prc = wire_parse_leaf_advance_client_pubnonce(cpn.json, client_pn_ser, NULL);
        cJSON_Delete(cpn.json);
        if (!prc) { ok = 0; break; }

        if (!factory_session_init_node(f, node_idx)) { ok = 0; break; }
        int client_slot = factory_find_signer_slot(f, node_idx, 1);
        int lsp_slot = factory_find_signer_slot(f, node_idx, 0);
        if (client_slot < 0 || lsp_slot < 0) { ok = 0; break; }
        secp256k1_musig_pubnonce client_pn;
        if (!musig_pubnonce_parse(ctx, &client_pn, client_pn_ser) ||
            !factory_session_set_nonce(f, node_idx, (size_t)client_slot, &client_pn)) {
            ok = 0; break;
        }
        unsigned char lsp_sk[32];
        secp256k1_pubkey lsp_pub;
        secp256k1_keypair_sec(ctx, lsp_sk, &kps[0]);
        secp256k1_keypair_pub(ctx, &lsp_pub, &kps[0]);
        secp256k1_musig_secnonce lsp_secnonce;
        secp256k1_musig_pubnonce lsp_pubnonce;
        int ng = musig_generate_nonce(ctx, &lsp_secnonce, &lsp_pubnonce, lsp_sk, &lsp_pub,
                                      &f->nodes[node_idx].keyagg.cache);
        memset(lsp_sk, 0, 32);
        if (!ng ||
            !factory_session_set_nonce(f, node_idx, (size_t)lsp_slot, &lsp_pubnonce) ||
            !factory_session_finalize_node(f, node_idx)) {
            ok = 0; break;
        }
        secp256k1_musig_partial_sig lsp_psig;
        if (!musig_create_partial_sig(ctx, &lsp_psig, &lsp_secnonce, &kps[0],
                                      &f->nodes[node_idx].signing_session) ||
            !factory_session_set_partial_sig(f, node_idx, (size_t)lsp_slot, &lsp_psig)) {
            ok = 0; break;
        }
        memcpy(r->sighash, f->nodes[node_idx].signing_session.msg32, 32);

        unsigned char lsp_pn_ser[66], lsp_psig_ser[32];
        musig_pubnonce_serialize(ctx, lsp_pn_ser, &lsp_pubnonce);
        musig_partial_sig_serialize(ctx, lsp_psig_ser, &lsp_psig);
        cJSON *resp = wire_build_leaf_advance_lsp_response(lsp_pn_ser, lsp_psig_ser, NULL, NULL);
        int sent = wire_send(sv[0], MSG_LEAF_ADVANCE_LSP_RESPONSE, resp);
        cJSON_Delete(resp);
        if (!sent) { ok = 0; break; }

        /* Did the client's signature leave its process? */
        wire_msg_t fin;
        if (!wire_recv(sv[0], &fin)) break;  /* EOF: refused, aborted or crashed before FINAL */
        if (fin.msg_type != MSG_LEAF_ADVANCE_FINAL) {
            cJSON_Delete(fin.json); ok = 0; break;
        }
        unsigned char final_sig[64];
        int frc = wire_parse_leaf_advance_final(fin.json, final_sig, NULL);
        cJSON_Delete(fin.json);
        if (!frc) { ok = 0; break; }
        /* Verify like the LSP does: output key from the (tweaked) session cache. */
        secp256k1_pubkey out_pk;
        secp256k1_xonly_pubkey out_x;
        if (!secp256k1_musig_pubkey_get(ctx, &out_pk, &f->nodes[node_idx].signing_session.cache) ||
            !secp256k1_xonly_pubkey_from_pubkey(ctx, &out_x, NULL, &out_pk) ||
            !secp256k1_schnorrsig_verify(ctx, final_sig,
                                         f->nodes[node_idx].signing_session.msg32, 32, &out_x)) {
            ok = 0; break;
        }
        r->got_final = 1;
        cJSON *done = wire_build_leaf_advance_done(0);
        (void)wire_send(sv[0], MSG_LEAF_ADVANCE_DONE, done);
        cJSON_Delete(done);
    } while (0);
    close(sv[0]);
    if (!wait_child(pid, r)) ok = 0;

    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return ok;
}

static const unsigned char CONFLICTING_SIGHASH[32] = {
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };

/* ------------------------------------------------------------------ tests */

/* t1: the pre-sign lookup fails (DB error).  "Unknown" must mean "refuse":
   no nonce, no signature, nothing sent, nothing recorded. */
static int test_ps_refusal_check_error_refuses_body(void) {
    char db[256];
    db_path_fresh(db, sizeof db, "t1");
    ceremony_opts_t o = { PERSIST_TEST_PS_CHECK, NULL, NULL };
    ceremony_result_t r;
    TEST_ASSERT(run_ceremony(db, &o, &r), "harness");
    TEST_ASSERT(r.child_rc == 0, "ceremony must return failure on a check error");
    TEST_ASSERT(!r.got_pubnonce, "refused before any nonce was generated");
    TEST_ASSERT(!r.got_final, "no MSG_LEAF_ADVANCE_FINAL was sent");
    TEST_ASSERT(db_rows(db) == 0, "nothing recorded");
    db_drop(db);
    return 1;
}

/* t2: the record insert fails.  The signature exists in memory at this point;
   it must not leave the process: abort before complete_node / FINAL. */
static int test_ps_refusal_save_error_aborts_before_final_body(void) {
    char db[256];
    db_path_fresh(db, sizeof db, "t2");
    ceremony_opts_t o = { PERSIST_TEST_PS_SAVE, NULL, NULL };
    ceremony_result_t r;
    TEST_ASSERT(run_ceremony(db, &o, &r), "harness");
    TEST_ASSERT(r.got_pubnonce, "the ceremony got as far as the nonce exchange");
    TEST_ASSERT(r.child_rc == 0, "ceremony must return failure when the record cannot be saved");
    TEST_ASSERT(!r.got_final, "no MSG_LEAF_ADVANCE_FINAL was sent");
    TEST_ASSERT(db_rows(db) == 0, "no record (the insert failed) -- and no signature out, consistent");
    db_drop(db);
    return 1;
}

/* t3: the sighash the record is keyed on cannot be computed.  With nothing to
   record against, nothing may be signed. */
static int test_ps_refusal_sighash_failure_aborts_body(void) {
    char db[256];
    db_path_fresh(db, sizeof db, "t3");
    ceremony_opts_t o = { PERSIST_TEST_PS_SIGHASH, NULL, NULL };
    ceremony_result_t r;
    TEST_ASSERT(run_ceremony(db, &o, &r), "harness");
    TEST_ASSERT(r.child_rc == 0, "ceremony must return failure when the sighash cannot be computed");
    TEST_ASSERT(!r.got_pubnonce, "aborted before any nonce was generated");
    TEST_ASSERT(!r.got_final, "no MSG_LEAF_ADVANCE_FINAL was sent");
    TEST_ASSERT(db_rows(db) == 0, "nothing recorded");
    db_drop(db);
    return 1;
}

/* t4 (regression): a record for this parent with a DIFFERENT sighash exists:
   the classic double-spend attempt.  Refused before any nonce. */
static int test_ps_refusal_conflicting_record_refuses_body(void) {
    char db[256];
    db_path_fresh(db, sizeof db, "t4");
    /* Learn the parent txid from a factory build; seed the conflicting record. */
    ceremony_result_t probe;
    {
        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        secp256k1_keypair kps[3];
        factory_t *f = NULL;
        TEST_ASSERT(build_ps_factory(ctx, kps, &f), "build factory");
        memcpy(probe.parent_txid, f->nodes[f->leaf_node_indices[0]].txid, 32);
        factory_free(f); free(f); secp256k1_context_destroy(ctx);
    }
    TEST_ASSERT(db_seed(db, probe.parent_txid, CONFLICTING_SIGHASH), "seed conflicting record");

    ceremony_opts_t o = { 0, NULL, NULL };
    ceremony_result_t r;
    TEST_ASSERT(run_ceremony(db, &o, &r), "harness");
    TEST_ASSERT(memcmp(r.parent_txid, probe.parent_txid, 32) == 0, "same parent every build");
    TEST_ASSERT(r.child_rc == 0, "ceremony must be refused");
    TEST_ASSERT(!r.got_pubnonce, "refused before any nonce was generated");
    TEST_ASSERT(!r.got_final, "no MSG_LEAF_ADVANCE_FINAL was sent");
    unsigned char stored[32];
    TEST_ASSERT(db_lookup(db, r.parent_txid, stored) == 1 &&
                memcmp(stored, CONFLICTING_SIGHASH, 32) == 0,
                "the earlier record is untouched");
    db_drop(db);
    return 1;
}

/* t5: a record for this parent with the SAME sighash exists -- we already
   signed exactly this spend (e.g. the LSP never got our FINAL).  Re-signing
   the identical message is safe and must succeed, or the leaf is stuck. */
static int test_ps_refusal_same_sighash_record_is_idempotent_body(void) {
    char db[256];
    db_path_fresh(db, sizeof db, "t5");
    ceremony_opts_t o = { 0, NULL, NULL };
    ceremony_result_t a, b;

    TEST_ASSERT(run_ceremony(db, &o, &a), "harness A");
    TEST_ASSERT(a.child_rc == 1 && a.got_final, "first ceremony succeeds and sends FINAL");
    unsigned char stored[32];
    TEST_ASSERT(db_lookup(db, a.parent_txid, stored) == 1, "first ceremony recorded its signing");
    TEST_ASSERT(memcmp(stored, a.sighash, 32) == 0,
                "the recorded sighash is the message the LSP side signed too");

    TEST_ASSERT(run_ceremony(db, &o, &b), "harness B");
    TEST_ASSERT(b.child_rc == 1, "identical retry must succeed (idempotent), not be refused");
    TEST_ASSERT(b.got_final, "identical retry sends FINAL");
    TEST_ASSERT(memcmp(b.sighash, a.sighash, 32) == 0, "the retry signed the identical spend");
    TEST_ASSERT(db_rows(db) == 1, "still exactly one record for the parent");
    db_drop(db);
    return 1;
}

/* t6: two ceremonies on the same parent both pass the pre-sign check (there is
   no row yet when either looks).  The INSERT is the arbiter: whichever records
   first wins; the other must see the conflict and release nothing.  Then the
   benign variant: the other ceremony recorded the identical spend, so ours is
   an idempotent success. */
static int test_ps_refusal_concurrent_record_race_one_signature_body(void) {
    char db[256];
    db_path_fresh(db, sizeof db, "t6a");
    ceremony_opts_t lose = { 0, NULL, CONFLICTING_SIGHASH };
    ceremony_result_t r;
    TEST_ASSERT(run_ceremony(db, &lose, &r), "harness (lost race)");
    TEST_ASSERT(r.got_pubnonce, "both ceremonies passed the check: nonces were exchanged");
    TEST_ASSERT(r.child_rc == 0, "the ceremony that lost the record race must fail");
    TEST_ASSERT(!r.got_final, "the loser releases no signature");
    unsigned char stored[32];
    TEST_ASSERT(db_lookup(db, r.parent_txid, stored) == 1, "exactly one record exists");
    TEST_ASSERT(memcmp(stored, CONFLICTING_SIGHASH, 32) == 0,
                "the first record won and was NOT overwritten");
    TEST_ASSERT(db_rows(db) == 1, "one row");
    db_drop(db);

    /* Same race, but the winner recorded the identical spend. */
    db_path_fresh(db, sizeof db, "t6b");
    ceremony_opts_t same = { 0, NULL, r.sighash };
    ceremony_result_t s;
    TEST_ASSERT(run_ceremony(db, &same, &s), "harness (identical winner)");
    TEST_ASSERT(s.child_rc == 1, "identical record already present: idempotent success");
    TEST_ASSERT(s.got_final, "exactly one signature for the one spend is released");
    TEST_ASSERT(db_rows(db) == 1, "one row");
    db_drop(db);
    return 1;
}

/* Crash drill around the record, with restart.  The client-side checkpoints
   (lsp_crash_checkpoint names ps_record_pre_save / ps_record_post_save /
   ps_record_post_final) abort the child at the cut point; the next
   run_ceremony on the same DB file is the restart, and the LSP retries the
   same transaction. */
static int test_ps_refusal_crash_drill_restart_semantics_body(void) {
    char db[256];
    ceremony_opts_t clean = { 0, NULL, NULL };
    ceremony_result_t r;
    unsigned char stored[32];

    /* A: crash BEFORE the record.  Nothing recorded, nothing sent; the restart
       signs the same spend normally. */
    db_path_fresh(db, sizeof db, "drillA");
    {
        ceremony_opts_t crash = { 0, "ps_record_pre_save", NULL };
        TEST_ASSERT(run_ceremony(db, &crash, &r), "harness A/crash");
        TEST_ASSERT(r.child_rc == -1 && r.child_signal == SIGABRT, "client aborted at ps_record_pre_save");
        TEST_ASSERT(!r.got_final, "no FINAL before the crash");
        TEST_ASSERT(db_rows(db) == 0, "no record before the crash");
        TEST_ASSERT(run_ceremony(db, &clean, &r), "harness A/restart");
        TEST_ASSERT(r.child_rc == 1 && r.got_final, "restart signs the same spend (no record existed)");
        TEST_ASSERT(db_rows(db) == 1, "restart recorded it");
    }
    db_drop(db);

    /* B: crash BETWEEN the record and FINAL.  The record is durable, FINAL
       never left.  Restart with the identical spend succeeds (idempotent); a
       restart proposing a DIFFERENT spend of the same parent is refused. */
    db_path_fresh(db, sizeof db, "drillB");
    {
        ceremony_opts_t crash = { 0, "ps_record_post_save", NULL };
        TEST_ASSERT(run_ceremony(db, &crash, &r), "harness B/crash");
        TEST_ASSERT(r.child_rc == -1 && r.child_signal == SIGABRT, "client aborted at ps_record_post_save");
        TEST_ASSERT(r.got_pubnonce && !r.got_final, "signed, recorded, but FINAL never left");
        TEST_ASSERT(db_lookup(db, r.parent_txid, stored) == 1 && memcmp(stored, r.sighash, 32) == 0,
                    "the record survived the crash and carries the signed sighash");
        TEST_ASSERT(run_ceremony(db, &clean, &r), "harness B/restart-identical");
        TEST_ASSERT(r.child_rc == 1, "identical retry after the crash succeeds (idempotent)");
        TEST_ASSERT(r.got_final, "identical retry sends FINAL");
        TEST_ASSERT(db_seed(db, r.parent_txid, CONFLICTING_SIGHASH), "record now says: a different spend");
        TEST_ASSERT(run_ceremony(db, &clean, &r), "harness B/restart-conflicting");
        TEST_ASSERT(r.child_rc == 0 && !r.got_pubnonce && !r.got_final,
                    "conflicting retry is refused before any nonce");
    }
    db_drop(db);

    /* C: crash AFTER FINAL left.  The LSP holds our signature; the record is
       there.  A conflicting retry is refused; an identical one is idempotent. */
    db_path_fresh(db, sizeof db, "drillC");
    {
        ceremony_opts_t crash = { 0, "ps_record_post_final", NULL };
        TEST_ASSERT(run_ceremony(db, &crash, &r), "harness C/crash");
        TEST_ASSERT(r.child_rc == -1 && r.child_signal == SIGABRT, "client aborted at ps_record_post_final");
        TEST_ASSERT(r.got_final, "FINAL had already left");
        TEST_ASSERT(db_lookup(db, r.parent_txid, stored) == 1 && memcmp(stored, r.sighash, 32) == 0,
                    "the record matches what left");
        TEST_ASSERT(run_ceremony(db, &clean, &r), "harness C/restart-identical");
        TEST_ASSERT(r.child_rc == 1 && r.got_final, "identical retry is idempotent");
        TEST_ASSERT(db_seed(db, r.parent_txid, CONFLICTING_SIGHASH), "record now says: a different spend");
        TEST_ASSERT(run_ceremony(db, &clean, &r), "harness C/restart-conflicting");
        TEST_ASSERT(r.child_rc == 0 && !r.got_pubnonce && !r.got_final,
                    "conflicting retry is refused before any nonce");
    }
    db_drop(db);
    return 1;
}

/* Public entry points (registered in tests/test_main.c).  Each body runs
   under with_db_cleanup so its temp DBs are removed even when it fails. */
int test_ps_refusal_check_error_refuses(void) { return with_db_cleanup(test_ps_refusal_check_error_refuses_body); }
int test_ps_refusal_save_error_aborts_before_final(void) { return with_db_cleanup(test_ps_refusal_save_error_aborts_before_final_body); }
int test_ps_refusal_sighash_failure_aborts(void) { return with_db_cleanup(test_ps_refusal_sighash_failure_aborts_body); }
int test_ps_refusal_conflicting_record_refuses(void) { return with_db_cleanup(test_ps_refusal_conflicting_record_refuses_body); }
int test_ps_refusal_same_sighash_record_is_idempotent(void) { return with_db_cleanup(test_ps_refusal_same_sighash_record_is_idempotent_body); }
int test_ps_refusal_concurrent_record_race_one_signature(void) { return with_db_cleanup(test_ps_refusal_concurrent_record_race_one_signature_body); }
int test_ps_refusal_crash_drill_restart_semantics(void) { return with_db_cleanup(test_ps_refusal_crash_drill_restart_semantics_body); }
