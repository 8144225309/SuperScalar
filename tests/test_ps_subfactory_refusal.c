/* Pseudo-Spilman record-and-refuse for SUB-FACTORY chain advances
 * (client_handle_subfactory_advance, src/client.c).
 *
 * A NODE_PS_SUBFACTORY chain[N+1] spends every output of chain[N] -- the k
 * channel outputs and the sales-stock -- and nothing revokes it.  The LSP
 * picks channel_idx and delta_sats.  So once this client has co-signed one
 * chain[N] -> chain[N+1], the only thing that stops the LSP from getting a
 * second, different chain[N+1] co-signed (after the client restarted from
 * chain[N]: a crash before it kept the new state, or an older DB) is the
 * client refusing to sign a different spend of an outpoint it has already
 * signed a spend of.  The client records one client_ps_signed_inputs row per
 * input it signs.  These tests assert on whether
 * MSG_SUBFACTORY_CLIENT_FINAL_PSIGS -- the message that carries the client's
 * partial signatures out of the process -- was sent:
 *
 *   conflicting re-proposal (other delta / channel)  -> refused, nothing sent
 *   identical retry after a crash between record and send -> idempotent
 *   injected check / save / sighash failure           -> refused or aborted
 *   INSERT race lost to a different spend             -> nothing sent
 *   second input's INSERT fails                       -> abort; the first
 *       input's row then refuses a different spend and admits the identical
 *       retry
 *   crash drill before / between / after the record, with restart
 *   PROPOSE_INTENT whose n_inputs is not the chain tx's input count, or
 *       whose subfactory_id is not the sub-factory (leaf_side, sub_idx)
 *       names                                         -> refused, unchanged
 *   chain[1] -> chain[2]: the same rules one advance further
 *   hashlock sub-factory (poison active): honest advance, and an insert error
 *
 * Harness: same shape as tests/test_ps_refusal.c.  The client runs in a
 * forked child over a socketpair against an on-disk persist DB (the record
 * has to outlive the child).  The parent plays the LSP and the sub-factory's
 * other client the way lsp_subfactory_chain_advance_stateless_multi does:
 * the child consumes a PROPOSE_INTENT, the parent reads CLIENT_PUBNONCES,
 * generates the other signers' per-input nonces and partial sigs on a
 * mirrored factory, sends LSP_RESPONSE with the full signer x input nonce
 * matrix, then waits for CLIENT_FINAL_PSIGS, aggregates every input and
 * verifies each input's Schnorr signature against its prevout key (what
 * bitcoind would check), and answers DONE.  Without hashlock no poison
 * fields are sent, so the client degrades its poison side-channel, which a
 * non-hashlock sub allows.  With hashlock the parent also runs the poison
 * side-channel, aggregates and verifies the poison, ships the aggregate in
 * DONE and reveals the superseded state's secret, like the LSP.  One run can
 * drive several advances in a row (chain[0] -> chain[1] -> chain[2]) over
 * the same connection; the child reports, per advance, its handler's result
 * and whether its sub-factory state changed.  Both sides build the identical
 * N=5, k=2 PS factory from fixed keys, so a second run on a fresh factory IS
 * the restart-from-chain[0] case, with the same DB file carrying the record
 * across.
 *
 * Sub-factory 0 of leaf 0 has signers {LSP, A, B}; the client under test is A.
 * Every advance spends three inputs: 0 = A's channel (A + LSP), 1 = B's
 * channel (B + LSP; A does not sign it), 2 = sales-stock (all three).  A
 * therefore signs, and records, inputs 0 and 2.
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
#include <secp256k1.h>
#include <secp256k1_musig.h>
#include <secp256k1_schnorrsig.h>
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

#define SF_N 5          /* LSP + 4 clients: 1 leaf, 2 sub-factories of 2 clients */
#define SF_N_INPUTS 3   /* a k=2 sub's chain tx: 2 channels + sales-stock */
#define SF_MAX_STEPS 2  /* advances driven in one run (chain[0] -> [1] -> [2]) */
#define POISON_FEE_SATS 1000

/* The honest advance, and different spends of the same chain[N]. */
#define DELTA_A  50000u
#define DELTA_B  40000u
#define DELTA_C  30000u   /* chain[1] -> chain[2] */
#define DELTA_D  20000u   /* a different chain[2] */

/* ---------------------------------------------------------------- factory */

static void sf_keys(secp256k1_context *ctx, secp256k1_keypair kps[SF_N]) {
    for (size_t i = 0; i < SF_N; i++) {
        unsigned char sk[32] = {0};
        sk[31] = (unsigned char)(i + 1);
        sk[0]  = 0x5F;
        (void)secp256k1_keypair_create(ctx, &kps[i], sk);
    }
}

/* Build the factory.  lsp_hashlock: the LSP's factory with hashlock poison on
   (seeded).  mirror: the client's seedless mirror of such a factory -- every
   node's committed L-stock hash is copied from it before the build, as the
   LSP ships them. */
static int build_sf_factory(secp256k1_context *ctx, const secp256k1_keypair kps[SF_N],
                            int lsp_hashlock, const factory_t *mirror, factory_t **out) {
    unsigned char fund_spk[34];
    {
        secp256k1_pubkey pks[SF_N];
        for (size_t i = 0; i < SF_N; i++)
            secp256k1_keypair_pub(ctx, &pks[i], &kps[i]);
        musig_keyagg_t ka;
        musig_aggregate_keys(ctx, &ka, pks, SF_N);
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
    memset(fake_fund_txid, 0x5A, 32);

    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;
    /* factory_init zeroes *f and allocates its own arrays. */
    factory_init(f, ctx, kps, SF_N, 6, 10);
    factory_set_arity(f, FACTORY_ARITY_PS);
    factory_set_ps_subfactory_arity(f, 2);
    factory_set_funding(f, fake_fund_txid, 0, 2000000, fund_spk, 34);
    if (lsp_hashlock) {
        unsigned char seed[32];
        for (int i = 0; i < 32; i++) seed[i] = (unsigned char)(0x3C ^ i);
        factory_set_shachain_seed(f, seed);
        if (!factory_enable_hashlock_poison(f)) { factory_free(f); free(f); return 0; }
    }
    if (mirror) {
        for (size_t i = 0; i < mirror->n_nodes; i++)
            if (mirror->nodes[i].has_l_stock_hash)
                factory_set_node_l_stock_hash(f, i, mirror->nodes[i].l_stock_hash);
    }
    if (!factory_build_tree(f) || !factory_sign_all(f)) {
        factory_free(f);
        free(f);
        return 0;
    }
    *out = f;
    return 1;
}

/* Sub-factory 0 of leaf 0, its first two clients (A = under test, B), and
   leaf 0's sub-factory 1 (for the "names another sub-factory" cases). */
static int sf_pick(const factory_t *f, size_t *sub_node_i, uint32_t *a, uint32_t *b,
                   size_t *other_sub_node_i) {
    const factory_node_t *leaf = &f->nodes[f->leaf_node_indices[0]];
    if (leaf->n_subfactories < 2 || leaf->subfactory_node_indices[0] < 0 ||
        leaf->subfactory_node_indices[1] < 0) return 0;
    *sub_node_i = (size_t)leaf->subfactory_node_indices[0];
    *other_sub_node_i = (size_t)leaf->subfactory_node_indices[1];
    const factory_node_t *sub = &f->nodes[*sub_node_i];
    if (sub->type != NODE_PS_SUBFACTORY || sub->n_signers != 3 ||
        sub->n_outputs != SF_N_INPUTS) return 0;
    *a = sub->signer_indices[1];
    *b = sub->signer_indices[2];
    return 1;
}

/* Layout of finalize_signed_tx_multi (see test_factory_multi_input_keyagg.c). */
static int extract_input_sig(const unsigned char *tx, size_t tx_len,
                             size_t n_inputs, size_t n_outputs,
                             size_t input_idx, unsigned char sig_out[64]) {
    if (tx_len < 10) return 0;
    size_t pos = 6;
    if ((size_t)tx[pos] != n_inputs) return 0;
    pos += 1 + 41 * n_inputs;
    if ((size_t)tx[pos] != n_outputs) return 0;
    pos += 1;
    for (size_t i = 0; i < n_outputs; i++) {
        pos += 8;
        size_t spk_len = (size_t)tx[pos];
        pos += 1 + spk_len;
    }
    for (size_t i = 0; i < n_inputs; i++) {
        if (pos + 66 > tx_len || tx[pos] != 0x01 || tx[pos + 1] != 0x40) return 0;
        if (i == input_idx) {
            memcpy(sig_out, tx + pos + 2, 64);
            return 1;
        }
        pos += 66;
    }
    return 0;
}

/* ------------------------------------------------------------ DB helpers */

#define SF_MAX_TEST_DBS 16
static char g_test_dbs[SF_MAX_TEST_DBS][256];
static int g_n_test_dbs = 0;

/* A fresh DB path, registered for cleanup.  0 if the cleanup table is full
   (the caller asserts on it, so a test can never leave an untracked file). */
static int db_path_fresh(char *buf, size_t n, const char *tag) {
    if (g_n_test_dbs >= SF_MAX_TEST_DBS) return 0;
    snprintf(buf, n, "/tmp/ss_ps_sub_refusal_%s_%d.db", tag, (int)getpid());
    snprintf(g_test_dbs[g_n_test_dbs], sizeof g_test_dbs[0], "%s", buf);
    g_n_test_dbs++;
    char side[320];
    unlink(buf);
    snprintf(side, sizeof side, "%s-wal", buf); unlink(side);
    snprintf(side, sizeof side, "%s-shm", buf); unlink(side);
    return 1;
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

static long db_count(const char *path, const char *sql) {
    persist_t db;
    if (!persist_open(&db, path)) return -1;
    long n = -1;
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db.db, sql, -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW) n = (long)sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    persist_close(&db);
    return n;
}

/* Rows in client_ps_signed_inputs. */
static long db_rows(const char *path) {
    return db_count(path, "SELECT COUNT(*) FROM client_ps_signed_inputs;");
}

/* Sub-factory poison recourse the client persisted after DONE (template),
   and with the revealed secret. */
static long db_poison_rows(const char *path) {
    return db_count(path, "SELECT COUNT(*) FROM l_stock_poison_reveals;");
}
static long db_poison_secrets(const char *path) {
    return db_count(path, "SELECT COUNT(*) FROM l_stock_poison_reveals "
                          "WHERE revocation_secret IS NOT NULL;");
}

/* What the client recorded for (parent, vout): -1 error, 0 none, 1 found. */
static int db_lookup(const char *path, const unsigned char parent[32], uint32_t vout,
                     unsigned char out_sighash[32]) {
    persist_t db;
    if (!persist_open(&db, path)) return -1;
    int rc = persist_check_ps_signed_input(&db, 0, parent, vout, out_sighash);
    persist_close(&db);
    return rc;
}

/* ------------------------------------------------------------ the harness */

typedef struct {
    uint64_t delta;                     /* delta_sats proposed */
    int channel_idx;                    /* channel_idx proposed */
    uint32_t n_inputs;                  /* declared in PROPOSE_INTENT; 0 = honest */
    int fail_point;                     /* PERSIST_TEST_PS_* to fail, or 0 */
    int fail_nth;                       /* fail its nth firing (1-based); 0 = first */
    const char *crash_at;               /* client crash checkpoint, or NULL */
    const unsigned char *race_sighash;  /* at the first SAVE a second connection
                                           records this for (parent, race_vout) */
    uint32_t race_vout;
    int name_other_sub;                 /* 1: subfactory_id names leaf 0's sub 1;
                                           2: sub_idx names sub 1.  0: consistent */
} sf_opts_t;

typedef struct {
    int child_rc;        /* 1 handler succeeded, 0 failed, -1 child died in this
                            advance (signal), -2 advance never reached */
    int child_signal;
    int changed;         /* the client's sub-factory state changed in this advance */
    int chain_len_after; /* the client's sub 0 ps_chain_len after it */
    int got_pubnonce;    /* CLIENT_PUBNONCES reached the LSP (nonces were generated) */
    int got_after_resp;  /* any message at all reached the LSP after LSP_RESPONSE */
    int got_final;       /* CLIENT_FINAL_PSIGS reached the LSP */
    int final_valid;     /* ...and with them every input of the new chain tx verifies */
    int input_valid[SF_N_INPUTS];  /* per input: its aggregated sig verifies */
    int got_poison_psig; /* FINAL_PSIGS carried the client's poison partial sig */
    int poison_valid;    /* ...and the aggregated poison verifies */
    unsigned char parent_txid[32];  /* chain[N]: the sub's pre-advance txid */
    unsigned char new_txid[32];     /* the chain[N+1] the LSP side built */
    unsigned char sighash[SF_N_INPUTS][32];  /* per-input session msg32, LSP side */
} sf_result_t;

/* What the child reports per advance through a pipe. */
typedef struct { int rc; int changed; int chain_len_after; } sf_child_report_t;

typedef struct {
    const sf_opts_t *o;
    const char *dbpath;
    int sub_node;
    int fail_count;
    int raced;
    unsigned char parent_txid[32];
} sf_hook_state_t;

static int sf_child_hook(int point, void *user) {
    sf_hook_state_t *st = (sf_hook_state_t *)user;
    if (!st->o) return 0;
    if (st->o->race_sighash && point == PERSIST_TEST_PS_SAVE && !st->raced) {
        /* Another ceremony for the same parent passed its pre-sign checks too
           and records first, through a second connection; then this
           ceremony's own INSERT runs -- and loses. */
        st->raced = 1;
        persist_t other;
        if (persist_open(&other, st->dbpath)) {
            unsigned char psig[36];
            memset(psig, 0xC0, 36);
            (void)persist_save_ps_signed_input(&other, 0, st->sub_node, st->parent_txid,
                                               st->o->race_vout, st->o->race_sighash, psig);
            persist_close(&other);
        }
        return 0;
    }
    if (st->o->fail_point && point == st->o->fail_point) {
        st->fail_count++;
        if (st->fail_count == (st->o->fail_nth ? st->o->fail_nth : 1))
            return 1;  /* inject the failure on exactly this firing */
    }
    return 0;
}

/* Waits for the child; returns its exit status in *status (0 on a harness
   timeout, after killing it). */
static int wait_child(pid_t pid, int *status) {
    for (int i = 0; i < 600; i++) {  /* up to 60 s, then give up */
        pid_t w = waitpid(pid, status, WNOHANG);
        if (w == pid) return 1;
        if (w < 0) return 0;
        struct timespec ts = { 0, 100 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    kill(pid, SIGKILL);
    waitpid(pid, status, 0);
    return 0;
}

/* Fingerprint of every sub-factory node's chain state, to tell whether an
   advance changed anything locally. */
static void sf_state_fingerprint(const factory_t *f, unsigned char out[32]) {
    const size_t per = sizeof(int) + 64 + FACTORY_MAX_OUTPUTS * sizeof(uint64_t);
    unsigned char *buf = calloc(f->n_nodes ? f->n_nodes : 1, per);
    size_t len = 0;
    if (!buf) { memset(out, 0xFF, 32); return; }
    for (size_t i = 0; i < f->n_nodes; i++) {
        const factory_node_t *n = &f->nodes[i];
        if (n->type != NODE_PS_SUBFACTORY) continue;
        memcpy(buf + len, &n->ps_chain_len, sizeof n->ps_chain_len);
        len += sizeof n->ps_chain_len;
        memcpy(buf + len, n->txid, 32); len += 32;
        memcpy(buf + len, n->ps_prev_txid, 32); len += 32;
        for (size_t o = 0; o < FACTORY_MAX_OUTPUTS; o++) {
            uint64_t a = (o < n->n_outputs) ? n->outputs[o].amount_sats : 0;
            memcpy(buf + len, &a, sizeof a);
            len += sizeof a;
        }
    }
    sha256(buf, len, out);
    free(buf);
}

/* The LSP (and client B) for one advance of sub 0 declaring n inputs, as
   lsp_subfactory_chain_advance_stateless_multi -- with the poison
   side-channel when the factory has hashlock on.  Returns 1 if the harness
   worked (EOF from the client is an outcome, not a harness error). */
static int lsp_side_multi(secp256k1_context *ctx, const secp256k1_keypair kps[SF_N],
                          factory_t *f, size_t sub_node_i, uint32_t client, int fd,
                          const sf_opts_t *o, size_t n, sf_result_t *r) {
    factory_node_t *sub = &f->nodes[sub_node_i];
    memcpy(r->parent_txid, sub->txid, 32);

    /* Poison prep from the soon-to-be-superseded state, before the advance. */
    int poison = 0;
    if (f->use_hashlock_poison) {
        unsigned char old_txid[32];
        memcpy(old_txid, sub->txid, 32);
        size_t old_n_chans = sub->n_outputs - 1;
        uint64_t old_sstock = sub->outputs[sub->n_outputs - 1].amount_sats;
        if (old_sstock <= POISON_FEE_SATS + (uint64_t)old_n_chans * 330u ||
            !factory_session_prepare_poison_tx_subfactory(f, sub_node_i, old_txid,
                                                          (uint32_t)old_n_chans, old_sstock,
                                                          POISON_FEE_SATS, NULL))
            return 0;
        poison = 1;
    }
    if (!factory_subfactory_chain_advance_unsigned(f, 0, 0, o->channel_idx, o->delta))
        return 0;
    memcpy(r->new_txid, sub->txid, 32);
    size_t n_real = sub->ps_n_prev_outputs;
    if (n < 2 || n > n_real) return 0;
    for (size_t i = 0; i < n; i++)
        if (!factory_session_init_node_input(f, sub_node_i, i)) return 0;
    if (poison && !factory_session_init_node_poison(f, sub_node_i)) return 0;

    wire_msg_t cpn;
    if (!wire_recv(fd, &cpn)) return 1;  /* EOF: refused before any nonce */
    if (cpn.msg_type != MSG_SUBFACTORY_CLIENT_PUBNONCES) {
        cJSON_Delete(cpn.json);
        return 0;
    }
    r->got_pubnonce = 1;
    unsigned char client_pn[SF_N_INPUTS * 66], client_poison_pn[66];
    int prc = wire_parse_subfactory_client_pubnonces(cpn.json, client_pn, (uint32_t)n,
                                                     poison ? client_poison_pn : NULL);
    cJSON_Delete(cpn.json);
    if (!prc || (poison && prc != 2)) return 0;

    const size_t ns = sub->n_signers;
    if (ns > SF_N) return 0;
    int client_slot = factory_find_signer_slot(f, sub_node_i, client);
    int lsp_slot = factory_find_signer_slot(f, sub_node_i, 0);
    if (client_slot < 0 || lsp_slot < 0) return 0;
    unsigned char *matrix = calloc(ns * n, 66);  /* [node slot][input] pubnonces */
    if (!matrix) return 0;
    unsigned char lsp_pn[SF_N_INPUTS * 66], lsp_ps[SF_N_INPUTS * 32];
    memset(lsp_pn, 0, sizeof lsp_pn);
    memset(lsp_ps, 0, sizeof lsp_ps);
    for (size_t i = 0; i < n; i++)
        memcpy(matrix + ((size_t)client_slot * n + i) * 66, client_pn + i * 66, 66);

    int ok = 1;
    for (size_t i = 0; i < n && ok; i++) {
        secp256k1_musig_secnonce secn[SF_N];
        memset(secn, 0, sizeof secn);
        /* Nonces for every signer of input i the parent plays (all but the client). */
        for (size_t s = 0; s < ns && ok; s++) {
            uint32_t p = sub->signer_indices[s];
            if (p == client || !factory_session_input_signs(f, sub_node_i, i, p)) continue;
            unsigned char sk[32];
            secp256k1_pubkey pk;
            secp256k1_musig_pubnonce pn;
            secp256k1_keypair_sec(ctx, sk, &kps[p]);
            secp256k1_keypair_pub(ctx, &pk, &kps[p]);
            if (!musig_generate_nonce(ctx, &secn[s], &pn, sk, &pk,
                                      &sub->input_keyaggs[i].cache))
                ok = 0;
            else
                musig_pubnonce_serialize(ctx, matrix + (s * n + i) * 66, &pn);
            memset(sk, 0, 32);
        }
        for (size_t s = 0; s < ns && ok; s++) {
            int slot_i = factory_session_get_input_signer_slot(f, sub_node_i, i,
                                                               sub->signer_indices[s]);
            if (slot_i < 0) continue;
            secp256k1_musig_pubnonce pn;
            if (!musig_pubnonce_parse(ctx, &pn, matrix + (s * n + i) * 66) ||
                !factory_session_set_nonce_input(f, sub_node_i, i, (size_t)slot_i, &pn))
                ok = 0;
        }
        if (ok && !factory_session_finalize_node_input(f, sub_node_i, i)) ok = 0;
        if (ok && i < SF_N_INPUTS)
            memcpy(r->sighash[i], sub->input_signing_sessions[i].msg32, 32);
        for (size_t s = 0; s < ns && ok; s++) {
            uint32_t p = sub->signer_indices[s];
            if (p == client) continue;
            int slot_i = factory_session_get_input_signer_slot(f, sub_node_i, i, p);
            if (slot_i < 0) continue;
            secp256k1_musig_partial_sig ps;
            if (!musig_create_partial_sig(ctx, &ps, &secn[s], &kps[p],
                                          &sub->input_signing_sessions[i]) ||
                !factory_session_set_partial_sig_input(f, sub_node_i, i,
                                                       (size_t)slot_i, &ps))
                ok = 0;
            else if (p == 0)
                musig_partial_sig_serialize(ctx, lsp_ps + i * 32, &ps);
        }
        memcpy(lsp_pn + i * 66, matrix + ((size_t)lsp_slot * n + i) * 66, 66);
        memset(secn, 0, sizeof secn);
    }

    /* Poison side-channel: one N-of-N session over the sub's key. */
    unsigned char all_poison_pn[SF_N * 66], lsp_poison_ps[32];
    memset(all_poison_pn, 0, sizeof all_poison_pn);
    memset(lsp_poison_ps, 0, sizeof lsp_poison_ps);
    if (ok && poison) {
        secp256k1_musig_secnonce psecn[SF_N];
        memset(psecn, 0, sizeof psecn);
        memcpy(all_poison_pn + (size_t)client_slot * 66, client_poison_pn, 66);
        for (size_t s = 0; s < ns && ok; s++) {
            uint32_t p = sub->signer_indices[s];
            if (p == client) continue;
            unsigned char sk[32];
            secp256k1_pubkey pk;
            secp256k1_musig_pubnonce pn;
            secp256k1_keypair_sec(ctx, sk, &kps[p]);
            secp256k1_keypair_pub(ctx, &pk, &kps[p]);
            if (!musig_generate_nonce(ctx, &psecn[s], &pn, sk, &pk, &sub->keyagg.cache))
                ok = 0;
            else
                musig_pubnonce_serialize(ctx, all_poison_pn + s * 66, &pn);
            memset(sk, 0, 32);
        }
        for (size_t s = 0; s < ns && ok; s++) {
            secp256k1_musig_pubnonce pn;
            if (!musig_pubnonce_parse(ctx, &pn, all_poison_pn + s * 66) ||
                !factory_session_set_nonce_poison(f, sub_node_i, s, &pn))
                ok = 0;
        }
        if (ok && !factory_session_finalize_node_poison(f, sub_node_i)) ok = 0;
        for (size_t s = 0; s < ns && ok; s++) {
            uint32_t p = sub->signer_indices[s];
            if (p == client) continue;
            secp256k1_musig_partial_sig ps;
            if (!musig_create_partial_sig(ctx, &ps, &psecn[s], &kps[p],
                                          &sub->poison_signing_session) ||
                !factory_session_set_partial_sig_poison(f, sub_node_i, s, &ps))
                ok = 0;
            else if (p == 0)
                musig_partial_sig_serialize(ctx, lsp_poison_ps, &ps);
        }
        memset(psecn, 0, sizeof psecn);
    }
    if (!ok) { free(matrix); return 0; }
    cJSON *resp = wire_build_subfactory_lsp_response(
        lsp_pn, lsp_ps, (uint32_t)n, matrix, (uint32_t)(ns * n * 66),
        poison ? all_poison_pn : NULL, poison ? (uint32_t)(ns * 66) : 0,
        poison ? lsp_poison_ps : NULL);
    free(matrix);
    int sent = wire_send(fd, MSG_SUBFACTORY_LSP_RESPONSE, resp);
    cJSON_Delete(resp);
    if (!sent) return 0;

    /* Did the client's signatures leave its process?  FINAL_PSIGS is the only
       message that can carry them (the poison partial sig included). */
    wire_msg_t fin;
    if (!wire_recv(fd, &fin)) return 1;  /* EOF: refused, aborted or crashed first */
    r->got_after_resp = 1;
    if (fin.msg_type != MSG_SUBFACTORY_CLIENT_FINAL_PSIGS) {
        cJSON_Delete(fin.json);
        return 0;
    }
    r->got_final = 1;
    unsigned char cps[SF_N_INPUTS * 32], client_poison_ps[32];
    int frc = wire_parse_subfactory_client_final_psigs(fin.json, cps, (uint32_t)n,
                                                       poison ? client_poison_ps : NULL);
    cJSON_Delete(fin.json);
    if (!frc) return 0;
    r->got_poison_psig = (frc == 2);

    /* Is what left a usable signature?  Add the client's partial sigs,
       aggregate every input and verify each against its prevout key. */
    if (n == n_real) {
        int valid = 1;
        for (size_t i = 0; i < n && valid; i++) {
            int slot_i = factory_session_get_input_signer_slot(f, sub_node_i, i, client);
            if (slot_i < 0) continue;
            secp256k1_musig_partial_sig ps;
            if (!musig_partial_sig_parse(ctx, &ps, cps + i * 32) ||
                !factory_session_set_partial_sig_input(f, sub_node_i, i, (size_t)slot_i, &ps))
                valid = 0;
        }
        int assembled = valid && factory_session_assemble_signed_tx_multi(f, sub_node_i);
        int all = assembled;
        for (size_t i = 0; i < n && i < SF_N_INPUTS && assembled; i++) {
            unsigned char sig64[64];
            secp256k1_xonly_pubkey xo;
            r->input_valid[i] =
                extract_input_sig(sub->signed_tx.data, sub->signed_tx.len,
                                  n, sub->n_outputs, i, sig64) &&
                sub->ps_prev_spk_lens[i] == 34 &&
                secp256k1_xonly_pubkey_parse(ctx, &xo, sub->ps_prev_spks[i] + 2) &&
                secp256k1_schnorrsig_verify(ctx, sig64, r->sighash[i], 32, &xo);
            all = all && r->input_valid[i];
        }
        r->final_valid = all;
    }
    if (poison && r->got_poison_psig) {
        secp256k1_musig_partial_sig ps;
        secp256k1_pubkey ppk;
        secp256k1_xonly_pubkey pxo;
        r->poison_valid =
            musig_partial_sig_parse(ctx, &ps, client_poison_ps) &&
            factory_session_set_partial_sig_poison(f, sub_node_i, (size_t)client_slot, &ps) &&
            factory_session_complete_node_poison(f, sub_node_i) &&
            sub->poison_has_agg_sig &&
            secp256k1_musig_pubkey_get(ctx, &ppk, &sub->poison_signing_session.cache) &&
            secp256k1_xonly_pubkey_from_pubkey(ctx, &pxo, NULL, &ppk) &&
            secp256k1_schnorrsig_verify(ctx, sub->poison_agg_sig,
                                        sub->poison_signing_session.msg32, 32, &pxo);
    }
    cJSON *done = wire_build_subfactory_done(0, 0, (uint32_t)sub->ps_chain_len);
    if (poison && r->poison_valid)
        wire_subfactory_done_set_poison_aggsig(done, sub->poison_agg_sig);
    (void)wire_send(fd, MSG_SUBFACTORY_DONE, done);
    cJSON_Delete(done);
    if (poison && r->poison_valid) {
        /* Reveal the superseded state's sales-stock secret, as the LSP does. */
        uint32_t old_counter = sub->l_stock_state_counter - 1u;
        unsigned char secret[1][32];
        if (!factory_derive_l_stock_secret(f, sub, old_counter, secret[0])) return 0;
        uint32_t rn = (uint32_t)sub_node_i;
        cJSON *rev = wire_build_lstock_reveal(&rn, &old_counter, secret, 1);
        memset(secret, 0, sizeof secret);
        if (!rev) return 0;
        (void)wire_send(fd, MSG_LSTOCK_REVEAL, rev);
        cJSON_Delete(rev);
    }
    return 1;
}

/* The LSP for a single-input PROPOSE_INTENT (n_inputs = 1).  The client no
   longer has a single-input ceremony and refuses at the dispatcher, so this
   only ever sees EOF -- except on a build that still has that ceremony,
   which this plays far enough to see whether the client sent its partial
   sig: one node-level session over the sub's N-of-N key, every signer's
   nonce forwarded.  Its message is not a BIP-341 sighash of any input of
   the k+1-input chain tx, so there is nothing to verify it against. */
static int lsp_side_single(secp256k1_context *ctx, const secp256k1_keypair kps[SF_N],
                           factory_t *f, size_t sub_node_i, uint32_t client, int fd,
                           const sf_opts_t *o, sf_result_t *r) {
    factory_node_t *sub = &f->nodes[sub_node_i];
    memcpy(r->parent_txid, sub->txid, 32);
    if (!factory_subfactory_chain_advance_unsigned(f, 0, 0, o->channel_idx, o->delta))
        return 0;
    memcpy(r->new_txid, sub->txid, 32);

    wire_msg_t cpn;
    if (!wire_recv(fd, &cpn)) return 1;  /* EOF: refused before any nonce */
    if (cpn.msg_type != MSG_SUBFACTORY_CLIENT_PUBNONCES) {
        cJSON_Delete(cpn.json);
        return 0;
    }
    r->got_pubnonce = 1;
    unsigned char client_pn[66];
    int prc = wire_parse_subfactory_client_pubnonces(cpn.json, client_pn, 1, NULL);
    cJSON_Delete(cpn.json);
    if (!prc) return 0;

    const size_t ns = sub->n_signers;
    if (ns > SF_N) return 0;
    unsigned char all[SF_N * 66];
    memset(all, 0, sizeof all);
    int client_slot = factory_find_signer_slot(f, sub_node_i, client);
    int lsp_slot = factory_find_signer_slot(f, sub_node_i, 0);
    if (client_slot < 0 || lsp_slot < 0) return 0;
    memcpy(all + (size_t)client_slot * 66, client_pn, 66);
    for (size_t s = 0; s < ns; s++) {
        uint32_t p = sub->signer_indices[s];
        if (p == client) continue;
        unsigned char sk[32];
        secp256k1_pubkey pk;
        secp256k1_musig_secnonce secn;
        secp256k1_musig_pubnonce pn;
        secp256k1_keypair_sec(ctx, sk, &kps[p]);
        secp256k1_keypair_pub(ctx, &pk, &kps[p]);
        int g = musig_generate_nonce(ctx, &secn, &pn, sk, &pk, &sub->keyagg.cache);
        memset(sk, 0, 32);
        memset(&secn, 0, sizeof secn);  /* the parent never signs this message */
        if (!g) return 0;
        musig_pubnonce_serialize(ctx, all + s * 66, &pn);
    }
    unsigned char lsp_ps[32];
    memset(lsp_ps, 0x01, sizeof lsp_ps);  /* that ceremony never parses it */
    cJSON *resp = wire_build_subfactory_lsp_response(all + (size_t)lsp_slot * 66, lsp_ps, 1,
                                                     all, (uint32_t)(ns * 66),
                                                     NULL, 0, NULL);
    int sent = wire_send(fd, MSG_SUBFACTORY_LSP_RESPONSE, resp);
    cJSON_Delete(resp);
    if (!sent) return 0;

    wire_msg_t fin;
    if (!wire_recv(fd, &fin)) return 1;
    r->got_after_resp = 1;
    if (fin.msg_type != MSG_SUBFACTORY_CLIENT_FINAL_PSIGS) {
        cJSON_Delete(fin.json);
        return 0;
    }
    r->got_final = 1;
    cJSON_Delete(fin.json);
    cJSON *done = wire_build_subfactory_done(0, 0, (uint32_t)sub->ps_chain_len);
    (void)wire_send(fd, MSG_SUBFACTORY_DONE, done);
    cJSON_Delete(done);
    return 1;
}

/* Run n_steps consecutive advances of sub 0 (chain[0] -> chain[1] -> ...)
   against dbpath, from a fresh factory.  res[k] is the outcome of advance k.
   Returns 1 when the harness itself worked, 0 on a harness error. */
static int run_sf_steps(const char *dbpath, int hashlock, const sf_opts_t *steps,
                        int n_steps, sf_result_t res[]) {
    if (n_steps < 1 || n_steps > SF_MAX_STEPS) return 0;
    memset(res, 0, sizeof(sf_result_t) * (size_t)n_steps);
    for (int k = 0; k < n_steps; k++) res[k].child_rc = -2;
    /* A child that aborts after FINAL_PSIGS leaves us writing DONE to a dead
       peer: ignore SIGPIPE for the run, restore the caller's handler after. */
    void (*old_sigpipe)(int) = signal(SIGPIPE, SIG_IGN);

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_keypair kps[SF_N];
    sf_keys(ctx, kps);
    factory_t *f = NULL, *fc = NULL;  /* LSP's factory, client's factory */
    int ok = build_sf_factory(ctx, kps, hashlock, NULL, &f) &&
             build_sf_factory(ctx, kps, 0, hashlock ? f : NULL, &fc);
    size_t sub_node_i = 0, other_sub = 0;
    uint32_t client = 0, other = 0;
    ok = ok && sf_pick(f, &sub_node_i, &client, &other, &other_sub) &&
         memcmp(f->nodes[sub_node_i].txid, fc->nodes[sub_node_i].txid, 32) == 0;
    (void)other;
    /* With hashlock the PROPOSE_INTENT ships the NEW state's H, which the LSP
       derives from its seed: H(state k+1) for advance k. */
    unsigned char h_new[SF_MAX_STEPS][32];
    memset(h_new, 0, sizeof h_new);
    for (int k = 0; ok && hashlock && k < n_steps; k++) {
        unsigned char s[32];
        ok = factory_derive_l_stock_secret(f, &f->nodes[sub_node_i],
                                           f->nodes[sub_node_i].l_stock_state_counter +
                                           (uint32_t)k + 1u, s);
        sha256(s, 32, h_new[k]);
        memset(s, 0, sizeof s);
    }
    int sv[2] = { -1, -1 }, pfd[2] = { -1, -1 };
    if (ok && (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0 || pipe(pfd) != 0)) ok = 0;
    if (!ok) {
        if (sv[0] >= 0) { close(sv[0]); close(sv[1]); }
        if (pfd[0] >= 0) { close(pfd[0]); close(pfd[1]); }
        if (fc) { factory_free(fc); free(fc); }
        if (f) { factory_free(f); free(f); }
        secp256k1_context_destroy(ctx);
        signal(SIGPIPE, old_sigpipe);
        return 0;
    }
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) {
        close(sv[0]); close(sv[1]); close(pfd[0]); close(pfd[1]);
        factory_free(fc); free(fc); factory_free(f); free(f);
        secp256k1_context_destroy(ctx);
        signal(SIGPIPE, old_sigpipe);
        return 0;
    }
    if (pid == 0) {
        /* ---- child: client A, on its own (seedless) factory ---- */
        close(sv[0]);
        close(pfd[0]);
        wire_set_timeout(sv[1], 30);  /* a harness deadlock fails, never hangs */
        persist_t db;
        if (!persist_open(&db, dbpath)) _exit(3);
        client_set_persist(&db);
        /* Tree advances are refused unless the harness opts in; opt in so
           the proposals reach the record-and-refuse path under test. */
        client_set_allow_tree_advance(1);
        sf_hook_state_t st;
        memset(&st, 0, sizeof st);
        st.dbpath = dbpath;
        st.sub_node = (int)sub_node_i;
        persist_test_set_ps_hook(sf_child_hook, &st);
        struct rlimit no_core = { 0, 0 };  /* the drill abort()s on purpose */
        (void)setrlimit(RLIMIT_CORE, &no_core);
        for (int k = 0; k < n_steps; k++) {
            const sf_opts_t *o = &steps[k];
            st.o = o;
            st.fail_count = 0;
            st.raced = 0;
            memcpy(st.parent_txid, fc->nodes[sub_node_i].txid, 32);
            lsp_crash_set_target(o->crash_at);
            const uint32_t n_decl = o->n_inputs ? o->n_inputs
                                                : (uint32_t)fc->nodes[sub_node_i].n_outputs;
            uint32_t named = (o->name_other_sub == 1) ? (uint32_t)other_sub
                                                      : (uint32_t)sub_node_i;
            int sub_idx = (o->name_other_sub == 2) ? 1 : 0;
            wire_msg_t propose;
            memset(&propose, 0, sizeof propose);
            propose.msg_type = MSG_SUBFACTORY_PROPOSE_INTENT;
            propose.json = wire_build_subfactory_propose_intent(named, n_decl, 0, sub_idx,
                                                                o->channel_idx, o->delta);
            if (hashlock)
                wire_json_add_hex(propose.json, "l_stock_hash", h_new[k], 32);
            unsigned char before[32], after[32];
            sf_state_fingerprint(fc, before);
            int rc = client_handle_subfactory_advance(sv[1], ctx, &kps[client], fc, client,
                                                      &propose);
            cJSON_Delete(propose.json);
            sf_state_fingerprint(fc, after);
            sf_child_report_t rep = { rc ? 1 : 0, memcmp(before, after, 32) != 0,
                                      fc->nodes[sub_node_i].ps_chain_len };
            if (write(pfd[1], &rep, sizeof rep) != (ssize_t)sizeof rep) _exit(4);
            if (!rc) break;  /* the LSP stops at a failed advance too */
        }
        lsp_crash_set_target(NULL);
        client_set_allow_tree_advance(0);
        client_set_persist(NULL);
        persist_test_set_ps_hook(NULL, NULL);
        persist_close(&db);
        close(sv[1]);
        close(pfd[1]);
        fflush(stdout);  /* _exit skips stdio: keep the client's log lines */
        _exit(0);
    }

    /* ---- parent: the LSP + client B.  wire_set_timeout sets SO_RCVTIMEO /
       SO_SNDTIMEO, so a harness deadlock fails the test instead of hanging
       the suite; wait_child bounds the child the same way. ---- */
    close(sv[1]);
    close(pfd[1]);
    wire_set_timeout(sv[0], 20);
    for (int k = 0; k < n_steps && ok; k++) {
        const uint32_t n_decl = steps[k].n_inputs ? steps[k].n_inputs
                                                  : (uint32_t)f->nodes[sub_node_i].n_outputs;
        int hrc = (n_decl == 1)
            ? lsp_side_single(ctx, kps, f, sub_node_i, client, sv[0], &steps[k], &res[k])
            : lsp_side_multi(ctx, kps, f, sub_node_i, client, sv[0], &steps[k], n_decl,
                             &res[k]);
        if (!hrc)
            ok = 0;
        else if (!res[k].got_final)
            break;
    }
    close(sv[0]);
    int status = 0;
    if (!wait_child(pid, &status)) ok = 0;
    for (int k = 0; k < n_steps; k++) {
        sf_child_report_t rep;
        if (read(pfd[0], &rep, sizeof rep) != (ssize_t)sizeof rep) {
            /* No report: the child died in this advance, or never reached it. */
            if (WIFSIGNALED(status)) {
                res[k].child_rc = -1;
                res[k].child_signal = WTERMSIG(status);
            }
            break;
        }
        res[k].child_rc = rep.rc;
        res[k].changed = rep.changed;
        res[k].chain_len_after = rep.chain_len_after;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) ok = 0;  /* harness error in the child */
    close(pfd[0]);

    factory_free(fc);
    free(fc);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    signal(SIGPIPE, old_sigpipe);
    return ok;
}

/* One advance (chain[0] -> chain[1]), no hashlock. */
static int run_sf_ceremony(const char *dbpath, const sf_opts_t *o, sf_result_t *r) {
    return run_sf_steps(dbpath, 0, o, 1, r);
}

static const unsigned char CONFLICTING_SIGHASH[32] = {
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };

/* For the parent of `want`: A's inputs 0 (its channel) and 2 (sales-stock)
   carry want's sighashes and B's channel (1) has no row. */
static int rows_match_parent(const char *db, const sf_result_t *want) {
    unsigned char s[32];
    return db_lookup(db, want->parent_txid, 0, s) == PS_SIGNED_INPUT_FOUND &&
           memcmp(s, want->sighash[0], 32) == 0 &&
           db_lookup(db, want->parent_txid, 1, s) == PS_SIGNED_INPUT_NOT_FOUND &&
           db_lookup(db, want->parent_txid, 2, s) == PS_SIGNED_INPUT_FOUND &&
           memcmp(s, want->sighash[2], 32) == 0;
}

/* ...and those two rows are the only ones. */
static int rows_match(const char *db, const sf_result_t *want) {
    return db_rows(db) == 2 && rows_match_parent(db, want);
}

#define DB_FRESH(buf, tag) TEST_ASSERT(db_path_fresh(buf, sizeof buf, tag), \
                                       "temp DB cleanup table full")
#define OPTS(delta, chan) { (delta), (chan), 0, 0, 0, NULL, NULL, 0, 0 }

/* ------------------------------------------------------------------ tests */

/* The attack.  A co-signs chain[0] -> chain[1] (delta A).  It restarts from
   chain[0] and the LSP proposes a different chain[1] spending the same
   outputs: another delta, then the same delta into the other channel.  Each
   must be refused before any nonce; without the record, A co-signs a second,
   fully valid, conflicting chain[1]. */
static int test_ps_subfactory_refusal_conflicting_reproposal_refused_body(void) {
    char db[256];
    DB_FRESH(db, "conflict");
    sf_opts_t honest = OPTS(DELTA_A, 0);
    sf_opts_t other_delta = OPTS(DELTA_B, 0);
    sf_opts_t other_chan = OPTS(DELTA_A, 1);
    sf_result_t a, b, c;

    TEST_ASSERT(run_sf_ceremony(db, &honest, &a), "harness A");
    TEST_ASSERT(a.child_rc == 1 && a.got_final && a.final_valid,
                "first advance succeeds and every input of chain[1] verifies");

    TEST_ASSERT(run_sf_ceremony(db, &other_delta, &b), "harness B");
    TEST_ASSERT(memcmp(b.parent_txid, a.parent_txid, 32) == 0 &&
                memcmp(b.new_txid, a.new_txid, 32) != 0,
                "B is a different chain[1] spending the same chain[0]");
    TEST_ASSERT(!(b.got_final && b.final_valid),
                "client co-signed a second, valid, conflicting chain[1] (other delta)");
    TEST_ASSERT(b.child_rc == 0 && !b.got_pubnonce && !b.got_final,
                "other delta: refused before any nonce, nothing sent");

    TEST_ASSERT(run_sf_ceremony(db, &other_chan, &c), "harness C");
    TEST_ASSERT(memcmp(c.new_txid, a.new_txid, 32) != 0, "C is yet another chain[1]");
    TEST_ASSERT(c.child_rc == 0 && !c.got_pubnonce && !c.got_final,
                "other channel: refused before any nonce, nothing sent");

    TEST_ASSERT(rows_match(db, &a), "the records are A's, untouched, one per signed input");
    db_drop(db);
    return 1;
}

/* Crash between the record and FINAL_PSIGS, restart, the LSP retries the
   identical advance: it must succeed (or the sub is stuck), and the record
   still names that one transaction. */
static int test_ps_subfactory_refusal_identical_retry_after_crash_is_idempotent_body(void) {
    char db[256];
    DB_FRESH(db, "idem");
    sf_opts_t crash = OPTS(DELTA_A, 0);
    crash.crash_at = "ps_sub_record_post_save";
    sf_opts_t honest = OPTS(DELTA_A, 0);
    sf_result_t a, b;

    TEST_ASSERT(run_sf_ceremony(db, &crash, &a), "harness crash");
    TEST_ASSERT(a.child_rc == -1 && a.child_signal == SIGABRT,
                "client aborted at ps_sub_record_post_save");
    TEST_ASSERT(a.got_pubnonce && !a.got_final, "signed and recorded, FINAL_PSIGS never left");
    TEST_ASSERT(rows_match(db, &a), "both signed inputs recorded before the crash");

    TEST_ASSERT(run_sf_ceremony(db, &honest, &b), "harness retry");
    TEST_ASSERT(memcmp(b.new_txid, a.new_txid, 32) == 0, "the retry is the identical chain[1]");
    TEST_ASSERT(b.child_rc == 1 && b.got_final && b.final_valid,
                "identical retry succeeds (idempotent), and its signatures verify");
    TEST_ASSERT(rows_match(db, &a), "still exactly the first record");
    db_drop(db);
    return 1;
}

/* The pre-sign lookup fails: "unknown" means refuse -- no nonce, nothing sent. */
static int test_ps_subfactory_refusal_check_error_refuses_body(void) {
    char db[256];
    DB_FRESH(db, "chk");
    sf_opts_t o = OPTS(DELTA_A, 0);
    o.fail_point = PERSIST_TEST_PS_CHECK;
    sf_result_t r;
    TEST_ASSERT(run_sf_ceremony(db, &o, &r), "harness");
    TEST_ASSERT(!r.got_final, "no CLIENT_FINAL_PSIGS was sent");
    TEST_ASSERT(r.child_rc == 0 && !r.got_pubnonce, "refused before any nonce");
    TEST_ASSERT(db_rows(db) == 0, "nothing recorded");
    db_drop(db);

    /* The second input's lookup fails, the first passed: still refused. */
    DB_FRESH(db, "chk2");
    sf_opts_t o2 = o;
    o2.fail_nth = 2;
    TEST_ASSERT(run_sf_ceremony(db, &o2, &r), "harness (2nd input)");
    TEST_ASSERT(r.child_rc == 0 && !r.got_pubnonce && !r.got_final,
                "a lookup error on any input refuses before any nonce");
    TEST_ASSERT(db_rows(db) == 0, "nothing recorded");
    db_drop(db);
    return 1;
}

/* The first record insert fails.  The partial sigs exist in memory; they
   must not leave the process. */
static int test_ps_subfactory_refusal_save_error_aborts_before_final_body(void) {
    char db[256];
    DB_FRESH(db, "save");
    sf_opts_t o = OPTS(DELTA_A, 0);
    o.fail_point = PERSIST_TEST_PS_SAVE;
    sf_result_t r;
    TEST_ASSERT(run_sf_ceremony(db, &o, &r), "harness");
    TEST_ASSERT(!r.got_final, "no CLIENT_FINAL_PSIGS was sent");
    TEST_ASSERT(r.got_pubnonce && r.child_rc == 0,
                "got as far as the nonce exchange, then aborted");
    TEST_ASSERT(db_rows(db) == 0, "no record (the insert failed), and no signature out");
    db_drop(db);
    return 1;
}

/* The sighash a record is keyed on cannot be computed: nothing is signed. */
static int test_ps_subfactory_refusal_sighash_failure_refuses_body(void) {
    char db[256];
    DB_FRESH(db, "sigh");
    sf_opts_t o = OPTS(DELTA_A, 0);
    o.fail_point = PERSIST_TEST_PS_SIGHASH;
    o.fail_nth = 2;
    sf_result_t r;
    TEST_ASSERT(run_sf_ceremony(db, &o, &r), "harness");
    TEST_ASSERT(!r.got_final, "no CLIENT_FINAL_PSIGS was sent");
    TEST_ASSERT(r.child_rc == 0 && !r.got_pubnonce,
                "a sighash failure on any input refuses before any nonce");
    TEST_ASSERT(db_rows(db) == 0, "nothing recorded");
    db_drop(db);
    return 1;
}

/* Two ceremonies on the same chain[0] both pass the pre-sign checks; the
   other one records a different spend of input 0 first.  The PRIMARY KEY is
   the arbiter: ours loses at its first INSERT and releases nothing. */
static int test_ps_subfactory_refusal_record_race_one_signature_body(void) {
    char db[256];
    DB_FRESH(db, "race");
    sf_opts_t o = OPTS(DELTA_A, 0);
    o.race_sighash = CONFLICTING_SIGHASH;
    o.race_vout = 0;
    sf_result_t r;
    TEST_ASSERT(run_sf_ceremony(db, &o, &r), "harness");
    TEST_ASSERT(!r.got_final, "the ceremony that lost the record race releases nothing");
    TEST_ASSERT(r.got_pubnonce && r.child_rc == 0, "both passed the check; ours failed");
    unsigned char s[32];
    TEST_ASSERT(db_lookup(db, r.parent_txid, 0, s) == PS_SIGNED_INPUT_FOUND &&
                memcmp(s, CONFLICTING_SIGHASH, 32) == 0,
                "the first record won and was not overwritten");
    TEST_ASSERT(db_rows(db) == 1, "the loser recorded nothing (not even input 2)");
    db_drop(db);
    return 1;
}

/* Multi-input atomicity.  Input 0 records, input 2's INSERT fails: abort,
   nothing sent, input 0's row stays.  A different chain[1] is then refused
   (it spends input 0 too); the identical one goes through and completes the
   record. */
static int test_ps_subfactory_refusal_partial_record_blocks_conflict_body(void) {
    char db[256];
    DB_FRESH(db, "partial");
    sf_opts_t half = OPTS(DELTA_A, 0);
    half.fail_point = PERSIST_TEST_PS_SAVE;
    half.fail_nth = 2;
    sf_opts_t other_delta = OPTS(DELTA_B, 0);
    sf_opts_t honest = OPTS(DELTA_A, 0);
    sf_result_t a, b, c;
    unsigned char s[32];

    TEST_ASSERT(run_sf_ceremony(db, &half, &a), "harness half-recorded");
    TEST_ASSERT(!a.got_final, "second input's save failed: nothing sent");
    TEST_ASSERT(a.got_pubnonce && a.child_rc == 0, "aborted after signing");
    TEST_ASSERT(db_rows(db) == 1 &&
                db_lookup(db, a.parent_txid, 0, s) == PS_SIGNED_INPUT_FOUND &&
                memcmp(s, a.sighash[0], 32) == 0 &&
                db_lookup(db, a.parent_txid, 2, s) == PS_SIGNED_INPUT_NOT_FOUND,
                "input 0 recorded, input 2 not");

    TEST_ASSERT(run_sf_ceremony(db, &other_delta, &b), "harness conflicting");
    TEST_ASSERT(!b.got_final, "conflicting chain[1] after a partial record: nothing sent");
    TEST_ASSERT(b.child_rc == 0 && !b.got_pubnonce, "refused at input 0's check, before any nonce");
    TEST_ASSERT(db_rows(db) == 1, "the partial record is unchanged");

    TEST_ASSERT(run_sf_ceremony(db, &honest, &c), "harness identical");
    TEST_ASSERT(c.child_rc == 1 && c.got_final && c.final_valid,
                "the identical chain[1] goes through");
    TEST_ASSERT(rows_match(db, &a), "and the record is now complete");
    db_drop(db);
    return 1;
}

/* Crash drill around the record, with restart (same DB file, fresh factory
   from chain[0]). */
static int test_ps_subfactory_refusal_crash_drill_restart_semantics_body(void) {
    char db[256];
    sf_opts_t honest = OPTS(DELTA_A, 0);
    sf_opts_t other_delta = OPTS(DELTA_B, 0);
    sf_result_t r, x;

    /* A: crash BEFORE the record.  Nothing recorded, nothing sent: a restart
       may sign any spend -- here a different one. */
    DB_FRESH(db, "drillA");
    {
        sf_opts_t crash = OPTS(DELTA_A, 0);
        crash.crash_at = "ps_sub_record_pre_save";
        TEST_ASSERT(run_sf_ceremony(db, &crash, &r), "harness A/crash");
        TEST_ASSERT(r.child_rc == -1 && r.child_signal == SIGABRT,
                    "client aborted at ps_sub_record_pre_save");
        TEST_ASSERT(r.got_pubnonce && !r.got_final, "signed, but nothing left the process");
        TEST_ASSERT(db_rows(db) == 0, "no record before the crash");
        TEST_ASSERT(run_sf_ceremony(db, &other_delta, &x), "harness A/restart");
        TEST_ASSERT(x.child_rc == 1 && x.got_final && x.final_valid,
                    "restart signs normally (no record existed, no signature had left)");
        TEST_ASSERT(rows_match(db, &x), "restart recorded what it signed");
    }
    db_drop(db);

    /* B: crash BETWEEN the record and FINAL_PSIGS.  Identical retry succeeds;
       a different spend of the same chain[0] is refused. */
    DB_FRESH(db, "drillB");
    {
        sf_opts_t crash = OPTS(DELTA_A, 0);
        crash.crash_at = "ps_sub_record_post_save";
        TEST_ASSERT(run_sf_ceremony(db, &crash, &r), "harness B/crash");
        TEST_ASSERT(r.child_rc == -1 && r.child_signal == SIGABRT,
                    "client aborted at ps_sub_record_post_save");
        TEST_ASSERT(r.got_pubnonce && !r.got_final, "recorded, FINAL_PSIGS never left");
        TEST_ASSERT(rows_match(db, &r), "the record survived the crash");
        TEST_ASSERT(run_sf_ceremony(db, &honest, &x), "harness B/restart-identical");
        TEST_ASSERT(x.child_rc == 1 && x.got_final && x.final_valid,
                    "identical retry succeeds");
        TEST_ASSERT(run_sf_ceremony(db, &other_delta, &x), "harness B/restart-conflicting");
        TEST_ASSERT(x.child_rc == 0 && !x.got_pubnonce && !x.got_final,
                    "conflicting retry is refused before any nonce");
        TEST_ASSERT(rows_match(db, &r), "record unchanged");
    }
    db_drop(db);

    /* C: crash AFTER FINAL_PSIGS left.  The LSP holds our signatures. */
    DB_FRESH(db, "drillC");
    {
        sf_opts_t crash = OPTS(DELTA_A, 0);
        crash.crash_at = "ps_sub_record_post_final";
        TEST_ASSERT(run_sf_ceremony(db, &crash, &r), "harness C/crash");
        TEST_ASSERT(r.child_rc == -1 && r.child_signal == SIGABRT,
                    "client aborted at ps_sub_record_post_final");
        TEST_ASSERT(r.got_final && r.final_valid, "FINAL_PSIGS had left, and verifies");
        TEST_ASSERT(rows_match(db, &r), "the record matches what left");
        TEST_ASSERT(run_sf_ceremony(db, &other_delta, &x), "harness C/restart-conflicting");
        TEST_ASSERT(x.child_rc == 0 && !x.got_pubnonce && !x.got_final,
                    "conflicting retry is refused before any nonce");
        TEST_ASSERT(run_sf_ceremony(db, &honest, &x), "harness C/restart-identical");
        TEST_ASSERT(x.child_rc == 1 && x.got_final && x.final_valid,
                    "identical retry is idempotent");
        TEST_ASSERT(rows_match(db, &r), "record unchanged");
    }
    db_drop(db);
    return 1;
}

/* The declared input count must be the chain tx's.  After A signed chain[1],
   the LSP proposes a different chain[1] declaring one input (what used to
   select a single-input ceremony that signed the sub's node-level session and
   recorded nothing), then two of the three inputs.  Both refused before any
   nonce and before any local change. */
static int test_ps_subfactory_refusal_input_count_must_match_body(void) {
    char db[256];
    DB_FRESH(db, "count");
    sf_opts_t honest = OPTS(DELTA_A, 0);
    sf_opts_t single = OPTS(DELTA_B, 0);
    single.n_inputs = 1;
    sf_opts_t shortn = OPTS(DELTA_B, 0);
    shortn.n_inputs = 2;
    sf_result_t a, r;

    TEST_ASSERT(run_sf_ceremony(db, &honest, &a), "harness A");
    TEST_ASSERT(a.child_rc == 1 && a.got_final && a.final_valid, "A signs chain[1]");

    TEST_ASSERT(run_sf_ceremony(db, &single, &r), "harness single-input");
    TEST_ASSERT(!r.got_final,
                "single-input PROPOSE_INTENT for a 3-input chain tx: partial sig sent, unrecorded");
    TEST_ASSERT(r.child_rc == 0 && !r.got_pubnonce, "refused before any nonce");
    TEST_ASSERT(!r.changed, "refused before any local change");

    TEST_ASSERT(run_sf_ceremony(db, &shortn, &r), "harness short count");
    TEST_ASSERT(!r.got_final, "n_inputs=2 for a 3-input chain tx: partial sig sent");
    TEST_ASSERT(r.child_rc == 0 && !r.got_pubnonce, "refused before any nonce");
    TEST_ASSERT(!r.changed, "refused before any local change");

    TEST_ASSERT(rows_match(db, &a), "the record is still A's");
    db_drop(db);
    return 1;
}

/* subfactory_id must be the sub-factory (leaf_side, sub_idx) names: the
   local advance mutates the latter, the signing and the record use the
   former.  Either kind of mismatch is refused before any local change. */
static int test_ps_subfactory_refusal_sub_node_mismatch_refused_body(void) {
    char db[256];
    DB_FRESH(db, "mismatch");
    sf_result_t r;

    sf_opts_t id_other = OPTS(DELTA_A, 0);
    id_other.name_other_sub = 1;  /* subfactory_id = sub 1, (leaf 0, sub 0) */
    TEST_ASSERT(run_sf_ceremony(db, &id_other, &r), "harness id names sub 1");
    TEST_ASSERT(r.child_rc == 0 && !r.got_pubnonce && !r.got_final,
                "subfactory_id names another sub-factory: refused before any nonce");
    TEST_ASSERT(!r.changed, "subfactory_id mismatch: refused before any local change");

    sf_opts_t idx_other = OPTS(DELTA_A, 0);
    idx_other.name_other_sub = 2;  /* subfactory_id = sub 0, (leaf 0, sub 1) */
    TEST_ASSERT(run_sf_ceremony(db, &idx_other, &r), "harness sub_idx names sub 1");
    TEST_ASSERT(r.child_rc == 0 && !r.got_pubnonce && !r.got_final,
                "sub_idx names another sub-factory: refused before any nonce");
    TEST_ASSERT(!r.changed, "sub_idx mismatch: refused before any local change");

    TEST_ASSERT(db_rows(db) == 0, "nothing recorded");
    db_drop(db);
    return 1;
}

/* One advance further: chain[1] -> chain[2] spends all three outputs of
   chain[1].  The input-count rule and the per-input record hold there too:
   after a restart from chain[0] (the identical chain[1] is an idempotent
   retry), a short count and a different chain[2] are both refused, and the
   identical chain[2] is idempotent. */
static int test_ps_subfactory_refusal_second_advance_body(void) {
    char db[256];
    DB_FRESH(db, "second");
    sf_result_t a[2], r[2];
    unsigned char s[32];

    sf_opts_t seq[2] = { OPTS(DELTA_A, 0), OPTS(DELTA_C, 0) };
    TEST_ASSERT(run_sf_steps(db, 0, seq, 2, a), "harness chain[0]->[1]->[2]");
    TEST_ASSERT(a[0].child_rc == 1 && a[0].got_final && a[0].final_valid, "chain[1] signed");
    TEST_ASSERT(a[1].child_rc == 1 && a[1].got_final && a[1].final_valid &&
                a[1].chain_len_after == 2, "chain[2] signed, every input verifies");
    TEST_ASSERT(memcmp(a[1].parent_txid, a[0].new_txid, 32) == 0, "chain[2] spends chain[1]");
    TEST_ASSERT(db_rows(db) == 4 && rows_match_parent(db, &a[0]) &&
                rows_match_parent(db, &a[1]),
                "two rows per advance, keyed on chain[0] and on chain[1]");

    sf_opts_t shortn[2] = { OPTS(DELTA_A, 0), OPTS(DELTA_C, 0) };
    shortn[1].n_inputs = 2;
    TEST_ASSERT(run_sf_steps(db, 0, shortn, 2, r), "harness restart, short count");
    TEST_ASSERT(r[0].child_rc == 1 && r[0].got_final, "identical chain[1]: idempotent");
    TEST_ASSERT(!r[1].got_final, "n_inputs=2 for chain[1]'s 3 outputs: partial sig sent");
    TEST_ASSERT(r[1].child_rc == 0 && !r[1].got_pubnonce, "refused before any nonce");
    TEST_ASSERT(!r[1].changed, "refused before any local change");

    sf_opts_t conflict[2] = { OPTS(DELTA_A, 0), OPTS(DELTA_D, 0) };
    TEST_ASSERT(run_sf_steps(db, 0, conflict, 2, r), "harness restart, different chain[2]");
    TEST_ASSERT(r[0].child_rc == 1 && r[0].got_final, "identical chain[1]: idempotent");
    TEST_ASSERT(memcmp(r[1].parent_txid, a[1].parent_txid, 32) == 0 &&
                memcmp(r[1].new_txid, a[1].new_txid, 32) != 0,
                "a different chain[2] spending the same chain[1]");
    TEST_ASSERT(!r[1].got_final, "client co-signed a second, conflicting chain[2]");
    TEST_ASSERT(r[1].child_rc == 0 && !r[1].got_pubnonce, "refused before any nonce");

    TEST_ASSERT(run_sf_steps(db, 0, seq, 2, r), "harness restart, identical");
    TEST_ASSERT(r[1].child_rc == 1 && r[1].got_final && r[1].final_valid,
                "identical chain[2]: idempotent");
    TEST_ASSERT(db_rows(db) == 4 && db_lookup(db, a[1].parent_txid, 2, s) == 1 &&
                memcmp(s, a[1].sighash[2], 32) == 0, "records unchanged");
    db_drop(db);
    return 1;
}

/* Hashlock sub-factory, poison active, honest advance: the record must not
   get in the poison's way.  FINAL_PSIGS carries the poison partial sig, the
   aggregated poison verifies, the client verifies the LSP's aggregate from
   DONE and the revealed secret and persists the recourse, and the sub
   advances.
   Only the channel inputs' state signatures are asserted here: on a hashlock
   sub the sales-stock input (2) is signed under derive_input_keyagg's
   CSV-only L-stock merkle while chain[0]'s sales-stock output commits the
   2-leaf {poison, CSV} taptree, so its aggregate does not verify against
   the prevout key.  That is independent of the record (it is the same
   without it) and is not asserted either way. */
static int test_ps_subfactory_refusal_hashlock_honest_poison_verifies_body(void) {
    char db[256];
    DB_FRESH(db, "hl_ok");
    sf_opts_t honest = OPTS(DELTA_A, 0);
    sf_result_t r;
    TEST_ASSERT(run_sf_steps(db, 1, &honest, 1, &r), "harness (hashlock)");
    TEST_ASSERT(r.child_rc == 1, "hashlock advance succeeds on the client");
    TEST_ASSERT(r.got_final, "hashlock advance sends CLIENT_FINAL_PSIGS");
    TEST_ASSERT(r.input_valid[0] && r.input_valid[1],
                "both channel inputs of the hashlock chain[1] verify");
    TEST_ASSERT(r.got_poison_psig && r.poison_valid,
                "FINAL_PSIGS carries the poison partial sig and the aggregate verifies");
    TEST_ASSERT(r.changed && r.chain_len_after == 1, "the client's sub advanced to chain[1]");
    TEST_ASSERT(db_poison_secrets(db) == 1,
                "the client verified and persisted the poison recourse with its secret");
    TEST_ASSERT(rows_match(db, &r), "state inputs recorded; the poison is not");
    db_drop(db);
    return 1;
}

/* Hashlock sub-factory, the first record insert fails: the poison partial
   sig exists (it is made before the record), but nothing at all may leave --
   no FINAL_PSIGS, so no poison partial sig either -- and no recourse
   template is persisted for an advance that did not happen. */
static int test_ps_subfactory_refusal_hashlock_save_error_sends_no_poison_body(void) {
    char db[256];
    DB_FRESH(db, "hl_save");
    sf_opts_t o = OPTS(DELTA_A, 0);
    o.fail_point = PERSIST_TEST_PS_SAVE;
    sf_result_t r;
    TEST_ASSERT(run_sf_steps(db, 1, &o, 1, &r), "harness (hashlock)");
    TEST_ASSERT(!r.got_final && !r.got_poison_psig,
                "no CLIENT_FINAL_PSIGS, so no poison partial sig, left the process");
    TEST_ASSERT(!r.got_after_resp, "nothing at all was sent after LSP_RESPONSE");
    TEST_ASSERT(r.got_pubnonce && r.child_rc == 0, "aborted after signing");
    TEST_ASSERT(db_rows(db) == 0 && db_poison_rows(db) == 0,
                "no record and no poison recourse persisted");
    db_drop(db);
    return 1;
}

/* Public entry points (registered in tests/test_main.c).  Each body runs
   under with_db_cleanup so its temp DBs are removed even when it fails. */
int test_ps_subfactory_refusal_conflicting_reproposal_refused(void) { return with_db_cleanup(test_ps_subfactory_refusal_conflicting_reproposal_refused_body); }
int test_ps_subfactory_refusal_identical_retry_after_crash_is_idempotent(void) { return with_db_cleanup(test_ps_subfactory_refusal_identical_retry_after_crash_is_idempotent_body); }
int test_ps_subfactory_refusal_check_error_refuses(void) { return with_db_cleanup(test_ps_subfactory_refusal_check_error_refuses_body); }
int test_ps_subfactory_refusal_save_error_aborts_before_final(void) { return with_db_cleanup(test_ps_subfactory_refusal_save_error_aborts_before_final_body); }
int test_ps_subfactory_refusal_sighash_failure_refuses(void) { return with_db_cleanup(test_ps_subfactory_refusal_sighash_failure_refuses_body); }
int test_ps_subfactory_refusal_record_race_one_signature(void) { return with_db_cleanup(test_ps_subfactory_refusal_record_race_one_signature_body); }
int test_ps_subfactory_refusal_partial_record_blocks_conflict(void) { return with_db_cleanup(test_ps_subfactory_refusal_partial_record_blocks_conflict_body); }
int test_ps_subfactory_refusal_crash_drill_restart_semantics(void) { return with_db_cleanup(test_ps_subfactory_refusal_crash_drill_restart_semantics_body); }
int test_ps_subfactory_refusal_input_count_must_match(void) { return with_db_cleanup(test_ps_subfactory_refusal_input_count_must_match_body); }
int test_ps_subfactory_refusal_sub_node_mismatch_refused(void) { return with_db_cleanup(test_ps_subfactory_refusal_sub_node_mismatch_refused_body); }
int test_ps_subfactory_refusal_second_advance(void) { return with_db_cleanup(test_ps_subfactory_refusal_second_advance_body); }
int test_ps_subfactory_refusal_hashlock_honest_poison_verifies(void) { return with_db_cleanup(test_ps_subfactory_refusal_hashlock_honest_poison_verifies_body); }
int test_ps_subfactory_refusal_hashlock_save_error_sends_no_poison(void) { return with_db_cleanup(test_ps_subfactory_refusal_hashlock_save_error_sends_no_poison_body); }
