/* LSP restart and reconnect persistence: what an LSP restarted from its
   DB loads back, what it keeps writing to it, and what it refuses to load. */
#include "superscalar/persist.h"
#include "superscalar/factory.h"
#include "superscalar/channel.h"
#include "superscalar/lsp.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/dw_state.h"
#include "superscalar/musig.h"
#include "superscalar/wire.h"
#include "superscalar/tx_builder.h"
#include "superscalar/sha256.h"
#include "superscalar/client.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

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

static const unsigned char rs_seckeys[5][32] = {
    { [0 ... 31] = 0x10 },
    { [0 ... 31] = 0x21 },
    { [0 ... 31] = 0x32 },
    { [0 ... 31] = 0x43 },
    { [0 ... 31] = 0x54 },
};

/* An LSP + 4-client factory with channels set up the normal way
   (lsp_channels_init with the DB attached) and persisted: factory,
   channels, basepoints and balances.  Channel 0 is at commitment 5. */
typedef struct {
    persist_t db;
    secp256k1_context *ctx;
    secp256k1_pubkey pks[5];
    factory_t *f;
    lsp_channel_mgr_t mgr;
} rs_fixture_t;

#define RS_CH0_LOCAL  30000
#define RS_CH0_REMOTE 50000
#define RS_CH0_CN     5

static int rs_build_factory(secp256k1_context *ctx, const secp256k1_pubkey *pks,
                            factory_arity_t arity, factory_t **out) {
    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;
    factory_init_from_pubkeys(f, ctx, pks, 5, 10, 4);  /* allocates the arrays */
    if (arity != FACTORY_ARITY_2) factory_set_arity(f, arity);
    f->cltv_timeout = 200;
    f->fee_per_tx = 500;

    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks, 5)) return 0;
    unsigned char internal_ser[32], twk[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    sha256_tagged("TapTweak", internal_ser, 32, twk);
    musig_keyagg_t kac = ka;
    secp256k1_pubkey tpk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tpk, &kac.cache, twk)) return 0;
    secp256k1_xonly_pubkey txo;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &txo, NULL, &tpk)) return 0;
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &txo);

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAB, 32);
    factory_set_funding(f, fake_txid, 0, 200000, fund_spk, 34);
    if (!factory_build_tree(f)) return 0;
    *out = f;
    return 1;
}

/* n_basepoints: how many channels get their basepoints saved (4 = all). */
static int rs_setup(rs_fixture_t *fx, size_t n_basepoints) {
    memset(fx, 0, sizeof(*fx));
    if (!persist_open(&fx->db, NULL)) return 0;
    fx->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                       SECP256K1_CONTEXT_VERIFY);
    for (int i = 0; i < 5; i++)
        if (!secp256k1_ec_pubkey_create(fx->ctx, &fx->pks[i], rs_seckeys[i]))
            return 0;
    if (!rs_build_factory(fx->ctx, fx->pks, FACTORY_ARITY_2, &fx->f)) return 0;

    fx->mgr.persist = &fx->db;
    if (!lsp_channels_init(&fx->mgr, fx->ctx, fx->f, rs_seckeys[0], 4)) return 0;

    for (size_t c = 0; c < 4; c++) {
        channel_t *ch = &fx->mgr.entries[c].channel;
        secp256k1_pubkey rpay, rdelay, rrevoc, rhtlc;
        unsigned char rs[32];
        memset(rs, 0x60 + (unsigned char)c, 32);
        if (!secp256k1_ec_pubkey_create(fx->ctx, &rpay, rs)) return 0;
        rs[0]++;
        if (!secp256k1_ec_pubkey_create(fx->ctx, &rdelay, rs)) return 0;
        rs[0]++;
        if (!secp256k1_ec_pubkey_create(fx->ctx, &rrevoc, rs)) return 0;
        rs[0]++;
        if (!secp256k1_ec_pubkey_create(fx->ctx, &rhtlc, rs)) return 0;
        channel_set_remote_basepoints(ch, &rpay, &rdelay, &rrevoc);
        channel_set_remote_htlc_basepoint(ch, &rhtlc);
    }
    fx->mgr.entries[0].channel.local_amount = RS_CH0_LOCAL;
    fx->mgr.entries[0].channel.remote_amount = RS_CH0_REMOTE;
    fx->mgr.entries[0].channel.commitment_number = RS_CH0_CN;

    if (!persist_begin(&fx->db)) return 0;
    if (!persist_save_factory(&fx->db, fx->f, fx->ctx, 0)) return 0;
    for (size_t c = 0; c < 4; c++) {
        const channel_t *ch = &fx->mgr.entries[c].channel;
        if (!persist_save_channel(&fx->db, ch, 0, (uint32_t)c)) return 0;
        if (c < n_basepoints &&
            !persist_save_basepoints(&fx->db, (uint32_t)c, ch)) return 0;
        if (!persist_update_channel_balance(&fx->db, (uint32_t)c,
                ch->local_amount, ch->remote_amount, ch->commitment_number))
            return 0;
    }
    return persist_commit(&fx->db);
}

static void rs_teardown(rs_fixture_t *fx) {
    lsp_channels_cleanup(&fx->mgr);
    if (fx->f) { factory_free(fx->f); free(fx->f); }
    persist_close(&fx->db);
    if (fx->ctx) secp256k1_context_destroy(fx->ctx);
}

static int rs_load_factory(rs_fixture_t *fx, factory_t **out) {
    factory_t *rec_f = calloc(1, sizeof(factory_t));  /* load allocates the arrays */
    if (!rec_f) return 0;
    if (!persist_load_factory(&fx->db, 0, rec_f, fx->ctx)) return 0;
    *out = rec_f;
    return 1;
}

/* ---- Restored channels keep writing to the DB ---- */

/* The LSP restart path calloc()s the manager and used to set mgr->persist
   only after lsp_channels_init_from_db, so every restored channel had no
   DB.  Restore the way the daemon does and check that a revocation and a
   remote per-commitment point received afterwards reach the DB. */
int test_restart_lsp_revocation_persisted_after_restore(void) {
    rs_fixture_t fx;
    TEST_ASSERT(rs_setup(&fx, 4), "fixture");

    factory_t *rec_f = NULL;
    TEST_ASSERT(rs_load_factory(&fx, &rec_f), "load factory");
    lsp_channel_mgr_t *rec_mgr = calloc(1, sizeof(*rec_mgr));
    TEST_ASSERT(rec_mgr, "alloc");
    TEST_ASSERT(lsp_channels_init_from_db(rec_mgr, fx.ctx, rec_f,
                                          rs_seckeys[0], 4, &fx.db),
                "init from db");

    channel_t *ch = &rec_mgr->entries[0].channel;
    TEST_ASSERT_EQ(ch->commitment_number, RS_CH0_CN, "restored commitment number");

    /* The client revokes commitment 4: its PCP, then the matching secret. */
    const uint64_t cn = RS_CH0_CN - 1;
    unsigned char secret[32];
    memset(secret, 0x77, 32);
    secp256k1_pubkey pcp;
    TEST_ASSERT(secp256k1_ec_pubkey_create(fx.ctx, &pcp, secret), "pcp");
    channel_set_remote_pcp(ch, cn, &pcp);
    TEST_ASSERT(channel_receive_revocation_flat(ch, cn, secret), "revocation accepted");

    unsigned char secrets[16][32];
    uint8_t valid[16];
    size_t n_rev = 0;
    TEST_ASSERT(persist_load_revocations_flat(&fx.db, 0, secrets, valid, 16, &n_rev),
                "load revocations");
    TEST_ASSERT(valid[cn], "revocation secret persisted after restore");
    TEST_ASSERT(memcmp(secrets[cn], secret, 32) == 0, "persisted secret matches");

    unsigned char pcp_ser[33], want_ser[33];
    size_t len = 33;
    TEST_ASSERT(secp256k1_ec_pubkey_serialize(fx.ctx, want_ser, &len, &pcp,
                                              SECP256K1_EC_COMPRESSED), "ser");
    TEST_ASSERT(persist_load_remote_pcp(&fx.db, 0, cn, pcp_ser),
                "remote PCP persisted after restore");
    TEST_ASSERT(memcmp(pcp_ser, want_ser, 33) == 0, "persisted PCP matches");

    TEST_ASSERT(rec_mgr->persist == &fx.db, "mgr->persist attached");
    for (size_t c = 0; c < 4; c++)
        TEST_ASSERT(rec_mgr->entries[c].channel.persist_db == &fx.db,
                    "every channel attached to the DB");

    lsp_channels_cleanup(rec_mgr);
    free(rec_mgr);
    factory_free(rec_f);
    free(rec_f);
    rs_teardown(&fx);
    return 1;
}

/* Restoring from one DB while mgr->persist names another would split the
   channel's writes from its source; refuse it. */
int test_restart_init_from_db_refuses_other_db(void) {
    rs_fixture_t fx;
    TEST_ASSERT(rs_setup(&fx, 4), "fixture");
    persist_t other;
    TEST_ASSERT(persist_open(&other, NULL), "open other db");

    factory_t *rec_f = NULL;
    TEST_ASSERT(rs_load_factory(&fx, &rec_f), "load factory");
    lsp_channel_mgr_t *rec_mgr = calloc(1, sizeof(*rec_mgr));
    TEST_ASSERT(rec_mgr, "alloc");
    rec_mgr->persist = &other;
    TEST_ASSERT(!lsp_channels_init_from_db(rec_mgr, fx.ctx, rec_f,
                                           rs_seckeys[0], 4, &fx.db),
                "restore refused when mgr->persist is a different DB");
    TEST_ASSERT(rec_mgr->entries == NULL, "nothing allocated");

    lsp_channels_cleanup(rec_mgr);
    free(rec_mgr);
    factory_free(rec_f);
    free(rec_f);
    persist_close(&other);
    rs_teardown(&fx);
    return 1;
}

/* ---- A failed restore frees what it allocated ---- */

/* channel_init freed its arrays on an allocation failure without clearing
   the pointers, so a caller that then ran channel_cleanup (a failed
   restore does, through lsp_channels_cleanup) freed them twice; its later
   failures returned with the arrays still allocated.  Every failure now
   leaves the channel owning nothing.  An all-zero funding secret fails the
   keypair step, after the arrays are allocated. */
int test_restart_channel_init_failure_owns_nothing(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    TEST_ASSERT(ctx, "ctx");
    secp256k1_pubkey a, b;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &a, rs_seckeys[0]), "pubkey a");
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &b, rs_seckeys[1]), "pubkey b");
    const unsigned char zero_secret[32] = {0};
    unsigned char txid[32], spk[34];
    memset(txid, 0x11, sizeof(txid));
    memset(spk, 0x22, sizeof(spk));

    channel_t ch;
    TEST_ASSERT(!channel_init(&ch, ctx, zero_secret, &a, &b, txid, 0, 100000,
                              spk, sizeof(spk), 50000, 50000,
                              CHANNEL_DEFAULT_CSV_DELAY),
                "channel_init fails on an invalid funding secret");
    TEST_ASSERT(ch.htlcs == NULL && ch.htlcs_cap == 0, "HTLC array released");
    TEST_ASSERT(ch.local_pcs == NULL, "local PCS array released");
    TEST_ASSERT(ch.received_revocations == NULL &&
                ch.received_revocation_valid == NULL, "revocation arrays released");
    channel_cleanup(&ch);  /* a caller's cleanup is a no-op */

    secp256k1_context_destroy(ctx);
    return 1;
}

/* A restore that fails part-way (channel 3 has no basepoints) frees the
   channels it had already set up instead of leaking them. */
int test_restart_restore_failure_frees_mgr(void) {
    rs_fixture_t fx;
    TEST_ASSERT(rs_setup(&fx, 3), "fixture without channel 3 basepoints");

    factory_t *rec_f = NULL;
    TEST_ASSERT(rs_load_factory(&fx, &rec_f), "load factory");
    lsp_channel_mgr_t *rec_mgr = calloc(1, sizeof(*rec_mgr));
    TEST_ASSERT(rec_mgr, "alloc");
    TEST_ASSERT(!lsp_channels_init_from_db(rec_mgr, fx.ctx, rec_f,
                                           rs_seckeys[0], 4, &fx.db),
                "restore fails");
    TEST_ASSERT(rec_mgr->entries == NULL, "entries freed");
    TEST_ASSERT(rec_mgr->invoices == NULL, "invoices freed");
    TEST_ASSERT(rec_mgr->htlc_origins == NULL, "htlc origins freed");
    TEST_ASSERT_EQ(rec_mgr->n_channels, 0, "no channels left");

    free(rec_mgr);
    factory_free(rec_f);
    free(rec_f);
    rs_teardown(&fx);
    return 1;
}

/* ---- HTLCs restored on restart ---- */

static void rs_make_htlc(htlc_t *h, uint64_t id, htlc_state_t state) {
    memset(h, 0, sizeof(*h));
    h->id = id;
    h->direction = (id & 1) ? HTLC_RECEIVED : HTLC_OFFERED;
    h->state = state;
    h->amount_sats = 1000 + id;
    memset(h->payment_hash, (unsigned char)(id & 0xff), 32);
    h->payment_hash[0] = (unsigned char)(id >> 8);
    h->cltv_expiry = 500 + (uint32_t)id;
}

/* Store HTLC rows with ids [first, first + n). */
static int rs_save_htlcs(persist_t *db, uint32_t ch, uint64_t first, size_t n,
                         htlc_state_t state) {
    if (!persist_begin(db)) return 0;
    for (size_t i = 0; i < n; i++) {
        htlc_t h;
        rs_make_htlc(&h, first + i, state);
        if (!persist_save_htlc(db, ch, &h)) { persist_rollback(db); return 0; }
    }
    return persist_commit(db);
}

/* ch holds exactly the active HTLCs with ids [first, first + n), in order. */
static int rs_check_htlcs(const channel_t *ch, uint64_t first, size_t n) {
    if (ch->n_htlcs != n || ch->htlcs_cap < ch->n_htlcs) return 0;
    for (size_t i = 0; i < n; i++) {
        htlc_t want;
        rs_make_htlc(&want, first + i, HTLC_STATE_ACTIVE);
        const htlc_t *got = &ch->htlcs[i];
        if (got->id != want.id || got->amount_sats != want.amount_sats ||
            got->direction != want.direction || got->state != HTLC_STATE_ACTIVE ||
            got->cltv_expiry != want.cltv_expiry ||
            memcmp(got->payment_hash, want.payment_hash, 32) != 0)
            return 0;
    }
    return 1;
}

/* channel_init allocates DEFAULT_HTLCS_CAP (64) HTLC slots and the restore
   copied every stored HTLC into them.  100 active HTLCs (a channel can hold
   up to MAX_HTLCS) must all come back, in a large enough array. */
int test_restart_restore_more_than_64_htlcs(void) {
    rs_fixture_t fx;
    TEST_ASSERT(rs_setup(&fx, 4), "fixture");
    TEST_ASSERT(rs_save_htlcs(&fx.db, 0, 0, 100, HTLC_STATE_ACTIVE), "save active");
    TEST_ASSERT(rs_save_htlcs(&fx.db, 0, 1000, 3, HTLC_STATE_FULFILLED), "save settled");

    factory_t *rec_f = NULL;
    TEST_ASSERT(rs_load_factory(&fx, &rec_f), "load factory");
    lsp_channel_mgr_t *rec_mgr = calloc(1, sizeof(*rec_mgr));
    TEST_ASSERT(rec_mgr, "alloc");
    TEST_ASSERT(lsp_channels_init_from_db(rec_mgr, fx.ctx, rec_f,
                                          rs_seckeys[0], 4, &fx.db),
                "init from db");
    TEST_ASSERT(rs_check_htlcs(&rec_mgr->entries[0].channel, 0, 100),
                "all 100 active HTLCs restored (settled ones skipped)");
    TEST_ASSERT_EQ(rec_mgr->entries[1].channel.n_htlcs, 0, "other channels empty");

    lsp_channels_cleanup(rec_mgr);
    free(rec_mgr);
    factory_free(rec_f);
    free(rec_f);
    rs_teardown(&fx);
    return 1;
}

/* More active HTLCs than a channel can hold: refuse the restore (it used
   to keep the first MAX_HTLCS, after overflowing the array) and free
   everything. */
int test_restart_restore_too_many_htlcs_fails_closed(void) {
    rs_fixture_t fx;
    TEST_ASSERT(rs_setup(&fx, 4), "fixture");
    TEST_ASSERT(rs_save_htlcs(&fx.db, 1, 0, MAX_HTLCS + 1, HTLC_STATE_ACTIVE),
                "save MAX_HTLCS + 1 active");

    factory_t *rec_f = NULL;
    TEST_ASSERT(rs_load_factory(&fx, &rec_f), "load factory");
    lsp_channel_mgr_t *rec_mgr = calloc(1, sizeof(*rec_mgr));
    TEST_ASSERT(rec_mgr, "alloc");
    TEST_ASSERT(!lsp_channels_init_from_db(rec_mgr, fx.ctx, rec_f,
                                           rs_seckeys[0], 4, &fx.db),
                "restore refused");
    TEST_ASSERT(rec_mgr->entries == NULL, "entries freed");
    TEST_ASSERT_EQ(rec_mgr->n_channels, 0, "no channels left");

    lsp_channels_cleanup(rec_mgr);
    free(rec_mgr);
    factory_free(rec_f);
    free(rec_f);
    rs_teardown(&fx);
    return 1;
}

/* ---- HTLCs restored on a reconnect with a commitment-number gap ---- */

static lsp_t *rs_make_lsp(rs_fixture_t *fx) {
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    if (!lsp) return NULL;
    lsp->client_fds = calloc(LSP_MAX_CLIENTS, sizeof(int));
    lsp->client_pubkeys = calloc(LSP_MAX_CLIENTS, sizeof(secp256k1_pubkey));
    if (!lsp->client_fds || !lsp->client_pubkeys) {
        free(lsp->client_fds);
        free(lsp->client_pubkeys);
        free(lsp);
        return NULL;
    }
    lsp->clients_cap = LSP_MAX_CLIENTS;
    lsp->ctx = fx->ctx;
    lsp->lsp_pubkey = fx->pks[0];
    lsp->n_clients = 4;
    lsp->listen_fd = -1;
    lsp->bridge_fd = -1;
    for (int i = 0; i < 4; i++) {
        lsp->client_pubkeys[i] = fx->pks[i + 1];
        lsp->client_fds[i] = -1;
    }
    return lsp;
}

static void rs_free_lsp(lsp_t *lsp) {
    if (!lsp) return;
    free(lsp->client_fds);
    free(lsp->client_pubkeys);
    free(lsp);
}

/* Client 0 reconnects claiming claimed_cn.  The peer sends MSG_RECONNECT
   and stops writing, so the handler runs the commitment-number
   reconciliation under test and then fails at the nonce exchange (EOF);
   its return value is not what these tests check.  Returns 1 if the
   handler got past the reconciliation and took the connection, 0 if it
   refused it, -1 if the test could not send. */
static int rs_reconnect(rs_fixture_t *fx, lsp_t *lsp, uint64_t claimed_cn) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;
    cJSON *m = wire_build_reconnect(fx->ctx, &fx->pks[1], claimed_cn);
    int sent = m && wire_send(sv[1], MSG_RECONNECT, m);
    cJSON_Delete(m);
    if (!sent) {
        close(sv[0]);
        close(sv[1]);
        return -1;
    }
    shutdown(sv[1], SHUT_WR);
    (void)lsp_channels_handle_reconnect(&fx->mgr, lsp, sv[0]);
    int kept = (lsp->client_fds[0] == sv[0]);
    if (kept) {
        wire_close(sv[0]);       /* the refused path closed it itself */
        lsp->client_fds[0] = -1;
    }
    close(sv[1]);
    return kept;
}

/* The reconnect branches loaded every stored row, so fulfilled and failed
   rows counted towards MAX_HTLCS: MAX_HTLCS active HTLCs plus three settled
   rows were refused as too many.  Like the restart, they now load only the
   active rows.  (Today every settle and fail deletes its row, so such rows
   should not exist, but nothing enforces that.) */
int test_restart_reconnect_skips_settled_htlcs(void) {
    rs_fixture_t fx;
    TEST_ASSERT(rs_setup(&fx, 4), "fixture");
    TEST_ASSERT(rs_save_htlcs(&fx.db, 0, 0, MAX_HTLCS, HTLC_STATE_ACTIVE),
                "save MAX_HTLCS active");
    TEST_ASSERT(rs_save_htlcs(&fx.db, 0, 1000, 2, HTLC_STATE_FULFILLED),
                "save fulfilled");
    TEST_ASSERT(rs_save_htlcs(&fx.db, 0, 2000, 1, HTLC_STATE_FAILED), "save failed");
    lsp_t *lsp = rs_make_lsp(&fx);
    TEST_ASSERT(lsp, "lsp");
    channel_t *ch = &fx.mgr.entries[0].channel;

    ch->commitment_number = RS_CH0_CN + 1;
    ch->n_htlcs = 0;
    TEST_ASSERT_EQ(rs_reconnect(&fx, lsp, RS_CH0_CN), 1, "rollback taken");
    TEST_ASSERT(rs_check_htlcs(ch, 0, MAX_HTLCS),
                "rollback loaded the active HTLCs only");

    ch->n_htlcs = 0;
    TEST_ASSERT_EQ(rs_reconnect(&fx, lsp, RS_CH0_CN + 1), 1, "reload taken");
    TEST_ASSERT(rs_check_htlcs(ch, 0, MAX_HTLCS),
                "reload loaded the active HTLCs only");

    rs_free_lsp(lsp);
    rs_teardown(&fx);
    return 1;
}

/* The LSP is one commitment ahead (rolls back to the DB) and then one
   behind (accepts the client's number, reloads from the DB).  Both reload
   the HTLCs into the channel; with 100 stored they no longer fit in the
   64 slots channel_init allocated. */
int test_restart_reconnect_rollback_more_than_64_htlcs(void) {
    rs_fixture_t fx;
    TEST_ASSERT(rs_setup(&fx, 4), "fixture");
    TEST_ASSERT(rs_save_htlcs(&fx.db, 0, 0, 100, HTLC_STATE_ACTIVE), "save htlcs");
    lsp_t *lsp = rs_make_lsp(&fx);
    TEST_ASSERT(lsp, "lsp");
    channel_t *ch = &fx.mgr.entries[0].channel;

    /* LSP one ahead of the client and of the DB: roll back. */
    ch->commitment_number = RS_CH0_CN + 1;
    ch->local_amount = 1;
    ch->remote_amount = 2;
    ch->n_htlcs = 0;
    TEST_ASSERT_EQ(rs_reconnect(&fx, lsp, RS_CH0_CN), 1, "reconnect taken");
    TEST_ASSERT_EQ(ch->commitment_number, RS_CH0_CN, "rolled back to DB commitment");
    TEST_ASSERT_EQ(ch->local_amount, RS_CH0_LOCAL, "DB local balance");
    TEST_ASSERT_EQ(ch->remote_amount, RS_CH0_REMOTE, "DB remote balance");
    TEST_ASSERT(rs_check_htlcs(ch, 0, 100), "rollback restored all 100 HTLCs");

    /* Client one ahead: take its number, reload the rest from the DB. */
    ch->n_htlcs = 0;
    TEST_ASSERT_EQ(rs_reconnect(&fx, lsp, RS_CH0_CN + 1), 1, "reconnect taken");
    TEST_ASSERT_EQ(ch->commitment_number, RS_CH0_CN + 1, "accepted client commitment");
    TEST_ASSERT(rs_check_htlcs(ch, 0, 100), "reload restored all 100 HTLCs");

    rs_free_lsp(lsp);
    rs_teardown(&fx);
    return 1;
}

/* More stored HTLCs than a channel can hold: both reconnect branches
   refuse and leave the channel as it was. */
int test_restart_reconnect_too_many_htlcs_fails_closed(void) {
    rs_fixture_t fx;
    TEST_ASSERT(rs_setup(&fx, 4), "fixture");
    TEST_ASSERT(rs_save_htlcs(&fx.db, 0, 0, MAX_HTLCS + 1, HTLC_STATE_ACTIVE),
                "save MAX_HTLCS + 1 htlcs");
    lsp_t *lsp = rs_make_lsp(&fx);
    TEST_ASSERT(lsp, "lsp");
    channel_t *ch = &fx.mgr.entries[0].channel;

    ch->commitment_number = RS_CH0_CN + 1;
    ch->local_amount = 1;
    ch->remote_amount = 2;
    ch->n_htlcs = 0;
    TEST_ASSERT_EQ(rs_reconnect(&fx, lsp, RS_CH0_CN), 0, "rollback refused");
    TEST_ASSERT_EQ(ch->commitment_number, RS_CH0_CN + 1, "rollback refused: cn kept");
    TEST_ASSERT_EQ(ch->local_amount, 1, "rollback refused: balance kept");
    TEST_ASSERT_EQ(ch->n_htlcs, 0, "rollback refused: HTLCs kept");

    ch->commitment_number = RS_CH0_CN - 1;
    TEST_ASSERT_EQ(rs_reconnect(&fx, lsp, RS_CH0_CN), 0, "reload refused");
    TEST_ASSERT_EQ(ch->commitment_number, RS_CH0_CN - 1, "reload refused: cn kept");
    TEST_ASSERT_EQ(ch->local_amount, 1, "reload refused: balance kept");
    TEST_ASSERT_EQ(ch->n_htlcs, 0, "reload refused: HTLCs kept");

    rs_free_lsp(lsp);
    rs_teardown(&fx);
    return 1;
}

/* ---- DW counter ---- */

static int rs_dw_factory(rs_fixture_t *fx) {
    memset(fx, 0, sizeof(*fx));
    if (!persist_open(&fx->db, NULL)) return 0;
    fx->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                       SECP256K1_CONTEXT_VERIFY);
    for (int i = 0; i < 5; i++)
        if (!secp256k1_ec_pubkey_create(fx->ctx, &fx->pks[i], rs_seckeys[i]))
            return 0;
    if (!rs_build_factory(fx->ctx, fx->pks, FACTORY_ARITY_1, &fx->f)) return 0;
    return persist_save_factory(&fx->db, fx->f, fx->ctx, 0);
}

/* A DW row that cannot be read fails the load.  persist_load_factory
   ignored the error and kept the counter at the initial state, behind
   states already signed; an allocation failure took the same path.  Two
   read errors: a row that fails while being stepped, and no table (the
   prepare fails).  No row at all is a fresh factory and loads. */
int test_restart_dw_state_read_error_fails_load(void) {
    rs_fixture_t fx;
    TEST_ASSERT(rs_dw_factory(&fx), "fixture");

    factory_t *rec_f = NULL;
    TEST_ASSERT(rs_load_factory(&fx, &rec_f), "no row: loads");
    TEST_ASSERT_EQ(rec_f->counter.current_epoch, 0, "no row: initial state");
    factory_free(rec_f);
    free(rec_f);

    factory_t *g = calloc(1, sizeof(factory_t));
    TEST_ASSERT(g, "alloc");
    TEST_ASSERT(sqlite3_exec(fx.db.db,
        "DROP TABLE dw_counter_state;"
        "CREATE VIEW dw_counter_state AS SELECT 0 AS factory_id, "
        "  abs(-9223372036854775807 - 1) AS current_epoch, 2 AS n_layers, "
        "  '0,0' AS layer_states, 0 AS per_leaf_enabled, 2 AS n_leaf_nodes, "
        "  '0,0' AS leaf_states;",
        NULL, NULL, NULL) == SQLITE_OK, "a row that fails when stepped");
    TEST_ASSERT(!persist_load_factory(&fx.db, 0, g, fx.ctx),
                "step error fails the load");
    TEST_ASSERT(g->nodes == NULL && g->leaf_layers == NULL,
                "the failed load freed the factory");

    TEST_ASSERT(sqlite3_exec(fx.db.db, "DROP VIEW dw_counter_state;",
                             NULL, NULL, NULL) == SQLITE_OK, "no table");
    TEST_ASSERT(!persist_load_factory(&fx.db, 0, g, fx.ctx),
                "prepare error fails the load");

    free(g);
    rs_teardown(&fx);
    return 1;
}

/* Older builds cut the leaf-state string at 255 characters, possibly in
   the middle of a number: "...,12" stored as "...,1", which would move
   that leaf back from state 12 to state 1.  The last value of a
   255-character string is treated as unknown (the leaf loads as
   exhausted), as are the leaves the string no longer holds. */
int test_restart_dw_counter_cut_leaf_string(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f, "alloc");
    factory_alloc_default_arrays(f);
    enum { N = 100, MAX = 100 };
    TEST_ASSERT(f->config.max_leaves >= N, "leaf capacity");
    dw_counter_init(&f->counter, 2, 10, 4);
    f->per_leaf_enabled = 1;
    f->n_leaf_nodes = N;
    for (int i = 0; i < N; i++) {
        dw_layer_init(&f->leaf_layers[i], 10, MAX);
        f->leaf_layers[i].current_state = (i == 0) ? 1 : 12;
    }
    /* "1,12,12,...": leaf 85's "12" is characters 254 and 255 (from 0). */
    TEST_ASSERT(persist_save_factory_dw_state(&db, 0, f), "save");
    TEST_ASSERT(sqlite3_exec(db.db, "UPDATE dw_counter_state SET leaf_states = "
                "substr(leaf_states, 1, 255);", NULL, NULL, NULL) == SQLITE_OK,
                "cut the string as older builds did");

    for (int i = 0; i < N; i++) f->leaf_layers[i].current_state = 0;
    TEST_ASSERT_EQ(persist_load_factory_dw_state(&db, 0, f), 1, "row applied");
    TEST_ASSERT_EQ(f->leaf_layers[0].current_state, 1, "leaf 0 as stored");
    for (int i = 1; i < 85; i++)
        TEST_ASSERT_EQ(f->leaf_layers[i].current_state, 12,
                       "complete values as stored");
    for (int i = 85; i < N; i++)
        TEST_ASSERT_EQ(f->leaf_layers[i].current_state, MAX - 1,
                       "the cut value and the missing ones load as exhausted");

    factory_free(f);
    free(f);
    persist_close(&db);
    return 1;
}

/* Rows with per-leaf mode off.  This build writes per_leaf=0 only while no
   leaf has moved since the leaves were last reset (a leaf advance turns
   the mode on first and nothing turns it off without resetting every
   leaf), and records every leaf, so the leaf states load as stored.
   Older builds stored "0,0" with per-leaf mode off; past epoch 0 their
   only such writer was the demo-mode epoch advance, run after the demo
   payments had advanced leaves, so those leaves load as exhausted.  At
   epoch 0 such a row is the creation one, and the leaves stay at 0. */
int test_restart_dw_counter_per_leaf_off_rows(void) {
    rs_fixture_t fx;
    TEST_ASSERT(rs_dw_factory(&fx), "fixture");
    factory_t *f = fx.f;
    TEST_ASSERT(f->n_leaf_nodes > 2, "more leaves than an old row's 2");
    TEST_ASSERT(!f->per_leaf_enabled, "per-leaf mode off");

    /* This build, after a root advance with no leaf advanced. */
    f->counter.layers[0].current_state = 1;
    f->counter.current_epoch = 1;
    TEST_ASSERT(persist_save_factory_dw_state(&fx.db, 0, f), "save");
    sqlite3_stmt *st;
    TEST_ASSERT(sqlite3_prepare_v2(fx.db.db, "SELECT n_leaf_nodes FROM "
                "dw_counter_state WHERE factory_id = 0;", -1, &st, NULL)
                == SQLITE_OK, "prepare");
    TEST_ASSERT(sqlite3_step(st) == SQLITE_ROW, "row");
    int stored_leaves = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    TEST_ASSERT_EQ(stored_leaves, f->n_leaf_nodes, "the row records every leaf");

    factory_t *rec_f = NULL;
    TEST_ASSERT(rs_load_factory(&fx, &rec_f), "load");
    TEST_ASSERT_EQ(rec_f->counter.current_epoch, 1, "epoch restored");
    TEST_ASSERT_EQ(rec_f->per_leaf_enabled, 0, "per-leaf mode still off");
    for (int i = 0; i < rec_f->n_leaf_nodes; i++)
        TEST_ASSERT_EQ(rec_f->leaf_layers[i].current_state, 0,
                       "leaf states as stored");
    factory_free(rec_f);
    free(rec_f);

    /* An older build's row past epoch 0 (the demo-mode epoch advance). */
    uint32_t layers[DW_MAX_LAYERS] = {0};
    for (uint32_t i = 0; i < f->counter.n_layers; i++)
        layers[i] = f->counter.layers[i].current_state;
    TEST_ASSERT(persist_save_dw_counter(&fx.db, 0, 1, f->counter.n_layers,
                                        layers), "save older row, epoch 1");
    TEST_ASSERT(rs_load_factory(&fx, &rec_f), "load older row, epoch 1");
    TEST_ASSERT_EQ(rec_f->counter.layers[0].current_state, 1,
                   "layer state as stored");
    for (int i = 0; i < rec_f->n_leaf_nodes; i++)
        TEST_ASSERT_EQ(rec_f->leaf_layers[i].current_state,
                       rec_f->leaf_layers[i].config.max_states - 1,
                       "unknown leaf states load as exhausted");
    factory_free(rec_f);
    free(rec_f);

    /* An older build's creation row (epoch 0). */
    for (uint32_t i = 0; i < f->counter.n_layers; i++) layers[i] = 0;
    TEST_ASSERT(persist_save_dw_counter(&fx.db, 0, 0, f->counter.n_layers,
                                        layers), "save older row, epoch 0");
    TEST_ASSERT(rs_load_factory(&fx, &rec_f), "load older row, epoch 0");
    for (int i = 0; i < rec_f->n_leaf_nodes; i++)
        TEST_ASSERT_EQ(rec_f->leaf_layers[i].current_state, 0,
                       "creation row: leaves stay at 0");
    factory_free(rec_f);
    free(rec_f);

    rs_teardown(&fx);
    return 1;
}

/* The remaining gap, asserted as it stands: on a two-leaf factory an older
   build's per_leaf=0 "0,0" row (n_leaf_nodes 2) cannot be told from this
   build's, so past epoch 0 its leaves still load as stored (0), not as
   exhausted.  Only main's demo-mode epoch save, run after demo payments on
   a two-leaf factory, wrote such a row with leaves that had moved. */
int test_restart_dw_counter_two_leaf_old_row(void) {
    rs_fixture_t fx;
    memset(&fx, 0, sizeof(fx));
    TEST_ASSERT(persist_open(&fx.db, NULL), "open");
    fx.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                      SECP256K1_CONTEXT_VERIFY);
    for (int i = 0; i < 5; i++)
        TEST_ASSERT(secp256k1_ec_pubkey_create(fx.ctx, &fx.pks[i], rs_seckeys[i]),
                    "pubkey");
    TEST_ASSERT(rs_build_factory(fx.ctx, fx.pks, FACTORY_ARITY_2, &fx.f), "factory");
    TEST_ASSERT_EQ(fx.f->n_leaf_nodes, 2, "two leaves");
    TEST_ASSERT(persist_save_factory(&fx.db, fx.f, fx.ctx, 0), "save factory");

    uint32_t layers[DW_MAX_LAYERS] = {0};
    for (uint32_t i = 0; i < fx.f->counter.n_layers; i++)
        layers[i] = (i == 0) ? 1 : 0;
    TEST_ASSERT(persist_save_dw_counter(&fx.db, 0, 1, fx.f->counter.n_layers,
                                        layers), "older row, epoch 1");
    factory_t *rec_f = NULL;
    TEST_ASSERT(rs_load_factory(&fx, &rec_f), "load");
    TEST_ASSERT_EQ(rec_f->counter.current_epoch, 1, "epoch restored");
    TEST_ASSERT_EQ(rec_f->counter.layers[0].current_state, 1, "root state restored");
    TEST_ASSERT_EQ(rec_f->per_leaf_enabled, 0, "per-leaf mode off");
    for (int i = 0; i < rec_f->n_leaf_nodes; i++)
        TEST_ASSERT_EQ(rec_f->leaf_layers[i].current_state, 0,
                       "gap: leaves load as stored, not as exhausted");

    factory_free(rec_f);
    free(rec_f);
    rs_teardown(&fx);
    return 1;
}

/* A restarted LSP must come back at the stored layer states, epoch and
   per-leaf states.  Stored with persist_save_dw_counter_with_leaves (the
   row the fixed save sites write), loaded with persist_load_factory (the
   restart path). */
int test_restart_dw_counter_restored_by_load_factory(void) {
    rs_fixture_t fx;
    TEST_ASSERT(rs_dw_factory(&fx), "fixture");
    factory_t *f = fx.f;
    TEST_ASSERT(f->counter.n_layers > 0 && f->n_leaf_nodes >= 2, "factory shape");

    uint32_t layers[DW_MAX_LAYERS] = {0};
    for (uint32_t i = 0; i < f->counter.n_layers; i++)
        layers[i] = (i + 1) % f->counter.layers[i].config.max_states;
    uint32_t leaves[64] = {0};
    TEST_ASSERT(f->n_leaf_nodes <= 64, "leaf count");
    for (int i = 0; i < f->n_leaf_nodes; i++)
        leaves[i] = (uint32_t)(i * 3 + 1) % f->leaf_layers[i].config.max_states;
    TEST_ASSERT(persist_save_dw_counter_with_leaves(&fx.db, 0, 6,
                    f->counter.n_layers, layers, 1, leaves, f->n_leaf_nodes),
                "save counter");

    factory_t *rec_f = NULL;
    TEST_ASSERT(rs_load_factory(&fx, &rec_f), "load factory");
    TEST_ASSERT_EQ(rec_f->counter.n_layers, f->counter.n_layers, "n_layers");
    for (uint32_t i = 0; i < rec_f->counter.n_layers; i++)
        TEST_ASSERT_EQ(rec_f->counter.layers[i].current_state, layers[i],
                       "layer current_state restored");
    TEST_ASSERT_EQ(rec_f->counter.current_epoch, 6, "epoch restored");
    TEST_ASSERT_EQ(rec_f->per_leaf_enabled, 1, "per-leaf mode restored");
    TEST_ASSERT_EQ(rec_f->n_leaf_nodes, f->n_leaf_nodes, "leaf count");
    for (int i = 0; i < rec_f->n_leaf_nodes; i++)
        TEST_ASSERT_EQ(rec_f->leaf_layers[i].current_state, leaves[i],
                       "leaf state restored");

    factory_free(rec_f);
    free(rec_f);
    rs_teardown(&fx);
    return 1;
}

/* Rows written before this fix hold config.max_states as each layer's
   state, which is out of range (dw_delay_for_state underflows on it).  The
   real state is unknown, so the layer loads as its last state: the next
   advance moves to a new root state instead of reusing one. */
int test_restart_dw_counter_legacy_row_loads_exhausted(void) {
    rs_fixture_t fx;
    TEST_ASSERT(rs_dw_factory(&fx), "fixture");
    factory_t *f = fx.f;

    uint32_t layers[DW_MAX_LAYERS] = {0};
    for (uint32_t i = 0; i < f->counter.n_layers; i++)
        layers[i] = f->counter.layers[i].config.max_states;
    uint32_t leaves[64] = {0};
    for (int i = 0; i < f->n_leaf_nodes; i++) leaves[i] = 1;
    TEST_ASSERT(persist_save_dw_counter_with_leaves(&fx.db, 0, 2,
                    f->counter.n_layers, layers, 1, leaves, f->n_leaf_nodes),
                "save legacy row");

    factory_t *rec_f = NULL;
    TEST_ASSERT(rs_load_factory(&fx, &rec_f), "load factory");
    for (uint32_t i = 0; i < rec_f->counter.n_layers; i++) {
        const dw_layer_t *L = &rec_f->counter.layers[i];
        TEST_ASSERT_EQ(L->current_state, L->config.max_states - 1,
                       "out-of-range layer state loads as the last state");
        TEST_ASSERT_EQ(dw_delay_for_state(&L->config, L->current_state), 0,
                       "no nSequence underflow");
    }
    TEST_ASSERT_EQ(rec_f->counter.current_epoch, 2, "epoch restored");
    for (int i = 0; i < rec_f->n_leaf_nodes; i++)
        TEST_ASSERT_EQ(rec_f->leaf_layers[i].current_state, 1,
                       "in-range leaf states restored as stored");

    factory_free(rec_f);
    free(rec_f);
    rs_teardown(&fx);
    return 1;
}

/* The save used by the leaf-advance, realloc, Tier B, rotation and
   creation paths writes each layer's current_state (it wrote
   config.max_states) and every leaf's state.  12 leaves: those paths
   copied leaf states into a uint32_t[8] on the stack. */
int test_restart_dw_state_save_writes_current_state(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f, "alloc");
    factory_alloc_default_arrays(f);
    dw_counter_init(&f->counter, 3, 10, 4);
    f->counter.layers[0].current_state = 1;
    f->counter.layers[1].current_state = 3;
    f->counter.layers[2].current_state = 2;
    f->counter.current_epoch = 9;
    f->per_leaf_enabled = 1;
    f->n_leaf_nodes = 12;
    for (int i = 0; i < f->n_leaf_nodes; i++) {
        dw_layer_init(&f->leaf_layers[i], 10, 4);
        f->leaf_layers[i].current_state = (uint32_t)(i % 4);
    }

    TEST_ASSERT(persist_save_factory_dw_state(&db, 0, f), "save");

    uint32_t epoch = 0, n_layers = 0, layers[DW_MAX_LAYERS];
    uint32_t leaves[32];
    int per_leaf = 0, n_leaf = 0;
    TEST_ASSERT(persist_load_dw_counter_with_leaves(&db, 0, &epoch, &n_layers,
                    layers, DW_MAX_LAYERS, &per_leaf, leaves, &n_leaf, 32),
                "load");
    TEST_ASSERT_EQ(n_layers, 3, "n_layers");
    TEST_ASSERT_EQ(layers[0], 1, "layer 0 current_state");
    TEST_ASSERT_EQ(layers[1], 3, "layer 1 current_state");
    TEST_ASSERT_EQ(layers[2], 2, "layer 2 current_state");
    TEST_ASSERT_EQ(epoch, 9, "epoch");
    TEST_ASSERT_EQ(per_leaf, 1, "per-leaf flag");
    TEST_ASSERT_EQ(n_leaf, 12, "leaf count");
    for (int i = 0; i < 12; i++)
        TEST_ASSERT_EQ(leaves[i], (uint32_t)(i % 4), "leaf state");

    factory_free(f);
    free(f);
    persist_close(&db);
    return 1;
}

/* Up to FACTORY_MAX_LEAVES leaves: the leaf-state string was built in, and
   parsed from, a 256-byte buffer, so leaves past about the 128th were
   dropped without an error. */
int test_restart_dw_counter_many_leaves_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");
    enum { N = 200 };
    const uint32_t layers[2] = { 1, 2 };
    uint32_t leaves[N], loaded[N];
    for (int i = 0; i < N; i++) {
        leaves[i] = (i % 7 == 0) ? 4000000000u : (uint32_t)(i % 4);
        loaded[i] = 0xDEADBEEFu;
    }
    TEST_ASSERT(persist_save_dw_counter_with_leaves(&db, 0, 3, 2, layers,
                                                    1, leaves, N), "save");
    uint32_t epoch = 0, n_layers = 0, lay[DW_MAX_LAYERS];
    int per_leaf = 0, n_leaf = 0;
    TEST_ASSERT(persist_load_dw_counter_with_leaves(&db, 0, &epoch, &n_layers,
                    lay, DW_MAX_LAYERS, &per_leaf, loaded, &n_leaf, N), "load");
    TEST_ASSERT_EQ(n_leaf, N, "leaf count");
    for (int i = 0; i < N; i++)
        TEST_ASSERT_EQ(loaded[i], leaves[i], "every leaf state round-trips");

    persist_close(&db);
    return 1;
}

/* ---- A failed COMMIT ---- */

static long rs_count(persist_t *db, const char *sql) {
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    long n = (sqlite3_step(st) == SQLITE_ROW) ? (long)sqlite3_column_int64(st, 0) : -1;
    sqlite3_finalize(st);
    return n;
}

/* A busy COMMIT, made on one connection.  In rollback-journal mode an
   INSERT takes the SHARED and then the RESERVED lock; only COMMIT asks
   the VFS for EXCLUSIVE, which it must hold before it writes the database
   file.  rs_bvfs wraps the platform's default VFS and answers the next n
   EXCLUSIVE requests with SQLITE_BUSY, which is what the default VFS
   answers while another connection holds SHARED.  The pager then calls the
   busy handler (here: give up at once) and COMMIT returns SQLITE_BUSY with
   the transaction still open.  No second connection is involved, so
   nothing depends on how a platform's SQLite settles locks between
   connections.  (The daemon's DBs use WAL, where COMMIT takes no such lock
   and is rarely busy; the rollback journal is only how the test gets a
   busy COMMIT.) */
typedef struct {
    sqlite3_file base;
    sqlite3_file *real;  /* the wrapped file, stored right after this */
} rs_bfile_t;

static sqlite3_vfs rs_bvfs;
static sqlite3_vfs *rs_bvfs_real;
static int rs_bvfs_refuse;   /* EXCLUSIVE requests still to refuse */
static int rs_bvfs_refused;  /* EXCLUSIVE requests refused */

#define RS_REAL(f) (((rs_bfile_t *)(f))->real)

static int rs_bf_close(sqlite3_file *f) {
    return RS_REAL(f)->pMethods->xClose(RS_REAL(f));
}
static int rs_bf_read(sqlite3_file *f, void *buf, int n, sqlite3_int64 off) {
    return RS_REAL(f)->pMethods->xRead(RS_REAL(f), buf, n, off);
}
static int rs_bf_write(sqlite3_file *f, const void *buf, int n, sqlite3_int64 off) {
    return RS_REAL(f)->pMethods->xWrite(RS_REAL(f), buf, n, off);
}
static int rs_bf_truncate(sqlite3_file *f, sqlite3_int64 size) {
    return RS_REAL(f)->pMethods->xTruncate(RS_REAL(f), size);
}
static int rs_bf_sync(sqlite3_file *f, int flags) {
    return RS_REAL(f)->pMethods->xSync(RS_REAL(f), flags);
}
static int rs_bf_size(sqlite3_file *f, sqlite3_int64 *size) {
    return RS_REAL(f)->pMethods->xFileSize(RS_REAL(f), size);
}
static int rs_bf_lock(sqlite3_file *f, int level) {
    if (level == SQLITE_LOCK_EXCLUSIVE && rs_bvfs_refuse > 0) {
        rs_bvfs_refuse--;
        rs_bvfs_refused++;
        return SQLITE_BUSY;
    }
    return RS_REAL(f)->pMethods->xLock(RS_REAL(f), level);
}
static int rs_bf_unlock(sqlite3_file *f, int level) {
    return RS_REAL(f)->pMethods->xUnlock(RS_REAL(f), level);
}
static int rs_bf_check_reserved(sqlite3_file *f, int *out) {
    return RS_REAL(f)->pMethods->xCheckReservedLock(RS_REAL(f), out);
}
static int rs_bf_fcntl(sqlite3_file *f, int op, void *arg) {
    return RS_REAL(f)->pMethods->xFileControl(RS_REAL(f), op, arg);
}
static int rs_bf_sector(sqlite3_file *f) {
    return RS_REAL(f)->pMethods->xSectorSize(RS_REAL(f));
}
static int rs_bf_devchar(sqlite3_file *f) {
    return RS_REAL(f)->pMethods->xDeviceCharacteristics(RS_REAL(f));
}
static int rs_bf_shm_map(sqlite3_file *f, int pg, int pgsz, int extend,
                         void volatile **pp) {
    return RS_REAL(f)->pMethods->xShmMap(RS_REAL(f), pg, pgsz, extend, pp);
}
static int rs_bf_shm_lock(sqlite3_file *f, int off, int n, int flags) {
    return RS_REAL(f)->pMethods->xShmLock(RS_REAL(f), off, n, flags);
}
static void rs_bf_shm_barrier(sqlite3_file *f) {
    RS_REAL(f)->pMethods->xShmBarrier(RS_REAL(f));
}
static int rs_bf_shm_unmap(sqlite3_file *f, int del) {
    return RS_REAL(f)->pMethods->xShmUnmap(RS_REAL(f), del);
}
static int rs_bf_fetch(sqlite3_file *f, sqlite3_int64 off, int n, void **pp) {
    return RS_REAL(f)->pMethods->xFetch(RS_REAL(f), off, n, pp);
}
static int rs_bf_unfetch(sqlite3_file *f, sqlite3_int64 off, void *p) {
    return RS_REAL(f)->pMethods->xUnfetch(RS_REAL(f), off, p);
}

/* One table per io-methods version: the wrapper offers the version the
   wrapped file has (SQLite checks it before using shared memory or mmap). */
#define RS_BF_METHODS(v) { v, rs_bf_close, rs_bf_read, rs_bf_write, \
    rs_bf_truncate, rs_bf_sync, rs_bf_size, rs_bf_lock, rs_bf_unlock, \
    rs_bf_check_reserved, rs_bf_fcntl, rs_bf_sector, rs_bf_devchar, \
    rs_bf_shm_map, rs_bf_shm_lock, rs_bf_shm_barrier, rs_bf_shm_unmap, \
    rs_bf_fetch, rs_bf_unfetch }
static const sqlite3_io_methods rs_bf_methods[3] = {
    RS_BF_METHODS(1), RS_BF_METHODS(2), RS_BF_METHODS(3)
};

static int rs_bvfs_open(sqlite3_vfs *vfs, const char *name, sqlite3_file *f,
                        int flags, int *out_flags) {
    (void)vfs;
    rs_bfile_t *bf = (rs_bfile_t *)f;
    bf->real = (sqlite3_file *)(bf + 1);
    memset(bf->real, 0, (size_t)rs_bvfs_real->szOsFile);
    int rc = rs_bvfs_real->xOpen(rs_bvfs_real, name, bf->real, flags, out_flags);
    if (!bf->real->pMethods) {
        bf->base.pMethods = NULL;  /* nothing was opened: nothing to close */
        return rc;
    }
    int v = bf->real->pMethods->iVersion;
    bf->base.pMethods = &rs_bf_methods[(v < 1 ? 1 : v > 3 ? 3 : v) - 1];
    return rc;
}

static int rs_bvfs_install(void) {
    rs_bvfs_real = sqlite3_vfs_find(NULL);
    if (!rs_bvfs_real) return 0;
    rs_bvfs = *rs_bvfs_real;
    rs_bvfs.pNext = NULL;
    rs_bvfs.zName = "rs_busy";
    rs_bvfs.szOsFile = (int)sizeof(rs_bfile_t) + rs_bvfs_real->szOsFile;
    rs_bvfs.xOpen = rs_bvfs_open;
    rs_bvfs_refuse = 0;
    rs_bvfs_refused = 0;
    return sqlite3_vfs_register(&rs_bvfs, 0) == SQLITE_OK;  /* not the default */
}

static int rs_give_up(void *arg, int n) {
    (void)arg;
    (void)n;
    return 0;  /* no waiting: COMMIT returns SQLITE_BUSY at once */
}

static void rs_unlink_db(const char *path) {
    char side[600];
    unlink(path);
    snprintf(side, sizeof(side), "%s-journal", path);
    unlink(side);
    snprintf(side, sizeof(side), "%s-wal", path);
    unlink(side);
    snprintf(side, sizeof(side), "%s-shm", path);
    unlink(side);
}

static int rs_busy_commit_body(persist_t *db, const char *path) {
    TEST_ASSERT(sqlite3_open_v2(path, &db->db,
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                                "rs_busy") == SQLITE_OK, "open through the test VFS");
    sqlite3_stmt *st;
    TEST_ASSERT(sqlite3_prepare_v2(db->db, "PRAGMA journal_mode=DELETE;", -1,
                                   &st, NULL) == SQLITE_OK, "journal mode");
    const unsigned char *mode =
        (sqlite3_step(st) == SQLITE_ROW) ? sqlite3_column_text(st, 0) : NULL;
    int rollback = mode && strcmp((const char *)mode, "wal") != 0 &&
                   strcmp((const char *)mode, "off") != 0;
    sqlite3_finalize(st);
    TEST_ASSERT(rollback, "rollback journal (its COMMIT takes the EXCLUSIVE lock)");
    TEST_ASSERT(sqlite3_exec(db->db, "CREATE TABLE rs_busy (id INTEGER PRIMARY KEY);",
                             NULL, NULL, NULL) == SQLITE_OK, "table");
    sqlite3_busy_handler(db->db, rs_give_up, NULL);

    /* Busy once: the retry commits. */
    TEST_ASSERT(persist_begin(db), "begin");
    TEST_ASSERT(sqlite3_exec(db->db, "INSERT INTO rs_busy VALUES (1);",
                             NULL, NULL, NULL) == SQLITE_OK, "insert");
    rs_bvfs_refused = 0;
    rs_bvfs_refuse = 1;
    TEST_ASSERT(persist_commit(db), "the retry commits");
    TEST_ASSERT_EQ(rs_bvfs_refused, 1, "the first COMMIT was busy");
    TEST_ASSERT_EQ(rs_bvfs_refuse, 0, "the refusal was used");
    TEST_ASSERT(!persist_in_transaction(db) && sqlite3_get_autocommit(db->db),
                "transaction closed");
    TEST_ASSERT_EQ(rs_count(db, "SELECT COUNT(*) FROM rs_busy;"), 1, "row committed");

    /* Busy on both attempts: rolled back. */
    TEST_ASSERT(persist_begin(db), "begin");
    TEST_ASSERT(sqlite3_exec(db->db, "INSERT INTO rs_busy VALUES (2);",
                             NULL, NULL, NULL) == SQLITE_OK, "insert");
    rs_bvfs_refused = 0;
    rs_bvfs_refuse = 2;
    TEST_ASSERT(!persist_commit(db), "still busy after the retry: fails");
    TEST_ASSERT_EQ(rs_bvfs_refused, 2, "COMMIT tried twice");
    rs_bvfs_refuse = 0;
    TEST_ASSERT(sqlite3_get_autocommit(db->db), "rolled back");
    TEST_ASSERT(!persist_in_transaction(db), "flag cleared");
    TEST_ASSERT_EQ(rs_count(db, "SELECT COUNT(*) FROM rs_busy;"), 1,
                   "the rolled-back row is not there");
    return 1;
}

/* A busy COMMIT is retried once: when the retry gets the lock it commits;
   when the retry is busy too, the transaction is rolled back. */
int test_restart_commit_busy_retried_once(void) {
    char path[] = "/tmp/ss_rs_busy_XXXXXX";
    int tfd = mkstemp(path);  /* an empty file (mode 0600) opens as a new DB */
    TEST_ASSERT(tfd >= 0, "temp file");
    close(tfd);
    persist_t db;
    memset(&db, 0, sizeof(db));
    int ok = 0;
    if (rs_bvfs_install()) {
        ok = rs_busy_commit_body(&db, path);
        persist_close(&db);
        sqlite3_vfs_unregister(&rs_bvfs);
    } else {
        printf("  FAIL: %s: cannot register the test VFS\n", __func__);
    }
    rs_unlink_db(path);
    return ok;
}

/* A deferred foreign-key violation makes COMMIT fail and leaves the
   SQLite transaction open.  persist_commit used to clear its flag anyway:
   the next BEGIN then failed and later writes went into the stale
   transaction.  Now the failed transaction is rolled back, the flag
   matches the connection, and the next transaction starts clean. */
int test_restart_commit_failure_rolls_back(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");
    TEST_ASSERT(sqlite3_exec(db.db,
        "CREATE TABLE rs_parent (id INTEGER PRIMARY KEY);"
        "CREATE TABLE rs_child (id INTEGER PRIMARY KEY, parent INTEGER "
        "  REFERENCES rs_parent(id) DEFERRABLE INITIALLY DEFERRED);",
        NULL, NULL, NULL) == SQLITE_OK, "create tables");

    TEST_ASSERT(persist_begin(&db), "begin");
    TEST_ASSERT(sqlite3_exec(db.db, "INSERT INTO rs_child VALUES (1, 99);",
                             NULL, NULL, NULL) == SQLITE_OK, "insert orphan row");
    TEST_ASSERT(!persist_commit(&db), "COMMIT fails on the deferred FK");
    TEST_ASSERT_EQ(persist_in_transaction(&db), !sqlite3_get_autocommit(db.db),
                   "in-transaction flag matches the connection");
    TEST_ASSERT(sqlite3_get_autocommit(db.db), "failed transaction rolled back");

    TEST_ASSERT(persist_begin(&db), "next BEGIN succeeds");
    TEST_ASSERT(sqlite3_exec(db.db, "INSERT INTO rs_parent VALUES (7);",
                             NULL, NULL, NULL) == SQLITE_OK, "insert");
    TEST_ASSERT(persist_commit(&db), "next COMMIT succeeds");
    TEST_ASSERT_EQ(rs_count(&db, "SELECT COUNT(*) FROM rs_child;"), 0,
                   "the failed transaction's row was not committed later");
    TEST_ASSERT_EQ(rs_count(&db, "SELECT COUNT(*) FROM rs_parent;"), 1,
                   "the next transaction's row was");

    persist_close(&db);
    return 1;
}

/* ---- A client reconnect attaches the DB ---- */

#define RS_CLIENT_IDX 1   /* client 2: a channel id other than 0 */
#define RS_CLIENT_CN  3

/* The LSP side of a reconnect, in a child process: accept, noise
   handshake, MSG_RECONNECT, CHANNEL_NONCES both ways, RECONNECT_ACK, then
   wait for the client to hang up.  The exit code says where it stopped. */
static void rs_fake_lsp(int listen_fd, uint64_t cn) {
    alarm(30);
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                      SECP256K1_CONTEXT_VERIFY);
    int fd = wire_accept(listen_fd);
    if (fd < 0) _exit(2);
    if (!wire_noise_handshake_responder(fd, ctx)) _exit(3);
    wire_msg_t m;
    if (!wire_recv(fd, &m) || m.msg_type != MSG_RECONNECT) _exit(4);
    cJSON_Delete(m.json);

    /* Real pubnonces, from a throwaway channel's pool. */
    secp256k1_pubkey lpk, cpk;
    if (!secp256k1_ec_pubkey_create(ctx, &lpk, rs_seckeys[0]) ||
        !secp256k1_ec_pubkey_create(ctx, &cpk, rs_seckeys[RS_CLIENT_IDX + 1]))
        _exit(5);
    const unsigned char txid[32] = {0}, spk[34] = {0};
    channel_t nch;
    if (!channel_init(&nch, ctx, rs_seckeys[0], &lpk, &cpk, txid, 0, 100000,
                      spk, sizeof(spk), 50000, 50000, CHANNEL_DEFAULT_CSV_DELAY) ||
        !channel_init_nonce_pool(&nch, 4))
        _exit(6);
    size_t n = nch.local_nonce_pool.count;
    unsigned char (*pn)[66] = calloc(n, 66);
    if (!pn) _exit(6);
    for (size_t i = 0; i < n; i++)
        musig_pubnonce_serialize(ctx, pn[i], &nch.local_nonce_pool.nonces[i].pubnonce);
    cJSON *nm = wire_build_channel_nonces(RS_CLIENT_IDX,
                                          (const unsigned char (*)[66])pn, n);
    if (!wire_send(fd, MSG_CHANNEL_NONCES, nm)) _exit(7);
    cJSON_Delete(nm);
    if (!wire_recv(fd, &m) || m.msg_type != MSG_CHANNEL_NONCES) _exit(8);
    cJSON_Delete(m.json);

    cJSON *ack = wire_build_reconnect_ack(RS_CLIENT_IDX, 45000000, 40000000, cn);
    if (!wire_send(fd, MSG_RECONNECT_ACK, ack)) _exit(9);
    cJSON_Delete(ack);
    while (wire_recv(fd, &m))
        if (m.json) cJSON_Delete(m.json);
    _exit(0);
}

typedef struct {
    int called;
    void *persist_db;
    uint32_t persist_channel_id;
    int revocation_ok;
} rs_client_cb_t;

/* Stands in for the daemon's channel callback on a reconnect: records how
   the restored channel is attached, then receives the LSP's revocation of
   commitment RS_CLIENT_CN - 1 (its PCP, then the secret). */
static int rs_client_cb(int fd, channel_t *ch, uint32_t my_index,
                        secp256k1_context *ctx, const secp256k1_keypair *kp,
                        factory_t *f, size_t n_participants, void *ud) {
    (void)fd; (void)my_index; (void)kp; (void)f; (void)n_participants;
    rs_client_cb_t *c = ud;
    c->called = 1;
    c->persist_db = ch->persist_db;
    c->persist_channel_id = ch->persist_channel_id;
    unsigned char secret[32];
    memset(secret, 0x5a, sizeof(secret));
    secp256k1_pubkey pcp;
    if (secp256k1_ec_pubkey_create(ctx, &pcp, secret)) {
        channel_set_remote_pcp(ch, RS_CLIENT_CN - 1, &pcp);
        c->revocation_ok = channel_receive_revocation_flat(ch, RS_CLIENT_CN - 1,
                                                           secret);
    }
    return 2;  /* handled; client_run_reconnect returns 1 */
}

/* The client's channel as its first run builds it, for client
   RS_CLIENT_IDX + 1 of the fixture factory (so its index is not 0). */
static int rs_client_channel(rs_fixture_t *fx, secp256k1_keypair *kp,
                             channel_t *cch) {
    const uint32_t my_index = RS_CLIENT_IDX + 1;
    if (!secp256k1_keypair_create(fx->ctx, kp, rs_seckeys[my_index])) return 0;
    secp256k1_pubkey lsp_bp[4];
    unsigned char s[32], csec[4][32];
    for (int i = 0; i < 4; i++) {
        memset(s, 0x70 + i, sizeof(s));
        if (!secp256k1_ec_pubkey_create(fx->ctx, &lsp_bp[i], s)) return 0;
        memset(csec[i], 0x80 + i, sizeof(csec[i]));
    }
    return client_init_channel(cch, fx->ctx, fx->f, kp, my_index,
                               &lsp_bp[0], &lsp_bp[1], &lsp_bp[2], &lsp_bp[3],
                               csec[0], csec[1], csec[2], csec[3], NULL);
}

/* client_run_reconnect from cdb against a fake LSP (a forked child) that
   acknowledges commitment cn.  Returns client_run_reconnect's result;
   *lsp_ok says whether the fake LSP ran the whole reconnect. */
static int rs_run_reconnect(rs_fixture_t *fx, persist_t *cdb,
                            const secp256k1_keypair *kp, uint64_t cn,
                            client_channel_cb_t cb, void *ud, int *lsp_ok) {
    extern factory_t *g_client_active_factory;
    *lsp_ok = 0;
    int lfd = wire_listen("127.0.0.1", 0);
    if (lfd < 0) return 0;
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    if (getsockname(lfd, (struct sockaddr *)&sa, &sl) != 0) {
        close(lfd);
        return 0;
    }
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) {
        close(lfd);
        return 0;
    }
    if (pid == 0) rs_fake_lsp(lfd, cn);
    close(lfd);
    int ok = client_run_reconnect(fx->ctx, kp, "127.0.0.1", ntohs(sa.sin_port),
                                  cdb, cb, ud);
    g_client_active_factory = NULL;  /* client_run_reconnect freed it */
    int status = 0;
    if (waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0)
        *lsp_ok = 1;
    return ok;
}

/* The daemon attaches the client's DB to its channel only on the first
   run; client_run_reconnect rebuilt the channel without it, so after any
   reconnect or client restart the LSP's revocation secrets were no longer
   written to the DB.  Reconnect from a client DB to a fake LSP and check
   that a revocation received afterwards reaches the DB, under
   CLIENT_DB_CHANNEL_ID although the client's index is 1. */
int test_restart_client_reconnect_attaches_db(void) {
    rs_fixture_t fx;
    TEST_ASSERT(rs_setup(&fx, 4), "fixture");  /* for the factory and keys */

    /* The client DB as the client's first run left it. */
    persist_t cdb;
    TEST_ASSERT(persist_open(&cdb, NULL), "client db");
    secp256k1_keypair kp;
    channel_t cch;
    TEST_ASSERT(rs_client_channel(&fx, &kp, &cch), "client channel");
    TEST_ASSERT(persist_begin(&cdb), "begin");
    TEST_ASSERT(persist_save_factory(&cdb, fx.f, fx.ctx, 0), "save factory");
    TEST_ASSERT(persist_save_channel(&cdb, &cch, 0, CLIENT_DB_CHANNEL_ID),
                "save channel");
    TEST_ASSERT(persist_save_basepoints(&cdb, CLIENT_DB_CHANNEL_ID, &cch),
                "save basepoints");
    TEST_ASSERT(persist_update_channel_balance(&cdb, CLIENT_DB_CHANNEL_ID, 40000,
                                               45000, RS_CLIENT_CN), "save balance");
    TEST_ASSERT(persist_commit(&cdb), "commit");
    channel_cleanup(&cch);

    rs_client_cb_t cb = { 0, NULL, 0, 0 };
    int lsp_ok = 0;
    int ok = rs_run_reconnect(&fx, &cdb, &kp, RS_CLIENT_CN, rs_client_cb, &cb,
                              &lsp_ok);
    TEST_ASSERT(lsp_ok, "fake LSP ran the whole reconnect");
    TEST_ASSERT(ok, "client_run_reconnect");
    TEST_ASSERT(cb.called, "channel callback ran");
    TEST_ASSERT(cb.persist_db == &cdb, "restored channel attached to the DB");
    TEST_ASSERT_EQ(cb.persist_channel_id, CLIENT_DB_CHANNEL_ID,
                   "under the client DB's channel id");
    TEST_ASSERT(cb.revocation_ok, "revocation accepted");

    unsigned char secrets[16][32], want[32];
    uint8_t valid[16];
    size_t n_rev = 0;
    memset(want, 0x5a, sizeof(want));
    TEST_ASSERT(persist_load_revocations_flat(&cdb, CLIENT_DB_CHANNEL_ID, secrets,
                                              valid, 16, &n_rev), "load revocations");
    TEST_ASSERT(valid[RS_CLIENT_CN - 1], "revocation secret written after the reconnect");
    TEST_ASSERT(memcmp(secrets[RS_CLIENT_CN - 1], want, 32) == 0,
                "persisted secret matches");
    unsigned char pcp_ser[33];
    TEST_ASSERT(persist_load_remote_pcp(&cdb, CLIENT_DB_CHANNEL_ID, RS_CLIENT_CN - 1,
                                        pcp_ser), "remote PCP written after the reconnect");

    persist_close(&cdb);
    rs_teardown(&fx);
    return 1;
}

/* ---- A restored factory refuses to advance ---- */

/* Every dw_counter_state and tree_nodes row, as one string. */
static char *rs_snapshot(persist_t *db) {
    const char *sql =
        "SELECT group_concat(r, '|') FROM ("
        " SELECT 'dw' || quote(factory_id) || quote(current_epoch) ||"
        "  quote(n_layers) || quote(layer_states) || quote(per_leaf_enabled) ||"
        "  quote(n_leaf_nodes) || quote(leaf_states) AS r FROM dw_counter_state"
        " UNION ALL"
        " SELECT 'tn' || quote(factory_id) || quote(node_index) ||"
        "  quote(nsequence) || quote(output_amounts) || quote(txid) ||"
        "  quote(is_signed) || quote(signed_tx_hex) FROM tree_nodes"
        " ORDER BY 1);";
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db->db, sql, -1, &st, NULL) != SQLITE_OK) return NULL;
    char *out = NULL;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *t = (const char *)sqlite3_column_text(st, 0);
        out = strdup(t ? t : "");
    }
    sqlite3_finalize(st);
    return out;
}

/* persist_load_factory rebuilds the tree at its initial state, so with the
   DW counter restored an advance would be built over the epoch-0 parents.
   Tier B moved the root to state 1 and reset the leaves (the stored state
   is set up as Tier B leaves it); after a restart the counter comes back
   there, and every advance entry point, and the LSP's leaf advance, refuse
   without changing the counter or the stored rows. */
int test_restart_advance_refused_after_restore(void) {
    rs_fixture_t fx;
    TEST_ASSERT(rs_dw_factory(&fx), "fixture");
    factory_t *f = fx.f;
    TEST_ASSERT(persist_save_tree_nodes(&fx.db, f, 0), "save tree");
    f->counter.layers[0].current_state = 1;
    f->counter.current_epoch = 1;
    f->per_leaf_enabled = 1;
    TEST_ASSERT(persist_save_factory_dw_state(&fx.db, 0, f), "save DW state");
    TEST_ASSERT(!f->tree_rebuilt_on_load && !factory_advance_refused(f),
                "a factory built in memory is not marked");
    char *before = rs_snapshot(&fx.db);
    TEST_ASSERT(before && before[0], "snapshot");

    factory_t *rec_f = NULL;
    TEST_ASSERT(rs_load_factory(&fx, &rec_f), "load factory");
    TEST_ASSERT(rec_f->tree_rebuilt_on_load, "loaded factory marked");
    TEST_ASSERT_EQ(rec_f->counter.layers[0].current_state, 1, "root state restored");
    TEST_ASSERT_EQ(rec_f->counter.current_epoch, 1, "epoch restored");

    uint64_t amounts[4] = { 0 };
    size_t n_amounts = rec_f->nodes[rec_f->leaf_node_indices[0]].n_outputs;
    for (size_t i = 0; i < n_amounts && i < 4; i++)
        amounts[i] = rec_f->nodes[rec_f->leaf_node_indices[0]].outputs[i].amount_sats;
    TEST_ASSERT(factory_advance_refused(rec_f), "loaded factory refuses advances");
    TEST_ASSERT(!rec_f->tree_refusal_logged, "nothing logged yet");
    TEST_ASSERT_EQ(factory_advance_leaf_unsigned(rec_f, 0), FACTORY_ADVANCE_REFUSED,
                   "leaf advance refused, not reported as exhausted");
    TEST_ASSERT(rec_f->tree_refusal_logged, "refusal logged (once per factory)");
    TEST_ASSERT_EQ(factory_advance_and_rebuild_path(rec_f, 0), FACTORY_ADVANCE_REFUSED,
                   "advance-and-rebuild refused");
    TEST_ASSERT_EQ(factory_advance_leaf(rec_f, 0), 0, "signed leaf advance refused");
    TEST_ASSERT_EQ(factory_set_leaf_amounts(rec_f, 0, amounts,
                                            n_amounts < 4 ? n_amounts : 4), 0,
                   "realloc refused");
    TEST_ASSERT_EQ(factory_advance(rec_f), 0, "root advance refused");
    TEST_ASSERT_EQ(factory_tick_root(rec_f), FACTORY_ADVANCE_REFUSED,
                   "root tick refused, not reported as no rollover");
    TEST_ASSERT_EQ(factory_subfactory_chain_advance_unsigned(rec_f, 0, 0, 0, 1000), 0,
                   "sub-factory chain advance refused");
    TEST_ASSERT_EQ(rec_f->counter.layers[0].current_state, 1, "root state unchanged");
    TEST_ASSERT_EQ(rec_f->counter.current_epoch, 1, "epoch unchanged");
    for (int i = 0; i < rec_f->n_leaf_nodes; i++)
        TEST_ASSERT_EQ(rec_f->leaf_layers[i].current_state, 0, "leaf states unchanged");
    factory_free(rec_f);
    free(rec_f);

    /* The LSP's leaf advance, on a factory restored the way the daemon
       restores it. */
    lsp_t *lsp = rs_make_lsp(&fx);
    TEST_ASSERT(lsp, "lsp");
    TEST_ASSERT(persist_load_factory(&fx.db, 0, &lsp->factory, fx.ctx), "restore");
    lsp_channel_mgr_t *mgr = calloc(1, sizeof(*mgr));
    TEST_ASSERT(mgr, "alloc");
    mgr->persist = &fx.db;
    TEST_ASSERT(!lsp_channels_advance_ps_leaf(mgr, lsp, 0), "LSP leaf advance refused");
    TEST_ASSERT_EQ(lsp->factory.leaf_layers[0].current_state, 0, "leaf state unchanged");

    char *after = rs_snapshot(&fx.db);
    TEST_ASSERT(after && strcmp(before, after) == 0,
                "DW and tree rows unchanged");

    free(before);
    free(after);
    free(mgr);
    factory_free(&lsp->factory);
    rs_free_lsp(lsp);
    rs_teardown(&fx);
    return 1;
}

/* A restarted client loads its factory through persist_load_factory too,
   so it refuses a Tier B proposal, root-driven or leaf-driven, before
   sending anything back: one restarted client stops root rollovers for
   the whole factory until the tree reload lands. */
int test_restart_client_refuses_tier_b_after_restore(void) {
    rs_fixture_t fx;
    TEST_ASSERT(rs_dw_factory(&fx), "fixture");
    factory_t *rec_f = NULL;
    TEST_ASSERT(rs_load_factory(&fx, &rec_f), "client restart: load factory");
    secp256k1_keypair kp;
    TEST_ASSERT(secp256k1_keypair_create(fx.ctx, &kp, rs_seckeys[1]), "keypair");
    uint32_t root0 = rec_f->counter.layers[0].current_state;
    uint32_t epoch0 = rec_f->counter.current_epoch;
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    for (int trigger = -1; trigger <= 0; trigger++) {
        cJSON *j = wire_build_state_adv_propose_intent(epoch0 + 1, 1, trigger);
        TEST_ASSERT(j, "proposal");
        wire_msg_t m = { .msg_type = MSG_STATE_ADV_PROPOSE_INTENT, .json = j };
        int ok = client_handle_state_advance(sv[0], fx.ctx, &kp, rec_f, 1, &m);
        cJSON_Delete(j);
        TEST_ASSERT(!ok, trigger < 0 ? "root-driven Tier B refused"
                                     : "leaf-driven Tier B refused");
    }
    TEST_ASSERT_EQ(rec_f->counter.layers[0].current_state, root0, "root state unchanged");
    TEST_ASSERT_EQ(rec_f->counter.current_epoch, epoch0, "epoch unchanged");
    for (int i = 0; i < rec_f->n_leaf_nodes; i++)
        TEST_ASSERT_EQ(rec_f->leaf_layers[i].current_state, 0, "leaf states unchanged");
    char b;
    errno = 0;
    TEST_ASSERT(recv(sv[1], &b, 1, MSG_DONTWAIT) < 0 &&
                (errno == EAGAIN || errno == EWOULDBLOCK), "nothing sent to the LSP");

    close(sv[0]);
    close(sv[1]);
    factory_free(rec_f);
    free(rec_f);
    rs_teardown(&fx);
    return 1;
}

/* ---- A client DB keeps its channel under one id ---- */

/* Older client builds kept the channel row, balances, basepoints, and the
   revocation secrets and points written through the channel under the
   client's index, and everything else under 0, so for any client but the
   first, reads that used the other id found nothing.  Lay a DB out the way
   main's client 2 left it and move it: every row is under
   CLIENT_DB_CHANNEL_ID and loads, a second run changes nothing, and an
   LSP DB is left alone.  client_run_reconnect and every DB open in the
   client daemon run the move first. */
int test_restart_client_legacy_db_moves_to_channel_0(void) {
    rs_fixture_t fx;
    TEST_ASSERT(rs_setup(&fx, 4), "fixture");
    persist_t cdb;
    TEST_ASSERT(persist_open(&cdb, NULL), "client db");
    secp256k1_keypair kp;
    channel_t cch;
    TEST_ASSERT(rs_client_channel(&fx, &kp, &cch), "client channel");

    const uint32_t old = RS_CLIENT_IDX;
    unsigned char secret[32], pcs[32], ser[33];
    memset(secret, 0x5a, sizeof(secret));
    memset(pcs, 0x6b, sizeof(pcs));
    secp256k1_pubkey pcp;
    size_t len = sizeof(ser);
    TEST_ASSERT(secp256k1_ec_pubkey_create(fx.ctx, &pcp, secret) &&
                secp256k1_ec_pubkey_serialize(fx.ctx, ser, &len, &pcp,
                                              SECP256K1_EC_COMPRESSED), "point");
    TEST_ASSERT(persist_begin(&cdb), "begin");
    TEST_ASSERT(persist_save_factory(&cdb, fx.f, fx.ctx, 0), "factory");
    TEST_ASSERT(persist_save_channel(&cdb, &cch, 0, old), "channel row, index");
    TEST_ASSERT(persist_save_basepoints(&cdb, old, &cch), "basepoints, index");
    TEST_ASSERT(persist_update_channel_balance(&cdb, old, 40000, 45000, 3),
                "balance, index");
    TEST_ASSERT(persist_save_revocation(&cdb, old, 2, secret), "revocation, index");
    TEST_ASSERT(persist_save_remote_pcp(&cdb, old, 2, ser), "point 2, index");
    TEST_ASSERT(persist_save_remote_pcp(&cdb, CLIENT_DB_CHANNEL_ID, 2, ser),
                "point 2 again under 0 (explicit save)");
    TEST_ASSERT(persist_save_remote_pcp(&cdb, old, 3, ser), "point 3, index only");
    TEST_ASSERT(persist_save_local_pcs(&cdb, CLIENT_DB_CHANNEL_ID, 3, pcs),
                "local secret under 0");
    TEST_ASSERT(persist_commit(&cdb), "commit");
    channel_cleanup(&cch);

    for (int run = 0; run < 2; run++) {
        TEST_ASSERT(persist_client_move_to_channel_0(&cdb), "move");
        uint64_t l = 0, r = 0, cn = 0;
        TEST_ASSERT(persist_load_channel_state(&cdb, CLIENT_DB_CHANNEL_ID,
                                               &l, &r, &cn), "channel state under 0");
        TEST_ASSERT(l == 40000 && r == 45000 && cn == 3,
                    "balances and commitment number kept");
        unsigned char ls[4][32], rb[4][33];
        TEST_ASSERT(persist_load_basepoints(&cdb, CLIENT_DB_CHANNEL_ID, ls, rb),
                    "basepoints under 0");
        unsigned char secrets[8][32];
        uint8_t valid[8];
        size_t n = 0;
        TEST_ASSERT(persist_load_revocations_flat(&cdb, CLIENT_DB_CHANNEL_ID,
                                                  secrets, valid, 8, &n) &&
                    valid[2] && memcmp(secrets[2], secret, 32) == 0,
                    "revocation under 0");
        unsigned char got[33];
        TEST_ASSERT(persist_load_remote_pcp(&cdb, CLIENT_DB_CHANNEL_ID, 2, got) &&
                    memcmp(got, ser, 33) == 0, "point 2 under 0");
        TEST_ASSERT(persist_load_remote_pcp(&cdb, CLIENT_DB_CHANNEL_ID, 3, got) &&
                    memcmp(got, ser, 33) == 0, "point 3 moved to 0");
        TEST_ASSERT_EQ(rs_count(&cdb,
            "SELECT (SELECT COUNT(*) FROM channels WHERE id = 1)"
            " + (SELECT COUNT(*) FROM channel_basepoints WHERE channel_id = 1)"
            " + (SELECT COUNT(*) FROM revocation_secrets WHERE channel_id = 1)"
            " + (SELECT COUNT(*) FROM remote_pcps WHERE channel_id = 1);"),
            0, "nothing left under the index");
    }

    /* An LSP DB (channels 0..3) is not touched. */
    TEST_ASSERT(persist_client_move_to_channel_0(&fx.db), "LSP DB");
    TEST_ASSERT_EQ(rs_count(&fx.db, "SELECT COUNT(*) FROM channels;"), 4,
                   "LSP channels kept");
    TEST_ASSERT_EQ(rs_count(&fx.db, "SELECT COUNT(*) FROM channel_basepoints "
                            "WHERE channel_id BETWEEN 1 AND 3;"), 3,
                   "LSP basepoints kept under their ids");

    persist_close(&cdb);
    rs_teardown(&fx);
    return 1;
}

/* ---- A client restarted before its first payment ---- */

#define RS_LSP_PCS0 0x41  /* every byte of the LSP's per-commitment secret 0 */

typedef struct {
    int called;
    int forged_ok;
    int valid_ok;
} rs_first_cb_t;

/* After the restart: the first payment moves the client to commitment 1
   (as its COMMITMENT_SIGNED handler does), then the LSP revokes commitment
   0.  A forged REVOKE_AND_ACK, then the real one, go through the client's
   own handler. */
static int rs_first_payment_cb(int fd, channel_t *ch, uint32_t my_index,
                               secp256k1_context *ctx,
                               const secp256k1_keypair *kp, factory_t *f,
                               size_t n_participants, void *ud) {
    (void)fd; (void)my_index; (void)kp; (void)f; (void)n_participants;
    rs_first_cb_t *c = ud;
    c->called = 1;
    ch->commitment_number = 1;
    unsigned char forged[32], real[32], nxt[32];
    memset(forged, 0x3c, sizeof(forged));
    memset(real, RS_LSP_PCS0, sizeof(real));
    memset(nxt, 0x43, sizeof(nxt));
    secp256k1_pubkey next_pcp;
    if (!secp256k1_ec_pubkey_create(ctx, &next_pcp, nxt)) return 2;
    const unsigned char *secrets[2] = { forged, real };
    int *results[2] = { &c->forged_ok, &c->valid_ok };
    for (int i = 0; i < 2; i++) {
        cJSON *j = wire_build_revoke_and_ack(RS_CLIENT_IDX, secrets[i], ctx,
                                             &next_pcp);
        if (!j) return 2;
        wire_msg_t m = { .msg_type = MSG_LSP_REVOKE_AND_ACK, .json = j };
        *results[i] = client_handle_lsp_revoke_and_ack(ch, ctx, &m);
        cJSON_Delete(j);
    }
    return 2;
}

/* The LSP's points for commitments 0 and 1 reach the client before its DB
   is attached, and the first run saved only the client's own secrets: a
   client restarted before its first payment had no point to check the
   LSP's first revocation against, refused it as invalid, and its forgery
   policy then halted or closed the channel.  Save the first run's state
   the way the daemon does, restart (reconnect at commitment 0), take the
   first payment's commitment, and receive the LSP's revocation of
   commitment 0: a forged secret is refused, the real one is accepted and
   stored. */
int test_restart_client_first_points_saved(void) {
    rs_fixture_t fx;
    TEST_ASSERT(rs_setup(&fx, 4), "fixture");
    persist_t cdb;
    TEST_ASSERT(persist_open(&cdb, NULL), "client db");
    secp256k1_keypair kp;
    channel_t cch;
    TEST_ASSERT(rs_client_channel(&fx, &kp, &cch), "client channel");

    /* The LSP's first two points, as its basepoints message brings them. */
    unsigned char s[32];
    secp256k1_pubkey pcp0, pcp1;
    memset(s, RS_LSP_PCS0, sizeof(s));
    TEST_ASSERT(secp256k1_ec_pubkey_create(fx.ctx, &pcp0, s), "PCP 0");
    memset(s, RS_LSP_PCS0 + 1, sizeof(s));
    TEST_ASSERT(secp256k1_ec_pubkey_create(fx.ctx, &pcp1, s), "PCP 1");
    channel_set_remote_pcp(&cch, 0, &pcp0);
    channel_set_remote_pcp(&cch, 1, &pcp1);

    /* The daemon's first-run save. */
    TEST_ASSERT(persist_begin(&cdb), "begin");
    TEST_ASSERT(client_persist_initial_state(&cdb, fx.f, &cch, fx.ctx),
                "first-run save");
    TEST_ASSERT(persist_commit(&cdb), "commit");
    channel_cleanup(&cch);

    /* Restart before any payment: reconnect at commitment 0. */
    rs_first_cb_t cb = { 0, 0, 0 };
    int lsp_ok = 0;
    int ok = rs_run_reconnect(&fx, &cdb, &kp, 0, rs_first_payment_cb, &cb, &lsp_ok);
    TEST_ASSERT(lsp_ok, "fake LSP ran the whole reconnect");
    TEST_ASSERT(ok && cb.called, "reconnected");
    TEST_ASSERT(!cb.forged_ok, "forged revocation of commitment 0 refused");
    TEST_ASSERT(cb.valid_ok, "the LSP's real revocation of commitment 0 accepted");

    unsigned char secrets[4][32], want[32];
    uint8_t valid[4];
    size_t n_rev = 0;
    memset(want, RS_LSP_PCS0, sizeof(want));
    TEST_ASSERT(persist_load_revocations_flat(&cdb, CLIENT_DB_CHANNEL_ID, secrets,
                                              valid, 4, &n_rev) &&
                valid[0] && memcmp(secrets[0], want, 32) == 0,
                "the real secret is stored");
    unsigned char ser[33];
    TEST_ASSERT(persist_load_remote_pcp(&cdb, CLIENT_DB_CHANNEL_ID, 0, ser) &&
                persist_load_remote_pcp(&cdb, CLIENT_DB_CHANNEL_ID, 1, ser),
                "the first run saved PCP 0 and 1");

    persist_close(&cdb);
    rs_teardown(&fx);
    return 1;
}
