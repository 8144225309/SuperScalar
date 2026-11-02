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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

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
    unsigned char zero_secret[32] = {0}, txid[32], spk[34];
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
    if (!lsp->client_fds || !lsp->client_pubkeys) return NULL;
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

