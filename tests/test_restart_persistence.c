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
    secp256k1_keypair kps[5];
    for (int i = 0; i < 5; i++)
        if (!secp256k1_keypair_create(ctx, &kps[i], rs_seckeys[i])) return 0;
    factory_init(f, ctx, kps, 5, 10, 4);  /* allocates the arrays */
    if (arity != FACTORY_ARITY_2) factory_set_arity(f, arity);
    f->cltv_timeout = 200;
    f->use_tree_anchor = 1;  /* as every factory is rebuilt on reload */

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
    if (!factory_build_tree(f) || !factory_sign_all(f)) return 0;
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
    if (!persist_save_factory(&fx->db, fx->f, fx->ctx, 0) ||
        !persist_save_tree_nodes(&fx->db, fx->f, 0)) return 0;
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

