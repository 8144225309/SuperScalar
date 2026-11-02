/*
 * test_regtest_funding_reval.c — R5 funding revalidation for factory channels.
 *
 * Unit:
 *   test_reorg_funding_recheck_due          per-block re-check decision
 *   test_reorg_funding_freeze_reloaded_on_restart
 *                                           a persisted freeze is loaded by
 *                                           lsp_channels_init_from_db and
 *                                           makes the re-check due
 * Regtest:
 *   test_regtest_reorg_revalidate_factory_funding
 *     5-party arity-2 factory funded on regtest; lsp_channels_revalidate_
 *     funding() checked through: a shallow tip reorg, the funding block
 *     invalidated (funding TX back in the mempool), the funding TX
 *     double-spent, reconsiderblock, and a restart with persisted freezes.
 *     Revalidation runs through a wallet that does not own the funding TX,
 *     so lookups go through getrawtransaction / -txindex as on an LSP whose
 *     node wallet did not build the TX.
 */

#include "superscalar/lsp_channels.h"
#include "superscalar/factory.h"
#include "superscalar/persist.h"
#include "superscalar/regtest.h"
#include "superscalar/sha256.h"
#include "superscalar/musig.h"
#include "superscalar/tx_builder.h"
#include "superscalar/watchtower.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define TEST_ASSERT_GOTO(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        goto done; \
    } \
} while(0)

static int count_frozen(const lsp_channel_mgr_t *mgr) {
    int n = 0;
    for (size_t c = 0; c < mgr->n_channels; c++)
        if (mgr->entries[c].channel.funding_pending_reorg) n++;
    return n;
}

static int count_frozen_db(persist_t *db, size_t n) {
    int frozen = 0;
    for (size_t c = 0; c < n; c++) {
        int f = 0;
        if (!persist_load_channel_funding_reorg(db, (uint32_t)c, &f)) return -1;
        frozen += f;
    }
    return frozen;
}

/* Remote basepoints so the channels can be saved and reloaded from the DB. */
static int set_remote_basepoints(secp256k1_context *ctx, lsp_channel_mgr_t *mgr) {
    for (size_t c = 0; c < mgr->n_channels; c++) {
        channel_t *ch = &mgr->entries[c].channel;
        secp256k1_pubkey rpay, rdelay, rrevoc, rhtlc;
        unsigned char rs[32];
        memset(rs, 0x60 + (unsigned char)c, 32);
        if (!secp256k1_ec_pubkey_create(ctx, &rpay, rs)) return 0;
        rs[0]++;
        if (!secp256k1_ec_pubkey_create(ctx, &rdelay, rs)) return 0;
        rs[0]++;
        if (!secp256k1_ec_pubkey_create(ctx, &rrevoc, rs)) return 0;
        rs[0]++;
        if (!secp256k1_ec_pubkey_create(ctx, &rhtlc, rs)) return 0;
        channel_set_remote_basepoints(ch, &rpay, &rdelay, &rrevoc);
        channel_set_remote_htlc_basepoint(ch, &rhtlc);
    }
    return 1;
}

static int save_channels(persist_t *db, const lsp_channel_mgr_t *mgr) {
    for (size_t c = 0; c < mgr->n_channels; c++) {
        if (!persist_save_channel(db, &mgr->entries[c].channel, 0, (uint32_t)c))
            return 0;
        if (!persist_save_basepoints(db, (uint32_t)c, &mgr->entries[c].channel))
            return 0;
    }
    return 1;
}

/* LSP + 4 clients and the key-path P2TR of their 5-party MuSig2 key. */
static int make_keys(secp256k1_context *ctx, unsigned char sk[5][32],
                     secp256k1_pubkey pks[5], unsigned char fund_spk[34],
                     unsigned char tweaked_xonly32[32]) {
    for (int i = 0; i < 5; i++) {
        memset(sk[i], 0x51 + i, 32);
        if (!secp256k1_ec_pubkey_create(ctx, &pks[i], sk[i])) return 0;
    }
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks, 5)) return 0;
    unsigned char ser[32], tw[32];
    secp256k1_xonly_pubkey_serialize(ctx, ser, &ka.agg_pubkey);
    sha256_tagged("TapTweak", ser, 32, tw);
    secp256k1_pubkey tpk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tpk, &ka.cache, tw)) return 0;
    secp256k1_xonly_pubkey txo;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &txo, NULL, &tpk);
    build_p2tr_script_pubkey(fund_spk, &txo);
    secp256k1_xonly_pubkey_serialize(ctx, tweaked_xonly32, &txo);
    return 1;
}

static int build_factory(secp256k1_context *ctx, factory_t *f,
                         secp256k1_pubkey pks[5], const unsigned char txid[32],
                         uint32_t vout, uint64_t amt,
                         const unsigned char fund_spk[34], uint32_t cltv) {
    factory_alloc_default_arrays(f);
    factory_init_from_pubkeys(f, ctx, pks, 5, 10, 4);
    f->cltv_timeout = cltv;
    f->fee_per_tx = 500;
    factory_set_funding(f, txid, vout, amt, fund_spk, 34);
    return factory_build_tree(f);
}

/* ---- unit ---------------------------------------------------------------- */

int test_reorg_funding_recheck_due(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    TEST_ASSERT(lsp_channels_funding_recheck_due(NULL) == 0, "NULL mgr");
    TEST_ASSERT(lsp_channels_funding_recheck_due(&mgr) == 0, "no channels");
    mgr.entries = calloc(4, sizeof(lsp_channel_entry_t));
    TEST_ASSERT(mgr.entries, "alloc");
    mgr.n_channels = 4;
    int ok = 1;
    if (lsp_channels_funding_recheck_due(&mgr) != 0) ok = 0;
    /* A reorg left the funding TX unconfirmed: nothing frozen yet, but the
       next block must re-check it. */
    mgr.funding_anchor_unconfirmed = 1;
    if (lsp_channels_funding_recheck_due(&mgr) != 1) ok = 0;
    mgr.funding_anchor_unconfirmed = 0;
    mgr.entries[2].channel.funding_pending_reorg = 1;
    if (lsp_channels_funding_recheck_due(&mgr) != 1) ok = 0;
    mgr.entries[2].channel.funding_pending_reorg = 0;
    if (lsp_channels_funding_recheck_due(&mgr) != 0) ok = 0;
    free(mgr.entries);
    TEST_ASSERT(ok, "re-check due iff a channel is frozen or funding unconfirmed");
    return 1;
}

int test_reorg_funding_freeze_reloaded_on_restart(void) {
    int rc = 0;
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    factory_t *f = calloc(1, sizeof(factory_t));
    lsp_channel_mgr_t mgr, rec;
    memset(&mgr, 0, sizeof(mgr));
    memset(&rec, 0, sizeof(rec));
    int mgr_ok = 0, rec_ok = 0, db_ok = 0;
    persist_t db;
    unsigned char sk[5][32], spk[34], xo[32], txid[32];
    secp256k1_pubkey pks[5];

    TEST_ASSERT_GOTO(f, "alloc factory");
    TEST_ASSERT_GOTO(make_keys(ctx, sk, pks, spk, xo), "keys");
    memset(txid, 0xAB, 32);
    TEST_ASSERT_GOTO(build_factory(ctx, f, pks, txid, 0, 200000, spk, 500),
                     "build factory");
    TEST_ASSERT_GOTO(persist_open(&db, NULL), "open db");
    db_ok = 1;
    mgr.persist = &db;
    TEST_ASSERT_GOTO(lsp_channels_init(&mgr, ctx, f, sk[0], 4), "init");
    mgr_ok = 1;
    TEST_ASSERT_GOTO(set_remote_basepoints(ctx, &mgr), "basepoints");
    TEST_ASSERT_GOTO(save_channels(&db, &mgr), "save channels");

    /* Channels 1 and 3 were frozen when the LSP stopped. */
    TEST_ASSERT_GOTO(persist_update_channel_funding_reorg(&db, 1, 1) &&
                     persist_update_channel_funding_reorg(&db, 3, 1),
                     "persist freeze");

    rec.persist = &db;
    TEST_ASSERT_GOTO(lsp_channels_init_from_db(&rec, ctx, f, sk[0], 4, &db),
                     "init from db");
    rec_ok = 1;
    printf("\n    reloaded flags: %d %d %d %d, recheck due=%d\n   ",
           rec.entries[0].channel.funding_pending_reorg,
           rec.entries[1].channel.funding_pending_reorg,
           rec.entries[2].channel.funding_pending_reorg,
           rec.entries[3].channel.funding_pending_reorg,
           lsp_channels_funding_recheck_due(&rec));
    TEST_ASSERT_GOTO(!rec.entries[0].channel.funding_pending_reorg &&
                     rec.entries[1].channel.funding_pending_reorg &&
                     !rec.entries[2].channel.funding_pending_reorg &&
                     rec.entries[3].channel.funding_pending_reorg,
                     "persisted freezes reloaded");
    TEST_ASSERT_GOTO(lsp_channels_funding_recheck_due(&rec) == 1,
                     "daemon loop re-checks on its first block");
    {
        unsigned char ph[32];
        memset(ph, 0x77, 32);
        uint64_t id = 0;
        TEST_ASSERT_GOTO(!channel_add_htlc(&rec.entries[1].channel, HTLC_OFFERED,
                                           1000, ph, 600, &id),
                         "frozen channel refuses HTLCs until re-checked");
    }
    rc = 1;
done:
    if (rec_ok) lsp_channels_cleanup(&rec);
    if (mgr_ok) lsp_channels_cleanup(&mgr);
    if (db_ok) persist_close(&db);
    if (f) { factory_free(f); free(f); }
    secp256k1_context_destroy(ctx);
    return rc;
}

/* ---- regtest ------------------------------------------------------------- */

static int rpc_ok(regtest_t *rt, const char *method, const char *params) {
    char *r = regtest_exec(rt, method, params);
    if (!r) return 0;
    free(r);
    return 1;
}

static void print_frozen(const char *label, const lsp_channel_mgr_t *mgr,
                         int changed) {
    printf("\n    %s: changed=%d frozen=%d/%zu recheck_due=%d",
           label, changed, count_frozen(mgr), mgr->n_channels,
           lsp_channels_funding_recheck_due(mgr));
}

int test_regtest_reorg_revalidate_factory_funding(void) {
    int rc = 0;
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lsp_t *lsp = NULL;
    lsp_channel_mgr_t mgr, rec;
    int mgr_ok = 0, rec_ok = 0, db_ok = 0;
    persist_t db;
    memset(&mgr, 0, sizeof(mgr));
    memset(&rec, 0, sizeof(rec));

    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 2;
    }
    regtest_create_wallet(&rt, "reorg_reval");
    /* The LSP side looks the funding TX up through a wallet that did not
       create it. */
    regtest_t obs = rt;
    regtest_create_wallet(&obs, "reorg_reval_obs");

    char mine_addr[128], other_addr[128];
    TEST_ASSERT_GOTO(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)),
                     "mine address");
    TEST_ASSERT_GOTO(regtest_get_new_address(&rt, other_addr, sizeof(other_addr)),
                     "second address");
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    regtest_mine_blocks(&rt, 1, mine_addr);

    unsigned char sk[5][32], fund_spk[34], tser[32];
    secp256k1_pubkey pks[5];
    TEST_ASSERT_GOTO(make_keys(ctx, sk, pks, fund_spk, tser), "keys");
    char faddr[128];
    TEST_ASSERT_GOTO(regtest_derive_p2tr_address(&rt, tser, faddr, sizeof(faddr)),
                     "factory address");

    char fund_txid[65];
    TEST_ASSERT_GOTO(regtest_fund_address(&rt, faddr, 0.002, fund_txid),
                     "fund factory");
    TEST_ASSERT_GOTO(regtest_mine_blocks(&rt, 1, mine_addr), "mine funding");
    int fund_height = regtest_get_block_height(&rt);
    char fund_block[65] = {0};
    TEST_ASSERT_GOTO(regtest_get_block_hash(&rt, fund_height, fund_block,
                                            sizeof(fund_block)),
                     "funding block hash");
    TEST_ASSERT_GOTO(regtest_get_confirmations(&obs, fund_txid) == 1,
                     "funding confirmed (seen via txindex)");

    int vout = -1; uint64_t amt = 0;
    for (int v = 0; v < 4; v++) {
        unsigned char sc[64]; size_t sl = 0; uint64_t a = 0;
        if (regtest_get_tx_output(&rt, fund_txid, (uint32_t)v, &a, sc, &sl) &&
            sl == 34 && memcmp(sc, fund_spk, 34) == 0) { vout = v; amt = a; break; }
    }
    TEST_ASSERT_GOTO(vout >= 0, "factory funding output found");
    unsigned char txid_b[32];
    hex_decode(fund_txid, txid_b, 32);
    reverse_bytes(txid_b, 32);

    lsp = calloc(1, sizeof(lsp_t));
    TEST_ASSERT_GOTO(lsp, "alloc lsp");
    factory_t *f = &lsp->factory;
    TEST_ASSERT_GOTO(build_factory(ctx, f, pks, txid_b, (uint32_t)vout, amt,
                                   fund_spk, (uint32_t)fund_height + 500),
                     "build factory tree");

    TEST_ASSERT_GOTO(persist_open(&db, NULL), "open in-memory db");
    db_ok = 1;
    mgr.persist = &db;
    TEST_ASSERT_GOTO(lsp_channels_init(&mgr, ctx, f, sk[0], 4), "init channels");
    mgr_ok = 1;
    TEST_ASSERT_GOTO(set_remote_basepoints(ctx, &mgr), "basepoints");
    TEST_ASSERT_GOTO(save_channels(&db, &mgr), "persist channels");

    /* Every channel's funding_txid is a leaf state TX, and that TX is not
       on chain. */
    for (size_t c = 0; c < mgr.n_channels; c++)
        TEST_ASSERT_GOTO(memcmp(mgr.entries[c].channel.funding_txid,
                                f->funding_txid, 32) != 0,
                         "channel funding_txid is the leaf TX");
    {
        unsigned char d[32]; char leaf_hex[65];
        memcpy(d, mgr.entries[0].channel.funding_txid, 32);
        reverse_bytes(d, 32);
        hex_encode(d, 32, leaf_hex);
        leaf_hex[64] = '\0';
        TEST_ASSERT_GOTO(regtest_get_confirmations(&obs, leaf_hex) < 0,
                         "leaf TX is off-chain");
    }

    watchtower_t wt;
    memset(&wt, 0, sizeof(wt));
    wt.rt = &obs;
    mgr.watchtower = &wt;

    TEST_ASSERT_GOTO(regtest_mine_blocks(&rt, 5, mine_addr), "bury funding");
    TEST_ASSERT_GOTO(regtest_get_confirmations(&obs, fund_txid) == 6,
                     "funding has 6 confirmations");

    /* (a) 1-block tip reorg, funding buried. */
    {
        int h_before = regtest_get_block_height(&rt);
        char tip_before[65], tip_after[65], p[96];
        TEST_ASSERT_GOTO(regtest_get_best_block_hash(&rt, tip_before), "tip");
        snprintf(p, sizeof(p), "\"%s\"", tip_before);
        TEST_ASSERT_GOTO(rpc_ok(&rt, "invalidateblock", p), "invalidate tip");
        TEST_ASSERT_GOTO(regtest_mine_blocks(&rt, 1, other_addr),
                         "mine competing tip");
        TEST_ASSERT_GOTO(regtest_get_best_block_hash(&rt, tip_after), "tip'");
        TEST_ASSERT_GOTO(regtest_get_block_height(&rt) == h_before &&
                         strcmp(tip_before, tip_after) != 0,
                         "same-height tip replacement happened");
        int changed = lsp_channels_revalidate_funding(&mgr, lsp);
        print_frozen("(a) 1-block tip reorg, funding buried", &mgr, changed);
        TEST_ASSERT_GOTO(count_frozen(&mgr) == 0, "(a) nothing frozen");
        TEST_ASSERT_GOTO(lsp_channels_funding_recheck_due(&mgr) == 0,
                         "(a) no re-check needed");
    }

    /* (b) Funding block invalidated: funding TX back in the mempool. */
    {
        char p[96];
        snprintf(p, sizeof(p), "\"%s\"", fund_block);
        TEST_ASSERT_GOTO(rpc_ok(&rt, "invalidateblock", p),
                         "invalidate funding block");
        TEST_ASSERT_GOTO(regtest_get_block_height(&rt) == fund_height - 1,
                         "tip below the funding block");
        TEST_ASSERT_GOTO(regtest_is_in_mempool(&rt, fund_txid),
                         "funding TX back in the mempool");
        int changed = lsp_channels_revalidate_funding(&mgr, lsp);
        print_frozen("(b) funding unconfirmed, in mempool", &mgr, changed);
        TEST_ASSERT_GOTO(count_frozen(&mgr) == 0,
                         "(b) not frozen yet (pending in the mempool)");
        TEST_ASSERT_GOTO(lsp_channels_funding_recheck_due(&mgr) == 1,
                         "(b) re-checked on the next block");
    }

    /* (b2) Funding TX double-spent and the replacement mined; the
       per-block re-check freezes. */
    {
        char p[96];
        snprintf(p, sizeof(p), "\"%s\"", fund_txid);
        char *bump = regtest_exec(&rt, "bumpfee", p);
        TEST_ASSERT_GOTO(bump && strstr(bump, "txid"),
                         "bumpfee replaced the funding TX");
        free(bump);
        TEST_ASSERT_GOTO(regtest_mine_blocks(&rt, 1, other_addr),
                         "mine the replacement");
        int fconf = regtest_get_confirmations(&obs, fund_txid);
        printf("\n    (b2) funding TX after double-spend: confirmations=%d "
               "in_mempool=%d", fconf, (int)regtest_is_in_mempool(&obs, fund_txid));
        TEST_ASSERT_GOTO(fconf < 1 && !regtest_is_in_mempool(&obs, fund_txid),
                         "funding TX neither confirmed nor in the mempool");
        TEST_ASSERT_GOTO(lsp_channels_funding_recheck_due(&mgr) == 1,
                         "(b2) re-check due on this block");
        int changed = lsp_channels_revalidate_funding(&mgr, lsp);
        print_frozen("(b2) per-block re-check after double-spend", &mgr, changed);
        TEST_ASSERT_GOTO(changed == (int)mgr.n_channels &&
                         count_frozen(&mgr) == (int)mgr.n_channels,
                         "(b2) every channel frozen");
        TEST_ASSERT_GOTO(count_frozen_db(&db, mgr.n_channels) ==
                         (int)mgr.n_channels, "(b2) freeze persisted");
        TEST_ASSERT_GOTO(lsp_channels_revalidate_funding(&mgr, lsp) == 0,
                         "(b2) second pass is a no-op");
    }

    /* (c) Original chain restored. */
    {
        char p[96];
        snprintf(p, sizeof(p), "\"%s\"", fund_block);
        TEST_ASSERT_GOTO(rpc_ok(&rt, "reconsiderblock", p),
                         "reconsider funding block");
        int fconf = regtest_get_confirmations(&obs, fund_txid);
        printf("\n    (c) funding TX after reconsiderblock: confirmations=%d", fconf);
        TEST_ASSERT_GOTO(fconf >= 1, "funding TX back on chain");
        int changed = lsp_channels_revalidate_funding(&mgr, lsp);
        print_frozen("(c) funding back on chain", &mgr, changed);
        TEST_ASSERT_GOTO(changed == (int)mgr.n_channels &&
                         count_frozen(&mgr) == 0, "(c) every channel unfrozen");
        TEST_ASSERT_GOTO(count_frozen_db(&db, mgr.n_channels) == 0,
                         "(c) unfreeze persisted");
        TEST_ASSERT_GOTO(lsp_channels_funding_recheck_due(&mgr) == 0,
                         "(c) no further re-checks");
    }

    /* (d) Restart with freezes persisted (e.g. stopped mid-reorg, or rows
       left by the previous revalidation): reloaded frozen, and the first
       re-check clears them because the funding TX is confirmed. */
    {
        for (size_t c = 0; c < mgr.n_channels; c++)
            TEST_ASSERT_GOTO(persist_update_channel_funding_reorg(&db, (uint32_t)c, 1),
                             "persist freeze");
        rec.persist = &db;
        TEST_ASSERT_GOTO(lsp_channels_init_from_db(&rec, ctx, f, sk[0], 4, &db),
                         "init from db");
        rec_ok = 1;
        rec.watchtower = &wt;
        printf("\n    (d) after restart: frozen=%d/%zu recheck_due=%d",
               count_frozen(&rec), rec.n_channels,
               lsp_channels_funding_recheck_due(&rec));
        TEST_ASSERT_GOTO(count_frozen(&rec) == (int)rec.n_channels,
                         "(d) freezes reloaded");
        TEST_ASSERT_GOTO(lsp_channels_funding_recheck_due(&rec) == 1,
                         "(d) re-check due on the first block");
        int changed = lsp_channels_revalidate_funding(&rec, lsp);
        print_frozen("(d) first re-check after restart", &rec, changed);
        TEST_ASSERT_GOTO(count_frozen(&rec) == 0, "(d) cleared");
        TEST_ASSERT_GOTO(count_frozen_db(&db, rec.n_channels) == 0,
                         "(d) cleared in the DB");
    }
    printf("\n   ");
    rc = 1;

done:
    if (rec_ok) { rec.watchtower = NULL; lsp_channels_cleanup(&rec); }
    if (mgr_ok) { mgr.watchtower = NULL; lsp_channels_cleanup(&mgr); }
    if (db_ok) persist_close(&db);
    if (lsp) { factory_free(&lsp->factory); free(lsp); }
    secp256k1_context_destroy(ctx);
    return rc;
}
