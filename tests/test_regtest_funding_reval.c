/*
 * test_regtest_funding_reval.c — R5 funding revalidation for factory channels.
 *
 * Unit:
 *   test_reorg_funding_recheck_due          per-block re-check decision
 *   test_reorg_funding_freeze_reloaded_on_restart
 *                                           a persisted freeze is loaded by
 *                                           lsp_channels_init_from_db and
 *                                           makes the re-check due
 *   test_reorg_revalidate_rpc_outage_no_change
 *                                           bitcoind unreachable during
 *                                           revalidation: nothing changes
 *   test_persist_funding_anchor_reorg_tip   v40 tables round trip
 * Regtest:
 *   test_regtest_reorg_revalidate_factory_funding
 *     5-party arity-2 factory funded on regtest; lsp_channels_revalidate_
 *     funding() checked through: a shallow tip reorg, the funding block
 *     invalidated (funding TX back in the mempool), the funding TX
 *     double-spent, reconsiderblock, and a restart with persisted freezes.
 *     Revalidation runs through a wallet that does not own the funding TX,
 *     so lookups go through getrawtransaction / -txindex as on an LSP whose
 *     node wallet did not build the TX.
 *   test_regtest_reorg_revalidate_deep_funding
 *     The funding TX buried deeper than the lookup scan depth, on a node
 *     without -txindex (run it in such a sandbox; it also passes with
 *     -txindex): stays CONFIRMED, also after a shallow reorg, after the
 *     funding output is spent, and after a restart (anchor from the DB).
 *   test_regtest_reorg_revalidate_anchor_race
 *     A reorg that drops the funding TX lands between the gettxout read and
 *     the block-hash lookup of the anchor recording: no anchor is recorded
 *     (in memory or the DB), so the funding later reads as gone (-txindex)
 *     or unknown (no -txindex) instead of confirmed.
 *   test_regtest_reorg_revalidate_spent_funding_reorged_out
 *     The recorded-anchor path when the funding output is spent: anchor
 *     recorded, output spent, anchor block invalidated, funding TX
 *     double-spent with its spend in the mempool: every channel freezes.
 *   test_regtest_reorg_revalidate_conflicted_funding_no_anchor
 *     A wallet funding TX that never confirmed is double-spent: the wallet
 *     reports it conflicted, which freezes the channels even though no
 *     anchor was ever recorded.
 */

#include "superscalar/lsp_channels.h"
#include "superscalar/factory.h"
#include "superscalar/persist.h"
#include "superscalar/regtest.h"
#include "superscalar/sha256.h"
#include "superscalar/musig.h"
#include "superscalar/tx_builder.h"
#include "superscalar/watchtower.h"
#include "cJSON.h"
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

/* A chain handle that cannot reach any node: nothing listens on port 1
   and the bitcoin-cli fallback path does not exist. */
static void unreachable_rt(regtest_t *rt) {
    memset(rt, 0, sizeof(*rt));
    snprintf(rt->cli_path, sizeof(rt->cli_path), "/nonexistent/ss-test-bitcoin-cli");
    snprintf(rt->rpcuser, sizeof(rt->rpcuser), "rpcuser");
    snprintf(rt->rpcpassword, sizeof(rt->rpcpassword), "rpcpass");
    snprintf(rt->network, sizeof(rt->network), "regtest");
    rt->rpcport = 1;
    rt->scan_depth = 10;
}

int test_reorg_revalidate_rpc_outage_no_change(void) {
    int rc = 0;
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    int mgr_ok = 0;
    unsigned char sk[5][32], spk[34], xo[32], txid[32];
    secp256k1_pubkey pks[5];
    regtest_t dead;
    watchtower_t wt;

    TEST_ASSERT_GOTO(lsp, "alloc lsp");
    TEST_ASSERT_GOTO(make_keys(ctx, sk, pks, spk, xo), "keys");
    memset(txid, 0xCD, 32);
    TEST_ASSERT_GOTO(build_factory(ctx, &lsp->factory, pks, txid, 0, 200000,
                                   spk, 500), "build factory");
    TEST_ASSERT_GOTO(lsp_channels_init(&mgr, ctx, &lsp->factory, sk[0], 4),
                     "init");
    mgr_ok = 1;
    unreachable_rt(&dead);
    memset(&wt, 0, sizeof(wt));
    wt.rt = &dead;
    mgr.watchtower = &wt;

    /* Live channels: an outage must not freeze them. */
    int changed = lsp_channels_revalidate_funding(&mgr, lsp);
    printf("\n    outage, live channels: changed=%d frozen=%d/4", changed,
           count_frozen(&mgr));
    TEST_ASSERT_GOTO(changed == 0 && count_frozen(&mgr) == 0,
                     "outage does not freeze live channels");
    TEST_ASSERT_GOTO(mgr.funding_anchor_unconfirmed == 0,
                     "outage does not mark the funding unconfirmed");

    /* Frozen channel and a pending re-check: both stay as they are. */
    mgr.entries[1].channel.funding_pending_reorg = 1;
    mgr.funding_anchor_unconfirmed = 1;
    changed = lsp_channels_revalidate_funding(&mgr, lsp);
    printf("\n    outage, channel 1 frozen: changed=%d frozen=%d/4 "
           "recheck_due=%d", changed, count_frozen(&mgr),
           lsp_channels_funding_recheck_due(&mgr));
    TEST_ASSERT_GOTO(changed == 0 && count_frozen(&mgr) == 1 &&
                     mgr.entries[1].channel.funding_pending_reorg,
                     "outage leaves the freeze in place");
    TEST_ASSERT_GOTO(mgr.funding_anchor_unconfirmed == 1,
                     "outage leaves the pending re-check in place");

    int conf = regtest_get_confirmations(&dead,
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
    printf("\n    regtest_get_confirmations while unreachable: %d\n   ", conf);
    TEST_ASSERT_GOTO(conf == REGTEST_CONF_RPC_ERROR,
                     "unreachable node reported as RPC error, not not-found");
    rc = 1;
done:
    if (mgr_ok) { mgr.watchtower = NULL; lsp_channels_cleanup(&mgr); }
    if (lsp) { factory_free(&lsp->factory); free(lsp); }
    secp256k1_context_destroy(ctx);
    return rc;
}

int test_persist_funding_anchor_reorg_tip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open db");
    const char *txid = "11111111111111111111111111111111"
                       "11111111111111111111111111111111";
    const char *b1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const char *b2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    int32_t h = 0;
    char hash[65] = {0};
    int ok = 1;
    if (persist_load_funding_anchor(&db, txid, &h, hash)) ok = 0;
    if (!persist_save_funding_anchor(&db, txid, 120, b1)) ok = 0;
    if (!persist_load_funding_anchor(&db, txid, &h, hash) || h != 120 ||
        strcmp(hash, b1) != 0) ok = 0;
    if (!persist_save_funding_anchor(&db, txid, 121, b2)) ok = 0;   /* replace */
    if (!persist_load_funding_anchor(&db, txid, &h, hash) || h != 121 ||
        strcmp(hash, b2) != 0) ok = 0;
    if (persist_save_funding_anchor(&db, txid, 1, "short")) ok = 0;  /* rejected */
    if (persist_load_reorg_tip(&db, "daemon", &h, hash)) ok = 0;
    if (!persist_save_reorg_tip(&db, "daemon", 3000, b1)) ok = 0;
    if (!persist_load_reorg_tip(&db, "daemon", &h, hash) || h != 3000 ||
        strcmp(hash, b1) != 0) ok = 0;
    if (persist_load_reorg_tip(&db, "heartbeat", &h, hash)) ok = 0;
    persist_close(&db);
    TEST_ASSERT(ok, "funding_anchors / reorg_tips save, replace, load");
    return 1;
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

/* Key-path spend of the factory funding output with all five keys (what a
   cooperative close does to it).  Returns 1 and the txid on success. */
static int spend_funding(regtest_t *rt, secp256k1_context *ctx,
                         unsigned char sk[5][32], secp256k1_pubkey pks[5],
                         const unsigned char fund_txid_internal[32],
                         uint32_t vout, uint64_t amt,
                         const unsigned char fund_spk[34], char *txid_out) {
    secp256k1_keypair kps[5];
    for (int i = 0; i < 5; i++)
        if (!secp256k1_keypair_create(ctx, &kps[i], sk[i])) return 0;
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks, 5)) return 0;
    tx_output_t out;
    memset(&out, 0, sizeof(out));
    out.amount_sats = amt - 1000;
    memcpy(out.script_pubkey, fund_spk, 34);   /* any P2TR will do */
    out.script_pubkey_len = 34;
    tx_buf_t utx, stx;
    tx_buf_init(&utx, 256);
    tx_buf_init(&stx, 512);
    int ok = 0;
    unsigned char sighash[32], sig[64];
    musig_keyagg_t sign_ka = ka;
    if (build_unsigned_tx(&utx, NULL, fund_txid_internal, vout, 0xFFFFFFFD, &out, 1) &&
        compute_taproot_sighash(sighash, utx.data, utx.len, 0, fund_spk, 34, amt,
                                0xFFFFFFFD) &&
        musig_sign_taproot(ctx, sig, sighash, kps, 5, &sign_ka, NULL) &&
        finalize_signed_tx(&stx, utx.data, utx.len, sig)) {
        char *hex = malloc(stx.len * 2 + 1);
        if (hex) {
            hex_encode(stx.data, stx.len, hex);
            ok = regtest_send_raw_tx(rt, hex, txid_out);
            free(hex);
        }
    }
    tx_buf_free(&utx);
    tx_buf_free(&stx);
    return ok;
}

int test_regtest_reorg_revalidate_deep_funding(void) {
    int rc = 0;
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lsp_t *lsp = NULL;
    lsp_channel_mgr_t mgr, mgr2, mgr3;
    int mgr_ok = 0, mgr2_ok = 0, mgr3_ok = 0, db_ok = 0;
    persist_t db;
    memset(&mgr, 0, sizeof(mgr));
    memset(&mgr2, 0, sizeof(mgr2));
    memset(&mgr3, 0, sizeof(mgr3));
    char invalidated[65] = {0};

    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 2;
    }
    regtest_create_wallet(&rt, "deep_fund");
    regtest_t obs = rt;
    regtest_create_wallet(&obs, "deep_fund_obs");
    int txindex = 0;
    {
        char *ii = regtest_exec(&rt, "getindexinfo", "");
        txindex = ii && strstr(ii, "txindex") != NULL;
        free(ii);
    }

    char mine_addr[128], other_addr[128];
    TEST_ASSERT_GOTO(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)), "addr");
    TEST_ASSERT_GOTO(regtest_get_new_address(&rt, other_addr, sizeof(other_addr)), "addr2");
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    regtest_mine_blocks(&rt, 1, mine_addr);

    unsigned char sk[5][32], fund_spk[34], tser[32];
    secp256k1_pubkey pks[5];
    TEST_ASSERT_GOTO(make_keys(ctx, sk, pks, fund_spk, tser), "keys");
    char faddr[128], fund_txid[65];
    TEST_ASSERT_GOTO(regtest_derive_p2tr_address(&rt, tser, faddr, sizeof(faddr)),
                     "factory address");
    TEST_ASSERT_GOTO(regtest_fund_address(&rt, faddr, 0.002, fund_txid), "fund");
    TEST_ASSERT_GOTO(regtest_mine_blocks(&rt, 1, mine_addr), "mine funding");
    int vout = -1; uint64_t amt = 0;
    for (int v = 0; v < 4; v++) {
        unsigned char sc[64]; size_t sl = 0; uint64_t a = 0;
        if (regtest_get_tx_output(&rt, fund_txid, (uint32_t)v, &a, sc, &sl) &&
            sl == 34 && memcmp(sc, fund_spk, 34) == 0) { vout = v; amt = a; break; }
    }
    TEST_ASSERT_GOTO(vout >= 0, "funding output");
    unsigned char txid_b[32];
    hex_decode(fund_txid, txid_b, 32);
    reverse_bytes(txid_b, 32);

    lsp = calloc(1, sizeof(lsp_t));
    TEST_ASSERT_GOTO(lsp, "alloc lsp");
    factory_t *f = &lsp->factory;
    TEST_ASSERT_GOTO(build_factory(ctx, f, pks, txid_b, (uint32_t)vout, amt,
                                   fund_spk, 5000), "factory");
    TEST_ASSERT_GOTO(persist_open(&db, NULL), "db");
    db_ok = 1;
    mgr.persist = &db;
    TEST_ASSERT_GOTO(lsp_channels_init(&mgr, ctx, f, sk[0], 4), "init");
    mgr_ok = 1;
    watchtower_t wt;
    memset(&wt, 0, sizeof(wt));
    wt.rt = &obs;
    mgr.watchtower = &wt;

    /* Bury the funding deeper than the lookup scan depth. */
    int depth = obs.scan_depth > 0 ? obs.scan_depth : 20;
    TEST_ASSERT_GOTO(regtest_mine_blocks(&rt, depth + 5, mine_addr), "bury");
    int lookup = regtest_get_confirmations(&obs, fund_txid);
    printf("\n    node txindex=%d, scan_depth=%d, funding %d+ deep: "
           "regtest_get_confirmations=%d", txindex, depth, depth + 6, lookup);
    if (!txindex)
        TEST_ASSERT_GOTO(lookup == -1, "TX lookup cannot see the funding");

    int changed = lsp_channels_revalidate_funding(&mgr, lsp);
    printf("\n    deep funding: changed=%d frozen=%d/4", changed, count_frozen(&mgr));
    TEST_ASSERT_GOTO(count_frozen(&mgr) == 0, "deep funding stays confirmed");

    /* Shallow reorg. */
    {
        char p[96];
        TEST_ASSERT_GOTO(regtest_get_best_block_hash(&rt, invalidated), "tip");
        snprintf(p, sizeof(p), "\"%s\"", invalidated);
        TEST_ASSERT_GOTO(rpc_ok(&rt, "invalidateblock", p), "invalidate tip");
        TEST_ASSERT_GOTO(regtest_mine_blocks(&rt, 2, other_addr), "mine 2");
        changed = lsp_channels_revalidate_funding(&mgr, lsp);
        printf("\n    after a 1-block reorg: changed=%d frozen=%d/4", changed,
               count_frozen(&mgr));
        TEST_ASSERT_GOTO(count_frozen(&mgr) == 0, "shallow reorg: nothing frozen");
    }

    /* The funding output is spent (cooperative close). */
    {
        char spend_txid[65];
        TEST_ASSERT_GOTO(spend_funding(&rt, ctx, sk, pks, txid_b, (uint32_t)vout,
                                       amt, fund_spk, spend_txid), "spend funding");
        TEST_ASSERT_GOTO(regtest_mine_blocks(&rt, 1, mine_addr), "mine spend");
        int c = -1; char best[65];
        TEST_ASSERT_GOTO(regtest_get_txout(&obs, fund_txid, (uint32_t)vout, &c, best) == 0,
                         "funding output spent");
        changed = lsp_channels_revalidate_funding(&mgr, lsp);
        printf("\n    funding output spent: changed=%d frozen=%d/4", changed,
               count_frozen(&mgr));
        TEST_ASSERT_GOTO(count_frozen(&mgr) == 0, "spent funding stays confirmed");
    }

    /* Restart: fresh manager, anchor read back from the DB. */
    {
        mgr2.persist = &db;
        TEST_ASSERT_GOTO(lsp_channels_init(&mgr2, ctx, f, sk[0], 4), "init 2");
        mgr2_ok = 1;
        mgr2.watchtower = &wt;
        changed = lsp_channels_revalidate_funding(&mgr2, lsp);
        printf("\n    restart, spent output, anchor from DB: changed=%d frozen=%d/4",
               changed, count_frozen(&mgr2));
        TEST_ASSERT_GOTO(count_frozen(&mgr2) == 0,
                         "restart: anchor from the DB keeps it confirmed");
    }

    /* No DB and no anchor, output spent: unknown, so nothing changes. */
    {
        TEST_ASSERT_GOTO(lsp_channels_init(&mgr3, ctx, f, sk[0], 4), "init 3");
        mgr3_ok = 1;
        mgr3.watchtower = &wt;
        changed = lsp_channels_revalidate_funding(&mgr3, lsp);
        printf("\n    no anchor, spent output: changed=%d frozen=%d/4\n   ",
               changed, count_frozen(&mgr3));
        TEST_ASSERT_GOTO(count_frozen(&mgr3) == 0,
                         "spent output with no anchor: no freeze");
    }
    rc = 1;
done:
    if (invalidated[0]) {
        char p[96];
        snprintf(p, sizeof(p), "\"%s\"", invalidated);
        rpc_ok(&rt, "reconsiderblock", p);
    }
    if (mgr3_ok) { mgr3.watchtower = NULL; lsp_channels_cleanup(&mgr3); }
    if (mgr2_ok) { mgr2.watchtower = NULL; lsp_channels_cleanup(&mgr2); }
    if (mgr_ok) { mgr.watchtower = NULL; lsp_channels_cleanup(&mgr); }
    if (db_ok) persist_close(&db);
    if (lsp) { factory_free(&lsp->factory); free(lsp); }
    secp256k1_context_destroy(ctx);
    return rc;
}

/* ---- anchor recording races, double-spends ------------------------------- */

/* Funded factory on regtest for the tests below: rt's wallet funds it, and
   revalidation runs through obs (a wallet that did not build the funding
   TX) or rt itself.  Clean up with reval_env_free. */
typedef struct {
    secp256k1_context *ctx;
    regtest_t rt, obs;
    char mine_addr[128], other_addr[128];
    unsigned char sk[5][32], fund_spk[34], tser[32];
    secp256k1_pubkey pks[5];
    char fund_txid[65];
    unsigned char txid_b[32];
    int vout;
    uint64_t amt;
    lsp_t *lsp;
    persist_t db;
    int db_ok;
    lsp_channel_mgr_t mgr;
    int mgr_ok;
    watchtower_t wt;
    char invalidated[65];
} reval_env_t;

/* mine_funding: mine the funding TX (1 block) before building the factory. */
static int reval_env_init(reval_env_t *e, const char *wallet, int use_obs,
                          int mine_funding) {
    memset(e, 0, sizeof(*e));
    e->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!regtest_init(&e->rt)) return 2;
    regtest_create_wallet(&e->rt, wallet);
    e->obs = e->rt;
    if (use_obs) {
        char obs_name[64];
        snprintf(obs_name, sizeof(obs_name), "%s_obs", wallet);
        regtest_create_wallet(&e->obs, obs_name);
    }
    if (!regtest_get_new_address(&e->rt, e->mine_addr, sizeof(e->mine_addr)) ||
        !regtest_get_new_address(&e->rt, e->other_addr, sizeof(e->other_addr)))
        return 0;
    if (!regtest_fund_from_faucet(&e->rt, 1.0))
        regtest_mine_blocks(&e->rt, 101, e->mine_addr);
    regtest_mine_blocks(&e->rt, 1, e->mine_addr);
    if (!make_keys(e->ctx, e->sk, e->pks, e->fund_spk, e->tser)) return 0;
    char faddr[128];
    if (!regtest_derive_p2tr_address(&e->rt, e->tser, faddr, sizeof(faddr)) ||
        !regtest_fund_address(&e->rt, faddr, 0.002, e->fund_txid))
        return 0;
    if (mine_funding && !regtest_mine_blocks(&e->rt, 1, e->mine_addr)) return 0;
    e->vout = -1;
    for (int v = 0; v < 4; v++) {
        unsigned char sc[64]; size_t sl = 0; uint64_t a = 0;
        if (regtest_get_tx_output(&e->rt, e->fund_txid, (uint32_t)v, &a, sc, &sl) &&
            sl == 34 && memcmp(sc, e->fund_spk, 34) == 0) { e->vout = v; e->amt = a; break; }
    }
    if (e->vout < 0) return 0;
    hex_decode(e->fund_txid, e->txid_b, 32);
    reverse_bytes(e->txid_b, 32);
    e->lsp = calloc(1, sizeof(lsp_t));
    if (!e->lsp) return 0;
    if (!build_factory(e->ctx, &e->lsp->factory, e->pks, e->txid_b,
                       (uint32_t)e->vout, e->amt, e->fund_spk, 5000))
        return 0;
    if (!persist_open(&e->db, NULL)) return 0;
    e->db_ok = 1;
    e->mgr.persist = &e->db;
    if (!lsp_channels_init(&e->mgr, e->ctx, &e->lsp->factory, e->sk[0], 4)) return 0;
    e->mgr_ok = 1;
    /* Channel rows, so freezes are persisted. */
    if (!set_remote_basepoints(e->ctx, &e->mgr) || !save_channels(&e->db, &e->mgr))
        return 0;
    e->wt.rt = use_obs ? &e->obs : &e->rt;
    e->mgr.watchtower = &e->wt;
    return 1;
}

static void reval_env_free(reval_env_t *e) {
    lsp_channels_test_anchor_hook = NULL;
    lsp_channels_test_anchor_hook_arg = NULL;
    if (e->invalidated[0]) {
        char p[96];
        snprintf(p, sizeof(p), "\"%s\"", e->invalidated);
        rpc_ok(&e->rt, "reconsiderblock", p);
    }
    if (e->mgr_ok) { e->mgr.watchtower = NULL; lsp_channels_cleanup(&e->mgr); }
    if (e->db_ok) persist_close(&e->db);
    if (e->lsp) { factory_free(&e->lsp->factory); free(e->lsp); }
    if (e->ctx) secp256k1_context_destroy(e->ctx);
}

static int db_has_anchor(reval_env_t *e) {
    int32_t h = 0;
    char hash[65];
    return persist_load_funding_anchor(&e->db, e->fund_txid, &h, hash);
}

static int node_has_txindex(regtest_t *rt) {
    char *ii = regtest_exec(rt, "getindexinfo", "");
    int t = ii && strstr(ii, "txindex") != NULL;
    free(ii);
    return t;
}

static int invalidate(reval_env_t *e, const char *block) {
    char p[96];
    snprintf(p, sizeof(p), "\"%s\"", block);
    if (!rpc_ok(&e->rt, "invalidateblock", p)) return 0;
    snprintf(e->invalidated, sizeof(e->invalidated), "%s", block);
    return 1;
}

static int bumpfee(regtest_t *rt, const char *txid) {
    char p[96];
    snprintf(p, sizeof(p), "\"%s\"", txid);
    char *r = regtest_exec(rt, "bumpfee", p);
    int ok = r && strstr(r, "txid") != NULL;
    free(r);
    return ok;
}

/* Replace the mempool wallet TX `txid` with one spending the same inputs to
   `addr`, paying a fee that also covers replacing its descendants (bumpfee
   refuses a TX that has them). */
static int double_spend_raw(regtest_t *rt, const char *txid, const char *addr,
                            char *new_txid) {
    char p[160];
    snprintf(p, sizeof(p), "\"%s\" true", txid);
    char *r = regtest_exec(rt, "getrawtransaction", p);
    cJSON *tx = r ? cJSON_Parse(r) : NULL;
    free(r);
    if (!tx) return 0;
    cJSON *vin = cJSON_GetObjectItem(tx, "vin");
    cJSON *ins = cJSON_CreateArray();
    double total = 0;
    int ok = cJSON_IsArray(vin) && cJSON_GetArraySize(vin) > 0;
    for (int i = 0; ok && i < cJSON_GetArraySize(vin); i++) {
        cJSON *in = cJSON_GetArrayItem(vin, i);
        cJSON *pt = cJSON_GetObjectItem(in, "txid");
        cJSON *pv = cJSON_GetObjectItem(in, "vout");
        if (!pt || !cJSON_IsString(pt) || !pv || !cJSON_IsNumber(pv)) { ok = 0; break; }
        /* The prevout is confirmed and spent only in the mempool. */
        snprintf(p, sizeof(p), "\"%s\" %d false", pt->valuestring, pv->valueint);
        char *o = regtest_exec(rt, "gettxout", p);
        cJSON *oj = o ? cJSON_Parse(o) : NULL;
        free(o);
        cJSON *val = oj ? cJSON_GetObjectItem(oj, "value") : NULL;
        if (!val || !cJSON_IsNumber(val)) { ok = 0; cJSON_Delete(oj); break; }
        total += val->valuedouble;
        cJSON_Delete(oj);
        cJSON *ni = cJSON_CreateObject();
        cJSON_AddStringToObject(ni, "txid", pt->valuestring);
        cJSON_AddNumberToObject(ni, "vout", pv->valueint);
        cJSON_AddItemToArray(ins, ni);
    }
    cJSON_Delete(tx);
    char *signed_hex = NULL;
    if (ok && total > 0.002) {
        cJSON *outs = cJSON_CreateObject();
        char amt[32];
        snprintf(amt, sizeof(amt), "%.8f", total - 0.001);
        cJSON_AddStringToObject(outs, addr, amt);
        char *is = cJSON_PrintUnformatted(ins);
        char *os = cJSON_PrintUnformatted(outs);
        cJSON_Delete(outs);
        char *params = malloc(strlen(is) + strlen(os) + 16);
        if (params) {
            sprintf(params, "'%s' '%s'", is, os);
            char *raw = regtest_exec(rt, "createrawtransaction", params);
            free(params);
            if (raw) {
                char *s = raw;
                while (*s == '"' || *s == ' ' || *s == '\n') s++;
                char *e = s + strlen(s);
                while (e > s && (e[-1] == '"' || e[-1] == ' ' || e[-1] == '\n' ||
                                 e[-1] == '\r')) *--e = '\0';
                signed_hex = regtest_sign_raw_tx_with_wallet(rt, s, NULL, 1);
                free(raw);
            }
        }
        free(is);
        free(os);
    }
    cJSON_Delete(ins);
    if (!signed_hex) return 0;
    int sent = regtest_send_raw_tx(rt, signed_hex, new_txid);
    free(signed_hex);
    return sent;
}

typedef struct {
    reval_env_t *e;
    char fund_block[65];
    int fired, ok;
} anchor_race_t;

/* Runs inside the anchor recording, after its gettxout read: the funding
   block is disconnected, the funding TX double-spent, and a replacement
   block mined at the funding height. */
static void anchor_race_hook(void *arg) {
    anchor_race_t *r = (anchor_race_t *)arg;
    if (r->fired) return;
    r->fired = 1;
    if (!invalidate(r->e, r->fund_block)) return;
    if (!bumpfee(&r->e->rt, r->e->fund_txid)) return;
    if (!regtest_mine_blocks(&r->e->rt, 1, r->e->other_addr)) return;
    r->ok = 1;
}

int test_regtest_reorg_revalidate_anchor_race(void) {
    int rc = 0;
    reval_env_t e;
    int ir = reval_env_init(&e, "anchor_race", 1, 1);
    if (ir == 2) {
        printf("  SKIP: bitcoind not available\n");
        reval_env_free(&e);
        return 2;
    }
    TEST_ASSERT_GOTO(ir == 1, "funded factory");
    anchor_race_t race;
    memset(&race, 0, sizeof(race));
    race.e = &e;
    int fund_height = regtest_get_block_height(&e.rt);
    TEST_ASSERT_GOTO(regtest_get_block_hash(&e.rt, fund_height, race.fund_block,
                                            sizeof(race.fund_block)), "funding block");
    TEST_ASSERT_GOTO(regtest_mine_blocks(&e.rt, 2, e.mine_addr), "bury funding");
    int txindex = node_has_txindex(&e.rt);

    lsp_channels_test_anchor_hook = anchor_race_hook;
    lsp_channels_test_anchor_hook_arg = &race;
    int noted = lsp_channels_note_funding_anchor(&e.mgr, e.lsp);
    lsp_channels_test_anchor_hook = NULL;
    lsp_channels_test_anchor_hook_arg = NULL;
    TEST_ASSERT_GOTO(race.fired && race.ok, "reorg ran inside the recording");
    {
        char now_at[65] = {0};
        regtest_get_block_hash(&e.rt, fund_height, now_at, sizeof(now_at));
        printf("\n    txindex=%d; funding block %.16s replaced by %.16s inside the "
               "recording: noted=%d anchor in memory=%d (height %d %.16s) in DB=%d",
               txindex, race.fund_block, now_at, noted,
               e.mgr.funding_anchor_height > 0, (int)e.mgr.funding_anchor_height,
               e.mgr.funding_anchor_block, db_has_anchor(&e));
    }
    TEST_ASSERT_GOTO(noted == 0 && e.mgr.funding_anchor_height == 0 &&
                     e.mgr.funding_anchor_block[0] == '\0',
                     "no anchor recorded in memory");
    TEST_ASSERT_GOTO(!db_has_anchor(&e), "no anchor persisted");

    /* The funding TX is gone: with -txindex the lookup sees it out of the
       active chain (GONE, freeze); without, a spent-or-gone output with no
       anchor is UNKNOWN (no change).  A wrong anchor would read CONFIRMED. */
    TEST_ASSERT_GOTO(!regtest_is_in_mempool(&e.obs, e.fund_txid),
                     "funding TX not in the mempool");
    int changed = lsp_channels_revalidate_funding(&e.mgr, e.lsp);
    print_frozen("after the race", &e.mgr, changed);
    if (txindex)
        TEST_ASSERT_GOTO(changed == 4 && count_frozen(&e.mgr) == 4,
                         "-txindex: funding gone, every channel frozen");
    else
        TEST_ASSERT_GOTO(changed == 0 && count_frozen(&e.mgr) == 0 &&
                         e.mgr.funding_anchor_unconfirmed == 0,
                         "no -txindex: unknown, nothing changes");
    printf("\n   ");
    rc = 1;
done:
    reval_env_free(&e);
    return rc;
}

int test_regtest_reorg_revalidate_spent_funding_reorged_out(void) {
    int rc = 0;
    reval_env_t e;
    int ir = reval_env_init(&e, "spent_reorged", 1, 1);
    if (ir == 2) {
        printf("  SKIP: bitcoind not available\n");
        reval_env_free(&e);
        return 2;
    }
    TEST_ASSERT_GOTO(ir == 1, "funded factory");
    int fund_height = regtest_get_block_height(&e.rt);
    char fund_block[65] = {0};
    TEST_ASSERT_GOTO(regtest_get_block_hash(&e.rt, fund_height, fund_block,
                                            sizeof(fund_block)), "funding block");
    TEST_ASSERT_GOTO(regtest_mine_blocks(&e.rt, 2, e.mine_addr), "bury funding");

    /* Anchor recorded while the output is unspent. */
    int changed = lsp_channels_revalidate_funding(&e.mgr, e.lsp);
    printf("\n    txindex=%d; confirmed: anchor height %d (funding at %d) %.16s",
           node_has_txindex(&e.rt), (int)e.mgr.funding_anchor_height,
           fund_height, e.mgr.funding_anchor_block);
    TEST_ASSERT_GOTO(count_frozen(&e.mgr) == 0, "confirmed: nothing frozen");
    TEST_ASSERT_GOTO(e.mgr.funding_anchor_height == fund_height &&
                     strcmp(e.mgr.funding_anchor_block, fund_block) == 0 &&
                     db_has_anchor(&e), "anchor recorded and persisted");

    /* Funding output spent and the spend mined: CONFIRMED through the
       anchor. */
    char spend_txid[65];
    TEST_ASSERT_GOTO(spend_funding(&e.rt, e.ctx, e.sk, e.pks, e.txid_b,
                                   (uint32_t)e.vout, e.amt, e.fund_spk, spend_txid),
                     "spend funding");
    TEST_ASSERT_GOTO(regtest_mine_blocks(&e.rt, 1, e.mine_addr), "mine spend");
    {
        int c = -1; char best[65];
        TEST_ASSERT_GOTO(regtest_get_txout(&e.obs, e.fund_txid, (uint32_t)e.vout,
                                           &c, best) == 0, "funding output spent");
    }
    changed = lsp_channels_revalidate_funding(&e.mgr, e.lsp);
    print_frozen("output spent, anchor in the chain", &e.mgr, changed);
    TEST_ASSERT_GOTO(count_frozen(&e.mgr) == 0, "spent: nothing frozen");

    /* Anchor block disconnected: funding and spend back in the mempool. */
    TEST_ASSERT_GOTO(invalidate(&e, fund_block), "invalidate funding block");
    TEST_ASSERT_GOTO(regtest_is_in_mempool(&e.obs, e.fund_txid) &&
                     regtest_is_in_mempool(&e.obs, spend_txid),
                     "funding and spend back in the mempool");
    changed = lsp_channels_revalidate_funding(&e.mgr, e.lsp);
    print_frozen("anchor block disconnected, funding in the mempool", &e.mgr, changed);
    TEST_ASSERT_GOTO(count_frozen(&e.mgr) == 0, "pending: nothing frozen yet");
    TEST_ASSERT_GOTO(lsp_channels_funding_recheck_due(&e.mgr) == 1,
                     "pending: re-checked on the next block");

    /* Funding double-spent (its spend is a mempool descendant, so a raw
       replacement rather than bumpfee) and the replacement mined. */
    char repl[65];
    TEST_ASSERT_GOTO(double_spend_raw(&e.rt, e.fund_txid, e.other_addr, repl),
                     "raw RBF replacement of the funding TX");
    TEST_ASSERT_GOTO(regtest_mine_blocks(&e.rt, 1, e.other_addr), "mine replacement");
    TEST_ASSERT_GOTO(!regtest_is_in_mempool(&e.obs, e.fund_txid) &&
                     !regtest_is_in_mempool(&e.obs, spend_txid),
                     "funding and spend evicted");
    {
        char at[65] = {0};
        regtest_get_block_hash(&e.rt, fund_height, at, sizeof(at));
        printf("\n    funding double-spent by %.16s; block at the anchor height "
               "now %.16s (anchor %.16s)", repl, at, e.mgr.funding_anchor_block);
    }
    changed = lsp_channels_revalidate_funding(&e.mgr, e.lsp);
    print_frozen("funding double-spent, anchor off the chain", &e.mgr, changed);
    TEST_ASSERT_GOTO(changed == 4 && count_frozen(&e.mgr) == 4,
                     "every channel frozen");
    TEST_ASSERT_GOTO(count_frozen_db(&e.db, e.mgr.n_channels) == 4,
                     "freeze persisted");
    printf("\n   ");
    rc = 1;
done:
    reval_env_free(&e);
    return rc;
}

int test_regtest_reorg_revalidate_conflicted_funding_no_anchor(void) {
    int rc = 0;
    reval_env_t e;
    /* Revalidation through the funding wallet (the LSP's own node wallet
       built the funding TX), funding left unconfirmed. */
    int ir = reval_env_init(&e, "conflicted_fund", 0, 0);
    if (ir == 2) {
        printf("  SKIP: bitcoind not available\n");
        reval_env_free(&e);
        return 2;
    }
    TEST_ASSERT_GOTO(ir == 1, "funded factory");
    TEST_ASSERT_GOTO(regtest_is_in_mempool(&e.rt, e.fund_txid), "funding in the mempool");
    int changed = lsp_channels_revalidate_funding(&e.mgr, e.lsp);
    print_frozen("funding in the mempool", &e.mgr, changed);
    TEST_ASSERT_GOTO(count_frozen(&e.mgr) == 0, "pending: nothing frozen");
    TEST_ASSERT_GOTO(e.mgr.funding_anchor_height == 0, "no anchor (never confirmed)");

    /* Double-spent and the replacement mined: the wallet reports the
       funding TX conflicted. */
    TEST_ASSERT_GOTO(bumpfee(&e.rt, e.fund_txid), "bumpfee replaced the funding TX");
    TEST_ASSERT_GOTO(regtest_mine_blocks(&e.rt, 1, e.other_addr), "mine replacement");
    int conf1 = regtest_get_confirmations(&e.rt, e.fund_txid);
    changed = lsp_channels_revalidate_funding(&e.mgr, e.lsp);
    printf("\n    conflicted 1 deep: regtest_get_confirmations=%d", conf1);
    print_frozen("conflicted, no anchor", &e.mgr, changed);
    TEST_ASSERT_GOTO(conf1 == REGTEST_CONF_CONFLICTED, "conflicted 1 deep: -3");
    TEST_ASSERT_GOTO(e.mgr.funding_anchor_height == 0, "still no anchor");
    TEST_ASSERT_GOTO(changed == 4 && count_frozen(&e.mgr) == 4,
                     "conflicted funding freezes every channel");

    /* Two deep the wallet says -2: not to be read as an RPC outage. */
    TEST_ASSERT_GOTO(regtest_mine_blocks(&e.rt, 1, e.other_addr), "mine");
    int conf2 = regtest_get_confirmations(&e.rt, e.fund_txid);
    printf("\n    conflicted 2 deep: regtest_get_confirmations=%d (RPC error is %d)\n   ",
           conf2, REGTEST_CONF_RPC_ERROR);
    TEST_ASSERT_GOTO(conf2 == REGTEST_CONF_CONFLICTED, "conflicted 2 deep: -3");
    TEST_ASSERT_GOTO(lsp_channels_revalidate_funding(&e.mgr, e.lsp) == 0 &&
                     count_frozen(&e.mgr) == 4, "stays frozen");
    rc = 1;
done:
    reval_env_free(&e);
    return rc;
}
