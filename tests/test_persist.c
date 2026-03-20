#include "superscalar/persist.h"
#include "superscalar/circuit_breaker.h"
#include "superscalar/gossip_store.h"
#include "superscalar/rgs.h"
#include "superscalar/lnurl.h"
#include "superscalar/ptlc_commit.h"
#include "superscalar/factory.h"
#include "superscalar/musig.h"
#include "superscalar/channel.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/dw_state.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
#include "superscalar/sha256.h"

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

static const unsigned char seckeys[5][32] = {
    { [0 ... 31] = 0x10 },
    { [0 ... 31] = 0x21 },
    { [0 ... 31] = 0x32 },
    { [0 ... 31] = 0x43 },
    { [0 ... 31] = 0x54 },
};

static secp256k1_context *test_ctx(void) {
    return secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

/* ---- Test 1: Open/close in-memory database ---- */

int test_persist_open_close(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open in-memory");
    TEST_ASSERT(db.db != NULL, "db handle");
    persist_close(&db);
    TEST_ASSERT(db.db == NULL, "db closed");
    return 1;
}

/* ---- Test 2: Channel save/load round-trip ---- */

int test_persist_channel_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    secp256k1_context *ctx = test_ctx();
    secp256k1_pubkey pk_local, pk_remote;
    if (!secp256k1_ec_pubkey_create(ctx, &pk_local, seckeys[0])) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pk_remote, seckeys[1])) return 0;

    unsigned char fake_txid[32] = {0};
    fake_txid[0] = 0xDD;
    unsigned char fake_spk[34];
    memset(fake_spk, 0xAA, 34);

    channel_t ch;
    TEST_ASSERT(channel_init(&ch, ctx, seckeys[0], &pk_local, &pk_remote,
                              fake_txid, 1, 100000, fake_spk, 34,
                              50000, 50000, 144), "channel_init");

    /* Simulate some updates */
    ch.local_amount = 45000;
    ch.remote_amount = 55000;
    ch.commitment_number = 3;

    /* Save */
    TEST_ASSERT(persist_save_channel(&db, &ch, 0, 0), "save channel");

    /* Load */
    uint64_t local, remote, commit;
    TEST_ASSERT(persist_load_channel_state(&db, 0, &local, &remote, &commit),
                "load channel");
    TEST_ASSERT_EQ(local, 45000, "local_amount");
    TEST_ASSERT_EQ(remote, 55000, "remote_amount");
    TEST_ASSERT_EQ(commit, 3, "commitment_number");

    /* Update balance */
    TEST_ASSERT(persist_update_channel_balance(&db, 0, 40000, 60000, 4),
                "update balance");

    TEST_ASSERT(persist_load_channel_state(&db, 0, &local, &remote, &commit),
                "load updated");
    TEST_ASSERT_EQ(local, 40000, "updated local");
    TEST_ASSERT_EQ(remote, 60000, "updated remote");
    TEST_ASSERT_EQ(commit, 4, "updated commit");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}

/* ---- Test 3: Revocation secret save/load (flat storage) ---- */

int test_persist_revocation_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    /* Generate 3 revocation secrets */
    unsigned char sec0[32], sec1[32], sec2[32];
    memset(sec0, 0x42, 32);
    memset(sec1, 0x43, 32);
    memset(sec2, 0x44, 32);

    TEST_ASSERT(persist_save_revocation(&db, 0, 0, sec0), "save rev 0");
    TEST_ASSERT(persist_save_revocation(&db, 0, 1, sec1), "save rev 1");
    TEST_ASSERT(persist_save_revocation(&db, 0, 2, sec2), "save rev 2");

    /* Load into flat arrays */
    unsigned char secrets[256][32];
    uint8_t valid[256];
    size_t count = 0;
    TEST_ASSERT(persist_load_revocations_flat(&db, 0, secrets, valid, 256, &count),
                "load revocations flat");
    TEST_ASSERT(count == 3, "loaded 3 secrets");

    /* Verify secrets match */
    TEST_ASSERT(valid[0] == 1, "slot 0 valid");
    TEST_ASSERT(memcmp(secrets[0], sec0, 32) == 0, "secret 0 matches");
    TEST_ASSERT(valid[1] == 1, "slot 1 valid");
    TEST_ASSERT(memcmp(secrets[1], sec1, 32) == 0, "secret 1 matches");
    TEST_ASSERT(valid[2] == 1, "slot 2 valid");
    TEST_ASSERT(memcmp(secrets[2], sec2, 32) == 0, "secret 2 matches");

    persist_close(&db);
    return 1;
}

/* ---- Test 4: HTLC save/load round-trip ---- */

int test_persist_htlc_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    htlc_t h1 = {0};
    h1.direction = HTLC_OFFERED;
    h1.state = HTLC_STATE_ACTIVE;
    h1.amount_sats = 5000;
    memset(h1.payment_hash, 0xAB, 32);
    h1.cltv_expiry = 500;
    h1.id = 0;

    htlc_t h2 = {0};
    h2.direction = HTLC_RECEIVED;
    h2.state = HTLC_STATE_FULFILLED;
    h2.amount_sats = 3000;
    memset(h2.payment_hash, 0xCD, 32);
    memset(h2.payment_preimage, 0xEF, 32);
    h2.cltv_expiry = 600;
    h2.id = 1;

    TEST_ASSERT(persist_save_htlc(&db, 0, &h1), "save htlc 1");
    TEST_ASSERT(persist_save_htlc(&db, 0, &h2), "save htlc 2");

    htlc_t loaded[16];
    size_t count = persist_load_htlcs(&db, 0, loaded, 16);
    TEST_ASSERT_EQ(count, 2, "htlc count");

    TEST_ASSERT_EQ(loaded[0].id, 0, "htlc 0 id");
    TEST_ASSERT_EQ(loaded[0].direction, HTLC_OFFERED, "htlc 0 direction");
    TEST_ASSERT_EQ(loaded[0].state, HTLC_STATE_ACTIVE, "htlc 0 state");
    TEST_ASSERT_EQ(loaded[0].amount_sats, 5000, "htlc 0 amount");
    TEST_ASSERT_EQ(loaded[0].cltv_expiry, 500, "htlc 0 cltv");
    TEST_ASSERT(memcmp(loaded[0].payment_hash, h1.payment_hash, 32) == 0,
                "htlc 0 hash");

    TEST_ASSERT_EQ(loaded[1].id, 1, "htlc 1 id");
    TEST_ASSERT_EQ(loaded[1].direction, HTLC_RECEIVED, "htlc 1 direction");
    TEST_ASSERT_EQ(loaded[1].state, HTLC_STATE_FULFILLED, "htlc 1 state");
    TEST_ASSERT_EQ(loaded[1].amount_sats, 3000, "htlc 1 amount");
    TEST_ASSERT(memcmp(loaded[1].payment_preimage, h2.payment_preimage, 32) == 0,
                "htlc 1 preimage");

    persist_close(&db);
    return 1;
}

/* ---- Test: HTLC delete ---- */

int test_persist_htlc_delete(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    /* Save two HTLCs on channel 0 */
    htlc_t h1 = {0};
    h1.direction = HTLC_OFFERED;
    h1.state = HTLC_STATE_ACTIVE;
    h1.amount_sats = 5000;
    memset(h1.payment_hash, 0xAA, 32);
    h1.cltv_expiry = 500;
    h1.id = 10;

    htlc_t h2 = {0};
    h2.direction = HTLC_OFFERED;
    h2.state = HTLC_STATE_ACTIVE;
    h2.amount_sats = 3000;
    memset(h2.payment_hash, 0xBB, 32);
    h2.cltv_expiry = 600;
    h2.id = 11;

    TEST_ASSERT(persist_save_htlc(&db, 0, &h1), "save htlc 1");
    TEST_ASSERT(persist_save_htlc(&db, 0, &h2), "save htlc 2");

    /* Delete h1 */
    TEST_ASSERT(persist_delete_htlc(&db, 0, 10), "delete htlc 10");

    /* Only h2 should remain */
    htlc_t loaded[16];
    size_t count = persist_load_htlcs(&db, 0, loaded, 16);
    TEST_ASSERT_EQ(count, 1, "count after delete");
    TEST_ASSERT_EQ(loaded[0].id, 11, "remaining htlc id");
    TEST_ASSERT_EQ(loaded[0].amount_sats, 3000, "remaining amount");

    /* Verify remaining HTLC fields fully */
    {
        unsigned char expected_hash[32];
        memset(expected_hash, 0xBB, 32);
        TEST_ASSERT(memcmp(loaded[0].payment_hash, expected_hash, 32) == 0,
                    "remaining htlc hash");
    }
    TEST_ASSERT_EQ(loaded[0].cltv_expiry, 600, "remaining cltv");

    /* Delete h2 */
    TEST_ASSERT(persist_delete_htlc(&db, 0, 11), "delete htlc 11");
    count = persist_load_htlcs(&db, 0, loaded, 16);
    TEST_ASSERT_EQ(count, 0, "count after second delete");

    /* Deleting non-existent HTLC should succeed (no-op in SQLite) */
    TEST_ASSERT(persist_delete_htlc(&db, 0, 999), "delete non-existent");

    /* Cross-channel isolation: HTLCs on different channels are independent */
    htlc_t h3 = {0};
    h3.id = 20;
    h3.direction = HTLC_OFFERED;
    h3.state = HTLC_STATE_ACTIVE;
    h3.amount_sats = 7000;
    memset(h3.payment_hash, 0xCC, 32);

    htlc_t h4 = {0};
    h4.id = 20;  /* same htlc_id, different channel */
    h4.direction = HTLC_OFFERED;
    h4.state = HTLC_STATE_ACTIVE;
    h4.amount_sats = 9000;
    memset(h4.payment_hash, 0xDD, 32);

    TEST_ASSERT(persist_save_htlc(&db, 0, &h3), "save ch0 htlc");
    TEST_ASSERT(persist_save_htlc(&db, 1, &h4), "save ch1 htlc");

    /* Delete from channel 0 only */
    TEST_ASSERT(persist_delete_htlc(&db, 0, 20), "delete ch0 htlc");
    count = persist_load_htlcs(&db, 0, loaded, 16);
    TEST_ASSERT_EQ(count, 0, "ch0 empty after delete");

    /* Channel 1 still has its HTLC */
    count = persist_load_htlcs(&db, 1, loaded, 16);
    TEST_ASSERT_EQ(count, 1, "ch1 still has htlc");
    TEST_ASSERT_EQ(loaded[0].amount_sats, 9000, "ch1 htlc amount");

    /* Delete wrong channel — no effect */
    TEST_ASSERT(persist_delete_htlc(&db, 0, 20), "delete wrong channel");
    count = persist_load_htlcs(&db, 1, loaded, 16);
    TEST_ASSERT_EQ(count, 1, "ch1 unaffected by wrong-channel delete");

    persist_close(&db);
    return 1;
}

/* ---- Test 5: Factory save/load round-trip ---- */

int test_persist_factory_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    secp256k1_context *ctx = test_ctx();
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_ec_pubkey_create(ctx, &pks[i], seckeys[i])) return 0;
    }

    /* Build factory */
    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, 5);

    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);
    musig_keyagg_t ka_copy = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &ka_copy.cache, tweak)) return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) return 0;
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tweaked_xonly);

    factory_t f;
    factory_init_from_pubkeys(&f, ctx, pks, 5, 10, 4);
    unsigned char fake_txid[32] = {0};
    fake_txid[0] = 0xDD;
    factory_set_funding(&f, fake_txid, 0, 1000000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* Save factory */
    TEST_ASSERT(persist_save_factory(&db, &f, ctx, 0), "save factory");

    /* Load factory into new struct */
    factory_t f2;
    TEST_ASSERT(persist_load_factory(&db, 0, &f2, ctx), "load factory");

    /* Verify */
    TEST_ASSERT_EQ(f2.n_participants, 5, "n_participants");
    TEST_ASSERT_EQ(f2.step_blocks, 10, "step_blocks");
    TEST_ASSERT_EQ(f2.funding_amount_sats, 1000000, "funding_amount");
    TEST_ASSERT_EQ(f2.n_nodes, f.n_nodes, "n_nodes");

    /* Verify txids match (the tree was rebuilt, so all node txids should match) */
    for (size_t i = 0; i < f.n_nodes; i++) {
        TEST_ASSERT(memcmp(f.nodes[i].txid, f2.nodes[i].txid, 32) == 0,
                    "node txid matches");
    }

    factory_free(&f);
    factory_free(&f2);
    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}

/* ---- Test 6: Nonce pool save/load round-trip ---- */

int test_persist_nonce_pool_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    /* Save some fake pool data */
    unsigned char pool_data[128];
    memset(pool_data, 0x42, sizeof(pool_data));

    TEST_ASSERT(persist_save_nonce_pool(&db, 0, "local", pool_data, 128, 5),
                "save nonce pool");

    /* Load it back */
    unsigned char loaded[256];
    size_t data_len, next_idx;
    TEST_ASSERT(persist_load_nonce_pool(&db, 0, "local", loaded, 256,
                                          &data_len, &next_idx),
                "load nonce pool");
    TEST_ASSERT_EQ(data_len, 128, "data_len");
    TEST_ASSERT_EQ(next_idx, 5, "next_index");
    TEST_ASSERT(memcmp(loaded, pool_data, 128) == 0, "pool data matches");

    persist_close(&db);
    return 1;
}

/* ---- Test 7: Multiple channels in same database ---- */

int test_persist_multi_channel(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    secp256k1_context *ctx = test_ctx();
    secp256k1_pubkey pk_local, pk_remote;
    if (!secp256k1_ec_pubkey_create(ctx, &pk_local, seckeys[0])) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pk_remote, seckeys[1])) return 0;

    unsigned char fake_txid[32] = {0};
    unsigned char fake_spk[34];
    memset(fake_spk, 0xAA, 34);

    /* Save 4 channels with different balances */
    for (uint32_t i = 0; i < 4; i++) {
        channel_t ch;
        fake_txid[0] = (unsigned char)(0xDD + i);
        channel_init(&ch, ctx, seckeys[0], &pk_local, &pk_remote,
                      fake_txid, i, 100000, fake_spk, 34,
                      50000 - i * 1000, 50000 + i * 1000, 144);
        ch.commitment_number = i;
        TEST_ASSERT(persist_save_channel(&db, &ch, 0, i), "save channel");
        channel_cleanup(&ch);
    }

    /* Load each and verify */
    for (uint32_t i = 0; i < 4; i++) {
        uint64_t local, remote, commit;
        TEST_ASSERT(persist_load_channel_state(&db, i, &local, &remote, &commit),
                    "load channel");
        TEST_ASSERT_EQ(local, 50000 - i * 1000, "local_amount");
        TEST_ASSERT_EQ(remote, 50000 + i * 1000, "remote_amount");
        TEST_ASSERT_EQ(commit, i, "commitment_number");
    }

    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}

/* ==== Phase 23: Persistence Hardening Tests ==== */

/* ---- Test: DW counter save/load round-trip ---- */

int test_persist_dw_counter_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    uint32_t layers[] = {3, 1};
    TEST_ASSERT(persist_save_dw_counter(&db, 0, 7, 2, layers), "save dw counter");

    uint32_t epoch, n_layers;
    uint32_t loaded_layers[8];
    TEST_ASSERT(persist_load_dw_counter(&db, 0, &epoch, &n_layers, loaded_layers, 8),
                "load dw counter");
    TEST_ASSERT_EQ(epoch, 7, "epoch");
    TEST_ASSERT_EQ(n_layers, 2, "n_layers");
    TEST_ASSERT_EQ(loaded_layers[0], 3, "layer 0");
    TEST_ASSERT_EQ(loaded_layers[1], 1, "layer 1");

    /* Overwrite with new epoch */
    uint32_t layers2[] = {4, 2, 0};
    TEST_ASSERT(persist_save_dw_counter(&db, 0, 12, 3, layers2), "save dw counter 2");
    TEST_ASSERT(persist_load_dw_counter(&db, 0, &epoch, &n_layers, loaded_layers, 8),
                "load dw counter 2");
    TEST_ASSERT_EQ(epoch, 12, "epoch 2");
    TEST_ASSERT_EQ(n_layers, 3, "n_layers 2");
    TEST_ASSERT_EQ(loaded_layers[0], 4, "layer 0 v2");
    TEST_ASSERT_EQ(loaded_layers[1], 2, "layer 1 v2");
    TEST_ASSERT_EQ(loaded_layers[2], 0, "layer 2 v2");

    /* Non-existent factory */
    TEST_ASSERT(!persist_load_dw_counter(&db, 99, &epoch, &n_layers, loaded_layers, 8),
                "missing factory returns 0");

    persist_close(&db);
    return 1;
}

/* ---- Test: Departed clients round-trip ---- */

int test_persist_departed_clients_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    unsigned char key0[32], key1[32], key2[32];
    memset(key0, 0xAA, 32);
    memset(key1, 0xBB, 32);
    memset(key2, 0xCC, 32);

    TEST_ASSERT(persist_save_departed_client(&db, 0, 1, key0), "save departed 0");
    TEST_ASSERT(persist_save_departed_client(&db, 0, 2, key1), "save departed 1");
    TEST_ASSERT(persist_save_departed_client(&db, 0, 3, key2), "save departed 2");

    int departed[8];
    unsigned char keys[8][32];
    memset(departed, 0, sizeof(departed));
    memset(keys, 0, sizeof(keys));

    size_t count = persist_load_departed_clients(&db, 0, departed, keys, 8);
    TEST_ASSERT_EQ(count, 3, "departed count");
    TEST_ASSERT_EQ(departed[1], 1, "client 1 departed");
    TEST_ASSERT_EQ(departed[2], 1, "client 2 departed");
    TEST_ASSERT_EQ(departed[3], 1, "client 3 departed");
    TEST_ASSERT_EQ(departed[0], 0, "client 0 not departed");
    TEST_ASSERT(memcmp(keys[1], key0, 32) == 0, "key 0 matches");
    TEST_ASSERT(memcmp(keys[2], key1, 32) == 0, "key 1 matches");
    TEST_ASSERT(memcmp(keys[3], key2, 32) == 0, "key 2 matches");

    /* Different factory returns 0 */
    memset(departed, 0, sizeof(departed));
    count = persist_load_departed_clients(&db, 99, departed, keys, 8);
    TEST_ASSERT_EQ(count, 0, "no departed for factory 99");

    persist_close(&db);
    return 1;
}

/* ---- Test: Invoice registry round-trip ---- */

int test_persist_invoice_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    unsigned char hash0[32], hash1[32], hash2[32];
    memset(hash0, 0x01, 32);
    memset(hash1, 0x02, 32);
    memset(hash2, 0x03, 32);

    TEST_ASSERT(persist_save_invoice(&db, hash0, 0, 10000), "save invoice 0");
    TEST_ASSERT(persist_save_invoice(&db, hash1, 2, 25000), "save invoice 1");
    TEST_ASSERT(persist_save_invoice(&db, hash2, 1, 5000), "save invoice 2");

    /* Deactivate one */
    TEST_ASSERT(persist_deactivate_invoice(&db, hash2), "deactivate invoice 2");

    /* Load active only */
    unsigned char hashes[8][32];
    size_t dests[8];
    uint64_t amounts[8];
    size_t count = persist_load_invoices(&db, hashes, dests, amounts, 8);
    TEST_ASSERT_EQ(count, 2, "active invoice count");
    TEST_ASSERT(memcmp(hashes[0], hash0, 32) == 0, "hash 0");
    TEST_ASSERT_EQ(dests[0], 0, "dest 0");
    TEST_ASSERT_EQ(amounts[0], 10000, "amount 0");
    TEST_ASSERT(memcmp(hashes[1], hash1, 32) == 0, "hash 1");
    TEST_ASSERT_EQ(dests[1], 2, "dest 1");
    TEST_ASSERT_EQ(amounts[1], 25000, "amount 1");

    persist_close(&db);
    return 1;
}

/* ---- Test: HTLC origin round-trip ---- */

int test_persist_htlc_origin_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    unsigned char hash0[32], hash1[32];
    memset(hash0, 0xA1, 32);
    memset(hash1, 0xB2, 32);

    TEST_ASSERT(persist_save_htlc_origin(&db, hash0, 5, 0, 0, 0),
                "save origin 0");
    TEST_ASSERT(persist_save_htlc_origin(&db, hash1, 0, 3, 1, 7),
                "save origin 1");

    /* Deactivate first */
    TEST_ASSERT(persist_deactivate_htlc_origin(&db, hash0), "deactivate origin 0");

    /* Load active */
    unsigned char hashes[8][32];
    uint64_t bridge[8], req[8], htlc_ids[8];
    size_t senders[8];
    size_t count = persist_load_htlc_origins(&db, hashes, bridge, req,
                                               senders, htlc_ids, 8);
    TEST_ASSERT_EQ(count, 1, "active origin count");
    TEST_ASSERT(memcmp(hashes[0], hash1, 32) == 0, "hash matches");
    TEST_ASSERT_EQ(bridge[0], 0, "bridge_htlc_id");
    TEST_ASSERT_EQ(req[0], 3, "request_id");
    TEST_ASSERT_EQ(senders[0], 1, "sender_idx");
    TEST_ASSERT_EQ(htlc_ids[0], 7, "sender_htlc_id");

    persist_close(&db);
    return 1;
}

/* ---- Test: Client invoice round-trip ---- */

int test_persist_client_invoice_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    unsigned char hash0[32], preimage0[32];
    unsigned char hash1[32], preimage1[32];
    memset(hash0, 0xD0, 32); memset(preimage0, 0xE0, 32);
    memset(hash1, 0xD1, 32); memset(preimage1, 0xE1, 32);

    TEST_ASSERT(persist_save_client_invoice(&db, hash0, preimage0, 10000),
                "save client invoice 0");
    TEST_ASSERT(persist_save_client_invoice(&db, hash1, preimage1, 5000),
                "save client invoice 1");

    /* Deactivate first */
    TEST_ASSERT(persist_deactivate_client_invoice(&db, hash0),
                "deactivate client invoice 0");

    /* Load active */
    unsigned char hashes[8][32], preimages[8][32];
    uint64_t amounts[8];
    size_t count = persist_load_client_invoices(&db, hashes, preimages, amounts, 8);
    TEST_ASSERT_EQ(count, 1, "active client invoice count");
    TEST_ASSERT(memcmp(hashes[0], hash1, 32) == 0, "hash matches");
    TEST_ASSERT(memcmp(preimages[0], preimage1, 32) == 0, "preimage matches");
    TEST_ASSERT_EQ(amounts[0], 5000, "amount matches");

    persist_close(&db);
    return 1;
}

/* ---- Test: ID counter round-trip ---- */

int test_persist_counter_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    TEST_ASSERT(persist_save_counter(&db, "next_request_id", 5), "save counter");

    uint64_t val = persist_load_counter(&db, "next_request_id", 0);
    TEST_ASSERT_EQ(val, 5, "counter value");

    /* Overwrite */
    TEST_ASSERT(persist_save_counter(&db, "next_request_id", 42), "overwrite counter");
    val = persist_load_counter(&db, "next_request_id", 0);
    TEST_ASSERT_EQ(val, 42, "updated value");

    /* Missing key returns default */
    val = persist_load_counter(&db, "nonexistent", 999);
    TEST_ASSERT_EQ(val, 999, "missing key returns default");

    /* Multiple counters */
    TEST_ASSERT(persist_save_counter(&db, "next_htlc_id", 100), "save htlc counter");
    val = persist_load_counter(&db, "next_htlc_id", 0);
    TEST_ASSERT_EQ(val, 100, "htlc counter value");

    /* First counter still intact */
    val = persist_load_counter(&db, "next_request_id", 0);
    TEST_ASSERT_EQ(val, 42, "first counter still correct");

    persist_close(&db);
    return 1;
}

/* ---- Test: Basepoint persistence round-trip ---- */

int test_persist_basepoints(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    secp256k1_context *ctx = test_ctx();

    /* Create a channel with known basepoint secrets */
    secp256k1_pubkey local_pk, remote_pk;
    if (!secp256k1_ec_pubkey_create(ctx, &local_pk, seckeys[0])) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &remote_pk, seckeys[1])) return 0;

    /* Build funding SPK */
    secp256k1_pubkey pks[2] = { local_pk, remote_pk };
    musig_keyagg_t ka;
    TEST_ASSERT(musig_aggregate_keys(ctx, &ka, pks, 2), "keyagg");
    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    unsigned char twk[32];
    sha256_tagged("TapTweak", internal_ser, 32, twk);
    musig_keyagg_t ka2 = ka;
    secp256k1_pubkey tweaked;
    TEST_ASSERT(secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked, &ka2.cache, twk), "tweak");
    secp256k1_xonly_pubkey twx;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &twx, NULL, &tweaked)) return 0;
    unsigned char spk[34];
    build_p2tr_script_pubkey(spk, &twx);

    unsigned char txid[32] = {0};
    channel_t ch;
    TEST_ASSERT(channel_init(&ch, ctx, seckeys[0], &local_pk, &remote_pk,
                              txid, 0, 100000, spk, 34, 40000, 40000,
                              CHANNEL_DEFAULT_CSV_DELAY), "init ch");

    /* Set local basepoints with known secrets */
    unsigned char pay_sec[32] = { [0 ... 31] = 0xAA };
    unsigned char delay_sec[32] = { [0 ... 31] = 0xBB };
    unsigned char revoc_sec[32] = { [0 ... 31] = 0xCC };
    unsigned char htlc_sec[32] = { [0 ... 31] = 0xDD };
    channel_set_local_basepoints(&ch, pay_sec, delay_sec, revoc_sec);
    channel_set_local_htlc_basepoint(&ch, htlc_sec);

    /* Set remote basepoints */
    secp256k1_pubkey rpay, rdelay, rrevoc, rhtlc;
    unsigned char rsec1[32] = { [0 ... 31] = 0x61 };
    unsigned char rsec2[32] = { [0 ... 31] = 0x71 };
    unsigned char rsec3[32] = { [0 ... 31] = 0x81 };
    unsigned char rsec4[32] = { [0 ... 31] = 0x91 };
    if (!secp256k1_ec_pubkey_create(ctx, &rpay, rsec1)) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &rdelay, rsec2)) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &rrevoc, rsec3)) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &rhtlc, rsec4)) return 0;
    channel_set_remote_basepoints(&ch, &rpay, &rdelay, &rrevoc);
    channel_set_remote_htlc_basepoint(&ch, &rhtlc);

    /* Save */
    TEST_ASSERT(persist_save_basepoints(&db, 0, &ch), "save basepoints");

    /* Load */
    unsigned char loaded_local[4][32];
    unsigned char loaded_remote[4][33];
    TEST_ASSERT(persist_load_basepoints(&db, 0, loaded_local, loaded_remote),
                "load basepoints");

    /* Verify local secrets */
    TEST_ASSERT(memcmp(loaded_local[0], pay_sec, 32) == 0, "pay secret match");
    TEST_ASSERT(memcmp(loaded_local[1], delay_sec, 32) == 0, "delay secret match");
    TEST_ASSERT(memcmp(loaded_local[2], revoc_sec, 32) == 0, "revoc secret match");
    TEST_ASSERT(memcmp(loaded_local[3], htlc_sec, 32) == 0, "htlc secret match");

    /* Verify remote pubkeys */
    unsigned char expected_remote[33];
    size_t slen = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, expected_remote, &slen, &rpay, SECP256K1_EC_COMPRESSED)) return 0;
    TEST_ASSERT(memcmp(loaded_remote[0], expected_remote, 33) == 0, "remote pay bp match");

    slen = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, expected_remote, &slen, &rdelay, SECP256K1_EC_COMPRESSED)) return 0;
    TEST_ASSERT(memcmp(loaded_remote[1], expected_remote, 33) == 0, "remote delay bp match");

    slen = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, expected_remote, &slen, &rrevoc, SECP256K1_EC_COMPRESSED)) return 0;
    TEST_ASSERT(memcmp(loaded_remote[2], expected_remote, 33) == 0, "remote revoc bp match");

    slen = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, expected_remote, &slen, &rhtlc, SECP256K1_EC_COMPRESSED)) return 0;
    TEST_ASSERT(memcmp(loaded_remote[3], expected_remote, 33) == 0, "remote htlc bp match");

    /* Verify loading non-existent channel fails */
    TEST_ASSERT(!persist_load_basepoints(&db, 99, loaded_local, loaded_remote),
                "non-existent channel fails");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}

/* ---- Test: LSP recovery round-trip ---- */

int test_lsp_recovery_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    secp256k1_context *ctx = test_ctx();

    /* Create factory with 5 participants (LSP + 4 clients) */
    unsigned char extra_sec3[32], extra_sec4[32];
    memset(extra_sec3, 0x33, 32);
    memset(extra_sec4, 0x44, 32);
    secp256k1_pubkey pks[5];
    if (!secp256k1_ec_pubkey_create(ctx, &pks[0], seckeys[0])) return 0;  /* LSP */
    if (!secp256k1_ec_pubkey_create(ctx, &pks[1], seckeys[1])) return 0;  /* Client 0 */
    if (!secp256k1_ec_pubkey_create(ctx, &pks[2], seckeys[2])) return 0;  /* Client 1 */
    if (!secp256k1_ec_pubkey_create(ctx, &pks[3], extra_sec3)) return 0;  /* Client 2 */
    if (!secp256k1_ec_pubkey_create(ctx, &pks[4], extra_sec4)) return 0;  /* Client 3 */

    factory_t f;
    factory_init_from_pubkeys(&f, ctx, pks, 5, 10, 4);
    f.cltv_timeout = 200;
    f.fee_per_tx = 500;

    /* Set funding (need valid funding for channel init) */
    musig_keyagg_t ka;
    TEST_ASSERT(musig_aggregate_keys(ctx, &ka, pks, 3), "keyagg");
    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    unsigned char twk[32];
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
    factory_set_funding(&f, fake_txid, 0, 200000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* Initialize channels the normal way */
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    TEST_ASSERT(lsp_channels_init(&mgr, ctx, &f, seckeys[0], 4), "init channels");

    /* Simulate basepoint exchange: set remote basepoints */
    for (size_t c = 0; c < 4; c++) {
        channel_t *ch = &mgr.entries[c].channel;
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

    /* Simulate some payments (modify balances) - only test first 2 channels */
    mgr.entries[0].channel.local_amount = 30000;
    mgr.entries[0].channel.remote_amount = 50000;
    mgr.entries[0].channel.commitment_number = 5;
    mgr.entries[1].channel.local_amount = 35000;
    mgr.entries[1].channel.remote_amount = 45000;
    mgr.entries[1].channel.commitment_number = 3;

    /* Persist: factory, channels, basepoints */
    TEST_ASSERT(persist_begin(&db), "begin");
    TEST_ASSERT(persist_save_factory(&db, &f, ctx, 0), "save factory");
    for (size_t c = 0; c < 4; c++) {
        TEST_ASSERT(persist_save_channel(&db, &mgr.entries[c].channel, 0,
                                           (uint32_t)c), "save channel");
        TEST_ASSERT(persist_save_basepoints(&db, (uint32_t)c,
                                              &mgr.entries[c].channel),
                    "save basepoints");
    }
    /* Update balances after payments */
    for (size_t c = 0; c < 4; c++) {
        const channel_t *ch = &mgr.entries[c].channel;
        TEST_ASSERT(persist_update_channel_balance(&db, (uint32_t)c,
                        ch->local_amount, ch->remote_amount,
                        ch->commitment_number), "update balance");
    }

    /* Save an active HTLC on channel 0 for recovery testing */
    {
        htlc_t test_htlc;
        memset(&test_htlc, 0, sizeof(test_htlc));
        test_htlc.id = 42;
        test_htlc.direction = HTLC_OFFERED;
        test_htlc.state = HTLC_STATE_ACTIVE;
        test_htlc.amount_sats = 2500;
        memset(test_htlc.payment_hash, 0xDD, 32);
        test_htlc.cltv_expiry = 700;
        TEST_ASSERT(persist_save_htlc(&db, 0, &test_htlc), "save test htlc");

        /* Also save a fulfilled HTLC — should NOT be loaded on recovery */
        htlc_t dead_htlc;
        memset(&dead_htlc, 0, sizeof(dead_htlc));
        dead_htlc.id = 43;
        dead_htlc.direction = HTLC_OFFERED;
        dead_htlc.state = HTLC_STATE_FULFILLED;
        dead_htlc.amount_sats = 1000;
        memset(dead_htlc.payment_hash, 0xEE, 32);
        dead_htlc.cltv_expiry = 800;
        TEST_ASSERT(persist_save_htlc(&db, 0, &dead_htlc), "save dead htlc");
    }
    TEST_ASSERT(persist_commit(&db), "commit");

    /* Now recover: load factory from DB, init channels from DB */
    factory_t rec_f;
    memset(&rec_f, 0, sizeof(rec_f));
    TEST_ASSERT(persist_load_factory(&db, 0, &rec_f, ctx), "load factory");
    TEST_ASSERT_EQ(rec_f.n_participants, 5, "n_participants");

    lsp_channel_mgr_t rec_mgr;
    memset(&rec_mgr, 0, sizeof(rec_mgr));
    TEST_ASSERT(lsp_channels_init_from_db(&rec_mgr, ctx, &rec_f,
                                            seckeys[0], 4, &db),
                "init from db");
    TEST_ASSERT_EQ(rec_mgr.n_channels, 4, "n_channels");

    /* Verify ALL 4 channels recovered correctly */
    for (size_t c = 0; c < 4; c++) {
        const channel_t *orig = &mgr.entries[c].channel;
        const channel_t *rec = &rec_mgr.entries[c].channel;

        TEST_ASSERT_EQ(rec->local_amount, orig->local_amount, "local_amount");
        TEST_ASSERT_EQ(rec->remote_amount, orig->remote_amount, "remote_amount");
        TEST_ASSERT_EQ(rec->commitment_number, orig->commitment_number,
                        "commitment_number");

        /* Verify local basepoint secrets match */
        TEST_ASSERT(memcmp(rec->local_payment_basepoint_secret,
                           orig->local_payment_basepoint_secret, 32) == 0,
                    "pay secret match");
        TEST_ASSERT(memcmp(rec->local_delayed_payment_basepoint_secret,
                           orig->local_delayed_payment_basepoint_secret, 32) == 0,
                    "delay secret match");
        TEST_ASSERT(memcmp(rec->local_revocation_basepoint_secret,
                           orig->local_revocation_basepoint_secret, 32) == 0,
                    "revoc secret match");
        TEST_ASSERT(memcmp(rec->local_htlc_basepoint_secret,
                           orig->local_htlc_basepoint_secret, 32) == 0,
                    "htlc secret match");

        /* Verify ALL 4 remote basepoint pubkeys match */
        unsigned char orig_ser[33], rec_ser[33];
        size_t slen;

        slen = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, orig_ser, &slen,
            &orig->remote_payment_basepoint, SECP256K1_EC_COMPRESSED)) return 0;
        slen = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, rec_ser, &slen,
            &rec->remote_payment_basepoint, SECP256K1_EC_COMPRESSED)) return 0;
        TEST_ASSERT(memcmp(orig_ser, rec_ser, 33) == 0, "remote pay bp");

        slen = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, orig_ser, &slen,
            &orig->remote_delayed_payment_basepoint, SECP256K1_EC_COMPRESSED)) return 0;
        slen = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, rec_ser, &slen,
            &rec->remote_delayed_payment_basepoint, SECP256K1_EC_COMPRESSED)) return 0;
        TEST_ASSERT(memcmp(orig_ser, rec_ser, 33) == 0, "remote delay bp");

        slen = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, orig_ser, &slen,
            &orig->remote_revocation_basepoint, SECP256K1_EC_COMPRESSED)) return 0;
        slen = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, rec_ser, &slen,
            &rec->remote_revocation_basepoint, SECP256K1_EC_COMPRESSED)) return 0;
        TEST_ASSERT(memcmp(orig_ser, rec_ser, 33) == 0, "remote revoc bp");

        slen = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, orig_ser, &slen,
            &orig->remote_htlc_basepoint, SECP256K1_EC_COMPRESSED)) return 0;
        slen = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, rec_ser, &slen,
            &rec->remote_htlc_basepoint, SECP256K1_EC_COMPRESSED)) return 0;
        TEST_ASSERT(memcmp(orig_ser, rec_ser, 33) == 0, "remote htlc bp");

        /* Verify channel is marked ready */
        TEST_ASSERT_EQ(rec_mgr.entries[c].ready, 1, "channel ready");
    }

    /* Verify HTLC recovery: channel 0 should have 1 active HTLC (not the fulfilled one) */
    TEST_ASSERT_EQ(rec_mgr.entries[0].channel.n_htlcs, 1, "ch0 htlc count");
    TEST_ASSERT_EQ(rec_mgr.entries[0].channel.htlcs[0].id, 42, "ch0 htlc id");
    TEST_ASSERT_EQ(rec_mgr.entries[0].channel.htlcs[0].amount_sats, 2500, "ch0 htlc amount");
    TEST_ASSERT_EQ(rec_mgr.entries[0].channel.htlcs[0].state, HTLC_STATE_ACTIVE, "ch0 htlc state");
    {
        unsigned char expected_hash[32];
        memset(expected_hash, 0xDD, 32);
        TEST_ASSERT(memcmp(rec_mgr.entries[0].channel.htlcs[0].payment_hash,
                           expected_hash, 32) == 0, "ch0 htlc hash");
    }

    /* Channel 1 should have no HTLCs */
    TEST_ASSERT_EQ(rec_mgr.entries[1].channel.n_htlcs, 0, "ch1 no htlcs");

    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}

/* ---- Test: File-based persist close/reopen round-trip ---- */

int test_persist_file_reopen_round_trip(void) {
    const char *path = "/tmp/test_persist_reopen.db";
    unlink(path);  /* ensure clean slate */

    /* Phase 1: open file-based DB, save data, close */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "open file db");

        secp256k1_context *ctx = test_ctx();
        secp256k1_pubkey pk_local, pk_remote;
        if (!secp256k1_ec_pubkey_create(ctx, &pk_local, seckeys[0])) return 0;
        if (!secp256k1_ec_pubkey_create(ctx, &pk_remote, seckeys[1])) return 0;

        unsigned char fake_txid[32] = {0};
        fake_txid[0] = 0xDD;
        unsigned char fake_spk[34];
        memset(fake_spk, 0xAA, 34);

        channel_t ch;
        TEST_ASSERT(channel_init(&ch, ctx, seckeys[0], &pk_local, &pk_remote,
                                  fake_txid, 1, 100000, fake_spk, 34,
                                  45000, 55000, 144), "channel_init");
        ch.commitment_number = 7;

        TEST_ASSERT(persist_save_channel(&db, &ch, 0, 0), "save channel");
        channel_cleanup(&ch);

        /* Also save a counter and an HTLC */
        TEST_ASSERT(persist_save_counter(&db, "test_counter", 42), "save counter");

        htlc_t h = {0};
        h.direction = HTLC_OFFERED;
        h.state = HTLC_STATE_ACTIVE;
        h.amount_sats = 3000;
        memset(h.payment_hash, 0xBE, 32);
        h.cltv_expiry = 500;
        h.id = 0;
        TEST_ASSERT(persist_save_htlc(&db, 0, &h), "save htlc");

        secp256k1_context_destroy(ctx);
        persist_close(&db);
    }

    /* Phase 2: reopen from file, verify all data survived */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "reopen file db");

        /* Verify channel state */
        uint64_t local, remote, commit;
        TEST_ASSERT(persist_load_channel_state(&db, 0, &local, &remote, &commit),
                    "load channel after reopen");
        TEST_ASSERT_EQ(local, 45000, "local_amount after reopen");
        TEST_ASSERT_EQ(remote, 55000, "remote_amount after reopen");
        TEST_ASSERT_EQ(commit, 7, "commitment_number after reopen");

        /* Verify counter */
        uint64_t val = persist_load_counter(&db, "test_counter", 0);
        TEST_ASSERT_EQ(val, 42, "counter after reopen");

        /* Verify HTLC */
        htlc_t loaded[16];
        size_t count = persist_load_htlcs(&db, 0, loaded, 16);
        TEST_ASSERT_EQ(count, 1, "htlc count after reopen");
        TEST_ASSERT_EQ(loaded[0].amount_sats, 3000, "htlc amount after reopen");
        TEST_ASSERT_EQ(loaded[0].cltv_expiry, 500, "htlc cltv after reopen");
        {
            unsigned char expected[32];
            memset(expected, 0xBE, 32);
            TEST_ASSERT(memcmp(loaded[0].payment_hash, expected, 32) == 0,
                        "htlc hash after reopen");
        }

        persist_close(&db);
    }

    unlink(path);  /* cleanup */
    return 1;
}

/* ---- Test: DW counter with N leaf states (arity-1 support) ---- */

int test_persist_dw_counter_with_leaves_4(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    /* Save with 4 leaf states (arity-1: 4 clients) */
    uint32_t layers[] = {5, 2, 1};
    uint32_t leaf_states[] = {3, 0, 7, 2};
    TEST_ASSERT(persist_save_dw_counter_with_leaves(&db, 42, 10, 3, layers,
                                                      1, leaf_states, 4),
                "save with 4 leaves");

    /* Load and verify */
    uint32_t epoch, n_layers;
    uint32_t loaded_layers[8];
    int per_leaf_enabled;
    uint32_t loaded_leaves[8];
    int n_leaf_nodes;
    TEST_ASSERT(persist_load_dw_counter_with_leaves(&db, 42, &epoch, &n_layers,
                                                      loaded_layers, 8,
                                                      &per_leaf_enabled,
                                                      loaded_leaves, &n_leaf_nodes, 8),
                "load with 4 leaves");

    TEST_ASSERT_EQ(epoch, 10, "epoch");
    TEST_ASSERT_EQ(n_layers, 3, "n_layers");
    TEST_ASSERT_EQ(loaded_layers[0], 5, "layer 0");
    TEST_ASSERT_EQ(loaded_layers[1], 2, "layer 1");
    TEST_ASSERT_EQ(loaded_layers[2], 1, "layer 2");
    TEST_ASSERT_EQ(per_leaf_enabled, 1, "per_leaf enabled");
    TEST_ASSERT_EQ(n_leaf_nodes, 4, "n_leaf_nodes");
    TEST_ASSERT_EQ(loaded_leaves[0], 3, "leaf 0");
    TEST_ASSERT_EQ(loaded_leaves[1], 0, "leaf 1");
    TEST_ASSERT_EQ(loaded_leaves[2], 7, "leaf 2");
    TEST_ASSERT_EQ(loaded_leaves[3], 2, "leaf 3");

    /* Overwrite with 2 leaf states (arity-2 compatibility) */
    uint32_t layers2[] = {1, 0};
    uint32_t leaf_states2[] = {4, 6};
    TEST_ASSERT(persist_save_dw_counter_with_leaves(&db, 42, 5, 2, layers2,
                                                      1, leaf_states2, 2),
                "save with 2 leaves");

    TEST_ASSERT(persist_load_dw_counter_with_leaves(&db, 42, &epoch, &n_layers,
                                                      loaded_layers, 8,
                                                      &per_leaf_enabled,
                                                      loaded_leaves, &n_leaf_nodes, 8),
                "load with 2 leaves");
    TEST_ASSERT_EQ(n_leaf_nodes, 2, "n_leaf_nodes after overwrite");
    TEST_ASSERT_EQ(loaded_leaves[0], 4, "leaf 0 after overwrite");
    TEST_ASSERT_EQ(loaded_leaves[1], 6, "leaf 1 after overwrite");

    /* Save with per_leaf disabled */
    TEST_ASSERT(persist_save_dw_counter_with_leaves(&db, 42, 0, 2, layers2,
                                                      0, NULL, 0),
                "save with per_leaf disabled");
    TEST_ASSERT(persist_load_dw_counter_with_leaves(&db, 42, &epoch, &n_layers,
                                                      loaded_layers, 8,
                                                      &per_leaf_enabled,
                                                      loaded_leaves, &n_leaf_nodes, 8),
                "load with per_leaf disabled");
    TEST_ASSERT_EQ(per_leaf_enabled, 0, "per_leaf disabled");

    persist_close(&db);
    return 1;
}

/* --- Schema Versioning (Phase 2: item 2.2) --- */

int test_persist_schema_version(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open in-memory");

    /* Fresh DB should have version PERSIST_SCHEMA_VERSION (1) */
    int ver = persist_schema_version(&db);
    TEST_ASSERT_EQ(ver, PERSIST_SCHEMA_VERSION, "fresh db version");

    persist_close(&db);
    return 1;
}

int test_persist_schema_future_reject(void) {
    /* Create a temporary file DB, inject future version, close, reopen → reject */
    const char *tmp_path = "/tmp/test_schema_future.db";
    unlink(tmp_path);

    persist_t db;
    TEST_ASSERT(persist_open(&db, tmp_path), "open tmp");

    /* Inject a future version row */
    int rc = sqlite3_exec(db.db,
        "INSERT INTO schema_version (version) VALUES (999);",
        NULL, NULL, NULL);
    TEST_ASSERT(rc == SQLITE_OK, "inject future version");
    persist_close(&db);

    /* Reopen should fail: DB version 999 > code version */
    persist_t db2;
    int opened = persist_open(&db2, tmp_path);
    TEST_ASSERT(opened == 0, "future version rejected");

    unlink(tmp_path);
    return 1;
}

/* --- Data Validation on Load (Phase 2: item 2.6) --- */

int test_persist_validate_factory_load(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");
    secp256k1_context *ctx = test_ctx();

    /* Insert invalid factory: n_participants = 1 (too low, need >= 2) */
    int rc = sqlite3_exec(db.db,
        "INSERT INTO factories (id, n_participants, funding_txid, funding_vout, "
        "funding_amount, step_blocks, states_per_layer, cltv_timeout, fee_per_tx, leaf_arity) "
        "VALUES (10, 1, '00', 0, 100000, 10, 8, 200, 500, 2);",
        NULL, NULL, NULL);
    TEST_ASSERT(rc == SQLITE_OK, "insert invalid factory");

    factory_t f;
    memset(&f, 0, sizeof(f));
    int loaded = persist_load_factory(&db, 10, &f, ctx);
    TEST_ASSERT(loaded == 0, "n_participants=1 rejected");

    /* Insert factory with funding_amount = 0 */
    rc = sqlite3_exec(db.db,
        "INSERT OR REPLACE INTO factories (id, n_participants, funding_txid, "
        "funding_vout, funding_amount, step_blocks, states_per_layer, "
        "cltv_timeout, fee_per_tx, leaf_arity) "
        "VALUES (11, 5, '00', 0, 0, 10, 8, 200, 500, 2);",
        NULL, NULL, NULL);
    TEST_ASSERT(rc == SQLITE_OK, "insert zero-amount factory");
    loaded = persist_load_factory(&db, 11, &f, ctx);
    TEST_ASSERT(loaded == 0, "funding_amount=0 rejected");

    /* Insert factory with states_per_layer = 0 */
    rc = sqlite3_exec(db.db,
        "INSERT OR REPLACE INTO factories (id, n_participants, funding_txid, "
        "funding_vout, funding_amount, step_blocks, states_per_layer, "
        "cltv_timeout, fee_per_tx, leaf_arity) "
        "VALUES (12, 5, '00', 0, 100000, 10, 0, 200, 500, 2);",
        NULL, NULL, NULL);
    TEST_ASSERT(rc == SQLITE_OK, "insert zero-states factory");
    loaded = persist_load_factory(&db, 12, &f, ctx);
    TEST_ASSERT(loaded == 0, "states_per_layer=0 rejected");

    /* Insert factory with step_blocks = 0 */
    rc = sqlite3_exec(db.db,
        "INSERT OR REPLACE INTO factories (id, n_participants, funding_txid, "
        "funding_vout, funding_amount, step_blocks, states_per_layer, "
        "cltv_timeout, fee_per_tx, leaf_arity) "
        "VALUES (13, 5, '00', 0, 100000, 0, 8, 200, 500, 2);",
        NULL, NULL, NULL);
    TEST_ASSERT(rc == SQLITE_OK, "insert zero-step factory");
    loaded = persist_load_factory(&db, 13, &f, ctx);
    TEST_ASSERT(loaded == 0, "step_blocks=0 rejected");

    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}

int test_persist_validate_channel_load(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    /* High commitment numbers are now valid (no upper bound) */
    int rc = sqlite3_exec(db.db,
        "INSERT INTO channels (id, factory_id, slot, local_amount, remote_amount, "
        "funding_amount, commitment_number) VALUES (100, 0, 0, 50000, 50000, "
        "100000, 999);",
        NULL, NULL, NULL);
    TEST_ASSERT(rc == SQLITE_OK, "insert high cn channel");

    uint64_t la, ra, cn;
    int loaded = persist_load_channel_state(&db, 100, &la, &ra, &cn);
    TEST_ASSERT(loaded == 1, "high commitment_number accepted");
    TEST_ASSERT(cn == 999, "commitment_number is 999");

    /* Insert a channel with both balances zero */
    rc = sqlite3_exec(db.db,
        "INSERT INTO channels (id, factory_id, slot, local_amount, remote_amount, "
        "funding_amount, commitment_number) VALUES (101, 0, 1, 0, 0, 100000, 0);",
        NULL, NULL, NULL);
    TEST_ASSERT(rc == SQLITE_OK, "insert zero-balance channel");
    loaded = persist_load_channel_state(&db, 101, &la, &ra, &cn);
    TEST_ASSERT(loaded == 0, "total balance=0 rejected");

    /* Insert a valid channel — should pass */
    rc = sqlite3_exec(db.db,
        "INSERT INTO channels (id, factory_id, slot, local_amount, remote_amount, "
        "funding_amount, commitment_number) VALUES (102, 0, 2, 50000, 50000, "
        "100000, 5);",
        NULL, NULL, NULL);
    TEST_ASSERT(rc == SQLITE_OK, "insert valid channel");
    loaded = persist_load_channel_state(&db, 102, &la, &ra, &cn);
    TEST_ASSERT(loaded == 1, "valid channel loads");
    TEST_ASSERT_EQ(la, (uint64_t)50000, "local amount");
    TEST_ASSERT_EQ(ra, (uint64_t)50000, "remote amount");
    TEST_ASSERT_EQ(cn, (uint64_t)5, "commitment number");

    persist_close(&db);
    return 1;
}

/* ---- Test: Crash stress — 4 cycles of persist/crash/recover on file-based DB ---- */

int test_persist_crash_stress(void) {
    const char *path = "/tmp/test_crash_stress.db";
    unlink(path);

    secp256k1_context *ctx = test_ctx();

    /* Create factory with 5 participants (LSP + 4 clients) */
    unsigned char extra_sec3[32], extra_sec4[32];
    memset(extra_sec3, 0x33, 32);
    memset(extra_sec4, 0x44, 32);
    secp256k1_pubkey pks[5];
    if (!secp256k1_ec_pubkey_create(ctx, &pks[0], seckeys[0])) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pks[1], seckeys[1])) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pks[2], seckeys[2])) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pks[3], extra_sec3)) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pks[4], extra_sec4)) return 0;

    factory_t f;
    factory_init_from_pubkeys(&f, ctx, pks, 5, 10, 4);
    f.cltv_timeout = 200;
    f.fee_per_tx = 500;

    /* Compute funding SPK */
    musig_keyagg_t ka;
    TEST_ASSERT(musig_aggregate_keys(ctx, &ka, pks, 3), "keyagg");
    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    unsigned char twk[32];
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
    factory_set_funding(&f, fake_txid, 0, 200000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* Initialize channels */
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    TEST_ASSERT(lsp_channels_init(&mgr, ctx, &f, seckeys[0], 4), "init channels");

    /* Simulate basepoint exchange */
    for (size_t c = 0; c < 4; c++) {
        channel_t *ch = &mgr.entries[c].channel;
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

    /* ===== Cycle 1: Fresh state ===== */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "c1 open");
        TEST_ASSERT(persist_begin(&db), "c1 begin");
        TEST_ASSERT(persist_save_factory(&db, &f, ctx, 0), "c1 save factory");
        for (size_t c = 0; c < 4; c++) {
            TEST_ASSERT(persist_save_channel(&db, &mgr.entries[c].channel, 0,
                                               (uint32_t)c), "c1 save ch");
            TEST_ASSERT(persist_save_basepoints(&db, (uint32_t)c,
                                                  &mgr.entries[c].channel),
                        "c1 save bp");
            const channel_t *ch = &mgr.entries[c].channel;
            TEST_ASSERT(persist_update_channel_balance(&db, (uint32_t)c,
                            ch->local_amount, ch->remote_amount,
                            ch->commitment_number), "c1 update bal");
        }
        TEST_ASSERT(persist_commit(&db), "c1 commit");
        persist_close(&db);
    }

    /* Save original state for comparison */
    uint64_t orig_local[4], orig_remote[4], orig_cn[4];
    unsigned char orig_bp_pay[4][32], orig_bp_delay[4][32];
    unsigned char orig_bp_revoc[4][32], orig_bp_htlc[4][32];
    for (size_t c = 0; c < 4; c++) {
        const channel_t *ch = &mgr.entries[c].channel;
        orig_local[c] = ch->local_amount;
        orig_remote[c] = ch->remote_amount;
        orig_cn[c] = ch->commitment_number;
        memcpy(orig_bp_pay[c], ch->local_payment_basepoint_secret, 32);
        memcpy(orig_bp_delay[c], ch->local_delayed_payment_basepoint_secret, 32);
        memcpy(orig_bp_revoc[c], ch->local_revocation_basepoint_secret, 32);
        memcpy(orig_bp_htlc[c], ch->local_htlc_basepoint_secret, 32);
    }

    /* Zero everything */
    memset(&mgr, 0, sizeof(mgr));
    memset(&f, 0, sizeof(f));

    /* Recover cycle 1 */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "c1 reopen");
        factory_t rec_f;
        memset(&rec_f, 0, sizeof(rec_f));
        TEST_ASSERT(persist_load_factory(&db, 0, &rec_f, ctx), "c1 load factory");
        TEST_ASSERT_EQ(rec_f.n_participants, 5, "c1 n_participants");

        lsp_channel_mgr_t rec_mgr;
        memset(&rec_mgr, 0, sizeof(rec_mgr));
        TEST_ASSERT(lsp_channels_init_from_db(&rec_mgr, ctx, &rec_f,
                                                seckeys[0], 4, &db),
                    "c1 init from db");
        TEST_ASSERT_EQ(rec_mgr.n_channels, 4, "c1 n_channels");

        for (size_t c = 0; c < 4; c++) {
            const channel_t *rec = &rec_mgr.entries[c].channel;
            TEST_ASSERT_EQ(rec->local_amount, orig_local[c], "c1 local");
            TEST_ASSERT_EQ(rec->remote_amount, orig_remote[c], "c1 remote");
            TEST_ASSERT_EQ(rec->commitment_number, orig_cn[c], "c1 cn");
            TEST_ASSERT(memcmp(rec->local_payment_basepoint_secret,
                               orig_bp_pay[c], 32) == 0, "c1 pay secret");
            TEST_ASSERT(memcmp(rec->local_delayed_payment_basepoint_secret,
                               orig_bp_delay[c], 32) == 0, "c1 delay secret");
            TEST_ASSERT(memcmp(rec->local_revocation_basepoint_secret,
                               orig_bp_revoc[c], 32) == 0, "c1 revoc secret");
            TEST_ASSERT(memcmp(rec->local_htlc_basepoint_secret,
                               orig_bp_htlc[c], 32) == 0, "c1 htlc secret");
        }

        /* Copy recovered state into mgr/f for next cycle */
        memcpy(&mgr, &rec_mgr, sizeof(mgr));
        memcpy(&f, &rec_f, sizeof(f));
        persist_close(&db);
    }

    /* ===== Cycle 2: Payments + active HTLCs ===== */
    mgr.entries[0].channel.local_amount += 5000;
    mgr.entries[0].channel.remote_amount -= 5000;
    mgr.entries[0].channel.commitment_number = 2;
    mgr.entries[1].channel.local_amount -= 3000;
    mgr.entries[1].channel.remote_amount += 3000;
    mgr.entries[1].channel.commitment_number = 1;

    /* Add active HTLCs */
    {
        htlc_t h0 = {0};
        h0.direction = HTLC_OFFERED; h0.state = HTLC_STATE_ACTIVE;
        h0.id = 1; h0.amount_sats = 2500; h0.cltv_expiry = 600;
        memset(h0.payment_hash, 0xAA, 32);
        mgr.entries[0].channel.htlcs[mgr.entries[0].channel.n_htlcs++] = h0;

        htlc_t h1 = {0};
        h1.direction = HTLC_RECEIVED; h1.state = HTLC_STATE_ACTIVE;
        h1.id = 2; h1.amount_sats = 4000; h1.cltv_expiry = 700;
        memset(h1.payment_hash, 0xBB, 32);
        mgr.entries[1].channel.htlcs[mgr.entries[1].channel.n_htlcs++] = h1;

        htlc_t h2 = {0};
        h2.direction = HTLC_OFFERED; h2.state = HTLC_STATE_ACTIVE;
        h2.id = 3; h2.amount_sats = 1500; h2.cltv_expiry = 800;
        memset(h2.payment_hash, 0xCC, 32);
        mgr.entries[2].channel.htlcs[mgr.entries[2].channel.n_htlcs++] = h2;

        /* Fulfilled HTLC on ch0 — should be filtered on recovery */
        htlc_t hf = {0};
        hf.direction = HTLC_OFFERED; hf.state = HTLC_STATE_FULFILLED;
        hf.id = 99; hf.amount_sats = 1000; hf.cltv_expiry = 500;
        memset(hf.payment_hash, 0xFF, 32);
        mgr.entries[0].channel.htlcs[mgr.entries[0].channel.n_htlcs++] = hf;
    }

    /* Save expected state */
    uint64_t c2_local[4], c2_remote[4], c2_cn[4];
    for (size_t c = 0; c < 4; c++) {
        c2_local[c] = mgr.entries[c].channel.local_amount;
        c2_remote[c] = mgr.entries[c].channel.remote_amount;
        c2_cn[c] = mgr.entries[c].channel.commitment_number;
    }

    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "c2 open");
        TEST_ASSERT(persist_begin(&db), "c2 begin");
        for (size_t c = 0; c < 4; c++) {
            const channel_t *ch = &mgr.entries[c].channel;
            TEST_ASSERT(persist_update_channel_balance(&db, (uint32_t)c,
                            ch->local_amount, ch->remote_amount,
                            ch->commitment_number), "c2 update bal");
        }
        /* Save HTLCs: 3 active + 1 fulfilled */
        for (size_t c = 0; c < 3; c++) {
            for (size_t h = 0; h < mgr.entries[c].channel.n_htlcs; h++) {
                TEST_ASSERT(persist_save_htlc(&db, (uint32_t)c,
                                &mgr.entries[c].channel.htlcs[h]), "c2 save htlc");
            }
        }
        TEST_ASSERT(persist_commit(&db), "c2 commit");
        persist_close(&db);
    }

    memset(&mgr, 0, sizeof(mgr));
    memset(&f, 0, sizeof(f));

    /* Recover cycle 2 */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "c2 reopen");
        factory_t rec_f;
        memset(&rec_f, 0, sizeof(rec_f));
        TEST_ASSERT(persist_load_factory(&db, 0, &rec_f, ctx), "c2 load factory");

        lsp_channel_mgr_t rec_mgr;
        memset(&rec_mgr, 0, sizeof(rec_mgr));
        TEST_ASSERT(lsp_channels_init_from_db(&rec_mgr, ctx, &rec_f,
                                                seckeys[0], 4, &db),
                    "c2 init from db");
        TEST_ASSERT_EQ(rec_mgr.n_channels, 4, "c2 n_channels");

        for (size_t c = 0; c < 4; c++) {
            TEST_ASSERT_EQ(rec_mgr.entries[c].channel.local_amount,
                           c2_local[c], "c2 local");
            TEST_ASSERT_EQ(rec_mgr.entries[c].channel.remote_amount,
                           c2_remote[c], "c2 remote");
            TEST_ASSERT_EQ(rec_mgr.entries[c].channel.commitment_number,
                           c2_cn[c], "c2 cn");
        }

        /* ch0: 1 active HTLC (fulfilled filtered out) */
        TEST_ASSERT_EQ(rec_mgr.entries[0].channel.n_htlcs, 1, "c2 ch0 htlc count");
        TEST_ASSERT_EQ(rec_mgr.entries[0].channel.htlcs[0].id, 1, "c2 ch0 htlc id");
        TEST_ASSERT_EQ(rec_mgr.entries[0].channel.htlcs[0].amount_sats, 2500, "c2 ch0 htlc amt");
        {
            unsigned char exp[32]; memset(exp, 0xAA, 32);
            TEST_ASSERT(memcmp(rec_mgr.entries[0].channel.htlcs[0].payment_hash,
                               exp, 32) == 0, "c2 ch0 htlc hash");
        }
        /* ch1: 1 active HTLC */
        TEST_ASSERT_EQ(rec_mgr.entries[1].channel.n_htlcs, 1, "c2 ch1 htlc count");
        TEST_ASSERT_EQ(rec_mgr.entries[1].channel.htlcs[0].id, 2, "c2 ch1 htlc id");
        /* ch2: 1 active HTLC */
        TEST_ASSERT_EQ(rec_mgr.entries[2].channel.n_htlcs, 1, "c2 ch2 htlc count");
        TEST_ASSERT_EQ(rec_mgr.entries[2].channel.htlcs[0].id, 3, "c2 ch2 htlc id");
        /* ch3: 0 HTLCs */
        TEST_ASSERT_EQ(rec_mgr.entries[3].channel.n_htlcs, 0, "c2 ch3 htlc count");

        memcpy(&mgr, &rec_mgr, sizeof(mgr));
        memcpy(&f, &rec_f, sizeof(f));
        persist_close(&db);
    }

    /* ===== Cycle 3: HTLC resolution + new HTLCs ===== */
    mgr.entries[0].channel.local_amount += 2500;
    mgr.entries[0].channel.remote_amount -= 2500;
    mgr.entries[0].channel.commitment_number = 4;

    /* ch3: add 2 new active HTLCs */
    {
        htlc_t h10 = {0};
        h10.direction = HTLC_OFFERED; h10.state = HTLC_STATE_ACTIVE;
        h10.id = 10; h10.amount_sats = 8000; h10.cltv_expiry = 900;
        memset(h10.payment_hash, 0xD0, 32);
        mgr.entries[3].channel.htlcs[mgr.entries[3].channel.n_htlcs++] = h10;

        htlc_t h11 = {0};
        h11.direction = HTLC_RECEIVED; h11.state = HTLC_STATE_ACTIVE;
        h11.id = 11; h11.amount_sats = 6000; h11.cltv_expiry = 950;
        memset(h11.payment_hash, 0xD1, 32);
        mgr.entries[3].channel.htlcs[mgr.entries[3].channel.n_htlcs++] = h11;
    }

    /* Remove resolved HTLCs from local state */
    mgr.entries[0].channel.n_htlcs = 0;
    mgr.entries[1].channel.n_htlcs = 0;

    uint64_t c3_local[4], c3_remote[4], c3_cn[4];
    for (size_t c = 0; c < 4; c++) {
        c3_local[c] = mgr.entries[c].channel.local_amount;
        c3_remote[c] = mgr.entries[c].channel.remote_amount;
        c3_cn[c] = mgr.entries[c].channel.commitment_number;
    }

    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "c3 open");
        TEST_ASSERT(persist_begin(&db), "c3 begin");
        for (size_t c = 0; c < 4; c++) {
            const channel_t *ch = &mgr.entries[c].channel;
            TEST_ASSERT(persist_update_channel_balance(&db, (uint32_t)c,
                            ch->local_amount, ch->remote_amount,
                            ch->commitment_number), "c3 update bal");
        }
        /* Delete resolved HTLCs */
        TEST_ASSERT(persist_delete_htlc(&db, 0, 1), "c3 del htlc 0/1");
        TEST_ASSERT(persist_delete_htlc(&db, 1, 2), "c3 del htlc 1/2");
        /* Save new HTLCs on ch3 */
        for (size_t h = 0; h < mgr.entries[3].channel.n_htlcs; h++) {
            TEST_ASSERT(persist_save_htlc(&db, 3,
                            &mgr.entries[3].channel.htlcs[h]), "c3 save htlc");
        }
        TEST_ASSERT(persist_commit(&db), "c3 commit");
        persist_close(&db);
    }

    memset(&mgr, 0, sizeof(mgr));
    memset(&f, 0, sizeof(f));

    /* Recover cycle 3 */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "c3 reopen");
        factory_t rec_f;
        memset(&rec_f, 0, sizeof(rec_f));
        TEST_ASSERT(persist_load_factory(&db, 0, &rec_f, ctx), "c3 load factory");

        lsp_channel_mgr_t rec_mgr;
        memset(&rec_mgr, 0, sizeof(rec_mgr));
        TEST_ASSERT(lsp_channels_init_from_db(&rec_mgr, ctx, &rec_f,
                                                seckeys[0], 4, &db),
                    "c3 init from db");

        for (size_t c = 0; c < 4; c++) {
            TEST_ASSERT_EQ(rec_mgr.entries[c].channel.local_amount,
                           c3_local[c], "c3 local");
            TEST_ASSERT_EQ(rec_mgr.entries[c].channel.remote_amount,
                           c3_remote[c], "c3 remote");
            TEST_ASSERT_EQ(rec_mgr.entries[c].channel.commitment_number,
                           c3_cn[c], "c3 cn");
        }

        TEST_ASSERT_EQ(rec_mgr.entries[0].channel.n_htlcs, 0, "c3 ch0 0 htlcs");
        TEST_ASSERT_EQ(rec_mgr.entries[1].channel.n_htlcs, 0, "c3 ch1 0 htlcs");
        TEST_ASSERT_EQ(rec_mgr.entries[2].channel.n_htlcs, 1, "c3 ch2 1 htlc");
        TEST_ASSERT_EQ(rec_mgr.entries[2].channel.htlcs[0].id, 3, "c3 ch2 htlc id");
        TEST_ASSERT_EQ(rec_mgr.entries[3].channel.n_htlcs, 2, "c3 ch3 2 htlcs");
        TEST_ASSERT_EQ(rec_mgr.entries[3].channel.htlcs[0].id, 10, "c3 ch3 htlc0 id");
        TEST_ASSERT_EQ(rec_mgr.entries[3].channel.htlcs[1].id, 11, "c3 ch3 htlc1 id");

        memcpy(&mgr, &rec_mgr, sizeof(mgr));
        memcpy(&f, &rec_f, sizeof(f));
        persist_close(&db);
    }

    /* ===== Cycle 4: Extreme values ===== */
    uint64_t commit_fee = f.fee_per_tx;
    mgr.entries[0].channel.local_amount = 0;
    mgr.entries[0].channel.remote_amount = f.funding_amount_sats / 4 - commit_fee;
    mgr.entries[0].channel.commitment_number = 200;
    mgr.entries[1].channel.local_amount = f.funding_amount_sats / 4 - commit_fee;
    mgr.entries[1].channel.remote_amount = 0;
    mgr.entries[1].channel.commitment_number = 255;

    /* Add 8 active HTLCs on ch2 */
    mgr.entries[2].channel.n_htlcs = 0;  /* clear old HTLC */
    for (int i = 0; i < 8; i++) {
        htlc_t h = {0};
        h.direction = (i % 2 == 0) ? HTLC_OFFERED : HTLC_RECEIVED;
        h.state = HTLC_STATE_ACTIVE;
        h.id = (uint64_t)(100 + i);
        h.amount_sats = (uint64_t)(1000 + i * 500);
        h.cltv_expiry = (uint32_t)(1000 + i * 10);
        memset(h.payment_hash, 0xE0 + (unsigned char)i, 32);
        mgr.entries[2].channel.htlcs[mgr.entries[2].channel.n_htlcs++] = h;
    }

    uint64_t c4_local[4], c4_remote[4], c4_cn[4];
    for (size_t c = 0; c < 4; c++) {
        c4_local[c] = mgr.entries[c].channel.local_amount;
        c4_remote[c] = mgr.entries[c].channel.remote_amount;
        c4_cn[c] = mgr.entries[c].channel.commitment_number;
    }

    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "c4 open");
        TEST_ASSERT(persist_begin(&db), "c4 begin");
        for (size_t c = 0; c < 4; c++) {
            const channel_t *ch = &mgr.entries[c].channel;
            TEST_ASSERT(persist_update_channel_balance(&db, (uint32_t)c,
                            ch->local_amount, ch->remote_amount,
                            ch->commitment_number), "c4 update bal");
        }
        /* Delete old ch2 HTLC (id=3 from cycle 2) */
        persist_delete_htlc(&db, 2, 3);
        /* Save 8 new HTLCs on ch2 */
        for (size_t h = 0; h < 8; h++) {
            TEST_ASSERT(persist_save_htlc(&db, 2,
                            &mgr.entries[2].channel.htlcs[h]), "c4 save htlc");
        }
        TEST_ASSERT(persist_commit(&db), "c4 commit");
        persist_close(&db);
    }

    memset(&mgr, 0, sizeof(mgr));
    memset(&f, 0, sizeof(f));

    /* Recover cycle 4 */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "c4 reopen");
        factory_t rec_f;
        memset(&rec_f, 0, sizeof(rec_f));
        TEST_ASSERT(persist_load_factory(&db, 0, &rec_f, ctx), "c4 load factory");

        lsp_channel_mgr_t rec_mgr;
        memset(&rec_mgr, 0, sizeof(rec_mgr));
        TEST_ASSERT(lsp_channels_init_from_db(&rec_mgr, ctx, &rec_f,
                                                seckeys[0], 4, &db),
                    "c4 init from db");

        /* Verify extreme balances */
        TEST_ASSERT_EQ(rec_mgr.entries[0].channel.local_amount, c4_local[0], "c4 ch0 local=0");
        TEST_ASSERT_EQ(rec_mgr.entries[0].channel.remote_amount, c4_remote[0], "c4 ch0 remote");
        TEST_ASSERT_EQ(rec_mgr.entries[0].channel.commitment_number, c4_cn[0], "c4 ch0 cn");
        TEST_ASSERT_EQ(rec_mgr.entries[1].channel.local_amount, c4_local[1], "c4 ch1 local");
        TEST_ASSERT_EQ(rec_mgr.entries[1].channel.remote_amount, c4_remote[1], "c4 ch1 remote=0");
        TEST_ASSERT_EQ(rec_mgr.entries[1].channel.commitment_number, c4_cn[1], "c4 ch1 cn");

        /* Verify 8 HTLCs on ch2 */
        TEST_ASSERT_EQ(rec_mgr.entries[2].channel.n_htlcs, 8, "c4 ch2 8 htlcs");
        for (int i = 0; i < 8; i++) {
            const htlc_t *h = &rec_mgr.entries[2].channel.htlcs[i];
            TEST_ASSERT_EQ(h->id, (uint64_t)(100 + i), "c4 ch2 htlc id");
            TEST_ASSERT_EQ(h->amount_sats, (uint64_t)(1000 + i * 500), "c4 ch2 htlc amt");
            TEST_ASSERT_EQ(h->cltv_expiry, (uint32_t)(1000 + i * 10), "c4 ch2 htlc cltv");
            htlc_direction_t exp_dir = (i % 2 == 0) ? HTLC_OFFERED : HTLC_RECEIVED;
            TEST_ASSERT_EQ(h->direction, exp_dir, "c4 ch2 htlc dir");
            unsigned char exp_hash[32];
            memset(exp_hash, 0xE0 + (unsigned char)i, 32);
            TEST_ASSERT(memcmp(h->payment_hash, exp_hash, 32) == 0, "c4 ch2 htlc hash");
        }

        /* ch3 still has 2 HTLCs from cycle 3 */
        TEST_ASSERT_EQ(rec_mgr.entries[3].channel.n_htlcs, 2, "c4 ch3 2 htlcs");

        persist_close(&db);
    }

    secp256k1_context_destroy(ctx);
    unlink(path);
    return 1;
}

/* ---- Test: DW counter state survives crash/recovery ---- */

int test_persist_crash_dw_state(void) {
    const char *path = "/tmp/test_crash_dw.db";
    unlink(path);

    /* Create factory to get proper DW counter */
    secp256k1_context *ctx = test_ctx();
    secp256k1_pubkey pks[5];
    if (!secp256k1_ec_pubkey_create(ctx, &pks[0], seckeys[0])) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pks[1], seckeys[1])) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pks[2], seckeys[2])) return 0;
    unsigned char s3[32], s4[32];
    memset(s3, 0x33, 32); memset(s4, 0x44, 32);
    if (!secp256k1_ec_pubkey_create(ctx, &pks[3], s3)) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pks[4], s4)) return 0;

    factory_t f;
    factory_init_from_pubkeys(&f, ctx, pks, 5, 10, 4);

    /* Advance DW counter 5 times */
    for (int i = 0; i < 5; i++) {
        TEST_ASSERT(dw_counter_advance(&f.counter), "advance counter");
    }

    uint32_t epoch_after5 = f.counter.current_epoch;
    uint32_t layers_after5[DW_MAX_LAYERS];
    for (uint32_t i = 0; i < f.counter.n_layers; i++) {
        layers_after5[i] = f.counter.layers[i].current_state;
    }

    /* Enable per-leaf mode and set leaf states */
    f.per_leaf_enabled = 1;
    f.n_leaf_nodes = 2;
    f.leaf_layers[0].current_state = 2;
    f.leaf_layers[1].current_state = 1;

    /* ===== Persist cycle 1 ===== */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "dw c1 open");

        uint32_t layer_states[DW_MAX_LAYERS];
        for (uint32_t i = 0; i < f.counter.n_layers; i++)
            layer_states[i] = f.counter.layers[i].current_state;

        uint32_t leaf_states[8];
        for (int i = 0; i < f.n_leaf_nodes; i++)
            leaf_states[i] = f.leaf_layers[i].current_state;

        TEST_ASSERT(persist_save_dw_counter_with_leaves(&db, 0,
                        f.counter.current_epoch, f.counter.n_layers,
                        layer_states, f.per_leaf_enabled,
                        leaf_states, f.n_leaf_nodes), "dw c1 save");
        persist_close(&db);
    }

    /* Save expected n_layers for verification */
    uint32_t saved_n_layers = f.counter.n_layers;

    /* Zero factory DW state */
    memset(&f.counter, 0, sizeof(f.counter));
    f.per_leaf_enabled = 0;
    memset(f.leaf_layers, 0, sizeof(f.leaf_layers));
    f.n_leaf_nodes = 0;

    /* Recover cycle 1 */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "dw c1 reopen");

        uint32_t epoch, n_layers;
        uint32_t loaded_layers[DW_MAX_LAYERS];
        int per_leaf;
        uint32_t loaded_leaves[8];
        int n_leaves;

        TEST_ASSERT(persist_load_dw_counter_with_leaves(&db, 0,
                        &epoch, &n_layers, loaded_layers, DW_MAX_LAYERS,
                        &per_leaf, loaded_leaves, &n_leaves, 8), "dw c1 load");

        TEST_ASSERT_EQ(epoch, epoch_after5, "dw c1 epoch");
        TEST_ASSERT_EQ(n_layers, saved_n_layers, "dw c1 n_layers");
        for (uint32_t i = 0; i < saved_n_layers; i++) {
            TEST_ASSERT_EQ(loaded_layers[i], layers_after5[i], "dw c1 layer state");
        }
        TEST_ASSERT_EQ(per_leaf, 1, "dw c1 per_leaf enabled");
        TEST_ASSERT_EQ(n_leaves, 2, "dw c1 n_leaf_nodes");
        TEST_ASSERT_EQ(loaded_leaves[0], 2, "dw c1 leaf 0");
        TEST_ASSERT_EQ(loaded_leaves[1], 1, "dw c1 leaf 1");

        persist_close(&db);
    }

    /* ===== Persist cycle 2: advance more, re-persist ===== */
    dw_counter_init(&f.counter, saved_n_layers, 10, 4);
    for (int i = 0; i < 5; i++) dw_counter_advance(&f.counter);
    /* Advance 3 more times */
    for (int i = 0; i < 3; i++) {
        TEST_ASSERT(dw_counter_advance(&f.counter), "advance counter more");
    }

    uint32_t epoch_after8 = f.counter.current_epoch;
    uint32_t layers_after8[DW_MAX_LAYERS];
    for (uint32_t i = 0; i < f.counter.n_layers; i++) {
        layers_after8[i] = f.counter.layers[i].current_state;
    }

    f.per_leaf_enabled = 1;
    f.n_leaf_nodes = 2;
    f.leaf_layers[0].current_state = 3;
    f.leaf_layers[1].current_state = 1;

    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "dw c2 open");

        uint32_t layer_states[DW_MAX_LAYERS];
        for (uint32_t i = 0; i < f.counter.n_layers; i++)
            layer_states[i] = f.counter.layers[i].current_state;

        uint32_t leaf_states[8];
        for (int i = 0; i < f.n_leaf_nodes; i++)
            leaf_states[i] = f.leaf_layers[i].current_state;

        TEST_ASSERT(persist_save_dw_counter_with_leaves(&db, 0,
                        f.counter.current_epoch, f.counter.n_layers,
                        layer_states, f.per_leaf_enabled,
                        leaf_states, f.n_leaf_nodes), "dw c2 save");
        persist_close(&db);
    }

    memset(&f.counter, 0, sizeof(f.counter));

    /* Recover cycle 2 */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "dw c2 reopen");

        uint32_t epoch, n_layers;
        uint32_t loaded_layers[DW_MAX_LAYERS];
        int per_leaf;
        uint32_t loaded_leaves[8];
        int n_leaves;

        TEST_ASSERT(persist_load_dw_counter_with_leaves(&db, 0,
                        &epoch, &n_layers, loaded_layers, DW_MAX_LAYERS,
                        &per_leaf, loaded_leaves, &n_leaves, 8), "dw c2 load");

        TEST_ASSERT_EQ(epoch, epoch_after8, "dw c2 epoch");
        for (uint32_t i = 0; i < saved_n_layers; i++) {
            TEST_ASSERT_EQ(loaded_layers[i], layers_after8[i], "dw c2 layer state");
        }
        TEST_ASSERT_EQ(per_leaf, 1, "dw c2 per_leaf");
        TEST_ASSERT_EQ(loaded_leaves[0], 3, "dw c2 leaf 0");
        TEST_ASSERT_EQ(loaded_leaves[1], 1, "dw c2 leaf 1");

        persist_close(&db);
    }

    secp256k1_context_destroy(ctx);
    unlink(path);
    return 1;
}

/* ---- Test: bidirectional HTLC persistence (sender + receiver) ---- */

int test_persist_htlc_bidirectional(void) {
    const char *path = "/tmp/test_persist_htlc_bidir.db";
    unlink(path);

    /* Save: RECEIVED on channel 0 (sender-side), OFFERED on channel 1 (dest-side) */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "open for save");

        unsigned char hash[32];
        memset(hash, 0x42, 32);

        htlc_t h_sender = {0};
        h_sender.id = 7;
        h_sender.direction = HTLC_RECEIVED;  /* LSP received from sender */
        h_sender.state = HTLC_STATE_ACTIVE;
        h_sender.amount_sats = 2000;
        memcpy(h_sender.payment_hash, hash, 32);
        h_sender.cltv_expiry = 144;

        htlc_t h_dest = {0};
        h_dest.id = 3;
        h_dest.direction = HTLC_OFFERED;  /* LSP offered to dest */
        h_dest.state = HTLC_STATE_ACTIVE;
        h_dest.amount_sats = 2000;
        memcpy(h_dest.payment_hash, hash, 32);
        h_dest.cltv_expiry = 144;

        TEST_ASSERT(persist_save_htlc(&db, 0, &h_sender), "save sender htlc");
        TEST_ASSERT(persist_save_htlc(&db, 1, &h_dest), "save dest htlc");
        persist_close(&db);
    }

    /* Load: reopen and verify both HTLCs on different channels */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "reopen for load");

        htlc_t loaded[16];
        size_t count0 = persist_load_htlcs(&db, 0, loaded, 16);
        TEST_ASSERT_EQ(count0, 1, "channel 0 htlc count");
        TEST_ASSERT_EQ(loaded[0].id, 7, "ch0 htlc id");
        TEST_ASSERT_EQ(loaded[0].direction, HTLC_RECEIVED, "ch0 direction");
        TEST_ASSERT_EQ(loaded[0].amount_sats, 2000, "ch0 amount");

        size_t count1 = persist_load_htlcs(&db, 1, loaded, 16);
        TEST_ASSERT_EQ(count1, 1, "channel 1 htlc count");
        TEST_ASSERT_EQ(loaded[0].id, 3, "ch1 htlc id");
        TEST_ASSERT_EQ(loaded[0].direction, HTLC_OFFERED, "ch1 direction");
        TEST_ASSERT_EQ(loaded[0].amount_sats, 2000, "ch1 amount");

        /* Delete both */
        TEST_ASSERT(persist_delete_htlc(&db, 0, 7), "delete sender htlc");
        TEST_ASSERT(persist_delete_htlc(&db, 1, 3), "delete dest htlc");

        /* Verify zero HTLCs remain */
        count0 = persist_load_htlcs(&db, 0, loaded, 16);
        TEST_ASSERT_EQ(count0, 0, "ch0 empty after delete");
        count1 = persist_load_htlcs(&db, 1, loaded, 16);
        TEST_ASSERT_EQ(count1, 0, "ch1 empty after delete");

        persist_close(&db);
    }

    unlink(path);
    return 1;
}

/* ---- Test: Transaction commit — multi-statement atomic persistence ---- */

int test_persist_transaction_commit(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    secp256k1_context *ctx = test_ctx();
    secp256k1_pubkey pk_local, pk_remote;
    if (!secp256k1_ec_pubkey_create(ctx, &pk_local, seckeys[0])) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pk_remote, seckeys[1])) return 0;

    unsigned char fake_txid[32] = {0};
    fake_txid[0] = 0xDD;
    unsigned char fake_spk[34];
    memset(fake_spk, 0xAA, 34);

    /* Create channel with initial state */
    channel_t ch;
    TEST_ASSERT(channel_init(&ch, ctx, seckeys[0], &pk_local, &pk_remote,
                              fake_txid, 1, 100000, fake_spk, 34,
                              50000, 50000, 144), "channel_init");
    TEST_ASSERT(persist_save_channel(&db, &ch, 0, 0), "save channel");

    /* Begin transaction, update balance + save HTLC, commit */
    TEST_ASSERT(persist_begin(&db), "begin txn");
    TEST_ASSERT(persist_in_transaction(&db), "in txn");

    TEST_ASSERT(persist_update_channel_balance(&db, 0, 40000, 60000, 1),
                "update balance in txn");

    htlc_t h = {0};
    h.id = 5;
    h.direction = HTLC_OFFERED;
    h.state = HTLC_STATE_ACTIVE;
    h.amount_sats = 10000;
    memset(h.payment_hash, 0xAB, 32);
    h.cltv_expiry = 500;
    TEST_ASSERT(persist_save_htlc(&db, 0, &h), "save htlc in txn");

    TEST_ASSERT(persist_commit(&db), "commit txn");
    TEST_ASSERT(!persist_in_transaction(&db), "not in txn after commit");

    /* Verify both operations persisted */
    uint64_t local, remote, commit;
    TEST_ASSERT(persist_load_channel_state(&db, 0, &local, &remote, &commit),
                "load after commit");
    TEST_ASSERT_EQ(local, 40000, "local after commit");
    TEST_ASSERT_EQ(remote, 60000, "remote after commit");
    TEST_ASSERT_EQ(commit, 1, "commit_number after commit");

    htlc_t loaded[16];
    size_t count = persist_load_htlcs(&db, 0, loaded, 16);
    TEST_ASSERT_EQ(count, 1, "htlc count after commit");
    TEST_ASSERT_EQ(loaded[0].id, 5, "htlc id after commit");
    TEST_ASSERT_EQ(loaded[0].amount_sats, 10000, "htlc amount after commit");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}

/* ---- Test: Transaction rollback — multi-statement atomic rollback ---- */

int test_persist_transaction_rollback(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    secp256k1_context *ctx = test_ctx();
    secp256k1_pubkey pk_local, pk_remote;
    if (!secp256k1_ec_pubkey_create(ctx, &pk_local, seckeys[0])) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pk_remote, seckeys[1])) return 0;

    unsigned char fake_txid[32] = {0};
    fake_txid[0] = 0xDD;
    unsigned char fake_spk[34];
    memset(fake_spk, 0xAA, 34);

    /* Create channel with initial state */
    channel_t ch;
    TEST_ASSERT(channel_init(&ch, ctx, seckeys[0], &pk_local, &pk_remote,
                              fake_txid, 1, 100000, fake_spk, 34,
                              50000, 50000, 144), "channel_init");
    TEST_ASSERT(persist_save_channel(&db, &ch, 0, 0), "save channel");

    /* Begin transaction, update balance + save HTLC, then ROLLBACK */
    TEST_ASSERT(persist_begin(&db), "begin txn");

    TEST_ASSERT(persist_update_channel_balance(&db, 0, 30000, 70000, 2),
                "update balance in txn");

    htlc_t h = {0};
    h.id = 9;
    h.direction = HTLC_RECEIVED;
    h.state = HTLC_STATE_ACTIVE;
    h.amount_sats = 20000;
    memset(h.payment_hash, 0xCD, 32);
    h.cltv_expiry = 600;
    TEST_ASSERT(persist_save_htlc(&db, 0, &h), "save htlc in txn");

    TEST_ASSERT(persist_rollback(&db), "rollback txn");
    TEST_ASSERT(!persist_in_transaction(&db), "not in txn after rollback");

    /* Verify original state preserved (balance unchanged, no HTLC) */
    uint64_t local, remote, commit;
    TEST_ASSERT(persist_load_channel_state(&db, 0, &local, &remote, &commit),
                "load after rollback");
    TEST_ASSERT_EQ(local, 50000, "local after rollback (original)");
    TEST_ASSERT_EQ(remote, 50000, "remote after rollback (original)");
    TEST_ASSERT_EQ(commit, 0, "commit_number after rollback (original)");

    htlc_t loaded[16];
    size_t count = persist_load_htlcs(&db, 0, loaded, 16);
    TEST_ASSERT_EQ(count, 0, "no htlcs after rollback");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}

/* ================================================================
 * PS_N1 – PS_N8: LN invoice + peer channel persistence (schema v9)
 * ================================================================ */

#include "superscalar/invoice.h"

/* helper: make a deterministic bolt11_invoice_entry_t */
static bolt11_invoice_entry_t make_test_invoice(unsigned char seed) {
    bolt11_invoice_entry_t e;
    memset(&e, 0, sizeof(e));
    memset(e.payment_hash,   seed,     32);
    memset(e.preimage,       seed + 1, 32);
    memset(e.payment_secret, seed + 2, 32);
    e.amount_msat  = 100000ULL + seed;
    e.expiry       = 3600;
    e.created_at   = 1700000000U + seed;
    e.settled      = 0;
    e.active       = 1;
    snprintf(e.description, sizeof(e.description), "test invoice %d", (int)seed);
    return e;
}

/* PS_N1: save one invoice, reload, hash matches */
int test_ps_n1_save_load_invoice(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    bolt11_invoice_entry_t inv = make_test_invoice(0x01);
    TEST_ASSERT(persist_save_ln_invoice(&db, &inv), "save invoice");

    bolt11_invoice_table_t tbl;
    memset(&tbl, 0, sizeof(tbl));
    int n = persist_load_ln_invoices(&db, &tbl);
    TEST_ASSERT(n >= 0, "load ok");
    TEST_ASSERT_EQ(tbl.count, 1, "count == 1");
    TEST_ASSERT(memcmp(tbl.entries[0].payment_hash, inv.payment_hash, 32) == 0,
                "payment_hash matches");

    persist_close(&db);
    return 1;
}

/* PS_N2: save 3 invoices, load, all 3 present */
int test_ps_n2_save_3_invoices(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    for (unsigned char s = 1; s <= 3; s++) {
        bolt11_invoice_entry_t inv = make_test_invoice(s * 10);
        TEST_ASSERT(persist_save_ln_invoice(&db, &inv), "save invoice");
    }

    bolt11_invoice_table_t tbl;
    memset(&tbl, 0, sizeof(tbl));
    int n = persist_load_ln_invoices(&db, &tbl);
    TEST_ASSERT(n >= 0, "load ok");
    TEST_ASSERT_EQ(tbl.count, 3, "count == 3");

    persist_close(&db);
    return 1;
}

/* PS_N3: delete invoice, reload, count = 0 */
int test_ps_n3_delete_invoice(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    bolt11_invoice_entry_t inv = make_test_invoice(0x42);
    TEST_ASSERT(persist_save_ln_invoice(&db, &inv), "save invoice");
    TEST_ASSERT(persist_delete_ln_invoice(&db, inv.payment_hash), "delete invoice");

    bolt11_invoice_table_t tbl;
    memset(&tbl, 0, sizeof(tbl));
    int n = persist_load_ln_invoices(&db, &tbl);
    TEST_ASSERT(n >= 0, "load ok");
    TEST_ASSERT_EQ(tbl.count, 0, "count == 0 after delete");

    persist_close(&db);
    return 1;
}

/* PS_N4: upsert – same payment_hash twice → count = 1 */
int test_ps_n4_upsert_invoice(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    bolt11_invoice_entry_t inv = make_test_invoice(0x07);
    TEST_ASSERT(persist_save_ln_invoice(&db, &inv), "save first");
    inv.amount_msat = 999999;
    TEST_ASSERT(persist_save_ln_invoice(&db, &inv), "save second (upsert)");

    bolt11_invoice_table_t tbl;
    memset(&tbl, 0, sizeof(tbl));
    int n = persist_load_ln_invoices(&db, &tbl);
    TEST_ASSERT(n >= 0, "load ok");
    TEST_ASSERT_EQ(tbl.count, 1, "count == 1 after upsert");
    TEST_ASSERT_EQ((long long)tbl.entries[0].amount_msat, 999999LL, "updated amount");

    persist_close(&db);
    return 1;
}

/* callback context for peer channel tests */
typedef struct {
    int            count;
    unsigned char  last_channel_id[32];
    uint64_t       last_local;
    uint64_t       last_remote;
    int            last_state;
    char           last_host[256];
    uint16_t       last_port;
} pc_cb_ctx_t;

static void pc_callback(const unsigned char channel_id[32],
                         const unsigned char peer_pubkey[33],
                         uint64_t capacity_sat,
                         uint64_t local_balance_msat,
                         uint64_t remote_balance_msat,
                         int state,
                         const char *peer_host,
                         uint16_t peer_port,
                         void *ctx) {
    pc_cb_ctx_t *c = (pc_cb_ctx_t *)ctx;
    c->count++;
    memcpy(c->last_channel_id, channel_id, 32);
    c->last_local  = local_balance_msat;
    c->last_remote = remote_balance_msat;
    c->last_state  = state;
    if (peer_host) strncpy(c->last_host, peer_host, sizeof(c->last_host) - 1);
    c->last_port = peer_port;
    (void)peer_pubkey; (void)capacity_sat;
}

/* PS_N5: save one channel, load via callback, channel_id matches */
int test_ps_n5_save_load_peer_channel(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    unsigned char cid[32], ppk[33];
    memset(cid, 0xAA, 32);
    memset(ppk, 0xBB, 33);

    TEST_ASSERT(persist_save_ln_peer_channel(&db, cid, ppk,
                    1000000, 500000, 500000, 1, NULL, 0),
                "save channel");

    pc_cb_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    TEST_ASSERT(persist_load_ln_peer_channels(&db, pc_callback, &ctx), "load ok");
    TEST_ASSERT_EQ(ctx.count, 1, "callback fired once");
    TEST_ASSERT(memcmp(ctx.last_channel_id, cid, 32) == 0, "channel_id matches");

    persist_close(&db);
    return 1;
}

/* PS_N6: save 2 channels, callback fires twice */
int test_ps_n6_save_2_channels(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    unsigned char cid1[32], cid2[32], ppk[33];
    memset(cid1, 0x11, 32);
    memset(cid2, 0x22, 32);
    memset(ppk,  0x33, 33);

    TEST_ASSERT(persist_save_ln_peer_channel(&db, cid1, ppk, 1000000, 500000, 500000, 0, NULL, 0),
                "save channel 1");
    TEST_ASSERT(persist_save_ln_peer_channel(&db, cid2, ppk, 2000000, 900000, 1100000, 0, NULL, 0),
                "save channel 2");

    pc_cb_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    TEST_ASSERT(persist_load_ln_peer_channels(&db, pc_callback, &ctx), "load ok");
    TEST_ASSERT_EQ(ctx.count, 2, "callback fired twice");

    persist_close(&db);
    return 1;
}

/* PS_N7: update channel (same channel_id, different balance), sees updated */
int test_ps_n7_update_channel(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    unsigned char cid[32], ppk[33];
    memset(cid, 0x55, 32);
    memset(ppk, 0x66, 33);

    TEST_ASSERT(persist_save_ln_peer_channel(&db, cid, ppk,
                    1000000, 600000, 400000, 0, NULL, 0),
                "initial save");
    TEST_ASSERT(persist_save_ln_peer_channel(&db, cid, ppk,
                    1000000, 300000, 700000, 2, NULL, 0),
                "updated save");

    pc_cb_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    TEST_ASSERT(persist_load_ln_peer_channels(&db, pc_callback, &ctx), "load ok");
    TEST_ASSERT_EQ(ctx.count, 1, "only one row");
    TEST_ASSERT_EQ((long long)ctx.last_local,  300000LL, "updated local");
    TEST_ASSERT_EQ((long long)ctx.last_remote, 700000LL, "updated remote");
    TEST_ASSERT_EQ(ctx.last_state, 2, "updated state");

    persist_close(&db);
    return 1;
}

/* PS_N8: NULL db → save returns 0 (no crash) */
int test_ps_n8_null_db(void) {
    persist_t db;
    memset(&db, 0, sizeof(db));  /* db.db == NULL */

    bolt11_invoice_entry_t inv = make_test_invoice(0xFF);
    TEST_ASSERT(persist_save_ln_invoice(&db, &inv) == 0, "null db returns 0");

    unsigned char cid[32], ppk[33];
    memset(cid, 0xAA, 32);
    memset(ppk, 0xBB, 33);
    TEST_ASSERT(persist_save_ln_peer_channel(&db, cid, ppk,
                    100, 50, 50, 0, NULL, 0) == 0,
                "null db channel returns 0");
    return 1;
}

/* ==========================================================================
 * Phase A tests: host/port persistence (PS_10A through PS_10D)
 * ========================================================================== */

/* PS_10A: Save channel with host/port -> load -> host/port match */
int test_ps_10a_host_port_roundtrip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "PS_10A: open");

    unsigned char cid[32], ppk[33];
    memset(cid, 0xA1, 32);
    memset(ppk, 0xA2, 33);

    TEST_ASSERT(persist_save_ln_peer_channel(&db, cid, ppk,
                    1000000, 500000, 500000, 1,
                    "localhost", 9735),
                "PS_10A: save with host/port");

    pc_cb_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    TEST_ASSERT(persist_load_ln_peer_channels(&db, pc_callback, &ctx), "PS_10A: load ok");
    TEST_ASSERT_EQ(ctx.count, 1, "PS_10A: callback fired once");
    TEST_ASSERT(strcmp(ctx.last_host, "localhost") == 0, "PS_10A: host matches");
    TEST_ASSERT_EQ(ctx.last_port, 9735, "PS_10A: port matches");

    persist_close(&db);
    return 1;
}

/* PS_10B: Save with empty host (ephemeral peer) -> load -> no crash, host is empty */
int test_ps_10b_empty_host(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "PS_10B: open");

    unsigned char cid[32], ppk[33];
    memset(cid, 0xB1, 32);
    memset(ppk, 0xB2, 33);

    TEST_ASSERT(persist_save_ln_peer_channel(&db, cid, ppk,
                    500000, 200000, 300000, 0,
                    NULL, 0),
                "PS_10B: save with NULL host");

    pc_cb_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    TEST_ASSERT(persist_load_ln_peer_channels(&db, pc_callback, &ctx), "PS_10B: load ok");
    TEST_ASSERT_EQ(ctx.count, 1, "PS_10B: callback fired once");
    TEST_ASSERT(strlen(ctx.last_host) == 0, "PS_10B: host is empty");
    TEST_ASSERT_EQ(ctx.last_port, 0, "PS_10B: port is 0");

    persist_close(&db);
    return 1;
}

/* PS_10C: Schema v10 applied; peer_host/peer_port columns exist */
int test_ps_10c_schema_v10(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "PS_10C: open");
    int ver = persist_schema_version(&db);
    TEST_ASSERT(ver == 10, "PS_10C: schema version is 10");

    unsigned char cid[32], ppk[33];
    memset(cid, 0xC1, 32);
    memset(ppk, 0xC2, 33);
    TEST_ASSERT(persist_save_ln_peer_channel(&db, cid, ppk,
                    800000, 400000, 400000, 0,
                    "192.168.1.1", 9735),
                "PS_10C: save with IP");

    pc_cb_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    TEST_ASSERT(persist_load_ln_peer_channels(&db, pc_callback, &ctx), "PS_10C: load ok");
    TEST_ASSERT_EQ(ctx.count, 1, "PS_10C: one row");

    persist_close(&db);
    return 1;
}

/* PS_10D: persist_load_ln_peer_channels delivers host/port to callback */
int test_ps_10d_host_in_callback(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "PS_10D: open");

    unsigned char cid[32], ppk[33];
    memset(cid, 0xD1, 32);
    memset(ppk, 0xD2, 33);

    TEST_ASSERT(persist_save_ln_peer_channel(&db, cid, ppk,
                    2000000, 1000000, 1000000, 1,
                    "node.example.com", 9736),
                "PS_10D: save");

    pc_cb_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    persist_load_ln_peer_channels(&db, pc_callback, &ctx);
    TEST_ASSERT_EQ(ctx.count, 1, "PS_10D: got callback");
    TEST_ASSERT(strcmp(ctx.last_host, "node.example.com") == 0, "PS_10D: host delivered");
    TEST_ASSERT_EQ(ctx.last_port, 9736, "PS_10D: port delivered");

    persist_close(&db);
    return 1;
}

/* ==========================================================================
 * Phase D tests: circuit breaker persistence (CB_P1 through CB_P4)
 * ========================================================================== */

/* CB_P1: save + load circuit breaker limits -> match */
int test_cb_p1_save_load_limits(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "CB_P1: open");

    unsigned char pk[33];
    memset(pk, 0xE1, 33);

    TEST_ASSERT(persist_save_circuit_breaker_peer(&db, pk, 100, 50000000000ULL, 1800) == 1,
                "CB_P1: save");

    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    int n = persist_load_circuit_breaker_peers(&db, &cb);
    TEST_ASSERT(n >= 1, "CB_P1: loaded at least 1");

    int found = 0;
    for (int i = 0; i < cb.n_peers; i++) {
        if (cb.peers[i].active && memcmp(cb.peers[i].peer_pubkey, pk, 33) == 0) {
            TEST_ASSERT_EQ(cb.peers[i].max_pending_htlcs, 100, "CB_P1: max_pending_htlcs");
            TEST_ASSERT_EQ((long long)cb.peers[i].max_pending_msat, 50000000000LL,
                           "CB_P1: max_pending_msat");
            TEST_ASSERT_EQ(cb.peers[i].max_htlcs_per_hour, 1800, "CB_P1: max_htlcs_per_hour");
            found = 1; break;
        }
    }
    TEST_ASSERT(found, "CB_P1: peer slot found in circuit breaker");

    persist_close(&db);
    return 1;
}

/* CB_P2: Save 3 peers -> load -> all 3 in circuit_breaker_t */
int test_cb_p2_save_3_peers(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "CB_P2: open");

    unsigned char pk1[33], pk2[33], pk3[33];
    memset(pk1, 0x11, 33); pk1[0] = 0x02;
    memset(pk2, 0x22, 33); pk2[0] = 0x02;
    memset(pk3, 0x33, 33); pk3[0] = 0x02;

    TEST_ASSERT(persist_save_circuit_breaker_peer(&db, pk1, 10, 1000000ULL, 100) == 1,
                "CB_P2: save 1");
    TEST_ASSERT(persist_save_circuit_breaker_peer(&db, pk2, 20, 2000000ULL, 200) == 1,
                "CB_P2: save 2");
    TEST_ASSERT(persist_save_circuit_breaker_peer(&db, pk3, 30, 3000000ULL, 300) == 1,
                "CB_P2: save 3");

    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    int n = persist_load_circuit_breaker_peers(&db, &cb);
    TEST_ASSERT(n == 3, "CB_P2: loaded 3 peers");
    TEST_ASSERT(cb.n_peers == 3, "CB_P2: n_peers == 3");

    persist_close(&db);
    return 1;
}

/* CB_P3: Upsert same pubkey with new limits -> load -> sees new limits (no duplicate) */
int test_cb_p3_upsert_limits(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "CB_P3: open");

    unsigned char pk[33];
    memset(pk, 0xAB, 33);

    TEST_ASSERT(persist_save_circuit_breaker_peer(&db, pk, 50, 9999ULL, 60) == 1,
                "CB_P3: initial save");
    TEST_ASSERT(persist_save_circuit_breaker_peer(&db, pk, 75, 8888ULL, 120) == 1,
                "CB_P3: upsert");

    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    int n = persist_load_circuit_breaker_peers(&db, &cb);
    TEST_ASSERT(n == 1, "CB_P3: only 1 row (upsert)");

    int found = 0;
    for (int i = 0; i < cb.n_peers; i++) {
        if (cb.peers[i].active && memcmp(cb.peers[i].peer_pubkey, pk, 33) == 0) {
            TEST_ASSERT_EQ(cb.peers[i].max_pending_htlcs, 75, "CB_P3: updated htlcs");
            TEST_ASSERT_EQ((long long)cb.peers[i].max_pending_msat, 8888LL,
                           "CB_P3: updated msat");
            TEST_ASSERT_EQ(cb.peers[i].max_htlcs_per_hour, 120, "CB_P3: updated hourly");
            found = 1; break;
        }
    }
    TEST_ASSERT(found, "CB_P3: upserted peer found");

    persist_close(&db);
    return 1;
}

/* CB_P4: NULL persist -> save returns -1, no crash */
int test_cb_p4_null_persist(void) {
    TEST_ASSERT(persist_save_circuit_breaker_peer(NULL, NULL, 0, 0, 0) == -1,
                "CB_P4: NULL persist returns -1");

    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    TEST_ASSERT(persist_load_circuit_breaker_peers(NULL, &cb) == -1,
                "CB_P4: NULL persist load returns -1");
    TEST_ASSERT(persist_load_circuit_breaker_peers(NULL, NULL) == -1,
                "CB_P4: NULL both returns -1");
    return 1;
}

/* ==========================================================================
 * PR #78 tests: PTLC persistence, peer storage, RGS export,
 * BIP 353, dynamic commitments, BIP 158 RPC elimination
 * ========================================================================== */

/* PTLC_P1: save + load PTLC round-trip */
int test_ptlc_p1_persist_roundtrip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "PTLC_P1: open");

    ptlc_t pt;
    memset(&pt, 0, sizeof(pt));
    pt.id = 42;
    pt.direction = PTLC_OFFERED;
    pt.state = PTLC_STATE_ACTIVE;
    pt.amount_sats = 100000;
    pt.cltv_expiry = 700000;

    TEST_ASSERT(persist_save_ptlc(&db, 1, &pt), "PTLC_P1: save");

    ptlc_t loaded[4];
    size_t n = persist_load_ptlcs(&db, 1, loaded, 4);
    TEST_ASSERT_EQ(n, 1, "PTLC_P1: loaded 1");
    TEST_ASSERT_EQ(loaded[0].id, 42, "PTLC_P1: id matches");
    TEST_ASSERT_EQ(loaded[0].direction, PTLC_OFFERED, "PTLC_P1: direction");
    TEST_ASSERT_EQ((long long)loaded[0].amount_sats, 100000LL, "PTLC_P1: amount");

    persist_close(&db);
    return 1;
}

/* PTLC_P2: delete PTLC */
int test_ptlc_p2_delete(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "PTLC_P2: open");

    ptlc_t pt;
    memset(&pt, 0, sizeof(pt));
    pt.id = 7;
    pt.direction = PTLC_RECEIVED;
    pt.state = PTLC_STATE_ACTIVE;
    pt.amount_sats = 50000;

    persist_save_ptlc(&db, 1, &pt);
    TEST_ASSERT(persist_delete_ptlc(&db, 1, 7), "PTLC_P2: delete");

    ptlc_t loaded[4];
    size_t n = persist_load_ptlcs(&db, 1, loaded, 4);
    TEST_ASSERT_EQ(n, 0, "PTLC_P2: empty after delete");

    persist_close(&db);
    return 1;
}

/* PS_BLOB1: peer storage save + load round-trip */
int test_ps_blob1_roundtrip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "PS_BLOB1: open");

    unsigned char pk[33];
    memset(pk, 0x42, 33);
    unsigned char blob[] = "encrypted_backup_data_here";
    uint16_t blen = sizeof(blob) - 1;

    TEST_ASSERT(persist_save_peer_storage(&db, pk, blob, blen), "PS_BLOB1: save");

    unsigned char loaded[256];
    uint16_t loaded_len = 0;
    TEST_ASSERT(persist_load_peer_storage(&db, pk, loaded, &loaded_len, sizeof(loaded)),
                "PS_BLOB1: load");
    TEST_ASSERT_EQ(loaded_len, blen, "PS_BLOB1: length matches");
    TEST_ASSERT(memcmp(loaded, blob, blen) == 0, "PS_BLOB1: data matches");

    persist_close(&db);
    return 1;
}

/* RGS_E1: RGS export produces valid blob with magic header */
int test_rgs_e1_export(void) {
    gossip_store_t gs;
    TEST_ASSERT(gossip_store_open_in_memory(&gs), "RGS_E1: open store");

    unsigned char out[4096];
    size_t len = gossip_store_export_rgs(&gs, out, sizeof(out));
    /* Empty store produces a minimal RGS blob (17 bytes: magic+ts+node_count+chan_count) */
    TEST_ASSERT(len > 0, "RGS_E1: blob produced");
    if (len >= 5)
        TEST_ASSERT(memcmp(out, "RGSV1", 5) == 0, "RGS_E1: magic header");

    gossip_store_close(&gs);
    return 1;
}

/* BIP353_1: bip353_to_dns_name produces correct DNS name */
int test_bip353_dns_name(void) {
    char dns[512];
    int ok = bip353_to_dns_name("satoshi@bitcoin.org", dns, sizeof(dns));
    TEST_ASSERT(ok, "BIP353_1: conversion ok");
    TEST_ASSERT(strcmp(dns, "satoshi._bitcoin-payment.bitcoin.org") == 0,
                "BIP353_1: DNS name matches");
    return 1;
}

/* BIP353_2: bip353_validate_address accepts valid, rejects invalid */
int test_bip353_validate(void) {
    TEST_ASSERT(bip353_validate_address("user@example.com") == 1,
                "BIP353_2: valid address");
    TEST_ASSERT(bip353_validate_address("noatsign") == 0,
                "BIP353_2: no @ rejected");
    TEST_ASSERT(bip353_validate_address("@nodomain") == 0,
                "BIP353_2: empty user rejected");
    return 1;
}

/* CHANTYPE_1: channel_type TLV encode/decode round-trip */
int test_chantype_roundtrip(void) {
    uint32_t bits = (1 << 12) | (1 << 22);  /* static_remote_key + anchors */
    unsigned char buf[16];
    size_t len = channel_type_encode(bits, buf, sizeof(buf));
    TEST_ASSERT(len > 0, "CHANTYPE_1: encode ok");

    uint32_t decoded = 0;
    TEST_ASSERT(channel_type_decode(buf, len, &decoded), "CHANTYPE_1: decode ok");
    TEST_ASSERT_EQ(decoded, bits, "CHANTYPE_1: round-trip matches");
    return 1;
}

/* CHANTYPE_2: negotiate = AND of local and remote bits */
int test_chantype_negotiate(void) {
    uint32_t local  = (1 << 12) | (1 << 22) | (1 << 4);
    uint32_t remote = (1 << 12) | (1 << 6);
    uint32_t agreed = channel_type_negotiate(local, remote);
    TEST_ASSERT_EQ(agreed, (uint32_t)(1 << 12), "CHANTYPE_2: only shared bit");
    return 1;
}

/* PTLC_COMMIT_1: commitment tx with PTLC has extra output */
int test_ptlc_commitment_output(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    TEST_ASSERT(ctx, "PTLC_CO1: ctx");

    channel_t ch;
    unsigned char local_priv[32], remote_priv[32];
    memset(local_priv, 0x01, 32); local_priv[31] = 0x01;
    memset(remote_priv, 0x02, 32); remote_priv[31] = 0x02;

    secp256k1_pubkey local_pk, remote_pk;
    secp256k1_ec_pubkey_create(ctx, &local_pk, local_priv);
    secp256k1_ec_pubkey_create(ctx, &remote_pk, remote_priv);

    unsigned char txid[32] = {0};
    unsigned char spk[34] = {0x51, 0x20};
    channel_init(&ch, ctx, local_priv, &local_pk, &remote_pk,
                  txid, 0, 1000000, spk, 34, 500000, 400000, 144);

    /* Set up basepoints */
    unsigned char bp1[32], bp2[32], bp3[32], bp4[32];
    memset(bp1, 0x11, 32); bp1[0] = 0x01;
    memset(bp2, 0x12, 32); bp2[0] = 0x01;
    memset(bp3, 0x13, 32); bp3[0] = 0x01;
    memset(bp4, 0x14, 32); bp4[0] = 0x01;
    channel_set_local_basepoints(&ch, bp1, bp2, bp3);
    channel_set_local_htlc_basepoint(&ch, bp4);

    secp256k1_pubkey rbp, pbp, dbp, hbp;
    secp256k1_ec_pubkey_create(ctx, &rbp, bp3);
    secp256k1_ec_pubkey_create(ctx, &pbp, bp1);
    secp256k1_ec_pubkey_create(ctx, &dbp, bp2);
    secp256k1_ec_pubkey_create(ctx, &hbp, bp4);
    channel_set_remote_basepoints(&ch, &pbp, &dbp, &rbp);
    channel_set_remote_htlc_basepoint(&ch, &hbp);

    channel_generate_local_pcs(&ch, 0);

    /* Build commitment tx WITHOUT PTLC */
    tx_buf_t tx1;
    unsigned char txid1[32];
    int r1 = channel_build_commitment_tx(&ch, &tx1, txid1);
    TEST_ASSERT(r1, "PTLC_CO1: commitment without PTLC");
    size_t len1 = tx1.len;

    /* Add a PTLC */
    unsigned char pp_priv[32];
    memset(pp_priv, 0x77, 32); pp_priv[0] = 0x01;
    secp256k1_pubkey pp;
    secp256k1_ec_pubkey_create(ctx, &pp, pp_priv);

    uint64_t ptlc_id;
    channel_add_ptlc(&ch, PTLC_OFFERED, 10000, &pp, 800000, &ptlc_id);

    /* Build commitment tx WITH PTLC */
    tx_buf_t tx2;
    unsigned char txid2[32];
    int r2 = channel_build_commitment_tx(&ch, &tx2, txid2);
    TEST_ASSERT(r2, "PTLC_CO1: commitment with PTLC");

    /* TX with PTLC should be larger (has extra output) */
    TEST_ASSERT(tx2.len > len1, "PTLC_CO1: tx with PTLC is larger");

    tx_buf_free(&tx1);
    tx_buf_free(&tx2);
    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    return 1;
}
