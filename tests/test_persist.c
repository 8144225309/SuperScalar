#include "superscalar/persist.h"
#include "superscalar/factory.h"
#include "superscalar/musig.h"
#include "superscalar/channel.h"
#include "superscalar/lsp_channels.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void sha256(const unsigned char *, size_t, unsigned char *);
extern void sha256_tagged(const char *, const unsigned char *, size_t,
                           unsigned char *);

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
    secp256k1_ec_pubkey_create(ctx, &pk_local, seckeys[0]);
    secp256k1_ec_pubkey_create(ctx, &pk_remote, seckeys[1]);

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

/* ---- Test: HTLC delete (GAP-4b) ---- */

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

    /* Delete h2 */
    TEST_ASSERT(persist_delete_htlc(&db, 0, 11), "delete htlc 11");
    count = persist_load_htlcs(&db, 0, loaded, 16);
    TEST_ASSERT_EQ(count, 0, "count after second delete");

    persist_close(&db);
    return 1;
}

/* ---- Test 5: Factory save/load round-trip ---- */

int test_persist_factory_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    secp256k1_context *ctx = test_ctx();
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++)
        secp256k1_ec_pubkey_create(ctx, &pks[i], seckeys[i]);

    /* Build factory */
    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, 5);

    unsigned char internal_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey);
    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);
    musig_keyagg_t ka_copy = ka;
    secp256k1_pubkey tweaked_pk;
    secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &ka_copy.cache, tweak);
    secp256k1_xonly_pubkey tweaked_xonly;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk);
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
    secp256k1_ec_pubkey_create(ctx, &pk_local, seckeys[0]);
    secp256k1_ec_pubkey_create(ctx, &pk_remote, seckeys[1]);

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
    secp256k1_ec_pubkey_create(ctx, &local_pk, seckeys[0]);
    secp256k1_ec_pubkey_create(ctx, &remote_pk, seckeys[1]);

    /* Build funding SPK */
    extern void sha256_tagged(const char *, const unsigned char *, size_t, unsigned char *);
    secp256k1_pubkey pks[2] = { local_pk, remote_pk };
    musig_keyagg_t ka;
    TEST_ASSERT(musig_aggregate_keys(ctx, &ka, pks, 2), "keyagg");
    unsigned char internal_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey);
    unsigned char twk[32];
    sha256_tagged("TapTweak", internal_ser, 32, twk);
    musig_keyagg_t ka2 = ka;
    secp256k1_pubkey tweaked;
    TEST_ASSERT(secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked, &ka2.cache, twk), "tweak");
    secp256k1_xonly_pubkey twx;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &twx, NULL, &tweaked);
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
    secp256k1_ec_pubkey_create(ctx, &rpay, rsec1);
    secp256k1_ec_pubkey_create(ctx, &rdelay, rsec2);
    secp256k1_ec_pubkey_create(ctx, &rrevoc, rsec3);
    secp256k1_ec_pubkey_create(ctx, &rhtlc, rsec4);
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
    secp256k1_ec_pubkey_serialize(ctx, expected_remote, &slen, &rpay, SECP256K1_EC_COMPRESSED);
    TEST_ASSERT(memcmp(loaded_remote[0], expected_remote, 33) == 0, "remote pay bp match");

    slen = 33;
    secp256k1_ec_pubkey_serialize(ctx, expected_remote, &slen, &rdelay, SECP256K1_EC_COMPRESSED);
    TEST_ASSERT(memcmp(loaded_remote[1], expected_remote, 33) == 0, "remote delay bp match");

    slen = 33;
    secp256k1_ec_pubkey_serialize(ctx, expected_remote, &slen, &rrevoc, SECP256K1_EC_COMPRESSED);
    TEST_ASSERT(memcmp(loaded_remote[2], expected_remote, 33) == 0, "remote revoc bp match");

    slen = 33;
    secp256k1_ec_pubkey_serialize(ctx, expected_remote, &slen, &rhtlc, SECP256K1_EC_COMPRESSED);
    TEST_ASSERT(memcmp(loaded_remote[3], expected_remote, 33) == 0, "remote htlc bp match");

    /* Verify loading non-existent channel fails */
    TEST_ASSERT(!persist_load_basepoints(&db, 99, loaded_local, loaded_remote),
                "non-existent channel fails");

    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}

/* ---- Test: LSP recovery round-trip (GAP-2) ---- */

int test_lsp_recovery_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    secp256k1_context *ctx = test_ctx();

    /* Create factory with 5 participants (LSP + 4 clients) */
    unsigned char extra_sec3[32], extra_sec4[32];
    memset(extra_sec3, 0x33, 32);
    memset(extra_sec4, 0x44, 32);
    secp256k1_pubkey pks[5];
    secp256k1_ec_pubkey_create(ctx, &pks[0], seckeys[0]);  /* LSP */
    secp256k1_ec_pubkey_create(ctx, &pks[1], seckeys[1]);  /* Client 0 */
    secp256k1_ec_pubkey_create(ctx, &pks[2], seckeys[2]);  /* Client 1 */
    secp256k1_ec_pubkey_create(ctx, &pks[3], extra_sec3);  /* Client 2 */
    secp256k1_ec_pubkey_create(ctx, &pks[4], extra_sec4);  /* Client 3 */

    factory_t f;
    factory_init_from_pubkeys(&f, ctx, pks, 5, 10, 4);
    f.cltv_timeout = 200;
    f.fee_per_tx = 500;

    /* Set funding (need valid funding for channel init) */
    extern void sha256_tagged(const char *, const unsigned char *, size_t,
                               unsigned char *);
    musig_keyagg_t ka;
    TEST_ASSERT(musig_aggregate_keys(ctx, &ka, pks, 3), "keyagg");
    unsigned char internal_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey);
    unsigned char twk[32];
    sha256_tagged("TapTweak", internal_ser, 32, twk);
    musig_keyagg_t kac = ka;
    secp256k1_pubkey tpk;
    secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tpk, &kac.cache, twk);
    secp256k1_xonly_pubkey txo;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &txo, NULL, &tpk);
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &txo);

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAB, 32);
    factory_set_funding(&f, fake_txid, 0, 200000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* Initialize channels the normal way */
    lsp_channel_mgr_t mgr;
    TEST_ASSERT(lsp_channels_init(&mgr, ctx, &f, seckeys[0], 4), "init channels");

    /* Simulate basepoint exchange: set remote basepoints */
    for (size_t c = 0; c < 4; c++) {
        channel_t *ch = &mgr.entries[c].channel;
        secp256k1_pubkey rpay, rdelay, rrevoc, rhtlc;
        unsigned char rs[32];
        memset(rs, 0x60 + (unsigned char)c, 32);
        secp256k1_ec_pubkey_create(ctx, &rpay, rs);
        rs[0]++;
        secp256k1_ec_pubkey_create(ctx, &rdelay, rs);
        rs[0]++;
        secp256k1_ec_pubkey_create(ctx, &rrevoc, rs);
        rs[0]++;
        secp256k1_ec_pubkey_create(ctx, &rhtlc, rs);
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
    TEST_ASSERT(persist_commit(&db), "commit");

    /* Now recover: load factory from DB, init channels from DB */
    factory_t rec_f;
    memset(&rec_f, 0, sizeof(rec_f));
    TEST_ASSERT(persist_load_factory(&db, 0, &rec_f, ctx), "load factory");
    TEST_ASSERT_EQ(rec_f.n_participants, 5, "n_participants");

    lsp_channel_mgr_t rec_mgr;
    TEST_ASSERT(lsp_channels_init_from_db(&rec_mgr, ctx, &rec_f,
                                            seckeys[0], 4, &db),
                "init from db");
    TEST_ASSERT_EQ(rec_mgr.n_channels, 4, "n_channels");

    /* Verify recovered channel state matches saved state (check first 2 which had payments) */
    for (size_t c = 0; c < 2; c++) {
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

        /* Verify remote basepoint pubkeys match */
        unsigned char orig_ser[33], rec_ser[33];
        size_t slen;

        slen = 33;
        secp256k1_ec_pubkey_serialize(ctx, orig_ser, &slen,
            &orig->remote_payment_basepoint, SECP256K1_EC_COMPRESSED);
        slen = 33;
        secp256k1_ec_pubkey_serialize(ctx, rec_ser, &slen,
            &rec->remote_payment_basepoint, SECP256K1_EC_COMPRESSED);
        TEST_ASSERT(memcmp(orig_ser, rec_ser, 33) == 0, "remote pay bp");

        slen = 33;
        secp256k1_ec_pubkey_serialize(ctx, orig_ser, &slen,
            &orig->remote_delayed_payment_basepoint, SECP256K1_EC_COMPRESSED);
        slen = 33;
        secp256k1_ec_pubkey_serialize(ctx, rec_ser, &slen,
            &rec->remote_delayed_payment_basepoint, SECP256K1_EC_COMPRESSED);
        TEST_ASSERT(memcmp(orig_ser, rec_ser, 33) == 0, "remote delay bp");

        /* Verify channel is marked ready */
        TEST_ASSERT_EQ(rec_mgr.entries[c].ready, 1, "channel ready");
    }

    secp256k1_context_destroy(ctx);
    persist_close(&db);
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
