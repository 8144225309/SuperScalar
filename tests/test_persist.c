#include "superscalar/persist.h"
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
    extern void sha256_tagged(const char *, const unsigned char *, size_t, unsigned char *);
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
    extern void sha256_tagged(const char *, const unsigned char *, size_t,
                               unsigned char *);
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

    /* Insert a channel with commitment_number exceeding CHANNEL_MAX_SECRETS */
    int rc = sqlite3_exec(db.db,
        "INSERT INTO channels (id, factory_id, slot, local_amount, remote_amount, "
        "funding_amount, commitment_number) VALUES (100, 0, 0, 50000, 50000, "
        "100000, 999);",
        NULL, NULL, NULL);
    TEST_ASSERT(rc == SQLITE_OK, "insert high cn channel");

    uint64_t la, ra, cn;
    int loaded = persist_load_channel_state(&db, 100, &la, &ra, &cn);
    TEST_ASSERT(loaded == 0, "commitment_number>256 rejected");

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
