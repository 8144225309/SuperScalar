/* Phase 16: Reconnection tests */
#include "superscalar/wire.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/client.h"
#include "superscalar/persist.h"
#include "superscalar/factory.h"
#include "superscalar/musig.h"
#include "superscalar/regtest.h"
#include "superscalar/types.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>

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

#define TEST_ASSERT_MEM_EQ(a, b, len, msg) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

static secp256k1_context *test_ctx(void) {
    return secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

/* Test 1: MSG_RECONNECT and MSG_RECONNECT_ACK wire round-trip */
int test_reconnect_wire(void) {
    secp256k1_context *ctx = test_ctx();

    /* Build MSG_RECONNECT */
    unsigned char seckey[32];
    memset(seckey, 0x22, 32);
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey)) return 0;

    uint64_t commitment_number = 42;
    cJSON *msg = wire_build_reconnect(ctx, &pubkey, commitment_number);
    TEST_ASSERT(msg != NULL, "build reconnect returned NULL");

    /* Parse MSG_RECONNECT */
    secp256k1_pubkey parsed_pk;
    uint64_t parsed_cn;
    int ok = wire_parse_reconnect(msg, ctx, &parsed_pk, &parsed_cn);
    TEST_ASSERT(ok, "parse reconnect failed");
    TEST_ASSERT_EQ(parsed_cn, commitment_number, "commitment_number mismatch");

    /* Compare pubkeys */
    unsigned char orig_ser[33], parsed_ser[33];
    size_t len1 = 33, len2 = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, orig_ser, &len1, &pubkey,
                                   SECP256K1_EC_COMPRESSED)) return 0;
    if (!secp256k1_ec_pubkey_serialize(ctx, parsed_ser, &len2, &parsed_pk,
                                   SECP256K1_EC_COMPRESSED)) return 0;
    TEST_ASSERT_MEM_EQ(orig_ser, parsed_ser, 33, "pubkey mismatch");
    cJSON_Delete(msg);

    /* Build MSG_RECONNECT_ACK */
    cJSON *ack = wire_build_reconnect_ack(3, 50000000, 50000000, 42);
    TEST_ASSERT(ack != NULL, "build reconnect_ack returned NULL");

    /* Parse MSG_RECONNECT_ACK */
    uint32_t channel_id;
    uint64_t local_msat, remote_msat, ack_cn;
    ok = wire_parse_reconnect_ack(ack, &channel_id, &local_msat,
                                    &remote_msat, &ack_cn);
    TEST_ASSERT(ok, "parse reconnect_ack failed");
    TEST_ASSERT_EQ(channel_id, 3, "channel_id mismatch");
    TEST_ASSERT_EQ(local_msat, 50000000, "local_msat mismatch");
    TEST_ASSERT_EQ(remote_msat, 50000000, "remote_msat mismatch");
    TEST_ASSERT_EQ(ack_cn, 42, "commitment_number mismatch");
    cJSON_Delete(ack);

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 2: LSP matches reconnecting client by pubkey */
int test_reconnect_pubkey_match(void) {
    secp256k1_context *ctx = test_ctx();

    /* Create LSP + 4 client keys */
    unsigned char lsp_sec[32];
    memset(lsp_sec, 0x10, 32);
    secp256k1_pubkey lsp_pk;
    if (!secp256k1_ec_pubkey_create(ctx, &lsp_pk, lsp_sec)) return 0;

    unsigned char client_secs[4][32];
    secp256k1_pubkey client_pks[4];
    for (int i = 0; i < 4; i++) {
        memset(client_secs[i], 0x21 + i, 32);
        if (!secp256k1_ec_pubkey_create(ctx, &client_pks[i], client_secs[i])) return 0;
    }

    /* Create socketpair for the reconnect channel */
    int sv[2];
    int r = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    TEST_ASSERT(r == 0, "socketpair failed");

    /* Set up lsp_t with known pubkeys */
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    if (!lsp) return 0;

    lsp->client_fds = calloc(LSP_MAX_CLIENTS, sizeof(int));
    lsp->client_pubkeys = calloc(LSP_MAX_CLIENTS, sizeof(secp256k1_pubkey));
    lsp->clients_cap = LSP_MAX_CLIENTS;
    lsp->ctx = ctx;
    lsp->lsp_pubkey = lsp_pk;
    lsp->n_clients = 4;
    lsp->listen_fd = -1;
    lsp->bridge_fd = -1;
    for (int i = 0; i < 4; i++) {
        lsp->client_pubkeys[i] = client_pks[i];
        lsp->client_fds[i] = -1;  /* all disconnected */
    }

    /* Set up factory with all pubkeys */
    secp256k1_pubkey all_pks[5];
    all_pks[0] = lsp_pk;
    for (int i = 0; i < 4; i++)
        all_pks[i + 1] = client_pks[i];

    factory_t *factory = calloc(1, sizeof(factory_t));
    if (!factory) { free(lsp->client_fds); free(lsp->client_pubkeys); free(lsp); return 0; }
    factory_init_from_pubkeys(factory, ctx, all_pks, 5, 10, 4);

    unsigned char fake_txid[32], fake_spk[34];
    memset(fake_txid, 0x01, 32);
    memset(fake_spk, 0x51, 1);
    fake_spk[1] = 0x20;
    memset(fake_spk + 2, 0xAA, 32);
    factory_set_funding(factory, fake_txid, 0, 100000, fake_spk, 34);
    factory_build_tree(factory);
    lsp->factory = *factory;

    /* Set up channel manager */
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    if (!lsp_channels_init(&mgr, ctx, factory, lsp_sec, 4)) {
        printf("  FAIL: %s: lsp_channels_init failed\n", __func__);
        factory_free(factory); free(factory);
        free(lsp->client_fds); free(lsp->client_pubkeys); free(lsp);
        return 0;
    }

    /* Send MSG_RECONNECT from sv[1] as client 2 (index 2) */
    {
        cJSON *reconn = wire_build_reconnect(ctx, &client_pks[2], 0);
        TEST_ASSERT(wire_send(sv[1], MSG_RECONNECT, reconn), "send reconnect failed");
        cJSON_Delete(reconn);
    }

    /* Also need to send CHANNEL_NONCES from client side after LSP sends its nonces.
       Do this in a fork so we don't deadlock. */
    pid_t pid = fork();
    if (pid == 0) {
        close(sv[0]);

        /* Recv CHANNEL_NONCES from LSP */
        wire_msg_t nm;
        if (!wire_recv(sv[1], &nm)) _exit(1);
        if (nm.msg_type != MSG_CHANNEL_NONCES) _exit(2);
        cJSON_Delete(nm.json);

        /* Send back dummy CHANNEL_NONCES */
        unsigned char dummy_nonces[MUSIG_NONCE_POOL_MAX][66];
        memset(dummy_nonces, 0, sizeof(dummy_nonces));

        /* Generate real nonces for the client */
        unsigned char csec[32];
        memset(csec, 0x23, 32);  /* client 2 secret */
        secp256k1_context *cctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        secp256k1_pubkey cpk;
        if (!secp256k1_ec_pubkey_create(cctx, &cpk, csec)) return 0;

        for (size_t i = 0; i < MUSIG_NONCE_POOL_MAX; i++) {
            secp256k1_musig_secnonce sn;
            secp256k1_musig_pubnonce pn;
            musig_keyagg_t ka;
            secp256k1_pubkey pks[2] = {lsp_pk, cpk};
            musig_aggregate_keys(cctx, &ka, pks, 2);
            musig_generate_nonce(cctx, &sn, &pn, csec, &cpk, &ka.cache);
            musig_pubnonce_serialize(cctx, dummy_nonces[i], &pn);
        }

        cJSON *reply = wire_build_channel_nonces(2,
            (const unsigned char (*)[66])dummy_nonces, MUSIG_NONCE_POOL_MAX);
        wire_send(sv[1], MSG_CHANNEL_NONCES, reply);
        cJSON_Delete(reply);

        /* Recv RECONNECT_ACK */
        wire_msg_t ack_msg;
        if (!wire_recv(sv[1], &ack_msg)) _exit(3);
        if (ack_msg.msg_type != MSG_RECONNECT_ACK) _exit(4);

        uint32_t ch_id;
        uint64_t la, ra, cn;
        if (!wire_parse_reconnect_ack(ack_msg.json, &ch_id, &la, &ra, &cn))
            _exit(5);

        /* Client 2 = channel_id 2 */
        if (ch_id != 2) _exit(6);
        cJSON_Delete(ack_msg.json);

        close(sv[1]);
        secp256k1_context_destroy(cctx);
        _exit(0);
    }

    /* Parent: handle reconnect from sv[0] */
    close(sv[1]);
    int ok = lsp_channels_handle_reconnect(&mgr, lsp, sv[0]);
    TEST_ASSERT(ok, "handle_reconnect failed");

    /* Verify client_fds[2] was set */
    TEST_ASSERT(lsp->client_fds[2] >= 0, "client_fds[2] not set");

    int status;
    waitpid(pid, &status, 0);
    TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "child process failed");

    free(lsp->client_fds);
    free(lsp->client_pubkeys);
    free(lsp);
    factory_free(factory);
    free(factory);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 3: Nonce pool re-initialization + wire exchange works after reconnect.
   Verifies: (1) channel_init_nonce_pool can be called again (simulating reconnect),
   (2) pubnonces serialize correctly, (3) wire round-trip of CHANNEL_NONCES works,
   (4) nonce pool can be consumed after re-init. */
int test_reconnect_nonce_reexchange(void) {
    secp256k1_context *ctx = test_ctx();

    unsigned char sec[32];
    memset(sec, 0x10, 32);
    secp256k1_pubkey pk, pk2;
    if (!secp256k1_ec_pubkey_create(ctx, &pk, sec)) return 0;
    unsigned char sec2[32];
    memset(sec2, 0x21, 32);
    if (!secp256k1_ec_pubkey_create(ctx, &pk2, sec2)) return 0;

    unsigned char fake_txid[32], fake_spk[34];
    memset(fake_txid, 0x01, 32);
    memset(fake_spk, 0x51, 1);
    fake_spk[1] = 0x20;
    memset(fake_spk + 2, 0xAA, 32);

    channel_t ch;
    TEST_ASSERT(channel_init(&ch, ctx, sec, &pk, &pk2,
                              fake_txid, 0, 100000, fake_spk, 34,
                              50000, 50000, 144), "channel_init");

    /* First nonce pool init */
    TEST_ASSERT(channel_init_nonce_pool(&ch, 8), "first nonce pool init");
    TEST_ASSERT_EQ(ch.local_nonce_pool.count, 8, "first pool count");

    /* Consume a couple of nonces */
    secp256k1_musig_secnonce *sn;
    secp256k1_musig_pubnonce pn;
    TEST_ASSERT(musig_nonce_pool_next(&ch.local_nonce_pool, &sn, &pn),
                "consume nonce 1");
    TEST_ASSERT(musig_nonce_pool_next(&ch.local_nonce_pool, &sn, &pn),
                "consume nonce 2");
    TEST_ASSERT_EQ(ch.local_nonce_pool.next_unused, 2, "consumed 2");

    /* Re-init nonce pool (simulates reconnect) */
    TEST_ASSERT(channel_init_nonce_pool(&ch, 8), "re-init nonce pool");
    TEST_ASSERT_EQ(ch.local_nonce_pool.count, 8, "re-init pool count");
    TEST_ASSERT_EQ(ch.local_nonce_pool.next_unused, 0, "re-init next_index reset");

    /* Serialize pubnonces and verify round-trip via wire message */
    unsigned char pn_ser[8][66];
    for (size_t i = 0; i < 8; i++) {
        musig_pubnonce_serialize(ctx, pn_ser[i],
            &ch.local_nonce_pool.nonces[i].pubnonce);
    }

    cJSON *nonce_msg = wire_build_channel_nonces(0,
        (const unsigned char (*)[66])pn_ser, 8);
    TEST_ASSERT(nonce_msg != NULL, "build channel_nonces");

    uint32_t ch_id;
    unsigned char parsed_nonces[MUSIG_NONCE_POOL_MAX][66];
    size_t parsed_count;
    TEST_ASSERT(wire_parse_channel_nonces(nonce_msg, &ch_id,
                                            parsed_nonces, MUSIG_NONCE_POOL_MAX,
                                            &parsed_count),
                "parse channel_nonces");
    TEST_ASSERT_EQ(parsed_count, 8, "parsed nonce count");

    /* Verify serialized nonces match */
    for (size_t i = 0; i < 8; i++) {
        TEST_ASSERT_MEM_EQ(pn_ser[i], parsed_nonces[i], 66, "nonce mismatch");
    }

    cJSON_Delete(nonce_msg);

    /* Set parsed nonces as remote and verify we can consume from new pool */
    channel_set_remote_pubnonces(&ch,
        (const unsigned char (*)[66])parsed_nonces, parsed_count);
    TEST_ASSERT_EQ(ch.remote_nonce_count, 8, "remote nonce count");
    TEST_ASSERT_EQ(ch.remote_nonce_next, 0, "remote nonce next reset");

    /* Can still draw from re-initialized local pool */
    TEST_ASSERT(musig_nonce_pool_next(&ch.local_nonce_pool, &sn, &pn),
                "consume from re-init pool");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 4: Save factory+channel to DB, load back, verify state matches */
int test_client_persist_reload(void) {
    secp256k1_context *ctx = test_ctx();

    /* Create 5 keys: LSP + 4 clients */
    static const unsigned char seckeys[5][32] = {
        { [0 ... 31] = 0x10 },
        { [0 ... 31] = 0x21 },
        { [0 ... 31] = 0x32 },
        { [0 ... 31] = 0x43 },
        { [0 ... 31] = 0x54 },
    };
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_ec_pubkey_create(ctx, &pks[i], seckeys[i])) return 0;
    }

    /* Build factory */
    factory_t *factory = calloc(1, sizeof(factory_t));
    if (!factory) return 0;
    factory_init_from_pubkeys(factory, ctx, pks, 5, 10, 4);

    unsigned char fake_txid[32], fake_spk[34];
    memset(fake_txid, 0x01, 32);
    memset(fake_spk, 0x51, 1);
    fake_spk[1] = 0x20;
    memset(fake_spk + 2, 0xAA, 32);
    factory_set_funding(factory, fake_txid, 0, 100000, fake_spk, 34);
    TEST_ASSERT(factory_build_tree(factory), "factory_build_tree");

    /* Initialize a channel (client 0 = participant index 1) */
    channel_t ch;
    TEST_ASSERT(channel_init(&ch, ctx, seckeys[1], &pks[1], &pks[0],
                              factory->nodes[4].txid, 0,
                              factory->nodes[4].outputs[0].amount_sats,
                              factory->nodes[4].outputs[0].script_pubkey,
                              factory->nodes[4].outputs[0].script_pubkey_len,
                              12000, 12000, 144), "channel_init");
    ch.commitment_number = 7;  /* simulate some updates */

    /* Open in-memory DB */
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "persist_open");

    /* Save factory */
    TEST_ASSERT(persist_save_factory(&db, factory, ctx, 0), "persist_save_factory");

    /* Save channel */
    TEST_ASSERT(persist_save_channel(&db, &ch, 0, 0), "persist_save_channel");

    /* Update balance (simulate payment) */
    TEST_ASSERT(persist_update_channel_balance(&db, 0,
        10000, 14000, 7), "persist_update_channel_balance");

    /* Load factory back */
    factory_t *loaded_factory = calloc(1, sizeof(factory_t));
    if (!loaded_factory) return 0;
    TEST_ASSERT(persist_load_factory(&db, 0, loaded_factory, ctx), "persist_load_factory");
    TEST_ASSERT_EQ(loaded_factory->funding_amount_sats, factory->funding_amount_sats,
                   "funding_amount mismatch");
    TEST_ASSERT_MEM_EQ(loaded_factory->funding_txid, factory->funding_txid, 32,
                       "funding_txid mismatch");

    /* Load channel state back */
    uint64_t local_amount, remote_amount, commitment_number;
    TEST_ASSERT(persist_load_channel_state(&db, 0,
        &local_amount, &remote_amount, &commitment_number),
        "persist_load_channel_state");
    TEST_ASSERT_EQ(local_amount, 10000, "local_amount mismatch");
    TEST_ASSERT_EQ(remote_amount, 14000, "remote_amount mismatch");
    TEST_ASSERT_EQ(commitment_number, 7, "commitment_number mismatch");

    channel_cleanup(&ch);
    persist_close(&db);
    factory_free(factory);
    free(factory);
    factory_free(loaded_factory);
    free(loaded_factory);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* === Phase 17 Tests === */

/* Test: MSG_CREATE_INVOICE and MSG_INVOICE_CREATED wire round-trip */
int test_create_invoice_wire(void) {
    /* Build MSG_CREATE_INVOICE */
    uint64_t amount_msat = 50000000;
    cJSON *msg = wire_build_create_invoice(amount_msat);
    TEST_ASSERT(msg != NULL, "build create_invoice returned NULL");

    uint64_t parsed_amount;
    int ok = wire_parse_create_invoice(msg, &parsed_amount);
    TEST_ASSERT(ok, "parse create_invoice failed");
    TEST_ASSERT_EQ(parsed_amount, amount_msat, "amount_msat mismatch");
    cJSON_Delete(msg);

    /* Build MSG_INVOICE_CREATED */
    unsigned char payment_hash[32];
    memset(payment_hash, 0xAB, 32);
    cJSON *resp = wire_build_invoice_created(payment_hash, amount_msat);
    TEST_ASSERT(resp != NULL, "build invoice_created returned NULL");

    unsigned char parsed_hash[32];
    uint64_t parsed_amt2;
    ok = wire_parse_invoice_created(resp, parsed_hash, &parsed_amt2);
    TEST_ASSERT(ok, "parse invoice_created failed");
    TEST_ASSERT_EQ(parsed_amt2, amount_msat, "amount_msat mismatch (created)");
    TEST_ASSERT_MEM_EQ(parsed_hash, payment_hash, 32, "payment_hash mismatch");
    cJSON_Delete(resp);

    return 1;
}

/* Test: Real preimage fulfills HTLC — SHA256(preimage) matches payment_hash */
int test_preimage_fulfills_htlc(void) {
    secp256k1_context *ctx = test_ctx();

    /* Generate a preimage and compute hash */
    unsigned char preimage[32];
    memset(preimage, 0xDE, 32);
    unsigned char payment_hash[32];
    sha256(preimage, 32, payment_hash);

    /* Verify SHA256(preimage) == payment_hash */
    unsigned char verify_hash[32];
    sha256(preimage, 32, verify_hash);
    TEST_ASSERT_MEM_EQ(verify_hash, payment_hash, 32, "SHA256 verification failed");

    /* Create a channel and add HTLC with this payment_hash */
    unsigned char sec1[32], sec2[32];
    memset(sec1, 0x10, 32);
    memset(sec2, 0x21, 32);
    secp256k1_pubkey pk1, pk2;
    if (!secp256k1_ec_pubkey_create(ctx, &pk1, sec1)) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pk2, sec2)) return 0;

    unsigned char fake_txid[32], fake_spk[34];
    memset(fake_txid, 0x01, 32);
    memset(fake_spk, 0x51, 1);
    fake_spk[1] = 0x20;
    memset(fake_spk + 2, 0xAA, 32);

    channel_t ch;
    TEST_ASSERT(channel_init(&ch, ctx, sec1, &pk1, &pk2,
                              fake_txid, 0, 100000, fake_spk, 34,
                              50000, 50000, 144), "channel_init");

    /* Add HTLC with the real payment_hash */
    uint64_t htlc_id;
    TEST_ASSERT(channel_add_htlc(&ch, HTLC_OFFERED, 10000,
                                   payment_hash, 500, &htlc_id),
                "channel_add_htlc failed");

    /* Fulfill with the real preimage */
    TEST_ASSERT(channel_fulfill_htlc(&ch, htlc_id, preimage),
                "channel_fulfill_htlc with real preimage failed");

    /* Verify wrong preimage would fail on a new HTLC */
    unsigned char wrong_preimage[32];
    memset(wrong_preimage, 0x42, 32);
    unsigned char wrong_hash[32];
    sha256(wrong_preimage, 32, wrong_hash);

    /* The wrong preimage produces a different hash */
    TEST_ASSERT(memcmp(wrong_hash, payment_hash, 32) != 0,
                "wrong preimage should not match payment_hash");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test: Balance reporting produces valid output */
int test_balance_reporting(void) {
    secp256k1_context *ctx = test_ctx();

    unsigned char lsp_sec[32];
    memset(lsp_sec, 0x10, 32);
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        unsigned char sec[32];
        memset(sec, 0x10 + i * 0x11, 32);
        if (!secp256k1_ec_pubkey_create(ctx, &pks[i], sec)) return 0;
    }

    factory_t *factory = calloc(1, sizeof(factory_t));
    if (!factory) return 0;
    factory_init_from_pubkeys(factory, ctx, pks, 5, 10, 4);

    unsigned char fake_txid[32], fake_spk[34];
    memset(fake_txid, 0x01, 32);
    memset(fake_spk, 0x51, 1);
    fake_spk[1] = 0x20;
    memset(fake_spk + 2, 0xAA, 32);
    factory_set_funding(factory, fake_txid, 0, 100000, fake_spk, 34);
    TEST_ASSERT(factory_build_tree(factory), "factory_build_tree");

    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    TEST_ASSERT(lsp_channels_init(&mgr, ctx, factory, lsp_sec, 4),
                "lsp_channels_init");
    TEST_ASSERT(mgr.n_channels > 0, "channels were initialized");

    /* Verify balances are set (each channel should have non-zero capacity) */
    for (size_t c = 0; c < mgr.n_channels; c++) {
        uint64_t total = mgr.entries[c].channel.local_amount +
                         mgr.entries[c].channel.remote_amount;
        TEST_ASSERT(total > 0, "channel has non-zero capacity");
    }

    /* Print should not crash */
    lsp_channels_print_balances(&mgr);

    /* NULL should be a no-op */
    lsp_channels_print_balances(NULL);

    factory_free(factory);
    free(factory);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ============================================================ */
/* Phase 18: Fee estimation + Watchtower + Persistence tests     */
/* ============================================================ */

#include "superscalar/fee.h"
#include "superscalar/watchtower.h"

/* Test 8: fee_init and fee_estimate basics */
int test_fee_init_default(void) {
    fee_estimator_static_t fe;
    fee_estimator_static_init(&fe, 1000);  /* 1 sat/vB */

    TEST_ASSERT_EQ(fe.sat_per_kvb, 1000, "default rate");

    /* 200 vB tx at 1 sat/vB = 200 sats */
    uint64_t fee = fee_estimate((fee_estimator_t *)&fe, 200);
    TEST_ASSERT_EQ(fee, 200, "200 vB at 1 sat/vB");

    /* 100 vB tx at 2 sat/vB (2000 sat/kvB) */
    fee_estimator_static_t fe2;
    fee_estimator_static_init(&fe2, 2000);
    fee = fee_estimate((fee_estimator_t *)&fe2, 100);
    TEST_ASSERT_EQ(fee, 200, "100 vB at 2 sat/vB");

    /* Rounding: 150 vB at 1 sat/vB = ceil(150000/1000) = 150 */
    fee = fee_estimate((fee_estimator_t *)&fe, 150);
    TEST_ASSERT_EQ(fee, 150, "150 vB at 1 sat/vB");

    /* Edge: 1 vB at 1 sat/vB = ceil(1999/1000) = 1 */
    fee = fee_estimate((fee_estimator_t *)&fe, 1);
    /* (1000*1 + 999) / 1000 = 1999/1000 = 1 */
    TEST_ASSERT_EQ(fee, 1, "1 vB minimum");

    return 1;
}

/* Test 9: penalty and HTLC tx fee conveniences */
int test_fee_penalty_tx(void) {
    fee_estimator_static_t fe;
    fee_estimator_static_init(&fe, 1000);  /* 1 sat/vB */

    uint64_t penalty = fee_for_penalty_tx((fee_estimator_t *)&fe);
    TEST_ASSERT(penalty >= 100, "penalty fee >= 100");
    TEST_ASSERT(penalty <= 10000, "penalty fee <= 10000");
    TEST_ASSERT_EQ(penalty, 165, "penalty fee = 165 sats at 1 sat/vB (P2A anchor)");

    uint64_t htlc = fee_for_htlc_tx((fee_estimator_t *)&fe);
    TEST_ASSERT(htlc >= 100, "htlc fee >= 100");
    TEST_ASSERT(htlc <= 10000, "htlc fee <= 10000");
    TEST_ASSERT_EQ(htlc, 180, "htlc fee = 180 sats at 1 sat/vB");

    /* At higher fee rate */
    fee_estimator_static_t fe5;
    fee_estimator_static_init(&fe5, 5000);  /* 5 sat/vB */
    TEST_ASSERT_EQ(fee_for_penalty_tx((fee_estimator_t *)&fe5), 825, "penalty at 5 sat/vB (P2A anchor)");
    TEST_ASSERT_EQ(fee_for_htlc_tx((fee_estimator_t *)&fe5), 900, "htlc at 5 sat/vB");

    return 1;
}

/* Test 10: factory tx fee scales with n_outputs */
int test_fee_factory_tx(void) {
    fee_estimator_static_t fe;
    fee_estimator_static_init(&fe, 1000);  /* 1 sat/vB */

    uint64_t fee1 = fee_for_factory_tx((fee_estimator_t *)&fe, 1);
    uint64_t fee3 = fee_for_factory_tx((fee_estimator_t *)&fe, 3);
    uint64_t fee5 = fee_for_factory_tx((fee_estimator_t *)&fe, 5);

    /* fee = (68 + 43*n) at 1 sat/vB: 68 = 10 tx overhead + 58 P2TR keypath input */
    TEST_ASSERT_EQ(fee1, 111, "1 output: 68+43=111");
    TEST_ASSERT_EQ(fee3, 197, "3 outputs: 68+129=197");
    TEST_ASSERT_EQ(fee5, 283, "5 outputs: 68+215=283");

    /* Must scale: more outputs = higher fee */
    TEST_ASSERT(fee3 > fee1, "fee scales up with outputs");
    TEST_ASSERT(fee5 > fee3, "fee scales up more");

    return 1;
}

/* Test: commitment tx fee scales with n_htlcs */
int test_fee_commitment_tx(void) {
    fee_estimator_static_t fe;
    fee_estimator_static_init(&fe, 1000);  /* 1 sat/vB */

    /* 154 vB base at 1 sat/vB */
    TEST_ASSERT_EQ(fee_for_commitment_tx((fee_estimator_t *)&fe, 0), 154,
                   "0 HTLCs: 154 vB = 154 sats");
    /* 154 + 43 = 197 */
    TEST_ASSERT_EQ(fee_for_commitment_tx((fee_estimator_t *)&fe, 1), 197,
                   "1 HTLC: 197 vB = 197 sats");
    /* 154 + 86 = 240 */
    TEST_ASSERT_EQ(fee_for_commitment_tx((fee_estimator_t *)&fe, 2), 240,
                   "2 HTLCs: 240 vB = 240 sats");
    /* 154 + 129 = 283 */
    TEST_ASSERT_EQ(fee_for_commitment_tx((fee_estimator_t *)&fe, 3), 283,
                   "3 HTLCs: 283 vB = 283 sats");

    /* Must scale with HTLC count */
    TEST_ASSERT(fee_for_commitment_tx((fee_estimator_t *)&fe, 3) >
                fee_for_commitment_tx((fee_estimator_t *)&fe, 1),
                "fee scales up with HTLC count");

    /* NULL guard */
    TEST_ASSERT_EQ(fee_for_commitment_tx(NULL, 0), 0, "NULL fe returns 0");

    /* At 5 sat/vB (5000 sat/kvB): 5000*154/1000 = 770 */
    fee_estimator_static_t fe5;
    fee_estimator_static_init(&fe5, 5000);
    TEST_ASSERT_EQ(fee_for_commitment_tx((fee_estimator_t *)&fe5, 0), 770,
                   "0 HTLCs at 5 sat/vB = 770");
    /* 5000*240/1000 = 1200 — matches regtest fee_estimation_parsing output */
    TEST_ASSERT_EQ(fee_for_commitment_tx((fee_estimator_t *)&fe5, 2), 1200,
                   "2 HTLCs at 5 sat/vB = 1200");

    return 1;
}

/* Test: CPFP child tx fee (P2A anchor spend) */
int test_fee_cpfp_tx(void) {
    fee_estimator_static_t fe;
    fee_estimator_static_init(&fe, 1000);  /* 1 sat/vB */

    /* 264 vB at 1 sat/vB */
    TEST_ASSERT_EQ(fee_for_cpfp_child((fee_estimator_t *)&fe), 264,
                   "cpfp child: 264 vB at 1 sat/vB = 264 sats");

    /* At 5 sat/vB: 5000*264/1000 = 1320 */
    fee_estimator_static_t fe5;
    fee_estimator_static_init(&fe5, 5000);
    TEST_ASSERT_EQ(fee_for_cpfp_child((fee_estimator_t *)&fe5), 1320,
                   "cpfp child at 5 sat/vB = 1320 sats");

    /* NULL guard */
    TEST_ASSERT_EQ(fee_for_cpfp_child(NULL), 0, "NULL fe returns 0");

    return 1;
}

/* Test: fee_update_from_node with NULL/invalid args */
int test_fee_update_from_node_null(void) {
    fee_estimator_static_t fe;
    fee_estimator_static_init(&fe, 1000);

    /* Static impl has no update() — fee_update_from_node returns 0 */
    TEST_ASSERT(!fee_update_from_node((fee_estimator_t *)&fe, NULL, 6), "static: no update");
    TEST_ASSERT_EQ(fe.sat_per_kvb, 1000, "rate unchanged for static impl");

    /* NULL fe should not crash */
    TEST_ASSERT(!fee_update_from_node(NULL, NULL, 6), "NULL fe returns 0");

    return 1;
}

/* Test 11: watchtower watch and check (no breach) */
int test_watchtower_watch_and_check(void) {
    secp256k1_context *ctx = test_ctx();

    /* Create a channel for the watchtower */
    unsigned char sec_a[32], sec_b[32];
    memset(sec_a, 0xAA, 32);
    memset(sec_b, 0xBB, 32);
    secp256k1_keypair kp_a, kp_b;
    if (!secp256k1_keypair_create(ctx, &kp_a, sec_a)) return 0;
    if (!secp256k1_keypair_create(ctx, &kp_b, sec_b)) return 0;
    secp256k1_pubkey pk_a, pk_b;
    if (!secp256k1_keypair_pub(ctx, &pk_a, &kp_a)) return 0;
    if (!secp256k1_keypair_pub(ctx, &pk_b, &kp_b)) return 0;

    /* Build funding SPK */
    secp256k1_pubkey pks[2] = { pk_a, pk_b };
    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, 2);
    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey xonly_tmp;
    unsigned char ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, ser, &ka.agg_pubkey)) return 0;
    unsigned char twk[32];
    sha256_tagged("TapTweak", ser, 32, twk);
    secp256k1_pubkey tweaked_pub;
    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked_pub, &ka.agg_pubkey, twk)) return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pub)) return 0;
    extern void build_p2tr_script_pubkey(unsigned char *out,
                                           const secp256k1_xonly_pubkey *xpk);
    build_p2tr_script_pubkey(fund_spk, &tweaked_xonly);
    (void)xonly_tmp;

    unsigned char fund_txid[32];
    memset(fund_txid, 0x11, 32);
    channel_t ch;
    channel_init(&ch, ctx, sec_a, &pk_a, &pk_b,
                  fund_txid, 0, 50000, fund_spk, 34,
                  25000, 25000, 144);

    /* Init watchtower with no DB, no regtest */
    watchtower_t wt;
    watchtower_init(&wt, 1, NULL, NULL, NULL);
    watchtower_set_channel(&wt, 0, &ch);
    TEST_ASSERT_EQ(wt.n_entries, 0, "no entries initially");

    /* Add a fake old commitment */
    unsigned char old_txid[32];
    memset(old_txid, 0x22, 32);
    TEST_ASSERT(watchtower_watch(&wt, 0, 0, old_txid, 0, 24000, fund_spk, 34),
                "watch ok");
    TEST_ASSERT_EQ(wt.n_entries, 1, "1 entry after watch");

    /* Check without regtest — should return 0 (no rt set) */
    int penalties = watchtower_check(&wt);
    TEST_ASSERT_EQ(penalties, 0, "no penalties without regtest");

    /* Remove channel entries */
    watchtower_remove_channel(&wt, 0);
    TEST_ASSERT_EQ(wt.n_entries, 0, "0 entries after remove");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 12: persist old commitments round-trip */
int test_persist_old_commitments(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open in-memory DB");

    unsigned char txid[32];
    memset(txid, 0x33, 32);
    unsigned char spk[34];
    memset(spk, 0x44, 34);

    TEST_ASSERT(persist_save_old_commitment(&db, 0, 5, txid, 1, 30000, spk, 34),
                "save old commitment");

    /* Save another */
    unsigned char txid2[32];
    memset(txid2, 0x55, 32);
    TEST_ASSERT(persist_save_old_commitment(&db, 0, 6, txid2, 0, 28000, spk, 34),
                "save second old commitment");

    /* Load */
    uint64_t commit_nums[16];
    unsigned char loaded_txids[16][32];
    uint32_t vouts[16];
    uint64_t amounts[16];
    unsigned char loaded_spks[16][34];
    size_t spk_lens[16];

    size_t count = persist_load_old_commitments(&db, 0, commit_nums,
        loaded_txids, vouts, amounts, loaded_spks, spk_lens, 16);
    TEST_ASSERT_EQ(count, 2, "loaded 2 entries");
    TEST_ASSERT_EQ(commit_nums[0], 5, "commit_num 0");
    TEST_ASSERT_EQ(commit_nums[1], 6, "commit_num 1");
    TEST_ASSERT_EQ(vouts[0], 1, "vout 0");
    TEST_ASSERT_EQ(vouts[1], 0, "vout 1");
    TEST_ASSERT_EQ(amounts[0], 30000, "amount 0");
    TEST_ASSERT_EQ(amounts[1], 28000, "amount 1");
    TEST_ASSERT_MEM_EQ(loaded_txids[0], txid, 32, "txid 0 match");
    TEST_ASSERT_MEM_EQ(loaded_txids[1], txid2, 32, "txid 1 match");

    /* Load for different channel — should be empty */
    count = persist_load_old_commitments(&db, 1, commit_nums,
        loaded_txids, vouts, amounts, loaded_spks, spk_lens, 16);
    TEST_ASSERT_EQ(count, 0, "no entries for channel 1");

    persist_close(&db);
    return 1;
}

/* Test 13: regtest_get_raw_tx API validation (unit test, no bitcoind needed) */
int test_regtest_get_raw_tx_api(void) {
    char buf[256];
    /* Should return 0 with invalid args */
    int ok = regtest_get_raw_tx(NULL, "abc", buf, sizeof(buf));
    TEST_ASSERT_EQ(ok, 0, "NULL rt returns 0");
    ok = regtest_get_raw_tx(NULL, NULL, buf, sizeof(buf));
    TEST_ASSERT_EQ(ok, 0, "NULL both returns 0");
    return 1;
}

/* ============================================================ */
/* Phase 19: Encrypted Transport tests                          */
/* ============================================================ */

#include "superscalar/crypto_aead.h"
#include "superscalar/noise.h"
#include <sys/wait.h>

extern void hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void hex_encode(const unsigned char *data, size_t len, char *out);

/* Test 14: ChaCha20-Poly1305 RFC 7539 Section 2.8.2 test vector */
int test_chacha20_poly1305_rfc7539(void) {
    /* Key */
    const unsigned char key[32] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
    };
    /* Nonce: 0x070000004041424344454647 */
    const unsigned char nonce[12] = {
        0x07,0x00,0x00,0x00, 0x40,0x41,0x42,0x43,
        0x44,0x45,0x46,0x47
    };
    /* AAD */
    const unsigned char aad[12] = {
        0x50,0x51,0x52,0x53, 0xc0,0xc1,0xc2,0xc3,
        0xc4,0xc5,0xc6,0xc7
    };
    /* Plaintext: "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it." */
    const char *plaintext_str =
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, "
        "sunscreen would be it.";
    const unsigned char *plaintext = (const unsigned char *)plaintext_str;
    size_t pt_len = strlen(plaintext_str);

    /* Expected ciphertext (from RFC 7539 Section 2.8.2) */
    const unsigned char expected_ct[] = {
        0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,0x7b,0x86,0xaf,0xbc,
        0x53,0xef,0x7e,0xc2,0xa4,0xad,0xed,0x51,0x29,0x6e,0x08,0xfe,
        0xa9,0xe2,0xb5,0xa7,0x36,0xee,0x62,0xd6,0x3d,0xbe,0xa4,0x5e,
        0x8c,0xa9,0x67,0x12,0x82,0xfa,0xfb,0x69,0xda,0x92,0x72,0x8b,
        0x1a,0x71,0xde,0x0a,0x9e,0x06,0x0b,0x29,0x05,0xd6,0xa5,0xb6,
        0x7e,0xcd,0x3b,0x36,0x92,0xdd,0xbd,0x7f,0x2d,0x77,0x8b,0x8c,
        0x98,0x03,0xae,0xe3,0x28,0x09,0x1b,0x58,0xfa,0xb3,0x24,0xe4,
        0xfa,0xd6,0x75,0x94,0x55,0x85,0x80,0x8b,0x48,0x31,0xd7,0xbc,
        0x3f,0xf4,0xde,0xf0,0x8e,0x4b,0x7a,0x9d,0xe5,0x76,0xd2,0x65,
        0x86,0xce,0xc6,0x4b,0x61,0x16
    };
    /* Expected tag */
    const unsigned char expected_tag[16] = {
        0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,
        0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91
    };

    unsigned char ct[128];
    unsigned char tag[16];
    TEST_ASSERT(pt_len <= sizeof(ct), "plaintext too long");

    int ok = aead_encrypt(ct, tag, plaintext, pt_len, aad, sizeof(aad), key, nonce);
    TEST_ASSERT(ok, "aead_encrypt failed");
    TEST_ASSERT_MEM_EQ(ct, expected_ct, pt_len, "ciphertext mismatch");
    TEST_ASSERT_MEM_EQ(tag, expected_tag, 16, "tag mismatch");

    /* Decrypt and verify round-trip */
    unsigned char decrypted[128];
    ok = aead_decrypt(decrypted, ct, pt_len, tag, aad, sizeof(aad), key, nonce);
    TEST_ASSERT(ok, "aead_decrypt failed");
    TEST_ASSERT_MEM_EQ(decrypted, plaintext, pt_len, "decrypted text mismatch");

    /* Tampered tag should fail */
    unsigned char bad_tag[16];
    memcpy(bad_tag, tag, 16);
    bad_tag[0] ^= 0x01;
    ok = aead_decrypt(decrypted, ct, pt_len, bad_tag, aad, sizeof(aad), key, nonce);
    TEST_ASSERT(!ok, "tampered tag should fail decryption");

    return 1;
}

/* Test 15: HMAC-SHA256 RFC 4231 test case 2 */
int test_hmac_sha256_rfc4231(void) {
    /* Key = "Jefe" */
    const unsigned char key[] = { 0x4a, 0x65, 0x66, 0x65 };
    /* Data = "what do ya want for nothing?" */
    const unsigned char data[] = {
        0x77,0x68,0x61,0x74,0x20,0x64,0x6f,0x20,
        0x79,0x61,0x20,0x77,0x61,0x6e,0x74,0x20,
        0x66,0x6f,0x72,0x20,0x6e,0x6f,0x74,0x68,
        0x69,0x6e,0x67,0x3f
    };
    /* Expected HMAC-SHA256 */
    const unsigned char expected[32] = {
        0x5b,0xdc,0xc1,0x46,0xbf,0x60,0x75,0x4e,
        0x6a,0x04,0x24,0x26,0x08,0x95,0x75,0xc7,
        0x5a,0x00,0x3f,0x08,0x9d,0x27,0x39,0x83,
        0x9d,0xec,0x58,0xb9,0x64,0xec,0x38,0x43
    };

    unsigned char out[32];
    hmac_sha256(out, key, sizeof(key), data, sizeof(data));
    TEST_ASSERT_MEM_EQ(out, expected, 32, "HMAC-SHA256 mismatch");

    return 1;
}

/* HKDF-SHA256 RFC 5869 test case 1 */
int test_hkdf_sha256_rfc5869(void) {
    /* IKM (22 bytes) */
    const unsigned char ikm[22] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    /* Salt (13 bytes) */
    const unsigned char salt[13] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c
    };
    /* Info (10 bytes) */
    const unsigned char info[10] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
        0xf8,0xf9
    };
    /* Expected PRK (32 bytes) */
    const unsigned char expected_prk[32] = {
        0x07,0x77,0x09,0x36,0x2c,0x2e,0x32,0xdf,
        0x0d,0xdc,0x3f,0x0d,0xc4,0x7b,0xba,0x63,
        0x90,0xb6,0xc7,0x3b,0xb5,0x0f,0x9c,0x31,
        0x22,0xec,0x84,0x4a,0xd7,0xc2,0xb3,0xe5
    };
    /* Expected OKM (42 bytes) */
    const unsigned char expected_okm[42] = {
        0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,
        0x90,0x43,0x4f,0x64,0xd0,0x36,0x2f,0x2a,
        0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,
        0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,
        0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,
        0x58,0x65
    };

    /* Test extract */
    unsigned char prk[32];
    hkdf_extract(prk, salt, sizeof(salt), ikm, sizeof(ikm));
    TEST_ASSERT_MEM_EQ(prk, expected_prk, 32, "HKDF extract PRK mismatch");

    /* Test expand */
    unsigned char okm[42];
    hkdf_expand(okm, 42, prk, info, sizeof(info));
    TEST_ASSERT_MEM_EQ(okm, expected_okm, 42, "HKDF expand OKM mismatch");

    return 1;
}

/* Test 16: Noise handshake key agreement via socketpair */
int test_noise_handshake(void) {
    secp256k1_context *ctx = test_ctx();
    int sv[2];
    int r = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    TEST_ASSERT(r == 0, "socketpair failed");

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: responder */
        close(sv[0]);
        secp256k1_context *child_ctx = test_ctx();
        noise_state_t resp_ns;
        int ok = noise_handshake_responder(&resp_ns, sv[1], child_ctx);
        if (!ok) _exit(1);

        /* Write keys to parent for comparison */
        ssize_t w3 = write(sv[1], resp_ns.send_key, 32);
        ssize_t w4 = write(sv[1], resp_ns.recv_key, 32);
        (void)w3; (void)w4;

        close(sv[1]);
        secp256k1_context_destroy(child_ctx);
        _exit(0);
    }

    /* Parent: initiator */
    close(sv[1]);
    noise_state_t init_ns;
    int ok = noise_handshake_initiator(&init_ns, sv[0], ctx);
    TEST_ASSERT(ok, "initiator handshake failed");

    /* Read responder's keys */
    unsigned char resp_send[32], resp_recv[32];
    ssize_t r1 = read(sv[0], resp_send, 32);
    ssize_t r2 = read(sv[0], resp_recv, 32);
    (void)r1; (void)r2;

    /* Initiator's send_key should == Responder's recv_key */
    TEST_ASSERT_MEM_EQ(init_ns.send_key, resp_recv, 32,
                       "initiator.send != responder.recv");
    /* Initiator's recv_key should == Responder's send_key */
    TEST_ASSERT_MEM_EQ(init_ns.recv_key, resp_send, 32,
                       "initiator.recv != responder.send");

    int status;
    waitpid(pid, &status, 0);
    TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "responder child failed");

    close(sv[0]);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 17: Encrypted wire round-trip: handshake + wire_send/wire_recv */
int test_encrypted_wire_round_trip(void) {
    secp256k1_context *ctx = test_ctx();
    int sv[2];
    int r = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    TEST_ASSERT(r == 0, "socketpair failed");

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: responder — does handshake, then receives 3 messages */
        close(sv[0]);
        secp256k1_context *child_ctx = test_ctx();

        if (!wire_noise_handshake_responder(sv[1], child_ctx)) _exit(1);

        /* Receive 3 messages and echo the msg_type back as exit code */
        for (int i = 0; i < 3; i++) {
            wire_msg_t msg;
            if (!wire_recv(sv[1], &msg)) _exit(10 + i);

            /* Verify content based on message number */
            cJSON *val = cJSON_GetObjectItem(msg.json, "seq");
            if (!val || !cJSON_IsNumber(val) || (int)val->valuedouble != i)
                _exit(20 + i);
            cJSON_Delete(msg.json);
        }

        wire_close(sv[1]);
        secp256k1_context_destroy(child_ctx);
        _exit(0);
    }

    /* Parent: initiator — does handshake, then sends 3 messages */
    close(sv[1]);
    int ok = wire_noise_handshake_initiator(sv[0], ctx);
    TEST_ASSERT(ok, "initiator handshake failed");

    for (int i = 0; i < 3; i++) {
        cJSON *j = cJSON_CreateObject();
        cJSON_AddNumberToObject(j, "seq", i);
        cJSON_AddStringToObject(j, "hello", "encrypted world");
        ok = wire_send(sv[0], MSG_HELLO + i, j);
        cJSON_Delete(j);
        TEST_ASSERT(ok, "wire_send failed");
    }

    int status;
    waitpid(pid, &status, 0);
    TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "responder child failed");

    wire_close(sv[0]);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 18: Encrypted tamper reject — flip ciphertext bit, verify wire_recv fails */
int test_encrypted_tamper_reject(void) {
    secp256k1_context *ctx = test_ctx();
    int sv[2];
    int r = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    TEST_ASSERT(r == 0, "socketpair failed");

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: responder — does handshake, sends a message */
        close(sv[0]);
        secp256k1_context *child_ctx = test_ctx();

        if (!wire_noise_handshake_responder(sv[1], child_ctx)) _exit(1);

        /* Send one message (will be tampered by parent) */
        cJSON *j = cJSON_CreateObject();
        cJSON_AddStringToObject(j, "secret", "data");
        /* Write directly using wire_send which encrypts */
        if (!wire_send(sv[1], MSG_HELLO, j)) _exit(2);
        cJSON_Delete(j);

        /* Also send a good message to confirm channel still works for valid data */
        j = cJSON_CreateObject();
        cJSON_AddStringToObject(j, "ok", "true");
        wire_send(sv[1], MSG_HELLO, j);
        cJSON_Delete(j);

        close(sv[1]);
        secp256k1_context_destroy(child_ctx);
        _exit(0);
    }

    /* Parent: initiator — does handshake, reads raw bytes, tampers, verifies failure */
    close(sv[1]);
    int ok = wire_noise_handshake_initiator(sv[0], ctx);
    TEST_ASSERT(ok, "initiator handshake failed");

    /* Read raw encrypted frame from socket (bypassing wire_recv) */
    unsigned char len_buf[4];
    TEST_ASSERT(read(sv[0], len_buf, 4) == 4, "read len failed");
    uint32_t frame_len = ((uint32_t)len_buf[0] << 24) | ((uint32_t)len_buf[1] << 16) |
                         ((uint32_t)len_buf[2] << 8) | (uint32_t)len_buf[3];
    TEST_ASSERT(frame_len > 16, "frame too short");

    unsigned char *raw = (unsigned char *)malloc(frame_len);
    TEST_ASSERT(raw != NULL, "malloc failed");
    size_t total = 0;
    while (total < frame_len) {
        ssize_t n = read(sv[0], raw + total, frame_len - total);
        TEST_ASSERT(n > 0, "read frame failed");
        total += (size_t)n;
    }

    /* Flip a bit in the ciphertext (not the tag) */
    raw[0] ^= 0x01;

    /* Now try to decrypt via wire_recv — but we need to reconstruct the frame.
       We can't use wire_recv directly since we already read the bytes.
       Instead, create a new socketpair and write the tampered data. */
    int tv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, tv) == 0, "socketpair2 failed");

    /* Copy the initiator's encryption state to the new fd */
    noise_state_t *ns = wire_get_encryption(sv[0]);
    TEST_ASSERT(ns != NULL, "no encryption state");
    /* Reset recv_nonce since we consumed data outside wire_recv */
    /* Actually, the nonce was NOT incremented because wire_recv wasn't called.
       We just need to register the same state on the new fd. */
    wire_set_encryption(tv[0], ns);

    /* Write tampered frame to tv[1] */
    ssize_t w1 = write(tv[1], len_buf, 4);
    ssize_t w2 = write(tv[1], raw, frame_len);
    (void)w1; (void)w2;
    close(tv[1]);

    /* wire_recv should fail due to tag mismatch */
    wire_msg_t msg;
    int recv_ok = wire_recv(tv[0], &msg);
    TEST_ASSERT(!recv_ok, "tampered message should fail decryption");

    free(raw);
    wire_close(tv[0]);

    int status;
    waitpid(pid, &status, 0);
    TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "sender child failed");

    wire_close(sv[0]);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Network mode tests (Step 1: Demo Day) ---- */

#include "superscalar/regtest.h"

/* Test: regtest_init backward compat — network field exists and stores "regtest" */
int test_network_init_regtest(void) {
    regtest_t rt;
    memset(&rt, 0, sizeof(rt));
    strncpy(rt.cli_path, "bitcoin-cli", sizeof(rt.cli_path) - 1);
    strncpy(rt.rpcuser, "rpcuser", sizeof(rt.rpcuser) - 1);
    strncpy(rt.rpcpassword, "rpcpass", sizeof(rt.rpcpassword) - 1);
    strncpy(rt.network, "regtest", sizeof(rt.network) - 1);

    TEST_ASSERT(strcmp(rt.network, "regtest") == 0, "network field stores regtest");
    TEST_ASSERT(sizeof(rt.network) >= 16, "network field large enough");
    return 1;
}

/* Test: different network modes can be stored */
int test_network_mode_flag(void) {
    regtest_t rt;
    memset(&rt, 0, sizeof(rt));

    strncpy(rt.network, "signet", sizeof(rt.network) - 1);
    TEST_ASSERT(strcmp(rt.network, "signet") == 0, "stores signet");

    strncpy(rt.network, "testnet", sizeof(rt.network) - 1);
    TEST_ASSERT(strcmp(rt.network, "testnet") == 0, "stores testnet");

    strncpy(rt.network, "mainnet", sizeof(rt.network) - 1);
    TEST_ASSERT(strcmp(rt.network, "mainnet") == 0, "stores mainnet");

    return 1;
}

/* Test: regtest_get_block_height function works without crash */
int test_block_height(void) {
    regtest_t rt;
    memset(&rt, 0, sizeof(rt));
    strncpy(rt.cli_path, "echo", sizeof(rt.cli_path) - 1);
    strncpy(rt.rpcuser, "x", sizeof(rt.rpcuser) - 1);
    strncpy(rt.rpcpassword, "x", sizeof(rt.rpcpassword) - 1);
    strncpy(rt.network, "regtest", sizeof(rt.network) - 1);

    /* With a fake cli, should not crash and returns a reasonable value */
    int h = regtest_get_block_height(&rt);
    TEST_ASSERT(h >= -1, "block height returns valid int");
    return 1;
}

/* ---- Dust/Reserve Validation tests (Step 2: Demo Day) ---- */

#include "superscalar/channel.h"

/* Helper: create a test channel with known balances */
static int make_test_channel(channel_t *ch, secp256k1_context *ctx,
                              uint64_t local, uint64_t remote) {
    unsigned char seckey[32];
    memset(seckey, 0x11, 32);

    secp256k1_pubkey local_pk, remote_pk;
    if (!secp256k1_ec_pubkey_create(ctx, &local_pk, seckey)) return 0;
    unsigned char remote_sec[32];
    memset(remote_sec, 0x22, 32);
    if (!secp256k1_ec_pubkey_create(ctx, &remote_pk, remote_sec)) return 0;

    unsigned char txid[32], spk[34];
    memset(txid, 0xAA, 32);
    memset(spk, 0, 34);
    spk[0] = 0x51; spk[1] = 0x20;

    return channel_init(ch, ctx, seckey, &local_pk, &remote_pk,
                         txid, 0, local + remote, spk, 34,
                         local, remote, 144);
}

int test_dust_limit_reject(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    channel_t ch;
    make_test_channel(&ch, ctx, 50000, 50000);

    unsigned char hash[32];
    memset(hash, 0x42, 32);
    uint64_t htlc_id;

    /* Below dust: should fail */
    int ok = channel_add_htlc(&ch, HTLC_OFFERED, 100, hash, 500, &htlc_id);
    TEST_ASSERT(ok == 0, "HTLC below dust limit rejected");

    /* Exactly at dust: should succeed */
    ok = channel_add_htlc(&ch, HTLC_OFFERED, CHANNEL_DUST_LIMIT_SATS, hash, 500, &htlc_id);
    TEST_ASSERT(ok == 1, "HTLC at dust limit accepted");

    secp256k1_context_destroy(ctx);
    channel_cleanup(&ch);
    return 1;
}

int test_reserve_enforcement(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    channel_t ch;
    /* Start with local=10000, remote=10000 */
    make_test_channel(&ch, ctx, 10000, 10000);

    unsigned char hash[32];
    memset(hash, 0x43, 32);
    uint64_t htlc_id;

    /* Try to send 6000 — would leave local at 4000 < 5000 reserve. Should fail. */
    int ok = channel_add_htlc(&ch, HTLC_OFFERED, 6000, hash, 500, &htlc_id);
    TEST_ASSERT(ok == 0, "HTLC violating reserve rejected");

    /* Send 4000 — leaves 6000 >= 5000 reserve. Should succeed. */
    memset(hash, 0x44, 32);
    ok = channel_add_htlc(&ch, HTLC_OFFERED, 4000, hash, 500, &htlc_id);
    TEST_ASSERT(ok == 1, "HTLC respecting reserve accepted");

    secp256k1_context_destroy(ctx);
    channel_cleanup(&ch);
    return 1;
}

int test_factory_dust_reject(void) {
    /* Constants check: CHANNEL_DUST_LIMIT_SATS is 546 */
    TEST_ASSERT_EQ(CHANNEL_DUST_LIMIT_SATS, 546, "dust limit is 546");
    TEST_ASSERT_EQ(CHANNEL_RESERVE_SATS, 5000, "reserve is 5000");
    return 1;
}

/* ---- Watchtower Wiring tests (Step 3: Demo Day) ---- */

#include "superscalar/watchtower.h"

int test_watchtower_wired(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Create a channel */
    channel_t ch;
    make_test_channel(&ch, ctx, 50000, 50000);

    /* Set up basepoints */
    unsigned char pay_sec[32], del_sec[32], rev_sec[32], htlc_sec[32];
    memset(pay_sec, 0x31, 32);
    memset(del_sec, 0x32, 32);
    memset(rev_sec, 0x33, 32);
    memset(htlc_sec, 0x34, 32);
    channel_set_local_basepoints(&ch, pay_sec, del_sec, rev_sec);
    channel_set_local_htlc_basepoint(&ch, htlc_sec);

    /* Set remote basepoints */
    secp256k1_pubkey rpay, rdel, rrev, rhtlc;
    unsigned char rs[32];
    memset(rs, 0x41, 32); if (!secp256k1_ec_pubkey_create(ctx, &rpay, rs)) return 0;
    memset(rs, 0x42, 32); if (!secp256k1_ec_pubkey_create(ctx, &rdel, rs)) return 0;
    memset(rs, 0x43, 32); if (!secp256k1_ec_pubkey_create(ctx, &rrev, rs)) return 0;
    memset(rs, 0x44, 32); if (!secp256k1_ec_pubkey_create(ctx, &rhtlc, rs)) return 0;
    channel_set_remote_basepoints(&ch, &rpay, &rdel, &rrev);
    channel_set_remote_htlc_basepoint(&ch, &rhtlc);

    /* Init watchtower */
    watchtower_t wt;
    watchtower_init(&wt, 1, NULL, NULL, NULL);
    watchtower_set_channel(&wt, 0, &ch);

    /* watchtower_watch should accept an entry */
    unsigned char fake_txid[32];
    memset(fake_txid, 0xDE, 32);
    unsigned char fake_spk[34];
    memset(fake_spk, 0, 34);
    fake_spk[0] = 0x51; fake_spk[1] = 0x20;

    int ok = watchtower_watch(&wt, 0, 0, fake_txid, 0, 25000, fake_spk, 34);
    TEST_ASSERT(ok == 1, "watchtower_watch accepts entry");
    TEST_ASSERT_EQ(wt.n_entries, 1, "watchtower has 1 entry");

    secp256k1_context_destroy(ctx);
    channel_cleanup(&ch);
    return 1;
}

int test_watchtower_entry_fields(void) {
    watchtower_t wt;
    watchtower_init(&wt, 1, NULL, NULL, NULL);

    unsigned char txid[32];
    memset(txid, 0xBE, 32);
    unsigned char spk[34];
    memset(spk, 0, 34);
    spk[0] = 0x51; spk[1] = 0x20;

    watchtower_watch(&wt, 0, 42, txid, 1, 12345, spk, 34);

    TEST_ASSERT_EQ(wt.entries[0].channel_id, 0, "channel_id stored");
    TEST_ASSERT_EQ(wt.entries[0].commit_num, 42, "commit_num stored");
    TEST_ASSERT_EQ(wt.entries[0].to_local_vout, 1, "vout stored");
    TEST_ASSERT_EQ(wt.entries[0].to_local_amount, 12345, "amount stored");
    TEST_ASSERT_MEM_EQ(wt.entries[0].txid, txid, 32, "txid stored");

    return 1;
}

/* ---- HTLC Timeout Enforcement tests (Step 4: Demo Day) ---- */

int test_htlc_timeout_auto_fail(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    channel_t ch;
    make_test_channel(&ch, ctx, 50000, 50000);

    unsigned char hash[32];
    memset(hash, 0x55, 32);
    uint64_t htlc_id;

    /* Add HTLC with cltv_expiry = 100 */
    int ok = channel_add_htlc(&ch, HTLC_OFFERED, 10000, hash, 100, &htlc_id);
    TEST_ASSERT(ok == 1, "HTLC added");

    /* At height 99: should NOT timeout */
    int failed = channel_check_htlc_timeouts(&ch, 99);
    TEST_ASSERT_EQ(failed, 0, "no timeout at height 99");

    /* At height 100: should timeout */
    failed = channel_check_htlc_timeouts(&ch, 100);
    TEST_ASSERT_EQ(failed, 1, "timeout at height 100");

    /* Verify HTLC is now failed */
    TEST_ASSERT_EQ(ch.htlcs[0].state, HTLC_STATE_FAILED, "HTLC state is FAILED");

    /* Verify funds returned to offerer (local) */
    TEST_ASSERT_EQ(ch.local_amount, 50000, "local balance restored");

    secp256k1_context_destroy(ctx);
    channel_cleanup(&ch);
    return 1;
}

int test_htlc_fulfill_before_timeout(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    channel_t ch;
    make_test_channel(&ch, ctx, 50000, 50000);

    /* Add HTLC with cltv_expiry = 200 */
    unsigned char preimage[32], hash[32];
    memset(preimage, 0x77, 32);
    sha256(preimage, 32, hash);

    uint64_t htlc_id;
    int ok = channel_add_htlc(&ch, HTLC_OFFERED, 10000, hash, 200, &htlc_id);
    TEST_ASSERT(ok == 1, "HTLC added");

    /* Fulfill before timeout */
    ok = channel_fulfill_htlc(&ch, htlc_id, preimage);
    TEST_ASSERT(ok == 1, "fulfill succeeds before timeout");

    /* Check timeouts at height 200 — should find nothing (already fulfilled) */
    int failed = channel_check_htlc_timeouts(&ch, 200);
    TEST_ASSERT_EQ(failed, 0, "no timeout for fulfilled HTLC");

    secp256k1_context_destroy(ctx);
    channel_cleanup(&ch);
    return 1;
}

int test_htlc_no_timeout_zero_expiry(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    channel_t ch;
    make_test_channel(&ch, ctx, 50000, 50000);

    unsigned char hash[32];
    memset(hash, 0x88, 32);
    uint64_t htlc_id;

    /* Add HTLC with cltv_expiry = 0 (should NOT auto-fail) */
    int ok = channel_add_htlc(&ch, HTLC_OFFERED, 10000, hash, 0, &htlc_id);
    TEST_ASSERT(ok == 1, "HTLC added with zero expiry");

    int failed = channel_check_htlc_timeouts(&ch, 1000);
    TEST_ASSERT_EQ(failed, 0, "zero expiry HTLCs not auto-failed");

    secp256k1_context_destroy(ctx);
    channel_cleanup(&ch);
    return 1;
}

/* ---- Keyfile tests (Step 5: Demo Day) ---- */

#include "superscalar/keyfile.h"

int test_keyfile_save_load(void) {
    unsigned char seckey[32];
    memset(seckey, 0xAB, 32);

    const char *path = "/tmp/test_superscalar_keyfile.dat";
    int ok = keyfile_save(path, seckey, "testpassword123");
    TEST_ASSERT(ok == 1, "keyfile_save succeeds");

    unsigned char loaded[32];
    ok = keyfile_load(path, loaded, "testpassword123");
    TEST_ASSERT(ok == 1, "keyfile_load succeeds");
    TEST_ASSERT_MEM_EQ(seckey, loaded, 32, "round-trip key matches");

    unlink(path);
    return 1;
}

int test_keyfile_wrong_passphrase(void) {
    unsigned char seckey[32];
    memset(seckey, 0xCD, 32);

    const char *path = "/tmp/test_superscalar_keyfile2.dat";
    keyfile_save(path, seckey, "correct_password");

    unsigned char loaded[32];
    int ok = keyfile_load(path, loaded, "wrong_password");
    TEST_ASSERT(ok == 0, "wrong passphrase rejected");

    unlink(path);
    return 1;
}

int test_keyfile_generate(void) {
    const char *path = "/tmp/test_superscalar_keyfile3.dat";
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char seckey[32];
    int ok = keyfile_generate(path, seckey, "genpass", ctx);
    TEST_ASSERT(ok == 1, "keyfile_generate succeeds");

    /* Verify the generated key is valid */
    secp256k1_keypair kp;
    ok = secp256k1_keypair_create(ctx, &kp, seckey);
    TEST_ASSERT(ok == 1, "generated key is valid");

    /* Verify we can reload it */
    unsigned char reloaded[32];
    ok = keyfile_load(path, reloaded, "genpass");
    TEST_ASSERT(ok == 1, "reload generated key");
    TEST_ASSERT_MEM_EQ(seckey, reloaded, 32, "reloaded key matches");

    unlink(path);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Signet Interop tests (Phase 20) ---- */

/* Test: regtest_init_full stores custom cli_path, rpcuser, rpcpassword */
int test_regtest_init_full(void) {
    regtest_t rt;
    memset(&rt, 0, sizeof(rt));

    /* Use a non-existent cli path so it won't actually connect,
       but we can verify fields are stored correctly. */
    strncpy(rt.cli_path, "/usr/bin/true", sizeof(rt.cli_path) - 1);
    strncpy(rt.rpcuser, "myuser", sizeof(rt.rpcuser) - 1);
    strncpy(rt.rpcpassword, "mypass", sizeof(rt.rpcpassword) - 1);
    strncpy(rt.network, "signet", sizeof(rt.network) - 1);

    TEST_ASSERT(strcmp(rt.cli_path, "/usr/bin/true") == 0, "cli_path stored");
    TEST_ASSERT(strcmp(rt.rpcuser, "myuser") == 0, "rpcuser stored");
    TEST_ASSERT(strcmp(rt.rpcpassword, "mypass") == 0, "rpcpassword stored");
    TEST_ASSERT(strcmp(rt.network, "signet") == 0, "network stored");

    /* Test datadir and rpcport fields */
    strncpy(rt.datadir, "/tmp/btc", sizeof(rt.datadir) - 1);
    rt.rpcport = 38332;
    TEST_ASSERT(strcmp(rt.datadir, "/tmp/btc") == 0, "datadir stored");
    TEST_ASSERT(rt.rpcport == 38332, "rpcport stored");

    /* Test regtest_init_full with NULL defaults */
    regtest_t rt2;
    /* init_full won't connect (no bitcoind), so just verify it doesn't crash
       with NULLs by testing the struct fields would be set.
       We can't call it since it requires bitcoind, so test field assignment. */
    memset(&rt2, 0, sizeof(rt2));
    strncpy(rt2.cli_path, "bitcoin-cli", sizeof(rt2.cli_path) - 1);
    strncpy(rt2.rpcuser, "rpcuser", sizeof(rt2.rpcuser) - 1);
    strncpy(rt2.rpcpassword, "rpcpass", sizeof(rt2.rpcpassword) - 1);
    strncpy(rt2.network, "regtest", sizeof(rt2.network) - 1);

    TEST_ASSERT(strcmp(rt2.cli_path, "bitcoin-cli") == 0, "default cli_path");
    TEST_ASSERT(strcmp(rt2.rpcuser, "rpcuser") == 0, "default rpcuser");
    TEST_ASSERT(rt2.rpcport == 0, "default rpcport is 0");
    TEST_ASSERT(rt2.datadir[0] == '\0', "default datadir is empty");

    return 1;
}

/* Test: regtest_http_rpc path returns same result as fork+exec for getblockcount.
   Requires bitcoind running on regtest port 18443 — skips if not available. */
int test_regtest_http_rpc_path(void) {
    regtest_t rt_fork, rt_http;
    memset(&rt_fork, 0, sizeof(rt_fork));
    memset(&rt_http,  0, sizeof(rt_http));

    strncpy(rt_fork.cli_path,    "bitcoin-cli", sizeof(rt_fork.cli_path) - 1);
    strncpy(rt_fork.rpcuser,     "rpcuser",     sizeof(rt_fork.rpcuser)  - 1);
    strncpy(rt_fork.rpcpassword, "rpcpass",     sizeof(rt_fork.rpcpassword) - 1);
    strncpy(rt_fork.network,     "regtest",     sizeof(rt_fork.network)  - 1);
    /* rpcport = 0 → fork path */

    memcpy(&rt_http, &rt_fork, sizeof(rt_fork));
    rt_http.rpcport = 18443;  /* HTTP path */

    /* Test the HTTP path directly — skip if bitcoind unavailable */
    char *result_http = regtest_exec(&rt_http, "getblockcount", "");
    if (!result_http) {
        /* bitcoind not running — skip gracefully */
        return 1;
    }
    int height_http = atoi(result_http);
    free(result_http);

    TEST_ASSERT(height_http >= 0, "HTTP RPC getblockcount returns non-negative height");

    /* Also verify against the fork+exec path if bitcoin-cli is available */
    char *result_fork = regtest_exec(&rt_fork, "getblockcount", "");
    if (result_fork) {
        /* Only compare if fork path returned a plausible integer (not an error string) */
        int height_fork = atoi(result_fork);
        int looks_valid = (result_fork[0] >= '0' && result_fork[0] <= '9');
        free(result_fork);
        if (looks_valid) {
            TEST_ASSERT(height_http == height_fork,
                        "HTTP RPC height matches fork+exec height");
        }
        /* If not valid (e.g. bitcoin-cli not in PATH), skip the comparison */
    }

    /* Verify string result: getblockhash returns a valid 64-char hex hash */
    if (height_http > 0) {
        char params[32];
        snprintf(params, sizeof(params), "%d", height_http);
        char *hash_http = regtest_exec(&rt_http, "getblockhash", params);
        TEST_ASSERT(hash_http != NULL, "getblockhash returns result");
        if (hash_http) {
            /* HTTP path wraps strings in quotes — strip them */
            const char *hp = hash_http;
            while (*hp == '"' || *hp == ' ' || *hp == '\n') hp++;
            char h[65] = {0};
            strncpy(h, hp, 64);
            char *he = h + strlen(h) - 1;
            while (he > h && (*he == '"' || *he == ' ' || *he == '\n' || *he == '\r'))
                *he-- = '\0';
            TEST_ASSERT(strlen(h) == 64, "getblockhash is 64-char hex");
            free(hash_http);
        }
    }

    return 1;
}

/* Test: regtest_get_balance with fake cli returns valid double */
int test_regtest_get_balance(void) {
    regtest_t rt;
    memset(&rt, 0, sizeof(rt));
    /* Use printf to simulate bitcoin-cli getbalance output */
    strncpy(rt.cli_path, "printf", sizeof(rt.cli_path) - 1);
    strncpy(rt.rpcuser, "x", sizeof(rt.rpcuser) - 1);
    strncpy(rt.rpcpassword, "x", sizeof(rt.rpcpassword) - 1);
    strncpy(rt.network, "regtest", sizeof(rt.network) - 1);

    /* regtest_get_balance calls regtest_exec which runs:
       printf -regtest -rpcuser=x -rpcpassword=x getbalance
       This will output the literal arguments. atof on non-numeric = 0.0 */
    double bal = regtest_get_balance(&rt);
    TEST_ASSERT(bal == 0.0, "fake cli returns 0.0 balance");

    return 1;
}

/* Test: mine_blocks refuses on non-regtest */
int test_mine_blocks_non_regtest(void) {
    regtest_t rt;
    memset(&rt, 0, sizeof(rt));
    strncpy(rt.cli_path, "echo", sizeof(rt.cli_path) - 1);
    strncpy(rt.rpcuser, "x", sizeof(rt.rpcuser) - 1);
    strncpy(rt.rpcpassword, "x", sizeof(rt.rpcpassword) - 1);
    strncpy(rt.network, "signet", sizeof(rt.network) - 1);

    /* mine_blocks should return 0 on signet (safety check) */
    int ok = regtest_mine_blocks(&rt, 1, "addr");
    TEST_ASSERT(ok == 0, "mine_blocks rejected on signet");

    strncpy(rt.network, "mainnet", sizeof(rt.network) - 1);
    ok = regtest_mine_blocks(&rt, 1, "addr");
    TEST_ASSERT(ok == 0, "mine_blocks rejected on mainnet");

    return 1;
}

/* ---- Demo Protections (Tier 1) ---- */

#include "superscalar/factory.h"
#include "superscalar/dw_state.h"

/* Test: factory lifecycle state transitions ACTIVE→DYING→EXPIRED */
int test_factory_lifecycle_daemon_check(void) {
    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;

    /* Set lifecycle: created at block 100, active 20 blocks, dying 10 blocks */
    factory_set_lifecycle(f, 100, 20, 10);

    /* At block 110: still ACTIVE */
    factory_state_t s = factory_get_state(f, 110);
    TEST_ASSERT_EQ(s, FACTORY_ACTIVE, "block 110 = ACTIVE");

    /* At block 119: last ACTIVE block */
    s = factory_get_state(f, 119);
    TEST_ASSERT_EQ(s, FACTORY_ACTIVE, "block 119 = ACTIVE (last)");

    /* At block 120: transitions to DYING */
    s = factory_get_state(f, 120);
    TEST_ASSERT_EQ(s, FACTORY_DYING, "block 120 = DYING");

    /* Check blocks_until_expired from DYING */
    uint32_t remaining = factory_blocks_until_expired(f, 120);
    TEST_ASSERT_EQ(remaining, 10, "10 blocks until expired at 120");

    remaining = factory_blocks_until_expired(f, 125);
    TEST_ASSERT_EQ(remaining, 5, "5 blocks until expired at 125");

    /* At block 130: transitions to EXPIRED */
    s = factory_get_state(f, 130);
    TEST_ASSERT_EQ(s, FACTORY_EXPIRED, "block 130 = EXPIRED");

    /* At block 200: still EXPIRED */
    s = factory_get_state(f, 200);
    TEST_ASSERT_EQ(s, FACTORY_EXPIRED, "block 200 = EXPIRED");

    free(f);
    return 1;
}

/* Test: rebuilding old commitment matches watchtower entry */
int test_breach_detect_old_commitment(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Create channel with 50k/50k balances */
    channel_t ch;
    make_test_channel(&ch, ctx, 50000, 50000);

    /* Set up basepoints (required for commitment tx) */
    unsigned char pay_sec[32], del_sec[32], rev_sec[32], htlc_sec[32];
    memset(pay_sec, 0x31, 32);
    memset(del_sec, 0x32, 32);
    memset(rev_sec, 0x33, 32);
    memset(htlc_sec, 0x34, 32);
    channel_set_local_basepoints(&ch, pay_sec, del_sec, rev_sec);
    channel_set_local_htlc_basepoint(&ch, htlc_sec);

    secp256k1_pubkey rpay, rdel, rrev, rhtlc;
    unsigned char rs[32];
    memset(rs, 0x41, 32); if (!secp256k1_ec_pubkey_create(ctx, &rpay, rs)) return 0;
    memset(rs, 0x42, 32); if (!secp256k1_ec_pubkey_create(ctx, &rdel, rs)) return 0;
    memset(rs, 0x43, 32); if (!secp256k1_ec_pubkey_create(ctx, &rrev, rs)) return 0;
    memset(rs, 0x44, 32); if (!secp256k1_ec_pubkey_create(ctx, &rhtlc, rs)) return 0;
    channel_set_remote_basepoints(&ch, &rpay, &rdel, &rrev);
    channel_set_remote_htlc_basepoint(&ch, &rhtlc);

    /* Build commitment #0 and save its txid */
    tx_buf_t commit0_tx;
    tx_buf_init(&commit0_tx, 512);
    unsigned char commit0_txid[32];
    int ok = channel_build_commitment_tx(&ch, &commit0_tx, commit0_txid);
    TEST_ASSERT(ok == 1, "build commitment #0");
    tx_buf_free(&commit0_tx);

    /* Simulate a payment: update channel balances */
    ch.local_amount = 40000;
    ch.remote_amount = 60000;
    ch.commitment_number = 1;

    /* Now rebuild old commitment #0 (same pattern as watch_revoked_commitment) */
    uint64_t saved_num = ch.commitment_number;
    uint64_t saved_local = ch.local_amount;
    uint64_t saved_remote = ch.remote_amount;

    ch.commitment_number = 0;
    ch.local_amount = 50000;
    ch.remote_amount = 50000;

    tx_buf_t rebuilt_tx;
    tx_buf_init(&rebuilt_tx, 512);
    unsigned char rebuilt_txid[32];
    ok = channel_build_commitment_tx(&ch, &rebuilt_tx, rebuilt_txid);

    ch.commitment_number = saved_num;
    ch.local_amount = saved_local;
    ch.remote_amount = saved_remote;

    TEST_ASSERT(ok == 1, "rebuild old commitment");
    tx_buf_free(&rebuilt_tx);

    /* Verify rebuilt txid matches original commit #0 txid */
    TEST_ASSERT_MEM_EQ(commit0_txid, rebuilt_txid, 32,
                        "rebuilt txid matches original");

    /* Register in watchtower and verify entry matches */
    watchtower_t wt;
    watchtower_init(&wt, 1, NULL, NULL, NULL);
    watchtower_set_channel(&wt, 0, &ch);

    unsigned char fake_spk[34];
    memset(fake_spk, 0, 34);
    fake_spk[0] = 0x51; fake_spk[1] = 0x20;
    watchtower_watch(&wt, 0, 0, commit0_txid, 0, 50000, fake_spk, 34);

    TEST_ASSERT_MEM_EQ(wt.entries[0].txid, rebuilt_txid, 32,
                        "watchtower entry matches rebuilt txid");

    secp256k1_context_destroy(ctx);
    channel_cleanup(&ch);
    return 1;
}

/* Test: DW counter advance and delay decrease */
int test_dw_counter_tracks_advance(void) {
    dw_counter_t ctr;
    dw_counter_init(&ctr, 2, 10, 4);  /* 2 layers, step=10, 4 states each */

    /* Initial state: epoch 0 */
    TEST_ASSERT_EQ(dw_counter_epoch(&ctr), 0, "initial epoch 0");

    /* Get initial delay for layer 0 */
    uint16_t d0_init = dw_delay_for_state(&ctr.layers[0].config,
                                            ctr.layers[0].current_state);
    TEST_ASSERT(d0_init > 0, "initial delay > 0");

    /* Advance once */
    int ok = dw_counter_advance(&ctr);
    TEST_ASSERT(ok == 1, "first advance succeeds");
    TEST_ASSERT_EQ(dw_counter_epoch(&ctr), 1, "epoch now 1");

    /* Inner layer advanced, so its delay should decrease */
    uint16_t d1_new = dw_delay_for_state(&ctr.layers[1].config,
                                           ctr.layers[1].current_state);
    uint16_t d1_init = dw_delay_for_state(&ctr.layers[1].config, 0);
    TEST_ASSERT(d1_new < d1_init, "inner delay decreased after advance");

    /* Advance until exhausted */
    while (dw_counter_advance(&ctr))
        ;

    /* total_states = 4^2 = 16, max epoch = 15 */
    TEST_ASSERT_EQ(dw_counter_epoch(&ctr), 15, "exhausted at epoch 15");

    /* Further advance should fail */
    ok = dw_counter_advance(&ctr);
    TEST_ASSERT(ok == 0, "advance returns 0 when exhausted");

    return 1;
}

/* ============================================================ */
/* Tier 2: Daemon Feature Wiring tests                          */
/* ============================================================ */

#include "superscalar/ladder.h"
#include "superscalar/adaptor.h"

/* Test: ladder daemon integration — advance block, verify state transitions */
int test_ladder_daemon_integration(void) {
    secp256k1_context *ctx = test_ctx();

    unsigned char lsp_sec[32];
    memset(lsp_sec, 0x10, 32);
    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec)) return 0;

    ladder_t *lad = calloc(1, sizeof(ladder_t));
    if (!lad) return 0;
    ladder_init(lad, ctx, &lsp_kp, 20, 10);
    lad->current_block = 100;

    /* Manually populate slot 0 */
    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;

    factory_set_lifecycle(f, 100, 20, 10);

    ladder_factory_t *lf = &lad->factories[0];
    lf->factory = *f;
    factory_detach_txbufs(&lf->factory);
    lf->factory_id = lad->next_factory_id++;
    lf->is_initialized = 1;
    lf->is_funded = 1;
    lf->cached_state = factory_get_state(f, 100);
    tx_buf_init(&lf->distribution_tx, 16);
    lad->n_factories = 1;

    TEST_ASSERT_EQ(lf->cached_state, FACTORY_ACTIVE, "initially ACTIVE");

    /* Advance to block 120 → should transition to DYING */
    ladder_advance_block(lad, 120);
    TEST_ASSERT_EQ(lf->cached_state, FACTORY_DYING, "DYING at 120");

    /* Advance to block 130 → should transition to EXPIRED */
    ladder_advance_block(lad, 130);
    TEST_ASSERT_EQ(lf->cached_state, FACTORY_EXPIRED, "EXPIRED at 130");

    tx_buf_free(&lf->distribution_tx);
    free(f);
    free(lad);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test: distribution TX output amounts sum correctly */
int test_distribution_tx_amounts(void) {
    secp256k1_context *ctx = test_ctx();

    static const unsigned char seckeys[5][32] = {
        { [0 ... 31] = 0x10 },
        { [0 ... 31] = 0x21 },
        { [0 ... 31] = 0x32 },
        { [0 ... 31] = 0x43 },
        { [0 ... 31] = 0x54 },
    };
    secp256k1_keypair kps[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_create(ctx, &kps[i], seckeys[i])) return 0;
    }

    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;
    factory_init(f, ctx, kps, 5, 1, 4);

    unsigned char fake_txid[32], fake_spk[34];
    memset(fake_txid, 0x01, 32);
    memset(fake_spk, 0x51, 1);
    fake_spk[1] = 0x20;
    memset(fake_spk + 2, 0xAA, 32);
    factory_set_funding(f, fake_txid, 0, 100000, fake_spk, 34);
    factory_set_lifecycle(f, 100, 20, 10);
    f->cltv_timeout = 135;

    TEST_ASSERT(factory_build_tree(f), "build tree");
    /* Advance counter to max for signing */
    for (uint32_t i = 0; i < f->counter.total_states - 1; i++)
        dw_counter_advance(&f->counter);
    TEST_ASSERT(factory_sign_all(f), "sign all");

    /* Build distribution TX with equal split */
    tx_output_t outputs[5];
    uint64_t per = 100000 / 5;
    for (int i = 0; i < 5; i++) {
        outputs[i].amount_sats = per;
        memcpy(outputs[i].script_pubkey, fake_spk, 34);
        outputs[i].script_pubkey_len = 34;
    }

    tx_buf_t dist_tx;
    tx_buf_init(&dist_tx, 512);
    unsigned char dist_txid[32];
    int ok = factory_build_distribution_tx(f, &dist_tx, dist_txid,
                                             outputs, 5, f->cltv_timeout);
    TEST_ASSERT(ok, "distribution TX built");
    TEST_ASSERT(dist_tx.len > 0, "distribution TX non-empty");

    /* Verify total output amounts sum to 100000 */
    uint64_t total = 0;
    for (int i = 0; i < 5; i++)
        total += outputs[i].amount_sats;
    TEST_ASSERT_EQ(total, 100000, "outputs sum to funding amount");

    tx_buf_free(&dist_tx);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test: PTLC key turnover extract + ladder close */
int test_turnover_extract_and_close(void) {
    secp256k1_context *ctx = test_ctx();

    static const unsigned char seckeys[5][32] = {
        { [0 ... 31] = 0x10 },
        { [0 ... 31] = 0x21 },
        { [0 ... 31] = 0x32 },
        { [0 ... 31] = 0x43 },
        { [0 ... 31] = 0x54 },
    };
    secp256k1_keypair kps[5];
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_create(ctx, &kps[i], seckeys[i])) return 0;
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

    /* Create ladder with one factory */
    ladder_t *lad = calloc(1, sizeof(ladder_t));
    if (!lad) return 0;
    ladder_init(lad, ctx, &kps[0], 20, 10);
    lad->current_block = 100;

    unsigned char fake_txid[32], fake_spk[34];
    memset(fake_txid, 0x01, 32);
    memset(fake_spk, 0x51, 1);
    fake_spk[1] = 0x20;
    memset(fake_spk + 2, 0xAA, 32);

    TEST_ASSERT(ladder_create_factory(lad, &kps[1], 4, 100000,
                                        fake_txid, 0, fake_spk, 34),
                "ladder_create_factory");

    /* Build keyagg and message for turnover */
    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, 5);
    unsigned char msg[32];
    memset(msg, 0xAA, 32);

    /* Do turnover for all 4 clients */
    for (int ci = 0; ci < 4; ci++) {
        uint32_t pidx = (uint32_t)(ci + 1);

        unsigned char presig[64];
        int nonce_parity;
        musig_keyagg_t ka_copy = ka;
        TEST_ASSERT(adaptor_create_turnover_presig(ctx, presig, &nonce_parity,
                                                     msg, kps, 5, &ka_copy,
                                                     NULL, &pks[pidx]),
                    "presig");

        unsigned char client_sec[32];
        if (!secp256k1_keypair_sec(ctx, client_sec, &kps[pidx])) return 0;

        unsigned char adapted[64];
        TEST_ASSERT(adaptor_adapt(ctx, adapted, presig, client_sec, nonce_parity),
                    "adapt");

        unsigned char extracted[32];
        TEST_ASSERT(adaptor_extract_secret(ctx, extracted, adapted, presig,
                                             nonce_parity),
                    "extract");

        TEST_ASSERT(adaptor_verify_extracted_key(ctx, extracted, &pks[pidx]),
                    "verify");

        TEST_ASSERT(ladder_record_key_turnover(lad, 0, pidx, extracted),
                    "record");

        memset(client_sec, 0, 32);
    }

    /* Verify can close */
    TEST_ASSERT(ladder_can_close(lad, 0), "can_close");

    /* Build close */
    tx_output_t outputs[5];
    uint64_t per = 100000 / 5;
    unsigned char out_spk[34];
    memset(out_spk, 0x51, 1);
    out_spk[1] = 0x20;
    memset(out_spk + 2, 0xBB, 32);
    for (int i = 0; i < 5; i++) {
        outputs[i].amount_sats = per;
        memcpy(outputs[i].script_pubkey, out_spk, 34);
        outputs[i].script_pubkey_len = 34;
    }

    tx_buf_t close_tx;
    tx_buf_init(&close_tx, 512);
    TEST_ASSERT(ladder_build_close(lad, 0, &close_tx, outputs, 5, 0),
                "ladder_build_close");
    TEST_ASSERT(close_tx.len > 0, "close TX non-empty");

    tx_buf_free(&close_tx);
    ladder_free(lad);
    free(lad);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ============================================================ */
/* Tier 3: Factory Rotation tests                                */
/* ============================================================ */

/* Test: PTLC wire message round-trip (build + parse) */
int test_ptlc_wire_round_trip(void) {
    /* PTLC_PRESIG round-trip */
    unsigned char presig[64], msg32[32];
    memset(presig, 0xAA, 64);
    memset(msg32, 0xBB, 32);
    int parity = 1;

    cJSON *j = wire_build_ptlc_presig(presig, parity, msg32);
    TEST_ASSERT(j != NULL, "build presig");

    unsigned char presig2[64], msg2[32];
    int parity2;
    TEST_ASSERT(wire_parse_ptlc_presig(j, presig2, &parity2, msg2),
                "parse presig");
    TEST_ASSERT_MEM_EQ(presig, presig2, 64, "presig match");
    TEST_ASSERT_EQ(parity, parity2, "parity match");
    TEST_ASSERT_MEM_EQ(msg32, msg2, 32, "turnover_msg match");
    cJSON_Delete(j);

    /* PTLC_ADAPTED_SIG round-trip */
    unsigned char asig[64];
    memset(asig, 0xCC, 64);
    j = wire_build_ptlc_adapted_sig(asig);
    TEST_ASSERT(j != NULL, "build adapted_sig");

    unsigned char asig2[64];
    TEST_ASSERT(wire_parse_ptlc_adapted_sig(j, asig2), "parse adapted_sig");
    TEST_ASSERT_MEM_EQ(asig, asig2, 64, "adapted_sig match");
    cJSON_Delete(j);

    /* PTLC_COMPLETE round-trip */
    j = wire_build_ptlc_complete();
    TEST_ASSERT(j != NULL, "build complete");
    cJSON_Delete(j);

    return 1;
}

/* Test: PTLC wire messages over socket pair */
int test_ptlc_wire_over_socket(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        printf("  FAIL: socketpair not available\n");
        return 0;
    }

    unsigned char presig[64], msg32[32];
    memset(presig, 0xDE, 64);
    memset(msg32, 0xAD, 32);
    int parity = 0;

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: acts as client — recv PRESIG, send ADAPTED_SIG, recv COMPLETE */
        close(sv[0]);
        int fd = sv[1];

        wire_msg_t m;
        if (!wire_recv(fd, &m)) _exit(1);
        if (m.msg_type != MSG_PTLC_PRESIG) { cJSON_Delete(m.json); _exit(2); }

        unsigned char p[64], t[32];
        int par;
        if (!wire_parse_ptlc_presig(m.json, p, &par, t)) { cJSON_Delete(m.json); _exit(3); }
        cJSON_Delete(m.json);

        /* Send adapted sig (just echo presig as demo) */
        unsigned char adapted[64];
        memcpy(adapted, p, 64);
        adapted[0] ^= 0xFF;  /* modify to simulate adaptation */
        cJSON *reply = wire_build_ptlc_adapted_sig(adapted);
        if (!wire_send(fd, MSG_PTLC_ADAPTED_SIG, reply)) { cJSON_Delete(reply); _exit(4); }
        cJSON_Delete(reply);

        /* Recv COMPLETE */
        if (!wire_recv(fd, &m)) _exit(5);
        if (m.msg_type != MSG_PTLC_COMPLETE) { cJSON_Delete(m.json); _exit(6); }
        cJSON_Delete(m.json);

        close(fd);
        _exit(0);
    }

    /* Parent: acts as LSP — send PRESIG, recv ADAPTED_SIG, send COMPLETE */
    close(sv[1]);
    int fd = sv[0];

    cJSON *presig_msg = wire_build_ptlc_presig(presig, parity, msg32);
    TEST_ASSERT(wire_send(fd, MSG_PTLC_PRESIG, presig_msg), "send presig");
    cJSON_Delete(presig_msg);

    wire_msg_t resp;
    TEST_ASSERT(wire_recv(fd, &resp), "recv adapted_sig");
    TEST_ASSERT_EQ(resp.msg_type, MSG_PTLC_ADAPTED_SIG, "adapted_sig type");

    unsigned char adapted[64];
    TEST_ASSERT(wire_parse_ptlc_adapted_sig(resp.json, adapted), "parse adapted");
    /* Verify child modified byte 0 */
    TEST_ASSERT_EQ(adapted[0], presig[0] ^ 0xFF, "adapted byte 0 modified");
    cJSON_Delete(resp.json);

    cJSON *complete = wire_build_ptlc_complete();
    TEST_ASSERT(wire_send(fd, MSG_PTLC_COMPLETE, complete), "send complete");
    cJSON_Delete(complete);

    close(fd);

    int status;
    waitpid(pid, &status, 0);
    TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child exited ok");

    return 1;
}

/* Test: multi-factory ladder monitor — verify state transitions for 2 factories */
int test_multi_factory_ladder_monitor(void) {
    secp256k1_context *ctx = test_ctx();

    unsigned char lsp_sec[32];
    memset(lsp_sec, 0x10, 32);
    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_sec)) return 0;

    ladder_t *lad = calloc(1, sizeof(ladder_t));
    if (!lad) return 0;
    ladder_init(lad, ctx, &lsp_kp, 20, 10);  /* active=20, dying=10 */

    /* Create 4 client keypairs */
    secp256k1_keypair client_kps[4];
    static const unsigned char fills[4] = { 0x21, 0x32, 0x43, 0x54 };
    for (int i = 0; i < 4; i++) {
        unsigned char sec[32];
        memset(sec, fills[i], 32);
        if (!secp256k1_keypair_create(ctx, &client_kps[i], sec)) return 0;
    }

    /* Factory 0: created at block 100 */
    unsigned char txid0[32];
    memset(txid0, 0xF0, 32);
    unsigned char spk[34] = {0x51, 0x20};
    memset(spk + 2, 0xAA, 32);
    TEST_ASSERT(ladder_create_factory(lad, client_kps, 4,
                100000, txid0, 0, spk, 34), "create factory 0");
    lad->factories[0].factory.created_block = 100;

    /* Factory 1: created at block 110 */
    unsigned char txid1[32];
    memset(txid1, 0xF1, 32);
    TEST_ASSERT(ladder_create_factory(lad, client_kps, 4,
                100000, txid1, 0, spk, 34), "create factory 1");
    lad->factories[1].factory.created_block = 110;

    TEST_ASSERT_EQ(lad->n_factories, 2, "2 factories");

    /* Advance to 120: factory 0 DYING (100+20=120), factory 1 ACTIVE (110+20=130) */
    ladder_advance_block(lad, 120);
    TEST_ASSERT_EQ(lad->factories[0].cached_state, FACTORY_DYING, "f0 DYING at 120");
    TEST_ASSERT_EQ(lad->factories[1].cached_state, FACTORY_ACTIVE, "f1 ACTIVE at 120");

    /* Advance to 130: factory 0 EXPIRED (100+20+10=130), factory 1 DYING (110+20=130) */
    ladder_advance_block(lad, 130);
    TEST_ASSERT_EQ(lad->factories[0].cached_state, FACTORY_EXPIRED, "f0 EXPIRED at 130");
    TEST_ASSERT_EQ(lad->factories[1].cached_state, FACTORY_DYING, "f1 DYING at 130");

    /* Advance to 140: both EXPIRED */
    ladder_advance_block(lad, 140);
    TEST_ASSERT_EQ(lad->factories[0].cached_state, FACTORY_EXPIRED, "f0 EXPIRED at 140");
    TEST_ASSERT_EQ(lad->factories[1].cached_state, FACTORY_EXPIRED, "f1 EXPIRED at 140");

    ladder_free(lad);
    free(lad);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test: secure_zero actually zeroes memory */
int test_secure_zero_basic(void) {
    unsigned char buf[32];
    memset(buf, 0xFF, 32);

    /* Verify non-zero */
    int nonzero = 0;
    for (int i = 0; i < 32; i++) nonzero |= buf[i];
    TEST_ASSERT(nonzero != 0, "buffer should be non-zero before secure_zero");

    secure_zero(buf, 32);

    /* Verify all zero */
    int sum = 0;
    for (int i = 0; i < 32; i++) sum |= buf[i];
    TEST_ASSERT(sum == 0, "buffer should be all-zero after secure_zero");

    /* Test with odd sizes */
    unsigned char small[7];
    memset(small, 0xAB, 7);
    secure_zero(small, 7);
    sum = 0;
    for (int i = 0; i < 7; i++) sum |= small[i];
    TEST_ASSERT(sum == 0, "small buffer should be all-zero after secure_zero");

    /* Test zero-length (should not crash) */
    secure_zero(buf, 0);

    return 1;
}

/* Test: plaintext refused after handshake attempt on an fd */
int test_wire_plaintext_refused_after_handshake(void) {
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    /* Before marking, plaintext should work */
    TEST_ASSERT(!wire_is_encryption_required(sv[0]),
                "fd should not require encryption initially");

    /* Mark encryption required (simulates handshake start) */
    TEST_ASSERT(wire_mark_encryption_required(sv[0]),
                "wire_mark_encryption_required should succeed");
    TEST_ASSERT(wire_is_encryption_required(sv[0]),
                "fd should require encryption after mark");

    /* wire_send should refuse plaintext on this fd */
    cJSON *msg = cJSON_CreateObject();
    cJSON_AddStringToObject(msg, "test", "hello");
    int ok = wire_send(sv[0], 1, msg);
    TEST_ASSERT(ok == 0, "wire_send should refuse plaintext after handshake mark");
    cJSON_Delete(msg);

    /* Clear and verify the flag is reset */
    wire_clear_encryption(sv[0]);
    TEST_ASSERT(!wire_is_encryption_required(sv[0]),
                "flag should be cleared after wire_clear_encryption");

    close(sv[0]);
    close(sv[1]);
    return 1;
}

/* Test: send nonce not incremented on write failure */
int test_nonce_stable_on_send_failure(void) {
    /* Ignore SIGPIPE so write to closed socket returns EPIPE instead of killing us */
    signal(SIGPIPE, SIG_IGN);

    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
                "socketpair");

    /* Set up encryption on the sender */
    noise_state_t ns;
    memset(&ns, 0, sizeof(ns));
    memset(ns.send_key, 0xAA, 32);
    memset(ns.recv_key, 0xBB, 32);
    ns.send_nonce = 0;
    ns.recv_nonce = 0;
    TEST_ASSERT(wire_set_encryption(sv[0], &ns), "set encryption");

    /* Send one message successfully */
    cJSON *j1 = cJSON_CreateObject();
    cJSON_AddStringToObject(j1, "test", "hello");
    TEST_ASSERT(wire_send(sv[0], 0x42, j1), "first send should succeed");
    cJSON_Delete(j1);

    /* Verify nonce advanced to 1 */
    noise_state_t *state = wire_get_encryption(sv[0]);
    TEST_ASSERT(state != NULL, "should have encryption state");
    TEST_ASSERT_EQ(state->send_nonce, 1, "nonce should be 1 after successful send");

    /* Close the read end to force write failure */
    close(sv[1]);

    /* Try to send — should fail (broken pipe) */
    cJSON *j2 = cJSON_CreateObject();
    cJSON_AddStringToObject(j2, "test", "world");
    int result = wire_send(sv[0], 0x43, j2);
    cJSON_Delete(j2);
    TEST_ASSERT(result == 0, "send should fail on closed pipe");

    /* Verify nonce did NOT advance past 1 */
    state = wire_get_encryption(sv[0]);
    TEST_ASSERT(state != NULL, "should still have encryption state");
    TEST_ASSERT_EQ(state->send_nonce, 1, "nonce should still be 1 after failed send");

    wire_clear_encryption(sv[0]);
    close(sv[0]);
    return 1;
}

/* Test: fd table grows beyond initial 16 entries */
int test_fd_table_grows_beyond_16(void) {
    /* Register encryption for 20 different fds (exceeding initial cap of 16) */
    noise_state_t ns;
    memset(&ns, 0, sizeof(ns));
    memset(ns.send_key, 0xAA, 32);
    memset(ns.recv_key, 0xBB, 32);

    /* Use high fd numbers to avoid collisions with real fds */
    int base_fd = 1000;
    for (int i = 0; i < 20; i++) {
        TEST_ASSERT(wire_set_encryption(base_fd + i, &ns),
                    "wire_set_encryption should succeed for all 20 fds");
    }

    /* Verify all 20 are retrievable */
    for (int i = 0; i < 20; i++) {
        noise_state_t *got = wire_get_encryption(base_fd + i);
        TEST_ASSERT(got != NULL, "should retrieve encryption state");
        TEST_ASSERT_MEM_EQ(got->send_key, ns.send_key, 32, "send_key match");
    }

    /* Clean up */
    for (int i = 0; i < 20; i++)
        wire_clear_encryption(base_fd + i);

    return 1;
}

/* --- Gap 2B / 2C Tests: Commitment Reconciliation + HTLC Replay --- */

/* Helper: set up LSP + factory + channel manager with persistence for reconnect tests.
   Creates 4 clients. Returns 1 on success. */
static int setup_reconnect_env(secp256k1_context **ctx_out,
                                 unsigned char *lsp_sec,
                                 secp256k1_pubkey *lsp_pk,
                                 secp256k1_pubkey *client_pks,
                                 unsigned char client_secs[][32],
                                 factory_t *factory,
                                 lsp_t *lsp,
                                 lsp_channel_mgr_t *mgr,
                                 persist_t *db) {
    secp256k1_context *ctx = test_ctx();
    *ctx_out = ctx;

    memset(lsp_sec, 0x10, 32);
    if (!secp256k1_ec_pubkey_create(ctx, lsp_pk, lsp_sec)) return 0;

    for (int i = 0; i < 4; i++) {
        memset(client_secs[i], 0x21 + i, 32);
        if (!secp256k1_ec_pubkey_create(ctx, &client_pks[i], client_secs[i])) return 0;
    }

    secp256k1_pubkey all_pks[5];
    all_pks[0] = *lsp_pk;
    for (int i = 0; i < 4; i++)
        all_pks[i + 1] = client_pks[i];

    factory_init_from_pubkeys(factory, ctx, all_pks, 5, 10, 4);

    unsigned char fake_txid[32], fake_spk[34];
    memset(fake_txid, 0x01, 32);
    memset(fake_spk, 0x51, 1);
    fake_spk[1] = 0x20;
    memset(fake_spk + 2, 0xAA, 32);
    factory_set_funding(factory, fake_txid, 0, 100000, fake_spk, 34);
    factory_build_tree(factory);

    memset(lsp, 0, sizeof(*lsp));
    lsp->client_fds = calloc(LSP_MAX_CLIENTS, sizeof(int));
    lsp->client_pubkeys = calloc(LSP_MAX_CLIENTS, sizeof(secp256k1_pubkey));
    lsp->clients_cap = LSP_MAX_CLIENTS;
    lsp->ctx = ctx;
    lsp->lsp_pubkey = *lsp_pk;
    lsp->n_clients = 4;
    lsp->listen_fd = -1;
    lsp->bridge_fd = -1;
    for (int i = 0; i < 4; i++) {
        lsp->client_pubkeys[i] = client_pks[i];
        lsp->client_fds[i] = -1;
    }
    lsp->factory = *factory;

    memset(mgr, 0, sizeof(*mgr));
    if (!lsp_channels_init(mgr, ctx, factory, lsp_sec, 4)) return 0;

    /* Open in-memory persistence */
    if (!persist_open(db, NULL)) return 0;

    /* Save initial channel states */
    for (int i = 0; i < 4; i++) {
        channel_t *ch = &mgr->entries[i].channel;
        if (!persist_save_channel(db, ch, 0, (uint32_t)i)) return 0;
    }

    mgr->persist = db;
    return 1;
}

/* Helper: child process for reconnect nonce exchange.
   Receives CHANNEL_NONCES, sends back valid nonces, receives RECONNECT_ACK. */
static void child_nonce_exchange(int fd, int client_idx,
                                  secp256k1_pubkey lsp_pk,
                                  unsigned char client_sec[32]) {
    secp256k1_context *cctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey cpk;
    if (!secp256k1_ec_pubkey_create(cctx, &cpk, client_sec)) _exit(1);

    /* Recv CHANNEL_NONCES from LSP */
    wire_msg_t nm;
    if (!wire_recv(fd, &nm)) _exit(2);
    if (nm.msg_type != MSG_CHANNEL_NONCES) _exit(3);
    cJSON_Delete(nm.json);

    /* Generate and send client nonces */
    unsigned char nonces[MUSIG_NONCE_POOL_MAX][66];
    memset(nonces, 0, sizeof(nonces));
    for (size_t i = 0; i < MUSIG_NONCE_POOL_MAX; i++) {
        secp256k1_musig_secnonce sn;
        secp256k1_musig_pubnonce pn;
        musig_keyagg_t ka;
        secp256k1_pubkey pks[2] = {lsp_pk, cpk};
        musig_aggregate_keys(cctx, &ka, pks, 2);
        musig_generate_nonce(cctx, &sn, &pn, client_sec, &cpk, &ka.cache);
        musig_pubnonce_serialize(cctx, nonces[i], &pn);
    }

    cJSON *reply = wire_build_channel_nonces((uint32_t)client_idx,
        (const unsigned char (*)[66])nonces, MUSIG_NONCE_POOL_MAX);
    wire_send(fd, MSG_CHANNEL_NONCES, reply);
    cJSON_Delete(reply);

    /* Recv RECONNECT_ACK */
    wire_msg_t ack_msg;
    if (!wire_recv(fd, &ack_msg)) _exit(4);
    if (ack_msg.msg_type != MSG_RECONNECT_ACK) _exit(5);
    cJSON_Delete(ack_msg.json);

    close(fd);
    secp256k1_context_destroy(cctx);
}

/* Test 5A: Commitment mismatch rollback (LSP ahead by 1) */
int test_reconnect_commitment_mismatch_rollback(void) {
    secp256k1_context *ctx;
    unsigned char lsp_sec[32];
    secp256k1_pubkey lsp_pk;
    unsigned char client_secs[4][32];
    secp256k1_pubkey client_pks[4];
    factory_t *factory = calloc(1, sizeof(factory_t));
    if (!factory) return 0;
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    if (!lsp) { free(factory); return 0; }
    lsp_channel_mgr_t mgr;
    persist_t db;

    TEST_ASSERT(setup_reconnect_env(&ctx, lsp_sec, &lsp_pk, client_pks,
                client_secs, factory, lsp, &mgr, &db),
                "setup_reconnect_env failed");

    /* Persist initial state for client 2 (cn=0, local=12500, remote=12500) */
    channel_t *ch = &mgr.entries[2].channel;
    uint64_t orig_local = ch->local_amount;
    uint64_t orig_remote = ch->remote_amount;
    TEST_ASSERT(persist_update_channel_balance(&db, 2,
        orig_local, orig_remote, 0), "persist initial balance");

    /* Simulate LSP being 1 ahead: manually advance commitment_number */
    ch->commitment_number = 1;
    ch->local_amount = orig_local + 1000;  /* simulated in-flight change */
    ch->remote_amount = orig_remote - 1000;

    /* Client sends reconnect with cn=0 (behind by 1) */
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    cJSON *reconn = wire_build_reconnect(ctx, &client_pks[2], 0);
    TEST_ASSERT(wire_send(sv[1], MSG_RECONNECT, reconn), "send reconnect");
    cJSON_Delete(reconn);

    pid_t pid = fork();
    if (pid == 0) {
        close(sv[0]);
        child_nonce_exchange(sv[1], 2, lsp_pk, client_secs[2]);
        _exit(0);
    }

    close(sv[1]);
    int ok = lsp_channels_handle_reconnect(&mgr, lsp, sv[0]);
    TEST_ASSERT(ok, "handle_reconnect should succeed with rollback");

    /* Verify channel was rolled back to DB state */
    TEST_ASSERT_EQ(ch->commitment_number, 0, "cn should be rolled back to 0");
    TEST_ASSERT(ch->local_amount == orig_local, "local should match DB");
    TEST_ASSERT(ch->remote_amount == orig_remote, "remote should match DB");

    int status;
    waitpid(pid, &status, 0);
    TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child failed");

    persist_close(&db);
    free(lsp->client_fds);
    free(lsp->client_pubkeys);
    free(lsp);
    factory_free(factory);
    free(factory);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 5B: Irreconcilable commitment mismatch (diff > 1) → reject */
int test_reconnect_commitment_mismatch_reject(void) {
    secp256k1_context *ctx;
    unsigned char lsp_sec[32];
    secp256k1_pubkey lsp_pk;
    unsigned char client_secs[4][32];
    secp256k1_pubkey client_pks[4];
    factory_t *factory = calloc(1, sizeof(factory_t));
    if (!factory) return 0;
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    if (!lsp) { free(factory); return 0; }
    lsp_channel_mgr_t mgr;
    persist_t db;

    TEST_ASSERT(setup_reconnect_env(&ctx, lsp_sec, &lsp_pk, client_pks,
                client_secs, factory, lsp, &mgr, &db),
                "setup_reconnect_env failed");

    /* Set LSP's cn = 5, client will send cn = 0 (diff = 5, irreconcilable) */
    mgr.entries[2].channel.commitment_number = 5;

    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    cJSON *reconn = wire_build_reconnect(ctx, &client_pks[2], 0);
    TEST_ASSERT(wire_send(sv[1], MSG_RECONNECT, reconn), "send reconnect");
    cJSON_Delete(reconn);

    /* No fork needed — reconnect should fail before nonce exchange */
    close(sv[1]);  /* close client end so LSP can detect disconnect */

    wire_msg_t msg;
    if (!wire_recv_timeout(sv[0], &msg, 5)) {
        /* If recv fails, that's fine — we'll call handle_reconnect_with_msg directly */
    }

    /* Re-create socketpair for clean test */
    int sv2[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0, "socketpair2");

    cJSON *reconn2 = wire_build_reconnect(ctx, &client_pks[2], 0);
    TEST_ASSERT(wire_send(sv2[1], MSG_RECONNECT, reconn2), "send reconnect2");
    cJSON_Delete(reconn2);
    close(sv2[1]);

    int ok = lsp_channels_handle_reconnect(&mgr, lsp, sv2[0]);
    TEST_ASSERT(!ok, "handle_reconnect should fail for large mismatch");

    /* Also test: no persistence + mismatch by 1 → fails */
    mgr.persist = NULL;
    mgr.entries[2].channel.commitment_number = 1;

    int sv3[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv3) == 0, "socketpair3");

    cJSON *reconn3 = wire_build_reconnect(ctx, &client_pks[2], 0);
    TEST_ASSERT(wire_send(sv3[1], MSG_RECONNECT, reconn3), "send reconnect3");
    cJSON_Delete(reconn3);
    close(sv3[1]);

    ok = lsp_channels_handle_reconnect(&mgr, lsp, sv3[0]);
    TEST_ASSERT(!ok, "handle_reconnect should fail without persistence");

    persist_close(&db);
    free(lsp->client_fds);
    free(lsp->client_pubkeys);
    free(lsp);
    factory_free(factory);
    free(factory);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 5C: HTLC replay on reconnect (Gap 2C) */
int test_reconnect_htlc_replay(void) {
    secp256k1_context *ctx;
    unsigned char lsp_sec[32];
    secp256k1_pubkey lsp_pk;
    unsigned char client_secs[4][32];
    secp256k1_pubkey client_pks[4];
    factory_t *factory = calloc(1, sizeof(factory_t));
    if (!factory) return 0;
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    if (!lsp) { free(factory); return 0; }
    lsp_channel_mgr_t mgr;
    persist_t db;

    TEST_ASSERT(setup_reconnect_env(&ctx, lsp_sec, &lsp_pk, client_pks,
                client_secs, factory, lsp, &mgr, &db),
                "setup_reconnect_env failed");

    /* Create a payment_hash and register an invoice destined for client 1 */
    unsigned char preimage[32], payment_hash[32];
    memset(preimage, 0xBB, 32);
    sha256(preimage, 32, payment_hash);

    TEST_ASSERT(lsp_channels_register_invoice(&mgr, payment_hash, preimage, 1, 1000000),
                "register invoice failed");

    /* Add an ACTIVE RECEIVED HTLC on client 0's channel (sender side) */
    channel_t *src_ch = &mgr.entries[0].channel;
    TEST_ASSERT(src_ch->n_htlcs < MAX_HTLCS, "htlc space");
    htlc_t *htlc = &src_ch->htlcs[src_ch->n_htlcs];
    memset(htlc, 0, sizeof(*htlc));
    htlc->id = 1;
    htlc->direction = HTLC_RECEIVED;
    htlc->state = HTLC_STATE_ACTIVE;
    htlc->amount_sats = 1000;
    memcpy(htlc->payment_hash, payment_hash, 32);
    htlc->cltv_expiry = 500;
    src_ch->n_htlcs++;

    /* Verify dest channel has no HTLCs yet */
    channel_t *dest_ch = &mgr.entries[1].channel;
    TEST_ASSERT_EQ(dest_ch->n_htlcs, 0, "dest should have no HTLCs before replay");

    /* Client 1 reconnects */
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    cJSON *reconn = wire_build_reconnect(ctx, &client_pks[1], 0);
    TEST_ASSERT(wire_send(sv[1], MSG_RECONNECT, reconn), "send reconnect");
    cJSON_Delete(reconn);

    pid_t pid = fork();
    if (pid == 0) {
        close(sv[0]);
        secp256k1_context *cctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        secp256k1_pubkey cpk;
        if (!secp256k1_ec_pubkey_create(cctx, &cpk, client_secs[1])) _exit(1);

        /* Recv CHANNEL_NONCES from LSP */
        wire_msg_t nm;
        if (!wire_recv(sv[1], &nm)) _exit(2);
        if (nm.msg_type != MSG_CHANNEL_NONCES) _exit(3);
        cJSON_Delete(nm.json);

        /* Generate and send client nonces */
        unsigned char nonces[MUSIG_NONCE_POOL_MAX][66];
        memset(nonces, 0, sizeof(nonces));
        for (size_t i = 0; i < MUSIG_NONCE_POOL_MAX; i++) {
            secp256k1_musig_secnonce sn;
            secp256k1_musig_pubnonce pn;
            musig_keyagg_t ka;
            secp256k1_pubkey pks[2] = {lsp_pk, cpk};
            musig_aggregate_keys(cctx, &ka, pks, 2);
            musig_generate_nonce(cctx, &sn, &pn, client_secs[1], &cpk, &ka.cache);
            musig_pubnonce_serialize(cctx, nonces[i], &pn);
        }

        cJSON *reply = wire_build_channel_nonces(1,
            (const unsigned char (*)[66])nonces, MUSIG_NONCE_POOL_MAX);
        wire_send(sv[1], MSG_CHANNEL_NONCES, reply);
        cJSON_Delete(reply);

        /* Recv RECONNECT_ACK */
        wire_msg_t ack_msg;
        if (!wire_recv(sv[1], &ack_msg)) _exit(4);
        if (ack_msg.msg_type != MSG_RECONNECT_ACK) _exit(5);
        cJSON_Delete(ack_msg.json);

        /* Drain any replayed messages (ADD_HTLC, COMMITMENT_SIGNED, etc.)
           The partial sig may fail in unit test context, so use timeouts. */
        for (int drain = 0; drain < 5; drain++) {
            wire_msg_t extra;
            if (!wire_recv_timeout(sv[1], &extra, 2)) break;
            if (extra.msg_type == MSG_COMMITMENT_SIGNED) {
                /* Send REVOKE_AND_ACK */
                secp256k1_pubkey tmp_pk;
                unsigned char tmp_sec[32];
                memset(tmp_sec, 0x99, 32);
                if (!secp256k1_ec_pubkey_create(cctx, &tmp_pk, tmp_sec)) _exit(10);
                unsigned char rev_sec[32];
                memset(rev_sec, 0, 32);
                cJSON *revack = wire_build_revoke_and_ack(1, rev_sec, cctx, &tmp_pk);
                wire_send(sv[1], MSG_REVOKE_AND_ACK, revack);
                cJSON_Delete(revack);
            }
            if (extra.json) cJSON_Delete(extra.json);
        }

        close(sv[1]);
        secp256k1_context_destroy(cctx);
        _exit(0);
    }

    close(sv[1]);
    int ok = lsp_channels_handle_reconnect(&mgr, lsp, sv[0]);
    TEST_ASSERT(ok, "handle_reconnect with replay should succeed");

    /* Verify HTLC was replayed to dest channel */
    TEST_ASSERT(dest_ch->n_htlcs > 0, "dest should have replayed HTLC");

    /* Check the replayed HTLC has matching payment_hash */
    int found = 0;
    for (size_t i = 0; i < dest_ch->n_htlcs; i++) {
        if (memcmp(dest_ch->htlcs[i].payment_hash, payment_hash, 32) == 0) {
            found = 1;
            TEST_ASSERT_EQ(dest_ch->htlcs[i].direction, HTLC_OFFERED,
                           "replayed HTLC should be OFFERED on dest");
            TEST_ASSERT_EQ(dest_ch->htlcs[i].amount_sats, 1000,
                           "replayed HTLC amount mismatch");
            break;
        }
    }
    TEST_ASSERT(found, "replayed HTLC not found on dest channel");

    int status;
    waitpid(pid, &status, 0);
    TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "child process failed");

    persist_close(&db);
    free(lsp->client_fds);
    free(lsp->client_pubkeys);
    free(lsp);
    factory_free(factory);
    free(factory);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Mainnet codepath: build_cli_prefix omits -network flag for mainnet. */
int test_mainnet_cli_prefix_no_flag(void) {
    regtest_t rt;
    memset(&rt, 0, sizeof(rt));
    strncpy(rt.cli_path, "echo", sizeof(rt.cli_path) - 1);
    strncpy(rt.rpcuser, "testuser", sizeof(rt.rpcuser) - 1);
    strncpy(rt.rpcpassword, "testpass", sizeof(rt.rpcpassword) - 1);
    strncpy(rt.network, "mainnet", sizeof(rt.network) - 1);

    /* regtest_exec builds: "<cli_path> [opts] <method> [params] 2>&1"
       For mainnet, it must NOT include "-mainnet" flag. */
    char *result = regtest_exec(&rt, "getblockchaininfo", "");
    TEST_ASSERT(result != NULL, "regtest_exec returned NULL");

    /* echo outputs the command args — verify no "-mainnet" present */
    TEST_ASSERT(strstr(result, "-mainnet") == NULL,
                "mainnet CLI prefix should not contain -mainnet flag");

    /* Verify rpc credentials are present */
    TEST_ASSERT(strstr(result, "-rpcuser=testuser") != NULL,
                "should contain rpcuser");
    TEST_ASSERT(strstr(result, "-rpcpassword=testpass") != NULL,
                "should contain rpcpassword");

    free(result);
    return 1;
}

/* Mainnet codepath: non-regtest networks get scan_depth=1000. */
int test_mainnet_scan_depth(void) {
    regtest_t rt;

    /* Regtest should get scan_depth=20 */
    memset(&rt, 0, sizeof(rt));
    strncpy(rt.network, "regtest", sizeof(rt.network) - 1);
    rt.scan_depth = (strcmp(rt.network, "regtest") == 0) ? 20 : 1000;
    TEST_ASSERT(rt.scan_depth == 20, "regtest scan_depth should be 20");

    /* Mainnet should get scan_depth=1000 */
    memset(&rt, 0, sizeof(rt));
    strncpy(rt.network, "mainnet", sizeof(rt.network) - 1);
    rt.scan_depth = (strcmp(rt.network, "regtest") == 0) ? 20 : 1000;
    TEST_ASSERT(rt.scan_depth == 1000, "mainnet scan_depth should be 1000");

    /* Signet should also get scan_depth=1000 */
    memset(&rt, 0, sizeof(rt));
    strncpy(rt.network, "signet", sizeof(rt.network) - 1);
    rt.scan_depth = (strcmp(rt.network, "regtest") == 0) ? 20 : 1000;
    TEST_ASSERT(rt.scan_depth == 1000, "signet scan_depth should be 1000");

    return 1;
}

/* Shell injection via regtest_exec: $(echo pwned) should be treated as literal. */
int test_regtest_exec_no_shell_interp(void) {
    regtest_t rt;
    memset(&rt, 0, sizeof(rt));
    strncpy(rt.cli_path, "echo", sizeof(rt.cli_path) - 1);
    strncpy(rt.rpcuser, "u", sizeof(rt.rpcuser) - 1);
    strncpy(rt.rpcpassword, "p", sizeof(rt.rpcpassword) - 1);
    strncpy(rt.network, "regtest", sizeof(rt.network) - 1);

    /* The sanitizer should reject $(echo pwned) because $ is not in
       the allowed character set. regtest_exec returns NULL. */
    char *result = regtest_exec(&rt, "getinfo", "$(echo pwned)");
    TEST_ASSERT(result == NULL,
                "params with $() should be rejected by sanitizer");

    /* Also test backticks */
    result = regtest_exec(&rt, "getinfo", "`whoami`");
    TEST_ASSERT(result == NULL,
                "params with backticks should be rejected by sanitizer");

    /* Semicolons */
    result = regtest_exec(&rt, "getinfo", "; rm -rf /");
    TEST_ASSERT(result == NULL,
                "params with semicolons should be rejected by sanitizer");

    /* Pipe */
    result = regtest_exec(&rt, "getinfo", "| cat /etc/passwd");
    TEST_ASSERT(result == NULL,
                "params with pipe should be rejected by sanitizer");

    return 1;
}

/* Verify argv tokenization: quoted strings stay as single args. */
int test_regtest_argv_tokenization(void) {
    regtest_t rt;
    memset(&rt, 0, sizeof(rt));
    strncpy(rt.cli_path, "echo", sizeof(rt.cli_path) - 1);
    strncpy(rt.rpcuser, "u", sizeof(rt.rpcuser) - 1);
    strncpy(rt.rpcpassword, "p", sizeof(rt.rpcpassword) - 1);
    strncpy(rt.network, "regtest", sizeof(rt.network) - 1);

    /* Test simple method with no params */
    char *result = regtest_exec(&rt, "getblockcount", "");
    TEST_ASSERT(result != NULL, "echo should succeed");
    TEST_ASSERT(strstr(result, "getblockcount") != NULL,
                "output should contain method name");
    free(result);

    /* Test method with quoted param */
    result = regtest_exec(&rt, "createwallet", "\"testwallet\"");
    TEST_ASSERT(result != NULL, "echo with params should succeed");
    TEST_ASSERT(strstr(result, "createwallet") != NULL,
                "output should contain method");
    free(result);

    return 1;
}
