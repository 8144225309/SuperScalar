#include "superscalar/factory.h"
#include "superscalar/wire.h"
#include "superscalar/lsp.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/client.h"
#include "superscalar/musig.h"
#include "superscalar/regtest.h"
#include "cJSON.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);
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

#define TEST_ASSERT_MEM_EQ(a, b, len, msg) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

/* Secret keys for 5 participants: LSP + 4 clients */
static const unsigned char seckeys[5][32] = {
    { [0 ... 31] = 0x10 },  /* LSP */
    { [0 ... 31] = 0x21 },  /* Client A */
    { [0 ... 31] = 0x32 },  /* Client B */
    { [0 ... 31] = 0x43 },  /* Client C */
    { [0 ... 31] = 0x54 },  /* Client D */
};

static secp256k1_context *test_ctx(void) {
    return secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

static int make_keypairs(secp256k1_context *ctx, secp256k1_keypair *kps) {
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_create(ctx, &kps[i], seckeys[i])) return 0;
    }
    return 1;
}

/* ---- Test 1: pubkey-only factory produces identical tree ---- */

int test_wire_pubkey_only_factory(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    /* Build factory with keypairs (reference) */
    factory_t f_ref;
    factory_init(&f_ref, ctx, kps, 5, 10, 4);

    unsigned char fake_txid[32] = {0};
    fake_txid[0] = 0xAA;
    unsigned char fake_spk[34] = {0x51, 0x20};
    factory_set_funding(&f_ref, fake_txid, 0, 10000000, fake_spk, 34);
    TEST_ASSERT(factory_build_tree(&f_ref), "ref build tree");

    /* Build factory with pubkeys only */
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

    factory_t f_pk;
    factory_init_from_pubkeys(&f_pk, ctx, pks, 5, 10, 4);
    factory_set_funding(&f_pk, fake_txid, 0, 10000000, fake_spk, 34);
    TEST_ASSERT(factory_build_tree(&f_pk), "pubkey-only build tree");

    /* Compare: same number of nodes */
    TEST_ASSERT_EQ(f_pk.n_nodes, f_ref.n_nodes, "node count mismatch");

    /* Compare each node's unsigned tx */
    for (size_t i = 0; i < f_ref.n_nodes; i++) {
        TEST_ASSERT_EQ(f_pk.nodes[i].unsigned_tx.len, f_ref.nodes[i].unsigned_tx.len,
                        "unsigned tx len mismatch");
        TEST_ASSERT_MEM_EQ(f_pk.nodes[i].unsigned_tx.data,
                            f_ref.nodes[i].unsigned_tx.data,
                            f_ref.nodes[i].unsigned_tx.len,
                            "unsigned tx data mismatch");
        TEST_ASSERT_MEM_EQ(f_pk.nodes[i].txid, f_ref.nodes[i].txid, 32,
                            "txid mismatch");
    }

    factory_free(&f_ref);
    factory_free(&f_pk);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test 2: wire framing over socketpair ---- */

int test_wire_framing(void) {
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    /* Send a message */
    cJSON *sent = cJSON_CreateObject();
    cJSON_AddStringToObject(sent, "hello", "world");
    cJSON_AddNumberToObject(sent, "count", 42);
    TEST_ASSERT(wire_send(sv[0], MSG_HELLO, sent), "wire_send");
    cJSON_Delete(sent);

    /* Receive it */
    wire_msg_t msg;
    TEST_ASSERT(wire_recv(sv[1], &msg), "wire_recv");
    TEST_ASSERT_EQ(msg.msg_type, MSG_HELLO, "msg type");

    cJSON *hello = cJSON_GetObjectItem(msg.json, "hello");
    TEST_ASSERT(hello && cJSON_IsString(hello), "hello field");
    TEST_ASSERT(strcmp(hello->valuestring, "world") == 0, "hello value");

    cJSON *count = cJSON_GetObjectItem(msg.json, "count");
    TEST_ASSERT(count && cJSON_IsNumber(count), "count field");
    TEST_ASSERT_EQ(count->valueint, 42, "count value");

    cJSON_Delete(msg.json);
    close(sv[0]);
    close(sv[1]);
    return 1;
}

/* ---- Test 3: crypto serialization round-trip ---- */

int test_wire_crypto_serialization(void) {
    secp256k1_context *ctx = test_ctx();

    /* Test pubkey round-trip via HELLO message */
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, seckeys[0])) return 0;
    secp256k1_pubkey pk;
    if (!secp256k1_keypair_pub(ctx, &pk, &kp)) return 0;

    cJSON *hello = wire_build_hello(ctx, &pk);
    cJSON *pk_item = cJSON_GetObjectItem(hello, "pubkey");
    TEST_ASSERT(pk_item && cJSON_IsString(pk_item), "pubkey hex");

    unsigned char pk_buf[33];
    TEST_ASSERT_EQ(hex_decode(pk_item->valuestring, pk_buf, 33), 33, "pk decode");

    secp256k1_pubkey pk2;
    TEST_ASSERT(secp256k1_ec_pubkey_parse(ctx, &pk2, pk_buf, 33), "pk parse");

    unsigned char ser1[33], ser2[33];
    size_t len1 = 33, len2 = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, ser1, &len1, &pk, SECP256K1_EC_COMPRESSED)) return 0;
    if (!secp256k1_ec_pubkey_serialize(ctx, ser2, &len2, &pk2, SECP256K1_EC_COMPRESSED)) return 0;
    TEST_ASSERT_MEM_EQ(ser1, ser2, 33, "pubkey round-trip");

    cJSON_Delete(hello);

    /* Test nonce serialization round-trip */
    secp256k1_musig_secnonce secnonce;
    secp256k1_musig_pubnonce pubnonce;
    musig_generate_nonce(ctx, &secnonce, &pubnonce, seckeys[0], &pk, NULL);

    unsigned char nonce_ser[66];
    TEST_ASSERT(musig_pubnonce_serialize(ctx, nonce_ser, &pubnonce), "nonce ser");

    secp256k1_musig_pubnonce pubnonce2;
    TEST_ASSERT(musig_pubnonce_parse(ctx, &pubnonce2, nonce_ser), "nonce parse");

    unsigned char nonce_ser2[66];
    musig_pubnonce_serialize(ctx, nonce_ser2, &pubnonce2);
    TEST_ASSERT_MEM_EQ(nonce_ser, nonce_ser2, 66, "nonce round-trip");

    /* Test hex JSON helper */
    cJSON *obj = cJSON_CreateObject();
    unsigned char test_data[32] = {0x01, 0x02, 0x03};
    wire_json_add_hex(obj, "test", test_data, 32);
    unsigned char decoded[32];
    TEST_ASSERT_EQ(wire_json_get_hex(obj, "test", decoded, 32), 32, "hex decode len");
    TEST_ASSERT_MEM_EQ(test_data, decoded, 32, "hex round-trip");
    cJSON_Delete(obj);

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test 4: nonce bundle build + parse ---- */

int test_wire_nonce_bundle(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, seckeys[1])) return 0;
    secp256k1_pubkey pk;
    if (!secp256k1_keypair_pub(ctx, &pk, &kp)) return 0;

    /* Build a bundle with 3 entries */
    wire_bundle_entry_t entries[3];
    for (int i = 0; i < 3; i++) {
        entries[i].node_idx = (uint32_t)i;
        entries[i].signer_slot = (uint32_t)(i + 1);

        secp256k1_musig_secnonce sn;
        secp256k1_musig_pubnonce pn;
        musig_generate_nonce(ctx, &sn, &pn, seckeys[1], &pk, NULL);
        musig_pubnonce_serialize(ctx, entries[i].data, &pn);
        entries[i].data_len = 66;
    }

    cJSON *bundle = wire_build_nonce_bundle(entries, 3);
    cJSON *arr = cJSON_GetObjectItem(bundle, "entries");
    TEST_ASSERT(cJSON_IsArray(arr), "bundle is array");
    TEST_ASSERT_EQ(cJSON_GetArraySize(arr), 3, "bundle size");

    /* Parse back */
    wire_bundle_entry_t parsed[3];
    size_t n = wire_parse_bundle(arr, parsed, 3, 66);
    TEST_ASSERT_EQ(n, 3, "parsed count");

    for (int i = 0; i < 3; i++) {
        TEST_ASSERT_EQ(parsed[i].node_idx, entries[i].node_idx, "node_idx");
        TEST_ASSERT_EQ(parsed[i].signer_slot, entries[i].signer_slot, "slot");
        TEST_ASSERT_MEM_EQ(parsed[i].data, entries[i].data, 66, "nonce data");
    }

    cJSON_Delete(bundle);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test 5: psig bundle build + parse ---- */

int test_wire_psig_bundle(void) {
    wire_bundle_entry_t entries[2];
    for (int i = 0; i < 2; i++) {
        entries[i].node_idx = (uint32_t)(i * 2);
        entries[i].signer_slot = 0;
        memset(entries[i].data, 0x30 + i, 32);
        entries[i].data_len = 32;
    }

    cJSON *bundle = wire_build_psig_bundle(entries, 2);
    cJSON *arr = cJSON_GetObjectItem(bundle, "entries");

    wire_bundle_entry_t parsed[2];
    size_t n = wire_parse_bundle(arr, parsed, 2, 32);
    TEST_ASSERT_EQ(n, 2, "parsed psig count");
    TEST_ASSERT_MEM_EQ(parsed[0].data, entries[0].data, 32, "psig data 0");
    TEST_ASSERT_MEM_EQ(parsed[1].data, entries[1].data, 32, "psig data 1");

    cJSON_Delete(bundle);
    return 1;
}

/* ---- Test 6: cooperative close unsigned ---- */

int test_wire_close_unsigned(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    /* Build reference factory */
    factory_t f;
    factory_init(&f, ctx, kps, 5, 10, 4);

    unsigned char fake_txid[32] = {0};
    fake_txid[0] = 0xBB;

    /* Compute proper funding SPK */
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, 5);

    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &ka.cache, tweak)) return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) return 0;
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tweaked_xonly);

    factory_set_funding(&f, fake_txid, 0, 10000000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* Build unsigned close tx */
    tx_output_t outputs[2];
    outputs[0].amount_sats = 4999000;
    memcpy(outputs[0].script_pubkey, fund_spk, 34);
    outputs[0].script_pubkey_len = 34;
    outputs[1].amount_sats = 4999000;
    memcpy(outputs[1].script_pubkey, fund_spk, 34);
    outputs[1].script_pubkey_len = 34;

    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 256);
    unsigned char sighash[32];

    TEST_ASSERT(factory_build_cooperative_close_unsigned(&f, &unsigned_tx, sighash,
                                                          outputs, 2),
                "close unsigned");
    TEST_ASSERT(unsigned_tx.len > 0, "unsigned tx not empty");

    /* Verify sighash is non-zero */
    unsigned char zeros[32] = {0};
    TEST_ASSERT(memcmp(sighash, zeros, 32) != 0, "sighash non-zero");

    tx_buf_free(&unsigned_tx);
    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test 7: full distributed signing via TCP (in-process with socketpair) ---- */

int test_wire_distributed_signing(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    /* Build reference factory with all keypairs, sign it the old way */
    factory_t f_ref;
    factory_init(&f_ref, ctx, kps, 5, 10, 4);

    unsigned char fake_txid[32] = {0};
    fake_txid[0] = 0xCC;

    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, 5);

    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);
    secp256k1_pubkey tweaked_pk;
    musig_keyagg_t ka_copy = ka;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &ka_copy.cache, tweak)) return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) return 0;
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tweaked_xonly);

    factory_set_funding(&f_ref, fake_txid, 0, 10000000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f_ref), "ref build tree");

    /* Now do it via distributed split-round signing:
       Use pubkey-only factory for each "party", share nonces via memory. */

    /* All parties build identical factories from pubkeys */
    factory_t factories[5];
    for (int p = 0; p < 5; p++) {
        factory_init_from_pubkeys(&factories[p], ctx, pks, 5, 10, 4);
        factory_set_funding(&factories[p], fake_txid, 0, 10000000, fund_spk, 34);
        TEST_ASSERT(factory_build_tree(&factories[p]), "party build tree");
    }

    /* Verify all unsigned txs match reference */
    for (int p = 0; p < 5; p++) {
        for (size_t n = 0; n < f_ref.n_nodes; n++) {
            TEST_ASSERT_MEM_EQ(factories[p].nodes[n].unsigned_tx.data,
                                f_ref.nodes[n].unsigned_tx.data,
                                f_ref.nodes[n].unsigned_tx.len,
                                "distributed tx mismatch");
        }
    }

    /* Step 1: Each party initializes sessions and generates nonces */
    typedef struct {
        size_t node_idx;
        size_t signer_slot;
        secp256k1_musig_secnonce secnonce;
        secp256k1_musig_pubnonce pubnonce;
    } nonce_record_t;

    nonce_record_t all_nonces[5 * FACTORY_MAX_NODES];
    size_t nonce_total = 0;

    for (int p = 0; p < 5; p++) {
        factory_t *fp = &factories[p];
        TEST_ASSERT(factory_sessions_init(fp), "init sessions");

        unsigned char sk[32];
        if (!secp256k1_keypair_sec(ctx, sk, &kps[p])) return 0;

        for (size_t n = 0; n < fp->n_nodes; n++) {
            int slot = factory_find_signer_slot(fp, n, (uint32_t)p);
            if (slot < 0) continue;

            nonce_record_t *rec = &all_nonces[nonce_total++];
            rec->node_idx = n;
            rec->signer_slot = (size_t)slot;

            TEST_ASSERT(musig_generate_nonce(ctx, &rec->secnonce, &rec->pubnonce,
                                              sk, &pks[p],
                                              &fp->nodes[n].keyagg.cache),
                        "gen nonce");
        }
        memset(sk, 0, 32);
    }

    /* Step 2: Distribute all pubnonces to all parties */
    for (int p = 0; p < 5; p++) {
        /* Re-init sessions to reset nonce counts */
        TEST_ASSERT(factory_sessions_init(&factories[p]), "re-init sessions");

        for (size_t i = 0; i < nonce_total; i++) {
            TEST_ASSERT(factory_session_set_nonce(&factories[p],
                                                   all_nonces[i].node_idx,
                                                   all_nonces[i].signer_slot,
                                                   &all_nonces[i].pubnonce),
                        "set nonce");
        }
    }

    /* Step 3: Finalize nonces on all parties */
    for (int p = 0; p < 5; p++)
        TEST_ASSERT(factory_sessions_finalize(&factories[p]), "finalize nonces");

    /* Step 4: Each party creates partial sigs for their nodes */
    size_t nonce_idx = 0;
    for (int p = 0; p < 5; p++) {
        for (size_t n = 0; n < factories[p].n_nodes; n++) {
            int slot = factory_find_signer_slot(&factories[p], n, (uint32_t)p);
            if (slot < 0) continue;

            secp256k1_musig_partial_sig psig;
            TEST_ASSERT(musig_create_partial_sig(ctx, &psig,
                                                  &all_nonces[nonce_idx].secnonce,
                                                  &kps[p],
                                                  &factories[p].nodes[n].signing_session),
                        "partial sig");

            /* Set on ALL factories (in a real protocol, sent to LSP who aggregates) */
            for (int q = 0; q < 5; q++) {
                TEST_ASSERT(factory_session_set_partial_sig(&factories[q], n,
                                                             (size_t)slot, &psig),
                            "set psig");
            }
            nonce_idx++;
        }
    }

    /* Step 5: Complete signing on factory 0 (LSP) */
    TEST_ASSERT(factory_sessions_complete(&factories[0]), "complete signing");

    /* Verify signed txs match reference: sign ref and compare */
    TEST_ASSERT(factory_sign_all(&f_ref), "sign ref");

    /* The signatures will differ (different nonces), but the unsigned txs are identical
       and both should be valid. Just verify completion succeeded. */
    for (size_t n = 0; n < factories[0].n_nodes; n++) {
        TEST_ASSERT(factories[0].nodes[n].is_signed, "node signed");
        TEST_ASSERT(factories[0].nodes[n].signed_tx.len > 0, "signed tx non-empty");
    }

    for (int p = 0; p < 5; p++)
        factory_free(&factories[p]);
    factory_free(&f_ref);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test: MSG_CHANNEL_BASEPOINTS wire round-trip ---- */

int test_wire_channel_basepoints_round_trip(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Create 5 known pubkeys (payment, delayed, revocation, htlc, first_pcp) */
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        unsigned char sec[32];
        memset(sec, 0x30 + i, 32);
        TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &pks[i], sec),
                    "create pubkey");
    }

    /* Generate a 6th pubkey for second_per_commitment_point */
    {
        unsigned char sec6[32] = { [0 ... 31] = 0x77 };
        secp256k1_pubkey pk6;
        if (!secp256k1_ec_pubkey_create(ctx, &pk6, sec6)) return 0;

        /* Build message */
        cJSON *j = wire_build_channel_basepoints(
            42, ctx, &pks[0], &pks[1], &pks[2], &pks[3], &pks[4], &pk6);
        TEST_ASSERT(j != NULL, "build_channel_basepoints");

        /* Parse back */
        uint32_t ch_id;
        secp256k1_pubkey out[6];
        TEST_ASSERT(wire_parse_channel_basepoints(j, &ch_id, ctx,
                        &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]),
                    "parse_channel_basepoints");
        cJSON_Delete(j);

        TEST_ASSERT_EQ(ch_id, 42, "channel_id round-trip");

        /* Verify all 6 pubkeys match */
        secp256k1_pubkey expected[6];
        for (int i = 0; i < 5; i++) expected[i] = pks[i];
        expected[5] = pk6;
        for (int i = 0; i < 6; i++) {
            unsigned char ser1[33], ser2[33];
            size_t l1 = 33, l2 = 33;
            if (!secp256k1_ec_pubkey_serialize(ctx, ser1, &l1, &expected[i],
                                           SECP256K1_EC_COMPRESSED)) return 0;
            if (!secp256k1_ec_pubkey_serialize(ctx, ser2, &l2, &out[i],
                                           SECP256K1_EC_COMPRESSED)) return 0;
            TEST_ASSERT(memcmp(ser1, ser2, 33) == 0, "pubkey round-trip mismatch");
        }
    }

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test: Basepoint independence after lsp_channels_init ---- */

int test_basepoint_independence(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Create pubkeys */
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_ec_pubkey_create(ctx, &pks[i], seckeys[i])) return 0;
    }

    /* Build a factory for testing */
    factory_t f;
    factory_init_from_pubkeys(&f, ctx, pks, 5, 10, 4);
    unsigned char fake_txid[32];
    memset(fake_txid, 0xDD, 32);

    /* Create proper funding SPK */
    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, 5);
    secp256k1_xonly_pubkey xonly;
    xonly = ka.agg_pubkey;
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &xonly);
    factory_set_funding(&f, fake_txid, 0, 1000000, fund_spk, 34);
    factory_build_tree(&f);

    /* Init LSP channel manager */
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    TEST_ASSERT(lsp_channels_init(&mgr, ctx, &f, seckeys[0], 4),
                "lsp_channels_init");

    /* Verify remote basepoints are ZEROED (not populated by init) */
    for (size_t c = 0; c < 4; c++) {
        lsp_channel_entry_t *entry = &mgr.entries[c];
        /* A zeroed secp256k1_pubkey won't serialize successfully,
           so we check if the raw bytes are zero */
        unsigned char zero[sizeof(secp256k1_pubkey)];
        memset(zero, 0, sizeof(zero));
        TEST_ASSERT(memcmp(&entry->channel.remote_payment_basepoint,
                           zero, sizeof(secp256k1_pubkey)) == 0,
                    "remote_payment_basepoint should be zeroed");
        TEST_ASSERT(memcmp(&entry->channel.remote_delayed_payment_basepoint,
                           zero, sizeof(secp256k1_pubkey)) == 0,
                    "remote_delayed_payment_basepoint should be zeroed");
        TEST_ASSERT(memcmp(&entry->channel.remote_revocation_basepoint,
                           zero, sizeof(secp256k1_pubkey)) == 0,
                    "remote_revocation_basepoint should be zeroed");
    }

    /* Verify local basepoints ARE populated */
    for (size_t c = 0; c < 4; c++) {
        unsigned char zero[sizeof(secp256k1_pubkey)];
        memset(zero, 0, sizeof(zero));
        TEST_ASSERT(memcmp(&mgr.entries[c].channel.local_payment_basepoint,
                           zero, sizeof(secp256k1_pubkey)) != 0,
                    "local_payment_basepoint should be populated");
    }

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Regtest test: full TCP factory creation + cooperative close with fork ---- */

int test_regtest_wire_factory(void) {
    /* Initialize regtest */
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: regtest not available\n");
        return 0;
    }
    if (!regtest_create_wallet(&rt, "test_wire_factory")) {
        /* Wallet exists but may not be loaded */
        char *lr = regtest_exec(&rt, "loadwallet", "\"test_wire_factory\"");
        if (lr) free(lr);
        strncpy(rt.wallet, "test_wire_factory", sizeof(rt.wallet) - 1);
    }

    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    /* Compute funding SPK */
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, 5);

    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    unsigned char tweak_val[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak_val);
    musig_keyagg_t ka_copy = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &ka_copy.cache, tweak_val)) return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) return 0;
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tweaked_xonly);

    /* Derive bech32m address via bitcoin-cli descriptors */
    unsigned char tweaked_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, tweaked_ser, &tweaked_xonly)) return 0;
    char tweaked_hex[65];
    hex_encode(tweaked_ser, 32, tweaked_hex);

    char params[512];
    snprintf(params, sizeof(params), "\"rawtr(%s)\"", tweaked_hex);
    char *desc_result = regtest_exec(&rt, "getdescriptorinfo", params);
    TEST_ASSERT(desc_result != NULL, "getdescriptorinfo");

    char checksummed_desc[256];
    char *dstart = strstr(desc_result, "\"descriptor\"");
    TEST_ASSERT(dstart != NULL, "parse descriptor field");
    dstart = strchr(dstart + 12, '"'); dstart++;
    char *dend = strchr(dstart, '"');
    size_t dlen = (size_t)(dend - dstart);
    memcpy(checksummed_desc, dstart, dlen);
    checksummed_desc[dlen] = '\0';
    free(desc_result);

    snprintf(params, sizeof(params), "\"%s\"", checksummed_desc);
    char *addr_result = regtest_exec(&rt, "deriveaddresses", params);
    TEST_ASSERT(addr_result != NULL, "deriveaddresses");

    char fund_addr[128] = {0};
    char *astart = strchr(addr_result, '"'); astart++;
    char *aend = strchr(astart, '"');
    size_t alen = (size_t)(aend - astart);
    memcpy(fund_addr, astart, alen);
    fund_addr[alen] = '\0';
    free(addr_result);

    char mine_addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)),
                "get mine address");
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    TEST_ASSERT(regtest_get_balance(&rt) >= 0.01, "factory setup for funding");

    char funding_txid_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, fund_addr, 0.001, funding_txid_hex),
                "fund factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    /* Get funding output details */
    unsigned char funding_txid[32];
    hex_decode(funding_txid_hex, funding_txid, 32);
    reverse_bytes(funding_txid, 32);  /* display -> internal */

    uint64_t funding_amount = 0;
    unsigned char actual_spk[256];
    size_t actual_spk_len = 0;

    /* Find which vout has our SPK */
    uint32_t funding_vout = 0;
    for (uint32_t v = 0; v < 2; v++) {
        regtest_get_tx_output(&rt, funding_txid_hex, v,
                              &funding_amount, actual_spk, &actual_spk_len);
        if (actual_spk_len == 34 && memcmp(actual_spk, fund_spk, 34) == 0) {
            funding_vout = v;
            break;
        }
    }
    TEST_ASSERT(funding_amount > 0, "funding amount > 0");
    TEST_ASSERT(actual_spk_len == 34, "funding spk len");

    /* Use a fixed port with PID offset to avoid collisions */
    int port = 19735 + (getpid() % 1000);

    /* Fork 4 client processes */
    pid_t child_pids[4];
    for (int c = 0; c < 4; c++) {
        pid_t pid = fork();
        if (pid == 0) {
            /* Child: run client ceremony */
            usleep(100000 * (c + 1));  /* stagger connections: 100ms, 200ms, ... */
            secp256k1_context *child_ctx = test_ctx();
            secp256k1_keypair child_kp;
            if (!secp256k1_keypair_create(child_ctx, &child_kp, seckeys[c + 1])) return 0;

            int ok = client_run_ceremony(child_ctx, &child_kp, "127.0.0.1", port);
            secp256k1_context_destroy(child_ctx);
            _exit(ok ? 0 : 1);
        }
        child_pids[c] = pid;
    }

    /* Parent: run LSP */
    lsp_t lsp;
    lsp_init(&lsp, ctx, &kps[0], port, 4);

    int lsp_ok = 1;
    if (!lsp_accept_clients(&lsp)) {
        fprintf(stderr, "LSP: accept clients failed\n");
        lsp_ok = 0;
    }

    if (lsp_ok && !lsp_run_factory_creation(&lsp,
                                             funding_txid, funding_vout,
                                             funding_amount,
                                             fund_spk, 34,
                                             10, 4, 0)) {
        fprintf(stderr, "LSP: factory creation failed\n");
        lsp_ok = 0;
    }

    /* Cooperative close — spends funding output directly (bypasses factory tree) */
    if (lsp_ok) {
        /* Build close outputs: equal split to 5 addresses */
        uint64_t close_total = funding_amount - 500;  /* fee */
        uint64_t per_party = close_total / 5;

        tx_output_t close_outputs[5];
        for (int i = 0; i < 5; i++) {
            close_outputs[i].amount_sats = per_party;
            /* Use the funding SPK for simplicity (all go to same address) */
            memcpy(close_outputs[i].script_pubkey, fund_spk, 34);
            close_outputs[i].script_pubkey_len = 34;
        }
        /* Give remainder to last output */
        close_outputs[4].amount_sats = close_total - per_party * 4;

        tx_buf_t close_tx;
        tx_buf_init(&close_tx, 512);

        if (!lsp_run_cooperative_close(&lsp, &close_tx, close_outputs, 5)) {
            fprintf(stderr, "LSP: cooperative close failed\n");
            lsp_ok = 0;
        } else {
            /* Broadcast close tx */
            char close_hex[close_tx.len * 2 + 1];
            hex_encode(close_tx.data, close_tx.len, close_hex);
            char close_txid[65];
            if (regtest_send_raw_tx(&rt, close_hex, close_txid)) {
                regtest_mine_blocks(&rt, 1, mine_addr);
                int conf = regtest_get_confirmations(&rt, close_txid);
                if (conf < 1) {
                    fprintf(stderr, "LSP: close tx not confirmed\n");
                    lsp_ok = 0;
                }
            } else {
                fprintf(stderr, "LSP: broadcast close tx failed\n");
                lsp_ok = 0;
            }
        }
        tx_buf_free(&close_tx);
    }

    lsp_cleanup(&lsp);

    /* Wait for all children */
    int all_children_ok = 1;
    for (int c = 0; c < 4; c++) {
        int status;
        waitpid(child_pids[c], &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "Client %d exited with status %d\n", c + 1,
                    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            all_children_ok = 0;
        }
    }

    secp256k1_context_destroy(ctx);

    TEST_ASSERT(lsp_ok, "LSP ceremony");
    TEST_ASSERT(all_children_ok, "all clients");
    return 1;
}

/* Arity-1 regtest test: factory creation with 14-node tree + cooperative close */
int test_regtest_wire_factory_arity1(void) {
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: regtest not available\n");
        return 0;
    }
    if (!regtest_create_wallet(&rt, "test_wire_arity1")) {
        char *lr = regtest_exec(&rt, "loadwallet", "\"test_wire_arity1\"");
        if (lr) free(lr);
        strncpy(rt.wallet, "test_wire_arity1", sizeof(rt.wallet) - 1);
    }

    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    if (!make_keypairs(ctx, kps)) return 0;

    /* Compute funding SPK (5-of-5 MuSig2 taproot) */
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, 5);

    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    unsigned char tweak_val[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak_val);
    musig_keyagg_t ka_copy = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &ka_copy.cache, tweak_val)) return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) return 0;
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tweaked_xonly);

    /* Derive bech32m address */
    unsigned char tweaked_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, tweaked_ser, &tweaked_xonly)) return 0;
    char tweaked_hex[65];
    hex_encode(tweaked_ser, 32, tweaked_hex);

    char params[512];
    snprintf(params, sizeof(params), "\"rawtr(%s)\"", tweaked_hex);
    char *desc_result = regtest_exec(&rt, "getdescriptorinfo", params);
    TEST_ASSERT(desc_result != NULL, "getdescriptorinfo");

    char checksummed_desc[256];
    char *dstart = strstr(desc_result, "\"descriptor\"");
    TEST_ASSERT(dstart != NULL, "parse descriptor field");
    dstart = strchr(dstart + 12, '"'); dstart++;
    char *dend = strchr(dstart, '"');
    size_t dlen = (size_t)(dend - dstart);
    memcpy(checksummed_desc, dstart, dlen);
    checksummed_desc[dlen] = '\0';
    free(desc_result);

    snprintf(params, sizeof(params), "\"%s\"", checksummed_desc);
    char *addr_result = regtest_exec(&rt, "deriveaddresses", params);
    TEST_ASSERT(addr_result != NULL, "deriveaddresses");

    char fund_addr[128] = {0};
    char *astart = strchr(addr_result, '"'); astart++;
    char *aend = strchr(astart, '"');
    size_t alen = (size_t)(aend - astart);
    memcpy(fund_addr, astart, alen);
    fund_addr[alen] = '\0';
    free(addr_result);

    /* Fund */
    char mine_addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)),
                "get mine address");
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    TEST_ASSERT(regtest_get_balance(&rt) >= 0.01, "factory setup for funding");

    char funding_txid_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, fund_addr, 0.001, funding_txid_hex),
                "fund factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    unsigned char funding_txid[32];
    hex_decode(funding_txid_hex, funding_txid, 32);
    reverse_bytes(funding_txid, 32);

    uint64_t funding_amount = 0;
    unsigned char actual_spk[256];
    size_t actual_spk_len = 0;
    uint32_t funding_vout = 0;
    for (uint32_t v = 0; v < 2; v++) {
        regtest_get_tx_output(&rt, funding_txid_hex, v,
                              &funding_amount, actual_spk, &actual_spk_len);
        if (actual_spk_len == 34 && memcmp(actual_spk, fund_spk, 34) == 0) {
            funding_vout = v;
            break;
        }
    }
    TEST_ASSERT(funding_amount > 0, "funding amount > 0");

    /* Use different port than arity-2 test */
    int port = 19935 + (getpid() % 1000);

    /* Fork 4 client processes */
    pid_t child_pids[4];
    for (int c = 0; c < 4; c++) {
        pid_t pid = fork();
        if (pid == 0) {
            usleep(100000 * (c + 1));
            secp256k1_context *child_ctx = test_ctx();
            secp256k1_keypair child_kp;
            if (!secp256k1_keypair_create(child_ctx, &child_kp, seckeys[c + 1])) return 0;

            int ok = client_run_ceremony(child_ctx, &child_kp, "127.0.0.1", port);
            secp256k1_context_destroy(child_ctx);
            _exit(ok ? 0 : 1);
        }
        child_pids[c] = pid;
    }

    /* Parent: LSP with arity-1 */
    lsp_t lsp;
    lsp_init(&lsp, ctx, &kps[0], port, 4);

    int lsp_ok = 1;
    if (!lsp_accept_clients(&lsp)) {
        fprintf(stderr, "LSP: accept clients failed\n");
        lsp_ok = 0;
    }

    /* Set arity-1 BEFORE factory creation */
    lsp.factory.leaf_arity = FACTORY_ARITY_1;

    if (lsp_ok && !lsp_run_factory_creation(&lsp,
                                             funding_txid, funding_vout,
                                             funding_amount,
                                             fund_spk, 34,
                                             10, 4, 200)) {
        fprintf(stderr, "LSP: factory creation (arity-1) failed\n");
        lsp_ok = 0;
    }

    /* Verify arity-1 tree: 14 nodes, 4 leaf nodes */
    if (lsp_ok) {
        TEST_ASSERT(lsp.factory.n_nodes == 14, "14 nodes");
        TEST_ASSERT(lsp.factory.n_leaf_nodes == 4, "4 leaf nodes");
        TEST_ASSERT(lsp.factory.leaf_arity == FACTORY_ARITY_1, "arity-1");
        TEST_ASSERT(lsp.factory.counter.n_layers == 3, "3 DW layers");
        printf("  Arity-1 factory: %zu nodes, %d leaf nodes, %u DW layers\n",
               lsp.factory.n_nodes, lsp.factory.n_leaf_nodes,
               lsp.factory.counter.n_layers);
    }

    /* Cooperative close (same as arity-2 — 5-of-5 on funding output) */
    if (lsp_ok) {
        uint64_t close_total = funding_amount - 500;
        uint64_t per_party = close_total / 5;

        tx_output_t close_outputs[5];
        for (int i = 0; i < 5; i++) {
            close_outputs[i].amount_sats = per_party;
            memcpy(close_outputs[i].script_pubkey, fund_spk, 34);
            close_outputs[i].script_pubkey_len = 34;
        }
        close_outputs[4].amount_sats = close_total - per_party * 4;

        tx_buf_t close_tx;
        tx_buf_init(&close_tx, 512);

        if (!lsp_run_cooperative_close(&lsp, &close_tx, close_outputs, 5)) {
            fprintf(stderr, "LSP: cooperative close (arity-1) failed\n");
            lsp_ok = 0;
        } else {
            char close_hex[close_tx.len * 2 + 1];
            hex_encode(close_tx.data, close_tx.len, close_hex);
            char close_txid[65];
            if (regtest_send_raw_tx(&rt, close_hex, close_txid)) {
                regtest_mine_blocks(&rt, 1, mine_addr);
                int conf = regtest_get_confirmations(&rt, close_txid);
                if (conf < 1) {
                    fprintf(stderr, "LSP: close tx not confirmed\n");
                    lsp_ok = 0;
                }
            } else {
                fprintf(stderr, "LSP: broadcast close tx failed\n");
                lsp_ok = 0;
            }
        }
        tx_buf_free(&close_tx);
    }

    lsp_cleanup(&lsp);

    int all_children_ok = 1;
    for (int c = 0; c < 4; c++) {
        int status;
        waitpid(child_pids[c], &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "Client %d (arity-1) exited with status %d\n", c + 1,
                    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            all_children_ok = 0;
        }
    }

    secp256k1_context_destroy(ctx);

    TEST_ASSERT(lsp_ok, "LSP arity-1 ceremony");
    TEST_ASSERT(all_children_ok, "all arity-1 clients");
    return 1;
}

/* --- Wire frame size limit (Phase 2: item 2.5) --- */

int test_wire_oversized_frame_rejected(void) {
    /* WIRE_MAX_FRAME_SIZE is 64KB.  Forge a 4-byte length header claiming a
       payload larger than the limit, then verify wire_recv rejects it.
       (Avoids writing 65KB+ through a socketpair — macOS buffers are ~8KB.) */
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    /* Write a 4-byte big-endian length = WIRE_MAX_FRAME_SIZE + 100 */
    uint32_t fake_len = WIRE_MAX_FRAME_SIZE + 100;
    unsigned char hdr[4];
    hdr[0] = (unsigned char)(fake_len >> 24);
    hdr[1] = (unsigned char)(fake_len >> 16);
    hdr[2] = (unsigned char)(fake_len >> 8);
    hdr[3] = (unsigned char)(fake_len);
    ssize_t w = write(sv[0], hdr, 4);
    (void)w;
    close(sv[0]);

    /* wire_recv reads 4-byte header, sees length > WIRE_MAX_FRAME_SIZE, returns 0 */
    wire_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    int got = wire_recv(sv[1], &msg);
    if (msg.json) cJSON_Delete(msg.json);
    close(sv[1]);

    TEST_ASSERT(got == 0, "oversized frame rejected by wire_recv");
    return 1;
}

/* Gap 5: Wire frame truncation — partial header, truncated body, zero-length frame.
   Proves: wire_recv handles connection failures cleanly without leaking or crashing. */

int test_wire_recv_truncated_header(void) {
    /* Write only 2 of 4 header bytes, then close the writer */
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    unsigned char partial_hdr[2] = { 0x00, 0x0A };
    ssize_t w = write(sv[0], partial_hdr, 2);
    (void)w;
    close(sv[0]);

    wire_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    int got = wire_recv(sv[1], &msg);
    if (msg.json) cJSON_Delete(msg.json);
    close(sv[1]);

    TEST_ASSERT(got == 0, "truncated header (2/4 bytes) returns 0");
    return 1;
}

int test_wire_recv_truncated_body(void) {
    /* Write a valid 4-byte header claiming 10 bytes, then only 3 body bytes */
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    unsigned char hdr[4] = { 0x00, 0x00, 0x00, 0x0A };  /* frame_len = 10 */
    unsigned char partial_body[3] = { 0x01, '{', '}' };
    ssize_t w = write(sv[0], hdr, 4);
    (void)w;
    w = write(sv[0], partial_body, 3);
    (void)w;
    close(sv[0]);  /* body cut short: 3 of 10 */

    wire_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    int got = wire_recv(sv[1], &msg);
    if (msg.json) cJSON_Delete(msg.json);
    close(sv[1]);

    TEST_ASSERT(got == 0, "truncated body (3/10 bytes) returns 0");
    return 1;
}

int test_wire_recv_zero_length_frame(void) {
    /* frame_len = 0: caught by the < 1 guard in wire_recv */
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    unsigned char hdr[4] = { 0x00, 0x00, 0x00, 0x00 };
    ssize_t w = write(sv[0], hdr, 4);
    (void)w;
    close(sv[0]);

    wire_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    int got = wire_recv(sv[1], &msg);
    if (msg.json) cJSON_Delete(msg.json);
    close(sv[1]);

    TEST_ASSERT(got == 0, "zero-length frame rejected");
    return 1;
}
