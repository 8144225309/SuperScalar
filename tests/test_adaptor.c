#include "superscalar/adaptor.h"
#include "superscalar/ln_dispatch.h"
#include "superscalar/ptlc_commit.h"
#include "superscalar/factory.h"
#include "superscalar/regtest.h"
#include "cJSON.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "superscalar/sha256.h"
extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

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

/* Secret keys for participants */
static const unsigned char lsp_sec[32] = { [0 ... 31] = 0x10 };
static const unsigned char client_a_sec[32] = { [0 ... 31] = 0x21 };
static const unsigned char client_b_sec[32] = { [0 ... 31] = 0x32 };

static secp256k1_context *test_ctx(void) {
    return secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

/* --- Part A: Adaptor signature tests --- */

/* Test 1: Create 2-of-2 pre-sig with adaptor point, adapt with secret,
   extract secret back — round-trip matches */
int test_adaptor_round_trip(void) {
    secp256k1_context *ctx = test_ctx();

    /* Create 2 keypairs for signers */
    secp256k1_keypair kps[2];
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[0], lsp_sec), "create kp0");
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[1], client_a_sec), "create kp1");

    secp256k1_pubkey pks[2];
    if (!secp256k1_keypair_pub(ctx, &pks[0], &kps[0])) return 0;
    if (!secp256k1_keypair_pub(ctx, &pks[1], &kps[1])) return 0;

    /* Aggregate keys */
    musig_keyagg_t keyagg;
    TEST_ASSERT(musig_aggregate_keys(ctx, &keyagg, pks, 2), "aggregate keys");

    /* Adaptor point: use client B's pubkey as the adaptor */
    secp256k1_keypair adaptor_kp;
    TEST_ASSERT(secp256k1_keypair_create(ctx, &adaptor_kp, client_b_sec), "create adaptor kp");
    secp256k1_pubkey adaptor_point;
    if (!secp256k1_keypair_pub(ctx, &adaptor_point, &adaptor_kp)) return 0;

    /* Message to sign */
    unsigned char msg[32];
    memset(msg, 0x42, 32);

    /* Create pre-signature with adaptor */
    unsigned char presig[64];
    int nonce_parity;
    TEST_ASSERT(adaptor_create_turnover_presig(ctx, presig, &nonce_parity, msg,
                                                kps, 2, &keyagg, NULL,
                                                &adaptor_point),
                "create pre-sig");

    /* Adapt: add secret scalar to get valid signature */
    unsigned char sig[64];
    TEST_ASSERT(adaptor_adapt(ctx, sig, presig, client_b_sec, nonce_parity),
                "adapt pre-sig");

    /* Extract: recover secret scalar from pre-sig + valid sig */
    unsigned char extracted[32];
    TEST_ASSERT(adaptor_extract_secret(ctx, extracted, sig, presig, nonce_parity),
                "extract secret");

    /* Verify round-trip: extracted scalar matches original */
    TEST_ASSERT(memcmp(extracted, client_b_sec, 32) == 0,
                "extracted secret matches original");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 2: Pre-signature alone fails Schnorr verification;
   adapted signature passes */
int test_adaptor_pre_sig_invalid(void) {
    secp256k1_context *ctx = test_ctx();

    secp256k1_keypair kps[2];
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[0], lsp_sec), "create kp0");
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[1], client_a_sec), "create kp1");

    secp256k1_pubkey pks[2];
    if (!secp256k1_keypair_pub(ctx, &pks[0], &kps[0])) return 0;
    if (!secp256k1_keypair_pub(ctx, &pks[1], &kps[1])) return 0;

    musig_keyagg_t keyagg;
    TEST_ASSERT(musig_aggregate_keys(ctx, &keyagg, pks, 2), "aggregate keys");

    secp256k1_keypair adaptor_kp;
    TEST_ASSERT(secp256k1_keypair_create(ctx, &adaptor_kp, client_b_sec), "create adaptor kp");
    secp256k1_pubkey adaptor_point;
    if (!secp256k1_keypair_pub(ctx, &adaptor_point, &adaptor_kp)) return 0;

    unsigned char msg[32];
    memset(msg, 0x55, 32);

    /* Create pre-signature */
    unsigned char presig[64];
    int nonce_parity;
    musig_keyagg_t keyagg_copy = keyagg;
    TEST_ASSERT(adaptor_create_turnover_presig(ctx, presig, &nonce_parity, msg,
                                                kps, 2, &keyagg_copy, NULL,
                                                &adaptor_point),
                "create pre-sig");

    /* Get tweaked output key for verification */
    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &keyagg.agg_pubkey)) return 0;
    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);

    musig_keyagg_t verify_keyagg = keyagg;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk,
                                             &verify_keyagg.cache, tweak)) return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) return 0;

    /* Pre-signature should NOT verify as a Schnorr sig */
    int presig_valid = secp256k1_schnorrsig_verify(ctx, presig, msg, 32,
                                                     &tweaked_xonly);
    TEST_ASSERT(!presig_valid, "pre-sig should not verify");

    /* Adapted signature SHOULD verify */
    unsigned char sig[64];
    TEST_ASSERT(adaptor_adapt(ctx, sig, presig, client_b_sec, nonce_parity),
                "adapt");

    int sig_valid = secp256k1_schnorrsig_verify(ctx, sig, msg, 32,
                                                  &tweaked_xonly);
    TEST_ASSERT(sig_valid, "adapted sig should verify");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 3: Adaptor signatures work with taproot-tweaked MuSig2 (key-path spend) */
int test_adaptor_taproot(void) {
    secp256k1_context *ctx = test_ctx();

    secp256k1_keypair kps[3];
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[0], lsp_sec), "create kp0");
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[1], client_a_sec), "create kp1");
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[2], client_b_sec), "create kp2");

    secp256k1_pubkey pks[3];
    for (int i = 0; i < 3; i++) {
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

    musig_keyagg_t keyagg;
    TEST_ASSERT(musig_aggregate_keys(ctx, &keyagg, pks, 3), "aggregate keys");

    /* Adaptor point = client A's pubkey */
    secp256k1_pubkey adaptor_point = pks[1];

    unsigned char msg[32];
    memset(msg, 0x77, 32);

    /* Create pre-sig with taproot tweak (merkle_root = NULL = key-path-only) */
    unsigned char presig[64];
    int nonce_parity;
    musig_keyagg_t keyagg_copy = keyagg;
    TEST_ASSERT(adaptor_create_turnover_presig(ctx, presig, &nonce_parity, msg,
                                                kps, 3, &keyagg_copy, NULL,
                                                &adaptor_point),
                "create pre-sig taproot");

    /* Adapt with client A's secret */
    unsigned char sig[64];
    TEST_ASSERT(adaptor_adapt(ctx, sig, presig, client_a_sec, nonce_parity),
                "adapt");

    /* Verify adapted sig against tweaked key */
    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &keyagg.agg_pubkey)) return 0;
    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);

    musig_keyagg_t verify_keyagg = keyagg;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk,
                                             &verify_keyagg.cache, tweak)) return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) return 0;

    int valid = secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &tweaked_xonly);
    TEST_ASSERT(valid, "taproot adaptor sig valid");

    /* Extract and verify */
    unsigned char extracted[32];
    TEST_ASSERT(adaptor_extract_secret(ctx, extracted, sig, presig, nonce_parity),
                "extract");
    TEST_ASSERT(memcmp(extracted, client_a_sec, 32) == 0,
                "extracted key matches client A secret");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- Part B: PTLC key turnover tests --- */

/* Test 4: Full PTLC cycle: 3-of-3 (LSP, A, B) create pre-sig with A's pubkey
   as adaptor → A adapts → LSP extracts A's private key → verify */
int test_ptlc_key_turnover(void) {
    secp256k1_context *ctx = test_ctx();

    secp256k1_keypair kps[3];
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[0], lsp_sec), "create LSP");
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[1], client_a_sec), "create A");
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[2], client_b_sec), "create B");

    secp256k1_pubkey pks[3];
    for (int i = 0; i < 3; i++) {
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

    musig_keyagg_t keyagg;
    TEST_ASSERT(musig_aggregate_keys(ctx, &keyagg, pks, 3), "aggregate keys");

    /* Adaptor point = client A's pubkey (the departing client) */
    secp256k1_pubkey adaptor_point = pks[1];

    unsigned char msg[32];
    memset(msg, 0xAB, 32);

    /* Step 1: All 3 signers create pre-signature */
    unsigned char presig[64];
    int nonce_parity;
    TEST_ASSERT(adaptor_create_turnover_presig(ctx, presig, &nonce_parity, msg,
                                                kps, 3, &keyagg, NULL,
                                                &adaptor_point),
                "create pre-sig");

    /* Step 2: Client A adapts with their private key */
    unsigned char sig[64];
    TEST_ASSERT(adaptor_adapt(ctx, sig, presig, client_a_sec, nonce_parity),
                "A adapts");

    /* Step 3: LSP extracts A's private key from on-chain sig + held pre-sig */
    unsigned char extracted_key[32];
    TEST_ASSERT(adaptor_extract_secret(ctx, extracted_key, sig, presig,
                                        nonce_parity),
                "LSP extracts");

    /* Step 4: Verify extracted key matches A's public key */
    TEST_ASSERT(adaptor_verify_extracted_key(ctx, extracted_key, &pks[1]),
                "extracted key matches A's pubkey");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 5: After extracting A's key, LSP creates a valid 3-of-3 signature
   using {LSP_key, extracted_A_key, B_key} without A's participation */
int test_ptlc_lsp_sockpuppet(void) {
    secp256k1_context *ctx = test_ctx();

    secp256k1_keypair kps[3];
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[0], lsp_sec), "create LSP");
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[1], client_a_sec), "create A");
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[2], client_b_sec), "create B");

    secp256k1_pubkey pks[3];
    for (int i = 0; i < 3; i++) {
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

    musig_keyagg_t keyagg;
    TEST_ASSERT(musig_aggregate_keys(ctx, &keyagg, pks, 3), "aggregate keys");

    /* PTLC: get A's key */
    secp256k1_pubkey adaptor_point = pks[1];
    unsigned char msg_ptlc[32];
    memset(msg_ptlc, 0xAB, 32);

    unsigned char presig[64];
    int nonce_parity;
    musig_keyagg_t keyagg_copy = keyagg;
    TEST_ASSERT(adaptor_create_turnover_presig(ctx, presig, &nonce_parity,
                                                msg_ptlc, kps, 3,
                                                &keyagg_copy, NULL,
                                                &adaptor_point),
                "create pre-sig");

    unsigned char sig[64];
    TEST_ASSERT(adaptor_adapt(ctx, sig, presig, client_a_sec, nonce_parity),
                "A adapts");

    unsigned char extracted_key[32];
    TEST_ASSERT(adaptor_extract_secret(ctx, extracted_key, sig, presig,
                                        nonce_parity),
                "extract A's key");

    /* Now LSP signs a NEW message using {LSP, extracted_A, B} -- no A! */
    secp256k1_keypair sockpuppet_kps[3];
    sockpuppet_kps[0] = kps[0];  /* LSP */
    TEST_ASSERT(secp256k1_keypair_create(ctx, &sockpuppet_kps[1],
                                          extracted_key),
                "create keypair from extracted key");
    sockpuppet_kps[2] = kps[2];  /* B */

    unsigned char msg_new[32];
    memset(msg_new, 0xCD, 32);

    /* Sign normally (no adaptor) using the sockpuppet keypairs */
    musig_keyagg_t keyagg2 = keyagg;  /* same aggregate key */
    unsigned char new_sig[64];
    TEST_ASSERT(musig_sign_taproot(ctx, new_sig, msg_new, sockpuppet_kps, 3,
                                    &keyagg2, NULL),
                "LSP signs as sockpuppet");

    /* Verify against the same tweaked aggregate key */
    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &keyagg.agg_pubkey)) return 0;
    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);

    musig_keyagg_t verify_keyagg = keyagg;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk,
                                             &verify_keyagg.cache, tweak)) return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) return 0;

    int valid = secp256k1_schnorrsig_verify(ctx, new_sig, msg_new, 32,
                                              &tweaked_xonly);
    TEST_ASSERT(valid, "sockpuppet sig valid");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 6: LSP extracts A's key, then builds cooperative close of factory
   using extracted key — valid */
int test_ptlc_factory_coop_close_after_turnover(void) {
    secp256k1_context *ctx = test_ctx();

    /* Secret keys for 5 participants */
    static const unsigned char seckeys[5][32] = {
        { [0 ... 31] = 0x10 },  /* LSP */
        { [0 ... 31] = 0x21 },  /* Client A */
        { [0 ... 31] = 0x32 },  /* Client B */
        { [0 ... 31] = 0x43 },  /* Client C */
        { [0 ... 31] = 0x54 },  /* Client D */
    };

    secp256k1_keypair kps[5];
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[i], seckeys[i]),
                    "create kp");
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

    /* Build factory */
    unsigned char fund_spk[34];
    {
        musig_keyagg_t ka;
        TEST_ASSERT(musig_aggregate_keys(ctx, &ka, pks, 5), "aggregate");
        unsigned char ser[32];
        if (!secp256k1_xonly_pubkey_serialize(ctx, ser, &ka.agg_pubkey)) return 0;
        unsigned char tweak[32];
        sha256_tagged("TapTweak", ser, 32, tweak);
        musig_keyagg_t tmp = ka;
        secp256k1_pubkey tw_pk;
        if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tw_pk, &tmp.cache, tweak)) return 0;
        secp256k1_xonly_pubkey tw_xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tw_xonly, NULL, &tw_pk)) return 0;
        build_p2tr_script_pubkey(fund_spk, &tw_xonly);
    }

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Simulate PTLC: extract all 4 clients' keys */
    unsigned char extracted_keys[4][32];
    for (int c = 0; c < 4; c++) {
        musig_keyagg_t ka;
        TEST_ASSERT(musig_aggregate_keys(ctx, &ka, pks, 5), "aggregate");

        unsigned char presig[64];
        int nonce_parity;
        secp256k1_pubkey adaptor = pks[c + 1];
        TEST_ASSERT(adaptor_create_turnover_presig(ctx, presig, &nonce_parity,
                        fake_txid, kps, 5, &ka, NULL, &adaptor),
                    "create pre-sig");

        unsigned char sig[64];
        TEST_ASSERT(adaptor_adapt(ctx, sig, presig, seckeys[c + 1],
                                    nonce_parity),
                    "adapt");

        TEST_ASSERT(adaptor_extract_secret(ctx, extracted_keys[c], sig,
                                            presig, nonce_parity),
                    "extract");

        TEST_ASSERT(adaptor_verify_extracted_key(ctx, extracted_keys[c],
                                                   &pks[c + 1]),
                    "verify extracted key");
    }

    /* Build cooperative close using extracted keys */
    secp256k1_keypair close_kps[5];
    close_kps[0] = kps[0];  /* LSP original */
    for (int c = 0; c < 4; c++) {
        TEST_ASSERT(secp256k1_keypair_create(ctx, &close_kps[c + 1],
                                              extracted_keys[c]),
                    "create kp from extracted");
    }

    /* Swap keypairs in factory */
    memcpy(f.keypairs, close_kps, 5 * sizeof(secp256k1_keypair));

    tx_output_t outputs[1];
    outputs[0].amount_sats = 100000 - 500;
    build_p2tr_script_pubkey(outputs[0].script_pubkey, &f.nodes[0].tweaked_pubkey);
    outputs[0].script_pubkey_len = 34;

    tx_buf_t close_tx;
    tx_buf_init(&close_tx, 512);
    TEST_ASSERT(factory_build_cooperative_close(&f, &close_tx, NULL,
                                                  outputs, 1, 0),
                "build coop close with extracted keys");
    TEST_ASSERT(close_tx.len > 0, "close tx non-empty");

    tx_buf_free(&close_tx);
    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 7 (regtest): Fund a factory, create pre-sig with adaptor, A adapts and
   broadcasts, LSP extracts key, LSP uses extracted key to coop-close factory */
int test_regtest_ptlc_turnover(void) {
    secp256k1_context *ctx = test_ctx();
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    regtest_create_wallet(&rt, "test_ptlc");

    char mine_addr[128];
    regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr));
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    /* 5 participants: LSP + 4 clients */
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

    /* Compute funding spk */
    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    {
        musig_keyagg_t ka;
        musig_aggregate_keys(ctx, &ka, pks, 5);
        unsigned char ser[32];
        if (!secp256k1_xonly_pubkey_serialize(ctx, ser, &ka.agg_pubkey)) return 0;
        unsigned char tweak[32];
        sha256_tagged("TapTweak", ser, 32, tweak);
        musig_keyagg_t tmp = ka;
        secp256k1_pubkey tw_pk;
        if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tw_pk, &tmp.cache, tweak)) return 0;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &fund_tweaked, NULL, &tw_pk)) return 0;
        build_p2tr_script_pubkey(fund_spk, &fund_tweaked);
    }

    /* Derive bech32m address */
    unsigned char tweaked_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, tweaked_ser, &fund_tweaked)) return 0;
    char key_hex[65];
    hex_encode(tweaked_ser, 32, key_hex);

    char params[512];
    snprintf(params, sizeof(params), "\"rawtr(%s)\"", key_hex);
    char *desc_result = regtest_exec(&rt, "getdescriptorinfo", params);
    TEST_ASSERT(desc_result != NULL, "getdescriptorinfo");

    char checksummed_desc[256];
    {
        char *dstart = strstr(desc_result, "\"descriptor\"");
        TEST_ASSERT(dstart != NULL, "find descriptor");
        dstart = strchr(dstart + 12, '"'); dstart++;
        char *dend = strchr(dstart, '"');
        size_t dlen = (size_t)(dend - dstart);
        memcpy(checksummed_desc, dstart, dlen);
        checksummed_desc[dlen] = '\0';
    }
    free(desc_result);

    snprintf(params, sizeof(params), "\"%s\"", checksummed_desc);
    char *addr_result = regtest_exec(&rt, "deriveaddresses", params);
    TEST_ASSERT(addr_result != NULL, "deriveaddresses");

    char factory_addr[128];
    {
        char *start = strchr(addr_result, '"'); start++;
        char *end = strchr(start, '"');
        size_t len = (size_t)(end - start);
        memcpy(factory_addr, start, len);
        factory_addr[len] = '\0';
    }
    free(addr_result);

    /* Fund factory */
    char funding_txid_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, factory_addr, 0.001, funding_txid_hex),
                "fund factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    unsigned char fund_txid_bytes[32];
    hex_decode(funding_txid_hex, fund_txid_bytes, 32);
    reverse_bytes(fund_txid_bytes, 32);

    /* Find factory vout */
    uint64_t fund_amount = 0;
    int found_vout = -1;
    for (int v = 0; v < 3; v++) {
        uint64_t amt;
        unsigned char spk[256];
        size_t spk_len;
        if (regtest_get_tx_output(&rt, funding_txid_hex, (uint32_t)v,
                                   &amt, spk, &spk_len)) {
            if (spk_len == 34 && memcmp(spk, fund_spk, 34) == 0) {
                found_vout = v;
                fund_amount = amt;
                break;
            }
        }
    }
    TEST_ASSERT(found_vout >= 0, "find factory vout");
    printf("  Factory funded: %s vout=%d amount=%lu\n",
           funding_txid_hex, found_vout, (unsigned long)fund_amount);

    /* Init factory */
    factory_t f;
    factory_init(&f, ctx, kps, 5, 1, 4);
    for (int i = 0; i < 15; i++)
        dw_counter_advance(&f.counter);
    factory_set_funding(&f, fund_txid_bytes, (uint32_t)found_vout,
                         fund_amount, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* PTLC: extract all 4 clients' keys via adaptor signatures */
    unsigned char extracted_keys[4][32];
    for (int c = 0; c < 4; c++) {
        musig_keyagg_t ka;
        musig_aggregate_keys(ctx, &ka, pks, 5);

        unsigned char presig[64];
        int nonce_parity;
        secp256k1_pubkey adaptor = pks[c + 1];
        TEST_ASSERT(adaptor_create_turnover_presig(ctx, presig, &nonce_parity,
                        fund_txid_bytes, kps, 5, &ka, NULL, &adaptor),
                    "create pre-sig");

        unsigned char sig[64];
        TEST_ASSERT(adaptor_adapt(ctx, sig, presig, seckeys[c + 1],
                                    nonce_parity),
                    "adapt");
        TEST_ASSERT(adaptor_extract_secret(ctx, extracted_keys[c], sig,
                                            presig, nonce_parity),
                    "extract key");
    }

    /* Build cooperative close using extracted keys */
    secp256k1_keypair close_kps[5];
    close_kps[0] = kps[0];
    for (int c = 0; c < 4; c++) {
        if (!secp256k1_keypair_create(ctx, &close_kps[c + 1], extracted_keys[c])) return 0;
    }

    memcpy(f.keypairs, close_kps, 5 * sizeof(secp256k1_keypair));

    /* Close to LSP's address */
    tx_output_t close_output;
    close_output.amount_sats = fund_amount - 500;
    {
        secp256k1_xonly_pubkey lsp_xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &lsp_xonly, NULL, &pks[0])) return 0;
        unsigned char ser[32];
        if (!secp256k1_xonly_pubkey_serialize(ctx, ser, &lsp_xonly)) return 0;
        unsigned char tweak[32];
        sha256_tagged("TapTweak", ser, 32, tweak);
        secp256k1_pubkey tw;
        if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tw, &lsp_xonly, tweak)) return 0;
        secp256k1_xonly_pubkey tw_xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tw_xonly, NULL, &tw)) return 0;
        build_p2tr_script_pubkey(close_output.script_pubkey, &tw_xonly);
        close_output.script_pubkey_len = 34;
    }

    tx_buf_t close_tx;
    tx_buf_init(&close_tx, 512);
    TEST_ASSERT(factory_build_cooperative_close(&f, &close_tx, NULL,
                                                  &close_output, 1, 0),
                "build coop close");

    /* Broadcast */
    char *close_hex = (char *)malloc(close_tx.len * 2 + 1);
    hex_encode(close_tx.data, close_tx.len, close_hex);

    char close_txid_hex[65];
    int sent = regtest_send_raw_tx(&rt, close_hex, close_txid_hex);
    free(close_hex);
    TEST_ASSERT(sent, "broadcast coop close");
    printf("  Cooperative close (via PTLC): %s\n", close_txid_hex);

    regtest_mine_blocks(&rt, 1, mine_addr);
    int conf = regtest_get_confirmations(&rt, close_txid_hex);
    TEST_ASSERT(conf > 0, "coop close confirmed");
    printf("  PTLC key turnover + coop close confirmed!\n");

    tx_buf_free(&close_tx);
    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* PTLC1 — channel_add_ptlc: adds PTLC, assigns id, state ACTIVE     */
/* ================================================================== */
int test_channel_add_ptlc(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    channel_t ch;
    memset(&ch, 0, sizeof(ch));

    secp256k1_pubkey payment_pt;
    unsigned char sec[32]; memset(sec, 0x22, 32);
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &payment_pt, sec), "create pubkey");

    uint64_t id = 0xFFFF;
    int r = channel_add_ptlc(&ch, PTLC_OFFERED, 50000, &payment_pt, 700100, &id);
    TEST_ASSERT(r == 1, "PTLC1: add succeeded");
    TEST_ASSERT(id == 0, "PTLC1: first id = 0");
    TEST_ASSERT(ch.n_ptlcs == 1, "PTLC1: n_ptlcs == 1");
    TEST_ASSERT(ch.ptlcs[0].state == PTLC_STATE_ACTIVE, "PTLC1: state ACTIVE");
    TEST_ASSERT(ch.ptlcs[0].amount_sats == 50000, "PTLC1: amount");
    TEST_ASSERT(ch.ptlcs[0].direction == PTLC_OFFERED, "PTLC1: direction OFFERED");

    free(ch.ptlcs);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* PTLC2 — channel_settle_ptlc: state transitions to SETTLED          */
/* ================================================================== */
int test_channel_settle_ptlc(void)
{
    channel_t ch;
    memset(&ch, 0, sizeof(ch));

    uint64_t id = 0;
    int r = channel_add_ptlc(&ch, PTLC_RECEIVED, 10000, NULL, 700200, &id);
    TEST_ASSERT(r == 1, "PTLC2: add ok");

    unsigned char sig[64]; memset(sig, 0xAB, 64);
    r = channel_settle_ptlc(&ch, id, sig);
    TEST_ASSERT(r == 1, "PTLC2: settle ok");
    TEST_ASSERT(ch.ptlcs[0].state == PTLC_STATE_SETTLED, "PTLC2: state SETTLED");
    TEST_ASSERT(ch.ptlcs[0].has_adapted_sig == 1, "PTLC2: has_adapted_sig");

    free(ch.ptlcs);
    return 1;
}

/* ================================================================== */
/* PTLC3 — channel_fail_ptlc: state transitions to FAILED             */
/* ================================================================== */
int test_channel_fail_ptlc(void)
{
    channel_t ch;
    memset(&ch, 0, sizeof(ch));

    uint64_t id = 0;
    channel_add_ptlc(&ch, PTLC_OFFERED, 20000, NULL, 700300, &id);

    int r = channel_fail_ptlc(&ch, id);
    TEST_ASSERT(r == 1, "PTLC3: fail ok");
    TEST_ASSERT(ch.ptlcs[0].state == PTLC_STATE_FAILED, "PTLC3: state FAILED");

    free(ch.ptlcs);
    return 1;
}

/* ================================================================== */
/* PTLC4 — add 3 PTLCs, settle middle one                            */
/* ================================================================== */
int test_channel_ptlc_multiple(void)
{
    channel_t ch;
    memset(&ch, 0, sizeof(ch));

    uint64_t id0, id1, id2;
    channel_add_ptlc(&ch, PTLC_OFFERED, 1000, NULL, 700000, &id0);
    channel_add_ptlc(&ch, PTLC_RECEIVED, 2000, NULL, 700000, &id1);
    channel_add_ptlc(&ch, PTLC_OFFERED, 3000, NULL, 700000, &id2);
    TEST_ASSERT(ch.n_ptlcs == 3, "PTLC4: 3 ptlcs");

    channel_settle_ptlc(&ch, id1, NULL);
    TEST_ASSERT(ch.ptlcs[0].state == PTLC_STATE_ACTIVE,  "PTLC4: ptlc[0] still active");
    TEST_ASSERT(ch.ptlcs[1].state == PTLC_STATE_SETTLED, "PTLC4: ptlc[1] settled");
    TEST_ASSERT(ch.ptlcs[2].state == PTLC_STATE_ACTIVE,  "PTLC4: ptlc[2] still active");

    free(ch.ptlcs);
    return 1;
}

/* ================================================================== */
/* PTLC5 — ptlc_commit_dispatch: type 0x4C processed                 */
/* ================================================================== */
int test_ptlc_commit_dispatch_presig(void)
{
    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    peer_mgr_t pmgr; memset(&pmgr, 0, sizeof(pmgr));

    /* Add a PTLC to receive presig for */
    uint64_t id = 0;
    channel_add_ptlc(&ch, PTLC_RECEIVED, 5000, NULL, 700000, &id);

    /* Build PTLC_PRESIG message: type(2) + id(8) + pre_sig(64) = 74 bytes */
    unsigned char msg[74]; memset(msg, 0, sizeof(msg));
    msg[0] = 0x00; msg[1] = 0x4C;
    /* id = 0 at bytes 2..9 */
    /* pre_sig at bytes 10..73 */
    memset(msg + 10, 0xBB, 64);

    int r = ptlc_commit_dispatch(&pmgr, 0, &ch, NULL, msg, sizeof(msg));
    TEST_ASSERT(r == 0x4C, "PTLC5: returns 0x4C");
    TEST_ASSERT(ch.ptlcs[0].has_pre_sig == 1, "PTLC5: pre_sig stored");

    free(ch.ptlcs);
    return 1;
}

/* ================================================================== */
/* PTLC6 — ptlc_commit_dispatch: type 0x4D processed                 */
/* ================================================================== */
int test_ptlc_commit_dispatch_adapted(void)
{
    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    peer_mgr_t pmgr; memset(&pmgr, 0, sizeof(pmgr));

    uint64_t id = 0;
    channel_add_ptlc(&ch, PTLC_RECEIVED, 5000, NULL, 700000, &id);

    unsigned char msg[74]; memset(msg, 0, sizeof(msg));
    msg[0] = 0x00; msg[1] = 0x4D;
    memset(msg + 10, 0xCC, 64);

    int r = ptlc_commit_dispatch(&pmgr, 0, &ch, NULL, msg, sizeof(msg));
    TEST_ASSERT(r == 0x4D, "PTLC6: returns 0x4D");
    TEST_ASSERT(ch.ptlcs[0].state == PTLC_STATE_SETTLED, "PTLC6: SETTLED");

    free(ch.ptlcs);
    return 1;
}

/* ================================================================== */
/* PTLC7 — ptlc_commit_dispatch: type 0x4E processed                 */
/* ================================================================== */
int test_ptlc_commit_dispatch_complete(void)
{
    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    peer_mgr_t pmgr; memset(&pmgr, 0, sizeof(pmgr));

    uint64_t id = 0;
    channel_add_ptlc(&ch, PTLC_RECEIVED, 5000, NULL, 700000, &id);
    channel_settle_ptlc(&ch, id, NULL);

    unsigned char msg[10]; memset(msg, 0, sizeof(msg));
    msg[0] = 0x00; msg[1] = 0x4E;

    int r = ptlc_commit_dispatch(&pmgr, 0, &ch, NULL, msg, sizeof(msg));
    TEST_ASSERT(r == 0x4E, "PTLC7: returns 0x4E");

    free(ch.ptlcs);
    return 1;
}

/* ================================================================== */
/* PTLC8 — ptlc_commit_dispatch: NULL ch doesn't crash               */
/* ================================================================== */
int test_ptlc_commit_dispatch_null_ch(void)
{
    peer_mgr_t pmgr; memset(&pmgr, 0, sizeof(pmgr));
    unsigned char msg[74]; memset(msg, 0, sizeof(msg));
    msg[0] = 0x00; msg[1] = 0x4C;
    int r = ptlc_commit_dispatch(&pmgr, 0, NULL, NULL, msg, sizeof(msg));
    TEST_ASSERT(r == 0x4C, "PTLC8: NULL ch returns 0x4C no crash");
    return 1;
}

/* ================================================================== */
/* PTLC9 — channel_add_ptlc grows cap beyond initial 8                */
/* ================================================================== */
int test_channel_ptlc_grow(void)
{
    channel_t ch; memset(&ch, 0, sizeof(ch));
    /* Add 10 PTLCs to force realloc */
    for (int i = 0; i < 10; i++) {
        uint64_t id = 0;
        int r = channel_add_ptlc(&ch, PTLC_OFFERED, 1000 * (i+1), NULL, 700000 + i, &id);
        TEST_ASSERT(r == 1, "PTLC9: add ok");
        TEST_ASSERT((uint64_t)i == id, "PTLC9: id sequential");
    }
    TEST_ASSERT(ch.n_ptlcs == 10, "PTLC9: 10 ptlcs added");
    free(ch.ptlcs);
    return 1;
}

/* ================================================================== */
/* PTLC10 — channel_fail_ptlc with non-existent id returns 0         */
/* ================================================================== */
int test_channel_fail_ptlc_not_found(void)
{
    channel_t ch; memset(&ch, 0, sizeof(ch));
    int r = channel_fail_ptlc(&ch, 999);
    TEST_ASSERT(r == 0, "PTLC10: not found returns 0");
    return 1;
}

/* ================================================================== */
/* PTLC11 — channel_settle_ptlc with non-existent id returns 0       */
/* ================================================================== */
int test_channel_settle_ptlc_not_found(void)
{
    channel_t ch; memset(&ch, 0, sizeof(ch));
    unsigned char sig[64]; memset(sig, 0, 64);
    int r = channel_settle_ptlc(&ch, 999, sig);
    TEST_ASSERT(r == 0, "PTLC11: not found returns 0");
    return 1;
}

/* ================================================================== */
/* PTLC12 — dispatch type 0x4E (PTLC_COMPLETE) on same path as 78    */
/* ================================================================== */
int test_ptlc_complete_via_dispatch(void)
{
    /* type 78 = 0x4E with 10-byte msg goes to PTLC path */
    unsigned char msg[10]; memset(msg, 0, sizeof(msg));
    msg[0] = 0x00; msg[1] = 0x4E;
    ln_dispatch_t d; memset(&d, 0, sizeof(d));
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    TEST_ASSERT(r == 78, "PTLC12: type 0x4E dispatched as 78");
    return 1;
}
