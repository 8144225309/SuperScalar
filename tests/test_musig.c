#include "superscalar/musig.h"
#include <secp256k1_musig.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

static const unsigned char test_seckey1[32] = {
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
};

static const unsigned char test_seckey2[32] = {
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
};

static const unsigned char test_msg[32] = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
};

int test_musig_aggregate_keys(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    TEST_ASSERT(ctx != NULL, "context creation");

    secp256k1_keypair kp1, kp2;
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kp1, test_seckey1), "keypair1");
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kp2, test_seckey2), "keypair2");

    secp256k1_pubkey pubkeys[2];
    secp256k1_keypair_pub(ctx, &pubkeys[0], &kp1);
    secp256k1_keypair_pub(ctx, &pubkeys[1], &kp2);

    musig_keyagg_t keyagg;
    TEST_ASSERT(musig_aggregate_keys(ctx, &keyagg, pubkeys, 2), "key aggregation");

    unsigned char agg_ser[32];
    TEST_ASSERT(secp256k1_xonly_pubkey_serialize(ctx, agg_ser, &keyagg.agg_pubkey),
                "serialize aggregate key");

    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (agg_ser[i] != 0) { all_zero = 0; break; }
    }
    TEST_ASSERT(!all_zero, "aggregate key should not be zero");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_musig_sign_verify(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_keypair kps[2];
    secp256k1_keypair_create(ctx, &kps[0], test_seckey1);
    secp256k1_keypair_create(ctx, &kps[1], test_seckey2);

    secp256k1_pubkey pubkeys[2];
    secp256k1_keypair_pub(ctx, &pubkeys[0], &kps[0]);
    secp256k1_keypair_pub(ctx, &pubkeys[1], &kps[1]);

    musig_keyagg_t keyagg;
    TEST_ASSERT(musig_aggregate_keys(ctx, &keyagg, pubkeys, 2), "key aggregation");

    unsigned char sig[64];
    TEST_ASSERT(musig_sign_all_local(ctx, sig, test_msg, kps, 2, &keyagg),
                "MuSig2 signing");

    TEST_ASSERT(secp256k1_schnorrsig_verify(ctx, sig, test_msg, 32, &keyagg.agg_pubkey),
                "signature verification");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_musig_wrong_message(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_keypair kps[2];
    secp256k1_keypair_create(ctx, &kps[0], test_seckey1);
    secp256k1_keypair_create(ctx, &kps[1], test_seckey2);

    secp256k1_pubkey pubkeys[2];
    secp256k1_keypair_pub(ctx, &pubkeys[0], &kps[0]);
    secp256k1_keypair_pub(ctx, &pubkeys[1], &kps[1]);

    musig_keyagg_t keyagg;
    musig_aggregate_keys(ctx, &keyagg, pubkeys, 2);

    unsigned char sig[64];
    musig_sign_all_local(ctx, sig, test_msg, kps, 2, &keyagg);

    unsigned char wrong_msg[32];
    memset(wrong_msg, 0x42, 32);
    TEST_ASSERT(!secp256k1_schnorrsig_verify(ctx, sig, wrong_msg, 32, &keyagg.agg_pubkey),
                "wrong message should fail verification");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_musig_taproot_sign(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_keypair kps[2];
    secp256k1_keypair_create(ctx, &kps[0], test_seckey1);
    secp256k1_keypair_create(ctx, &kps[1], test_seckey2);

    secp256k1_pubkey pubkeys[2];
    secp256k1_keypair_pub(ctx, &pubkeys[0], &kps[0]);
    secp256k1_keypair_pub(ctx, &pubkeys[1], &kps[1]);

    musig_keyagg_t keyagg;
    musig_aggregate_keys(ctx, &keyagg, pubkeys, 2);

    /* key-path only, no script tree */
    unsigned char sig[64];
    TEST_ASSERT(musig_sign_taproot(ctx, sig, test_msg, kps, 2, &keyagg, NULL),
                "taproot signing");

    /* To verify, we need the tweaked output key: P + H("TapTweak" || P) * G.
     * musig_sign_taproot modifies keyagg in place, so re-aggregate. */
    musig_keyagg_t keyagg2;
    musig_aggregate_keys(ctx, &keyagg2, pubkeys, 2);

    unsigned char internal_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &keyagg2.agg_pubkey);

    extern void sha256_tagged(const char *, const unsigned char *, size_t, unsigned char *);
    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);

    secp256k1_pubkey tweaked_pk;
    secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &keyagg2.cache, tweak);

    secp256k1_xonly_pubkey tweaked_xonly;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk);

    TEST_ASSERT(secp256k1_schnorrsig_verify(ctx, sig, test_msg, 32, &tweaked_xonly),
                "taproot sig verification against tweaked key");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Additional secret keys for multi-signer tests */
static const unsigned char test_seckey3[32] = {
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
};
static const unsigned char test_seckey4[32] = {
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
};
static const unsigned char test_seckey5[32] = {
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
};

extern void sha256_tagged(const char *, const unsigned char *, size_t, unsigned char *);

/* Helper: compute taproot-tweaked xonly pubkey for verification */
static int compute_tweaked_xonly(
    const secp256k1_context *ctx,
    secp256k1_xonly_pubkey *tweaked_xonly_out,
    const secp256k1_pubkey *pubkeys,
    size_t n,
    const unsigned char *merkle_root
) {
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pubkeys, n))
        return 0;

    unsigned char internal_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey);

    unsigned char tweak[32];
    if (merkle_root) {
        unsigned char data[64];
        memcpy(data, internal_ser, 32);
        memcpy(data + 32, merkle_root, 32);
        sha256_tagged("TapTweak", data, 64, tweak);
    } else {
        sha256_tagged("TapTweak", internal_ser, 32, tweak);
    }

    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &ka.cache, tweak))
        return 0;

    return secp256k1_xonly_pubkey_from_pubkey(ctx, tweaked_xonly_out, NULL, &tweaked_pk);
}

/* === Split-round tests === */

int test_musig_split_round_basic(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Setup 2 signers */
    secp256k1_keypair kps[2];
    secp256k1_keypair_create(ctx, &kps[0], test_seckey1);
    secp256k1_keypair_create(ctx, &kps[1], test_seckey2);

    secp256k1_pubkey pubkeys[2];
    secp256k1_keypair_pub(ctx, &pubkeys[0], &kps[0]);
    secp256k1_keypair_pub(ctx, &pubkeys[1], &kps[1]);

    musig_keyagg_t keyagg;
    TEST_ASSERT(musig_aggregate_keys(ctx, &keyagg, pubkeys, 2), "key aggregation");

    /* Each signer generates a nonce */
    secp256k1_musig_secnonce secnonces[2];
    secp256k1_musig_pubnonce pubnonces[2];
    TEST_ASSERT(musig_generate_nonce(ctx, &secnonces[0], &pubnonces[0],
                                      test_seckey1, &pubkeys[0], &keyagg.cache),
                "nonce gen signer 0");
    TEST_ASSERT(musig_generate_nonce(ctx, &secnonces[1], &pubnonces[1],
                                      test_seckey2, &pubkeys[1], &keyagg.cache),
                "nonce gen signer 1");

    /* Create session, set pubnonces */
    musig_signing_session_t session;
    musig_session_init(&session, &keyagg, 2);
    TEST_ASSERT(musig_session_set_pubnonce(&session, 0, &pubnonces[0]), "set pubnonce 0");
    TEST_ASSERT(musig_session_set_pubnonce(&session, 1, &pubnonces[1]), "set pubnonce 1");

    /* Finalize: key-path-only, no adaptor */
    TEST_ASSERT(musig_session_finalize_nonces(ctx, &session, test_msg, NULL, NULL),
                "finalize nonces");

    /* Each signer creates partial sig */
    secp256k1_musig_partial_sig psigs[2];
    TEST_ASSERT(musig_create_partial_sig(ctx, &psigs[0], &secnonces[0], &kps[0], &session),
                "partial sig 0");
    TEST_ASSERT(musig_create_partial_sig(ctx, &psigs[1], &secnonces[1], &kps[1], &session),
                "partial sig 1");

    /* Aggregate */
    unsigned char sig[64];
    TEST_ASSERT(musig_aggregate_partial_sigs(ctx, sig, &session, psigs, 2),
                "aggregate partial sigs");

    /* Verify against taproot-tweaked key (key-path-only) */
    secp256k1_xonly_pubkey tweaked_xonly;
    TEST_ASSERT(compute_tweaked_xonly(ctx, &tweaked_xonly, pubkeys, 2, NULL),
                "compute tweaked xonly");
    TEST_ASSERT(secp256k1_schnorrsig_verify(ctx, sig, test_msg, 32, &tweaked_xonly),
                "split-round sig verification");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_musig_split_round_taproot(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_keypair kps[2];
    secp256k1_keypair_create(ctx, &kps[0], test_seckey1);
    secp256k1_keypair_create(ctx, &kps[1], test_seckey2);

    secp256k1_pubkey pubkeys[2];
    secp256k1_keypair_pub(ctx, &pubkeys[0], &kps[0]);
    secp256k1_keypair_pub(ctx, &pubkeys[1], &kps[1]);

    musig_keyagg_t keyagg;
    musig_aggregate_keys(ctx, &keyagg, pubkeys, 2);

    /* Dummy merkle root (as if there's a script tree) */
    unsigned char merkle_root[32];
    memset(merkle_root, 0xAB, 32);

    /* Generate nonces */
    secp256k1_musig_secnonce secnonces[2];
    secp256k1_musig_pubnonce pubnonces[2];
    musig_generate_nonce(ctx, &secnonces[0], &pubnonces[0],
                          test_seckey1, &pubkeys[0], &keyagg.cache);
    musig_generate_nonce(ctx, &secnonces[1], &pubnonces[1],
                          test_seckey2, &pubkeys[1], &keyagg.cache);

    /* Session with merkle root */
    musig_signing_session_t session;
    musig_session_init(&session, &keyagg, 2);
    musig_session_set_pubnonce(&session, 0, &pubnonces[0]);
    musig_session_set_pubnonce(&session, 1, &pubnonces[1]);
    TEST_ASSERT(musig_session_finalize_nonces(ctx, &session, test_msg, merkle_root, NULL),
                "finalize with merkle root");

    /* Partial sign + aggregate */
    secp256k1_musig_partial_sig psigs[2];
    TEST_ASSERT(musig_create_partial_sig(ctx, &psigs[0], &secnonces[0], &kps[0], &session),
                "partial sig 0");
    TEST_ASSERT(musig_create_partial_sig(ctx, &psigs[1], &secnonces[1], &kps[1], &session),
                "partial sig 1");

    unsigned char sig[64];
    TEST_ASSERT(musig_aggregate_partial_sigs(ctx, sig, &session, psigs, 2),
                "aggregate");

    /* Verify against independently computed tweaked key with merkle root */
    secp256k1_xonly_pubkey tweaked_xonly;
    TEST_ASSERT(compute_tweaked_xonly(ctx, &tweaked_xonly, pubkeys, 2, merkle_root),
                "compute tweaked xonly with merkle root");
    TEST_ASSERT(secp256k1_schnorrsig_verify(ctx, sig, test_msg, 32, &tweaked_xonly),
                "taproot split-round sig verification");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_musig_nonce_pool(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_keypair kp1, kp2;
    secp256k1_keypair_create(ctx, &kp1, test_seckey1);
    secp256k1_keypair_create(ctx, &kp2, test_seckey2);

    secp256k1_pubkey pubkeys[2];
    secp256k1_keypair_pub(ctx, &pubkeys[0], &kp1);
    secp256k1_keypair_pub(ctx, &pubkeys[1], &kp2);

    musig_keyagg_t keyagg;
    musig_aggregate_keys(ctx, &keyagg, pubkeys, 2);

    /* Generate pool of 8 nonces for signer 0 */
    musig_nonce_pool_t pool;
    TEST_ASSERT(musig_nonce_pool_generate(ctx, &pool, 8, test_seckey1,
                                           &pubkeys[0], &keyagg.cache),
                "pool generate");
    TEST_ASSERT(musig_nonce_pool_remaining(&pool) == 8, "pool has 8 nonces");

    /* Draw 3 nonces and use each in a signing session */
    for (int i = 0; i < 3; i++) {
        secp256k1_musig_secnonce *secnonce;
        secp256k1_musig_pubnonce pubnonce_a;
        TEST_ASSERT(musig_nonce_pool_next(&pool, &secnonce, &pubnonce_a),
                    "draw nonce from pool");

        /* Signer 1 generates ad-hoc nonce */
        secp256k1_musig_secnonce secnonce_b;
        secp256k1_musig_pubnonce pubnonce_b;
        musig_generate_nonce(ctx, &secnonce_b, &pubnonce_b,
                              test_seckey2, &pubkeys[1], &keyagg.cache);

        /* Fresh keyagg for each session (tweak modifies cache) */
        musig_keyagg_t ka;
        musig_aggregate_keys(ctx, &ka, pubkeys, 2);

        musig_signing_session_t session;
        musig_session_init(&session, &ka, 2);
        musig_session_set_pubnonce(&session, 0, &pubnonce_a);
        musig_session_set_pubnonce(&session, 1, &pubnonce_b);
        TEST_ASSERT(musig_session_finalize_nonces(ctx, &session, test_msg, NULL, NULL),
                    "finalize");

        secp256k1_musig_partial_sig psigs[2];
        TEST_ASSERT(musig_create_partial_sig(ctx, &psigs[0], secnonce, &kp1, &session),
                    "partial sig pool nonce");
        TEST_ASSERT(musig_create_partial_sig(ctx, &psigs[1], &secnonce_b, &kp2, &session),
                    "partial sig ad-hoc nonce");

        unsigned char sig[64];
        TEST_ASSERT(musig_aggregate_partial_sigs(ctx, sig, &session, psigs, 2),
                    "aggregate");

        secp256k1_xonly_pubkey tweaked;
        compute_tweaked_xonly(ctx, &tweaked, pubkeys, 2, NULL);
        TEST_ASSERT(secp256k1_schnorrsig_verify(ctx, sig, test_msg, 32, &tweaked),
                    "verify pool nonce sig");
    }

    TEST_ASSERT(musig_nonce_pool_remaining(&pool) == 5, "5 remaining after drawing 3");

    /* Draw remaining 5 */
    for (int i = 0; i < 5; i++) {
        secp256k1_musig_secnonce *secnonce;
        secp256k1_musig_pubnonce pubnonce;
        TEST_ASSERT(musig_nonce_pool_next(&pool, &secnonce, &pubnonce), "draw remaining");
    }

    TEST_ASSERT(musig_nonce_pool_remaining(&pool) == 0, "pool exhausted");

    /* Next draw should fail */
    secp256k1_musig_secnonce *dummy_sec;
    secp256k1_musig_pubnonce dummy_pub;
    TEST_ASSERT(!musig_nonce_pool_next(&pool, &dummy_sec, &dummy_pub),
                "exhausted pool returns 0");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_musig_partial_sig_verify(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* 3 signers */
    const unsigned char *seckeys[3] = { test_seckey1, test_seckey2, test_seckey3 };
    secp256k1_keypair kps[3];
    secp256k1_pubkey pubkeys[3];

    for (int i = 0; i < 3; i++) {
        secp256k1_keypair_create(ctx, &kps[i], seckeys[i]);
        secp256k1_keypair_pub(ctx, &pubkeys[i], &kps[i]);
    }

    musig_keyagg_t keyagg;
    musig_aggregate_keys(ctx, &keyagg, pubkeys, 3);

    /* Generate nonces */
    secp256k1_musig_secnonce secnonces[3];
    secp256k1_musig_pubnonce pubnonces[3];
    for (int i = 0; i < 3; i++) {
        musig_generate_nonce(ctx, &secnonces[i], &pubnonces[i],
                              seckeys[i], &pubkeys[i], &keyagg.cache);
    }

    /* Session */
    musig_signing_session_t session;
    musig_session_init(&session, &keyagg, 3);
    for (int i = 0; i < 3; i++)
        musig_session_set_pubnonce(&session, (size_t)i, &pubnonces[i]);
    TEST_ASSERT(musig_session_finalize_nonces(ctx, &session, test_msg, NULL, NULL),
                "finalize 3-of-3");

    /* Create and verify each partial sig */
    secp256k1_musig_partial_sig psigs[3];
    for (int i = 0; i < 3; i++) {
        TEST_ASSERT(musig_create_partial_sig(ctx, &psigs[i], &secnonces[i], &kps[i], &session),
                    "partial sig");
        TEST_ASSERT(musig_verify_partial_sig(ctx, &psigs[i], &pubnonces[i],
                                              &pubkeys[i], &session),
                    "verify partial sig");
    }

    /* Tamper with a partial sig: serialize, flip byte, parse back */
    unsigned char sig_bytes[32];
    TEST_ASSERT(musig_partial_sig_serialize(ctx, sig_bytes, &psigs[0]),
                "serialize partial sig");
    sig_bytes[15] ^= 0xFF;  /* flip a byte */
    secp256k1_musig_partial_sig tampered;
    TEST_ASSERT(musig_partial_sig_parse(ctx, &tampered, sig_bytes),
                "parse tampered sig");
    TEST_ASSERT(!musig_verify_partial_sig(ctx, &tampered, &pubnonces[0],
                                           &pubkeys[0], &session),
                "tampered sig should fail verification");

    /* Aggregate untampered sigs should still produce valid final sig */
    unsigned char sig[64];
    TEST_ASSERT(musig_aggregate_partial_sigs(ctx, sig, &session, psigs, 3),
                "aggregate 3 partial sigs");

    secp256k1_xonly_pubkey tweaked;
    compute_tweaked_xonly(ctx, &tweaked, pubkeys, 3, NULL);
    TEST_ASSERT(secp256k1_schnorrsig_verify(ctx, sig, test_msg, 32, &tweaked),
                "final sig valid");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_musig_serialization(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_keypair kps[2];
    secp256k1_keypair_create(ctx, &kps[0], test_seckey1);
    secp256k1_keypair_create(ctx, &kps[1], test_seckey2);

    secp256k1_pubkey pubkeys[2];
    secp256k1_keypair_pub(ctx, &pubkeys[0], &kps[0]);
    secp256k1_keypair_pub(ctx, &pubkeys[1], &kps[1]);

    musig_keyagg_t keyagg;
    musig_aggregate_keys(ctx, &keyagg, pubkeys, 2);

    /* Generate nonces */
    secp256k1_musig_secnonce secnonces[2];
    secp256k1_musig_pubnonce pubnonces[2];
    musig_generate_nonce(ctx, &secnonces[0], &pubnonces[0],
                          test_seckey1, &pubkeys[0], &keyagg.cache);
    musig_generate_nonce(ctx, &secnonces[1], &pubnonces[1],
                          test_seckey2, &pubkeys[1], &keyagg.cache);

    /* Test pubnonce round-trip */
    unsigned char nonce_bytes1[66], nonce_bytes2[66];
    TEST_ASSERT(musig_pubnonce_serialize(ctx, nonce_bytes1, &pubnonces[0]),
                "serialize pubnonce");
    secp256k1_musig_pubnonce parsed_nonce;
    TEST_ASSERT(musig_pubnonce_parse(ctx, &parsed_nonce, nonce_bytes1),
                "parse pubnonce");
    TEST_ASSERT(musig_pubnonce_serialize(ctx, nonce_bytes2, &parsed_nonce),
                "re-serialize pubnonce");
    TEST_ASSERT(memcmp(nonce_bytes1, nonce_bytes2, 66) == 0,
                "pubnonce round-trip byte-identical");

    /* Full split-round with serialized partial sigs */
    musig_signing_session_t session;
    musig_session_init(&session, &keyagg, 2);
    musig_session_set_pubnonce(&session, 0, &pubnonces[0]);
    musig_session_set_pubnonce(&session, 1, &pubnonces[1]);
    TEST_ASSERT(musig_session_finalize_nonces(ctx, &session, test_msg, NULL, NULL),
                "finalize");

    secp256k1_musig_partial_sig psigs[2];
    musig_create_partial_sig(ctx, &psigs[0], &secnonces[0], &kps[0], &session);
    musig_create_partial_sig(ctx, &psigs[1], &secnonces[1], &kps[1], &session);

    /* Serialize partial sigs, parse back, aggregate */
    unsigned char psig_bytes[2][32];
    secp256k1_musig_partial_sig parsed_psigs[2];
    for (int i = 0; i < 2; i++) {
        TEST_ASSERT(musig_partial_sig_serialize(ctx, psig_bytes[i], &psigs[i]),
                    "serialize partial sig");
        TEST_ASSERT(musig_partial_sig_parse(ctx, &parsed_psigs[i], psig_bytes[i]),
                    "parse partial sig");
    }

    unsigned char sig[64];
    TEST_ASSERT(musig_aggregate_partial_sigs(ctx, sig, &session, parsed_psigs, 2),
                "aggregate parsed sigs");

    secp256k1_xonly_pubkey tweaked;
    compute_tweaked_xonly(ctx, &tweaked, pubkeys, 2, NULL);
    TEST_ASSERT(secp256k1_schnorrsig_verify(ctx, sig, test_msg, 32, &tweaked),
                "verify sig from parsed partial sigs");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_musig_split_round_5of5(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* 5 signers: LSP + 4 clients (factory root topology) */
    const unsigned char *seckeys[5] = {
        test_seckey1, test_seckey2, test_seckey3, test_seckey4, test_seckey5
    };
    secp256k1_keypair kps[5];
    secp256k1_pubkey pubkeys[5];

    for (int i = 0; i < 5; i++) {
        secp256k1_keypair_create(ctx, &kps[i], seckeys[i]);
        secp256k1_keypair_pub(ctx, &pubkeys[i], &kps[i]);
    }

    musig_keyagg_t keyagg;
    TEST_ASSERT(musig_aggregate_keys(ctx, &keyagg, pubkeys, 5), "5-key aggregation");

    /* Each signer generates a nonce */
    secp256k1_musig_secnonce secnonces[5];
    secp256k1_musig_pubnonce pubnonces[5];
    for (int i = 0; i < 5; i++) {
        TEST_ASSERT(musig_generate_nonce(ctx, &secnonces[i], &pubnonces[i],
                                          seckeys[i], &pubkeys[i], &keyagg.cache),
                    "nonce gen");
    }

    /* Session: key-path-only taproot */
    musig_signing_session_t session;
    musig_session_init(&session, &keyagg, 5);
    for (int i = 0; i < 5; i++)
        musig_session_set_pubnonce(&session, (size_t)i, &pubnonces[i]);
    TEST_ASSERT(musig_session_finalize_nonces(ctx, &session, test_msg, NULL, NULL),
                "finalize 5-of-5");

    /* All 5 create partial sigs */
    secp256k1_musig_partial_sig psigs[5];
    for (int i = 0; i < 5; i++) {
        TEST_ASSERT(musig_create_partial_sig(ctx, &psigs[i], &secnonces[i], &kps[i], &session),
                    "partial sig");
    }

    /* Aggregate */
    unsigned char sig[64];
    TEST_ASSERT(musig_aggregate_partial_sigs(ctx, sig, &session, psigs, 5),
                "aggregate 5 partial sigs");

    /* Verify against taproot-tweaked key */
    secp256k1_xonly_pubkey tweaked;
    TEST_ASSERT(compute_tweaked_xonly(ctx, &tweaked, pubkeys, 5, NULL),
                "compute 5-of-5 tweaked key");
    TEST_ASSERT(secp256k1_schnorrsig_verify(ctx, sig, test_msg, 32, &tweaked),
                "5-of-5 split-round sig verification");

    secp256k1_context_destroy(ctx);
    return 1;
}
