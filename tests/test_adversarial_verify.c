/* test_adversarial_verify.c — the "forgery rejection matrix".
 *
 * Adversarial / negative tests: each feeds a fund-safety verifier an input that
 * LOOKS real (valid structure, valid scalars/points) but is WRONG, and asserts
 * the verifier rejects it. A fail-closed check is only proven by watching it
 * reject a plausible forgery; these tests also catch regressions if a check is
 * ever weakened back to fail-open.
 *
 * This file holds the crypto-level rows (keyagg substitution, final-sig tamper,
 * wrong-message). Other matrix rows are proven by dedicated tests elsewhere and
 * are mapped in doc/adversarial-verification-matrix.md:
 *   preimage            -> test_channel.c (wrong preimage rejected)
 *   HTLC cltv range     -> test_channels.c (cltv <= delta rejected)
 *   nonce reuse         -> test_musig.c   (pool exhaustion, no reissue)
 *   partial-sig tamper  -> test_musig.c   (tampered partial sig)
 *   peer auth wrong key -> test_channels.c (noise NK wrong pubkey)
 *   revocation forgery  -> test_persist.c (failclosed + client verifies LSP)
 *   cheat gate          -> test_persist.c (gate off -> inert)
 * Integration rows (WT false-positive, reconnect, item-1 live) are regtest
 * adversarial drills (tools/test_regtest_adversarial_*.sh).
 */
#include "superscalar/musig.h"
#include "superscalar/sha256.h"
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

static secp256k1_context *adv_ctx(void) {
    return secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

/* KEYAGG SUBSTITUTION: an honest 2-of-2 signs under keyagg[A,B]. An attacker who
   substitutes a co-signer (B -> C) cannot make that signature verify under the
   substituted keyagg[A,C] — proving keys can't be swapped after the fact. */
int test_adversarial_keyagg_substitution(void) {
    secp256k1_context *ctx = adv_ctx();
    TEST_ASSERT(ctx, "ctx");
    unsigned char skA[32], skB[32], skC[32], msg[32];
    memset(skA, 0x11, 32); memset(skB, 0x22, 32); memset(skC, 0x33, 32); memset(msg, 0x44, 32);

    secp256k1_keypair kpA, kpB;
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kpA, skA), "kpA");
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kpB, skB), "kpB");
    secp256k1_pubkey pkA, pkB, pkC;
    TEST_ASSERT(secp256k1_keypair_pub(ctx, &pkA, &kpA), "pkA");
    TEST_ASSERT(secp256k1_keypair_pub(ctx, &pkB, &kpB), "pkB");
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &pkC, skC), "pkC");

    secp256k1_pubkey set_ab[2] = { pkA, pkB };
    musig_keyagg_t ka_ab;
    TEST_ASSERT(musig_aggregate_keys(ctx, &ka_ab, set_ab, 2), "agg AB");
    secp256k1_keypair kps[2] = { kpA, kpB };
    unsigned char sig[64];
    TEST_ASSERT(musig_sign_all_local(ctx, sig, msg, kps, 2, &ka_ab), "sign AB");
    TEST_ASSERT(secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &ka_ab.agg_pubkey),
                "honest AB sig verifies");

    /* substitute B -> C */
    secp256k1_pubkey set_ac[2] = { pkA, pkC };
    musig_keyagg_t ka_ac;
    TEST_ASSERT(musig_aggregate_keys(ctx, &ka_ac, set_ac, 2), "agg AC");
    TEST_ASSERT(!secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &ka_ac.agg_pubkey),
                "FORGERY: AB sig must NOT verify under substituted keyagg[A,C]");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* FINAL-SIG TAMPER: a single flipped byte in the aggregate signature must fail
   verification (no malleable acceptance). */
int test_adversarial_final_sig_tamper(void) {
    secp256k1_context *ctx = adv_ctx();
    TEST_ASSERT(ctx, "ctx");
    unsigned char skA[32], skB[32], msg[32];
    memset(skA, 0x55, 32); memset(skB, 0x66, 32); memset(msg, 0x77, 32);
    secp256k1_keypair kps[2];
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[0], skA), "kpA");
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[1], skB), "kpB");
    secp256k1_pubkey pks[2];
    TEST_ASSERT(secp256k1_keypair_pub(ctx, &pks[0], &kps[0]), "pkA");
    TEST_ASSERT(secp256k1_keypair_pub(ctx, &pks[1], &kps[1]), "pkB");
    musig_keyagg_t ka;
    TEST_ASSERT(musig_aggregate_keys(ctx, &ka, pks, 2), "agg");
    unsigned char sig[64];
    TEST_ASSERT(musig_sign_all_local(ctx, sig, msg, kps, 2, &ka), "sign");
    TEST_ASSERT(secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &ka.agg_pubkey),
                "honest sig verifies");

    for (int b = 0; b < 64; b += 16) {
        unsigned char t[64];
        memcpy(t, sig, 64);
        t[b] ^= 0x01;
        TEST_ASSERT(!secp256k1_schnorrsig_verify(ctx, t, msg, 32, &ka.agg_pubkey),
                    "FORGERY: tampered aggregate sig must fail");
    }
    secp256k1_context_destroy(ctx);
    return 1;
}

/* WRONG MESSAGE: a valid signature does not verify against any other message
   (binding). */
int test_adversarial_wrong_message_binding(void) {
    secp256k1_context *ctx = adv_ctx();
    TEST_ASSERT(ctx, "ctx");
    unsigned char skA[32], skB[32], msg[32], other[32];
    memset(skA, 0x12, 32); memset(skB, 0x34, 32); memset(msg, 0x56, 32); memset(other, 0x57, 32);
    secp256k1_keypair kps[2];
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[0], skA), "kpA");
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[1], skB), "kpB");
    secp256k1_pubkey pks[2];
    TEST_ASSERT(secp256k1_keypair_pub(ctx, &pks[0], &kps[0]), "pkA");
    TEST_ASSERT(secp256k1_keypair_pub(ctx, &pks[1], &kps[1]), "pkB");
    musig_keyagg_t ka;
    TEST_ASSERT(musig_aggregate_keys(ctx, &ka, pks, 2), "agg");
    unsigned char sig[64];
    TEST_ASSERT(musig_sign_all_local(ctx, sig, msg, kps, 2, &ka), "sign");
    TEST_ASSERT(secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &ka.agg_pubkey), "honest verify");
    TEST_ASSERT(!secp256k1_schnorrsig_verify(ctx, sig, other, 32, &ka.agg_pubkey),
                "FORGERY: sig must NOT verify against a different message");
    secp256k1_context_destroy(ctx);
    return 1;
}
