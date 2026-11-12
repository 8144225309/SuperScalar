/* Standalone MuSig2 scaling test: does the crypto have a hard limit at 256?
   Aggregates N pubkeys, does the full nonce->partial->aggregate MuSig2 flow via
   the project's dynamic (size_t/calloc) wrappers, and BIP-340 verifies the
   resulting 64-byte Schnorr sig against the aggregate x-only key.
   If it PASSES at 512/1024/2048, Schnorr/MuSig2 has no 256 limit -> our factory's
   256 failure is an implementation cap (the fixed session array / wire), not crypto. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_musig.h>
#include "superscalar/musig.h"

static void seckey_from_i(unsigned char sk[32], unsigned int i) {
    memset(sk, 0, 32);
    sk[0] = 0x01;                     /* keep well inside curve order, nonzero */
    sk[28] = (unsigned char)(i >> 24);
    sk[29] = (unsigned char)(i >> 16);
    sk[30] = (unsigned char)(i >> 8);
    sk[31] = (unsigned char)(i) ;
    sk[31] = (unsigned char)(sk[31] | 0x01); /* ensure nonzero even for i=0 */
}

static int test_n(secp256k1_context *ctx, size_t n) {
    int rc = 0;
    secp256k1_keypair *kps = calloc(n, sizeof(secp256k1_keypair));
    secp256k1_pubkey  *pks = calloc(n, sizeof(secp256k1_pubkey));
    if (!kps || !pks) { printf("N=%zu: ALLOC FAIL\n", n); goto done; }

    for (size_t i = 0; i < n; i++) {
        unsigned char sk[32];
        seckey_from_i(sk, (unsigned)(i + 1));
        if (!secp256k1_keypair_create(ctx, &kps[i], sk)) { printf("N=%zu: keypair %zu FAIL\n", n, i); goto done; }
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) { printf("N=%zu: pub %zu FAIL\n", n, i); goto done; }
    }

    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks, n)) { printf("N=%4zu: KEYAGG FAIL\n", n); goto done; }

    unsigned char msg[32]; memset(msg, 0x42, 32);
    unsigned char sig[64];
    if (!musig_sign_all_local(ctx, sig, msg, kps, n, &ka)) { printf("N=%4zu: SIGN FAIL\n", n); goto done; }

    int ok = secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &ka.agg_pubkey);
    printf("N=%4zu signers:  keyagg=OK  sign=OK  BIP340-verify=%s\n", n, ok ? "PASS" : "FAIL");
    rc = ok;
done:
    free(kps); free(pks);
    return rc;
}

int main(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    size_t sizes[] = { 2, 128, 160, 255, 256, 257, 384, 512, 1024, 2048 };
    int all = 1;
    printf("=== MuSig2 aggregation scaling (pure crypto, dynamic path) ===\n");
    for (size_t i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++)
        all &= test_n(ctx, sizes[i]);
    printf("\n%s\n", all ? "ALL PASS: MuSig2/Schnorr has NO hard limit at 256 (verifies to 2048 signers)"
                          : "SOME FAILED: a real limit exists at the failing N");
    secp256k1_context_destroy(ctx);
    return all ? 0 : 1;
}
