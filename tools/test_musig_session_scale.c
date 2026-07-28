/* Distributed MuSig2 SESSION-flow scaling test — replicates the factory's exact
   cooperative-close signing path (fixed-array session + taproot tweak + per-signer
   partial-sig verify + aggregate), in isolation (no wire, no thrash).
   If the session path fails at 256 while pure crypto passes, the limiter is our
   fixed-array session cap. Per-partial verify pinpoints a bad signer if any. */
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
    sk[0] = 0x01;
    sk[28] = (unsigned char)(i >> 24); sk[29] = (unsigned char)(i >> 16);
    sk[30] = (unsigned char)(i >> 8);  sk[31] = (unsigned char)(i | 0x01);
}

static int test_session_n(secp256k1_context *ctx, size_t n) {
    int rc = 0, bad_partial = -1;
    secp256k1_keypair *kps = calloc(n, sizeof(secp256k1_keypair));
    secp256k1_pubkey  *pks = calloc(n, sizeof(secp256k1_pubkey));
    secp256k1_musig_secnonce *sns = calloc(n, sizeof(secp256k1_musig_secnonce));
    secp256k1_musig_pubnonce *pns = calloc(n, sizeof(secp256k1_musig_pubnonce));
    secp256k1_musig_partial_sig *psigs = calloc(n, sizeof(secp256k1_musig_partial_sig));
    musig_signing_session_t *session = calloc(1, sizeof(musig_signing_session_t));
    if (!kps||!pks||!sns||!pns||!psigs||!session) { printf("N=%zu: ALLOC FAIL\n", n); goto done; }

    for (size_t i = 0; i < n; i++) {
        unsigned char sk[32]; seckey_from_i(sk, (unsigned)(i + 1));
        if (!secp256k1_keypair_create(ctx, &kps[i], sk)) { printf("N=%zu kp %zu FAIL\n",n,i); goto done; }
        secp256k1_keypair_pub(ctx, &pks[i], &kps[i]);
    }
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks, n)) { printf("N=%4zu SESSION: keyagg FAIL\n", n); goto done; }

    musig_session_init(session, &ka, n);
    unsigned char msg[32]; memset(msg, 0x37, 32);

    /* each signer generates a nonce and hands its pubnonce to the session (fixed array) */
    int set_ok = 1;
    for (size_t i = 0; i < n; i++) {
        unsigned char sk[32];
        if (!secp256k1_keypair_sec(ctx, sk, &kps[i])) { goto done; }
        if (!musig_generate_nonce(ctx, &sns[i], &pns[i], sk, &pks[i], &ka.cache)) { printf("N=%zu nonce %zu FAIL\n",n,i); goto done; }
        if (!musig_session_set_pubnonce(session, i, &pns[i])) { set_ok = 0; printf("N=%4zu SESSION: set_pubnonce REJECTED at signer %zu (cap)\n", n, i); break; }
    }
    if (!set_ok) goto done;

    if (!musig_session_finalize_nonces(ctx, session, msg, NULL /*keypath*/, NULL)) { printf("N=%4zu SESSION: finalize_nonces FAIL\n", n); goto done; }

    /* each signer partial-signs; verify EACH partial against the session */
    for (size_t i = 0; i < n; i++) {
        if (!musig_create_partial_sig(ctx, &psigs[i], &sns[i], &kps[i], session)) { printf("N=%zu partial %zu FAIL\n",n,i); goto done; }
        if (!musig_verify_partial_sig(ctx, &psigs[i], &pns[i], &pks[i], session) && bad_partial < 0) bad_partial = (int)i;
    }

    unsigned char sig[64];
    if (!musig_aggregate_partial_sigs(ctx, sig, session, psigs, n)) { printf("N=%4zu SESSION: partial_sig_agg FAIL\n", n); goto done; }

    /* verify aggregate vs the TAPROOT-TWEAKED aggregate key (keypath, merkle_root NULL) */
    unsigned char xser[32]; secp256k1_xonly_pubkey_serialize(ctx, xser, &ka.agg_pubkey);
    unsigned char tweak[32]; secp256k1_tagged_sha256(ctx, tweak, (const unsigned char*)"TapTweak", 8, xser, 32);
    secp256k1_musig_keyagg_cache cc = ka.cache; secp256k1_pubkey tpk;
    secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tpk, &cc, tweak);
    secp256k1_xonly_pubkey txo; secp256k1_xonly_pubkey_from_pubkey(ctx, &txo, NULL, &tpk);
    int ok = secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &txo);

    printf("N=%4zu SESSION: set=OK finalize=OK partials=%s agg=OK BIP340-verify=%s\n",
           n, bad_partial < 0 ? "all-valid" : "BAD", ok ? "PASS" : "FAIL");
    if (bad_partial >= 0) printf("        (first invalid partial sig at signer %d)\n", bad_partial);
    rc = ok && (bad_partial < 0);
done:
    free(kps); free(pks); free(sns); free(pns); free(psigs); free(session);
    return rc;
}

int main(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    size_t sizes[] = { 128, 255, 256, 257, 300, 512 };
    printf("=== MuSig2 DISTRIBUTED SESSION flow (factory close path) ===\n");
    printf("(MUSIG_SESSION_MAX_SIGNERS = %d)\n", MUSIG_SESSION_MAX_SIGNERS);
    int all_upto256 = 1;
    for (size_t i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
        int r = test_session_n(ctx, sizes[i]);
        if (sizes[i] <= 256) all_upto256 &= r;
    }
    printf("\nSession path %s at N<=256\n", all_upto256 ? "PASSES" : "FAILS");
    secp256k1_context_destroy(ctx);
    return 0;
}
