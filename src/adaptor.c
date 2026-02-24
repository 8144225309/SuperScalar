#include "superscalar/adaptor.h"
#include <string.h>
#include <stdlib.h>

/* --- Part A: MuSig2 adaptor signature primitives --- */

int adaptor_get_nonce_parity(
    const secp256k1_context *ctx,
    int *nonce_parity_out,
    const musig_signing_session_t *session)
{
    if (!session->session_ready)
        return 0;
    return secp256k1_musig_nonce_parity(ctx, nonce_parity_out, &session->session);
}

int adaptor_adapt(
    const secp256k1_context *ctx,
    unsigned char *sig64_out,
    const unsigned char *pre_sig64,
    const unsigned char *sec_adaptor32,
    int nonce_parity)
{
    return secp256k1_musig_adapt(ctx, sig64_out, pre_sig64,
                                  sec_adaptor32, nonce_parity);
}

int adaptor_extract_secret(
    const secp256k1_context *ctx,
    unsigned char *sec_adaptor32_out,
    const unsigned char *sig64,
    const unsigned char *pre_sig64,
    int nonce_parity)
{
    return secp256k1_musig_extract_adaptor(ctx, sec_adaptor32_out,
                                            sig64, pre_sig64, nonce_parity);
}

/* --- Part B: PTLC key turnover protocol --- */

int adaptor_create_turnover_presig(
    const secp256k1_context *ctx,
    unsigned char *presig64_out,
    int *nonce_parity_out,
    const unsigned char *msg32,
    const secp256k1_keypair *keypairs,
    size_t n_signers,
    musig_keyagg_t *keyagg,
    const unsigned char *merkle_root,
    const secp256k1_pubkey *adaptor_point)
{
    int ret = 0;

    /* Initialize signing session */
    musig_signing_session_t session;
    musig_session_init(&session, keyagg, n_signers);

    /* Allocate secnonces */
    secp256k1_musig_secnonce *secnonces =
        (secp256k1_musig_secnonce *)calloc(n_signers,
                                            sizeof(secp256k1_musig_secnonce));
    if (!secnonces) return 0;

    /* Generate nonces and set pubnonces */
    for (size_t i = 0; i < n_signers; i++) {
        unsigned char seckey[32];
        secp256k1_pubkey pk;

        if (!secp256k1_keypair_sec(ctx, seckey, &keypairs[i]))
            goto cleanup;
        if (!secp256k1_keypair_pub(ctx, &pk, &keypairs[i]))
            goto cleanup;

        secp256k1_musig_pubnonce pubnonce;
        if (!musig_generate_nonce(ctx, &secnonces[i], &pubnonce,
                                   seckey, &pk, &keyagg->cache))
            goto cleanup;

        memset(seckey, 0, 32);

        if (!musig_session_set_pubnonce(&session, i, &pubnonce))
            goto cleanup;
    }

    /* Finalize nonces WITH adaptor point (produces pre-signature on aggregate) */
    if (!musig_session_finalize_nonces(ctx, &session, msg32,
                                        merkle_root, adaptor_point))
        goto cleanup;

    /* Get nonce parity */
    if (!adaptor_get_nonce_parity(ctx, nonce_parity_out, &session))
        goto cleanup;

    /* Create partial signatures */
    secp256k1_musig_partial_sig *partial_sigs =
        (secp256k1_musig_partial_sig *)calloc(n_signers,
                                               sizeof(secp256k1_musig_partial_sig));
    if (!partial_sigs)
        goto cleanup;

    for (size_t i = 0; i < n_signers; i++) {
        if (!musig_create_partial_sig(ctx, &partial_sigs[i],
                                       &secnonces[i], &keypairs[i], &session))
        {
            free(partial_sigs);
            goto cleanup;
        }
    }

    /* Aggregate partial sigs -> pre-signature (because adaptor was non-NULL) */
    if (!musig_aggregate_partial_sigs(ctx, presig64_out, &session,
                                       partial_sigs, n_signers))
    {
        free(partial_sigs);
        goto cleanup;
    }

    free(partial_sigs);
    ret = 1;

cleanup:
    memset(secnonces, 0, n_signers * sizeof(secp256k1_musig_secnonce));
    free(secnonces);
    return ret;
}

int adaptor_verify_extracted_key(
    const secp256k1_context *ctx,
    const unsigned char *extracted_scalar32,
    const secp256k1_pubkey *expected_pubkey)
{
    /* Derive public key from extracted scalar */
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, extracted_scalar32))
        return 0;

    secp256k1_pubkey derived_pk;
    if (!secp256k1_keypair_pub(ctx, &derived_pk, &kp))
        return 0;

    /* Compare serialized compressed pubkeys */
    unsigned char derived_ser[33], expected_ser[33];
    size_t len1 = 33, len2 = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, derived_ser, &len1,
                                        &derived_pk, SECP256K1_EC_COMPRESSED))
        return 0;
    if (!secp256k1_ec_pubkey_serialize(ctx, expected_ser, &len2,
                                        expected_pubkey, SECP256K1_EC_COMPRESSED))
        return 0;

    return (memcmp(derived_ser, expected_ser, 33) == 0) ? 1 : 0;
}
