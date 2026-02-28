#include "superscalar/musig.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "superscalar/sha256.h"

static int fill_random(unsigned char *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 0;
    size_t n = fread(buf, 1, len, f);
    fclose(f);
    return n == len ? 1 : 0;
}

int musig_aggregate_keys(
    const secp256k1_context *ctx,
    musig_keyagg_t *out,
    const secp256k1_pubkey *pubkeys,
    size_t n_pubkeys
) {
    const secp256k1_pubkey **ptrs = (const secp256k1_pubkey **)malloc(
        n_pubkeys * sizeof(secp256k1_pubkey *));
    if (!ptrs) return 0;

    for (size_t i = 0; i < n_pubkeys; i++)
        ptrs[i] = &pubkeys[i];

    int ret = secp256k1_musig_pubkey_agg(
        ctx, &out->agg_pubkey, &out->cache, ptrs, n_pubkeys
    );

    free(ptrs);
    return ret;
}

int musig_sign_all_local(
    const secp256k1_context *ctx,
    unsigned char *sig64_out,
    const unsigned char *msg32,
    const secp256k1_keypair *keypairs,
    size_t n_signers,
    const musig_keyagg_t *keyagg
) {
    int ret = 0;

    secp256k1_musig_secnonce *secnonces = (secp256k1_musig_secnonce *)calloc(
        n_signers, sizeof(secp256k1_musig_secnonce));
    secp256k1_musig_pubnonce *pubnonces = (secp256k1_musig_pubnonce *)calloc(
        n_signers, sizeof(secp256k1_musig_pubnonce));
    const secp256k1_musig_pubnonce **pubnonce_ptrs = (const secp256k1_musig_pubnonce **)malloc(
        n_signers * sizeof(secp256k1_musig_pubnonce *));
    secp256k1_musig_partial_sig *partial_sigs = (secp256k1_musig_partial_sig *)calloc(
        n_signers, sizeof(secp256k1_musig_partial_sig));
    const secp256k1_musig_partial_sig **psig_ptrs = (const secp256k1_musig_partial_sig **)malloc(
        n_signers * sizeof(secp256k1_musig_partial_sig *));

    if (!secnonces || !pubnonces || !pubnonce_ptrs || !partial_sigs || !psig_ptrs)
        goto cleanup;

    /* Generate nonces */
    for (size_t i = 0; i < n_signers; i++) {
        unsigned char session_id[32];
        unsigned char seckey[32];
        secp256k1_pubkey pk;

        if (!fill_random(session_id, 32))
            goto cleanup;
        if (!secp256k1_keypair_sec(ctx, seckey, &keypairs[i]))
            goto cleanup;
        if (!secp256k1_keypair_pub(ctx, &pk, &keypairs[i]))
            goto cleanup;

        if (!secp256k1_musig_nonce_gen(ctx, &secnonces[i], &pubnonces[i],
                                        session_id, seckey, &pk, msg32,
                                        &keyagg->cache, NULL))
            goto cleanup;

        memset(seckey, 0, 32);
        memset(session_id, 0, 32);
        pubnonce_ptrs[i] = &pubnonces[i];
    }

    /* Aggregate nonces */
    secp256k1_musig_aggnonce aggnonce;
    if (!secp256k1_musig_nonce_agg(ctx, &aggnonce, pubnonce_ptrs, n_signers))
        goto cleanup;

    /* Process -> session */
    secp256k1_musig_session session;
    if (!secp256k1_musig_nonce_process(ctx, &session, &aggnonce,
                                        msg32, &keyagg->cache, NULL))
        goto cleanup;

    /* Partial sign */
    for (size_t i = 0; i < n_signers; i++) {
        if (!secp256k1_musig_partial_sign(ctx, &partial_sigs[i],
                                           &secnonces[i], &keypairs[i],
                                           &keyagg->cache, &session))
            goto cleanup;
        psig_ptrs[i] = &partial_sigs[i];
    }

    /* Aggregate into final Schnorr sig */
    if (!secp256k1_musig_partial_sig_agg(ctx, sig64_out, &session,
                                          psig_ptrs, n_signers))
        goto cleanup;

    ret = 1;

cleanup:
    free(secnonces);
    free(pubnonces);
    free(pubnonce_ptrs);
    free(partial_sigs);
    free(psig_ptrs);
    return ret;
}

/* Compute BIP-341 TapTweak from internal key and optional merkle root.
   tweak_out: 32-byte output.
   internal_key: x-only aggregate pubkey (pre-tweak).
   merkle_root: NULL for key-path-only, 32 bytes for script tree. */
static int compute_taptweak(
    const secp256k1_context *ctx,
    unsigned char *tweak_out,
    const secp256k1_xonly_pubkey *internal_key,
    const unsigned char *merkle_root
) {
    unsigned char internal_key_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_key_ser, internal_key))
        return 0;

    if (merkle_root) {
        unsigned char data[64];
        memcpy(data, internal_key_ser, 32);
        memcpy(data + 32, merkle_root, 32);
        sha256_tagged("TapTweak", data, 64, tweak_out);
    } else {
        sha256_tagged("TapTweak", internal_key_ser, 32, tweak_out);
    }
    return 1;
}

int musig_sign_taproot(
    const secp256k1_context *ctx,
    unsigned char *sig64_out,
    const unsigned char *msg32,
    const secp256k1_keypair *keypairs,
    size_t n_signers,
    musig_keyagg_t *keyagg,
    const unsigned char *merkle_root
) {
    unsigned char tweak[32];
    if (!compute_taptweak(ctx, tweak, &keyagg->agg_pubkey, merkle_root))
        return 0;

    secp256k1_pubkey tweaked_agg;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_agg,
                                                 &keyagg->cache, tweak))
        return 0;

    return musig_sign_all_local(ctx, sig64_out, msg32, keypairs, n_signers, keyagg);
}

/* --- Nonce pool --- */

int musig_nonce_pool_generate(
    const secp256k1_context *ctx,
    musig_nonce_pool_t *pool,
    size_t count,
    const unsigned char *seckey32,
    const secp256k1_pubkey *pubkey,
    const secp256k1_musig_keyagg_cache *keyagg_cache
) {
    if (count > MUSIG_NONCE_POOL_MAX)
        count = MUSIG_NONCE_POOL_MAX;

    memset(pool, 0, sizeof(*pool));

    for (size_t i = 0; i < count; i++) {
        unsigned char session_id[32];
        unsigned char extra_input[32];

        if (!fill_random(session_id, 32))
            return 0;

        /* Build unique extra_input: random + counter XOR */
        if (!fill_random(extra_input, 32))
            return 0;
        extra_input[0] ^= (unsigned char)(i & 0xff);
        extra_input[1] ^= (unsigned char)((i >> 8) & 0xff);

        musig_nonce_pair_t *pair = &pool->nonces[i];
        if (!secp256k1_musig_nonce_gen(ctx, &pair->secnonce, &pair->pubnonce,
                                        session_id, seckey32, pubkey,
                                        NULL,  /* msg32 unknown at pool generation time */
                                        keyagg_cache, extra_input))
        {
            memset(session_id, 0, 32);
            memset(extra_input, 0, 32);
            return 0;
        }

        memset(session_id, 0, 32);
        memset(extra_input, 0, 32);
    }

    pool->count = count;
    pool->next_unused = 0;
    return 1;
}

int musig_nonce_pool_next(
    musig_nonce_pool_t *pool,
    secp256k1_musig_secnonce **secnonce_out,
    secp256k1_musig_pubnonce *pubnonce_out
) {
    if (pool->next_unused >= pool->count)
        return 0;

    musig_nonce_pair_t *pair = &pool->nonces[pool->next_unused];
    *secnonce_out = &pair->secnonce;
    memcpy(pubnonce_out, &pair->pubnonce, sizeof(secp256k1_musig_pubnonce));
    pool->next_unused++;
    return 1;
}

size_t musig_nonce_pool_remaining(const musig_nonce_pool_t *pool) {
    return pool->count - pool->next_unused;
}

/* --- Serialization wrappers --- */

int musig_pubnonce_serialize(
    const secp256k1_context *ctx,
    unsigned char *out66,
    const secp256k1_musig_pubnonce *nonce
) {
    return secp256k1_musig_pubnonce_serialize(ctx, out66, nonce);
}

int musig_pubnonce_parse(
    const secp256k1_context *ctx,
    secp256k1_musig_pubnonce *nonce,
    const unsigned char *in66
) {
    return secp256k1_musig_pubnonce_parse(ctx, nonce, in66);
}

int musig_partial_sig_serialize(
    const secp256k1_context *ctx,
    unsigned char *out32,
    const secp256k1_musig_partial_sig *sig
) {
    return secp256k1_musig_partial_sig_serialize(ctx, out32, sig);
}

int musig_partial_sig_parse(
    const secp256k1_context *ctx,
    secp256k1_musig_partial_sig *sig,
    const unsigned char *in32
) {
    return secp256k1_musig_partial_sig_parse(ctx, sig, in32);
}

/* --- Split-round signing session --- */

void musig_session_init(
    musig_signing_session_t *session,
    const musig_keyagg_t *keyagg,
    size_t n_signers
) {
    memset(session, 0, sizeof(*session));
    memcpy(&session->cache, &keyagg->cache, sizeof(secp256k1_musig_keyagg_cache));
    memcpy(&session->agg_pubkey, &keyagg->agg_pubkey, sizeof(secp256k1_xonly_pubkey));
    session->n_signers = n_signers;
}

int musig_session_set_pubnonce(
    musig_signing_session_t *session,
    size_t signer_index,
    const secp256k1_musig_pubnonce *pubnonce
) {
    if (signer_index >= session->n_signers)
        return 0;
    if (signer_index >= MUSIG_SESSION_MAX_SIGNERS)
        return 0;

    memcpy(&session->pubnonces[signer_index], pubnonce,
           sizeof(secp256k1_musig_pubnonce));
    session->nonces_collected++;
    return 1;
}

int musig_session_finalize_nonces(
    const secp256k1_context *ctx,
    musig_signing_session_t *session,
    const unsigned char *msg32,
    const unsigned char *merkle_root,
    const secp256k1_pubkey *adaptor
) {
    if ((size_t)session->nonces_collected != session->n_signers)
        return 0;

    /* Build pointer array for nonce aggregation */
    const secp256k1_musig_pubnonce *ptrs[MUSIG_SESSION_MAX_SIGNERS];
    for (size_t i = 0; i < session->n_signers; i++)
        ptrs[i] = &session->pubnonces[i];

    if (!secp256k1_musig_nonce_agg(ctx, &session->aggnonce, ptrs, session->n_signers))
        return 0;

    /* Apply taproot tweak to session's cache copy */
    unsigned char tweak[32];
    if (!compute_taptweak(ctx, tweak, &session->agg_pubkey, merkle_root))
        return 0;

    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, NULL, &session->cache, tweak))
        return 0;

    /* Store message */
    memcpy(session->msg32, msg32, 32);

    /* Create MuSig2 session (nonce_process) */
    if (!secp256k1_musig_nonce_process(ctx, &session->session, &session->aggnonce,
                                        msg32, &session->cache, adaptor))
        return 0;

    session->session_ready = 1;
    return 1;
}

int musig_create_partial_sig(
    const secp256k1_context *ctx,
    secp256k1_musig_partial_sig *partial_sig_out,
    secp256k1_musig_secnonce *secnonce,
    const secp256k1_keypair *keypair,
    const musig_signing_session_t *session
) {
    if (!session->session_ready)
        return 0;

    return secp256k1_musig_partial_sign(ctx, partial_sig_out, secnonce,
                                         keypair, &session->cache,
                                         &session->session);
}

int musig_verify_partial_sig(
    const secp256k1_context *ctx,
    const secp256k1_musig_partial_sig *partial_sig,
    const secp256k1_musig_pubnonce *pubnonce,
    const secp256k1_pubkey *pubkey,
    const musig_signing_session_t *session
) {
    if (!session->session_ready)
        return 0;

    return secp256k1_musig_partial_sig_verify(ctx, partial_sig, pubnonce,
                                               pubkey, &session->cache,
                                               &session->session);
}

int musig_aggregate_partial_sigs(
    const secp256k1_context *ctx,
    unsigned char *sig64_out,
    const musig_signing_session_t *session,
    const secp256k1_musig_partial_sig *partial_sigs,
    size_t n_sigs
) {
    if (!session->session_ready)
        return 0;

    const secp256k1_musig_partial_sig *ptrs[MUSIG_SESSION_MAX_SIGNERS];
    if (n_sigs > MUSIG_SESSION_MAX_SIGNERS)
        return 0;

    for (size_t i = 0; i < n_sigs; i++)
        ptrs[i] = &partial_sigs[i];

    return secp256k1_musig_partial_sig_agg(ctx, sig64_out, &session->session,
                                            ptrs, n_sigs);
}

/* --- Ad-hoc single nonce generation --- */

int musig_generate_nonce(
    const secp256k1_context *ctx,
    secp256k1_musig_secnonce *secnonce_out,
    secp256k1_musig_pubnonce *pubnonce_out,
    const unsigned char *seckey32,
    const secp256k1_pubkey *pubkey,
    const secp256k1_musig_keyagg_cache *keyagg_cache
) {
    unsigned char session_id[32];
    if (!fill_random(session_id, 32))
        return 0;

    int ret = secp256k1_musig_nonce_gen(ctx, secnonce_out, pubnonce_out,
                                         session_id, seckey32, pubkey,
                                         NULL, keyagg_cache, NULL);
    memset(session_id, 0, 32);
    return ret;
}
