#ifndef SUPERSCALAR_ADAPTOR_H
#define SUPERSCALAR_ADAPTOR_H

#include "musig.h"
#include <secp256k1.h>

/* --- Part A: MuSig2 adaptor signature primitives --- */

/* Get nonce parity from a finalized signing session (needed for adapt/extract). */
int adaptor_get_nonce_parity(
    const secp256k1_context *ctx,
    int *nonce_parity_out,
    const musig_signing_session_t *session);

/* Create valid signature from pre-signature + secret adaptor scalar.
   pre_sig64: output of musig_aggregate_partial_sigs() when adaptor was non-NULL.
   sec_adaptor32: the 32-byte secret scalar (e.g., client's private key). */
int adaptor_adapt(
    const secp256k1_context *ctx,
    unsigned char *sig64_out,
    const unsigned char *pre_sig64,
    const unsigned char *sec_adaptor32,
    int nonce_parity);

/* Extract secret adaptor scalar from pre-signature + completed signature.
   sig64: the valid signature (published on-chain).
   pre_sig64: the pre-signature (held by LSP). */
int adaptor_extract_secret(
    const secp256k1_context *ctx,
    unsigned char *sec_adaptor32_out,
    const unsigned char *sig64,
    const unsigned char *pre_sig64,
    int nonce_parity);

/* --- Part B: PTLC key turnover protocol --- */

/* High-level: create a key-turnover pre-signature using all-local signing.
   All signers (including the departing client) participate in MuSig2.
   The adaptor point is the departing client's public key.
   Returns: pre-signature (64 bytes) + nonce parity.

   This uses the split-round infrastructure: init session, generate nonces,
   finalize with adaptor point, create partial sigs, aggregate.

   keypairs: array of n_signers keypairs.
   keyagg: aggregated key (will be modified by taproot tweak).
   merkle_root: NULL for key-path-only.
   adaptor_point: the departing client's public key (adaptor). */
int adaptor_create_turnover_presig(
    const secp256k1_context *ctx,
    unsigned char *presig64_out,
    int *nonce_parity_out,
    const unsigned char *msg32,
    const secp256k1_keypair *keypairs,
    size_t n_signers,
    musig_keyagg_t *keyagg,
    const unsigned char *merkle_root,
    const secp256k1_pubkey *adaptor_point);

/* LSP-side: verify extracted key matches expected public key. */
int adaptor_verify_extracted_key(
    const secp256k1_context *ctx,
    const unsigned char *extracted_scalar32,
    const secp256k1_pubkey *expected_pubkey);

#endif /* SUPERSCALAR_ADAPTOR_H */
