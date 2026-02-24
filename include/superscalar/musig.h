#ifndef SUPERSCALAR_MUSIG_H
#define SUPERSCALAR_MUSIG_H

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_musig.h>

#include <stddef.h>

typedef struct {
    secp256k1_xonly_pubkey agg_pubkey;
    secp256k1_musig_keyagg_cache cache;
} musig_keyagg_t;

/* Aggregate N pubkeys into a single x-only key. */
int musig_aggregate_keys(
    const secp256k1_context *ctx,
    musig_keyagg_t *out,
    const secp256k1_pubkey *pubkeys,
    size_t n_pubkeys
);

/* All-local MuSig2 signing. Produces a 64-byte BIP-340 Schnorr sig. */
int musig_sign_all_local(
    const secp256k1_context *ctx,
    unsigned char *sig64_out,
    const unsigned char *msg32,
    const secp256k1_keypair *keypairs,
    size_t n_signers,
    const musig_keyagg_t *keyagg
);

/* MuSig2 signing with taproot key-path tweak. Modifies keyagg. */
int musig_sign_taproot(
    const secp256k1_context *ctx,
    unsigned char *sig64_out,
    const unsigned char *msg32,
    const secp256k1_keypair *keypairs,
    size_t n_signers,
    musig_keyagg_t *keyagg,
    const unsigned char *merkle_root  /* NULL for keypath-only */
);

/* --- Serialization sizes --- */
#define MUSIG_PUBNONCE_SERIALIZED_SIZE    66
#define MUSIG_PARTIAL_SIG_SERIALIZED_SIZE 32

/* --- Nonce pool (client-side pre-generation) --- */
#define MUSIG_NONCE_POOL_MAX 256

typedef struct {
    secp256k1_musig_secnonce secnonce;
    secp256k1_musig_pubnonce pubnonce;
} musig_nonce_pair_t;

typedef struct {
    musig_nonce_pair_t nonces[MUSIG_NONCE_POOL_MAX];
    size_t count;       /* total generated */
    size_t next_unused; /* index of next available */
} musig_nonce_pool_t;

/* --- Signing session (one per transaction being signed) --- */
#define MUSIG_SESSION_MAX_SIGNERS 16

typedef struct {
    secp256k1_musig_pubnonce pubnonces[MUSIG_SESSION_MAX_SIGNERS];
    secp256k1_musig_aggnonce aggnonce;
    secp256k1_musig_session session;
    secp256k1_musig_keyagg_cache cache;  /* working copy, potentially tweaked */
    secp256k1_xonly_pubkey agg_pubkey;   /* internal key (pre-tweak) */
    unsigned char msg32[32];
    size_t n_signers;
    int nonces_collected;                /* count of pubnonces received */
    int session_ready;                   /* nonce_process completed */
} musig_signing_session_t;

/* --- Nonce pool functions --- */

/* Generate a pool of N nonce pairs. Client calls this once at factory creation.
   seckey + pubkey: required (NONNULL by secp256k1 API).
   keyagg_cache: optional, pass for improved security if known.

   Pool size guide: n_nodes_participated * n_epochs.
   e.g., Client A in 4 nodes, 16 epochs -> pool of 64. */
int musig_nonce_pool_generate(
    const secp256k1_context *ctx,
    musig_nonce_pool_t *pool,
    size_t count,
    const unsigned char *seckey32,
    const secp256k1_pubkey *pubkey,
    const secp256k1_musig_keyagg_cache *keyagg_cache  /* optional, may be NULL */
);

/* Get next unused nonce pair. Returns pointers to secnonce (client keeps)
   and copies pubnonce to pubnonce_out (send to LSP). Returns 0 if exhausted. */
int musig_nonce_pool_next(
    musig_nonce_pool_t *pool,
    secp256k1_musig_secnonce **secnonce_out,
    secp256k1_musig_pubnonce *pubnonce_out
);

/* How many unused nonces remain */
size_t musig_nonce_pool_remaining(const musig_nonce_pool_t *pool);

/* --- Serialization (wire protocol) --- */

int musig_pubnonce_serialize(
    const secp256k1_context *ctx,
    unsigned char *out66,
    const secp256k1_musig_pubnonce *nonce
);

int musig_pubnonce_parse(
    const secp256k1_context *ctx,
    secp256k1_musig_pubnonce *nonce,
    const unsigned char *in66
);

int musig_partial_sig_serialize(
    const secp256k1_context *ctx,
    unsigned char *out32,
    const secp256k1_musig_partial_sig *sig
);

int musig_partial_sig_parse(
    const secp256k1_context *ctx,
    secp256k1_musig_partial_sig *sig,
    const unsigned char *in32
);

/* --- Split-round signing session --- */

/* Initialize a signing session with a keyagg result.
   Copies keyagg_cache internally (will be tweaked in finalize step). */
void musig_session_init(
    musig_signing_session_t *session,
    const musig_keyagg_t *keyagg,
    size_t n_signers
);

/* Add a signer's pubnonce. signer_index: 0..n_signers-1.
   Returns 1 on success, 0 on error. */
int musig_session_set_pubnonce(
    musig_signing_session_t *session,
    size_t signer_index,
    const secp256k1_musig_pubnonce *pubnonce
);

/* Finalize round 1: aggregate nonces, apply taproot tweak, create session.
   Must be called after all pubnonces are set.
   merkle_root: NULL for key-path-only, non-NULL for taproot script tree.
   adaptor: NULL normally. Non-NULL for adaptor signatures (PTLC key turnover).
   Applies taproot xonly tweak to session's keyagg cache copy. */
int musig_session_finalize_nonces(
    const secp256k1_context *ctx,
    musig_signing_session_t *session,
    const unsigned char *msg32,
    const unsigned char *merkle_root,
    const secp256k1_pubkey *adaptor       /* NULL for normal, non-NULL for PTLC */
);

/* Produce a partial signature. Uses secnonce (zeroed after -- single use!).
   keypair: this signer's keypair. */
int musig_create_partial_sig(
    const secp256k1_context *ctx,
    secp256k1_musig_partial_sig *partial_sig_out,
    secp256k1_musig_secnonce *secnonce,
    const secp256k1_keypair *keypair,
    const musig_signing_session_t *session
);

/* Verify one signer's partial sig. Optional but recommended.
   pubnonce: that signer's pubnonce (from set_pubnonce step).
   pubkey: that signer's pubkey (must match keyagg order). */
int musig_verify_partial_sig(
    const secp256k1_context *ctx,
    const secp256k1_musig_partial_sig *partial_sig,
    const secp256k1_musig_pubnonce *pubnonce,
    const secp256k1_pubkey *pubkey,
    const musig_signing_session_t *session
);

/* Aggregate all partial sigs into final 64-byte Schnorr signature. */
int musig_aggregate_partial_sigs(
    const secp256k1_context *ctx,
    unsigned char *sig64_out,
    const musig_signing_session_t *session,
    const secp256k1_musig_partial_sig *partial_sigs,
    size_t n_sigs
);

/* --- Convenience: ad-hoc single nonce generation (no pool) --- */

int musig_generate_nonce(
    const secp256k1_context *ctx,
    secp256k1_musig_secnonce *secnonce_out,
    secp256k1_musig_pubnonce *pubnonce_out,
    const unsigned char *seckey32,
    const secp256k1_pubkey *pubkey,
    const secp256k1_musig_keyagg_cache *keyagg_cache  /* optional */
);

#endif /* SUPERSCALAR_MUSIG_H */
