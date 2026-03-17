#ifndef SUPERSCALAR_BOLT12_H
#define SUPERSCALAR_BOLT12_H

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

/*
 * BOLT 12 / Offers implementation.
 *
 * offer_t         : static reusable payment code (bech32m `lno1...` string).
 * invoice_request_t: payer → offer; Schnorr-signed TLV.
 * invoice_t        : LSP → payer; adds payment_hash, signed by offer's node_id.
 * invoice_error_t  : node → payer; rejection reason.
 *
 * Phase 5 additions:
 *   - Offer expiry (absolute_expiry TLV)
 *   - Blinded paths in invoices (for privacy)
 *   - Recurrence fields (subscription offers)
 *   - invoice_error on rejected invoice_request
 */

#define BOLT12_OFFER_MAX_DESC  256
#define BOLT12_MAX_BLINDED_HOPS 8

/* Blinded path hop */
typedef struct {
    unsigned char blinded_node_id[33];
    unsigned char encrypted_recipient_data[64];
    size_t        encrypted_data_len;
} bolt12_blinded_hop_t;

/* Blinded path */
typedef struct {
    unsigned char       first_node_id[33];  /* unblinded introduction point */
    unsigned char       blinding_point[33]; /* ephemeral blinding pubkey */
    bolt12_blinded_hop_t hops[BOLT12_MAX_BLINDED_HOPS];
    int                 n_hops;
} bolt12_blinded_path_t;

/* Recurrence period */
typedef struct {
    uint32_t time_unit;  /* 0=seconds, 1=days, 2=months, 3=years */
    uint32_t period;     /* number of time_units per recurrence */
} bolt12_recurrence_t;

typedef struct {
    unsigned char node_id[33];     /* 33-byte compressed pubkey of issuer */
    uint64_t      amount_msat;     /* 0 = any amount */
    char          description[BOLT12_OFFER_MAX_DESC];
    unsigned char signing_key[32]; /* private key for offer signing (local only) */
    int           has_amount;      /* 1 if amount_msat is set */
    /* Phase 5 additions */
    uint64_t      absolute_expiry; /* Unix timestamp; 0 = no expiry */
    int           has_expiry;
    bolt12_recurrence_t recurrence;
    int           has_recurrence;
    bolt12_blinded_path_t paths[4]; /* blinded paths for privacy */
    int           n_paths;
} offer_t;

typedef struct {
    unsigned char offer_id[32];    /* SHA256 of offer TLV */
    uint64_t      amount_msat;
    unsigned char payer_key[33];   /* payer node_id */
    unsigned char sig[64];         /* Schnorr signature over TLV fields */
    /* Recurrence fields */
    uint32_t      recurrence_counter; /* 0-based recurrence period */
    int           has_recurrence_counter;
} invoice_request_t;

typedef struct {
    unsigned char payment_hash[32];
    unsigned char payment_secret[32];
    uint64_t      amount_msat;
    unsigned char node_sig[64];    /* signature by offer node_id */
    unsigned char offer_id[32];
    /* Phase 5 additions */
    bolt12_blinded_path_t paths[4]; /* blinded route hints */
    int           n_paths;
    uint32_t      relative_expiry;  /* seconds from creation */
    int           has_relative_expiry;
    uint32_t      recurrence_basetime;
    int           has_recurrence;
} invoice_t;

/* invoice_error: sent back to payer when invoice_request is rejected */
typedef struct {
    unsigned char invoice_request[512]; /* echo of the invoice_request TLV */
    size_t        invoice_request_len;
    char          error[256];           /* human-readable error description */
    uint32_t      erroneous_field;      /* TLV type that caused the error, or 0 */
} invoice_error_t;

/* Encode an offer_t to a bech32m string (`lno1...`).
   Returns 1 on success, 0 on error. */
int offer_encode(const offer_t *o, char *out, size_t out_cap);

/* Decode a `lno1...` bech32m string to an offer_t.
   Returns 1 on success, 0 on error. */
int offer_decode(const char *bech32m, offer_t *o_out);

/* Sign an invoice_request with the payer's key.
   Returns 1 on success. */
int invoice_request_sign(invoice_request_t *req, secp256k1_context *ctx,
                          const unsigned char *seckey32);

/* Verify an invoice_request signature against payer_key.
   Returns 1 if valid. */
int invoice_request_verify(const invoice_request_t *req, secp256k1_context *ctx);

/* Sign an invoice_t with the offer's node signing key.
   Returns 1 on success. */
int invoice_sign(invoice_t *inv, secp256k1_context *ctx,
                  const unsigned char *node_seckey32);

/* Verify an invoice_t signature against the given node_id.
   Returns 1 if valid. */
int invoice_verify(const invoice_t *inv, secp256k1_context *ctx,
                    const unsigned char *node_id33);

/*
 * Build an invoice in response to an invoice_request.
 * Fills inv_out with payment_hash, payment_secret, amount, signature.
 * node_seckey32: signing key.
 * Returns 1 on success.
 */
int invoice_from_request(const invoice_request_t *req,
                          secp256k1_context *ctx,
                          const unsigned char node_seckey32[32],
                          const unsigned char payment_hash[32],
                          const unsigned char payment_secret[32],
                          invoice_t *inv_out);

/*
 * Build an invoice_error response.
 * error_msg: human-readable reason.
 * erroneous_field: TLV type that caused the error (0 if unknown).
 * Returns 1 on success.
 */
int invoice_error_build(const unsigned char *invoice_request_tlv,
                         size_t inv_req_len,
                         const char *error_msg,
                         uint32_t erroneous_field,
                         invoice_error_t *err_out);

/*
 * Check if an offer has expired.
 * now_unix: current Unix timestamp.
 * Returns 1 if expired, 0 if still valid.
 */
int offer_is_expired(const offer_t *o, uint64_t now_unix);

#endif /* SUPERSCALAR_BOLT12_H */
