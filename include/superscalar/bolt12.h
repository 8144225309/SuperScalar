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
 * offer_t   : static reusable payment code (bech32m `lno1...` string).
 * invoice_request_t: payer → offer; Schnorr-signed TLV.
 * invoice_t : LSP → payer; adds payment_hash, signed by offer's node_id.
 */

#define BOLT12_OFFER_MAX_DESC  256

typedef struct {
    unsigned char node_id[33];     /* 33-byte compressed pubkey of issuer */
    uint64_t      amount_msat;     /* 0 = any amount */
    char          description[BOLT12_OFFER_MAX_DESC];
    unsigned char signing_key[32]; /* private key for offer signing (local only) */
    int           has_amount;      /* 1 if amount_msat is set */
} offer_t;

typedef struct {
    unsigned char offer_id[32];    /* SHA256 of offer TLV */
    uint64_t      amount_msat;
    unsigned char payer_key[33];   /* payer node_id */
    unsigned char sig[64];         /* Schnorr signature over TLV fields */
} invoice_request_t;

typedef struct {
    unsigned char payment_hash[32];
    unsigned char payment_secret[32];
    uint64_t      amount_msat;
    unsigned char node_sig[64];    /* signature by offer node_id */
    unsigned char offer_id[32];
} invoice_t;

/*
 * Encode an offer_t to a bech32m string (`lno1...`).
 * out: buffer of at least 512 bytes.
 * Returns 1 on success, 0 on error.
 */
int offer_encode(const offer_t *o, char *out, size_t out_cap);

/*
 * Decode a `lno1...` bech32m string to an offer_t.
 * Returns 1 on success, 0 on error.
 */
int offer_decode(const char *bech32m, offer_t *o_out);

/*
 * Sign an invoice_request with the payer's key.
 * ctx: secp256k1 context with SIGN capability.
 * seckey: 32-byte payer private key.
 * Returns 1 on success.
 */
int invoice_request_sign(invoice_request_t *req, secp256k1_context *ctx,
                          const unsigned char *seckey32);

/*
 * Verify an invoice_request signature against payer_key.
 * Returns 1 if valid.
 */
int invoice_request_verify(const invoice_request_t *req, secp256k1_context *ctx);

/*
 * Sign an invoice_t with the offer's node signing key.
 * Returns 1 on success.
 */
int invoice_sign(invoice_t *inv, secp256k1_context *ctx,
                  const unsigned char *node_seckey32);

/*
 * Verify an invoice_t signature against the given node_id.
 * Returns 1 if valid.
 */
int invoice_verify(const invoice_t *inv, secp256k1_context *ctx,
                    const unsigned char *node_id33);

#endif /* SUPERSCALAR_BOLT12_H */
