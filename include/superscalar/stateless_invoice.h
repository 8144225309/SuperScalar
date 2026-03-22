#ifndef SUPERSCALAR_STATELESS_INVOICE_H
#define SUPERSCALAR_STATELESS_INVOICE_H

/*
 * stateless_invoice.h — HMAC-derived payment secrets for scalable invoicing
 *
 * Stateless invoices eliminate the in-memory invoice table for payment_secret
 * verification.  The payment_secret is derived deterministically from the
 * node secret key and payment_hash using HMAC-SHA256, so verification
 * requires only the node key — not a table lookup.
 *
 * Two-level statelessness:
 *   Level 1 (secret only): node derives payment_secret from (key, payment_hash).
 *     The payment_hash and preimage are generated normally; only the secret
 *     verification is stateless.  This is LDK's create_inbound_payment_for_hash().
 *
 *   Level 2 (fully stateless): node derives BOTH preimage AND secret from
 *     (key, invoice_nonce).  The nonce is a 32-byte random value embedded in
 *     the invoice as payment_metadata (BOLT #11 tagged field 'd').  When the
 *     payer presents the HTLC, the nonce is returned in the onion TLV, allowing
 *     the node to re-derive the preimage without storing it.
 *
 * Reference:
 *   LDK: lightning/src/ln/inbound_payment.rs create_inbound_payment_for_hash()
 *   CLN: lightningd/invoice.c stateless invoice support
 *   LND: invoicesrpc/addinvoice.go (s-value commitment)
 *   BOLT #11: §tagged-fields, field 'd' (payment_metadata)
 */

#include <stdint.h>
#include <stddef.h>

/* -----------------------------------------------------------------------
 * Derivation domain separators (HMAC labels)
 * --------------------------------------------------------------------- */
#define STATELESS_LABEL_SECRET    "stateless:payment_secret"
#define STATELESS_LABEL_PREIMAGE  "stateless:preimage"

/* -----------------------------------------------------------------------
 * Level 1: Stateless payment_secret derivation
 * --------------------------------------------------------------------- */

/*
 * Derive a payment_secret from a node key and payment_hash.
 *
 *   secret = HMAC-SHA256(node_key, "stateless:payment_secret" || payment_hash)
 *
 * The result is a 32-byte secret to include in the BOLT #11 invoice.
 * When an HTLC arrives, call stateless_invoice_verify_secret() to confirm
 * the payer presented the correct secret — no table lookup required.
 */
void stateless_invoice_derive_secret(const unsigned char node_key[32],
                                      const unsigned char payment_hash[32],
                                      unsigned char       secret_out[32]);

/*
 * Verify a presented payment_secret against the derived expected value.
 * Returns 1 if the presented secret is correct, 0 otherwise.
 *
 * Uses a constant-time comparison to prevent timing attacks.
 */
int stateless_invoice_verify_secret(const unsigned char node_key[32],
                                     const unsigned char payment_hash[32],
                                     const unsigned char presented_secret[32]);

/* -----------------------------------------------------------------------
 * Level 2: Fully stateless (preimage + secret from nonce)
 * --------------------------------------------------------------------- */

/*
 * Generate a fully-stateless invoice nonce (32-byte random value).
 * Returns 1 on success, 0 on /dev/urandom failure.
 */
int stateless_invoice_gen_nonce(unsigned char nonce_out[32]);

/*
 * Derive the payment_preimage from a node key and nonce.
 *
 *   preimage = HMAC-SHA256(node_key, "stateless:preimage" || nonce)
 *
 * The nonce must be stored in the invoice as payment_metadata (tagged
 * field 'd' in BOLT #11) so it is returned with each HTLC.
 */
void stateless_invoice_derive_preimage(const unsigned char node_key[32],
                                        const unsigned char nonce[32],
                                        unsigned char       preimage_out[32]);

/*
 * Convenience: derive both preimage and secret from a nonce.
 *
 *   preimage = HMAC-SHA256(node_key, "stateless:preimage" || nonce)
 *   payment_hash = SHA256(preimage)
 *   secret = HMAC-SHA256(node_key, "stateless:payment_secret" || payment_hash)
 *
 * Returns 1 on success, 0 on error.
 */
int stateless_invoice_from_nonce(const unsigned char node_key[32],
                                  const unsigned char nonce[32],
                                  unsigned char payment_hash_out[32],
                                  unsigned char preimage_out[32],
                                  unsigned char secret_out[32]);

/*
 * Claim a fully-stateless invoice payment.
 *
 * Given the node key, the nonce recovered from payment_metadata, and the
 * payment_hash from the HTLC, verifies that the payment_hash matches
 * SHA256(derive_preimage(key, nonce)) and the presented_secret matches
 * derive_secret(key, payment_hash).
 *
 * On success (returns 1), writes the preimage to preimage_out.
 * On failure (returns 0), preimage_out is zeroed.
 *
 * payment_hash:      32-byte hash from the incoming HTLC
 * nonce:             32-byte nonce from payment_metadata TLV
 * presented_secret:  32-byte payment_secret from the HTLC onion TLV type 8
 */
int stateless_invoice_claim(const unsigned char node_key[32],
                             const unsigned char nonce[32],
                             const unsigned char payment_hash[32],
                             const unsigned char presented_secret[32],
                             unsigned char       preimage_out[32]);

/* -----------------------------------------------------------------------
 * Utilities
 * --------------------------------------------------------------------- */

/*
 * Verify that a preimage reveals the payment_hash.
 * Returns 1 if SHA256(preimage) == payment_hash, 0 otherwise.
 */
int stateless_invoice_check_preimage(const unsigned char payment_hash[32],
                                      const unsigned char preimage[32]);

/*
 * Generate a new random Level-1 invoice:
 *   1. Generate 32 random bytes → preimage
 *   2. payment_hash = SHA256(preimage)
 *   3. secret = derive_secret(node_key, payment_hash)
 *
 * Returns 1 on success, 0 on /dev/urandom failure.
 */
int stateless_invoice_generate_l1(const unsigned char node_key[32],
                                   unsigned char preimage_out[32],
                                   unsigned char payment_hash_out[32],
                                   unsigned char secret_out[32]);

#endif /* SUPERSCALAR_STATELESS_INVOICE_H */
