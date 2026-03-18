#ifndef SUPERSCALAR_INVOICE_H
#define SUPERSCALAR_INVOICE_H

/*
 * invoice.h — BOLT #11 inbound payment invoice management
 *
 * Generates payment_hash/secret pairs, tracks pending invoices,
 * and redeems them when the final HTLC arrives.
 *
 * Reference: CLN lightningd/invoices.c, LND invoices/invoiceregistry.go,
 *            LDK lightning/src/ln/channelmanager.rs (create_inbound_payment)
 */

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>

#define INVOICE_TABLE_MAX  64

typedef struct {
    unsigned char payment_hash[32];
    unsigned char preimage[32];
    unsigned char payment_secret[32];
    uint64_t      amount_msat;       /* 0 = any amount */
    uint32_t      created_at;        /* Unix timestamp */
    uint32_t      expiry;            /* seconds from created_at; default 3600 */
    char          description[256];
    int           settled;           /* 1 = already claimed */
    int           active;            /* 1 = slot in use */
} bolt11_invoice_entry_t;

typedef struct {
    bolt11_invoice_entry_t entries[INVOICE_TABLE_MAX];
    int             count;           /* number of active entries */
} bolt11_invoice_table_t;

/*
 * Initialise an empty invoice table.
 */
void invoice_init(bolt11_invoice_table_t *tbl);

/*
 * Generate a new invoice and encode it as a BOLT #11 bech32 string.
 *
 * Internally:
 *   1. getrandom(preimage, 32)
 *   2. payment_hash = SHA256(preimage)
 *   3. getrandom(payment_secret, 32)
 *   4. Populate bolt11_invoice_t, call bolt11_encode()
 *
 * amount_msat: 0 = any amount (amountless invoice)
 * expiry_secs: 0 = use default (3600 s)
 * bech32_out:  caller-supplied buffer for the encoded invoice string
 * out_cap:     size of bech32_out (>= 512 bytes recommended)
 *
 * Returns 1 on success, 0 on error.
 */
int invoice_create(bolt11_invoice_table_t *tbl,
                   secp256k1_context *ctx,
                   const unsigned char node_privkey[32],
                   const char *network,
                   uint64_t amount_msat,
                   const char *description,
                   uint32_t expiry_secs,
                   char *bech32_out, size_t out_cap);

/*
 * Redeem a pending invoice when the final HTLC arrives.
 *
 * Looks up the invoice by payment_hash, validates:
 *   - Invoice exists and is not yet settled
 *   - Invoice has not expired (created_at + expiry < now)
 *   - amount_msat >= invoice->amount_msat (unless invoice->amount_msat == 0)
 *
 * On success: copies preimage to preimage_out and returns 1.
 * On failure (not found, expired, underpaid, double-claim): returns 0.
 */
int invoice_claim(bolt11_invoice_table_t *tbl,
                  const unsigned char payment_hash[32],
                  uint64_t amount_msat,
                  unsigned char preimage_out[32]);

/*
 * Mark an invoice as settled after update_fulfill_htlc has been sent.
 * No-op if payment_hash not found.
 */
void invoice_settle(bolt11_invoice_table_t *tbl, const unsigned char payment_hash[32]);

#endif /* SUPERSCALAR_INVOICE_H */
