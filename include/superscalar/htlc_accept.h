#ifndef SUPERSCALAR_HTLC_ACCEPT_H
#define SUPERSCALAR_HTLC_ACCEPT_H

/*
 * htlc_accept.h — Final-hop HTLC acceptance validation
 *
 * Validates an incoming HTLC at the final hop against the invoice table:
 *   1. Payment hash matches a known invoice
 *   2. Invoice is not expired (timestamp + expiry > now)
 *   3. HTLC amount >= invoice amount (or invoice is any-amount)
 *   4. Payment secret matches (if invoice has one)
 *   5. Invoice not already settled (prevents double-payment)
 *
 * Called by the HTLC forwarding engine when is_final=1, before settling.
 *
 * Reference:
 *   BOLT #4 §accepting-htlcs-for-payment
 *   LDK: ChannelManager::process_pending_htlc_forwards (receive.rs)
 *   CLN: channeld.c invoice_check_payment()
 *   LND: invoices.go InvoiceRegistry.NotifyExitHopHtlc()
 */

#include <stdint.h>
#include <stddef.h>

/* Result codes */
#define HTLC_ACCEPT_OK              0   /* accept: valid, settle */
#define HTLC_ACCEPT_UNKNOWN_HASH    1   /* no invoice for this payment_hash */
#define HTLC_ACCEPT_EXPIRED         2   /* invoice expired */
#define HTLC_ACCEPT_AMOUNT_LOW      3   /* HTLC amount below invoice amount */
#define HTLC_ACCEPT_WRONG_SECRET    4   /* payment_secret mismatch */
#define HTLC_ACCEPT_ALREADY_PAID    5   /* invoice already settled */
#define HTLC_ACCEPT_CLTV_TOO_LOW    6   /* CLTV expiry below min_final_cltv */

/* Minimum CLTV delta required at final hop (BOLT #11 tagged field 'c') */
#define HTLC_ACCEPT_MIN_FINAL_CLTV  18

/* A minimal invoice record for validation */
typedef struct {
    unsigned char payment_hash[32];
    unsigned char payment_secret[32];
    uint64_t      amount_msat;          /* 0 = any amount */
    uint32_t      timestamp;            /* creation timestamp */
    uint32_t      expiry;               /* seconds; default 3600 */
    int           has_payment_secret;   /* 1 if payment_secret is required */
    int           settled;              /* 1 if already paid */
} htlc_accept_invoice_t;

#define HTLC_ACCEPT_TABLE_MAX  256

typedef struct {
    htlc_accept_invoice_t entries[HTLC_ACCEPT_TABLE_MAX];
    int count;
} htlc_accept_table_t;

/* Initialise an empty invoice table. */
void htlc_accept_init(htlc_accept_table_t *tbl);

/* Add an invoice to the table. Returns 1 on success, 0 if table full. */
int htlc_accept_add(htlc_accept_table_t *tbl,
                    const unsigned char payment_hash[32],
                    const unsigned char payment_secret[32],  /* may be NULL */
                    uint64_t amount_msat,
                    uint32_t timestamp, uint32_t expiry);

/*
 * Validate an incoming final-hop HTLC.
 *
 * payment_hash:    32-byte payment hash from HTLC.
 * payment_secret:  32-byte payment secret from onion TLV type 8 (may be NULL).
 * htlc_amount_msat: amount arriving on the HTLC.
 * htlc_cltv:       absolute CLTV expiry of the HTLC.
 * chain_height:    current best block height.
 * now_unix:        current Unix timestamp.
 *
 * Returns HTLC_ACCEPT_OK, or an error code.
 * On HTLC_ACCEPT_OK, marks the invoice as settled.
 */
int htlc_accept_check(htlc_accept_table_t *tbl,
                      const unsigned char payment_hash[32],
                      const unsigned char *payment_secret,
                      uint64_t htlc_amount_msat,
                      uint32_t htlc_cltv,
                      uint32_t chain_height,
                      uint32_t now_unix);

/*
 * Find an invoice by payment_hash.
 * Returns pointer to the entry, or NULL if not found.
 */
htlc_accept_invoice_t *htlc_accept_find(htlc_accept_table_t *tbl,
                                         const unsigned char payment_hash[32]);

/*
 * Remove all expired and settled invoices older than cutoff_unix.
 * Returns count removed.
 */
int htlc_accept_prune(htlc_accept_table_t *tbl, uint32_t now_unix);

/*
 * Human-readable result description (for logging).
 */
const char *htlc_accept_result_str(int result);

#endif /* SUPERSCALAR_HTLC_ACCEPT_H */
