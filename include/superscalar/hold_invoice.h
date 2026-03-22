#ifndef SUPERSCALAR_HOLD_INVOICE_H
#define SUPERSCALAR_HOLD_INVOICE_H

/*
 * hold_invoice.h — BOLT #11 hold invoices for async payment delivery.
 *
 * Hold invoices allow an LSP to accept an HTLC on behalf of an offline
 * payee and hold it until the payee comes online to reveal the preimage.
 *
 * States:
 *   HOLD_INVOICE_PENDING   — invoice created, no HTLC yet
 *   HOLD_INVOICE_ACCEPTED  — matching HTLC arrived, held at LSP
 *   HOLD_INVOICE_SETTLED   — preimage revealed, HTLC can be fulfilled
 *   HOLD_INVOICE_CANCELLED — invoice cancelled or payment timed out
 *
 * Reference:
 *   LND: lnrpc.HoldInvoice, invoices/invoiceregistry.go
 *   CLN: hold invoice plugin (ElementsProject/lightning plugins/holdinvoice)
 *   LDK: InterceptedHTLC + ChannelManager::get_intercept_scid()
 *   LSPS2: bLIP-52 JIT channel hold flow
 */

#include <stdint.h>
#include <stddef.h>

#define HOLD_INVOICE_TABLE_MAX  32

#define HOLD_INVOICE_PENDING    0  /* created, waiting for HTLC */
#define HOLD_INVOICE_ACCEPTED   1  /* HTLC arrived and held */
#define HOLD_INVOICE_SETTLED    2  /* preimage revealed */
#define HOLD_INVOICE_CANCELLED  3  /* cancelled or expired */

typedef struct {
    unsigned char payment_hash[32];   /* SHA256(preimage) */
    unsigned char payment_secret[32]; /* BOLT #11 payment_secret */
    unsigned char preimage[32];       /* only set on settle */
    uint64_t      amount_msat;        /* 0 = any amount */
    uint64_t      htlc_amount_msat;   /* amount from accepted HTLC */
    uint64_t      htlc_id;            /* HTLC ID from peer */
    int           peer_idx;           /* peer that sent the HTLC */
    uint32_t      created_at;         /* Unix timestamp */
    uint32_t      expiry;             /* seconds from created_at */
    int           state;              /* HOLD_INVOICE_* */
    int           active;             /* 1 = slot in use */
    char          description[256];
} hold_invoice_entry_t;

typedef struct {
    hold_invoice_entry_t entries[HOLD_INVOICE_TABLE_MAX];
    int count;  /* active slots */
} hold_invoice_table_t;

/* ---- Lifecycle ---- */

/*
 * Initialise an empty hold invoice table.
 */
void hold_invoice_init(hold_invoice_table_t *tbl);

/*
 * Create a hold invoice. Unlike regular invoices, the preimage is NOT
 * stored here — the caller (payee) controls resolution.
 *
 * payment_hash: 32-byte SHA256 of the preimage (caller provides)
 * payment_secret: 32-byte random secret for BOLT #11 (caller provides)
 * amount_msat: 0 = any amount
 * expiry_secs: 0 = default (3600 s)
 *
 * Returns 1 on success, 0 if table full or null args.
 */
int hold_invoice_add(hold_invoice_table_t *tbl,
                     const unsigned char payment_hash[32],
                     const unsigned char payment_secret[32],
                     uint64_t amount_msat,
                     uint32_t expiry_secs,
                     const char *description);

/*
 * Mark an HTLC as accepted for a hold invoice.
 * Called when update_add_htlc arrives with a matching payment_hash.
 *
 * Must be in HOLD_INVOICE_PENDING state.
 * Returns 1 on success, 0 if not found/wrong state/wrong amount.
 */
int hold_invoice_on_htlc(hold_invoice_table_t *tbl,
                          const unsigned char payment_hash[32],
                          uint64_t htlc_amount_msat,
                          uint64_t htlc_id,
                          int peer_idx);

/*
 * Settle a hold invoice: caller provides the preimage.
 * Transitions ACCEPTED → SETTLED.
 * Returns 1 if settlement is valid (hash matches + state=ACCEPTED).
 * Returns 0 on wrong state, wrong preimage, or not found.
 *
 * After returning 1, the caller must send update_fulfill_htlc to the peer.
 */
int hold_invoice_settle(hold_invoice_table_t *tbl,
                         const unsigned char payment_hash[32],
                         const unsigned char preimage[32]);

/*
 * Cancel a hold invoice.
 * Transitions PENDING or ACCEPTED → CANCELLED.
 * Returns 1 on success, 0 if already settled or not found.
 *
 * After returning 1 for ACCEPTED state, caller must send update_fail_htlc.
 */
int hold_invoice_cancel(hold_invoice_table_t *tbl,
                         const unsigned char payment_hash[32]);

/*
 * Look up a hold invoice by payment_hash.
 * Returns pointer into tbl (valid until next tbl modification), or NULL.
 */
hold_invoice_entry_t *hold_invoice_find(hold_invoice_table_t *tbl,
                                         const unsigned char payment_hash[32]);

/*
 * Remove a settled or cancelled invoice to free its slot.
 * No-op if not found or still pending/accepted.
 */
void hold_invoice_remove(hold_invoice_table_t *tbl,
                          const unsigned char payment_hash[32]);

/*
 * Return number of invoices in each state.
 */
int hold_invoice_count_by_state(const hold_invoice_table_t *tbl, int state);

#endif /* SUPERSCALAR_HOLD_INVOICE_H */
