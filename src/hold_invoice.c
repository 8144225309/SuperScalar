/*
 * hold_invoice.c — Hold invoice management for async HTLC delivery.
 *
 * Reference: LND invoices/invoiceregistry.go, CLN holdinvoice plugin,
 *            LDK InterceptedHTLC, bLIP-52 LSPS2 JIT hold flow
 */

#include "superscalar/hold_invoice.h"
#include <string.h>
#include <stdint.h>

/* ---- SHA256 helper for preimage validation ---- */

/* Simple single-block SHA256 for 32-byte preimage.
 * We need SHA256(preimage) == payment_hash to settle. */
#ifndef SUPERSCALAR_SHA256_H
/* Use a minimal portable SHA256 for the settle check.
 * In a real build, link against libsecp256k1 or OpenSSL. */
#include <openssl/sha.h>
static void sha256_preimage(const unsigned char *in, unsigned char *out)
{
    SHA256(in, 32, out);
}
#endif

void hold_invoice_init(hold_invoice_table_t *tbl)
{
    if (!tbl) return;
    memset(tbl, 0, sizeof(*tbl));
}

int hold_invoice_add(hold_invoice_table_t *tbl,
                     const unsigned char payment_hash[32],
                     const unsigned char payment_secret[32],
                     uint64_t amount_msat,
                     uint32_t expiry_secs,
                     const char *description)
{
    if (!tbl || !payment_hash || !payment_secret) return 0;

    /* Find free slot */
    int slot = -1;
    for (int i = 0; i < HOLD_INVOICE_TABLE_MAX; i++) {
        if (!tbl->entries[i].active) { slot = i; break; }
    }
    if (slot < 0) return 0;

    hold_invoice_entry_t *e = &tbl->entries[slot];
    memset(e, 0, sizeof(*e));
    memcpy(e->payment_hash, payment_hash, 32);
    memcpy(e->payment_secret, payment_secret, 32);
    e->amount_msat = amount_msat;
    e->expiry      = expiry_secs ? expiry_secs : 3600;
    e->state       = HOLD_INVOICE_PENDING;
    e->active      = 1;
    e->peer_idx    = -1;
    if (description) {
        strncpy(e->description, description,
                sizeof(e->description) - 1);
    }
    tbl->count++;
    return 1;
}

hold_invoice_entry_t *hold_invoice_find(hold_invoice_table_t *tbl,
                                         const unsigned char payment_hash[32])
{
    if (!tbl || !payment_hash) return NULL;
    for (int i = 0; i < HOLD_INVOICE_TABLE_MAX; i++) {
        if (tbl->entries[i].active &&
            memcmp(tbl->entries[i].payment_hash, payment_hash, 32) == 0)
            return &tbl->entries[i];
    }
    return NULL;
}

int hold_invoice_on_htlc(hold_invoice_table_t *tbl,
                          const unsigned char payment_hash[32],
                          uint64_t htlc_amount_msat,
                          uint64_t htlc_id,
                          int peer_idx)
{
    if (!tbl || !payment_hash) return 0;
    hold_invoice_entry_t *e = hold_invoice_find(tbl, payment_hash);
    if (!e) return 0;
    if (e->state != HOLD_INVOICE_PENDING) return 0;
    /* Validate amount: must be >= invoice amount (unless 0 = any) */
    if (e->amount_msat > 0 && htlc_amount_msat < e->amount_msat) return 0;

    e->htlc_amount_msat = htlc_amount_msat;
    e->htlc_id          = htlc_id;
    e->peer_idx         = peer_idx;
    e->state            = HOLD_INVOICE_ACCEPTED;
    return 1;
}

int hold_invoice_settle(hold_invoice_table_t *tbl,
                         const unsigned char payment_hash[32],
                         const unsigned char preimage[32])
{
    if (!tbl || !payment_hash || !preimage) return 0;
    hold_invoice_entry_t *e = hold_invoice_find(tbl, payment_hash);
    if (!e) return 0;
    if (e->state != HOLD_INVOICE_ACCEPTED) return 0;

    /* Verify SHA256(preimage) == payment_hash */
    unsigned char computed[32];
    sha256_preimage(preimage, computed);
    if (memcmp(computed, payment_hash, 32) != 0) return 0;

    memcpy(e->preimage, preimage, 32);
    e->state = HOLD_INVOICE_SETTLED;
    return 1;
}

int hold_invoice_cancel(hold_invoice_table_t *tbl,
                         const unsigned char payment_hash[32])
{
    if (!tbl || !payment_hash) return 0;
    hold_invoice_entry_t *e = hold_invoice_find(tbl, payment_hash);
    if (!e) return 0;
    if (e->state == HOLD_INVOICE_SETTLED) return 0;
    if (e->state == HOLD_INVOICE_CANCELLED) return 0;

    e->state = HOLD_INVOICE_CANCELLED;
    return 1;
}

void hold_invoice_remove(hold_invoice_table_t *tbl,
                          const unsigned char payment_hash[32])
{
    if (!tbl || !payment_hash) return;
    for (int i = 0; i < HOLD_INVOICE_TABLE_MAX; i++) {
        hold_invoice_entry_t *e = &tbl->entries[i];
        if (!e->active) continue;
        if (memcmp(e->payment_hash, payment_hash, 32) != 0) continue;
        if (e->state == HOLD_INVOICE_SETTLED ||
            e->state == HOLD_INVOICE_CANCELLED) {
            memset(e, 0, sizeof(*e));
            tbl->count--;
        }
        return;
    }
}

int hold_invoice_count_by_state(const hold_invoice_table_t *tbl, int state)
{
    if (!tbl) return 0;
    int count = 0;
    for (int i = 0; i < HOLD_INVOICE_TABLE_MAX; i++) {
        if (tbl->entries[i].active && tbl->entries[i].state == state)
            count++;
    }
    return count;
}
