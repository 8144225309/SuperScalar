/*
 * htlc_accept.c — Final-hop HTLC acceptance validation
 *
 * Reference: BOLT #4 §accepting-htlcs-for-payment
 */

#include "superscalar/htlc_accept.h"
#include <string.h>
#include <stdint.h>

void htlc_accept_init(htlc_accept_table_t *tbl)
{
    if (!tbl) return;
    memset(tbl, 0, sizeof(*tbl));
}

int htlc_accept_add(htlc_accept_table_t *tbl,
                    const unsigned char payment_hash[32],
                    const unsigned char payment_secret[32],
                    uint64_t amount_msat,
                    uint32_t timestamp, uint32_t expiry)
{
    if (!tbl || !payment_hash) return 0;
    if (tbl->count >= HTLC_ACCEPT_TABLE_MAX) return 0;

    htlc_accept_invoice_t *e = &tbl->entries[tbl->count++];
    memcpy(e->payment_hash, payment_hash, 32);
    if (payment_secret) {
        memcpy(e->payment_secret, payment_secret, 32);
        e->has_payment_secret = 1;
    } else {
        memset(e->payment_secret, 0, 32);
        e->has_payment_secret = 0;
    }
    e->amount_msat = amount_msat;
    e->timestamp   = timestamp;
    e->expiry      = expiry;
    e->settled     = 0;
    return 1;
}

htlc_accept_invoice_t *htlc_accept_find(htlc_accept_table_t *tbl,
                                         const unsigned char payment_hash[32])
{
    if (!tbl || !payment_hash) return NULL;
    for (int i = 0; i < tbl->count; i++) {
        if (memcmp(tbl->entries[i].payment_hash, payment_hash, 32) == 0)
            return &tbl->entries[i];
    }
    return NULL;
}

int htlc_accept_check(htlc_accept_table_t *tbl,
                      const unsigned char payment_hash[32],
                      const unsigned char *payment_secret,
                      uint64_t htlc_amount_msat,
                      uint32_t htlc_cltv,
                      uint32_t chain_height,
                      uint32_t now_unix)
{
    if (!tbl || !payment_hash) return HTLC_ACCEPT_UNKNOWN_HASH;

    htlc_accept_invoice_t *e = htlc_accept_find(tbl, payment_hash);
    if (!e) return HTLC_ACCEPT_UNKNOWN_HASH;

    /* Already settled? */
    if (e->settled) return HTLC_ACCEPT_ALREADY_PAID;

    /* Expired? */
    if (e->expiry > 0 && now_unix >= e->timestamp + e->expiry)
        return HTLC_ACCEPT_EXPIRED;

    /* HTLC amount below invoice amount? (0 = any-amount invoice) */
    if (e->amount_msat > 0 && htlc_amount_msat < e->amount_msat)
        return HTLC_ACCEPT_AMOUNT_LOW;

    /* Payment secret check */
    if (e->has_payment_secret) {
        if (!payment_secret) return HTLC_ACCEPT_WRONG_SECRET;
        if (memcmp(payment_secret, e->payment_secret, 32) != 0)
            return HTLC_ACCEPT_WRONG_SECRET;
    }

    /* CLTV minimum check */
    if (chain_height > 0 &&
        htlc_cltv < chain_height + HTLC_ACCEPT_MIN_FINAL_CLTV)
        return HTLC_ACCEPT_CLTV_TOO_LOW;

    /* All checks passed — mark as settled */
    e->settled = 1;
    return HTLC_ACCEPT_OK;
}

int htlc_accept_prune(htlc_accept_table_t *tbl, uint32_t now_unix)
{
    if (!tbl) return 0;
    int removed = 0;
    int i = 0;
    while (i < tbl->count) {
        htlc_accept_invoice_t *e = &tbl->entries[i];
        int expired = (e->expiry > 0 && now_unix >= e->timestamp + e->expiry);
        if (expired || e->settled) {
            for (int j = i; j < tbl->count - 1; j++)
                tbl->entries[j] = tbl->entries[j + 1];
            tbl->count--;
            removed++;
        } else {
            i++;
        }
    }
    return removed;
}

const char *htlc_accept_result_str(int result)
{
    switch (result) {
    case HTLC_ACCEPT_OK:           return "ok";
    case HTLC_ACCEPT_UNKNOWN_HASH: return "unknown_payment_hash";
    case HTLC_ACCEPT_EXPIRED:      return "invoice_expired";
    case HTLC_ACCEPT_AMOUNT_LOW:   return "amount_below_minimum";
    case HTLC_ACCEPT_WRONG_SECRET: return "wrong_payment_secret";
    case HTLC_ACCEPT_ALREADY_PAID: return "already_paid";
    case HTLC_ACCEPT_CLTV_TOO_LOW: return "cltv_expiry_too_low";
    default:                        return "unknown_error";
    }
}
