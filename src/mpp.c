/*
 * mpp.c — Multi-path payment aggregation
 */

#include "superscalar/mpp.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

void mpp_init(mpp_table_t *tbl) {
    if (tbl) memset(tbl, 0, sizeof(*tbl));
}

/* Return active entry for payment_secret, or NULL if not found. */
static mpp_payment_t *mpp_find(mpp_table_t *tbl,
                                 const unsigned char payment_secret[32]) {
    for (int i = 0; i < MPP_MAX_PAYMENTS; i++) {
        if (tbl->entries[i].active &&
            memcmp(tbl->entries[i].payment_secret, payment_secret, 32) == 0)
            return &tbl->entries[i];
    }
    return NULL;
}

/* Allocate a new entry, or return NULL if table full. */
static mpp_payment_t *mpp_alloc(mpp_table_t *tbl) {
    for (int i = 0; i < MPP_MAX_PAYMENTS; i++) {
        if (!tbl->entries[i].active)
            return &tbl->entries[i];
    }
    return NULL;
}

int mpp_add_part(mpp_table_t *tbl,
                 const unsigned char payment_secret[32],
                 uint64_t htlc_id, uint64_t amount_msat,
                 uint64_t total_msat, uint32_t cltv_expiry) {
    if (!tbl || !payment_secret) return -1;

    mpp_payment_t *entry = mpp_find(tbl, payment_secret);

    if (!entry) {
        entry = mpp_alloc(tbl);
        if (!entry) return -1;
        memset(entry, 0, sizeof(*entry));
        memcpy(entry->payment_secret, payment_secret, 32);
        entry->total_msat          = total_msat;
        entry->first_received_unix = (uint32_t)time(NULL);
        entry->active              = 1;
        tbl->count++;
    }

    if (entry->n_parts >= MPP_MAX_PARTS) return -1;

    /* Overpayment guard: collected + this part > 2 * total → fail */
    if (entry->collected_msat + amount_msat > 2 * entry->total_msat) return -1;

    entry->parts[entry->n_parts].htlc_id     = htlc_id;
    entry->parts[entry->n_parts].amount_msat = amount_msat;
    entry->parts[entry->n_parts].cltv_expiry = cltv_expiry;
    entry->n_parts++;
    entry->collected_msat += amount_msat;

    return (entry->collected_msat >= entry->total_msat) ? 1 : 0;
}

int mpp_check_timeouts(mpp_table_t *tbl, uint32_t now_unix,
                       uint64_t *failed_htlc_ids_out, int max_out) {
    if (!tbl) return 0;

    int written = 0;
    for (int i = 0; i < MPP_MAX_PAYMENTS; i++) {
        mpp_payment_t *e = &tbl->entries[i];
        if (!e->active) continue;
        if (e->first_received_unix + MPP_TIMEOUT_SECS > now_unix) continue;

        /* Timed out — collect all htlc_ids for failing */
        for (int j = 0; j < e->n_parts && written < max_out; j++) {
            if (failed_htlc_ids_out)
                failed_htlc_ids_out[written] = e->parts[j].htlc_id;
            written++;
        }
        memset(e, 0, sizeof(*e));
        tbl->count--;
    }
    return written;
}

int mpp_get_parts(mpp_table_t *tbl, const unsigned char payment_secret[32],
                  uint64_t *htlc_ids_out, int max_out) {
    if (!tbl || !payment_secret) return 0;

    mpp_payment_t *e = mpp_find(tbl, payment_secret);
    if (!e) return 0;

    int written = 0;
    for (int j = 0; j < e->n_parts && written < max_out; j++) {
        if (htlc_ids_out)
            htlc_ids_out[written] = e->parts[j].htlc_id;
        written++;
    }
    return written;
}

void mpp_remove(mpp_table_t *tbl, const unsigned char payment_secret[32]) {
    if (!tbl || !payment_secret) return;

    for (int i = 0; i < MPP_MAX_PAYMENTS; i++) {
        if (tbl->entries[i].active &&
            memcmp(tbl->entries[i].payment_secret, payment_secret, 32) == 0) {
            memset(&tbl->entries[i], 0, sizeof(tbl->entries[i]));
            tbl->count--;
            return;
        }
    }
}
