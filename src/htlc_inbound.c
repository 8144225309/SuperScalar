/*
 * htlc_inbound.c — Inbound HTLC state machine
 */

#include "superscalar/htlc_inbound.h"
#include <string.h>

void htlc_inbound_init(htlc_inbound_table_t *tbl) {
    if (!tbl) return;
    memset(tbl, 0, sizeof(*tbl));
}

int htlc_inbound_add(htlc_inbound_table_t *tbl,
                     uint64_t htlc_id,
                     uint64_t amount_msat,
                     const unsigned char payment_hash[32],
                     const unsigned char payment_secret[32],
                     uint32_t cltv_expiry,
                     uint64_t scid) {
    if (!tbl || !payment_hash || !payment_secret) return 0;
    if (tbl->count >= HTLC_INBOUND_MAX) return 0;

    /* Reject duplicate htlc_id */
    for (int i = 0; i < tbl->count; i++) {
        if (tbl->entries[i].htlc_id == htlc_id) return 0;
    }

    htlc_inbound_t *e = &tbl->entries[tbl->count++];
    e->htlc_id    = htlc_id;
    e->amount_msat = amount_msat;
    memcpy(e->payment_hash,   payment_hash,   32);
    memcpy(e->payment_secret, payment_secret, 32);
    e->cltv_expiry = cltv_expiry;
    e->scid        = scid;
    e->state       = HTLC_INBOUND_PENDING;
    memset(e->preimage, 0, 32);
    return 1;
}

int htlc_inbound_fulfill(htlc_inbound_table_t *tbl,
                          const unsigned char payment_hash[32],
                          const unsigned char preimage[32]) {
    if (!tbl || !payment_hash || !preimage) return 0;
    for (int i = 0; i < tbl->count; i++) {
        htlc_inbound_t *e = &tbl->entries[i];
        if (e->state == HTLC_INBOUND_PENDING &&
            memcmp(e->payment_hash, payment_hash, 32) == 0) {
            e->state = HTLC_INBOUND_FULFILLED;
            memcpy(e->preimage, preimage, 32);
            return 1;
        }
    }
    return 0;
}

int htlc_inbound_fail(htlc_inbound_table_t *tbl, uint64_t htlc_id) {
    if (!tbl) return 0;
    for (int i = 0; i < tbl->count; i++) {
        if (tbl->entries[i].htlc_id == htlc_id &&
            tbl->entries[i].state == HTLC_INBOUND_PENDING) {
            tbl->entries[i].state = HTLC_INBOUND_FAILED;
            return 1;
        }
    }
    return 0;
}

int htlc_inbound_check_timeouts(htlc_inbound_table_t *tbl,
                                 uint32_t current_height) {
    if (!tbl) return 0;
    int n = 0;
    for (int i = 0; i < tbl->count; i++) {
        htlc_inbound_t *e = &tbl->entries[i];
        if (e->state == HTLC_INBOUND_PENDING &&
            e->cltv_expiry <= current_height) {
            e->state = HTLC_INBOUND_FAILED;
            n++;
        }
    }
    return n;
}

htlc_inbound_t *htlc_inbound_find_by_secret(htlc_inbound_table_t *tbl,
                                              const unsigned char payment_secret[32]) {
    if (!tbl || !payment_secret) return NULL;
    for (int i = 0; i < tbl->count; i++) {
        if (tbl->entries[i].state == HTLC_INBOUND_PENDING &&
            memcmp(tbl->entries[i].payment_secret, payment_secret, 32) == 0)
            return &tbl->entries[i];
    }
    return NULL;
}
