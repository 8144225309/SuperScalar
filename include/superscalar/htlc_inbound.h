/*
 * htlc_inbound.h — Inbound HTLC state machine for native LSP payment routing
 *
 * Tracks pending inbound LN HTLCs that need to be forwarded to factory leaves
 * via their fake SCIDs. Decoupled from the network layer for testability.
 */

#ifndef SUPERSCALAR_HTLC_INBOUND_H
#define SUPERSCALAR_HTLC_INBOUND_H

#include <stdint.h>
#include <stddef.h>
#include "superscalar/mpp.h"

#define HTLC_INBOUND_MAX 64   /* max concurrent inbound HTLCs */

typedef enum {
    HTLC_INBOUND_PENDING   = 0,  /* awaiting factory leaf fulfillment  */
    HTLC_INBOUND_FULFILLED = 1,  /* factory returned preimage          */
    HTLC_INBOUND_FAILED    = 2   /* timed out or factory failed        */
} htlc_inbound_state_t;

typedef struct {
    uint64_t htlc_id;                   /* from update_add_htlc          */
    uint64_t amount_msat;               /* msats we received             */
    unsigned char payment_hash[32];     /* SHA256(preimage)              */
    unsigned char payment_secret[32];   /* matched to invoice            */
    uint32_t cltv_expiry;               /* absolute block height timeout */
    uint64_t scid;                      /* fake SCID for factory leaf    */
    htlc_inbound_state_t state;
    unsigned char preimage[32];         /* filled on fulfill             */
} htlc_inbound_t;

typedef struct {
    htlc_inbound_t entries[HTLC_INBOUND_MAX];
    int count;
    mpp_table_t mpp;   /* MPP aggregation (PR #19 Commit 5) */
} htlc_inbound_table_t;

/* Initialise an empty HTLC table. */
void htlc_inbound_init(htlc_inbound_table_t *tbl);

/*
 * Add a new pending inbound HTLC.
 * Returns 1 on success, 0 if the table is full or htlc_id is duplicate.
 */
int htlc_inbound_add(htlc_inbound_table_t *tbl,
                     uint64_t htlc_id,
                     uint64_t amount_msat,
                     const unsigned char payment_hash[32],
                     const unsigned char payment_secret[32],
                     uint32_t cltv_expiry,
                     uint64_t scid);

/*
 * Mark an HTLC as fulfilled; store the preimage.
 * Matches by payment_hash. Returns 1 if found and updated, 0 otherwise.
 */
int htlc_inbound_fulfill(htlc_inbound_table_t *tbl,
                          const unsigned char payment_hash[32],
                          const unsigned char preimage[32]);

/*
 * Mark an HTLC as failed (by htlc_id).
 * Returns 1 if found and updated, 0 otherwise.
 */
int htlc_inbound_fail(htlc_inbound_table_t *tbl, uint64_t htlc_id);

/*
 * Fail all PENDING HTLCs whose cltv_expiry <= current_height.
 * Returns number of HTLCs failed.
 */
int htlc_inbound_check_timeouts(htlc_inbound_table_t *tbl,
                                 uint32_t current_height);

/*
 * Look up a pending HTLC by payment_secret.
 * Returns pointer into tbl->entries (valid until table is modified), or NULL.
 */
htlc_inbound_t *htlc_inbound_find_by_secret(htlc_inbound_table_t *tbl,
                                              const unsigned char payment_secret[32]);

#endif /* SUPERSCALAR_HTLC_INBOUND_H */
