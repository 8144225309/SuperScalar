/*
 * mpp.h — Multi-path payment (MPP) aggregation
 *
 * Collects HTLC parts sharing a payment_secret until the total_msat
 * threshold is reached, then exposes them as a complete payment.
 *
 * BOLT #4 rules applied:
 *   - All parts must share the same payment_secret
 *   - collected_msat >= total_msat to fulfil
 *   - collected_msat <= 2 * total_msat (overpayment guard — Eclair)
 *   - Incomplete sets fail after MPP_TIMEOUT_SECS (BOLT #4)
 */

#ifndef SUPERSCALAR_MPP_H
#define SUPERSCALAR_MPP_H

#include <stdint.h>
#include <stddef.h>

#define MPP_MAX_PAYMENTS   32   /* max concurrent multi-part payments */
#define MPP_MAX_PARTS      10   /* max HTLCs per payment (LDK default) */
#define MPP_TIMEOUT_SECS   60   /* fail incomplete set after 60s (BOLT #4) */

typedef struct {
    uint64_t htlc_id;
    uint64_t amount_msat;
    uint32_t cltv_expiry;
} mpp_part_t;

typedef struct {
    unsigned char payment_secret[32];
    uint64_t      total_msat;           /* target from invoice */
    mpp_part_t    parts[MPP_MAX_PARTS];
    int           n_parts;
    uint64_t      collected_msat;
    uint32_t      first_received_unix;
    int           active;
} mpp_payment_t;

typedef struct {
    mpp_payment_t entries[MPP_MAX_PAYMENTS];
    int count;
} mpp_table_t;

/* Initialise an empty MPP table. */
void mpp_init(mpp_table_t *tbl);

/*
 * Add one HTLC part.
 *
 * Returns:
 *   1  = payment complete (collected >= total_msat)   → caller should fulfil
 *   0  = still collecting more parts
 *  -1  = part limit, table full, or overpayment guard → caller should fail
 */
int mpp_add_part(mpp_table_t *tbl,
                 const unsigned char payment_secret[32],
                 uint64_t htlc_id, uint64_t amount_msat,
                 uint64_t total_msat, uint32_t cltv_expiry);

/*
 * Fail all parts of incomplete sets whose first_received + MPP_TIMEOUT_SECS <= now.
 * Writes up to max_out htlc_ids into failed_htlc_ids_out.
 * Returns count of htlc_ids written.
 */
int mpp_check_timeouts(mpp_table_t *tbl, uint32_t now_unix,
                       uint64_t *failed_htlc_ids_out, int max_out);

/*
 * Retrieve all htlc_ids for a payment_secret (to fulfil all parts together).
 * Returns count of ids written (up to max_out).
 */
int mpp_get_parts(mpp_table_t *tbl, const unsigned char payment_secret[32],
                  uint64_t *htlc_ids_out, int max_out);

/*
 * Remove the payment for payment_secret from the table (after fulfil/fail).
 */
void mpp_remove(mpp_table_t *tbl, const unsigned char payment_secret[32]);

#endif /* SUPERSCALAR_MPP_H */
