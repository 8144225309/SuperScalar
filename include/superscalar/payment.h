/*
 * payment.h — Top-level payment state machine
 *
 * Drives BOLT #11 / keysend payments end-to-end:
 *   pathfind_route → onion_build → add_htlc → await resolution.
 *
 * Reference: LDK ChannelManager::send_payment, CLN pay plugin.
 */

#ifndef SUPERSCALAR_PAYMENT_H
#define SUPERSCALAR_PAYMENT_H

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>
#include "bolt11.h"
#include "pathfind.h"
#include "htlc_forward.h"
#include "mpp.h"
#include "peer_mgr.h"
#include "gossip_store.h"

#define PAYMENT_TABLE_MAX   64
#define PAYMENT_MAX_ROUTES   8   /* MPP shards */
#define PAYMENT_MAX_ATTEMPTS 3   /* retry limit (CLN/LDK default) */

typedef enum {
    PAY_STATE_PENDING = 0,
    PAY_STATE_INFLIGHT,
    PAY_STATE_SUCCESS,
    PAY_STATE_FAILED,
    PAY_STATE_RETRYING
} pay_state_t;

typedef struct {
    unsigned char payment_hash[32];
    unsigned char payment_preimage[32];   /* set on success */
    unsigned char payment_secret[32];     /* from invoice */
    uint64_t      amount_msat;
    uint32_t      max_cltv_delta;
    int           n_routes;
    pathfind_route_t routes[PAYMENT_MAX_ROUTES];
    pay_state_t   state;
    uint32_t      attempt_at;            /* Unix timestamp of last attempt */
    int           n_attempts;
    char          last_error[128];
    /* Session keys used for onion construction (for error decryption) */
    unsigned char session_keys[PAYMENT_MAX_ROUTES][32];
} payment_t;

typedef struct {
    payment_t entries[PAYMENT_TABLE_MAX];
    int       count;
} payment_table_t;

/* Initialise an empty payment table. */
void payment_init(payment_table_t *pt);

/*
 * Send a payment from a BOLT #11 invoice.
 * Finds routes via pathfind, builds onion packets, adds HTLCs.
 * Returns payment index (≥0) on success, -1 on failure.
 */
int payment_send(payment_table_t *pt,
                 gossip_store_t *gs,
                 htlc_forward_table_t *fwd,
                 mpp_table_t *mpp,
                 peer_mgr_t *pmgr,
                 secp256k1_context *ctx,
                 const unsigned char our_priv[32],
                 const bolt11_invoice_t *inv);

/*
 * Keysend: spontaneous payment to dest_pubkey without invoice.
 * Embeds preimage in onion TLV type 5482373484 (keysend).
 * feature bit 55 must be negotiated with the peer.
 * Returns payment index on success, -1 on failure.
 */
int payment_keysend(payment_table_t *pt,
                    gossip_store_t *gs,
                    htlc_forward_table_t *fwd,
                    mpp_table_t *mpp,
                    peer_mgr_t *pmgr,
                    secp256k1_context *ctx,
                    const unsigned char our_priv[32],
                    const unsigned char dest_pubkey[33],
                    uint64_t amount_msat,
                    const unsigned char preimage[32]);

/*
 * Called when an HTLC settles (preimage received).
 * Marks the corresponding payment as SUCCESS.
 */
void payment_on_settle(payment_table_t *pt,
                       const unsigned char payment_hash[32],
                       const unsigned char preimage[32]);

/*
 * Called when an HTLC fails (failure message received).
 * Decrypts error onion, updates penalty box, retries if attempts remain.
 * Returns 1 if retrying, 0 if permanently failed.
 */
int payment_on_fail(payment_table_t *pt,
                    gossip_store_t *gs,
                    htlc_forward_table_t *fwd,
                    mpp_table_t *mpp,
                    peer_mgr_t *pmgr,
                    secp256k1_context *ctx,
                    const unsigned char our_priv[32],
                    const unsigned char payment_hash[32],
                    const unsigned char *onion_error, size_t err_len);

#endif /* SUPERSCALAR_PAYMENT_H */
