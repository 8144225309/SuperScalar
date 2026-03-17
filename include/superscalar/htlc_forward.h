/*
 * htlc_forward.h — HTLC forwarding engine (relay node functionality)
 *
 * Receives inbound HTLCs, decrypts the onion to find the next hop or
 * recognizes the final-hop case, and tracks in-flight state until settled.
 *
 * Reference: LDK ChannelManager, CLN channeld/channeld.c
 */

#ifndef SUPERSCALAR_HTLC_FORWARD_H
#define SUPERSCALAR_HTLC_FORWARD_H

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>
#include "onion_last_hop.h"
#include "mpp.h"

#define FORWARD_TABLE_MAX  256

/* Return codes for htlc_forward_process */
#define FORWARD_FINAL   1   /* we are the final destination */
#define FORWARD_RELAY   2   /* forward to next hop */
#define FORWARD_FAIL    0   /* error, send fail_htlc */

/* HTLC in-flight state */
typedef enum {
    FORWARD_STATE_PENDING_OUT = 0,
    FORWARD_STATE_INFLIGHT,
    FORWARD_STATE_SETTLED,
    FORWARD_STATE_FAILED
} htlc_forward_state_t;

typedef struct {
    uint64_t in_htlc_id;
    uint64_t in_chan_id;
    uint64_t out_htlc_id;
    uint64_t out_chan_id;
    unsigned char payment_hash[32];
    unsigned char onion_shared_secret[32]; /* for error re-encryption */
    uint64_t in_amount_msat;
    uint64_t out_amount_msat;
    uint32_t in_cltv;
    uint32_t out_cltv;
    uint64_t next_hop_scid;             /* outgoing short_channel_id */
    unsigned char next_hop_pubkey[33];  /* outgoing node pubkey */
    htlc_forward_state_t state;
} htlc_forward_entry_t;

typedef struct {
    htlc_forward_entry_t entries[FORWARD_TABLE_MAX];
    int count;
} htlc_forward_table_t;

/* Initialise an empty forward table. */
void htlc_forward_init(htlc_forward_table_t *fwd);

/*
 * Process an inbound HTLC.
 * Decrypts the onion layer:
 *   - FORWARD_FINAL: delivers to mpp table.
 *   - FORWARD_RELAY: adds to forward table, fills *out with next-hop info.
 *   - FORWARD_FAIL:  malformed onion or routing failure.
 */
int htlc_forward_process(htlc_forward_table_t *fwd,
                          mpp_table_t *mpp,
                          const unsigned char our_privkey[32],
                          secp256k1_context *ctx,
                          const unsigned char onion[ONION_PACKET_SIZE],
                          uint64_t in_htlc_id, uint64_t in_chan_id,
                          uint64_t amount_msat, uint32_t cltv,
                          htlc_forward_entry_t *out);

/*
 * Settle: preimage received on outbound HTLC → propagate backward.
 * Finds the inbound HTLC by (out_htlc_id, out_chan_id) and marks it settled.
 */
void htlc_forward_settle(htlc_forward_table_t *fwd,
                          uint64_t out_htlc_id, uint64_t out_chan_id,
                          const unsigned char preimage[32]);

/*
 * Fail: failure received on outbound HTLC → propagate backward.
 * Re-encrypts the onion error with this hop's shared secret.
 */
void htlc_forward_fail(htlc_forward_table_t *fwd,
                        uint64_t out_htlc_id, uint64_t out_chan_id,
                        const unsigned char *onion_error, size_t err_len,
                        unsigned char out_error[256]);

#endif /* SUPERSCALAR_HTLC_FORWARD_H */
