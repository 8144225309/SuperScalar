#ifndef SUPERSCALAR_GOSSIP_INGEST_H
#define SUPERSCALAR_GOSSIP_INGEST_H

/*
 * gossip_ingest.h — Verify and store incoming BOLT #7 gossip messages
 *
 * Handles inbound gossip pushed by peers:
 *   256  channel_announcement   — verify 4 Schnorr sigs, store scid + node_ids
 *   257  node_announcement      — verify 1 Schnorr sig, store pubkey + alias
 *   258  channel_update         — verify sig against stored node_id, store policy
 *   265  gossip_timestamp_filter — parse peer's desired gossip window
 *
 * All types validated before being written to the gossip_store.
 * Rate limiting prevents spam: same key may not be updated within
 * GOSSIP_INGEST_MIN_INTERVAL seconds.
 *
 * Reference:
 *   BOLT #7 §gossip-messages
 *   LDK: lightning/src/routing/gossip.rs NetworkGraph::update_*
 *   CLN: gossipd/gossip_store.c + routing.c
 *   LND: discovery/gossiper.go
 */

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>
#include "gossip_store.h"

/* Ingest result codes */
#define GOSSIP_INGEST_OK           0   /* accepted and stored */
#define GOSSIP_INGEST_BAD_SIG      1   /* signature invalid */
#define GOSSIP_INGEST_RATE_LIMITED 2   /* same key updated too recently */
#define GOSSIP_INGEST_ORPHAN       3   /* channel_update for unknown channel */
#define GOSSIP_INGEST_MALFORMED    4   /* message too short / cannot parse */
#define GOSSIP_INGEST_UNKNOWN_TYPE 5   /* not a gossip message type */
#define GOSSIP_INGEST_NO_VERIFY    6   /* ctx=NULL, stored without sig check */

/* Minimum seconds between updates for the same key (anti-spam) */
#define GOSSIP_INGEST_MIN_INTERVAL  60

/* Maximum entries in the rate-limit table */
#define GOSSIP_INGEST_RATE_MAX      512

/* One rate-limit entry (keyed by pubkey33 or scid+dir(1)) */
typedef struct {
    unsigned char key[34];   /* node: 33-byte pubkey; channel: 8-byte scid + 1-byte dir */
    uint8_t       key_len;   /* 33 or 9 */
    uint32_t      last_seen; /* unix timestamp of last accepted update */
} gossip_ingest_rate_t;

typedef struct {
    secp256k1_context    *ctx;           /* for sig verification; NULL = skip verify */
    gossip_store_t       *gs;            /* storage; NULL = verify only, no persist */

    gossip_ingest_rate_t  rate[GOSSIP_INGEST_RATE_MAX];
    int                   rate_count;

    /* diagnostic counters */
    uint32_t n_channel_ann;     /* channel_announcements accepted */
    uint32_t n_node_ann;        /* node_announcements accepted */
    uint32_t n_chan_update;     /* channel_updates accepted */
    uint32_t n_rejected_sig;    /* rejected: bad signature */
    uint32_t n_rejected_rate;   /* rejected: rate limited */
    uint32_t n_rejected_orphan; /* rejected: channel_update for unknown scid */
    uint32_t n_rejected_malformed; /* rejected: parse failure */
} gossip_ingest_t;

/* Initialise. ctx and gs may be NULL (disables sig verification / storage). */
void gossip_ingest_init(gossip_ingest_t *gi,
                        secp256k1_context *ctx,
                        gossip_store_t    *gs);

/*
 * Dispatch a raw wire message to the appropriate ingest handler.
 * msg must include the 2-byte type prefix.
 * Returns one of GOSSIP_INGEST_*.
 */
int gossip_ingest_message(gossip_ingest_t      *gi,
                          const unsigned char  *msg,
                          size_t                msg_len,
                          uint32_t              now_unix);

/*
 * Ingest a channel_announcement (type 256).
 * Verifies all 4 Schnorr sigs, then upserts channel into gossip_store.
 * Returns GOSSIP_INGEST_OK, GOSSIP_INGEST_BAD_SIG, GOSSIP_INGEST_MALFORMED,
 *         GOSSIP_INGEST_RATE_LIMITED, or GOSSIP_INGEST_NO_VERIFY.
 */
int gossip_ingest_channel_announcement(gossip_ingest_t     *gi,
                                        const unsigned char *msg,
                                        size_t               msg_len,
                                        uint32_t             now_unix);

/*
 * Ingest a node_announcement (type 257).
 * Verifies the Schnorr sig, then upserts node into gossip_store.
 * Returns GOSSIP_INGEST_OK, GOSSIP_INGEST_BAD_SIG, GOSSIP_INGEST_MALFORMED,
 *         GOSSIP_INGEST_RATE_LIMITED, or GOSSIP_INGEST_NO_VERIFY.
 */
int gossip_ingest_node_announcement(gossip_ingest_t     *gi,
                                     const unsigned char *msg,
                                     size_t               msg_len,
                                     uint32_t             now_unix);

/*
 * Ingest a channel_update (type 258).
 * Looks up the channel's node_ids from gossip_store, verifies the Schnorr sig
 * from the appropriate node (direction bit in channel_flags), then upserts the
 * routing policy.
 * Returns GOSSIP_INGEST_OK, GOSSIP_INGEST_BAD_SIG, GOSSIP_INGEST_ORPHAN,
 *         GOSSIP_INGEST_MALFORMED, GOSSIP_INGEST_RATE_LIMITED, or
 *         GOSSIP_INGEST_NO_VERIFY.
 */
int gossip_ingest_channel_update(gossip_ingest_t     *gi,
                                  const unsigned char *msg,
                                  size_t               msg_len,
                                  uint32_t             now_unix);

/*
 * Parse a gossip_timestamp_filter (type 265).
 * Extracts chain_hash, first_timestamp, and timestamp_range.
 * Does not rate-limit or store; caller interprets the filter.
 * Returns GOSSIP_INGEST_OK or GOSSIP_INGEST_MALFORMED.
 */
int gossip_ingest_timestamp_filter(gossip_ingest_t     *gi,
                                    const unsigned char *msg,
                                    size_t               msg_len,
                                    unsigned char        chain_hash_out[32],
                                    uint32_t            *first_ts_out,
                                    uint32_t            *range_out);

/*
 * Human-readable description of an ingest result code.
 */
const char *gossip_ingest_result_str(int result);

#endif /* SUPERSCALAR_GOSSIP_INGEST_H */
