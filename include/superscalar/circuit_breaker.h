#ifndef SUPERSCALAR_CIRCUIT_BREAKER_H
#define SUPERSCALAR_CIRCUIT_BREAKER_H

#include <stdint.h>
#include <stddef.h>

/*
 * Circuit breaker: per-peer HTLC forwarding limits.
 *
 * Protects the node against spam/DoS by capping in-flight HTLCs per peer.
 * Mirrors lightningequipment/circuitbreaker and CLN's per-peer quota design.
 *
 * When a limit is exceeded the forwarding engine must return
 * HTLC_TEMPORARY_CHANNEL_FAILURE so the sender can retry another route.
 *
 * Token-bucket rate limiter (max_htlcs_per_hour):
 *   tokens refilled once per hour up to max_htlcs_per_hour.
 *   Each accepted HTLC consumes one token.
 */

#define CIRCUIT_BREAKER_MAX_PEERS 64
#define CIRCUIT_BREAKER_DEFAULT_MAX_PENDING    483  /* BOLT #2 max_accepted_htlcs */
#define CIRCUIT_BREAKER_DEFAULT_MAX_MSAT       100000000000ULL  /* 1 BTC */
#define CIRCUIT_BREAKER_DEFAULT_HOURLY_RATE    3600  /* 1/sec */
#define CIRCUIT_BREAKER_SECS_PER_HOUR          3600

typedef struct {
    unsigned char peer_pubkey[33];   /* 33-byte compressed pubkey (key) */
    int           active;            /* 1 if this slot is in use */

    /* Limits (configured per peer or using defaults) */
    uint16_t      max_pending_htlcs;       /* cap on concurrent in-flight HTLCs */
    uint64_t      max_pending_msat;        /* cap on total in-flight amount */
    uint32_t      max_htlcs_per_hour;      /* token bucket refill count */

    /* Runtime state */
    uint16_t      pending_htlc_count;      /* currently in-flight */
    uint64_t      pending_msat;            /* currently in-flight amount */
    uint32_t      tokens;                  /* available tokens (rate limit) */
    uint32_t      last_refill_unix;        /* when tokens were last replenished */
} circuit_breaker_peer_t;

typedef struct {
    circuit_breaker_peer_t peers[CIRCUIT_BREAKER_MAX_PEERS];
    int                    n_peers;

    /* Global defaults applied to peers with no explicit config */
    uint16_t default_max_pending_htlcs;
    uint64_t default_max_pending_msat;
    uint32_t default_max_htlcs_per_hour;
} circuit_breaker_t;

/* Initialise circuit_breaker_t with default limits. */
void circuit_breaker_init(circuit_breaker_t *cb);

/*
 * Configure limits for a specific peer (identified by 33-byte pubkey).
 * Creates a peer slot if it doesn't exist.
 */
void circuit_breaker_set_peer_limits(circuit_breaker_t *cb,
                                      const unsigned char peer_pubkey[33],
                                      uint16_t max_pending_htlcs,
                                      uint64_t max_pending_msat,
                                      uint32_t max_htlcs_per_hour);

/*
 * Check if a new HTLC from peer_pubkey can be accepted.
 * Returns 1 if within limits, 0 if the circuit should be tripped
 * (forwarding engine should return HTLC_TEMPORARY_CHANNEL_FAILURE).
 * now_unix: current UNIX timestamp (for token bucket refill).
 */
int circuit_breaker_check_add(circuit_breaker_t *cb,
                               const unsigned char peer_pubkey[33],
                               uint64_t amount_msat,
                               uint32_t now_unix);

/*
 * Record that an HTLC was settled (fulfilled or failed) for peer_pubkey.
 * Decrements the pending count and amount.
 */
void circuit_breaker_record_settled(circuit_breaker_t *cb,
                                     const unsigned char peer_pubkey[33],
                                     uint64_t amount_msat);

/*
 * Refill token buckets for all peers based on elapsed time.
 * now_unix: current UNIX timestamp.
 */
void circuit_breaker_refill_tokens(circuit_breaker_t *cb, uint32_t now_unix);

/*
 * Query current pending count and amount for a peer.
 * Returns 1 if peer found, 0 if unknown (use defaults).
 */
int circuit_breaker_get_peer_state(const circuit_breaker_t *cb,
                                    const unsigned char peer_pubkey[33],
                                    uint16_t *pending_htlcs_out,
                                    uint64_t *pending_msat_out);

/* ---- Channel-Type TLV (BOLT #2 PR #880 / option_will_fund) ---- */

/*
 * BOLT #9 feature bits for channel type negotiation.
 * Encoded as a bitfield in open_channel / accept_channel TLV type 5.
 */
#define CHAN_TYPE_STATIC_REMOTE_KEY_BIT   12  /* option_static_remote_key */
#define CHAN_TYPE_ANCHOR_OUTPUTS_BIT      22  /* option_anchor_outputs */
#define CHAN_TYPE_SCID_ALIAS_BIT           4  /* option_scid_alias (uint32 mapping) */
#define CHAN_TYPE_ZERO_CONF_BIT            6  /* option_zeroconf (uint32 mapping) */

#define CHAN_TYPE_TLV_TYPE                 5  /* channel_type TLV in open_channel */

/*
 * Encode feature bits as a channel_type TLV (type 5).
 * Wire format: type(1) + len(1) + feature_bits(len bytes, BE).
 * Returns bytes written, or 0 on error.
 */
size_t channel_type_encode(uint32_t feature_bits,
                            unsigned char *buf, size_t buf_cap);

/*
 * Decode a channel_type TLV (type 5) into feature_bits.
 * Returns 1 on success.
 */
int channel_type_decode(const unsigned char *buf, size_t buf_len,
                         uint32_t *feature_bits_out);

/*
 * Negotiate channel type: AND the local and remote feature bits.
 * Returns the agreed feature bits (intersection).
 */
uint32_t channel_type_negotiate(uint32_t local_bits, uint32_t remote_bits);

/*
 * Validate a feerate for update_fee (BOLT #2 §7).
 * floor: 250 sat/kw, ceiling: 100,000 sat/kw.
 * Returns 1 if valid.
 */
int update_fee_validate(uint32_t feerate_perkw);

#endif /* SUPERSCALAR_CIRCUIT_BREAKER_H */
