#ifndef SUPERSCALAR_BOLT4_FAILURE_H
#define SUPERSCALAR_BOLT4_FAILURE_H

/*
 * bolt4_failure.h — BOLT #4 onion failure message parser
 *
 * After onion_error_decrypt() returns the 224-byte plaintext, this module
 * parses the structured failure_code + failure_data to extract:
 *   - failure code and its semantic flags (PERM, NODE, UPDATE, BAD_ONION)
 *   - embedded channel_update bytes for gossip propagation
 *   - htlc_msat / cltv_expiry / disabled_flags for routing decisions
 *   - sha256_of_onion for bad-onion attribution
 *
 * Failure code flag bits (BOLT #4 §failure-codes):
 *   bit 15 (0x8000) = BADONION — error describes a bad onion; exclude from routing
 *   bit 14 (0x4000) = PERM     — permanent failure; don't retry via this channel
 *   bit 13 (0x2000) = NODE     — node-level error; exclude the whole node
 *   bit 12 (0x1000) = UPDATE   — failure includes a channel_update
 *
 * Reference:
 *   BOLT #4: https://github.com/lightning/bolts/blob/master/04-onion-routing.md
 *   LND: htlcswitch/failure.go
 *   CLN: common/route.c failure_msg_parse
 *   LDK: ln/msgs.rs DecodeError / HTLCFailChannelUpdate
 */

#include <stdint.h>
#include <stddef.h>

/* -----------------------------------------------------------------------
 * Failure code flag masks
 * --------------------------------------------------------------------- */
#define BOLT4_FAIL_BADONION  0x8000  /* corrupted onion — bad_onion_sha256 valid */
#define BOLT4_FAIL_PERM      0x4000  /* permanent failure — don't retry */
#define BOLT4_FAIL_NODE      0x2000  /* node failure — blacklist node */
#define BOLT4_FAIL_UPDATE    0x1000  /* channel_update included in failure_data */

/* -----------------------------------------------------------------------
 * Known failure codes
 * --------------------------------------------------------------------- */
/* Bad-onion errors (BADONION set) */
#define BOLT4_INVALID_ONION_VERSION          0x8004
#define BOLT4_INVALID_ONION_HMAC             0x8005
#define BOLT4_INVALID_ONION_KEY              0x8006
#define BOLT4_INVALID_ONION_BLINDING         0x8015

/* Channel-level UPDATE failures (UPDATE set) */
#define BOLT4_TEMPORARY_CHANNEL_FAILURE      0x1007
#define BOLT4_AMOUNT_BELOW_MINIMUM           0x100B
#define BOLT4_FEE_INSUFFICIENT               0x100C
#define BOLT4_INCORRECT_CLTV_EXPIRY          0x100D
#define BOLT4_EXPIRY_TOO_SOON                0x100E
#define BOLT4_CHANNEL_DISABLED               0x1006

/* Permanent channel failures (PERM set, no UPDATE) */
#define BOLT4_PERMANENT_CHANNEL_FAILURE      0x4009
#define BOLT4_REQUIRED_CHANNEL_FEATURE_MISSING 0x4011
#define BOLT4_UNKNOWN_NEXT_PEER              0x400A

/* Permanent node failures (PERM | NODE set) */
#define BOLT4_PERMANENT_NODE_FAILURE         0x4002
#define BOLT4_TEMPORARY_NODE_FAILURE         0x2002
#define BOLT4_REQUIRED_NODE_FEATURE_MISSING  0x4003
#define BOLT4_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS 0x400F  /* also NODE */

/* Final-hop errors (no routing flags) */
#define BOLT4_UNKNOWN_PAYMENT_HASH           0x000F  /* probe: destination reached */
#define BOLT4_FINAL_EXPIRY_TOO_SOON          0x0011
#define BOLT4_FINAL_INCORRECT_CLTV_EXPIRY    0x001C
#define BOLT4_FINAL_INCORRECT_HTLC_AMOUNT    0x001B

/* -----------------------------------------------------------------------
 * Maximum size of an embedded channel_update wire message
 * --------------------------------------------------------------------- */
#define BOLT4_CHANNEL_UPDATE_MAX  512

typedef struct {
    uint16_t  failure_code;           /* raw failure_code (2 bytes BE) */

    /* Flag bits extracted from failure_code */
    int       is_bad_onion;           /* bit 15 */
    int       is_permanent;           /* bit 14 */
    int       is_node_failure;        /* bit 13 */
    int       has_channel_update;     /* bit 12 */

    /* Bad-onion SHA256 (if is_bad_onion): SHA256 of the corrupted onion */
    unsigned char bad_onion_sha256[32];
    int           has_bad_onion_sha;  /* 1 if bad_onion_sha256 is valid */

    /* Embedded channel_update (if has_channel_update):
     * Points into a copy of the channel_update bytes (including wire type 258). */
    unsigned char channel_update_buf[BOLT4_CHANNEL_UPDATE_MAX];
    size_t        channel_update_len; /* 0 if not present */

    /* htlc_msat carried in failure (AMOUNT_BELOW_MINIMUM, FEE_INSUFFICIENT,
     * INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS) */
    uint64_t  htlc_msat;
    int       has_htlc_msat;

    /* cltv_expiry carried in failure (INCORRECT_CLTV_EXPIRY) */
    uint32_t  cltv_expiry;
    int       has_cltv_expiry;

    /* CHANNEL_DISABLED flags (type 0x1006) */
    uint16_t  disabled_flags;
    int       has_disabled_flags;

    /* Height at which failure was generated (INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS) */
    uint32_t  block_height;
    int       has_block_height;
} bolt4_failure_t;

/*
 * Parse a decrypted BOLT #4 failure plaintext.
 *
 * plaintext:     224-byte buffer from onion_error_decrypt() (or any ≥2-byte buffer).
 * plaintext_len: length of plaintext (must be ≥ 2).
 * out:           filled on success.
 *
 * Returns 1 on success, 0 if plaintext is NULL or too short.
 */
int bolt4_failure_parse(const unsigned char *plaintext, size_t plaintext_len,
                         bolt4_failure_t *out);

/*
 * Return a human-readable short string for a failure code.
 * Always returns a non-NULL string (falls back to "unknown").
 */
const char *bolt4_failure_str(uint16_t code);

/*
 * Returns 1 if a payment should NOT be retried through the same channel.
 * True for any permanent failure (PERM bit set).
 */
int bolt4_failure_is_permanent(const bolt4_failure_t *f);

/*
 * Returns 1 if the failure is a node-level error (blacklist the whole node).
 * True when NODE bit set (0x2000).
 */
int bolt4_failure_is_node_failure(const bolt4_failure_t *f);

/*
 * Returns 1 if the failure is due to a corrupted onion packet.
 * The failing_hop from onion_error_decrypt may be unreliable in this case.
 */
int bolt4_failure_is_bad_onion(const bolt4_failure_t *f);

/*
 * Returns 1 if the failure contains an embedded channel_update that should
 * be applied to the gossip store.
 */
int bolt4_failure_has_update(const bolt4_failure_t *f);

#endif /* SUPERSCALAR_BOLT4_FAILURE_H */
