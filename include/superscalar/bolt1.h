#ifndef SUPERSCALAR_BOLT1_H
#define SUPERSCALAR_BOLT1_H

/*
 * bolt1.h — BOLT #1 Peer Protocol: fundamental messages.
 *
 * Implements: init (16), error (17), warning (1), ping (18), pong (19).
 * Feature bit negotiation per BOLT #9.
 *
 * Reference: lightning/bolts BOLT #1, BOLT #9
 *            CLN: lightningd/connect_control.c, LDK: ln/peers_manager.rs
 */

#include <stdint.h>
#include <stddef.h>

/* ---- BOLT #1 message types ---- */
#define BOLT1_MSG_WARNING    1
#define BOLT1_MSG_INIT      16
#define BOLT1_MSG_ERROR     17
#define BOLT1_MSG_PING      18
#define BOLT1_MSG_PONG      19

/* ---- BOLT #9 feature bit positions (odd = optional, even = required) ---- */
#define BOLT9_DATA_LOSS_PROTECT           1   /* option_data_loss_protect (odd) */
#define BOLT9_INITIAL_ROUTING_SYNC        5   /* initial_routing_sync (odd) */
#define BOLT9_UPFRONT_SHUTDOWN_SCRIPT     3   /* upfront_shutdown_script (odd) */
#define BOLT9_GOSSIP_QUERIES              7   /* gossip_queries (odd) */
#define BOLT9_VAR_ONION_OPTIN             9   /* var_onion_optin (odd) */
#define BOLT9_PAYMENT_SECRET             15   /* payment_secret (odd) — REQUIRED */
#define BOLT9_BASIC_MPP                  17   /* basic_mpp (odd) */
#define BOLT9_STATIC_REMOTE_KEY          13   /* option_static_remotekey (odd) */
#define BOLT9_LARGE_CHANNEL              19   /* option_support_large_channel (odd) */
#define BOLT9_ANCHOR_OUTPUTS             23   /* option_anchor_outputs (odd) */
#define BOLT9_ANCHOR_ZERO_FEE_HTLC       31   /* option_anchors_zero_fee_htlc_tx (odd) */
#define BOLT9_CHANNEL_TYPE               45   /* option_channel_type (odd) */
#define BOLT9_SCID_ALIAS                 47   /* option_scid_alias (odd) */
#define BOLT9_ZEROCONF                   51   /* option_zeroconf (odd) */

/*
 * Our advertised feature set: payment_secret, basic_mpp, static_remote_key,
 * data_loss_protect, gossip_queries.
 */
#define BOLT1_OUR_FEATURES  ((UINT64_C(1) << BOLT9_DATA_LOSS_PROTECT)  | \
                             (UINT64_C(1) << BOLT9_GOSSIP_QUERIES)      | \
                             (UINT64_C(1) << BOLT9_PAYMENT_SECRET)      | \
                             (UINT64_C(1) << BOLT9_BASIC_MPP)           | \
                             (UINT64_C(1) << BOLT9_STATIC_REMOTE_KEY))

/* Maximum feature bytes we'll encode (covers bit 63) */
#define BOLT1_MAX_FEATURE_BYTES 8

/* Parsed init message */
typedef struct {
    uint64_t global_features;  /* peer's global feature bits */
    uint64_t local_features;   /* peer's local (init) feature bits */
} bolt1_init_t;

/* Parsed error/warning message */
typedef struct {
    unsigned char channel_id[32]; /* all-zeros = global */
    char          data[256];      /* NUL-terminated description */
    size_t        data_len;
} bolt1_error_t;

/* Parsed ping */
typedef struct {
    uint16_t num_pong_bytes;  /* bytes we must echo back in pong */
    uint16_t ignored_len;     /* length of padding to ignore */
} bolt1_ping_t;

/*
 * Build an init message (type 16).
 * local_features: BOLT #9 feature bits as uint64_t bitfield.
 * Returns bytes written, 0 on error.
 */
size_t bolt1_build_init(uint64_t local_features,
                         unsigned char *buf, size_t buf_cap);

/*
 * Parse an init message.
 * Returns 1 on success, 0 on error.
 */
int bolt1_parse_init(const unsigned char *msg, size_t msg_len,
                      bolt1_init_t *out);

/*
 * Build a ping message (type 18).
 * num_pong_bytes: how many bytes the pong should contain.
 * Returns bytes written.
 */
size_t bolt1_build_ping(uint16_t num_pong_bytes,
                         unsigned char *buf, size_t buf_cap);

/*
 * Build a pong message (type 19) in response to a ping.
 * byteslen: num_pong_bytes from the received ping.
 * Returns bytes written.
 */
size_t bolt1_build_pong(uint16_t byteslen,
                         unsigned char *buf, size_t buf_cap);

/*
 * Parse a ping message.
 * Returns 1 on success.
 */
int bolt1_parse_ping(const unsigned char *msg, size_t msg_len,
                      bolt1_ping_t *out);

/*
 * Build an error message (type 17).
 * channel_id: 32-byte channel, or all-zeros for global.
 * data: error description string.
 * Returns bytes written.
 */
size_t bolt1_build_error(const unsigned char channel_id[32],
                          const char *data,
                          unsigned char *buf, size_t buf_cap);

/*
 * Build a warning message (type 1).
 * Same wire format as error.
 */
size_t bolt1_build_warning(const unsigned char channel_id[32],
                             const char *data,
                             unsigned char *buf, size_t buf_cap);

/*
 * Parse an error or warning message.
 * Returns 1 on success.
 */
int bolt1_parse_error(const unsigned char *msg, size_t msg_len,
                       bolt1_error_t *out);

/*
 * Check if a feature bit is set in a feature bitfield.
 * Returns 1 if set.
 */
int bolt1_has_feature(uint64_t features, int bit);

/*
 * Check for unknown mandatory (even) feature bits.
 * Returns 1 if all unknown bits are odd (acceptable), 0 if any unknown
 * even bits are present (must disconnect per BOLT #1).
 * known_bits: bitmask of feature bits we understand.
 */
int bolt1_check_mandatory_features(uint64_t peer_features, uint64_t known_bits);

#endif /* SUPERSCALAR_BOLT1_H */
