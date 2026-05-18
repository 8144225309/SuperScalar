/* bLIP-56 wire codec — skeleton.
 *
 * The bLIP-56 (pluggable channel factories) protocol reuses SuperScalar's
 * existing wire opcodes from include/superscalar/wire.h. This file mirrors
 * the subset relevant to plugin-mediated coordination (factory setup,
 * channel ops, splice). Real encode/decode lives in src/wire.c; here we
 * only declare the stub entry points the plugin uses. */

#ifndef SUPERSCALAR_CLN_BLIP56_CODEC_H
#define SUPERSCALAR_CLN_BLIP56_CODEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* bLIP-56 message type IDs. Numeric values intentionally match the
 * existing MSG_* macros in include/superscalar/wire.h to keep one wire
 * format across plugin and standalone daemon paths. */
typedef enum {
    BLIP56_MSG_HELLO              = 0x01,
    BLIP56_MSG_HELLO_ACK          = 0x02,

    /* Factory setup */
    BLIP56_MSG_FACTORY_PROPOSE    = 0x10,
    BLIP56_MSG_NONCE_BUNDLE       = 0x11,
    BLIP56_MSG_ALL_NONCES         = 0x12,
    BLIP56_MSG_PSIG_BUNDLE        = 0x13,
    BLIP56_MSG_FACTORY_READY      = 0x14,

    /* Cooperative close */
    BLIP56_MSG_CLOSE_PROPOSE      = 0x20,
    BLIP56_MSG_CLOSE_NONCE        = 0x21,
    BLIP56_MSG_CLOSE_ALL_NONCES   = 0x22,
    BLIP56_MSG_CLOSE_PSIG         = 0x23,
    BLIP56_MSG_CLOSE_DONE         = 0x24,

    /* Channel operations */
    BLIP56_MSG_CHANNEL_READY      = 0x30,
    BLIP56_MSG_UPDATE_ADD_HTLC    = 0x31,
    BLIP56_MSG_COMMITMENT_SIGNED  = 0x32,
    BLIP56_MSG_REVOKE_AND_ACK     = 0x33,
    BLIP56_MSG_UPDATE_FULFILL_HTLC= 0x34,
    BLIP56_MSG_UPDATE_FAIL_HTLC   = 0x35,

    /* Keepalive */
    BLIP56_MSG_PING               = 0x70,
    BLIP56_MSG_PONG               = 0x71,
} blip56_msg_type_t;

/* Decode result. */
typedef struct {
    blip56_msg_type_t type;
    const uint8_t    *payload;     /* borrowed pointer into caller's buffer */
    size_t            payload_len;
} blip56_frame_t;

/* Decode a raw wire frame (type byte + payload).
 * Returns 0 on success, -1 on malformed input. */
int blip56_decode(const uint8_t *buf, size_t buf_len, blip56_frame_t *out);

/* Encode a frame. Writes msg_type then payload. Returns bytes written,
 * or -1 if out_cap is too small. */
int blip56_encode(blip56_msg_type_t type,
                  const uint8_t    *payload,
                  size_t            payload_len,
                  uint8_t          *out,
                  size_t            out_cap);

#ifdef __cplusplus
}
#endif

#endif /* SUPERSCALAR_CLN_BLIP56_CODEC_H */
