/*
 * onion_message.h — BOLT #4 onion message (type 513) support
 *
 * Onion messages carry BOLT #12 content (invoice_request, invoice, etc.)
 * without an associated HTLC.  They use the Sphinx packet format but with
 * a blinding_point in the wire header and TLV content at the final hop.
 *
 * Wire format (type 513 = 0x0201):
 *   [u8:type_high][u8:type_low]    -- 0x02 0x01
 *   [point:blinding_point]          -- 33 bytes: ephemeral blinding key
 *   [u16:onion_len]                 -- big-endian length of onion bytes
 *   [onion_len:onion_bytes]         -- Sphinx onion payload (encrypted)
 *
 * Simplified 1-hop (direct) scheme implemented here:
 *   sender builds onion_bytes by XOR-ing the plaintext payload with
 *   ChaCha20(rho) where rho = HMAC-SHA256("rho", ECDH(session_key, dest)).
 *   The blinding_point = session_key * G.
 *   Recipient inverts: ECDH(our_priv, blinding_point) → rho → decrypt.
 *
 * For multi-hop blinded path routing, use blinded_path_build() to create
 * the hop list and call onion_msg_build_multihop() (not yet implemented).
 *
 * Reference: BOLT #4 §§8-10; CLN connectd/onion_message.c;
 *            LDK lightning/src/onion_message/
 */

#ifndef SUPERSCALAR_ONION_MESSAGE_H
#define SUPERSCALAR_ONION_MESSAGE_H

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>

/* Wire type for onion messages (BOLT #4) */
#define ONION_MSG_TYPE        513    /* 0x0201 */
#define ONION_MSG_TYPE_HIGH   0x02
#define ONION_MSG_TYPE_LOW    0x01

/* Maximum payload that can be carried in a single direct onion message */
#define ONION_MSG_MAX_PAYLOAD 1300

/* TLV type codes embedded in the final-hop onion message payload */
#define ONION_MSG_TLV_INVOICE_REQUEST  64   /* invoice_request bytes */
#define ONION_MSG_TLV_INVOICE          66   /* invoice bytes */
#define ONION_MSG_TLV_INVOICE_ERROR    68   /* invoice_error bytes */
#define ONION_MSG_TLV_REPLY_PATH       10   /* blinded path for reply */

/*
 * Parsed representation of a received type-513 wire message.
 * onion_bytes is a reference into the caller's buffer (not heap-allocated).
 */
typedef struct {
    unsigned char        blinding_point[33]; /* ephemeral key from wire */
    const unsigned char *onion_bytes;        /* points into caller's buffer */
    uint16_t             onion_len;          /* number of onion bytes */
} onion_msg_t;

/*
 * Parse a type-513 wire message.
 * buf must start with the 2-byte type prefix (0x02 0x01).
 * Fills msg_out with references into buf (no allocation — buf must outlive msg_out).
 * Returns 1 on success, 0 on format error.
 */
int onion_msg_parse(const unsigned char *buf, size_t len, onion_msg_t *msg_out);

/*
 * Build a direct (1-hop) type-513 onion message to dest_pubkey33.
 * payload/payload_len: the content to send (e.g. serialized invoice_request TLV).
 * session_key: 32 random bytes (ephemeral secret; caller must keep unique per message).
 * out/out_cap: output buffer (needs at least 2+33+2+payload_len bytes).
 * Returns bytes written to out, or 0 on error.
 */
/* onion_msg_build is declared in onion_msg.h (PR #34 evolved version) */

/*
 * Decrypt the final-hop payload of a received onion message.
 * Uses ECDH(our_priv, blinding_point) → rho → ChaCha20 to recover plaintext.
 * payload_out: caller-allocated buffer (recommend ONION_MSG_MAX_PAYLOAD bytes).
 * Returns bytes written to payload_out, or 0 on error.
 */
size_t onion_msg_decrypt_final(const onion_msg_t *msg,
                                secp256k1_context *ctx,
                                const unsigned char our_priv32[32],
                                unsigned char *payload_out, size_t payload_cap);

#endif /* SUPERSCALAR_ONION_MESSAGE_H */
