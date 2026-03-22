/*
 * onion_message.c — BOLT #4 type-513 onion message wire support
 *
 * Implements the simplified 1-hop ECIES scheme:
 *   sender:    blinding_pt = sk*G; rho = HMAC("rho", ECDH(sk, dest));
 *              ciphertext  = payload XOR ChaCha20(rho)
 *   recipient: rho = HMAC("rho", ECDH(our_priv, blinding_pt));
 *              plaintext   = ciphertext XOR ChaCha20(rho)
 *
 * Reference: BOLT #4 §8-10; CLN connectd/onion_message.c
 */

#include "superscalar/onion_message.h"
#include "superscalar/onion_last_hop.h"  /* onion_ecdh_shared_secret,
                                           onion_generate_rho, onion_xor_stream */
#include <secp256k1.h>
#include <string.h>

/* ------------------------------------------------------------------ */

int onion_msg_parse(const unsigned char *buf, size_t len, onion_msg_t *msg_out)
{
    /* Minimum: type(2) + blinding(33) + onion_len(2) = 37 bytes */
    if (!buf || !msg_out || len < 37) return 0;

    /* Verify type 513 = 0x0201 */
    if (buf[0] != ONION_MSG_TYPE_HIGH || buf[1] != ONION_MSG_TYPE_LOW) return 0;

    memcpy(msg_out->blinding_point, buf + 2, 33);

    uint16_t onion_len = ((uint16_t)buf[35] << 8) | buf[36];
    if ((size_t)(37 + onion_len) > len) return 0;

    msg_out->onion_bytes = buf + 37;
    msg_out->onion_len   = onion_len;
    return 1;
}

/* onion_msg_build removed — superseded by the evolved version in onion_msg.c
   (PR #34) which uses the canonical parameter order matching BOLT #4. */

size_t onion_msg_decrypt_final(const onion_msg_t *msg,
                                secp256k1_context *ctx,
                                const unsigned char our_priv32[32],
                                unsigned char *payload_out, size_t payload_cap)
{
    if (!msg || !ctx || !our_priv32 || !payload_out || msg->onion_len == 0) return 0;

    /* shared_secret = SHA256(our_priv * blinding_point) */
    unsigned char ss[32];
    if (!onion_ecdh_shared_secret(ctx, our_priv32, msg->blinding_point, ss)) return 0;

    /* rho = HMAC-SHA256("rho", ss) */
    unsigned char rho[32];
    onion_generate_rho(ss, rho);

    /* Decrypt: plaintext = ciphertext XOR ChaCha20(rho) */
    size_t copy_len = msg->onion_len < payload_cap ? msg->onion_len : payload_cap;
    if (!onion_xor_stream(msg->onion_bytes, copy_len, rho, payload_out)) return 0;
    return copy_len;
}
