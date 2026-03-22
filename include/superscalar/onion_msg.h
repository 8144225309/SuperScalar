#ifndef SUPERSCALAR_ONION_MSG_H
#define SUPERSCALAR_ONION_MSG_H

/*
 * onion_msg.h — BOLT #12 Onion Messages (type 513 / 0x0201)
 *
 * Onion messages allow nodes to exchange application data (invoice_request,
 * invoice, invoice_error) without an established payment channel.
 * They are a prerequisite for the BOLT #12 offer protocol.
 *
 * Wire format (type 513):
 *   type(2=0x0201) + path_key(33) + pkt_len(2BE) + onion_routing_packet(pkt_len)
 *
 * Onion packet format:
 *   version(1=0x00) + ephemeral_key(33) + encrypted_payload(variable) + hmac(32)
 *
 * Crypto (single-hop, non-blinded path):
 *   shared_secret = SHA256(secp256k1_ec_point_mul(dest_pub, session_key))
 *   rho_key = HMAC-SHA256("rho", shared_secret)   <- ChaCha20 encryption key
 *   mu_key  = HMAC-SHA256("mu",  shared_secret)   <- HMAC key
 *   ciphertext = ChaCha20(key=rho, nonce=0) XOR payload_tlv
 *   hmac = HMAC-SHA256(key=mu, data=ciphertext)
 *
 * Reference:
 *   BOLT #12: https://github.com/lightning/bolts/blob/master/12-offer-encoding.md
 *   LDK: lightning/src/onion_message/
 *   CLN: plugins/offers.c, common/onion_message.c
 */

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>

#define ONION_MSG_TYPE                  513    /* 0x0201 — BOLT #12 */
#define ONION_MSG_APP_MAX               1024   /* max application payload bytes */

/* Application TLV type tags for onion_msg_build app_tlv_type parameter.
   These match the BOLT #12 final-hop TLV types from onion_message.h. */
#ifndef ONION_MSG_TLV_INVOICE_REQUEST
#define ONION_MSG_TLV_INVOICE_REQUEST  64     /* invoice_request (BOLT #12) */
#define ONION_MSG_TLV_INVOICE          66     /* invoice (BOLT #12) */
#define ONION_MSG_TLV_INVOICE_ERROR    68     /* invoice_error (BOLT #12) */
#endif

/*
 * Encode an onion message wire frame:
 *   type(2=0x0201) + path_key(33) + pkt_len(2BE) + packet(pkt_len)
 * Returns bytes written, 0 on error (buffer too small or NULL input).
 */
size_t onion_msg_encode(const unsigned char path_key[33],
                        const unsigned char *pkt, size_t pkt_len,
                        unsigned char *out, size_t out_cap);

/*
 * Decode an onion message wire frame.
 * Returns 1 if type==513 and parse succeeded.
 * path_key_out: filled with the 33-byte path key.
 * pkt_out: pointer into msg (not owned); copy if persistence needed.
 * pkt_len_out: length of the onion routing packet.
 */
int onion_msg_decode(const unsigned char *msg, size_t msg_len,
                     unsigned char path_key_out[33],
                     const unsigned char **pkt_out, size_t *pkt_len_out);

/*
 * Build a single-hop onion message packet.
 *
 * ctx:          secp256k1 context (with SIGN + VERIFY).
 * session_key:  32 random bytes (ephemeral private key).
 * dest_pub33:   33-byte compressed pubkey of the recipient node.
 * app_payload:  application data bytes to deliver.
 * app_len:      length of app_payload.
 * app_tlv_type: TLV type tag (e.g. ONION_MSG_TLV_INVOICE_REQUEST = 1).
 * path_key_out: output 33-byte path key (= session_key * G for single hop).
 * pkt_out:      output buffer for the packet bytes.
 * pkt_cap:      capacity of pkt_out.
 *
 * Returns packet bytes written, 0 on error.
 */
size_t onion_msg_build(secp256k1_context *ctx,
                       const unsigned char session_key[32],
                       const unsigned char dest_pub33[33],
                       const unsigned char *app_payload, size_t app_len,
                       uint64_t app_tlv_type,
                       unsigned char path_key_out[33],
                       unsigned char *pkt_out, size_t pkt_cap);

/*
 * Decrypt and verify the final-hop onion message payload.
 *
 * our_priv:          32-byte private key of the receiving node.
 * path_key:          33-byte path key from the wire frame.
 * pkt/pkt_len:       raw onion routing packet bytes.
 * app_data_out:      buffer to receive decoded application payload.
 * app_buf_cap:       capacity of app_data_out.
 * app_len_out:       bytes written to app_data_out.
 * app_tlv_type_out:  TLV type tag of the application payload.
 *
 * Returns 1 on success (HMAC verified + app data extracted), 0 on failure.
 */
int onion_msg_recv_final(secp256k1_context *ctx,
                          const unsigned char our_priv[32],
                          const unsigned char path_key[33],
                          const unsigned char *pkt, size_t pkt_len,
                          unsigned char *app_data_out, size_t app_buf_cap,
                          size_t *app_len_out,
                          uint64_t *app_tlv_type_out);

#endif /* SUPERSCALAR_ONION_MSG_H */
