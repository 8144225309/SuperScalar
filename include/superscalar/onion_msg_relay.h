#ifndef SUPERSCALAR_ONION_MSG_RELAY_H
#define SUPERSCALAR_ONION_MSG_RELAY_H

/*
 * onion_msg_relay.h — Multi-hop onion message relay (BOLT #7 / BOLT #12)
 *
 * Implements intermediate-node processing for BOLT #12 onion messages.
 * Each relay node:
 *   1. Decrypts its hop payload using ECDH(our_priv, path_key)
 *   2. Finds next_node_id (TLV type 4) or treats message as final
 *   3. Updates path_key for the next hop (blinding key tweak)
 *   4. Forwards inner_pkt to next_node_id with updated path_key
 *
 * Relay hop payload TLV types:
 *   2 = next_blinding_override (33 bytes) — override computed path_key
 *   4 = next_node_id            (33 bytes) — if present, relay to this pubkey
 *   6 = inner_pkt               (variable) — inner onion packet to forward
 *
 * Path key update (blinding factor construction):
 *   shared_secret   = ECDH(our_priv, path_key)
 *   blinding_factor = SHA256(path_key(33) || shared_secret(32))
 *   next_path_key   = EC_POINT_MUL(path_key, blinding_factor)
 *
 * Reference:
 *   BOLT #7 §onion-messages
 *   LDK: lightning/src/onion_message/
 *   CLN: common/onion_message.c
 */

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>

/* TLV type tags in relay hop payloads */
#define ONION_MSG_RELAY_TLV_BKEY_OVERRIDE  2   /* next_blinding_override (33 bytes) */
#define ONION_MSG_RELAY_TLV_NEXT_NODE      4   /* next_node_id (33 bytes) */
#define ONION_MSG_RELAY_TLV_INNER_PKT      6   /* inner packet to forward */

#define ONION_MSG_RELAY_APP_MAX   1024  /* max app payload bytes */
#define ONION_MSG_RELAY_PKT_MAX   2048  /* max inner packet bytes */

typedef struct {
    int           is_final;                          /* 1 = deliver to us, 0 = relay */

    /* Set when is_final == 0 (relay hop) */
    unsigned char next_node_id[33];                  /* pubkey of next hop */
    unsigned char next_path_key[33];                 /* updated path_key for forwarding */
    unsigned char inner_pkt[ONION_MSG_RELAY_PKT_MAX]; /* inner packet to forward */
    size_t        inner_pkt_len;

    /* Set when is_final == 1 (final hop) */
    unsigned char app_data[ONION_MSG_RELAY_APP_MAX]; /* application payload */
    size_t        app_data_len;
    uint64_t      app_tlv_type;
} onion_msg_relay_result_t;

/*
 * Build a relay hop payload TLV stream:
 *   { TLV4: next_node_id(33), TLV6: inner_pkt(inner_pkt_len) }
 *
 * This is the plaintext payload to encrypt when building the relay layer.
 * Returns bytes written, 0 on error (NULL inputs or buffer too small).
 */
size_t onion_msg_relay_build_hop_payload(
    const unsigned char next_node_id[33],
    const unsigned char *inner_pkt, size_t inner_pkt_len,
    unsigned char *out, size_t out_cap);

/*
 * Peel one relay hop from an onion message packet.
 *
 * Performs HMAC verification, decryption, and TLV parsing.
 * If result->is_final == 0: forward result->inner_pkt to result->next_node_id.
 *   The inner_pkt is self-contained; its wire path_key is at inner_pkt[1..33].
 * If result->is_final == 1: deliver result->app_data to the local application.
 *
 * Returns 1 on success (HMAC verified), 0 on failure.
 */
int onion_msg_relay_peel(secp256k1_context *ctx,
                          const unsigned char our_priv[32],
                          const unsigned char path_key[33],
                          const unsigned char *pkt, size_t pkt_len,
                          onion_msg_relay_result_t *result);

/*
 * Compute the next_path_key for the following relay hop.
 *
 *   shared_secret   = ECDH(our_priv, path_key)
 *   blinding_factor = SHA256(path_key || shared_secret)
 *   next_path_key   = EC_POINT_MUL(path_key, blinding_factor)
 *
 * Returns 1 on success, 0 on failure.
 */
int onion_msg_relay_next_path_key(secp256k1_context *ctx,
                                   const unsigned char our_priv[32],
                                   const unsigned char path_key[33],
                                   unsigned char next_path_key_out[33]);

/*
 * Build a complete 2-hop relay onion message (sender → relay_node → dest).
 *
 * Builds the inner packet (relay_node → dest) and wraps it in an outer
 * packet (sender → relay_node) containing the relay hop payload TLV.
 *
 * session_key_relay: ephemeral private key for the outer (sender→relay) hop.
 * session_key_final: ephemeral private key for the inner (relay→dest) hop.
 * relay_pub:         33-byte pubkey of the relay node.
 * dest_pub:          33-byte pubkey of the final destination.
 * app_data:          application payload bytes.
 * app_data_len:      length of app_data.
 * app_tlv_type:      TLV type tag for the application payload.
 * relay_path_key_out: output path_key for the outer wire frame.
 * outer_pkt_out:     output buffer for the complete outer packet.
 * outer_pkt_cap:     capacity of outer_pkt_out.
 *
 * Returns bytes written to outer_pkt_out, 0 on error.
 */
size_t onion_msg_relay_build2(secp256k1_context *ctx,
                               const unsigned char session_key_relay[32],
                               const unsigned char session_key_final[32],
                               const unsigned char relay_pub[33],
                               const unsigned char dest_pub[33],
                               const unsigned char *app_data, size_t app_data_len,
                               uint64_t app_tlv_type,
                               unsigned char relay_path_key_out[33],
                               unsigned char *outer_pkt_out, size_t outer_pkt_cap);

#endif /* SUPERSCALAR_ONION_MSG_RELAY_H */
