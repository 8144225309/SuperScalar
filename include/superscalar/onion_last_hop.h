/*
 * onion_last_hop.h — BOLT #4 final-hop Sphinx onion decryption
 *
 * Decrypts the innermost onion layer to extract the TLV hop payload.
 * Only the final-hop case is handled (no relaying).
 *
 * Onion packet: version(1) + ephemeral_pubkey(33) + hops_data(1300) + hmac(32) = 1366 bytes
 */

#ifndef SUPERSCALAR_ONION_LAST_HOP_H
#define SUPERSCALAR_ONION_LAST_HOP_H

#include <stddef.h>
#include <stdint.h>
#include <secp256k1.h>

#define ONION_PACKET_SIZE 1366
#define ONION_HOPS_DATA_SIZE 1300

/* Decoded TLV fields from the final-hop payload. */
typedef struct {
    uint64_t amt_to_forward;        /* type 2: msats                        */
    uint32_t outgoing_cltv_value;   /* type 4: absolute block height        */
    unsigned char payment_secret[32]; /* type 8 field 0: 32-byte secret     */
    uint64_t total_msat;            /* type 8 field 1: total payment amount */
    int has_amt;
    int has_cltv;
    int has_payment_data;
} onion_hop_payload_t;

/*
 * Derive the ECDH shared secret for this onion layer.
 * ss_out = SHA256(secp256k1_ec_point_mul(ephemeral_pub33, node_priv32))
 * Returns 1 on success.
 */
int onion_ecdh_shared_secret(secp256k1_context *ctx,
                              const unsigned char node_priv32[32],
                              const unsigned char ephemeral_pub33[33],
                              unsigned char ss_out[32]);

/*
 * Generate the "rho" key: HMAC-SHA256(key="rho", data=shared_secret).
 * Used as the ChaCha20 key to decrypt the hops_data.
 */
void onion_generate_rho(const unsigned char shared_secret[32],
                        unsigned char rho_out[32]);

/*
 * XOR hops_data with ChaCha20(rho, nonce=0) stream of the same length.
 * Both input and output buffers must be at least hops_len bytes.
 * Returns 1 on success.
 */
int onion_xor_stream(const unsigned char *hops_data, size_t hops_len,
                     const unsigned char rho[32],
                     unsigned char *out);

/*
 * Parse a BOLT #4 TLV hop payload.
 * payload / payload_len: the raw TLV bytes (after the leading BigSize length varint).
 * Returns 1 if at least amt_to_forward and outgoing_cltv_value were found.
 */
int onion_parse_tlv_payload(const unsigned char *payload, size_t payload_len,
                             onion_hop_payload_t *out);

/*
 * High-level: decrypt the final-hop onion layer and extract payment fields.
 *
 * onion_packet is ONION_PACKET_SIZE (1366) bytes.
 * Extracts the payload after decrypting and parsing the BigSize-prefixed TLV.
 * Returns 1 on success (mandatory fields found), 0 on decryption/parse error.
 */
int onion_last_hop_decrypt(secp256k1_context *ctx,
                            const unsigned char node_priv32[32],
                            const unsigned char onion_packet[ONION_PACKET_SIZE],
                            onion_hop_payload_t *payload_out);

#endif /* SUPERSCALAR_ONION_LAST_HOP_H */
