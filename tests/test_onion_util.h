#ifndef SUPERSCALAR_TEST_ONION_UTIL_H
#define SUPERSCALAR_TEST_ONION_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <secp256k1.h>

/* The TLV payload of a final hop: amt_to_forward, outgoing_cltv_value and,
   with secret32, payment_data (secret, total_msat).  Returns its length
   (out must hold 80 bytes). */
size_t test_final_hop_tlv(uint64_t amt_msat, uint32_t cltv,
                          const unsigned char *secret32, uint64_t total_msat,
                          unsigned char *out);

/* A BOLT 4 onion packet whose only (final) hop is node_pk, carrying tlv,
   with the HMAC over the associated data (the payment hash).  Returns 1. */
int test_build_final_onion(secp256k1_context *ctx,
                           const unsigned char session_key[32],
                           const secp256k1_pubkey *node_pk,
                           const unsigned char *tlv, size_t tlv_len,
                           const unsigned char *assoc, size_t assoc_len,
                           unsigned char onion[1366]);

#endif
