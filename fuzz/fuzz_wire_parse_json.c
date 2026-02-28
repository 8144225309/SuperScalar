/*
 * fuzz_wire_parse_json.c — libFuzzer harness for wire_parse_*() functions.
 *
 * Input: arbitrary bytes interpreted as a JSON string.
 * If valid JSON, feeds through each wire_parse_*() function.
 * Must never crash regardless of JSON structure.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "superscalar/wire.h"
#include <cJSON.h>
#include <secp256k1.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* NUL-terminate for cJSON_Parse */
    char *str = (char *)malloc(size + 1);
    if (!str) return 0;
    memcpy(str, data, size);
    str[size] = '\0';

    cJSON *json = cJSON_Parse(str);
    free(str);
    if (!json) return 0;

    /* Try each parser — none should crash on arbitrary JSON */

    /* update_add_htlc */
    {
        uint64_t htlc_id, amount_msat;
        unsigned char payment_hash[32];
        uint32_t cltv_expiry;
        wire_parse_update_add_htlc(json, &htlc_id, &amount_msat,
                                     payment_hash, &cltv_expiry);
    }

    /* commitment_signed */
    {
        uint32_t channel_id, nonce_index;
        uint64_t commitment_number;
        unsigned char psig[32];
        wire_parse_commitment_signed(json, &channel_id, &commitment_number,
                                       psig, &nonce_index);
    }

    /* revoke_and_ack */
    {
        uint32_t channel_id;
        unsigned char secret[32], point[33];
        wire_parse_revoke_and_ack(json, &channel_id, secret, point);
    }

    /* channel_ready */
    {
        uint32_t channel_id;
        uint64_t local_msat, remote_msat;
        wire_parse_channel_ready(json, &channel_id, &local_msat, &remote_msat);
    }

    /* update_fulfill_htlc */
    {
        uint64_t htlc_id;
        unsigned char preimage[32];
        wire_parse_update_fulfill_htlc(json, &htlc_id, preimage);
    }

    /* update_fail_htlc */
    {
        uint64_t htlc_id;
        char reason[256];
        wire_parse_update_fail_htlc(json, &htlc_id, reason, sizeof(reason));
    }

    /* bridge_add_htlc */
    {
        unsigned char payment_hash[32];
        uint64_t amount_msat, htlc_id;
        uint32_t cltv_expiry;
        wire_parse_bridge_add_htlc(json, payment_hash, &amount_msat,
                                     &cltv_expiry, &htlc_id);
    }

    /* bridge_fulfill_htlc */
    {
        unsigned char payment_hash[32], preimage[32];
        uint64_t htlc_id;
        wire_parse_bridge_fulfill_htlc(json, payment_hash, preimage, &htlc_id);
    }

    /* bridge_fail_htlc */
    {
        unsigned char payment_hash[32];
        char reason[256];
        uint64_t htlc_id;
        wire_parse_bridge_fail_htlc(json, payment_hash, reason,
                                      sizeof(reason), &htlc_id);
    }

    /* register_invoice */
    {
        unsigned char payment_hash[32];
        unsigned char preimage[32];
        uint64_t amount_msat;
        size_t dest_client;
        wire_parse_register_invoice(json, payment_hash, preimage, &amount_msat,
                                      &dest_client);
    }

    /* channel_basepoints (needs secp context) */
    {
        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        uint32_t channel_id;
        secp256k1_pubkey p1, p2, p3, p4, p5, p6;
        wire_parse_channel_basepoints(json, &channel_id, ctx,
                                        &p1, &p2, &p3, &p4, &p5, &p6);
        secp256k1_context_destroy(ctx);
    }

    cJSON_Delete(json);
    return 0;
}
