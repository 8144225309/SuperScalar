/*
 * scid_registry.c — Fake SCID encode/decode + BOLT #11 route hint builder
 */

#include "superscalar/scid_registry.h"
#include <string.h>

uint64_t scid_encode(uint32_t factory_id, uint32_t leaf_idx) {
    return ((uint64_t)(factory_id & 0xFFFFFF) << 40)
         | ((uint64_t)(leaf_idx  & 0xFFFFFF) << 16);
}

void scid_decode(uint64_t scid,
                 uint32_t *factory_id_out,
                 uint32_t *leaf_idx_out) {
    if (factory_id_out) *factory_id_out = (uint32_t)((scid >> 40) & 0xFFFFFF);
    if (leaf_idx_out)   *leaf_idx_out   = (uint32_t)((scid >> 16) & 0xFFFFFF);
}

int scid_route_hint(unsigned char out[51],
                    const unsigned char node_id33[33],
                    uint64_t scid,
                    uint32_t fee_base_msat,
                    uint32_t fee_proportional_millionths,
                    uint16_t cltv_expiry_delta) {
    if (!out || !node_id33) return 0;

    /* pubkey(33) */
    memcpy(out, node_id33, 33);
    size_t off = 33;

    /* scid(8) big-endian */
    out[off++] = (unsigned char)(scid >> 56);
    out[off++] = (unsigned char)(scid >> 48);
    out[off++] = (unsigned char)(scid >> 40);
    out[off++] = (unsigned char)(scid >> 32);
    out[off++] = (unsigned char)(scid >> 24);
    out[off++] = (unsigned char)(scid >> 16);
    out[off++] = (unsigned char)(scid >>  8);
    out[off++] = (unsigned char)(scid);

    /* fee_base_msat(4) big-endian */
    out[off++] = (unsigned char)(fee_base_msat >> 24);
    out[off++] = (unsigned char)(fee_base_msat >> 16);
    out[off++] = (unsigned char)(fee_base_msat >>  8);
    out[off++] = (unsigned char)(fee_base_msat);

    /* fee_proportional_millionths(4) big-endian */
    out[off++] = (unsigned char)(fee_proportional_millionths >> 24);
    out[off++] = (unsigned char)(fee_proportional_millionths >> 16);
    out[off++] = (unsigned char)(fee_proportional_millionths >>  8);
    out[off++] = (unsigned char)(fee_proportional_millionths);

    /* cltv_expiry_delta(2) big-endian */
    out[off++] = (unsigned char)(cltv_expiry_delta >> 8);
    out[off++] = (unsigned char)(cltv_expiry_delta);

    return (off == 51) ? 1 : 0;
}
