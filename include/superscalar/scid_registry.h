/*
 * scid_registry.h — Fake short_channel_id (SCID) registry for factory leaves
 *
 * Each factory leaf is assigned a fake SCID used in BOLT #11 route hints.
 * SCID format (8 bytes, big-endian):
 *   bits 63-40: block_height (24 bits) = factory_id (internal ID)
 *   bits 39-16: tx_index    (24 bits) = leaf_idx
 *   bits 15-0:  output_index (16 bits) = 0
 */

#ifndef SUPERSCALAR_SCID_REGISTRY_H
#define SUPERSCALAR_SCID_REGISTRY_H

#include <stdint.h>
#include <stddef.h>

/* Encode a factory leaf → SCID. */
uint64_t scid_encode(uint32_t factory_id, uint32_t leaf_idx);

/* Decode SCID → factory_id and leaf_idx. */
void scid_decode(uint64_t scid, uint32_t *factory_id_out, uint32_t *leaf_idx_out);

/*
 * Build a BOLT #11 route hint record for a fake SCID.
 *
 * Route hint wire format (51 bytes):
 *   pubkey(33) + short_channel_id(8) + fee_base_msat(4)
 *   + fee_proportional_millionths(4) + cltv_expiry_delta(2)
 *
 * Returns 1 on success.
 */
int scid_route_hint(unsigned char out[51],
                    const unsigned char node_id33[33],
                    uint64_t scid,
                    uint32_t fee_base_msat,
                    uint32_t fee_proportional_millionths,
                    uint16_t cltv_expiry_delta);

#endif /* SUPERSCALAR_SCID_REGISTRY_H */
