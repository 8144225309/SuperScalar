#ifndef SUPERSCALAR_RGS_H
#define SUPERSCALAR_RGS_H

/*
 * rgs.h — Rapid Gossip Sync (RGS) compact gossip format.
 *
 * RGS is a compact binary gossip format developed by LDK for fast initial
 * routing table sync. Clients download a single binary blob from a server
 * instead of fetching individual channel_announcement + channel_update msgs.
 *
 * Format (version 1):
 *   Header: "RGSV1\x00" (6 bytes)
 *   last_sync_timestamp: 4 bytes BE (Unix timestamp of snapshot)
 *   node_id_count: 3 bytes BE
 *   node_id_data: node_id_count * 33 bytes (compressed pubkeys)
 *   channel_count: 4 bytes BE
 *   channels[]: per-channel data (variable length)
 *
 * Each channel entry:
 *   short_channel_id: 8 bytes BE
 *   features: 2 bytes BE
 *   node_id_1_idx: 3 bytes BE (index into node_id_data)
 *   node_id_2_idx: 3 bytes BE
 *   funding_satoshis: 8 bytes BE
 *   update_count: 1 byte (0, 1, or 2 direction updates)
 *   updates[]: per-direction channel_update data
 *
 * Each channel_update:
 *   direction: 1 byte (0 = node1→node2, 1 = node2→node1)
 *   cltv_expiry_delta: 2 bytes BE
 *   htlc_minimum_msat: 8 bytes BE
 *   htlc_maximum_msat: 8 bytes BE
 *   fee_base_msat: 4 bytes BE
 *   fee_proportional_millionths: 4 bytes BE
 *   flags: 2 bytes BE (channel_flags: disabled bit, etc.)
 *   timestamp: 4 bytes BE
 *
 * Reference:
 *   LDK: lightning/src/routing/gossip.rs (RapidGossipSync)
 *   RGS server: https://rapidsync.lightningdevkit.org
 *   LDK-node: lightning-rapid-gossip-sync crate
 *   Zeus wallet: uses RGS for fast sync
 */

#include <stdint.h>
#include <stddef.h>

#define RGS_MAGIC   "RGSV1\x00"
#define RGS_MAGIC_LEN 6

#define RGS_MAX_NODE_IDS    8192
#define RGS_MAX_CHANNELS   16384
#define RGS_MAX_UPDATES_PER_CHAN 2

typedef struct {
    unsigned char pubkey[33];
} rgs_node_id_t;

typedef struct {
    int      direction;               /* 0 = n1→n2, 1 = n2→n1 */
    uint16_t cltv_expiry_delta;
    uint64_t htlc_minimum_msat;
    uint64_t htlc_maximum_msat;
    uint32_t fee_base_msat;
    uint32_t fee_proportional_millionths;
    uint16_t flags;                   /* channel_flags (1 = disabled) */
    uint32_t timestamp;
} rgs_channel_update_t;

typedef struct {
    uint64_t short_channel_id;
    uint16_t features;
    uint32_t node_id_1_idx;
    uint32_t node_id_2_idx;
    uint64_t funding_satoshis;
    int      update_count;            /* 0, 1, or 2 */
    rgs_channel_update_t updates[RGS_MAX_UPDATES_PER_CHAN];
} rgs_channel_t;

typedef struct {
    uint32_t last_sync_timestamp;
    uint32_t node_id_count;
    rgs_node_id_t *node_ids;          /* caller-allocated, node_id_count entries */
    uint32_t channel_count;
    rgs_channel_t *channels;          /* caller-allocated, channel_count entries */
} rgs_snapshot_t;

/* ---- Parsing ---- */

/*
 * Parse an RGS binary snapshot blob.
 * snap: caller-allocated snapshot struct with pre-allocated node_ids and channels arrays.
 * Returns 1 on success, 0 on parse error or unsupported version.
 *
 * snap->node_ids must point to an array of at least snap->node_id_count rgs_node_id_t.
 * snap->channels must point to an array of at least snap->channel_count rgs_channel_t.
 *
 * Simpler API: use rgs_parse_alloc() which allocates internally.
 */
int rgs_parse(const unsigned char *blob, size_t blob_len, rgs_snapshot_t *snap,
              rgs_node_id_t *node_buf, uint32_t node_cap,
              rgs_channel_t *chan_buf, uint32_t chan_cap);

/* ---- Building ---- */

/*
 * Build an RGS snapshot binary blob from a snapshot struct.
 * Returns bytes written, 0 on error (buffer too small or too many entries).
 */
size_t rgs_build(const rgs_snapshot_t *snap,
                  const rgs_node_id_t *node_ids,
                  const rgs_channel_t *channels,
                  unsigned char *out, size_t out_cap);

/* ---- Query helpers ---- */

/*
 * Find a channel by SCID in a parsed snapshot.
 * Returns pointer into channels array, or NULL if not found.
 */
const rgs_channel_t *rgs_find_channel(const rgs_snapshot_t *snap,
                                       const rgs_channel_t *channels,
                                       uint64_t scid);

/*
 * Get the active update for a given channel+direction.
 * Returns NULL if no update or if channel is disabled.
 */
const rgs_channel_update_t *rgs_get_update(const rgs_channel_t *chan, int direction);

/*
 * Count channels that have at least one enabled direction.
 */
uint32_t rgs_count_active_channels(const rgs_snapshot_t *snap,
                                    const rgs_channel_t *channels);

#endif /* SUPERSCALAR_RGS_H */
