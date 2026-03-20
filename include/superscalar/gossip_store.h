/*
 * gossip_store.h — SQLite-backed gossip data store
 *
 * Tables: gossip_nodes, gossip_channels, gossip_channel_updates
 * Designed for minimal-footprint LSP use: store enough to route HTLCs
 * to peers and verify payment path quality.
 */

#ifndef SUPERSCALAR_GOSSIP_STORE_H
#define SUPERSCALAR_GOSSIP_STORE_H

#include <stddef.h>
#include <stdint.h>
#include <sqlite3.h>

#define GOSSIP_STORE_ALIAS_MAX   33  /* 32-byte alias + NUL */
#define GOSSIP_STORE_ADDR_MAX    64  /* IP:port string + NUL */
#define GOSSIP_STORE_PUBKEY_MAX  67  /* 33-byte hex + NUL */
#define GOSSIP_STORE_SCID_MAX    32  /* "BLOCKxTXxOUT" string + NUL */

typedef struct {
    sqlite3 *db;
} gossip_store_t;

/* Open (or create) the gossip store at db_path.
   Returns 1 on success. */
int  gossip_store_open(gossip_store_t *gs, const char *db_path);

/* Open an in-memory gossip store (useful for unit tests). */
int  gossip_store_open_in_memory(gossip_store_t *gs);

void gossip_store_close(gossip_store_t *gs);

/*
 * Upsert a node record. pubkey33 is the 33-byte compressed pubkey.
 * alias: up to GOSSIP_STORE_ALIAS_MAX bytes (NUL-padded in BOLT #7).
 * address: "IP:port" or "host:port" string.
 * last_seen: Unix timestamp.
 */
int gossip_store_upsert_node(gossip_store_t *gs,
                              const unsigned char pubkey33[33],
                              const char *alias,
                              const char *address,
                              uint32_t    last_seen);

/* Retrieve a node by pubkey.  Returns 1 if found, 0 otherwise. */
int gossip_store_get_node(gossip_store_t *gs,
                           const unsigned char pubkey33[33],
                           char *alias_out,   size_t alias_cap,
                           char *addr_out,    size_t addr_cap,
                           uint32_t *last_seen_out);

/*
 * Upsert a channel record. scid is the 8-byte short_channel_id.
 * node1_33 / node2_33: the two endpoint pubkeys (node1 < node2 lexically).
 */
int gossip_store_upsert_channel(gossip_store_t *gs,
                                 uint64_t scid,
                                 const unsigned char node1_33[33],
                                 const unsigned char node2_33[33],
                                 uint64_t capacity_sats,
                                 uint32_t last_update);

/* Returns 1 if channel scid was found, 0 otherwise. */
int gossip_store_get_channel(gossip_store_t *gs,
                              uint64_t scid,
                              unsigned char node1_out[33],
                              unsigned char node2_out[33],
                              uint64_t *capacity_out,
                              uint32_t *last_update_out);

/*
 * Upsert a channel_update record.
 * direction: 0 (node1→node2) or 1 (node2→node1).
 */
int gossip_store_upsert_channel_update(gossip_store_t *gs,
                                        uint64_t scid,
                                        int      direction,
                                        uint32_t fee_base_msat,
                                        uint32_t fee_ppm,
                                        uint16_t cltv_delta,
                                        uint32_t timestamp);

/* Returns 1 if found, 0 otherwise. */
int gossip_store_get_channel_update(gossip_store_t *gs,
                                     uint64_t scid,
                                     int      direction,
                                     uint32_t *fee_base_out,
                                     uint32_t *fee_ppm_out,
                                     uint16_t *cltv_delta_out,
                                     uint32_t *timestamp_out);

/* --- Stale channel pruning --- */

#define GOSSIP_PRUNE_SECS   1209600u   /* 14 days — standard across CLN/LND/Eclair */
#define GOSSIP_GRACE_SECS    604800u   /* 7 days tracking after removal (LDK) */

/*
 * Remove channel_updates older than GOSSIP_PRUNE_SECS, then remove
 * gossip_channels where both directions are stale (or never updated).
 * Returns count of channels removed, or -1 on error.
 */
int gossip_store_prune_stale(gossip_store_t *gs, uint32_t now_unix);

/*
 * Mark a channel as spent (funding output confirmed spent on-chain).
 * Sets pruned_at = now_unix; rows with pruned_at + GOSSIP_GRACE_SECS <= now
 * are hard-deleted on the next call to gossip_store_prune_stale.
 * Returns 1 on success, 0 on error.
 */
int gossip_store_mark_channel_spent(gossip_store_t *gs,
                                     uint64_t scid, uint32_t now_unix);

/* Callback type for channel iteration */
typedef void (*gossip_store_channel_cb_t)(uint64_t scid,
    const unsigned char node1[33], const unsigned char node2[33],
    void *userdata);

/* Iterate channels matching a list of SCIDs. Calls cb for each found channel. */
int gossip_store_get_channels_by_scids(gossip_store_t *gs,
    const uint64_t *scids, int n_scids,
    gossip_store_channel_cb_t cb, void *userdata);

/* Iterate channels whose SCID block is in [first_blocknum, first_blocknum+num_blocks).
   SCID block = scid >> 40. */
int gossip_store_get_channels_in_range(gossip_store_t *gs,
    uint32_t first_blocknum, uint32_t num_blocks,
    gossip_store_channel_cb_t cb, void *userdata);

/* Callback for gossip_store_enumerate_channels.
 * Called once per (scid, direction) row that has a channel_update.
 * src_pubkey/dst_pubkey reflect the direction: direction 0 means node1 is src,
 * direction 1 means node2 is src. */
typedef void (*gossip_store_full_channel_cb_t)(
    uint64_t scid,
    const unsigned char src_pubkey[33],
    const unsigned char dst_pubkey[33],
    uint32_t fee_base_msat,
    uint32_t fee_ppm,
    uint16_t cltv_delta,
    uint64_t htlc_min_msat,
    uint64_t htlc_max_msat,
    uint64_t capacity_sat,
    void *ctx);

/* Enumerate all (channel, channel_update) directed edges from the gossip store.
 * Calls cb() once per (scid, direction) row.  Returns count of edges, -1 on error. */
int gossip_store_enumerate_channels(gossip_store_t *gs,
                                     gossip_store_full_channel_cb_t cb,
                                     void *ctx);

/* Like gossip_store_enumerate_channels() but only returns directed edges whose
 * channel_update timestamp > since_ts.  Used for incremental graph refresh.
 * Returns count of edges, -1 on error. */
int gossip_store_enumerate_channels_since(gossip_store_t *gs,
                                           uint32_t since_ts,
                                           gossip_store_full_channel_cb_t cb,
                                           void *ctx);

/* Export current gossip store state as an RGS (Rapid Gossip Sync) binary blob.
 * Returns bytes written to out, or 0 on error. */
size_t gossip_store_export_rgs(gossip_store_t *gs, unsigned char *out, size_t out_cap);

#endif /* SUPERSCALAR_GOSSIP_STORE_H */
