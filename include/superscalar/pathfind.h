/*
 * pathfind.h — Dijkstra pathfinding over the gossip graph
 *
 * Finds lowest-fee routes from our node to a destination pubkey.
 * Graph is loaded from gossip_store_t (SQLite).
 *
 * Reference: LDK lightning/src/routing/router.rs (Dijkstra + penalties),
 *            CLN plugins/askrene/algorithm.c (MCF),
 *            LND routing/pathfind.go (A*).
 *
 * We implement Dijkstra with LDK-style edge penalties (simpler than MCF).
 */

#ifndef SUPERSCALAR_PATHFIND_H
#define SUPERSCALAR_PATHFIND_H

#include <stdint.h>
#include <stddef.h>
#include "gossip_store.h"
#include "mission_control.h"
#include "pathfind_exclude.h"

#define PATHFIND_MAX_HOPS  20

/*
 * LDK risk factor for CLTV penalty.
 * Edge weight = fee_msat + cltv_delta * amount_msat * RISK_FACTOR / 1e9
 * LDK default: 15 (ns per msat)
 */
#define PATHFIND_RISK_FACTOR  15

typedef struct {
    uint64_t      scid;
    unsigned char node_id[33];      /* next-hop node pubkey */
    uint32_t      fee_base_msat;
    uint32_t      fee_ppm;
    uint16_t      cltv_expiry_delta;
    uint64_t      htlc_min_msat;
    uint64_t      htlc_max_msat;
} pathfind_hop_t;

typedef struct {
    pathfind_hop_t hops[PATHFIND_MAX_HOPS];
    int            n_hops;
    uint64_t       total_fee_msat;
    uint32_t       total_cltv;
} pathfind_route_t;

/*
 * pathfind_graph_t — opaque handle to a loaded routing graph.
 * Allocated and freed by pathfind_graph_alloc() / pathfind_graph_free().
 */
typedef struct pathfind_graph_s pathfind_graph_t;

/* Allocate an empty graph.  Returns NULL on OOM. */
pathfind_graph_t *pathfind_graph_alloc(void);

/* Free a graph allocated with pathfind_graph_alloc(). */
void pathfind_graph_free(pathfind_graph_t *g);

/* Populate graph from gossip store — clears the graph and reloads all
 * channel_updates from gs.
 * Returns number of directed edges loaded, or -1 on error. */
int pathfind_graph_load_from_gossip(pathfind_graph_t *g, gossip_store_t *gs);


/*
 * Find the lowest-fee single-path route from our_node to dest_pubkey
 * for amount_msat.
 * Loads the graph from the gossip_store DB.
 * Returns 1 on success, 0 if no path found.
 */
int pathfind_route(gossip_store_t *gs,
                   const unsigned char our_node[33],
                   const unsigned char dest_pubkey[33],
                   uint64_t amount_msat,
                   pathfind_route_t *out);

/*
 * MPP variant: find up to max_paths routes each carrying
 * roughly total_msat / max_paths.
 * Returns count of routes found (0 = failure).
 */
int pathfind_mpp_routes(gossip_store_t *gs,
                        const unsigned char our_node[33],
                        const unsigned char dest_pubkey[33],
                        uint64_t total_msat,
                        int max_paths,
                        pathfind_route_t *routes_out,
                        int max_out);

/*
 * Like pathfind_route() but skips channels penalised in mc.
 * mc may be NULL (falls back to plain pathfind_route).
 * current_height is the current block tip (used for MC penalty decay).
 * Returns 1 on success, 0 if no path found (or all paths excluded by MC).
 */
int pathfind_route_ex(gossip_store_t *gs,
                      const unsigned char our_node[33],
                      const unsigned char dest_pubkey[33],
                      uint64_t amount_msat,
                      uint32_t current_height,
                      mc_table_t *mc,
                      pathfind_route_t *out);

/* ---- Incremental graph cache ---- */

/*
 * pathfind_graph_cache_t — persistent routing graph cache with incremental refresh.
 *
 * On each use:
 *   - if cache is stale (> PATHFIND_CACHE_TTL_SECS since last full load): full reload
 *   - if fresh but newer updates exist (timestamp > last_gossip_ts): incremental patch
 *   - otherwise: reuse cached graph with no DB access
 *
 * Modelled on LDK NetworkGraph (atomic diff-apply) and LND lastUpdateTime delta filter.
 */
typedef struct pathfind_graph_cache pathfind_graph_cache_t;

#define PATHFIND_CACHE_TTL_SECS  30u

pathfind_graph_cache_t *pathfind_graph_cache_create(void);
void pathfind_graph_cache_destroy(pathfind_graph_cache_t *c);

/* Route using cached graph. Full reload if stale, incremental patch if fresh. */
int pathfind_route_cached(gossip_store_t *gs,
                           pathfind_graph_cache_t *c,
                           const unsigned char our_node[33],
                           const unsigned char dest_pubkey[33],
                           uint64_t amount_msat,
                           uint32_t now_unix,
                           pathfind_route_t *out);

/* Accessors for cache internals (used by tests) */
uint32_t pathfind_graph_cache_loaded_at(const pathfind_graph_cache_t *c);
uint32_t pathfind_graph_cache_last_gossip_ts(const pathfind_graph_cache_t *c);

#endif /* SUPERSCALAR_PATHFIND_H */
