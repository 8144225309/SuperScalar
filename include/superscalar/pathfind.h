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

#endif /* SUPERSCALAR_PATHFIND_H */
