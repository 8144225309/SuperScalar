/*
 * pathfind.c — Dijkstra pathfinding over the gossip graph
 *
 * Loads channel graph from gossip_store_t (SQLite).
 * Cost function: fee_base_msat + fee_ppm*amount/1e6 + cltv_delta*amount*RISK/1e9
 *
 * Reference: LDK lightning/src/routing/router.rs,
 *            CLN plugins/askrene/algorithm.c
 */

#include "superscalar/pathfind.h"
#include "superscalar/gossip_store.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sqlite3.h>

/* ---- Maximum graph size ---- */
#define MAX_NODES   4096
#define MAX_EDGES   32768

typedef struct {
    unsigned char pubkey[33];
    int           index;
} node_entry_t;

typedef struct {
    int      from_idx;
    int      to_idx;
    uint64_t scid;
    uint32_t fee_base_msat;
    uint32_t fee_ppm;
    uint16_t cltv_delta;
    uint64_t htlc_min_msat;
    uint64_t htlc_max_msat;
} edge_t;

/* ---- Graph ---- */
typedef struct {
    node_entry_t nodes[MAX_NODES];
    int          n_nodes;
    edge_t       edges[MAX_EDGES];
    int          n_edges;
} graph_t;

static int node_find_or_add(graph_t *g, const unsigned char pubkey[33]) {
    for (int i = 0; i < g->n_nodes; i++)
        if (memcmp(g->nodes[i].pubkey, pubkey, 33) == 0) return i;
    if (g->n_nodes >= MAX_NODES) return -1;
    memcpy(g->nodes[g->n_nodes].pubkey, pubkey, 33);
    g->nodes[g->n_nodes].index = g->n_nodes;
    return g->n_nodes++;
}

/* ---- Load graph from gossip_store ---- */
static int load_graph(gossip_store_t *gs, graph_t *g) {
    if (!gs || !gs->db) return 0;
    memset(g, 0, sizeof(*g));

    /* Join channels with channel_updates to build directed edges */
    const char *sql =
        "SELECT c.scid, c.node1_hex, c.node2_hex, "
        "       u.direction, u.fee_base_msat, u.fee_ppm, u.cltv_delta, "
        "       c.capacity_sat "
        "FROM gossip_channels c "
        "JOIN gossip_channel_updates u ON c.scid = u.scid "
        "WHERE c.pruned_at = 0";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(gs->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        uint64_t scid        = (uint64_t)sqlite3_column_int64(stmt, 0);
        const char *n1_hex   = (const char *)sqlite3_column_text(stmt, 1);
        const char *n2_hex   = (const char *)sqlite3_column_text(stmt, 2);
        int direction        = sqlite3_column_int(stmt, 3);
        uint32_t fee_base    = (uint32_t)sqlite3_column_int64(stmt, 4);
        uint32_t fee_ppm_val = (uint32_t)sqlite3_column_int64(stmt, 5);
        uint16_t cltv        = (uint16_t)sqlite3_column_int(stmt, 6);
        uint64_t cap_sat     = (uint64_t)sqlite3_column_int64(stmt, 7);

        if (!n1_hex || !n2_hex) continue;

        /* Decode hex pubkeys */
        unsigned char pk1[33], pk2[33];
        for (int i = 0; i < 33; i++) {
            unsigned int v1, v2;
            if (sscanf(n1_hex + i*2, "%02x", &v1) != 1) { v1 = 0; }
            if (sscanf(n2_hex + i*2, "%02x", &v2) != 1) { v2 = 0; }
            pk1[i] = (unsigned char)v1;
            pk2[i] = (unsigned char)v2;
        }

        int idx1 = node_find_or_add(g, pk1);
        int idx2 = node_find_or_add(g, pk2);
        if (idx1 < 0 || idx2 < 0) continue;
        if (g->n_edges >= MAX_EDGES) continue;

        /* direction 0 = node1→node2, direction 1 = node2→node1 */
        edge_t *e = &g->edges[g->n_edges++];
        e->scid         = scid;
        e->fee_base_msat = fee_base;
        e->fee_ppm      = fee_ppm_val;
        e->cltv_delta   = cltv;
        e->htlc_min_msat = 1;
        e->htlc_max_msat = cap_sat * 1000; /* conservative: full capacity */
        if (direction == 0) {
            e->from_idx = idx1;
            e->to_idx   = idx2;
        } else {
            e->from_idx = idx2;
            e->to_idx   = idx1;
        }
    }
    sqlite3_finalize(stmt);
    return 1;
}

/* ---- Dijkstra ---- */

#define DIST_INF  UINT64_MAX

typedef struct {
    uint64_t dist;
    int      prev_edge;   /* index into g->edges, -1 for source */
    int      visited;
} dijk_node_t;

static uint64_t edge_cost(const edge_t *e, uint64_t amount_msat) {
    uint64_t fee = (uint64_t)e->fee_base_msat +
                   (uint64_t)e->fee_ppm * amount_msat / 1000000ULL;
    uint64_t cltv_pen = (uint64_t)e->cltv_delta * amount_msat *
                        PATHFIND_RISK_FACTOR / 1000000000ULL;
    return fee + cltv_pen + 1; /* +1 to prefer fewer hops on tie */
}

static int dijkstra(const graph_t *g,
                    int src, int dst, uint64_t amount_msat,
                    dijk_node_t *nodes_out) {
    for (int i = 0; i < g->n_nodes; i++) {
        nodes_out[i].dist      = DIST_INF;
        nodes_out[i].prev_edge = -1;
        nodes_out[i].visited   = 0;
    }
    nodes_out[src].dist = 0;

    for (int iter = 0; iter < g->n_nodes; iter++) {
        /* Find unvisited node with minimum dist */
        int u = -1;
        for (int i = 0; i < g->n_nodes; i++) {
            if (!nodes_out[i].visited && nodes_out[i].dist != DIST_INF) {
                if (u == -1 || nodes_out[i].dist < nodes_out[u].dist)
                    u = i;
            }
        }
        if (u == -1 || u == dst) break;
        nodes_out[u].visited = 1;

        /* Relax outgoing edges */
        for (int ei = 0; ei < g->n_edges; ei++) {
            const edge_t *e = &g->edges[ei];
            if (e->from_idx != u) continue;
            int v = e->to_idx;
            if (nodes_out[v].visited) continue;

            /* HTLC amount constraints */
            if (amount_msat < e->htlc_min_msat) continue;
            if (e->htlc_max_msat > 0 && amount_msat > e->htlc_max_msat) continue;

            uint64_t w = edge_cost(e, amount_msat);
            uint64_t nd = nodes_out[u].dist + w;
            if (nd < nodes_out[u].dist) nd = DIST_INF; /* overflow guard */
            if (nd < nodes_out[v].dist) {
                nodes_out[v].dist      = nd;
                nodes_out[v].prev_edge = ei;
            }
        }
    }
    return (nodes_out[dst].dist != DIST_INF) ? 1 : 0;
}

/* ---- Extract path ---- */
static int extract_path(const graph_t *g, const dijk_node_t *dn,
                         int src, int dst,
                         uint64_t amount_msat,
                         pathfind_route_t *out) {
    memset(out, 0, sizeof(*out));

    /* Walk backwards from dst to src */
    int path_edges[PATHFIND_MAX_HOPS];
    int n_path = 0;
    int cur = dst;
    while (cur != src) {
        int ei = dn[cur].prev_edge;
        if (ei < 0 || n_path >= PATHFIND_MAX_HOPS) return 0;
        path_edges[n_path++] = ei;
        cur = g->edges[ei].from_idx;
    }

    /* Reverse */
    for (int i = 0; i < n_path / 2; i++) {
        int tmp = path_edges[i];
        path_edges[i] = path_edges[n_path - 1 - i];
        path_edges[n_path - 1 - i] = tmp;
    }

    out->n_hops = n_path;
    uint64_t total_fee = 0;
    uint32_t total_cltv = 0;

    for (int i = 0; i < n_path; i++) {
        const edge_t *e = &g->edges[path_edges[i]];
        pathfind_hop_t *hop = &out->hops[i];
        hop->scid             = e->scid;
        memcpy(hop->node_id, g->nodes[e->to_idx].pubkey, 33);
        hop->fee_base_msat    = e->fee_base_msat;
        hop->fee_ppm          = e->fee_ppm;
        hop->cltv_expiry_delta = e->cltv_delta;
        hop->htlc_min_msat    = e->htlc_min_msat;
        hop->htlc_max_msat    = e->htlc_max_msat;

        uint64_t fee = (uint64_t)e->fee_base_msat +
                       (uint64_t)e->fee_ppm * amount_msat / 1000000ULL;
        total_fee  += fee;
        total_cltv += e->cltv_delta;
    }
    out->total_fee_msat = total_fee;
    out->total_cltv     = total_cltv;
    return 1;
}

/* ---- Public API ---- */

int pathfind_route(gossip_store_t *gs,
                   const unsigned char our_node[33],
                   const unsigned char dest_pubkey[33],
                   uint64_t amount_msat,
                   pathfind_route_t *out) {
    if (!gs || !our_node || !dest_pubkey || !out || amount_msat == 0) return 0;

    graph_t *g = (graph_t *)malloc(sizeof(graph_t));
    if (!g) return 0;
    if (!load_graph(gs, g)) { free(g); return 0; }

    int src = -1, dst = -1;
    for (int i = 0; i < g->n_nodes; i++) {
        if (memcmp(g->nodes[i].pubkey, our_node, 33) == 0)  src = i;
        if (memcmp(g->nodes[i].pubkey, dest_pubkey, 33) == 0) dst = i;
    }
    if (src < 0 || dst < 0 || src == dst) { free(g); return 0; }

    dijk_node_t *dn = (dijk_node_t *)malloc(g->n_nodes * sizeof(dijk_node_t));
    if (!dn) { free(g); return 0; }

    int ok = dijkstra(g, src, dst, amount_msat, dn);
    if (ok) ok = extract_path(g, dn, src, dst, amount_msat, out);

    free(dn);
    free(g);
    return ok;
}

int pathfind_mpp_routes(gossip_store_t *gs,
                        const unsigned char our_node[33],
                        const unsigned char dest_pubkey[33],
                        uint64_t total_msat,
                        int max_paths,
                        pathfind_route_t *routes_out,
                        int max_out) {
    if (!gs || !our_node || !dest_pubkey || !routes_out || max_paths <= 0) return 0;
    if (max_paths > max_out) max_paths = max_out;

    uint64_t shard = total_msat / (uint64_t)max_paths;
    if (shard == 0) shard = 1;

    int found = 0;
    for (int i = 0; i < max_paths; i++) {
        if (pathfind_route(gs, our_node, dest_pubkey, shard, &routes_out[found]))
            found++;
    }
    return found;
}
