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
#include "superscalar/mission_control.h"
#include "superscalar/pathfind_exclude.h"
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
struct pathfind_graph_s {
    node_entry_t nodes[MAX_NODES];
    int          n_nodes;
    edge_t       edges[MAX_EDGES];
    int          n_edges;
};
typedef struct pathfind_graph_s graph_t;

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

/* ---- pathfind_route_ex: route with MC exclusion ---- */
/*
 * Runs Dijkstra over the gossip graph, skipping edges whose (scid, direction)
 * is currently penalised by mc.  This lets the router avoid failed channels
 * on the INITIAL route attempt rather than only on retries.
 */
int pathfind_route_ex(gossip_store_t *gs,
                      const unsigned char our_node[33],
                      const unsigned char dest_pubkey[33],
                      uint64_t amount_msat,
                      uint32_t current_height,
                      mc_table_t *mc,
                      pathfind_route_t *out)
{
    /* Without MC, fall back to plain Dijkstra */
    if (!mc)
        return pathfind_route(gs, our_node, dest_pubkey, amount_msat, out);

    if (!gs || !our_node || !dest_pubkey || !out || amount_msat == 0) return 0;

    /* Build exclusion list from mission control */
    pathfind_exclude_t ex;
    pathfind_exclude_init(&ex);
    pathfind_exclude_from_mc(&ex, mc, amount_msat, current_height);

    /* Load graph */
    graph_t *g = (graph_t *)malloc(sizeof(graph_t));
    if (!g) return 0;
    if (!load_graph(gs, g)) { free(g); return 0; }

    int src = -1, dst = -1;
    for (int i = 0; i < g->n_nodes; i++) {
        if (memcmp(g->nodes[i].pubkey, our_node,    33) == 0) src = i;
        if (memcmp(g->nodes[i].pubkey, dest_pubkey, 33) == 0) dst = i;
    }
    if (src < 0 || dst < 0 || src == dst) { free(g); return 0; }

    /* Mark excluded edges so Dijkstra skips them.
     * We temporarily set htlc_max_msat=0 for excluded edges; Dijkstra
     * already skips edges where amount_msat > htlc_max_msat > 0.
     * We save/restore to avoid corrupting the graph for future calls.
     */
    uint64_t saved_max[MAX_EDGES];
    for (int ei = 0; ei < g->n_edges; ei++) {
        edge_t *e = &g->edges[ei];
        saved_max[ei] = e->htlc_max_msat;
        /* Determine direction for this edge: direction 0 means from < to */
        int dir = (e->from_idx < e->to_idx) ? 0 : 1;
        if (pathfind_exclude_is_excluded(&ex, e->scid, dir) ||
            pathfind_exclude_is_excluded(&ex, e->scid, 1 - dir) ||
            pathfind_exclude_is_excluded(&ex, e->scid, -1)) {
            /* Poison edge: set max below amount so Dijkstra skips it */
            e->htlc_max_msat = (amount_msat > 0) ? (amount_msat - 1) : 0;
        }
    }

    dijk_node_t *dn = (dijk_node_t *)malloc(g->n_nodes * sizeof(dijk_node_t));
    int ok = 0;
    if (dn) {
        ok = dijkstra(g, src, dst, amount_msat, dn);
        if (ok) ok = extract_path(g, dn, src, dst, amount_msat, out);
        free(dn);
    }

    /* Restore poisoned edge max values */
    for (int ei = 0; ei < g->n_edges; ei++)
        g->edges[ei].htlc_max_msat = saved_max[ei];

    free(g);
    return ok;
}

/* ---- Public graph management API ---- */

pathfind_graph_t *pathfind_graph_alloc(void) {
    graph_t *g = (graph_t *)calloc(1, sizeof(graph_t));
    return (pathfind_graph_t *)g;
}

void pathfind_graph_free(pathfind_graph_t *g) {
    free(g);
}

/*
 * pathfind_graph_load_from_gossip — populate a graph from live gossip data.
 *
 * Uses gossip_store_enumerate_channels() which joins gossip_channels with
 * gossip_channel_updates to emit one directed edge per (scid, direction).
 * The graph is cleared before loading.
 *
 * Returns number of directed edges loaded, or -1 on error.
 */

typedef struct {
    graph_t *g;
    int      count;
} load_ctx_t;

static void load_edge_cb(uint64_t scid,
                          const unsigned char src_pubkey[33],
                          const unsigned char dst_pubkey[33],
                          uint32_t fee_base_msat,
                          uint32_t fee_ppm,
                          uint16_t cltv_delta,
                          uint64_t htlc_min_msat,
                          uint64_t htlc_max_msat,
                          uint64_t capacity_sat,
                          void *ctx)
{
    load_ctx_t *lc = (load_ctx_t *)ctx;
    graph_t    *g  = lc->g;

    (void)capacity_sat; /* already encoded in htlc_max_msat */

    int idx_src = node_find_or_add(g, src_pubkey);
    int idx_dst = node_find_or_add(g, dst_pubkey);
    if (idx_src < 0 || idx_dst < 0) return;
    if (g->n_edges >= MAX_EDGES) return;

    edge_t *e       = &g->edges[g->n_edges++];
    e->scid         = scid;
    e->from_idx     = idx_src;
    e->to_idx       = idx_dst;
    e->fee_base_msat = fee_base_msat;
    e->fee_ppm      = fee_ppm;
    e->cltv_delta   = cltv_delta;
    e->htlc_min_msat = htlc_min_msat;
    e->htlc_max_msat = htlc_max_msat;

    lc->count++;
}

int pathfind_graph_load_from_gossip(pathfind_graph_t *g, gossip_store_t *gs)
{
    if (!g || !gs) return -1;
    /* Clear the graph */
    memset(g, 0, sizeof(graph_t));

    load_ctx_t lc = { (graph_t *)g, 0 };
    int ret = gossip_store_enumerate_channels(gs, load_edge_cb, &lc);
    if (ret < 0) return -1;
    return lc.count;
}

/* ================================================================== */
/* PR #70: Incremental graph cache                                     */
/* ================================================================== */

struct pathfind_graph_cache {
    graph_t  *g;               /* heap-allocated graph; NULL if not yet loaded */
    uint32_t  last_gossip_ts;  /* MAX(timestamp) across all loaded edges */
    uint32_t  loaded_at;       /* Unix time of last full reload */
};

pathfind_graph_cache_t *pathfind_graph_cache_create(void)
{
    pathfind_graph_cache_t *c =
        (pathfind_graph_cache_t *)calloc(1, sizeof(pathfind_graph_cache_t));
    return c;
}

void pathfind_graph_cache_destroy(pathfind_graph_cache_t *c)
{
    if (!c) return;
    free(c->g);
    free(c);
}

/* Context passed to patch_edge_cb during incremental refresh */
typedef struct {
    graph_t  *g;
    int       count;
} patch_ctx_t;

/*
 * patch_edge_cb -- update an existing edge in-place or append a new edge.
 * Called by gossip_store_enumerate_channels_since() for each updated edge.
 * If the (scid, direction encoded as from_idx == idx_src, to_idx == idx_dst)
 * edge already exists, its fee/cltv fields are overwritten.
 * Otherwise a new edge is appended.
 */
static void patch_edge_cb(uint64_t scid,
                           const unsigned char src_pubkey[33],
                           const unsigned char dst_pubkey[33],
                           uint32_t fee_base_msat,
                           uint32_t fee_ppm,
                           uint16_t cltv_delta,
                           uint64_t htlc_min_msat,
                           uint64_t htlc_max_msat,
                           uint64_t capacity_sat,
                           void *ctx)
{
    patch_ctx_t *pc = (patch_ctx_t *)ctx;
    graph_t     *g  = pc->g;

    (void)capacity_sat;

    int idx_src = node_find_or_add(g, src_pubkey);
    int idx_dst = node_find_or_add(g, dst_pubkey);
    if (idx_src < 0 || idx_dst < 0) return;

    /* Search for existing edge with same scid and same direction */
    for (int ei = 0; ei < g->n_edges; ei++) {
        edge_t *e = &g->edges[ei];
        if (e->scid == scid &&
            e->from_idx == idx_src &&
            e->to_idx   == idx_dst) {
            /* Update in-place */
            e->fee_base_msat  = fee_base_msat;
            e->fee_ppm        = fee_ppm;
            e->cltv_delta     = cltv_delta;
            e->htlc_min_msat  = htlc_min_msat;
            e->htlc_max_msat  = htlc_max_msat;
            pc->count++;
            return;
        }
    }

    /* New edge -- append */
    if (g->n_edges >= MAX_EDGES) return;
    edge_t *e       = &g->edges[g->n_edges++];
    e->scid         = scid;
    e->from_idx     = idx_src;
    e->to_idx       = idx_dst;
    e->fee_base_msat = fee_base_msat;
    e->fee_ppm      = fee_ppm;
    e->cltv_delta   = cltv_delta;
    e->htlc_min_msat = htlc_min_msat;
    e->htlc_max_msat = htlc_max_msat;
    pc->count++;
}

/*
 * query_max_ts -- query MAX(timestamp) from gossip_channel_updates.
 * If since_ts == 0, returns the global max (used after full reload).
 * If since_ts > 0, returns the max among rows with timestamp > since_ts
 *   (used to detect whether an incremental patch is needed).
 * Returns 0 if no rows found or on error.
 */
static uint32_t query_max_ts(gossip_store_t *gs, uint32_t since_ts)
{
    if (!gs || !gs->db) return 0;

    sqlite3_stmt *stmt = NULL;
    const char *sql_all   = "SELECT MAX(timestamp) FROM gossip_channel_updates;";
    const char *sql_since = "SELECT MAX(timestamp) FROM gossip_channel_updates WHERE timestamp > ?;";

    const char *sql = (since_ts == 0) ? sql_all : sql_since;
    if (sqlite3_prepare_v2(gs->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    if (since_ts != 0)
        sqlite3_bind_int64(stmt, 1, (sqlite3_int64)since_ts);

    uint32_t result = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW &&
        sqlite3_column_type(stmt, 0) != SQLITE_NULL)
        result = (uint32_t)sqlite3_column_int64(stmt, 0);

    sqlite3_finalize(stmt);
    return result;
}

int pathfind_route_cached(gossip_store_t *gs,
                           pathfind_graph_cache_t *c,
                           const unsigned char our_node[33],
                           const unsigned char dest_pubkey[33],
                           uint64_t amount_msat,
                           uint32_t now_unix,
                           pathfind_route_t *out)
{
    if (!gs || !c || !our_node || !dest_pubkey || !out || amount_msat == 0)
        return 0;

    int need_full = (c->g == NULL) ||
                    ((now_unix - c->loaded_at) > PATHFIND_CACHE_TTL_SECS);

    if (need_full) {
        /* Full reload */
        if (!c->g) {
            c->g = (graph_t *)malloc(sizeof(graph_t));
            if (!c->g) return 0;
        }
        memset(c->g, 0, sizeof(graph_t));

        load_ctx_t lc = { c->g, 0 };
        gossip_store_enumerate_channels(gs, load_edge_cb, &lc);

        c->loaded_at      = now_unix;
        c->last_gossip_ts = query_max_ts(gs, 0);

    } else {
        /* Check for incremental updates newer than what we loaded */
        uint32_t newer_ts = query_max_ts(gs, c->last_gossip_ts);
        if (newer_ts > c->last_gossip_ts) {
            /* Incremental patch -- only reload changed edges */
            patch_ctx_t pc = { c->g, 0 };
            gossip_store_enumerate_channels_since(gs, c->last_gossip_ts,
                                                  patch_edge_cb, &pc);
            c->last_gossip_ts = newer_ts;
        }
        /* else: graph is fully up to date -- no DB access needed */
    }

    /* Run Dijkstra on the cached graph */
    graph_t *g = c->g;
    if (!g || g->n_nodes == 0) return 0;

    int src = -1, dst = -1;
    for (int i = 0; i < g->n_nodes; i++) {
        if (memcmp(g->nodes[i].pubkey, our_node,    33) == 0) src = i;
        if (memcmp(g->nodes[i].pubkey, dest_pubkey, 33) == 0) dst = i;
    }
    if (src < 0 || dst < 0 || src == dst) return 0;

    dijk_node_t *dn = (dijk_node_t *)malloc(g->n_nodes * sizeof(dijk_node_t));
    if (!dn) return 0;

    int ok = dijkstra(g, src, dst, amount_msat, dn);
    if (ok) ok = extract_path(g, dn, src, dst, amount_msat, out);

    free(dn);
    return ok;
}

/* ---- Cache accessors (used by tests) ---- */

uint32_t pathfind_graph_cache_loaded_at(const pathfind_graph_cache_t *c)
{
    return c ? c->loaded_at : 0;
}

uint32_t pathfind_graph_cache_last_gossip_ts(const pathfind_graph_cache_t *c)
{
    return c ? c->last_gossip_ts : 0;
}
