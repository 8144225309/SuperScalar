/*
 * test_pathfind.c — Unit tests for Dijkstra pathfinding over gossip graph
 */

#include "superscalar/pathfind.h"
#include "superscalar/gossip_store.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* ---- Helpers ---- */
static void make_pubkey(unsigned char pk[33], int seed) {
    memset(pk, 0, 33);
    pk[0] = 0x02;
    pk[1] = (unsigned char)seed;
    pk[2] = (unsigned char)(seed >> 8);
}

static int build_test_graph(gossip_store_t *gs) {
    /* Create a simple graph: A → B → C (two hops) */
    unsigned char pka[33], pkb[33], pkc[33];
    make_pubkey(pka, 1);
    make_pubkey(pkb, 2);
    make_pubkey(pkc, 3);

    uint32_t now = 1700000000;

    /* Add nodes */
    gossip_store_upsert_node(gs, pka, "A", "127.0.0.1:9735", now);
    gossip_store_upsert_node(gs, pkb, "B", "127.0.0.1:9736", now);
    gossip_store_upsert_node(gs, pkc, "C", "127.0.0.1:9737", now);

    /* Channel A-B (scid=1) */
    gossip_store_upsert_channel(gs, 1, pka, pkb, 1000000, now);
    gossip_store_upsert_channel_update(gs, 1, 0, /* dir A→B */
                                        1000, 100, 40, now);
    gossip_store_upsert_channel_update(gs, 1, 1, /* dir B→A */
                                        1000, 100, 40, now);

    /* Channel B-C (scid=2) */
    gossip_store_upsert_channel(gs, 2, pkb, pkc, 1000000, now);
    gossip_store_upsert_channel_update(gs, 2, 0, /* dir B→C */
                                        500, 50, 20, now);
    gossip_store_upsert_channel_update(gs, 2, 1, /* dir C→B */
                                        500, 50, 20, now);
    return 1;
}

/* ---- Test P1: simple two-hop route found ---- */
int test_pathfind_two_hops(void)
{
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open in-memory store");
    ASSERT(build_test_graph(&gs), "build test graph");

    unsigned char pka[33], pkc[33];
    make_pubkey(pka, 1);
    make_pubkey(pkc, 3);

    pathfind_route_t route;
    int ok = pathfind_route(&gs, pka, pkc, 50000, &route);
    ASSERT(ok, "route found");
    ASSERT(route.n_hops == 2, "two hops");
    ASSERT(route.total_fee_msat > 0, "non-zero fee");
    ASSERT(route.total_cltv > 0, "non-zero CLTV");

    /* First hop should be the A→B channel */
    ASSERT(route.hops[0].scid == 1, "first hop is A→B channel");
    /* Second hop should be B→C */
    ASSERT(route.hops[1].scid == 2, "second hop is B→C channel");

    gossip_store_close(&gs);
    return 1;
}

/* ---- Test P2: direct route (one hop) ---- */
int test_pathfind_one_hop(void)
{
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open in-memory store");
    ASSERT(build_test_graph(&gs), "build test graph");

    unsigned char pka[33], pkb[33];
    make_pubkey(pka, 1);
    make_pubkey(pkb, 2);

    pathfind_route_t route;
    int ok = pathfind_route(&gs, pka, pkb, 10000, &route);
    ASSERT(ok, "direct route found");
    ASSERT(route.n_hops == 1, "one hop");
    ASSERT(route.hops[0].scid == 1, "correct channel");

    gossip_store_close(&gs);
    return 1;
}

/* ---- Test P3: no route (disconnected graph) ---- */
int test_pathfind_no_route(void)
{
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open in-memory store");

    /* Only add one node, no channels */
    unsigned char pka[33], pkb[33];
    make_pubkey(pka, 1);
    make_pubkey(pkb, 99);
    gossip_store_upsert_node(&gs, pka, "A", "", 1700000000);

    pathfind_route_t route;
    int ok = pathfind_route(&gs, pka, pkb, 10000, &route);
    ASSERT(!ok, "no route for disconnected nodes");

    gossip_store_close(&gs);
    return 1;
}

/* ---- Test P4: MPP finds multiple routes ---- */
int test_pathfind_mpp(void)
{
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open in-memory store");
    ASSERT(build_test_graph(&gs), "build test graph");

    unsigned char pka[33], pkc[33];
    make_pubkey(pka, 1);
    make_pubkey(pkc, 3);

    pathfind_route_t routes[4];
    int n = pathfind_mpp_routes(&gs, pka, pkc, 100000, 2, routes, 4);
    /* Should find at least 1 route (same path used for both shards) */
    ASSERT(n >= 1, "at least one MPP route");

    gossip_store_close(&gs);
    return 1;
}
/* ---- PF_MC1: pathfind_route_ex with NULL mc == pathfind_route ---- */
int test_pathfind_mc1_null_mc(void)
{
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open in-memory store");
    ASSERT(build_test_graph(&gs), "build test graph");

    unsigned char pka[33], pkc[33];
    make_pubkey(pka, 1);
    make_pubkey(pkc, 3);

    pathfind_route_t route_plain, route_ex;
    int ok_plain = pathfind_route(&gs, pka, pkc, 50000, &route_plain);
    int ok_ex    = pathfind_route_ex(&gs, pka, pkc, 50000, 800000, NULL, &route_ex);

    ASSERT(ok_plain == ok_ex, "same result code");
    ASSERT(route_plain.n_hops == route_ex.n_hops, "same hop count");

    gossip_store_close(&gs);
    return 1;
}

/* ---- PF_MC2: pathfind_route_ex with empty mc finds route normally ---- */
int test_pathfind_mc2_empty_mc(void)
{
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open in-memory store");
    ASSERT(build_test_graph(&gs), "build test graph");

    unsigned char pka[33], pkc[33];
    make_pubkey(pka, 1);
    make_pubkey(pkc, 3);

    mc_table_t mc;
    mc_init(&mc);  /* empty -- no penalties */

    pathfind_route_t route;
    int ok = pathfind_route_ex(&gs, pka, pkc, 50000, 800000, &mc, &route);
    ASSERT(ok == 1, "route found with empty mc");
    ASSERT(route.n_hops == 2, "two hops");

    gossip_store_close(&gs);
    return 1;
}

/* ---- PF_MC3: mc penalises only channel -> no route ---- */
int test_pathfind_mc3_penalised_only_path(void)
{
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open in-memory store");
    ASSERT(build_test_graph(&gs), "build test graph");

    unsigned char pka[33], pkb[33];
    make_pubkey(pka, 1);
    make_pubkey(pkb, 2);

    mc_table_t mc;
    mc_init(&mc);

    /* Record fresh failure on scid=1 (A->B) for the amount we will query */
    uint32_t now = 1700000000u;
    mc_record_failure(&mc, 1, 0, 10000, now);

    /* Route from A to B uses only scid=1; with MC penalty it should be excluded */
    pathfind_route_t route;
    int ok = pathfind_route_ex(&gs, pka, pkb, 10000, 800000, &mc, &route);
    ASSERT(ok == 0, "no route when only channel is penalised");

    gossip_store_close(&gs);
    return 1;
}

/* ---- PF_MC4: two parallel paths, mc penalises one ---- */
int test_pathfind_mc4_parallel_paths(void)
{
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open in-memory store");

    /* Build graph: A --scid1-- B (direct)
                    A --scid3-- D --scid4-- B (alternate) */
    unsigned char pka[33], pkb[33], pkd[33];
    make_pubkey(pka, 1);
    make_pubkey(pkb, 2);
    make_pubkey(pkd, 4);
    uint32_t now = 1700000000u;

    gossip_store_upsert_node(&gs, pka, "A", "127.0.0.1:9735", now);
    gossip_store_upsert_node(&gs, pkb, "B", "127.0.0.1:9736", now);
    gossip_store_upsert_node(&gs, pkd, "D", "127.0.0.1:9738", now);

    /* Direct A->B (scid=1) */
    gossip_store_upsert_channel(&gs, 1, pka, pkb, 1000000, now);
    gossip_store_upsert_channel_update(&gs, 1, 0, 1000, 100, 40, now);
    gossip_store_upsert_channel_update(&gs, 1, 1, 1000, 100, 40, now);

    /* Alternate A->D (scid=3) */
    gossip_store_upsert_channel(&gs, 3, pka, pkd, 1000000, now);
    gossip_store_upsert_channel_update(&gs, 3, 0, 1000, 100, 40, now);
    gossip_store_upsert_channel_update(&gs, 3, 1, 1000, 100, 40, now);

    /* Alternate D->B (scid=4) */
    gossip_store_upsert_channel(&gs, 4, pkd, pkb, 1000000, now);
    gossip_store_upsert_channel_update(&gs, 4, 0, 1000, 100, 40, now);
    gossip_store_upsert_channel_update(&gs, 4, 1, 1000, 100, 40, now);

    mc_table_t mc;
    mc_init(&mc);
    /* Penalise direct channel scid=1 */
    mc_record_failure(&mc, 1, 0, 10000, now);

    pathfind_route_t route;
    int ok = pathfind_route_ex(&gs, pka, pkb, 10000, 800000, &mc, &route);
    ASSERT(ok == 1, "route found via alternate path");
    /* The route should NOT use scid=1 */
    for (int h = 0; h < route.n_hops; h++) {
        ASSERT(route.hops[h].scid != 1, "penalised channel not used");
    }

    gossip_store_close(&gs);
    return 1;
}

/* ================================================================== */
/* PR #69: gossip_store → pathfind_graph_load_from_gossip tests       */
/* ================================================================== */

/* GS_PF1: Create in-memory gossip_store, add one channel_update,
 *         call pathfind_graph_load_from_gossip() -> returns >= 1 edge. */
int test_gs_pf1_load_one_edge(void)
{
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "GS_PF1: open in-memory store");

    unsigned char pka[33], pkb[33];
    make_pubkey(pka, 0xA1);
    make_pubkey(pkb, 0xB2);

    uint32_t now = 1700000000u;
    gossip_store_upsert_channel(&gs, 42, pka, pkb, 500000, now);
    gossip_store_upsert_channel_update(&gs, 42, 0, 1000, 200, 40, now);

    pathfind_graph_t *g = pathfind_graph_alloc();
    ASSERT(g != NULL, "GS_PF1: graph alloc");

    int edges = pathfind_graph_load_from_gossip(g, &gs);
    ASSERT(edges >= 1, "GS_PF1: at least 1 edge loaded");

    pathfind_graph_free(g);
    gossip_store_close(&gs);
    return 1;
}

/* GS_PF2: Empty gossip_store -> returns 0, no crash. */
int test_gs_pf2_empty_store(void)
{
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "GS_PF2: open in-memory store");

    pathfind_graph_t *g = pathfind_graph_alloc();
    ASSERT(g != NULL, "GS_PF2: graph alloc");

    int edges = pathfind_graph_load_from_gossip(g, &gs);
    ASSERT(edges == 0, "GS_PF2: 0 edges from empty store");

    pathfind_graph_free(g);
    gossip_store_close(&gs);
    return 1;
}

/* GS_PF3: Two channel_updates forming A->B->C path;
 *         pathfind_route() from A to C finds the route. */
int test_gs_pf3_route_via_gossip(void)
{
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "GS_PF3: open in-memory store");

    unsigned char pka[33], pkb[33], pkc[33];
    make_pubkey(pka, 0x10);
    make_pubkey(pkb, 0x20);
    make_pubkey(pkc, 0x30);

    uint32_t now = 1700000000u;

    /* Channel A-B (scid=10) */
    gossip_store_upsert_channel(&gs, 10, pka, pkb, 1000000, now);
    gossip_store_upsert_channel_update(&gs, 10, 0, 1000, 100, 40, now);

    /* Channel B-C (scid=11) */
    gossip_store_upsert_channel(&gs, 11, pkb, pkc, 1000000, now);
    gossip_store_upsert_channel_update(&gs, 11, 0, 500, 50, 20, now);

    /* Verify graph loads correctly */
    pathfind_graph_t *g = pathfind_graph_alloc();
    ASSERT(g != NULL, "GS_PF3: graph alloc");
    int edges = pathfind_graph_load_from_gossip(g, &gs);
    ASSERT(edges == 2, "GS_PF3: 2 edges loaded");
    pathfind_graph_free(g);

    /* Now verify pathfind_route finds A->C via gossip store */
    pathfind_route_t route;
    int ok = pathfind_route(&gs, pka, pkc, 50000, &route);
    ASSERT(ok == 1, "GS_PF3: route found");
    ASSERT(route.n_hops == 2, "GS_PF3: two hops");
    ASSERT(route.hops[0].scid == 10, "GS_PF3: first hop scid=10");
    ASSERT(route.hops[1].scid == 11, "GS_PF3: second hop scid=11");

    gossip_store_close(&gs);
    return 1;
}

/* ================================================================== */
/* PR #70: pathfind_graph_cache incremental refresh tests             */
/* ================================================================== */

/* PF_CACHE1: empty gossip_store -- no route, no crash */
int test_pf_cache1_empty_no_crash(void)
{
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "PF_CACHE1: open in-memory store");

    unsigned char pka[33], pkb[33];
    make_pubkey(pka, 0xAA);
    make_pubkey(pkb, 0xBB);

    pathfind_graph_cache_t *c = pathfind_graph_cache_create();
    ASSERT(c != NULL, "PF_CACHE1: cache alloc");

    pathfind_route_t route;
    uint32_t now = 1700000000u;
    int ok = pathfind_route_cached(&gs, c, pka, pkb, 10000, now, &route);
    ASSERT(ok == 0, "PF_CACHE1: no route in empty store");

    pathfind_graph_cache_destroy(c);
    gossip_store_close(&gs);
    return 1;
}

/* PF_CACHE2: add a channel, route should be found and cache populated */
int test_pf_cache2_route_found(void)
{
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "PF_CACHE2: open in-memory store");

    unsigned char pka[33], pkb[33];
    make_pubkey(pka, 0x01);
    make_pubkey(pkb, 0x02);

    uint32_t now = 1700000000u;
    gossip_store_upsert_channel(&gs, 100, pka, pkb, 1000000, now);
    gossip_store_upsert_channel_update(&gs, 100, 0, 1000, 100, 40, now);

    pathfind_graph_cache_t *c = pathfind_graph_cache_create();
    ASSERT(c != NULL, "PF_CACHE2: cache alloc");

    pathfind_route_t route;
    int ok = pathfind_route_cached(&gs, c, pka, pkb, 50000, now, &route);
    ASSERT(ok == 1, "PF_CACHE2: route found");
    ASSERT(route.n_hops == 1, "PF_CACHE2: one hop");
    ASSERT(route.hops[0].scid == 100, "PF_CACHE2: correct scid");
    /* Cache should now be populated */
    ASSERT(pathfind_graph_cache_loaded_at(c) == now, "PF_CACHE2: loaded_at set");

    pathfind_graph_cache_destroy(c);
    gossip_store_close(&gs);
    return 1;
}

/* PF_CACHE3: two calls with same now_unix -- second reuses cache (loaded_at unchanged) */
int test_pf_cache3_reuse_cache(void)
{
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "PF_CACHE3: open in-memory store");

    unsigned char pka[33], pkb[33];
    make_pubkey(pka, 0x03);
    make_pubkey(pkb, 0x04);

    uint32_t now = 1700000000u;
    gossip_store_upsert_channel(&gs, 200, pka, pkb, 1000000, now);
    gossip_store_upsert_channel_update(&gs, 200, 0, 500, 50, 20, now);

    pathfind_graph_cache_t *c = pathfind_graph_cache_create();
    ASSERT(c != NULL, "PF_CACHE3: cache alloc");

    pathfind_route_t route;
    /* First call -- full load */
    int ok1 = pathfind_route_cached(&gs, c, pka, pkb, 50000, now, &route);
    ASSERT(ok1 == 1, "PF_CACHE3: first call finds route");
    uint32_t loaded_after_first = pathfind_graph_cache_loaded_at(c);
    ASSERT(loaded_after_first == now, "PF_CACHE3: loaded_at set after first call");

    /* Second call -- same now_unix, well within TTL, no new updates */
    int ok2 = pathfind_route_cached(&gs, c, pka, pkb, 50000, now, &route);
    ASSERT(ok2 == 1, "PF_CACHE3: second call finds route");
    /* loaded_at must NOT change -- cache was reused */
    ASSERT(pathfind_graph_cache_loaded_at(c) == loaded_after_first,
           "PF_CACHE3: loaded_at unchanged on reuse");

    pathfind_graph_cache_destroy(c);
    gossip_store_close(&gs);
    return 1;
}

/* PF_CACHE4: call with now_unix = loaded_at + TTL + 1 -- triggers full reload */
int test_pf_cache4_full_reload_on_stale(void)
{
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "PF_CACHE4: open in-memory store");

    unsigned char pka[33], pkb[33];
    make_pubkey(pka, 0x05);
    make_pubkey(pkb, 0x06);

    uint32_t now = 1700000000u;
    gossip_store_upsert_channel(&gs, 300, pka, pkb, 1000000, now);
    gossip_store_upsert_channel_update(&gs, 300, 0, 1000, 100, 40, now);

    pathfind_graph_cache_t *c = pathfind_graph_cache_create();
    ASSERT(c != NULL, "PF_CACHE4: cache alloc");

    pathfind_route_t route;
    /* First call at 'now' */
    int ok1 = pathfind_route_cached(&gs, c, pka, pkb, 50000, now, &route);
    ASSERT(ok1 == 1, "PF_CACHE4: first call finds route");
    ASSERT(pathfind_graph_cache_loaded_at(c) == now,
           "PF_CACHE4: loaded_at == now after first call");

    /* Second call with now + TTL + 1 -- cache is stale, must reload */
    uint32_t later = now + PATHFIND_CACHE_TTL_SECS + 1;
    int ok2 = pathfind_route_cached(&gs, c, pka, pkb, 50000, later, &route);
    ASSERT(ok2 == 1, "PF_CACHE4: second call (stale) finds route");
    /* loaded_at must update to the new timestamp */
    ASSERT(pathfind_graph_cache_loaded_at(c) == later,
           "PF_CACHE4: loaded_at updated after stale reload");

    pathfind_graph_cache_destroy(c);
    gossip_store_close(&gs);
    return 1;
}
