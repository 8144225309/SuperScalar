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
