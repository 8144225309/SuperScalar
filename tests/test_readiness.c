#include "superscalar/readiness.h"
#include "superscalar/persist.h"
#include <stdio.h>
#include <string.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

int test_readiness_init(void) {
    readiness_tracker_t rt;
    readiness_init(&rt, 42, 4, NULL);
    TEST_ASSERT(rt.factory_id == 42, "factory_id");
    TEST_ASSERT(rt.n_clients == 4, "n_clients");
    TEST_ASSERT(rt.ready_bitmap == 0, "ready_bitmap zeroed");
    TEST_ASSERT(rt.connected_bitmap == 0, "connected_bitmap zeroed");
    TEST_ASSERT(rt.db == NULL, "db NULL");
    for (size_t i = 0; i < 4; i++) {
        TEST_ASSERT(rt.clients[i].client_idx == (uint32_t)i, "client_idx");
        TEST_ASSERT(rt.clients[i].is_connected == 0, "not connected");
        TEST_ASSERT(rt.clients[i].is_ready == 0, "not ready");
    }
    return 1;
}

int test_readiness_set_connected(void) {
    readiness_tracker_t rt;
    readiness_init(&rt, 1, 4, NULL);
    readiness_set_connected(&rt, 2, 1);
    TEST_ASSERT(rt.connected_bitmap == (1ULL <<2), "bit 2 set");
    TEST_ASSERT(rt.clients[2].is_connected == 1, "entry connected");
    readiness_set_connected(&rt, 0, 1);
    TEST_ASSERT(rt.connected_bitmap == ((1ULL <<2) | (1ULL <<0)), "bits 0,2 set");
    return 1;
}

int test_readiness_set_ready(void) {
    readiness_tracker_t rt;
    readiness_init(&rt, 1, 4, NULL);
    /* Not connected — ready should be rejected */
    readiness_set_ready(&rt, 1, QUEUE_REQ_ROTATION);
    TEST_ASSERT(rt.ready_bitmap == 0, "not ready without connection");
    /* Connect then set ready */
    readiness_set_connected(&rt, 1, 1);
    readiness_set_ready(&rt, 1, QUEUE_REQ_ROTATION);
    TEST_ASSERT(rt.ready_bitmap == (1ULL <<1), "bit 1 ready");
    TEST_ASSERT(rt.clients[1].ready_for == QUEUE_REQ_ROTATION, "ready_for type");
    return 1;
}

int test_readiness_all_ready(void) {
    readiness_tracker_t rt;
    readiness_init(&rt, 1, 4, NULL);
    for (uint32_t i = 0; i < 4; i++) {
        readiness_set_connected(&rt, i, 1);
        readiness_set_ready(&rt, i, QUEUE_REQ_ROTATION);
    }
    TEST_ASSERT(readiness_all_ready(&rt) == 1, "all 4 ready");
    return 1;
}

int test_readiness_partial(void) {
    readiness_tracker_t rt;
    readiness_init(&rt, 1, 4, NULL);
    /* 3 of 4 ready */
    for (uint32_t i = 0; i < 3; i++) {
        readiness_set_connected(&rt, i, 1);
        readiness_set_ready(&rt, i, QUEUE_REQ_ROTATION);
    }
    TEST_ASSERT(readiness_all_ready(&rt) == 0, "3/4 not all ready");
    TEST_ASSERT(readiness_count_ready(&rt) == 3, "count 3");
    return 1;
}

int test_readiness_clear(void) {
    readiness_tracker_t rt;
    readiness_init(&rt, 1, 4, NULL);
    readiness_set_connected(&rt, 2, 1);
    readiness_set_ready(&rt, 2, QUEUE_REQ_ROTATION);
    TEST_ASSERT(rt.ready_bitmap == (1ULL <<2), "ready before clear");
    readiness_clear(&rt, 2);
    TEST_ASSERT(rt.ready_bitmap == 0, "ready cleared");
    TEST_ASSERT(rt.connected_bitmap == 0, "connected cleared");
    TEST_ASSERT(rt.clients[2].is_connected == 0, "entry disconnected");
    TEST_ASSERT(rt.clients[2].is_ready == 0, "entry not ready");
    return 1;
}

int test_readiness_persist_roundtrip(void) {
    persist_t db;
    if (!persist_open(&db, ":memory:")) {
        printf("  FAIL: could not open in-memory db\n");
        return 0;
    }
    readiness_tracker_t rt;
    readiness_init(&rt, 7, 4, &db);
    readiness_set_connected(&rt, 0, 1);
    readiness_set_ready(&rt, 0, QUEUE_REQ_ROTATION);
    readiness_set_connected(&rt, 2, 1);
    TEST_ASSERT(readiness_save(&rt) == 1, "save ok");

    /* Load into fresh tracker */
    readiness_tracker_t rt2;
    readiness_init(&rt2, 7, 4, &db);
    TEST_ASSERT(readiness_load(&rt2) == 1, "load ok");
    TEST_ASSERT(rt2.clients[0].is_connected == 1, "client 0 connected");
    TEST_ASSERT(rt2.clients[0].is_ready == 1, "client 0 ready");
    TEST_ASSERT(rt2.clients[0].ready_for == QUEUE_REQ_ROTATION, "client 0 ready_for");
    TEST_ASSERT(rt2.clients[2].is_connected == 1, "client 2 connected");
    TEST_ASSERT(rt2.clients[2].is_ready == 0, "client 2 not ready");
    TEST_ASSERT(rt2.ready_bitmap == (1ULL <<0), "ready bitmap restored");
    TEST_ASSERT(rt2.connected_bitmap == ((1ULL <<0) | (1ULL <<2)),
                "connected bitmap restored");
    persist_close(&db);
    return 1;
}

int test_readiness_urgency_levels(void) {
    /* blocks_left > dying_blocks → LOW */
    TEST_ASSERT(readiness_compute_urgency(100, 50) == QUEUE_URGENCY_LOW,
                "100/50 = LOW");
    /* blocks_left == dying_blocks → NORMAL (> dying/2) */
    TEST_ASSERT(readiness_compute_urgency(50, 50) == QUEUE_URGENCY_NORMAL,
                "50/50 = NORMAL");
    /* blocks_left == dying/2 → HIGH (not > dying/2, but > dying/4) */
    TEST_ASSERT(readiness_compute_urgency(25, 50) == QUEUE_URGENCY_HIGH,
                "25/50 = HIGH");
    /* blocks_left == dying/4 → CRITICAL */
    /* 12 == dying/4 (50/4=12), not > dying/4, so CRITICAL */
    TEST_ASSERT(readiness_compute_urgency(12, 50) == QUEUE_URGENCY_CRITICAL,
                "12/50 = CRITICAL (== dying/4)");
    TEST_ASSERT(readiness_compute_urgency(13, 50) == QUEUE_URGENCY_HIGH,
                "13/50 = HIGH (> dying/4)");
    TEST_ASSERT(readiness_compute_urgency(5, 50) == QUEUE_URGENCY_CRITICAL,
                "5/50 = CRITICAL");
    /* Edge: dying_blocks == 0 → CRITICAL */
    TEST_ASSERT(readiness_compute_urgency(10, 0) == QUEUE_URGENCY_CRITICAL,
                "0 dying = CRITICAL");
    return 1;
}

int test_readiness_get_missing(void) {
    readiness_tracker_t rt;
    readiness_init(&rt, 1, 4, NULL);
    readiness_set_connected(&rt, 0, 1);
    readiness_set_ready(&rt, 0, QUEUE_REQ_ROTATION);
    readiness_set_connected(&rt, 2, 1);
    readiness_set_ready(&rt, 2, QUEUE_REQ_ROTATION);
    uint32_t missing[4];
    size_t n = readiness_get_missing(&rt, missing, 4);
    TEST_ASSERT(n == 2, "2 missing");
    TEST_ASSERT(missing[0] == 1, "client 1 missing");
    TEST_ASSERT(missing[1] == 3, "client 3 missing");
    return 1;
}

int test_readiness_reset(void) {
    readiness_tracker_t rt;
    readiness_init(&rt, 1, 4, NULL);
    for (uint32_t i = 0; i < 4; i++) {
        readiness_set_connected(&rt, i, 1);
        readiness_set_ready(&rt, i, QUEUE_REQ_ROTATION);
    }
    TEST_ASSERT(readiness_all_ready(&rt) == 1, "all ready before reset");
    readiness_reset(&rt);
    TEST_ASSERT(rt.ready_bitmap == 0, "ready zeroed");
    TEST_ASSERT(rt.connected_bitmap == 0, "connected zeroed");
    TEST_ASSERT(readiness_all_ready(&rt) == 0, "not ready after reset");
    return 1;
}
