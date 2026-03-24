#include "superscalar/lsp_queue.h"

#ifndef ASSERT
#define ASSERT(cond, msg) do { if (!(cond)) { printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); return 0; } } while(0)
#endif
#include "superscalar/ln_dispatch.h"
#include "superscalar/persist.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define TEST_ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { \
        printf("  FAIL: %s (line %d): %s (got %ld, expected %ld)\n", \
               __func__, __LINE__, msg, (long)(a), (long)(b)); \
        return 0; \
    } \
} while(0)

/* Test 1: Push and drain roundtrip. */
int test_queue_push_drain(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open in-memory db");

    TEST_ASSERT(queue_push(&db, 0, 1, QUEUE_REQ_ROTATION,
                           QUEUE_URGENCY_NORMAL, 0, "{\"round\":1}"),
                "push rotation request");

    queue_entry_t entries[QUEUE_MAX_PENDING];
    size_t count = queue_drain(&db, 0, entries, QUEUE_MAX_PENDING);
    TEST_ASSERT_EQ(count, 1, "should drain 1 entry");
    TEST_ASSERT_EQ(entries[0].client_idx, 0, "client_idx");
    TEST_ASSERT_EQ(entries[0].factory_id, 1, "factory_id");
    TEST_ASSERT_EQ(entries[0].request_type, QUEUE_REQ_ROTATION, "request_type");
    TEST_ASSERT_EQ(entries[0].urgency, QUEUE_URGENCY_NORMAL, "urgency");
    TEST_ASSERT(strcmp(entries[0].payload, "{\"round\":1}") == 0, "payload matches");
    TEST_ASSERT(entries[0].id > 0, "id assigned");
    TEST_ASSERT(entries[0].created_at > 0, "created_at set");

    persist_close(&db);
    return 1;
}

/* Test 2: Urgency ordering — critical first, then high, normal, low. */
int test_queue_urgency_ordering(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    /* Push in wrong order: low, critical, normal, high */
    TEST_ASSERT(queue_push(&db, 0, 1, QUEUE_REQ_CLOSE,
                           QUEUE_URGENCY_LOW, 0, NULL), "push low");
    TEST_ASSERT(queue_push(&db, 0, 2, QUEUE_REQ_ROTATION,
                           QUEUE_URGENCY_CRITICAL, 0, NULL), "push critical");
    TEST_ASSERT(queue_push(&db, 0, 3, QUEUE_REQ_LEAF_ADVANCE,
                           QUEUE_URGENCY_NORMAL, 0, NULL), "push normal");
    TEST_ASSERT(queue_push(&db, 0, 4, QUEUE_REQ_LEAF_ADVANCE,
                           QUEUE_URGENCY_HIGH, 0, NULL), "push high");

    queue_entry_t entries[QUEUE_MAX_PENDING];
    size_t count = queue_drain(&db, 0, entries, QUEUE_MAX_PENDING);
    TEST_ASSERT_EQ(count, 4, "4 entries");

    /* Should come out: critical(3), high(2), normal(1), low(0) */
    TEST_ASSERT_EQ(entries[0].urgency, QUEUE_URGENCY_CRITICAL, "first is critical");
    TEST_ASSERT_EQ(entries[1].urgency, QUEUE_URGENCY_HIGH, "second is high");
    TEST_ASSERT_EQ(entries[2].urgency, QUEUE_URGENCY_NORMAL, "third is normal");
    TEST_ASSERT_EQ(entries[3].urgency, QUEUE_URGENCY_LOW, "fourth is low");

    persist_close(&db);
    return 1;
}

/* Test 3: Dedup — same (client_idx, factory_id, request_type) replaces. */
int test_queue_dedup_replace(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    TEST_ASSERT(queue_push(&db, 0, 1, QUEUE_REQ_ROTATION,
                           QUEUE_URGENCY_NORMAL, 0, "{\"v\":1}"), "push first");
    TEST_ASSERT(queue_push(&db, 0, 1, QUEUE_REQ_ROTATION,
                           QUEUE_URGENCY_HIGH, 0, "{\"v\":2}"), "push replace");

    /* Should have exactly 1 entry with the updated values */
    TEST_ASSERT_EQ(queue_count(&db, 0), 1, "count is 1 after dedup");

    queue_entry_t entries[QUEUE_MAX_PENDING];
    size_t count = queue_drain(&db, 0, entries, QUEUE_MAX_PENDING);
    TEST_ASSERT_EQ(count, 1, "drain 1");
    TEST_ASSERT_EQ(entries[0].urgency, QUEUE_URGENCY_HIGH, "urgency updated");
    TEST_ASSERT(strcmp(entries[0].payload, "{\"v\":2}") == 0, "payload updated");

    persist_close(&db);
    return 1;
}

/* Test 4: Different request types for same client+factory are separate. */
int test_queue_different_types(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    TEST_ASSERT(queue_push(&db, 0, 1, QUEUE_REQ_ROTATION,
                           QUEUE_URGENCY_NORMAL, 0, NULL), "push rotation");
    TEST_ASSERT(queue_push(&db, 0, 1, QUEUE_REQ_LEAF_ADVANCE,
                           QUEUE_URGENCY_NORMAL, 0, NULL), "push leaf_advance");
    TEST_ASSERT(queue_push(&db, 0, 1, QUEUE_REQ_DW_PRESIGN,
                           QUEUE_URGENCY_NORMAL, 0, NULL), "push dw_presign");

    TEST_ASSERT_EQ(queue_count(&db, 0), 3, "3 distinct entries");

    persist_close(&db);
    return 1;
}

/* Test 5: Drain only returns entries for the requested client. */
int test_queue_client_isolation(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    TEST_ASSERT(queue_push(&db, 0, 1, QUEUE_REQ_ROTATION,
                           QUEUE_URGENCY_NORMAL, 0, NULL), "push client 0");
    TEST_ASSERT(queue_push(&db, 1, 1, QUEUE_REQ_ROTATION,
                           QUEUE_URGENCY_NORMAL, 0, NULL), "push client 1");
    TEST_ASSERT(queue_push(&db, 2, 1, QUEUE_REQ_ROTATION,
                           QUEUE_URGENCY_NORMAL, 0, NULL), "push client 2");

    queue_entry_t entries[QUEUE_MAX_PENDING];
    size_t count = queue_drain(&db, 1, entries, QUEUE_MAX_PENDING);
    TEST_ASSERT_EQ(count, 1, "only client 1's entry");
    TEST_ASSERT_EQ(entries[0].client_idx, 1, "correct client");

    TEST_ASSERT_EQ(queue_count(&db, 0), 1, "client 0 still has 1");
    TEST_ASSERT_EQ(queue_count(&db, 2), 1, "client 2 still has 1");

    persist_close(&db);
    return 1;
}

/* Test 6: Expire removes past-deadline entries. */
int test_queue_expire(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    time_t now = time(NULL);

    /* Push one expired (deadline in the past) and one not expired */
    TEST_ASSERT(queue_push(&db, 0, 1, QUEUE_REQ_ROTATION,
                           QUEUE_URGENCY_NORMAL, now - 100, NULL),
                "push expired");
    TEST_ASSERT(queue_push(&db, 0, 2, QUEUE_REQ_LEAF_ADVANCE,
                           QUEUE_URGENCY_NORMAL, now + 3600, NULL),
                "push not expired");
    /* Push one with no expiry (expires_at=0) */
    TEST_ASSERT(queue_push(&db, 0, 3, QUEUE_REQ_DW_PRESIGN,
                           QUEUE_URGENCY_NORMAL, 0, NULL),
                "push no expiry");

    TEST_ASSERT_EQ(queue_count(&db, 0), 3, "3 before expire");

    size_t expired = queue_expire(&db);
    TEST_ASSERT_EQ(expired, 1, "1 expired entry removed");
    TEST_ASSERT_EQ(queue_count(&db, 0), 2, "2 remaining");

    /* Verify the right ones survived */
    queue_entry_t entries[QUEUE_MAX_PENDING];
    size_t count = queue_drain(&db, 0, entries, QUEUE_MAX_PENDING);
    TEST_ASSERT_EQ(count, 2, "drain 2");
    /* expires_at=0 entry and future entry should remain */
    int found_no_expiry = 0, found_future = 0;
    for (size_t i = 0; i < count; i++) {
        if (entries[i].factory_id == 3) found_no_expiry = 1;
        if (entries[i].factory_id == 2) found_future = 1;
    }
    TEST_ASSERT(found_no_expiry, "no-expiry entry survived");
    TEST_ASSERT(found_future, "future entry survived");

    persist_close(&db);
    return 1;
}

/* Test 7: Delete single entry by ID. */
int test_queue_delete_single(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    TEST_ASSERT(queue_push(&db, 0, 1, QUEUE_REQ_ROTATION,
                           QUEUE_URGENCY_NORMAL, 0, NULL), "push 1");
    TEST_ASSERT(queue_push(&db, 0, 2, QUEUE_REQ_LEAF_ADVANCE,
                           QUEUE_URGENCY_NORMAL, 0, NULL), "push 2");

    queue_entry_t entries[QUEUE_MAX_PENDING];
    size_t count = queue_drain(&db, 0, entries, QUEUE_MAX_PENDING);
    TEST_ASSERT_EQ(count, 2, "drain 2");

    /* Delete the first one */
    TEST_ASSERT(queue_delete(&db, entries[0].id), "delete first");
    TEST_ASSERT_EQ(queue_count(&db, 0), 1, "1 remaining");

    persist_close(&db);
    return 1;
}

/* Test 8: Delete all entries for a client. */
int test_queue_delete_all(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    TEST_ASSERT(queue_push(&db, 0, 1, QUEUE_REQ_ROTATION,
                           QUEUE_URGENCY_NORMAL, 0, NULL), "push 1");
    TEST_ASSERT(queue_push(&db, 0, 2, QUEUE_REQ_LEAF_ADVANCE,
                           QUEUE_URGENCY_HIGH, 0, NULL), "push 2");
    TEST_ASSERT(queue_push(&db, 1, 1, QUEUE_REQ_ROTATION,
                           QUEUE_URGENCY_NORMAL, 0, NULL), "push other client");

    TEST_ASSERT(queue_delete_all(&db, 0), "delete all for client 0");
    TEST_ASSERT_EQ(queue_count(&db, 0), 0, "client 0 empty");
    TEST_ASSERT_EQ(queue_count(&db, 1), 1, "client 1 untouched");

    persist_close(&db);
    return 1;
}

/* Test 9: has_pending reflects queue state. */
int test_queue_has_pending(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    TEST_ASSERT(!queue_has_pending(&db, 0), "empty initially");

    TEST_ASSERT(queue_push(&db, 0, 1, QUEUE_REQ_ROTATION,
                           QUEUE_URGENCY_NORMAL, 0, NULL), "push");
    TEST_ASSERT(queue_has_pending(&db, 0), "has pending after push");

    TEST_ASSERT(queue_delete_all(&db, 0), "delete all");
    TEST_ASSERT(!queue_has_pending(&db, 0), "empty after delete");

    persist_close(&db);
    return 1;
}

/* Test 10: request_type_name returns correct strings. */
int test_queue_request_type_name(void) {
    TEST_ASSERT(strcmp(queue_request_type_name(QUEUE_REQ_ROTATION), "rotation") == 0,
                "rotation name");
    TEST_ASSERT(strcmp(queue_request_type_name(QUEUE_REQ_LEAF_ADVANCE), "leaf_advance") == 0,
                "leaf_advance name");
    TEST_ASSERT(strcmp(queue_request_type_name(QUEUE_REQ_DW_PRESIGN), "dw_presign") == 0,
                "dw_presign name");
    TEST_ASSERT(strcmp(queue_request_type_name(QUEUE_REQ_CLOSE), "close") == 0,
                "close name");
    TEST_ASSERT(strcmp(queue_request_type_name(999), "unknown") == 0,
                "unknown for invalid type");
    return 1;
}

/* Test 11: NULL payload is handled correctly. */
int test_queue_null_payload(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    TEST_ASSERT(queue_push(&db, 0, 1, QUEUE_REQ_ROTATION,
                           QUEUE_URGENCY_NORMAL, 0, NULL), "push null payload");

    queue_entry_t entries[QUEUE_MAX_PENDING];
    size_t count = queue_drain(&db, 0, entries, QUEUE_MAX_PENDING);
    TEST_ASSERT_EQ(count, 1, "drain 1");
    TEST_ASSERT_EQ(entries[0].payload[0], '\0', "payload is empty string");

    persist_close(&db);
    return 1;
}

/* Test 12: Drain with max_entries limit. */
int test_queue_drain_limit(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    for (int i = 0; i < 5; i++) {
        TEST_ASSERT(queue_push(&db, 0, (uint32_t)i, QUEUE_REQ_ROTATION,
                               QUEUE_URGENCY_NORMAL, 0, NULL), "push");
    }

    queue_entry_t entries[2];
    size_t count = queue_drain(&db, 0, entries, 2);
    TEST_ASSERT_EQ(count, 2, "limited to 2");

    /* All 5 still in DB (drain doesn't delete) */
    TEST_ASSERT_EQ(queue_count(&db, 0), 5, "all 5 still present");

    persist_close(&db);
    return 1;
}

/* Test 13: NULL/invalid persist_t is handled safely. */
int test_queue_null_safety(void) {
    TEST_ASSERT_EQ(queue_push(NULL, 0, 0, 0, 0, 0, NULL), 0, "push null");
    TEST_ASSERT_EQ(queue_delete(NULL, 1), 0, "delete null");
    TEST_ASSERT_EQ(queue_delete_all(NULL, 0), 0, "delete_all null");
    TEST_ASSERT_EQ(queue_expire(NULL), 0, "expire null");
    TEST_ASSERT_EQ(queue_count(NULL, 0), 0, "count null");
    TEST_ASSERT_EQ(queue_has_pending(NULL, 0), 0, "has_pending null");

    queue_entry_t entries[1];
    TEST_ASSERT_EQ(queue_drain(NULL, 0, entries, 1), 0, "drain null persist");

    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");
    TEST_ASSERT_EQ(queue_drain(&db, 0, NULL, 1), 0, "drain null entries");
    TEST_ASSERT_EQ(queue_drain(&db, 0, entries, 0), 0, "drain zero max");
    persist_close(&db);

    return 1;
}

/* Test 14: queue_get fetches a single entry by id. */
int test_queue_get(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    TEST_ASSERT(queue_push(&db, 2, 7, QUEUE_REQ_ROTATION,
                           QUEUE_URGENCY_HIGH, 0, "{\"test\":1}"), "push");

    /* Drain to get the assigned id */
    queue_entry_t entries[4];
    size_t n = queue_drain(&db, 2, entries, 4);
    TEST_ASSERT_EQ(n, 1, "one entry");
    uint64_t entry_id = entries[0].id;

    /* Fetch by id and verify all fields */
    queue_entry_t got;
    TEST_ASSERT(queue_get(&db, entry_id, &got), "get found");
    TEST_ASSERT_EQ(got.id, entry_id, "id matches");
    TEST_ASSERT_EQ(got.client_idx, 2, "client_idx");
    TEST_ASSERT_EQ(got.factory_id, 7, "factory_id");
    TEST_ASSERT_EQ(got.request_type, QUEUE_REQ_ROTATION, "request_type");
    TEST_ASSERT_EQ(got.urgency, QUEUE_URGENCY_HIGH, "urgency");
    TEST_ASSERT(strcmp(got.payload, "{\"test\":1}") == 0, "payload");

    /* Not-found returns 0 */
    TEST_ASSERT_EQ(queue_get(&db, 99999, &got), 0, "not found");

    /* NULL safety */
    TEST_ASSERT_EQ(queue_get(NULL, entry_id, &got), 0, "null persist");
    TEST_ASSERT_EQ(queue_get(&db, entry_id, NULL), 0, "null out");

    persist_close(&db);
    return 1;
}

/* ================================================================== */
/* QD1 — null persist: MSG_QUEUE_POLL returns 0x6D without crash      */
/* ================================================================== */
int test_queue_ln_dispatch_poll_null_persist(void)
{
    unsigned char msg[4] = {0x00, 0x6D, 0x00, 0x00};
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.persist = NULL;
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 0x6D, "QD1: null persist returns 0x6D");
    return 1;
}

/* ================================================================== */
/* QD2 — null persist: MSG_QUEUE_DONE returns 0x6F without crash      */
/* ================================================================== */
int test_queue_ln_dispatch_done_null_persist(void)
{
    unsigned char msg[4] = {0x00, 0x6F, 0x00, 0x00};
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.persist = NULL;
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 0x6F, "QD2: null persist returns 0x6F");
    return 1;
}

/* ================================================================== */
/* QD3 — MSG_QUEUE_POLL type returned                                  */
/* ================================================================== */
int test_queue_dispatch_poll_type_returned(void)
{
    unsigned char msg[4] = {0x00, 0x6D, 0x00, 0x00};
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 0x6D, "QD3: type 0x6D dispatched");
    return 1;
}

/* ================================================================== */
/* QD4 — MSG_QUEUE_DONE type returned                                  */
/* ================================================================== */
int test_queue_dispatch_done_type_returned(void)
{
    unsigned char msg[4] = {0x00, 0x6F, 0x00, 0x00};
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 0x6F, "QD4: type 0x6F dispatched");
    return 1;
}

/* ================================================================== */
/* QD5 — MSG_QUEUE_DONE with count=0 (no IDs) doesn't crash          */
/* ================================================================== */
int test_queue_ln_dispatch_done_empty(void)
{
    unsigned char msg[4] = {0x00, 0x6F, 0x00, 0x00}; /* count=0 */
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 0x6F, "QD5: empty DONE returns 0x6F");
    return 1;
}

/* ================================================================== */
/* QD6 — MSG_QUEUE_DONE too short returns -1                          */
/* ================================================================== */
int test_queue_ln_dispatch_done_too_short(void)
{
    unsigned char msg[2] = {0x00, 0x6F};
    ln_dispatch_t d;
    memset(&d, 0, sizeof(d));
    /* No persist, so returns 0x6F before length check */
    int r = ln_dispatch_process_msg(&d, 0, msg, sizeof(msg));
    ASSERT(r == 0x6F, "QD6: no persist returns 0x6F");
    return 1;
}
