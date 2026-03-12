#include "superscalar/notify.h"
#include "superscalar/lsp_queue.h"
#include <stdio.h>
#include <string.h>

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

/* --- Custom test backend to capture calls --- */

typedef struct {
    int call_count;
    uint32_t last_client_idx;
    int last_event_type;
    int last_urgency;
    char last_detail[256];
} test_backend_t;

static void test_callback(void *backend_data,
                           uint32_t client_idx,
                           int event_type,
                           int urgency,
                           const char *detail_json) {
    test_backend_t *tb = (test_backend_t *)backend_data;
    if (!tb) return;
    tb->call_count++;
    tb->last_client_idx = client_idx;
    tb->last_event_type = event_type;
    tb->last_urgency = urgency;
    if (detail_json) {
        strncpy(tb->last_detail, detail_json, sizeof(tb->last_detail) - 1);
        tb->last_detail[sizeof(tb->last_detail) - 1] = '\0';
    } else {
        tb->last_detail[0] = '\0';
    }
}

/* Test 1: Log backend initializes correctly. */
int test_notify_log_init(void) {
    notify_t n;
    notify_init_log(&n);
    TEST_ASSERT_EQ(n.backend_type, NOTIFY_BACKEND_LOG, "backend type");
    TEST_ASSERT(n.callback != NULL, "callback set");
    TEST_ASSERT(n.backend_data == NULL, "no backend data for log");
    notify_cleanup(&n);
    return 1;
}

/* Test 2: Custom callback receives correct arguments. */
int test_notify_custom_dispatch(void) {
    test_backend_t tb;
    memset(&tb, 0, sizeof(tb));

    notify_t n;
    memset(&n, 0, sizeof(n));
    n.callback = test_callback;
    n.backend_data = &tb;

    notify_send(&n, 42, NOTIFY_ROTATION_NEEDED,
                QUEUE_URGENCY_HIGH, "{\"factory\":7}");

    TEST_ASSERT_EQ(tb.call_count, 1, "called once");
    TEST_ASSERT_EQ(tb.last_client_idx, 42, "client_idx");
    TEST_ASSERT_EQ(tb.last_event_type, NOTIFY_ROTATION_NEEDED, "event_type");
    TEST_ASSERT_EQ(tb.last_urgency, QUEUE_URGENCY_HIGH, "urgency");
    TEST_ASSERT(strcmp(tb.last_detail, "{\"factory\":7}") == 0, "detail_json");

    return 1;
}

/* Test 3: Multiple sends accumulate call count. */
int test_notify_multiple_sends(void) {
    test_backend_t tb;
    memset(&tb, 0, sizeof(tb));

    notify_t n;
    memset(&n, 0, sizeof(n));
    n.callback = test_callback;
    n.backend_data = &tb;

    notify_send(&n, 0, NOTIFY_QUEUE_ITEM, QUEUE_URGENCY_LOW, NULL);
    notify_send(&n, 1, NOTIFY_EPOCH_RESET, QUEUE_URGENCY_NORMAL, NULL);
    notify_send(&n, 2, NOTIFY_FACTORY_EXPIRING, QUEUE_URGENCY_CRITICAL, "{}");

    TEST_ASSERT_EQ(tb.call_count, 3, "called 3 times");
    TEST_ASSERT_EQ(tb.last_client_idx, 2, "last client was 2");
    TEST_ASSERT_EQ(tb.last_event_type, NOTIFY_FACTORY_EXPIRING, "last event");

    return 1;
}

/* Test 4: Cleanup nullifies callback and frees backend_data. */
int test_notify_cleanup(void) {
    notify_t n;
    notify_init_log(&n);
    TEST_ASSERT(n.callback != NULL, "callback before cleanup");

    notify_cleanup(&n);
    TEST_ASSERT(n.callback == NULL, "callback NULL after cleanup");
    TEST_ASSERT(n.backend_data == NULL, "backend_data NULL after cleanup");

    /* Double cleanup should be safe */
    notify_cleanup(&n);
    return 1;
}

/* Test 5: Send with NULL notify_t is a no-op. */
int test_notify_null_safety(void) {
    /* Should not crash */
    notify_send(NULL, 0, NOTIFY_QUEUE_ITEM, QUEUE_URGENCY_LOW, NULL);

    /* Send with no callback set is a no-op */
    notify_t n;
    memset(&n, 0, sizeof(n));
    notify_send(&n, 0, NOTIFY_QUEUE_ITEM, QUEUE_URGENCY_LOW, NULL);

    /* Cleanup NULL is safe */
    notify_cleanup(NULL);

    /* Init NULL is safe */
    notify_init_log(NULL);

    return 1;
}

/* Test 6: event_name returns correct strings. */
int test_notify_event_names(void) {
    TEST_ASSERT(strcmp(notify_event_name(NOTIFY_ROTATION_NEEDED), "rotation_needed") == 0,
                "rotation_needed");
    TEST_ASSERT(strcmp(notify_event_name(NOTIFY_EPOCH_RESET), "epoch_reset") == 0,
                "epoch_reset");
    TEST_ASSERT(strcmp(notify_event_name(NOTIFY_FACTORY_EXPIRING), "factory_expiring") == 0,
                "factory_expiring");
    TEST_ASSERT(strcmp(notify_event_name(NOTIFY_PAYMENT_RECEIVED), "payment_received") == 0,
                "payment_received");
    TEST_ASSERT(strcmp(notify_event_name(NOTIFY_QUEUE_ITEM), "queue_item") == 0,
                "queue_item");
    TEST_ASSERT(strcmp(notify_event_name(999), "unknown") == 0,
                "unknown for invalid");
    return 1;
}

/* Test 7: NULL detail_json is passed through correctly. */
int test_notify_null_detail(void) {
    test_backend_t tb;
    memset(&tb, 0, sizeof(tb));

    notify_t n;
    memset(&n, 0, sizeof(n));
    n.callback = test_callback;
    n.backend_data = &tb;

    notify_send(&n, 0, NOTIFY_QUEUE_ITEM, QUEUE_URGENCY_LOW, NULL);

    TEST_ASSERT_EQ(tb.call_count, 1, "called");
    TEST_ASSERT_EQ(tb.last_detail[0], '\0', "detail is empty for NULL input");

    return 1;
}

/* Test 8: Webhook init sets correct backend type. */
int test_notify_webhook_init(void) {
    notify_t n;
    notify_init_webhook(&n, "http://localhost:8080/hook");
    TEST_ASSERT_EQ(n.backend_type, NOTIFY_BACKEND_WEBHOOK, "backend type");
    TEST_ASSERT(n.callback != NULL, "callback set");
    TEST_ASSERT(n.backend_data != NULL, "backend_data allocated");
    notify_cleanup(&n);
    return 1;
}

/* Test 9: Exec init sets correct backend type. */
int test_notify_exec_init(void) {
    notify_t n;
    notify_init_exec(&n, "/usr/local/bin/notify.sh");
    TEST_ASSERT_EQ(n.backend_type, NOTIFY_BACKEND_EXEC, "backend type");
    TEST_ASSERT(n.callback != NULL, "callback set");
    TEST_ASSERT(n.backend_data != NULL, "backend_data allocated");
    notify_cleanup(&n);
    return 1;
}

/* Test 10: Init with NULL url/script is safe. */
int test_notify_init_null_args(void) {
    notify_t n;
    memset(&n, 0, sizeof(n));
    notify_init_webhook(&n, NULL);
    /* Should not have initialized */
    TEST_ASSERT(n.callback == NULL, "webhook with NULL url: no callback");

    notify_init_exec(&n, NULL);
    TEST_ASSERT(n.callback == NULL, "exec with NULL script: no callback");

    return 1;
}
