/* Unit tests for lsp_check_rotation_readiness().
   Tests the null/not-ready early-exit paths, which do not call
   lsp_channels_rotate_factory() and require no live LSP state. */

#include "superscalar/lsp_channels.h"
#include "superscalar/readiness.h"
#include <stdio.h>
#include <string.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

/* Test 1: readiness == NULL — returns 0 without touching lsp. */
int test_rotation_readiness_null(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    /* mgr.readiness is NULL */
    TEST_ASSERT(lsp_check_rotation_readiness(&mgr, NULL) == 0,
                "returns 0 when readiness is NULL");
    return 1;
}

/* Test 2: readiness set but no clients connected — returns 0. */
int test_rotation_readiness_none_connected(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));

    readiness_tracker_t rt;
    readiness_init(&rt, 1, 3, NULL);
    mgr.readiness = &rt;

    /* No clients connected or ready */
    TEST_ASSERT(lsp_check_rotation_readiness(&mgr, NULL) == 0,
                "returns 0 when no clients ready");
    return 1;
}

/* Test 3: partial readiness (2/3 ready) — returns 0. */
int test_rotation_readiness_partial(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));

    readiness_tracker_t rt;
    readiness_init(&rt, 1, 3, NULL);

    /* Connect and mark ready: clients 0 and 1, but not 2 */
    readiness_set_connected(&rt, 0, 1);
    readiness_set_ready(&rt, 0, QUEUE_REQ_ROTATION);
    readiness_set_connected(&rt, 1, 1);
    readiness_set_ready(&rt, 1, QUEUE_REQ_ROTATION);

    mgr.readiness = &rt;

    TEST_ASSERT(lsp_check_rotation_readiness(&mgr, NULL) == 0,
                "returns 0 when only 2/3 clients ready");
    /* Tracker should be unmodified — reset not called on partial */
    TEST_ASSERT(readiness_count_ready(&rt) == 2, "tracker unchanged");
    return 1;
}
