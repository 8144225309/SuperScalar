#include <stdio.h>
#include <string.h>
#include "superscalar/rate_limit.h"

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

/* Test 1: Connections under limit are allowed. */
int test_rate_limit_under_limit(void) {
    rate_limiter_t rl;
    rate_limiter_init(&rl, 5, 60, 4);

    /* 5 connections from same IP should all be allowed */
    for (int i = 0; i < 5; i++) {
        TEST_ASSERT(rate_limiter_allow(&rl, "192.168.1.1"),
                    "connection under limit should be allowed");
    }

    return 1;
}

/* Test 2: Connections over limit are rejected. */
int test_rate_limit_over_limit(void) {
    rate_limiter_t rl;
    rate_limiter_init(&rl, 3, 60, 4);

    /* First 3 should pass */
    for (int i = 0; i < 3; i++) {
        TEST_ASSERT(rate_limiter_allow(&rl, "10.0.0.1"),
                    "should allow up to limit");
    }

    /* 4th should be rejected */
    TEST_ASSERT(!rate_limiter_allow(&rl, "10.0.0.1"),
                "should reject over limit");

    /* Different IP should still be allowed */
    TEST_ASSERT(rate_limiter_allow(&rl, "10.0.0.2"),
                "different IP should be allowed");

    return 1;
}

/* Test 3: Window expiry re-allows connections.
   We can't easily manipulate time() in a unit test, so we test that
   the window parameter is stored correctly and affects behavior. */
int test_rate_limit_window_config(void) {
    rate_limiter_t rl;
    rate_limiter_init(&rl, 2, 1, 4);  /* 2 per 1 second window */

    TEST_ASSERT(rl.max_per_window == 2, "max_per_window should be 2");
    TEST_ASSERT(rl.window_secs == 1, "window_secs should be 1");

    /* Saturate */
    TEST_ASSERT(rate_limiter_allow(&rl, "1.2.3.4"), "first ok");
    TEST_ASSERT(rate_limiter_allow(&rl, "1.2.3.4"), "second ok");
    TEST_ASSERT(!rate_limiter_allow(&rl, "1.2.3.4"), "third should fail");

    return 1;
}

/* Test 4: Concurrent handshake cap. */
int test_rate_limit_handshake_cap(void) {
    rate_limiter_t rl;
    rate_limiter_init(&rl, 100, 60, 2);  /* max 2 concurrent handshakes */

    /* Start 2 handshakes */
    TEST_ASSERT(rate_limiter_handshake_start(&rl), "first handshake ok");
    TEST_ASSERT(rate_limiter_handshake_start(&rl), "second handshake ok");

    /* Third should fail */
    TEST_ASSERT(!rate_limiter_handshake_start(&rl),
                "third handshake should be rejected");

    /* End one, then a new one should be allowed */
    rate_limiter_handshake_end(&rl);
    TEST_ASSERT(rate_limiter_handshake_start(&rl),
                "handshake after end should be allowed");

    /* End all */
    rate_limiter_handshake_end(&rl);
    rate_limiter_handshake_end(&rl);
    TEST_ASSERT(rl.active_handshakes == 0, "should be 0 after all ended");

    /* Extra end should not go negative */
    rate_limiter_handshake_end(&rl);
    TEST_ASSERT(rl.active_handshakes == 0, "should not go negative");

    return 1;
}
