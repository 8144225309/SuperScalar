#include "superscalar/ceremony.h"
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

int test_ceremony_all_respond(void) {
    ceremony_t c;
    ceremony_init(&c, 4, 30, 2);

    TEST_ASSERT_EQ(c.state, CEREMONY_INIT, "initial state");
    TEST_ASSERT_EQ(c.n_clients, 4, "n_clients");
    TEST_ASSERT_EQ(c.per_client_timeout_sec, 30, "timeout");
    TEST_ASSERT_EQ(c.min_clients, 2, "min_clients");

    /* Simulate all clients responding */
    for (size_t i = 0; i < 4; i++) {
        TEST_ASSERT_EQ(c.clients[i], CLIENT_WAITING, "client initially waiting");
        c.clients[i] = CLIENT_NONCE_RECEIVED;
    }

    TEST_ASSERT_EQ(ceremony_count_in_state(&c, CLIENT_NONCE_RECEIVED), 4, "all received");
    TEST_ASSERT_EQ(ceremony_count_in_state(&c, CLIENT_WAITING), 0, "none waiting");
    TEST_ASSERT(ceremony_has_quorum(&c), "quorum met");

    size_t active[4];
    size_t n_active = ceremony_get_active_clients(&c, active, 4);
    TEST_ASSERT_EQ(n_active, 4, "all active");

    return 1;
}

int test_ceremony_one_timeout(void) {
    ceremony_t c;
    ceremony_init(&c, 4, 30, 2);

    /* 3 respond, 1 times out */
    c.clients[0] = CLIENT_NONCE_RECEIVED;
    c.clients[1] = CLIENT_NONCE_RECEIVED;
    c.clients[2] = CLIENT_TIMED_OUT;
    c.clients[3] = CLIENT_NONCE_RECEIVED;

    TEST_ASSERT_EQ(ceremony_count_in_state(&c, CLIENT_NONCE_RECEIVED), 3, "3 received");
    TEST_ASSERT_EQ(ceremony_count_in_state(&c, CLIENT_TIMED_OUT), 1, "1 timed out");
    TEST_ASSERT(ceremony_has_quorum(&c), "quorum still met with 3/4");

    size_t active[4];
    size_t n_active = ceremony_get_active_clients(&c, active, 4);
    TEST_ASSERT_EQ(n_active, 3, "3 active");

    /* Verify active indices are correct (0, 1, 3) */
    TEST_ASSERT_EQ(active[0], 0, "active[0] = 0");
    TEST_ASSERT_EQ(active[1], 1, "active[1] = 1");
    TEST_ASSERT_EQ(active[2], 3, "active[2] = 3");

    return 1;
}

int test_ceremony_below_minimum(void) {
    ceremony_t c;
    ceremony_init(&c, 4, 30, 3);  /* min_clients = 3 */

    /* Only 2 respond, rest time out */
    c.clients[0] = CLIENT_NONCE_RECEIVED;
    c.clients[1] = CLIENT_TIMED_OUT;
    c.clients[2] = CLIENT_TIMED_OUT;
    c.clients[3] = CLIENT_NONCE_RECEIVED;

    TEST_ASSERT(!ceremony_has_quorum(&c), "quorum NOT met with 2/4 (min=3)");

    size_t active[4];
    size_t n_active = ceremony_get_active_clients(&c, active, 4);
    TEST_ASSERT_EQ(n_active, 2, "only 2 active");

    return 1;
}

int test_ceremony_state_transitions(void) {
    ceremony_t c;
    ceremony_init(&c, 3, 10, 2);

    /* Walk through state machine */
    c.state = CEREMONY_COLLECTING_NONCES;
    TEST_ASSERT_EQ(c.state, CEREMONY_COLLECTING_NONCES, "collecting nonces");

    /* All send nonces */
    for (size_t i = 0; i < 3; i++)
        c.clients[i] = CLIENT_NONCE_RECEIVED;

    c.state = CEREMONY_DISTRIBUTING_NONCES;
    TEST_ASSERT_EQ(c.state, CEREMONY_DISTRIBUTING_NONCES, "distributing");

    c.state = CEREMONY_COLLECTING_PSIGS;
    /* All send psigs */
    for (size_t i = 0; i < 3; i++)
        c.clients[i] = CLIENT_PSIG_RECEIVED;

    c.state = CEREMONY_FINALIZING;
    TEST_ASSERT_EQ(ceremony_count_in_state(&c, CLIENT_PSIG_RECEIVED), 3, "all psigs");

    c.state = CEREMONY_DONE;
    TEST_ASSERT_EQ(c.state, CEREMONY_DONE, "done");

    /* Test error client doesn't affect quorum count */
    ceremony_init(&c, 3, 10, 2);
    c.clients[0] = CLIENT_NONCE_RECEIVED;
    c.clients[1] = CLIENT_ERROR;
    c.clients[2] = CLIENT_NONCE_RECEIVED;
    TEST_ASSERT(ceremony_has_quorum(&c), "quorum met despite error (2 active >= min 2)");

    return 1;
}

int test_ceremony_retry_excludes_timeout(void) {
    ceremony_t c;
    ceremony_init(&c, 4, 30, 2);

    /* Simulate: 3 respond, 1 times out */
    c.clients[0] = CLIENT_NONCE_RECEIVED;
    c.clients[1] = CLIENT_TIMED_OUT;
    c.clients[2] = CLIENT_NONCE_RECEIVED;
    c.clients[3] = CLIENT_ERROR;
    c.state = CEREMONY_ABORTED;

    /* Prepare retry: active clients reset to WAITING, excluded stay */
    size_t active = ceremony_prepare_retry(&c);
    TEST_ASSERT_EQ(active, 2, "2 active after retry prep");
    TEST_ASSERT_EQ(c.state, CEREMONY_INIT, "state reset to INIT");
    TEST_ASSERT_EQ(c.clients[0], CLIENT_WAITING, "client 0 reset to waiting");
    TEST_ASSERT_EQ(c.clients[1], CLIENT_TIMED_OUT, "client 1 stays timed out");
    TEST_ASSERT_EQ(c.clients[2], CLIENT_WAITING, "client 2 reset to waiting");
    TEST_ASSERT_EQ(c.clients[3], CLIENT_ERROR, "client 3 stays error");

    /* Active clients list should be {0, 2} */
    size_t active_arr[4];
    size_t n_active = ceremony_get_active_clients(&c, active_arr, 4);
    TEST_ASSERT_EQ(n_active, 2, "2 active clients");
    TEST_ASSERT_EQ(active_arr[0], 0, "active[0] = 0");
    TEST_ASSERT_EQ(active_arr[1], 2, "active[1] = 2");

    return 1;
}

int test_funding_reserve_check(void) {
    /* Sufficient: 100000 >= 80000 + 10000 */
    TEST_ASSERT(ceremony_check_funding_reserve(100000, 80000, 10000),
                "sufficient reserve");

    /* Exact match: 90000 >= 80000 + 10000 */
    TEST_ASSERT(ceremony_check_funding_reserve(90000, 80000, 10000),
                "exact reserve");

    /* Insufficient: 89999 < 80000 + 10000 */
    TEST_ASSERT(!ceremony_check_funding_reserve(89999, 80000, 10000),
                "insufficient reserve");

    /* Zero fees: 80000 >= 80000 + 0 */
    TEST_ASSERT(ceremony_check_funding_reserve(80000, 80000, 0),
                "zero fee reserve");

    return 1;
}
