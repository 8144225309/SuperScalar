#include "superscalar/ceremony.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/select.h>

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

    /* Walk through state machine — verify counts at each stage */
    c.state = CEREMONY_COLLECTING_NONCES;
    TEST_ASSERT_EQ(ceremony_count_in_state(&c, CLIENT_WAITING), 3,
                   "all clients waiting initially");

    /* Simulate nonce receipt */
    for (size_t i = 0; i < 3; i++)
        c.clients[i] = CLIENT_NONCE_RECEIVED;
    TEST_ASSERT_EQ(ceremony_count_in_state(&c, CLIENT_NONCE_RECEIVED), 3,
                   "all 3 sent nonces");

    c.state = CEREMONY_DISTRIBUTING_NONCES;
    c.state = CEREMONY_COLLECTING_PSIGS;

    /* Simulate partial sig receipt */
    for (size_t i = 0; i < 3; i++)
        c.clients[i] = CLIENT_PSIG_RECEIVED;
    TEST_ASSERT_EQ(ceremony_count_in_state(&c, CLIENT_PSIG_RECEIVED), 3,
                   "all 3 sent psigs");

    c.state = CEREMONY_FINALIZING;
    c.state = CEREMONY_DONE;

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

/* ---------------------------------------------------------------------------
 * ceremony_select_all with HIGH-NUMBERED descriptors.
 *
 * This is the N=1024 blocker in miniature.  The old implementation used
 * select()/FD_SET, where FD_SET(fd, &set) sets bit `fd` in a fixed 1024-bit
 * fd_set.  The hazard is the descriptor VALUE, not how many are watched: a
 * single fd >= FD_SETSIZE writes past the end of a stack fd_set.  An LSP with
 * ~1000 client sockets plus DB handles and logs hands out exactly such
 * descriptors, so the ceremony would have corrupted its own stack -- the same
 * failure mode as the fixed [FACTORY_MAX_SIGNERS] arrays at N=256, one order
 * of magnitude further out.
 *
 * Here we deliberately push a socketpair above FD_SETSIZE with dup2 and require
 * correct results.  Under the old code this was undefined behaviour (and under
 * ASan, a stack-buffer-overflow); with poll() the value is irrelevant.
 * ------------------------------------------------------------------------- */
int test_ceremony_select_high_fds(void) {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) { printf("  SKIP: getrlimit\n"); return 1; }
    rlim_t want = (rlim_t)FD_SETSIZE + 64;
    if (rl.rlim_cur < want) {
        if (rl.rlim_max < want) { printf("  SKIP: fd hard limit too low\n"); return 1; }
        rl.rlim_cur = want;
        if (setrlimit(RLIMIT_NOFILE, &rl) != 0) { printf("  SKIP: setrlimit\n"); return 1; }
    }

    /* Two SEPARATE pairs, deliberately.  An earlier version of this test put
       the same fd in two slots and asserted both reported ready.  That passes
       on Linux and fails on macOS, because POSIX does not actually pin down
       how poll() treats a repeated fd within one array.  It was also testing
       something that cannot happen: production client_fds[] are distinct
       sockets, and a slot with no connection holds -1, not a duplicate.

       The property worth protecting is the one that blocks N=1024 -- that
       these paths work with fd VALUES above FD_SETSIZE, which select() cannot
       represent and which FD_SET would smash the stack on.  Distinct high fds
       test that directly and portably. */
    int sp1[2], sp2[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp1) != 0) { printf("  SKIP: socketpair\n"); return 1; }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp2) != 0) {
        close(sp1[0]); close(sp1[1]); printf("  SKIP: socketpair\n"); return 1;
    }

    /* Relocate both read ends ABOVE FD_SETSIZE — values select() cannot hold. */
    int hi1 = FD_SETSIZE + 7;
    int hi2 = FD_SETSIZE + 8;
    if (dup2(sp1[0], hi1) < 0 || dup2(sp2[0], hi2) < 0) {
        close(sp1[0]); close(sp1[1]); close(sp2[0]); close(sp2[1]);
        printf("  SKIP: dup2 high\n"); return 1;
    }
    close(sp1[0]); close(sp2[0]);
    TEST_ASSERT(hi1 >= FD_SETSIZE && hi2 >= FD_SETSIZE, "test fds are above FD_SETSIZE");

    int fds[3]  = { hi1, -1, hi2 };   /* -1 must still be skipped, as before */
    int ready[3];

    /* Nothing written yet -> timeout, all clear. */
    int n = ceremony_select_all(fds, 3, 0, ready);
    TEST_ASSERT_EQ(n, 0, "timeout with no data");
    TEST_ASSERT_EQ(ready[0], 0, "slot0 not ready");
    TEST_ASSERT_EQ(ready[2], 0, "slot2 not ready");

    /* Make both readable -> both high-fd slots report ready. */
    TEST_ASSERT(write(sp1[1], "x", 1) == 1, "write to peer 1");
    TEST_ASSERT(write(sp2[1], "x", 1) == 1, "write to peer 2");
    n = ceremony_select_all(fds, 3, 1, ready);
    TEST_ASSERT_EQ(n, 2, "both high fds are ready");
    TEST_ASSERT_EQ(ready[0], 1, "slot0 ready");
    TEST_ASSERT_EQ(ready[1], 0, "slot1 (-1) skipped");
    TEST_ASSERT_EQ(ready[2], 1, "slot2 ready");

    /* Peer hangup counts as ready, matching select(), so callers see EOF. */
    close(sp1[1]);
    { char b[8]; while (read(hi1, b, sizeof(b)) > 0) {} }
    n = ceremony_select_all(fds, 3, 1, ready);
    TEST_ASSERT(n >= 1, "hangup reported ready (select parity)");

    /* All-invalid set still returns -1. */
    int none[2] = { -1, -1 };
    int nready[2];
    TEST_ASSERT_EQ(ceremony_select_all(none, 2, 0, nready), -1, "no usable fd -> -1");

    close(hi1); close(hi2); close(sp2[1]);
    return 1;
}
