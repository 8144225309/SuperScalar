/* SF-CRASH-INJECT-WIRE #245 Half B unit tests.
 *
 * Validates:
 *  1. MSG_FORCE_OUT codec round-trip with named checkpoint.
 *  2. MSG_FORCE_OUT empty name parses cleanly (immediate-abort sentinel).
 *  3. MSG_ROTATE codec mode round-trip.
 *  4. lsp_crash_set_target + lsp_crash_checkpoint fork-and-abort.
 *  5. Mismatch checkpoint is a no-op (does not abort).
 *
 * The fork-and-abort tests use POSIX fork() + waitpid() to verify the
 * child terminated with SIGABRT.  Skipped on platforms without fork().
 */
#include "superscalar/crash_inject.h"
#include "superscalar/wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

/* Test 1: MSG_FORCE_OUT codec round-trip. */
int test_crash_force_out_codec_round_trip(void) {
    cJSON *j = wire_build_force_out("factory_creation_propose");
    TEST_ASSERT(j != NULL, "build_force_out returned NULL");
    char name[64] = {0};
    int ok = wire_parse_force_out(j, name);
    cJSON_Delete(j);
    TEST_ASSERT(ok == 1, "parse_force_out failed");
    TEST_ASSERT(strcmp(name, "factory_creation_propose") == 0,
                "parsed name mismatch");
    return 1;
}

/* Test 2: empty checkpoint name parses cleanly (immediate-abort sentinel). */
int test_crash_force_out_empty_name(void) {
    cJSON *j = wire_build_force_out("");
    TEST_ASSERT(j != NULL, "build_force_out(empty) returned NULL");
    char name[64];
    /* Pre-fill to non-zero to verify parser explicitly zeroes. */
    memset(name, 0xAA, sizeof(name));
    int ok = wire_parse_force_out(j, name);
    cJSON_Delete(j);
    TEST_ASSERT(ok == 1, "parse_force_out(empty) failed");
    TEST_ASSERT(name[0] == '\0', "expected empty string for omitted checkpoint");
    return 1;
}

/* Test 3: MSG_ROTATE codec mode round-trip. */
int test_crash_rotate_codec_round_trip(void) {
    cJSON *j = wire_build_rotate(1);
    TEST_ASSERT(j != NULL, "build_rotate returned NULL");
    uint8_t mode = 0xff;
    int ok = wire_parse_rotate(j, &mode);
    cJSON_Delete(j);
    TEST_ASSERT(ok == 1, "parse_rotate failed");
    TEST_ASSERT(mode == 1, "mode round-trip mismatch");

    /* Default mode = 0 also round-trips. */
    cJSON *j0 = wire_build_rotate(0);
    uint8_t m0 = 0xff;
    ok = wire_parse_rotate(j0, &m0);
    cJSON_Delete(j0);
    TEST_ASSERT(ok == 1, "parse_rotate(0) failed");
    TEST_ASSERT(m0 == 0, "mode 0 round-trip mismatch");
    return 1;
}

/* Test 4: lsp_crash_set_target + lsp_crash_checkpoint fork-and-abort. */
int test_crash_runtime_target_aborts(void) {
    pid_t pid = fork();
    if (pid < 0) {
        printf("  SKIP: %s: fork() failed (errno=%d)\n", __func__, errno);
        return 1;  /* not a hard failure on constrained CI */
    }
    if (pid == 0) {
        /* Child: install target, trigger checkpoint, should abort. */
        /* Silence the child's abort() stderr noise.  Cast: cppcheck flags
           freopen() retval unused; we genuinely don't care if stderr
           silencing fails — the child only runs to abort. */
        (void)!freopen("/dev/null", "w", stderr);
        lsp_crash_set_target("crash_unit_test_target");
        lsp_crash_checkpoint("crash_unit_test_target");
        _exit(0);  /* unreachable on success */
    }
    int status = 0;
    pid_t w = waitpid(pid, &status, 0);
    TEST_ASSERT(w == pid, "waitpid failed");
    TEST_ASSERT(WIFSIGNALED(status), "child did not exit via signal");
    TEST_ASSERT(WTERMSIG(status) == SIGABRT, "child did not abort with SIGABRT");
    return 1;
}

/* Test 5: mismatch is a no-op (does not abort). */
int test_crash_checkpoint_mismatch_noop(void) {
    /* Install a target then hit a DIFFERENT checkpoint -- must return cleanly. */
    lsp_crash_set_target("target_foo");
    lsp_crash_checkpoint("target_bar");  /* mismatch: must return */
    lsp_crash_set_target(NULL);          /* clear */
    lsp_crash_checkpoint("target_foo");  /* now uninstalled: must return */
    /* Also verify NULL name is safe. */
    lsp_crash_checkpoint(NULL);
    return 1;
}
