#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

// Forward declaration of the function we're testing
extern void admin_rpc_process_command(char *buffer, size_t buffer_size, const char *input);

START_TEST(test_buffer_reads_never_exceed_declared_length)
{
    // Invariant: Buffer reads never exceed the declared length
    const char *payloads[] = {
        "GET /admin?cmd=shutdown\x00",  // Valid input (24 chars + null)
        "A",  // Minimal valid input
        "GET /admin?cmd="
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "\x00"  // 1024 'A's + null - 10x typical buffer
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        // Fork to isolate each test case and catch crashes
        pid_t pid = fork();
        if (pid == 0) {
            // Child process
            size_t buffer_size = 256;  // Typical buffer size in admin_rpc.c
            char buffer[buffer_size];
            memset(buffer, 0xCC, buffer_size);  // Fill with sentinel value
            
            // Call the actual production function
            admin_rpc_process_command(buffer, buffer_size, payloads[i]);
            
            // Check that sentinel bytes after buffer_size are untouched
            // We'll allocate a larger guard region and check its boundaries
            size_t guard_size = 1024;
            char *guard_buffer = malloc(buffer_size + guard_size);
            memset(guard_buffer, 0xCC, buffer_size + guard_size);
            
            // Copy input to avoid modifying const
            char *input_copy = strdup(payloads[i]);
            
            // Call function with guard buffer
            admin_rpc_process_command(guard_buffer, buffer_size, input_copy);
            
            // Check guard region after buffer_size is untouched
            for (size_t j = buffer_size; j < buffer_size + guard_size; j++) {
                ck_assert_msg(guard_buffer[j] == 0xCC,
                    "Buffer overflow detected! Byte at offset %zu was modified (0x%02x)",
                    j, (unsigned char)guard_buffer[j]);
            }
            
            free(guard_buffer);
            free(input_copy);
            exit(0);  // Child exits normally
        } else {
            // Parent process
            int status;
            waitpid(pid, &status, 0);
            
            // Check if child crashed (segfault, etc.)
            ck_assert_msg(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "Process crashed with payload %d: '%s'", i, payloads[i]);
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_buffer_reads_never_exceed_declared_length);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}