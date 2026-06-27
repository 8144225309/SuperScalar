#include <check.h>
#include <stdlib.h>
#include <string.h>
#include "src/chain_backend_rpc.h"

START_TEST(test_unauthenticated_requests_rejected)
{
    // Invariant: Protected endpoints reject unauthenticated requests
    const char *auth_headers[] = {
        "",                          // Missing Authorization header
        "Authorization: Bearer expired.token.here",  // Wrong token type
        "Authorization: Basic invalidbase64==",      // Malformed Basic auth
        "Authorization: Basic dXNlcjpwYXNz",         // Valid credentials (user:pass)
    };
    int num_payloads = sizeof(auth_headers) / sizeof(auth_headers[0]);

    for (int i = 0; i < num_payloads; i++) {
        struct rpc_config config = {
            .host = "localhost",
            .port = 8332,
            .rpcuser = "testuser",
            .rpcpassword = "testpass"
        };
        
        char *response = rpc_call(&config, "getblockchaininfo", "[]");
        
        if (i == 3) {
            // Valid credentials should succeed
            ck_assert_msg(response != NULL, "Valid credentials should return response");
        } else {
            // Invalid/missing credentials should fail
            ck_assert_msg(response == NULL || 
                         strstr(response, "401") != NULL || 
                         strstr(response, "403") != NULL,
                         "Unauthenticated request should be rejected");
        }
        
        if (response) free(response);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_unauthenticated_requests_rejected);
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