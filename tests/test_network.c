#include "superscalar/network.h"
#include "superscalar/cli_arity.h"
#include <stdio.h>
#include <string.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

/* Both spellings of mainnet; every gate must treat them alike. */
static const char *const MAINNET_NAMES[] = { "mainnet", "bitcoin" };
static const char *const OTHER_NAMES[] = { "regtest", "signet", "testnet", "testnet4" };
#define N_MAINNET (sizeof(MAINNET_NAMES) / sizeof(MAINNET_NAMES[0]))
#define N_OTHER   (sizeof(OTHER_NAMES) / sizeof(OTHER_NAMES[0]))

int test_network_is_mainnet(void) {
    TEST_ASSERT(network_is_mainnet("mainnet"), "mainnet is mainnet");
    TEST_ASSERT(network_is_mainnet("bitcoin"), "bitcoin is mainnet");
    for (size_t i = 0; i < N_OTHER; i++)
        TEST_ASSERT(!network_is_mainnet(OTHER_NAMES[i]), "test chain is not mainnet");
    TEST_ASSERT(!network_is_mainnet(NULL), "NULL is not mainnet");
    TEST_ASSERT(!network_is_mainnet(""), "empty is not mainnet");
    TEST_ASSERT(!network_is_mainnet("Mainnet"), "names are case-sensitive");
    TEST_ASSERT(!network_is_mainnet("mainnet "), "no trailing junk");
    return 1;
}

int test_network_canonical(void) {
    const char *c = network_canonical("bitcoin");
    TEST_ASSERT(c && strcmp(c, "mainnet") == 0, "bitcoin canonicalises to mainnet");
    c = network_canonical("mainnet");
    TEST_ASSERT(c && strcmp(c, "mainnet") == 0, "mainnet stays mainnet");
    for (size_t i = 0; i < N_OTHER; i++) {
        c = network_canonical(OTHER_NAMES[i]);
        TEST_ASSERT(c && strcmp(c, OTHER_NAMES[i]) == 0, "test chain maps to itself");
    }
    TEST_ASSERT(network_canonical(NULL) == NULL, "NULL is unknown");
    TEST_ASSERT(network_canonical("") == NULL, "empty is unknown");
    TEST_ASSERT(network_canonical("main") == NULL, "main is unknown");
    TEST_ASSERT(network_canonical("livenet") == NULL, "livenet is unknown");
    TEST_ASSERT(network_canonical("MAINNET") == NULL, "names are case-sensitive");
    return 1;
}

int test_network_gate_risk_accepted(void) {
    char err[512];
    for (size_t i = 0; i < N_MAINNET; i++) {
        err[0] = '\0';
        TEST_ASSERT(!network_gate_risk_accepted(MAINNET_NAMES[i], 0, err, sizeof(err)),
                    "mainnet without acknowledgement is refused");
        TEST_ASSERT(strstr(err, "--i-accept-the-risk") != NULL, "message names the flag");
        TEST_ASSERT(network_gate_risk_accepted(MAINNET_NAMES[i], 1, err, sizeof(err)),
                    "mainnet with acknowledgement passes");
    }
    for (size_t i = 0; i < N_OTHER; i++)
        TEST_ASSERT(network_gate_risk_accepted(OTHER_NAMES[i], 0, err, sizeof(err)),
                    "test chains need no acknowledgement");
    TEST_ASSERT(!network_gate_risk_accepted("bitcoin", 0, NULL, 0),
                "refusal does not need an error buffer");
    return 1;
}

int test_network_gate_cmdline_seckey(void) {
    char err[512];
    for (size_t i = 0; i < N_MAINNET; i++) {
        err[0] = '\0';
        TEST_ASSERT(!network_gate_cmdline_seckey(MAINNET_NAMES[i], 1, err, sizeof(err)),
                    "--seckey on mainnet is refused");
        TEST_ASSERT(strstr(err, "--keyfile") != NULL, "message points at --keyfile");
        TEST_ASSERT(network_gate_cmdline_seckey(MAINNET_NAMES[i], 0, err, sizeof(err)),
                    "mainnet without --seckey passes");
    }
    for (size_t i = 0; i < N_OTHER; i++)
        TEST_ASSERT(network_gate_cmdline_seckey(OTHER_NAMES[i], 1, err, sizeof(err)),
                    "test chains may use --seckey");
    return 1;
}

int test_network_gate_no_test_scaffolding(void) {
    char err[512];
    char *const clean_argv[] = { "prog", "--network", "bitcoin", "--db", "x.db", NULL };
    char *const cheat_argv[] = { "prog", "--db", "x.db", "--cheat-daemon", NULL };
    char *const test_argv[]  = { "prog", "--test-expiry", NULL };
    /* argv[0] is the program name, never an option. */
    char *const prog_argv[]  = { "--test-prog", "--db", "x.db", NULL };
    char *const clean_env[]  = { "PATH=/usr/bin", "HOME=/root", "SSH_TTY=x", NULL };
    char *const cheat_env[]  = { "PATH=/usr/bin", "SS_CHEAT_DUST_RACE=1", NULL };
    char *const kill_env[]   = { "SS_KILL_AT=3", NULL };
    char *const crash_env[]  = { "SUPERSCALAR_CRASH_ALLOW=1", NULL };

    for (size_t i = 0; i < N_MAINNET; i++) {
        const char *net = MAINNET_NAMES[i];
        TEST_ASSERT(network_gate_no_test_scaffolding(net, 5, clean_argv, clean_env,
                                                     err, sizeof(err)),
                    "clean mainnet start passes");
        TEST_ASSERT(network_gate_no_test_scaffolding(net, 3, prog_argv, NULL,
                                                     err, sizeof(err)),
                    "argv[0] is not checked; NULL environment is fine");

        err[0] = '\0';
        TEST_ASSERT(!network_gate_no_test_scaffolding(net, 4, cheat_argv, clean_env,
                                                      err, sizeof(err)),
                    "--cheat-* is refused on mainnet");
        TEST_ASSERT(strstr(err, "--cheat-daemon") != NULL, "message names the flag");
        TEST_ASSERT(!network_gate_no_test_scaffolding(net, 2, test_argv, clean_env,
                                                      err, sizeof(err)),
                    "--test-* is refused on mainnet");

        err[0] = '\0';
        TEST_ASSERT(!network_gate_no_test_scaffolding(net, 5, clean_argv, cheat_env,
                                                      err, sizeof(err)),
                    "SS_CHEAT* is refused on mainnet");
        TEST_ASSERT(strstr(err, "SS_CHEAT_DUST_RACE") != NULL, "message names the variable");
        TEST_ASSERT(!network_gate_no_test_scaffolding(net, 5, clean_argv, kill_env,
                                                      err, sizeof(err)),
                    "SS_KILL* is refused on mainnet");
        TEST_ASSERT(!network_gate_no_test_scaffolding(net, 5, clean_argv, crash_env,
                                                      err, sizeof(err)),
                    "SUPERSCALAR_CRASH* is refused on mainnet");
    }

    for (size_t i = 0; i < N_OTHER; i++) {
        TEST_ASSERT(network_gate_no_test_scaffolding(OTHER_NAMES[i], 4, cheat_argv,
                                                     cheat_env, err, sizeof(err)),
                    "test chains may use test scaffolding");
    }
    return 1;
}

int test_network_gate_db(void) {
    char err[512];
    for (size_t i = 0; i < N_MAINNET; i++) {
        err[0] = '\0';
        TEST_ASSERT(!network_gate_db(MAINNET_NAMES[i], 0, err, sizeof(err)),
                    "mainnet without --db is refused");
        TEST_ASSERT(strstr(err, "--db") != NULL, "message names --db");
        TEST_ASSERT(network_gate_db(MAINNET_NAMES[i], 1, err, sizeof(err)),
                    "mainnet with --db passes");

        err[0] = '\0';
        TEST_ASSERT(!network_gate_watchtower_db(MAINNET_NAMES[i], 0, err, sizeof(err)),
                    "mainnet without --wt-db is refused");
        TEST_ASSERT(strstr(err, "--wt-db") != NULL, "message names --wt-db");
        TEST_ASSERT(network_gate_watchtower_db(MAINNET_NAMES[i], 1, err, sizeof(err)),
                    "mainnet with --wt-db passes");
    }
    for (size_t i = 0; i < N_OTHER; i++) {
        TEST_ASSERT(network_gate_db(OTHER_NAMES[i], 0, err, sizeof(err)),
                    "test chains may run without --db");
        TEST_ASSERT(network_gate_watchtower_db(OTHER_NAMES[i], 0, err, sizeof(err)),
                    "test chains may run without --wt-db");
    }
    return 1;
}

/* The step-blocks floor is a mainnet gate that lives in the CLI validator. */
int test_network_mainnet_step_floor_alias(void) {
    char err[256];
    for (size_t i = 0; i < N_MAINNET; i++) {
        TEST_ASSERT(!cli_validate_mainnet_step_floor(MAINNET_NAMES[i], 10, err, sizeof(err)),
                    "step floor applies on mainnet");
        TEST_ASSERT(cli_validate_mainnet_step_floor(MAINNET_NAMES[i], 144, err, sizeof(err)),
                    "step at the floor passes");
    }
    for (size_t i = 0; i < N_OTHER; i++)
        TEST_ASSERT(cli_validate_mainnet_step_floor(OTHER_NAMES[i], 10, err, sizeof(err)),
                    "no step floor on test chains");
    return 1;
}
