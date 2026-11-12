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

/* The funding depth both daemons default to, and the override. */
int test_network_funding_confs(void) {
    TEST_ASSERT(network_funding_confs("regtest", 0) == 1, "regtest default 1");
    TEST_ASSERT(network_funding_confs("signet", 0) == 3, "signet default 3");
    TEST_ASSERT(network_funding_confs("testnet", 0) == 3, "testnet default 3");
    TEST_ASSERT(network_funding_confs("testnet4", 0) == 3, "testnet4 default 3");
    for (size_t i = 0; i < N_MAINNET; i++)
        TEST_ASSERT(network_funding_confs(MAINNET_NAMES[i], 0) == 6, "mainnet default 6");
    TEST_ASSERT(network_funding_confs("mainnet", 2) == 2, "override wins");
    TEST_ASSERT(network_funding_confs("regtest", 4) == 4, "override wins on regtest");
    TEST_ASSERT(network_funding_confs("signet", -1) == 3, "non-positive override ignored");
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

int test_network_gate_no_experimental_jit(void) {
    char err[512];
    char *const clean_argv[] = { "daemon", "--db", "x.db", NULL };
    for (size_t i = 0; i < N_MAINNET; i++) {
        err[0] = (char)0;
        TEST_ASSERT(!network_gate_no_experimental_jit(MAINNET_NAMES[i], 1, err, sizeof(err)),
                    "the JIT opt-in is refused on mainnet");
        TEST_ASSERT(strstr(err, "--enable-jit-experimental") != NULL,
                    "message names the flag");
        TEST_ASSERT(network_gate_no_experimental_jit(MAINNET_NAMES[i], 0, err, sizeof(err)),
                    "mainnet without the opt-in passes");

        /* The LSP start-up check applies it. */
        network_startup_t st = {
            .role = NETWORK_ROLE_LSP, .network = MAINNET_NAMES[i], .accept_risk = 1,
            .seckey_on_cmdline = 0, .have_db = 1, .have_wt_db = 1,
            .argc = 3, .argv = clean_argv, .envp = NULL,
        };
        TEST_ASSERT(network_startup_gates(&st, err, sizeof(err)),
                    "a complete mainnet start passes");
        st.enable_jit_experimental = 1;
        TEST_ASSERT(!network_startup_gates(&st, err, sizeof(err)),
                    "a mainnet start with the JIT opt-in is refused");
    }
    for (size_t i = 0; i < N_OTHER; i++)
        TEST_ASSERT(network_gate_no_experimental_jit(OTHER_NAMES[i], 1, err, sizeof(err)),
                    "test chains may opt in");
    return 1;
}

int test_network_gate_no_experimental_rotation(void) {
    char err[512];
    char *const clean_argv[] = { "daemon", "--db", "x.db", NULL };
    for (size_t i = 0; i < N_MAINNET; i++) {
        err[0] = (char)0;
        TEST_ASSERT(!network_gate_no_experimental_rotation(MAINNET_NAMES[i], 1,
                                                           err, sizeof(err)),
                    "the rotation opt-in is refused on mainnet");
        TEST_ASSERT(strstr(err, "--enable-rotation-experimental") != NULL,
                    "message names the flag");
        TEST_ASSERT(network_gate_no_experimental_rotation(MAINNET_NAMES[i], 0,
                                                          err, sizeof(err)),
                    "mainnet without the opt-in passes");

        /* The start-up check applies it. */
        network_startup_t st = {
            .role = NETWORK_ROLE_LSP, .network = MAINNET_NAMES[i], .accept_risk = 1,
            .seckey_on_cmdline = 0, .have_db = 1, .have_wt_db = 1,
            .argc = 3, .argv = clean_argv, .envp = NULL,
        };
        TEST_ASSERT(network_startup_gates(&st, err, sizeof(err)),
                    "a complete mainnet start passes");
        st.enable_rotation_experimental = 1;
        err[0] = (char)0;
        TEST_ASSERT(!network_startup_gates(&st, err, sizeof(err)),
                    "a mainnet start with the rotation opt-in is refused");
        TEST_ASSERT(strstr(err, "--enable-rotation-experimental") != NULL,
                    "refused by the rotation gate");
    }
    for (size_t i = 0; i < N_OTHER; i++) {
        TEST_ASSERT(network_gate_no_experimental_rotation(OTHER_NAMES[i], 1,
                                                          err, sizeof(err)),
                    "test chains may opt in");
        network_startup_t st = {
            .role = NETWORK_ROLE_LSP, .network = OTHER_NAMES[i],
            .enable_rotation_experimental = 1,
            .argc = 3, .argv = clean_argv, .envp = NULL,
        };
        TEST_ASSERT(network_startup_gates(&st, err, sizeof(err)),
                    "a test-chain start with the rotation opt-in passes");
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

/* The start-up check each daemon runs, with the gates that belong to its
   role.  A start that satisfies every gate passes; taking any one thing away
   is refused, under either spelling of mainnet. */
int test_network_startup_gates_per_role(void) {
    char err[512];
    char *const clean_argv[] = { "daemon", "--db", "x.db", NULL };
    char *const cheat_argv[] = { "daemon", "--cheat-daemon", NULL };
    char *const clean_env[]  = { "PATH=/usr/bin", NULL };
    char *const cheat_env[]  = { "SS_CHEAT_DUST_RACE=1", NULL };

    static const network_role_t roles[] = {
        NETWORK_ROLE_LSP, NETWORK_ROLE_CLIENT, NETWORK_ROLE_WATCHTOWER
    };

    for (size_t r = 0; r < sizeof(roles) / sizeof(roles[0]); r++) {
        network_role_t role = roles[r];
        int holds_key = role != NETWORK_ROLE_WATCHTOWER;

        for (size_t i = 0; i < N_MAINNET; i++) {
            const network_startup_t good = {
                .role = role, .network = MAINNET_NAMES[i], .accept_risk = 1,
                .seckey_on_cmdline = 0, .have_db = 1, .have_wt_db = 1,
                .argc = 3, .argv = clean_argv, .envp = clean_env,
            };
            TEST_ASSERT(network_startup_gates(&good, err, sizeof(err)),
                        "a complete mainnet start passes");

            network_startup_t s = good;
            s.accept_risk = 0;
            err[0] = '\0';
            TEST_ASSERT(!network_startup_gates(&s, err, sizeof(err)),
                        "every role needs the risk acknowledgement");
            TEST_ASSERT(strstr(err, "--i-accept-the-risk") != NULL, "risk message");

            s = good;
            s.argc = 2;
            s.argv = cheat_argv;
            TEST_ASSERT(!network_startup_gates(&s, err, sizeof(err)),
                        "every role refuses cheat flags");
            s = good;
            s.envp = cheat_env;
            TEST_ASSERT(!network_startup_gates(&s, err, sizeof(err)),
                        "every role refuses cheat environment variables");

            s = good;
            s.seckey_on_cmdline = 1;
            err[0] = '\0';
            TEST_ASSERT(network_startup_gates(&s, err, sizeof(err)) == !holds_key,
                        "LSP and client refuse --seckey on mainnet");
            if (holds_key)
                TEST_ASSERT(strstr(err, "--seckey") != NULL, "seckey message");

            s = good;
            s.have_db = 0;
            TEST_ASSERT(network_startup_gates(&s, err, sizeof(err)) == !holds_key,
                        "LSP and client need --db on mainnet");

            s = good;
            s.have_wt_db = 0;
            TEST_ASSERT(network_startup_gates(&s, err, sizeof(err)) ==
                            (role != NETWORK_ROLE_LSP),
                        "the LSP needs --wt-db on mainnet");
        }

        /* Other chains: none of the gates apply. */
        for (size_t i = 0; i < N_OTHER; i++) {
            const network_startup_t bare = {
                .role = role, .network = OTHER_NAMES[i], .seckey_on_cmdline = 1,
                .argc = 2, .argv = cheat_argv, .envp = cheat_env,
            };
            TEST_ASSERT(network_startup_gates(&bare, err, sizeof(err)),
                        "test chains pass without any of it");
        }

        /* A chain name that is not supported is refused for every role. */
        static const char *const unknown[] = { "livenet", "Mainnet", "", NULL };
        for (size_t i = 0; i < sizeof(unknown) / sizeof(unknown[0]); i++) {
            const network_startup_t bad = {
                .role = role, .network = unknown[i], .accept_risk = 1,
                .have_db = 1, .have_wt_db = 1,
                .argc = 3, .argv = clean_argv, .envp = clean_env,
            };
            err[0] = '\0';
            TEST_ASSERT(!network_startup_gates(&bad, err, sizeof(err)),
                        "unknown chain name is refused");
            TEST_ASSERT(strstr(err, "unknown --network") != NULL, "unknown-network message");
        }
    }

    TEST_ASSERT(!network_startup_gates(NULL, err, sizeof(err)), "NULL is refused");
    return 1;
}
