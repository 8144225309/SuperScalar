/* #9: unit tests for the mainnet cheat/test-hook startup refusal (Layer 1). */
#include "superscalar/cheat_guard.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef TEST_ASSERT
#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "  FAIL: %s\n", msg); return 0; } \
} while (0)
#endif

int test_cheat_guard_mainnet_refusal(void) {
    char *prog = (char *)"superscalar_lsp";

    /* --- mainnet: every dev/test/cheat surface is refused --- */
    { char *a[] = { prog, (char *)"--cheat-leaf", (char *)"0" };
      TEST_ASSERT(ss_find_mainnet_cheat(3, a, "mainnet") != NULL, "mainnet refuses --cheat-leaf"); }
    { char *a[] = { prog, (char *)"--cheat-daemon-leaf" };
      TEST_ASSERT(ss_find_mainnet_cheat(2, a, "mainnet") != NULL, "mainnet refuses --cheat-daemon-leaf"); }
    { char *a[] = { prog, (char *)"--test-burn" };
      TEST_ASSERT(ss_find_mainnet_cheat(2, a, "mainnet") != NULL, "mainnet refuses --test-burn"); }
    { char *a[] = { prog, (char *)"--breach-test" };
      TEST_ASSERT(ss_find_mainnet_cheat(2, a, "mainnet") != NULL, "mainnet refuses --breach-test"); }
    { char *a[] = { prog, (char *)"--kill-after-state-advance" };
      TEST_ASSERT(ss_find_mainnet_cheat(2, a, "mainnet") != NULL, "mainnet refuses --kill-after-*"); }
    { char *a[] = { prog, (char *)"--demo" };
      TEST_ASSERT(ss_find_mainnet_cheat(2, a, "mainnet") != NULL, "mainnet refuses --demo"); }
    /* "bitcoin" is the mainnet alias */
    { char *a[] = { prog, (char *)"--cheat-leaf" };
      TEST_ASSERT(ss_find_mainnet_cheat(2, a, "bitcoin") != NULL, "bitcoin alias refuses cheats"); }
    /* NULL/unknown network => fail-safe (treat as mainnet) */
    { char *a[] = { prog, (char *)"--cheat-leaf" };
      TEST_ASSERT(ss_find_mainnet_cheat(2, a, NULL) != NULL, "NULL network refuses cheat (fail-safe)"); }
    { char *a[] = { prog, (char *)"--cheat-leaf" };
      TEST_ASSERT(ss_find_mainnet_cheat(2, a, "wibble") != NULL, "unknown network refuses cheat (fail-safe)"); }

    /* --- mainnet: legitimate production flags are NOT refused --- */
    { char *a[] = { prog, (char *)"--port", (char *)"9735", (char *)"--db", (char *)"l.db",
                    (char *)"--enable-hashlock-poison", (char *)"--wallet", (char *)"w" };
      TEST_ASSERT(ss_find_mainnet_cheat(8, a, "mainnet") == NULL, "mainnet allows clean prod args"); }
    /* --enable-hashlock-poison is a production SECURITY feature, never a cheat */
    { char *a[] = { prog, (char *)"--enable-hashlock-poison" };
      TEST_ASSERT(ss_find_mainnet_cheat(2, a, "mainnet") == NULL, "mainnet allows --enable-hashlock-poison"); }

    /* --- non-mainnet networks intentionally permit cheats (for testing) --- */
    { char *a[] = { prog, (char *)"--cheat-leaf" };
      TEST_ASSERT(ss_find_mainnet_cheat(2, a, "regtest") == NULL, "regtest permits cheats");
      TEST_ASSERT(ss_find_mainnet_cheat(2, a, "signet")  == NULL, "signet permits cheats");
      TEST_ASSERT(ss_find_mainnet_cheat(2, a, "testnet") == NULL, "testnet permits cheats"); }

    /* --- env-var cheats (SS_CHEAT*/SS_KILL*) are caught on mainnet --- */
    setenv("SS_CHEAT_OMIT_POISON", "1", 1);
    { char *a[] = { prog, (char *)"--port", (char *)"9735" };
      TEST_ASSERT(ss_find_mainnet_cheat(3, a, "mainnet") != NULL, "mainnet refuses SS_CHEAT_* env");
      TEST_ASSERT(ss_find_mainnet_cheat(3, a, "regtest") == NULL, "regtest permits SS_CHEAT_* env"); }
    unsetenv("SS_CHEAT_OMIT_POISON");
    { char *a[] = { prog, (char *)"--port", (char *)"9735" };
      TEST_ASSERT(ss_find_mainnet_cheat(3, a, "mainnet") == NULL, "mainnet clean once env cleared"); }
    setenv("SS_KILL_AFTER_STATE_ADVANCE", "1", 1);
    { char *a[] = { prog };
      TEST_ASSERT(ss_find_mainnet_cheat(1, a, "mainnet") != NULL, "mainnet refuses SS_KILL_* env"); }
    unsetenv("SS_KILL_AFTER_STATE_ADVANCE");

    printf("  cheat_guard: mainnet refuses --cheat/--test/--breach/--kill/--demo + SS_CHEAT/SS_KILL env; "
           "prod flags allowed; non-mainnet permits\n");
    return 1;
}
