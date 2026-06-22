/* #9: mainnet cheat/test-hook startup refusal (Layer 1).
   See include/superscalar/cheat_guard.h.  Layer 2 (per-site inert reads) is the
   pre-existing superscalar_cheat_allowed() in crash_inject.c. */
#include "superscalar/cheat_guard.h"
#include <string.h>

extern char **environ;

/* Argv tokens that are unambiguously dev/test/cheat (never valid on mainnet).
   Prefix match => future --cheat-X / --test-X are caught without code changes. */
static const char *const ARG_PREFIXES[] = {
    "--cheat", "--test-", "--breach", "--kill-after", "--demo", NULL
};
/* Environment-variable test/cheat toggles. */
static const char *const ENV_PREFIXES[] = {
    "SS_CHEAT", "SS_KILL", NULL
};

/* Cheats are permitted ONLY on a known dev/test network (allowlist).  Anything
   else - mainnet, bitcoin, an unknown string, or NULL - is treated as production
   and enforced (fail-safe: a new/unrecognized network never silently permits a
   cheat; it must be added here explicitly). */
static int is_dev_network(const char *network) {
    return network != NULL && (
        strcmp(network, "regtest")  == 0 ||
        strcmp(network, "testnet")  == 0 ||
        strcmp(network, "testnet4") == 0 ||
        strcmp(network, "signet")   == 0);
}

const char *ss_find_mainnet_cheat(int argc, char **argv, const char *network) {
    if (is_dev_network(network)) return NULL;  /* dev/test network: cheats permitted */
    /* production (mainnet/bitcoin) or unknown/NULL: enforce the refusal. */

    for (int i = 1; i < argc; i++) {
        if (!argv[i]) continue;
        for (const char *const *p = ARG_PREFIXES; *p; p++)
            if (strncmp(argv[i], *p, strlen(*p)) == 0) return argv[i];
    }
    for (char **e = environ; e && *e; e++) {
        for (const char *const *p = ENV_PREFIXES; *p; p++)
            if (strncmp(*e, *p, strlen(*p)) == 0) return *e;
    }
    return NULL;
}
