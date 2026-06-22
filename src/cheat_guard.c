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

const char *ss_find_mainnet_cheat(int argc, char **argv, const char *network) {
    /* Only enforced on mainnet/bitcoin; NULL/unknown network treated as mainnet
       (fail-safe).  Dev/test networks (regtest/testnet/signet) permit cheats. */
    if (network &&
        strcmp(network, "mainnet") != 0 &&
        strcmp(network, "bitcoin") != 0)
        return NULL;

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
