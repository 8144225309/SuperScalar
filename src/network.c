#include "superscalar/network.h"
#include <stdio.h>
#include <string.h>

int network_is_mainnet(const char *network) {
    return network != NULL &&
           (strcmp(network, "mainnet") == 0 || strcmp(network, "bitcoin") == 0);
}

const char *network_canonical(const char *network) {
    static const char *const names[] = {
        "regtest", "signet", "testnet", "testnet4", "mainnet"
    };
    if (!network) return NULL;
    if (network_is_mainnet(network)) return "mainnet";
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (strcmp(network, names[i]) == 0) return names[i];
    }
    return NULL;
}

static int has_prefix(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

int network_gate_risk_accepted(const char *network, int accept_risk,
                               char *err_buf, size_t err_buf_len) {
    if (!network_is_mainnet(network) || accept_risk) return 1;
    if (err_buf && err_buf_len)
        snprintf(err_buf, err_buf_len,
            "Error: mainnet operation refused.\n"
            "SuperScalar is a PROTOTYPE. Running on mainnet risks loss of funds.\n"
            "If you understand this risk, pass --i-accept-the-risk\n");
    return 0;
}

int network_gate_cmdline_seckey(const char *network, int seckey_on_cmdline,
                                char *err_buf, size_t err_buf_len) {
    if (!network_is_mainnet(network) || !seckey_on_cmdline) return 1;
    if (err_buf && err_buf_len)
        snprintf(err_buf, err_buf_len,
            "Error: --seckey is refused on mainnet (visible via ps / shell history).\n"
            "Use --keyfile PATH (encrypted at rest); create one with --generate-mnemonic\n"
            "or --from-mnemonic, optionally protected by --passphrase.\n");
    return 0;
}

int network_gate_no_test_scaffolding(const char *network,
                                     int argc, char *const *argv,
                                     char *const *envp,
                                     char *err_buf, size_t err_buf_len) {
    if (!network_is_mainnet(network)) return 1;

    for (int i = 1; argv && i < argc; i++) {
        if (!argv[i]) continue;
        if (has_prefix(argv[i], "--cheat-") || has_prefix(argv[i], "--test-")) {
            if (err_buf && err_buf_len)
                snprintf(err_buf, err_buf_len,
                    "Error: %s is test/cheat scaffolding and is refused on mainnet.\n",
                    argv[i]);
            return 0;
        }
    }

    /* Prefix matches, so every variable of each family is caught. */
    for (char *const *e = envp; e && *e; e++) {
        if (has_prefix(*e, "SS_CHEAT") || has_prefix(*e, "SS_KILL") ||
            has_prefix(*e, "SUPERSCALAR_CRASH")) {
            if (err_buf && err_buf_len)
                snprintf(err_buf, err_buf_len,
                    "Error: test/cheat env var (%.40s) is refused on mainnet.\n", *e);
            return 0;
        }
    }
    return 1;
}

int network_gate_db(const char *network, int have_db,
                    char *err_buf, size_t err_buf_len) {
    if (!network_is_mainnet(network) || have_db) return 1;
    if (err_buf && err_buf_len)
        snprintf(err_buf, err_buf_len,
            "Error: mainnet requires --db for persistent state.\n"
            "Without a database, revocation secrets are lost on crash\n"
            "and breach penalties cannot be constructed.\n");
    return 0;
}

int network_gate_watchtower_db(const char *network, int have_wt_db,
                               char *err_buf, size_t err_buf_len) {
    if (!network_is_mainnet(network) || have_wt_db) return 1;
    if (err_buf && err_buf_len)
        snprintf(err_buf, err_buf_len,
            "Error: mainnet requires --wt-db for the trustless watchtower.\n"
            "v0.2.0 removed the legacy --db-only watchtower mode; the LSP\n"
            "must populate wt.db so a standalone trustless WT can broadcast\n"
            "penalty TXs on breach without ever opening lsp.db.\n"
            "See docs/watchtower-trustless-schema.md for the model.\n");
    return 0;
}
