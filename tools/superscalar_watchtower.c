#include "superscalar/version.h"
#include "superscalar/watchtower.h"
#include "superscalar/persist_wt.h"
#include "superscalar/regtest.h"
#include "superscalar/fee.h"
#include "superscalar/channel.h"
#include <secp256k1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_shutdown = 0;

static void sigint_handler(int sig) {
    (void)sig;
    g_shutdown = 1;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --wt-db PATH [OPTIONS]\n"
        "\n"
        "  Standalone trustless watchtower.  Monitors blockchain for stale-state\n"
        "  broadcasts using pre-signed response transactions provided by the LSP\n"
        "  via watchtower.db.  This binary CANNOT read revocation secrets — even\n"
        "  if compromised, no key material is reachable.  v0.2.0 ships trustless\n"
        "  mode as the ONLY mode (see docs/watchtower-trustless-schema.md).\n"
        "\n"
        "Options:\n"
        "  --wt-db PATH        Path to watchtower.db (REQUIRED).  Contains pre-signed\n"
        "                      response TXs and watch metadata.  No secrets.  Populated\n"
        "                      by the LSP at revocation / advance / force-close time.\n"
        "  --network MODE      Network: regtest, signet, testnet, testnet4, mainnet\n"
        "  --poll-interval N   Seconds between block checks (default: 30)\n"
        "  --cli-path PATH     Path to bitcoin-cli (default: bitcoin-cli)\n"
        "  --rpcuser USER      Bitcoin RPC username\n"
        "  --rpcpassword PASS  Bitcoin RPC password\n"
        "  --datadir PATH      Bitcoin datadir\n"
        "  --rpcport PORT      Bitcoin RPC port\n"
        "  --bump-budget-pct N CPFP fee budget as %% of penalty value (1-100, default 50)\n"
        "  --max-bump-fee SAT  Absolute fee ceiling per CPFP bump (default 50000)\n"
        "  --bump-wallet NAME  Funded wallet the CPFP fee-bumper draws UTXOs from (#52)\n"
        "  --version           Show version and exit\n"
        "  --help              Show this help\n"
        "\n"
        "Migration: v0.1.x used --db PATH (lsp.db) which exposed revocation secrets\n"
        "to the WT process.  v0.2.0 removes this flag entirely.  To migrate:\n"
        "  1. On the LSP, add --wt-db <path/to/wt.db>.  Restart LSP.\n"
        "  2. On the WT, replace --db with --wt-db <same path>.\n"
        "  3. lsp.db stays where it is; the LSP still uses it for everything else.\n",
        prog);
}

int main(int argc, char *argv[]) {
    int bump_budget_pct = 0;
    uint64_t max_bump_fee = 0;
    /* SF-WT-TRUSTLESS Phase 2c (#248) PR-E: --db removed.  v0.2.0 ships
       trustless mode as the only mode. */
    const char *wt_db_path = NULL;
    const char *network = "regtest";
    int poll_interval = 30;
    const char *cli_path = NULL;
    const char *rpcuser = NULL;
    const char *rpcpassword = NULL;
    const char *datadir = NULL;
    int rpcport = 0;
    const char *bump_wallet = NULL;  /* #52: wallet the CPFP fee-bumper draws UTXOs from */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--db") == 0) {
            fprintf(stderr,
                "Error: --db is no longer a valid flag for the standalone\n"
                "       watchtower.  v0.2.0 ships trustless mode as the only\n"
                "       mode.  Use --wt-db PATH instead.\n"
                "\n"
                "       Migration: have your LSP run with --wt-db <path/to/wt.db>,\n"
                "       then point this binary at the same file.  See\n"
                "       docs/watchtower-trustless-schema.md.\n");
            return 1;
        }
        else if (strcmp(argv[i], "--inspect-db") == 0) {
            fprintf(stderr,
                "Error: --inspect-db was removed alongside --db.  Use sqlite3\n"
                "       directly on the wt_db file for inspection; the schema is\n"
                "       documented at docs/watchtower-trustless-schema.md.\n");
            return 1;
        }
        else if (strcmp(argv[i], "--wt-db") == 0 && i + 1 < argc)
            wt_db_path = argv[++i];
        else if (strcmp(argv[i], "--network") == 0 && i + 1 < argc)
            network = argv[++i];
        else if (strcmp(argv[i], "--poll-interval") == 0 && i + 1 < argc)
            poll_interval = atoi(argv[++i]);
        else if (strcmp(argv[i], "--cli-path") == 0 && i + 1 < argc)
            cli_path = argv[++i];
        else if (strcmp(argv[i], "--rpcuser") == 0 && i + 1 < argc)
            rpcuser = argv[++i];
        else if (strcmp(argv[i], "--rpcpassword") == 0 && i + 1 < argc)
            rpcpassword = argv[++i];
        else if (strcmp(argv[i], "--datadir") == 0 && i + 1 < argc)
            datadir = argv[++i];
        else if (strcmp(argv[i], "--rpcport") == 0 && i + 1 < argc)
            rpcport = atoi(argv[++i]);
        else if (strcmp(argv[i], "--bump-wallet") == 0 && i + 1 < argc)
            bump_wallet = argv[++i];
        else if (strcmp(argv[i], "--max-bump-fee") == 0 && i + 1 < argc)
            max_bump_fee = (uint64_t)strtoull(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--bump-budget-pct") == 0 && i + 1 < argc) {
            bump_budget_pct = atoi(argv[++i]);
            if (bump_budget_pct < 1 || bump_budget_pct > 100) {
                fprintf(stderr, "Error: --bump-budget-pct must be 1-100\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "--version") == 0) {
            printf("superscalar_watchtower %s\n", SUPERSCALAR_VERSION);
            return 0;
        }
        else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    if (!wt_db_path) {
        fprintf(stderr, "Error: --wt-db PATH is required.\n");
        usage(argv[0]);
        return 1;
    }

    /* Initialize bitcoin RPC connection */
    regtest_t rt;
    int rt_ok;
    if (cli_path || rpcuser || rpcpassword || datadir || rpcport) {
        rt_ok = regtest_init_full(&rt, network, cli_path, rpcuser, rpcpassword,
                                  datadir, rpcport);
    } else {
        rt_ok = regtest_init_network(&rt, network);
    }
    if (!rt_ok) {
        fprintf(stderr, "Error: cannot connect to bitcoind\n");
        return 1;
    }

    /* #52: point the CPFP fee-bumper at a FUNDED wallet. Without this, regtest_exec
       runs listunspent on the node's default wallet (empty for a standalone WT) ->
       "no suitable wallet UTXO for bump" -> the penalty can't be fee-bumped and loses
       the race under fee pressure. This is the operator/client-funded bumper wallet
       (the design's "client-funded bumper" realized as the WT's own RPC wallet). The
       WT still holds NO signing keys; it only spends this wallet's UTXOs to CPFP the
       anyone-can-spend P2A anchor on a pre-signed penalty. */
    if (bump_wallet) {
        strncpy(rt.wallet, bump_wallet, sizeof(rt.wallet) - 1);
        rt.wallet[sizeof(rt.wallet) - 1] = '\0';
        printf("WT-TRUSTLESS: CPFP fee-bump wallet = %s\n", bump_wallet);
    }

    /* Initialize fee estimator */
    fee_estimator_static_t fee;
    fee_estimator_static_init(&fee, 1000);

    /* Initialize watchtower in TRUSTLESS mode: wt->db = NULL.  The
       per-callsite NULL guards in src/watchtower.c (every wt->db deref
       is `if (wt->db && wt->db->db) ...`) make this safe; no lsp.db
       access ever happens in this binary. */
    watchtower_t wt;
    if (!watchtower_init(&wt, 0, &rt, (fee_estimator_t *)&fee, NULL)) {
        fprintf(stderr, "Error: watchtower_init failed\n");
        return 1;
    }
    if (bump_budget_pct > 0) wt.bump_budget_pct = bump_budget_pct;
    if (max_bump_fee > 0) wt.max_bump_fee_sat = max_bump_fee;

    /* Open wt_db and hydrate watches.  All 4 watch kinds (factory,
       sub-factory, channel commitment, force-close HTLC) are populated
       by the LSP at revocation / advance / close time and read here.
       No secrets are involved at any step. */
    persist_wt_t wt_pdb;
    if (!persist_wt_open(&wt_pdb, wt_db_path)) {
        fprintf(stderr, "Error: cannot open watchtower database '%s'\n",
                wt_db_path);
        return 1;
    }
    printf("WT-TRUSTLESS: opened wt_db at %s\n", wt_db_path);

    int n_wt = watchtower_hydrate_from_wt_db(&wt, &wt_pdb);
    if (n_wt < 0) {
        fprintf(stderr,
                "WT-TRUSTLESS: ERROR — hydration failed (returned %d)\n", n_wt);
        persist_wt_close(&wt_pdb);
        return 1;
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    printf("SuperScalar Watchtower (TRUSTLESS — only mode)\n");
    printf("  WT-DB: %s\n", wt_db_path);
    printf("  Network: %s\n", network);
    printf("  Poll interval: %d seconds\n", poll_interval);
    printf("  Watching for breaches...\n");
    fflush(stdout);

    int last_height = -1;
    char last_hash[65] = {0};  /* Issue #2: same-height reorg detection */

    while (!g_shutdown) {
        int height = regtest_get_block_height(&rt);
        char cur_hash[65] = {0};
        regtest_get_best_block_hash(&rt, cur_hash);

        /* R6 (mainnet pre-flight): mirror the LSP daemon-loop detection
           (PR #201).  Standalone WT had SAME_HEIGHT + HEIGHT_REGRESSION but
           missed FORWARD_REORG (competing longer chain wins; tip advances
           but block at last_height is no longer canonical).  Detect by
           re-querying the block hash at last_height. */
        int reorg_kind = 0;  /* 0=none, 1=height-decrease, 2=same-height, 3=forward */
        if (last_height > 0 && height < last_height) {
            reorg_kind = 1;
        } else if (last_height > 0 && height == last_height &&
                   last_hash[0] != 0 && cur_hash[0] != 0 &&
                   strcmp(cur_hash, last_hash) != 0) {
            reorg_kind = 2;
        } else if (last_height > 0 && height > last_height && last_hash[0]) {
            char prev_hash_now[65] = {0};
            if (regtest_get_block_hash(&rt, last_height,
                                        prev_hash_now, sizeof(prev_hash_now)) &&
                prev_hash_now[0] &&
                strcmp(prev_hash_now, last_hash) != 0) {
                reorg_kind = 3;
            }
        }

        if (reorg_kind > 0) {
            /* Reorg detected — re-validate all watchtower entries. */
            const char *kind_str =
                (reorg_kind == 3) ? "FORWARD_REORG" :
                (reorg_kind == 2) ? "SAME_HEIGHT"   :
                                     "HEIGHT_REGRESSION";
            fprintf(stderr, "[%ld] REORG (%s): height %d -> %d hash %.16s -> %.16s\n",
                    (long)time(NULL), kind_str, last_height, height,
                    last_hash, cur_hash);
            /* Phase 2c PR-E: legacy persist_log_broadcast call removed.
               wt_db has no broadcast_log table; reorg observability lives
               in dashboard / external metrics. */
            watchtower_on_reorg(&wt, height, last_height);
            last_height = height;
            if (cur_hash[0]) { memcpy(last_hash, cur_hash, 65); }
            /* Run a watchtower check immediately after reorg */
            watchtower_check(&wt);
        } else if (height > last_height) {
            int penalties = watchtower_check(&wt);
            if (penalties > 0) {
                printf("[%ld] Block %d: %d penalty tx(s) broadcast!\n",
                       (long)time(NULL), height, penalties);
            }
            last_height = height;
            if (cur_hash[0]) { memcpy(last_hash, cur_hash, 65); }
        }

        /* Heartbeat */
        time_t now = time(NULL);
        printf("[%ld] heartbeat height=%d entries=%zu\n",
               (long)now, height, wt.n_entries);
        fflush(stdout);

        for (int s = 0; s < poll_interval && !g_shutdown; s++)
            sleep(1);
    }

    printf("\nShutdown requested. Cleaning up...\n");
    watchtower_cleanup(&wt);
    persist_wt_close(&wt_pdb);
    return 0;
}
