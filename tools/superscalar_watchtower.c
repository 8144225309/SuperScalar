#include "superscalar/version.h"
#include "superscalar/watchtower.h"
#include "superscalar/persist.h"
#include "superscalar/regtest.h"
#include "superscalar/fee.h"
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
        "Usage: %s --db PATH [OPTIONS]\n"
        "\n"
        "  Standalone watchtower: monitors blockchain for stale-state broadcasts\n"
        "  and broadcasts penalty transactions.\n"
        "\n"
        "Options:\n"
        "  --db PATH           SQLite database (read-only) shared with LSP\n"
        "  --network MODE      Network: regtest, signet, testnet, testnet4, mainnet\n"
        "  --poll-interval N   Seconds between block checks (default: 30)\n"
        "  --cli-path PATH     Path to bitcoin-cli (default: bitcoin-cli)\n"
        "  --rpcuser USER      Bitcoin RPC username\n"
        "  --rpcpassword PASS  Bitcoin RPC password\n"
        "  --datadir PATH      Bitcoin datadir\n"
        "  --rpcport PORT      Bitcoin RPC port\n"
        "  --version           Show version and exit\n"
        "  --help              Show this help\n",
        prog);
}

int main(int argc, char *argv[]) {
    const char *db_path = NULL;
    const char *network = "regtest";
    int poll_interval = 30;
    const char *cli_path = NULL;
    const char *rpcuser = NULL;
    const char *rpcpassword = NULL;
    const char *datadir = NULL;
    int rpcport = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--db") == 0 && i + 1 < argc)
            db_path = argv[++i];
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
        else if (strcmp(argv[i], "--version") == 0) {
            printf("superscalar_watchtower %s\n", SUPERSCALAR_VERSION);
            return 0;
        }
        else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    if (!db_path) {
        fprintf(stderr, "Error: --db PATH required\n");
        usage(argv[0]);
        return 1;
    }

    /* Open DB read-only */
    persist_t db;
    if (!persist_open_readonly(&db, db_path)) {
        fprintf(stderr, "Error: cannot open database '%s'\n", db_path);
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
        persist_close(&db);
        return 1;
    }

    /* Initialize fee estimator */
    fee_estimator_static_t fee;
    fee_estimator_static_init(&fee, 1000);

    /* Initialize watchtower */
    watchtower_t wt;
    if (!watchtower_init(&wt, 0, &rt, (fee_estimator_t *)&fee, &db)) {
        fprintf(stderr, "Error: watchtower_init failed\n");
        persist_close(&db);
        return 1;
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    printf("SuperScalar Watchtower\n");
    printf("  DB: %s (read-only)\n", db_path);
    printf("  Network: %s\n", network);
    printf("  Poll interval: %d seconds\n", poll_interval);
    printf("  Watching for breaches...\n");
    fflush(stdout);

    int last_height = -1;

    while (!g_shutdown) {
        int height = regtest_get_block_height(&rt);
        if (height > last_height) {
            int penalties = watchtower_check(&wt);
            if (penalties > 0) {
                printf("[%ld] Block %d: %d penalty tx(s) broadcast!\n",
                       (long)time(NULL), height, penalties);
            }
            last_height = height;
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
    persist_close(&db);
    return 0;
}
