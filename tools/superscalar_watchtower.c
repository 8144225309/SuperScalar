#include "superscalar/version.h"
#include "superscalar/watchtower.h"
#include "superscalar/persist.h"
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
    int bump_budget_pct = 0;
    uint64_t max_bump_fee = 0;
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

    if (!db_path) {
        fprintf(stderr, "Error: --db PATH required\n");
        usage(argv[0]);
        return 1;
    }

    /* CL4.C: open DB read-write so the WT can read WAL-pending rows from a
       concurrently-running LSP (read-only + WAL silently misses uncheckpointed
       data) and append its own response/poison TX broadcasts to broadcast_log
       for test verification. */
    persist_t db;
    if (!persist_open(&db, db_path)) {
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
    if (bump_budget_pct > 0) wt.bump_budget_pct = bump_budget_pct;
    if (max_bump_fee > 0) wt.max_bump_fee_sat = max_bump_fee;

    /* Hydrate channels from the DB so breach detections can build penalty TXes.
       Without this, watchtower_check() sees the breach, looks up wt->channels[
       id], finds NULL, and falls through to "no channel N for penalty". */
    secp256k1_context *chan_ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    channel_t *loaded_channels[WATCHTOWER_MAX_CHANNELS] = {0};
    if (chan_ctx) {
        uint32_t ch_ids[WATCHTOWER_MAX_CHANNELS];
        size_t n_loaded = 0;
        if (persist_list_channel_ids(&db, ch_ids, WATCHTOWER_MAX_CHANNELS,
                                       &n_loaded) && n_loaded > 0) {
            for (size_t i = 0; i < n_loaded; i++) {
                channel_t *ch = calloc(1, sizeof(*ch));
                if (!ch) continue;
                if (!persist_load_channel_for_watchtower(&db, ch_ids[i],
                                                          chan_ctx, ch)) {
                    free(ch);
                    continue;
                }
                if (ch_ids[i] < WATCHTOWER_MAX_CHANNELS) {
                    /* watchtower_set_channel dropped in #208 A3.2 — penalty
                       bytes are now pre-built at revocation time inside
                       watchtower_watch_revoked_commitment.  Tracking
                       loaded_channels[] is still useful for the standalone
                       daemon's own bookkeeping (channel_cleanup at exit). */
                    loaded_channels[ch_ids[i]] = ch;
                } else {
                    channel_cleanup(ch);
                    free(ch);
                }
            }
            printf("  Loaded %zu channel(s) for penalty signing\n", n_loaded);
        }

    /* CL4: hydrate PS state entries from client DB.  For each chain entry
       except the LATEST (which represents the current state, not a stale),
       register a watchtower entry that triggers on the OLD chain[K]'s txid
       and broadcasts chain[K+1]'s signed_tx + chain[K]'s poison TX. */
    {
        #define WT_PS_MAX_KEYS 64
        #define WT_PS_MAX_CHAIN 32
        uint32_t f_ids[WT_PS_MAX_KEYS];
        uint32_t n_idxs[WT_PS_MAX_KEYS];
        size_t n_keys = 0;
        size_t n_registered = 0;
        if (persist_list_ps_leaf_chain_keys(&db, f_ids, n_idxs,
                                             WT_PS_MAX_KEYS, &n_keys) && n_keys > 0) {
            for (size_t k = 0; k < n_keys; k++) {
                tx_buf_t chain_txs[WT_PS_MAX_CHAIN];
                unsigned char txids[WT_PS_MAX_CHAIN][32];
                uint64_t amounts[WT_PS_MAX_CHAIN];
                tx_buf_t poison_txs[WT_PS_MAX_CHAIN];
                for (int j = 0; j < WT_PS_MAX_CHAIN; j++) {
                    tx_buf_init(&chain_txs[j], 0);
                    tx_buf_init(&poison_txs[j], 0);
                    amounts[j] = 0;
                }
                int chain_len = persist_load_ps_chain(&db, f_ids[k], n_idxs[k],
                                                       chain_txs, txids, amounts,
                                                       poison_txs, WT_PS_MAX_CHAIN);
                /* CL4.D / Task #40: register the initial-state defense entry.
                   chain[0]'s persisted signed_tx + poison_tx describe state 1
                   (post-1st-advance signed_tx) and the poison built BEFORE
                   the 1st advance (consumes initial state's L-stock vout).
                   Pair them with the initial txid from ps_initial_signed_states
                   so the WT can detect a pre-PS state broadcast and respond.
                   This closes the standalone-WT chain_len=1 gap. */
                if (chain_len >= 1 && chain_txs[0].len > 0) {
                    tx_buf_t init_tx = {0};
                    unsigned char init_txid_be[32] = {0};
                    if (persist_load_ps_initial_signed_state(&db,
                            f_ids[k], n_idxs[k], &init_tx, init_txid_be)
                        && init_tx.len > 0) {
                        if (watchtower_watch_factory_node(&wt, n_idxs[k],
                                                           init_txid_be,
                                                           chain_txs[0].data,
                                                           chain_txs[0].len,
                                                           poison_txs[0].data,
                                                           poison_txs[0].len)) {
                            n_registered++;
                        }
                    }
                    tx_buf_free(&init_tx);
                }
                /* Existing loop: chain[j].txid -> chain[j+1].signed_tx defense
                   for transitions between persisted advances (j >= 1 states). */
                for (int j = 0; j < chain_len - 1; j++) {
                    if (chain_txs[j+1].len == 0) continue;
                    if (watchtower_watch_factory_node(&wt, n_idxs[k],
                                                       txids[j],
                                                       chain_txs[j+1].data,
                                                       chain_txs[j+1].len,
                                                       poison_txs[j].data,
                                                       poison_txs[j].len)) {
                        n_registered++;
                    }
                }
                for (int j = 0; j < WT_PS_MAX_CHAIN; j++) {
                    tx_buf_free(&chain_txs[j]);
                    tx_buf_free(&poison_txs[j]);
                }
            }
            printf("  Loaded %zu PS leaf chain entries for watchtower\n", n_registered);
        }

        size_t n_sub_keys = 0;
        size_t n_sub_registered = 0;
        if (persist_list_subfactory_chain_keys(&db, f_ids, n_idxs,
                                                 WT_PS_MAX_KEYS, &n_sub_keys) && n_sub_keys > 0) {
            for (size_t k = 0; k < n_sub_keys; k++) {
                tx_buf_t chain_txs[WT_PS_MAX_CHAIN];
                unsigned char txids[WT_PS_MAX_CHAIN][32];
                uint64_t amounts[WT_PS_MAX_CHAIN];
                tx_buf_t poison_txs[WT_PS_MAX_CHAIN];
                for (int j = 0; j < WT_PS_MAX_CHAIN; j++) {
                    tx_buf_init(&chain_txs[j], 0);
                    tx_buf_init(&poison_txs[j], 0);
                    amounts[j] = 0;
                }
                uint64_t sales_stock_amounts[WT_PS_MAX_CHAIN];
                uint64_t channel_amounts[WT_PS_MAX_CHAIN][16];
                int n_channels_per_chain[WT_PS_MAX_CHAIN];
                for (int j = 0; j < WT_PS_MAX_CHAIN; j++) {
                    sales_stock_amounts[j] = 0;
                    n_channels_per_chain[j] = 0;
                    for (int m = 0; m < 16; m++) channel_amounts[j][m] = 0;
                }
                int chain_len = persist_load_subfactory_chain(&db, f_ids[k], n_idxs[k],
                                                                chain_txs, txids,
                                                                sales_stock_amounts,
                                                                channel_amounts,
                                                                n_channels_per_chain,
                                                                poison_txs, WT_PS_MAX_CHAIN);
                (void)amounts;  /* unused for subfactory variant */
                /* CL4.E: sub-factory analog of CL4.D / Task #40 — register the
                   initial-state defense entry using chain[0]'s signed_tx +
                   poison_tx paired with the pre-advance sub-factory txid from
                   ps_initial_signed_states (saved by the v23 fix in
                   lsp_subfactory_chain_advance). Closes the standalone-WT
                   chain_len=1 gap for sub-factory cheats. */
                if (chain_len >= 1 && chain_txs[0].len > 0) {
                    tx_buf_t init_tx = {0};
                    unsigned char init_txid_be[32] = {0};
                    if (persist_load_ps_initial_signed_state(&db,
                            f_ids[k], n_idxs[k], &init_tx, init_txid_be)
                        && init_tx.len > 0) {
                        if (watchtower_watch_factory_node(&wt, n_idxs[k],
                                                           init_txid_be,
                                                           chain_txs[0].data,
                                                           chain_txs[0].len,
                                                           poison_txs[0].data,
                                                           poison_txs[0].len)) {
                            n_sub_registered++;
                        }
                    }
                    tx_buf_free(&init_tx);
                }
                /* Existing loop: chain[j].txid -> chain[j+1].signed_tx for
                   transitions between persisted advances (j >= 1 states). */
                for (int j = 0; j < chain_len - 1; j++) {
                    if (chain_txs[j+1].len == 0) continue;
                    /* Use subfactory_node registration if available; falls back to
                       factory_node which is the same backing storage shape. */
                    if (watchtower_watch_factory_node(&wt, n_idxs[k],
                                                       txids[j],
                                                       chain_txs[j+1].data,
                                                       chain_txs[j+1].len,
                                                       poison_txs[j].data,
                                                       poison_txs[j].len)) {
                        n_sub_registered++;
                    }
                }
                for (int j = 0; j < WT_PS_MAX_CHAIN; j++) {
                    tx_buf_free(&chain_txs[j]);
                    tx_buf_free(&poison_txs[j]);
                }
            }
            printf("  Loaded %zu PS sub-factory chain entries for watchtower\n",
                   n_sub_registered);
        }
        #undef WT_PS_MAX_KEYS
        #undef WT_PS_MAX_CHAIN
    }
    } else {
        fprintf(stderr, "Warning: secp256k1 context creation failed — "
                        "penalty TXes cannot be built\n");
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
        } else if (last_height > 0 && height < last_height) {
            /* Reorg detected — re-validate all watchtower entries */
            fprintf(stderr, "[%ld] REORG: height %d → %d (depth %d)\n",
                    (long)time(NULL), last_height, height,
                    last_height - height);
            /* CL6: persist reorg event for test evidence */
            {
                char det[128];
                snprintf(det, sizeof(det), "height_%d->%d depth_%d",
                         last_height, height, last_height - height);
                persist_log_broadcast(&db, "", "reorg_detected", det, "ok");
            }
            watchtower_on_reorg(&wt, height, last_height);
            last_height = height;
            /* Run a watchtower check immediately after reorg */
            watchtower_check(&wt);
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
    for (size_t i = 0; i < WATCHTOWER_MAX_CHANNELS; i++) {
        if (loaded_channels[i]) {
            channel_cleanup(loaded_channels[i]);
            free(loaded_channels[i]);
        }
    }
    if (chan_ctx) secp256k1_context_destroy(chan_ctx);
    persist_close(&db);
    return 0;
}
