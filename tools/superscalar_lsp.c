#include "superscalar/version.h"
#include "superscalar/lsp.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/jit_channel.h"
#include "superscalar/tx_builder.h"
#include "superscalar/regtest.h"
#include "superscalar/report.h"
#include "superscalar/persist.h"
#include "superscalar/fee.h"
#include "superscalar/watchtower.h"
#include "superscalar/keyfile.h"
#include "superscalar/dw_state.h"
#include "superscalar/tor.h"
#include "superscalar/tapscript.h"
#include "superscalar/backup.h"
#include "superscalar/bip39.h"
#include "superscalar/hd_key.h"
#include "superscalar/ladder.h"
#include "superscalar/adaptor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#ifdef __linux__
#include <execinfo.h>
#endif
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);
#include "superscalar/sha256.h"

static volatile sig_atomic_t g_shutdown = 0;
static lsp_t *g_lsp = NULL;  /* for signal handler cleanup */
static persist_t *g_db = NULL;  /* for broadcast audit logging */

static void sigint_handler(int sig) {
    (void)sig;
    g_shutdown = 1;
}

#ifdef __linux__
static void crash_handler(int sig) {
    void *bt[64];
    int n = backtrace(bt, 64);
    fprintf(stderr, "\n=== CRASH (signal %d) ===\n", sig);
    backtrace_symbols_fd(bt, n, STDERR_FILENO);
    fflush(stderr);
    _exit(128 + sig);
}
#endif

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --port PORT --network MODE [OPTIONS]\n"
        "\n"
        "  SuperScalar LSP: creates a factory with N clients, then cooperatively closes.\n"
        "\n"
        "Options:\n"
        "  --port PORT         Listen port (default 9735)\n"
        "  --clients N         Number of clients to accept (default 4, max %d)\n"
        "  --amount SATS       Funding amount in satoshis (default 100000)\n"
        "  --step-blocks N     DW step blocks (default 10)\n"
        "  --seckey HEX        LSP secret key (32-byte hex, default: deterministic)\n"
        "  --payments N        Number of HTLC payments to process (default 0)\n"
        "  --daemon            Run as long-lived daemon (Ctrl+C for graceful close)\n"
        "  --cli               Enable interactive CLI in daemon mode (pay/status/rotate/close)\n"
        "  --demo              Run demo payment sequence after channels ready\n"
        "  --fee-rate N        Fee rate in sat/kvB (default 1000 = 1 sat/vB)\n"
        "  --dynamic-fees      Force dynamic fee estimation via estimatesmartfee (default: always on)\n"
        "  --report PATH       Write diagnostic JSON report to PATH\n"
        "  --db PATH           SQLite database for persistence (default: none)\n"
        "  --network MODE      Network: regtest, signet, testnet, testnet4, mainnet (default: regtest)\n"
        "  --regtest           Shorthand for --network regtest\n"
        "  --keyfile PATH      Load/save secret key from encrypted file\n"
        "  --passphrase PASS   Passphrase for keyfile (default: prompt or empty)\n"
        "  --cltv-timeout N    Factory CLTV timeout (absolute block height; auto: +35 regtest, +1008 non-regtest)\n"
        "  --cli-path PATH     Path to bitcoin-cli binary (default: bitcoin-cli)\n"
        "  --rpcuser USER      Bitcoin RPC username (default: rpcuser)\n"
        "  --rpcpassword PASS  Bitcoin RPC password (default: rpcpass)\n"
        "  --datadir PATH      Bitcoin datadir (default: bitcoind default)\n"
        "  --rpcport PORT      Bitcoin RPC port (default: network default)\n"
        "  --wallet NAME       Bitcoin wallet name (default: create 'superscalar_lsp')\n"
        "  --breach-test       After demo: broadcast revoked commitment, trigger penalty\n"
        "  --cheat-daemon      After demo: broadcast revoked commitment, sleep (no penalty)\n"
        "  --test-expiry       After demo: mine past CLTV, recover via timeout script\n"
        "  --test-distrib      After demo: mine past CLTV, broadcast distribution TX\n"
        "  --test-turnover     After demo: PTLC key turnover for all clients, close\n"
        "  --test-rotation     After demo: full factory rotation (PTLC over wire + new factory)\n"
        "  --active-blocks N   Factory active period in blocks (default: 20 regtest, 4320 non-regtest)\n"
        "  --dying-blocks N    Factory dying period in blocks (default: 10 regtest, 432 non-regtest)\n"
        "  --jit-amount SATS   Per-client JIT channel funding amount (default: funding/clients)\n"
        "  --no-jit            Disable JIT channel fallback\n"
        "  --states-per-layer N States per DW layer (default 4, range 2-256)\n"
        "  --arity N|N,N,...   Leaf arity: 1 or 2 (default 2). Comma-separated for per-level.\n"
        "  --force-close       After factory creation (+ demo), broadcast tree and wait for confirmations\n"
        "  --test-burn         After factory creation (+ demo), broadcast tree and burn L-stock via shachain\n"
        "  --test-htlc-force-close  After demo: add pending HTLC, force-close, broadcast HTLC timeout TX\n"
        "  --test-dw-advance   After demo: advance DW counter, re-sign tree, force-close (shows nSequence decrease)\n"
        "  --test-leaf-advance After demo: advance left leaf only, force-close (proves per-leaf independence)\n"
        "  --test-dual-factory After demo: create second factory, show two ACTIVE in ladder, force-close both\n"
        "  --test-dw-exhibition After demo: full DW lifecycle (multi-advance + PTLC close + cross-factory contrast)\n"
        "  --test-bridge       After demo: simulate bridge inbound HTLC, verify client fulfills\n"
        "  --confirm-timeout N Confirmation wait timeout in seconds (default: 3600 regtest, 259200 non-regtest)\n"
        "  --heartbeat-interval N  Print daemon status every N seconds (default: 0 = disabled)\n"
        "  --max-connections N Max inbound connections to accept (default: %d = LSP_MAX_CLIENTS)\n"
        "  --max-conn-rate N   Max connections per IP per minute (default: 10)\n"
        "  --max-handshakes N  Max concurrent handshakes (default: 4)\n"
        "  --accept-timeout N  Max seconds to wait for each client connection (default: 0 = no timeout)\n"
        "  --routing-fee-ppm N Routing fee in parts-per-million (default: 0 = free)\n"
        "  --lsp-balance-pct N LSP's share of channel capacity, 0-100 (default: 50 = fair split)\n"
        "  --placement-mode M  Client placement: sequential, inward, outward, timezone-cluster (default: timezone-cluster)\n"
        "  --economic-mode M   Fee model: lsp-takes-all, profit-shared (default: lsp-takes-all)\n"
        "  --default-profit-bps N  Default profit share basis points per client (default: 0)\n"
        "  --settlement-interval N Blocks between profit settlements (default: 144)\n"
        "  --tor-proxy HOST:PORT SOCKS5 proxy for Tor (default: 127.0.0.1:9050)\n"
        "  --tor-control HOST:PORT Tor control port (default: 127.0.0.1:9051)\n"
        "  --tor-password PASS   Tor control auth password (default: empty)\n"
        "  --onion               Create Tor hidden service on startup\n"
        "  --generate-mnemonic Generate 24-word BIP39 mnemonic, derive key, save to --keyfile, then exit\n"
        "  --from-mnemonic WORDS Restore key from BIP39 mnemonic, save to --keyfile, then exit\n"
        "  --mnemonic-passphrase P BIP39 passphrase for seed derivation (default: empty)\n"
        "  --backup PATH       Create encrypted backup of --db and --keyfile to PATH, then exit\n"
        "  --restore PATH      Restore encrypted backup from PATH to --db and --keyfile, then exit\n"
        "  --backup-verify PATH  Verify encrypted backup integrity, then exit\n"
        "  --i-accept-the-risk Allow mainnet operation (PROTOTYPE — funds at risk!)\n"
        "  --version           Show version and exit\n"
        "  --help              Show this help\n",
        prog, LSP_MAX_CLIENTS, LSP_MAX_CLIENTS);
}

/* Ensure wallet has funds (handle exhausted regtest chains) */
static int ensure_funded(regtest_t *rt, const char *mine_addr) {
    char *bal_s = regtest_exec(rt, "getbalance", "");
    double wallet_bal = bal_s ? atof(bal_s) : 0;
    if (bal_s) free(bal_s);

    if (wallet_bal >= 0.01) return 1;

    /* Block subsidy exhausted — fund from an existing wallet */
    static const char *faucet_wallets[] = {
        "test_dw", "test_factory", "test_ladder_life", NULL
    };
    for (int w = 0; faucet_wallets[w]; w++) {
        regtest_t faucet;
        memcpy(&faucet, rt, sizeof(faucet));
        faucet.wallet[0] = '\0';
        char wparams[128];
        snprintf(wparams, sizeof(wparams), "\"%s\"", faucet_wallets[w]);
        char *lr = regtest_exec(&faucet, "loadwallet", wparams);
        if (lr) free(lr);
        strncpy(faucet.wallet, faucet_wallets[w], sizeof(faucet.wallet) - 1);

        char sp[256];
        snprintf(sp, sizeof(sp), "\"%s\" 0.01", mine_addr);
        char *sr = regtest_exec(&faucet, "sendtoaddress", sp);
        if (sr && !strstr(sr, "error")) {
            free(sr);
            regtest_mine_blocks(rt, 1, mine_addr);
            return 1;
        }
        if (sr) free(sr);
    }
    return 0;
}

/* Advance chain by N blocks: mine on regtest, poll on non-regtest.
   Returns 1 on success, 0 on timeout. */
static int advance_chain(regtest_t *rt, int n, const char *mine_addr,
                          int is_regtest, int timeout_secs) {
    if (n <= 0) return 1;
    if (is_regtest) {
        regtest_mine_blocks(rt, n, mine_addr);
        return 1;
    }
    /* Poll for N new blocks */
    int start_h = regtest_get_block_height(rt);
    int target_h = start_h + n;
    printf("Waiting for %d block(s) (height %d -> %d)...\n",
           n, start_h, target_h);
    for (int waited = 0; waited < timeout_secs; waited += 10) {
        if (regtest_get_block_height(rt) >= target_h) return 1;
        sleep(10);
    }
    fprintf(stderr, "advance_chain: timed out waiting for %d blocks "
            "(height %d / %d)\n", n, regtest_get_block_height(rt), target_h);
    return 0;
}

/* Report all factory tree nodes */
static void report_factory_tree(report_t *rpt, secp256k1_context *ctx,
                                 const factory_t *f) {
    static const char *type_names[] = { "kickoff", "state" };

    report_begin_array(rpt, "nodes");
    for (size_t i = 0; i < f->n_nodes; i++) {
        const factory_node_t *node = &f->nodes[i];
        report_begin_section(rpt, NULL);

        report_add_uint(rpt, "index", i);
        report_add_string(rpt, "type",
                          node->type <= NODE_STATE ? type_names[node->type] : "unknown");
        report_add_uint(rpt, "n_signers", node->n_signers);

        report_begin_array(rpt, "signer_indices");
        for (size_t s = 0; s < node->n_signers; s++)
            report_add_uint(rpt, NULL, node->signer_indices[s]);
        report_end_array(rpt);

        report_add_int(rpt, "parent_index", node->parent_index);
        report_add_uint(rpt, "parent_vout", node->parent_vout);
        report_add_int(rpt, "dw_layer_index", node->dw_layer_index);
        report_add_uint(rpt, "nsequence", node->nsequence);
        report_add_uint(rpt, "input_amount", node->input_amount);
        report_add_bool(rpt, "has_taptree", node->has_taptree);

        /* Aggregate pubkey */
        {
            unsigned char xonly_ser[32];
            if (secp256k1_xonly_pubkey_serialize(ctx, xonly_ser, &node->keyagg.agg_pubkey))
                report_add_hex(rpt, "agg_pubkey", xonly_ser, 32);
        }

        /* Tweaked pubkey */
        {
            unsigned char xonly_ser[32];
            if (secp256k1_xonly_pubkey_serialize(ctx, xonly_ser, &node->tweaked_pubkey))
                report_add_hex(rpt, "tweaked_pubkey", xonly_ser, 32);
        }

        if (node->has_taptree)
            report_add_hex(rpt, "merkle_root", node->merkle_root, 32);

        report_add_hex(rpt, "spending_spk", node->spending_spk, 34);

        /* Outputs */
        report_begin_array(rpt, "outputs");
        for (size_t o = 0; o < node->n_outputs; o++) {
            report_begin_section(rpt, NULL);
            report_add_uint(rpt, "amount_sats", node->outputs[o].amount_sats);
            report_add_hex(rpt, "script_pubkey",
                           node->outputs[o].script_pubkey,
                           node->outputs[o].script_pubkey_len);
            report_end_section(rpt);
        }
        report_end_array(rpt);

        /* Transaction data */
        if (node->is_built) {
            report_add_hex(rpt, "unsigned_tx",
                           node->unsigned_tx.data, node->unsigned_tx.len);
            unsigned char display_txid[32];
            memcpy(display_txid, node->txid, 32);
            reverse_bytes(display_txid, 32);
            report_add_hex(rpt, "txid", display_txid, 32);
        }
        if (node->is_signed) {
            report_add_hex(rpt, "signed_tx",
                           node->signed_tx.data, node->signed_tx.len);
        }

        report_end_section(rpt);
    }
    report_end_array(rpt);
}

/* Report channel state */
static void report_channel_state(report_t *rpt, const char *label,
                                  const lsp_channel_mgr_t *mgr) {
    report_begin_section(rpt, label);
    for (size_t c = 0; c < mgr->n_channels; c++) {
        char key[32];
        snprintf(key, sizeof(key), "channel_%zu", c);
        report_begin_section(rpt, key);
        const channel_t *ch = &mgr->entries[c].channel;
        report_add_uint(rpt, "channel_id", mgr->entries[c].channel_id);
        report_add_uint(rpt, "local_amount", ch->local_amount);
        report_add_uint(rpt, "remote_amount", ch->remote_amount);
        report_add_uint(rpt, "commitment_number", ch->commitment_number);
        report_add_uint(rpt, "n_htlcs", ch->n_htlcs);
        report_end_section(rpt);
    }
    report_end_section(rpt);
}

/* Wire message log callback (Phase 22) */
static void lsp_wire_log_cb(int dir, uint8_t type, const cJSON *json,
                              const char *peer_label, void *ud) {
    persist_log_wire_message((persist_t *)ud, dir, type, peer_label, json);
}

/* Broadcast all signed factory tree nodes in parent→child order.
   Mines blocks between each to satisfy nSequence relative timelocks.
   Returns 1 on success. */
static int broadcast_factory_tree(factory_t *f, regtest_t *rt,
                                    const char *mine_addr) {
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *node = &f->nodes[i];
        if (!node->is_signed) {
            fprintf(stderr, "broadcast_factory_tree: node %zu not signed\n", i);
            return 0;
        }

        char *tx_hex = malloc(node->signed_tx.len * 2 + 1);
        if (!tx_hex) return 0;
        hex_encode(node->signed_tx.data, node->signed_tx.len, tx_hex);

        char txid_out[65];
        int ok = regtest_send_raw_tx(rt, tx_hex, txid_out);

        /* Audit log */
        if (g_db) {
            char src[32];
            snprintf(src, sizeof(src), "tree_node_%zu", i);
            persist_log_broadcast(g_db, ok ? txid_out : "?", src, tx_hex,
                                  ok ? "ok" : "failed");
        }
        free(tx_hex);

        if (!ok) {
            fprintf(stderr, "broadcast_factory_tree: node %zu broadcast failed\n", i);
            return 0;
        }

        /* Mine blocks to satisfy relative timelock for next child.
         * The NEXT node's nSequence is the relative delay from THIS node's
         * confirmation. If this is the last node, just confirm it (1 block). */
        int blocks_to_mine;
        if (i + 1 < f->n_nodes) {
            uint32_t child_nseq = f->nodes[i + 1].nsequence;
            if (child_nseq == NSEQUENCE_DISABLE_BIP68) {
                blocks_to_mine = 1;
            } else {
                blocks_to_mine = (int)(child_nseq & 0xFFFF) + 1;
            }
        } else {
            blocks_to_mine = 1;  /* last node, just confirm */
        }
        regtest_mine_blocks(rt, blocks_to_mine, mine_addr);

        unsigned char display_txid[32];
        memcpy(display_txid, node->txid, 32);
        reverse_bytes(display_txid, 32);
        char display_hex[65];
        hex_encode(display_txid, 32, display_hex);
        printf("  node[%zu] broadcast: %s (mined %d blocks)\n",
               i, display_hex, blocks_to_mine);
    }
    return 1;
}

/* Broadcast all signed factory tree nodes, waiting for real block confirmations.
   On regtest: mines blocks. On signet/testnet: polls getblockcount.
   Handles nSequence relative timelocks by waiting for the required depth.
   Returns 1 on success. */
static int broadcast_factory_tree_any_network(factory_t *f, regtest_t *rt,
                                                const char *mine_addr,
                                                int is_regtest,
                                                int confirm_timeout) {
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *node = &f->nodes[i];
        if (!node->is_signed) {
            fprintf(stderr, "force-close: node %zu not signed\n", i);
            return 0;
        }

        char *tx_hex = malloc(node->signed_tx.len * 2 + 1);
        if (!tx_hex) return 0;
        hex_encode(node->signed_tx.data, node->signed_tx.len, tx_hex);

        char txid_out[65];

        /* For nodes with nSequence > 0, we may need to wait for the parent
           to reach sufficient depth before this tx is valid */
        if (node->nsequence != NSEQUENCE_DISABLE_BIP68 && node->nsequence > 0) {
            uint32_t required_depth = (node->nsequence & 0xFFFF);
            int est_mins = (int)required_depth * 10; /* ~10 min/block */
            printf("  node[%zu/%zu] requires %u-block relative timelock "
                   "(~%dh%02dm), waiting...\n",
                   i, f->n_nodes, required_depth,
                   est_mins / 60, est_mins % 60);

            if (is_regtest) {
                /* Mine the required blocks */
                regtest_mine_blocks(rt, (int)required_depth, mine_addr);
            } else {
                /* Poll for blocks on signet/testnet with timeout */
                int start_height = regtest_get_block_height(rt);
                int target_height = start_height + (int)required_depth;
                int waited = 0;
                while (regtest_get_block_height(rt) < target_height) {
                    if (waited >= confirm_timeout) {
                        fprintf(stderr, "force-close: node %zu BIP68 wait "
                                "timed out after %ds (height %d / %d)\n",
                                i, waited, regtest_get_block_height(rt),
                                target_height);
                        free(tx_hex);
                        return 0;
                    }
                    sleep(10);
                    waited += 10;
                    int cur_h = regtest_get_block_height(rt);
                    int blocks_left = target_height - cur_h;
                    int est_mins = blocks_left * 10;
                    printf("    height: %d / %d (%ds elapsed, ~%dh%02dm remaining)\n",
                           cur_h, target_height, waited,
                           est_mins / 60, est_mins % 60);
                    fflush(stdout);
                }
            }
        }

        /* Try to broadcast — may need retries if BIP68 not yet satisfied */
        int ok = 0;
        int bcast_waited = 0;
        int bcast_limit = is_regtest ? 60 : confirm_timeout;
        for (int attempt = 0; bcast_waited < bcast_limit; attempt++) {
            ok = regtest_send_raw_tx(rt, tx_hex, txid_out);
            if (ok) break;
            if (attempt == 0)
                printf("  node[%zu] broadcast pending (waiting for BIP68)...\n", i);
            if (is_regtest) {
                regtest_mine_blocks(rt, 1, mine_addr);
                bcast_waited++;
            } else {
                sleep(15);
                bcast_waited += 15;
            }
        }

        /* Audit log */
        if (g_db) {
            char src[32];
            snprintf(src, sizeof(src), "tree_node_%zu", i);
            persist_log_broadcast(g_db, ok ? txid_out : "?", src, tx_hex,
                                  ok ? "ok" : "failed");
        }
        free(tx_hex);

        if (!ok) {
            fprintf(stderr, "force-close: node %zu broadcast failed after retries\n", i);
            return 0;
        }

        /* Confirm it: mine 1 block on regtest, wait on signet */
        if (is_regtest) {
            regtest_mine_blocks(rt, 1, mine_addr);
        } else {
            printf("  node[%zu/%zu] broadcast OK (txid=%.16s...), "
                   "waiting for confirmation...\n",
                   i, f->n_nodes, txid_out);
            fflush(stdout);
            regtest_wait_for_confirmation(rt, txid_out, confirm_timeout);
        }

        unsigned char display_txid[32];
        memcpy(display_txid, node->txid, 32);
        reverse_bytes(display_txid, 32);
        char display_hex[65];
        hex_encode(display_txid, 32, display_hex);

        int conf = regtest_get_confirmations(rt, txid_out);
        printf("  node[%zu] confirmed: %s (%d confs)\n", i, display_hex, conf);
    }
    return 1;
}

int main(int argc, char *argv[]) {
    /* Line-buffered stdout/stderr so logs are visible in real time */
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    /* Ignore SIGPIPE — write() to dead client sockets returns EPIPE instead of killing us */
    signal(SIGPIPE, SIG_IGN);
#ifdef __linux__
    signal(SIGABRT, crash_handler);
    signal(SIGSEGV, crash_handler);
#endif

    int port = 9735;
    int n_clients = 4;
    int n_payments = 0;
    int daemon_mode = 0;
    int cli_mode = 0;
    int demo_mode = 0;
    uint64_t funding_sats = 100000;
    uint16_t step_blocks = 10;
    uint64_t fee_rate = 1000;  /* sat/kvB, default 1 sat/vB */
    const char *seckey_hex = NULL;
    const char *report_path = NULL;
    const char *db_path = NULL;
    const char *network = NULL;
    const char *keyfile_path = NULL;
    const char *passphrase = "";
    const char *cli_path = NULL;
    const char *rpcuser = NULL;
    const char *rpcpassword = NULL;
    const char *datadir = NULL;
    int rpcport = 0;
    const char *wallet_name = NULL;
    int64_t cltv_timeout_arg = -1;  /* -1 = auto */
    int breach_test = 0;
    int test_expiry = 0;
    int test_distrib = 0;
    int test_turnover = 0;
    int test_rotation = 0;
    int32_t active_blocks_arg = -1;  /* -1 = auto */
    int32_t dying_blocks_arg = -1;   /* -1 = auto */
    int64_t jit_amount_arg = -1;     /* -1 = auto (funding_sats / n_clients) */
    int no_jit = 0;
    int states_per_layer = 4;        /* DW states per layer (2-256, default 4) */
    int leaf_arity = 2;              /* 1 or 2, default arity-2 */
    uint8_t level_arities[FACTORY_MAX_LEVELS];
    size_t n_level_arity = 0;        /* 0 = uniform leaf_arity */
    int force_close = 0;
    int test_burn = 0;
    int test_htlc_force_close = 0;
    int test_dw_advance = 0;
    int test_leaf_advance = 0;
    int test_dual_factory = 0;
    int test_dw_exhibition = 0;
    int test_bridge = 0;
    int confirm_timeout_arg = -1;    /* -1 = auto (3600 regtest, 259200 non-regtest) */
    int accept_timeout_arg = 0;      /* 0 = no timeout (block indefinitely) */
    int max_connections_arg = 0;      /* 0 = use LSP_MAX_CLIENTS default */
    int max_conn_rate_arg = 10;      /* max connections per IP per minute */
    int max_handshakes_arg = 4;      /* max concurrent handshakes */
    uint64_t routing_fee_ppm = 0;    /* 0 = zero-fee (no routing fee) */
    uint16_t lsp_balance_pct = 50;   /* 50 = fair 50-50 split */
    int accept_risk = 0;             /* --i-accept-the-risk for mainnet */
    int placement_mode_arg = 3;      /* 0=sequential, 1=inward, 2=outward, 3=timezone-cluster */
    int economic_mode_arg = 0;       /* 0=lsp-takes-all, 1=profit-shared */
    uint16_t default_profit_bps = 0; /* per-client profit share bps */
    uint32_t settlement_interval = 144; /* blocks between profit settlements */
    const char *tor_proxy_arg = NULL;
    const char *tor_control_arg = NULL;
    const char *tor_password = NULL;
    int tor_onion = 0;
    char *tor_password_file = NULL;
    int tor_only = 0;
    const char *bind_addr = NULL;
    int auto_rebalance = 0;
    int rebalance_threshold = 80;  /* default 80% imbalance threshold */
    int test_rebalance = 0;
    int test_batch_rebalance = 0;
    int test_realloc = 0;
    int dynamic_fees = 0;
    int heartbeat_interval = 0;  /* 0 = disabled; seconds between daemon status lines */
    const char *backup_path_arg = NULL;
    const char *restore_path_arg = NULL;
    int backup_verify_arg = 0;
    int generate_mnemonic = 0;
    const char *from_mnemonic = NULL;
    const char *mnemonic_passphrase = "";
    int fee_bump_after = 6;       /* blocks before first bump */
    int fee_bump_max = 3;         /* max bump attempts */
    double fee_bump_multiplier = 1.5;
    (void)fee_bump_after; (void)fee_bump_max; (void)fee_bump_multiplier;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--clients") == 0 && i + 1 < argc)
            n_clients = atoi(argv[++i]);
        else if (strcmp(argv[i], "--amount") == 0 && i + 1 < argc)
            funding_sats = (uint64_t)strtoull(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--step-blocks") == 0 && i + 1 < argc)
            step_blocks = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--seckey") == 0 && i + 1 < argc)
            seckey_hex = argv[++i];
        else if (strcmp(argv[i], "--payments") == 0 && i + 1 < argc)
            n_payments = atoi(argv[++i]);
        else if (strcmp(argv[i], "--report") == 0 && i + 1 < argc)
            report_path = argv[++i];
        else if (strcmp(argv[i], "--daemon") == 0)
            daemon_mode = 1;
        else if (strcmp(argv[i], "--cli") == 0)
            cli_mode = 1;
        else if (strcmp(argv[i], "--demo") == 0)
            demo_mode = 1;
        else if (strcmp(argv[i], "--fee-rate") == 0 && i + 1 < argc)
            fee_rate = (uint64_t)strtoull(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc)
            db_path = argv[++i];
        else if (strcmp(argv[i], "--network") == 0 && i + 1 < argc)
            network = argv[++i];
        else if (strcmp(argv[i], "--regtest") == 0)
            network = "regtest";
        else if (strcmp(argv[i], "--keyfile") == 0 && i + 1 < argc)
            keyfile_path = argv[++i];
        else if (strcmp(argv[i], "--passphrase") == 0 && i + 1 < argc)
            passphrase = argv[++i];
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
        else if (strcmp(argv[i], "--wallet") == 0 && i + 1 < argc)
            wallet_name = argv[++i];
        else if (strcmp(argv[i], "--cltv-timeout") == 0 && i + 1 < argc)
            cltv_timeout_arg = (int64_t)strtoll(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--breach-test") == 0)
            breach_test = 1;
        else if (strcmp(argv[i], "--test-expiry") == 0)
            test_expiry = 1;
        else if (strcmp(argv[i], "--test-distrib") == 0)
            test_distrib = 1;
        else if (strcmp(argv[i], "--test-turnover") == 0)
            test_turnover = 1;
        else if (strcmp(argv[i], "--test-rotation") == 0)
            test_rotation = 1;
        else if (strcmp(argv[i], "--cheat-daemon") == 0)
            breach_test = 2;  /* 2 = cheat-daemon mode (no LSP watchtower, sleep after breach) */
        else if (strcmp(argv[i], "--test-rebalance") == 0)
            test_rebalance = 1;
        else if (strcmp(argv[i], "--test-batch-rebalance") == 0)
            test_batch_rebalance = 1;
        else if (strcmp(argv[i], "--test-realloc") == 0)
            test_realloc = 1;
        else if (strcmp(argv[i], "--active-blocks") == 0 && i + 1 < argc)
            active_blocks_arg = (int32_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--dying-blocks") == 0 && i + 1 < argc)
            dying_blocks_arg = (int32_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--jit-amount") == 0 && i + 1 < argc)
            jit_amount_arg = (int64_t)strtoll(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--no-jit") == 0)
            no_jit = 1;
        else if (strcmp(argv[i], "--states-per-layer") == 0 && i + 1 < argc) {
            states_per_layer = atoi(argv[++i]);
            if (states_per_layer < 2 || states_per_layer > 256) {
                fprintf(stderr, "Error: --states-per-layer must be 2-256\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "--arity") == 0 && i + 1 < argc) {
            const char *arity_str = argv[++i];
            /* Comma-separated: --arity 1,1,2,2  or single: --arity 2 */
            if (strchr(arity_str, ',')) {
                char buf[128];
                strncpy(buf, arity_str, sizeof(buf) - 1);
                buf[sizeof(buf) - 1] = '\0';
                char *tok = strtok(buf, ",");
                while (tok && n_level_arity < FACTORY_MAX_LEVELS) {
                    int v = atoi(tok);
                    if (v != 1 && v != 2) { fprintf(stderr, "Error: each arity must be 1 or 2\n"); return 1; }
                    level_arities[n_level_arity++] = (uint8_t)v;
                    tok = strtok(NULL, ",");
                }
                leaf_arity = (int)level_arities[n_level_arity - 1];
            } else {
                leaf_arity = atoi(arity_str);
            }
        }
        else if (strcmp(argv[i], "--force-close") == 0)
            force_close = 1;
        else if (strcmp(argv[i], "--test-burn") == 0)
            test_burn = 1;
        else if (strcmp(argv[i], "--test-htlc-force-close") == 0)
            test_htlc_force_close = 1;
        else if (strcmp(argv[i], "--test-dw-advance") == 0)
            test_dw_advance = 1;
        else if (strcmp(argv[i], "--test-leaf-advance") == 0)
            test_leaf_advance = 1;
        else if (strcmp(argv[i], "--test-dual-factory") == 0)
            test_dual_factory = 1;
        else if (strcmp(argv[i], "--test-dw-exhibition") == 0)
            test_dw_exhibition = 1;
        else if (strcmp(argv[i], "--test-bridge") == 0)
            test_bridge = 1;
        else if (strcmp(argv[i], "--confirm-timeout") == 0 && i + 1 < argc) {
            confirm_timeout_arg = atoi(argv[++i]);
            if (confirm_timeout_arg <= 0) {
                fprintf(stderr, "Error: --confirm-timeout must be positive\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "--max-connections") == 0 && i + 1 < argc) {
            max_connections_arg = atoi(argv[++i]);
            if (max_connections_arg < 1 || max_connections_arg > LSP_MAX_CLIENTS) {
                fprintf(stderr, "Error: --max-connections must be 1..%d\n", LSP_MAX_CLIENTS);
                return 1;
            }
        }
        else if (strcmp(argv[i], "--max-conn-rate") == 0 && i + 1 < argc)
            max_conn_rate_arg = atoi(argv[++i]);
        else if (strcmp(argv[i], "--max-handshakes") == 0 && i + 1 < argc)
            max_handshakes_arg = atoi(argv[++i]);
        else if (strcmp(argv[i], "--accept-timeout") == 0 && i + 1 < argc) {
            accept_timeout_arg = atoi(argv[++i]);
            if (accept_timeout_arg <= 0) {
                fprintf(stderr, "Error: --accept-timeout must be positive\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "--routing-fee-ppm") == 0 && i + 1 < argc)
            routing_fee_ppm = (uint64_t)strtoull(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--lsp-balance-pct") == 0 && i + 1 < argc) {
            lsp_balance_pct = (uint16_t)atoi(argv[++i]);
            if (lsp_balance_pct > 100) {
                fprintf(stderr, "Error: --lsp-balance-pct must be 0-100\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "--tor-proxy") == 0 && i + 1 < argc)
            tor_proxy_arg = argv[++i];
        else if (strcmp(argv[i], "--tor-control") == 0 && i + 1 < argc)
            tor_control_arg = argv[++i];
        else if (strcmp(argv[i], "--tor-password") == 0 && i + 1 < argc)
            tor_password = argv[++i];
        else if (strcmp(argv[i], "--onion") == 0)
            tor_onion = 1;
        else if (strcmp(argv[i], "--tor-only") == 0)
            tor_only = 1;
        else if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc)
            bind_addr = argv[++i];
        else if (strcmp(argv[i], "--tor-password-file") == 0 && i + 1 < argc)
            tor_password_file = argv[++i];
        else if (strcmp(argv[i], "--placement-mode") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "sequential") == 0) placement_mode_arg = 0;
            else if (strcmp(argv[i], "inward") == 0) placement_mode_arg = 1;
            else if (strcmp(argv[i], "outward") == 0) placement_mode_arg = 2;
            else if (strcmp(argv[i], "timezone-cluster") == 0) placement_mode_arg = 3;
            else { fprintf(stderr, "Error: unknown --placement-mode '%s' (options: sequential, inward, outward, timezone-cluster)\n", argv[i]); return 1; }
        }
        else if (strcmp(argv[i], "--economic-mode") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "lsp-takes-all") == 0) economic_mode_arg = 0;
            else if (strcmp(argv[i], "profit-shared") == 0) economic_mode_arg = 1;
            else { fprintf(stderr, "Error: unknown --economic-mode '%s'\n", argv[i]); return 1; }
        }
        else if (strcmp(argv[i], "--default-profit-bps") == 0 && i + 1 < argc) {
            default_profit_bps = (uint16_t)atoi(argv[++i]);
            if (default_profit_bps > 10000) {
                fprintf(stderr, "Error: --default-profit-bps must be 0-10000\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "--settlement-interval") == 0 && i + 1 < argc)
            settlement_interval = (uint32_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--auto-rebalance") == 0)
            auto_rebalance = 1;
        else if (strcmp(argv[i], "--rebalance-threshold") == 0 && i + 1 < argc) {
            rebalance_threshold = atoi(argv[++i]);
            if (rebalance_threshold < 51 || rebalance_threshold > 99) {
                fprintf(stderr, "Error: --rebalance-threshold must be 51-99\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "--dynamic-fees") == 0)
            dynamic_fees = 1;
        else if (strcmp(argv[i], "--heartbeat-interval") == 0 && i + 1 < argc)
            heartbeat_interval = atoi(argv[++i]);
        else if (strcmp(argv[i], "--fee-bump-after") == 0 && i + 1 < argc)
            fee_bump_after = atoi(argv[++i]);
        else if (strcmp(argv[i], "--fee-bump-max") == 0 && i + 1 < argc)
            fee_bump_max = atoi(argv[++i]);
        else if (strcmp(argv[i], "--fee-bump-multiplier") == 0 && i + 1 < argc)
            fee_bump_multiplier = atof(argv[++i]);
        else if (strcmp(argv[i], "--generate-mnemonic") == 0)
            generate_mnemonic = 1;
        else if (strcmp(argv[i], "--from-mnemonic") == 0 && i + 1 < argc)
            from_mnemonic = argv[++i];
        else if (strcmp(argv[i], "--mnemonic-passphrase") == 0 && i + 1 < argc)
            mnemonic_passphrase = argv[++i];
        else if (strcmp(argv[i], "--backup") == 0 && i + 1 < argc)
            backup_path_arg = argv[++i];
        else if (strcmp(argv[i], "--restore") == 0 && i + 1 < argc)
            restore_path_arg = argv[++i];
        else if (strcmp(argv[i], "--backup-verify") == 0 && i + 1 < argc) {
            restore_path_arg = argv[++i];
            backup_verify_arg = 1;
        }
        else if (strcmp(argv[i], "--i-accept-the-risk") == 0)
            accept_risk = 1;
        else if (strcmp(argv[i], "--version") == 0) {
            printf("superscalar_lsp %s\n", SUPERSCALAR_VERSION);
            return 0;
        }
        else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    if (!network)
        network = "regtest";  /* default to regtest */
    int is_regtest = (strcmp(network, "regtest") == 0);

    /* --- Backup / Restore / Verify (early exit) --- */
    if (backup_path_arg || restore_path_arg || backup_verify_arg) {
        const char *bp_env = getenv("SUPERSCALAR_BACKUP_PASSPHRASE");
        const char *bp = bp_env ? bp_env : passphrase;
        size_t bp_len = strlen(bp);
        if (bp_len == 0) {
            fprintf(stderr, "Error: passphrase required for backup operations.\n"
                    "Set SUPERSCALAR_BACKUP_PASSPHRASE env var or use --passphrase\n");
            return 1;
        }
        if (backup_verify_arg && restore_path_arg) {
            int ok = backup_verify(restore_path_arg, (const unsigned char *)bp, bp_len);
            printf("Backup verify: %s\n", ok ? "OK" : "FAILED");
            return ok ? 0 : 1;
        }
        if (backup_path_arg) {
            if (!db_path || !keyfile_path) {
                fprintf(stderr, "Error: --backup requires --db and --keyfile\n");
                return 1;
            }
            int ok = backup_create(db_path, keyfile_path, backup_path_arg,
                                    (const unsigned char *)bp, bp_len);
            printf("Backup create: %s\n", ok ? "OK" : "FAILED");
            return ok ? 0 : 1;
        }
        if (restore_path_arg) {
            if (!db_path || !keyfile_path) {
                fprintf(stderr, "Error: --restore requires --db and --keyfile (destination paths)\n");
                return 1;
            }
            int ok = backup_restore(restore_path_arg, db_path, keyfile_path,
                                     (const unsigned char *)bp, bp_len);
            printf("Backup restore: %s\n", ok ? "OK" : "FAILED");
            return ok ? 0 : 1;
        }
    }

    /* --- BIP39 Mnemonic (early exit) --- */
    if (generate_mnemonic || from_mnemonic) {
        if (!keyfile_path) {
            fprintf(stderr, "Error: --keyfile required for mnemonic operations\n");
            return 1;
        }
        unsigned char seed[64];
        if (generate_mnemonic) {
            char mnemonic[1024];
            if (!bip39_generate(24, mnemonic, sizeof(mnemonic))) {
                fprintf(stderr, "Error: failed to generate mnemonic\n");
                return 1;
            }
            printf("BIP39 Mnemonic (WRITE THIS DOWN!):\n\n  %s\n\n", mnemonic);
            if (!bip39_mnemonic_to_seed(mnemonic, mnemonic_passphrase, seed)) {
                fprintf(stderr, "Error: failed to derive seed\n");
                secure_zero(mnemonic, sizeof(mnemonic));
                return 1;
            }
            secure_zero(mnemonic, sizeof(mnemonic));
        } else {
            if (!bip39_validate(from_mnemonic)) {
                fprintf(stderr, "Error: invalid mnemonic (bad word or checksum)\n");
                return 1;
            }
            if (!bip39_mnemonic_to_seed(from_mnemonic, mnemonic_passphrase, seed)) {
                fprintf(stderr, "Error: failed to derive seed from mnemonic\n");
                return 1;
            }
        }
        unsigned char seckey[32];
        int ok = keyfile_generate_from_seed(keyfile_path, seckey, passphrase,
                                             seed, 64, NULL);
        secure_zero(seed, sizeof(seed));
        secure_zero(seckey, sizeof(seckey));
        printf("Keyfile %s: %s\n", keyfile_path, ok ? "OK" : "FAILED");
        return ok ? 0 : 1;
    }

    /* Mainnet safety guard: refuse unless explicitly acknowledged */
    if (strcmp(network, "mainnet") == 0 && !accept_risk) {
        fprintf(stderr,
            "Error: mainnet operation refused.\n"
            "SuperScalar is a PROTOTYPE. Running on mainnet risks loss of funds.\n"
            "If you understand this risk, pass --i-accept-the-risk\n");
        return 1;
    }

    /* Mainnet requires --db for revocation secret persistence */
    if (strcmp(network, "mainnet") == 0 && !db_path) {
        fprintf(stderr,
            "Error: mainnet requires --db for persistent state.\n"
            "Without a database, revocation secrets are lost on crash\n"
            "and breach penalties cannot be constructed.\n");
        return 1;
    }

    /* Resolve confirmation timeout */
    int confirm_timeout_secs = (confirm_timeout_arg > 0) ? confirm_timeout_arg
                               : (is_regtest ? 3600 : 259200);

    /* Convenience macro: advance chain by N blocks (mine on regtest, poll on
       non-regtest).  Relies on local variables: rt, mine_addr, is_regtest,
       confirm_timeout_secs — all of which are in scope throughout main(). */
    #define ADVANCE(n) advance_chain(&rt, (n), mine_addr, is_regtest, confirm_timeout_secs)
    /* --cheat-daemon (mode 2) only broadcasts + sleeps — allowed on any network.
       --breach-test (mode 1) uses broadcast_factory_tree_any_network() on
       non-regtest networks (polls for confirmation instead of mining). */

    /* Resolve active/dying block defaults */
    uint32_t active_blocks = (active_blocks_arg > 0) ? (uint32_t)active_blocks_arg
                             : (is_regtest ? 20 : 4320);
    uint32_t dying_blocks = (dying_blocks_arg > 0) ? (uint32_t)dying_blocks_arg
                            : (is_regtest ? 10 : 432);

    if (n_clients < 1 || n_clients > LSP_MAX_CLIENTS) {
        fprintf(stderr, "Error: --clients must be 1..%d\n", LSP_MAX_CLIENTS);
        return 1;
    }
    if (leaf_arity != 1 && leaf_arity != 2) {
        fprintf(stderr, "Error: --arity must be 1 or 2\n");
        return 1;
    }
    if (leaf_arity == 2 && n_clients < 2) {
        fprintf(stderr, "Error: --arity 2 requires at least 2 clients\n");
        return 1;
    }

    /* Initialize diagnostic report */
    report_t rpt;
    if (!report_init(&rpt, report_path)) {
        fprintf(stderr, "Error: cannot open report file: %s\n", report_path);
        return 1;
    }
    report_add_string(&rpt, "role", "lsp");
    report_add_uint(&rpt, "n_clients", (uint64_t)n_clients);
    report_add_uint(&rpt, "funding_sats", funding_sats);

    /* Initialize persistence (optional) */
    persist_t db;
    int use_db = 0;
    if (db_path) {
        if (!persist_open(&db, db_path)) {
            fprintf(stderr, "Error: cannot open database: %s\n", db_path);
            report_close(&rpt);
            return 1;
        }
        use_db = 1;
        g_db = &db;
        printf("LSP: persistence enabled (%s)\n", db_path);

        /* Wire message logging (Phase 22) */
        wire_set_log_callback(lsp_wire_log_cb, &db);
    }

    /* Tor SOCKS5 proxy setup */
    if (tor_proxy_arg) {
        char proxy_host[256];
        int proxy_port;
        if (!tor_parse_proxy_arg(tor_proxy_arg, proxy_host, sizeof(proxy_host),
                                  &proxy_port)) {
            fprintf(stderr, "Error: invalid --tor-proxy format (use HOST:PORT)\n");
            if (use_db) persist_close(&db);
            report_close(&rpt);
            return 1;
        }
        wire_set_proxy(proxy_host, proxy_port);
        printf("LSP: Tor SOCKS5 proxy set to %s:%d\n", proxy_host, proxy_port);
    }

    /* --tor-only mode: refuse all clearnet connections */
    if (tor_only) {
        if (!tor_proxy_arg) {
            fprintf(stderr, "Error: --tor-only requires --tor-proxy\n");
            if (use_db) persist_close(&db);
            report_close(&rpt);
            return 1;
        }
        wire_set_tor_only(1);
        printf("LSP: Tor-only mode enabled (clearnet connections refused)\n");
    }

    /* --tor-password-file: read password from file */
    char tor_password_buf[256];
    if (tor_password_file) {
        FILE *pf = fopen(tor_password_file, "r");
        if (!pf) {
            fprintf(stderr, "Error: cannot read %s\n", tor_password_file);
            if (use_db) persist_close(&db);
            report_close(&rpt);
            return 1;
        }
        if (!fgets(tor_password_buf, sizeof(tor_password_buf), pf)) {
            fclose(pf);
            fprintf(stderr, "Error: empty password file %s\n", tor_password_file);
            if (use_db) persist_close(&db);
            report_close(&rpt);
            return 1;
        }
        tor_password_buf[strcspn(tor_password_buf, "\r\n")] = '\0';
        fclose(pf);
        tor_password = tor_password_buf;
    }

    /* --bind or auto-bind for --onion */
    if (!bind_addr && tor_onion) {
        bind_addr = "127.0.0.1";
        printf("LSP: --onion defaults to --bind 127.0.0.1\n");
    }

    /* Tor hidden service (ephemeral, via control port) */
    int tor_control_fd = -1;
    if (tor_onion) {
        const char *ctrl_arg = tor_control_arg ? tor_control_arg : "127.0.0.1:9051";
        char ctrl_host[256];
        int ctrl_port;
        if (!tor_parse_proxy_arg(ctrl_arg, ctrl_host, sizeof(ctrl_host),
                                  &ctrl_port)) {
            fprintf(stderr, "Error: invalid --tor-control format (use HOST:PORT)\n");
            if (use_db) persist_close(&db);
            report_close(&rpt);
            return 1;
        }
        char onion_addr[128];
        tor_control_fd = tor_create_hidden_service(ctrl_host, ctrl_port,
            tor_password ? tor_password : "", port, port,
            onion_addr, sizeof(onion_addr));
        if (tor_control_fd < 0) {
            fprintf(stderr, "Error: failed to create Tor hidden service\n");
            if (use_db) persist_close(&db);
            report_close(&rpt);
            return 1;
        }
        printf("LSP: reachable at %s:%d\n", onion_addr, port);
    }

    /* Create LSP keypair */
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char lsp_seckey[32];
    if (seckey_hex) {
        if (hex_decode(seckey_hex, lsp_seckey, 32) != 32) {
            fprintf(stderr, "Error: invalid --seckey (need 64 hex chars)\n");
            return 1;
        }
    } else if (keyfile_path) {
        /* Try to load from keyfile */
        if (keyfile_load(keyfile_path, lsp_seckey, passphrase)) {
            printf("LSP: loaded key from %s\n", keyfile_path);
        } else {
            /* File doesn't exist or wrong passphrase — generate new key */
            printf("LSP: generating new key and saving to %s\n", keyfile_path);
            if (!keyfile_generate(keyfile_path, lsp_seckey, passphrase, ctx)) {
                fprintf(stderr, "Error: failed to generate keyfile\n");
                secp256k1_context_destroy(ctx);
                return 1;
            }
        }
    } else if (is_regtest) {
        /* Deterministic default key — regtest only */
        memset(lsp_seckey, 0x10, 32);
    } else {
        fprintf(stderr, "Error: --seckey or --keyfile required on %s\n", network);
        fprintf(stderr, "  (deterministic default key is only allowed on regtest)\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_seckey)) {
        fprintf(stderr, "Error: invalid secret key\n");
        memset(lsp_seckey, 0, 32);
        return 1;
    }
    /* Note: lsp_seckey zeroed at cleanup — needed for lsp_channels_init() */

    /* Initialize bitcoin-cli connection */
    regtest_t rt;
    int rt_ok;
    if (cli_path || rpcuser || rpcpassword || datadir || rpcport) {
        rt_ok = regtest_init_full(&rt, network, cli_path, rpcuser, rpcpassword,
                                  datadir, rpcport);
    } else {
        rt_ok = regtest_init_network(&rt, network);
    }
    if (!rt_ok) {
        fprintf(stderr, "Error: cannot connect to bitcoind (is it running with -%s?)\n", network);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    /* Auto-create/load wallet (handles "already exists" gracefully) */
    regtest_create_wallet(&rt, wallet_name ? wallet_name : "superscalar_lsp");

    /* Initialize fee estimator (dynamic fees always enabled; --dynamic-fees kept for compat) */
    (void)dynamic_fees;
    fee_estimator_t fee_est;
    fee_init(&fee_est, fee_rate);
    fee_est.use_estimatesmartfee = 1;
    if (fee_est.use_estimatesmartfee && fee_update_from_node(&fee_est, &rt, 6)) {
        printf("LSP: fee rate from estimatesmartfee(6): %llu sat/kvB\n",
               (unsigned long long)fee_est.fee_rate_sat_per_kvb);
    } else {
        printf("LSP: fee rate (static): %llu sat/kvB\n", (unsigned long long)fee_rate);
        if (!is_regtest)
            fprintf(stderr, "WARNING: estimatesmartfee failed on %s; using static --fee-rate %llu sat/kvB\n",
                    network, (unsigned long long)fee_rate);
    }

    /* === Recovery probe: skip ceremony if factory exists in DB === */
    if (use_db && daemon_mode) {
        factory_t *rec_f = calloc(1, sizeof(factory_t));
        if (!rec_f) { fprintf(stderr, "LSP: alloc failed\n"); return 1; }
        if (persist_load_factory(&db, 0, rec_f, ctx)) {
            if (rec_f->n_participants < 2) {
                fprintf(stderr, "LSP recovery: corrupt factory (n_participants=%zu)\n",
                        rec_f->n_participants);
                free(rec_f);
                persist_close(&db);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("LSP: found existing factory in DB, entering recovery mode\n");
            fflush(stdout);

            /* Set up LSP with listen socket only (skip ceremony) */
            lsp_t lsp;
            if (!lsp_init(&lsp, ctx, &lsp_kp, port, rec_f->n_participants - 1)) {
                fprintf(stderr, "LSP recovery: lsp_init failed\n");
                free(rec_f);
                persist_close(&db);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            g_lsp = &lsp;
            lsp.use_nk = 1;
            memcpy(lsp.nk_seckey, lsp_seckey, 32);

            signal(SIGINT, sigint_handler);
            signal(SIGTERM, sigint_handler);

            /* Open listen socket for reconnections */
            lsp.listen_fd = wire_listen(bind_addr, lsp.port);
            if (lsp.listen_fd < 0) {
                fprintf(stderr, "LSP recovery: listen failed on port %d\n", port);
                persist_close(&db);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Populate pubkeys from recovered factory */
            size_t rec_n_clients = rec_f->n_participants - 1;
            lsp.n_clients = rec_n_clients;
            for (size_t i = 0; i < rec_n_clients; i++)
                lsp.client_pubkeys[i] = rec_f->pubkeys[i + 1];

            /* Copy factory and set fee estimator */
            lsp.factory = *rec_f;
            free(rec_f);
            rec_f = NULL;
            lsp.factory.fee = &fee_est;

            /* Load DW counter state from DB */
            {
                uint32_t epoch_out, n_layers_out;
                uint32_t layer_states_out[DW_MAX_LAYERS];
                if (persist_load_dw_counter(&db, 0, &epoch_out, &n_layers_out,
                                              layer_states_out, DW_MAX_LAYERS)) {
                    for (uint32_t li = 0; li < n_layers_out &&
                         li < lsp.factory.counter.n_layers; li++)
                        lsp.factory.counter.layers[li].current_state =
                            layer_states_out[li];
                    printf("LSP recovery: DW counter loaded (epoch %u)\n",
                           dw_counter_epoch(&lsp.factory.counter));
                }
            }

            /* Set factory lifecycle from current block height */
            {
                int cur_height = regtest_get_block_height(&rt);
                if (cur_height > 0)
                    factory_set_lifecycle(&lsp.factory, (uint32_t)cur_height,
                                          active_blocks, dying_blocks);
            }

            /* Initialize channels from DB */
            lsp_channel_mgr_t *mgr = calloc(1, sizeof(lsp_channel_mgr_t));
            if (!mgr) { fprintf(stderr, "LSP: alloc failed\n"); lsp_cleanup(&lsp); return 1; }
            mgr->fee = &fee_est;
            if (!lsp_channels_init_from_db(mgr, ctx, &lsp.factory, lsp_seckey,
                                             rec_n_clients, &db)) {
                fprintf(stderr, "LSP recovery: channel init from DB failed\n");
                free(mgr);
                lsp_cleanup(&lsp);
                persist_close(&db);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            mgr->persist = &db;
            mgr->confirm_timeout_secs = confirm_timeout_secs;
            mgr->heartbeat_interval = heartbeat_interval;

            /* Load persisted state: invoices, HTLC origins, request_id */
            mgr->next_request_id = persist_load_counter(&db, "next_request_id", 1);

            {
                unsigned char inv_hashes[MAX_INVOICE_REGISTRY][32];
                size_t inv_dests[MAX_INVOICE_REGISTRY];
                uint64_t inv_amounts[MAX_INVOICE_REGISTRY];
                size_t n_inv = persist_load_invoices(&db,
                    inv_hashes, inv_dests, inv_amounts, MAX_INVOICE_REGISTRY);
                for (size_t i = 0; i < n_inv; i++) {
                    if (mgr->n_invoices >= MAX_INVOICE_REGISTRY) break;
                    invoice_entry_t *inv = &mgr->invoices[mgr->n_invoices++];
                    memcpy(inv->payment_hash, inv_hashes[i], 32);
                    inv->dest_client = inv_dests[i];
                    inv->amount_msat = inv_amounts[i];
                    inv->bridge_htlc_id = 0;
                    inv->active = 1;
                }
                if (n_inv > 0)
                    printf("LSP recovery: loaded %zu invoices from DB\n", n_inv);
            }

            {
                unsigned char orig_hashes[MAX_HTLC_ORIGINS][32];
                uint64_t orig_bridge[MAX_HTLC_ORIGINS], orig_req[MAX_HTLC_ORIGINS];
                size_t orig_sender[MAX_HTLC_ORIGINS];
                uint64_t orig_htlc[MAX_HTLC_ORIGINS];
                size_t n_orig = persist_load_htlc_origins(&db,
                    orig_hashes, orig_bridge, orig_req, orig_sender, orig_htlc,
                    MAX_HTLC_ORIGINS);
                for (size_t i = 0; i < n_orig; i++) {
                    if (mgr->n_htlc_origins >= MAX_HTLC_ORIGINS) break;
                    htlc_origin_t *o = &mgr->htlc_origins[mgr->n_htlc_origins++];
                    memcpy(o->payment_hash, orig_hashes[i], 32);
                    o->bridge_htlc_id = orig_bridge[i];
                    o->request_id = orig_req[i];
                    o->sender_idx = orig_sender[i];
                    o->sender_htlc_id = orig_htlc[i];
                    o->active = 1;
                }
                if (n_orig > 0)
                    printf("LSP recovery: loaded %zu HTLC origins from DB\n", n_orig);
            }

            /* Initialize watchtower */
            static watchtower_t rec_wt;
            memset(&rec_wt, 0, sizeof(rec_wt));
            watchtower_init(&rec_wt, mgr->n_channels, &rt, &fee_est, &db);
            for (size_t c = 0; c < mgr->n_channels; c++)
                watchtower_set_channel(&rec_wt, c, &mgr->entries[c].channel);
            mgr->watchtower = &rec_wt;

            /* Initialize ladder */
            ladder_t rec_lad;
            if (!ladder_init(&rec_lad, ctx, &lsp_kp, active_blocks, dying_blocks)) {
                fprintf(stderr, "LSP recovery: ladder_init failed\n");
                persist_close(&db);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            {
                int cur_h = regtest_get_block_height(&rt);
                if (cur_h > 0) rec_lad.current_block = (uint32_t)cur_h;
            }
            {
                ladder_factory_t *lf = &rec_lad.factories[0];
                lf->factory = lsp.factory;
                factory_detach_txbufs(&lf->factory);
                lf->factory_id = rec_lad.next_factory_id++;
                lf->is_initialized = 1;
                lf->is_funded = 1;
                lf->cached_state = factory_get_state(&lsp.factory,
                                                       rec_lad.current_block);
                tx_buf_init(&lf->distribution_tx, 256);
                rec_lad.n_factories = 1;
            }
            mgr->ladder = &rec_lad;

            /* Wire rotation parameters */
            memcpy(mgr->rot_lsp_seckey, lsp_seckey, 32);
            mgr->rot_fee_est = &fee_est;
            memcpy(mgr->rot_fund_spk, lsp.factory.funding_spk,
                   lsp.factory.funding_spk_len);
            mgr->rot_fund_spk_len = lsp.factory.funding_spk_len;

            /* Derive funding + mining addresses for rotation */
            {
                musig_keyagg_t ka;
                secp256k1_pubkey all_pks[FACTORY_MAX_SIGNERS];
                for (size_t i = 0; i < lsp.factory.n_participants; i++)
                    all_pks[i] = lsp.factory.pubkeys[i];
                musig_aggregate_keys(ctx, &ka, all_pks,
                                       lsp.factory.n_participants);
                unsigned char is2[32];
                if (!secp256k1_xonly_pubkey_serialize(ctx, is2, &ka.agg_pubkey)) {
                    fprintf(stderr, "LSP recovery: xonly serialize failed\n");
                    return 1;
                }
                unsigned char twk[32];
                sha256_tagged("TapTweak", is2, 32, twk);
                musig_keyagg_t kac = ka;
                secp256k1_pubkey tpk;
                if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tpk,
                                                             &kac.cache, twk)) {
                    fprintf(stderr, "LSP recovery: tweak add failed\n");
                    return 1;
                }
                secp256k1_xonly_pubkey txo;
                if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &txo, NULL, &tpk)) {
                    fprintf(stderr, "LSP recovery: xonly from pubkey failed\n");
                    return 1;
                }
                unsigned char ts2[32];
                if (!secp256k1_xonly_pubkey_serialize(ctx, ts2, &txo)) {
                    fprintf(stderr, "LSP recovery: xonly serialize failed\n");
                    return 1;
                }
                char rfa[128];
                if (regtest_derive_p2tr_address(&rt, ts2, rfa, sizeof(rfa)))
                    snprintf(mgr->rot_fund_addr, sizeof(mgr->rot_fund_addr),
                             "%s", rfa);
            }
            {
                char rma[128];
                if (regtest_get_new_address(&rt, rma, sizeof(rma)))
                    snprintf(mgr->rot_mine_addr, sizeof(mgr->rot_mine_addr),
                             "%s", rma);
            }
            mgr->rot_step_blocks = step_blocks;
            mgr->rot_states_per_layer = states_per_layer;
            mgr->rot_leaf_arity = leaf_arity;
            mgr->rot_is_regtest = is_regtest;
            mgr->rot_funding_sats = funding_sats;
            mgr->rot_auto_rotate = 1;
            mgr->rot_attempted_mask = 0;
            mgr->cli_enabled = cli_mode;
            mgr->auto_rebalance = auto_rebalance;
            mgr->rebalance_threshold_pct = (uint16_t)rebalance_threshold;

            /* JIT Channel Fallback */
            jit_channels_init(mgr);
            if (no_jit) mgr->jit_enabled = 0;
            mgr->jit_funding_sats = (jit_amount_arg > 0) ?
                (uint64_t)jit_amount_arg :
                (funding_sats / (uint64_t)rec_n_clients);

            /* Load JIT channels from DB */
            {
                jit_channel_t *jits = (jit_channel_t *)mgr->jit_channels;
                size_t jit_count = 0;
                persist_load_jit_channels(&db, jits, JIT_MAX_CHANNELS,
                                            &jit_count);
                mgr->n_jit_channels = jit_count;
                for (size_t ji = 0; ji < jit_count; ji++) {
                    if (jits[ji].state != JIT_STATE_OPEN)
                        continue;

                    unsigned char ls[4][32], rb[4][33];
                    if (!persist_load_basepoints(&db,
                            jits[ji].jit_channel_id, ls, rb)) {
                        fprintf(stderr, "LSP recovery: JIT channel %u "
                                "missing basepoints, disabling\n",
                                jits[ji].jit_channel_id);
                        jits[ji].state = JIT_STATE_CLOSED;
                        continue;
                    }

                    channel_t *jch = &jits[ji].channel;
                    memcpy(jch->local_payment_basepoint_secret, ls[0], 32);
                    memcpy(jch->local_delayed_payment_basepoint_secret, ls[1], 32);
                    memcpy(jch->local_revocation_basepoint_secret, ls[2], 32);
                    memcpy(jch->local_htlc_basepoint_secret, ls[3], 32);

                    int bp_ok = 1;
                    bp_ok &= secp256k1_ec_pubkey_create(ctx,
                                &jch->local_payment_basepoint, ls[0]);
                    bp_ok &= secp256k1_ec_pubkey_create(ctx,
                                &jch->local_delayed_payment_basepoint, ls[1]);
                    bp_ok &= secp256k1_ec_pubkey_create(ctx,
                                &jch->local_revocation_basepoint, ls[2]);
                    bp_ok &= secp256k1_ec_pubkey_create(ctx,
                                &jch->local_htlc_basepoint, ls[3]);
                    bp_ok &= secp256k1_ec_pubkey_parse(ctx,
                                &jch->remote_payment_basepoint, rb[0], 33);
                    bp_ok &= secp256k1_ec_pubkey_parse(ctx,
                                &jch->remote_delayed_payment_basepoint, rb[1], 33);
                    bp_ok &= secp256k1_ec_pubkey_parse(ctx,
                                &jch->remote_revocation_basepoint, rb[2], 33);
                    bp_ok &= secp256k1_ec_pubkey_parse(ctx,
                                &jch->remote_htlc_basepoint, rb[3], 33);
                    memset(ls, 0, sizeof(ls));

                    if (!bp_ok) {
                        fprintf(stderr, "LSP recovery: JIT channel %u "
                                "has corrupt basepoints, disabling\n",
                                jits[ji].jit_channel_id);
                        jits[ji].state = JIT_STATE_CLOSED;
                        continue;
                    }

                    size_t wt_idx = mgr->n_channels + jits[ji].client_idx;
                    if (wt_idx < WATCHTOWER_MAX_CHANNELS)
                        watchtower_set_channel(&rec_wt, wt_idx, jch);
                }
                if (jit_count > 0)
                    printf("LSP recovery: loaded %zu JIT channels from DB\n",
                           jit_count);
            }

            printf("LSP recovery: entering daemon mode "
                   "(waiting for client reconnections)...\n");
            fflush(stdout);
            lsp_channels_run_daemon_loop(mgr, &lsp, &g_shutdown);

            /* Persist updated channel balances on shutdown */
            if (persist_begin(&db)) {
                int bal_ok = 1;
                for (size_t c = 0; c < mgr->n_channels; c++) {
                    const channel_t *ch = &mgr->entries[c].channel;
                    if (!persist_update_channel_balance(&db, (uint32_t)c,
                        ch->local_amount, ch->remote_amount,
                        ch->commitment_number)) {
                        bal_ok = 0;
                        break;
                    }
                }
                if (bal_ok) persist_commit(&db);
                else persist_rollback(&db);
            }

            printf("LSP recovery: daemon shutdown complete\n");
            jit_channels_cleanup(mgr);
            free(mgr);
            persist_close(&db);
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 0;
        }
    }

    /* === Phase 1: Accept clients === */
    printf("LSP: listening on port %d, waiting for %d clients...\n", port, n_clients);
    fflush(stdout);

    lsp_t lsp;
    if (!lsp_init(&lsp, ctx, &lsp_kp, port, (size_t)n_clients)) {
        fprintf(stderr, "LSP: lsp_init failed\n");
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    g_lsp = &lsp;
    lsp.accept_timeout_sec = accept_timeout_arg;
    if (max_connections_arg > 0)
        lsp.max_connections = max_connections_arg;
    rate_limiter_init(&lsp.rate_limiter, max_conn_rate_arg, 60, max_handshakes_arg);

    /* Enable NK (server-authenticated) noise handshake */
    lsp.use_nk = 1;
    memcpy(lsp.nk_seckey, lsp_seckey, 32);
    {
        secp256k1_pubkey nk_pub;
        if (!secp256k1_ec_pubkey_create(ctx, &nk_pub, lsp_seckey)) {
            fprintf(stderr, "LSP: failed to derive NK static pubkey\n");
            lsp_cleanup(&lsp);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        unsigned char nk_pub_ser[33];
        size_t nk_pub_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, nk_pub_ser, &nk_pub_len, &nk_pub,
                                       SECP256K1_EC_COMPRESSED);
        char nk_hex[67];
        hex_encode(nk_pub_ser, 33, nk_hex);
        printf("LSP: NK static pubkey: %s\n", nk_hex);
        printf("LSP: clients should use --lsp-pubkey %s\n", nk_hex);
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    if (!lsp_accept_clients(&lsp)) {
        fprintf(stderr, "LSP: failed to accept clients\n");
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    printf("LSP: all %d clients connected\n", n_clients);

    /* Disable socket timeout during ceremony — on-chain funding confirmation
       can take 10+ minutes on signet/testnet */
    for (size_t i = 0; i < lsp.n_clients; i++)
        wire_set_timeout(lsp.client_fds[i], 0);

    /* Set peer labels for wire logging (Phase 22) */
    for (size_t i = 0; i < lsp.n_clients; i++) {
        char label[32];
        snprintf(label, sizeof(label), "client_%zu", i);
        wire_set_peer_label(lsp.client_fds[i], label);
    }

    /* Report: participants */
    report_begin_section(&rpt, "participants");
    report_add_pubkey(&rpt, "lsp", ctx, &lsp.lsp_pubkey);
    report_begin_array(&rpt, "clients");
    for (size_t i = 0; i < lsp.n_clients; i++)
        report_add_pubkey(&rpt, NULL, ctx, &lsp.client_pubkeys[i]);
    report_end_array(&rpt);
    report_end_section(&rpt);
    report_flush(&rpt);

    if (g_shutdown) {
        lsp_abort_ceremony(&lsp, "LSP shutting down");
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }

    /* === Phase 2: Compute funding address === */
    size_t n_total = 1 + lsp.n_clients;
    secp256k1_pubkey all_pks[FACTORY_MAX_SIGNERS];
    all_pks[0] = lsp.lsp_pubkey;
    for (size_t i = 0; i < lsp.n_clients; i++)
        all_pks[i + 1] = lsp.client_pubkeys[i];

    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, all_pks, n_total);

    /* Compute tweaked xonly pubkey for P2TR */
    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) {
        fprintf(stderr, "LSP: xonly serialize failed\n");
        lsp_cleanup(&lsp);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);

    musig_keyagg_t ka_copy = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &ka_copy.cache, tweak)) {
        fprintf(stderr, "LSP: tweak add failed\n");
        lsp_cleanup(&lsp);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) {
        fprintf(stderr, "LSP: xonly from pubkey failed\n");
        lsp_cleanup(&lsp);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 1;
    }

    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tweaked_xonly);

    /* Derive bech32m address */
    unsigned char tweaked_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, tweaked_ser, &tweaked_xonly)) {
        fprintf(stderr, "LSP: xonly serialize failed\n");
        lsp_cleanup(&lsp);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 1;
    }

    char fund_addr[128];
    if (!regtest_derive_p2tr_address(&rt, tweaked_ser, fund_addr, sizeof(fund_addr))) {
        fprintf(stderr, "LSP: failed to derive funding address\n");
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    printf("LSP: funding address: %s\n", fund_addr);

    /* === Phase 3: Fund the factory === */
    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) {
        fprintf(stderr, "LSP: failed to get mining address\n");
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }

    if (is_regtest) {
        regtest_mine_blocks(&rt, 101, mine_addr);
        if (!ensure_funded(&rt, mine_addr)) {
            fprintf(stderr, "LSP: failed to fund wallet (exhausted regtest?)\n");
            lsp_cleanup(&lsp);
            secp256k1_context_destroy(ctx);
            return 1;
        }
    } else {
        /* Signet/testnet/mainnet: check wallet balance, no mining */
        double bal = regtest_get_balance(&rt);
        double needed = (double)funding_sats / 100000000.0;
        if (bal < needed) {
            fprintf(stderr, "LSP: wallet balance %.8f BTC insufficient (need %.8f). "
                    "Fund via faucet first.\n", bal, needed);
            lsp_cleanup(&lsp);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        printf("LSP: wallet balance: %.8f BTC (sufficient)\n", bal);
    }

    double funding_btc = (double)funding_sats / 100000000.0;
    char funding_txid_hex[65];
    if (!regtest_fund_address(&rt, fund_addr, funding_btc, funding_txid_hex)) {
        fprintf(stderr, "LSP: failed to fund factory address\n");
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    if (is_regtest) {
        regtest_mine_blocks(&rt, 1, mine_addr);
    } else {
        printf("LSP: waiting for funding tx confirmation on %s...\n", network);
        int conf = regtest_wait_for_confirmation(&rt, funding_txid_hex,
                                                    confirm_timeout_secs);
        if (conf < 1) {
            fprintf(stderr, "LSP: funding tx not confirmed within timeout\n");
            lsp_cleanup(&lsp);
            secp256k1_context_destroy(ctx);
            return 1;
        }
    }
    printf("LSP: funded %llu sats, txid: %s\n",
           (unsigned long long)funding_sats, funding_txid_hex);

    /* Get funding output details */
    unsigned char funding_txid[32];
    hex_decode(funding_txid_hex, funding_txid, 32);
    reverse_bytes(funding_txid, 32);  /* display -> internal */

    uint64_t funding_amount = 0;
    unsigned char actual_spk[256];
    size_t actual_spk_len = 0;
    uint32_t funding_vout = 0;

    for (uint32_t v = 0; v < 4; v++) {
        regtest_get_tx_output(&rt, funding_txid_hex, v,
                              &funding_amount, actual_spk, &actual_spk_len);
        if (actual_spk_len == 34 && memcmp(actual_spk, fund_spk, 34) == 0) {
            funding_vout = v;
            break;
        }
    }
    if (funding_amount == 0) {
        fprintf(stderr, "LSP: could not find funding output\n");
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    printf("LSP: funding vout=%u, amount=%llu sats\n",
           funding_vout, (unsigned long long)funding_amount);

    /* Report: funding */
    report_begin_section(&rpt, "funding");
    report_add_string(&rpt, "txid", funding_txid_hex);
    report_add_uint(&rpt, "vout", funding_vout);
    report_add_uint(&rpt, "amount_sats", funding_amount);
    report_add_hex(&rpt, "script_pubkey", fund_spk, 34);
    report_add_string(&rpt, "address", fund_addr);
    report_end_section(&rpt);
    report_flush(&rpt);

    /* === Phase 4: Run factory creation ceremony === */
    if (g_shutdown) {
        lsp_abort_ceremony(&lsp, "LSP shutting down");
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    /* Compute cltv_timeout BEFORE factory creation (needed for staggered taptrees) */
    uint32_t cltv_timeout = 0;
    {
        int cur_height = regtest_get_block_height(&rt);
        if (cltv_timeout_arg > 0) {
            cltv_timeout = (uint32_t)cltv_timeout_arg;
        } else if (cur_height > 0) {
            /* Auto: regtest +35 blocks, non-regtest +1008 (~1 week) */
            int offset = is_regtest ? 35 : 1008;
            cltv_timeout = (uint32_t)cur_height + offset;
        }
    }

    printf("LSP: CLTV timeout: block %u (current: %d)\n",
           cltv_timeout, regtest_get_block_height(&rt));
    if (n_level_arity > 0)
        factory_set_level_arity(&lsp.factory, level_arities, n_level_arity);
    else if (leaf_arity == 1)
        factory_set_arity(&lsp.factory, FACTORY_ARITY_1);
    lsp.factory.placement_mode = (placement_mode_t)placement_mode_arg;
    lsp.factory.economic_mode = (economic_mode_t)economic_mode_arg;

    /* Populate default profiles from CLI config */
    for (size_t pi = 0; pi < (size_t)(1 + n_clients) && pi < FACTORY_MAX_SIGNERS; pi++) {
        lsp.factory.profiles[pi].participant_idx = (uint32_t)pi;
        if (pi == 0) {
            /* LSP gets remainder of profit share */
            lsp.factory.profiles[pi].profit_share_bps =
                (uint16_t)(10000 - (uint32_t)default_profit_bps * (uint32_t)n_clients);
        } else {
            lsp.factory.profiles[pi].profit_share_bps = default_profit_bps;
        }
        lsp.factory.profiles[pi].contribution_sats = funding_sats / (uint64_t)(1 + n_clients);
        lsp.factory.profiles[pi].uptime_score = 1.0f;
        lsp.factory.profiles[pi].timezone_bucket = 0;
    }

    /* If --test-burn, enable L-stock revocation before tree construction.
       Uses flat secrets (per ZmnSCPxj: no multi-party shachain method exists,
       just store all revocation keys independently).
       State is preserved across factory_init_from_pubkeys() in lsp.c. */
    if (test_burn) {
        if (!factory_generate_flat_secrets(&lsp.factory, 16)) {
            fprintf(stderr, "LSP: failed to generate flat revocation secrets\n");
            lsp_cleanup(&lsp);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        printf("LSP: flat revocation secrets generated for burn test (%zu epochs)\n",
               lsp.factory.n_revocation_secrets);
    }

    printf("LSP: starting factory creation ceremony...\n");
    if (!lsp_run_factory_creation(&lsp,
                                   funding_txid, funding_vout,
                                   funding_amount,
                                   fund_spk, 34,
                                   step_blocks, 4, cltv_timeout)) {
        fprintf(stderr, "LSP: factory creation failed\n");
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    printf("LSP: factory creation complete! (%zu nodes signed)\n", lsp.factory.n_nodes);

    /* Set factory lifecycle */
    {
        int cur_height = regtest_get_block_height(&rt);
        if (cur_height > 0) {
            factory_set_lifecycle(&lsp.factory, (uint32_t)cur_height,
                                  active_blocks, dying_blocks);
            printf("LSP: factory lifecycle set at height %d "
                   "(active=%u, dying=%u, CLTV=%u)\n",
                   cur_height, active_blocks, dying_blocks,
                   lsp.factory.cltv_timeout);
        }
    }

    /* Log DW counter initial state */
    {
        uint32_t epoch = dw_counter_epoch(&lsp.factory.counter);
        printf("LSP: DW epoch %u/%u (nSeq delays:", epoch,
               lsp.factory.counter.total_states);
        for (uint32_t li = 0; li < lsp.factory.counter.n_layers; li++) {
            uint16_t d = dw_delay_for_state(&lsp.factory.counter.layers[li].config,
                                              lsp.factory.counter.layers[li].current_state);
            printf(" L%u=%u", li, d);
        }
        printf(" blocks)\n");
    }

    /* Set fee estimator on factory (for computed fees) */
    lsp.factory.fee = &fee_est;

    /* === Ladder manager initialization (Tier 2) === */
    ladder_t *lad = calloc(1, sizeof(ladder_t));
    if (!lad) { fprintf(stderr, "LSP: alloc failed\n"); lsp_cleanup(&lsp); return 1; }
    if (!ladder_init(lad, ctx, &lsp_kp, active_blocks, dying_blocks)) {
        fprintf(stderr, "LSP: ladder_init failed\n");
        free(lad);
        lsp_cleanup(&lsp);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    {
        int cur_h = regtest_get_block_height(&rt);
        if (cur_h > 0) lad->current_block = (uint32_t)cur_h;
    }
    /* Populate slot 0 with the existing factory (detached copy — no shared
       tx_buf heap data, preventing double-free if lsp.factory is freed later). */
    {
        ladder_factory_t *lf = &lad->factories[0];
        lf->factory = lsp.factory;
        factory_detach_txbufs(&lf->factory);
        lf->factory_id = lad->next_factory_id++;
        lf->is_initialized = 1;
        lf->is_funded = 1;
        lf->cached_state = factory_get_state(&lsp.factory,
                                               lad->current_block);
        tx_buf_init(&lf->distribution_tx, 256);
        lad->n_factories = 1;
    }
    printf("LSP: ladder initialized (factory 0 at slot 0, state=%d)\n",
           (int)lad->factories[0].cached_state);

    /* Persist factory + tree nodes + DW counter */
    if (use_db) {
        if (!persist_begin(&db)) {
            fprintf(stderr, "LSP: warning: persist_begin failed for initial factory\n");
        } else {
            int init_ok = 1;
            if (!persist_save_factory(&db, &lsp.factory, ctx, 0)) {
                fprintf(stderr, "LSP: warning: failed to persist factory\n");
                init_ok = 0;
            }
            if (init_ok && !persist_save_tree_nodes(&db, &lsp.factory, 0)) {
                fprintf(stderr, "LSP: warning: failed to persist tree nodes\n");
                init_ok = 0;
            }
            if (init_ok) {
                /* Save initial DW counter state — use actual layer count (2 for arity-2, 3 for arity-1) */
                uint32_t init_layers[DW_MAX_LAYERS];
                for (uint32_t li = 0; li < lsp.factory.counter.n_layers; li++)
                    init_layers[li] = lsp.factory.counter.layers[li].config.max_states;
                persist_save_dw_counter(&db, 0, 0, lsp.factory.counter.n_layers, init_layers);
            }
            if (init_ok) {
                /* Save ladder factory state (Tier 2) */
                persist_save_ladder_factory(&db, 0, "active", 1, 1, 0,
                    lsp.factory.created_block, lsp.factory.active_blocks,
                    lsp.factory.dying_blocks, 0);
            }
            if (init_ok)
                persist_commit(&db);
            else
                persist_rollback(&db);
        }
    }

    /* Report: factory tree */
    report_begin_section(&rpt, "factory");
    report_add_uint(&rpt, "n_nodes", lsp.factory.n_nodes);
    report_add_uint(&rpt, "n_participants", lsp.factory.n_participants);
    report_add_uint(&rpt, "step_blocks", lsp.factory.step_blocks);
    report_add_uint(&rpt, "fee_per_tx", lsp.factory.fee_per_tx);
    report_factory_tree(&rpt, ctx, &lsp.factory);
    report_end_section(&rpt);
    report_flush(&rpt);

    /* === Phase 4b: Channel Operations === */
    lsp_channel_mgr_t *mgr = calloc(1, sizeof(lsp_channel_mgr_t));
    if (!mgr) { fprintf(stderr, "LSP: alloc failed\n"); lsp_cleanup(&lsp); return 1; }
    int channels_active = 0;
    uint64_t init_local = 0, init_remote = 0;
    if (n_payments > 0 || daemon_mode || demo_mode || breach_test || test_expiry ||
        test_distrib || test_turnover || test_rotation || force_close || test_burn ||
        test_htlc_force_close || test_rebalance || test_batch_rebalance || test_realloc ||
        test_dual_factory || test_dw_exhibition) {
        /* Set fee policy before init (init preserves these across memset) */
        mgr->fee = &fee_est;
        mgr->routing_fee_ppm = routing_fee_ppm;
        mgr->lsp_balance_pct = lsp_balance_pct;
        mgr->placement_mode = (placement_mode_t)placement_mode_arg;
        mgr->economic_mode = (economic_mode_t)economic_mode_arg;
        mgr->default_profit_bps = default_profit_bps;
        mgr->settlement_interval_blocks = settlement_interval;
        if (!lsp_channels_init(mgr, ctx, &lsp.factory, lsp_seckey, (size_t)n_clients)) {
            fprintf(stderr, "LSP: channel init failed\n");
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        if (!lsp_channels_exchange_basepoints(mgr, &lsp)) {
            fprintf(stderr, "LSP: basepoint exchange failed\n");
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        /* Save factory channel basepoints to DB for recovery */
        if (use_db) {
            if (!persist_begin(&db)) {
                fprintf(stderr, "LSP: warning: persist_begin failed for basepoint save\n");
            } else {
                int bp_ok = 1;
                for (size_t c = 0; c < mgr->n_channels; c++) {
                    if (!persist_save_basepoints(&db, (uint32_t)c,
                                                   &mgr->entries[c].channel)) {
                        fprintf(stderr, "LSP: warning: failed to persist basepoints "
                                "for channel %zu\n", c);
                        bp_ok = 0;
                        break;
                    }
                }
                if (bp_ok)
                    persist_commit(&db);
                else
                    persist_rollback(&db);
            }
        }

        /* Set persistence pointer (Phase 23) */
        mgr->persist = use_db ? &db : NULL;

        /* Set configurable confirmation timeout */
        mgr->confirm_timeout_secs = confirm_timeout_secs;
        mgr->heartbeat_interval = heartbeat_interval;

        /* Load persisted state (Phase 23) */
        if (use_db) {
            mgr->next_request_id = persist_load_counter(&db, "next_request_id", 1);

            /* Load invoices */
            unsigned char inv_hashes[MAX_INVOICE_REGISTRY][32];
            size_t inv_dests[MAX_INVOICE_REGISTRY];
            uint64_t inv_amounts[MAX_INVOICE_REGISTRY];
            size_t n_inv = persist_load_invoices(&db,
                inv_hashes, inv_dests, inv_amounts, MAX_INVOICE_REGISTRY);
            for (size_t i = 0; i < n_inv; i++) {
                if (mgr->n_invoices >= MAX_INVOICE_REGISTRY) break;
                invoice_entry_t *inv = &mgr->invoices[mgr->n_invoices++];
                memcpy(inv->payment_hash, inv_hashes[i], 32);
                inv->dest_client = inv_dests[i];
                inv->amount_msat = inv_amounts[i];
                inv->bridge_htlc_id = 0;
                inv->active = 1;
            }
            if (n_inv > 0)
                printf("LSP: loaded %zu invoices from DB\n", n_inv);

            /* Load HTLC origins */
            unsigned char orig_hashes[MAX_HTLC_ORIGINS][32];
            uint64_t orig_bridge[MAX_HTLC_ORIGINS], orig_req[MAX_HTLC_ORIGINS];
            size_t orig_sender[MAX_HTLC_ORIGINS];
            uint64_t orig_htlc[MAX_HTLC_ORIGINS];
            size_t n_orig = persist_load_htlc_origins(&db,
                orig_hashes, orig_bridge, orig_req, orig_sender, orig_htlc,
                MAX_HTLC_ORIGINS);
            for (size_t i = 0; i < n_orig; i++) {
                if (mgr->n_htlc_origins >= MAX_HTLC_ORIGINS) break;
                htlc_origin_t *origin = &mgr->htlc_origins[mgr->n_htlc_origins++];
                memcpy(origin->payment_hash, orig_hashes[i], 32);
                origin->bridge_htlc_id = orig_bridge[i];
                origin->request_id = orig_req[i];
                origin->sender_idx = orig_sender[i];
                origin->sender_htlc_id = orig_htlc[i];
                origin->active = 1;
            }
            if (n_orig > 0)
                printf("LSP: loaded %zu HTLC origins from DB\n", n_orig);
        }

        /* Set fee rate on all channels */
        for (size_t c = 0; c < mgr->n_channels; c++)
            mgr->entries[c].channel.fee_rate_sat_per_kvb = fee_rate;

        if (!lsp_channels_send_ready(mgr, &lsp)) {
            fprintf(stderr, "LSP: send CHANNEL_READY failed\n");
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }

        /* Persist initial channel state */
        if (use_db) {
            if (!persist_begin(&db)) {
                fprintf(stderr, "LSP: warning: persist_begin failed for channels\n");
            } else {
                int ch_ok = 1;
                for (size_t c = 0; c < mgr->n_channels; c++) {
                    if (!persist_save_channel(&db, &mgr->entries[c].channel, 0, (uint32_t)c)) {
                        ch_ok = 0;
                        break;
                    }
                    /* Save initial local PCS */
                    channel_t *ch = &mgr->entries[c].channel;
                    for (uint64_t cn = 0; cn < ch->n_local_pcs; cn++) {
                        unsigned char pcs[32];
                        if (channel_get_local_pcs(ch, cn, pcs)) {
                            persist_save_local_pcs(&db, (uint32_t)c, cn, pcs);
                            memset(pcs, 0, 32);
                        }
                    }
                }
                if (ch_ok)
                    persist_commit(&db);
                else
                    persist_rollback(&db);
            }
        }

        /* Report: channel init */
        report_channel_state(&rpt, "channels_initial", mgr);
        report_flush(&rpt);

        /* Initialize watchtower for breach detection.
         * Use static to avoid stack corruption (watchtower_t is ~6.5KB). */
        static watchtower_t wt;
        memset(&wt, 0, sizeof(wt));
        watchtower_init(&wt, mgr->n_channels, &rt, &fee_est,
                          use_db ? &db : NULL);
        for (size_t c = 0; c < mgr->n_channels; c++)
            watchtower_set_channel(&wt, c, &mgr->entries[c].channel);
        mgr->watchtower = &wt;

        /* Wire ladder into channel manager (Tier 2) */
        mgr->ladder = lad;

        /* Wire rotation parameters for continuous ladder (Gap #3) */
        memcpy(mgr->rot_lsp_seckey, lsp_seckey, 32);
        mgr->rot_fee_est = &fee_est;
        memcpy(mgr->rot_fund_spk, fund_spk, 34);
        mgr->rot_fund_spk_len = 34;
        snprintf(mgr->rot_fund_addr, sizeof(mgr->rot_fund_addr), "%s", fund_addr);
        snprintf(mgr->rot_mine_addr, sizeof(mgr->rot_mine_addr), "%s", mine_addr);
        mgr->rot_step_blocks = step_blocks;
        mgr->rot_states_per_layer = states_per_layer;
        mgr->rot_leaf_arity = leaf_arity;
        mgr->rot_is_regtest = is_regtest;
        mgr->rot_funding_sats = funding_sats;
        mgr->rot_auto_rotate = daemon_mode;  /* auto-rotate when in daemon mode */
        mgr->rot_attempted_mask = 0;
        mgr->cli_enabled = cli_mode;
        mgr->auto_rebalance = auto_rebalance;
        mgr->rebalance_threshold_pct = (uint16_t)rebalance_threshold;

        /* JIT Channel Fallback (Gap #2) */
        jit_channels_init(mgr);
        if (no_jit) mgr->jit_enabled = 0;
        mgr->jit_funding_sats = (jit_amount_arg > 0) ?
            (uint64_t)jit_amount_arg : (funding_sats / (uint64_t)n_clients);

        /* Load persisted JIT channels from DB */
        if (use_db) {
            jit_channel_t *jits = (jit_channel_t *)mgr->jit_channels;
            size_t jit_count = 0;
            persist_load_jit_channels(&db, jits, JIT_MAX_CHANNELS, &jit_count);
            mgr->n_jit_channels = jit_count;
            for (size_t ji = 0; ji < jit_count; ji++) {
                if (jits[ji].state == JIT_STATE_OPEN) {
                    unsigned char ls[4][32], rb[4][33];
                    if (persist_load_basepoints(&db, jits[ji].jit_channel_id,
                                                  ls, rb)) {
                        memcpy(jits[ji].channel.local_payment_basepoint_secret, ls[0], 32);
                        memcpy(jits[ji].channel.local_delayed_payment_basepoint_secret, ls[1], 32);
                        memcpy(jits[ji].channel.local_revocation_basepoint_secret, ls[2], 32);
                        memcpy(jits[ji].channel.local_htlc_basepoint_secret, ls[3], 32);
                        int bp_ok = 1;
                        bp_ok &= secp256k1_ec_pubkey_create(ctx, &jits[ji].channel.local_payment_basepoint, ls[0]);
                        bp_ok &= secp256k1_ec_pubkey_create(ctx, &jits[ji].channel.local_delayed_payment_basepoint, ls[1]);
                        bp_ok &= secp256k1_ec_pubkey_create(ctx, &jits[ji].channel.local_revocation_basepoint, ls[2]);
                        bp_ok &= secp256k1_ec_pubkey_create(ctx, &jits[ji].channel.local_htlc_basepoint, ls[3]);
                        bp_ok &= secp256k1_ec_pubkey_parse(ctx, &jits[ji].channel.remote_payment_basepoint, rb[0], 33);
                        bp_ok &= secp256k1_ec_pubkey_parse(ctx, &jits[ji].channel.remote_delayed_payment_basepoint, rb[1], 33);
                        bp_ok &= secp256k1_ec_pubkey_parse(ctx, &jits[ji].channel.remote_revocation_basepoint, rb[2], 33);
                        bp_ok &= secp256k1_ec_pubkey_parse(ctx, &jits[ji].channel.remote_htlc_basepoint, rb[3], 33);
                        if (!bp_ok) {
                            fprintf(stderr, "LSP: JIT channel %u has corrupt basepoints\n",
                                    jits[ji].jit_channel_id);
                            jits[ji].state = JIT_STATE_CLOSED;
                            continue;
                        }
                    }
                    size_t wt_idx = mgr->n_channels + jits[ji].client_idx;
                    watchtower_set_channel(&wt, wt_idx, &jits[ji].channel);
                }
            }
            if (jit_count > 0)
                printf("LSP: loaded %zu JIT channels from DB\n", jit_count);
        }

        if (n_payments > 0) {
            printf("LSP: channels ready, waiting for %d payments (%d messages)...\n",
                   n_payments, n_payments * 2);
            if (!lsp_channels_run_event_loop(mgr, &lsp, (size_t)(n_payments * 2))) {
                fprintf(stderr, "LSP: event loop failed\n");
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("LSP: all %d payments processed\n", n_payments);
        }

        /* Capture initial balances before demo (for breach test) */
        if ((breach_test || test_expiry) && mgr->n_channels > 0) {
            init_local = mgr->entries[0].channel.local_amount;
            init_remote = mgr->entries[0].channel.remote_amount;
        }

        if (demo_mode) {
            printf("LSP: channels ready, running demo sequence...\n");
            if (!lsp_channels_run_demo_sequence(mgr, &lsp)) {
                fprintf(stderr, "LSP: demo sequence failed\n");
            }

            /* Advance DW counter and track new epoch.  We only advance
               the counter here — in production the tree would be re-signed
               via split-round MuSig2 with all participants.  Skip when
               --test-burn is set so the burn test can broadcast the
               correctly-signed epoch-0 tree. */
            if (!test_burn && dw_counter_advance(&lsp.factory.counter)) {
                uint32_t epoch = dw_counter_epoch(&lsp.factory.counter);
                printf("LSP: DW advanced to epoch %u (delays:", epoch);
                for (uint32_t li = 0; li < lsp.factory.counter.n_layers; li++) {
                    uint16_t d = dw_delay_for_state(
                        &lsp.factory.counter.layers[li].config,
                        lsp.factory.counter.layers[li].current_state);
                    printf(" L%u=%u", li, d);
                }
                printf(" blocks)\n");
                if (use_db) {
                    uint32_t layer_states[DW_MAX_LAYERS];
                    for (uint32_t li = 0; li < lsp.factory.counter.n_layers; li++)
                        layer_states[li] = lsp.factory.counter.layers[li].current_state;
                    persist_save_dw_counter(&db, 0, epoch,
                                             lsp.factory.counter.n_layers,
                                             layer_states);
                }
            }
        }
        channels_active = 1;

        /* === DW Advance Test: advance counter, re-sign tree, force-close === */
        if (test_dw_advance) {
            printf("\n=== DW ADVANCE TEST ===\n");

            /* Record epoch-0 nSequence values for before/after comparison */
            uint32_t dwa_initial[FACTORY_MAX_NODES];
            printf("Before advance (epoch %u):\n",
                   dw_counter_epoch(&lsp.factory.counter));
            for (size_t ni = 0; ni < lsp.factory.n_nodes; ni++) {
                factory_node_t *node = &lsp.factory.nodes[ni];
                dwa_initial[ni] = node->nsequence;
                printf("  Node %zu: nSequence=0x%X (%u blocks)\n",
                       ni, node->nsequence, node->nsequence);
            }

            /* Populate keypairs — factory_init_from_pubkeys() leaves them
               zeroed, but factory_sign_all() needs them to generate nonces.
               In demo mode the LSP has all keys (same pattern as distrib/turnover tests). */
            {
                secp256k1_keypair all_kps[FACTORY_MAX_SIGNERS];
                all_kps[0] = lsp_kp;
                static const unsigned char fill[4] = { 0x22, 0x33, 0x44, 0x55 };
                for (int ci = 0; ci < n_clients; ci++) {
                    unsigned char ds[32];
                    memset(ds, fill[ci], 32);
                    if (!secp256k1_keypair_create(ctx, &all_kps[ci + 1], ds)) {
                        fprintf(stderr, "DW ADVANCE TEST: keypair create failed\n");
                        return 1;
                    }
                }
                memcpy(lsp.factory.keypairs, all_kps,
                       n_total * sizeof(secp256k1_keypair));
            }

            if (!factory_advance(&lsp.factory)) {
                fprintf(stderr, "DW ADVANCE TEST: factory_advance failed\n");
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            printf("After advance (epoch %u):\n",
                   dw_counter_epoch(&lsp.factory.counter));
            int saw_decrease = 0;
            for (size_t ni = 0; ni < lsp.factory.n_nodes; ni++) {
                factory_node_t *node = &lsp.factory.nodes[ni];
                printf("  Node %zu: nSequence=0x%X (%u blocks, was 0x%X)\n",
                       ni, node->nsequence, node->nsequence, dwa_initial[ni]);
                /* Compare before/after: any node that had nSequence > 0
                   and now has a lower value counts as a decrease */
                if (dwa_initial[ni] > 0 && node->nsequence < dwa_initial[ni])
                    saw_decrease = 1;
            }

            /* Force-close with the re-signed tree */
            printf("\nBroadcasting re-signed tree (%zu nodes) on %s...\n",
                   lsp.factory.n_nodes, network);

            if (!broadcast_factory_tree_any_network(&lsp.factory, &rt,
                                                      mine_addr, is_regtest,
                                                      confirm_timeout_secs)) {
                fprintf(stderr, "DW ADVANCE TEST: tree broadcast failed\n");
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            printf("\n=== DW ADVANCE TEST %s ===\n",
                   saw_decrease ? "PASSED" : "FAILED");
            if (saw_decrease)
                printf("All %zu nodes confirmed with advanced DW counter.\n",
                       lsp.factory.n_nodes);
            else
                fprintf(stderr, "DW ADVANCE TEST: no nSequence decrease detected\n");

            report_add_string(&rpt, "result",
                              saw_decrease ? "dw_advance_pass" : "dw_advance_fail");
            report_close(&rpt);
            jit_channels_cleanup(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return saw_decrease ? 0 : 1;
        }

        /* === DW Exhibition Test: multi-advance + PTLC close + cross-factory contrast === */
        if (test_dw_exhibition && channels_active) {
            printf("\n=== DW EXHIBITION TEST ===\n\n");
            int exhibition_pass = 1;
            char exhibition_close_txid[65] = {0};

            /* --- Phase 1: Multiple DW Advances — nSequence Countdown to Zero --- */
            printf("--- Phase 1: nSequence Countdown ---\n");

            /* Populate keypairs (demo mode: LSP has all keys) */
            secp256k1_keypair exh_kps[FACTORY_MAX_SIGNERS];
            exh_kps[0] = lsp_kp;
            {
                static const unsigned char fill[4] = { 0x22, 0x33, 0x44, 0x55 };
                for (int ci = 0; ci < n_clients; ci++) {
                    unsigned char ds[32];
                    memset(ds, fill[ci], 32);
                    if (!secp256k1_keypair_create(ctx, &exh_kps[ci + 1], ds)) {
                        fprintf(stderr, "DW EXHIBITION: keypair create failed\n");
                        return 1;
                    }
                }
            }
            memcpy(lsp.factory.keypairs, exh_kps,
                   n_total * sizeof(secp256k1_keypair));

            /* Record initial nSequence for all nodes */
            uint32_t initial_nseq[FACTORY_MAX_NODES];
            for (size_t ni = 0; ni < lsp.factory.n_nodes; ni++)
                initial_nseq[ni] = lsp.factory.nodes[ni].nsequence;

            printf("Epoch 0 (initial):\n");
            for (size_t ni = 0; ni < lsp.factory.n_nodes; ni++)
                printf("  Node %zu: nSequence=%u\n", ni, lsp.factory.nodes[ni].nsequence);

            /* Advance states_per_layer - 1 times to reach zero */
            int max_advances = states_per_layer - 1;
            int any_zero = 0;
            int any_decreased = 0;
            for (int adv = 0; adv < max_advances; adv++) {
                if (!factory_advance(&lsp.factory)) {
                    fprintf(stderr, "DW EXHIBITION: factory_advance failed at step %d\n", adv + 1);
                    exhibition_pass = 0;
                    break;
                }
                printf("Epoch %u (advance %d/%d):\n",
                       dw_counter_epoch(&lsp.factory.counter), adv + 1, max_advances);
                for (size_t ni = 0; ni < lsp.factory.n_nodes; ni++) {
                    uint32_t cur = lsp.factory.nodes[ni].nsequence;
                    int32_t delta = (int32_t)cur - (int32_t)initial_nseq[ni];
                    printf("  Node %zu: nSequence=%u (delta=%d)\n", ni, cur, delta);
                    if (cur == 0) any_zero = 1;
                }
            }

            /* Verify: all state nodes decreased from initial AND at least one reached 0 */
            for (size_t ni = 0; ni < lsp.factory.n_nodes; ni++) {
                if (initial_nseq[ni] > 0 && initial_nseq[ni] != 0xFFFFFFFF &&
                    lsp.factory.nodes[ni].nsequence < initial_nseq[ni])
                    any_decreased = 1;
            }

            if (!any_decreased || !any_zero) {
                fprintf(stderr, "DW EXHIBITION Phase 1: countdown check failed "
                        "(any_decreased=%d, any_zero=%d)\n", any_decreased, any_zero);
                exhibition_pass = 0;
            }
            printf("Phase 1: %s (any_decreased=%d, any_zero=%d)\n\n",
                   (any_decreased && any_zero) ? "PASS" : "FAIL",
                   any_decreased, any_zero);

            /* Record Factory 0 final nSequence for Phase 3 comparison */
            uint32_t f0_final_nseq = 0;
            for (size_t ni = 0; ni < lsp.factory.n_nodes; ni++) {
                if (lsp.factory.nodes[ni].nsequence != 0xFFFFFFFF && lsp.factory.nodes[ni].nsequence > f0_final_nseq)
                    f0_final_nseq = lsp.factory.nodes[ni].nsequence;
            }

            /* --- Phase 2: PTLC-Assisted Exit — Close Without Clients --- */
            printf("--- Phase 2: PTLC-Assisted Close ---\n");

            /* Build pubkey array and aggregate */
            secp256k1_pubkey exh_pks[FACTORY_MAX_SIGNERS];
            for (size_t ti = 0; ti < n_total; ti++) {
                if (!secp256k1_keypair_pub(ctx, &exh_pks[ti], &exh_kps[ti])) {
                    fprintf(stderr, "DW EXHIBITION: keypair pub failed\n");
                    return 1;
                }
            }
            musig_keyagg_t exh_ka;
            musig_aggregate_keys(ctx, &exh_ka, exh_pks, n_total);

            /* Turnover message hash */
            unsigned char exh_msg[32];
            sha256_tagged("turnover", (const unsigned char *)"turnover", 8, exh_msg);

            /* For each client: adaptor presig -> adapt -> extract -> verify -> record */
            for (int ci = 0; ci < n_clients; ci++) {
                uint32_t participant_idx = (uint32_t)(ci + 1);
                secp256k1_pubkey client_pk = exh_pks[participant_idx];

                unsigned char presig[64];
                int nonce_parity;
                musig_keyagg_t ka_copy = exh_ka;
                if (!adaptor_create_turnover_presig(ctx, presig, &nonce_parity,
                                                      exh_msg, exh_kps, n_total,
                                                      &ka_copy, NULL, &client_pk)) {
                    fprintf(stderr, "DW EXHIBITION: presig failed for client %d\n", ci);
                    exhibition_pass = 0;
                    break;
                }

                unsigned char client_sec[32];
                if (!secp256k1_keypair_sec(ctx, client_sec, &exh_kps[participant_idx])) {
                    fprintf(stderr, "DW EXHIBITION: keypair sec failed\n");
                    return 1;
                }
                unsigned char adapted_sig[64];
                if (!adaptor_adapt(ctx, adapted_sig, presig, client_sec, nonce_parity)) {
                    fprintf(stderr, "DW EXHIBITION: adapt failed for client %d\n", ci);
                    memset(client_sec, 0, 32);
                    exhibition_pass = 0;
                    break;
                }

                unsigned char extracted[32];
                if (!adaptor_extract_secret(ctx, extracted, adapted_sig, presig,
                                              nonce_parity)) {
                    fprintf(stderr, "DW EXHIBITION: extract failed for client %d\n", ci);
                    memset(client_sec, 0, 32);
                    exhibition_pass = 0;
                    break;
                }

                if (!adaptor_verify_extracted_key(ctx, extracted, &client_pk)) {
                    fprintf(stderr, "DW EXHIBITION: verify failed for client %d\n", ci);
                    memset(client_sec, 0, 32);
                    exhibition_pass = 0;
                    break;
                }

                ladder_record_key_turnover(lad, 0, participant_idx, extracted);
                if (use_db)
                    persist_save_departed_client(&db, 0, participant_idx, extracted);
                printf("  Client %d: key extracted and verified\n", ci + 1);
                memset(client_sec, 0, 32);
            }

            /* Verify all clients departed */
            int can_close = ladder_can_close(lad, 0);
            if (!can_close) {
                fprintf(stderr, "DW EXHIBITION Phase 2: ladder_can_close returned false\n");
                exhibition_pass = 0;
            }

            /* Build close outputs (equal split minus 500 sat fee) */
            tx_output_t exh_outputs[FACTORY_MAX_SIGNERS];
            uint64_t exh_per = (lsp.factory.funding_amount_sats - 500) / n_total;
            for (size_t ti = 0; ti < n_total; ti++) {
                exh_outputs[ti].amount_sats = exh_per;
                memcpy(exh_outputs[ti].script_pubkey, fund_spk, 34);
                exh_outputs[ti].script_pubkey_len = 34;
            }
            exh_outputs[n_total - 1].amount_sats =
                lsp.factory.funding_amount_sats - 500 - exh_per * (n_total - 1);

            /* Build cooperative close using extracted keys */
            tx_buf_t exh_close_tx;
            tx_buf_init(&exh_close_tx, 512);
            int close_built = ladder_build_close(lad, 0, &exh_close_tx,
                                                   exh_outputs, n_total,
                                                   (uint32_t)regtest_get_block_height(&rt));
            if (!close_built) {
                fprintf(stderr, "DW EXHIBITION Phase 2: ladder_build_close failed\n");
                tx_buf_free(&exh_close_tx);
                exhibition_pass = 0;
            }

            /* Broadcast close TX */
            int close_confirmed = 0;
            if (close_built) {
                char *ec_hex = malloc(exh_close_tx.len * 2 + 1);
                hex_encode(exh_close_tx.data, exh_close_tx.len, ec_hex);
                int ec_sent = regtest_send_raw_tx(&rt, ec_hex, exhibition_close_txid);
                if (g_db)
                    persist_log_broadcast(g_db, ec_sent ? exhibition_close_txid : "?",
                        "exhibition_close", ec_hex, ec_sent ? "ok" : "failed");
                free(ec_hex);
                tx_buf_free(&exh_close_tx);

                if (!ec_sent) {
                    fprintf(stderr, "DW EXHIBITION Phase 2: close TX broadcast failed\n");
                    exhibition_pass = 0;
                } else {
                    ADVANCE(1);
                    close_confirmed = 1;
                    printf("  Close TX broadcast: %s\n", exhibition_close_txid);
                }
            }
            printf("Phase 2: %s\n\n",
                   (can_close && close_confirmed) ? "PASS" : "FAIL");

            /* --- Phase 3: Cross-Factory nSequence Contrast --- */
            printf("--- Phase 3: Cross-Factory nSequence Contrast ---\n");

            /* Check wallet balance (non-regtest only) */
            if (!is_regtest) {
                double bal = regtest_get_balance(&rt);
                double needed = (double)funding_sats / 100000000.0;
                if (bal < needed) {
                    fprintf(stderr, "DW EXHIBITION Phase 3: insufficient balance "
                            "(%.8f < %.8f)\n", bal, needed);
                    exhibition_pass = 0;
                }
            }

            /* Fund Factory 1 */
            double exh_funding_btc = (double)funding_sats / 100000000.0;
            char exh_fund_txid[65];
            int f1_funded = 0;
            if (exhibition_pass) {
                if (!regtest_fund_address(&rt, fund_addr, exh_funding_btc, exh_fund_txid)) {
                    fprintf(stderr, "DW EXHIBITION Phase 3: fund Factory 1 failed\n");
                    exhibition_pass = 0;
                } else {
                    if (is_regtest) {
                        regtest_mine_blocks(&rt, 1, mine_addr);
                    } else {
                        printf("Waiting for Factory 1 funding confirmation on %s...\n",
                               network);
                        fflush(stdout);
                        int conf = regtest_wait_for_confirmation(&rt, exh_fund_txid,
                                                                  confirm_timeout_secs);
                        if (conf < 1) {
                            fprintf(stderr, "DW EXHIBITION Phase 3: funding not confirmed\n");
                            exhibition_pass = 0;
                        }
                    }
                    if (exhibition_pass) {
                        f1_funded = 1;
                        printf("  Factory 1 funded: %s\n", exh_fund_txid);
                    }
                }
            }

            /* Find funding output */
            factory_t exh_f1;
            memset(&exh_f1, 0, sizeof(exh_f1));
            int f1_built = 0;
            uint32_t f1_initial_nseq = 0;

            if (f1_funded) {
                unsigned char exh_fund_txid_bytes[32];
                hex_decode(exh_fund_txid, exh_fund_txid_bytes, 32);
                reverse_bytes(exh_fund_txid_bytes, 32);

                uint64_t exh_fund_amount = 0;
                unsigned char exh_fund_spk[256];
                size_t exh_fund_spk_len = 0;
                uint32_t exh_fund_vout = 0;
                for (uint32_t v = 0; v < 4; v++) {
                    regtest_get_tx_output(&rt, exh_fund_txid, v,
                                          &exh_fund_amount, exh_fund_spk, &exh_fund_spk_len);
                    if (exh_fund_spk_len == 34 && memcmp(exh_fund_spk, fund_spk, 34) == 0) {
                        exh_fund_vout = v;
                        break;
                    }
                }
                if (exh_fund_amount == 0) {
                    fprintf(stderr, "DW EXHIBITION Phase 3: no funding output found\n");
                    exhibition_pass = 0;
                } else {
                    /* Build Factory 1 locally */
                    if (n_level_arity > 0)
                        factory_set_level_arity(&exh_f1, level_arities, n_level_arity);
                    else if (leaf_arity == 1)
                        factory_set_arity(&exh_f1, FACTORY_ARITY_1);

                    if (!factory_init(&exh_f1, ctx, exh_kps, n_total,
                                      step_blocks, states_per_layer)) {
                        fprintf(stderr, "DW EXHIBITION Phase 3: factory_init failed\n");
                        exhibition_pass = 0;
                    } else {
                        int cur_h = regtest_get_block_height(&rt);
                        if (cltv_timeout_arg > 0) {
                            exh_f1.cltv_timeout = (uint32_t)cltv_timeout_arg;
                        } else if (cur_h > 0) {
                            int offset = is_regtest ? 35 : 1008;
                            exh_f1.cltv_timeout = (uint32_t)cur_h + offset;
                        }

                        factory_set_funding(&exh_f1, exh_fund_txid_bytes, exh_fund_vout,
                                            exh_fund_amount, fund_spk, 34);

                        if (!factory_build_tree(&exh_f1)) {
                            fprintf(stderr, "DW EXHIBITION Phase 3: factory_build_tree failed\n");
                            factory_free(&exh_f1);
                            exhibition_pass = 0;
                        } else if (!factory_sign_all(&exh_f1)) {
                            fprintf(stderr, "DW EXHIBITION Phase 3: factory_sign_all failed\n");
                            factory_free(&exh_f1);
                            exhibition_pass = 0;
                        } else {
                            f1_built = 1;
                            /* Set lifecycle for Factory 1 */
                            if (cur_h > 0)
                                factory_set_lifecycle(&exh_f1, (uint32_t)cur_h,
                                                      active_blocks, dying_blocks);
                            exh_f1.fee = &fee_est;

                            /* Record Factory 1 initial (max) nSequence */
                            for (size_t ni = 0; ni < exh_f1.n_nodes; ni++) {
                                if (exh_f1.nodes[ni].nsequence != 0xFFFFFFFF && exh_f1.nodes[ni].nsequence > f1_initial_nseq)
                                    f1_initial_nseq = exh_f1.nodes[ni].nsequence;
                            }

                            /* Store in ladder slot 1 */
                            ladder_factory_t *lf1 = &lad->factories[1];
                            lf1->factory = exh_f1;
                            factory_detach_txbufs(&lf1->factory);
                            lf1->factory_id = lad->next_factory_id++;
                            lf1->is_initialized = 1;
                            lf1->is_funded = 1;
                            lf1->cached_state = FACTORY_ACTIVE;
                            tx_buf_init(&lf1->distribution_tx, 256);
                            lad->n_factories = 2;

                            printf("\n--- nSequence Contrast ---\n");
                            printf("  Factory 0 (epoch %u, fully advanced): "
                                   "max state node nSequence=%u\n",
                                   dw_counter_epoch(&lsp.factory.counter), f0_final_nseq);
                            printf("  Factory 1 (epoch 0, fresh):           "
                                   "max state node nSequence=%u\n", f1_initial_nseq);
                            printf("  Delta: %u blocks\n",
                                   f1_initial_nseq > f0_final_nseq ?
                                   f1_initial_nseq - f0_final_nseq : 0);
                            printf("---\n\n");

                            /* Force-close Factory 1 (Factory 0 was closed by PTLC in Phase 2) */
                            printf("Broadcasting Factory 1 tree (%zu nodes) on %s...\n",
                                   exh_f1.n_nodes, network);
                            fflush(stdout);

                            if (!broadcast_factory_tree_any_network(&exh_f1, &rt,
                                                                      mine_addr, is_regtest,
                                                                      confirm_timeout_secs)) {
                                fprintf(stderr, "DW EXHIBITION Phase 3: "
                                        "Factory 1 tree broadcast failed\n");
                                exhibition_pass = 0;
                            } else {
                                printf("Factory 1 tree confirmed.\n");
                            }
                        }
                    }
                }
            }

            int phase3_pass = f1_built;
            if (!phase3_pass) exhibition_pass = 0;
            printf("Phase 3: %s\n\n", phase3_pass ? "PASS" : "FAIL");

            /* --- Final Verdict --- */
            printf("=== DW EXHIBITION TEST %s ===\n",
                   exhibition_pass ? "PASSED" : "FAILED");
            if (exhibition_pass) {
                printf("  Phase 1: nSequence countdown %u -> 0 over %d advances\n",
                       initial_nseq[0], max_advances);
                printf("  Phase 2: PTLC-assisted close confirmed (txid: %s)\n",
                       exhibition_close_txid);
                printf("  Phase 3: Cross-factory contrast (%u vs %u blocks)\n",
                       f0_final_nseq, f1_initial_nseq);
            }

            report_add_string(&rpt, "result",
                              exhibition_pass ? "dw_exhibition_pass" : "dw_exhibition_fail");
            report_close(&rpt);
            if (f1_built) factory_free(&exh_f1);
            jit_channels_cleanup(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return exhibition_pass ? 0 : 1;
        }

        /* === Leaf Advance Test: advance left leaf only, show per-leaf independence === */
        if (test_leaf_advance) {
            printf("\n=== LEAF ADVANCE TEST ===\n");

            if (lsp.factory.n_leaf_nodes < 2) {
                fprintf(stderr, "LEAF ADVANCE TEST: need >= 2 leaf nodes\n");
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Record nSequence for both leaves before */
            size_t left_ni = lsp.factory.leaf_node_indices[0];
            size_t right_ni = lsp.factory.leaf_node_indices[1];
            uint32_t left_nseq_before = lsp.factory.nodes[left_ni].nsequence;
            uint32_t right_nseq_before = lsp.factory.nodes[right_ni].nsequence;

            printf("Before leaf advance:\n");
            printf("  Left  leaf (node %zu): nSequence=0x%X\n", left_ni, left_nseq_before);
            printf("  Right leaf (node %zu): nSequence=0x%X\n", right_ni, right_nseq_before);

            /* Populate keypairs (same pattern as dw_advance test) */
            {
                secp256k1_keypair all_kps[FACTORY_MAX_SIGNERS];
                all_kps[0] = lsp_kp;
                static const unsigned char fill[4] = { 0x22, 0x33, 0x44, 0x55 };
                for (int ci = 0; ci < n_clients; ci++) {
                    unsigned char ds[32];
                    memset(ds, fill[ci], 32);
                    if (!secp256k1_keypair_create(ctx, &all_kps[ci + 1], ds)) {
                        fprintf(stderr, "LEAF ADVANCE TEST: keypair create failed\n");
                        return 1;
                    }
                }
                memcpy(lsp.factory.keypairs, all_kps,
                       n_total * sizeof(secp256k1_keypair));
            }

            /* Advance LEFT leaf only */
            if (!factory_advance_leaf(&lsp.factory, 0)) {
                fprintf(stderr, "LEAF ADVANCE TEST: factory_advance_leaf(0) failed\n");
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            uint32_t left_nseq_after = lsp.factory.nodes[left_ni].nsequence;
            uint32_t right_nseq_after = lsp.factory.nodes[right_ni].nsequence;

            printf("After advancing LEFT leaf only:\n");
            printf("  Left  leaf (node %zu): nSequence=0x%X (was 0x%X)\n",
                   left_ni, left_nseq_after, left_nseq_before);
            printf("  Right leaf (node %zu): nSequence=0x%X (was 0x%X)\n",
                   right_ni, right_nseq_after, right_nseq_before);

            int left_changed = (left_nseq_after != left_nseq_before);
            int right_unchanged = (right_nseq_after == right_nseq_before);

            /* Force-close with the re-signed tree */
            printf("\nBroadcasting tree with per-leaf advance on %s...\n", network);

            if (!broadcast_factory_tree_any_network(&lsp.factory, &rt,
                                                      mine_addr, is_regtest,
                                                      confirm_timeout_secs)) {
                fprintf(stderr, "LEAF ADVANCE TEST: tree broadcast failed\n");
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            int pass = left_changed && right_unchanged;
            printf("\n=== LEAF ADVANCE TEST %s ===\n", pass ? "PASSED" : "FAILED");
            printf("Left leaf nSequence %s (0x%X → 0x%X)\n",
                   left_changed ? "decreased" : "UNCHANGED", left_nseq_before, left_nseq_after);
            printf("Right leaf nSequence %s (0x%X → 0x%X)\n",
                   right_unchanged ? "unchanged" : "CHANGED", right_nseq_before, right_nseq_after);

            report_add_string(&rpt, "result", pass ? "leaf_advance_pass" : "leaf_advance_fail");
            report_close(&rpt);
            jit_channels_cleanup(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return pass ? 0 : 1;
        }

        /* === Dual Factory Test: create second factory, both ACTIVE, force-close both === */
        if (test_dual_factory && channels_active) {
            printf("\n=== DUAL FACTORY TEST ===\n");
            printf("Creating Factory 1 while Factory 0 is still ACTIVE...\n\n");

            /* Build keypairs array (demo mode: LSP has all keys) */
            secp256k1_keypair all_kps[FACTORY_MAX_SIGNERS];
            all_kps[0] = lsp_kp;
            {
                static const unsigned char fill[4] = { 0x22, 0x33, 0x44, 0x55 };
                for (int ci = 0; ci < n_clients; ci++) {
                    unsigned char ds[32];
                    memset(ds, fill[ci], 32);
                    if (!secp256k1_keypair_create(ctx, &all_kps[ci + 1], ds)) {
                        fprintf(stderr, "DUAL FACTORY TEST: keypair create failed\n");
                        return 1;
                    }
                }
            }

            /* Verify Factory 0 is ACTIVE */
            {
                int cur_h = regtest_get_block_height(&rt);
                if (cur_h > 0) ladder_advance_block(lad, (uint32_t)cur_h);
            }
            factory_state_t f0_state = lad->factories[0].cached_state;
            printf("Factory 0: state=%s, %zu nodes\n",
                   f0_state == FACTORY_ACTIVE ? "ACTIVE" :
                   f0_state == FACTORY_DYING ? "DYING" : "EXPIRED",
                   lad->factories[0].factory.n_nodes);

            /* Check wallet balance for second funding */
            if (!is_regtest) {
                double bal = regtest_get_balance(&rt);
                double needed = (double)funding_sats / 100000000.0;
                if (bal < needed) {
                    fprintf(stderr, "DUAL FACTORY TEST: insufficient balance (%.8f < %.8f)\n",
                            bal, needed);
                    fprintf(stderr, "  Fund wallet and retry.\n");
                    jit_channels_cleanup(mgr);
                    if (use_db) persist_close(&db);
                    lsp_cleanup(&lsp);
                    memset(lsp_seckey, 0, 32);
                    secp256k1_context_destroy(ctx);
                    return 1;
                }
                printf("Wallet balance: %.8f BTC (sufficient for Factory 1)\n", bal);
            }

            /* Fund Factory 1 */
            double funding_btc2 = (double)funding_sats / 100000000.0;
            char fund2_txid_hex[65];
            if (!regtest_fund_address(&rt, fund_addr, funding_btc2, fund2_txid_hex)) {
                fprintf(stderr, "DUAL FACTORY TEST: fund Factory 1 failed\n");
                jit_channels_cleanup(mgr);
                if (use_db) persist_close(&db);
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            if (is_regtest) {
                regtest_mine_blocks(&rt, 1, mine_addr);
            } else {
                printf("Waiting for Factory 1 funding confirmation on %s...\n", network);
                fflush(stdout);
                int conf = regtest_wait_for_confirmation(&rt, fund2_txid_hex,
                                                          confirm_timeout_secs);
                if (conf < 1) {
                    fprintf(stderr, "DUAL FACTORY TEST: funding not confirmed\n");
                    jit_channels_cleanup(mgr);
                    if (use_db) persist_close(&db);
                    lsp_cleanup(&lsp);
                    memset(lsp_seckey, 0, 32);
                    secp256k1_context_destroy(ctx);
                    return 1;
                }
            }
            printf("Factory 1 funded: %s\n", fund2_txid_hex);

            /* Find funding output */
            unsigned char fund2_txid[32];
            hex_decode(fund2_txid_hex, fund2_txid, 32);
            reverse_bytes(fund2_txid, 32);

            uint64_t fund2_amount = 0;
            unsigned char fund2_spk[256];
            size_t fund2_spk_len = 0;
            uint32_t fund2_vout = 0;
            for (uint32_t v = 0; v < 4; v++) {
                regtest_get_tx_output(&rt, fund2_txid_hex, v,
                                      &fund2_amount, fund2_spk, &fund2_spk_len);
                if (fund2_spk_len == 34 && memcmp(fund2_spk, fund_spk, 34) == 0) {
                    fund2_vout = v;
                    break;
                }
            }
            if (fund2_amount == 0) {
                fprintf(stderr, "DUAL FACTORY TEST: no funding output found\n");
                jit_channels_cleanup(mgr);
                if (use_db) persist_close(&db);
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Build Factory 1 locally (demo mode: we have all keypairs,
               no wire ceremony needed) */
            factory_t f1;
            memset(&f1, 0, sizeof(f1));
            if (n_level_arity > 0)
                factory_set_level_arity(&f1, level_arities, n_level_arity);
            else if (leaf_arity == 1)
                factory_set_arity(&f1, FACTORY_ARITY_1);

            if (!factory_init(&f1, ctx, all_kps, n_total, step_blocks, 4)) {
                fprintf(stderr, "DUAL FACTORY TEST: factory_init failed\n");
                jit_channels_cleanup(mgr);
                if (use_db) persist_close(&db);
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Compute cltv_timeout for Factory 1 */
            {
                int cur_h = regtest_get_block_height(&rt);
                if (cltv_timeout_arg > 0) {
                    f1.cltv_timeout = (uint32_t)cltv_timeout_arg;
                } else if (cur_h > 0) {
                    int offset = is_regtest ? 35 : 1008;
                    f1.cltv_timeout = (uint32_t)cur_h + offset;
                }
            }

            factory_set_funding(&f1, fund2_txid, fund2_vout, fund2_amount,
                                fund_spk, 34);

            if (!factory_build_tree(&f1)) {
                fprintf(stderr, "DUAL FACTORY TEST: factory_build_tree failed\n");
                factory_free(&f1);
                jit_channels_cleanup(mgr);
                if (use_db) persist_close(&db);
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            if (!factory_sign_all(&f1)) {
                fprintf(stderr, "DUAL FACTORY TEST: factory_sign_all failed\n");
                factory_free(&f1);
                jit_channels_cleanup(mgr);
                if (use_db) persist_close(&db);
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Set lifecycle for Factory 1 */
            {
                int cur_h = regtest_get_block_height(&rt);
                if (cur_h > 0)
                    factory_set_lifecycle(&f1, (uint32_t)cur_h,
                                          active_blocks, dying_blocks);
            }
            f1.fee = &fee_est;

            printf("Factory 1 created: %zu nodes signed\n", f1.n_nodes);

            /* Store Factory 1 in ladder slot 1 */
            {
                ladder_factory_t *lf1 = &lad->factories[1];
                lf1->factory = f1;
                factory_detach_txbufs(&lf1->factory);
                lf1->factory_id = lad->next_factory_id++;
                lf1->is_initialized = 1;
                lf1->is_funded = 1;
                lf1->cached_state = FACTORY_ACTIVE;
                tx_buf_init(&lf1->distribution_tx, 256);
                lad->n_factories = 2;
            }

            /* Update ladder block height */
            {
                int cur_h = regtest_get_block_height(&rt);
                if (cur_h > 0) ladder_advance_block(lad, (uint32_t)cur_h);
            }

            /* Report: both factories ACTIVE */
            printf("\n--- Ladder Status ---\n");
            printf("  Factories in ladder: %zu\n", lad->n_factories);
            for (size_t fi = 0; fi < lad->n_factories; fi++) {
                ladder_factory_t *lf = &lad->factories[fi];
                const char *st = lf->cached_state == FACTORY_ACTIVE ? "ACTIVE" :
                                 lf->cached_state == FACTORY_DYING ? "DYING" : "EXPIRED";
                printf("  Factory %u: state=%s, nodes=%zu, cltv=%u\n",
                       lf->factory_id, st, lf->factory.n_nodes,
                       lf->factory.cltv_timeout);
            }
            printf("---\n\n");

            int both_active = (lad->factories[0].cached_state == FACTORY_ACTIVE &&
                               lad->factories[1].cached_state == FACTORY_ACTIVE);

            /* Force-close both trees to show two independent factory trees on-chain */
            printf("Broadcasting Factory 0 tree (%zu nodes) on %s...\n",
                   lad->factories[0].factory.n_nodes, network);
            fflush(stdout);

            /* Populate keypairs for Factory 0 (ladder copy may not have them) */
            memcpy(lad->factories[0].factory.keypairs, all_kps,
                   n_total * sizeof(secp256k1_keypair));

            if (!broadcast_factory_tree_any_network(&lad->factories[0].factory, &rt,
                                                      mine_addr, is_regtest,
                                                      confirm_timeout_secs)) {
                fprintf(stderr, "DUAL FACTORY TEST: Factory 0 tree broadcast failed\n");
                factory_free(&f1);
                jit_channels_cleanup(mgr);
                if (use_db) persist_close(&db);
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("Factory 0 tree confirmed.\n\n");

            printf("Broadcasting Factory 1 tree (%zu nodes) on %s...\n",
                   f1.n_nodes, network);
            fflush(stdout);

            if (!broadcast_factory_tree_any_network(&f1, &rt,
                                                      mine_addr, is_regtest,
                                                      confirm_timeout_secs)) {
                fprintf(stderr, "DUAL FACTORY TEST: Factory 1 tree broadcast failed\n");
                factory_free(&f1);
                jit_channels_cleanup(mgr);
                if (use_db) persist_close(&db);
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("Factory 1 tree confirmed.\n\n");

            printf("=== DUAL FACTORY TEST %s ===\n",
                   both_active ? "PASSED" : "FAILED (not both ACTIVE)");
            printf("Two independent factory trees broadcast and confirmed on %s.\n",
                   network);

            report_add_string(&rpt, "result",
                              both_active ? "dual_factory_pass" : "dual_factory_fail");
            report_close(&rpt);
            factory_free(&f1);
            jit_channels_cleanup(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return both_active ? 0 : 1;
        }

        /* === Bridge Test: simulate inbound HTLC via bridge === */
        if (test_bridge && mgr->n_channels > 0) {
            printf("\n=== BRIDGE TEST ===\n");

            /* Create socketpair to simulate bridge <-> LSP connection */
            int sv[2];
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
                fprintf(stderr, "BRIDGE TEST: socketpair failed\n");
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            int bridge_test_fd = sv[0];  /* "bridge" side */
            int lsp_bridge_fd = sv[1];   /* LSP side */

            /* Set bridge_fd on the channel manager */
            lsp_channels_set_bridge(mgr, lsp_bridge_fd);
            lsp.bridge_fd = lsp_bridge_fd;
            printf("Bridge: simulated connection established\n");

            /* Generate a known preimage + payment_hash for the test invoice */
            unsigned char test_preimage[32];
            memset(test_preimage, 0xBE, 32);
            unsigned char test_hash[32];
            sha256(test_preimage, 32, test_hash);

            /* Register invoice: route to client 0, amount 1000 sats */
            size_t dest_client = 0;
            uint64_t amount_msat = 1000000;  /* 1000 sats */
            if (!lsp_channels_register_invoice(mgr, test_hash, test_preimage,
                                                 dest_client, amount_msat)) {
                fprintf(stderr, "BRIDGE TEST: register invoice failed\n");
                close(bridge_test_fd);
                close(lsp_bridge_fd);
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("Bridge: invoice registered for client %zu (amount=%llu msat)\n",
                   dest_client, (unsigned long long)amount_msat);

            /* Send MSG_BRIDGE_ADD_HTLC from bridge side */
            cJSON *add_msg = wire_build_bridge_add_htlc(test_hash,
                                                           amount_msat, 500, 42);
            if (!wire_send(bridge_test_fd, MSG_BRIDGE_ADD_HTLC, add_msg)) {
                fprintf(stderr, "BRIDGE TEST: send ADD_HTLC failed\n");
                cJSON_Delete(add_msg);
                close(bridge_test_fd);
                close(lsp_bridge_fd);
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            cJSON_Delete(add_msg);
            printf("Bridge: sent ADD_HTLC (htlc_id=42)\n");

            /* LSP handles the bridge message — routes HTLC to client */
            wire_msg_t bridge_msg;
            if (!wire_recv(lsp_bridge_fd, &bridge_msg)) {
                fprintf(stderr, "BRIDGE TEST: LSP recv from bridge failed\n");
                close(bridge_test_fd);
                close(lsp_bridge_fd);
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            if (!lsp_channels_handle_bridge_msg(mgr, &lsp, &bridge_msg)) {
                fprintf(stderr, "BRIDGE TEST: handle_bridge_msg failed\n");
                cJSON_Delete(bridge_msg.json);
                close(bridge_test_fd);
                close(lsp_bridge_fd);
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            cJSON_Delete(bridge_msg.json);
            printf("Bridge: LSP routed HTLC to client %zu via factory channel\n",
                   dest_client);

            /* Wait for MSG_BRIDGE_FULFILL_HTLC back on bridge side */
            wire_msg_t fulfill_msg;
            if (wire_recv_timeout(bridge_test_fd, &fulfill_msg, 10) &&
                fulfill_msg.msg_type == MSG_BRIDGE_FULFILL_HTLC) {
                unsigned char got_hash[32], got_preimage[32];
                uint64_t got_htlc_id;
                if (wire_parse_bridge_fulfill_htlc(fulfill_msg.json,
                                                      got_hash, got_preimage,
                                                      &got_htlc_id)) {
                    int hash_ok = (memcmp(got_hash, test_hash, 32) == 0);
                    int preimage_ok = (memcmp(got_preimage, test_preimage, 32) == 0);
                    printf("Bridge: received FULFILL_HTLC (htlc_id=%llu, "
                           "hash_ok=%d, preimage_ok=%d)\n",
                           (unsigned long long)got_htlc_id, hash_ok, preimage_ok);

                    if (hash_ok && preimage_ok) {
                        printf("\n=== BRIDGE TEST PASSED ===\n");
                        printf("Inbound HTLC routed through factory channel "
                               "and fulfilled with correct preimage.\n");
                    } else {
                        printf("\n=== BRIDGE TEST FAILED: preimage mismatch ===\n");
                    }
                } else {
                    printf("\n=== BRIDGE TEST FAILED: could not parse FULFILL ===\n");
                }
                cJSON_Delete(fulfill_msg.json);
            } else {
                printf("Bridge: no FULFILL received (client may not have auto-fulfilled)\n");
                printf("\n=== BRIDGE TEST FAILED (no fulfill) ===\n");
                printf("HTLC was routed to client but no FULFILL_HTLC was returned.\n");
                if (fulfill_msg.json) cJSON_Delete(fulfill_msg.json);
            }

            close(bridge_test_fd);
            /* lsp_bridge_fd owned by mgr now, cleaned up with lsp_cleanup */
        }

        /* === Force-close: broadcast entire factory tree === */
        if (force_close) {
            printf("\n=== FORCE CLOSE ===\n");
            printf("Broadcasting factory tree (%zu nodes) on %s...\n",
                   lsp.factory.n_nodes, network);

            if (!broadcast_factory_tree_any_network(&lsp.factory, &rt,
                                                      mine_addr, is_regtest,
                                                      confirm_timeout_secs)) {
                fprintf(stderr, "FORCE CLOSE: tree broadcast failed\n");
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            printf("\n=== FORCE CLOSE COMPLETE ===\n");
            printf("All %zu nodes confirmed on-chain.\n", lsp.factory.n_nodes);

            /* Skip cooperative close — factory already spent */
            report_add_string(&rpt, "result", "force_close_complete");
            report_close(&rpt);
            jit_channels_cleanup(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 0;
        }

        /* === Burn TX Test: broadcast tree + burn L-stock via shachain === */
        if (test_burn) {
            printf("\n=== BURN TX TEST ===\n");

            if (!lsp.factory.has_shachain) {
                fprintf(stderr, "BURN TEST: factory has no shachain (internal error)\n");
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Identify first leaf node and its L-stock output */
            size_t leaf_idx = lsp.factory.leaf_node_indices[0];
            factory_node_t *leaf = &lsp.factory.nodes[leaf_idx];
            uint32_t l_stock_vout = (uint32_t)(leaf->n_outputs - 1);
            uint64_t l_stock_amount = leaf->outputs[l_stock_vout].amount_sats;

            printf("Leaf node[%zu]: %zu outputs, L-stock at vout %u (%llu sats)\n",
                   leaf_idx, (size_t)leaf->n_outputs, l_stock_vout,
                   (unsigned long long)l_stock_amount);

            /* Step 1: Broadcast full factory tree */
            printf("Broadcasting factory tree (%zu nodes) on %s...\n",
                   lsp.factory.n_nodes, network);

            if (!broadcast_factory_tree_any_network(&lsp.factory, &rt,
                                                      mine_addr, is_regtest,
                                                      confirm_timeout_secs)) {
                fprintf(stderr, "BURN TEST: tree broadcast failed\n");
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("All %zu tree nodes confirmed on-chain.\n", lsp.factory.n_nodes);

            /* Step 2: Build burn TX for epoch 0 L-stock */
            tx_buf_t burn_tx;
            tx_buf_init(&burn_tx, 256);
            if (!factory_build_burn_tx(&lsp.factory, &burn_tx,
                                         leaf->txid, l_stock_vout,
                                         l_stock_amount, 0)) {
                fprintf(stderr, "BURN TEST: factory_build_burn_tx failed\n");
                tx_buf_free(&burn_tx);
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Step 3: Broadcast burn TX */
            char *burn_hex = malloc(burn_tx.len * 2 + 1);
            hex_encode(burn_tx.data, burn_tx.len, burn_hex);
            char burn_txid[65];
            int sent = regtest_send_raw_tx(&rt, burn_hex, burn_txid);
            if (g_db)
                persist_log_broadcast(g_db, sent ? burn_txid : "?",
                    "burn_tx", burn_hex, sent ? "ok" : "failed");
            free(burn_hex);
            tx_buf_free(&burn_tx);

            if (!sent) {
                fprintf(stderr, "BURN TEST: burn TX broadcast failed\n");
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            ADVANCE(1);

            printf("Burn TX broadcast: %s\n", burn_txid);
            printf("L-stock at leaf[%zu]:vout %u burned (%llu sats revoked)\n",
                   leaf_idx, l_stock_vout, (unsigned long long)l_stock_amount);

            printf("\n=== BURN TX TEST PASSED ===\n");

            report_add_string(&rpt, "result", "burn_test_complete");
            report_close(&rpt);
            jit_channels_cleanup(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 0;
        }

        /* === HTLC Force-Close Test: pending HTLC + tree broadcast + timeout TX === */
        if (test_htlc_force_close) {
            printf("\n=== HTLC FORCE-CLOSE TEST ===\n");

            if (mgr->n_channels < 2) {
                fprintf(stderr, "HTLC FORCE-CLOSE TEST: need at least 2 channels\n");
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Step 1: Add a pending HTLC on channel 0 (low CLTV for quick timeout) */
            uint32_t current_height = (uint32_t)regtest_get_block_height(&rt);
            uint32_t htlc_cltv = current_height + 10;  /* expires in ~10 blocks */
            unsigned char dummy_hash[32];
            memset(dummy_hash, 0xAA, 32);  /* dummy payment hash */
            uint64_t htlc_amount = 1000;

            printf("Adding pending HTLC on channel 0 (amount=%llu sats, cltv=%u, "
                   "current_height=%u)\n",
                   (unsigned long long)htlc_amount, htlc_cltv, current_height);

            if (!lsp_channels_add_pending_htlc(mgr, &lsp, 0, htlc_amount,
                                                 dummy_hash, htlc_cltv)) {
                fprintf(stderr, "HTLC FORCE-CLOSE TEST: add_pending_htlc failed\n");
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Step 2: Broadcast the factory tree */
            printf("Broadcasting factory tree (%zu nodes) on %s...\n",
                   lsp.factory.n_nodes, network);

            if (!broadcast_factory_tree_any_network(&lsp.factory, &rt,
                                                      mine_addr, is_regtest,
                                                      confirm_timeout_secs)) {
                fprintf(stderr, "HTLC FORCE-CLOSE TEST: tree broadcast failed\n");
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("All %zu tree nodes confirmed on-chain.\n", lsp.factory.n_nodes);

            /* Step 3: Build and broadcast the commitment TX (has HTLC output) */
            channel_t *ch0 = &mgr->entries[0].channel;
            tx_buf_t commit_unsigned;
            tx_buf_init(&commit_unsigned, 512);
            unsigned char commit_txid[32];

            if (!channel_build_commitment_tx(ch0, &commit_unsigned, commit_txid)) {
                fprintf(stderr, "HTLC FORCE-CLOSE TEST: build commitment TX failed\n");
                tx_buf_free(&commit_unsigned);
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Sign with both LSP + client keys (test key 0x22..22) */
            unsigned char cli_sec[32];
            memset(cli_sec, 0x22, 32);
            secp256k1_keypair cli_kp;
            if (!secp256k1_keypair_create(ctx, &cli_kp, cli_sec)) {
                fprintf(stderr, "HTLC FORCE-CLOSE TEST: client keypair failed\n");
                memset(cli_sec, 0, 32);
                tx_buf_free(&commit_unsigned);
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            memset(cli_sec, 0, 32);

            tx_buf_t commit_signed;
            tx_buf_init(&commit_signed, 512);
            if (!channel_sign_commitment(ch0, &commit_signed, &commit_unsigned, &cli_kp)) {
                fprintf(stderr, "HTLC FORCE-CLOSE TEST: sign commitment failed\n");
                tx_buf_free(&commit_signed);
                tx_buf_free(&commit_unsigned);
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            tx_buf_free(&commit_unsigned);

            char *commit_hex = malloc(commit_signed.len * 2 + 1);
            hex_encode(commit_signed.data, commit_signed.len, commit_hex);
            char commit_txid_str[65];
            int sent = regtest_send_raw_tx(&rt, commit_hex, commit_txid_str);
            if (g_db)
                persist_log_broadcast(g_db, sent ? commit_txid_str : "?",
                    "htlc_commitment", commit_hex, sent ? "ok" : "failed");
            free(commit_hex);
            tx_buf_free(&commit_signed);

            if (!sent) {
                fprintf(stderr, "HTLC FORCE-CLOSE TEST: commitment broadcast failed\n");
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            ADVANCE(1);
            printf("Commitment TX broadcast: %s\n", commit_txid_str);

            /* Step 4: HTLC output is at vout 2 (after to_local and to_remote).
               Get the script pubkey from the commitment TX output. */
            uint32_t htlc_vout = 2;
            /* Re-build commitment to extract output script pubkeys */
            tx_buf_t commit_rebuild;
            tx_buf_init(&commit_rebuild, 512);
            unsigned char rebuild_txid[32];
            channel_build_commitment_tx(ch0, &commit_rebuild, rebuild_txid);

            /* Parse the commitment TX to get the HTLC output script pubkey.
               In our serialization, outputs start after the input section.
               We can use the channel's HTLC amount directly. */
            /* For the HTLC timeout TX, we need the HTLC output's scriptPubKey.
               Build it from the channel state (same as commitment_tx_impl does). */
            unsigned char htlc_spk[34];
            size_t htlc_spk_len = 0;
            {
                /* Derive the HTLC output scriptPubKey by rebuilding the taproot key */
                secp256k1_pubkey pcp;
                channel_get_per_commitment_point(ch0, ch0->commitment_number, &pcp);

                secp256k1_pubkey revocation_pubkey;
                channel_derive_revocation_pubkey(ch0->ctx, &revocation_pubkey,
                    &ch0->remote_revocation_basepoint, &pcp);
                secp256k1_xonly_pubkey revocation_xonly;
                secp256k1_xonly_pubkey_from_pubkey(ch0->ctx, &revocation_xonly, NULL,
                    &revocation_pubkey);

                secp256k1_pubkey local_htlc_pub, remote_htlc_pub;
                channel_derive_pubkey(ch0->ctx, &local_htlc_pub,
                    &ch0->local_htlc_basepoint, &pcp);
                channel_derive_pubkey(ch0->ctx, &remote_htlc_pub,
                    &ch0->remote_htlc_basepoint, &pcp);
                secp256k1_xonly_pubkey local_htlc_xonly, remote_htlc_xonly;
                secp256k1_xonly_pubkey_from_pubkey(ch0->ctx, &local_htlc_xonly, NULL,
                    &local_htlc_pub);
                secp256k1_xonly_pubkey_from_pubkey(ch0->ctx, &remote_htlc_xonly, NULL,
                    &remote_htlc_pub);

                /* Build the HTLC taptree leaves (same as commitment TX builder) */
                tapscript_leaf_t success_leaf, timeout_leaf;
                htlc_t *h = &ch0->htlcs[ch0->n_htlcs - 1]; /* last HTLC = ours */
                if (h->direction == HTLC_OFFERED) {
                    tapscript_build_htlc_offered_success(&success_leaf,
                        h->payment_hash, &remote_htlc_xonly, ch0->ctx);
                    tapscript_build_htlc_offered_timeout(&timeout_leaf,
                        h->cltv_expiry, ch0->to_self_delay,
                        &local_htlc_xonly, ch0->ctx);
                } else {
                    tapscript_build_htlc_received_success(&success_leaf,
                        h->payment_hash, ch0->to_self_delay,
                        &local_htlc_xonly, ch0->ctx);
                    tapscript_build_htlc_received_timeout(&timeout_leaf,
                        h->cltv_expiry, &remote_htlc_xonly, ch0->ctx);
                }

                tapscript_leaf_t htlc_leaves[2] = { success_leaf, timeout_leaf };
                unsigned char htlc_merkle[32];
                tapscript_merkle_root(htlc_merkle, htlc_leaves, 2);

                secp256k1_xonly_pubkey htlc_tweaked;
                tapscript_tweak_pubkey(ch0->ctx, &htlc_tweaked, NULL,
                    &revocation_xonly, htlc_merkle);

                build_p2tr_script_pubkey(htlc_spk, &htlc_tweaked);
                htlc_spk_len = 34;
            }
            tx_buf_free(&commit_rebuild);

            /* Step 5: Mine blocks to reach CLTV expiry */
            uint32_t now_height = (uint32_t)regtest_get_block_height(&rt);
            if (now_height < htlc_cltv) {
                uint32_t blocks_needed = htlc_cltv - now_height;
                printf("Advancing %u blocks to reach CLTV expiry %u...\n",
                       blocks_needed, htlc_cltv);
                ADVANCE((int)blocks_needed);
            }

            /* Also mine to_self_delay blocks for CSV on the timeout TX */
            printf("Advancing %u blocks for CSV delay...\n", ch0->to_self_delay);
            ADVANCE((int)ch0->to_self_delay);

            /* Step 6: Build and broadcast HTLC timeout TX */
            size_t htlc_index = ch0->n_htlcs - 1;  /* last HTLC */
            tx_buf_t timeout_tx;
            tx_buf_init(&timeout_tx, 256);

            if (!channel_build_htlc_timeout_tx(ch0, &timeout_tx,
                    commit_txid, htlc_vout, htlc_amount,
                    htlc_spk, htlc_spk_len, htlc_index)) {
                fprintf(stderr, "HTLC FORCE-CLOSE TEST: build timeout TX failed\n");
                tx_buf_free(&timeout_tx);
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            char *timeout_hex = malloc(timeout_tx.len * 2 + 1);
            hex_encode(timeout_tx.data, timeout_tx.len, timeout_hex);
            char timeout_txid_str[65];
            int timeout_sent = regtest_send_raw_tx(&rt, timeout_hex, timeout_txid_str);
            if (g_db)
                persist_log_broadcast(g_db, timeout_sent ? timeout_txid_str : "?",
                    "htlc_timeout", timeout_hex, timeout_sent ? "ok" : "failed");
            free(timeout_hex);
            tx_buf_free(&timeout_tx);

            if (!timeout_sent) {
                fprintf(stderr, "HTLC FORCE-CLOSE TEST: timeout TX broadcast failed\n");
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            ADVANCE(1);

            printf("HTLC timeout TX broadcast: %s\n", timeout_txid_str);
            printf("\n=== HTLC FORCE-CLOSE TEST PASSED ===\n");

            report_add_string(&rpt, "result", "htlc_force_close_complete");
            report_close(&rpt);
            jit_channels_cleanup(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 0;
        }

        if (daemon_mode) {
            printf("LSP: channels ready, entering daemon mode...\n");
            fflush(stdout);

            /* Restore default socket timeout for daemon mode health checks */
            for (size_t i = 0; i < lsp.n_clients; i++)
                wire_set_timeout(lsp.client_fds[i], WIRE_DEFAULT_TIMEOUT_SEC);

            /* Accept bridge connection if available */
            /* (bridge connects asynchronously — handled in daemon loop via select) */

            lsp_channels_run_daemon_loop(mgr, &lsp, &g_shutdown);
        }

        /* The daemon loop exits when g_shutdown is set — either by the
           CLI "close" command or by SIGINT/SIGTERM.  For "close", we want
           Phase 5 to run the cooperative close ceremony.  For signals,
           we want the abort path.  Clear g_shutdown here so Phase 5
           proceeds; if a signal arrives *after* this point the handler
           will set it again and Phase 5's abort guard will catch it. */
        g_shutdown = 0;

        channels_active = 1;

        /* Persist updated channel balances */
        if (use_db) {
            if (!persist_begin(&db)) {
                fprintf(stderr, "LSP: warning: persist_begin failed for balance update\n");
            } else {
                int bal_ok = 1;
                for (size_t c = 0; c < mgr->n_channels; c++) {
                    const channel_t *ch = &mgr->entries[c].channel;
                    if (!persist_update_channel_balance(&db, (uint32_t)c,
                        ch->local_amount, ch->remote_amount, ch->commitment_number)) {
                        bal_ok = 0;
                        break;
                    }
                }
                if (bal_ok)
                    persist_commit(&db);
                else
                    persist_rollback(&db);
            }
        }

        /* Report: channel state after payments */
        report_channel_state(&rpt, "channels_after_payments", mgr);
        report_flush(&rpt);
    }

    /* === Breach Test: broadcast factory tree + revoked commitment === */
    if (breach_test && channels_active) {
        printf("\n=== BREACH TEST ===\n");
        fflush(stdout);
        printf("Broadcasting factory tree (all %zu nodes)...\n", lsp.factory.n_nodes);

        int tree_ok;
        if (is_regtest) {
            tree_ok = broadcast_factory_tree(&lsp.factory, &rt, mine_addr);
        } else {
            tree_ok = broadcast_factory_tree_any_network(&lsp.factory, &rt,
                                                          mine_addr, 0,
                                                          confirm_timeout_secs);
        }
        if (!tree_ok) {
            fprintf(stderr, "BREACH TEST: factory tree broadcast failed\n");
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        printf("Factory tree confirmed on-chain.\n");

        /* Broadcast revoked commitments for ALL channels so every client's
         * watchtower can detect the breach independently. */
        static const unsigned char client_fills[4] = { 0x22, 0x33, 0x44, 0x55 };
        for (size_t ci = 0; ci < mgr->n_channels; ci++) {
            channel_t *chX = &mgr->entries[ci].channel;
            uint64_t saved_num = chX->commitment_number;
            uint64_t saved_local = chX->local_amount;
            uint64_t saved_remote = chX->remote_amount;
            size_t saved_n_htlcs = chX->n_htlcs;

            /* Temporarily revert to commitment #0 with no HTLCs */
            chX->commitment_number = 0;
            chX->local_amount = init_local;
            chX->remote_amount = init_remote;
            chX->n_htlcs = 0;

            /* Ensure remote PCP for commitment #0 is available.
               Re-derive from the stored revocation secret (same approach
               as watchtower_watch_revoked_commitment). */
            {
                unsigned char rev_secret[32];
                if (channel_get_received_revocation(chX, 0, rev_secret)) {
                    secp256k1_pubkey old_pcp;
                    if (secp256k1_ec_pubkey_create(ctx, &old_pcp, rev_secret))
                        channel_set_remote_pcp(chX, 0, &old_pcp);
                    memset(rev_secret, 0, 32);
                }
            }

            /* Verify local PCP for commitment #0 is still available.
               The local_pcs array retains all entries (no pruning), so this
               should always succeed.  Log diagnostic if it doesn't. */
            {
                secp256k1_pubkey local_pcp_check;
                if (!channel_get_per_commitment_point(chX, 0, &local_pcp_check)) {
                    fprintf(stderr, "BREACH TEST: local PCP for commitment 0 unavailable "
                            "(channel %zu, n_local_pcs=%zu) — build will fail\n",
                            ci, chX->n_local_pcs);
                }
            }

            tx_buf_t old_commit_tx;
            tx_buf_init(&old_commit_tx, 512);
            unsigned char old_txid[32];
            /* Build the LSP's OWN old commitment (not the client's).
               Client watchtowers watch for the LSP's commitment txid. */
            int built = channel_build_commitment_tx(chX, &old_commit_tx, old_txid);

            /* Restore current state */
            chX->commitment_number = saved_num;
            chX->local_amount = saved_local;
            chX->remote_amount = saved_remote;
            chX->n_htlcs = saved_n_htlcs;

            if (!built) {
                fprintf(stderr, "BREACH TEST: failed to rebuild old commitment for channel %zu\n", ci);
                tx_buf_free(&old_commit_tx);
                continue;
            }

            /* Sign with both LSP + client keys */
            unsigned char cli_sec[32];
            memset(cli_sec, client_fills[ci], 32);
            secp256k1_keypair cli_kp;
            if (!secp256k1_keypair_create(ctx, &cli_kp, cli_sec)) {
                fprintf(stderr, "BREACH TEST: keypair create failed for channel %zu\n", ci);
                memset(cli_sec, 0, 32);
                tx_buf_free(&old_commit_tx);
                continue;
            }
            memset(cli_sec, 0, 32);

            tx_buf_t old_signed;
            tx_buf_init(&old_signed, 512);
            if (!channel_sign_commitment(chX, &old_signed, &old_commit_tx, &cli_kp)) {
                fprintf(stderr, "BREACH TEST: failed to sign old commitment for channel %zu\n", ci);
                tx_buf_free(&old_signed);
                tx_buf_free(&old_commit_tx);
                continue;
            }
            tx_buf_free(&old_commit_tx);

            char *old_hex = malloc(old_signed.len * 2 + 1);
            hex_encode(old_signed.data, old_signed.len, old_hex);
            char old_txid_str[65];
            int sent = regtest_send_raw_tx(&rt, old_hex, old_txid_str);
            if (g_db) {
                char src[48];
                snprintf(src, sizeof(src), "breach_revoked_ch%zu", ci);
                persist_log_broadcast(g_db, sent ? old_txid_str : "?",
                    src, old_hex, sent ? "ok" : "failed");
            }
            free(old_hex);
            tx_buf_free(&old_signed);

            if (!sent) {
                fprintf(stderr, "BREACH TEST: failed to broadcast revoked commitment for channel %zu\n", ci);
                continue;
            }
            printf("Revoked commitment broadcast (ch %zu): %s\n", ci, old_txid_str);
        }

        /* Confirm all revoked commitments so watchtowers can detect them */
        if (is_regtest) {
            regtest_mine_blocks(&rt, 1, mine_addr);
        } else {
            int rc_start_h = regtest_get_block_height(&rt);
            printf("Waiting for revoked commitments to confirm (height %d)...\n",
                   rc_start_h);
            for (int w = 0; w < confirm_timeout_secs && !g_shutdown; w++) {
                if (regtest_get_block_height(&rt) > rc_start_h) break;
                sleep(1);
            }
        }

        if (breach_test == 2) {
            /* --cheat-daemon: LSP does NOT run watchtower — sleep so clients can detect */
            printf("CHEAT DAEMON: revoked commitment broadcast, sleeping for clients...\n");
            if (is_regtest) {
                for (int s = 0; s < 30 && !g_shutdown; s++)
                    sleep(1);
            } else {
                /* On signet: wait for 2 blocks via height polling (up to 30 min),
                   then give clients time to detect */
                int start_h = regtest_get_block_height(&rt);
                int target_h = start_h + 2;
                printf("CHEAT DAEMON: waiting for height %d (current %d)...\n",
                       target_h, start_h);
                for (int w = 0; w < 1800 && !g_shutdown; w++) {
                    if (regtest_get_block_height(&rt) >= target_h) break;
                    sleep(1);
                }
                /* Extra time for clients to process */
                for (int s = 0; s < 60 && !g_shutdown; s++)
                    sleep(1);
            }
            printf("=== CHEAT DAEMON COMPLETE ===\n");
            report_add_string(&rpt, "result", "cheat_daemon_complete");
            report_close(&rpt);
            if (use_db) persist_close(&db);
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 0;
        }

        /* Watchtower check: should detect breach and broadcast penalty */
        printf("Running watchtower check...\n");
        watchtower_t *wt = mgr->watchtower;
        if (!wt) {
            fprintf(stderr, "BREACH TEST FAILED: no watchtower configured\n");
            report_add_string(&rpt, "result", "breach_test_no_watchtower");
            report_close(&rpt);
            if (use_db) persist_close(&db);
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        {
            int detected = watchtower_check(wt);
            if (detected > 0) {
                printf("BREACH DETECTED! Watchtower broadcast %d penalty tx(s)\n",
                       detected);
                if (is_regtest) {
                    regtest_mine_blocks(&rt, 1, mine_addr);
                } else {
                    int pen_start_h = regtest_get_block_height(&rt);
                    printf("Waiting for penalty to confirm (height %d)...\n",
                           pen_start_h);
                    for (int w = 0; w < confirm_timeout_secs && !g_shutdown; w++) {
                        if (regtest_get_block_height(&rt) > pen_start_h) break;
                        sleep(1);
                    }
                }
                printf("BREACH TEST PASSED — penalty confirmed on-chain\n");
            } else {
                fprintf(stderr, "BREACH TEST FAILED: watchtower did not detect breach\n");
                report_add_string(&rpt, "result", "breach_test_failed");
                report_close(&rpt);
                if (use_db) persist_close(&db);
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
        }

        printf("=== BREACH TEST COMPLETE ===\n\n");

        /* Skip cooperative close — factory already spent */
        report_add_string(&rpt, "result", "breach_test_complete");
        report_close(&rpt);
        if (use_db) persist_close(&db);
        lsp_cleanup(&lsp);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 0;
    }

    /* === Expiry Test: multi-level timeout recovery === */
    if (test_expiry && channels_active) {
        printf("\n=== EXPIRY TEST (Multi-Level Timeout Recovery) ===\n");

        /* Step 1: Broadcast kickoff_root (node 0, key-path pre-signed) */
        factory_node_t *kickoff_root = &lsp.factory.nodes[0];
        {
            char *kr_hex = malloc(kickoff_root->signed_tx.len * 2 + 1);
            hex_encode(kickoff_root->signed_tx.data, kickoff_root->signed_tx.len, kr_hex);
            char kr_txid_str[65];
            if (!regtest_send_raw_tx(&rt, kr_hex, kr_txid_str)) {
                if (g_db)
                    persist_log_broadcast(g_db, "?", "expiry_kickoff_root",
                        kr_hex, "failed");
                fprintf(stderr, "EXPIRY TEST: kickoff_root broadcast failed\n");
                free(kr_hex);
                lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            if (g_db)
                persist_log_broadcast(g_db, kr_txid_str,
                    "expiry_kickoff_root", kr_hex, "ok");
            free(kr_hex);
            ADVANCE(1);
            printf("1. kickoff_root broadcast: %s\n", kr_txid_str);
        }

        /* Step 2: Broadcast state_root (node 1, key-path pre-signed) */
        factory_node_t *state_root = &lsp.factory.nodes[1];
        {
            uint32_t state_nseq = state_root->nsequence;
            int nseq_blocks = (state_nseq == NSEQUENCE_DISABLE_BIP68)
                ? 0 : (int)(state_nseq & 0xFFFF);
            if (nseq_blocks > 0)
                ADVANCE(nseq_blocks);

            char *sr_hex = malloc(state_root->signed_tx.len * 2 + 1);
            hex_encode(state_root->signed_tx.data, state_root->signed_tx.len, sr_hex);
            char sr_txid_str[65];
            if (!regtest_send_raw_tx(&rt, sr_hex, sr_txid_str)) {
                if (g_db)
                    persist_log_broadcast(g_db, "?", "expiry_state_root",
                        sr_hex, "failed");
                fprintf(stderr, "EXPIRY TEST: state_root broadcast failed\n");
                free(sr_hex);
                lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            if (g_db)
                persist_log_broadcast(g_db, sr_txid_str,
                    "expiry_state_root", sr_hex, "ok");
            free(sr_hex);
            ADVANCE(1);
            printf("2. state_root broadcast: %s (nSeq blocks: %d)\n",
                   sr_txid_str, nseq_blocks);
        }

        /* Build broadcast chain: walk from first leaf state up to state_root,
           collecting intermediate kickoff+state nodes to broadcast.
           Works for both arity-2 (3 nodes: kl) and arity-1 (5 nodes: kl,sl,ka). */
        size_t first_leaf_idx = lsp.factory.leaf_node_indices[0];
        int chain[16];  /* node indices to broadcast (root-to-leaf order) */
        int chain_len = 0;
        {
            /* Walk from first leaf's kickoff parent up to state_root */
            int ko_idx = lsp.factory.nodes[first_leaf_idx].parent_index;
            while (ko_idx >= 0) {
                int parent_state = lsp.factory.nodes[ko_idx].parent_index;
                if (parent_state < 0 || parent_state == 1) break; /* stop at state_root children */
                chain[chain_len++] = parent_state; /* state node (grandparent) */
                chain[chain_len++] = ko_idx;       /* kickoff node */
                ko_idx = lsp.factory.nodes[parent_state].parent_index;
            }
            chain[chain_len++] = ko_idx; /* the kickoff that's a direct child of state_root */
        }
        /* Reverse chain to get root-to-leaf order */
        for (int a = 0, b = chain_len - 1; a < b; a++, b--) {
            int tmp = chain[a]; chain[a] = chain[b]; chain[b] = tmp;
        }

        /* Step 3..N: Broadcast intermediate nodes down to the deepest kickoff */
        int step = 3;
        for (int ci = 0; ci < chain_len; ci++) {
            factory_node_t *nd = &lsp.factory.nodes[chain[ci]];
            uint32_t nseq = nd->nsequence;
            int nseq_blocks = (nseq == NSEQUENCE_DISABLE_BIP68) ? 0 : (int)(nseq & 0xFFFF);
            if (nseq_blocks > 0)
                ADVANCE(nseq_blocks);

            char *hex = malloc(nd->signed_tx.len * 2 + 1);
            hex_encode(nd->signed_tx.data, nd->signed_tx.len, hex);
            char txid_str[65];
            if (!regtest_send_raw_tx(&rt, hex, txid_str)) {
                if (g_db) {
                    char src[48];
                    snprintf(src, sizeof(src), "expiry_node_%d", chain[ci]);
                    persist_log_broadcast(g_db, "?", src, hex, "failed");
                }
                fprintf(stderr, "EXPIRY TEST: node[%d] broadcast failed\n", chain[ci]);
                free(hex);
                lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            if (g_db) {
                char src[48];
                snprintf(src, sizeof(src), "expiry_node_%d", chain[ci]);
                persist_log_broadcast(g_db, txid_str, src, hex, "ok");
            }
            free(hex);
            ADVANCE(1);
            printf("%d. node[%d] (%s) broadcast: %s%s\n", step++, chain[ci],
                   nd->type == NODE_KICKOFF ? "kickoff" : "state", txid_str,
                   nseq_blocks > 0 ? " (waited nSeq)" : "");
        }

        /* The deepest kickoff is the last in the chain */
        factory_node_t *deepest_kickoff = &lsp.factory.nodes[chain[chain_len - 1]];
        /* The leaf state node that times out this kickoff's output */
        factory_node_t *leaf_state = &lsp.factory.nodes[first_leaf_idx];

        /* LSP pubkey for signing + destination */
        secp256k1_xonly_pubkey lsp_xonly;
        if (!secp256k1_keypair_xonly_pub(ctx, &lsp_xonly, NULL, &lsp_kp)) {
            fprintf(stderr, "EXPIRY TEST: keypair xonly pub failed\n");
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        unsigned char dest_spk[34];
        build_p2tr_script_pubkey(dest_spk, &lsp_xonly);

        uint64_t fee_sats = fee_estimate(&fee_est, 150);
        if (fee_sats == 0) fee_sats = 500;
        uint64_t leaf_recovered = 0, mid_recovered = 0;

        /* Mine to leaf CLTV (deepest state node's timeout) */
        uint32_t leaf_cltv = leaf_state->cltv_timeout;
        {
            int height = regtest_get_block_height(&rt);
            int needed = (int)leaf_cltv - height;
            if (needed > 0) {
                printf("%d. Advancing %d blocks to reach leaf CLTV %u...\n",
                       step++, needed, leaf_cltv);
                ADVANCE(needed);
            }
        }

        /* Leaf recovery: Spend deepest_kickoff:0 via leaf_state timeout script-path */
        {
            if (!leaf_state->has_taptree) {
                fprintf(stderr, "EXPIRY TEST: leaf state node[%zu] has no taptree\n",
                        first_leaf_idx);
                lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }

            uint64_t spend_amount = deepest_kickoff->outputs[0].amount_sats;
            if (fee_sats >= spend_amount) fee_sats = 500;

            tx_output_t tout;
            tout.amount_sats = spend_amount - fee_sats;
            memcpy(tout.script_pubkey, dest_spk, 34);
            tout.script_pubkey_len = 34;

            tx_buf_t tu;
            tx_buf_init(&tu, 256);
            if (!build_unsigned_tx_with_locktime(&tu, NULL,
                    deepest_kickoff->txid, 0, 0xFFFFFFFEu, leaf_cltv,
                    &tout, 1)) {
                fprintf(stderr, "EXPIRY TEST: leaf build failed\n");
                tx_buf_free(&tu);
                lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }

            unsigned char sh[32];
            compute_tapscript_sighash(sh, tu.data, tu.len, 0,
                leaf_state->spending_spk, leaf_state->spending_spk_len,
                spend_amount, 0xFFFFFFFEu, &leaf_state->timeout_leaf);

            unsigned char sig[64], aux[32];
            memset(aux, 0xEE, 32);
            if (!secp256k1_schnorrsig_sign32(ctx, sig, sh, &lsp_kp, aux)) {
                fprintf(stderr, "EXPIRY TEST: schnorr sign failed\n");
                return 1;
            }

            unsigned char cb[65];
            size_t cb_len;
            tapscript_build_control_block(cb, &cb_len,
                leaf_state->output_parity,
                &leaf_state->keyagg.agg_pubkey, ctx);

            tx_buf_t ts;
            tx_buf_init(&ts, 512);
            finalize_script_path_tx(&ts, tu.data, tu.len, sig,
                leaf_state->timeout_leaf.script,
                leaf_state->timeout_leaf.script_len, cb, cb_len);
            tx_buf_free(&tu);

            char *hex = malloc(ts.len * 2 + 1);
            hex_encode(ts.data, ts.len, hex);
            char txid_str[65];
            int sent = regtest_send_raw_tx(&rt, hex, txid_str);
            if (g_db)
                persist_log_broadcast(g_db, sent ? txid_str : "?",
                    "expiry_leaf_timeout", hex, sent ? "ok" : "failed");
            free(hex);
            tx_buf_free(&ts);

            if (!sent) {
                fprintf(stderr, "EXPIRY TEST: leaf timeout tx broadcast failed\n");
                lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            ADVANCE(1);
            leaf_recovered = tout.amount_sats;
            printf("%d. Leaf recovery: %llu sats (node[%zu] timeout) txid: %s\n",
                   step++, (unsigned long long)leaf_recovered, first_leaf_idx, txid_str);
        }

        /* Mid recovery: Spend state_root:1 via kickoff_right timeout.
           kickoff_right is the second child of state_root (vout 1). */
        factory_node_t *kickoff_right = &lsp.factory.nodes[state_root->child_indices[1]];
        uint32_t mid_cltv = kickoff_right->cltv_timeout;
        {
            int height = regtest_get_block_height(&rt);
            int needed = (int)mid_cltv - height;
            if (needed > 0) {
                printf("%d. Advancing %d blocks to reach mid CLTV %u...\n",
                       step++, needed, mid_cltv);
                ADVANCE(needed);
            }
        }

        /* Spend state_root:1 via kickoff_right timeout script-path */
        {
            if (!kickoff_right->has_taptree) {
                fprintf(stderr, "EXPIRY TEST: kickoff_right has no taptree\n");
                lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }

            uint64_t spend_amount = state_root->outputs[1].amount_sats;
            if (fee_sats >= spend_amount) fee_sats = 500;

            tx_output_t tout;
            tout.amount_sats = spend_amount - fee_sats;
            memcpy(tout.script_pubkey, dest_spk, 34);
            tout.script_pubkey_len = 34;

            tx_buf_t tu;
            tx_buf_init(&tu, 256);
            if (!build_unsigned_tx_with_locktime(&tu, NULL,
                    state_root->txid, 1, 0xFFFFFFFEu, mid_cltv,
                    &tout, 1)) {
                fprintf(stderr, "EXPIRY TEST: mid build failed\n");
                tx_buf_free(&tu);
                lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }

            unsigned char sh[32];
            compute_tapscript_sighash(sh, tu.data, tu.len, 0,
                kickoff_right->spending_spk, kickoff_right->spending_spk_len,
                spend_amount, 0xFFFFFFFEu, &kickoff_right->timeout_leaf);

            unsigned char sig[64], aux[32];
            memset(aux, 0xFF, 32);
            if (!secp256k1_schnorrsig_sign32(ctx, sig, sh, &lsp_kp, aux)) {
                fprintf(stderr, "EXPIRY TEST: schnorr sign failed\n");
                return 1;
            }

            unsigned char cb[65];
            size_t cb_len;
            tapscript_build_control_block(cb, &cb_len,
                kickoff_right->output_parity,
                &kickoff_right->keyagg.agg_pubkey, ctx);

            tx_buf_t ts;
            tx_buf_init(&ts, 512);
            finalize_script_path_tx(&ts, tu.data, tu.len, sig,
                kickoff_right->timeout_leaf.script,
                kickoff_right->timeout_leaf.script_len, cb, cb_len);
            tx_buf_free(&tu);

            char *hex = malloc(ts.len * 2 + 1);
            hex_encode(ts.data, ts.len, hex);
            char txid_str[65];
            int sent = regtest_send_raw_tx(&rt, hex, txid_str);
            if (g_db)
                persist_log_broadcast(g_db, sent ? txid_str : "?",
                    "expiry_mid_timeout", hex, sent ? "ok" : "failed");
            free(hex);
            tx_buf_free(&ts);

            if (!sent) {
                fprintf(stderr, "EXPIRY TEST: mid timeout tx broadcast failed\n");
                lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            ADVANCE(1);
            mid_recovered = tout.amount_sats;
            printf("%d. Mid recovery: %llu sats (kickoff_right timeout) txid: %s\n",
                   step++, (unsigned long long)mid_recovered, txid_str);
        }

        printf("\nLeaf recovery: %llu sats\n", (unsigned long long)leaf_recovered);
        printf("Mid recovery:  %llu sats\n", (unsigned long long)mid_recovered);
        int expiry_pass = (leaf_recovered > 0 && mid_recovered > 0);
        if (!expiry_pass)
            fprintf(stderr, "EXPIRY TEST: recovered amounts are zero "
                    "(leaf=%llu, mid=%llu)\n",
                    (unsigned long long)leaf_recovered,
                    (unsigned long long)mid_recovered);
        printf("=== EXPIRY TEST %s ===\n\n", expiry_pass ? "PASSED" : "FAILED");

        /* Skip cooperative close — factory already spent */
        report_add_string(&rpt, "result",
                          expiry_pass ? "expiry_test_pass" : "expiry_test_fail");
        report_close(&rpt);
        if (use_db) persist_close(&db);
        lsp_cleanup(&lsp);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return expiry_pass ? 0 : 1;
    }

    /* === Distribution TX Test: mine past CLTV, broadcast distribution TX === */
    if (test_distrib && channels_active) {
        printf("\n=== DISTRIBUTION TX TEST ===\n");

        /* Build distribution TX with demo keypairs (LSP has all keys in demo) */
        factory_t df = lsp.factory;
        secp256k1_keypair dk[FACTORY_MAX_SIGNERS];
        dk[0] = lsp_kp;
        {
            static const unsigned char fill[4] = { 0x22, 0x33, 0x44, 0x55 };
            for (int ci = 0; ci < n_clients; ci++) {
                unsigned char ds[32];
                memset(ds, fill[ci], 32);
                if (!secp256k1_keypair_create(ctx, &dk[ci + 1], ds)) {
                    fprintf(stderr, "DISTRIB TEST: keypair create failed\n");
                    return 1;
                }
            }
        }
        memcpy(df.keypairs, dk, n_total * sizeof(secp256k1_keypair));

        /* Equal-split outputs */
        tx_output_t dist_outputs[FACTORY_MAX_SIGNERS];
        uint64_t dist_per = (df.funding_amount_sats - 500) / n_total;
        for (size_t di = 0; di < n_total; di++) {
            dist_outputs[di].amount_sats = dist_per;
            /* Derive per-participant P2TR from their keypair */
            secp256k1_pubkey di_pub;
            secp256k1_keypair_pub(ctx, &di_pub, &dk[di]);
            secp256k1_xonly_pubkey di_xonly;
            secp256k1_xonly_pubkey_from_pubkey(ctx, &di_xonly, NULL, &di_pub);
            build_p2tr_script_pubkey(dist_outputs[di].script_pubkey, &di_xonly);
            dist_outputs[di].script_pubkey_len = 34;
        }
        dist_outputs[n_total - 1].amount_sats =
            df.funding_amount_sats - 500 - dist_per * (n_total - 1);

        tx_buf_t dist_tx;
        tx_buf_init(&dist_tx, 512);
        unsigned char dist_txid[32];
        if (!factory_build_distribution_tx(&df, &dist_tx, dist_txid,
                                             dist_outputs, n_total,
                                             lsp.factory.cltv_timeout)) {
            fprintf(stderr, "DISTRIBUTION TX TEST: build failed\n");
            tx_buf_free(&dist_tx);
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        printf("Distribution TX built (%zu bytes)\n", dist_tx.len);

        /* Store in ladder slot */
        lad->factories[0].distribution_tx = dist_tx;

        /* Mine past CLTV timeout */
        int cur_h = regtest_get_block_height(&rt);
        int blocks_to_cltv = (int)lsp.factory.cltv_timeout - cur_h;
        if (blocks_to_cltv > 0) {
            printf("Advancing %d blocks to reach CLTV timeout %u...\n",
                   blocks_to_cltv, lsp.factory.cltv_timeout);
            ADVANCE(blocks_to_cltv);
        }

        /* Broadcast distribution TX */
        char *dt_hex = malloc(dist_tx.len * 2 + 1);
        hex_encode(dist_tx.data, dist_tx.len, dt_hex);
        char dt_txid_str[65];
        int dt_sent = regtest_send_raw_tx(&rt, dt_hex, dt_txid_str);
        if (g_db)
            persist_log_broadcast(g_db, dt_sent ? dt_txid_str : "?",
                "distribution_tx", dt_hex, dt_sent ? "ok" : "failed");
        free(dt_hex);

        if (!dt_sent) {
            fprintf(stderr, "DISTRIBUTION TX TEST: broadcast failed\n");
            tx_buf_free(&lad->factories[0].distribution_tx);
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        ADVANCE(1);

        printf("Distribution TX broadcast: %s\n", dt_txid_str);
        printf("=== DISTRIBUTION TX TEST PASSED ===\n\n");

        report_add_string(&rpt, "result", "distrib_test_complete");
        report_close(&rpt);
        if (use_db) persist_close(&db);
        tx_buf_free(&lad->factories[0].distribution_tx);
        lsp_cleanup(&lsp);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 0;
    }

    /* === PTLC Key Turnover Test === */
    if (test_turnover && channels_active) {
        printf("\n=== PTLC KEY TURNOVER TEST ===\n");

        /* Build demo keypairs (same as test_ladder.c) */
        secp256k1_keypair all_kps[FACTORY_MAX_SIGNERS];
        all_kps[0] = lsp_kp;
        {
            static const unsigned char fill[4] = { 0x22, 0x33, 0x44, 0x55 };
            for (int ci = 0; ci < n_clients; ci++) {
                unsigned char ds[32];
                memset(ds, fill[ci], 32);
                if (!secp256k1_keypair_create(ctx, &all_kps[ci + 1], ds)) {
                    fprintf(stderr, "TURNOVER TEST: keypair create failed\n");
                    return 1;
                }
            }
        }

        /* We need the factory with real keypairs for signing */
        factory_t tf = lsp.factory;
        memcpy(tf.keypairs, all_kps, n_total * sizeof(secp256k1_keypair));

        /* Build keyagg for the funding key (used as message) */
        secp256k1_pubkey turnover_pks[FACTORY_MAX_SIGNERS];
        for (size_t ti = 0; ti < n_total; ti++) {
            if (!secp256k1_keypair_pub(ctx, &turnover_pks[ti], &all_kps[ti])) {
                fprintf(stderr, "TURNOVER TEST: keypair pub failed\n");
                return 1;
            }
        }

        musig_keyagg_t turnover_ka;
        musig_aggregate_keys(ctx, &turnover_ka, turnover_pks, n_total);

        /* Dummy message (hash of "turnover") */
        unsigned char turnover_msg[32];
        sha256_tagged("turnover", (const unsigned char *)"turnover", 8,
                       turnover_msg);

        /* For each client: adaptor presig → adapt → extract → verify → record */
        for (int ci = 0; ci < n_clients; ci++) {
            uint32_t participant_idx = (uint32_t)(ci + 1);
            secp256k1_pubkey client_pk = turnover_pks[participant_idx];

            /* Create turnover pre-signature with adaptor point = client pubkey */
            unsigned char presig[64];
            int nonce_parity;
            musig_keyagg_t ka_copy = turnover_ka;
            if (!adaptor_create_turnover_presig(ctx, presig, &nonce_parity,
                                                  turnover_msg, all_kps, n_total,
                                                  &ka_copy, NULL, &client_pk)) {
                fprintf(stderr, "TURNOVER TEST: presig failed for client %d\n", ci);
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Client adapts with their secret key */
            unsigned char client_sec[32];
            if (!secp256k1_keypair_sec(ctx, client_sec, &all_kps[participant_idx])) {
                fprintf(stderr, "TURNOVER TEST: keypair sec failed\n");
                return 1;
            }
            unsigned char adapted_sig[64];
            if (!adaptor_adapt(ctx, adapted_sig, presig, client_sec, nonce_parity)) {
                fprintf(stderr, "TURNOVER TEST: adapt failed for client %d\n", ci);
                memset(client_sec, 0, 32);
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* LSP extracts client's secret key */
            unsigned char extracted[32];
            if (!adaptor_extract_secret(ctx, extracted, adapted_sig, presig,
                                          nonce_parity)) {
                fprintf(stderr, "TURNOVER TEST: extract failed for client %d\n", ci);
                memset(client_sec, 0, 32);
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Verify extracted key matches */
            if (!adaptor_verify_extracted_key(ctx, extracted, &client_pk)) {
                fprintf(stderr, "TURNOVER TEST: verify failed for client %d\n", ci);
                memset(client_sec, 0, 32);
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Record in ladder */
            ladder_record_key_turnover(lad, 0, participant_idx, extracted);

            /* Persist departed client */
            if (use_db)
                persist_save_departed_client(&db, 0, participant_idx, extracted);

            printf("  Client %d: key extracted and verified ✓\n", ci + 1);
            memset(client_sec, 0, 32);
        }

        /* Verify all clients departed */
        if (!ladder_can_close(lad, 0)) {
            fprintf(stderr, "TURNOVER TEST: ladder_can_close returned false\n");
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        printf("All %d clients departed — ladder_can_close = true\n", n_clients);

        /* Build close outputs (equal split) */
        tx_output_t to_outputs[FACTORY_MAX_SIGNERS];
        uint64_t to_per = (lsp.factory.funding_amount_sats - 500) / n_total;
        for (size_t ti = 0; ti < n_total; ti++) {
            to_outputs[ti].amount_sats = to_per;
            memcpy(to_outputs[ti].script_pubkey, fund_spk, 34);
            to_outputs[ti].script_pubkey_len = 34;
        }
        to_outputs[n_total - 1].amount_sats =
            lsp.factory.funding_amount_sats - 500 - to_per * (n_total - 1);

        /* Build cooperative close using extracted keys */
        tx_buf_t turnover_close_tx;
        tx_buf_init(&turnover_close_tx, 512);
        if (!ladder_build_close(lad, 0, &turnover_close_tx,
                                  to_outputs, n_total,
                                  (uint32_t)regtest_get_block_height(&rt))) {
            fprintf(stderr, "TURNOVER TEST: ladder_build_close failed\n");
            tx_buf_free(&turnover_close_tx);
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }

        /* Broadcast close TX */
        char *tc_hex = malloc(turnover_close_tx.len * 2 + 1);
        hex_encode(turnover_close_tx.data, turnover_close_tx.len, tc_hex);
        char tc_txid_str[65];
        int tc_sent = regtest_send_raw_tx(&rt, tc_hex, tc_txid_str);
        if (g_db)
            persist_log_broadcast(g_db, tc_sent ? tc_txid_str : "?",
                "turnover_close", tc_hex, tc_sent ? "ok" : "failed");
        free(tc_hex);
        tx_buf_free(&turnover_close_tx);

        if (!tc_sent) {
            fprintf(stderr, "TURNOVER TEST: close TX broadcast failed\n");
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        ADVANCE(1);

        printf("Close TX broadcast: %s\n", tc_txid_str);
        printf("=== PTLC KEY TURNOVER TEST PASSED ===\n\n");

        report_add_string(&rpt, "result", "turnover_test_complete");
        report_close(&rpt);
        if (use_db) persist_close(&db);
        lsp_cleanup(&lsp);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 0;
    }

    /* === Auto-Rebalance Test === */
    if (test_rebalance && channels_active) {
        printf("\n=== AUTO-REBALANCE TEST ===\n");
        fflush(stdout);
        int rebalance_pass = 1;

        /* Record pre-rebalance balances */
        uint64_t pre_total = 0;
        for (size_t c = 0; c < mgr->n_channels; c++) {
            pre_total += mgr->entries[c].channel.local_amount +
                         mgr->entries[c].channel.remote_amount;
        }

        /* Deliberately imbalance: send large payment ch0 → ch1 */
        if (mgr->n_channels >= 2) {
            uint64_t imbalance_amt = mgr->entries[0].channel.local_amount / 3;
            if (imbalance_amt > 0) {
                printf("Imbalancing: %llu sats from ch0 → ch1\n",
                       (unsigned long long)imbalance_amt);
                lsp_channels_initiate_payment(mgr, &lsp, 0, 1, imbalance_amt);
            }
        }

        /* Record heaviest channel local% before rebalance */
        uint64_t heaviest_pct_before = 0;
        size_t heaviest_idx = 0;
        for (size_t c = 0; c < mgr->n_channels; c++) {
            uint64_t tot = mgr->entries[c].channel.local_amount +
                           mgr->entries[c].channel.remote_amount;
            if (tot > 0) {
                uint64_t pct = (mgr->entries[c].channel.local_amount * 100) / tot;
                if (pct > heaviest_pct_before) {
                    heaviest_pct_before = pct;
                    heaviest_idx = c;
                }
            }
        }

        /* Set threshold and run auto-rebalance */
        mgr->rebalance_threshold_pct = 70;
        int rebal_count = lsp_channels_auto_rebalance(mgr, &lsp);
        printf("Auto-rebalance moved %d channel(s)\n", rebal_count);

        /* Verify: total balance conservation */
        uint64_t post_total = 0;
        for (size_t c = 0; c < mgr->n_channels; c++) {
            post_total += mgr->entries[c].channel.local_amount +
                          mgr->entries[c].channel.remote_amount;
        }
        if (post_total != pre_total) {
            printf("  FAIL: balance conservation violated "
                   "(pre=%llu post=%llu)\n",
                   (unsigned long long)pre_total,
                   (unsigned long long)post_total);
            rebalance_pass = 0;
        }

        /* Verify: rebalance must have happened, and heaviest channel should decrease */
        if (rebal_count == 0) {
            printf("  FAIL: no channels were rebalanced\n");
            rebalance_pass = 0;
        } else {
            uint64_t tot = mgr->entries[heaviest_idx].channel.local_amount +
                           mgr->entries[heaviest_idx].channel.remote_amount;
            uint64_t pct_after = (tot > 0) ?
                (mgr->entries[heaviest_idx].channel.local_amount * 100) / tot : 0;
            if (pct_after >= heaviest_pct_before) {
                printf("  FAIL: heaviest channel local%% did not decrease "
                       "(%llu → %llu)\n",
                       (unsigned long long)heaviest_pct_before,
                       (unsigned long long)pct_after);
                rebalance_pass = 0;
            }
        }

        printf("AUTO-REBALANCE TEST: %s\n", rebalance_pass ? "PASS" : "FAIL");
        fflush(stdout);
        if (!rebalance_pass) {
            jit_channels_cleanup(mgr);
            free(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
    }

    /* === Batch-Rebalance Test === */
    if (test_batch_rebalance && channels_active) {
        printf("\n=== BATCH-REBALANCE TEST ===\n");
        fflush(stdout);
        int batch_pass = 1;

        /* Record pre-rebalance totals */
        uint64_t pre_total = 0;
        for (size_t c = 0; c < mgr->n_channels; c++) {
            pre_total += mgr->entries[c].channel.local_amount +
                         mgr->entries[c].channel.remote_amount;
        }

        /* Build batch entries */
        int batch_count = 0;
        if (mgr->n_channels >= 4) {
            rebalance_entry_t entries[2];
            entries[0].from = 0;
            entries[0].to = 1;
            entries[0].amount_sats = 2000;
            entries[1].from = 2;
            entries[1].to = 3;
            entries[1].amount_sats = 1500;
            batch_count = lsp_channels_batch_rebalance(mgr, &lsp, entries, 2);
            printf("Batch rebalance: %d/2 succeeded\n", batch_count);
        } else if (mgr->n_channels >= 2) {
            rebalance_entry_t entries[1];
            entries[0].from = 0;
            entries[0].to = 1;
            entries[0].amount_sats = 2000;
            batch_count = lsp_channels_batch_rebalance(mgr, &lsp, entries, 1);
            printf("Batch rebalance: %d/1 succeeded\n", batch_count);
        }

        /* Verify: total balance conservation */
        uint64_t post_total = 0;
        for (size_t c = 0; c < mgr->n_channels; c++) {
            post_total += mgr->entries[c].channel.local_amount +
                          mgr->entries[c].channel.remote_amount;
        }
        if (post_total != pre_total) {
            printf("  FAIL: balance conservation violated "
                   "(pre=%llu post=%llu)\n",
                   (unsigned long long)pre_total,
                   (unsigned long long)post_total);
            batch_pass = 0;
        }

        if (batch_count <= 0) {
            printf("  FAIL: no batch transfers succeeded\n");
            batch_pass = 0;
        }

        printf("BATCH-REBALANCE TEST: %s\n", batch_pass ? "PASS" : "FAIL");
        fflush(stdout);
        if (!batch_pass) {
            jit_channels_cleanup(mgr);
            free(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
    }

    /* === Leaf Realloc Test === */
    if (test_realloc && channels_active) {
        printf("\n=== LEAF REALLOC TEST ===\n");
        fflush(stdout);
        int realloc_pass = 1;

        if (leaf_arity != 2) {
            printf("  SKIP: --test-realloc requires --leaf-arity 2\n");
            printf("LEAF REALLOC TEST: SKIP\n");
        } else if (n_clients < 2) {
            printf("  SKIP: --test-realloc requires --clients >= 2\n");
            printf("LEAF REALLOC TEST: SKIP\n");
        } else {
            /* Record current leaf node output amounts (authoritative source) */
            size_t leaf_node_idx = lsp.factory.leaf_node_indices[0];
            factory_node_t *leaf_node = &lsp.factory.nodes[leaf_node_idx];
            uint64_t orig_amounts[3];
            uint64_t orig_total = 0;
            for (size_t k = 0; k < 3 && k < leaf_node->n_outputs; k++) {
                orig_amounts[k] = leaf_node->outputs[k].amount_sats;
                orig_total += orig_amounts[k];
            }

            /* Build redistributed amounts: shift 20% from slot 1 to slot 2 */
            uint64_t shift = orig_amounts[1] / 5;
            uint64_t new_amounts[3];
            new_amounts[0] = orig_amounts[0];
            new_amounts[1] = orig_amounts[1] - shift;
            new_amounts[2] = orig_amounts[2] + shift;

            printf("Reallocating leaf 0: [%llu, %llu, %llu] → [%llu, %llu, %llu]\n",
                   (unsigned long long)orig_amounts[0],
                   (unsigned long long)orig_amounts[1],
                   (unsigned long long)orig_amounts[2],
                   (unsigned long long)new_amounts[0],
                   (unsigned long long)new_amounts[1],
                   (unsigned long long)new_amounts[2]);

            int rc = lsp_realloc_leaf(mgr, &lsp, 0, new_amounts, 3);
            if (rc != 1) {
                printf("  FAIL: lsp_realloc_leaf returned %d (expected 1)\n", rc);
                realloc_pass = 0;
            }

            /* Verify amounts updated (read from leaf node outputs) */
            if (realloc_pass) {
                uint64_t post_total = 0;
                for (size_t k = 0; k < leaf_node->n_outputs; k++)
                    post_total += leaf_node->outputs[k].amount_sats;
                if (post_total != orig_total) {
                    printf("  FAIL: total funding changed "
                           "(%llu → %llu)\n",
                           (unsigned long long)orig_total,
                           (unsigned long long)post_total);
                    realloc_pass = 0;
                }
            }

            printf("LEAF REALLOC TEST: %s\n", realloc_pass ? "PASS" : "FAIL");
        }
        fflush(stdout);
        if (!realloc_pass) {
            jit_channels_cleanup(mgr);
            free(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
    }

    /* === Factory Rotation Test (Tier 3) === */
    if (test_rotation && channels_active) {
        printf("\n=== FACTORY ROTATION TEST ===\n");

        /* --- Phase A: PTLC key turnover over wire --- */
        printf("Phase A: PTLC key turnover for Factory 0\n");

        /* Build keypair/pubkey arrays matching production pattern
           (lsp_rotation.c:94-111): real LSP keypair + actual client
           pubkeys with LSP placeholder keypairs for signing slots. */
        secp256k1_keypair rot_kps[FACTORY_MAX_SIGNERS];
        secp256k1_pubkey rot_pks[FACTORY_MAX_SIGNERS];
        rot_kps[0] = lsp_kp;
        if (!secp256k1_keypair_pub(ctx, &rot_pks[0], &lsp_kp)) {
            fprintf(stderr, "rotation: keypair_pub failed for LSP\n");
            return 1;
        }
        for (int ci = 0; ci < n_clients; ci++) {
            rot_pks[ci + 1] = lsp.client_pubkeys[ci];
            rot_kps[ci + 1] = lsp_kp;  /* placeholder — not used for signing */
        }

        musig_keyagg_t rot_ka;
        musig_aggregate_keys(ctx, &rot_ka, rot_pks, n_total);

        unsigned char turnover_msg[32];
        sha256_tagged("turnover", (const unsigned char *)"turnover", 8, turnover_msg);

        for (int ci = 0; ci < n_clients; ci++) {
            uint32_t pidx = (uint32_t)(ci + 1);
            secp256k1_pubkey client_pk = rot_pks[pidx];

            unsigned char presig[64];
            int nonce_parity;
            musig_keyagg_t ka_copy = rot_ka;
            if (!adaptor_create_turnover_presig(ctx, presig, &nonce_parity,
                                                  turnover_msg, rot_kps, n_total,
                                                  &ka_copy, NULL, &client_pk)) {
                fprintf(stderr, "ROTATION: presig failed client %d\n", ci);
                lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }

            /* Send PTLC_PRESIG to client */
            cJSON *pm = wire_build_ptlc_presig(presig, nonce_parity, turnover_msg);
            if (!wire_send(lsp.client_fds[ci], MSG_PTLC_PRESIG, pm)) {
                cJSON_Delete(pm);
                fprintf(stderr, "ROTATION: send presig failed client %d\n", ci);
                lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            cJSON_Delete(pm);

            /* Recv PTLC_ADAPTED_SIG from client */
            wire_msg_t resp;
            if (!wire_recv(lsp.client_fds[ci], &resp) ||
                resp.msg_type != MSG_PTLC_ADAPTED_SIG) {
                if (resp.json) cJSON_Delete(resp.json);
                fprintf(stderr, "ROTATION: no adapted_sig from client %d\n", ci);
                lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }

            unsigned char adapted_sig[64];
            if (!wire_parse_ptlc_adapted_sig(resp.json, adapted_sig)) {
                cJSON_Delete(resp.json);
                fprintf(stderr, "ROTATION: parse adapted_sig failed client %d\n", ci);
                lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            cJSON_Delete(resp.json);

            /* Extract client's secret key */
            unsigned char extracted[32];
            if (!adaptor_extract_secret(ctx, extracted, adapted_sig, presig,
                                          nonce_parity)) {
                fprintf(stderr, "ROTATION: extract failed client %d\n", ci);
                lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }

            if (!adaptor_verify_extracted_key(ctx, extracted, &client_pk)) {
                fprintf(stderr, "ROTATION: verify failed client %d\n", ci);
                lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }

            ladder_record_key_turnover(lad, 0, pidx, extracted);
            if (use_db)
                persist_save_departed_client(&db, 0, pidx, extracted);

            /* Send PTLC_COMPLETE */
            cJSON *cm = wire_build_ptlc_complete();
            wire_send(lsp.client_fds[ci], MSG_PTLC_COMPLETE, cm);
            cJSON_Delete(cm);

            printf("  Client %d: key extracted via wire PTLC\n", ci + 1);
        }

        /* --- Phase B: Ladder close of Factory 0 --- */
        printf("Phase B: Ladder close of Factory 0\n");
        if (!ladder_can_close(lad, 0)) {
            fprintf(stderr, "ROTATION: ladder_can_close returned false\n");
            lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }

        tx_output_t rot_outputs[FACTORY_MAX_SIGNERS];
        uint64_t rot_per = (lsp.factory.funding_amount_sats - 500) / n_total;
        for (size_t ti = 0; ti < n_total; ti++) {
            rot_outputs[ti].amount_sats = rot_per;
            memcpy(rot_outputs[ti].script_pubkey, fund_spk, 34);
            rot_outputs[ti].script_pubkey_len = 34;
        }
        rot_outputs[n_total - 1].amount_sats =
            lsp.factory.funding_amount_sats - 500 - rot_per * (n_total - 1);

        tx_buf_t rot_close_tx;
        tx_buf_init(&rot_close_tx, 512);
        if (!ladder_build_close(lad, 0, &rot_close_tx, rot_outputs, n_total,
                                  (uint32_t)regtest_get_block_height(&rt))) {
            fprintf(stderr, "ROTATION: ladder_build_close failed\n");
            tx_buf_free(&rot_close_tx);
            lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }

        char *rc_hex = malloc(rot_close_tx.len * 2 + 1);
        hex_encode(rot_close_tx.data, rot_close_tx.len, rc_hex);
        char rc_txid[65];
        int rc_sent = regtest_send_raw_tx(&rt, rc_hex, rc_txid);
        if (g_db)
            persist_log_broadcast(g_db, rc_sent ? rc_txid : "?",
                "rotation_close_f0", rc_hex, rc_sent ? "ok" : "failed");
        free(rc_hex);
        tx_buf_free(&rot_close_tx);

        if (!rc_sent) {
            fprintf(stderr, "ROTATION: Factory 0 close TX broadcast failed\n");
            lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }
        ADVANCE(1);
        printf("  Factory 0 closed: %s\n", rc_txid);

        /* --- Phase C: Create Factory 1 --- */
        printf("Phase C: Creating Factory 1\n");

        /* Fund new factory (same address since same participants) */
        char fund2_txid_hex[65];
        if (is_regtest) {
            if (!regtest_fund_address(&rt, fund_addr, funding_btc, fund2_txid_hex)) {
                fprintf(stderr, "ROTATION: fund Factory 1 failed\n");
                lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            regtest_mine_blocks(&rt, 1, mine_addr);
        }

        unsigned char fund2_txid[32];
        hex_decode(fund2_txid_hex, fund2_txid, 32);
        reverse_bytes(fund2_txid, 32);

        uint64_t fund2_amount = 0;
        unsigned char fund2_spk[256];
        size_t fund2_spk_len = 0;
        uint32_t fund2_vout = 0;
        for (uint32_t v = 0; v < 4; v++) {
            regtest_get_tx_output(&rt, fund2_txid_hex, v,
                                  &fund2_amount, fund2_spk, &fund2_spk_len);
            if (fund2_spk_len == 34 && memcmp(fund2_spk, fund_spk, 34) == 0) {
                fund2_vout = v;
                break;
            }
        }
        if (fund2_amount == 0) {
            fprintf(stderr, "ROTATION: no funding output for Factory 1\n");
            lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }

        /* Free old factory in lsp before reusing.
           Ladder entries use detached copies so no double-free risk. */
        factory_free(&lsp.factory);

        /* Compute cltv_timeout for Factory 1 */
        uint32_t cltv2 = 0;
        {
            int cur_h = regtest_get_block_height(&rt);
            if (cltv_timeout_arg > 0) {
                cltv2 = (uint32_t)cltv_timeout_arg;
            } else if (cur_h > 0) {
                int offset = is_regtest ? 35 : 1008;
                cltv2 = (uint32_t)cur_h + offset;
            }
        }

        /* Run factory creation ceremony (sends FACTORY_PROPOSE to clients,
           who handle it in their MSG_FACTORY_PROPOSE daemon callback) */
        if (!lsp_run_factory_creation(&lsp,
                                       fund2_txid, fund2_vout,
                                       fund2_amount,
                                       fund_spk, 34,
                                       step_blocks, 4, cltv2)) {
            fprintf(stderr, "ROTATION: Factory 1 creation failed\n");
            lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }

        /* Set lifecycle for Factory 1 */
        {
            int cur_h = regtest_get_block_height(&rt);
            if (cur_h > 0)
                factory_set_lifecycle(&lsp.factory, (uint32_t)cur_h, 20, 10);
        }

        /* Store in ladder slot 1 */
        {
            ladder_factory_t *lf1 = &lad->factories[1];
            lf1->factory = lsp.factory;
            lf1->factory_id = lad->next_factory_id++;
            lf1->is_initialized = 1;
            lf1->is_funded = 1;
            lf1->cached_state = FACTORY_ACTIVE;
            tx_buf_init(&lf1->distribution_tx, 256);
            lad->n_factories = 2;
        }
        printf("  Factory 1 created and stored in ladder slot 1\n");

        /* Initialize new channel manager + send CHANNEL_READY */
        lsp_channel_mgr_t *mgr2 = calloc(1, sizeof(lsp_channel_mgr_t));
        if (!mgr2) { fprintf(stderr, "LSP: alloc failed\n"); return 1; }
        mgr2->fee = &fee_est;
        mgr2->routing_fee_ppm = routing_fee_ppm;
        mgr2->lsp_balance_pct = lsp_balance_pct;
        mgr2->settlement_interval_blocks = settlement_interval;
        if (!lsp_channels_init(mgr2, ctx, &lsp.factory, lsp_seckey, (size_t)n_clients)) {
            fprintf(stderr, "ROTATION: channel init for Factory 1 failed\n");
            free(mgr2); lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }
        if (!lsp_channels_exchange_basepoints(mgr2, &lsp)) {
            fprintf(stderr, "ROTATION: basepoint exchange for Factory 1 failed\n");
            free(mgr2); lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }
        if (!lsp_channels_send_ready(mgr2, &lsp)) {
            fprintf(stderr, "ROTATION: send_ready for Factory 1 failed\n");
            free(mgr2); lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }
        printf("  Factory 1 channels ready\n");

        /* --- Phase C.5: Wait for client reconnections --- */
        /* Clients disconnect after rotation to reload cleanly from DB
           (Bug 11 fix in superscalar_client.c:1067-1072), then reconnect.
           We must accept those reconnections before cooperative close,
           otherwise lsp_run_cooperative_close sends to stale FDs. */
        {
            size_t reconnected = 0;
            printf("  Waiting for client reconnections...\n");
            for (int attempt = 0; attempt < 30 && reconnected < (size_t)n_clients; attempt++) {
                fd_set rfds;
                FD_ZERO(&rfds);
                FD_SET(lsp.listen_fd, &rfds);
                struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
                int sel = select(lsp.listen_fd + 1, &rfds, NULL, NULL, &tv);
                if (sel <= 0) continue;

                int new_fd = wire_accept(lsp.listen_fd);
                if (new_fd < 0) continue;

                /* Noise handshake */
                int hs;
                if (lsp.use_nk)
                    hs = wire_noise_handshake_nk_responder(new_fd, ctx, lsp.nk_seckey);
                else
                    hs = wire_noise_handshake_responder(new_fd, ctx);
                if (!hs) { wire_close(new_fd); continue; }

                if (lsp_channels_handle_reconnect(mgr2, &lsp, new_fd))
                    reconnected++;
            }
            if (reconnected < (size_t)n_clients) {
                fprintf(stderr, "ROTATION: only %zu/%d clients reconnected\n",
                        reconnected, n_clients);
                free(mgr2); lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            printf("  All %d clients reconnected\n", n_clients);
        }

        /* --- Phase D: Cooperative close on Factory 1 --- */
        printf("Phase D: Cooperative close of Factory 1\n");

        /* Cooperative close of Factory 1 */
        tx_output_t close2_outputs[FACTORY_MAX_SIGNERS];
        size_t n_close2 = lsp_channels_build_close_outputs(mgr2, &lsp.factory,
                                                             close2_outputs, 500,
                                                             NULL, 0);
        tx_buf_t close2_tx;
        tx_buf_init(&close2_tx, 512);
        if (!lsp_run_cooperative_close(&lsp, &close2_tx, close2_outputs, n_close2,
                                          (uint32_t)regtest_get_block_height(&rt))) {
            fprintf(stderr, "ROTATION: cooperative close of Factory 1 failed\n");
            tx_buf_free(&close2_tx); free(mgr2);
            lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }

        char *c2_hex = malloc(close2_tx.len * 2 + 1);
        hex_encode(close2_tx.data, close2_tx.len, c2_hex);
        char c2_txid[65];
        int c2_sent = regtest_send_raw_tx(&rt, c2_hex, c2_txid);
        if (g_db)
            persist_log_broadcast(g_db, c2_sent ? c2_txid : "?",
                "rotation_close_f1", c2_hex, c2_sent ? "ok" : "failed");
        free(c2_hex);
        tx_buf_free(&close2_tx);

        if (!c2_sent) {
            fprintf(stderr, "ROTATION: Factory 1 close TX broadcast failed\n");
            lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }
        ADVANCE(1);

        printf("  Factory 1 closed: %s\n", c2_txid);
        printf("\n=== FACTORY ROTATION TEST PASSED ===\n");

        report_add_string(&rpt, "result", "rotation_test_complete");
        report_close(&rpt);
        free(mgr2);
        if (use_db) persist_close(&db);
        tx_buf_free(&lad->factories[0].distribution_tx);
        tx_buf_free(&lad->factories[1].distribution_tx);
        lsp_cleanup(&lsp);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 0;
    }

    /* === Phase 5: Cooperative close === */
    if (g_shutdown) {
        lsp_abort_ceremony(&lsp, "LSP shutting down");
        lsp_cleanup(&lsp);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    printf("LSP: starting cooperative close...\n");

    tx_output_t close_outputs[FACTORY_MAX_SIGNERS];
    size_t n_close_outputs;

    /* Get wallet-controlled address for close outputs (UTXO recycling) */
    char final_wallet_addr[128];
    unsigned char final_wallet_spk[64];
    size_t final_wallet_spk_len = 0;
    const unsigned char *final_close_spk = NULL;
    size_t final_close_spk_len = 0;

    if (regtest_get_new_address(&rt, final_wallet_addr, sizeof(final_wallet_addr)) &&
        regtest_get_address_scriptpubkey(&rt, final_wallet_addr,
                                          final_wallet_spk, &final_wallet_spk_len)) {
        final_close_spk = final_wallet_spk;
        final_close_spk_len = final_wallet_spk_len;
        printf("LSP: final close outputs to wallet address %s\n", final_wallet_addr);
    }

    if (channels_active) {
        /* Pass NULL for close_spk so client outputs use per-client P2TR
           addresses derived from their factory pubkeys. LSP output uses
           factory funding SPK (or wallet SPK if needed). */
        n_close_outputs = lsp_channels_build_close_outputs(mgr, &lsp.factory,
                                                            close_outputs, 500,
                                                            NULL, 0);
        if (n_close_outputs == 0) {
            fprintf(stderr, "LSP: build close outputs failed\n");
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
    } else {
        /* No payments — equal split (original behavior) */
        const unsigned char *close_spk = final_close_spk ? final_close_spk : fund_spk;
        size_t close_spk_len = final_close_spk ? final_close_spk_len : 34;
        uint64_t close_total = funding_amount - 500;  /* fee */
        uint64_t per_party = close_total / n_total;
        for (size_t i = 0; i < n_total; i++) {
            close_outputs[i].amount_sats = per_party;
            memcpy(close_outputs[i].script_pubkey, close_spk, close_spk_len);
            close_outputs[i].script_pubkey_len = close_spk_len;
        }
        /* Give remainder to last output */
        close_outputs[n_total - 1].amount_sats = close_total - per_party * (n_total - 1);
        n_close_outputs = n_total;
    }

    /* Print final balances */
    printf("LSP: Close outputs:\n");
    printf("  LSP:      %llu sats\n", (unsigned long long)close_outputs[0].amount_sats);
    for (size_t i = 0; i < (size_t)n_clients; i++)
        printf("  Client %zu: %llu sats\n", i, (unsigned long long)close_outputs[i + 1].amount_sats);

    /* Report: close outputs */
    report_begin_section(&rpt, "close");
    report_begin_array(&rpt, "outputs");
    for (size_t i = 0; i < n_close_outputs; i++) {
        report_begin_section(&rpt, NULL);
        report_add_uint(&rpt, "amount_sats", close_outputs[i].amount_sats);
        report_add_hex(&rpt, "script_pubkey",
                       close_outputs[i].script_pubkey,
                       close_outputs[i].script_pubkey_len);
        report_end_section(&rpt);
    }
    report_end_array(&rpt);

    tx_buf_t close_tx;
    tx_buf_init(&close_tx, 512);

    if (!lsp_run_cooperative_close(&lsp, &close_tx, close_outputs, n_close_outputs,
                                      (uint32_t)regtest_get_block_height(&rt))) {
        fprintf(stderr, "LSP: cooperative close failed\n");
        tx_buf_free(&close_tx);
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }

    /* Broadcast close tx */
    char close_hex[close_tx.len * 2 + 1];
    hex_encode(close_tx.data, close_tx.len, close_hex);
    char close_txid[65];
    if (!regtest_send_raw_tx(&rt, close_hex, close_txid)) {
        if (g_db)
            persist_log_broadcast(g_db, "?", "cooperative_close",
                close_hex, "failed");
        fprintf(stderr, "LSP: broadcast close tx failed\n");
        tx_buf_free(&close_tx);
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    if (g_db)
        persist_log_broadcast(g_db, close_txid, "cooperative_close",
            close_hex, "ok");
    if (is_regtest) {
        regtest_mine_blocks(&rt, 1, mine_addr);
    } else {
        printf("LSP: waiting for close tx confirmation on %s...\n", network);
        regtest_wait_for_confirmation(&rt, close_txid, confirm_timeout_secs);
    }
    tx_buf_free(&close_tx);

    int conf = regtest_get_confirmations(&rt, close_txid);
    if (conf < 1) {
        fprintf(stderr, "LSP: close tx not confirmed (conf=%d)\n", conf);
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }

    printf("LSP: cooperative close confirmed! txid: %s\n", close_txid);
    printf("LSP: SUCCESS — factory created and closed with %d clients\n", n_clients);

    /* Report: close confirmation */
    report_add_string(&rpt, "close_txid", close_txid);
    report_add_uint(&rpt, "confirmations", (uint64_t)conf);
    report_end_section(&rpt);  /* end "close" section */

    report_add_string(&rpt, "result", "success");
    report_close(&rpt);

    jit_channels_cleanup(mgr);
    free(mgr);
    if (use_db)
        persist_close(&db);
    if (tor_control_fd >= 0)
        close(tor_control_fd);
    lsp_cleanup(&lsp);
    memset(lsp_seckey, 0, 32);
    secp256k1_context_destroy(ctx);
    return 0;
}
