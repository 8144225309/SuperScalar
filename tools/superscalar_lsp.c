#include "superscalar/version.h"
#include "superscalar/lsp.h"
#include "superscalar/lsps.h"
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
#include "superscalar/log.h"
#ifdef __linux__
#include <syslog.h>
#endif
#include "superscalar/backup.h"
#include "superscalar/bip39.h"
#include "superscalar/hd_key.h"
#include "superscalar/ladder.h"
#include "superscalar/adaptor.h"
#include "superscalar/bip158_backend.h"
#include "superscalar/wallet_source_hd.h"
#include "superscalar/lsp_fund.h"
#include "superscalar/chain_backend.h"
#include "superscalar/wallet_source.h"
#include "superscalar/readiness.h"
#include "superscalar/notify.h"
#include "superscalar/splice.h"
#include "superscalar/musig.h"
#include "superscalar/lsp_wellknown.h"
#include "superscalar/admin_rpc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>
#ifdef __linux__
#include <execinfo.h>
#endif
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);
#include "superscalar/sha256.h"
#include "superscalar/bolt12.h"
#include "superscalar/bech32m.h"
#include "superscalar/bolt8_server.h"
#include "superscalar/ln_dispatch.h"
#include "superscalar/invoice.h"
#include "superscalar/peer_mgr.h"
#include "superscalar/htlc_forward.h"
#include "superscalar/mpp.h"
#include "superscalar/payment.h"
#include "superscalar/cltv_watchdog.h"
#include "superscalar/gossip_peer.h"
#include "superscalar/gossip_store.h"
#include <pthread.h>

static volatile sig_atomic_t g_shutdown = 0;
static lsp_t *g_lsp = NULL;  /* for signal handler cleanup */
static persist_t *g_db = NULL;  /* for broadcast audit logging */

/* BOLT #8 server thread — owns g_bolt8_cfg; runs blocking accept loop */
static bolt8_server_cfg_t g_bolt8_cfg;
static void *bolt8_server_thread(void *arg) {
    (void)arg;
    bolt8_server_run(&g_bolt8_cfg);
    return NULL;
}

/* LN peer message dispatch globals */
static peer_mgr_t         g_peer_mgr;
static htlc_forward_table_t g_fwd;
static mpp_table_t         g_mpp;
static payment_table_t     g_payments;
static ln_dispatch_t       g_ln_dispatch;
static bolt11_invoice_table_t g_invoice_tbl;

/* CLTV watchdog: pointer to the active channel manager, set after each alloc */
static lsp_channel_mgr_t *g_channel_mgr = NULL;

/* LSPS0 context for bolt8_server callback */
static lsps_ctx_t  g_lsps_ctx;

/* LSPS2 JIT pending channel intercept table */
static lsps2_pending_table_t g_lsps2_pending;

/* Watchtower: breach detection on every block */
static watchtower_t g_watchtower;
static int          g_watchtower_ready = 0;

/* Admin RPC: JSON-RPC 2.0 Unix socket operator interface */
static admin_rpc_t   g_admin_rpc;
static gossip_store_t *g_gossip_store_ptr = NULL; /* set after gossip store init */

static void *ln_dispatch_thread(void *arg) {
    (void)arg;
    ln_dispatch_run(&g_ln_dispatch);
    return NULL;
}

/* Gap 3: callback from ln_dispatch when JIT cost is covered.
 * Opens a JIT channel for the client then relays the pending HTLC. */
static void on_jit_open(void *cb_ctx, uint64_t scid,
                         uint64_t out_amount_msat,
                         size_t in_peer_idx, uint64_t in_htlc_id)
{
    (void)cb_ctx; (void)in_peer_idx; (void)in_htlc_id;
    /* SCID encodes client_idx: (0x800000 << 40) | ((client_idx+1) << 16) | block */
    size_t client_idx = (size_t)(((scid >> 16) & 0xFFFFFF) - 1);

    /* Open the JIT channel (no-op if already open) */
    if (!jit_channel_is_active(g_channel_mgr, client_idx))
        jit_channel_create(g_channel_mgr, g_lsp, client_idx,
                            out_amount_msat * 2, "lsps2-jit");

    fprintf(stderr, "LSP: JIT channel opened for client %zu (scid=0x%llx)\n",
            client_idx, (unsigned long long)scid);
}

/* LSPS0 adapter: bridges bolt8_server callback to lsps_handle_request. */
static int lsps0_bolt8_cb(void *userdata, int fd, bolt8_state_t *state,
                           const char *json_req, char *resp_buf, size_t resp_cap)
{
    (void)state;
    if (!json_req || !resp_buf || resp_cap == 0) return 0;
    lsps_ctx_t *ctx = (lsps_ctx_t *)userdata;

    cJSON *json = cJSON_Parse(json_req);
    if (!json) {
        cJSON *err = lsps_build_error(0, LSPS_ERR_PARSE_ERROR, "parse error");
        if (err) {
            char *s = cJSON_PrintUnformatted(err);
            if (s) {
                size_t n = strlen(s);
                if (n < resp_cap) { memcpy(resp_buf, s, n + 1); free(s); cJSON_Delete(err); return (int)n; }
                free(s);
            }
            cJSON_Delete(err);
        }
        return 0;
    }

    int id = 0;
    const char *method = lsps_parse_request(json, &id);
    cJSON *resp = NULL;

    if (!method) {
        resp = lsps_build_error(id, LSPS_ERR_INVALID_REQUEST, "invalid request");
    } else if (strcmp(method, "lsps1_get_info") == 0) {
        lsps1_info_t info;
        memset(&info, 0, sizeof(info));
        info.min_channel_balance_msat = 100000000ULL;
        info.max_channel_balance_msat = 10000000000ULL;
        info.min_confirmations        = 1;
        info.base_fee_msat            = 1000;
        info.fee_ppm                  = 500;
        resp = lsps_build_response(id, lsps1_build_get_info_response(&info));
    } else if (strcmp(method, "lsps2_get_info") == 0) {
        lsps2_fee_params_t params;
        memset(&params, 0, sizeof(params));
        params.min_fee_msat             = 1000;
        params.fee_ppm                  = 500;
        params.min_channel_balance_msat = 100000000ULL;
        params.max_channel_balance_msat = 10000000000ULL;
        resp = lsps_build_response(id, lsps2_build_get_info_response(&params));
    } else if (lsps_handle_request(ctx, fd, json)) {
        cJSON_Delete(json);
        return 0;
    } else {
        resp = lsps_build_error(id, LSPS_ERR_METHOD_NOT_FOUND, "method not found");
    }

    cJSON_Delete(json);
    int written = 0;
    if (resp) {
        char *s = cJSON_PrintUnformatted(resp);
        if (s) {
            size_t n = strlen(s);
            if (n < resp_cap) { memcpy(resp_buf, s, n + 1); written = (int)n; }
            free(s);
        }
        cJSON_Delete(resp);
    }
    return written;
}

/* Chain monitoring: called by bip158_backend after each new block is processed */
static void on_block_connected(uint32_t height, void *cb_ctx)
{
    (void)cb_ctx;
    if (!g_channel_mgr) return;

    for (size_t i = 0; i < g_channel_mgr->n_channels; i++) {
        channel_t *ch = &g_channel_mgr->entries[i].channel;
        cltv_watchdog_t wd;
        cltv_watchdog_init(&wd, ch, 0);          /* 0 = CLTV_EXPIRY_DELTA default */
        int at_risk = cltv_watchdog_check(&wd, height);
        if (at_risk > 0)
            fprintf(stderr, "LSP: block %u: channel %zu has %d HTLC(s)"
                    " within expiry delta — consider force-close\n",
                    (unsigned)height, i, at_risk);
        cltv_watchdog_expire(&wd, height);
    }

    /* Phase J: advance LSPS1 order confirmations */
    lsps1_orders_tick_all(height);

    /* Watchtower breach detection */
    if (g_watchtower_ready) {
        int penalties = watchtower_check(&g_watchtower);
        if (penalties > 0)
            fprintf(stderr, "LSP: block %u: broadcast %d penalty tx(s)\n",
                    (unsigned)height, penalties);
    }
}

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
        "  --fee-rate N        Fee rate in sat/kvB (default 1000 = 1 sat/vB, min 100 = 0.1 sat/vB)\n"
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
        "  --test-multi-htlc-force-close  After demo: add HTLCs on ALL channels, force-close, broadcast all timeout TXs\n"
        "  --test-full-settlement  After demo: force-close tree, broadcast ALL commitment TXs, verify cross-leaf balances\n"
        "  --test-dw-advance   After demo: advance DW counter, re-sign tree, force-close (shows nSequence decrease)\n"
        "  --test-leaf-advance After demo: advance left leaf only, force-close (proves per-leaf independence)\n"
        "  --test-partial-rotation After demo: 1 client goes offline, partial rotation with 3/4, dist TX on old factory\n"
        "  --test-dual-factory After demo: create second factory, show two ACTIVE in ladder, force-close both\n"
        "  --test-dw-exhibition After demo: full DW lifecycle (multi-advance + PTLC close + cross-factory contrast)\n"
        "  --test-bridge       After demo: simulate bridge inbound HTLC, verify client fulfills\n"
        "  --test-splice       After demo: splice-out channel[0] by 10k sats, broadcast, confirm\n"
        "  --test-splice-client-seckey HEX  Client[0] secret key for test-only MuSig2 signing\n"
        "  --test-lightclient  Run in BIP 157/158 light-client mode and verify filter sync\n"
        "  --test-jit          After demo: create JIT channels for all clients\n"
        "  --test-lsps2        After demo: wait for client LSPS2 buy flow\n"
        "  --test-bolt12       After demo: BOLT12 offer codec + signature test\n"
        "  --test-buy-liquidity After demo: buy inbound liquidity from L-stock\n"
        "  --test-bip39        Full factory lifecycle with BIP39 HD-derived LSP key\n"
        "  --test-large-factory Use --clients 8 for 8-client factory (combine with --demo)\n"
        "  --confirm-timeout N Confirmation wait timeout in seconds (default: 3600 regtest, 259200 non-regtest)\n"
        "  --safe-confs N      Set ALL confirmation depths at once (shorthand).\n"
        "  --funding-confs N   Funding TX depth before acting (default: %d, CLN=3, LND=1-6)\n"
        "  --close-confs N     Close TX depth before removing entries (default: %d, LDK=6)\n"
        "  --penalty-confs N   Penalty TX depth before removing breach entry (default: %d)\n"
        "  --sweep-confs N     HTLC sweep depth before considering settled (default: %d)\n"
        "                        On regtest, all operations use 1 regardless.\n"
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
        "  --rpc-file PATH     Unix socket path for JSON-RPC 2.0 admin interface\n"
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
        "  --light-client HOST:PORT  Use BIP 157/158 P2P compact block filters for chain scanning.\n"
        "                            When set, bitcoind is NOT required at startup (no --cli-path\n"
        "                            needed for chain data). Fee estimation and wallet funding still\n"
        "                            use --cli-path if provided. Requires a BIP 157 full-node peer.\n"
        "  --light-client-fallback HOST:PORT  Add a fallback peer for automatic rotation on\n"
        "                            disconnect. May be specified multiple times (up to 7 total).\n"
        "  --fee-estimator MODE  Select fee estimation backend:\n"
        "                          rpc         estimatesmartfee via bitcoin-cli (default when --cli-path set)\n"
        "                          blocks      block-derived + BIP 133 feefilter (default when --light-client set)\n"
        "                          api         mempool.space /api/v1/fees/recommended\n"
        "                          api:URL     custom HTTP/HTTPS endpoint (mempool.space-compatible JSON)\n"
        "                          static:N    fixed N sat/vByte (e.g. static:10)\n"
        "  --async-rotation    Queue rotation requests and wait for clients to reconnect (default: synchronous)\n"
        "  --notify-webhook URL  Send push notifications to webhook URL on rotation events\n"
        "  --notify-exec SCRIPT  Run script on rotation events: script <client> <event> <urgency> <json>\n"
        "  --bolt8-port N      Start BOLT #8 TCP server on port N for external LN peers\n"
        "  --i-accept-the-risk Allow mainnet operation (PROTOTYPE — funds at risk!)\n"
        "  --version           Show version and exit\n"
        "  --help              Show this help\n",
        prog, LSP_MAX_CLIENTS,
        CONF_DEFAULT_FUNDING, CONF_DEFAULT_CLOSE,
        CONF_DEFAULT_PENALTY, CONF_DEFAULT_SWEEP,
        LSP_MAX_CLIENTS);
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

/* Non-blocking confirmation wait: poll for TX confirmation while servicing
   the LSP's listen socket for client reconnections.  This prevents clients
   from disconnecting during long confirmation waits on signet/testnet.
   Returns 1 on confirmed, 0 on timeout. */
static int wait_for_confirmation_servicing(regtest_t *rt, const char *txid_hex,
                                            int timeout_secs, lsp_t *lsp,
                                            lsp_channel_mgr_t *mgr) {
    if (!rt || !txid_hex) return 0;
    time_t t_start = time(NULL);

    while (1) {
        time_t tnow = time(NULL);
        int elapsed = (int)(tnow - t_start);
        if (elapsed >= timeout_secs) return 0;

        /* Check confirmation */
        int conf = regtest_get_confirmations(rt, txid_hex);
        if (conf >= 1) return 1;

        /* Log progress */
        int height = regtest_get_block_height(rt);
        if (elapsed > 0 && (elapsed % 15) == 0)
            printf("  waiting for confirmation of %.16s... (height=%d, %ds / %ds)\n",
                   txid_hex, height, elapsed, timeout_secs);
        fflush(stdout);

        /* Send keepalive ping to all clients every 30 seconds */
        {
            static time_t last_ping = 0;
            if (!last_ping) last_ping = time(NULL);
            if (tnow - last_ping >= 30 && lsp) {
                cJSON *ping = cJSON_CreateObject();
                for (size_t i = 0; i < lsp->n_clients; i++) {
                    if (lsp->client_fds[i] >= 0)
                        wire_send(lsp->client_fds[i], MSG_PING, ping);
                }
                cJSON_Delete(ping);
                last_ping = tnow;
            }
        }

        /* Poll listen socket + client fds (5s timeout) */
        {
            struct pollfd pfds[16];
            int nfds = 0;
            int listen_idx = -1;
            if (lsp && lsp->listen_fd >= 0 && nfds < 16) {
                listen_idx = nfds;
                pfds[nfds].fd = lsp->listen_fd;
                pfds[nfds].events = POLLIN;
                nfds++;
            }
            /* Also poll client fds to respond to pings */
            if (lsp) {
                for (size_t i = 0; i < lsp->n_clients && nfds < 16; i++) {
                    if (lsp->client_fds[i] >= 0) {
                        pfds[nfds].fd = lsp->client_fds[i];
                        pfds[nfds].events = POLLIN;
                        nfds++;
                    }
                }
            }
            int pret = nfds > 0 ? poll(pfds, (nfds_t)nfds, 5000) : 0;
            if (!pret) { if (!nfds) sleep(5); }
            if (pret > 0) {
                for (int fi = 0; fi < nfds; fi++) {
                    if (!(pfds[fi].revents & POLLIN)) continue;
                    if (fi == listen_idx) {
                        int new_fd = wire_accept(lsp->listen_fd);
                        if (new_fd >= 0) {
                            int hs_ok;
                            if (lsp->use_nk)
                                hs_ok = wire_noise_handshake_nk_responder(new_fd,
                                            mgr ? mgr->ctx : NULL, lsp->nk_seckey);
                            else
                                hs_ok = wire_noise_handshake_responder(new_fd,
                                            mgr ? mgr->ctx : NULL);
                            if (hs_ok && mgr)
                                lsp_channels_handle_reconnect(mgr, lsp, new_fd);
                            else
                                wire_close(new_fd);
                        }
                    } else {
                        /* Client socket ready — handle ping/pong */
                        wire_msg_t cmsg;
                        if (wire_recv(pfds[fi].fd, &cmsg)) {
                            if (cmsg.msg_type == MSG_PING) {
                                cJSON *pong = cJSON_CreateObject();
                                wire_send(pfds[fi].fd, MSG_PONG, pong);
                                cJSON_Delete(pong);
                            }
                            if (cmsg.json) cJSON_Delete(cmsg.json);
                        }
                    }
                }
            }
        }
    }
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

/* -------------------------------------------------------------------------
 * BIP 158 light client — production wiring
 * ------------------------------------------------------------------------- */

/* Static backend — bip158_backend_t contains two 64 KB ring buffers;
 * too large for the stack of main(). */
static bip158_backend_t g_bip158;

/* HD wallet — used when --light-client is active without a bitcoind wallet.
 * Heap-allocated so the 100 × 34-byte SPK cache doesn't bloat the stack. */
static wallet_source_hd_t *g_hd_wallet = NULL;

/*
 * Initialise an in-process HD wallet and attach it to the watchtower.
 * Loads an existing seed from the DB, or generates and persists a fresh one.
 * Called after attach_light_client() when no bitcoind RPC is available.
 */
static int attach_hd_wallet(watchtower_t *wt, persist_t *db_ptr,
                              secp256k1_context *ctx, const char *network,
                              const char *hd_mnemonic,
                              const char *hd_passphrase,
                              uint32_t lookahead)
{
    if (!wt || !ctx) return 0;

    unsigned char seed[64];
    size_t seed_len = 64;

    /* 1. If seed exists in DB AND no hd_mnemonic override: load and use */
    if (!hd_mnemonic && db_ptr &&
        persist_load_hd_seed(db_ptr, seed, &seed_len, sizeof(seed)) && seed_len >= 16) {
        printf("LSP: HD wallet: loaded existing seed (%zu bytes)\n", seed_len);
    } else if (hd_mnemonic) {
        /* 2. Derive seed from provided mnemonic */
        if (!bip39_mnemonic_to_seed(hd_mnemonic, hd_passphrase ? hd_passphrase : "", seed)) {
            fprintf(stderr, "LSP: HD wallet: bip39_mnemonic_to_seed failed\n");
            memset(seed, 0, sizeof(seed));
            return 0;
        }
        seed_len = 64;
        printf("LSP: HD wallet: derived seed from provided mnemonic\n");
    } else {
        /* 3. First run: generate a BIP 39 24-word phrase */
        char mnemonic_buf[300];
        if (!bip39_generate(24, mnemonic_buf, sizeof(mnemonic_buf))) {
            fprintf(stderr, "LSP: HD wallet: bip39_generate failed\n");
            return 0;
        }
        printf("=== WRITE THIS DOWN: YOUR 24-WORD RECOVERY PHRASE ===\n%s\n"
               "=== KEEP THIS SAFE — LOSING IT MEANS LOSING FUNDS ===\n",
               mnemonic_buf);
        if (!bip39_mnemonic_to_seed(mnemonic_buf, hd_passphrase ? hd_passphrase : "", seed)) {
            fprintf(stderr, "LSP: HD wallet: bip39_mnemonic_to_seed failed\n");
            memset(seed, 0, sizeof(seed));
            return 0;
        }
        seed_len = 64;
    }

    /* Save seed and lookahead to DB */
    if (db_ptr) {
        persist_save_hd_seed(db_ptr, seed, seed_len);
        persist_save_hd_lookahead(db_ptr, lookahead);
    }

    g_hd_wallet = (wallet_source_hd_t *)calloc(1, sizeof(wallet_source_hd_t));
    if (!g_hd_wallet) {
        memset(seed, 0, sizeof(seed));
        return 0;
    }

    if (!wallet_source_hd_init(g_hd_wallet, seed, 64,
                                ctx, db_ptr, &g_bip158, network, lookahead)) {
        fprintf(stderr, "LSP: HD wallet: init failed\n");
        free(g_hd_wallet);
        g_hd_wallet = NULL;
        memset(seed, 0, sizeof(seed));
        return 0;
    }
    memset(seed, 0, sizeof(seed));

    /* Print the first address for funding */
    char spk_hex[69];
    if (wallet_source_hd_get_address(g_hd_wallet, 0, spk_hex, sizeof(spk_hex)))
        printf("LSP: HD wallet address[0] SPK: %s\n"
               "LSP: HD wallet ready (%u addresses pre-derived)\n",
               spk_hex, g_hd_wallet->n_spks);

    watchtower_set_wallet(wt, &g_hd_wallet->base);
    return 1;
}

/*
 * Parse a "host:port" string into separate host / port components.
 * Modifies a temporary buffer; writes to host_out (up to host_cap bytes)
 * and *port_out.  Returns 1 on success, 0 on parse error.
 */
static int parse_host_port(const char *arg,
                            char *host_out, size_t host_cap,
                            int *port_out)
{
    const char *colon = strrchr(arg, ':');
    if (!colon || colon == arg) return 0;
    size_t hlen = (size_t)(colon - arg);
    if (hlen >= host_cap) return 0;
    memcpy(host_out, arg, hlen);
    host_out[hlen] = '\0';
    *port_out = atoi(colon + 1);
    return (*port_out > 0 && *port_out <= 65535);
}

/*
 * Initialise the BIP 158 backend, connect to the peer, restore checkpoint,
 * then plug the backend into the watchtower as its chain backend.
 * Returns 1 on success, 0 on failure (caller may fall back to regtest).
 */
static int attach_light_client(watchtower_t *wt, persist_t *db_ptr,
                                const char *host_port, const char *network,
                                const char **fallbacks, int n_fallbacks,
                                fee_estimator_t *fee_est)
{
    char host[256];
    int  port = 0;
    if (!parse_host_port(host_port, host, sizeof(host), &port)) {
        fprintf(stderr, "LSP: --light-client: bad HOST:PORT '%s'\n", host_port);
        return 0;
    }

    if (!bip158_backend_init(&g_bip158, network)) {
        fprintf(stderr, "LSP: bip158_backend_init failed\n");
        return 0;
    }

    if (db_ptr) {
        bip158_backend_set_db(&g_bip158, db_ptr);
        int restored = bip158_backend_restore_checkpoint(&g_bip158);
        if (restored)
            printf("LSP: BIP 158 checkpoint restored (tip_height=%d)\n",
                   g_bip158.tip_height);
    }

    /* Register fallback peers before connecting so they're available on retry */
    for (int i = 0; i < n_fallbacks; i++) {
        char fb_host[256];
        int  fb_port = 0;
        if (parse_host_port(fallbacks[i], fb_host, sizeof(fb_host), &fb_port))
            bip158_backend_add_peer(&g_bip158, fb_host, fb_port);
        else
            fprintf(stderr, "LSP: --light-client-fallback: bad HOST:PORT '%s' (ignored)\n",
                    fallbacks[i]);
    }

    printf("LSP: connecting BIP 157/158 peer %s:%d ...\n", host, port);
    if (!bip158_backend_connect_p2p(&g_bip158, host, port)) {
        fprintf(stderr, "LSP: primary peer %s:%d failed; trying fallbacks...\n",
                host, port);
        /* Stash primary in slot 0 so rotation has a full list */
        if (g_bip158.n_peers == 0) {
            snprintf(g_bip158.peer_hosts[0], sizeof(g_bip158.peer_hosts[0]),
                     "%s", host);
            g_bip158.peer_ports[0] = port;
            g_bip158.n_peers = 1;
        }
        if (!bip158_backend_reconnect(&g_bip158)) {
            fprintf(stderr, "LSP: --light-client: all peers failed\n");
            bip158_backend_free(&g_bip158);
            return 0;
        }
    }
    printf("LSP: BIP 158 P2P peer connected (version %u, height %d)\n",
           g_bip158.peers[g_bip158.current_peer].peer_version,
           g_bip158.peers[g_bip158.current_peer].peer_start_height);

    /* Wire fee estimator if provided (enables per-block fee samples) */
    if (fee_est)
        bip158_backend_set_fee_estimator(&g_bip158, fee_est);

    /* Wire block_connected callback for chain monitoring (CLTV watchdog) */
    bip158_backend_set_block_connected_cb(&g_bip158, on_block_connected, NULL);

    watchtower_set_chain_backend(wt, &g_bip158.base);
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
    int bump_budget_pct = 0;       /* --bump-budget-pct (0 = default 50%) */
    uint64_t max_bump_fee = 0;     /* --max-bump-fee (0 = default 50000 sats) */
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
    int test_partial_rotation = 0;
    int test_splice = 0;
    const char *test_splice_client_seckey = NULL;  /* hex seckey for test signing */
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
    int test_multi_htlc_force_close = 0;
    int test_full_settlement = 0;
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
    const char *rpc_file_arg = NULL;
    const char *scb_path_arg = NULL;
    const char *tor_proxy_arg = NULL;
    const char *tor_control_arg = NULL;
    const char *tor_password = NULL;
    int tor_onion = 0;
    char *tor_password_file = NULL;
    int tor_only = 0;
    const char *bind_addr = NULL;
    int auto_rebalance = 0;
    int rebalance_threshold = 80;  /* default 80% imbalance threshold */
    int async_rotation = 0;
    const char *notify_webhook = NULL;  /* --notify-webhook URL */
    const char *notify_exec = NULL;     /* --notify-exec SCRIPT */
    int test_rebalance = 0;
    int test_batch_rebalance = 0;
    int test_realloc = 0;
    int test_jit = 0;
    int test_lsps2 = 0;
    int test_bolt12 = 0;
    int test_buy_liquidity = 0;
    int test_bip39 = 0;
    int test_large_factory = 0;
    int dynamic_fees = 0;
    const char *fee_estimator_arg = NULL; /* --fee-estimator MODE */
    int heartbeat_interval = 0;  /* 0 = disabled; seconds between daemon status lines */
    int safe_confs_arg = 0;      /* 0 = use defaults; >0 = set all four at once */
    int funding_confs_arg = 0;   /* --funding-confs: per-operation override */
    int close_confs_arg = 0;     /* --close-confs */
    int penalty_confs_arg = 0;   /* --penalty-confs */
    int sweep_confs_arg = 0;     /* --sweep-confs */
    const char *backup_path_arg = NULL;
    const char *restore_path_arg = NULL;
    int backup_verify_arg = 0;
    int generate_mnemonic = 0;
    const char *from_mnemonic = NULL;
    const char *mnemonic_passphrase = "";
    const char *hd_mnemonic = NULL;
    const char *hd_passphrase = "";
    uint32_t hd_lookahead = HD_WALLET_LOOKAHEAD;
    int fee_bump_after = 6;       /* blocks before first bump */
    int fee_bump_max = 3;         /* max bump attempts */
    double fee_bump_multiplier = 1.5;
    (void)fee_bump_after; (void)fee_bump_max; (void)fee_bump_multiplier;
    const char *light_client_arg = NULL;  /* HOST:PORT for BIP 157 P2P peer */
    /* Fallback peers for rotation: up to BIP158_MAX_PEERS-1 additional entries */
    const char *lc_fallbacks[BIP158_MAX_PEERS - 1];
    memset(lc_fallbacks, 0, sizeof(lc_fallbacks));
    int n_lc_fallbacks = 0;
    const char *create_offer_desc = NULL;  /* --create-offer DESCRIPTION */
    uint64_t create_offer_amount = 0;      /* optional amount_msat (0 = any) */
    uint16_t well_known_port = 0;          /* 0 = disabled; set with --well-known-port */
    int use_clnbridge = 0;                 /* --clnbridge: use CLN bridge for inbound payments */
    char gossip_peers[1024] = "";          /* --gossip-peers HOST:PORT[,HOST:PORT,...] */
    uint16_t bolt8_listen_port = 0;        /* --bolt8-port N: BOLT #8 TCP accept port */
    const char *log_file_path = NULL;      /* --log-file PATH */
    int use_syslog = 0;                    /* --syslog */
    int use_json_log = 0;                  /* --json-log */

    /* Load config file if --config provided (first pass) */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            FILE *cf = fopen(argv[i + 1], "r");
            if (!cf) { fprintf(stderr, "ERROR: cannot open config: %s\n", argv[i + 1]); return 1; }
            fseek(cf, 0, SEEK_END);
            long cfsz = ftell(cf);
            fseek(cf, 0, SEEK_SET);
            char *cfdata = malloc((size_t)cfsz + 1);
            if (cfdata) {
                size_t cfrd = fread(cfdata, 1, (size_t)cfsz, cf);
                cfdata[cfrd] = '\0';
                cJSON *cfg = cJSON_Parse(cfdata);
                free(cfdata);
                if (cfg) {
                    cJSON *v;
                    if ((v = cJSON_GetObjectItem(cfg, "port")) && cJSON_IsNumber(v)) port = (int)v->valuedouble;
                    if ((v = cJSON_GetObjectItem(cfg, "clients")) && cJSON_IsNumber(v)) n_clients = (int)v->valuedouble;
                    if ((v = cJSON_GetObjectItem(cfg, "amount")) && cJSON_IsNumber(v)) funding_sats = (uint64_t)v->valuedouble;
                    if ((v = cJSON_GetObjectItem(cfg, "network")) && cJSON_IsString(v)) network = strdup(v->valuestring);
                    if ((v = cJSON_GetObjectItem(cfg, "keyfile")) && cJSON_IsString(v)) keyfile_path = strdup(v->valuestring);
                    if ((v = cJSON_GetObjectItem(cfg, "db")) && cJSON_IsString(v)) db_path = strdup(v->valuestring);
                    if ((v = cJSON_GetObjectItem(cfg, "rpcuser")) && cJSON_IsString(v)) rpcuser = strdup(v->valuestring);
                    if ((v = cJSON_GetObjectItem(cfg, "rpcpassword")) && cJSON_IsString(v)) rpcpassword = strdup(v->valuestring);
                    if ((v = cJSON_GetObjectItem(cfg, "rpcport")) && cJSON_IsNumber(v)) rpcport = (int)v->valuedouble;
                    printf("Loaded config from %s\n", argv[i + 1]);
                    cJSON_Delete(cfg);
                } else {
                    fprintf(stderr, "WARNING: failed to parse config JSON: %s\n", argv[i + 1]);
                }
            }
            fclose(cf);
            break;
        }
    }

    /* Parse CLI arguments (override config file) */
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
        else if (strcmp(argv[i], "--test-partial-rotation") == 0)
            test_partial_rotation = 1;
        else if (strcmp(argv[i], "--cheat-daemon") == 0)
            breach_test = 2;  /* 2 = cheat-daemon mode (no LSP watchtower, sleep after breach) */
        else if (strcmp(argv[i], "--test-rebalance") == 0)
            test_rebalance = 1;
        else if (strcmp(argv[i], "--test-batch-rebalance") == 0)
            test_batch_rebalance = 1;
        else if (strcmp(argv[i], "--test-realloc") == 0)
            test_realloc = 1;
        else if (strcmp(argv[i], "--test-jit") == 0)
            test_jit = 1;
        else if (strcmp(argv[i], "--test-lsps2") == 0)
            test_lsps2 = 1;
        else if (strcmp(argv[i], "--test-bolt12") == 0)
            test_bolt12 = 1;
        else if (strcmp(argv[i], "--test-buy-liquidity") == 0)
            test_buy_liquidity = 1;
        else if (strcmp(argv[i], "--test-bip39") == 0)
            test_bip39 = 1;
        else if (strcmp(argv[i], "--test-large-factory") == 0)
            test_large_factory = 1;
        else if (strcmp(argv[i], "--active-blocks") == 0 && i + 1 < argc)
            active_blocks_arg = (int32_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--dying-blocks") == 0 && i + 1 < argc)
            dying_blocks_arg = (int32_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--jit-amount") == 0 && i + 1 < argc)
            jit_amount_arg = (int64_t)strtoll(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--no-jit") == 0)
            no_jit = 1;
        else if (strcmp(argv[i], "--async-rotation") == 0)
            async_rotation = 1;
        else if (strcmp(argv[i], "--notify-webhook") == 0 && i + 1 < argc)
            notify_webhook = argv[++i];
        else if (strcmp(argv[i], "--notify-exec") == 0 && i + 1 < argc)
            notify_exec = argv[++i];
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
        else if (strcmp(argv[i], "--test-multi-htlc-force-close") == 0)
            test_multi_htlc_force_close = 1;
        else if (strcmp(argv[i], "--test-full-settlement") == 0)
            test_full_settlement = 1;
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
        else if (strcmp(argv[i], "--test-splice") == 0)
            test_splice = 1;
        else if (strcmp(argv[i], "--test-splice-client-seckey") == 0 && i + 1 < argc)
            test_splice_client_seckey = argv[++i];
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
        else if (strcmp(argv[i], "--rpc-file") == 0 && i + 1 < argc)
            rpc_file_arg = argv[++i];
        else if (strcmp(argv[i], "--scb-path") == 0 && i + 1 < argc)
            scb_path_arg = argv[++i];
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
        else if (strcmp(argv[i], "--fee-estimator") == 0 && i + 1 < argc)
            fee_estimator_arg = argv[++i];
        else if (strcmp(argv[i], "--heartbeat-interval") == 0 && i + 1 < argc)
            heartbeat_interval = atoi(argv[++i]);
        else if (strcmp(argv[i], "--safe-confs") == 0 && i + 1 < argc)
            safe_confs_arg = atoi(argv[++i]);
        else if (strcmp(argv[i], "--funding-confs") == 0 && i + 1 < argc)
            funding_confs_arg = atoi(argv[++i]);
        else if (strcmp(argv[i], "--close-confs") == 0 && i + 1 < argc)
            close_confs_arg = atoi(argv[++i]);
        else if (strcmp(argv[i], "--penalty-confs") == 0 && i + 1 < argc)
            penalty_confs_arg = atoi(argv[++i]);
        else if (strcmp(argv[i], "--sweep-confs") == 0 && i + 1 < argc)
            sweep_confs_arg = atoi(argv[++i]);
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
        else if (strcmp(argv[i], "--light-client") == 0 && i + 1 < argc)
            light_client_arg = argv[++i];
        else if (strcmp(argv[i], "--light-client-fallback") == 0 && i + 1 < argc) {
            if (n_lc_fallbacks < (int)(sizeof(lc_fallbacks)/sizeof(lc_fallbacks[0])))
                lc_fallbacks[n_lc_fallbacks++] = argv[++i];
            else { fprintf(stderr, "Warning: too many --light-client-fallback peers (max %d)\n",
                           (int)(sizeof(lc_fallbacks)/sizeof(lc_fallbacks[0]))); i++; }
        }
        else if (strcmp(argv[i], "--hd-mnemonic") == 0 && i + 1 < argc)
            hd_mnemonic = argv[++i];
        else if (strcmp(argv[i], "--hd-passphrase") == 0 && i + 1 < argc)
            hd_passphrase = argv[++i];
        else if (strcmp(argv[i], "--hd-lookahead") == 0 && i + 1 < argc)
            hd_lookahead = (uint32_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--create-offer") == 0 && i + 1 < argc)
            create_offer_desc = argv[++i];
        else if (strcmp(argv[i], "--offer-amount") == 0 && i + 1 < argc)
            create_offer_amount = (uint64_t)strtoull(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--well-known-port") == 0 && i + 1 < argc)
            well_known_port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--clnbridge") == 0)
            use_clnbridge = 1;
        else if (strcmp(argv[i], "--gossip-peers") == 0 && i + 1 < argc) {
            strncpy(gossip_peers, argv[++i], sizeof(gossip_peers) - 1);
            gossip_peers[sizeof(gossip_peers) - 1] = '\0';
        }
        else if (strcmp(argv[i], "--bolt8-port") == 0 && i + 1 < argc)
            bolt8_listen_port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--i-accept-the-risk") == 0)
            accept_risk = 1;
        else if (strcmp(argv[i], "--log-file") == 0 && i + 1 < argc)
            log_file_path = argv[++i];
        else if (strcmp(argv[i], "--syslog") == 0)
            use_syslog = 1;
        else if (strcmp(argv[i], "--json-log") == 0)
            use_json_log = 1;
        else if (strcmp(argv[i], "--max-bump-fee") == 0 && i + 1 < argc)
            max_bump_fee = (uint64_t)strtoull(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--bump-budget-pct") == 0 && i + 1 < argc) {
            bump_budget_pct = atoi(argv[++i]);
            if (bump_budget_pct < 1 || bump_budget_pct > 100) {
                fprintf(stderr, "Error: --bump-budget-pct must be 1-100\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc)
            i++;  /* already parsed in first pass */
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

    /* Redirect logs if requested */
    if (log_file_path) {
        if (!freopen(log_file_path, "a", stderr)) {
            printf("ERROR: cannot open log file: %s\n", log_file_path);
            return 1;
        }
        setvbuf(stderr, NULL, _IOLBF, 0); /* line-buffered */
    }
    if (use_syslog) {
#ifdef __linux__
        openlog("superscalar_lsp", LOG_PID | LOG_NDELAY, LOG_DAEMON);
#endif
    }
    if (use_json_log)
        ss_log_set_json(1);

    /* --- Validate fee rate floor --- */
    if (fee_rate < FEE_FLOOR_SAT_PER_KVB) {
        fprintf(stderr, "ERROR: --fee-rate %llu is below minimum %d sat/kvB (0.1 sat/vB)\n",
                (unsigned long long)fee_rate, FEE_FLOOR_SAT_PER_KVB);
        return 1;
    }
    if (fee_rate < 1000) {
        int is_mainnet = (strcmp(network, "mainnet") == 0 || strcmp(network, "bitcoin") == 0);
        if (is_mainnet) {
            fprintf(stderr, "WARNING: fee rate %llu sat/kvB (%.1f sat/vB) is below Bitcoin Core "
                    "default minrelaytxfee (1 sat/vB).\n"
                    "  Ensure your bitcoind has -minrelaytxfee=0.0000001 or use package relay "
                    "(Bitcoin Core v30+ with ephemeral anchor support).\n"
                    "  Anchor outputs disabled at sub-1-sat/vB rates.\n",
                    (unsigned long long)fee_rate, (double)fee_rate / 1000.0);
        } else {
            /* signet/testnet4/regtest: low fees are normal with -minrelaytxfee=0.0000001 */
            fprintf(stderr, "NOTE: fee rate %llu sat/kvB (%.1f sat/vB); ensure bitcoind has "
                    "-minrelaytxfee=0.0000001 (standard for signet/testnet4).\n"
                    "  Anchor outputs disabled at sub-1-sat/vB rates.\n",
                    (unsigned long long)fee_rate, (double)fee_rate / 1000.0);
        }
    }

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

    /* --- BOLT 12 Offer creation (early exit) --- */
    if (create_offer_desc) {
        if (!seckey_hex && !keyfile_path) {
            fprintf(stderr, "Error: --create-offer requires --seckey or --keyfile\n");
            return 1;
        }
        /* Build a simple LSP offer with the node key and description */
        secp256k1_context *ctx2 = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        unsigned char seckey[32] = {0};
        if (seckey_hex) {
            extern int hex_decode(const char *, unsigned char *, size_t);
            hex_decode(seckey_hex, seckey, 32);
        }
        secp256k1_keypair kp2;
        secp256k1_pubkey pub2;
        unsigned char node_id[33];
        if (secp256k1_keypair_create(ctx2, &kp2, seckey) &&
            secp256k1_keypair_pub(ctx2, &pub2, &kp2)) {
            size_t sz = 33;
            secp256k1_ec_pubkey_serialize(ctx2, node_id, &sz,
                                           &pub2, SECP256K1_EC_COMPRESSED);
        } else {
            memset(node_id, 0, 33);
        }
        secp256k1_context_destroy(ctx2);

        offer_t offer;
        memset(&offer, 0, sizeof(offer));
        memcpy(offer.node_id, node_id, 33);
        offer.amount_msat = create_offer_amount;
        offer.has_amount = (create_offer_amount > 0);
        strncpy(offer.description, create_offer_desc,
                sizeof(offer.description) - 1);

        char enc[1024];
        if (!offer_encode(&offer, enc, sizeof(enc))) {
            fprintf(stderr, "Error: offer_encode failed\n");
            return 1;
        }
        printf("%s\n", enc);

        /* Optionally persist to DB */
        if (db_path) {
            persist_t pdb;
            if (persist_open(&pdb, db_path)) {
                unsigned char offer_id[32];
                sha256((const unsigned char *)enc, strlen(enc), offer_id);
                persist_save_offer(&pdb, offer_id, enc);
                persist_close(&pdb);
                fprintf(stderr, "Offer saved to %s\n", db_path);
            }
        }
        return 0;
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

    /* --- BIP39 Test placeholder (moved after key init) --- */

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

    /* --- BIP39 Test: override LSP key with HD-derived key --- */
    if (test_bip39) {
        printf("\n=== BIP39 HD WALLET TEST ===\n");
        fflush(stdout);

        char bip39_mnemonic[512];
        if (!bip39_generate(24, bip39_mnemonic, sizeof(bip39_mnemonic))) {
            fprintf(stderr, "BIP39: mnemonic generation FAILED\n");
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        printf("  Mnemonic: %s\n", bip39_mnemonic);
        printf("  Validation: %s\n", bip39_validate(bip39_mnemonic) ? "OK" : "FAILED");

        unsigned char bip39_seed[64];
        if (!bip39_mnemonic_to_seed(bip39_mnemonic, "", bip39_seed)) {
            fprintf(stderr, "BIP39: seed derivation FAILED\n");
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        printf("  Seed: OK (64 bytes)\n");

        if (!hd_key_derive_path(bip39_seed, 64, "m/1039'/0'/0'", lsp_seckey)) {
            fprintf(stderr, "BIP39: key derivation FAILED\n");
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        memset(bip39_seed, 0, 64);

        if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_seckey)) {
            fprintf(stderr, "BIP39: keypair creation FAILED\n");
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }

        secp256k1_pubkey bip39_pk;
        secp256k1_keypair_pub(ctx, &bip39_pk, &lsp_kp);
        unsigned char bip39_pub33[33];
        size_t bip39_pub33_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, bip39_pub33, &bip39_pub33_len,
                                      &bip39_pk, SECP256K1_EC_COMPRESSED);
        printf("  LSP key (m/1039'/0'/0'): ");
        for (int i = 0; i < 33; i++) printf("%02x", bip39_pub33[i]);
        printf("\n  Proceeding with factory creation using HD-derived key...\n");
        fflush(stdout);
    }

    /* Initialize bitcoin-cli connection */
    regtest_t rt;
    int rt_ok;
    if (cli_path || rpcuser || rpcpassword || datadir || rpcport) {
        rt_ok = regtest_init_full(&rt, network, cli_path, rpcuser, rpcpassword,
                                  datadir, rpcport);
    } else {
        rt_ok = regtest_init_network(&rt, network);
    }
    if (!rt_ok && !light_client_arg) {
        fprintf(stderr, "Error: cannot connect to bitcoind (is it running with -%s?)\n"
                        "       Pass --light-client HOST:PORT to use P2P without bitcoind.\n",
                network);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    /* Auto-create/load wallet (handles "already exists" gracefully) */
    if (rt_ok)
        regtest_create_wallet(&rt, wallet_name ? wallet_name : "superscalar_lsp");

    /* Initialize fee estimator.
       Priority: --fee-estimator arg > auto-select (rpc when bitcoind up,
       blocks when --light-client, static otherwise).
       --dynamic-fees kept for CLI compat (treated as --fee-estimator rpc). */
    (void)dynamic_fees;
    fee_estimator_rpc_t    fee_est_rpc;
    fee_estimator_static_t fee_est_static;
    fee_estimator_blocks_t fee_est_blocks;
    fee_estimator_api_t    fee_est_api;
    fee_estimator_t *fee_est_ptr = NULL;

    /* Determine mode from --fee-estimator arg */
    const char *fe_mode = fee_estimator_arg;
    if (!fe_mode) {
        /* Auto-select: prefer rpc when bitcoind is up */
        if (rt_ok)       fe_mode = "rpc";
        else if (light_client_arg) fe_mode = "blocks";
        else             fe_mode = "static";
    }

    if (strcmp(fe_mode, "rpc") == 0) {
        if (!rt_ok) {
            fprintf(stderr, "LSP: --fee-estimator rpc requires bitcoind (use --cli-path)\n");
            secp256k1_context_destroy(ctx); return 1;
        }
        fee_estimator_rpc_init(&fee_est_rpc, &rt);
        fee_est_ptr = &fee_est_rpc.base;
        uint64_t initial = fee_est_ptr->get_rate(fee_est_ptr, FEE_TARGET_NORMAL);
        printf("LSP: fee estimator: rpc (estimatesmartfee), current=%llu sat/kvB\n",
               (unsigned long long)(initial ? initial : fee_rate));
    } else if (strcmp(fe_mode, "blocks") == 0) {
        fee_estimator_blocks_init(&fee_est_blocks);
        fee_est_ptr = &fee_est_blocks.base;
        printf("LSP: fee estimator: blocks (BIP 133 feefilter + block-derived)\n");
    } else if (strncmp(fe_mode, "api:", 4) == 0) {
        fee_estimator_api_init(&fee_est_api, fe_mode + 4, NULL, NULL);
        fee_est_ptr = &fee_est_api.base;
        printf("LSP: fee estimator: api (%s)\n", fe_mode + 4);
    } else if (strcmp(fe_mode, "api") == 0) {
        fee_estimator_api_init(&fee_est_api, NULL, NULL, NULL);
        fee_est_ptr = &fee_est_api.base;
        printf("LSP: fee estimator: api (mempool.space)\n");
    } else if (strncmp(fe_mode, "static:", 7) == 0) {
        uint64_t r = (uint64_t)strtoull(fe_mode + 7, NULL, 10) * 1000;
        if (r == 0) r = fee_rate;
        fee_estimator_static_init(&fee_est_static, r);
        fee_est_ptr = &fee_est_static.base;
        printf("LSP: fee estimator: static (%llu sat/kvB)\n", (unsigned long long)r);
    } else {
        /* Unknown / "static" without value */
        fee_estimator_static_init(&fee_est_static, fee_rate);
        fee_est_ptr = &fee_est_static.base;
        printf("LSP: fee estimator: static (%llu sat/kvB)\n", (unsigned long long)fee_rate);
    }
    /* Alias fee_est for existing code below that references fee_est */
    fee_estimator_t *fee_est = fee_est_ptr;

    /* === Chain backend and wallet source (mode-agnostic) === */
    static chain_backend_t g_chain_be_rpc;
    static wallet_source_rpc_t g_ws_rpc;
    chain_backend_t *chain_be;
    wallet_source_t *wallet_src;

    if (rt_ok) {
        chain_backend_regtest_init(&g_chain_be_rpc, &rt);
        chain_be = &g_chain_be_rpc;
        if (g_hd_wallet) {
            /* HD wallet available: use it for UTXO selection + signing,
               use RPC chain backend for monitoring + broadcasting */
            wallet_src = &g_hd_wallet->base;
            printf("LSP: using HD wallet for factory funding (RPC for chain)\n");
        } else {
            wallet_source_rpc_init(&g_ws_rpc, &rt);
            wallet_src = &g_ws_rpc.base;
        }
    } else {
        chain_be = (chain_backend_t *)&g_bip158;
        wallet_src = g_hd_wallet ? &g_hd_wallet->base : NULL;
    }

    /* Apply confirmation depth overrides.
       --safe-confs sets all four; per-operation flags override individually. */
    if (safe_confs_arg > 0) {
        conf_targets_set_all(&chain_be->conf, safe_confs_arg);
        printf("LSP: all confirmation depths set to %d (--safe-confs)\n",
               safe_confs_arg);
    }
    if (funding_confs_arg > 0) chain_be->conf.funding = funding_confs_arg;
    if (close_confs_arg > 0)   chain_be->conf.close   = close_confs_arg;
    if (penalty_confs_arg > 0) chain_be->conf.penalty = penalty_confs_arg;
    if (sweep_confs_arg > 0)   chain_be->conf.sweep   = sweep_confs_arg;
    if (funding_confs_arg || close_confs_arg || penalty_confs_arg || sweep_confs_arg) {
        printf("LSP: confirmation depths — funding=%d close=%d penalty=%d sweep=%d\n",
               chain_be->conf.funding, chain_be->conf.close,
               chain_be->conf.penalty, chain_be->conf.sweep);
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
            /* Heap-allocate lsp_t — factory_t embedded inside is ~3MB */
            lsp_t *lsp_rp = calloc(1, sizeof(lsp_t));
            if (!lsp_rp) {
                fprintf(stderr, "LSP recovery: lsp_t alloc failed\n");
                free(rec_f);
                persist_close(&db);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            
            if (!lsp_init(lsp_rp, ctx, &lsp_kp, port, rec_f->n_participants - 1)) {
                fprintf(stderr, "LSP recovery: lsp_init failed\n");
                free(lsp_rp);
                free(rec_f);
                persist_close(&db);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            g_lsp = lsp_rp;
            lsp_rp->use_nk = 1;
            memcpy(lsp_rp->nk_seckey, lsp_seckey, 32);

            signal(SIGINT, sigint_handler);
            signal(SIGTERM, sigint_handler);

            /* Open listen socket for reconnections */
            lsp_rp->listen_fd = wire_listen(bind_addr, lsp_rp->port);
            if (lsp_rp->listen_fd < 0) {
                fprintf(stderr, "LSP recovery: listen failed on port %d\n", port);
                persist_close(&db);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Populate pubkeys from recovered factory */
            size_t rec_n_clients = rec_f->n_participants - 1;
            lsp_rp->n_clients = rec_n_clients;
            for (size_t i = 0; i < rec_n_clients; i++)
                lsp_rp->client_pubkeys[i] = rec_f->pubkeys[i + 1];

            /* Copy factory and set fee estimator */
            lsp_rp->factory = *rec_f;
            free(rec_f);
            rec_f = NULL;
            lsp_rp->factory.fee = fee_est;

            /* Load DW counter state from DB */
            {
                uint32_t epoch_out, n_layers_out;
                uint32_t layer_states_out[DW_MAX_LAYERS];
                if (persist_load_dw_counter(&db, 0, &epoch_out, &n_layers_out,
                                              layer_states_out, DW_MAX_LAYERS)) {
                    for (uint32_t li = 0; li < n_layers_out &&
                         li < lsp_rp->factory.counter.n_layers; li++)
                        lsp_rp->factory.counter.layers[li].current_state =
                            layer_states_out[li];
                    printf("LSP recovery: DW counter loaded (epoch %u)\n",
                           dw_counter_epoch(&lsp_rp->factory.counter));
                }
            }

            /* Set factory lifecycle from current block height */
            {
                int cur_height = regtest_get_block_height(&rt);
                if (cur_height > 0)
                    factory_set_lifecycle(&lsp_rp->factory, (uint32_t)cur_height,
                                          active_blocks, dying_blocks);
            }

            /* Initialize channels from DB */
            lsp_channel_mgr_t *mgr = calloc(1, sizeof(lsp_channel_mgr_t));
            if (!mgr) { fprintf(stderr, "LSP: alloc failed\n"); lsp_cleanup(lsp_rp); return 1; }
            g_channel_mgr = mgr;
            mgr->fee = fee_est;
            if (!lsp_channels_init_from_db(mgr, ctx, &lsp_rp->factory, lsp_seckey,
                                             rec_n_clients, &db)) {
                fprintf(stderr, "LSP recovery: channel init from DB failed\n");
                free(mgr);
                lsp_cleanup(lsp_rp);
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
            watchtower_init(&rec_wt, mgr->n_channels, &rt, fee_est, &db);
            for (size_t c = 0; c < mgr->n_channels; c++)
                watchtower_set_channel(&rec_wt, c, &mgr->entries[c].channel);
            mgr->watchtower = &rec_wt;

            if (bump_budget_pct > 0) rec_wt.bump_budget_pct = bump_budget_pct;
            if (max_bump_fee > 0) rec_wt.max_bump_fee_sat = max_bump_fee;
            mgr->chain_be  = chain_be;
            mgr->wallet_src = wallet_src;
            if (light_client_arg) {
                attach_light_client(&rec_wt, use_db ? &db : NULL,
                                    light_client_arg, network,
                                    lc_fallbacks, n_lc_fallbacks, fee_est);
                if (!rt_ok)
                    attach_hd_wallet(&rec_wt, use_db ? &db : NULL, ctx, network,
                                     hd_mnemonic, hd_passphrase, hd_lookahead);
            }

            /* Initialize ladder (heap — ladder_t is ~26MB with 8 factories) */
            ladder_t *rec_lad_p = calloc(1, sizeof(ladder_t));
            if (!rec_lad_p) {
                fprintf(stderr, "LSP recovery: ladder alloc failed\n");
                persist_close(&db);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            #define rec_lad (*rec_lad_p)
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
                lf->factory = lsp_rp->factory;
                factory_detach_txbufs(&lf->factory);
                lf->factory_id = rec_lad.next_factory_id++;
                lf->is_initialized = 1;
                lf->is_funded = 1;
                lf->cached_state = factory_get_state(&lsp_rp->factory,
                                                       rec_lad.current_block);
                tx_buf_init(&lf->distribution_tx, 256);
                rec_lad.n_factories = 1;
            }
            mgr->ladder = &rec_lad;
            #undef rec_lad

            /* Wire rotation parameters */
            memcpy(mgr->rot_lsp_seckey, lsp_seckey, 32);
            mgr->rot_fee_est = fee_est;
            memcpy(mgr->rot_fund_spk, lsp_rp->factory.funding_spk,
                   lsp_rp->factory.funding_spk_len);
            mgr->rot_fund_spk_len = lsp_rp->factory.funding_spk_len;

            /* Derive funding + mining addresses for rotation */
            {
                musig_keyagg_t ka;
                secp256k1_pubkey all_pks[FACTORY_MAX_SIGNERS];
                for (size_t i = 0; i < lsp_rp->factory.n_participants; i++)
                    all_pks[i] = lsp_rp->factory.pubkeys[i];
                musig_aggregate_keys(ctx, &ka, all_pks,
                                       lsp_rp->factory.n_participants);
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

            /* Async rotation coordination */
            if (async_rotation) {
                readiness_tracker_t *rt = calloc(1, sizeof(readiness_tracker_t));
                if (rt) mgr->readiness = rt;
                notify_t *nfy = calloc(1, sizeof(notify_t));
                if (nfy) {
                    if (notify_webhook)
                        notify_init_webhook(nfy, notify_webhook);
                    else if (notify_exec)
                        notify_init_exec(nfy, notify_exec);
                    else
                        notify_init_log(nfy);
                    mgr->notify = nfy;
                }
                printf("LSP: async rotation enabled\n");
            }

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

            /* Admin RPC: initialize for recovery daemon mode */
            if (rpc_file_arg) {
                payment_init(&g_payments);
                invoice_init(&g_invoice_tbl);
                memset(&g_admin_rpc, 0, sizeof(g_admin_rpc));
                g_admin_rpc.ctx           = ctx;
                memcpy(g_admin_rpc.node_privkey, lsp_seckey, 32);
                g_admin_rpc.channel_mgr   = mgr;
                g_admin_rpc.lsp           = lsp_rp;
                strncpy(g_admin_rpc.network, network, sizeof(g_admin_rpc.network) - 1);
                g_admin_rpc.payments      = &g_payments;
                g_admin_rpc.invoices      = &g_invoice_tbl;
                g_admin_rpc.shutdown_flag = (volatile int *)&g_shutdown;
                if (admin_rpc_init(&g_admin_rpc, rpc_file_arg)) {
                    printf("LSP: admin RPC socket at %s\n", rpc_file_arg);
                    mgr->admin_rpc = &g_admin_rpc;
                } else {
                    fprintf(stderr, "LSP: warning: failed to bind admin RPC socket %s\n",
                            rpc_file_arg);
                }
            }

            lsp_channels_run_daemon_loop(mgr, lsp_rp, &g_shutdown);

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
            lsp_cleanup(lsp_rp);
            
            free(lsp_rp);
            free(rec_lad_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 0;
        }
    }

    /* === Phase 1: Accept clients === */
    uint32_t factory_generation = 0;  /* increments each factory lifecycle */

accept_new_factory:
    printf("LSP: listening on port %d, waiting for %d clients...\n", port, n_clients);
    fflush(stdout);

    /* Heap-allocate lsp_t — factory_t embedded inside is ~3MB at MAX_SIGNERS=64 */
    lsp_t *lsp_p = calloc(1, sizeof(lsp_t));
    if (!lsp_p) {
        fprintf(stderr, "LSP: failed to allocate lsp_t\n");
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    
    if (!lsp_init(lsp_p, ctx, &lsp_kp, port, (size_t)n_clients)) {
        fprintf(stderr, "LSP: lsp_init failed\n");
        free(lsp_p);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    g_lsp = lsp_p;
    lsp_p->accept_timeout_sec = accept_timeout_arg;
    if (max_connections_arg > 0)
        lsp_p->max_connections = max_connections_arg;
    rate_limiter_init(&lsp_p->rate_limiter, max_conn_rate_arg, 60, max_handshakes_arg);

    /* Enable NK (server-authenticated) noise handshake */
    lsp_p->use_nk = 1;
    memcpy(lsp_p->nk_seckey, lsp_seckey, 32);
    {
        secp256k1_pubkey nk_pub;
        if (!secp256k1_ec_pubkey_create(ctx, &nk_pub, lsp_seckey)) {
            fprintf(stderr, "LSP: failed to derive NK static pubkey\n");
            lsp_cleanup(lsp_p);
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

        if (use_clnbridge)
            printf("LSP: inbound HTLC routing: CLN bridge (--clnbridge)\n");
        else
            printf("LSP: inbound HTLC routing: native (fake-SCID / htlc_inbound)\n");

        if (gossip_peers[0]) {
            printf("LSP: gossip peers configured: %s\n", gossip_peers);

            static gossip_store_t s_gossip_store;
            static int s_gossip_store_opened = 0;
            if (!s_gossip_store_opened) {
                const char *gdb_path = db_path ? db_path : ":memory:";
                s_gossip_store_opened = gossip_store_open(&s_gossip_store, gdb_path);
                if (s_gossip_store_opened)
                    g_gossip_store_ptr = &s_gossip_store;
            }

            if (s_gossip_store_opened) {
                static gossip_peer_mgr_cfg_t s_gp_cfg;
                memset(&s_gp_cfg, 0, sizeof(s_gp_cfg));
                s_gp_cfg.n_peers = gossip_peer_parse_list(gossip_peers,
                    s_gp_cfg.peers, GOSSIP_PEER_MAX);
                s_gp_cfg.ctx = ctx;
                s_gp_cfg.store = &s_gossip_store;
                memcpy(s_gp_cfg.our_priv32, lsp_p->nk_seckey, 32);
                s_gp_cfg.network = network;
                s_gp_cfg.shutdown_flag = (volatile int *)&g_shutdown;

                if (s_gp_cfg.n_peers > 0) {
                    static pthread_t s_gp_tids[GOSSIP_PEER_MAX];
                    int started = gossip_peer_mgr_start(&s_gp_cfg, s_gp_tids);
                    if (started > 0)
                        printf("LSP: gossip peer manager started (%d peers)\n",
                               started);
                    else
                        fprintf(stderr, "LSP: warning: gossip peer manager failed to start\n");
                }
            }
        } else
            printf("LSP: gossip peers: none configured (use --gossip-peers HOST:PORT,...)\n");

        if (bolt8_listen_port > 0) {
            /* Initialise LN payment/forward/MPP tables */
            peer_mgr_init(&g_peer_mgr, ctx, lsp_p->nk_seckey);
            htlc_forward_init(&g_fwd);
            mpp_init(&g_mpp);
            payment_init(&g_payments);
            invoice_init(&g_invoice_tbl);

            memset(&g_bolt8_cfg, 0, sizeof(g_bolt8_cfg));
            g_bolt8_cfg.bolt8_port = bolt8_listen_port;
            memcpy(g_bolt8_cfg.static_priv, lsp_p->nk_seckey, 32);
            g_bolt8_cfg.ctx = ctx;
            g_bolt8_cfg.peer_mgr = &g_peer_mgr;
            g_bolt8_cfg.ln_dispatch = &g_ln_dispatch;
            pthread_t bolt8_tid;
            if (pthread_create(&bolt8_tid, NULL, bolt8_server_thread, NULL) == 0) {
                pthread_detach(bolt8_tid);
                printf("LSP: BOLT #8 server listening on port %u\n",
                       (unsigned)bolt8_listen_port);
            } else {
                fprintf(stderr,
                        "LSP: warning: failed to start BOLT #8 server on port %u\n",
                        (unsigned)bolt8_listen_port);
            }

            /* Spawn LN peer message dispatch thread */
            memset(&g_ln_dispatch, 0, sizeof(g_ln_dispatch));
            g_ln_dispatch.pmgr         = &g_peer_mgr;
            g_ln_dispatch.fwd          = &g_fwd;
            g_ln_dispatch.mpp          = &g_mpp;
            g_ln_dispatch.payments     = &g_payments;
            g_ln_dispatch.ctx          = ctx;
            g_ln_dispatch.shutdown_flag = (volatile int *)&g_shutdown;
            memcpy(g_ln_dispatch.our_privkey, lsp_p->nk_seckey, 32);
            g_ln_dispatch.invoices = &g_invoice_tbl;

            /* Wire LSPS0 callback */
            memset(&g_lsps_ctx, 0, sizeof(g_lsps_ctx));
            g_lsps_ctx.mgr = g_channel_mgr;
            g_lsps_ctx.lsp = g_lsp;
            g_bolt8_cfg.lsps0_request_cb = lsps0_bolt8_cb;
            g_bolt8_cfg.cb_userdata      = &g_lsps_ctx;

            /* Wire Tor proxy for .onion outbound peers */
            if (tor_proxy_arg) {
                char px_host[256]; int px_port;
                if (tor_parse_proxy_arg(tor_proxy_arg, px_host, sizeof(px_host), &px_port))
                    peer_mgr_set_proxy(&g_peer_mgr, px_host, px_port);
            }

            /* Watchtower: init and wire into dispatch */
            watchtower_init(&g_watchtower, g_channel_mgr->n_channels, NULL, fee_est, g_db);

            if (bump_budget_pct > 0) g_watchtower.bump_budget_pct = bump_budget_pct;
            if (max_bump_fee > 0) g_watchtower.max_bump_fee_sat = max_bump_fee;
            if (g_bip158.base.get_block_height)
                watchtower_set_chain_backend(&g_watchtower, &g_bip158.base);
            if (g_hd_wallet)
                watchtower_set_wallet(&g_watchtower, &g_hd_wallet->base);
            for (size_t _wi = 0; _wi < g_channel_mgr->n_channels; _wi++)
                watchtower_set_channel(&g_watchtower, _wi,
                                       &g_channel_mgr->entries[_wi].channel);
            g_watchtower_ready = 1;
            g_ln_dispatch.watchtower  = &g_watchtower;
            g_ln_dispatch.scb_path    = scb_path_arg; /* NULL = disabled */
    g_ln_dispatch.jit_pending = &g_lsps2_pending;
    g_ln_dispatch.jit_open_cb = on_jit_open;
    g_ln_dispatch.jit_cb_ctx  = NULL;

            pthread_t dispatch_tid;
            if (pthread_create(&dispatch_tid, NULL, ln_dispatch_thread, NULL) == 0) {
                pthread_detach(dispatch_tid);
                printf("LSP: LN peer dispatch thread started\n");
            } else {
                fprintf(stderr, "LSP: warning: failed to start LN dispatch thread\n");
            }
        }

        /* Admin RPC: wire and start if --rpc-file is given */
        if (rpc_file_arg) {
            memset(&g_admin_rpc, 0, sizeof(g_admin_rpc));
            g_admin_rpc.ctx          = ctx;
            memcpy(g_admin_rpc.node_privkey, lsp_p->nk_seckey, 32);
            g_admin_rpc.pmgr         = &g_peer_mgr;
            g_admin_rpc.channel_mgr  = g_channel_mgr;
            g_admin_rpc.payments     = &g_payments;
            g_admin_rpc.invoices     = &g_invoice_tbl;
            g_admin_rpc.gossip       = g_gossip_store_ptr;
            g_admin_rpc.fwd          = &g_fwd;
            g_admin_rpc.mpp          = &g_mpp;
            g_admin_rpc.shutdown_flag = (volatile int *)&g_shutdown;
            g_admin_rpc.block_height = NULL; /* TODO: wire block height in PR#28 */
            if (admin_rpc_init(&g_admin_rpc, rpc_file_arg))
                printf("LSP: admin RPC socket at %s\n", rpc_file_arg);
            else
                fprintf(stderr, "LSP: warning: failed to bind admin RPC socket %s\n",
                        rpc_file_arg);
        }

        if (well_known_port > 0) {
            char wk_pubkey[67] = {0};
            secp256k1_pubkey wk_pub;
            if (secp256k1_ec_pubkey_create(ctx, &wk_pub, lsp_seckey)) {
                unsigned char wk_ser[33]; size_t wk_len = 33;
                secp256k1_ec_pubkey_serialize(ctx, wk_ser, &wk_len, &wk_pub,
                                              SECP256K1_EC_COMPRESSED);
                hex_encode(wk_ser, 33, wk_pubkey);
            }
            lsp_wellknown_cfg_t wk_cfg = {
                .pubkey_hex       = wk_pubkey,
                .host             = bind_addr ? bind_addr : "",
                .bolt8_port       = (uint16_t)port,
                .native_port      = (uint16_t)port,
                .network          = network,
                .fee_ppm          = (uint32_t)routing_fee_ppm,
                .min_channel_sats = 100000,
                .max_channel_sats = 10000000,
                .version          = SUPERSCALAR_VERSION,
            };
            if (lsp_wellknown_serve_fork(&wk_cfg, well_known_port))
                printf("LSP: well-known HTTP server on port %u\n",
                       (unsigned)well_known_port);
            else
                fprintf(stderr,
                        "LSP: warning: well-known server on port %u failed\n",
                        (unsigned)well_known_port);
        }
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    if (!lsp_accept_clients(lsp_p)) {
        fprintf(stderr, "LSP: failed to accept clients\n");
        lsp_cleanup(lsp_p);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    printf("LSP: all %d clients connected\n", n_clients);

    /* Disable socket timeout during ceremony — on-chain funding confirmation
       can take 10+ minutes on signet/testnet */
    for (size_t i = 0; i < lsp_p->n_clients; i++)
        wire_set_timeout(lsp_p->client_fds[i], 0);

    /* Set peer labels for wire logging (Phase 22) */
    for (size_t i = 0; i < lsp_p->n_clients; i++) {
        char label[32];
        snprintf(label, sizeof(label), "client_%zu", i);
        wire_set_peer_label(lsp_p->client_fds[i], label);
    }

    /* Report: participants */
    report_begin_section(&rpt, "participants");
    report_add_pubkey(&rpt, "lsp", ctx, &lsp_p->lsp_pubkey);
    report_begin_array(&rpt, "clients");
    for (size_t i = 0; i < lsp_p->n_clients; i++)
        report_add_pubkey(&rpt, NULL, ctx, &lsp_p->client_pubkeys[i]);
    report_end_array(&rpt);
    report_end_section(&rpt);
    report_flush(&rpt);

    if (g_shutdown) {
        lsp_abort_ceremony(lsp_p, "LSP shutting down");
        lsp_cleanup(lsp_p);
        secp256k1_context_destroy(ctx);
        return 1;
    }

    /* === Phase 2: Compute funding address === */
    size_t n_total = 1 + lsp_p->n_clients;
    secp256k1_pubkey all_pks[FACTORY_MAX_SIGNERS];
    all_pks[0] = lsp_p->lsp_pubkey;
    for (size_t i = 0; i < lsp_p->n_clients; i++)
        all_pks[i + 1] = lsp_p->client_pubkeys[i];

    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, all_pks, n_total);

    /* Compute tweaked xonly pubkey for P2TR */
    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) {
        fprintf(stderr, "LSP: xonly serialize failed\n");
        lsp_cleanup(lsp_p);
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
        lsp_cleanup(lsp_p);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) {
        fprintf(stderr, "LSP: xonly from pubkey failed\n");
        lsp_cleanup(lsp_p);
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
        lsp_cleanup(lsp_p);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 1;
    }

    char fund_addr[128];
    if (rt_ok) {
        if (!regtest_derive_p2tr_address(&rt, tweaked_ser, fund_addr, sizeof(fund_addr))) {
            fprintf(stderr, "LSP: failed to derive funding address\n");
            lsp_cleanup(lsp_p);
            secp256k1_context_destroy(ctx);
            return 1;
        }
    } else {
        /* Light-client: display SPK hex as address proxy */
        static const char hx[] = "0123456789abcdef";
        for (int ii = 0; ii < 34; ii++) {
            fund_addr[ii*2]   = hx[(fund_spk[ii]>>4)&0xf];
            fund_addr[ii*2+1] = hx[ fund_spk[ii]    &0xf];
        }
        fund_addr[68] = '\0';
    }
    printf("LSP: funding address: %s\n", fund_addr);

    /* === Phase 3: Fund the factory === */
    char mine_addr[128] = {0};
    if (rt_ok) {
        if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) {
            fprintf(stderr, "LSP: failed to get mining address\n");
            lsp_cleanup(lsp_p);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        if (is_regtest) {
            regtest_mine_blocks(&rt, 101, mine_addr);
            if (!ensure_funded(&rt, mine_addr)) {
                fprintf(stderr, "LSP: failed to fund wallet (exhausted regtest?)\n");
                lsp_cleanup(lsp_p);
                secp256k1_context_destroy(ctx);
                return 1;
            }
        } else {
            double bal = regtest_get_balance(&rt);
            double needed = (double)funding_sats / 100000000.0;
            if (bal < needed) {
                fprintf(stderr, "LSP: wallet balance %.8f BTC insufficient (need %.8f). "
                        "Fund via faucet first.\n", bal, needed);
                lsp_cleanup(lsp_p);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("LSP: wallet balance: %.8f BTC (sufficient)\n", bal);
        }
    } else {
        /* Light-client mode: HD wallet must be pre-funded externally */
        if (!wallet_src) {
            fprintf(stderr, "LSP: no wallet available in light-client mode\n");
            lsp_cleanup(lsp_p);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        printf("LSP: light-client mode — HD wallet must be pre-funded at %s\n", fund_addr);
    }

    char funding_txid_hex[65];
    if (g_hd_wallet && wallet_src) {
        /* HD wallet mode: fund via wallet_source_t interface (works with
           both RPC chain backend and BIP158 lite client) */
        printf("LSP: funding factory via HD wallet (%llu sats)...\n",
               (unsigned long long)funding_sats);
        if (!lsp_fund_spk(wallet_src, chain_be,
                          fund_spk, sizeof(fund_spk),
                          funding_sats, fee_rate, funding_txid_hex)) {
            fprintf(stderr, "LSP: HD wallet factory funding failed\n");
            lsp_cleanup(lsp_p);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        if (is_regtest) {
            regtest_mine_blocks(&rt, 1, mine_addr);
        } else {
            printf("LSP: waiting for funding tx confirmation on %s...\n", network);
            int conf = lsp_wait_for_confirmation_service(chain_be, funding_txid_hex,
                                                   confirm_timeout_secs,
                                                   chain_funding_confs(chain_be, chain_be->is_regtest), NULL, lsp_p);
            if (conf < 1) {
                fprintf(stderr, "LSP: funding tx not confirmed within timeout\n");
                lsp_cleanup(lsp_p);
                secp256k1_context_destroy(ctx);
                return 1;
            }
        }
    } else if (rt_ok) {
        double funding_btc = (double)funding_sats / 100000000.0;
        if (!regtest_fund_address(&rt, fund_addr, funding_btc, funding_txid_hex)) {
            fprintf(stderr, "LSP: failed to fund factory address\n");
            lsp_cleanup(lsp_p);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        if (is_regtest) {
            regtest_mine_blocks(&rt, 1, mine_addr);
        } else {
            printf("LSP: waiting for funding tx confirmation on %s...\n", network);
            int conf = wait_for_confirmation_servicing(&rt, funding_txid_hex,
                                                         confirm_timeout_secs,
                                                         lsp_p, NULL);
            if (!conf) {
                fprintf(stderr, "LSP: funding tx not confirmed within timeout\n");
                lsp_cleanup(lsp_p);
                secp256k1_context_destroy(ctx);
                return 1;
            }
        }
    } else {
        if (!lsp_fund_spk(wallet_src, chain_be,
                          fund_spk, sizeof(fund_spk),
                          funding_sats, fee_rate, funding_txid_hex)) {
            fprintf(stderr, "LSP: light-client factory funding failed\n");
            lsp_cleanup(lsp_p);
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
        lsp_cleanup(lsp_p);
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
        lsp_abort_ceremony(lsp_p, "LSP shutting down");
        lsp_cleanup(lsp_p);
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
            /* Auto: regtest +35 blocks, non-regtest = factory lifetime + 10 block buffer */
            int offset = is_regtest ? 35 : (int)(active_blocks + dying_blocks + 10);
            cltv_timeout = (uint32_t)cur_height + offset;
        }
    }

    printf("LSP: CLTV timeout: block %u (current: %d)\n",
           cltv_timeout, regtest_get_block_height(&rt));
    if (n_level_arity > 0)
        factory_set_level_arity(&lsp_p->factory, level_arities, n_level_arity);
    else if (leaf_arity == 1)
        factory_set_arity(&lsp_p->factory, FACTORY_ARITY_1);
    lsp_p->factory.placement_mode = (placement_mode_t)placement_mode_arg;
    lsp_p->factory.economic_mode = (economic_mode_t)economic_mode_arg;

    /* Populate default profiles from CLI config */
    for (size_t pi = 0; pi < (size_t)(1 + n_clients) && pi < FACTORY_MAX_SIGNERS; pi++) {
        lsp_p->factory.profiles[pi].participant_idx = (uint32_t)pi;
        if (pi == 0) {
            /* LSP gets remainder of profit share */
            lsp_p->factory.profiles[pi].profit_share_bps =
                (uint16_t)(10000 - (uint32_t)default_profit_bps * (uint32_t)n_clients);
        } else {
            lsp_p->factory.profiles[pi].profit_share_bps = default_profit_bps;
        }
        lsp_p->factory.profiles[pi].contribution_sats = funding_sats / (uint64_t)(1 + n_clients);
        lsp_p->factory.profiles[pi].uptime_score = 1.0f;
        lsp_p->factory.profiles[pi].timezone_bucket = 0;
    }

    /* If --test-burn, enable L-stock revocation before tree construction.
       Uses flat secrets (per ZmnSCPxj: no multi-party shachain method exists,
       just store all revocation keys independently).
       State is preserved across factory_init_from_pubkeys() in lsp_p->c. */
    if (test_burn) {
        if (!factory_generate_flat_secrets(&lsp_p->factory, 16)) {
            fprintf(stderr, "LSP: failed to generate flat revocation secrets\n");
            lsp_cleanup(lsp_p);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        printf("LSP: flat revocation secrets generated for burn test (%zu epochs)\n",
               lsp_p->factory.n_revocation_secrets);
    }

    printf("LSP: starting factory creation ceremony...\n");
    {
        int creation_ok = 0;
        for (int attempt = 0; attempt < 3; attempt++) {
            if (attempt > 0) {
                printf("LSP: factory creation retry %d/3...\n", attempt + 1);
                /* Brief pause for clients to stabilize */
                sleep(5);
            }
            if (lsp_run_factory_creation(lsp_p,
                                          funding_txid, funding_vout,
                                          funding_amount,
                                          fund_spk, 34,
                                          step_blocks, 4, cltv_timeout)) {
                creation_ok = 1;
                break;
            }
            fprintf(stderr, "LSP: factory creation attempt %d failed\n", attempt + 1);
        }
        if (!creation_ok) {
            fprintf(stderr, "LSP: factory creation failed after 3 attempts\n");
            lsp_cleanup(lsp_p);
            secp256k1_context_destroy(ctx);
            return 1;
        }
    }
    printf("LSP: factory creation complete! (%zu nodes signed)\n", lsp_p->factory.n_nodes);

    /* Set factory lifecycle */
    {
        int cur_height = regtest_get_block_height(&rt);
        if (cur_height > 0) {
            factory_set_lifecycle(&lsp_p->factory, (uint32_t)cur_height,
                                  active_blocks, dying_blocks);
            printf("LSP: factory lifecycle set at height %d "
                   "(active=%u, dying=%u, CLTV=%u)\n",
                   cur_height, active_blocks, dying_blocks,
                   lsp_p->factory.cltv_timeout);
        }
    }

    /* Log DW counter initial state */
    {
        uint32_t epoch = dw_counter_epoch(&lsp_p->factory.counter);
        printf("LSP: DW epoch %u/%u (nSeq delays:", epoch,
               lsp_p->factory.counter.total_states);
        for (uint32_t li = 0; li < lsp_p->factory.counter.n_layers; li++) {
            uint16_t d = dw_delay_for_state(&lsp_p->factory.counter.layers[li].config,
                                              lsp_p->factory.counter.layers[li].current_state);
            printf(" L%u=%u", li, d);
        }
        printf(" blocks)\n");
    }

    /* Set fee estimator on factory (for computed fees) */
    lsp_p->factory.fee = fee_est;

    /* === Ladder manager initialization (Tier 2) === */
    ladder_t *lad = calloc(1, sizeof(ladder_t));
    if (!lad) { fprintf(stderr, "LSP: alloc failed\n"); lsp_cleanup(lsp_p); return 1; }
    if (!ladder_init(lad, ctx, &lsp_kp, active_blocks, dying_blocks)) {
        fprintf(stderr, "LSP: ladder_init failed\n");
        free(lad);
        lsp_cleanup(lsp_p);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    {
        int cur_h = regtest_get_block_height(&rt);
        if (cur_h > 0) lad->current_block = (uint32_t)cur_h;
    }
    /* Populate slot 0 with the existing factory (detached copy — no shared
       tx_buf heap data, preventing double-free if lsp_p->factory is freed later). */
    {
        ladder_factory_t *lf = &lad->factories[0];
        lf->factory = lsp_p->factory;
        factory_detach_txbufs(&lf->factory);
        lf->factory_id = lad->next_factory_id++;
        lf->is_initialized = 1;
        lf->is_funded = 1;
        lf->cached_state = factory_get_state(&lsp_p->factory,
                                               lad->current_block);
        /* Copy signed distribution TX from ceremony (if available) */
        tx_buf_init(&lf->distribution_tx, 256);
        if (lsp_p->factory.dist_tx_ready && lsp_p->factory.dist_unsigned_tx.len > 0) {
            /* dist_unsigned_tx holds the signed version after ceremony */
            tx_buf_free(&lf->distribution_tx);
            tx_buf_init(&lf->distribution_tx, lsp_p->factory.dist_unsigned_tx.len);
            memcpy(lf->distribution_tx.data, lsp_p->factory.dist_unsigned_tx.data,
                   lsp_p->factory.dist_unsigned_tx.len);
            lf->distribution_tx.len = lsp_p->factory.dist_unsigned_tx.len;
            printf("LSP: distribution TX stored (%zu bytes)\n",
                   lf->distribution_tx.len);
        }
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
            if (!persist_save_factory(&db, &lsp_p->factory, ctx, 0)) {
                fprintf(stderr, "LSP: warning: failed to persist factory\n");
                init_ok = 0;
            }
            if (init_ok && !persist_save_tree_nodes(&db, &lsp_p->factory, 0)) {
                fprintf(stderr, "LSP: warning: failed to persist tree nodes\n");
                init_ok = 0;
            }
            if (init_ok) {
                /* Save initial DW counter state — use actual layer count (2 for arity-2, 3 for arity-1) */
                uint32_t init_layers[DW_MAX_LAYERS];
                for (uint32_t li = 0; li < lsp_p->factory.counter.n_layers; li++)
                    init_layers[li] = lsp_p->factory.counter.layers[li].config.max_states;
                persist_save_dw_counter(&db, 0, 0, lsp_p->factory.counter.n_layers, init_layers);
            }
            if (init_ok) {
                /* Save ladder factory state (Tier 2) */
                persist_save_ladder_factory(&db, 0, "active", 1, 1, 0,
                    lsp_p->factory.created_block, lsp_p->factory.active_blocks,
                    lsp_p->factory.dying_blocks, 0);
            }
            if (init_ok)
                persist_commit(&db);
            else
                persist_rollback(&db);
        }
    }

    /* Report: factory tree */
    report_begin_section(&rpt, "factory");
    report_add_uint(&rpt, "n_nodes", lsp_p->factory.n_nodes);
    report_add_uint(&rpt, "n_participants", lsp_p->factory.n_participants);
    report_add_uint(&rpt, "step_blocks", lsp_p->factory.step_blocks);
    report_add_uint(&rpt, "fee_per_tx", lsp_p->factory.fee_per_tx);
    report_factory_tree(&rpt, ctx, &lsp_p->factory);
    report_end_section(&rpt);
    report_flush(&rpt);

    /* === Phase 4b: Channel Operations === */
    lsp_channel_mgr_t *mgr = calloc(1, sizeof(lsp_channel_mgr_t));
    if (!mgr) { fprintf(stderr, "LSP: alloc failed\n"); lsp_cleanup(lsp_p); return 1; }
    g_channel_mgr = mgr;
    /* Update admin RPC channel_mgr (was NULL when RPC was initialized earlier) */
    if (g_admin_rpc.ctx) {
        g_admin_rpc.channel_mgr = mgr;
        g_admin_rpc.lsp = lsp_p;
        strncpy(g_admin_rpc.network, network, sizeof(g_admin_rpc.network) - 1);
    }
    int channels_active = 0;
    uint64_t init_local = 0, init_remote = 0;
    if (n_payments > 0 || daemon_mode || demo_mode || breach_test || test_expiry ||
        test_distrib || test_turnover || test_rotation || test_partial_rotation ||
        force_close || test_burn ||
        test_htlc_force_close || test_multi_htlc_force_close || test_full_settlement ||
        test_rebalance || test_batch_rebalance || test_realloc ||
        test_dual_factory || test_dw_exhibition || test_splice || test_bridge || test_jit || test_bolt12 ||
        test_buy_liquidity || test_large_factory) {
        /* Set fee policy before init (init preserves these across memset) */
        mgr->fee = fee_est;
        mgr->routing_fee_ppm = routing_fee_ppm;
        mgr->lsp_balance_pct = lsp_balance_pct;
        mgr->placement_mode = (placement_mode_t)placement_mode_arg;
        mgr->economic_mode = (economic_mode_t)economic_mode_arg;
        mgr->default_profit_bps = default_profit_bps;
        mgr->settlement_interval_blocks = settlement_interval;
        if (!lsp_channels_init(mgr, ctx, &lsp_p->factory, lsp_seckey, (size_t)n_clients)) {
            fprintf(stderr, "LSP: channel init failed\n");
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        if (!lsp_channels_exchange_basepoints(mgr, lsp_p)) {
            fprintf(stderr, "LSP: basepoint exchange failed\n");
            lsp_cleanup(lsp_p);
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

        /* Do NOT override channel.fee_rate_sat_per_kvb with --fee-rate:
           The channel commitment TX fee rate must match the client, which always
           uses the default 1000 sat/kvB from channel_init. The --fee-rate flag
           controls on-chain transaction fees (funding, sweep) only. */

        if (!lsp_channels_send_ready(mgr, lsp_p)) {
            fprintf(stderr, "LSP: send CHANNEL_READY failed\n");
            lsp_cleanup(lsp_p);
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
        watchtower_init(&wt, mgr->n_channels, &rt, fee_est,
                          use_db ? &db : NULL);
        for (size_t c = 0; c < mgr->n_channels; c++)
            watchtower_set_channel(&wt, c, &mgr->entries[c].channel);
        mgr->watchtower = &wt;

            if (bump_budget_pct > 0) wt.bump_budget_pct = bump_budget_pct;
            if (max_bump_fee > 0) wt.max_bump_fee_sat = max_bump_fee;
        mgr->chain_be  = chain_be;
        mgr->wallet_src = wallet_src;
        if (light_client_arg) {
            attach_light_client(&wt, use_db ? &db : NULL,
                                 light_client_arg, network,
                                 lc_fallbacks, n_lc_fallbacks, fee_est);
            if (!rt_ok)
                attach_hd_wallet(&wt, use_db ? &db : NULL, ctx, network,
                                 hd_mnemonic, hd_passphrase, hd_lookahead);
        }

        /* Wire ladder into channel manager (Tier 2) */
        mgr->ladder = lad;

        /* Wire rotation parameters for continuous ladder (Gap #3) */
        memcpy(mgr->rot_lsp_seckey, lsp_seckey, 32);
        mgr->rot_fee_est = fee_est;
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

        /* Async rotation coordination */
        if (async_rotation) {
            readiness_tracker_t *rt = calloc(1, sizeof(readiness_tracker_t));
            if (rt) mgr->readiness = rt;
            notify_t *nfy = calloc(1, sizeof(notify_t));
            if (nfy) {
                if (notify_webhook)
                    notify_init_webhook(nfy, notify_webhook);
                else if (notify_exec)
                    notify_init_exec(nfy, notify_exec);
                else
                    notify_init_log(nfy);
                mgr->notify = nfy;
            }
            printf("LSP: async rotation enabled\n");
        }

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
            if (!lsp_channels_run_event_loop(mgr, lsp_p, (size_t)(n_payments * 2))) {
                fprintf(stderr, "LSP: event loop failed\n");
                lsp_cleanup(lsp_p);
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
            if (!lsp_channels_run_demo_sequence(mgr, lsp_p)) {
                fprintf(stderr, "LSP: demo sequence failed\n");
            }

            /* Advance DW counter and track new epoch.  We only advance
               the counter here — in production the tree would be re-signed
               via split-round MuSig2 with all participants.  Skip when
               --test-burn is set so the burn test can broadcast the
               correctly-signed epoch-0 tree. */
            if (!test_burn && dw_counter_advance(&lsp_p->factory.counter)) {
                uint32_t epoch = dw_counter_epoch(&lsp_p->factory.counter);
                printf("LSP: DW advanced to epoch %u (delays:", epoch);
                for (uint32_t li = 0; li < lsp_p->factory.counter.n_layers; li++) {
                    uint16_t d = dw_delay_for_state(
                        &lsp_p->factory.counter.layers[li].config,
                        lsp_p->factory.counter.layers[li].current_state);
                    printf(" L%u=%u", li, d);
                }
                printf(" blocks)\n");
                if (use_db) {
                    uint32_t layer_states[DW_MAX_LAYERS];
                    for (uint32_t li = 0; li < lsp_p->factory.counter.n_layers; li++)
                        layer_states[li] = lsp_p->factory.counter.layers[li].current_state;
                    persist_save_dw_counter(&db, 0, epoch,
                                             lsp_p->factory.counter.n_layers,
                                             layer_states);
                }
            }
        }
        channels_active = 1;


        /* Pre-daemon test blocks (dw_advance, dw_exhibition, leaf_advance,
           dual_factory, bridge, force_close, burn, htlc_force_close). */
#include "superscalar_lsp_pre_daemon_tests.inc"


        if (daemon_mode) {
            printf("LSP: channels ready, entering daemon mode...\n");
            fflush(stdout);

            /* Restore default socket timeout for daemon mode health checks */
            for (size_t i = 0; i < lsp_p->n_clients; i++)
                wire_set_timeout(lsp_p->client_fds[i], WIRE_DEFAULT_TIMEOUT_SEC);

            /* Accept bridge connection if available */
            /* (bridge connects asynchronously — handled in daemon loop via select) */

            /* Wire admin RPC into daemon loop if initialized */
            if (g_admin_rpc.listen_fd >= 0)
                mgr->admin_rpc = &g_admin_rpc;

            lsp_channels_run_daemon_loop(mgr, lsp_p, &g_shutdown);
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


    /* Post-daemon test blocks (breach, expiry, distrib, turnover, rebalance,
       batch_rebalance, realloc, jit, lsps2, bolt12, buy_liquidity,
       large_factory, rotation, splice). Extracted for readability. */
#include "superscalar_lsp_post_daemon_tests.inc"


    /* === Phase 5: Cooperative close === */
    if (g_shutdown) {
        lsp_abort_ceremony(lsp_p, "LSP shutting down");
        lsp_cleanup(lsp_p);
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
        n_close_outputs = lsp_channels_build_close_outputs(mgr, &lsp_p->factory,
                                                            close_outputs, 500,
                                                            NULL, 0);
        if (n_close_outputs == 0) {
            fprintf(stderr, "LSP: build close outputs failed\n");
            lsp_cleanup(lsp_p);
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

    if (!lsp_run_cooperative_close(lsp_p, &close_tx, close_outputs, n_close_outputs,
                                      chain_be ? (uint32_t)chain_be->get_block_height(chain_be) :
                                      (uint32_t)regtest_get_block_height(&rt))) {
        fprintf(stderr, "LSP: cooperative close failed\n");
        tx_buf_free(&close_tx);
        lsp_cleanup(lsp_p);
        secp256k1_context_destroy(ctx);
        return 1;
    }

    /* Broadcast close tx */
    char close_hex[close_tx.len * 2 + 1];
    hex_encode(close_tx.data, close_tx.len, close_hex);
    char close_txid[65];
    if (!(chain_be ? chain_be->send_raw_tx(chain_be, close_hex, close_txid) :
                     regtest_send_raw_tx(&rt, close_hex, close_txid))) {
        if (g_db)
            persist_log_broadcast(g_db, "?", "cooperative_close",
                close_hex, "failed");
        fprintf(stderr, "LSP: broadcast close tx failed\n");
        tx_buf_free(&close_tx);
        lsp_cleanup(lsp_p);
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
        lsp_cleanup(lsp_p);
        secp256k1_context_destroy(ctx);
        return 1;
    }

    printf("LSP: cooperative close confirmed! txid: %s\n", close_txid);
    printf("LSP: SUCCESS — factory created and closed with %d clients\n", n_clients);
    if (test_bip39)
        printf("=== BIP39 HD WALLET TEST PASSED ===\n");

    /* Report: close confirmation */
    report_add_string(&rpt, "close_txid", close_txid);
    report_add_uint(&rpt, "confirmations", (uint64_t)conf);
    report_end_section(&rpt);  /* end "close" section */

    report_add_string(&rpt, "result", "success");
    report_close(&rpt);

    /* Clean up this factory's resources */
    jit_channels_cleanup(mgr);
    free(mgr);
    mgr = NULL;
    lsp_cleanup(lsp_p);
    free(lsp_p);
    lsp_p = NULL;

    /* Persistent daemon: loop back for a new factory instead of exiting.
       Mark this factory as closed in DB (cooperative close already on chain).
       Only loop if --daemon was specified and no SIGTERM received. */
    if (daemon_mode && !g_shutdown) {
        if (use_db) {
            persist_save_ladder_factory(&db, factory_generation, "closed",
                                         1, 1, 0, 0, 0, 0, 0);
        }
        factory_generation++;
        printf("\nLSP: factory %u closed, ready for new clients...\n\n",
               factory_generation - 1);
        fflush(stdout);
        goto accept_new_factory;
    }

    if (use_db)
        persist_close(&db);
    if (tor_control_fd >= 0)
        close(tor_control_fd);
    memset(lsp_seckey, 0, 32);
    secp256k1_context_destroy(ctx);
    return 0;
}
