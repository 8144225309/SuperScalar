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
#include "superscalar/ladder.h"
#include "superscalar/adaptor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);
extern void sha256_tagged(const char *, const unsigned char *, size_t, unsigned char *);

static volatile sig_atomic_t g_shutdown = 0;
static lsp_t *g_lsp = NULL;  /* for signal handler cleanup */
static persist_t *g_db = NULL;  /* for broadcast audit logging */

static void sigint_handler(int sig) {
    (void)sig;
    g_shutdown = 1;
}

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
        "  --report PATH       Write diagnostic JSON report to PATH\n"
        "  --db PATH           SQLite database for persistence (default: none)\n"
        "  --network MODE      Network: regtest, signet, testnet, mainnet (default: regtest)\n"
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
        "  --arity N           Leaf arity: 1 (per-client leaves) or 2 (default, paired leaves)\n"
        "  --force-close       After factory creation (+ demo), broadcast tree and wait for confirmations\n"
        "  --confirm-timeout N Confirmation wait timeout in seconds (default: 3600 regtest, 7200 non-regtest)\n"
        "  --accept-timeout N  Max seconds to wait for each client connection (default: 0 = no timeout)\n"
        "  --routing-fee-ppm N Routing fee in parts-per-million (default: 0 = free)\n"
        "  --lsp-balance-pct N LSP's share of channel capacity, 0-100 (default: 50 = fair split)\n"
        "  --placement-mode M  Client placement: sequential, inward, outward (default: sequential)\n"
        "  --economic-mode M   Fee model: lsp-takes-all, profit-shared (default: lsp-takes-all)\n"
        "  --default-profit-bps N  Default profit share basis points per client (default: 0)\n"
        "  --settlement-interval N Blocks between profit settlements (default: 144)\n"
        "  --tor-proxy HOST:PORT SOCKS5 proxy for Tor (default: 127.0.0.1:9050)\n"
        "  --tor-control HOST:PORT Tor control port (default: 127.0.0.1:9051)\n"
        "  --tor-password PASS   Tor control auth password (default: empty)\n"
        "  --onion               Create Tor hidden service on startup\n"
        "  --i-accept-the-risk Allow mainnet operation (PROTOTYPE — funds at risk!)\n"
        "  --help              Show this help\n",
        prog, LSP_MAX_CLIENTS);
}

/* Derive bech32m address from tweaked xonly pubkey via bitcoin-cli descriptors */
static int derive_p2tr_address(regtest_t *rt, const unsigned char *tweaked_ser32,
                                char *addr_out, size_t addr_len) {
    char tweaked_hex[65];
    hex_encode(tweaked_ser32, 32, tweaked_hex);

    /* Step 1: getdescriptorinfo "rawtr(HEX)" -> checksummed descriptor */
    char params[512];
    snprintf(params, sizeof(params), "\"rawtr(%s)\"", tweaked_hex);
    char *desc_result = regtest_exec(rt, "getdescriptorinfo", params);
    if (!desc_result) return 0;

    char checksummed_desc[256];
    char *dstart = strstr(desc_result, "\"descriptor\"");
    if (!dstart) { free(desc_result); return 0; }
    dstart = strchr(dstart + 12, '"');
    if (!dstart) { free(desc_result); return 0; }
    dstart++;
    char *dend = strchr(dstart, '"');
    if (!dend) { free(desc_result); return 0; }
    size_t dlen = (size_t)(dend - dstart);
    if (dlen >= sizeof(checksummed_desc)) { free(desc_result); return 0; }
    memcpy(checksummed_desc, dstart, dlen);
    checksummed_desc[dlen] = '\0';
    free(desc_result);

    /* Step 2: deriveaddresses "rawtr(HEX)#checksum" -> bech32m address */
    snprintf(params, sizeof(params), "\"%s\"", checksummed_desc);
    char *addr_result = regtest_exec(rt, "deriveaddresses", params);
    if (!addr_result) return 0;

    char *astart = strchr(addr_result, '"');
    if (!astart) { free(addr_result); return 0; }
    astart++;
    char *aend = strchr(astart, '"');
    if (!aend) { free(addr_result); return 0; }
    size_t alen = (size_t)(aend - astart);
    if (alen == 0 || alen >= addr_len) { free(addr_result); return 0; }
    memcpy(addr_out, astart, alen);
    addr_out[alen] = '\0';
    free(addr_result);

    return 1;
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
            printf("  node[%zu] requires %u-block relative timelock, waiting...\n",
                   i, required_depth);

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
                    printf("    height: %d / %d (%ds/%ds)\n",
                           regtest_get_block_height(rt), target_height,
                           waited, confirm_timeout);
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
            printf("  node[%zu] broadcast OK, waiting for confirmation...\n", i);
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
    /* Ignore SIGPIPE — write() to dead client sockets returns EPIPE instead of killing us */
    signal(SIGPIPE, SIG_IGN);

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
    int force_close = 0;
    int confirm_timeout_arg = -1;    /* -1 = auto (3600 regtest, 7200 non-regtest) */
    int accept_timeout_arg = 0;      /* 0 = no timeout (block indefinitely) */
    uint64_t routing_fee_ppm = 0;    /* 0 = zero-fee (no routing fee) */
    uint16_t lsp_balance_pct = 50;   /* 50 = fair 50-50 split */
    int accept_risk = 0;             /* --i-accept-the-risk for mainnet */
    int placement_mode_arg = 0;      /* 0=sequential, 1=inward, 2=outward */
    int economic_mode_arg = 0;       /* 0=lsp-takes-all, 1=profit-shared */
    uint16_t default_profit_bps = 0; /* per-client profit share bps */
    uint32_t settlement_interval = 144; /* blocks between profit settlements */
    const char *tor_proxy_arg = NULL;
    const char *tor_control_arg = NULL;
    const char *tor_password = NULL;
    int tor_onion = 0;

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
        else if (strcmp(argv[i], "--arity") == 0 && i + 1 < argc)
            leaf_arity = atoi(argv[++i]);
        else if (strcmp(argv[i], "--force-close") == 0)
            force_close = 1;
        else if (strcmp(argv[i], "--confirm-timeout") == 0 && i + 1 < argc) {
            confirm_timeout_arg = atoi(argv[++i]);
            if (confirm_timeout_arg <= 0) {
                fprintf(stderr, "Error: --confirm-timeout must be positive\n");
                return 1;
            }
        }
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
        else if (strcmp(argv[i], "--placement-mode") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "sequential") == 0) placement_mode_arg = 0;
            else if (strcmp(argv[i], "inward") == 0) placement_mode_arg = 1;
            else if (strcmp(argv[i], "outward") == 0) placement_mode_arg = 2;
            else { fprintf(stderr, "Error: unknown --placement-mode '%s' (options: sequential, inward, outward)\n", argv[i]); return 1; }
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
        else if (strcmp(argv[i], "--i-accept-the-risk") == 0)
            accept_risk = 1;
        else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    if (!network)
        network = "regtest";  /* default to regtest */
    int is_regtest = (strcmp(network, "regtest") == 0);

    /* Mainnet safety guard: refuse unless explicitly acknowledged */
    if (strcmp(network, "mainnet") == 0 && !accept_risk) {
        fprintf(stderr,
            "Error: mainnet operation refused.\n"
            "SuperScalar is a PROTOTYPE. Running on mainnet risks loss of funds.\n"
            "If you understand this risk, pass --i-accept-the-risk\n");
        return 1;
    }

    /* Resolve confirmation timeout */
    int confirm_timeout_secs = (confirm_timeout_arg > 0) ? confirm_timeout_arg
                               : (is_regtest ? 3600 : 7200);

    /* Test flags that mine blocks require regtest */
    if (!is_regtest && (test_expiry || test_distrib ||
                        test_turnover || test_rotation)) {
        fprintf(stderr, "Error: --test-expiry, --test-distrib, "
                "--test-turnover, and --test-rotation require --network regtest\n");
        return 1;
    }
    /* --breach-test (mode 1) mines for tree broadcast — regtest only */
    if (!is_regtest && breach_test == 1) {
        fprintf(stderr, "Error: --breach-test requires --network regtest "
                "(it mines blocks for tree broadcast)\n");
        return 1;
    }
    /* --cheat-daemon (mode 2) only broadcasts + sleeps — allowed on any network */

    /* Resolve active/dying block defaults */
    uint32_t active_blocks = (active_blocks_arg > 0) ? (uint32_t)active_blocks_arg
                             : (is_regtest ? 20 : 4320);
    uint32_t dying_blocks = (dying_blocks_arg > 0) ? (uint32_t)dying_blocks_arg
                            : (is_regtest ? 10 : 432);

    if (n_clients < 1 || n_clients > LSP_MAX_CLIENTS) {
        fprintf(stderr, "Error: --clients must be 1..%d\n", LSP_MAX_CLIENTS);
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
    if (wallet_name) {
        /* Use existing wallet — just set the name, don't create */
        strncpy(rt.wallet, wallet_name, sizeof(rt.wallet) - 1);
    } else {
        regtest_create_wallet(&rt, "superscalar_lsp");
    }

    /* Initialize fee estimator */
    fee_estimator_t fee_est;
    fee_init(&fee_est, fee_rate);
    if (!is_regtest) fee_est.use_estimatesmartfee = 1;
    if (!is_regtest && fee_update_from_node(&fee_est, &rt, 6)) {
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
        factory_t rec_f;
        memset(&rec_f, 0, sizeof(rec_f));
        if (persist_load_factory(&db, 0, &rec_f, ctx)) {
            if (rec_f.n_participants < 2) {
                fprintf(stderr, "LSP recovery: corrupt factory (n_participants=%zu)\n",
                        rec_f.n_participants);
                persist_close(&db);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("LSP: found existing factory in DB, entering recovery mode\n");
            fflush(stdout);

            /* Set up LSP with listen socket only (skip ceremony) */
            lsp_t lsp;
            if (!lsp_init(&lsp, ctx, &lsp_kp, port, rec_f.n_participants - 1)) {
                fprintf(stderr, "LSP recovery: lsp_init failed\n");
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
            lsp.listen_fd = wire_listen(NULL, lsp.port);
            if (lsp.listen_fd < 0) {
                fprintf(stderr, "LSP recovery: listen failed on port %d\n", port);
                persist_close(&db);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Populate pubkeys from recovered factory */
            size_t rec_n_clients = rec_f.n_participants - 1;
            lsp.n_clients = rec_n_clients;
            for (size_t i = 0; i < rec_n_clients; i++)
                lsp.client_pubkeys[i] = rec_f.pubkeys[i + 1];

            /* Copy factory and set fee estimator */
            lsp.factory = rec_f;
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
            lsp_channel_mgr_t mgr;
            memset(&mgr, 0, sizeof(mgr));
            mgr.fee = &fee_est;
            if (!lsp_channels_init_from_db(&mgr, ctx, &lsp.factory, lsp_seckey,
                                             rec_n_clients, &db)) {
                fprintf(stderr, "LSP recovery: channel init from DB failed\n");
                lsp_cleanup(&lsp);
                persist_close(&db);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            mgr.persist = &db;
            mgr.confirm_timeout_secs = confirm_timeout_secs;

            /* Load persisted state: invoices, HTLC origins, request_id */
            mgr.next_request_id = persist_load_counter(&db, "next_request_id", 1);

            {
                unsigned char inv_hashes[MAX_INVOICE_REGISTRY][32];
                size_t inv_dests[MAX_INVOICE_REGISTRY];
                uint64_t inv_amounts[MAX_INVOICE_REGISTRY];
                size_t n_inv = persist_load_invoices(&db,
                    inv_hashes, inv_dests, inv_amounts, MAX_INVOICE_REGISTRY);
                for (size_t i = 0; i < n_inv; i++) {
                    if (mgr.n_invoices >= MAX_INVOICE_REGISTRY) break;
                    invoice_entry_t *inv = &mgr.invoices[mgr.n_invoices++];
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
                    if (mgr.n_htlc_origins >= MAX_HTLC_ORIGINS) break;
                    htlc_origin_t *o = &mgr.htlc_origins[mgr.n_htlc_origins++];
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
            watchtower_init(&rec_wt, mgr.n_channels, &rt, &fee_est, &db);
            for (size_t c = 0; c < mgr.n_channels; c++)
                watchtower_set_channel(&rec_wt, c, &mgr.entries[c].channel);
            mgr.watchtower = &rec_wt;

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
                lf->factory_id = rec_lad.next_factory_id++;
                lf->is_initialized = 1;
                lf->is_funded = 1;
                lf->cached_state = factory_get_state(&lsp.factory,
                                                       rec_lad.current_block);
                tx_buf_init(&lf->distribution_tx, 256);
                rec_lad.n_factories = 1;
            }
            mgr.ladder = &rec_lad;

            /* Wire rotation parameters */
            memcpy(mgr.rot_lsp_seckey, lsp_seckey, 32);
            mgr.rot_fee_est = &fee_est;
            memcpy(mgr.rot_fund_spk, lsp.factory.funding_spk,
                   lsp.factory.funding_spk_len);
            mgr.rot_fund_spk_len = lsp.factory.funding_spk_len;

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
                if (derive_p2tr_address(&rt, ts2, rfa, sizeof(rfa)))
                    snprintf(mgr.rot_fund_addr, sizeof(mgr.rot_fund_addr),
                             "%s", rfa);
            }
            {
                char rma[128];
                if (regtest_get_new_address(&rt, rma, sizeof(rma)))
                    snprintf(mgr.rot_mine_addr, sizeof(mgr.rot_mine_addr),
                             "%s", rma);
            }
            mgr.rot_step_blocks = step_blocks;
            mgr.rot_states_per_layer = states_per_layer;
            mgr.rot_leaf_arity = leaf_arity;
            mgr.rot_is_regtest = is_regtest;
            mgr.rot_funding_sats = funding_sats;
            mgr.rot_auto_rotate = 1;
            mgr.rot_attempted_mask = 0;
            mgr.cli_enabled = cli_mode;

            /* JIT Channel Fallback */
            jit_channels_init(&mgr);
            if (no_jit) mgr.jit_enabled = 0;
            mgr.jit_funding_sats = (jit_amount_arg > 0) ?
                (uint64_t)jit_amount_arg :
                (funding_sats / (uint64_t)rec_n_clients);

            /* Load JIT channels from DB */
            {
                jit_channel_t *jits = (jit_channel_t *)mgr.jit_channels;
                size_t jit_count = 0;
                persist_load_jit_channels(&db, jits, JIT_MAX_CHANNELS,
                                            &jit_count);
                mgr.n_jit_channels = jit_count;
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

                    size_t wt_idx = mgr.n_channels + jits[ji].client_idx;
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
            lsp_channels_run_daemon_loop(&mgr, &lsp, &g_shutdown);

            /* Persist updated channel balances on shutdown */
            if (persist_begin(&db)) {
                int bal_ok = 1;
                for (size_t c = 0; c < mgr.n_channels; c++) {
                    const channel_t *ch = &mgr.entries[c].channel;
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
            jit_channels_cleanup(&mgr);
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
    if (!derive_p2tr_address(&rt, tweaked_ser, fund_addr, sizeof(fund_addr))) {
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
    if (leaf_arity == 1)
        lsp.factory.leaf_arity = FACTORY_ARITY_1;
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
    ladder_t lad;
    if (!ladder_init(&lad, ctx, &lsp_kp, active_blocks, dying_blocks)) {
        fprintf(stderr, "LSP: ladder_init failed\n");
        lsp_cleanup(&lsp);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    {
        int cur_h = regtest_get_block_height(&rt);
        if (cur_h > 0) lad.current_block = (uint32_t)cur_h;
    }
    /* Populate slot 0 with the existing factory (shallow copy) */
    {
        ladder_factory_t *lf = &lad.factories[0];
        lf->factory = lsp.factory;
        lf->factory_id = lad.next_factory_id++;
        lf->is_initialized = 1;
        lf->is_funded = 1;
        lf->cached_state = factory_get_state(&lsp.factory,
                                               lad.current_block);
        tx_buf_init(&lf->distribution_tx, 256);
        lad.n_factories = 1;
    }
    printf("LSP: ladder initialized (factory 0 at slot 0, state=%d)\n",
           (int)lad.factories[0].cached_state);

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
    lsp_channel_mgr_t mgr;
    int channels_active = 0;
    uint64_t init_local = 0, init_remote = 0;
    if (n_payments > 0 || daemon_mode || demo_mode || breach_test || test_expiry ||
        test_distrib || test_turnover || test_rotation || force_close) {
        /* Set fee policy before init (init preserves these across memset) */
        memset(&mgr, 0, sizeof(mgr));
        mgr.fee = &fee_est;
        mgr.routing_fee_ppm = routing_fee_ppm;
        mgr.lsp_balance_pct = lsp_balance_pct;
        mgr.placement_mode = (placement_mode_t)placement_mode_arg;
        mgr.economic_mode = (economic_mode_t)economic_mode_arg;
        mgr.default_profit_bps = default_profit_bps;
        mgr.settlement_interval_blocks = settlement_interval;
        if (!lsp_channels_init(&mgr, ctx, &lsp.factory, lsp_seckey, (size_t)n_clients)) {
            fprintf(stderr, "LSP: channel init failed\n");
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        if (!lsp_channels_exchange_basepoints(&mgr, &lsp)) {
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
                for (size_t c = 0; c < mgr.n_channels; c++) {
                    if (!persist_save_basepoints(&db, (uint32_t)c,
                                                   &mgr.entries[c].channel)) {
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
        mgr.persist = use_db ? &db : NULL;

        /* Set configurable confirmation timeout */
        mgr.confirm_timeout_secs = confirm_timeout_secs;

        /* Load persisted state (Phase 23) */
        if (use_db) {
            mgr.next_request_id = persist_load_counter(&db, "next_request_id", 1);

            /* Load invoices */
            unsigned char inv_hashes[MAX_INVOICE_REGISTRY][32];
            size_t inv_dests[MAX_INVOICE_REGISTRY];
            uint64_t inv_amounts[MAX_INVOICE_REGISTRY];
            size_t n_inv = persist_load_invoices(&db,
                inv_hashes, inv_dests, inv_amounts, MAX_INVOICE_REGISTRY);
            for (size_t i = 0; i < n_inv; i++) {
                if (mgr.n_invoices >= MAX_INVOICE_REGISTRY) break;
                invoice_entry_t *inv = &mgr.invoices[mgr.n_invoices++];
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
                if (mgr.n_htlc_origins >= MAX_HTLC_ORIGINS) break;
                htlc_origin_t *origin = &mgr.htlc_origins[mgr.n_htlc_origins++];
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
        for (size_t c = 0; c < mgr.n_channels; c++)
            mgr.entries[c].channel.fee_rate_sat_per_kvb = fee_rate;

        if (!lsp_channels_send_ready(&mgr, &lsp)) {
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
                for (size_t c = 0; c < mgr.n_channels; c++) {
                    if (!persist_save_channel(&db, &mgr.entries[c].channel, 0, (uint32_t)c)) {
                        ch_ok = 0;
                        break;
                    }
                }
                if (ch_ok)
                    persist_commit(&db);
                else
                    persist_rollback(&db);
            }
        }

        /* Report: channel init */
        report_channel_state(&rpt, "channels_initial", &mgr);
        report_flush(&rpt);

        /* Initialize watchtower for breach detection.
         * Use static to avoid stack corruption (watchtower_t is ~6.5KB). */
        static watchtower_t wt;
        memset(&wt, 0, sizeof(wt));
        watchtower_init(&wt, mgr.n_channels, &rt, &fee_est,
                          use_db ? &db : NULL);
        for (size_t c = 0; c < mgr.n_channels; c++)
            watchtower_set_channel(&wt, c, &mgr.entries[c].channel);
        mgr.watchtower = &wt;

        /* Wire ladder into channel manager (Tier 2) */
        mgr.ladder = &lad;

        /* Wire rotation parameters for continuous ladder (Gap #3) */
        memcpy(mgr.rot_lsp_seckey, lsp_seckey, 32);
        mgr.rot_fee_est = &fee_est;
        memcpy(mgr.rot_fund_spk, fund_spk, 34);
        mgr.rot_fund_spk_len = 34;
        snprintf(mgr.rot_fund_addr, sizeof(mgr.rot_fund_addr), "%s", fund_addr);
        snprintf(mgr.rot_mine_addr, sizeof(mgr.rot_mine_addr), "%s", mine_addr);
        mgr.rot_step_blocks = step_blocks;
        mgr.rot_states_per_layer = states_per_layer;
        mgr.rot_leaf_arity = leaf_arity;
        mgr.rot_is_regtest = is_regtest;
        mgr.rot_funding_sats = funding_sats;
        mgr.rot_auto_rotate = daemon_mode;  /* auto-rotate when in daemon mode */
        mgr.rot_attempted_mask = 0;
        mgr.cli_enabled = cli_mode;

        /* JIT Channel Fallback (Gap #2) */
        jit_channels_init(&mgr);
        if (no_jit) mgr.jit_enabled = 0;
        mgr.jit_funding_sats = (jit_amount_arg > 0) ?
            (uint64_t)jit_amount_arg : (funding_sats / (uint64_t)n_clients);

        /* Load persisted JIT channels from DB */
        if (use_db) {
            jit_channel_t *jits = (jit_channel_t *)mgr.jit_channels;
            size_t jit_count = 0;
            persist_load_jit_channels(&db, jits, JIT_MAX_CHANNELS, &jit_count);
            mgr.n_jit_channels = jit_count;
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
                    size_t wt_idx = mgr.n_channels + jits[ji].client_idx;
                    watchtower_set_channel(&wt, wt_idx, &jits[ji].channel);
                }
            }
            if (jit_count > 0)
                printf("LSP: loaded %zu JIT channels from DB\n", jit_count);
        }

        if (n_payments > 0) {
            printf("LSP: channels ready, waiting for %d payments (%d messages)...\n",
                   n_payments, n_payments * 2);
            if (!lsp_channels_run_event_loop(&mgr, &lsp, (size_t)(n_payments * 2))) {
                fprintf(stderr, "LSP: event loop failed\n");
                lsp_cleanup(&lsp);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("LSP: all %d payments processed\n", n_payments);
        }

        /* Capture initial balances before demo (for breach test) */
        if ((breach_test || test_expiry) && mgr.n_channels > 0) {
            init_local = mgr.entries[0].channel.local_amount;
            init_remote = mgr.entries[0].channel.remote_amount;
        }

        if (demo_mode) {
            printf("LSP: channels ready, running demo sequence...\n");
            if (!lsp_channels_run_demo_sequence(&mgr, &lsp)) {
                fprintf(stderr, "LSP: demo sequence failed\n");
            }

            /* DW counter tracking after demo payments */
            if (dw_counter_advance(&lsp.factory.counter)) {
                uint32_t epoch = dw_counter_epoch(&lsp.factory.counter);
                printf("LSP: DW advanced to epoch %u (delays:", epoch);
                for (uint32_t li = 0; li < lsp.factory.counter.n_layers; li++) {
                    uint16_t d = dw_delay_for_state(
                        &lsp.factory.counter.layers[li].config,
                        lsp.factory.counter.layers[li].current_state);
                    printf(" L%u=%u", li, d);
                }
                printf(" blocks)\n");
                printf("  Note: In production, factory tree would be re-signed "
                       "via split-round MuSig2.\n");
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
            jit_channels_cleanup(&mgr);
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

            lsp_channels_run_daemon_loop(&mgr, &lsp, &g_shutdown);
        }

        channels_active = 1;

        /* Persist updated channel balances */
        if (use_db) {
            if (!persist_begin(&db)) {
                fprintf(stderr, "LSP: warning: persist_begin failed for balance update\n");
            } else {
                int bal_ok = 1;
                for (size_t c = 0; c < mgr.n_channels; c++) {
                    const channel_t *ch = &mgr.entries[c].channel;
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
        report_channel_state(&rpt, "channels_after_payments", &mgr);
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
        for (size_t ci = 0; ci < mgr.n_channels; ci++) {
            channel_t *chX = &mgr.entries[ci].channel;
            uint64_t saved_num = chX->commitment_number;
            uint64_t saved_local = chX->local_amount;
            uint64_t saved_remote = chX->remote_amount;
            size_t saved_n_htlcs = chX->n_htlcs;

            /* Temporarily revert to commitment #0 with no HTLCs */
            chX->commitment_number = 0;
            chX->local_amount = init_local;
            chX->remote_amount = init_remote;
            chX->n_htlcs = 0;

            tx_buf_t old_commit_tx;
            tx_buf_init(&old_commit_tx, 512);
            unsigned char old_txid[32];
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
            printf("Waiting for revoked commitments to confirm...\n");
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
        watchtower_t *wt = mgr.watchtower;
        if (wt) {
            int detected = watchtower_check(wt);
            if (detected > 0) {
                printf("BREACH DETECTED! Watchtower broadcast %d penalty tx(s)\n",
                       detected);
                regtest_mine_blocks(&rt, 1, mine_addr);
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
                fprintf(stderr, "EXPIRY TEST: kickoff_root broadcast failed\n");
                free(kr_hex);
                lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            free(kr_hex);
            regtest_mine_blocks(&rt, 1, mine_addr);
            printf("1. kickoff_root broadcast: %s\n", kr_txid_str);
        }

        /* Step 2: Broadcast state_root (node 1, key-path pre-signed) */
        factory_node_t *state_root = &lsp.factory.nodes[1];
        {
            uint32_t state_nseq = state_root->nsequence;
            int nseq_blocks = (state_nseq == NSEQUENCE_DISABLE_BIP68)
                ? 0 : (int)(state_nseq & 0xFFFF);
            if (nseq_blocks > 0)
                regtest_mine_blocks(&rt, nseq_blocks, mine_addr);

            char *sr_hex = malloc(state_root->signed_tx.len * 2 + 1);
            hex_encode(state_root->signed_tx.data, state_root->signed_tx.len, sr_hex);
            char sr_txid_str[65];
            if (!regtest_send_raw_tx(&rt, sr_hex, sr_txid_str)) {
                fprintf(stderr, "EXPIRY TEST: state_root broadcast failed\n");
                free(sr_hex);
                lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            free(sr_hex);
            regtest_mine_blocks(&rt, 1, mine_addr);
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
                regtest_mine_blocks(&rt, nseq_blocks, mine_addr);

            char *hex = malloc(nd->signed_tx.len * 2 + 1);
            hex_encode(nd->signed_tx.data, nd->signed_tx.len, hex);
            char txid_str[65];
            if (!regtest_send_raw_tx(&rt, hex, txid_str)) {
                fprintf(stderr, "EXPIRY TEST: node[%d] broadcast failed\n", chain[ci]);
                free(hex);
                lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            free(hex);
            regtest_mine_blocks(&rt, 1, mine_addr);
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
                printf("%d. Mining %d blocks to reach leaf CLTV %u...\n",
                       step++, needed, leaf_cltv);
                regtest_mine_blocks(&rt, needed, mine_addr);
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
            free(hex);
            tx_buf_free(&ts);

            if (!sent) {
                fprintf(stderr, "EXPIRY TEST: leaf timeout tx broadcast failed\n");
                lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            regtest_mine_blocks(&rt, 1, mine_addr);
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
                printf("%d. Mining %d blocks to reach mid CLTV %u...\n",
                       step++, needed, mid_cltv);
                regtest_mine_blocks(&rt, needed, mine_addr);
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
            free(hex);
            tx_buf_free(&ts);

            if (!sent) {
                fprintf(stderr, "EXPIRY TEST: mid timeout tx broadcast failed\n");
                lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            regtest_mine_blocks(&rt, 1, mine_addr);
            mid_recovered = tout.amount_sats;
            printf("%d. Mid recovery: %llu sats (kickoff_right timeout) txid: %s\n",
                   step++, (unsigned long long)mid_recovered, txid_str);
        }

        printf("\nLeaf recovery: %llu sats\n", (unsigned long long)leaf_recovered);
        printf("Mid recovery:  %llu sats\n", (unsigned long long)mid_recovered);
        printf("=== EXPIRY TEST PASSED ===\n\n");

        /* Skip cooperative close — factory already spent */
        report_add_string(&rpt, "result", "expiry_test_complete");
        report_close(&rpt);
        if (use_db) persist_close(&db);
        lsp_cleanup(&lsp);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 0;
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
            memcpy(dist_outputs[di].script_pubkey, fund_spk, 34);
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
        lad.factories[0].distribution_tx = dist_tx;

        /* Mine past CLTV timeout */
        int cur_h = regtest_get_block_height(&rt);
        int blocks_to_cltv = (int)lsp.factory.cltv_timeout - cur_h;
        if (blocks_to_cltv > 0) {
            printf("Mining %d blocks to reach CLTV timeout %u...\n",
                   blocks_to_cltv, lsp.factory.cltv_timeout);
            regtest_mine_blocks(&rt, blocks_to_cltv, mine_addr);
        }

        /* Broadcast distribution TX */
        char *dt_hex = malloc(dist_tx.len * 2 + 1);
        hex_encode(dist_tx.data, dist_tx.len, dt_hex);
        char dt_txid_str[65];
        int dt_sent = regtest_send_raw_tx(&rt, dt_hex, dt_txid_str);
        free(dt_hex);

        if (!dt_sent) {
            fprintf(stderr, "DISTRIBUTION TX TEST: broadcast failed\n");
            tx_buf_free(&lad.factories[0].distribution_tx);
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        regtest_mine_blocks(&rt, 1, mine_addr);

        printf("Distribution TX broadcast: %s\n", dt_txid_str);
        printf("=== DISTRIBUTION TX TEST PASSED ===\n\n");

        report_add_string(&rpt, "result", "distrib_test_complete");
        report_close(&rpt);
        if (use_db) persist_close(&db);
        tx_buf_free(&lad.factories[0].distribution_tx);
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
            ladder_record_key_turnover(&lad, 0, participant_idx, extracted);

            /* Persist departed client */
            if (use_db)
                persist_save_departed_client(&db, 0, participant_idx, extracted);

            printf("  Client %d: key extracted and verified ✓\n", ci + 1);
            memset(client_sec, 0, 32);
        }

        /* Verify all clients departed */
        if (!ladder_can_close(&lad, 0)) {
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
        if (!ladder_build_close(&lad, 0, &turnover_close_tx,
                                  to_outputs, n_total)) {
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
        free(tc_hex);
        tx_buf_free(&turnover_close_tx);

        if (!tc_sent) {
            fprintf(stderr, "TURNOVER TEST: close TX broadcast failed\n");
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        regtest_mine_blocks(&rt, 1, mine_addr);

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

    /* === Factory Rotation Test (Tier 3) === */
    if (test_rotation && channels_active) {
        printf("\n=== FACTORY ROTATION TEST ===\n");

        /* --- Phase A: PTLC key turnover over wire --- */
        printf("Phase A: PTLC key turnover for Factory 0\n");

        /* Build demo keypairs (same as --test-turnover) */
        secp256k1_keypair rot_kps[FACTORY_MAX_SIGNERS];
        rot_kps[0] = lsp_kp;
        {
            static const unsigned char fill[4] = { 0x22, 0x33, 0x44, 0x55 };
            for (int ci = 0; ci < n_clients; ci++) {
                unsigned char ds[32];
                memset(ds, fill[ci], 32);
                if (!secp256k1_keypair_create(ctx, &rot_kps[ci + 1], ds)) {
                    fprintf(stderr, "rotation: keypair_create failed for client %d\n", ci);
                    return 1;
                }
            }
        }

        secp256k1_pubkey rot_pks[FACTORY_MAX_SIGNERS];
        for (size_t ti = 0; ti < n_total; ti++) {
            if (!secp256k1_keypair_pub(ctx, &rot_pks[ti], &rot_kps[ti])) {
                fprintf(stderr, "rotation: keypair_pub failed for participant %zu\n", ti);
                return 1;
            }
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

            ladder_record_key_turnover(&lad, 0, pidx, extracted);
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
        if (!ladder_can_close(&lad, 0)) {
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
        if (!ladder_build_close(&lad, 0, &rot_close_tx, rot_outputs, n_total)) {
            fprintf(stderr, "ROTATION: ladder_build_close failed\n");
            tx_buf_free(&rot_close_tx);
            lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }

        char *rc_hex = malloc(rot_close_tx.len * 2 + 1);
        hex_encode(rot_close_tx.data, rot_close_tx.len, rc_hex);
        char rc_txid[65];
        int rc_sent = regtest_send_raw_tx(&rt, rc_hex, rc_txid);
        free(rc_hex);
        tx_buf_free(&rot_close_tx);

        if (!rc_sent) {
            fprintf(stderr, "ROTATION: Factory 0 close TX broadcast failed\n");
            lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }
        regtest_mine_blocks(&rt, 1, mine_addr);
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

        /* Free old factory in lsp before reusing */
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
            ladder_factory_t *lf1 = &lad.factories[1];
            lf1->factory = lsp.factory;
            lf1->factory_id = lad.next_factory_id++;
            lf1->is_initialized = 1;
            lf1->is_funded = 1;
            lf1->cached_state = FACTORY_ACTIVE;
            tx_buf_init(&lf1->distribution_tx, 256);
            lad.n_factories = 2;
        }
        printf("  Factory 1 created and stored in ladder slot 1\n");

        /* Initialize new channel manager + send CHANNEL_READY */
        lsp_channel_mgr_t mgr2;
        memset(&mgr2, 0, sizeof(mgr2));
        mgr2.fee = &fee_est;
        mgr2.routing_fee_ppm = routing_fee_ppm;
        mgr2.lsp_balance_pct = lsp_balance_pct;
        mgr2.settlement_interval_blocks = settlement_interval;
        if (!lsp_channels_init(&mgr2, ctx, &lsp.factory, lsp_seckey, (size_t)n_clients)) {
            fprintf(stderr, "ROTATION: channel init for Factory 1 failed\n");
            lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }
        if (!lsp_channels_exchange_basepoints(&mgr2, &lsp)) {
            fprintf(stderr, "ROTATION: basepoint exchange for Factory 1 failed\n");
            lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }
        if (!lsp_channels_send_ready(&mgr2, &lsp)) {
            fprintf(stderr, "ROTATION: send_ready for Factory 1 failed\n");
            lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }
        printf("  Factory 1 channels ready\n");

        /* --- Phase D: Payment + cooperative close on Factory 1 --- */
        printf("Phase D: Payment on Factory 1\n");

        /* Run one payment: client 0 → client 1 */
        if (!lsp_channels_initiate_payment(&mgr2, &lsp, 0, 1, 1000)) {
            fprintf(stderr, "ROTATION: payment on Factory 1 failed\n");
            /* Non-fatal — continue to close */
        } else {
            printf("  Payment: client 1 -> client 2: 1000 sats\n");
            lsp_channels_print_balances(&mgr2);
        }

        /* Cooperative close of Factory 1 */
        tx_output_t close2_outputs[FACTORY_MAX_SIGNERS];
        size_t n_close2 = lsp_channels_build_close_outputs(&mgr2, &lsp.factory,
                                                             close2_outputs, 500);
        tx_buf_t close2_tx;
        tx_buf_init(&close2_tx, 512);
        if (!lsp_run_cooperative_close(&lsp, &close2_tx, close2_outputs, n_close2)) {
            fprintf(stderr, "ROTATION: cooperative close of Factory 1 failed\n");
            tx_buf_free(&close2_tx);
            lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }

        char *c2_hex = malloc(close2_tx.len * 2 + 1);
        hex_encode(close2_tx.data, close2_tx.len, c2_hex);
        char c2_txid[65];
        int c2_sent = regtest_send_raw_tx(&rt, c2_hex, c2_txid);
        free(c2_hex);
        tx_buf_free(&close2_tx);

        if (!c2_sent) {
            fprintf(stderr, "ROTATION: Factory 1 close TX broadcast failed\n");
            lsp_cleanup(&lsp); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }
        regtest_mine_blocks(&rt, 1, mine_addr);

        printf("  Factory 1 closed: %s\n", c2_txid);
        printf("\n=== FACTORY ROTATION TEST PASSED ===\n");

        report_add_string(&rpt, "result", "rotation_test_complete");
        report_close(&rpt);
        if (use_db) persist_close(&db);
        tx_buf_free(&lad.factories[0].distribution_tx);
        tx_buf_free(&lad.factories[1].distribution_tx);
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

    if (channels_active) {
        n_close_outputs = lsp_channels_build_close_outputs(&mgr, &lsp.factory,
                                                            close_outputs, 500);
        if (n_close_outputs == 0) {
            fprintf(stderr, "LSP: build close outputs failed\n");
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
    } else {
        /* No payments — equal split (original behavior) */
        uint64_t close_total = funding_amount - 500;  /* fee */
        uint64_t per_party = close_total / n_total;
        for (size_t i = 0; i < n_total; i++) {
            close_outputs[i].amount_sats = per_party;
            memcpy(close_outputs[i].script_pubkey, fund_spk, 34);
            close_outputs[i].script_pubkey_len = 34;
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

    if (!lsp_run_cooperative_close(&lsp, &close_tx, close_outputs, n_close_outputs)) {
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
        fprintf(stderr, "LSP: broadcast close tx failed\n");
        tx_buf_free(&close_tx);
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }
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

    jit_channels_cleanup(&mgr);
    if (use_db)
        persist_close(&db);
    if (tor_control_fd >= 0)
        close(tor_control_fd);
    lsp_cleanup(&lsp);
    memset(lsp_seckey, 0, 32);
    secp256k1_context_destroy(ctx);
    return 0;
}
