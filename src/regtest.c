#include "superscalar/regtest.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);

static char *run_command(const char *cmd) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;

    size_t cap = 4096;
    size_t len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) { pclose(fp); return NULL; }

    while (1) {
        size_t n = fread(buf + len, 1, cap - len - 1, fp);
        if (n == 0) break;
        len += n;
        if (len >= cap - 1) {
            cap *= 2;
            char *tmp = (char *)realloc(buf, cap);
            if (!tmp) { free(buf); pclose(fp); return NULL; }
            buf = tmp;
        }
    }
    buf[len] = '\0';

    pclose(fp);
    return buf;
}

static void build_cli_prefix(const regtest_t *rt, char *buf, size_t buf_len) {
    if (strcmp(rt->network, "mainnet") == 0) {
        snprintf(buf, buf_len,
            "%s -rpcuser=%s -rpcpassword=%s",
            rt->cli_path, rt->rpcuser, rt->rpcpassword);
    } else {
        snprintf(buf, buf_len,
            "%s -%s -rpcuser=%s -rpcpassword=%s",
            rt->cli_path, rt->network, rt->rpcuser, rt->rpcpassword);
    }

    if (rt->datadir[0] != '\0') {
        size_t cur = strlen(buf);
        snprintf(buf + cur, buf_len - cur, " -datadir=%s", rt->datadir);
    }
    if (rt->rpcport > 0) {
        size_t cur = strlen(buf);
        snprintf(buf + cur, buf_len - cur, " -rpcport=%d", rt->rpcport);
    }
    if (rt->wallet[0] != '\0') {
        size_t cur = strlen(buf);
        snprintf(buf + cur, buf_len - cur, " -rpcwallet=%s", rt->wallet);
    }
}

int regtest_init(regtest_t *rt) {
    return regtest_init_network(rt, "regtest");
}

int regtest_init_network(regtest_t *rt, const char *network) {
    memset(rt, 0, sizeof(*rt));
    strncpy(rt->cli_path, "bitcoin-cli", sizeof(rt->cli_path) - 1);
    strncpy(rt->rpcuser, "rpcuser", sizeof(rt->rpcuser) - 1);
    strncpy(rt->rpcpassword, "rpcpass", sizeof(rt->rpcpassword) - 1);
    strncpy(rt->network, network ? network : "regtest", sizeof(rt->network) - 1);
    rt->scan_depth = (strcmp(rt->network, "regtest") == 0) ? 20 : 1000;

    /* Build verification command using rt->cli_path (not hardcoded) */
    char cmd[512];
    if (strcmp(rt->network, "mainnet") == 0) {
        snprintf(cmd, sizeof(cmd),
            "%s -rpcuser=%s -rpcpassword=%s getblockchaininfo 2>&1",
            rt->cli_path, rt->rpcuser, rt->rpcpassword);
    } else {
        snprintf(cmd, sizeof(cmd),
            "%s -%s -rpcuser=%s -rpcpassword=%s getblockchaininfo 2>&1",
            rt->cli_path, rt->network, rt->rpcuser, rt->rpcpassword);
    }

    char *result = run_command(cmd);
    if (!result) return 0;

    int ok = (strstr(result, "\"chain\"") != NULL);
    free(result);
    return ok ? 1 : 0;
}

int regtest_init_full(regtest_t *rt, const char *network,
                      const char *cli_path, const char *rpcuser,
                      const char *rpcpassword, const char *datadir,
                      int rpcport) {
    memset(rt, 0, sizeof(*rt));
    strncpy(rt->cli_path,
            cli_path ? cli_path : "bitcoin-cli",
            sizeof(rt->cli_path) - 1);
    strncpy(rt->rpcuser,
            rpcuser ? rpcuser : "rpcuser",
            sizeof(rt->rpcuser) - 1);
    strncpy(rt->rpcpassword,
            rpcpassword ? rpcpassword : "rpcpass",
            sizeof(rt->rpcpassword) - 1);
    strncpy(rt->network,
            network ? network : "regtest",
            sizeof(rt->network) - 1);
    if (datadir)
        strncpy(rt->datadir, datadir, sizeof(rt->datadir) - 1);
    rt->rpcport = rpcport;
    rt->scan_depth = (strcmp(rt->network, "regtest") == 0) ? 20 : 1000;

    /* Verify connection using build_cli_prefix for consistency */
    char prefix[512];
    build_cli_prefix(rt, prefix, sizeof(prefix));
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "%s getblockchaininfo 2>&1", prefix);

    char *result = run_command(cmd);
    if (!result) return 0;

    int ok = (strstr(result, "\"chain\"") != NULL);
    free(result);
    return ok ? 1 : 0;
}

char *regtest_exec(const regtest_t *rt, const char *method, const char *params) {
    char prefix[512];
    build_cli_prefix(rt, prefix, sizeof(prefix));

    char cmd[2048];
    if (params && params[0] != '\0') {
        snprintf(cmd, sizeof(cmd), "%s %s %s 2>&1", prefix, method, params);
    } else {
        snprintf(cmd, sizeof(cmd), "%s %s 2>&1", prefix, method);
    }

    return run_command(cmd);
}

int regtest_create_wallet(regtest_t *rt, const char *name) {
    char params[256];
    snprintf(params, sizeof(params), "\"%s\"", name);
    char *result = regtest_exec(rt, "createwallet", params);
    if (!result) return 0;

    if (strstr(result, "error") != NULL && strstr(result, "already exists") == NULL) {
        free(result);
        result = regtest_exec(rt, "loadwallet", params);
        if (!result) return 0;
    }

    free(result);
    strncpy(rt->wallet, name, sizeof(rt->wallet) - 1);
    return 1;
}

int regtest_get_new_address(regtest_t *rt, char *addr_out, size_t len) {
    char *result = regtest_exec(rt, "getnewaddress", "\"\" bech32m");
    if (!result) return 0;

    char *start = result;
    while (*start == '"' || *start == ' ' || *start == '\n') start++;
    char *end = start + strlen(start) - 1;
    while (end > start && (*end == '"' || *end == '\n' || *end == '\r' || *end == ' ')) {
        *end = '\0';
        end--;
    }

    if (strlen(start) == 0 || strlen(start) >= len) {
        free(result);
        return 0;
    }

    strncpy(addr_out, start, len - 1);
    addr_out[len - 1] = '\0';
    free(result);
    return 1;
}

int regtest_get_address_scriptpubkey(regtest_t *rt, const char *address,
                                      unsigned char *spk_out, size_t *spk_len_out) {
    if (!rt || !address || !spk_out || !spk_len_out) return 0;

    char params[256];
    snprintf(params, sizeof(params), "\"%s\"", address);
    char *result = regtest_exec(rt, "getaddressinfo", params);
    if (!result) return 0;

    cJSON *json = cJSON_Parse(result);
    free(result);
    if (!json) return 0;

    cJSON *spk = cJSON_GetObjectItem(json, "scriptPubKey");
    if (!spk || !cJSON_IsString(spk)) {
        cJSON_Delete(json);
        return 0;
    }

    int decoded = hex_decode(spk->valuestring, spk_out, 256);
    cJSON_Delete(json);
    if (decoded <= 0) return 0;

    *spk_len_out = (size_t)decoded;
    return 1;
}

int regtest_get_block_height(regtest_t *rt) {
    char *result = regtest_exec(rt, "getblockcount", "");
    if (!result) return -1;
    int height = atoi(result);
    free(result);
    return height;
}

int regtest_mine_blocks(regtest_t *rt, int n, const char *address) {
    /* Only allow mining on regtest to prevent accidental mining on other networks */
    if (strcmp(rt->network, "regtest") != 0) return 0;

    char params[512];
    snprintf(params, sizeof(params), "%d \"%s\"", n, address);
    char *result = regtest_exec(rt, "generatetoaddress", params);
    if (!result) return 0;

    int ok = (result[0] == '[');
    free(result);
    return ok;
}

int regtest_fund_address(regtest_t *rt, const char *address,
                         double btc_amount, char *txid_out) {
    char params[512];
    snprintf(params, sizeof(params), "\"%s\" %.8f", address, btc_amount);
    char *result = regtest_exec(rt, "sendtoaddress", params);
    if (!result) return 0;

    char *start = result;
    while (*start == '"' || *start == ' ' || *start == '\n') start++;
    char *end = start + strlen(start) - 1;
    while (end > start && (*end == '"' || *end == '\n' || *end == '\r' || *end == ' ')) {
        *end = '\0';
        end--;
    }

    if (strlen(start) != 64) {
        free(result);
        return 0;
    }

    if (txid_out)
        strncpy(txid_out, start, 65);
    free(result);
    return 1;
}

int regtest_mine_for_balance(regtest_t *rt, double min_btc, const char *address) {
    if (strcmp(rt->network, "regtest") != 0) return 0;

    /* Mine initial 101 blocks for coinbase maturity */
    if (!regtest_mine_blocks(rt, 101, address)) return 0;

    /* Mine additional blocks if subsidy is too low (regtest halves every 150) */
    for (int i = 0; i < 100; i++) {
        double bal = regtest_get_balance(rt);
        if (bal >= min_btc) return 1;
        if (!regtest_mine_blocks(rt, 25, address)) return 0;
    }
    return 0;
}

int regtest_send_raw_tx(regtest_t *rt, const char *tx_hex, char *txid_out) {
    char *params = (char *)malloc(strlen(tx_hex) + 4);
    if (!params) return 0;
    snprintf(params, strlen(tx_hex) + 4, "\"%s\"", tx_hex);

    char *result = regtest_exec(rt, "sendrawtransaction", params);
    free(params);
    if (!result) return 0;

    if (strstr(result, "error") != NULL) {
        fprintf(stderr, "sendrawtransaction error: %s\n", result);
        free(result);
        return 0;
    }

    char *start = result;
    while (*start == '"' || *start == ' ' || *start == '\n') start++;
    char *end = start + strlen(start) - 1;
    while (end > start && (*end == '"' || *end == '\n' || *end == '\r' || *end == ' ')) {
        *end = '\0';
        end--;
    }

    if (strlen(start) != 64) {
        free(result);
        return 0;
    }

    if (txid_out)
        strncpy(txid_out, start, 65);
    free(result);
    return 1;
}

int regtest_get_confirmations(regtest_t *rt, const char *txid) {
    char params[256];

    /* Try gettransaction (wallet txs) */
    snprintf(params, sizeof(params), "\"%s\" true", txid);
    char *result = regtest_exec(rt, "gettransaction", params);
    if (result) {
        cJSON *json = cJSON_Parse(result);
        free(result);
        if (json) {
            cJSON *conf = cJSON_GetObjectItem(json, "confirmations");
            if (conf && cJSON_IsNumber(conf)) {
                int val = conf->valueint;
                cJSON_Delete(json);
                return val;
            }
            cJSON_Delete(json);
        }
    }

    /* Fallback: scan recent blocks with getrawtransaction + blockhash */
    result = regtest_exec(rt, "getblockcount", "");
    if (!result) return -1;
    int height = atoi(result);
    free(result);

    int depth = rt->scan_depth > 0 ? rt->scan_depth : 20;
    for (int i = 0; i < depth && i <= height; i++) {
        snprintf(params, sizeof(params), "%d", height - i);
        char *hash_result = regtest_exec(rt, "getblockhash", params);
        if (!hash_result) continue;

        /* Trim whitespace */
        char blockhash[65];
        char *s = hash_result;
        while (*s == ' ' || *s == '\n' || *s == '"') s++;
        char *e = s + strlen(s) - 1;
        while (e > s && (*e == ' ' || *e == '\n' || *e == '"' || *e == '\r'))
            *e-- = '\0';
        strncpy(blockhash, s, 64);
        blockhash[64] = '\0';
        free(hash_result);

        snprintf(params, sizeof(params), "\"%s\" true \"%s\"", txid, blockhash);
        char *tx_result = regtest_exec(rt, "getrawtransaction", params);
        if (!tx_result) continue;

        cJSON *json = cJSON_Parse(tx_result);
        free(tx_result);
        if (!json) continue;

        cJSON *conf = cJSON_GetObjectItem(json, "confirmations");
        if (conf && cJSON_IsNumber(conf)) {
            int val = conf->valueint;
            cJSON_Delete(json);
            return val;
        }
        cJSON_Delete(json);
    }

    return -1;
}

bool regtest_is_in_mempool(regtest_t *rt, const char *txid) {
    char params[256];
    snprintf(params, sizeof(params), "\"%s\"", txid);
    char *result = regtest_exec(rt, "getmempoolentry", params);
    if (!result) return false;

    bool in_mempool = (strstr(result, "error") == NULL);
    free(result);
    return in_mempool;
}

/* Parse a vout object from getrawtransaction or gettransaction decoded output. */
static int parse_vout_obj(cJSON *vout_obj,
                           uint64_t *amount_sats_out,
                           unsigned char *scriptpubkey_out, size_t *spk_len_out) {
    cJSON *value = cJSON_GetObjectItem(vout_obj, "value");
    if (value && cJSON_IsNumber(value))
        *amount_sats_out = (uint64_t)(value->valuedouble * 100000000.0 + 0.5);

    cJSON *spk = cJSON_GetObjectItem(vout_obj, "scriptPubKey");
    if (spk) {
        cJSON *hex = cJSON_GetObjectItem(spk, "hex");
        if (hex && cJSON_IsString(hex)) {
            int decoded = hex_decode(hex->valuestring, scriptpubkey_out, 256);
            if (decoded > 0)
                *spk_len_out = (size_t)decoded;
        }
    }
    return 1;
}

int regtest_get_tx_output(regtest_t *rt, const char *txid, uint32_t vout,
                          uint64_t *amount_sats_out,
                          unsigned char *scriptpubkey_out, size_t *spk_len_out) {
    char params[256];
    cJSON *json = NULL;
    cJSON *vouts = NULL;

    /* Try getrawtransaction first (works with -txindex or for mempool txs) */
    snprintf(params, sizeof(params), "\"%s\" true", txid);
    char *result = regtest_exec(rt, "getrawtransaction", params);
    if (result) {
        json = cJSON_Parse(result);
        free(result);
        if (json) {
            vouts = cJSON_GetObjectItem(json, "vout");
            if (vouts && cJSON_IsArray(vouts)) {
                cJSON *vout_obj = cJSON_GetArrayItem(vouts, (int)vout);
                if (vout_obj) {
                    int ok = parse_vout_obj(vout_obj, amount_sats_out,
                                             scriptpubkey_out, spk_len_out);
                    cJSON_Delete(json);
                    return ok;
                }
            }
            cJSON_Delete(json);
            json = NULL;
        }
    }

    /* Fallback: gettransaction with decode (wallet txs, no -txindex needed) */
    snprintf(params, sizeof(params), "\"%s\" true true", txid);
    result = regtest_exec(rt, "gettransaction", params);
    if (result) {
        json = cJSON_Parse(result);
        free(result);
        if (json) {
            cJSON *decoded = cJSON_GetObjectItem(json, "decoded");
            if (decoded) {
                vouts = cJSON_GetObjectItem(decoded, "vout");
                if (vouts && cJSON_IsArray(vouts)) {
                    cJSON *vout_obj = cJSON_GetArrayItem(vouts, (int)vout);
                    if (vout_obj) {
                        int ok = parse_vout_obj(vout_obj, amount_sats_out,
                                                 scriptpubkey_out, spk_len_out);
                        cJSON_Delete(json);
                        return ok;
                    }
                }
            }
            cJSON_Delete(json);
            json = NULL;
        }
    }

    /* Fallback: scan recent blocks with getrawtransaction + blockhash
       (works for non-wallet txs without -txindex) */
    result = regtest_exec(rt, "getblockcount", "");
    if (!result) return 0;
    int height = atoi(result);
    free(result);

    int depth = rt->scan_depth > 0 ? rt->scan_depth : 20;
    for (int i = 0; i < depth && i <= height; i++) {
        snprintf(params, sizeof(params), "%d", height - i);
        char *hash_result = regtest_exec(rt, "getblockhash", params);
        if (!hash_result) continue;

        char blockhash[65];
        char *s = hash_result;
        while (*s == ' ' || *s == '\n' || *s == '"') s++;
        char *e = s + strlen(s) - 1;
        while (e > s && (*e == ' ' || *e == '\n' || *e == '"' || *e == '\r'))
            *e-- = '\0';
        strncpy(blockhash, s, 64);
        blockhash[64] = '\0';
        free(hash_result);

        snprintf(params, sizeof(params), "\"%s\" true \"%s\"", txid, blockhash);
        result = regtest_exec(rt, "getrawtransaction", params);
        if (!result) continue;

        json = cJSON_Parse(result);
        free(result);
        if (!json) continue;

        vouts = cJSON_GetObjectItem(json, "vout");
        if (vouts && cJSON_IsArray(vouts)) {
            cJSON *vout_obj = cJSON_GetArrayItem(vouts, (int)vout);
            if (vout_obj) {
                int ok = parse_vout_obj(vout_obj, amount_sats_out,
                                         scriptpubkey_out, spk_len_out);
                cJSON_Delete(json);
                return ok;
            }
        }
        cJSON_Delete(json);
    }

    return 0;
}

int regtest_get_raw_tx(regtest_t *rt, const char *txid,
                         char *tx_hex_out, size_t max_len) {
    if (!rt || !txid || !tx_hex_out || max_len == 0) return 0;

    char params[256];
    snprintf(params, sizeof(params), "\"%s\"", txid);
    char *result = regtest_exec(rt, "getrawtransaction", params);
    if (!result) return 0;

    if (strstr(result, "error") != NULL) {
        free(result);
        return 0;
    }

    /* Trim whitespace/quotes */
    char *start = result;
    while (*start == '"' || *start == ' ' || *start == '\n') start++;
    char *end = start + strlen(start) - 1;
    while (end > start && (*end == '"' || *end == '\n' || *end == '\r' || *end == ' ')) {
        *end = '\0';
        end--;
    }

    size_t len = strlen(start);
    if (len == 0 || len >= max_len) {
        free(result);
        return 0;
    }

    strncpy(tx_hex_out, start, max_len - 1);
    tx_hex_out[max_len - 1] = '\0';
    free(result);
    return 1;
}

/* --- Shared faucet for regtest test suites --- */
static regtest_t g_faucet;
static char g_faucet_addr[128];
static int g_faucet_ready = 0;

int regtest_init_faucet(void) {
    if (g_faucet_ready) return 1;

    if (!regtest_init(&g_faucet)) return 0;

    if (!regtest_create_wallet(&g_faucet, "faucet")) {
        /* Wallet may already exist from a previous run — try loading */
        char *lr = regtest_exec(&g_faucet, "loadwallet", "\"faucet\"");
        if (lr) free(lr);
        strncpy(g_faucet.wallet, "faucet", sizeof(g_faucet.wallet) - 1);
    }

    if (!regtest_get_new_address(&g_faucet, g_faucet_addr, sizeof(g_faucet_addr)))
        return 0;

    /* Check if chain already has blocks (stale regtest, not wiped). */
    int height = regtest_get_block_height(&g_faucet);
    if (height > 1000) {
        fprintf(stderr, "WARNING: regtest chain at height %d — "
                "consider wiping (rm -rf ~/.bitcoin/regtest) for clean results\n",
                height);
    }

    /* Mine 200 blocks while subsidy is high.
       Blocks 0-149: 50 BTC each = 7,500 BTC
       Blocks 150-199: 25 BTC each = 1,250 BTC
       Total: ~8,750 BTC (only first 100 are spendable due to maturity). */
    if (!regtest_mine_blocks(&g_faucet, 200, g_faucet_addr))
        return 0;

    double bal = regtest_get_balance(&g_faucet);
    if (bal < 10.0) {
        fprintf(stderr, "WARNING: faucet balance %.4f BTC after init — "
                "subsidy may be exhausted (height %d). Wipe regtest.\n",
                bal, regtest_get_block_height(&g_faucet));
    }

    g_faucet_ready = 1;
    return 1;
}

int regtest_fund_from_faucet(regtest_t *rt, double amount) {
    if (!g_faucet_ready) return 0;

    /* Check faucet balance — try to replenish if running low */
    double bal = regtest_get_balance(&g_faucet);
    if (bal < amount + 1.0) {
        /* Try to mine more blocks to replenish */
        fprintf(stderr, "faucet: balance %.4f BTC low, mining 50 blocks to replenish\n", bal);
        regtest_mine_blocks(&g_faucet, 50, g_faucet_addr);
        bal = regtest_get_balance(&g_faucet);
        if (bal < amount) {
            fprintf(stderr, "faucet: EXHAUSTED (%.4f BTC < %.4f needed). "
                    "Wipe regtest: rm -rf ~/.bitcoin/regtest\n", bal, amount);
            return 0;
        }
    }

    /* Get new address in the target wallet */
    char addr[128];
    if (!regtest_get_new_address(rt, addr, sizeof(addr)))
        return 0;

    /* Send from faucet to target wallet */
    if (!regtest_fund_address(&g_faucet, addr, amount, NULL))
        return 0;

    /* Mine 1 block to confirm (to faucet address, keeps subsidy in faucet) */
    if (!regtest_mine_blocks(&g_faucet, 1, g_faucet_addr))
        return 0;

    return 1;
}

void regtest_faucet_health_report(void) {
    if (!g_faucet_ready) {
        printf("\n  [faucet] not initialized\n");
        return;
    }
    int height = regtest_get_block_height(&g_faucet);
    double bal = regtest_get_balance(&g_faucet);
    printf("\n  [faucet] height=%d  balance=%.4f BTC", height, bal);
    if (height > 2000)
        printf("  WARNING: chain getting tall, wipe before next run");
    if (bal < 50.0)
        printf("  WARNING: balance low, subsidy degrading");
    printf("\n");
}

double regtest_get_balance(regtest_t *rt) {
    char *result = regtest_exec(rt, "getbalance", "");
    if (!result) return -1.0;
    double bal = atof(result);
    free(result);
    return bal;
}

int regtest_wait_for_confirmation(regtest_t *rt, const char *txid,
                                    int timeout_secs) {
    if (!rt || !txid) return -1;

    int is_regtest = (strcmp(rt->network, "regtest") == 0);
    int interval = is_regtest ? 5 : 15;       /* initial poll interval */
    int max_interval = is_regtest ? 10 : 120;  /* cap */

    int elapsed = 0;
    while (elapsed < timeout_secs) {
        int conf = regtest_get_confirmations(rt, txid);
        if (conf >= 1) return conf;

        /* Also check mempool — tx exists but unconfirmed */
        if (conf < 0 && !regtest_is_in_mempool(rt, txid)) {
            fprintf(stderr, "regtest_wait_for_confirmation: tx %s not found\n", txid);
            return -1;
        }

        printf("  waiting for confirmation... (%ds/%ds)\n", elapsed, timeout_secs);
        sleep(interval);
        elapsed += interval;
        /* Exponential backoff, capped */
        interval *= 2;
        if (interval > max_interval)
            interval = max_interval;
    }

    return -1;  /* timeout */
}

int regtest_get_utxo_for_bump(regtest_t *rt, uint64_t min_amount_sats,
                                char *txid_out, uint32_t *vout_out,
                                uint64_t *amount_out,
                                unsigned char *spk_out, size_t *spk_len_out) {
    if (!rt || !txid_out || !vout_out || !amount_out) return 0;

    char *result = regtest_exec(rt, "listunspent", "1 9999999");
    if (!result) return 0;

    cJSON *json = cJSON_Parse(result);
    free(result);
    if (!json || !cJSON_IsArray(json)) {
        if (json) cJSON_Delete(json);
        return 0;
    }

    double min_btc = (double)min_amount_sats / 100000000.0;
    int found = 0;

    int n = cJSON_GetArraySize(json);
    for (int i = 0; i < n; i++) {
        cJSON *utxo = cJSON_GetArrayItem(json, i);
        cJSON *amount = cJSON_GetObjectItem(utxo, "amount");
        if (!amount || !cJSON_IsNumber(amount)) continue;
        if (amount->valuedouble < min_btc) continue;

        cJSON *txid = cJSON_GetObjectItem(utxo, "txid");
        cJSON *vout = cJSON_GetObjectItem(utxo, "vout");
        if (!txid || !cJSON_IsString(txid) || !vout || !cJSON_IsNumber(vout))
            continue;

        strncpy(txid_out, txid->valuestring, 65);
        *vout_out = (uint32_t)vout->valueint;
        *amount_out = (uint64_t)(amount->valuedouble * 100000000.0 + 0.5);

        if (spk_out && spk_len_out) {
            cJSON *spk = cJSON_GetObjectItem(utxo, "scriptPubKey");
            if (spk && cJSON_IsString(spk)) {
                int decoded = hex_decode(spk->valuestring, spk_out, 64);
                if (decoded > 0)
                    *spk_len_out = (size_t)decoded;
            }
        }

        found = 1;
        break;
    }

    cJSON_Delete(json);
    return found;
}

int regtest_derive_p2tr_address(const regtest_t *rt,
                                const unsigned char *tweaked_ser32,
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

char *regtest_sign_raw_tx_with_wallet(regtest_t *rt, const char *unsigned_hex,
                                        const char *prevtxs_json) {
    if (!rt || !unsigned_hex) return NULL;

    char *params;
    if (prevtxs_json) {
        size_t plen = strlen(unsigned_hex) + strlen(prevtxs_json) + 16;
        params = (char *)malloc(plen);
        if (!params) return NULL;
        /* NOTE: Single-quote quoting relies on popen() invoking /bin/sh.
           This works on Linux and macOS. */
        snprintf(params, plen, "\"%s\" '%s'", unsigned_hex, prevtxs_json);
    } else {
        size_t plen = strlen(unsigned_hex) + 8;
        params = (char *)malloc(plen);
        if (!params) return NULL;
        snprintf(params, plen, "\"%s\"", unsigned_hex);
    }

    char *result = regtest_exec(rt, "signrawtransactionwithwallet", params);
    free(params);
    if (!result) return NULL;

    cJSON *json = cJSON_Parse(result);
    free(result);
    if (!json) return NULL;

    cJSON *hex = cJSON_GetObjectItem(json, "hex");
    if (!hex || !cJSON_IsString(hex)) {
        cJSON_Delete(json);
        return NULL;
    }

    /* Check that signing actually completed — if the wallet can't sign
       (wrong wallet, missing key), complete will be false */
    cJSON *complete = cJSON_GetObjectItem(json, "complete");
    if (!complete || !cJSON_IsTrue(complete)) {
        cJSON_Delete(json);
        return NULL;
    }

    char *signed_hex = strdup(hex->valuestring);
    cJSON_Delete(json);
    return signed_hex;
}

/* --- UTXO coin selection (Mainnet Gap #1) --- */

#define DUST_THRESHOLD_SATS 546

int regtest_list_utxos(regtest_t *rt, utxo_t **utxos_out, size_t *n_out) {
    if (!rt || !utxos_out || !n_out) return 0;

    char *result = regtest_exec(rt, "listunspent", "1 9999999");
    if (!result) return 0;

    cJSON *json = cJSON_Parse(result);
    free(result);
    if (!json || !cJSON_IsArray(json)) {
        if (json) cJSON_Delete(json);
        return 0;
    }

    int n = cJSON_GetArraySize(json);
    if (n == 0) {
        cJSON_Delete(json);
        *utxos_out = NULL;
        *n_out = 0;
        return 1;
    }

    utxo_t *utxos = (utxo_t *)calloc((size_t)n, sizeof(utxo_t));
    if (!utxos) { cJSON_Delete(json); return 0; }

    size_t count = 0;
    for (int i = 0; i < n; i++) {
        cJSON *item = cJSON_GetArrayItem(json, i);
        cJSON *txid = cJSON_GetObjectItem(item, "txid");
        cJSON *vout = cJSON_GetObjectItem(item, "vout");
        cJSON *amount = cJSON_GetObjectItem(item, "amount");
        if (!txid || !cJSON_IsString(txid) || !vout || !cJSON_IsNumber(vout) ||
            !amount || !cJSON_IsNumber(amount))
            continue;

        strncpy(utxos[count].txid, txid->valuestring, 64);
        utxos[count].txid[64] = '\0';
        utxos[count].vout = vout->valueint;
        utxos[count].amount_sats = (uint64_t)(amount->valuedouble * 100000000.0 + 0.5);
        count++;
    }

    cJSON_Delete(json);
    *utxos_out = utxos;
    *n_out = count;
    return 1;
}

/* Sort comparator: descending by amount (largest first). */
static int utxo_cmp_desc(const void *a, const void *b) {
    const utxo_t *ua = (const utxo_t *)a;
    const utxo_t *ub = (const utxo_t *)b;
    if (ub->amount_sats > ua->amount_sats) return 1;
    if (ub->amount_sats < ua->amount_sats) return -1;
    return 0;
}

int regtest_coin_select(const utxo_t *utxos, size_t n_utxos,
                        uint64_t target_sats, uint64_t fee_rate_sat_vb,
                        utxo_t **selected_out, size_t *n_selected,
                        uint64_t *change_sats) {
    if (!utxos || !selected_out || !n_selected || !change_sats || n_utxos == 0)
        return 0;

    /* Copy + sort descending */
    utxo_t *sorted = (utxo_t *)malloc(n_utxos * sizeof(utxo_t));
    if (!sorted) return 0;
    memcpy(sorted, utxos, n_utxos * sizeof(utxo_t));
    qsort(sorted, n_utxos, sizeof(utxo_t), utxo_cmp_desc);

    /* Estimate fee: ~68 vB per input, ~43 vB per output, ~11 vB overhead.
       We assume 2 outputs (target + change). Adjust as inputs grow. */
    size_t sel_count = 0;
    uint64_t sel_total = 0;

    for (size_t i = 0; i < n_utxos; i++) {
        sel_count = i + 1;
        sel_total += sorted[i].amount_sats;

        /* Estimate fee for current number of inputs + 2 outputs */
        uint64_t est_vsize = 11 + sel_count * 68 + 2 * 43;
        uint64_t est_fee = est_vsize * fee_rate_sat_vb;

        if (sel_total >= target_sats + est_fee + DUST_THRESHOLD_SATS) {
            /* We have enough including change */
            uint64_t ch = sel_total - target_sats - est_fee;
            if (ch < DUST_THRESHOLD_SATS) {
                /* Change below dust: absorb into fee */
                ch = 0;
            }
            *change_sats = ch;
            *selected_out = (utxo_t *)malloc(sel_count * sizeof(utxo_t));
            if (!*selected_out) { free(sorted); return 0; }
            memcpy(*selected_out, sorted, sel_count * sizeof(utxo_t));
            *n_selected = sel_count;
            free(sorted);
            return 1;
        }

        if (sel_total >= target_sats + est_fee) {
            /* Enough without change (change would be dust) */
            *change_sats = 0;
            *selected_out = (utxo_t *)malloc(sel_count * sizeof(utxo_t));
            if (!*selected_out) { free(sorted); return 0; }
            memcpy(*selected_out, sorted, sel_count * sizeof(utxo_t));
            *n_selected = sel_count;
            free(sorted);
            return 1;
        }
    }

    /* Insufficient funds */
    free(sorted);
    return 0;
}

int regtest_create_funded_tx(regtest_t *rt, const tx_output_t *outputs,
                              size_t n_outputs, uint64_t fee_rate,
                              char *txid_hex_out, char *signed_hex_out,
                              size_t hex_max) {
    if (!rt || !outputs || n_outputs == 0) return 0;

    /* Calculate total target */
    uint64_t target = 0;
    for (size_t i = 0; i < n_outputs; i++)
        target += outputs[i].amount_sats;

    /* List UTXOs and select coins */
    utxo_t *all_utxos = NULL;
    size_t n_all = 0;
    if (!regtest_list_utxos(rt, &all_utxos, &n_all) || n_all == 0) {
        free(all_utxos);
        return 0;
    }

    utxo_t *selected = NULL;
    size_t n_sel = 0;
    uint64_t change = 0;
    if (!regtest_coin_select(all_utxos, n_all, target, fee_rate,
                              &selected, &n_sel, &change)) {
        free(all_utxos);
        return 0;
    }
    free(all_utxos);

    /* Build inputs JSON array */
    cJSON *inputs = cJSON_CreateArray();
    for (size_t i = 0; i < n_sel; i++) {
        cJSON *inp = cJSON_CreateObject();
        cJSON_AddStringToObject(inp, "txid", selected[i].txid);
        cJSON_AddNumberToObject(inp, "vout", selected[i].vout);
        cJSON_AddItemToArray(inputs, inp);
    }
    free(selected);

    /* Build outputs JSON array */
    cJSON *outs_json = cJSON_CreateArray();
    for (size_t i = 0; i < n_outputs; i++) {
        /* Get address from scriptPubKey */
        char spk_hex[69];
        hex_encode(outputs[i].script_pubkey, outputs[i].script_pubkey_len, spk_hex);

        cJSON *out = cJSON_CreateObject();
        /* Use scriptPubKey hex as key — createrawtransaction handles it via "data" */
        char amount_str[32];
        snprintf(amount_str, sizeof(amount_str), "%.8f",
                 (double)outputs[i].amount_sats / 100000000.0);
        /* For createrawtransaction, we need address:amount pairs.
           Fall back to "data" output if we can't derive address. */
        cJSON_AddStringToObject(out, "data", spk_hex);
        cJSON_AddItemToArray(outs_json, out);
    }

    /* Add change output if non-zero */
    if (change > 0) {
        char change_addr[128];
        if (regtest_get_new_address(rt, change_addr, sizeof(change_addr))) {
            cJSON *chg = cJSON_CreateObject();
            char chg_str[32];
            snprintf(chg_str, sizeof(chg_str), "%.8f",
                     (double)change / 100000000.0);
            cJSON_AddStringToObject(chg, change_addr, chg_str);
            cJSON_AddItemToArray(outs_json, chg);
        }
    }

    /* Call createrawtransaction */
    char *inputs_str = cJSON_PrintUnformatted(inputs);
    char *outs_str = cJSON_PrintUnformatted(outs_json);
    cJSON_Delete(inputs);
    cJSON_Delete(outs_json);

    char *params = (char *)malloc(strlen(inputs_str) + strlen(outs_str) + 16);
    if (!params) { free(inputs_str); free(outs_str); return 0; }
    sprintf(params, "'%s' '%s'", inputs_str, outs_str);
    free(inputs_str);
    free(outs_str);

    char *raw = regtest_exec(rt, "createrawtransaction", params);
    free(params);
    if (!raw) return 0;

    /* Strip whitespace/quotes */
    char *s = raw;
    while (*s == '"' || *s == ' ' || *s == '\n') s++;
    char *e = s + strlen(s) - 1;
    while (e > s && (*e == '"' || *e == ' ' || *e == '\n')) *e-- = '\0';

    /* Sign */
    char *signed_hex = regtest_sign_raw_tx_with_wallet(rt, s, NULL);
    free(raw);
    if (!signed_hex) return 0;

    /* Copy signed hex out */
    if (signed_hex_out && hex_max > 0) {
        strncpy(signed_hex_out, signed_hex, hex_max - 1);
        signed_hex_out[hex_max - 1] = '\0';
    }

    /* Broadcast and get txid */
    char txid_buf[65];
    int ok = regtest_send_raw_tx(rt, signed_hex, txid_buf);
    free(signed_hex);

    if (ok && txid_hex_out)
        strncpy(txid_hex_out, txid_buf, 65);

    return ok;
}

/* --- RBF fee bumping (Mainnet Gap #2) --- */

int regtest_bump_fee(regtest_t *rt, const char *txid_hex,
                      uint64_t new_fee_rate_sat_vb) {
    if (!rt || !txid_hex) return 0;

    char params[256];
    snprintf(params, sizeof(params),
             "\"%s\" {\"fee_rate\": %llu}",
             txid_hex, (unsigned long long)new_fee_rate_sat_vb);

    char *result = regtest_exec(rt, "bumpfee", params);
    if (!result) return 0;

    /* Check for success: result should contain "txid" field */
    int ok = (strstr(result, "\"txid\"") != NULL);
    if (!ok)
        fprintf(stderr, "regtest_bump_fee: %s\n", result);
    free(result);
    return ok;
}

int regtest_wait_confirmed_with_bump(regtest_t *rt, const char *txid_hex,
                                      int target_blocks, int max_bumps,
                                      uint64_t initial_fee_rate,
                                      double fee_multiplier,
                                      int timeout_secs) {
    if (!rt || !txid_hex) return -1;

    int bumps_done = 0;
    uint64_t current_rate = initial_fee_rate;
    int start_height = regtest_get_block_height(rt);
    int elapsed = 0;
    int poll_interval = (strcmp(rt->network, "regtest") == 0) ? 5 : 30;

    while (elapsed < timeout_secs) {
        /* Check confirmation */
        int conf = regtest_get_confirmations(rt, txid_hex);
        if (conf >= 1) return conf;

        /* Check if enough blocks have passed for a bump */
        int current_height = regtest_get_block_height(rt);
        int blocks_passed = current_height - start_height;

        if (blocks_passed >= target_blocks && bumps_done < max_bumps) {
            current_rate = (uint64_t)((double)current_rate * fee_multiplier);
            printf("  Fee bump #%d: new rate %llu sat/vB\n",
                   bumps_done + 1, (unsigned long long)current_rate);

            if (regtest_bump_fee(rt, txid_hex, current_rate)) {
                bumps_done++;
                start_height = current_height; /* reset block counter */
            }
        }

        sleep(poll_interval);
        elapsed += poll_interval;
    }

    return -1; /* timeout */
}
