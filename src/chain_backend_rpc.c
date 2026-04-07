/*
 * chain_backend_rpc.c — HTTP JSON-RPC chain backend for Bitcoin Core.
 *
 * Works with any network (mainnet, signet, testnet, regtest).
 * Uses direct TCP socket + HTTP/1.0 POST to bitcoind's JSON-RPC interface.
 * No external dependencies beyond POSIX sockets and cJSON (already vendored).
 */

#include "superscalar/chain_backend_rpc.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>

/* ------------------------------------------------------------------ */
/* Base64 encoder (for HTTP Basic Auth)                                 */
/* ------------------------------------------------------------------ */

static int rpc_base64(const char *in, size_t in_len, char *out, size_t out_cap)
{
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t olen = ((in_len + 2) / 3) * 4;
    if (olen + 1 > out_cap) return -1;
    size_t i, j;
    for (i = 0, j = 0; i + 2 < in_len; i += 3) {
        unsigned c0 = (unsigned char)in[i];
        unsigned c1 = (unsigned char)in[i+1];
        unsigned c2 = (unsigned char)in[i+2];
        out[j++] = b64[(c0 >> 2) & 0x3f];
        out[j++] = b64[((c0 << 4) | (c1 >> 4)) & 0x3f];
        out[j++] = b64[((c1 << 2) | (c2 >> 6)) & 0x3f];
        out[j++] = b64[c2 & 0x3f];
    }
    if (i < in_len) {
        unsigned c0 = (unsigned char)in[i];
        unsigned c1 = (i + 1 < in_len) ? (unsigned char)in[i+1] : 0;
        out[j++] = b64[(c0 >> 2) & 0x3f];
        out[j++] = b64[((c0 << 4) | (c1 >> 4)) & 0x3f];
        out[j++] = (i + 1 < in_len) ? b64[(c1 << 2) & 0x3f] : '=';
        out[j++] = '=';
    }
    out[j] = '\0';
    return (int)j;
}

/* ------------------------------------------------------------------ */
/* Core HTTP JSON-RPC call                                              */
/* ------------------------------------------------------------------ */

/* Send a JSON-RPC call to bitcoind and return the parsed "result" field.
   Caller must cJSON_Delete the returned object. Returns NULL on error. */
static cJSON *rpc_call(const chain_backend_rpc_ctx_t *rpc,
                        const char *method, cJSON *params)
{
    /* Basic Auth header */
    char credentials[512];
    snprintf(credentials, sizeof(credentials), "%s:%s",
             rpc->rpcuser, rpc->rpcpassword);
    char auth_b64[512];
    if (rpc_base64(credentials, strlen(credentials), auth_b64, sizeof(auth_b64)) < 0)
        return NULL;

    /* Build JSON-RPC body */
    cJSON *req_json = cJSON_CreateObject();
    cJSON_AddStringToObject(req_json, "jsonrpc", "1.0");
    cJSON_AddNumberToObject(req_json, "id", 1);
    cJSON_AddStringToObject(req_json, "method", method);
    if (params)
        cJSON_AddItemToObject(req_json, "params", params);
    else
        cJSON_AddItemToObject(req_json, "params", cJSON_CreateArray());

    char *body = cJSON_PrintUnformatted(req_json);
    cJSON_Delete(req_json);
    if (!body) return NULL;
    int body_len = (int)strlen(body);

    /* Wallet path */
    char path[256] = "/";
    if (rpc->wallet[0] != '\0')
        snprintf(path, sizeof(path), "/wallet/%s", rpc->wallet);

    /* Build HTTP request */
    size_t reqcap = (size_t)body_len + 512;
    char *req = malloc(reqcap);
    if (!req) { free(body); return NULL; }
    int req_len = snprintf(req, reqcap,
        "POST %s HTTP/1.0\r\n"
        "Host: %s:%d\r\n"
        "Authorization: Basic %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        path, rpc->host, rpc->port, auth_b64, body_len, body);
    free(body);
    if (req_len <= 0 || (size_t)req_len >= reqcap) { free(req); return NULL; }

    /* Connect */
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", rpc->port);
    if (getaddrinfo(rpc->host, port_str, &hints, &res) != 0) {
        free(req); return NULL;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); free(req); return NULL; }
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd); freeaddrinfo(res); free(req); return NULL;
    }
    freeaddrinfo(res);

    /* Send */
    ssize_t sent = send(fd, req, (size_t)req_len, 0);
    free(req);
    if (sent != (ssize_t)req_len) { close(fd); return NULL; }

    /* Receive */
    size_t cap = 65536, used = 0;
    char *resp = malloc(cap);
    if (!resp) { close(fd); return NULL; }
    ssize_t n;
    while ((n = recv(fd, resp + used, cap - used - 1, 0)) > 0) {
        used += (size_t)n;
        if (used + 1 >= cap) {
            cap *= 2;
            char *tmp = realloc(resp, cap);
            if (!tmp) { free(resp); close(fd); return NULL; }
            resp = tmp;
        }
    }
    close(fd);
    resp[used] = '\0';

    /* Parse HTTP body */
    char *bodyp = strstr(resp, "\r\n\r\n");
    if (!bodyp) { free(resp); return NULL; }
    bodyp += 4;

    cJSON *jresp = cJSON_Parse(bodyp);
    free(resp);
    if (!jresp) return NULL;

    /* Check for RPC error */
    cJSON *err = cJSON_GetObjectItem(jresp, "error");
    if (err && !cJSON_IsNull(err)) {
        cJSON_Delete(jresp);
        return NULL;
    }

    /* Detach and return result */
    cJSON *result = cJSON_DetachItemFromObject(jresp, "result");
    cJSON_Delete(jresp);
    return result;
}

/* ------------------------------------------------------------------ */
/* chain_backend_t vtable implementations                               */
/* ------------------------------------------------------------------ */

static int cb_rpc_get_block_height(chain_backend_t *self)
{
    chain_backend_rpc_ctx_t *rpc = (chain_backend_rpc_ctx_t *)self->ctx;
    cJSON *result = rpc_call(rpc, "getblockcount", NULL);
    if (!result) return -1;
    int height = -1;
    if (cJSON_IsNumber(result))
        height = (int)result->valuedouble;
    cJSON_Delete(result);
    return height;
}

static int cb_rpc_get_confirmations(chain_backend_t *self, const char *txid_hex)
{
    chain_backend_rpc_ctx_t *rpc = (chain_backend_rpc_ctx_t *)self->ctx;

    /* Try gettransaction first (wallet TX) */
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(txid_hex));
    cJSON *result = rpc_call(rpc, "gettransaction", params);

    if (result) {
        cJSON *confs = cJSON_GetObjectItem(result, "confirmations");
        int c = confs && cJSON_IsNumber(confs) ? (int)confs->valuedouble : 0;
        cJSON_Delete(result);
        return c > 0 ? c : 0;
    }

    /* Fallback: getrawtransaction (requires -txindex or mempool) */
    params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(txid_hex));
    cJSON_AddItemToArray(params, cJSON_CreateBool(1)); /* verbose */
    result = rpc_call(rpc, "getrawtransaction", params);

    if (result) {
        cJSON *confs = cJSON_GetObjectItem(result, "confirmations");
        int c = confs && cJSON_IsNumber(confs) ? (int)confs->valuedouble : 0;
        cJSON_Delete(result);
        return c > 0 ? c : 0;
    }

    return -1; /* TX not found */
}

static int cb_rpc_get_confirmations_batch(chain_backend_t *self,
                                           const char **txids_hex,
                                           size_t n_txids,
                                           int *confs_out)
{
    for (size_t i = 0; i < n_txids; i++)
        confs_out[i] = self->get_confirmations(self, txids_hex[i]);
    return 1;
}

static bool cb_rpc_is_in_mempool(chain_backend_t *self, const char *txid_hex)
{
    chain_backend_rpc_ctx_t *rpc = (chain_backend_rpc_ctx_t *)self->ctx;
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(txid_hex));
    cJSON *result = rpc_call(rpc, "getmempoolentry", params);
    if (result) {
        cJSON_Delete(result);
        return true;
    }
    return false;
}

static int cb_rpc_send_raw_tx(chain_backend_t *self, const char *tx_hex,
                                char *txid_out)
{
    chain_backend_rpc_ctx_t *rpc = (chain_backend_rpc_ctx_t *)self->ctx;
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(tx_hex));
    cJSON *result = rpc_call(rpc, "sendrawtransaction", params);
    if (!result) return 0;
    if (cJSON_IsString(result) && txid_out) {
        strncpy(txid_out, result->valuestring, 64);
        txid_out[64] = '\0';
    }
    cJSON_Delete(result);
    return 1;
}

static int cb_rpc_register_script(chain_backend_t *self,
                                    const unsigned char *spk, size_t spk_len)
{
    (void)self; (void)spk; (void)spk_len;
    return 1; /* no-op for RPC polling */
}

static int cb_rpc_unregister_script(chain_backend_t *self,
                                      const unsigned char *spk, size_t spk_len)
{
    (void)self; (void)spk; (void)spk_len;
    return 1;
}

/* ------------------------------------------------------------------ */
/* Initialization                                                       */
/* ------------------------------------------------------------------ */

int chain_backend_rpc_init(chain_backend_t *backend,
                            const char *host, int port,
                            const char *rpcuser, const char *rpcpassword,
                            const char *wallet,
                            const char *network)
{
    if (!backend || !host || !rpcuser || !rpcpassword) return 0;

    chain_backend_rpc_ctx_t *rpc = calloc(1, sizeof(chain_backend_rpc_ctx_t));
    if (!rpc) return 0;

    strncpy(rpc->host, host, sizeof(rpc->host) - 1);
    rpc->port = port;
    strncpy(rpc->rpcuser, rpcuser, sizeof(rpc->rpcuser) - 1);
    strncpy(rpc->rpcpassword, rpcpassword, sizeof(rpc->rpcpassword) - 1);
    if (wallet)
        strncpy(rpc->wallet, wallet, sizeof(rpc->wallet) - 1);

    /* Auto-detect port from network if not specified */
    if (rpc->port <= 0) {
        if (strcmp(network, "regtest") == 0)       rpc->port = 18443;
        else if (strcmp(network, "testnet") == 0)   rpc->port = 18332;
        else if (strcmp(network, "testnet4") == 0)  rpc->port = 48332;
        else if (strcmp(network, "signet") == 0)    rpc->port = 38332;
        else                                        rpc->port = 8332; /* mainnet */
    }

    backend->get_block_height        = cb_rpc_get_block_height;
    backend->get_confirmations       = cb_rpc_get_confirmations;
    backend->get_confirmations_batch = cb_rpc_get_confirmations_batch;
    backend->is_in_mempool           = cb_rpc_is_in_mempool;
    backend->send_raw_tx             = cb_rpc_send_raw_tx;
    backend->register_script         = cb_rpc_register_script;
    backend->unregister_script       = cb_rpc_unregister_script;
    backend->ctx                     = rpc;
    backend->is_regtest              = (network && strcmp(network, "regtest") == 0);
    conf_targets_default(&backend->conf);

    return 1;
}
