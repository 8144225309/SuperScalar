#include "superscalar/fee_estimator.h"
#include "cJSON.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

/* Default mempool.space endpoint */
#define MEMPOOL_SPACE_URL "https://mempool.space/api/v1/fees/recommended"

/* -----------------------------------------------------------------------
 * Built-in HTTP GET (POSIX sockets + OpenSSL for HTTPS)
 * Simple synchronous implementation — app can replace via ss_http_get_fn.
 * --------------------------------------------------------------------- */

#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* Parse "http[s]://host[:port]/path" into components.
   Returns 1 on success. */
static int parse_url(const char *url, char *scheme, char *host, int *port, char *path)
{
    if (strncmp(url, "https://", 8) == 0) {
        strcpy(scheme, "https");
        url += 8;
        *port = 443;
    } else if (strncmp(url, "http://", 7) == 0) {
        strcpy(scheme, "http");
        url += 7;
        *port = 80;
    } else {
        return 0;
    }
    /* host[:port]/path */
    const char *slash = strchr(url, '/');
    const char *colon = strchr(url, ':');
    if (colon && (!slash || colon < slash)) {
        size_t hlen = (size_t)(colon - url);
        if (hlen >= 256) return 0;
        memcpy(host, url, hlen);
        host[hlen] = '\0';
        *port = atoi(colon + 1);
        url = slash ? slash : "";
    } else {
        size_t hlen = slash ? (size_t)(slash - url) : strlen(url);
        if (hlen >= 256) return 0;
        memcpy(host, url, hlen);
        host[hlen] = '\0';
        url = slash ? slash : "";
    }
    snprintf(path, 1024, "%s", url[0] ? url : "/");
    return 1;
}

char *ss_http_get_simple(const char *url, void *ctx)
{
    (void)ctx;
    char scheme[8], host[256], path[1024];
    int port;
    if (!parse_url(url, scheme, host, &port, path)) return NULL;

    /* Resolve host */
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return NULL;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return NULL; }
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd); freeaddrinfo(res); return NULL;
    }
    freeaddrinfo(res);

    /* Build request */
    char req[1536];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.0\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n\r\n",
             path, host);

    char *body = NULL;

    if (strcmp(scheme, "https") == 0) {
        SSL_CTX *sctx = SSL_CTX_new(TLS_client_method());
        if (!sctx) { close(fd); return NULL; }
        SSL_CTX_set_verify(sctx, SSL_VERIFY_NONE, NULL);
        SSL *ssl = SSL_new(sctx);
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, host);
        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl); SSL_CTX_free(sctx); close(fd); return NULL;
        }
        SSL_write(ssl, req, (int)strlen(req));

        /* Read response */
        char buf[4096];
        size_t cap = 65536, used = 0;
        char *resp = malloc(cap);
        if (!resp) { SSL_free(ssl); SSL_CTX_free(sctx); close(fd); return NULL; }
        int n;
        while ((n = SSL_read(ssl, buf, (int)sizeof(buf))) > 0) {
            if (used + (size_t)n + 1 > cap) {
                cap *= 2;
                char *tmp = realloc(resp, cap);
                if (!tmp) { free(resp); resp = NULL; break; }
                resp = tmp;
            }
            memcpy(resp + used, buf, (size_t)n);
            used += (size_t)n;
        }
        SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(sctx); close(fd);
        if (!resp) return NULL;
        resp[used] = '\0';
        /* Find body after blank line */
        char *bodyp = strstr(resp, "\r\n\r\n");
        if (!bodyp) { free(resp); return NULL; }
        body = strdup(bodyp + 4);
        free(resp);
    } else {
        /* Plain HTTP */
        send(fd, req, strlen(req), 0);
        char buf[4096];
        size_t cap = 65536, used = 0;
        char *resp = malloc(cap);
        if (!resp) { close(fd); return NULL; }
        ssize_t n;
        while ((n = recv(fd, buf, sizeof(buf), 0)) > 0) {
            if (used + (size_t)n + 1 > cap) {
                cap *= 2;
                char *tmp = realloc(resp, cap);
                if (!tmp) { free(resp); resp = NULL; break; }
                resp = tmp;
            }
            memcpy(resp + used, buf, (size_t)n);
            used += (size_t)n;
        }
        close(fd);
        if (!resp) return NULL;
        resp[used] = '\0';
        char *bodyp = strstr(resp, "\r\n\r\n");
        if (!bodyp) { free(resp); return NULL; }
        body = strdup(bodyp + 4);
        free(resp);
    }
    return body;
}

/* -----------------------------------------------------------------------
 * Parse mempool.space JSON
 * {"fastestFee":N,"halfHourFee":N,"hourFee":N,"economyFee":N,"minimumFee":N}
 * All values in sat/vByte; multiply by 1000 to get sat/kvB.
 * --------------------------------------------------------------------- */
static int parse_mempool_json(const char *body, uint64_t cached[4])
{
    cJSON *json = cJSON_Parse(body);
    if (!json) return 0;

    cJSON *fastest = cJSON_GetObjectItem(json, "fastestFee");
    cJSON *half    = cJSON_GetObjectItem(json, "halfHourFee");
    cJSON *economy = cJSON_GetObjectItem(json, "economyFee");
    cJSON *minimum = cJSON_GetObjectItem(json, "minimumFee");

    int ok = 0;
    if (fastest && cJSON_IsNumber(fastest) && fastest->valuedouble > 0) {
        cached[FEE_RPC_IDX_URGENT] = (uint64_t)(fastest->valuedouble * 1000.0 + 0.5);
        ok = 1;
    }
    if (half && cJSON_IsNumber(half) && half->valuedouble > 0)
        cached[FEE_RPC_IDX_NORMAL] = (uint64_t)(half->valuedouble * 1000.0 + 0.5);
    if (economy && cJSON_IsNumber(economy) && economy->valuedouble > 0)
        cached[FEE_RPC_IDX_ECONOMY] = (uint64_t)(economy->valuedouble * 1000.0 + 0.5);
    if (minimum && cJSON_IsNumber(minimum) && minimum->valuedouble > 0)
        cached[FEE_RPC_IDX_MINIMUM] = (uint64_t)(minimum->valuedouble * 1000.0 + 0.5);

    /* Clamp all to minimum 1000 sat/kvB */
    for (int i = 0; i < 4; i++)
        if (cached[i] < 1000) cached[i] = 1000;

    cJSON_Delete(json);
    return ok;
}

static int rpc_idx_for_target(fee_target_t target)
{
    switch (target) {
        case FEE_TARGET_URGENT:  return FEE_RPC_IDX_URGENT;
        case FEE_TARGET_NORMAL:  return FEE_RPC_IDX_NORMAL;
        case FEE_TARGET_ECONOMY: return FEE_RPC_IDX_ECONOMY;
        case FEE_TARGET_MINIMUM: return FEE_RPC_IDX_MINIMUM;
        default:                 return FEE_RPC_IDX_NORMAL;
    }
}

static void api_fetch(fee_estimator_api_t *fe)
{
    char *body = fe->http_get(fe->url, fe->http_ctx);
    if (!body) return;
    parse_mempool_json(body, fe->cached);
    free(body);
    fe->last_updated = (uint64_t)time(NULL);
}

static uint64_t api_get_rate(fee_estimator_t *self, fee_target_t target)
{
    fee_estimator_api_t *fe = (fee_estimator_api_t *)self;
    uint64_t now = (uint64_t)time(NULL);
    int idx = rpc_idx_for_target(target);

    if (fe->cached[idx] == 0 || now - fe->last_updated >= (uint64_t)fe->ttl_seconds)
        api_fetch(fe);

    return fe->cached[idx];
}

static void api_update(fee_estimator_t *self)
{
    fee_estimator_api_t *fe = (fee_estimator_api_t *)self;
    uint64_t now = (uint64_t)time(NULL);
    if (now - fe->last_updated >= (uint64_t)fe->ttl_seconds)
        api_fetch(fe);
}

void fee_estimator_api_init(fee_estimator_api_t *fe,
                             const char *url,
                             ss_http_get_fn http_get,
                             void *http_ctx)
{
    if (!fe) return;
    memset(fe, 0, sizeof(*fe));
    fe->base.get_rate = api_get_rate;
    fe->base.update   = api_update;
    fe->base.free     = NULL;
    strncpy(fe->url, url ? url : MEMPOOL_SPACE_URL, FEE_API_URL_MAX - 1);
    fe->url[FEE_API_URL_MAX - 1] = '\0';
    fe->http_get   = http_get ? http_get : ss_http_get_simple;
    fe->http_ctx   = http_ctx;
    fe->ttl_seconds = 60;
}
