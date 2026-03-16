/*
 * test_lsp_discovery.c — Phase 2: LSP well-known endpoint tests
 *
 * Tests:
 *   test_wellknown_json_format   — JSON body has all required fields
 *   test_wellknown_json_parse    — parse a JSON body back into fields
 *   test_wellknown_http_serve    — handle_connection writes valid HTTP response
 */

#include "superscalar/lsp_wellknown.h"
#include <cJSON.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

static const lsp_wellknown_cfg_t TEST_CFG = {
    .pubkey_hex       = "02abc123def456abc123def456abc123def456abc123def456abc123def456ab0102",
    .host             = "lsp.example.com",
    .bolt8_port       = 9735,
    .native_port      = 9736,
    .network          = "bitcoin",
    .fee_ppm          = 1000,
    .min_channel_sats = 100000,
    .max_channel_sats = 10000000,
    .version          = "0.1.3",
};

/* -----------------------------------------------------------------------
 * Test 1: JSON builder produces all required fields
 * ----------------------------------------------------------------------- */
int test_wellknown_json_format(void) {
    char buf[2048];
    size_t n = lsp_wellknown_build_json(&TEST_CFG, buf, sizeof(buf));
    ASSERT(n > 0, "build_json returns non-zero length");

    cJSON *obj = cJSON_Parse(buf);
    ASSERT(obj != NULL, "JSON is valid");

    /* Required fields per LSP well-known spec */
    const cJSON *pubkey  = cJSON_GetObjectItemCaseSensitive(obj, "pubkey");
    const cJSON *host    = cJSON_GetObjectItemCaseSensitive(obj, "host");
    const cJSON *port    = cJSON_GetObjectItemCaseSensitive(obj, "bolt8_port");
    const cJSON *net     = cJSON_GetObjectItemCaseSensitive(obj, "network");
    const cJSON *lsps    = cJSON_GetObjectItemCaseSensitive(obj, "lsps");
    const cJSON *ss      = cJSON_GetObjectItemCaseSensitive(obj, "superscalar");
    const cJSON *fee     = cJSON_GetObjectItemCaseSensitive(obj, "fee_ppm");
    const cJSON *minch   = cJSON_GetObjectItemCaseSensitive(obj, "min_channel_sats");
    const cJSON *maxch   = cJSON_GetObjectItemCaseSensitive(obj, "max_channel_sats");
    const cJSON *ver     = cJSON_GetObjectItemCaseSensitive(obj, "version");

    ASSERT(cJSON_IsString(pubkey), "pubkey is string");
    ASSERT(strcmp(pubkey->valuestring, TEST_CFG.pubkey_hex) == 0,
           "pubkey value matches");
    ASSERT(cJSON_IsString(host), "host is string");
    ASSERT(strcmp(host->valuestring, TEST_CFG.host) == 0, "host value matches");
    ASSERT(cJSON_IsNumber(port), "bolt8_port is number");
    ASSERT((int)port->valuedouble == TEST_CFG.bolt8_port, "bolt8_port value");
    ASSERT(cJSON_IsString(net), "network is string");
    ASSERT(strcmp(net->valuestring, "bitcoin") == 0, "network is bitcoin");
    ASSERT(cJSON_IsArray(lsps), "lsps is array");
    ASSERT(cJSON_GetArraySize(lsps) == 3, "lsps has 3 entries");
    ASSERT(cJSON_IsTrue(ss), "superscalar is true");
    ASSERT(cJSON_IsNumber(fee), "fee_ppm is number");
    ASSERT((int)fee->valuedouble == 1000, "fee_ppm value");
    ASSERT(cJSON_IsNumber(minch), "min_channel_sats is number");
    ASSERT(cJSON_IsNumber(maxch), "max_channel_sats is number");
    ASSERT(cJSON_IsString(ver), "version is string");
    ASSERT(strcmp(ver->valuestring, "0.1.3") == 0, "version value");

    /* Verify lsps array contents */
    const cJSON *lsps0 = cJSON_GetArrayItem(lsps, 0);
    const cJSON *lsps1 = cJSON_GetArrayItem(lsps, 1);
    const cJSON *lsps2 = cJSON_GetArrayItem(lsps, 2);
    ASSERT(cJSON_IsString(lsps0) && strcmp(lsps0->valuestring, "lsps0") == 0,
           "lsps[0] is lsps0");
    ASSERT(cJSON_IsString(lsps1) && strcmp(lsps1->valuestring, "lsps1") == 0,
           "lsps[1] is lsps1");
    ASSERT(cJSON_IsString(lsps2) && strcmp(lsps2->valuestring, "lsps2") == 0,
           "lsps[2] is lsps2");

    cJSON_Delete(obj);
    return 1;
}

/* -----------------------------------------------------------------------
 * Test 2: JSON parser extracts host, port, pubkey correctly
 * ----------------------------------------------------------------------- */
int test_wellknown_json_parse(void) {
    /* Build JSON then round-trip through parse */
    char buf[2048];
    size_t n = lsp_wellknown_build_json(&TEST_CFG, buf, sizeof(buf));
    ASSERT(n > 0, "build_json succeeds");

    char host[256];
    uint16_t port = 0;
    char pubkey[128];

    ASSERT(lsp_wellknown_parse_json(buf, host, sizeof(host),
                                    &port, pubkey, sizeof(pubkey)),
           "parse_json succeeds");

    ASSERT(strcmp(host, TEST_CFG.host) == 0, "host round-trips correctly");
    ASSERT(port == TEST_CFG.bolt8_port, "port round-trips correctly");
    ASSERT(strcmp(pubkey, TEST_CFG.pubkey_hex) == 0, "pubkey round-trips correctly");

    /* Test that "port" field also works (some implementations use "port") */
    const char *alt_json =
        "{\"pubkey\":\"02aabbcc\","
        "\"host\":\"peer.example.com\","
        "\"port\":19735,"
        "\"network\":\"signet\","
        "\"superscalar\":true}";

    char alt_host[256]; uint16_t alt_port = 0; char alt_pub[64];
    ASSERT(lsp_wellknown_parse_json(alt_json, alt_host, sizeof(alt_host),
                                    &alt_port, alt_pub, sizeof(alt_pub)),
           "parse alt json (using 'port' field)");
    ASSERT(strcmp(alt_host, "peer.example.com") == 0, "alt host");
    ASSERT(alt_port == 19735, "alt port");
    ASSERT(strcmp(alt_pub, "02aabbcc") == 0, "alt pubkey");

    /* Test that missing required field fails */
    const char *bad_json = "{\"host\":\"x\",\"port\":9735}";  /* no pubkey */
    char bh[64]; uint16_t bp = 0; char bpk[64];
    ASSERT(!lsp_wellknown_parse_json(bad_json, bh, sizeof(bh),
                                     &bp, bpk, sizeof(bpk)),
           "missing pubkey field should fail");

    return 1;
}

/* -----------------------------------------------------------------------
 * Test 3: handle_connection writes valid HTTP 200 response with JSON body
 * ----------------------------------------------------------------------- */
int test_wellknown_http_serve(void) {
    /* Use socketpair to simulate client ↔ server */
    int sv[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    /* "Client" side: write GET request then read response */
    const char *req =
        "GET /.well-known/lsps.json HTTP/1.0\r\n"
        "Host: lsp.example.com\r\n\r\n";

    /* Write request on sv[0], run handler on sv[1] */
    ssize_t nw = write(sv[0], req, strlen(req));
    ASSERT(nw == (ssize_t)strlen(req), "write GET request");

    /* Shut down write side so server gets EOF after headers */
    shutdown(sv[0], SHUT_WR);

    /* Handle the connection — this closes sv[1] */
    lsp_wellknown_handle_connection(sv[1], &TEST_CFG);

    /* Read response from sv[0] */
    char resp[4096];
    size_t total = 0;
    ssize_t nr;
    while (total < sizeof(resp) - 1 &&
           (nr = read(sv[0], resp + total, sizeof(resp) - 1 - total)) > 0)
        total += (size_t)nr;
    resp[total] = '\0';
    close(sv[0]);

    ASSERT(total > 0, "received non-empty response");

    /* Verify status line */
    ASSERT(strncmp(resp, "HTTP/1.0 200 OK", 15) == 0, "HTTP 200 status");

    /* Find JSON body after blank line */
    const char *body = strstr(resp, "\r\n\r\n");
    ASSERT(body != NULL, "response has CRLFCRLF separator");
    body += 4;

    /* Parse and verify body */
    char host[256]; uint16_t port = 0; char pubkey[128];
    ASSERT(lsp_wellknown_parse_json(body, host, sizeof(host),
                                    &port, pubkey, sizeof(pubkey)),
           "response body is valid lsps.json");
    ASSERT(strcmp(host, TEST_CFG.host) == 0, "served host matches cfg");
    ASSERT(port == TEST_CFG.bolt8_port, "served port matches cfg");
    ASSERT(strcmp(pubkey, TEST_CFG.pubkey_hex) == 0, "served pubkey matches cfg");

    /* Test 404 for unknown path */
    int sv2[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0, "socketpair 2");
    const char *req404 =
        "GET /unknown HTTP/1.0\r\n\r\n";
    write(sv2[0], req404, strlen(req404));
    shutdown(sv2[0], SHUT_WR);
    lsp_wellknown_handle_connection(sv2[1], &TEST_CFG);

    char resp2[512]; size_t total2 = 0;
    while (total2 < sizeof(resp2) - 1 &&
           (nr = read(sv2[0], resp2 + total2, sizeof(resp2) - 1 - total2)) > 0)
        total2 += (size_t)nr;
    resp2[total2] = '\0';
    close(sv2[0]);

    ASSERT(strncmp(resp2, "HTTP/1.0 404", 12) == 0, "unknown path returns 404");

    return 1;
}

/* -----------------------------------------------------------------------
 * Test 4: end-to-end fetch from a local well-known HTTP server
 *
 * Forks a background server via lsp_wellknown_serve_fork(), then uses
 * lsp_wellknown_fetch_http_port() to retrieve and parse the response.
 * ----------------------------------------------------------------------- */
int test_client_bootstrap_from_domain(void) {
    /* Use a high port unlikely to collide with anything */
    uint16_t test_port = 18765;

    /* Fork a background server serving TEST_CFG */
    if (!lsp_wellknown_serve_fork(&TEST_CFG, test_port)) {
        /* If fork is unavailable (e.g. some sandboxes), skip gracefully */
        printf("  SKIP: lsp_wellknown_serve_fork unavailable\n");
        return 1;
    }

    /* Give the child process time to bind and listen */
    usleep(150000);  /* 150 ms */

    char host[256]   = {0};
    uint16_t port    = 0;
    char pubkey[128] = {0};

    ASSERT(lsp_wellknown_fetch_http_port("127.0.0.1", test_port,
                                         host, sizeof(host),
                                         &port, pubkey, sizeof(pubkey)),
           "fetch_http_port from local server succeeds");

    ASSERT(strcmp(host, TEST_CFG.host) == 0, "fetched host matches cfg");
    ASSERT(port == TEST_CFG.bolt8_port,       "fetched port matches cfg");
    ASSERT(strcmp(pubkey, TEST_CFG.pubkey_hex) == 0, "fetched pubkey matches cfg");

    return 1;
}
