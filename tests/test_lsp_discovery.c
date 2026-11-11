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
#include <signal.h>

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
 * Forks a background server on a free port, then uses
 * lsp_wellknown_fetch_http_port() to retrieve and parse the response.
 * ----------------------------------------------------------------------- */
/* Stop a server started with lsp_wellknown_serve_fork() and reap it, so the
   test leaves no process behind. */
static void stop_server(int server_pid) {
    if (server_pid <= 0) return;
    kill((pid_t)server_pid, SIGTERM);
    waitpid((pid_t)server_pid, NULL, 0);
}

int test_client_bootstrap_from_domain(void) {
    /* Fork a background server serving TEST_CFG on a free port.  Not being
       able to start it is a failure: the test must not pass without running. */
    uint16_t test_port = 0;
    int server = lsp_wellknown_serve_fork_any_port(&TEST_CFG, &test_port);
    ASSERT(server > 0 && test_port != 0, "well-known test server starts");

    /* Give the child process time to bind and listen */
    usleep(150000);  /* 150 ms */

    char host[256]   = {0};
    uint16_t port    = 0;
    char pubkey[128] = {0};

    int fetched = lsp_wellknown_fetch_http_port("127.0.0.1", test_port,
                                                host, sizeof(host),
                                                &port, pubkey, sizeof(pubkey));
    stop_server(server);

    ASSERT(fetched, "fetch_http_port from local server succeeds");
    ASSERT(strcmp(host, TEST_CFG.host) == 0, "fetched host matches cfg");
    ASSERT(port == TEST_CFG.bolt8_port,       "fetched port matches cfg");
    ASSERT(strcmp(pubkey, TEST_CFG.pubkey_hex) == 0, "fetched pubkey matches cfg");

    return 1;
}

/* -----------------------------------------------------------------------
 * Test 5: a key from the well-known response never becomes the pinned key
 *
 * The response is fetched over plain HTTP, so whoever controls the network
 * path chooses the key in it.  Only the key the operator configured can pin
 * the LSP; the advertised key can agree with it or contradict it.
 * ----------------------------------------------------------------------- */
int test_wellknown_pubkey_never_pins(void) {
    const char *operator_key =
        "02abc123def456abc123def456abc123def456abc123def456abc123def456ab0102";
    const char *operator_key_upper =
        "02ABC123DEF456ABC123DEF456ABC123DEF456ABC123DEF456ABC123DEF456AB0102";
    const char *other_key =
        "03ffc123def456abc123def456abc123def456abc123def456abc123def456ab0102";
    const char *pin;

    /* No configured key: the advertised key must not be adopted. */
    pin = other_key;
    ASSERT(lsp_wellknown_select_pin(NULL, other_key, &pin) == LSP_PIN_NONE,
           "advertised key alone pins nothing");
    ASSERT(pin == NULL, "no pin without a configured key");

    pin = other_key;
    ASSERT(lsp_wellknown_select_pin(NULL, NULL, &pin) == LSP_PIN_NONE,
           "no keys at all pins nothing");
    ASSERT(pin == NULL, "no pin without any key");

    /* Configured key, matching advertisement: the configured key is pinned. */
    pin = NULL;
    ASSERT(lsp_wellknown_select_pin(operator_key, operator_key_upper, &pin)
               == LSP_PIN_CONFIGURED,
           "matching advertisement (any hex case) is accepted");
    ASSERT(pin == operator_key, "the configured key is the pin");

    /* Configured key, nothing advertised (no --lsp lookup). */
    pin = NULL;
    ASSERT(lsp_wellknown_select_pin(operator_key, NULL, &pin) == LSP_PIN_CONFIGURED,
           "configured key pins without a lookup");
    ASSERT(pin == operator_key, "the configured key is the pin");

    /* Configured key, different advertisement: reported, and the advertised
       key is still not handed out. */
    pin = other_key;
    ASSERT(lsp_wellknown_select_pin(operator_key, other_key, &pin) == LSP_PIN_MISMATCH,
           "differing advertisement is a mismatch");
    ASSERT(pin == NULL, "no pin on mismatch");

    /* pin_out is optional. */
    ASSERT(lsp_wellknown_select_pin(NULL, other_key, NULL) == LSP_PIN_NONE,
           "NULL pin_out is accepted");
    return 1;
}

/* -----------------------------------------------------------------------
 * Test 6: the client's start-up resolution of the LSP endpoint and pin
 *
 * Runs the function the client calls at start-up against a local well-known
 * server whose response advertises TEST_CFG.pubkey_hex.  The advertised key
 * must never end up pinned and must never satisfy the pin requirement.
 * ----------------------------------------------------------------------- */
int test_client_endpoint_resolution(void) {
    const char *other_key =
        "03ffc123def456abc123def456abc123def456abc123def456abc123def456ab0102";

    uint16_t test_port = 0;
    int server = lsp_wellknown_serve_fork_any_port(&TEST_CFG, &test_port);
    ASSERT(server > 0 && test_port != 0, "well-known test server starts");
    usleep(150000);

    lsp_endpoint_t no_key_required, no_key_optional, mismatch, match;
    lsp_endpoint_status_t st_required = lsp_wellknown_resolve_endpoint(
        "127.0.0.1", test_port, "ignored.example", 1, NULL, 1, &no_key_required);
    lsp_endpoint_status_t st_optional = lsp_wellknown_resolve_endpoint(
        "127.0.0.1", test_port, "ignored.example", 1, NULL, 0, &no_key_optional);
    lsp_endpoint_status_t st_mismatch = lsp_wellknown_resolve_endpoint(
        "127.0.0.1", test_port, "ignored.example", 1, other_key, 1, &mismatch);
    lsp_endpoint_status_t st_match = lsp_wellknown_resolve_endpoint(
        "127.0.0.1", test_port, "ignored.example", 1, TEST_CFG.pubkey_hex, 1, &match);
    stop_server(server);

    /* Lookup without --lsp-pubkey where a pin is required: refused, although
       the response carries a key. */
    ASSERT(st_required == LSP_ENDPOINT_PIN_REQUIRED,
           "advertised key does not satisfy the pin requirement");
    ASSERT(no_key_required.pinned_pubkey_hex == NULL, "nothing pinned");
    ASSERT(strcmp(no_key_required.advertised_pubkey_hex, TEST_CFG.pubkey_hex) == 0,
           "advertised key is reported for display");

    /* Same lookup where no pin is required (regtest): allowed, still unpinned. */
    ASSERT(st_optional == LSP_ENDPOINT_OK, "no pin required: lookup alone is enough");
    ASSERT(no_key_optional.pinned_pubkey_hex == NULL, "advertised key is not pinned");
    ASSERT(strcmp(no_key_optional.host, TEST_CFG.host) == 0, "host from the lookup");
    ASSERT(no_key_optional.port == TEST_CFG.bolt8_port, "port from the lookup");

    /* --lsp-pubkey differs from the advertised key. */
    ASSERT(st_mismatch == LSP_ENDPOINT_PIN_MISMATCH, "mismatch is refused");
    ASSERT(mismatch.pinned_pubkey_hex == NULL, "nothing pinned on mismatch");

    /* --lsp-pubkey equals the advertised key: the operator's key is pinned. */
    ASSERT(st_match == LSP_ENDPOINT_OK, "matching key is accepted");
    ASSERT(match.pinned_pubkey_hex == TEST_CFG.pubkey_hex, "the configured key is pinned");
    ASSERT(strcmp(match.host, TEST_CFG.host) == 0, "host from the lookup");

    /* The server is gone now: the lookup fails and yields nothing. */
    lsp_endpoint_t failed;
    ASSERT(lsp_wellknown_resolve_endpoint("127.0.0.1", test_port, "h", 1,
                                          TEST_CFG.pubkey_hex, 1, &failed)
               == LSP_ENDPOINT_FETCH_FAILED,
           "failed lookup is reported");
    ASSERT(failed.pinned_pubkey_hex == NULL && failed.host[0] == '\0',
           "no endpoint from a failed lookup");

    /* No lookup (--host/--port): the endpoint is passed through. */
    lsp_endpoint_t direct;
    ASSERT(lsp_wellknown_resolve_endpoint(NULL, 80, "lsp.example.org", 9735,
                                          other_key, 1, &direct) == LSP_ENDPOINT_OK,
           "direct endpoint with a configured key");
    ASSERT(strcmp(direct.host, "lsp.example.org") == 0 && direct.port == 9735,
           "host and port passed through");
    ASSERT(direct.pinned_pubkey_hex == other_key, "configured key pinned");
    ASSERT(direct.advertised_pubkey_hex[0] == '\0', "nothing advertised");

    ASSERT(lsp_wellknown_resolve_endpoint(NULL, 80, "lsp.example.org", 9735,
                                          NULL, 1, &direct) == LSP_ENDPOINT_PIN_REQUIRED,
           "direct endpoint without a key where one is required");
    ASSERT(lsp_wellknown_resolve_endpoint(NULL, 80, "127.0.0.1", 9735,
                                          NULL, 0, &direct) == LSP_ENDPOINT_OK,
           "direct endpoint without a key where none is required");
    ASSERT(direct.pinned_pubkey_hex == NULL, "nothing pinned");
    return 1;
}

/* -----------------------------------------------------------------------
 * Test 7: server start-up on a fixed port and on a free port
 * ----------------------------------------------------------------------- */
int test_wellknown_serve_fork_ports(void) {
    ASSERT(lsp_wellknown_serve_fork(&TEST_CFG, 0) == 0, "port 0 is not a fixed port");
    ASSERT(lsp_wellknown_serve_fork_any_port(&TEST_CFG, NULL) == 0, "port out is required");
    ASSERT(lsp_wellknown_serve_fork_any_port(NULL, &(uint16_t){0}) == 0, "cfg is required");

    uint16_t port_a = 0, port_b = 0;
    int server_a = lsp_wellknown_serve_fork_any_port(&TEST_CFG, &port_a);
    int server_b = lsp_wellknown_serve_fork_any_port(&TEST_CFG, &port_b);
    stop_server(server_a);
    stop_server(server_b);

    ASSERT(server_a > 0 && server_b > 0, "two servers start");
    ASSERT(port_a != 0 && port_b != 0 && port_a != port_b, "each on its own port");
    return 1;
}
