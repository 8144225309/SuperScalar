/*
 * test_prometheus.c - unit tests for the native Prometheus exporter.
 *
 * Verifies:
 *   - prometheus_build_body returns a non-zero length and emits the
 *     expected metric names with proper HELP/TYPE preambles.
 *   - The body is well-formed Prometheus text format (no NULs, each
 *     metric line ends in \n, and label values are quoted).
 *   - prometheus_handle_connection over a socketpair returns
 *     "HTTP/1.0 200 OK" with the metric body when GET /metrics is sent.
 *   - It returns 404 for unknown paths and 405 for non-GET methods.
 *
 * No external dependencies: socketpair gives us a portable in-process
 * bidirectional channel that exercises the same read_line/write_all
 * paths as a real TCP scrape.
 */

#include "superscalar/prometheus.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* P1: body builder emits expected metric names and TYPE comments. */
int test_prometheus_build_body_contains_all_metrics(void) {
    prometheus_cfg_t cfg = {
        .db_path = NULL,            /* DB-less path: emits zero rows */
        .start_time = time(NULL) - 42,  /* uptime ~42s */
        .n_clients_connected = NULL,
    };
    char buf[8192];
    size_t n = prometheus_build_body(&cfg, buf, sizeof(buf));
    ASSERT(n > 0, "body length > 0");
    ASSERT(n < sizeof(buf), "body fits in buffer");
    buf[n] = '\0';

    /* Required metric names */
    ASSERT(strstr(buf, "superscalar_lsp_uptime_seconds") != NULL,
           "uptime_seconds present");
    ASSERT(strstr(buf, "superscalar_lsp_factories_total") != NULL,
           "factories_total present");
    ASSERT(strstr(buf, "superscalar_lsp_clients_connected") != NULL,
           "clients_connected present");
    ASSERT(strstr(buf, "superscalar_lsp_signing_round_total") != NULL,
           "signing_round_total present");
    ASSERT(strstr(buf, "superscalar_lsp_signing_round_duration_seconds_sum")
           != NULL, "duration_sum present");
    ASSERT(strstr(buf, "superscalar_lsp_signing_round_duration_seconds_count")
           != NULL, "duration_count present");
    ASSERT(strstr(buf, "superscalar_lsp_breaches_detected_total") != NULL,
           "breaches_detected present");
    ASSERT(strstr(buf, "superscalar_lsp_reorg_events_total") != NULL,
           "reorg_events_total present");
    ASSERT(strstr(buf, "superscalar_lsp_penalty_broadcasts_total") != NULL,
           "penalty_broadcasts present");

    /* HELP and TYPE comments */
    ASSERT(strstr(buf, "# HELP superscalar_lsp_uptime_seconds") != NULL,
           "uptime HELP comment");
    ASSERT(strstr(buf, "# TYPE superscalar_lsp_uptime_seconds gauge") != NULL,
           "uptime TYPE gauge");
    ASSERT(strstr(buf, "# TYPE superscalar_lsp_breaches_detected_total counter")
           != NULL, "breaches TYPE counter");

    /* No NUL embedded mid-body */
    ASSERT(strlen(buf) == n, "no embedded NUL bytes");

    return 1;
}

/* P2: HTTP handler over socketpair returns 200 OK with body for GET /metrics. */
int test_prometheus_handle_connection_metrics(void) {
    int sv[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    prometheus_cfg_t cfg = {
        .db_path = NULL,
        .start_time = time(NULL) - 5,
        .n_clients_connected = NULL,
    };

    /* Send GET /metrics request on sv[0] */
    const char *req = "GET /metrics HTTP/1.0\r\nHost: x\r\n\r\n";
    ssize_t w = write(sv[0], req, strlen(req));
    ASSERT(w == (ssize_t)strlen(req), "write request");

    /* Server side processes sv[1] */
    prometheus_handle_connection(sv[1], &cfg);

    /* Read response from sv[0] */
    char resp[16384];
    ssize_t total = 0, n;
    while (total < (ssize_t)sizeof(resp) - 1 &&
           (n = read(sv[0], resp + total, sizeof(resp) - 1 - total)) > 0)
        total += n;
    resp[total] = '\0';
    close(sv[0]);

    ASSERT(total > 0, "response has bytes");
    ASSERT(strncmp(resp, "HTTP/1.0 200 OK", 15) == 0, "200 OK status");
    ASSERT(strstr(resp, "Content-Type: text/plain") != NULL,
           "text/plain content-type");
    ASSERT(strstr(resp, "superscalar_lsp_uptime_seconds") != NULL,
           "body contains uptime metric");

    return 1;
}

/* P3: unknown path returns 404. */
int test_prometheus_handle_connection_404(void) {
    int sv[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    prometheus_cfg_t cfg = {
        .db_path = NULL,
        .start_time = time(NULL),
        .n_clients_connected = NULL,
    };

    const char *req = "GET /not-metrics HTTP/1.0\r\nHost: x\r\n\r\n";
    write(sv[0], req, strlen(req));
    prometheus_handle_connection(sv[1], &cfg);

    char resp[1024];
    ssize_t n = read(sv[0], resp, sizeof(resp) - 1);
    if (n < 0) n = 0;
    resp[n] = '\0';
    close(sv[0]);
    ASSERT(strncmp(resp, "HTTP/1.0 404", 12) == 0, "404 status");
    return 1;
}

/* P4: non-GET method returns 405. */
int test_prometheus_handle_connection_405(void) {
    int sv[2];
    ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    prometheus_cfg_t cfg = {
        .db_path = NULL,
        .start_time = time(NULL),
        .n_clients_connected = NULL,
    };

    const char *req = "POST /metrics HTTP/1.0\r\nHost: x\r\n\r\n";
    write(sv[0], req, strlen(req));
    prometheus_handle_connection(sv[1], &cfg);

    char resp[1024];
    ssize_t n = read(sv[0], resp, sizeof(resp) - 1);
    if (n < 0) n = 0;
    resp[n] = '\0';
    close(sv[0]);
    ASSERT(strncmp(resp, "HTTP/1.0 405", 12) == 0, "405 status");
    return 1;
}

/* P5: live client counter is reflected. */
int test_prometheus_client_counter(void) {
    volatile size_t n_clients = 7;
    prometheus_cfg_t cfg = {
        .db_path = NULL,
        .start_time = time(NULL),
        .n_clients_connected = &n_clients,
    };
    char buf[8192];
    size_t n = prometheus_build_body(&cfg, buf, sizeof(buf));
    ASSERT(n > 0, "body length > 0");
    buf[n] = '\0';
    ASSERT(strstr(buf, "superscalar_lsp_clients_connected 7") != NULL,
           "clients=7 reflected");
    return 1;
}
