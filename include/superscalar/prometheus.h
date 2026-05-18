/*
 * prometheus.h - native Prometheus /metrics exporter for superscalar_lsp.
 *
 * Exposes a minimal HTTP/1.0 server on a configurable port that serves
 * Prometheus text-format metrics scraped from the LSP runtime state and
 * the persist (SQLite) forensic tables (signing_rounds, breach_detections,
 * reorg_events, broadcast_log).
 *
 * Design: a background fork serves the endpoint, similar in spirit to
 * lsp_wellknown_serve_fork.  The exporter opens the SQLite file
 * read-only per scrape from the cached path so the live LSP process is
 * unaffected by concurrent reads.
 *
 * Usage (LSP side):
 *   prometheus_cfg_t cfg = { .db_path = ..., .start_time = ..., ... };
 *   prometheus_serve_fork(&cfg, 9100);
 *
 * Metrics exposed (Prometheus text format):
 *   superscalar_lsp_uptime_seconds (gauge)
 *   superscalar_lsp_factories_total{state="..."} (gauge)
 *   superscalar_lsp_clients_connected (gauge)
 *   superscalar_lsp_signing_round_total{ceremony_type="..."} (counter)
 *   superscalar_lsp_signing_round_duration_seconds_sum (counter)
 *   superscalar_lsp_signing_round_duration_seconds_count (counter)
 *   superscalar_lsp_breaches_detected_total (counter)
 *   superscalar_lsp_reorg_events_total{severity="..."} (counter)
 *   superscalar_lsp_penalty_broadcasts_total (counter)
 */

#ifndef SUPERSCALAR_PROMETHEUS_H
#define SUPERSCALAR_PROMETHEUS_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/*
 * Configuration passed to the exporter at fork time.  The struct is
 * copied into the child via fork inheritance; pointed-to strings must
 * remain live for the lifetime of the LSP process.
 */
typedef struct {
    /* Path to the SQLite db (forensic tables).  May be NULL: in that
       case DB-derived metrics are emitted as 0 with a HELP comment. */
    const char *db_path;

    /* Process start time in seconds since epoch.  Used to compute uptime. */
    time_t start_time;

    /* Pointer to a volatile size_t that the LSP main loop updates
       whenever a client connects/disconnects.  May be NULL (omits
       superscalar_lsp_clients_connected). */
    const volatile size_t *n_clients_connected;
} prometheus_cfg_t;

/*
 * Build the Prometheus text-format body into buf.  Returns bytes written
 * (excluding NUL terminator), or 0 on error.  Caller-supplied buffer must
 * be at least 8 KiB to comfortably hold the full output.
 */
size_t prometheus_build_body(const prometheus_cfg_t *cfg,
                              char *buf, size_t buf_cap);

/*
 * Handle one HTTP connection: read the GET request on fd, write the
 * /metrics response (200 + text body for GET /metrics, 404 otherwise).
 * Closes fd when done.  Callable with a socketpair fd for unit testing.
 */
void prometheus_handle_connection(int fd, const prometheus_cfg_t *cfg);

/*
 * Fork a background process that accepts HTTP connections on tcp_port
 * and serves the /metrics endpoint.  Returns 1 in the parent on success,
 * 0 on error.  The child runs indefinitely; the parent continues.
 *
 * Note: the child inherits a copy of *cfg.  db_path is opened read-only
 * per request, so DB updates by the parent are visible to scrapes.
 * Live counters (clients_connected) are read through the volatile
 * pointer in *cfg, which after fork points to the child's stale copy
 * of parent memory; for v1 the in-DB counters are authoritative and
 * the live client count is best-effort only.
 */
int prometheus_serve_fork(const prometheus_cfg_t *cfg, uint16_t tcp_port);

#endif /* SUPERSCALAR_PROMETHEUS_H */
