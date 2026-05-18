/*
 * prometheus_exporter.c - native Prometheus /metrics exporter.
 *
 * Implements the API declared in superscalar/prometheus.h.  Modelled on
 * src/lsp_wellknown.c (same fork-per-connection accept loop, same HTTP/1.0
 * request parsing); the only meaningful difference is the response body,
 * which is Prometheus text format scraped from runtime counters and from
 * the SQLite forensic tables.
 *
 * No new external dependencies - uses only libc, POSIX sockets, and the
 * already-linked sqlite3.  DB queries open a fresh sqlite3_open_v2 with
 * SQLITE_OPEN_READONLY per scrape so the live LSP process is unaffected.
 */

#include "superscalar/prometheus.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sqlite3.h>

/* ------------------------------------------------------------------ */
/* IO helpers (copied from lsp_wellknown.c to avoid coupling)         */
/* ------------------------------------------------------------------ */

static int read_line(int fd, char *buf, size_t cap) {
    size_t i = 0;
    while (i < cap - 1) {
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n <= 0) return 0;
        if (c == '\n') break;
        if (c != '\r') buf[i++] = c;
    }
    buf[i] = '\0';
    return 1;
}

static int write_all(int fd, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n <= 0) return 0;
        sent += (size_t)n;
    }
    return 1;
}

/* Bounded append helper. Returns new offset (or buf_cap on overflow). */
static size_t append_str(char *buf, size_t buf_cap, size_t off,
                          const char *s) {
    if (off >= buf_cap) return buf_cap;
    size_t remain = buf_cap - off - 1;
    size_t len = strlen(s);
    if (len > remain) len = remain;
    memcpy(buf + off, s, len);
    buf[off + len] = '\0';
    return off + len;
}

static size_t append_fmt(char *buf, size_t buf_cap, size_t off,
                          const char *fmt, ...) {
    if (off >= buf_cap) return buf_cap;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + off, buf_cap - off, fmt, ap);
    va_end(ap);
    if (n < 0) return off;
    if ((size_t)n >= buf_cap - off) return buf_cap;
    return off + (size_t)n;
}

/* ------------------------------------------------------------------ */
/* DB queries (read-only)                                              */
/* ------------------------------------------------------------------ */

/* Sanitize a SQLite TEXT value into a Prometheus label-safe token.
   Allows alphanumeric and underscore, replaces other chars with
   underscore.  Caps at 32 chars.  Empty input becomes "unknown". */
static void sanitize_label(const char *in, char *out, size_t out_cap) {
    if (!out || out_cap == 0) return;
    if (!in || !*in) {
        snprintf(out, out_cap, "unknown");
        return;
    }
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 1 < out_cap && j < 32; i++) {
        char c = in[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_')
            out[j++] = c;
        else
            out[j++] = '_';
    }
    out[j] = '\0';
    if (j == 0) snprintf(out, out_cap, "unknown");
}

/* Emit factories_total grouped by state. */
static size_t emit_factories(sqlite3 *db, char *buf, size_t buf_cap,
                              size_t off) {
    off = append_str(buf, buf_cap, off,
        "# HELP superscalar_lsp_factories_total Number of factories by state.\n"
        "# TYPE superscalar_lsp_factories_total gauge\n");
    if (!db) {
        off = append_str(buf, buf_cap, off,
            "superscalar_lsp_factories_total{state=\"unknown\"} 0\n");
        return off;
    }
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT COALESCE(state,'unknown') AS s, COUNT(*) FROM factories "
        "GROUP BY s;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        off = append_str(buf, buf_cap, off,
            "superscalar_lsp_factories_total{state=\"unknown\"} 0\n");
        return off;
    }
    int rows = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *state = sqlite3_column_text(stmt, 0);
        int count = sqlite3_column_int(stmt, 1);
        char label[40];
        sanitize_label((const char *)state, label, sizeof(label));
        off = append_fmt(buf, buf_cap, off,
            "superscalar_lsp_factories_total{state=\"%s\"} %d\n",
            label, count);
        rows++;
    }
    sqlite3_finalize(stmt);
    if (rows == 0)
        off = append_str(buf, buf_cap, off,
            "superscalar_lsp_factories_total{state=\"unknown\"} 0\n");
    return off;
}

static size_t emit_signing_rounds(sqlite3 *db, char *buf, size_t buf_cap,
                                    size_t off) {
    off = append_str(buf, buf_cap, off,
        "# HELP superscalar_lsp_signing_round_total Total signing rounds by ceremony type.\n"
        "# TYPE superscalar_lsp_signing_round_total counter\n");
    if (!db) {
        off = append_str(buf, buf_cap, off,
            "superscalar_lsp_signing_round_total{ceremony_type=\"unknown\"} 0\n");
    } else {
        sqlite3_stmt *stmt = NULL;
        const char *sql =
            "SELECT COALESCE(ceremony_type,'unknown') AS c, COUNT(*) "
            "FROM signing_rounds GROUP BY c;";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            int rows = 0;
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const unsigned char *ct = sqlite3_column_text(stmt, 0);
                int count = sqlite3_column_int(stmt, 1);
                char label[40];
                sanitize_label((const char *)ct, label, sizeof(label));
                off = append_fmt(buf, buf_cap, off,
                    "superscalar_lsp_signing_round_total{ceremony_type=\"%s\"} %d\n",
                    label, count);
                rows++;
            }
            sqlite3_finalize(stmt);
            if (rows == 0)
                off = append_str(buf, buf_cap, off,
                    "superscalar_lsp_signing_round_total{ceremony_type=\"unknown\"} 0\n");
        } else {
            off = append_str(buf, buf_cap, off,
                "superscalar_lsp_signing_round_total{ceremony_type=\"unknown\"} 0\n");
        }
    }

    off = append_str(buf, buf_cap, off,
        "# HELP superscalar_lsp_signing_round_duration_seconds Total time spent in completed signing rounds.\n"
        "# TYPE superscalar_lsp_signing_round_duration_seconds_sum counter\n"
        "# TYPE superscalar_lsp_signing_round_duration_seconds_count counter\n");
    long long sum_s = 0;
    long long count_n = 0;
    if (db) {
        sqlite3_stmt *stmt = NULL;
        const char *sql =
            "SELECT COALESCE(SUM(completed_at - started_at), 0), COUNT(*) "
            "FROM signing_rounds "
            "WHERE completed_at IS NOT NULL AND started_at IS NOT NULL "
            "  AND completed_at >= started_at;";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                sum_s = sqlite3_column_int64(stmt, 0);
                count_n = sqlite3_column_int64(stmt, 1);
            }
            sqlite3_finalize(stmt);
        }
    }
    off = append_fmt(buf, buf_cap, off,
        "superscalar_lsp_signing_round_duration_seconds_sum %lld\n", sum_s);
    off = append_fmt(buf, buf_cap, off,
        "superscalar_lsp_signing_round_duration_seconds_count %lld\n",
        count_n);
    return off;
}

static size_t emit_breaches(sqlite3 *db, char *buf, size_t buf_cap,
                              size_t off) {
    off = append_str(buf, buf_cap, off,
        "# HELP superscalar_lsp_breaches_detected_total Total breach (revoked-commit) detections.\n"
        "# TYPE superscalar_lsp_breaches_detected_total counter\n");
    long long n = 0;
    if (db) {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT COUNT(*) FROM breach_detections;",
                -1, &stmt, NULL) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW)
                n = sqlite3_column_int64(stmt, 0);
            sqlite3_finalize(stmt);
        }
    }
    off = append_fmt(buf, buf_cap, off,
        "superscalar_lsp_breaches_detected_total %lld\n", n);
    return off;
}

/* Reorg severity derivation:
     n_entries_reset == 0 AND depth <= 0  -> info
     n_entries_reset 1..5 AND depth <= 2  -> warn
     anything deeper                       -> critical
   depth = old_tip - new_tip (positive on rollback). */
static size_t emit_reorgs(sqlite3 *db, char *buf, size_t buf_cap,
                            size_t off) {
    off = append_str(buf, buf_cap, off,
        "# HELP superscalar_lsp_reorg_events_total Total reorg events by derived severity.\n"
        "# TYPE superscalar_lsp_reorg_events_total counter\n");
    long long info_n = 0, warn_n = 0, crit_n = 0;
    if (db) {
        sqlite3_stmt *stmt = NULL;
        const char *sql =
            "SELECT n_entries_reset, (old_tip - new_tip) AS depth "
            "FROM reorg_events;";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                int n_reset = sqlite3_column_int(stmt, 0);
                int depth   = sqlite3_column_int(stmt, 1);
                if (n_reset == 0 && depth <= 0) info_n++;
                else if (n_reset <= 5 && depth <= 2) warn_n++;
                else crit_n++;
            }
            sqlite3_finalize(stmt);
        }
    }
    off = append_fmt(buf, buf_cap, off,
        "superscalar_lsp_reorg_events_total{severity=\"info\"} %lld\n",
        info_n);
    off = append_fmt(buf, buf_cap, off,
        "superscalar_lsp_reorg_events_total{severity=\"warn\"} %lld\n",
        warn_n);
    off = append_fmt(buf, buf_cap, off,
        "superscalar_lsp_reorg_events_total{severity=\"critical\"} %lld\n",
        crit_n);
    return off;
}

static size_t emit_penalty_broadcasts(sqlite3 *db, char *buf, size_t buf_cap,
                                        size_t off) {
    off = append_str(buf, buf_cap, off,
        "# HELP superscalar_lsp_penalty_broadcasts_total Total penalty TX broadcasts logged.\n"
        "# TYPE superscalar_lsp_penalty_broadcasts_total counter\n");
    long long n = 0;
    if (db) {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT COUNT(*) FROM broadcast_log WHERE source = 'penalty';",
                -1, &stmt, NULL) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW)
                n = sqlite3_column_int64(stmt, 0);
            sqlite3_finalize(stmt);
        }
    }
    off = append_fmt(buf, buf_cap, off,
        "superscalar_lsp_penalty_broadcasts_total %lld\n", n);
    return off;
}

/* ------------------------------------------------------------------ */
/* Body builder                                                        */
/* ------------------------------------------------------------------ */

size_t prometheus_build_body(const prometheus_cfg_t *cfg,
                              char *buf, size_t buf_cap) {
    if (!cfg || !buf || buf_cap < 256) return 0;
    size_t off = 0;

    time_t now = time(NULL);
    long long uptime = (long long)(now - cfg->start_time);
    if (uptime < 0) uptime = 0;
    off = append_str(buf, buf_cap, off,
        "# HELP superscalar_lsp_uptime_seconds Seconds since LSP process start.\n"
        "# TYPE superscalar_lsp_uptime_seconds gauge\n");
    off = append_fmt(buf, buf_cap, off,
        "superscalar_lsp_uptime_seconds %lld\n", uptime);

    off = append_str(buf, buf_cap, off,
        "# HELP superscalar_lsp_clients_connected Currently connected native clients.\n"
        "# TYPE superscalar_lsp_clients_connected gauge\n");
    long long n_conn = 0;
    if (cfg->n_clients_connected)
        n_conn = (long long)(*cfg->n_clients_connected);
    off = append_fmt(buf, buf_cap, off,
        "superscalar_lsp_clients_connected %lld\n", n_conn);

    sqlite3 *db = NULL;
    if (cfg->db_path) {
        int rc = sqlite3_open_v2(cfg->db_path, &db,
                                   SQLITE_OPEN_READONLY, NULL);
        if (rc != SQLITE_OK) {
            if (db) sqlite3_close(db);
            db = NULL;
        }
    }

    off = emit_factories(db, buf, buf_cap, off);
    off = emit_signing_rounds(db, buf, buf_cap, off);
    off = emit_breaches(db, buf, buf_cap, off);
    off = emit_reorgs(db, buf, buf_cap, off);
    off = emit_penalty_broadcasts(db, buf, buf_cap, off);

    if (db) sqlite3_close(db);

    return off;
}

/* ------------------------------------------------------------------ */
/* HTTP connection handler                                             */
/* ------------------------------------------------------------------ */

void prometheus_handle_connection(int fd, const prometheus_cfg_t *cfg) {
    if (fd < 0 || !cfg) {
        if (fd >= 0) close(fd);
        return;
    }

    char req_line[512];
    if (!read_line(fd, req_line, sizeof(req_line))) {
        close(fd);
        return;
    }

    char header_line[512];
    while (read_line(fd, header_line, sizeof(header_line))) {
        if (header_line[0] == '\0') break;
    }

    char method[8] = {0}, path[256] = {0};
    sscanf(req_line, "%7s %255s", method, path);

    if (strcmp(method, "GET") != 0) {
        const char *resp =
            "HTTP/1.0 405 Method Not Allowed\r\n"
            "Content-Length: 0\r\n\r\n";
        write_all(fd, resp, strlen(resp));
        close(fd);
        return;
    }

    if (strcmp(path, "/metrics") != 0 && strcmp(path, "/") != 0) {
        const char *resp =
            "HTTP/1.0 404 Not Found\r\n"
            "Content-Length: 0\r\n\r\n";
        write_all(fd, resp, strlen(resp));
        close(fd);
        return;
    }

    static char body[16384];
    size_t body_len = prometheus_build_body(cfg, body, sizeof(body));
    if (body_len == 0) {
        const char *resp =
            "HTTP/1.0 500 Internal Server Error\r\n"
            "Content-Length: 0\r\n\r\n";
        write_all(fd, resp, strlen(resp));
        close(fd);
        return;
    }

    char header[256];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
        "Content-Length: %zu\r\n\r\n",
        body_len);
    if (header_len <= 0) {
        close(fd);
        return;
    }
    write_all(fd, header, (size_t)header_len);
    write_all(fd, body, body_len);
    close(fd);
}

/* ------------------------------------------------------------------ */
/* Background server (fork-based, mirrors lsp_wellknown_serve_fork)    */
/* ------------------------------------------------------------------ */

int prometheus_serve_fork(const prometheus_cfg_t *cfg, uint16_t tcp_port) {
    if (!cfg || tcp_port == 0) return 0;

    int srv = socket(AF_INET6, SOCK_STREAM, 0);
    if (srv < 0) {
        srv = socket(AF_INET, SOCK_STREAM, 0);
        if (srv < 0) return 0;
    }

    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in6 addr6;
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port   = htons(tcp_port);
    addr6.sin6_addr   = in6addr_any;

    if (bind(srv, (struct sockaddr *)&addr6, sizeof(addr6)) != 0) {
        close(srv);
        srv = socket(AF_INET, SOCK_STREAM, 0);
        if (srv < 0) return 0;
        setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in addr4;
        memset(&addr4, 0, sizeof(addr4));
        addr4.sin_family      = AF_INET;
        addr4.sin_port        = htons(tcp_port);
        addr4.sin_addr.s_addr = INADDR_ANY;
        if (bind(srv, (struct sockaddr *)&addr4, sizeof(addr4)) != 0) {
            close(srv);
            return 0;
        }
    }

    if (listen(srv, 16) != 0) {
        close(srv);
        return 0;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(srv);
        return 0;
    }

    if (pid > 0) {
        close(srv);
        return 1;
    }

    signal(SIGCHLD, SIG_IGN);

    while (1) {
        int conn = accept(srv, NULL, NULL);
        if (conn < 0) {
            if (errno == EINTR) continue;
            break;
        }
        pid_t cpid = fork();
        if (cpid == 0) {
            close(srv);
            prometheus_handle_connection(conn, cfg);
            _exit(0);
        }
        close(conn);
    }
    close(srv);
    _exit(0);
}
