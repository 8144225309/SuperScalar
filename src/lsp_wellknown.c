/*
 * lsp_wellknown.c — /.well-known/lsps.json HTTP endpoint + client fetch
 *
 * Server: single-connection handler; caller is responsible for threading.
 * Client: plain HTTP GET (operator's reverse proxy handles TLS in prod).
 */

#include "superscalar/lsp_wellknown.h"
#include <cJSON.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

/* --- JSON builder --- */

size_t lsp_wellknown_build_json(const lsp_wellknown_cfg_t *cfg,
                                 char *buf, size_t buf_cap) {
    if (!cfg || !buf || buf_cap < 2) return 0;

    cJSON *obj = cJSON_CreateObject();
    if (!obj) return 0;

    cJSON_AddStringToObject(obj, "pubkey",
        cfg->pubkey_hex  ? cfg->pubkey_hex  : "");
    cJSON_AddStringToObject(obj, "host",
        cfg->host        ? cfg->host        : "");
    cJSON_AddNumberToObject(obj, "port",        cfg->bolt8_port);
    cJSON_AddNumberToObject(obj, "bolt8_port",  cfg->bolt8_port);
    cJSON_AddNumberToObject(obj, "native_port", cfg->native_port);
    cJSON_AddStringToObject(obj, "network",
        cfg->network     ? cfg->network     : "bitcoin");

    /* Supported LSPS protocols */
    cJSON *lsps = cJSON_CreateArray();
    if (lsps) {
        cJSON_AddItemToArray(lsps, cJSON_CreateString("lsps0"));
        cJSON_AddItemToArray(lsps, cJSON_CreateString("lsps1"));
        cJSON_AddItemToArray(lsps, cJSON_CreateString("lsps2"));
        cJSON_AddItemToObject(obj, "lsps", lsps);
    }

    cJSON_AddTrueToObject(obj, "superscalar");
    cJSON_AddNumberToObject(obj, "fee_ppm",          (double)cfg->fee_ppm);
    cJSON_AddNumberToObject(obj, "min_channel_sats",
                            (double)cfg->min_channel_sats);
    cJSON_AddNumberToObject(obj, "max_channel_sats",
                            (double)cfg->max_channel_sats);
    cJSON_AddStringToObject(obj, "version",
        cfg->version     ? cfg->version     : "0.0.0");

    char *raw = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    if (!raw) return 0;

    size_t raw_len = strlen(raw);
    if (raw_len >= buf_cap) {
        free(raw);
        return 0;
    }
    memcpy(buf, raw, raw_len + 1);
    free(raw);
    return raw_len;
}

/* --- JSON parser --- */

int lsp_wellknown_parse_json(const char *json,
                              char *host_out,       size_t host_cap,
                              uint16_t *port_out,
                              char *pubkey_hex_out, size_t pubkey_cap) {
    if (!json || !host_out || !port_out || !pubkey_hex_out) return 0;

    cJSON *obj = cJSON_Parse(json);
    if (!obj) return 0;

    int ok = 0;

    const cJSON *pubkey = cJSON_GetObjectItemCaseSensitive(obj, "pubkey");
    const cJSON *host   = cJSON_GetObjectItemCaseSensitive(obj, "host");
    /* Accept either "port" or "bolt8_port" */
    const cJSON *port   = cJSON_GetObjectItemCaseSensitive(obj, "bolt8_port");
    if (!port) port     = cJSON_GetObjectItemCaseSensitive(obj, "port");

    if (!cJSON_IsString(pubkey) || !cJSON_IsString(host) ||
        !cJSON_IsNumber(port))
        goto cleanup;

    const char *pubkey_str = pubkey->valuestring;
    const char *host_str   = host->valuestring;
    int         port_val   = (int)port->valuedouble;

    if (!pubkey_str || !host_str || port_val <= 0 || port_val > 65535)
        goto cleanup;
    if (strlen(pubkey_str) >= pubkey_cap)
        goto cleanup;
    if (strlen(host_str) >= host_cap)
        goto cleanup;

    strncpy(host_out, host_str, host_cap - 1);
    host_out[host_cap - 1] = '\0';
    *port_out = (uint16_t)port_val;
    strncpy(pubkey_hex_out, pubkey_str, pubkey_cap - 1);
    pubkey_hex_out[pubkey_cap - 1] = '\0';
    ok = 1;

cleanup:
    cJSON_Delete(obj);
    return ok;
}

/* --- HTTP connection handler --- */

/* Read one line from fd (strips \r\n). Returns 0 on EOF/error. */
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

/* Write all bytes to fd */
static int write_all(int fd, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n <= 0) return 0;
        sent += (size_t)n;
    }
    return 1;
}

void lsp_wellknown_handle_connection(int fd,
                                      const lsp_wellknown_cfg_t *cfg) {
    if (fd < 0 || !cfg) {
        if (fd >= 0) close(fd);
        return;
    }

    /* Read request line: "GET /path HTTP/1.x" */
    char req_line[512];
    if (!read_line(fd, req_line, sizeof(req_line))) {
        close(fd);
        return;
    }

    /* Drain headers */
    char header_line[512];
    while (read_line(fd, header_line, sizeof(header_line))) {
        if (header_line[0] == '\0') break;  /* blank line = end of headers */
    }

    /* Parse method and path */
    char method[8] = {0}, path[256] = {0};
    sscanf(req_line, "%7s %255s", method, path);

    if (strcmp(method, "GET") != 0) {
        const char *resp405 =
            "HTTP/1.0 405 Method Not Allowed\r\n"
            "Content-Length: 0\r\n\r\n";
        write_all(fd, resp405, strlen(resp405));
        close(fd);
        return;
    }

    if (strcmp(path, "/.well-known/lsps.json") != 0) {
        const char *resp404 =
            "HTTP/1.0 404 Not Found\r\n"
            "Content-Length: 0\r\n\r\n";
        write_all(fd, resp404, strlen(resp404));
        close(fd);
        return;
    }

    /* Build JSON body */
    char body[2048];
    size_t body_len = lsp_wellknown_build_json(cfg, body, sizeof(body));
    if (body_len == 0) {
        const char *resp500 =
            "HTTP/1.0 500 Internal Server Error\r\n"
            "Content-Length: 0\r\n\r\n";
        write_all(fd, resp500, strlen(resp500));
        close(fd);
        return;
    }

    /* Write HTTP response */
    char header[256];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: application/json\r\n"
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

/* --- Client: fetch .well-known/lsps.json over plain HTTP --- */

int lsp_wellknown_fetch_http_port(const char *domain, uint16_t tcp_port,
                                   char *host_out,       size_t host_cap,
                                   uint16_t *port_out,
                                   char *pubkey_hex_out, size_t pubkey_cap) {
    if (!domain || !host_out || !port_out || !pubkey_hex_out) return 0;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)tcp_port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(domain, port_str, &hints, &res) != 0 || !res)
        return 0;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return 0;
    }

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        freeaddrinfo(res);
        close(fd);
        return 0;
    }
    freeaddrinfo(res);

    /* Send HTTP GET */
    char req[512];
    int req_len = snprintf(req, sizeof(req),
        "GET /.well-known/lsps.json HTTP/1.0\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n\r\n",
        domain);
    if (req_len <= 0 || !write_all(fd, req, (size_t)req_len)) {
        close(fd);
        return 0;
    }

    /* Read response into buffer — skip HTTP headers */
    char buf[4096];
    size_t total = 0;
    ssize_t n;
    while (total < sizeof(buf) - 1 &&
           (n = read(fd, buf + total, sizeof(buf) - 1 - total)) > 0)
        total += (size_t)n;
    buf[total] = '\0';
    close(fd);

    /* Find blank line separating headers from body */
    const char *body = strstr(buf, "\r\n\r\n");
    if (!body) body = strstr(buf, "\n\n");
    if (!body) return 0;
    body += (body[0] == '\r') ? 4 : 2;

    return lsp_wellknown_parse_json(body, host_out, host_cap,
                                    port_out, pubkey_hex_out, pubkey_cap);
}

int lsp_wellknown_fetch_http(const char *domain,
                              char *host_out,       size_t host_cap,
                              uint16_t *port_out,
                              char *pubkey_hex_out, size_t pubkey_cap) {
    return lsp_wellknown_fetch_http_port(domain, 80,
                                         host_out, host_cap,
                                         port_out,
                                         pubkey_hex_out, pubkey_cap);
}

/* --- Background server (fork-based) --- */

int lsp_wellknown_serve_fork(const lsp_wellknown_cfg_t *cfg,
                              uint16_t tcp_port) {
    if (!cfg || tcp_port == 0) return 0;

    /* Create TCP server socket before forking */
    int srv = socket(AF_INET6, SOCK_STREAM, 0);
    if (srv < 0) {
        /* Fall back to IPv4-only */
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
        /* Try IPv4 */
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
        /* Parent: close server fd, continue */
        close(srv);
        return 1;
    }

    /* Child: accept connections and serve .well-known/lsps.json */
    signal(SIGCHLD, SIG_IGN);  /* reap grandchildren automatically */

    while (1) {
        int conn = accept(srv, NULL, NULL);
        if (conn < 0) {
            if (errno == EINTR) continue;
            break;
        }
        /* Fork per connection to avoid blocking the accept loop */
        pid_t cpid = fork();
        if (cpid == 0) {
            close(srv);
            lsp_wellknown_handle_connection(conn, cfg);
            _exit(0);
        }
        close(conn);
    }
    close(srv);
    _exit(0);
}
