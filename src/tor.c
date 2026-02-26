#include "superscalar/tor.h"
#include "superscalar/wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* --- SOCKS5 proxy connection (RFC 1928) --- */

/* Low-level: write exactly `len` bytes */
static int tor_write_all(int fd, const unsigned char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n <= 0) return 0;
        sent += (size_t)n;
    }
    return 1;
}

/* Low-level: read exactly `len` bytes */
static int tor_read_all(int fd, unsigned char *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) return 0;
        got += (size_t)n;
    }
    return 1;
}

int tor_connect_socks5(const char *proxy_host, int proxy_port,
                       const char *host, int port) {
    if (!host || !proxy_host) return -1;

    size_t host_len = strlen(host);
    if (host_len == 0 || host_len > 255) return -1;

    /* 1. TCP connect to SOCKS5 proxy */
    int fd = wire_connect_direct_internal(proxy_host, proxy_port);
    if (fd < 0) return -1;

    /* 2. SOCKS5 greeting: version=5, 1 auth method, NO_AUTH=0 */
    unsigned char greeting[3] = { 0x05, 0x01, 0x00 };
    if (!tor_write_all(fd, greeting, 3)) {
        close(fd);
        return -1;
    }

    /* 3. Read greeting response: expect version=5, method=0 (NO_AUTH) */
    unsigned char gresp[2];
    if (!tor_read_all(fd, gresp, 2) || gresp[0] != 0x05 || gresp[1] != 0x00) {
        fprintf(stderr, "tor: SOCKS5 greeting failed (ver=%02x method=%02x)\n",
                gresp[0], gresp[1]);
        close(fd);
        return -1;
    }

    /* 4. CONNECT request: VER=5 CMD=1(CONNECT) RSV=0 ATYP=3(DOMAINNAME)
       LEN HOST... PORT_BE */
    size_t req_len = 4 + 1 + host_len + 2;
    unsigned char *req = (unsigned char *)malloc(req_len);
    if (!req) { close(fd); return -1; }

    req[0] = 0x05;                        /* VER */
    req[1] = 0x01;                        /* CMD: CONNECT */
    req[2] = 0x00;                        /* RSV */
    req[3] = 0x03;                        /* ATYP: DOMAINNAME */
    req[4] = (unsigned char)host_len;     /* domain length */
    memcpy(req + 5, host, host_len);      /* domain */
    req[5 + host_len] = (unsigned char)((port >> 8) & 0xFF);  /* port high */
    req[6 + host_len] = (unsigned char)(port & 0xFF);          /* port low */

    int wok = tor_write_all(fd, req, req_len);
    free(req);
    if (!wok) { close(fd); return -1; }

    /* 5. Read CONNECT response: VER REP RSV ATYP ... */
    unsigned char cresp[4];
    if (!tor_read_all(fd, cresp, 4)) {
        close(fd);
        return -1;
    }
    if (cresp[0] != 0x05 || cresp[1] != 0x00) {
        fprintf(stderr, "tor: SOCKS5 CONNECT failed (rep=%02x)\n", cresp[1]);
        close(fd);
        return -1;
    }

    /* Drain the bound address from response */
    switch (cresp[3]) {
    case 0x01: { /* IPv4: 4 bytes addr + 2 bytes port */
        unsigned char skip[6];
        if (!tor_read_all(fd, skip, 6)) { close(fd); return -1; }
        break;
    }
    case 0x04: { /* IPv6: 16 bytes addr + 2 bytes port */
        unsigned char skip[18];
        if (!tor_read_all(fd, skip, 18)) { close(fd); return -1; }
        break;
    }
    case 0x03: { /* Domain: 1 byte len + domain + 2 bytes port */
        unsigned char dlen;
        if (!tor_read_all(fd, &dlen, 1)) { close(fd); return -1; }
        unsigned char *skip = (unsigned char *)malloc(dlen + 2);
        if (!skip) { close(fd); return -1; }
        int ok = tor_read_all(fd, skip, dlen + 2);
        free(skip);
        if (!ok) { close(fd); return -1; }
        break;
    }
    default:
        close(fd);
        return -1;
    }

    /* 6. Connection established — fd is now a transparent tunnel */
    wire_set_timeout(fd, WIRE_DEFAULT_TIMEOUT_SEC);
    return fd;
}

/* --- wire_connect_via_proxy (called from wire.c) --- */

int wire_connect_via_proxy(const char *host, int port,
                           const char *proxy_host, int proxy_port) {
    return tor_connect_socks5(proxy_host, proxy_port, host, port);
}

/* --- Tor control port (hidden service creation) --- */

/* Read a line from control port (up to \r\n or \n). Returns length or -1. */
static int tor_control_readline(int fd, char *buf, size_t buflen) {
    size_t pos = 0;
    while (pos < buflen - 1) {
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n <= 0) return -1;
        if (c == '\n') {
            /* Strip trailing \r */
            if (pos > 0 && buf[pos - 1] == '\r')
                pos--;
            buf[pos] = '\0';
            return (int)pos;
        }
        buf[pos++] = c;
    }
    buf[pos] = '\0';
    return (int)pos;
}

/* Write a command to control port */
static int tor_control_send(int fd, const char *cmd) {
    size_t len = strlen(cmd);
    return tor_write_all(fd, (const unsigned char *)cmd, len);
}

int tor_create_hidden_service(const char *control_host, int control_port,
                              const char *control_password,
                              int virtual_port, int local_port,
                              char *onion_out, size_t onion_out_len) {
    if (!control_host || !onion_out || onion_out_len < 64) return -1;

    /* 1. Connect to Tor control port */
    int fd = wire_connect_direct_internal(control_host, control_port);
    if (fd < 0) {
        fprintf(stderr, "tor: failed to connect to control port %s:%d\n",
                control_host, control_port);
        return -1;
    }

    wire_set_timeout(fd, 30);
    char line[1024];

    /* 2. Authenticate — reject passwords containing quotes or control chars
       to prevent command injection into the Tor control protocol */
    char auth_cmd[512];
    if (control_password && control_password[0] != '\0') {
        for (const char *p = control_password; *p; p++) {
            if (*p == '"' || *p == '\\' || *p == '\r' || *p == '\n') {
                fprintf(stderr, "tor: control password contains unsafe character\n");
                close(fd);
                return -1;
            }
        }
        snprintf(auth_cmd, sizeof(auth_cmd),
                 "AUTHENTICATE \"%s\"\r\n", control_password);
    } else {
        snprintf(auth_cmd, sizeof(auth_cmd), "AUTHENTICATE\r\n");
    }

    if (!tor_control_send(fd, auth_cmd)) {
        close(fd);
        return -1;
    }

    if (tor_control_readline(fd, line, sizeof(line)) < 0) {
        close(fd);
        return -1;
    }
    if (strncmp(line, "250", 3) != 0) {
        fprintf(stderr, "tor: AUTHENTICATE failed: %s\n", line);
        close(fd);
        return -1;
    }

    /* 3. Create ephemeral hidden service */
    char add_cmd[256];
    snprintf(add_cmd, sizeof(add_cmd),
             "ADD_ONION NEW:ED25519-V3 Port=%d,127.0.0.1:%d Flags=DiscardPK\r\n",
             virtual_port, local_port);

    if (!tor_control_send(fd, add_cmd)) {
        close(fd);
        return -1;
    }

    /* 4. Parse response: "250-ServiceID=<56-char-onion>" then "250 OK" */
    char service_id[128] = {0};
    while (1) {
        if (tor_control_readline(fd, line, sizeof(line)) < 0) {
            close(fd);
            return -1;
        }

        if (strncmp(line, "250-ServiceID=", 14) == 0) {
            strncpy(service_id, line + 14, sizeof(service_id) - 1);
        } else if (strncmp(line, "250 ", 4) == 0) {
            break;
        } else if (strncmp(line, "5", 1) == 0) {
            fprintf(stderr, "tor: ADD_ONION failed: %s\n", line);
            close(fd);
            return -1;
        }
    }

    if (service_id[0] == '\0') {
        fprintf(stderr, "tor: no ServiceID in ADD_ONION response\n");
        close(fd);
        return -1;
    }

    /* 5. Write onion hostname */
    snprintf(onion_out, onion_out_len, "%s.onion", service_id);
    printf("tor: hidden service created — %s:%d\n", onion_out, virtual_port);

    /* Return fd — keep it open to maintain the service.
       Closing the control connection tears down the ephemeral service. */
    return fd;
}

/* --- Helper: parse HOST:PORT string --- */

int tor_parse_proxy_arg(const char *arg, char *host_out, size_t host_len,
                        int *port_out) {
    if (!arg) return 0;

    /* Find last colon (handles IPv6 [::1]:9050 if bracketed) */
    const char *colon = strrchr(arg, ':');
    if (!colon || colon == arg) return 0;

    size_t hlen = (size_t)(colon - arg);
    if (hlen >= host_len) return 0;

    memcpy(host_out, arg, hlen);
    host_out[hlen] = '\0';

    *port_out = atoi(colon + 1);
    if (*port_out <= 0 || *port_out > 65535) return 0;

    return 1;
}
