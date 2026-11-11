#include "superscalar/bridge.h"
#include "superscalar/noise.h"
#include <secp256k1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>

extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);

void bridge_init(bridge_t *br) {
    memset(br, 0, sizeof(*br));
    br->lsp_fd = -1;
    br->plugin_listen_fd = -1;
    br->plugin_fd = -1;
    br->plugin_pending_fd = -1;
    br->next_htlc_id = 1;
    br->next_request_id = 1;
    br->use_nk = 0;
    br->heartbeat_interval = 30;
    br->last_lsp_activity = time(NULL);
    br->reconnect_attempts = 0;
    memset(br->lsp_host, 0, sizeof(br->lsp_host));
    br->lsp_port = 0;
}

void bridge_set_lsp_pubkey(bridge_t *br, const secp256k1_pubkey *pk) {
    if (pk) {
        br->lsp_pubkey = *pk;
        br->use_nk = 1;
    } else {
        br->use_nk = 0;
    }
}

void bridge_set_pubkey(bridge_t *br, const secp256k1_pubkey *pk) {
    if (!br || !pk) return;
    memcpy(&br->bridge_pubkey, pk, sizeof(secp256k1_pubkey));
    br->has_bridge_pubkey = 1;
}

int bridge_connect_lsp(bridge_t *br, const char *lsp_host, int lsp_port) {
    /* Save host/port for reconnection */
    if (lsp_host) {
        strncpy(br->lsp_host, lsp_host, sizeof(br->lsp_host) - 1);
        br->lsp_host[sizeof(br->lsp_host) - 1] = '\0';
    } else {
        strncpy(br->lsp_host, "127.0.0.1", sizeof(br->lsp_host) - 1);
    }
    br->lsp_port = lsp_port;

    br->lsp_fd = wire_connect(lsp_host, lsp_port);
    if (br->lsp_fd < 0) {
        fprintf(stderr, "Bridge: failed to connect to LSP at %s:%d\n",
                lsp_host ? lsp_host : "127.0.0.1", lsp_port);
        return 0;
    }

    /* Encrypted transport handshake (NK if pubkey pinned, NN fallback) */
    {
        secp256k1_context *hs_ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        int hs_ok;
        if (br->use_nk) {
            hs_ok = wire_noise_handshake_nk_initiator(br->lsp_fd, hs_ctx,
                                                       &br->lsp_pubkey);
        } else {
            fprintf(stderr, "Bridge: WARNING — no --lsp-pubkey, using unauthenticated NN handshake\n");
            hs_ok = wire_noise_handshake_initiator(br->lsp_fd, hs_ctx);
        }
        secp256k1_context_destroy(hs_ctx);
        if (!hs_ok) {
            fprintf(stderr, "Bridge: noise handshake failed\n");
            wire_close(br->lsp_fd);
            br->lsp_fd = -1;
            return 0;
        }
    }

    /* Send BRIDGE_HELLO */
    cJSON *hello = wire_build_bridge_hello(
        br->has_bridge_pubkey ? &br->bridge_pubkey : NULL);
    if (!wire_send(br->lsp_fd, MSG_BRIDGE_HELLO, hello)) {
        cJSON_Delete(hello);
        fprintf(stderr, "Bridge: failed to send BRIDGE_HELLO\n");
        return 0;
    }
    cJSON_Delete(hello);

    /* Wait for BRIDGE_HELLO_ACK */
    wire_msg_t msg;
    if (!wire_recv(br->lsp_fd, &msg) || msg.msg_type != MSG_BRIDGE_HELLO_ACK) {
        fprintf(stderr, "Bridge: expected BRIDGE_HELLO_ACK, got 0x%02x\n",
                msg.msg_type);
        if (msg.json) cJSON_Delete(msg.json);
        return 0;
    }
    cJSON_Delete(msg.json);

    br->last_lsp_activity = time(NULL);
    br->reconnect_attempts = 0;
    printf("Bridge: connected to LSP\n");
    return 1;
}

/* --- Plugin shared secret --- */

static int is_secret_hex(const char *s) {
    if (!s || strlen(s) != BRIDGE_PLUGIN_SECRET_HEX_LEN) return 0;
    for (size_t i = 0; i < BRIDGE_PLUGIN_SECRET_HEX_LEN; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return 0;
    }
    return 1;
}

/* Compare two n-byte buffers without an early exit, so the time taken does
   not reveal how many leading bytes matched. */
static int ct_equal(const unsigned char *a, const unsigned char *b, size_t n) {
    unsigned char diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

static int read_random(unsigned char *out, size_t len) {
    int rfd = open("/dev/urandom", O_RDONLY);
    if (rfd < 0) return 0;
    size_t got = 0;
    while (got < len) {
        ssize_t r = read(rfd, out + got, len - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(rfd);
    return got == len;
}

int bridge_plugin_auth_proof(const char *secret_hex, const char *role,
                              const unsigned char *plugin_nonce,
                              const unsigned char *bridge_nonce,
                              unsigned char proof_out[32]) {
    static const char label[] = "superscalar-bridge-plugin-auth-v1/";
    unsigned char key[BRIDGE_PLUGIN_SECRET_HEX_LEN / 2];
    unsigned char msg[sizeof(label) + 16 + 2 * BRIDGE_AUTH_NONCE_LEN];
    size_t role_len = role ? strlen(role) : 0;
    if (!is_secret_hex(secret_hex) || role_len == 0 || role_len > 15 ||
        hex_decode(secret_hex, key, sizeof(key)) != (int)sizeof(key))
        return 0;
    size_t n = 0;
    memcpy(msg + n, label, sizeof(label) - 1); n += sizeof(label) - 1;
    memcpy(msg + n, role, role_len);           n += role_len;
    msg[n++] = '/';
    memcpy(msg + n, plugin_nonce, BRIDGE_AUTH_NONCE_LEN); n += BRIDGE_AUTH_NONCE_LEN;
    memcpy(msg + n, bridge_nonce, BRIDGE_AUTH_NONCE_LEN); n += BRIDGE_AUTH_NONCE_LEN;
    hmac_sha256(proof_out, key, sizeof(key), msg, n);
    memset(key, 0, sizeof(key));
    return 1;
}

static int write_all(int fd, const char *buf, size_t len) {
    while (len > 0) {
        ssize_t w = write(fd, buf, len);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return 0;
        buf += w;
        len -= (size_t)w;
    }
    return 1;
}

static int secret_create(const char *path, char *out_hex) {
    unsigned char raw[BRIDGE_PLUGIN_SECRET_HEX_LEN / 2];
    if (!read_random(raw, sizeof(raw))) return 0;

    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(raw); i++) {
        out_hex[2 * i]     = digits[raw[i] >> 4];
        out_hex[2 * i + 1] = digits[raw[i] & 0x0f];
    }
    out_hex[BRIDGE_PLUGIN_SECRET_HEX_LEN] = '\0';
    memset(raw, 0, sizeof(raw));

    /* O_EXCL: never write into a file somebody else put there. */
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return 0;
    int ok = fchmod(fd, 0600) == 0 &&
             write_all(fd, out_hex, BRIDGE_PLUGIN_SECRET_HEX_LEN) &&
             write_all(fd, "\n", 1) && fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;
    if (!ok) unlink(path);
    return ok;
}

int bridge_plugin_secret_load(const char *path, char *out_hex) {
    if (!path || !path[0] || !out_hex) return 0;
    out_hex[0] = '\0';

    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        if (errno != ENOENT) {
            fprintf(stderr, "Bridge: cannot open plugin secret %s: %s\n",
                    path, strerror(errno));
            return 0;
        }
        if (!secret_create(path, out_hex)) {
            fprintf(stderr, "Bridge: cannot create plugin secret %s: %s\n",
                    path, strerror(errno));
            out_hex[0] = '\0';
            return 0;
        }
        printf("Bridge: wrote new plugin secret to %s\n", path);
        return 1;
    }

    struct stat st;
    char buf[BRIDGE_PLUGIN_SECRET_HEX_LEN + 16];
    ssize_t n = -1;
    int ok = fstat(fd, &st) == 0;
    if (ok && (!S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
               (st.st_mode & 077) != 0)) {
        fprintf(stderr, "Bridge: plugin secret %s must be a regular file "
                "owned by this user with mode 0600\n", path);
        ok = 0;
    }
    if (ok) {
        n = read(fd, buf, sizeof(buf) - 1);
        if (n < 0) ok = 0;
    }
    close(fd);
    if (!ok) return 0;

    buf[n] = '\0';
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
                     buf[n - 1] == ' ' || buf[n - 1] == '\t'))
        buf[--n] = '\0';
    if (!is_secret_hex(buf)) {
        fprintf(stderr, "Bridge: plugin secret %s is not %d hex characters\n",
                path, BRIDGE_PLUGIN_SECRET_HEX_LEN);
        memset(buf, 0, sizeof(buf));
        return 0;
    }
    memcpy(out_hex, buf, BRIDGE_PLUGIN_SECRET_HEX_LEN + 1);
    memset(buf, 0, sizeof(buf));
    return 1;
}

int bridge_set_plugin_secret(bridge_t *br, const char *secret_hex) {
    if (!br || !is_secret_hex(secret_hex)) return 0;
    memcpy(br->plugin_secret, secret_hex, BRIDGE_PLUGIN_SECRET_HEX_LEN + 1);
    br->has_plugin_secret = 1;
    return 1;
}

/* --- Plugin port --- */

int bridge_listen_plugin(bridge_t *br, const char *bind_addr, int plugin_port) {
    if (!br->has_plugin_secret) {
        fprintf(stderr, "Bridge: no plugin secret set, not listening\n");
        return 0;
    }
    if (!bind_addr || !bind_addr[0])
        bind_addr = BRIDGE_PLUGIN_BIND_DEFAULT;
    struct in_addr parsed;
    if (inet_pton(AF_INET, bind_addr, &parsed) != 1) {
        fprintf(stderr, "Bridge: plugin bind address '%s' is not an IPv4 "
                "address\n", bind_addr);
        return 0;
    }
    if ((ntohl(parsed.s_addr) >> 24) != 127)
        fprintf(stderr, "Bridge: WARNING — plugin port bound to %s; the "
                "plugin link is not encrypted, keep it on a trusted network\n",
                bind_addr);

    br->plugin_listen_fd = wire_listen(bind_addr, plugin_port);
    if (br->plugin_listen_fd < 0) {
        fprintf(stderr, "Bridge: failed to listen on %s:%d\n",
                bind_addr, plugin_port);
        return 0;
    }
    printf("Bridge: listening for plugin on %s:%d\n", bind_addr, plugin_port);
    return 1;
}

static void drop_pending_plugin(bridge_t *br) {
    if (br->plugin_pending_fd >= 0)
        wire_close(br->plugin_pending_fd);
    br->plugin_pending_fd = -1;
    br->plugin_pending_len = 0;
    br->plugin_pending_challenged = 0;
    memset(br->plugin_pending_buf, 0, sizeof(br->plugin_pending_buf));
    memset(br->plugin_nonce_peer, 0, sizeof(br->plugin_nonce_peer));
    memset(br->plugin_nonce_own, 0, sizeof(br->plugin_nonce_own));
}

int bridge_accept_plugin(bridge_t *br) {
    int fd = wire_accept(br->plugin_listen_fd);
    if (fd < 0) {
        fprintf(stderr, "Bridge: failed to accept plugin\n");
        return 0;
    }
    /* One plugin at a time: a newcomer never displaces or joins it. */
    if (br->plugin_fd >= 0 || br->plugin_pending_fd >= 0) {
        fprintf(stderr, "Bridge: rejected extra connection on plugin port\n");
        wire_close(fd);
        return 0;
    }
    br->plugin_pending_fd = fd;
    br->plugin_pending_since = time(NULL);
    br->plugin_pending_len = 0;
    br->plugin_pending_challenged = 0;
    return 1;
}

int bridge_expire_pending_plugin(bridge_t *br, time_t now) {
    if (br->plugin_pending_fd < 0) return 0;
    if (now - br->plugin_pending_since < BRIDGE_PLUGIN_AUTH_TIMEOUT) return 0;
    fprintf(stderr, "Bridge: plugin connection did not authenticate in time\n");
    drop_pending_plugin(br);
    return 1;
}

/* A 32-byte value given as 64 hex characters in a JSON string field. */
static int json_get_hex32(const cJSON *json, const char *name,
                           unsigned char out[32]) {
    cJSON *item = cJSON_GetObjectItem(json, name);
    return item && cJSON_IsString(item) &&
           strlen(item->valuestring) == 64 &&
           hex_decode(item->valuestring, out, 32) == 32;
}

static int json_method_is(const cJSON *json, const char *name) {
    cJSON *method = cJSON_GetObjectItem(json, "method");
    return method && cJSON_IsString(method) &&
           strcmp(method->valuestring, name) == 0;
}

/* First line of a new connection: its nonce.  Answer with ours and the
   proof that this is the bridge.  Returns 1 if the challenge went out. */
static int plugin_auth_hello(bridge_t *br, const char *line) {
    if (!br->has_plugin_secret) return 0;
    cJSON *json = cJSON_Parse(line);
    if (!json) return 0;
    int ok = json_method_is(json, "auth_hello") &&
             json_get_hex32(json, "nonce", br->plugin_nonce_peer);
    cJSON_Delete(json);
    if (!ok) return 0;

    unsigned char proof[32];
    if (!read_random(br->plugin_nonce_own, sizeof(br->plugin_nonce_own)) ||
        !bridge_plugin_auth_proof(br->plugin_secret, BRIDGE_AUTH_ROLE_BRIDGE,
                                   br->plugin_nonce_peer, br->plugin_nonce_own,
                                   proof))
        return 0;

    cJSON *ch = cJSON_CreateObject();
    cJSON_AddStringToObject(ch, "method", "auth_challenge");
    wire_json_add_hex(ch, "nonce", br->plugin_nonce_own,
                      sizeof(br->plugin_nonce_own));
    wire_json_add_hex(ch, "proof", proof, sizeof(proof));
    char *str = cJSON_PrintUnformatted(ch);
    cJSON_Delete(ch);
    if (!str) return 0;
    ok = write_all(br->plugin_pending_fd, str, strlen(str)) &&
         write_all(br->plugin_pending_fd, "\n", 1);
    free(str);
    return ok;
}

/* Second line: the proof that the other side is the plugin. */
static int plugin_auth_response_ok(const bridge_t *br, const char *line) {
    cJSON *json = cJSON_Parse(line);
    if (!json) return 0;
    unsigned char given[32], expected[32];
    int ok = json_method_is(json, "auth_response") &&
             json_get_hex32(json, "proof", given) &&
             bridge_plugin_auth_proof(br->plugin_secret, BRIDGE_AUTH_ROLE_PLUGIN,
                                       br->plugin_nonce_peer,
                                       br->plugin_nonce_own, expected) &&
             ct_equal(given, expected, sizeof(expected));
    cJSON_Delete(json);
    return ok;
}

int bridge_service_pending_plugin(bridge_t *br) {
    if (br->plugin_pending_fd < 0) return -1;

    size_t room = sizeof(br->plugin_pending_buf) - br->plugin_pending_len;
    ssize_t n = room > 0
        ? recv(br->plugin_pending_fd,
               br->plugin_pending_buf + br->plugin_pending_len, room,
               MSG_DONTWAIT)
        : 0;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return 0;
    if (n <= 0) {
        /* Closed, failed, or a line too long to be a handshake message. */
        drop_pending_plugin(br);
        return -1;
    }
    br->plugin_pending_len += (size_t)n;

    for (;;) {
        char *nl = memchr(br->plugin_pending_buf, '\n', br->plugin_pending_len);
        if (!nl) {
            if (br->plugin_pending_len == sizeof(br->plugin_pending_buf)) {
                drop_pending_plugin(br);
                return -1;
            }
            return 0;
        }
        *nl = '\0';
        size_t used = (size_t)(nl - br->plugin_pending_buf) + 1;
        size_t rest = br->plugin_pending_len - used;

        if (!br->plugin_pending_challenged) {
            if (!plugin_auth_hello(br, br->plugin_pending_buf)) {
                fprintf(stderr, "Bridge: plugin connection did not start "
                        "the handshake\n");
                drop_pending_plugin(br);
                return -1;
            }
            br->plugin_pending_challenged = 1;
            memmove(br->plugin_pending_buf, br->plugin_pending_buf + used, rest);
            br->plugin_pending_len = rest;
            continue;
        }

        if (!plugin_auth_response_ok(br, br->plugin_pending_buf)) {
            fprintf(stderr, "Bridge: plugin connection failed authentication\n");
            drop_pending_plugin(br);
            return -1;
        }

        /* Authenticated: this is the plugin.  Anything it sent after its
           proof is ordinary plugin traffic. */
        memcpy(br->plugin_read_buf, br->plugin_pending_buf + used, rest);
        br->plugin_read_len = rest;
        br->plugin_read_pos = 0;
        br->plugin_fd = br->plugin_pending_fd;
        br->plugin_pending_fd = -1;
        drop_pending_plugin(br);
        printf("Bridge: plugin connected and authenticated\n");

        cJSON *ack = cJSON_CreateObject();
        cJSON_AddStringToObject(ack, "method", "auth_ok");
        bridge_send_plugin_json(br, ack);
        cJSON_Delete(ack);
        return 1;
    }
}

uint64_t bridge_add_pending(bridge_t *br, const unsigned char *payment_hash32) {
    for (size_t i = 0; i < BRIDGE_MAX_PENDING; i++) {
        bridge_pending_htlc_t *e = &br->pending_inbound[i];
        if (e->pending) continue;
        /* 0 means "no HTLC" to the LSP, so it is never handed out */
        if (br->next_htlc_id == 0) br->next_htlc_id = 1;
        memcpy(e->payment_hash, payment_hash32, 32);
        e->htlc_id = br->next_htlc_id++;
        e->pending = 1;
        br->n_pending++;
        return e->htlc_id;
    }
    return 0;
}

uint64_t bridge_add_pending_upstream(bridge_t *br,
                                      const unsigned char *payment_hash32,
                                      const char *upstream_id) {
    if (!upstream_id || strlen(upstream_id) >=
            sizeof(br->pending_inbound[0].upstream_id))
        upstream_id = "";
    for (size_t i = 0; upstream_id[0] && i < BRIDGE_MAX_PENDING; i++) {
        bridge_pending_htlc_t *e = &br->pending_inbound[i];
        if (e->pending && strcmp(e->upstream_id, upstream_id) == 0 &&
            memcmp(e->payment_hash, payment_hash32, 32) == 0)
            return e->htlc_id;
    }
    uint64_t id = bridge_add_pending(br, payment_hash32);
    for (size_t i = 0; id != 0 && i < BRIDGE_MAX_PENDING; i++) {
        bridge_pending_htlc_t *e = &br->pending_inbound[i];
        if (e->pending && e->htlc_id == id) {
            strcpy(e->upstream_id, upstream_id);
            break;
        }
    }
    return id;
}

static void free_pending(bridge_t *br, bridge_pending_htlc_t *e) {
    memset(e, 0, sizeof(*e));
    if (br->n_pending > 0) br->n_pending--;
}

int bridge_resolve_pending(bridge_t *br, const unsigned char *payment_hash32,
                             uint64_t *htlc_id_out) {
    for (size_t i = 0; i < BRIDGE_MAX_PENDING; i++) {
        bridge_pending_htlc_t *e = &br->pending_inbound[i];
        if (!e->pending) continue;
        if (memcmp(e->payment_hash, payment_hash32, 32) == 0) {
            *htlc_id_out = e->htlc_id;
            free_pending(br, e);
            return 1;
        }
    }
    return 0;
}

int bridge_release_pending(bridge_t *br, uint64_t htlc_id) {
    if (htlc_id == 0) return 0;
    for (size_t i = 0; i < BRIDGE_MAX_PENDING; i++) {
        bridge_pending_htlc_t *e = &br->pending_inbound[i];
        if (e->pending && e->htlc_id == htlc_id) {
            free_pending(br, e);
            return 1;
        }
    }
    return 0;
}

/* Send newline-delimited JSON to plugin */
int bridge_send_plugin_json(bridge_t *br, cJSON *json) {
    if (br->plugin_fd < 0) return 0;

    char *str = cJSON_PrintUnformatted(json);
    if (!str) return 0;

    size_t len = strlen(str);
    /* Write JSON + newline */
    ssize_t w = write(br->plugin_fd, str, len);
    free(str);
    if (w != (ssize_t)len) return 0;

    char nl = '\n';
    w = write(br->plugin_fd, &nl, 1);
    return w == 1;
}

/* Read one newline-delimited line from plugin_fd (buffered) */
char *bridge_read_plugin_line(bridge_t *br) {
    if (br->plugin_fd < 0) return NULL;

    size_t cap = 4096;
    size_t len = 0;
    char *line = (char *)malloc(cap);
    if (!line) return NULL;

    while (1) {
        /* Scan buffered data for newline */
        while (br->plugin_read_pos < br->plugin_read_len) {
            char c = br->plugin_read_buf[br->plugin_read_pos++];
            if (c == '\n') {
                line[len] = '\0';
                return line;
            }
            if (len + 1 >= cap) {
                cap *= 2;
                char *tmp = (char *)realloc(line, cap);
                if (!tmp) { free(line); return NULL; }
                line = tmp;
            }
            line[len++] = c;
        }

        /* Buffer exhausted — refill from fd */
        ssize_t n = read(br->plugin_fd, br->plugin_read_buf,
                         sizeof(br->plugin_read_buf));
        if (n <= 0) {
            free(line);
            return NULL;
        }
        br->plugin_read_len = (size_t)n;
        br->plugin_read_pos = 0;
    }
}

/* Handle a wire message from the LSP */
int bridge_handle_lsp_msg(bridge_t *br, const wire_msg_t *msg) {
    switch (msg->msg_type) {
    case MSG_BRIDGE_FULFILL_HTLC: {
        unsigned char payment_hash[32], preimage[32];
        uint64_t htlc_id;
        if (!wire_parse_bridge_fulfill_htlc(msg->json, payment_hash, preimage,
                                              &htlc_id))
            return 0;
        bridge_release_pending(br, htlc_id);

        /* Forward to plugin (include payment_hash for correlation) */
        cJSON *j = cJSON_CreateObject();
        cJSON_AddStringToObject(j, "method", "htlc_resolve");
        wire_json_add_hex(j, "payment_hash", payment_hash, 32);
        cJSON_AddNumberToObject(j, "htlc_id", (double)htlc_id);
        cJSON_AddStringToObject(j, "result", "fulfill");
        wire_json_add_hex(j, "preimage", preimage, 32);
        int ok = bridge_send_plugin_json(br, j);
        cJSON_Delete(j);
        return ok;
    }

    case MSG_BRIDGE_FAIL_HTLC: {
        unsigned char payment_hash[32];
        char reason[256];
        uint64_t htlc_id;
        if (!wire_parse_bridge_fail_htlc(msg->json, payment_hash, reason,
                                           sizeof(reason), &htlc_id))
            return 0;
        bridge_release_pending(br, htlc_id);

        cJSON *j = cJSON_CreateObject();
        cJSON_AddStringToObject(j, "method", "htlc_resolve");
        wire_json_add_hex(j, "payment_hash", payment_hash, 32);
        cJSON_AddNumberToObject(j, "htlc_id", (double)htlc_id);
        cJSON_AddStringToObject(j, "result", "fail");
        cJSON_AddStringToObject(j, "reason", reason);
        int ok = bridge_send_plugin_json(br, j);
        cJSON_Delete(j);
        return ok;
    }

    case MSG_BRIDGE_SEND_PAY: {
        char bolt11[2048];
        unsigned char payment_hash[32];
        uint64_t request_id, max_total_msat;
        uint32_t max_delay;
        if (!wire_parse_bridge_send_pay(msg->json, bolt11, sizeof(bolt11),
                                          payment_hash, &request_id,
                                          &max_total_msat, &max_delay))
            return 0;

        /* The plugin checks the invoice against payment_hash, refuses to
           spend more than max_total_msat and keeps the route within
           max_delay blocks, so all three must reach it. */
        cJSON *j = cJSON_CreateObject();
        cJSON_AddStringToObject(j, "method", "pay_request");
        cJSON_AddStringToObject(j, "bolt11", bolt11);
        cJSON_AddNumberToObject(j, "request_id", (double)request_id);
        wire_json_add_hex(j, "payment_hash", payment_hash, 32);
        cJSON_AddNumberToObject(j, "max_total_msat", (double)max_total_msat);
        cJSON_AddNumberToObject(j, "max_delay", (double)max_delay);
        int ok = bridge_send_plugin_json(br, j);
        cJSON_Delete(j);
        return ok;
    }

    case MSG_BRIDGE_REGISTER: {
        unsigned char payment_hash[32];
        unsigned char preimage[32];
        uint64_t amount_msat;
        size_t dest_client;
        if (!wire_parse_bridge_register(msg->json, payment_hash, preimage,
                                          &amount_msat, &dest_client))
            return 0;

        cJSON *j = cJSON_CreateObject();
        cJSON_AddStringToObject(j, "method", "invoice_registered");
        wire_json_add_hex(j, "payment_hash", payment_hash, 32);
        wire_json_add_hex(j, "preimage", preimage, 32);
        cJSON_AddNumberToObject(j, "amount_msat", (double)amount_msat);
        cJSON_AddNumberToObject(j, "dest_client", (double)dest_client);
        int ok = bridge_send_plugin_json(br, j);
        cJSON_Delete(j);
        return ok;
    }

    case MSG_BRIDGE_HELLO_ACK:
        /* Heartbeat response from LSP — update activity timestamp */
        br->last_lsp_activity = time(NULL);
        return 1;

    default:
        fprintf(stderr, "Bridge: unexpected LSP msg 0x%02x\n", msg->msg_type);
        return 0;
    }
}

/* Handle a newline-delimited JSON message from the CLN plugin */
int bridge_handle_plugin_msg(bridge_t *br, const char *line) {
    cJSON *json = cJSON_Parse(line);
    if (!json) {
        fprintf(stderr, "Bridge: failed to parse plugin JSON\n");
        return 0;
    }

    cJSON *method = cJSON_GetObjectItem(json, "method");
    if (!method || !cJSON_IsString(method)) {
        cJSON_Delete(json);
        return 0;
    }

    if (strcmp(method->valuestring, "htlc_accepted") == 0) {
        unsigned char payment_hash[32];
        if (wire_json_get_hex(json, "payment_hash", payment_hash, 32) != 32) {
            cJSON_Delete(json);
            return 0;
        }
        cJSON *am = cJSON_GetObjectItem(json, "amount_msat");
        cJSON *ce = cJSON_GetObjectItem(json, "cltv_expiry");
        if (!am || !cJSON_IsNumber(am) || !ce || !cJSON_IsNumber(ce)) {
            cJSON_Delete(json);
            return 0;
        }

        uint64_t amount_msat = (uint64_t)am->valuedouble;
        uint32_t cltv_expiry = (uint32_t)ce->valuedouble;

        cJSON *up = cJSON_GetObjectItem(json, "upstream_id");
        const char *upstream_id =
            (up && cJSON_IsString(up)) ? up->valuestring : "";

        /* Assign htlc_id and track */
        uint64_t htlc_id = bridge_add_pending_upstream(br, payment_hash,
                                                        upstream_id);
        if (htlc_id == 0) {
            /* Table full: the LSP cannot be asked, so tell the plugin to
               fail this HTLC rather than leave it held with no id. */
            fprintf(stderr, "Bridge: %d inbound HTLCs pending, refusing another\n",
                    BRIDGE_MAX_PENDING);
            cJSON *j = cJSON_CreateObject();
            cJSON_AddStringToObject(j, "method", "htlc_resolve");
            wire_json_add_hex(j, "payment_hash", payment_hash, 32);
            cJSON_AddNumberToObject(j, "htlc_id", 0);
            cJSON_AddStringToObject(j, "result", "fail");
            cJSON_AddStringToObject(j, "reason", "bridge_busy");
            bridge_send_plugin_json(br, j);
            cJSON_Delete(j);
            cJSON_Delete(json);
            return 1;
        }

        /* Forward to LSP */
        cJSON *msg = wire_build_bridge_add_htlc(payment_hash, amount_msat,
                                                  cltv_expiry, htlc_id);
        if (strlen(upstream_id) < sizeof(br->pending_inbound[0].upstream_id))
            cJSON_AddStringToObject(msg, "upstream_id", upstream_id);
        int ok = wire_send(br->lsp_fd, MSG_BRIDGE_ADD_HTLC, msg);
        cJSON_Delete(msg);
        cJSON_Delete(json);
        fprintf(stderr, "Bridge: forwarded ADD_HTLC to LSP (%llu msat, ok=%d)\n",
                (unsigned long long)amount_msat, ok);
        return ok;
    }

    if (strcmp(method->valuestring, "pay_result") == 0) {
        cJSON *ri = cJSON_GetObjectItem(json, "request_id");
        cJSON *su = cJSON_GetObjectItem(json, "success");
        if (!ri || !cJSON_IsNumber(ri) || !su || !cJSON_IsBool(su)) {
            cJSON_Delete(json);
            return 0;
        }

        uint64_t request_id = (uint64_t)ri->valuedouble;
        int success = cJSON_IsTrue(su);
        unsigned char preimage[32];
        memset(preimage, 0, 32);
        if (success &&
            wire_json_get_hex(json, "preimage", preimage, 32) != 32) {
            /* Not a usable result: never pass on a success without proof */
            fprintf(stderr, "Bridge: pay_result %llu claims success without "
                    "a preimage, dropped\n", (unsigned long long)request_id);
            cJSON_Delete(json);
            return 1;
        }

        cJSON *msg = wire_build_bridge_pay_result(request_id, success,
                                                    success ? preimage : NULL);
        int ok = wire_send(br->lsp_fd, MSG_BRIDGE_PAY_RESULT, msg);
        cJSON_Delete(msg);
        cJSON_Delete(json);
        return ok;
    }

    if (strcmp(method->valuestring, "invoice_bolt11") == 0) {
        unsigned char payment_hash[32];
        if (wire_json_get_hex(json, "payment_hash", payment_hash, 32) != 32) {
            cJSON_Delete(json);
            return 0;
        }
        cJSON *b11 = cJSON_GetObjectItem(json, "bolt11");
        if (!b11 || !cJSON_IsString(b11)) {
            cJSON_Delete(json);
            return 0;
        }

        cJSON *msg = wire_build_invoice_bolt11(payment_hash, b11->valuestring);
        int ok = wire_send(br->lsp_fd, MSG_INVOICE_BOLT11, msg);
        cJSON_Delete(msg);
        cJSON_Delete(json);
        return ok;
    }

    fprintf(stderr, "Bridge: unknown plugin method '%s'\n", method->valuestring);
    cJSON_Delete(json);
    return 0;
}

int bridge_run(bridge_t *br) {
    if (br->lsp_fd < 0) return 0;

    while (1) {
        fd_set rfds;
        FD_ZERO(&rfds);
        int max_fd = br->lsp_fd;
        FD_SET(br->lsp_fd, &rfds);

        if (br->plugin_fd >= 0) {
            FD_SET(br->plugin_fd, &rfds);
            if (br->plugin_fd > max_fd) max_fd = br->plugin_fd;
        }
        if (br->plugin_pending_fd >= 0) {
            FD_SET(br->plugin_pending_fd, &rfds);
            if (br->plugin_pending_fd > max_fd) max_fd = br->plugin_pending_fd;
        }
        /* Keep watching the listen socket while a plugin is connected, so
           further connections are turned away instead of queueing up. */
        if (br->plugin_listen_fd >= 0) {
            FD_SET(br->plugin_listen_fd, &rfds);
            if (br->plugin_listen_fd > max_fd) max_fd = br->plugin_listen_fd;
        }

        /* Use heartbeat interval as select timeout (or 60s if no heartbeat);
           wake sooner while a connection still has to authenticate. */
        int timeout_sec = (br->heartbeat_interval > 0) ? br->heartbeat_interval : 60;
        if (br->plugin_pending_fd >= 0 && timeout_sec > BRIDGE_PLUGIN_AUTH_TIMEOUT)
            timeout_sec = BRIDGE_PLUGIN_AUTH_TIMEOUT;
        struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };
        int ret = select(max_fd + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) {
            perror("Bridge: select");
            return 0;
        }
        bridge_expire_pending_plugin(br, time(NULL));

        /* Heartbeat: check for stale LSP connection on timeout */
        if (ret == 0) {
            if (bridge_is_stale(br)) {
                fprintf(stderr, "Bridge: LSP connection stale, sending ping\n");
                cJSON *ping = wire_build_bridge_hello(
            br->has_bridge_pubkey ? &br->bridge_pubkey : NULL);
                if (!wire_send(br->lsp_fd, MSG_BRIDGE_HELLO, ping)) {
                    cJSON_Delete(ping);
                    fprintf(stderr, "Bridge: ping failed, attempting reconnect\n");
                    int reconnected = 0;
                    for (int attempt = 0; attempt < 12; attempt++) {
                        if (bridge_reconnect_lsp(br)) {
                            reconnected = 1;
                            break;
                        }
                        int delay = (attempt < 3) ? 2 : (attempt < 6) ? 5 : 10;
                        fprintf(stderr, "Bridge: reconnect failed, retrying in %ds...\n", delay);
                        sleep(delay);
                    }
                    if (!reconnected)
                        return 0;
                } else {
                    cJSON_Delete(ping);
                }
            }
            continue;
        }

        /* A connection waiting to authenticate has sent something */
        int plugin_just_authenticated = 0;
        if (br->plugin_pending_fd >= 0 &&
            FD_ISSET(br->plugin_pending_fd, &rfds)) {
            plugin_just_authenticated = bridge_service_pending_plugin(br) == 1;
        }

        /* New connection on the plugin port (held until it authenticates,
           or closed at once if a plugin is already there) */
        if (br->plugin_listen_fd >= 0 &&
            FD_ISSET(br->plugin_listen_fd, &rfds)) {
            bridge_accept_plugin(br);
        }

        /* Handle LSP messages */
        if (FD_ISSET(br->lsp_fd, &rfds)) {
            wire_msg_t msg;
            if (!wire_recv(br->lsp_fd, &msg)) {
                fprintf(stderr, "Bridge: LSP connection lost\n");
                /* Attempt reconnect with retry */
                int reconnected = 0;
                for (int attempt = 0; attempt < 12; attempt++) {
                    if (bridge_reconnect_lsp(br)) {
                        reconnected = 1;
                        break;
                    }
                    int delay = (attempt < 3) ? 2 : (attempt < 6) ? 5 : 10;
                    fprintf(stderr, "Bridge: reconnect failed, retrying in %ds...\n", delay);
                    sleep(delay);
                }
                if (reconnected) continue;
                return 0;
            }
            br->last_lsp_activity = time(NULL);
            if (!bridge_handle_lsp_msg(br, &msg)) {
                cJSON_Delete(msg.json);
                return 0;
            }
            cJSON_Delete(msg.json);
        }

        /* Handle plugin messages: when the socket is readable, and for as
           long as complete lines are already buffered (several messages can
           arrive in one read, or right behind the auth line). */
        int plugin_readable = br->plugin_fd >= 0 && !plugin_just_authenticated &&
                              FD_ISSET(br->plugin_fd, &rfds);
        while (br->plugin_fd >= 0 &&
               (plugin_readable ||
                memchr(br->plugin_read_buf + br->plugin_read_pos, '\n',
                       br->plugin_read_len - br->plugin_read_pos))) {
            plugin_readable = 0;
            char *line = bridge_read_plugin_line(br);
            if (!line) {
                fprintf(stderr, "Bridge: plugin connection lost\n");
                wire_close(br->plugin_fd);
                br->plugin_fd = -1;
                br->plugin_read_len = 0;
                br->plugin_read_pos = 0;
                break;
            }
            if (!bridge_handle_plugin_msg(br, line)) {
                free(line);
                return 0;
            }
            free(line);
        }
    }
}

void bridge_set_heartbeat(bridge_t *br, int interval_sec) {
    br->heartbeat_interval = interval_sec > 0 ? interval_sec : 30;
}

int bridge_is_stale(const bridge_t *br) {
    if (br->heartbeat_interval <= 0 || br->lsp_fd < 0)
        return 0;
    return (time(NULL) - br->last_lsp_activity) > br->heartbeat_interval;
}

int bridge_reconnect_lsp(bridge_t *br) {
    /* Close existing connection */
    if (br->lsp_fd >= 0) {
        wire_close(br->lsp_fd);
        br->lsp_fd = -1;
    }

    br->reconnect_attempts++;
    fprintf(stderr, "Bridge: reconnecting to LSP %s:%d (attempt %d)\n",
            br->lsp_host, br->lsp_port, br->reconnect_attempts);

    return bridge_connect_lsp(br, br->lsp_host, br->lsp_port);
}

void bridge_cleanup(bridge_t *br) {
    if (br->lsp_fd >= 0) wire_close(br->lsp_fd);
    if (br->plugin_fd >= 0) wire_close(br->plugin_fd);
    if (br->plugin_pending_fd >= 0) wire_close(br->plugin_pending_fd);
    if (br->plugin_listen_fd >= 0) wire_close(br->plugin_listen_fd);
    br->lsp_fd = -1;
    br->plugin_fd = -1;
    br->plugin_pending_fd = -1;
    br->plugin_listen_fd = -1;
}
