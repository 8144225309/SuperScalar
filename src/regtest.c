#include "superscalar/regtest.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef _POSIX_VERSION
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);

#ifdef _POSIX_VERSION

/* Default timeout for bitcoin-cli commands (seconds). */
#ifndef REGTEST_CMD_TIMEOUT_SECS
#define REGTEST_CMD_TIMEOUT_SECS 30
#endif

/* Wait for child with timeout. Returns 0 on normal exit, -1 on timeout (child killed). */
static int waitpid_timeout(pid_t pid, int timeout_secs) {
    time_t deadline = time(NULL) + timeout_secs;
    while (time(NULL) < deadline) {
        int status;
        pid_t ret = waitpid(pid, &status, WNOHANG);
        if (ret == pid) return 0;    /* child exited */
        if (ret < 0) return 0;       /* error (already exited) */
        usleep(50000);               /* 50ms poll interval */
    }
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);  /* reap zombie */
    return -1;
}

/* Execute argv via fork/execvp with no shell interpretation.
   Captures combined stdout+stderr. Returns malloc'd string or NULL. */
static char *run_command_exec(char *const argv[]) {
    int pipefd[2];
    if (pipe(pipefd) < 0) return NULL;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return NULL;
    }

    if (pid == 0) {
        /* Child: redirect stdout+stderr to pipe write end */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execvp(argv[0], argv);
        _exit(127);  /* exec failed */
    }

    /* Parent: read from pipe */
    close(pipefd[1]);

    size_t cap = 4096;
    size_t len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) { close(pipefd[0]); waitpid_timeout(pid, REGTEST_CMD_TIMEOUT_SECS); return NULL; }

    while (1) {
        ssize_t n = read(pipefd[0], buf + len, cap - len - 1);
        if (n <= 0) break;
        len += (size_t)n;
        if (len >= cap - 1) {
            cap *= 2;
            char *tmp = (char *)realloc(buf, cap);
            if (!tmp) { free(buf); close(pipefd[0]); waitpid_timeout(pid, REGTEST_CMD_TIMEOUT_SECS); return NULL; }
            buf = tmp;
        }
    }
    buf[len] = '\0';
    close(pipefd[0]);

    if (waitpid_timeout(pid, REGTEST_CMD_TIMEOUT_SECS) < 0) {
        free(buf);
        return NULL;  /* child killed after timeout */
    }
    return buf;
}
#endif /* _POSIX_VERSION */

/* Execute shell command via popen (fallback / used for backward compat). */
static char *run_command(const char *cmd) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;

    size_t cap = 4096;
    size_t len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) { pclose(fp); return NULL; }

    while (1) {
        size_t n = fread(buf + len, 1, cap - len - 1, fp);
        if (n == 0) break;
        len += n;
        if (len >= cap - 1) {
            cap *= 2;
            char *tmp = (char *)realloc(buf, cap);
            if (!tmp) { free(buf); pclose(fp); return NULL; }
            buf = tmp;
        }
    }
    buf[len] = '\0';

    pclose(fp);
    return buf;
}

/* Validate RPC parameter against allowed character set.
   Rejects shell metacharacters to prevent command injection via popen().
   Returns 1 if safe, 0 if rejected. */
static int sanitize_rpc_param(const char *s) {
    if (!s) return 1;
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9')) continue;
        switch (c) {
        case '.': case '_': case ':': case '/': case '-':
        case ' ': case ',': case '"': case '\'':
        case '[': case ']': case '{': case '}':
        case '(': case ')': case '#': case '*':
        case '@': case '~':
        case '+': case '=': continue;
        default: return 0;  /* rejected */
        }
    }
    return 1;
}

static void build_cli_prefix(const regtest_t *rt, char *buf, size_t buf_len) {
    /* Validate all rt fields that will be interpolated into shell commands */
    if (!sanitize_rpc_param(rt->cli_path) ||
        !sanitize_rpc_param(rt->network) ||
        !sanitize_rpc_param(rt->rpcuser) ||
        !sanitize_rpc_param(rt->rpcpassword) ||
        !sanitize_rpc_param(rt->datadir) ||
        !sanitize_rpc_param(rt->wallet)) {
        buf[0] = '\0';
        return;
    }

    if (strcmp(rt->network, "mainnet") == 0) {
        snprintf(buf, buf_len,
            "%s -rpcuser=%s -rpcpassword=%s",
            rt->cli_path, rt->rpcuser, rt->rpcpassword);
    } else {
        snprintf(buf, buf_len,
            "%s -%s -rpcuser=%s -rpcpassword=%s",
            rt->cli_path, rt->network, rt->rpcuser, rt->rpcpassword);
    }

    if (rt->datadir[0] != '\0') {
        size_t cur = strlen(buf);
        snprintf(buf + cur, buf_len - cur, " -datadir=%s", rt->datadir);
    }
    if (rt->rpcport > 0) {
        size_t cur = strlen(buf);
        snprintf(buf + cur, buf_len - cur, " -rpcport=%d", rt->rpcport);
    }
    if (rt->wallet[0] != '\0') {
        size_t cur = strlen(buf);
        snprintf(buf + cur, buf_len - cur, " -rpcwallet=%s", rt->wallet);
    }
}

int regtest_init(regtest_t *rt) {
    return regtest_init_network(rt, "regtest");
}

int regtest_init_network(regtest_t *rt, const char *network) {
    memset(rt, 0, sizeof(*rt));
    strncpy(rt->cli_path, "bitcoin-cli", sizeof(rt->cli_path) - 1);
    strncpy(rt->rpcuser, "rpcuser", sizeof(rt->rpcuser) - 1);
    strncpy(rt->rpcpassword, "rpcpass", sizeof(rt->rpcpassword) - 1);
    strncpy(rt->network, network ? network : "regtest", sizeof(rt->network) - 1);
    rt->scan_depth = (strcmp(rt->network, "regtest") == 0) ? 10 : 1000;

    /* Set default RPC port by network so HTTP path is tried first.
       Standard Bitcoin Core ports: regtest=18443, testnet=18332,
       signet=38332, mainnet=8332.  Falls back to fork+exec if HTTP fails. */
    if (strcmp(rt->network, "regtest") == 0)       rt->rpcport = 18443;
    else if (strcmp(rt->network, "testnet") == 0)  rt->rpcport = 18332;
    else if (strcmp(rt->network, "signet") == 0)   rt->rpcport = 38332;
    else                                            rt->rpcport = 8332;

    /* Verify connection — uses HTTP when rpcport > 0, else fork+exec */
    char *result = regtest_exec(rt, "getblockchaininfo", "");
    if (!result) return 0;

    int ok = (strstr(result, "\"chain\"") != NULL);
    free(result);
    return ok ? 1 : 0;
}

int regtest_init_full(regtest_t *rt, const char *network,
                      const char *cli_path, const char *rpcuser,
                      const char *rpcpassword, const char *datadir,
                      int rpcport) {
    memset(rt, 0, sizeof(*rt));
    strncpy(rt->cli_path,
            cli_path ? cli_path : "bitcoin-cli",
            sizeof(rt->cli_path) - 1);
    strncpy(rt->rpcuser,
            rpcuser ? rpcuser : "rpcuser",
            sizeof(rt->rpcuser) - 1);
    strncpy(rt->rpcpassword,
            rpcpassword ? rpcpassword : "rpcpass",
            sizeof(rt->rpcpassword) - 1);
    strncpy(rt->network,
            network ? network : "regtest",
            sizeof(rt->network) - 1);
    if (datadir)
        strncpy(rt->datadir, datadir, sizeof(rt->datadir) - 1);
    rt->rpcport = rpcport;
    rt->scan_depth = (strcmp(rt->network, "regtest") == 0) ? 10 : 1000;

    /* Verify connection using build_cli_prefix for consistency */
    char prefix[512];
    build_cli_prefix(rt, prefix, sizeof(prefix));
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "%s getblockchaininfo 2>&1", prefix);

    char *result = run_command(cmd);
    if (!result) return 0;

    int ok = (strstr(result, "\"chain\"") != NULL);
    free(result);
    return ok ? 1 : 0;
}

#ifdef _POSIX_VERSION
/* Build argv array from regtest_t + method + params for execvp.
   Tokenizes params on spaces (respecting double-quoted substrings).
   Returns malloc'd argv (caller must free each element + the array), n_out set.
   Returns NULL on error. */
static char **build_argv(const regtest_t *rt, const char *method,
                          const char *params, size_t *n_out) {
    /* Max args: cli_path, -network, -rpcuser=X, -rpcpassword=X,
       -datadir=X, -rpcport=X, -rpcwallet=X, method, + up to 32 param tokens, NULL */
    char *args[48];
    size_t n = 0;

    args[n++] = strdup(rt->cli_path);

    if (strcmp(rt->network, "mainnet") != 0) {
        char net_flag[32];
        snprintf(net_flag, sizeof(net_flag), "-%s", rt->network);
        args[n++] = strdup(net_flag);
    }

    char rpcuser_arg[128];
    snprintf(rpcuser_arg, sizeof(rpcuser_arg), "-rpcuser=%s", rt->rpcuser);
    args[n++] = strdup(rpcuser_arg);

    char rpcpass_arg[128];
    snprintf(rpcpass_arg, sizeof(rpcpass_arg), "-rpcpassword=%s", rt->rpcpassword);
    args[n++] = strdup(rpcpass_arg);

    if (rt->datadir[0] != '\0') {
        char dd_arg[512];
        snprintf(dd_arg, sizeof(dd_arg), "-datadir=%s", rt->datadir);
        args[n++] = strdup(dd_arg);
    }
    if (rt->rpcport > 0) {
        char port_arg[32];
        snprintf(port_arg, sizeof(port_arg), "-rpcport=%d", rt->rpcport);
        args[n++] = strdup(port_arg);
    }
    if (rt->wallet[0] != '\0') {
        char wallet_arg[128];
        snprintf(wallet_arg, sizeof(wallet_arg), "-rpcwallet=%s", rt->wallet);
        args[n++] = strdup(wallet_arg);
    }

    args[n++] = strdup(method);

    /* Tokenize params on spaces, respecting double-quoted substrings */
    if (params && params[0] != '\0') {
        size_t plen = strlen(params);
        char *pcopy = malloc(plen + 1);
        if (pcopy) {
            memcpy(pcopy, params, plen + 1);
            char *p = pcopy;
            while (*p && n < 46) {
                while (*p == ' ') p++;
                if (!*p) break;

                char *start;
                if (*p == '"' || *p == '\'') {
                    /* Quoted token: find matching closing quote */
                    char quote = *p;
                    p++;
                    start = p;
                    while (*p && *p != quote) p++;
                    if (*p == quote) *p++ = '\0';
                } else {
                    start = p;
                    while (*p && *p != ' ') p++;
                    if (*p) *p++ = '\0';
                }
                args[n++] = strdup(start);
            }
            free(pcopy);
        }
    }

    /* Build NULL-terminated argv */
    char **argv = malloc((n + 1) * sizeof(char *));
    if (!argv) {
        for (size_t i = 0; i < n; i++) free(args[i]);
        return NULL;
    }
    for (size_t i = 0; i < n; i++) argv[i] = args[i];
    argv[n] = NULL;
    *n_out = n;
    return argv;
}

static void free_argv(char **argv, size_t n) {
    for (size_t i = 0; i < n; i++) free(argv[i]);
    free(argv);
}
#endif /* _POSIX_VERSION */

/* -----------------------------------------------------------------------
 * HTTP JSON-RPC client for Bitcoin Core
 *
 * Replaces fork+exec(bitcoin-cli) with a direct HTTP/1.0 POST to
 * 127.0.0.1:rpcport.  One TCP connection per call; no external deps.
 * Falls back to fork+exec when rpcport == 0.
 * --------------------------------------------------------------------- */

#ifdef _POSIX_VERSION

/* RFC 4648 base64 encoder. Writes NUL-terminated string to out[0..out_cap).
   Returns number of output chars written (excluding NUL), or -1 on overflow. */
static int regtest_base64(const char *in, size_t in_len, char *out, size_t out_cap)
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

/* Convert space-tokenized params string (same format as build_argv) into
   a JSON array string.  Tokens in double quotes become JSON strings;
   "true"/"false"/"null" become JSON literals; purely numeric tokens become
   JSON numbers; everything else becomes a JSON string.
   Writes directly to out[0..out_cap) without intermediate token buffers,
   so arbitrarily long tokens (e.g. full raw tx hex) are handled correctly. */
static int params_to_json_array(const char *params, char *out, size_t out_cap)
{
    if (!params || params[0] == '\0') {
        if (out_cap < 3) return 0;
        strcpy(out, "[]");
        return 1;
    }

    size_t pos = 0;
    if (pos + 1 >= out_cap) return 0;
    out[pos++] = '[';

    const char *p = params;
    int first = 1;
    while (*p) {
        /* Skip whitespace */
        while (*p == ' ') p++;
        if (!*p) break;

        if (!first) {
            if (pos + 1 >= out_cap) return 0;
            out[pos++] = ',';
        }
        first = 0;

        const char *tok_start;
        size_t tok_len;
        int is_quoted = 0;

        if (*p == '"' || *p == '\'') {
            /* Quoted string token: strip outer quotes */
            char q = *p++;
            tok_start = p;
            while (*p && *p != q) p++;
            tok_len = (size_t)(p - tok_start);
            if (*p == q) p++;
            is_quoted = 1;
        } else {
            tok_start = p;
            while (*p && *p != ' ') p++;
            tok_len = (size_t)(p - tok_start);
        }

        /* Classify token (using the raw bytes, not a copy).
           Single-quoted JSON objects/arrays (e.g. '[{"txid":...}]') must be
           emitted as raw JSON, not as JSON strings. */
        int is_num = 0, is_literal = 0, is_raw_json = 0;
        if (is_quoted && tok_len > 0 && (tok_start[0] == '{' || tok_start[0] == '[')) {
            is_raw_json = 1;
            is_quoted = 0;  /* treat as raw JSON, no string wrapping */
        }
        if (!is_quoted) {
            if (tok_len > 0 &&
                (tok_start[0] == '-' || (tok_start[0] >= '0' && tok_start[0] <= '9'))) {
                is_num = 1;
                for (size_t k = (tok_start[0] == '-') ? 1 : 0; k < tok_len; k++) {
                    if (tok_start[k] != '.' &&
                        (tok_start[k] < '0' || tok_start[k] > '9')) { is_num = 0; break; }
                }
            }
            if (!is_num) {
                is_literal = ((tok_len == 4 && memcmp(tok_start, "true", 4) == 0) ||
                              (tok_len == 5 && memcmp(tok_start, "false", 5) == 0) ||
                              (tok_len == 4 && memcmp(tok_start, "null", 4) == 0));
                is_raw_json = (tok_len > 0 && (tok_start[0] == '{' || tok_start[0] == '['));
            }
        }

        if (is_num || is_literal || is_raw_json) {
            if (pos + tok_len + 1 > out_cap) return 0;
            memcpy(out + pos, tok_start, tok_len);
            pos += tok_len;
        } else {
            /* Emit as JSON string with escaping */
            if (pos + 1 >= out_cap) return 0;
            out[pos++] = '"';
            for (size_t k = 0; k < tok_len; k++) {
                if (tok_start[k] == '"' || tok_start[k] == '\\') {
                    if (pos + 2 > out_cap) return 0;
                    out[pos++] = '\\';
                    out[pos++] = tok_start[k];
                } else {
                    if (pos + 1 >= out_cap) return 0;
                    out[pos++] = tok_start[k];
                }
            }
            if (pos + 1 >= out_cap) return 0;
            out[pos++] = '"';
        }
    }

    if (pos + 2 > out_cap) return 0;
    out[pos++] = ']';
    out[pos] = '\0';
    return 1;
}

/* HTTP/1.0 JSON-RPC POST to Bitcoin Core.
   Returns malloc'd string containing the serialized "result" field,
   or NULL on error (caller falls back to fork+exec).
   Return format mirrors bitcoin-cli output:
     - JSON object/array result: compact JSON string (cJSON_PrintUnformatted)
     - String result: "value" (with outer quotes, matching bitcoin-cli)
     - Number result: "42" decimal string
   All existing regtest_exec callers work unchanged. */
static char *regtest_http_rpc(const regtest_t *rt,
                               const char *method, const char *params)
{
    int port = (rt->rpcport > 0) ? rt->rpcport : 18443;

    /* Build Basic Auth header */
    char credentials[512];
    snprintf(credentials, sizeof(credentials), "%s:%s", rt->rpcuser, rt->rpcpassword);
    char auth_b64[512];
    if (regtest_base64(credentials, strlen(credentials), auth_b64, sizeof(auth_b64)) < 0)
        return NULL;

    /* Build JSON-RPC body — heap-allocated to handle large params (e.g. raw tx hex).
       params_json capacity: params length * 2 + 32 covers worst-case escaping. */
    size_t params_len = params ? strlen(params) : 0;
    size_t pjcap = params_len * 2 + 64;
    char *params_json = malloc(pjcap);
    if (!params_json) return NULL;
    if (!params_to_json_array(params, params_json, pjcap)) {
        free(params_json); return NULL;
    }

    /* Wallet path: /wallet/NAME or / */
    char path[256] = "/";
    if (rt->wallet[0] != '\0')
        snprintf(path, sizeof(path), "/wallet/%s", rt->wallet);

    size_t bodycap = strlen(params_json) + 128;
    char *body = malloc(bodycap);
    if (!body) { free(params_json); return NULL; }
    int body_len = snprintf(body, bodycap,
        "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"%s\",\"params\":%s}",
        method, params_json);
    free(params_json);
    if (body_len <= 0 || (size_t)body_len >= bodycap) { free(body); return NULL; }

    /* Build HTTP request */
    size_t reqcap = (size_t)body_len + 512;
    char *req = malloc(reqcap);
    if (!req) { free(body); return NULL; }
    int req_len = snprintf(req, reqcap,
        "POST %s HTTP/1.0\r\n"
        "Host: 127.0.0.1:%d\r\n"
        "Authorization: Basic %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        path, port, auth_b64, body_len, body);
    free(body);
    if (req_len <= 0 || (size_t)req_len >= reqcap) { free(req); return NULL; }

    /* Connect to 127.0.0.1:port */
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo("127.0.0.1", port_str, &hints, &res) != 0) { free(req); return NULL; }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); free(req); return NULL; }
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd); freeaddrinfo(res); free(req); return NULL;
    }
    freeaddrinfo(res);

    /* Send request */
    ssize_t sent_bytes = send(fd, req, (size_t)req_len, 0);
    free(req);
    if (sent_bytes != (ssize_t)req_len) {
        close(fd); return NULL;
    }

    /* Read full response */
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

    /* Find HTTP body (after blank line) */
    char *bodyp = strstr(resp, "\r\n\r\n");
    if (!bodyp) { free(resp); return NULL; }
    bodyp += 4;

    /* Parse JSON-RPC response */
    cJSON *jresp = cJSON_Parse(bodyp);
    free(resp);
    if (!jresp) return NULL;

    /* Check for error */
    cJSON *err = cJSON_GetObjectItem(jresp, "error");
    if (err && !cJSON_IsNull(err)) {
        char *errstr = cJSON_PrintUnformatted(err);
        if (errstr) {
            fprintf(stderr, "HTTP RPC %s error: %s\n", method, errstr);
            free(errstr);
        }
        cJSON_Delete(jresp);
        return NULL;
    }

    cJSON *result = cJSON_GetObjectItem(jresp, "result");
    if (!result) { cJSON_Delete(jresp); return NULL; }

    /* Serialize result to match bitcoin-cli output format */
    char *out = NULL;
    if (cJSON_IsString(result)) {
        /* Return with outer quotes: matches bitcoin-cli "value"\n format */
        size_t vlen = strlen(result->valuestring);
        out = malloc(vlen + 3);
        if (out) {
            out[0] = '"';
            memcpy(out + 1, result->valuestring, vlen);
            out[vlen + 1] = '"';
            out[vlen + 2] = '\0';
        }
    } else if (cJSON_IsNumber(result)) {
        out = malloc(64);
        if (out) snprintf(out, 64, "%g", result->valuedouble);
    } else {
        /* Object, array, bool, null: compact JSON */
        out = cJSON_PrintUnformatted(result);
    }

    cJSON_Delete(jresp);
    return out;
}

#endif /* _POSIX_VERSION (HTTP RPC) */

char *regtest_exec(const regtest_t *rt, const char *method, const char *params) {
    /* Reject shell metacharacters in method and params */
    if (!sanitize_rpc_param(method) || !sanitize_rpc_param(params))
        return NULL;

#ifdef _POSIX_VERSION
    /* Preferred path: direct HTTP JSON-RPC (no subprocess fork).
       Falls back to fork/execvp when rpcport == 0 or HTTP fails. */
    if (rt->rpcport > 0) {
        char *result = regtest_http_rpc(rt, method, params);
        if (result) return result;
        /* HTTP failed — fall through to fork+exec */
    }

    /* Fork+exec bitcoin-cli (used when rpcport==0 or HTTP unavailable) */
    size_t argc_n = 0;
    char **argv = build_argv(rt, method, params, &argc_n);
    if (!argv) return NULL;

    char *result = run_command_exec(argv);
    free_argv(argv, argc_n);
    return result;
#else
    /* Fallback: popen (non-POSIX systems) */
    char prefix[512];
    build_cli_prefix(rt, prefix, sizeof(prefix));
    if (prefix[0] == '\0') return NULL;

    char cmd[2048];
    if (params && params[0] != '\0') {
        snprintf(cmd, sizeof(cmd), "%s %s %s 2>&1", prefix, method, params);
    } else {
        snprintf(cmd, sizeof(cmd), "%s %s 2>&1", prefix, method);
    }

    return run_command(cmd);
#endif
}

int regtest_create_wallet(regtest_t *rt, const char *name) {
    char params[256];
    snprintf(params, sizeof(params), "\"%s\"", name);
    char *result = regtest_exec(rt, "createwallet", params);
    if (!result) {
        /* createwallet failed — wallet may already exist (HTTP path returns NULL for
           all errors, including the benign "already exists" case).
           Try loadwallet; if that also fails the wallet is likely already loaded. */
        result = regtest_exec(rt, "loadwallet", params);
        if (result) {
            free(result);
        }
        /* Fall through: set wallet name regardless — it either was created, loaded,
           or is already active.  Subsequent RPC calls will confirm. */
    } else {
        if (strstr(result, "error") != NULL && strstr(result, "already exists") == NULL) {
            free(result);
            result = regtest_exec(rt, "loadwallet", params);
            if (!result) return 0;
        }
        free(result);
    }

    strncpy(rt->wallet, name, sizeof(rt->wallet) - 1);
    return 1;
}

int regtest_get_new_address(regtest_t *rt, char *addr_out, size_t len) {
    char *result = regtest_exec(rt, "getnewaddress", "\"\" bech32m");
    if (!result) return 0;

    char *start = result;
    while (*start == '"' || *start == ' ' || *start == '\n') start++;
    char *end = start + strlen(start) - 1;
    while (end > start && (*end == '"' || *end == '\n' || *end == '\r' || *end == ' ')) {
        *end = '\0';
        end--;
    }

    if (strlen(start) == 0 || strlen(start) >= len) {
        free(result);
        return 0;
    }

    strncpy(addr_out, start, len - 1);
    addr_out[len - 1] = '\0';
    free(result);
    return 1;
}

int regtest_get_address_scriptpubkey(regtest_t *rt, const char *address,
                                      unsigned char *spk_out, size_t *spk_len_out) {
    if (!rt || !address || !spk_out || !spk_len_out) return 0;

    char params[256];
    snprintf(params, sizeof(params), "\"%s\"", address);
    char *result = regtest_exec(rt, "getaddressinfo", params);
    if (!result) return 0;

    cJSON *json = cJSON_Parse(result);
    free(result);
    if (!json) return 0;

    cJSON *spk = cJSON_GetObjectItem(json, "scriptPubKey");
    if (!spk || !cJSON_IsString(spk)) {
        cJSON_Delete(json);
        return 0;
    }

    int decoded = hex_decode(spk->valuestring, spk_out, 256);
    cJSON_Delete(json);
    if (decoded <= 0) return 0;

    *spk_len_out = (size_t)decoded;
    return 1;
}

int regtest_get_block_height(regtest_t *rt) {
    char *result = regtest_exec(rt, "getblockcount", "");
    if (!result) return -1;
    int height = atoi(result);
    free(result);
    return height;
}

int regtest_mine_blocks(regtest_t *rt, int n, const char *address) {
    /* Only allow mining on regtest to prevent accidental mining on other networks */
    if (strcmp(rt->network, "regtest") != 0) return 0;

    char params[512];
    snprintf(params, sizeof(params), "%d \"%s\"", n, address);
    char *result = regtest_exec(rt, "generatetoaddress", params);
    if (!result) return 0;

    int ok = (result[0] == '[');
    free(result);
    return ok;
}

int regtest_fund_address(regtest_t *rt, const char *address,
                         double btc_amount, char *txid_out) {
    char params[512];
    snprintf(params, sizeof(params), "\"%s\" %.8f", address, btc_amount);
    char *result = regtest_exec(rt, "sendtoaddress", params);
    if (!result) return 0;

    char *start = result;
    while (*start == '"' || *start == ' ' || *start == '\n') start++;
    char *end = start + strlen(start) - 1;
    while (end > start && (*end == '"' || *end == '\n' || *end == '\r' || *end == ' ')) {
        *end = '\0';
        end--;
    }

    if (strlen(start) != 64) {
        fprintf(stderr, "regtest_fund_address: unexpected result: %s\n", start);
        if (strstr(result, "Fee estimation failed") ||
            strstr(result, "fallbackfee"))
            fprintf(stderr, "  hint: set fallbackfee=0.00001 in bitcoin.conf\n");
        free(result);
        return 0;
    }

    if (txid_out)
        strncpy(txid_out, start, 65);
    free(result);
    return 1;
}

int regtest_mine_for_balance(regtest_t *rt, double min_btc, const char *address) {
    if (strcmp(rt->network, "regtest") != 0) return 0;

    /* Mine initial 101 blocks for coinbase maturity */
    if (!regtest_mine_blocks(rt, 101, address)) return 0;

    /* Mine additional blocks if subsidy is too low (regtest halves every 150) */
    for (int i = 0; i < 100; i++) {
        double bal = regtest_get_balance(rt);
        if (bal >= min_btc) return 1;
        if (!regtest_mine_blocks(rt, 25, address)) return 0;
    }
    return 0;
}

int regtest_send_raw_tx(regtest_t *rt, const char *tx_hex, char *txid_out) {
    char *params = (char *)malloc(strlen(tx_hex) + 4);
    if (!params) return 0;
    snprintf(params, strlen(tx_hex) + 4, "\"%s\"", tx_hex);

    char *result = regtest_exec(rt, "sendrawtransaction", params);
    free(params);
    if (!result) return 0;

    if (strstr(result, "error") != NULL) {
        fprintf(stderr, "sendrawtransaction error: %s\n", result);
        if (strstr(result, "min relay fee not met") ||
            strstr(result, "insufficient fee"))
            fprintf(stderr, "  hint: increase --fee-rate (current may be "
                    "below mempool minimum)\n");
        free(result);
        return 0;
    }

    char *start = result;
    while (*start == '"' || *start == ' ' || *start == '\n') start++;
    char *end = start + strlen(start) - 1;
    while (end > start && (*end == '"' || *end == '\n' || *end == '\r' || *end == ' ')) {
        *end = '\0';
        end--;
    }

    if (strlen(start) != 64) {
        free(result);
        return 0;
    }

    if (txid_out)
        strncpy(txid_out, start, 65);
    free(result);
    return 1;
}

int regtest_get_confirmations(regtest_t *rt, const char *txid) {
    char params[256];

    /* Try gettransaction (wallet txs) */
    snprintf(params, sizeof(params), "\"%s\" true", txid);
    char *result = regtest_exec(rt, "gettransaction", params);
    if (result) {
        cJSON *json = cJSON_Parse(result);
        free(result);
        if (json) {
            cJSON *conf = cJSON_GetObjectItem(json, "confirmations");
            if (conf && cJSON_IsNumber(conf)) {
                int val = conf->valueint;
                cJSON_Delete(json);
                return val;
            }
            cJSON_Delete(json);
        }
    }

    /* Try getrawtransaction (works for any TX with -txindex=1, or if in
       mempool even without txindex).  This is the industry standard approach
       used by CLN, LND, and LDK — treats bitcoind as a chain source, not
       a wallet.  Fixes the gap where manually-built TXs (HD wallet path)
       are invisible to gettransaction. */
    snprintf(params, sizeof(params), "\"%s\" true", txid);
    result = regtest_exec(rt, "getrawtransaction", params);
    if (result) {
        cJSON *json = cJSON_Parse(result);
        free(result);
        if (json) {
            cJSON *conf = cJSON_GetObjectItem(json, "confirmations");
            if (conf && cJSON_IsNumber(conf)) {
                int val = conf->valueint;
                cJSON_Delete(json);
                return val;
            }
            /* No confirmations field = in mempool, not yet confirmed */
            cJSON_Delete(json);
            return 0;
        }
    }

    /* Fallback: scan recent blocks with getrawtransaction + blockhash */
    result = regtest_exec(rt, "getblockcount", "");
    if (!result) return -1;
    int height = atoi(result);
    free(result);

    int depth = rt->scan_depth > 0 ? rt->scan_depth : 20;
    for (int i = 0; i < depth && i <= height; i++) {
        snprintf(params, sizeof(params), "%d", height - i);
        char *hash_result = regtest_exec(rt, "getblockhash", params);
        if (!hash_result) continue;

        /* Trim whitespace */
        char blockhash[65];
        char *s = hash_result;
        while (*s == ' ' || *s == '\n' || *s == '"') s++;
        char *e = s + strlen(s) - 1;
        while (e > s && (*e == ' ' || *e == '\n' || *e == '"' || *e == '\r'))
            *e-- = '\0';
        strncpy(blockhash, s, 64);
        blockhash[64] = '\0';
        free(hash_result);

        snprintf(params, sizeof(params), "\"%s\" true \"%s\"", txid, blockhash);
        char *tx_result = regtest_exec(rt, "getrawtransaction", params);
        if (!tx_result) continue;

        cJSON *json = cJSON_Parse(tx_result);
        free(tx_result);
        if (!json) continue;

        cJSON *conf = cJSON_GetObjectItem(json, "confirmations");
        if (conf && cJSON_IsNumber(conf)) {
            int val = conf->valueint;
            cJSON_Delete(json);
            return val;
        }
        cJSON_Delete(json);
    }

    return -1;
}

int regtest_get_confirmations_batch(regtest_t *rt,
                                    const char **txids_hex, size_t n_txids,
                                    int *confs_out)
{
    if (!rt || !txids_hex || !confs_out || n_txids == 0) return 0;

    for (size_t i = 0; i < n_txids; i++)
        confs_out[i] = -1;

    size_t n_remaining = n_txids;

    /* Step 1: gettransaction for each txid (cheap for wallet txs) */
    for (size_t i = 0; i < n_txids; i++) {
        char params[256];
        snprintf(params, sizeof(params), "\"%s\" true", txids_hex[i]);
        char *result = regtest_exec(rt, "gettransaction", params);
        if (!result) continue;
        cJSON *json = cJSON_Parse(result);
        free(result);
        if (!json) continue;
        cJSON *conf = cJSON_GetObjectItem(json, "confirmations");
        if (conf && cJSON_IsNumber(conf)) {
            confs_out[i] = conf->valueint;
            n_remaining--;
        }
        cJSON_Delete(json);
    }

    if (n_remaining == 0) return 1;

    /* Step 1b: getrawtransaction for remaining txids (works with -txindex=1
       or for mempool TXs).  Same approach as CLN/LND/LDK. */
    for (size_t i = 0; i < n_txids; i++) {
        if (confs_out[i] >= 0) continue;  /* already found */
        char params[256];
        snprintf(params, sizeof(params), "\"%s\" true", txids_hex[i]);
        char *result = regtest_exec(rt, "getrawtransaction", params);
        if (!result) continue;
        cJSON *json = cJSON_Parse(result);
        free(result);
        if (!json) continue;
        cJSON *conf = cJSON_GetObjectItem(json, "confirmations");
        if (conf && cJSON_IsNumber(conf)) {
            confs_out[i] = conf->valueint;
        } else {
            confs_out[i] = 0;  /* in mempool */
        }
        cJSON_Delete(json);
        n_remaining--;
    }

    if (n_remaining == 0) return 1;

    /* Step 2: scan recent blocks — one getblockhash + one getblock per block,
       then check all remaining txids against the block's tx array in memory.
       O(scan_depth) RPCs regardless of n_txids. */
    char *hcnt = regtest_exec(rt, "getblockcount", "");
    if (!hcnt) return 1;
    int height = atoi(hcnt);
    free(hcnt);

    int depth = rt->scan_depth > 0 ? rt->scan_depth : 20;
    for (int blk = 0; blk < depth && blk <= height && n_remaining > 0; blk++) {
        char params[256];
        snprintf(params, sizeof(params), "%d", height - blk);
        char *hash_result = regtest_exec(rt, "getblockhash", params);
        if (!hash_result) continue;

        char blockhash[65];
        char *s = hash_result;
        while (*s == ' ' || *s == '\n' || *s == '"') s++;
        char *e = s + strlen(s) - 1;
        while (e > s && (*e == ' ' || *e == '\n' || *e == '"' || *e == '\r'))
            *e-- = '\0';
        strncpy(blockhash, s, 64);
        blockhash[64] = '\0';
        free(hash_result);

        /* getblock hash 1 — returns tx as array of txid strings, much lighter
           than verbosity 2 (no decoded script data needed here) */
        snprintf(params, sizeof(params), "\"%s\" 1", blockhash);
        char *blk_result = regtest_exec(rt, "getblock", params);
        if (!blk_result) continue;

        cJSON *block = cJSON_Parse(blk_result);
        free(blk_result);
        if (!block) continue;

        /* Use the block's own confirmations field for accuracy */
        int blk_confs = blk + 1;
        cJSON *conf_j = cJSON_GetObjectItem(block, "confirmations");
        if (conf_j && cJSON_IsNumber(conf_j))
            blk_confs = conf_j->valueint;

        cJSON *txs = cJSON_GetObjectItem(block, "tx");
        if (txs && cJSON_IsArray(txs)) {
            cJSON *txid_j = NULL;
            cJSON_ArrayForEach(txid_j, txs) {
                if (!cJSON_IsString(txid_j)) continue;
                const char *block_txid = txid_j->valuestring;
                for (size_t i = 0; i < n_txids; i++) {
                    if (confs_out[i] != -1) continue;
                    if (strcasecmp(block_txid, txids_hex[i]) == 0) {
                        confs_out[i] = blk_confs;
                        n_remaining--;
                    }
                }
            }
        }
        cJSON_Delete(block);
    }

    return 1;
}

bool regtest_is_in_mempool(regtest_t *rt, const char *txid) {
    char params[256];
    snprintf(params, sizeof(params), "\"%s\"", txid);
    char *result = regtest_exec(rt, "getmempoolentry", params);
    if (!result || result[0] == '\0') {
        free(result);
        return false;
    }

    bool in_mempool = (strstr(result, "error") == NULL);
    free(result);
    return in_mempool;
}

/* Parse a vout object from getrawtransaction or gettransaction decoded output. */
static int parse_vout_obj(cJSON *vout_obj,
                           uint64_t *amount_sats_out,
                           unsigned char *scriptpubkey_out, size_t *spk_len_out) {
    cJSON *value = cJSON_GetObjectItem(vout_obj, "value");
    if (value && cJSON_IsNumber(value))
        *amount_sats_out = (uint64_t)(value->valuedouble * 100000000.0 + 0.5);

    cJSON *spk = cJSON_GetObjectItem(vout_obj, "scriptPubKey");
    if (spk) {
        cJSON *hex = cJSON_GetObjectItem(spk, "hex");
        if (hex && cJSON_IsString(hex)) {
            int decoded = hex_decode(hex->valuestring, scriptpubkey_out, 256);
            if (decoded > 0)
                *spk_len_out = (size_t)decoded;
        }
    }
    return 1;
}

int regtest_get_tx_output(regtest_t *rt, const char *txid, uint32_t vout,
                          uint64_t *amount_sats_out,
                          unsigned char *scriptpubkey_out, size_t *spk_len_out) {
    char params[256];
    cJSON *json = NULL;
    cJSON *vouts = NULL;

    /* Try getrawtransaction first (works with -txindex or for mempool txs) */
    snprintf(params, sizeof(params), "\"%s\" true", txid);
    char *result = regtest_exec(rt, "getrawtransaction", params);
    if (result) {
        json = cJSON_Parse(result);
        free(result);
        if (json) {
            vouts = cJSON_GetObjectItem(json, "vout");
            if (vouts && cJSON_IsArray(vouts)) {
                cJSON *vout_obj = cJSON_GetArrayItem(vouts, (int)vout);
                if (vout_obj) {
                    int ok = parse_vout_obj(vout_obj, amount_sats_out,
                                             scriptpubkey_out, spk_len_out);
                    cJSON_Delete(json);
                    return ok;
                }
            }
            cJSON_Delete(json);
            json = NULL;
        }
    }

    /* Fallback: gettransaction with decode (wallet txs, no -txindex needed) */
    snprintf(params, sizeof(params), "\"%s\" true true", txid);
    result = regtest_exec(rt, "gettransaction", params);
    if (result) {
        json = cJSON_Parse(result);
        free(result);
        if (json) {
            cJSON *decoded = cJSON_GetObjectItem(json, "decoded");
            if (decoded) {
                vouts = cJSON_GetObjectItem(decoded, "vout");
                if (vouts && cJSON_IsArray(vouts)) {
                    cJSON *vout_obj = cJSON_GetArrayItem(vouts, (int)vout);
                    if (vout_obj) {
                        int ok = parse_vout_obj(vout_obj, amount_sats_out,
                                                 scriptpubkey_out, spk_len_out);
                        cJSON_Delete(json);
                        return ok;
                    }
                }
            }
            cJSON_Delete(json);
            json = NULL;
        }
    }

    /* Fallback: scan recent blocks with getrawtransaction + blockhash
       (works for non-wallet txs without -txindex) */
    result = regtest_exec(rt, "getblockcount", "");
    if (!result) return 0;
    int height = atoi(result);
    free(result);

    int depth = rt->scan_depth > 0 ? rt->scan_depth : 20;
    for (int i = 0; i < depth && i <= height; i++) {
        snprintf(params, sizeof(params), "%d", height - i);
        char *hash_result = regtest_exec(rt, "getblockhash", params);
        if (!hash_result) continue;

        char blockhash[65];
        char *s = hash_result;
        while (*s == ' ' || *s == '\n' || *s == '"') s++;
        char *e = s + strlen(s) - 1;
        while (e > s && (*e == ' ' || *e == '\n' || *e == '"' || *e == '\r'))
            *e-- = '\0';
        strncpy(blockhash, s, 64);
        blockhash[64] = '\0';
        free(hash_result);

        snprintf(params, sizeof(params), "\"%s\" true \"%s\"", txid, blockhash);
        result = regtest_exec(rt, "getrawtransaction", params);
        if (!result) continue;

        json = cJSON_Parse(result);
        free(result);
        if (!json) continue;

        vouts = cJSON_GetObjectItem(json, "vout");
        if (vouts && cJSON_IsArray(vouts)) {
            cJSON *vout_obj = cJSON_GetArrayItem(vouts, (int)vout);
            if (vout_obj) {
                int ok = parse_vout_obj(vout_obj, amount_sats_out,
                                         scriptpubkey_out, spk_len_out);
                cJSON_Delete(json);
                return ok;
            }
        }
        cJSON_Delete(json);
    }

    return 0;
}

int regtest_get_raw_tx(regtest_t *rt, const char *txid,
                         char *tx_hex_out, size_t max_len) {
    if (!rt || !txid || !tx_hex_out || max_len == 0) return 0;

    char params[256];
    snprintf(params, sizeof(params), "\"%s\"", txid);
    char *result = regtest_exec(rt, "getrawtransaction", params);
    if (!result) return 0;

    if (strstr(result, "error") != NULL) {
        free(result);
        return 0;
    }

    /* Trim whitespace/quotes */
    char *start = result;
    while (*start == '"' || *start == ' ' || *start == '\n') start++;
    char *end = start + strlen(start) - 1;
    while (end > start && (*end == '"' || *end == '\n' || *end == '\r' || *end == ' ')) {
        *end = '\0';
        end--;
    }

    size_t len = strlen(start);
    if (len == 0 || len >= max_len) {
        free(result);
        return 0;
    }

    strncpy(tx_hex_out, start, max_len - 1);
    tx_hex_out[max_len - 1] = '\0';
    free(result);
    return 1;
}

/* --- Shared faucet for regtest test suites --- */
static regtest_t g_faucet;
static char g_faucet_addr[128];
static int g_faucet_ready = 0;

int regtest_init_faucet(void) {
    if (g_faucet_ready) return 1;

    if (!regtest_init(&g_faucet)) return 0;

    if (!regtest_create_wallet(&g_faucet, "faucet")) {
        /* Wallet may already exist from a previous run — try loading */
        char *lr = regtest_exec(&g_faucet, "loadwallet", "\"faucet\"");
        if (lr) free(lr);
        strncpy(g_faucet.wallet, "faucet", sizeof(g_faucet.wallet) - 1);
    }

    if (!regtest_get_new_address(&g_faucet, g_faucet_addr, sizeof(g_faucet_addr)))
        return 0;

    /* Check if chain already has blocks (stale regtest, not wiped). */
    int height = regtest_get_block_height(&g_faucet);
    if (height > 1000) {
        fprintf(stderr, "WARNING: regtest chain at height %d — "
                "consider wiping (rm -rf ~/.bitcoin/regtest) for clean results\n",
                height);
    }

    /* Mine 200 blocks while subsidy is high.
       Blocks 0-149: 50 BTC each = 7,500 BTC
       Blocks 150-199: 25 BTC each = 1,250 BTC
       Total: ~8,750 BTC (only first 100 are spendable due to maturity). */
    if (!regtest_mine_blocks(&g_faucet, 200, g_faucet_addr))
        return 0;

    double bal = regtest_get_balance(&g_faucet);
    if (bal < 10.0) {
        fprintf(stderr, "WARNING: faucet balance %.4f BTC after init — "
                "subsidy may be exhausted (height %d). Wipe regtest.\n",
                bal, regtest_get_block_height(&g_faucet));
    }

    g_faucet_ready = 1;
    return 1;
}

int regtest_fund_from_faucet(regtest_t *rt, double amount) {
    if (!g_faucet_ready) return 0;

    /* Check faucet balance — try to replenish if running low */
    double bal = regtest_get_balance(&g_faucet);
    if (bal < amount + 1.0) {
        /* Try to mine more blocks to replenish */
        fprintf(stderr, "faucet: balance %.4f BTC low, mining 50 blocks to replenish\n", bal);
        regtest_mine_blocks(&g_faucet, 50, g_faucet_addr);
        bal = regtest_get_balance(&g_faucet);
        if (bal < amount) {
            fprintf(stderr, "faucet: EXHAUSTED (%.4f BTC < %.4f needed). "
                    "Wipe regtest: rm -rf ~/.bitcoin/regtest\n", bal, amount);
            return 0;
        }
    }

    /* Get new address in the target wallet */
    char addr[128];
    if (!regtest_get_new_address(rt, addr, sizeof(addr)))
        return 0;

    /* Send from faucet to target wallet */
    if (!regtest_fund_address(&g_faucet, addr, amount, NULL))
        return 0;

    /* Mine 1 block to confirm (to faucet address, keeps subsidy in faucet) */
    if (!regtest_mine_blocks(&g_faucet, 1, g_faucet_addr))
        return 0;

    return 1;
}

void regtest_faucet_health_report(void) {
    if (!g_faucet_ready) {
        printf("\n  [faucet] not initialized\n");
        return;
    }
    int height = regtest_get_block_height(&g_faucet);
    double bal = regtest_get_balance(&g_faucet);
    printf("\n  [faucet] height=%d  balance=%.4f BTC", height, bal);
    if (height > 2000)
        printf("  WARNING: chain getting tall, wipe before next run");
    if (bal < 50.0)
        printf("  WARNING: balance low, subsidy degrading");
    printf("\n");
}

double regtest_get_balance(regtest_t *rt) {
    char *result = regtest_exec(rt, "getbalance", "");
    if (!result) return -1.0;
    double bal = atof(result);
    free(result);
    return bal;
}

int regtest_wait_for_confirmation(regtest_t *rt, const char *txid,
                                    int timeout_secs) {
    if (!rt || !txid) return -1;

    int is_regtest = (strcmp(rt->network, "regtest") == 0);
    int interval = is_regtest ? 5 : 15;       /* initial poll interval */
    int max_interval = is_regtest ? 10 : 120;  /* cap */

    int elapsed = 0;
    while (elapsed < timeout_secs) {
        int conf = regtest_get_confirmations(rt, txid);
        if (conf >= 1) return conf;

        /* Also check mempool — tx exists but unconfirmed */
        if (conf < 0 && !regtest_is_in_mempool(rt, txid)) {
            fprintf(stderr, "regtest_wait_for_confirmation: tx %s not found\n", txid);
            return -1;
        }

        int height = regtest_get_block_height(rt);
        int mins = elapsed / 60;
        if (mins > 0)
            printf("  waiting for confirmation of %.16s... "
                   "(height=%d, %dm %ds / %ds)\n",
                   txid, height, mins, elapsed % 60, timeout_secs);
        else
            printf("  waiting for confirmation of %.16s... "
                   "(height=%d, %ds / %ds)\n",
                   txid, height, elapsed, timeout_secs);
        /* Stuck TX warning: if unconfirmed for >1 hour on non-regtest */
        if (!is_regtest && elapsed == 3600)
            fprintf(stderr, "  WARNING: TX %.16s... unconfirmed for 1 hour. "
                    "Consider CPFP bump: bitcoin-cli bumpfee %s\n", txid, txid);
        fflush(stdout);
        sleep(interval);
        elapsed += interval;
        /* Exponential backoff, capped */
        interval *= 2;
        if (interval > max_interval)
            interval = max_interval;
    }

    return -1;  /* timeout */
}

int regtest_get_utxo_for_bump(regtest_t *rt, uint64_t min_amount_sats,
                                char *txid_out, uint32_t *vout_out,
                                uint64_t *amount_out,
                                unsigned char *spk_out, size_t *spk_len_out) {
    if (!rt || !txid_out || !vout_out || !amount_out) return 0;

    char *result = regtest_exec(rt, "listunspent", "1 9999999");
    if (!result) return 0;

    cJSON *json = cJSON_Parse(result);
    free(result);
    if (!json || !cJSON_IsArray(json)) {
        if (json) cJSON_Delete(json);
        return 0;
    }

    double min_btc = (double)min_amount_sats / 100000000.0;
    int found = 0;

    int n = cJSON_GetArraySize(json);
    for (int i = 0; i < n; i++) {
        cJSON *utxo = cJSON_GetArrayItem(json, i);
        cJSON *amount = cJSON_GetObjectItem(utxo, "amount");
        if (!amount || !cJSON_IsNumber(amount)) continue;
        if (amount->valuedouble < min_btc) continue;

        cJSON *txid = cJSON_GetObjectItem(utxo, "txid");
        cJSON *vout = cJSON_GetObjectItem(utxo, "vout");
        if (!txid || !cJSON_IsString(txid) || !vout || !cJSON_IsNumber(vout))
            continue;

        strncpy(txid_out, txid->valuestring, 65);
        *vout_out = (uint32_t)vout->valueint;
        *amount_out = (uint64_t)(amount->valuedouble * 100000000.0 + 0.5);

        if (spk_out && spk_len_out) {
            cJSON *spk = cJSON_GetObjectItem(utxo, "scriptPubKey");
            if (spk && cJSON_IsString(spk)) {
                int decoded = hex_decode(spk->valuestring, spk_out, 64);
                if (decoded > 0)
                    *spk_len_out = (size_t)decoded;
            }
        }

        /* Lock the selected UTXO so concurrent callers don't pick the same
         * coin.  Released by regtest_release_utxo() after broadcast. */
        {
            char lp[160];
            snprintf(lp, sizeof(lp),
                     "false [{\"txid\":\"%s\",\"vout\":%u}]",
                     txid_out, *vout_out);
            char *lr = regtest_exec(rt, "lockunspent", lp);
            if (lr) free(lr);
        }

        found = 1;
        break;
    }

    cJSON_Delete(json);
    return found;
}

void regtest_release_utxo(regtest_t *rt, const char *txid_hex, uint32_t vout) {
    char params[160];
    snprintf(params, sizeof(params),
             "true [{\"txid\":\"%s\",\"vout\":%u}]", txid_hex, vout);
    char *r = regtest_exec(rt, "lockunspent", params);
    if (r) free(r);
}

int regtest_derive_p2tr_address(const regtest_t *rt,
                                const unsigned char *tweaked_ser32,
                                char *addr_out, size_t addr_len) {
    char tweaked_hex[65];
    hex_encode(tweaked_ser32, 32, tweaked_hex);

    /* Step 1: getdescriptorinfo "rawtr(HEX)" -> checksummed descriptor */
    char params[512];
    snprintf(params, sizeof(params), "\"rawtr(%s)\"", tweaked_hex);
    char *desc_result = regtest_exec(rt, "getdescriptorinfo", params);
    if (!desc_result) return 0;

    char checksummed_desc[256];
    char *dstart = strstr(desc_result, "\"descriptor\"");
    if (!dstart) { free(desc_result); return 0; }
    dstart = strchr(dstart + 12, '"');
    if (!dstart) { free(desc_result); return 0; }
    dstart++;
    char *dend = strchr(dstart, '"');
    if (!dend) { free(desc_result); return 0; }
    size_t dlen = (size_t)(dend - dstart);
    if (dlen >= sizeof(checksummed_desc)) { free(desc_result); return 0; }
    memcpy(checksummed_desc, dstart, dlen);
    checksummed_desc[dlen] = '\0';
    free(desc_result);

    /* Step 2: deriveaddresses "rawtr(HEX)#checksum" -> bech32m address */
    snprintf(params, sizeof(params), "\"%s\"", checksummed_desc);
    char *addr_result = regtest_exec(rt, "deriveaddresses", params);
    if (!addr_result) return 0;

    char *astart = strchr(addr_result, '"');
    if (!astart) { free(addr_result); return 0; }
    astart++;
    char *aend = strchr(astart, '"');
    if (!aend) { free(addr_result); return 0; }
    size_t alen = (size_t)(aend - astart);
    if (alen == 0 || alen >= addr_len) { free(addr_result); return 0; }
    memcpy(addr_out, astart, alen);
    addr_out[alen] = '\0';
    free(addr_result);

    return 1;
}

char *regtest_sign_raw_tx_with_wallet(regtest_t *rt, const char *unsigned_hex,
                                        const char *prevtxs_json,
                                        int require_complete) {
    if (!rt || !unsigned_hex) return NULL;

    char *params;
    if (prevtxs_json) {
        size_t plen = strlen(unsigned_hex) + strlen(prevtxs_json) + 16;
        params = (char *)malloc(plen);
        if (!params) return NULL;
        /* NOTE: Single-quote quoting relies on popen() invoking /bin/sh.
           This works on Linux and macOS. */
        snprintf(params, plen, "\"%s\" '%s'", unsigned_hex, prevtxs_json);
    } else {
        size_t plen = strlen(unsigned_hex) + 8;
        params = (char *)malloc(plen);
        if (!params) return NULL;
        snprintf(params, plen, "\"%s\"", unsigned_hex);
    }

    char *result = regtest_exec(rt, "signrawtransactionwithwallet", params);
    free(params);

    cJSON *json = cJSON_Parse(result);
    free(result);
    if (!json) { fprintf(stderr, "SIGN DEBUG: JSON parse failed\n"); return NULL; }

    cJSON *hex = cJSON_GetObjectItem(json, "hex");
    if (!hex || !cJSON_IsString(hex)) {
        fprintf(stderr, "SIGN DEBUG: no hex field\n");
        cJSON_Delete(json);
        return NULL;
    }

    /* Check that signing actually completed — if the wallet can't sign
       (wrong wallet, missing key), complete will be false.
       Skip this check when require_complete==0, e.g. CPFP transactions
       with a P2A anchor input (anyone-can-spend) that the wallet
       legitimately does not sign. */
    if (require_complete) {
        cJSON *complete = cJSON_GetObjectItem(json, "complete");
        if (!complete || !cJSON_IsTrue(complete)) {
            cJSON_Delete(json);
            return NULL;
        }
    }

    char *signed_hex = strdup(hex->valuestring);
    cJSON_Delete(json);
    return signed_hex;
}

/* --- UTXO coin selection (Mainnet Gap #1) --- */

#define DUST_THRESHOLD_SATS 546

int regtest_list_utxos(regtest_t *rt, utxo_t **utxos_out, size_t *n_out) {
    if (!rt || !utxos_out || !n_out) return 0;

    char *result = regtest_exec(rt, "listunspent", "1 9999999");
    if (!result) return 0;

    cJSON *json = cJSON_Parse(result);
    free(result);
    if (!json || !cJSON_IsArray(json)) {
        if (json) cJSON_Delete(json);
        return 0;
    }

    int n = cJSON_GetArraySize(json);
    if (n == 0) {
        cJSON_Delete(json);
        *utxos_out = NULL;
        *n_out = 0;
        return 1;
    }

    utxo_t *utxos = (utxo_t *)calloc((size_t)n, sizeof(utxo_t));
    if (!utxos) { cJSON_Delete(json); return 0; }

    size_t count = 0;
    for (int i = 0; i < n; i++) {
        cJSON *item = cJSON_GetArrayItem(json, i);
        cJSON *txid = cJSON_GetObjectItem(item, "txid");
        cJSON *vout = cJSON_GetObjectItem(item, "vout");
        cJSON *amount = cJSON_GetObjectItem(item, "amount");
        if (!txid || !cJSON_IsString(txid) || !vout || !cJSON_IsNumber(vout) ||
            !amount || !cJSON_IsNumber(amount))
            continue;

        strncpy(utxos[count].txid, txid->valuestring, 64);
        utxos[count].txid[64] = '\0';
        utxos[count].vout = vout->valueint;
        utxos[count].amount_sats = (uint64_t)(amount->valuedouble * 100000000.0 + 0.5);
        count++;
    }

    cJSON_Delete(json);
    *utxos_out = utxos;
    *n_out = count;
    return 1;
}

/* Sort comparator: descending by amount (largest first). */
static int utxo_cmp_desc(const void *a, const void *b) {
    const utxo_t *ua = (const utxo_t *)a;
    const utxo_t *ub = (const utxo_t *)b;
    if (ub->amount_sats > ua->amount_sats) return 1;
    if (ub->amount_sats < ua->amount_sats) return -1;
    return 0;
}

int regtest_coin_select(const utxo_t *utxos, size_t n_utxos,
                        uint64_t target_sats, uint64_t fee_rate_sat_vb,
                        utxo_t **selected_out, size_t *n_selected,
                        uint64_t *change_sats) {
    if (!utxos || !selected_out || !n_selected || !change_sats || n_utxos == 0)
        return 0;

    /* Copy + sort descending */
    utxo_t *sorted = (utxo_t *)malloc(n_utxos * sizeof(utxo_t));
    if (!sorted) return 0;
    memcpy(sorted, utxos, n_utxos * sizeof(utxo_t));
    qsort(sorted, n_utxos, sizeof(utxo_t), utxo_cmp_desc);

    /* Estimate fee: ~68 vB per input, ~43 vB per output, ~11 vB overhead.
       We assume 2 outputs (target + change). Adjust as inputs grow. */
    size_t sel_count = 0;
    uint64_t sel_total = 0;

    for (size_t i = 0; i < n_utxos; i++) {
        sel_count = i + 1;
        sel_total += sorted[i].amount_sats;

        /* Estimate fee for current number of inputs + 2 outputs */
        uint64_t est_vsize = 11 + sel_count * 68 + 2 * 43;
        uint64_t est_fee = est_vsize * fee_rate_sat_vb;

        if (sel_total >= target_sats + est_fee + DUST_THRESHOLD_SATS) {
            /* We have enough including change */
            uint64_t ch = sel_total - target_sats - est_fee;
            if (ch < DUST_THRESHOLD_SATS) {
                /* Change below dust: absorb into fee */
                ch = 0;
            }
            *change_sats = ch;
            *selected_out = (utxo_t *)malloc(sel_count * sizeof(utxo_t));
            if (!*selected_out) { free(sorted); return 0; }
            memcpy(*selected_out, sorted, sel_count * sizeof(utxo_t));
            *n_selected = sel_count;
            free(sorted);
            return 1;
        }

        if (sel_total >= target_sats + est_fee) {
            /* Enough without change (change would be dust) */
            *change_sats = 0;
            *selected_out = (utxo_t *)malloc(sel_count * sizeof(utxo_t));
            if (!*selected_out) { free(sorted); return 0; }
            memcpy(*selected_out, sorted, sel_count * sizeof(utxo_t));
            *n_selected = sel_count;
            free(sorted);
            return 1;
        }
    }

    /* Insufficient funds */
    free(sorted);
    return 0;
}

int regtest_create_funded_tx(regtest_t *rt, const tx_output_t *outputs,
                              size_t n_outputs, uint64_t fee_rate,
                              char *txid_hex_out, char *signed_hex_out,
                              size_t hex_max) {
    if (!rt || !outputs || n_outputs == 0) return 0;

    /* Calculate total target */
    uint64_t target = 0;
    for (size_t i = 0; i < n_outputs; i++)
        target += outputs[i].amount_sats;

    /* List UTXOs and select coins */
    utxo_t *all_utxos = NULL;
    size_t n_all = 0;
    if (!regtest_list_utxos(rt, &all_utxos, &n_all) || n_all == 0) {
        free(all_utxos);
        return 0;
    }

    utxo_t *selected = NULL;
    size_t n_sel = 0;
    uint64_t change = 0;
    if (!regtest_coin_select(all_utxos, n_all, target, fee_rate,
                              &selected, &n_sel, &change)) {
        free(all_utxos);
        return 0;
    }
    free(all_utxos);

    /* Build inputs JSON array */
    cJSON *inputs = cJSON_CreateArray();
    for (size_t i = 0; i < n_sel; i++) {
        cJSON *inp = cJSON_CreateObject();
        cJSON_AddStringToObject(inp, "txid", selected[i].txid);
        cJSON_AddNumberToObject(inp, "vout", selected[i].vout);
        cJSON_AddItemToArray(inputs, inp);
    }
    free(selected);

    /* Build outputs JSON array */
    cJSON *outs_json = cJSON_CreateArray();
    for (size_t i = 0; i < n_outputs; i++) {
        /* Get address from scriptPubKey */
        char spk_hex[69];
        hex_encode(outputs[i].script_pubkey, outputs[i].script_pubkey_len, spk_hex);

        cJSON *out = cJSON_CreateObject();
        /* Use scriptPubKey hex as key — createrawtransaction handles it via "data" */
        char amount_str[32];
        snprintf(amount_str, sizeof(amount_str), "%.8f",
                 (double)outputs[i].amount_sats / 100000000.0);
        /* For createrawtransaction, we need address:amount pairs.
           Fall back to "data" output if we can't derive address. */
        cJSON_AddStringToObject(out, "data", spk_hex);
        cJSON_AddItemToArray(outs_json, out);
    }

    /* Add change output if non-zero */
    if (change > 0) {
        char change_addr[128];
        if (regtest_get_new_address(rt, change_addr, sizeof(change_addr))) {
            cJSON *chg = cJSON_CreateObject();
            char chg_str[32];
            snprintf(chg_str, sizeof(chg_str), "%.8f",
                     (double)change / 100000000.0);
            cJSON_AddStringToObject(chg, change_addr, chg_str);
            cJSON_AddItemToArray(outs_json, chg);
        }
    }

    /* Call createrawtransaction */
    char *inputs_str = cJSON_PrintUnformatted(inputs);
    char *outs_str = cJSON_PrintUnformatted(outs_json);
    cJSON_Delete(inputs);
    cJSON_Delete(outs_json);

    char *params = (char *)malloc(strlen(inputs_str) + strlen(outs_str) + 16);
    if (!params) { free(inputs_str); free(outs_str); return 0; }
    sprintf(params, "'%s' '%s'", inputs_str, outs_str);
    free(inputs_str);
    free(outs_str);

    char *raw = regtest_exec(rt, "createrawtransaction", params);
    free(params);
    if (!raw) return 0;

    /* Strip whitespace/quotes */
    char *s = raw;
    while (*s == '"' || *s == ' ' || *s == '\n') s++;
    char *e = s + strlen(s) - 1;
    while (e > s && (*e == '"' || *e == ' ' || *e == '\n')) *e-- = '\0';

    /* Sign */
    char *signed_hex = regtest_sign_raw_tx_with_wallet(rt, s, NULL, 1);
    free(raw);
    if (!signed_hex) return 0;

    /* Copy signed hex out */
    if (signed_hex_out && hex_max > 0) {
        strncpy(signed_hex_out, signed_hex, hex_max - 1);
        signed_hex_out[hex_max - 1] = '\0';
    }

    /* Broadcast and get txid */
    char txid_buf[65];
    int ok = regtest_send_raw_tx(rt, signed_hex, txid_buf);
    free(signed_hex);

    if (ok && txid_hex_out)
        strncpy(txid_hex_out, txid_buf, 65);

    return ok;
}

/* --- RBF fee bumping (Mainnet Gap #2) --- */

int regtest_bump_fee(regtest_t *rt, const char *txid_hex,
                      uint64_t new_fee_rate_sat_vb) {
    if (!rt || !txid_hex) return 0;

    char params[256];
    snprintf(params, sizeof(params),
             "\"%s\" {\"fee_rate\": %llu}",
             txid_hex, (unsigned long long)new_fee_rate_sat_vb);

    char *result = regtest_exec(rt, "bumpfee", params);
    if (!result) return 0;

    /* Check for success: result should contain "txid" field */
    int ok = (strstr(result, "\"txid\"") != NULL);
    if (!ok)
        fprintf(stderr, "regtest_bump_fee: %s\n", result);
    free(result);
    return ok;
}

int regtest_wait_confirmed_with_bump(regtest_t *rt, const char *txid_hex,
                                      int target_blocks, int max_bumps,
                                      uint64_t initial_fee_rate,
                                      double fee_multiplier,
                                      int timeout_secs) {
    if (!rt || !txid_hex) return -1;

    int bumps_done = 0;
    uint64_t current_rate = initial_fee_rate;
    int start_height = regtest_get_block_height(rt);
    int elapsed = 0;
    int poll_interval = (strcmp(rt->network, "regtest") == 0) ? 5 : 30;

    while (elapsed < timeout_secs) {
        /* Check confirmation */
        int conf = regtest_get_confirmations(rt, txid_hex);
        if (conf >= 1) return conf;

        /* Check if enough blocks have passed for a bump */
        int current_height = regtest_get_block_height(rt);
        int blocks_passed = current_height - start_height;

        if (blocks_passed >= target_blocks && bumps_done < max_bumps) {
            current_rate = (uint64_t)((double)current_rate * fee_multiplier);
            printf("  Fee bump #%d: new rate %llu sat/vB\n",
                   bumps_done + 1, (unsigned long long)current_rate);

            if (regtest_bump_fee(rt, txid_hex, current_rate)) {
                bumps_done++;
                start_height = current_height; /* reset block counter */
            }
        }

        sleep(poll_interval);
        elapsed += poll_interval;
    }

    return -1; /* timeout */
}

/* -------------------------------------------------------------------------
 * BIP 157/158 filter helpers
 * ------------------------------------------------------------------------- */

int regtest_get_block_hash(regtest_t *rt, int height,
                            char *hash_out, size_t hash_out_len)
{
    char params[32];
    snprintf(params, sizeof(params), "%d", height);
    char *result = regtest_exec(rt, "getblockhash", params);
    if (!result) return 0;

    /* Strip surrounding quotes and whitespace */
    char *start = result;
    while (*start == '"' || *start == ' ' || *start == '\n') start++;
    char *end = start + strlen(start) - 1;
    while (end > start && (*end == '"' || *end == ' ' || *end == '\n'))
        *end-- = '\0';

    if (strlen(start) < 64) { free(result); return 0; }
    if (hash_out_len >= 65)
        strncpy(hash_out, start, 65);
    free(result);
    return 1;
}

int regtest_get_block_filter(regtest_t *rt, const char *block_hash,
                              unsigned char *filter_bytes_out,
                              size_t        *filter_len_out,
                              size_t         filter_max,
                              unsigned char  key_out[16])
{
    /* getblockfilter <hash> "basic" returns:
       {"filter":"<hex>","header":"<hex>"}  */
    char params[200];
    snprintf(params, sizeof(params), "\"%s\" \"basic\"", block_hash);
    char *result = regtest_exec(rt, "getblockfilter", params);
    if (!result) return 0;

    /* Parse "filter" field */
    const char *fp = strstr(result, "\"filter\"");
    if (!fp) { free(result); return 0; }
    fp = strchr(fp, ':');
    if (!fp) { free(result); return 0; }
    fp++;
    while (*fp == ' ' || *fp == '"') fp++;

    /* Decode hex into filter_bytes_out */
    size_t hex_len = 0;
    const char *p = fp;
    while (*p && *p != '"') { p++; hex_len++; }
    if (hex_len % 2 != 0 || hex_len / 2 > filter_max) {
        free(result);
        return 0;
    }
    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int byte;
        if (sscanf(fp + i * 2, "%02x", &byte) != 1) {
            free(result);
            return 0;
        }
        filter_bytes_out[i] = (unsigned char)byte;
    }
    *filter_len_out = hex_len / 2;
    free(result);

    /* Derive the 16-byte SipHash key: first 16 bytes of block hash
       (in internal byte order = reversed from display order) */
    if (key_out) {
        unsigned char block_hash_bytes[32];
        for (int i = 0; i < 32; i++) {
            unsigned int byte;
            sscanf(block_hash + (31 - i) * 2, "%02x", &byte);
            block_hash_bytes[i] = (unsigned char)byte;
        }
        memcpy(key_out, block_hash_bytes, 16);
    }

    return 1;
}

int regtest_scan_block_txs(regtest_t *rt, const char *block_hash,
                            regtest_tx_callback_t callback, void *ctx)
{
    /* getblock <hash> 2 returns full verbose JSON with decoded tx data */
    char params[200];
    snprintf(params, sizeof(params), "\"%s\" 2", block_hash);
    char *result = regtest_exec(rt, "getblock", params);
    if (!result) return -1;

    int tx_count = 0;

    /* Walk through each "txid" field and the following "vout" array.
       Parsing with cJSON for correctness. */
    cJSON *block = cJSON_Parse(result);
    free(result);
    if (!block) return -1;

    cJSON *txs = cJSON_GetObjectItem(block, "tx");
    if (!txs || !cJSON_IsArray(txs)) { cJSON_Delete(block); return -1; }

    cJSON *tx = NULL;
    cJSON_ArrayForEach(tx, txs) {
        cJSON *txid_json = cJSON_GetObjectItem(tx, "txid");
        if (!txid_json || !cJSON_IsString(txid_json)) continue;
        const char *txid_hex = txid_json->valuestring;

        cJSON *vout = cJSON_GetObjectItem(tx, "vout");
        if (!vout || !cJSON_IsArray(vout)) continue;

        int n_out = cJSON_GetArraySize(vout);
        if (n_out <= 0) continue;

        /* Collect scriptPubKeys */
        const unsigned char **spks  = calloc(n_out, sizeof(unsigned char *));
        size_t              *lens   = calloc(n_out, sizeof(size_t));
        unsigned char      **bufs   = calloc(n_out, sizeof(unsigned char *));
        if (!spks || !lens || !bufs) {
            free(spks); free(lens); free(bufs);
            continue;
        }

        int valid = 1;
        for (int i = 0; i < n_out && valid; i++) {
            cJSON *out   = cJSON_GetArrayItem(vout, i);
            cJSON *spk_j = cJSON_GetObjectItem(out, "scriptPubKey");
            cJSON *hex_j = spk_j ? cJSON_GetObjectItem(spk_j, "hex") : NULL;
            if (!hex_j || !cJSON_IsString(hex_j)) { valid = 0; break; }

            const char *hex = hex_j->valuestring;
            size_t hlen = strlen(hex);
            if (hlen % 2 != 0) { valid = 0; break; }

            bufs[i] = malloc(hlen / 2);
            if (!bufs[i]) { valid = 0; break; }
            for (size_t j = 0; j < hlen / 2; j++) {
                unsigned int byte;
                sscanf(hex + j * 2, "%02x", &byte);
                bufs[i][j] = (unsigned char)byte;
            }
            spks[i] = bufs[i];
            lens[i] = hlen / 2;
        }

        if (valid && callback)
            callback(txid_hex, (size_t)n_out, spks, lens, ctx);

        for (int i = 0; i < n_out; i++) free(bufs[i]);
        free(spks); free(lens); free(bufs);

        tx_count++;
    }

    cJSON_Delete(block);
    return tx_count;
}
