#include "superscalar/bridge.h"
#include <secp256k1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <time.h>

void bridge_init(bridge_t *br) {
    memset(br, 0, sizeof(*br));
    br->lsp_fd = -1;
    br->plugin_listen_fd = -1;
    br->plugin_fd = -1;
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
    cJSON *hello = wire_build_bridge_hello();
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

int bridge_listen_plugin(bridge_t *br, int plugin_port) {
    br->plugin_listen_fd = wire_listen(NULL, plugin_port);
    if (br->plugin_listen_fd < 0) {
        fprintf(stderr, "Bridge: failed to listen on port %d\n", plugin_port);
        return 0;
    }
    printf("Bridge: listening for plugin on port %d\n", plugin_port);
    return 1;
}

int bridge_accept_plugin(bridge_t *br) {
    br->plugin_fd = wire_accept(br->plugin_listen_fd);
    if (br->plugin_fd < 0) {
        fprintf(stderr, "Bridge: failed to accept plugin\n");
        return 0;
    }
    printf("Bridge: plugin connected\n");
    return 1;
}

uint64_t bridge_add_pending(bridge_t *br, const unsigned char *payment_hash32) {
    if (br->n_pending >= BRIDGE_MAX_PENDING) return 0;

    size_t idx = br->n_pending++;
    memcpy(br->pending_inbound[idx].payment_hash, payment_hash32, 32);
    br->pending_inbound[idx].htlc_id = br->next_htlc_id++;
    br->pending_inbound[idx].pending = 1;
    return br->pending_inbound[idx].htlc_id;
}

int bridge_resolve_pending(bridge_t *br, const unsigned char *payment_hash32,
                             uint64_t *htlc_id_out) {
    for (size_t i = 0; i < br->n_pending; i++) {
        if (!br->pending_inbound[i].pending) continue;
        if (memcmp(br->pending_inbound[i].payment_hash, payment_hash32, 32) == 0) {
            *htlc_id_out = br->pending_inbound[i].htlc_id;
            br->pending_inbound[i].pending = 0;
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

/* Read one newline-delimited line from plugin_fd */
char *bridge_read_plugin_line(bridge_t *br) {
    if (br->plugin_fd < 0) return NULL;

    size_t cap = 4096;
    size_t len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;

    while (1) {
        char c;
        ssize_t n = read(br->plugin_fd, &c, 1);
        if (n <= 0) {
            free(buf);
            return NULL;
        }
        if (c == '\n') break;
        if (len + 1 >= cap) {
            cap *= 2;
            char *tmp = (char *)realloc(buf, cap);
            if (!tmp) { free(buf); return NULL; }
            buf = tmp;
        }
        buf[len++] = c;
    }
    buf[len] = '\0';
    return buf;
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

        /* Forward to plugin */
        cJSON *j = cJSON_CreateObject();
        cJSON_AddStringToObject(j, "method", "htlc_resolve");
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

        cJSON *j = cJSON_CreateObject();
        cJSON_AddStringToObject(j, "method", "htlc_resolve");
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
        uint64_t request_id;
        if (!wire_parse_bridge_send_pay(msg->json, bolt11, sizeof(bolt11),
                                          payment_hash, &request_id))
            return 0;

        cJSON *j = cJSON_CreateObject();
        cJSON_AddStringToObject(j, "method", "pay_request");
        cJSON_AddStringToObject(j, "bolt11", bolt11);
        cJSON_AddNumberToObject(j, "request_id", (double)request_id);
        int ok = bridge_send_plugin_json(br, j);
        cJSON_Delete(j);
        return ok;
    }

    case MSG_BRIDGE_REGISTER: {
        unsigned char payment_hash[32];
        uint64_t amount_msat;
        size_t dest_client;
        if (!wire_parse_bridge_register(msg->json, payment_hash,
                                          &amount_msat, &dest_client))
            return 0;

        cJSON *j = cJSON_CreateObject();
        cJSON_AddStringToObject(j, "method", "invoice_registered");
        wire_json_add_hex(j, "payment_hash", payment_hash, 32);
        cJSON_AddNumberToObject(j, "amount_msat", (double)amount_msat);
        cJSON_AddNumberToObject(j, "dest_client", (double)dest_client);
        int ok = bridge_send_plugin_json(br, j);
        cJSON_Delete(j);
        return ok;
    }

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

        /* Assign htlc_id and track */
        uint64_t htlc_id = bridge_add_pending(br, payment_hash);

        /* Forward to LSP */
        cJSON *msg = wire_build_bridge_add_htlc(payment_hash, amount_msat,
                                                  cltv_expiry, htlc_id);
        int ok = wire_send(br->lsp_fd, MSG_BRIDGE_ADD_HTLC, msg);
        cJSON_Delete(msg);
        cJSON_Delete(json);
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
        if (success)
            wire_json_get_hex(json, "preimage", preimage, 32);

        cJSON *msg = wire_build_bridge_pay_result(request_id, success,
                                                    success ? preimage : NULL);
        int ok = wire_send(br->lsp_fd, MSG_BRIDGE_PAY_RESULT, msg);
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
        } else if (br->plugin_listen_fd >= 0) {
            FD_SET(br->plugin_listen_fd, &rfds);
            if (br->plugin_listen_fd > max_fd) max_fd = br->plugin_listen_fd;
        }

        /* Use heartbeat interval as select timeout (or 60s if no heartbeat) */
        int timeout_sec = (br->heartbeat_interval > 0) ? br->heartbeat_interval : 60;
        struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };
        int ret = select(max_fd + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) {
            perror("Bridge: select");
            return 0;
        }

        /* Heartbeat: check for stale LSP connection on timeout */
        if (ret == 0) {
            if (bridge_is_stale(br)) {
                fprintf(stderr, "Bridge: LSP connection stale, sending ping\n");
                cJSON *ping = wire_build_bridge_hello();
                if (!wire_send(br->lsp_fd, MSG_BRIDGE_HELLO, ping)) {
                    cJSON_Delete(ping);
                    fprintf(stderr, "Bridge: ping failed, attempting reconnect\n");
                    if (!bridge_reconnect_lsp(br))
                        return 0;
                } else {
                    cJSON_Delete(ping);
                }
            }
            continue;
        }

        /* Accept pending plugin connection */
        if (br->plugin_listen_fd >= 0 && br->plugin_fd < 0 &&
            FD_ISSET(br->plugin_listen_fd, &rfds)) {
            bridge_accept_plugin(br);
        }

        /* Handle LSP messages */
        if (FD_ISSET(br->lsp_fd, &rfds)) {
            wire_msg_t msg;
            if (!wire_recv(br->lsp_fd, &msg)) {
                fprintf(stderr, "Bridge: LSP connection lost\n");
                /* Attempt reconnect */
                if (bridge_reconnect_lsp(br))
                    continue;
                return 0;
            }
            br->last_lsp_activity = time(NULL);
            if (!bridge_handle_lsp_msg(br, &msg)) {
                cJSON_Delete(msg.json);
                return 0;
            }
            cJSON_Delete(msg.json);
        }

        /* Handle plugin messages */
        if (br->plugin_fd >= 0 && FD_ISSET(br->plugin_fd, &rfds)) {
            char *line = bridge_read_plugin_line(br);
            if (!line) {
                fprintf(stderr, "Bridge: plugin connection lost\n");
                wire_close(br->plugin_fd);
                br->plugin_fd = -1;
                continue;
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
    if (br->plugin_listen_fd >= 0) wire_close(br->plugin_listen_fd);
    br->lsp_fd = -1;
    br->plugin_fd = -1;
    br->plugin_listen_fd = -1;
}
