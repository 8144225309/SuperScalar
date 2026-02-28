#include "superscalar/wire.h"
#include "superscalar/factory.h"
#include "superscalar/noise.h"
#include "superscalar/crypto_aead.h"
#include "superscalar/types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

/* --- Wire message logging (Phase 22) --- */

static wire_log_callback_t g_wire_log_cb = NULL;
static void *g_wire_log_ud = NULL;

#define WIRE_MAX_FDS 32
static struct { int fd; char label[32]; } g_peer_labels[WIRE_MAX_FDS];
static size_t g_n_peer_labels = 0;

void wire_set_log_callback(wire_log_callback_t cb, void *userdata) {
    g_wire_log_cb = cb;
    g_wire_log_ud = userdata;
}

void wire_set_peer_label(int fd, const char *label) {
    /* Update existing entry if fd already registered */
    for (size_t i = 0; i < g_n_peer_labels; i++) {
        if (g_peer_labels[i].fd == fd) {
            strncpy(g_peer_labels[i].label, label, sizeof(g_peer_labels[i].label) - 1);
            g_peer_labels[i].label[sizeof(g_peer_labels[i].label) - 1] = '\0';
            return;
        }
    }
    if (g_n_peer_labels < WIRE_MAX_FDS) {
        g_peer_labels[g_n_peer_labels].fd = fd;
        strncpy(g_peer_labels[g_n_peer_labels].label, label,
                sizeof(g_peer_labels[g_n_peer_labels].label) - 1);
        g_peer_labels[g_n_peer_labels].label[sizeof(g_peer_labels[g_n_peer_labels].label) - 1] = '\0';
        g_n_peer_labels++;
    }
}

static const char *wire_get_peer_label(int fd) {
    for (size_t i = 0; i < g_n_peer_labels; i++) {
        if (g_peer_labels[i].fd == fd)
            return g_peer_labels[i].label;
    }
    return "unknown";
}

const char *wire_msg_type_name(uint8_t type) {
    switch (type) {
    case 0x01: return "HELLO";
    case 0x02: return "HELLO_ACK";
    case 0x10: return "FACTORY_PROPOSE";
    case 0x11: return "NONCE_BUNDLE";
    case 0x12: return "ALL_NONCES";
    case 0x13: return "PSIG_BUNDLE";
    case 0x14: return "FACTORY_READY";
    case 0x20: return "CLOSE_PROPOSE";
    case 0x21: return "CLOSE_NONCE";
    case 0x22: return "CLOSE_ALL_NONCES";
    case 0x23: return "CLOSE_PSIG";
    case 0x24: return "CLOSE_DONE";
    case 0x30: return "CHANNEL_READY";
    case 0x31: return "UPDATE_ADD_HTLC";
    case 0x32: return "COMMITMENT_SIGNED";
    case 0x33: return "REVOKE_AND_ACK";
    case 0x34: return "UPDATE_FULFILL_HTLC";
    case 0x35: return "UPDATE_FAIL_HTLC";
    case 0x36: return "CLOSE_REQUEST";
    case 0x37: return "CHANNEL_NONCES";
    case 0x38: return "REGISTER_INVOICE";
    case 0x40: return "BRIDGE_HELLO";
    case 0x41: return "BRIDGE_HELLO_ACK";
    case 0x42: return "BRIDGE_ADD_HTLC";
    case 0x43: return "BRIDGE_FULFILL_HTLC";
    case 0x44: return "BRIDGE_FAIL_HTLC";
    case 0x45: return "BRIDGE_SEND_PAY";
    case 0x46: return "BRIDGE_PAY_RESULT";
    case 0x47: return "BRIDGE_REGISTER";
    case 0x48: return "RECONNECT";
    case 0x49: return "RECONNECT_ACK";
    case 0x4A: return "CREATE_INVOICE";
    case 0x4B: return "INVOICE_CREATED";
    case 0x4C: return "PTLC_PRESIG";
    case 0x4D: return "PTLC_ADAPTED_SIG";
    case 0x4E: return "PTLC_COMPLETE";
    case 0x4F: return "CHANNEL_BASEPOINTS";
    case 0x50: return "LSP_REVOKE_AND_ACK";
    case 0x51: return "JIT_OFFER";
    case 0x60: return "PATH_NONCE_BUNDLE";
    case 0x61: return "PATH_ALL_NONCES";
    case 0x62: return "PATH_PSIG_BUNDLE";
    case 0x63: return "PATH_SIGN_DONE";
    case 0x52: return "JIT_ACCEPT";
    case 0x53: return "JIT_READY";
    case 0x54: return "JIT_MIGRATE";
    case 0x55: return "EPOCH_RESET_PROPOSE";
    case 0x56: return "EPOCH_RESET_PSIG";
    case 0x57: return "EPOCH_RESET_DONE";
    case 0x58: return "LEAF_ADVANCE_PROPOSE";
    case 0x59: return "LEAF_ADVANCE_PSIG";
    case 0x5A: return "LEAF_ADVANCE_DONE";
    case 0xFF: return "ERROR";
    default:   return "UNKNOWN";
    }
}

/* --- TCP transport --- */

int wire_listen(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (host && host[0])
        inet_pton(AF_INET, host, &addr.sin_addr);
    else
        addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int wire_accept(int listen_fd) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int fd = accept(listen_fd, (struct sockaddr *)&addr, &len);
    if (fd >= 0)
        wire_set_timeout(fd, WIRE_DEFAULT_TIMEOUT_SEC);
    return fd;
}

/* Global SOCKS5 proxy state (set via wire_set_proxy) */
static char g_proxy_host[256] = {0};
static int g_proxy_port = 0;
static int g_proxy_set = 0;

/* Tor-only mode: refuse all clearnet connections */
static int g_tor_only = 0;

void wire_set_tor_only(int enable) {
    g_tor_only = enable;
}

int wire_get_tor_only(void) {
    return g_tor_only;
}

void wire_set_proxy(const char *host, int port) {
    if (host && port > 0) {
        strncpy(g_proxy_host, host, sizeof(g_proxy_host) - 1);
        g_proxy_host[sizeof(g_proxy_host) - 1] = '\0';
        g_proxy_port = port;
        g_proxy_set = 1;
    } else {
        g_proxy_set = 0;
    }
}

int wire_get_proxy(char *host_out, size_t host_len, int *port_out) {
    if (!g_proxy_set) return 0;
    if (host_out && host_len > 0) {
        strncpy(host_out, g_proxy_host, host_len - 1);
        host_out[host_len - 1] = '\0';
    }
    if (port_out) *port_out = g_proxy_port;
    return 1;
}

/* Direct TCP connection via getaddrinfo (supports hostnames + IPv6) */
int wire_connect_direct_internal(const char *host, int port) {
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host ? host : "127.0.0.1", port_str, &hints, &res) != 0)
        return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    if (connect(fd, res->ai_addr, (socklen_t)res->ai_addrlen) < 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    wire_set_timeout(fd, WIRE_DEFAULT_TIMEOUT_SEC);
    return fd;
}

int wire_connect(const char *host, int port) {
    const char *h = host ? host : "127.0.0.1";
    size_t hlen = strlen(h);
    int is_onion = (hlen >= 6 && strcmp(h + hlen - 6, ".onion") == 0);

    /* Tor-only mode: refuse clearnet connections */
    if (g_tor_only && !is_onion) {
        fprintf(stderr, "wire_connect: --tor-only refuses clearnet "
                        "connection to %s:%d\n", h, port);
        return -1;
    }

    /* Safety: refuse .onion without proxy (prevents DNS leak) */
    if (is_onion) {
        if (!g_proxy_set) {
            fprintf(stderr, "wire_connect: .onion address requires --tor-proxy (refusing to prevent DNS leak)\n");
            return -1;
        }
        /* Route through SOCKS5 proxy */
        return wire_connect_via_proxy(h, port, g_proxy_host, g_proxy_port);
    }

    /* If proxy is set, route all connections through it */
    if (g_proxy_set)
        return wire_connect_via_proxy(h, port, g_proxy_host, g_proxy_port);

    return wire_connect_direct_internal(h, port);
}

void wire_close(int fd) {
    if (fd >= 0) {
        wire_clear_encryption(fd);
        close(fd);
    }
}

int wire_set_timeout(int fd, int timeout_sec) {
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return 1;
}

/* --- Low-level I/O --- */

static int write_all(int fd, const unsigned char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n <= 0) return 0;
        sent += (size_t)n;
    }
    return 1;
}

static int read_all(int fd, unsigned char *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) return 0;
        got += (size_t)n;
    }
    return 1;
}

/* --- Framing --- */

/* Build 12-byte nonce from 8-byte LE counter: [4 zero bytes][8-byte LE seq] */
static void make_nonce(unsigned char nonce[12], uint64_t seq) {
    memset(nonce, 0, 4);
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (unsigned char)(seq & 0xff);
        seq >>= 8;
    }
}

int wire_send(int fd, uint8_t msg_type, cJSON *json) {
    char *payload = cJSON_PrintUnformatted(json);
    if (!payload) return 0;

    uint32_t payload_len = (uint32_t)strlen(payload);
    uint32_t pt_len = 1 + payload_len;  /* type byte + JSON */

    noise_state_t *ns = wire_get_encryption(fd);
    if (ns) {
        /* Encrypt: plaintext = [type][JSON] */
        unsigned char *plaintext = (unsigned char *)malloc(pt_len);
        if (!plaintext) { free(payload); return 0; }
        plaintext[0] = msg_type;
        memcpy(plaintext + 1, payload, payload_len);
        free(payload);

        unsigned char *ciphertext = (unsigned char *)malloc(pt_len);
        unsigned char tag[16];
        if (!ciphertext) { free(plaintext); return 0; }

        unsigned char nonce[12];
        make_nonce(nonce, ns->send_nonce);

        if (!aead_encrypt(ciphertext, tag, plaintext, pt_len,
                          NULL, 0, ns->send_key, nonce)) {
            free(plaintext);
            free(ciphertext);
            return 0;
        }
        free(plaintext);

        /* Write: [4-byte len = pt_len + 16][ciphertext][tag] */
        uint32_t frame_len = pt_len + 16;
        unsigned char header[4];
        header[0] = (unsigned char)(frame_len >> 24);
        header[1] = (unsigned char)(frame_len >> 16);
        header[2] = (unsigned char)(frame_len >> 8);
        header[3] = (unsigned char)(frame_len);

        int ok = write_all(fd, header, 4) &&
                 write_all(fd, ciphertext, pt_len) &&
                 write_all(fd, tag, 16);
        free(ciphertext);
        if (!ok) return 0;

        /* Increment nonce only after successful transmission */
        ns->send_nonce++;
        if (g_wire_log_cb)
            g_wire_log_cb(0, msg_type, json, wire_get_peer_label(fd), g_wire_log_ud);
        return 1;
    }

    /* Refuse plaintext if encryption was established on this fd */
    if (wire_is_encryption_required(fd)) {
        free(payload);
        return 0;
    }

    /* Plaintext path (no encryption, no prior handshake) */
    uint32_t frame_len = pt_len;
    unsigned char header[5];
    header[0] = (unsigned char)(frame_len >> 24);
    header[1] = (unsigned char)(frame_len >> 16);
    header[2] = (unsigned char)(frame_len >> 8);
    header[3] = (unsigned char)(frame_len);
    header[4] = msg_type;

    int ok = write_all(fd, header, 5) &&
             write_all(fd, (unsigned char *)payload, payload_len);
    free(payload);
    if (ok && g_wire_log_cb)
        g_wire_log_cb(0, msg_type, json, wire_get_peer_label(fd), g_wire_log_ud);
    return ok;
}

int wire_recv(int fd, wire_msg_t *msg) {
    msg->json = NULL;
    unsigned char header[4];
    if (!read_all(fd, header, 4)) return 0;

    uint32_t frame_len = ((uint32_t)header[0] << 24) |
                          ((uint32_t)header[1] << 16) |
                          ((uint32_t)header[2] << 8) |
                          ((uint32_t)header[3]);
    if (frame_len < 1 || frame_len > WIRE_MAX_FRAME_SIZE) return 0;

    noise_state_t *ns = wire_get_encryption(fd);
    if (ns) {
        /* Encrypted: frame_len includes 16-byte tag */
        if (frame_len < 17) return 0;  /* at least 1 byte pt + 16 tag */
        uint32_t ct_len = frame_len - 16;

        unsigned char *ct_and_tag = (unsigned char *)malloc(frame_len);
        if (!ct_and_tag) return 0;
        if (!read_all(fd, ct_and_tag, frame_len)) {
            free(ct_and_tag);
            return 0;
        }

        unsigned char *ciphertext = ct_and_tag;
        unsigned char *tag = ct_and_tag + ct_len;

        unsigned char *plaintext = (unsigned char *)malloc(ct_len);
        if (!plaintext) { free(ct_and_tag); return 0; }

        unsigned char nonce[12];
        make_nonce(nonce, ns->recv_nonce);

        if (!aead_decrypt(plaintext, ciphertext, ct_len, tag,
                          NULL, 0, ns->recv_key, nonce)) {
            free(ct_and_tag);
            free(plaintext);
            return 0;
        }
        free(ct_and_tag);
        ns->recv_nonce++;

        msg->msg_type = plaintext[0];
        uint32_t json_len = ct_len - 1;
        char *buf = (char *)malloc(json_len + 1);
        if (!buf) { free(plaintext); return 0; }
        memcpy(buf, plaintext + 1, json_len);
        buf[json_len] = '\0';
        free(plaintext);

        msg->json = cJSON_Parse(buf);
        free(buf);
        if (msg->json && g_wire_log_cb)
            g_wire_log_cb(1, msg->msg_type, msg->json, wire_get_peer_label(fd), g_wire_log_ud);
        return msg->json ? 1 : 0;
    }

    /* Refuse plaintext if encryption was established on this fd */
    if (wire_is_encryption_required(fd))
        return 0;

    /* Plaintext path (no encryption, no prior handshake) */
    unsigned char type_byte;
    if (!read_all(fd, &type_byte, 1)) return 0;
    msg->msg_type = type_byte;

    uint32_t json_len = frame_len - 1;
    char *buf = (char *)malloc(json_len + 1);
    if (!buf) return 0;

    if (!read_all(fd, (unsigned char *)buf, json_len)) {
        free(buf);
        return 0;
    }
    buf[json_len] = '\0';

    msg->json = cJSON_Parse(buf);
    free(buf);
    if (msg->json && g_wire_log_cb)
        g_wire_log_cb(1, msg->msg_type, msg->json, wire_get_peer_label(fd), g_wire_log_ud);
    return msg->json ? 1 : 0;
}

int wire_recv_timeout(int fd, wire_msg_t *msg, int timeout_sec) {
    wire_set_timeout(fd, timeout_sec);
    int ok = wire_recv(fd, msg);
    wire_set_timeout(fd, WIRE_DEFAULT_TIMEOUT_SEC);
    return ok;
}

/* --- Crypto JSON helpers --- */

void wire_json_add_hex(cJSON *obj, const char *key,
                       const unsigned char *data, size_t len) {
    char *hex = (char *)malloc(len * 2 + 1);
    if (!hex) return;
    hex_encode(data, len, hex);
    cJSON_AddStringToObject(obj, key, hex);
    free(hex);
}

int wire_json_get_hex(const cJSON *obj, const char *key,
                      unsigned char *out, size_t max_len) {
    cJSON *item = cJSON_GetObjectItem(obj, key);
    if (!item || !cJSON_IsString(item)) return 0;
    return hex_decode(item->valuestring, out, max_len);
}

/* --- Pubkey serialization helpers --- */

static void pubkey_to_hex(const secp256k1_context *ctx,
                          const secp256k1_pubkey *pk, char *hex_out) {
    unsigned char buf[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, buf, &len, pk, SECP256K1_EC_COMPRESSED);
    hex_encode(buf, 33, hex_out);
}

static int hex_to_pubkey(const secp256k1_context *ctx,
                         secp256k1_pubkey *pk, const char *hex) {
    unsigned char buf[33];
    if (hex_decode(hex, buf, 33) != 33) return 0;
    return secp256k1_ec_pubkey_parse(ctx, pk, buf, 33);
}

/* --- Bundle helper: build JSON array from entries --- */

static cJSON *build_bundle_array(const wire_bundle_entry_t *entries, size_t n) {
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < n; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, "node_idx", entries[i].node_idx);
        cJSON_AddNumberToObject(item, "slot", entries[i].signer_slot);
        wire_json_add_hex(item, "data", entries[i].data, entries[i].data_len);
        cJSON_AddItemToArray(arr, item);
    }
    return arr;
}

/* --- Message builders --- */

cJSON *wire_build_hello(const secp256k1_context *ctx,
                        const secp256k1_pubkey *pubkey) {
    cJSON *j = cJSON_CreateObject();
    char hex[67];
    pubkey_to_hex(ctx, pubkey, hex);
    cJSON_AddStringToObject(j, "pubkey", hex);
    return j;
}

cJSON *wire_build_hello_ack(const secp256k1_context *ctx,
                            const secp256k1_pubkey *lsp_pubkey,
                            uint32_t participant_index,
                            const secp256k1_pubkey *all_pubkeys, size_t n) {
    cJSON *j = cJSON_CreateObject();
    char hex[67];
    pubkey_to_hex(ctx, lsp_pubkey, hex);
    cJSON_AddStringToObject(j, "lsp_pubkey", hex);
    cJSON_AddNumberToObject(j, "participant_index", participant_index);

    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < n; i++) {
        pubkey_to_hex(ctx, &all_pubkeys[i], hex);
        cJSON_AddItemToArray(arr, cJSON_CreateString(hex));
    }
    cJSON_AddItemToObject(j, "all_pubkeys", arr);
    return j;
}

cJSON *wire_build_factory_propose(const factory_t *f) {
    cJSON *j = cJSON_CreateObject();

    /* Funding txid in display order */
    unsigned char display_txid[32];
    memcpy(display_txid, f->funding_txid, 32);
    reverse_bytes(display_txid, 32);
    wire_json_add_hex(j, "funding_txid", display_txid, 32);

    cJSON_AddNumberToObject(j, "funding_vout", f->funding_vout);
    cJSON_AddNumberToObject(j, "funding_amount", (double)f->funding_amount_sats);
    wire_json_add_hex(j, "funding_spk", f->funding_spk, f->funding_spk_len);
    cJSON_AddNumberToObject(j, "step_blocks", f->step_blocks);
    cJSON_AddNumberToObject(j, "states_per_layer", f->states_per_layer);
    cJSON_AddNumberToObject(j, "cltv_timeout", f->cltv_timeout);
    cJSON_AddNumberToObject(j, "fee_per_tx", (double)f->fee_per_tx);
    cJSON_AddNumberToObject(j, "leaf_arity", (double)f->leaf_arity);
    cJSON_AddNumberToObject(j, "placement_mode", (double)f->placement_mode);
    cJSON_AddNumberToObject(j, "economic_mode", (double)f->economic_mode);

    /* Participant profiles */
    cJSON *profiles = cJSON_CreateArray();
    for (size_t i = 0; i < f->n_participants; i++) {
        const participant_profile_t *p = &f->profiles[i];
        cJSON *item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, "idx", p->participant_idx);
        cJSON_AddNumberToObject(item, "contribution", (double)p->contribution_sats);
        cJSON_AddNumberToObject(item, "profit_bps", p->profit_share_bps);
        cJSON_AddNumberToObject(item, "uptime", (double)p->uptime_score);
        cJSON_AddNumberToObject(item, "tz_bucket", p->timezone_bucket);
        cJSON_AddItemToArray(profiles, item);
    }
    cJSON_AddItemToObject(j, "profiles", profiles);
    return j;
}

cJSON *wire_build_nonce_bundle(const wire_bundle_entry_t *entries, size_t n) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddItemToObject(j, "entries", build_bundle_array(entries, n));
    return j;
}

cJSON *wire_build_all_nonces(const wire_bundle_entry_t *entries, size_t n) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddItemToObject(j, "nonces", build_bundle_array(entries, n));
    return j;
}

cJSON *wire_build_psig_bundle(const wire_bundle_entry_t *entries, size_t n) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddItemToObject(j, "entries", build_bundle_array(entries, n));
    return j;
}

cJSON *wire_build_factory_ready(const factory_t *f) {
    cJSON *j = cJSON_CreateObject();
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < f->n_nodes; i++) {
        if (!f->nodes[i].is_signed) continue;
        cJSON *item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, "node_idx", (double)i);
        wire_json_add_hex(item, "tx_hex",
                          f->nodes[i].signed_tx.data,
                          f->nodes[i].signed_tx.len);
        cJSON_AddItemToArray(arr, item);
    }
    cJSON_AddItemToObject(j, "signed_txs", arr);
    return j;
}

cJSON *wire_build_close_propose(const tx_output_t *outputs, size_t n) {
    cJSON *j = cJSON_CreateObject();
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < n; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, "amount", (double)outputs[i].amount_sats);
        wire_json_add_hex(item, "spk", outputs[i].script_pubkey,
                          outputs[i].script_pubkey_len);
        cJSON_AddItemToArray(arr, item);
    }
    cJSON_AddItemToObject(j, "outputs", arr);
    return j;
}

cJSON *wire_build_close_nonce(const unsigned char *pubnonce66) {
    cJSON *j = cJSON_CreateObject();
    wire_json_add_hex(j, "pubnonce", pubnonce66, 66);
    return j;
}

cJSON *wire_build_close_all_nonces(const unsigned char pubnonces[][66], size_t n) {
    cJSON *j = cJSON_CreateObject();
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < n; i++) {
        char hex[133];
        hex_encode(pubnonces[i], 66, hex);
        cJSON_AddItemToArray(arr, cJSON_CreateString(hex));
    }
    cJSON_AddItemToObject(j, "nonces", arr);
    return j;
}

cJSON *wire_build_close_psig(const unsigned char *psig32) {
    cJSON *j = cJSON_CreateObject();
    wire_json_add_hex(j, "psig", psig32, 32);
    return j;
}

cJSON *wire_build_close_done(const unsigned char *tx_data, size_t tx_len) {
    cJSON *j = cJSON_CreateObject();
    wire_json_add_hex(j, "tx_hex", tx_data, tx_len);
    return j;
}

cJSON *wire_build_error(const char *message) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "message", message);
    return j;
}

/* --- Channel operation message builders (Phase 10) --- */

cJSON *wire_build_channel_ready(uint32_t channel_id,
                                 uint64_t balance_local_msat,
                                 uint64_t balance_remote_msat) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "channel_id", channel_id);
    cJSON_AddNumberToObject(j, "balance_local_msat", (double)balance_local_msat);
    cJSON_AddNumberToObject(j, "balance_remote_msat", (double)balance_remote_msat);
    return j;
}

cJSON *wire_build_update_add_htlc(uint64_t htlc_id, uint64_t amount_msat,
                                    const unsigned char *payment_hash32,
                                    uint32_t cltv_expiry) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "htlc_id", (double)htlc_id);
    cJSON_AddNumberToObject(j, "amount_msat", (double)amount_msat);
    wire_json_add_hex(j, "payment_hash", payment_hash32, 32);
    cJSON_AddNumberToObject(j, "cltv_expiry", cltv_expiry);
    return j;
}

cJSON *wire_build_commitment_signed(uint32_t channel_id,
                                      uint64_t commitment_number,
                                      const unsigned char *partial_sig32,
                                      uint32_t nonce_index) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "channel_id", channel_id);
    cJSON_AddNumberToObject(j, "commitment_number", (double)commitment_number);
    wire_json_add_hex(j, "partial_sig", partial_sig32, 32);
    cJSON_AddNumberToObject(j, "nonce_index", nonce_index);
    return j;
}

cJSON *wire_build_revoke_and_ack(uint32_t channel_id,
                                   const unsigned char *revocation_secret32,
                                   const secp256k1_context *ctx,
                                   const secp256k1_pubkey *next_per_commitment_point) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "channel_id", channel_id);
    wire_json_add_hex(j, "revocation_secret", revocation_secret32, 32);
    if (ctx && next_per_commitment_point) {
        char hex[67];
        pubkey_to_hex(ctx, next_per_commitment_point, hex);
        cJSON_AddStringToObject(j, "next_per_commitment_point", hex);
    }
    return j;
}

cJSON *wire_build_update_fulfill_htlc(uint64_t htlc_id,
                                        const unsigned char *preimage32) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "htlc_id", (double)htlc_id);
    wire_json_add_hex(j, "preimage", preimage32, 32);
    return j;
}

cJSON *wire_build_update_fail_htlc(uint64_t htlc_id, const char *reason) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "htlc_id", (double)htlc_id);
    cJSON_AddStringToObject(j, "reason", reason ? reason : "unknown");
    return j;
}

cJSON *wire_build_close_request(void) {
    return cJSON_CreateObject();
}

cJSON *wire_build_channel_nonces(uint32_t channel_id,
                                   const unsigned char pubnonces[][66],
                                   size_t count) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "channel_id", channel_id);
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < count; i++) {
        char hex[133];
        hex_encode(pubnonces[i], 66, hex);
        cJSON_AddItemToArray(arr, cJSON_CreateString(hex));
    }
    cJSON_AddItemToObject(j, "pubnonces", arr);
    return j;
}

/* --- Channel operation message parsers (Phase 10) --- */

int wire_parse_channel_ready(const cJSON *json, uint32_t *channel_id,
                              uint64_t *balance_local_msat,
                              uint64_t *balance_remote_msat) {
    cJSON *ci = cJSON_GetObjectItem(json, "channel_id");
    cJSON *bl = cJSON_GetObjectItem(json, "balance_local_msat");
    cJSON *br = cJSON_GetObjectItem(json, "balance_remote_msat");
    if (!ci || !cJSON_IsNumber(ci) || !bl || !cJSON_IsNumber(bl) ||
        !br || !cJSON_IsNumber(br))
        return 0;
    *channel_id = (uint32_t)ci->valuedouble;
    *balance_local_msat = (uint64_t)bl->valuedouble;
    *balance_remote_msat = (uint64_t)br->valuedouble;
    return 1;
}

int wire_parse_update_add_htlc(const cJSON *json, uint64_t *htlc_id,
                                 uint64_t *amount_msat,
                                 unsigned char *payment_hash32,
                                 uint32_t *cltv_expiry) {
    cJSON *hi = cJSON_GetObjectItem(json, "htlc_id");
    cJSON *am = cJSON_GetObjectItem(json, "amount_msat");
    cJSON *ce = cJSON_GetObjectItem(json, "cltv_expiry");
    if (!hi || !cJSON_IsNumber(hi) || !am || !cJSON_IsNumber(am) ||
        !ce || !cJSON_IsNumber(ce))
        return 0;
    if (wire_json_get_hex(json, "payment_hash", payment_hash32, 32) != 32)
        return 0;
    *htlc_id = (uint64_t)hi->valuedouble;
    *amount_msat = (uint64_t)am->valuedouble;
    *cltv_expiry = (uint32_t)ce->valuedouble;
    return 1;
}

int wire_parse_commitment_signed(const cJSON *json, uint32_t *channel_id,
                                   uint64_t *commitment_number,
                                   unsigned char *partial_sig32,
                                   uint32_t *nonce_index) {
    cJSON *ci = cJSON_GetObjectItem(json, "channel_id");
    cJSON *cn = cJSON_GetObjectItem(json, "commitment_number");
    cJSON *ni = cJSON_GetObjectItem(json, "nonce_index");
    if (!ci || !cJSON_IsNumber(ci) || !cn || !cJSON_IsNumber(cn) ||
        !ni || !cJSON_IsNumber(ni))
        return 0;
    if (wire_json_get_hex(json, "partial_sig", partial_sig32, 32) != 32)
        return 0;
    *channel_id = (uint32_t)ci->valuedouble;
    *commitment_number = (uint64_t)cn->valuedouble;
    *nonce_index = (uint32_t)ni->valuedouble;
    return 1;
}

int wire_parse_revoke_and_ack(const cJSON *json, uint32_t *channel_id,
                                unsigned char *revocation_secret32,
                                unsigned char *next_point33) {
    cJSON *ci = cJSON_GetObjectItem(json, "channel_id");
    if (!ci || !cJSON_IsNumber(ci)) return 0;
    if (wire_json_get_hex(json, "revocation_secret", revocation_secret32, 32) != 32)
        return 0;
    if (next_point33) {
        cJSON *np = cJSON_GetObjectItem(json, "next_per_commitment_point");
        if (!np || !cJSON_IsString(np)) return 0;
        if (hex_decode(np->valuestring, next_point33, 33) != 33) return 0;
    }
    *channel_id = (uint32_t)ci->valuedouble;
    return 1;
}

int wire_parse_update_fulfill_htlc(const cJSON *json, uint64_t *htlc_id,
                                     unsigned char *preimage32) {
    cJSON *hi = cJSON_GetObjectItem(json, "htlc_id");
    if (!hi || !cJSON_IsNumber(hi)) return 0;
    if (wire_json_get_hex(json, "preimage", preimage32, 32) != 32)
        return 0;
    *htlc_id = (uint64_t)hi->valuedouble;
    return 1;
}

int wire_parse_update_fail_htlc(const cJSON *json, uint64_t *htlc_id,
                                  char *reason, size_t reason_len) {
    cJSON *hi = cJSON_GetObjectItem(json, "htlc_id");
    cJSON *re = cJSON_GetObjectItem(json, "reason");
    if (!hi || !cJSON_IsNumber(hi)) return 0;
    *htlc_id = (uint64_t)hi->valuedouble;
    if (reason && reason_len > 0) {
        if (re && cJSON_IsString(re)) {
            strncpy(reason, re->valuestring, reason_len - 1);
            reason[reason_len - 1] = '\0';
        } else {
            reason[0] = '\0';
        }
    }
    return 1;
}

int wire_parse_channel_nonces(const cJSON *json, uint32_t *channel_id,
                                unsigned char pubnonces_out[][66],
                                size_t max_nonces, size_t *count_out) {
    cJSON *ci = cJSON_GetObjectItem(json, "channel_id");
    cJSON *arr = cJSON_GetObjectItem(json, "pubnonces");
    if (!ci || !cJSON_IsNumber(ci) || !arr || !cJSON_IsArray(arr))
        return 0;
    *channel_id = (uint32_t)ci->valuedouble;
    size_t count = 0;
    cJSON *item;
    cJSON_ArrayForEach(item, arr) {
        if (count >= max_nonces) break;
        if (!cJSON_IsString(item)) continue;
        if (hex_decode(item->valuestring, pubnonces_out[count], 66) != 66)
            continue;
        count++;
    }
    *count_out = count;
    return 1;
}

/* --- Bridge message builders (Phase 14) --- */

cJSON *wire_build_bridge_hello(void) {
    return cJSON_CreateObject();
}

cJSON *wire_build_bridge_hello_ack(void) {
    return cJSON_CreateObject();
}

cJSON *wire_build_bridge_add_htlc(const unsigned char *payment_hash32,
                                    uint64_t amount_msat, uint32_t cltv_expiry,
                                    uint64_t htlc_id) {
    cJSON *j = cJSON_CreateObject();
    wire_json_add_hex(j, "payment_hash", payment_hash32, 32);
    cJSON_AddNumberToObject(j, "amount_msat", (double)amount_msat);
    cJSON_AddNumberToObject(j, "cltv_expiry", cltv_expiry);
    cJSON_AddNumberToObject(j, "htlc_id", (double)htlc_id);
    return j;
}

cJSON *wire_build_bridge_fulfill_htlc(const unsigned char *payment_hash32,
                                        const unsigned char *preimage32,
                                        uint64_t htlc_id) {
    cJSON *j = cJSON_CreateObject();
    wire_json_add_hex(j, "payment_hash", payment_hash32, 32);
    wire_json_add_hex(j, "preimage", preimage32, 32);
    cJSON_AddNumberToObject(j, "htlc_id", (double)htlc_id);
    return j;
}

cJSON *wire_build_bridge_fail_htlc(const unsigned char *payment_hash32,
                                     const char *reason, uint64_t htlc_id) {
    cJSON *j = cJSON_CreateObject();
    wire_json_add_hex(j, "payment_hash", payment_hash32, 32);
    cJSON_AddStringToObject(j, "reason", reason ? reason : "unknown");
    cJSON_AddNumberToObject(j, "htlc_id", (double)htlc_id);
    return j;
}

cJSON *wire_build_bridge_send_pay(const char *bolt11,
                                    const unsigned char *payment_hash32,
                                    uint64_t request_id) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "bolt11", bolt11);
    wire_json_add_hex(j, "payment_hash", payment_hash32, 32);
    cJSON_AddNumberToObject(j, "request_id", (double)request_id);
    return j;
}

cJSON *wire_build_bridge_pay_result(uint64_t request_id, int success,
                                      const unsigned char *preimage32) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "request_id", (double)request_id);
    cJSON_AddBoolToObject(j, "success", success);
    if (preimage32)
        wire_json_add_hex(j, "preimage", preimage32, 32);
    return j;
}

cJSON *wire_build_bridge_register(const unsigned char *payment_hash32,
                                    uint64_t amount_msat, size_t dest_client) {
    cJSON *j = cJSON_CreateObject();
    wire_json_add_hex(j, "payment_hash", payment_hash32, 32);
    cJSON_AddNumberToObject(j, "amount_msat", (double)amount_msat);
    cJSON_AddNumberToObject(j, "dest_client", (double)dest_client);
    return j;
}

/* --- Register invoice (Phase 15) --- */

cJSON *wire_build_register_invoice(const unsigned char *payment_hash32,
                                     uint64_t amount_msat, size_t dest_client) {
    cJSON *j = cJSON_CreateObject();
    wire_json_add_hex(j, "payment_hash", payment_hash32, 32);
    cJSON_AddNumberToObject(j, "amount_msat", (double)amount_msat);
    cJSON_AddNumberToObject(j, "dest_client", (double)dest_client);
    return j;
}

int wire_parse_register_invoice(const cJSON *json,
                                  unsigned char *payment_hash32,
                                  uint64_t *amount_msat, size_t *dest_client) {
    cJSON *am = cJSON_GetObjectItem(json, "amount_msat");
    cJSON *dc = cJSON_GetObjectItem(json, "dest_client");
    if (!am || !cJSON_IsNumber(am) || !dc || !cJSON_IsNumber(dc))
        return 0;
    if (wire_json_get_hex(json, "payment_hash", payment_hash32, 32) != 32)
        return 0;
    *amount_msat = (uint64_t)am->valuedouble;
    *dest_client = (size_t)dc->valuedouble;
    return 1;
}

/* --- Bridge message parsers (Phase 14) --- */

int wire_parse_bridge_add_htlc(const cJSON *json,
                                 unsigned char *payment_hash32,
                                 uint64_t *amount_msat, uint32_t *cltv_expiry,
                                 uint64_t *htlc_id) {
    cJSON *am = cJSON_GetObjectItem(json, "amount_msat");
    cJSON *ce = cJSON_GetObjectItem(json, "cltv_expiry");
    cJSON *hi = cJSON_GetObjectItem(json, "htlc_id");
    if (!am || !cJSON_IsNumber(am) || !ce || !cJSON_IsNumber(ce) ||
        !hi || !cJSON_IsNumber(hi))
        return 0;
    if (wire_json_get_hex(json, "payment_hash", payment_hash32, 32) != 32)
        return 0;
    *amount_msat = (uint64_t)am->valuedouble;
    *cltv_expiry = (uint32_t)ce->valuedouble;
    *htlc_id = (uint64_t)hi->valuedouble;
    return 1;
}

int wire_parse_bridge_fulfill_htlc(const cJSON *json,
                                     unsigned char *payment_hash32,
                                     unsigned char *preimage32,
                                     uint64_t *htlc_id) {
    cJSON *hi = cJSON_GetObjectItem(json, "htlc_id");
    if (!hi || !cJSON_IsNumber(hi)) return 0;
    if (wire_json_get_hex(json, "payment_hash", payment_hash32, 32) != 32)
        return 0;
    if (wire_json_get_hex(json, "preimage", preimage32, 32) != 32)
        return 0;
    *htlc_id = (uint64_t)hi->valuedouble;
    return 1;
}

int wire_parse_bridge_fail_htlc(const cJSON *json,
                                  unsigned char *payment_hash32,
                                  char *reason, size_t reason_len,
                                  uint64_t *htlc_id) {
    cJSON *hi = cJSON_GetObjectItem(json, "htlc_id");
    if (!hi || !cJSON_IsNumber(hi)) return 0;
    if (wire_json_get_hex(json, "payment_hash", payment_hash32, 32) != 32)
        return 0;
    *htlc_id = (uint64_t)hi->valuedouble;
    if (reason && reason_len > 0) {
        cJSON *re = cJSON_GetObjectItem(json, "reason");
        if (re && cJSON_IsString(re)) {
            strncpy(reason, re->valuestring, reason_len - 1);
            reason[reason_len - 1] = '\0';
        } else {
            reason[0] = '\0';
        }
    }
    return 1;
}

int wire_parse_bridge_send_pay(const cJSON *json,
                                 char *bolt11, size_t bolt11_len,
                                 unsigned char *payment_hash32,
                                 uint64_t *request_id) {
    cJSON *b = cJSON_GetObjectItem(json, "bolt11");
    cJSON *ri = cJSON_GetObjectItem(json, "request_id");
    if (!b || !cJSON_IsString(b) || !ri || !cJSON_IsNumber(ri))
        return 0;
    if (wire_json_get_hex(json, "payment_hash", payment_hash32, 32) != 32)
        return 0;
    *request_id = (uint64_t)ri->valuedouble;
    if (bolt11 && bolt11_len > 0) {
        strncpy(bolt11, b->valuestring, bolt11_len - 1);
        bolt11[bolt11_len - 1] = '\0';
    }
    return 1;
}

int wire_parse_bridge_pay_result(const cJSON *json,
                                   uint64_t *request_id, int *success,
                                   unsigned char *preimage32) {
    cJSON *ri = cJSON_GetObjectItem(json, "request_id");
    cJSON *su = cJSON_GetObjectItem(json, "success");
    if (!ri || !cJSON_IsNumber(ri) || !su || !cJSON_IsBool(su))
        return 0;
    *request_id = (uint64_t)ri->valuedouble;
    *success = cJSON_IsTrue(su) ? 1 : 0;
    if (*success && preimage32)
        wire_json_get_hex(json, "preimage", preimage32, 32);
    return 1;
}

int wire_parse_bridge_register(const cJSON *json,
                                 unsigned char *payment_hash32,
                                 uint64_t *amount_msat, size_t *dest_client) {
    cJSON *am = cJSON_GetObjectItem(json, "amount_msat");
    cJSON *dc = cJSON_GetObjectItem(json, "dest_client");
    if (!am || !cJSON_IsNumber(am) || !dc || !cJSON_IsNumber(dc))
        return 0;
    if (wire_json_get_hex(json, "payment_hash", payment_hash32, 32) != 32)
        return 0;
    *amount_msat = (uint64_t)am->valuedouble;
    *dest_client = (size_t)dc->valuedouble;
    return 1;
}

/* --- Reconnection messages (Phase 16) --- */

cJSON *wire_build_reconnect(const secp256k1_context *ctx,
                              const secp256k1_pubkey *pubkey,
                              uint64_t commitment_number) {
    cJSON *j = cJSON_CreateObject();
    char hex[67];
    pubkey_to_hex(ctx, pubkey, hex);
    cJSON_AddStringToObject(j, "pubkey", hex);
    cJSON_AddNumberToObject(j, "commitment_number", (double)commitment_number);
    return j;
}

int wire_parse_reconnect(const cJSON *json, const secp256k1_context *ctx,
                           secp256k1_pubkey *pubkey_out,
                           uint64_t *commitment_number_out) {
    cJSON *pk = cJSON_GetObjectItem(json, "pubkey");
    cJSON *cn = cJSON_GetObjectItem(json, "commitment_number");
    if (!pk || !cJSON_IsString(pk) || !cn || !cJSON_IsNumber(cn))
        return 0;
    if (!hex_to_pubkey(ctx, pubkey_out, pk->valuestring))
        return 0;
    *commitment_number_out = (uint64_t)cn->valuedouble;
    return 1;
}

cJSON *wire_build_reconnect_ack(uint32_t channel_id,
                                  uint64_t local_amount_msat,
                                  uint64_t remote_amount_msat,
                                  uint64_t commitment_number) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "channel_id", channel_id);
    cJSON_AddNumberToObject(j, "local_amount_msat", (double)local_amount_msat);
    cJSON_AddNumberToObject(j, "remote_amount_msat", (double)remote_amount_msat);
    cJSON_AddNumberToObject(j, "commitment_number", (double)commitment_number);
    return j;
}

int wire_parse_reconnect_ack(const cJSON *json, uint32_t *channel_id,
                                uint64_t *local_amount_msat,
                                uint64_t *remote_amount_msat,
                                uint64_t *commitment_number) {
    cJSON *ci = cJSON_GetObjectItem(json, "channel_id");
    cJSON *la = cJSON_GetObjectItem(json, "local_amount_msat");
    cJSON *ra = cJSON_GetObjectItem(json, "remote_amount_msat");
    cJSON *cn = cJSON_GetObjectItem(json, "commitment_number");
    if (!ci || !cJSON_IsNumber(ci) || !la || !cJSON_IsNumber(la) ||
        !ra || !cJSON_IsNumber(ra) || !cn || !cJSON_IsNumber(cn))
        return 0;
    *channel_id = (uint32_t)ci->valuedouble;
    *local_amount_msat = (uint64_t)la->valuedouble;
    *remote_amount_msat = (uint64_t)ra->valuedouble;
    *commitment_number = (uint64_t)cn->valuedouble;
    return 1;
}

/* --- Invoice messages (Phase 17) --- */

cJSON *wire_build_create_invoice(uint64_t amount_msat) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "amount_msat", (double)amount_msat);
    return j;
}

int wire_parse_create_invoice(const cJSON *json, uint64_t *amount_msat) {
    cJSON *am = cJSON_GetObjectItem(json, "amount_msat");
    if (!am || !cJSON_IsNumber(am))
        return 0;
    *amount_msat = (uint64_t)am->valuedouble;
    return 1;
}

cJSON *wire_build_invoice_created(const unsigned char *payment_hash32,
                                    uint64_t amount_msat) {
    cJSON *j = cJSON_CreateObject();
    wire_json_add_hex(j, "payment_hash", payment_hash32, 32);
    cJSON_AddNumberToObject(j, "amount_msat", (double)amount_msat);
    return j;
}

int wire_parse_invoice_created(const cJSON *json,
                                 unsigned char *payment_hash32,
                                 uint64_t *amount_msat) {
    cJSON *am = cJSON_GetObjectItem(json, "amount_msat");
    if (!am || !cJSON_IsNumber(am))
        return 0;
    if (wire_json_get_hex(json, "payment_hash", payment_hash32, 32) != 32)
        return 0;
    *amount_msat = (uint64_t)am->valuedouble;
    return 1;
}

/* --- PTLC key turnover messages (Tier 3) --- */

cJSON *wire_build_ptlc_presig(const unsigned char *presig64,
                               int nonce_parity,
                               const unsigned char *turnover_msg32) {
    cJSON *j = cJSON_CreateObject();
    wire_json_add_hex(j, "presig", presig64, 64);
    cJSON_AddNumberToObject(j, "nonce_parity", nonce_parity);
    wire_json_add_hex(j, "turnover_msg", turnover_msg32, 32);
    return j;
}

int wire_parse_ptlc_presig(const cJSON *json, unsigned char *presig64,
                            int *nonce_parity, unsigned char *turnover_msg32) {
    cJSON *np = cJSON_GetObjectItem(json, "nonce_parity");
    if (!np || !cJSON_IsNumber(np))
        return 0;
    if (wire_json_get_hex(json, "presig", presig64, 64) != 64)
        return 0;
    if (wire_json_get_hex(json, "turnover_msg", turnover_msg32, 32) != 32)
        return 0;
    *nonce_parity = (int)np->valuedouble;
    return 1;
}

cJSON *wire_build_ptlc_adapted_sig(const unsigned char *adapted_sig64) {
    cJSON *j = cJSON_CreateObject();
    wire_json_add_hex(j, "adapted_sig", adapted_sig64, 64);
    return j;
}

int wire_parse_ptlc_adapted_sig(const cJSON *json, unsigned char *adapted_sig64) {
    if (wire_json_get_hex(json, "adapted_sig", adapted_sig64, 64) != 64)
        return 0;
    return 1;
}

cJSON *wire_build_ptlc_complete(void) {
    return cJSON_CreateObject();
}

/* --- Basepoint exchange (Gap #1) --- */

cJSON *wire_build_channel_basepoints(
    uint32_t channel_id,
    const secp256k1_context *ctx,
    const secp256k1_pubkey *payment_basepoint,
    const secp256k1_pubkey *delayed_payment_basepoint,
    const secp256k1_pubkey *revocation_basepoint,
    const secp256k1_pubkey *htlc_basepoint,
    const secp256k1_pubkey *first_per_commitment_point,
    const secp256k1_pubkey *second_per_commitment_point) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "channel_id", channel_id);
    char hex[67];
    pubkey_to_hex(ctx, payment_basepoint, hex);
    cJSON_AddStringToObject(j, "payment_basepoint", hex);
    pubkey_to_hex(ctx, delayed_payment_basepoint, hex);
    cJSON_AddStringToObject(j, "delayed_payment_basepoint", hex);
    pubkey_to_hex(ctx, revocation_basepoint, hex);
    cJSON_AddStringToObject(j, "revocation_basepoint", hex);
    pubkey_to_hex(ctx, htlc_basepoint, hex);
    cJSON_AddStringToObject(j, "htlc_basepoint", hex);
    pubkey_to_hex(ctx, first_per_commitment_point, hex);
    cJSON_AddStringToObject(j, "first_per_commitment_point", hex);
    if (second_per_commitment_point) {
        pubkey_to_hex(ctx, second_per_commitment_point, hex);
        cJSON_AddStringToObject(j, "second_per_commitment_point", hex);
    }
    return j;
}

int wire_parse_channel_basepoints(
    const cJSON *json,
    uint32_t *channel_id_out,
    const secp256k1_context *ctx,
    secp256k1_pubkey *payment_bp_out,
    secp256k1_pubkey *delayed_bp_out,
    secp256k1_pubkey *revocation_bp_out,
    secp256k1_pubkey *htlc_bp_out,
    secp256k1_pubkey *first_pcp_out,
    secp256k1_pubkey *second_pcp_out) {
    cJSON *ci = cJSON_GetObjectItem(json, "channel_id");
    if (!ci || !cJSON_IsNumber(ci)) return 0;
    *channel_id_out = (uint32_t)ci->valuedouble;

    cJSON *pb = cJSON_GetObjectItem(json, "payment_basepoint");
    cJSON *db = cJSON_GetObjectItem(json, "delayed_payment_basepoint");
    cJSON *rb = cJSON_GetObjectItem(json, "revocation_basepoint");
    cJSON *hb = cJSON_GetObjectItem(json, "htlc_basepoint");
    cJSON *fp = cJSON_GetObjectItem(json, "first_per_commitment_point");
    if (!pb || !cJSON_IsString(pb) ||
        !db || !cJSON_IsString(db) ||
        !rb || !cJSON_IsString(rb) ||
        !hb || !cJSON_IsString(hb) ||
        !fp || !cJSON_IsString(fp))
        return 0;

    if (!hex_to_pubkey(ctx, payment_bp_out, pb->valuestring)) return 0;
    if (!hex_to_pubkey(ctx, delayed_bp_out, db->valuestring)) return 0;
    if (!hex_to_pubkey(ctx, revocation_bp_out, rb->valuestring)) return 0;
    if (!hex_to_pubkey(ctx, htlc_bp_out, hb->valuestring)) return 0;
    if (!hex_to_pubkey(ctx, first_pcp_out, fp->valuestring)) return 0;

    /* second_per_commitment_point is optional (backward-compat) */
    if (second_pcp_out) {
        cJSON *sp = cJSON_GetObjectItem(json, "second_per_commitment_point");
        if (sp && cJSON_IsString(sp)) {
            if (!hex_to_pubkey(ctx, second_pcp_out, sp->valuestring)) return 0;
        } else {
            memset(second_pcp_out, 0, sizeof(secp256k1_pubkey));
        }
    }
    return 1;
}

/* --- JIT Channel messages (Gap #2) --- */

cJSON *wire_build_jit_offer(size_t client_idx, uint64_t funding_amount,
                              const char *reason,
                              const secp256k1_context *ctx,
                              const secp256k1_pubkey *lsp_pubkey) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "client_idx", (double)client_idx);
    cJSON_AddNumberToObject(j, "funding_amount", (double)funding_amount);
    cJSON_AddStringToObject(j, "reason", reason ? reason : "unknown");
    if (ctx && lsp_pubkey) {
        char hex[67];
        pubkey_to_hex(ctx, lsp_pubkey, hex);
        cJSON_AddStringToObject(j, "lsp_pubkey", hex);
    }
    return j;
}

int wire_parse_jit_offer(const cJSON *json, const secp256k1_context *ctx,
                           size_t *client_idx, uint64_t *funding_amount,
                           char *reason, size_t reason_len,
                           secp256k1_pubkey *lsp_pubkey) {
    cJSON *ci = cJSON_GetObjectItem(json, "client_idx");
    cJSON *fa = cJSON_GetObjectItem(json, "funding_amount");
    cJSON *re = cJSON_GetObjectItem(json, "reason");
    cJSON *pk = cJSON_GetObjectItem(json, "lsp_pubkey");
    if (!ci || !cJSON_IsNumber(ci) || !fa || !cJSON_IsNumber(fa))
        return 0;
    *client_idx = (size_t)ci->valuedouble;
    *funding_amount = (uint64_t)fa->valuedouble;
    if (reason && reason_len > 0 && re && cJSON_IsString(re)) {
        strncpy(reason, re->valuestring, reason_len - 1);
        reason[reason_len - 1] = '\0';
    }
    if (lsp_pubkey && pk && cJSON_IsString(pk) && ctx) {
        if (!hex_to_pubkey(ctx, lsp_pubkey, pk->valuestring))
            return 0;
    }
    return 1;
}

cJSON *wire_build_jit_accept(size_t client_idx,
                               const secp256k1_context *ctx,
                               const secp256k1_pubkey *client_pubkey) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "client_idx", (double)client_idx);
    if (ctx && client_pubkey) {
        char hex[67];
        pubkey_to_hex(ctx, client_pubkey, hex);
        cJSON_AddStringToObject(j, "client_pubkey", hex);
    }
    return j;
}

int wire_parse_jit_accept(const cJSON *json, const secp256k1_context *ctx,
                            size_t *client_idx,
                            secp256k1_pubkey *client_pubkey) {
    cJSON *ci = cJSON_GetObjectItem(json, "client_idx");
    cJSON *pk = cJSON_GetObjectItem(json, "client_pubkey");
    if (!ci || !cJSON_IsNumber(ci))
        return 0;
    *client_idx = (size_t)ci->valuedouble;
    if (client_pubkey && pk && cJSON_IsString(pk) && ctx) {
        if (!hex_to_pubkey(ctx, client_pubkey, pk->valuestring))
            return 0;
    }
    return 1;
}

cJSON *wire_build_jit_ready(uint32_t jit_channel_id,
                              const char *funding_txid_hex,
                              uint32_t vout, uint64_t amount,
                              uint64_t local_amount, uint64_t remote_amount) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "jit_channel_id", jit_channel_id);
    cJSON_AddStringToObject(j, "funding_txid", funding_txid_hex ? funding_txid_hex : "");
    cJSON_AddNumberToObject(j, "vout", vout);
    cJSON_AddNumberToObject(j, "amount", (double)amount);
    cJSON_AddNumberToObject(j, "local_amount", (double)local_amount);
    cJSON_AddNumberToObject(j, "remote_amount", (double)remote_amount);
    return j;
}

int wire_parse_jit_ready(const cJSON *json, uint32_t *jit_channel_id,
                           char *funding_txid_hex, size_t hex_len,
                           uint32_t *vout, uint64_t *amount,
                           uint64_t *local_amount, uint64_t *remote_amount) {
    cJSON *ji = cJSON_GetObjectItem(json, "jit_channel_id");
    cJSON *tx = cJSON_GetObjectItem(json, "funding_txid");
    cJSON *vo = cJSON_GetObjectItem(json, "vout");
    cJSON *am = cJSON_GetObjectItem(json, "amount");
    cJSON *la = cJSON_GetObjectItem(json, "local_amount");
    cJSON *ra = cJSON_GetObjectItem(json, "remote_amount");
    if (!ji || !cJSON_IsNumber(ji) || !tx || !cJSON_IsString(tx) ||
        !vo || !cJSON_IsNumber(vo) || !am || !cJSON_IsNumber(am) ||
        !la || !cJSON_IsNumber(la) || !ra || !cJSON_IsNumber(ra))
        return 0;
    *jit_channel_id = (uint32_t)ji->valuedouble;
    if (funding_txid_hex && hex_len > 0) {
        strncpy(funding_txid_hex, tx->valuestring, hex_len - 1);
        funding_txid_hex[hex_len - 1] = '\0';
    }
    *vout = (uint32_t)vo->valuedouble;
    *amount = (uint64_t)am->valuedouble;
    *local_amount = (uint64_t)la->valuedouble;
    *remote_amount = (uint64_t)ra->valuedouble;
    return 1;
}

cJSON *wire_build_jit_migrate(uint32_t jit_channel_id,
                                uint32_t target_factory_id,
                                uint64_t local_balance, uint64_t remote_balance) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "jit_channel_id", jit_channel_id);
    cJSON_AddNumberToObject(j, "target_factory_id", target_factory_id);
    cJSON_AddNumberToObject(j, "local_balance", (double)local_balance);
    cJSON_AddNumberToObject(j, "remote_balance", (double)remote_balance);
    return j;
}

int wire_parse_jit_migrate(const cJSON *json, uint32_t *jit_channel_id,
                             uint32_t *target_factory_id,
                             uint64_t *local_balance, uint64_t *remote_balance) {
    cJSON *ji = cJSON_GetObjectItem(json, "jit_channel_id");
    cJSON *tf = cJSON_GetObjectItem(json, "target_factory_id");
    cJSON *lb = cJSON_GetObjectItem(json, "local_balance");
    cJSON *rb = cJSON_GetObjectItem(json, "remote_balance");
    if (!ji || !cJSON_IsNumber(ji) || !tf || !cJSON_IsNumber(tf) ||
        !lb || !cJSON_IsNumber(lb) || !rb || !cJSON_IsNumber(rb))
        return 0;
    *jit_channel_id = (uint32_t)ji->valuedouble;
    *target_factory_id = (uint32_t)tf->valuedouble;
    *local_balance = (uint64_t)lb->valuedouble;
    *remote_balance = (uint64_t)rb->valuedouble;
    return 1;
}

/* --- Epoch Reset messages (Phase 5) --- */

cJSON *wire_build_epoch_reset_propose(const wire_bundle_entry_t *nonce_entries,
                                       size_t n_entries) {
    cJSON *j = cJSON_CreateObject();
    cJSON *arr = cJSON_AddArrayToObject(j, "nonces");
    for (size_t i = 0; i < n_entries; i++) {
        cJSON *e = cJSON_CreateObject();
        cJSON_AddNumberToObject(e, "node_idx", nonce_entries[i].node_idx);
        cJSON_AddNumberToObject(e, "signer_slot", nonce_entries[i].signer_slot);
        wire_json_add_hex(e, "data", nonce_entries[i].data, 66);
        cJSON_AddItemToArray(arr, e);
    }
    return j;
}

int wire_parse_epoch_reset_propose(const cJSON *json,
                                    wire_bundle_entry_t *entries_out,
                                    size_t max_entries, size_t *n_entries_out) {
    cJSON *arr = cJSON_GetObjectItem(json, "nonces");
    if (!arr || !cJSON_IsArray(arr)) return 0;
    *n_entries_out = wire_parse_bundle(arr, entries_out, max_entries, 66);
    return 1;
}

cJSON *wire_build_epoch_reset_psig(const wire_bundle_entry_t *nonce_entries,
                                    size_t n_nonces,
                                    const wire_bundle_entry_t *psig_entries,
                                    size_t n_psigs) {
    cJSON *j = cJSON_CreateObject();
    cJSON *narr = cJSON_AddArrayToObject(j, "nonces");
    for (size_t i = 0; i < n_nonces; i++) {
        cJSON *e = cJSON_CreateObject();
        cJSON_AddNumberToObject(e, "node_idx", nonce_entries[i].node_idx);
        cJSON_AddNumberToObject(e, "signer_slot", nonce_entries[i].signer_slot);
        wire_json_add_hex(e, "data", nonce_entries[i].data, 66);
        cJSON_AddItemToArray(narr, e);
    }
    cJSON *parr = cJSON_AddArrayToObject(j, "psigs");
    for (size_t i = 0; i < n_psigs; i++) {
        cJSON *e = cJSON_CreateObject();
        cJSON_AddNumberToObject(e, "node_idx", psig_entries[i].node_idx);
        cJSON_AddNumberToObject(e, "signer_slot", psig_entries[i].signer_slot);
        wire_json_add_hex(e, "data", psig_entries[i].data, 32);
        cJSON_AddItemToArray(parr, e);
    }
    return j;
}

int wire_parse_epoch_reset_psig(const cJSON *json,
                                 wire_bundle_entry_t *nonce_entries_out,
                                 size_t max_nonces, size_t *n_nonces_out,
                                 wire_bundle_entry_t *psig_entries_out,
                                 size_t max_psigs, size_t *n_psigs_out) {
    cJSON *narr = cJSON_GetObjectItem(json, "nonces");
    cJSON *parr = cJSON_GetObjectItem(json, "psigs");
    if (!narr || !cJSON_IsArray(narr) || !parr || !cJSON_IsArray(parr))
        return 0;
    *n_nonces_out = wire_parse_bundle(narr, nonce_entries_out, max_nonces, 66);
    *n_psigs_out = wire_parse_bundle(parr, psig_entries_out, max_psigs, 32);
    return 1;
}

cJSON *wire_build_epoch_reset_done(void) {
    return cJSON_CreateObject();
}

/* --- Per-Leaf Advance messages (Upgrade 2) --- */

cJSON *wire_build_leaf_advance_propose(int leaf_side,
                                        const unsigned char *pubnonce66) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "leaf_side", leaf_side);
    wire_json_add_hex(j, "pubnonce", pubnonce66, 66);
    return j;
}

int wire_parse_leaf_advance_propose(const cJSON *json, int *leaf_side,
                                      unsigned char *pubnonce66) {
    cJSON *ls = cJSON_GetObjectItem(json, "leaf_side");
    if (!ls || !cJSON_IsNumber(ls)) return 0;
    *leaf_side = (int)ls->valuedouble;
    if (wire_json_get_hex(json, "pubnonce", pubnonce66, 66) != 66) return 0;
    return 1;
}

cJSON *wire_build_leaf_advance_psig(const unsigned char *pubnonce66,
                                      const unsigned char *partial_sig32) {
    cJSON *j = cJSON_CreateObject();
    wire_json_add_hex(j, "pubnonce", pubnonce66, 66);
    wire_json_add_hex(j, "partial_sig", partial_sig32, 32);
    return j;
}

int wire_parse_leaf_advance_psig(const cJSON *json,
                                    unsigned char *pubnonce66,
                                    unsigned char *partial_sig32) {
    if (wire_json_get_hex(json, "pubnonce", pubnonce66, 66) != 66) return 0;
    if (wire_json_get_hex(json, "partial_sig", partial_sig32, 32) != 32) return 0;
    return 1;
}

cJSON *wire_build_leaf_advance_done(int leaf_side) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "leaf_side", leaf_side);
    return j;
}

int wire_parse_leaf_advance_done(const cJSON *json, int *leaf_side) {
    cJSON *ls = cJSON_GetObjectItem(json, "leaf_side");
    if (!ls || !cJSON_IsNumber(ls)) return 0;
    *leaf_side = (int)ls->valuedouble;
    return 1;
}

/* --- Bundle parsing --- */

size_t wire_parse_bundle(const cJSON *array, wire_bundle_entry_t *entries,
                         size_t max_entries, size_t expected_data_len) {
    if (!cJSON_IsArray(array)) return 0;
    size_t count = 0;
    cJSON *item;
    cJSON_ArrayForEach(item, array) {
        if (count >= max_entries) break;

        cJSON *ni = cJSON_GetObjectItem(item, "node_idx");
        cJSON *sl = cJSON_GetObjectItem(item, "slot");
        cJSON *d  = cJSON_GetObjectItem(item, "data");
        if (!ni || !cJSON_IsNumber(ni) ||
            !sl || !cJSON_IsNumber(sl) ||
            !d || !cJSON_IsString(d)) continue;
        if (ni->valuedouble < 0 || ni->valuedouble >= FACTORY_MAX_NODES) continue;
        if (sl->valuedouble < 0 || sl->valuedouble >= FACTORY_MAX_SIGNERS) continue;

        entries[count].node_idx = (uint32_t)ni->valuedouble;
        entries[count].signer_slot = (uint32_t)sl->valuedouble;
        int decoded = hex_decode(d->valuestring, entries[count].data, sizeof(entries[count].data));
        if (decoded != (int)expected_data_len) continue;
        entries[count].data_len = (size_t)decoded;
        count++;
    }
    return count;
}

/* --- Encrypted transport convenience (Phase 19) --- */

int wire_noise_handshake_initiator(int fd, secp256k1_context *ctx) {
    if (!wire_mark_encryption_required(fd))
        return 0;
    noise_state_t ns;
    if (!noise_handshake_initiator(&ns, fd, ctx))
        return 0;
    if (!wire_set_encryption(fd, &ns)) {
        secure_zero(&ns, sizeof(ns));
        return 0;
    }
    secure_zero(&ns, sizeof(ns));
    return 1;
}

int wire_noise_handshake_responder(int fd, secp256k1_context *ctx) {
    if (!wire_mark_encryption_required(fd))
        return 0;
    noise_state_t ns;
    if (!noise_handshake_responder(&ns, fd, ctx))
        return 0;
    if (!wire_set_encryption(fd, &ns)) {
        secure_zero(&ns, sizeof(ns));
        return 0;
    }
    secure_zero(&ns, sizeof(ns));
    return 1;
}

int wire_noise_handshake_nk_initiator(int fd, secp256k1_context *ctx,
                                        const secp256k1_pubkey *server_pubkey) {
    if (!wire_mark_encryption_required(fd))
        return 0;
    noise_state_t ns;
    if (!noise_handshake_nk_initiator(&ns, fd, ctx, server_pubkey))
        return 0;
    if (!wire_set_encryption(fd, &ns)) {
        secure_zero(&ns, sizeof(ns));
        return 0;
    }
    secure_zero(&ns, sizeof(ns));
    return 1;
}

int wire_noise_handshake_nk_responder(int fd, secp256k1_context *ctx,
                                        const unsigned char *static_seckey32) {
    if (!wire_mark_encryption_required(fd))
        return 0;
    noise_state_t ns;
    if (!noise_handshake_nk_responder(&ns, fd, ctx, static_seckey32))
        return 0;
    if (!wire_set_encryption(fd, &ns)) {
        secure_zero(&ns, sizeof(ns));
        return 0;
    }
    secure_zero(&ns, sizeof(ns));
    return 1;
}
