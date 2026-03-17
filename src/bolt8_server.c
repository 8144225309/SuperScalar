/*
 * bolt8_server.c — TCP accept loop + BOLT #1 init + LSPS/native dispatch
 *
 * Accepts inbound connections from standard LN peers and LSPS-compatible
 * wallets (Zeus, Blixt, Phoenix). Performs BOLT #8 Noise_XK handshake,
 * exchanges BOLT #1 init messages, then dispatches by message type.
 *
 * The factory protocol (DW tree, MuSig2) is never exposed here.
 * To the outside world this is just a Lightning node.
 */

#include "superscalar/bolt8_server.h"
#include "superscalar/bolt8.h"
#include "superscalar/lsps.h"
#include "superscalar/types.h"

#include <secp256k1.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Maximum inbound message size (1 MB) */
#define MAX_MSG_LEN (1024 * 1024)

/* BOLT #1 init message: feature bits 729 and 759.
   Feature bytes are big-endian; bit N is at byte[len-1 - N/8], position N%8.
   We need at least ceil(760/8) = 95 bytes.
   Byte at offset (94 - 91) = 3 gets bit 1 set (bit 729): 0x02
   Byte at offset (94 - 94) = 0 gets bit 7 set (bit 759): 0x80 */
#define INIT_FEATURES_LEN 95

static void build_init_features(unsigned char features[INIT_FEATURES_LEN]) {
    memset(features, 0, INIT_FEATURES_LEN);
    /* Bit 729: byte offset from start = 94 - 729/8 = 94 - 91 = 3, bit 729%8 = 1 */
    features[3] |= (1u << (BOLT8_FEATURE_BIT_LSPS0 % 8));
    /* Bit 759: byte offset from start = 94 - 759/8 = 94 - 94 = 0, bit 759%8 = 7 */
    features[0] |= (1u << (BOLT8_FEATURE_BIT_SUPERSCALAR % 8));
}

/* Write 2-byte big-endian value into buf */
static void write_be16(unsigned char *buf, uint16_t v) {
    buf[0] = (unsigned char)(v >> 8);
    buf[1] = (unsigned char)(v);
}

/* Read 2-byte big-endian value */
static uint16_t read_be16(const unsigned char *buf) {
    return ((uint16_t)buf[0] << 8) | buf[1];
}

int bolt8_init_exchange(bolt8_state_t *state, int fd) {
    /* Build BOLT #1 init message:
       [u16: type=16][u16: gflen=0][u16: lflen=95][95: features] */
    unsigned char init_msg[2 + 2 + 2 + INIT_FEATURES_LEN];
    write_be16(init_msg + 0, BOLT1_MSG_INIT);         /* type */
    write_be16(init_msg + 2, 0);                       /* globalfeatures_len */
    write_be16(init_msg + 4, INIT_FEATURES_LEN);       /* localfeatures_len */
    build_init_features(init_msg + 6);

    /* Send our init message */
    if (!bolt8_send(state, fd, init_msg, sizeof(init_msg))) {
        fprintf(stderr, "bolt8_server: failed to send init\n");
        return 0;
    }

    /* Read peer's init message */
    unsigned char peer_msg[2048];
    size_t peer_len = 0;
    if (!bolt8_recv(state, fd, peer_msg, &peer_len, sizeof(peer_msg))) {
        fprintf(stderr, "bolt8_server: failed to receive peer init\n");
        return 0;
    }

    /* Validate: type must be 16 (init) */
    if (peer_len < 6) {
        fprintf(stderr, "bolt8_server: peer init too short (%zu bytes)\n", peer_len);
        return 0;
    }
    uint16_t peer_type = read_be16(peer_msg);
    if (peer_type != BOLT1_MSG_INIT) {
        fprintf(stderr, "bolt8_server: expected init (16), got type %u\n", peer_type);
        return 0;
    }

    /* We accept any feature vector from the peer — just log it */
    uint16_t gflen = read_be16(peer_msg + 2);
    if (peer_len < (size_t)(6 + gflen)) return 0;
    uint16_t lflen = read_be16(peer_msg + 4 + gflen);
    (void)lflen;  /* accept all feature vectors */

    return 1;
}

int bolt8_dispatch_message(const bolt8_server_cfg_t *cfg,
                            int fd, bolt8_state_t *state) {
    unsigned char *msg = (unsigned char *)malloc(MAX_MSG_LEN);
    if (!msg) return 0;

    size_t msg_len = 0;
    if (!bolt8_recv(state, fd, msg, &msg_len, MAX_MSG_LEN)) {
        free(msg);
        return 0;
    }

    if (msg_len < 2) {
        free(msg);
        return 1;  /* ignore undersized messages */
    }

    uint16_t msg_type = read_be16(msg);
    const unsigned char *payload = msg + 2;
    size_t payload_len = msg_len - 2;

    int ok = 1;

    if (msg_type == LSPS0_MSG_REQUEST) {
        /* LSPS0 JSON-RPC request */
        if (cfg->lsps0_request_cb && payload_len > 0) {
            /* Ensure null-terminated JSON */
            char *json = (char *)malloc(payload_len + 1);
            if (json) {
                memcpy(json, payload, payload_len);
                json[payload_len] = '\0';

                char resp_buf[65536];
                int resp_len = cfg->lsps0_request_cb(cfg->cb_userdata, fd, state,
                                                       json, resp_buf, sizeof(resp_buf));
                if (resp_len > 0) {
                    /* Send response: [type=0x9449][json] */
                    size_t resp_msg_len = 2 + (size_t)resp_len;
                    unsigned char *resp_msg = (unsigned char *)malloc(resp_msg_len);
                    if (resp_msg) {
                        write_be16(resp_msg, LSPS0_MSG_RESPONSE);
                        memcpy(resp_msg + 2, resp_buf, (size_t)resp_len);
                        bolt8_send(state, fd, resp_msg, resp_msg_len);
                        free(resp_msg);
                    }
                }
                free(json);
            }
        }
    } else if (msg_type >= 0x51 && msg_type <= 0x57) {
        /* SuperScalar native message types */
        if (cfg->native_msg_cb) {
            ok = cfg->native_msg_cb(cfg->cb_userdata, fd, state,
                                     msg_type, payload, payload_len);
        }
    } else {
        /* Unknown/unsupported message type — ignore (odd type = OK per BOLT) */
        if ((msg_type & 1) == 0) {
            /* Even type = mandatory feature we don't understand: close connection */
            fprintf(stderr, "bolt8_server: unsupported mandatory message type 0x%04x\n",
                    msg_type);
            ok = 0;
        }
    }

    free(msg);
    return ok;
}

/* Per-connection handler — run in a thread or fork */
static void handle_connection(const bolt8_server_cfg_t *cfg, int client_fd) {
    /* BOLT #8 handshake (responder side) */
    bolt8_hs_t hs;

    /* Get our static pubkey for hs_init */
    secp256k1_pubkey static_pub;
    if (!secp256k1_ec_pubkey_create(cfg->ctx, &static_pub, cfg->static_priv)) {
        close(client_fd);
        return;
    }
    unsigned char static_pub33[33];
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(cfg->ctx, static_pub33, &pub_len,
                                   &static_pub, SECP256K1_EC_COMPRESSED);

    bolt8_hs_init(&hs, static_pub33);

    /* Act 1: read from initiator */
    unsigned char act1[BOLT8_ACT1_SIZE];
    {
        ssize_t n = 0, total = 0;
        while (total < BOLT8_ACT1_SIZE) {
            n = read(client_fd, act1 + total, BOLT8_ACT1_SIZE - total);
            if (n <= 0) { close(client_fd); return; }
            total += n;
        }
    }
    if (!bolt8_act1_process(&hs, cfg->ctx, act1, cfg->static_priv)) {
        fprintf(stderr, "bolt8_server: act1 failed\n");
        close(client_fd);
        return;
    }

    /* Act 2: generate ephemeral key and respond */
    unsigned char e_priv[32];
    FILE *rnd = fopen("/dev/urandom", "rb");
    if (!rnd || fread(e_priv, 1, 32, rnd) != 32) {
        if (rnd) fclose(rnd);
        close(client_fd);
        return;
    }
    fclose(rnd);

    unsigned char act2[BOLT8_ACT2_SIZE];
    if (!bolt8_act2_create(&hs, cfg->ctx, e_priv, act2)) {
        secure_zero(e_priv, 32);
        close(client_fd);
        return;
    }
    secure_zero(e_priv, 32);

    {
        ssize_t n = write(client_fd, act2, BOLT8_ACT2_SIZE);
        if (n != BOLT8_ACT2_SIZE) { close(client_fd); return; }
    }

    /* Act 3: read from initiator and derive transport keys */
    unsigned char act3[BOLT8_ACT3_SIZE];
    {
        ssize_t n = 0, total = 0;
        while (total < BOLT8_ACT3_SIZE) {
            n = read(client_fd, act3 + total, BOLT8_ACT3_SIZE - total);
            if (n <= 0) { close(client_fd); return; }
            total += (ssize_t)n;
        }
    }

    bolt8_state_t state;
    if (!bolt8_act3_process(&hs, cfg->ctx, act3, &state)) {
        fprintf(stderr, "bolt8_server: act3 failed\n");
        close(client_fd);
        return;
    }

    /* BOLT #1 init exchange */
    if (!bolt8_init_exchange(&state, client_fd)) {
        close(client_fd);
        return;
    }

    /* Register accepted peer in peer_mgr if configured */
    if (cfg->peer_mgr)
        peer_mgr_accept(cfg->peer_mgr, client_fd);

    /* Message dispatch loop */
    while (bolt8_dispatch_message(cfg, client_fd, &state))
        ;

    secure_zero(&state, sizeof(state));
    close(client_fd);
}

int bolt8_server_run(const bolt8_server_cfg_t *cfg) {
    if (!cfg || cfg->bolt8_port == 0) return 0;

    int srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv_fd < 0) {
        perror("bolt8_server: socket");
        return 0;
    }

    int opt = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(cfg->bolt8_port);

    if (bind(srv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bolt8_server: bind");
        close(srv_fd);
        return 0;
    }

    if (listen(srv_fd, 16) < 0) {
        perror("bolt8_server: listen");
        close(srv_fd);
        return 0;
    }

    fprintf(stderr, "bolt8_server: listening on port %u\n", cfg->bolt8_port);

    while (1) {
        struct sockaddr_in peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        int client_fd = accept(srv_fd, (struct sockaddr *)&peer_addr, &peer_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("bolt8_server: accept");
            break;
        }
        /* Single-threaded: handle inline.
           Production: fork() or pthread_create() here. */
        handle_connection(cfg, client_fd);
    }

    close(srv_fd);
    return 0;
}
