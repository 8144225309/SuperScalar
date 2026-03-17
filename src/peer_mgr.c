/*
 * peer_mgr.c — External peer connection manager
 *
 * Manages outbound and inbound BOLT #8 connections to LN peers.
 * Handles handshake, init exchange, and bookkeeping.
 *
 * Reference: CLN connectd/connectd.c, LND server.go, LDK PeerManager.
 */

#include "superscalar/peer_mgr.h"
#include "superscalar/bolt8.h"
#include "superscalar/tor.h"
#include "superscalar/bolt8_server.h"   /* bolt8_init_exchange */
#include <secp256k1.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>

int peer_mgr_init(peer_mgr_t *mgr, secp256k1_context *ctx,
                  const unsigned char our_privkey[32]) {
    if (!mgr || !ctx || !our_privkey) return 0;
    memset(mgr, 0, sizeof(*mgr));
    mgr->ctx = ctx;
    memcpy(mgr->our_privkey, our_privkey, 32);

    /* Derive our pubkey */
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(ctx, &pub, our_privkey)) return 0;
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, mgr->our_pubkey, &pub_len,
                                  &pub, SECP256K1_EC_COMPRESSED);
    return 1;
}

/* Open a TCP connection to host:port, returns fd or -1 */
static int tcp_connect(const char *host, uint16_t port) {
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;

    int fd = -1;
    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

int peer_mgr_connect(peer_mgr_t *mgr, const char *host, uint16_t port,
                     const unsigned char their_pub33[33]) {
    if (!mgr || !host || !their_pub33) return -1;
    if (mgr->count >= PEER_MGR_MAX_PEERS) return -1;

    /* Check if already connected */
    int existing = peer_mgr_find(mgr, their_pub33);
    if (existing >= 0) return existing;

    int fd;
    int is_onion = (strstr(host, ".onion") != NULL);
    if (is_onion && mgr->tor_proxy_port > 0)
        fd = tor_connect_socks5(mgr->tor_proxy_host, mgr->tor_proxy_port, host, port);
    else
        fd = tcp_connect(host, port);
    if (fd < 0) {
        fprintf(stderr, "peer_mgr: connect to %s:%u failed: %s\n",
                host, port, strerror(errno));
        return -1;
    }

    /* Generate ephemeral key from /dev/urandom */
    unsigned char eph_priv[32];
    {
        FILE *f = fopen("/dev/urandom", "rb");
        if (!f || fread(eph_priv, 1, 32, f) != 32) {
            if (f) fclose(f);
            close(fd);
            return -1;
        }
        fclose(f);
    }

    /* BOLT #8 initiator handshake */
    bolt8_hs_t hs;
    bolt8_hs_init(&hs, their_pub33);

    unsigned char act1[BOLT8_ACT1_SIZE];
    if (!bolt8_act1_create(&hs, mgr->ctx, eph_priv, their_pub33, act1)) {
        close(fd); return -1;
    }
    if (send(fd, act1, BOLT8_ACT1_SIZE, 0) != BOLT8_ACT1_SIZE) {
        close(fd); return -1;
    }

    unsigned char act2[BOLT8_ACT2_SIZE];
    if (recv(fd, act2, BOLT8_ACT2_SIZE, MSG_WAITALL) != BOLT8_ACT2_SIZE) {
        close(fd); return -1;
    }
    if (!bolt8_act2_process(&hs, mgr->ctx, act2)) { close(fd); return -1; }

    unsigned char act3[BOLT8_ACT3_SIZE];
    bolt8_state_t state;
    if (!bolt8_act3_create(&hs, mgr->ctx, mgr->our_privkey, act3, &state)) {
        close(fd); return -1;
    }
    if (send(fd, act3, BOLT8_ACT3_SIZE, 0) != BOLT8_ACT3_SIZE) {
        close(fd); return -1;
    }

    /* BOLT #1 init exchange */
    if (!bolt8_init_exchange(&state, fd)) { close(fd); return -1; }

    /* Add to table */
    int idx = mgr->count++;
    peer_entry_t *p = &mgr->peers[idx];
    memset(p, 0, sizeof(*p));
    memcpy(p->pubkey, their_pub33, 33);
    strncpy(p->host, host, sizeof(p->host) - 1);
    p->port       = port;
    p->fd         = fd;
    p->bolt8      = state;
    p->initiated  = 1;
    return idx;
}

int peer_mgr_accept(peer_mgr_t *mgr, int fd) {
    if (!mgr || fd < 0) return -1;
    if (mgr->count >= PEER_MGR_MAX_PEERS) { close(fd); return -1; }

    /* Generate ephemeral key */
    unsigned char eph_priv[32];
    {
        FILE *f = fopen("/dev/urandom", "rb");
        if (!f || fread(eph_priv, 1, 32, f) != 32) {
            if (f) fclose(f);
            close(fd);
            return -1;
        }
        fclose(f);
    }

    bolt8_hs_t hs;
    bolt8_hs_init(&hs, mgr->our_pubkey);

    /* Receive act1 */
    unsigned char act1[BOLT8_ACT1_SIZE];
    if (recv(fd, act1, BOLT8_ACT1_SIZE, MSG_WAITALL) != BOLT8_ACT1_SIZE) {
        close(fd); return -1;
    }
    if (!bolt8_act1_process(&hs, mgr->ctx, act1, mgr->our_privkey)) {
        close(fd); return -1;
    }

    /* Send act2 */
    unsigned char act2[BOLT8_ACT2_SIZE];
    if (!bolt8_act2_create(&hs, mgr->ctx, eph_priv, act2)) {
        close(fd); return -1;
    }
    if (send(fd, act2, BOLT8_ACT2_SIZE, 0) != BOLT8_ACT2_SIZE) {
        close(fd); return -1;
    }

    /* Receive act3 */
    unsigned char act3[BOLT8_ACT3_SIZE];
    if (recv(fd, act3, BOLT8_ACT3_SIZE, MSG_WAITALL) != BOLT8_ACT3_SIZE) {
        close(fd); return -1;
    }
    bolt8_state_t state;
    if (!bolt8_act3_process(&hs, mgr->ctx, act3, &state)) {
        close(fd); return -1;
    }

    /* Init exchange */
    if (!bolt8_init_exchange(&state, fd)) { close(fd); return -1; }

    int idx = mgr->count++;
    peer_entry_t *p = &mgr->peers[idx];
    memset(p, 0, sizeof(*p));
    /* Initiator's static pubkey was established during act3 processing.
     * We store zeros here; caller can update after reading channel_announcement. */
    p->fd       = fd;
    p->bolt8    = state;
    p->initiated = 0;
    return idx;
}

int peer_mgr_send(peer_mgr_t *mgr, int peer_idx,
                  const unsigned char *msg, size_t len) {
    if (!mgr || peer_idx < 0 || peer_idx >= mgr->count) return 0;
    if (!msg || len == 0) return 0;
    return bolt8_send(&mgr->peers[peer_idx].bolt8,
                      mgr->peers[peer_idx].fd, msg, len);
}

int peer_mgr_recv(peer_mgr_t *mgr, int peer_idx,
                  unsigned char *msg_out, size_t *msg_len_out, size_t max_len) {
    if (!mgr || peer_idx < 0 || peer_idx >= mgr->count) return 0;
    if (!msg_out || !msg_len_out) return 0;
    return bolt8_recv(&mgr->peers[peer_idx].bolt8,
                      mgr->peers[peer_idx].fd,
                      msg_out, msg_len_out, max_len);
}

void peer_mgr_disconnect(peer_mgr_t *mgr, int peer_idx) {
    if (!mgr || peer_idx < 0 || peer_idx >= mgr->count) return;
    peer_entry_t *p = &mgr->peers[peer_idx];
    if (p->fd >= 0) { close(p->fd); p->fd = -1; }

    /* Compact table */
    if (peer_idx < mgr->count - 1)
        memmove(&mgr->peers[peer_idx], &mgr->peers[peer_idx + 1],
                (size_t)(mgr->count - peer_idx - 1) * sizeof(peer_entry_t));
    mgr->count--;
}

int peer_mgr_find(const peer_mgr_t *mgr, const unsigned char pubkey33[33]) {
    if (!mgr || !pubkey33) return -1;
    for (int i = 0; i < mgr->count; i++) {
        if (memcmp(mgr->peers[i].pubkey, pubkey33, 33) == 0) return i;
    }
    return -1;
}

void peer_mgr_set_proxy(peer_mgr_t *mgr, const char *host, int port) {
    if (!mgr) return;
    if (host)
        strncpy(mgr->tor_proxy_host, host, sizeof(mgr->tor_proxy_host) - 1);
    mgr->tor_proxy_port = port;
}
