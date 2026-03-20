/*
 * peer_mgr.c — External peer connection manager
 *
 * Manages outbound and inbound BOLT #8 connections to LN peers.
 * Handles handshake, init exchange, and bookkeeping.
 *
 * Reference: CLN connectd/connectd.c, LND server.go, LDK PeerManager.
 */

#include "superscalar/peer_mgr.h"
#include "superscalar/gossip.h"
#include "superscalar/chan_open.h"
#include <time.h>
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
    /* Send gossip_timestamp_filter to bootstrap routing graph sync */
    if (mgr->gs) {
        unsigned char ts_filter[42];
        uint32_t first_ts = (uint32_t)((uint32_t)time(NULL) > 14*24*3600
                                        ? (uint32_t)time(NULL) - 14*24*3600 : 0);
        size_t ts_len = gossip_build_timestamp_filter(
            ts_filter, sizeof(ts_filter),
            GOSSIP_CHAIN_HASH_MAINNET, first_ts, 0xFFFFFFFFu);
        if (ts_len == 42)
            peer_mgr_send(mgr, idx, ts_filter, ts_len);
    }
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

int peer_mgr_find_by_scid(const peer_mgr_t *mgr, uint64_t scid)
{
    if (!mgr || scid == 0) return -1;
    for (int i = 0; i < mgr->count; i++) {
        if (mgr->peers[i].fd >= 0 &&
            mgr->peers[i].channel_scid == scid)
            return i;
    }
    return -1;
}

void peer_mgr_mark_disconnected(peer_mgr_t *mgr, int peer_idx,
                                  uint32_t backoff_secs)
{
    if (!mgr || peer_idx < 0 || peer_idx >= mgr->count) return;
    peer_entry_t *p = &mgr->peers[peer_idx];
    if (p->fd >= 0) { close(p->fd); p->fd = -1; }
    memcpy(p->saved_pubkey, p->pubkey, 33);
    strncpy(p->saved_host, p->host, sizeof(p->saved_host) - 1);
    p->saved_port = p->port;
    p->disconnected_at = (uint32_t)time(NULL);
    p->reconnect_attempts++;
    uint32_t back = backoff_secs < 1   ? 1   :
                    backoff_secs > 300 ? 300 : backoff_secs;
    p->next_reconnect_at = p->disconnected_at + back;
}

int peer_mgr_reconnect_all(peer_mgr_t *mgr, channel_t **ch_table, uint32_t now)
{
    if (!mgr) return 0;
    int reconnected = 0;
    for (int i = 0; i < mgr->count; i++) {
        peer_entry_t *p = &mgr->peers[i];
        if (p->fd >= 0) continue;                    /* already connected */
        if (p->disconnected_at == 0) continue;       /* never disconnected */
        if (now < p->next_reconnect_at) continue;    /* too early */

        /* Attempt TCP + BOLT #8 reconnect */
        int fd = tcp_connect(p->saved_host, p->saved_port);
        if (fd < 0) {
            /* back off further */
            uint32_t back = 5u << (p->reconnect_attempts < 6
                                   ? (unsigned)p->reconnect_attempts : 6u);
            if (back > 300) back = 300;
            p->next_reconnect_at = now + back;
            p->reconnect_attempts++;
            continue;
        }

        /* Run BOLT #8 outbound (initiator) handshake */
        {
            int hs_ok = 0;
            unsigned char eph[32], act1[BOLT8_ACT1_SIZE];
            unsigned char act2[BOLT8_ACT2_SIZE], act3[BOLT8_ACT3_SIZE];
            bolt8_hs_t hs;
            bolt8_state_t new_st;
            FILE *rnd = fopen("/dev/urandom", "rb");
            if (rnd && fread(eph, 1, 32, rnd) == 32) {
                fclose(rnd); rnd = NULL;
                bolt8_hs_init(&hs, p->saved_pubkey);
                if (bolt8_act1_create(&hs, mgr->ctx, eph, p->saved_pubkey, act1) &&
                    send(fd, act1, BOLT8_ACT1_SIZE, 0) == BOLT8_ACT1_SIZE &&
                    recv(fd, act2, BOLT8_ACT2_SIZE, MSG_WAITALL) == BOLT8_ACT2_SIZE &&
                    bolt8_act2_process(&hs, mgr->ctx, act2) &&
                    bolt8_act3_create(&hs, mgr->ctx, mgr->our_privkey, act3, &new_st) &&
                    send(fd, act3, BOLT8_ACT3_SIZE, 0) == BOLT8_ACT3_SIZE &&
                    bolt8_init_exchange(&new_st, fd)) {
                    p->bolt8 = new_st;
                    hs_ok = 1;
                }
            }
            if (rnd) fclose(rnd);
            if (!hs_ok) {
                close(fd);
                uint32_t back = 5u << (p->reconnect_attempts < 6
                                       ? (unsigned)p->reconnect_attempts : 6u);
                if (back > 300) back = 300;
                p->next_reconnect_at = now + back;
                p->reconnect_attempts++;
                continue;
            }
        }

        /* Success */
        p->fd = fd;
        memcpy(p->pubkey, p->saved_pubkey, 33);
        strncpy(p->host, p->saved_host, sizeof(p->host) - 1);
        p->port = p->saved_port;
        p->disconnected_at   = 0;
        p->reconnect_attempts = 0;
        reconnected++;

        /* Channel reestablish if we have a channel with this peer */
        if (p->has_channel && ch_table && ch_table[i])
            chan_reestablish(mgr, i, mgr->ctx, ch_table[i]);
        /* Send gossip_timestamp_filter to re-bootstrap routing graph */
        if (mgr->gs) {
            unsigned char ts_filter[42];
            uint32_t first_ts = (uint32_t)(now > 14*24*3600
                                            ? now - 14*24*3600 : 0);
            size_t ts_len = gossip_build_timestamp_filter(
                ts_filter, sizeof(ts_filter),
                GOSSIP_CHAIN_HASH_MAINNET, first_ts, 0xFFFFFFFFu);
            if (ts_len == 42)
                peer_mgr_send(mgr, i, ts_filter, ts_len);
        }
    }
    return reconnected;
}
