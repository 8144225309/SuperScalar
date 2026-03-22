/*
 * peer_mgr.h — External peer connection manager
 *
 * Manages connections to standard LN peers (not factory participants).
 * Performs BOLT #8 handshake + BOLT #1 init exchange.
 *
 * Reference: CLN connectd/connectd.c, LND server.go, LDK PeerManager.
 */

#ifndef SUPERSCALAR_PEER_MGR_H
#define SUPERSCALAR_PEER_MGR_H

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>
#include "bolt8.h"
#include "gossip_store.h"
#include "channel.h"

#define PEER_MGR_MAX_PEERS  64

typedef struct {
    unsigned char pubkey[33];
    char          host[256];
    uint16_t      port;
    int           fd;
    bolt8_state_t bolt8;
    int           initiated;         /* 1 = we connected outbound */
    uint32_t      connected_at;      /* Unix timestamp */
    int           has_channel;       /* 1 if a channel is open with this peer */
    uint16_t      peer_features;     /* features from their BOLT #1 init */
    uint64_t      channel_scid;      /* short_channel_id of open channel (0=none) */
    /* Phase O: reconnect state */
    uint32_t      disconnected_at;   /* Unix ts of disconnect; 0 = connected */
    int           reconnect_attempts;
    uint32_t      next_reconnect_at; /* earliest time to retry */
    unsigned char saved_pubkey[33];  /* preserved across disconnect */
    char          saved_host[256];   /* preserved across disconnect */
    uint16_t      saved_port;
} peer_entry_t;

typedef struct {
    peer_entry_t      peers[PEER_MGR_MAX_PEERS];
    int               count;
    secp256k1_context *ctx;
    unsigned char     our_privkey[32];
    unsigned char     our_pubkey[33];
    volatile int      *shutdown_flag; /* set to non-zero to stop accept loop */
    char              tor_proxy_host[256];
    int               tor_proxy_port; /* 0 = no proxy configured */
    gossip_store_t    *gs;             /* gossip store for timestamp filter (NULL=disabled) */
} peer_mgr_t;

/*
 * Initialise a peer_mgr_t.
 * our_privkey: 32-byte node static private key.
 * ctx: secp256k1 context with SIGN|VERIFY.
 */
int peer_mgr_init(peer_mgr_t *mgr, secp256k1_context *ctx,
                  const unsigned char our_privkey[32]);

/*
 * Connect to a peer, run BOLT #8 handshake and BOLT #1 init.
 * Returns peer index (0..PEER_MGR_MAX_PEERS-1) on success, -1 on failure.
 */
int peer_mgr_connect(peer_mgr_t *mgr, const char *host, uint16_t port,
                     const unsigned char their_pub33[33]);

/*
 * Accept an inbound peer connection (called from an accept() loop).
 * fd: already-accepted socket file descriptor.
 * Returns peer index on success, -1 on failure.
 */
int peer_mgr_accept(peer_mgr_t *mgr, int fd);

/*
 * Send a BOLT #8-framed message to a peer.
 * Returns 1 on success, 0 on I/O error.
 */
int peer_mgr_send(peer_mgr_t *mgr, int peer_idx,
                  const unsigned char *msg, size_t len);

/*
 * Receive a BOLT #8-framed message from a peer (blocking).
 * msg_out must be at least max_len bytes.
 * Returns 1 on success, 0 on I/O or decryption error.
 */
int peer_mgr_recv(peer_mgr_t *mgr, int peer_idx,
                  unsigned char *msg_out, size_t *msg_len_out, size_t max_len);

/*
 * Disconnect a peer and clean up state.
 */
void peer_mgr_disconnect(peer_mgr_t *mgr, int peer_idx);

/*
 * Find a peer by pubkey.
 * Returns peer index, or -1 if not connected.
 */
int peer_mgr_find(const peer_mgr_t *mgr, const unsigned char pubkey33[33]);

/*
 * Find a connected peer by its short_channel_id.
 * Returns peer index, or -1 if not found.
 */
int peer_mgr_find_by_scid(const peer_mgr_t *mgr, uint64_t scid);

/*
 * Mark a peer as transiently disconnected (close fd, set reconnect timer).
 * Slot is retained; peer will be reconnected by peer_mgr_reconnect_all().
 */
void peer_mgr_mark_disconnected(peer_mgr_t *mgr, int peer_idx,
                                 uint32_t backoff_secs);

/*
 * Attempt to reconnect all disconnected peers whose next_reconnect_at <= now.
 * Runs BOLT #8 + BOLT #1 init on success. ch_table[peer_idx] if non-NULL
 * triggers chan_reestablish after reconnect. Returns reconnected count.
 */
int peer_mgr_reconnect_all(peer_mgr_t *mgr, channel_t **ch_table, uint32_t now);

/*
 * Configure a SOCKS5 proxy for outbound .onion connections.
 * host: proxy hostname (e.g. "127.0.0.1"), port: proxy port (e.g. 9050).
 * Set port=0 to disable proxy.
 */
void peer_mgr_set_proxy(peer_mgr_t *mgr, const char *host, int port);

#endif /* SUPERSCALAR_PEER_MGR_H */
