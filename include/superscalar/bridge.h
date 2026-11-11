#ifndef SUPERSCALAR_BRIDGE_H
#define SUPERSCALAR_BRIDGE_H

#include "wire.h"
#include <secp256k1.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>

#define BRIDGE_MAX_PENDING 256
/* Messages kept for the plugin while it is not connected */
#define BRIDGE_PLUGIN_QUEUE_MAX 1024

/* The bridge and the CLN plugin share a secret: 32 random bytes, kept as
   64 hex characters in a file only its owner can read.  It never crosses
   the link.  Each side sends a random nonce and proves it knows the secret
   with HMAC-SHA256(secret, label || plugin nonce || bridge nonce), where
   the label names the side giving the proof:

     plugin -> bridge  {"method":"auth_hello","nonce":<plugin nonce>}
     bridge -> plugin  {"method":"auth_challenge","nonce":<bridge nonce>,
                        "proof":<bridge's proof>}
     plugin -> bridge  {"method":"auth_response","proof":<plugin's proof>}
     bridge -> plugin  {"method":"auth_ok"}

   The plugin checks the bridge's proof before it answers, and the bridge
   treats the connection as the plugin only after the plugin's proof. */
#define BRIDGE_PLUGIN_SECRET_HEX_LEN 64
#define BRIDGE_AUTH_NONCE_LEN        32
#define BRIDGE_AUTH_ROLE_BRIDGE      "bridge"
#define BRIDGE_AUTH_ROLE_PLUGIN      "plugin"
#define BRIDGE_PLUGIN_BIND_DEFAULT   "127.0.0.1"
/* Seconds a new connection has to present the secret. */
#define BRIDGE_PLUGIN_AUTH_TIMEOUT   10

/* Pending inbound HTLC (from CLN plugin, waiting for LSP resolution) */
typedef struct {
    unsigned char payment_hash[32];
    uint64_t htlc_id;
    int pending;
    char upstream_id[64];   /* the plugin's name for the HTLC; "" if none */
} bridge_pending_htlc_t;

typedef struct {
    int lsp_fd;                          /* TCP connection to LSP */
    int plugin_listen_fd;                /* TCP listen socket for CLN plugin */
    int plugin_fd;                       /* Connected, authenticated CLN plugin */

    /* A connection is not the plugin until it has presented the shared
       secret.  Until then it waits here and nothing is read from or sent
       to it as plugin traffic. */
    int plugin_pending_fd;               /* accepted, not yet authenticated */
    time_t plugin_pending_since;
    char plugin_pending_buf[512];        /* its current line, as it arrives */
    size_t plugin_pending_len;
    int plugin_pending_challenged;       /* 1 once our challenge is out */
    unsigned char plugin_nonce_peer[BRIDGE_AUTH_NONCE_LEN];
    unsigned char plugin_nonce_own[BRIDGE_AUTH_NONCE_LEN];
    char plugin_secret[BRIDGE_PLUGIN_SECRET_HEX_LEN + 1];
    int has_plugin_secret;

    bridge_pending_htlc_t pending_inbound[BRIDGE_MAX_PENDING];
    size_t n_pending;                    /* entries currently in use */

    uint64_t next_htlc_id;              /* correlation ID for inbound HTLCs */
    uint64_t next_request_id;           /* correlation ID for outbound pays */

    /* NK (server-authenticated) handshake support */
    secp256k1_pubkey lsp_pubkey;        /* pinned LSP static pubkey */
    char lsp_pubkey_hex[67];            /* the same, as told to the plugin;
                                           "" when no key is pinned */
    int use_nk;                         /* 1 = use NK handshake, 0 = NN fallback */

    /* Finding A defense-in-depth: optional bridge static pubkey advertised
       in BRIDGE_HELLO so the LSP can pin which bridge it expects. Empty
       unless --bridge-pubkey was passed on the CLI. */
    secp256k1_pubkey bridge_pubkey;
    int has_bridge_pubkey;

    /* Heartbeat (bridge reliability) */
    time_t last_lsp_activity;           /* timestamp of last message from LSP */
    int heartbeat_interval;             /* seconds between pings (default 30) */

    /* Reconnection state */
    char lsp_host[256];                 /* saved for reconnect */
    int lsp_port;                       /* saved for reconnect */
    int reconnect_attempts;             /* consecutive failed attempts */

    /* Messages for the plugin that could not be delivered because it was
       not connected, oldest first.  Sent when it is back. */
    char *plugin_queue[BRIDGE_PLUGIN_QUEUE_MAX];
    size_t plugin_queue_len;

    /* Plugin read buffer (avoids 1-byte-at-a-time syscalls) */
    char plugin_read_buf[4096];
    size_t plugin_read_len;             /* valid bytes in buffer */
    size_t plugin_read_pos;             /* current scan position */
} bridge_t;

/* Initialize bridge state. */
void bridge_init(bridge_t *br);

/* Pin LSP static pubkey for NK (server-authenticated) handshake.
   If set, bridge_connect_lsp() uses NK mode instead of NN. */
void bridge_set_lsp_pubkey(bridge_t *br, const secp256k1_pubkey *pk);

/* Set this bridge's own static pubkey to advertise in BRIDGE_HELLO so the
   LSP can pin (Finding A). Without this the bridge runs unpinned; LSPs that
   configured an expected_bridge_pubkey will reject the connection. */
void bridge_set_pubkey(bridge_t *br, const secp256k1_pubkey *pk);

/* Connect bridge to LSP. Sends BRIDGE_HELLO, waits for BRIDGE_HELLO_ACK.
   Returns 1 on success. */
int bridge_connect_lsp(bridge_t *br, const char *lsp_host, int lsp_port);

/* Read the plugin shared secret from `path`, creating the file with a fresh
   random secret (mode 0600) if it does not exist.  An existing file must be
   a regular file owned by this user, not accessible by group or others, and
   hold exactly 64 hex characters.  out_hex receives the secret
   (BRIDGE_PLUGIN_SECRET_HEX_LEN + 1 bytes).  Returns 1 on success. */
int bridge_plugin_secret_load(const char *path, char *out_hex);

/* Set the secret the plugin must present (64 hex characters).
   Returns 1 on success, 0 if the value is malformed. */
int bridge_set_plugin_secret(bridge_t *br, const char *secret_hex);

/* Start listening for the CLN plugin on bind_addr:plugin_port.
   bind_addr NULL or "" means loopback (BRIDGE_PLUGIN_BIND_DEFAULT); it must
   be a literal IPv4 address.  Refuses to listen before a secret is set.
   Returns 1 on success. */
int bridge_listen_plugin(bridge_t *br, const char *bind_addr, int plugin_port);

/* Accept a connection on the plugin port (blocking).  The connection is
   held as pending until it authenticates; it is closed immediately if a
   plugin is already connected or another connection is pending.
   Returns 1 if a connection is now pending, 0 otherwise. */
int bridge_accept_plugin(bridge_t *br);

/* Read what the pending connection has sent and take the handshake one
   step further: answer its auth_hello with our challenge and proof, then
   check the proof in its auth_response in constant time.  Returns 1 once
   it is authenticated (it is then plugin_fd), 0 while the handshake is
   still under way, -1 if the connection was dropped. */
int bridge_service_pending_plugin(bridge_t *br);

/* The proof one side gives: HMAC-SHA256 keyed with the secret over
   "superscalar-bridge-plugin-auth-v1/" role "/" plugin nonce bridge nonce.
   Returns 0 if secret_hex is not a 64-hex secret. */
int bridge_plugin_auth_proof(const char *secret_hex, const char *role,
                              const unsigned char *plugin_nonce,
                              const unsigned char *bridge_nonce,
                              unsigned char proof_out[32]);

/* Drop a pending connection that has not authenticated within
   BRIDGE_PLUGIN_AUTH_TIMEOUT seconds of `now`.  Returns 1 if dropped. */
int bridge_expire_pending_plugin(bridge_t *br, time_t now);

/* Handle a wire message from the LSP (MSG_BRIDGE_*).
   Forwards to plugin as newline-delimited JSON. Returns 1 on success. */
int bridge_handle_lsp_msg(bridge_t *br, const wire_msg_t *msg);

/* Handle a newline-delimited JSON message from the CLN plugin.
   Forwards to LSP as MSG_BRIDGE_*. Returns 1 on success. */
int bridge_handle_plugin_msg(bridge_t *br, const char *line);

/* Read one newline-delimited line from plugin_fd.
   Returns allocated string (caller must free), or NULL on error. */
char *bridge_read_plugin_line(bridge_t *br);

/* Send a message to the plugin.  If the plugin is not connected, or the
   write fails, the message is queued and goes out when the plugin is back
   (bridge_flush_plugin_queue, called after it authenticates).  Returns 1
   once the message is sent or queued. */
int bridge_send_plugin_json(bridge_t *br, cJSON *json);

/* Send queued messages to the connected plugin.  Returns how many went. */
size_t bridge_flush_plugin_queue(bridge_t *br);

/* Read and handle one message from the plugin.  A lost connection or a
   message that cannot be handled drops the plugin connection (it reconnects
   and repeats what matters); pending HTLCs and the queue are kept.
   Returns 1 if a message was handled, 0 if the connection was dropped. */
int bridge_service_plugin(bridge_t *br);

/* Run the bridge event loop (select on lsp_fd + plugin_fd).
   Runs until error or shutdown. Returns 0 on error. */
int bridge_run(bridge_t *br);

/* Add a pending inbound HTLC.  Returns the htlc_id assigned to it (never
   0), or 0 if BRIDGE_MAX_PENDING HTLCs are already pending. */
uint64_t bridge_add_pending(bridge_t *br, const unsigned char *payment_hash32);

/* As bridge_add_pending, for an HTLC the plugin identifies as upstream_id.
   An HTLC that is already pending under the same hash and the same
   (non-empty) identity is the same HTLC offered again and keeps its id. */
uint64_t bridge_add_pending_upstream(bridge_t *br,
                                      const unsigned char *payment_hash32,
                                      const char *upstream_id);

/* Find and free a pending HTLC by payment_hash.  Returns 1 and sets
   *htlc_id_out if one was pending, 0 otherwise. */
int bridge_resolve_pending(bridge_t *br, const unsigned char *payment_hash32,
                             uint64_t *htlc_id_out);

/* Free the pending HTLC with this htlc_id (the LSP resolved it).
   Returns 1 if it was pending. */
int bridge_release_pending(bridge_t *br, uint64_t htlc_id);

/* Set heartbeat interval in seconds (default 30). */
void bridge_set_heartbeat(bridge_t *br, int interval_sec);

/* Check if LSP connection is stale (no activity within heartbeat_interval).
   Returns 1 if stale, 0 if healthy. */
int bridge_is_stale(const bridge_t *br);

/* Attempt to reconnect to LSP. Returns 1 on success. */
int bridge_reconnect_lsp(bridge_t *br);

/* Cleanup */
void bridge_cleanup(bridge_t *br);

#endif /* SUPERSCALAR_BRIDGE_H */
