#ifndef SUPERSCALAR_BRIDGE_H
#define SUPERSCALAR_BRIDGE_H

#include "wire.h"
#include <stdint.h>
#include <stddef.h>

#define BRIDGE_MAX_PENDING 32

/* Pending inbound HTLC (from CLN plugin, waiting for LSP resolution) */
typedef struct {
    unsigned char payment_hash[32];
    uint64_t htlc_id;
    int pending;
} bridge_pending_htlc_t;

typedef struct {
    int lsp_fd;                          /* TCP connection to LSP */
    int plugin_listen_fd;                /* TCP listen socket for CLN plugin */
    int plugin_fd;                       /* Connected CLN plugin socket */

    bridge_pending_htlc_t pending_inbound[BRIDGE_MAX_PENDING];
    size_t n_pending;

    uint64_t next_htlc_id;              /* correlation ID for inbound HTLCs */
    uint64_t next_request_id;           /* correlation ID for outbound pays */
} bridge_t;

/* Initialize bridge state. */
void bridge_init(bridge_t *br);

/* Connect bridge to LSP. Sends BRIDGE_HELLO, waits for BRIDGE_HELLO_ACK.
   Returns 1 on success. */
int bridge_connect_lsp(bridge_t *br, const char *lsp_host, int lsp_port);

/* Start listening for CLN plugin connections on plugin_port.
   Returns 1 on success. */
int bridge_listen_plugin(bridge_t *br, int plugin_port);

/* Accept a plugin connection (blocking). Returns 1 on success. */
int bridge_accept_plugin(bridge_t *br);

/* Handle a wire message from the LSP (MSG_BRIDGE_*).
   Forwards to plugin as newline-delimited JSON. Returns 1 on success. */
int bridge_handle_lsp_msg(bridge_t *br, const wire_msg_t *msg);

/* Handle a newline-delimited JSON message from the CLN plugin.
   Forwards to LSP as MSG_BRIDGE_*. Returns 1 on success. */
int bridge_handle_plugin_msg(bridge_t *br, const char *line);

/* Read one newline-delimited line from plugin_fd.
   Returns allocated string (caller must free), or NULL on error. */
char *bridge_read_plugin_line(bridge_t *br);

/* Send newline-delimited JSON to plugin.
   Returns 1 on success. */
int bridge_send_plugin_json(bridge_t *br, cJSON *json);

/* Run the bridge event loop (select on lsp_fd + plugin_fd).
   Runs until error or shutdown. Returns 0 on error. */
int bridge_run(bridge_t *br);

/* Add a pending inbound HTLC. Returns assigned htlc_id. */
uint64_t bridge_add_pending(bridge_t *br, const unsigned char *payment_hash32);

/* Find and remove a pending HTLC by payment_hash. Returns htlc_id, or -1. */
int bridge_resolve_pending(bridge_t *br, const unsigned char *payment_hash32,
                             uint64_t *htlc_id_out);

/* Cleanup */
void bridge_cleanup(bridge_t *br);

#endif /* SUPERSCALAR_BRIDGE_H */
