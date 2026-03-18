#ifndef SUPERSCALAR_BOLT8_SERVER_H
#define SUPERSCALAR_BOLT8_SERVER_H

/*
 * BOLT #8 + BOLT #1 server: TCP accept loop for inbound LN peer connections.
 *
 * Handles:
 *   - Noise_XK handshake (bolt8.c)
 *   - BOLT #1 init message exchange (feature bits 729 + 759)
 *   - Message dispatch by wire type:
 *       0x9451 (37969): LSPS0 request → lsps_handle_request()
 *       0x51–0x57:      SuperScalar native → existing wire handler
 */

#include <stddef.h>
#include <stdint.h>
#include <secp256k1.h>
#include "superscalar/bolt8.h"
#include "superscalar/peer_mgr.h"

/* Feature bits advertised in BOLT #1 init message */
#define BOLT8_FEATURE_BIT_LSPS0       729   /* odd = optional, LSPS0 support */
#define BOLT8_FEATURE_BIT_SUPERSCALAR 759   /* odd = optional, native protocol available */

/* BOLT #1 message type */
#define BOLT1_MSG_INIT  16

/* LSPS0 message types (BOLT #8 framed) */
#define LSPS0_MSG_REQUEST  0x9451   /* 37969 */
#define LSPS0_MSG_RESPONSE 0x9449   /* 37961 */

/* Server configuration */
typedef struct {
    uint16_t bolt8_port;            /* TCP port for BOLT #8 connections (default 9735) */
    unsigned char static_priv[32];  /* node static private key */
    secp256k1_context *ctx;         /* secp256k1 context (not owned) */

    /* If set, accepted peers are registered in this peer_mgr (not owned) */
    peer_mgr_t *peer_mgr;

    /* If set, BOLT #2 messages (types 128-135) are routed here inline.
     * bolt8_server exclusively owns inbound fds; routing happens in the
     * bolt8_dispatch_message loop to avoid a double-read race with ln_dispatch_run.
     * Stored as void* to avoid circular header dependency; cast to ln_dispatch_t*. */
    void *ln_dispatch;

    /* Callbacks for inbound messages */
    void *cb_userdata;
    /* Called for LSPS0 requests; json_req is null-terminated JSON.
       Write response JSON to resp_buf (resp_cap bytes max). Return bytes written. */
    int (*lsps0_request_cb)(void *userdata, int fd, bolt8_state_t *state,
                             const char *json_req, char *resp_buf, size_t resp_cap);
    /* Called for SuperScalar native messages (type 0x51–0x57).
       msg_type is the 2-byte wire type, payload excludes the type bytes. */
    int (*native_msg_cb)(void *userdata, int fd, bolt8_state_t *state,
                          uint16_t msg_type, const unsigned char *payload, size_t payload_len);
} bolt8_server_cfg_t;

/* Start the BOLT #8 accept loop (blocking — call from a dedicated thread).
   Returns only on fatal error. */
int bolt8_server_run(const bolt8_server_cfg_t *cfg);

/* --- Lower-level helpers (used by bolt8_server_run and tests) --- */

/* Exchange BOLT #1 init messages on an already-handshaked connection.
   Sends our init (with feature bits 729 + 759), reads peer's init.
   Returns 1 on success, 0 on I/O or parse error. */
int bolt8_init_exchange(bolt8_state_t *state, int fd);

/* Read one BOLT #8 framed message and dispatch it.
   Returns 1 to continue reading, 0 to close connection. */
int bolt8_dispatch_message(const bolt8_server_cfg_t *cfg,
                            int fd, bolt8_state_t *state);

#endif /* SUPERSCALAR_BOLT8_SERVER_H */
