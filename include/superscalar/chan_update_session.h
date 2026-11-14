#ifndef SUPERSCALAR_CHAN_UPDATE_SESSION_H
#define SUPERSCALAR_CHAN_UPDATE_SESSION_H

/* One channel's engine on one connection, as the host and member daemons
 * use it: the engine (chan_update.c), its commitment layer over channel_t
 * (chan_update_ops.c) and its wire form (chan_update_wire.c) over a socket
 * (wire_send / wire_recv).
 *
 * - cu_session_open: a new channel; commitment 0 signed both ways
 *   (MSG_CU_OPEN), then the engine is loaded.
 * - cu_session_resume: an existing channel after a restart or reconnect;
 *   fresh nonces, then channel_reestablish.
 * - cu_session_offer (member) / cu_session_round (host), then
 *   cu_session_wait to run the exchange to its end.
 *
 * Messages on the connection that are not the engine's are kept, in order,
 * for the caller (cu_session_take_other); a full queue fails the call. */

#include "chan_update.h"
#include "chan_update_ops.h"
#include "wire.h"

#define CU_SESSION_OTHER_CAP 64

typedef struct {
    int fd;
    cu_chan_t *c;
    cu_chops_t ops;
    channel_t *ch;
    persist_t *db;
    cu_config_t cfg;
    secp256k1_context *ctx;
    wire_msg_t other[CU_SESSION_OTHER_CAP];
    size_t n_other;
    int last_rc;              /* last engine error seen, CU_OK if none */
} cu_session_t;

enum {
    CU_WAIT_REST    = 1,      /* idle, and (member) no offer pending */
    CU_WAIT_REQUEST = 2,      /* host: at least one member request pending */
};

/* A new channel: per-commitment secrets, nonces, and commitment 0 both ways,
   then cu_create and the engine loaded.  Blocks up to timeout_sec per
   message. */
int cu_session_open(cu_session_t *s, int fd, persist_t *db, const cu_config_t *cfg,
                    channel_t *ch, secp256k1_context *ctx, const cu_state_t *initial,
                    uint32_t tip, int timeout_sec);

/* An existing channel on a new connection: engine from the database, fresh
   nonces, channel_reestablish. */
int cu_session_resume(cu_session_t *s, int fd, persist_t *db, const cu_config_t *cfg,
                      channel_t *ch, secp256k1_context *ctx, uint32_t tip);

/* 1 if type is one of the engine's messages. */
int cu_session_is_msg(uint8_t type);

/* One received engine message: hand it to the engine and send what it
   produced. */
int cu_session_handle(cu_session_t *s, uint8_t type, const cJSON *json);

/* Member: ask the host (add = pay, fulfil, fail).  Host: open a round with
   every pending member request and own updates. */
int cu_session_offer(cu_session_t *s, const cu_update_t *u, size_t n);
int cu_session_round(cu_session_t *s, const cu_update_t *own, size_t n);

/* Receive and handle messages until the channel holds commitment
   min_held or later and cond (CU_WAIT_*) holds; messages that are not the
   engine's are kept.  Returns CU_OK, or the engine's error, or
   CU_ERR_PROTOCOL on a timeout or a closed connection. */
int cu_session_wait(cu_session_t *s, int cond, uint64_t min_held, int timeout_sec);

/* The oldest kept non-engine message (the caller frees its json); 0 if none. */
int cu_session_take_other(cu_session_t *s, wire_msg_t *out);

/* Connection gone: the engine forgets the connection; the session keeps the
   engine for cu_session_resume. */
void cu_session_disconnect(cu_session_t *s);
void cu_session_free(cu_session_t *s);

#endif /* SUPERSCALAR_CHAN_UPDATE_SESSION_H */
