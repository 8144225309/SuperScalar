#ifndef SUPERSCALAR_LSP_CHANNELS_INTERNAL_H
#define SUPERSCALAR_LSP_CHANNELS_INTERNAL_H

#include "lsp_channels.h"
#include "lsp.h"

/* Shared helpers used across lsp_channels split modules.
   These are internal to the LSP channel subsystem — not public API. */

/* Send the LSP's own revocation secret to a client after each commitment update.
   Enables bidirectional revocation so clients can detect LSP breaches. */
void lsp_send_revocation(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                         size_t client_idx, uint64_t old_cn);

/* Fail client_idx's channel (channel_t.revocation_failed): mark it, persist
   the mark, tell the client (MSG_ERROR, WIRE_ERROR_CHANNEL_FAILED) and
   disconnect it (lsp may be NULL).  Nothing more is signed for the
   channel, no preimage is revealed to it and its messages are dropped; it
   must be closed on chain.  recoverable: the only problem is a missing or
   invalid revocation of the commitment before the current one, which the
   client may still deliver on reconnect (lsp_channels_take_late_revocation
   then restores the channel); a later non-recoverable failure overrides. */
void lsp_channels_fail_channel(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                               size_t client_idx, const char *reason,
                               int recoverable);

/* Watch, on client_idx's commitment in its current state, every HTLC the
   client offered us (sweeper_watch_htlc), since the client may never
   revoke that commitment.  A preimage learned later then arms the claim
   there too (lsp_channels_register_htlc_claim); a valid revocation drops
   the watches.  Returns 0 if one could not be stored. */
int lsp_channels_watch_commitment(lsp_channel_mgr_t *mgr, size_t client_idx);

/* The client's answer (ack: NULL if none came) to our commitment_signed
   for its channel.  A valid REVOKE_AND_ACK: the secret is stored, the
   claims and watches on the revoked commitment dropped, *next_pcp_out set,
   and 1 returned.  Otherwise 0, and the channel is failed if the answer
   was invalid, or missing with missing_is_fatal set.  On 0 the caller
   must not record a next point nor send the LSP revocation.  Updates use
   lsp_channels_update_revoke, which wraps this. */
int lsp_channels_take_revocation(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                 size_t client_idx, const wire_msg_t *ack,
                                 int missing_is_fatal,
                                 secp256k1_pubkey *next_pcp_out);

/* One update of a client's commitment, as the LSP drives it.  Every path
   that replaces a client commitment goes through these, so that none can
   skip the watches or the strict revocation check:
     lsp_channels_update_begin   before the channel changes: refuses a
                                 failed channel, watches the HTLCs the
                                 client offered on the commitment about to
                                 be replaced, and keeps what it holds (for
                                 the watchtower once it is revoked, and to
                                 undo a refused update);
     (the caller changes the channel and sends its update message)
     lsp_channels_update_sign    signs the new commitment and sends
                                 COMMITMENT_SIGNED;
     lsp_channels_update_revoke  takes the client's answer;
     lsp_channels_update_end     frees what begin kept.
   A JIT channel (lsp_channels_update_begin_jit) is not in the sweeper's
   channel lookup: it gets the strict revocation check, no watches. */
typedef struct {
    size_t     idx;         /* client index (its fd slot) */
    channel_t *ch;
    int        jit;
    uint32_t   chan_id;     /* channel id on the wire */
    uint32_t   wt_id;       /* watchtower channel id */
    uint64_t   cn;          /* number of the commitment replaced */
    int        undone;      /* set by lsp_channels_update_sign: refused,
                               the channel is back as begin found it */
    uint64_t   local, remote;
    htlc_t    *htlcs;
    size_t     n_htlcs;
    ptlc_t    *ptlcs;
    size_t     n_ptlcs;
} lsp_update_t;

int lsp_channels_update_begin(lsp_channel_mgr_t *mgr, size_t client_idx,
                              lsp_update_t *u);
int lsp_channels_update_begin_jit(lsp_channel_mgr_t *mgr, size_t client_idx,
                                  channel_t *jit_ch, uint32_t chan_id,
                                  lsp_update_t *u);

/* Sign the client's commitment in its current state and send
   COMMITMENT_SIGNED.  First the HTLCs the client offered on it are
   watched, and its number and txid recorded on disk (lsp_channel_entry_t
   signed_cn): the LSP never signs a different commitment at a number it
   has signed, since the client would then hold two signed commitments at
   one number, one unwatched and, once that number is revoked,
   unpunishable.  Such an update (on a channel behind a commitment the LSP
   signed: rolled back on reconnect, or reloaded after a restart) is
   refused instead: nothing is sent, the channel is put back as
   lsp_channels_update_begin found it and u->undone is set; the channel is
   not failed.  Returns 1 if sent. */
int lsp_channels_update_sign(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                             lsp_update_t *u);

/* Resend the commitment_signed of client_idx's current commitment with
   fresh nonces (reconnect), only if it is the very commitment signed at
   that number (also to a recoverably failed channel).  Returns 1 if sent. */
int lsp_channels_resend_commitment_signed(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                          size_t client_idx);

/* The client's answer (ack: NULL if none came) to lsp_channels_update_sign.
   On a valid revocation (lsp_channels_take_revocation) the replaced
   commitment goes to the watchtower, the next point is stored and
   persisted, and the LSP's own revocation is sent: returns 1.  Otherwise
   0 and none of that is done; the channel is failed if the answer was
   invalid, or missing with missing_is_fatal.  A missing answer leaves no
   next point, so nothing more can be signed for the channel until the
   revocation comes on reconnect (lsp_channels_take_late_revocation). */
int lsp_channels_update_revoke(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                               lsp_update_t *u, const wire_msg_t *ack,
                               int missing_is_fatal);
void lsp_channels_update_end(lsp_update_t *u);

/* A revocation of the commitment before client_idx's current one that
   arrives on reconnect, answering lsp_channels_resend_commitment_signed.
   Verified like lsp_channels_update_revoke; a valid one also restores a
   recoverably failed channel.  Returns 1 if valid. */
int lsp_channels_take_late_revocation(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                      size_t client_idx, const wire_msg_t *ack);

/* Free what updates still waiting for a revocation keep (cleanup and
   rotation). */
void lsp_channels_drop_pending_updates(lsp_channel_mgr_t *mgr);

/* Make the preimage of HTLC htlc_id, which client idx offered us,
   claimable on chain: watch and arm its claim on every commitment of the
   channel that holds it.  If that fails the preimage is stored on disk
   (lsp_channels_retry_pending_preimages arms it later) and the channel
   fails, so that it is never revealed to the client.  Returns 1 if armed
   (or nothing to claim on chain), 0 otherwise. */
int lsp_channels_secure_preimage(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                 size_t idx, uint64_t htlc_id,
                                 const unsigned char *preimage32);

/* Settle HTLC htlc_id, which client idx offered us, with its preimage:
   secure it (above), then fulfil it off chain with a full update whose
   missing revocation is fatal.  A failed channel is only secured, never
   told the preimage.  Returns 1 if the HTLC is fulfilled or claimable,
   0 if it could not be secured (the channel then failed, the preimage is
   on disk). */
int lsp_channels_settle_received(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                 size_t idx, uint64_t htlc_id,
                                 const unsigned char *preimage32);

/* Retry arming the claims whose preimages lsp_channels_secure_preimage
   stored; drop the ones armed or whose HTLC is gone (daemon cycle). */
void lsp_channels_retry_pending_preimages(lsp_channel_mgr_t *mgr);

/* A bridge message read while a client update waits (bmsg->json is
   taken): a heartbeat is answered, anything else queued for
   lsp_channels_drain_deferred_bridge, which handles the queue in order
   from the daemon loop, outside any update and its DB transaction.  A
   successful pay result has its on-chain claim armed at once when it can
   be. */
void lsp_channels_defer_bridge_msg(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                   wire_msg_t *bmsg);
void lsp_channels_drain_deferred_bridge(lsp_channel_mgr_t *mgr, lsp_t *lsp);
void lsp_channels_free_deferred_bridge(lsp_channel_mgr_t *mgr);

/* Wait up to timeout_sec for a message of type expected from client
   client_idx, servicing the bridge meanwhile.  Benign messages the client
   may send at any time (PONG, QUEUE_POLL, REGISTER_INVOICE, ...) are
   handled and the wait goes on; anything else is dropped.  Returns 1 with
   *msg set, 0 on timeout, disconnect or MSG_ERROR. */
int lsp_channels_recv_expected(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                               size_t client_idx, wire_msg_t *msg,
                               uint8_t expected, int timeout_sec);

/* Rotation retry helpers.
   Returns:  1 = ready to retry, -1 = max retries exhausted (fallback),
             0 = no action (not attempted, or delay not elapsed, or already handled). */
int lsp_rotation_should_retry(const lsp_channel_mgr_t *mgr,
                              uint32_t factory_id, uint32_t cur_height);

/* Record a failed rotation attempt (increments count, saves block height). */
void lsp_rotation_record_failure(lsp_channel_mgr_t *mgr,
                                 uint32_t factory_id, uint32_t cur_height);

/* 1 if every client is ready to rotate, except those whose channel
   failed: they stay in the old factory (it is closed on chain) and do not
   hold back the rotation of the others. */
int lsp_rotation_clients_ready(const lsp_channel_mgr_t *mgr);

/* Record a successful rotation (resets retry state). */
void lsp_rotation_record_success(lsp_channel_mgr_t *mgr, uint32_t factory_id);

#endif /* SUPERSCALAR_LSP_CHANNELS_INTERNAL_H */
