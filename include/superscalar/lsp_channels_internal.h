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
   the mark and disconnect the client (lsp may be NULL).  Nothing more is
   signed for the channel, no preimage is revealed to it, its messages are
   dropped and its reconnects refused; it must be closed on chain. */
void lsp_channels_fail_channel(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                               size_t client_idx, const char *reason);

/* Before an update replaces client_idx's commitment: watch, on that
   commitment, every HTLC the client offered us (sweeper_watch_htlc), since
   the client may never revoke it.  A preimage learned later then arms the
   claim there too (lsp_channels_register_htlc_claim); a valid revocation
   drops the watches.  Returns 0 if one could not be stored. */
int lsp_channels_watch_commitment(lsp_channel_mgr_t *mgr, size_t client_idx);

/* The client's answer (ack: NULL if none came) to our commitment_signed
   for its channel.  A valid REVOKE_AND_ACK: the secret is stored, the
   claims and watches on the revoked commitment dropped, *next_pcp_out set,
   and 1 returned.  Otherwise 0, and the channel is failed if the answer
   was invalid, or missing with missing_is_fatal set.  On 0 the caller
   must not record a next point nor send the LSP revocation. */
int lsp_channels_take_revocation(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                 size_t client_idx, const wire_msg_t *ack,
                                 int missing_is_fatal,
                                 secp256k1_pubkey *next_pcp_out);

/* Rotation retry helpers.
   Returns:  1 = ready to retry, -1 = max retries exhausted (fallback),
             0 = no action (not attempted, or delay not elapsed, or already handled). */
int lsp_rotation_should_retry(const lsp_channel_mgr_t *mgr,
                              uint32_t factory_id, uint32_t cur_height);

/* Record a failed rotation attempt (increments count, saves block height). */
void lsp_rotation_record_failure(lsp_channel_mgr_t *mgr,
                                 uint32_t factory_id, uint32_t cur_height);

/* Record a successful rotation (resets retry state). */
void lsp_rotation_record_success(lsp_channel_mgr_t *mgr, uint32_t factory_id);

#endif /* SUPERSCALAR_LSP_CHANNELS_INTERNAL_H */
