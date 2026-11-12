#ifndef SUPERSCALAR_LSP_CHANNELS_INTERNAL_H
#define SUPERSCALAR_LSP_CHANNELS_INTERNAL_H

#include "lsp_channels.h"
#include "lsp.h"
#include "chain_backend.h"
#include "cpfp.h"
#include "ladder.h"

/* Shared helpers used across lsp_channels split modules.
   These are internal to the LSP channel subsystem — not public API. */

/* Send the LSP's own revocation secret to a client after each commitment update.
   Enables bidirectional revocation so clients can detect LSP breaches. */
void lsp_send_revocation(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                         size_t client_idx, uint64_t old_cn);

/* Fail a client's channel that can no longer safely advance (see
   channel_t.revocation_failed): mark it, persist the mark, and disconnect the
   client.  ch is the client's factory channel (or NULL for it) or its JIT
   channel.  While the mark is set every message from the client is dropped
   and its reconnects are refused; the operator must force-close the channel.

   peer_fault is 1 when the client's own message caused the failure (a
   revocation that does not verify).  Such a failure on a session opened by
   MSG_RECONNECT is kept in memory only (CHANNEL_FAILED_SESSION); an LSP
   restart clears it.
   Every other failure is persisted (CHANNEL_FAILED_DURABLE). */
void lsp_channels_fail_channel(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                               size_t client_idx, channel_t *ch,
                               int peer_fault, const char *reason);

/* 1 if the client's factory channel or its JIT channel has failed. */
int lsp_channels_client_failed(lsp_channel_mgr_t *mgr, size_t client_idx);

/* Before an update replaces client_idx's factory-channel commitment: watch,
   on that commitment, every HTLC the client offered us (sweeper_watch_htlc),
   since the client may never revoke it.  A preimage learned later then arms
   the claim there too (lsp_channels_register_htlc_claim); a verified
   revocation of that commitment drops the watches.  Returns 1 (also with no
   sweeper attached), 0 if a watch could not be stored. */
int lsp_channels_watch_commitment(lsp_channel_mgr_t *mgr, size_t client_idx);

/* Apply a client's REVOKE_AND_ACK for the commitment it just replaced on `ch`:
   parse it, check the next per-commitment point, and store the revocation
   secret (verified at the channel_receive_revocation choke point).  On
   success returns 1 with *old_cn_out (the revoked commitment number) and
   *next_pcp_out set (either may be NULL).  It does NOT record the next point.

   On any failure the channel is failed (lsp_channels_fail_channel) and 0 is
   returned.  The caller must then abort the ceremony: no watch, no LSP
   revocation, and nothing forwarded or settled that relies on the old
   commitment being revoked. */
SS_MUST_CHECK int (lsp_channels_accept_revocation)(lsp_channel_mgr_t *mgr,
        lsp_t *lsp, size_t client_idx, channel_t *ch, const cJSON *raa_json,
        uint64_t *old_cn_out, secp256k1_pubkey *next_pcp_out);
#define lsp_channels_accept_revocation(...) \
    ((lsp_channels_accept_revocation)(__VA_ARGS__) != 0)

/* lsp_channels_accept_revocation(), then register the revoked commitment
   (described by old_local/old_remote/old_htlcs/old_ptlcs) with the LSP's
   watchtower under wt_channel_id, then record the client's next
   per-commitment point.  The snapshots may alias ch->htlcs / ch->ptlcs.
   Same failure contract: on 0 the channel has been failed (a revoked
   commitment that cannot be watched is as unsafe as one never revoked). */
SS_MUST_CHECK int (lsp_channels_accept_raa)(lsp_channel_mgr_t *mgr,
        lsp_t *lsp, size_t client_idx, channel_t *ch,
        uint32_t wt_channel_id, const cJSON *raa_json,
        uint64_t old_local, uint64_t old_remote,
        const htlc_t *old_htlcs, size_t old_n_htlcs,
        const ptlc_t *old_ptlcs, size_t old_n_ptlcs,
        uint64_t *old_cn_out, secp256k1_pubkey *next_pcp_out);
#define lsp_channels_accept_raa(...) \
    ((lsp_channels_accept_raa)(__VA_ARGS__) != 0)

/* Rotation retry helpers.
   Returns:  1 = ready to retry, -1 = max retries exhausted (fallback),
             0 = no action (not attempted, or delay not elapsed, or already handled). */
int lsp_rotation_should_retry(const lsp_channel_mgr_t *mgr,
                              uint32_t factory_id, uint32_t cur_height);

/* Record a failed rotation attempt (increments count, saves block height). */
void lsp_rotation_record_failure(lsp_channel_mgr_t *mgr,
                                 uint32_t factory_id, uint32_t cur_height);

/* Record a rotation postponed because the old factory's cooperative close
   does not fit at the current fee estimate.  Not a failure: the retry count
   is untouched and should_retry fires again on the next block.  expired:
   the factory is past its expiry, the last point a rotation can replace it;
   the retry budget is then spent so the next retry tick takes the
   distribution-TX fallback. */
void lsp_rotation_record_postponed(lsp_channel_mgr_t *mgr, uint32_t factory_id,
                                   uint32_t cur_height, int expired);

/* Record a successful rotation (resets retry state). */
void lsp_rotation_record_success(lsp_channel_mgr_t *mgr, uint32_t factory_id);

/* Where a factory's distribution TX (parsed as ti) stands on chain. */
typedef enum {
    LSP_DIST_TO_SEND,          /* funding unspent, the TX in the mempool, or not known */
    LSP_DIST_CONFIRMED,        /* found by txid, or (no txindex) its outputs exist */
    LSP_DIST_SPENT_ELSEWHERE   /* funding spent, the TX neither in the mempool nor found */
} lsp_dist_state_t;
lsp_dist_state_t lsp_distribution_tx_state(chain_backend_t *cb, const ladder_factory_t *lf,
                                           const cpfp_tx_info_t *ti);

#endif /* SUPERSCALAR_LSP_CHANNELS_INTERNAL_H */
