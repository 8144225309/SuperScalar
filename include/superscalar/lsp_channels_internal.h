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
