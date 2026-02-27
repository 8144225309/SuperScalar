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
