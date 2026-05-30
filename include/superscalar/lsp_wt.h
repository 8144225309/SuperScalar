#ifndef SUPERSCALAR_LSP_WT_H
#define SUPERSCALAR_LSP_WT_H

/* #248 SF-WT-TRUSTLESS — LSP-side adapter between in-memory tx blobs
   (held by the LSP / factory / channel code) and the schema-level
   register helper in persist_wt.c.

   Each adapter:
     - hex-encodes signed_response_tx into the response_tx_hex column
     - passes the (pre-computed) response_txid32 through unchanged
     - calls persist_wt_register_watch with the matching watch_kind

   Why the txid is a caller responsibility:
     Canonical Bitcoin TXID is sha256_double of the NON-witness
     serialization of the tx.  Most LSP code paths already hold the
     txid alongside the signed-tx bytes (e.g. node->txid in factory_t,
     or e->txid in watchtower_entry_t) — computing it from the witness
     serialization on the wt-register hot path would require tx parsing,
     which is a separate refactor.  Leave that as a caller responsibility.

   Phase 1b wired lsp_wt_register_factory_node_watch from:
     - lsp_advance_leaf_stateless (src/lsp_channels.c ~line 2055)
     - lsp_run_state_advance_stateless (Tier B, ~line 2820)
     - lsp_realloc_leaf (~line 3460)

   Phase 2c wires the 3 new adapters below from:
     - lsp_subfactory_chain_advance_stateless single + multi (~line 4156, ~4674)
     - the 7 channel-revocation callsites in lsp_channels.c + lsp_bridge.c
     - the force-close callsite at ln_dispatch.c:710 */

#include "persist_wt.h"
#include <stddef.h>
#include <stdint.h>

/* WT_KIND_FACTORY_NODE adapter.  See persist_wt.h for parameter
   semantics.  Returns the new watch_id on success, -1 on error (or if
   pwt is NULL).  NULL pwt is a no-op — callers gate on lsp->wt_db being
   non-NULL at their callsite, but this also accepts NULL here for
   defense in depth. */
int64_t lsp_wt_register_factory_node_watch(persist_wt_t *pwt,
                                            uint32_t factory_id,
                                            const unsigned char parent_txid32[32],
                                            uint32_t parent_vout,
                                            uint64_t parent_value_sat,
                                            const unsigned char *parent_spk,
                                            size_t parent_spk_len,
                                            uint32_t csv_delay,
                                            const unsigned char *signed_response_tx,
                                            size_t signed_response_tx_len,
                                            const unsigned char response_txid32[32],
                                            uint64_t fee_bump_budget_sat,
                                            uint32_t fee_bump_deadline_height);

/* WT_KIND_SUBFACTORY_NODE adapter.  Same row shape as factory_node;
   factory_id is the sub-factory chain index. */
int64_t lsp_wt_register_subfactory_node_watch(persist_wt_t *pwt,
                                                uint32_t sub_factory_id,
                                                const unsigned char parent_txid32[32],
                                                uint32_t parent_vout,
                                                uint64_t parent_value_sat,
                                                const unsigned char *parent_spk,
                                                size_t parent_spk_len,
                                                uint32_t csv_delay,
                                                const unsigned char *signed_response_tx,
                                                size_t signed_response_tx_len,
                                                const unsigned char response_txid32[32],
                                                uint64_t fee_bump_budget_sat,
                                                uint32_t fee_bump_deadline_height);

/* WT_KIND_CHANNEL_COMMITMENT adapter.  Used by the 7 channel-revocation
   callsites.  factory_id carries the channel index for the watched
   commitment.  parent_txid is the revoked commit TX outpoint we look
   for on chain; signed_penalty_tx is the pre-signed penalty that the
   WT broadcasts when the revoked commit appears. */
int64_t lsp_wt_register_commitment_watch(persist_wt_t *pwt,
                                          uint32_t channel_id,
                                          const unsigned char commit_txid32[32],
                                          uint32_t to_local_vout,
                                          uint64_t to_local_amount,
                                          const unsigned char *to_local_spk,
                                          size_t to_local_spk_len,
                                          uint32_t csv_delay,
                                          const unsigned char *signed_penalty_tx,
                                          size_t signed_penalty_tx_len,
                                          const unsigned char penalty_txid32[32]);

/* WT_KIND_FORCE_CLOSE_HTLC adapter.  Used by the force-close HTLC sweep
   callsite (ln_dispatch.c).  One row per HTLC to sweep; all rows share
   the same commit_txid32 (the honest-close commit TX outpoint).
   factory_id carries the channel index.  At hydration time the WT
   builds N separate WATCH_FORCE_CLOSE entries that fire independently
   when commit_txid32 is observed. */
int64_t lsp_wt_register_force_close_watch(persist_wt_t *pwt,
                                            uint32_t channel_id,
                                            const unsigned char commit_txid32[32],
                                            uint32_t htlc_vout,
                                            uint64_t htlc_amount,
                                            const unsigned char *htlc_spk,
                                            size_t htlc_spk_len,
                                            uint32_t csv_delay,
                                            const unsigned char *signed_sweep_tx,
                                            size_t signed_sweep_tx_len,
                                            const unsigned char sweep_txid32[32]);

#endif /* SUPERSCALAR_LSP_WT_H */
