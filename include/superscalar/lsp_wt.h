#ifndef SUPERSCALAR_LSP_WT_H
#define SUPERSCALAR_LSP_WT_H

/* #248 SF-WT-TRUSTLESS Phase 1b.2 — LSP-side adapter between in-memory
   tx blobs (held by the LSP / factory / channel code) and the schema-
   level register helper in persist_wt.c.

   This is a thin wrapper:
     - hex-encodes signed_response_tx into the response_tx_hex column
     - passes the (pre-computed) response_txid32 through unchanged
     - calls persist_wt_register_watch for the actual write

   Why the txid is a caller responsibility:
     Canonical Bitcoin TXID is sha256_double of the NON-witness
     serialization of the tx.  Most LSP code paths already hold the
     txid alongside the signed-tx bytes (e.g. node->txid in factory_t,
     or e->txid in watchtower_entry_t) — computing it from the witness
     serialization on the wt-register hot path would require tx parsing,
     which is a separate refactor.  Phase 1b.2 leaves that as a caller
     responsibility.

   Phase 1b.2 ships the helper; Phase 1b.3 wires it from:
     - lsp_advance_leaf_stateless (src/lsp_channels.c)
     - lsp_run_state_advance_stateless (Tier B)
     - lsp_subfactory_chain_advance_stateless (single + multi)
     - lsp_run_factory_creation (root watch)
   alongside the existing watchtower_watch_factory_node_with_channels
   callsites so wt_db gets the same coverage as the in-memory watchtower. */

#include "persist_wt.h"
#include <stddef.h>
#include <stdint.h>

/* Register a watchable (parent_outpoint, signed_response_tx) pair into
   the trustless watchtower DB.  Hex-encodes the tx bytes then delegates
   to persist_wt_register_watch.

   Returns the new watch_id on success, -1 on error (or if pwt is NULL).
   Idempotent within persist_wt_register_watch's transaction.

   pwt                       — wt_db handle; NULL → -1 (no-op, no error log)
   factory_id                — opaque LSP-side handle (per persist_wt.h)
   parent_txid32             — 32 bytes, the outpoint to watch
   parent_vout               — vout index
   parent_value_sat          — value of the watched output, used by WT for
                                fee math + sanity checks
   parent_spk, parent_spk_len — scriptpubkey of the watched output
   csv_delay                 — relative-timelock the response_tx assumes
   signed_response_tx, signed_response_tx_len — raw tx bytes; helper
                                                hex-encodes inline
   response_txid32           — 32 bytes, CANONICAL non-witness txid;
                                caller's responsibility (see note above)
   fee_bump_budget_sat       — max sats authorized for fee escalation
   fee_bump_deadline_height  — absolute block height past which fee-bump
                                escalation gives up */
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

#endif /* SUPERSCALAR_LSP_WT_H */
