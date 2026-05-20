#ifndef SUPERSCALAR_PERSIST_WT_H
#define SUPERSCALAR_PERSIST_WT_H

/* #248 (SF-WT-TRUSTLESS) Phase 1a — watchtower-side persistence module.
   Owns watchtower.db, a SQLite file separate from lsp.db. The trustless
   model is detailed in docs/watchtower-trustless-schema.md. This Phase
   1a PR lands ONLY the schema + open/close + a single write helper. The
   LSP-side wiring (call sites that emit watches) and the WT-side reader
   switchover are subsequent phases tracked under #248.

   No column declared here is a secret. The 32-byte response_txid is a
   public bitcoin txid; the hex blob is a fully-signed TX (revealed in
   mempool the moment WT broadcasts it). Anyone with shell access to
   watchtower.db can dump it and learn only what the chain already
   reveals — that is the entire point of the split. */

#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>

#define PERSIST_WT_SCHEMA_VERSION 1

typedef struct {
    sqlite3 *db;
    char path[256];
} persist_wt_t;

/* Open (or create) watchtower.db at the given path. Runs DDL on first
   open. Returns 1 on success, 0 on error. Caller must persist_wt_close
   on success. Refuses to open a file whose schema_version doesn't match
   PERSIST_WT_SCHEMA_VERSION — there is no migration framework for WT
   schema yet (Phase 1 only). */
int persist_wt_open(persist_wt_t *pwt, const char *path);

/* Close the connection. Safe to call on a zero-initialized struct. */
void persist_wt_close(persist_wt_t *pwt);

/* Register a new (parent_outpoint, response_tx) pair. Atomic — both
   wt_responses + wt_watches rows are written under a single transaction.
   Returns the new wt_watches.watch_id on success, -1 on error.

   factory_id    — opaque LSP-side handle, no semantic meaning to WT
   parent_txid32 — 32 bytes, big-endian (internal byte order)
   parent_vout   — vout index of the watched outpoint
   parent_value_sat, parent_spk[len] — value + scriptpubkey to match in
                   block scans; both are publicly observable once the
                   parent tx confirms
   csv_delay     — relative-timelock the response_tx assumes (set when
                   constructing the pre-signed response)
   response_tx_hex     — fully-signed response TX, ready for
                          sendrawtransaction. Caller signs with key
                          material that lives in lsp.db only.
   response_txid32     — 32 bytes; can be NULL to have the helper
                          derive it from the hex (Phase 1a always
                          requires the caller to pass it explicitly)
   fee_bump_budget_sat — max sats authorized for fee-bump escalation;
                          0 = no fee-bump child available
   fee_bump_deadline   — absolute block height past which the WT
                          should give up on fee-bump escalation */
int64_t persist_wt_register_watch(persist_wt_t *pwt,
                                    uint32_t factory_id,
                                    const unsigned char *parent_txid32,
                                    uint32_t parent_vout,
                                    uint64_t parent_value_sat,
                                    const unsigned char *parent_spk,
                                    size_t parent_spk_len,
                                    uint32_t csv_delay,
                                    const char *response_tx_hex,
                                    const unsigned char *response_txid32,
                                    uint64_t fee_bump_budget_sat,
                                    uint32_t fee_bump_deadline_height);

/* Mark a watch as superseded by a chain advance. Used when a leaf
   advances to a newer state and the older row is no longer canonical.
   Returns 1 on success, 0 if no row matched. */
int persist_wt_supersede_watch(persist_wt_t *pwt, int64_t watch_id,
                                 uint32_t at_height);

/* Count active (non-superseded) watches. Used by the WT for the
   health heartbeat row. Returns -1 on error. */
int persist_wt_count_active_watches(const persist_wt_t *pwt);

#endif /* SUPERSCALAR_PERSIST_WT_H */
