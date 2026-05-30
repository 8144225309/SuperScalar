#ifndef SUPERSCALAR_PERSIST_WT_H
#define SUPERSCALAR_PERSIST_WT_H

/* #248 (SF-WT-TRUSTLESS) — watchtower-side persistence module.
   Owns watchtower.db, a SQLite file separate from lsp.db.  The trustless
   model is detailed in docs/watchtower-trustless-schema.md.

   Phase 1a (schema v1) landed the single-shape wt_watches row carrying
   (parent_outpoint, signed_response_tx, optional fee-bump).  Phase 1b
   wired the three factory-family LSP callsites (leaf advance, Tier B,
   leaf realloc) to write into it.

   Phase 2c (schema v2) generalizes the wt_watches row with a
   watch_kind discriminant so the same physical schema can carry
   sub-factory chain advance, channel-level revoked-commitment, and
   force-close HTLC-sweep watches.  See wt_watch_kind_t below.  The
   wt_watches row shape itself is unchanged — only the new column is
   added.  The WT process does NOT interpret watch_kind for broadcast
   decisions; it broadcasts response_tx_hex when the parent outpoint is
   spent regardless of kind.  watch_kind is used only by the LSP-side
   helpers (for clarity at the callsite) and by the WT-side hydration
   helper (to populate the correct in-memory entry type).

   No column declared here is a secret.  The 32-byte response_txid is a
   public bitcoin txid; the hex blob is a fully-signed TX (revealed in
   mempool the moment WT broadcasts it).  Anyone with shell access to
   watchtower.db can dump it and learn only what the chain already
   reveals — that is the entire point of the split. */

#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>

#define PERSIST_WT_SCHEMA_VERSION 2

typedef struct {
    sqlite3 *db;
    char path[256];
} persist_wt_t;

/* SF-WT-TRUSTLESS Phase 2c — watch_kind discriminant.
 *
 * Stored in wt_watches.watch_kind.  The WT process does not interpret
 * these values at broadcast time — it only uses them when populating
 * its in-memory entry table at hydration so the right
 * watchtower_entry_type_t is set.  LSP-side helpers pick the right
 * kind by their semantic role.
 *
 * Values are stable on disk; do NOT renumber.  Append-only. */
typedef enum {
    WT_KIND_FACTORY_NODE       = 0, /* Phase 1b — factory chain advance (DW Tier B, PS leaf advance,
                                       leaf realloc).  Default value: pre-Phase 2c rows have this kind. */
    WT_KIND_SUBFACTORY_NODE    = 1, /* Phase 2c — sub-factory chain advance (k>=2 shapes). */
    WT_KIND_CHANNEL_COMMITMENT = 2, /* Phase 2c — channel-level revoked-commitment breach.
                                       parent_txid is the revoked commit TX outpoint; response_tx
                                       is the pre-signed penalty TX. */
    WT_KIND_FORCE_CLOSE_HTLC   = 3, /* Phase 2c — honest force-close HTLC sweep.
                                       One row per HTLC; parent_txid is the honest commit TX
                                       outpoint shared by every row; response_tx is the per-HTLC
                                       sweep TX.  The WT broadcasts each row independently when
                                       the parent is observed. */
} wt_watch_kind_t;

/* Open (or create) watchtower.db at the given path.  Runs DDL on first
   open; applies in-place migrations (v1 -> v2 = add watch_kind column)
   when opening an older schema.  Returns 1 on success, 0 on error.
   Caller must persist_wt_close on success.  Refuses to open a file whose
   schema_version is newer than PERSIST_WT_SCHEMA_VERSION — there is no
   forward-migration framework. */
int persist_wt_open(persist_wt_t *pwt, const char *path);

/* Close the connection.  Safe to call on a zero-initialized struct. */
void persist_wt_close(persist_wt_t *pwt);

/* Register a new (parent_outpoint, response_tx) pair.  Atomic — both
   wt_responses + wt_watches rows are written under a single transaction.
   Returns the new wt_watches.watch_id on success, -1 on error.

   kind          — watch_kind discriminant (see wt_watch_kind_t)
   factory_id    — opaque LSP-side handle, no semantic meaning to WT.
                   For kind=FACTORY_NODE / SUBFACTORY_NODE this is the
                   factory/sub-factory node index; for kind=CHANNEL_COMMITMENT
                   / FORCE_CLOSE_HTLC this is the channel index.
   parent_txid32 — 32 bytes, big-endian (internal byte order)
   parent_vout   — vout index of the watched outpoint
   parent_value_sat, parent_spk[len] — value + scriptpubkey to match in
                   block scans; both are publicly observable once the
                   parent tx confirms
   csv_delay     — relative-timelock the response_tx assumes (set when
                   constructing the pre-signed response)
   response_tx_hex     — fully-signed response TX, ready for
                          sendrawtransaction.  Caller signs with key
                          material that lives in lsp.db only.
   response_txid32     — 32 bytes; canonical non-witness txid of the
                          response_tx
   fee_bump_budget_sat — max sats authorized for fee-bump escalation;
                          0 = no fee-bump child available
   fee_bump_deadline   — absolute block height past which the WT
                          should give up on fee-bump escalation */
int64_t persist_wt_register_watch(persist_wt_t *pwt,
                                    wt_watch_kind_t kind,
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

/* Mark a watch as superseded by a chain advance.  Used when a leaf
   advances to a newer state and the older row is no longer canonical.
   Returns 1 on success, 0 if no row matched. */
int persist_wt_supersede_watch(persist_wt_t *pwt, int64_t watch_id,
                                 uint32_t at_height);

/* Count active (non-superseded) watches.  Used by the WT for the
   health heartbeat row.  Returns -1 on error. */
int persist_wt_count_active_watches(const persist_wt_t *pwt);

/* SF-WT-TRUSTLESS Phase 2c — list active watches of a given kind.
 *
 * Used by the WT-side hydration helper (watchtower_hydrate_from_wt_db)
 * to populate the in-memory entries with the right type discriminant.
 * Streaming callback model — caller decodes/consumes each row.  Callback
 * returns 1 to continue iteration, 0 to stop early.  Returns the number
 * of rows visited on success, -1 on error.
 *
 * cb receives:
 *   factory_id           — value stored in the row
 *   parent_txid32        — pointer to 32-byte parent_txid blob (caller-owned
 *                          for the duration of the callback only — copy if you
 *                          need to keep it)
 *   parent_vout, parent_value_sat, parent_spk, parent_spk_len, csv_delay
 *                          — same semantics as register_watch
 *   response_tx_hex      — pointer to NUL-terminated hex string (callee-owned
 *                          for the duration of the callback)
 *   response_txid32      — pointer to 32-byte response_txid blob
 *   fee_bump_budget_sat, fee_bump_deadline_height
 *                          — fee-bump fields as registered
 *   user                 — opaque pass-through for the caller */
typedef int (*persist_wt_watch_cb)(uint32_t factory_id,
                                     const unsigned char parent_txid32[32],
                                     uint32_t parent_vout,
                                     uint64_t parent_value_sat,
                                     const unsigned char *parent_spk,
                                     size_t parent_spk_len,
                                     uint32_t csv_delay,
                                     const char *response_tx_hex,
                                     const unsigned char response_txid32[32],
                                     uint64_t fee_bump_budget_sat,
                                     uint32_t fee_bump_deadline_height,
                                     void *user);

int persist_wt_list_watches_by_kind(persist_wt_t *pwt,
                                      wt_watch_kind_t kind,
                                      persist_wt_watch_cb cb,
                                      void *user);

#endif /* SUPERSCALAR_PERSIST_WT_H */
