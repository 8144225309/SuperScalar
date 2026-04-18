#include "superscalar/persist.h"
#include "superscalar/chain_backend.h"
#include "superscalar/wire.h"
#include "superscalar/channel.h"
#include "superscalar/sha256.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>

#ifndef BASEPOINT_DIAG
#define BASEPOINT_DIAG 0
#endif

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

static const char *SCHEMA_VERSION_SQL =
    "CREATE TABLE IF NOT EXISTS schema_version ("
    "  version INTEGER NOT NULL,"
    "  applied_at INTEGER DEFAULT (strftime('%s','now'))"
    ");";

static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS factories ("
    "  id INTEGER PRIMARY KEY,"
    "  n_participants INTEGER NOT NULL,"
    "  funding_txid TEXT,"
    "  funding_vout INTEGER,"
    "  funding_amount INTEGER,"
    "  step_blocks INTEGER,"
    "  states_per_layer INTEGER,"
    "  cltv_timeout INTEGER,"
    "  fee_per_tx INTEGER,"
    "  leaf_arity INTEGER DEFAULT 2,"
    "  state TEXT DEFAULT 'active',"
    "  created_at INTEGER DEFAULT (strftime('%%s','now'))"
    ");"
    "CREATE TABLE IF NOT EXISTS factory_participants ("
    "  factory_id INTEGER NOT NULL,"
    "  slot INTEGER NOT NULL,"
    "  pubkey TEXT NOT NULL,"
    "  PRIMARY KEY (factory_id, slot)"
    ");"
    "CREATE TABLE IF NOT EXISTS channels ("
    "  id INTEGER PRIMARY KEY,"
    "  factory_id INTEGER NOT NULL,"
    "  slot INTEGER NOT NULL,"
    "  local_amount INTEGER NOT NULL,"
    "  remote_amount INTEGER NOT NULL,"
    "  funding_amount INTEGER NOT NULL,"
    "  commitment_number INTEGER DEFAULT 0,"
    "  funding_txid TEXT,"
    "  funding_vout INTEGER,"
    "  state TEXT DEFAULT 'open'"
    ");"
    "CREATE TABLE IF NOT EXISTS revocation_secrets ("
    "  channel_id INTEGER NOT NULL,"
    "  commit_num INTEGER NOT NULL,"
    "  secret TEXT NOT NULL,"
    "  PRIMARY KEY (channel_id, commit_num)"
    ");"
    "CREATE TABLE IF NOT EXISTS htlcs ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  channel_id INTEGER NOT NULL,"
    "  htlc_id INTEGER NOT NULL,"
    "  direction TEXT NOT NULL,"
    "  amount INTEGER NOT NULL,"
    "  payment_hash TEXT NOT NULL,"
    "  payment_preimage TEXT,"
    "  cltv_expiry INTEGER,"
    "  state TEXT NOT NULL,"
    "  UNIQUE(channel_id, htlc_id)"
    ");"
    "CREATE TABLE IF NOT EXISTS nonce_pools ("
    "  channel_id INTEGER NOT NULL,"
    "  side TEXT NOT NULL,"
    "  pool_data BLOB,"
    "  next_index INTEGER DEFAULT 0,"
    "  PRIMARY KEY (channel_id, side)"
    ");"
    "CREATE TABLE IF NOT EXISTS old_commitments ("
    "  channel_id INTEGER NOT NULL,"
    "  commit_num INTEGER NOT NULL,"
    "  txid TEXT NOT NULL,"
    "  to_local_vout INTEGER NOT NULL,"
    "  to_local_amount INTEGER NOT NULL,"
    "  to_local_spk TEXT NOT NULL,"
    "  PRIMARY KEY (channel_id, commit_num)"
    ");"
    "CREATE TABLE IF NOT EXISTS old_commitment_htlcs ("
    "  channel_id INTEGER NOT NULL,"
    "  commit_num INTEGER NOT NULL,"
    "  htlc_vout INTEGER NOT NULL,"
    "  htlc_amount INTEGER NOT NULL,"
    "  htlc_spk TEXT NOT NULL,"
    "  direction INTEGER NOT NULL,"
    "  payment_hash TEXT NOT NULL,"
    "  cltv_expiry INTEGER NOT NULL,"
    "  PRIMARY KEY (channel_id, commit_num, htlc_vout)"
    ");"
    "CREATE TABLE IF NOT EXISTS wire_messages ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  timestamp INTEGER NOT NULL,"
    "  direction TEXT NOT NULL,"
    "  msg_type INTEGER NOT NULL,"
    "  msg_name TEXT NOT NULL,"
    "  peer TEXT,"
    "  payload_summary TEXT"
    ");"
    "CREATE TABLE IF NOT EXISTS tree_nodes ("
    "  factory_id INTEGER NOT NULL,"
    "  node_index INTEGER NOT NULL,"
    "  type TEXT NOT NULL,"
    "  parent_index INTEGER,"
    "  parent_vout INTEGER,"
    "  dw_layer_index INTEGER,"
    "  n_signers INTEGER,"
    "  signer_indices TEXT,"
    "  n_outputs INTEGER,"
    "  output_amounts TEXT,"
    "  nsequence INTEGER,"
    "  input_amount INTEGER,"
    "  txid TEXT,"
    "  is_built INTEGER,"
    "  is_signed INTEGER,"
    "  spending_spk TEXT,"
    "  signed_tx_hex TEXT,"
    "  PRIMARY KEY (factory_id, node_index)"
    ");"
    "CREATE TABLE IF NOT EXISTS broadcast_log ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  txid TEXT NOT NULL,"
    "  source TEXT NOT NULL,"
    "  raw_hex TEXT,"
    "  result TEXT,"
    "  broadcast_time INTEGER DEFAULT (strftime('%%s','now'))"
    ");"
    "CREATE TABLE IF NOT EXISTS signing_progress ("
    "  factory_id INTEGER NOT NULL,"
    "  node_index INTEGER NOT NULL,"
    "  signer_slot INTEGER NOT NULL,"
    "  has_nonce INTEGER NOT NULL DEFAULT 0,"
    "  has_partial_sig INTEGER NOT NULL DEFAULT 0,"
    "  updated_at INTEGER DEFAULT (strftime('%%s','now')),"
    "  PRIMARY KEY (factory_id, node_index, signer_slot)"
    ");"
    "CREATE TABLE IF NOT EXISTS ladder_factories ("
    "  factory_id INTEGER PRIMARY KEY,"
    "  state TEXT NOT NULL,"
    "  is_funded INTEGER,"
    "  is_initialized INTEGER,"
    "  n_departed INTEGER DEFAULT 0,"
    "  created_block INTEGER,"
    "  active_blocks INTEGER,"
    "  dying_blocks INTEGER,"
    "  partial_rotation INTEGER DEFAULT 0,"
    "  updated_at INTEGER"
    ");"
    /* Phase 23: Persistence Hardening */
    "CREATE TABLE IF NOT EXISTS dw_counter_state ("
    "  factory_id INTEGER PRIMARY KEY,"
    "  current_epoch INTEGER NOT NULL,"
    "  n_layers INTEGER NOT NULL,"
    "  layer_states TEXT NOT NULL,"
    "  per_leaf_enabled INTEGER NOT NULL DEFAULT 0,"
    "  n_leaf_nodes INTEGER NOT NULL DEFAULT 2,"
    "  leaf_states TEXT NOT NULL DEFAULT '0,0'"
    ");"
    "CREATE TABLE IF NOT EXISTS departed_clients ("
    "  factory_id INTEGER NOT NULL,"
    "  client_idx INTEGER NOT NULL,"
    "  extracted_key TEXT NOT NULL,"
    "  departed_at INTEGER DEFAULT (strftime('%%s','now')),"
    "  PRIMARY KEY (factory_id, client_idx)"
    ");"
    "CREATE TABLE IF NOT EXISTS invoice_registry ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  payment_hash TEXT NOT NULL,"
    "  dest_client INTEGER NOT NULL,"
    "  amount_msat INTEGER NOT NULL,"
    "  bridge_htlc_id INTEGER DEFAULT 0,"
    "  active INTEGER DEFAULT 1,"
    "  created_at INTEGER DEFAULT (strftime('%%s','now'))"
    ");"
    "CREATE TABLE IF NOT EXISTS htlc_origins ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  payment_hash TEXT NOT NULL,"
    "  bridge_htlc_id INTEGER DEFAULT 0,"
    "  request_id INTEGER DEFAULT 0,"
    "  sender_idx INTEGER NOT NULL,"
    "  sender_htlc_id INTEGER DEFAULT 0,"
    "  active INTEGER DEFAULT 1,"
    "  created_at INTEGER DEFAULT (strftime('%%s','now'))"
    ");"
    "CREATE TABLE IF NOT EXISTS client_invoices ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  payment_hash TEXT NOT NULL,"
    "  preimage TEXT NOT NULL,"
    "  amount_msat INTEGER NOT NULL,"
    "  active INTEGER DEFAULT 1,"
    "  created_at INTEGER DEFAULT (strftime('%%s','now'))"
    ");"
    "CREATE TABLE IF NOT EXISTS id_counters ("
    "  name TEXT PRIMARY KEY,"
    "  value INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS local_pcs ("
    "  channel_id INTEGER NOT NULL,"
    "  commit_num INTEGER NOT NULL,"
    "  secret TEXT NOT NULL,"
    "  PRIMARY KEY (channel_id, commit_num)"
    ");"
    "CREATE TABLE IF NOT EXISTS remote_pcps ("
    "  channel_id INTEGER NOT NULL,"
    "  commit_num INTEGER NOT NULL,"
    "  point TEXT NOT NULL,"
    "  PRIMARY KEY (channel_id, commit_num)"
    ");"
    "CREATE TABLE IF NOT EXISTS channel_basepoints ("
    "  channel_id INTEGER PRIMARY KEY,"
    "  local_payment_secret TEXT NOT NULL,"
    "  local_delayed_secret TEXT NOT NULL,"
    "  local_revocation_secret TEXT NOT NULL,"
    "  local_htlc_secret TEXT NOT NULL,"
    "  remote_payment_bp TEXT NOT NULL,"
    "  remote_delayed_bp TEXT NOT NULL,"
    "  remote_revocation_bp TEXT NOT NULL,"
    "  remote_htlc_bp TEXT NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS watchtower_keys ("
    "  key_name TEXT PRIMARY KEY,"
    "  key_hex TEXT NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS watchtower_pending ("
    "  txid TEXT PRIMARY KEY,"
    "  anchor_vout INTEGER NOT NULL,"
    "  anchor_amount INTEGER NOT NULL,"
    "  cycles_in_mempool INTEGER NOT NULL DEFAULT 0,"
    "  bump_count INTEGER NOT NULL DEFAULT 0,"
    "  penalty_value INTEGER NOT NULL DEFAULT 0,"
    "  csv_delay INTEGER NOT NULL DEFAULT 144,"
    "  start_height INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE TABLE IF NOT EXISTS jit_channels ("
    "  jit_channel_id INTEGER PRIMARY KEY,"
    "  client_idx INTEGER NOT NULL,"
    "  state TEXT NOT NULL,"
    "  funding_txid TEXT,"
    "  funding_vout INTEGER,"
    "  funding_amount INTEGER,"
    "  local_amount INTEGER,"
    "  remote_amount INTEGER,"
    "  commitment_number INTEGER DEFAULT 0,"
    "  created_at INTEGER,"
    "  created_block INTEGER,"
    "  target_factory_id INTEGER DEFAULT 0,"
    "  funding_tx_hex TEXT"
    ");"
    /* Phase 2: Flat revocation secrets (item 2.8) */
    "CREATE TABLE IF NOT EXISTS factory_revocation_secrets ("
    "  factory_id INTEGER NOT NULL,"
    "  epoch INTEGER NOT NULL,"
    "  secret TEXT NOT NULL,"
    "  PRIMARY KEY (factory_id, epoch)"
    ");"
    /* BIP 158 light client scan checkpoint (singleton row, id=1) */
    "CREATE TABLE IF NOT EXISTS bip158_checkpoints ("
    "  id INTEGER PRIMARY KEY DEFAULT 1,"
    "  tip_height INTEGER NOT NULL DEFAULT -1,"
    "  headers_synced INTEGER NOT NULL DEFAULT -1,"
    "  filter_headers_synced INTEGER NOT NULL DEFAULT -1,"
    "  header_hashes BLOB,"
    "  filter_headers BLOB"
    ");"
    /* Async signing: pending work queue for offline clients */
    "CREATE TABLE IF NOT EXISTS pending_queue ("
    "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  client_idx  INTEGER NOT NULL,"
    "  factory_id  INTEGER NOT NULL,"
    "  request_type INTEGER NOT NULL,"
    "  urgency     INTEGER NOT NULL DEFAULT 1,"
    "  created_at  INTEGER NOT NULL,"
    "  expires_at  INTEGER NOT NULL DEFAULT 0,"
    "  payload     TEXT,"
    "  UNIQUE (client_idx, factory_id, request_type) ON CONFLICT REPLACE"
    ");"
    /* Async signing: per-client readiness state across LSP restarts */
    "CREATE TABLE IF NOT EXISTS client_readiness ("
    "  client_idx   INTEGER NOT NULL,"
    "  factory_id   INTEGER NOT NULL,"
    "  is_connected INTEGER NOT NULL DEFAULT 0,"
    "  is_ready     INTEGER NOT NULL DEFAULT 0,"
    "  last_seen    INTEGER NOT NULL DEFAULT 0,"
    "  ready_for    INTEGER NOT NULL DEFAULT 0,"
    "  PRIMARY KEY (client_idx, factory_id)"
    ");"
    /* Schema v4: pending commitment-signed flag (Fix 5 reconnect retransmit) */
    "CREATE TABLE IF NOT EXISTS pending_cs ("
    "  channel_id INTEGER PRIMARY KEY,"
    "  commitment_number INTEGER NOT NULL"
    ");"
    /* Schema v13: signed commitment TX for client trustless force-close */
    "CREATE TABLE IF NOT EXISTS signed_commitments ("
    "  channel_id INTEGER PRIMARY KEY,"
    "  commitment_number INTEGER NOT NULL,"
    "  sig64_hex TEXT NOT NULL,"
    "  signed_tx_hex TEXT NOT NULL"
    ");"
    /* Schema v14: distribution TX for inverted timeout default */
    "CREATE TABLE IF NOT EXISTS distribution_txs ("
    "  factory_id INTEGER PRIMARY KEY,"
    "  signed_tx_hex TEXT NOT NULL"
    ");"
    /* Schema v12: pending sweeps for auto-settlement */
    "CREATE TABLE IF NOT EXISTS fee_settlement ("
    "  factory_id INTEGER NOT NULL DEFAULT 0,"
    "  accumulated_fees_sats INTEGER NOT NULL DEFAULT 0,"
    "  last_settlement_block INTEGER NOT NULL DEFAULT 0,"
    "  PRIMARY KEY (factory_id)"
    ");"

    "CREATE TABLE IF NOT EXISTS pending_sweeps ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  sweep_type TEXT NOT NULL,"
    "  state INTEGER NOT NULL DEFAULT 0,"
    "  source_txid TEXT NOT NULL,"
    "  source_vout INTEGER NOT NULL,"
    "  amount_sats INTEGER NOT NULL,"
    "  csv_delay INTEGER NOT NULL DEFAULT 0,"
    "  confirmed_height INTEGER NOT NULL DEFAULT 0,"
    "  channel_id INTEGER NOT NULL,"
    "  factory_id INTEGER NOT NULL,"
    "  commitment_number INTEGER NOT NULL DEFAULT 0,"
    "  sweep_txid TEXT DEFAULT '',"
    "  created_at INTEGER DEFAULT (strftime('%%s','now'))"
    ");";

int persist_open(persist_t *p, const char *path) {
    if (!p) return 0;
    memset(p, 0, sizeof(*p));

    const char *db_path = (path && path[0]) ? path : ":memory:";
    strncpy(p->path, db_path, sizeof(p->path) - 1);

    int rc = sqlite3_open(db_path, &p->db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "persist_open: %s\n", sqlite3_errmsg(p->db));
        sqlite3_close(p->db);
        p->db = NULL;
        return 0;
    }

    /* Enable WAL mode for better concurrent performance */
    char *pragma_err = NULL;
    rc = sqlite3_exec(p->db, "PRAGMA journal_mode=WAL;", NULL, NULL, &pragma_err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "persist_open: PRAGMA journal_mode=WAL failed: %s\n",
                pragma_err ? pragma_err : "unknown");
        sqlite3_free(pragma_err);
        sqlite3_close(p->db);
        p->db = NULL;
        return 0;
    }
    sqlite3_busy_timeout(p->db, 5000);
    /* FULL sync: WAL default NORMAL can lose data on OS crash */
    rc = sqlite3_exec(p->db, "PRAGMA synchronous=FULL;", NULL, NULL, &pragma_err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "persist_open: PRAGMA synchronous=FULL failed: %s\n",
                pragma_err ? pragma_err : "unknown");
        sqlite3_free(pragma_err);
        sqlite3_close(p->db);
        p->db = NULL;
        return 0;
    }
    /* Enforce foreign key constraints */
    rc = sqlite3_exec(p->db, "PRAGMA foreign_keys=ON;", NULL, NULL, &pragma_err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "persist_open: PRAGMA foreign_keys=ON failed: %s\n",
                pragma_err ? pragma_err : "unknown");
        sqlite3_free(pragma_err);
        sqlite3_close(p->db);
        p->db = NULL;
        return 0;
    }

    /* Create schema_version table first (always safe, idempotent) */
    char *errmsg = NULL;
    rc = sqlite3_exec(p->db, SCHEMA_VERSION_SQL, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "persist_open: schema_version table error: %s\n", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close(p->db);
        p->db = NULL;
        return 0;
    }

    /* Check existing DB version */
    int db_version = 0;
    {
        sqlite3_stmt *vstmt;
        if (sqlite3_prepare_v2(p->db,
                "SELECT MAX(version) FROM schema_version;",
                -1, &vstmt, NULL) == SQLITE_OK) {
            if (sqlite3_step(vstmt) == SQLITE_ROW &&
                sqlite3_column_type(vstmt, 0) != SQLITE_NULL) {
                db_version = sqlite3_column_int(vstmt, 0);
            }
            sqlite3_finalize(vstmt);
        }
    }

    /* Reject if DB version > code version (old code on new DB) */
    if (db_version > PERSIST_SCHEMA_VERSION) {
        fprintf(stderr, "persist_open: DB schema version %d > code version %d "
                "(upgrade your binary)\n", db_version, PERSIST_SCHEMA_VERSION);
        sqlite3_close(p->db);
        p->db = NULL;
        return 0;
    }

    /* Create main schema (all IF NOT EXISTS, safe on existing DBs) */
    rc = sqlite3_exec(p->db, SCHEMA_SQL, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "persist_open: schema error: %s\n", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close(p->db);
        p->db = NULL;
        return 0;
    }

    /* Run migrations from db_version+1 to PERSIST_SCHEMA_VERSION. */
    if (db_version < 2) {
        const char *sql_v2 =
            "CREATE TABLE IF NOT EXISTS hd_utxos ("
            "  txid TEXT NOT NULL,"
            "  vout INTEGER NOT NULL,"
            "  amount_sats INTEGER NOT NULL,"
            "  key_index INTEGER NOT NULL,"
            "  spent INTEGER NOT NULL DEFAULT 0,"
            "  PRIMARY KEY (txid, vout)"
            ");"
            "CREATE TABLE IF NOT EXISTS hd_wallet_state ("
            "  id INTEGER PRIMARY KEY CHECK (id = 1),"
            "  next_index INTEGER NOT NULL DEFAULT 0,"
            "  seed_hex TEXT"          /* 64–128 hex chars; NULL until first use */
            ");";
        char *merr = NULL;
        if (sqlite3_exec(p->db, sql_v2, NULL, NULL, &merr) != SQLITE_OK) {
            fprintf(stderr, "persist_open: migration v2 failed: %s\n",
                    merr ? merr : "unknown");
            sqlite3_free(merr);
            sqlite3_close(p->db);
            p->db = NULL;
            return 0;
        }
    }

    /* Migrate: add lookahead column if missing (silently ignore error) */
    sqlite3_exec(p->db,
        "ALTER TABLE hd_wallet_state ADD COLUMN lookahead INTEGER DEFAULT 100;",
        NULL, NULL, NULL);

    /* v5: add reserved column to hd_utxos — silently ignore if already present */
    sqlite3_exec(p->db,
        "ALTER TABLE hd_utxos ADD COLUMN reserved INTEGER NOT NULL DEFAULT 0;",
        NULL, NULL, NULL);

    /* v3 migration: offers table for BOLT 12 */
    if (db_version < 3) {
        const char *sql_v3 =
            "CREATE TABLE IF NOT EXISTS offers ("
            "  offer_id BLOB NOT NULL PRIMARY KEY,"  /* 32 bytes */
            "  encoded  TEXT NOT NULL,"              /* bech32m string */
            "  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))"
            ");";
        char *merr3 = NULL;
        if (sqlite3_exec(p->db, sql_v3, NULL, NULL, &merr3) != SQLITE_OK) {
            fprintf(stderr, "persist_open: migration v3 failed: %s\n",
                    merr3 ? merr3 : "unknown");
            sqlite3_free(merr3);
            sqlite3_close(p->db);
            p->db = NULL;
            return 0;
        }
    }

    if (db_version < 4) {
        const char *sql_v4 =
            "CREATE TABLE IF NOT EXISTS pending_cs ("
            "  channel_id INTEGER PRIMARY KEY,"
            "  commitment_number INTEGER NOT NULL"
            ");";
        char *merr4 = NULL;
        if (sqlite3_exec(p->db, sql_v4, NULL, NULL, &merr4) != SQLITE_OK) {
            fprintf(stderr, "persist_open: migration v4 failed: %s\n",
                    merr4 ? merr4 : "unknown");
            sqlite3_free(merr4);
            sqlite3_close(p->db);
            p->db = NULL;
            return 0;
        }
    }

    /* v6 migration: lsp_endpoints cache for client bootstrap */
    if (db_version < 6) {
        const char *sql_v6 =
            "CREATE TABLE IF NOT EXISTS lsp_endpoints ("
            "  domain     TEXT NOT NULL PRIMARY KEY,"
            "  host       TEXT NOT NULL,"
            "  port       INTEGER NOT NULL,"
            "  pubkey_hex TEXT NOT NULL,"
            "  updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))"
            ");";
        char *merr6 = NULL;
        if (sqlite3_exec(p->db, sql_v6, NULL, NULL, &merr6) != SQLITE_OK) {
            fprintf(stderr, "persist_open: migration v6 failed: %s\n",
                    merr6 ? merr6 : "unknown");
            sqlite3_free(merr6);
            sqlite3_close(p->db);
            p->db = NULL;
            return 0;
        }
    }

    if (db_version < 7) {
        const char *sql_v5 =
            "CREATE TABLE IF NOT EXISTS scid_registry ("
            "  scid        INTEGER NOT NULL PRIMARY KEY,"
            "  factory_id  INTEGER NOT NULL,"
            "  leaf_idx    INTEGER NOT NULL,"
            "  created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))"
            ");";
        char *merr7 = NULL;
        if (sqlite3_exec(p->db, sql_v5, NULL, NULL, &merr7) != SQLITE_OK) {
            fprintf(stderr, "persist_open: migration v7 failed: %s\n",
                    merr7 ? merr7 : "unknown");
            sqlite3_free(merr7);
            sqlite3_close(p->db);
            p->db = NULL;
            return 0;
        }
    }

    /* v8 migration: htlc_inbound for durable inbound HTLC state */
    if (db_version < 8) {
        const char *sql_v6 =
            "CREATE TABLE IF NOT EXISTS htlc_inbound ("
            "  htlc_id        INTEGER NOT NULL PRIMARY KEY,"
            "  amount_msat    INTEGER NOT NULL,"
            "  payment_hash   TEXT    NOT NULL,"
            "  payment_secret TEXT    NOT NULL,"
            "  cltv_expiry    INTEGER NOT NULL,"
            "  scid           INTEGER NOT NULL,"
            "  state          INTEGER NOT NULL DEFAULT 0,"
            "  preimage       TEXT,"
            "  created_at     INTEGER NOT NULL DEFAULT (strftime('%s','now'))"
            ");";
        char *merr8 = NULL;
        if (sqlite3_exec(p->db, sql_v6, NULL, NULL, &merr8) != SQLITE_OK) {
            fprintf(stderr, "persist_open: migration v8 failed: %s\n",
                    merr8 ? merr8 : "unknown");
            sqlite3_free(merr8);
            sqlite3_close(p->db);
            p->db = NULL;
            return 0;
        }
    }

    /* v9 migration: ln_invoices + ln_peer_channels for LN node persistence */
    if (db_version < 9) {
        const char *sql_v9 =
            "CREATE TABLE IF NOT EXISTS ln_invoices ("
            "  payment_hash BLOB PRIMARY KEY,"
            "  preimage BLOB NOT NULL,"
            "  payment_secret BLOB NOT NULL,"
            "  amount_msat INTEGER NOT NULL,"
            "  description TEXT,"
            "  expiry INTEGER NOT NULL,"
            "  created_at INTEGER NOT NULL,"
            "  settled INTEGER NOT NULL DEFAULT 0,"
            "  active INTEGER NOT NULL DEFAULT 1,"
            "  has_stateless_secret INTEGER NOT NULL DEFAULT 0,"
            "  has_stateless_preimage INTEGER NOT NULL DEFAULT 0,"
            "  stateless_nonce BLOB"
            ");"
            "CREATE TABLE IF NOT EXISTS ln_peer_channels ("
            "  channel_id BLOB PRIMARY KEY,"
            "  peer_pubkey BLOB NOT NULL,"
            "  capacity_sat INTEGER NOT NULL,"
            "  local_balance_msat INTEGER NOT NULL,"
            "  remote_balance_msat INTEGER NOT NULL,"
            "  our_funding_pubkey BLOB,"
            "  their_funding_pubkey BLOB,"
            "  state INTEGER NOT NULL DEFAULT 0,"
            "  updated_at INTEGER NOT NULL"
            ");";
        char *merr9 = NULL;
        if (sqlite3_exec(p->db, sql_v9, NULL, NULL, &merr9) != SQLITE_OK) {
            fprintf(stderr, "persist_open: migration v9 failed: %s\n",
                    merr9 ? merr9 : "unknown");
            sqlite3_free(merr9);
            sqlite3_close(p->db);
            p->db = NULL;
            return 0;
        }
    }

    /* v10 migration: peer host/port + circuit_breaker_peers */
    if (db_version < 10) {
        sqlite3_exec(p->db,
            "ALTER TABLE ln_peer_channels ADD COLUMN peer_host TEXT DEFAULT '';",
            NULL, NULL, NULL);
        sqlite3_exec(p->db,
            "ALTER TABLE ln_peer_channels ADD COLUMN peer_port INTEGER DEFAULT 0;",
            NULL, NULL, NULL);
        const char *sql_v10_cb =
            "CREATE TABLE IF NOT EXISTS circuit_breaker_peers ("
            "  peer_pubkey        BLOB PRIMARY KEY,"
            "  max_pending_htlcs  INTEGER NOT NULL DEFAULT 483,"
            "  max_pending_msat   INTEGER NOT NULL DEFAULT 100000000000,"
            "  max_htlcs_per_hour INTEGER NOT NULL DEFAULT 3600"
            ");"
            "CREATE TABLE IF NOT EXISTS ptlcs ("
            "  channel_id INTEGER NOT NULL,"
            "  ptlc_id    INTEGER NOT NULL,"
            "  direction  TEXT NOT NULL,"
            "  amount     INTEGER NOT NULL,"
            "  payment_point BLOB,"
            "  cltv_expiry INTEGER NOT NULL,"
            "  state      TEXT NOT NULL DEFAULT 'active',"
            "  PRIMARY KEY (channel_id, ptlc_id)"
            ");"
            "CREATE TABLE IF NOT EXISTS peer_storage_blobs ("
            "  peer_pubkey  BLOB NOT NULL PRIMARY KEY,"
            "  blob         BLOB NOT NULL,"
            "  received_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))"
            ");";
        char *merr10 = NULL;
        if (sqlite3_exec(p->db, sql_v10_cb, NULL, NULL, &merr10) != SQLITE_OK) {
            fprintf(stderr, "persist_open: migration v10 failed: %s\n",
                    merr10 ? merr10 : "unknown");
            sqlite3_free(merr10);
            sqlite3_close(p->db);
            p->db = NULL;
            return 0;
        }
    }

    /* v11: reorg resistance — add staleness tracking columns */
    if (db_version < 11) {
        sqlite3_exec(p->db,
            "ALTER TABLE broadcast_log ADD COLUMN reorg_stale INTEGER NOT NULL DEFAULT 0;",
            NULL, NULL, NULL);
        sqlite3_exec(p->db,
            "ALTER TABLE tree_nodes ADD COLUMN validated_at_height INTEGER DEFAULT 0;",
            NULL, NULL, NULL);
        sqlite3_exec(p->db,
            "ALTER TABLE tree_nodes ADD COLUMN reorg_stale INTEGER NOT NULL DEFAULT 0;",
            NULL, NULL, NULL);
        sqlite3_exec(p->db,
            "ALTER TABLE jit_channels ADD COLUMN funded_height INTEGER DEFAULT 0;",
            NULL, NULL, NULL);
        sqlite3_exec(p->db,
            "ALTER TABLE jit_channels ADD COLUMN reorg_stale INTEGER NOT NULL DEFAULT 0;",
            NULL, NULL, NULL);
        sqlite3_exec(p->db,
            "ALTER TABLE ladder_factories ADD COLUMN reorg_stale INTEGER NOT NULL DEFAULT 0;",
            NULL, NULL, NULL);
    }

    /* v13: signed commitment TX for client trustless force-close */
    if (db_version < 13) {
        const char *sql_v13 =
            "CREATE TABLE IF NOT EXISTS signed_commitments ("
            "  channel_id INTEGER PRIMARY KEY,"
            "  commitment_number INTEGER NOT NULL,"
            "  sig64_hex TEXT NOT NULL,"
            "  signed_tx_hex TEXT NOT NULL"
            ");";
        char *merr13 = NULL;
        if (sqlite3_exec(p->db, sql_v13, NULL, NULL, &merr13) != SQLITE_OK) {
            fprintf(stderr, "persist_open: migration v13 failed: %s\n",
                    merr13 ? merr13 : "unknown");
            sqlite3_free(merr13);
            sqlite3_close(p->db);
            p->db = NULL;
            return 0;
        }
    }

    /* v14: distribution TX for inverted timeout default */
    if (db_version < 14) {
        const char *sql_v14 =
            "CREATE TABLE IF NOT EXISTS distribution_txs ("
            "  factory_id INTEGER PRIMARY KEY,"
            "  signed_tx_hex TEXT NOT NULL"
            ");";
        char *merr14 = NULL;
        if (sqlite3_exec(p->db, sql_v14, NULL, NULL, &merr14) != SQLITE_OK) {
            fprintf(stderr, "persist_open: migration v14 failed: %s\n",
                    merr14 ? merr14 : "unknown");
            sqlite3_free(merr14);
            sqlite3_close(p->db);
            p->db = NULL;
            return 0;
        }
    }

    /* v15: per-HTLC fee tracking for conservation invariant */
    if (db_version < 15) {
        const char *sql_v15 =
            "ALTER TABLE htlcs ADD COLUMN fee_at_add INTEGER DEFAULT 0;";
        char *merr15 = NULL;
        /* ALTER TABLE fails silently if column already exists in some
           SQLite versions; ignore errors from duplicate column. */
        sqlite3_exec(p->db, sql_v15, NULL, NULL, &merr15);
        sqlite3_free(merr15);
    }

    /* v12: pending sweeps for auto-settlement */
    if (db_version < 12) {
        const char *sql_v12 =
            "CREATE TABLE IF NOT EXISTS pending_sweeps ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  sweep_type TEXT NOT NULL,"
            "  state INTEGER NOT NULL DEFAULT 0,"
            "  source_txid TEXT NOT NULL,"
            "  source_vout INTEGER NOT NULL,"
            "  amount_sats INTEGER NOT NULL,"
            "  csv_delay INTEGER NOT NULL DEFAULT 0,"
            "  confirmed_height INTEGER NOT NULL DEFAULT 0,"
            "  channel_id INTEGER NOT NULL,"
            "  factory_id INTEGER NOT NULL,"
            "  commitment_number INTEGER NOT NULL DEFAULT 0,"
            "  sweep_txid TEXT DEFAULT '',"
            "  created_at INTEGER DEFAULT (strftime('%s','now'))"
            ");";
        char *merr12 = NULL;
        if (sqlite3_exec(p->db, sql_v12, NULL, NULL, &merr12) != SQLITE_OK) {
            fprintf(stderr, "persist_open: migration v12 failed: %s\n",
                    merr12 ? merr12 : "unknown");
            sqlite3_free(merr12);
            sqlite3_close(p->db);
            p->db = NULL;
            return 0;
        }
    }

    /* v16: CPFP budget fields on watchtower_pending */
    if (db_version < 16) {
        sqlite3_exec(p->db,
            "ALTER TABLE watchtower_pending ADD COLUMN penalty_value INTEGER NOT NULL DEFAULT 0;",
            NULL, NULL, NULL);
        sqlite3_exec(p->db,
            "ALTER TABLE watchtower_pending ADD COLUMN csv_delay INTEGER NOT NULL DEFAULT 144;",
            NULL, NULL, NULL);
        sqlite3_exec(p->db,
            "ALTER TABLE watchtower_pending ADD COLUMN start_height INTEGER NOT NULL DEFAULT 0;",
            NULL, NULL, NULL);
    }

    /* v17: fee settlement persistence for profit-shared mode */
    if (db_version < 17) {
        sqlite3_exec(p->db,
            "CREATE TABLE IF NOT EXISTS fee_settlement ("
            "  factory_id INTEGER NOT NULL DEFAULT 0,"
            "  accumulated_fees_sats INTEGER NOT NULL DEFAULT 0,"
            "  last_settlement_block INTEGER NOT NULL DEFAULT 0,"
            "  PRIMARY KEY (factory_id)"
            ");",
            NULL, NULL, NULL);
    }

    if (db_version < 18) {
        sqlite3_exec(p->db,
            "ALTER TABLE channels ADD COLUMN to_self_delay INTEGER NOT NULL DEFAULT 144;",
            NULL, NULL, NULL);
        sqlite3_exec(p->db,
            "ALTER TABLE channels ADD COLUMN fee_rate_sat_per_kvb INTEGER NOT NULL DEFAULT 1000;",
            NULL, NULL, NULL);
        sqlite3_exec(p->db,
            "ALTER TABLE channels ADD COLUMN use_revocation_leaf INTEGER NOT NULL DEFAULT 0;",
            NULL, NULL, NULL);
    }

    /* Record the current version if not already present */
    if (db_version < PERSIST_SCHEMA_VERSION) {
        char vsql[128];
        snprintf(vsql, sizeof(vsql),
                 "INSERT INTO schema_version (version) VALUES (%d);",
                 PERSIST_SCHEMA_VERSION);
        sqlite3_exec(p->db, vsql, NULL, NULL, NULL);
    }

    return 1;
}

int persist_open_readonly(persist_t *p, const char *path) {
    if (!p || !path) return 0;
    memset(p, 0, sizeof(*p));
    strncpy(p->path, path, sizeof(p->path) - 1);

    int rc = sqlite3_open_v2(path, &p->db, SQLITE_OPEN_READONLY, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "persist_open_readonly: %s\n", sqlite3_errmsg(p->db));
        sqlite3_close(p->db);
        p->db = NULL;
        return 0;
    }
    sqlite3_busy_timeout(p->db, 5000);
    return 1;
}

void persist_close(persist_t *p) {
    if (p && p->db) {
        sqlite3_close(p->db);
        p->db = NULL;
    }
}

int persist_schema_version(persist_t *p) {
    if (!p || !p->db) return 0;

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "SELECT MAX(version) FROM schema_version;",
            -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    int version = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW &&
        sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
        version = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return version;
}

int persist_begin(persist_t *p) {
    if (!p || !p->db) return 0;
    if (sqlite3_exec(p->db, "BEGIN;", NULL, NULL, NULL) != SQLITE_OK)
        return 0;
    p->in_transaction = 1;
    return 1;
}

int persist_commit(persist_t *p) {
    if (!p || !p->db) return 0;
    int ok = (sqlite3_exec(p->db, "COMMIT;", NULL, NULL, NULL) == SQLITE_OK);
    p->in_transaction = 0;
    return ok;
}

int persist_rollback(persist_t *p) {
    if (!p || !p->db) return 0;
    int ok = (sqlite3_exec(p->db, "ROLLBACK;", NULL, NULL, NULL) == SQLITE_OK);
    p->in_transaction = 0;
    return ok;
}

int persist_in_transaction(const persist_t *p) {
    return p && p->in_transaction;
}

/* --- Factory --- */

int persist_save_factory(persist_t *p, const factory_t *f,
                          secp256k1_context *ctx, uint32_t factory_id) {
    if (!p || !p->db || !f || !ctx) return 0;

    /* Use internal transaction if caller hasn't started one */
    int own_txn = !p->in_transaction;
    if (own_txn && !persist_begin(p)) return 0;

    /* Encode funding_txid as hex (display order = reversed internal) */
    unsigned char txid_display[32];
    memcpy(txid_display, f->funding_txid, 32);
    /* reverse to display order */
    for (size_t i = 0; i < 16; i++) {
        unsigned char tmp = txid_display[i];
        txid_display[i] = txid_display[31 - i];
        txid_display[31 - i] = tmp;
    }
    char txid_hex[65];
    hex_encode(txid_display, 32, txid_hex);

    const char *sql =
        "INSERT OR REPLACE INTO factories "
        "(id, n_participants, funding_txid, funding_vout, funding_amount, "
        " step_blocks, states_per_layer, cltv_timeout, fee_per_tx, leaf_arity) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        if (own_txn) persist_rollback(p);
        return 0;
    }

    sqlite3_bind_int(stmt, 1, (int)factory_id);
    sqlite3_bind_int(stmt, 2, (int)f->n_participants);
    sqlite3_bind_text(stmt, 3, txid_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, (int)f->funding_vout);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)f->funding_amount_sats);
    sqlite3_bind_int(stmt, 6, (int)f->step_blocks);
    sqlite3_bind_int(stmt, 7, (int)f->states_per_layer);
    sqlite3_bind_int(stmt, 8, (int)f->cltv_timeout);
    sqlite3_bind_int64(stmt, 9, (sqlite3_int64)f->fee_per_tx);
    sqlite3_bind_int(stmt, 10, (int)f->leaf_arity);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    if (!ok) {
        if (own_txn) persist_rollback(p);
        return 0;
    }

    /* Save participants */
    const char *pk_sql =
        "INSERT OR REPLACE INTO factory_participants (factory_id, slot, pubkey) "
        "VALUES (?, ?, ?);";

    for (size_t i = 0; i < f->n_participants; i++) {
        sqlite3_stmt *pk_stmt;
        if (sqlite3_prepare_v2(p->db, pk_sql, -1, &pk_stmt, NULL) != SQLITE_OK) {
            if (own_txn) persist_rollback(p);
            return 0;
        }

        unsigned char pk_ser[33];
        size_t pk_len = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, pk_ser, &pk_len, &f->pubkeys[i],
                                            SECP256K1_EC_COMPRESSED)) {
            sqlite3_finalize(pk_stmt);
            if (own_txn) persist_rollback(p);
            return 0;
        }
        char pk_hex[67];
        hex_encode(pk_ser, 33, pk_hex);

        sqlite3_bind_int(pk_stmt, 1, (int)factory_id);
        sqlite3_bind_int(pk_stmt, 2, (int)i);
        sqlite3_bind_text(pk_stmt, 3, pk_hex, -1, SQLITE_TRANSIENT);

        ok = (sqlite3_step(pk_stmt) == SQLITE_DONE);
        sqlite3_finalize(pk_stmt);
        if (!ok) {
            if (own_txn) persist_rollback(p);
            return 0;
        }
    }

    if (own_txn && !persist_commit(p)) return 0;
    return 1;
}

int persist_mark_factory_closed(persist_t *p, uint32_t factory_id) {
    if (!p || !p->db) return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "UPDATE factories SET state='closed' WHERE id=?;",
            -1, &stmt, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int(stmt, 1, (int)factory_id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 1 : 0;
}

int persist_has_factory(persist_t *p, uint32_t factory_id) {
    if (!p || !p->db) return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "SELECT 1 FROM factories WHERE id = ?;", -1, &stmt, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int(stmt, 1, (int)factory_id);
    int found = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return found;
}

size_t persist_list_active_factory_ids(persist_t *p,
                                        uint32_t *ids_out, size_t max_ids) {
    if (!p || !p->db || !ids_out || max_ids == 0) return 0;
    const char *sql =
        "SELECT factory_id FROM ladder_factories "
        "WHERE state != 'closed' ORDER BY factory_id ASC";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;
    size_t count = 0;
    while (count < max_ids && sqlite3_step(stmt) == SQLITE_ROW) {
        ids_out[count] = (uint32_t)sqlite3_column_int(stmt, 0);
        count++;
    }
    sqlite3_finalize(stmt);
    return count;
}

int persist_load_factory(persist_t *p, uint32_t factory_id,
                          factory_t *f, secp256k1_context *ctx) {
    if (!p || !p->db || !f || !ctx) return 0;

    const char *sql =
        "SELECT n_participants, funding_txid, funding_vout, funding_amount, "
        "step_blocks, states_per_layer, cltv_timeout, fee_per_tx, leaf_arity "
        "FROM factories WHERE id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)factory_id);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return 0;
    }

    size_t n_participants = (size_t)sqlite3_column_int(stmt, 0);
    const char *txid_hex = (const char *)sqlite3_column_text(stmt, 1);
    uint32_t funding_vout = (uint32_t)sqlite3_column_int(stmt, 2);
    uint64_t funding_amount = (uint64_t)sqlite3_column_int64(stmt, 3);
    uint16_t step_blocks = (uint16_t)sqlite3_column_int(stmt, 4);
    uint32_t states_per_layer = (uint32_t)sqlite3_column_int(stmt, 5);
    uint32_t cltv_timeout = (uint32_t)sqlite3_column_int(stmt, 6);
    uint64_t fee_per_tx = (uint64_t)sqlite3_column_int64(stmt, 7);
    int leaf_arity = sqlite3_column_int(stmt, 8);
    if (leaf_arity != 1) leaf_arity = 2;  /* default to arity-2 */

    /* Data validation (Phase 2: item 2.6) */
    if (n_participants < 2 || n_participants > FACTORY_MAX_SIGNERS) {
        fprintf(stderr, "persist_load_factory: invalid n_participants %zu\n",
                n_participants);
        sqlite3_finalize(stmt);
        return 0;
    }
    if (funding_amount == 0) {
        fprintf(stderr, "persist_load_factory: funding_amount is 0\n");
        sqlite3_finalize(stmt);
        return 0;
    }
    if (states_per_layer == 0) {
        fprintf(stderr, "persist_load_factory: states_per_layer is 0\n");
        sqlite3_finalize(stmt);
        return 0;
    }
    if (step_blocks == 0) {
        fprintf(stderr, "persist_load_factory: step_blocks is 0\n");
        sqlite3_finalize(stmt);
        return 0;
    }

    (void)cltv_timeout;
    (void)fee_per_tx;

    unsigned char funding_txid[32];
    if (txid_hex)
        hex_decode(txid_hex, funding_txid, 32);
    else
        memset(funding_txid, 0, 32);

    /* Reverse from display to internal order */
    for (size_t i = 0; i < 16; i++) {
        unsigned char tmp = funding_txid[i];
        funding_txid[i] = funding_txid[31 - i];
        funding_txid[31 - i] = tmp;
    }

    sqlite3_finalize(stmt);

    /* Load participants */
    const char *pk_sql =
        "SELECT slot, pubkey FROM factory_participants "
        "WHERE factory_id = ? ORDER BY slot;";

    sqlite3_stmt *pk_stmt;
    if (sqlite3_prepare_v2(p->db, pk_sql, -1, &pk_stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(pk_stmt, 1, (int)factory_id);

    secp256k1_pubkey pubkeys[FACTORY_MAX_SIGNERS];
    size_t pk_count = 0;
    while (sqlite3_step(pk_stmt) == SQLITE_ROW && pk_count < FACTORY_MAX_SIGNERS) {
        const char *pk_hex = (const char *)sqlite3_column_text(pk_stmt, 1);
        if (!pk_hex) continue;
        unsigned char pk_ser[33];
        if (hex_decode(pk_hex, pk_ser, 33) != 33) continue;
        if (!secp256k1_ec_pubkey_parse(ctx, &pubkeys[pk_count], pk_ser, 33))
            continue;
        pk_count++;
    }
    sqlite3_finalize(pk_stmt);

    if (pk_count != n_participants) return 0;

    /* Compute funding SPK from aggregate key of all participants */
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pubkeys, n_participants))
        return 0;

    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey))
        return 0;
    unsigned char twk[32];
    sha256_tagged("TapTweak", internal_ser, 32, twk);

    musig_keyagg_t ka_copy = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk,
                                                   &ka_copy.cache, twk))
        return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk))
        return 0;

    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tweaked_xonly);

    /* Release any prior tree state (caller may reuse f across loads).
       factory_init_from_pubkeys memsets f, which would leak existing tx_bufs. */
    if (f->n_nodes > 0)
        factory_free(f);

    /* Reconstruct factory */
    factory_init_from_pubkeys(f, ctx, pubkeys, n_participants,
                               step_blocks, states_per_layer);
    f->cltv_timeout = cltv_timeout;
    f->fee_per_tx = fee_per_tx;
    if (leaf_arity == 1)
        factory_set_arity(f, FACTORY_ARITY_1);

    factory_set_funding(f, funding_txid, funding_vout, funding_amount,
                         fund_spk, 34);

    if (!factory_build_tree(f)) {
        /* factory_build_tree may have partially allocated tx_bufs in nodes
           before failing validation; release them so caller doesn't leak. */
        factory_free(f);
        return 0;
    }

    return 1;
}

/* --- Channel --- */

int persist_save_channel(persist_t *p, const channel_t *ch,
                          uint32_t factory_id, uint32_t slot) {
    if (!p || !p->db || !ch) return 0;

    /* Encode funding txid as display hex */
    unsigned char txid_display[32];
    memcpy(txid_display, ch->funding_txid, 32);
    for (size_t i = 0; i < 16; i++) {
        unsigned char tmp = txid_display[i];
        txid_display[i] = txid_display[31 - i];
        txid_display[31 - i] = tmp;
    }
    char txid_hex[65];
    hex_encode(txid_display, 32, txid_hex);

    const char *sql =
        "INSERT OR REPLACE INTO channels "
        "(id, factory_id, slot, local_amount, remote_amount, funding_amount, "
        " commitment_number, funding_txid, funding_vout, state, "
        " to_self_delay, fee_rate_sat_per_kvb, use_revocation_leaf) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)slot);  /* channel_id = slot */
    sqlite3_bind_int(stmt, 2, (int)factory_id);
    sqlite3_bind_int(stmt, 3, (int)slot);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)ch->local_amount);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)ch->remote_amount);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)ch->funding_amount);
    sqlite3_bind_int64(stmt, 7, (sqlite3_int64)ch->commitment_number);
    sqlite3_bind_text(stmt, 8, txid_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 9, (int)ch->funding_vout);
    sqlite3_bind_int(stmt, 10, (int)ch->to_self_delay);
    sqlite3_bind_int64(stmt, 11, (sqlite3_int64)ch->fee_rate_sat_per_kvb);
    sqlite3_bind_int(stmt, 12, ch->use_revocation_leaf);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

int persist_load_channel_state(persist_t *p, uint32_t channel_id,
                                 uint64_t *local_amount,
                                 uint64_t *remote_amount,
                                 uint64_t *commitment_number) {
    if (!p || !p->db) return 0;

    const char *sql =
        "SELECT local_amount, remote_amount, commitment_number "
        "FROM channels WHERE id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return 0;
    }

    uint64_t la = (uint64_t)sqlite3_column_int64(stmt, 0);
    uint64_t ra = (uint64_t)sqlite3_column_int64(stmt, 1);
    uint64_t cn = (uint64_t)sqlite3_column_int64(stmt, 2);

    /* Data validation (Phase 2: item 2.6) */
    if (la == 0 && ra == 0) {
        fprintf(stderr, "persist_load_channel_state: total balance is 0\n");
        sqlite3_finalize(stmt);
        return 0;
    }

    if (local_amount) *local_amount = la;
    if (remote_amount) *remote_amount = ra;
    if (commitment_number) *commitment_number = cn;

    sqlite3_finalize(stmt);
    return 1;
}

int persist_update_channel_balance(persist_t *p, uint32_t channel_id,
                                     uint64_t local_amount,
                                     uint64_t remote_amount,
                                     uint64_t commitment_number) {
    if (!p || !p->db) return 0;

    const char *sql =
        "UPDATE channels SET local_amount = ?, remote_amount = ?, "
        "commitment_number = ? WHERE id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)local_amount);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)remote_amount);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)commitment_number);
    sqlite3_bind_int(stmt, 4, (int)channel_id);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

/* List channel ids currently in the channels table, in ascending order.
   Returns the count written to *count_out (bounded by max). */
int persist_list_channel_ids(persist_t *p, uint32_t *ids_out, size_t max,
                               size_t *count_out) {
    if (!p || !p->db || !ids_out) return 0;

    const char *sql = "SELECT id FROM channels ORDER BY id ASC;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    size_t count = 0;
    while (count < max && sqlite3_step(stmt) == SQLITE_ROW) {
        ids_out[count++] = (uint32_t)sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    if (count_out) *count_out = count;
    return 1;
}

/* --- Revocation secrets --- */

int persist_save_revocation(persist_t *p, uint32_t channel_id,
                              uint64_t commitment_number,
                              const unsigned char *secret32) {
    if (!p || !p->db || !secret32) return 0;

    char secret_hex[65];
    hex_encode(secret32, 32, secret_hex);

    const char *sql =
        "INSERT OR REPLACE INTO revocation_secrets "
        "(channel_id, commit_num, secret) VALUES (?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)commitment_number);
    sqlite3_bind_text(stmt, 3, secret_hex, -1, SQLITE_TRANSIENT);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

/* --- Revocation secrets (flat storage) --- */

int persist_load_revocations_flat(persist_t *p, uint32_t channel_id,
                                    unsigned char (*secrets_out)[32],
                                    uint8_t *valid_out, size_t max,
                                    size_t *count_out) {
    if (!p || !p->db || !secrets_out || !valid_out) return 0;

    memset(valid_out, 0, max);

    const char *sql =
        "SELECT commit_num, secret FROM revocation_secrets "
        "WHERE channel_id = ? ORDER BY commit_num ASC;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        uint64_t commit_num = (uint64_t)sqlite3_column_int64(stmt, 0);
        const char *hex = (const char *)sqlite3_column_text(stmt, 1);
        if (!hex || commit_num >= max) continue;

        if (hex_decode(hex, secrets_out[commit_num], 32) == 32) {
            valid_out[commit_num] = 1;
            count++;
        }
    }

    sqlite3_finalize(stmt);
    if (count_out) *count_out = count;
    return 1;
}

/* --- Local per-commitment secrets --- */

int persist_save_local_pcs(persist_t *p, uint32_t channel_id,
                             uint64_t commit_num,
                             const unsigned char *secret32) {
    if (!p || !p->db || !secret32) return 0;

    char secret_hex[65];
    hex_encode(secret32, 32, secret_hex);

    const char *sql =
        "INSERT OR REPLACE INTO local_pcs "
        "(channel_id, commit_num, secret) VALUES (?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)commit_num);
    sqlite3_bind_text(stmt, 3, secret_hex, -1, SQLITE_TRANSIENT);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

int persist_load_local_pcs(persist_t *p, uint32_t channel_id,
                             unsigned char (*secrets_out)[32], size_t max,
                             size_t *count_out) {
    if (!p || !p->db || !secrets_out) return 0;

    const char *sql =
        "SELECT commit_num, secret FROM local_pcs "
        "WHERE channel_id = ? ORDER BY commit_num ASC;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        uint64_t commit_num = (uint64_t)sqlite3_column_int64(stmt, 0);
        const char *hex = (const char *)sqlite3_column_text(stmt, 1);
        if (!hex || commit_num >= max) continue;

        if (hex_decode(hex, secrets_out[commit_num], 32) == 32)
            count++;
    }

    sqlite3_finalize(stmt);
    if (count_out) *count_out = count;
    return 1;
}

/* --- Remote per-commitment points --- */

int persist_save_remote_pcp(persist_t *p, uint32_t channel_id,
                              uint64_t commit_num,
                              const unsigned char *point33) {
    if (!p || !p->db || !point33) return 0;

    char point_hex[67];
    hex_encode(point33, 33, point_hex);

    const char *sql =
        "INSERT OR REPLACE INTO remote_pcps "
        "(channel_id, commit_num, point) VALUES (?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)commit_num);
    sqlite3_bind_text(stmt, 3, point_hex, -1, SQLITE_TRANSIENT);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

int persist_load_remote_pcp(persist_t *p, uint32_t channel_id,
                              uint64_t commit_num,
                              unsigned char *point33_out) {
    if (!p || !p->db || !point33_out) return 0;

    const char *sql =
        "SELECT point FROM remote_pcps "
        "WHERE channel_id = ? AND commit_num = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)commit_num);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return 0;
    }

    const char *hex = (const char *)sqlite3_column_text(stmt, 0);
    int ok = 0;
    if (hex && hex_decode(hex, point33_out, 33) == 33)
        ok = 1;

    sqlite3_finalize(stmt);
    return ok;
}

/* --- HTLC --- */

int persist_save_htlc(persist_t *p, uint32_t channel_id,
                        const htlc_t *htlc) {
    if (!p || !p->db || !htlc) return 0;

    char hash_hex[65], preimage_hex[65];
    hex_encode(htlc->payment_hash, 32, hash_hex);
    hex_encode(htlc->payment_preimage, 32, preimage_hex);

    const char *direction_str = (htlc->direction == HTLC_OFFERED) ? "offered" : "received";
    const char *state_str;
    switch (htlc->state) {
        case HTLC_STATE_ACTIVE:    state_str = "active"; break;
        case HTLC_STATE_FULFILLED: state_str = "fulfilled"; break;
        case HTLC_STATE_FAILED:    state_str = "failed"; break;
        default:                   state_str = "unknown"; break;
    }

    const char *sql =
        "INSERT OR REPLACE INTO htlcs "
        "(channel_id, htlc_id, direction, amount, payment_hash, "
        " payment_preimage, cltv_expiry, state, fee_at_add) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)htlc->id);
    sqlite3_bind_text(stmt, 3, direction_str, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)htlc->amount_sats);
    sqlite3_bind_text(stmt, 5, hash_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, preimage_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 7, (int)htlc->cltv_expiry);
    sqlite3_bind_text(stmt, 8, state_str, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 9, (sqlite3_int64)htlc->fee_at_add);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

size_t persist_load_htlcs(persist_t *p, uint32_t channel_id,
                            htlc_t *htlcs_out, size_t max_htlcs) {
    if (!p || !p->db || !htlcs_out) return 0;

    const char *sql =
        "SELECT htlc_id, direction, amount, payment_hash, "
        "payment_preimage, cltv_expiry, state, fee_at_add "
        "FROM htlcs WHERE channel_id = ? ORDER BY htlc_id;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_htlcs) {
        htlc_t *h = &htlcs_out[count];
        memset(h, 0, sizeof(*h));

        h->id = (uint64_t)sqlite3_column_int64(stmt, 0);

        const char *dir = (const char *)sqlite3_column_text(stmt, 1);
        h->direction = (dir && strcmp(dir, "offered") == 0)
                       ? HTLC_OFFERED : HTLC_RECEIVED;

        h->amount_sats = (uint64_t)sqlite3_column_int64(stmt, 2);

        const char *hash_hex = (const char *)sqlite3_column_text(stmt, 3);
        if (hash_hex)
            hex_decode(hash_hex, h->payment_hash, 32);

        const char *preimage_hex = (const char *)sqlite3_column_text(stmt, 4);
        if (preimage_hex)
            hex_decode(preimage_hex, h->payment_preimage, 32);

        h->cltv_expiry = (uint32_t)sqlite3_column_int(stmt, 5);

        const char *state = (const char *)sqlite3_column_text(stmt, 6);
        if (state && strcmp(state, "fulfilled") == 0)
            h->state = HTLC_STATE_FULFILLED;
        else if (state && strcmp(state, "failed") == 0)
            h->state = HTLC_STATE_FAILED;
        else
            h->state = HTLC_STATE_ACTIVE;

        h->fee_at_add = (uint64_t)sqlite3_column_int64(stmt, 7);

        count++;
    }

    sqlite3_finalize(stmt);
    return count;
}

int persist_delete_htlc(persist_t *p, uint32_t channel_id, uint64_t htlc_id) {
    if (!p || !p->db) return 0;

    const char *sql =
        "DELETE FROM htlcs WHERE channel_id = ? AND htlc_id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)htlc_id);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

/* --- Nonce pool --- */

int persist_save_nonce_pool(persist_t *p, uint32_t channel_id,
                              const char *side,
                              const unsigned char *pool_data,
                              size_t pool_data_len,
                              size_t next_index) {
    if (!p || !p->db || !side) return 0;

    const char *sql =
        "INSERT OR REPLACE INTO nonce_pools "
        "(channel_id, side, pool_data, next_index) VALUES (?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);
    sqlite3_bind_text(stmt, 2, side, -1, SQLITE_STATIC);
    if (pool_data && pool_data_len > 0)
        sqlite3_bind_blob(stmt, 3, pool_data, (int)pool_data_len, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(stmt, 3);
    sqlite3_bind_int(stmt, 4, (int)next_index);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

int persist_load_nonce_pool(persist_t *p, uint32_t channel_id,
                              const char *side,
                              unsigned char *pool_data_out,
                              size_t max_len,
                              size_t *data_len_out,
                              size_t *next_index_out) {
    if (!p || !p->db || !side) return 0;

    const char *sql =
        "SELECT pool_data, next_index FROM nonce_pools "
        "WHERE channel_id = ? AND side = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);
    sqlite3_bind_text(stmt, 2, side, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return 0;
    }

    const void *blob = sqlite3_column_blob(stmt, 0);
    int blob_len = sqlite3_column_bytes(stmt, 0);
    size_t copy_len = (size_t)blob_len < max_len ? (size_t)blob_len : max_len;

    if (pool_data_out && blob && copy_len > 0)
        memcpy(pool_data_out, blob, copy_len);
    if (data_len_out)
        *data_len_out = copy_len;
    if (next_index_out)
        *next_index_out = (size_t)sqlite3_column_int(stmt, 1);

    sqlite3_finalize(stmt);
    return 1;
}

/* --- Old commitments (watchtower) --- */

int persist_save_old_commitment(persist_t *p, uint32_t channel_id,
                                  uint64_t commit_num,
                                  const unsigned char *txid32,
                                  uint32_t to_local_vout,
                                  uint64_t to_local_amount,
                                  const unsigned char *to_local_spk,
                                  size_t spk_len) {
    if (!p || !p->db || !txid32 || !to_local_spk) return 0;

    char txid_hex[65], spk_hex[69];
    hex_encode(txid32, 32, txid_hex);
    hex_encode(to_local_spk, spk_len, spk_hex);

    const char *sql =
        "INSERT OR REPLACE INTO old_commitments "
        "(channel_id, commit_num, txid, to_local_vout, to_local_amount, to_local_spk) "
        "VALUES (?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)commit_num);
    sqlite3_bind_text(stmt, 3, txid_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, (int)to_local_vout);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)to_local_amount);
    sqlite3_bind_text(stmt, 6, spk_hex, -1, SQLITE_TRANSIENT);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

size_t persist_load_old_commitments(persist_t *p, uint32_t channel_id,
                                      uint64_t *commit_nums,
                                      unsigned char (*txids)[32],
                                      uint32_t *vouts,
                                      uint64_t *amounts,
                                      unsigned char (*spks)[34],
                                      size_t *spk_lens,
                                      size_t max_entries) {
    if (!p || !p->db) return 0;

    const char *sql =
        "SELECT commit_num, txid, to_local_vout, to_local_amount, to_local_spk "
        "FROM old_commitments WHERE channel_id = ? ORDER BY commit_num ASC;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_entries) {
        if (commit_nums)
            commit_nums[count] = (uint64_t)sqlite3_column_int64(stmt, 0);

        const char *txid_hex = (const char *)sqlite3_column_text(stmt, 1);
        if (txid_hex && txids)
            hex_decode(txid_hex, txids[count], 32);

        if (vouts)
            vouts[count] = (uint32_t)sqlite3_column_int(stmt, 2);

        if (amounts)
            amounts[count] = (uint64_t)sqlite3_column_int64(stmt, 3);

        const char *spk_hex_str = (const char *)sqlite3_column_text(stmt, 4);
        if (spk_hex_str && spks && spk_lens) {
            int decoded = hex_decode(spk_hex_str, spks[count], 34);
            spk_lens[count] = decoded > 0 ? (size_t)decoded : 0;
        }

        count++;
    }

    sqlite3_finalize(stmt);
    return count;
}

/* --- Old commitment HTLC outputs (watchtower) --- */

#include "superscalar/watchtower.h"

int persist_save_old_commitment_htlc(persist_t *p, uint32_t channel_id,
    uint64_t commit_num, const watchtower_htlc_t *htlc) {
    if (!p || !p->db || !htlc) return 0;

    char spk_hex[69], hash_hex[65];
    hex_encode(htlc->htlc_spk, 34, spk_hex);
    hex_encode(htlc->payment_hash, 32, hash_hex);

    const char *sql =
        "INSERT OR REPLACE INTO old_commitment_htlcs "
        "(channel_id, commit_num, htlc_vout, htlc_amount, htlc_spk, "
        "direction, payment_hash, cltv_expiry) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)commit_num);
    sqlite3_bind_int(stmt, 3, (int)htlc->htlc_vout);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)htlc->htlc_amount);
    sqlite3_bind_text(stmt, 5, spk_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 6, (int)htlc->direction);
    sqlite3_bind_text(stmt, 7, hash_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 8, (int)htlc->cltv_expiry);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

size_t persist_load_old_commitment_htlcs(persist_t *p, uint32_t channel_id,
    uint64_t commit_num, watchtower_htlc_t *htlcs_out, size_t max_htlcs) {
    if (!p || !p->db || !htlcs_out) return 0;

    const char *sql =
        "SELECT htlc_vout, htlc_amount, htlc_spk, direction, payment_hash, cltv_expiry "
        "FROM old_commitment_htlcs WHERE channel_id = ? AND commit_num = ? "
        "ORDER BY htlc_vout ASC;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)commit_num);

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_htlcs) {
        watchtower_htlc_t *h = &htlcs_out[count];
        h->htlc_vout = (uint32_t)sqlite3_column_int(stmt, 0);
        h->htlc_amount = (uint64_t)sqlite3_column_int64(stmt, 1);

        const char *spk_hex = (const char *)sqlite3_column_text(stmt, 2);
        if (spk_hex)
            hex_decode(spk_hex, h->htlc_spk, 34);

        h->direction = (htlc_direction_t)sqlite3_column_int(stmt, 3);

        const char *hash_hex = (const char *)sqlite3_column_text(stmt, 4);
        if (hash_hex)
            hex_decode(hash_hex, h->payment_hash, 32);

        h->cltv_expiry = (uint32_t)sqlite3_column_int(stmt, 5);
        count++;
    }

    sqlite3_finalize(stmt);
    return count;
}

/* --- Wire message logging (Phase 22) --- */

void persist_log_wire_message(persist_t *p, int direction, uint8_t msg_type,
                               const char *peer_label, const void *json) {
    if (!p || !p->db) return;

    const char *dir_str = direction ? "recv" : "sent";
    const char *msg_name = wire_msg_type_name(msg_type);

    /* Truncated payload summary */
    char summary[501];
    summary[0] = '\0';
    if (json) {
        char *printed = cJSON_PrintUnformatted((cJSON *)json);
        if (printed) {
            size_t len = strlen(printed);
            if (len > 500) len = 500;
            memcpy(summary, printed, len);
            summary[len] = '\0';
            free(printed);
        }
    }

    const char *sql =
        "INSERT INTO wire_messages "
        "(timestamp, direction, msg_type, msg_name, peer, payload_summary) "
        "VALUES (?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return;

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)time(NULL));
    sqlite3_bind_text(stmt, 2, dir_str, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, (int)msg_type);
    sqlite3_bind_text(stmt, 4, msg_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, peer_label ? peer_label : "unknown", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, summary, -1, SQLITE_TRANSIENT);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

/* --- Factory tree nodes (Phase 22) --- */

int persist_save_tree_nodes(persist_t *p, const factory_t *f, uint32_t factory_id) {
    if (!p || !p->db || !f) return 0;

    /* Use internal transaction if caller hasn't started one */
    int own_txn = !p->in_transaction;
    if (own_txn && !persist_begin(p)) return 0;

    const char *sql =
        "INSERT OR REPLACE INTO tree_nodes "
        "(factory_id, node_index, type, parent_index, parent_vout, "
        " dw_layer_index, n_signers, signer_indices, n_outputs, output_amounts, "
        " nsequence, input_amount, txid, is_built, is_signed, spending_spk, "
        " signed_tx_hex) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    for (size_t i = 0; i < f->n_nodes; i++) {
        const factory_node_t *node = &f->nodes[i];

        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            if (own_txn) persist_rollback(p);
            return 0;
        }

        sqlite3_bind_int(stmt, 1, (int)factory_id);
        sqlite3_bind_int(stmt, 2, (int)i);
        sqlite3_bind_text(stmt, 3, node->type == NODE_KICKOFF ? "kickoff" : "state",
                          -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 4, node->parent_index);
        sqlite3_bind_int(stmt, 5, (int)node->parent_vout);
        sqlite3_bind_int(stmt, 6, node->dw_layer_index);
        sqlite3_bind_int(stmt, 7, (int)node->n_signers);

        /* signer_indices as comma-separated */
        char signers_buf[128];
        signers_buf[0] = '\0';
        for (size_t s = 0; s < node->n_signers; s++) {
            char tmp[16];
            snprintf(tmp, sizeof(tmp), "%s%u", s > 0 ? "," : "",
                     node->signer_indices[s]);
            strncat(signers_buf, tmp, sizeof(signers_buf) - strlen(signers_buf) - 1);
        }
        sqlite3_bind_text(stmt, 8, signers_buf, -1, SQLITE_TRANSIENT);

        sqlite3_bind_int(stmt, 9, (int)node->n_outputs);

        /* output_amounts as comma-separated sats */
        char amounts_buf[256];
        amounts_buf[0] = '\0';
        for (size_t o = 0; o < node->n_outputs; o++) {
            char tmp[32];
            snprintf(tmp, sizeof(tmp), "%s%llu", o > 0 ? "," : "",
                     (unsigned long long)node->outputs[o].amount_sats);
            strncat(amounts_buf, tmp, sizeof(amounts_buf) - strlen(amounts_buf) - 1);
        }
        sqlite3_bind_text(stmt, 10, amounts_buf, -1, SQLITE_TRANSIENT);

        sqlite3_bind_int64(stmt, 11, (sqlite3_int64)node->nsequence);
        sqlite3_bind_int64(stmt, 12, (sqlite3_int64)node->input_amount);

        /* txid in display order */
        if (node->is_built) {
            unsigned char display_txid[32];
            memcpy(display_txid, node->txid, 32);
            reverse_bytes(display_txid, 32);
            char txid_hex[65];
            hex_encode(display_txid, 32, txid_hex);
            sqlite3_bind_text(stmt, 13, txid_hex, -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_null(stmt, 13);
        }

        sqlite3_bind_int(stmt, 14, node->is_built);
        sqlite3_bind_int(stmt, 15, node->is_signed);

        /* spending_spk as hex */
        if (node->spending_spk_len > 0) {
            char spk_hex[69];
            hex_encode(node->spending_spk, node->spending_spk_len, spk_hex);
            sqlite3_bind_text(stmt, 16, spk_hex, -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_null(stmt, 16);
        }

        /* signed_tx_hex — persist the signed transaction for crash recovery */
        if (node->is_signed && node->signed_tx.len > 0) {
            char *stx_hex = (char *)malloc(node->signed_tx.len * 2 + 1);
            if (stx_hex) {
                hex_encode(node->signed_tx.data, node->signed_tx.len, stx_hex);
                sqlite3_bind_text(stmt, 17, stx_hex, -1, SQLITE_TRANSIENT);
                free(stx_hex);
            } else {
                sqlite3_bind_null(stmt, 17);
            }
        } else {
            sqlite3_bind_null(stmt, 17);
        }

        int ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        if (!ok) {
            if (own_txn) persist_rollback(p);
            return 0;
        }
    }

    if (own_txn && !persist_commit(p)) return 0;
    return 1;
}

/* --- Broadcast audit log --- */

int persist_log_broadcast(persist_t *p, const char *txid,
                           const char *source, const char *raw_hex,
                           const char *result) {
    if (!p || !p->db) return 0;

    const char *sql =
        "INSERT INTO broadcast_log (txid, source, raw_hex, result) "
        "VALUES (?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_text(stmt, 1, txid ? txid : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, source ? source : "unknown", -1, SQLITE_TRANSIENT);
    if (raw_hex)
        sqlite3_bind_text(stmt, 3, raw_hex, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(stmt, 3);
    if (result)
        sqlite3_bind_text(stmt, 4, result, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(stmt, 4);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

/* Retry failed penalty broadcasts. Returns count re-broadcast. */
int persist_retry_pending_broadcasts(persist_t *p, chain_backend_t *chain) {
    if (!p || !p->db || !chain) return 0;

    const char *sql =
        "SELECT id, raw_hex FROM broadcast_log "
        "WHERE result = 'pending_retry' AND raw_hex IS NOT NULL "
        "ORDER BY broadcast_time ASC LIMIT 16;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    int retried = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int row_id = sqlite3_column_int(stmt, 0);
        const char *raw_hex = (const char *)sqlite3_column_text(stmt, 1);
        if (!raw_hex) continue;

        char txid_out[65] = {0};
        if (chain->send_raw_tx(chain, raw_hex, txid_out)) {
            fprintf(stderr, "Watchtower: retry broadcast succeeded: %s\n", txid_out);
            /* Mark as ok */
            const char *upd = "UPDATE broadcast_log SET result='ok', txid=? WHERE id=?;";
            sqlite3_stmt *u;
            if (sqlite3_prepare_v2(p->db, upd, -1, &u, NULL) == SQLITE_OK) {
                sqlite3_bind_text(u, 1, txid_out, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(u, 2, row_id);
                sqlite3_step(u);
                sqlite3_finalize(u);
            }
            retried++;
        } else {
            /* Still failing — leave as pending_retry for next cycle */
            fprintf(stderr, "Watchtower: retry broadcast still failing (id=%d)\n", row_id);
        }
    }
    sqlite3_finalize(stmt);
    return retried;
}

/* --- Reorg staleness tracking --- */

int persist_mark_reorg_stale(persist_t *p, int reorg_height) {
    if (!p || !p->db || reorg_height < 0) return 0;

    int total = 0;

    /* broadcast_log: mark 'ok' entries as potentially stale.
       We keep the data — just flag it so operators can audit. */
    {
        const char *sql =
            "UPDATE broadcast_log SET reorg_stale = 1 "
            "WHERE result = 'ok' AND reorg_stale = 0;";
        sqlite3_exec(p->db, sql, NULL, NULL, NULL);
        total += sqlite3_changes(p->db);
    }

    /* tree_nodes: mark nodes validated above the reorg height as stale.
       Factory recovery will skip stale nodes until re-validated. */
    {
        char sql[256];
        snprintf(sql, sizeof(sql),
            "UPDATE tree_nodes SET reorg_stale = 1 "
            "WHERE validated_at_height > %d AND reorg_stale = 0;",
            reorg_height);
        sqlite3_exec(p->db, sql, NULL, NULL, NULL);
        total += sqlite3_changes(p->db);
    }

    /* jit_channels: mark funded channels above reorg height as stale.
       jit_channels_revalidate_funding() will re-check on next cycle. */
    {
        char sql[256];
        snprintf(sql, sizeof(sql),
            "UPDATE jit_channels SET reorg_stale = 1 "
            "WHERE state = 'open' AND created_block > %d AND reorg_stale = 0;",
            reorg_height);
        sqlite3_exec(p->db, sql, NULL, NULL, NULL);
        total += sqlite3_changes(p->db);
    }

    /* ladder_factories: mark factories created above reorg height as stale,
       AND any factory with partial_rotation=1 (rotation close TX may have
       been reorged out regardless of created_block). */
    {
        char sql[256];
        snprintf(sql, sizeof(sql),
            "UPDATE ladder_factories SET reorg_stale = 1 "
            "WHERE (created_block > %d OR partial_rotation = 1) "
            "AND reorg_stale = 0;",
            reorg_height);
        sqlite3_exec(p->db, sql, NULL, NULL, NULL);
        total += sqlite3_changes(p->db);
    }

    /* watchtower_pending: reset cycles for re-evaluation */
    {
        const char *sql =
            "UPDATE watchtower_pending SET cycles_in_mempool = 0;";
        sqlite3_exec(p->db, sql, NULL, NULL, NULL);
        total += sqlite3_changes(p->db);
    }

    if (total > 0)
        fprintf(stderr, "persist_mark_reorg_stale: marked %d entries stale "
                "(reorg to height %d)\n", total, reorg_height);

    return total;
}

/* --- Signing progress tracking --- */

int persist_save_signing_progress(persist_t *p, uint32_t factory_id,
                                    uint32_t node_index, uint32_t signer_slot,
                                    int has_nonce, int has_partial_sig) {
    if (!p || !p->db) return 0;

    const char *sql =
        "INSERT OR REPLACE INTO signing_progress "
        "(factory_id, node_index, signer_slot, has_nonce, has_partial_sig, updated_at) "
        "VALUES (?, ?, ?, ?, ?, strftime('%s','now'));";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)factory_id);
    sqlite3_bind_int(stmt, 2, (int)node_index);
    sqlite3_bind_int(stmt, 3, (int)signer_slot);
    sqlite3_bind_int(stmt, 4, has_nonce);
    sqlite3_bind_int(stmt, 5, has_partial_sig);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

int persist_clear_signing_progress(persist_t *p, uint32_t factory_id) {
    if (!p || !p->db) return 0;

    const char *sql = "DELETE FROM signing_progress WHERE factory_id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)factory_id);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

/* --- Ladder factory state (Phase 22) --- */

int persist_save_ladder_factory(persist_t *p, uint32_t factory_id,
                                 const char *state_str,
                                 int is_funded, int is_initialized,
                                 size_t n_departed,
                                 uint32_t created_block,
                                 uint32_t active_blocks,
                                 uint32_t dying_blocks,
                                 int partial_rotation) {
    if (!p || !p->db) return 0;

    const char *sql =
        "INSERT OR REPLACE INTO ladder_factories "
        "(factory_id, state, is_funded, is_initialized, n_departed, "
        " created_block, active_blocks, dying_blocks, partial_rotation, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)factory_id);
    sqlite3_bind_text(stmt, 2, state_str ? state_str : "active", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, is_funded);
    sqlite3_bind_int(stmt, 4, is_initialized);
    sqlite3_bind_int(stmt, 5, (int)n_departed);
    sqlite3_bind_int(stmt, 6, (int)created_block);
    sqlite3_bind_int(stmt, 7, (int)active_blocks);
    sqlite3_bind_int(stmt, 8, (int)dying_blocks);
    sqlite3_bind_int(stmt, 9, partial_rotation);
    sqlite3_bind_int64(stmt, 10, (sqlite3_int64)time(NULL));

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

/* === Phase 23: Persistence Hardening === */

/* --- DW counter state --- */

int persist_save_dw_counter(persist_t *p, uint32_t factory_id,
                             uint32_t current_epoch, uint32_t n_layers,
                             const uint32_t *layer_states) {
    if (!p || !p->db || !layer_states || n_layers == 0) return 0;

    /* Build comma-separated layer_states string */
    char buf[256];
    buf[0] = '\0';
    for (uint32_t i = 0; i < n_layers; i++) {
        char tmp[16];
        snprintf(tmp, sizeof(tmp), "%s%u", i > 0 ? "," : "", layer_states[i]);
        strncat(buf, tmp, sizeof(buf) - strlen(buf) - 1);
    }

    const char *sql =
        "INSERT OR REPLACE INTO dw_counter_state "
        "(factory_id, current_epoch, n_layers, layer_states, "
        " per_leaf_enabled, n_leaf_nodes, leaf_states) "
        "VALUES (?, ?, ?, ?, 0, 2, '0,0');";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)factory_id);
    sqlite3_bind_int(stmt, 2, (int)current_epoch);
    sqlite3_bind_int(stmt, 3, (int)n_layers);
    sqlite3_bind_text(stmt, 4, buf, -1, SQLITE_TRANSIENT);

    int ok2 = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok2;
}

int persist_save_dw_counter_with_leaves(persist_t *p, uint32_t factory_id,
                                         uint32_t current_epoch, uint32_t n_layers,
                                         const uint32_t *layer_states,
                                         int per_leaf_enabled,
                                         const uint32_t *leaf_states,
                                         int n_leaf_nodes) {
    if (!p || !p->db || !layer_states || n_layers == 0) return 0;
    if (per_leaf_enabled && (!leaf_states || n_leaf_nodes <= 0)) return 0;

    char buf[256];
    buf[0] = '\0';
    for (uint32_t i = 0; i < n_layers; i++) {
        char tmp[16];
        snprintf(tmp, sizeof(tmp), "%s%u", i > 0 ? "," : "", layer_states[i]);
        strncat(buf, tmp, sizeof(buf) - strlen(buf) - 1);
    }

    /* Build comma-separated leaf_states string */
    char leaf_buf[256];
    leaf_buf[0] = '\0';
    int n_leaves = (per_leaf_enabled && leaf_states) ? n_leaf_nodes : 2;
    for (int i = 0; i < n_leaves; i++) {
        char tmp[16];
        uint32_t val = (per_leaf_enabled && leaf_states) ? leaf_states[i] : 0;
        snprintf(tmp, sizeof(tmp), "%s%u", i > 0 ? "," : "", val);
        strncat(leaf_buf, tmp, sizeof(leaf_buf) - strlen(leaf_buf) - 1);
    }

    const char *sql =
        "INSERT OR REPLACE INTO dw_counter_state "
        "(factory_id, current_epoch, n_layers, layer_states, "
        " per_leaf_enabled, n_leaf_nodes, leaf_states) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)factory_id);
    sqlite3_bind_int(stmt, 2, (int)current_epoch);
    sqlite3_bind_int(stmt, 3, (int)n_layers);
    sqlite3_bind_text(stmt, 4, buf, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, per_leaf_enabled);
    sqlite3_bind_int(stmt, 6, n_leaves);
    sqlite3_bind_text(stmt, 7, leaf_buf, -1, SQLITE_TRANSIENT);

    int ok2 = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok2;
}

int persist_load_dw_counter(persist_t *p, uint32_t factory_id,
                             uint32_t *epoch_out, uint32_t *n_layers_out,
                             uint32_t *layer_states_out, size_t max_layers) {
    if (!p || !p->db) return 0;

    const char *sql =
        "SELECT current_epoch, n_layers, layer_states "
        "FROM dw_counter_state WHERE factory_id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)factory_id);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return 0;
    }

    uint32_t epoch = (uint32_t)sqlite3_column_int(stmt, 0);
    uint32_t n_layers = (uint32_t)sqlite3_column_int(stmt, 1);
    const char *states_str = (const char *)sqlite3_column_text(stmt, 2);

    if (epoch_out) *epoch_out = epoch;
    if (n_layers_out) *n_layers_out = n_layers;

    /* Parse comma-separated layer states */
    if (layer_states_out && states_str) {
        char tmp[256];
        strncpy(tmp, states_str, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = '\0';

        char *tok = strtok(tmp, ",");
        size_t idx = 0;
        while (tok && idx < max_layers && idx < n_layers) {
            layer_states_out[idx++] = (uint32_t)strtol(tok, NULL, 10);
            tok = strtok(NULL, ",");
        }
    }

    sqlite3_finalize(stmt);
    return 1;
}

int persist_load_dw_counter_with_leaves(persist_t *p, uint32_t factory_id,
                                         uint32_t *epoch_out, uint32_t *n_layers_out,
                                         uint32_t *layer_states_out, size_t max_layers,
                                         int *per_leaf_enabled_out,
                                         uint32_t *leaf_states_out,
                                         int *n_leaf_nodes_out,
                                         size_t max_leaf_nodes) {
    if (!p || !p->db) return 0;

    const char *sql =
        "SELECT current_epoch, n_layers, layer_states, "
        "per_leaf_enabled, n_leaf_nodes, leaf_states "
        "FROM dw_counter_state WHERE factory_id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)factory_id);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return 0;
    }

    uint32_t epoch = (uint32_t)sqlite3_column_int(stmt, 0);
    uint32_t n_layers = (uint32_t)sqlite3_column_int(stmt, 1);
    const char *states_str = (const char *)sqlite3_column_text(stmt, 2);

    if (epoch_out) *epoch_out = epoch;
    if (n_layers_out) *n_layers_out = n_layers;

    if (layer_states_out && states_str) {
        char tmp[256];
        strncpy(tmp, states_str, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = '\0';

        char *tok = strtok(tmp, ",");
        size_t idx = 0;
        while (tok && idx < max_layers && idx < n_layers) {
            layer_states_out[idx++] = (uint32_t)strtol(tok, NULL, 10);
            tok = strtok(NULL, ",");
        }
    }

    if (per_leaf_enabled_out)
        *per_leaf_enabled_out = sqlite3_column_int(stmt, 3);

    int n_leaf = sqlite3_column_int(stmt, 4);
    if (n_leaf_nodes_out)
        *n_leaf_nodes_out = n_leaf;

    const char *leaf_str = (const char *)sqlite3_column_text(stmt, 5);
    if (leaf_states_out && leaf_str) {
        char tmp[256];
        strncpy(tmp, leaf_str, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = '\0';

        char *tok = strtok(tmp, ",");
        size_t idx = 0;
        while (tok && idx < max_leaf_nodes && idx < (size_t)n_leaf) {
            leaf_states_out[idx++] = (uint32_t)strtol(tok, NULL, 10);
            tok = strtok(NULL, ",");
        }
    }

    sqlite3_finalize(stmt);
    return 1;
}

/* --- Departed clients --- */

int persist_save_departed_client(persist_t *p, uint32_t factory_id,
                                  uint32_t client_idx,
                                  const unsigned char *extracted_key32) {
    if (!p || !p->db || !extracted_key32) return 0;

    char key_hex[65];
    hex_encode(extracted_key32, 32, key_hex);

    const char *sql =
        "INSERT OR REPLACE INTO departed_clients "
        "(factory_id, client_idx, extracted_key) VALUES (?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)factory_id);
    sqlite3_bind_int(stmt, 2, (int)client_idx);
    sqlite3_bind_text(stmt, 3, key_hex, -1, SQLITE_TRANSIENT);

    int ok3 = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok3;
}

size_t persist_load_departed_clients(persist_t *p, uint32_t factory_id,
                                      int *departed_out,
                                      unsigned char (*keys_out)[32],
                                      size_t max_clients) {
    if (!p || !p->db) return 0;

    const char *sql =
        "SELECT client_idx, extracted_key FROM departed_clients "
        "WHERE factory_id = ? ORDER BY client_idx;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)factory_id);

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        uint32_t cidx = (uint32_t)sqlite3_column_int(stmt, 0);
        const char *key_hex = (const char *)sqlite3_column_text(stmt, 1);

        if (cidx < max_clients) {
            if (departed_out) departed_out[cidx] = 1;
            if (keys_out && key_hex)
                hex_decode(key_hex, keys_out[cidx], 32);
        }
        count++;
    }

    sqlite3_finalize(stmt);
    return count;
}

/* --- Invoice registry --- */

int persist_save_invoice(persist_t *p,
                          const unsigned char *payment_hash32,
                          size_t dest_client, uint64_t amount_msat) {
    if (!p || !p->db || !payment_hash32) return 0;

    char hash_hex[65];
    hex_encode(payment_hash32, 32, hash_hex);

    const char *sql =
        "INSERT INTO invoice_registry "
        "(payment_hash, dest_client, amount_msat) VALUES (?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_text(stmt, 1, hash_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, (int)dest_client);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)amount_msat);

    int ok4 = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok4;
}

int persist_deactivate_invoice(persist_t *p,
                                const unsigned char *payment_hash32) {
    if (!p || !p->db || !payment_hash32) return 0;

    char hash_hex[65];
    hex_encode(payment_hash32, 32, hash_hex);

    const char *sql =
        "UPDATE invoice_registry SET active = 0 "
        "WHERE payment_hash = ? AND active = 1;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_text(stmt, 1, hash_hex, -1, SQLITE_TRANSIENT);

    int ok5 = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok5;
}

size_t persist_load_invoices(persist_t *p,
                              unsigned char (*hashes_out)[32],
                              size_t *dest_clients_out,
                              uint64_t *amounts_out,
                              size_t max_invoices) {
    if (!p || !p->db) return 0;

    const char *sql =
        "SELECT payment_hash, dest_client, amount_msat "
        "FROM invoice_registry WHERE active = 1 ORDER BY id;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_invoices) {
        const char *hash_hex = (const char *)sqlite3_column_text(stmt, 0);
        if (hashes_out && hash_hex)
            hex_decode(hash_hex, hashes_out[count], 32);
        if (dest_clients_out)
            dest_clients_out[count] = (size_t)sqlite3_column_int(stmt, 1);
        if (amounts_out)
            amounts_out[count] = (uint64_t)sqlite3_column_int64(stmt, 2);
        count++;
    }

    sqlite3_finalize(stmt);
    return count;
}

/* --- HTLC origin tracking --- */

int persist_save_htlc_origin(persist_t *p,
                              const unsigned char *payment_hash32,
                              uint64_t bridge_htlc_id, uint64_t request_id,
                              size_t sender_idx, uint64_t sender_htlc_id) {
    if (!p || !p->db || !payment_hash32) return 0;

    char hash_hex[65];
    hex_encode(payment_hash32, 32, hash_hex);

    const char *sql =
        "INSERT INTO htlc_origins "
        "(payment_hash, bridge_htlc_id, request_id, sender_idx, sender_htlc_id) "
        "VALUES (?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_text(stmt, 1, hash_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)bridge_htlc_id);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)request_id);
    sqlite3_bind_int(stmt, 4, (int)sender_idx);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)sender_htlc_id);

    int ok6 = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok6;
}

int persist_deactivate_htlc_origin(persist_t *p,
                                    const unsigned char *payment_hash32) {
    if (!p || !p->db || !payment_hash32) return 0;

    char hash_hex[65];
    hex_encode(payment_hash32, 32, hash_hex);

    const char *sql =
        "UPDATE htlc_origins SET active = 0 "
        "WHERE payment_hash = ? AND active = 1;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_text(stmt, 1, hash_hex, -1, SQLITE_TRANSIENT);

    int ok7 = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok7;
}

size_t persist_load_htlc_origins(persist_t *p,
                                  unsigned char (*hashes_out)[32],
                                  uint64_t *bridge_ids_out,
                                  uint64_t *request_ids_out,
                                  size_t *sender_idxs_out,
                                  uint64_t *sender_htlc_ids_out,
                                  size_t max_origins) {
    if (!p || !p->db) return 0;

    const char *sql =
        "SELECT payment_hash, bridge_htlc_id, request_id, sender_idx, sender_htlc_id "
        "FROM htlc_origins WHERE active = 1 ORDER BY id;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_origins) {
        const char *hash_hex = (const char *)sqlite3_column_text(stmt, 0);
        if (hashes_out && hash_hex)
            hex_decode(hash_hex, hashes_out[count], 32);
        if (bridge_ids_out)
            bridge_ids_out[count] = (uint64_t)sqlite3_column_int64(stmt, 1);
        if (request_ids_out)
            request_ids_out[count] = (uint64_t)sqlite3_column_int64(stmt, 2);
        if (sender_idxs_out)
            sender_idxs_out[count] = (size_t)sqlite3_column_int(stmt, 3);
        if (sender_htlc_ids_out)
            sender_htlc_ids_out[count] = (uint64_t)sqlite3_column_int64(stmt, 4);
        count++;
    }

    sqlite3_finalize(stmt);
    return count;
}

/* --- Client invoices --- */

int persist_save_client_invoice(persist_t *p,
                                 const unsigned char *payment_hash32,
                                 const unsigned char *preimage32,
                                 uint64_t amount_msat) {
    if (!p || !p->db || !payment_hash32 || !preimage32) return 0;

    char hash_hex[65], preimage_hex[65];
    hex_encode(payment_hash32, 32, hash_hex);
    hex_encode(preimage32, 32, preimage_hex);

    const char *sql =
        "INSERT INTO client_invoices "
        "(payment_hash, preimage, amount_msat) VALUES (?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_text(stmt, 1, hash_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, preimage_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)amount_msat);

    int ok8 = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok8;
}

int persist_deactivate_client_invoice(persist_t *p,
                                       const unsigned char *payment_hash32) {
    if (!p || !p->db || !payment_hash32) return 0;

    char hash_hex[65];
    hex_encode(payment_hash32, 32, hash_hex);

    const char *sql =
        "UPDATE client_invoices SET active = 0 "
        "WHERE payment_hash = ? AND active = 1;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_text(stmt, 1, hash_hex, -1, SQLITE_TRANSIENT);

    int ok9 = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok9;
}

size_t persist_load_client_invoices(persist_t *p,
                                     unsigned char (*hashes_out)[32],
                                     unsigned char (*preimages_out)[32],
                                     uint64_t *amounts_out,
                                     size_t max_invoices) {
    if (!p || !p->db) return 0;

    const char *sql =
        "SELECT payment_hash, preimage, amount_msat "
        "FROM client_invoices WHERE active = 1 ORDER BY id;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_invoices) {
        const char *hash_hex = (const char *)sqlite3_column_text(stmt, 0);
        if (hashes_out && hash_hex)
            hex_decode(hash_hex, hashes_out[count], 32);
        const char *preimage_hex = (const char *)sqlite3_column_text(stmt, 1);
        if (preimages_out && preimage_hex)
            hex_decode(preimage_hex, preimages_out[count], 32);
        if (amounts_out)
            amounts_out[count] = (uint64_t)sqlite3_column_int64(stmt, 2);
        count++;
    }

    sqlite3_finalize(stmt);
    return count;
}

/* --- Channel basepoints --- */

int persist_save_basepoints(persist_t *p, uint32_t channel_id,
                             const channel_t *ch) {
    if (!p || !p->db || !ch) return 0;

    /* Encode 4 local secrets as hex */
    char pay_hex[65], delay_hex[65], revoc_hex[65], htlc_hex[65];
    hex_encode(ch->local_payment_basepoint_secret, 32, pay_hex);
    hex_encode(ch->local_delayed_payment_basepoint_secret, 32, delay_hex);
    hex_encode(ch->local_revocation_basepoint_secret, 32, revoc_hex);
    hex_encode(ch->local_htlc_basepoint_secret, 32, htlc_hex);

    /* Encode 4 remote pubkeys as compressed hex */
    unsigned char ser[33];
    size_t slen;
    char rpay_hex[67], rdelay_hex[67], rrevoc_hex[67], rhtlc_hex[67];

    slen = 33;
    if (!secp256k1_ec_pubkey_serialize(ch->ctx, ser, &slen,
            &ch->remote_payment_basepoint, SECP256K1_EC_COMPRESSED))
        return 0;
    hex_encode(ser, 33, rpay_hex);

    slen = 33;
    if (!secp256k1_ec_pubkey_serialize(ch->ctx, ser, &slen,
            &ch->remote_delayed_payment_basepoint, SECP256K1_EC_COMPRESSED))
        return 0;
    hex_encode(ser, 33, rdelay_hex);

    slen = 33;
    if (!secp256k1_ec_pubkey_serialize(ch->ctx, ser, &slen,
            &ch->remote_revocation_basepoint, SECP256K1_EC_COMPRESSED))
        return 0;
    hex_encode(ser, 33, rrevoc_hex);

    slen = 33;
    if (!secp256k1_ec_pubkey_serialize(ch->ctx, ser, &slen,
            &ch->remote_htlc_basepoint, SECP256K1_EC_COMPRESSED))
        return 0;
    hex_encode(ser, 33, rhtlc_hex);

    const char *sql =
        "INSERT OR REPLACE INTO channel_basepoints "
        "(channel_id, local_payment_secret, local_delayed_secret, "
        " local_revocation_secret, local_htlc_secret, "
        " remote_payment_bp, remote_delayed_bp, "
        " remote_revocation_bp, remote_htlc_bp) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);
    sqlite3_bind_text(stmt, 2, pay_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, delay_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, revoc_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, htlc_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, rpay_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, rdelay_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, rrevoc_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, rhtlc_hex, -1, SQLITE_TRANSIENT);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);

#if BASEPOINT_DIAG
    if (ok)
        fprintf(stderr, "DIAG basepoint: saved to DB channel_id=%u\n", channel_id);
#endif

    return ok;
}

int persist_load_basepoints(persist_t *p, uint32_t channel_id,
                             unsigned char local_secrets[4][32],
                             unsigned char remote_bps[4][33]) {
    if (!p || !p->db || !local_secrets || !remote_bps) return 0;

    const char *sql =
        "SELECT local_payment_secret, local_delayed_secret, "
        "local_revocation_secret, local_htlc_secret, "
        "remote_payment_bp, remote_delayed_bp, "
        "remote_revocation_bp, remote_htlc_bp "
        "FROM channel_basepoints WHERE channel_id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return 0;
    }

    /* Decode 4 local secrets */
    for (int i = 0; i < 4; i++) {
        const char *hex = (const char *)sqlite3_column_text(stmt, i);
        if (!hex || hex_decode(hex, local_secrets[i], 32) != 32) {
            sqlite3_finalize(stmt);
            return 0;
        }
    }

    /* Decode 4 remote pubkeys */
    for (int i = 0; i < 4; i++) {
        const char *hex = (const char *)sqlite3_column_text(stmt, 4 + i);
        if (!hex || hex_decode(hex, remote_bps[i], 33) != 33) {
            sqlite3_finalize(stmt);
            return 0;
        }
    }

    sqlite3_finalize(stmt);

#if BASEPOINT_DIAG
    fprintf(stderr, "DIAG basepoint: loaded from DB channel_id=%u\n", channel_id);
#endif

    return 1;
}

/* --- Watchtower hydration ---
   Build a channel_t from persisted rows that is sufficient for
   channel_build_penalty_tx() to sign a breach penalty.  Used by the
   standalone superscalar_watchtower binary, which runs in a separate
   process and does not share live channel_t memory with the LSP/client.

   Reads from: channels, channel_basepoints, revocation_secrets.
   The three per-channel fields that no table currently holds
   (to_self_delay, fee_rate_sat_per_kvb, use_revocation_leaf) are set
   to the codebase-wide defaults used by every existing test.  A proper
   schema migration for these fields is a separate follow-up and is not
   needed for v0.1.11 — current defaults match every factory created.

   Success leaves *out_ch owning three heap allocations
   (htlcs, local_pcs, received_revocations, received_revocation_valid);
   call channel_cleanup() to release them.  Failure leaves *out_ch unowned. */
int persist_load_channel_for_watchtower(persist_t *p, uint32_t channel_id,
                                         secp256k1_context *ctx,
                                         channel_t *out_ch) {
    if (!p || !p->db || !ctx || !out_ch) return 0;

    /* Per-channel balances + commitment number */
    uint64_t local_amt = 0, remote_amt = 0, cn = 0;
    if (!persist_load_channel_state(p, channel_id, &local_amt, &remote_amt, &cn))
        return 0;

    /* Local secrets + remote basepoints (all four categories) */
    unsigned char local_secrets[4][32];
    unsigned char remote_bps_ser[4][33];
    if (!persist_load_basepoints(p, channel_id, local_secrets, remote_bps_ser)) {
        memset(local_secrets, 0, sizeof(local_secrets));
        return 0;
    }

    /* Allocate the same dynamic arrays channel_init() sets up.  Doing this
       directly avoids reimplementing channel_init's full ceremony (funding
       keyagg, nonces, etc.) which is out of scope for penalty signing. */
    memset(out_ch, 0, sizeof(*out_ch));
    out_ch->ctx = ctx;

    out_ch->htlcs = calloc(DEFAULT_HTLCS_CAP, sizeof(htlc_t));
    out_ch->local_pcs = calloc(512, 32);
    out_ch->received_revocations = calloc(512, 32);
    out_ch->received_revocation_valid = calloc(512, 1);
    if (!out_ch->htlcs || !out_ch->local_pcs ||
        !out_ch->received_revocations || !out_ch->received_revocation_valid) {
        free(out_ch->htlcs);
        free(out_ch->local_pcs);
        free(out_ch->received_revocations);
        free(out_ch->received_revocation_valid);
        memset(out_ch, 0, sizeof(*out_ch));
        memset(local_secrets, 0, sizeof(local_secrets));
        return 0;
    }
    out_ch->htlcs_cap = DEFAULT_HTLCS_CAP;
    out_ch->local_pcs_cap = 512;
    out_ch->revocations_cap = 512;

    /* Install local basepoints (payment, delayed, revocation) + htlc.
       channel_set_local_basepoints derives the three pubkeys and zeroes
       on any failure. */
    if (!channel_set_local_basepoints(out_ch,
                                       local_secrets[0],
                                       local_secrets[1],
                                       local_secrets[2]) ||
        !channel_set_local_htlc_basepoint(out_ch, local_secrets[3])) {
        memset(local_secrets, 0, sizeof(local_secrets));
        free(out_ch->htlcs);
        free(out_ch->local_pcs);
        free(out_ch->received_revocations);
        free(out_ch->received_revocation_valid);
        memset(out_ch, 0, sizeof(*out_ch));
        return 0;
    }
    memset(local_secrets, 0, sizeof(local_secrets));

    /* Parse remote basepoint pubkeys from serialized form */
    secp256k1_pubkey remote_pay, remote_delay, remote_revoc, remote_htlc;
    if (!secp256k1_ec_pubkey_parse(ctx, &remote_pay, remote_bps_ser[0], 33) ||
        !secp256k1_ec_pubkey_parse(ctx, &remote_delay, remote_bps_ser[1], 33) ||
        !secp256k1_ec_pubkey_parse(ctx, &remote_revoc, remote_bps_ser[2], 33) ||
        !secp256k1_ec_pubkey_parse(ctx, &remote_htlc, remote_bps_ser[3], 33)) {
        free(out_ch->htlcs);
        free(out_ch->local_pcs);
        free(out_ch->received_revocations);
        free(out_ch->received_revocation_valid);
        memset(out_ch, 0, sizeof(*out_ch));
        return 0;
    }
    channel_set_remote_basepoints(out_ch, &remote_pay, &remote_delay,
                                   &remote_revoc);
    channel_set_remote_htlc_basepoint(out_ch, &remote_htlc);

    /* Received revocation secrets (for penalty signing on a breach) */
    size_t rev_count = 0;
    persist_load_revocations_flat(p, channel_id,
                                   out_ch->received_revocations,
                                   out_ch->received_revocation_valid,
                                   out_ch->revocations_cap, &rev_count);

    /* Balances + config from the channels table (schema v18+). */
    out_ch->local_amount = local_amt;
    out_ch->remote_amount = remote_amt;
    out_ch->commitment_number = cn;

    /* Load per-channel config (to_self_delay, fee_rate, use_revocation_leaf).
       Schema v18 added these columns; older DBs get the migration defaults. */
    {
        const char *cfg_sql =
            "SELECT to_self_delay, fee_rate_sat_per_kvb, use_revocation_leaf "
            "FROM channels WHERE id = ?;";
        sqlite3_stmt *cfg_stmt;
        if (sqlite3_prepare_v2(p->db, cfg_sql, -1, &cfg_stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int(cfg_stmt, 1, (int)channel_id);
            if (sqlite3_step(cfg_stmt) == SQLITE_ROW) {
                out_ch->to_self_delay = (uint32_t)sqlite3_column_int(cfg_stmt, 0);
                out_ch->fee_rate_sat_per_kvb = (uint64_t)sqlite3_column_int64(cfg_stmt, 1);
                out_ch->use_revocation_leaf = sqlite3_column_int(cfg_stmt, 2);
            } else {
                out_ch->to_self_delay = CHANNEL_DEFAULT_CSV_DELAY;
                out_ch->fee_rate_sat_per_kvb = 1000;
                out_ch->use_revocation_leaf = 0;
            }
            sqlite3_finalize(cfg_stmt);
        } else {
            out_ch->to_self_delay = CHANNEL_DEFAULT_CSV_DELAY;
            out_ch->fee_rate_sat_per_kvb = 1000;
            out_ch->use_revocation_leaf = 0;
        }
    }

    return 1;
}

/* --- ID counters --- */

int persist_save_counter(persist_t *p, const char *name, uint64_t value) {
    if (!p || !p->db || !name) return 0;

    const char *sql =
        "INSERT OR REPLACE INTO id_counters (name, value) VALUES (?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)value);

    int ok10 = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok10;
}

uint64_t persist_load_counter(persist_t *p, const char *name,
                               uint64_t default_val) {
    if (!p || !p->db || !name) return default_val;

    const char *sql =
        "SELECT value FROM id_counters WHERE name = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return default_val;

    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return default_val;
    }

    uint64_t val = (uint64_t)sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return val;
}

/* --- Watchtower anchor key persistence --- */

int persist_save_anchor_key(persist_t *p, const unsigned char *seckey32) {
    if (!p || !p->db || !seckey32) return 0;

    char key_hex[65];
    hex_encode(seckey32, 32, key_hex);

    const char *sql =
        "INSERT OR REPLACE INTO watchtower_keys (key_name, key_hex) "
        "VALUES ('anchor', ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_text(stmt, 1, key_hex, -1, SQLITE_TRANSIENT);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

int persist_load_anchor_key(persist_t *p, unsigned char *seckey32_out) {
    if (!p || !p->db || !seckey32_out) return 0;

    const char *sql =
        "SELECT key_hex FROM watchtower_keys WHERE key_name = 'anchor';";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return 0;
    }

    const char *hex = (const char *)sqlite3_column_text(stmt, 0);
    int ok = 0;
    if (hex && hex_decode(hex, seckey32_out, 32) == 32)
        ok = 1;

    sqlite3_finalize(stmt);
    return ok;
}

/* --- Watchtower pending entry persistence --- */

int persist_save_pending(persist_t *p, const char *txid,
                           uint32_t anchor_vout, uint64_t anchor_amount,
                           int cycles_in_mempool, int bump_count,
                           uint64_t penalty_value, uint32_t csv_delay,
                           uint32_t start_height) {
    if (!p || !p->db || !txid) return 0;

    const char *sql =
        "INSERT OR REPLACE INTO watchtower_pending "
        "(txid, anchor_vout, anchor_amount, cycles_in_mempool, bump_count, penalty_value, csv_delay, start_height) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_text(stmt, 1, txid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, (int)anchor_vout);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)anchor_amount);
    sqlite3_bind_int(stmt, 4, cycles_in_mempool);
    sqlite3_bind_int(stmt, 5, bump_count);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)penalty_value);
    sqlite3_bind_int(stmt, 7, (int)csv_delay);
    sqlite3_bind_int(stmt, 8, (int)start_height);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

size_t persist_load_pending(persist_t *p, char (*txids_out)[65],
                              uint32_t *vouts_out, uint64_t *amounts_out,
                              int *cycles_out, int *bumps_out,
                              uint64_t *penalty_values_out,
                              uint32_t *csv_delays_out,
                              uint32_t *start_heights_out,
                              size_t max_entries) {
    if (!p || !p->db) return 0;

    const char *sql =
        "SELECT txid, anchor_vout, anchor_amount, cycles_in_mempool, bump_count, penalty_value, csv_delay, start_height "
        "FROM watchtower_pending ORDER BY txid;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_entries) {
        const char *txid = (const char *)sqlite3_column_text(stmt, 0);
        if (txids_out && txid) {
            strncpy(txids_out[count], txid, 64);
            txids_out[count][64] = '\0';
        }
        if (vouts_out)
            vouts_out[count] = (uint32_t)sqlite3_column_int(stmt, 1);
        if (amounts_out)
            amounts_out[count] = (uint64_t)sqlite3_column_int64(stmt, 2);
        if (cycles_out)
            cycles_out[count] = sqlite3_column_int(stmt, 3);
        if (bumps_out)
            bumps_out[count] = sqlite3_column_int(stmt, 4);
        if (penalty_values_out)
            penalty_values_out[count] = (uint64_t)sqlite3_column_int64(stmt, 5);
        if (csv_delays_out)
            csv_delays_out[count] = (uint32_t)sqlite3_column_int(stmt, 6);
        if (start_heights_out)
            start_heights_out[count] = (uint32_t)sqlite3_column_int(stmt, 7);
        count++;
    }

    sqlite3_finalize(stmt);
    return count;
}

int persist_delete_pending(persist_t *p, const char *txid) {
    if (!p || !p->db || !txid) return 0;

    const char *sql = "DELETE FROM watchtower_pending WHERE txid = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_text(stmt, 1, txid, -1, SQLITE_TRANSIENT);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

/* --- JIT Channel persistence (Gap #2) --- */

#include "superscalar/jit_channel.h"

int persist_save_jit_channel(persist_t *p, const void *jit_ptr) {
    if (!p || !p->db || !jit_ptr) return 0;
    const jit_channel_t *jit = (const jit_channel_t *)jit_ptr;

    const char *sql =
        "INSERT OR REPLACE INTO jit_channels "
        "(jit_channel_id, client_idx, state, funding_txid, funding_vout, "
        "funding_amount, local_amount, remote_amount, commitment_number, "
        "created_at, created_block, target_factory_id, funding_tx_hex) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)jit->jit_channel_id);
    sqlite3_bind_int(stmt, 2, (int)jit->client_idx);
    sqlite3_bind_text(stmt, 3, jit_state_to_str(jit->state), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, jit->funding_txid_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, (int)jit->funding_vout);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)jit->funding_amount);
    sqlite3_bind_int64(stmt, 7, (sqlite3_int64)jit->channel.local_amount);
    sqlite3_bind_int64(stmt, 8, (sqlite3_int64)jit->channel.remote_amount);
    sqlite3_bind_int64(stmt, 9, (sqlite3_int64)jit->channel.commitment_number);
    sqlite3_bind_int64(stmt, 10, (sqlite3_int64)jit->created_at);
    sqlite3_bind_int(stmt, 11, (int)jit->created_block);
    sqlite3_bind_int(stmt, 12, (int)jit->target_factory_id);
    if (jit->funding_tx_hex[0])
        sqlite3_bind_text(stmt, 13, jit->funding_tx_hex, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(stmt, 13);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

size_t persist_load_jit_channels(persist_t *p, void *out_ptr, size_t max,
                                   size_t *count_out) {
    if (!p || !p->db || !out_ptr || !count_out) return 0;
    jit_channel_t *out = (jit_channel_t *)out_ptr;

    const char *sql =
        "SELECT jit_channel_id, client_idx, state, funding_txid, funding_vout, "
        "funding_amount, local_amount, remote_amount, commitment_number, "
        "created_at, created_block, target_factory_id, funding_tx_hex "
        "FROM jit_channels ORDER BY jit_channel_id;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        *count_out = 0;
        return 0;
    }

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max) {
        jit_channel_t *jit = &out[count];
        memset(jit, 0, sizeof(*jit));
        jit->jit_channel_id = (uint32_t)sqlite3_column_int(stmt, 0);
        jit->client_idx = (size_t)sqlite3_column_int(stmt, 1);
        const char *state_str = (const char *)sqlite3_column_text(stmt, 2);
        jit->state = jit_state_from_str(state_str);
        const char *txid = (const char *)sqlite3_column_text(stmt, 3);
        if (txid) {
            strncpy(jit->funding_txid_hex, txid, 64);
            jit->funding_txid_hex[64] = '\0';
        }
        jit->funding_vout = (uint32_t)sqlite3_column_int(stmt, 4);
        jit->funding_amount = (uint64_t)sqlite3_column_int64(stmt, 5);
        jit->channel.local_amount = (uint64_t)sqlite3_column_int64(stmt, 6);
        jit->channel.remote_amount = (uint64_t)sqlite3_column_int64(stmt, 7);
        jit->channel.commitment_number = (uint64_t)sqlite3_column_int64(stmt, 8);
        jit->created_at = (time_t)sqlite3_column_int64(stmt, 9);
        jit->created_block = (uint32_t)sqlite3_column_int(stmt, 10);
        jit->target_factory_id = (uint32_t)sqlite3_column_int(stmt, 11);
        const char *ftx_hex = (const char *)sqlite3_column_text(stmt, 12);
        if (ftx_hex) {
            strncpy(jit->funding_tx_hex, ftx_hex, sizeof(jit->funding_tx_hex) - 1);
            jit->funding_tx_hex[sizeof(jit->funding_tx_hex) - 1] = '\0';
        }
        count++;
    }

    sqlite3_finalize(stmt);
    *count_out = count;
    return count;
}

int persist_update_jit_state(persist_t *p, uint32_t jit_id, const char *state) {
    if (!p || !p->db || !state) return 0;

    const char *sql =
        "UPDATE jit_channels SET state = ? WHERE jit_channel_id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_text(stmt, 1, state, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, (int)jit_id);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

int persist_update_jit_balance(persist_t *p, uint32_t jit_id,
                                 uint64_t local, uint64_t remote, uint64_t cn) {
    if (!p || !p->db) return 0;

    const char *sql =
        "UPDATE jit_channels SET local_amount = ?, remote_amount = ?, "
        "commitment_number = ? WHERE jit_channel_id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)local);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)remote);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)cn);
    sqlite3_bind_int(stmt, 4, (int)jit_id);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

int persist_delete_jit_channel(persist_t *p, uint32_t jit_id) {
    if (!p || !p->db) return 0;

    const char *sql =
        "DELETE FROM jit_channels WHERE jit_channel_id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)jit_id);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

/* --- Flat revocation secrets (Phase 2: item 2.8) --- */

int persist_save_flat_secrets(persist_t *p, uint32_t factory_id,
                               const unsigned char secrets[][32],
                               size_t n_secrets) {
    if (!p || !p->db || !secrets || n_secrets == 0) return 0;

    const char *sql =
        "INSERT OR REPLACE INTO factory_revocation_secrets "
        "(factory_id, epoch, secret) VALUES (?, ?, ?);";

    int own_txn = !p->in_transaction;
    if (own_txn && !persist_begin(p)) return 0;

    for (size_t i = 0; i < n_secrets; i++) {
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            if (own_txn) persist_rollback(p);
            return 0;
        }

        char hex[65];
        hex_encode(secrets[i], 32, hex);

        sqlite3_bind_int(stmt, 1, (int)factory_id);
        sqlite3_bind_int(stmt, 2, (int)i);
        sqlite3_bind_text(stmt, 3, hex, -1, SQLITE_TRANSIENT);

        int ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        if (!ok) {
            if (own_txn) persist_rollback(p);
            return 0;
        }
    }

    if (own_txn) return persist_commit(p);
    return 1;
}

size_t persist_load_flat_secrets(persist_t *p, uint32_t factory_id,
                                  unsigned char secrets_out[][32],
                                  size_t max_secrets) {
    if (!p || !p->db || !secrets_out || max_secrets == 0) return 0;

    const char *sql =
        "SELECT epoch, secret FROM factory_revocation_secrets "
        "WHERE factory_id = ? ORDER BY epoch;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)factory_id);

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_secrets) {
        int epoch = sqlite3_column_int(stmt, 0);
        const char *hex = (const char *)sqlite3_column_text(stmt, 1);
        if (!hex || epoch < 0 || (size_t)epoch >= max_secrets) continue;
        if (hex_decode(hex, secrets_out[epoch], 32) != 32) continue;
        count++;
    }
    sqlite3_finalize(stmt);
    return count;
}

/* --- BIP 158 scan checkpoint (singleton) --- */

int persist_save_bip158_checkpoint(persist_t *p,
                                    int32_t tip_height,
                                    int32_t headers_synced,
                                    int32_t filter_headers_synced,
                                    const uint8_t *header_hashes,
                                    size_t header_hashes_len,
                                    const uint8_t *filter_headers,
                                    size_t filter_headers_len) {
    if (!p || !p->db) return 0;

    const char *sql =
        "INSERT OR REPLACE INTO bip158_checkpoints "
        "(id, tip_height, headers_synced, filter_headers_synced, "
        " header_hashes, filter_headers) "
        "VALUES (1, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)tip_height);
    sqlite3_bind_int(stmt, 2, (int)headers_synced);
    sqlite3_bind_int(stmt, 3, (int)filter_headers_synced);
    if (header_hashes && header_hashes_len > 0 &&
        header_hashes_len <= (size_t)INT_MAX)
        sqlite3_bind_blob(stmt, 4, header_hashes, (int)header_hashes_len,
                          SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(stmt, 4);
    if (filter_headers && filter_headers_len > 0 &&
        filter_headers_len <= (size_t)INT_MAX)
        sqlite3_bind_blob(stmt, 5, filter_headers, (int)filter_headers_len,
                          SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(stmt, 5);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

int persist_load_bip158_checkpoint(persist_t *p,
                                    int32_t *tip_height_out,
                                    int32_t *headers_synced_out,
                                    int32_t *filter_headers_synced_out,
                                    uint8_t *header_hashes_out,
                                    size_t header_hashes_cap,
                                    uint8_t *filter_headers_out,
                                    size_t filter_headers_cap) {
    if (!p || !p->db) return 0;

    const char *sql =
        "SELECT tip_height, headers_synced, filter_headers_synced, "
        "       header_hashes, filter_headers "
        "FROM bip158_checkpoints WHERE id = 1;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        found = 1;
        if (tip_height_out)
            *tip_height_out = (int32_t)sqlite3_column_int(stmt, 0);
        if (headers_synced_out)
            *headers_synced_out = (int32_t)sqlite3_column_int(stmt, 1);
        if (filter_headers_synced_out)
            *filter_headers_synced_out = (int32_t)sqlite3_column_int(stmt, 2);

        if (header_hashes_out && header_hashes_cap > 0) {
            const void *blob = sqlite3_column_blob(stmt, 3);
            int blen = sqlite3_column_bytes(stmt, 3);
            if (blob && blen > 0 && (size_t)blen <= header_hashes_cap)
                memcpy(header_hashes_out, blob, (size_t)blen);
        }
        if (filter_headers_out && filter_headers_cap > 0) {
            const void *blob = sqlite3_column_blob(stmt, 4);
            int blen = sqlite3_column_bytes(stmt, 4);
            if (blob && blen > 0 && (size_t)blen <= filter_headers_cap)
                memcpy(filter_headers_out, blob, (size_t)blen);
        }
    }
    sqlite3_finalize(stmt);
    return found;
}

/* --- HD wallet UTXO persistence --- */

int persist_save_hd_utxo(persist_t *p,
                           const char *txid,
                           uint32_t vout,
                           uint64_t amount_sats,
                           uint32_t key_index)
{
    if (!p || !p->db || !txid) return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "INSERT OR IGNORE INTO hd_utxos "
            "(txid, vout, amount_sats, key_index, spent) VALUES (?,?,?,?,0);",
            -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text (stmt, 1, txid, -1, SQLITE_STATIC);
    sqlite3_bind_int  (stmt, 2, (int)vout);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)amount_sats);
    sqlite3_bind_int  (stmt, 4, (int)key_index);
    int ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

int persist_mark_hd_utxo_spent(persist_t *p, const char *txid, uint32_t vout)
{
    if (!p || !p->db || !txid) return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "UPDATE hd_utxos SET spent=1 WHERE txid=? AND vout=?;",
            -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(stmt, 1, txid, -1, SQLITE_STATIC);
    sqlite3_bind_int (stmt, 2, (int)vout);
    int ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

uint64_t persist_sum_hd_utxos(persist_t *p)
{
    if (!p || !p->db) return 0;
    sqlite3_stmt *stmt;
    const char *sql = "SELECT COALESCE(SUM(amount_sats), 0) FROM hd_utxos "
                      "WHERE spent = 0 AND reserved = 0";
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;
    uint64_t total = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        total = (uint64_t)sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return total;
}

int persist_get_hd_utxo(persist_t *p,
                          uint64_t min_sats,
                          char txid_out[65],
                          uint32_t *vout_out,
                          uint64_t *amount_out,
                          uint32_t *key_index_out)
{
    if (!p || !p->db) return 0;

    /* BEGIN IMMEDIATE acquires a write lock so the SELECT + UPDATE
     * that follows is atomic — no concurrent caller can pick the same coin. */
    if (sqlite3_exec(p->db, "BEGIN IMMEDIATE;", NULL, NULL, NULL) != SQLITE_OK)
        return 0;

    char txid_buf[65] = {0};
    uint32_t vout_val = 0;
    uint64_t amount_val = 0;
    uint32_t key_val = 0;
    int found = 0;

    sqlite3_stmt *sel;
    if (sqlite3_prepare_v2(p->db,
            "SELECT txid, vout, amount_sats, key_index FROM hd_utxos "
            "WHERE spent=0 AND reserved=0 AND amount_sats>=? "
            "ORDER BY amount_sats ASC LIMIT 1;",
            -1, &sel, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(sel, 1, (sqlite3_int64)min_sats);
        if (sqlite3_step(sel) == SQLITE_ROW) {
            const char *txid = (const char *)sqlite3_column_text(sel, 0);
            if (txid) { strncpy(txid_buf, txid, 64); txid_buf[64] = '\0'; }
            vout_val   = (uint32_t)sqlite3_column_int(sel, 1);
            amount_val = (uint64_t)sqlite3_column_int64(sel, 2);
            key_val    = (uint32_t)sqlite3_column_int(sel, 3);
            found = 1;
        }
        sqlite3_finalize(sel);
    }

    if (found) {
        /* Mark reserved so concurrent callers skip this coin */
        sqlite3_stmt *upd;
        if (sqlite3_prepare_v2(p->db,
                "UPDATE hd_utxos SET reserved=1 WHERE txid=? AND vout=?;",
                -1, &upd, NULL) == SQLITE_OK) {
            sqlite3_bind_text(upd, 1, txid_buf, -1, SQLITE_STATIC);
            sqlite3_bind_int (upd, 2, (int)vout_val);
            sqlite3_step(upd);
            sqlite3_finalize(upd);
        }
        if (txid_out)      { strncpy(txid_out, txid_buf, 64); txid_out[64] = '\0'; }
        if (vout_out)      *vout_out      = vout_val;
        if (amount_out)    *amount_out    = amount_val;
        if (key_index_out) *key_index_out = key_val;
    }

    sqlite3_exec(p->db, "COMMIT;", NULL, NULL, NULL);
    return found;
}

int persist_unreserve_hd_utxo(persist_t *p, const char *txid, uint32_t vout)
{
    if (!p || !p->db || !txid) return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "UPDATE hd_utxos SET reserved=0 WHERE txid=? AND vout=? AND spent=0;",
            -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(stmt, 1, txid, -1, SQLITE_STATIC);
    sqlite3_bind_int (stmt, 2, (int)vout);
    int ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

void persist_clear_hd_reserved(persist_t *p)
{
    if (!p || !p->db) return;
    /* On startup, release any reservations left by a prior run that crashed
     * before broadcast — those coins are still spendable on-chain. */
    sqlite3_exec(p->db,
        "UPDATE hd_utxos SET reserved=0 WHERE spent=0;",
        NULL, NULL, NULL);
}

int persist_save_hd_next_index(persist_t *p, uint32_t next_index)
{
    if (!p || !p->db) return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "INSERT INTO hd_wallet_state (id, next_index) VALUES (1, ?) "
            "ON CONFLICT(id) DO UPDATE SET next_index=excluded.next_index;",
            -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(stmt, 1, (int)next_index);
    int ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

uint32_t persist_load_hd_next_index(persist_t *p)
{
    if (!p || !p->db) return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "SELECT next_index FROM hd_wallet_state WHERE id=1;",
            -1, &stmt, NULL) != SQLITE_OK) return 0;
    uint32_t val = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        val = (uint32_t)sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return val;
}

int persist_save_hd_seed(persist_t *p,
                           const unsigned char *seed, size_t seed_len)
{
    if (!p || !p->db || !seed || seed_len == 0 || seed_len > 64) return 0;
    /* Hex-encode the seed */
    char hex[129];
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < seed_len; i++) {
        hex[i * 2]     = hx[(seed[i] >> 4) & 0xf];
        hex[i * 2 + 1] = hx[ seed[i]       & 0xf];
    }
    hex[seed_len * 2] = '\0';

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "INSERT INTO hd_wallet_state (id, next_index, seed_hex) VALUES (1, 0, ?) "
            "ON CONFLICT(id) DO UPDATE SET seed_hex=excluded.seed_hex;",
            -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(stmt, 1, hex, -1, SQLITE_STATIC);
    int ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

int persist_load_hd_seed(persist_t *p,
                           unsigned char *seed_out, size_t *seed_len_out,
                           size_t seed_cap)
{
    if (!p || !p->db || !seed_out || !seed_len_out) return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "SELECT seed_hex FROM hd_wallet_state WHERE id=1;",
            -1, &stmt, NULL) != SQLITE_OK) return 0;
    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *hex = (const char *)sqlite3_column_text(stmt, 0);
        if (hex) {
            size_t hex_len = strlen(hex);
            size_t byte_len = hex_len / 2;
            if (byte_len > 0 && byte_len <= seed_cap) {
                /* Inline hex decode */
                for (size_t i = 0; i < byte_len; i++) {
                    unsigned char hi = hex[i*2];
                    unsigned char lo = hex[i*2+1];
                    hi = (hi >= '0' && hi <= '9') ? hi - '0' :
                         (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 :
                         (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : 0;
                    lo = (lo >= '0' && lo <= '9') ? lo - '0' :
                         (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 :
                         (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : 0;
                    seed_out[i] = (hi << 4) | lo;
                }
                *seed_len_out = byte_len;
                found = 1;
            }
        }
    }
    sqlite3_finalize(stmt);
    return found;
}

int persist_save_hd_lookahead(persist_t *p, uint32_t lookahead)
{
    if (!p || !p->db) return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "INSERT INTO hd_wallet_state (id, next_index, lookahead) VALUES (1, 0, ?) "
            "ON CONFLICT(id) DO UPDATE SET lookahead=excluded.lookahead;",
            -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(stmt, 1, (int)lookahead);
    int ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

uint32_t persist_load_hd_lookahead(persist_t *p)
{
    if (!p || !p->db) return 100; /* default: HD_WALLET_LOOKAHEAD */
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "SELECT lookahead FROM hd_wallet_state WHERE id=1;",
            -1, &stmt, NULL) != SQLITE_OK) return 100;
    uint32_t val = 100; /* default: HD_WALLET_LOOKAHEAD */
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int col = sqlite3_column_int(stmt, 0);
        if (col > 0) val = (uint32_t)col;
    }
    sqlite3_finalize(stmt);
    return val;
}

/* --- BOLT 12 Offers (schema v3) --- */

int persist_save_offer(persist_t *p,
                        const unsigned char *offer_id32,
                        const char *encoded) {
    if (!p || !p->db || !offer_id32 || !encoded) return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "INSERT OR REPLACE INTO offers (offer_id, encoded) VALUES (?, ?);",
            -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_blob(stmt, 1, offer_id32, 32, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, encoded, -1, SQLITE_STATIC);
    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

size_t persist_list_offers(persist_t *p,
                            unsigned char (*ids_out)[32],
                            char (*encoded_out)[PERSIST_OFFER_ENC_MAX],
                            size_t max_offers) {
    if (!p || !p->db || !ids_out || !encoded_out || max_offers == 0) return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "SELECT offer_id, encoded FROM offers ORDER BY created_at;",
            -1, &stmt, NULL) != SQLITE_OK) return 0;
    size_t count = 0;
    while (count < max_offers && sqlite3_step(stmt) == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(stmt, 0);
        int blen = sqlite3_column_bytes(stmt, 0);
        if (blob && blen == 32) memcpy(ids_out[count], blob, 32);
        const char *enc = (const char *)sqlite3_column_text(stmt, 1);
        if (enc) {
            strncpy(encoded_out[count], enc, PERSIST_OFFER_ENC_MAX - 1);
            encoded_out[count][PERSIST_OFFER_ENC_MAX - 1] = '\0';
        }
        count++;
    }
    sqlite3_finalize(stmt);
    return count;
}

int persist_delete_offer(persist_t *p, const unsigned char *offer_id32) {
    if (!p || !p->db || !offer_id32) return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "DELETE FROM offers WHERE offer_id = ?;",
            -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_blob(stmt, 1, offer_id32, 32, SQLITE_STATIC);
    sqlite3_step(stmt);
    int changes = sqlite3_changes(p->db);
    sqlite3_finalize(stmt);
    return changes > 0;
}

/* Fix 5: pending CS tracking for reconnect retransmit. */
int persist_save_pending_cs(persist_t *p, uint32_t channel_id,
                             uint64_t commitment_number)
{
    if (!p || !p->db) return 0;
    if (commitment_number == 0) {
        /* Clear: delete the entry for this channel */
        const char *sql = "DELETE FROM pending_cs WHERE channel_id = ?;";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
            return 0;
        sqlite3_bind_int64(stmt, 1, (sqlite3_int64)channel_id);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return 1;
    }
    /* Upsert: save or overwrite the pending CS cn for this channel */
    const char *sql =
        "INSERT OR REPLACE INTO pending_cs (channel_id, commitment_number)"
        " VALUES (?, ?);";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)channel_id);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)commitment_number);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return 1;
}

int persist_load_pending_cs(persist_t *p, uint32_t channel_id,
                             uint64_t *cn_out)
{
    if (!p || !p->db || !cn_out) return 0;
    const char *sql =
        "SELECT commitment_number FROM pending_cs WHERE channel_id = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)channel_id);
    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *cn_out = (uint64_t)sqlite3_column_int64(stmt, 0);
        found = 1;
    }
    sqlite3_finalize(stmt);
    return found;
}

/* --- LSP endpoint cache (schema v4) --- */

int persist_save_lsp_endpoint(persist_t *p,
                               const char *domain,
                               const char *host,
                               uint16_t    port,
                               const char *pubkey_hex) {
    if (!p || !p->db || !domain || !host || !pubkey_hex) return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "INSERT OR REPLACE INTO lsp_endpoints"
            "  (domain, host, port, pubkey_hex, updated_at)"
            "  VALUES (?, ?, ?, ?, strftime('%s','now'));",
            -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(stmt, 1, domain, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, host,   -1, SQLITE_STATIC);
    sqlite3_bind_int (stmt, 3, (int)port);
    sqlite3_bind_text(stmt, 4, pubkey_hex, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE);
}

int persist_load_lsp_endpoint(persist_t *p,
                               const char *domain,
                               char *host_out,       size_t host_cap,
                               uint16_t   *port_out,
                               char *pubkey_hex_out, size_t pubkey_cap) {
    if (!p || !p->db || !domain || !host_out || !port_out || !pubkey_hex_out)
        return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "SELECT host, port, pubkey_hex FROM lsp_endpoints"
            "  WHERE domain = ? LIMIT 1;",
            -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(stmt, 1, domain, -1, SQLITE_STATIC);
    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *h = (const char *)sqlite3_column_text(stmt, 0);
        int          pt = sqlite3_column_int (stmt, 1);
        const char *pk = (const char *)sqlite3_column_text(stmt, 2);
        if (h && pk && pt > 0 && pt <= 65535) {
            strncpy(host_out, h, host_cap - 1);
            host_out[host_cap - 1] = '\0';
            *port_out = (uint16_t)pt;
            strncpy(pubkey_hex_out, pk, pubkey_cap - 1);
            pubkey_hex_out[pubkey_cap - 1] = '\0';
            found = 1;
        }
    }
    sqlite3_finalize(stmt);
    return found;
}

/* --- Schema v5: SCID registry --- */

int persist_save_scid_entry(persist_t *p,
                             uint32_t factory_id,
                             uint32_t leaf_idx,
                             uint64_t scid) {
    if (!p || !p->db) return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "INSERT OR REPLACE INTO scid_registry"
            "  (scid, factory_id, leaf_idx)"
            "  VALUES (?, ?, ?);",
            -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)scid);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)factory_id);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)leaf_idx);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 1 : 0;
}

int persist_load_scid_entry(persist_t *p,
                             uint64_t scid,
                             uint32_t *factory_id_out,
                             uint32_t *leaf_idx_out) {
    if (!p || !p->db) return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "SELECT factory_id, leaf_idx FROM scid_registry"
            "  WHERE scid = ? LIMIT 1;",
            -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)scid);
    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        if (factory_id_out) *factory_id_out = (uint32_t)sqlite3_column_int64(stmt, 0);
        if (leaf_idx_out)   *leaf_idx_out   = (uint32_t)sqlite3_column_int64(stmt, 1);
        found = 1;
    }
    sqlite3_finalize(stmt);
    return found;
}

/* --- Schema v6: inbound HTLC persistence --- */

int persist_save_htlc_inbound(persist_t *p, const htlc_inbound_t *h) {
    if (!p || !p->db || !h) return 0;

    char ph_hex[65], ps_hex[65];
    hex_encode(h->payment_hash,   32, ph_hex);
    hex_encode(h->payment_secret, 32, ps_hex);

    char pre_hex[65] = "";
    if (h->state == HTLC_INBOUND_FULFILLED)
        hex_encode(h->preimage, 32, pre_hex);

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "INSERT OR REPLACE INTO htlc_inbound"
            "  (htlc_id, amount_msat, payment_hash, payment_secret,"
            "   cltv_expiry, scid, state, preimage)"
            "  VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
            -1, &stmt, NULL) != SQLITE_OK) return 0;

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)h->htlc_id);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)h->amount_msat);
    sqlite3_bind_text (stmt, 3, ph_hex, -1, SQLITE_STATIC);
    sqlite3_bind_text (stmt, 4, ps_hex, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)h->cltv_expiry);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)h->scid);
    sqlite3_bind_int  (stmt, 7, (int)h->state);
    if (pre_hex[0])
        sqlite3_bind_text(stmt, 8, pre_hex, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 8);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 1 : 0;
}

int persist_load_htlc_inbound_pending(persist_t *p, htlc_inbound_table_t *tbl) {
    if (!p || !p->db || !tbl) return -1;

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "SELECT htlc_id, amount_msat, payment_hash, payment_secret,"
            "       cltv_expiry, scid"
            "  FROM htlc_inbound WHERE state = 0;",
            -1, &stmt, NULL) != SQLITE_OK) return -1;

    int n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && tbl->count < HTLC_INBOUND_MAX) {
        htlc_inbound_t *e = &tbl->entries[tbl->count];
        e->htlc_id    = (uint64_t)sqlite3_column_int64(stmt, 0);
        e->amount_msat = (uint64_t)sqlite3_column_int64(stmt, 1);

        const char *ph = (const char *)sqlite3_column_text(stmt, 2);
        const char *ps = (const char *)sqlite3_column_text(stmt, 3);
        if (ph) hex_decode(ph, e->payment_hash,   32);
        if (ps) hex_decode(ps, e->payment_secret, 32);

        e->cltv_expiry = (uint32_t)sqlite3_column_int64(stmt, 4);
        e->scid        = (uint64_t)sqlite3_column_int64(stmt, 5);
        e->state       = HTLC_INBOUND_PENDING;
        memset(e->preimage, 0, 32);
        tbl->count++;
        n++;
    }
    sqlite3_finalize(stmt);
    return n;
}

int persist_update_htlc_inbound(persist_t *p, uint64_t htlc_id,
                                 htlc_inbound_state_t state,
                                 const unsigned char preimage[32]) {
    if (!p || !p->db) return 0;

    char pre_hex[65] = "";
    if (state == HTLC_INBOUND_FULFILLED && preimage)
        hex_encode(preimage, 32, pre_hex);

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "UPDATE htlc_inbound SET state = ?, preimage = ?"
            "  WHERE htlc_id = ?;",
            -1, &stmt, NULL) != SQLITE_OK) return 0;

    sqlite3_bind_int  (stmt, 1, (int)state);
    if (pre_hex[0])
        sqlite3_bind_text(stmt, 2, pre_hex, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 2);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)htlc_id);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 1 : 0;
}

/* === Schema v9: LN node persistent invoice + peer channel tables === */

int persist_save_ln_invoice(persist_t *p, const bolt11_invoice_entry_t *e) {
    if (!p || !p->db || !e) return 0;

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "INSERT OR REPLACE INTO ln_invoices "
            "(payment_hash, preimage, payment_secret, amount_msat, "
            " description, expiry, created_at, settled, active, "
            " has_stateless_secret, has_stateless_preimage, stateless_nonce) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_blob (stmt,  1, e->payment_hash,   32, SQLITE_STATIC);
    sqlite3_bind_blob (stmt,  2, e->preimage,        32, SQLITE_STATIC);
    sqlite3_bind_blob (stmt,  3, e->payment_secret,  32, SQLITE_STATIC);
    sqlite3_bind_int64(stmt,  4, (sqlite3_int64)e->amount_msat);
    sqlite3_bind_text (stmt,  5, e->description,    -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt,  6, (sqlite3_int64)e->expiry);
    sqlite3_bind_int64(stmt,  7, (sqlite3_int64)e->created_at);
    sqlite3_bind_int  (stmt,  8, e->settled);
    sqlite3_bind_int  (stmt,  9, e->active);
    sqlite3_bind_int  (stmt, 10, e->has_stateless_secret);
    sqlite3_bind_int  (stmt, 11, e->has_stateless_preimage);
    if (e->has_stateless_preimage)
        sqlite3_bind_blob(stmt, 12, e->stateless_nonce, 32, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 12);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 1 : 0;
}

int persist_load_ln_invoices(persist_t *p, bolt11_invoice_table_t *tbl) {
    if (!p || !p->db || !tbl) return -1;

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "SELECT payment_hash, preimage, payment_secret, amount_msat, "
            "       description, expiry, created_at, settled, active, "
            "       has_stateless_secret, has_stateless_preimage, stateless_nonce "
            "  FROM ln_invoices;",
            -1, &stmt, NULL) != SQLITE_OK)
        return -1;

    int n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW &&
           tbl->count < INVOICE_TABLE_MAX) {
        bolt11_invoice_entry_t *e = &tbl->entries[tbl->count];
        memset(e, 0, sizeof(*e));

        const void *ph = sqlite3_column_blob(stmt, 0);
        if (ph) memcpy(e->payment_hash, ph, 32);

        const void *pre = sqlite3_column_blob(stmt, 1);
        if (pre) memcpy(e->preimage, pre, 32);

        const void *ps = sqlite3_column_blob(stmt, 2);
        if (ps) memcpy(e->payment_secret, ps, 32);

        e->amount_msat  = (uint64_t)sqlite3_column_int64(stmt, 3);

        const unsigned char *desc = sqlite3_column_text(stmt, 4);
        if (desc)
            strncpy(e->description, (const char *)desc,
                    sizeof(e->description) - 1);

        e->expiry      = (uint32_t)sqlite3_column_int64(stmt, 5);
        e->created_at  = (uint32_t)sqlite3_column_int64(stmt, 6);
        e->settled     = sqlite3_column_int(stmt, 7);
        e->active      = sqlite3_column_int(stmt, 8);
        e->has_stateless_secret   = sqlite3_column_int(stmt, 9);
        e->has_stateless_preimage = sqlite3_column_int(stmt, 10);

        const void *nonce = sqlite3_column_blob(stmt, 11);
        if (nonce && e->has_stateless_preimage)
            memcpy(e->stateless_nonce, nonce, 32);

        tbl->count++;
        n++;
    }
    sqlite3_finalize(stmt);
    return n;
}

int persist_delete_ln_invoice(persist_t *p, const unsigned char payment_hash[32]) {
    if (!p || !p->db || !payment_hash) return 0;

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "DELETE FROM ln_invoices WHERE payment_hash = ?;",
            -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_blob(stmt, 1, payment_hash, 32, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 1 : 0;
}

int persist_save_ln_peer_channel(persist_t *p,
                                  const unsigned char channel_id[32],
                                  const unsigned char peer_pubkey[33],
                                  uint64_t capacity_sat,
                                  uint64_t local_balance_msat,
                                  uint64_t remote_balance_msat,
                                  int state,
                                  const char *peer_host,
                                  uint16_t peer_port) {
    if (!p || !p->db || !channel_id || !peer_pubkey) return 0;

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "INSERT OR REPLACE INTO ln_peer_channels "
            "(channel_id, peer_pubkey, capacity_sat, "
            " local_balance_msat, remote_balance_msat, "
            " our_funding_pubkey, their_funding_pubkey, "
            " state, updated_at, peer_host, peer_port) "
            "VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?);",
            -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_blob (stmt, 1, channel_id,         32, SQLITE_STATIC);
    sqlite3_bind_blob (stmt, 2, peer_pubkey,         33, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)capacity_sat);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)local_balance_msat);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)remote_balance_msat);
    sqlite3_bind_int  (stmt, 6, state);
    sqlite3_bind_int64(stmt, 7, (sqlite3_int64)time(NULL));
    sqlite3_bind_text (stmt, 8, peer_host ? peer_host : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int  (stmt, 9, (int)peer_port);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 1 : 0;
}

int persist_load_ln_peer_channels(persist_t *p,
                                   void (*cb)(const unsigned char channel_id[32],
                                              const unsigned char peer_pubkey[33],
                                              uint64_t capacity_sat,
                                              uint64_t local_balance_msat,
                                              uint64_t remote_balance_msat,
                                              int state,
                                              const char *peer_host,
                                              uint16_t peer_port,
                                              void *ctx),
                                   void *ctx) {
    if (!p || !p->db || !cb) return 0;

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "SELECT channel_id, peer_pubkey, capacity_sat, "
            "       local_balance_msat, remote_balance_msat, state, "
            "       COALESCE(peer_host, ''), COALESCE(peer_port, 0) "
            "  FROM ln_peer_channels;",
            -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        unsigned char cid[32] = {0};
        unsigned char ppk[33] = {0};

        const void *cid_blob = sqlite3_column_blob(stmt, 0);
        if (cid_blob) memcpy(cid, cid_blob, 32);

        const void *ppk_blob = sqlite3_column_blob(stmt, 1);
        if (ppk_blob) memcpy(ppk, ppk_blob, 33);

        uint64_t cap    = (uint64_t)sqlite3_column_int64(stmt, 2);
        uint64_t local  = (uint64_t)sqlite3_column_int64(stmt, 3);
        uint64_t remote = (uint64_t)sqlite3_column_int64(stmt, 4);
        int      st     = sqlite3_column_int(stmt, 5);
        const char *host = (const char *)sqlite3_column_text(stmt, 6);
        uint16_t port   = (uint16_t)sqlite3_column_int(stmt, 7);

        cb(cid, ppk, cap, local, remote, st, host ? host : "", port, ctx);
    }
    sqlite3_finalize(stmt);
    return 1;
}

/* === Circuit breaker persistence (schema v10) === */

#include "superscalar/circuit_breaker.h"

int persist_save_circuit_breaker_peer(persist_t *p,
                                       const unsigned char peer_pubkey[33],
                                       uint16_t max_pending_htlcs,
                                       uint64_t max_pending_msat,
                                       uint32_t max_htlcs_per_hour) {
    if (!p || !p->db || !peer_pubkey) return -1;

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "INSERT OR REPLACE INTO circuit_breaker_peers "
            "(peer_pubkey, max_pending_htlcs, max_pending_msat, max_htlcs_per_hour) "
            "VALUES (?, ?, ?, ?);",
            -1, &stmt, NULL) != SQLITE_OK)
        return -1;

    sqlite3_bind_blob (stmt, 1, peer_pubkey, 33, SQLITE_STATIC);
    sqlite3_bind_int  (stmt, 2, (int)max_pending_htlcs);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)max_pending_msat);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)max_htlcs_per_hour);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 1 : 0;
}

int persist_load_circuit_breaker_peers(persist_t *p, circuit_breaker_t *cb) {
    if (!p || !p->db || !cb) return -1;

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "SELECT peer_pubkey, max_pending_htlcs, max_pending_msat, max_htlcs_per_hour "
            "  FROM circuit_breaker_peers;",
            -1, &stmt, NULL) != SQLITE_OK)
        return -1;

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        unsigned char pk[33] = {0};
        const void *pk_blob = sqlite3_column_blob(stmt, 0);
        if (pk_blob) memcpy(pk, pk_blob, 33);

        uint16_t max_htlcs = (uint16_t)sqlite3_column_int(stmt, 1);
        uint64_t max_msat  = (uint64_t)sqlite3_column_int64(stmt, 2);
        uint32_t max_hour  = (uint32_t)sqlite3_column_int64(stmt, 3);

        circuit_breaker_set_peer_limits(cb, pk, max_htlcs, max_msat, max_hour);
        count++;
    }
    sqlite3_finalize(stmt);
    return count;
}

/* === PTLC persistence (schema v10) === */

int persist_save_ptlc(persist_t *p, uint32_t channel_id, const ptlc_t *ptlc) {
    if (!p || !p->db || !ptlc) return 0;
    const char *dir = (ptlc->direction == PTLC_OFFERED) ? "offered" : "received";
    const char *state;
    switch (ptlc->state) {
        case PTLC_STATE_ACTIVE:  state = "active"; break;
        case PTLC_STATE_SETTLED: state = "settled"; break;
        case PTLC_STATE_FAILED:  state = "failed"; break;
        default:                 state = "unknown"; break;
    }
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "INSERT OR REPLACE INTO ptlcs "
            "(channel_id, ptlc_id, direction, amount, payment_point, cltv_expiry, state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?);",
            -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    /* Serialize payment_point as 64-byte raw pubkey data */
    sqlite3_bind_int   (stmt, 1, (int)channel_id);
    sqlite3_bind_int64 (stmt, 2, (sqlite3_int64)ptlc->id);
    sqlite3_bind_text  (stmt, 3, dir, -1, SQLITE_STATIC);
    sqlite3_bind_int64 (stmt, 4, (sqlite3_int64)ptlc->amount_sats);
    sqlite3_bind_blob  (stmt, 5, &ptlc->payment_point, sizeof(secp256k1_pubkey), SQLITE_STATIC);
    sqlite3_bind_int   (stmt, 6, (int)ptlc->cltv_expiry);
    sqlite3_bind_text  (stmt, 7, state, -1, SQLITE_STATIC);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

size_t persist_load_ptlcs(persist_t *p, uint32_t channel_id,
                            ptlc_t *ptlcs_out, size_t max_ptlcs) {
    if (!p || !p->db || !ptlcs_out) return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "SELECT ptlc_id, direction, amount, payment_point, cltv_expiry, state "
            "FROM ptlcs WHERE channel_id = ? ORDER BY ptlc_id;",
            -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);
    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_ptlcs) {
        ptlc_t *pt = &ptlcs_out[count];
        memset(pt, 0, sizeof(*pt));
        pt->id = (uint64_t)sqlite3_column_int64(stmt, 0);
        const char *dir = (const char *)sqlite3_column_text(stmt, 1);
        pt->direction = (dir && strcmp(dir, "offered") == 0) ? PTLC_OFFERED : PTLC_RECEIVED;
        pt->amount_sats = (uint64_t)sqlite3_column_int64(stmt, 2);
        const void *pp = sqlite3_column_blob(stmt, 3);
        if (pp && sqlite3_column_bytes(stmt, 3) == (int)sizeof(secp256k1_pubkey))
            memcpy(&pt->payment_point, pp, sizeof(secp256k1_pubkey));
        pt->cltv_expiry = (uint32_t)sqlite3_column_int(stmt, 4);
        const char *st = (const char *)sqlite3_column_text(stmt, 5);
        if (st && strcmp(st, "settled") == 0) pt->state = PTLC_STATE_SETTLED;
        else if (st && strcmp(st, "failed") == 0) pt->state = PTLC_STATE_FAILED;
        else pt->state = PTLC_STATE_ACTIVE;
        count++;
    }
    sqlite3_finalize(stmt);
    return count;
}

int persist_delete_ptlc(persist_t *p, uint32_t channel_id, uint64_t ptlc_id) {
    if (!p || !p->db) return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "DELETE FROM ptlcs WHERE channel_id = ? AND ptlc_id = ?;",
            -1, &stmt, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int   (stmt, 1, (int)channel_id);
    sqlite3_bind_int64 (stmt, 2, (sqlite3_int64)ptlc_id);
    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

/* === Peer storage persistence (schema v10) === */

int persist_save_peer_storage(persist_t *p, const unsigned char peer_pubkey[33],
                                const unsigned char *blob, uint16_t blob_len) {
    if (!p || !p->db || !peer_pubkey || !blob) return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "INSERT OR REPLACE INTO peer_storage_blobs "
            "(peer_pubkey, blob, received_at) VALUES (?, ?, ?);",
            -1, &stmt, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_blob (stmt, 1, peer_pubkey, 33, SQLITE_STATIC);
    sqlite3_bind_blob (stmt, 2, blob, (int)blob_len, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)time(NULL));
    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

int persist_load_peer_storage(persist_t *p, const unsigned char peer_pubkey[33],
                                unsigned char *blob_out, uint16_t *blob_len_out,
                                size_t blob_cap) {
    if (!p || !p->db || !peer_pubkey || !blob_out) return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db,
            "SELECT blob FROM peer_storage_blobs WHERE peer_pubkey = ?;",
            -1, &stmt, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_blob(stmt, 1, peer_pubkey, 33, SQLITE_STATIC);
    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int blen = sqlite3_column_bytes(stmt, 0);
        if ((size_t)blen <= blob_cap) {
            memcpy(blob_out, sqlite3_column_blob(stmt, 0), (size_t)blen);
            if (blob_len_out) *blob_len_out = (uint16_t)blen;
            found = 1;
        }
    }
    sqlite3_finalize(stmt);
    return found;
}

/* --- Signed commitment TX (schema v13) --- */

int persist_save_commitment_sig(persist_t *p, uint32_t channel_id,
                                 uint64_t commitment_number,
                                 const unsigned char *sig64,
                                 const unsigned char *signed_tx,
                                 size_t signed_tx_len)
{
    if (!p || !p->db || !sig64 || !signed_tx) return 0;

    const char *sql =
        "INSERT OR REPLACE INTO signed_commitments "
        "(channel_id, commitment_number, sig64_hex, signed_tx_hex) "
        "VALUES (?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    char sig_hex[129];
    hex_encode(sig64, 64, sig_hex);

    char *tx_hex = (char *)malloc(signed_tx_len * 2 + 1);
    if (!tx_hex) { sqlite3_finalize(stmt); return 0; }
    hex_encode(signed_tx, signed_tx_len, tx_hex);

    sqlite3_bind_int(stmt, 1, (int)channel_id);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)commitment_number);
    sqlite3_bind_text(stmt, 3, sig_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, tx_hex, -1, SQLITE_TRANSIENT);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    free(tx_hex);
    return ok;
}

int persist_load_commitment_sig(persist_t *p, uint32_t channel_id,
                                 uint64_t *commitment_number_out,
                                 unsigned char *sig64_out,
                                 unsigned char *signed_tx_out,
                                 size_t *signed_tx_len_out,
                                 size_t max_tx_len)
{
    if (!p || !p->db) return 0;

    const char *sql =
        "SELECT commitment_number, sig64_hex, signed_tx_hex "
        "FROM signed_commitments WHERE channel_id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);

    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        if (commitment_number_out)
            *commitment_number_out = (uint64_t)sqlite3_column_int64(stmt, 0);

        const char *sig_hex = (const char *)sqlite3_column_text(stmt, 1);
        if (sig64_out && sig_hex && strlen(sig_hex) == 128)
            hex_decode(sig_hex, sig64_out, 64);

        const char *tx_hex = (const char *)sqlite3_column_text(stmt, 2);
        if (signed_tx_out && tx_hex) {
            size_t hex_len = strlen(tx_hex);
            size_t raw_len = hex_len / 2;
            if (raw_len <= max_tx_len) {
                hex_decode(tx_hex, signed_tx_out, raw_len);
                if (signed_tx_len_out) *signed_tx_len_out = raw_len;
            }
        } else if (signed_tx_len_out && !signed_tx_out) {
            const char *txh = (const char *)sqlite3_column_text(stmt, 2);
            if (txh) *signed_tx_len_out = strlen(txh) / 2;
        }

        found = 1;
    }
    sqlite3_finalize(stmt);
    return found;
}

/* --- Distribution TX (schema v14) --- */

int persist_save_distribution_tx(persist_t *p, uint32_t factory_id,
                                  const unsigned char *signed_tx,
                                  size_t signed_tx_len)
{
    if (!p || !p->db || !signed_tx || signed_tx_len == 0) return 0;

    const char *sql =
        "INSERT OR REPLACE INTO distribution_txs "
        "(factory_id, signed_tx_hex) VALUES (?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    char *tx_hex = (char *)malloc(signed_tx_len * 2 + 1);
    if (!tx_hex) { sqlite3_finalize(stmt); return 0; }
    hex_encode(signed_tx, signed_tx_len, tx_hex);

    sqlite3_bind_int(stmt, 1, (int)factory_id);
    sqlite3_bind_text(stmt, 2, tx_hex, -1, SQLITE_TRANSIENT);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    free(tx_hex);
    return ok;
}

int persist_load_distribution_tx(persist_t *p, uint32_t factory_id,
                                  unsigned char *signed_tx_out,
                                  size_t *signed_tx_len_out,
                                  size_t max_len)
{
    if (!p || !p->db) return 0;

    const char *sql =
        "SELECT signed_tx_hex FROM distribution_txs WHERE factory_id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)factory_id);

    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *tx_hex = (const char *)sqlite3_column_text(stmt, 0);
        if (tx_hex) {
            size_t hex_len = strlen(tx_hex);
            size_t raw_len = hex_len / 2;
            if (signed_tx_out && raw_len <= max_len) {
                hex_decode(tx_hex, signed_tx_out, raw_len);
                if (signed_tx_len_out) *signed_tx_len_out = raw_len;
            } else if (signed_tx_len_out) {
                *signed_tx_len_out = raw_len;
            }
            found = 1;
        }
    }
    sqlite3_finalize(stmt);
    return found;
}

/* --- Fee settlement persistence (schema v17) --- */

int persist_save_fee_settlement(persist_t *p, uint32_t factory_id,
                                 uint64_t accumulated_fees_sats,
                                 uint32_t last_settlement_block) {
    if (!p || !p->db) return 0;
    sqlite3_stmt *stmt;
    const char *sql =
        "INSERT OR REPLACE INTO fee_settlement "
        "(factory_id, accumulated_fees_sats, last_settlement_block) "
        "VALUES (?, ?, ?);";
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int(stmt, 1, (int)factory_id);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)accumulated_fees_sats);
    sqlite3_bind_int(stmt, 3, (int)last_settlement_block);
    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

int persist_load_fee_settlement(persist_t *p, uint32_t factory_id,
                                 uint64_t *accumulated_fees_sats_out,
                                 uint32_t *last_settlement_block_out) {
    if (!p || !p->db) return 0;
    sqlite3_stmt *stmt;
    const char *sql =
        "SELECT accumulated_fees_sats, last_settlement_block "
        "FROM fee_settlement WHERE factory_id = ?;";
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int(stmt, 1, (int)factory_id);
    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        if (accumulated_fees_sats_out)
            *accumulated_fees_sats_out = (uint64_t)sqlite3_column_int64(stmt, 0);
        if (last_settlement_block_out)
            *last_settlement_block_out = (uint32_t)sqlite3_column_int(stmt, 1);
        found = 1;
    }
    sqlite3_finalize(stmt);
    return found;
}
