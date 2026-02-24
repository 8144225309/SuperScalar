#include "superscalar/persist.h"
#include "superscalar/wire.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#ifndef BASEPOINT_DIAG
#define BASEPOINT_DIAG 0
#endif

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

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
    "  state TEXT NOT NULL"
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
    "  bump_count INTEGER NOT NULL DEFAULT 0"
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
    sqlite3_exec(p->db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_busy_timeout(p->db, 5000);

    /* Create schema */
    char *errmsg = NULL;
    rc = sqlite3_exec(p->db, SCHEMA_SQL, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "persist_open: schema error: %s\n", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close(p->db);
        p->db = NULL;
        return 0;
    }

    return 1;
}

void persist_close(persist_t *p) {
    if (p && p->db) {
        sqlite3_close(p->db);
        p->db = NULL;
    }
}

int persist_begin(persist_t *p) {
    if (!p || !p->db) return 0;
    return sqlite3_exec(p->db, "BEGIN;", NULL, NULL, NULL) == SQLITE_OK;
}

int persist_commit(persist_t *p) {
    if (!p || !p->db) return 0;
    return sqlite3_exec(p->db, "COMMIT;", NULL, NULL, NULL) == SQLITE_OK;
}

int persist_rollback(persist_t *p) {
    if (!p || !p->db) return 0;
    return sqlite3_exec(p->db, "ROLLBACK;", NULL, NULL, NULL) == SQLITE_OK;
}

/* --- Factory --- */

int persist_save_factory(persist_t *p, const factory_t *f,
                          secp256k1_context *ctx, uint32_t factory_id) {
    if (!p || !p->db || !f || !ctx) return 0;

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
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

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
    if (!ok) return 0;

    /* Save participants */
    const char *pk_sql =
        "INSERT OR REPLACE INTO factory_participants (factory_id, slot, pubkey) "
        "VALUES (?, ?, ?);";

    for (size_t i = 0; i < f->n_participants; i++) {
        sqlite3_stmt *pk_stmt;
        if (sqlite3_prepare_v2(p->db, pk_sql, -1, &pk_stmt, NULL) != SQLITE_OK)
            return 0;

        unsigned char pk_ser[33];
        size_t pk_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, pk_ser, &pk_len, &f->pubkeys[i],
                                       SECP256K1_EC_COMPRESSED);
        char pk_hex[67];
        hex_encode(pk_ser, 33, pk_hex);

        sqlite3_bind_int(pk_stmt, 1, (int)factory_id);
        sqlite3_bind_int(pk_stmt, 2, (int)i);
        sqlite3_bind_text(pk_stmt, 3, pk_hex, -1, SQLITE_TRANSIENT);

        ok = (sqlite3_step(pk_stmt) == SQLITE_DONE);
        sqlite3_finalize(pk_stmt);
        if (!ok) return 0;
    }

    return 1;
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
    extern void sha256_tagged(const char *, const unsigned char *, size_t,
                               unsigned char *);
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pubkeys, n_participants))
        return 0;

    unsigned char internal_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey);
    unsigned char twk[32];
    sha256_tagged("TapTweak", internal_ser, 32, twk);

    musig_keyagg_t ka_copy = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk,
                                                   &ka_copy.cache, twk))
        return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk);

    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tweaked_xonly);

    /* Reconstruct factory */
    factory_init_from_pubkeys(f, ctx, pubkeys, n_participants,
                               step_blocks, states_per_layer);
    f->cltv_timeout = cltv_timeout;
    f->fee_per_tx = fee_per_tx;
    if (leaf_arity == 1)
        factory_set_arity(f, FACTORY_ARITY_1);

    factory_set_funding(f, funding_txid, funding_vout, funding_amount,
                         fund_spk, 34);

    if (!factory_build_tree(f))
        return 0;

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
        " commitment_number, funding_txid, funding_vout, state) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open');";

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

    if (local_amount)
        *local_amount = (uint64_t)sqlite3_column_int64(stmt, 0);
    if (remote_amount)
        *remote_amount = (uint64_t)sqlite3_column_int64(stmt, 1);
    if (commitment_number)
        *commitment_number = (uint64_t)sqlite3_column_int64(stmt, 2);

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
        " payment_preimage, cltv_expiry, state) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";

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

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

size_t persist_load_htlcs(persist_t *p, uint32_t channel_id,
                            htlc_t *htlcs_out, size_t max_htlcs) {
    if (!p || !p->db || !htlcs_out) return 0;

    const char *sql =
        "SELECT htlc_id, direction, amount, payment_hash, "
        "payment_preimage, cltv_expiry, state "
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

        count++;
    }

    sqlite3_finalize(stmt);
    return count;
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
        if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
            return 0;

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
        if (!ok) return 0;
    }

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
                                 uint32_t dying_blocks) {
    if (!p || !p->db) return 0;

    const char *sql =
        "INSERT OR REPLACE INTO ladder_factories "
        "(factory_id, state, is_funded, is_initialized, n_departed, "
        " created_block, active_blocks, dying_blocks, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";

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
    sqlite3_bind_int64(stmt, 9, (sqlite3_int64)time(NULL));

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
    secp256k1_ec_pubkey_serialize(ch->ctx, ser, &slen,
        &ch->remote_payment_basepoint, SECP256K1_EC_COMPRESSED);
    hex_encode(ser, 33, rpay_hex);

    slen = 33;
    secp256k1_ec_pubkey_serialize(ch->ctx, ser, &slen,
        &ch->remote_delayed_payment_basepoint, SECP256K1_EC_COMPRESSED);
    hex_encode(ser, 33, rdelay_hex);

    slen = 33;
    secp256k1_ec_pubkey_serialize(ch->ctx, ser, &slen,
        &ch->remote_revocation_basepoint, SECP256K1_EC_COMPRESSED);
    hex_encode(ser, 33, rrevoc_hex);

    slen = 33;
    secp256k1_ec_pubkey_serialize(ch->ctx, ser, &slen,
        &ch->remote_htlc_basepoint, SECP256K1_EC_COMPRESSED);
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
                           int cycles_in_mempool, int bump_count) {
    if (!p || !p->db || !txid) return 0;

    const char *sql =
        "INSERT OR REPLACE INTO watchtower_pending "
        "(txid, anchor_vout, anchor_amount, cycles_in_mempool, bump_count) "
        "VALUES (?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_text(stmt, 1, txid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, (int)anchor_vout);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)anchor_amount);
    sqlite3_bind_int(stmt, 4, cycles_in_mempool);
    sqlite3_bind_int(stmt, 5, bump_count);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

size_t persist_load_pending(persist_t *p, char (*txids_out)[65],
                              uint32_t *vouts_out, uint64_t *amounts_out,
                              int *cycles_out, int *bumps_out,
                              size_t max_entries) {
    if (!p || !p->db) return 0;

    const char *sql =
        "SELECT txid, anchor_vout, anchor_amount, cycles_in_mempool, bump_count "
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
