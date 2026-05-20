/* #248 (SF-WT-TRUSTLESS) Phase 1a — watchtower.db schema + open/close +
   register_watch helper. See include/superscalar/persist_wt.h and
   docs/watchtower-trustless-schema.md for the trust model. */

#include "superscalar/persist_wt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *WT_SCHEMA_DDL =
    "CREATE TABLE IF NOT EXISTS wt_meta ("
    "    key   TEXT PRIMARY KEY,"
    "    value TEXT NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS wt_responses ("
    "    response_id       INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    response_tx_hex   TEXT NOT NULL,"
    "    response_txid     BLOB NOT NULL,"
    "    fee_bump_anchor   BLOB,"
    "    fee_bump_budget   INTEGER NOT NULL DEFAULT 0,"
    "    fee_bump_deadline INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE INDEX IF NOT EXISTS wt_responses_txid_idx "
    "    ON wt_responses(response_txid);"
    "CREATE TABLE IF NOT EXISTS wt_watches ("
    "    watch_id          INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    factory_id        INTEGER NOT NULL,"
    "    parent_txid       BLOB NOT NULL,"
    "    parent_vout       INTEGER NOT NULL,"
    "    parent_value_sat  INTEGER NOT NULL,"
    "    parent_spk        BLOB NOT NULL,"
    "    csv_delay         INTEGER NOT NULL,"
    "    response_id       INTEGER NOT NULL,"
    "    superseded_at     INTEGER,"
    "    registered_at     INTEGER NOT NULL DEFAULT (strftime('%s','now')),"
    "    FOREIGN KEY (response_id) REFERENCES wt_responses(response_id)"
    ");"
    "CREATE INDEX IF NOT EXISTS wt_watches_active_idx "
    "    ON wt_watches(superseded_at) WHERE superseded_at IS NULL;"
    "CREATE TABLE IF NOT EXISTS wt_responses_broadcast ("
    "    broadcast_id              INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    watch_id                  INTEGER NOT NULL,"
    "    observed_spend_txid       BLOB NOT NULL,"
    "    observed_at_height        INTEGER NOT NULL,"
    "    response_broadcast_txid   BLOB,"
    "    response_broadcast_at     INTEGER,"
    "    broadcast_result          TEXT NOT NULL,"
    "    bitcoind_error            TEXT,"
    "    FOREIGN KEY (watch_id) REFERENCES wt_watches(watch_id)"
    ");"
    "CREATE TABLE IF NOT EXISTS wt_health ("
    "    heartbeat_at      INTEGER PRIMARY KEY,"
    "    chain_height      INTEGER NOT NULL,"
    "    n_active_watches  INTEGER NOT NULL,"
    "    last_reorg_at     INTEGER,"
    "    last_reorg_depth  INTEGER"
    ");";

static int wt_get_schema_version(sqlite3 *db, int *out) {
    const char *sql = "SELECT value FROM wt_meta WHERE key = 'schema_version';";
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        /* wt_meta doesn't exist yet — caller treats as version 0. */
        *out = 0;
        return 1;
    }
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        *out = atoi((const char *)sqlite3_column_text(st, 0));
    } else {
        *out = 0;
    }
    sqlite3_finalize(st);
    return 1;
}

static int wt_apply_schema(sqlite3 *db) {
    char *err = NULL;
    if (sqlite3_exec(db, WT_SCHEMA_DDL, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "persist_wt: schema DDL failed: %s\n",
                err ? err : "(unknown)");
        if (err) sqlite3_free(err);
        return 0;
    }
    char ver_buf[16];
    snprintf(ver_buf, sizeof(ver_buf), "%d", PERSIST_WT_SCHEMA_VERSION);
    sqlite3_stmt *st;
    const char *sql =
        "INSERT INTO wt_meta (key, value) VALUES ('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value;";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(st, 1, ver_buf, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 1 : 0;
}

int persist_wt_open(persist_wt_t *pwt, const char *path) {
    if (!pwt || !path) return 0;
    memset(pwt, 0, sizeof(*pwt));
    if (sqlite3_open(path, &pwt->db) != SQLITE_OK) {
        fprintf(stderr, "persist_wt_open: sqlite3_open(%s) failed: %s\n",
                path, sqlite3_errmsg(pwt->db));
        if (pwt->db) sqlite3_close(pwt->db);
        pwt->db = NULL;
        return 0;
    }
    /* Recommended pragmas for a moderate-write workload. */
    sqlite3_exec(pwt->db, "PRAGMA journal_mode = WAL;",         NULL, NULL, NULL);
    sqlite3_exec(pwt->db, "PRAGMA synchronous = NORMAL;",       NULL, NULL, NULL);
    sqlite3_exec(pwt->db, "PRAGMA foreign_keys = ON;",          NULL, NULL, NULL);

    int existing_ver = 0;
    if (!wt_get_schema_version(pwt->db, &existing_ver)) {
        sqlite3_close(pwt->db); pwt->db = NULL; return 0;
    }
    if (existing_ver == 0) {
        if (!wt_apply_schema(pwt->db)) {
            sqlite3_close(pwt->db); pwt->db = NULL; return 0;
        }
    } else if (existing_ver != PERSIST_WT_SCHEMA_VERSION) {
        fprintf(stderr,
                "persist_wt_open: schema version mismatch — file=%d code=%d. "
                "Phase 1a has no migration framework; refusing to open.\n",
                existing_ver, PERSIST_WT_SCHEMA_VERSION);
        sqlite3_close(pwt->db); pwt->db = NULL; return 0;
    }

    strncpy(pwt->path, path, sizeof(pwt->path) - 1);
    return 1;
}

void persist_wt_close(persist_wt_t *pwt) {
    if (!pwt) return;
    if (pwt->db) {
        sqlite3_close(pwt->db);
        pwt->db = NULL;
    }
}

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
                                    uint32_t fee_bump_deadline_height) {
    if (!pwt || !pwt->db) return -1;
    if (!parent_txid32 || !parent_spk || parent_spk_len == 0) return -1;
    if (!response_tx_hex || !response_txid32) return -1;

    int64_t watch_id = -1;
    char *err = NULL;
    if (sqlite3_exec(pwt->db, "BEGIN IMMEDIATE;", NULL, NULL, &err) != SQLITE_OK) {
        if (err) { fprintf(stderr, "persist_wt: BEGIN failed: %s\n", err); sqlite3_free(err); }
        return -1;
    }

    sqlite3_stmt *st;
    const char *ins_resp =
        "INSERT INTO wt_responses "
        "(response_tx_hex, response_txid, fee_bump_anchor, fee_bump_budget, fee_bump_deadline) "
        "VALUES (?, ?, NULL, ?, ?);";
    if (sqlite3_prepare_v2(pwt->db, ins_resp, -1, &st, NULL) != SQLITE_OK) goto rollback;
    sqlite3_bind_text (st, 1, response_tx_hex, -1, SQLITE_STATIC);
    sqlite3_bind_blob (st, 2, response_txid32, 32, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)fee_bump_budget_sat);
    sqlite3_bind_int  (st, 4, (int)fee_bump_deadline_height);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) goto rollback;
    int64_t response_id = sqlite3_last_insert_rowid(pwt->db);

    const char *ins_watch =
        "INSERT INTO wt_watches "
        "(factory_id, parent_txid, parent_vout, parent_value_sat, parent_spk, "
        " csv_delay, response_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);";
    if (sqlite3_prepare_v2(pwt->db, ins_watch, -1, &st, NULL) != SQLITE_OK) goto rollback;
    sqlite3_bind_int  (st, 1, (int)factory_id);
    sqlite3_bind_blob (st, 2, parent_txid32, 32, SQLITE_STATIC);
    sqlite3_bind_int  (st, 3, (int)parent_vout);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)parent_value_sat);
    sqlite3_bind_blob (st, 5, parent_spk, (int)parent_spk_len, SQLITE_STATIC);
    sqlite3_bind_int  (st, 6, (int)csv_delay);
    sqlite3_bind_int64(st, 7, (sqlite3_int64)response_id);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) goto rollback;
    watch_id = sqlite3_last_insert_rowid(pwt->db);

    if (sqlite3_exec(pwt->db, "COMMIT;", NULL, NULL, &err) != SQLITE_OK) {
        if (err) { fprintf(stderr, "persist_wt: COMMIT failed: %s\n", err); sqlite3_free(err); }
        return -1;
    }
    return watch_id;

rollback:
    sqlite3_exec(pwt->db, "ROLLBACK;", NULL, NULL, NULL);
    return -1;
}

int persist_wt_supersede_watch(persist_wt_t *pwt, int64_t watch_id,
                                 uint32_t at_height) {
    if (!pwt || !pwt->db || watch_id <= 0) return 0;
    const char *sql =
        "UPDATE wt_watches SET superseded_at = ? "
        "WHERE watch_id = ? AND superseded_at IS NULL;";
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(pwt->db, sql, -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int  (st, 1, (int)at_height);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)watch_id);
    int rc = sqlite3_step(st);
    int changes = sqlite3_changes(pwt->db);
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE && changes == 1) ? 1 : 0;
}

int persist_wt_count_active_watches(const persist_wt_t *pwt) {
    if (!pwt || !pwt->db) return -1;
    const char *sql =
        "SELECT COUNT(*) FROM wt_watches WHERE superseded_at IS NULL;";
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(pwt->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int n = 0;
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}
