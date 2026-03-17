/*
 * peer_db.c — SQLite-backed persistent peer database
 *
 * See peer_db.h for the full API description.
 */

#include "superscalar/peer_db.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ---- Helpers ---- */

static void pubkey_to_hex(const unsigned char pk[33], char out[67]) {
    static const char *hx = "0123456789abcdef";
    for (int i = 0; i < 33; i++) {
        out[i*2]     = hx[(pk[i] >> 4) & 0xF];
        out[i*2 + 1] = hx[pk[i] & 0xF];
    }
    out[66] = '\0';
}

static int hex_to_pubkey(const char *hex, unsigned char pk[33]) {
    if (!hex || strlen(hex) != 66) return 0;
    for (int i = 0; i < 33; i++) {
        unsigned char h = (unsigned char)hex[i*2];
        unsigned char l = (unsigned char)hex[i*2 + 1];
        unsigned int hi = (h >= '0' && h <= '9') ? (unsigned)(h - '0')
                        : (h >= 'a' && h <= 'f') ? (unsigned)(h - 'a' + 10)
                        : (h >= 'A' && h <= 'F') ? (unsigned)(h - 'A' + 10) : 0xFF;
        unsigned int lo = (l >= '0' && l <= '9') ? (unsigned)(l - '0')
                        : (l >= 'a' && l <= 'f') ? (unsigned)(l - 'a' + 10)
                        : (l >= 'A' && l <= 'F') ? (unsigned)(l - 'A' + 10) : 0xFF;
        if (hi == 0xFF || lo == 0xFF) return 0;
        pk[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

static int run_sql(sqlite3 *db, const char *sql) {
    char *errmsg = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "peer_db: SQL error: %s\n", errmsg ? errmsg : "?");
        sqlite3_free(errmsg);
        return 0;
    }
    return 1;
}

static const char *PEER_DB_SCHEMA =
    "CREATE TABLE IF NOT EXISTS peers ("
    "  pubkey_hex   TEXT    NOT NULL PRIMARY KEY,"
    "  address      TEXT    NOT NULL DEFAULT '',"
    "  score        INTEGER NOT NULL DEFAULT 100,"
    "  last_seen    INTEGER NOT NULL DEFAULT 0,"
    "  n_channels   INTEGER NOT NULL DEFAULT 0,"
    "  banned_until INTEGER NOT NULL DEFAULT 0"
    ");";

static int peer_db_init(peer_db_t *db) {
    return run_sql(db->db, PEER_DB_SCHEMA);
}

/* ---- Lifecycle ---- */

int peer_db_open(peer_db_t *db, const char *db_path) {
    int rc = sqlite3_open(db_path, &db->db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "peer_db: cannot open %s: %s\n",
                db_path, sqlite3_errmsg(db->db));
        sqlite3_close(db->db);
        db->db = NULL;
        return 0;
    }
    return peer_db_init(db);
}

int peer_db_open_in_memory(peer_db_t *db) {
    int rc = sqlite3_open(":memory:", &db->db);
    if (rc != SQLITE_OK) {
        db->db = NULL;
        return 0;
    }
    return peer_db_init(db);
}

void peer_db_close(peer_db_t *db) {
    if (db->db) {
        sqlite3_close(db->db);
        db->db = NULL;
    }
}

/* ---- CRUD ---- */

int peer_db_upsert(peer_db_t *db, const peer_db_entry_t *entry) {
    char hex[67];
    pubkey_to_hex(entry->pubkey33, hex);

    const char *sql =
        "INSERT OR REPLACE INTO peers "
        "(pubkey_hex, address, score, last_seen, n_channels, banned_until) "
        "VALUES (?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_text   (stmt, 1, hex, -1, SQLITE_STATIC);
    sqlite3_bind_text   (stmt, 2, entry->address, -1, SQLITE_STATIC);
    sqlite3_bind_int    (stmt, 3, entry->score);
    sqlite3_bind_int64  (stmt, 4, (sqlite3_int64)entry->last_seen);
    sqlite3_bind_int    (stmt, 5, entry->n_channels);
    sqlite3_bind_int64  (stmt, 6, (sqlite3_int64)entry->banned_until);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

int peer_db_get(peer_db_t *db, const unsigned char pubkey33[33],
                 peer_db_entry_t *out)
{
    char hex[67];
    pubkey_to_hex(pubkey33, hex);

    const char *sql =
        "SELECT pubkey_hex, address, score, last_seen, n_channels, banned_until "
        "FROM peers WHERE pubkey_hex = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_text(stmt, 1, hex, -1, SQLITE_STATIC);

    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *h = (const char *)sqlite3_column_text(stmt, 0);
        hex_to_pubkey(h, out->pubkey33);

        const char *addr = (const char *)sqlite3_column_text(stmt, 1);
        if (addr)
            snprintf(out->address, sizeof(out->address), "%s", addr);
        else
            out->address[0] = '\0';

        out->score        = sqlite3_column_int  (stmt, 2);
        out->last_seen    = (uint32_t)sqlite3_column_int64(stmt, 3);
        out->n_channels   = sqlite3_column_int  (stmt, 4);
        out->banned_until = (uint32_t)sqlite3_column_int64(stmt, 5);
        found = 1;
    }
    sqlite3_finalize(stmt);
    return found;
}

int peer_db_update_score(peer_db_t *db, const unsigned char pubkey33[33],
                          int delta)
{
    char hex[67];
    pubkey_to_hex(pubkey33, hex);

    /* Clamp new score to [0, 1000] */
    const char *sql =
        "UPDATE peers "
        "SET score = MAX(0, MIN(1000, score + ?)) "
        "WHERE pubkey_hex = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int (stmt, 1, delta);
    sqlite3_bind_text(stmt, 2, hex, -1, SQLITE_STATIC);

    sqlite3_step(stmt);
    int changed = sqlite3_changes(db->db);
    sqlite3_finalize(stmt);
    return changed > 0;
}

int peer_db_ban(peer_db_t *db, const unsigned char pubkey33[33],
                 uint32_t until_unix)
{
    char hex[67];
    pubkey_to_hex(pubkey33, hex);

    const char *sql =
        "UPDATE peers SET banned_until = ? WHERE pubkey_hex = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)until_unix);
    sqlite3_bind_text (stmt, 2, hex, -1, SQLITE_STATIC);

    sqlite3_step(stmt);
    int changed = sqlite3_changes(db->db);
    sqlite3_finalize(stmt);
    return changed > 0;
}

int peer_db_is_banned(peer_db_t *db, const unsigned char pubkey33[33],
                       uint32_t now_unix)
{
    char hex[67];
    pubkey_to_hex(pubkey33, hex);

    const char *sql =
        "SELECT banned_until FROM peers WHERE pubkey_hex = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_text(stmt, 1, hex, -1, SQLITE_STATIC);

    int banned = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        uint32_t until = (uint32_t)sqlite3_column_int64(stmt, 0);
        banned = (until > 0 && now_unix < until);
    }
    sqlite3_finalize(stmt);
    return banned;
}

int peer_db_count(peer_db_t *db) {
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db->db,
            "SELECT COUNT(*) FROM peers;", -1, &stmt, NULL) != SQLITE_OK)
        return -1;

    int count = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}
