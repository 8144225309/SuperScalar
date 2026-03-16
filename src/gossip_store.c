/*
 * gossip_store.c — SQLite-backed gossip data store
 *
 * Tables: gossip_nodes, gossip_channels, gossip_channel_updates
 */

#include "superscalar/gossip_store.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Helper: encode 33-byte pubkey as 66-char hex string (+ NUL) */
static void pubkey_to_hex(const unsigned char pk[33], char out[67]) {
    static const char *hx = "0123456789abcdef";
    for (int i = 0; i < 33; i++) {
        out[i*2]     = hx[(pk[i] >> 4) & 0xF];
        out[i*2 + 1] = hx[pk[i] & 0xF];
    }
    out[66] = '\0';
}

/* Helper: decode 66-char hex string → 33-byte pubkey. Returns 1 on success. */
static int hex_to_pubkey(const char *hex, unsigned char pk[33]) {
    if (!hex || strlen(hex) != 66) return 0;
    for (int i = 0; i < 33; i++) {
        unsigned char h = (unsigned char)hex[i*2];
        unsigned char l = (unsigned char)hex[i*2 + 1];
        unsigned int hi = (h >= '0' && h <= '9') ? (unsigned)(h - '0')
                        : (h >= 'a' && h <= 'f') ? (unsigned)(h - 'a' + 10)
                        : (h >= 'A' && h <= 'F') ? (unsigned)(h - 'A' + 10)
                        : 0xFF;
        unsigned int lo = (l >= '0' && l <= '9') ? (unsigned)(l - '0')
                        : (l >= 'a' && l <= 'f') ? (unsigned)(l - 'a' + 10)
                        : (l >= 'A' && l <= 'F') ? (unsigned)(l - 'A' + 10)
                        : 0xFF;
        if (hi == 0xFF || lo == 0xFF) return 0;
        pk[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

static const char *GOSSIP_SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS gossip_nodes ("
    "  pubkey_hex TEXT NOT NULL PRIMARY KEY,"
    "  alias      TEXT,"
    "  address    TEXT,"
    "  last_seen  INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE TABLE IF NOT EXISTS gossip_channels ("
    "  scid         INTEGER NOT NULL PRIMARY KEY,"
    "  node1_hex    TEXT NOT NULL,"
    "  node2_hex    TEXT NOT NULL,"
    "  capacity_sat INTEGER NOT NULL DEFAULT 0,"
    "  last_update  INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE TABLE IF NOT EXISTS gossip_channel_updates ("
    "  scid          INTEGER NOT NULL,"
    "  direction     INTEGER NOT NULL,"
    "  fee_base_msat INTEGER NOT NULL DEFAULT 0,"
    "  fee_ppm       INTEGER NOT NULL DEFAULT 0,"
    "  cltv_delta    INTEGER NOT NULL DEFAULT 0,"
    "  timestamp     INTEGER NOT NULL DEFAULT 0,"
    "  PRIMARY KEY (scid, direction)"
    ");";

static int run_sql(sqlite3 *db, const char *sql) {
    char *errmsg = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "gossip_store: SQL error: %s\n", errmsg ? errmsg : "?");
        sqlite3_free(errmsg);
        return 0;
    }
    return 1;
}

static int gossip_store_init(gossip_store_t *gs) {
    return run_sql(gs->db, GOSSIP_SCHEMA_SQL);
}

int gossip_store_open(gossip_store_t *gs, const char *db_path) {
    if (!gs || !db_path) return 0;
    gs->db = NULL;
    int rc = sqlite3_open(db_path, &gs->db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "gossip_store_open: %s\n", sqlite3_errmsg(gs->db));
        sqlite3_close(gs->db);
        gs->db = NULL;
        return 0;
    }
    return gossip_store_init(gs);
}

int gossip_store_open_in_memory(gossip_store_t *gs) {
    return gossip_store_open(gs, ":memory:");
}

void gossip_store_close(gossip_store_t *gs) {
    if (gs && gs->db) {
        sqlite3_close(gs->db);
        gs->db = NULL;
    }
}

int gossip_store_upsert_node(gossip_store_t *gs,
                              const unsigned char pubkey33[33],
                              const char *alias,
                              const char *address,
                              uint32_t    last_seen) {
    if (!gs || !gs->db || !pubkey33) return 0;

    char pk_hex[67];
    pubkey_to_hex(pubkey33, pk_hex);

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(gs->db,
        "INSERT OR REPLACE INTO gossip_nodes"
        "  (pubkey_hex, alias, address, last_seen)"
        "  VALUES (?, ?, ?, ?);",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    sqlite3_bind_text(stmt, 1, pk_hex, -1, SQLITE_STATIC);
    if (alias)
        sqlite3_bind_text(stmt, 2, alias, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(stmt, 2);
    if (address)
        sqlite3_bind_text(stmt, 3, address, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(stmt, 3);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)last_seen);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 1 : 0;
}

int gossip_store_get_node(gossip_store_t *gs,
                           const unsigned char pubkey33[33],
                           char *alias_out,   size_t alias_cap,
                           char *addr_out,    size_t addr_cap,
                           uint32_t *last_seen_out) {
    if (!gs || !gs->db || !pubkey33) return 0;

    char pk_hex[67];
    pubkey_to_hex(pubkey33, pk_hex);

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(gs->db,
        "SELECT alias, address, last_seen FROM gossip_nodes"
        "  WHERE pubkey_hex = ? LIMIT 1;",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    sqlite3_bind_text(stmt, 1, pk_hex, -1, SQLITE_STATIC);

    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        found = 1;
        if (alias_out && alias_cap > 0) {
            const char *a = (const char *)sqlite3_column_text(stmt, 0);
            if (a) {
                strncpy(alias_out, a, alias_cap - 1);
                alias_out[alias_cap - 1] = '\0';
            } else {
                alias_out[0] = '\0';
            }
        }
        if (addr_out && addr_cap > 0) {
            const char *a = (const char *)sqlite3_column_text(stmt, 1);
            if (a) {
                strncpy(addr_out, a, addr_cap - 1);
                addr_out[addr_cap - 1] = '\0';
            } else {
                addr_out[0] = '\0';
            }
        }
        if (last_seen_out)
            *last_seen_out = (uint32_t)sqlite3_column_int64(stmt, 2);
    }
    sqlite3_finalize(stmt);
    return found;
}

int gossip_store_upsert_channel(gossip_store_t *gs,
                                 uint64_t scid,
                                 const unsigned char node1_33[33],
                                 const unsigned char node2_33[33],
                                 uint64_t capacity_sats,
                                 uint32_t last_update) {
    if (!gs || !gs->db || !node1_33 || !node2_33) return 0;

    char n1_hex[67], n2_hex[67];
    pubkey_to_hex(node1_33, n1_hex);
    pubkey_to_hex(node2_33, n2_hex);

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(gs->db,
        "INSERT OR REPLACE INTO gossip_channels"
        "  (scid, node1_hex, node2_hex, capacity_sat, last_update)"
        "  VALUES (?, ?, ?, ?, ?);",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)scid);
    sqlite3_bind_text(stmt, 2, n1_hex, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, n2_hex, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)capacity_sats);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)last_update);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 1 : 0;
}

int gossip_store_get_channel(gossip_store_t *gs,
                              uint64_t scid,
                              unsigned char node1_out[33],
                              unsigned char node2_out[33],
                              uint64_t *capacity_out,
                              uint32_t *last_update_out) {
    if (!gs || !gs->db) return 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(gs->db,
        "SELECT node1_hex, node2_hex, capacity_sat, last_update"
        "  FROM gossip_channels WHERE scid = ? LIMIT 1;",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)scid);

    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        found = 1;
        if (node1_out)
            hex_to_pubkey((const char *)sqlite3_column_text(stmt, 0), node1_out);
        if (node2_out)
            hex_to_pubkey((const char *)sqlite3_column_text(stmt, 1), node2_out);
        if (capacity_out)
            *capacity_out = (uint64_t)sqlite3_column_int64(stmt, 2);
        if (last_update_out)
            *last_update_out = (uint32_t)sqlite3_column_int64(stmt, 3);
    }
    sqlite3_finalize(stmt);
    return found;
}

int gossip_store_upsert_channel_update(gossip_store_t *gs,
                                        uint64_t scid,
                                        int      direction,
                                        uint32_t fee_base_msat,
                                        uint32_t fee_ppm,
                                        uint16_t cltv_delta,
                                        uint32_t timestamp) {
    if (!gs || !gs->db) return 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(gs->db,
        "INSERT OR REPLACE INTO gossip_channel_updates"
        "  (scid, direction, fee_base_msat, fee_ppm, cltv_delta, timestamp)"
        "  VALUES (?, ?, ?, ?, ?, ?);",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)scid);
    sqlite3_bind_int(stmt,   2, direction);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)fee_base_msat);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)fee_ppm);
    sqlite3_bind_int(stmt,   5, (int)cltv_delta);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)timestamp);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 1 : 0;
}

int gossip_store_get_channel_update(gossip_store_t *gs,
                                     uint64_t scid,
                                     int      direction,
                                     uint32_t *fee_base_out,
                                     uint32_t *fee_ppm_out,
                                     uint16_t *cltv_delta_out,
                                     uint32_t *timestamp_out) {
    if (!gs || !gs->db) return 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(gs->db,
        "SELECT fee_base_msat, fee_ppm, cltv_delta, timestamp"
        "  FROM gossip_channel_updates"
        "  WHERE scid = ? AND direction = ? LIMIT 1;",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)scid);
    sqlite3_bind_int(stmt,   2, direction);

    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        found = 1;
        if (fee_base_out)
            *fee_base_out = (uint32_t)sqlite3_column_int64(stmt, 0);
        if (fee_ppm_out)
            *fee_ppm_out = (uint32_t)sqlite3_column_int64(stmt, 1);
        if (cltv_delta_out)
            *cltv_delta_out = (uint16_t)sqlite3_column_int(stmt, 2);
        if (timestamp_out)
            *timestamp_out = (uint32_t)sqlite3_column_int64(stmt, 3);
    }
    sqlite3_finalize(stmt);
    return found;
}
