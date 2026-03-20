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
    "  last_update  INTEGER NOT NULL DEFAULT 0,"
    "  pruned_at    INTEGER NOT NULL DEFAULT 0"
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
    if (!run_sql(gs->db, GOSSIP_SCHEMA_SQL)) return 0;
    /* Add pruned_at column to existing databases (idempotent — ignore error if exists). */
    sqlite3_exec(gs->db,
        "ALTER TABLE gossip_channels ADD COLUMN pruned_at INTEGER NOT NULL DEFAULT 0;",
        NULL, NULL, NULL);
    return 1;
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

/* --- Stale channel pruning --- */

int gossip_store_prune_stale(gossip_store_t *gs, uint32_t now_unix) {
    if (!gs || !gs->db) return -1;

    /* 1. Hard-delete channels that have been marked spent and grace period has elapsed */
    {
        sqlite3_stmt *stmt;
        int rc = sqlite3_prepare_v2(gs->db,
            "DELETE FROM gossip_channels"
            "  WHERE pruned_at > 0 AND pruned_at + ? <= ?;",
            -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, (sqlite3_int64)GOSSIP_GRACE_SECS);
            sqlite3_bind_int64(stmt, 2, (sqlite3_int64)now_unix);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    /* 2. Delete channel_updates older than GOSSIP_PRUNE_SECS */
    {
        sqlite3_stmt *stmt;
        int rc = sqlite3_prepare_v2(gs->db,
            "DELETE FROM gossip_channel_updates"
            "  WHERE timestamp + ? <= ?;",
            -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, (sqlite3_int64)GOSSIP_PRUNE_SECS);
            sqlite3_bind_int64(stmt, 2, (sqlite3_int64)now_unix);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    /* 3. Delete channels where neither direction has a recent update and not spent-marked */
    {
        sqlite3_stmt *stmt;
        int rc = sqlite3_prepare_v2(gs->db,
            "DELETE FROM gossip_channels"
            "  WHERE pruned_at = 0"
            "    AND scid NOT IN (SELECT DISTINCT scid FROM gossip_channel_updates);",
            -1, &stmt, NULL);
        if (rc != SQLITE_OK) return -1;
        sqlite3_step(stmt);
        int removed = sqlite3_changes(gs->db);
        sqlite3_finalize(stmt);
        return removed;
    }
}

int gossip_store_mark_channel_spent(gossip_store_t *gs,
                                     uint64_t scid, uint32_t now_unix) {
    if (!gs || !gs->db) return 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(gs->db,
        "UPDATE gossip_channels SET pruned_at = ? WHERE scid = ?;",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)now_unix);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)scid);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 1 : 0;
}

int gossip_store_get_channels_by_scids(gossip_store_t *gs,
    const uint64_t *scids, int n_scids,
    gossip_store_channel_cb_t cb, void *userdata)
{
    if (!gs || !gs->db || !scids || n_scids <= 0 || !cb) return 0;
    int found = 0;
    for (int i = 0; i < n_scids; i++) {
        unsigned char n1[33], n2[33];
        uint64_t cap; uint32_t lu;
        if (gossip_store_get_channel(gs, scids[i], n1, n2, &cap, &lu)) {
            cb(scids[i], n1, n2, userdata);
            found++;
        }
    }
    return found;
}

int gossip_store_get_channels_in_range(gossip_store_t *gs,
    uint32_t first_blocknum, uint32_t num_blocks,
    gossip_store_channel_cb_t cb, void *userdata)
{
    if (!gs || !gs->db || !cb) return 0;
    sqlite3_stmt *stmt;
    /* SCID block number = (scid >> 40) */
    int rc = sqlite3_prepare_v2(gs->db,
        "SELECT scid, node1_hex, node2_hex FROM gossip_channels"
        " WHERE ((scid >> 40) >= ? AND (scid >> 40) < ?) AND pruned_at = 0;",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)first_blocknum);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)((uint64_t)first_blocknum + num_blocks));
    int found = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        uint64_t scid = (uint64_t)sqlite3_column_int64(stmt, 0);
        unsigned char n1[33], n2[33];
        const char *h1 = (const char *)sqlite3_column_text(stmt, 1);
        const char *h2 = (const char *)sqlite3_column_text(stmt, 2);
        /* decode hex to bytes using inline helper */
        if (h1) {
            for (int j = 0; j < 33 && h1[j*2] && h1[j*2+1]; j++) {
                unsigned char hi = (unsigned char)h1[j*2];
                unsigned char lo = (unsigned char)h1[j*2+1];
                hi = (hi >= 'a') ? hi-'a'+10 : (hi >= 'A') ? hi-'A'+10 : hi-'0';
                lo = (lo >= 'a') ? lo-'a'+10 : (lo >= 'A') ? lo-'A'+10 : lo-'0';
                n1[j] = (hi << 4) | lo;
            }
        }
        if (h2) {
            for (int j = 0; j < 33 && h2[j*2] && h2[j*2+1]; j++) {
                unsigned char hi = (unsigned char)h2[j*2];
                unsigned char lo = (unsigned char)h2[j*2+1];
                hi = (hi >= 'a') ? hi-'a'+10 : (hi >= 'A') ? hi-'A'+10 : hi-'0';
                lo = (lo >= 'a') ? lo-'a'+10 : (lo >= 'A') ? lo-'A'+10 : lo-'0';
                n2[j] = (hi << 4) | lo;
            }
        }
        cb(scid, n1, n2, userdata);
        found++;
    }
    sqlite3_finalize(stmt);
    return found;
}

/* ---- Channel enumeration for pathfinding ---- */

int gossip_store_enumerate_channels(gossip_store_t *gs,
                                     gossip_store_full_channel_cb_t cb,
                                     void *ctx)
{
    if (!gs || !gs->db || !cb) return -1;

    sqlite3_stmt *stmt;
    /*
     * Join channels with their channel_updates to emit one directed edge per
     * (scid, direction) row.  We use capacity_sat * 1000 as a conservative
     * htlc_max_msat because the gossip_channel_updates table does not store
     * the htlc_maximum_msat field (it is optional in BOLT #7 and was not
     * added to the schema).  htlc_min_msat is set to 1 msat (permissive).
     */
    const char *sql =
        "SELECT c.scid, c.node1_hex, c.node2_hex, c.capacity_sat, "
        "       u.direction, u.fee_base_msat, u.fee_ppm, u.cltv_delta "
        "FROM gossip_channels c "
        "JOIN gossip_channel_updates u ON c.scid = u.scid "
        "WHERE c.pruned_at = 0;";

    int rc = sqlite3_prepare_v2(gs->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        uint64_t scid        = (uint64_t)sqlite3_column_int64(stmt, 0);
        const char *n1_hex   = (const char *)sqlite3_column_text(stmt, 1);
        const char *n2_hex   = (const char *)sqlite3_column_text(stmt, 2);
        uint64_t cap_sat     = (uint64_t)sqlite3_column_int64(stmt, 3);
        int direction        = sqlite3_column_int(stmt, 4);
        uint32_t fee_base    = (uint32_t)sqlite3_column_int64(stmt, 5);
        uint32_t fee_ppm     = (uint32_t)sqlite3_column_int64(stmt, 6);
        uint16_t cltv        = (uint16_t)sqlite3_column_int(stmt, 7);

        if (!n1_hex || !n2_hex) continue;

        unsigned char pk1[33], pk2[33];
        if (!hex_to_pubkey(n1_hex, pk1)) continue;
        if (!hex_to_pubkey(n2_hex, pk2)) continue;

        /* direction 0: node1 is src; direction 1: node2 is src */
        const unsigned char *src = (direction == 0) ? pk1 : pk2;
        const unsigned char *dst = (direction == 0) ? pk2 : pk1;

        uint64_t htlc_max = cap_sat * 1000ULL; /* conservative upper bound */

        cb(scid, src, dst, fee_base, fee_ppm, cltv,
           1ULL /* htlc_min_msat */, htlc_max, cap_sat, ctx);
        count++;
    }
    sqlite3_finalize(stmt);
    return count;
}

/* ---- Incremental channel enumeration (since a given timestamp) ---- */

int gossip_store_enumerate_channels_since(gossip_store_t *gs,
                                           uint32_t since_ts,
                                           gossip_store_full_channel_cb_t cb,
                                           void *ctx)
{
    if (!gs || !gs->db || !cb) return -1;

    sqlite3_stmt *stmt;
    const char *sql =
        "SELECT c.scid, c.node1_hex, c.node2_hex, c.capacity_sat, "
        "       u.direction, u.fee_base_msat, u.fee_ppm, u.cltv_delta "
        "FROM gossip_channels c "
        "JOIN gossip_channel_updates u ON c.scid = u.scid "
        "WHERE c.pruned_at = 0 AND u.timestamp > ?;";

    int rc = sqlite3_prepare_v2(gs->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)since_ts);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        uint64_t scid        = (uint64_t)sqlite3_column_int64(stmt, 0);
        const char *n1_hex   = (const char *)sqlite3_column_text(stmt, 1);
        const char *n2_hex   = (const char *)sqlite3_column_text(stmt, 2);
        uint64_t cap_sat     = (uint64_t)sqlite3_column_int64(stmt, 3);
        int direction        = sqlite3_column_int(stmt, 4);
        uint32_t fee_base    = (uint32_t)sqlite3_column_int64(stmt, 5);
        uint32_t fee_ppm     = (uint32_t)sqlite3_column_int64(stmt, 6);
        uint16_t cltv        = (uint16_t)sqlite3_column_int(stmt, 7);

        if (!n1_hex || !n2_hex) continue;

        unsigned char pk1[33], pk2[33];
        if (!hex_to_pubkey(n1_hex, pk1)) continue;
        if (!hex_to_pubkey(n2_hex, pk2)) continue;

        const unsigned char *src = (direction == 0) ? pk1 : pk2;
        const unsigned char *dst = (direction == 0) ? pk2 : pk1;

        uint64_t htlc_max = cap_sat * 1000ULL;

        cb(scid, src, dst, fee_base, fee_ppm, cltv,
           1ULL /* htlc_min_msat */, htlc_max, cap_sat, ctx);
        count++;
    }
    sqlite3_finalize(stmt);
    return count;
}
