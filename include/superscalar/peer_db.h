/*
 * peer_db.h — SQLite-backed persistent peer database
 *
 * Tracks known LN peers with connection quality scores, last-seen
 * timestamps, channel counts, and ban expiry.  Used by peer_mgr to
 * prefer high-quality peers on reconnect and to avoid banned peers.
 *
 * Schema (single table "peers"):
 *   pubkey_hex   TEXT PRIMARY KEY  (33-byte compressed key, hex-encoded)
 *   address      TEXT              ("host:port" string)
 *   score        INTEGER           (higher = better; default 100)
 *   last_seen    INTEGER           (Unix timestamp of last successful connection)
 *   n_channels   INTEGER           (number of open channels with this peer)
 *   banned_until INTEGER           (Unix timestamp; 0 = not banned)
 */

#ifndef SUPERSCALAR_PEER_DB_H
#define SUPERSCALAR_PEER_DB_H

#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

#define PEER_DB_ADDR_MAX  256   /* max "host:port" string length */

typedef struct {
    unsigned char pubkey33[33];
    char          address[PEER_DB_ADDR_MAX];
    int           score;         /* connection quality (0–1000) */
    uint32_t      last_seen;     /* Unix timestamp */
    int           n_channels;    /* open channels */
    uint32_t      banned_until;  /* 0 = not banned */
} peer_db_entry_t;

typedef struct {
    sqlite3 *db;
} peer_db_t;

/* Open (or create) peer DB at db_path. Returns 1 on success. */
int  peer_db_open(peer_db_t *db, const char *db_path);

/* Open an in-memory peer DB (for unit tests). Returns 1 on success. */
int  peer_db_open_in_memory(peer_db_t *db);

void peer_db_close(peer_db_t *db);

/*
 * Upsert a peer entry (INSERT OR REPLACE).
 * Returns 1 on success.
 */
int peer_db_upsert(peer_db_t *db, const peer_db_entry_t *entry);

/*
 * Retrieve a peer by pubkey33.
 * Returns 1 if found, 0 if not found or error.
 */
int peer_db_get(peer_db_t *db, const unsigned char pubkey33[33],
                 peer_db_entry_t *out);

/*
 * Adjust peer score by delta (clamped to [0, 1000]).
 * Returns 1 on success, 0 if peer not found.
 */
int peer_db_update_score(peer_db_t *db, const unsigned char pubkey33[33],
                          int delta);

/*
 * Ban a peer until until_unix (Unix timestamp).
 * Pass until_unix = 0 to unban.
 * Returns 1 on success, 0 if peer not found.
 */
int peer_db_ban(peer_db_t *db, const unsigned char pubkey33[33],
                 uint32_t until_unix);

/*
 * Returns 1 if the peer is currently banned (banned_until > now_unix).
 * Returns 0 if not banned or not found.
 */
int peer_db_is_banned(peer_db_t *db, const unsigned char pubkey33[33],
                       uint32_t now_unix);

/*
 * Return the number of peers in the database.
 * Returns -1 on error.
 */
int peer_db_count(peer_db_t *db);

#endif /* SUPERSCALAR_PEER_DB_H */
