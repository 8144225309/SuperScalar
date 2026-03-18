/*
 * test_peer_db.c — Unit tests for the SQLite-backed peer database
 *
 * PD1: test_peer_db_upsert_and_get         — insert and retrieve peer
 * PD2: test_peer_db_upsert_update          — upsert twice updates data
 * PD3: test_peer_db_update_score           — score delta clamped to [0,1000]
 * PD4: test_peer_db_ban_and_is_banned      — ban peer, verify banned within window
 * PD5: test_peer_db_ban_expires            — is_banned returns 0 after ban_until
 * PD6: test_peer_db_count                  — count correct with multiple peers
 * PD7: test_peer_db_get_not_found          — get returns 0 for unknown pubkey
 * PD8: test_peer_db_unban                  — ban then unban (until_unix=0)
 */

#include "superscalar/peer_db.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* Fixed test pubkeys */
static const unsigned char pk1[33] = { [0 ... 31] = 0x01, [32] = 0x02 };
static const unsigned char pk2[33] = { [0 ... 31] = 0x03, [32] = 0x04 };
static const unsigned char pk3[33] = { [0 ... 31] = 0x05, [32] = 0x06 };
static const unsigned char pk_unknown[33] = { [0 ... 31] = 0xFF };

/* ================================================================== */
/* PD1 — insert and retrieve peer                                     */
/* ================================================================== */
int test_peer_db_upsert_and_get(void)
{
    peer_db_t db;
    ASSERT(peer_db_open_in_memory(&db), "open in-memory DB");

    peer_db_entry_t entry;
    memcpy(entry.pubkey33, pk1, 33);
    snprintf(entry.address, sizeof(entry.address), "127.0.0.1:9735");
    entry.score        = 250;
    entry.last_seen    = 1700000000U;
    entry.n_channels   = 3;
    entry.banned_until = 0;

    ASSERT(peer_db_upsert(&db, &entry), "upsert should succeed");

    peer_db_entry_t got;
    memset(&got, 0, sizeof(got));
    ASSERT(peer_db_get(&db, pk1, &got), "get should find pk1");
    ASSERT(memcmp(got.pubkey33, pk1, 33) == 0, "pubkey round-trips");
    ASSERT(strcmp(got.address, "127.0.0.1:9735") == 0, "address round-trips");
    ASSERT(got.score      == 250,          "score round-trips");
    ASSERT(got.last_seen  == 1700000000U,  "last_seen round-trips");
    ASSERT(got.n_channels == 3,            "n_channels round-trips");
    ASSERT(got.banned_until == 0,          "banned_until = 0");

    peer_db_close(&db);
    return 1;
}

/* ================================================================== */
/* PD2 — upsert twice updates all fields                              */
/* ================================================================== */
int test_peer_db_upsert_update(void)
{
    peer_db_t db;
    ASSERT(peer_db_open_in_memory(&db), "open in-memory DB");

    peer_db_entry_t entry;
    memcpy(entry.pubkey33, pk1, 33);
    snprintf(entry.address, sizeof(entry.address), "10.0.0.1:9735");
    entry.score = 100; entry.last_seen = 1000; entry.n_channels = 1;
    entry.banned_until = 0;
    ASSERT(peer_db_upsert(&db, &entry), "first upsert");

    /* Update same pubkey */
    snprintf(entry.address, sizeof(entry.address), "10.0.0.2:9736");
    entry.score = 500; entry.last_seen = 2000; entry.n_channels = 5;
    ASSERT(peer_db_upsert(&db, &entry), "second upsert (update)");

    peer_db_entry_t got;
    ASSERT(peer_db_get(&db, pk1, &got), "get after update");
    ASSERT(strcmp(got.address, "10.0.0.2:9736") == 0, "address updated");
    ASSERT(got.score      == 500, "score updated");
    ASSERT(got.last_seen  == 2000, "last_seen updated");
    ASSERT(got.n_channels == 5,   "n_channels updated");
    ASSERT(peer_db_count(&db) == 1, "still only 1 peer");

    peer_db_close(&db);
    return 1;
}

/* ================================================================== */
/* PD3 — score delta clamped to [0, 1000]                            */
/* ================================================================== */
int test_peer_db_update_score(void)
{
    peer_db_t db;
    ASSERT(peer_db_open_in_memory(&db), "open in-memory DB");

    peer_db_entry_t entry;
    memcpy(entry.pubkey33, pk1, 33);
    entry.address[0] = '\0'; entry.score = 500;
    entry.last_seen = 0; entry.n_channels = 0; entry.banned_until = 0;
    ASSERT(peer_db_upsert(&db, &entry), "upsert");

    /* Normal delta */
    ASSERT(peer_db_update_score(&db, pk1, +100), "positive delta");
    peer_db_entry_t got;
    ASSERT(peer_db_get(&db, pk1, &got), "get after +100");
    ASSERT(got.score == 600, "score = 600 after +100");

    /* Clamp at 1000 */
    ASSERT(peer_db_update_score(&db, pk1, +500), "large positive delta");
    ASSERT(peer_db_get(&db, pk1, &got), "get after +500");
    ASSERT(got.score == 1000, "score clamped at 1000");

    /* Negative delta */
    ASSERT(peer_db_update_score(&db, pk1, -200), "negative delta");
    ASSERT(peer_db_get(&db, pk1, &got), "get after -200");
    ASSERT(got.score == 800, "score = 800 after -200");

    /* Clamp at 0 */
    ASSERT(peer_db_update_score(&db, pk1, -5000), "large negative delta");
    ASSERT(peer_db_get(&db, pk1, &got), "get after -5000");
    ASSERT(got.score == 0, "score clamped at 0");

    /* Unknown peer returns 0 */
    int ok = peer_db_update_score(&db, pk_unknown, +10);
    ASSERT(ok == 0, "update_score on unknown peer returns 0");

    peer_db_close(&db);
    return 1;
}

/* ================================================================== */
/* PD4 — ban peer, verify is_banned within window                     */
/* ================================================================== */
int test_peer_db_ban_and_is_banned(void)
{
    peer_db_t db;
    ASSERT(peer_db_open_in_memory(&db), "open in-memory DB");

    peer_db_entry_t entry;
    memcpy(entry.pubkey33, pk1, 33);
    entry.address[0] = '\0'; entry.score = 100;
    entry.last_seen = 0; entry.n_channels = 0; entry.banned_until = 0;
    ASSERT(peer_db_upsert(&db, &entry), "upsert");

    /* Ban until 2000000000 */
    ASSERT(peer_db_ban(&db, pk1, 2000000000U), "ban peer");
    ASSERT(peer_db_is_banned(&db, pk1, 1700000000U), "banned at time < ban_until");
    ASSERT(!peer_db_is_banned(&db, pk1, 2000000001U), "not banned after ban_until");

    peer_db_close(&db);
    return 1;
}

/* ================================================================== */
/* PD5 — ban expires: is_banned returns 0 after ban_until             */
/* ================================================================== */
int test_peer_db_ban_expires(void)
{
    peer_db_t db;
    ASSERT(peer_db_open_in_memory(&db), "open in-memory DB");

    peer_db_entry_t entry;
    memcpy(entry.pubkey33, pk2, 33);
    entry.address[0] = '\0'; entry.score = 100;
    entry.last_seen = 0; entry.n_channels = 0;
    entry.banned_until = 1000;   /* already in the past */
    ASSERT(peer_db_upsert(&db, &entry), "upsert with past ban");

    /* now = 2000 > 1000, ban has expired */
    ASSERT(!peer_db_is_banned(&db, pk2, 2000U), "expired ban not active");

    /* ban it fresh */
    ASSERT(peer_db_ban(&db, pk2, 5000U), "apply fresh ban");
    ASSERT(peer_db_is_banned(&db, pk2, 4999U), "fresh ban active");
    ASSERT(!peer_db_is_banned(&db, pk2, 5001U), "fresh ban expired");

    peer_db_close(&db);
    return 1;
}

/* ================================================================== */
/* PD6 — count correct with multiple peers                            */
/* ================================================================== */
int test_peer_db_count(void)
{
    peer_db_t db;
    ASSERT(peer_db_open_in_memory(&db), "open in-memory DB");

    ASSERT(peer_db_count(&db) == 0, "empty db count = 0");

    peer_db_entry_t e;
    e.address[0] = '\0'; e.score = 100;
    e.last_seen = 0; e.n_channels = 0; e.banned_until = 0;

    memcpy(e.pubkey33, pk1, 33); peer_db_upsert(&db, &e);
    ASSERT(peer_db_count(&db) == 1, "count = 1 after first insert");

    memcpy(e.pubkey33, pk2, 33); peer_db_upsert(&db, &e);
    ASSERT(peer_db_count(&db) == 2, "count = 2 after second insert");

    memcpy(e.pubkey33, pk3, 33); peer_db_upsert(&db, &e);
    ASSERT(peer_db_count(&db) == 3, "count = 3 after third insert");

    /* Upsert existing key — count stays at 3 */
    memcpy(e.pubkey33, pk1, 33); e.score = 999;
    peer_db_upsert(&db, &e);
    ASSERT(peer_db_count(&db) == 3, "count unchanged after upsert of existing key");

    peer_db_close(&db);
    return 1;
}

/* ================================================================== */
/* PD7 — get returns 0 for unknown pubkey                             */
/* ================================================================== */
int test_peer_db_get_not_found(void)
{
    peer_db_t db;
    ASSERT(peer_db_open_in_memory(&db), "open in-memory DB");

    peer_db_entry_t got;
    int found = peer_db_get(&db, pk_unknown, &got);
    ASSERT(found == 0, "get on unknown pubkey returns 0");

    peer_db_close(&db);
    return 1;
}

/* ================================================================== */
/* PD8 — ban then unban (until_unix = 0)                              */
/* ================================================================== */
int test_peer_db_unban(void)
{
    peer_db_t db;
    ASSERT(peer_db_open_in_memory(&db), "open in-memory DB");

    peer_db_entry_t entry;
    memcpy(entry.pubkey33, pk1, 33);
    entry.address[0] = '\0'; entry.score = 100;
    entry.last_seen = 0; entry.n_channels = 0; entry.banned_until = 0;
    ASSERT(peer_db_upsert(&db, &entry), "upsert");

    ASSERT(peer_db_ban(&db, pk1, 2147483647U), "ban peer");
    ASSERT(peer_db_is_banned(&db, pk1, 1700000000U), "peer is banned");

    /* Unban by setting until=0 */
    ASSERT(peer_db_ban(&db, pk1, 0), "unban peer");
    ASSERT(!peer_db_is_banned(&db, pk1, 1700000000U), "peer is no longer banned");

    peer_db_close(&db);
    return 1;
}
