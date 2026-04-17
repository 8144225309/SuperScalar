#include "superscalar/readiness.h"
#include <stdio.h>
#include <string.h>

/* popcount for uint64_t */
static size_t popcount64(uint64_t x) {
    size_t count = 0;
    while (x) { count += x & 1; x >>= 1; }
    return count;
}

void readiness_init(readiness_tracker_t *rt, uint32_t factory_id,
                    size_t n_clients, persist_t *db) {
    if (!rt) return;
    memset(rt, 0, sizeof(*rt));
    rt->factory_id = factory_id;
    rt->n_clients = (n_clients > FACTORY_MAX_SIGNERS) ?
                    FACTORY_MAX_SIGNERS : n_clients;
    rt->db = db;
    for (size_t i = 0; i < rt->n_clients; i++)
        rt->clients[i].client_idx = (uint32_t)i;
}

void readiness_set_connected(readiness_tracker_t *rt, uint32_t client_idx,
                             int connected) {
    if (!rt || client_idx >= rt->n_clients) return;
    rt->clients[client_idx].is_connected = connected;
    if (connected) {
        rt->connected_bitmap |= (1ULL << client_idx);
        rt->clients[client_idx].last_seen = time(NULL);
    } else {
        rt->connected_bitmap &= ~(1ULL << client_idx);
        /* Disconnecting also clears ready */
        rt->clients[client_idx].is_ready = 0;
        rt->clients[client_idx].ready_for = 0;
        rt->ready_bitmap &= ~(1ULL << client_idx);
    }
}

void readiness_set_ready(readiness_tracker_t *rt, uint32_t client_idx,
                         int ready_for) {
    if (!rt || client_idx >= rt->n_clients) return;
    /* Must be connected to be ready */
    if (!rt->clients[client_idx].is_connected) return;
    rt->clients[client_idx].is_ready = 1;
    rt->clients[client_idx].ready_for = ready_for;
    rt->clients[client_idx].last_seen = time(NULL);
    rt->ready_bitmap |= (1ULL << client_idx);
}

void readiness_clear(readiness_tracker_t *rt, uint32_t client_idx) {
    if (!rt || client_idx >= rt->n_clients) return;
    rt->clients[client_idx].is_connected = 0;
    rt->clients[client_idx].is_ready = 0;
    rt->clients[client_idx].ready_for = 0;
    rt->connected_bitmap &= ~(1ULL << client_idx);
    rt->ready_bitmap &= ~(1ULL << client_idx);
}

void readiness_touch(readiness_tracker_t *rt, uint32_t client_idx) {
    if (!rt || client_idx >= rt->n_clients) return;
    rt->clients[client_idx].last_seen = time(NULL);
}

int readiness_all_ready(const readiness_tracker_t *rt) {
    if (!rt || rt->n_clients == 0) return 0;
    uint64_t full_mask = (rt->n_clients >= 64) ?
                         0xFFFFFFFFFFFFFFFFULL : ((1ULL << rt->n_clients) - 1);
    return (rt->ready_bitmap & full_mask) == full_mask;
}

size_t readiness_count_ready(const readiness_tracker_t *rt) {
    if (!rt) return 0;
    return popcount64(rt->ready_bitmap);
}

size_t readiness_count_connected(const readiness_tracker_t *rt) {
    if (!rt) return 0;
    return popcount64(rt->connected_bitmap);
}

size_t readiness_get_missing(const readiness_tracker_t *rt,
                             uint32_t *out, size_t max) {
    if (!rt || !out || max == 0) return 0;
    size_t count = 0;
    for (uint32_t i = 0; i < rt->n_clients && count < max; i++) {
        if (!(rt->ready_bitmap & (1ULL << i)))
            out[count++] = i;
    }
    return count;
}

int readiness_compute_urgency(uint32_t blocks_left, uint32_t dying_blocks) {
    if (dying_blocks == 0) return QUEUE_URGENCY_CRITICAL;
    if (blocks_left > dying_blocks)    return QUEUE_URGENCY_LOW;
    if (blocks_left > dying_blocks / 2) return QUEUE_URGENCY_NORMAL;
    if (blocks_left > dying_blocks / 4) return QUEUE_URGENCY_HIGH;
    return QUEUE_URGENCY_CRITICAL;
}

int readiness_save(const readiness_tracker_t *rt) {
    if (!rt || !rt->db || !rt->db->db) return 0;
    const char *sql =
        "INSERT OR REPLACE INTO client_readiness "
        "(client_idx, factory_id, is_connected, is_ready, last_seen, ready_for) "
        "VALUES (?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(rt->db->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;
    for (size_t i = 0; i < rt->n_clients; i++) {
        const readiness_entry_t *e = &rt->clients[i];
        sqlite3_reset(stmt);
        sqlite3_bind_int(stmt, 1, (int)e->client_idx);
        sqlite3_bind_int(stmt, 2, (int)rt->factory_id);
        sqlite3_bind_int(stmt, 3, e->is_connected);
        sqlite3_bind_int(stmt, 4, e->is_ready);
        sqlite3_bind_int64(stmt, 5, (sqlite3_int64)e->last_seen);
        sqlite3_bind_int(stmt, 6, e->ready_for);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            return 0;
        }
    }
    sqlite3_finalize(stmt);
    return 1;
}

int readiness_load(readiness_tracker_t *rt) {
    if (!rt || !rt->db || !rt->db->db) return 0;
    const char *sql =
        "SELECT client_idx, is_connected, is_ready, last_seen, ready_for "
        "FROM client_readiness WHERE factory_id = ?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(rt->db->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int(stmt, 1, (int)rt->factory_id);
    /* Clear bitmaps before loading */
    rt->ready_bitmap = 0;
    rt->connected_bitmap = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        uint32_t idx = (uint32_t)sqlite3_column_int(stmt, 0);
        if (idx >= rt->n_clients) continue;
        readiness_entry_t *e = &rt->clients[idx];
        e->is_connected = sqlite3_column_int(stmt, 1);
        e->is_ready = sqlite3_column_int(stmt, 2);
        e->last_seen = (time_t)sqlite3_column_int64(stmt, 3);
        e->ready_for = sqlite3_column_int(stmt, 4);
        if (e->is_connected)
            rt->connected_bitmap |= (1ULL << idx);
        if (e->is_ready)
            rt->ready_bitmap |= (1ULL << idx);
    }
    sqlite3_finalize(stmt);
    return 1;
}

void readiness_reset(readiness_tracker_t *rt) {
    if (!rt) return;
    for (size_t i = 0; i < rt->n_clients; i++) {
        rt->clients[i].is_connected = 0;
        rt->clients[i].is_ready = 0;
        rt->clients[i].ready_for = 0;
        rt->clients[i].last_seen = 0;
    }
    rt->ready_bitmap = 0;
    rt->connected_bitmap = 0;
}
