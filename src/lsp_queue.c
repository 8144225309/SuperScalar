#include "superscalar/lsp_queue.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

int queue_push(persist_t *p, uint32_t client_idx, uint32_t factory_id,
               int request_type, int urgency, time_t expires_at,
               const char *payload_json) {
    if (!p || !p->db) return 0;

    const char *sql =
        "INSERT OR REPLACE INTO pending_queue "
        "(client_idx, factory_id, request_type, urgency, created_at, expires_at, payload) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    sqlite3_bind_int(stmt, 1, (int)client_idx);
    sqlite3_bind_int(stmt, 2, (int)factory_id);
    sqlite3_bind_int(stmt, 3, request_type);
    sqlite3_bind_int(stmt, 4, urgency);
    sqlite3_bind_int64(stmt, 5, (int64_t)time(NULL));
    sqlite3_bind_int64(stmt, 6, (int64_t)expires_at);
    if (payload_json)
        sqlite3_bind_text(stmt, 7, payload_json, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(stmt, 7);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 1 : 0;
}

size_t queue_drain(persist_t *p, uint32_t client_idx,
                   queue_entry_t *entries_out, size_t max_entries) {
    if (!p || !p->db || !entries_out || max_entries == 0) return 0;

    const char *sql =
        "SELECT id, client_idx, factory_id, request_type, urgency, "
        "       created_at, expires_at, payload "
        "FROM pending_queue "
        "WHERE client_idx = ? "
        "ORDER BY urgency DESC, created_at ASC";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    sqlite3_bind_int(stmt, 1, (int)client_idx);

    size_t count = 0;
    while (count < max_entries && sqlite3_step(stmt) == SQLITE_ROW) {
        queue_entry_t *e = &entries_out[count];
        memset(e, 0, sizeof(*e));
        e->id = (uint64_t)sqlite3_column_int64(stmt, 0);
        e->client_idx = (uint32_t)sqlite3_column_int(stmt, 1);
        e->factory_id = (uint32_t)sqlite3_column_int(stmt, 2);
        e->request_type = sqlite3_column_int(stmt, 3);
        e->urgency = sqlite3_column_int(stmt, 4);
        e->created_at = (time_t)sqlite3_column_int64(stmt, 5);
        e->expires_at = (time_t)sqlite3_column_int64(stmt, 6);
        const char *payload = (const char *)sqlite3_column_text(stmt, 7);
        if (payload) {
            size_t len = strlen(payload);
            if (len >= sizeof(e->payload)) len = sizeof(e->payload) - 1;
            memcpy(e->payload, payload, len);
            e->payload[len] = '\0';
        }
        count++;
    }
    sqlite3_finalize(stmt);
    return count;
}

int queue_delete(persist_t *p, uint64_t entry_id) {
    if (!p || !p->db) return 0;

    const char *sql = "DELETE FROM pending_queue WHERE id = ?";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    sqlite3_bind_int64(stmt, 1, (int64_t)entry_id);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 1 : 0;
}

int queue_delete_all(persist_t *p, uint32_t client_idx) {
    if (!p || !p->db) return 0;

    const char *sql = "DELETE FROM pending_queue WHERE client_idx = ?";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    sqlite3_bind_int(stmt, 1, (int)client_idx);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 1 : 0;
}

size_t queue_expire(persist_t *p) {
    if (!p || !p->db) return 0;

    const char *sql =
        "DELETE FROM pending_queue WHERE expires_at > 0 AND expires_at < ?";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    sqlite3_bind_int64(stmt, 1, (int64_t)time(NULL));
    rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(p->db);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? (size_t)changes : 0;
}

size_t queue_count(persist_t *p, uint32_t client_idx) {
    if (!p || !p->db) return 0;

    const char *sql =
        "SELECT COUNT(*) FROM pending_queue WHERE client_idx = ?";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    sqlite3_bind_int(stmt, 1, (int)client_idx);
    size_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = (size_t)sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

int queue_has_pending(persist_t *p, uint32_t client_idx) {
    return queue_count(p, client_idx) > 0;
}

const char *queue_request_type_name(int request_type) {
    switch (request_type) {
        case QUEUE_REQ_ROTATION:     return "rotation";
        case QUEUE_REQ_EPOCH_RESET:  return "epoch_reset";
        case QUEUE_REQ_LEAF_ADVANCE: return "leaf_advance";
        case QUEUE_REQ_DW_PRESIGN:   return "dw_presign";
        case QUEUE_REQ_CLOSE:        return "close";
        default:                     return "unknown";
    }
}
