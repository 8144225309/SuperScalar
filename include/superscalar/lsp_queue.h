#ifndef SUPERSCALAR_LSP_QUEUE_H
#define SUPERSCALAR_LSP_QUEUE_H

#include "persist.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* --- Request types --- */
#define QUEUE_REQ_ROTATION      1  /* participate in factory rotation */
#define QUEUE_REQ_EPOCH_RESET   2  /* sign epoch reset */
#define QUEUE_REQ_LEAF_ADVANCE  3  /* sign per-leaf DW advance */
#define QUEUE_REQ_DW_PRESIGN    4  /* presign future DW states */
#define QUEUE_REQ_CLOSE         5  /* cooperative close */

/* --- Urgency levels (for notification hooks) --- */
#define QUEUE_URGENCY_LOW       0  /* informational */
#define QUEUE_URGENCY_NORMAL    1  /* action needed within hours */
#define QUEUE_URGENCY_HIGH      2  /* action needed within minutes */
#define QUEUE_URGENCY_CRITICAL  3  /* factory expiry imminent */

/* --- Queue entry --- */
typedef struct {
    uint64_t    id;              /* unique row id */
    uint32_t    client_idx;      /* which client this request is for */
    uint32_t    factory_id;      /* which factory */
    int         request_type;    /* QUEUE_REQ_* */
    int         urgency;         /* QUEUE_URGENCY_* */
    time_t      created_at;      /* when queued */
    time_t      expires_at;      /* deadline (0 = no expiry) */
    char        payload[1024];   /* JSON string with request-specific data */
} queue_entry_t;

#define QUEUE_MAX_PENDING 64

/* --- Queue operations --- */
/* pending_queue table is created by persist_open() in SCHEMA_SQL. */

/* Push a request for a client. Returns 1 on success. */
int queue_push(persist_t *p, uint32_t client_idx, uint32_t factory_id,
               int request_type, int urgency, time_t expires_at,
               const char *payload_json);

/* Drain all pending requests for a client.
   Returns count loaded into entries_out. */
size_t queue_drain(persist_t *p, uint32_t client_idx,
                   queue_entry_t *entries_out, size_t max_entries);

/* Delete a single entry by id (after client processes it). Returns 1 on success. */
int queue_delete(persist_t *p, uint64_t entry_id);

/* Delete all entries for a client. Returns 1 on success. */
int queue_delete_all(persist_t *p, uint32_t client_idx);

/* Delete expired entries. Returns count deleted. */
size_t queue_expire(persist_t *p);

/* Count pending entries for a client. */
size_t queue_count(persist_t *p, uint32_t client_idx);

/* Check if a client has any pending work. */
int queue_has_pending(persist_t *p, uint32_t client_idx);

/* Human-readable name for a request type. */
const char *queue_request_type_name(int request_type);

#endif /* SUPERSCALAR_LSP_QUEUE_H */
