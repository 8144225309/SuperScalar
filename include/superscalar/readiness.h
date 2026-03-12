#ifndef SUPERSCALAR_READINESS_H
#define SUPERSCALAR_READINESS_H

#include "factory.h"
#include "persist.h"
#include "lsp_queue.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

typedef struct {
    uint32_t client_idx;
    int      is_connected;   /* TCP socket alive */
    int      is_ready;       /* acknowledged rotation via MSG_QUEUE_DONE */
    time_t   last_seen;
    int      ready_for;      /* QUEUE_REQ_* type acknowledged */
} readiness_entry_t;

typedef struct {
    readiness_entry_t clients[FACTORY_MAX_SIGNERS];
    size_t   n_clients;
    uint32_t factory_id;
    uint32_t ready_bitmap;      /* bit i = connected AND ready */
    uint32_t connected_bitmap;  /* bit i = connected */
    persist_t *db;              /* may be NULL */
} readiness_tracker_t;

/* Initialize tracker. Zeros all state. db may be NULL. */
void readiness_init(readiness_tracker_t *rt, uint32_t factory_id,
                    size_t n_clients, persist_t *db);

/* Mark client as connected/disconnected. */
void readiness_set_connected(readiness_tracker_t *rt, uint32_t client_idx,
                             int connected);

/* Mark client as ready (must be connected first). */
void readiness_set_ready(readiness_tracker_t *rt, uint32_t client_idx,
                         int ready_for);

/* Clear both connected and ready bits (disconnect). */
void readiness_clear(readiness_tracker_t *rt, uint32_t client_idx);

/* Update last_seen timestamp. */
void readiness_touch(readiness_tracker_t *rt, uint32_t client_idx);

/* True when all n_clients are connected AND ready. */
int readiness_all_ready(const readiness_tracker_t *rt);

/* Count of ready clients (popcount of ready_bitmap). */
size_t readiness_count_ready(const readiness_tracker_t *rt);

/* Count of connected clients (popcount of connected_bitmap). */
size_t readiness_count_connected(const readiness_tracker_t *rt);

/* Fill out[] with indices of clients that are NOT ready. Returns count. */
size_t readiness_get_missing(const readiness_tracker_t *rt,
                             uint32_t *out, size_t max);

/* Map blocks_left / dying_blocks ratio to QUEUE_URGENCY_* level. */
int readiness_compute_urgency(uint32_t blocks_left, uint32_t dying_blocks);

/* Persist current state to SQLite. Returns 1 on success. */
int readiness_save(const readiness_tracker_t *rt);

/* Load state from SQLite. Returns 1 on success. */
int readiness_load(readiness_tracker_t *rt);

/* Reset all state for new rotation cycle. */
void readiness_reset(readiness_tracker_t *rt);

#endif /* SUPERSCALAR_READINESS_H */
