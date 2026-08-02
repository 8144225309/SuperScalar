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

/* Readiness is tracked ONLY in the per-entry booleans below.  There is
 * deliberately no summary bitmap: n_clients can reach FACTORY_MAX_SIGNERS
 * (256), a uint64_t bitmap made every shift for client_idx >= 64 undefined
 * behaviour (x86 shift-wrap aliased bit i to bit i%64, so at 127 clients
 * readiness_all_ready could report true with 63 clients still not ready),
 * and the entries are the source of truth anyway — every query derives
 * from them directly. */
/* Trackers with <= this many clients use the inline buffer: no heap, safe on an
   uninitialized stack tracker, and nothing to free.  The unit tests all run at
   n_clients=4 and so never touch the allocator; real daemons run far above this
   and take the heap path. */
#define READINESS_SMALL 8

typedef struct {
    /* Points at clients_small (n_clients <= READINESS_SMALL) or at heap.
       SELF-REFERENTIAL in the small case, so a readiness_tracker_t must never
       be copied or moved by value -- the copy's pointer would still address the
       original's inline buffer.  (factory_t had exactly this bug.)  Every user
       today holds it by pointer, and ->clients is private to readiness.c. */
    readiness_entry_t *clients;
    size_t   clients_cap;
    readiness_entry_t clients_small[READINESS_SMALL];
    size_t   n_clients;
    uint32_t factory_id;
    persist_t *db;              /* may be NULL */
} readiness_tracker_t;

/* Initialize tracker for n_clients.  db may be NULL.  Returns 1 on success,
   0 if the per-client array could not be allocated (tracker is left valid but
   empty, so every accessor is still safe to call).
   Was void; ignoring the result still compiles.

   TREATS *rt AS UNINITIALIZED MEMORY.  It must not read any pre-existing field,
   because callers legitimately declare a readiness_tracker_t on the stack and
   call this on it first thing (the unit tests do exactly that).  Consequence:
   calling init on a tracker that is ALREADY initialized leaks its heap array --
   call readiness_free() first.  src/lsp_channels.c does this when a rotation
   re-inits the tracker.

   No longer clamps n_clients to FACTORY_MAX_SIGNERS.  The old clamp was a
   silent-corruption bug waiting at scale: above 255 clients the tracker
   quietly forgot the surplus, and readiness_all_ready() would then report
   "all ready" while untracked clients were still missing -- the same class of
   bug as the uint64_t bitmap removed earlier (see the note above). */
int readiness_init(readiness_tracker_t *rt, uint32_t factory_id,
                   size_t n_clients, persist_t *db);

/* Release the per-client array.  Safe on a zeroed tracker, safe to call twice,
   and a no-op for trackers that fit the inline buffer.  Leaves *rt valid and
   empty, so accessors called afterwards return zero/false rather than crash. */
void readiness_free(readiness_tracker_t *rt);

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

/* Count of ready clients. */
size_t readiness_count_ready(const readiness_tracker_t *rt);

/* Count of connected clients. */
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
