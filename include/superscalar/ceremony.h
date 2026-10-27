#ifndef SUPERSCALAR_CEREMONY_H
#define SUPERSCALAR_CEREMONY_H

#include "factory.h"
#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef enum {
    CEREMONY_INIT,
    CEREMONY_COLLECTING_NONCES,
    CEREMONY_DISTRIBUTING_NONCES,
    CEREMONY_COLLECTING_PSIGS,
    CEREMONY_FINALIZING,
    CEREMONY_DONE,
    CEREMONY_ABORTED,
} ceremony_state_t;

typedef enum {
    CLIENT_WAITING,
    CLIENT_NONCE_RECEIVED,
    CLIENT_PSIG_RECEIVED,
    CLIENT_TIMED_OUT,
    CLIENT_ERROR,
} client_ceremony_state_t;

/* Ceremonies with <= this many clients use the inline buffer: no heap, safe on
   an uninitialized stack ceremony_t, and nothing to free.  Unit tests all sit
   below it; real ceremonies take the heap path. */
#define CEREMONY_SMALL 8

typedef struct {
    ceremony_state_t state;
    /* Points at clients_small or heap.  SELF-REFERENTIAL in the small case, so a
       ceremony_t must never be copied by value.
       Was client_ceremony_state_t[FACTORY_MAX_SIGNERS].  The fixed array was an
       overread waiting to happen: ceremony_init clamped only the WRITE loop
       (`i < n_clients && i < FACTORY_MAX_SIGNERS`) while setting n_clients to the
       untruncated count, so every later query -- ceremony_count_in_state,
       ceremony_has_quorum, ceremony_get_active_clients -- loops to n_clients and
       reads past the end once n_clients > 256.  Clamping the write made it look
       guarded while leaving the reads unbounded. */
    client_ceremony_state_t *clients;
    size_t clients_cap;
    client_ceremony_state_t clients_small[CEREMONY_SMALL];
    size_t n_clients;
    int per_client_timeout_sec;  /* per-client response deadline (seconds) */
    int min_clients;             /* minimum for viable factory (default: 2) */
} ceremony_t;

/* Initialize ceremony for n_clients.  1 on success, 0 if the per-client array
   could not be allocated (ceremony left valid but empty, so every accessor is
   still safe).  Was void; ignoring the result still compiles.
   TREATS *c AS UNINITIALIZED -- callers pass stack ceremony_t.  Call
   ceremony_free() before re-initializing an existing one. */
int ceremony_init(ceremony_t *c, size_t n_clients,
                  int per_client_timeout_sec, int min_clients);

/* Release the per-client array.  Safe on a zeroed ceremony, safe twice, no-op
   for ceremonies that fit the inline buffer. */
void ceremony_free(ceremony_t *c);

/* Parallel select: wait for any of the given fds to become readable.
   client_fds[n_clients], timeout in seconds.
   On return, ready[i] = 1 if client_fds[i] is readable.
   Returns number of ready fds (0 on timeout, -1 on error). */
int ceremony_select_all(const int *client_fds, size_t n_clients,
                        int timeout_sec, int *ready_out);

/* Count clients in a given state. */
size_t ceremony_count_in_state(const ceremony_t *c, client_ceremony_state_t state);

/* Check if enough clients responded for a viable factory. */
int ceremony_has_quorum(const ceremony_t *c);

/* Get array of active (non-timed-out, non-error) client indices.
   Returns count written. active_out must hold at least n_clients entries. */
size_t ceremony_get_active_clients(const ceremony_t *c,
                                   size_t *active_out, size_t max_out);

/* Prepare ceremony for retry: reset states for active clients to WAITING,
   keep timed-out/error clients excluded. Returns new active count. */
size_t ceremony_prepare_retry(ceremony_t *c);

/* Check if factory creation should proceed given available funds.
   Returns 1 if sufficient, 0 if insufficient. */
int ceremony_check_funding_reserve(uint64_t available_sats,
                                   uint64_t factory_amount_sats,
                                   uint64_t fee_reserve_sats);

#endif /* SUPERSCALAR_CEREMONY_H */
