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

typedef struct {
    ceremony_state_t state;
    client_ceremony_state_t clients[FACTORY_MAX_SIGNERS];
    size_t n_clients;
    int per_client_timeout_sec;  /* per-client response deadline (seconds) */
    int min_clients;             /* minimum for viable factory (default: 2) */
} ceremony_t;

/* Initialize ceremony for n_clients with given timeout and minimum. */
void ceremony_init(ceremony_t *c, size_t n_clients,
                   int per_client_timeout_sec, int min_clients);

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
