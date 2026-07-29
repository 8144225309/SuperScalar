#include "superscalar/ceremony.h"
#include <string.h>
#include <stdlib.h>
#include <poll.h>

void ceremony_init(ceremony_t *c, size_t n_clients,
                   int per_client_timeout_sec, int min_clients) {
    memset(c, 0, sizeof(*c));
    c->state = CEREMONY_INIT;
    c->n_clients = n_clients;
    c->per_client_timeout_sec = per_client_timeout_sec;
    c->min_clients = min_clients > 0 ? min_clients : 2;
    for (size_t i = 0; i < n_clients && i < FACTORY_MAX_SIGNERS; i++)
        c->clients[i] = CLIENT_WAITING;
}

/* poll(), not select().
 *
 * select() is unusable in an LSP that serves many clients, and the reason is
 * NOT the number of watched descriptors -- it is their VALUE.  FD_SET(fd,&set)
 * sets bit `fd` inside a fixed FD_SETSIZE-bit (1024) bitmap, so a single
 * descriptor numbered >= 1024 writes off the end of `fd_set`.  With one socket
 * per client plus the listener, DB handles and log files, an LSP serving ~1000
 * clients hands out descriptors past 1024 and every FD_SET here becomes a stack
 * buffer overflow -- silent corruption, not a clean error, in exactly the way
 * the fixed [FACTORY_MAX_SIGNERS] arrays smashed the stack at N=256.
 *
 * poll() takes an explicit array and cares only about the count, so descriptor
 * values are irrelevant and the array is sized to n_clients at call time.
 *
 * Semantics are preserved exactly:
 *   -1  no usable descriptor in the set (was: maxfd < 0)
 *    0  timeout, ready_out all zero
 *   >0  number ready, ready_out[i] = 1 for each readable client_fds[i]
 * POLLHUP/POLLERR count as ready, matching select(), which reports a hung-up
 * peer as readable so the caller's read() sees EOF and detects the disconnect.
 */
int ceremony_select_all(const int *client_fds, size_t n_clients,
                        int timeout_sec, int *ready_out) {
    if (!client_fds || !ready_out || n_clients == 0) return -1;

    struct pollfd *pfds = (struct pollfd *)calloc(n_clients, sizeof(*pfds));
    size_t *owner = (size_t *)calloc(n_clients, sizeof(*owner)); /* pfd -> client idx */
    if (!pfds || !owner) { free(pfds); free(owner); return -1; }

    nfds_t nfds = 0;
    for (size_t i = 0; i < n_clients; i++) {
        if (client_fds[i] < 0) continue;   /* skipped, as select() did */
        pfds[nfds].fd = client_fds[i];
        pfds[nfds].events = POLLIN;
        owner[nfds] = i;
        nfds++;
    }
    if (nfds == 0) { free(pfds); free(owner); return -1; }

    /* select() with a negative tv_sec returns immediately; keep that. */
    int ms = timeout_sec > 0 ? timeout_sec * 1000 : 0;
    int ret = poll(pfds, nfds, ms);

    memset(ready_out, 0, n_clients * sizeof(int));
    if (ret <= 0) { free(pfds); free(owner); return ret; }

    int count = 0;
    for (nfds_t k = 0; k < nfds; k++) {
        if (pfds[k].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) {
            ready_out[owner[k]] = 1;
            count++;
        }
    }
    free(pfds);
    free(owner);
    return count;
}

size_t ceremony_count_in_state(const ceremony_t *c, client_ceremony_state_t state) {
    size_t count = 0;
    for (size_t i = 0; i < c->n_clients; i++) {
        if (c->clients[i] == state)
            count++;
    }
    return count;
}

int ceremony_has_quorum(const ceremony_t *c) {
    size_t active = 0;
    for (size_t i = 0; i < c->n_clients; i++) {
        if (c->clients[i] != CLIENT_TIMED_OUT && c->clients[i] != CLIENT_ERROR)
            active++;
    }
    return (int)active >= c->min_clients;
}

size_t ceremony_get_active_clients(const ceremony_t *c,
                                   size_t *active_out, size_t max_out) {
    size_t count = 0;
    for (size_t i = 0; i < c->n_clients && count < max_out; i++) {
        if (c->clients[i] != CLIENT_TIMED_OUT && c->clients[i] != CLIENT_ERROR) {
            active_out[count++] = i;
        }
    }
    return count;
}

size_t ceremony_prepare_retry(ceremony_t *c) {
    size_t active = 0;
    for (size_t i = 0; i < c->n_clients; i++) {
        if (c->clients[i] != CLIENT_TIMED_OUT && c->clients[i] != CLIENT_ERROR) {
            c->clients[i] = CLIENT_WAITING;
            active++;
        }
    }
    c->state = CEREMONY_INIT;
    return active;
}

int ceremony_check_funding_reserve(uint64_t available_sats,
                                   uint64_t factory_amount_sats,
                                   uint64_t fee_reserve_sats) {
    return available_sats >= factory_amount_sats + fee_reserve_sats;
}
