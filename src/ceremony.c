#include "superscalar/ceremony.h"
#include <string.h>
#include <sys/select.h>

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

int ceremony_select_all(const int *client_fds, size_t n_clients,
                        int timeout_sec, int *ready_out) {
    fd_set rfds;
    FD_ZERO(&rfds);
    int maxfd = -1;

    for (size_t i = 0; i < n_clients; i++) {
        if (client_fds[i] < 0) continue;
        FD_SET(client_fds[i], &rfds);
        if (client_fds[i] > maxfd)
            maxfd = client_fds[i];
    }

    if (maxfd < 0) return -1;

    struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };
    int ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
    if (ret <= 0) {
        memset(ready_out, 0, n_clients * sizeof(int));
        return ret;
    }

    int count = 0;
    for (size_t i = 0; i < n_clients; i++) {
        if (client_fds[i] >= 0 && FD_ISSET(client_fds[i], &rfds)) {
            ready_out[i] = 1;
            count++;
        } else {
            ready_out[i] = 0;
        }
    }
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
