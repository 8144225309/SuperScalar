#include "superscalar/rate_limit.h"
#include <string.h>

void rate_limiter_init(rate_limiter_t *rl, int max_per_window,
                       int window_secs, int max_handshakes) {
    memset(rl, 0, sizeof(*rl));
    rl->max_per_window = max_per_window > 0 ? max_per_window : 10;
    rl->window_secs = window_secs > 0 ? window_secs : 60;
    rl->max_handshakes = max_handshakes > 0 ? max_handshakes : 4;
    rl->active_handshakes = 0;
}

/* Simple hash of IP string to bucket index. */
static uint32_t hash_ip(const char *ip) {
    uint32_t h = 5381;
    for (const char *p = ip; *p; p++)
        h = ((h << 5) + h) ^ (uint32_t)(unsigned char)*p;
    return h;
}

int rate_limiter_allow(rate_limiter_t *rl, const char *ip_addr) {
    if (!rl || !ip_addr) return 0;

    uint32_t h = hash_ip(ip_addr);
    size_t idx = h % RATE_LIMIT_BUCKETS;
    rate_limit_bucket_t *b = &rl->buckets[idx];

    time_t now = time(NULL);
    time_t cutoff = now - rl->window_secs;

    /* If bucket is for a different IP (collision), reset it */
    if (b->count > 0 && b->ip_hash != h) {
        b->count = 0;
        b->head = 0;
    }
    b->ip_hash = h;

    /* Count recent timestamps within window */
    int recent = 0;
    for (size_t i = 0; i < b->count && i < RATE_LIMIT_RING_SIZE; i++) {
        if (b->timestamps[i] >= cutoff)
            recent++;
    }

    if (recent >= rl->max_per_window)
        return 0;  /* rate limited */

    /* Record this connection */
    b->timestamps[b->head] = now;
    b->head = (b->head + 1) % RATE_LIMIT_RING_SIZE;
    if (b->count < RATE_LIMIT_RING_SIZE)
        b->count++;

    return 1;
}

int rate_limiter_handshake_start(rate_limiter_t *rl) {
    if (!rl) return 0;
    if (rl->active_handshakes >= rl->max_handshakes)
        return 0;
    rl->active_handshakes++;
    return 1;
}

void rate_limiter_handshake_end(rate_limiter_t *rl) {
    if (!rl) return;
    if (rl->active_handshakes > 0)
        rl->active_handshakes--;
}
