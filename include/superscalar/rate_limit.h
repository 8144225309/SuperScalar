#ifndef SUPERSCALAR_RATE_LIMIT_H
#define SUPERSCALAR_RATE_LIMIT_H

#include <stdint.h>
#include <time.h>

/*
 * Per-IP sliding window rate limiter with concurrent handshake cap.
 *
 * - Tracks connection timestamps per IP (hashed to fixed-size table).
 * - Rejects connections exceeding max_per_window within window_secs.
 * - Rejects new handshakes when active handshakes >= max_handshakes.
 */

#define RATE_LIMIT_BUCKETS 256
#define RATE_LIMIT_RING_SIZE 64  /* max timestamps per bucket */

typedef struct {
    uint32_t ip_hash;
    time_t   timestamps[RATE_LIMIT_RING_SIZE];
    size_t   head;   /* next write position */
    size_t   count;  /* total entries (up to RING_SIZE) */
} rate_limit_bucket_t;

typedef struct {
    rate_limit_bucket_t buckets[RATE_LIMIT_BUCKETS];
    int    max_per_window;   /* max connections per IP per window */
    int    window_secs;      /* sliding window duration */
    int    max_handshakes;   /* max concurrent handshakes */
    int    active_handshakes;
} rate_limiter_t;

/* Initialize rate limiter. */
void rate_limiter_init(rate_limiter_t *rl, int max_per_window,
                       int window_secs, int max_handshakes);

/* Check if a connection from this IP is allowed.
   ip_addr: dotted-quad string (e.g. "192.168.1.1") or any string key.
   Returns 1 if allowed, 0 if rate-limited. */
int rate_limiter_allow(rate_limiter_t *rl, const char *ip_addr);

/* Record start of a handshake. Returns 1 if allowed, 0 if at cap. */
int rate_limiter_handshake_start(rate_limiter_t *rl);

/* Record end of a handshake (success or failure). */
void rate_limiter_handshake_end(rate_limiter_t *rl);

#endif /* SUPERSCALAR_RATE_LIMIT_H */
