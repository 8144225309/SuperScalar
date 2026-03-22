/*
 * circuit_breaker.c — Per-peer HTLC forwarding limits + channel-type TLV.
 *
 * Reference: lightningequipment/circuitbreaker, CLN peer HTLC quotas,
 *            BOLT #2 PR #880 (channel_type TLV)
 */

#include "superscalar/circuit_breaker.h"
#include <string.h>

/* ---- Helpers ---- */

static void put_be32(unsigned char *b, uint32_t v) {
    b[0] = (unsigned char)(v >> 24);
    b[1] = (unsigned char)(v >> 16);
    b[2] = (unsigned char)(v >>  8);
    b[3] = (unsigned char)(v);
}
static uint32_t get_be32(const unsigned char *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
         | ((uint32_t)b[2] <<  8) |  (uint32_t)b[3];
}

/* ---- Internal helpers ---- */

static circuit_breaker_peer_t *find_peer(circuit_breaker_t *cb,
                                          const unsigned char pubkey[33])
{
    for (int i = 0; i < cb->n_peers; i++) {
        if (cb->peers[i].active &&
            memcmp(cb->peers[i].peer_pubkey, pubkey, 33) == 0)
            return &cb->peers[i];
    }
    return NULL;
}

static circuit_breaker_peer_t *find_or_create_peer(circuit_breaker_t *cb,
                                                     const unsigned char pubkey[33])
{
    circuit_breaker_peer_t *p = find_peer(cb, pubkey);
    if (p) return p;
    if (cb->n_peers >= CIRCUIT_BREAKER_MAX_PEERS) return NULL;
    p = &cb->peers[cb->n_peers++];
    memset(p, 0, sizeof(*p));
    memcpy(p->peer_pubkey, pubkey, 33);
    p->active               = 1;
    p->max_pending_htlcs    = cb->default_max_pending_htlcs;
    p->max_pending_msat     = cb->default_max_pending_msat;
    p->max_htlcs_per_hour   = cb->default_max_htlcs_per_hour;
    p->tokens               = p->max_htlcs_per_hour;
    return p;
}

/* ---- Public API ---- */

void circuit_breaker_init(circuit_breaker_t *cb)
{
    if (!cb) return;
    memset(cb, 0, sizeof(*cb));
    cb->default_max_pending_htlcs  = CIRCUIT_BREAKER_DEFAULT_MAX_PENDING;
    cb->default_max_pending_msat   = CIRCUIT_BREAKER_DEFAULT_MAX_MSAT;
    cb->default_max_htlcs_per_hour = CIRCUIT_BREAKER_DEFAULT_HOURLY_RATE;
}

void circuit_breaker_set_peer_limits(circuit_breaker_t *cb,
                                      const unsigned char peer_pubkey[33],
                                      uint16_t max_pending_htlcs,
                                      uint64_t max_pending_msat,
                                      uint32_t max_htlcs_per_hour)
{
    if (!cb || !peer_pubkey) return;
    circuit_breaker_peer_t *p = find_or_create_peer(cb, peer_pubkey);
    if (!p) return;
    p->max_pending_htlcs  = max_pending_htlcs;
    p->max_pending_msat   = max_pending_msat;
    p->max_htlcs_per_hour = max_htlcs_per_hour;
    if (p->tokens > max_htlcs_per_hour)
        p->tokens = max_htlcs_per_hour;
}

int circuit_breaker_check_add(circuit_breaker_t *cb,
                               const unsigned char peer_pubkey[33],
                               uint64_t amount_msat,
                               uint32_t now_unix)
{
    if (!cb || !peer_pubkey) return 0;

    circuit_breaker_peer_t *p = find_or_create_peer(cb, peer_pubkey);
    if (!p) return 0;

    /* Refill tokens if an hour has passed */
    if (now_unix >= p->last_refill_unix + CIRCUIT_BREAKER_SECS_PER_HOUR) {
        uint32_t periods = (now_unix - p->last_refill_unix)
                           / CIRCUIT_BREAKER_SECS_PER_HOUR;
        uint32_t add = periods * p->max_htlcs_per_hour;
        p->tokens = (add > p->max_htlcs_per_hour - p->tokens)
                    ? p->max_htlcs_per_hour
                    : p->tokens + add;
        p->last_refill_unix += periods * CIRCUIT_BREAKER_SECS_PER_HOUR;
    }

    /* Check pending HTLC count */
    if (p->pending_htlc_count >= p->max_pending_htlcs) return 0;

    /* Check pending amount */
    if (p->max_pending_msat > 0 &&
        p->pending_msat + amount_msat > p->max_pending_msat) return 0;

    /* Check rate limit token; escalate to ban on exhaustion */
    if (p->tokens == 0) {
        if (cb->ban_fn)
            cb->ban_fn(cb->ban_ctx, peer_pubkey, cb->ban_duration_secs);
        return 0;
    }

    /* Accept: consume token and increment counters */
    p->tokens--;
    p->pending_htlc_count++;
    p->pending_msat += amount_msat;
    return 1;
}

void circuit_breaker_record_settled(circuit_breaker_t *cb,
                                     const unsigned char peer_pubkey[33],
                                     uint64_t amount_msat)
{
    if (!cb || !peer_pubkey) return;
    circuit_breaker_peer_t *p = find_peer(cb, peer_pubkey);
    if (!p) return;
    if (p->pending_htlc_count > 0) p->pending_htlc_count--;
    if (p->pending_msat >= amount_msat) p->pending_msat -= amount_msat;
    else p->pending_msat = 0;
}

void circuit_breaker_refill_tokens(circuit_breaker_t *cb, uint32_t now_unix)
{
    if (!cb) return;
    for (int i = 0; i < cb->n_peers; i++) {
        if (!cb->peers[i].active) continue;
        circuit_breaker_peer_t *p = &cb->peers[i];
        if (now_unix >= p->last_refill_unix + CIRCUIT_BREAKER_SECS_PER_HOUR) {
            p->tokens = p->max_htlcs_per_hour;
            p->last_refill_unix = now_unix;
        }
    }
}

int circuit_breaker_get_peer_state(const circuit_breaker_t *cb,
                                    const unsigned char peer_pubkey[33],
                                    uint16_t *pending_htlcs_out,
                                    uint64_t *pending_msat_out)
{
    if (!cb || !peer_pubkey) return 0;
    for (int i = 0; i < cb->n_peers; i++) {
        if (cb->peers[i].active &&
            memcmp(cb->peers[i].peer_pubkey, peer_pubkey, 33) == 0) {
            if (pending_htlcs_out) *pending_htlcs_out = cb->peers[i].pending_htlc_count;
            if (pending_msat_out)  *pending_msat_out  = cb->peers[i].pending_msat;
            return 1;
        }
    }
    return 0;
}

/* ---- Channel-Type TLV ---- */

size_t channel_type_encode(uint32_t feature_bits,
                            unsigned char *buf, size_t buf_cap)
{
    /* type(1) + len(1) + value(4 bytes BE) = 6 bytes */
    if (!buf || buf_cap < 6) return 0;
    buf[0] = (unsigned char)CHAN_TYPE_TLV_TYPE;
    buf[1] = 4;  /* 4 bytes for uint32 feature_bits */
    put_be32(buf + 2, feature_bits);
    return 6;
}

int channel_type_decode(const unsigned char *buf, size_t buf_len,
                         uint32_t *feature_bits_out)
{
    if (!buf || buf_len < 6) return 0;
    if (buf[0] != (unsigned char)CHAN_TYPE_TLV_TYPE) return 0;
    if (buf[1] < 4) return 0;
    if (feature_bits_out) *feature_bits_out = get_be32(buf + 2);
    return 1;
}

uint32_t channel_type_negotiate(uint32_t local_bits, uint32_t remote_bits)
{
    /* Intersection of supported features */
    return local_bits & remote_bits;
}

int update_fee_validate(uint32_t feerate_perkw)
{
    /* BOLT #2: floor=250 sat/kw, ceiling=100000 sat/kw */
    return (feerate_perkw >= 250 && feerate_perkw <= 100000);
}
