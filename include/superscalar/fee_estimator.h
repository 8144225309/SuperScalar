#ifndef SUPERSCALAR_FEE_ESTIMATOR_H
#define SUPERSCALAR_FEE_ESTIMATOR_H

#include <stdint.h>
#include <stddef.h>

/*
 * Pluggable fee estimation vtable.
 *
 * All concrete types (static, rpc, blocks, api) embed fee_estimator_t as
 * their first member so that a pointer to any concrete type can be cast
 * directly to fee_estimator_t *.
 *
 * Units: sat/kvB (satoshis per kilo-virtual-byte).  This matches Bitcoin
 * Core's estimatesmartfee and mempool.space "sat/vByte × 1000" convention.
 */

typedef enum {
    FEE_TARGET_URGENT  = 2,    /* breach remedy, HTLC timeout: next 1-2 blocks */
    FEE_TARGET_NORMAL  = 6,    /* channel ops / funding: ~1 hour              */
    FEE_TARGET_ECONOMY = 144,  /* background sweeps: ~1 day                   */
    FEE_TARGET_MINIMUM = 1008, /* mempool floor: informational                */
} fee_target_t;

/* Minimum relayable fee: 100 sat/kvB = 0.1 sat/vB.
   Bitcoin Core won't relay below this with lowered -minrelaytxfee. */
#define FEE_FLOOR_SAT_PER_KVB  100

typedef struct fee_estimator fee_estimator_t;
struct fee_estimator {
    /* Required.  Returns sat/kvB; 0 = unavailable / estimator not ready. */
    uint64_t (*get_rate)(fee_estimator_t *self, fee_target_t target);
    /* Optional.  Refresh cached rates (e.g. re-query RPC, re-fetch URL).
       Implementations that cache internally throttle refreshes themselves. */
    void     (*update)(fee_estimator_t *self);
    /* Optional.  Free heap allocations owned by the impl. */
    void     (*free)(fee_estimator_t *self);
};

/* Returns 1 if P2A anchors should be included at this estimator's URGENT
   rate.  At sub-1-sat/vB the 240-sat anchor costs more than the TX fee
   itself, making CPFP uneconomical.  Pass NULL to default to 1 (use anchor). */
int fee_should_use_anchor(fee_estimator_t *fe);

/* -----------------------------------------------------------------------
 * Static (constant-rate) implementation
 * All targets return the same sat_per_kvb.  update/free are NULL.
 * Stack-allocatable; no heap.
 * --------------------------------------------------------------------- */
typedef struct {
    fee_estimator_t base;      /* MUST be first */
    uint64_t        sat_per_kvb;
} fee_estimator_static_t;

void fee_estimator_static_init(fee_estimator_static_t *fe, uint64_t sat_per_kvb);

/* -----------------------------------------------------------------------
 * RPC (estimatesmartfee) implementation
 * Calls bitcoin-cli estimatesmartfee for each target; caches results for
 * up to 60 seconds.  Stack-allocatable.
 * rt must be a regtest_t *.
 * --------------------------------------------------------------------- */
typedef struct {
    fee_estimator_t base;      /* MUST be first */
    void           *rt;        /* regtest_t * (not owned) */
    uint64_t        cached[4]; /* sat/kvB per target, indexed 0..3 */
    uint64_t        last_updated;
} fee_estimator_rpc_t;

/* cached[] index helpers */
#define FEE_RPC_IDX_URGENT  0
#define FEE_RPC_IDX_NORMAL  1
#define FEE_RPC_IDX_ECONOMY 2
#define FEE_RPC_IDX_MINIMUM 3

void fee_estimator_rpc_init(fee_estimator_rpc_t *fe, void *rt);

/* -----------------------------------------------------------------------
 * Block-derived + feefilter floor implementation
 * Accumulates per-block fee averages from downloaded blocks and uses the
 * BIP 133 feefilter value from the connected peer as a floor.
 * Stack-allocatable.
 * --------------------------------------------------------------------- */
#define FEE_BLOCKS_SAMPLES 32

typedef struct {
    fee_estimator_t base;                     /* MUST be first */
    uint64_t        samples[FEE_BLOCKS_SAMPLES]; /* sat/kvB per downloaded block */
    int             n_samples;
    int             cursor;                   /* next write slot (wraps) */
    uint64_t        feefilter_floor;          /* BIP 133: peer's minimum sat/kvB */
} fee_estimator_blocks_t;

void fee_estimator_blocks_init(fee_estimator_blocks_t *fe);
void fee_estimator_blocks_add_sample(fee_estimator_blocks_t *fe,
                                      uint64_t sat_per_kvb);
void fee_estimator_blocks_set_floor(fee_estimator_blocks_t *fe,
                                     uint64_t floor_sat_per_kvb);

/* -----------------------------------------------------------------------
 * HTTP API (mempool.space / pluggable URL) implementation
 * Fetches {"fastestFee":N,...} JSON; caches for ttl_seconds.
 * --------------------------------------------------------------------- */

/* App-supplied HTTP transport callback.  Returns a malloc-allocated
   NUL-terminated response body, or NULL on failure.  Caller frees. */
typedef char *(*ss_http_get_fn)(const char *url, void *ctx);

/* Built-in simple HTTP GET (POSIX sockets + OpenSSL for https).
   Supports http:// and https://.  Returns malloc'd body or NULL. */
char *ss_http_get_simple(const char *url, void *ctx);

#define FEE_API_URL_MAX 256

typedef struct {
    fee_estimator_t base;             /* MUST be first */
    char            url[FEE_API_URL_MAX];
    ss_http_get_fn  http_get;
    void           *http_ctx;
    uint64_t        cached[4];        /* sat/kvB per target */
    uint64_t        last_updated;
    int             ttl_seconds;      /* default: 60 */
} fee_estimator_api_t;

/* url: NULL → mempool.space default.
   http_get: NULL → built-in ss_http_get_simple. */
void fee_estimator_api_init(fee_estimator_api_t *fe,
                             const char *url,
                             ss_http_get_fn http_get,
                             void *http_ctx);

/* -----------------------------------------------------------------------
 * fee_est_t — lightweight fallback-aware fee estimate cache.
 *
 * Wraps a pluggable fee_estimator_t with a manual fallback and a simple
 * 60-second freshness check. Useful when bitcoind is temporarily
 * unavailable.
 *
 * Units: sat/kvB throughout.
 * --------------------------------------------------------------------- */

typedef struct {
    fee_estimator_t *backend;          /* underlying estimator; may be NULL */
    uint32_t         fallback_rate_sat_kvb;  /* manual fallback (default 1000) */
    uint32_t         cached_rate_sat_kvb;    /* last successful fetch from backend */
    uint64_t         last_update_ts;         /* Unix time of last successful fetch */
} fee_est_t;

/* Initialise with default fallback 1000 sat/kvB and no cached value. */
void fee_est_init(fee_est_t *fe, fee_estimator_t *backend);

/* Set a manual feerate fallback (sat/kvB).
 * Used when bitcoind is unavailable.  Default is 1000 sat/kvB. */
void fee_est_set_fallback(fee_est_t *fe, uint32_t feerate_sat_kvb);

/* Get current feerate estimate (sat/kvB).
 * If last_update_ts was set within the last 60 seconds the cached value is
 * returned; otherwise the fallback is returned. */
uint32_t fee_est_get_feerate(fee_est_t *fe);

/* Store a freshly fetched rate and stamp last_update_ts = now. */
void fee_est_set_cached(fee_est_t *fe, uint32_t feerate_sat_kvb);

/* Force the cache stale so the next call to fee_est_get_feerate() returns
 * the fallback instead of the cached value. */
void fee_est_invalidate(fee_est_t *fe);

#endif /* SUPERSCALAR_FEE_ESTIMATOR_H */
