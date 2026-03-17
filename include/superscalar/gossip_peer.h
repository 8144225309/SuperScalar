/*
 * gossip_peer.h — Outbound gossip peer connection manager
 *
 * Implements:
 *   - TCP→BOLT#8→init→timestamp_filter→recv→store pipeline
 *   - Exponential reconnect backoff with ±500ms jitter (CLN production values)
 *   - Two-tier timestamp_filter strategy (LDK: 2-week for bootstrap, 1-hour after)
 *
 * Extended in PR #19 commits 3/4 to add:
 *   - Rejection LRU cache (1024 entries)
 *   - WaitingProofStore for channel_announcement 4-sig buffering
 *   - Per-channel token-bucket rate limiting (LND: 10 burst / 60s)
 *   - 5-minute new-peer embargo (Eclair)
 *   - Peer prioritization (important vs transient)
 */

#ifndef SUPERSCALAR_GOSSIP_PEER_H
#define SUPERSCALAR_GOSSIP_PEER_H

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include <secp256k1.h>
#include "superscalar/gossip_store.h"

/* -----------------------------------------------------------------------
 * Config constants
 * --------------------------------------------------------------------- */
#define GOSSIP_PEER_MAX              8
#define GOSSIP_RECONNECT_INIT_MS  1000   /* CLN: start at 1s */
#define GOSSIP_RECONNECT_MAX_MS 300000   /* CLN: cap at 300s */
#define GOSSIP_BOOTSTRAP_PEER_COUNT  5   /* LDK: first 5 get 2-week filter */
#define GOSSIP_TRANSIENT_MAX_RETRIES 5   /* transient peers give up after 5 failures */
#define GOSSIP_EMBARGO_SECS        300   /* Eclair: ignore gossip for 5min from new peers */

/* -----------------------------------------------------------------------
 * Per-peer config
 * --------------------------------------------------------------------- */
typedef struct {
    char     host[256];
    uint16_t port;
    unsigned char their_pub33[33];  /* 0 = unknown, skip BOLT #8 auth check */
    int      important;             /* 1 = has channel, protect from eviction */
} gossip_peer_cfg_t;

/* -----------------------------------------------------------------------
 * Manager config (passed to each peer thread)
 * --------------------------------------------------------------------- */
typedef struct {
    gossip_peer_cfg_t peers[GOSSIP_PEER_MAX];
    int               n_peers;
    secp256k1_context *ctx;
    unsigned char     our_priv32[32];
    gossip_store_t    *store;
    const char        *network;      /* "bitcoin","signet","testnet","regtest" */
    volatile int      *shutdown_flag;
} gossip_peer_mgr_cfg_t;

/* -----------------------------------------------------------------------
 * Rejection LRU cache (added Commit 3)
 * --------------------------------------------------------------------- */
#define GOSSIP_REJECT_CACHE_SIZE  1024

typedef struct {
    uint64_t scid;
    uint32_t evict_clock;
} gossip_reject_entry_t;

typedef struct {
    gossip_reject_entry_t entries[GOSSIP_REJECT_CACHE_SIZE];
    int      count;
    uint32_t clock;
} gossip_reject_cache_t;

int  gossip_reject_cache_contains(gossip_reject_cache_t *c, uint64_t scid);
void gossip_reject_cache_add(gossip_reject_cache_t *c, uint64_t scid);

/* -----------------------------------------------------------------------
 * WaitingProofStore (added Commit 3)
 * --------------------------------------------------------------------- */
#define GOSSIP_WAITING_PROOF_MAX  256

typedef struct {
    unsigned char ann[512];
    size_t        ann_len;
    uint64_t      scid;
    uint32_t      received_at;
    int           has_node1_sig;
    int           has_node2_sig;
} gossip_waiting_proof_t;

typedef struct {
    gossip_waiting_proof_t entries[GOSSIP_WAITING_PROOF_MAX];
    int count;
} gossip_waiting_proof_store_t;

/*
 * Add one channel_announcement (or partial). If all 4 sigs present and valid,
 * calls gossip_store_upsert_channel().
 * Returns:
 *   1 = accepted (4 sigs validated, stored)
 *   2 = buffered (waiting for complementary announcement)
 *   0 = invalid
 */
int gossip_waiting_proof_add(gossip_waiting_proof_store_t *s,
                              gossip_store_t *gs,
                              secp256k1_context *ctx,
                              const unsigned char *ann, size_t ann_len);

/* -----------------------------------------------------------------------
 * Per-channel rate limiting (added Commit 4)
 * --------------------------------------------------------------------- */
#define GOSSIP_UPDATE_BURST        10   /* LND: 10 updates burst */
#define GOSSIP_UPDATE_REFILL_SECS  60   /* LND: refill per minute */

typedef struct {
    uint64_t scid;
    int      direction;
    int      tokens;
    uint32_t last_refill_unix;
} gossip_rate_entry_t;

#define GOSSIP_RATE_TABLE_SIZE  256

typedef struct {
    gossip_rate_entry_t entries[GOSSIP_RATE_TABLE_SIZE];
    int count;
} gossip_rate_table_t;

/*
 * Returns 1 if update is allowed (token consumed), 0 if rate-limited.
 */
int gossip_rate_allow_update(gossip_rate_table_t *rt,
                              uint64_t scid, int direction, uint32_t now_unix);

/* -----------------------------------------------------------------------
 * Timestamp filter strategy
 * --------------------------------------------------------------------- */

/*
 * Returns the first_timestamp to use for gossip_timestamp_filter.
 * Bootstrap peers (index < GOSSIP_BOOTSTRAP_PEER_COUNT) get 2-week history;
 * subsequent peers get 1-hour window (bandwidth saving).
 */
uint32_t gossip_timestamp_for_peer(int peer_index, uint32_t now_unix);

/* -----------------------------------------------------------------------
 * Reconnect backoff
 * --------------------------------------------------------------------- */

/*
 * Returns next backoff delay in ms: doubles current, capped at
 * GOSSIP_RECONNECT_MAX_MS, with ±500ms jitter.
 */
int gossip_next_backoff_ms(int current_ms);

/* -----------------------------------------------------------------------
 * Core functions
 * --------------------------------------------------------------------- */

/*
 * Connect to one gossip peer, exchange init + timestamp_filter, loop
 * reading gossip until disconnected.
 * Returns 1 if graceful, 0 on error.
 */
int gossip_peer_run_once(const gossip_peer_cfg_t *peer,
                          const gossip_peer_mgr_cfg_t *cfg,
                          int peer_index);

/*
 * Background thread: reconnects with exponential backoff + jitter.
 * Runs until cfg->shutdown_flag is set.
 */
void *gossip_peer_thread(void *arg);

/*
 * Parse "HOST:PORT[,HOST:PORT,...]" into cfg array.
 * Returns number of peers parsed.
 */
int gossip_peer_parse_list(const char *list, gossip_peer_cfg_t *out, int max);

/*
 * Returns 1 if peer is important (should reconnect indefinitely).
 */
int gossip_peer_is_important(const gossip_peer_mgr_cfg_t *cfg, int peer_index);

/*
 * Start one pthread per peer. Returns number of threads started.
 */
int gossip_peer_mgr_start(gossip_peer_mgr_cfg_t *cfg, pthread_t *tids_out);

#endif /* SUPERSCALAR_GOSSIP_PEER_H */
