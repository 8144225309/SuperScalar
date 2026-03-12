#ifndef SUPERSCALAR_BIP158_BACKEND_H
#define SUPERSCALAR_BIP158_BACKEND_H

#include "chain_backend.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * BIP 157/158 compact block filter light client backend.
 *
 * Replaces bitcoin-cli TXID polling with compact block filter queries:
 *   - Downloads one compact filter (~10 KB) per new block from a BIP 157 peer
 *   - Checks all registered scriptPubKeys against the GCS filter
 *   - Only downloads the full block (~1-2 MB) on a filter match
 *   - Skips the vast majority of blocks with no relevant scripts
 *
 * Usage:
 *   1. bip158_backend_init(&backend, "mainnet")
 *   2. watchtower_set_chain_backend(&wt, &backend.base)
 *   3. Call backend.base.register_script() for each watched scriptPubKey
 *      (watchtower_watch / watchtower_watch_factory_node do this automatically)
 *   4. watchtower_check() drives the scan loop
 *
 * SuperScalar script load profile:
 *   - Steady state (1 active factory epoch):   ~80 scriptPubKeys
 *   - During factory rotation (2 epochs):      ~160 scriptPubKeys
 *   - With watchtower history (open channels): 100-300 scriptPubKeys typical
 */

/* GCS parameters for BIP 158 basic filter (type 0) */
#define BIP158_P  19           /* Golomb-Rice parameter                */
#define BIP158_M  784931ULL    /* False-positive rate denominator (1/M) */

/* Capacity limits */
#define BIP158_MAX_SCRIPTS     512   /* watched scriptPubKeys             */
#define BIP158_TX_CACHE_SIZE   256   /* confirmed tx entries              */
#define BIP158_FILTER_CACHE    16    /* cached filters (ring buffer)      */

typedef struct {
    unsigned char spk[34];
    size_t        spk_len;
} bip158_script_t;

typedef struct {
    unsigned char txid[32];  /* internal byte order */
    int32_t       height;
} bip158_tx_entry_t;

typedef struct {
    uint32_t      height;
    unsigned char key[16];   /* SipHash key = first 16 bytes of block hash */
    unsigned char *data;     /* raw GCS bytes (heap-allocated)              */
    size_t         data_len;
    uint64_t       n_items;  /* number of elements in this filter           */
} bip158_filter_t;

typedef struct {
    chain_backend_t  base;   /* Must be first — cast-compatible              */

    /* Script registry */
    bip158_script_t  scripts[BIP158_MAX_SCRIPTS];
    size_t           n_scripts;

    /* Confirmed tx cache: populated when a filter match triggers a full-block
       download and the committing tx is found inside */
    bip158_tx_entry_t tx_cache[BIP158_TX_CACHE_SIZE];
    size_t            n_tx_cache;

    /* Filter ring buffer (most-recently-seen blocks) */
    bip158_filter_t  filters[BIP158_FILTER_CACHE];
    size_t           filter_head;  /* next write slot */

    /* Chain tip (updated on each successful filter download) */
    int32_t          tip_height;

    /* Network ("mainnet", "signet", "testnet") */
    char             network[16];

    /* RPC context for Phase 3 scan loop (regtest_t *); NULL when using P2P */
    void            *rpc_ctx;

    /* TODO: P2P peer connection state */
} bip158_backend_t;

/* Initialise backend. Returns 1 on success, 0 on failure. */
int  bip158_backend_init(bip158_backend_t *backend, const char *network);
void bip158_backend_free(bip158_backend_t *backend);

/*
 * Attach a regtest_t RPC handle for the Phase-3 scan loop.
 * Must be called before bip158_backend_scan() when not using a P2P peer.
 * rt is typed void* to avoid pulling regtest.h into this header.
 */
void bip158_backend_set_rpc(bip158_backend_t *backend, void *rt);

/*
 * Walk blocks from last synced height + 1 up to the current chain tip.
 * For each new block:
 *   1. Fetch its compact filter via regtest RPC (getblockfilter).
 *   2. Run the GCS filter against all registered scriptPubKeys.
 *   3. On a match, fetch the full block (getblock verbosity 2) and cache
 *      every tx whose outputs include a watched script.
 * Updates backend->tip_height on success.
 * Returns the number of matched blocks (may include false positives),
 * or -1 on hard error (RPC unavailable, no rpc_ctx attached).
 */
int bip158_backend_scan(bip158_backend_t *backend);

/*
 * Low-level GCS helpers — exposed for unit testing.
 *
 * bip158_gcs_match_any: check whether any of the n_scripts watched scripts
 * appear in a serialised GCS filter.
 *   filter_data / filter_len : raw bytes after the leading N varint
 *   n_items                  : N decoded from that varint
 *   key16                    : 16-byte SipHash key (first 16 bytes of block hash)
 * Returns 1 if at least one script matches (or false-positive), 0 if none.
 */
int bip158_gcs_match_any(const unsigned char *filter_data, size_t filter_len,
                          uint64_t n_items,
                          const unsigned char *key16,
                          const bip158_script_t *scripts, size_t n_scripts);

/*
 * Store a confirmed tx in the backend's cache so get_confirmations() can
 * return meaningful results after a filter match drives a full-block download.
 */
void bip158_cache_tx(bip158_backend_t *backend,
                     const unsigned char *txid32, int32_t height);

/*
 * Scan a full serialised BIP 158 filter (including leading N varint) against
 * the backend's script registry. Returns 1 on any match, 0 if none.
 * key16: first 16 bytes of the block hash (SipHash key).
 * Called internally by the scan loop once per new block.
 */
int bip158_scan_filter(bip158_backend_t *backend,
                        const unsigned char *filter_bytes, size_t filter_len,
                        const unsigned char *key16);

#endif /* SUPERSCALAR_BIP158_BACKEND_H */
