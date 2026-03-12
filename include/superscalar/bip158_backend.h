#ifndef SUPERSCALAR_BIP158_BACKEND_H
#define SUPERSCALAR_BIP158_BACKEND_H

#include "chain_backend.h"

/*
 * BIP 157/158 compact block filter light client backend.
 *
 * Replaces bitcoin-cli TXID polling with compact block filter queries:
 *   - Downloads one compact filter (~10 KB) per new block from a BIP 157 peer
 *   - Checks all registered scriptPubKeys against the filter in O(n) lookups
 *   - Only downloads full blocks (~1-2 MB) on a filter match
 *   - Skips the vast majority of blocks cheaply
 *
 * Script registration is required before the first watchtower_check() call.
 * The watchtower registers scripts automatically when entries are added
 * (see watchtower_watch, watchtower_watch_factory_node, etc.).
 *
 * SuperScalar script load profile:
 *   - Steady state (1 active factory epoch):   ~80 scriptPubKeys
 *   - During factory rotation (2 epochs):      ~160 scriptPubKeys
 *   - With watchtower history (open channels): 100-300 scriptPubKeys typical
 *
 * Status: not yet implemented — peer connection and GCS filter decoding
 * are pending. See issue #11: https://github.com/8144225309/SuperScalar/issues/11
 */

typedef struct {
    chain_backend_t base;  /* Must be first — cast-compatible with chain_backend_t */

    /* TODO: peer connection state (BIP 157 P2P) */
    /* TODO: compact filter cache (filter per block height) */
    /* TODO: script registry (watched scriptPubKeys + their match state) */
    /* TODO: confirmed tx cache (txid -> block height, populated on filter match) */

} bip158_backend_t;

/*
 * Initialise the BIP 158 backend.
 * network: "mainnet", "signet", "testnet"
 * Returns 1 on success, 0 on failure.
 *
 * NOTE: Not yet implemented — returns 0.
 */
int  bip158_backend_init(bip158_backend_t *backend, const char *network);
void bip158_backend_free(bip158_backend_t *backend);

#endif /* SUPERSCALAR_BIP158_BACKEND_H */
