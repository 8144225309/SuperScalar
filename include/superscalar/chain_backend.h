#ifndef SUPERSCALAR_CHAIN_BACKEND_H
#define SUPERSCALAR_CHAIN_BACKEND_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * Chain backend abstraction for SuperScalar watchtower.
 *
 * Decouples chain queries and tx broadcast from the bitcoin-cli RPC harness,
 * enabling BIP 157/158 compact block filter light client mode as an
 * alternative to trusted full-node polling.
 *
 * Implementations:
 *   - chain_backend_regtest: wraps regtest_t (existing bitcoin-cli backend)
 *   - chain_backend_bip158:  compact block filter light client (see bip158_backend.h)
 */

typedef struct chain_backend chain_backend_t;

struct chain_backend {
    /* Current chain tip height. Returns -1 on error. */
    int  (*get_block_height)(chain_backend_t *self);

    /*
     * Confirmation depth of a transaction (display-order hex txid).
     * Returns confirmation count (>= 1 if confirmed), 0 if unconfirmed
     * but found in mempool, -1 if not found anywhere.
     */
    int  (*get_confirmations)(chain_backend_t *self, const char *txid_hex);

    /* Returns true if txid is in the mempool. */
    bool (*is_in_mempool)(chain_backend_t *self, const char *txid_hex);

    /*
     * Broadcast a raw transaction. Writes the resulting txid (64 hex chars
     * + NUL) to txid_out if non-NULL. Returns 1 on success, 0 on failure.
     */
    int  (*send_raw_tx)(chain_backend_t *self, const char *tx_hex,
                        char *txid_out);

    /*
     * Register a scriptPubKey for the backend to watch (optional).
     * Required for filter-based backends (BIP 158) — the backend will
     * recognise matches via get_confirmations / is_in_mempool rather than
     * polling per-txid.
     * TXID-polling backends (regtest wrapper) may leave these NULL.
     */
    int  (*register_script)(chain_backend_t *self,
                            const unsigned char *spk, size_t spk_len);
    int  (*unregister_script)(chain_backend_t *self,
                              const unsigned char *spk, size_t spk_len);

    /* Backend-specific state. */
    void *ctx;
};

#endif /* SUPERSCALAR_CHAIN_BACKEND_H */
