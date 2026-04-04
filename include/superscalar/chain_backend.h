#ifndef SUPERSCALAR_CHAIN_BACKEND_H
#define SUPERSCALAR_CHAIN_BACKEND_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Default confirmation depth for mainnet safety. Runtime-configurable
   via chain_backend_t.safe_confirmations or --safe-confs CLI flag.
   LN ecosystem norms: LND defaults to 3, CLN to 1-3, Phoenix to 0.
   6 is the most conservative (original Bitcoin whitepaper).
   On regtest, the code uses 1 regardless of this setting. */
#define MAINNET_SAFE_CONFIRMATIONS 6

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

    /*
     * Batch confirmations for n_txids txids (display-order hex).
     * confs_out[i] = confirmation count (>= 1) if confirmed, -1 if not found.
     * Returns 1 on success. Optional — may be NULL; callers must fall back to
     * repeated get_confirmations if NULL.
     * Implementations should fetch each block only once (O(scan_depth) RPCs).
     */
    int  (*get_confirmations_batch)(chain_backend_t *self,
                                    const char **txids_hex, size_t n_txids,
                                    int *confs_out);

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

    /* Optional reorg notification. When the backend detects a chain
       reorganisation (tip height decrease), it fires this callback.
       Higher layers (watchtower, channel manager) register to re-validate
       cached state. May be NULL (no notification). */
    void (*reorg_cb)(int new_tip, int old_tip, void *reorg_ctx);
    void *reorg_cb_ctx;

    /* Runtime-configurable confirmation depth for safety-critical decisions.
       Defaults to MAINNET_SAFE_CONFIRMATIONS (6). Set via --safe-confs flag.
       On regtest, code uses 1 regardless. Common values:
         0 = turbo/0-conf (trusted LSP, small amounts)
         1 = fast settlement (single conf)
         3 = LND/CLN standard
         6 = maximum safety (Bitcoin whitepaper convention)
       Initialized by chain_backend_regtest_init() or manually. */
    int safe_confirmations;

    /* Backend-specific state. */
    void *ctx;
};

/* Return the effective safe confirmation depth.
   On regtest, always returns 1 (fast testing).
   On other networks, returns backend->safe_confirmations.
   If backend is NULL, returns MAINNET_SAFE_CONFIRMATIONS as fallback. */
static inline int chain_safe_confs(const chain_backend_t *backend, int is_regtest)
{
    if (is_regtest) return 1;
    if (backend && backend->safe_confirmations > 0)
        return backend->safe_confirmations;
    return MAINNET_SAFE_CONFIRMATIONS;
}

/*
 * Regtest (bitcoin-cli RPC) implementation.
 * Defined in src/chain_backend_regtest.c.
 * Callers must also include "regtest.h" for the regtest_t type.
 */
#ifdef SUPERSCALAR_REGTEST_H
void chain_backend_regtest_init(chain_backend_t *backend, regtest_t *rt);
#endif

#endif /* SUPERSCALAR_CHAIN_BACKEND_H */
