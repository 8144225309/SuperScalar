#ifndef SUPERSCALAR_CHAIN_BACKEND_H
#define SUPERSCALAR_CHAIN_BACKEND_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Default confirmation depths per operation type.
   Aligned with LN ecosystem norms (CLN, LND, LDK, Eclair).
   On regtest, all operations use 1 regardless of these settings. */
#define CONF_DEFAULT_FUNDING  3   /* CLN mainnet default; LND scales 1-6 by capacity */
#define CONF_DEFAULT_CLOSE    6   /* LDK ANTI_REORG_DELAY; LND min 3, typically 3-6 */
#define CONF_DEFAULT_PENALTY  6   /* LDK ANTI_REORG_DELAY; safety-critical */
#define CONF_DEFAULT_SWEEP    6   /* LDK ANTI_REORG_DELAY; HTLC timeout sweeps */

/* Legacy alias — kept for any code that references the old constant. */
#define MAINNET_SAFE_CONFIRMATIONS 6

/* Per-operation confirmation depth targets.
   Different operations have different speed/safety tradeoffs:

   funding:  How deep must a funding TX be before acting on it?
             Lower = faster UX, higher reorg risk.
             Factory funding is amplified risk (one reorg kills ALL channels).
             CLN=3, LND=1-6 scaled by capacity, LDK=6, Eclair=8.
             CLI: --funding-confs N

   close:    How deep must a cooperative close TX be before removing
             watchtower entries and considering the channel closed?
             LDK=6, LND=3-6 scaled with min 3.
             CLI: --close-confs N

   penalty:  How deep must a penalty/justice TX be before removing
             the watchtower breach entry? Removing too early means
             a reorg could undo the penalty and the breach goes undetected.
             LDK=6, CLN=100 (irrevocable), LND=spend-based.
             CLI: --penalty-confs N

   sweep:    How deep must an HTLC timeout sweep TX be before
             considering the output fully settled?
             CLI: --sweep-confs N

   Use --safe-confs N to set all four at once. */
typedef struct {
    int funding;
    int close;
    int penalty;
    int sweep;
} conf_targets_t;

/* Initialize conf_targets to ecosystem-aligned defaults. */
static inline void conf_targets_default(conf_targets_t *ct)
{
    ct->funding = CONF_DEFAULT_FUNDING;
    ct->close   = CONF_DEFAULT_CLOSE;
    ct->penalty = CONF_DEFAULT_PENALTY;
    ct->sweep   = CONF_DEFAULT_SWEEP;
}

/* Set all targets to the same value (--safe-confs shorthand). */
static inline void conf_targets_set_all(conf_targets_t *ct, int n)
{
    ct->funding = n;
    ct->close   = n;
    ct->penalty = n;
    ct->sweep   = n;
}

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

    /* Per-operation confirmation depth targets. */
    conf_targets_t conf;

    /* Set to 1 if this backend is running on regtest. Allows code without
       access to regtest_t to branch correctly. Set by init functions. */
    int is_regtest;

    /* Backend-specific state. */
    void *ctx;
};

/* Return the effective confirmation depth for each operation type.
   On regtest, always returns 1 (fast testing).
   On other networks, returns the configured target. */
static inline int chain_funding_confs(const chain_backend_t *b, int is_regtest) {
    if (is_regtest) return 1;
    return (b && b->conf.funding > 0) ? b->conf.funding : CONF_DEFAULT_FUNDING;
}
static inline int chain_close_confs(const chain_backend_t *b, int is_regtest) {
    if (is_regtest) return 1;
    return (b && b->conf.close > 0) ? b->conf.close : CONF_DEFAULT_CLOSE;
}
static inline int chain_penalty_confs(const chain_backend_t *b, int is_regtest) {
    if (is_regtest) return 1;
    return (b && b->conf.penalty > 0) ? b->conf.penalty : CONF_DEFAULT_PENALTY;
}
static inline int chain_sweep_confs(const chain_backend_t *b, int is_regtest) {
    if (is_regtest) return 1;
    return (b && b->conf.sweep > 0) ? b->conf.sweep : CONF_DEFAULT_SWEEP;
}

/* Legacy helper — returns funding confs (backward compat for code using chain_safe_confs). */
static inline int chain_safe_confs(const chain_backend_t *b, int is_regtest) {
    return chain_funding_confs(b, is_regtest);
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
