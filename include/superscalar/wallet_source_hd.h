#ifndef SUPERSCALAR_WALLET_SOURCE_HD_H
#define SUPERSCALAR_WALLET_SOURCE_HD_H

#include "wallet_source.h"
#include "persist.h"
#include "bip158_backend.h"
#include <secp256k1.h>
#include <stdint.h>
#include <stddef.h>

/*
 * wallet_source_hd_t — in-process P2TR hot wallet backed by BIP 32 HD keys.
 *
 * Key derivation path: m/86'/coin_type'/0'/index' (all hardened).
 * Spending: Taproot key-path, SIGHASH_ALL|ANYONECANPAY (0x81).
 * UTXO tracking: SQLite hd_utxos table updated by block scanning callbacks.
 *
 * Usage:
 *   1. wallet_source_hd_init(&ws, seed, seed_len, ctx, db, bip158, "mainnet", HD_WALLET_LOOKAHEAD)
 *   2. watchtower_set_wallet(&wt, &ws.base)
 *   3. bip158_backend_set_utxo_cb(&backend, ws.utxo_found_cb, ws.utxo_spent_cb, &ws)
 *   4. Fund at least one address from ws.spks[0..lookahead-1]
 */

#define HD_WALLET_LOOKAHEAD 100  /* number of addresses pre-derived at init */

typedef struct {
    wallet_source_t    base;         /* vtable — must be first */
    secp256k1_context *ctx;          /* secp256k1 SIGN context (not owned) */
    unsigned char      seed[64];     /* BIP 39 seed bytes */
    size_t             seed_len;
    persist_t         *db;           /* UTXO store (not owned) */
    bip158_backend_t  *bip158;       /* for script registration (not owned, may be NULL) */
    uint32_t           next_index;   /* next fresh address index */
    uint32_t           coin_type;    /* 0=mainnet, 1=testnet/regtest/signet */

    /* Pre-derived scriptPubKeys for UTXO scan registration.
     * spks[i] = P2TR SPK for path m/86'/coin_type'/0'/i' */
    unsigned char    (*spks)[34];   /* heap-allocated, size = lookahead */
    uint32_t           n_spks;
    uint32_t           lookahead;   /* number of pre-derived addresses */
} wallet_source_hd_t;

/*
 * Initialise the HD wallet.  Derives the first HD_WALLET_LOOKAHEAD addresses,
 * registers their P2TR scriptPubKeys with the BIP 158 backend (if provided),
 * and loads next_index from the DB.
 *
 * seed/seed_len: 64-byte BIP 39 PBKDF2 output (or any 16-64 byte entropy).
 * ctx: secp256k1 context with SECP256K1_CONTEXT_SIGN capability.
 * db: writable SQLite persist handle; NULL disables UTXO persistence.
 * bip158: optional light-client backend for script registration + block scanning.
 * network: "mainnet", "signet", "testnet3" / "testnet" → coin_type=1, else 0.
 * Returns 1 on success, 0 on failure.
 */
int wallet_source_hd_init(wallet_source_hd_t *ws,
                           const unsigned char *seed, size_t seed_len,
                           secp256k1_context *ctx,
                           persist_t *db,
                           bip158_backend_t *bip158,
                           const char *network,
                           uint32_t lookahead);

/*
 * Derive the P2TR scriptPubKey and tweaked secret key for address index i.
 * Returns 1 on success.
 */
int wallet_source_hd_derive(const wallet_source_hd_t *ws, uint32_t index,
                              unsigned char spk_out[34],
                              unsigned char seckey_out[32]);

/*
 * Get the display-order hex address string (Bech32m) for index i.
 * Fills addr_out (at least 90 bytes).  Returns 1 on success.
 * NOTE: bech32m encoding is provided as a helper for display only.
 */
int wallet_source_hd_get_address(const wallet_source_hd_t *ws, uint32_t index,
                                   char *addr_out, size_t addr_cap);

/*
 * Get total confirmed balance across all HD wallet UTXOs.
 * Queries persist layer for unspent, unreserved UTXOs.
 */
uint64_t wallet_source_hd_get_balance(const wallet_source_hd_t *ws);

/*
 * Extend the pre-derived address cache if next_index is approaching the limit.
 * Called periodically to maintain gap limit coverage. Returns new n_spks.
 */
uint32_t wallet_source_hd_extend_gap(wallet_source_hd_t *ws);

#endif /* SUPERSCALAR_WALLET_SOURCE_HD_H */
