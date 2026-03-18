#ifndef SUPERSCALAR_WALLET_SOURCE_H
#define SUPERSCALAR_WALLET_SOURCE_H

#include <stdint.h>
#include <stddef.h>

/*
 * wallet_source_t — vtable for UTXO selection and transaction signing.
 *
 * Abstracts the wallet operations used by watchtower_build_cpfp_tx() so that
 * the watchtower can run without a hard dependency on regtest_t.  The RPC
 * implementation (wallet_source_rpc_t) wraps the existing regtest_* helpers.
 * Mobile / hardware-wallet implementations can provide their own.
 */

typedef struct wallet_source wallet_source_t;
struct wallet_source {
    /*
     * Select a wallet UTXO with value >= min_sats.
     * On success: fills txid_hex (65 chars, display order), *vout, *amount,
     * spk (raw scriptPubKey bytes), *spk_len.
     * Returns 1 on success, 0 if no suitable UTXO found.
     */
    int (*get_utxo)(wallet_source_t *self,
                    uint64_t min_sats,
                    char txid_hex[65],
                    uint32_t *vout,
                    uint64_t *amount,
                    unsigned char *spk,
                    size_t *spk_len);

    /*
     * Obtain a fresh change scriptPubKey from the wallet.
     * spk must be at least 34 bytes.
     * Returns 1 on success, 0 on failure.
     */
    int (*get_change_spk)(wallet_source_t *self,
                          unsigned char *spk,
                          size_t *spk_len);

    /*
     * Sign input input_idx of the serialised unsigned transaction.
     * tx/tx_len: buffer holding the unsigned tx (updated in-place with the
     *            signed version; caller must provide a buffer large enough
     *            for the signed result — typically tx_len + 200 bytes).
     * spk/spk_len: scriptPubKey of the UTXO being signed.
     * amount_sats: value of the UTXO being signed.
     * Returns 1 on success (tx updated), 0 on failure.
     */
    int (*sign_input)(wallet_source_t *self,
                      unsigned char *tx, size_t *tx_len,
                      size_t input_idx,
                      const unsigned char *spk, size_t spk_len,
                      uint64_t amount_sats);

    /*
     * Release a UTXO previously selected by get_utxo.  Implementations
     * should call lockunspent true so the wallet can reuse the coin if the
     * broadcast failed.  Called on every exit path after get_utxo succeeds,
     * whether or not the broadcast succeeded.  May be NULL (e.g. HD wallet).
     */
    void (*release_utxo)(wallet_source_t *self,
                         const char *txid_hex, uint32_t vout);

    /* Optional cleanup.  NULL if no heap allocs. */
    void (*free)(wallet_source_t *self);
};

/* -------------------------------------------------------------------------
 * RPC-backed implementation (wraps regtest_t)
 * ------------------------------------------------------------------------- */

/*
 * wallet_source_rpc_t — stack-allocatable; rt is borrowed (caller owns).
 */
typedef struct {
    wallet_source_t base; /* must be first */
    void           *rt;  /* regtest_t *; void* to avoid pulling regtest.h here */
} wallet_source_rpc_t;

/* rt: regtest_t * (cast to void* to match the field type above) */
void wallet_source_rpc_init(wallet_source_rpc_t *ws, void *rt);

#endif /* SUPERSCALAR_WALLET_SOURCE_H */
