#ifndef SUPERSCALAR_TESTS_SPEND_HELPERS_H
#define SUPERSCALAR_TESTS_SPEND_HELPERS_H

#include "superscalar/tx_builder.h"
#include "superscalar/regtest.h"
#include "superscalar/factory.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

/*
 * Spendability helpers — prove each party can unilaterally sweep their
 * post-close UTXO using only their own seckey. Used by the spendability
 * gauntlet test suite.
 */

/*
 * Find the vout index in raw_tx_hex whose scriptPubKey matches spk (spk_len
 * bytes). Returns vout index on success, -1 if no match, -2 on decode error.
 * amount_out (may be NULL) receives the output's amount in sats on success.
 */
int spend_find_vout_by_spk(regtest_t *rt,
                            const char *txid_hex,
                            const unsigned char *spk, size_t spk_len,
                            uint64_t *amount_out);

/*
 * Build + sign a single-input, single-output spending tx for a P2TR output
 * whose taproot output key == xonly(seckey32) (i.e. NO BIP341 taptweak —
 * the "raw xonly as output key" variant used by lsp_channels.c close_spk
 * and the new mgr->lsp_close_spk).
 *
 * in_txid_hex/in_vout identify the UTXO being spent.
 * in_amount_sats is the UTXO's amount (needed for BIP341 sighash).
 * in_spk/in_spk_len is the input's scriptPubKey (the 34-byte P2TR SPK).
 * dest_spk/dest_spk_len is the output scriptPubKey (e.g. regtest wallet addr).
 * fee_sats is subtracted from in_amount_sats to produce the output amount.
 *
 * tx_out receives the fully-signed raw tx bytes on success.
 * Returns 1 on success, 0 on failure.
 */
int spend_build_p2tr_raw_keypath(secp256k1_context *ctx,
                                  const unsigned char *seckey32,
                                  const char *in_txid_hex,
                                  uint32_t in_vout,
                                  uint64_t in_amount_sats,
                                  const unsigned char *in_spk, size_t in_spk_len,
                                  const unsigned char *dest_spk, size_t dest_spk_len,
                                  uint64_t fee_sats,
                                  tx_buf_t *tx_out);

/*
 * Convenience: broadcast tx_hex via regtest and mine n_blocks to a freshly
 * generated regtest wallet address. Returns 1 if broadcast + confirmation
 * both succeed. txid_out (must be >= 65 bytes) receives the broadcast txid.
 */
int spend_broadcast_and_mine(regtest_t *rt,
                              const char *tx_hex,
                              int n_blocks,
                              char *txid_out);

/*
 * Build + sign a single-input, single-output spending tx for a P2TR output
 * with BIP-341 taptweak applied to the output key (no merkle root — the
 * "key-path-only" variant used by channel to_remote outputs).
 *
 * Same arguments as spend_build_p2tr_raw_keypath, but the signer derives
 * the tweaked seckey before signing:
 *   tweaked_seckey = seckey + H_taptweak(xonly(pubkey))*G
 *
 * Use this for sweeping BIP-341-tweaked outputs (e.g. channel to_remote
 * from src/channel.c:696-714).
 */
int spend_build_p2tr_bip341_keypath(secp256k1_context *ctx,
                                     const unsigned char *seckey32,
                                     const char *in_txid_hex,
                                     uint32_t in_vout,
                                     uint64_t in_amount_sats,
                                     const unsigned char *in_spk, size_t in_spk_len,
                                     const unsigned char *dest_spk, size_t dest_spk_len,
                                     uint64_t fee_sats,
                                     tx_buf_t *tx_out);

/*
 * Re-usable cooperative-close spendability gauntlet. Given a confirmed
 * close tx and the seckeys of all participants (seckeys[0]=LSP,
 * seckeys[1..n_clients]=clients), for each party:
 *   1. Re-derive the expected close_spk from their pubkey.
 *   2. Find the matching vout in the confirmed close tx.
 *   3. Build a sweep using spend_build_p2tr_raw_keypath.
 *   4. Broadcast + mine + confirm.
 *
 * Returns 1 if all n_clients+1 parties successfully sweep, 0 otherwise.
 * Prints per-party progress.
 */
int spend_coop_close_gauntlet(secp256k1_context *ctx,
                               regtest_t *rt,
                               const char *close_txid,
                               const unsigned char seckeys[][32],
                               size_t n_clients);

/*
 * Cooperatively spend an L-stock UTXO via the canonical
 * `or(N-of-N, L&CSV)` SPK's key-path (N-of-N MuSig over leaf signers).
 *
 * Wraps factory_sign_l_stock_cooperative_spend with a call shape
 * matching spend_build_p2tr_bip341_keypath: passes the leaf node and
 * factory (which holds all keypairs in the test process) instead of an
 * LSP seckey.
 *
 * dest_spk is wrapped in a single tx_output_t with amount =
 * (l_stock_amount - fee_sats).
 */
int spend_l_stock_cooperative(secp256k1_context *ctx,
                                factory_t *f,
                                const factory_node_t *leaf_node,
                                const char *l_stock_txid_hex,
                                uint32_t l_stock_vout,
                                uint64_t l_stock_amount,
                                const unsigned char *dest_spk,
                                size_t dest_spk_len,
                                uint64_t fee_sats,
                                tx_buf_t *tx_out);

#endif /* SUPERSCALAR_TESTS_SPEND_HELPERS_H */
