#ifndef SUPERSCALAR_LSP_FUND_H
#define SUPERSCALAR_LSP_FUND_H

#include "chain_backend.h"
#include "wallet_source.h"
#include <stdint.h>
#include <stddef.h>

/*
 * lsp_fund.h — chain-mode-agnostic funding and broadcast helpers.
 *
 * Work in both full-node mode (wallet_source_rpc_t + chain_backend_regtest_t)
 * and light-client mode (wallet_source_hd_t + bip158_backend_t).
 */

/*
 * Build, sign, and broadcast a tx paying `amount_sats` to `target_spk`.
 * Uses wallet->get_utxo for coin selection, wallet->get_change_spk for change,
 * wallet->sign_input for signing, chain->send_raw_tx for broadcast.
 * fee_rate_kvb: 0 = default (110 sat/kvB = 0.11 sat/vB).
 * txid_out_65: filled with display-order hex TXID + NUL on success.
 * Returns 1 on success.
 */
int lsp_fund_spk(wallet_source_t *wallet, chain_backend_t *chain,
                 const unsigned char *target_spk, size_t target_spk_len,
                 uint64_t amount_sats, uint64_t fee_rate_kvb,
                 char *txid_out_65);

/*
 * Poll chain backend until txid is confirmed or timeout_secs elapses.
 * Polls every 15 seconds. Returns 1 if confirmed, 0 on timeout.
 */
int lsp_wait_for_confirmation(chain_backend_t *chain, const char *txid_hex,
                               int timeout_secs);

/*
 * Same as lsp_wait_for_confirmation but services the listen socket during the
 * wait so clients can reconnect.  Pass mgr=NULL/lsp=NULL to fall back to the
 * plain sleep-only version.
 */
int lsp_wait_for_confirmation_service(chain_backend_t *chain, const char *txid_hex,
                                       int timeout_secs, void *mgr, void *lsp);

#endif /* SUPERSCALAR_LSP_FUND_H */
