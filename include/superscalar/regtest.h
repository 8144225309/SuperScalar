#ifndef SUPERSCALAR_REGTEST_H
#define SUPERSCALAR_REGTEST_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "tx_builder.h"

/* bitcoin-cli subprocess harness for regtest. */

typedef struct {
    char cli_path[256];
    char datadir[256];
    char rpcuser[64];
    char rpcpassword[64];
    char wallet[64];
    char network[16];  /* "regtest", "signet", "testnet", "mainnet" */
    int  rpcport;      /* 0 = use network default */
    int  scan_depth;   /* block scan depth for tx lookups (0 = use default) */
} regtest_t;

int   regtest_init(regtest_t *rt);
int   regtest_init_network(regtest_t *rt, const char *network);
int   regtest_init_full(regtest_t *rt, const char *network,
                        const char *cli_path, const char *rpcuser,
                        const char *rpcpassword, const char *datadir,
                        int rpcport);
char *regtest_exec(const regtest_t *rt, const char *method, const char *params);
int   regtest_get_block_height(regtest_t *rt);
int   regtest_create_wallet(regtest_t *rt, const char *name);
int   regtest_get_new_address(regtest_t *rt, char *addr_out, size_t len);
int   regtest_get_address_scriptpubkey(regtest_t *rt, const char *address,
                                        unsigned char *spk_out, size_t *spk_len_out);
int   regtest_mine_blocks(regtest_t *rt, int n, const char *address);
int   regtest_mine_for_balance(regtest_t *rt, double min_btc, const char *address);
int   regtest_fund_address(regtest_t *rt, const char *address, double btc_amount, char *txid_out);
int   regtest_send_raw_tx(regtest_t *rt, const char *tx_hex, char *txid_out);
int   regtest_get_confirmations(regtest_t *rt, const char *txid);
bool  regtest_is_in_mempool(regtest_t *rt, const char *txid);
int   regtest_get_tx_output(regtest_t *rt, const char *txid, uint32_t vout,
                             uint64_t *amount_sats_out,
                             unsigned char *scriptpubkey_out, size_t *spk_len_out);

/* Get raw tx hex by txid. Returns 1 on success. */
int regtest_get_raw_tx(regtest_t *rt, const char *txid,
                         char *tx_hex_out, size_t max_len);

/* Get wallet balance in BTC. Returns -1.0 on error. */
double regtest_get_balance(regtest_t *rt);

/* Shared faucet: call once before running regtest tests.
   Mines 200 blocks into a "faucet" wallet while subsidy is high (~8,750 BTC).
   Safe to call multiple times (no-op after first success). */
int regtest_init_faucet(void);

/* Fund a test wallet from the shared faucet.
   Sends `amount` BTC to a new address in rt's wallet, confirms with 1 block.
   Auto-mines if balance is low. Returns 1 on success, 0 if exhausted. */
int regtest_fund_from_faucet(regtest_t *rt, double amount);

/* Print faucet health: block height, balance, warning if degraded.
   Call after regtest tests to catch exhaustion trends early. */
void regtest_faucet_health_report(void);

/* Poll for tx confirmation. Returns confirmations count, -1 on timeout. */
int regtest_wait_for_confirmation(regtest_t *rt, const char *txid,
                                    int timeout_secs);

/* Find a wallet UTXO suitable for CPFP bump funding.
   Returns 1 on success with UTXO details filled. */
int regtest_get_utxo_for_bump(regtest_t *rt, uint64_t min_amount_sats,
                                char *txid_out, uint32_t *vout_out,
                                uint64_t *amount_out,
                                unsigned char *spk_out, size_t *spk_len_out);

/* Sign a raw tx using the wallet's keys. Returns signed hex (caller frees).
   prevtxs_json: JSON array of prevtx objects for non-wallet inputs, or NULL. */
char *regtest_sign_raw_tx_with_wallet(regtest_t *rt, const char *unsigned_hex,
                                        const char *prevtxs_json);

/* Derive bech32m P2TR address from a tweaked x-only pubkey via bitcoin-cli.
   tweaked_ser32: 32-byte serialized x-only public key (already TapTweaked).
   Returns 1 on success with address written to addr_out. */
int regtest_derive_p2tr_address(const regtest_t *rt,
                                const unsigned char *tweaked_ser32,
                                char *addr_out, size_t addr_len);

/* --- RBF fee bumping (Mainnet Gap #2) --- */

/* Bump fee on an unconfirmed wallet TX via bitcoin-cli bumpfee.
   Returns 1 on success, 0 on error (e.g., already confirmed). */
int regtest_bump_fee(regtest_t *rt, const char *txid_hex,
                      uint64_t new_fee_rate_sat_vb);

/* Wait for confirmation with auto fee-bumping.
   If not confirmed after target_blocks blocks, bumps fee (rate *= multiplier).
   Repeats up to max_bumps times. Returns confirmations or -1 on timeout. */
int regtest_wait_confirmed_with_bump(regtest_t *rt, const char *txid_hex,
                                      int target_blocks, int max_bumps,
                                      uint64_t initial_fee_rate,
                                      double fee_multiplier,
                                      int timeout_secs);

/* --- UTXO coin selection (Mainnet Gap #1) --- */

typedef struct {
    char txid[65];
    int vout;
    uint64_t amount_sats;
} utxo_t;

/* List confirmed wallet UTXOs. Caller frees *utxos_out. */
int regtest_list_utxos(regtest_t *rt, utxo_t **utxos_out, size_t *n_out);

/* Select UTXOs to cover target_sats + fees. Largest-first heuristic.
   Change below dust is absorbed into fee. Caller frees *selected_out. */
int regtest_coin_select(const utxo_t *utxos, size_t n_utxos,
                        uint64_t target_sats, uint64_t fee_rate_sat_vb,
                        utxo_t **selected_out, size_t *n_selected,
                        uint64_t *change_sats);

/* Create, sign, and broadcast a funded TX with coin selection.
   Replaces manual UTXO management. Returns 1 on success. */
int regtest_create_funded_tx(regtest_t *rt, const tx_output_t *outputs,
                              size_t n_outputs, uint64_t fee_rate,
                              char *txid_hex_out, char *signed_hex_out,
                              size_t hex_max);

#endif /* SUPERSCALAR_REGTEST_H */
