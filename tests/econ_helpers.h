#ifndef SUPERSCALAR_TESTS_ECON_HELPERS_H
#define SUPERSCALAR_TESTS_ECON_HELPERS_H

#include "superscalar/regtest.h"
#include <secp256k1.h>
#include <stdint.h>
#include <stddef.h>

/*
 * Economic-correctness harness — verifies that each participant's wallet
 * delta after a close matches the economic model:
 *
 *   LSP_output      = initial_L-stock + Σ(channel.local_amount_post_ops)
 *                                     + accumulated_routing_fees
 *                                     − close_fee
 *   client_i_output = channel_i.remote_amount_post_ops
 *   conservation    = Σ(close_outputs) + close_fee == funding_amount
 *
 * Usage pattern:
 *   econ_ctx_t ctx;
 *   econ_ctx_init(&ctx, rt, n_participants);
 *   econ_register_party(&ctx, 0, "LSP",       lsp_seckey,    addr_hint);
 *   econ_register_party(&ctx, 1, "client_0",  c0_seckey,     addr_hint);
 *   ...
 *   econ_snap_pre(&ctx);
 *   // ... run ops + close ...
 *   econ_snap_post(&ctx);
 *   econ_assert_close_amounts(&ctx, close_txid, expected_amounts[]);
 *   econ_assert_wallet_deltas(&ctx, expected_deltas[]);
 */

#define ECON_MAX_PARTIES 128

typedef struct {
    char     name[32];
    unsigned char seckey[32];        /* party's seckey for sweep derivation */
    unsigned char expect_close_spk[34]; /* P2TR(xonly(pk(seckey))) */
    size_t   expect_close_spk_len;
    uint64_t pre_balance_sats;        /* cached at econ_snap_pre */
    uint64_t post_balance_sats;       /* cached at econ_snap_post */
    uint64_t received_from_close;     /* amount at matching vout in close tx */
    uint64_t expected_close_amount;   /* from economic formula */
    uint64_t expected_delta;          /* expected wallet delta (net of fees) */
} econ_party_t;

typedef struct {
    regtest_t *rt;
    secp256k1_context *ctx;
    size_t    n_parties;
    econ_party_t parties[ECON_MAX_PARTIES];
    uint64_t  factory_funding_amount;
    uint64_t  close_fee;
    char      close_txid[65];
    int       n_outputs_checked;
    int       n_deltas_checked;
} econ_ctx_t;

/* Initialize context bound to a regtest connection and secp context. */
void econ_ctx_init(econ_ctx_t *ctx, regtest_t *rt, secp256k1_context *secp_ctx);

/* Register a participant with their seckey. The helper derives
 * expect_close_spk = P2TR(xonly(pk(seckey))), matching both
 * src/lsp_channels.c close_spk derivation and mgr->lsp_close_spk
 * (from PR #68). */
int econ_register_party(econ_ctx_t *ctx, size_t idx,
                         const char *name,
                         const unsigned char seckey32[32]);

/* Snapshot each party's balance before the test ops run. Balances are
 * computed by scanning regtest's UTXO set for the party's
 * expect_close_spk — this is the on-chain ground truth, not a wallet
 * query. */
int econ_snap_pre(econ_ctx_t *ctx);

/* Snapshot each party's balance after close + sweeps confirmed. */
int econ_snap_post(econ_ctx_t *ctx);

/* Assert each close-tx output's amount matches the expected economic
 * formula. Also asserts Σ(outputs) + close_fee == factory_funding_amount.
 * expected_amounts[i] is the amount party i should receive. Pass 0 if
 * the party is not expected to have an output (e.g., dust-reclaimed).
 * Returns 1 on success.
 */
int econ_assert_close_amounts(econ_ctx_t *ctx,
                               const char *close_txid,
                               uint64_t close_fee,
                               uint64_t factory_funding_amount,
                               const uint64_t *expected_amounts);

/* Assert each party's wallet delta (post − pre) matches
 * expected_delta[i] (which already accounts for the sweep fee the party
 * will pay). Call AFTER all sweeps have been broadcast + confirmed.
 * Returns 1 on success.
 */
int econ_assert_wallet_deltas(econ_ctx_t *ctx,
                               const uint64_t *expected_deltas,
                               int64_t tolerance_sats);

/* Convenience: print a one-shot summary table of all parties with
 * pre, post, expected, delta. */
void econ_print_summary(const econ_ctx_t *ctx);

#endif /* SUPERSCALAR_TESTS_ECON_HELPERS_H */
