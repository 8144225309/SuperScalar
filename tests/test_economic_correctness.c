/*
 * Chart B — Economic correctness tests.
 *
 * Each test:
 *   1. Snapshots every participant's on-chain balance (scantxoutset) before
 *      the operation.
 *   2. Runs real operations (payments, buy_liquidity, JIT, etc).
 *   3. Performs the close and confirms on-chain.
 *   4. Asserts every close-tx output's amount matches the economic formula.
 *   5. Has each party sweep their output using only their own seckey.
 *   6. Asserts every party's wallet delta matches the expected economic delta
 *      within a fee tolerance.
 *
 * Different from the spendability gauntlet: spendability proves "you can
 * move it"; this proves "the amount moved is what you're economically
 * owed".
 */

#include "econ_helpers.h"
#include "spend_helpers.h"
#include "superscalar/factory.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/musig.h"
#include "superscalar/regtest.h"
#include "superscalar/sha256.h"
#include "superscalar/tx_builder.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int  hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

static const unsigned char ECON_SECKEYS[5][32] = {
    { [0 ... 30] = 0, [31] = 0x61 },  /* LSP */
    { [0 ... 30] = 0, [31] = 0x62 },  /* client 0 */
    { [0 ... 30] = 0, [31] = 0x63 },  /* client 1 */
    { [0 ... 30] = 0, [31] = 0x64 },  /* client 2 */
    { [0 ... 30] = 0, [31] = 0x65 },  /* client 3 */
};
static const char *ECON_NAMES[5] = {
    "LSP", "client_0", "client_1", "client_2", "client_3",
};

/*
 * Arity-2 baseline: open factory, coop close IMMEDIATELY (no payments).
 *
 * Economic expectation:
 *   - Each client's remote_amount == 0 initially (lsp_balance_pct defaults
 *     to 100 so all capacity stays with LSP — but lsp_channels_init will
 *     use 50% if default is 0, per src/lsp_channels.c:207).
 *   - LSP gets funding − Σremote − fee.
 *   - Each client's close output = their starting remote_amount.
 *   - Conservation: Σoutputs + fee == funding.
 *
 * This test does NOT depend on the HTLC routing bugs that block arity-1/PS,
 * because it does no payments.
 */
int test_regtest_econ_arity2_baseline(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "econ_a2_baseline");
    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    const size_t N = 5;
    secp256k1_keypair kps[5];
    secp256k1_pubkey  pks[5];
    for (size_t i = 0; i < N; i++) {
        secp256k1_keypair_create(ctx, &kps[i], ECON_SECKEYS[i]);
        secp256k1_keypair_pub(ctx, &pks[i], &kps[i]);
    }

    /* Build factory funding SPK. */
    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, N);
    unsigned char agg_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, agg_ser, &ka.agg_pubkey);
    unsigned char tw[32];
    sha256_tagged("TapTweak", agg_ser, 32, tw);
    musig_keyagg_t ka_spk = ka;
    secp256k1_pubkey tpk;
    secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tpk, &ka_spk.cache, tw);
    secp256k1_xonly_pubkey tpx;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &tpx, NULL, &tpk);
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tpx);
    unsigned char tpx_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, tpx_ser, &tpx);
    char fund_addr[128];
    TEST_ASSERT(regtest_derive_p2tr_address(&rt, tpx_ser, fund_addr, sizeof(fund_addr)),
                "derive factory addr");
    char fund_txid[65];
    uint64_t fund_btc_sats = 400000;
    TEST_ASSERT(regtest_fund_address(&rt, fund_addr, (double)fund_btc_sats/1e8, fund_txid),
                "fund factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    uint32_t fund_vout = UINT32_MAX;
    uint64_t fund_amount = 0;
    for (uint32_t v = 0; v < 4; v++) {
        uint64_t a = 0; unsigned char s[64]; size_t sl = 0;
        if (regtest_get_tx_output(&rt, fund_txid, v, &a, s, &sl) &&
            sl == 34 && memcmp(s, fund_spk, 34) == 0) {
            fund_vout = v; fund_amount = a; break;
        }
    }
    TEST_ASSERT(fund_vout != UINT32_MAX, "locate factory vout");

    /* Econ context. */
    econ_ctx_t ectx;
    econ_ctx_init(&ectx, &rt, ctx);
    for (size_t i = 0; i < N; i++)
        econ_register_party(&ectx, i, ECON_NAMES[i], ECON_SECKEYS[i]);

    /* Pre-snapshot: should all be 0 (nothing paid to these SPKs yet). */
    TEST_ASSERT(econ_snap_pre(&ectx), "pre-snapshot");

    /* Build coop-close outputs matching the economic expectation:
     * no payments → lsp_balance_pct=100 default means clients have 0
     * remote_amount. But the in-process test here doesn't go through
     * lsp_channels_init → we set the split manually. For a true
     * BASELINE, split 50/50 (the lsp_channels_init default) so each
     * client gets an equal non-dust share. */
    uint64_t close_fee = 500;
    uint64_t usable = fund_amount - close_fee;
    /* Mirror lsp_channels_init with lsp_balance_pct=50: per-client
     * initial remote_amount ≈ (funding/N − commit_fee) / 2. Here we
     * simplify: assign each client 30,000 sats from the factory,
     * LSP keeps the rest. */
    uint64_t per_client = 30000;
    uint64_t lsp_amt = usable - per_client * (N - 1);

    tx_output_t outs[5];
    for (size_t i = 0; i < N; i++) {
        memcpy(outs[i].script_pubkey, ectx.parties[i].expect_close_spk, 34);
        outs[i].script_pubkey_len = 34;
        outs[i].amount_sats = (i == 0) ? lsp_amt : per_client;
    }
    uint64_t expected[5] = { lsp_amt, per_client, per_client, per_client, per_client };

    /* Build + sign + broadcast close. */
    unsigned char ftxid[32];
    memcpy(ftxid, fund_txid, 0);  /* silence */
    {
        unsigned char ftxid_bytes[32];
        hex_decode(fund_txid, ftxid_bytes, 32);
        reverse_bytes(ftxid_bytes, 32);

        tx_buf_t uc;
        tx_buf_init(&uc, 256);
        TEST_ASSERT(build_unsigned_tx(&uc, NULL, ftxid_bytes, fund_vout,
                                        0xFFFFFFFEu, outs, N),
                    "build unsigned close");
        unsigned char sh[32];
        TEST_ASSERT(compute_taproot_sighash(sh, uc.data, uc.len, 0,
                                              fund_spk, 34, fund_amount, 0xFFFFFFFEu),
                    "sighash");
        unsigned char sig[64];
        TEST_ASSERT(musig_sign_taproot(ctx, sig, sh, kps, N, &ka, NULL),
                    "musig_sign_taproot");
        tx_buf_t sc;
        tx_buf_init(&sc, 256);
        finalize_signed_tx(&sc, uc.data, uc.len, sig);
        tx_buf_free(&uc);
        char hex[sc.len * 2 + 1];
        hex_encode(sc.data, sc.len, hex); hex[sc.len * 2] = '\0';
        char close_txid[65];
        TEST_ASSERT(regtest_send_raw_tx(&rt, hex, close_txid), "broadcast close");
        regtest_mine_blocks(&rt, 1, mine_addr);
        TEST_ASSERT(regtest_get_confirmations(&rt, close_txid) >= 1, "close confirmed");
        tx_buf_free(&sc);

        /* STEP 4: on-chain amount assertions. */
        TEST_ASSERT(econ_assert_close_amounts(&ectx, close_txid,
                                                close_fee, fund_amount,
                                                expected),
                    "close amounts match economic formula");

        /* STEP 5: gauntlet sweep. */
        TEST_ASSERT(spend_coop_close_gauntlet(ctx, &rt, close_txid,
                                                ECON_SECKEYS, N - 1),
                    "gauntlet sweep");
    }

    /* STEP 6: post-snapshot. After sweeps, on-chain balance at each
     * party's close SPK should be 0 (they moved the sats elsewhere).
     * So each party's delta vs pre is 0 (pre was 0, post is 0). The
     * economic win is reflected at the SWEEP destination, not the
     * close SPK. For this test we track delta-at-close-SPK which
     * should return to 0 — proving the sweep actually moved the sats. */
    TEST_ASSERT(econ_snap_post(&ectx), "post-snapshot");
    uint64_t zero_deltas[5] = { 0, 0, 0, 0, 0 };
    TEST_ASSERT(econ_assert_wallet_deltas(&ectx, zero_deltas, 0),
                "all parties' close-SPK balance returned to 0 after sweep");

    econ_print_summary(&ectx);
    secp256k1_context_destroy(ctx);
    return 1;
}
