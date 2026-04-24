#include "econ_helpers.h"
#include "superscalar/tx_builder.h"
#include "spend_helpers.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);

void econ_ctx_init(econ_ctx_t *ctx, regtest_t *rt, secp256k1_context *secp_ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->rt = rt;
    ctx->ctx = secp_ctx;
}

int econ_register_party(econ_ctx_t *ctx, size_t idx,
                         const char *name,
                         const unsigned char seckey32[32]) {
    if (!ctx || idx >= ECON_MAX_PARTIES) return 0;
    econ_party_t *p = &ctx->parties[idx];
    strncpy(p->name, name, sizeof(p->name) - 1);
    p->name[sizeof(p->name) - 1] = '\0';
    memcpy(p->seckey, seckey32, 32);

    /* Derive expect_close_spk = P2TR(xonly(pk(seckey))). */
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx->ctx, &kp, seckey32)) return 0;
    secp256k1_xonly_pubkey xo;
    if (!secp256k1_keypair_xonly_pub(ctx->ctx, &xo, NULL, &kp)) return 0;
    build_p2tr_script_pubkey(p->expect_close_spk, &xo);
    p->expect_close_spk_len = 34;

    if (idx + 1 > ctx->n_parties) ctx->n_parties = idx + 1;
    return 1;
}

/* Balance ≙ sum of UTXOs on-chain matching the party's close SPK.
 * The balance after close will include the close output; after a sweep
 * it's whatever the sweep tx produces (typically, sweep to a fresh
 * wallet addr means the party's tracked SPK goes to 0 after sweep — so
 * for accounting purposes we snapshot BEFORE sweep, not after). */
static int balance_at_spk(regtest_t *rt,
                           const unsigned char *spk, size_t spk_len,
                           uint64_t *out_sats) {
    /* Iterate over the wallet's listunspent and sum matches. Since our
       participant SPKs aren't necessarily in the bitcoind wallet, we
       instead scan recent blocks via scantxoutset. The simpler and
       more robust path on regtest is to use the scantxoutset RPC. */
    char spk_hex[69];
    hex_encode(spk, spk_len, spk_hex);
    spk_hex[spk_len * 2] = '\0';

    char params[512];
    snprintf(params, sizeof(params),
             "start '[{\"desc\":\"raw(%s)\"}]'", spk_hex);
    char *result = regtest_exec(rt, "scantxoutset", params);
    if (!result) { *out_sats = 0; return 1; }

    /* Very loose JSON peek at "total_amount" field (float BTC). */
    const char *ta = strstr(result, "\"total_amount\"");
    if (!ta) { free(result); *out_sats = 0; return 1; }
    ta = strchr(ta, ':');
    if (!ta) { free(result); *out_sats = 0; return 1; }
    double btc = 0.0;
    sscanf(ta + 1, " %lf", &btc);
    free(result);
    *out_sats = (uint64_t)(btc * 1e8 + 0.5);
    return 1;
}

int econ_snap_pre(econ_ctx_t *ctx) {
    if (!ctx) return 0;
    for (size_t i = 0; i < ctx->n_parties; i++) {
        econ_party_t *p = &ctx->parties[i];
        if (!balance_at_spk(ctx->rt, p->expect_close_spk, p->expect_close_spk_len,
                             &p->pre_balance_sats)) return 0;
    }
    return 1;
}

int econ_snap_post(econ_ctx_t *ctx) {
    if (!ctx) return 0;
    for (size_t i = 0; i < ctx->n_parties; i++) {
        econ_party_t *p = &ctx->parties[i];
        if (!balance_at_spk(ctx->rt, p->expect_close_spk, p->expect_close_spk_len,
                             &p->post_balance_sats)) return 0;
    }
    return 1;
}

int econ_assert_close_amounts(econ_ctx_t *ctx,
                               const char *close_txid,
                               uint64_t close_fee,
                               uint64_t factory_funding_amount,
                               const uint64_t *expected_amounts) {
    if (!ctx || !close_txid || !expected_amounts) return 0;
    strncpy(ctx->close_txid, close_txid, sizeof(ctx->close_txid) - 1);
    ctx->close_fee = close_fee;
    ctx->factory_funding_amount = factory_funding_amount;

    int all_ok = 1;
    uint64_t sum_outputs = 0;
    for (size_t i = 0; i < ctx->n_parties; i++) {
        econ_party_t *p = &ctx->parties[i];
        p->expected_close_amount = expected_amounts[i];
        uint64_t on_chain_amt = 0;
        int v = spend_find_vout_by_spk(ctx->rt, close_txid,
                                         p->expect_close_spk, p->expect_close_spk_len,
                                         &on_chain_amt);
        if (expected_amounts[i] == 0) {
            if (v >= 0) {
                fprintf(stderr, "  econ FAIL party %zu (%s): expected no output, "
                                "but close vout[%d] = %llu sats matched SPK\n",
                        i, p->name, v, (unsigned long long)on_chain_amt);
                all_ok = 0;
            }
            p->received_from_close = 0;
            continue;
        }
        if (v < 0) {
            fprintf(stderr, "  econ FAIL party %zu (%s): expected %llu sats, "
                            "but close tx has no matching vout\n",
                    i, p->name, (unsigned long long)expected_amounts[i]);
            all_ok = 0;
            continue;
        }
        p->received_from_close = on_chain_amt;
        sum_outputs += on_chain_amt;
        if (on_chain_amt != expected_amounts[i]) {
            fprintf(stderr, "  econ FAIL party %zu (%s): expected %llu, got %llu "
                            "(delta=%lld)\n",
                    i, p->name,
                    (unsigned long long)expected_amounts[i],
                    (unsigned long long)on_chain_amt,
                    (long long)((int64_t)on_chain_amt - (int64_t)expected_amounts[i]));
            all_ok = 0;
        }
    }

    /* Conservation: Σ outputs + fee == funding. */
    if (sum_outputs + close_fee != factory_funding_amount) {
        fprintf(stderr, "  econ FAIL conservation: Σoutputs=%llu + fee=%llu "
                        "!= funding=%llu (delta=%lld)\n",
                (unsigned long long)sum_outputs, (unsigned long long)close_fee,
                (unsigned long long)factory_funding_amount,
                (long long)((int64_t)(sum_outputs + close_fee) -
                            (int64_t)factory_funding_amount));
        all_ok = 0;
    } else {
        printf("  econ OK: conservation Σoutputs(%llu) + fee(%llu) == funding(%llu)\n",
               (unsigned long long)sum_outputs, (unsigned long long)close_fee,
               (unsigned long long)factory_funding_amount);
    }

    ctx->n_outputs_checked = all_ok ? (int)ctx->n_parties : -1;
    return all_ok;
}

int econ_assert_wallet_deltas(econ_ctx_t *ctx,
                               const uint64_t *expected_deltas,
                               int64_t tolerance_sats) {
    if (!ctx || !expected_deltas) return 0;
    int all_ok = 1;
    for (size_t i = 0; i < ctx->n_parties; i++) {
        econ_party_t *p = &ctx->parties[i];
        p->expected_delta = expected_deltas[i];
        int64_t actual = (int64_t)p->post_balance_sats
                         - (int64_t)p->pre_balance_sats;
        int64_t exp = (int64_t)expected_deltas[i];
        int64_t diff = actual - exp;
        if (diff < -tolerance_sats || diff > tolerance_sats) {
            fprintf(stderr, "  econ FAIL wallet-delta party %zu (%s): "
                            "pre=%llu post=%llu delta=%lld expected=%lld "
                            "(diff=%lld > tol=%lld)\n",
                    i, p->name,
                    (unsigned long long)p->pre_balance_sats,
                    (unsigned long long)p->post_balance_sats,
                    (long long)actual, (long long)exp,
                    (long long)diff, (long long)tolerance_sats);
            all_ok = 0;
        }
    }
    ctx->n_deltas_checked = all_ok ? (int)ctx->n_parties : -1;
    return all_ok;
}

void econ_print_summary(const econ_ctx_t *ctx) {
    if (!ctx) return;
    printf("  ┌─ econ summary ─────────────────────────────────────────────────────\n");
    printf("  │ party            pre         post        close_out    delta    expected\n");
    for (size_t i = 0; i < ctx->n_parties; i++) {
        const econ_party_t *p = &ctx->parties[i];
        int64_t delta = (int64_t)p->post_balance_sats - (int64_t)p->pre_balance_sats;
        printf("  │ %-14s  %10llu  %10llu  %10llu  %+9lld  %10llu\n",
               p->name,
               (unsigned long long)p->pre_balance_sats,
               (unsigned long long)p->post_balance_sats,
               (unsigned long long)p->received_from_close,
               (long long)delta,
               (unsigned long long)p->expected_delta);
    }
    printf("  └──────────────────────────────────────────────────────────────────\n");
}
