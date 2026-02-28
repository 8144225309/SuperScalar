#include "superscalar/regtest.h"
#include "superscalar/musig.h"
#include "superscalar/tx_builder.h"
#include "superscalar/dw_state.h"
#include "superscalar/types.h"
#include "superscalar/watchtower.h"
#include "superscalar/fee.h"
#include "superscalar/channel.h"
#include "superscalar/sha256.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

static const unsigned char lsp_seckey[32] = {
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
};

static const unsigned char client_seckey[32] = {
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
};

/* Set up a 2-of-2 MuSig factory UTXO on regtest.
   Returns the correct vout, amount, and scriptpubkey by matching
   against the computed P2TR key (not just any P2TR output). */
static int setup_factory(
    regtest_t *rt,
    secp256k1_context *ctx,
    secp256k1_keypair *kps,
    musig_keyagg_t *keyagg,
    char *factory_addr,
    char *funding_txid,
    int *found_vout_out,
    uint64_t *fund_amount_out,
    unsigned char *fund_spk_out,
    size_t *fund_spk_len_out
) {
    if (!secp256k1_keypair_create(ctx, &kps[0], lsp_seckey)) return 0;
    if (!secp256k1_keypair_create(ctx, &kps[1], client_seckey)) return 0;

    secp256k1_pubkey pubkeys[2];
    if (!secp256k1_keypair_pub(ctx, &pubkeys[0], &kps[0])) return 0;
    if (!secp256k1_keypair_pub(ctx, &pubkeys[1], &kps[1])) return 0;

    if (!musig_aggregate_keys(ctx, keyagg, pubkeys, 2)) return 0;

    /* tweaked output key for P2TR key-path (no script tree) */
    unsigned char internal_key[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_key, &keyagg->agg_pubkey)) return 0;

    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_key, 32, tweak);

    musig_keyagg_t addr_keyagg = *keyagg;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &addr_keyagg.cache, tweak)) return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) return 0;

    unsigned char spk[34];
    build_p2tr_script_pubkey(spk, &tweaked_xonly);

    /* derive bech32m address via bitcoin-cli */
    char spk_hex[69];
    hex_encode(spk, 34, spk_hex);

    char params[256];
    snprintf(params, sizeof(params), "\"%s\"", spk_hex);
    char *result = regtest_exec(rt, "decodescript", params);
    if (!result) return 0;

    char *addr_start = strstr(result, "\"address\"");
    if (!addr_start) {
        free(result);

        /* fallback: rawtr() descriptor */
        char key_hex[65];
        unsigned char tweaked_ser[32];
        if (!secp256k1_xonly_pubkey_serialize(ctx, tweaked_ser, &tweaked_xonly)) return 0;
        hex_encode(tweaked_ser, 32, key_hex);

        snprintf(params, sizeof(params), "\"rawtr(%s)\"", key_hex);
        result = regtest_exec(rt, "deriveaddresses", params);
        if (!result) return 0;

        char *start = strchr(result, '"');
        if (!start) { free(result); return 0; }
        start++;
        start = strchr(result, '"');
        if (start) start++;
        if (!start) { free(result); return 0; }
        char *end = strchr(start, '"');
        if (!end || (size_t)(end - start) >= 128) { free(result); return 0; }
        size_t addr_len = (size_t)(end - start);
        memcpy(factory_addr, start, addr_len);
        factory_addr[addr_len] = '\0';
    } else {
        addr_start = strchr(addr_start, ':');
        if (!addr_start) { free(result); return 0; }
        addr_start = strchr(addr_start, '"');
        if (!addr_start) { free(result); return 0; }
        addr_start++;
        char *addr_end = strchr(addr_start, '"');
        if (!addr_end) { free(result); return 0; }
        size_t addr_len = (size_t)(addr_end - addr_start);
        memcpy(factory_addr, addr_start, addr_len);
        factory_addr[addr_len] = '\0';
    }
    free(result);

    if (!regtest_fund_address(rt, factory_addr, 0.001, funding_txid)) return 0;

    char mine_addr[128];
    if (!regtest_get_new_address(rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_mine_blocks(rt, 1, mine_addr)) return 0;

    /* Find the vout matching our computed SPK (not just any P2TR output).
       Bitcoin Core v28+ uses P2TR change addresses, so both outputs may be P2TR. */
    *found_vout_out = -1;
    for (int v = 0; v < 4; v++) {
        uint64_t amt;
        unsigned char out_spk[64];
        size_t out_spk_len = 0;
        if (regtest_get_tx_output(rt, funding_txid, (uint32_t)v,
                                   &amt, out_spk, &out_spk_len)) {
            if (out_spk_len == 34 && memcmp(out_spk, spk, 34) == 0) {
                *found_vout_out = v;
                *fund_amount_out = amt;
                memcpy(fund_spk_out, out_spk, 34);
                *fund_spk_len_out = 34;
                break;
            }
        }
    }
    if (*found_vout_out < 0) return 0;

    return 1;
}

/* Build, sign, and broadcast a state tx spending the given outpoint. */
static int build_and_broadcast_state_tx(
    regtest_t *rt,
    secp256k1_context *ctx,
    const secp256k1_keypair *kps,
    musig_keyagg_t *keyagg,
    const unsigned char *prev_txid_bytes,
    uint32_t prev_vout,
    uint64_t prev_amount,
    const unsigned char *prev_spk,
    size_t prev_spk_len,
    uint32_t nsequence,
    const secp256k1_xonly_pubkey *output_key,
    uint64_t output_amount,
    char *txid_out
) {
    tx_output_t output;
    output.amount_sats = output_amount;
    build_p2tr_script_pubkey(output.script_pubkey, output_key);
    output.script_pubkey_len = 34;

    tx_buf_t unsigned_buf;
    tx_buf_init(&unsigned_buf, 256);
    unsigned char state_txid[32];

    if (!build_unsigned_tx(&unsigned_buf, state_txid, prev_txid_bytes, prev_vout,
                           nsequence, &output, 1)) {
        tx_buf_free(&unsigned_buf);
        return 0;
    }

    unsigned char sighash[32];
    if (!compute_taproot_sighash(sighash, unsigned_buf.data, unsigned_buf.len,
                                  0, prev_spk, prev_spk_len, prev_amount,
                                  nsequence)) {
        tx_buf_free(&unsigned_buf);
        return 0;
    }

    unsigned char sig[64];
    musig_keyagg_t sign_keyagg = *keyagg;
    if (!musig_sign_taproot(ctx, sig, sighash, kps, 2, &sign_keyagg, NULL)) {
        tx_buf_free(&unsigned_buf);
        return 0;
    }

    tx_buf_t signed_buf;
    tx_buf_init(&signed_buf, 512);
    if (!finalize_signed_tx(&signed_buf, unsigned_buf.data, unsigned_buf.len, sig)) {
        tx_buf_free(&unsigned_buf);
        tx_buf_free(&signed_buf);
        return 0;
    }

    char *tx_hex = (char *)malloc(signed_buf.len * 2 + 1);
    hex_encode(signed_buf.data, signed_buf.len, tx_hex);

    int ok = regtest_send_raw_tx(rt, tx_hex, txid_out);

    free(tx_hex);
    tx_buf_free(&unsigned_buf);
    tx_buf_free(&signed_buf);
    return ok;
}

/* Spend factory UTXO with newest state (lowest nSequence), mine to confirm. */
int test_regtest_basic_dw(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    regtest_create_wallet(&rt, "test_dw");

    char mine_addr[128];
    regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr));
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    secp256k1_keypair kps[2];
    musig_keyagg_t keyagg;
    char factory_addr[128];
    char funding_txid[65];
    int found_vout = -1;
    uint64_t fund_amount;
    unsigned char fund_spk[34];
    size_t fund_spk_len;

    TEST_ASSERT(setup_factory(&rt, ctx, kps, &keyagg, factory_addr, funding_txid,
                              &found_vout, &fund_amount, fund_spk, &fund_spk_len),
                "factory setup");

    printf("  Factory funded: %s (vout %d)\n", funding_txid, found_vout);

    unsigned char fund_txid_bytes[32];
    hex_decode(funding_txid, fund_txid_bytes, 32);
    reverse_bytes(fund_txid_bytes, 32); /* display order -> internal order */

    /* small step for test: 2 blocks instead of 144 */
    dw_layer_t layer;
    dw_layer_init(&layer, 2, 4);

    /* advance to newest state */
    dw_advance(&layer); dw_advance(&layer); dw_advance(&layer);
    uint32_t nseq = dw_current_nsequence(&layer);

    unsigned char out_seckey[32];
    memset(out_seckey, 0x30, 32);
    secp256k1_keypair out_kp;
    if (!secp256k1_keypair_create(ctx, &out_kp, out_seckey)) return 0;
    secp256k1_xonly_pubkey out_xpk;
    if (!secp256k1_keypair_xonly_pub(ctx, &out_xpk, NULL, &out_kp)) return 0;

    uint64_t output_amount = fund_amount - 1000; /* leave room for fee */

    char state_txid[65];
    int sent = build_and_broadcast_state_tx(
        &rt, ctx, kps, &keyagg,
        fund_txid_bytes, (uint32_t)found_vout,
        fund_amount, fund_spk, fund_spk_len,
        nseq, &out_xpk, output_amount, state_txid);

    TEST_ASSERT(sent, "broadcast state tx");
    printf("  State tx in mempool: %s\n", state_txid);
    regtest_mine_blocks(&rt, (int)nseq + 1, mine_addr);

    int conf = regtest_get_confirmations(&rt, state_txid);
    printf("  State tx confirmations: %d\n", conf);
    TEST_ASSERT(conf > 0, "state tx should be confirmed");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Broadcast oldest state first — it confirms. Then try newest — double-spend.
   Demonstrates DW invariant: old states have higher nSequence (longer delays). */
int test_regtest_old_first_attack(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    regtest_create_wallet(&rt, "test_old_first");

    char mine_addr[128];
    regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr));
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    secp256k1_keypair kps[2];
    musig_keyagg_t keyagg;
    char factory_addr[128];
    char funding_txid[65];
    int found_vout = -1;
    uint64_t fund_amount;
    unsigned char fund_spk[34];
    size_t fund_spk_len;

    TEST_ASSERT(setup_factory(&rt, ctx, kps, &keyagg, factory_addr, funding_txid,
                              &found_vout, &fund_amount, fund_spk, &fund_spk_len),
                "factory setup");

    unsigned char fund_txid_bytes[32];
    hex_decode(funding_txid, fund_txid_bytes, 32);
    reverse_bytes(fund_txid_bytes, 32);

    /* DW layer: step=1, max_states=4 */
    dw_layer_t layer;
    dw_layer_init(&layer, 1, 4);

    /* Epoch 0 (oldest): nSeq = 1*(4-1-0) = 3 */
    uint32_t old_nseq = dw_current_nsequence(&layer);

    /* Advance to epoch 3 (newest): nSeq = 1*(4-1-3) = 0 */
    dw_advance(&layer); dw_advance(&layer); dw_advance(&layer);
    uint32_t new_nseq = dw_current_nsequence(&layer);

    printf("  Old nSeq=%u, New nSeq=%u\n", old_nseq, new_nseq);
    TEST_ASSERT(old_nseq > new_nseq, "old state has higher nSequence");

    unsigned char out_seckey[32];
    memset(out_seckey, 0x30, 32);
    secp256k1_keypair out_kp;
    if (!secp256k1_keypair_create(ctx, &out_kp, out_seckey)) return 0;
    secp256k1_xonly_pubkey out_xpk;
    if (!secp256k1_keypair_xonly_pub(ctx, &out_xpk, NULL, &out_kp)) return 0;

    uint64_t output_amount = fund_amount - 1000;

    /* Mine enough blocks for old state's relative timelock */
    regtest_mine_blocks(&rt, (int)old_nseq, mine_addr);

    /* Broadcast OLD state tx (high nSequence) */
    char old_txid[65];
    int old_sent = build_and_broadcast_state_tx(
        &rt, ctx, kps, &keyagg,
        fund_txid_bytes, (uint32_t)found_vout,
        fund_amount, fund_spk, fund_spk_len,
        old_nseq, &out_xpk, output_amount, old_txid);
    TEST_ASSERT(old_sent, "broadcast old state tx");
    printf("  Old state tx in mempool: %s\n", old_txid);

    /* Mine 1 block to confirm */
    regtest_mine_blocks(&rt, 1, mine_addr);
    int old_conf = regtest_get_confirmations(&rt, old_txid);
    TEST_ASSERT(old_conf > 0, "old state tx confirmed");

    /* Try NEW state tx (low nSequence) — funding already spent */
    char new_txid[65];
    int new_sent = build_and_broadcast_state_tx(
        &rt, ctx, kps, &keyagg,
        fund_txid_bytes, (uint32_t)found_vout,
        fund_amount, fund_spk, fund_spk_len,
        new_nseq, &out_xpk, output_amount, new_txid);
    TEST_ASSERT(!new_sent, "new state tx rejected (double-spend)");
    printf("  New state tx correctly rejected (funding UTXO already spent)\n");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* MuSig2 on-chain via split-round protocol (not the all-local convenience). */
int test_regtest_musig_onchain(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    regtest_create_wallet(&rt, "test_musig_oc");

    char mine_addr[128];
    regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr));
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    secp256k1_keypair kps[2];
    musig_keyagg_t keyagg;
    char factory_addr[128];
    char funding_txid[65];
    int found_vout = -1;
    uint64_t fund_amount;
    unsigned char fund_spk[34];
    size_t fund_spk_len;

    TEST_ASSERT(setup_factory(&rt, ctx, kps, &keyagg, factory_addr, funding_txid,
                              &found_vout, &fund_amount, fund_spk, &fund_spk_len),
                "factory setup");

    unsigned char fund_txid_bytes[32];
    hex_decode(funding_txid, fund_txid_bytes, 32);
    reverse_bytes(fund_txid_bytes, 32);

    /* Build unsigned spending tx (nSequence=0) */
    unsigned char out_seckey[32];
    memset(out_seckey, 0x30, 32);
    secp256k1_keypair out_kp;
    if (!secp256k1_keypair_create(ctx, &out_kp, out_seckey)) return 0;
    secp256k1_xonly_pubkey out_xpk;
    if (!secp256k1_keypair_xonly_pub(ctx, &out_xpk, NULL, &out_kp)) return 0;

    tx_output_t output;
    output.amount_sats = fund_amount - 1000;
    build_p2tr_script_pubkey(output.script_pubkey, &out_xpk);
    output.script_pubkey_len = 34;

    tx_buf_t unsigned_buf;
    tx_buf_init(&unsigned_buf, 256);

    TEST_ASSERT(build_unsigned_tx(&unsigned_buf, NULL,
                                   fund_txid_bytes, (uint32_t)found_vout,
                                   0, &output, 1), "build unsigned tx");

    unsigned char sighash[32];
    TEST_ASSERT(compute_taproot_sighash(sighash, unsigned_buf.data, unsigned_buf.len,
                                         0, fund_spk, fund_spk_len, fund_amount, 0),
                "compute sighash");

    /* --- Split-round MuSig2 --- */

    /* Round 1: each signer generates a nonce */
    secp256k1_pubkey pubkeys[2];
    if (!secp256k1_keypair_pub(ctx, &pubkeys[0], &kps[0])) return 0;
    if (!secp256k1_keypair_pub(ctx, &pubkeys[1], &kps[1])) return 0;

    secp256k1_musig_secnonce secnonces[2];
    secp256k1_musig_pubnonce pubnonces[2];

    TEST_ASSERT(musig_generate_nonce(ctx, &secnonces[0], &pubnonces[0],
                                      lsp_seckey, &pubkeys[0], &keyagg.cache),
                "nonce gen signer 0");
    TEST_ASSERT(musig_generate_nonce(ctx, &secnonces[1], &pubnonces[1],
                                      client_seckey, &pubkeys[1], &keyagg.cache),
                "nonce gen signer 1");

    /* Round 1 finalize: collect pubnonces, apply taproot tweak */
    musig_signing_session_t session;
    musig_session_init(&session, &keyagg, 2);
    TEST_ASSERT(musig_session_set_pubnonce(&session, 0, &pubnonces[0]),
                "set pubnonce 0");
    TEST_ASSERT(musig_session_set_pubnonce(&session, 1, &pubnonces[1]),
                "set pubnonce 1");
    TEST_ASSERT(musig_session_finalize_nonces(ctx, &session, sighash, NULL, NULL),
                "finalize nonces");

    /* Round 2: each signer creates + verifies partial sig */
    secp256k1_musig_partial_sig psigs[2];
    TEST_ASSERT(musig_create_partial_sig(ctx, &psigs[0], &secnonces[0], &kps[0], &session),
                "partial sig 0");
    TEST_ASSERT(musig_create_partial_sig(ctx, &psigs[1], &secnonces[1], &kps[1], &session),
                "partial sig 1");
    TEST_ASSERT(musig_verify_partial_sig(ctx, &psigs[0], &pubnonces[0], &pubkeys[0], &session),
                "verify psig 0");
    TEST_ASSERT(musig_verify_partial_sig(ctx, &psigs[1], &pubnonces[1], &pubkeys[1], &session),
                "verify psig 1");

    /* Aggregate into final 64-byte Schnorr sig */
    unsigned char sig[64];
    TEST_ASSERT(musig_aggregate_partial_sigs(ctx, sig, &session, psigs, 2),
                "aggregate partial sigs");

    /* Finalize tx and broadcast */
    tx_buf_t signed_buf;
    tx_buf_init(&signed_buf, 512);
    TEST_ASSERT(finalize_signed_tx(&signed_buf, unsigned_buf.data, unsigned_buf.len, sig),
                "finalize signed tx");

    char *tx_hex = (char *)malloc(signed_buf.len * 2 + 1);
    hex_encode(signed_buf.data, signed_buf.len, tx_hex);

    char txid_out[65];
    int sent = regtest_send_raw_tx(&rt, tx_hex, txid_out);
    free(tx_hex);
    tx_buf_free(&unsigned_buf);
    tx_buf_free(&signed_buf);

    TEST_ASSERT(sent, "broadcast split-round MuSig2 tx");
    printf("  Split-round MuSig2 tx: %s\n", txid_out);

    regtest_mine_blocks(&rt, 1, mine_addr);
    int conf = regtest_get_confirmations(&rt, txid_out);
    TEST_ASSERT(conf > 0, "split-round MuSig2 tx confirmed on-chain");
    printf("  Confirmed (%d conf)\n", conf);

    secp256k1_context_destroy(ctx);
    return 1;
}

/* nSequence edge case: tx rejected before relative timelock, accepted after. */
int test_regtest_nsequence_edge(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    regtest_create_wallet(&rt, "test_nseq");

    char mine_addr[128];
    regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr));
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    secp256k1_keypair kps[2];
    musig_keyagg_t keyagg;
    char factory_addr[128];
    char funding_txid[65];
    int found_vout = -1;
    uint64_t fund_amount;
    unsigned char fund_spk[34];
    size_t fund_spk_len;

    TEST_ASSERT(setup_factory(&rt, ctx, kps, &keyagg, factory_addr, funding_txid,
                              &found_vout, &fund_amount, fund_spk, &fund_spk_len),
                "factory setup");

    unsigned char fund_txid_bytes[32];
    hex_decode(funding_txid, fund_txid_bytes, 32);
    reverse_bytes(fund_txid_bytes, 32);

    /* DW layer: step=1, max_states=4, advance to state 1 */
    dw_layer_t layer;
    dw_layer_init(&layer, 1, 4);
    dw_advance(&layer); /* state 1: nSeq = 1*(4-1-1) = 2 */
    uint32_t nseq = dw_current_nsequence(&layer);
    printf("  nSequence = %u\n", nseq);
    TEST_ASSERT(nseq == 2, "intermediate state nSeq");

    unsigned char out_seckey[32];
    memset(out_seckey, 0x30, 32);
    secp256k1_keypair out_kp;
    if (!secp256k1_keypair_create(ctx, &out_kp, out_seckey)) return 0;
    secp256k1_xonly_pubkey out_xpk;
    if (!secp256k1_keypair_xonly_pub(ctx, &out_xpk, NULL, &out_kp)) return 0;

    uint64_t output_amount = fund_amount - 1000;

    /* Try broadcasting immediately — nSeq not satisfied */
    char state_txid[65];
    int sent = build_and_broadcast_state_tx(
        &rt, ctx, kps, &keyagg,
        fund_txid_bytes, (uint32_t)found_vout,
        fund_amount, fund_spk, fund_spk_len,
        nseq, &out_xpk, output_amount, state_txid);
    TEST_ASSERT(!sent, "tx rejected before relative timelock met");
    printf("  Correctly rejected (0/%u blocks)\n", nseq);

    /* Mine exactly nSeq blocks to satisfy relative timelock */
    regtest_mine_blocks(&rt, (int)nseq, mine_addr);

    /* Broadcast again — should succeed now */
    sent = build_and_broadcast_state_tx(
        &rt, ctx, kps, &keyagg,
        fund_txid_bytes, (uint32_t)found_vout,
        fund_amount, fund_spk, fund_spk_len,
        nseq, &out_xpk, output_amount, state_txid);
    TEST_ASSERT(sent, "tx accepted after relative timelock met");
    printf("  Accepted after %u blocks: %s\n", nseq, state_txid);

    /* Mine 1 more block to confirm */
    regtest_mine_blocks(&rt, 1, mine_addr);
    int conf = regtest_get_confirmations(&rt, state_txid);
    TEST_ASSERT(conf > 0, "state tx confirmed");
    printf("  Confirmed (%d conf)\n", conf);

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test: regtest_get_utxo_for_bump + signrawtransactionwithwallet */
int test_regtest_cpfp_penalty_bump(void) {
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not available\n");
        return 0;
    }
    regtest_create_wallet(&rt, "test_cpfp_bump");

    char mine_addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)),
                "get mining address");
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    /* Test regtest_get_utxo_for_bump */
    char txid_out[65];
    uint32_t vout_out;
    uint64_t amount_out;
    unsigned char spk_out[64];
    size_t spk_len_out = 0;

    int found = regtest_get_utxo_for_bump(&rt, 1000,
                                            txid_out, &vout_out,
                                            &amount_out, spk_out, &spk_len_out);
    TEST_ASSERT(found, "found wallet UTXO for bump");
    TEST_ASSERT(amount_out >= 1000, "UTXO amount sufficient");
    TEST_ASSERT(spk_len_out > 0, "UTXO SPK non-empty");
    printf("  Found UTXO: %s:%u amount=%llu\n", txid_out, vout_out,
           (unsigned long long)amount_out);

    /* Test watchtower anchor init on regtest */
    watchtower_t wt;
    fee_estimator_t fee;
    fee_init(&fee, 1000);
    watchtower_init(&wt, 1, &rt, &fee, NULL);
    TEST_ASSERT(wt.anchor_spk_len == P2A_SPK_LEN, "P2A anchor SPK initialized");
    printf("  Watchtower P2A anchor SPK set successfully\n");

    watchtower_cleanup(&wt);
    return 1;
}

/* Full on-chain breach → penalty → CPFP regtest test.
   1. Set up LSP + client channels with proper key derivation
   2. Build/sign commitment #0, advance to #1, exchange revocations
   3. Client watchtower registers old commitment #0
   4. Broadcast revoked commitment #0 (breach)
   5. watchtower_check() detects breach, builds penalty with P2A anchor
   6. Simulate CPFP bumping cycles
   7. Mine and verify penalty confirms */
int test_regtest_breach_penalty_cpfp(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    regtest_create_wallet(&rt, "test_breach_cpfp");

    char mine_addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)),
                "get mining address");
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    /* --- Set up a 2-of-2 MuSig funding UTXO --- */
    secp256k1_keypair kps[2];
    musig_keyagg_t keyagg;
    char factory_addr[128];
    char funding_txid_hex[65];
    int found_vout = -1;
    uint64_t fund_amount;
    unsigned char fund_spk[34];
    size_t fund_spk_len;

    TEST_ASSERT(setup_factory(&rt, ctx, kps, &keyagg, factory_addr,
                                funding_txid_hex, &found_vout,
                                &fund_amount, fund_spk, &fund_spk_len),
                "factory setup for channel funding");
    printf("  Funding UTXO: %s:%d (%llu sats)\n",
           funding_txid_hex, found_vout, (unsigned long long)fund_amount);

    unsigned char fund_txid_bytes[32];
    hex_decode(funding_txid_hex, fund_txid_bytes, 32);
    reverse_bytes(fund_txid_bytes, 32);

    /* --- Set up LSP + client channels --- */
    secp256k1_pubkey lsp_pk, client_pk;
    if (!secp256k1_keypair_pub(ctx, &lsp_pk, &kps[0])) return 0;
    if (!secp256k1_keypair_pub(ctx, &client_pk, &kps[1])) return 0;

    fee_estimator_t fe;
    fee_init(&fe, 1000);
    uint64_t commit_fee = fee_for_commitment_tx(&fe, 0);
    uint64_t usable = fund_amount > commit_fee ? fund_amount - commit_fee : fund_amount;
    uint64_t local_amt = usable / 2;
    uint64_t remote_amt = usable - local_amt;
    uint32_t csv_delay = 6;

    /* LSP channel (local=LSP, remote=client) */
    channel_t lsp_ch;
    TEST_ASSERT(channel_init(&lsp_ch, ctx, lsp_seckey, &lsp_pk, &client_pk,
                               fund_txid_bytes, (uint32_t)found_vout, fund_amount,
                               fund_spk, 34, local_amt, remote_amt, csv_delay),
                "init LSP channel");
    channel_generate_random_basepoints(&lsp_ch);

    /* Client channel (local=client, remote=LSP) */
    channel_t client_ch;
    TEST_ASSERT(channel_init(&client_ch, ctx, client_seckey, &client_pk, &lsp_pk,
                               fund_txid_bytes, (uint32_t)found_vout, fund_amount,
                               fund_spk, 34, remote_amt, local_amt, csv_delay),
                "init client channel");
    channel_generate_random_basepoints(&client_ch);

    /* Exchange basepoints */
    channel_set_remote_basepoints(&lsp_ch,
        &client_ch.local_payment_basepoint,
        &client_ch.local_delayed_payment_basepoint,
        &client_ch.local_revocation_basepoint);
    channel_set_remote_basepoints(&client_ch,
        &lsp_ch.local_payment_basepoint,
        &lsp_ch.local_delayed_payment_basepoint,
        &lsp_ch.local_revocation_basepoint);

    /* Exchange HTLC basepoints */
    channel_set_remote_htlc_basepoint(&lsp_ch, &client_ch.local_htlc_basepoint);
    channel_set_remote_htlc_basepoint(&client_ch, &lsp_ch.local_htlc_basepoint);

    /* Exchange per-commitment points for commitments 0 and 1 */
    secp256k1_pubkey lsp_pcp0, lsp_pcp1, client_pcp0, client_pcp1;
    channel_get_per_commitment_point(&lsp_ch, 0, &lsp_pcp0);
    channel_get_per_commitment_point(&lsp_ch, 1, &lsp_pcp1);
    channel_get_per_commitment_point(&client_ch, 0, &client_pcp0);
    channel_get_per_commitment_point(&client_ch, 1, &client_pcp1);
    channel_set_remote_pcp(&lsp_ch, 0, &client_pcp0);
    channel_set_remote_pcp(&lsp_ch, 1, &client_pcp1);
    channel_set_remote_pcp(&client_ch, 0, &lsp_pcp0);
    channel_set_remote_pcp(&client_ch, 1, &lsp_pcp1);

    /* --- Build + sign commitment #0 (LSP's local commitment) --- */
    tx_buf_t commit0_unsigned;
    tx_buf_init(&commit0_unsigned, 512);
    unsigned char commit0_txid[32];
    TEST_ASSERT(channel_build_commitment_tx(&lsp_ch, &commit0_unsigned, commit0_txid),
                "build LSP commitment #0");

    tx_buf_t commit0_signed;
    tx_buf_init(&commit0_signed, 1024);
    TEST_ASSERT(channel_sign_commitment(&lsp_ch, &commit0_signed, &commit0_unsigned,
                                          &kps[1]),
                "sign LSP commitment #0 (client countersigns)");

    /* Extract to_local SPK from commitment #0 unsigned for watchtower registration.
       Layout: nVersion(4) + varint_in(1) + txid(32) + vout(4) + scriptSig_len(1) +
       nSequence(4) = 46, then varint_out(1) = 47, then amount(8) + spk_varint(1) + spk(34) */
    unsigned char to_local_spk[34];
    memcpy(to_local_spk, commit0_unsigned.data + 47 + 8 + 1, 34);

    /* --- Advance to commitment #1 --- */
    channel_generate_local_pcs(&lsp_ch, 1);
    channel_generate_local_pcs(&client_ch, 1);

    secp256k1_pubkey lsp_pcp2, client_pcp2;
    channel_get_per_commitment_point(&lsp_ch, 2, &lsp_pcp2);
    channel_get_per_commitment_point(&client_ch, 2, &client_pcp2);
    channel_set_remote_pcp(&lsp_ch, 2, &client_pcp2);
    channel_set_remote_pcp(&client_ch, 2, &lsp_pcp2);

    lsp_ch.commitment_number = 1;
    client_ch.commitment_number = 1;

    /* Exchange revocation secrets for commitment #0 */
    unsigned char lsp_secret0[32], client_secret0[32];
    channel_get_revocation_secret(&lsp_ch, 0, lsp_secret0);
    channel_get_revocation_secret(&client_ch, 0, client_secret0);
    channel_receive_revocation(&lsp_ch, 0, client_secret0);
    channel_receive_revocation(&client_ch, 0, lsp_secret0);

    /* --- Client watchtower: register old commitment #0 for monitoring --- */
    watchtower_t wt;
    watchtower_init(&wt, 1, &rt, &fe, NULL);
    watchtower_set_channel(&wt, 0, &client_ch);
    TEST_ASSERT(wt.anchor_spk_len == P2A_SPK_LEN, "P2A anchor initialized");

    /* Build the remote-view commitment #0 to get the correct txid */
    tx_buf_t remote_commit0;
    tx_buf_init(&remote_commit0, 512);
    unsigned char remote_commit0_txid[32];
    client_ch.commitment_number = 0;
    channel_build_commitment_tx_for_remote(&client_ch, &remote_commit0, remote_commit0_txid);
    client_ch.commitment_number = 1;

    /* Extract to_local SPK/amount from the remote view (this is what the
       breach tx will look like — LSP's to_local output that client can sweep) */
    unsigned char breach_to_local_spk[34];
    memcpy(breach_to_local_spk, remote_commit0.data + 47 + 8 + 1, 34);
    tx_buf_free(&remote_commit0);

    TEST_ASSERT(watchtower_watch(&wt, 0, 0, commit0_txid,
                                   0, local_amt, breach_to_local_spk, 34),
                "register old commitment for watching");
    printf("  Watchtower watching commitment #0\n");

    /* --- BREACH: broadcast revoked commitment #0 --- */
    char *commit0_hex = (char *)malloc(commit0_signed.len * 2 + 1);
    hex_encode(commit0_signed.data, commit0_signed.len, commit0_hex);

    char commit0_txid_hex[65];
    int sent = regtest_send_raw_tx(&rt, commit0_hex, commit0_txid_hex);
    free(commit0_hex);
    TEST_ASSERT(sent, "broadcast revoked commitment #0 (breach)");
    printf("  BREACH: revoked commitment broadcast: %s\n", commit0_txid_hex);

    /* Mine 1 block to confirm the breach */
    regtest_mine_blocks(&rt, 1, mine_addr);
    int conf = regtest_get_confirmations(&rt, commit0_txid_hex);
    TEST_ASSERT(conf > 0, "breach commitment confirmed");

    /* --- watchtower_check() detects breach and broadcasts penalty --- */
    int penalties = watchtower_check(&wt);
    TEST_ASSERT(penalties > 0, "watchtower detected breach and broadcast penalty");
    printf("  Watchtower broadcast %d penalty tx(s)\n", penalties);

    /* Verify penalty is pending for CPFP */
    TEST_ASSERT(wt.n_pending > 0, "pending penalty entry created");
    TEST_ASSERT(wt.pending[0].anchor_amount == ANCHOR_OUTPUT_AMOUNT,
                "pending anchor amount matches P2A");
    printf("  Penalty pending: txid=%s, anchor_vout=%u\n",
           wt.pending[0].txid, wt.pending[0].anchor_vout);

    /* --- Simulate CPFP bumping --- */
    /* Cycle 1 (second watchtower_check call): cycles_in_mempool goes 1→2,
       triggering the first CPFP bump (policy: bump at cycles_in_mempool >= 2) */
    int check1 = watchtower_check(&wt);
    TEST_ASSERT(wt.n_pending > 0, "still pending after cycle 1");
    printf("  After cycle 1: bump_count=%d\n", wt.pending[0].bump_count);
    TEST_ASSERT(wt.pending[0].bump_count == 1, "first CPFP bump at cycle 1");
    (void)check1;

    /* Cycle 2: should NOT bump again (cycles_since_bump < 6) */
    int check2 = watchtower_check(&wt);
    (void)check2;
    TEST_ASSERT(wt.pending[0].bump_count == 1, "no re-bump at cycle 2 (too soon)");
    printf("  After cycle 2: bump_count=%d (no re-bump, cooldown active)\n",
           wt.pending[0].bump_count);

    /* --- Mine and verify penalty confirms --- */
    regtest_mine_blocks(&rt, 1, mine_addr);

    /* Run check again — should clear pending since penalty is now confirmed */
    watchtower_check(&wt);
    printf("  After mining: n_pending=%zu\n", wt.n_pending);
    TEST_ASSERT(wt.n_pending == 0, "pending cleared after penalty confirmed");

    /* Cleanup */
    tx_buf_free(&commit0_unsigned);
    tx_buf_free(&commit0_signed);
    watchtower_cleanup(&wt);
    secp256k1_context_destroy(ctx);

    printf("  Breach → Penalty → CPFP flow complete!\n");
    return 1;
}

/* Adversarial Test: Watchtower detects breach in mempool (before any mining).
   Verifies the mempool-detection path in watchtower_check(). */
int test_regtest_watchtower_mempool_detection(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    regtest_create_wallet(&rt, "test_mempool_wt");

    char mine_addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)),
                "get mining address");
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    /* Set up 2-of-2 MuSig funding UTXO */
    secp256k1_keypair kps[2];
    musig_keyagg_t keyagg;
    char factory_addr[128];
    char funding_txid_hex[65];
    int found_vout = -1;
    uint64_t fund_amount;
    unsigned char fund_spk[34];
    size_t fund_spk_len;

    TEST_ASSERT(setup_factory(&rt, ctx, kps, &keyagg, factory_addr,
                                funding_txid_hex, &found_vout,
                                &fund_amount, fund_spk, &fund_spk_len),
                "factory setup");

    unsigned char fund_txid_bytes[32];
    hex_decode(funding_txid_hex, fund_txid_bytes, 32);
    reverse_bytes(fund_txid_bytes, 32);

    /* Set up LSP + client channels */
    secp256k1_pubkey lsp_pk, client_pk;
    if (!secp256k1_keypair_pub(ctx, &lsp_pk, &kps[0])) return 0;
    if (!secp256k1_keypair_pub(ctx, &client_pk, &kps[1])) return 0;

    fee_estimator_t fe;
    fee_init(&fe, 1000);
    uint64_t commit_fee = fee_for_commitment_tx(&fe, 0);
    uint64_t usable = fund_amount > commit_fee ? fund_amount - commit_fee : fund_amount;
    uint64_t local_amt = usable / 2;
    uint64_t remote_amt = usable - local_amt;
    uint32_t csv_delay = 6;

    channel_t lsp_ch;
    TEST_ASSERT(channel_init(&lsp_ch, ctx, lsp_seckey, &lsp_pk, &client_pk,
                               fund_txid_bytes, (uint32_t)found_vout, fund_amount,
                               fund_spk, 34, local_amt, remote_amt, csv_delay),
                "init LSP channel");
    channel_generate_random_basepoints(&lsp_ch);

    channel_t client_ch;
    TEST_ASSERT(channel_init(&client_ch, ctx, client_seckey, &client_pk, &lsp_pk,
                               fund_txid_bytes, (uint32_t)found_vout, fund_amount,
                               fund_spk, 34, remote_amt, local_amt, csv_delay),
                "init client channel");
    channel_generate_random_basepoints(&client_ch);

    /* Exchange basepoints */
    channel_set_remote_basepoints(&lsp_ch,
        &client_ch.local_payment_basepoint,
        &client_ch.local_delayed_payment_basepoint,
        &client_ch.local_revocation_basepoint);
    channel_set_remote_basepoints(&client_ch,
        &lsp_ch.local_payment_basepoint,
        &lsp_ch.local_delayed_payment_basepoint,
        &lsp_ch.local_revocation_basepoint);
    channel_set_remote_htlc_basepoint(&lsp_ch, &client_ch.local_htlc_basepoint);
    channel_set_remote_htlc_basepoint(&client_ch, &lsp_ch.local_htlc_basepoint);

    /* Exchange per-commitment points */
    secp256k1_pubkey lsp_pcp0, lsp_pcp1, client_pcp0, client_pcp1;
    channel_get_per_commitment_point(&lsp_ch, 0, &lsp_pcp0);
    channel_get_per_commitment_point(&lsp_ch, 1, &lsp_pcp1);
    channel_get_per_commitment_point(&client_ch, 0, &client_pcp0);
    channel_get_per_commitment_point(&client_ch, 1, &client_pcp1);
    channel_set_remote_pcp(&lsp_ch, 0, &client_pcp0);
    channel_set_remote_pcp(&lsp_ch, 1, &client_pcp1);
    channel_set_remote_pcp(&client_ch, 0, &lsp_pcp0);
    channel_set_remote_pcp(&client_ch, 1, &lsp_pcp1);

    /* Build + sign commitment #0 */
    tx_buf_t commit0_unsigned;
    tx_buf_init(&commit0_unsigned, 512);
    unsigned char commit0_txid[32];
    TEST_ASSERT(channel_build_commitment_tx(&lsp_ch, &commit0_unsigned, commit0_txid),
                "build commitment #0");

    tx_buf_t commit0_signed;
    tx_buf_init(&commit0_signed, 1024);
    TEST_ASSERT(channel_sign_commitment(&lsp_ch, &commit0_signed, &commit0_unsigned,
                                          &kps[1]),
                "sign commitment #0");

    /* Advance to commitment #1, revoke #0 */
    channel_generate_local_pcs(&lsp_ch, 1);
    channel_generate_local_pcs(&client_ch, 1);

    secp256k1_pubkey lsp_pcp2, client_pcp2;
    channel_get_per_commitment_point(&lsp_ch, 2, &lsp_pcp2);
    channel_get_per_commitment_point(&client_ch, 2, &client_pcp2);
    channel_set_remote_pcp(&lsp_ch, 2, &client_pcp2);
    channel_set_remote_pcp(&client_ch, 2, &lsp_pcp2);

    lsp_ch.commitment_number = 1;
    client_ch.commitment_number = 1;

    unsigned char lsp_secret0[32], client_secret0[32];
    channel_get_revocation_secret(&lsp_ch, 0, lsp_secret0);
    channel_get_revocation_secret(&client_ch, 0, client_secret0);
    channel_receive_revocation(&lsp_ch, 0, client_secret0);
    channel_receive_revocation(&client_ch, 0, lsp_secret0);

    /* Register commitment #0 with watchtower */
    watchtower_t wt;
    watchtower_init(&wt, 1, &rt, &fe, NULL);
    watchtower_set_channel(&wt, 0, &client_ch);

    tx_buf_t remote_commit0;
    tx_buf_init(&remote_commit0, 512);
    unsigned char remote_commit0_txid[32];
    client_ch.commitment_number = 0;
    channel_build_commitment_tx_for_remote(&client_ch, &remote_commit0, remote_commit0_txid);
    client_ch.commitment_number = 1;

    unsigned char breach_to_local_spk[34];
    memcpy(breach_to_local_spk, remote_commit0.data + 47 + 8 + 1, 34);
    tx_buf_free(&remote_commit0);

    TEST_ASSERT(watchtower_watch(&wt, 0, 0, commit0_txid,
                                   0, local_amt, breach_to_local_spk, 34),
                "register commitment for watching");

    /* BREACH: broadcast revoked commitment #0 — do NOT mine */
    char *commit0_hex = (char *)malloc(commit0_signed.len * 2 + 1);
    hex_encode(commit0_signed.data, commit0_signed.len, commit0_hex);
    char commit0_txid_hex[65];
    int sent = regtest_send_raw_tx(&rt, commit0_hex, commit0_txid_hex);
    free(commit0_hex);
    TEST_ASSERT(sent, "broadcast revoked commitment #0");
    printf("  BREACH broadcast (mempool only): %s\n", commit0_txid_hex);

    /* Verify breach is in mempool but NOT confirmed */
    TEST_ASSERT(regtest_is_in_mempool(&rt, commit0_txid_hex),
                "breach tx in mempool");
    int conf_before = regtest_get_confirmations(&rt, commit0_txid_hex);
    printf("  Breach confirmations before check: %d (expected <1)\n", conf_before);

    /* Watchtower detects breach from mempool — on regtest it auto-mines */
    int penalties = watchtower_check(&wt);
    TEST_ASSERT(penalties > 0,
                "watchtower detected mempool-only breach and broadcast penalty");
    printf("  Watchtower detected mempool breach! Broadcast %d penalty tx(s)\n",
           penalties);

    /* Mine to confirm penalty */
    regtest_mine_blocks(&rt, 1, mine_addr);
    watchtower_check(&wt);
    TEST_ASSERT(wt.n_pending == 0, "penalty confirmed and cleared");
    printf("  Mempool breach → penalty confirmed!\n");

    tx_buf_free(&commit0_unsigned);
    tx_buf_free(&commit0_signed);
    watchtower_cleanup(&wt);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Adversarial Test 2: Watchtower detects breach after being offline.
   Breach is already confirmed on-chain when watchtower first checks. */
int test_regtest_watchtower_late_detection(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }
    regtest_create_wallet(&rt, "test_late_wt");

    char mine_addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)),
                "get mining address");
    if (!regtest_fund_from_faucet(&rt, 0.01))
        regtest_mine_for_balance(&rt, 0.002, mine_addr);

    /* Set up 2-of-2 MuSig funding UTXO */
    secp256k1_keypair kps[2];
    musig_keyagg_t keyagg;
    char factory_addr[128];
    char funding_txid_hex[65];
    int found_vout = -1;
    uint64_t fund_amount;
    unsigned char fund_spk[34];
    size_t fund_spk_len;

    TEST_ASSERT(setup_factory(&rt, ctx, kps, &keyagg, factory_addr,
                                funding_txid_hex, &found_vout,
                                &fund_amount, fund_spk, &fund_spk_len),
                "factory setup");

    unsigned char fund_txid_bytes[32];
    hex_decode(funding_txid_hex, fund_txid_bytes, 32);
    reverse_bytes(fund_txid_bytes, 32);

    /* Set up LSP + client channels */
    secp256k1_pubkey lsp_pk, client_pk;
    if (!secp256k1_keypair_pub(ctx, &lsp_pk, &kps[0])) return 0;
    if (!secp256k1_keypair_pub(ctx, &client_pk, &kps[1])) return 0;

    fee_estimator_t fe;
    fee_init(&fe, 1000);
    uint64_t commit_fee = fee_for_commitment_tx(&fe, 0);
    uint64_t usable = fund_amount > commit_fee ? fund_amount - commit_fee : fund_amount;
    uint64_t local_amt = usable / 2;
    uint64_t remote_amt = usable - local_amt;
    uint32_t csv_delay = 6;

    /* LSP channel */
    channel_t lsp_ch;
    TEST_ASSERT(channel_init(&lsp_ch, ctx, lsp_seckey, &lsp_pk, &client_pk,
                               fund_txid_bytes, (uint32_t)found_vout, fund_amount,
                               fund_spk, fund_spk_len, local_amt, remote_amt, csv_delay),
                "init LSP channel");
    channel_generate_random_basepoints(&lsp_ch);

    /* Client channel */
    channel_t client_ch;
    TEST_ASSERT(channel_init(&client_ch, ctx, client_seckey, &client_pk, &lsp_pk,
                               fund_txid_bytes, (uint32_t)found_vout, fund_amount,
                               fund_spk, fund_spk_len, remote_amt, local_amt, csv_delay),
                "init client channel");
    channel_generate_random_basepoints(&client_ch);

    /* Exchange basepoints */
    channel_set_remote_basepoints(&lsp_ch,
        &client_ch.local_payment_basepoint,
        &client_ch.local_delayed_payment_basepoint,
        &client_ch.local_revocation_basepoint);
    channel_set_remote_basepoints(&client_ch,
        &lsp_ch.local_payment_basepoint,
        &lsp_ch.local_delayed_payment_basepoint,
        &lsp_ch.local_revocation_basepoint);
    channel_set_remote_htlc_basepoint(&lsp_ch, &client_ch.local_htlc_basepoint);
    channel_set_remote_htlc_basepoint(&client_ch, &lsp_ch.local_htlc_basepoint);

    /* Exchange per-commitment points */
    secp256k1_pubkey lsp_pcp0, lsp_pcp1, client_pcp0, client_pcp1;
    channel_get_per_commitment_point(&lsp_ch, 0, &lsp_pcp0);
    channel_get_per_commitment_point(&lsp_ch, 1, &lsp_pcp1);
    channel_get_per_commitment_point(&client_ch, 0, &client_pcp0);
    channel_get_per_commitment_point(&client_ch, 1, &client_pcp1);
    channel_set_remote_pcp(&lsp_ch, 0, &client_pcp0);
    channel_set_remote_pcp(&lsp_ch, 1, &client_pcp1);
    channel_set_remote_pcp(&client_ch, 0, &lsp_pcp0);
    channel_set_remote_pcp(&client_ch, 1, &lsp_pcp1);

    /* Build + sign commitment #0 */
    tx_buf_t commit0_unsigned;
    tx_buf_init(&commit0_unsigned, 512);
    unsigned char commit0_txid[32];
    TEST_ASSERT(channel_build_commitment_tx(&lsp_ch, &commit0_unsigned, commit0_txid),
                "build commitment #0");

    tx_buf_t commit0_signed;
    tx_buf_init(&commit0_signed, 1024);
    TEST_ASSERT(channel_sign_commitment(&lsp_ch, &commit0_signed, &commit0_unsigned,
                                          &kps[1]),
                "sign commitment #0");

    /* Advance to commitment #1, revoke #0 */
    channel_generate_local_pcs(&lsp_ch, 1);
    channel_generate_local_pcs(&client_ch, 1);

    secp256k1_pubkey lsp_pcp2, client_pcp2;
    channel_get_per_commitment_point(&lsp_ch, 2, &lsp_pcp2);
    channel_get_per_commitment_point(&client_ch, 2, &client_pcp2);
    channel_set_remote_pcp(&lsp_ch, 2, &client_pcp2);
    channel_set_remote_pcp(&client_ch, 2, &lsp_pcp2);

    lsp_ch.commitment_number = 1;
    client_ch.commitment_number = 1;

    unsigned char lsp_secret0[32], client_secret0[32];
    channel_get_revocation_secret(&lsp_ch, 0, lsp_secret0);
    channel_get_revocation_secret(&client_ch, 0, client_secret0);
    channel_receive_revocation(&lsp_ch, 0, client_secret0);
    channel_receive_revocation(&client_ch, 0, lsp_secret0);

    /* Register commitment #0 with watchtower */
    watchtower_t wt;
    watchtower_init(&wt, 1, &rt, &fe, NULL);
    watchtower_set_channel(&wt, 0, &client_ch);

    tx_buf_t remote_commit0;
    tx_buf_init(&remote_commit0, 512);
    unsigned char remote_commit0_txid[32];
    client_ch.commitment_number = 0;
    channel_build_commitment_tx_for_remote(&client_ch, &remote_commit0, remote_commit0_txid);
    client_ch.commitment_number = 1;

    unsigned char breach_to_local_spk[34];
    memcpy(breach_to_local_spk, remote_commit0.data + 47 + 8 + 1, 34);
    tx_buf_free(&remote_commit0);

    TEST_ASSERT(watchtower_watch(&wt, 0, 0, commit0_txid,
                                   0, local_amt, breach_to_local_spk, 34),
                "register commitment for watching");

    /* BREACH: broadcast revoked commitment #0 */
    char *commit0_hex = (char *)malloc(commit0_signed.len * 2 + 1);
    hex_encode(commit0_signed.data, commit0_signed.len, commit0_hex);
    char commit0_txid_hex[65];
    int sent = regtest_send_raw_tx(&rt, commit0_hex, commit0_txid_hex);
    free(commit0_hex);
    TEST_ASSERT(sent, "broadcast revoked commitment #0");
    printf("  BREACH broadcast: %s\n", commit0_txid_hex);

    /* Mine 3 blocks — breach is ALREADY CONFIRMED before watchtower checks */
    regtest_mine_blocks(&rt, 3, mine_addr);
    int conf = regtest_get_confirmations(&rt, commit0_txid_hex);
    TEST_ASSERT(conf >= 3, "breach has 3+ confirmations");
    printf("  Breach confirmed with %d blocks (watchtower was offline)\n", conf);

    /* NOW watchtower comes online and checks for the first time */
    int penalties = watchtower_check(&wt);
    TEST_ASSERT(penalties > 0, "watchtower detected breach despite being late");
    printf("  Late watchtower detected breach! Broadcast %d penalty tx(s)\n", penalties);

    /* Mine and verify penalty confirms */
    regtest_mine_blocks(&rt, 1, mine_addr);
    watchtower_check(&wt);
    TEST_ASSERT(wt.n_pending == 0, "penalty confirmed and cleared");
    printf("  Late watchtower penalty confirmed!\n");

    tx_buf_free(&commit0_unsigned);
    tx_buf_free(&commit0_signed);
    watchtower_cleanup(&wt);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test fee_update_from_node against real bitcoind.
   On fresh regtest, estimatesmartfee returns errors (insufficient data).
   After generating some transactions, it may return a valid feerate.
   Either way, this exercises the real JSON parsing path. */
int test_regtest_fee_estimation_parsing(void) {
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: bitcoind not running\n");
        return 0;
    }
    regtest_create_wallet(&rt, "test_fee_est");

    char mine_addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)),
                "get mining address");
    if (!regtest_fund_from_faucet(&rt, 0.1))
        regtest_mine_blocks(&rt, 101, mine_addr);

    fee_estimator_t fe;
    fee_init(&fe, 5000);  /* 5 sat/vB default */
    TEST_ASSERT(fe.fee_rate_sat_per_kvb == 5000, "initial rate");

    /* estimatesmartfee on fresh regtest typically returns errors (insufficient
       data) — verify the function handles this gracefully (returns 0, rate
       unchanged). */
    int updated = fee_update_from_node(&fe, &rt, 6);
    if (!updated) {
        /* Expected: insufficient data, rate unchanged */
        TEST_ASSERT(fe.fee_rate_sat_per_kvb == 5000,
                    "rate unchanged on insufficient data");
        printf("  estimatesmartfee returned insufficient data (expected on fresh regtest)\n");
    } else {
        /* If we got a rate, verify it's reasonable (clamped >= 1000) */
        TEST_ASSERT(fe.fee_rate_sat_per_kvb >= 1000,
                    "rate clamped to minimum 1000");
        printf("  estimatesmartfee returned rate: %llu sat/kvB\n",
               (unsigned long long)fe.fee_rate_sat_per_kvb);
    }

    /* Generate some transactions to give estimatesmartfee data */
    for (int i = 0; i < 5; i++) {
        char addr[128];
        if (regtest_get_new_address(&rt, addr, sizeof(addr)))
            regtest_fund_address(&rt, addr, 0.001, NULL);
    }
    regtest_mine_blocks(&rt, 6, mine_addr);

    /* Try again — may or may not have enough data depending on bitcoind version */
    fee_estimator_t fe2;
    fee_init(&fe2, 9999);
    updated = fee_update_from_node(&fe2, &rt, 6);
    if (updated) {
        TEST_ASSERT(fe2.fee_rate_sat_per_kvb >= 1000,
                    "updated rate at least 1000");
        printf("  After txs: rate=%llu sat/kvB\n",
               (unsigned long long)fe2.fee_rate_sat_per_kvb);
    } else {
        printf("  Still insufficient data (normal on regtest)\n");
    }

    /* Verify fee calculation helpers work with either rate */
    uint64_t penalty_fee = fee_for_penalty_tx(&fe);
    TEST_ASSERT(penalty_fee > 0, "penalty fee > 0");
    uint64_t commit_fee = fee_for_commitment_tx(&fe, 2);
    TEST_ASSERT(commit_fee > penalty_fee, "commitment with HTLCs > penalty");
    printf("  Fee calcs: penalty=%llu, commitment(2htlc)=%llu\n",
           (unsigned long long)penalty_fee, (unsigned long long)commit_fee);

    return 1;
}
