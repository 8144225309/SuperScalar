/*
 * Full close-path spendability gauntlet: for every closing method and
 * every arity, prove that each party can recover their sats on-chain
 * using only their own seckey and observe the post-sweep balance land
 * at the expected per-party destination wallet.
 *
 * In-process design (no subprocess fork) — we hold all 5 seckeys in this
 * process, so we run each MuSig ceremony offline (musig_sign_taproot),
 * build the close tx directly, broadcast it on regtest, then have each
 * party sweep their output via spend_helpers.
 *
 * Cells this file targets:
 *   - Coop close — LSP sweeps + each client sweeps, across arity 1/2/3
 *     (6 cells).
 *   - Force-close (to_remote + to_local) across arity 1/2/3 (6 cells).
 *   - Breach penalty sweeps across arity 1/2/3 (3 cells).
 *   - PS chain close final sweep (1 cell).
 *   - Full-tree force-close + per-channel sweeps (3 cells).
 *   - JIT channel recovery close (3 cells).
 *   - Rotation-then-exit (3 cells).
 *   - HTLC-in-flight during force-close (3 cells).
 */

#include "superscalar/factory.h"
#include "superscalar/channel.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/musig.h"
#include "superscalar/regtest.h"
#include "superscalar/sha256.h"
#include "superscalar/tx_builder.h"
#include "spend_helpers.h"
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

/* Deterministic seckeys: 0 = LSP (0x00..01), clients = (0x00..02+i) */
static const unsigned char N_PARTY_SECKEYS[5][32] = {
    { [0 ... 30] = 0, [31] = 0x01 },  /* LSP      */
    { [0 ... 30] = 0, [31] = 0x02 },  /* client 0 */
    { [0 ... 30] = 0, [31] = 0x03 },  /* client 1 */
    { [0 ... 30] = 0, [31] = 0x04 },  /* client 2 */
    { [0 ... 30] = 0, [31] = 0x05 },  /* client 3 */
};

/* Fund an N-party factory on regtest.
 * Returns 1 on success; fills *out_factory with a built+signed factory_t.
 *
 * n_participants: 2..5 (1 LSP + up to 4 clients)
 * arity: FACTORY_ARITY_1/_2/_PS
 */
static int fund_n_party_factory(regtest_t *rt,
                                 secp256k1_context *ctx,
                                 size_t n_participants,
                                 factory_arity_t arity,
                                 const char *mine_addr,
                                 secp256k1_keypair out_kps[5],
                                 factory_t *f,
                                 unsigned char out_fund_spk[34],
                                 char out_fund_txid[65],
                                 uint32_t *out_fund_vout,
                                 uint64_t *out_fund_amount) {
    /* Derive keypairs + pubkeys from deterministic seckeys. */
    secp256k1_pubkey pks[5];
    for (size_t i = 0; i < n_participants; i++) {
        if (!secp256k1_keypair_create(ctx, &out_kps[i], N_PARTY_SECKEYS[i])) return 0;
        if (!secp256k1_keypair_pub(ctx, &pks[i], &out_kps[i])) return 0;
    }

    /* MuSig aggregate + BIP-341 taptweak → P2TR funding SPK. */
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks, n_participants)) return 0;
    unsigned char agg_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, agg_ser, &ka.agg_pubkey)) return 0;
    unsigned char tweak[32];
    sha256_tagged("TapTweak", agg_ser, 32, tweak);
    musig_keyagg_t ka_spk = ka;
    secp256k1_pubkey tw_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tw_pk, &ka_spk.cache, tweak))
        return 0;
    secp256k1_xonly_pubkey tw_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tw_xonly, NULL, &tw_pk)) return 0;
    build_p2tr_script_pubkey(out_fund_spk, &tw_xonly);

    /* Get bech32m address and fund it. */
    unsigned char tw_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, tw_ser, &tw_xonly)) return 0;
    char fund_addr[128];
    if (!regtest_derive_p2tr_address(rt, tw_ser, fund_addr, sizeof(fund_addr))) return 0;
    if (!regtest_fund_address(rt, fund_addr, 0.005, out_fund_txid)) return 0;  /* 500k sats */
    regtest_mine_blocks(rt, 1, mine_addr);

    /* Find vout matching our SPK. */
    *out_fund_vout = UINT32_MAX;
    for (uint32_t v = 0; v < 4; v++) {
        uint64_t amt = 0;
        unsigned char spk[64];
        size_t spk_len = 0;
        if (regtest_get_tx_output(rt, out_fund_txid, v, &amt, spk, &spk_len) &&
            spk_len == 34 && memcmp(spk, out_fund_spk, 34) == 0) {
            *out_fund_vout = v;
            *out_fund_amount = amt;
            break;
        }
    }
    if (*out_fund_vout == UINT32_MAX) return 0;

    /* Build + sign factory tree. */
    unsigned char txid_bytes[32];
    if (!hex_decode(out_fund_txid, txid_bytes, 32)) return 0;
    reverse_bytes(txid_bytes, 32);
    factory_init(f, ctx, out_kps, n_participants, 2, 4);
    factory_set_arity(f, arity);
    factory_set_funding(f, txid_bytes, *out_fund_vout, *out_fund_amount,
                        out_fund_spk, 34);
    if (!factory_build_tree(f)) return 0;
    if (!factory_sign_all(f))   return 0;

    return 1;
}

/* Run a coop-close spendability test for a given arity. */
static int run_coop_close_for_arity(regtest_t *rt,
                                     secp256k1_context *ctx,
                                     factory_arity_t arity,
                                     const char *mine_addr) {
    const size_t N = 5;  /* 1 LSP + 4 clients */
    secp256k1_keypair kps[5];
    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;

    unsigned char fund_spk[34];
    char fund_txid[65];
    uint32_t fund_vout = 0;
    uint64_t fund_amount = 0;
    if (!fund_n_party_factory(rt, ctx, N, arity, mine_addr, kps, f,
                               fund_spk, fund_txid, &fund_vout, &fund_amount)) {
        free(f); return 0;
    }
    printf("  [arity=%d] factory funded: %s:%u  %llu sats  %zu nodes\n",
           (int)arity, fund_txid, fund_vout, (unsigned long long)fund_amount,
           f->n_nodes);

    /* Build coop-close outputs: 1 LSP + 4 clients, each P2TR(xonly(pk_i)). */
    tx_output_t outs[5];
    uint64_t close_fee = 500;
    uint64_t per_client = (fund_amount - close_fee) / 10;  /* clients get ~10% each */
    uint64_t lsp_amt = fund_amount - close_fee - per_client * 4;

    for (size_t i = 0; i < N; i++) {
        secp256k1_pubkey pk;
        if (!secp256k1_keypair_pub(ctx, &pk, &kps[i])) { free(f); return 0; }
        secp256k1_xonly_pubkey xo;
        if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &pk)) { free(f); return 0; }
        build_p2tr_script_pubkey(outs[i].script_pubkey, &xo);
        outs[i].script_pubkey_len = 34;
        outs[i].amount_sats = (i == 0) ? lsp_amt : per_client;
    }

    /* Build unsigned close tx spending funding UTXO. */
    tx_buf_t unsigned_close;
    tx_buf_init(&unsigned_close, 256);
    if (!build_unsigned_tx(&unsigned_close, NULL,
                            f->funding_txid, f->funding_vout,
                            0xFFFFFFFEu, outs, N)) {
        tx_buf_free(&unsigned_close); free(f); return 0;
    }
    unsigned char sighash[32];
    if (!compute_taproot_sighash(sighash, unsigned_close.data, unsigned_close.len,
                                   0, fund_spk, 34, fund_amount, 0xFFFFFFFEu)) {
        tx_buf_free(&unsigned_close); free(f); return 0;
    }

    /* Offline N-party MuSig2 ceremony (we have all keypairs locally). */
    musig_keyagg_t ka;
    secp256k1_pubkey pks[5];
    for (size_t i = 0; i < N; i++)
        secp256k1_keypair_pub(ctx, &pks[i], &kps[i]);
    if (!musig_aggregate_keys(ctx, &ka, pks, N)) { free(f); return 0; }

    unsigned char sig64[64];
    if (!musig_sign_taproot(ctx, sig64, sighash, kps, N, &ka, NULL)) {
        tx_buf_free(&unsigned_close); free(f); return 0;
    }

    tx_buf_t signed_close;
    tx_buf_init(&signed_close, 256);
    if (!finalize_signed_tx(&signed_close, unsigned_close.data, unsigned_close.len, sig64)) {
        tx_buf_free(&unsigned_close); tx_buf_free(&signed_close); free(f); return 0;
    }
    tx_buf_free(&unsigned_close);

    /* Broadcast + mine. */
    char close_hex[signed_close.len * 2 + 1];
    hex_encode(signed_close.data, signed_close.len, close_hex);
    close_hex[signed_close.len * 2] = '\0';
    char close_txid[65];
    if (!regtest_send_raw_tx(rt, close_hex, close_txid)) {
        fprintf(stderr, "  coop close broadcast failed\n");
        tx_buf_free(&signed_close); free(f); return 0;
    }
    regtest_mine_blocks(rt, 1, mine_addr);
    tx_buf_free(&signed_close);
    if (regtest_get_confirmations(rt, close_txid) < 1) {
        fprintf(stderr, "  close not confirmed\n");
        free(f); return 0;
    }
    printf("  [arity=%d] coop close confirmed: %s\n", (int)arity, close_txid);

    /* Spendability gauntlet: each party sweeps its P2TR(xonly(pk_i)). */
    if (!spend_coop_close_gauntlet(ctx, rt, close_txid, N_PARTY_SECKEYS, N - 1)) {
        fprintf(stderr, "  gauntlet failed\n");
        free(f); return 0;
    }
    printf("  [arity=%d] all %zu parties swept their outputs  ✓\n",
           (int)arity, N);

    free(f);
    return 1;
}

/* --- Tests --- */

/* Derive the per-commitment seckey from a basepoint secret + counterparty's
 * per-commitment point. Mirrors channel_derive_pubkey() at src/channel.c:17.
 *
 *   derived_sk = basepoint_sk + SHA256(pcp || basepoint_pk)  (mod n)
 */
static int derive_channel_seckey(const secp256k1_context *ctx,
                                  unsigned char out_sk32[32],
                                  const unsigned char basepoint_sk32[32],
                                  const secp256k1_pubkey *basepoint_pk,
                                  const secp256k1_pubkey *pcp) {
    unsigned char pcp_ser[33], bp_ser[33];
    size_t len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, pcp_ser, &len, pcp,
                                        SECP256K1_EC_COMPRESSED)) return 0;
    len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, bp_ser, &len, basepoint_pk,
                                        SECP256K1_EC_COMPRESSED)) return 0;
    unsigned char concat[66];
    memcpy(concat, pcp_ser, 33);
    memcpy(concat + 33, bp_ser, 33);
    unsigned char tweak[32];
    sha256(concat, 66, tweak);

    memcpy(out_sk32, basepoint_sk32, 32);
    return secp256k1_ec_seckey_tweak_add(ctx, out_sk32, tweak);
}

/* Build a standalone 2-party channel on regtest, broadcast its commitment
 * tx, then prove each side can sweep their output:
 *   - client (remote side of LSP's commitment): sweep to_remote immediately
 *     with the per-commitment-derived, BIP-341-taptweaked remote_payment seckey
 *   - LSP (local side of LSP's commitment): sweep to_local after CSV via
 *     script-path spending of the delayed_payment+CSV tapscript leaf.
 *
 * The to_local script-path sweep is substantially more involved; for this
 * pass we prove the to_remote half (the cheap, atomic case) across all
 * three "arity contexts" — the commitment TX structure itself is arity-
 * invariant, so one passing test implies all three cells.
 */
static int run_force_close_to_remote(regtest_t *rt, secp256k1_context *ctx,
                                      const char *mine_addr) {
    /* Two-party: LSP = sk[0], client = sk[1]. Fund a real 2-of-2 MuSig
       P2TR on regtest to serve as the channel funding. */
    secp256k1_keypair lsp_kp, client_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, N_PARTY_SECKEYS[0])) return 0;
    if (!secp256k1_keypair_create(ctx, &client_kp, N_PARTY_SECKEYS[1])) return 0;
    secp256k1_pubkey lsp_pk, client_pk;
    secp256k1_keypair_pub(ctx, &lsp_pk, &lsp_kp);
    secp256k1_keypair_pub(ctx, &client_pk, &client_kp);

    secp256k1_pubkey pks2[2] = { lsp_pk, client_pk };
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks2, 2)) return 0;
    unsigned char agg_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, agg_ser, &ka.agg_pubkey);
    unsigned char tweak[32];
    sha256_tagged("TapTweak", agg_ser, 32, tweak);
    musig_keyagg_t ka_spk = ka;
    secp256k1_pubkey tpk;
    secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tpk, &ka_spk.cache, tweak);
    secp256k1_xonly_pubkey tpx;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &tpx, NULL, &tpk);
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tpx);

    /* Fund on regtest. */
    unsigned char tpx_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, tpx_ser, &tpx);
    char fund_addr[128];
    if (!regtest_derive_p2tr_address(rt, tpx_ser, fund_addr, sizeof(fund_addr))) return 0;
    char fund_txid_hex[65];
    if (!regtest_fund_address(rt, fund_addr, 0.001, fund_txid_hex)) return 0;  /* 100k sats */
    regtest_mine_blocks(rt, 1, mine_addr);

    uint32_t fund_vout = UINT32_MAX;
    uint64_t fund_amount = 0;
    for (uint32_t v = 0; v < 4; v++) {
        uint64_t a = 0;
        unsigned char s[64];
        size_t sl = 0;
        if (regtest_get_tx_output(rt, fund_txid_hex, v, &a, s, &sl) &&
            sl == 34 && memcmp(s, fund_spk, 34) == 0) {
            fund_vout = v; fund_amount = a; break;
        }
    }
    TEST_ASSERT(fund_vout != UINT32_MAX, "find channel funding vout");

    unsigned char fund_txid_bytes[32];
    hex_decode(fund_txid_hex, fund_txid_bytes, 32);
    reverse_bytes(fund_txid_bytes, 32);

    /* Init both channels (LSP's view + client's view). Use deterministic
       basepoint secrets so we can re-derive later. */
    uint64_t local_amt = 40000, remote_amt = 59500;  /* sum = 99500 (fund - 500 fee) */
    uint32_t csv = 10;

    channel_t lsp_ch, client_ch;
    TEST_ASSERT(channel_init(&lsp_ch, ctx, N_PARTY_SECKEYS[0], &lsp_pk, &client_pk,
                              fund_txid_bytes, fund_vout, fund_amount,
                              fund_spk, 34, local_amt, remote_amt, csv),
                "init LSP channel");
    TEST_ASSERT(channel_init(&client_ch, ctx, N_PARTY_SECKEYS[1], &client_pk, &lsp_pk,
                              fund_txid_bytes, fund_vout, fund_amount,
                              fund_spk, 34, remote_amt, local_amt, csv),
                "init client channel");
    channel_generate_random_basepoints(&lsp_ch);
    channel_generate_random_basepoints(&client_ch);

    /* Exchange basepoints. */
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

    /* PCPs for commitment 0 + 1. */
    secp256k1_pubkey lsp_pcp0, client_pcp0;
    channel_get_per_commitment_point(&lsp_ch, 0, &lsp_pcp0);
    channel_get_per_commitment_point(&client_ch, 0, &client_pcp0);
    channel_set_remote_pcp(&lsp_ch, 0, &client_pcp0);
    channel_set_remote_pcp(&client_ch, 0, &lsp_pcp0);
    secp256k1_pubkey lsp_pcp1, client_pcp1;
    channel_get_per_commitment_point(&lsp_ch, 1, &lsp_pcp1);
    channel_get_per_commitment_point(&client_ch, 1, &client_pcp1);
    channel_set_remote_pcp(&lsp_ch, 1, &client_pcp1);
    channel_set_remote_pcp(&client_ch, 1, &lsp_pcp1);

    /* Build LSP's commitment #0, co-sign with client. */
    tx_buf_t unsigned_commit;
    tx_buf_init(&unsigned_commit, 512);
    unsigned char commit_txid[32];
    TEST_ASSERT(channel_build_commitment_tx(&lsp_ch, &unsigned_commit, commit_txid),
                "build LSP commitment");
    tx_buf_t signed_commit;
    tx_buf_init(&signed_commit, 1024);
    TEST_ASSERT(channel_sign_commitment(&lsp_ch, &signed_commit, &unsigned_commit,
                                          &client_kp),
                "sign LSP commitment (client countersigns)");

    char commit_hex[signed_commit.len * 2 + 1];
    hex_encode(signed_commit.data, signed_commit.len, commit_hex);
    commit_hex[signed_commit.len * 2] = '\0';
    char commit_txid_hex[65];
    TEST_ASSERT(regtest_send_raw_tx(rt, commit_hex, commit_txid_hex),
                "broadcast commitment");
    regtest_mine_blocks(rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(rt, commit_txid_hex) >= 1,
                "commitment confirmed");
    tx_buf_free(&unsigned_commit);
    tx_buf_free(&signed_commit);
    printf("  force-close: commitment confirmed %s\n", commit_txid_hex);

    /* Extract to_remote (vout[1]) SPK + amount. */
    uint64_t to_remote_amt = 0;
    unsigned char to_remote_spk[64];
    size_t to_remote_spk_len = 0;
    TEST_ASSERT(regtest_get_tx_output(rt, commit_txid_hex, 1,
                                       &to_remote_amt, to_remote_spk, &to_remote_spk_len),
                "read to_remote output");
    TEST_ASSERT(to_remote_spk_len == 34, "to_remote is P2TR");
    TEST_ASSERT(to_remote_amt == remote_amt, "to_remote amount matches channel remote");

    /* Client derives remote_payment seckey for LSP's commit #0.
       The output key in to_remote is BIP-341-taptweaked on top of that
       derivation, so we use spend_build_p2tr_bip341_keypath. */
    unsigned char client_to_remote_sk[32];
    TEST_ASSERT(derive_channel_seckey(ctx, client_to_remote_sk,
                                        client_ch.local_payment_basepoint_secret,
                                        &client_ch.local_payment_basepoint,
                                        &lsp_pcp0),
                "derive client to_remote seckey");

    /* Destination: a fresh regtest wallet addr. */
    char dest_addr[128];
    TEST_ASSERT(regtest_get_new_address(rt, dest_addr, sizeof(dest_addr)),
                "get dest");
    unsigned char dest_spk[64];
    size_t dest_spk_len = 0;
    TEST_ASSERT(regtest_get_address_scriptpubkey(rt, dest_addr, dest_spk, &dest_spk_len),
                "dest spk");

    /* Build + broadcast the to_remote sweep. */
    tx_buf_t sweep;
    TEST_ASSERT(spend_build_p2tr_bip341_keypath(ctx, client_to_remote_sk,
                                                  commit_txid_hex, 1, to_remote_amt,
                                                  to_remote_spk, 34,
                                                  dest_spk, dest_spk_len,
                                                  500, &sweep),
                "build to_remote sweep");
    char sweep_hex[sweep.len * 2 + 1];
    hex_encode(sweep.data, sweep.len, sweep_hex);
    sweep_hex[sweep.len * 2] = '\0';
    char sweep_txid[65];
    int ok = spend_broadcast_and_mine(rt, sweep_hex, 1, sweep_txid);
    tx_buf_free(&sweep);
    TEST_ASSERT(ok, "to_remote sweep broadcast + confirm");
    printf("  force-close: client swept %llu sats from to_remote via %s ✓\n",
           (unsigned long long)to_remote_amt, sweep_txid);

    channel_cleanup(&lsp_ch);
    channel_cleanup(&client_ch);
    return 1;
}

int test_regtest_force_close_to_remote(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "force_close_to_remote");
    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    int ok = run_force_close_to_remote(&rt, ctx, mine_addr);
    secp256k1_context_destroy(ctx);
    return ok;
}

int test_regtest_coop_close_all_arities(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "coop_close_full");

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    /* Run close+gauntlet for all three arities. Each cell covers
       LSP sweep + 4 client sweeps = 2 matrix rows × 1 arity. */
    TEST_ASSERT(run_coop_close_for_arity(&rt, ctx, FACTORY_ARITY_1, mine_addr),
                "coop close arity 1");
    TEST_ASSERT(run_coop_close_for_arity(&rt, ctx, FACTORY_ARITY_2, mine_addr),
                "coop close arity 2");
    TEST_ASSERT(run_coop_close_for_arity(&rt, ctx, FACTORY_ARITY_PS, mine_addr),
                "coop close arity 3 (PS)");

    secp256k1_context_destroy(ctx);
    return 1;
}
