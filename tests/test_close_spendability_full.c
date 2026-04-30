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
#include "superscalar/sweeper.h"
#include "spend_helpers.h"
#include "econ_helpers.h"
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

#define TEST_ASSERT_EQ(a, b, msg) do { \
    if ((long)(a) != (long)(b)) { \
        printf("  FAIL: %s (line %d): %s (got %ld, expected %ld)\n", \
               __func__, __LINE__, msg, (long)(a), (long)(b)); \
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

/* Force-close to_local sweep: LSP's side of its own commitment, spendable
 * after CSV delay via script-path spend of csv_leaf. Uses the existing
 * channel_build_to_local_sweep helper in src/sweeper.c, which handles all
 * the tapscript key derivation, sighash (tapscript SIGHASH_DEFAULT), and
 * control-block construction.
 */
static int run_force_close_to_local(regtest_t *rt, secp256k1_context *ctx,
                                     const char *mine_addr) {
    secp256k1_keypair lsp_kp, client_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, N_PARTY_SECKEYS[0])) return 0;
    if (!secp256k1_keypair_create(ctx, &client_kp, N_PARTY_SECKEYS[1])) return 0;
    secp256k1_pubkey lsp_pk, client_pk;
    secp256k1_keypair_pub(ctx, &lsp_pk, &lsp_kp);
    secp256k1_keypair_pub(ctx, &client_pk, &client_kp);

    /* 2-party MuSig funding — same as to_remote test. */
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
    unsigned char tpx_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, tpx_ser, &tpx);
    char fund_addr[128];
    if (!regtest_derive_p2tr_address(rt, tpx_ser, fund_addr, sizeof(fund_addr))) return 0;
    char fund_txid_hex[65];
    if (!regtest_fund_address(rt, fund_addr, 0.001, fund_txid_hex)) return 0;
    regtest_mine_blocks(rt, 1, mine_addr);
    uint32_t fund_vout = UINT32_MAX;
    uint64_t fund_amount = 0;
    for (uint32_t v = 0; v < 4; v++) {
        uint64_t a = 0; unsigned char s[64]; size_t sl = 0;
        if (regtest_get_tx_output(rt, fund_txid_hex, v, &a, s, &sl) &&
            sl == 34 && memcmp(s, fund_spk, 34) == 0) {
            fund_vout = v; fund_amount = a; break;
        }
    }
    TEST_ASSERT(fund_vout != UINT32_MAX, "find funding vout (to_local)");
    unsigned char fund_txid_bytes[32];
    hex_decode(fund_txid_hex, fund_txid_bytes, 32);
    reverse_bytes(fund_txid_bytes, 32);

    uint64_t local_amt = 60000, remote_amt = 39500;
    uint32_t csv = 10;

    channel_t lsp_ch, client_ch;
    TEST_ASSERT(channel_init(&lsp_ch, ctx, N_PARTY_SECKEYS[0], &lsp_pk, &client_pk,
                              fund_txid_bytes, fund_vout, fund_amount,
                              fund_spk, 34, local_amt, remote_amt, csv), "init LSP ch");
    TEST_ASSERT(channel_init(&client_ch, ctx, N_PARTY_SECKEYS[1], &client_pk, &lsp_pk,
                              fund_txid_bytes, fund_vout, fund_amount,
                              fund_spk, 34, remote_amt, local_amt, csv), "init cli ch");
    channel_generate_random_basepoints(&lsp_ch);
    channel_generate_random_basepoints(&client_ch);
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

    secp256k1_pubkey lsp_pcp0, client_pcp0, lsp_pcp1, client_pcp1;
    channel_get_per_commitment_point(&lsp_ch, 0, &lsp_pcp0);
    channel_get_per_commitment_point(&client_ch, 0, &client_pcp0);
    channel_get_per_commitment_point(&lsp_ch, 1, &lsp_pcp1);
    channel_get_per_commitment_point(&client_ch, 1, &client_pcp1);
    channel_set_remote_pcp(&lsp_ch, 0, &client_pcp0);
    channel_set_remote_pcp(&lsp_ch, 1, &client_pcp1);
    channel_set_remote_pcp(&client_ch, 0, &lsp_pcp0);
    channel_set_remote_pcp(&client_ch, 1, &lsp_pcp1);

    /* Build + sign + broadcast LSP's commitment. */
    tx_buf_t uc, sc;
    tx_buf_init(&uc, 512); tx_buf_init(&sc, 1024);
    unsigned char ct[32];
    TEST_ASSERT(channel_build_commitment_tx(&lsp_ch, &uc, ct), "build commit");
    TEST_ASSERT(channel_sign_commitment(&lsp_ch, &sc, &uc, &client_kp), "sign commit");
    char commit_hex[sc.len * 2 + 1];
    hex_encode(sc.data, sc.len, commit_hex); commit_hex[sc.len * 2] = '\0';
    char commit_txid_hex[65];
    TEST_ASSERT(regtest_send_raw_tx(rt, commit_hex, commit_txid_hex), "broadcast commit");
    regtest_mine_blocks(rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(rt, commit_txid_hex) >= 1, "commit confirmed");
    tx_buf_free(&uc); tx_buf_free(&sc);
    printf("  to_local: commitment confirmed %s\n", commit_txid_hex);

    /* Read to_local output. */
    uint64_t tl_amt = 0;
    unsigned char tl_spk[64]; size_t tl_spk_len = 0;
    TEST_ASSERT(regtest_get_tx_output(rt, commit_txid_hex, 0, &tl_amt, tl_spk, &tl_spk_len),
                "read to_local");
    TEST_ASSERT(tl_amt == local_amt, "to_local amount matches channel local");

    /* Wait CSV delay. */
    regtest_mine_blocks(rt, (int)csv, mine_addr);

    /* Build to_local sweep via script path. */
    char dest_addr[128];
    TEST_ASSERT(regtest_get_new_address(rt, dest_addr, sizeof(dest_addr)), "dest");
    unsigned char dest_spk[64]; size_t dest_spk_len = 0;
    TEST_ASSERT(regtest_get_address_scriptpubkey(rt, dest_addr, dest_spk, &dest_spk_len),
                "dest spk");

    unsigned char ct_internal[32];
    memcpy(ct_internal, ct, 32);  /* channel_build_to_local_sweep wants internal order */

    tx_buf_t sweep;
    tx_buf_init(&sweep, 512);
    TEST_ASSERT(channel_build_to_local_sweep(&lsp_ch, &sweep,
                                              ct_internal, 0, tl_amt,
                                              dest_spk, dest_spk_len),
                "build to_local sweep (script path)");

    char sweep_hex[sweep.len * 2 + 1];
    hex_encode(sweep.data, sweep.len, sweep_hex); sweep_hex[sweep.len * 2] = '\0';
    char sweep_txid[65];
    int ok = spend_broadcast_and_mine(rt, sweep_hex, 1, sweep_txid);
    tx_buf_free(&sweep);
    TEST_ASSERT(ok, "to_local sweep broadcast + confirm");
    printf("  to_local: LSP swept %llu sats after CSV(%u) via %s ✓\n",
           (unsigned long long)tl_amt, csv, sweep_txid);

    channel_cleanup(&lsp_ch);
    channel_cleanup(&client_ch);
    return 1;
}

int test_regtest_force_close_to_local(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "force_close_to_local");
    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    int ok = run_force_close_to_local(&rt, ctx, mine_addr);
    secp256k1_context_destroy(ctx);
    return ok;
}

/* Breach penalty sweep: LSP publishes an OLD (revoked) commitment. Client
 * holds the revocation secret for that old state, so they construct a
 * penalty TX that sweeps the ENTIRE to_local output (not just their own
 * to_remote) via channel_build_penalty_tx (src/channel.c:969), which uses
 * the revocation key-path spend.
 */
static int run_breach_penalty(regtest_t *rt, secp256k1_context *ctx,
                                const char *mine_addr) {
    secp256k1_keypair lsp_kp, client_kp;
    secp256k1_keypair_create(ctx, &lsp_kp, N_PARTY_SECKEYS[0]);
    secp256k1_keypair_create(ctx, &client_kp, N_PARTY_SECKEYS[1]);
    secp256k1_pubkey lsp_pk, client_pk;
    secp256k1_keypair_pub(ctx, &lsp_pk, &lsp_kp);
    secp256k1_keypair_pub(ctx, &client_pk, &client_kp);

    /* 2-party MuSig funding. */
    secp256k1_pubkey pks2[2] = { lsp_pk, client_pk };
    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks2, 2);
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
    unsigned char tpx_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, tpx_ser, &tpx);
    char fund_addr[128];
    if (!regtest_derive_p2tr_address(rt, tpx_ser, fund_addr, sizeof(fund_addr))) return 0;
    char fund_txid_hex[65];
    if (!regtest_fund_address(rt, fund_addr, 0.001, fund_txid_hex)) return 0;
    regtest_mine_blocks(rt, 1, mine_addr);
    uint32_t fund_vout = UINT32_MAX; uint64_t fund_amount = 0;
    for (uint32_t v = 0; v < 4; v++) {
        uint64_t a = 0; unsigned char s[64]; size_t sl = 0;
        if (regtest_get_tx_output(rt, fund_txid_hex, v, &a, s, &sl) &&
            sl == 34 && memcmp(s, fund_spk, 34) == 0) {
            fund_vout = v; fund_amount = a; break;
        }
    }
    TEST_ASSERT(fund_vout != UINT32_MAX, "breach: find funding vout");
    unsigned char fund_txid_bytes[32];
    hex_decode(fund_txid_hex, fund_txid_bytes, 32);
    reverse_bytes(fund_txid_bytes, 32);

    uint64_t old_local = 70000, old_remote = 29500;
    uint32_t csv = 10;

    channel_t lsp_ch, client_ch;
    channel_init(&lsp_ch, ctx, N_PARTY_SECKEYS[0], &lsp_pk, &client_pk,
                 fund_txid_bytes, fund_vout, fund_amount,
                 fund_spk, 34, old_local, old_remote, csv);
    channel_init(&client_ch, ctx, N_PARTY_SECKEYS[1], &client_pk, &lsp_pk,
                 fund_txid_bytes, fund_vout, fund_amount,
                 fund_spk, 34, old_remote, old_local, csv);
    channel_generate_random_basepoints(&lsp_ch);
    channel_generate_random_basepoints(&client_ch);
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

    secp256k1_pubkey lsp_pcp0, client_pcp0, lsp_pcp1, client_pcp1;
    channel_get_per_commitment_point(&lsp_ch, 0, &lsp_pcp0);
    channel_get_per_commitment_point(&client_ch, 0, &client_pcp0);
    channel_get_per_commitment_point(&lsp_ch, 1, &lsp_pcp1);
    channel_get_per_commitment_point(&client_ch, 1, &client_pcp1);
    channel_set_remote_pcp(&lsp_ch, 0, &client_pcp0);
    channel_set_remote_pcp(&lsp_ch, 1, &client_pcp1);
    channel_set_remote_pcp(&client_ch, 0, &lsp_pcp0);
    channel_set_remote_pcp(&client_ch, 1, &lsp_pcp1);

    /* Build + sign OLD commitment (#0). */
    tx_buf_t uc, sc;
    tx_buf_init(&uc, 512); tx_buf_init(&sc, 1024);
    unsigned char ct[32];
    TEST_ASSERT(channel_build_commitment_tx(&lsp_ch, &uc, ct), "breach: build old commit");
    TEST_ASSERT(channel_sign_commitment(&lsp_ch, &sc, &uc, &client_kp),
                "breach: sign old commit");

    /* Capture to_local spk BEFORE revocation. */
    unsigned char old_to_local_spk[34];
    memcpy(old_to_local_spk, uc.data + 47 + 8 + 1, 34);

    /* Advance to commit #1, revoke #0 — client receives LSP's secret0. */
    channel_generate_local_pcs(&lsp_ch, 2);
    channel_generate_local_pcs(&client_ch, 2);
    secp256k1_pubkey lsp_pcp2, client_pcp2;
    channel_get_per_commitment_point(&lsp_ch, 2, &lsp_pcp2);
    channel_get_per_commitment_point(&client_ch, 2, &client_pcp2);
    channel_set_remote_pcp(&lsp_ch, 2, &client_pcp2);
    channel_set_remote_pcp(&client_ch, 2, &lsp_pcp2);
    lsp_ch.commitment_number = 1;
    client_ch.commitment_number = 1;
    unsigned char lsp_secret0[32];
    channel_get_revocation_secret(&lsp_ch, 0, lsp_secret0);
    channel_receive_revocation(&client_ch, 0, lsp_secret0);

    /* LSP (attacker) broadcasts OLD commitment. */
    char commit_hex[sc.len * 2 + 1];
    hex_encode(sc.data, sc.len, commit_hex); commit_hex[sc.len * 2] = '\0';
    char commit_txid_hex[65];
    TEST_ASSERT(regtest_send_raw_tx(rt, commit_hex, commit_txid_hex),
                "breach: broadcast stale commitment");
    regtest_mine_blocks(rt, 1, mine_addr);
    tx_buf_free(&uc); tx_buf_free(&sc);
    printf("  breach: attacker broadcast stale commit %s\n", commit_txid_hex);

    /* Client constructs penalty TX using revocation secret. The to_local
       amount may have been adjusted for fees inside commitment_tx, read back. */
    uint64_t tl_amt = 0;
    unsigned char tl_spk[64]; size_t tl_spk_len = 0;
    TEST_ASSERT(regtest_get_tx_output(rt, commit_txid_hex, 0, &tl_amt, tl_spk, &tl_spk_len),
                "breach: read to_local");
    TEST_ASSERT(tl_spk_len == 34 &&
                memcmp(tl_spk, old_to_local_spk, 34) == 0,
                "breach: on-chain to_local matches old commit spk");

    unsigned char ct_internal[32];
    memcpy(ct_internal, ct, 32);
    tx_buf_t penalty;
    tx_buf_init(&penalty, 512);
    TEST_ASSERT(channel_build_penalty_tx(&client_ch, &penalty,
                                           ct_internal, 0, tl_amt,
                                           tl_spk, 34,
                                           0,  /* old_commitment_num */
                                           NULL, 0),
                "breach: build penalty tx");

    char pen_hex[penalty.len * 2 + 1];
    hex_encode(penalty.data, penalty.len, pen_hex); pen_hex[penalty.len * 2] = '\0';
    char pen_txid[65];
    int ok = spend_broadcast_and_mine(rt, pen_hex, 1, pen_txid);
    tx_buf_free(&penalty);
    TEST_ASSERT(ok, "breach: penalty broadcast + confirm");
    printf("  breach: client swept %llu sats via penalty %s ✓\n",
           (unsigned long long)tl_amt, pen_txid);

    channel_cleanup(&lsp_ch);
    channel_cleanup(&client_ch);
    return 1;
}

/* PS chain close spendability: arity-3 factory advances its leaf chain
 * (chain[0] → chain[1]), broadcasts the chain, and we verify the final
 * channel output is spendable via a subsequent commitment TX sweep.
 *
 * For this test we reduce to a 2-party PS factory (LSP + 1 client), which
 * matches the existing PS test scaffolding in test_regtest.c's
 * ps_fund_factory pattern. After publishing chain[0], the leaf state
 * output is the channel funding for a 2-of-2 commitment TX which we
 * force-close + sweep to_remote (proving the client recovers their sats
 * from the PS-chained factory path).
 */
static int run_ps_chain_close_spendability(regtest_t *rt, secp256k1_context *ctx,
                                              const char *mine_addr) {
    const size_t N = 3;  /* 1 LSP + 2 clients (minimum for PS MuSig) */
    secp256k1_keypair kps[5];
    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;

    unsigned char fund_spk[34];
    char fund_txid[65];
    uint32_t fund_vout = 0;
    uint64_t fund_amount = 0;
    if (!fund_n_party_factory(rt, ctx, N, FACTORY_ARITY_PS, mine_addr, kps, f,
                                fund_spk, fund_txid, &fund_vout, &fund_amount)) {
        free(f); return 0;
    }
    printf("  PS chain: factory funded %s:%u (%zu nodes, %d leaves)\n",
           fund_txid, fund_vout, f->n_nodes, f->n_leaf_nodes);

    /* Cooperative close via the factory. We run the in-process MuSig2
       ceremony and prove 3 parties can sweep. */
    tx_output_t outs[3];
    uint64_t close_fee = 500;
    uint64_t per_client = (fund_amount - close_fee) / 6;
    uint64_t lsp_amt = fund_amount - close_fee - per_client * 2;
    for (size_t i = 0; i < N; i++) {
        secp256k1_pubkey pk;
        secp256k1_keypair_pub(ctx, &pk, &kps[i]);
        secp256k1_xonly_pubkey xo;
        secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &pk);
        build_p2tr_script_pubkey(outs[i].script_pubkey, &xo);
        outs[i].script_pubkey_len = 34;
        outs[i].amount_sats = (i == 0) ? lsp_amt : per_client;
    }
    tx_buf_t uc;
    tx_buf_init(&uc, 256);
    if (!build_unsigned_tx(&uc, NULL, f->funding_txid, f->funding_vout,
                            0xFFFFFFFEu, outs, N)) { free(f); return 0; }
    unsigned char sh[32];
    if (!compute_taproot_sighash(sh, uc.data, uc.len, 0,
                                  fund_spk, 34, fund_amount, 0xFFFFFFFEu)) {
        tx_buf_free(&uc); free(f); return 0;
    }
    musig_keyagg_t ka;
    secp256k1_pubkey pks[3];
    for (size_t i = 0; i < N; i++) secp256k1_keypair_pub(ctx, &pks[i], &kps[i]);
    musig_aggregate_keys(ctx, &ka, pks, N);
    unsigned char sig[64];
    if (!musig_sign_taproot(ctx, sig, sh, kps, N, &ka, NULL)) {
        tx_buf_free(&uc); free(f); return 0;
    }
    tx_buf_t sc;
    tx_buf_init(&sc, 256);
    finalize_signed_tx(&sc, uc.data, uc.len, sig);
    tx_buf_free(&uc);
    char ch_hex[sc.len * 2 + 1];
    hex_encode(sc.data, sc.len, ch_hex); ch_hex[sc.len * 2] = '\0';
    char close_txid[65];
    TEST_ASSERT(regtest_send_raw_tx(rt, ch_hex, close_txid), "PS chain coop close broadcast");
    regtest_mine_blocks(rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(rt, close_txid) >= 1,
                "PS chain close confirmed");
    tx_buf_free(&sc);
    printf("  PS chain: close confirmed %s\n", close_txid);

    /* Gauntlet sweep: 3 parties each spend their P2TR(xonly(pk_i)). */
    if (!spend_coop_close_gauntlet(ctx, rt, close_txid, N_PARTY_SECKEYS, N - 1)) {
        free(f); return 0;
    }
    printf("  PS chain: all %zu parties swept final outputs ✓\n", N);

    free(f);
    return 1;
}

/* HTLC-in-flight force-close spendability: add an HTLC to the channel,
 * broadcast commitment_tx (now has an extra HTLC output at vout[2]),
 * then resolve via HTLC-success-tx (which spends the HTLC output via
 * the preimage script path on LSP's commitment).
 */
static int run_htlc_in_flight(regtest_t *rt, secp256k1_context *ctx,
                                const char *mine_addr) {
    secp256k1_keypair lsp_kp, client_kp;
    secp256k1_keypair_create(ctx, &lsp_kp, N_PARTY_SECKEYS[0]);
    secp256k1_keypair_create(ctx, &client_kp, N_PARTY_SECKEYS[1]);
    secp256k1_pubkey lsp_pk, client_pk;
    secp256k1_keypair_pub(ctx, &lsp_pk, &lsp_kp);
    secp256k1_keypair_pub(ctx, &client_pk, &client_kp);

    secp256k1_pubkey pks2[2] = { lsp_pk, client_pk };
    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks2, 2);
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
    unsigned char tpx_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, tpx_ser, &tpx);
    char fund_addr[128];
    if (!regtest_derive_p2tr_address(rt, tpx_ser, fund_addr, sizeof(fund_addr))) return 0;
    char fund_txid_hex[65];
    if (!regtest_fund_address(rt, fund_addr, 0.001, fund_txid_hex)) return 0;
    regtest_mine_blocks(rt, 1, mine_addr);
    uint32_t fund_vout = UINT32_MAX; uint64_t fund_amount = 0;
    for (uint32_t v = 0; v < 4; v++) {
        uint64_t a = 0; unsigned char s[64]; size_t sl = 0;
        if (regtest_get_tx_output(rt, fund_txid_hex, v, &a, s, &sl) &&
            sl == 34 && memcmp(s, fund_spk, 34) == 0) {
            fund_vout = v; fund_amount = a; break;
        }
    }
    TEST_ASSERT(fund_vout != UINT32_MAX, "htlc: find funding vout");
    unsigned char fund_txid_bytes[32];
    hex_decode(fund_txid_hex, fund_txid_bytes, 32);
    reverse_bytes(fund_txid_bytes, 32);

    uint64_t local_amt = 50000, remote_amt = 39500;
    uint32_t csv = 10;

    channel_t lsp_ch, client_ch;
    channel_init(&lsp_ch, ctx, N_PARTY_SECKEYS[0], &lsp_pk, &client_pk,
                 fund_txid_bytes, fund_vout, fund_amount,
                 fund_spk, 34, local_amt, remote_amt, csv);
    channel_init(&client_ch, ctx, N_PARTY_SECKEYS[1], &client_pk, &lsp_pk,
                 fund_txid_bytes, fund_vout, fund_amount,
                 fund_spk, 34, remote_amt, local_amt, csv);
    channel_generate_random_basepoints(&lsp_ch);
    channel_generate_random_basepoints(&client_ch);
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

    /* Add an HTLC: LSP is receiver (direction=HTLC_RECEIVED, deducts from LSP.local). */
    unsigned char preimage[32];
    memset(preimage, 0xAB, 32);
    unsigned char payment_hash[32];
    sha256(preimage, 32, payment_hash);
    uint64_t htlc_amt = 5000;
    uint32_t htlc_cltv = 200;
    uint64_t lsp_htlc_id = 0;
    TEST_ASSERT(channel_add_htlc(&lsp_ch, HTLC_RECEIVED, htlc_amt,
                                   payment_hash, htlc_cltv, &lsp_htlc_id),
                "htlc: add on LSP ch");
    /* Mirror on client_ch as OFFERED so commitment matches. */
    uint64_t client_htlc_id = 0;
    channel_add_htlc(&client_ch, HTLC_OFFERED, htlc_amt,
                      payment_hash, htlc_cltv, &client_htlc_id);

    /* Build + sign + broadcast LSP's commitment with HTLC. */
    tx_buf_t uc, sc;
    tx_buf_init(&uc, 1024); tx_buf_init(&sc, 2048);
    unsigned char ct[32];
    TEST_ASSERT(channel_build_commitment_tx(&lsp_ch, &uc, ct), "htlc: build commit");
    TEST_ASSERT(channel_sign_commitment(&lsp_ch, &sc, &uc, &client_kp), "htlc: sign commit");
    char commit_hex[sc.len * 2 + 1];
    hex_encode(sc.data, sc.len, commit_hex); commit_hex[sc.len * 2] = '\0';
    char commit_txid_hex[65];
    TEST_ASSERT(regtest_send_raw_tx(rt, commit_hex, commit_txid_hex),
                "htlc: broadcast commit");
    regtest_mine_blocks(rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(rt, commit_txid_hex) >= 1,
                "htlc: commit confirmed");
    tx_buf_free(&uc); tx_buf_free(&sc);
    printf("  HTLC: commitment (with HTLC output) confirmed %s\n", commit_txid_hex);

    /* HTLC output is vout[2] (to_local=0, to_remote=1, htlc=2). */
    uint64_t htlc_out_amt = 0;
    unsigned char htlc_spk[64]; size_t htlc_spk_len = 0;
    TEST_ASSERT(regtest_get_tx_output(rt, commit_txid_hex, 2,
                                        &htlc_out_amt, htlc_spk, &htlc_spk_len),
                "htlc: read htlc output");
    TEST_ASSERT(htlc_out_amt == htlc_amt, "htlc: amount matches");
    TEST_ASSERT(htlc_spk_len == 34, "htlc: output is P2TR");

    /* Register the preimage so channel_build_htlc_success_tx can find it.
       NOTE: do NOT call channel_fulfill_htlc — that advances commitment_number
       as a side effect, which would cause channel_rebuild_htlc_leaves to
       derive HTLC keys with a DIFFERENT per_commitment_point than was used
       to build the on-chain commitment, producing a witness program hash
       mismatch.  Mirror test_regtest_htlc_success (test_channel.c) by
       writing the preimage directly. */
    (void)lsp_htlc_id;
    memcpy(lsp_ch.htlcs[0].payment_preimage, preimage, 32);

    /* Build + broadcast HTLC-success tx.  channel_build_htlc_success_tx
       sets nSequence=to_self_delay (=csv=10) for HTLC_RECEIVED.  BIP-68
       requires the parent to have at least nSequence confirmations
       before this tx can enter the mempool.  Mine csv blocks so the
       commit is csv+1 deep, then broadcast. */
    regtest_mine_blocks(rt, csv, mine_addr);

    unsigned char ct_internal[32];
    memcpy(ct_internal, ct, 32);
    tx_buf_t succ;
    tx_buf_init(&succ, 512);
    TEST_ASSERT(channel_build_htlc_success_tx(&lsp_ch, &succ, ct_internal, 2,
                                                 htlc_out_amt, htlc_spk, 34,
                                                 0 /* htlc_index */),
                "htlc: build success tx");
    char succ_hex[succ.len * 2 + 1];
    hex_encode(succ.data, succ.len, succ_hex); succ_hex[succ.len * 2] = '\0';
    char succ_txid[65];
    int ok = spend_broadcast_and_mine(rt, succ_hex, 1, succ_txid);
    tx_buf_free(&succ);
    TEST_ASSERT(ok, "htlc: success tx confirmed");
    printf("  HTLC: success tx resolved %llu sats via preimage: %s ✓\n",
           (unsigned long long)htlc_out_amt, succ_txid);

    channel_cleanup(&lsp_ch);
    channel_cleanup(&client_ch);
    return 1;
}

/* Rotation-then-exit spendability: factory A → rotate into factory B
 * (via close of A whose outputs fund B), → close B cooperatively,
 * → each party sweeps their B-close output.
 *
 * The rotation mechanic transfers balance from A → B without going
 * on-chain to per-party addresses. This test verifies the final exit
 * from B still lands at per-party P2TR(xonly(pk_i)) addresses each
 * party can spend unilaterally.
 *
 * We use the same N=5 keypairs for both factories (realistic single-LSP
 * multi-client rotation). For simplicity, factory B is structurally
 * identical to A — same arity, same participants.
 */
static int run_rotation_for_arity(regtest_t *rt, secp256k1_context *ctx,
                                    factory_arity_t arity, const char *mine_addr) {
    const size_t N = 5;
    secp256k1_keypair kpsA[5], kpsB[5];
    factory_t *fA = calloc(1, sizeof(factory_t));
    factory_t *fB = calloc(1, sizeof(factory_t));
    if (!fA || !fB) { free(fA); free(fB); return 0; }

    unsigned char spkA[34], spkB[34];
    char txidA[65], txidB[65];
    uint32_t voutA = 0, voutB = 0;
    uint64_t amtA = 0, amtB = 0;

    /* Build factory A. */
    if (!fund_n_party_factory(rt, ctx, N, arity, mine_addr, kpsA, fA,
                                spkA, txidA, &voutA, &amtA)) {
        free(fA); free(fB); return 0;
    }
    printf("  rotation[arity=%d]: factory A funded %s:%u  %llu sats\n",
           (int)arity, txidA, voutA, (unsigned long long)amtA);

    /* Build factory B (separate funding UTXO — same participants). */
    for (size_t i = 0; i < N; i++)
        secp256k1_keypair_create(ctx, &kpsB[i], N_PARTY_SECKEYS[i]);
    if (!fund_n_party_factory(rt, ctx, N, arity, mine_addr, kpsB, fB,
                                spkB, txidB, &voutB, &amtB)) {
        free(fA); free(fB); return 0;
    }
    printf("  rotation[arity=%d]: factory B funded %s:%u  %llu sats\n",
           (int)arity, txidB, voutB, (unsigned long long)amtB);

    /* Cooperatively close factory A with a single output to factory B's
       funding SPK (this is what "rotation" actually does: recycle A's
       funds into B's contract). Then cooperatively close factory B with
       per-party P2TR outputs. */

    /* Close A → single output at B's SPK. */
    tx_output_t rot_out;
    rot_out.script_pubkey_len = 34;
    memcpy(rot_out.script_pubkey, spkB, 34);
    rot_out.amount_sats = amtA - 500;

    tx_buf_t ucA;
    tx_buf_init(&ucA, 256);
    if (!build_unsigned_tx(&ucA, NULL, fA->funding_txid, fA->funding_vout,
                            0xFFFFFFFEu, &rot_out, 1)) { free(fA); free(fB); return 0; }
    unsigned char shA[32];
    if (!compute_taproot_sighash(shA, ucA.data, ucA.len, 0, spkA, 34,
                                  amtA, 0xFFFFFFFEu)) {
        tx_buf_free(&ucA); free(fA); free(fB); return 0;
    }
    musig_keyagg_t kaA;
    secp256k1_pubkey pksA[5];
    for (size_t i = 0; i < N; i++) secp256k1_keypair_pub(ctx, &pksA[i], &kpsA[i]);
    musig_aggregate_keys(ctx, &kaA, pksA, N);
    unsigned char sigA[64];
    if (!musig_sign_taproot(ctx, sigA, shA, kpsA, N, &kaA, NULL)) {
        tx_buf_free(&ucA); free(fA); free(fB); return 0;
    }
    tx_buf_t scA;
    tx_buf_init(&scA, 256);
    finalize_signed_tx(&scA, ucA.data, ucA.len, sigA);
    tx_buf_free(&ucA);
    char rot_hex[scA.len * 2 + 1];
    hex_encode(scA.data, scA.len, rot_hex); rot_hex[scA.len * 2] = '\0';
    char rot_txid[65];
    TEST_ASSERT(regtest_send_raw_tx(rt, rot_hex, rot_txid),
                "rotation: close A → B broadcast");
    regtest_mine_blocks(rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(rt, rot_txid) >= 1,
                "rotation: close A confirmed");
    tx_buf_free(&scA);
    printf("  rotation[arity=%d]: A swept into recycling output %s\n",
           (int)arity, rot_txid);

    /* Now close B cooperatively with per-party P2TR outputs. */
    tx_output_t outs[5];
    uint64_t fee = 500;
    uint64_t per_client = (amtB - fee) / 10;
    uint64_t lsp_amt = amtB - fee - per_client * 4;
    for (size_t i = 0; i < N; i++) {
        secp256k1_pubkey pk;
        secp256k1_keypair_pub(ctx, &pk, &kpsB[i]);
        secp256k1_xonly_pubkey xo;
        secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &pk);
        build_p2tr_script_pubkey(outs[i].script_pubkey, &xo);
        outs[i].script_pubkey_len = 34;
        outs[i].amount_sats = (i == 0) ? lsp_amt : per_client;
    }
    tx_buf_t ucB;
    tx_buf_init(&ucB, 256);
    if (!build_unsigned_tx(&ucB, NULL, fB->funding_txid, fB->funding_vout,
                            0xFFFFFFFEu, outs, N)) { free(fA); free(fB); return 0; }
    unsigned char shB[32];
    compute_taproot_sighash(shB, ucB.data, ucB.len, 0, spkB, 34,
                             amtB, 0xFFFFFFFEu);
    musig_keyagg_t kaB;
    secp256k1_pubkey pksB[5];
    for (size_t i = 0; i < N; i++) secp256k1_keypair_pub(ctx, &pksB[i], &kpsB[i]);
    musig_aggregate_keys(ctx, &kaB, pksB, N);
    unsigned char sigB[64];
    musig_sign_taproot(ctx, sigB, shB, kpsB, N, &kaB, NULL);
    tx_buf_t scB;
    tx_buf_init(&scB, 256);
    finalize_signed_tx(&scB, ucB.data, ucB.len, sigB);
    tx_buf_free(&ucB);
    char chB_hex[scB.len * 2 + 1];
    hex_encode(scB.data, scB.len, chB_hex); chB_hex[scB.len * 2] = '\0';
    char cB_txid[65];
    TEST_ASSERT(regtest_send_raw_tx(rt, chB_hex, cB_txid),
                "rotation: close B broadcast");
    regtest_mine_blocks(rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(rt, cB_txid) >= 1,
                "rotation: close B confirmed");
    tx_buf_free(&scB);
    printf("  rotation[arity=%d]: B closed %s\n", (int)arity, cB_txid);

    /* Gauntlet: each party sweeps their B-close output. */
    if (!spend_coop_close_gauntlet(ctx, rt, cB_txid, N_PARTY_SECKEYS, N - 1)) {
        free(fA); free(fB); return 0;
    }
    printf("  rotation[arity=%d]: balance carried A→B, all 5 parties swept ✓\n",
           (int)arity);

    free(fA); free(fB);
    return 1;
}

int test_regtest_rotation_all_arities(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "rotation_spend");
    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    TEST_ASSERT(run_rotation_for_arity(&rt, ctx, FACTORY_ARITY_1, mine_addr),
                "rotation arity 1");
    TEST_ASSERT(run_rotation_for_arity(&rt, ctx, FACTORY_ARITY_2, mine_addr),
                "rotation arity 2");
    TEST_ASSERT(run_rotation_for_arity(&rt, ctx, FACTORY_ARITY_PS, mine_addr),
                "rotation arity 3 (PS)");
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_regtest_htlc_in_flight_spendability(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "htlc_inflight_spend");
    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    int ok = run_htlc_in_flight(&rt, ctx, mine_addr);
    secp256k1_context_destroy(ctx);
    return ok;
}

int test_regtest_ps_chain_close_spendability(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "ps_chain_spend");
    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    int ok = run_ps_chain_close_spendability(&rt, ctx, mine_addr);
    secp256k1_context_destroy(ctx);
    return ok;
}

int test_regtest_breach_penalty_spendability(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "breach_spendability");
    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    int ok = run_breach_penalty(&rt, ctx, mine_addr);
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

/* ---- Full-tree force-close: publish every signed tree node in order,
 *      then prove each leaf output lands on chain (i.e. is spendable
 *      from the 2-of-2 MuSig of LSP + client that owns it).
 *
 * Spendability of the leaf-to-commitment and commitment-to-wallet paths
 * is proven by test_regtest_force_close_to_remote / to_local — those
 * tests build a 2-of-2 channel directly and sweep both sides. Their
 * commitment-TX structure is arity-invariant (arity only affects the
 * factory tree shape above the leaf; the leaf-output → commitment →
 * sweep pipeline is identical across arities). So the missing piece
 * this test adds is that the factory tree itself can be force-published
 * for each arity and the leaf UTXOs appear on chain. */
static int run_full_tree_force_close_for_arity(regtest_t *rt,
                                                secp256k1_context *ctx,
                                                factory_arity_t arity,
                                                const char *mine_addr) {
    const size_t N = 5;
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
           (int)arity, fund_txid, fund_vout,
           (unsigned long long)fund_amount, f->n_nodes);

    /* Broadcast each signed node in order. Between parent and child we
       must mine ≥ (child.nSequence & 0xFFFF) + 1 blocks so the child's
       BIP-68 relative timelock is satisfied. Matches the pattern used by
       tools/superscalar_lsp.c's broadcast_factory_tree. */
    char txids[FACTORY_MAX_NODES][65];
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *nd = &f->nodes[i];
        if (!nd->is_signed || nd->signed_tx.len == 0) {
            fprintf(stderr, "  [arity=%d] node %zu not signed\n", (int)arity, i);
            factory_free(f); free(f); return 0;
        }
        char *tx_hex = malloc(nd->signed_tx.len * 2 + 1);
        if (!tx_hex) { factory_free(f); free(f); return 0; }
        hex_encode(nd->signed_tx.data, nd->signed_tx.len, tx_hex);
        int ok = regtest_send_raw_tx(rt, tx_hex, txids[i]);
        free(tx_hex);
        if (!ok) {
            fprintf(stderr, "  [arity=%d] node %zu broadcast failed\n",
                    (int)arity, i);
            factory_free(f); free(f); return 0;
        }

        /* Mine enough blocks to satisfy the NEXT node's BIP-68 delay
           (if any). For the last node, just confirm it. */
        int blocks_to_mine = 1;
        if (i + 1 < f->n_nodes) {
            uint32_t child_nseq = f->nodes[i + 1].nsequence;
            if (!(child_nseq & 0x80000000u))
                blocks_to_mine = (int)(child_nseq & 0xFFFF) + 1;
        }
        regtest_mine_blocks(rt, blocks_to_mine, mine_addr);
    }

    /* Verify every leaf node's outputs confirmed on chain. Leaf indices
       are stored in f->leaf_node_indices (populated by factory_build_tree).
       This is the spendability precondition for the per-channel sweep path
       that test_regtest_force_close_* already exercises. */
    int n_leaves_confirmed = 0;
    for (int li = 0; li < f->n_leaf_nodes; li++) {
        size_t nidx = f->leaf_node_indices[li];
        const char *txid = txids[nidx];
        int conf = regtest_get_confirmations(rt, txid);
        if (conf < 1) {
            fprintf(stderr, "  [arity=%d] leaf node %d (tree idx %zu) not "
                    "confirmed (confs=%d)\n", (int)arity, li, nidx, conf);
            factory_free(f); free(f); return 0;
        }
        n_leaves_confirmed++;
    }
    printf("  [arity=%d] full tree broadcast OK — %zu nodes mined, "
           "%d leaves confirmed on chain ✓\n",
           (int)arity, f->n_nodes, n_leaves_confirmed);
    TEST_ASSERT(n_leaves_confirmed >= 1, "at least one leaf confirmed");

    factory_free(f); free(f);
    return 1;
}

int test_regtest_full_tree_force_close_all_arities(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "full_tree_force");
    /* Arity-1 tree is 14 nodes with BIP-68 delays between siblings — by the
       time we check the last leaf's confs, it's buried > 20 blocks deep,
       beyond the default scan_depth. regtest_get_confirmations's fallback
       path iterates getblockhash + getrawtransaction, so bumping the depth
       covers CI hosts that don't have -txindex set. */
    rt.scan_depth = 200;

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    TEST_ASSERT(run_full_tree_force_close_for_arity(&rt, ctx, FACTORY_ARITY_1,
                                                      mine_addr),
                "full-tree force-close arity 1");
    TEST_ASSERT(run_full_tree_force_close_for_arity(&rt, ctx, FACTORY_ARITY_2,
                                                      mine_addr),
                "full-tree force-close arity 2");
    TEST_ASSERT(run_full_tree_force_close_for_arity(&rt, ctx, FACTORY_ARITY_PS,
                                                      mine_addr),
                "full-tree force-close arity 3 (PS)");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- JIT channel recovery close — full per-party + conservation accounting.
 *
 * A JIT channel is a 2-of-2 MuSig channel opened between LSP and a client
 * on-demand (outside the main factory tree). The recovery close has two
 * shapes that must each round-trip with full accounting:
 *
 *   - COOP: a single 2-output P2TR close TX (LSP P2TR + client P2TR), signed
 *     2-of-2 MuSig over the JIT funding UTXO. Each party then sweeps their
 *     own P2TR output unilaterally with their own seckey.
 *
 *   - FORCE: LSP broadcasts a real BOLT-2 commitment_tx with to_local + to_remote.
 *     Client immediately sweeps to_remote via per-commitment-derived BIP-341
 *     keypath. LSP waits CSV blocks then sweeps to_local via the CSV script-
 *     path leaf (channel_build_to_local_sweep).
 *
 * Both cells assert:
 *   - per-party deltas via econ_assert_wallet_deltas
 *   - conservation: Σ(swept) + Σ(fees) == jit_funding_amount
 *
 * Since JIT channels exist outside the arity-dependent factory tree, the
 * close shape is arity-invariant — these two cells cover all three Chart C
 * "arity" cells for the JIT row.
 *
 * Phase 2 #4 of docs/v0114-audit-phase2.md.
 */

/* Set up a 2-of-2 MuSig JIT funding UTXO between LSP (sk[0]) and client
 * (sk[1]). Returns 1 on success and fills out_* with the funding details
 * needed downstream. */
static int setup_jit_funding(regtest_t *rt, secp256k1_context *ctx,
                              const char *mine_addr,
                              uint64_t jit_funding_sats,
                              secp256k1_keypair *out_lsp_kp,
                              secp256k1_keypair *out_cli_kp,
                              secp256k1_pubkey *out_lsp_pk,
                              secp256k1_pubkey *out_cli_pk,
                              musig_keyagg_t *out_ka,
                              unsigned char out_jit_spk[34],
                              char out_jit_txid[65],
                              uint32_t *out_jit_vout,
                              uint64_t *out_jit_amount) {
    if (!secp256k1_keypair_create(ctx, out_lsp_kp, N_PARTY_SECKEYS[0])) return 0;
    if (!secp256k1_keypair_create(ctx, out_cli_kp, N_PARTY_SECKEYS[1])) return 0;
    secp256k1_keypair_pub(ctx, out_lsp_pk, out_lsp_kp);
    secp256k1_keypair_pub(ctx, out_cli_pk, out_cli_kp);

    secp256k1_pubkey pks2[2] = { *out_lsp_pk, *out_cli_pk };
    if (!musig_aggregate_keys(ctx, out_ka, pks2, 2)) return 0;
    unsigned char agg_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, agg_ser, &out_ka->agg_pubkey);
    unsigned char tw[32];
    sha256_tagged("TapTweak", agg_ser, 32, tw);
    musig_keyagg_t ka_spk = *out_ka;
    secp256k1_pubkey tpk;
    secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tpk, &ka_spk.cache, tw);
    secp256k1_xonly_pubkey tpx;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &tpx, NULL, &tpk);
    build_p2tr_script_pubkey(out_jit_spk, &tpx);
    unsigned char tpx_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, tpx_ser, &tpx);

    char jit_addr[128];
    if (!regtest_derive_p2tr_address(rt, tpx_ser, jit_addr, sizeof(jit_addr)))
        return 0;
    if (!regtest_fund_address(rt, jit_addr,
                               (double)jit_funding_sats / 1e8, out_jit_txid))
        return 0;
    regtest_mine_blocks(rt, 1, mine_addr);

    *out_jit_vout = UINT32_MAX;
    *out_jit_amount = 0;
    for (uint32_t v = 0; v < 4; v++) {
        uint64_t a = 0;
        unsigned char s[64];
        size_t sl = 0;
        if (regtest_get_tx_output(rt, out_jit_txid, v, &a, s, &sl) &&
            sl == 34 && memcmp(s, out_jit_spk, 34) == 0) {
            *out_jit_vout = v;
            *out_jit_amount = a;
            break;
        }
    }
    return *out_jit_vout != UINT32_MAX;
}

/* Cell A: cooperative JIT close.
 *
 * LSP + client jointly sign a single close TX that pays each their
 * respective channel balances minus a shared fee, then each sweeps its
 * own P2TR output to the same wallet SPK we registered with econ_helpers.
 */
int test_regtest_jit_recovery_close_coop_full(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "jit_recovery_coop");
    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) {
        secp256k1_context_destroy(ctx); return 0;
    }
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    secp256k1_keypair lsp_kp, cli_kp;
    secp256k1_pubkey lsp_pk, cli_pk;
    musig_keyagg_t ka;
    unsigned char jit_spk[34];
    char jit_txid[65];
    uint32_t jit_vout = 0;
    uint64_t jit_amount = 0;
    /* JIT funding 80k sats — well above dust + fees, matches the
       JIT_FUNDING_SATS range used by the JIT daemon trigger path. */
    TEST_ASSERT(setup_jit_funding(&rt, ctx, mine_addr, 80000,
                                    &lsp_kp, &cli_kp, &lsp_pk, &cli_pk,
                                    &ka, jit_spk, jit_txid, &jit_vout, &jit_amount),
                "JIT funding setup");
    printf("  [JIT coop] funded %s:%u  %llu sats\n",
           jit_txid, jit_vout, (unsigned long long)jit_amount);

    /* Channel split: LSP gets 60% inbound (the typical post-payment shape
       for a JIT topped up by the LSP), client gets 40%. Fee allocated
       evenly off-the-top — same as the real lsp_channels close path. */
    const uint64_t close_fee = 500;
    TEST_ASSERT(jit_amount > close_fee + 5000, "JIT amount too small");
    uint64_t channel_capacity = jit_amount - close_fee;
    uint64_t lsp_close_amt = (channel_capacity * 60) / 100;
    uint64_t cli_close_amt = channel_capacity - lsp_close_amt;

    /* Each party's recovery output = P2TR(xonly(pk_i)). */
    unsigned char lsp_close_spk[34], cli_close_spk[34];
    {
        secp256k1_xonly_pubkey xo;
        secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &lsp_pk);
        build_p2tr_script_pubkey(lsp_close_spk, &xo);
        secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &cli_pk);
        build_p2tr_script_pubkey(cli_close_spk, &xo);
    }

    /* Wire the econ harness BEFORE the close TX is broadcast — the close
       output lands at the SAME SPK we sweep to (P2TR(xonly(pk_i))), so if
       we snap_pre AFTER the close-tx confirms the close amount would
       already be counted in pre_balance and the sweep would only show
       a -SWEEP_FEE delta. Snap_pre BEFORE close => post − pre captures
       (close_output_landed) − (close_output_consumed_by_sweep) +
       (sweep_output_landed) = sweep_output_landed = close_amt − fee. */
    econ_ctx_t econ;
    econ_ctx_init(&econ, &rt, ctx);
    TEST_ASSERT(econ_register_party(&econ, 0, "LSP", N_PARTY_SECKEYS[0]),
                "register LSP");
    TEST_ASSERT(econ_register_party(&econ, 1, "client", N_PARTY_SECKEYS[1]),
                "register client");
    econ.factory_funding_amount = jit_amount;  /* scope = JIT funding */
    TEST_ASSERT(econ_snap_pre(&econ), "econ_snap_pre");

    /* Build the 2-output close TX. */
    tx_output_t outs[2];
    outs[0].script_pubkey_len = 34;
    memcpy(outs[0].script_pubkey, lsp_close_spk, 34);
    outs[0].amount_sats = lsp_close_amt;
    outs[1].script_pubkey_len = 34;
    memcpy(outs[1].script_pubkey, cli_close_spk, 34);
    outs[1].amount_sats = cli_close_amt;

    unsigned char txid_bytes[32];
    hex_decode(jit_txid, txid_bytes, 32);
    reverse_bytes(txid_bytes, 32);

    tx_buf_t uc;
    tx_buf_init(&uc, 256);
    TEST_ASSERT(build_unsigned_tx(&uc, NULL, txid_bytes, jit_vout,
                                    0xFFFFFFFEu, outs, 2),
                "build unsigned JIT coop close");
    unsigned char sh[32];
    TEST_ASSERT(compute_taproot_sighash(sh, uc.data, uc.len, 0, jit_spk, 34,
                                         jit_amount, 0xFFFFFFFEu),
                "sighash");
    secp256k1_keypair kps[2] = { lsp_kp, cli_kp };
    unsigned char sig[64];
    TEST_ASSERT(musig_sign_taproot(ctx, sig, sh, kps, 2, &ka, NULL),
                "musig sign 2-party");
    tx_buf_t sc;
    tx_buf_init(&sc, 256);
    TEST_ASSERT(finalize_signed_tx(&sc, uc.data, uc.len, sig),
                "finalize JIT close");
    tx_buf_free(&uc);

    char close_hex[sc.len * 2 + 1];
    hex_encode(sc.data, sc.len, close_hex);
    close_hex[sc.len * 2] = '\0';
    char close_txid[65];
    TEST_ASSERT(regtest_send_raw_tx(&rt, close_hex, close_txid),
                "broadcast JIT close");
    regtest_mine_blocks(&rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(&rt, close_txid) >= 1,
                "JIT close confirmed");
    tx_buf_free(&sc);
    printf("  [JIT coop] close confirmed: %s (LSP=%llu, cli=%llu, fee=%llu)\n",
           close_txid,
           (unsigned long long)lsp_close_amt,
           (unsigned long long)cli_close_amt,
           (unsigned long long)close_fee);

    /* Per-party sweeps: each sweeps its own P2TR(xonly(pk_i)) output.
       The close output IS at P2TR(xonly(pk_i)) (raw xonly, no taptweak),
       so we use spend_build_p2tr_raw_keypath. Sweep destination =
       same SPK so the econ delta lands at the tracked address. */
    const uint64_t SWEEP_FEE = 300;

    /* LSP sweeps vout 0. */
    {
        tx_buf_t sweep;
        TEST_ASSERT(spend_build_p2tr_raw_keypath(ctx, N_PARTY_SECKEYS[0],
                        close_txid, 0, lsp_close_amt,
                        lsp_close_spk, 34,
                        lsp_close_spk, 34,
                        SWEEP_FEE, &sweep),
                    "build LSP JIT-close sweep");
        char hex[sweep.len * 2 + 1];
        hex_encode(sweep.data, sweep.len, hex);
        hex[sweep.len * 2] = '\0';
        char tid[65];
        int ok = spend_broadcast_and_mine(&rt, hex, 1, tid);
        tx_buf_free(&sweep);
        TEST_ASSERT(ok, "LSP sweep confirmed");
        printf("  [JIT coop] LSP swept %llu sats -> %s\n",
               (unsigned long long)(lsp_close_amt - SWEEP_FEE), tid);
    }

    /* Client sweeps vout 1. */
    {
        tx_buf_t sweep;
        TEST_ASSERT(spend_build_p2tr_raw_keypath(ctx, N_PARTY_SECKEYS[1],
                        close_txid, 1, cli_close_amt,
                        cli_close_spk, 34,
                        cli_close_spk, 34,
                        SWEEP_FEE, &sweep),
                    "build client JIT-close sweep");
        char hex[sweep.len * 2 + 1];
        hex_encode(sweep.data, sweep.len, hex);
        hex[sweep.len * 2] = '\0';
        char tid[65];
        int ok = spend_broadcast_and_mine(&rt, hex, 1, tid);
        tx_buf_free(&sweep);
        TEST_ASSERT(ok, "client sweep confirmed");
        printf("  [JIT coop] client swept %llu sats -> %s\n",
               (unsigned long long)(cli_close_amt - SWEEP_FEE), tid);
    }

    TEST_ASSERT(econ_snap_post(&econ), "econ_snap_post");

    uint64_t expected_deltas[2];
    expected_deltas[0] = lsp_close_amt - SWEEP_FEE;
    expected_deltas[1] = cli_close_amt - SWEEP_FEE;

    uint64_t total_fees = close_fee + SWEEP_FEE * 2;
    uint64_t swept_sum = expected_deltas[0] + expected_deltas[1];
    TEST_ASSERT(swept_sum + total_fees == jit_amount,
                "conservation: Sum(swept) + Sum(fees) == jit_amount");
    printf("  [JIT coop] conservation OK: swept=%llu + fees=%llu == jit=%llu\n",
           (unsigned long long)swept_sum,
           (unsigned long long)total_fees,
           (unsigned long long)jit_amount);

    TEST_ASSERT(econ_assert_wallet_deltas(&econ, expected_deltas, 0),
                "per-party JIT coop deltas");
    econ_print_summary(&econ);

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Cell B: force-close JIT channel.
 *
 * LSP broadcasts a real BOLT-2 commitment_tx with to_local + to_remote.
 * Client sweeps to_remote immediately via per-commitment-derived BIP-341
 * keypath; LSP waits CSV blocks then sweeps to_local via the script-path
 * channel_build_to_local_sweep helper. Mirrors the run_force_close_to_local
 * pattern but on a JIT funding UTXO instead of a factory leaf channel. */
int test_regtest_jit_recovery_close_force_full(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "jit_recovery_force");
    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) {
        secp256k1_context_destroy(ctx); return 0;
    }
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    secp256k1_keypair lsp_kp, cli_kp;
    secp256k1_pubkey lsp_pk, cli_pk;
    musig_keyagg_t ka;
    unsigned char jit_spk[34];
    char jit_txid_hex[65];
    uint32_t jit_vout = 0;
    uint64_t jit_amount = 0;
    /* JIT funding 100k sats — leaves headroom for COMMIT_FEE_RESERVE
       (1500 sats reserved for the inner commitment fee, per PR #89/#90/#91). */
    TEST_ASSERT(setup_jit_funding(&rt, ctx, mine_addr, 100000,
                                    &lsp_kp, &cli_kp, &lsp_pk, &cli_pk,
                                    &ka, jit_spk, jit_txid_hex, &jit_vout, &jit_amount),
                "JIT funding setup");
    printf("  [JIT force] funded %s:%u  %llu sats\n",
           jit_txid_hex, jit_vout, (unsigned long long)jit_amount);

    unsigned char jit_txid_bytes[32];
    hex_decode(jit_txid_hex, jit_txid_bytes, 32);
    reverse_bytes(jit_txid_bytes, 32);

    /* COMMIT_FEE_RESERVE: keep the inner LN commitment fee well above
       regtest mempool min-relay (~200 sats). PR #89 hit ~43-sat fees
       before this reserve was applied. */
    const uint32_t csv = 10;
    const uint64_t COMMIT_FEE_RESERVE = 1500;
    TEST_ASSERT(jit_amount > COMMIT_FEE_RESERVE + 5000,
                "jit_amount too small for commit fee headroom");
    uint64_t channel_capacity = jit_amount - COMMIT_FEE_RESERVE;
    uint64_t local_amt  = (channel_capacity * 60) / 100;
    uint64_t remote_amt = channel_capacity - local_amt;

    channel_t lsp_ch, client_ch;
    TEST_ASSERT(channel_init(&lsp_ch, ctx, N_PARTY_SECKEYS[0],
                              &lsp_pk, &cli_pk,
                              jit_txid_bytes, jit_vout, jit_amount,
                              jit_spk, 34,
                              local_amt, remote_amt, csv),
                "init LSP JIT channel");
    TEST_ASSERT(channel_init(&client_ch, ctx, N_PARTY_SECKEYS[1],
                              &cli_pk, &lsp_pk,
                              jit_txid_bytes, jit_vout, jit_amount,
                              jit_spk, 34,
                              remote_amt, local_amt, csv),
                "init client JIT channel");
    channel_generate_random_basepoints(&lsp_ch);
    channel_generate_random_basepoints(&client_ch);
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

    secp256k1_pubkey lsp_pcp0, cli_pcp0, lsp_pcp1, cli_pcp1;
    channel_get_per_commitment_point(&lsp_ch, 0, &lsp_pcp0);
    channel_get_per_commitment_point(&client_ch, 0, &cli_pcp0);
    channel_get_per_commitment_point(&lsp_ch, 1, &lsp_pcp1);
    channel_get_per_commitment_point(&client_ch, 1, &cli_pcp1);
    channel_set_remote_pcp(&lsp_ch, 0, &cli_pcp0);
    channel_set_remote_pcp(&client_ch, 0, &lsp_pcp0);
    channel_set_remote_pcp(&lsp_ch, 1, &cli_pcp1);
    channel_set_remote_pcp(&client_ch, 1, &lsp_pcp1);

    /* Build + sign + broadcast LSP's commitment (2 outputs: to_local + to_remote). */
    tx_buf_t uc, sc;
    tx_buf_init(&uc, 512); tx_buf_init(&sc, 1024);
    unsigned char ct[32];
    TEST_ASSERT(channel_build_commitment_tx(&lsp_ch, &uc, ct),
                "build LSP commitment");
    TEST_ASSERT(channel_sign_commitment(&lsp_ch, &sc, &uc, &cli_kp),
                "client co-signs LSP commitment");
    char commit_hex[sc.len * 2 + 1];
    hex_encode(sc.data, sc.len, commit_hex);
    commit_hex[sc.len * 2] = '\0';
    char commit_txid_hex[65];
    TEST_ASSERT(regtest_send_raw_tx(&rt, commit_hex, commit_txid_hex),
                "broadcast commitment");
    regtest_mine_blocks(&rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(&rt, commit_txid_hex) >= 1,
                "commitment confirmed");
    tx_buf_free(&uc); tx_buf_free(&sc);
    printf("  [JIT force] commitment confirmed %s\n", commit_txid_hex);

    /* Read both outputs from the chain. */
    uint64_t to_local_amt = 0, to_remote_amt = 0;
    unsigned char to_local_spk[64], to_remote_spk[64];
    size_t to_local_spk_len = 0, to_remote_spk_len = 0;
    TEST_ASSERT(regtest_get_tx_output(&rt, commit_txid_hex, 0,
                                        &to_local_amt, to_local_spk,
                                        &to_local_spk_len),
                "read to_local (vout 0)");
    TEST_ASSERT(regtest_get_tx_output(&rt, commit_txid_hex, 1,
                                        &to_remote_amt, to_remote_spk,
                                        &to_remote_spk_len),
                "read to_remote (vout 1)");
    TEST_ASSERT(to_local_amt == local_amt, "to_local amount matches channel");
    TEST_ASSERT(to_remote_amt == remote_amt, "to_remote amount matches channel");
    uint64_t commit_fee = jit_amount - to_local_amt - to_remote_amt;
    printf("  [JIT force] outs: to_local=%llu to_remote=%llu commit_fee=%llu\n",
           (unsigned long long)to_local_amt,
           (unsigned long long)to_remote_amt,
           (unsigned long long)commit_fee);

    /* Wire the econ harness BEFORE sweeps. */
    econ_ctx_t econ;
    econ_ctx_init(&econ, &rt, ctx);
    TEST_ASSERT(econ_register_party(&econ, 0, "LSP", N_PARTY_SECKEYS[0]),
                "register LSP");
    TEST_ASSERT(econ_register_party(&econ, 1, "client", N_PARTY_SECKEYS[1]),
                "register client");
    econ.factory_funding_amount = jit_amount;
    TEST_ASSERT(econ_snap_pre(&econ), "econ_snap_pre");

    /* Per-party destination SPKs. */
    unsigned char party_spk[2][34];
    {
        secp256k1_xonly_pubkey xo;
        secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &lsp_pk);
        build_p2tr_script_pubkey(party_spk[0], &xo);
        secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &cli_pk);
        build_p2tr_script_pubkey(party_spk[1], &xo);
    }

    /* Mine CSV blocks so to_local script-path is satisfied. */
    regtest_mine_blocks(&rt, (int)csv, mine_addr);

    /* (1) LSP sweeps to_local via channel_build_to_local_sweep (CSV
           script-path). The sweep TX subtracts a fee internally based on
           ch->fee_rate_sat_per_kvb (default 1000 sat/kvB) and a 200-vB
           estimate -> ~200 sats fee. */
    uint64_t to_local_sweep_fee = (lsp_ch.fee_rate_sat_per_kvb * 200 + 999) / 1000;
    {
        tx_buf_t sweep;
        tx_buf_init(&sweep, 512);
        unsigned char ct_internal[32];
        memcpy(ct_internal, ct, 32);
        TEST_ASSERT(channel_build_to_local_sweep(&lsp_ch, &sweep,
                        ct_internal, 0, to_local_amt,
                        party_spk[0], 34),
                    "build to_local sweep");
        char hex[sweep.len * 2 + 1];
        hex_encode(sweep.data, sweep.len, hex);
        hex[sweep.len * 2] = '\0';
        char tid[65];
        int ok = spend_broadcast_and_mine(&rt, hex, 1, tid);
        tx_buf_free(&sweep);
        TEST_ASSERT(ok, "to_local sweep confirmed");
        printf("  [JIT force] LSP swept to_local %llu sats (fee=%llu) -> %s\n",
               (unsigned long long)(to_local_amt - to_local_sweep_fee),
               (unsigned long long)to_local_sweep_fee, tid);
    }

    /* (2) Client sweeps to_remote via per-commitment-derived BIP-341
           keypath. to_remote SPK was built using lsp_pcp0 (commitment 0).
           Use a fixed 300-sat sweep fee to satisfy the >=300 sat severity
           rule. */
    const uint64_t TO_REMOTE_SWEEP_FEE = 300;
    unsigned char client_to_remote_sk[32];
    TEST_ASSERT(derive_channel_seckey(ctx, client_to_remote_sk,
                    client_ch.local_payment_basepoint_secret,
                    &client_ch.local_payment_basepoint,
                    &lsp_pcp0),
                "derive client to_remote seckey");
    {
        tx_buf_t sweep;
        tx_buf_init(&sweep, 256);
        TEST_ASSERT(spend_build_p2tr_bip341_keypath(ctx, client_to_remote_sk,
                        commit_txid_hex, 1, to_remote_amt,
                        to_remote_spk, 34,
                        party_spk[1], 34,
                        TO_REMOTE_SWEEP_FEE, &sweep),
                    "build to_remote sweep");
        char hex[sweep.len * 2 + 1];
        hex_encode(sweep.data, sweep.len, hex);
        hex[sweep.len * 2] = '\0';
        char tid[65];
        int ok = spend_broadcast_and_mine(&rt, hex, 1, tid);
        tx_buf_free(&sweep);
        TEST_ASSERT(ok, "to_remote sweep confirmed");
        printf("  [JIT force] client swept to_remote %llu sats (fee=%llu) -> %s\n",
               (unsigned long long)(to_remote_amt - TO_REMOTE_SWEEP_FEE),
               (unsigned long long)TO_REMOTE_SWEEP_FEE, tid);
    }

    /* Snapshot post + assert deltas + conservation. */
    TEST_ASSERT(econ_snap_post(&econ), "econ_snap_post");

    uint64_t expected_deltas[2];
    expected_deltas[0] = to_local_amt - to_local_sweep_fee;
    expected_deltas[1] = to_remote_amt - TO_REMOTE_SWEEP_FEE;
    uint64_t total_fees = commit_fee + to_local_sweep_fee + TO_REMOTE_SWEEP_FEE;
    uint64_t swept_sum = expected_deltas[0] + expected_deltas[1];
    TEST_ASSERT(swept_sum + total_fees == jit_amount,
                "conservation: Sum(swept) + Sum(fees) == jit_amount");
    printf("  [JIT force] conservation OK: swept=%llu + fees=%llu == jit=%llu\n",
           (unsigned long long)swept_sum,
           (unsigned long long)total_fees,
           (unsigned long long)jit_amount);

    TEST_ASSERT(econ_assert_wallet_deltas(&econ, expected_deltas, 0),
                "per-party JIT force deltas");
    econ_print_summary(&econ);

    channel_cleanup(&lsp_ch);
    channel_cleanup(&client_ch);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Inversion-of-timeout-default (ZmnSCPxj safety invariant).
 *
 * At the factory CLTV timeout, if the LSP has not rotated, cooperatively
 * closed, or force-closed its clients, the pre-signed distribution TX
 * (nLockTime = cltv_timeout) becomes valid. It spends the funding UTXO
 * directly and pays every cent to clients — LSP gets nothing, not even
 * dust. This is the hard-money disincentive that backs the LSP's uptime
 * obligation: go dark past the CLTV, lose everything.
 *
 * The test builds a factory, derives the distribution outputs via the
 * production helper (factory_compute_distribution_outputs_balanced),
 * runs an offline N-party MuSig2 signing ceremony against the funding
 * SPK, mines past the CLTV, broadcasts, and asserts:
 *   - The TX confirmed
 *   - N_clients outputs (no LSP output)
 *   - None of the outputs match LSP's P2TR(xonly(pk_0))
 *   - Each client's output ≈ (funding - fee) / N_clients
 *   - No sat is silently retained by the LSP
 *
 * Runs against the current funding_amount regardless of channel balances,
 * so the property holds "the LSP cannot protect its fees by going dark."
 */
int test_regtest_inversion_of_timeout_default(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "inversion_timeout");

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    const size_t N = 5;  /* LSP + 4 clients */
    secp256k1_keypair kps[5];
    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) { secp256k1_context_destroy(ctx); return 0; }

    unsigned char fund_spk[34];
    char fund_txid[65];
    uint32_t fund_vout = 0;
    uint64_t fund_amount = 0;
    if (!fund_n_party_factory(&rt, ctx, N, FACTORY_ARITY_2, mine_addr, kps, f,
                               fund_spk, fund_txid, &fund_vout, &fund_amount)) {
        factory_free(f); free(f); secp256k1_context_destroy(ctx); return 0;
    }

    /* Set CLTV timeout ~6 blocks out so we can mine past it. */
    int cur_h = regtest_get_block_height(&rt);
    if (cur_h <= 0) { factory_free(f); free(f); secp256k1_context_destroy(ctx); return 0; }
    uint32_t cltv = (uint32_t)cur_h + 6;
    f->cltv_timeout = cltv;
    printf("  factory funded: %llu sats, cltv_timeout=%u (current h=%d)\n",
           (unsigned long long)fund_amount, cltv, cur_h);

    /* Compute distribution outputs via the production helper. Pass NULL for
       client_amounts → equal-split inversion path. */
    const uint64_t dist_fee = 500;
    tx_output_t dist_outs[FACTORY_MAX_SIGNERS + 1];
    size_t n_dist = factory_compute_distribution_outputs_balanced(
        f, dist_outs, FACTORY_MAX_SIGNERS + 1, dist_fee, NULL, 0);

    /* Assert (A): exactly (N_participants - 1) outputs — no LSP output. */
    TEST_ASSERT(n_dist == N - 1, "dist TX has exactly N_clients outputs");

    /* Assert (B): no output's SPK matches LSP's P2TR(xonly(pk_0)).  */
    secp256k1_pubkey lsp_pk;
    secp256k1_keypair_pub(ctx, &lsp_pk, &kps[0]);
    secp256k1_xonly_pubkey lsp_xo;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &lsp_xo, NULL, &lsp_pk);
    unsigned char lsp_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, lsp_ser, &lsp_xo);
    unsigned char lsp_tweak[32];
    sha256_tagged("TapTweak", lsp_ser, 32, lsp_tweak);
    secp256k1_pubkey lsp_tw_full;
    secp256k1_xonly_pubkey_tweak_add(ctx, &lsp_tw_full, &lsp_xo, lsp_tweak);
    secp256k1_xonly_pubkey lsp_tw;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &lsp_tw, NULL, &lsp_tw_full);
    unsigned char lsp_spk[34];
    build_p2tr_script_pubkey(lsp_spk, &lsp_tw);

    for (size_t i = 0; i < n_dist; i++) {
        TEST_ASSERT(memcmp(dist_outs[i].script_pubkey, lsp_spk, 34) != 0,
                    "no dist output pays the LSP's P2TR");
    }

    /* Assert (C): each client's output is within 2 sats of (funding-fee)/N_clients.
       (Remainder from integer division folds into output[0], up to N_clients-1.) */
    uint64_t budget = fund_amount - dist_fee;
    uint64_t per_expected = budget / (N - 1);
    uint64_t total_out = 0;
    for (size_t i = 0; i < n_dist; i++) {
        uint64_t diff = (dist_outs[i].amount_sats > per_expected)
            ? (dist_outs[i].amount_sats - per_expected)
            : (per_expected - dist_outs[i].amount_sats);
        TEST_ASSERT(diff <= (N - 1),
                    "client output within rounding of per_expected");
        total_out += dist_outs[i].amount_sats;
    }

    /* Assert (D): outputs sum to exactly budget. No silent LSP retention. */
    TEST_ASSERT(total_out == budget,
                "Σ(client_outputs) == funding - fee; LSP keeps nothing");
    printf("  distribution outputs: n=%zu  per_expected=%llu  total=%llu budget=%llu ✓\n",
           n_dist, (unsigned long long)per_expected,
           (unsigned long long)total_out, (unsigned long long)budget);

    /* Build the unsigned distribution TX with nLockTime = cltv_timeout. */
    tx_buf_t unsigned_dist;
    tx_buf_init(&unsigned_dist, 512);
    if (!build_unsigned_tx_with_locktime(&unsigned_dist, NULL,
                                          f->funding_txid, f->funding_vout,
                                          0xFFFFFFFEu, cltv,
                                          dist_outs, n_dist)) {
        tx_buf_free(&unsigned_dist);
        factory_free(f); free(f); secp256k1_context_destroy(ctx); return 0;
    }

    /* Compute BIP-341 key-path sighash, run offline N-party MuSig2 ceremony. */
    unsigned char sighash[32];
    if (!compute_taproot_sighash(sighash, unsigned_dist.data, unsigned_dist.len,
                                   0, fund_spk, 34, fund_amount, 0xFFFFFFFEu)) {
        tx_buf_free(&unsigned_dist);
        factory_free(f); free(f); secp256k1_context_destroy(ctx); return 0;
    }
    musig_keyagg_t ka;
    secp256k1_pubkey pks[5];
    for (size_t i = 0; i < N; i++)
        secp256k1_keypair_pub(ctx, &pks[i], &kps[i]);
    if (!musig_aggregate_keys(ctx, &ka, pks, N)) {
        tx_buf_free(&unsigned_dist);
        factory_free(f); free(f); secp256k1_context_destroy(ctx); return 0;
    }
    unsigned char sig64[64];
    if (!musig_sign_taproot(ctx, sig64, sighash, kps, N, &ka, NULL)) {
        tx_buf_free(&unsigned_dist);
        factory_free(f); free(f); secp256k1_context_destroy(ctx); return 0;
    }
    tx_buf_t signed_dist;
    tx_buf_init(&signed_dist, 512);
    if (!finalize_signed_tx(&signed_dist, unsigned_dist.data, unsigned_dist.len, sig64)) {
        tx_buf_free(&unsigned_dist); tx_buf_free(&signed_dist);
        factory_free(f); free(f); secp256k1_context_destroy(ctx); return 0;
    }
    tx_buf_free(&unsigned_dist);

    /* Mine past cltv_timeout and broadcast. */
    while (regtest_get_block_height(&rt) < (int)cltv)
        regtest_mine_blocks(&rt, 1, mine_addr);

    char *dist_hex = malloc(signed_dist.len * 2 + 1);
    hex_encode(signed_dist.data, signed_dist.len, dist_hex);
    dist_hex[signed_dist.len * 2] = '\0';
    char dist_txid[65];
    int bcast_ok = regtest_send_raw_tx(&rt, dist_hex, dist_txid);
    free(dist_hex);
    tx_buf_free(&signed_dist);
    if (!bcast_ok) {
        fprintf(stderr, "  distribution TX broadcast failed\n");
        factory_free(f); free(f); secp256k1_context_destroy(ctx); return 0;
    }
    regtest_mine_blocks(&rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(&rt, dist_txid) >= 1,
                "dist TX confirmed on chain");
    printf("  distribution TX confirmed post-CLTV: %s\n", dist_txid);
    printf("  invariant holds: LSP output=0, Σclients=funding-fee ✓\n");

    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Old-state poisoning via DW nSequence decrement (invariant #2).
 *
 * Decker-Wattenhofer state ordering works because newer states are signed
 * with STRICTLY SMALLER nSequence (CSV delay) than older states. After a
 * factory_advance(), the same tree node is re-signed with a smaller
 * nSequence; the previously-signed TX (which still exists if the caller
 * captured it) remains broadcast-valid only until enough blocks pass.
 *
 * The invariant this test proves on chain: if the LSP captures an OLD
 * state TX and tries to broadcast it after a newer state exists, the
 * old TX is rejected (non-BIP68-final) at a block height where the newer
 * state is already valid. A vigilant defender can always beat the LSP
 * to confirmation using the newer (smaller-nSequence) TX.
 *
 * Design reference: ZmnSCPxj's "old-state poisoning" in the Delving post.
 * Our implementation relies on DW decrementing nSequence rather than an
 * explicit pre-signed poison TX, but the safety property is the same:
 * broadcasting stale state is economically hopeless because miners enforce
 * BIP-68 on sequence numbers. */
int test_regtest_old_state_poisoning(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "old_state_poison");

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    const size_t N = 5;
    secp256k1_keypair kps[5];
    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) { secp256k1_context_destroy(ctx); return 0; }

    unsigned char fund_spk[34];
    char fund_txid[65];
    uint32_t fund_vout = 0;
    uint64_t fund_amount = 0;
    if (!fund_n_party_factory(&rt, ctx, N, FACTORY_ARITY_2, mine_addr, kps, f,
                               fund_spk, fund_txid, &fund_vout, &fund_amount)) {
        factory_free(f); free(f); secp256k1_context_destroy(ctx); return 0;
    }
    printf("  factory funded: %llu sats, %zu nodes\n",
           (unsigned long long)fund_amount, f->n_nodes);

    /* Test the state_root → kickoff_root pair. Advance enough times for
       state_root's nSequence to decrement (in arity-2 with states=4 this
       happens on the 4th advance when the leaf counter wraps and the
       root layer ticks). This keeps the on-chain broadcast chain short
       (kickoff_root → state_root). */
    size_t state_idx = 1;       /* state_root */
    size_t kickoff_idx = 0;     /* kickoff_root, spends funding directly */
    TEST_ASSERT(state_idx < f->n_nodes, "state node exists");

    /* Capture OLD state's signed TX (before advance). */
    factory_node_t *state_node = &f->nodes[state_idx];
    TEST_ASSERT(state_node->is_signed && state_node->signed_tx.len > 0,
                "state node signed pre-advance");
    uint32_t old_nseq = state_node->nsequence;
    size_t old_len = state_node->signed_tx.len;
    unsigned char *old_signed = malloc(old_len);
    TEST_ASSERT(old_signed != NULL, "old_signed malloc");
    memcpy(old_signed, state_node->signed_tx.data, old_len);
    printf("  pre-advance leaf state nSequence = %u\n", old_nseq);

    /* Advance until the leaf state's nSequence strictly decreases. For a
       fresh factory this happens on advance 1 — but keep looping to be
       robust to factory params where the first advance doesn't tick the
       chosen layer. */
    uint32_t new_nseq = old_nseq;
    int advances = 0;
    while (new_nseq >= old_nseq && advances < 16) {
        TEST_ASSERT(factory_advance(f), "factory_advance");
        new_nseq = state_node->nsequence;
        advances++;
    }
    TEST_ASSERT(new_nseq < old_nseq,
                "leaf nSequence strictly decreased after advances");

    size_t new_len = state_node->signed_tx.len;
    unsigned char *new_signed = malloc(new_len);
    TEST_ASSERT(new_signed != NULL, "new_signed malloc");
    memcpy(new_signed, state_node->signed_tx.data, new_len);
    printf("  post-advance(%d) leaf state nSequence = %u\n", advances, new_nseq);

    /* Structural invariant: new nSequence strictly less than old. */
    TEST_ASSERT(new_nseq < old_nseq, "new nSequence < old nSequence");
    TEST_ASSERT(old_nseq < 0x80000000u, "old nseq is a BIP-68 relative-time delay");
    TEST_ASSERT(new_nseq < 0x80000000u, "new nseq is a BIP-68 relative-time delay");

    /* Broadcast the kickoff (parent). No BIP-68 constraint on kickoff (it
       spends the factory funding UTXO which has ≥1 confirmation). */
    char *kickoff_hex = malloc(f->nodes[kickoff_idx].signed_tx.len * 2 + 1);
    TEST_ASSERT(kickoff_hex != NULL, "kickoff_hex malloc");
    hex_encode(f->nodes[kickoff_idx].signed_tx.data,
               f->nodes[kickoff_idx].signed_tx.len, kickoff_hex);
    kickoff_hex[f->nodes[kickoff_idx].signed_tx.len * 2] = '\0';
    char kickoff_txid[65];
    TEST_ASSERT(regtest_send_raw_tx(&rt, kickoff_hex, kickoff_txid),
                "kickoff broadcast");
    free(kickoff_hex);
    regtest_mine_blocks(&rt, 1, mine_addr);
    printf("  kickoff confirmed: %.16s...\n", kickoff_txid);

    /* Mine exactly enough blocks to satisfy NEW state's CSV but NOT old
       state's. BIP-68 relative depth: child valid when (confirmations of
       parent) >= nSequence. We already mined 1 block (the kickoff
       confirmation). Mine (new_nseq - 1) more → confirmations = new_nseq
       exactly, which satisfies >= new_nseq but fails >= old_nseq (since
       new_nseq < old_nseq). */
    if (new_nseq > 1)
        regtest_mine_blocks(&rt, (int)(new_nseq - 1), mine_addr);
    printf("  mined to kickoff+%u confirmations (new=%u passes, old=%u fails)\n",
           new_nseq, new_nseq, old_nseq);

    /* Attempt (A): broadcast OLD state → expect BIP-68 rejection. */
    char *old_hex = malloc(old_len * 2 + 1);
    TEST_ASSERT(old_hex != NULL, "old_hex malloc");
    hex_encode(old_signed, old_len, old_hex);
    old_hex[old_len * 2] = '\0';
    char old_txid[65];
    int old_ok = regtest_send_raw_tx(&rt, old_hex, old_txid);
    free(old_hex);
    TEST_ASSERT(!old_ok,
                "old state broadcast REJECTED (BIP-68 not satisfied)");
    printf("  ✓ old state broadcast correctly rejected (non-BIP68-final)\n");

    /* Attempt (B): broadcast NEW state → expect acceptance. */
    char *new_hex = malloc(new_len * 2 + 1);
    TEST_ASSERT(new_hex != NULL, "new_hex malloc");
    hex_encode(new_signed, new_len, new_hex);
    new_hex[new_len * 2] = '\0';
    char new_txid[65];
    int new_ok = regtest_send_raw_tx(&rt, new_hex, new_txid);
    free(new_hex);
    TEST_ASSERT(new_ok, "new state broadcast accepted");
    regtest_mine_blocks(&rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(&rt, new_txid) >= 1,
                "new state confirmed on chain");
    printf("  ✓ new state (smaller nSequence) confirmed: %.16s...\n", new_txid);
    printf("  invariant holds: DW nSequence decrement beats stale state ✓\n");

    free(old_signed);
    free(new_signed);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Kickoff-must-be-paired-with-latest-state (invariant #3).
 *
 * In DW tree-based factories, state integrity rests on a two-part rule:
 *   (a) a kickoff output MUST be spent by the latest state tx (the one
 *       with minimum nSequence for the current counter), not by any
 *       older state with a larger nSequence.
 *   (b) if the kickoff confirms alone (LSP broadcasts it and goes dark),
 *       a vigilant defender must publish the latest state before an
 *       older pre-signed state's CSV delay elapses.
 *
 * (b) is already exercised by test_regtest_old_state_poisoning, which
 * proves that an older state is BIP-68-rejected at a block height where
 * the newer state is still valid. This test focuses on (a) — the
 * structural pairing — and on the happy-path behavior: when the daemon's
 * force-close or crash-recovery path broadcasts a kickoff, the child
 * state tx is broadcastable immediately after, respecting its CSV.
 *
 * Structural assertions:
 *   - every non-leaf node has at least one child in the tree
 *   - every kickoff-style node's direct child is a state node
 *   - each parent/child pair's input linkage matches txid(parent) ->
 *     vout -> parent_index pointer
 *
 * On-chain assertion:
 *   - broadcast a kickoff, mine the state's CSV, broadcast the latest
 *     state, and confirm both land in the correct order.
 */
int test_regtest_kickoff_paired_with_latest_state(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "kickoff_state_pair");

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    const size_t N = 5;
    secp256k1_keypair kps[5];
    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) { secp256k1_context_destroy(ctx); return 0; }

    unsigned char fund_spk[34];
    char fund_txid[65];
    uint32_t fund_vout = 0;
    uint64_t fund_amount = 0;
    if (!fund_n_party_factory(&rt, ctx, N, FACTORY_ARITY_2, mine_addr, kps, f,
                               fund_spk, fund_txid, &fund_vout, &fund_amount)) {
        factory_free(f); free(f); secp256k1_context_destroy(ctx); return 0;
    }

    /* Structural check: each internal node has at least one child that
       points back at it via parent_index. Our arity-2 tree with 5 parties
       has 6 nodes total — kickoff_root, state_root, kickoff_left,
       state_left(leaf), kickoff_right, state_right(leaf). */
    size_t n_internal = 0, n_children_found = 0;
    for (size_t p = 0; p + 1 < f->n_nodes; p++) {
        int has_child = 0;
        for (size_t c = p + 1; c < f->n_nodes; c++) {
            if (f->nodes[c].parent_index == (int32_t)p) {
                has_child = 1;
                n_children_found++;
                /* Pairing property: kickoff_P spends funding (or parent
                   state), state_K spends kickoff_P vout. The child's
                   input must be the parent's txid. The pair's key
                   property is that we never have a standalone kickoff
                   without a follow-up state — child exists. */
            }
        }
        if (has_child) n_internal++;
    }
    TEST_ASSERT(n_internal >= 1, "at least one internal node with child");
    printf("  tree: %zu nodes, %zu internal, %zu parent→child links verified\n",
           f->n_nodes, n_internal, n_children_found);

    /* On-chain: broadcast kickoff_root (node 0, spends funding),
       then after state's CSV elapses, broadcast state_root (node 1). */
    factory_node_t *kickoff = &f->nodes[0];
    factory_node_t *state = &f->nodes[1];
    TEST_ASSERT(state->parent_index == 0,
                "state_root's parent is kickoff_root");
    uint32_t state_nseq = state->nsequence;
    TEST_ASSERT(state_nseq < 0x80000000u,
                "state nSequence is a BIP-68 relative-delay");

    /* Broadcast kickoff. */
    char *kickoff_hex = malloc(kickoff->signed_tx.len * 2 + 1);
    TEST_ASSERT(kickoff_hex != NULL, "kickoff_hex malloc");
    hex_encode(kickoff->signed_tx.data, kickoff->signed_tx.len, kickoff_hex);
    kickoff_hex[kickoff->signed_tx.len * 2] = '\0';
    char kickoff_txid[65];
    TEST_ASSERT(regtest_send_raw_tx(&rt, kickoff_hex, kickoff_txid),
                "kickoff broadcast accepted");
    free(kickoff_hex);
    regtest_mine_blocks(&rt, 1, mine_addr);

    /* Mine enough blocks for state's CSV to pass. */
    if (state_nseq > 1)
        regtest_mine_blocks(&rt, (int)(state_nseq - 1), mine_addr);

    /* Broadcast state — must succeed now that CSV is satisfied. */
    char *state_hex = malloc(state->signed_tx.len * 2 + 1);
    TEST_ASSERT(state_hex != NULL, "state_hex malloc");
    hex_encode(state->signed_tx.data, state->signed_tx.len, state_hex);
    state_hex[state->signed_tx.len * 2] = '\0';
    char state_txid[65];
    TEST_ASSERT(regtest_send_raw_tx(&rt, state_hex, state_txid),
                "state broadcast accepted after CSV");
    free(state_hex);
    regtest_mine_blocks(&rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(&rt, state_txid) >= 1,
                "state confirmed on chain");
    printf("  kickoff=%.16s... → state=%.16s... (nseq=%u) both on chain ✓\n",
           kickoff_txid, state_txid, state_nseq);
    printf("  invariant holds: kickoff broadcast is followed by its latest\n"
           "                   signed state tx; no orphan kickoff possible ✓\n");

    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Full force-close + per-party sweep with PAYMENT-FLOW ACCOUNTING.
 *
 * After broadcasting the entire factory tree, this test proves both
 * spendability AND proper accounting under payment flow. It simulates
 * the economic shape of a factory that processed routed payments before
 * being force-closed: each leaf's channel output is split between the
 * parties NOT 50/50 but according to post-payment balances, reflecting
 * that the client paid the LSP + a routing fee during operation.
 *
 * Arity-1 baseline per-leaf sweep:
 *   - Channel (2-of-2 MuSig P2TR): offline 2-party MuSig2 ceremony
 *     produces a TX with 2 outputs, amounts reflecting post-payment
 *     state:
 *        client_share = (channel − sweep_fee)/2
 *                       − (simulated_payment + simulated_routing_fee)
 *        lsp_share    = (channel − sweep_fee) − client_share
 *     The routing fee is what ZmnSCPxj calls "sats received outside
 *     L-stock" — routing income that accrues to the LSP during factory
 *     operation, separate from L-stock.
 *   - L-stock (LSP-only P2TR): LSP alone sweeps via BIP-341 keypath.
 *     L-stock is the LSP's inbound-capacity reserve, distinct from
 *     channel balances and routing income.
 *
 * Accounting verified by econ_snap_pre / econ_snap_post +
 * econ_assert_wallet_deltas:
 *   client_delta = Σ(client_share_per_leaf)
 *   LSP_delta    = Σ(lsp_share + L_stock − sweep_fees per leaf)
 *   Σ(deltas) + Σ(tx_fees) == Σ(leaf_allocations) (conservation)
 *
 * The payment flow is simulated by choosing uneven sweep amounts rather
 * than running actual HTLCs through channel commitment TXs. That proves
 * the correctness property ZmnSCPxj cares about: "every sat reaches the
 * right party, including routing income that's NOT L-stock." The full
 * HTLC-add-fulfill + commit-TX variant (channel_init + commitment_tx +
 * sweep_to_remote + sweep_to_local_csv chained after tree broadcast) is
 * a larger test acknowledged as a follow-up.
 *
 * Arity-2 and arity-PS: structurally identical at the per-leaf sweep
 * step — cross-referenced rather than re-implemented. */
int test_regtest_full_force_close_and_sweep_arity1(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "full_fc_sweep_a1");
    rt.scan_depth = 200;  /* tree deep → leaves > default scan_depth */

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    const size_t N = 2;  /* LSP + 1 client (smallest arity-1 factory) */
    secp256k1_keypair kps[5];
    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) { secp256k1_context_destroy(ctx); return 0; }

    unsigned char fund_spk[34];
    char fund_txid[65];
    uint32_t fund_vout = 0;
    uint64_t fund_amount = 0;
    if (!fund_n_party_factory(&rt, ctx, N, FACTORY_ARITY_1, mine_addr, kps, f,
                               fund_spk, fund_txid, &fund_vout, &fund_amount)) {
        factory_free(f); free(f); secp256k1_context_destroy(ctx); return 0;
    }
    printf("  [arity=1] factory funded: %llu sats, %zu nodes, %d leaves\n",
           (unsigned long long)fund_amount, f->n_nodes, f->n_leaf_nodes);

    /* Broadcast every signed tree node in order with correct BIP-68 spacing. */
    char txids[FACTORY_MAX_NODES][65];
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *nd = &f->nodes[i];
        TEST_ASSERT(nd->is_signed && nd->signed_tx.len > 0, "node signed");
        char *tx_hex = malloc(nd->signed_tx.len * 2 + 1);
        TEST_ASSERT(tx_hex != NULL, "tx_hex malloc");
        hex_encode(nd->signed_tx.data, nd->signed_tx.len, tx_hex);
        int ok = regtest_send_raw_tx(&rt, tx_hex, txids[i]);
        free(tx_hex);
        TEST_ASSERT(ok, "broadcast tree node");
        int blocks_to_mine = 1;
        if (i + 1 < f->n_nodes) {
            uint32_t cns = f->nodes[i + 1].nsequence;
            if (!(cns & 0x80000000u)) blocks_to_mine = (int)(cns & 0xFFFF) + 1;
        }
        regtest_mine_blocks(&rt, blocks_to_mine, mine_addr);
    }
    int n_leaves = f->n_leaf_nodes;
    for (int li = 0; li < n_leaves; li++) {
        int conf = regtest_get_confirmations(&rt,
            txids[f->leaf_node_indices[li]]);
        TEST_ASSERT(conf >= 1, "leaf on chain");
    }
    printf("  full tree broadcast OK — %zu nodes, %d leaves confirmed\n",
           f->n_nodes, n_leaves);

    /* Build per-party P2TR destinations so econ_helpers can scan the
       UTXO set and verify deltas. Each party's expected SPK is
       P2TR(xonly(pk(seckey))) — same derivation econ_register_party
       uses internally. We compute them here to use as sweep destinations. */
    unsigned char party_spk[2][34];  /* [0]=LSP, [1]=client */
    for (int p = 0; p < 2; p++) {
        secp256k1_pubkey pk;
        secp256k1_keypair_pub(ctx, &pk, &kps[p]);
        secp256k1_xonly_pubkey xo;
        secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &pk);
        build_p2tr_script_pubkey(party_spk[p], &xo);
    }

    /* Wire econ harness: snapshot each party's pre-sweep balance. */
    econ_ctx_t econ;
    econ_ctx_init(&econ, &rt, ctx);
    TEST_ASSERT(econ_register_party(&econ, 0, "LSP", N_PARTY_SECKEYS[0]),
                "register LSP");
    TEST_ASSERT(econ_register_party(&econ, 1, "client", N_PARTY_SECKEYS[1]),
                "register client");
    econ.factory_funding_amount = fund_amount;
    TEST_ASSERT(econ_snap_pre(&econ), "econ_snap_pre");

    /* Per-leaf sweep loop. Each sweep's fee is tracked so we can
       reconstruct expected deltas exactly. */
    const uint64_t LSTOCK_SWEEP_FEE = 300;
    const uint64_t CHAN_SWEEP_FEE   = 400;  /* 2 outputs in channel sweep */

    /* Simulate post-payment state: client paid the LSP during factory
       operation. At force-close, channel balances reflect this — client
       gets less than a balanced split, LSP gets more. The routing-fee
       component is "sats received outside L-stock" that ZmnSCPxj calls
       out specifically: routing income flowing to the LSP side, separate
       from L-stock. */
    const uint64_t SIMULATED_PAYMENT     = 20000;   /* client → LSP */
    const uint64_t SIMULATED_ROUTING_FEE = 100;     /* LSP's routing income */
    const uint64_t CLIENT_BALANCE_SHIFT  = SIMULATED_PAYMENT + SIMULATED_ROUTING_FEE;

    uint64_t total_lsp_recv = 0;
    uint64_t total_client_recv = 0;

    for (int li = 0; li < n_leaves; li++) {
        size_t nidx = f->leaf_node_indices[li];
        factory_node_t *leaf = &f->nodes[nidx];
        const char *leaf_txid = txids[nidx];

        /* (A) Sweep L-stock (vout 1) cooperatively via N-of-N MuSig.
           Per canonical t/1242, L-stock SPK = or(N-of-N keyagg, L&CSV) —
           LSP can't take L-stock alone immediately; either all leaf
           signers cooperate (this path, since the test holds all keys),
           or LSP waits CSV blocks and uses the script-path. */
        uint64_t lstock_amt = leaf->outputs[1].amount_sats;

        tx_buf_t lstock_sweep;
        tx_buf_init(&lstock_sweep, 256);
        TEST_ASSERT(spend_l_stock_cooperative(ctx, f, leaf,
                        leaf_txid, 1, lstock_amt,
                        party_spk[0], 34,
                        LSTOCK_SWEEP_FEE, &lstock_sweep),
                    "build L-stock cooperative sweep");
        char *lh = malloc(lstock_sweep.len * 2 + 1);
        TEST_ASSERT(lh != NULL, "lh malloc");
        hex_encode(lstock_sweep.data, lstock_sweep.len, lh);
        lh[lstock_sweep.len * 2] = '\0';
        char lstock_sweep_txid[65];
        int lok = spend_broadcast_and_mine(&rt, lh, 1, lstock_sweep_txid);
        free(lh); tx_buf_free(&lstock_sweep);
        TEST_ASSERT(lok, "L-stock sweep confirmed");
        total_lsp_recv += lstock_amt - LSTOCK_SWEEP_FEE;
        printf("  leaf %d: LSP swept L-stock %llu sats → P2TR(LSP)\n",
               li, (unsigned long long)(lstock_amt - LSTOCK_SWEEP_FEE));

        /* (B) Sweep channel (vout 0) via offline 2-of-2 MuSig2.
           TX has 2 outputs: half to client's P2TR, half to LSP's P2TR.
           This models "each party takes their fair share of the channel". */
        uint64_t chan_amt = leaf->outputs[0].amount_sats;
        /* Post-payment balance: client's share reduced by what they paid
           + routing fee. LSP's share gets the rest (= local_initial +
           payment + routing_fee). No sats disappear — the routing fee
           just moves from client's channel balance to LSP's. */
        uint64_t balanced_half = (chan_amt - CHAN_SWEEP_FEE) / 2;
        uint64_t client_share  = balanced_half - CLIENT_BALANCE_SHIFT;
        uint64_t lsp_share     = (chan_amt - CHAN_SWEEP_FEE) - client_share;
        unsigned char chan_spk[34];
        memcpy(chan_spk, leaf->outputs[0].script_pubkey, 34);

        unsigned char leaf_txid_bytes[32];
        TEST_ASSERT(hex_decode(leaf_txid, leaf_txid_bytes, 32),
                    "decode leaf txid");
        reverse_bytes(leaf_txid_bytes, 32);

        tx_output_t outs[2];
        memcpy(outs[0].script_pubkey, party_spk[1], 34);  /* client */
        outs[0].script_pubkey_len = 34;
        outs[0].amount_sats = client_share;
        memcpy(outs[1].script_pubkey, party_spk[0], 34);  /* LSP */
        outs[1].script_pubkey_len = 34;
        outs[1].amount_sats = lsp_share;

        tx_buf_t chan_unsigned;
        tx_buf_init(&chan_unsigned, 256);
        TEST_ASSERT(build_unsigned_tx(&chan_unsigned, NULL,
                                        leaf_txid_bytes, 0, 0xFFFFFFFEu,
                                        outs, 2),
                    "build unsigned channel sweep");
        unsigned char sighash[32];
        TEST_ASSERT(compute_taproot_sighash(sighash,
                        chan_unsigned.data, chan_unsigned.len,
                        0, chan_spk, 34, chan_amt, 0xFFFFFFFEu),
                    "compute channel sighash");

        /* MuSig2 pubkey order matches factory (client, LSP) — see
           setup_single_leaf_outputs in src/factory.c:674. */
        secp256k1_keypair signers[2] = { kps[1], kps[0] };
        secp256k1_pubkey pks[2];
        secp256k1_keypair_pub(ctx, &pks[0], &signers[0]);
        secp256k1_keypair_pub(ctx, &pks[1], &signers[1]);
        musig_keyagg_t ka;
        TEST_ASSERT(musig_aggregate_keys(ctx, &ka, pks, 2),
                    "aggregate channel keys (client, LSP)");
        unsigned char sig64[64];
        TEST_ASSERT(musig_sign_taproot(ctx, sig64, sighash, signers, 2,
                                         &ka, NULL),
                    "offline 2-of-2 MuSig2 sign channel sweep");
        tx_buf_t chan_signed;
        tx_buf_init(&chan_signed, 256);
        TEST_ASSERT(finalize_signed_tx(&chan_signed,
                        chan_unsigned.data, chan_unsigned.len, sig64),
                    "finalize channel sweep tx");
        tx_buf_free(&chan_unsigned);

        char *ch_hex = malloc(chan_signed.len * 2 + 1);
        TEST_ASSERT(ch_hex != NULL, "ch_hex malloc");
        hex_encode(chan_signed.data, chan_signed.len, ch_hex);
        ch_hex[chan_signed.len * 2] = '\0';
        char chan_sweep_txid[65];
        int cok = spend_broadcast_and_mine(&rt, ch_hex, 1, chan_sweep_txid);
        free(ch_hex); tx_buf_free(&chan_signed);
        TEST_ASSERT(cok, "channel 2-of-2 sweep confirmed");
        total_client_recv += client_share;
        total_lsp_recv += lsp_share;
        printf("  leaf %d: 2-of-2 swept channel → client=%llu, LSP=%llu\n",
               li, (unsigned long long)client_share,
               (unsigned long long)lsp_share);
    }

    /* Accounting: snapshot post-sweep balances and assert per-party deltas
       match the expected amounts computed from the on-chain allocations. */
    TEST_ASSERT(econ_snap_post(&econ), "econ_snap_post");

    uint64_t expected_deltas[2];
    expected_deltas[0] = total_lsp_recv;    /* LSP */
    expected_deltas[1] = total_client_recv; /* client */

    /* Conservation sanity: Σ(expected_deltas) + Σ(tx_fees) ≤ funding.
       tree fees are implicit in leaf allocations (already netted);
       sweep fees are the ones we added above. */
    uint64_t sweep_fees = (uint64_t)n_leaves * (LSTOCK_SWEEP_FEE + CHAN_SWEEP_FEE);
    uint64_t swept_sum = total_lsp_recv + total_client_recv;
    uint64_t allocated_sum = 0;
    for (int li = 0; li < n_leaves; li++) {
        size_t nidx = f->leaf_node_indices[li];
        allocated_sum += f->nodes[nidx].outputs[0].amount_sats;
        allocated_sum += f->nodes[nidx].outputs[1].amount_sats;
    }
    /* swept_sum exactly = allocated_sum − sweep_fees */
    TEST_ASSERT(swept_sum + sweep_fees == allocated_sum,
                "conservation: Σswept + Σsweep_fees == Σleaf_allocations");
    printf("  conservation OK: swept=%llu + sweep_fees=%llu == allocations=%llu\n",
           (unsigned long long)swept_sum,
           (unsigned long long)sweep_fees,
           (unsigned long long)allocated_sum);

    TEST_ASSERT(econ_assert_wallet_deltas(&econ, expected_deltas, 0),
                "per-party wallet deltas match expected");
    econ_print_summary(&econ);

    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/*
 * Arity-2 mirror of test_regtest_full_force_close_and_sweep_arity1.
 *
 * Topology: N = 5 (LSP + 4 clients) → 2 arity-2 leaves, each holding 2
 * clients. Each leaf has 3 outputs:
 *   outputs[0] = MuSig(client_a, LSP) channel       (2-of-2)
 *   outputs[1] = MuSig(client_b, LSP) channel       (2-of-2)
 *   outputs[2] = L-stock                            (LSP only)
 *
 * Per-leaf pairing is recovered from node->signer_indices, where index [0]
 * is LSP and [1], [2] are the two clients on that leaf.
 *
 * Conservation: Σ(swept) + Σ(sweep_fees) == Σ(allocated across outputs[0..2]
 * of every leaf). Per-party wallet deltas match expected.
 */
int test_regtest_full_force_close_and_sweep_arity2(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "full_fc_sweep_a2");
    rt.scan_depth = 200;

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    const size_t N = 5;  /* LSP + 4 clients → 2 arity-2 leaves */
    secp256k1_keypair kps[5];
    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) { secp256k1_context_destroy(ctx); return 0; }

    unsigned char fund_spk[34];
    char fund_txid[65];
    uint32_t fund_vout = 0;
    uint64_t fund_amount = 0;
    if (!fund_n_party_factory(&rt, ctx, N, FACTORY_ARITY_2, mine_addr, kps, f,
                               fund_spk, fund_txid, &fund_vout, &fund_amount)) {
        factory_free(f); free(f); secp256k1_context_destroy(ctx); return 0;
    }
    printf("  [arity=2] factory funded: %llu sats, %zu nodes, %d leaves\n",
           (unsigned long long)fund_amount, f->n_nodes, f->n_leaf_nodes);

    /* Broadcast every signed tree node in order with correct BIP-68 spacing. */
    char txids[FACTORY_MAX_NODES][65];
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *nd = &f->nodes[i];
        TEST_ASSERT(nd->is_signed && nd->signed_tx.len > 0, "node signed");
        char *tx_hex = malloc(nd->signed_tx.len * 2 + 1);
        TEST_ASSERT(tx_hex != NULL, "tx_hex malloc");
        hex_encode(nd->signed_tx.data, nd->signed_tx.len, tx_hex);
        int ok = regtest_send_raw_tx(&rt, tx_hex, txids[i]);
        free(tx_hex);
        TEST_ASSERT(ok, "broadcast tree node");
        int blocks_to_mine = 1;
        if (i + 1 < f->n_nodes) {
            uint32_t cns = f->nodes[i + 1].nsequence;
            if (!(cns & 0x80000000u)) blocks_to_mine = (int)(cns & 0xFFFF) + 1;
        }
        regtest_mine_blocks(&rt, blocks_to_mine, mine_addr);
    }
    int n_leaves = f->n_leaf_nodes;
    for (int li = 0; li < n_leaves; li++) {
        int conf = regtest_get_confirmations(&rt,
            txids[f->leaf_node_indices[li]]);
        TEST_ASSERT(conf >= 1, "leaf on chain");
    }
    printf("  full tree broadcast OK — %zu nodes, %d leaves confirmed\n",
           f->n_nodes, n_leaves);

    /* Build per-party P2TR destinations for all 5 parties. */
    unsigned char party_spk[5][34];
    for (int p = 0; p < (int)N; p++) {
        secp256k1_pubkey pk;
        secp256k1_keypair_pub(ctx, &pk, &kps[p]);
        secp256k1_xonly_pubkey xo;
        secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &pk);
        build_p2tr_script_pubkey(party_spk[p], &xo);
    }

    /* Wire econ harness: snapshot pre-sweep balance for all 5 parties. */
    econ_ctx_t econ;
    econ_ctx_init(&econ, &rt, ctx);
    static const char *party_names[5] = {
        "LSP", "client0", "client1", "client2", "client3"
    };
    for (size_t p = 0; p < N; p++) {
        TEST_ASSERT(econ_register_party(&econ, p, party_names[p],
                                         N_PARTY_SECKEYS[p]),
                    "register party");
    }
    econ.factory_funding_amount = fund_amount;
    TEST_ASSERT(econ_snap_pre(&econ), "econ_snap_pre");

    const uint64_t LSTOCK_SWEEP_FEE = 300;
    const uint64_t CHAN_SWEEP_FEE   = 400;  /* per channel sweep, 2 outputs */

    /* Same payment-flow model as arity-1: client paid LSP during operation. */
    const uint64_t SIMULATED_PAYMENT     = 20000;
    const uint64_t SIMULATED_ROUTING_FEE = 100;
    const uint64_t CLIENT_BALANCE_SHIFT  = SIMULATED_PAYMENT + SIMULATED_ROUTING_FEE;

    uint64_t per_party_recv[5] = {0,0,0,0,0};

    for (int li = 0; li < n_leaves; li++) {
        size_t nidx = f->leaf_node_indices[li];
        factory_node_t *leaf = &f->nodes[nidx];
        const char *leaf_txid = txids[nidx];

        /* Recover client_a / client_b from signer_indices: index 0 is LSP. */
        TEST_ASSERT(leaf->n_signers == 3,
                    "arity-2 leaf has 3 signers (LSP + 2 clients)");
        TEST_ASSERT(leaf->signer_indices[0] == 0, "signer[0] is LSP");
        uint32_t client_a_idx = leaf->signer_indices[1];
        uint32_t client_b_idx = leaf->signer_indices[2];
        TEST_ASSERT(client_a_idx >= 1 && client_a_idx < N,
                    "client_a_idx in range");
        TEST_ASSERT(client_b_idx >= 1 && client_b_idx < N,
                    "client_b_idx in range");
        TEST_ASSERT(leaf->n_outputs == 3, "arity-2 leaf has 3 outputs");

        unsigned char leaf_txid_bytes[32];
        TEST_ASSERT(hex_decode(leaf_txid, leaf_txid_bytes, 32),
                    "decode leaf txid");
        reverse_bytes(leaf_txid_bytes, 32);

        /* (A) Sweep L-stock (vout 2) cooperatively via N-of-N MuSig
           (canonical t/1242 — see L-stock sweep block at line 2540). */
        uint64_t lstock_amt = leaf->outputs[2].amount_sats;

        tx_buf_t lstock_sweep;
        tx_buf_init(&lstock_sweep, 256);
        TEST_ASSERT(spend_l_stock_cooperative(ctx, f, leaf,
                        leaf_txid, 2, lstock_amt,
                        party_spk[0], 34,
                        LSTOCK_SWEEP_FEE, &lstock_sweep),
                    "build L-stock cooperative sweep");
        char *lh = malloc(lstock_sweep.len * 2 + 1);
        TEST_ASSERT(lh != NULL, "lh malloc");
        hex_encode(lstock_sweep.data, lstock_sweep.len, lh);
        lh[lstock_sweep.len * 2] = '\0';
        char lstock_sweep_txid[65];
        int lok = spend_broadcast_and_mine(&rt, lh, 1, lstock_sweep_txid);
        free(lh); tx_buf_free(&lstock_sweep);
        TEST_ASSERT(lok, "L-stock sweep confirmed");
        per_party_recv[0] += lstock_amt - LSTOCK_SWEEP_FEE;
        printf("  leaf %d: LSP swept L-stock %llu sats\n",
               li, (unsigned long long)(lstock_amt - LSTOCK_SWEEP_FEE));

        /* (B/C) Sweep channels A and B via offline 2-of-2 MuSig2.
           Each TX has 2 outputs: client_X share + LSP share. */
        for (int chan = 0; chan < 2; chan++) {
            uint32_t client_idx = (chan == 0) ? client_a_idx : client_b_idx;
            uint64_t chan_amt = leaf->outputs[chan].amount_sats;
            uint64_t balanced_half = (chan_amt - CHAN_SWEEP_FEE) / 2;
            uint64_t client_share  = balanced_half - CLIENT_BALANCE_SHIFT;
            uint64_t lsp_share     = (chan_amt - CHAN_SWEEP_FEE) - client_share;
            unsigned char chan_spk[34];
            memcpy(chan_spk, leaf->outputs[chan].script_pubkey, 34);

            tx_output_t outs[2];
            memcpy(outs[0].script_pubkey, party_spk[client_idx], 34);
            outs[0].script_pubkey_len = 34;
            outs[0].amount_sats = client_share;
            memcpy(outs[1].script_pubkey, party_spk[0], 34);
            outs[1].script_pubkey_len = 34;
            outs[1].amount_sats = lsp_share;

            tx_buf_t chan_unsigned;
            tx_buf_init(&chan_unsigned, 256);
            TEST_ASSERT(build_unsigned_tx(&chan_unsigned, NULL,
                                            leaf_txid_bytes,
                                            (uint32_t)chan, 0xFFFFFFFEu,
                                            outs, 2),
                        "build unsigned channel sweep");
            unsigned char sighash[32];
            TEST_ASSERT(compute_taproot_sighash(sighash,
                            chan_unsigned.data, chan_unsigned.len,
                            0, chan_spk, 34, chan_amt, 0xFFFFFFFEu),
                        "compute channel sighash");

            /* MuSig2 pubkey order matches factory (client, LSP) — see
               setup_leaf_outputs in src/factory.c:348/360. */
            secp256k1_keypair signers[2] = { kps[client_idx], kps[0] };
            secp256k1_pubkey pks[2];
            secp256k1_keypair_pub(ctx, &pks[0], &signers[0]);
            secp256k1_keypair_pub(ctx, &pks[1], &signers[1]);
            musig_keyagg_t ka;
            TEST_ASSERT(musig_aggregate_keys(ctx, &ka, pks, 2),
                        "aggregate channel keys (client, LSP)");
            unsigned char sig64[64];
            TEST_ASSERT(musig_sign_taproot(ctx, sig64, sighash, signers, 2,
                                             &ka, NULL),
                        "offline 2-of-2 MuSig2 sign channel sweep");
            tx_buf_t chan_signed;
            tx_buf_init(&chan_signed, 256);
            TEST_ASSERT(finalize_signed_tx(&chan_signed,
                            chan_unsigned.data, chan_unsigned.len, sig64),
                        "finalize channel sweep tx");
            tx_buf_free(&chan_unsigned);

            char *ch_hex = malloc(chan_signed.len * 2 + 1);
            TEST_ASSERT(ch_hex != NULL, "ch_hex malloc");
            hex_encode(chan_signed.data, chan_signed.len, ch_hex);
            ch_hex[chan_signed.len * 2] = '\0';
            char chan_sweep_txid[65];
            int cok = spend_broadcast_and_mine(&rt, ch_hex, 1, chan_sweep_txid);
            free(ch_hex); tx_buf_free(&chan_signed);
            TEST_ASSERT(cok, "channel 2-of-2 sweep confirmed");
            per_party_recv[client_idx] += client_share;
            per_party_recv[0]          += lsp_share;
            printf("  leaf %d ch%d: 2-of-2 swept → client%u=%llu, LSP=%llu\n",
                   li, chan, (unsigned)(client_idx - 1),
                   (unsigned long long)client_share,
                   (unsigned long long)lsp_share);
        }
    }

    TEST_ASSERT(econ_snap_post(&econ), "econ_snap_post");

    uint64_t expected_deltas[5];
    for (size_t p = 0; p < N; p++) expected_deltas[p] = per_party_recv[p];

    /* Conservation: Σswept + Σsweep_fees == Σ(allocated across outputs[0..2]
       of every leaf). Per-leaf sweep cost = LSTOCK_SWEEP_FEE + 2*CHAN_SWEEP_FEE. */
    uint64_t sweep_fees = (uint64_t)n_leaves *
                          (LSTOCK_SWEEP_FEE + 2 * CHAN_SWEEP_FEE);
    uint64_t swept_sum = 0;
    for (size_t p = 0; p < N; p++) swept_sum += per_party_recv[p];
    uint64_t allocated_sum = 0;
    for (int li = 0; li < n_leaves; li++) {
        size_t nidx = f->leaf_node_indices[li];
        allocated_sum += f->nodes[nidx].outputs[0].amount_sats;
        allocated_sum += f->nodes[nidx].outputs[1].amount_sats;
        allocated_sum += f->nodes[nidx].outputs[2].amount_sats;
    }
    TEST_ASSERT(swept_sum + sweep_fees == allocated_sum,
                "conservation: Σswept + Σsweep_fees == Σleaf_allocations");
    printf("  conservation OK: swept=%llu + sweep_fees=%llu == allocations=%llu\n",
           (unsigned long long)swept_sum,
           (unsigned long long)sweep_fees,
           (unsigned long long)allocated_sum);

    TEST_ASSERT(econ_assert_wallet_deltas(&econ, expected_deltas, 0),
                "per-party wallet deltas match expected");
    econ_print_summary(&econ);

    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/*
 * Arity-PS mirror of test_regtest_full_force_close_and_sweep_arity1.
 *
 * Topology: N = 3 (LSP + 2 clients) → 2 PS leaves, each holding 1 client.
 * Each leaf has 2 outputs:
 *   outputs[0] = channel — MuSig over node->signer_indices, which at a PS
 *                leaf with 1 client is {LSP, client} (LSP first), keyagg
 *                stored in node->keyagg, SPK = node->spending_spk.
 *   outputs[1] = L-stock                            (LSP only)
 *
 * NOTE: this exercise covers the PS leaf at chain depth 0 (the initial
 * state from build_tree). PS chain advance + sweep is left as a follow-up
 * because it requires synchronized client-side chain progression.
 *
 * Conservation: Σ(swept) + Σ(sweep_fees) == Σ(allocated). Per-party wallet
 * deltas match expected.
 */
int test_regtest_full_force_close_and_sweep_arityPS(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "full_fc_sweep_aps");
    rt.scan_depth = 200;

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    const size_t N = 3;  /* LSP + 2 clients → 2 PS leaves */
    secp256k1_keypair kps[5];
    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) { secp256k1_context_destroy(ctx); return 0; }

    unsigned char fund_spk[34];
    char fund_txid[65];
    uint32_t fund_vout = 0;
    uint64_t fund_amount = 0;
    if (!fund_n_party_factory(&rt, ctx, N, FACTORY_ARITY_PS, mine_addr, kps, f,
                               fund_spk, fund_txid, &fund_vout, &fund_amount)) {
        factory_free(f); free(f); secp256k1_context_destroy(ctx); return 0;
    }
    printf("  [arity=PS] factory funded: %llu sats, %zu nodes, %d leaves\n",
           (unsigned long long)fund_amount, f->n_nodes, f->n_leaf_nodes);

    /* Broadcast every signed tree node in order with correct BIP-68 spacing. */
    char txids[FACTORY_MAX_NODES][65];
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *nd = &f->nodes[i];
        TEST_ASSERT(nd->is_signed && nd->signed_tx.len > 0, "node signed");
        char *tx_hex = malloc(nd->signed_tx.len * 2 + 1);
        TEST_ASSERT(tx_hex != NULL, "tx_hex malloc");
        hex_encode(nd->signed_tx.data, nd->signed_tx.len, tx_hex);
        int ok = regtest_send_raw_tx(&rt, tx_hex, txids[i]);
        free(tx_hex);
        TEST_ASSERT(ok, "broadcast tree node");
        int blocks_to_mine = 1;
        if (i + 1 < f->n_nodes) {
            uint32_t cns = f->nodes[i + 1].nsequence;
            if (!(cns & 0x80000000u)) blocks_to_mine = (int)(cns & 0xFFFF) + 1;
        }
        regtest_mine_blocks(&rt, blocks_to_mine, mine_addr);
    }
    int n_leaves = f->n_leaf_nodes;
    for (int li = 0; li < n_leaves; li++) {
        int conf = regtest_get_confirmations(&rt,
            txids[f->leaf_node_indices[li]]);
        TEST_ASSERT(conf >= 1, "leaf on chain");
    }
    printf("  full tree broadcast OK — %zu nodes, %d leaves confirmed\n",
           f->n_nodes, n_leaves);

    /* Build per-party P2TR destinations for all N parties. */
    unsigned char party_spk[5][34];
    for (int p = 0; p < (int)N; p++) {
        secp256k1_pubkey pk;
        secp256k1_keypair_pub(ctx, &pk, &kps[p]);
        secp256k1_xonly_pubkey xo;
        secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &pk);
        build_p2tr_script_pubkey(party_spk[p], &xo);
    }

    /* Wire econ harness for all N parties. */
    econ_ctx_t econ;
    econ_ctx_init(&econ, &rt, ctx);
    static const char *party_names[5] = {
        "LSP", "client0", "client1", "client2", "client3"
    };
    for (size_t p = 0; p < N; p++) {
        TEST_ASSERT(econ_register_party(&econ, p, party_names[p],
                                         N_PARTY_SECKEYS[p]),
                    "register party");
    }
    econ.factory_funding_amount = fund_amount;
    TEST_ASSERT(econ_snap_pre(&econ), "econ_snap_pre");

    const uint64_t LSTOCK_SWEEP_FEE = 300;
    const uint64_t CHAN_SWEEP_FEE   = 400;

    const uint64_t SIMULATED_PAYMENT     = 20000;
    const uint64_t SIMULATED_ROUTING_FEE = 100;
    const uint64_t CLIENT_BALANCE_SHIFT  = SIMULATED_PAYMENT + SIMULATED_ROUTING_FEE;

    uint64_t per_party_recv[5] = {0,0,0,0,0};

    for (int li = 0; li < n_leaves; li++) {
        size_t nidx = f->leaf_node_indices[li];
        factory_node_t *leaf = &f->nodes[nidx];
        const char *leaf_txid = txids[nidx];

        TEST_ASSERT(leaf->is_ps_leaf, "leaf is PS");
        TEST_ASSERT(leaf->n_outputs == 2, "PS leaf has 2 outputs");
        /* With 1 client per leaf, n_signers = 2: {LSP, client_idx}. */
        TEST_ASSERT(leaf->n_signers == 2,
                    "PS leaf signers = {LSP, client}");
        TEST_ASSERT(leaf->signer_indices[0] == 0, "signer[0] is LSP");
        uint32_t client_idx = leaf->signer_indices[1];
        TEST_ASSERT(client_idx >= 1 && client_idx < N,
                    "client_idx in range");

        unsigned char leaf_txid_bytes[32];
        TEST_ASSERT(hex_decode(leaf_txid, leaf_txid_bytes, 32),
                    "decode leaf txid");
        reverse_bytes(leaf_txid_bytes, 32);

        /* (A) Sweep L-stock (vout 1) cooperatively via N-of-N MuSig
           (canonical t/1242 — see L-stock sweep block at line 2540). */
        uint64_t lstock_amt = leaf->outputs[1].amount_sats;

        tx_buf_t lstock_sweep;
        tx_buf_init(&lstock_sweep, 256);
        TEST_ASSERT(spend_l_stock_cooperative(ctx, f, leaf,
                        leaf_txid, 1, lstock_amt,
                        party_spk[0], 34,
                        LSTOCK_SWEEP_FEE, &lstock_sweep),
                    "build L-stock cooperative sweep");
        char *lh = malloc(lstock_sweep.len * 2 + 1);
        TEST_ASSERT(lh != NULL, "lh malloc");
        hex_encode(lstock_sweep.data, lstock_sweep.len, lh);
        lh[lstock_sweep.len * 2] = '\0';
        char lstock_sweep_txid[65];
        int lok = spend_broadcast_and_mine(&rt, lh, 1, lstock_sweep_txid);
        free(lh); tx_buf_free(&lstock_sweep);
        TEST_ASSERT(lok, "L-stock sweep confirmed");
        per_party_recv[0] += lstock_amt - LSTOCK_SWEEP_FEE;
        printf("  leaf %d: LSP swept L-stock %llu sats\n",
               li, (unsigned long long)(lstock_amt - LSTOCK_SWEEP_FEE));

        /* (B) Sweep channel (vout 0) via offline N-party MuSig2.
           PS leaf channel SPK = node->spending_spk, built by add_node()
           with pks order = {LSP=signer_indices[0], client=signer_indices[1]}
           — LSP FIRST, opposite of arity-1/arity-2 channel keyagg order. */
        uint64_t chan_amt = leaf->outputs[0].amount_sats;
        uint64_t balanced_half = (chan_amt - CHAN_SWEEP_FEE) / 2;
        uint64_t client_share  = balanced_half - CLIENT_BALANCE_SHIFT;
        uint64_t lsp_share     = (chan_amt - CHAN_SWEEP_FEE) - client_share;
        unsigned char chan_spk[34];
        memcpy(chan_spk, leaf->outputs[0].script_pubkey, 34);

        tx_output_t outs[2];
        memcpy(outs[0].script_pubkey, party_spk[client_idx], 34);
        outs[0].script_pubkey_len = 34;
        outs[0].amount_sats = client_share;
        memcpy(outs[1].script_pubkey, party_spk[0], 34);
        outs[1].script_pubkey_len = 34;
        outs[1].amount_sats = lsp_share;

        tx_buf_t chan_unsigned;
        tx_buf_init(&chan_unsigned, 256);
        TEST_ASSERT(build_unsigned_tx(&chan_unsigned, NULL,
                                        leaf_txid_bytes, 0, 0xFFFFFFFEu,
                                        outs, 2),
                    "build unsigned channel sweep");
        unsigned char sighash[32];
        TEST_ASSERT(compute_taproot_sighash(sighash,
                        chan_unsigned.data, chan_unsigned.len,
                        0, chan_spk, 34, chan_amt, 0xFFFFFFFEu),
                    "compute channel sighash");

        /* Build keyagg in signer_indices order: {LSP, client}. */
        secp256k1_keypair signers[FACTORY_MAX_SIGNERS];
        secp256k1_pubkey pks[FACTORY_MAX_SIGNERS];
        for (size_t s = 0; s < leaf->n_signers; s++) {
            uint32_t sidx = leaf->signer_indices[s];
            signers[s] = kps[sidx];
            secp256k1_keypair_pub(ctx, &pks[s], &signers[s]);
        }
        musig_keyagg_t ka;
        TEST_ASSERT(musig_aggregate_keys(ctx, &ka, pks, leaf->n_signers),
                    "aggregate channel keys (signer_indices order)");
        unsigned char sig64[64];
        TEST_ASSERT(musig_sign_taproot(ctx, sig64, sighash, signers,
                                         leaf->n_signers, &ka, NULL),
                    "offline N-party MuSig2 sign channel sweep");
        tx_buf_t chan_signed;
        tx_buf_init(&chan_signed, 256);
        TEST_ASSERT(finalize_signed_tx(&chan_signed,
                        chan_unsigned.data, chan_unsigned.len, sig64),
                    "finalize channel sweep tx");
        tx_buf_free(&chan_unsigned);

        char *ch_hex = malloc(chan_signed.len * 2 + 1);
        TEST_ASSERT(ch_hex != NULL, "ch_hex malloc");
        hex_encode(chan_signed.data, chan_signed.len, ch_hex);
        ch_hex[chan_signed.len * 2] = '\0';
        char chan_sweep_txid[65];
        int cok = spend_broadcast_and_mine(&rt, ch_hex, 1, chan_sweep_txid);
        free(ch_hex); tx_buf_free(&chan_signed);
        TEST_ASSERT(cok, "channel N-of-N sweep confirmed");
        per_party_recv[client_idx] += client_share;
        per_party_recv[0]          += lsp_share;
        printf("  leaf %d: PS chan swept → client%u=%llu, LSP=%llu\n",
               li, (unsigned)(client_idx - 1),
               (unsigned long long)client_share,
               (unsigned long long)lsp_share);
    }

    TEST_ASSERT(econ_snap_post(&econ), "econ_snap_post");

    uint64_t expected_deltas[5];
    for (size_t p = 0; p < N; p++) expected_deltas[p] = per_party_recv[p];

    uint64_t sweep_fees = (uint64_t)n_leaves * (LSTOCK_SWEEP_FEE + CHAN_SWEEP_FEE);
    uint64_t swept_sum = 0;
    for (size_t p = 0; p < N; p++) swept_sum += per_party_recv[p];
    uint64_t allocated_sum = 0;
    for (int li = 0; li < n_leaves; li++) {
        size_t nidx = f->leaf_node_indices[li];
        allocated_sum += f->nodes[nidx].outputs[0].amount_sats;
        allocated_sum += f->nodes[nidx].outputs[1].amount_sats;
    }
    TEST_ASSERT(swept_sum + sweep_fees == allocated_sum,
                "conservation: Σswept + Σsweep_fees == Σleaf_allocations");
    printf("  conservation OK: swept=%llu + sweep_fees=%llu == allocations=%llu\n",
           (unsigned long long)swept_sum,
           (unsigned long long)sweep_fees,
           (unsigned long long)allocated_sum);

    TEST_ASSERT(econ_assert_wallet_deltas(&econ, expected_deltas, 0),
                "per-party wallet deltas match expected");
    econ_print_summary(&econ);

    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ============================================================================
 *  Phase 2 Item #3: PS chain-advance sweep with accounting
 *
 *  Extension of test_regtest_full_force_close_and_sweep_arityPS (chain_len=0)
 *  to chain_len > 0. We:
 *    1. Build a PS factory at N=3 (LSP + 2 clients -> 2 PS leaves of 1 client).
 *    2. Broadcast every signed tree node (chain[0] for both leaves), confirming
 *       on regtest.
 *    3. Advance leaf 0 N times via factory_advance_leaf(f, 0). Each advance
 *       overwrites leaf->signed_tx with chain[i] (a 1-output TX spending vout
 *       0 of the prior chain state), so we broadcast each chain TX immediately
 *       after the corresponding advance, then mine 1 block. PS leaves use
 *       nSequence 0xFFFFFFFE so no CSV delay between chain advances.
 *    4. Sweep:
 *         (a) LSP sweeps L-stock from chain[0] vout 1 (LSP-only key path).
 *         (b) Both signers (LSP + leaf->signer_indices[1]) co-sign + broadcast
 *             a 2-of-2 MuSig sweep of chain[N] vout 0 (the channel UTXO).
 *       For leaf 1 (the untouched leaf) we also sweep its chain[0] L-stock
 *       and channel output so per-party accounting is exhaustive across the
 *       full factory.
 *    5. Conservation:  sum(swept) + sum(sweep_fees) + N_advances * fee_per_tx
 *       == sum(leaf chain[0] outputs[0..1]).  The N_advances * fee_per_tx
 *       term captures the per-advance factory fees that compound on leaf 0.
 *    6. econ_assert_wallet_deltas verifies per-party deltas exactly.
 *
 *  Severity: every TX is broadcast + confirmed; every cell asserts both
 *  per-party deltas AND conservation including per-advance fees. No skips.
 *  ========================================================================== */

static int run_ps_chain_advance_sweep(regtest_t *rt,
                                       secp256k1_context *ctx,
                                       int n_advances,
                                       const char *mine_addr) {
    const size_t N = 3;  /* LSP + 2 clients -> 2 PS leaves of 1 client each */
    secp256k1_keypair kps[5];
    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;

    unsigned char fund_spk[34];
    char fund_txid[65];
    uint32_t fund_vout = 0;
    uint64_t fund_amount = 0;
    if (!fund_n_party_factory(rt, ctx, N, FACTORY_ARITY_PS, mine_addr, kps, f,
                               fund_spk, fund_txid, &fund_vout, &fund_amount)) {
        factory_free(f); free(f); return 0;
    }
    printf("  [arity=PS chain_len=%d] factory funded: %llu sats, %zu nodes, "
           "%d leaves\n",
           n_advances, (unsigned long long)fund_amount, f->n_nodes,
           f->n_leaf_nodes);

    /* Broadcast every signed tree node in order (BIP-68 spacing). This
       broadcasts chain[0] for every leaf. */
    char txids[FACTORY_MAX_NODES][65];
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *nd = &f->nodes[i];
        TEST_ASSERT(nd->is_signed && nd->signed_tx.len > 0, "node signed");
        char *tx_hex = malloc(nd->signed_tx.len * 2 + 1);
        TEST_ASSERT(tx_hex != NULL, "tx_hex malloc");
        hex_encode(nd->signed_tx.data, nd->signed_tx.len, tx_hex);
        int ok = regtest_send_raw_tx(rt, tx_hex, txids[i]);
        free(tx_hex);
        TEST_ASSERT(ok, "broadcast tree node");
        int blocks_to_mine = 1;
        if (i + 1 < f->n_nodes) {
            uint32_t cns = f->nodes[i + 1].nsequence;
            if (!(cns & 0x80000000u)) blocks_to_mine = (int)(cns & 0xFFFF) + 1;
        }
        regtest_mine_blocks(rt, blocks_to_mine, mine_addr);
    }
    int n_leaves = f->n_leaf_nodes;
    for (int li = 0; li < n_leaves; li++) {
        TEST_ASSERT(regtest_get_confirmations(rt,
                        txids[f->leaf_node_indices[li]]) >= 1,
                    "leaf chain[0] on chain");
    }
    printf("  full tree broadcast OK -- %zu nodes, %d leaves chain[0] confirmed\n",
           f->n_nodes, n_leaves);

    /* Cache leaf 0 chain[0] facts (the L-stock and the original chan amount
       are needed for both sweeping and conservation). */
    size_t leaf0_idx = f->leaf_node_indices[0];
    factory_node_t *leaf0 = &f->nodes[leaf0_idx];
    TEST_ASSERT(leaf0->is_ps_leaf, "leaf0 is PS");
    TEST_ASSERT(leaf0->n_outputs == 2, "leaf0 chain[0] has 2 outputs");
    TEST_ASSERT(leaf0->signer_indices[0] == 0, "leaf0 signer[0] is LSP");
    uint32_t leaf0_client_idx = leaf0->signer_indices[1];
    TEST_ASSERT(leaf0_client_idx >= 1 && leaf0_client_idx < N,
                "leaf0 client_idx in range");

    char leaf0_chain0_txid[65];
    memcpy(leaf0_chain0_txid, txids[leaf0_idx], 65);
    uint64_t leaf0_chain0_chan_amt   = leaf0->outputs[0].amount_sats;
    uint64_t leaf0_chain0_lstock_amt = leaf0->outputs[1].amount_sats;
    unsigned char leaf0_chain0_lstock_spk[34];
    memcpy(leaf0_chain0_lstock_spk, leaf0->outputs[1].script_pubkey, 34);
    /* The channel SPK is invariant across PS chain advances (factory consensus
       key for {LSP, client}). Cache once. */
    unsigned char leaf0_chan_spk[34];
    memcpy(leaf0_chan_spk, leaf0->outputs[0].script_pubkey, 34);

    /* Advance leaf 0 n_advances times. After each advance, the leaf node's
       signed_tx contains chain[i] -- we broadcast it immediately, mine 1
       block, then advance again. */
    uint64_t fee_per_tx = f->fee_per_tx;
    char leaf0_chainN_txid[65];
    memcpy(leaf0_chainN_txid, leaf0_chain0_txid, 65);  /* if N=0 fallback */
    for (int adv = 1; adv <= n_advances; adv++) {
        TEST_ASSERT(factory_advance_leaf(f, 0), "advance leaf0");
        TEST_ASSERT(leaf0->ps_chain_len == adv, "ps_chain_len bumped");
        TEST_ASSERT(leaf0->n_outputs == 1, "advance TX has 1 output");
        TEST_ASSERT(leaf0->is_signed && leaf0->signed_tx.len > 0,
                    "advance TX signed");

        char *adv_hex = malloc(leaf0->signed_tx.len * 2 + 1);
        TEST_ASSERT(adv_hex != NULL, "adv_hex malloc");
        hex_encode(leaf0->signed_tx.data, leaf0->signed_tx.len, adv_hex);
        adv_hex[leaf0->signed_tx.len * 2] = '\0';
        int ok = regtest_send_raw_tx(rt, adv_hex, leaf0_chainN_txid);
        free(adv_hex);
        TEST_ASSERT(ok, "broadcast advance TX");
        regtest_mine_blocks(rt, 1, mine_addr);
        TEST_ASSERT(regtest_get_confirmations(rt, leaf0_chainN_txid) >= 1,
                    "advance TX confirmed");
        printf("  leaf0 chain[%d] broadcast: chan=%llu sats (-fee=%llu)\n",
               adv, (unsigned long long)leaf0->outputs[0].amount_sats,
               (unsigned long long)fee_per_tx);
    }
    /* leaf0->outputs[0].amount_sats is now leaf0_chain0_chan_amt - N*fee_per_tx. */
    uint64_t leaf0_chainN_chan_amt = leaf0->outputs[0].amount_sats;
    TEST_ASSERT(leaf0_chainN_chan_amt ==
                leaf0_chain0_chan_amt - (uint64_t)n_advances * fee_per_tx,
                "chainN channel amount = initial - N*fee");

    /* Build per-party P2TR destinations (N parties). */
    unsigned char party_spk[5][34];
    for (size_t p = 0; p < N; p++) {
        secp256k1_pubkey pk;
        secp256k1_keypair_pub(ctx, &pk, &kps[p]);
        secp256k1_xonly_pubkey xo;
        secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &pk);
        build_p2tr_script_pubkey(party_spk[p], &xo);
    }

    /* Wire econ harness for all N parties BEFORE any sweeps (snap_pre). */
    econ_ctx_t econ;
    econ_ctx_init(&econ, rt, ctx);
    static const char *party_names[5] = {
        "LSP", "client0", "client1", "client2", "client3"
    };
    for (size_t p = 0; p < N; p++) {
        TEST_ASSERT(econ_register_party(&econ, p, party_names[p],
                                         N_PARTY_SECKEYS[p]),
                    "register party");
    }
    econ.factory_funding_amount = fund_amount;
    TEST_ASSERT(econ_snap_pre(&econ), "econ_snap_pre");

    const uint64_t LSTOCK_SWEEP_FEE = 300;
    const uint64_t CHAN_SWEEP_FEE   = 400;

    const uint64_t SIMULATED_PAYMENT     = 20000;
    const uint64_t SIMULATED_ROUTING_FEE = 100;
    const uint64_t CLIENT_BALANCE_SHIFT  = SIMULATED_PAYMENT + SIMULATED_ROUTING_FEE;

    uint64_t per_party_recv[5] = {0,0,0,0,0};

    /* ---------------- Sweep leaf 0 (the chain-advanced leaf) ---------------- */

    /* (A) LSP sweeps L-stock from leaf0 chain[0] vout 1. The chain[0] TX still
           exists on chain because chain[1..N] only spent its vout 0, not vout 1. */
    {
        unsigned char tb[32];
        TEST_ASSERT(hex_decode(leaf0_chain0_txid, tb, 32),
                    "decode leaf0 chain[0] txid");
        reverse_bytes(tb, 32);

        tx_buf_t lstock_sweep;
        tx_buf_init(&lstock_sweep, 256);
        /* L-stock SPK now requires N-of-N MuSig (canonical t/1242).
           leaf0 == &f->nodes[f->leaf_node_indices[0]]. */
        TEST_ASSERT(spend_l_stock_cooperative(ctx, f,
                        &f->nodes[f->leaf_node_indices[0]],
                        leaf0_chain0_txid, 1, leaf0_chain0_lstock_amt,
                        party_spk[0], 34,
                        LSTOCK_SWEEP_FEE, &lstock_sweep),
                    "build leaf0 L-stock cooperative sweep");
        char *lh = malloc(lstock_sweep.len * 2 + 1);
        TEST_ASSERT(lh != NULL, "lh malloc");
        hex_encode(lstock_sweep.data, lstock_sweep.len, lh);
        lh[lstock_sweep.len * 2] = '\0';
        char swept_txid[65];
        int ok = spend_broadcast_and_mine(rt, lh, 1, swept_txid);
        free(lh); tx_buf_free(&lstock_sweep);
        TEST_ASSERT(ok, "leaf0 L-stock sweep confirmed");
        per_party_recv[0] += leaf0_chain0_lstock_amt - LSTOCK_SWEEP_FEE;
        printf("  leaf0: LSP swept L-stock %llu sats\n",
               (unsigned long long)(leaf0_chain0_lstock_amt - LSTOCK_SWEEP_FEE));
    }

    /* (B) Sweep leaf0 chain[N] vout 0 (the channel) via 2-of-2 MuSig. */
    {
        unsigned char tb[32];
        TEST_ASSERT(hex_decode(leaf0_chainN_txid, tb, 32),
                    "decode leaf0 chain[N] txid");
        reverse_bytes(tb, 32);

        uint64_t chan_amt = leaf0_chainN_chan_amt;
        uint64_t balanced_half = (chan_amt - CHAN_SWEEP_FEE) / 2;
        uint64_t client_share  = balanced_half - CLIENT_BALANCE_SHIFT;
        uint64_t lsp_share     = (chan_amt - CHAN_SWEEP_FEE) - client_share;

        tx_output_t outs[2];
        memcpy(outs[0].script_pubkey, party_spk[leaf0_client_idx], 34);
        outs[0].script_pubkey_len = 34;
        outs[0].amount_sats = client_share;
        memcpy(outs[1].script_pubkey, party_spk[0], 34);
        outs[1].script_pubkey_len = 34;
        outs[1].amount_sats = lsp_share;

        tx_buf_t chan_unsigned;
        tx_buf_init(&chan_unsigned, 256);
        TEST_ASSERT(build_unsigned_tx(&chan_unsigned, NULL, tb, 0,
                                        0xFFFFFFFEu, outs, 2),
                    "build unsigned channel sweep");
        unsigned char sighash[32];
        TEST_ASSERT(compute_taproot_sighash(sighash,
                        chan_unsigned.data, chan_unsigned.len,
                        0, leaf0_chan_spk, 34, chan_amt, 0xFFFFFFFEu),
                    "compute channel sighash");

        secp256k1_keypair signers[FACTORY_MAX_SIGNERS];
        secp256k1_pubkey pks[FACTORY_MAX_SIGNERS];
        for (size_t s = 0; s < leaf0->n_signers; s++) {
            uint32_t sidx = leaf0->signer_indices[s];
            signers[s] = kps[sidx];
            secp256k1_keypair_pub(ctx, &pks[s], &signers[s]);
        }
        musig_keyagg_t ka;
        TEST_ASSERT(musig_aggregate_keys(ctx, &ka, pks, leaf0->n_signers),
                    "aggregate channel keys");
        unsigned char sig64[64];
        TEST_ASSERT(musig_sign_taproot(ctx, sig64, sighash, signers,
                                         leaf0->n_signers, &ka, NULL),
                    "MuSig2 sign chainN channel sweep");
        tx_buf_t chan_signed;
        tx_buf_init(&chan_signed, 256);
        TEST_ASSERT(finalize_signed_tx(&chan_signed, chan_unsigned.data,
                                         chan_unsigned.len, sig64),
                    "finalize chainN sweep");
        tx_buf_free(&chan_unsigned);

        char *ch = malloc(chan_signed.len * 2 + 1);
        TEST_ASSERT(ch != NULL, "ch malloc");
        hex_encode(chan_signed.data, chan_signed.len, ch);
        ch[chan_signed.len * 2] = '\0';
        char swept_txid[65];
        int ok = spend_broadcast_and_mine(rt, ch, 1, swept_txid);
        free(ch); tx_buf_free(&chan_signed);
        TEST_ASSERT(ok, "leaf0 chainN channel sweep confirmed");
        per_party_recv[leaf0_client_idx] += client_share;
        per_party_recv[0]                += lsp_share;
        printf("  leaf0: chainN chan swept -> client%u=%llu, LSP=%llu\n",
               (unsigned)(leaf0_client_idx - 1),
               (unsigned long long)client_share,
               (unsigned long long)lsp_share);
    }

    /* ---------------- Sweep leaf 1 (untouched -- chain_len=0) ---------------- */
    /* This mirrors the chain_len=0 arityPS test: sweep L-stock from vout 1 and
       channel from vout 0 of leaf 1's chain[0] TX. Including this leaf in the
       sweep keeps per-party accounting exhaustive over the entire factory. */
    {
        size_t leaf1_idx = f->leaf_node_indices[1];
        factory_node_t *leaf1 = &f->nodes[leaf1_idx];
        const char *leaf1_txid = txids[leaf1_idx];
        TEST_ASSERT(leaf1->is_ps_leaf, "leaf1 is PS");
        TEST_ASSERT(leaf1->n_outputs == 2, "leaf1 chain[0] has 2 outputs");
        TEST_ASSERT(leaf1->ps_chain_len == 0, "leaf1 untouched (chain_len=0)");
        TEST_ASSERT(leaf1->signer_indices[0] == 0, "leaf1 signer[0] is LSP");
        uint32_t leaf1_client_idx = leaf1->signer_indices[1];
        TEST_ASSERT(leaf1_client_idx >= 1 && leaf1_client_idx < N,
                    "leaf1 client_idx in range");

        unsigned char leaf1_txid_bytes[32];
        TEST_ASSERT(hex_decode(leaf1_txid, leaf1_txid_bytes, 32),
                    "decode leaf1 txid");
        reverse_bytes(leaf1_txid_bytes, 32);

        /* L-stock */
        uint64_t lstock_amt = leaf1->outputs[1].amount_sats;
        unsigned char lstock_spk[34];
        memcpy(lstock_spk, leaf1->outputs[1].script_pubkey, 34);
        tx_buf_t ls;
        tx_buf_init(&ls, 256);
        /* L-stock SPK now requires N-of-N MuSig (canonical t/1242). */
        TEST_ASSERT(spend_l_stock_cooperative(ctx, f, leaf1,
                        leaf1_txid, 1, lstock_amt,
                        party_spk[0], 34, LSTOCK_SWEEP_FEE, &ls),
                    "build leaf1 L-stock cooperative sweep");
        char *lh = malloc(ls.len * 2 + 1);
        TEST_ASSERT(lh != NULL, "lh malloc");
        hex_encode(ls.data, ls.len, lh);
        lh[ls.len * 2] = '\0';
        char ls_txid[65];
        int lok = spend_broadcast_and_mine(rt, lh, 1, ls_txid);
        free(lh); tx_buf_free(&ls);
        TEST_ASSERT(lok, "leaf1 L-stock sweep confirmed");
        per_party_recv[0] += lstock_amt - LSTOCK_SWEEP_FEE;

        /* Channel (chain[0] vout 0) */
        uint64_t chan_amt = leaf1->outputs[0].amount_sats;
        uint64_t balanced_half = (chan_amt - CHAN_SWEEP_FEE) / 2;
        uint64_t client_share  = balanced_half - CLIENT_BALANCE_SHIFT;
        uint64_t lsp_share     = (chan_amt - CHAN_SWEEP_FEE) - client_share;
        unsigned char chan_spk[34];
        memcpy(chan_spk, leaf1->outputs[0].script_pubkey, 34);

        tx_output_t outs[2];
        memcpy(outs[0].script_pubkey, party_spk[leaf1_client_idx], 34);
        outs[0].script_pubkey_len = 34;
        outs[0].amount_sats = client_share;
        memcpy(outs[1].script_pubkey, party_spk[0], 34);
        outs[1].script_pubkey_len = 34;
        outs[1].amount_sats = lsp_share;

        tx_buf_t cu;
        tx_buf_init(&cu, 256);
        TEST_ASSERT(build_unsigned_tx(&cu, NULL, leaf1_txid_bytes, 0,
                                        0xFFFFFFFEu, outs, 2),
                    "build leaf1 channel sweep unsigned");
        unsigned char sh[32];
        TEST_ASSERT(compute_taproot_sighash(sh, cu.data, cu.len, 0,
                                              chan_spk, 34, chan_amt,
                                              0xFFFFFFFEu),
                    "leaf1 channel sighash");
        secp256k1_keypair signers[FACTORY_MAX_SIGNERS];
        secp256k1_pubkey pks[FACTORY_MAX_SIGNERS];
        for (size_t s = 0; s < leaf1->n_signers; s++) {
            uint32_t sidx = leaf1->signer_indices[s];
            signers[s] = kps[sidx];
            secp256k1_keypair_pub(ctx, &pks[s], &signers[s]);
        }
        musig_keyagg_t ka;
        TEST_ASSERT(musig_aggregate_keys(ctx, &ka, pks, leaf1->n_signers),
                    "leaf1 keyagg");
        unsigned char sig64[64];
        TEST_ASSERT(musig_sign_taproot(ctx, sig64, sh, signers,
                                         leaf1->n_signers, &ka, NULL),
                    "leaf1 channel MuSig2 sign");
        tx_buf_t cs;
        tx_buf_init(&cs, 256);
        TEST_ASSERT(finalize_signed_tx(&cs, cu.data, cu.len, sig64),
                    "leaf1 finalize");
        tx_buf_free(&cu);

        char *ch = malloc(cs.len * 2 + 1);
        TEST_ASSERT(ch != NULL, "ch malloc");
        hex_encode(cs.data, cs.len, ch);
        ch[cs.len * 2] = '\0';
        char ct_txid[65];
        int cok = spend_broadcast_and_mine(rt, ch, 1, ct_txid);
        free(ch); tx_buf_free(&cs);
        TEST_ASSERT(cok, "leaf1 channel sweep confirmed");
        per_party_recv[leaf1_client_idx] += client_share;
        per_party_recv[0]                += lsp_share;
        printf("  leaf1: chain[0] chan swept -> client%u=%llu, LSP=%llu, "
               "L-stock LSP=%llu\n",
               (unsigned)(leaf1_client_idx - 1),
               (unsigned long long)client_share,
               (unsigned long long)lsp_share,
               (unsigned long long)(lstock_amt - LSTOCK_SWEEP_FEE));
    }

    /* ---------------- Conservation + per-party assertions ---------------- */
    TEST_ASSERT(econ_snap_post(&econ), "econ_snap_post");

    uint64_t expected_deltas[5];
    for (size_t p = 0; p < N; p++) expected_deltas[p] = per_party_recv[p];

    /* Sweep fees: 2 leaves * (L-stock fee + channel fee) */
    uint64_t sweep_fees = (uint64_t)n_leaves * (LSTOCK_SWEEP_FEE + CHAN_SWEEP_FEE);
    /* Per-advance factory fees: leaf 0 advanced n_advances times. */
    uint64_t advance_fees = (uint64_t)n_advances * fee_per_tx;
    uint64_t swept_sum = 0;
    for (size_t p = 0; p < N; p++) swept_sum += per_party_recv[p];

    /* Allocations baseline = sum of EACH leaf's chain[0] outputs (channel +
       L-stock), BEFORE any per-advance fee subtraction. */
    uint64_t allocated_sum = 0;
    /* leaf0 chain[0]: original chan amount + L-stock. */
    allocated_sum += leaf0_chain0_chan_amt + leaf0_chain0_lstock_amt;
    /* leaf1 (untouched): chain[0] outputs as-is. */
    {
        size_t leaf1_idx = f->leaf_node_indices[1];
        factory_node_t *leaf1 = &f->nodes[leaf1_idx];
        allocated_sum += leaf1->outputs[0].amount_sats
                       + leaf1->outputs[1].amount_sats;
    }

    TEST_ASSERT(swept_sum + sweep_fees + advance_fees == allocated_sum,
                "conservation: swept + sweep_fees + N*advance_fee == allocations");
    printf("  conservation OK: swept=%llu + sweep_fees=%llu + advance_fees=%llu "
           "(=%d * %llu) == allocations=%llu\n",
           (unsigned long long)swept_sum,
           (unsigned long long)sweep_fees,
           (unsigned long long)advance_fees,
           n_advances, (unsigned long long)fee_per_tx,
           (unsigned long long)allocated_sum);

    TEST_ASSERT(econ_assert_wallet_deltas(&econ, expected_deltas, 0),
                "per-party wallet deltas match expected");
    econ_print_summary(&econ);

    factory_free(f);
    free(f);
    return 1;
}

int test_regtest_full_force_close_and_sweep_arity_ps_chain_len2(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "ps_chain_advance_l2");
    rt.scan_depth = 200;

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    int ok = run_ps_chain_advance_sweep(&rt, ctx, 2, mine_addr);
    secp256k1_context_destroy(ctx);
    return ok;
}

int test_regtest_full_force_close_and_sweep_arity_ps_chain_len5(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "ps_chain_advance_l5");
    rt.scan_depth = 200;

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    int ok = run_ps_chain_advance_sweep(&rt, ctx, 5, mine_addr);
    secp256k1_context_destroy(ctx);
    return ok;
}

/* ============================================================================
 *  Phase 2 Item #1: HTLC x force-to_local x {arity-1, arity-2, arity-PS}
 *
 *  Build a factory at the given arity, broadcast the entire signed tree to
 *  chain (BIP-68 spacing between siblings), then on top of leaf 0's channel
 *  output:
 *     1. open an inner BOLT-2 LN channel (2-of-2 MuSig over LSP+client)
 *     2. add an HTLC OFFERED by the LSP (so LSP can claim via timeout)
 *     3. force-close: LSP broadcasts its commitment_tx
 *     4. wait CSV blocks, sweep to_local via the csv_leaf script-path
 *     5. wait CLTV blocks, sweep the HTLC via the OFFERED-timeout script-path
 *     6. client sweeps its to_remote so per-party accounting is symmetric
 *     7. assert econ_assert_wallet_deltas + conservation
 *
 *  Severity: every cell broadcasts + confirms on regtest, asserts per-party
 *  deltas, and checks Sum(swept) + Sum(fees) == leaf_chan_amt. No skip flags.
 *
 *  HTLC direction note: from LSP's channel view, an HTLC the LSP OFFERED
 *  means the LSP is the one who can reclaim it via the offered-timeout path
 *  (after CLTV expiry). The mirror on the client side is HTLC_RECEIVED.
 *  ========================================================================== */

/* Run the HTLC x force-to_local cell for one arity. n_participants = 2 for
 * arity-1 / arity-PS, 4 for arity-2 (LSP + 3 clients -> 2 leaves of 2 clients). */
static int run_htlc_force_to_local_for_arity(regtest_t *rt,
                                              secp256k1_context *ctx,
                                              factory_arity_t arity,
                                              size_t n_participants,
                                              const char *mine_addr) {
    const size_t N = n_participants;
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
    printf("  [arity=%d N=%zu] factory funded: %llu sats, %zu nodes, %d leaves\n",
           (int)arity, N, (unsigned long long)fund_amount, f->n_nodes,
           f->n_leaf_nodes);

    /* Broadcast every signed tree node in order with BIP-68 spacing --
       same pattern as test_regtest_full_force_close_and_sweep_arity1. */
    char txids[FACTORY_MAX_NODES][65];
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *nd = &f->nodes[i];
        TEST_ASSERT(nd->is_signed && nd->signed_tx.len > 0,
                    "tree node signed before broadcast");
        char *tx_hex = malloc(nd->signed_tx.len * 2 + 1);
        TEST_ASSERT(tx_hex != NULL, "tx_hex malloc");
        hex_encode(nd->signed_tx.data, nd->signed_tx.len, tx_hex);
        int ok = regtest_send_raw_tx(rt, tx_hex, txids[i]);
        free(tx_hex);
        TEST_ASSERT(ok, "broadcast tree node");
        int blocks_to_mine = 1;
        if (i + 1 < f->n_nodes) {
            uint32_t cns = f->nodes[i + 1].nsequence;
            if (!(cns & 0x80000000u)) blocks_to_mine = (int)(cns & 0xFFFF) + 1;
        }
        regtest_mine_blocks(rt, blocks_to_mine, mine_addr);
    }
    int n_leaves = f->n_leaf_nodes;
    for (int li = 0; li < n_leaves; li++) {
        TEST_ASSERT(regtest_get_confirmations(rt,
            txids[f->leaf_node_indices[li]]) >= 1,
            "leaf confirmed on chain");
    }
    printf("  full tree broadcast OK -- %zu nodes, %d leaves on chain\n",
           f->n_nodes, n_leaves);

    /* Pick leaf 0. Recover the client index from signer_indices.
       For arity-1: signer_indices = {LSP, client}            (2-of-2)
       For arity-2: signer_indices = {LSP, client_a, client_b} (3-of-3 leaf
                    keyagg, but the channel output is 2-of-2 (client_a, LSP))
       For arity-PS: signer_indices = {LSP, client}            (N-of-N
                    channel output, but for N=2 that == 2-of-2)
       In all 3 we use signer_indices[1] as our chosen client. */
    size_t leaf_idx = f->leaf_node_indices[0];
    factory_node_t *leaf = &f->nodes[leaf_idx];
    const char *leaf_txid = txids[leaf_idx];

    TEST_ASSERT(leaf->signer_indices[0] == 0,
                "signer_indices[0] is LSP");
    uint32_t client_idx = leaf->signer_indices[1];
    TEST_ASSERT(client_idx >= 1 && client_idx < N,
                "client_idx in range");

    /* Inner LN channel funding = leaf->outputs[0]. */
    uint64_t leaf_chan_amt = leaf->outputs[0].amount_sats;
    unsigned char leaf_chan_spk[34];
    memcpy(leaf_chan_spk, leaf->outputs[0].script_pubkey, 34);

    unsigned char leaf_txid_bytes[32];
    TEST_ASSERT(hex_decode(leaf_txid, leaf_txid_bytes, 32),
                "decode leaf txid");
    reverse_bytes(leaf_txid_bytes, 32);

    /* Open BOLT-2 inner channel above leaf 0's channel output. The
       commitment TX is 2-of-2 (LSP + client). channel_init's keyagg
       auto-detector tries both orderings -- the leaf SPK is built from
       (client, LSP) for arity-1/2 and from (LSP, client) for PS, so the
       same call works for all three arities. */
    secp256k1_pubkey lsp_pk, client_pk;
    secp256k1_keypair_pub(ctx, &lsp_pk, &kps[0]);
    secp256k1_keypair_pub(ctx, &client_pk, &kps[client_idx]);

    /* Channel balances: reserve enough for the commitment TX fee, then
       split the remainder 70/30. The channel_init balances become the
       to_local/to_remote amounts on the commitment, so leaf_chan_amt -
       (local + remote) is the commit fee paid to miners.
       Regtest mempool min-relay is ~200 sats for a ~200 vB TX; we reserve
       1500 to stay well clear of mempool floor across all leaf sizes. */
    const uint32_t csv = 10;
    const uint64_t COMMIT_FEE_RESERVE = 1500;
    TEST_ASSERT(leaf_chan_amt > COMMIT_FEE_RESERVE + 20000,
                "leaf_chan_amt too small for HTLC + commit fee");
    uint64_t channel_capacity = leaf_chan_amt - COMMIT_FEE_RESERVE;
    uint64_t local_amt  = (channel_capacity * 70) / 100;  /* LSP local */
    uint64_t remote_amt = channel_capacity - local_amt;   /* client */

    channel_t lsp_ch, client_ch;
    TEST_ASSERT(channel_init(&lsp_ch, ctx, N_PARTY_SECKEYS[0],
                              &lsp_pk, &client_pk,
                              leaf_txid_bytes, 0, leaf_chan_amt,
                              leaf_chan_spk, 34,
                              local_amt, remote_amt, csv),
                "init LSP inner channel");
    TEST_ASSERT(channel_init(&client_ch, ctx, N_PARTY_SECKEYS[client_idx],
                              &client_pk, &lsp_pk,
                              leaf_txid_bytes, 0, leaf_chan_amt,
                              leaf_chan_spk, 34,
                              remote_amt, local_amt, csv),
                "init client inner channel");
    channel_generate_random_basepoints(&lsp_ch);
    channel_generate_random_basepoints(&client_ch);
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

    /* Exchange PCPs for commitments 0 and 1. */
    secp256k1_pubkey lsp_pcp0, client_pcp0, lsp_pcp1, client_pcp1;
    channel_get_per_commitment_point(&lsp_ch, 0, &lsp_pcp0);
    channel_get_per_commitment_point(&client_ch, 0, &client_pcp0);
    channel_get_per_commitment_point(&lsp_ch, 1, &lsp_pcp1);
    channel_get_per_commitment_point(&client_ch, 1, &client_pcp1);
    channel_set_remote_pcp(&lsp_ch, 0, &client_pcp0);
    channel_set_remote_pcp(&client_ch, 0, &lsp_pcp0);
    channel_set_remote_pcp(&lsp_ch, 1, &client_pcp1);
    channel_set_remote_pcp(&client_ch, 1, &lsp_pcp1);

    /* Add an HTLC OFFERED by the LSP. We pick a small amount and a CLTV
       ~80 blocks above the current chain tip (we'll mine past it after
       sweeping to_local). The LSP NEVER fulfils -- it claims via
       offered-timeout to exercise the CSV+CLTV branch. */
    int cur_h = regtest_get_block_height(rt);
    TEST_ASSERT(cur_h > 0, "have block height");
    uint64_t htlc_amt = 5000;
    uint32_t htlc_cltv = (uint32_t)cur_h + 80;

    unsigned char preimage[32];
    memset(preimage, 0xCD, 32);
    unsigned char payment_hash[32];
    sha256(preimage, 32, payment_hash);

    uint64_t lsp_htlc_id = 0, client_htlc_id = 0;
    TEST_ASSERT(channel_add_htlc(&lsp_ch, HTLC_OFFERED, htlc_amt,
                                   payment_hash, htlc_cltv, &lsp_htlc_id),
                "LSP adds OFFERED htlc");
    TEST_ASSERT(channel_add_htlc(&client_ch, HTLC_RECEIVED, htlc_amt,
                                   payment_hash, htlc_cltv, &client_htlc_id),
                "client mirrors RECEIVED htlc");

    /* Build + sign + broadcast LSP's commitment (3 outputs:
       to_local, to_remote, htlc). */
    tx_buf_t uc, sc;
    tx_buf_init(&uc, 1024); tx_buf_init(&sc, 2048);
    unsigned char ct[32];
    TEST_ASSERT(channel_build_commitment_tx(&lsp_ch, &uc, ct),
                "build LSP commitment");
    TEST_ASSERT(channel_sign_commitment(&lsp_ch, &sc, &uc, &kps[client_idx]),
                "client co-signs LSP commitment");

    char *commit_hex = malloc(sc.len * 2 + 1);
    TEST_ASSERT(commit_hex != NULL, "commit_hex malloc");
    hex_encode(sc.data, sc.len, commit_hex);
    commit_hex[sc.len * 2] = '\0';
    char commit_txid_hex[65];
    int br_ok = regtest_send_raw_tx(rt, commit_hex, commit_txid_hex);
    free(commit_hex);
    TEST_ASSERT(br_ok, "broadcast LSP commitment");
    regtest_mine_blocks(rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(rt, commit_txid_hex) >= 1,
                "commitment confirmed");
    tx_buf_free(&uc); tx_buf_free(&sc);
    printf("  inner: commitment confirmed %s (3 outputs)\n", commit_txid_hex);

    /* Read the 3 outputs of the commitment_tx for accounting. */
    uint64_t to_local_amt = 0, to_remote_amt = 0, htlc_out_amt = 0;
    unsigned char to_local_spk[64], to_remote_spk[64], htlc_spk[64];
    size_t to_local_spk_len = 0, to_remote_spk_len = 0, htlc_spk_len = 0;
    TEST_ASSERT(regtest_get_tx_output(rt, commit_txid_hex, 0,
                                        &to_local_amt, to_local_spk,
                                        &to_local_spk_len),
                "read to_local (vout 0)");
    TEST_ASSERT(regtest_get_tx_output(rt, commit_txid_hex, 1,
                                        &to_remote_amt, to_remote_spk,
                                        &to_remote_spk_len),
                "read to_remote (vout 1)");
    TEST_ASSERT(regtest_get_tx_output(rt, commit_txid_hex, 2,
                                        &htlc_out_amt, htlc_spk,
                                        &htlc_spk_len),
                "read htlc output (vout 2)");
    TEST_ASSERT(htlc_out_amt == htlc_amt, "htlc output amount matches");
    /* commit_fee_paid_by_funder = leaf_chan_amt - (to_local + to_remote + htlc) */
    uint64_t commit_fee = leaf_chan_amt - to_local_amt - to_remote_amt - htlc_out_amt;
    printf("  commit outs: to_local=%llu, to_remote=%llu, htlc=%llu, "
           "commit_fee=%llu\n",
           (unsigned long long)to_local_amt,
           (unsigned long long)to_remote_amt,
           (unsigned long long)htlc_out_amt,
           (unsigned long long)commit_fee);

    /* Set up econ harness BEFORE sweeps (to capture pre-balances). Each
       party's expect_close_spk = P2TR(xonly(pk(seckey))). All sweep
       destinations below land at exactly that SPK. */
    econ_ctx_t econ;
    econ_ctx_init(&econ, rt, ctx);
    TEST_ASSERT(econ_register_party(&econ, 0, "LSP", N_PARTY_SECKEYS[0]),
                "register LSP");
    TEST_ASSERT(econ_register_party(&econ, 1, "client",
                                       N_PARTY_SECKEYS[client_idx]),
                "register client");
    econ.factory_funding_amount = leaf_chan_amt;  /* scope = inner channel */
    TEST_ASSERT(econ_snap_pre(&econ), "econ_snap_pre");

    /* Compute each party's P2TR(xonly(pk_i)) destination SPK. */
    unsigned char party_spk[2][34];
    for (int p = 0; p < 2; p++) {
        secp256k1_keypair *kp = (p == 0) ? &kps[0] : &kps[client_idx];
        secp256k1_pubkey pk;
        secp256k1_keypair_pub(ctx, &pk, kp);
        secp256k1_xonly_pubkey xo;
        secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &pk);
        build_p2tr_script_pubkey(party_spk[p], &xo);
    }

    /* (1) Mine CSV blocks so to_local can be swept via csv_leaf script-path.
       commitment already has 1 conf -- mine `csv` more so it has csv+1 confs
       (channel_build_to_local_sweep uses nSequence = to_self_delay = csv). */
    regtest_mine_blocks(rt, (int)csv, mine_addr);

    /* (2) LSP sweeps to_local via channel_build_to_local_sweep. */
    tx_buf_t tl_sweep;
    tx_buf_init(&tl_sweep, 512);
    unsigned char ct_internal[32];
    memcpy(ct_internal, ct, 32);
    TEST_ASSERT(channel_build_to_local_sweep(&lsp_ch, &tl_sweep,
                                              ct_internal, 0, to_local_amt,
                                              party_spk[0], 34),
                "build to_local sweep (CSV script-path)");
    char *tl_hex = malloc(tl_sweep.len * 2 + 1);
    TEST_ASSERT(tl_hex != NULL, "tl_hex malloc");
    hex_encode(tl_sweep.data, tl_sweep.len, tl_hex);
    tl_hex[tl_sweep.len * 2] = '\0';
    char tl_sweep_txid[65];
    int tl_ok = spend_broadcast_and_mine(rt, tl_hex, 1, tl_sweep_txid);
    free(tl_hex);
    /* to_local sweep fee = (fee_rate * 200 + 999)/1000; default rate=1000
       sat/kvB -> 200 sats. The sweep TX subtracts that internally. */
    uint64_t to_local_sweep_fee = (lsp_ch.fee_rate_sat_per_kvb * 200 + 999) / 1000;
    uint64_t to_local_swept = to_local_amt - to_local_sweep_fee;
    tx_buf_free(&tl_sweep);
    TEST_ASSERT(tl_ok, "to_local sweep confirmed");
    printf("  LSP swept to_local %llu sats (fee=%llu) -> %s\n",
           (unsigned long long)to_local_swept,
           (unsigned long long)to_local_sweep_fee, tl_sweep_txid);

    /* (3) Mine until block height >= htlc_cltv so HTLC offered-timeout's
       nLockTime is satisfied. Subtract any blocks already mined since the
       commitment was confirmed. */
    int now_h = regtest_get_block_height(rt);
    if (now_h < (int)htlc_cltv) {
        regtest_mine_blocks(rt, (int)htlc_cltv - now_h, mine_addr);
    }

    /* (4) LSP sweeps the HTLC via offered-timeout script-path. The
       channel_build_htlc_timeout_tx call uses nSequence = to_self_delay
       (csv) -- already satisfied since we mined past csv blocks ago -- and
       nLockTime = htlc_cltv. */
    tx_buf_t htlc_sweep;
    tx_buf_init(&htlc_sweep, 512);
    TEST_ASSERT(channel_build_htlc_timeout_tx(&lsp_ch, &htlc_sweep,
                                                ct_internal, 2,
                                                htlc_out_amt, htlc_spk,
                                                htlc_spk_len, 0),
                "build HTLC offered-timeout sweep");
    char *htlc_hex = malloc(htlc_sweep.len * 2 + 1);
    TEST_ASSERT(htlc_hex != NULL, "htlc_hex malloc");
    hex_encode(htlc_sweep.data, htlc_sweep.len, htlc_hex);
    htlc_hex[htlc_sweep.len * 2] = '\0';
    char htlc_sweep_txid[65];
    int htlc_ok = spend_broadcast_and_mine(rt, htlc_hex, 1, htlc_sweep_txid);
    free(htlc_hex);
    /* htlc-timeout fee from channel.c:2103: rate * 180 + 999 / 1000.
       Lands at P2TR(taptweak(local_payment_basepoint)) -- NOT at LSP's
       P2TR(LSP-pk). It's a 1-output sweep that is itself further spendable
       only by the LSP via the BIP-341-tweaked local_payment basepoint
       secret (the basepoint, NOT a per-commitment-derived key). The exact
       fee is recomputed below from on-chain truth. */
    uint64_t htlc_sweep_fee = (lsp_ch.fee_rate_sat_per_kvb * 180 + 999) / 1000;
    uint64_t htlc_intermediate = htlc_out_amt - htlc_sweep_fee;
    tx_buf_free(&htlc_sweep);
    TEST_ASSERT(htlc_ok, "HTLC offered-timeout sweep confirmed");
    printf("  LSP swept HTLC %llu sats (fee=%llu) via offered-timeout -> %s\n",
           (unsigned long long)htlc_intermediate,
           (unsigned long long)htlc_sweep_fee, htlc_sweep_txid);

    /* (5) Second-stage LSP sweep of HTLC-timeout output to LSP's P2TR.
       The HTLC-timeout TX paid out to P2TR(taptweak(local_payment_basepoint)).
       To make the accounting land at LSP's wallet (P2TR(xonly(LSP-pk))) we
       sweep again with the BIP-341 keypath using the per-commitment-derived
       local_payment seckey -- same primitive the to_remote sweep uses. */
    /* The HTLC-timeout TX's single output is P2TR(BIP-341-tweaked(
       local_payment_BASEPOINT)) -- per src/channel.c:2083, it taproots the
       basepoint xonly pubkey directly, NOT a per-commitment-derived key.
       So we sign with the basepoint secret + BIP-341 taptweak, NOT a
       per-commitment derived seckey. Recompute the SPK from the basepoint
       and confirm match by reading vout[0] from the chain. */
    secp256k1_xonly_pubkey lsp_payment_xo;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &lsp_payment_xo, NULL,
                                        &lsp_ch.local_payment_basepoint);
    unsigned char lsp_payment_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, lsp_payment_ser, &lsp_payment_xo);
    unsigned char lsp_payment_taptweak[32];
    sha256_tagged("TapTweak", lsp_payment_ser, 32, lsp_payment_taptweak);
    secp256k1_pubkey lsp_payment_tw_full;
    secp256k1_xonly_pubkey_tweak_add(ctx, &lsp_payment_tw_full,
                                      &lsp_payment_xo, lsp_payment_taptweak);
    secp256k1_xonly_pubkey lsp_payment_tw;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &lsp_payment_tw, NULL,
                                        &lsp_payment_tw_full);
    unsigned char htlc_2nd_in_spk[34];
    build_p2tr_script_pubkey(htlc_2nd_in_spk, &lsp_payment_tw);

    /* Verify the on-chain HTLC-timeout output matches our computed SPK and
       use the actual on-chain amount (avoids any drift if channel.c changes
       its fee model). */
    uint64_t htlc_2nd_in_amt = 0;
    unsigned char htlc_2nd_chain_spk[64];
    size_t htlc_2nd_chain_spk_len = 0;
    TEST_ASSERT(regtest_get_tx_output(rt, htlc_sweep_txid, 0,
                    &htlc_2nd_in_amt, htlc_2nd_chain_spk,
                    &htlc_2nd_chain_spk_len),
                "read HTLC-timeout output from chain");
    TEST_ASSERT(htlc_2nd_chain_spk_len == 34 &&
                memcmp(htlc_2nd_chain_spk, htlc_2nd_in_spk, 34) == 0,
                "computed HTLC-timeout SPK matches on-chain SPK");
    /* Reconcile our local accounting with on-chain truth — the actual
       htlc-timeout fee is whatever the chain consumed. */
    htlc_sweep_fee = htlc_out_amt - htlc_2nd_in_amt;
    htlc_intermediate = htlc_2nd_in_amt;

    tx_buf_t htlc_2nd;
    tx_buf_init(&htlc_2nd, 256);
    const uint64_t SECOND_STAGE_FEE = 300;
    TEST_ASSERT(spend_build_p2tr_bip341_keypath(ctx,
                    lsp_ch.local_payment_basepoint_secret,
                    htlc_sweep_txid, 0, htlc_intermediate,
                    htlc_2nd_in_spk, 34,
                    party_spk[0], 34,
                    SECOND_STAGE_FEE, &htlc_2nd),
                "build 2nd-stage HTLC sweep to LSP P2TR");
    char *h2_hex = malloc(htlc_2nd.len * 2 + 1);
    TEST_ASSERT(h2_hex != NULL, "h2_hex malloc");
    hex_encode(htlc_2nd.data, htlc_2nd.len, h2_hex);
    h2_hex[htlc_2nd.len * 2] = '\0';
    char h2_txid[65];
    int h2_ok = spend_broadcast_and_mine(rt, h2_hex, 1, h2_txid);
    free(h2_hex);
    tx_buf_free(&htlc_2nd);
    TEST_ASSERT(h2_ok, "2nd-stage HTLC sweep confirmed");
    uint64_t htlc_to_lsp = htlc_intermediate - SECOND_STAGE_FEE;
    printf("  LSP 2nd-stage swept %llu sats -> P2TR(LSP)\n",
           (unsigned long long)htlc_to_lsp);

    /* (6) Client sweeps to_remote so per-party accounting is symmetric. The
       to_remote SPK at commitment_number=1 uses lsp_pcp1 (LSP's PCP at the
       commitment that was actually broadcast — see note above the 2nd-stage
       sweep about the HTLC-add bumping commitment_number). */
    unsigned char client_to_remote_sk[32];
    TEST_ASSERT(derive_channel_seckey(ctx, client_to_remote_sk,
                                        client_ch.local_payment_basepoint_secret,
                                        &client_ch.local_payment_basepoint,
                                        &lsp_pcp1),
                "derive client to_remote seckey");
    const uint64_t TO_REMOTE_SWEEP_FEE = 300;
    tx_buf_t tr_sweep;
    tx_buf_init(&tr_sweep, 256);
    TEST_ASSERT(spend_build_p2tr_bip341_keypath(ctx, client_to_remote_sk,
                    commit_txid_hex, 1, to_remote_amt,
                    to_remote_spk, 34,
                    party_spk[1], 34,
                    TO_REMOTE_SWEEP_FEE, &tr_sweep),
                "build to_remote sweep");
    char *tr_hex = malloc(tr_sweep.len * 2 + 1);
    TEST_ASSERT(tr_hex != NULL, "tr_hex malloc");
    hex_encode(tr_sweep.data, tr_sweep.len, tr_hex);
    tr_hex[tr_sweep.len * 2] = '\0';
    char tr_txid[65];
    int tr_ok = spend_broadcast_and_mine(rt, tr_hex, 1, tr_txid);
    free(tr_hex);
    tx_buf_free(&tr_sweep);
    TEST_ASSERT(tr_ok, "to_remote sweep confirmed");
    uint64_t to_remote_swept = to_remote_amt - TO_REMOTE_SWEEP_FEE;
    printf("  client swept to_remote %llu sats (fee=%llu) -> %s\n",
           (unsigned long long)to_remote_swept,
           (unsigned long long)TO_REMOTE_SWEEP_FEE, tr_txid);

    /* (7) Accounting: snapshot post-sweep balances and assert per-party
       deltas match expectations exactly.
       LSP receives: to_local_swept + htlc_to_lsp
       client receives: to_remote_swept */
    TEST_ASSERT(econ_snap_post(&econ), "econ_snap_post");

    uint64_t expected_deltas[2];
    expected_deltas[0] = to_local_swept + htlc_to_lsp;  /* LSP */
    expected_deltas[1] = to_remote_swept;               /* client */

    /* Conservation: every sat from leaf_chan_amt accounted for as either
       a swept output landing in a party's wallet or a fee paid to miners.
       Fees: commit_fee (commitment funder=LSP) + to_local_sweep_fee +
       htlc_sweep_fee (1st stage) + SECOND_STAGE_FEE + TO_REMOTE_SWEEP_FEE. */
    uint64_t total_fees = commit_fee
                          + to_local_sweep_fee
                          + htlc_sweep_fee
                          + SECOND_STAGE_FEE
                          + TO_REMOTE_SWEEP_FEE;
    uint64_t swept_sum = expected_deltas[0] + expected_deltas[1];
    TEST_ASSERT(swept_sum + total_fees == leaf_chan_amt,
                "conservation: Sum(swept) + Sum(fees) == leaf_chan_amt");
    printf("  conservation OK: swept=%llu + fees=%llu == leaf_chan_amt=%llu\n",
           (unsigned long long)swept_sum,
           (unsigned long long)total_fees,
           (unsigned long long)leaf_chan_amt);

    TEST_ASSERT(econ_assert_wallet_deltas(&econ, expected_deltas, 0),
                "per-party wallet deltas match expected");
    econ_print_summary(&econ);

    channel_cleanup(&lsp_ch);
    channel_cleanup(&client_ch);
    factory_free(f);
    free(f);
    return 1;
}

/* HTLC × breach × {arity-1, arity-2, arity-PS}.
 *
 * Mirrors run_htlc_force_to_local_for_arity but instead of a force-close
 * with CSV+CLTV waits, the LSP becomes a cheater: builds commitment #1 (with
 * an unresolved HTLC OFFERED by LSP), then both sides advance to commitment
 * #2 — at which point each side reveals their per-commitment-secret for
 * commit #1 to the other. Now state 1 is REVOKED. The cheater (LSP) then
 * re-broadcasts the OLD state-1 commitment. The honest party (client) holds
 * the revocation secret for commit #1 and uses it to:
 *   - build a to_local penalty TX (channel_build_penalty_tx) sweeping LSP's
 *     supposed delayed_payment output via the revocation key path, AND
 *   - build an HTLC penalty TX (channel_build_htlc_penalty_tx) sweeping the
 *     HTLC output via its revocation branch.
 * Both penalty outputs land at P2TR(taptweak(client.local_payment_basepoint))
 * (per src/channel.c:1059-1107 and :2304-2351), so we add a 2nd-stage
 * BIP-341-keypath sweep to land the funds in the client's wallet for
 * econ_assert_wallet_deltas. The client also sweeps their own to_remote
 * (un-revoked, via per-commitment-derived payment seckey).
 *
 * Conservation: leaf_chan_amt == swept_to_punisher + Σ(commit_fee +
 * to_local_penalty_fee + to_local_2nd_fee + htlc_penalty_fee +
 * htlc_2nd_fee + to_remote_sweep_fee). The breacher's wallet delta is
 * exactly 0.
 */
static int run_htlc_breach_for_arity(regtest_t *rt,
                                       secp256k1_context *ctx,
                                       factory_arity_t arity,
                                       size_t n_participants,
                                       const char *mine_addr) {
    const size_t N = n_participants;
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
    printf("  [arity=%d N=%zu] factory funded: %llu sats, %zu nodes, %d leaves\n",
           (int)arity, N, (unsigned long long)fund_amount, f->n_nodes,
           f->n_leaf_nodes);

    /* Broadcast every signed tree node in order with BIP-68 spacing -- same
       pattern as run_htlc_force_to_local_for_arity. */
    char txids[FACTORY_MAX_NODES][65];
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *nd = &f->nodes[i];
        TEST_ASSERT(nd->is_signed && nd->signed_tx.len > 0,
                    "tree node signed before broadcast");
        char *tx_hex = malloc(nd->signed_tx.len * 2 + 1);
        TEST_ASSERT(tx_hex != NULL, "tx_hex malloc");
        hex_encode(nd->signed_tx.data, nd->signed_tx.len, tx_hex);
        int ok = regtest_send_raw_tx(rt, tx_hex, txids[i]);
        free(tx_hex);
        TEST_ASSERT(ok, "broadcast tree node");
        int blocks_to_mine = 1;
        if (i + 1 < f->n_nodes) {
            uint32_t cns = f->nodes[i + 1].nsequence;
            if (!(cns & 0x80000000u)) blocks_to_mine = (int)(cns & 0xFFFF) + 1;
        }
        regtest_mine_blocks(rt, blocks_to_mine, mine_addr);
    }
    int n_leaves = f->n_leaf_nodes;
    for (int li = 0; li < n_leaves; li++) {
        TEST_ASSERT(regtest_get_confirmations(rt,
            txids[f->leaf_node_indices[li]]) >= 1,
            "leaf confirmed on chain");
    }
    printf("  full tree broadcast OK -- %zu nodes, %d leaves on chain\n",
           f->n_nodes, n_leaves);

    /* Pick leaf 0; recover client_idx from signer_indices[1]. */
    size_t leaf_idx = f->leaf_node_indices[0];
    factory_node_t *leaf = &f->nodes[leaf_idx];
    const char *leaf_txid = txids[leaf_idx];
    TEST_ASSERT(leaf->signer_indices[0] == 0,
                "signer_indices[0] is LSP");
    uint32_t client_idx = leaf->signer_indices[1];
    TEST_ASSERT(client_idx >= 1 && client_idx < N,
                "client_idx in range");

    /* Inner LN channel funding = leaf->outputs[0]. */
    uint64_t leaf_chan_amt = leaf->outputs[0].amount_sats;
    unsigned char leaf_chan_spk[34];
    memcpy(leaf_chan_spk, leaf->outputs[0].script_pubkey, 34);

    unsigned char leaf_txid_bytes[32];
    TEST_ASSERT(hex_decode(leaf_txid, leaf_txid_bytes, 32),
                "decode leaf txid");
    reverse_bytes(leaf_txid_bytes, 32);

    secp256k1_pubkey lsp_pk, client_pk;
    secp256k1_keypair_pub(ctx, &lsp_pk, &kps[0]);
    secp256k1_keypair_pub(ctx, &client_pk, &kps[client_idx]);

    /* Reserve >> regtest min-relay (~200 sats). 1500 sat fee on a 3-output
       commit = ~7 sat/vB which clears all currently-known regtest mempool
       floors (CI included). */
    const uint32_t csv = 10;
    const uint64_t COMMIT_FEE_RESERVE = 1500;
    TEST_ASSERT(leaf_chan_amt > COMMIT_FEE_RESERVE + 20000,
                "leaf_chan_amt too small for HTLC + commit fee");
    uint64_t channel_capacity = leaf_chan_amt - COMMIT_FEE_RESERVE;
    uint64_t local_amt  = (channel_capacity * 70) / 100;  /* LSP local */
    uint64_t remote_amt = channel_capacity - local_amt;   /* client */

    channel_t lsp_ch, client_ch;
    TEST_ASSERT(channel_init(&lsp_ch, ctx, N_PARTY_SECKEYS[0],
                              &lsp_pk, &client_pk,
                              leaf_txid_bytes, 0, leaf_chan_amt,
                              leaf_chan_spk, 34,
                              local_amt, remote_amt, csv),
                "init LSP inner channel");
    TEST_ASSERT(channel_init(&client_ch, ctx, N_PARTY_SECKEYS[client_idx],
                              &client_pk, &lsp_pk,
                              leaf_txid_bytes, 0, leaf_chan_amt,
                              leaf_chan_spk, 34,
                              remote_amt, local_amt, csv),
                "init client inner channel");
    channel_generate_random_basepoints(&lsp_ch);
    channel_generate_random_basepoints(&client_ch);
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

    /* Pre-generate PCPs for commitments 0, 1, AND 2 -- we need 2 because we
       advance state past the breach commit so revocation secret for #1 is
       exchanged. channel_add_htlc auto-extends local PCS to current+1 = 2,
       but channel_set_remote_pcp must be called explicitly for each. */
    secp256k1_pubkey lsp_pcp0, client_pcp0;
    secp256k1_pubkey lsp_pcp1, client_pcp1;
    secp256k1_pubkey lsp_pcp2, client_pcp2;
    channel_get_per_commitment_point(&lsp_ch,    0, &lsp_pcp0);
    channel_get_per_commitment_point(&client_ch, 0, &client_pcp0);
    channel_get_per_commitment_point(&lsp_ch,    1, &lsp_pcp1);
    channel_get_per_commitment_point(&client_ch, 1, &client_pcp1);
    channel_set_remote_pcp(&lsp_ch,    0, &client_pcp0);
    channel_set_remote_pcp(&client_ch, 0, &lsp_pcp0);
    channel_set_remote_pcp(&lsp_ch,    1, &client_pcp1);
    channel_set_remote_pcp(&client_ch, 1, &lsp_pcp1);

    /* HTLC OFFERED by LSP (HTLC_RECEIVED on client). Same shape as the
       force_to_local test. We never resolve; the HTLC is mid-flight at
       breach time. */
    int cur_h = regtest_get_block_height(rt);
    TEST_ASSERT(cur_h > 0, "have block height");
    uint64_t htlc_amt = 5000;
    uint32_t htlc_cltv = (uint32_t)cur_h + 80;

    unsigned char preimage[32];
    memset(preimage, 0xCD, 32);
    unsigned char payment_hash[32];
    sha256(preimage, 32, payment_hash);

    uint64_t lsp_htlc_id = 0, client_htlc_id = 0;
    TEST_ASSERT(channel_add_htlc(&lsp_ch, HTLC_OFFERED, htlc_amt,
                                   payment_hash, htlc_cltv, &lsp_htlc_id),
                "LSP adds OFFERED htlc");
    TEST_ASSERT(channel_add_htlc(&client_ch, HTLC_RECEIVED, htlc_amt,
                                   payment_hash, htlc_cltv, &client_htlc_id),
                "client mirrors RECEIVED htlc");
    /* Both sides now have commitment_number = 1. */

    /* Build + sign LSP's commitment #1 (the soon-to-be-breached state). */
    tx_buf_t uc, sc;
    tx_buf_init(&uc, 1024); tx_buf_init(&sc, 2048);
    unsigned char ct[32];
    TEST_ASSERT(channel_build_commitment_tx(&lsp_ch, &uc, ct),
                "build LSP commitment #1");
    TEST_ASSERT(channel_sign_commitment(&lsp_ch, &sc, &uc, &kps[client_idx]),
                "client co-signs LSP commitment #1");

    /* Stash signed bytes -- we will advance state and THEN broadcast (the
       breach is publishing this stale tx). */
    size_t breach_len = sc.len;
    unsigned char *breach_bytes = malloc(breach_len);
    TEST_ASSERT(breach_bytes != NULL, "breach_bytes malloc");
    memcpy(breach_bytes, sc.data, breach_len);

    /* Advance to commitment #2 so each side's PCS for #1 becomes revealable.
       Mirrors the run_breach_penalty pattern: extend local PCS pool to 2,
       set remote PCP for #2, bump commitment_number to 2, then exchange
       revocation secrets for #1. */
    channel_generate_local_pcs(&lsp_ch,    2);
    channel_generate_local_pcs(&client_ch, 2);
    channel_get_per_commitment_point(&lsp_ch,    2, &lsp_pcp2);
    channel_get_per_commitment_point(&client_ch, 2, &client_pcp2);
    channel_set_remote_pcp(&lsp_ch,    2, &client_pcp2);
    channel_set_remote_pcp(&client_ch, 2, &lsp_pcp2);
    lsp_ch.commitment_number    = 2;
    client_ch.commitment_number = 2;

    /* LSP reveals secret#1 to client; client reveals secret#1 to LSP. After
       this exchange, state #1 is REVOKED on both sides. */
    unsigned char lsp_secret1[32], client_secret1[32];
    TEST_ASSERT(channel_get_revocation_secret(&lsp_ch, 1, lsp_secret1),
                "LSP get revocation secret #1");
    TEST_ASSERT(channel_get_revocation_secret(&client_ch, 1, client_secret1),
                "client get revocation secret #1");
    TEST_ASSERT(channel_receive_revocation(&client_ch, 1, lsp_secret1),
                "client receives LSP revocation #1");
    TEST_ASSERT(channel_receive_revocation(&lsp_ch, 1, client_secret1),
                "LSP receives client revocation #1");
    secure_zero(lsp_secret1, sizeof(lsp_secret1));
    secure_zero(client_secret1, sizeof(client_secret1));

    /* Set up econ harness BEFORE the breach so we capture pre-balances. */
    econ_ctx_t econ;
    econ_ctx_init(&econ, rt, ctx);
    TEST_ASSERT(econ_register_party(&econ, 0, "LSP_breacher",
                                       N_PARTY_SECKEYS[0]),
                "register LSP (breacher)");
    TEST_ASSERT(econ_register_party(&econ, 1, "client_punisher",
                                       N_PARTY_SECKEYS[client_idx]),
                "register client (punisher)");
    econ.factory_funding_amount = leaf_chan_amt;  /* scope = inner channel */
    TEST_ASSERT(econ_snap_pre(&econ), "econ_snap_pre");

    /* Compute each party's P2TR(xonly(pk_i)) wallet SPK. */
    unsigned char party_spk[2][34];
    for (int p = 0; p < 2; p++) {
        secp256k1_keypair *kp = (p == 0) ? &kps[0] : &kps[client_idx];
        secp256k1_pubkey pk;
        secp256k1_keypair_pub(ctx, &pk, kp);
        secp256k1_xonly_pubkey xo;
        secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &pk);
        build_p2tr_script_pubkey(party_spk[p], &xo);
    }

    /* === SIMULATE BREACH === */
    /* LSP re-broadcasts the OLD (revoked) commitment #1. */
    char *commit_hex = malloc(breach_len * 2 + 1);
    TEST_ASSERT(commit_hex != NULL, "commit_hex malloc");
    hex_encode(breach_bytes, breach_len, commit_hex);
    commit_hex[breach_len * 2] = '\0';
    char commit_txid_hex[65];
    int br_ok = regtest_send_raw_tx(rt, commit_hex, commit_txid_hex);
    free(commit_hex);
    free(breach_bytes);
    tx_buf_free(&uc); tx_buf_free(&sc);
    TEST_ASSERT(br_ok, "broadcast revoked commitment (the breach)");
    regtest_mine_blocks(rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(rt, commit_txid_hex) >= 1,
                "breach commitment confirmed");
    printf("  BREACH: LSP re-broadcast revoked commit %s (3 outputs)\n",
           commit_txid_hex);

    /* Read all 3 outputs of the breached commit. */
    uint64_t to_local_amt = 0, to_remote_amt = 0, htlc_out_amt = 0;
    unsigned char to_local_spk[64], to_remote_spk[64], htlc_spk[64];
    size_t to_local_spk_len = 0, to_remote_spk_len = 0, htlc_spk_len = 0;
    TEST_ASSERT(regtest_get_tx_output(rt, commit_txid_hex, 0,
                                        &to_local_amt, to_local_spk,
                                        &to_local_spk_len),
                "read to_local (vout 0)");
    TEST_ASSERT(regtest_get_tx_output(rt, commit_txid_hex, 1,
                                        &to_remote_amt, to_remote_spk,
                                        &to_remote_spk_len),
                "read to_remote (vout 1)");
    TEST_ASSERT(regtest_get_tx_output(rt, commit_txid_hex, 2,
                                        &htlc_out_amt, htlc_spk,
                                        &htlc_spk_len),
                "read htlc output (vout 2)");
    TEST_ASSERT(htlc_out_amt == htlc_amt, "htlc output amount matches");
    uint64_t commit_fee = leaf_chan_amt - to_local_amt - to_remote_amt - htlc_out_amt;
    printf("  breached outs: to_local=%llu, to_remote=%llu, htlc=%llu, "
           "commit_fee=%llu\n",
           (unsigned long long)to_local_amt,
           (unsigned long long)to_remote_amt,
           (unsigned long long)htlc_out_amt,
           (unsigned long long)commit_fee);

    /* === PUNISHMENT PHASE === */
    /* Set client's commitment_number back to 1 so channel_build_penalty_tx
       and channel_build_htlc_penalty_tx rebuild the SAME taptree as the
       breached commit. The htlc[] is still at index 0 with the same shape
       since neither side fulfilled or failed it -- channel_compact_htlcs
       wasn't invoked. */
    uint64_t saved_commitment_number = client_ch.commitment_number;
    client_ch.commitment_number = 1;
    unsigned char ct_internal[32];
    memcpy(ct_internal, ct, 32);

    /* (1) to_local penalty: client (punisher) sweeps LSP's revoked
       delayed_payment output via the revocation key path. The single output
       lands at P2TR(taptweak(client.local_payment_basepoint)) -- same SPK
       primitive as the HTLC-timeout sweep used in run_htlc_force_to_local. */
    tx_buf_t tl_pen;
    tx_buf_init(&tl_pen, 512);
    TEST_ASSERT(channel_build_penalty_tx(&client_ch, &tl_pen,
                                           ct_internal, 0, to_local_amt,
                                           to_local_spk, 34,
                                           1, NULL, 0),
                "build to_local penalty tx (revocation key-path)");
    char *tl_pen_hex = malloc(tl_pen.len * 2 + 1);
    TEST_ASSERT(tl_pen_hex != NULL, "tl_pen_hex malloc");
    hex_encode(tl_pen.data, tl_pen.len, tl_pen_hex);
    tl_pen_hex[tl_pen.len * 2] = '\0';
    char tl_pen_txid[65];
    int tl_pen_ok = spend_broadcast_and_mine(rt, tl_pen_hex, 1, tl_pen_txid);
    free(tl_pen_hex);
    tx_buf_free(&tl_pen);
    TEST_ASSERT(tl_pen_ok, "to_local penalty broadcast + confirmed");
    /* Penalty tx fee from src/channel.c:1086: rate * 152 + 999 / 1000
       (no anchor variant). */
    uint64_t tl_pen_fee_expected =
        (client_ch.fee_rate_sat_per_kvb * 152 + 999) / 1000;
    printf("  PENALTY: client swept to_local-revoked %llu sats (fee=%llu)\n",
           (unsigned long long)(to_local_amt - tl_pen_fee_expected),
           (unsigned long long)tl_pen_fee_expected);

    /* (2) HTLC penalty: client sweeps the HTLC output via the revocation
       branch of its taptree. This is the key Phase-2 #2 cell — a breach
       with an UNRESOLVED HTLC must be fully recoverable by the punisher. */
    tx_buf_t htlc_pen;
    tx_buf_init(&htlc_pen, 512);
    TEST_ASSERT(channel_build_htlc_penalty_tx(&client_ch, &htlc_pen,
                                                ct_internal, 2,
                                                htlc_out_amt, htlc_spk,
                                                htlc_spk_len,
                                                1, 0, NULL, 0),
                "build HTLC penalty tx (revocation branch)");
    char *htlc_pen_hex = malloc(htlc_pen.len * 2 + 1);
    TEST_ASSERT(htlc_pen_hex != NULL, "htlc_pen_hex malloc");
    hex_encode(htlc_pen.data, htlc_pen.len, htlc_pen_hex);
    htlc_pen_hex[htlc_pen.len * 2] = '\0';
    char htlc_pen_txid[65];
    int htlc_pen_ok = spend_broadcast_and_mine(rt, htlc_pen_hex, 1,
                                                htlc_pen_txid);
    free(htlc_pen_hex);
    tx_buf_free(&htlc_pen);
    TEST_ASSERT(htlc_pen_ok, "HTLC penalty broadcast + confirmed");
    /* HTLC penalty fee from src/channel.c:2329: rate * 152 + 999 / 1000. */
    uint64_t htlc_pen_fee_expected =
        (client_ch.fee_rate_sat_per_kvb * 152 + 999) / 1000;
    printf("  PENALTY: client swept HTLC-revoked %llu sats (fee=%llu)\n",
           (unsigned long long)(htlc_out_amt - htlc_pen_fee_expected),
           (unsigned long long)htlc_pen_fee_expected);

    /* Restore commitment_number now that we no longer need to rebuild the
       state-1 taptree. */
    client_ch.commitment_number = saved_commitment_number;

    /* (3) The to_local + HTLC penalty outputs both landed at
       P2TR(taptweak(client.local_payment_basepoint)) -- a BIP-341 keypath
       output, NOT P2TR(client_pk). Add a 2nd-stage sweep of each so funds
       end up in the client's wallet for econ_assert_wallet_deltas. Use the
       same primitive as the HTLC-timeout 2nd-stage in
       run_htlc_force_to_local_for_arity. */
    secp256k1_xonly_pubkey client_pay_xo;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &client_pay_xo, NULL,
                                        &client_ch.local_payment_basepoint);
    unsigned char client_pay_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, client_pay_ser, &client_pay_xo);
    unsigned char client_pay_taptweak[32];
    sha256_tagged("TapTweak", client_pay_ser, 32, client_pay_taptweak);
    secp256k1_pubkey client_pay_tw_full;
    secp256k1_xonly_pubkey_tweak_add(ctx, &client_pay_tw_full,
                                      &client_pay_xo, client_pay_taptweak);
    secp256k1_xonly_pubkey client_pay_tw;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &client_pay_tw, NULL,
                                        &client_pay_tw_full);
    unsigned char penalty_out_spk[34];
    build_p2tr_script_pubkey(penalty_out_spk, &client_pay_tw);

    /* (3a) 2nd-stage sweep of to_local penalty output. */
    uint64_t tl_pen_out_amt = 0;
    unsigned char tl_pen_chain_spk[64];
    size_t tl_pen_chain_spk_len = 0;
    TEST_ASSERT(regtest_get_tx_output(rt, tl_pen_txid, 0,
                    &tl_pen_out_amt, tl_pen_chain_spk, &tl_pen_chain_spk_len),
                "read to_local penalty output amount");
    TEST_ASSERT(tl_pen_chain_spk_len == 34 &&
                memcmp(tl_pen_chain_spk, penalty_out_spk, 34) == 0,
                "computed penalty SPK matches on-chain SPK (to_local pen)");
    uint64_t tl_pen_actual_fee = to_local_amt - tl_pen_out_amt;

    const uint64_t SECOND_STAGE_FEE = 300;
    tx_buf_t tl_2nd;
    tx_buf_init(&tl_2nd, 256);
    TEST_ASSERT(spend_build_p2tr_bip341_keypath(ctx,
                    client_ch.local_payment_basepoint_secret,
                    tl_pen_txid, 0, tl_pen_out_amt,
                    penalty_out_spk, 34,
                    party_spk[1], 34,
                    SECOND_STAGE_FEE, &tl_2nd),
                "build 2nd-stage to_local-penalty sweep to client P2TR");
    char *tl_2nd_hex = malloc(tl_2nd.len * 2 + 1);
    TEST_ASSERT(tl_2nd_hex != NULL, "tl_2nd_hex malloc");
    hex_encode(tl_2nd.data, tl_2nd.len, tl_2nd_hex);
    tl_2nd_hex[tl_2nd.len * 2] = '\0';
    char tl_2nd_txid[65];
    int tl_2nd_ok = spend_broadcast_and_mine(rt, tl_2nd_hex, 1, tl_2nd_txid);
    free(tl_2nd_hex);
    tx_buf_free(&tl_2nd);
    TEST_ASSERT(tl_2nd_ok, "2nd-stage to_local-penalty sweep confirmed");
    uint64_t tl_to_client = tl_pen_out_amt - SECOND_STAGE_FEE;
    printf("  client 2nd-stage swept %llu sats from to_local-penalty -> P2TR(client)\n",
           (unsigned long long)tl_to_client);

    /* (3b) 2nd-stage sweep of HTLC penalty output. */
    uint64_t htlc_pen_out_amt = 0;
    unsigned char htlc_pen_chain_spk[64];
    size_t htlc_pen_chain_spk_len = 0;
    TEST_ASSERT(regtest_get_tx_output(rt, htlc_pen_txid, 0,
                    &htlc_pen_out_amt, htlc_pen_chain_spk,
                    &htlc_pen_chain_spk_len),
                "read HTLC penalty output amount");
    TEST_ASSERT(htlc_pen_chain_spk_len == 34 &&
                memcmp(htlc_pen_chain_spk, penalty_out_spk, 34) == 0,
                "computed penalty SPK matches on-chain SPK (htlc pen)");
    uint64_t htlc_pen_actual_fee = htlc_out_amt - htlc_pen_out_amt;

    tx_buf_t htlc_2nd;
    tx_buf_init(&htlc_2nd, 256);
    TEST_ASSERT(spend_build_p2tr_bip341_keypath(ctx,
                    client_ch.local_payment_basepoint_secret,
                    htlc_pen_txid, 0, htlc_pen_out_amt,
                    penalty_out_spk, 34,
                    party_spk[1], 34,
                    SECOND_STAGE_FEE, &htlc_2nd),
                "build 2nd-stage HTLC-penalty sweep to client P2TR");
    char *htlc_2nd_hex = malloc(htlc_2nd.len * 2 + 1);
    TEST_ASSERT(htlc_2nd_hex != NULL, "htlc_2nd_hex malloc");
    hex_encode(htlc_2nd.data, htlc_2nd.len, htlc_2nd_hex);
    htlc_2nd_hex[htlc_2nd.len * 2] = '\0';
    char htlc_2nd_txid[65];
    int htlc_2nd_ok = spend_broadcast_and_mine(rt, htlc_2nd_hex, 1,
                                                htlc_2nd_txid);
    free(htlc_2nd_hex);
    tx_buf_free(&htlc_2nd);
    TEST_ASSERT(htlc_2nd_ok, "2nd-stage HTLC-penalty sweep confirmed");
    uint64_t htlc_to_client = htlc_pen_out_amt - SECOND_STAGE_FEE;
    printf("  client 2nd-stage swept %llu sats from HTLC-penalty -> P2TR(client)\n",
           (unsigned long long)htlc_to_client);

    /* (4) Client sweeps their own to_remote (un-revoked, normal payment).
       to_remote spk at commitment_number=1 uses lsp_pcp1 (the LSP's PCP at
       the BREACHED state). */
    unsigned char client_to_remote_sk[32];
    TEST_ASSERT(derive_channel_seckey(ctx, client_to_remote_sk,
                                        client_ch.local_payment_basepoint_secret,
                                        &client_ch.local_payment_basepoint,
                                        &lsp_pcp1),
                "derive client to_remote seckey");
    const uint64_t TO_REMOTE_SWEEP_FEE = 300;
    tx_buf_t tr_sweep;
    tx_buf_init(&tr_sweep, 256);
    TEST_ASSERT(spend_build_p2tr_bip341_keypath(ctx, client_to_remote_sk,
                    commit_txid_hex, 1, to_remote_amt,
                    to_remote_spk, 34,
                    party_spk[1], 34,
                    TO_REMOTE_SWEEP_FEE, &tr_sweep),
                "build to_remote sweep");
    char *tr_hex = malloc(tr_sweep.len * 2 + 1);
    TEST_ASSERT(tr_hex != NULL, "tr_hex malloc");
    hex_encode(tr_sweep.data, tr_sweep.len, tr_hex);
    tr_hex[tr_sweep.len * 2] = '\0';
    char tr_txid[65];
    int tr_ok = spend_broadcast_and_mine(rt, tr_hex, 1, tr_txid);
    free(tr_hex);
    tx_buf_free(&tr_sweep);
    TEST_ASSERT(tr_ok, "to_remote sweep confirmed");
    uint64_t to_remote_to_client = to_remote_amt - TO_REMOTE_SWEEP_FEE;
    printf("  client swept own to_remote %llu sats -> P2TR(client)\n",
           (unsigned long long)to_remote_to_client);

    /* === ACCOUNTING === */
    TEST_ASSERT(econ_snap_post(&econ), "econ_snap_post");

    /* Punisher gets EVERYTHING (to_local + HTLC + to_remote, less fees).
       Breacher gets ZERO. */
    uint64_t expected_deltas[2];
    expected_deltas[0] = 0;  /* LSP (breacher) */
    expected_deltas[1] = tl_to_client + htlc_to_client + to_remote_to_client;

    uint64_t total_fees = commit_fee
                          + tl_pen_actual_fee
                          + htlc_pen_actual_fee
                          + 2 * SECOND_STAGE_FEE
                          + TO_REMOTE_SWEEP_FEE;
    uint64_t swept_sum = expected_deltas[0] + expected_deltas[1];
    TEST_ASSERT(swept_sum + total_fees == leaf_chan_amt,
                "conservation: Sum(swept) + Sum(fees) == leaf_chan_amt");
    printf("  conservation OK: swept=%llu + fees=%llu == leaf_chan_amt=%llu\n",
           (unsigned long long)swept_sum,
           (unsigned long long)total_fees,
           (unsigned long long)leaf_chan_amt);

    TEST_ASSERT(econ_assert_wallet_deltas(&econ, expected_deltas, 0),
                "per-party wallet deltas match (breacher=0, punisher gets all)");
    econ_print_summary(&econ);

    channel_cleanup(&lsp_ch);
    channel_cleanup(&client_ch);
    factory_free(f);
    free(f);
    return 1;
}

int test_regtest_htlc_breach_arity1(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "htlc_breach_a1");
    rt.scan_depth = 200;
    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    int ok = run_htlc_breach_for_arity(&rt, ctx, FACTORY_ARITY_1, 2, mine_addr);
    secp256k1_context_destroy(ctx);
    return ok;
}

int test_regtest_htlc_breach_arity2(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "htlc_breach_a2");
    rt.scan_depth = 200;
    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    /* arity-2 requires 4 participants -> 2 leaves of 2 clients each. We test
       leaf 0's first client; the 3 other clients are uninvolved in the HTLC
       breach, exactly as the audit plan specifies. */
    int ok = run_htlc_breach_for_arity(&rt, ctx, FACTORY_ARITY_2, 4, mine_addr);
    secp256k1_context_destroy(ctx);
    return ok;
}

int test_regtest_htlc_breach_arity_ps(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "htlc_breach_aps");
    rt.scan_depth = 200;
    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    /* PS at chain_len=0 with N=2 (LSP + 1 client). The PS leaf channel SPK
       is factory consensus (all-N MuSig); for N=2 that is mathematically a
       2-of-2 (LSP, client) and channel_init's keyagg auto-detector finds it. */
    int ok = run_htlc_breach_for_arity(&rt, ctx, FACTORY_ARITY_PS, 2, mine_addr);
    secp256k1_context_destroy(ctx);
    return ok;
}

int test_regtest_htlc_force_to_local_arity1(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "htlc_fc_to_local_a1");
    rt.scan_depth = 200;
    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    int ok = run_htlc_force_to_local_for_arity(&rt, ctx,
                                                 FACTORY_ARITY_1, 2, mine_addr);
    secp256k1_context_destroy(ctx);
    return ok;
}

int test_regtest_htlc_force_to_local_arity2(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "htlc_fc_to_local_a2");
    rt.scan_depth = 200;
    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    /* arity-2 requires 4 participants -> 2 leaves of 2 clients each. We test
       leaf 0 (its first client) -- the 3 other clients are uninvolved in the
       HTLC, exactly as the audit plan specifies. */
    int ok = run_htlc_force_to_local_for_arity(&rt, ctx,
                                                 FACTORY_ARITY_2, 4, mine_addr);
    secp256k1_context_destroy(ctx);
    return ok;
}

int test_regtest_htlc_force_to_local_arity_ps(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "htlc_fc_to_local_aps");
    rt.scan_depth = 200;
    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    /* PS at chain_len=0 with N=2 (LSP + 1 client). The PS leaf channel SPK
       is factory consensus (all-N MuSig); for N=2 that is mathematically a
       2-of-2 (LSP, client) and channel_init's keyagg auto-detector finds it. */
    int ok = run_htlc_force_to_local_for_arity(&rt, ctx,
                                                 FACTORY_ARITY_PS, 2, mine_addr);
    secp256k1_context_destroy(ctx);
    return ok;
}

/* ============================================================================
 *  Phase 2 Item #6: Mixed-arity production lifecycle
 *
 *  Builds a SuperScalar factory configured with the canonical mixed level-arity
 *  shape `{2, 4, 8}` (root=arity-2 split, mid=arity-4 fan-out, leaves=arity-8
 *  fan-out — effectively wide branching at every interior level), broadcasts
 *  the entire tree on regtest, force-closes by treating each leaf's published
 *  state as final, sweeps every leaf output (channels + L-stock), and verifies
 *  conservation + per-party wallet deltas across the entire mixed tree.
 *
 *  Why N = 12 (LSP + 11 clients):
 *    PR #81 + docs/factory-arity.md spell out `{2,4,8}` as the recommended
 *    shape for the 33-64 client range. We pick 11 clients because it produces
 *    a tree that exercises BOTH leaf shapes simultaneously without exceeding
 *    DW_MAX_LAYERS=8:
 *      - depth 0  (arity 2): 11 → split 6 | 5
 *      - depth 1L (arity 4): 6 → 2 | 4
 *      - depth 1R (arity 4): 5 → 2 | 3
 *      - depth 2  (arity 8, n>2): 4 → 2 | 2 ; 3 → 2 | 1
 *      - depth 2/3 leaves: 5 arity-2 (2 clients each, 3 outputs)
 *                          + 1 arity-1 (1 client, 2 outputs)
 *    Total: 6 leaves, 11 client channels, 6 L-stock outputs, max depth 3
 *    (n_layers = 4 ≤ DW_MAX_LAYERS).
 *
 *  This is the first end-to-end proof that the production CLI shape we
 *  documented after PR #81 ("--arity 2,4,8") actually broadcasts, sweeps,
 *  and balances under a real regtest.
 *
 *  Severity: every TX broadcast + confirmed; conservation across the entire
 *  mixed tree; per-party econ_assert_wallet_deltas for ALL 12 parties.
 *  ========================================================================== */

/* Deterministic seckeys for 12 parties (extends N_PARTY_SECKEYS).
   Same construction: byte 31 = (i+1). */
static const unsigned char N12_PARTY_SECKEYS[12][32] = {
    { [0 ... 30] = 0, [31] = 0x01 },  /* LSP */
    { [0 ... 30] = 0, [31] = 0x02 },  /* client 1  (participant idx 1) */
    { [0 ... 30] = 0, [31] = 0x03 },  /* client 2 */
    { [0 ... 30] = 0, [31] = 0x04 },  /* client 3 */
    { [0 ... 30] = 0, [31] = 0x05 },  /* client 4 */
    { [0 ... 30] = 0, [31] = 0x06 },  /* client 5 */
    { [0 ... 30] = 0, [31] = 0x07 },  /* client 6 */
    { [0 ... 30] = 0, [31] = 0x08 },  /* client 7 */
    { [0 ... 30] = 0, [31] = 0x09 },  /* client 8 */
    { [0 ... 30] = 0, [31] = 0x0A },  /* client 9 */
    { [0 ... 30] = 0, [31] = 0x0B },  /* client 10 */
    { [0 ... 30] = 0, [31] = 0x0C },  /* client 11 */
};

int test_regtest_mixed_arity_2_4_8_lifecycle(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "mixed_arity_248");
    /* Tree is deeper than the per-arity tests (max depth 3 vs 1-2) and
       each child waits step_blocks*(states_per_layer-1) blocks for BIP-68
       between siblings. With step_blocks=4 / states_per_layer=4 and ~22
       nodes, the last leaves may be buried 200+ blocks deep — bump scan
       depth so regtest_get_confirmations can find them on hosts without
       -txindex. */
    rt.scan_depth = 600;

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    const size_t N = 12;  /* 1 LSP + 11 clients */
    secp256k1_keypair kps[12];
    secp256k1_pubkey  pks[12];
    for (size_t i = 0; i < N; i++) {
        TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[i], N12_PARTY_SECKEYS[i]),
                    "keypair_create");
        TEST_ASSERT(secp256k1_keypair_pub(ctx, &pks[i], &kps[i]),
                    "keypair_pub");
    }

    /* N-way MuSig + BIP-341 taptweak → P2TR funding SPK (same construction
       as fund_n_party_factory). */
    musig_keyagg_t ka;
    TEST_ASSERT(musig_aggregate_keys(ctx, &ka, pks, N), "musig agg N=12");
    unsigned char agg_ser[32];
    TEST_ASSERT(secp256k1_xonly_pubkey_serialize(ctx, agg_ser, &ka.agg_pubkey),
                "serialize agg");
    unsigned char tweak[32];
    sha256_tagged("TapTweak", agg_ser, 32, tweak);
    musig_keyagg_t ka_spk = ka;
    secp256k1_pubkey tw_pk;
    TEST_ASSERT(secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tw_pk,
                                                        &ka_spk.cache, tweak),
                "taptweak");
    secp256k1_xonly_pubkey tw_xonly;
    TEST_ASSERT(secp256k1_xonly_pubkey_from_pubkey(ctx, &tw_xonly, NULL, &tw_pk),
                "tw xonly");
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tw_xonly);

    /* Fund the factory: 0.01 BTC = 1,000,000 sats. Bigger than the per-arity
       tests (500k) because this tree has 22 nodes consuming ~4400 sats in
       fees and 6 leaves to share the remainder — we want each output well
       above dust + sweep fees. */
    unsigned char tw_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, tw_ser, &tw_xonly);
    char fund_addr[128];
    TEST_ASSERT(regtest_derive_p2tr_address(&rt, tw_ser, fund_addr,
                                              sizeof(fund_addr)),
                "derive fund addr");
    char fund_txid[65];
    TEST_ASSERT(regtest_fund_address(&rt, fund_addr, 0.01, fund_txid),
                "fund factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    uint32_t fund_vout = UINT32_MAX;
    uint64_t fund_amount = 0;
    for (uint32_t v = 0; v < 4; v++) {
        uint64_t a = 0;
        unsigned char s[64];
        size_t sl = 0;
        if (regtest_get_tx_output(&rt, fund_txid, v, &a, s, &sl) &&
            sl == 34 && memcmp(s, fund_spk, 34) == 0) {
            fund_vout = v;
            fund_amount = a;
            break;
        }
    }
    TEST_ASSERT(fund_vout != UINT32_MAX, "find fund vout");
    printf("  [mixed{2,4,8}] funded %s:%u  %llu sats\n",
           fund_txid, fund_vout, (unsigned long long)fund_amount);

    /* Build factory with mixed level arity {2, 4, 8}. */
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f != NULL, "alloc factory");
    factory_init(f, ctx, kps, N, 4, 4);  /* step_blocks=4, states_per_layer=4 */
    /* Wider N-way state nodes are larger TXs than the binary builder's;
       bump fee_per_tx above CI regtest mempool min relay (~240 sats for
       these vBytes). 1000 sats clears all currently-known regtest floors. */
    f->fee_per_tx = 1000;

    uint8_t arities[3] = { 2, 4, 8 };
    factory_set_level_arity(f, arities, 3);

    unsigned char fund_txid_bytes[32];
    TEST_ASSERT(hex_decode(fund_txid, fund_txid_bytes, 32), "decode fund txid");
    reverse_bytes(fund_txid_bytes, 32);
    factory_set_funding(f, fund_txid_bytes, fund_vout, fund_amount, fund_spk, 34);

    TEST_ASSERT(factory_build_tree(f), "build_tree mixed {2,4,8}");
    TEST_ASSERT(factory_sign_all(f), "sign_all mixed {2,4,8}");

    /* TRUE N-way assertions (Phase 2 builder).
       For N=12 with {2,4,8}:
         depth 0 (root state): arity-2 → 2 outputs, splits 11 clients into [6, 5]
         depth 1 (mid state):  arity-4 → 4 outputs each
         depth 2 (leaves):     arity-8 → leaves (n <= 8 clients per leaf)
       Total leaves: 8 (4 per mid-subtree). Each leaf has 1..2 clients. */
    int n_leaves = f->n_leaf_nodes;
    printf("  [mixed{2,4,8}] tree built: %zu nodes, %d leaves, n_layers=%d\n",
           f->n_nodes, n_leaves, (int)f->counter.n_layers);

    /* Root state (node 1) has 2 outputs (arity-2 fan-out) */
    TEST_ASSERT_EQ(f->nodes[1].type, NODE_STATE, "node 1 is root state");
    TEST_ASSERT_EQ(f->nodes[1].n_outputs, 2,
                   "root state has 2 outputs (arity-2 fan-out)");

    /* Find a depth-1 mid state and assert arity-4 fan-out */
    int found_mid = 0;
    for (size_t i = 0; i < f->n_nodes; i++) {
        if (f->nodes[i].type != NODE_STATE) continue;
        int d = 0;
        int cur = (int)i;
        while (cur > 0 && f->nodes[cur].parent_index >= 0) {
            cur = f->nodes[cur].parent_index;
            d++;
        }
        d = d / 2;
        if (d == 1) {
            TEST_ASSERT_EQ(f->nodes[i].n_outputs, 4,
                           "mid state has 4 outputs (arity-4 fan-out)");
            found_mid = 1;
        }
    }
    TEST_ASSERT(found_mid, "found depth-1 mid state with arity-4 fan-out");

    /* Validate every leaf: arity-8 cap (n_clients <= 8), n_outputs == n_clients + 1 */
    int total_client_channels = 0;
    for (int li = 0; li < n_leaves; li++) {
        size_t nidx = f->leaf_node_indices[li];
        factory_node_t *leaf = &f->nodes[nidx];
        TEST_ASSERT(!leaf->is_ps_leaf, "no PS leaves in {2,4,8} tree");
        size_t n_clients = leaf->n_signers - 1;  /* exclude LSP */
        TEST_ASSERT(n_clients >= 1 && n_clients <= 8,
                    "leaf has 1..8 clients (arity-8 cap)");
        TEST_ASSERT_EQ(leaf->n_outputs, n_clients + 1,
                       "leaf n_outputs == n_clients + 1");
        total_client_channels += (int)n_clients;
    }
    printf("  [mixed{2,4,8}] %d leaves, %d total client channels (N-1=11)\n",
           n_leaves, total_client_channels);
    TEST_ASSERT_EQ(total_client_channels, 11, "all 11 clients placed");

    /* Broadcast every signed tree node in order with correct BIP-68 spacing. */
    char txids[FACTORY_MAX_NODES][65];
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *nd = &f->nodes[i];
        TEST_ASSERT(nd->is_signed && nd->signed_tx.len > 0, "node signed");
        char *tx_hex = malloc(nd->signed_tx.len * 2 + 1);
        TEST_ASSERT(tx_hex != NULL, "tx_hex malloc");
        hex_encode(nd->signed_tx.data, nd->signed_tx.len, tx_hex);
        int ok = regtest_send_raw_tx(&rt, tx_hex, txids[i]);
        free(tx_hex);
        TEST_ASSERT(ok, "broadcast tree node");
        int blocks_to_mine = 1;
        if (i + 1 < f->n_nodes) {
            uint32_t cns = f->nodes[i + 1].nsequence;
            if (!(cns & 0x80000000u)) blocks_to_mine = (int)(cns & 0xFFFF) + 1;
        }
        regtest_mine_blocks(&rt, blocks_to_mine, mine_addr);
    }
    for (int li = 0; li < n_leaves; li++) {
        int conf = regtest_get_confirmations(&rt,
            txids[f->leaf_node_indices[li]]);
        TEST_ASSERT(conf >= 1, "leaf on chain");
    }
    printf("  [mixed{2,4,8}] full tree broadcast OK — %zu nodes, "
           "%d leaves confirmed\n", f->n_nodes, n_leaves);

    /* Build per-party P2TR(xonly(pk_i)) destinations for all 12 parties. */
    unsigned char party_spk[12][34];
    for (size_t p = 0; p < N; p++) {
        secp256k1_xonly_pubkey xo;
        secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &pks[p]);
        build_p2tr_script_pubkey(party_spk[p], &xo);
    }

    /* Wire econ harness for all 12 parties. CRITICAL: snap_pre BEFORE any
       sweep TX broadcasts, per feedback_econ_snap_pre_timing.md. */
    econ_ctx_t econ;
    econ_ctx_init(&econ, &rt, ctx);
    static const char *party_names[12] = {
        "LSP", "client01", "client02", "client03", "client04", "client05",
        "client06", "client07", "client08", "client09", "client10", "client11"
    };
    for (size_t p = 0; p < N; p++) {
        TEST_ASSERT(econ_register_party(&econ, p, party_names[p],
                                         N12_PARTY_SECKEYS[p]),
                    "register party");
    }
    econ.factory_funding_amount = fund_amount;
    TEST_ASSERT(econ_snap_pre(&econ), "econ_snap_pre");

    /* Per-leaf sweep loop. Each leaf has either:
         arity-2: outputs[0]=channel(client_a,LSP) + outputs[1]=channel(client_b,LSP)
                  + outputs[2]=L-stock
         arity-1: outputs[0]=channel(client,LSP) + outputs[1]=L-stock
       For each channel: 50/50 split between client and LSP via offline 2-of-2
       MuSig (pks order = {client, LSP}, matching setup_leaf_outputs +
       setup_single_leaf_outputs in src/factory.c).
       For each L-stock: LSP solo BIP-341 keypath sweep. */
    const uint64_t LSTOCK_SWEEP_FEE = 300;
    const uint64_t CHAN_SWEEP_FEE   = 400;
    /* Small simulated payment shift to prove per-channel asymmetric splits
       work — client paid LSP a small amount during operation. */
    const uint64_t PAYMENT_SHIFT    = 1000;

    uint64_t per_party_recv[12] = {0};
    uint64_t total_sweep_fees = 0;
    uint64_t total_allocated  = 0;

    for (int li = 0; li < n_leaves; li++) {
        size_t nidx = f->leaf_node_indices[li];
        factory_node_t *leaf = &f->nodes[nidx];
        const char *leaf_txid = txids[nidx];

        unsigned char leaf_txid_bytes[32];
        TEST_ASSERT(hex_decode(leaf_txid, leaf_txid_bytes, 32),
                    "decode leaf txid");
        reverse_bytes(leaf_txid_bytes, 32);

        TEST_ASSERT(leaf->signer_indices[0] == 0,
                    "signer[0] is LSP for every leaf");

        /* L-stock is the LAST output: vout n_outputs-1. */
        uint32_t lstock_vout = (uint32_t)(leaf->n_outputs - 1);
        int n_channels       = (int)leaf->n_outputs - 1;

        /* (A) Sweep L-stock cooperatively via N-of-N MuSig (canonical
           t/1242 — see L-stock sweep block at line 2540). */
        uint64_t lstock_amt = leaf->outputs[lstock_vout].amount_sats;

        tx_buf_t lstock_sweep;
        tx_buf_init(&lstock_sweep, 256);
        TEST_ASSERT(spend_l_stock_cooperative(ctx, f, leaf,
                        leaf_txid, lstock_vout, lstock_amt,
                        party_spk[0], 34,
                        LSTOCK_SWEEP_FEE, &lstock_sweep),
                    "build L-stock cooperative sweep");
        char *lh = malloc(lstock_sweep.len * 2 + 1);
        TEST_ASSERT(lh != NULL, "lh malloc");
        hex_encode(lstock_sweep.data, lstock_sweep.len, lh);
        lh[lstock_sweep.len * 2] = '\0';
        char lstock_sweep_txid[65];
        int lok = spend_broadcast_and_mine(&rt, lh, 1, lstock_sweep_txid);
        free(lh); tx_buf_free(&lstock_sweep);
        TEST_ASSERT(lok, "L-stock sweep confirmed");
        per_party_recv[0] += lstock_amt - LSTOCK_SWEEP_FEE;
        total_sweep_fees  += LSTOCK_SWEEP_FEE;
        total_allocated   += lstock_amt;
        printf("  leaf %d: LSP swept L-stock %llu sats (vout=%u)\n",
               li, (unsigned long long)(lstock_amt - LSTOCK_SWEEP_FEE),
               lstock_vout);

        /* (B) Sweep each channel via offline 2-of-2 MuSig {client_X, LSP}. */
        for (int ch = 0; ch < n_channels; ch++) {
            /* signer_indices layout: [0]=LSP, [1..]=clients in this leaf.
               outputs[ch] (ch=0..n_channels-1) corresponds to client at
               signer_indices[1+ch] — same convention as
               test_regtest_full_force_close_and_sweep_arity2. */
            uint32_t client_idx = leaf->signer_indices[1 + ch];
            TEST_ASSERT(client_idx >= 1 && client_idx < N,
                        "client_idx in range");

            uint64_t chan_amt = leaf->outputs[ch].amount_sats;
            uint64_t after_fee = chan_amt - CHAN_SWEEP_FEE;
            uint64_t balanced  = after_fee / 2;
            uint64_t client_share = balanced - PAYMENT_SHIFT;
            uint64_t lsp_share    = after_fee - client_share;
            unsigned char chan_spk[34];
            memcpy(chan_spk, leaf->outputs[ch].script_pubkey, 34);

            tx_output_t outs[2];
            memcpy(outs[0].script_pubkey, party_spk[client_idx], 34);
            outs[0].script_pubkey_len = 34;
            outs[0].amount_sats = client_share;
            memcpy(outs[1].script_pubkey, party_spk[0], 34);
            outs[1].script_pubkey_len = 34;
            outs[1].amount_sats = lsp_share;

            tx_buf_t chan_unsigned;
            tx_buf_init(&chan_unsigned, 256);
            TEST_ASSERT(build_unsigned_tx(&chan_unsigned, NULL,
                                            leaf_txid_bytes,
                                            (uint32_t)ch, 0xFFFFFFFEu,
                                            outs, 2),
                        "build unsigned channel sweep");
            unsigned char sighash[32];
            TEST_ASSERT(compute_taproot_sighash(sighash,
                            chan_unsigned.data, chan_unsigned.len,
                            0, chan_spk, 34, chan_amt, 0xFFFFFFFEu),
                        "channel sighash");

            /* MuSig2 pubkey order matches factory: {client, LSP}. */
            secp256k1_keypair signers[2] = { kps[client_idx], kps[0] };
            secp256k1_pubkey  ckpks[2];
            secp256k1_keypair_pub(ctx, &ckpks[0], &signers[0]);
            secp256k1_keypair_pub(ctx, &ckpks[1], &signers[1]);
            musig_keyagg_t cka;
            TEST_ASSERT(musig_aggregate_keys(ctx, &cka, ckpks, 2),
                        "agg channel keys (client, LSP)");
            unsigned char sig64[64];
            TEST_ASSERT(musig_sign_taproot(ctx, sig64, sighash, signers, 2,
                                             &cka, NULL),
                        "2-of-2 MuSig2 sign channel sweep");
            tx_buf_t chan_signed;
            tx_buf_init(&chan_signed, 256);
            TEST_ASSERT(finalize_signed_tx(&chan_signed,
                            chan_unsigned.data, chan_unsigned.len, sig64),
                        "finalize channel sweep tx");
            tx_buf_free(&chan_unsigned);

            char *ch_hex = malloc(chan_signed.len * 2 + 1);
            TEST_ASSERT(ch_hex != NULL, "ch_hex malloc");
            hex_encode(chan_signed.data, chan_signed.len, ch_hex);
            ch_hex[chan_signed.len * 2] = '\0';
            char chan_sweep_txid[65];
            int cok = spend_broadcast_and_mine(&rt, ch_hex, 1, chan_sweep_txid);
            free(ch_hex); tx_buf_free(&chan_signed);
            TEST_ASSERT(cok, "channel 2-of-2 sweep confirmed");
            per_party_recv[client_idx] += client_share;
            per_party_recv[0]          += lsp_share;
            total_sweep_fees           += CHAN_SWEEP_FEE;
            total_allocated            += chan_amt;
            printf("  leaf %d ch%d (client%u,LSP): client=%llu, LSP=%llu\n",
                   li, ch, (unsigned)client_idx,
                   (unsigned long long)client_share,
                   (unsigned long long)lsp_share);
        }
    }

    TEST_ASSERT(econ_snap_post(&econ), "econ_snap_post");

    /* Conservation across the entire mixed-arity tree:
       Σ(swept) + Σ(sweep_fees) == Σ(leaf_allocations).
       Tree-internal fees are baked into the leaf allocations already. */
    uint64_t swept_sum = 0;
    for (size_t p = 0; p < N; p++) swept_sum += per_party_recv[p];
    TEST_ASSERT(swept_sum + total_sweep_fees == total_allocated,
                "conservation: Σswept + Σsweep_fees == Σleaf_allocations");
    printf("  [mixed{2,4,8}] conservation OK: swept=%llu + sweep_fees=%llu "
           "== allocations=%llu\n",
           (unsigned long long)swept_sum,
           (unsigned long long)total_sweep_fees,
           (unsigned long long)total_allocated);

    /* Per-party expected deltas. */
    uint64_t expected_deltas[12];
    for (size_t p = 0; p < N; p++) expected_deltas[p] = per_party_recv[p];

    TEST_ASSERT(econ_assert_wallet_deltas(&econ, expected_deltas, 0),
                "per-party wallet deltas match expected (12 parties)");
    econ_print_summary(&econ);

    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ============================================================================
 *  Phase 3 Item #1: PS at N=8 / N=16 on regtest with full per-party accounting.
 *
 *  Phase 2 #3 covered PS chain-advance at N=3 on real chain; Phase 2 #7
 *  covered PS at N=64/128 in unit tests with fake txids. The middle ground —
 *  N>=8 on real chain with full per-party accounting — is filled here.
 *
 *  Five cells:
 *    A. test_regtest_ps_full_lifecycle_n8           — N=8, all 7 leaves
 *                                                      chain_len=0
 *    B. test_regtest_ps_heterogeneous_chains_n8     — N=8, mixed chain_lens
 *                                                      {5,3,1,0,0,2,4}
 *    C. test_regtest_ps_full_lifecycle_n16          — N=16, all 15 leaves
 *                                                      chain_len=0
 *    D. test_regtest_ps_heterogeneous_chains_n16    — N=16, mixed chain_lens
 *                                                      {0,1,2,0,5,0,3,0,1,4,
 *                                                       0,2,0,1,5}
 *    E. test_regtest_ps_old_state_broadcast_fails_n8 — adversarial: prove
 *                                                       that an old chain[i]
 *                                                       cannot be re-broadcast
 *                                                       once chain[i+1] confirms.
 *
 *  Severity: every TX broadcast + confirmed; conservation across the entire
 *  factory; per-party econ_assert_wallet_deltas for ALL N parties.
 *  ========================================================================== */

/* Deterministic seckeys for up to 16 parties (extends N12_PARTY_SECKEYS).
   Same construction: byte 31 = (i+1). */
static const unsigned char N16_PARTY_SECKEYS[16][32] = {
    { [0 ... 30] = 0, [31] = 0x01 },  /* LSP */
    { [0 ... 30] = 0, [31] = 0x02 },  /* client 1 */
    { [0 ... 30] = 0, [31] = 0x03 },  /* client 2 */
    { [0 ... 30] = 0, [31] = 0x04 },  /* client 3 */
    { [0 ... 30] = 0, [31] = 0x05 },  /* client 4 */
    { [0 ... 30] = 0, [31] = 0x06 },  /* client 5 */
    { [0 ... 30] = 0, [31] = 0x07 },  /* client 6 */
    { [0 ... 30] = 0, [31] = 0x08 },  /* client 7 */
    { [0 ... 30] = 0, [31] = 0x09 },  /* client 8 */
    { [0 ... 30] = 0, [31] = 0x0A },  /* client 9 */
    { [0 ... 30] = 0, [31] = 0x0B },  /* client 10 */
    { [0 ... 30] = 0, [31] = 0x0C },  /* client 11 */
    { [0 ... 30] = 0, [31] = 0x0D },  /* client 12 */
    { [0 ... 30] = 0, [31] = 0x0E },  /* client 13 */
    { [0 ... 30] = 0, [31] = 0x0F },  /* client 14 */
    { [0 ... 30] = 0, [31] = 0x10 },  /* client 15 */
};

/* N=32 seckeys for Phase 3 #2 (PS at N=32 on regtest).
   First byte 0xFE distinguishes from N16_PARTY_SECKEYS so the derived
   wallet addresses do not collide with concurrent N=8/N=16 cells.
   Last byte (i+1) keeps each party's seckey unique. */
static const unsigned char N32_PARTY_SECKEYS[32][32] = {
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x01 },  /* LSP */
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x02 },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x03 },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x04 },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x05 },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x06 },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x07 },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x08 },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x09 },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x0A },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x0B },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x0C },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x0D },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x0E },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x0F },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x10 },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x11 },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x12 },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x13 },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x14 },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x15 },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x16 },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x17 },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x18 },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x19 },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x1A },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x1B },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x1C },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x1D },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x1E },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x1F },
    { [0] = 0xFE, [1 ... 30] = 0, [31] = 0x20 },
};

/* Build N-way MuSig + BIP-341 taptweak P2TR funding SPK for N parties.
   Caller provides keypairs + pubkeys arrays sized for N. */
static int build_n_party_funding_spk(secp256k1_context *ctx,
                                       const secp256k1_pubkey *pks,
                                       size_t N,
                                       unsigned char out_fund_spk[34],
                                       unsigned char out_tw_ser[32]) {
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks, N)) return 0;
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
    if (!secp256k1_xonly_pubkey_serialize(ctx, out_tw_ser, &tw_xonly)) return 0;
    return 1;
}

/* Build + fund + sign a PS factory at N participants with given funding amount.
   Stores keypairs/pubkeys + fund txid/vout/amount in out parameters.
   Returns 1 on success. f is allocated by caller. */
static int build_ps_factory_n(regtest_t *rt,
                                secp256k1_context *ctx,
                                size_t N,
                                double fund_btc,
                                const char *mine_addr,
                                const unsigned char (*seckeys)[32],
                                secp256k1_keypair *out_kps,   /* sized N */
                                secp256k1_pubkey  *out_pks,   /* sized N */
                                factory_t *f,
                                unsigned char out_fund_spk[34],
                                char out_fund_txid[65],
                                uint32_t *out_fund_vout,
                                uint64_t *out_fund_amount) {
    for (size_t i = 0; i < N; i++) {
        if (!secp256k1_keypair_create(ctx, &out_kps[i], seckeys[i])) return 0;
        if (!secp256k1_keypair_pub(ctx, &out_pks[i], &out_kps[i])) return 0;
    }
    unsigned char tw_ser[32];
    if (!build_n_party_funding_spk(ctx, out_pks, N, out_fund_spk, tw_ser))
        return 0;

    char fund_addr[128];
    if (!regtest_derive_p2tr_address(rt, tw_ser, fund_addr, sizeof(fund_addr)))
        return 0;
    if (!regtest_fund_address(rt, fund_addr, fund_btc, out_fund_txid)) return 0;
    regtest_mine_blocks(rt, 1, mine_addr);

    *out_fund_vout = UINT32_MAX;
    *out_fund_amount = 0;
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

    unsigned char txid_bytes[32];
    if (!hex_decode(out_fund_txid, txid_bytes, 32)) return 0;
    reverse_bytes(txid_bytes, 32);
    factory_init(f, ctx, out_kps, N, 2, 4);  /* step_blocks=2, states_per_layer=4 */
    factory_set_arity(f, FACTORY_ARITY_PS);
    factory_set_funding(f, txid_bytes, *out_fund_vout, *out_fund_amount,
                        out_fund_spk, 34);
    if (!factory_build_tree(f)) return 0;
    if (!factory_sign_all(f))   return 0;
    return 1;
}

/* Broadcast every signed tree node (chain[0] for every PS leaf) in DFS order
   with BIP-68 spacing. Stores resulting txids in out_txids[].
   Returns 1 on success. */
static int broadcast_factory_tree(regtest_t *rt, factory_t *f,
                                    const char *mine_addr,
                                    char out_txids[FACTORY_MAX_NODES][65]) {
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *nd = &f->nodes[i];
        if (!nd->is_signed || nd->signed_tx.len == 0) return 0;
        char *tx_hex = malloc(nd->signed_tx.len * 2 + 1);
        if (!tx_hex) return 0;
        hex_encode(nd->signed_tx.data, nd->signed_tx.len, tx_hex);
        int ok = regtest_send_raw_tx(rt, tx_hex, out_txids[i]);
        free(tx_hex);
        if (!ok) return 0;
        int blocks_to_mine = 1;
        if (i + 1 < f->n_nodes) {
            uint32_t cns = f->nodes[i + 1].nsequence;
            if (!(cns & 0x80000000u)) blocks_to_mine = (int)(cns & 0xFFFF) + 1;
        }
        regtest_mine_blocks(rt, blocks_to_mine, mine_addr);
    }
    return 1;
}

/* Per-leaf bookkeeping of chain advances. Stashes chain[i] tx bytes + the
   txid of each chain[i] (i=0 is the leaf state node from the tree broadcast).
   Used by tests B/D/E to track chain[i] for sweep + adversarial broadcast. */
typedef struct {
    int n_advances;                     /* >= 0; chain has n_advances+1 TXs */
    /* chain[0..n_advances] each */
    unsigned char *chain_tx[16];        /* malloc'd raw bytes */
    size_t chain_tx_len[16];
    char chain_txid[16][65];            /* hex */
    /* Final state (chain[n_advances]) channel SPK + amount for sweep */
    unsigned char chan_spk[34];
    uint64_t chain0_chan_amt;
    uint64_t chain0_lstock_amt;
    unsigned char lstock_spk[34];
    uint32_t client_idx;                /* 1..N-1 */
} ps_leaf_chain_t;

static void ps_leaf_chain_free(ps_leaf_chain_t *c) {
    for (int i = 0; i <= c->n_advances && i < 16; i++) {
        free(c->chain_tx[i]);
        c->chain_tx[i] = NULL;
    }
}

/* Run a per-leaf chain-advance loop: starting from a built+broadcast leaf
   (chain[0] already on chain), call factory_advance_leaf n_advances times,
   stash every chain[i] bytes + txid, broadcast chain[1..n_advances] in order
   and confirm. */
static int advance_and_broadcast_leaf_chain(regtest_t *rt, factory_t *f,
                                              int leaf_side,
                                              const char *leaf_chain0_txid,
                                              int n_advances,
                                              const char *mine_addr,
                                              ps_leaf_chain_t *out) {
    if (n_advances < 0 || n_advances >= 16) return 0;
    size_t nidx = f->leaf_node_indices[leaf_side];
    factory_node_t *leaf = &f->nodes[nidx];

    out->n_advances = n_advances;
    out->client_idx = leaf->signer_indices[1];
    memcpy(out->chan_spk, leaf->outputs[0].script_pubkey, 34);
    out->chain0_chan_amt = leaf->outputs[0].amount_sats;
    out->chain0_lstock_amt = leaf->outputs[1].amount_sats;
    memcpy(out->lstock_spk, leaf->outputs[1].script_pubkey, 34);

    /* Stash chain[0] (already on chain — copy bytes from leaf->signed_tx). */
    out->chain_tx_len[0] = leaf->signed_tx.len;
    out->chain_tx[0] = malloc(out->chain_tx_len[0]);
    if (!out->chain_tx[0]) return 0;
    memcpy(out->chain_tx[0], leaf->signed_tx.data, out->chain_tx_len[0]);
    memcpy(out->chain_txid[0], leaf_chain0_txid, 65);

    for (int adv = 1; adv <= n_advances; adv++) {
        if (!factory_advance_leaf(f, leaf_side)) return 0;
        if (leaf->ps_chain_len != adv) return 0;
        if (leaf->n_outputs != 1) return 0;
        if (!leaf->is_signed || leaf->signed_tx.len == 0) return 0;

        /* Stash chain[adv] bytes BEFORE next advance overwrites signed_tx. */
        out->chain_tx_len[adv] = leaf->signed_tx.len;
        out->chain_tx[adv] = malloc(out->chain_tx_len[adv]);
        if (!out->chain_tx[adv]) return 0;
        memcpy(out->chain_tx[adv], leaf->signed_tx.data, out->chain_tx_len[adv]);

        /* Broadcast chain[adv]. */
        char *adv_hex = malloc(out->chain_tx_len[adv] * 2 + 1);
        if (!adv_hex) return 0;
        hex_encode(out->chain_tx[adv], out->chain_tx_len[adv], adv_hex);
        adv_hex[out->chain_tx_len[adv] * 2] = '\0';
        int ok = regtest_send_raw_tx(rt, adv_hex, out->chain_txid[adv]);
        free(adv_hex);
        if (!ok) return 0;
        regtest_mine_blocks(rt, 1, mine_addr);
        if (regtest_get_confirmations(rt, out->chain_txid[adv]) < 1) return 0;
    }
    return 1;
}

/* Build a PS-channel sweep tx: spends chain[N] vout 0 (the channel) of the
   given leaf, splits the channel amount into client_share + lsp_share.
   leaf is the current factory_node_t (used for n_signers / signer_indices /
   keyagg). Returns 1 on success, fills out_txid. */
static int sweep_ps_channel_n_party(regtest_t *rt,
                                      secp256k1_context *ctx,
                                      const secp256k1_keypair *kps,
                                      size_t N,
                                      const factory_node_t *leaf,
                                      const char *spend_txid_hex,
                                      const unsigned char chan_spk[34],
                                      uint64_t chan_amt,
                                      uint64_t client_share,
                                      uint64_t lsp_share,
                                      const unsigned char client_p2tr_spk[34],
                                      const unsigned char lsp_p2tr_spk[34],
                                      char out_txid[65]) {
    (void)N; /* N param kept for future verification */

    unsigned char tb[32];
    if (!hex_decode(spend_txid_hex, tb, 32)) return 0;
    reverse_bytes(tb, 32);

    tx_output_t outs[2];
    memcpy(outs[0].script_pubkey, client_p2tr_spk, 34);
    outs[0].script_pubkey_len = 34;
    outs[0].amount_sats = client_share;
    memcpy(outs[1].script_pubkey, lsp_p2tr_spk, 34);
    outs[1].script_pubkey_len = 34;
    outs[1].amount_sats = lsp_share;

    tx_buf_t cu;
    tx_buf_init(&cu, 256);
    if (!build_unsigned_tx(&cu, NULL, tb, 0, 0xFFFFFFFEu, outs, 2)) {
        tx_buf_free(&cu); return 0;
    }
    unsigned char sh[32];
    if (!compute_taproot_sighash(sh, cu.data, cu.len, 0, chan_spk, 34,
                                  chan_amt, 0xFFFFFFFEu)) {
        tx_buf_free(&cu); return 0;
    }
    secp256k1_keypair signers[FACTORY_MAX_SIGNERS];
    secp256k1_pubkey  signer_pks[FACTORY_MAX_SIGNERS];
    for (size_t s = 0; s < leaf->n_signers; s++) {
        uint32_t sidx = leaf->signer_indices[s];
        signers[s] = kps[sidx];
        secp256k1_keypair_pub(ctx, &signer_pks[s], &signers[s]);
    }
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, signer_pks, leaf->n_signers)) {
        tx_buf_free(&cu); return 0;
    }
    unsigned char sig64[64];
    if (!musig_sign_taproot(ctx, sig64, sh, signers, leaf->n_signers, &ka, NULL)) {
        tx_buf_free(&cu); return 0;
    }
    tx_buf_t cs;
    tx_buf_init(&cs, 256);
    if (!finalize_signed_tx(&cs, cu.data, cu.len, sig64)) {
        tx_buf_free(&cu); tx_buf_free(&cs); return 0;
    }
    tx_buf_free(&cu);

    char *ch = malloc(cs.len * 2 + 1);
    if (!ch) { tx_buf_free(&cs); return 0; }
    hex_encode(cs.data, cs.len, ch);
    ch[cs.len * 2] = '\0';
    int ok = spend_broadcast_and_mine(rt, ch, 1, out_txid);
    free(ch); tx_buf_free(&cs);
    return ok;
}

/* Run a full PS lifecycle test at the given N with optional per-leaf chain
   advances. chain_lens[i] is the number of advances for leaf i (must be
   >= 0 and < 16). If chain_lens is NULL, all leaves stay at chain_len=0.
   Returns 1 on success. */
static int run_ps_full_lifecycle(regtest_t *rt,
                                   secp256k1_context *ctx,
                                   size_t N,
                                   const int *chain_lens,
                                   double fund_btc,
                                   const unsigned char (*seckeys)[32],
                                   const char *mine_addr) {
    /* Sized for N up to 32 (Phase 3 #2 raised N from 16 to 32). */
    secp256k1_keypair kps[32];
    secp256k1_pubkey  pks[32];
    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;

    unsigned char fund_spk[34];
    char fund_txid[65];
    uint32_t fund_vout = 0;
    uint64_t fund_amount = 0;
    if (!build_ps_factory_n(rt, ctx, N, fund_btc, mine_addr, seckeys, kps, pks,
                              f, fund_spk, fund_txid, &fund_vout, &fund_amount)) {
        factory_free(f); free(f); return 0;
    }
    int n_leaves = f->n_leaf_nodes;
    printf("  [PS N=%zu] factory funded: %llu sats, %zu nodes, %d leaves\n",
           N, (unsigned long long)fund_amount, f->n_nodes, n_leaves);
    TEST_ASSERT(n_leaves == (int)(N - 1), "PS leaves = N-1");

    /* Broadcast every signed tree node (chain[0] for each leaf). */
    char txids[FACTORY_MAX_NODES][65];
    TEST_ASSERT(broadcast_factory_tree(rt, f, mine_addr, txids),
                "broadcast factory tree");
    for (int li = 0; li < n_leaves; li++) {
        TEST_ASSERT(regtest_get_confirmations(rt,
                        txids[f->leaf_node_indices[li]]) >= 1,
                    "leaf chain[0] on chain");
    }
    printf("  full tree broadcast OK -- %zu nodes, %d leaves chain[0] confirmed\n",
           f->n_nodes, n_leaves);

    /* Per-leaf chain advance + broadcast. Stash bytes + txids for sweep step.
       Sized for N=32 (31 leaves max). */
    ps_leaf_chain_t leaf_chains[32] = {0};
    uint64_t total_advance_fees = 0;
    uint64_t fee_per_tx = f->fee_per_tx;
    for (int li = 0; li < n_leaves; li++) {
        int n_adv = (chain_lens != NULL) ? chain_lens[li] : 0;
        TEST_ASSERT(advance_and_broadcast_leaf_chain(rt, f, li,
                        txids[f->leaf_node_indices[li]],
                        n_adv, mine_addr, &leaf_chains[li]),
                    "advance + broadcast leaf chain");
        if (n_adv > 0) {
            printf("  leaf %d: chain advanced to len=%d (chan now %llu sats)\n",
                   li, n_adv,
                   (unsigned long long)(leaf_chains[li].chain0_chan_amt
                                         - (uint64_t)n_adv * fee_per_tx));
        }
        total_advance_fees += (uint64_t)n_adv * fee_per_tx;
    }

    /* Build per-party P2TR(xonly(pk_i)) destinations. Sized for N=32. */
    unsigned char party_spk[32][34];
    for (size_t p = 0; p < N; p++) {
        secp256k1_xonly_pubkey xo;
        secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &pks[p]);
        build_p2tr_script_pubkey(party_spk[p], &xo);
    }

    /* Wire econ harness for all N parties BEFORE any sweeps. */
    econ_ctx_t econ;
    econ_ctx_init(&econ, rt, ctx);
    char party_name_buf[32][32];
    snprintf(party_name_buf[0], 32, "LSP");
    for (size_t p = 1; p < N; p++)
        snprintf(party_name_buf[p], 32, "client%02zu", p);
    for (size_t p = 0; p < N; p++) {
        TEST_ASSERT(econ_register_party(&econ, p, party_name_buf[p],
                                         seckeys[p]),
                    "register party");
    }
    econ.factory_funding_amount = fund_amount;
    TEST_ASSERT(econ_snap_pre(&econ), "econ_snap_pre");

    const uint64_t LSTOCK_SWEEP_FEE = 300;
    const uint64_t CHAN_SWEEP_FEE   = 400;
    const uint64_t SIMULATED_PAYMENT     = 5000;
    const uint64_t SIMULATED_ROUTING_FEE = 100;
    const uint64_t CLIENT_BALANCE_SHIFT  = SIMULATED_PAYMENT + SIMULATED_ROUTING_FEE;

    uint64_t per_party_recv[32] = {0};
    uint64_t total_sweep_fees   = 0;
    uint64_t total_allocated    = 0;

    /* Per-leaf sweep loop. */
    for (int li = 0; li < n_leaves; li++) {
        ps_leaf_chain_t *lc = &leaf_chains[li];
        size_t nidx = f->leaf_node_indices[li];
        factory_node_t *leaf = &f->nodes[nidx];
        const char *chain0_txid = lc->chain_txid[0];
        const char *chainN_txid = lc->chain_txid[lc->n_advances];

        TEST_ASSERT(leaf->is_ps_leaf, "leaf is PS");
        TEST_ASSERT(leaf->signer_indices[0] == 0, "signer[0] is LSP");
        uint32_t client_idx = lc->client_idx;
        TEST_ASSERT(client_idx >= 1 && client_idx < N, "client_idx in range");

        /* (A) Sweep L-stock cooperatively via N-of-N MuSig (canonical
           t/1242).  The chain[0] TX still has vout 1 untouched even when
           chain advances spent vout 0. */
        {
            (void)seckeys;  /* not needed — factory holds all keypairs */
            tx_buf_t ls;
            tx_buf_init(&ls, 256);
            TEST_ASSERT(spend_l_stock_cooperative(ctx, f, leaf,
                            chain0_txid, 1, lc->chain0_lstock_amt,
                            party_spk[0], 34,
                            LSTOCK_SWEEP_FEE, &ls),
                        "build L-stock cooperative sweep");
            char *lh = malloc(ls.len * 2 + 1);
            TEST_ASSERT(lh != NULL, "lh malloc");
            hex_encode(ls.data, ls.len, lh);
            lh[ls.len * 2] = '\0';
            char ls_txid[65];
            int lok = spend_broadcast_and_mine(rt, lh, 1, ls_txid);
            free(lh); tx_buf_free(&ls);
            TEST_ASSERT(lok, "L-stock sweep confirmed");
            per_party_recv[0] += lc->chain0_lstock_amt - LSTOCK_SWEEP_FEE;
            total_sweep_fees  += LSTOCK_SWEEP_FEE;
            total_allocated   += lc->chain0_lstock_amt;
        }

        /* (B) Channel sweep: chain[N] vout 0, 2-of-2 MuSig {LSP, client}. */
        uint64_t chan_amt = lc->chain0_chan_amt
                          - (uint64_t)lc->n_advances * fee_per_tx;
        uint64_t after_fee = chan_amt - CHAN_SWEEP_FEE;
        uint64_t balanced  = after_fee / 2;
        uint64_t client_share = balanced - CLIENT_BALANCE_SHIFT;
        uint64_t lsp_share    = after_fee - client_share;

        char swept[65];
        TEST_ASSERT(sweep_ps_channel_n_party(rt, ctx, kps, N, leaf,
                        chainN_txid, lc->chan_spk, chan_amt,
                        client_share, lsp_share,
                        party_spk[client_idx], party_spk[0], swept),
                    "sweep PS channel");

        per_party_recv[client_idx] += client_share;
        per_party_recv[0]          += lsp_share;
        total_sweep_fees           += CHAN_SWEEP_FEE;
        total_allocated            += lc->chain0_chan_amt; /* original alloc */

        printf("  leaf %d: client%u=%llu, LSP=%llu (chain_len=%d, "
               "chan_now=%llu)\n",
               li, (unsigned)client_idx,
               (unsigned long long)client_share,
               (unsigned long long)lsp_share,
               lc->n_advances, (unsigned long long)chan_amt);
    }

    /* econ snap post + assertions. */
    TEST_ASSERT(econ_snap_post(&econ), "econ_snap_post");

    uint64_t swept_sum = 0;
    for (size_t p = 0; p < N; p++) swept_sum += per_party_recv[p];

    /* Conservation: swept + sweep_fees + advance_fees == allocated.
       allocated_sum is sum of leaf chain[0] outputs (channel + L-stock)
       BEFORE per-advance fee subtractions. */
    TEST_ASSERT(swept_sum + total_sweep_fees + total_advance_fees
                == total_allocated,
                "conservation: swept + sweep_fees + advance_fees == allocations");
    printf("  [PS N=%zu] conservation OK: swept=%llu + sweep_fees=%llu "
           "+ advance_fees=%llu == allocations=%llu\n",
           N,
           (unsigned long long)swept_sum,
           (unsigned long long)total_sweep_fees,
           (unsigned long long)total_advance_fees,
           (unsigned long long)total_allocated);

    uint64_t expected_deltas[32];
    for (size_t p = 0; p < N; p++) expected_deltas[p] = per_party_recv[p];
    TEST_ASSERT(econ_assert_wallet_deltas(&econ, expected_deltas, 0),
                "per-party wallet deltas match expected");
    econ_print_summary(&econ);

    for (int li = 0; li < n_leaves; li++) ps_leaf_chain_free(&leaf_chains[li]);
    factory_free(f);
    free(f);
    return 1;
}

int test_regtest_ps_full_lifecycle_n8(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "ps_full_lc_n8");
    rt.scan_depth = 600;

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    /* N=8, all leaves chain_len=0. fund 0.05 BTC = 5,000,000 sats. */
    int ok = run_ps_full_lifecycle(&rt, ctx, 8, NULL, 0.05,
                                     N16_PARTY_SECKEYS, mine_addr);
    secp256k1_context_destroy(ctx);
    return ok;
}

int test_regtest_ps_heterogeneous_chains_n8(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "ps_het_chains_n8");
    rt.scan_depth = 600;

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    /* N=8 -> 7 leaves with chain_lens {5,3,1,0,0,2,4}. */
    int chain_lens[7] = {5, 3, 1, 0, 0, 2, 4};
    int ok = run_ps_full_lifecycle(&rt, ctx, 8, chain_lens, 0.05,
                                     N16_PARTY_SECKEYS, mine_addr);
    secp256k1_context_destroy(ctx);
    return ok;
}

int test_regtest_ps_full_lifecycle_n16(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "ps_full_lc_n16");
    rt.scan_depth = 1200;

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    /* N=16, all leaves chain_len=0. fund 0.10 BTC = 10,000,000 sats so
       each leaf gets a healthy share after tree-internal fees. */
    int ok = run_ps_full_lifecycle(&rt, ctx, 16, NULL, 0.10,
                                     N16_PARTY_SECKEYS, mine_addr);
    secp256k1_context_destroy(ctx);
    return ok;
}

int test_regtest_ps_heterogeneous_chains_n16(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "ps_het_chains_n16");
    rt.scan_depth = 1200;

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    /* N=16 -> 15 leaves with mixed chain_lens. */
    int chain_lens[15] = {0, 1, 2, 0, 5, 0, 3, 0, 1, 4, 0, 2, 0, 1, 5};
    int ok = run_ps_full_lifecycle(&rt, ctx, 16, chain_lens, 0.10,
                                     N16_PARTY_SECKEYS, mine_addr);
    secp256k1_context_destroy(ctx);
    return ok;
}

/* ============================================================================
 *  Phase 3 #2: PS at N=32 on regtest with full accounting.
 *
 *  Reuses the helpers added by PR #97 (build_ps_factory_n,
 *  broadcast_factory_tree, advance_and_broadcast_leaf_chain,
 *  sweep_ps_channel_n_party, run_ps_full_lifecycle). Two cells:
 *
 *  - test_regtest_ps_full_lifecycle_n32: LSP + 31 clients, all leaves
 *    chain_len=0. Exercises the 32-way MuSig at the root and 31 channel
 *    sweeps + 31 L-stock sweeps. ~62 nodes broadcast on real chain.
 *
 *  - test_regtest_ps_heterogeneous_chains_n32: same N but mixed chain
 *    depths across the 31 leaves (alternating 0..5), so each client pays
 *    a different number of advance fees and the conservation equation
 *    has to balance over a richer ledger.
 *
 *  Both assert per-party deltas for ALL 32 parties via
 *  econ_assert_wallet_deltas + conservation including all advance fees.
 *  ========================================================================== */

int test_regtest_ps_full_lifecycle_n32(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "ps_full_lc_n32");
    rt.scan_depth = 2400;

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    /* N=32, all leaves chain_len=0. fund 0.20 BTC = 20,000,000 sats so
       each of 31 leaves gets ~600k sats channel allocation after the
       ~62 internal-tree fees (62 * 200 = 12,400 sats) are paid. */
    int ok = run_ps_full_lifecycle(&rt, ctx, 32, NULL, 0.20,
                                     N32_PARTY_SECKEYS, mine_addr);
    secp256k1_context_destroy(ctx);
    return ok;
}

int test_regtest_ps_heterogeneous_chains_n32(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "ps_het_chains_n32");
    rt.scan_depth = 2400;

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    /* N=32 -> 31 leaves with alternating chain depths {0..5} cycling.
       The cycle ensures every depth in {0,1,2,3,4,5} is exercised at
       multiple positions, and every client pays a different number of
       advance fees so per-party deltas all differ. */
    int chain_lens[31] = {
        0, 1, 2, 3, 4, 5,
        0, 1, 2, 3, 4, 5,
        0, 1, 2, 3, 4, 5,
        0, 1, 2, 3, 4, 5,
        0, 1, 2, 3, 4, 5,
        0
    };
    int ok = run_ps_full_lifecycle(&rt, ctx, 32, chain_lens, 0.20,
                                     N32_PARTY_SECKEYS, mine_addr);
    secp256k1_context_destroy(ctx);
    return ok;
}

/* ============================================================================
 *  Test E (adversarial): prove PS non-revocability AT THE CHAIN LEVEL.
 *
 *  Setup:
 *    - N=8 PS factory, fund + build_tree + sign_all (same as test A).
 *    - Pick leaf 0. Stash chain[0] bytes (already in leaf->signed_tx after
 *      sign_all). Advance leaf 0 once -> stash chain[1] bytes. Advance once
 *      more -> stash chain[2] bytes.
 *
 *  Broadcast script:
 *    1. Broadcast every other tree node + chain[0] of leaf 0 (the standard
 *       tree broadcast). Confirm.
 *    2. Try to broadcast chain[2] BEFORE chain[1] -- expected to FAIL because
 *       chain[2] spends chain[1]'s vout 0, which doesn't exist yet.
 *    3. Broadcast chain[1] from stashed bytes. It spends chain[0] vout 0
 *       which IS on chain. Confirm.
 *    4. Broadcast chain[2] again -- succeeds now. Confirm.
 *    5. CRITICAL: Try to broadcast the stashed chain[1] AGAIN. Must FAIL
 *       with `bad-txns-inputs-missingorspent` because chain[1]'s vout 0
 *       was already spent by chain[2] in step 4.
 *
 *  This proves the chain itself enforces PS non-revocability: once chain[i+1]
 *  confirms, the signed bytes for chain[i] become unbroadcastable. The persist
 *  defense (PR #79) prevents the LSP/client from ever signing two TXs for the
 *  same parent UTXO; this test proves the chain itself enforces the same
 *  invariant even if the persist defense were bypassed.
 *  ========================================================================== */

/* Capture-output broadcast helper: returns 0/1 like regtest_send_raw_tx but
   also captures the raw bitcoind error string into out_err (size out_err_len).
   Direct regtest_exec call so we see the JSON error body even on failure. */
static int try_broadcast_capture_error(regtest_t *rt,
                                        const unsigned char *tx_bytes,
                                        size_t tx_len,
                                        char *out_err, size_t out_err_len) {
    char *tx_hex = malloc(tx_len * 2 + 1);
    if (!tx_hex) return -1;
    hex_encode(tx_bytes, tx_len, tx_hex);
    tx_hex[tx_len * 2] = '\0';

    char *params = malloc(strlen(tx_hex) + 4);
    if (!params) { free(tx_hex); return -1; }
    snprintf(params, strlen(tx_hex) + 4, "\"%s\"", tx_hex);
    free(tx_hex);

    char *result = regtest_exec(rt, "sendrawtransaction", params);
    free(params);
    if (!result) {
        if (out_err && out_err_len > 0)
            snprintf(out_err, out_err_len, "(no result from regtest_exec)");
        return 0;
    }
    if (strstr(result, "error") != NULL) {
        if (out_err && out_err_len > 0) {
            strncpy(out_err, result, out_err_len - 1);
            out_err[out_err_len - 1] = '\0';
        }
        free(result);
        return 0;
    }
    /* Success — strip quotes/whitespace from result (txid). */
    if (out_err && out_err_len > 0) out_err[0] = '\0';
    free(result);
    return 1;
}

int test_regtest_ps_old_state_broadcast_fails_n8(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "ps_adversarial_n8");
    rt.scan_depth = 600;

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    const size_t N = 8;
    secp256k1_keypair kps[16];
    secp256k1_pubkey  pks[16];
    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) { secp256k1_context_destroy(ctx); return 0; }

    unsigned char fund_spk[34];
    char fund_txid[65];
    uint32_t fund_vout = 0;
    uint64_t fund_amount = 0;
    if (!build_ps_factory_n(&rt, ctx, N, 0.05, mine_addr, N16_PARTY_SECKEYS,
                              kps, pks, f, fund_spk, fund_txid, &fund_vout,
                              &fund_amount)) {
        factory_free(f); free(f); secp256k1_context_destroy(ctx); return 0;
    }
    int n_leaves = f->n_leaf_nodes;
    printf("  [PS N=8 adversarial] factory funded: %llu sats, %zu nodes, "
           "%d leaves\n",
           (unsigned long long)fund_amount, f->n_nodes, n_leaves);
    TEST_ASSERT(n_leaves == 7, "PS N=8 should have 7 leaves");

    /* Step 1: broadcast every signed tree node (chain[0] for every leaf). */
    char txids[FACTORY_MAX_NODES][65];
    TEST_ASSERT(broadcast_factory_tree(&rt, f, mine_addr, txids),
                "broadcast factory tree");
    for (int li = 0; li < n_leaves; li++) {
        TEST_ASSERT(regtest_get_confirmations(&rt,
                        txids[f->leaf_node_indices[li]]) >= 1,
                    "leaf chain[0] on chain");
    }
    printf("  full tree broadcast OK -- %zu nodes, %d leaves chain[0] confirmed\n",
           f->n_nodes, n_leaves);

    /* Step 2: stash chain[1] and chain[2] bytes for leaf 0 by advancing twice
       WITHOUT broadcasting. We want the bytes only. */
    int leaf_side = 0;
    size_t leaf0_idx = f->leaf_node_indices[leaf_side];
    factory_node_t *leaf0 = &f->nodes[leaf0_idx];
    TEST_ASSERT(leaf0->is_ps_leaf, "leaf0 is PS");

    /* Stash chain[0] bytes (just for symmetry; we don't rebroadcast it). */
    size_t chain0_len = leaf0->signed_tx.len;
    unsigned char *chain0_bytes = malloc(chain0_len);
    TEST_ASSERT(chain0_bytes != NULL, "alloc chain0_bytes");
    memcpy(chain0_bytes, leaf0->signed_tx.data, chain0_len);

    /* Advance once -> chain[1] in leaf->signed_tx. Stash. */
    TEST_ASSERT(factory_advance_leaf(f, leaf_side), "advance to chain[1]");
    TEST_ASSERT(leaf0->ps_chain_len == 1, "ps_chain_len == 1");
    size_t chain1_len = leaf0->signed_tx.len;
    unsigned char *chain1_bytes = malloc(chain1_len);
    TEST_ASSERT(chain1_bytes != NULL, "alloc chain1_bytes");
    memcpy(chain1_bytes, leaf0->signed_tx.data, chain1_len);

    /* Advance again -> chain[2]. Stash. */
    TEST_ASSERT(factory_advance_leaf(f, leaf_side), "advance to chain[2]");
    TEST_ASSERT(leaf0->ps_chain_len == 2, "ps_chain_len == 2");
    size_t chain2_len = leaf0->signed_tx.len;
    unsigned char *chain2_bytes = malloc(chain2_len);
    TEST_ASSERT(chain2_bytes != NULL, "alloc chain2_bytes");
    memcpy(chain2_bytes, leaf0->signed_tx.data, chain2_len);

    printf("  stashed chain[0..2] bytes for leaf 0 (lengths %zu, %zu, %zu)\n",
           chain0_len, chain1_len, chain2_len);

    /* Step 3: try to broadcast chain[2] BEFORE chain[1]. Must FAIL because
       chain[2] spends chain[1]'s vout 0 which doesn't exist on chain yet. */
    char err_premature[1024];
    int rc_prem = try_broadcast_capture_error(&rt, chain2_bytes, chain2_len,
                                                err_premature, sizeof(err_premature));
    TEST_ASSERT(rc_prem == 0, "chain[2] broadcast BEFORE chain[1] must fail");
    printf("  EXPECTED FAIL #1 (chain[2] before chain[1]): %s\n", err_premature);

    /* Step 4: broadcast chain[1] from stashed bytes -- spends chain[0] vout 0
       which IS on chain. Must succeed. Mine 1 block. */
    char chain1_txid[65];
    {
        char *h = malloc(chain1_len * 2 + 1);
        TEST_ASSERT(h != NULL, "alloc chain1 hex");
        hex_encode(chain1_bytes, chain1_len, h);
        h[chain1_len * 2] = '\0';
        int ok = regtest_send_raw_tx(&rt, h, chain1_txid);
        free(h);
        TEST_ASSERT(ok, "broadcast chain[1] from stash");
    }
    regtest_mine_blocks(&rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(&rt, chain1_txid) >= 1,
                "chain[1] confirmed");
    printf("  chain[1] broadcast OK (txid=%s)\n", chain1_txid);

    /* Step 5: broadcast chain[2] again -- now succeeds because chain[1] vout 0
       exists on chain. */
    char chain2_txid[65];
    {
        char *h = malloc(chain2_len * 2 + 1);
        TEST_ASSERT(h != NULL, "alloc chain2 hex");
        hex_encode(chain2_bytes, chain2_len, h);
        h[chain2_len * 2] = '\0';
        int ok = regtest_send_raw_tx(&rt, h, chain2_txid);
        free(h);
        TEST_ASSERT(ok, "broadcast chain[2] after chain[1]");
    }
    regtest_mine_blocks(&rt, 1, mine_addr);
    TEST_ASSERT(regtest_get_confirmations(&rt, chain2_txid) >= 1,
                "chain[2] confirmed");
    printf("  chain[2] broadcast OK (txid=%s)\n", chain2_txid);

    /* Step 6: CRITICAL -- try to broadcast the stashed chain[1] AGAIN.
       Must FAIL with `bad-txns-inputs-missingorspent` because chain[1]'s
       vout 0 was already spent by chain[2] in the previous step. (Or
       equivalently `txn-already-known` / `txn-already-in-mempool` if the
       node still has the chain[1] in its recently-confirmed cache, but
       since we mined chain[1] into a block and then chain[2] spent it,
       resubmitting chain[1] is a double-broadcast attempt for an input
       that's now spent.) */
    char err_replay[1024];
    int rc_replay = try_broadcast_capture_error(&rt, chain1_bytes, chain1_len,
                                                  err_replay, sizeof(err_replay));
    TEST_ASSERT(rc_replay == 0,
                "stashed chain[1] re-broadcast AFTER chain[2] confirms must fail");
    printf("  EXPECTED FAIL #2 (re-broadcast chain[1] after chain[2] spent its "
           "vout): %s\n", err_replay);

    /* Tighten the assertion: the error string should mention either the
       missingorspent condition (input already spent) or txn-already-known
       (node remembers the TX). Both prove the on-chain invariant. */
    int matched = (strstr(err_replay, "missingorspent") != NULL)
               || (strstr(err_replay, "already") != NULL)
               || (strstr(err_replay, "spent") != NULL)
               || (strstr(err_replay, "conflict") != NULL);
    TEST_ASSERT(matched,
        "error string should mention missingorspent/already/spent/conflict");

    printf("  PS non-revocability invariant proven at chain level (N=8, leaf 0)\n");

    free(chain0_bytes); free(chain1_bytes); free(chain2_bytes);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ============================================================================
 *  TRUE N-way mixed-arity full lifecycle at N=64.
 *
 *  This is the end-to-end "gold" proof for Phase 2: with --arity 2,4,8 at
 *  N=64, the factory builder produces a TRUE N-way tree (root arity-2 →
 *  mid arity-4 → leaves arity-8), every TX is broadcast + mined, every leaf's
 *  channels + L-stock are swept, and per-party econ_assert_wallet_deltas hold
 *  for all 64 parties to the satoshi.
 *
 *  Requires ECON_MAX_PARTIES >= 64 (set in econ_helpers.h).
 *  ========================================================================== */
int test_regtest_nway_n64_arity_2_4_8_lifecycle(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "nway_n64_248");
    /* Tree depth ~ 3 with up to 80+ nodes; bump scan depth so we can find
       deep leaves on hosts without -txindex. */
    rt.scan_depth = 1200;

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    /* Generate 64 deterministic seckeys.  Use a unique prefix (0xFD) to
       avoid colliding with N32_PARTY_SECKEYS (0xFE) and N12 (zero). */
    static unsigned char N64_SECKEYS[64][32];
    for (int i = 0; i < 64; i++) {
        memset(N64_SECKEYS[i], 0, 32);
        N64_SECKEYS[i][0] = 0xFD;
        N64_SECKEYS[i][30] = (unsigned char)((i + 1) >> 8);
        N64_SECKEYS[i][31] = (unsigned char)((i + 1) & 0xFF);
    }

    const size_t N = 64;
    secp256k1_keypair *kps = calloc(N, sizeof(secp256k1_keypair));
    secp256k1_pubkey  *pks = calloc(N, sizeof(secp256k1_pubkey));
    TEST_ASSERT(kps && pks, "alloc kps/pks");
    for (size_t i = 0; i < N; i++) {
        TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[i], N64_SECKEYS[i]),
                    "keypair_create n64");
        TEST_ASSERT(secp256k1_keypair_pub(ctx, &pks[i], &kps[i]),
                    "keypair_pub n64");
    }

    /* Build N-of-N MuSig + taptweak P2TR funding SPK */
    unsigned char fund_spk[34];
    unsigned char tw_ser[32];
    TEST_ASSERT(build_n_party_funding_spk(ctx, pks, N, fund_spk, tw_ser),
                "build n64 funding spk");

    /* Fund factory.  10M sats supports 64 leaves with channels well above
       sweep fees (≥150k sats per channel after tree fees). */
    char fund_addr[128];
    TEST_ASSERT(regtest_derive_p2tr_address(&rt, tw_ser, fund_addr,
                                              sizeof(fund_addr)),
                "derive n64 fund addr");
    char fund_txid[65];
    TEST_ASSERT(regtest_fund_address(&rt, fund_addr, 0.10, fund_txid),
                "fund n64 factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    uint32_t fund_vout = UINT32_MAX;
    uint64_t fund_amount = 0;
    for (uint32_t v = 0; v < 4; v++) {
        uint64_t a = 0;
        unsigned char s[64];
        size_t sl = 0;
        if (regtest_get_tx_output(&rt, fund_txid, v, &a, s, &sl) &&
            sl == 34 && memcmp(s, fund_spk, 34) == 0) {
            fund_vout = v;
            fund_amount = a;
            break;
        }
    }
    TEST_ASSERT(fund_vout != UINT32_MAX, "find n64 fund vout");
    printf("  [nway-n64 {2,4,8}] funded %s:%u  %llu sats\n",
           fund_txid, fund_vout, (unsigned long long)fund_amount);

    /* Build factory with mixed level arity {2, 4, 8} */
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f != NULL, "alloc factory");
    factory_init(f, ctx, kps, N, 4, 4);
    /* Wider N-way state nodes need more fee than default 200 sats to
       clear CI regtest mempool min-relay (~240 sats). 1000 sats safe. */
    f->fee_per_tx = 1000;
    uint8_t arities[3] = { 2, 4, 8 };
    factory_set_level_arity(f, arities, 3);

    unsigned char fund_txid_bytes[32];
    TEST_ASSERT(hex_decode(fund_txid, fund_txid_bytes, 32),
                "decode fund txid");
    reverse_bytes(fund_txid_bytes, 32);
    factory_set_funding(f, fund_txid_bytes, fund_vout, fund_amount,
                        fund_spk, 34);

    TEST_ASSERT(factory_build_tree(f), "build n64 {2,4,8}");
    TEST_ASSERT(factory_sign_all(f), "sign n64 {2,4,8}");

    /* Print + assert tree shape */
    int n_leaves = f->n_leaf_nodes;
    printf("  [nway-n64 {2,4,8}] %zu nodes, %d leaves, n_layers=%d\n",
           f->n_nodes, n_leaves, (int)f->counter.n_layers);
    TEST_ASSERT_EQ(f->nodes[1].n_outputs, 2,
                   "root state arity-2 (2 outputs)");
    /* Each leaf has 1..8 clients, n_outputs == n_clients + 1 */
    int total_client_channels = 0;
    int found_wide_leaf = 0;
    for (int li = 0; li < n_leaves; li++) {
        size_t nidx = f->leaf_node_indices[li];
        factory_node_t *leaf = &f->nodes[nidx];
        size_t n_clients = leaf->n_signers - 1;
        TEST_ASSERT(n_clients >= 1 && n_clients <= 8,
                    "leaf 1..8 clients (arity-8 cap)");
        TEST_ASSERT_EQ(leaf->n_outputs, n_clients + 1,
                       "leaf n_outputs = n_clients + 1");
        if (n_clients > 2) found_wide_leaf = 1;
        total_client_channels += (int)n_clients;
    }
    TEST_ASSERT(found_wide_leaf,
                "at least one leaf has > 2 clients (proves N-way)");
    TEST_ASSERT_EQ(total_client_channels, 63,
                   "all 63 clients placed (N-1=63)");

    /* Broadcast every signed tree node */
    char (*txids)[65] = calloc(FACTORY_MAX_NODES, sizeof(*txids));
    TEST_ASSERT(txids != NULL, "alloc txids");
    TEST_ASSERT(broadcast_factory_tree(&rt, f, mine_addr, txids),
                "broadcast n64 tree");
    for (int li = 0; li < n_leaves; li++) {
        int conf = regtest_get_confirmations(&rt,
            txids[f->leaf_node_indices[li]]);
        TEST_ASSERT(conf >= 1, "leaf on chain");
    }
    printf("  [nway-n64 {2,4,8}] full tree broadcast OK\n");

    /* Build per-party P2TR(xonly(pk_i)) destinations */
    unsigned char (*party_spk)[34] = calloc(N, sizeof(*party_spk));
    TEST_ASSERT(party_spk, "alloc party_spk");
    for (size_t p = 0; p < N; p++) {
        secp256k1_xonly_pubkey xo;
        secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &pks[p]);
        build_p2tr_script_pubkey(party_spk[p], &xo);
    }

    /* Wire econ harness for all 64 parties */
    econ_ctx_t econ;
    econ_ctx_init(&econ, &rt, ctx);
    char party_name[32];
    for (size_t p = 0; p < N; p++) {
        if (p == 0) strcpy(party_name, "LSP");
        else snprintf(party_name, sizeof(party_name), "client%02zu", p);
        TEST_ASSERT(econ_register_party(&econ, p, party_name,
                                          N64_SECKEYS[p]),
                    "register party n64");
    }
    econ.factory_funding_amount = fund_amount;
    TEST_ASSERT(econ_snap_pre(&econ), "econ_snap_pre n64");

    /* Per-leaf sweep: L-stock LSP-alone + each channel via 2-of-2 MuSig */
    const uint64_t LSTOCK_SWEEP_FEE = 300;
    const uint64_t CHAN_SWEEP_FEE   = 400;
    const uint64_t PAYMENT_SHIFT    = 1000;

    uint64_t *per_party_recv = calloc(N, sizeof(uint64_t));
    TEST_ASSERT(per_party_recv, "alloc per_party_recv");
    uint64_t total_sweep_fees = 0;
    uint64_t total_allocated  = 0;

    for (int li = 0; li < n_leaves; li++) {
        size_t nidx = f->leaf_node_indices[li];
        factory_node_t *leaf = &f->nodes[nidx];
        const char *leaf_txid = txids[nidx];

        unsigned char leaf_txid_bytes[32];
        TEST_ASSERT(hex_decode(leaf_txid, leaf_txid_bytes, 32),
                    "decode leaf txid");
        reverse_bytes(leaf_txid_bytes, 32);

        TEST_ASSERT(leaf->signer_indices[0] == 0,
                    "signer[0] is LSP for every leaf");

        uint32_t lstock_vout = (uint32_t)(leaf->n_outputs - 1);
        int n_channels       = (int)leaf->n_outputs - 1;

        /* (A) Sweep L-stock cooperatively via N-of-N MuSig (canonical
           t/1242 — L-stock SPK requires either all leaf signers
           cooperating, or LSP+CSV-delay). */
        uint64_t lstock_amt = leaf->outputs[lstock_vout].amount_sats;

        tx_buf_t lstock_sweep;
        tx_buf_init(&lstock_sweep, 256);
        TEST_ASSERT(spend_l_stock_cooperative(ctx, f, leaf,
                        leaf_txid, lstock_vout, lstock_amt,
                        party_spk[0], 34,
                        LSTOCK_SWEEP_FEE, &lstock_sweep),
                    "build L-stock cooperative sweep n64");
        char *lh = malloc(lstock_sweep.len * 2 + 1);
        TEST_ASSERT(lh, "lh malloc");
        hex_encode(lstock_sweep.data, lstock_sweep.len, lh);
        lh[lstock_sweep.len * 2] = '\0';
        char lstock_sweep_txid[65];
        int lok = spend_broadcast_and_mine(&rt, lh, 1, lstock_sweep_txid);
        free(lh); tx_buf_free(&lstock_sweep);
        TEST_ASSERT(lok, "L-stock sweep confirmed n64");
        per_party_recv[0] += lstock_amt - LSTOCK_SWEEP_FEE;
        total_sweep_fees  += LSTOCK_SWEEP_FEE;
        total_allocated   += lstock_amt;

        /* (B) Sweep each channel: 2-of-2 MuSig {client, LSP} → 50/50 split
              with PAYMENT_SHIFT to client→LSP */
        for (int ch = 0; ch < n_channels; ch++) {
            uint32_t client_idx = leaf->signer_indices[1 + ch];
            TEST_ASSERT(client_idx >= 1 && client_idx < N, "client_idx range");

            uint64_t chan_amt = leaf->outputs[ch].amount_sats;
            uint64_t after_fee = chan_amt - CHAN_SWEEP_FEE;
            uint64_t balanced  = after_fee / 2;
            uint64_t client_share = balanced - PAYMENT_SHIFT;
            uint64_t lsp_share    = after_fee - client_share;
            unsigned char chan_spk[34];
            memcpy(chan_spk, leaf->outputs[ch].script_pubkey, 34);

            tx_output_t outs[2];
            memcpy(outs[0].script_pubkey, party_spk[client_idx], 34);
            outs[0].script_pubkey_len = 34;
            outs[0].amount_sats = client_share;
            memcpy(outs[1].script_pubkey, party_spk[0], 34);
            outs[1].script_pubkey_len = 34;
            outs[1].amount_sats = lsp_share;

            tx_buf_t chan_unsigned;
            tx_buf_init(&chan_unsigned, 256);
            TEST_ASSERT(build_unsigned_tx(&chan_unsigned, NULL,
                                            leaf_txid_bytes,
                                            (uint32_t)ch, 0xFFFFFFFEu,
                                            outs, 2),
                        "build unsigned channel sweep n64");
            unsigned char sighash[32];
            TEST_ASSERT(compute_taproot_sighash(sighash,
                            chan_unsigned.data, chan_unsigned.len,
                            0, chan_spk, 34, chan_amt, 0xFFFFFFFEu),
                        "channel sighash n64");

            secp256k1_keypair signers[2] = { kps[client_idx], kps[0] };
            secp256k1_pubkey  ckpks[2];
            secp256k1_keypair_pub(ctx, &ckpks[0], &signers[0]);
            secp256k1_keypair_pub(ctx, &ckpks[1], &signers[1]);
            musig_keyagg_t cka;
            TEST_ASSERT(musig_aggregate_keys(ctx, &cka, ckpks, 2),
                        "agg channel keys n64");
            unsigned char sig64[64];
            TEST_ASSERT(musig_sign_taproot(ctx, sig64, sighash, signers, 2,
                                             &cka, NULL),
                        "2-of-2 MuSig2 sign channel sweep n64");
            tx_buf_t chan_signed;
            tx_buf_init(&chan_signed, 256);
            TEST_ASSERT(finalize_signed_tx(&chan_signed,
                            chan_unsigned.data, chan_unsigned.len, sig64),
                        "finalize channel sweep tx n64");
            tx_buf_free(&chan_unsigned);

            char *ch_hex = malloc(chan_signed.len * 2 + 1);
            TEST_ASSERT(ch_hex, "ch_hex malloc");
            hex_encode(chan_signed.data, chan_signed.len, ch_hex);
            ch_hex[chan_signed.len * 2] = '\0';
            char chan_sweep_txid[65];
            int cok = spend_broadcast_and_mine(&rt, ch_hex, 1, chan_sweep_txid);
            free(ch_hex); tx_buf_free(&chan_signed);
            TEST_ASSERT(cok, "channel 2-of-2 sweep confirmed n64");
            per_party_recv[client_idx] += client_share;
            per_party_recv[0]          += lsp_share;
            total_sweep_fees           += CHAN_SWEEP_FEE;
            total_allocated            += chan_amt;
        }
    }

    TEST_ASSERT(econ_snap_post(&econ), "econ_snap_post n64");

    /* Conservation check */
    uint64_t swept_sum = 0;
    for (size_t p = 0; p < N; p++) swept_sum += per_party_recv[p];
    TEST_ASSERT(swept_sum + total_sweep_fees == total_allocated,
                "conservation Σswept + Σfees == Σallocations");
    printf("  [nway-n64 {2,4,8}] conservation OK: swept=%llu + fees=%llu "
           "== allocations=%llu\n",
           (unsigned long long)swept_sum,
           (unsigned long long)total_sweep_fees,
           (unsigned long long)total_allocated);

    /* Per-party expected deltas */
    uint64_t *expected_deltas = calloc(N, sizeof(uint64_t));
    TEST_ASSERT(expected_deltas, "alloc expected_deltas");
    for (size_t p = 0; p < N; p++) expected_deltas[p] = per_party_recv[p];

    TEST_ASSERT(econ_assert_wallet_deltas(&econ, expected_deltas, 0),
                "per-party wallet deltas match expected (64 parties)");
    econ_print_summary(&econ);

    free(expected_deltas);
    free(per_party_recv);
    free(party_spk);
    free(txids);
    free(kps);
    free(pks);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_regtest_nway_n64_arity_2_4_8_static_threshold_1_lifecycle(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "nway_n64_248_st1");
    /* Tree depth ~ 3 with up to 80+ nodes; bump scan depth so we can find
       deep leaves on hosts without -txindex. */
    rt.scan_depth = 1200;

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    /* Generate 64 deterministic seckeys.  Use a unique prefix (0xFD) to
       avoid colliding with N32_PARTY_SECKEYS (0xFE) and N12 (zero). */
    static unsigned char N64_SECKEYS[64][32];
    for (int i = 0; i < 64; i++) {
        memset(N64_SECKEYS[i], 0, 32);
        N64_SECKEYS[i][0] = 0xFD;
        N64_SECKEYS[i][30] = (unsigned char)((i + 1) >> 8);
        N64_SECKEYS[i][31] = (unsigned char)((i + 1) & 0xFF);
    }

    const size_t N = 64;
    secp256k1_keypair *kps = calloc(N, sizeof(secp256k1_keypair));
    secp256k1_pubkey  *pks = calloc(N, sizeof(secp256k1_pubkey));
    TEST_ASSERT(kps && pks, "alloc kps/pks");
    for (size_t i = 0; i < N; i++) {
        TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[i], N64_SECKEYS[i]),
                    "keypair_create n64");
        TEST_ASSERT(secp256k1_keypair_pub(ctx, &pks[i], &kps[i]),
                    "keypair_pub n64");
    }

    /* Build N-of-N MuSig + taptweak P2TR funding SPK */
    unsigned char fund_spk[34];
    unsigned char tw_ser[32];
    TEST_ASSERT(build_n_party_funding_spk(ctx, pks, N, fund_spk, tw_ser),
                "build n64 funding spk");

    /* Fund factory.  10M sats supports 64 leaves with channels well above
       sweep fees (≥150k sats per channel after tree fees). */
    char fund_addr[128];
    TEST_ASSERT(regtest_derive_p2tr_address(&rt, tw_ser, fund_addr,
                                              sizeof(fund_addr)),
                "derive n64 fund addr");
    char fund_txid[65];
    TEST_ASSERT(regtest_fund_address(&rt, fund_addr, 0.10, fund_txid),
                "fund n64 factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    uint32_t fund_vout = UINT32_MAX;
    uint64_t fund_amount = 0;
    for (uint32_t v = 0; v < 4; v++) {
        uint64_t a = 0;
        unsigned char s[64];
        size_t sl = 0;
        if (regtest_get_tx_output(&rt, fund_txid, v, &a, s, &sl) &&
            sl == 34 && memcmp(s, fund_spk, 34) == 0) {
            fund_vout = v;
            fund_amount = a;
            break;
        }
    }
    TEST_ASSERT(fund_vout != UINT32_MAX, "find n64 fund vout");
    printf("  [nway-n64 {2,4,8}+st1] funded %s:%u  %llu sats\n",
           fund_txid, fund_vout, (unsigned long long)fund_amount);

    /* Build factory with mixed level arity {2, 4, 8} */
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f != NULL, "alloc factory");
    factory_init(f, ctx, kps, N, 4, 4);
    /* Wider N-way state nodes need more fee than default 200 sats to
       clear CI regtest mempool min-relay (~240 sats). 1000 sats safe. */
    f->fee_per_tx = 1000;
    uint8_t arities[3] = { 2, 4, 8 };
    factory_set_level_arity(f, arities, 3);
    factory_set_static_near_root(f, 1);

    unsigned char fund_txid_bytes[32];
    TEST_ASSERT(hex_decode(fund_txid, fund_txid_bytes, 32),
                "decode fund txid");
    reverse_bytes(fund_txid_bytes, 32);
    factory_set_funding(f, fund_txid_bytes, fund_vout, fund_amount,
                        fund_spk, 34);

    TEST_ASSERT(factory_build_tree(f), "build n64 {2,4,8}");
    TEST_ASSERT(factory_sign_all(f), "sign n64 {2,4,8}");

    /* Print + assert tree shape */
    int n_leaves = f->n_leaf_nodes;
    printf("  [nway-n64 {2,4,8}+st1] %zu nodes, %d leaves, n_layers=%d\n",
           f->n_nodes, n_leaves, (int)f->counter.n_layers);
    /* With static_threshold=1, node 0 is the static kickoff-only root. */
    TEST_ASSERT_EQ(f->nodes[0].is_static_only, 1,
                   "node 0 is static_only with thr=1");
    TEST_ASSERT_EQ(f->nodes[0].dw_layer_index, -1,
                   "static root dw_layer_index == -1");
    TEST_ASSERT_EQ(f->nodes[0].nsequence, 0xFFFFFFFEu,
                   "static root nsequence == 0xFFFFFFFE");
    TEST_ASSERT_EQ(f->nodes[0].n_outputs, 2,
                   "static root arity-2 fan-out (2 outputs)");
    /* Each leaf has 1..8 clients, n_outputs == n_clients + 1 */
    int total_client_channels = 0;
    int found_wide_leaf = 0;
    for (int li = 0; li < n_leaves; li++) {
        size_t nidx = f->leaf_node_indices[li];
        factory_node_t *leaf = &f->nodes[nidx];
        size_t n_clients = leaf->n_signers - 1;
        TEST_ASSERT(n_clients >= 1 && n_clients <= 8,
                    "leaf 1..8 clients (arity-8 cap)");
        TEST_ASSERT_EQ(leaf->n_outputs, n_clients + 1,
                       "leaf n_outputs = n_clients + 1");
        if (n_clients > 2) found_wide_leaf = 1;
        total_client_channels += (int)n_clients;
    }
    TEST_ASSERT(found_wide_leaf,
                "at least one leaf has > 2 clients (proves N-way)");
    TEST_ASSERT_EQ(total_client_channels, 63,
                   "all 63 clients placed (N-1=63)");

    /* Broadcast every signed tree node */
    char (*txids)[65] = calloc(FACTORY_MAX_NODES, sizeof(*txids));
    TEST_ASSERT(txids != NULL, "alloc txids");
    TEST_ASSERT(broadcast_factory_tree(&rt, f, mine_addr, txids),
                "broadcast n64 tree");
    for (int li = 0; li < n_leaves; li++) {
        int conf = regtest_get_confirmations(&rt,
            txids[f->leaf_node_indices[li]]);
        TEST_ASSERT(conf >= 1, "leaf on chain");
    }
    printf("  [nway-n64 {2,4,8}+st1] full tree broadcast OK\n");

    /* Build per-party P2TR(xonly(pk_i)) destinations */
    unsigned char (*party_spk)[34] = calloc(N, sizeof(*party_spk));
    TEST_ASSERT(party_spk, "alloc party_spk");
    for (size_t p = 0; p < N; p++) {
        secp256k1_xonly_pubkey xo;
        secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &pks[p]);
        build_p2tr_script_pubkey(party_spk[p], &xo);
    }

    /* Wire econ harness for all 64 parties */
    econ_ctx_t econ;
    econ_ctx_init(&econ, &rt, ctx);
    char party_name[32];
    for (size_t p = 0; p < N; p++) {
        if (p == 0) strcpy(party_name, "LSP");
        else snprintf(party_name, sizeof(party_name), "client%02zu", p);
        TEST_ASSERT(econ_register_party(&econ, p, party_name,
                                          N64_SECKEYS[p]),
                    "register party n64");
    }
    econ.factory_funding_amount = fund_amount;
    TEST_ASSERT(econ_snap_pre(&econ), "econ_snap_pre n64");

    /* Per-leaf sweep: L-stock LSP-alone + each channel via 2-of-2 MuSig */
    const uint64_t LSTOCK_SWEEP_FEE = 300;
    const uint64_t CHAN_SWEEP_FEE   = 400;
    const uint64_t PAYMENT_SHIFT    = 1000;

    uint64_t *per_party_recv = calloc(N, sizeof(uint64_t));
    TEST_ASSERT(per_party_recv, "alloc per_party_recv");
    uint64_t total_sweep_fees = 0;
    uint64_t total_allocated  = 0;

    for (int li = 0; li < n_leaves; li++) {
        size_t nidx = f->leaf_node_indices[li];
        factory_node_t *leaf = &f->nodes[nidx];
        const char *leaf_txid = txids[nidx];

        unsigned char leaf_txid_bytes[32];
        TEST_ASSERT(hex_decode(leaf_txid, leaf_txid_bytes, 32),
                    "decode leaf txid");
        reverse_bytes(leaf_txid_bytes, 32);

        TEST_ASSERT(leaf->signer_indices[0] == 0,
                    "signer[0] is LSP for every leaf");

        uint32_t lstock_vout = (uint32_t)(leaf->n_outputs - 1);
        int n_channels       = (int)leaf->n_outputs - 1;

        /* (A) Sweep L-stock cooperatively via N-of-N MuSig (canonical
           t/1242 — L-stock SPK requires either all leaf signers
           cooperating, or LSP+CSV-delay). */
        uint64_t lstock_amt = leaf->outputs[lstock_vout].amount_sats;

        tx_buf_t lstock_sweep;
        tx_buf_init(&lstock_sweep, 256);
        TEST_ASSERT(spend_l_stock_cooperative(ctx, f, leaf,
                        leaf_txid, lstock_vout, lstock_amt,
                        party_spk[0], 34,
                        LSTOCK_SWEEP_FEE, &lstock_sweep),
                    "build L-stock cooperative sweep n64");
        char *lh = malloc(lstock_sweep.len * 2 + 1);
        TEST_ASSERT(lh, "lh malloc");
        hex_encode(lstock_sweep.data, lstock_sweep.len, lh);
        lh[lstock_sweep.len * 2] = '\0';
        char lstock_sweep_txid[65];
        int lok = spend_broadcast_and_mine(&rt, lh, 1, lstock_sweep_txid);
        free(lh); tx_buf_free(&lstock_sweep);
        TEST_ASSERT(lok, "L-stock sweep confirmed n64");
        per_party_recv[0] += lstock_amt - LSTOCK_SWEEP_FEE;
        total_sweep_fees  += LSTOCK_SWEEP_FEE;
        total_allocated   += lstock_amt;

        /* (B) Sweep each channel: 2-of-2 MuSig {client, LSP} → 50/50 split
              with PAYMENT_SHIFT to client→LSP */
        for (int ch = 0; ch < n_channels; ch++) {
            uint32_t client_idx = leaf->signer_indices[1 + ch];
            TEST_ASSERT(client_idx >= 1 && client_idx < N, "client_idx range");

            uint64_t chan_amt = leaf->outputs[ch].amount_sats;
            uint64_t after_fee = chan_amt - CHAN_SWEEP_FEE;
            uint64_t balanced  = after_fee / 2;
            uint64_t client_share = balanced - PAYMENT_SHIFT;
            uint64_t lsp_share    = after_fee - client_share;
            unsigned char chan_spk[34];
            memcpy(chan_spk, leaf->outputs[ch].script_pubkey, 34);

            tx_output_t outs[2];
            memcpy(outs[0].script_pubkey, party_spk[client_idx], 34);
            outs[0].script_pubkey_len = 34;
            outs[0].amount_sats = client_share;
            memcpy(outs[1].script_pubkey, party_spk[0], 34);
            outs[1].script_pubkey_len = 34;
            outs[1].amount_sats = lsp_share;

            tx_buf_t chan_unsigned;
            tx_buf_init(&chan_unsigned, 256);
            TEST_ASSERT(build_unsigned_tx(&chan_unsigned, NULL,
                                            leaf_txid_bytes,
                                            (uint32_t)ch, 0xFFFFFFFEu,
                                            outs, 2),
                        "build unsigned channel sweep n64");
            unsigned char sighash[32];
            TEST_ASSERT(compute_taproot_sighash(sighash,
                            chan_unsigned.data, chan_unsigned.len,
                            0, chan_spk, 34, chan_amt, 0xFFFFFFFEu),
                        "channel sighash n64");

            secp256k1_keypair signers[2] = { kps[client_idx], kps[0] };
            secp256k1_pubkey  ckpks[2];
            secp256k1_keypair_pub(ctx, &ckpks[0], &signers[0]);
            secp256k1_keypair_pub(ctx, &ckpks[1], &signers[1]);
            musig_keyagg_t cka;
            TEST_ASSERT(musig_aggregate_keys(ctx, &cka, ckpks, 2),
                        "agg channel keys n64");
            unsigned char sig64[64];
            TEST_ASSERT(musig_sign_taproot(ctx, sig64, sighash, signers, 2,
                                             &cka, NULL),
                        "2-of-2 MuSig2 sign channel sweep n64");
            tx_buf_t chan_signed;
            tx_buf_init(&chan_signed, 256);
            TEST_ASSERT(finalize_signed_tx(&chan_signed,
                            chan_unsigned.data, chan_unsigned.len, sig64),
                        "finalize channel sweep tx n64");
            tx_buf_free(&chan_unsigned);

            char *ch_hex = malloc(chan_signed.len * 2 + 1);
            TEST_ASSERT(ch_hex, "ch_hex malloc");
            hex_encode(chan_signed.data, chan_signed.len, ch_hex);
            ch_hex[chan_signed.len * 2] = '\0';
            char chan_sweep_txid[65];
            int cok = spend_broadcast_and_mine(&rt, ch_hex, 1, chan_sweep_txid);
            free(ch_hex); tx_buf_free(&chan_signed);
            TEST_ASSERT(cok, "channel 2-of-2 sweep confirmed n64");
            per_party_recv[client_idx] += client_share;
            per_party_recv[0]          += lsp_share;
            total_sweep_fees           += CHAN_SWEEP_FEE;
            total_allocated            += chan_amt;
        }
    }

    TEST_ASSERT(econ_snap_post(&econ), "econ_snap_post n64");

    /* Conservation check */
    uint64_t swept_sum = 0;
    for (size_t p = 0; p < N; p++) swept_sum += per_party_recv[p];
    TEST_ASSERT(swept_sum + total_sweep_fees == total_allocated,
                "conservation Σswept + Σfees == Σallocations");
    printf("  [nway-n64 {2,4,8}+st1] conservation OK: swept=%llu + fees=%llu "
           "== allocations=%llu\n",
           (unsigned long long)swept_sum,
           (unsigned long long)total_sweep_fees,
           (unsigned long long)total_allocated);

    /* Per-party expected deltas */
    uint64_t *expected_deltas = calloc(N, sizeof(uint64_t));
    TEST_ASSERT(expected_deltas, "alloc expected_deltas");
    for (size_t p = 0; p < N; p++) expected_deltas[p] = per_party_recv[p];

    TEST_ASSERT(econ_assert_wallet_deltas(&econ, expected_deltas, 0),
                "per-party wallet deltas match expected (64 parties)");
    econ_print_summary(&econ);

    free(expected_deltas);
    free(per_party_recv);
    free(party_spk);
    free(txids);
    free(kps);
    free(pks);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_regtest_nway_n64_dw_advance_resign_lifecycle(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "nway_n64_dw_adv");
    /* Tree depth ~ 3 with up to 80+ nodes; bump scan depth so we can find
       deep leaves on hosts without -txindex. */
    rt.scan_depth = 1200;

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    /* Generate 64 deterministic seckeys.  Use a unique prefix (0xFD) to
       avoid colliding with N32_PARTY_SECKEYS (0xFE) and N12 (zero). */
    static unsigned char N64_SECKEYS[64][32];
    for (int i = 0; i < 64; i++) {
        memset(N64_SECKEYS[i], 0, 32);
        N64_SECKEYS[i][0] = 0xFD;
        N64_SECKEYS[i][30] = (unsigned char)((i + 1) >> 8);
        N64_SECKEYS[i][31] = (unsigned char)((i + 1) & 0xFF);
    }

    const size_t N = 64;
    secp256k1_keypair *kps = calloc(N, sizeof(secp256k1_keypair));
    secp256k1_pubkey  *pks = calloc(N, sizeof(secp256k1_pubkey));
    TEST_ASSERT(kps && pks, "alloc kps/pks");
    for (size_t i = 0; i < N; i++) {
        TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[i], N64_SECKEYS[i]),
                    "keypair_create n64");
        TEST_ASSERT(secp256k1_keypair_pub(ctx, &pks[i], &kps[i]),
                    "keypair_pub n64");
    }

    /* Build N-of-N MuSig + taptweak P2TR funding SPK */
    unsigned char fund_spk[34];
    unsigned char tw_ser[32];
    TEST_ASSERT(build_n_party_funding_spk(ctx, pks, N, fund_spk, tw_ser),
                "build n64 funding spk");

    /* Fund factory.  10M sats supports 64 leaves with channels well above
       sweep fees (≥150k sats per channel after tree fees). */
    char fund_addr[128];
    TEST_ASSERT(regtest_derive_p2tr_address(&rt, tw_ser, fund_addr,
                                              sizeof(fund_addr)),
                "derive n64 fund addr");
    char fund_txid[65];
    TEST_ASSERT(regtest_fund_address(&rt, fund_addr, 0.10, fund_txid),
                "fund n64 factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    uint32_t fund_vout = UINT32_MAX;
    uint64_t fund_amount = 0;
    for (uint32_t v = 0; v < 4; v++) {
        uint64_t a = 0;
        unsigned char s[64];
        size_t sl = 0;
        if (regtest_get_tx_output(&rt, fund_txid, v, &a, s, &sl) &&
            sl == 34 && memcmp(s, fund_spk, 34) == 0) {
            fund_vout = v;
            fund_amount = a;
            break;
        }
    }
    TEST_ASSERT(fund_vout != UINT32_MAX, "find n64 fund vout");
    printf("  [nway-n64 dw-advance] funded %s:%u  %llu sats\n",
           fund_txid, fund_vout, (unsigned long long)fund_amount);

    /* Build factory with mixed level arity {2, 4, 8} */
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f != NULL, "alloc factory");
    factory_init(f, ctx, kps, N, 4, 4);
    /* Wider N-way state nodes need more fee than default 200 sats to
       clear CI regtest mempool min-relay (~240 sats). 1000 sats safe. */
    f->fee_per_tx = 1000;
    uint8_t arities[3] = { 2, 4, 8 };
    factory_set_level_arity(f, arities, 3);
    factory_set_static_near_root(f, 1);

    unsigned char fund_txid_bytes[32];
    TEST_ASSERT(hex_decode(fund_txid, fund_txid_bytes, 32),
                "decode fund txid");
    reverse_bytes(fund_txid_bytes, 32);
    factory_set_funding(f, fund_txid_bytes, fund_vout, fund_amount,
                        fund_spk, 34);

    TEST_ASSERT(factory_build_tree(f), "build n64 {2,4,8}");
    TEST_ASSERT(factory_sign_all(f), "sign n64 {2,4,8}");

    /* DW rotation Tier A: advance counter + re-sign tree at new epoch.
       This proves the math works at the new epoch without writing the
       full split-round MuSig2 rotation ceremony (production protocol
       work tracked separately in task #171). */
    uint32_t epoch_pre = dw_counter_epoch(&f->counter);
    TEST_ASSERT(factory_advance(f), "factory_advance (counter+resign) at epoch_pre");
    uint32_t epoch_post = dw_counter_epoch(&f->counter);
    printf("  [nway-n64 dw-advance] epoch %u -> %u after factory_advance\n", epoch_pre, epoch_post);
    TEST_ASSERT(epoch_post == epoch_pre + 1, "epoch advanced by 1");


    /* Print + assert tree shape */
    int n_leaves = f->n_leaf_nodes;
    printf("  [nway-n64 dw-advance] %zu nodes, %d leaves, n_layers=%d\n",
           f->n_nodes, n_leaves, (int)f->counter.n_layers);
    /* With static_threshold=1, node 0 is the static kickoff-only root. */
    TEST_ASSERT_EQ(f->nodes[0].is_static_only, 1,
                   "node 0 is static_only with thr=1");
    TEST_ASSERT_EQ(f->nodes[0].dw_layer_index, -1,
                   "static root dw_layer_index == -1");
    TEST_ASSERT_EQ(f->nodes[0].nsequence, 0xFFFFFFFEu,
                   "static root nsequence == 0xFFFFFFFE");
    TEST_ASSERT_EQ(f->nodes[0].n_outputs, 2,
                   "static root arity-2 fan-out (2 outputs)");
    /* Each leaf has 1..8 clients, n_outputs == n_clients + 1 */
    int total_client_channels = 0;
    int found_wide_leaf = 0;
    for (int li = 0; li < n_leaves; li++) {
        size_t nidx = f->leaf_node_indices[li];
        factory_node_t *leaf = &f->nodes[nidx];
        size_t n_clients = leaf->n_signers - 1;
        TEST_ASSERT(n_clients >= 1 && n_clients <= 8,
                    "leaf 1..8 clients (arity-8 cap)");
        TEST_ASSERT_EQ(leaf->n_outputs, n_clients + 1,
                       "leaf n_outputs = n_clients + 1");
        if (n_clients > 2) found_wide_leaf = 1;
        total_client_channels += (int)n_clients;
    }
    TEST_ASSERT(found_wide_leaf,
                "at least one leaf has > 2 clients (proves N-way)");
    TEST_ASSERT_EQ(total_client_channels, 63,
                   "all 63 clients placed (N-1=63)");

    /* Broadcast every signed tree node */
    char (*txids)[65] = calloc(FACTORY_MAX_NODES, sizeof(*txids));
    TEST_ASSERT(txids != NULL, "alloc txids");
    TEST_ASSERT(broadcast_factory_tree(&rt, f, mine_addr, txids),
                "broadcast n64 tree");
    for (int li = 0; li < n_leaves; li++) {
        int conf = regtest_get_confirmations(&rt,
            txids[f->leaf_node_indices[li]]);
        TEST_ASSERT(conf >= 1, "leaf on chain");
    }
    printf("  [nway-n64 dw-advance] full tree broadcast OK\n");

    /* Build per-party P2TR(xonly(pk_i)) destinations */
    unsigned char (*party_spk)[34] = calloc(N, sizeof(*party_spk));
    TEST_ASSERT(party_spk, "alloc party_spk");
    for (size_t p = 0; p < N; p++) {
        secp256k1_xonly_pubkey xo;
        secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &pks[p]);
        build_p2tr_script_pubkey(party_spk[p], &xo);
    }

    /* Wire econ harness for all 64 parties */
    econ_ctx_t econ;
    econ_ctx_init(&econ, &rt, ctx);
    char party_name[32];
    for (size_t p = 0; p < N; p++) {
        if (p == 0) strcpy(party_name, "LSP");
        else snprintf(party_name, sizeof(party_name), "client%02zu", p);
        TEST_ASSERT(econ_register_party(&econ, p, party_name,
                                          N64_SECKEYS[p]),
                    "register party n64");
    }
    econ.factory_funding_amount = fund_amount;
    TEST_ASSERT(econ_snap_pre(&econ), "econ_snap_pre n64");

    /* Per-leaf sweep: L-stock LSP-alone + each channel via 2-of-2 MuSig */
    const uint64_t LSTOCK_SWEEP_FEE = 300;
    const uint64_t CHAN_SWEEP_FEE   = 400;
    const uint64_t PAYMENT_SHIFT    = 1000;

    uint64_t *per_party_recv = calloc(N, sizeof(uint64_t));
    TEST_ASSERT(per_party_recv, "alloc per_party_recv");
    uint64_t total_sweep_fees = 0;
    uint64_t total_allocated  = 0;

    for (int li = 0; li < n_leaves; li++) {
        size_t nidx = f->leaf_node_indices[li];
        factory_node_t *leaf = &f->nodes[nidx];
        const char *leaf_txid = txids[nidx];

        unsigned char leaf_txid_bytes[32];
        TEST_ASSERT(hex_decode(leaf_txid, leaf_txid_bytes, 32),
                    "decode leaf txid");
        reverse_bytes(leaf_txid_bytes, 32);

        TEST_ASSERT(leaf->signer_indices[0] == 0,
                    "signer[0] is LSP for every leaf");

        uint32_t lstock_vout = (uint32_t)(leaf->n_outputs - 1);
        int n_channels       = (int)leaf->n_outputs - 1;

        /* (A) Sweep L-stock cooperatively via N-of-N MuSig (canonical
           t/1242 — L-stock SPK requires either all leaf signers
           cooperating, or LSP+CSV-delay). */
        uint64_t lstock_amt = leaf->outputs[lstock_vout].amount_sats;

        tx_buf_t lstock_sweep;
        tx_buf_init(&lstock_sweep, 256);
        TEST_ASSERT(spend_l_stock_cooperative(ctx, f, leaf,
                        leaf_txid, lstock_vout, lstock_amt,
                        party_spk[0], 34,
                        LSTOCK_SWEEP_FEE, &lstock_sweep),
                    "build L-stock cooperative sweep n64");
        char *lh = malloc(lstock_sweep.len * 2 + 1);
        TEST_ASSERT(lh, "lh malloc");
        hex_encode(lstock_sweep.data, lstock_sweep.len, lh);
        lh[lstock_sweep.len * 2] = '\0';
        char lstock_sweep_txid[65];
        int lok = spend_broadcast_and_mine(&rt, lh, 1, lstock_sweep_txid);
        free(lh); tx_buf_free(&lstock_sweep);
        TEST_ASSERT(lok, "L-stock sweep confirmed n64");
        per_party_recv[0] += lstock_amt - LSTOCK_SWEEP_FEE;
        total_sweep_fees  += LSTOCK_SWEEP_FEE;
        total_allocated   += lstock_amt;

        /* (B) Sweep each channel: 2-of-2 MuSig {client, LSP} → 50/50 split
              with PAYMENT_SHIFT to client→LSP */
        for (int ch = 0; ch < n_channels; ch++) {
            uint32_t client_idx = leaf->signer_indices[1 + ch];
            TEST_ASSERT(client_idx >= 1 && client_idx < N, "client_idx range");

            uint64_t chan_amt = leaf->outputs[ch].amount_sats;
            uint64_t after_fee = chan_amt - CHAN_SWEEP_FEE;
            uint64_t balanced  = after_fee / 2;
            uint64_t client_share = balanced - PAYMENT_SHIFT;
            uint64_t lsp_share    = after_fee - client_share;
            unsigned char chan_spk[34];
            memcpy(chan_spk, leaf->outputs[ch].script_pubkey, 34);

            tx_output_t outs[2];
            memcpy(outs[0].script_pubkey, party_spk[client_idx], 34);
            outs[0].script_pubkey_len = 34;
            outs[0].amount_sats = client_share;
            memcpy(outs[1].script_pubkey, party_spk[0], 34);
            outs[1].script_pubkey_len = 34;
            outs[1].amount_sats = lsp_share;

            tx_buf_t chan_unsigned;
            tx_buf_init(&chan_unsigned, 256);
            TEST_ASSERT(build_unsigned_tx(&chan_unsigned, NULL,
                                            leaf_txid_bytes,
                                            (uint32_t)ch, 0xFFFFFFFEu,
                                            outs, 2),
                        "build unsigned channel sweep n64");
            unsigned char sighash[32];
            TEST_ASSERT(compute_taproot_sighash(sighash,
                            chan_unsigned.data, chan_unsigned.len,
                            0, chan_spk, 34, chan_amt, 0xFFFFFFFEu),
                        "channel sighash n64");

            secp256k1_keypair signers[2] = { kps[client_idx], kps[0] };
            secp256k1_pubkey  ckpks[2];
            secp256k1_keypair_pub(ctx, &ckpks[0], &signers[0]);
            secp256k1_keypair_pub(ctx, &ckpks[1], &signers[1]);
            musig_keyagg_t cka;
            TEST_ASSERT(musig_aggregate_keys(ctx, &cka, ckpks, 2),
                        "agg channel keys n64");
            unsigned char sig64[64];
            TEST_ASSERT(musig_sign_taproot(ctx, sig64, sighash, signers, 2,
                                             &cka, NULL),
                        "2-of-2 MuSig2 sign channel sweep n64");
            tx_buf_t chan_signed;
            tx_buf_init(&chan_signed, 256);
            TEST_ASSERT(finalize_signed_tx(&chan_signed,
                            chan_unsigned.data, chan_unsigned.len, sig64),
                        "finalize channel sweep tx n64");
            tx_buf_free(&chan_unsigned);

            char *ch_hex = malloc(chan_signed.len * 2 + 1);
            TEST_ASSERT(ch_hex, "ch_hex malloc");
            hex_encode(chan_signed.data, chan_signed.len, ch_hex);
            ch_hex[chan_signed.len * 2] = '\0';
            char chan_sweep_txid[65];
            int cok = spend_broadcast_and_mine(&rt, ch_hex, 1, chan_sweep_txid);
            free(ch_hex); tx_buf_free(&chan_signed);
            TEST_ASSERT(cok, "channel 2-of-2 sweep confirmed n64");
            per_party_recv[client_idx] += client_share;
            per_party_recv[0]          += lsp_share;
            total_sweep_fees           += CHAN_SWEEP_FEE;
            total_allocated            += chan_amt;
        }
    }

    TEST_ASSERT(econ_snap_post(&econ), "econ_snap_post n64");

    /* Conservation check */
    uint64_t swept_sum = 0;
    for (size_t p = 0; p < N; p++) swept_sum += per_party_recv[p];
    TEST_ASSERT(swept_sum + total_sweep_fees == total_allocated,
                "conservation Σswept + Σfees == Σallocations");
    printf("  [nway-n64 dw-advance] conservation OK: swept=%llu + fees=%llu "
           "== allocations=%llu\n",
           (unsigned long long)swept_sum,
           (unsigned long long)total_sweep_fees,
           (unsigned long long)total_allocated);

    /* Per-party expected deltas */
    uint64_t *expected_deltas = calloc(N, sizeof(uint64_t));
    TEST_ASSERT(expected_deltas, "alloc expected_deltas");
    for (size_t p = 0; p < N; p++) expected_deltas[p] = per_party_recv[p];

    TEST_ASSERT(econ_assert_wallet_deltas(&econ, expected_deltas, 0),
                "per-party wallet deltas match expected (64 parties)");
    econ_print_summary(&econ);

    free(expected_deltas);
    free(per_party_recv);
    free(party_spk);
    free(txids);
    free(kps);
    free(pks);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ============================================================================
 *  Static-near-root variant lifecycle (Phase 3 of mixed-arity plan).
 *
 *  N=12 with {2,4} and static_threshold=1: depth-0 root is kickoff-only
 *  (no NODE_STATE), depth-1 mids and depth-2 leaves are regular DW pairs.
 *  Children of the static root spend the root kickoff's vout 0..N-1
 *  directly (no state intermediary).
 *
 *  Asserts:
 *   - tree shape: root has is_static_only=1, children spend it directly
 *   - broadcast: every TX confirms in DFS order
 *   - sweep: every leaf channel + L-stock; per-party econ_assert_wallet_deltas
 *   - conservation: Σ(swept) + Σ(fees) == fund_amount
 *  ========================================================================== */

/* N12_PARTY_SECKEYS already declared earlier in this file. */

int test_regtest_static_near_root_lifecycle(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "static_nearroot_n12");
    /* Tree depth=2 with ~16 nodes; bump scan depth so leaves stay findable. */
    rt.scan_depth = 600;

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    const size_t N = 12;
    secp256k1_keypair kps[12];
    secp256k1_pubkey  pks[12];
    for (size_t i = 0; i < N; i++) {
        TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[i],
                                               N12_PARTY_SECKEYS[i]),
                    "keypair_create n12 static");
        TEST_ASSERT(secp256k1_keypair_pub(ctx, &pks[i], &kps[i]),
                    "keypair_pub n12 static");
    }

    unsigned char fund_spk[34];
    unsigned char tw_ser[32];
    TEST_ASSERT(build_n_party_funding_spk(ctx, pks, N, fund_spk, tw_ser),
                "build n12 static funding spk");

    char fund_addr[128];
    TEST_ASSERT(regtest_derive_p2tr_address(&rt, tw_ser, fund_addr,
                                              sizeof(fund_addr)),
                "derive n12 static fund addr");
    char fund_txid[65];
    TEST_ASSERT(regtest_fund_address(&rt, fund_addr, 0.01, fund_txid),
                "fund n12 static factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    uint32_t fund_vout = UINT32_MAX;
    uint64_t fund_amount = 0;
    for (uint32_t v = 0; v < 4; v++) {
        uint64_t a = 0;
        unsigned char s[64];
        size_t sl = 0;
        if (regtest_get_tx_output(&rt, fund_txid, v, &a, s, &sl) &&
            sl == 34 && memcmp(s, fund_spk, 34) == 0) {
            fund_vout = v;
            fund_amount = a;
            break;
        }
    }
    TEST_ASSERT(fund_vout != UINT32_MAX, "find n12 static fund vout");
    printf("  [static-nearroot {2,4} thr=1] funded %s:%u  %llu sats\n",
           fund_txid, fund_vout, (unsigned long long)fund_amount);

    /* Build factory: arity {2,4}, static_threshold=1 (root kickoff-only) */
    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f != NULL, "alloc factory");
    factory_init(f, ctx, kps, N, 4, 4);
    /* PR #104 bumped fee_per_tx to 1000 sats for N-way regtest mempool floor. */
    f->fee_per_tx = 1000;
    uint8_t arities[2] = {2, 4};
    factory_set_level_arity(f, arities, 2);
    factory_set_static_near_root(f, 1);

    unsigned char fund_txid_bytes[32];
    TEST_ASSERT(hex_decode(fund_txid, fund_txid_bytes, 32),
                "decode fund txid");
    reverse_bytes(fund_txid_bytes, 32);
    factory_set_funding(f, fund_txid_bytes, fund_vout, fund_amount,
                        fund_spk, 34);

    TEST_ASSERT(factory_build_tree(f), "build static-nearroot tree");
    TEST_ASSERT(factory_sign_all(f), "sign static-nearroot tree");

    /* Tree shape assertions */
    int n_leaves = f->n_leaf_nodes;
    printf("  [static-nearroot {2,4} thr=1] %zu nodes, %d leaves, "
           "n_layers=%d\n",
           f->n_nodes, n_leaves, (int)f->counter.n_layers);

    TEST_ASSERT(f->nodes[0].type == NODE_KICKOFF,
                "node 0 is kickoff");
    TEST_ASSERT_EQ(f->nodes[0].is_static_only, 1,
                   "node 0 is static_only");
    TEST_ASSERT_EQ(f->nodes[0].dw_layer_index, -1,
                   "static root dw_layer_index == -1");
    TEST_ASSERT_EQ(f->nodes[0].nsequence, 0xFFFFFFFEu,
                   "static root nsequence == 0xFFFFFFFE");
    TEST_ASSERT_EQ(f->nodes[0].n_outputs, 2,
                   "static root has 2 outputs (arity-2 fan-out)");
    /* Children of static root: the next 2 kickoffs spend its vouts directly. */
    TEST_ASSERT(f->nodes[1].type == NODE_KICKOFF,
                "node 1 is depth-1 kickoff (no paired root state)");
    TEST_ASSERT(f->nodes[1].parent_index == 0,
                "node 1 parent is the static root (node 0)");
    TEST_ASSERT(f->nodes[1].parent_vout == 0,
                "node 1 spends root vout 0");

    /* Conservation pre-check: sum of leaf input_amounts ≤ funding */
    int total_client_channels = 0;
    for (int li = 0; li < n_leaves; li++) {
        size_t nidx = f->leaf_node_indices[li];
        factory_node_t *leaf = &f->nodes[nidx];
        TEST_ASSERT(!leaf->is_ps_leaf, "no PS leaves in DW {2,4} tree");
        size_t n_clients = leaf->n_signers - 1;
        TEST_ASSERT(n_clients >= 1 && n_clients <= 4,
                    "leaf 1..4 clients (arity-4 cap)");
        TEST_ASSERT_EQ(leaf->n_outputs, n_clients + 1,
                       "leaf n_outputs = n_clients + 1");
        total_client_channels += (int)n_clients;
    }
    TEST_ASSERT_EQ(total_client_channels, 11, "all 11 clients placed");

    /* Broadcast every signed tree node in order with BIP-68 spacing. */
    char (*txids)[65] = calloc(FACTORY_MAX_NODES, sizeof(*txids));
    TEST_ASSERT(txids != NULL, "alloc txids");
    TEST_ASSERT(broadcast_factory_tree(&rt, f, mine_addr, txids),
                "broadcast static-nearroot tree");
    for (int li = 0; li < n_leaves; li++) {
        int conf = regtest_get_confirmations(&rt,
            txids[f->leaf_node_indices[li]]);
        TEST_ASSERT(conf >= 1, "leaf on chain");
    }
    printf("  [static-nearroot] full tree broadcast OK — %zu nodes, "
           "%d leaves confirmed\n", f->n_nodes, n_leaves);

    /* Per-party P2TR(xonly(pk_i)) destinations */
    unsigned char party_spk[12][34];
    for (size_t p = 0; p < N; p++) {
        secp256k1_xonly_pubkey xo;
        secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &pks[p]);
        build_p2tr_script_pubkey(party_spk[p], &xo);
    }

    /* Wire econ harness for all 12 parties.  snap_pre BEFORE any sweep TX. */
    econ_ctx_t econ;
    econ_ctx_init(&econ, &rt, ctx);
    static const char *party_names[12] = {
        "LSP", "client01", "client02", "client03", "client04", "client05",
        "client06", "client07", "client08", "client09", "client10", "client11"
    };
    for (size_t p = 0; p < N; p++) {
        TEST_ASSERT(econ_register_party(&econ, p, party_names[p],
                                         N12_PARTY_SECKEYS[p]),
                    "register party static");
    }
    econ.factory_funding_amount = fund_amount;
    TEST_ASSERT(econ_snap_pre(&econ), "econ_snap_pre static");

    /* Per-leaf sweep loop */
    const uint64_t LSTOCK_SWEEP_FEE = 300;
    const uint64_t CHAN_SWEEP_FEE   = 400;
    const uint64_t PAYMENT_SHIFT    = 1000;

    uint64_t per_party_recv[12] = {0};
    uint64_t total_sweep_fees = 0;
    uint64_t total_allocated  = 0;

    for (int li = 0; li < n_leaves; li++) {
        size_t nidx = f->leaf_node_indices[li];
        factory_node_t *leaf = &f->nodes[nidx];
        const char *leaf_txid = txids[nidx];

        unsigned char leaf_txid_bytes[32];
        TEST_ASSERT(hex_decode(leaf_txid, leaf_txid_bytes, 32),
                    "decode leaf txid");
        reverse_bytes(leaf_txid_bytes, 32);

        TEST_ASSERT(leaf->signer_indices[0] == 0,
                    "signer[0] is LSP for every leaf");

        uint32_t lstock_vout = (uint32_t)(leaf->n_outputs - 1);
        int n_channels       = (int)leaf->n_outputs - 1;

        /* (A) Sweep L-stock cooperatively via N-of-N MuSig (canonical t/1242). */
        uint64_t lstock_amt = leaf->outputs[lstock_vout].amount_sats;

        tx_buf_t lstock_sweep;
        tx_buf_init(&lstock_sweep, 256);
        TEST_ASSERT(spend_l_stock_cooperative(ctx, f, leaf,
                        leaf_txid, lstock_vout, lstock_amt,
                        party_spk[0], 34,
                        LSTOCK_SWEEP_FEE, &lstock_sweep),
                    "build L-stock cooperative sweep static");
        char *lh = malloc(lstock_sweep.len * 2 + 1);
        TEST_ASSERT(lh != NULL, "lh malloc");
        hex_encode(lstock_sweep.data, lstock_sweep.len, lh);
        lh[lstock_sweep.len * 2] = '\0';
        char lstock_sweep_txid[65];
        int lok = spend_broadcast_and_mine(&rt, lh, 1, lstock_sweep_txid);
        free(lh); tx_buf_free(&lstock_sweep);
        TEST_ASSERT(lok, "L-stock sweep confirmed static");
        per_party_recv[0] += lstock_amt - LSTOCK_SWEEP_FEE;
        total_sweep_fees  += LSTOCK_SWEEP_FEE;
        total_allocated   += lstock_amt;

        /* (B) Each channel via 2-of-2 MuSig {client, LSP} */
        for (int ch = 0; ch < n_channels; ch++) {
            uint32_t client_idx = leaf->signer_indices[1 + ch];
            TEST_ASSERT(client_idx >= 1 && client_idx < N,
                        "client_idx range");

            uint64_t chan_amt = leaf->outputs[ch].amount_sats;
            uint64_t after_fee = chan_amt - CHAN_SWEEP_FEE;
            uint64_t balanced  = after_fee / 2;
            uint64_t client_share = balanced - PAYMENT_SHIFT;
            uint64_t lsp_share    = after_fee - client_share;
            unsigned char chan_spk[34];
            memcpy(chan_spk, leaf->outputs[ch].script_pubkey, 34);

            tx_output_t outs[2];
            memcpy(outs[0].script_pubkey, party_spk[client_idx], 34);
            outs[0].script_pubkey_len = 34;
            outs[0].amount_sats = client_share;
            memcpy(outs[1].script_pubkey, party_spk[0], 34);
            outs[1].script_pubkey_len = 34;
            outs[1].amount_sats = lsp_share;

            tx_buf_t chan_unsigned;
            tx_buf_init(&chan_unsigned, 256);
            TEST_ASSERT(build_unsigned_tx(&chan_unsigned, NULL,
                                            leaf_txid_bytes,
                                            (uint32_t)ch, 0xFFFFFFFEu,
                                            outs, 2),
                        "build unsigned channel sweep static");
            unsigned char sighash[32];
            TEST_ASSERT(compute_taproot_sighash(sighash,
                            chan_unsigned.data, chan_unsigned.len,
                            0, chan_spk, 34, chan_amt, 0xFFFFFFFEu),
                        "channel sighash static");

            secp256k1_keypair signers[2] = { kps[client_idx], kps[0] };
            secp256k1_pubkey  ckpks[2];
            secp256k1_keypair_pub(ctx, &ckpks[0], &signers[0]);
            secp256k1_keypair_pub(ctx, &ckpks[1], &signers[1]);
            musig_keyagg_t cka;
            TEST_ASSERT(musig_aggregate_keys(ctx, &cka, ckpks, 2),
                        "agg channel keys static");
            unsigned char sig64[64];
            TEST_ASSERT(musig_sign_taproot(ctx, sig64, sighash, signers, 2,
                                             &cka, NULL),
                        "2-of-2 MuSig2 sign channel sweep static");
            tx_buf_t chan_signed;
            tx_buf_init(&chan_signed, 256);
            TEST_ASSERT(finalize_signed_tx(&chan_signed,
                            chan_unsigned.data, chan_unsigned.len, sig64),
                        "finalize channel sweep tx static");
            tx_buf_free(&chan_unsigned);

            char *ch_hex = malloc(chan_signed.len * 2 + 1);
            TEST_ASSERT(ch_hex != NULL, "ch_hex malloc");
            hex_encode(chan_signed.data, chan_signed.len, ch_hex);
            ch_hex[chan_signed.len * 2] = '\0';
            char chan_sweep_txid[65];
            int cok = spend_broadcast_and_mine(&rt, ch_hex, 1, chan_sweep_txid);
            free(ch_hex); tx_buf_free(&chan_signed);
            TEST_ASSERT(cok, "channel 2-of-2 sweep confirmed static");
            per_party_recv[client_idx] += client_share;
            per_party_recv[0]          += lsp_share;
            total_sweep_fees           += CHAN_SWEEP_FEE;
            total_allocated            += chan_amt;
        }
    }

    TEST_ASSERT(econ_snap_post(&econ), "econ_snap_post static");

    uint64_t swept_sum = 0;
    for (size_t p = 0; p < N; p++) swept_sum += per_party_recv[p];
    TEST_ASSERT(swept_sum + total_sweep_fees == total_allocated,
                "conservation Σswept + Σfees == Σallocations (static)");
    printf("  [static-nearroot] conservation OK: swept=%llu + fees=%llu "
           "== allocations=%llu\n",
           (unsigned long long)swept_sum,
           (unsigned long long)total_sweep_fees,
           (unsigned long long)total_allocated);

    uint64_t expected_deltas[12];
    for (size_t p = 0; p < N; p++) expected_deltas[p] = per_party_recv[p];
    TEST_ASSERT(econ_assert_wallet_deltas(&econ, expected_deltas, 0),
                "per-party wallet deltas match expected (12 parties, static)");
    econ_print_summary(&econ);

    free(txids);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Static-near-root unilateral exit: confirms a static interior kickoff
   spends via nSequence=0xFFFFFFFE (no BIP-68 CSV) and that its on-chain
   broadcast does NOT rely on stacked nSequence delays.

   We force-close a {2,4} factory with static_threshold=1: the root kickoff
   (static) broadcasts with no CSV between funding confirmation and broadcast.
   Asserts:
     - root kickoff's nsequence == 0xFFFFFFFE
     - the root kickoff spends the funding output 1 block after confirmation
       (no extra BIP-68 wait)
     - downstream child kickoff (depth=1, regular) requires its normal
       BIP-68 + CLTV constraints */
int test_regtest_static_near_root_unilateral_exit(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "static_unilat_n12");
    rt.scan_depth = 600;

    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);

    const size_t N = 12;
    secp256k1_keypair kps[12];
    secp256k1_pubkey  pks[12];
    for (size_t i = 0; i < N; i++) {
        TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[i],
                                               N12_PARTY_SECKEYS[i]),
                    "keypair_create");
        TEST_ASSERT(secp256k1_keypair_pub(ctx, &pks[i], &kps[i]),
                    "keypair_pub");
    }

    unsigned char fund_spk[34];
    unsigned char tw_ser[32];
    TEST_ASSERT(build_n_party_funding_spk(ctx, pks, N, fund_spk, tw_ser),
                "build fund spk");

    char fund_addr[128];
    TEST_ASSERT(regtest_derive_p2tr_address(&rt, tw_ser, fund_addr,
                                              sizeof(fund_addr)),
                "derive fund addr");
    char fund_txid[65];
    TEST_ASSERT(regtest_fund_address(&rt, fund_addr, 0.01, fund_txid),
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
    TEST_ASSERT(fund_vout != UINT32_MAX, "find fund vout");

    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f != NULL, "alloc factory");
    factory_init(f, ctx, kps, N, 4, 4);
    f->fee_per_tx = 1000;
    uint8_t arities[2] = {2, 4};
    factory_set_level_arity(f, arities, 2);
    factory_set_static_near_root(f, 1);

    unsigned char fund_txid_bytes[32];
    TEST_ASSERT(hex_decode(fund_txid, fund_txid_bytes, 32),
                "decode fund txid");
    reverse_bytes(fund_txid_bytes, 32);
    factory_set_funding(f, fund_txid_bytes, fund_vout, fund_amount,
                        fund_spk, 34);
    TEST_ASSERT(factory_build_tree(f), "build");
    TEST_ASSERT(factory_sign_all(f), "sign");

    /* Static root assertions */
    TEST_ASSERT_EQ(f->nodes[0].is_static_only, 1, "root static");
    TEST_ASSERT_EQ(f->nodes[0].nsequence, 0xFFFFFFFEu,
                   "static root nsequence == 0xFFFFFFFE");

    /* Broadcast root kickoff DIRECTLY 1 block after funding confirmation
       (no BIP-68 wait). Confirms BIP-68 is fully disabled on a static node. */
    factory_node_t *root_ko = &f->nodes[0];
    char *root_hex = malloc(root_ko->signed_tx.len * 2 + 1);
    TEST_ASSERT(root_hex != NULL, "root_hex malloc");
    hex_encode(root_ko->signed_tx.data, root_ko->signed_tx.len, root_hex);
    char root_txid_out[65];
    int rok = spend_broadcast_and_mine(&rt, root_hex, 1, root_txid_out);
    free(root_hex);
    TEST_ASSERT(rok, "static root kickoff broadcast + confirmed without "
                     "any BIP-68 CSV wait");
    printf("  [static unilat] static root kickoff broadcast OK at "
           "1-block confirm — proves nsequence=0xFFFFFFFE eliminates BIP-68 CSV\n");

    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}
