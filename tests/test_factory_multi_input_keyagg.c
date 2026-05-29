/* SF-MULTI-KEYAGG (#283) — per-input keyagg threading for sub-factory
   multi-input ceremony.  Verifies:
     1. After factory_session_init_node_input runs, the per-input metadata
        is populated:
          - input_n_signers[i] = 2 for channel inputs (0..k-1)
          - input_n_signers[k] = node->n_signers for sales-stock input
          - input_signer_indices[i][0..1] = {client_i, LSP} for channel inputs
          - input_signer_indices[k][..] = node->signer_indices[..] for sales-stock
     2. Driving the per-input ceremony to completion produces a signed TX
        whose Schnorr signatures pass secp256k1_schnorrsig_verify against
        the recorded prev-output SPKs (ps_prev_spks[]) for ALL k+1 inputs.
     3. factory_session_get_input_signer_slot / factory_session_input_signs
        report the expected per-input slot mappings.

   Scope: pure libsuperscalar exercise; does not touch the wire layer. */

#include "superscalar/factory.h"
#include "superscalar/musig.h"
#include "superscalar/sha256.h"
#include "superscalar/tx_builder.h"
#include <secp256k1.h>
#include <secp256k1_musig.h>
#include <secp256k1_schnorrsig.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define TEST_ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { \
        printf("  FAIL: %s (line %d): %s (got %ld, expected %ld)\n", \
               __func__, __LINE__, msg, (long)(a), (long)(b)); \
        return 0; \
    } \
} while(0)

static secp256k1_context *mk_test_ctx(void) {
    return secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

/* Extract the 64-byte Schnorr sig from witness slot `input_idx` of a
   signed multi-input TX whose layout matches finalize_signed_tx_multi:
     nVersion(4) + marker(0x00) + flag(0x01)
     vin_count varint
     for each input: 32 (txid) + 4 (vout) + 1 (scriptSig=0) + 4 (nSeq) = 41
     vout_count varint
     for each output: 8 (amount) + 1 (spk_len varint) + spk_len
     for each input: witness stack (1 byte count, sig_len byte, 64-byte sig). */
static int extract_input_sig(const unsigned char *tx, size_t tx_len,
                              size_t n_inputs, size_t n_outputs,
                              size_t input_idx,
                              unsigned char sig_out[64])
{
    if (tx_len < 10) return 0;
    size_t pos = 6;                                 /* version(4)+marker(1)+flag(1) */
    if ((size_t)tx[pos] != n_inputs) return 0;
    pos += 1 + 41 * n_inputs;
    if ((size_t)tx[pos] != n_outputs) return 0;
    pos += 1;
    for (size_t i = 0; i < n_outputs; i++) {
        pos += 8;
        size_t spk_len = (size_t)tx[pos];
        pos += 1 + spk_len;
    }
    for (size_t i = 0; i < n_inputs; i++) {
        if (tx[pos] != 0x01) return 0;
        if (tx[pos + 1] != 0x40) return 0;
        if (i == input_idx) {
            memcpy(sig_out, tx + pos + 2, 64);
            return 1;
        }
        pos += 66;
    }
    return 0;
}

int test_factory_multi_input_keyagg(void)
{
    secp256k1_context *ctx = mk_test_ctx();
    /* N = 5 participants: LSP at slot 0 + 4 clients.  k = 2 sub-factory
       means each leaf has k=2 sub-factories, and each sub-factory has
       k=2 clients + sales-stock => 3 outputs.  A chain advance of one
       sub-factory therefore spends 3 inputs from chain[0]. */
    secp256k1_keypair kps[5];
    for (int i = 0; i < 5; i++) {
        unsigned char sk[32] = {0};
        sk[31] = (unsigned char)(i + 1);
        sk[0]  = 0xCD;
        TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[i], sk), "keypair");
    }

    /* Build the funding SPK = P2TR(taproot_tweak(N-of-N agg key)). */
    unsigned char fund_spk[34];
    {
        secp256k1_pubkey pks[5];
        for (int i = 0; i < 5; i++)
            TEST_ASSERT(secp256k1_keypair_pub(ctx, &pks[i], &kps[i]),
                        "kp pub");
        musig_keyagg_t ka;
        TEST_ASSERT(musig_aggregate_keys(ctx, &ka, pks, 5), "agg keys");
        unsigned char ser[32];
        TEST_ASSERT(secp256k1_xonly_pubkey_serialize(ctx, ser, &ka.agg_pubkey),
                    "xonly ser");
        unsigned char tweak[32];
        sha256_tagged("TapTweak", ser, 32, tweak);
        secp256k1_pubkey tweaked_pk;
        TEST_ASSERT(secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk,
                                                             &ka.cache, tweak),
                    "musig tweak");
        secp256k1_xonly_pubkey fund_tw;
        TEST_ASSERT(secp256k1_xonly_pubkey_from_pubkey(ctx, &fund_tw, NULL,
                                                         &tweaked_pk),
                    "xonly tw");
        build_p2tr_script_pubkey(fund_spk, &fund_tw);
    }

    unsigned char fake_txid[32];
    memset(fake_txid, 0xBE, 32);

    factory_t *f = (factory_t *)calloc(1, sizeof(factory_t));
    TEST_ASSERT(f, "alloc factory");
    factory_init(f, ctx, kps, 5, 6, 10);
    factory_set_arity(f, FACTORY_ARITY_PS);
    factory_set_ps_subfactory_arity(f, 2);   /* k=2 -> 4 clients per leaf */
    factory_set_funding(f, fake_txid, 0, 2000000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(f), "build k**2=4 PS tree");
    TEST_ASSERT(factory_sign_all(f), "sign chain[0]");

    size_t leaf_idx = f->leaf_node_indices[0];
    factory_node_t *leaf = &f->nodes[leaf_idx];
    int sub0_node_idx = leaf->subfactory_node_indices[0];
    TEST_ASSERT(sub0_node_idx >= 0, "sub0 wired");
    factory_node_t *sub = &f->nodes[sub0_node_idx];
    TEST_ASSERT_EQ((long)sub->n_outputs, 3, "sub has k+1=3 outputs");

    /* Trigger chain advance: client A buys 50000 from sales-stock. */
    uint64_t delta = 50000;
    TEST_ASSERT_EQ(
        factory_subfactory_chain_advance_unsigned(f, 0, 0, 0, delta),
        1, "chain advance ok");
    TEST_ASSERT_EQ(sub->ps_chain_len, 1, "chain_len=1");
    TEST_ASSERT_EQ((long)sub->ps_n_prev_outputs, 3, "captured 3 prev outputs");

    size_t n_inp = sub->ps_n_prev_outputs;
    size_t sstock_idx = n_inp - 1;

    /* Driver: per-input ceremony.  Channel inputs sign 2-of-2; sales-stock
       signs N-of-N (= node->n_signers). */
    secp256k1_musig_secnonce secnonces[3][FACTORY_MAX_SIGNERS];
    memset(secnonces, 0, sizeof(secnonces));

    /* Round 1: init + nonces. */
    for (size_t i = 0; i < n_inp; i++) {
        TEST_ASSERT(factory_session_init_node_input(f, (size_t)sub0_node_idx, i),
                    "init per-input session");

        /* Verify per-input metadata after init. */
        if (i == sstock_idx) {
            TEST_ASSERT_EQ((long)sub->input_n_signers[i],
                            (long)sub->n_signers,
                            "sales-stock n_signers = node N-of-N");
        } else {
            TEST_ASSERT_EQ((long)sub->input_n_signers[i], 2,
                            "channel n_signers = 2-of-2");
            /* Slot 0 = client_i (signer_indices[i+1]); slot 1 = LSP. */
            TEST_ASSERT_EQ(
                (long)sub->input_signer_indices[i][0],
                (long)sub->signer_indices[i + 1],
                "channel slot 0 = client_i");
            TEST_ASSERT_EQ((long)sub->input_signer_indices[i][1], 0,
                            "channel slot 1 = LSP");
        }

        size_t this_n = sub->input_n_signers[i];
        for (size_t s = 0; s < this_n; s++) {
            uint32_t participant = sub->input_signer_indices[i][s];
            unsigned char seckey[32];
            secp256k1_pubkey pk;
            TEST_ASSERT(secp256k1_keypair_sec(ctx, seckey, &kps[participant]),
                        "kp sec");
            TEST_ASSERT(secp256k1_keypair_pub(ctx, &pk, &kps[participant]),
                        "kp pub");
            secp256k1_musig_pubnonce pubnonce;
            TEST_ASSERT(musig_generate_nonce(ctx, &secnonces[i][s], &pubnonce,
                                               seckey, &pk,
                                               &sub->input_keyaggs[i].cache),
                        "gen nonce per-input");
            TEST_ASSERT(factory_session_set_nonce_input(
                            f, (size_t)sub0_node_idx, i, s, &pubnonce),
                        "set nonce per-input");
            memset(seckey, 0, 32);
        }
        TEST_ASSERT(factory_session_finalize_node_input(
                        f, (size_t)sub0_node_idx, i),
                    "finalize per-input");
    }

    /* Round 2: partial sigs. */
    for (size_t i = 0; i < n_inp; i++) {
        size_t this_n = sub->input_n_signers[i];
        for (size_t s = 0; s < this_n; s++) {
            uint32_t participant = sub->input_signer_indices[i][s];
            secp256k1_musig_partial_sig psig;
            TEST_ASSERT(musig_create_partial_sig(
                            ctx, &psig, &secnonces[i][s], &kps[participant],
                            &sub->input_signing_sessions[i]),
                        "create per-input psig");
            TEST_ASSERT(factory_session_set_partial_sig_input(
                            f, (size_t)sub0_node_idx, i, s, &psig),
                        "set per-input psig");
        }
        TEST_ASSERT(factory_session_complete_node_input(
                        f, (size_t)sub0_node_idx, i),
                    "complete per-input");
    }

    TEST_ASSERT(factory_session_assemble_signed_tx_multi(
                    f, (size_t)sub0_node_idx),
                "assemble multi-witness signed_tx");
    TEST_ASSERT(sub->is_signed, "sub signed");
    TEST_ASSERT(sub->signed_tx.len > 100, "signed_tx populated");

    /* Extract per-input Schnorr sigs and verify each against the recorded
       prev-output SPK (i.e., what bitcoind will check on broadcast). */
    for (size_t i = 0; i < n_inp; i++) {
        unsigned char sig64[64];
        TEST_ASSERT(extract_input_sig(sub->signed_tx.data, sub->signed_tx.len,
                                       n_inp, sub->n_outputs, i, sig64),
                    "extract per-input sig");

        /* Recompute the per-input BIP-341 sighash via the same helper the
           library uses for finalize. */
        unsigned char sighash[32];
        const unsigned char *spks[FACTORY_MAX_OUTPUTS];
        uint32_t seqs[FACTORY_MAX_OUTPUTS];
        for (size_t j = 0; j < n_inp; j++) {
            spks[j] = sub->ps_prev_spks[j];
            seqs[j] = sub->nsequence;
        }
        TEST_ASSERT(compute_taproot_sighash_multi(sighash,
                        sub->unsigned_tx.data, sub->unsigned_tx.len,
                        (uint32_t)i, n_inp, spks, sub->ps_prev_spk_lens,
                        sub->ps_prev_amounts, seqs),
                    "recompute per-input sighash");

        TEST_ASSERT_EQ((long)sub->ps_prev_spk_lens[i], 34,
                        "prev SPK is P2TR (34 bytes)");
        secp256k1_xonly_pubkey xonly;
        TEST_ASSERT(secp256k1_xonly_pubkey_parse(ctx, &xonly,
                                                   sub->ps_prev_spks[i] + 2),
                    "parse prev SPK xonly");
        int ok = secp256k1_schnorrsig_verify(ctx, sig64, sighash, 32, &xonly);
        char msg[64];
        snprintf(msg, sizeof(msg), "schnorrsig_verify input %zu", i);
        TEST_ASSERT(ok, msg);
    }

    /* Per-input signer-slot helpers. */
    for (size_t i = 0; i < n_inp; i++) {
        TEST_ASSERT(factory_session_input_signs(f, (size_t)sub0_node_idx, i, 0),
                    "LSP signs every input");
    }
    uint32_t client0 = sub->signer_indices[1];
    uint32_t client1 = sub->signer_indices[2];
    TEST_ASSERT(factory_session_input_signs(f, (size_t)sub0_node_idx, 0, client0),
                "client0 signs channel 0");
    TEST_ASSERT(!factory_session_input_signs(f, (size_t)sub0_node_idx, 0, client1),
                "client1 does NOT sign channel 0");
    TEST_ASSERT(factory_session_input_signs(f, (size_t)sub0_node_idx, 1, client1),
                "client1 signs channel 1");
    TEST_ASSERT(!factory_session_input_signs(f, (size_t)sub0_node_idx, 1, client0),
                "client0 does NOT sign channel 1");
    TEST_ASSERT(factory_session_input_signs(f, (size_t)sub0_node_idx, sstock_idx, client0),
                "client0 signs sales-stock");
    TEST_ASSERT(factory_session_input_signs(f, (size_t)sub0_node_idx, sstock_idx, client1),
                "client1 signs sales-stock");

    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}
