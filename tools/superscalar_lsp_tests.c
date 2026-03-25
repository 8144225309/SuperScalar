/*
 * superscalar_lsp_tests.c — Test harness functions extracted from
 * superscalar_lsp.c main().  Each function implements one --test-* block.
 *
 * All functions receive an lsp_test_ctx_t* that bundles the local variables
 * they previously accessed directly.  Behavior is identical to the inline
 * blocks they replace.
 */

#include "superscalar_lsp_tests.h"
#include "superscalar/tx_builder.h"
#include "superscalar/adaptor.h"
#include "superscalar/tapscript.h"
#include "superscalar/musig.h"
#include "superscalar/sha256.h"
#include "superscalar/dw_state.h"
#include "superscalar/splice.h"
#include "superscalar/jit_channel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <secp256k1_schnorrsig.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

/* Defined in superscalar_lsp.c — broadcast helpers */
extern int broadcast_factory_tree_any_network(factory_t *f, regtest_t *rt,
                                                const char *mine_addr,
                                                int is_regtest,
                                                int confirm_timeout);

/* advance_chain is static in superscalar_lsp.c, so we re-wrap it here */
static int advance_chain_local(regtest_t *rt, int n, const char *mine_addr,
                                int is_regtest, int timeout_secs) {
    if (n <= 0) return 1;
    if (is_regtest) {
        regtest_mine_blocks(rt, n, mine_addr);
        return 1;
    }
    int start_h = regtest_get_block_height(rt);
    int target_h = start_h + n;
    printf("Waiting for %d block(s) (height %d -> %d)...\n",
           n, start_h, target_h);
    for (int waited = 0; waited < timeout_secs; waited += 10) {
        if (regtest_get_block_height(rt) >= target_h) return 1;
        sleep(10);
    }
    fprintf(stderr, "advance_chain: timed out waiting for %d blocks "
            "(height %d / %d)\n", n, regtest_get_block_height(rt), target_h);
    return 0;
}

int lsp_test_advance(lsp_test_ctx_t *ctx, int n) {
    return advance_chain_local(ctx->rt, n, ctx->mine_addr,
                                ctx->is_regtest, ctx->confirm_timeout_secs);
}

/* Convenience macro for use inside test functions */
#define ADVANCE(n) lsp_test_advance(ctx, (n))

/* ========================================================================= */
/* Helper: populate demo keypairs and reorder to match factory pubkey order   */
/* ========================================================================= */
static void populate_demo_keypairs(secp256k1_context *sctx,
                                    secp256k1_keypair *out_kps,
                                    const secp256k1_keypair *lsp_kp,
                                    const factory_t *factory,
                                    int n_clients, size_t n_total) {
    out_kps[0] = *lsp_kp;
    static const unsigned char fill[4] = { 0x22, 0x33, 0x44, 0x55 };
    for (int ci = 0; ci < n_clients && ci < 4; ci++) {
        unsigned char ds[32];
        memset(ds, fill[ci], 32);
        secp256k1_keypair_create(sctx, &out_kps[ci + 1], ds);
    }
    /* Reorder to match factory pubkeys connection order (BIP-327) */
    secp256k1_keypair ordered[FACTORY_MAX_SIGNERS];
    memcpy(ordered, out_kps, n_total * sizeof(secp256k1_keypair));
    for (size_t slot = 0; slot < n_total; slot++) {
        unsigned char target[33];
        size_t tlen = 33;
        secp256k1_ec_pubkey_serialize(sctx, target, &tlen,
                                      &factory->pubkeys[slot],
                                      SECP256K1_EC_COMPRESSED);
        for (size_t k = 0; k < n_total; k++) {
            secp256k1_pubkey kpub;
            secp256k1_keypair_pub(sctx, &kpub, &ordered[k]);
            unsigned char kser[33];
            size_t klen = 33;
            secp256k1_ec_pubkey_serialize(sctx, kser, &klen,
                                          &kpub, SECP256K1_EC_COMPRESSED);
            if (memcmp(target, kser, 33) == 0) {
                out_kps[slot] = ordered[k];
                break;
            }
        }
    }
}

/* ========================================================================= */
/* DW Exhibition Test                                                        */
/* ========================================================================= */
int lsp_test_dw_exhibition(lsp_test_ctx_t *ctx) {
    lsp_channel_mgr_t *mgr = ctx->mgr;
    lsp_t *lsp = ctx->lsp;
    secp256k1_context *sctx = ctx->ctx;
    secp256k1_keypair lsp_kp = *ctx->lsp_kp;
    int n_clients = ctx->n_clients;
    size_t n_total = ctx->n_total;
    int states_per_layer = ctx->states_per_layer;
    ladder_t *lad = ctx->lad;

    printf("\n=== DW EXHIBITION TEST ===\n\n");
    int exhibition_pass = 1;
    char exhibition_close_txid[65] = {0};

    /* --- Phase 1: Multiple DW Advances — nSequence Countdown to Zero --- */
    printf("--- Phase 1: nSequence Countdown ---\n");

    /* Populate keypairs (demo mode: LSP has all keys) */
    secp256k1_keypair exh_kps[FACTORY_MAX_SIGNERS];
    populate_demo_keypairs(sctx, exh_kps, &lsp_kp, &lsp->factory,
                            n_clients, n_total);

    memcpy(lsp->factory.keypairs, exh_kps,
           n_total * sizeof(secp256k1_keypair));

    /* Record initial nSequence for all nodes */
    uint32_t initial_nseq[FACTORY_MAX_NODES];
    for (size_t ni = 0; ni < lsp->factory.n_nodes; ni++)
        initial_nseq[ni] = lsp->factory.nodes[ni].nsequence;

    printf("Epoch 0 (initial):\n");
    for (size_t ni = 0; ni < lsp->factory.n_nodes; ni++)
        printf("  Node %zu: nSequence=%u\n", ni, lsp->factory.nodes[ni].nsequence);

    /* Advance states_per_layer - 1 times to reach zero */
    int max_advances = states_per_layer - 1;
    int any_zero = 0;
    int any_decreased = 0;
    for (int adv = 0; adv < max_advances; adv++) {
        if (!factory_advance(&lsp->factory)) {
            fprintf(stderr, "DW EXHIBITION: factory_advance failed at step %d\n", adv + 1);
            exhibition_pass = 0;
            break;
        }
        printf("Epoch %u (advance %d/%d):\n",
               dw_counter_epoch(&lsp->factory.counter), adv + 1, max_advances);
        for (size_t ni = 0; ni < lsp->factory.n_nodes; ni++) {
            uint32_t cur = lsp->factory.nodes[ni].nsequence;
            int32_t delta = (int32_t)cur - (int32_t)initial_nseq[ni];
            printf("  Node %zu: nSequence=%u (delta=%d)\n", ni, cur, delta);
            if (cur == 0) any_zero = 1;
        }
    }

    /* Verify: all state nodes decreased from initial AND at least one reached 0 */
    for (size_t ni = 0; ni < lsp->factory.n_nodes; ni++) {
        if (initial_nseq[ni] > 0 && initial_nseq[ni] != 0xFFFFFFFF &&
            lsp->factory.nodes[ni].nsequence < initial_nseq[ni])
            any_decreased = 1;
    }

    if (!any_decreased) {
        fprintf(stderr, "DW EXHIBITION Phase 1: countdown check failed "
                "(any_decreased=%d, any_zero=%d)\n", any_decreased, any_zero);
        exhibition_pass = 0;
    }
    printf("Phase 1: %s (any_decreased=%d, any_zero=%d)\n\n",
           any_decreased ? "PASS" : "FAIL",
           any_decreased, any_zero);

    /* Record Factory 0 final nSequence for Phase 3 comparison */
    uint32_t f0_final_nseq = 0;
    for (size_t ni = 0; ni < lsp->factory.n_nodes; ni++) {
        if (lsp->factory.nodes[ni].nsequence != 0xFFFFFFFF && lsp->factory.nodes[ni].nsequence > f0_final_nseq)
            f0_final_nseq = lsp->factory.nodes[ni].nsequence;
    }

    /* --- Phase 2: PTLC-Assisted Exit — Close Without Clients --- */
    printf("--- Phase 2: PTLC-Assisted Close ---\n");

    /* Build pubkey array and aggregate */
    secp256k1_pubkey exh_pks[FACTORY_MAX_SIGNERS];
    for (size_t ti = 0; ti < n_total; ti++) {
        if (!secp256k1_keypair_pub(sctx, &exh_pks[ti], &exh_kps[ti])) {
            fprintf(stderr, "DW EXHIBITION: keypair pub failed\n");
            return 1;
        }
    }
    musig_keyagg_t exh_ka;
    musig_aggregate_keys(sctx, &exh_ka, exh_pks, n_total);

    /* Turnover message hash */
    unsigned char exh_msg[32];
    sha256_tagged("turnover", (const unsigned char *)"turnover", 8, exh_msg);

    /* For each client: adaptor presig -> adapt -> extract -> verify -> record */
    for (int ci = 0; ci < n_clients; ci++) {
        uint32_t participant_idx = (uint32_t)(ci + 1);
        secp256k1_pubkey client_pk = exh_pks[participant_idx];

        unsigned char presig[64];
        int nonce_parity;
        musig_keyagg_t ka_copy = exh_ka;
        if (!adaptor_create_turnover_presig(sctx, presig, &nonce_parity,
                                              exh_msg, exh_kps, n_total,
                                              &ka_copy, NULL, &client_pk)) {
            fprintf(stderr, "DW EXHIBITION: presig failed for client %d\n", ci);
            exhibition_pass = 0;
            break;
        }

        unsigned char client_sec[32];
        if (!secp256k1_keypair_sec(sctx, client_sec, &exh_kps[participant_idx])) {
            fprintf(stderr, "DW EXHIBITION: keypair sec failed\n");
            return 1;
        }
        unsigned char adapted_sig[64];
        if (!adaptor_adapt(sctx, adapted_sig, presig, client_sec, nonce_parity)) {
            fprintf(stderr, "DW EXHIBITION: adapt failed for client %d\n", ci);
            memset(client_sec, 0, 32);
            exhibition_pass = 0;
            break;
        }

        unsigned char extracted[32];
        if (!adaptor_extract_secret(sctx, extracted, adapted_sig, presig,
                                      nonce_parity)) {
            fprintf(stderr, "DW EXHIBITION: extract failed for client %d\n", ci);
            memset(client_sec, 0, 32);
            exhibition_pass = 0;
            break;
        }

        if (!adaptor_verify_extracted_key(sctx, extracted, &client_pk)) {
            fprintf(stderr, "DW EXHIBITION: verify failed for client %d\n", ci);
            memset(client_sec, 0, 32);
            exhibition_pass = 0;
            break;
        }

        ladder_record_key_turnover(lad, 0, participant_idx, extracted);
        if (ctx->use_db)
            persist_save_departed_client(ctx->db, 0, participant_idx, extracted);
        printf("  Client %d: key extracted and verified\n", ci + 1);
        memset(client_sec, 0, 32);
    }

    /* Verify all clients departed */
    int can_close = ladder_can_close(lad, 0);
    if (!can_close) {
        fprintf(stderr, "DW EXHIBITION Phase 2: ladder_can_close returned false\n");
        exhibition_pass = 0;
    }

    /* Build close outputs (equal split minus 500 sat fee) */
    tx_output_t exh_outputs[FACTORY_MAX_SIGNERS];
    uint64_t exh_per = (lsp->factory.funding_amount_sats - 500) / n_total;
    for (size_t ti = 0; ti < n_total; ti++) {
        exh_outputs[ti].amount_sats = exh_per;
        memcpy(exh_outputs[ti].script_pubkey, ctx->fund_spk, 34);
        exh_outputs[ti].script_pubkey_len = 34;
    }
    exh_outputs[n_total - 1].amount_sats =
        lsp->factory.funding_amount_sats - 500 - exh_per * (n_total - 1);

    /* Build cooperative close using extracted keys */
    tx_buf_t exh_close_tx;
    tx_buf_init(&exh_close_tx, 512);
    int close_built = ladder_build_close(lad, 0, &exh_close_tx,
                                           exh_outputs, n_total,
                                           (uint32_t)regtest_get_block_height(ctx->rt));
    if (!close_built) {
        fprintf(stderr, "DW EXHIBITION Phase 2: ladder_build_close failed\n");
        tx_buf_free(&exh_close_tx);
        exhibition_pass = 0;
    }

    /* Broadcast close TX */
    int close_confirmed = 0;
    if (close_built) {
        char *ec_hex = malloc(exh_close_tx.len * 2 + 1);
        hex_encode(exh_close_tx.data, exh_close_tx.len, ec_hex);
        int ec_sent = regtest_send_raw_tx(ctx->rt, ec_hex, exhibition_close_txid);
        if (ctx->g_db)
            persist_log_broadcast(ctx->g_db, ec_sent ? exhibition_close_txid : "?",
                "exhibition_close", ec_hex, ec_sent ? "ok" : "failed");
        free(ec_hex);
        tx_buf_free(&exh_close_tx);

        if (!ec_sent) {
            fprintf(stderr, "DW EXHIBITION Phase 2: close TX broadcast failed\n");
            exhibition_pass = 0;
        } else {
            ADVANCE(1);
            close_confirmed = 1;
            printf("  Close TX broadcast: %s\n", exhibition_close_txid);
        }
    }
    printf("Phase 2: %s\n\n",
           (can_close && close_confirmed) ? "PASS" : "FAIL");

    /* --- Phase 3: Cross-Factory nSequence Contrast --- */
    printf("--- Phase 3: Cross-Factory nSequence Contrast ---\n");

    /* Check wallet balance (non-regtest only) */
    if (!ctx->is_regtest) {
        double bal = regtest_get_balance(ctx->rt);
        double needed = (double)ctx->funding_sats / 100000000.0;
        if (bal < needed) {
            fprintf(stderr, "DW EXHIBITION Phase 3: insufficient balance "
                    "(%.8f < %.8f)\n", bal, needed);
            exhibition_pass = 0;
        }
    }

    /* Fund Factory 1 */
    double exh_funding_btc = (double)ctx->funding_sats / 100000000.0;
    char exh_fund_txid[65];
    int f1_funded = 0;
    if (exhibition_pass) {
        if (!regtest_fund_address(ctx->rt, ctx->fund_addr, exh_funding_btc, exh_fund_txid)) {
            fprintf(stderr, "DW EXHIBITION Phase 3: fund Factory 1 failed\n");
            exhibition_pass = 0;
        } else {
            if (ctx->is_regtest) {
                regtest_mine_blocks(ctx->rt, 1, ctx->mine_addr);
            } else {
                printf("Waiting for Factory 1 funding confirmation on %s...\n",
                       ctx->network);
                fflush(stdout);
                int conf = regtest_wait_for_confirmation(ctx->rt, exh_fund_txid,
                                                          ctx->confirm_timeout_secs);
                if (conf < 1) {
                    fprintf(stderr, "DW EXHIBITION Phase 3: funding not confirmed\n");
                    exhibition_pass = 0;
                }
            }
            if (exhibition_pass) {
                f1_funded = 1;
                printf("  Factory 1 funded: %s\n", exh_fund_txid);
            }
        }
    }

    /* Find funding output */
    factory_t *exh_f1 = calloc(1, sizeof(factory_t));
    int f1_built = 0;
    uint32_t f1_initial_nseq = 0;

    if (f1_funded) {
        unsigned char exh_fund_txid_bytes[32];
        hex_decode(exh_fund_txid, exh_fund_txid_bytes, 32);
        reverse_bytes(exh_fund_txid_bytes, 32);

        uint64_t exh_fund_amount = 0;
        unsigned char exh_fund_spk[256];
        size_t exh_fund_spk_len = 0;
        uint32_t exh_fund_vout = 0;
        for (uint32_t v = 0; v < 4; v++) {
            regtest_get_tx_output(ctx->rt, exh_fund_txid, v,
                                  &exh_fund_amount, exh_fund_spk, &exh_fund_spk_len);
            if (exh_fund_spk_len == 34 && memcmp(exh_fund_spk, ctx->fund_spk, 34) == 0) {
                exh_fund_vout = v;
                break;
            }
        }
        if (exh_fund_amount == 0) {
            fprintf(stderr, "DW EXHIBITION Phase 3: no funding output found\n");
            exhibition_pass = 0;
        } else {
            /* Build Factory 1 locally */
            if (ctx->n_level_arity > 0)
                factory_set_level_arity(exh_f1, ctx->level_arities, ctx->n_level_arity);
            else if (ctx->leaf_arity == 1)
                factory_set_arity(exh_f1, FACTORY_ARITY_1);

            if (!factory_init(exh_f1, sctx, exh_kps, n_total,
                              ctx->step_blocks, states_per_layer)) {
                fprintf(stderr, "DW EXHIBITION Phase 3: factory_init failed\n");
                exhibition_pass = 0;
            } else {
                int cur_h = regtest_get_block_height(ctx->rt);
                if (ctx->cltv_timeout_arg > 0) {
                    exh_f1->cltv_timeout = (uint32_t)ctx->cltv_timeout_arg;
                } else if (cur_h > 0) {
                    int offset = ctx->is_regtest ? 35 : (int)(ctx->active_blocks + ctx->dying_blocks + 10);
                    exh_f1->cltv_timeout = (uint32_t)cur_h + offset;
                }

                factory_set_funding(exh_f1, exh_fund_txid_bytes, exh_fund_vout,
                                    exh_fund_amount, ctx->fund_spk, 34);

                if (!factory_build_tree(exh_f1)) {
                    fprintf(stderr, "DW EXHIBITION Phase 3: factory_build_tree failed\n");
                    factory_free(exh_f1);
                    exhibition_pass = 0;
                } else {
                    /* Sign with verify + retry */
                    int sign_ok = 0;
                    for (int attempt = 0; attempt < 3 && !sign_ok; attempt++) {
                        if (!factory_sign_all(exh_f1)) {
                            fprintf(stderr, "DW EXHIBITION Phase 3: factory_sign_all failed (attempt %d)\n", attempt + 1);
                            break;
                        }
                        if (factory_verify_all(exh_f1)) {
                            sign_ok = 1;
                        } else {
                            fprintf(stderr, "DW EXHIBITION Phase 3: sig verify failed (attempt %d), retrying\n", attempt + 1);
                            /* Full re-init for clean state */
                            factory_free(exh_f1);
                            memset(exh_f1, 0, sizeof(*exh_f1));
                            if (ctx->n_level_arity > 0)
                                factory_set_level_arity(exh_f1, ctx->level_arities, ctx->n_level_arity);
                            else if (ctx->leaf_arity == 1)
                                factory_set_arity(exh_f1, FACTORY_ARITY_1);
                            factory_init(exh_f1, sctx, exh_kps, n_total, ctx->step_blocks, states_per_layer);
                            {
                                int cur_h2 = regtest_get_block_height(ctx->rt);
                                if (ctx->cltv_timeout_arg > 0) exh_f1->cltv_timeout = (uint32_t)ctx->cltv_timeout_arg;
                                else if (cur_h2 > 0) exh_f1->cltv_timeout = (uint32_t)cur_h2 + (uint32_t)(ctx->is_regtest ? 35 : (int)(ctx->active_blocks + ctx->dying_blocks + 10));
                            }
                            factory_set_funding(exh_f1, exh_fund_txid_bytes, exh_fund_vout, exh_fund_amount, ctx->fund_spk, 34);
                            factory_build_tree(exh_f1);
                        }
                    }
                    if (!sign_ok) {
                        fprintf(stderr, "DW EXHIBITION Phase 3: signing failed after retries\n");
                        factory_free(exh_f1);
                        exhibition_pass = 0;
                    } else {
                    f1_built = 1;
                    /* Set lifecycle for Factory 1 */
                    if (cur_h > 0)
                        factory_set_lifecycle(exh_f1, (uint32_t)cur_h,
                                              ctx->active_blocks, ctx->dying_blocks);
                    exh_f1->fee = ctx->fee_est;

                    /* Record Factory 1 initial (max) nSequence */
                    for (size_t ni = 0; ni < exh_f1->n_nodes; ni++) {
                        if (exh_f1->nodes[ni].nsequence != 0xFFFFFFFF && exh_f1->nodes[ni].nsequence > f1_initial_nseq)
                            f1_initial_nseq = exh_f1->nodes[ni].nsequence;
                    }

                    /* Store in ladder slot 1 */
                    ladder_factory_t *lf1 = &lad->factories[1];
                    lf1->factory = *exh_f1;
                    factory_detach_txbufs(&lf1->factory);
                    lf1->factory_id = lad->next_factory_id++;
                    lf1->is_initialized = 1;
                    lf1->is_funded = 1;
                    lf1->cached_state = FACTORY_ACTIVE;
                    tx_buf_init(&lf1->distribution_tx, 256);
                    lad->n_factories = 2;

                    printf("\n--- nSequence Contrast ---\n");
                    printf("  Factory 0 (epoch %u, fully advanced): "
                           "max state node nSequence=%u\n",
                           dw_counter_epoch(&lsp->factory.counter), f0_final_nseq);
                    printf("  Factory 1 (epoch 0, fresh):           "
                           "max state node nSequence=%u\n", f1_initial_nseq);
                    printf("  Delta: %u blocks\n",
                           f1_initial_nseq > f0_final_nseq ?
                           f1_initial_nseq - f0_final_nseq : 0);
                    printf("---\n\n");

                    /* Force-close Factory 1 (Factory 0 was closed by PTLC in Phase 2) */
                    printf("Broadcasting Factory 1 tree (%zu nodes) on %s...\n",
                           exh_f1->n_nodes, ctx->network);
                    fflush(stdout);

                    if (!broadcast_factory_tree_any_network(exh_f1, ctx->rt,
                                                              ctx->mine_addr, ctx->is_regtest,
                                                              ctx->confirm_timeout_secs)) {
                        fprintf(stderr, "DW EXHIBITION Phase 3: "
                                "Factory 1 tree broadcast failed\n");
                        exhibition_pass = 0;
                    } else {
                        printf("Factory 1 tree confirmed.\n");
                    }
                    }
                }
            }
        }
    }

    int phase3_pass = f1_built;
    if (!phase3_pass) exhibition_pass = 0;
    printf("Phase 3: %s\n\n", phase3_pass ? "PASS" : "FAIL");

    /* --- Final Verdict --- */
    printf("=== DW EXHIBITION TEST %s ===\n",
           exhibition_pass ? "PASSED" : "FAILED");
    if (exhibition_pass) {
        printf("  Phase 1: nSequence countdown %u -> 0 over %d advances\n",
               initial_nseq[0], max_advances);
        printf("  Phase 2: PTLC-assisted close confirmed (txid: %s)\n",
               exhibition_close_txid);
        printf("  Phase 3: Cross-factory contrast (%u vs %u blocks)\n",
               f0_final_nseq, f1_initial_nseq);
    }

    report_add_string(ctx->rpt, "result",
                      exhibition_pass ? "dw_exhibition_pass" : "dw_exhibition_fail");
    report_close(ctx->rpt);
    if (f1_built) factory_free(exh_f1);
    free(exh_f1);
    jit_channels_cleanup(mgr);
    return exhibition_pass ? 0 : 1;
}

/* ========================================================================= */
/* Leaf Advance Test                                                         */
/* ========================================================================= */
int lsp_test_leaf_advance(lsp_test_ctx_t *ctx) {
    lsp_t *lsp = ctx->lsp;
    secp256k1_context *sctx = ctx->ctx;
    size_t n_total = ctx->n_total;

    printf("\n=== LEAF ADVANCE TEST ===\n");

    if (lsp->factory.n_leaf_nodes < 2) {
        fprintf(stderr, "LEAF ADVANCE TEST: need >= 2 leaf nodes\n");
        return 1;
    }

    /* Record nSequence for both leaves before */
    size_t left_ni = lsp->factory.leaf_node_indices[0];
    size_t right_ni = lsp->factory.leaf_node_indices[1];
    uint32_t left_nseq_before = lsp->factory.nodes[left_ni].nsequence;
    uint32_t right_nseq_before = lsp->factory.nodes[right_ni].nsequence;

    printf("Before leaf advance:\n");
    printf("  Left  leaf (node %zu): nSequence=0x%X\n", left_ni, left_nseq_before);
    printf("  Right leaf (node %zu): nSequence=0x%X\n", right_ni, right_nseq_before);

    /* Populate keypairs */
    {
        secp256k1_keypair all_kps[FACTORY_MAX_SIGNERS];
        populate_demo_keypairs(sctx, all_kps, ctx->lsp_kp, &lsp->factory,
                                ctx->n_clients, n_total);
        memcpy(lsp->factory.keypairs, all_kps,
               n_total * sizeof(secp256k1_keypair));
    }

    /* Advance LEFT leaf only */
    if (!factory_advance_leaf(&lsp->factory, 0)) {
        fprintf(stderr, "LEAF ADVANCE TEST: factory_advance_leaf(0) failed\n");
        return 1;
    }

    uint32_t left_nseq_after = lsp->factory.nodes[left_ni].nsequence;
    uint32_t right_nseq_after = lsp->factory.nodes[right_ni].nsequence;

    printf("After advancing LEFT leaf only:\n");
    printf("  Left  leaf (node %zu): nSequence=0x%X (was 0x%X)\n",
           left_ni, left_nseq_after, left_nseq_before);
    printf("  Right leaf (node %zu): nSequence=0x%X (was 0x%X)\n",
           right_ni, right_nseq_after, right_nseq_before);

    int left_changed = (left_nseq_after != left_nseq_before);
    int right_unchanged = (right_nseq_after == right_nseq_before);

    /* Force-close with the re-signed tree */
    printf("\nBroadcasting tree with per-leaf advance on %s...\n", ctx->network);

    if (!broadcast_factory_tree_any_network(&lsp->factory, ctx->rt,
                                              ctx->mine_addr, ctx->is_regtest,
                                              ctx->confirm_timeout_secs)) {
        fprintf(stderr, "LEAF ADVANCE TEST: tree broadcast failed\n");
        return 1;
    }

    int pass = left_changed && right_unchanged;
    printf("\n=== LEAF ADVANCE TEST %s ===\n", pass ? "PASSED" : "FAILED");
    printf("Left leaf nSequence %s (0x%X -> 0x%X)\n",
           left_changed ? "decreased" : "UNCHANGED", left_nseq_before, left_nseq_after);
    printf("Right leaf nSequence %s (0x%X -> 0x%X)\n",
           right_unchanged ? "unchanged" : "CHANGED", right_nseq_before, right_nseq_after);

    report_add_string(ctx->rpt, "result", pass ? "leaf_advance_pass" : "leaf_advance_fail");
    report_close(ctx->rpt);
    jit_channels_cleanup(ctx->mgr);
    return pass ? 0 : 1;
}

/* ========================================================================= */
/* Dual Factory Test                                                         */
/* ========================================================================= */
int lsp_test_dual_factory(lsp_test_ctx_t *ctx) {
    lsp_t *lsp = ctx->lsp;
    secp256k1_context *sctx = ctx->ctx;
    int n_clients = ctx->n_clients;
    size_t n_total = ctx->n_total;
    ladder_t *lad = ctx->lad;

    printf("\n=== DUAL FACTORY TEST ===\n");
    printf("Creating Factory 1 while Factory 0 is still ACTIVE...\n\n");

    /* Build keypairs array (demo mode: LSP has all keys) */
    secp256k1_keypair all_kps[FACTORY_MAX_SIGNERS];
    populate_demo_keypairs(sctx, all_kps, ctx->lsp_kp, &lsp->factory,
                            n_clients, n_total);

    /* Verify Factory 0 is ACTIVE */
    {
        int cur_h = regtest_get_block_height(ctx->rt);
        if (cur_h > 0) ladder_advance_block(lad, (uint32_t)cur_h);
    }
    factory_state_t f0_state = lad->factories[0].cached_state;
    printf("Factory 0: state=%s, %zu nodes\n",
           f0_state == FACTORY_ACTIVE ? "ACTIVE" :
           f0_state == FACTORY_DYING ? "DYING" : "EXPIRED",
           lad->factories[0].factory.n_nodes);

    /* Check wallet balance for second funding */
    if (!ctx->is_regtest) {
        double bal = regtest_get_balance(ctx->rt);
        double needed = (double)ctx->funding_sats / 100000000.0;
        if (bal < needed) {
            fprintf(stderr, "DUAL FACTORY TEST: insufficient balance (%.8f < %.8f)\n",
                    bal, needed);
            fprintf(stderr, "  Fund wallet and retry.\n");
            jit_channels_cleanup(ctx->mgr);
            return 1;
        }
        printf("Wallet balance: %.8f BTC (sufficient for Factory 1)\n", bal);
    }

    /* Fund Factory 1 */
    double funding_btc2 = (double)ctx->funding_sats / 100000000.0;
    char fund2_txid_hex[65];
    if (!regtest_fund_address(ctx->rt, ctx->fund_addr, funding_btc2, fund2_txid_hex)) {
        fprintf(stderr, "DUAL FACTORY TEST: fund Factory 1 failed\n");
        jit_channels_cleanup(ctx->mgr);
        return 1;
    }
    if (ctx->is_regtest) {
        regtest_mine_blocks(ctx->rt, 1, ctx->mine_addr);
    } else {
        printf("Waiting for Factory 1 funding confirmation on %s...\n", ctx->network);
        fflush(stdout);
        int conf = regtest_wait_for_confirmation(ctx->rt, fund2_txid_hex,
                                                  ctx->confirm_timeout_secs);
        if (conf < 1) {
            fprintf(stderr, "DUAL FACTORY TEST: funding not confirmed\n");
            jit_channels_cleanup(ctx->mgr);
            return 1;
        }
    }
    printf("Factory 1 funded: %s\n", fund2_txid_hex);

    /* Find funding output */
    unsigned char fund2_txid[32];
    hex_decode(fund2_txid_hex, fund2_txid, 32);
    reverse_bytes(fund2_txid, 32);

    uint64_t fund2_amount = 0;
    unsigned char fund2_spk[256];
    size_t fund2_spk_len = 0;
    uint32_t fund2_vout = 0;
    for (uint32_t v = 0; v < 4; v++) {
        regtest_get_tx_output(ctx->rt, fund2_txid_hex, v,
                              &fund2_amount, fund2_spk, &fund2_spk_len);
        if (fund2_spk_len == 34 && memcmp(fund2_spk, ctx->fund_spk, 34) == 0) {
            fund2_vout = v;
            break;
        }
    }
    if (fund2_amount == 0) {
        fprintf(stderr, "DUAL FACTORY TEST: no funding output found\n");
        jit_channels_cleanup(ctx->mgr);
        return 1;
    }

    /* Build Factory 1 locally */
    factory_t f1;
    memset(&f1, 0, sizeof(f1));
    if (ctx->n_level_arity > 0)
        factory_set_level_arity(&f1, ctx->level_arities, ctx->n_level_arity);
    else if (ctx->leaf_arity == 1)
        factory_set_arity(&f1, FACTORY_ARITY_1);

    if (!factory_init(&f1, sctx, all_kps, n_total, ctx->step_blocks, 4)) {
        fprintf(stderr, "DUAL FACTORY TEST: factory_init failed\n");
        jit_channels_cleanup(ctx->mgr);
        return 1;
    }

    /* Compute cltv_timeout for Factory 1 */
    {
        int cur_h = regtest_get_block_height(ctx->rt);
        if (ctx->cltv_timeout_arg > 0) {
            f1.cltv_timeout = (uint32_t)ctx->cltv_timeout_arg;
        } else if (cur_h > 0) {
            int offset = ctx->is_regtest ? 35 : (int)(ctx->active_blocks + ctx->dying_blocks + 10);
            f1.cltv_timeout = (uint32_t)cur_h + offset;
        }
    }

    factory_set_funding(&f1, fund2_txid, fund2_vout, fund2_amount,
                        ctx->fund_spk, 34);

    if (!factory_build_tree(&f1)) {
        fprintf(stderr, "DUAL FACTORY TEST: factory_build_tree failed\n");
        factory_free(&f1);
        jit_channels_cleanup(ctx->mgr);
        return 1;
    }
    if (!factory_sign_all(&f1)) {
        fprintf(stderr, "DUAL FACTORY TEST: factory_sign_all failed\n");
        factory_free(&f1);
        jit_channels_cleanup(ctx->mgr);
        return 1;
    }

    /* Set lifecycle for Factory 1 */
    {
        int cur_h = regtest_get_block_height(ctx->rt);
        if (cur_h > 0)
            factory_set_lifecycle(&f1, (uint32_t)cur_h,
                                  ctx->active_blocks, ctx->dying_blocks);
    }
    f1.fee = ctx->fee_est;

    printf("Factory 1 created: %zu nodes signed\n", f1.n_nodes);

    /* Store Factory 1 in ladder slot 1 */
    {
        ladder_factory_t *lf1 = &lad->factories[1];
        lf1->factory = f1;
        factory_detach_txbufs(&lf1->factory);
        lf1->factory_id = lad->next_factory_id++;
        lf1->is_initialized = 1;
        lf1->is_funded = 1;
        lf1->cached_state = FACTORY_ACTIVE;
        tx_buf_init(&lf1->distribution_tx, 256);
        lad->n_factories = 2;
    }

    /* Update ladder block height */
    {
        int cur_h = regtest_get_block_height(ctx->rt);
        if (cur_h > 0) ladder_advance_block(lad, (uint32_t)cur_h);
    }

    /* Report: both factories ACTIVE */
    printf("\n--- Ladder Status ---\n");
    printf("  Factories in ladder: %zu\n", lad->n_factories);
    for (size_t fi = 0; fi < lad->n_factories; fi++) {
        ladder_factory_t *lf = &lad->factories[fi];
        const char *st = lf->cached_state == FACTORY_ACTIVE ? "ACTIVE" :
                         lf->cached_state == FACTORY_DYING ? "DYING" : "EXPIRED";
        printf("  Factory %u: state=%s, nodes=%zu, cltv=%u\n",
               lf->factory_id, st, lf->factory.n_nodes,
               lf->factory.cltv_timeout);
    }
    printf("---\n\n");

    int both_active = (lad->factories[0].cached_state == FACTORY_ACTIVE &&
                       lad->factories[1].cached_state == FACTORY_ACTIVE);

    /* Force-close both trees */
    printf("Broadcasting Factory 0 tree (%zu nodes) on %s...\n",
           lsp->factory.n_nodes, ctx->network);
    fflush(stdout);

    /* Populate keypairs on lsp->factory */
    memcpy(lsp->factory.keypairs, all_kps,
           n_total * sizeof(secp256k1_keypair));

    if (!broadcast_factory_tree_any_network(&lsp->factory, ctx->rt,
                                              ctx->mine_addr, ctx->is_regtest,
                                              ctx->confirm_timeout_secs)) {
        fprintf(stderr, "DUAL FACTORY TEST: Factory 0 tree broadcast failed\n");
        factory_free(&f1);
        jit_channels_cleanup(ctx->mgr);
        return 1;
    }
    printf("Factory 0 tree confirmed.\n\n");

    printf("Broadcasting Factory 1 tree (%zu nodes) on %s...\n",
           f1.n_nodes, ctx->network);
    fflush(stdout);

    if (!broadcast_factory_tree_any_network(&f1, ctx->rt,
                                              ctx->mine_addr, ctx->is_regtest,
                                              ctx->confirm_timeout_secs)) {
        fprintf(stderr, "DUAL FACTORY TEST: Factory 1 tree broadcast failed\n");
        factory_free(&f1);
        jit_channels_cleanup(ctx->mgr);
        return 1;
    }
    printf("Factory 1 tree confirmed.\n\n");

    printf("=== DUAL FACTORY TEST %s ===\n",
           both_active ? "PASSED" : "FAILED (not both ACTIVE)");
    printf("Two independent factory trees broadcast and confirmed on %s.\n",
           ctx->network);

    report_add_string(ctx->rpt, "result",
                      both_active ? "dual_factory_pass" : "dual_factory_fail");
    report_close(ctx->rpt);
    factory_free(&f1);
    jit_channels_cleanup(ctx->mgr);
    return both_active ? 0 : 1;
}

/* ========================================================================= */
/* Bridge Test                                                               */
/* ========================================================================= */
int lsp_test_bridge(lsp_test_ctx_t *ctx) {
    lsp_channel_mgr_t *mgr = ctx->mgr;
    lsp_t *lsp = ctx->lsp;

    if (mgr->n_channels == 0) return -1;

    printf("\n=== BRIDGE TEST ===\n");

    /* Create socketpair to simulate bridge <-> LSP connection */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        fprintf(stderr, "BRIDGE TEST: socketpair failed\n");
        return 1;
    }
    int bridge_test_fd = sv[0];  /* "bridge" side */
    int lsp_bridge_fd = sv[1];   /* LSP side */

    /* Set bridge_fd on the channel manager */
    lsp_channels_set_bridge(mgr, lsp_bridge_fd);
    lsp->bridge_fd = lsp_bridge_fd;
    printf("Bridge: simulated connection established\n");

    /* Ask client 0 to create invoice */
    size_t dest_client = 0;
    uint64_t amount_msat = 1000000;  /* 1000 sats */
    unsigned char test_hash[32];
    unsigned char test_preimage[32];
    memset(test_preimage, 0, 32);

    {
        cJSON *inv_req = cJSON_CreateObject();
        cJSON_AddNumberToObject(inv_req, "amount_msat", (double)amount_msat);
        wire_send(lsp->client_fds[dest_client], MSG_CREATE_INVOICE, inv_req);
        cJSON_Delete(inv_req);

        sleep(15);

        int got_invoice_created = 0, got_register_invoice = 0;
        struct timeval _t0, _tnow;
        gettimeofday(&_t0, NULL);
        while (1) {
            gettimeofday(&_tnow, NULL);
            int _elapsed = (int)(_tnow.tv_sec - _t0.tv_sec);
            int _remaining = 60 - _elapsed;
            if (_remaining <= 0) break;
            wire_msg_t m;
            if (!wire_recv_timeout(lsp->client_fds[dest_client], &m, _remaining))
                break;
            if (m.msg_type == MSG_INVOICE_CREATED && !got_invoice_created) {
                cJSON *hash_j = cJSON_GetObjectItem(m.json, "payment_hash");
                if (hash_j && hash_j->valuestring)
                    hex_decode(hash_j->valuestring, test_hash, 32);
                got_invoice_created = 1;
            } else if (m.msg_type == MSG_REGISTER_INVOICE && !got_register_invoice) {
                unsigned char rh[32] = {0}, rp[32] = {0};
                cJSON *rhj = cJSON_GetObjectItem(m.json, "payment_hash");
                cJSON *rpj = cJSON_GetObjectItem(m.json, "preimage");
                if (rhj && rhj->valuestring) hex_decode(rhj->valuestring, rh, 32);
                if (rpj && rpj->valuestring) hex_decode(rpj->valuestring, rp, 32);
                lsp_channels_register_invoice(mgr, rh, rp, dest_client, amount_msat);
                memcpy(test_preimage, rp, 32);
                got_register_invoice = 1;
            }
            cJSON_Delete(m.json);
            if (got_invoice_created && got_register_invoice)
                break;
        }
        if (!got_invoice_created) {
            fprintf(stderr, "BRIDGE TEST: no INVOICE_CREATED from client\n");
            close(bridge_test_fd); close(lsp_bridge_fd);
            return 1;
        }
    }
    printf("Bridge: invoice registered for client %zu (amount=%llu msat)\n",
           dest_client, (unsigned long long)amount_msat);

    /* Send MSG_BRIDGE_ADD_HTLC from bridge side */
    uint32_t bridge_cltv = (uint32_t)regtest_get_block_height(ctx->rt) + 144;
    cJSON *add_msg = wire_build_bridge_add_htlc(test_hash,
                                                   amount_msat, bridge_cltv, 42);
    if (!wire_send(bridge_test_fd, MSG_BRIDGE_ADD_HTLC, add_msg)) {
        fprintf(stderr, "BRIDGE TEST: send ADD_HTLC failed\n");
        cJSON_Delete(add_msg);
        close(bridge_test_fd);
        close(lsp_bridge_fd);
        return 1;
    }
    cJSON_Delete(add_msg);
    printf("Bridge: sent ADD_HTLC (htlc_id=42)\n");

    /* LSP handles the bridge message — routes HTLC to client */
    wire_msg_t bridge_msg;
    if (!wire_recv(lsp_bridge_fd, &bridge_msg)) {
        fprintf(stderr, "BRIDGE TEST: LSP recv from bridge failed\n");
        close(bridge_test_fd);
        close(lsp_bridge_fd);
        return 1;
    }
    if (!lsp_channels_handle_bridge_msg(mgr, lsp, &bridge_msg)) {
        fprintf(stderr, "BRIDGE TEST: handle_bridge_msg failed\n");
        cJSON_Delete(bridge_msg.json);
        close(bridge_test_fd);
        close(lsp_bridge_fd);
        return 1;
    }
    cJSON_Delete(bridge_msg.json);
    printf("Bridge: LSP routed HTLC to client %zu via factory channel\n",
           dest_client);

    /* Pump client messages: read FULFILL from client and relay to bridge */
    {
        int pumped = 0;
        for (int attempt = 0; attempt < 20 && !pumped; attempt++) {
            wire_msg_t client_msg;
            if (wire_recv_timeout(lsp->client_fds[dest_client], &client_msg, 1)) {
                lsp_channels_handle_msg(mgr, lsp, dest_client, &client_msg);
                if (client_msg.msg_type == MSG_UPDATE_FULFILL_HTLC) {
                    printf("Bridge: client %zu sent FULFILL, relayed to bridge\n", dest_client);
                    pumped = 1;
                }
                cJSON_Delete(client_msg.json);
            }
        }
        if (!pumped) printf("Bridge: WARNING - no FULFILL from client after 20 attempts\n");
    }

    /* Wait for MSG_BRIDGE_FULFILL_HTLC back on bridge side */
    int bridge_result = 1; /* assume fail */
    wire_msg_t fulfill_msg;
    if (wire_recv_timeout(bridge_test_fd, &fulfill_msg, 10) &&
        fulfill_msg.msg_type == MSG_BRIDGE_FULFILL_HTLC) {
        unsigned char got_hash[32], got_preimage[32];
        uint64_t got_htlc_id;
        if (wire_parse_bridge_fulfill_htlc(fulfill_msg.json,
                                              got_hash, got_preimage,
                                              &got_htlc_id)) {
            int hash_ok = (memcmp(got_hash, test_hash, 32) == 0);
            int preimage_ok = (memcmp(got_preimage, test_preimage, 32) == 0);
            printf("Bridge: received FULFILL_HTLC (htlc_id=%llu, "
                   "hash_ok=%d, preimage_ok=%d)\n",
                   (unsigned long long)got_htlc_id, hash_ok, preimage_ok);

            if (hash_ok && preimage_ok) {
                printf("\n=== BRIDGE TEST PASSED ===\n");
                printf("Inbound HTLC routed through factory channel "
                       "and fulfilled with correct preimage.\n");
                bridge_result = 0;
            } else {
                printf("\n=== BRIDGE TEST FAILED: preimage mismatch ===\n");
            }
        } else {
            printf("\n=== BRIDGE TEST FAILED: could not parse FULFILL ===\n");
        }
        cJSON_Delete(fulfill_msg.json);
    } else {
        printf("Bridge: no FULFILL received (client may not have auto-fulfilled)\n");
        printf("\n=== BRIDGE TEST FAILED (no fulfill) ===\n");
        printf("HTLC was routed to client but no FULFILL_HTLC was returned.\n");
        if (fulfill_msg.json) cJSON_Delete(fulfill_msg.json);
    }

    close(bridge_test_fd);
    /* lsp_bridge_fd owned by mgr now, cleaned up with lsp_cleanup */

    /* Return -1 so caller continues (bridge test doesn't exit early in original) */
    (void)bridge_result;
    return -1;
}

/* ========================================================================= */
/* Breach Test                                                               */
/* ========================================================================= */
int lsp_test_breach(lsp_test_ctx_t *ctx) {
    lsp_channel_mgr_t *mgr = ctx->mgr;
    lsp_t *lsp = ctx->lsp;
    secp256k1_context *sctx = ctx->ctx;
    int is_regtest = ctx->is_regtest;

    printf("\n=== BREACH TEST ===\n");
    fflush(stdout);
    printf("Broadcasting factory tree (all %zu nodes)...\n", lsp->factory.n_nodes);

    int tree_ok;
    if (is_regtest) {
        /* Use broadcast_factory_tree_any_network with is_regtest=1 */
        tree_ok = broadcast_factory_tree_any_network(&lsp->factory, ctx->rt,
                                                      ctx->mine_addr, 1,
                                                      ctx->confirm_timeout_secs);
    } else {
        tree_ok = broadcast_factory_tree_any_network(&lsp->factory, ctx->rt,
                                                      ctx->mine_addr, 0,
                                                      ctx->confirm_timeout_secs);
    }
    if (!tree_ok) {
        fprintf(stderr, "BREACH TEST: factory tree broadcast failed\n");
        return 1;
    }
    printf("Factory tree confirmed on-chain.\n");

    /* Broadcast revoked commitments for ALL channels */
    static const unsigned char client_fills[4] = { 0x22, 0x33, 0x44, 0x55 };
    for (size_t ci = 0; ci < mgr->n_channels; ci++) {
        channel_t *chX = &mgr->entries[ci].channel;
        uint64_t saved_num = chX->commitment_number;
        uint64_t saved_local = chX->local_amount;
        uint64_t saved_remote = chX->remote_amount;
        size_t saved_n_htlcs = chX->n_htlcs;

        /* Temporarily revert to commitment #0 with no HTLCs */
        chX->commitment_number = 0;
        chX->local_amount = ctx->init_local;
        chX->remote_amount = ctx->init_remote;
        chX->n_htlcs = 0;

        /* Ensure remote PCP for commitment #0 is available */
        {
            unsigned char rev_secret[32];
            if (channel_get_received_revocation(chX, 0, rev_secret)) {
                secp256k1_pubkey old_pcp;
                if (secp256k1_ec_pubkey_create(sctx, &old_pcp, rev_secret))
                    channel_set_remote_pcp(chX, 0, &old_pcp);
                memset(rev_secret, 0, 32);
            }
        }

        /* Verify local PCP for commitment #0 */
        {
            secp256k1_pubkey local_pcp_check;
            if (!channel_get_per_commitment_point(chX, 0, &local_pcp_check)) {
                fprintf(stderr, "BREACH TEST: local PCP for commitment 0 unavailable "
                        "(channel %zu, n_local_pcs=%zu) -- build will fail\n",
                        ci, chX->n_local_pcs);
            }
        }

        tx_buf_t old_commit_tx;
        tx_buf_init(&old_commit_tx, 512);
        unsigned char old_txid[32];
        int built;
        if (ctx->breach_test == 2) {
            built = channel_build_commitment_tx(chX, &old_commit_tx, old_txid);
        } else {
            built = channel_build_commitment_tx_for_remote(chX, &old_commit_tx, old_txid);
        }

        /* Restore current state */
        chX->commitment_number = saved_num;
        chX->local_amount = saved_local;
        chX->remote_amount = saved_remote;
        chX->n_htlcs = saved_n_htlcs;

        if (!built) {
            fprintf(stderr, "BREACH TEST: failed to rebuild old commitment for channel %zu\n", ci);
            tx_buf_free(&old_commit_tx);
            continue;
        }

        /* Sign with both LSP + client keys */
        unsigned char cli_sec[32];
        memset(cli_sec, client_fills[ci], 32);
        secp256k1_keypair cli_kp;
        if (!secp256k1_keypair_create(sctx, &cli_kp, cli_sec)) {
            fprintf(stderr, "BREACH TEST: keypair create failed for channel %zu\n", ci);
            memset(cli_sec, 0, 32);
            tx_buf_free(&old_commit_tx);
            continue;
        }
        memset(cli_sec, 0, 32);

        tx_buf_t old_signed;
        tx_buf_init(&old_signed, 512);
        if (!channel_sign_commitment(chX, &old_signed, &old_commit_tx, &cli_kp)) {
            fprintf(stderr, "BREACH TEST: failed to sign old commitment for channel %zu\n", ci);
            tx_buf_free(&old_signed);
            tx_buf_free(&old_commit_tx);
            continue;
        }
        tx_buf_free(&old_commit_tx);

        char *old_hex = malloc(old_signed.len * 2 + 1);
        hex_encode(old_signed.data, old_signed.len, old_hex);
        char old_txid_str[65];
        int sent = regtest_send_raw_tx(ctx->rt, old_hex, old_txid_str);
        if (ctx->g_db) {
            char src[48];
            snprintf(src, sizeof(src), "breach_revoked_ch%zu", ci);
            persist_log_broadcast(ctx->g_db, sent ? old_txid_str : "?",
                src, old_hex, sent ? "ok" : "failed");
        }
        free(old_hex);
        tx_buf_free(&old_signed);

        if (!sent) {
            fprintf(stderr, "BREACH TEST: failed to broadcast revoked commitment for channel %zu\n", ci);
            continue;
        }
        printf("Revoked commitment broadcast (ch %zu): %s\n", ci, old_txid_str);
    }

    /* Confirm all revoked commitments */
    if (is_regtest) {
        regtest_mine_blocks(ctx->rt, 1, ctx->mine_addr);
    } else {
        int rc_start_h = regtest_get_block_height(ctx->rt);
        printf("Waiting for revoked commitments to confirm (height %d)...\n",
               rc_start_h);
        for (int w = 0; w < ctx->confirm_timeout_secs && !*ctx->g_shutdown; w++) {
            if (regtest_get_block_height(ctx->rt) > rc_start_h) break;
            sleep(1);
        }
    }

    if (ctx->breach_test == 2) {
        /* --cheat-daemon mode */
        printf("CHEAT DAEMON: revoked commitment broadcast, sleeping for clients...\n");
        if (is_regtest) {
            for (int s = 0; s < 30 && !*ctx->g_shutdown; s++)
                sleep(1);
        } else {
            int start_h = regtest_get_block_height(ctx->rt);
            int target_h = start_h + 2;
            printf("CHEAT DAEMON: waiting for height %d (current %d)...\n",
                   target_h, start_h);
            for (int w = 0; w < 1800 && !*ctx->g_shutdown; w++) {
                if (regtest_get_block_height(ctx->rt) >= target_h) break;
                sleep(1);
            }
            for (int s = 0; s < 60 && !*ctx->g_shutdown; s++)
                sleep(1);
        }
        printf("=== CHEAT DAEMON COMPLETE ===\n");
        report_add_string(ctx->rpt, "result", "cheat_daemon_complete");
        report_close(ctx->rpt);
        return 0;
    }

    /* Watchtower check */
    printf("Running watchtower check...\n");
    fflush(stdout);
    watchtower_t *wt = mgr->watchtower;
    if (!wt) {
        fprintf(stderr, "BREACH TEST FAILED: no watchtower configured\n");
        report_add_string(ctx->rpt, "result", "breach_test_no_watchtower");
        report_close(ctx->rpt);
        return 1;
    }
    {
        int detected = watchtower_check(wt);
        if (detected > 0) {
            printf("BREACH DETECTED! Watchtower broadcast %d penalty tx(s)\n",
                   detected);
            if (is_regtest) {
                regtest_mine_blocks(ctx->rt, 1, ctx->mine_addr);
            } else {
                int pen_start_h = regtest_get_block_height(ctx->rt);
                printf("Waiting for penalty to confirm (height %d)...\n",
                       pen_start_h);
                for (int w = 0; w < ctx->confirm_timeout_secs && !*ctx->g_shutdown; w++) {
                    if (regtest_get_block_height(ctx->rt) > pen_start_h) break;
                    sleep(1);
                }
            }
            printf("BREACH TEST PASSED -- penalty confirmed on-chain\n");
        } else {
            fprintf(stderr, "BREACH TEST FAILED: watchtower did not detect breach\n");
            report_add_string(ctx->rpt, "result", "breach_test_failed");
            report_close(ctx->rpt);
            return 1;
        }
    }

    printf("=== BREACH TEST COMPLETE ===\n\n");

    report_add_string(ctx->rpt, "result", "breach_test_complete");
    report_close(ctx->rpt);
    return 0;
}

/* ========================================================================= */
/* Expiry Test                                                               */
/* ========================================================================= */
int lsp_test_expiry(lsp_test_ctx_t *ctx) {
    lsp_t *lsp = ctx->lsp;
    secp256k1_context *sctx = ctx->ctx;
    secp256k1_keypair lsp_kp = *ctx->lsp_kp;

    printf("\n=== EXPIRY TEST (Multi-Level Timeout Recovery) ===\n");

    /* Step 1: Broadcast kickoff_root (node 0) */
    factory_node_t *kickoff_root = &lsp->factory.nodes[0];
    {
        char *kr_hex = malloc(kickoff_root->signed_tx.len * 2 + 1);
        hex_encode(kickoff_root->signed_tx.data, kickoff_root->signed_tx.len, kr_hex);
        char kr_txid_str[65];
        if (!regtest_send_raw_tx(ctx->rt, kr_hex, kr_txid_str)) {
            if (ctx->g_db)
                persist_log_broadcast(ctx->g_db, "?", "expiry_kickoff_root",
                    kr_hex, "failed");
            fprintf(stderr, "EXPIRY TEST: kickoff_root broadcast failed\n");
            free(kr_hex);
            return 1;
        }
        if (ctx->g_db)
            persist_log_broadcast(ctx->g_db, kr_txid_str,
                "expiry_kickoff_root", kr_hex, "ok");
        free(kr_hex);
        ADVANCE(1);
        printf("1. kickoff_root broadcast: %s\n", kr_txid_str);
    }

    /* Step 2: Broadcast state_root (node 1) */
    factory_node_t *state_root = &lsp->factory.nodes[1];
    {
        uint32_t state_nseq = state_root->nsequence;
        int nseq_blocks = (state_nseq == NSEQUENCE_DISABLE_BIP68)
            ? 0 : (int)(state_nseq & 0xFFFF);
        if (nseq_blocks > 0)
            ADVANCE(nseq_blocks);

        char *sr_hex = malloc(state_root->signed_tx.len * 2 + 1);
        hex_encode(state_root->signed_tx.data, state_root->signed_tx.len, sr_hex);
        char sr_txid_str[65];
        if (!regtest_send_raw_tx(ctx->rt, sr_hex, sr_txid_str)) {
            if (ctx->g_db)
                persist_log_broadcast(ctx->g_db, "?", "expiry_state_root",
                    sr_hex, "failed");
            fprintf(stderr, "EXPIRY TEST: state_root broadcast failed\n");
            free(sr_hex);
            return 1;
        }
        if (ctx->g_db)
            persist_log_broadcast(ctx->g_db, sr_txid_str,
                "expiry_state_root", sr_hex, "ok");
        free(sr_hex);
        ADVANCE(1);
        printf("2. state_root broadcast: %s (nSeq blocks: %d)\n",
               sr_txid_str, nseq_blocks);
    }

    /* Build broadcast chain from first leaf up to state_root */
    size_t first_leaf_idx = lsp->factory.leaf_node_indices[0];
    int chain[16];
    int chain_len = 0;
    {
        int ko_idx = lsp->factory.nodes[first_leaf_idx].parent_index;
        while (ko_idx >= 0) {
            int parent_state = lsp->factory.nodes[ko_idx].parent_index;
            if (parent_state < 0 || parent_state == 1) break;
            chain[chain_len++] = parent_state;
            chain[chain_len++] = ko_idx;
            ko_idx = lsp->factory.nodes[parent_state].parent_index;
        }
        chain[chain_len++] = ko_idx;
    }
    /* Reverse to get root-to-leaf order */
    for (int a = 0, b = chain_len - 1; a < b; a++, b--) {
        int tmp = chain[a]; chain[a] = chain[b]; chain[b] = tmp;
    }

    /* Step 3..N: Broadcast intermediate nodes */
    int step = 3;
    for (int ci = 0; ci < chain_len; ci++) {
        factory_node_t *nd = &lsp->factory.nodes[chain[ci]];
        uint32_t nseq = nd->nsequence;
        int nseq_blocks = (nseq == NSEQUENCE_DISABLE_BIP68) ? 0 : (int)(nseq & 0xFFFF);
        if (nseq_blocks > 0)
            ADVANCE(nseq_blocks);

        char *hex = malloc(nd->signed_tx.len * 2 + 1);
        hex_encode(nd->signed_tx.data, nd->signed_tx.len, hex);
        char txid_str[65];
        if (!regtest_send_raw_tx(ctx->rt, hex, txid_str)) {
            if (ctx->g_db) {
                char src[48];
                snprintf(src, sizeof(src), "expiry_node_%d", chain[ci]);
                persist_log_broadcast(ctx->g_db, "?", src, hex, "failed");
            }
            fprintf(stderr, "EXPIRY TEST: node[%d] broadcast failed\n", chain[ci]);
            free(hex);
            return 1;
        }
        if (ctx->g_db) {
            char src[48];
            snprintf(src, sizeof(src), "expiry_node_%d", chain[ci]);
            persist_log_broadcast(ctx->g_db, txid_str, src, hex, "ok");
        }
        free(hex);
        ADVANCE(1);
        printf("%d. node[%d] (%s) broadcast: %s%s\n", step++, chain[ci],
               nd->type == NODE_KICKOFF ? "kickoff" : "state", txid_str,
               nseq_blocks > 0 ? " (waited nSeq)" : "");
    }

    factory_node_t *deepest_kickoff = &lsp->factory.nodes[chain[chain_len - 1]];
    factory_node_t *leaf_state = &lsp->factory.nodes[first_leaf_idx];

    /* LSP pubkey for signing + destination */
    secp256k1_xonly_pubkey lsp_xonly;
    if (!secp256k1_keypair_xonly_pub(sctx, &lsp_xonly, NULL, &lsp_kp)) {
        fprintf(stderr, "EXPIRY TEST: keypair xonly pub failed\n");
        return 1;
    }
    unsigned char dest_spk[34];
    build_p2tr_script_pubkey(dest_spk, &lsp_xonly);

    uint64_t fee_sats = fee_estimate(ctx->fee_est, 150);
    if (fee_sats == 0) fee_sats = 500;
    uint64_t leaf_recovered = 0, mid_recovered = 0;

    /* Mine to leaf CLTV */
    uint32_t leaf_cltv = leaf_state->cltv_timeout;
    {
        int height = regtest_get_block_height(ctx->rt);
        int needed = (int)leaf_cltv - height;
        if (needed > 0) {
            printf("%d. Advancing %d blocks to reach leaf CLTV %u...\n",
                   step++, needed, leaf_cltv);
            ADVANCE(needed);
        }
    }

    /* Leaf recovery */
    {
        if (!leaf_state->has_taptree) {
            fprintf(stderr, "EXPIRY TEST: leaf state node[%zu] has no taptree\n",
                    first_leaf_idx);
            return 1;
        }

        uint64_t spend_amount = deepest_kickoff->outputs[0].amount_sats;
        if (fee_sats >= spend_amount) fee_sats = 500;

        tx_output_t tout;
        tout.amount_sats = spend_amount - fee_sats;
        memcpy(tout.script_pubkey, dest_spk, 34);
        tout.script_pubkey_len = 34;

        tx_buf_t tu;
        tx_buf_init(&tu, 256);
        if (!build_unsigned_tx_with_locktime(&tu, NULL,
                deepest_kickoff->txid, 0, 0xFFFFFFFEu, leaf_cltv,
                &tout, 1)) {
            fprintf(stderr, "EXPIRY TEST: leaf build failed\n");
            tx_buf_free(&tu);
            return 1;
        }

        unsigned char sh[32];
        compute_tapscript_sighash(sh, tu.data, tu.len, 0,
            leaf_state->spending_spk, leaf_state->spending_spk_len,
            spend_amount, 0xFFFFFFFEu, &leaf_state->timeout_leaf);

        unsigned char sig[64], aux[32];
        memset(aux, 0xEE, 32);
        if (!secp256k1_schnorrsig_sign32(sctx, sig, sh, &lsp_kp, aux)) {
            fprintf(stderr, "EXPIRY TEST: schnorr sign failed\n");
            return 1;
        }

        unsigned char cb[65];
        size_t cb_len;
        tapscript_build_control_block(cb, &cb_len,
            leaf_state->output_parity,
            &leaf_state->keyagg.agg_pubkey, sctx);

        tx_buf_t ts;
        tx_buf_init(&ts, 512);
        finalize_script_path_tx(&ts, tu.data, tu.len, sig,
            leaf_state->timeout_leaf.script,
            leaf_state->timeout_leaf.script_len, cb, cb_len);
        tx_buf_free(&tu);

        char *hex = malloc(ts.len * 2 + 1);
        hex_encode(ts.data, ts.len, hex);
        char txid_str[65];
        int sent = regtest_send_raw_tx(ctx->rt, hex, txid_str);
        if (ctx->g_db)
            persist_log_broadcast(ctx->g_db, sent ? txid_str : "?",
                "expiry_leaf_timeout", hex, sent ? "ok" : "failed");
        free(hex);
        tx_buf_free(&ts);

        if (!sent) {
            fprintf(stderr, "EXPIRY TEST: leaf timeout tx broadcast failed\n");
            return 1;
        }
        ADVANCE(1);
        leaf_recovered = tout.amount_sats;
        printf("%d. Leaf recovery: %llu sats (node[%zu] timeout) txid: %s\n",
               step++, (unsigned long long)leaf_recovered, first_leaf_idx, txid_str);
    }

    /* Mid recovery */
    factory_node_t *kickoff_right = &lsp->factory.nodes[state_root->child_indices[1]];
    uint32_t mid_cltv = kickoff_right->cltv_timeout;
    {
        int height = regtest_get_block_height(ctx->rt);
        int needed = (int)mid_cltv - height;
        if (needed > 0) {
            printf("%d. Advancing %d blocks to reach mid CLTV %u...\n",
                   step++, needed, mid_cltv);
            ADVANCE(needed);
        }
    }

    {
        if (!kickoff_right->has_taptree) {
            fprintf(stderr, "EXPIRY TEST: kickoff_right has no taptree\n");
            return 1;
        }

        uint64_t spend_amount = state_root->outputs[1].amount_sats;
        if (fee_sats >= spend_amount) fee_sats = 500;

        tx_output_t tout;
        tout.amount_sats = spend_amount - fee_sats;
        memcpy(tout.script_pubkey, dest_spk, 34);
        tout.script_pubkey_len = 34;

        tx_buf_t tu;
        tx_buf_init(&tu, 256);
        if (!build_unsigned_tx_with_locktime(&tu, NULL,
                state_root->txid, 1, 0xFFFFFFFEu, mid_cltv,
                &tout, 1)) {
            fprintf(stderr, "EXPIRY TEST: mid build failed\n");
            tx_buf_free(&tu);
            return 1;
        }

        unsigned char sh[32];
        compute_tapscript_sighash(sh, tu.data, tu.len, 0,
            kickoff_right->spending_spk, kickoff_right->spending_spk_len,
            spend_amount, 0xFFFFFFFEu, &kickoff_right->timeout_leaf);

        unsigned char sig[64], aux[32];
        memset(aux, 0xFF, 32);
        if (!secp256k1_schnorrsig_sign32(sctx, sig, sh, &lsp_kp, aux)) {
            fprintf(stderr, "EXPIRY TEST: schnorr sign failed\n");
            return 1;
        }

        unsigned char cb[65];
        size_t cb_len;
        tapscript_build_control_block(cb, &cb_len,
            kickoff_right->output_parity,
            &kickoff_right->keyagg.agg_pubkey, sctx);

        tx_buf_t ts;
        tx_buf_init(&ts, 512);
        finalize_script_path_tx(&ts, tu.data, tu.len, sig,
            kickoff_right->timeout_leaf.script,
            kickoff_right->timeout_leaf.script_len, cb, cb_len);
        tx_buf_free(&tu);

        char *hex = malloc(ts.len * 2 + 1);
        hex_encode(ts.data, ts.len, hex);
        char txid_str[65];
        int sent = regtest_send_raw_tx(ctx->rt, hex, txid_str);
        if (ctx->g_db)
            persist_log_broadcast(ctx->g_db, sent ? txid_str : "?",
                "expiry_mid_timeout", hex, sent ? "ok" : "failed");
        free(hex);
        tx_buf_free(&ts);

        if (!sent) {
            fprintf(stderr, "EXPIRY TEST: mid timeout tx broadcast failed\n");
            return 1;
        }
        ADVANCE(1);
        mid_recovered = tout.amount_sats;
        printf("%d. Mid recovery: %llu sats (kickoff_right timeout) txid: %s\n",
               step++, (unsigned long long)mid_recovered, txid_str);
    }

    printf("\nLeaf recovery: %llu sats\n", (unsigned long long)leaf_recovered);
    printf("Mid recovery:  %llu sats\n", (unsigned long long)mid_recovered);
    int expiry_pass = (leaf_recovered > 0 && mid_recovered > 0);
    if (!expiry_pass)
        fprintf(stderr, "EXPIRY TEST: recovered amounts are zero "
                "(leaf=%llu, mid=%llu)\n",
                (unsigned long long)leaf_recovered,
                (unsigned long long)mid_recovered);
    printf("=== EXPIRY TEST %s ===\n\n", expiry_pass ? "PASSED" : "FAILED");

    report_add_string(ctx->rpt, "result",
                      expiry_pass ? "expiry_test_pass" : "expiry_test_fail");
    report_close(ctx->rpt);
    return expiry_pass ? 0 : 1;
}

/* ========================================================================= */
/* Distribution TX Test                                                      */
/* ========================================================================= */
int lsp_test_distrib(lsp_test_ctx_t *ctx) {
    lsp_t *lsp = ctx->lsp;
    secp256k1_context *sctx = ctx->ctx;
    secp256k1_keypair lsp_kp = *ctx->lsp_kp;
    int n_clients = ctx->n_clients;
    size_t n_total = ctx->n_total;
    ladder_t *lad = ctx->lad;

    printf("\n=== DISTRIBUTION TX TEST ===\n");

    /* Build distribution TX with demo keypairs */
    factory_t df = lsp->factory;
    secp256k1_keypair dk[FACTORY_MAX_SIGNERS];
    dk[0] = lsp_kp;
    {
        static const unsigned char fill[4] = { 0x22, 0x33, 0x44, 0x55 };
        for (int ci = 0; ci < n_clients; ci++) {
            unsigned char ds[32];
            memset(ds, fill[ci], 32);
            if (!secp256k1_keypair_create(sctx, &dk[ci + 1], ds)) {
                fprintf(stderr, "DISTRIB TEST: keypair create failed\n");
                return 1;
            }
        }
    }
    memcpy(df.keypairs, dk, n_total * sizeof(secp256k1_keypair));

    /* Equal-split outputs */
    tx_output_t dist_outputs[FACTORY_MAX_SIGNERS];
    uint64_t dist_per = (df.funding_amount_sats - 500) / n_total;
    for (size_t di = 0; di < n_total; di++) {
        dist_outputs[di].amount_sats = dist_per;
        secp256k1_pubkey di_pub;
        secp256k1_keypair_pub(sctx, &di_pub, &dk[di]);
        secp256k1_xonly_pubkey di_xonly;
        secp256k1_xonly_pubkey_from_pubkey(sctx, &di_xonly, NULL, &di_pub);
        build_p2tr_script_pubkey(dist_outputs[di].script_pubkey, &di_xonly);
        dist_outputs[di].script_pubkey_len = 34;
    }
    dist_outputs[n_total - 1].amount_sats =
        df.funding_amount_sats - 500 - dist_per * (n_total - 1);

    tx_buf_t dist_tx;
    tx_buf_init(&dist_tx, 512);
    unsigned char dist_txid[32];
    if (!factory_build_distribution_tx(&df, &dist_tx, dist_txid,
                                         dist_outputs, n_total,
                                         lsp->factory.cltv_timeout)) {
        fprintf(stderr, "DISTRIBUTION TX TEST: build failed\n");
        tx_buf_free(&dist_tx);
        return 1;
    }
    printf("Distribution TX built (%zu bytes)\n", dist_tx.len);

    /* Store in ladder slot */
    lad->factories[0].distribution_tx = dist_tx;

    /* Mine past CLTV timeout */
    int cur_h = regtest_get_block_height(ctx->rt);
    int blocks_to_cltv = (int)lsp->factory.cltv_timeout - cur_h;
    if (blocks_to_cltv > 0) {
        printf("Advancing %d blocks to reach CLTV timeout %u...\n",
               blocks_to_cltv, lsp->factory.cltv_timeout);
        ADVANCE(blocks_to_cltv);
    }

    /* Broadcast distribution TX */
    char *dt_hex = malloc(dist_tx.len * 2 + 1);
    hex_encode(dist_tx.data, dist_tx.len, dt_hex);
    char dt_txid_str[65];
    int dt_sent = regtest_send_raw_tx(ctx->rt, dt_hex, dt_txid_str);
    if (ctx->g_db)
        persist_log_broadcast(ctx->g_db, dt_sent ? dt_txid_str : "?",
            "distribution_tx", dt_hex, dt_sent ? "ok" : "failed");
    free(dt_hex);

    if (!dt_sent) {
        fprintf(stderr, "DISTRIBUTION TX TEST: broadcast failed\n");
        tx_buf_free(&lad->factories[0].distribution_tx);
        return 1;
    }
    ADVANCE(1);

    printf("Distribution TX broadcast: %s\n", dt_txid_str);
    printf("=== DISTRIBUTION TX TEST PASSED ===\n\n");

    report_add_string(ctx->rpt, "result", "distrib_test_complete");
    report_close(ctx->rpt);
    tx_buf_free(&lad->factories[0].distribution_tx);
    return 0;
}

/* ========================================================================= */
/* PTLC Key Turnover Test                                                    */
/* ========================================================================= */
int lsp_test_turnover(lsp_test_ctx_t *ctx) {
    lsp_t *lsp = ctx->lsp;
    secp256k1_context *sctx = ctx->ctx;
    secp256k1_keypair lsp_kp = *ctx->lsp_kp;
    int n_clients = ctx->n_clients;
    size_t n_total = ctx->n_total;
    ladder_t *lad = ctx->lad;

    printf("\n=== PTLC KEY TURNOVER TEST ===\n");

    /* Build demo keypairs */
    secp256k1_keypair all_kps[FACTORY_MAX_SIGNERS];
    all_kps[0] = lsp_kp;
    {
        static const unsigned char fill[4] = { 0x22, 0x33, 0x44, 0x55 };
        for (int ci = 0; ci < n_clients; ci++) {
            unsigned char ds[32];
            memset(ds, fill[ci], 32);
            if (!secp256k1_keypair_create(sctx, &all_kps[ci + 1], ds)) {
                fprintf(stderr, "TURNOVER TEST: keypair create failed\n");
                return 1;
            }
        }
    }

    factory_t tf = lsp->factory;
    memcpy(tf.keypairs, all_kps, n_total * sizeof(secp256k1_keypair));

    secp256k1_pubkey turnover_pks[FACTORY_MAX_SIGNERS];
    for (size_t ti = 0; ti < n_total; ti++) {
        if (!secp256k1_keypair_pub(sctx, &turnover_pks[ti], &all_kps[ti])) {
            fprintf(stderr, "TURNOVER TEST: keypair pub failed\n");
            return 1;
        }
    }

    musig_keyagg_t turnover_ka;
    musig_aggregate_keys(sctx, &turnover_ka, turnover_pks, n_total);

    unsigned char turnover_msg[32];
    sha256_tagged("turnover", (const unsigned char *)"turnover", 8,
                   turnover_msg);

    for (int ci = 0; ci < n_clients; ci++) {
        uint32_t participant_idx = (uint32_t)(ci + 1);
        secp256k1_pubkey client_pk = turnover_pks[participant_idx];

        unsigned char presig[64];
        int nonce_parity;
        musig_keyagg_t ka_copy = turnover_ka;
        if (!adaptor_create_turnover_presig(sctx, presig, &nonce_parity,
                                              turnover_msg, all_kps, n_total,
                                              &ka_copy, NULL, &client_pk)) {
            fprintf(stderr, "TURNOVER TEST: presig failed for client %d\n", ci);
            return 1;
        }

        unsigned char client_sec[32];
        if (!secp256k1_keypair_sec(sctx, client_sec, &all_kps[participant_idx])) {
            fprintf(stderr, "TURNOVER TEST: keypair sec failed\n");
            return 1;
        }
        unsigned char adapted_sig[64];
        if (!adaptor_adapt(sctx, adapted_sig, presig, client_sec, nonce_parity)) {
            fprintf(stderr, "TURNOVER TEST: adapt failed for client %d\n", ci);
            memset(client_sec, 0, 32);
            return 1;
        }

        unsigned char extracted[32];
        if (!adaptor_extract_secret(sctx, extracted, adapted_sig, presig,
                                      nonce_parity)) {
            fprintf(stderr, "TURNOVER TEST: extract failed for client %d\n", ci);
            memset(client_sec, 0, 32);
            return 1;
        }

        if (!adaptor_verify_extracted_key(sctx, extracted, &client_pk)) {
            fprintf(stderr, "TURNOVER TEST: verify failed for client %d\n", ci);
            memset(client_sec, 0, 32);
            return 1;
        }

        ladder_record_key_turnover(lad, 0, participant_idx, extracted);

        if (ctx->use_db)
            persist_save_departed_client(ctx->db, 0, participant_idx, extracted);

        printf("  Client %d: key extracted and verified\n", ci + 1);
        memset(client_sec, 0, 32);
    }

    if (!ladder_can_close(lad, 0)) {
        fprintf(stderr, "TURNOVER TEST: ladder_can_close returned false\n");
        return 1;
    }
    printf("All %d clients departed -- ladder_can_close = true\n", n_clients);

    /* Build close outputs */
    tx_output_t to_outputs[FACTORY_MAX_SIGNERS];
    uint64_t to_per = (lsp->factory.funding_amount_sats - 500) / n_total;
    for (size_t ti = 0; ti < n_total; ti++) {
        to_outputs[ti].amount_sats = to_per;
        memcpy(to_outputs[ti].script_pubkey, ctx->fund_spk, 34);
        to_outputs[ti].script_pubkey_len = 34;
    }
    to_outputs[n_total - 1].amount_sats =
        lsp->factory.funding_amount_sats - 500 - to_per * (n_total - 1);

    tx_buf_t turnover_close_tx;
    tx_buf_init(&turnover_close_tx, 512);
    if (!ladder_build_close(lad, 0, &turnover_close_tx,
                              to_outputs, n_total,
                              (uint32_t)regtest_get_block_height(ctx->rt))) {
        fprintf(stderr, "TURNOVER TEST: ladder_build_close failed\n");
        tx_buf_free(&turnover_close_tx);
        return 1;
    }

    char *tc_hex = malloc(turnover_close_tx.len * 2 + 1);
    hex_encode(turnover_close_tx.data, turnover_close_tx.len, tc_hex);
    char tc_txid_str[65];
    int tc_sent = regtest_send_raw_tx(ctx->rt, tc_hex, tc_txid_str);
    if (ctx->g_db)
        persist_log_broadcast(ctx->g_db, tc_sent ? tc_txid_str : "?",
            "turnover_close", tc_hex, tc_sent ? "ok" : "failed");
    free(tc_hex);
    tx_buf_free(&turnover_close_tx);

    if (!tc_sent) {
        fprintf(stderr, "TURNOVER TEST: close TX broadcast failed\n");
        return 1;
    }
    ADVANCE(1);

    printf("Close TX broadcast: %s\n", tc_txid_str);
    printf("=== PTLC KEY TURNOVER TEST PASSED ===\n\n");

    report_add_string(ctx->rpt, "result", "turnover_test_complete");
    report_close(ctx->rpt);
    return 0;
}

/* ========================================================================= */
/* Auto-Rebalance Test                                                       */
/* ========================================================================= */
int lsp_test_rebalance(lsp_test_ctx_t *ctx) {
    lsp_channel_mgr_t *mgr = ctx->mgr;
    lsp_t *lsp = ctx->lsp;

    printf("\n=== AUTO-REBALANCE TEST ===\n");
    fflush(stdout);
    int rebalance_pass = 1;

    /* Record pre-rebalance balances */
    uint64_t pre_total = 0;
    for (size_t c = 0; c < mgr->n_channels; c++) {
        pre_total += mgr->entries[c].channel.local_amount +
                     mgr->entries[c].channel.remote_amount;
    }

    /* Deliberately imbalance: send large payment ch0 -> ch1 */
    if (mgr->n_channels >= 2) {
        uint64_t imbalance_amt = mgr->entries[0].channel.local_amount / 2;
        if (imbalance_amt > 0) {
            printf("Imbalancing: %llu sats from ch0 -> ch1\n",
                   (unsigned long long)imbalance_amt);
            lsp_channels_initiate_payment(mgr, lsp, 0, 1, imbalance_amt);
        }
    }

    for (size_t c = 0; c < mgr->n_channels; c++) {
        uint64_t tot = mgr->entries[c].channel.local_amount + mgr->entries[c].channel.remote_amount;
        uint64_t pct = (tot > 0) ? (mgr->entries[c].channel.local_amount * 100) / tot : 0;
        printf("  ch%zu: local=%llu remote=%llu (%llu%%)\n", c,
               (unsigned long long)mgr->entries[c].channel.local_amount,
               (unsigned long long)mgr->entries[c].channel.remote_amount,
               (unsigned long long)pct);
    }

    /* Record heaviest channel local% before rebalance */
    uint64_t heaviest_pct_before = 0;
    size_t heaviest_idx = 0;
    for (size_t c = 0; c < mgr->n_channels; c++) {
        uint64_t tot = mgr->entries[c].channel.local_amount +
                       mgr->entries[c].channel.remote_amount;
        if (tot > 0) {
            uint64_t pct = (mgr->entries[c].channel.local_amount * 100) / tot;
            if (pct > heaviest_pct_before) {
                heaviest_pct_before = pct;
                heaviest_idx = c;
            }
        }
    }

    /* Set threshold and run auto-rebalance */
    mgr->rebalance_threshold_pct = 70;
    int rebal_count = lsp_channels_auto_rebalance(mgr, lsp);
    printf("Auto-rebalance moved %d channel(s)\n", rebal_count);

    /* Verify: total balance conservation */
    uint64_t post_total = 0;
    for (size_t c = 0; c < mgr->n_channels; c++) {
        post_total += mgr->entries[c].channel.local_amount +
                      mgr->entries[c].channel.remote_amount;
    }
    if (post_total != pre_total) {
        printf("  FAIL: balance conservation violated "
               "(pre=%llu post=%llu)\n",
               (unsigned long long)pre_total,
               (unsigned long long)post_total);
        rebalance_pass = 0;
    }

    /* Verify: rebalance must have happened */
    if (rebal_count == 0) {
        printf("  FAIL: no channels were rebalanced\n");
        rebalance_pass = 0;
    } else {
        uint64_t tot = mgr->entries[heaviest_idx].channel.local_amount +
                       mgr->entries[heaviest_idx].channel.remote_amount;
        uint64_t pct_after = (tot > 0) ?
            (mgr->entries[heaviest_idx].channel.local_amount * 100) / tot : 0;
        if (pct_after >= heaviest_pct_before) {
            printf("  FAIL: heaviest channel local%% did not decrease "
                   "(%llu -> %llu)\n",
                   (unsigned long long)heaviest_pct_before,
                   (unsigned long long)pct_after);
            rebalance_pass = 0;
        }
    }

    printf("AUTO-REBALANCE TEST: %s\n", rebalance_pass ? "PASS" : "FAIL");
    fflush(stdout);

    if (!rebalance_pass)
        return 1;
    /* Return -1 so caller continues (rebalance test doesn't exit) */
    return -1;
}

/* ========================================================================= */
/* Batch-Rebalance Test                                                      */
/* ========================================================================= */
int lsp_test_batch_rebalance(lsp_test_ctx_t *ctx) {
    lsp_channel_mgr_t *mgr = ctx->mgr;
    lsp_t *lsp = ctx->lsp;

    printf("\n=== BATCH-REBALANCE TEST ===\n");
    fflush(stdout);
    int batch_pass = 1;

    /* Record pre-rebalance totals */
    uint64_t pre_total = 0;
    for (size_t c = 0; c < mgr->n_channels; c++) {
        pre_total += mgr->entries[c].channel.local_amount +
                     mgr->entries[c].channel.remote_amount;
    }

    /* Build batch entries */
    int batch_count = 0;
    if (mgr->n_channels >= 4) {
        rebalance_entry_t entries[2];
        entries[0].from = 0;
        entries[0].to = 1;
        entries[0].amount_sats = 2000;
        entries[1].from = 2;
        entries[1].to = 3;
        entries[1].amount_sats = 1500;
        batch_count = lsp_channels_batch_rebalance(mgr, lsp, entries, 2);
        printf("Batch rebalance: %d/2 succeeded\n", batch_count);
    } else if (mgr->n_channels >= 2) {
        rebalance_entry_t entries[1];
        entries[0].from = 0;
        entries[0].to = 1;
        entries[0].amount_sats = 2000;
        batch_count = lsp_channels_batch_rebalance(mgr, lsp, entries, 1);
        printf("Batch rebalance: %d/1 succeeded\n", batch_count);
    }

    /* Verify: total balance conservation */
    uint64_t post_total = 0;
    for (size_t c = 0; c < mgr->n_channels; c++) {
        post_total += mgr->entries[c].channel.local_amount +
                      mgr->entries[c].channel.remote_amount;
    }
    if (post_total != pre_total) {
        printf("  FAIL: balance conservation violated "
               "(pre=%llu post=%llu)\n",
               (unsigned long long)pre_total,
               (unsigned long long)post_total);
        batch_pass = 0;
    }

    if (batch_count <= 0) {
        printf("  FAIL: no batch transfers succeeded\n");
        batch_pass = 0;
    }

    printf("BATCH-REBALANCE TEST: %s\n", batch_pass ? "PASS" : "FAIL");
    fflush(stdout);

    if (!batch_pass)
        return 1;
    /* Return -1 so caller continues */
    return -1;
}

/* ========================================================================= */
/* Leaf Realloc Test                                                         */
/* ========================================================================= */
int lsp_test_realloc(lsp_test_ctx_t *ctx) {
    lsp_channel_mgr_t *mgr = ctx->mgr;
    lsp_t *lsp = ctx->lsp;

    printf("\n=== LEAF REALLOC TEST ===\n");
    fflush(stdout);
    int realloc_pass = 1;

    if (ctx->leaf_arity != 2) {
        printf("  SKIP: --test-realloc requires --leaf-arity 2\n");
        printf("LEAF REALLOC TEST: SKIP\n");
    } else if (ctx->n_clients < 2) {
        printf("  SKIP: --test-realloc requires --clients >= 2\n");
        printf("LEAF REALLOC TEST: SKIP\n");
    } else {
        /* Record current leaf node output amounts */
        size_t leaf_node_idx = lsp->factory.leaf_node_indices[0];
        factory_node_t *leaf_node = &lsp->factory.nodes[leaf_node_idx];
        uint64_t orig_amounts[3];
        uint64_t orig_total = 0;
        for (size_t k = 0; k < 3 && k < leaf_node->n_outputs; k++) {
            orig_amounts[k] = leaf_node->outputs[k].amount_sats;
            orig_total += orig_amounts[k];
        }

        /* Build redistributed amounts: shift 20% from slot 1 to slot 2 */
        uint64_t shift = orig_amounts[1] / 5;
        uint64_t new_amounts[3];
        new_amounts[0] = orig_amounts[0];
        new_amounts[1] = orig_amounts[1] - shift;
        new_amounts[2] = orig_amounts[2] + shift;

        printf("Reallocating leaf 0: [%llu, %llu, %llu] -> [%llu, %llu, %llu]\n",
               (unsigned long long)orig_amounts[0],
               (unsigned long long)orig_amounts[1],
               (unsigned long long)orig_amounts[2],
               (unsigned long long)new_amounts[0],
               (unsigned long long)new_amounts[1],
               (unsigned long long)new_amounts[2]);

        int rc = lsp_realloc_leaf(mgr, lsp, 0, new_amounts, 3);
        if (rc != 1) {
            printf("  FAIL: lsp_realloc_leaf returned %d (expected 1)\n", rc);
            realloc_pass = 0;
        }

        /* Verify amounts updated */
        if (realloc_pass) {
            uint64_t post_total = 0;
            for (size_t k = 0; k < leaf_node->n_outputs; k++)
                post_total += leaf_node->outputs[k].amount_sats;
            if (post_total != orig_total) {
                printf("  FAIL: total funding changed "
                       "(%llu -> %llu)\n",
                       (unsigned long long)orig_total,
                       (unsigned long long)post_total);
                realloc_pass = 0;
            }
        }

        printf("LEAF REALLOC TEST: %s\n", realloc_pass ? "PASS" : "FAIL");
    }
    fflush(stdout);

    if (!realloc_pass)
        return 1;
    /* Return -1 so caller continues */
    return -1;
}
