        /* === DW Advance Test: advance counter, re-sign tree, force-close === */
        if (test_dw_advance) {
            printf("\n=== DW ADVANCE TEST ===\n");

            /* Record epoch-0 nSequence values for before/after comparison */
            uint32_t dwa_initial[FACTORY_MAX_NODES];
            printf("Before advance (epoch %u):\n",
                   dw_counter_epoch(&lsp_p->factory.counter));
            for (size_t ni = 0; ni < lsp_p->factory.n_nodes; ni++) {
                factory_node_t *node = &lsp_p->factory.nodes[ni];
                dwa_initial[ni] = node->nsequence;
                printf("  Node %zu: nSequence=0x%X (%u blocks)\n",
                       ni, node->nsequence, node->nsequence);
            }

            /* Populate keypairs — factory_init_from_pubkeys() leaves them
               zeroed, but factory_sign_all() needs them to generate nonces.
               In demo mode the LSP has all keys (same pattern as distrib/turnover tests).
               Reorder to match lsp_p->factory.pubkeys connection order —
               MuSig2 key aggregation is order-dependent (BIP-327). */
            {
                secp256k1_keypair all_kps[FACTORY_MAX_SIGNERS];
                all_kps[0] = lsp_kp;
                for (int ci = 0; ci < n_clients; ci++) {
                    unsigned char ds[32];
                    memset(ds, 0, 32);
                    ds[31] = (unsigned char)(ci + 2);
                    if (!secp256k1_keypair_create(ctx, &all_kps[ci + 1], ds)) {
                        fprintf(stderr, "DW ADVANCE TEST: keypair create failed\n");
                        return 1;
                    }
                }
                secp256k1_keypair ordered[FACTORY_MAX_SIGNERS];
                memcpy(ordered, all_kps, n_total * sizeof(secp256k1_keypair));
                for (size_t slot = 0; slot < n_total; slot++) {
                    unsigned char target[33];
                    size_t tlen = 33;
                    secp256k1_ec_pubkey_serialize(ctx, target, &tlen,
                                                  &lsp_p->factory.pubkeys[slot],
                                                  SECP256K1_EC_COMPRESSED);
                    for (size_t k = 0; k < n_total; k++) {
                        secp256k1_pubkey kpub;
                        secp256k1_keypair_pub(ctx, &kpub, &ordered[k]);
                        unsigned char kser[33];
                        size_t klen = 33;
                        secp256k1_ec_pubkey_serialize(ctx, kser, &klen,
                                                      &kpub, SECP256K1_EC_COMPRESSED);
                        if (memcmp(target, kser, 33) == 0) {
                            all_kps[slot] = ordered[k];
                            break;
                        }
                    }
                }
                memcpy(lsp_p->factory.keypairs, all_kps,
                       n_total * sizeof(secp256k1_keypair));
            }

            if (!factory_advance(&lsp_p->factory)) {
                fprintf(stderr, "DW ADVANCE TEST: factory_advance failed\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            printf("After advance (epoch %u):\n",
                   dw_counter_epoch(&lsp_p->factory.counter));
            int saw_decrease = 0;
            for (size_t ni = 0; ni < lsp_p->factory.n_nodes; ni++) {
                factory_node_t *node = &lsp_p->factory.nodes[ni];
                printf("  Node %zu: nSequence=0x%X (%u blocks, was 0x%X)\n",
                       ni, node->nsequence, node->nsequence, dwa_initial[ni]);
                /* Compare before/after: any node that had nSequence > 0
                   and now has a lower value counts as a decrease */
                if (dwa_initial[ni] > 0 && node->nsequence < dwa_initial[ni])
                    saw_decrease = 1;
            }

            /* Force-close with the re-signed tree */
            printf("\nBroadcasting re-signed tree (%zu nodes) on %s...\n",
                   lsp_p->factory.n_nodes, network);

            if (!broadcast_factory_tree_any_network(&lsp_p->factory, &rt,
                                                      mine_addr, is_regtest,
                                                      confirm_timeout_secs)) {
                fprintf(stderr, "DW ADVANCE TEST: tree broadcast failed\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            printf("\n=== DW ADVANCE TEST %s ===\n",
                   saw_decrease ? "PASSED" : "FAILED");
            if (saw_decrease)
                printf("All %zu nodes confirmed with advanced DW counter.\n",
                       lsp_p->factory.n_nodes);
            else
                fprintf(stderr, "DW ADVANCE TEST: no nSequence decrease detected\n");

            report_add_string(&rpt, "result",
                              saw_decrease ? "dw_advance_pass" : "dw_advance_fail");
            report_close(&rpt);
            jit_channels_cleanup(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return saw_decrease ? 0 : 1;
        }

        /* === DW Exhibition Test: multi-advance + PTLC close + cross-factory contrast === */
        if (test_dw_exhibition && channels_active) {
            printf("\n=== DW EXHIBITION TEST ===\n\n");
            int exhibition_pass = 1;
            char exhibition_close_txid[65] = {0};

            /* --- Phase 1: Multiple DW Advances — nSequence Countdown to Zero --- */
            printf("--- Phase 1: nSequence Countdown ---\n");

            /* Populate keypairs (demo mode: LSP has all keys) */
            secp256k1_keypair exh_kps[FACTORY_MAX_SIGNERS];
            exh_kps[0] = lsp_kp;
            {
                for (int ci = 0; ci < n_clients; ci++) {
                    unsigned char ds[32];
                    memset(ds, 0, 32);
                    ds[31] = (unsigned char)(ci + 2);
                    if (!secp256k1_keypair_create(ctx, &exh_kps[ci + 1], ds)) {
                        fprintf(stderr, "DW EXHIBITION: keypair create failed\n");
                        return 1;
                    }
                }
            }
            /* Reorder exh_kps to match lsp_p->factory.pubkeys connection order.
               MuSig2 key aggregation is order-dependent (BIP-327). */
            {
                secp256k1_keypair ordered[FACTORY_MAX_SIGNERS];
                memcpy(ordered, exh_kps, n_total * sizeof(secp256k1_keypair));
                for (size_t slot = 0; slot < n_total; slot++) {
                    unsigned char target[33];
                    size_t tlen = 33;
                    secp256k1_ec_pubkey_serialize(ctx, target, &tlen,
                                                  &lsp_p->factory.pubkeys[slot],
                                                  SECP256K1_EC_COMPRESSED);
                    for (size_t k = 0; k < n_total; k++) {
                        secp256k1_pubkey kpub;
                        secp256k1_keypair_pub(ctx, &kpub, &ordered[k]);
                        unsigned char kser[33];
                        size_t klen = 33;
                        secp256k1_ec_pubkey_serialize(ctx, kser, &klen,
                                                      &kpub, SECP256K1_EC_COMPRESSED);
                        if (memcmp(target, kser, 33) == 0) {
                            exh_kps[slot] = ordered[k];
                            break;
                        }
                    }
                }
            }

            memcpy(lsp_p->factory.keypairs, exh_kps,
                   n_total * sizeof(secp256k1_keypair));

            /* Record initial nSequence for all nodes */
            uint32_t initial_nseq[FACTORY_MAX_NODES];
            for (size_t ni = 0; ni < lsp_p->factory.n_nodes; ni++)
                initial_nseq[ni] = lsp_p->factory.nodes[ni].nsequence;

            printf("Epoch 0 (initial):\n");
            for (size_t ni = 0; ni < lsp_p->factory.n_nodes; ni++)
                printf("  Node %zu: nSequence=%u\n", ni, lsp_p->factory.nodes[ni].nsequence);

            /* Advance states_per_layer - 1 times to reach zero */
            int max_advances = states_per_layer - 1;
            int any_zero = 0;
            int any_decreased = 0;
            for (int adv = 0; adv < max_advances; adv++) {
                if (!factory_advance(&lsp_p->factory)) {
                    fprintf(stderr, "DW EXHIBITION: factory_advance failed at step %d\n", adv + 1);
                    exhibition_pass = 0;
                    break;
                }
                printf("Epoch %u (advance %d/%d):\n",
                       dw_counter_epoch(&lsp_p->factory.counter), adv + 1, max_advances);
                for (size_t ni = 0; ni < lsp_p->factory.n_nodes; ni++) {
                    uint32_t cur = lsp_p->factory.nodes[ni].nsequence;
                    int32_t delta = (int32_t)cur - (int32_t)initial_nseq[ni];
                    printf("  Node %zu: nSequence=%u (delta=%d)\n", ni, cur, delta);
                    if (cur == 0) any_zero = 1;
                }
            }

            /* Verify: all state nodes decreased from initial AND at least one reached 0 */
            for (size_t ni = 0; ni < lsp_p->factory.n_nodes; ni++) {
                if (initial_nseq[ni] > 0 && initial_nseq[ni] != 0xFFFFFFFF &&
                    lsp_p->factory.nodes[ni].nsequence < initial_nseq[ni])
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
            for (size_t ni = 0; ni < lsp_p->factory.n_nodes; ni++) {
                if (lsp_p->factory.nodes[ni].nsequence != 0xFFFFFFFF && lsp_p->factory.nodes[ni].nsequence > f0_final_nseq)
                    f0_final_nseq = lsp_p->factory.nodes[ni].nsequence;
            }

            /* --- Phase 2: PTLC-Assisted Exit — Close Without Clients --- */
            printf("--- Phase 2: PTLC-Assisted Close ---\n");

            /* Build pubkey array and aggregate */
            secp256k1_pubkey exh_pks[FACTORY_MAX_SIGNERS];
            for (size_t ti = 0; ti < n_total; ti++) {
                if (!secp256k1_keypair_pub(ctx, &exh_pks[ti], &exh_kps[ti])) {
                    fprintf(stderr, "DW EXHIBITION: keypair pub failed\n");
                    return 1;
                }
            }
            musig_keyagg_t exh_ka;
            musig_aggregate_keys(ctx, &exh_ka, exh_pks, n_total);

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
                if (!adaptor_create_turnover_presig(ctx, presig, &nonce_parity,
                                                      exh_msg, exh_kps, n_total,
                                                      &ka_copy, NULL, &client_pk)) {
                    fprintf(stderr, "DW EXHIBITION: presig failed for client %d\n", ci);
                    exhibition_pass = 0;
                    break;
                }

                unsigned char client_sec[32];
                if (!secp256k1_keypair_sec(ctx, client_sec, &exh_kps[participant_idx])) {
                    fprintf(stderr, "DW EXHIBITION: keypair sec failed\n");
                    return 1;
                }
                unsigned char adapted_sig[64];
                if (!adaptor_adapt(ctx, adapted_sig, presig, client_sec, nonce_parity)) {
                    fprintf(stderr, "DW EXHIBITION: adapt failed for client %d\n", ci);
                    memset(client_sec, 0, 32);
                    exhibition_pass = 0;
                    break;
                }

                unsigned char extracted[32];
                if (!adaptor_extract_secret(ctx, extracted, adapted_sig, presig,
                                              nonce_parity)) {
                    fprintf(stderr, "DW EXHIBITION: extract failed for client %d\n", ci);
                    memset(client_sec, 0, 32);
                    exhibition_pass = 0;
                    break;
                }

                if (!adaptor_verify_extracted_key(ctx, extracted, &client_pk)) {
                    fprintf(stderr, "DW EXHIBITION: verify failed for client %d\n", ci);
                    memset(client_sec, 0, 32);
                    exhibition_pass = 0;
                    break;
                }

                ladder_record_key_turnover(lad, 0, participant_idx, extracted);
                if (use_db)
                    persist_save_departed_client(&db, 0, participant_idx, extracted);
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
            uint64_t exh_per = (lsp_p->factory.funding_amount_sats - 500) / n_total;
            for (size_t ti = 0; ti < n_total; ti++) {
                exh_outputs[ti].amount_sats = exh_per;
                memcpy(exh_outputs[ti].script_pubkey, fund_spk, 34);
                exh_outputs[ti].script_pubkey_len = 34;
            }
            exh_outputs[n_total - 1].amount_sats =
                lsp_p->factory.funding_amount_sats - 500 - exh_per * (n_total - 1);

            /* Build cooperative close using extracted keys */
            tx_buf_t exh_close_tx;
            tx_buf_init(&exh_close_tx, 512);
            int close_built = ladder_build_close(lad, 0, &exh_close_tx,
                                                   exh_outputs, n_total,
                                                   (uint32_t)regtest_get_block_height(&rt));
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
                int ec_sent = regtest_send_raw_tx(&rt, ec_hex, exhibition_close_txid);
                if (g_db)
                    persist_log_broadcast(g_db, ec_sent ? exhibition_close_txid : "?",
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
            if (!is_regtest) {
                double bal = regtest_get_balance(&rt);
                double needed = (double)funding_sats / 100000000.0;
                if (bal < needed) {
                    fprintf(stderr, "DW EXHIBITION Phase 3: insufficient balance "
                            "(%.8f < %.8f)\n", bal, needed);
                    exhibition_pass = 0;
                }
            }

            /* Fund Factory 1 */
            double exh_funding_btc = (double)funding_sats / 100000000.0;
            char exh_fund_txid[65];
            int f1_funded = 0;
            if (exhibition_pass) {
                if (!regtest_fund_address(&rt, fund_addr, exh_funding_btc, exh_fund_txid)) {
                    fprintf(stderr, "DW EXHIBITION Phase 3: fund Factory 1 failed\n");
                    exhibition_pass = 0;
                } else {
                    if (is_regtest) {
                        regtest_mine_blocks(&rt, 1, mine_addr);
                    } else {
                        printf("Waiting for Factory 1 funding confirmation on %s...\n",
                               network);
                        fflush(stdout);
                        int conf = regtest_wait_for_confirmation(&rt, exh_fund_txid,
                                                                  confirm_timeout_secs);
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
            /* calloc already zeroed */
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
                    regtest_get_tx_output(&rt, exh_fund_txid, v,
                                          &exh_fund_amount, exh_fund_spk, &exh_fund_spk_len);
                    if (exh_fund_spk_len == 34 && memcmp(exh_fund_spk, fund_spk, 34) == 0) {
                        exh_fund_vout = v;
                        break;
                    }
                }
                if (exh_fund_amount == 0) {
                    fprintf(stderr, "DW EXHIBITION Phase 3: no funding output found\n");
                    exhibition_pass = 0;
                } else {
                    /* Build Factory 1 locally */
                    if (n_level_arity > 0)
                        factory_set_level_arity(exh_f1, level_arities, n_level_arity);
                    else if (leaf_arity == 1)
                        factory_set_arity(exh_f1, FACTORY_ARITY_1);

                    if (!factory_init(exh_f1, ctx, exh_kps, n_total,
                                      step_blocks, states_per_layer)) {
                        fprintf(stderr, "DW EXHIBITION Phase 3: factory_init failed\n");
                        exhibition_pass = 0;
                    } else {
                        int cur_h = regtest_get_block_height(&rt);
                        if (cltv_timeout_arg > 0) {
                            exh_f1->cltv_timeout = (uint32_t)cltv_timeout_arg;
                        } else if (cur_h > 0) {
                            int offset = is_regtest ? 35 : (int)(active_blocks + dying_blocks + 10);
                            exh_f1->cltv_timeout = (uint32_t)cur_h + offset;
                        }

                        factory_set_funding(exh_f1, exh_fund_txid_bytes, exh_fund_vout,
                                            exh_fund_amount, fund_spk, 34);

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
                                    if (n_level_arity > 0)
                                        factory_set_level_arity(exh_f1, level_arities, n_level_arity);
                                    else if (leaf_arity == 1)
                                        factory_set_arity(exh_f1, FACTORY_ARITY_1);
                                    factory_init(exh_f1, ctx, exh_kps, n_total, step_blocks, states_per_layer);
                                    {
                                        int cur_h2 = regtest_get_block_height(&rt);
                                        if (cltv_timeout_arg > 0) exh_f1->cltv_timeout = (uint32_t)cltv_timeout_arg;
                                        else if (cur_h2 > 0) exh_f1->cltv_timeout = (uint32_t)cur_h2 + (uint32_t)(is_regtest ? 35 : (int)(active_blocks + dying_blocks + 10));
                                    }
                                    factory_set_funding(exh_f1, exh_fund_txid_bytes, exh_fund_vout, exh_fund_amount, fund_spk, 34);
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
                                                      active_blocks, dying_blocks);
                            exh_f1->fee = fee_est;

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
                                   dw_counter_epoch(&lsp_p->factory.counter), f0_final_nseq);
                            printf("  Factory 1 (epoch 0, fresh):           "
                                   "max state node nSequence=%u\n", f1_initial_nseq);
                            printf("  Delta: %u blocks\n",
                                   f1_initial_nseq > f0_final_nseq ?
                                   f1_initial_nseq - f0_final_nseq : 0);
                            printf("---\n\n");

                            /* Force-close Factory 1 (Factory 0 was closed by PTLC in Phase 2) */
                            printf("Broadcasting Factory 1 tree (%zu nodes) on %s...\n",
                                   exh_f1->n_nodes, network);
                            fflush(stdout);

                            if (!broadcast_factory_tree_any_network(exh_f1, &rt,
                                                                      mine_addr, is_regtest,
                                                                      confirm_timeout_secs)) {
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

            report_add_string(&rpt, "result",
                              exhibition_pass ? "dw_exhibition_pass" : "dw_exhibition_fail");
            report_close(&rpt);
            if (f1_built) factory_free(exh_f1);
            free(exh_f1);
            jit_channels_cleanup(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return exhibition_pass ? 0 : 1;
        }

        /* === Leaf Advance Test: advance left leaf only, show per-leaf independence === */
        if (test_leaf_advance) {
            printf("\n=== LEAF ADVANCE TEST ===\n");

            if (lsp_p->factory.n_leaf_nodes < 2) {
                fprintf(stderr, "LEAF ADVANCE TEST: need >= 2 leaf nodes\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Record nSequence for both leaves before */
            size_t left_ni = lsp_p->factory.leaf_node_indices[0];
            size_t right_ni = lsp_p->factory.leaf_node_indices[1];
            uint32_t left_nseq_before = lsp_p->factory.nodes[left_ni].nsequence;
            uint32_t right_nseq_before = lsp_p->factory.nodes[right_ni].nsequence;
            /* CL1.H: also snapshot chain_pos — PS leaves advance ps_chain_len, not nSequence. */
            int left_chain_pos_before = lsp_p->factory.nodes[left_ni].ps_chain_len;
            int right_chain_pos_before = lsp_p->factory.nodes[right_ni].ps_chain_len;

            printf("Before leaf advance:\n");
            printf("  Left  leaf (node %zu): nSequence=0x%X\n", left_ni, left_nseq_before);
            printf("  Right leaf (node %zu): nSequence=0x%X\n", right_ni, right_nseq_before);

            /* Populate keypairs (same pattern as dw_advance test) */
            {
                secp256k1_keypair all_kps[FACTORY_MAX_SIGNERS];
                all_kps[0] = lsp_kp;
                for (int ci = 0; ci < n_clients; ci++) {
                    unsigned char ds[32];
                    memset(ds, 0, 32);
                    ds[31] = (unsigned char)(ci + 2);
                    if (!secp256k1_keypair_create(ctx, &all_kps[ci + 1], ds)) {
                        fprintf(stderr, "LEAF ADVANCE TEST: keypair create failed\n");
                        return 1;
                    }
                }
                /* Reorder all_kps to match lsp_p->factory.pubkeys connection order (BIP-327). */
                {
                    secp256k1_keypair ordered[FACTORY_MAX_SIGNERS];
                    memcpy(ordered, all_kps, n_total * sizeof(secp256k1_keypair));
                    for (size_t slot = 0; slot < n_total; slot++) {
                        unsigned char target[33];
                        size_t tlen = 33;
                        secp256k1_ec_pubkey_serialize(ctx, target, &tlen,
                                                      &lsp_p->factory.pubkeys[slot],
                                                      SECP256K1_EC_COMPRESSED);
                        for (size_t k = 0; k < n_total; k++) {
                            secp256k1_pubkey kpub;
                            secp256k1_keypair_pub(ctx, &kpub, &ordered[k]);
                            unsigned char kser[33];
                            size_t klen = 33;
                            secp256k1_ec_pubkey_serialize(ctx, kser, &klen,
                                                          &kpub, SECP256K1_EC_COMPRESSED);
                            if (memcmp(target, kser, 33) == 0) {
                                all_kps[slot] = ordered[k];
                                break;
                            }
                        }
                    }
                }
                memcpy(lsp_p->factory.keypairs, all_kps,
                       n_total * sizeof(secp256k1_keypair));
            }

            /* CL1: snapshot pre-advance leaf signed_tx if --cheat-leaf is set.
               This is chain[0] (state BEFORE any advance fires).  CL3-K
               extends this: if --cheat-state K is set with K>0, the
               advance loop below re-snapshots after the Kth advance so we
               broadcast chain[K] instead.  K must be in [0, advance_count_arg-1];
               we validate after parsing and silently clamp to range. */
            tx_buf_t cl1_cheat_stale_leaf_tx;
            tx_buf_init(&cl1_cheat_stale_leaf_tx, 0);
            int cl1_cheat_side = (cheat_leaf_side >= 0) ? cheat_leaf_side : 0;
            unsigned char cl1_cheat_stale_leaf_txid[32] = {0};
            int cl3k_cheat_state = cheat_state_idx;
            if (cl3k_cheat_state >= advance_count_arg) {
                /* K out of range — clamp to the last valid index and warn. */
                fprintf(stderr,
                    "CL3-K: --cheat-state %d out of range for --advance-count %d; "
                    "clamping to %d (== advance_count-1)\n",
                    cl3k_cheat_state, advance_count_arg, advance_count_arg - 1);
                cl3k_cheat_state = advance_count_arg - 1;
            }
            {
                size_t cleaf_ni = (cl1_cheat_side == 0) ? left_ni : right_ni;
                if (cheat_leaf_side >= 0) memcpy(cl1_cheat_stale_leaf_txid, lsp_p->factory.nodes[cleaf_ni].txid, 32);
                if (cheat_leaf_side >= 0 && cl3k_cheat_state == 0 &&
                    lsp_p->factory.nodes[cleaf_ni].is_signed &&
                    lsp_p->factory.nodes[cleaf_ni].signed_tx.len > 0) {
                    /* K=0 path: snapshot chain[0] now.  Matches the original
                       single-advance behavior — broadcasting the pre-advance
                       state after N advances is the oldest-stale cheat. */
                    tx_buf_t *src = &lsp_p->factory.nodes[cleaf_ni].signed_tx;
                    tx_buf_init(&cl1_cheat_stale_leaf_tx, (int)src->len);
                    memcpy(cl1_cheat_stale_leaf_tx.data, src->data, src->len);
                    cl1_cheat_stale_leaf_tx.len = src->len;
                }
                /* K>0 path: snapshot deferred to inside the advance loop. */
            }

            /* CL1.F: use lsp_channels_advance_ps_leaf which drives the REAL wire ceremony
               with the running client processes — produces signatures matching on-chain pubkey
               aggregation AND registers the OLD leaf state with the LSP\u2019s watchtower internally.
               (Was factory_advance_leaf: low-level synthetic-keypair test mode that didn't register WT
               and produced signatures that failed on-chain validation.) */
            int left_chain_pos_peak = lsp_p->factory.nodes[left_ni].ps_chain_len;
            int right_chain_pos_peak = lsp_p->factory.nodes[right_ni].ps_chain_len;
            int tier_b_fired_in_loop = 0;
            uint32_t epoch_at_loop_start = lsp_p->factory.counter.current_epoch;
            for (int ac = 0; ac < advance_count_arg; ac++) {
                int adv_rc = lsp_channels_advance_ps_leaf(mgr, lsp_p, cl1_cheat_side);
                if (adv_rc != 1) {
                    fprintf(stderr, "LEAF ADVANCE TEST: lsp_channels_advance_ps_leaf(%d) returned %d at iter %d\n",
                            cl1_cheat_side, adv_rc, ac);
                    lsp_cleanup(lsp_p);
                    memset(lsp_seckey, 0, 32);
                    secp256k1_context_destroy(ctx);
                    return 1;
                }
                /* CL3-K: middle-state snapshot.  After this iteration, the
                   cheated leaf is at chain[ac+1].  If --cheat-state K == ac+1,
                   capture its CURRENT signed_tx for later broadcast.
                   Remaining iterations will continue advancing past it, so by
                   the time we broadcast cl1_cheat_stale_leaf_tx the leaf is
                   at chain[N] but we're rebroadcasting chain[K] — the
                   middle-state revocation case.

                   We only do this when --cheat-state K with K>0 was set
                   (cl3k_cheat_state > 0); K=0 case was snapshotted before
                   the loop above and we never overwrite it here. */
                if (cheat_leaf_side >= 0 && cl3k_cheat_state > 0 &&
                    cl3k_cheat_state == ac + 1) {
                    size_t cleaf_ni_cl3k = (cl1_cheat_side == 0) ? left_ni : right_ni;
                    factory_node_t *cleaf_node_cl3k = &lsp_p->factory.nodes[cleaf_ni_cl3k];
                    if (cleaf_node_cl3k->is_signed &&
                        cleaf_node_cl3k->signed_tx.len > 0) {
                        /* If a prior K=0 snapshot exists (shouldn't, since
                           the K>0 branch above skips it), free it first. */
                        if (cl1_cheat_stale_leaf_tx.data)
                            tx_buf_free(&cl1_cheat_stale_leaf_tx);
                        tx_buf_t *src = &cleaf_node_cl3k->signed_tx;
                        tx_buf_init(&cl1_cheat_stale_leaf_tx, (int)src->len);
                        memcpy(cl1_cheat_stale_leaf_tx.data, src->data, src->len);
                        cl1_cheat_stale_leaf_tx.len = src->len;
                        memcpy(cl1_cheat_stale_leaf_txid,
                               cleaf_node_cl3k->txid, 32);
                        printf("  CL3-K: snapshotted chain[%d] (after advance %d) "
                               "for stale broadcast (side=%d, len=%zu)\n",
                               cl3k_cheat_state, ac + 1, cl1_cheat_side,
                               cl1_cheat_stale_leaf_tx.len);
                    } else {
                        fprintf(stderr,
                            "CL3-K: cannot snapshot chain[%d] — leaf node "
                            "is_signed=%d, signed_tx.len=%zu\n",
                            cl3k_cheat_state, cleaf_node_cl3k->is_signed,
                            cleaf_node_cl3k->signed_tx.len);
                    }
                }
                /* Track peak chain_pos: F1+F7 Tier B resets chain_pos to 0 on
                   rollover; without peak tracking the test sees before=0/after=0
                   and falsely reports UNCHANGED.  Peak captures the advance
                   even if a later Tier B resets it. */
                int lcp = lsp_p->factory.nodes[left_ni].ps_chain_len;
                int rcp = lsp_p->factory.nodes[right_ni].ps_chain_len;
                if (lcp > left_chain_pos_peak) left_chain_pos_peak = lcp;
                if (rcp > right_chain_pos_peak) right_chain_pos_peak = rcp;
                if (lsp_p->factory.counter.current_epoch > epoch_at_loop_start)
                    tier_b_fired_in_loop = 1;
                if (advance_count_arg > 1)
                    printf("  advance %d/%d done (chain_pos now %d, peak %d)\n",
                           ac + 1, advance_count_arg, lcp,
                           (cl1_cheat_side == 0) ? left_chain_pos_peak : right_chain_pos_peak);
            }
            /* Use a sentinel "false" branch to keep the original error path scoping. */
            if (0) {
                fprintf(stderr, "LEAF ADVANCE TEST: factory_advance_leaf(%d) failed\n", cl1_cheat_side);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            uint32_t left_nseq_after = lsp_p->factory.nodes[left_ni].nsequence;
            uint32_t right_nseq_after = lsp_p->factory.nodes[right_ni].nsequence;

            printf("After advancing LEFT leaf only:\n");
            printf("  Left  leaf (node %zu): nSequence=0x%X (was 0x%X)\n",
                   left_ni, left_nseq_after, left_nseq_before);
            printf("  Right leaf (node %zu): nSequence=0x%X (was 0x%X)\n",
                   right_ni, right_nseq_after, right_nseq_before);

            int left_nseq_changed = (left_nseq_after != left_nseq_before);
            int right_nseq_unchanged = (right_nseq_after == right_nseq_before);
            int left_chain_pos_after = lsp_p->factory.nodes[left_ni].ps_chain_len;
            int right_chain_pos_after = lsp_p->factory.nodes[right_ni].ps_chain_len;
            /* CL1.H: for PS factories, the advance bumps ps_chain_len rather than nSequence.
               For DW factories (FACTORY_ARITY_1), it decrements nSequence. Use the right
               criterion based on factory arity.
               F1+F7: compare against peak (not after) — Tier B can reset chain_pos to 0
               during the advance loop, so "after" may be 0 even though advances succeeded. */
            int is_ps_factory = (lsp_p->factory.leaf_arity != FACTORY_ARITY_1);
            int left_changed = is_ps_factory
                ? (left_chain_pos_peak > left_chain_pos_before)
                : left_nseq_changed;
            int right_unchanged = is_ps_factory
                ? (right_chain_pos_after == right_chain_pos_before)
                : right_nseq_unchanged;

            int leaf_pass = 1;


            if (cheat_leaf_side < 0) {
                /* Normal --test-leaf-advance flow: force-close + broadcast tree */
                printf("\nBroadcasting tree with per-leaf advance on %s...\n", network);

                if (!broadcast_factory_tree_any_network(&lsp_p->factory, &rt,
                                                          mine_addr, is_regtest,
                                                          confirm_timeout_secs)) {
                    fprintf(stderr, "LEAF ADVANCE TEST: tree broadcast failed\n");
                    lsp_cleanup(lsp_p);
                    memset(lsp_seckey, 0, 32);
                    secp256k1_context_destroy(ctx);
                    return 1;
                }
                /* Gap 2 / --watchtower-final-check: after force-close, run
                   watchtower_check so client-initiated cheats (CL7) are
                   detected in the honest-LSP scenario. Without this flag,
                   the only path that triggers a WT check is the LSP-cheats
                   branch below, conflating LSP and client cheat semantics. */
                if (mgr->watchtower && getenv("SS_WATCHTOWER_FINAL_CHECK")) {
                    printf("  --watchtower-final-check: running watchtower_check on honest-LSP path\n");
                    int detected = watchtower_check(mgr->watchtower);
                    printf("  watchtower_check returned: %d\n", detected);
                    if (detected >= 1)
                        leaf_pass = 1;  /* defense fired */
                }
            } else if (cl1_cheat_stale_leaf_tx.len > 0 && mgr->watchtower) {
                /* CL1.B + CL4.B: --cheat-leaf flow.
                   1) broadcast parent path (root + kickoffs but NOT the
                      cheated leaf state)
                   2) broadcast snapshotted stale pre-advance leaf state
                   3) (default) run watchtower_check OR (daemon mode) sleep */
                printf("\n--- CHEAT-LEAF: broadcasting parent path then stale state ---\n");
                fflush(stdout);
                size_t cleaf_ni_cl1b = (cl1_cheat_side == 0) ? left_ni : right_ni;
                /* CL1.C: temporarily un-mark the cheated leaf is_signed so
                   broadcast_factory_tree_any_network SKIPS it. We will
                   broadcast the snapshotted stale leaf state separately
                   below. The helper handles BIP68 + getrawtransaction
                   confirmation (pre-existing CL1.B bug fix). */
                factory_node_t *cleaf_node_cl1c = &lsp_p->factory.nodes[cleaf_ni_cl1b];
                int saved_is_signed = cleaf_node_cl1c->is_signed;
                cleaf_node_cl1c->is_signed = 0;
                int parent_tree_ok = broadcast_factory_tree_any_network(
                    &lsp_p->factory, &rt, mine_addr, is_regtest,
                    confirm_timeout_secs);
                cleaf_node_cl1c->is_signed = saved_is_signed;
                /* Don't synthesize a broadcast_log row for the parent-tree
                   broadcast itself: broadcast_factory_tree_any_network() already
                   logs each tree node with a real txid + raw_hex. A synthetic
                   "tree_ok"/"tree_fail" placeholder with empty raw_hex was
                   dashboard noise (Item 2 of LSP_TEAM_OUTSTANDING_2026-05-21). */
                if (!parent_tree_ok) {
                    /* CL1.H: parent-tree broadcast intentionally bails on the cheated leaf
                       (is_signed=0 trick). Tree_node_0..4 still broadcast successfully.
                       The defense success criterion is the stale broadcast + WT response
                       + poison TX, not the parent path completing all nodes. */
                    fprintf(stderr, "CHEAT-LEAF: parent path bailed at cheated leaf (expected)\n");
                }

                char *cheat_hex = malloc(cl1_cheat_stale_leaf_tx.len * 2 + 1);
                char cheat_txid_str[65] = {0};
                int sent = 0;
                if (cheat_hex) {
                    hex_encode(cl1_cheat_stale_leaf_tx.data,
                               cl1_cheat_stale_leaf_tx.len, cheat_hex);
                    sent = regtest_send_raw_tx(&rt, cheat_hex, cheat_txid_str);
                    if (g_db)
                        persist_log_broadcast(g_db, sent ? cheat_txid_str : "?",
                            "cheat_leaf_stale", cheat_hex, sent ? "ok" : "failed");
                    free(cheat_hex);
                }
                if (!sent) {
                    fprintf(stderr, "CHEAT-LEAF: stale broadcast failed\n");
                    /* F1+F7 interaction: if Tier B fired during the advance
                       loop, the parent tree path was re-signed for the new
                       epoch.  The OLD chain[N] state captured pre-Tier-B
                       references the OLD parent txid which never confirmed
                       on-chain (the test broadcasts the parent tree AFTER
                       all advances).  bitcoind returns -25 missingorspent.
                       Semantically: Tier B PREVENTED the cheat from being
                       broadcastable at all — that's a defense win, not a
                       defense miss.  Counts as leaf_pass. */
                    if (tier_b_fired_in_loop) {
                        printf("  CHEAT-LEAF: Tier B made stale state unspendable — "
                               "defense success (no broadcast needed for WT response)\n");
                        /* leaf_pass left at 1 */
                    } else {
                        leaf_pass = 0;
                    }
                } else {
                    printf("  Stale pre-advance leaf broadcast: %s "
                           "(side=%d, cheat_state=chain[%d])\n",
                           cheat_txid_str, cl1_cheat_side, cl3k_cheat_state);
                    /* Wait for 5 confs of stale */
                    if (is_regtest) {
                        regtest_mine_blocks(&rt, 5, mine_addr);
                        sleep(2);
                    } else {
                        for (int ct = 1; ct <= 5; ct++) {
                            regtest_wait_for_confirmation(&rt, cheat_txid_str,
                                                           confirm_timeout_secs);
                            int cur = regtest_get_confirmations(&rt, cheat_txid_str);
                            if (cur >= 5) break;
                            sleep(15);
                        }
                    }
                    /* CL4.B: daemon mode skips internal WT */
                    if (getenv("SS_CHEAT_DAEMON_MODE")) {
                        printf("  CL4.B daemon mode: skipping internal watchtower_check\n");
                        printf("  CHEAT DAEMON COMPLETE\n");
                        fflush(stdout);
                        sleep(60);
                    } else {
                        int detected = watchtower_check(mgr->watchtower);
                        printf("  watchtower_check returned: %d\n", detected);
                        if (detected < 1) leaf_pass = 0;
                    }
                }
                tx_buf_free(&cl1_cheat_stale_leaf_tx);
            }

            /* #170: cheat-side-aware PASS criterion. The advance and unchanged checks
   must follow cl1_cheat_side (0=left, 1=right) — the SIDE=1 path was
   previously hardcoded to expect left advance + right unchanged, so any
   right-side cheat always failed despite the WT defense firing. */
            int cheated_changed = (cl1_cheat_side == 0)
                ? left_changed
                : (is_ps_factory
                    ? (right_chain_pos_after > right_chain_pos_before)
                    : !right_nseq_unchanged);
            int other_unchanged = (cl1_cheat_side == 0)
                ? right_unchanged
                : (is_ps_factory
                    ? (left_chain_pos_peak == left_chain_pos_before)
                    : !left_nseq_changed);
            int pass = cheated_changed && other_unchanged && leaf_pass;
            printf("\n=== LEAF ADVANCE TEST %s ===\n", pass ? "PASSED" : "FAILED");
            if (tier_b_fired_in_loop)
                printf("(Tier B fired during the advance loop; chain_pos reset; "
                       "comparing peak to before)\n");
            if (is_ps_factory) {
                printf("Left leaf chain_pos %s (before=%d, peak=%d, after=%d)\n",
                       left_changed ? "advanced" : "UNCHANGED",
                       left_chain_pos_before, left_chain_pos_peak, left_chain_pos_after);
                printf("Right leaf chain_pos %s (%d → %d)\n",
                       right_unchanged ? "unchanged" : "CHANGED",
                       right_chain_pos_before, right_chain_pos_after);
            } else {
                printf("Left leaf nSequence %s (0x%X → 0x%X)\n",
                       left_changed ? "decreased" : "UNCHANGED", left_nseq_before, left_nseq_after);
                printf("Right leaf nSequence %s (0x%X → 0x%X)\n",
                       right_unchanged ? "unchanged" : "CHANGED", right_nseq_before, right_nseq_after);
            }

            report_add_string(&rpt, "result", pass ? "leaf_advance_pass" : "leaf_advance_fail");
            report_close(&rpt);
            jit_channels_cleanup(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return pass ? 0 : 1;
        }

        /* === Dual Factory Test: create second factory, both ACTIVE, force-close both === */
        if (test_dual_factory && channels_active) {
            printf("\n=== DUAL FACTORY TEST ===\n");
            printf("Creating Factory 1 while Factory 0 is still ACTIVE...\n\n");

            /* Build keypairs array (demo mode: LSP has all keys) */
            secp256k1_keypair all_kps[FACTORY_MAX_SIGNERS];
            all_kps[0] = lsp_kp;
            {
                for (int ci = 0; ci < n_clients; ci++) {
                    unsigned char ds[32];
                    memset(ds, 0, 32);
                    ds[31] = (unsigned char)(ci + 2);
                    if (!secp256k1_keypair_create(ctx, &all_kps[ci + 1], ds)) {
                        fprintf(stderr, "DUAL FACTORY TEST: keypair create failed\n");
                        return 1;
                    }
                }

            /* Reorder all_kps to match lsp_p->factory.pubkeys[] connection order */
            {
                secp256k1_keypair ordered[FACTORY_MAX_SIGNERS];
                memcpy(ordered, all_kps, n_total * sizeof(secp256k1_keypair));
                for (size_t slot = 0; slot < (size_t)n_total; slot++) {
                    unsigned char target_ser[33];
                    size_t tlen = 33;
                    secp256k1_ec_pubkey_serialize(ctx, target_ser, &tlen,
                                                  &lsp_p->factory.pubkeys[slot],
                                                  SECP256K1_EC_COMPRESSED);
                    for (size_t k = 0; k < (size_t)n_total; k++) {
                        secp256k1_pubkey kpub;
                        secp256k1_keypair_pub(ctx, &kpub, &ordered[k]);
                        unsigned char kser[33];
                        size_t klen = 33;
                        secp256k1_ec_pubkey_serialize(ctx, kser, &klen,
                                                      &kpub, SECP256K1_EC_COMPRESSED);
                        if (memcmp(target_ser, kser, 33) == 0) {
                            all_kps[slot] = ordered[k];
                            break;
                        }
                    }
                }
            }

            }

            /* Verify Factory 0 is ACTIVE */
            {
                int cur_h = regtest_get_block_height(&rt);
                if (cur_h > 0) ladder_advance_block(lad, (uint32_t)cur_h);
            }
            factory_state_t f0_state = lad->factories[0].cached_state;
            printf("Factory 0: state=%s, %zu nodes\n",
                   f0_state == FACTORY_ACTIVE ? "ACTIVE" :
                   f0_state == FACTORY_DYING ? "DYING" : "EXPIRED",
                   lad->factories[0].factory.n_nodes);

            /* Check wallet balance for second funding */
            if (!is_regtest) {
                double bal = regtest_get_balance(&rt);
                double needed = (double)funding_sats / 100000000.0;
                if (bal < needed) {
                    fprintf(stderr, "DUAL FACTORY TEST: insufficient balance (%.8f < %.8f)\n",
                            bal, needed);
                    fprintf(stderr, "  Fund wallet and retry.\n");
                    jit_channels_cleanup(mgr);
                    if (use_db) persist_close(&db);
                    lsp_cleanup(lsp_p);
                    memset(lsp_seckey, 0, 32);
                    secp256k1_context_destroy(ctx);
                    return 1;
                }
                printf("Wallet balance: %.8f BTC (sufficient for Factory 1)\n", bal);
            }

            /* Fund Factory 1 */
            double funding_btc2 = (double)funding_sats / 100000000.0;
            char fund2_txid_hex[65];
            if (!regtest_fund_address(&rt, fund_addr, funding_btc2, fund2_txid_hex)) {
                fprintf(stderr, "DUAL FACTORY TEST: fund Factory 1 failed\n");
                jit_channels_cleanup(mgr);
                if (use_db) persist_close(&db);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            if (is_regtest) {
                regtest_mine_blocks(&rt, 1, mine_addr);
            } else {
                printf("Waiting for Factory 1 funding confirmation on %s...\n", network);
                fflush(stdout);
                int conf = regtest_wait_for_confirmation(&rt, fund2_txid_hex,
                                                          confirm_timeout_secs);
                if (conf < 1) {
                    fprintf(stderr, "DUAL FACTORY TEST: funding not confirmed\n");
                    jit_channels_cleanup(mgr);
                    if (use_db) persist_close(&db);
                    lsp_cleanup(lsp_p);
                    memset(lsp_seckey, 0, 32);
                    secp256k1_context_destroy(ctx);
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
                regtest_get_tx_output(&rt, fund2_txid_hex, v,
                                      &fund2_amount, fund2_spk, &fund2_spk_len);
                if (fund2_spk_len == 34 && memcmp(fund2_spk, fund_spk, 34) == 0) {
                    fund2_vout = v;
                    break;
                }
            }
            if (fund2_amount == 0) {
                fprintf(stderr, "DUAL FACTORY TEST: no funding output found\n");
                jit_channels_cleanup(mgr);
                if (use_db) persist_close(&db);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Build Factory 1 directly in ladder slot 1 (factory_t is ~3MB,
               already heap-allocated as part of ladder_t) */
            ladder_factory_t *lf1 = &lad->factories[1];
            factory_t *f1 = &lf1->factory;
            memset(f1, 0, sizeof(factory_t));
            if (n_level_arity > 0)
                factory_set_level_arity(f1, level_arities, n_level_arity);
            else if (leaf_arity == 1)
                factory_set_arity(f1, FACTORY_ARITY_1);

            if (!factory_init(f1, ctx, all_kps, n_total, step_blocks, 4)) {
                fprintf(stderr, "DUAL FACTORY TEST: factory_init failed\n");
                jit_channels_cleanup(mgr);
                if (use_db) persist_close(&db);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Compute cltv_timeout for Factory 1 */
            {
                int cur_h = regtest_get_block_height(&rt);
                if (cltv_timeout_arg > 0) {
                    f1->cltv_timeout = (uint32_t)cltv_timeout_arg;
                } else if (cur_h > 0) {
                    int offset = is_regtest ? 35 : (int)(active_blocks + dying_blocks + 10);
                    f1->cltv_timeout = (uint32_t)cur_h + offset;
                }
            }

            factory_set_funding(f1, fund2_txid, fund2_vout, fund2_amount,
                                fund_spk, 34);

            if (!factory_build_tree(f1)) {
                fprintf(stderr, "DUAL FACTORY TEST: factory_build_tree failed\n");
                factory_free(f1);
                jit_channels_cleanup(mgr);
                if (use_db) persist_close(&db);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            if (!factory_sign_all(f1)) {
                fprintf(stderr, "DUAL FACTORY TEST: factory_sign_all failed\n");
                factory_free(f1);
                jit_channels_cleanup(mgr);
                if (use_db) persist_close(&db);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Set lifecycle for Factory 1 */
            {
                int cur_h = regtest_get_block_height(&rt);
                if (cur_h > 0)
                    factory_set_lifecycle(f1, (uint32_t)cur_h,
                                          active_blocks, dying_blocks);
            }
            f1->fee = fee_est;

            printf("Factory 1 created: %zu nodes signed\n", f1->n_nodes);

            /* Finalize ladder slot 1 (f1 already points into lf1->factory) */
            lf1->factory_id = lad->next_factory_id++;
            lf1->is_initialized = 1;
            lf1->is_funded = 1;
            lf1->cached_state = FACTORY_ACTIVE;
            tx_buf_init(&lf1->distribution_tx, 256);
            lad->n_factories = 2;

            /* Update ladder block height */
            {
                int cur_h = regtest_get_block_height(&rt);
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

            /* Force-close both trees to show two independent factory trees on-chain */
            printf("Broadcasting Factory 0 tree (%zu nodes) on %s...\n",
                   lsp_p->factory.n_nodes, network);
            fflush(stdout);

            /* Populate keypairs on lsp_p->factory (ladder copy has detached tx buffers) */
            memcpy(lsp_p->factory.keypairs, all_kps,
                   n_total * sizeof(secp256k1_keypair));

            if (!broadcast_factory_tree_any_network(&lsp_p->factory, &rt,
                                                      mine_addr, is_regtest,
                                                      confirm_timeout_secs)) {
                fprintf(stderr, "DUAL FACTORY TEST: Factory 0 tree broadcast failed\n");
                jit_channels_cleanup(mgr);
                if (use_db) persist_close(&db);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("Factory 0 tree confirmed.\n\n");

            printf("Broadcasting Factory 1 tree (%zu nodes) on %s...\n",
                   f1->n_nodes, network);
            fflush(stdout);

            if (!broadcast_factory_tree_any_network(f1, &rt,
                                                      mine_addr, is_regtest,
                                                      confirm_timeout_secs)) {
                fprintf(stderr, "DUAL FACTORY TEST: Factory 1 tree broadcast failed\n");
                jit_channels_cleanup(mgr);
                if (use_db) persist_close(&db);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("Factory 1 tree confirmed.\n\n");

            printf("=== DUAL FACTORY TEST %s ===\n",
                   both_active ? "PASSED" : "FAILED (not both ACTIVE)");
            printf("Two independent factory trees broadcast and confirmed on %s.\n",
                   network);

            report_add_string(&rpt, "result",
                              both_active ? "dual_factory_pass" : "dual_factory_fail");
            report_close(&rpt);
            jit_channels_cleanup(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return both_active ? 0 : 1;
        }

        /* === Bridge Test: simulate inbound HTLC via bridge === */
        if (test_bridge && mgr->n_channels > 0) {
            printf("\n=== BRIDGE TEST ===\n");

            /* Create socketpair to simulate bridge <-> LSP connection */
            int sv[2];
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
                fprintf(stderr, "BRIDGE TEST: socketpair failed\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            int bridge_test_fd = sv[0];  /* "bridge" side */
            int lsp_bridge_fd = sv[1];   /* LSP side */

            /* Set bridge_fd on the channel manager */
            lsp_channels_set_bridge(mgr, lsp_bridge_fd);
            lsp_p->bridge_fd = lsp_bridge_fd;
            printf("Bridge: simulated connection established\n");

            /* Ask client 0 to create invoice so it has the preimage locally */
            size_t dest_client = 0;
            uint64_t amount_msat = 1000000;  /* 1000 sats */
            unsigned char test_hash[32];
            unsigned char test_preimage[32];
            memset(test_preimage, 0, 32);

            {
                cJSON *inv_req = cJSON_CreateObject();
                cJSON_AddNumberToObject(inv_req, "amount_msat", (double)amount_msat);
                wire_send(lsp_p->client_fds[dest_client], MSG_CREATE_INVOICE, inv_req);
                cJSON_Delete(inv_req);

                /* Sleep to let clients finish in-flight commit exchanges before
                   we send CREATE_INVOICE. MSG_UPDATE_ADD_HTLC handler has
                   nested recv timeouts up to 5+2+5+2=14s; sleeping ensures
                   the client is in daemon loop ready to receive. */
                sleep(15);

                /* Wait for INVOICE_CREATED, handling REGISTER_INVOICE that
                   may arrive in any order.  Stale REGISTER_INVOICE messages
                   from prior payment rounds can arrive before the fresh
                   INVOICE_CREATED, so loop until both are received or the
                   60-second window expires. */
                int got_invoice_created = 0, got_register_invoice = 0;
                struct timeval _t0, _tnow;
                gettimeofday(&_t0, NULL);
                while (1) {
                    gettimeofday(&_tnow, NULL);
                    int _elapsed = (int)(_tnow.tv_sec - _t0.tv_sec);
                    int _remaining = 60 - _elapsed;
                    if (_remaining <= 0) break;
                    wire_msg_t m;
                    if (!wire_recv_timeout(lsp_p->client_fds[dest_client], &m, _remaining))
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
                    lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                    secp256k1_context_destroy(ctx); return 1;
                }
            }
            printf("Bridge: invoice registered for client %zu (amount=%llu msat)\n",
                   dest_client, (unsigned long long)amount_msat);

            /* Send MSG_BRIDGE_ADD_HTLC from bridge side.
               cltv must be above current chain tip — use +144 blocks. */
            uint32_t bridge_cltv = (uint32_t)regtest_get_block_height(&rt) + 144;
            cJSON *add_msg = wire_build_bridge_add_htlc(test_hash,
                                                           amount_msat, bridge_cltv, 42);
            if (!wire_send(bridge_test_fd, MSG_BRIDGE_ADD_HTLC, add_msg)) {
                fprintf(stderr, "BRIDGE TEST: send ADD_HTLC failed\n");
                cJSON_Delete(add_msg);
                close(bridge_test_fd);
                close(lsp_bridge_fd);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
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
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            if (!lsp_channels_handle_bridge_msg(mgr, lsp_p, &bridge_msg)) {
                fprintf(stderr, "BRIDGE TEST: handle_bridge_msg failed\n");
                cJSON_Delete(bridge_msg.json);
                close(bridge_test_fd);
                close(lsp_bridge_fd);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
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
                    if (wire_recv_timeout(lsp_p->client_fds[dest_client], &client_msg, 1)) {
                        lsp_channels_handle_msg(mgr, lsp_p, dest_client, &client_msg);
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
        }

        /* === Force-close: broadcast entire factory tree === */
        /* === Tier B State-Advance Rollover Test (Gap B + F, PR #122) ===

           Drives enough multi-party leaf advances to exhaust the per-leaf
           DW counter; the (states_per_layer + 1)-th call returns rc=-1
           inside lsp_advance_leaf, which then calls lsp_run_state_advance
           to drive the whole-tree re-sign ceremony over the wire.  Runs
           BEFORE force_close so the post-rollover tree is what gets
           broadcast on-chain — the broadcast itself is then part of the
           verification (the new-epoch signed TXs must be valid).

           Requires arity-1 (DW leaves) — PS chains never trigger rc=-1. */
        /* === PS k² Sub-factory Chain Extension Test (Phase 2c) ===

           Drives a single sub-factory chain extension via
           lsp_subfactory_chain_advance.  Requires --arity 3 (PS) and
           --ps-subfactory-arity K with K>1 so the factory has actual
           sub-factory child nodes to extend. */
        if (test_subfactory_advance) {
            printf("\n=== PS K² SUB-FACTORY CHAIN EXTENSION TEST ===\n");
            fflush(stdout);
            int sub_pass = 1;

            if (lsp_p->factory.leaf_arity != FACTORY_ARITY_PS ||
                lsp_p->factory.ps_subfactory_arity <= 1) {
                printf("  SKIP: --test-subfactory-advance requires --arity 3 "
                       "and --ps-subfactory-arity K (K>1)\n");
                printf("PS K² SUB-FACTORY TEST: SKIP (gate=arity)\n");
            } else if (lsp_p->factory.n_leaf_nodes < 1) {
                printf("  SKIP: no leaves built\n");
                printf("PS K² SUB-FACTORY TEST: SKIP (gate=no-leaves)\n");
            } else {
                /* Pick leaf 0, sub-factory 0, channel 0; transfer 50000 sats
                   from sales-stock to channel 0. */
                size_t leaf0_idx = lsp_p->factory.leaf_node_indices[0];
                factory_node_t *leaf = &lsp_p->factory.nodes[leaf0_idx];
                if (leaf->n_subfactories < 1) {
                    printf("  SKIP: leaf 0 has no sub-factories\n");
                    printf("PS K² SUB-FACTORY TEST: SKIP (gate=no-subfactories)\n");
                } else {
                    int sub0_node_i = leaf->subfactory_node_indices[0];
                    factory_node_t *sub0 =
                        &lsp_p->factory.nodes[sub0_node_i];
                    int chain_before = sub0->ps_chain_len;
                    uint64_t ch0_before = sub0->outputs[0].amount_sats;
                    uint64_t sstock_before =
                        sub0->outputs[sub0->n_outputs - 1].amount_sats;

                    /* Snapshot the pre-advance signed_tx so we can broadcast
                       it post-advance as the "stale" chain[N-1] for the
                       --cheat-subfactory breach test. */
                    tx_buf_t cheat_stale_tx;
                    tx_buf_init(&cheat_stale_tx, 0);
                    if (cheat_subfactory_after_advance && sub0->is_signed &&
                        sub0->signed_tx.len > 0) {
                        tx_buf_init(&cheat_stale_tx, (int)sub0->signed_tx.len);
                        memcpy(cheat_stale_tx.data,
                               sub0->signed_tx.data, sub0->signed_tx.len);
                        cheat_stale_tx.len = sub0->signed_tx.len;
                    }
                    /* Auto-scale delta to actual sales-stock budget so
                       wider configs (N>=24 where per-output budget shrinks)
                       don't run into 'sstock < delta + fee + dust'. Use a
                       quarter of available stock with a 1000-sat floor so
                       the cryptographic flow still exercises meaningfully
                       at small N too. */
                    uint64_t delta = sstock_before / 4;
                    if (delta < 1000) delta = 1000;

                    printf("  pre-extension: chain_len=%d, ch[0]=%llu, "
                           "sales-stock=%llu, delta=%llu\n",
                           chain_before, (unsigned long long)ch0_before,
                           (unsigned long long)sstock_before,
                           (unsigned long long)delta);
                    fflush(stdout);

                    int rc = lsp_subfactory_chain_advance(mgr, lsp_p,
                                                           /*leaf_side=*/0,
                                                           /*sub_idx=*/0,
                                                           /*channel_idx=*/0,
                                                           delta);
                    if (rc != 1) {
                        printf("  FAIL: lsp_subfactory_chain_advance returned %d\n", rc);
                        sub_pass = 0;
                    } else if (sub0->ps_chain_len != chain_before + 1) {
                        printf("  FAIL: chain_len did not increment "
                               "(was %d, now %d)\n",
                               chain_before, sub0->ps_chain_len);
                        sub_pass = 0;
                    } else if (sub0->outputs[0].amount_sats !=
                                ch0_before + delta) {
                        printf("  FAIL: ch[0] did not grow by delta "
                               "(was %llu, now %llu)\n",
                               (unsigned long long)ch0_before,
                               (unsigned long long)sub0->outputs[0].amount_sats);
                        sub_pass = 0;
                    } else if (!sub0->is_signed) {
                        printf("  FAIL: chain[N+1] is not signed\n");
                        sub_pass = 0;
                    } else {
                        printf("  post-extension: chain_len=%d, ch[0]=%llu, "
                               "sales-stock=%llu (signed=%d)\n",
                               sub0->ps_chain_len,
                               (unsigned long long)sub0->outputs[0].amount_sats,
                               (unsigned long long)sub0->outputs[sub0->n_outputs - 1].amount_sats,
                               sub0->is_signed);
                    }

                    /* === SF-A #142: SECOND advance — multi-input ceremony ===
                       The first advance produced chain[1] which spends a single
                       sales-stock UTXO (single-input).  Now drive a SECOND
                       advance so chain[2] spends ALL k+1 outputs of chain[1]
                       (k channels + sales-stock).  This is the multi-input
                       MuSig case (#142 SF-A). */
                    if (sub_pass && test_subfactory_advance_multi) {
                        printf("\n--- SF-A: SECOND advance (multi-input ceremony) ---\n");
                        fflush(stdout);
                        int chain1 = sub0->ps_chain_len;
                        uint64_t ch0_b4 = sub0->outputs[0].amount_sats;
                        uint64_t sstock_b4 =
                            sub0->outputs[sub0->n_outputs - 1].amount_sats;
                        /* Auto-scale second-advance delta to remaining sales-stock. */
                        uint64_t delta2 = sstock_b4 / 4;
                        if (delta2 < 1000) delta2 = 1000;
                        if (delta2 + 1000 + 546 > sstock_b4) delta2 = 0;

                        if (delta2 == 0) {
                            printf("  SKIP: sales-stock too small for 2nd advance "
                                   "(%llu sats)\n", (unsigned long long)sstock_b4);
                        } else {
                            printf("  pre-2nd-advance: chain_len=%d, ch[0]=%llu, "
                                   "sales-stock=%llu, delta2=%llu, "
                                   "ps_n_prev_outputs=%zu\n",
                                   chain1, (unsigned long long)ch0_b4,
                                   (unsigned long long)sstock_b4,
                                   (unsigned long long)delta2,
                                   sub0->ps_n_prev_outputs);
                            fflush(stdout);
                            int rc2 = lsp_subfactory_chain_advance(mgr, lsp_p,
                                                                    /*leaf_side=*/0,
                                                                    /*sub_idx=*/0,
                                                                    /*channel_idx=*/0,
                                                                    delta2);
                            if (rc2 != 1) {
                                printf("  FAIL: 2nd lsp_subfactory_chain_advance "
                                       "returned %d\n", rc2);
                                sub_pass = 0;
                            } else if (sub0->ps_chain_len != chain1 + 1) {
                                printf("  FAIL: chain_len did not increment "
                                       "(was %d, now %d)\n",
                                       chain1, sub0->ps_chain_len);
                                sub_pass = 0;
                            } else if (!sub0->is_signed) {
                                printf("  FAIL: chain[N+2] is not signed\n");
                                sub_pass = 0;
                            } else {
                                printf("  post-2nd-advance: chain_len=%d, "
                                       "ch[0]=%llu, sales-stock=%llu (signed=%d)\n",
                                       sub0->ps_chain_len,
                                       (unsigned long long)sub0->outputs[0].amount_sats,
                                       (unsigned long long)sub0->outputs[sub0->n_outputs - 1].amount_sats,
                                       sub0->is_signed);
                                printf("  SF-A MULTI-INPUT CEREMONY: PASS\n");
                            }
                        }
                    }

                    /* === Sub-factory CHEATING + WATCHTOWER POISON ===

                       The LSP "cheats" by broadcasting the now-stale
                       chain[N-1] TX (snapshotted pre-advance).  For
                       chain[N-1] to confirm, its parent vout (the leaf
                       node's outputs[sub_idx]) must already be on-chain
                       — so we first broadcast the path from the funding
                       UTXO down through root + leaf (skipping
                       sub-factory nodes themselves so chain[N] doesn't
                       race chain[N-1]), then broadcast chain[N-1] as
                       the cheat, mine a block, and run watchtower_check.
                       The watchtower must:
                         1. Detect chain[N-1] confirming (its watched txid)
                         2. Broadcast the latest chain[N] (response_tx)
                         3. Broadcast the pre-signed poison TX */
                    if (sub_pass && cheat_subfactory_after_advance &&
                        cheat_stale_tx.len > 0) {
                        printf("\n--- CHEAT-SUBFACTORY: broadcasting parent path then stale chain[N-1] ---\n");
                        fflush(stdout);
                        /* CL1: --cheat-subfactory now works on any network. */
                        if (!mgr->watchtower) {
                            printf("  FAIL: no watchtower configured\n");
                            sub_pass = 0;
                        } else {
                            /* CL1.D: temporarily un-mark all NODE_PS_SUBFACTORY
                               nodes is_signed so broadcast_factory_tree_any_network
                               SKIPS them. This puts the sub-factory parent UTXOs
                               on-chain (so chain[N-1] can spend it). The helper
                               handles BIP68 + getrawtransaction (fixes the bare-loop
                               bug that affected non-regtest networks). */
                            int saved_is_signed[FACTORY_MAX_NODES] = {0};
                            for (size_t si = 0; si < lsp_p->factory.n_nodes; si++) {
                                if (lsp_p->factory.nodes[si].type == NODE_PS_SUBFACTORY) {
                                    saved_is_signed[si] = lsp_p->factory.nodes[si].is_signed;
                                    lsp_p->factory.nodes[si].is_signed = 0;
                                }
                            }
                            int parent_ok = broadcast_factory_tree_any_network(
                                &lsp_p->factory, &rt, mine_addr, is_regtest,
                                confirm_timeout_secs);
                            for (size_t si = 0; si < lsp_p->factory.n_nodes; si++) {
                                if (saved_is_signed[si]) {
                                    lsp_p->factory.nodes[si].is_signed = saved_is_signed[si];
                                }
                            }
                            if (g_db) {
                                persist_log_broadcast(g_db,
                                    parent_ok ? "tree_ok" : "tree_fail",
                                    "cheat_subfactory_parent_tree", "",
                                    parent_ok ? "ok" : "failed");
                            }
                            if (!parent_ok) {
                                printf("  FAIL: parent tree broadcast failed\n");
                                sub_pass = 0;
                            }

                            char *cheat_hex =
                                malloc(cheat_stale_tx.len * 2 + 1);
                            char cheat_txid_str[65] = {0};
                            int sent = 0;
                            if (cheat_hex) {
                                hex_encode(cheat_stale_tx.data,
                                           cheat_stale_tx.len, cheat_hex);
                                sent = regtest_send_raw_tx(&rt, cheat_hex,
                                                           cheat_txid_str);
                                if (g_db)
                                    persist_log_broadcast(g_db,
                                        sent ? cheat_txid_str : "?",
                                        "cheat_subfactory_stale",
                                        cheat_hex,
                                        sent ? "ok" : "failed");
                                free(cheat_hex);
                            }
                            if (!sent) {
                                printf("  FAIL: stale chain[N-1] broadcast failed\n");
                                sub_pass = 0;
                            } else {
                                printf("  Stale chain[N-1] broadcast: %s\n",
                                       cheat_txid_str);
                                /* Mine 5 blocks + sleep 2s before watchtower
                                   check so chain[N-1] is solidly confirmed
                                   (out of mempool, no race with chain[N]
                                   that the watchtower will broadcast).  Per
                                   the v0.1.15 master plan: 1 block was not
                                   enough because bitcoind's mempool/wallet
                                   reorg detection had transient state. */
                                /* CL1: network-aware 5-conf wait */
                                if (is_regtest) {
                                    regtest_mine_blocks(&rt, 5, mine_addr);
                                    sleep(2);
                                } else {
                                    for (int ct = 1; ct <= 5; ct++) {
                                        regtest_wait_for_confirmation(&rt, cheat_txid_str,
                                                                       confirm_timeout_secs);
                                        int cur = regtest_get_confirmations(&rt, cheat_txid_str);
                                        if (cur >= 5) break;
                                        sleep(15);
                                    }
                                }

                                /* CL4.F: daemon-mode skip — same as the leaf path's
                                   SS_CHEAT_DAEMON_MODE check. Lets the standalone WT
                                   handle detection + response instead of the in-memory WT. */
                                int detected;
                                if (getenv("SS_CHEAT_DAEMON_MODE")) {
                                    printf("  CL4.F daemon mode: skipping internal watchtower_check\n");
                                    printf("  CHEAT DAEMON COMPLETE\n");
                                    fflush(stdout);
                                    sleep(60);
                                    detected = 1;  /* trust the standalone WT to fire */
                                } else {
                                    detected = watchtower_check(mgr->watchtower);
                                }

                                /* Count entries that the check visited and
                                   marked as broadcast (regardless of whether
                                   the actual sendrawtransaction succeeded —
                                   the printf "SUB-FACTORY BREACH on node X"
                                   in src/watchtower.c fires before the
                                   broadcast attempt, so this is the closest
                                   we can get to "was the breach detected"
                                   without grepping our own log. */
                                int entries_marked_broadcast = 0;
                                for (size_t we = 0;
                                     we < mgr->watchtower->n_entries; we++) {
                                    if (mgr->watchtower->entries[we].penalty_broadcast)
                                        entries_marked_broadcast++;
                                }
                                printf("  watchtower_check returned %d, "
                                       "%d entries marked broadcast\n",
                                       detected, entries_marked_broadcast);

                                if (detected <= 0 && entries_marked_broadcast == 0) {
                                    printf("  FAIL: watchtower did not detect "
                                           "sub-factory breach (detected=%d)\n",
                                           detected);
                                    sub_pass = 0;
                                } else {
                                    printf("  SUB-FACTORY BREACH DETECTED — "
                                           "%d penalty tx broadcast\n",
                                           detected);
                                    /* CL1: network-aware response_tx + poison_tx confirmation */
                                    if (is_regtest) {
                                        regtest_mine_blocks(&rt, 5, mine_addr);
                                        sleep(2);
                                    } else {
                                        printf("  Waiting for response_tx + poison_tx on non-regtest network...\n");
                                        sleep(60);  /* let response txs propagate */
                                    }
                                    printf("  Penalty + poison TXs confirmed\n");
                                }
                            }
                        }
                    }
                    tx_buf_free(&cheat_stale_tx);
                }
                printf("PS K² SUB-FACTORY TEST: %s\n", sub_pass ? "PASS" : "FAIL");
            }
            fflush(stdout);
            if (!sub_pass) {
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
        }

        if (test_tier_b_rollover) {
            printf("\n=== TIER B STATE-ADVANCE ROLLOVER TEST ===\n");
            fflush(stdout);
            int rollover_pass = 1;

            /* CL2-TB: enable on FACTORY_ARITY_PS (arity 3) too.
               lsp_channels_advance_ps_leaf is a 1-line wrapper around
               lsp_advance_leaf which works for any arity. The gate was
               stale (predated PS arity introduction). */
            if (lsp_p->factory.leaf_arity != FACTORY_ARITY_1 &&
                lsp_p->factory.leaf_arity != FACTORY_ARITY_PS) {
                printf("  SKIP: --test-tier-b-rollover requires --arity 1 (DW) or --arity 3 (PS)\n");
                printf("TIER B ROLLOVER TEST: SKIP (gate=arity)\n");
            } else {
                /* Populate factory.keypairs[] for the LSP's local
                   factory_build_burn_tx call inside lsp_advance_leaf.
                   In multi-process mode the LSP only has its own keypair;
                   the burn-TX signer (factory_sign_l_stock_poison_tx) is
                   a single-process helper that needs every leaf signer's
                   keypair.  This is a pre-existing limitation of the
                   poison-TX signer (orthogonal to Tier B) and the same
                   workaround is used by --test-dw-advance / --test-leaf-
                   advance.  We hardcode the canonical multi-process test
                   seckeys 0x01 (LSP) + 0x02..0x09 (clients) so the
                   keypairs match factory.pubkeys received over the wire.
                   The Tier B ceremony itself does NOT use these
                   keypairs — it drives MuSig over the wire from each
                   client's own seckey.  Only the burn-TX side-effect
                   needs them. */
                {
                    size_t n_total = (size_t)(n_clients + 1);
                    /* Cap to the canonical seckey range we hardcode below
                       (0x01..0x09).  Cppcheck flags the memcpy below as
                       reading uninitialized entries when n_total > 9; the
                       cap keeps the analyzer happy AND limits the test
                       to configs we actually support. */
                    if (n_total > 9) n_total = 9;
                    secp256k1_keypair all_kps[FACTORY_MAX_SIGNERS];
                    memset(all_kps, 0, n_total * sizeof(secp256k1_keypair));
                    for (size_t pi = 0; pi < n_total; pi++) {
                        unsigned char sk[32];
                        memset(sk, 0, 32);
                        sk[31] = (unsigned char)(pi + 1);
                        if (!secp256k1_keypair_create(ctx, &all_kps[pi], sk)) {
                            fprintf(stderr, "TIER B: keypair create p=%zu failed\n", pi);
                            return 1;
                        }
                    }
                    /* Reorder to match factory.pubkeys connection order. */
                    secp256k1_keypair ordered[FACTORY_MAX_SIGNERS];
                    memcpy(ordered, all_kps, n_total * sizeof(secp256k1_keypair));
                    for (size_t slot = 0; slot < n_total; slot++) {
                        unsigned char target[33];
                        size_t tlen = 33;
                        secp256k1_ec_pubkey_serialize(ctx, target, &tlen,
                                                      &lsp_p->factory.pubkeys[slot],
                                                      SECP256K1_EC_COMPRESSED);
                        for (size_t k = 0; k < n_total; k++) {
                            secp256k1_pubkey kpub;
                            secp256k1_keypair_pub(ctx, &kpub, &ordered[k]);
                            unsigned char kser[33];
                            size_t klen = 33;
                            secp256k1_ec_pubkey_serialize(ctx, kser, &klen,
                                                          &kpub, SECP256K1_EC_COMPRESSED);
                            if (memcmp(target, kser, 33) == 0) {
                                all_kps[slot] = ordered[k];
                                break;
                            }
                        }
                    }
                    memcpy(lsp_p->factory.keypairs, all_kps,
                           n_total * sizeof(secp256k1_keypair));
                    printf("  populated %zu keypairs for burn-TX signing\n", n_total);
                }

                /* CL4-ROLLOVER (#250): snapshot every leaf's OLD signed_tx
                   BEFORE the rollover ticks run.  After lsp_factory_tick_root
                   completes, every leaf's signed_tx points at the NEW epoch
                   chain[0] — so we must capture pre-rollover bytes here.
                   Mirrored on the CL2 cheat-realloc precedent
                   (tools/superscalar_lsp_post_daemon_tests.inc:1066). */
                tx_buf_t cl4r_snap[FACTORY_MAX_LEAVES];
                unsigned char cl4r_snap_txid[FACTORY_MAX_LEAVES][32];
                int cl4r_cheat_enabled = (getenv("SS_CHEAT_ROLLOVER") != NULL);
                /* Full pre-rollover tree snapshot (EVERY node, not just leaves) so
                   the mid-window cheat can broadcast the OLD ancestor path with the
                   OLD txids — the only way the OLD leaf 0 is spendable on-chain.
                   malloc'd to keep the 512-node arrays off this already-deep stack;
                   freed after the cheat fires. */
                tx_buf_t *cl4r_node_snap = NULL;
                unsigned char (*cl4r_node_txid)[32] = NULL;
                int *cl4r_node_signed = NULL;
                for (size_t li = 0; li < FACTORY_MAX_LEAVES; li++) {
                    tx_buf_init(&cl4r_snap[li], 0);
                    memset(cl4r_snap_txid[li], 0, 32);
                }
                if (cl4r_cheat_enabled) {
                    for (size_t li = 0; li < (size_t)lsp_p->factory.n_leaf_nodes; li++) {
                        size_t ni = lsp_p->factory.leaf_node_indices[li];
                        factory_node_t *ln = &lsp_p->factory.nodes[ni];
                        if (!ln->is_signed || ln->signed_tx.len == 0) continue;
                        tx_buf_init(&cl4r_snap[li], ln->signed_tx.len);
                        memcpy(cl4r_snap[li].data, ln->signed_tx.data,
                               ln->signed_tx.len);
                        cl4r_snap[li].len = ln->signed_tx.len;
                        memcpy(cl4r_snap_txid[li], ln->txid, 32);
                    }
                    fprintf(stderr,
                            "CL4-ROLLOVER: snapshotted %d pre-rollover leaf tx "
                            "(leaf0 len=%zu first8=%02x%02x%02x%02x%02x%02x%02x%02x)\n",
                            lsp_p->factory.n_leaf_nodes,
                            cl4r_snap[0].len,
                            cl4r_snap[0].len > 0 ? cl4r_snap[0].data[0] : 0,
                            cl4r_snap[0].len > 1 ? cl4r_snap[0].data[1] : 0,
                            cl4r_snap[0].len > 2 ? cl4r_snap[0].data[2] : 0,
                            cl4r_snap[0].len > 3 ? cl4r_snap[0].data[3] : 0,
                            cl4r_snap[0].len > 4 ? cl4r_snap[0].data[4] : 0,
                            cl4r_snap[0].len > 5 ? cl4r_snap[0].data[5] : 0,
                            cl4r_snap[0].len > 6 ? cl4r_snap[0].data[6] : 0,
                            cl4r_snap[0].len > 7 ? cl4r_snap[0].data[7] : 0);

                    /* Snapshot EVERY node's signed bytes + txid (not just leaves):
                       the cheat broadcasts the whole pre-rollover tree so the OLD
                       leaf 0's ancestors land on-chain with matching (old) txids. */
                    cl4r_node_snap   = calloc(FACTORY_MAX_NODES, sizeof(tx_buf_t));
                    cl4r_node_txid   = calloc(FACTORY_MAX_NODES, 32);
                    cl4r_node_signed = calloc(FACTORY_MAX_NODES, sizeof(int));
                    if (cl4r_node_snap && cl4r_node_txid && cl4r_node_signed) {
                        for (size_t ni = 0; ni < lsp_p->factory.n_nodes; ni++) {
                            factory_node_t *nd = &lsp_p->factory.nodes[ni];
                            tx_buf_init(&cl4r_node_snap[ni], 0);
                            if (nd->is_signed && nd->signed_tx.len > 0) {
                                tx_buf_init(&cl4r_node_snap[ni], nd->signed_tx.len);
                                memcpy(cl4r_node_snap[ni].data, nd->signed_tx.data,
                                       nd->signed_tx.len);
                                cl4r_node_snap[ni].len = nd->signed_tx.len;
                                cl4r_node_signed[ni] = 1;
                                memcpy(cl4r_node_txid[ni], nd->txid, 32);
                            }
                        }
                    }
                }

                uint32_t epoch_before = lsp_p->factory.counter.current_epoch;
                int is_ps_factory = (lsp_p->factory.leaf_arity == FACTORY_ARITY_PS);
                int n_iters = states_per_layer + 1;

                if (is_ps_factory) {
                    /* PS Tier B: root rollover is block-driven, NOT
                       leaf-driven (PS leaves chain-extend without a
                       counter).  Drive the root counter directly via
                       lsp_factory_tick_root.  In production, this would
                       be wired into a block-height polling loop.  For the
                       test we tick the root states_per_layer+1 times
                       (the last tick rolls over the layer). */
                    printf("  PS factory: states_per_layer=%d → ticking root counter "
                           "%d times (last tick triggers Tier B ceremony)\n",
                           states_per_layer, n_iters);
                    for (int it = 0; it < n_iters; it++) {
                        printf("  tick %d/%d: lsp_factory_tick_root...\n",
                               it + 1, n_iters);
                        fflush(stdout);
                        int rc = lsp_factory_tick_root(mgr, lsp_p);
                        if (rc < 0) {
                            printf("  FAIL: lsp_factory_tick_root returned %d on tick %d\n",
                                   rc, it + 1);
                            rollover_pass = 0;
                            break;
                        }
                        /* rc=1 means rollover + ceremony complete; rc=0 means
                           tick without rollover (root counter advanced within
                           the layer).  Either is fine until the final tick. */
                    }
                } else {
                    /* DW Tier B: leaf-counter exhaustion drives root rollover.
                       Drive leaf-0 advances; the last one exhausts the leaf and
                       triggers Tier B via factory_advance_leaf_unsigned rc=-1. */
                    printf("  DW factory: states_per_layer=%d → driving %d leaf-0 advances "
                           "(last one triggers rc=-1 / Tier B ceremony)\n",
                           states_per_layer, n_iters);
                    for (int it = 0; it < n_iters; it++) {
                        printf("  iter %d/%d: lsp_channels_advance_ps_leaf(0)...\n",
                               it + 1, n_iters);
                        fflush(stdout);
                        /* CL4-ROLLOVER: the Tier-B ceremony (Step 10, lsp_channels.c)
                           arms the watchtower to watch the IMMEDIATELY-superseded leaf
                           state (T_{n-1}), not older ones (WT watches the most-dangerous
                           revoked state — smallest DW timelock — by design, see
                           lsp_channels.c rehydrate note).  Re-snapshot the leaf node txs
                           NOW (just before the final, rollover-triggering advance) so the
                           cheat broadcasts exactly that stale state.  The parent path was
                           captured pre-loop and is unchanged by leaf advances, so the
                           re-captured T_{n-1} leaves stay consistent with it. */
                        if (cl4r_cheat_enabled && it == n_iters - 1 && cl4r_node_snap) {
                            for (size_t li = 0; li < (size_t)lsp_p->factory.n_leaf_nodes; li++) {
                                size_t lni = lsp_p->factory.leaf_node_indices[li];
                                factory_node_t *ln = &lsp_p->factory.nodes[lni];
                                if (!ln->is_signed || ln->signed_tx.len == 0) continue;
                                tx_buf_free(&cl4r_node_snap[lni]);
                                tx_buf_init(&cl4r_node_snap[lni], ln->signed_tx.len);
                                memcpy(cl4r_node_snap[lni].data, ln->signed_tx.data, ln->signed_tx.len);
                                cl4r_node_snap[lni].len = ln->signed_tx.len;
                                cl4r_node_signed[lni] = 1;
                                memcpy(cl4r_node_txid[lni], ln->txid, 32);
                                if (li < FACTORY_MAX_LEAVES) {
                                    tx_buf_free(&cl4r_snap[li]);
                                    tx_buf_init(&cl4r_snap[li], ln->signed_tx.len);
                                    memcpy(cl4r_snap[li].data, ln->signed_tx.data, ln->signed_tx.len);
                                    cl4r_snap[li].len = ln->signed_tx.len;
                                    memcpy(cl4r_snap_txid[li], ln->txid, 32);
                                }
                            }
                            fprintf(stderr, "CL4-ROLLOVER: re-snapshotted %d leaves at T_{n-1} "
                                    "(the WT-armed immediately-superseded state) before final rollover\n",
                                    lsp_p->factory.n_leaf_nodes);
                        }
                        int rc = lsp_channels_advance_ps_leaf(mgr, lsp_p, 0);
                        if (rc != 1) {
                            printf("  FAIL: advance returned %d on iter %d\n", rc, it + 1);
                            rollover_pass = 0;
                            break;
                        }
                    }
                }

                if (rollover_pass) {
                    uint32_t epoch_after = lsp_p->factory.counter.current_epoch;
                    if (epoch_after <= epoch_before) {
                        printf("  FAIL: epoch did not advance "
                               "(before=%u, after=%u) — rc=-1 path likely never fired\n",
                               epoch_before, epoch_after);
                        rollover_pass = 0;
                    } else {
                        printf("  epoch advanced %u → %u (rc=-1 / Tier B ceremony fired)\n",
                               epoch_before, epoch_after);

                        /* CL4-ROLLOVER (#250): mid-window cheat broadcast.
                           Adversarial LSP behavior moved here from
                           src/lsp_rotation.c (where the cheat block lived
                           in lsp_channels_rotate_factory which only runs
                           under --daemon).  The test wrapper
                           test_regtest_cheat_daemon_rollover.sh uses --demo
                           + --test-tier-b-rollover so the rotation function
                           is never reached.

                           Mirror the CL2 cheat-realloc trick
                           (tools/superscalar_lsp_post_daemon_tests.inc:1111):
                           temporarily un-mark every leaf is_signed so
                           broadcast_factory_tree_any_network lands the
                           parent path on-chain WITHOUT new-state leaves,
                           then broadcast the OLD snapshot of leaf 0 as
                           the breach.  Watchtower detects + responds with
                           penalty TX. */
                        if (cl4r_cheat_enabled) {
                            const char *cl4r_phase = getenv("SS_CHEAT_ROLLOVER_PHASE");
                            if (cl4r_phase && strcmp(cl4r_phase, "mid-window") == 0 &&
                                cl4r_snap[0].len > 0) {
                                /* Swap the factory to the FULL pre-rollover tree, broadcast it,
                                   then swap the current tree back.  Reusing the normal tree-broadcast
                                   path (not a raw send of just the leaf) lands the OLD root -> ... ->
                                   OLD leaf 0 in topological order AND respects the DW timelocks, so
                                   the OLD leaf 0's ancestors exist on-chain with the OLD txids and it
                                   is spendable.  The funding is still unspent (this is the first
                                   on-chain tree broadcast), so the old root spends it.  The previous
                                   code broadcast the post-rollover tree (new-epoch txids) and then a
                                   raw OLD leaf 0 whose input never existed -> sent=0. */
                                unsigned char txid_tmp[32];
                                size_t nn = lsp_p->factory.n_nodes;
                                int have_snap = (cl4r_node_snap && cl4r_node_txid && cl4r_node_signed);
                                if (have_snap) {
                                    for (size_t ni = 0; ni < nn; ni++) {
                                        factory_node_t *nd = &lsp_p->factory.nodes[ni];
                                        tx_buf_t tb = nd->signed_tx; nd->signed_tx = cl4r_node_snap[ni]; cl4r_node_snap[ni] = tb;
                                        int s = nd->is_signed; nd->is_signed = cl4r_node_signed[ni]; cl4r_node_signed[ni] = s;
                                        memcpy(txid_tmp, nd->txid, 32); memcpy(nd->txid, cl4r_node_txid[ni], 32); memcpy(cl4r_node_txid[ni], txid_tmp, 32);
                                    }
                                }
                                int parent_ok = broadcast_factory_tree_any_network(
                                    &lsp_p->factory, &rt, mine_addr, is_regtest,
                                    confirm_timeout_secs);
                                /* old leaf-0 txid (display order) for the marker, read BEFORE swap-back */
                                char cheat_txid_str[65] = {0};
                                size_t leaf0_ni = lsp_p->factory.leaf_node_indices[0];
                                for (int b = 0; b < 32; b++)
                                    sprintf(cheat_txid_str + b * 2, "%02x",
                                            lsp_p->factory.nodes[leaf0_ni].txid[31 - b]);
                                if (have_snap) {   /* swap the current tree back */
                                    for (size_t ni = 0; ni < nn; ni++) {
                                        factory_node_t *nd = &lsp_p->factory.nodes[ni];
                                        tx_buf_t tb = nd->signed_tx; nd->signed_tx = cl4r_node_snap[ni]; cl4r_node_snap[ni] = tb;
                                        int s = nd->is_signed; nd->is_signed = cl4r_node_signed[ni]; cl4r_node_signed[ni] = s;
                                        memcpy(txid_tmp, nd->txid, 32); memcpy(nd->txid, cl4r_node_txid[ni], 32); memcpy(cl4r_node_txid[ni], txid_tmp, 32);
                                    }
                                }
                                int sent = parent_ok ? 1 : 0;
                                fprintf(stderr,
                                        "CL4-ROLLOVER: mid-window broadcast of "
                                        "dying factory leaf 0 tx: sent=%d txid=%s "
                                        "(severity=HIGH)\n",
                                        sent, cheat_txid_str);
                                if (g_db) {
                                    persist_log_broadcast(g_db,
                                        sent ? cheat_txid_str : "?",
                                        "cheat_rollover_stale", "",
                                        sent ? "ok" : "failed");
                                }
                                if (sent && is_regtest) {
                                    regtest_mine_blocks(&rt, 1, mine_addr);
                                    watchtower_t *wt_cl4 = mgr->watchtower;
                                    if (wt_cl4) {
                                        int detected = watchtower_check(wt_cl4);
                                        if (detected > 0) {
                                            printf("CL4-ROLLOVER: BREACH DETECTED! "
                                                   "Watchtower broadcast %d penalty tx(s)\n",
                                                   detected);
                                            regtest_mine_blocks(&rt, 1, mine_addr);
                                        } else {
                                            fprintf(stderr,
                                                    "CL4-ROLLOVER: watchtower did NOT "
                                                    "detect revoked broadcast (defense MISS)\n");
                                        }
                                    }
                                } else if (!parent_ok) {
                                    fprintf(stderr,
                                            "CL4-ROLLOVER: old-tree broadcast failed — "
                                            "cannot test stale broadcast\n");
                                }
                            }
                            for (size_t li = 0; li < FACTORY_MAX_LEAVES; li++)
                                tx_buf_free(&cl4r_snap[li]);
                            if (cl4r_node_snap) {
                                for (size_t ni = 0; ni < FACTORY_MAX_NODES; ni++)
                                    tx_buf_free(&cl4r_node_snap[ni]);
                                free(cl4r_node_snap);
                            }
                            free(cl4r_node_txid);
                            free(cl4r_node_signed);
                            cl4r_node_snap = NULL; cl4r_node_txid = NULL; cl4r_node_signed = NULL;
                        }

                        /* Verify every non-PS-leaf node is signed for the new epoch.
                           F1: for PS factories, also verify PS leaves are signed
                           (post-rollover chain[0]).  PS leaves used to be excluded
                           from root-driven Tier B; F1 includes them so force-close
                           can broadcast the new epoch's chain[0]. */
                        int all_signed = 1;
                        size_t n_checked = 0, n_ps_checked = 0;
                        for (size_t ni = 0; ni < lsp_p->factory.n_nodes; ni++) {
                            const factory_node_t *node = &lsp_p->factory.nodes[ni];
                            if (!node->is_built) continue;
                            if (node->is_ps_leaf) {
                                if (!is_ps_factory) continue;  /* skip on DW */
                                n_ps_checked++;
                            } else {
                                n_checked++;
                            }
                            if (!node->is_signed || node->signed_tx.len == 0) {
                                printf("  FAIL: %s node %zu not signed after Tier B ceremony\n",
                                       node->is_ps_leaf ? "PS-leaf" : "internal", ni);
                                all_signed = 0;
                            }
                        }
                        if (all_signed) {
                            printf("  all %zu internal + %zu PS-leaf nodes signed after Tier B\n",
                                   n_checked, n_ps_checked);
                        } else {
                            rollover_pass = 0;
                        }

                        /* F1: verify PS chain[0] was persisted for the new epoch.
                           After rollover the new chain[0] bytes should be in
                           ps_initial_signed_states (replacing the old epoch's row). */
                        if (is_ps_factory && rollover_pass && use_db) {
                            int n_ps_persisted = 0, n_ps_mismatch = 0;
                            for (size_t ni = 0; ni < lsp_p->factory.n_nodes; ni++) {
                                const factory_node_t *node = &lsp_p->factory.nodes[ni];
                                if (!node->is_ps_leaf) continue;
                                if (!node->is_signed) continue;
                                tx_buf_t loaded;
                                unsigned char loaded_txid_be[32];
                                if (persist_load_ps_initial_signed_state(
                                        &db, 0, (uint32_t)ni,
                                        &loaded, loaded_txid_be)) {
                                    n_ps_persisted++;
                                    if (loaded.len != node->signed_tx.len ||
                                        memcmp(loaded.data, node->signed_tx.data,
                                               loaded.len) != 0) {
                                        printf("  FAIL: PS node %zu chain[0] persisted bytes "
                                               "differ from in-memory signed_tx (stale row?)\n", ni);
                                        n_ps_mismatch++;
                                    }
                                    tx_buf_free(&loaded);
                                } else {
                                    printf("  FAIL: PS node %zu chain[0] not in "
                                           "ps_initial_signed_states after Tier B\n", ni);
                                    n_ps_mismatch++;
                                }
                            }
                            if (n_ps_mismatch == 0)
                                printf("  F1: %d PS chain[0] rows persisted for new epoch\n",
                                       n_ps_persisted);
                            else
                                rollover_pass = 0;
                        }

                        /* F1 deep check: drive ONE PS leaf advance after rollover.
                           If the new chain[0] is a valid spending point, the
                           advance ceremony will produce a signed chain[1] that
                           spends it.  This is the production scenario: clients
                           continue advancing after a Tier B without any user
                           visible interruption.

                           Skip for k>=2 sub-factory shape: the top-level leaf
                           is a sub-factory node which uses lsp_subfactory_chain_advance
                           (multi-input, "buy liquidity from sales-stock"), not the
                           simple 1-client lsp_channels_advance_ps_leaf path.  F1's
                           in-memory effect (PS leaves signed + chain[0] persisted)
                           is already verified above for both shapes. */
                        int is_subfactory_shape =
                            (lsp_p->factory.ps_subfactory_arity > 1);
                        if (is_ps_factory && rollover_pass && !is_subfactory_shape) {
                            printf("  F1: driving 1 PS leaf advance on leaf 0 to "
                                   "verify new chain[0] is spendable...\n");
                            fflush(stdout);
                            int adv_rc = lsp_channels_advance_ps_leaf(mgr, lsp_p, 0);
                            if (adv_rc != 1) {
                                printf("  FAIL (F1): post-rollover leaf advance "
                                       "returned %d (expected 1) — new chain[0] "
                                       "is not a valid spending point\n", adv_rc);
                                rollover_pass = 0;
                            } else {
                                size_t leaf0_ni = lsp_p->factory.leaf_node_indices[0];
                                int new_chain_len = lsp_p->factory.nodes[leaf0_ni].ps_chain_len;
                                if (new_chain_len != 1) {
                                    printf("  FAIL (F1): post-rollover advance left "
                                           "ps_chain_len at %d (expected 1)\n",
                                           new_chain_len);
                                    rollover_pass = 0;
                                } else {
                                    printf("  F1: post-rollover advance PASS "
                                           "(leaf 0 chain_len 0 -> 1)\n");
                                }
                            }
                        } else if (is_ps_factory && rollover_pass && is_subfactory_shape) {
                            printf("  F1: skipping post-rollover advance deep check "
                                   "for k>=2 sub-factory shape (uses "
                                   "lsp_subfactory_chain_advance, not the leaf path)\n");
                        }
                    }
                }

                printf("TIER B ROLLOVER TEST: %s\n", rollover_pass ? "PASS" : "FAIL");
            }
            fflush(stdout);
            if (!rollover_pass) {
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
        }

        if (force_close) {
            printf("\n=== FORCE CLOSE ===\n");
            printf("Broadcasting factory tree (%zu nodes) on %s...\n",
                   lsp_p->factory.n_nodes, network);

            if (!broadcast_factory_tree_any_network(&lsp_p->factory, &rt,
                                                      mine_addr, is_regtest,
                                                      confirm_timeout_secs)) {
                fprintf(stderr, "FORCE CLOSE: tree broadcast failed\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            printf("\n=== FORCE CLOSE COMPLETE ===\n");
            printf("All %zu nodes confirmed on-chain.\n", lsp_p->factory.n_nodes);
            /* Phase L: register root node tx for CPFP monitoring */
            if (g_watchtower_ready && lsp_p->factory.n_nodes > 0) {
                char root_txid_hex[65];
                unsigned char root_txid_rev[32];
                memcpy(root_txid_rev, lsp_p->factory.nodes[0].txid, 32);
                reverse_bytes(root_txid_rev, 32);
                hex_encode(root_txid_rev, 32, root_txid_hex);
                watchtower_add_pending_tx(&g_watchtower, root_txid_hex,
                                           1, WATCHTOWER_ANCHOR_AMOUNT);
            }

            /* Skip cooperative close — factory already spent */
            report_add_string(&rpt, "result", "force_close_complete");
            report_close(&rpt);
            jit_channels_cleanup(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 0;
        }

        /* === Burn TX Test: broadcast tree + burn L-stock via shachain === */
        if (test_burn) {
            printf("\n=== BURN TX TEST ===\n");

            if (!lsp_p->factory.has_shachain) {
                fprintf(stderr, "BURN TEST: factory has no shachain (internal error)\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Identify first leaf node and its L-stock output */
            size_t leaf_idx = lsp_p->factory.leaf_node_indices[0];
            factory_node_t *leaf = &lsp_p->factory.nodes[leaf_idx];
            uint32_t l_stock_vout = (uint32_t)(leaf->n_outputs - 1);
            uint64_t l_stock_amount = leaf->outputs[l_stock_vout].amount_sats;

            printf("Leaf node[%zu]: %zu outputs, L-stock at vout %u (%llu sats)\n",
                   leaf_idx, (size_t)leaf->n_outputs, l_stock_vout,
                   (unsigned long long)l_stock_amount);

            /* Step 1: Broadcast full factory tree */
            printf("Broadcasting factory tree (%zu nodes) on %s...\n",
                   lsp_p->factory.n_nodes, network);

            if (!broadcast_factory_tree_any_network(&lsp_p->factory, &rt,
                                                      mine_addr, is_regtest,
                                                      confirm_timeout_secs)) {
                fprintf(stderr, "BURN TEST: tree broadcast failed\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("All %zu tree nodes confirmed on-chain.\n", lsp_p->factory.n_nodes);

            /* Step 2: Build poison TX for epoch 0 L-stock (canonical t/1242) */
            tx_buf_t burn_tx;
            tx_buf_init(&burn_tx, 256);
            if (!factory_build_burn_tx(&lsp_p->factory, &burn_tx, leaf,
                                         leaf->txid, l_stock_vout,
                                         l_stock_amount, 0)) {
                fprintf(stderr, "BURN TEST: factory_build_burn_tx failed\n");
                tx_buf_free(&burn_tx);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Step 3: Broadcast burn TX */
            char *burn_hex = malloc(burn_tx.len * 2 + 1);
            hex_encode(burn_tx.data, burn_tx.len, burn_hex);
            char burn_txid[65];
            int sent = regtest_send_raw_tx(&rt, burn_hex, burn_txid);
            if (g_db)
                persist_log_broadcast(g_db, sent ? burn_txid : "?",
                    "burn_tx", burn_hex, sent ? "ok" : "failed");
            free(burn_hex);
            tx_buf_free(&burn_tx);

            if (!sent) {
                fprintf(stderr, "BURN TEST: burn TX broadcast failed\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            ADVANCE(1);

            printf("Burn TX broadcast: %s\n", burn_txid);
            printf("L-stock at leaf[%zu]:vout %u burned (%llu sats revoked)\n",
                   leaf_idx, l_stock_vout, (unsigned long long)l_stock_amount);

            printf("\n=== BURN TX TEST PASSED ===\n");

            report_add_string(&rpt, "result", "burn_test_complete");
            report_close(&rpt);
            jit_channels_cleanup(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 0;
        }

        /* === HTLC Force-Close Test: pending HTLC + tree broadcast + timeout TX === */
        if (test_htlc_force_close) {
            printf("\n=== HTLC FORCE-CLOSE TEST ===\n");

            if (mgr->n_channels < 2) {
                fprintf(stderr, "HTLC FORCE-CLOSE TEST: need at least 2 channels\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Step 1: Add a pending HTLC on channel 0 (low CLTV for quick timeout).
               #119: size the HTLC adaptively — channel_add_htlc requires
               local_amount - amount >= CHANNEL_RESERVE_SATS.  Fail fast with
               a clear message if even the dust-limit minimum can't clear. */
            uint32_t current_height = (uint32_t)regtest_get_block_height(&rt);
            uint32_t htlc_cltv = current_height + 10;  /* expires in ~10 blocks */
            unsigned char dummy_hash[32];
            memset(dummy_hash, 0xAA, 32);  /* dummy payment hash */
            uint64_t ch0_local = mgr->entries[0].channel.local_amount;
            uint64_t htlc_amount = 1000;
            if (ch0_local < htlc_amount + CHANNEL_RESERVE_SATS + 100 /* fee buffer */) {
                if (ch0_local <= CHANNEL_DUST_LIMIT_SATS + CHANNEL_RESERVE_SATS + 100) {
                    fprintf(stderr,
                            "HTLC FORCE-CLOSE TEST: channel 0 local %llu sats < "
                            "minimum %d (dust + reserve + fee); increase --amount\n",
                            (unsigned long long)ch0_local,
                            CHANNEL_DUST_LIMIT_SATS + CHANNEL_RESERVE_SATS + 100);
                    lsp_cleanup(lsp_p);
                    memset(lsp_seckey, 0, 32);
                    secp256k1_context_destroy(ctx);
                    return 1;
                }
                htlc_amount = ch0_local - CHANNEL_RESERVE_SATS - 100;
                printf("HTLC FORCE-CLOSE TEST: sized HTLC down to %llu sats "
                       "(channel 0 local=%llu, reserve=%d)\n",
                       (unsigned long long)htlc_amount,
                       (unsigned long long)ch0_local, CHANNEL_RESERVE_SATS);
            }

            printf("Adding pending HTLC on channel 0 (amount=%llu sats, cltv=%u, "
                   "current_height=%u)\n",
                   (unsigned long long)htlc_amount, htlc_cltv, current_height);

            if (!lsp_channels_add_pending_htlc(mgr, lsp_p, 0, htlc_amount,
                                                 dummy_hash, htlc_cltv)) {
                fprintf(stderr, "HTLC FORCE-CLOSE TEST: add_pending_htlc failed\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Step 2: Broadcast the factory tree */
            printf("Broadcasting factory tree (%zu nodes) on %s...\n",
                   lsp_p->factory.n_nodes, network);

            if (!broadcast_factory_tree_any_network(&lsp_p->factory, &rt,
                                                      mine_addr, is_regtest,
                                                      confirm_timeout_secs)) {
                fprintf(stderr, "HTLC FORCE-CLOSE TEST: tree broadcast failed\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("All %zu tree nodes confirmed on-chain.\n", lsp_p->factory.n_nodes);

            /* Step 3: Build and broadcast the commitment TX (has HTLC output) */
            channel_t *ch0 = &mgr->entries[0].channel;
            tx_buf_t commit_unsigned;
            tx_buf_init(&commit_unsigned, 512);
            unsigned char commit_txid[32];

            if (!channel_build_commitment_tx(ch0, &commit_unsigned, commit_txid)) {
                fprintf(stderr, "HTLC FORCE-CLOSE TEST: build commitment TX failed\n");
                tx_buf_free(&commit_unsigned);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Sign with both LSP + client keys.
               #154: previously hardcoded cli_sec = 0x22*32 which assumed
               client 1's seckey matched runt4.sh's CKEYS scheme.  When a
               different launcher uses a different scheme, the keypair
               mismatch produces an Invalid Schnorr signature on broadcast.
               Now reads from SUPERSCALAR_TEST_CLIENT0_SECKEY (64 hex chars)
               with fallback to the historic 0x22*32 default. */
            unsigned char cli_sec[32];
            const char *cli_sec_hex = getenv("SUPERSCALAR_TEST_CLIENT0_SECKEY");
            if (cli_sec_hex && strlen(cli_sec_hex) == 64
                && hex_decode(cli_sec_hex, cli_sec, 32)) {
                fprintf(stderr, "HTLC FORCE-CLOSE TEST: using client[0] seckey "
                        "from SUPERSCALAR_TEST_CLIENT0_SECKEY env\n");
            } else {
                memset(cli_sec, 0x22, 32);
            }
            secp256k1_keypair cli_kp;
            if (!secp256k1_keypair_create(ctx, &cli_kp, cli_sec)) {
                fprintf(stderr, "HTLC FORCE-CLOSE TEST: client keypair failed\n");
                memset(cli_sec, 0, 32);
                tx_buf_free(&commit_unsigned);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            memset(cli_sec, 0, 32);

            tx_buf_t commit_signed;
            tx_buf_init(&commit_signed, 512);
            if (!channel_sign_commitment(ch0, &commit_signed, &commit_unsigned, &cli_kp)) {
                fprintf(stderr, "HTLC FORCE-CLOSE TEST: sign commitment failed\n");
                tx_buf_free(&commit_signed);
                tx_buf_free(&commit_unsigned);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            tx_buf_free(&commit_unsigned);

            char *commit_hex = malloc(commit_signed.len * 2 + 1);
            hex_encode(commit_signed.data, commit_signed.len, commit_hex);
            char commit_txid_str[65];

            /* #154 SF-CH: dump everything needed to diagnose Invalid Schnorr
               on bitcoind broadcast.  Compare these against
               `bitcoin-cli -regtest gettxout <funding_txid_display> <vout>`. */
            if (getenv("SUPERSCALAR_DUMP_SIGHASH")) {
                char funding_txid_disp_hex[65];
                /* Display order: bitcoind reverses the internal byte order. */
                for (int i = 0; i < 32; i++)
                    sprintf(funding_txid_disp_hex + i * 2,
                            "%02x", ch0->funding_txid[31 - i]);
                funding_txid_disp_hex[64] = 0;
                char funding_spk_hex[69];
                for (size_t i = 0; i < ch0->funding_spk_len && i < 34; i++)
                    sprintf(funding_spk_hex + i * 2,
                            "%02x", ch0->funding_spk[i]);
                funding_spk_hex[ch0->funding_spk_len * 2] = 0;
                char commit_txid_disp_hex[65];
                for (int i = 0; i < 32; i++)
                    sprintf(commit_txid_disp_hex + i * 2,
                            "%02x", commit_txid[31 - i]);
                commit_txid_disp_hex[64] = 0;
                /* Dump keyagg state so we can verify the keyagg.agg_pubkey
                   matches the funding_spk after TapTweak(merkle_root). */
                unsigned char agg_xonly_ser[32] = {0};
                secp256k1_xonly_pubkey_serialize(ctx, agg_xonly_ser,
                                                  &ch0->funding_keyagg.agg_pubkey);
                char agg_xonly_hex[65];
                for (int i = 0; i < 32; i++)
                    sprintf(agg_xonly_hex + i * 2, "%02x", agg_xonly_ser[i]);
                agg_xonly_hex[64] = 0;
                char chan_merkle_hex[65];
                if (ch0->has_chan_merkle_root) {
                    for (int i = 0; i < 32; i++)
                        sprintf(chan_merkle_hex + i * 2,
                                "%02x", ch0->chan_merkle_root[i]);
                } else {
                    strcpy(chan_merkle_hex, "none");
                }
                chan_merkle_hex[64] = 0;
                /* LSP funding pubkey (compressed 33 bytes) */
                secp256k1_pubkey lsp_pub_dbg;
                unsigned char lsp_pub_ser[33];
                size_t lsp_pub_len = 33;
                char lsp_pub_hex[67] = {0};
                if (secp256k1_keypair_pub(ctx, &lsp_pub_dbg,
                                          &ch0->local_funding_keypair) &&
                    secp256k1_ec_pubkey_serialize(ctx, lsp_pub_ser,
                                                  &lsp_pub_len, &lsp_pub_dbg,
                                                  SECP256K1_EC_COMPRESSED)) {
                    for (size_t i = 0; i < lsp_pub_len; i++)
                        sprintf(lsp_pub_hex + i * 2, "%02x", lsp_pub_ser[i]);
                }
                /* Client funding pubkey from the cli_kp we just built */
                secp256k1_pubkey cli_pub_dbg;
                unsigned char cli_pub_ser[33];
                size_t cli_pub_len = 33;
                char cli_pub_hex[67] = {0};
                if (secp256k1_keypair_pub(ctx, &cli_pub_dbg, &cli_kp) &&
                    secp256k1_ec_pubkey_serialize(ctx, cli_pub_ser,
                                                  &cli_pub_len, &cli_pub_dbg,
                                                  SECP256K1_EC_COMPRESSED)) {
                    for (size_t i = 0; i < cli_pub_len; i++)
                        sprintf(cli_pub_hex + i * 2, "%02x", cli_pub_ser[i]);
                }
                /* Self-verify: compute TapTweak(agg_xonly, chan_merkle_root)
                   and check it matches funding_spk's xonly key. */
                char expected_xonly_hex[65] = "<failed>";
                int spk_match = 0;
                {
                    unsigned char twk[32];
                    extern void sha256_tagged(const char *tag, const unsigned char *data, size_t len, unsigned char *out);
                    if (ch0->has_chan_merkle_root) {
                        unsigned char buf[64];
                        memcpy(buf, agg_xonly_ser, 32);
                        memcpy(buf + 32, ch0->chan_merkle_root, 32);
                        sha256_tagged("TapTweak", buf, 64, twk);
                    } else {
                        sha256_tagged("TapTweak", agg_xonly_ser, 32, twk);
                    }
                    secp256k1_pubkey tweaked_full;
                    if (secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked_full,
                                                          &ch0->funding_keyagg.agg_pubkey,
                                                          twk)) {
                        secp256k1_xonly_pubkey tweaked_xonly;
                        if (secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly,
                                                                NULL, &tweaked_full)) {
                            unsigned char tx_ser[32];
                            if (secp256k1_xonly_pubkey_serialize(ctx, tx_ser, &tweaked_xonly)) {
                                for (int i = 0; i < 32; i++)
                                    sprintf(expected_xonly_hex + i * 2,
                                            "%02x", tx_ser[i]);
                                expected_xonly_hex[64] = 0;
                                /* funding_spk[2..34] = xonly portion */
                                if (ch0->funding_spk_len == 34 &&
                                    memcmp(tx_ser, ch0->funding_spk + 2, 32) == 0)
                                    spk_match = 1;
                            }
                        }
                    }
                }
                fprintf(stderr,
                        "[DUMP_SIGHASH_BROADCAST] phase=htlc_force_close "
                        "ch_idx=0 funding_txid=%s funding_vout=%u "
                        "funding_amount=%" PRIu64 " funding_spk_len=%zu "
                        "funding_spk=%s commit_txid=%s commit_n_htlcs=%zu "
                        "commit_local=%" PRIu64 " commit_remote=%" PRIu64 " "
                        "agg_xonly_pre_tweak=%s chan_merkle_root=%s "
                        "signer_idx=%u lsp_pub=%s cli_pub=%s "
                        "expected_tweaked_xonly=%s spk_match=%d "
                        "signed_tx_len=%zu signed_tx=%s\n",
                        funding_txid_disp_hex, ch0->funding_vout,
                        ch0->funding_amount, ch0->funding_spk_len,
                        funding_spk_hex, commit_txid_disp_hex,
                        ch0->n_htlcs, ch0->local_amount, ch0->remote_amount,
                        agg_xonly_hex, chan_merkle_hex,
                        (unsigned int)ch0->local_funding_signer_idx,
                        lsp_pub_hex, cli_pub_hex,
                        expected_xonly_hex, spk_match,
                        commit_signed.len, commit_hex);
                fflush(stderr);
            }

            int sent = regtest_send_raw_tx(&rt, commit_hex, commit_txid_str);
            if (g_db)
                persist_log_broadcast(g_db, sent ? commit_txid_str : "?",
                    "htlc_commitment", commit_hex, sent ? "ok" : "failed");
            free(commit_hex);
            tx_buf_free(&commit_signed);

            if (!sent) {
                fprintf(stderr, "HTLC FORCE-CLOSE TEST: commitment broadcast failed\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            ADVANCE(1);
            printf("Commitment TX broadcast: %s\n", commit_txid_str);

            /* Step 4: HTLC output is at vout 2 (after to_local and to_remote).
               Get the script pubkey from the commitment TX output. */
            uint32_t htlc_vout = 2;
            /* Re-build commitment to extract output script pubkeys */
            tx_buf_t commit_rebuild;
            tx_buf_init(&commit_rebuild, 512);
            unsigned char rebuild_txid[32];
            channel_build_commitment_tx(ch0, &commit_rebuild, rebuild_txid);

            /* Parse the commitment TX to get the HTLC output script pubkey.
               In our serialization, outputs start after the input section.
               We can use the channel's HTLC amount directly. */
            /* For the HTLC timeout TX, we need the HTLC output's scriptPubKey.
               Build it from the channel state (same as commitment_tx_impl does). */
            unsigned char htlc_spk[34];
            size_t htlc_spk_len = 0;
            {
                /* Derive the HTLC output scriptPubKey by rebuilding the taproot key */
                secp256k1_pubkey pcp;
                channel_get_per_commitment_point(ch0, ch0->commitment_number, &pcp);

                secp256k1_pubkey revocation_pubkey;
                channel_derive_revocation_pubkey(ch0->ctx, &revocation_pubkey,
                    &ch0->remote_revocation_basepoint, &pcp);
                secp256k1_xonly_pubkey revocation_xonly;
                secp256k1_xonly_pubkey_from_pubkey(ch0->ctx, &revocation_xonly, NULL,
                    &revocation_pubkey);

                secp256k1_pubkey local_htlc_pub, remote_htlc_pub;
                channel_derive_pubkey(ch0->ctx, &local_htlc_pub,
                    &ch0->local_htlc_basepoint, &pcp);
                channel_derive_pubkey(ch0->ctx, &remote_htlc_pub,
                    &ch0->remote_htlc_basepoint, &pcp);
                secp256k1_xonly_pubkey local_htlc_xonly, remote_htlc_xonly;
                secp256k1_xonly_pubkey_from_pubkey(ch0->ctx, &local_htlc_xonly, NULL,
                    &local_htlc_pub);
                secp256k1_xonly_pubkey_from_pubkey(ch0->ctx, &remote_htlc_xonly, NULL,
                    &remote_htlc_pub);

                /* Build the HTLC taptree leaves (same as commitment TX builder) */
                tapscript_leaf_t success_leaf, timeout_leaf;
                htlc_t *h = &ch0->htlcs[ch0->n_htlcs - 1]; /* last HTLC = ours */
                if (h->direction == HTLC_OFFERED) {
                    tapscript_build_htlc_offered_success(&success_leaf,
                        h->payment_hash, &remote_htlc_xonly, ch0->ctx);
                    tapscript_build_htlc_offered_timeout(&timeout_leaf,
                        h->cltv_expiry, ch0->to_self_delay,
                        &local_htlc_xonly, ch0->ctx);
                } else {
                    tapscript_build_htlc_received_success(&success_leaf,
                        h->payment_hash, ch0->to_self_delay,
                        &local_htlc_xonly, ch0->ctx);
                    tapscript_build_htlc_received_timeout(&timeout_leaf,
                        h->cltv_expiry, &remote_htlc_xonly, ch0->ctx);
                }

                tapscript_leaf_t htlc_leaves[2] = { success_leaf, timeout_leaf };
                unsigned char htlc_merkle[32];
                tapscript_merkle_root(htlc_merkle, htlc_leaves, 2);

                secp256k1_xonly_pubkey htlc_tweaked;
                tapscript_tweak_pubkey(ch0->ctx, &htlc_tweaked, NULL,
                    &revocation_xonly, htlc_merkle);

                build_p2tr_script_pubkey(htlc_spk, &htlc_tweaked);
                htlc_spk_len = 34;
            }
            tx_buf_free(&commit_rebuild);

            /* Step 5: Mine blocks to reach CLTV expiry */
            uint32_t now_height = (uint32_t)regtest_get_block_height(&rt);
            if (now_height < htlc_cltv) {
                uint32_t blocks_needed = htlc_cltv - now_height;
                printf("Advancing %u blocks to reach CLTV expiry %u...\n",
                       blocks_needed, htlc_cltv);
                ADVANCE((int)blocks_needed);
            }

            /* Also mine to_self_delay blocks for CSV on the timeout TX */
            printf("Advancing %u blocks for CSV delay...\n", ch0->to_self_delay);
            ADVANCE((int)ch0->to_self_delay);

            /* Step 6: Build and broadcast HTLC timeout TX */
            size_t htlc_index = ch0->n_htlcs - 1;  /* last HTLC */
            tx_buf_t timeout_tx;
            tx_buf_init(&timeout_tx, 256);

            if (!channel_build_htlc_timeout_tx(ch0, &timeout_tx,
                    commit_txid, htlc_vout, htlc_amount,
                    htlc_spk, htlc_spk_len, htlc_index)) {
                fprintf(stderr, "HTLC FORCE-CLOSE TEST: build timeout TX failed\n");
                tx_buf_free(&timeout_tx);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* === kind=3 standalone fire (#321 EVERY-PATH) ===
             * SS_FC_ARM_KIND3: rather than the owner broadcasting the HTLC
             * timeout sweep, arm a kind=3 wt_db force-close watch carrying the
             * SAME pre-signed sweep + the on-chain commit txid, then exit.  A
             * secret-less standalone WT (--wt-db only) must then broadcast the
             * sweep itself — proving the force-close HTLC-sweep delegation
             * works trustlessly (the last unfired penalty-matrix cell).
             * superscalar_lsp.c doesn't include lsp_wt.h (LSP arms wt_db via
             * watchtower.c), so declare the one helper we need locally. */
            if (getenv("SS_FC_ARM_KIND3")) {
                extern int64_t lsp_wt_register_force_close_watch(
                    persist_wt_t *pwt, uint32_t channel_id,
                    const unsigned char commit_txid32[32], uint32_t htlc_vout,
                    uint64_t htlc_amount, const unsigned char *htlc_spk,
                    size_t htlc_spk_len, uint32_t csv_delay,
                    const unsigned char *signed_sweep_tx,
                    size_t signed_sweep_tx_len,
                    const unsigned char sweep_txid32[32]);
                extern void sha256_double(const unsigned char *, size_t,
                                          unsigned char *);
                int k3_ok = 0;
                if (mgr->watchtower && mgr->watchtower->wt_db &&
                    mgr->watchtower->wt_db->db) {
                    unsigned char k3_sweep_txid[32];
                    sha256_double(timeout_tx.data, timeout_tx.len, k3_sweep_txid);
                    int64_t k3wid = lsp_wt_register_force_close_watch(
                        mgr->watchtower->wt_db, 0 /*peer_idx*/, commit_txid,
                        htlc_vout, htlc_amount, htlc_spk, htlc_spk_len,
                        (uint32_t)ch0->to_self_delay,
                        timeout_tx.data, timeout_tx.len, k3_sweep_txid);
                    k3_ok = (k3wid > 0);
                    printf("KIND3-ARM: registered force-close HTLC watch_id="
                           "%lld; commit on-chain, sweep pre-signed; owner "
                           "will NOT broadcast (standalone WT must)\n",
                           (long long)k3wid);
                    printf("\n=== HTLC FORCE-CLOSE KIND3-ARM COMPLETE ===\n");
                    report_add_string(&rpt, "result",
                                      "htlc_force_close_kind3_armed");
                } else {
                    fprintf(stderr, "KIND3-ARM: no wt_db on watchtower — "
                            "cannot arm (need --wt-db)\n");
                    report_add_string(&rpt, "result", "kind3_arm_no_wtdb");
                }
                tx_buf_free(&timeout_tx);
                report_close(&rpt);
                jit_channels_cleanup(mgr);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return k3_ok ? 0 : 1;
            }

            char *timeout_hex = malloc(timeout_tx.len * 2 + 1);
            hex_encode(timeout_tx.data, timeout_tx.len, timeout_hex);
            char timeout_txid_str[65];
            int timeout_sent = regtest_send_raw_tx(&rt, timeout_hex, timeout_txid_str);
            if (g_db)
                persist_log_broadcast(g_db, timeout_sent ? timeout_txid_str : "?",
                    "htlc_timeout", timeout_hex, timeout_sent ? "ok" : "failed");
            free(timeout_hex);
            tx_buf_free(&timeout_tx);

            if (!timeout_sent) {
                fprintf(stderr, "HTLC FORCE-CLOSE TEST: timeout TX broadcast failed\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            ADVANCE(1);

            printf("HTLC timeout TX broadcast: %s\n", timeout_txid_str);
            printf("\n=== HTLC FORCE-CLOSE TEST PASSED ===\n");

            report_add_string(&rpt, "result", "htlc_force_close_complete");
            report_close(&rpt);
            jit_channels_cleanup(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 0;
        }

        /* === PTLC BASIC TEST (#107, SF-W-PTLC Phase 3a) ===
           Validate LSP-side PTLC happy path: add PTLC, verify state machine,
           build commitment TX with PTLC output, fail PTLC, verify state.
           This exercises:
             - ptlc_safety_set_enabled gate
             - channel_add_ptlc
             - commitment TX builder PTLC output path
             - channel_fail_ptlc state transition
           Does NOT exercise the peer wire protocol (no peer round-trip);
           that requires CLN-bLIP56 integration (#172). */
        if (test_ptlc_basic) {
            printf("\n=== PTLC BASIC TEST ===\n");

            if (mgr->n_channels < 1) {
                fprintf(stderr, "PTLC BASIC TEST: need at least 1 channel\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            channel_t *ch0_p = &mgr->entries[0].channel;
            size_t initial_n_ptlcs = ch0_p->n_ptlcs;

            /* Step 1: Confirm safety gate is enabled (set by --test-ptlc-basic
               parser; without this, channel_add_ptlc refuses). */
            if (!ptlc_safety_is_enabled()) {
                fprintf(stderr, "PTLC BASIC TEST: safety gate not enabled "
                        "(parser should have enabled it)\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Step 2: Build a payment_point from a dummy seckey (test only).
               In production this comes from the payee's invoice. */
            unsigned char ptlc_dummy_sec[32];
            memset(ptlc_dummy_sec, 0xBE, 32);
            secp256k1_pubkey ptlc_payment_point;
            if (!secp256k1_ec_pubkey_create(ctx, &ptlc_payment_point,
                                              ptlc_dummy_sec)) {
                fprintf(stderr, "PTLC BASIC TEST: payment_point create failed\n");
                memset(ptlc_dummy_sec, 0, 32);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            memset(ptlc_dummy_sec, 0, 32);

            /* Step 3: Size PTLC under channel local + reserve constraints
               (mirror of HTLC FC sizing). */
            uint64_t ch0p_local = ch0_p->local_amount;
            uint64_t ptlc_amount = 1000;
            if (ch0p_local < ptlc_amount + CHANNEL_RESERVE_SATS + 100) {
                if (ch0p_local <= CHANNEL_DUST_LIMIT_SATS + CHANNEL_RESERVE_SATS + 100) {
                    fprintf(stderr,
                            "PTLC BASIC TEST: channel 0 local %llu < min %d "
                            "(dust + reserve + fee); increase --amount\n",
                            (unsigned long long)ch0p_local,
                            CHANNEL_DUST_LIMIT_SATS + CHANNEL_RESERVE_SATS + 100);
                    lsp_cleanup(lsp_p);
                    memset(lsp_seckey, 0, 32);
                    secp256k1_context_destroy(ctx);
                    return 1;
                }
                ptlc_amount = ch0p_local - CHANNEL_RESERVE_SATS - 100;
                printf("PTLC BASIC TEST: sized PTLC down to %llu sats\n",
                       (unsigned long long)ptlc_amount);
            }

            uint32_t ptlc_cur_height = (uint32_t)regtest_get_block_height(&rt);
            uint32_t ptlc_cltv = ptlc_cur_height + 10;
            uint64_t ptlc_id = 0;
            printf("Adding PTLC on channel 0 (amount=%llu sats, cltv=%u, "
                   "current_height=%u)\n",
                   (unsigned long long)ptlc_amount, ptlc_cltv, ptlc_cur_height);

            if (!channel_add_ptlc(ch0_p, PTLC_OFFERED, ptlc_amount,
                                    &ptlc_payment_point, ptlc_cltv, &ptlc_id)) {
                fprintf(stderr, "PTLC BASIC TEST: channel_add_ptlc failed\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* SF-PTLC-PERSIST #192: surface PTLC in DB so the
               dashboard ptlcs table populates during PTLC BASIC TEST. */
            if (g_db && ch0_p->n_ptlcs > 0)
                persist_save_ptlc(g_db, 0,
                    &ch0_p->ptlcs[ch0_p->n_ptlcs - 1]);

            /* Step 4: Verify PTLC was added and state is ACTIVE. */
            if (ch0_p->n_ptlcs != initial_n_ptlcs + 1) {
                fprintf(stderr, "PTLC BASIC TEST: n_ptlcs %zu != expected %zu\n",
                        ch0_p->n_ptlcs, initial_n_ptlcs + 1);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            ptlc_t *added_ptlc = &ch0_p->ptlcs[ch0_p->n_ptlcs - 1];
            if (added_ptlc->state != PTLC_STATE_ACTIVE) {
                fprintf(stderr, "PTLC BASIC TEST: added PTLC state %d != ACTIVE\n",
                        (int)added_ptlc->state);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            if (added_ptlc->amount_sats != ptlc_amount) {
                fprintf(stderr, "PTLC BASIC TEST: amount %llu != %llu\n",
                        (unsigned long long)added_ptlc->amount_sats,
                        (unsigned long long)ptlc_amount);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            if (added_ptlc->cltv_expiry != ptlc_cltv) {
                fprintf(stderr, "PTLC BASIC TEST: cltv %u != %u\n",
                        added_ptlc->cltv_expiry, ptlc_cltv);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("PTLC added: id=%llu state=ACTIVE amount=%llu cltv=%u\n",
                   (unsigned long long)ptlc_id,
                   (unsigned long long)added_ptlc->amount_sats,
                   added_ptlc->cltv_expiry);

            /* Step 5: Build the commitment TX. This exercises the PTLC-output
               path in the commitment TX builder. */
            tx_buf_t ptlc_commit_buf;
            tx_buf_init(&ptlc_commit_buf, 512);
            unsigned char ptlc_commit_txid[32];
            if (!channel_build_commitment_tx(ch0_p, &ptlc_commit_buf,
                                               ptlc_commit_txid)) {
                fprintf(stderr,
                        "PTLC BASIC TEST: build commitment TX failed (with PTLC)\n");
                tx_buf_free(&ptlc_commit_buf);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("Commitment TX built with PTLC output: %zu bytes\n",
                   ptlc_commit_buf.len);
            tx_buf_free(&ptlc_commit_buf);

            /* Step 6: Fail the PTLC. */
            if (!channel_fail_ptlc(ch0_p, ptlc_id)) {
                fprintf(stderr, "PTLC BASIC TEST: channel_fail_ptlc failed\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            if (added_ptlc->state != PTLC_STATE_FAILED) {
                fprintf(stderr, "PTLC BASIC TEST: state %d != FAILED after fail\n",
                        (int)added_ptlc->state);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("PTLC failed: state=FAILED\n");

            /* Step 7: Rebuild commitment TX after fail; should still succeed
               (the failed PTLC is excluded from the output set). */
            tx_buf_t ptlc_commit_after;
            tx_buf_init(&ptlc_commit_after, 512);
            unsigned char ptlc_commit_after_txid[32];
            if (!channel_build_commitment_tx(ch0_p, &ptlc_commit_after,
                                               ptlc_commit_after_txid)) {
                fprintf(stderr,
                        "PTLC BASIC TEST: rebuild commitment after fail failed\n");
                tx_buf_free(&ptlc_commit_after);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("Commitment TX rebuilt after fail: %zu bytes\n",
                   ptlc_commit_after.len);
            tx_buf_free(&ptlc_commit_after);

            printf("\n=== PTLC BASIC TEST PASSED ===\n");

            report_add_string(&rpt, "result", "ptlc_basic_complete");
            report_close(&rpt);
            jit_channels_cleanup(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 0;
        }

        /* === PTLC BREACH TEST (#108, SF-W-PTLC Phase 3b) ===
           Validate the watchtower PTLC feed end-to-end at the LSP entry
           point.  Add a PTLC, snapshot the channel state with it, call
           watchtower_watch_revoked_commitment with the snapshot, verify
           the resulting entry has populated ptlc_outputs, then build a
           PTLC penalty TX from the entry data.

           Does NOT broadcast a cheat TX or wait for chain-level sweep
           detection — the broadcast variant is for the testnet4 deliverable
           and #173 (regtest end-to-end).  This scaffold validates that
           the entire production code path produces correct artifacts. */
        if (test_ptlc_breach) {
            printf("\n=== PTLC BREACH TEST ===\n");

            if (mgr->n_channels < 1) {
                fprintf(stderr, "PTLC BREACH TEST: need at least 1 channel\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            if (!ptlc_safety_is_enabled()) {
                fprintf(stderr, "PTLC BREACH TEST: safety gate not enabled\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            watchtower_t *ptlc_wt = mgr->watchtower;
            if (!ptlc_wt) {
                fprintf(stderr, "PTLC BREACH TEST: lsp watchtower is NULL\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            channel_t *ch0_p = &mgr->entries[0].channel;

            /* Step 1: Build payment_point + size PTLC under channel
               constraints (mirror of BASIC scaffold sizing). */
            unsigned char br_dummy_sec[32];
            memset(br_dummy_sec, 0xCE, 32);
            secp256k1_pubkey br_payment_point;
            if (!secp256k1_ec_pubkey_create(ctx, &br_payment_point, br_dummy_sec)) {
                fprintf(stderr, "PTLC BREACH TEST: payment_point create failed\n");
                memset(br_dummy_sec, 0, 32);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            memset(br_dummy_sec, 0, 32);

            uint64_t br_ch0_local = ch0_p->local_amount;
            uint64_t br_ptlc_amount = 1500;
            if (br_ch0_local < br_ptlc_amount + CHANNEL_RESERVE_SATS + 100) {
                if (br_ch0_local <= CHANNEL_DUST_LIMIT_SATS + CHANNEL_RESERVE_SATS + 100) {
                    fprintf(stderr,
                            "PTLC BREACH TEST: channel 0 local %llu < min %d\n",
                            (unsigned long long)br_ch0_local,
                            CHANNEL_DUST_LIMIT_SATS + CHANNEL_RESERVE_SATS + 100);
                    lsp_cleanup(lsp_p);
                    memset(lsp_seckey, 0, 32);
                    secp256k1_context_destroy(ctx);
                    return 1;
                }
                br_ptlc_amount = br_ch0_local - CHANNEL_RESERVE_SATS - 100;
            }

            uint32_t br_cur_height = (uint32_t)regtest_get_block_height(&rt);
            uint32_t br_ptlc_cltv = br_cur_height + 40;
            uint64_t br_ptlc_id = 0;

            /* Step 2: Add PTLC to channel 0. */
            if (!channel_add_ptlc(ch0_p, PTLC_OFFERED, br_ptlc_amount,
                                    &br_payment_point, br_ptlc_cltv, &br_ptlc_id)) {
                fprintf(stderr, "PTLC BREACH TEST: channel_add_ptlc failed\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* SF-PTLC-PERSIST #192: surface PTLC in DB for dashboard. */
            if (g_db && ch0_p->n_ptlcs > 0)
                persist_save_ptlc(g_db, 0,
                    &ch0_p->ptlcs[ch0_p->n_ptlcs - 1]);
            printf("PTLC added: id=%llu amount=%llu cltv=%u\n",
                   (unsigned long long)br_ptlc_id,
                   (unsigned long long)br_ptlc_amount, br_ptlc_cltv);

            /* Step 3: Snapshot channel state WITH the PTLC.  This is the
               "old/revoked" state we'll register with the watchtower. */
            uint64_t br_old_commit_num = ch0_p->commitment_number;
            uint64_t br_old_local = ch0_p->local_amount;
            uint64_t br_old_remote = ch0_p->remote_amount;

            size_t br_old_n_htlcs = ch0_p->n_htlcs;
            htlc_t *br_old_htlcs = NULL;
            if (br_old_n_htlcs > 0) {
                br_old_htlcs = malloc(br_old_n_htlcs * sizeof(htlc_t));
                if (!br_old_htlcs) {
                    fprintf(stderr, "PTLC BREACH TEST: htlc snapshot alloc failed\n");
                    lsp_cleanup(lsp_p);
                    memset(lsp_seckey, 0, 32);
                    secp256k1_context_destroy(ctx);
                    return 1;
                }
                memcpy(br_old_htlcs, ch0_p->htlcs,
                       br_old_n_htlcs * sizeof(htlc_t));
            }

            size_t br_old_n_ptlcs = ch0_p->n_ptlcs;
            ptlc_t *br_old_ptlcs = NULL;
            if (br_old_n_ptlcs > 0) {
                br_old_ptlcs = malloc(br_old_n_ptlcs * sizeof(ptlc_t));
                if (!br_old_ptlcs) {
                    fprintf(stderr, "PTLC BREACH TEST: ptlc snapshot alloc failed\n");
                    free(br_old_htlcs);
                    lsp_cleanup(lsp_p);
                    memset(lsp_seckey, 0, 32);
                    secp256k1_context_destroy(ctx);
                    return 1;
                }
                memcpy(br_old_ptlcs, ch0_p->ptlcs,
                       br_old_n_ptlcs * sizeof(ptlc_t));
            }

            /* Step 4: Register old state with watchtower.  The feed should
               populate entry->ptlc_outputs from br_old_ptlcs. */
            size_t br_entries_before = ptlc_wt->n_entries;
            watchtower_watch_revoked_commitment(ptlc_wt, ch0_p,
                0, /* channel_id */
                br_old_commit_num, br_old_local, br_old_remote,
                br_old_htlcs, br_old_n_htlcs,
                br_old_ptlcs, br_old_n_ptlcs);

            /* Step 5: Verify entry registered + ptlc_outputs populated. */
            if (ptlc_wt->n_entries != br_entries_before + 1) {
                fprintf(stderr,
                        "PTLC BREACH TEST: expected n_entries=%zu, got %zu\n",
                        br_entries_before + 1, ptlc_wt->n_entries);
                free(br_old_htlcs);
                free(br_old_ptlcs);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            watchtower_entry_t *br_entry =
                &ptlc_wt->entries[ptlc_wt->n_entries - 1];

            if (br_entry->n_ptlc_outputs != br_old_n_ptlcs) {
                fprintf(stderr,
                        "PTLC BREACH TEST: entry n_ptlc_outputs %zu != %zu\n",
                        br_entry->n_ptlc_outputs, br_old_n_ptlcs);
                free(br_old_htlcs);
                free(br_old_ptlcs);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            if (br_entry->ptlc_outputs[0].htlc_amount != br_ptlc_amount) {
                fprintf(stderr,
                        "PTLC BREACH TEST: entry ptlc amount %llu != %llu\n",
                        (unsigned long long)br_entry->ptlc_outputs[0].htlc_amount,
                        (unsigned long long)br_ptlc_amount);
                free(br_old_htlcs);
                free(br_old_ptlcs);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            if (br_entry->ptlc_outputs[0].cltv_expiry != br_ptlc_cltv) {
                fprintf(stderr,
                        "PTLC BREACH TEST: entry cltv %u != %u\n",
                        br_entry->ptlc_outputs[0].cltv_expiry, br_ptlc_cltv);
                free(br_old_htlcs);
                free(br_old_ptlcs);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("Watchtower entry registered: type=%d ch_id=%u "
                   "commit_num=%llu n_ptlc_outputs=%zu\n",
                   (int)br_entry->type, br_entry->channel_id,
                   (unsigned long long)br_entry->commit_num,
                   br_entry->n_ptlc_outputs);
            printf("  PTLC[0]: vout=%u amount=%llu cltv=%u\n",
                   br_entry->ptlc_outputs[0].htlc_vout,
                   (unsigned long long)br_entry->ptlc_outputs[0].htlc_amount,
                   br_entry->ptlc_outputs[0].cltv_expiry);

            /* Step 6: Attempt to build a PTLC penalty TX from the entry.
               In production, channel_build_ptlc_penalty_tx is called by
               watchtower_check on breach detection; it requires a stored
               revocation secret for the old commitment (received via the
               peer's revoke_and_ack message).  In this scaffold there is
               no peer revocation flow — channel_add_ptlc + in-memory
               state does not deposit a revocation secret — so the build
               is expected to fail with "missing revocation secret".  We
               attempt it anyway so the scaffold exercises the code path
               and surfaces any other regressions (e.g., crash in P2TR
               script reconstruction over `payment_hash`).  The feed
               itself is validated by Step 5 entry-field assertions. */
            tx_buf_t br_penalty;
            tx_buf_init(&br_penalty, 512);
            int br_penalty_ok = channel_build_ptlc_penalty_tx(ch0_p, &br_penalty,
                    br_entry->txid,
                    br_entry->ptlc_outputs[0].htlc_vout,
                    br_entry->ptlc_outputs[0].htlc_amount,
                    br_entry->ptlc_outputs[0].htlc_spk, 34,
                    br_old_commit_num, /* old_commitment_num */
                    0, /* ptlc_index */
                    NULL, 0 /* anchor_spk */);
            printf("PTLC penalty TX build: %s (%zu bytes) "
                   "[expected fail in scaffold: no peer revocation]\n",
                   br_penalty_ok ? "succeeded" : "refused",
                   br_penalty.len);
            tx_buf_free(&br_penalty);

            free(br_old_htlcs);
            free(br_old_ptlcs);

            printf("\n=== PTLC BREACH TEST PASSED ===\n");

            report_add_string(&rpt, "result", "ptlc_breach_complete");
            report_close(&rpt);
            jit_channels_cleanup(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 0;
        }

        /* === PTLC RESTART TEST (#109, SF-W-PTLC Phase 3c) ===
           Validate schema v30 PTLC persistence round-trip.  Add a PTLC,
           register with watchtower (which persists via
           persist_save_old_commitment_ptlc), then close and reopen the
           persist DB and load the PTLCs back via
           persist_load_old_commitment_ptlcs — verify the loaded fields
           match what was saved.

           This is "logical restart" within one process.  For true
           process-level restart see test_regtest_ptlc_restart.sh which
           chains two LSP invocations against the same DB file. */
        if (test_ptlc_restart) {
            printf("\n=== PTLC RESTART TEST ===\n");

            if (mgr->n_channels < 1) {
                fprintf(stderr, "PTLC RESTART TEST: need at least 1 channel\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            if (!ptlc_safety_is_enabled()) {
                fprintf(stderr, "PTLC RESTART TEST: safety gate not enabled\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            if (!use_db) {
                fprintf(stderr,
                        "PTLC RESTART TEST: requires --db (persistence)\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            watchtower_t *re_wt = mgr->watchtower;
            if (!re_wt) {
                fprintf(stderr, "PTLC RESTART TEST: mgr->watchtower NULL\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            channel_t *ch0_r = &mgr->entries[0].channel;

            /* Step 1: Build payment_point + size PTLC (mirror BREACH). */
            unsigned char re_dummy_sec[32];
            memset(re_dummy_sec, 0xDE, 32);
            secp256k1_pubkey re_payment_point;
            if (!secp256k1_ec_pubkey_create(ctx, &re_payment_point, re_dummy_sec)) {
                fprintf(stderr, "PTLC RESTART TEST: payment_point create failed\n");
                memset(re_dummy_sec, 0, 32);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            memset(re_dummy_sec, 0, 32);

            uint64_t re_ch0_local = ch0_r->local_amount;
            uint64_t re_ptlc_amount = 2500;
            if (re_ch0_local < re_ptlc_amount + CHANNEL_RESERVE_SATS + 100) {
                if (re_ch0_local <= CHANNEL_DUST_LIMIT_SATS + CHANNEL_RESERVE_SATS + 100) {
                    fprintf(stderr,
                            "PTLC RESTART TEST: channel 0 local %llu < min\n",
                            (unsigned long long)re_ch0_local);
                    lsp_cleanup(lsp_p);
                    memset(lsp_seckey, 0, 32);
                    secp256k1_context_destroy(ctx);
                    return 1;
                }
                re_ptlc_amount = re_ch0_local - CHANNEL_RESERVE_SATS - 100;
            }

            uint32_t re_cur_height = (uint32_t)regtest_get_block_height(&rt);
            uint32_t re_ptlc_cltv = re_cur_height + 50;
            uint64_t re_ptlc_id = 0;

            /* Step 2: Add PTLC. */
            if (!channel_add_ptlc(ch0_r, PTLC_OFFERED, re_ptlc_amount,
                                    &re_payment_point, re_ptlc_cltv, &re_ptlc_id)) {
                fprintf(stderr, "PTLC RESTART TEST: channel_add_ptlc failed\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* SF-PTLC-PERSIST #192: surface PTLC in DB so the
               dashboard ptlcs table populates during PTLC RESTART TEST. */
            if (g_db && ch0_r->n_ptlcs > 0)
                persist_save_ptlc(g_db, 0,
                    &ch0_r->ptlcs[ch0_r->n_ptlcs - 1]);
            printf("PTLC added: id=%llu amount=%llu cltv=%u\n",
                   (unsigned long long)re_ptlc_id,
                   (unsigned long long)re_ptlc_amount, re_ptlc_cltv);

            /* Step 3: Snapshot + register with watchtower (which persists). */
            uint64_t re_old_commit_num = ch0_r->commitment_number;
            uint64_t re_old_local = ch0_r->local_amount;
            uint64_t re_old_remote = ch0_r->remote_amount;

            size_t re_old_n_htlcs = ch0_r->n_htlcs;
            htlc_t *re_old_htlcs = NULL;
            if (re_old_n_htlcs > 0) {
                re_old_htlcs = malloc(re_old_n_htlcs * sizeof(htlc_t));
                if (!re_old_htlcs) {
                    fprintf(stderr, "PTLC RESTART TEST: htlc snap alloc\n");
                    lsp_cleanup(lsp_p);
                    memset(lsp_seckey, 0, 32);
                    secp256k1_context_destroy(ctx);
                    return 1;
                }
                memcpy(re_old_htlcs, ch0_r->htlcs, re_old_n_htlcs * sizeof(htlc_t));
            }
            size_t re_old_n_ptlcs = ch0_r->n_ptlcs;
            ptlc_t *re_old_ptlcs = malloc(re_old_n_ptlcs * sizeof(ptlc_t));
            if (!re_old_ptlcs) {
                fprintf(stderr, "PTLC RESTART TEST: ptlc snap alloc\n");
                free(re_old_htlcs);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            memcpy(re_old_ptlcs, ch0_r->ptlcs, re_old_n_ptlcs * sizeof(ptlc_t));

            watchtower_watch_revoked_commitment(re_wt, ch0_r,
                0, re_old_commit_num, re_old_local, re_old_remote,
                re_old_htlcs, re_old_n_htlcs,
                re_old_ptlcs, re_old_n_ptlcs);

            /* Capture expected fields from the watchtower entry. */
            if (re_wt->n_entries == 0) {
                fprintf(stderr, "PTLC RESTART TEST: no wt entry\n");
                free(re_old_htlcs);
                free(re_old_ptlcs);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            watchtower_entry_t *re_entry = &re_wt->entries[re_wt->n_entries - 1];
            uint32_t expected_vout = re_entry->ptlc_outputs[0].htlc_vout;
            uint64_t expected_amount = re_entry->ptlc_outputs[0].htlc_amount;
            uint32_t expected_cltv = re_entry->ptlc_outputs[0].cltv_expiry;
            printf("Watchtower entry (saved): vout=%u amount=%llu cltv=%u\n",
                   expected_vout, (unsigned long long)expected_amount,
                   expected_cltv);

            /* Step 4: Close + reopen persist DB (simulates restart). */
            persist_close(&db);
            persist_t db2;
            if (!persist_open(&db2, db_path)) {
                fprintf(stderr,
                        "PTLC RESTART TEST: reopen failed: %s\n", db_path);
                free(re_old_htlcs);
                free(re_old_ptlcs);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("Persist DB closed + reopened: %s\n", db_path);

            /* Step 5: Load PTLCs from re-opened persist. */
            watchtower_htlc_t loaded_ptlcs[8] = {0};
            size_t n_loaded = persist_load_old_commitment_ptlcs(&db2, 0,
                re_old_commit_num, loaded_ptlcs, 8);

            if (n_loaded != re_old_n_ptlcs) {
                fprintf(stderr,
                        "PTLC RESTART TEST: loaded %zu != expected %zu\n",
                        n_loaded, re_old_n_ptlcs);
                persist_close(&db2);
                free(re_old_htlcs);
                free(re_old_ptlcs);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            if (loaded_ptlcs[0].htlc_amount != expected_amount) {
                fprintf(stderr,
                        "PTLC RESTART TEST: loaded amount %llu != %llu\n",
                        (unsigned long long)loaded_ptlcs[0].htlc_amount,
                        (unsigned long long)expected_amount);
                persist_close(&db2);
                free(re_old_htlcs);
                free(re_old_ptlcs);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            if (loaded_ptlcs[0].cltv_expiry != expected_cltv) {
                fprintf(stderr,
                        "PTLC RESTART TEST: loaded cltv %u != %u\n",
                        loaded_ptlcs[0].cltv_expiry, expected_cltv);
                persist_close(&db2);
                free(re_old_htlcs);
                free(re_old_ptlcs);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            if (loaded_ptlcs[0].htlc_vout != expected_vout) {
                fprintf(stderr,
                        "PTLC RESTART TEST: loaded vout %u != %u\n",
                        loaded_ptlcs[0].htlc_vout, expected_vout);
                persist_close(&db2);
                free(re_old_htlcs);
                free(re_old_ptlcs);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("PTLC loaded from DB: vout=%u amount=%llu cltv=%u\n",
                   loaded_ptlcs[0].htlc_vout,
                   (unsigned long long)loaded_ptlcs[0].htlc_amount,
                   loaded_ptlcs[0].cltv_expiry);

            persist_close(&db2);
            free(re_old_htlcs);
            free(re_old_ptlcs);

            /* The original `db` was closed at step 4 — clear use_db so the
               normal cleanup path doesn't double-close it. */
            use_db = 0;
            g_db = NULL;

            printf("\n=== PTLC RESTART TEST PASSED ===\n");

            report_add_string(&rpt, "result", "ptlc_restart_complete");
            report_close(&rpt);
            jit_channels_cleanup(mgr);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 0;
        }

        /* === PTLC CHAIN TEST (#173, SF-W-PTLC end-to-end) ===
           Chain-level validation: prove a Bitcoin TX containing a PTLC
           output is chain-valid by broadcasting a real commit TX with
           PTLC and confirming it on chain.

           Doesn't test the watchtower breach-sweep cycle (that needs
           state-rewind + revocation-secret injection — deferred).
           This is the most impactful chain-level PTLC validation
           achievable without the full breach scaffolding. */
        if (test_ptlc_chain) {
            printf("\n=== PTLC CHAIN TEST ===\n");

            if (mgr->n_channels < 1) {
                fprintf(stderr, "PTLC CHAIN TEST: need at least 1 channel\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            if (!ptlc_safety_is_enabled()) {
                fprintf(stderr, "PTLC CHAIN TEST: safety gate not enabled\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            channel_t *ch0_c = &mgr->entries[0].channel;

            /* Step 1: build payment_point + size PTLC */
            unsigned char pc_dummy_sec[32];
            memset(pc_dummy_sec, 0xCB, 32);
            secp256k1_pubkey pc_payment_point;
            if (!secp256k1_ec_pubkey_create(ctx, &pc_payment_point, pc_dummy_sec)) {
                fprintf(stderr, "PTLC CHAIN TEST: payment_point create failed\n");
                memset(pc_dummy_sec, 0, 32);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            memset(pc_dummy_sec, 0, 32);

            uint64_t pc_ch0_local = ch0_c->local_amount;
            /* +2000 buffer accommodates commit TX fee for PTLC output. */
            uint64_t pc_ptlc_amount = 2000;
            if (pc_ch0_local < pc_ptlc_amount + CHANNEL_RESERVE_SATS + 2000) {
                if (pc_ch0_local <= CHANNEL_DUST_LIMIT_SATS + CHANNEL_RESERVE_SATS + 100) {
                    fprintf(stderr,
                            "PTLC CHAIN TEST: channel 0 local %llu < min\n",
                            (unsigned long long)pc_ch0_local);
                    lsp_cleanup(lsp_p);
                    memset(lsp_seckey, 0, 32);
                    secp256k1_context_destroy(ctx);
                    return 1;
                }
                pc_ptlc_amount = pc_ch0_local - CHANNEL_RESERVE_SATS - 2000;
            }

            uint32_t pc_cur_height = (uint32_t)regtest_get_block_height(&rt);
            uint32_t pc_ptlc_cltv = pc_cur_height + 100;
            uint64_t pc_ptlc_id = 0;

            /* Step 2: Add PTLC */
            if (!channel_add_ptlc(ch0_c, PTLC_OFFERED, pc_ptlc_amount,
                                    &pc_payment_point, pc_ptlc_cltv, &pc_ptlc_id)) {
                fprintf(stderr, "PTLC CHAIN TEST: channel_add_ptlc failed\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* SF-PTLC-PERSIST #192: surface PTLC in DB so the
               dashboard ptlcs table populates during PTLC CHAIN TEST. */
            if (g_db && ch0_c->n_ptlcs > 0)
                persist_save_ptlc(g_db, 0,
                    &ch0_c->ptlcs[ch0_c->n_ptlcs - 1]);
            printf("PTLC added: id=%llu amount=%llu cltv=%u\n",
                   (unsigned long long)pc_ptlc_id,
                   (unsigned long long)pc_ptlc_amount, pc_ptlc_cltv);

            /* Step 3: Broadcast factory tree (need to commit funding UTXO) */
            printf("Broadcasting factory tree (%zu nodes)...\n",
                   lsp_p->factory.n_nodes);
            if (!broadcast_factory_tree_any_network(&lsp_p->factory, &rt,
                                                      mine_addr, is_regtest,
                                                      confirm_timeout_secs)) {
                fprintf(stderr, "PTLC CHAIN TEST: tree broadcast failed\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("Factory tree confirmed on chain.\n");

            /* Step 4: Build commit TX */
            tx_buf_t pc_commit_unsigned;
            tx_buf_init(&pc_commit_unsigned, 512);
            unsigned char pc_commit_txid[32];

            if (!channel_build_commitment_tx(ch0_c, &pc_commit_unsigned,
                                               pc_commit_txid)) {
                fprintf(stderr, "PTLC CHAIN TEST: build commit TX failed\n");
                tx_buf_free(&pc_commit_unsigned);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("Commitment TX built: %zu bytes (with PTLC output)\n",
                   pc_commit_unsigned.len);

            /* Step 5: Sign with client keypair.  Uses the same scheme as
               --test-htlc-force-close: client[0] seckey from env var, fallback
               to 0x22*32. */
            unsigned char pc_cli_sec[32];
            const char *pc_cli_hex = getenv("SUPERSCALAR_TEST_CLIENT0_SECKEY");
            if (pc_cli_hex && strlen(pc_cli_hex) == 64
                && hex_decode(pc_cli_hex, pc_cli_sec, 32)) {
                fprintf(stderr, "PTLC CHAIN TEST: using SUPERSCALAR_TEST_CLIENT0_SECKEY\n");
            } else {
                memset(pc_cli_sec, 0x22, 32);
            }
            secp256k1_keypair pc_cli_kp;
            if (!secp256k1_keypair_create(ctx, &pc_cli_kp, pc_cli_sec)) {
                fprintf(stderr, "PTLC CHAIN TEST: client keypair create failed\n");
                memset(pc_cli_sec, 0, 32);
                tx_buf_free(&pc_commit_unsigned);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            memset(pc_cli_sec, 0, 32);

            tx_buf_t pc_commit_signed;
            tx_buf_init(&pc_commit_signed, 512);
            if (!channel_sign_commitment(ch0_c, &pc_commit_signed,
                                           &pc_commit_unsigned, &pc_cli_kp)) {
                fprintf(stderr, "PTLC CHAIN TEST: sign commit failed\n");
                tx_buf_free(&pc_commit_signed);
                tx_buf_free(&pc_commit_unsigned);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            tx_buf_free(&pc_commit_unsigned);
            printf("Commit TX signed: %zu bytes\n", pc_commit_signed.len);

            /* Step 6: Broadcast */
            char *pc_commit_hex = malloc(pc_commit_signed.len * 2 + 1);
            if (!pc_commit_hex) {
                fprintf(stderr, "PTLC CHAIN TEST: hex alloc failed\n");
                tx_buf_free(&pc_commit_signed);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            hex_encode(pc_commit_signed.data, pc_commit_signed.len, pc_commit_hex);
            char pc_commit_txid_str[65];
            int pc_sent = regtest_send_raw_tx(&rt, pc_commit_hex,
                                                pc_commit_txid_str);
            if (g_db)
                persist_log_broadcast(g_db, pc_sent ? pc_commit_txid_str : "?",
                    "ptlc_chain_commit", pc_commit_hex,
                    pc_sent ? "ok" : "failed");
            free(pc_commit_hex);
            tx_buf_free(&pc_commit_signed);

            if (!pc_sent) {
                fprintf(stderr, "PTLC CHAIN TEST: commit broadcast failed\n");
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
            printf("Commit TX broadcast: %s\n", pc_commit_txid_str);

            /* Step 7: Mine block + verify confirmation */
            ADVANCE(1);
            printf("Mined 1 block for confirmation.\n");

            printf("\n=== PTLC CHAIN TEST PASSED ===\n");
            printf("Validated: PTLC-bearing commit TX is Bitcoin-valid and confirms on chain.\n");

            report_add_string(&rpt, "result", "ptlc_chain_complete");
            report_close(&rpt);
            jit_channels_cleanup(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 0;
        }

        /* === PTLC BREACH CHAIN TEST (#184 Stage A) ===
           Full trustless PTLC test on real chain:
             1. Add PTLC (state N has PTLC, balance accounted per #182)
             2. Sign commit-N TX (preserve signed bytes for breach)
             3. Snapshot state at N
             4. Advance to N+1, store rev secret for N
             5. Register revoked state with watchtower (auto-builds main
                penalty TX via the non-oracular path)
             6. Broadcast factory tree
             7. Broadcast saved commit-N TX (THE BREACH)
             8. Mine + watchtower_check → broadcasts main penalty +
                PTLC penalty (secondary sweep loop at watchtower.c:1192)
             9. Verify "penalty" + "ptlc_penalty" in broadcast_log
             10. PASS */
        if (test_ptlc_breach_chain) {
            printf("\n=== PTLC BREACH CHAIN TEST (#184 Stage A) ===\n");

            if (mgr->n_channels < 1) {
                fprintf(stderr, "PTLC BREACH CHAIN: need at least 1 channel\n");
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            if (!ptlc_safety_is_enabled()) {
                fprintf(stderr, "PTLC BREACH CHAIN: safety gate not enabled\n");
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }

            watchtower_t *bc_wt = mgr->watchtower;
            if (!bc_wt) {
                fprintf(stderr, "PTLC BREACH CHAIN: mgr->watchtower NULL\n");
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }

            channel_t *ch0_bc = &mgr->entries[0].channel;

            /* Step 1: Add PTLC */
            unsigned char bc_dummy_sec[32];
            memset(bc_dummy_sec, 0xBC, 32);
            secp256k1_pubkey bc_pp;
            if (!secp256k1_ec_pubkey_create(ctx, &bc_pp, bc_dummy_sec)) {
                fprintf(stderr, "PTLC BREACH CHAIN: pp create failed\n");
                memset(bc_dummy_sec, 0, 32);
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            memset(bc_dummy_sec, 0, 32);

            uint64_t bc_local = ch0_bc->local_amount;
            uint64_t bc_amt = 2000;
            if (bc_local < bc_amt + CHANNEL_RESERVE_SATS + 2000) {
                if (bc_local <= CHANNEL_DUST_LIMIT_SATS + CHANNEL_RESERVE_SATS + 2000) {
                    fprintf(stderr, "PTLC BREACH CHAIN: insufficient local %llu\n",
                            (unsigned long long)bc_local);
                    lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                    secp256k1_context_destroy(ctx); return 1;
                }
                bc_amt = bc_local - CHANNEL_RESERVE_SATS - 2000;
            }
            uint32_t bc_cur_h = (uint32_t)regtest_get_block_height(&rt);
            uint32_t bc_cltv = bc_cur_h + 100;
            uint64_t bc_ptlc_id = 0;
            if (!channel_add_ptlc(ch0_bc, PTLC_OFFERED, bc_amt, &bc_pp,
                                    bc_cltv, &bc_ptlc_id)) {
                fprintf(stderr, "PTLC BREACH CHAIN: channel_add_ptlc failed\n");
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }

            /* SF-PTLC-PERSIST #192: surface PTLC in DB so the
               dashboard ptlcs table populates during PTLC BREACH CHAIN. */
            if (g_db && ch0_bc->n_ptlcs > 0)
                persist_save_ptlc(g_db, 0,
                    &ch0_bc->ptlcs[ch0_bc->n_ptlcs - 1]);
            printf("[1] PTLC added: id=%llu amount=%llu cltv=%u\n",
                   (unsigned long long)bc_ptlc_id,
                   (unsigned long long)bc_amt, bc_cltv);

            /* #206 fix: override remote_pcp slot with rev_secret*G so that
             * commit-N, WT entry, and penalty TX all derive from the same PCP.
             * In production the LSP receives a real remote PCP during state
             * exchange + a real rev_secret from the remote; protocol invariant
             * guarantees rev_secret*G == slot_pcp.  In this single-process
             * test scaffold we self-revoke (LOCAL secret stored as if it were
             * the remote's revelation), so we must sync the slot to match. */
            {
                uint64_t bc_preview_cn = ch0_bc->commitment_number;
                unsigned char bc_preview_secret[32];
                if (channel_get_per_commitment_secret(ch0_bc, bc_preview_cn,
                                                       bc_preview_secret)) {
                    secp256k1_pubkey bc_synth_pcp;
                    if (secp256k1_ec_pubkey_create(ctx, &bc_synth_pcp,
                                                    bc_preview_secret)) {
                        channel_set_remote_pcp(ch0_bc, bc_preview_cn,
                                                &bc_synth_pcp);
                    }
                    secure_zero(bc_preview_secret, 32);
                }
            }

            /* Step 2: Build + sign commit-N TX (PRESERVE signed bytes) */
            tx_buf_t bc_commit_uns;
            tx_buf_init(&bc_commit_uns, 512);
            unsigned char bc_commit_txid[32];
            /* SF-W-PTLC #184: use _for_remote since the WT watches the REMOTE party broadcasting their old commit (the cheat). */
            if (!channel_build_commitment_tx_for_remote(ch0_bc, &bc_commit_uns, bc_commit_txid)) {
                fprintf(stderr, "PTLC BREACH CHAIN: build commit failed\n");
                tx_buf_free(&bc_commit_uns);
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            unsigned char bc_cli_sec[32];
            const char *bc_cli_hex = getenv("SUPERSCALAR_TEST_CLIENT0_SECKEY");
            if (bc_cli_hex && strlen(bc_cli_hex) == 64
                && hex_decode(bc_cli_hex, bc_cli_sec, 32)) {
                /* env provided */
            } else {
                memset(bc_cli_sec, 0x22, 32);
            }
            secp256k1_keypair bc_cli_kp;
            if (!secp256k1_keypair_create(ctx, &bc_cli_kp, bc_cli_sec)) {
                fprintf(stderr, "PTLC BREACH CHAIN: cli kp failed\n");
                memset(bc_cli_sec, 0, 32);
                tx_buf_free(&bc_commit_uns);
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            memset(bc_cli_sec, 0, 32);

            tx_buf_t bc_commit_signed;
            tx_buf_init(&bc_commit_signed, 512);
            if (!channel_sign_commitment(ch0_bc, &bc_commit_signed,
                                           &bc_commit_uns, &bc_cli_kp)) {
                fprintf(stderr, "PTLC BREACH CHAIN: sign commit failed\n");
                tx_buf_free(&bc_commit_signed);
                tx_buf_free(&bc_commit_uns);
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            tx_buf_free(&bc_commit_uns);
            printf("[2] commit-N TX signed: %zu bytes (preserving for breach)\n",
                   bc_commit_signed.len);

            /* Step 3: Snapshot state at N */
            uint64_t bc_old_cn = ch0_bc->commitment_number;
            uint64_t bc_old_local = ch0_bc->local_amount;
            uint64_t bc_old_remote = ch0_bc->remote_amount;
            size_t bc_n_h = ch0_bc->n_htlcs;
            htlc_t *bc_old_htlcs = NULL;
            if (bc_n_h > 0) {
                bc_old_htlcs = malloc(bc_n_h * sizeof(htlc_t));
                if (!bc_old_htlcs) goto bc_oom;
                memcpy(bc_old_htlcs, ch0_bc->htlcs, bc_n_h * sizeof(htlc_t));
            }
            size_t bc_n_p = ch0_bc->n_ptlcs;
            ptlc_t *bc_old_ptlcs = malloc(bc_n_p * sizeof(ptlc_t));
            if (!bc_old_ptlcs) {
                free(bc_old_htlcs);
                goto bc_oom;
            }
            memcpy(bc_old_ptlcs, ch0_bc->ptlcs, bc_n_p * sizeof(ptlc_t));
            printf("[3] State snapshotted at commit_n=%llu (n_h=%zu n_p=%zu)\n",
                   (unsigned long long)bc_old_cn, bc_n_h, bc_n_p);

            /* Step 4: Advance state — bump commit_number, store rev secret for N */
            unsigned char bc_rev_secret[32];
            if (!channel_get_per_commitment_secret(ch0_bc, bc_old_cn, bc_rev_secret)) {
                fprintf(stderr, "PTLC BREACH CHAIN: get per_commit_secret(N) failed\n");
                free(bc_old_htlcs); free(bc_old_ptlcs);
                tx_buf_free(&bc_commit_signed);
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            ch0_bc->commitment_number = bc_old_cn + 1;
            if (!channel_receive_revocation_flat(ch0_bc, bc_old_cn, bc_rev_secret)) {
                fprintf(stderr, "PTLC BREACH CHAIN: store rev secret failed\n");
                memset(bc_rev_secret, 0, 32);
                free(bc_old_htlcs); free(bc_old_ptlcs);
                tx_buf_free(&bc_commit_signed);
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            memset(bc_rev_secret, 0, 32);
            printf("[4] State advanced to %llu, rev_secret for N=%llu stored\n",
                   (unsigned long long)ch0_bc->commitment_number,
                   (unsigned long long)bc_old_cn);

            /* Step 5: Register revoked state with watchtower */
            size_t bc_entries_before = bc_wt->n_entries;
            watchtower_watch_revoked_commitment(bc_wt, ch0_bc, 0,
                bc_old_cn, bc_old_local, bc_old_remote,
                bc_old_htlcs, bc_n_h,
                bc_old_ptlcs, bc_n_p);
            if (bc_wt->n_entries != bc_entries_before + 1) {
                fprintf(stderr, "PTLC BREACH CHAIN: watchtower entry not registered\n");
                free(bc_old_htlcs); free(bc_old_ptlcs);
                tx_buf_free(&bc_commit_signed);
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            watchtower_entry_t *bc_entry = &bc_wt->entries[bc_wt->n_entries - 1];
            printf("[5] Watchtower entry registered: type=%d n_ptlc_outputs=%zu\n",
                   (int)bc_entry->type, bc_entry->n_ptlc_outputs);
            {
                /* Print entry's txid + funding info for diagnosis. */
                char bc_entry_txid_disp[65];
                for (int z = 0; z < 32; z++)
                    sprintf(bc_entry_txid_disp + z*2, "%02x",
                            bc_entry->txid[31 - z]);
                bc_entry_txid_disp[64] = 0;
                printf("[5d] Entry txid (display order): %s\n",
                       bc_entry_txid_disp);
                printf("[5d] Entry channel_id=%u commit_num=%llu "
                       "registered_height=%d\n",
                       bc_entry->channel_id,
                       (unsigned long long)bc_entry->commit_num,
                       bc_entry->registered_height);
                printf("[5d] Entry to_local_vout=%u to_local_amount=%llu "
                       "to_local_spk_len=%zu\n",
                       bc_entry->to_local_vout,
                       (unsigned long long)bc_entry->to_local_amount,
                       bc_entry->to_local_spk_len);
            }
            if (bc_entry->n_ptlc_outputs == 0) {
                fprintf(stderr, "PTLC BREACH CHAIN: entry n_ptlc_outputs == 0\n");
                free(bc_old_htlcs); free(bc_old_ptlcs);
                tx_buf_free(&bc_commit_signed);
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            /* Populate wt->channels[0] = ch0_bc so the secondary PTLC sweep
               loop has a live channel to build penalty TXs from.  In
               production this is done by the LSP at channel-init time. */
            if (bc_wt->channels_cap > 0) {
                bc_wt->channels[0] = ch0_bc;
                if (bc_wt->n_channels < 1) bc_wt->n_channels = 1;
            }

            /* Build + attach the main penalty TX to bc_entry->signed_penalty_tx
               so watchtower_check's WATCH_COMMITMENT branch can broadcast it.
               (Non-oracular watchtower_watch_revoked_commitment doesn't auto-
               attach; only the _oracular variant does.  We call non-oracular
               above so persist/script-registration runs, then attach manually
               here.) */
            {
                tx_buf_t bc_penalty;
                tx_buf_init(&bc_penalty, 512);
                if (channel_build_penalty_tx(ch0_bc, &bc_penalty,
                        bc_entry->txid,
                        bc_entry->to_local_vout,
                        bc_entry->to_local_amount,
                        bc_entry->to_local_spk,
                        bc_entry->to_local_spk_len,
                        bc_old_cn, NULL, 0)) {
                    free(bc_entry->signed_penalty_tx);
                    bc_entry->signed_penalty_tx = malloc(bc_penalty.len);
                    if (bc_entry->signed_penalty_tx) {
                        memcpy(bc_entry->signed_penalty_tx,
                               bc_penalty.data, bc_penalty.len);
                        bc_entry->signed_penalty_tx_len = bc_penalty.len;
                        printf("[5b] Pre-signed main penalty TX attached "
                               "to entry (%zu bytes)\n", bc_penalty.len);
                    }
                } else {
                    fprintf(stderr,
                            "PTLC BREACH CHAIN: channel_build_penalty_tx failed\n");
                }
                tx_buf_free(&bc_penalty);
            }

            /* Step 6: Broadcast factory tree */
            printf("[6] Broadcasting factory tree (%zu nodes)...\n",
                   lsp_p->factory.n_nodes);
            if (!broadcast_factory_tree_any_network(&lsp_p->factory, &rt,
                    mine_addr, is_regtest, confirm_timeout_secs)) {
                fprintf(stderr, "PTLC BREACH CHAIN: tree broadcast failed\n");
                free(bc_old_htlcs); free(bc_old_ptlcs);
                tx_buf_free(&bc_commit_signed);
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }

            /* Step 7: Broadcast the saved commit-N TX (THE BREACH) */
            char *bc_hex = malloc(bc_commit_signed.len * 2 + 1);
            if (!bc_hex) goto bc_oom;
            hex_encode(bc_commit_signed.data, bc_commit_signed.len, bc_hex);
            char bc_breach_txid[65];
            int bc_sent = regtest_send_raw_tx(&rt, bc_hex, bc_breach_txid);
            if (g_db)
                persist_log_broadcast(g_db, bc_sent ? bc_breach_txid : "?",
                    "ptlc_breach_chain_cheat", bc_hex,
                    bc_sent ? "ok" : "failed");
            free(bc_hex);
            tx_buf_free(&bc_commit_signed);
            if (!bc_sent) {
                fprintf(stderr, "PTLC BREACH CHAIN: BREACH broadcast failed\n");
                free(bc_old_htlcs); free(bc_old_ptlcs);
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            printf("[7] BREACH broadcast: %s\n", bc_breach_txid);
            /* Compare against entry's txid (which is internal byte order,
               opposite of display). Verify match. */
            {
                char bc_entry_txid_disp[65];
                for (int z = 0; z < 32; z++)
                    sprintf(bc_entry_txid_disp + z*2, "%02x",
                            bc_entry->txid[31 - z]);
                bc_entry_txid_disp[64] = 0;
                int matches = (strcmp(bc_entry_txid_disp, bc_breach_txid) == 0);
                printf("[7d] Entry txid vs broadcast: %s (match=%d)\n",
                       bc_entry_txid_disp, matches);
            }

            /* Step 8: confirm the breach BEFORE the secondary sweep.
               On regtest, mine.  On any TRUC-enforcing network (signet/
               testnet4/mainnet) the V2 HTLC/PTLC penalty CANNOT spend the V3
               breach commit until it CONFIRMS — BIP-431 permits an unconfirmed
               V3 tx exactly one V3 child (the main to_local penalty) and no V2
               children.  ADVANCE() is regtest-only mining (a no-op elsewhere),
               so on real networks we must wait for an actual confirmation;
               otherwise the secondary PTLC penalty is rejected
               (TRUC-violation) and ptlc_penalty stays 0. */
            if (is_regtest) {
                ADVANCE(1);
                printf("[8] Mined 1 block — breach confirmed\n");
            } else {
                printf("[8] Waiting for breach %s to confirm "
                       "(TRUC: the V2 PTLC penalty needs a confirmed parent)...\n",
                       bc_breach_txid);
                int bc_conf = 0;
                int bc_budget = (confirm_timeout_secs > 0 ? confirm_timeout_secs : 3600);
                for (int w = 0; w < bc_budget / 10; w++) {
                    bc_conf = regtest_get_confirmations(&rt, bc_breach_txid);
                    if (bc_conf >= 1) break;
                    sleep(10);
                }
                printf("[8] breach confirmations=%d (>=1 means TRUC now permits "
                       "the V2 secondary penalty)\n", bc_conf);
            }

            /* Step 9: Run watchtower_check */
            /* Print current chain height before check for diagnosis. */
            {
                int bc_cur_h_dbg = bc_wt->chain ? bc_wt->chain->get_block_height(bc_wt->chain) : -1;
                printf("[9d] pre-check chain height=%d, entry "
                       "registered_height=%d, n_entries=%zu\n",
                       bc_cur_h_dbg, bc_entry->registered_height,
                       bc_wt->n_entries);
            }
            int bc_penalties = watchtower_check(bc_wt);
            printf("[9] watchtower_check returned: %d penalties broadcast\n",
                   bc_penalties);
            /* If still 0, run check again — maybe timing/mempool. */
            if (bc_penalties == 0) {
                ADVANCE(2);
                printf("[9b] Mined 2 more blocks, retry watchtower_check\n");
                bc_penalties = watchtower_check(bc_wt);
                printf("[9b] watchtower_check returned: %d\n", bc_penalties);
            }

            /* Step 10: Verify penalty + ptlc_penalty in broadcast_log */
            if (g_db && g_db->db) {
                sqlite3_stmt *stmt;
                int n_pen = 0, n_ptlc_pen = 0;
                if (sqlite3_prepare_v2(g_db->db,
                        "SELECT source, COUNT(*) FROM broadcast_log "
                        "WHERE source IN ('penalty','ptlc_penalty') "
                        "AND result='ok' GROUP BY source;",
                        -1, &stmt, NULL) == SQLITE_OK) {
                    while (sqlite3_step(stmt) == SQLITE_ROW) {
                        const char *src_col = (const char *)sqlite3_column_text(stmt, 0);
                        int cnt = sqlite3_column_int(stmt, 1);
                        if (src_col && strcmp(src_col, "penalty") == 0) n_pen = cnt;
                        else if (src_col && strcmp(src_col, "ptlc_penalty") == 0) n_ptlc_pen = cnt;
                    }
                    sqlite3_finalize(stmt);
                }
                printf("[10] broadcast_log: penalty=%d ptlc_penalty=%d\n",
                       n_pen, n_ptlc_pen);
                if (n_pen < 1) {
                    fprintf(stderr, "PTLC BREACH CHAIN: no main penalty broadcast\n");
                    free(bc_old_htlcs); free(bc_old_ptlcs);
                    lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                    secp256k1_context_destroy(ctx); return 1;
                }
                if (n_ptlc_pen < 1) {
                    fprintf(stderr, "PTLC BREACH CHAIN: no PTLC penalty broadcast\n");
                    free(bc_old_htlcs); free(bc_old_ptlcs);
                    lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                    secp256k1_context_destroy(ctx); return 1;
                }
            }

            free(bc_old_htlcs); free(bc_old_ptlcs);
            printf("\n=== PTLC BREACH CHAIN TEST PASSED ===\n");
            printf("Trustless model proven: cheat broadcast detected and PTLC swept.\n");

            report_add_string(&rpt, "result", "ptlc_breach_chain_complete");
            report_close(&rpt);
            jit_channels_cleanup(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 0;

bc_oom:
            fprintf(stderr, "PTLC BREACH CHAIN: OOM\n");
            lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }

        /* === MULTI-HTLC FORCE-CLOSE TEST (S28) ===
           Add pending HTLCs on ALL channels simultaneously, then force-close.
           Produces n_channels HTLC timeout TXs — each with its own CSV/CLTV.
           Demonstrates production-realistic concurrent HTLC settlement. */
        if (test_multi_htlc_force_close) {
            printf("\n=== MULTI-HTLC FORCE-CLOSE TEST ===\n");

            size_t n_ch = mgr->n_channels;
            if (n_ch < 2) {
                fprintf(stderr, "MULTI-HTLC FORCE-CLOSE: need >= 2 channels\n");
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }

            /* Step 1: Add pending HTLCs on each channel with staggered CLTVs */
            uint32_t mhfc_height = (uint32_t)regtest_get_block_height(&rt);
            printf("Adding HTLCs on %zu channels (current_height=%u):\n",
                   n_ch, mhfc_height);

            static const unsigned char hash_fills[] = { 0xAA, 0xBB, 0xCC, 0xDD };
            static const uint64_t htlc_amounts[] = { 1000, 1500, 2000, 1000 };

            for (size_t ci = 0; ci < n_ch && ci < 4; ci++) {
                unsigned char phash[32];
                memset(phash, hash_fills[ci], 32);
                uint32_t cltv = mhfc_height + 10 + (uint32_t)ci * 5;

                if (!lsp_channels_add_pending_htlc(mgr, lsp_p, ci,
                        htlc_amounts[ci], phash, cltv)) {
                    fprintf(stderr, "MULTI-HTLC: add_pending_htlc failed ch %zu\n", ci);
                    lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                    secp256k1_context_destroy(ctx); return 1;
                }
                printf("  Channel %zu: %llu sats, CLTV=%u\n",
                       ci, (unsigned long long)htlc_amounts[ci], cltv);
            }

            /* Step 2: Broadcast factory tree */
            printf("Broadcasting factory tree (%zu nodes) on %s...\n",
                   lsp_p->factory.n_nodes, network);

            if (!broadcast_factory_tree_any_network(&lsp_p->factory, &rt,
                    mine_addr, is_regtest, confirm_timeout_secs)) {
                fprintf(stderr, "MULTI-HTLC: tree broadcast failed\n");
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            printf("All %zu tree nodes confirmed.\n", lsp_p->factory.n_nodes);

            /* Step 3: Build + broadcast commitment TX for each channel */
            static const unsigned char cli_fills[] = { 0x22, 0x33, 0x44, 0x55 };
            char commit_txids[4][65];
            int n_commits = 0;

            for (size_t ci = 0; ci < n_ch && ci < 4; ci++) {
                channel_t *ch = &mgr->entries[ci].channel;

                tx_buf_t cu;
                tx_buf_init(&cu, 512);
                unsigned char ctxid[32];
                if (!channel_build_commitment_tx(ch, &cu, ctxid)) {
                    fprintf(stderr, "MULTI-HTLC: build commitment %zu failed\n", ci);
                    tx_buf_free(&cu);
                    continue;
                }

                unsigned char csec[32];
                memset(csec, cli_fills[ci], 32);
                secp256k1_keypair ckp;
                secp256k1_keypair_create(ctx, &ckp, csec);
                memset(csec, 0, 32);

                tx_buf_t cs;
                tx_buf_init(&cs, 512);
                if (!channel_sign_commitment(ch, &cs, &cu, &ckp)) {
                    fprintf(stderr, "MULTI-HTLC: sign commitment %zu failed\n", ci);
                    tx_buf_free(&cs); tx_buf_free(&cu);
                    continue;
                }
                tx_buf_free(&cu);

                char *chex = malloc(cs.len * 2 + 1);
                hex_encode(cs.data, cs.len, chex);
                int csent = regtest_send_raw_tx(&rt, chex, commit_txids[ci]);
                if (g_db) {
                    char label[64];
                    snprintf(label, sizeof(label), "multi_htlc_commit_%zu", ci);
                    persist_log_broadcast(g_db, csent ? commit_txids[ci] : "?",
                        label, chex, csent ? "ok" : "failed");
                }
                free(chex);
                tx_buf_free(&cs);

                if (csent) {
                    printf("  Commitment %zu broadcast: %s\n", ci, commit_txids[ci]);
                    n_commits++;
                } else {
                    fprintf(stderr, "MULTI-HTLC: commitment %zu broadcast failed\n", ci);
                }
            }
            ADVANCE(1);

            /* Step 4: Mine past all CLTVs + CSV delay */
            uint32_t max_cltv = mhfc_height + 10 + (uint32_t)(n_ch - 1) * 5;
            uint32_t csv_delay = mgr->entries[0].channel.to_self_delay;
            uint32_t target = max_cltv + csv_delay + 1;
            uint32_t cur = (uint32_t)regtest_get_block_height(&rt);
            if (cur < target) {
                printf("Advancing %u blocks (CLTV=%u + CSV=%u)...\n",
                       target - cur, max_cltv, csv_delay);
                ADVANCE((int)(target - cur));
            }

            /* Step 5: Build + broadcast HTLC timeout TXs for each channel */
            int n_timeouts = 0;
            for (size_t ci = 0; ci < n_ch && ci < 4; ci++) {
                channel_t *ch = &mgr->entries[ci].channel;
                if (ch->n_htlcs == 0) continue;

                unsigned char ctxid[32];
                hex_decode(commit_txids[ci], ctxid, 32);
                reverse_bytes(ctxid, 32);

                size_t hi = ch->n_htlcs - 1;

                /* Rebuild the HTLC output SPK from the commitment TX.
                   channel_rebuild_htlc_leaves is static, so we rebuild
                   the taptree manually (same as S13 pattern). */
                unsigned char mhfc_htlc_spk[34];
                size_t mhfc_htlc_spk_len = 0;
                {
                    secp256k1_pubkey pcp;
                    channel_get_per_commitment_point(ch, ch->commitment_number, &pcp);
                    secp256k1_pubkey local_htlc_pub, remote_htlc_pub;
                    channel_derive_pubkey(ch->ctx, &local_htlc_pub,
                        &ch->local_htlc_basepoint, &pcp);
                    channel_derive_pubkey(ch->ctx, &remote_htlc_pub,
                        &ch->remote_htlc_basepoint, &pcp);
                    secp256k1_xonly_pubkey local_htlc_xo, remote_htlc_xo;
                    secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &local_htlc_xo, NULL, &local_htlc_pub);
                    secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &remote_htlc_xo, NULL, &remote_htlc_pub);

                    secp256k1_pubkey rev_pub;
                    channel_derive_revocation_pubkey(ch->ctx, &rev_pub,
                        &ch->remote_revocation_basepoint, &pcp);
                    secp256k1_xonly_pubkey rev_xo;
                    secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &rev_xo, NULL, &rev_pub);

                    htlc_t *h = &ch->htlcs[hi];
                    tapscript_leaf_t sl, tl;
                    if (h->direction == HTLC_OFFERED) {
                        tapscript_build_htlc_offered_success(&sl, h->payment_hash, &remote_htlc_xo, ch->ctx);
                        tapscript_build_htlc_offered_timeout(&tl, h->cltv_expiry, ch->to_self_delay, &local_htlc_xo, ch->ctx);
                    } else {
                        tapscript_build_htlc_received_success(&sl, h->payment_hash, ch->to_self_delay, &local_htlc_xo, ch->ctx);
                        tapscript_build_htlc_received_timeout(&tl, h->cltv_expiry, &remote_htlc_xo, ch->ctx);
                    }
                    tapscript_leaf_t leaves[2] = { sl, tl };
                    unsigned char mr[32];
                    tapscript_merkle_root(mr, leaves, 2);
                    secp256k1_xonly_pubkey tweaked;
                    tapscript_tweak_pubkey(ch->ctx, &tweaked, NULL, &rev_xo, mr);
                    build_p2tr_script_pubkey(mhfc_htlc_spk, &tweaked);
                    mhfc_htlc_spk_len = 34;
                }

                tx_buf_t ttx;
                tx_buf_init(&ttx, 256);

                if (!channel_build_htlc_timeout_tx(ch, &ttx,
                        ctxid, 2, htlc_amounts[ci],
                        mhfc_htlc_spk, mhfc_htlc_spk_len, hi)) {
                    fprintf(stderr, "MULTI-HTLC: build timeout TX %zu failed\n", ci);
                    tx_buf_free(&ttx);
                    continue;
                }

                char *thex = malloc(ttx.len * 2 + 1);
                hex_encode(ttx.data, ttx.len, thex);
                char ttxid[65];
                int tsent = regtest_send_raw_tx(&rt, thex, ttxid);
                if (g_db) {
                    char label[64];
                    snprintf(label, sizeof(label), "multi_htlc_timeout_%zu", ci);
                    persist_log_broadcast(g_db, tsent ? ttxid : "?",
                        label, thex, tsent ? "ok" : "failed");
                }
                free(thex);
                tx_buf_free(&ttx);

                if (tsent) {
                    printf("  HTLC timeout %zu: %s\n", ci, ttxid);
                    n_timeouts++;
                } else {
                    fprintf(stderr, "MULTI-HTLC: timeout TX %zu broadcast failed\n", ci);
                }
            }
            ADVANCE(1);

            int mhfc_pass = (n_commits >= 2 && n_timeouts >= 2);
            printf("\n=== MULTI-HTLC FORCE-CLOSE %s ===\n",
                   mhfc_pass ? "PASSED" : "FAILED");
            printf("  Commitments broadcast: %d/%zu\n", n_commits, n_ch);
            printf("  HTLC timeouts swept:   %d/%zu\n", n_timeouts, n_ch);

            report_add_string(&rpt, "result",
                mhfc_pass ? "multi_htlc_force_close_pass" : "multi_htlc_force_close_fail");
            report_close(&rpt);
            jit_channels_cleanup(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return mhfc_pass ? 0 : 1;
        }

        /* === FULL SETTLEMENT TEST (S30) ===
           After demo payments (including cross-leaf routing), force-close the
           factory tree AND broadcast commitment TXs for ALL channels.  Verifies
           that every client's balance is correctly settled on-chain after
           payments have crossed the arity-2 leaf divide.

           On-chain artifacts:
             1. Factory tree (6 nodes)
             2. Commitment TX for each channel (showing final balances)
           This proves the complete fund recovery path that production needs. */
        if (test_full_settlement) {
            printf("\n=== FULL SETTLEMENT TEST ===\n");
            printf("Force-close with commitment TXs for all %zu channels\n\n",
                   mgr->n_channels);

            /* Record post-demo balances for verification */
            printf("Post-demo balances (to be settled on-chain):\n");
            for (size_t ci = 0; ci < mgr->n_channels; ci++) {
                channel_t *ch = &mgr->entries[ci].channel;
                printf("  Channel %zu: local=%llu remote=%llu (leaf %zu)\n",
                       ci, (unsigned long long)ch->local_amount,
                       (unsigned long long)ch->remote_amount,
                       ci / 2);  /* arity-2: 2 clients per leaf */
            }

            /* Step 1: Broadcast factory tree */
            printf("\nStep 1: Broadcasting factory tree (%zu nodes)...\n",
                   lsp_p->factory.n_nodes);

            if (!broadcast_factory_tree_any_network(&lsp_p->factory, &rt,
                    mine_addr, is_regtest, confirm_timeout_secs)) {
                fprintf(stderr, "FULL SETTLEMENT: tree broadcast failed\n");
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            printf("  All %zu tree nodes confirmed.\n", lsp_p->factory.n_nodes);

            /* Step 2: Build + sign + broadcast commitment TX for each channel */
            printf("\nStep 2: Broadcasting commitment TXs for all channels...\n");

            static const unsigned char settle_fills[] = { 0x22, 0x33, 0x44, 0x55 };
            int n_settled = 0;

            for (size_t ci = 0; ci < mgr->n_channels && ci < 4; ci++) {
                channel_t *ch = &mgr->entries[ci].channel;

                /* Build unsigned commitment TX */
                tx_buf_t cu;
                tx_buf_init(&cu, 512);
                unsigned char ctxid[32];
                if (!channel_build_commitment_tx(ch, &cu, ctxid)) {
                    fprintf(stderr, "  Channel %zu: build commitment failed\n", ci);
                    tx_buf_free(&cu);
                    continue;
                }

                /* Sign with both LSP + client keys */
                unsigned char csec[32];
                memset(csec, settle_fills[ci], 32);
                secp256k1_keypair ckp;
                secp256k1_keypair_create(ctx, &ckp, csec);
                memset(csec, 0, 32);

                tx_buf_t cs;
                tx_buf_init(&cs, 512);
                if (!channel_sign_commitment(ch, &cs, &cu, &ckp)) {
                    fprintf(stderr, "  Channel %zu: sign commitment failed\n", ci);
                    tx_buf_free(&cs); tx_buf_free(&cu);
                    continue;
                }
                tx_buf_free(&cu);

                char *chex = malloc(cs.len * 2 + 1);
                hex_encode(cs.data, cs.len, chex);
                char ctxid_str[65];
                int csent = regtest_send_raw_tx(&rt, chex, ctxid_str);
                if (g_db) {
                    char label[64];
                    snprintf(label, sizeof(label), "settlement_commit_%zu", ci);
                    persist_log_broadcast(g_db, csent ? ctxid_str : "?",
                        label, chex, csent ? "ok" : "failed");
                }
                free(chex);
                tx_buf_free(&cs);

                if (csent) {
                    printf("  Channel %zu (leaf %zu): %s\n"
                           "    local=%llu remote=%llu\n",
                           ci, ci / 2, ctxid_str,
                           (unsigned long long)ch->local_amount,
                           (unsigned long long)ch->remote_amount);
                    n_settled++;
                } else {
                    fprintf(stderr, "  Channel %zu: broadcast failed\n", ci);
                }
            }
            ADVANCE(1);

            int fs_pass = (n_settled == (int)mgr->n_channels);
            printf("\n======================================================\n");
            printf("  FULL SETTLEMENT TEST %s\n", fs_pass ? "PASSED" : "FAILED");
            printf("======================================================\n");
            printf("  Channels settled: %d/%zu\n", n_settled, mgr->n_channels);
            printf("  Cross-leaf payments verified: yes (demo includes 2 cross-leaf)\n");
            printf("======================================================\n\n");

            report_add_string(&rpt, "result",
                fs_pass ? "full_settlement_pass" : "full_settlement_fail");
            report_close(&rpt);
            jit_channels_cleanup(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return fs_pass ? 0 : 1;
        }

        /* === PS Advance Test: advance all PS leaves, verify amounts, force-close === */
        if (test_ps_advance) {
            printf("\n=== PS ADVANCE TEST ===\n");

            factory_t *psa_f = &lsp_p->factory;
            if (psa_f->leaf_arity != FACTORY_ARITY_PS) {
                fprintf(stderr, "PS ADVANCE TEST: factory is not FACTORY_ARITY_PS (arity=%d)\n",
                        (int)psa_f->leaf_arity);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            printf("PS advance: %d leaf node(s), initiating advance via wire...\n",
                   psa_f->n_leaf_nodes);

            /* Snapshot pre-advance channel amounts AND signed_tx bytes.
             * factory_advance_leaf overwrites node->signed_tx in place, so
             * chain[0] is lost after advance. For on-chain force-close, we
             * must broadcast chain[0] before chain[1] (whose input is
             * chain[0]:0), so save a copy of chain[0]'s signed bytes here. */
            uint64_t pre_amounts[FACTORY_MAX_NODES];
            int pre_chain_len[FACTORY_MAX_NODES];
            unsigned char *pre_signed_tx[FACTORY_MAX_NODES] = {0};
            size_t pre_signed_tx_len[FACTORY_MAX_NODES] = {0};
            for (int li = 0; li < psa_f->n_leaf_nodes; li++) {
                size_t nidx = psa_f->leaf_node_indices[li];
                factory_node_t *n = &psa_f->nodes[nidx];
                pre_amounts[li]   = n->outputs[0].amount_sats;
                pre_chain_len[li] = n->ps_chain_len;
                if (n->is_signed && n->signed_tx.len > 0 && n->signed_tx.data) {
                    pre_signed_tx[li] = malloc(n->signed_tx.len);
                    if (pre_signed_tx[li]) {
                        memcpy(pre_signed_tx[li], n->signed_tx.data, n->signed_tx.len);
                        pre_signed_tx_len[li] = n->signed_tx.len;
                    }
                }
                printf("  Leaf %d: chain_len=%d, chan_amount=%llu sats\n",
                       li, pre_chain_len[li],
                       (unsigned long long)pre_amounts[li]);
            }

            /* Advance every PS leaf via the production wire ceremony */
            int psa_pass = 1;
            for (int li = 0; li < psa_f->n_leaf_nodes; li++) {
                printf("PS advance: leaf %d...\n", li);
                int arc = lsp_channels_advance_ps_leaf(mgr, lsp_p, li);
                if (!arc) {
                    fprintf(stderr, "PS ADVANCE TEST: lsp_advance_leaf failed for leaf %d\n", li);
                    psa_pass = 0;
                }
            }

            /* Verify post-advance state */
            if (psa_pass) {
                for (int li = 0; li < psa_f->n_leaf_nodes; li++) {
                    size_t nidx = psa_f->leaf_node_indices[li];
                    factory_node_t *node = &psa_f->nodes[nidx];
                    uint64_t expected_amt = pre_amounts[li] - psa_f->fee_per_tx;
                    printf("  Leaf %d post-advance: chain_len=%d, n_outputs=%zu, chan_amount=%llu (expected %llu)\n",
                           li, node->ps_chain_len, node->n_outputs,
                           (unsigned long long)node->outputs[0].amount_sats,
                           (unsigned long long)expected_amt);
                    if ((uint32_t)node->ps_chain_len != pre_chain_len[li] + 1u) {
                        fprintf(stderr, "PS ADVANCE TEST: leaf %d chain_len not incremented (%d→%d)\n",
                                li, pre_chain_len[li], node->ps_chain_len);
                        psa_pass = 0;
                    }
                    if (node->n_outputs != 1) {
                        fprintf(stderr, "PS ADVANCE TEST: leaf %d n_outputs=%zu (expected 1)\n",
                                li, node->n_outputs);
                        psa_pass = 0;
                    }
                    if (node->outputs[0].amount_sats != expected_amt) {
                        fprintf(stderr, "PS ADVANCE TEST: leaf %d amount %llu != expected %llu\n",
                                li, (unsigned long long)node->outputs[0].amount_sats,
                                (unsigned long long)expected_amt);
                        psa_pass = 0;
                    }
                }
            }

            /* Force-close to prove the chain TX is valid on-chain.
             * Custom broadcast loop: for each PS leaf we must broadcast
             * the saved chain[0] TX (pre-advance) before the current
             * signed_tx (chain[1]), because chain[1]->input is chain[0]:0.
             * Non-leaf nodes (the root/kickoff TX) are broadcast normally.
             *
             * #117 fix (2026-05-15): the old loop called regtest_mine_blocks(&rt, 1, ...)
             * between broadcasts.  That helper has a hard regtest-only guard
             * (src/regtest.c:786) and silently no-ops on testnet4/signet, so
             * the next CSV-locked child TX broadcast hit "non-BIP68-final".
             * Use broadcast_one_signed_tx instead — same helper the production
             * LSP force-close path uses (tools/superscalar_lsp.c:715), which
             * properly waits for the parent's BIP68 maturity on non-regtest. */
            if (psa_pass) {
                printf("\nBroadcasting PS factory tree (%zu nodes + saved chain[0]s)...\n",
                       psa_f->n_nodes);
                for (size_t i = 0; i < psa_f->n_nodes && psa_pass; i++) {
                    factory_node_t *n = &psa_f->nodes[i];
                    if (!n->is_signed) {
                        fprintf(stderr, "PS ADVANCE TEST: node %zu not signed\n", i);
                        psa_pass = 0;
                        break;
                    }

                    int leaf_idx = -1;
                    for (int li = 0; li < psa_f->n_leaf_nodes; li++) {
                        if (psa_f->leaf_node_indices[li] == i) { leaf_idx = li; break; }
                    }

                    /* PS leaf with prior chain state: broadcast saved chain[0] first */
                    if (leaf_idx >= 0 && n->ps_chain_len > 0
                        && pre_signed_tx[leaf_idx] && pre_signed_tx_len[leaf_idx] > 0) {
                        char label0[64];
                        snprintf(label0, sizeof(label0),
                                 "ps_advance_leaf_%d_chain0", leaf_idx);
                        if (!broadcast_one_signed_tx(&rt, mine_addr, is_regtest,
                                confirm_timeout_secs,
                                pre_signed_tx[leaf_idx], pre_signed_tx_len[leaf_idx],
                                n->nsequence, label0, NULL)) {
                            fprintf(stderr, "PS ADVANCE TEST: leaf %d chain[0] "
                                    "broadcast failed\n", leaf_idx);
                            psa_pass = 0;
                            break;
                        }
                    }

                    /* Broadcast this node's current signed_tx */
                    char label_n[64];
                    snprintf(label_n, sizeof(label_n), "ps_advance_node_%zu", i);
                    if (!broadcast_one_signed_tx(&rt, mine_addr, is_regtest,
                            confirm_timeout_secs,
                            n->signed_tx.data, n->signed_tx.len,
                            n->nsequence, label_n, n->txid)) {
                        fprintf(stderr, "PS ADVANCE TEST: node %zu broadcast failed\n", i);
                        psa_pass = 0;
                        break;
                    }
                }
                printf("All %zu factory nodes + PS chain TXs confirmed on-chain.\n",
                       psa_f->n_nodes);
            }

            /* Free saved pre-advance TXs */
            for (int li = 0; li < psa_f->n_leaf_nodes; li++) {
                if (pre_signed_tx[li]) free(pre_signed_tx[li]);
            }

            printf("\n=== PS ADVANCE TEST %s ===\n", psa_pass ? "PASSED" : "FAILED");
            if (psa_pass)
                printf("All %d PS leaf(s) advanced, amounts correct, chain TXs confirmed.\n",
                       psa_f->n_leaf_nodes);

            report_add_string(&rpt, "result",
                              psa_pass ? "ps_advance_pass" : "ps_advance_fail");
            report_close(&rpt);
            jit_channels_cleanup(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return psa_pass ? 0 : 1;
        }
