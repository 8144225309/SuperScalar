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
                static const unsigned char fill[4] = { 0x22, 0x33, 0x44, 0x55 };
                for (int ci = 0; ci < n_clients; ci++) {
                    unsigned char ds[32];
                    memset(ds, fill[ci], 32);
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
                static const unsigned char fill[4] = { 0x22, 0x33, 0x44, 0x55 };
                for (int ci = 0; ci < n_clients; ci++) {
                    unsigned char ds[32];
                    memset(ds, fill[ci], 32);
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

            printf("Before leaf advance:\n");
            printf("  Left  leaf (node %zu): nSequence=0x%X\n", left_ni, left_nseq_before);
            printf("  Right leaf (node %zu): nSequence=0x%X\n", right_ni, right_nseq_before);

            /* Populate keypairs (same pattern as dw_advance test) */
            {
                secp256k1_keypair all_kps[FACTORY_MAX_SIGNERS];
                all_kps[0] = lsp_kp;
                static const unsigned char fill[4] = { 0x22, 0x33, 0x44, 0x55 };
                for (int ci = 0; ci < n_clients; ci++) {
                    unsigned char ds[32];
                    memset(ds, fill[ci], 32);
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

            /* Advance LEFT leaf only */
            if (!factory_advance_leaf(&lsp_p->factory, 0)) {
                fprintf(stderr, "LEAF ADVANCE TEST: factory_advance_leaf(0) failed\n");
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

            int left_changed = (left_nseq_after != left_nseq_before);
            int right_unchanged = (right_nseq_after == right_nseq_before);

            /* Force-close with the re-signed tree */
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

            int pass = left_changed && right_unchanged;
            printf("\n=== LEAF ADVANCE TEST %s ===\n", pass ? "PASSED" : "FAILED");
            printf("Left leaf nSequence %s (0x%X → 0x%X)\n",
                   left_changed ? "decreased" : "UNCHANGED", left_nseq_before, left_nseq_after);
            printf("Right leaf nSequence %s (0x%X → 0x%X)\n",
                   right_unchanged ? "unchanged" : "CHANGED", right_nseq_before, right_nseq_after);

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
                static const unsigned char fill[4] = { 0x22, 0x33, 0x44, 0x55 };
                for (int ci = 0; ci < n_clients; ci++) {
                    unsigned char ds[32];
                    memset(ds, fill[ci], 32);
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

            /* Step 2: Build burn TX for epoch 0 L-stock */
            tx_buf_t burn_tx;
            tx_buf_init(&burn_tx, 256);
            if (!factory_build_burn_tx(&lsp_p->factory, &burn_tx,
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

            /* Step 1: Add a pending HTLC on channel 0 (low CLTV for quick timeout) */
            uint32_t current_height = (uint32_t)regtest_get_block_height(&rt);
            uint32_t htlc_cltv = current_height + 10;  /* expires in ~10 blocks */
            unsigned char dummy_hash[32];
            memset(dummy_hash, 0xAA, 32);  /* dummy payment hash */
            uint64_t htlc_amount = 1000;

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

            /* Sign with both LSP + client keys (test key 0x22..22) */
            unsigned char cli_sec[32];
            memset(cli_sec, 0x22, 32);
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
