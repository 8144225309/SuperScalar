    /* === Breach Test: broadcast factory tree + revoked commitment === */
    if (breach_test && channels_active) {
        printf("\n=== BREACH TEST ===\n");
        fflush(stdout);
        printf("Broadcasting factory tree (all %zu nodes)...\n", lsp_p->factory.n_nodes);

        int tree_ok;
        if (is_regtest) {
            tree_ok = broadcast_factory_tree(&lsp_p->factory, &rt, mine_addr);
        } else {
            tree_ok = broadcast_factory_tree_any_network(&lsp_p->factory, &rt,
                                                          mine_addr, 0,
                                                          confirm_timeout_secs);
        }
        if (!tree_ok) {
            fprintf(stderr, "BREACH TEST: factory tree broadcast failed\n");
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        printf("Factory tree confirmed on-chain.\n");

        /* Broadcast revoked commitments for ALL channels so every client's
         * watchtower can detect the breach independently. */
        static const unsigned char client_fills[4] = { 0x22, 0x33, 0x44, 0x55 };
        for (size_t ci = 0; ci < mgr->n_channels; ci++) {
            channel_t *chX = &mgr->entries[ci].channel;
            uint64_t saved_num = chX->commitment_number;
            uint64_t saved_local = chX->local_amount;
            uint64_t saved_remote = chX->remote_amount;
            size_t saved_n_htlcs = chX->n_htlcs;

            /* Temporarily revert to commitment #0 with no HTLCs */
            chX->commitment_number = 0;
            chX->local_amount = init_local;
            chX->remote_amount = init_remote;
            chX->n_htlcs = 0;

            /* Ensure remote PCP for commitment #0 is available.
               Re-derive from the stored revocation secret (same approach
               as watchtower_watch_revoked_commitment). */
            {
                unsigned char rev_secret[32];
                if (channel_get_received_revocation(chX, 0, rev_secret)) {
                    secp256k1_pubkey old_pcp;
                    if (secp256k1_ec_pubkey_create(ctx, &old_pcp, rev_secret))
                        channel_set_remote_pcp(chX, 0, &old_pcp);
                    memset(rev_secret, 0, 32);
                }
            }

            /* Verify local PCP for commitment #0 is still available.
               The local_pcs array retains all entries (no pruning), so this
               should always succeed.  Log diagnostic if it doesn't. */
            {
                secp256k1_pubkey local_pcp_check;
                if (!channel_get_per_commitment_point(chX, 0, &local_pcp_check)) {
                    fprintf(stderr, "BREACH TEST: local PCP for commitment 0 unavailable "
                            "(channel %zu, n_local_pcs=%zu) — build will fail\n",
                            ci, chX->n_local_pcs);
                }
            }

            tx_buf_t old_commit_tx;
            tx_buf_init(&old_commit_tx, 512);
            unsigned char old_txid[32];
            int built;
            if (breach_test == 2) {
                /* --cheat-daemon: simulate LSP cheating by broadcasting the
                   LSP's own old commitment TX.  Client watchtowers watch for
                   this via channel_build_commitment_tx_for_remote(client_ch),
                   which produces the same txid as our local commitment. */
                built = channel_build_commitment_tx(chX, &old_commit_tx, old_txid);
            } else {
                /* --test-breach: simulate CLIENT cheating by broadcasting the
                   client's old commitment TX.  The LSP's own watchtower
                   watches for this via channel_build_commitment_tx_for_remote
                   (lsp_ch) and broadcasts a penalty TX. */
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
            if (!secp256k1_keypair_create(ctx, &cli_kp, cli_sec)) {
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
            int sent = regtest_send_raw_tx(&rt, old_hex, old_txid_str);
            if (g_db) {
                char src[48];
                snprintf(src, sizeof(src), "breach_revoked_ch%zu", ci);
                persist_log_broadcast(g_db, sent ? old_txid_str : "?",
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

        /* Confirm all revoked commitments so watchtowers can detect them */
        if (is_regtest) {
            regtest_mine_blocks(&rt, 1, mine_addr);
        } else {
            int rc_start_h = regtest_get_block_height(&rt);
            printf("Waiting for revoked commitments to confirm (height %d)...\n",
                   rc_start_h);
            for (int w = 0; w < confirm_timeout_secs && !g_shutdown; w++) {
                if (regtest_get_block_height(&rt) > rc_start_h) break;
                sleep(1);
            }
        }

        if (breach_test == 2) {
            /* --cheat-daemon: LSP does NOT run watchtower — sleep so clients can detect */
            printf("CHEAT DAEMON: revoked commitment broadcast, sleeping for clients...\n");
            if (is_regtest) {
                for (int s = 0; s < 30 && !g_shutdown; s++)
                    sleep(1);
            } else {
                /* On signet: wait for 2 blocks via height polling (up to 30 min),
                   then give clients time to detect */
                int start_h = regtest_get_block_height(&rt);
                int target_h = start_h + 2;
                printf("CHEAT DAEMON: waiting for height %d (current %d)...\n",
                       target_h, start_h);
                for (int w = 0; w < 1800 && !g_shutdown; w++) {
                    if (regtest_get_block_height(&rt) >= target_h) break;
                    sleep(1);
                }
                /* Extra time for clients to process */
                for (int s = 0; s < 60 && !g_shutdown; s++)
                    sleep(1);
            }
            printf("=== CHEAT DAEMON COMPLETE ===\n");
            report_add_string(&rpt, "result", "cheat_daemon_complete");
            report_close(&rpt);
            if (use_db) persist_close(&db);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 0;
        }

        /* Watchtower check: should detect breach and broadcast penalty */
        printf("Running watchtower check...\n");
        fflush(stdout);
        watchtower_t *wt = mgr->watchtower;
        if (!wt) {
            fprintf(stderr, "BREACH TEST FAILED: no watchtower configured\n");
            report_add_string(&rpt, "result", "breach_test_no_watchtower");
            report_close(&rpt);
            if (use_db) persist_close(&db);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        {
            int detected = watchtower_check(wt);
            if (detected > 0) {
                printf("BREACH DETECTED! Watchtower broadcast %d penalty tx(s)\n",
                       detected);
                if (is_regtest) {
                    regtest_mine_blocks(&rt, 1, mine_addr);
                } else {
                    int pen_start_h = regtest_get_block_height(&rt);
                    printf("Waiting for penalty to confirm (height %d)...\n",
                           pen_start_h);
                    for (int w = 0; w < confirm_timeout_secs && !g_shutdown; w++) {
                        if (regtest_get_block_height(&rt) > pen_start_h) break;
                        sleep(1);
                    }
                }
                printf("BREACH TEST PASSED — penalty confirmed on-chain\n");
            } else {
                fprintf(stderr, "BREACH TEST FAILED: watchtower did not detect breach\n");
                report_add_string(&rpt, "result", "breach_test_failed");
                report_close(&rpt);
                if (use_db) persist_close(&db);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }
        }

        printf("=== BREACH TEST COMPLETE ===\n\n");

        /* Skip cooperative close — factory already spent */
        report_add_string(&rpt, "result", "breach_test_complete");
        report_close(&rpt);
        if (use_db) persist_close(&db);
        lsp_cleanup(lsp_p);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 0;
    }

    /* === Expiry Test: multi-level timeout recovery === */
    if (test_expiry && channels_active) {
        printf("\n=== EXPIRY TEST (Multi-Level Timeout Recovery) ===\n");

        /* Step 1: Broadcast kickoff_root (node 0, key-path pre-signed) */
        factory_node_t *kickoff_root = &lsp_p->factory.nodes[0];
        {
            char *kr_hex = malloc(kickoff_root->signed_tx.len * 2 + 1);
            hex_encode(kickoff_root->signed_tx.data, kickoff_root->signed_tx.len, kr_hex);
            char kr_txid_str[65];
            if (!regtest_send_raw_tx(&rt, kr_hex, kr_txid_str)) {
                if (g_db)
                    persist_log_broadcast(g_db, "?", "expiry_kickoff_root",
                        kr_hex, "failed");
                fprintf(stderr, "EXPIRY TEST: kickoff_root broadcast failed\n");
                free(kr_hex);
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            if (g_db)
                persist_log_broadcast(g_db, kr_txid_str,
                    "expiry_kickoff_root", kr_hex, "ok");
            free(kr_hex);
            ADVANCE(1);
            printf("1. kickoff_root broadcast: %s\n", kr_txid_str);
        }

        /* Step 2: Broadcast state_root (node 1, key-path pre-signed) */
        factory_node_t *state_root = &lsp_p->factory.nodes[1];
        {
            uint32_t state_nseq = state_root->nsequence;
            int nseq_blocks = (state_nseq == NSEQUENCE_DISABLE_BIP68)
                ? 0 : (int)(state_nseq & 0xFFFF);
            if (nseq_blocks > 0)
                ADVANCE(nseq_blocks);

            char *sr_hex = malloc(state_root->signed_tx.len * 2 + 1);
            hex_encode(state_root->signed_tx.data, state_root->signed_tx.len, sr_hex);
            char sr_txid_str[65];
            if (!regtest_send_raw_tx(&rt, sr_hex, sr_txid_str)) {
                if (g_db)
                    persist_log_broadcast(g_db, "?", "expiry_state_root",
                        sr_hex, "failed");
                fprintf(stderr, "EXPIRY TEST: state_root broadcast failed\n");
                free(sr_hex);
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            if (g_db)
                persist_log_broadcast(g_db, sr_txid_str,
                    "expiry_state_root", sr_hex, "ok");
            free(sr_hex);
            ADVANCE(1);
            printf("2. state_root broadcast: %s (nSeq blocks: %d)\n",
                   sr_txid_str, nseq_blocks);
        }

        /* Build broadcast chain: walk from first leaf state up to state_root,
           collecting intermediate kickoff+state nodes to broadcast.
           Works for both arity-2 (3 nodes: kl) and arity-1 (5 nodes: kl,sl,ka). */
        size_t first_leaf_idx = lsp_p->factory.leaf_node_indices[0];
        int chain[16];  /* node indices to broadcast (root-to-leaf order) */
        int chain_len = 0;
        {
            /* Walk from first leaf's kickoff parent up to state_root */
            int ko_idx = lsp_p->factory.nodes[first_leaf_idx].parent_index;
            while (ko_idx >= 0) {
                int parent_state = lsp_p->factory.nodes[ko_idx].parent_index;
                if (parent_state < 0 || parent_state == 1) break; /* stop at state_root children */
                chain[chain_len++] = parent_state; /* state node (grandparent) */
                chain[chain_len++] = ko_idx;       /* kickoff node */
                ko_idx = lsp_p->factory.nodes[parent_state].parent_index;
            }
            chain[chain_len++] = ko_idx; /* the kickoff that's a direct child of state_root */
        }
        /* Reverse chain to get root-to-leaf order */
        for (int a = 0, b = chain_len - 1; a < b; a++, b--) {
            int tmp = chain[a]; chain[a] = chain[b]; chain[b] = tmp;
        }

        /* Step 3..N: Broadcast intermediate nodes down to the deepest kickoff */
        int step = 3;
        for (int ci = 0; ci < chain_len; ci++) {
            factory_node_t *nd = &lsp_p->factory.nodes[chain[ci]];
            uint32_t nseq = nd->nsequence;
            int nseq_blocks = (nseq == NSEQUENCE_DISABLE_BIP68) ? 0 : (int)(nseq & 0xFFFF);
            if (nseq_blocks > 0)
                ADVANCE(nseq_blocks);

            char *hex = malloc(nd->signed_tx.len * 2 + 1);
            hex_encode(nd->signed_tx.data, nd->signed_tx.len, hex);
            char txid_str[65];
            if (!regtest_send_raw_tx(&rt, hex, txid_str)) {
                if (g_db) {
                    char src[48];
                    snprintf(src, sizeof(src), "expiry_node_%d", chain[ci]);
                    persist_log_broadcast(g_db, "?", src, hex, "failed");
                }
                fprintf(stderr, "EXPIRY TEST: node[%d] broadcast failed\n", chain[ci]);
                free(hex);
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            if (g_db) {
                char src[48];
                snprintf(src, sizeof(src), "expiry_node_%d", chain[ci]);
                persist_log_broadcast(g_db, txid_str, src, hex, "ok");
            }
            free(hex);
            ADVANCE(1);
            printf("%d. node[%d] (%s) broadcast: %s%s\n", step++, chain[ci],
                   nd->type == NODE_KICKOFF ? "kickoff" : "state", txid_str,
                   nseq_blocks > 0 ? " (waited nSeq)" : "");
        }

        /* The deepest kickoff is the last in the chain */
        factory_node_t *deepest_kickoff = &lsp_p->factory.nodes[chain[chain_len - 1]];
        /* The leaf state node that times out this kickoff's output */
        factory_node_t *leaf_state = &lsp_p->factory.nodes[first_leaf_idx];

        /* LSP pubkey for signing + destination */
        secp256k1_xonly_pubkey lsp_xonly;
        if (!secp256k1_keypair_xonly_pub(ctx, &lsp_xonly, NULL, &lsp_kp)) {
            fprintf(stderr, "EXPIRY TEST: keypair xonly pub failed\n");
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        unsigned char dest_spk[34];
        build_p2tr_script_pubkey(dest_spk, &lsp_xonly);

        uint64_t fee_sats = fee_estimate(fee_est, 150);
        if (fee_sats == 0) fee_sats = 500;
        uint64_t leaf_recovered = 0, mid_recovered = 0;

        /* Mine to leaf CLTV (deepest state node's timeout) */
        uint32_t leaf_cltv = leaf_state->cltv_timeout;
        {
            int height = regtest_get_block_height(&rt);
            int needed = (int)leaf_cltv - height;
            if (needed > 0) {
                printf("%d. Advancing %d blocks to reach leaf CLTV %u...\n",
                       step++, needed, leaf_cltv);
                ADVANCE(needed);
            }
        }

        /* Leaf recovery: Spend deepest_kickoff:0 via leaf_state timeout script-path */
        {
            if (!leaf_state->has_taptree) {
                fprintf(stderr, "EXPIRY TEST: leaf state node[%zu] has no taptree\n",
                        first_leaf_idx);
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
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
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }

            unsigned char sh[32];
            compute_tapscript_sighash(sh, tu.data, tu.len, 0,
                leaf_state->spending_spk, leaf_state->spending_spk_len,
                spend_amount, 0xFFFFFFFEu, &leaf_state->timeout_leaf);

            unsigned char sig[64], aux[32];
            memset(aux, 0xEE, 32);
            if (!secp256k1_schnorrsig_sign32(ctx, sig, sh, &lsp_kp, aux)) {
                fprintf(stderr, "EXPIRY TEST: schnorr sign failed\n");
                return 1;
            }

            unsigned char cb[65];
            size_t cb_len;
            tapscript_build_control_block(cb, &cb_len,
                leaf_state->output_parity,
                &leaf_state->keyagg.agg_pubkey, ctx);

            tx_buf_t ts;
            tx_buf_init(&ts, 512);
            finalize_script_path_tx(&ts, tu.data, tu.len, sig,
                leaf_state->timeout_leaf.script,
                leaf_state->timeout_leaf.script_len, cb, cb_len);
            tx_buf_free(&tu);

            char *hex = malloc(ts.len * 2 + 1);
            hex_encode(ts.data, ts.len, hex);
            char txid_str[65];
            int sent = regtest_send_raw_tx(&rt, hex, txid_str);
            if (g_db)
                persist_log_broadcast(g_db, sent ? txid_str : "?",
                    "expiry_leaf_timeout", hex, sent ? "ok" : "failed");
            free(hex);
            tx_buf_free(&ts);

            if (!sent) {
                fprintf(stderr, "EXPIRY TEST: leaf timeout tx broadcast failed\n");
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            ADVANCE(1);
            leaf_recovered = tout.amount_sats;
            printf("%d. Leaf recovery: %llu sats (node[%zu] timeout) txid: %s\n",
                   step++, (unsigned long long)leaf_recovered, first_leaf_idx, txid_str);
        }

        /* Mid recovery: Spend state_root:1 via kickoff_right timeout.
           kickoff_right is the second child of state_root (vout 1). */
        factory_node_t *kickoff_right = &lsp_p->factory.nodes[state_root->child_indices[1]];
        uint32_t mid_cltv = kickoff_right->cltv_timeout;
        {
            int height = regtest_get_block_height(&rt);
            int needed = (int)mid_cltv - height;
            if (needed > 0) {
                printf("%d. Advancing %d blocks to reach mid CLTV %u...\n",
                       step++, needed, mid_cltv);
                ADVANCE(needed);
            }
        }

        /* Spend state_root:1 via kickoff_right timeout script-path */
        {
            if (!kickoff_right->has_taptree) {
                fprintf(stderr, "EXPIRY TEST: kickoff_right has no taptree\n");
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
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
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }

            unsigned char sh[32];
            compute_tapscript_sighash(sh, tu.data, tu.len, 0,
                kickoff_right->spending_spk, kickoff_right->spending_spk_len,
                spend_amount, 0xFFFFFFFEu, &kickoff_right->timeout_leaf);

            unsigned char sig[64], aux[32];
            memset(aux, 0xFF, 32);
            if (!secp256k1_schnorrsig_sign32(ctx, sig, sh, &lsp_kp, aux)) {
                fprintf(stderr, "EXPIRY TEST: schnorr sign failed\n");
                return 1;
            }

            unsigned char cb[65];
            size_t cb_len;
            tapscript_build_control_block(cb, &cb_len,
                kickoff_right->output_parity,
                &kickoff_right->keyagg.agg_pubkey, ctx);

            tx_buf_t ts;
            tx_buf_init(&ts, 512);
            finalize_script_path_tx(&ts, tu.data, tu.len, sig,
                kickoff_right->timeout_leaf.script,
                kickoff_right->timeout_leaf.script_len, cb, cb_len);
            tx_buf_free(&tu);

            char *hex = malloc(ts.len * 2 + 1);
            hex_encode(ts.data, ts.len, hex);
            char txid_str[65];
            int sent = regtest_send_raw_tx(&rt, hex, txid_str);
            if (g_db)
                persist_log_broadcast(g_db, sent ? txid_str : "?",
                    "expiry_mid_timeout", hex, sent ? "ok" : "failed");
            free(hex);
            tx_buf_free(&ts);

            if (!sent) {
                fprintf(stderr, "EXPIRY TEST: mid timeout tx broadcast failed\n");
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
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

        /* Skip cooperative close — factory already spent */
        report_add_string(&rpt, "result",
                          expiry_pass ? "expiry_test_pass" : "expiry_test_fail");
        report_close(&rpt);
        if (use_db) persist_close(&db);
        lsp_cleanup(lsp_p);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return expiry_pass ? 0 : 1;
    }

    /* === Distribution TX Test: mine past CLTV, broadcast distribution TX === */
    if (test_distrib && channels_active) {
        printf("\n=== DISTRIBUTION TX TEST ===\n");

        /* Build distribution TX with demo keypairs (LSP has all keys in demo) */
        factory_t df = lsp_p->factory;
        secp256k1_keypair dk[FACTORY_MAX_SIGNERS];
        dk[0] = lsp_kp;
        {
            static const unsigned char fill[4] = { 0x22, 0x33, 0x44, 0x55 };
            for (int ci = 0; ci < n_clients; ci++) {
                unsigned char ds[32];
                memset(ds, fill[ci], 32);
                if (!secp256k1_keypair_create(ctx, &dk[ci + 1], ds)) {
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
            /* Derive per-participant P2TR from their keypair */
            secp256k1_pubkey di_pub;
            secp256k1_keypair_pub(ctx, &di_pub, &dk[di]);
            secp256k1_xonly_pubkey di_xonly;
            secp256k1_xonly_pubkey_from_pubkey(ctx, &di_xonly, NULL, &di_pub);
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
                                             lsp_p->factory.cltv_timeout)) {
            fprintf(stderr, "DISTRIBUTION TX TEST: build failed\n");
            tx_buf_free(&dist_tx);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        printf("Distribution TX built (%zu bytes)\n", dist_tx.len);

        /* Store in ladder slot */
        lad->factories[0].distribution_tx = dist_tx;

        /* Mine past CLTV timeout */
        int cur_h = regtest_get_block_height(&rt);
        int blocks_to_cltv = (int)lsp_p->factory.cltv_timeout - cur_h;
        if (blocks_to_cltv > 0) {
            printf("Advancing %d blocks to reach CLTV timeout %u...\n",
                   blocks_to_cltv, lsp_p->factory.cltv_timeout);
            ADVANCE(blocks_to_cltv);
        }

        /* Broadcast distribution TX */
        char *dt_hex = malloc(dist_tx.len * 2 + 1);
        hex_encode(dist_tx.data, dist_tx.len, dt_hex);
        char dt_txid_str[65];
        int dt_sent = regtest_send_raw_tx(&rt, dt_hex, dt_txid_str);
        if (g_db)
            persist_log_broadcast(g_db, dt_sent ? dt_txid_str : "?",
                "distribution_tx", dt_hex, dt_sent ? "ok" : "failed");
        free(dt_hex);

        if (!dt_sent) {
            fprintf(stderr, "DISTRIBUTION TX TEST: broadcast failed\n");
            tx_buf_free(&lad->factories[0].distribution_tx);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        ADVANCE(1);

        printf("Distribution TX broadcast: %s\n", dt_txid_str);
        printf("=== DISTRIBUTION TX TEST PASSED ===\n\n");

        report_add_string(&rpt, "result", "distrib_test_complete");
        report_close(&rpt);
        if (use_db) persist_close(&db);
        tx_buf_free(&lad->factories[0].distribution_tx);
        lsp_cleanup(lsp_p);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 0;
    }

    /* === PTLC Key Turnover Test === */
    if (test_turnover && channels_active) {
        printf("\n=== PTLC KEY TURNOVER TEST ===\n");

        /* Build demo keypairs (same as test_ladder.c) */
        secp256k1_keypair all_kps[FACTORY_MAX_SIGNERS];
        all_kps[0] = lsp_kp;
        {
            static const unsigned char fill[4] = { 0x22, 0x33, 0x44, 0x55 };
            for (int ci = 0; ci < n_clients; ci++) {
                unsigned char ds[32];
                memset(ds, fill[ci], 32);
                if (!secp256k1_keypair_create(ctx, &all_kps[ci + 1], ds)) {
                    fprintf(stderr, "TURNOVER TEST: keypair create failed\n");
                    return 1;
                }
            }
        }

        /* We need the factory with real keypairs for signing */
        factory_t tf = lsp_p->factory;
        memcpy(tf.keypairs, all_kps, n_total * sizeof(secp256k1_keypair));

        /* Build keyagg for the funding key (used as message) */
        secp256k1_pubkey turnover_pks[FACTORY_MAX_SIGNERS];
        for (size_t ti = 0; ti < n_total; ti++) {
            if (!secp256k1_keypair_pub(ctx, &turnover_pks[ti], &all_kps[ti])) {
                fprintf(stderr, "TURNOVER TEST: keypair pub failed\n");
                return 1;
            }
        }

        musig_keyagg_t turnover_ka;
        musig_aggregate_keys(ctx, &turnover_ka, turnover_pks, n_total);

        /* Dummy message (hash of "turnover") */
        unsigned char turnover_msg[32];
        sha256_tagged("turnover", (const unsigned char *)"turnover", 8,
                       turnover_msg);

        /* For each client: adaptor presig → adapt → extract → verify → record */
        for (int ci = 0; ci < n_clients; ci++) {
            uint32_t participant_idx = (uint32_t)(ci + 1);
            secp256k1_pubkey client_pk = turnover_pks[participant_idx];

            /* Create turnover pre-signature with adaptor point = client pubkey */
            unsigned char presig[64];
            int nonce_parity;
            musig_keyagg_t ka_copy = turnover_ka;
            if (!adaptor_create_turnover_presig(ctx, presig, &nonce_parity,
                                                  turnover_msg, all_kps, n_total,
                                                  &ka_copy, NULL, &client_pk)) {
                fprintf(stderr, "TURNOVER TEST: presig failed for client %d\n", ci);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Client adapts with their secret key */
            unsigned char client_sec[32];
            if (!secp256k1_keypair_sec(ctx, client_sec, &all_kps[participant_idx])) {
                fprintf(stderr, "TURNOVER TEST: keypair sec failed\n");
                return 1;
            }
            unsigned char adapted_sig[64];
            if (!adaptor_adapt(ctx, adapted_sig, presig, client_sec, nonce_parity)) {
                fprintf(stderr, "TURNOVER TEST: adapt failed for client %d\n", ci);
                memset(client_sec, 0, 32);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* LSP extracts client's secret key */
            unsigned char extracted[32];
            if (!adaptor_extract_secret(ctx, extracted, adapted_sig, presig,
                                          nonce_parity)) {
                fprintf(stderr, "TURNOVER TEST: extract failed for client %d\n", ci);
                memset(client_sec, 0, 32);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Verify extracted key matches */
            if (!adaptor_verify_extracted_key(ctx, extracted, &client_pk)) {
                fprintf(stderr, "TURNOVER TEST: verify failed for client %d\n", ci);
                memset(client_sec, 0, 32);
                lsp_cleanup(lsp_p);
                memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx);
                return 1;
            }

            /* Record in ladder */
            ladder_record_key_turnover(lad, 0, participant_idx, extracted);

            /* Persist departed client */
            if (use_db)
                persist_save_departed_client(&db, 0, participant_idx, extracted);

            printf("  Client %d: key extracted and verified ✓\n", ci + 1);
            memset(client_sec, 0, 32);
        }

        /* Verify all clients departed */
        if (!ladder_can_close(lad, 0)) {
            fprintf(stderr, "TURNOVER TEST: ladder_can_close returned false\n");
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        printf("All %d clients departed — ladder_can_close = true\n", n_clients);

        /* Build close outputs (equal split) */
        tx_output_t to_outputs[FACTORY_MAX_SIGNERS];
        uint64_t to_per = (lsp_p->factory.funding_amount_sats - 500) / n_total;
        for (size_t ti = 0; ti < n_total; ti++) {
            to_outputs[ti].amount_sats = to_per;
            memcpy(to_outputs[ti].script_pubkey, fund_spk, 34);
            to_outputs[ti].script_pubkey_len = 34;
        }
        to_outputs[n_total - 1].amount_sats =
            lsp_p->factory.funding_amount_sats - 500 - to_per * (n_total - 1);

        /* Build cooperative close using extracted keys */
        tx_buf_t turnover_close_tx;
        tx_buf_init(&turnover_close_tx, 512);
        if (!ladder_build_close(lad, 0, &turnover_close_tx,
                                  to_outputs, n_total,
                                  (uint32_t)regtest_get_block_height(&rt))) {
            fprintf(stderr, "TURNOVER TEST: ladder_build_close failed\n");
            tx_buf_free(&turnover_close_tx);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }

        /* Broadcast close TX */
        char *tc_hex = malloc(turnover_close_tx.len * 2 + 1);
        hex_encode(turnover_close_tx.data, turnover_close_tx.len, tc_hex);
        char tc_txid_str[65];
        int tc_sent = regtest_send_raw_tx(&rt, tc_hex, tc_txid_str);
        if (g_db)
            persist_log_broadcast(g_db, tc_sent ? tc_txid_str : "?",
                "turnover_close", tc_hex, tc_sent ? "ok" : "failed");
        free(tc_hex);
        tx_buf_free(&turnover_close_tx);

        if (!tc_sent) {
            fprintf(stderr, "TURNOVER TEST: close TX broadcast failed\n");
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        ADVANCE(1);

        printf("Close TX broadcast: %s\n", tc_txid_str);
        printf("=== PTLC KEY TURNOVER TEST PASSED ===\n\n");

        report_add_string(&rpt, "result", "turnover_test_complete");
        report_close(&rpt);
        if (use_db) persist_close(&db);
        lsp_cleanup(lsp_p);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 0;
    }

    /* === Auto-Rebalance Test === */
    if (test_rebalance && channels_active) {
        printf("\n=== AUTO-REBALANCE TEST ===\n");
        fflush(stdout);
        int rebalance_pass = 1;

        /* Record pre-rebalance balances */
        uint64_t pre_total = 0;
        for (size_t c = 0; c < mgr->n_channels; c++) {
            pre_total += mgr->entries[c].channel.local_amount +
                         mgr->entries[c].channel.remote_amount;
        }

        /* Deliberately imbalance: send large payment ch0 → ch1 */
        if (mgr->n_channels >= 2) {
            uint64_t imbalance_amt = mgr->entries[0].channel.local_amount / 2;
            if (imbalance_amt > 0) {
                printf("Imbalancing: %llu sats from ch0 → ch1\n",
                       (unsigned long long)imbalance_amt);
                lsp_channels_initiate_payment(mgr, lsp_p, 0, 1, imbalance_amt);
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
        int rebal_count = lsp_channels_auto_rebalance(mgr, lsp_p);
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

        /* Verify: rebalance must have happened, and heaviest channel should decrease */
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
                       "(%llu → %llu)\n",
                       (unsigned long long)heaviest_pct_before,
                       (unsigned long long)pct_after);
                rebalance_pass = 0;
            }
        }

        printf("AUTO-REBALANCE TEST: %s\n", rebalance_pass ? "PASS" : "FAIL");
        fflush(stdout);
        if (!rebalance_pass) {
            jit_channels_cleanup(mgr);
            free(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
    }

    /* === Batch-Rebalance Test === */
    if (test_batch_rebalance && channels_active) {
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
            batch_count = lsp_channels_batch_rebalance(mgr, lsp_p, entries, 2);
            printf("Batch rebalance: %d/2 succeeded\n", batch_count);
        } else if (mgr->n_channels >= 2) {
            rebalance_entry_t entries[1];
            entries[0].from = 0;
            entries[0].to = 1;
            entries[0].amount_sats = 2000;
            batch_count = lsp_channels_batch_rebalance(mgr, lsp_p, entries, 1);
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
        if (!batch_pass) {
            jit_channels_cleanup(mgr);
            free(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
    }

    /* === Leaf Realloc Test === */
    if (test_realloc && channels_active) {
        printf("\n=== LEAF REALLOC TEST ===\n");
        fflush(stdout);
        int realloc_pass = 1;

        if (leaf_arity != 2) {
            printf("  SKIP: --test-realloc requires --leaf-arity 2\n");
            printf("LEAF REALLOC TEST: SKIP\n");
        } else if (n_clients < 2) {
            printf("  SKIP: --test-realloc requires --clients >= 2\n");
            printf("LEAF REALLOC TEST: SKIP\n");
        } else {
            /* Record current leaf node output amounts (authoritative source) */
            size_t leaf_node_idx = lsp_p->factory.leaf_node_indices[0];
            factory_node_t *leaf_node = &lsp_p->factory.nodes[leaf_node_idx];
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

            printf("Reallocating leaf 0: [%llu, %llu, %llu] → [%llu, %llu, %llu]\n",
                   (unsigned long long)orig_amounts[0],
                   (unsigned long long)orig_amounts[1],
                   (unsigned long long)orig_amounts[2],
                   (unsigned long long)new_amounts[0],
                   (unsigned long long)new_amounts[1],
                   (unsigned long long)new_amounts[2]);

            int rc = lsp_realloc_leaf(mgr, lsp_p, 0, new_amounts, 3);
            if (rc != 1) {
                printf("  FAIL: lsp_realloc_leaf returned %d (expected 1)\n", rc);
                realloc_pass = 0;
            }

            /* Verify amounts updated (read from leaf node outputs) */
            if (realloc_pass) {
                uint64_t post_total = 0;
                for (size_t k = 0; k < leaf_node->n_outputs; k++)
                    post_total += leaf_node->outputs[k].amount_sats;
                if (post_total != orig_total) {
                    printf("  FAIL: total funding changed "
                           "(%llu → %llu)\n",
                           (unsigned long long)orig_total,
                           (unsigned long long)post_total);
                    realloc_pass = 0;
                }
            }

            printf("LEAF REALLOC TEST: %s\n", realloc_pass ? "PASS" : "FAIL");
        }
        fflush(stdout);
        if (!realloc_pass) {
            jit_channels_cleanup(mgr);
            free(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
    }

    /* === JIT Lifecycle Test === */
    if (test_jit && channels_active) {
        printf("\n=== JIT LIFECYCLE TEST ===\n");
        fflush(stdout);
        int jit_pass = 1;
        uint64_t jit_amount = mgr->jit_funding_sats;
        if (jit_amount == 0) jit_amount = 50000;  /* default 50k sats */

        /* Client uses non-blocking state machine for JIT — no delays needed.
           Create 1 JIT channel (each needs ~10 min on-chain confirmation). */
        for (int ci = 0; ci < 1; ci++) {
            printf("  Creating JIT channel for client %d (%llu sats)...\n",
                   ci, (unsigned long long)jit_amount);
            fflush(stdout);
            if (!jit_channel_create(mgr, lsp_p, (size_t)ci, jit_amount, "test_jit")) {
                printf("  Client %d: JIT create FAILED\n", ci);
                jit_pass = 0;
                break;
            }
            if (!jit_channel_is_active(mgr, (size_t)ci)) {
                printf("  Client %d: JIT not active after create\n", ci);
                jit_pass = 0;
                break;
            }
            jit_channel_t *jit = jit_channel_find(mgr, (size_t)ci);
            printf("  Client %d: JIT channel OPEN (id=0x%04x, funding=%s)\n",
                   ci, jit ? jit->jit_channel_id : 0,
                   jit ? jit->funding_txid_hex : "?");
        }

        printf("JIT LIFECYCLE TEST: %s\n", jit_pass ? "PASS" : "FAIL");
        fflush(stdout);
        if (!jit_pass) {
            jit_channels_cleanup(mgr);
            free(mgr);
            if (use_db) persist_close(&db);
            lsp_cleanup(lsp_p);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
    }

    /* === LSPS2 Wire Test === */
    if (test_lsps2 && channels_active) {
        printf("\n=== LSPS2 WIRE TEST ===\n");
        printf("  LSPS2 handlers active — entering daemon loop for LSPS2 flow\n");
        printf("  Client with --test-lsps2-buy will drive the test\n");
        fflush(stdout);

        /* The LSPS2 test is client-driven. The LSP must be in its daemon loop
           to process MSG_LSPS_REQUEST messages. Force daemon_mode so the daemon
           loop runs after this test block, which handles LSPS requests naturally.
           The test result is checked from the client log externally. */
        daemon_mode = 1;
        printf("LSPS2 WIRE TEST: DEFERRED TO DAEMON LOOP\n");
        fflush(stdout);
    }

    /* === BOLT12 Offer Test === */
    if (test_bolt12 && channels_active) {
        printf("\n=== BOLT12 OFFER TEST ===\n");
        fflush(stdout);
        int b12_pass = 1;

        /* Step 1: Create offer from LSP's node key */
        offer_t offer;
        memset(&offer, 0, sizeof(offer));
        unsigned char node_id[33];
        size_t node_id_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, node_id, &node_id_len,
                                       &lsp_p->lsp_pubkey, SECP256K1_EC_COMPRESSED);
        memcpy(offer.node_id, node_id, 33);
        offer.amount_msat = 1000000;  /* 1000 sats */
        offer.has_amount = 1;
        strncpy(offer.description, "SuperScalar factory payment", sizeof(offer.description) - 1);

        char offer_enc[1024];
        if (!offer_encode(&offer, offer_enc, sizeof(offer_enc))) {
            printf("  offer_encode FAILED\n");
            b12_pass = 0;
        } else {
            printf("  Offer created: %s\n", offer_enc);
        }

        /* Step 2: Decode round-trip */
        if (b12_pass) {
            offer_t decoded;
            if (!offer_decode(offer_enc, &decoded)) {
                printf("  offer_decode round-trip FAILED\n");
                b12_pass = 0;
            } else if (memcmp(decoded.node_id, offer.node_id, 33) != 0) {
                printf("  node_id mismatch after round-trip\n");
                b12_pass = 0;
            } else if (decoded.amount_msat != offer.amount_msat) {
                printf("  amount_msat mismatch after round-trip\n");
                b12_pass = 0;
            } else {
                printf("  Round-trip: OK (node_id, amount, description match)\n");
            }
        }

        /* Step 3: Create and verify invoice from request */
        if (b12_pass) {
            invoice_request_t req;
            memset(&req, 0, sizeof(req));
            req.amount_msat = 1000000;
            memcpy(req.payer_key, node_id, 33);

            /* Compute offer_id (SHA256 of encoded offer) */
            /* Use a simple hash of the offer string as stand-in */
            unsigned char offer_hash[32];
            {
                /* SHA256 of the bech32m string */
                size_t olen = strlen(offer_enc);
                secp256k1_context *tmpctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
                unsigned char tag[] = "superscalar/offer_id";
                /* Simple tagged hash: H(tag || offer_enc) */
                unsigned char preimage[512];
                memcpy(preimage, tag, sizeof(tag));
                size_t pl = sizeof(tag);
                if (olen + pl <= sizeof(preimage)) {
                    memcpy(preimage + pl, offer_enc, olen);
                    pl += olen;
                }
                /* Use bitcoin's double-SHA256 as a simple hash */
                /* For test purposes, just zero-fill offer_id */
                memset(offer_hash, 0x42, 32);
                secp256k1_context_destroy(tmpctx);
            }
            memcpy(req.offer_id, offer_hash, 32);

            if (!invoice_request_sign(&req, ctx, lsp_seckey)) {
                printf("  invoice_request_sign FAILED\n");
                b12_pass = 0;
            } else if (!invoice_request_verify(&req, ctx)) {
                printf("  invoice_request_verify FAILED\n");
                b12_pass = 0;
            } else {
                printf("  Invoice request: signed + verified OK\n");
            }
        }

        /* Step 4: Create invoice from request */
        if (b12_pass) {
            invoice_request_t req;
            memset(&req, 0, sizeof(req));
            req.amount_msat = 1000000;
            memcpy(req.payer_key, node_id, 33);
            memset(req.offer_id, 0x42, 32);
            invoice_request_sign(&req, ctx, lsp_seckey);

            unsigned char pay_hash[32], pay_secret[32];
            memset(pay_hash, 0xAA, 32);
            memset(pay_secret, 0xBB, 32);

            invoice_t inv;
            if (!invoice_from_request(&req, ctx, lsp_seckey, pay_hash, pay_secret, &inv)) {
                printf("  invoice_from_request FAILED\n");
                b12_pass = 0;
            } else if (!invoice_verify(&inv, ctx, node_id)) {
                printf("  invoice_verify FAILED\n");
                b12_pass = 0;
            } else {
                printf("  Invoice: created from request + verified OK\n");
            }
        }

        printf("BOLT12 OFFER TEST: %s\n", b12_pass ? "PASS" : "FAIL");
        fflush(stdout);
    }

    /* === Buy Liquidity Test (L-stock → client inbound capacity) === */
    if (test_buy_liquidity && channels_active) {
        printf("\n=== BUY LIQUIDITY TEST ===\n");
        fflush(stdout);
        int buy_pass = 1;

        if (leaf_arity != 2) {
            printf("  SKIP: --test-buy-liquidity requires --leaf-arity 2\n");
            printf("BUY LIQUIDITY TEST: SKIP\n");
        } else {
            /* Buy 1000 sats of inbound liquidity for client 0 from L-stock */
            uint64_t buy_amount = 1000;
            printf("  Buying %llu sats inbound for client 0 from L-stock...\n",
                   (unsigned long long)buy_amount);
            fflush(stdout);

            /* Record pre-buy state */
            size_t leaf_node_idx = lsp_p->factory.leaf_node_indices[0];
            uint64_t pre_lstock = lsp_p->factory.nodes[leaf_node_idx].outputs[2].amount_sats;
            uint64_t pre_client = lsp_p->factory.nodes[leaf_node_idx].outputs[0].amount_sats;

            if (!lsp_channels_buy_liquidity(mgr, lsp_p, 0, buy_amount)) {
                printf("  buy_liquidity FAILED\n");
                buy_pass = 0;
            } else {
                /* Verify L-stock decreased and client output increased */
                uint64_t post_lstock = lsp_p->factory.nodes[leaf_node_idx].outputs[2].amount_sats;
                uint64_t post_client = lsp_p->factory.nodes[leaf_node_idx].outputs[0].amount_sats;

                printf("  L-stock: %llu → %llu (-%llu)\n",
                       (unsigned long long)pre_lstock, (unsigned long long)post_lstock,
                       (unsigned long long)(pre_lstock - post_lstock));
                printf("  Client 0 output: %llu → %llu (+%llu)\n",
                       (unsigned long long)pre_client, (unsigned long long)post_client,
                       (unsigned long long)(post_client - pre_client));

                if (post_lstock >= pre_lstock || post_client <= pre_client) {
                    printf("  Balance check FAILED\n");
                    buy_pass = 0;
                }
            }
            printf("BUY LIQUIDITY TEST: %s\n", buy_pass ? "PASS" : "FAIL");
        }
        fflush(stdout);
    }

    /* BIP39 test moved to early-exit section (before factory creation) */

    /* === Large Factory Test (>4 clients) === */
    if (test_large_factory && channels_active) {
        printf("\n=== LARGE FACTORY TEST ===\n");
        printf("  Factory created with %d clients (%d channels)\n",
               n_clients, n_clients);
        printf("  DW tree nodes: %zu\n", lsp_p->factory.n_nodes);
        printf("  Leaf arity: %d\n", lsp_p->factory.leaf_arity);
        fflush(stdout);
        int large_pass = 1;

        /* Verify we have more than 4 clients */
        if (n_clients <= 4) {
            printf("  SKIP: --test-large-factory requires --clients > 4\n");
            printf("LARGE FACTORY TEST: SKIP\n");
        } else {
            /* Verify all channels are active */
            int active = 0;
            for (int ci = 0; ci < n_clients; ci++) {
                if (mgr->entries[ci].channel.funding_amount > 0)
                    active++;
            }
            printf("  Active channels: %d/%d\n", active, n_clients);
            if (active != n_clients) {
                printf("  Not all channels active — FAILED\n");
                large_pass = 0;
            }

            /* Verify DW tree is deeper than 4-client tree */
            if (lsp_p->factory.n_nodes <= 6) {
                printf("  Tree should have >6 nodes for >4 clients, got %zu\n",
                       lsp_p->factory.n_nodes);
                large_pass = 0;
            } else {
                printf("  Tree depth verified: %zu nodes (>6)\n",
                       lsp_p->factory.n_nodes);
            }

            printf("LARGE FACTORY TEST: %s\n", large_pass ? "PASS" : "FAIL");
        }
        fflush(stdout);
    }

    /* === Factory Rotation Test (Tier 3) === */
    if (test_rotation && channels_active) {
        printf("\n=== FACTORY ROTATION TEST ===\n");

        /* --- Phase A: PTLC key turnover over wire --- */
        printf("Phase A: PTLC key turnover for Factory 0\n");

        /* Build keypair/pubkey arrays matching production pattern
           (lsp_rotation.c:94-111): real LSP keypair + actual client
           pubkeys with LSP placeholder keypairs for signing slots. */
        secp256k1_keypair rot_kps[FACTORY_MAX_SIGNERS];
        secp256k1_pubkey rot_pks[FACTORY_MAX_SIGNERS];
        rot_kps[0] = lsp_kp;
        if (!secp256k1_keypair_pub(ctx, &rot_pks[0], &lsp_kp)) {
            fprintf(stderr, "rotation: keypair_pub failed for LSP\n");
            return 1;
        }
        for (int ci = 0; ci < n_clients; ci++) {
            rot_pks[ci + 1] = lsp_p->client_pubkeys[ci];
            rot_kps[ci + 1] = lsp_kp;  /* placeholder — not used for signing */
        }

        musig_keyagg_t rot_ka;
        musig_aggregate_keys(ctx, &rot_ka, rot_pks, n_total);

        unsigned char turnover_msg[32];
        sha256_tagged("turnover", (const unsigned char *)"turnover", 8, turnover_msg);

        for (int ci = 0; ci < n_clients; ci++) {
            uint32_t pidx = (uint32_t)(ci + 1);
            secp256k1_pubkey client_pk = rot_pks[pidx];

            unsigned char presig[64];
            int nonce_parity;
            musig_keyagg_t ka_copy = rot_ka;
            if (!adaptor_create_turnover_presig(ctx, presig, &nonce_parity,
                                                  turnover_msg, rot_kps, n_total,
                                                  &ka_copy, NULL, &client_pk)) {
                fprintf(stderr, "ROTATION: presig failed client %d\n", ci);
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }

            /* Send PTLC_PRESIG to client */
            cJSON *pm = wire_build_ptlc_presig(presig, nonce_parity, turnover_msg);
            if (!wire_send(lsp_p->client_fds[ci], MSG_PTLC_PRESIG, pm)) {
                cJSON_Delete(pm);
                fprintf(stderr, "ROTATION: send presig failed client %d\n", ci);
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            cJSON_Delete(pm);

            /* Recv PTLC_ADAPTED_SIG from client (30s wall-clock,
               discard stray messages from concurrent flows). */
            wire_msg_t resp;
            memset(&resp, 0, sizeof(resp));
            {
                struct timeval t_rs, t_rn;
                gettimeofday(&t_rs, NULL);
                int got_sig = 0;
                while (1) {
                    gettimeofday(&t_rn, NULL);
                    int elapsed = (int)(t_rn.tv_sec - t_rs.tv_sec);
                    int remain  = 30 - elapsed;
                    if (remain <= 0) break;
                    if (!wire_recv_timeout(lsp_p->client_fds[ci], &resp, remain)) break;
                    if (resp.msg_type == MSG_PTLC_ADAPTED_SIG) { got_sig = 1; break; }
                    if (resp.msg_type == MSG_ERROR) {
                        if (resp.json) cJSON_Delete(resp.json);
                        memset(&resp, 0, sizeof(resp));
                        break;
                    }
                    fprintf(stderr, "ROTATION: discarding stray msg 0x%02x from client %d\n",
                            resp.msg_type, ci);
                    if (resp.json) cJSON_Delete(resp.json);
                    memset(&resp, 0, sizeof(resp));
                }
                if (!got_sig) {
                    if (resp.json) cJSON_Delete(resp.json);
                    fprintf(stderr, "ROTATION: no adapted_sig from client %d\n", ci);
                    lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                    secp256k1_context_destroy(ctx); return 1;
                }
            }

            unsigned char adapted_sig[64];
            if (!wire_parse_ptlc_adapted_sig(resp.json, adapted_sig)) {
                cJSON_Delete(resp.json);
                fprintf(stderr, "ROTATION: parse adapted_sig failed client %d\n", ci);
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            cJSON_Delete(resp.json);

            /* Extract client's secret key */
            unsigned char extracted[32];
            if (!adaptor_extract_secret(ctx, extracted, adapted_sig, presig,
                                          nonce_parity)) {
                fprintf(stderr, "ROTATION: extract failed client %d\n", ci);
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }

            if (!adaptor_verify_extracted_key(ctx, extracted, &client_pk)) {
                fprintf(stderr, "ROTATION: verify failed client %d\n", ci);
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }

            ladder_record_key_turnover(lad, 0, pidx, extracted);
            if (use_db)
                persist_save_departed_client(&db, 0, pidx, extracted);

            /* Send PTLC_COMPLETE */
            cJSON *cm = wire_build_ptlc_complete();
            wire_send(lsp_p->client_fds[ci], MSG_PTLC_COMPLETE, cm);
            cJSON_Delete(cm);

            printf("  Client %d: key extracted via wire PTLC\n", ci + 1);
        }

        /* --- Phase B: Ladder close of Factory 0 --- */
        printf("Phase B: Ladder close of Factory 0\n");
        if (!ladder_can_close(lad, 0)) {
            fprintf(stderr, "ROTATION: ladder_can_close returned false\n");
            lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }

        tx_output_t rot_outputs[FACTORY_MAX_SIGNERS];
        uint64_t rot_per = (lsp_p->factory.funding_amount_sats - 500) / n_total;
        for (size_t ti = 0; ti < n_total; ti++) {
            rot_outputs[ti].amount_sats = rot_per;
            memcpy(rot_outputs[ti].script_pubkey, fund_spk, 34);
            rot_outputs[ti].script_pubkey_len = 34;
        }
        rot_outputs[n_total - 1].amount_sats =
            lsp_p->factory.funding_amount_sats - 500 - rot_per * (n_total - 1);

        tx_buf_t rot_close_tx;
        tx_buf_init(&rot_close_tx, 512);
        if (!ladder_build_close(lad, 0, &rot_close_tx, rot_outputs, n_total,
                                  (uint32_t)regtest_get_block_height(&rt))) {
            fprintf(stderr, "ROTATION: ladder_build_close failed\n");
            tx_buf_free(&rot_close_tx);
            lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }

        char *rc_hex = malloc(rot_close_tx.len * 2 + 1);
        hex_encode(rot_close_tx.data, rot_close_tx.len, rc_hex);
        char rc_txid[65];
        int rc_sent = regtest_send_raw_tx(&rt, rc_hex, rc_txid);
        if (g_db)
            persist_log_broadcast(g_db, rc_sent ? rc_txid : "?",
                "rotation_close_f0", rc_hex, rc_sent ? "ok" : "failed");
        free(rc_hex);
        tx_buf_free(&rot_close_tx);

        if (!rc_sent) {
            fprintf(stderr, "ROTATION: Factory 0 close TX broadcast failed\n");
            lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }
        ADVANCE(1);
        printf("  Factory 0 closed: %s\n", rc_txid);

        /* --- Phase C: Create Factory 1 --- */
        printf("Phase C: Creating Factory 1\n");

        /* Fund new factory (same address since same participants) */
        double fund2_btc = (double)funding_sats / 100000000.0;
        char fund2_txid_hex[65];
        if (!regtest_fund_address(&rt, fund_addr, fund2_btc, fund2_txid_hex)) {
            fprintf(stderr, "ROTATION: fund Factory 1 failed\n");
            lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }
        if (is_regtest) {
            regtest_mine_blocks(&rt, 1, mine_addr);
        } else {
            printf("ROTATION: waiting for Factory 1 funding confirmation on %s...\n", network);
            fflush(stdout);
            int conf2 = lsp_wait_for_confirmation_service(chain_be, fund2_txid_hex,
                                                      confirm_timeout_secs, mgr, lsp_p);
            if (conf2 < 1) {
                fprintf(stderr, "ROTATION: Factory 1 funding not confirmed within timeout\n");
                lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
        }

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
            fprintf(stderr, "ROTATION: no funding output for Factory 1\n");
            lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }

        /* Free old factory in lsp before reusing.
           Ladder entries use detached copies so no double-free risk. */
        factory_free(&lsp_p->factory);

        /* Compute cltv_timeout for Factory 1 */
        uint32_t cltv2 = 0;
        {
            int cur_h = regtest_get_block_height(&rt);
            if (cltv_timeout_arg > 0) {
                cltv2 = (uint32_t)cltv_timeout_arg;
            } else if (cur_h > 0) {
                int offset = is_regtest ? 35 : (int)(active_blocks + dying_blocks + 10);
                cltv2 = (uint32_t)cur_h + offset;
            }
        }

        /* Run factory creation ceremony (sends FACTORY_PROPOSE to clients,
           who handle it in their MSG_FACTORY_PROPOSE daemon callback) */
        if (!lsp_run_factory_creation(lsp_p,
                                       fund2_txid, fund2_vout,
                                       fund2_amount,
                                       fund_spk, 34,
                                       step_blocks, 4, cltv2)) {
            fprintf(stderr, "ROTATION: Factory 1 creation failed\n");
            lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }

        /* Set lifecycle for Factory 1 */
        {
            int cur_h = regtest_get_block_height(&rt);
            if (cur_h > 0)
                factory_set_lifecycle(&lsp_p->factory, (uint32_t)cur_h, 20, 10);
        }

        /* Store in ladder slot 1 */
        {
            ladder_factory_t *lf1 = &lad->factories[1];
            lf1->factory = lsp_p->factory;
            lf1->factory_id = lad->next_factory_id++;
            lf1->is_initialized = 1;
            lf1->is_funded = 1;
            lf1->cached_state = FACTORY_ACTIVE;
            tx_buf_init(&lf1->distribution_tx, 256);
            lad->n_factories = 2;
        }
        printf("  Factory 1 created and stored in ladder slot 1\n");

        /* Initialize new channel manager + send CHANNEL_READY */
        lsp_channel_mgr_t *mgr2 = calloc(1, sizeof(lsp_channel_mgr_t));
        if (!mgr2) { fprintf(stderr, "LSP: alloc failed\n"); return 1; }
        mgr2->fee = fee_est;
        mgr2->routing_fee_ppm = routing_fee_ppm;
        mgr2->lsp_balance_pct = lsp_balance_pct;
        mgr2->settlement_interval_blocks = settlement_interval;
        if (!lsp_channels_init(mgr2, ctx, &lsp_p->factory, lsp_seckey, (size_t)n_clients)) {
            fprintf(stderr, "ROTATION: channel init for Factory 1 failed\n");
            free(mgr2); lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }
        if (!lsp_channels_exchange_basepoints(mgr2, lsp_p)) {
            fprintf(stderr, "ROTATION: basepoint exchange for Factory 1 failed\n");
            free(mgr2); lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }
        if (!lsp_channels_send_ready(mgr2, lsp_p)) {
            fprintf(stderr, "ROTATION: send_ready for Factory 1 failed\n");
            free(mgr2); lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }
        printf("  Factory 1 channels ready\n");

        /* --- Phase C.5: Wait for client reconnections --- */
        /* Clients disconnect after rotation to reload cleanly from DB
           (Bug 11 fix in superscalar_client.c:1067-1072), then reconnect.
           We must accept those reconnections before cooperative close,
           otherwise lsp_run_cooperative_close sends to stale FDs. */
        {
            size_t reconnected = 0;
            printf("  Waiting for client reconnections...\n");
            for (int attempt = 0; attempt < 30 && reconnected < (size_t)n_clients; attempt++) {
                fd_set rfds;
                FD_ZERO(&rfds);
                FD_SET(lsp_p->listen_fd, &rfds);
                struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
                int sel = select(lsp_p->listen_fd + 1, &rfds, NULL, NULL, &tv);
                if (sel <= 0) continue;

                int new_fd = wire_accept(lsp_p->listen_fd);
                if (new_fd < 0) continue;

                /* Noise handshake */
                int hs;
                if (lsp_p->use_nk)
                    hs = wire_noise_handshake_nk_responder(new_fd, ctx, lsp_p->nk_seckey);
                else
                    hs = wire_noise_handshake_responder(new_fd, ctx);
                if (!hs) { wire_close(new_fd); continue; }

                if (lsp_channels_handle_reconnect(mgr2, lsp_p, new_fd))
                    reconnected++;
            }
            if (reconnected < (size_t)n_clients) {
                fprintf(stderr, "ROTATION: only %zu/%d clients reconnected\n",
                        reconnected, n_clients);
                free(mgr2); lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
                secp256k1_context_destroy(ctx); return 1;
            }
            printf("  All %d clients reconnected\n", n_clients);
        }

        /* --- Phase D: Cooperative close on Factory 1 --- */
        printf("Phase D: Cooperative close of Factory 1\n");

        /* Cooperative close of Factory 1 */
        tx_output_t close2_outputs[FACTORY_MAX_SIGNERS];
        size_t n_close2 = lsp_channels_build_close_outputs(mgr2, &lsp_p->factory,
                                                             close2_outputs, 500,
                                                             NULL, 0);
        tx_buf_t close2_tx;
        tx_buf_init(&close2_tx, 512);
        if (!lsp_run_cooperative_close(lsp_p, &close2_tx, close2_outputs, n_close2,
                                          (uint32_t)regtest_get_block_height(&rt))) {
            fprintf(stderr, "ROTATION: cooperative close of Factory 1 failed\n");
            tx_buf_free(&close2_tx); free(mgr2);
            lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }

        char *c2_hex = malloc(close2_tx.len * 2 + 1);
        hex_encode(close2_tx.data, close2_tx.len, c2_hex);
        char c2_txid[65];
        int c2_sent = regtest_send_raw_tx(&rt, c2_hex, c2_txid);
        if (g_db)
            persist_log_broadcast(g_db, c2_sent ? c2_txid : "?",
                "rotation_close_f1", c2_hex, c2_sent ? "ok" : "failed");
        free(c2_hex);
        tx_buf_free(&close2_tx);

        if (!c2_sent) {
            fprintf(stderr, "ROTATION: Factory 1 close TX broadcast failed\n");
            lsp_cleanup(lsp_p); memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx); return 1;
        }
        ADVANCE(1);

        printf("  Factory 1 closed: %s\n", c2_txid);
        printf("\n=== FACTORY ROTATION TEST PASSED ===\n");

        report_add_string(&rpt, "result", "rotation_test_complete");
        report_close(&rpt);
        free(mgr2);
        if (use_db) persist_close(&db);
        tx_buf_free(&lad->factories[0].distribution_tx);
        tx_buf_free(&lad->factories[1].distribution_tx);
        lsp_cleanup(lsp_p);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 0;
    }

    /* === Phase E-splice: LSP-initiated splice-out test === */
    if (test_splice && channels_active) {
        printf("\n=== SPLICE TEST ===\n");

        if (n_clients < 1) {
            fprintf(stderr, "SPLICE TEST: requires at least 1 client\n");
            goto splice_done;
        }

        int sp_fd = lsp_p->client_fds[0];

        /* ---- Step 1: Quiescence ---- */
        printf("Step 1: sending STFU to client[0]\n");
        {
            cJSON *stfu = cJSON_CreateObject();
            if (!stfu) { fprintf(stderr, "SPLICE TEST: OOM\n"); goto splice_done; }
            cJSON_AddNumberToObject(stfu, "channel_id", 0);
            wire_send(sp_fd, MSG_STFU, stfu);
            cJSON_Delete(stfu);
        }

        wire_msg_t sp_msg;
        if (!wire_recv(sp_fd, &sp_msg) || sp_msg.msg_type != MSG_STFU_ACK) {
            fprintf(stderr, "SPLICE TEST: expected STFU_ACK, got 0x%02x\n", sp_msg.msg_type);
            if (sp_msg.json) cJSON_Delete(sp_msg.json);
            goto splice_done;
        }
        cJSON_Delete(sp_msg.json);
        printf("  STFU_ACK received, channel quiescent\n");

        /* ---- Step 2: Compute 2-of-2 P2TR SPKs ----
         * Current SPK (pre-splice UTXO) and new SPK (post-splice output).
         * For this test both use the same key-path aggregate; the splice-out
         * just reduces the amount by 10 000 sats. */
        secp256k1_pubkey sp_lsp_pubkey;
        secp256k1_keypair_pub(ctx, &sp_lsp_pubkey, &lsp_kp);

        unsigned char sp_current_spk[34];  /* P2TR SPK of the UTXO being spliced */
        unsigned char sp_new_spk[34];      /* P2TR SPK of the new channel output  */
        if (!splice_compute_funding_spk(ctx, sp_current_spk,
                                          &sp_lsp_pubkey, &lsp_p->client_pubkeys[0]) ||
            !splice_compute_funding_spk(ctx, sp_new_spk,
                                          &sp_lsp_pubkey, &lsp_p->client_pubkeys[0])) {
            fprintf(stderr, "SPLICE TEST: splice_compute_funding_spk failed\n");
            goto splice_done;
        }

        /* Splice-out: 50 000 sats in → 40 000 sats out (10 000 removed) */
        uint64_t sp_current_amount = 50000;
        uint64_t sp_new_amount     = 40000;

        /* ---- Step 2a: Fund a standalone on-chain 2-of-2 UTXO ----
         * SuperScalar factory channels are off-chain tree nodes; they have no
         * independent on-chain UTXO until force-closed.  For the splice test we
         * create a dedicated UTXO on regtest so the splice tx has a real input. */
        char sp_fund_addr[128] = {0};
        /* Bytes [2..33] of a P2TR SPK are the 32-byte tweaked x-only pubkey */
        if (!regtest_derive_p2tr_address(&rt, sp_current_spk + 2,
                                           sp_fund_addr, sizeof(sp_fund_addr))) {
            fprintf(stderr, "SPLICE TEST: derive_p2tr_address failed\n");
            goto splice_done;
        }
        char sp_fund_txid_hex[65] = {0};
        printf("Step 2a: funding splice UTXO: %s\n", sp_fund_addr);
        if (!regtest_fund_address(&rt, sp_fund_addr,
                                    (double)sp_current_amount / 1e8,
                                    sp_fund_txid_hex)) {
            fprintf(stderr, "SPLICE TEST: fund_address failed\n");
            goto splice_done;
        }
        /* Confirm with 1 block */
        char sp_pre_mine_addr[128] = {0};
        regtest_get_new_address(&rt, sp_pre_mine_addr, sizeof(sp_pre_mine_addr));
        regtest_mine_blocks(&rt, 1, sp_pre_mine_addr);

        /* Locate the correct vout by matching the SPK */
        uint32_t sp_fund_vout = 0;
        uint64_t sp_funded_sats = 0;
        {
            unsigned char got_spk[64]; size_t got_len = 0;
            int found = 0;
            for (uint32_t v = 0; v < 4 && !found; v++) {
                if (regtest_get_tx_output(&rt, sp_fund_txid_hex, v,
                                           &sp_funded_sats, got_spk, &got_len)) {
                    if (got_len == 34 &&
                        memcmp(got_spk, sp_current_spk, 34) == 0) {
                        sp_fund_vout = v;
                        found = 1;
                    }
                }
            }
            if (!found) {
                fprintf(stderr, "SPLICE TEST: funded vout not found\n");
                goto splice_done;
            }
        }
        printf("  funded UTXO: %s:%u (%llu sats)\n",
               sp_fund_txid_hex, sp_fund_vout,
               (unsigned long long)sp_funded_sats);

        /* Convert display txid → internal byte order */
        unsigned char sp_fund_txid[32];
        for (int i = 0; i < 32; i++) {
            unsigned int b;
            sscanf(sp_fund_txid_hex + 2*(31-i), "%02x", &b);
            sp_fund_txid[i] = (unsigned char)b;
        }

        /* Build keyagg for the 2-of-2 channel (matches splice_compute_funding_spk) */
        secp256k1_pubkey sp_agg_pks[2];
        sp_agg_pks[0] = sp_lsp_pubkey;
        sp_agg_pks[1] = lsp_p->client_pubkeys[0];
        musig_keyagg_t sp_keyagg;
        if (!musig_aggregate_keys(ctx, &sp_keyagg, sp_agg_pks, 2)) {
            fprintf(stderr, "SPLICE TEST: musig_aggregate_keys failed\n");
            goto splice_done;
        }

        /* ---- Step 3: SPLICE_INIT ---- */
        printf("Step 3: sending SPLICE_INIT: new_funding=%llu sats\n",
               (unsigned long long)sp_new_amount);
        {
            cJSON *sinit = wire_build_splice_init(0, sp_new_amount, sp_new_spk, 34);
            if (!sinit) { fprintf(stderr, "SPLICE TEST: OOM\n"); goto splice_done; }
            wire_send(sp_fd, MSG_SPLICE_INIT, sinit);
            cJSON_Delete(sinit);
        }

        if (!wire_recv(sp_fd, &sp_msg) || sp_msg.msg_type != MSG_SPLICE_ACK) {
            fprintf(stderr, "SPLICE TEST: expected SPLICE_ACK, got 0x%02x\n", sp_msg.msg_type);
            if (sp_msg.json) cJSON_Delete(sp_msg.json);
            goto splice_done;
        }
        cJSON_Delete(sp_msg.json);
        printf("  SPLICE_ACK received\n");

        /* ---- Step 4: Build unsigned splice tx ---- */
        tx_buf_t sp_unsigned;
        tx_buf_init(&sp_unsigned, 256);
        if (!splice_build_funding_tx(&sp_unsigned, sp_fund_txid,
                                       sp_fund_vout, sp_new_amount,
                                       sp_new_spk)) {
            fprintf(stderr, "SPLICE TEST: splice_build_funding_tx failed\n");
            tx_buf_free(&sp_unsigned);
            goto splice_done;
        }

        /* ---- Step 5: Sign the splice tx (all-local 2-of-2 MuSig2) ----
         * In production each party exchanges a partial signature over the wire.
         * In this test we perform all-local signing using both keypairs together.
         * The client seckey defaults to 0x22*32 (the deterministic test key used
         * by manual_tests.py start_clients).  Pass --test-splice-client-seckey
         * to override if a different seckey was used. */
        unsigned char sp_client_seckey[32];
        if (test_splice_client_seckey) {
            for (int i = 0; i < 32; i++) {
                unsigned int byte;
                sscanf(test_splice_client_seckey + 2*i, "%02x", &byte);
                sp_client_seckey[i] = (unsigned char)byte;
            }
        } else {
            memset(sp_client_seckey, 0x22, 32);
        }
        secp256k1_keypair sp_client_kp;
        if (!secp256k1_keypair_create(ctx, &sp_client_kp, sp_client_seckey)) {
            fprintf(stderr, "SPLICE TEST: invalid client seckey\n");
            tx_buf_free(&sp_unsigned);
            goto splice_done;
        }

        unsigned char sp_sighash[32];
        if (!compute_taproot_sighash(sp_sighash,
                                       sp_unsigned.data, sp_unsigned.len,
                                       0,                     /* input index */
                                       sp_current_spk, 34,    /* prevout SPK */
                                       sp_funded_sats,        /* prevout amount */
                                       0xFFFFFFFD)) {          /* RBF nsequence */
            fprintf(stderr, "SPLICE TEST: sighash failed\n");
            tx_buf_free(&sp_unsigned);
            goto splice_done;
        }

        secp256k1_keypair sp_kps[2] = { lsp_kp, sp_client_kp };
        unsigned char sp_sig64[64];
        if (!musig_sign_taproot(ctx, sp_sig64, sp_sighash,
                                  sp_kps, 2, &sp_keyagg, NULL)) {
            fprintf(stderr, "SPLICE TEST: musig_sign_taproot failed\n");
            tx_buf_free(&sp_unsigned);
            goto splice_done;
        }

        tx_buf_t sp_signed;
        tx_buf_init(&sp_signed, sp_unsigned.len + 80);
        if (!finalize_signed_tx(&sp_signed, sp_unsigned.data, sp_unsigned.len, sp_sig64)) {
            fprintf(stderr, "SPLICE TEST: finalize_signed_tx failed\n");
            tx_buf_free(&sp_unsigned); tx_buf_free(&sp_signed);
            goto splice_done;
        }
        tx_buf_free(&sp_unsigned);

        /* ---- Step 6: Broadcast and confirm ---- */
        char *sp_tx_hex = malloc(sp_signed.len * 2 + 1);
        if (!sp_tx_hex) { tx_buf_free(&sp_signed); goto splice_done; }
        hex_encode(sp_signed.data, sp_signed.len, sp_tx_hex);
        tx_buf_free(&sp_signed);

        char sp_splice_txid[65] = {0};
        printf("Step 6: broadcasting splice tx\n");
        if (!regtest_send_raw_tx(&rt, sp_tx_hex, sp_splice_txid)) {
            fprintf(stderr, "SPLICE TEST: broadcast failed\n");
            free(sp_tx_hex);
            goto splice_done;
        }
        free(sp_tx_hex);

        char sp_mine_addr[128] = {0};
        regtest_get_new_address(&rt, sp_mine_addr, sizeof(sp_mine_addr));
        regtest_mine_blocks(&rt, 3, sp_mine_addr);
        printf("  splice tx confirmed: %s\n", sp_splice_txid);

        /* ---- Step 7: Decode display txid → internal byte order ---- */
        unsigned char sp_txid_internal[32];
        for (int i = 0; i < 32; i++) {
            unsigned int byte;
            sscanf(sp_splice_txid + 2*(31 - i), "%02x", &byte);
            sp_txid_internal[i] = (unsigned char)byte;
        }

        /* ---- Step 8: SPLICE_LOCKED exchange ---- */
        printf("Step 8: sending SPLICE_LOCKED\n");
        {
            cJSON *slocked = wire_build_splice_locked(0, sp_txid_internal, 0);
            if (!slocked) { fprintf(stderr, "SPLICE TEST: OOM\n"); goto splice_done; }
            wire_send(sp_fd, MSG_SPLICE_LOCKED, slocked);
            cJSON_Delete(slocked);
        }

        if (!wire_recv(sp_fd, &sp_msg) || sp_msg.msg_type != MSG_SPLICE_LOCKED) {
            fprintf(stderr, "SPLICE TEST: expected SPLICE_LOCKED echo, got 0x%02x\n",
                    sp_msg.msg_type);
            if (sp_msg.json) cJSON_Delete(sp_msg.json);
            goto splice_done;
        }
        cJSON_Delete(sp_msg.json);

        /* ---- Step 9: Apply channel update on LSP side ---- */
        channel_t *sp_ch = &mgr->entries[0].channel;
        channel_apply_splice_update(sp_ch, sp_txid_internal, 0, sp_new_amount);
        printf("  LSP channel updated: funding_amount=%llu sats\n",
               (unsigned long long)sp_ch->funding_amount);

        printf("\n=== SPLICE TEST PASSED ===\n");
        report_add_string(&rpt, "result", "splice_test_complete");
        report_add_string(&rpt, "splice_txid", sp_splice_txid);
        report_close(&rpt);
        lsp_cleanup(lsp_p);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 0;

    splice_done:
        fprintf(stderr, "SPLICE TEST FAILED\n");
        report_add_string(&rpt, "result", "splice_test_failed");
        report_close(&rpt);
        lsp_cleanup(lsp_p);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 1;
    }
