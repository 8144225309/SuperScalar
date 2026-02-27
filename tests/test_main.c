#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

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

#define TEST_ASSERT_MEM_EQ(a, b, len, msg) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define RUN_TEST(fn) do { \
    tests_run++; \
    printf("  %s...", #fn); \
    fflush(stdout); \
    if (fn()) { \
        tests_passed++; \
        printf(" OK\n"); \
    } else { \
        tests_failed++; \
    } \
} while(0)

extern int test_dw_layer_init(void);
extern int test_dw_delay_for_state(void);
extern int test_dw_nsequence_for_state(void);
extern int test_dw_advance(void);
extern int test_dw_exhaustion(void);
extern int test_dw_counter_init(void);
extern int test_dw_counter_advance(void);
extern int test_dw_counter_full_cycle(void);

extern int test_musig_aggregate_keys(void);
extern int test_musig_sign_verify(void);
extern int test_musig_wrong_message(void);
extern int test_musig_taproot_sign(void);

extern int test_musig_split_round_basic(void);
extern int test_musig_split_round_taproot(void);
extern int test_musig_nonce_pool(void);
extern int test_musig_partial_sig_verify(void);
extern int test_musig_serialization(void);
extern int test_musig_split_round_5of5(void);

extern int test_tx_buf_primitives(void);
extern int test_build_p2tr_script_pubkey(void);
extern int test_build_unsigned_tx(void);
extern int test_finalize_signed_tx(void);
extern int test_varint_encoding(void);

extern int test_regtest_basic_dw(void);
extern int test_regtest_old_first_attack(void);
extern int test_regtest_musig_onchain(void);
extern int test_regtest_nsequence_edge(void);

extern int test_factory_build_tree(void);
extern int test_factory_sign_all(void);
extern int test_factory_advance(void);
extern int test_factory_sign_split_round_step_by_step(void);
extern int test_factory_split_round_with_pool(void);
extern int test_factory_advance_split_round(void);
extern int test_regtest_factory_tree(void);

extern int test_tapscript_leaf_hash(void);
extern int test_tapscript_tweak_with_tree(void);
extern int test_tapscript_control_block(void);
extern int test_tapscript_sighash(void);
extern int test_factory_tree_with_timeout(void);
extern int test_multi_level_timeout_unit(void);
extern int test_regtest_timeout_spend(void);

extern int test_shachain_generation(void);
extern int test_shachain_derivation_property(void);

extern int test_factory_l_stock_with_burn_path(void);
extern int test_factory_burn_tx_construction(void);
extern int test_factory_advance_with_shachain(void);
extern int test_regtest_burn_tx(void);

extern int test_channel_key_derivation(void);
extern int test_channel_commitment_tx(void);
extern int test_channel_sign_commitment(void);
extern int test_channel_update(void);
extern int test_channel_revocation(void);
extern int test_channel_penalty_tx(void);
extern int test_regtest_channel_unilateral(void);
extern int test_regtest_channel_penalty(void);

extern int test_htlc_offered_scripts(void);
extern int test_htlc_received_scripts(void);
extern int test_htlc_control_block_2leaf(void);
extern int test_htlc_add_fulfill(void);
extern int test_htlc_add_fail(void);
extern int test_htlc_commitment_tx(void);
extern int test_htlc_success_spend(void);
extern int test_htlc_timeout_spend(void);
extern int test_htlc_penalty(void);
extern int test_regtest_htlc_success(void);
extern int test_regtest_htlc_timeout(void);

extern int test_factory_cooperative_close(void);
extern int test_factory_cooperative_close_balances(void);
extern int test_channel_cooperative_close(void);
extern int test_channel_near_exhaustion(void);
extern int test_regtest_factory_coop_close(void);
extern int test_regtest_channel_coop_close(void);

/* Phase 8: Adaptor signatures + PTLC */
extern int test_adaptor_round_trip(void);
extern int test_adaptor_pre_sig_invalid(void);
extern int test_adaptor_taproot(void);
extern int test_ptlc_key_turnover(void);
extern int test_ptlc_lsp_sockpuppet(void);
extern int test_ptlc_factory_coop_close_after_turnover(void);
extern int test_regtest_ptlc_turnover(void);

/* Phase 8: Factory lifecycle + distribution tx */
extern int test_factory_lifecycle_states(void);
extern int test_factory_lifecycle_queries(void);
extern int test_factory_distribution_tx(void);
extern int test_factory_distribution_tx_default(void);

/* Phase 8: Ladder manager */
extern int test_ladder_create_factories(void);
extern int test_ladder_state_transitions(void);
extern int test_ladder_key_turnover_close(void);
extern int test_ladder_overlapping(void);
extern int test_regtest_ladder_lifecycle(void);
extern int test_regtest_ladder_ptlc_migration(void);
extern int test_regtest_ladder_distribution_fallback(void);

/* Phase 9: Wire protocol */
extern int test_wire_pubkey_only_factory(void);
extern int test_wire_framing(void);
extern int test_wire_crypto_serialization(void);
extern int test_wire_nonce_bundle(void);
extern int test_wire_psig_bundle(void);
extern int test_wire_close_unsigned(void);
extern int test_wire_distributed_signing(void);
extern int test_regtest_wire_factory(void);
extern int test_regtest_wire_factory_arity1(void);

/* Phase 10: Channel operations over wire */
extern int test_channel_msg_round_trip(void);
extern int test_lsp_channel_init(void);
extern int test_fee_policy_balance_split(void);
extern int test_channel_wire_framing(void);
extern int test_regtest_intra_factory_payment(void);
extern int test_regtest_multi_payment(void);
extern int test_regtest_lsp_restart_recovery(void);

/* Phase 13: Persistence (SQLite) */
extern int test_persist_open_close(void);
extern int test_persist_channel_round_trip(void);
extern int test_persist_revocation_round_trip(void);
extern int test_persist_htlc_round_trip(void);
extern int test_persist_htlc_delete(void);
extern int test_persist_factory_round_trip(void);
extern int test_persist_nonce_pool_round_trip(void);
extern int test_persist_multi_channel(void);

/* Phase 14: CLN Bridge */
extern int test_bridge_msg_round_trip(void);
extern int test_bridge_hello_handshake(void);
extern int test_bridge_invoice_registry(void);
extern int test_bridge_inbound_flow(void);
extern int test_bridge_outbound_flow(void);
extern int test_bridge_unknown_hash(void);
extern int test_lsp_bridge_accept(void);
extern int test_lsp_inbound_via_bridge(void);
extern int test_bridge_register_forward(void);
extern int test_bridge_set_nk_pubkey(void);
extern int test_bridge_htlc_timeout(void);
extern int test_wire_connect_hostname(void);
extern int test_wire_connect_onion_no_proxy(void);
extern int test_tor_parse_proxy_arg(void);
extern int test_tor_parse_proxy_arg_edge_cases(void);
extern int test_tor_socks5_mock(void);
extern int test_regtest_bridge_nk_handshake(void);
extern int test_regtest_bridge_payment(void);

/* Phase 15: Daemon mode */
extern int test_register_invoice_wire(void);
extern int test_daemon_event_loop(void);
extern int test_client_daemon_autofulfill(void);

/* Phase 16: Reconnection */
extern int test_reconnect_wire(void);
extern int test_reconnect_pubkey_match(void);
extern int test_reconnect_nonce_reexchange(void);
extern int test_client_persist_reload(void);

/* Security hardening */
extern int test_secure_zero_basic(void);
extern int test_wire_plaintext_refused_after_handshake(void);
extern int test_nonce_stable_on_send_failure(void);
extern int test_fd_table_grows_beyond_16(void);

/* Phase 17: Demo polish */
extern int test_create_invoice_wire(void);
extern int test_preimage_fulfills_htlc(void);
extern int test_balance_reporting(void);

/* Phase 18: Watchtower + Fees */
extern int test_fee_init_default(void);
extern int test_fee_penalty_tx(void);
extern int test_fee_factory_tx(void);
extern int test_fee_update_from_node_null(void);
extern int test_watchtower_watch_and_check(void);
extern int test_persist_old_commitments(void);
extern int test_regtest_get_raw_tx_api(void);

/* Phase 19: Encrypted Transport */
extern int test_chacha20_poly1305_rfc7539(void);
extern int test_hmac_sha256_rfc4231(void);
extern int test_noise_handshake(void);
extern int test_encrypted_wire_round_trip(void);
extern int test_encrypted_tamper_reject(void);

/* Demo Day: Network Mode */
extern int test_network_init_regtest(void);
extern int test_network_mode_flag(void);
extern int test_block_height(void);

/* Demo Day: Dust/Reserve Validation */
extern int test_dust_limit_reject(void);
extern int test_reserve_enforcement(void);
extern int test_factory_dust_reject(void);

/* Demo Day: Watchtower Wiring */
extern int test_watchtower_wired(void);
extern int test_watchtower_entry_fields(void);

/* Demo Day: HTLC Timeout Enforcement */
extern int test_htlc_timeout_auto_fail(void);
extern int test_htlc_fulfill_before_timeout(void);
extern int test_htlc_no_timeout_zero_expiry(void);

/* Demo Day: Encrypted Keyfile */
extern int test_keyfile_save_load(void);
extern int test_keyfile_wrong_passphrase(void);
extern int test_keyfile_generate(void);

/* Phase 20: Signet Interop */
extern int test_regtest_init_full(void);
extern int test_regtest_get_balance(void);
extern int test_mine_blocks_non_regtest(void);

/* Phase 23: Persistence Hardening */
extern int test_persist_dw_counter_round_trip(void);
extern int test_persist_departed_clients_round_trip(void);
extern int test_persist_invoice_round_trip(void);
extern int test_persist_htlc_origin_round_trip(void);
extern int test_persist_client_invoice_round_trip(void);
extern int test_persist_counter_round_trip(void);

/* Tier 1: Demo Protections */
extern int test_factory_lifecycle_daemon_check(void);
extern int test_breach_detect_old_commitment(void);
extern int test_dw_counter_tracks_advance(void);

/* Tier 2: Daemon Feature Wiring */
extern int test_ladder_daemon_integration(void);
extern int test_distribution_tx_amounts(void);
extern int test_turnover_extract_and_close(void);

/* Tier 3: Factory Rotation */
extern int test_ptlc_wire_round_trip(void);
extern int test_ptlc_wire_over_socket(void);
extern int test_multi_factory_ladder_monitor(void);

/* Adversarial & Edge-Case Tests */
extern int test_regtest_dw_exhaustion_close(void);
extern int test_regtest_htlc_timeout_race(void);
extern int test_regtest_penalty_with_htlcs(void);
extern int test_regtest_multi_htlc_unilateral(void);
extern int test_regtest_watchtower_mempool_detection(void);
extern int test_regtest_watchtower_late_detection(void);
extern int test_regtest_fee_estimation_parsing(void);
extern int test_regtest_ptlc_no_coop_close(void);
extern int test_regtest_all_offline_recovery(void);
extern int test_regtest_tree_ordering(void);

/* Basepoint Exchange (Gap #1) */
extern int test_wire_channel_basepoints_round_trip(void);
extern int test_basepoint_independence(void);

/* Random Basepoints */
extern int test_random_basepoints(void);
extern int test_persist_basepoints(void);

/* LSP Recovery */
extern int test_lsp_recovery_round_trip(void);

/* Persistence Stress */
extern int test_persist_crash_stress(void);
extern int test_persist_crash_dw_state(void);
extern int test_regtest_crash_double_recovery(void);

/* Client Watchtower (Bidirectional Revocation) */
extern int test_client_watchtower_init(void);
extern int test_bidirectional_revocation(void);
extern int test_client_watch_revoked_commitment(void);
extern int test_lsp_revoke_and_ack_wire(void);
extern int test_factory_node_watch(void);
extern int test_factory_and_commitment_entries(void);
extern int test_htlc_penalty_watch(void);

/* CPFP Anchor System */
extern int test_penalty_tx_has_anchor(void);
extern int test_htlc_penalty_tx_has_anchor(void);
extern int test_watchtower_pending_tracking(void);
extern int test_penalty_fee_updated(void);
extern int test_watchtower_anchor_init(void);
extern int test_regtest_cpfp_penalty_bump(void);
extern int test_regtest_breach_penalty_cpfp(void);

/* CPFP Audit & Remediation */
extern int test_cpfp_sign_complete_check(void);
extern int test_cpfp_witness_offset_p2wpkh(void);
extern int test_cpfp_retry_bump(void);
extern int test_pending_persistence(void);

/* Continuous Ladder Daemon (Gap #3) */
extern int test_ladder_evict_expired(void);
extern int test_rotation_trigger_condition(void);
extern int test_rotation_context_save_restore(void);

/* Security Model Tests */
extern int test_ladder_partial_departure_blocks_close(void);
extern int test_ladder_restructure_fewer_clients(void);
extern int test_dw_cross_layer_delay_ordering(void);
extern int test_ladder_full_rotation_cycle(void);
extern int test_ladder_evict_and_reuse_slot(void);

/* JIT Channel Fallback (Gap #2) */
extern int test_last_message_time_update(void);
extern int test_offline_detection_flag(void);
extern int test_jit_offer_round_trip(void);
extern int test_jit_accept_round_trip(void);
extern int test_jit_ready_round_trip(void);
extern int test_jit_migrate_round_trip(void);
extern int test_jit_channel_init_and_find(void);
extern int test_jit_channel_id_no_collision(void);
extern int test_jit_routing_prefers_factory(void);
extern int test_jit_routing_fallback(void);
extern int test_client_jit_accept_flow(void);
extern int test_client_jit_channel_dispatch(void);
extern int test_persist_jit_save_load(void);
extern int test_persist_jit_update(void);
extern int test_persist_jit_delete(void);
extern int test_jit_migrate_lifecycle(void);
extern int test_jit_migrate_balance(void);
extern int test_jit_state_conversion(void);
extern int test_jit_msg_type_names(void);

/* JIT Hardening */
extern int test_jit_watchtower_registration(void);
extern int test_jit_watchtower_revocation(void);
extern int test_jit_watchtower_cleanup_on_close(void);
extern int test_jit_persist_reload_active(void);
extern int test_jit_persist_skip_closed(void);
extern int test_jit_multiple_channels(void);
extern int test_jit_multiple_watchtower_indices(void);
extern int test_jit_funding_confirmation_transition(void);

/* Cooperative Epoch Reset + Per-Leaf Advance */
extern int test_dw_counter_reset(void);
extern int test_factory_reset_epoch(void);
extern int test_factory_advance_leaf_left(void);
extern int test_factory_advance_leaf_right(void);
extern int test_factory_advance_leaf_independence(void);
extern int test_factory_advance_leaf_exhaustion(void);
extern int test_factory_advance_leaf_preserves_parent_txids(void);
extern int test_factory_epoch_reset_after_leaf_mode(void);

/* Edge Cases + Failure Modes */
extern int test_dw_counter_single_state(void);
extern int test_dw_delay_invariants(void);
extern int test_commitment_number_overflow(void);
extern int test_htlc_double_fulfill_rejected(void);
extern int test_htlc_fail_after_fulfill_rejected(void);
extern int test_htlc_fulfill_after_fail_rejected(void);
extern int test_htlc_max_count_enforcement(void);
extern int test_htlc_dust_amount_rejected(void);
extern int test_htlc_reserve_enforcement(void);
extern int test_factory_advance_past_exhaustion(void);

/* Phase 2: Testnet Ready */
extern int test_wire_oversized_frame_rejected(void);
extern int test_cltv_delta_enforcement(void);
extern int test_persist_schema_version(void);
extern int test_persist_schema_future_reject(void);
extern int test_persist_validate_factory_load(void);
extern int test_persist_validate_channel_load(void);
extern int test_factory_flat_secrets_round_trip(void);
extern int test_factory_flat_secrets_persistence(void);
extern int test_fee_estimator_wiring(void);
extern int test_fee_estimator_null_fallback(void);
extern int test_accept_timeout(void);
extern int test_noise_nk_handshake(void);
extern int test_noise_nk_wrong_pubkey(void);

/* Security Model Gap Tests */
extern int test_musig_nonce_pool_edge_cases(void);
extern int test_wire_recv_truncated_header(void);
extern int test_wire_recv_truncated_body(void);
extern int test_wire_recv_zero_length_frame(void);
extern int test_regtest_htlc_wrong_preimage_rejected(void);
extern int test_regtest_funding_double_spend_rejected(void);

/* Variable-N tree tests */
extern int test_factory_build_tree_n3(void);
extern int test_factory_build_tree_n7(void);
extern int test_factory_build_tree_n9(void);
extern int test_factory_build_tree_n16(void);

/* Tree navigation */
extern int test_factory_path_to_root(void);
extern int test_factory_subtree_clients(void);
extern int test_factory_find_leaf_for_client(void);
extern int test_factory_nav_variable_n(void);

/* Arity-1 tests */
extern int test_factory_build_tree_arity1(void);
extern int test_factory_arity1_leaf_outputs(void);
extern int test_factory_arity1_sign_all(void);
extern int test_factory_arity1_advance(void);
extern int test_factory_arity1_advance_leaf(void);
extern int test_factory_arity1_leaf_independence(void);
extern int test_factory_arity1_coop_close(void);
extern int test_factory_arity1_client_to_leaf(void);
extern int test_factory_arity1_cltv_strict_ordering(void);
extern int test_factory_arity1_min_funding_reject(void);
extern int test_factory_arity1_input_amounts_consistent(void);
extern int test_factory_arity1_split_round_leaf_advance(void);
extern int test_persist_dw_counter_with_leaves_4(void);
extern int test_persist_file_reopen_round_trip(void);

static void run_unit_tests(void) {
    printf("\n=== DW State Machine ===\n");
    RUN_TEST(test_dw_layer_init);
    RUN_TEST(test_dw_delay_for_state);
    RUN_TEST(test_dw_nsequence_for_state);
    RUN_TEST(test_dw_advance);
    RUN_TEST(test_dw_exhaustion);
    RUN_TEST(test_dw_counter_init);
    RUN_TEST(test_dw_counter_advance);
    RUN_TEST(test_dw_counter_full_cycle);

    printf("\n=== MuSig2 ===\n");
    RUN_TEST(test_musig_aggregate_keys);
    RUN_TEST(test_musig_sign_verify);
    RUN_TEST(test_musig_wrong_message);
    RUN_TEST(test_musig_taproot_sign);

    printf("\n=== MuSig2 Split-Round ===\n");
    RUN_TEST(test_musig_split_round_basic);
    RUN_TEST(test_musig_split_round_taproot);
    RUN_TEST(test_musig_nonce_pool);
    RUN_TEST(test_musig_partial_sig_verify);
    RUN_TEST(test_musig_serialization);
    RUN_TEST(test_musig_split_round_5of5);

    printf("\n=== Transaction Builder ===\n");
    RUN_TEST(test_tx_buf_primitives);
    RUN_TEST(test_build_p2tr_script_pubkey);
    RUN_TEST(test_build_unsigned_tx);
    RUN_TEST(test_finalize_signed_tx);
    RUN_TEST(test_varint_encoding);

    printf("\n=== Factory Tree ===\n");
    RUN_TEST(test_factory_build_tree);
    RUN_TEST(test_factory_sign_all);
    RUN_TEST(test_factory_advance);

    printf("\n=== Factory Split-Round ===\n");
    RUN_TEST(test_factory_sign_split_round_step_by_step);
    RUN_TEST(test_factory_split_round_with_pool);
    RUN_TEST(test_factory_advance_split_round);

    printf("\n=== Tapscript (Timeout-Sig-Trees) ===\n");
    RUN_TEST(test_tapscript_leaf_hash);
    RUN_TEST(test_tapscript_tweak_with_tree);
    RUN_TEST(test_tapscript_control_block);
    RUN_TEST(test_tapscript_sighash);
    RUN_TEST(test_factory_tree_with_timeout);
    RUN_TEST(test_multi_level_timeout_unit);

    printf("\n=== Shachain (Factory) ===\n");
    RUN_TEST(test_shachain_generation);
    RUN_TEST(test_shachain_derivation_property);

    printf("\n=== Factory Shachain (L-Output Invalidation) ===\n");
    RUN_TEST(test_factory_l_stock_with_burn_path);
    RUN_TEST(test_factory_burn_tx_construction);
    RUN_TEST(test_factory_advance_with_shachain);

    printf("\n=== Channel (Poon-Dryja) ===\n");
    RUN_TEST(test_channel_key_derivation);
    RUN_TEST(test_channel_commitment_tx);
    RUN_TEST(test_channel_sign_commitment);
    RUN_TEST(test_channel_update);
    RUN_TEST(test_channel_revocation);
    RUN_TEST(test_channel_penalty_tx);

    printf("\n=== HTLC (Phase 6) ===\n");
    RUN_TEST(test_htlc_offered_scripts);
    RUN_TEST(test_htlc_received_scripts);
    RUN_TEST(test_htlc_control_block_2leaf);
    RUN_TEST(test_htlc_add_fulfill);
    RUN_TEST(test_htlc_add_fail);
    RUN_TEST(test_htlc_commitment_tx);
    RUN_TEST(test_htlc_success_spend);
    RUN_TEST(test_htlc_timeout_spend);
    RUN_TEST(test_htlc_penalty);

    printf("\n=== Cooperative Close (Phase 7) ===\n");
    RUN_TEST(test_factory_cooperative_close);
    RUN_TEST(test_factory_cooperative_close_balances);
    RUN_TEST(test_channel_cooperative_close);

    printf("\n=== Adaptor Signatures (Phase 8a) ===\n");
    RUN_TEST(test_adaptor_round_trip);
    RUN_TEST(test_adaptor_pre_sig_invalid);
    RUN_TEST(test_adaptor_taproot);

    printf("\n=== PTLC Key Turnover (Phase 8b) ===\n");
    RUN_TEST(test_ptlc_key_turnover);
    RUN_TEST(test_ptlc_lsp_sockpuppet);
    RUN_TEST(test_ptlc_factory_coop_close_after_turnover);

    printf("\n=== Factory Lifecycle (Phase 8c) ===\n");
    RUN_TEST(test_factory_lifecycle_states);
    RUN_TEST(test_factory_lifecycle_queries);
    RUN_TEST(test_factory_distribution_tx);
    RUN_TEST(test_factory_distribution_tx_default);

    printf("\n=== Ladder Manager (Phase 8d) ===\n");
    RUN_TEST(test_ladder_create_factories);
    RUN_TEST(test_ladder_state_transitions);
    RUN_TEST(test_ladder_key_turnover_close);
    RUN_TEST(test_ladder_overlapping);

    printf("\n=== Wire Protocol (Phase 9) ===\n");
    RUN_TEST(test_wire_pubkey_only_factory);
    RUN_TEST(test_wire_framing);
    RUN_TEST(test_wire_crypto_serialization);
    RUN_TEST(test_wire_nonce_bundle);
    RUN_TEST(test_wire_psig_bundle);
    RUN_TEST(test_wire_close_unsigned);
    RUN_TEST(test_wire_distributed_signing);

    printf("\n=== Channel Operations (Phase 10) ===\n");
    RUN_TEST(test_channel_msg_round_trip);
    RUN_TEST(test_lsp_channel_init);
    RUN_TEST(test_fee_policy_balance_split);
    RUN_TEST(test_channel_wire_framing);

    printf("\n=== Persistence (Phase 13) ===\n");
    RUN_TEST(test_persist_open_close);
    RUN_TEST(test_persist_channel_round_trip);
    RUN_TEST(test_persist_revocation_round_trip);
    RUN_TEST(test_persist_htlc_round_trip);
    RUN_TEST(test_persist_htlc_delete);
    RUN_TEST(test_persist_factory_round_trip);
    RUN_TEST(test_persist_nonce_pool_round_trip);
    RUN_TEST(test_persist_multi_channel);

    printf("\n=== CLN Bridge (Phase 14) ===\n");
    RUN_TEST(test_bridge_msg_round_trip);
    RUN_TEST(test_bridge_hello_handshake);
    RUN_TEST(test_bridge_invoice_registry);
    RUN_TEST(test_bridge_inbound_flow);
    RUN_TEST(test_bridge_outbound_flow);
    RUN_TEST(test_bridge_unknown_hash);
    RUN_TEST(test_lsp_bridge_accept);
    RUN_TEST(test_lsp_inbound_via_bridge);
    RUN_TEST(test_bridge_register_forward);
    RUN_TEST(test_bridge_set_nk_pubkey);
    RUN_TEST(test_bridge_htlc_timeout);

    printf("\n=== Wire Hostname + Tor ===\n");
    RUN_TEST(test_wire_connect_hostname);
    RUN_TEST(test_wire_connect_onion_no_proxy);
    RUN_TEST(test_tor_parse_proxy_arg);
    RUN_TEST(test_tor_parse_proxy_arg_edge_cases);
    RUN_TEST(test_tor_socks5_mock);

    printf("\n=== Daemon Mode (Phase 15) ===\n");
    RUN_TEST(test_register_invoice_wire);
    RUN_TEST(test_daemon_event_loop);
    RUN_TEST(test_client_daemon_autofulfill);

    printf("\n=== Reconnection (Phase 16) ===\n");
    RUN_TEST(test_reconnect_wire);
    RUN_TEST(test_reconnect_pubkey_match);
    RUN_TEST(test_reconnect_nonce_reexchange);
    RUN_TEST(test_client_persist_reload);

    printf("\n=== Security Hardening ===\n");
    RUN_TEST(test_secure_zero_basic);
    RUN_TEST(test_wire_plaintext_refused_after_handshake);
    RUN_TEST(test_nonce_stable_on_send_failure);
    RUN_TEST(test_fd_table_grows_beyond_16);
    RUN_TEST(test_channel_near_exhaustion);

    printf("\n=== Demo Polish (Phase 17) ===\n");
    RUN_TEST(test_create_invoice_wire);
    RUN_TEST(test_preimage_fulfills_htlc);
    RUN_TEST(test_balance_reporting);

    printf("\n=== Watchtower + Fees (Phase 18) ===\n");
    RUN_TEST(test_fee_init_default);
    RUN_TEST(test_fee_penalty_tx);
    RUN_TEST(test_fee_factory_tx);
    RUN_TEST(test_fee_update_from_node_null);
    RUN_TEST(test_watchtower_watch_and_check);
    RUN_TEST(test_persist_old_commitments);
    RUN_TEST(test_regtest_get_raw_tx_api);

    printf("\n=== Encrypted Transport (Phase 19) ===\n");
    RUN_TEST(test_chacha20_poly1305_rfc7539);
    RUN_TEST(test_hmac_sha256_rfc4231);
    RUN_TEST(test_noise_handshake);
    RUN_TEST(test_encrypted_wire_round_trip);
    RUN_TEST(test_encrypted_tamper_reject);

    printf("\n=== Network Mode (Demo Day Step 1) ===\n");
    RUN_TEST(test_network_init_regtest);
    RUN_TEST(test_network_mode_flag);
    RUN_TEST(test_block_height);

    printf("\n=== Dust/Reserve Validation (Demo Day Step 2) ===\n");
    RUN_TEST(test_dust_limit_reject);
    RUN_TEST(test_reserve_enforcement);
    RUN_TEST(test_factory_dust_reject);

    printf("\n=== Watchtower Wiring (Demo Day Step 3) ===\n");
    RUN_TEST(test_watchtower_wired);
    RUN_TEST(test_watchtower_entry_fields);

    printf("\n=== HTLC Timeout Enforcement (Demo Day Step 4) ===\n");
    RUN_TEST(test_htlc_timeout_auto_fail);
    RUN_TEST(test_htlc_fulfill_before_timeout);
    RUN_TEST(test_htlc_no_timeout_zero_expiry);

    printf("\n=== Encrypted Keyfile (Demo Day Step 5) ===\n");
    RUN_TEST(test_keyfile_save_load);
    RUN_TEST(test_keyfile_wrong_passphrase);
    RUN_TEST(test_keyfile_generate);

    printf("\n=== Signet Interop (Phase 20) ===\n");
    RUN_TEST(test_regtest_init_full);
    RUN_TEST(test_regtest_get_balance);
    RUN_TEST(test_mine_blocks_non_regtest);

    printf("\n=== Persistence Hardening (Phase 23) ===\n");
    RUN_TEST(test_persist_dw_counter_round_trip);
    RUN_TEST(test_persist_departed_clients_round_trip);
    RUN_TEST(test_persist_invoice_round_trip);
    RUN_TEST(test_persist_htlc_origin_round_trip);
    RUN_TEST(test_persist_client_invoice_round_trip);
    RUN_TEST(test_persist_counter_round_trip);

    printf("\n=== Demo Protections (Tier 1) ===\n");
    RUN_TEST(test_factory_lifecycle_daemon_check);
    RUN_TEST(test_breach_detect_old_commitment);
    RUN_TEST(test_dw_counter_tracks_advance);

    printf("\n=== Daemon Feature Wiring (Tier 2) ===\n");
    RUN_TEST(test_ladder_daemon_integration);
    RUN_TEST(test_distribution_tx_amounts);
    RUN_TEST(test_turnover_extract_and_close);

    printf("\n=== Factory Rotation (Tier 3) ===\n");
    RUN_TEST(test_ptlc_wire_round_trip);
    RUN_TEST(test_ptlc_wire_over_socket);
    RUN_TEST(test_multi_factory_ladder_monitor);

    printf("\n=== Basepoint Exchange (Gap #1) ===\n");
    RUN_TEST(test_wire_channel_basepoints_round_trip);
    RUN_TEST(test_basepoint_independence);

    printf("\n=== Random Basepoints ===\n");
    RUN_TEST(test_random_basepoints);
    RUN_TEST(test_persist_basepoints);

    printf("\n=== LSP Recovery ===\n");
    RUN_TEST(test_lsp_recovery_round_trip);

    printf("\n=== Persistence Stress ===\n");
    RUN_TEST(test_persist_crash_stress);
    RUN_TEST(test_persist_crash_dw_state);

    printf("\n=== Client Watchtower ===\n");
    RUN_TEST(test_client_watchtower_init);
    RUN_TEST(test_bidirectional_revocation);
    RUN_TEST(test_client_watch_revoked_commitment);
    RUN_TEST(test_lsp_revoke_and_ack_wire);
    RUN_TEST(test_factory_node_watch);
    RUN_TEST(test_factory_and_commitment_entries);
    RUN_TEST(test_htlc_penalty_watch);

    printf("\n=== CPFP Anchor System ===\n");
    RUN_TEST(test_penalty_tx_has_anchor);
    RUN_TEST(test_htlc_penalty_tx_has_anchor);
    RUN_TEST(test_watchtower_pending_tracking);
    RUN_TEST(test_penalty_fee_updated);
    RUN_TEST(test_watchtower_anchor_init);

    printf("\n=== CPFP Audit & Remediation ===\n");
    RUN_TEST(test_cpfp_sign_complete_check);
    RUN_TEST(test_cpfp_witness_offset_p2wpkh);
    RUN_TEST(test_cpfp_retry_bump);
    RUN_TEST(test_pending_persistence);

    printf("\n=== Continuous Ladder Daemon (Gap #3) ===\n");
    RUN_TEST(test_ladder_evict_expired);
    RUN_TEST(test_rotation_trigger_condition);
    RUN_TEST(test_rotation_context_save_restore);

    printf("\n=== Security Model Tests ===\n");
    RUN_TEST(test_ladder_partial_departure_blocks_close);
    RUN_TEST(test_ladder_restructure_fewer_clients);
    RUN_TEST(test_dw_cross_layer_delay_ordering);
    RUN_TEST(test_ladder_full_rotation_cycle);
    RUN_TEST(test_ladder_evict_and_reuse_slot);

    printf("\n=== JIT Channel Fallback (Gap #2) ===\n");
    RUN_TEST(test_last_message_time_update);
    RUN_TEST(test_offline_detection_flag);
    RUN_TEST(test_jit_offer_round_trip);
    RUN_TEST(test_jit_accept_round_trip);
    RUN_TEST(test_jit_ready_round_trip);
    RUN_TEST(test_jit_migrate_round_trip);
    RUN_TEST(test_jit_channel_init_and_find);
    RUN_TEST(test_jit_channel_id_no_collision);
    RUN_TEST(test_jit_routing_prefers_factory);
    RUN_TEST(test_jit_routing_fallback);
    RUN_TEST(test_client_jit_accept_flow);
    RUN_TEST(test_client_jit_channel_dispatch);
    RUN_TEST(test_persist_jit_save_load);
    RUN_TEST(test_persist_jit_update);
    RUN_TEST(test_persist_jit_delete);
    RUN_TEST(test_jit_migrate_lifecycle);
    RUN_TEST(test_jit_migrate_balance);
    RUN_TEST(test_jit_state_conversion);
    RUN_TEST(test_jit_msg_type_names);

    printf("\n=== JIT Hardening ===\n");
    RUN_TEST(test_jit_watchtower_registration);
    RUN_TEST(test_jit_watchtower_revocation);
    RUN_TEST(test_jit_watchtower_cleanup_on_close);
    RUN_TEST(test_jit_persist_reload_active);
    RUN_TEST(test_jit_persist_skip_closed);
    RUN_TEST(test_jit_multiple_channels);
    RUN_TEST(test_jit_multiple_watchtower_indices);
    RUN_TEST(test_jit_funding_confirmation_transition);

    printf("\n=== Cooperative Epoch Reset + Per-Leaf Advance ===\n");
    RUN_TEST(test_dw_counter_reset);
    RUN_TEST(test_factory_reset_epoch);
    RUN_TEST(test_factory_advance_leaf_left);
    RUN_TEST(test_factory_advance_leaf_right);
    RUN_TEST(test_factory_advance_leaf_independence);
    RUN_TEST(test_factory_advance_leaf_exhaustion);
    RUN_TEST(test_factory_advance_leaf_preserves_parent_txids);
    RUN_TEST(test_factory_epoch_reset_after_leaf_mode);

    printf("\n=== Edge Cases + Failure Modes ===\n");
    RUN_TEST(test_dw_counter_single_state);
    RUN_TEST(test_dw_delay_invariants);
    RUN_TEST(test_commitment_number_overflow);
    RUN_TEST(test_htlc_double_fulfill_rejected);
    RUN_TEST(test_htlc_fail_after_fulfill_rejected);
    RUN_TEST(test_htlc_fulfill_after_fail_rejected);
    RUN_TEST(test_htlc_max_count_enforcement);
    RUN_TEST(test_htlc_dust_amount_rejected);
    RUN_TEST(test_htlc_reserve_enforcement);
    RUN_TEST(test_factory_advance_past_exhaustion);

    printf("\n=== Phase 2: Testnet Ready ===\n");
    RUN_TEST(test_wire_oversized_frame_rejected);
    RUN_TEST(test_cltv_delta_enforcement);
    RUN_TEST(test_persist_schema_version);
    RUN_TEST(test_persist_schema_future_reject);
    RUN_TEST(test_persist_validate_factory_load);
    RUN_TEST(test_persist_validate_channel_load);
    RUN_TEST(test_factory_flat_secrets_round_trip);
    RUN_TEST(test_factory_flat_secrets_persistence);
    RUN_TEST(test_fee_estimator_wiring);
    RUN_TEST(test_fee_estimator_null_fallback);
    RUN_TEST(test_accept_timeout);
    RUN_TEST(test_noise_nk_handshake);
    RUN_TEST(test_noise_nk_wrong_pubkey);

    printf("\n=== Security Model Gap Tests ===\n");
    RUN_TEST(test_musig_nonce_pool_edge_cases);
    RUN_TEST(test_wire_recv_truncated_header);
    RUN_TEST(test_wire_recv_truncated_body);
    RUN_TEST(test_wire_recv_zero_length_frame);

    printf("\n=== Tree Navigation ===\n");
    RUN_TEST(test_factory_path_to_root);
    RUN_TEST(test_factory_subtree_clients);
    RUN_TEST(test_factory_find_leaf_for_client);
    RUN_TEST(test_factory_nav_variable_n);

    printf("\n=== Variable-N Tree ===\n");
    RUN_TEST(test_factory_build_tree_n3);
    RUN_TEST(test_factory_build_tree_n7);
    RUN_TEST(test_factory_build_tree_n9);
    RUN_TEST(test_factory_build_tree_n16);

    printf("\n=== Arity-1 Leaves ===\n");
    RUN_TEST(test_factory_build_tree_arity1);
    RUN_TEST(test_factory_arity1_leaf_outputs);
    RUN_TEST(test_factory_arity1_sign_all);
    RUN_TEST(test_factory_arity1_advance);
    RUN_TEST(test_factory_arity1_advance_leaf);
    RUN_TEST(test_factory_arity1_leaf_independence);
    RUN_TEST(test_factory_arity1_coop_close);
    RUN_TEST(test_factory_arity1_client_to_leaf);

    printf("\n=== Arity-1 Hardening ===\n");
    RUN_TEST(test_factory_arity1_cltv_strict_ordering);
    RUN_TEST(test_factory_arity1_min_funding_reject);
    RUN_TEST(test_factory_arity1_input_amounts_consistent);
    RUN_TEST(test_factory_arity1_split_round_leaf_advance);
    RUN_TEST(test_persist_dw_counter_with_leaves_4);
    RUN_TEST(test_persist_file_reopen_round_trip);
}

extern int regtest_init_faucet(void);
extern void regtest_faucet_health_report(void);

static void run_regtest_tests(void) {
    printf("\n=== Regtest Integration ===\n");
    printf("(requires bitcoind -regtest)\n\n");

    /* Pre-fund a shared faucet wallet while block subsidy is high.
       This prevents chain exhaustion when tests run sequentially. */
    if (!regtest_init_faucet())
        printf("  WARNING: faucet init failed, tests will mine individually\n");

    RUN_TEST(test_regtest_basic_dw);
    RUN_TEST(test_regtest_old_first_attack);
    RUN_TEST(test_regtest_musig_onchain);
    RUN_TEST(test_regtest_nsequence_edge);
    RUN_TEST(test_regtest_factory_tree);
    RUN_TEST(test_regtest_timeout_spend);
    RUN_TEST(test_regtest_burn_tx);
    RUN_TEST(test_regtest_channel_unilateral);
    RUN_TEST(test_regtest_channel_penalty);
    RUN_TEST(test_regtest_htlc_success);
    RUN_TEST(test_regtest_htlc_timeout);
    RUN_TEST(test_regtest_factory_coop_close);
    RUN_TEST(test_regtest_channel_coop_close);

    printf("\n=== Regtest Phase 8 ===\n");
    RUN_TEST(test_regtest_ptlc_turnover);
    RUN_TEST(test_regtest_ladder_lifecycle);
    RUN_TEST(test_regtest_ladder_ptlc_migration);
    RUN_TEST(test_regtest_ladder_distribution_fallback);

    printf("\n=== Regtest Phase 9 (Wire Protocol) ===\n");
    RUN_TEST(test_regtest_wire_factory);
    RUN_TEST(test_regtest_wire_factory_arity1);

    printf("\n=== Regtest Phase 10 (Channel Operations) ===\n");
    RUN_TEST(test_regtest_intra_factory_payment);
    RUN_TEST(test_regtest_multi_payment);

    printf("\n=== Regtest LSP Recovery ===\n");
    RUN_TEST(test_regtest_lsp_restart_recovery);
    RUN_TEST(test_regtest_crash_double_recovery);

    printf("\n=== Regtest CPFP Anchor (P2A) ===\n");
    RUN_TEST(test_regtest_cpfp_penalty_bump);
    RUN_TEST(test_regtest_breach_penalty_cpfp);

    printf("\n=== Adversarial & Edge-Case Tests ===\n");
    RUN_TEST(test_regtest_dw_exhaustion_close);
    RUN_TEST(test_regtest_htlc_timeout_race);
    RUN_TEST(test_regtest_penalty_with_htlcs);
    RUN_TEST(test_regtest_multi_htlc_unilateral);
    RUN_TEST(test_regtest_watchtower_mempool_detection);
    RUN_TEST(test_regtest_watchtower_late_detection);
    RUN_TEST(test_regtest_ptlc_no_coop_close);
    RUN_TEST(test_regtest_all_offline_recovery);
    RUN_TEST(test_regtest_tree_ordering);

    printf("\n=== Security Model Gap Tests (Regtest) ===\n");
    RUN_TEST(test_regtest_htlc_wrong_preimage_rejected);
    RUN_TEST(test_regtest_funding_double_spend_rejected);

    printf("\n=== Regtest Fee Estimation ===\n");
    RUN_TEST(test_regtest_fee_estimation_parsing);

    printf("\n=== Regtest Bridge (Phase 14) ===\n");
    RUN_TEST(test_regtest_bridge_nk_handshake);
    RUN_TEST(test_regtest_bridge_payment);

    regtest_faucet_health_report();
}

int main(int argc, char *argv[]) {
    int run_unit = 0, run_regtest = 0;

    if (argc < 2)
        run_unit = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--unit") == 0) run_unit = 1;
        if (strcmp(argv[i], "--regtest") == 0) run_regtest = 1;
        if (strcmp(argv[i], "--all") == 0) { run_unit = 1; run_regtest = 1; }
    }

    printf("SuperScalar Test Suite\n");
    printf("======================\n");

    if (run_unit) run_unit_tests();
    if (run_regtest) run_regtest_tests();

    printf("\n==============================\n");
    printf("Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0)
        printf(" (%d FAILED)", tests_failed);
    printf("\n");

    return tests_failed > 0 ? 1 : 0;
}
