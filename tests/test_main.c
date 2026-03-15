#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;
static int tests_skipped = 0;

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

#define TEST_SKIP_CODE 2

#define RUN_TEST(fn) do { \
    tests_run++; \
    printf("  %s...", #fn); \
    fflush(stdout); \
    int _rc = fn(); \
    if (_rc == TEST_SKIP_CODE) { \
        tests_skipped++; \
        tests_run--; \
        printf(" SKIP\n"); \
    } else if (_rc) { \
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

/* Phase C: V3/TRUC CPFP */
extern int test_v3_cpfp_tx_version(void);
extern int test_v2_channel_tx_version(void);

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

extern int test_bip158_backend_init(void);
extern int test_bip158_script_registry(void);
extern int test_bip158_tx_cache(void);
extern int test_bip158_gcs_empty_filter(void);
extern int test_bip158_scan_filter_zero_items(void);
extern int test_bip158_gcs_round_trip(void);
extern int test_bip158_checkpoint_round_trip(void);
extern int test_bip158_backend_restore_checkpoint(void);
extern int test_bip158_add_peer(void);
extern int test_bip158_reconnect_no_peers(void);
extern int test_bip158_mempool_cb_wiring(void);
extern int test_bip158_scan_p2p_no_rpc(void);
extern int test_bip158_checkpoint_count(void);
extern int test_bip158_checkpoint_mismatch_disconnects(void);
extern int test_bip158_checkpoint_passthrough(void);
extern int test_bip158_gcs_build_empty(void);
extern int test_bip158_gcs_build_round_trip(void);
extern int test_bip158_compute_filter_header(void);

/* Phase D: multi-peer */
extern int test_multi_peer_filter_header_crosscheck(void);
extern int test_multi_peer_sybil_detection(void);
extern int test_multi_peer_round_robin(void);

/* Phase E: LSPS0/1/2 */
extern int test_lsps0_request_roundtrip(void);
extern int test_lsps0_error_response(void);
extern int test_lsps1_get_info_response(void);
extern int test_lsps1_create_order(void);
extern int test_lsps2_get_info(void);
extern int test_lsps2_buy_creates_jit(void);
/* Phase 2 fix: LSPS context / NULL-safety */
extern int test_lsps_null_ctx_returns_error(void);
extern int test_lsps_malformed_json_returns_zero(void);
/* Gap fix: lsps1.get_order */
extern int test_lsps1_get_order(void);

/* Phase F: BOLT 12 / Offers */
extern int test_offer_encode_decode(void);
extern int test_invoice_request_sign_verify(void);
extern int test_invoice_sign_verify(void);
extern int test_blinded_path_onion(void);
extern int test_offer_no_amount(void);
/* Phase 4 fix: real bech32m + persist schema v3 */
extern int test_bech32m_known_vector(void);
extern int test_offer_encode_bech32m_valid(void);
extern int test_offer_decode_bad_checksum(void);
extern int test_persist_schema_v3(void);
extern int test_persist_save_list_offer(void);

/* Phase G: Splicing */
extern int test_splice_out_flow(void);
extern int test_splice_in_flow(void);
extern int test_splice_mid_htlc(void);
extern int test_splice_channel_update(void);
/* Phase 3 fix: wire builder round-trips */
extern int test_wire_splice_init_roundtrip(void);
extern int test_wire_splice_ack_roundtrip(void);
extern int test_wire_splice_locked_roundtrip(void);
extern int test_splice_state_machine(void);
/* Gap fix: MuSig2 aggregate key for splice funding output */
extern int test_splice_musig_funding_spk(void);

extern int test_p2p_getcfilters_payload(void);
extern int test_p2p_cfilter_parse(void);
extern int test_p2p_cfilter_skips_ping(void);
extern int test_p2p_send_recv_roundtrip(void);
extern int test_p2p_recv_magic_mismatch(void);
extern int test_p2p_broadcast_tx_flow(void);
extern int test_p2p_getheaders_payload(void);
extern int test_p2p_recv_headers_parse(void);
extern int test_p2p_recv_headers_skips_ping(void);
extern int test_p2p_getcfheaders_payload(void);
extern int test_p2p_recv_cfheaders_parse(void);
extern int test_bip157_filter_header_chain(void);
extern int test_p2p_scan_block_txs_legacy(void);
extern int test_p2p_scan_block_txs_empty(void);
extern int test_p2p_recv_block(void);
extern int test_p2p_send_mempool(void);
extern int test_p2p_poll_inv_parse(void);
extern int test_p2p_poll_inv_ignores_block(void);
extern int test_p2p_connect_rejects_non_cf(void);
extern int test_p2p_connect_accepts_cf(void);

/* Phase B: PoW validation */
extern int test_pow_validate_mainnet_genesis(void);
extern int test_pow_validate_fabricated(void);
extern int test_pow_difficulty_transition_valid(void);
extern int test_pow_difficulty_transition_too_easy(void);
/* Phase 1 fix: real timespan tests */
extern int test_pow_difficulty_nominal_timespan(void);
extern int test_pow_difficulty_too_fast_rejected(void);
extern int test_pow_difficulty_too_slow_rejected(void);

extern int test_tapscript_leaf_hash(void);
extern int test_tapscript_tweak_with_tree(void);
extern int test_tapscript_control_block(void);
extern int test_tapscript_sighash(void);
extern int test_revocation_checksig_leaf(void);
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
extern int test_penalty_tx_script_path(void);
extern int test_penalty_tx_key_path_2leaf(void);
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
extern int test_channel_unlimited_commitments(void);
extern int test_channel_dynamic_growth(void);
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
extern int test_bridge_invoice_bolt11_round_trip(void);
extern int test_bridge_bolt11_plugin_to_lsp(void);
extern int test_bridge_preimage_passthrough(void);
extern int test_wire_connect_hostname(void);
extern int test_wire_connect_onion_no_proxy(void);
extern int test_tor_parse_proxy_arg(void);
extern int test_tor_parse_proxy_arg_edge_cases(void);
extern int test_tor_socks5_mock(void);
extern int test_regtest_bridge_nk_handshake(void);
extern int test_regtest_bridge_payment(void);
extern int test_regtest_bridge_invoice_flow(void);
extern int test_regtest_jit_daemon_trigger(void);

/* Phase 15: Daemon mode */
extern int test_register_invoice_wire(void);
extern int test_daemon_event_loop(void);
extern int test_client_daemon_autofulfill(void);
extern int test_cli_command_parsing(void);

/* Phase 16: Reconnection */
extern int test_reconnect_wire(void);
extern int test_reconnect_pubkey_match(void);
extern int test_reconnect_nonce_reexchange(void);
extern int test_client_persist_reload(void);

/* Gap 2B/2C: Reconnect Commitment Reconciliation + HTLC Replay */
extern int test_reconnect_commitment_mismatch_rollback(void);
extern int test_reconnect_commitment_mismatch_reject(void);
extern int test_reconnect_htlc_replay(void);

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
extern int test_hkdf_sha256_rfc5869(void);
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
extern int test_persist_htlc_bidirectional(void);
extern int test_regtest_crash_double_recovery(void);

/* TCP Reconnection Integration */
extern int test_regtest_tcp_reconnect(void);

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

/* Partial Close */
extern int test_ladder_get_cooperative_clients(void);
extern int test_ladder_get_uncooperative_clients(void);
extern int test_ladder_can_partial_close_thresholds(void);
extern int test_partial_rotation_3of4(void);
extern int test_partial_rotation_2of4(void);
extern int test_partial_rotation_insufficient(void);
extern int test_partial_rotation_preserves_distribution_tx(void);

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
extern int test_jit_cooperative_close(void);
extern int test_jit_cooperative_close_key_mismatch(void);
extern int test_jit_migrate_lifecycle(void);
extern int test_jit_migrate_no_balance_hack(void);
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
extern int test_factory_timeout_spend_tx(void);
extern int test_factory_timeout_spend_mid_node(void);

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
extern int test_factory_variable_arity_build(void);
extern int test_factory_variable_arity_sign(void);
extern int test_factory_variable_arity_backward_compat(void);
extern int test_factory_derive_scid(void);
extern int test_wire_scid_assign(void);
extern int test_wire_leaf_realloc(void);
extern int test_factory_set_leaf_amounts(void);
extern int test_leaf_realloc_signing(void);
extern int test_persist_dw_counter_with_leaves_4(void);
extern int test_persist_file_reopen_round_trip(void);

/* Placement + Economics tests */
extern int test_placement_sequential(void);
extern int test_placement_inward(void);
extern int test_placement_outward(void);
extern int test_placement_timezone_cluster(void);
extern int test_placement_profiles_wire_round_trip(void);
extern int test_economic_mode_validation(void);

/* Nonce Pool Integration tests */
extern int test_nonce_pool_factory_creation(void);
extern int test_nonce_pool_exhaustion(void);
extern int test_factory_count_nodes_for_participant(void);

/* Subtree-Scoped Signing tests */
extern int test_factory_sessions_init_path(void);
extern int test_factory_rebuild_path_unsigned(void);
extern int test_factory_sign_path(void);
extern int test_factory_advance_and_rebuild_path(void);

/* Ceremony State Machine tests */
extern int test_ceremony_all_respond(void);
extern int test_ceremony_one_timeout(void);
extern int test_ceremony_below_minimum(void);
extern int test_ceremony_state_transitions(void);

/* Distributed State Advances tests */
extern int test_distributed_epoch_reset(void);
extern int test_arity2_leaf_advance(void);

/* Production Hardening tests */
extern int test_distribution_tx_has_anchor(void);
extern int test_ceremony_retry_excludes_timeout(void);
extern int test_funding_reserve_check(void);

/* Rotation Retry with Backoff tests */
extern int test_rotation_retry_backoff(void);
extern int test_rotation_retry_success_resets(void);
extern int test_rotation_retry_defaults(void);
extern int test_rotation_retry_factory_id_collision(void);

/* Profit Settlement tests */
extern int test_profit_settlement_calculation(void);
extern int test_settlement_trigger_at_interval(void);
extern int test_on_close_includes_unsettled(void);
extern int test_close_outputs_wallet_spk(void);
extern int test_fee_accumulation_and_settlement(void);

/* Distributed Epoch Reset tests */
extern int test_epoch_reset_propose_round_field(void);
extern int test_distributed_epoch_reset_ceremony(void);

/* Property-Based Tests (Roadmap Item #5) */
extern int test_prop_hex_roundtrip(void);
extern int test_prop_shachain_uniqueness(void);
extern int test_prop_wire_msg_roundtrip(void);
extern int test_prop_varint_roundtrip(void);
extern int test_prop_channel_balance_conservation(void);
extern int test_prop_musig_sign_verify(void);
extern int test_prop_wire_commitment_roundtrip(void);
extern int test_prop_wire_bridge_roundtrip(void);
extern int test_prop_persist_factory_roundtrip(void);
extern int test_prop_wire_register_roundtrip(void);

/* Tor Safety Tests (Roadmap Item #6) */
extern int test_tor_only_refuses_clearnet(void);
extern int test_tor_only_allows_onion(void);
extern int test_tor_only_requires_proxy(void);
extern int test_bind_localhost(void);
extern int test_tor_password_file(void);

/* Keysend (Signet/Testnet4 Gap) */
extern int test_bridge_keysend_inbound(void);

/* Signet/Testnet4 Gap Stress Tests */
extern int test_prop_keysend_wire_roundtrip(void);
extern int test_prop_keysend_preimage_verify(void);
extern int test_prop_rebalance_conservation(void);
extern int test_prop_invoice_registry_exhaustion(void);
extern int test_prop_keysend_bridge_e2e(void);
extern int test_prop_cli_command_fuzzing(void);
extern int test_prop_batch_rebalance_partial_fail(void);
extern int test_prop_keysend_invoice_collision(void);
extern int test_auto_rebalance_threshold_edges(void);

/* Bridge Reliability Tests (Roadmap Item #7) */
extern int test_bridge_heartbeat_stale(void);
extern int test_bridge_reconnect(void);
extern int test_bridge_heartbeat_config(void);

/* Backup & Recovery (Mainnet Gap #7) */
extern int test_backup_create_verify_restore(void);
extern int test_backup_wrong_passphrase(void);
extern int test_backup_corrupt_file(void);
extern int test_backup_v2_roundtrip(void);
extern int test_backup_v1_compat(void);
extern int test_backup_v2_wrong_passphrase(void);

/* UTXO Coin Selection (Mainnet Gap #1) */
extern int test_coin_select_basic(void);
extern int test_coin_select_no_change(void);

/* Standalone Watchtower (Mainnet Gap #3) */
extern int test_watchtower_detect_stale_tx(void);
extern int test_persist_open_readonly(void);

/* Factory Config (Mainnet Gap #6) */
extern int test_factory_config_custom(void);
extern int test_factory_config_default(void);

/* Wire TLV Foundation (Mainnet Gap #8) */
extern int test_tlv_encode_decode(void);
extern int test_tlv_decode_truncated(void);
extern int test_wire_hello_tlv_negotiation(void);

/* Async Signing: Queue Wire Messages */
extern int test_wire_queue_items_empty(void);
extern int test_wire_queue_items_roundtrip(void);
extern int test_wire_queue_done_parse(void);
extern int test_wire_queue_done_empty(void);

/* Mainnet Codepath Tests */
extern int test_mainnet_cli_prefix_no_flag(void);
extern int test_mainnet_scan_depth(void);

/* Rate Limiting Tests */
extern int test_rate_limit_under_limit(void);
extern int test_rate_limit_over_limit(void);
extern int test_rate_limit_window_config(void);
extern int test_rate_limit_handshake_cap(void);

/* Shell-Free Execution Tests */
extern int test_regtest_exec_no_shell_interp(void);
extern int test_regtest_argv_tokenization(void);

/* BIP39 Mnemonic Support */
extern int test_bip39_entropy_roundtrip_12(void);
extern int test_bip39_entropy_roundtrip_24(void);
extern int test_bip39_validate_good(void);
extern int test_bip39_validate_bad_checksum(void);
extern int test_bip39_validate_bad_word(void);
extern int test_bip39_seed_derivation(void);
extern int test_bip39_seed_no_passphrase(void);
extern int test_bip39_vector_7f(void);
extern int test_bip39_generate(void);
extern int test_bip39_keyfile_integration(void);

/* Mainnet Audit: Atomic DB Transactions */
extern int test_persist_transaction_commit(void);
extern int test_persist_transaction_rollback(void);

/* Mainnet Audit: Shell Injection Fix */
extern int test_regtest_param_sanitization(void);
extern int test_regtest_exec_rejects_metacharacters(void);

/* Mainnet Audit: Password-Hardened KDF */
extern int test_keyfile_v2_roundtrip(void);
extern int test_keyfile_v1_compat(void);
extern int test_keyfile_wrong_passphrase_v2(void);

/* Mainnet Audit: HD Key Derivation */
extern int test_hd_master_from_seed(void);
extern int test_hd_derive_child(void);
extern int test_hd_derive_path(void);
extern int test_keyfile_from_seed(void);

/* Modular Fee Estimation & SDK Surface */
extern int test_fee_estimator_static_all_targets(void);
extern int test_fee_estimator_target_ordering(void);
extern int test_fee_estimator_blocks_floor_only(void);
extern int test_fee_estimator_blocks_target_ordering(void);
extern int test_feefilter_p2p_parse(void);
extern int test_fee_estimator_api_parse(void);
extern int test_fee_estimator_api_ttl(void);
extern int test_wallet_source_stub(void);
extern int test_ss_config_default(void);

/* HD Wallet (wallet_source_hd_t) */
extern int test_hd_wallet_derives_p2tr(void);
extern int test_hd_wallet_sign_verify(void);
extern int test_hd_wallet_utxo_persist(void);
extern int test_p2p_scan_block_full_output(void);
extern int test_hd_wallet_bip39_roundtrip(void);
extern int test_hd_wallet_passphrase_isolation(void);
extern int test_hd_wallet_dynamic_lookahead(void);

/* Async Signing: Pending Work Queue */
extern int test_queue_push_drain(void);
extern int test_queue_urgency_ordering(void);
extern int test_queue_dedup_replace(void);
extern int test_queue_different_types(void);
extern int test_queue_client_isolation(void);
extern int test_queue_expire(void);
extern int test_queue_delete_single(void);
extern int test_queue_delete_all(void);
extern int test_queue_has_pending(void);
extern int test_queue_request_type_name(void);
extern int test_queue_null_payload(void);
extern int test_queue_drain_limit(void);
extern int test_queue_null_safety(void);
extern int test_queue_get(void);

/* Async Signing: Notification Dispatch */
extern int test_notify_log_init(void);
extern int test_notify_custom_dispatch(void);
extern int test_notify_multiple_sends(void);
extern int test_notify_cleanup(void);
extern int test_notify_null_safety(void);
extern int test_notify_event_names(void);
extern int test_notify_null_detail(void);
extern int test_notify_webhook_init(void);
extern int test_notify_exec_init(void);
extern int test_notify_init_null_args(void);

/* Async Signing: Client Readiness Tracker */
extern int test_readiness_init(void);
extern int test_readiness_set_connected(void);
extern int test_readiness_set_ready(void);
extern int test_readiness_all_ready(void);
extern int test_readiness_partial(void);
extern int test_readiness_clear(void);
extern int test_readiness_persist_roundtrip(void);
extern int test_readiness_urgency_levels(void);
extern int test_readiness_get_missing(void);
extern int test_readiness_reset(void);

/* Async Signing: Rotation Readiness (lsp_check_rotation_readiness) */
extern int test_rotation_readiness_null(void);
extern int test_rotation_readiness_none_connected(void);
extern int test_rotation_readiness_partial(void);

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

    printf("\n=== Phase C: V3/TRUC CPFP ===\n");
    RUN_TEST(test_v3_cpfp_tx_version);
    RUN_TEST(test_v2_channel_tx_version);

    printf("\n=== Factory Tree ===\n");
    RUN_TEST(test_factory_build_tree);
    RUN_TEST(test_factory_sign_all);
    RUN_TEST(test_factory_advance);

    printf("\n=== Factory Split-Round ===\n");
    RUN_TEST(test_factory_sign_split_round_step_by_step);
    RUN_TEST(test_factory_split_round_with_pool);
    RUN_TEST(test_factory_advance_split_round);

    printf("\n=== BIP 158 Compact Block Filters ===\n");
    RUN_TEST(test_bip158_backend_init);
    RUN_TEST(test_bip158_script_registry);
    RUN_TEST(test_bip158_tx_cache);
    RUN_TEST(test_bip158_gcs_empty_filter);
    RUN_TEST(test_bip158_scan_filter_zero_items);
    RUN_TEST(test_bip158_gcs_round_trip);
    RUN_TEST(test_bip158_checkpoint_round_trip);
    RUN_TEST(test_bip158_backend_restore_checkpoint);
    RUN_TEST(test_bip158_add_peer);
    RUN_TEST(test_bip158_reconnect_no_peers);
    RUN_TEST(test_bip158_mempool_cb_wiring);
    RUN_TEST(test_bip158_scan_p2p_no_rpc);
    RUN_TEST(test_bip158_checkpoint_count);
    RUN_TEST(test_bip158_checkpoint_mismatch_disconnects);
    RUN_TEST(test_bip158_checkpoint_passthrough);
    RUN_TEST(test_bip158_gcs_build_empty);
    RUN_TEST(test_bip158_gcs_build_round_trip);
    RUN_TEST(test_bip158_compute_filter_header);

    printf("\n=== Phase D: Multi-Peer Filter Queries ===\n");
    RUN_TEST(test_multi_peer_filter_header_crosscheck);
    RUN_TEST(test_multi_peer_sybil_detection);
    RUN_TEST(test_multi_peer_round_robin);

    printf("\n=== Phase E: LSPS0/1/2 Protocol ===\n");
    RUN_TEST(test_lsps0_request_roundtrip);
    RUN_TEST(test_lsps0_error_response);
    RUN_TEST(test_lsps1_get_info_response);
    RUN_TEST(test_lsps1_create_order);
    RUN_TEST(test_lsps2_get_info);
    RUN_TEST(test_lsps2_buy_creates_jit);
    RUN_TEST(test_lsps_null_ctx_returns_error);
    RUN_TEST(test_lsps_malformed_json_returns_zero);
    RUN_TEST(test_lsps1_get_order);

    printf("\n=== Phase F: BOLT 12 / Offers ===\n");
    RUN_TEST(test_offer_encode_decode);
    RUN_TEST(test_invoice_request_sign_verify);
    RUN_TEST(test_invoice_sign_verify);
    RUN_TEST(test_blinded_path_onion);
    RUN_TEST(test_offer_no_amount);
    RUN_TEST(test_bech32m_known_vector);
    RUN_TEST(test_offer_encode_bech32m_valid);
    RUN_TEST(test_offer_decode_bad_checksum);
    RUN_TEST(test_persist_schema_v3);
    RUN_TEST(test_persist_save_list_offer);

    printf("\n=== Phase G: Splicing ===\n");
    RUN_TEST(test_splice_out_flow);
    RUN_TEST(test_splice_in_flow);
    RUN_TEST(test_splice_mid_htlc);
    RUN_TEST(test_splice_channel_update);
    RUN_TEST(test_wire_splice_init_roundtrip);
    RUN_TEST(test_wire_splice_ack_roundtrip);
    RUN_TEST(test_wire_splice_locked_roundtrip);
    RUN_TEST(test_splice_state_machine);
    RUN_TEST(test_splice_musig_funding_spk);

    printf("\n=== P2P Bitcoin Protocol (BIP 157 client) ===\n");
    RUN_TEST(test_p2p_getcfilters_payload);
    RUN_TEST(test_p2p_cfilter_parse);
    RUN_TEST(test_p2p_cfilter_skips_ping);
    RUN_TEST(test_p2p_send_recv_roundtrip);
    RUN_TEST(test_p2p_recv_magic_mismatch);
    RUN_TEST(test_p2p_broadcast_tx_flow);
    RUN_TEST(test_p2p_getheaders_payload);
    RUN_TEST(test_p2p_recv_headers_parse);
    RUN_TEST(test_p2p_recv_headers_skips_ping);
    RUN_TEST(test_p2p_getcfheaders_payload);
    RUN_TEST(test_p2p_recv_cfheaders_parse);
    RUN_TEST(test_bip157_filter_header_chain);
    RUN_TEST(test_p2p_scan_block_txs_legacy);
    RUN_TEST(test_p2p_scan_block_txs_empty);
    RUN_TEST(test_p2p_recv_block);
    RUN_TEST(test_p2p_send_mempool);
    RUN_TEST(test_p2p_poll_inv_parse);
    RUN_TEST(test_p2p_poll_inv_ignores_block);
    RUN_TEST(test_p2p_connect_rejects_non_cf);
    RUN_TEST(test_p2p_connect_accepts_cf);

    printf("\n=== Phase B: PoW Header Validation ===\n");
    RUN_TEST(test_pow_validate_mainnet_genesis);
    RUN_TEST(test_pow_validate_fabricated);
    RUN_TEST(test_pow_difficulty_transition_valid);
    RUN_TEST(test_pow_difficulty_transition_too_easy);
    RUN_TEST(test_pow_difficulty_nominal_timespan);
    RUN_TEST(test_pow_difficulty_too_fast_rejected);
    RUN_TEST(test_pow_difficulty_too_slow_rejected);

    printf("\n=== Tapscript (Timeout-Sig-Trees) ===\n");

    RUN_TEST(test_tapscript_leaf_hash);
    RUN_TEST(test_tapscript_tweak_with_tree);
    RUN_TEST(test_tapscript_control_block);
    RUN_TEST(test_tapscript_sighash);
    RUN_TEST(test_revocation_checksig_leaf);
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
    RUN_TEST(test_penalty_tx_script_path);
    RUN_TEST(test_penalty_tx_key_path_2leaf);

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
    RUN_TEST(test_bridge_invoice_bolt11_round_trip);
    RUN_TEST(test_bridge_bolt11_plugin_to_lsp);
    RUN_TEST(test_bridge_preimage_passthrough);
    RUN_TEST(test_bridge_keysend_inbound);

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
    RUN_TEST(test_cli_command_parsing);

    printf("\n=== Reconnection (Phase 16) ===\n");
    RUN_TEST(test_reconnect_wire);
    RUN_TEST(test_reconnect_pubkey_match);
    RUN_TEST(test_reconnect_nonce_reexchange);
    RUN_TEST(test_client_persist_reload);

    printf("\n=== Reconnect Commitment Reconciliation (Gap 2B/2C) ===\n");
    RUN_TEST(test_reconnect_commitment_mismatch_rollback);
    RUN_TEST(test_reconnect_commitment_mismatch_reject);
    RUN_TEST(test_reconnect_htlc_replay);

    printf("\n=== Security Hardening ===\n");
    RUN_TEST(test_secure_zero_basic);
    RUN_TEST(test_wire_plaintext_refused_after_handshake);
    RUN_TEST(test_nonce_stable_on_send_failure);
    RUN_TEST(test_fd_table_grows_beyond_16);
    RUN_TEST(test_channel_unlimited_commitments);
    RUN_TEST(test_channel_dynamic_growth);

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
    RUN_TEST(test_hkdf_sha256_rfc5869);
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
    RUN_TEST(test_persist_htlc_bidirectional);

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

    printf("\n=== Partial Close ===\n");
    RUN_TEST(test_ladder_get_cooperative_clients);
    RUN_TEST(test_ladder_get_uncooperative_clients);
    RUN_TEST(test_ladder_can_partial_close_thresholds);
    RUN_TEST(test_partial_rotation_3of4);
    RUN_TEST(test_partial_rotation_2of4);
    RUN_TEST(test_partial_rotation_insufficient);
    RUN_TEST(test_partial_rotation_preserves_distribution_tx);

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
    RUN_TEST(test_jit_cooperative_close);
    RUN_TEST(test_jit_cooperative_close_key_mismatch);
    RUN_TEST(test_jit_migrate_lifecycle);
    RUN_TEST(test_jit_migrate_no_balance_hack);
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
    RUN_TEST(test_factory_timeout_spend_tx);
    RUN_TEST(test_factory_timeout_spend_mid_node);

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

    printf("\n=== Variable Arity ===\n");
    RUN_TEST(test_factory_variable_arity_build);
    RUN_TEST(test_factory_variable_arity_sign);
    RUN_TEST(test_factory_variable_arity_backward_compat);
    RUN_TEST(test_factory_derive_scid);

    printf("\n=== Route Hints (SCID) ===\n");
    RUN_TEST(test_wire_scid_assign);
    RUN_TEST(test_wire_leaf_realloc);

    printf("\n=== Leaf-Level Fund Reallocation ===\n");
    RUN_TEST(test_factory_set_leaf_amounts);
    RUN_TEST(test_leaf_realloc_signing);

    RUN_TEST(test_persist_dw_counter_with_leaves_4);
    RUN_TEST(test_persist_file_reopen_round_trip);

    printf("\n=== Placement + Economics ===\n");
    RUN_TEST(test_placement_sequential);
    RUN_TEST(test_placement_inward);
    RUN_TEST(test_placement_outward);
    RUN_TEST(test_placement_timezone_cluster);
    RUN_TEST(test_placement_profiles_wire_round_trip);
    RUN_TEST(test_economic_mode_validation);

    printf("\n=== Nonce Pool Integration ===\n");
    RUN_TEST(test_nonce_pool_factory_creation);
    RUN_TEST(test_nonce_pool_exhaustion);
    RUN_TEST(test_factory_count_nodes_for_participant);

    printf("\n=== Subtree-Scoped Signing ===\n");
    RUN_TEST(test_factory_sessions_init_path);
    RUN_TEST(test_factory_rebuild_path_unsigned);
    RUN_TEST(test_factory_sign_path);
    RUN_TEST(test_factory_advance_and_rebuild_path);

    printf("\n=== Ceremony State Machine ===\n");
    RUN_TEST(test_ceremony_all_respond);
    RUN_TEST(test_ceremony_one_timeout);
    RUN_TEST(test_ceremony_below_minimum);
    RUN_TEST(test_ceremony_state_transitions);

    printf("\n=== Distributed State Advances ===\n");
    RUN_TEST(test_distributed_epoch_reset);
    RUN_TEST(test_arity2_leaf_advance);

    printf("\n=== Production Hardening ===\n");
    RUN_TEST(test_distribution_tx_has_anchor);
    RUN_TEST(test_ceremony_retry_excludes_timeout);
    RUN_TEST(test_funding_reserve_check);

    printf("\n=== Rotation Retry with Backoff ===\n");
    RUN_TEST(test_rotation_retry_backoff);
    RUN_TEST(test_rotation_retry_success_resets);
    RUN_TEST(test_rotation_retry_defaults);
    RUN_TEST(test_rotation_retry_factory_id_collision);

    printf("\n=== Profit Settlement ===\n");
    RUN_TEST(test_profit_settlement_calculation);
    RUN_TEST(test_settlement_trigger_at_interval);
    RUN_TEST(test_on_close_includes_unsettled);
    RUN_TEST(test_close_outputs_wallet_spk);
    RUN_TEST(test_fee_accumulation_and_settlement);

    printf("\n=== Distributed Epoch Reset ===\n");
    RUN_TEST(test_epoch_reset_propose_round_field);
    RUN_TEST(test_distributed_epoch_reset_ceremony);

    printf("\n=== Property-Based Tests ===\n");
    RUN_TEST(test_prop_hex_roundtrip);
    RUN_TEST(test_prop_shachain_uniqueness);
    RUN_TEST(test_prop_wire_msg_roundtrip);
    RUN_TEST(test_prop_varint_roundtrip);
    RUN_TEST(test_prop_channel_balance_conservation);
    RUN_TEST(test_prop_musig_sign_verify);
    RUN_TEST(test_prop_wire_commitment_roundtrip);
    RUN_TEST(test_prop_wire_bridge_roundtrip);
    RUN_TEST(test_prop_persist_factory_roundtrip);
    RUN_TEST(test_prop_wire_register_roundtrip);

    printf("\n=== Signet/Testnet4 Gap Stress Tests ===\n");
    RUN_TEST(test_prop_keysend_wire_roundtrip);
    RUN_TEST(test_prop_keysend_preimage_verify);
    RUN_TEST(test_prop_rebalance_conservation);
    RUN_TEST(test_prop_invoice_registry_exhaustion);
    RUN_TEST(test_prop_keysend_bridge_e2e);
    RUN_TEST(test_prop_cli_command_fuzzing);
    RUN_TEST(test_prop_batch_rebalance_partial_fail);
    RUN_TEST(test_prop_keysend_invoice_collision);
    RUN_TEST(test_auto_rebalance_threshold_edges);

    printf("\n=== Tor Safety ===\n");
    RUN_TEST(test_tor_only_refuses_clearnet);
    RUN_TEST(test_tor_only_allows_onion);
    RUN_TEST(test_tor_only_requires_proxy);
    RUN_TEST(test_bind_localhost);
    RUN_TEST(test_tor_password_file);

    printf("\n=== Bridge Reliability ===\n");
    RUN_TEST(test_bridge_heartbeat_stale);
    RUN_TEST(test_bridge_reconnect);
    RUN_TEST(test_bridge_heartbeat_config);

    printf("\n=== Backup & Recovery (Mainnet Gap #7) ===\n");
    RUN_TEST(test_backup_create_verify_restore);
    RUN_TEST(test_backup_wrong_passphrase);
    RUN_TEST(test_backup_corrupt_file);

    printf("\n=== Backup KDF v2 (PBKDF2) ===\n");
    RUN_TEST(test_backup_v2_roundtrip);
    RUN_TEST(test_backup_v1_compat);
    RUN_TEST(test_backup_v2_wrong_passphrase);

    printf("\n=== UTXO Coin Selection (Mainnet Gap #1) ===\n");
    RUN_TEST(test_coin_select_basic);
    RUN_TEST(test_coin_select_no_change);

    printf("\n=== Standalone Watchtower (Mainnet Gap #3) ===\n");
    RUN_TEST(test_watchtower_detect_stale_tx);
    RUN_TEST(test_persist_open_readonly);

    printf("\n=== Factory Config (Mainnet Gap #6) ===\n");
    RUN_TEST(test_factory_config_custom);
    RUN_TEST(test_factory_config_default);

    printf("\n=== Wire TLV Foundation (Mainnet Gap #8) ===\n");
    RUN_TEST(test_tlv_encode_decode);
    RUN_TEST(test_tlv_decode_truncated);
    RUN_TEST(test_wire_hello_tlv_negotiation);

    printf("\n=== Async Signing: Queue Wire Messages ===\n");
    RUN_TEST(test_wire_queue_items_empty);
    RUN_TEST(test_wire_queue_items_roundtrip);
    RUN_TEST(test_wire_queue_done_parse);
    RUN_TEST(test_wire_queue_done_empty);

    printf("\n=== Mainnet Codepath Tests ===\n");
    RUN_TEST(test_mainnet_cli_prefix_no_flag);
    RUN_TEST(test_mainnet_scan_depth);

    printf("\n=== Rate Limiting ===\n");
    RUN_TEST(test_rate_limit_under_limit);
    RUN_TEST(test_rate_limit_over_limit);
    RUN_TEST(test_rate_limit_window_config);
    RUN_TEST(test_rate_limit_handshake_cap);

    printf("\n=== Shell-Free Execution ===\n");
    RUN_TEST(test_regtest_exec_no_shell_interp);
    RUN_TEST(test_regtest_argv_tokenization);

    printf("\n=== BIP39 Mnemonic Support ===\n");
    RUN_TEST(test_bip39_entropy_roundtrip_12);
    RUN_TEST(test_bip39_entropy_roundtrip_24);
    RUN_TEST(test_bip39_validate_good);
    RUN_TEST(test_bip39_validate_bad_checksum);
    RUN_TEST(test_bip39_validate_bad_word);
    RUN_TEST(test_bip39_seed_derivation);
    RUN_TEST(test_bip39_seed_no_passphrase);
    RUN_TEST(test_bip39_vector_7f);
    RUN_TEST(test_bip39_generate);
    RUN_TEST(test_bip39_keyfile_integration);

    printf("\n=== Mainnet Audit: Atomic DB Transactions ===\n");
    RUN_TEST(test_persist_transaction_commit);
    RUN_TEST(test_persist_transaction_rollback);

    printf("\n=== Mainnet Audit: Shell Injection Fix ===\n");
    RUN_TEST(test_regtest_param_sanitization);
    RUN_TEST(test_regtest_exec_rejects_metacharacters);

    printf("\n=== Mainnet Audit: Password-Hardened KDF ===\n");
    RUN_TEST(test_keyfile_v2_roundtrip);
    RUN_TEST(test_keyfile_v1_compat);
    RUN_TEST(test_keyfile_wrong_passphrase_v2);

    printf("\n=== Mainnet Audit: HD Key Derivation ===\n");
    RUN_TEST(test_hd_master_from_seed);
    RUN_TEST(test_hd_derive_child);
    RUN_TEST(test_hd_derive_path);
    RUN_TEST(test_keyfile_from_seed);

    printf("\n=== Modular Fee Estimation & SDK Surface ===\n");
    RUN_TEST(test_fee_estimator_static_all_targets);
    RUN_TEST(test_fee_estimator_target_ordering);
    RUN_TEST(test_fee_estimator_blocks_floor_only);
    RUN_TEST(test_fee_estimator_blocks_target_ordering);
    RUN_TEST(test_feefilter_p2p_parse);
    RUN_TEST(test_fee_estimator_api_parse);
    RUN_TEST(test_fee_estimator_api_ttl);
    RUN_TEST(test_wallet_source_stub);
    RUN_TEST(test_ss_config_default);

    printf("\n=== HD Wallet (wallet_source_hd_t) ===\n");
    RUN_TEST(test_hd_wallet_derives_p2tr);
    RUN_TEST(test_hd_wallet_sign_verify);
    RUN_TEST(test_hd_wallet_utxo_persist);
    RUN_TEST(test_p2p_scan_block_full_output);
    RUN_TEST(test_hd_wallet_bip39_roundtrip);
    RUN_TEST(test_hd_wallet_passphrase_isolation);
    RUN_TEST(test_hd_wallet_dynamic_lookahead);

    printf("\n=== Async Signing: Pending Work Queue ===\n");
    RUN_TEST(test_queue_push_drain);
    RUN_TEST(test_queue_urgency_ordering);
    RUN_TEST(test_queue_dedup_replace);
    RUN_TEST(test_queue_different_types);
    RUN_TEST(test_queue_client_isolation);
    RUN_TEST(test_queue_expire);
    RUN_TEST(test_queue_delete_single);
    RUN_TEST(test_queue_delete_all);
    RUN_TEST(test_queue_has_pending);
    RUN_TEST(test_queue_request_type_name);
    RUN_TEST(test_queue_null_payload);
    RUN_TEST(test_queue_drain_limit);
    RUN_TEST(test_queue_null_safety);
    RUN_TEST(test_queue_get);

    printf("\n=== Async Signing: Notification Dispatch ===\n");
    RUN_TEST(test_notify_log_init);
    RUN_TEST(test_notify_custom_dispatch);
    RUN_TEST(test_notify_multiple_sends);
    RUN_TEST(test_notify_cleanup);
    RUN_TEST(test_notify_null_safety);
    RUN_TEST(test_notify_event_names);
    RUN_TEST(test_notify_null_detail);
    RUN_TEST(test_notify_webhook_init);
    RUN_TEST(test_notify_exec_init);
    RUN_TEST(test_notify_init_null_args);

    printf("\n=== Async Signing: Client Readiness Tracker ===\n");
    RUN_TEST(test_readiness_init);
    RUN_TEST(test_readiness_set_connected);
    RUN_TEST(test_readiness_set_ready);
    RUN_TEST(test_readiness_all_ready);
    RUN_TEST(test_readiness_partial);
    RUN_TEST(test_readiness_clear);
    RUN_TEST(test_readiness_persist_roundtrip);
    RUN_TEST(test_readiness_urgency_levels);
    RUN_TEST(test_readiness_get_missing);
    RUN_TEST(test_readiness_reset);

    printf("\n=== Async Signing: Rotation Readiness ===\n");
    RUN_TEST(test_rotation_readiness_null);
    RUN_TEST(test_rotation_readiness_none_connected);
    RUN_TEST(test_rotation_readiness_partial);
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

    printf("\n=== Regtest TCP Reconnection ===\n");
    RUN_TEST(test_regtest_tcp_reconnect);

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
    RUN_TEST(test_regtest_bridge_invoice_flow);

    printf("\n=== Regtest JIT Trigger ===\n");
    RUN_TEST(test_regtest_jit_daemon_trigger);

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
    if (tests_skipped > 0)
        printf(" (%d skipped)", tests_skipped);
    printf("\n");

    return tests_failed > 0 ? 1 : 0;
}
