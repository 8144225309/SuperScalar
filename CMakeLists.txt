cmake_minimum_required(VERSION 3.14)
# cJSON v1.7.18 declares cmake_minimum_required(VERSION 1.0) which CMake 4.0+
# rejects.  This silences the error without patching the vendored dep.
# Ignored on CMake < 3.31 (variable simply doesn't exist yet).
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
project(superscalar VERSION 0.1.3 LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --- Compiler warnings (INTERFACE so they never leak to FetchContent deps) ---
add_library(project_warnings INTERFACE)
target_compile_options(project_warnings INTERFACE
    -Wall -Wextra -Werror
    -Wno-unused-result
    $<$<C_COMPILER_ID:GNU>:-Wno-stringop-truncation>
)

# --- Sanitizers (opt-in) ---
option(ENABLE_SANITIZERS "Enable ASan + UBSan" OFF)
if(ENABLE_SANITIZERS)
    add_library(project_sanitizers INTERFACE)
    target_compile_options(project_sanitizers INTERFACE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(project_sanitizers INTERFACE
        -fsanitize=address,undefined)
endif()

# --- Coverage (opt-in, mutually exclusive with sanitizers) ---
option(ENABLE_COVERAGE "Enable gcov coverage instrumentation" OFF)
if(ENABLE_COVERAGE)
    if(ENABLE_SANITIZERS)
        message(WARNING "ENABLE_COVERAGE and ENABLE_SANITIZERS are mutually exclusive; coverage may produce unreliable results.")
    endif()
    add_compile_options(--coverage -fprofile-arcs -ftest-coverage)
    add_link_options(--coverage)
endif()

# --- Fuzzing (opt-in, requires clang with libFuzzer) ---
option(ENABLE_FUZZING "Build fuzz targets with libFuzzer" OFF)

# --- Static linking (eliminates LD_LIBRARY_PATH hacks) ---
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

include(FetchContent)

# --- secp256k1-zkp (BlockstreamResearch fork) with MuSig2 ---
set(SECP256K1_ENABLE_MODULE_MUSIG ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)

FetchContent_Declare(secp256k1-zkp
    GIT_REPOSITORY https://github.com/BlockstreamResearch/secp256k1-zkp.git
    # Pinned 2026-02-24 — bump explicitly and retest when updating
    GIT_TAG        64316eac116f1ae74111e98ab82fc7aa905b1d5a
)
FetchContent_MakeAvailable(secp256k1-zkp)

# --- cJSON for parsing bitcoin-cli output ---
set(CJSON_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(ENABLE_CJSON_TEST OFF CACHE BOOL "" FORCE)
# Prevent cJSON from building its own AFL fuzz targets (conflicts with our ENABLE_FUZZING)
set(ENABLE_FUZZING_saved ${ENABLE_FUZZING})
set(ENABLE_FUZZING OFF CACHE BOOL "" FORCE)

FetchContent_Declare(cjson
    GIT_REPOSITORY https://github.com/DaveGamble/cJSON.git
    GIT_TAG        v1.7.18
)
FetchContent_MakeAvailable(cjson)

# Restore our ENABLE_FUZZING after cJSON is configured
set(ENABLE_FUZZING ${ENABLE_FUZZING_saved} CACHE BOOL "" FORCE)

# --- SQLite3 (system library) ---
find_package(SQLite3 REQUIRED)

# --- OpenSSL (libcrypto for SHA-256 / HMAC) ---
find_package(OpenSSL REQUIRED)

# --- Main library ---
add_library(superscalar
    src/dw_state.c
    src/tx_builder.c
    src/musig.c
    src/regtest.c
    src/chain_backend_regtest.c
    src/bip158_backend.c
    src/p2p_bitcoin.c
    src/util.c
    src/factory.c
    src/tapscript.c
    src/shachain.c
    src/channel.c
    src/adaptor.c
    src/ladder.c
    src/wire.c
    src/lsp.c
    src/client.c
    src/lsp_channels.c
    src/lsp_bridge.c
    src/lsp_rotation.c
    src/lsp_demo.c
    src/report.c
    src/persist.c
    src/bridge.c
    src/fee.c
    src/fee_estimator_static.c
    src/fee_estimator_rpc.c
    src/fee_estimator_blocks.c
    src/fee_estimator_api.c
    src/wallet_source_rpc.c
    src/wallet_source_hd.c
    src/superscalar_sdk.c
    src/watchtower.c
    src/crypto_aead.c
    src/noise.c
    src/keyfile.c
    src/hd_key.c
    src/jit_channel.c
    src/tor.c
    src/ceremony.c
    src/backup.c
    src/wire_tlv.c
    src/bip39.c
    src/rate_limit.c
    src/lsp_queue.c
    src/notify.c
    src/readiness.c
    src/lsps.c
    src/bolt12.c
    src/blinded_path.c
    src/splice.c
    src/bech32m.c
    src/bolt8.c
    src/bolt8_server.c
    src/lsp_wellknown.c
    src/gossip.c
    src/gossip_store.c
    src/mpp.c
    src/scid_registry.c
    src/onion_last_hop.c
    src/htlc_inbound.c
    src/gossip_peer.c
    src/bolt11.c
    src/pathfind.c
    src/onion.c
    src/htlc_forward.c
    src/peer_mgr.c
    src/chan_open.c
    src/ptlc_commit.c
    src/htlc_commit.c
    src/cltv_watchdog.c
    src/chan_close.c
    src/peer_db.c
    src/probe.c
    src/peer_storage.c
    src/payment.c
    src/trampoline.c
    src/hold_invoice.c
    src/lnurl.c
    src/liquidity_ad.c
    src/bolt1.c
    src/circuit_breaker.c
    src/ln_dispatch.c
    src/invoice.c
    src/admin_rpc.c
)
target_include_directories(superscalar PUBLIC include)
target_include_directories(superscalar PRIVATE ${secp256k1-zkp_SOURCE_DIR}/include)
target_include_directories(superscalar PRIVATE ${cjson_SOURCE_DIR})
target_include_directories(superscalar PUBLIC ${SQLite3_INCLUDE_DIRS})
target_link_libraries(superscalar PUBLIC secp256k1 cjson SQLite::SQLite3 OpenSSL::Crypto OpenSSL::SSL)
target_link_libraries(superscalar PRIVATE project_warnings)
if(ENABLE_SANITIZERS)
    target_link_libraries(superscalar PRIVATE project_sanitizers)
endif()

# --- Tests ---
add_executable(test_superscalar
    tests/test_main.c
    tests/test_dw_state.c
    tests/test_musig.c
    tests/test_tx_builder.c
    tests/test_bip158.c
    tests/test_p2p.c
    tests/test_regtest.c
    tests/test_factory.c
    tests/test_tapscript.c
    tests/test_shachain.c
    tests/test_channel.c
    tests/test_adaptor.c
    tests/test_ladder.c
    tests/test_wire.c
    tests/test_channels.c
    tests/test_persist.c
    tests/test_bridge.c
    tests/test_daemon.c
    tests/test_reconnect.c
    tests/test_client_watchtower.c
    tests/test_cpfp.c
    tests/test_jit.c
    tests/test_ceremony.c
    tests/test_property.c
    tests/test_backup.c
    tests/test_keyfile.c
    tests/test_bip39.c
    tests/test_rate_limit.c
    tests/test_fee_estimator.c
    tests/test_wallet_hd.c
    tests/test_queue.c
    tests/test_notify.c
    tests/test_readiness.c
    tests/test_rotation_readiness.c
    tests/test_lsps.c
    tests/test_bolt12.c
    tests/test_splice.c
    tests/test_bolt8.c
    tests/test_lsp_discovery.c
    tests/test_gossip.c
    tests/test_scid_registry.c
    tests/test_onion_last_hop.c
    tests/test_gossip_net.c
    tests/test_mpp.c
    tests/test_lsps2_deferred.c
    tests/test_bolt11.c
    tests/test_pathfind.c
    tests/test_onion.c
    tests/test_htlc_forward.c
    tests/test_peer_mgr.c
    tests/test_chan_open.c
    tests/test_htlc_commit.c
    tests/test_cltv_watchdog.c
    tests/test_chan_close.c
    tests/test_peer_db.c
    tests/test_probe_storage.c
    tests/test_spec_vectors.c
    tests/test_payment.c
    tests/test_splice_wire.c
    tests/test_circuit_breaker.c
    tests/test_trampoline.c
    tests/test_hold_invoice.c
    tests/test_lnurl.c
    tests/test_splice_interactive.c
    tests/test_liquidity_ad.c
    tests/test_bolt1.c
    tests/test_bolt12_full.c
    tests/test_invoice.c
    tests/test_ln_dispatch.c
    tests/test_admin_rpc.c
)
target_include_directories(test_superscalar PRIVATE ${secp256k1-zkp_SOURCE_DIR}/include)
target_include_directories(test_superscalar PRIVATE ${cjson_SOURCE_DIR})
target_link_libraries(test_superscalar PRIVATE superscalar project_warnings)
if(ENABLE_SANITIZERS)
    target_link_libraries(test_superscalar PRIVATE project_sanitizers)
endif()
enable_testing()
add_test(NAME unit_tests COMMAND test_superscalar --unit)
add_test(NAME regtest_tests COMMAND test_superscalar --regtest)

# --- Executables ---
add_executable(superscalar_lsp tools/superscalar_lsp.c)
target_include_directories(superscalar_lsp PRIVATE ${secp256k1-zkp_SOURCE_DIR}/include)
target_include_directories(superscalar_lsp PRIVATE ${cjson_SOURCE_DIR})
target_link_libraries(superscalar_lsp PRIVATE superscalar project_warnings)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_options(superscalar_lsp PRIVATE -rdynamic)
endif()
if(ENABLE_SANITIZERS)
    target_link_libraries(superscalar_lsp PRIVATE project_sanitizers)
endif()

add_executable(superscalar_client_bin tools/superscalar_client.c)
target_include_directories(superscalar_client_bin PRIVATE ${secp256k1-zkp_SOURCE_DIR}/include)
target_include_directories(superscalar_client_bin PRIVATE ${cjson_SOURCE_DIR})
target_link_libraries(superscalar_client_bin PRIVATE superscalar project_warnings)
if(ENABLE_SANITIZERS)
    target_link_libraries(superscalar_client_bin PRIVATE project_sanitizers)
endif()
set_target_properties(superscalar_client_bin PROPERTIES OUTPUT_NAME superscalar_client)

add_executable(bip158_integration_test tools/bip158_integration_test.c)
target_include_directories(bip158_integration_test PRIVATE ${secp256k1-zkp_SOURCE_DIR}/include)
target_include_directories(bip158_integration_test PRIVATE ${cjson_SOURCE_DIR})
target_link_libraries(bip158_integration_test PRIVATE superscalar project_warnings)
if(ENABLE_SANITIZERS)
    target_link_libraries(bip158_integration_test PRIVATE project_sanitizers)
endif()

add_executable(superscalar_bridge tools/superscalar_bridge.c)
target_include_directories(superscalar_bridge PRIVATE ${secp256k1-zkp_SOURCE_DIR}/include)
target_include_directories(superscalar_bridge PRIVATE ${cjson_SOURCE_DIR})
target_link_libraries(superscalar_bridge PRIVATE superscalar project_warnings)
if(ENABLE_SANITIZERS)
    target_link_libraries(superscalar_bridge PRIVATE project_sanitizers)
endif()

add_executable(superscalar_watchtower tools/superscalar_watchtower.c)
target_include_directories(superscalar_watchtower PRIVATE ${secp256k1-zkp_SOURCE_DIR}/include)
target_include_directories(superscalar_watchtower PRIVATE ${cjson_SOURCE_DIR})
target_link_libraries(superscalar_watchtower PRIVATE superscalar project_warnings)
if(ENABLE_SANITIZERS)
    target_link_libraries(superscalar_watchtower PRIVATE project_sanitizers)
endif()

# --- Fuzz targets (libFuzzer + ASan + UBSan) ---
if(ENABLE_FUZZING)
    set(FUZZ_SOURCES
        fuzz/fuzz_wire_recv.c
        fuzz/fuzz_wire_parse_json.c
        fuzz/fuzz_tx_sighash.c
        fuzz/fuzz_persist_load.c
        fuzz/fuzz_hex_decode.c
        fuzz/fuzz_noise_handshake.c
        fuzz/fuzz_aead_decrypt.c
    )
    foreach(fuzz_src ${FUZZ_SOURCES})
        get_filename_component(fuzz_name ${fuzz_src} NAME_WE)
        add_executable(${fuzz_name} ${fuzz_src})
        target_include_directories(${fuzz_name} PRIVATE include)
        target_include_directories(${fuzz_name} PRIVATE ${secp256k1-zkp_SOURCE_DIR}/include)
        target_include_directories(${fuzz_name} PRIVATE ${cjson_SOURCE_DIR})
        target_link_libraries(${fuzz_name} superscalar secp256k1 cjson SQLite::SQLite3)
        target_compile_options(${fuzz_name} PRIVATE
            -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
        target_link_options(${fuzz_name} PRIVATE
            -fsanitize=fuzzer,address,undefined)
    endforeach()
endif()
