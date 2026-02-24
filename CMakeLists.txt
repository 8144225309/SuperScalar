cmake_minimum_required(VERSION 3.14)
project(superscalar C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

# --- secp256k1-zkp (BlockstreamResearch fork) with MuSig2 ---
set(SECP256K1_ENABLE_MODULE_MUSIG ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)

FetchContent_Declare(secp256k1-zkp
    GIT_REPOSITORY https://github.com/BlockstreamResearch/secp256k1-zkp.git
    GIT_TAG        master
)
FetchContent_MakeAvailable(secp256k1-zkp)

# --- cJSON for parsing bitcoin-cli output ---
set(CJSON_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(ENABLE_CJSON_TEST OFF CACHE BOOL "" FORCE)

FetchContent_Declare(cjson
    GIT_REPOSITORY https://github.com/DaveGamble/cJSON.git
    GIT_TAG        v1.7.18
)
FetchContent_MakeAvailable(cjson)

# --- SQLite3 (system library) ---
find_package(SQLite3 REQUIRED)

# --- Main library ---
add_library(superscalar
    src/dw_state.c
    src/tx_builder.c
    src/musig.c
    src/regtest.c
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
    src/report.c
    src/persist.c
    src/bridge.c
    src/fee.c
    src/watchtower.c
    src/crypto_aead.c
    src/noise.c
    src/keyfile.c
    src/jit_channel.c
)
target_include_directories(superscalar PUBLIC include)
target_include_directories(superscalar PRIVATE ${secp256k1-zkp_SOURCE_DIR}/include)
target_include_directories(superscalar PRIVATE ${cjson_SOURCE_DIR})
target_include_directories(superscalar PUBLIC ${SQLite3_INCLUDE_DIRS})
target_link_libraries(superscalar PUBLIC secp256k1 cjson SQLite::SQLite3)

# --- Tests ---
add_executable(test_superscalar
    tests/test_main.c
    tests/test_dw_state.c
    tests/test_musig.c
    tests/test_tx_builder.c
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
)
target_include_directories(test_superscalar PRIVATE ${secp256k1-zkp_SOURCE_DIR}/include)
target_include_directories(test_superscalar PRIVATE ${cjson_SOURCE_DIR})
target_link_libraries(test_superscalar PRIVATE superscalar)
enable_testing()
add_test(NAME unit_tests COMMAND test_superscalar --unit)
add_test(NAME regtest_tests COMMAND test_superscalar --regtest)

# --- Executables ---
add_executable(superscalar_lsp tools/superscalar_lsp.c)
target_include_directories(superscalar_lsp PRIVATE ${secp256k1-zkp_SOURCE_DIR}/include)
target_include_directories(superscalar_lsp PRIVATE ${cjson_SOURCE_DIR})
target_link_libraries(superscalar_lsp PRIVATE superscalar)

add_executable(superscalar_client_bin tools/superscalar_client.c)
target_include_directories(superscalar_client_bin PRIVATE ${secp256k1-zkp_SOURCE_DIR}/include)
target_include_directories(superscalar_client_bin PRIVATE ${cjson_SOURCE_DIR})
target_link_libraries(superscalar_client_bin PRIVATE superscalar)
set_target_properties(superscalar_client_bin PROPERTIES OUTPUT_NAME superscalar_client)

add_executable(superscalar_bridge tools/superscalar_bridge.c)
target_include_directories(superscalar_bridge PRIVATE ${secp256k1-zkp_SOURCE_DIR}/include)
target_include_directories(superscalar_bridge PRIVATE ${cjson_SOURCE_DIR})
target_link_libraries(superscalar_bridge PRIVATE superscalar)
