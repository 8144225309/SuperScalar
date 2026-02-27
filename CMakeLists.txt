cmake_minimum_required(VERSION 3.14)
# cJSON v1.7.18 declares cmake_minimum_required(VERSION 1.0) which CMake 4.0+
# rejects.  This silences the error without patching the vendored dep.
# Ignored on CMake < 3.31 (variable simply doesn't exist yet).
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
project(superscalar C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --- Compiler warnings (INTERFACE so they never leak to FetchContent deps) ---
add_library(project_warnings INTERFACE)
target_compile_options(project_warnings INTERFACE
    -Wall -Wextra -Werror
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

# --- Static linking (eliminates LD_LIBRARY_PATH hacks) ---
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

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
    # Pinned 2026-02-24 — bump explicitly and retest when updating
    GIT_TAG        64316eac116f1ae74111e98ab82fc7aa905b1d5a
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
    src/lsp_bridge.c
    src/lsp_rotation.c
    src/lsp_demo.c
    src/report.c
    src/persist.c
    src/bridge.c
    src/fee.c
    src/watchtower.c
    src/crypto_aead.c
    src/noise.c
    src/keyfile.c
    src/jit_channel.c
    src/tor.c
    src/ceremony.c
)
target_include_directories(superscalar PUBLIC include)
target_include_directories(superscalar PRIVATE ${secp256k1-zkp_SOURCE_DIR}/include)
target_include_directories(superscalar PRIVATE ${cjson_SOURCE_DIR})
target_include_directories(superscalar PUBLIC ${SQLite3_INCLUDE_DIRS})
target_link_libraries(superscalar PUBLIC secp256k1 cjson SQLite::SQLite3)
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

add_executable(superscalar_bridge tools/superscalar_bridge.c)
target_include_directories(superscalar_bridge PRIVATE ${secp256k1-zkp_SOURCE_DIR}/include)
target_include_directories(superscalar_bridge PRIVATE ${cjson_SOURCE_DIR})
target_link_libraries(superscalar_bridge PRIVATE superscalar project_warnings)
if(ENABLE_SANITIZERS)
    target_link_libraries(superscalar_bridge PRIVATE project_sanitizers)
endif()
