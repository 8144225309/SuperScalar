#!/bin/bash -eu
# OSS-Fuzz build script for SuperScalar.
#
# OSS-Fuzz invokes this from within their build container. Environment
# variables set by OSS-Fuzz: CC, CXX, CFLAGS, CXXFLAGS, LIB_FUZZING_ENGINE,
# OUT (output dir for compiled fuzzers + corpora).
#
# Reference: https://google.github.io/oss-fuzz/getting-started/new-project-guide/

cd "$SRC/SuperScalar"

# Configure with fuzzing enabled. OSS-Fuzz injects its own sanitizer flags
# via CFLAGS/CXXFLAGS, so we pass them through.
cmake -B build-oss-fuzz \
    -DCMAKE_BUILD_TYPE=Debug \
    -DENABLE_FUZZING=ON \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS="$LIB_FUZZING_ENGINE" \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5

# Build all fuzz targets
cmake --build build-oss-fuzz --parallel \
    --target fuzz_wire_recv \
    --target fuzz_wire_parse_json \
    --target fuzz_tx_sighash \
    --target fuzz_persist_load \
    --target fuzz_hex_decode \
    --target fuzz_noise_handshake \
    --target fuzz_aead_decrypt

# Copy fuzz binaries + seed corpora to $OUT
for target in fuzz_wire_recv fuzz_wire_parse_json fuzz_tx_sighash \
              fuzz_persist_load fuzz_hex_decode fuzz_noise_handshake \
              fuzz_aead_decrypt; do
    cp "build-oss-fuzz/$target" "$OUT/"
    # Seed corpus (optional — zip if a directory exists)
    if [ -d "oss-fuzz/corpora/$target" ]; then
        (cd "oss-fuzz/corpora/$target" && zip -q -r "$OUT/${target}_seed_corpus.zip" .)
    fi
done
