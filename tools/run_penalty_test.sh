#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/../build"

cd "$BUILD_DIR"
make -j$(nproc) 2>&1 | tail -5

echo "=== Running regtest channel ops tests ==="
export LD_LIBRARY_PATH=_deps/secp256k1-zkp-build/src:_deps/cjson-build
export DYLD_LIBRARY_PATH="$LD_LIBRARY_PATH"
./test_superscalar --regtest 2>&1
