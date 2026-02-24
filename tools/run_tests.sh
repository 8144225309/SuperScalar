#!/bin/bash
# Build and run all tests
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/../build"

echo "=== Building ==="
cd "$BUILD_DIR"
cmake .. -DCMAKE_BUILD_TYPE=Debug 2>&1 | tail -5
make -j$(nproc) 2>&1 | tail -20

echo ""
echo "=== Running ALL tests ==="
export LD_LIBRARY_PATH=_deps/secp256k1-zkp-build/src:_deps/cjson-build
export DYLD_LIBRARY_PATH="$LD_LIBRARY_PATH"
./test_superscalar --all 2>&1
