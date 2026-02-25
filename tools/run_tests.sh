#!/bin/bash
# Build and run all tests
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/../build"

NPROC=$(nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4)

echo "=== Building ==="
cd "$BUILD_DIR"
cmake .. -DCMAKE_BUILD_TYPE=Debug 2>&1 | tail -5
make -j"$NPROC" 2>&1 | tail -20

echo ""
echo "=== Running ALL tests ==="
./test_superscalar --all 2>&1
