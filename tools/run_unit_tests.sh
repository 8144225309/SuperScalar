#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/../build"

NPROC=$(nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4)

cd "$BUILD_DIR"
make -j"$NPROC" 2>&1 | tail -5

echo "=== Running unit tests ==="
./test_superscalar --unit 2>&1
