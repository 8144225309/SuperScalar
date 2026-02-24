#!/bin/bash
# require_regtest.sh — Wrapper that fails if bitcoind regtest is not running.
# Usage: tools/require_regtest.sh ./test_superscalar --regtest

set -e

if ! bitcoin-cli -regtest getblockchaininfo >/dev/null 2>&1; then
    echo "ERROR: bitcoind regtest not running. Regtest tests cannot be skipped silently."
    echo "Start with: bitcoind -regtest -daemon"
    exit 1
fi

exec "$@"
