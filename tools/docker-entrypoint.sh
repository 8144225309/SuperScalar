#!/bin/bash
# Docker entrypoint for SuperScalar
# Modes: demo (default), demo-all, test, unit, bash
set -e

export PATH="/usr/local/bin:$PATH"

setup_regtest() {
    # Start bitcoind regtest
    bitcoind -regtest -daemon -fallbackfee=0.00001 -txindex=1
    # Wait for RPC readiness
    for i in $(seq 1 30); do
        if bitcoin-cli -regtest getblockchaininfo >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    # Create and fund wallet (retry for startup race)
    for i in $(seq 1 10); do
        result=$(bitcoin-cli -regtest createwallet superscalar_lsp 2>&1)
        if echo "$result" | grep -q '"name"'; then
            break
        fi
        sleep 1
    done
    ADDR=$(bitcoin-cli -regtest -rpcwallet=superscalar_lsp getnewaddress)
    bitcoin-cli -regtest generatetoaddress 201 "$ADDR" >/dev/null
    sleep 1
}

case "${1:-demo}" in
    demo)
        setup_regtest
        cd /superscalar
        exec bash tools/run_demo.sh --basic
        ;;
    demo-all)
        setup_regtest
        cd /superscalar
        exec bash tools/run_demo.sh --all
        ;;
    test)
        setup_regtest
        cd /superscalar
        exec python3 tools/manual_tests.py
        ;;
    unit)
        exec /superscalar/build/test_superscalar --unit
        ;;
    bash)
        exec /bin/bash
        ;;
    *)
        exec "$@"
        ;;
esac
