#!/bin/bash
# Docker entrypoint for SuperScalar
# Modes: demo (default), demo-all, test, stress, unit, bash
set -e

export PATH="/usr/local/bin:$PATH"
# RPC credentials (match bitcoin.conf written in Dockerfile)
export RPCUSER="rpcuser"
export RPCPASSWORD="rpcpass"
# Tell Python test scripts where to find binaries
export SUPERSCALAR_BUILD="/superscalar/build"
export SUPERSCALAR_BTC="bitcoin-cli"
export SUPERSCALAR_BTCCONF=""

setup_regtest() {
    # Start bitcoind (config from /root/.bitcoin/bitcoin.conf)
    bitcoind -daemon
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
    stress)
        setup_regtest
        cd /superscalar
        exec python3 tools/test_stress.py
        ;;
    unit)
        exec /superscalar/build/test_superscalar --unit
        ;;
    bash)
        setup_regtest
        exec /bin/bash
        ;;
    *)
        exec "$@"
        ;;
esac
