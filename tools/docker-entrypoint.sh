#!/bin/bash
set -e

# Start bitcoind regtest
bitcoind -regtest -daemon -fallbackfee=0.00001 -txindex=1
sleep 2

# Fund wallet
bitcoin-cli -regtest createwallet superscalar_lsp >/dev/null 2>&1 || true
ADDR=$(bitcoin-cli -regtest -rpcwallet=superscalar_lsp getnewaddress)
bitcoin-cli -regtest generatetoaddress 101 "$ADDR" >/dev/null

case "${1:-demo}" in
    demo)
        exec bash /superscalar/tools/demo.sh
        ;;
    test)
        exec python3 /superscalar/tools/test_orchestrator.py --scenario all
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
