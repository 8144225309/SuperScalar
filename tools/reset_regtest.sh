#!/bin/bash
# Reset regtest chain to get fresh block subsidies

echo "=== Stopping bitcoind ==="
bitcoin-cli -regtest stop 2>/dev/null
# Wait for regtest bitcoind to exit (don't kill non-regtest instances)
for i in $(seq 1 15); do
    bitcoin-cli -regtest ping 2>/dev/null || break
    sleep 1
done

echo "=== Removing regtest data ==="
rm -rf "$HOME/.bitcoin/regtest"

echo "=== Starting bitcoind ==="
bitcoind -regtest -daemon -txindex -fallbackfee=0.00001
sleep 2

echo "=== Verifying ==="
if bitcoin-cli -regtest getblockchaininfo | grep -q '"chain"'; then
    bitcoin-cli -regtest getblockchaininfo | grep -E '"chain"|"blocks"'
    echo "=== Done ==="
else
    echo "FAIL: bitcoind did not start"
    exit 1
fi
