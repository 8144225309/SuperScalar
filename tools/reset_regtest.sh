#!/bin/bash
# Reset regtest chain to get fresh block subsidies
export PATH="$HOME/bitcoin-28.0/bin:$PATH"

echo "=== Stopping bitcoind ==="
bitcoin-cli -regtest stop 2>/dev/null
sleep 2

echo "=== Removing regtest data ==="
rm -rf "$HOME/.bitcoin/regtest"

echo "=== Starting bitcoind ==="
bitcoind -regtest -daemon -txindex -fallbackfee=0.00001
sleep 2

echo "=== Verifying ==="
bitcoin-cli -regtest getblockchaininfo | grep -E '"chain"|"blocks"'
echo "=== Done ==="
