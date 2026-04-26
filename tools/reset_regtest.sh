#!/bin/bash
# Reset regtest chain to get fresh block subsidies
#
# regtest_init() in src/regtest.c hardcodes rpcuser=rpcuser, rpcpassword=rpcpass
# (the literal strings — they are throwaway regtest credentials, not secrets).
# So bitcoind MUST be started with those credentials or every regtest test
# silently SKIPs because the auth handshake fails.
#
# This script forces those credentials on every restart so the test suite can
# always connect via the same auth path.

RPCUSER="rpcuser"
RPCPASS="rpcpass"

# bitcoin-cli wrapper that uses the credentials we'll start bitcoind with.
# Used everywhere except the initial stop (where cookie auth is also valid).
btccli_auth() {
    bitcoin-cli -regtest -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" "$@"
}

echo "=== Stopping bitcoind ==="
# Try auth-based stop first (matches what we'll restart with), fall back to cookie.
btccli_auth stop 2>/dev/null || bitcoin-cli -regtest stop 2>/dev/null
# Wait for regtest bitcoind to exit (don't kill non-regtest instances).
for i in $(seq 1 15); do
    btccli_auth ping 2>/dev/null || bitcoin-cli -regtest ping 2>/dev/null || break
    sleep 1
done

echo "=== Removing regtest data ==="
rm -rf "$HOME/.bitcoin/regtest"

echo "=== Starting bitcoind ==="
# CRITICAL: -rpcuser/-rpcpassword must match what regtest_init() in
# src/regtest.c uses, otherwise every regtest test SKIPs. See header comment.
bitcoind -regtest -daemon -txindex -fallbackfee=0.00001 \
    -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS"
sleep 2

echo "=== Verifying ==="
if btccli_auth getblockchaininfo | grep -q '"chain"'; then
    btccli_auth getblockchaininfo | grep -E '"chain"|"blocks"'
    echo "=== Done ==="
else
    echo "FAIL: bitcoind did not start, or rpcuser/rpcpass auth failed"
    echo "Check: bitcoind log under \$HOME/.bitcoin/regtest/debug.log"
    exit 1
fi
