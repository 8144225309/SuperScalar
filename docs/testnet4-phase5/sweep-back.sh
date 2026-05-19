#!/usr/bin/env bash
# sweep-back.sh — operator wrapper: pool wallet -> superscalar_test
# Usage: sweep-back.sh <pool> [target_wallet=superscalar_test]
#
# Sweeps all UTXOs from the named pool wallet to a fresh address in the target
# wallet at 1.1 sat/vB. Records the sweep-back txid to stdout for capture into
# the relevant V<n>.md file.
#
# Must be run on the VPS with bitcoind testnet4 reachable.

set -euo pipefail

POOL="${1:-}"
TARGET="${2:-superscalar_test}"

if [ -z "$POOL" ]; then
    echo "Usage: $0 <pool_wallet> [target_wallet]" >&2
    exit 1
fi

RPC="bitcoin-cli -datadir=/var/lib/bitcoind-testnet4 -rpcuser=testnet4rpc -rpcpassword=testnet4rpcpass123 -rpcport=48332"

BAL=$($RPC -rpcwallet="$POOL" getbalance)
if [ "$BAL" = "0.00000000" ]; then
    echo "sweep-back: $POOL already at 0; nothing to do" >&2
    exit 0
fi

DEST=$($RPC -rpcwallet="$TARGET" getnewaddress "sweepback-${POOL}-$(date +%s)")
echo "sweep-back: $POOL -> $DEST  (balance=$BAL)" >&2

# include_unsafe in case test left unconfirmed change in pool wallet
OUT=$($RPC -rpcwallet="$POOL" -named send \
    outputs="[{\"$DEST\":\"$BAL\"}]" \
    options="{\"include_unsafe\":true,\"subtract_fee_from_outputs\":[0]}" \
    fee_rate=1.1 2>&1)
TXID=$(echo "$OUT" | python3 -c "import sys,json
try:
  d=json.load(sys.stdin); print(d.get('txid','ERR'))
except Exception as e:
  print('ERR:'+str(e))")

if [ "${TXID:0:3}" = "ERR" ]; then
    echo "sweep-back: FAILED — $OUT" >&2
    exit 1
fi

echo "$TXID"
