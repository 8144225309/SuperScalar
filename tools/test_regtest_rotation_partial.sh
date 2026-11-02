#!/usr/bin/env bash
# PARTIAL ROTATION drill: one of four clients is offline when the factory
# reaches DYING.  The rotation runs with the three cooperative clients:
# Phase B retires the old factory WITHOUT closing it (its distribution TX
# pays the departed client at expiry) and Phase C funds and signs a
# three-client replacement.
#
# PASS: a partial rotation over 3/4 clients, no cooperative close of the old
#       factory (its funding stays unspent), exactly one replacement funding,
#       the replacement signed, rotation complete.
#
# Partial rotations are not tracked by the rotation_progress marker (see
# lsp_rotation.c): a crash inside one is not resumable.  Documented, not
# exercised here.
#
# Node/wallet are overridable so the drill can run against any private regtest
# node: REPO CONF RPCPORT RPCUSER RPCPASS WALLET PORT BUILD.
set -uo pipefail
REPO="${REPO:-/root/SuperScalar}"
cd "$REPO" || exit 1

PORT="${PORT:-9973}"
TMP="/tmp/rot_partial_$PORT"
BUILD="${BUILD:-build-release}"
CONF="${CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
RPCPORT="${RPCPORT:-18443}"
RPCUSER="${RPCUSER:-rpcuser}"
RPCPASS="${RPCPASS:-rpcpass}"
BCLI="bitcoin-cli -regtest -conf=$CONF"
WALLET="${WALLET:-ss_cheat_leaf_miner}"
LSP_SECKEY=0000000000000000000000000000000000000000000000000000000000000001
LSP_PUB=0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
DB="$TMP/lsp.db"
AMOUNT=200000

cleanup() { kill -9 ${LSP:-0} ${MINER:-0} 2>/dev/null || true
            pkill -9 -f "superscalar_(lsp|client).*--port $PORT " 2>/dev/null || true; }
trap cleanup EXIT

pkill -9 -f "superscalar_(lsp|client).*--port $PORT " 2>/dev/null || true
rm -rf "$TMP"; mkdir -p "$TMP"

$BCLI loadwallet "$WALLET" >/dev/null 2>&1 || true
MADDR=$($BCLI -rpcwallet="$WALLET" -named getnewaddress address_type=bech32m 2>/dev/null)
[ -n "$MADDR" ] || { echo "PARTIAL-FAIL: could not get mine address"; exit 1; }
$BCLI -rpcwallet="$WALLET" generatetoaddress 101 "$MADDR" >/dev/null 2>&1

LSP_ARGS=(--network regtest --port $PORT --daemon --active-blocks 6 --dying-blocks 120
  --lsp-balance-pct 50 --clients 4 --arity 1 --amount $AMOUNT --fee-rate 1100
  --confirm-timeout 86400 --seckey $LSP_SECKEY
  --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" --wallet "$WALLET" --db "$DB")

"$BUILD/superscalar_lsp" "${LSP_ARGS[@]}" > "$TMP/lsp.log" 2>&1 &
LSP=$!
for i in $(seq 1 20); do sleep 1; grep -q listening "$TMP/lsp.log" 2>/dev/null && break; done
grep -q listening "$TMP/lsp.log" || { echo "PARTIAL-FAIL: LSP never listened"; exit 1; }

declare -A CPID
for N in 1 2 3 4; do
  SK=$(printf "%064x" $((N + 1)))
  "$BUILD/superscalar_client" --network regtest --host 127.0.0.1 --port $PORT --daemon \
    --seckey "$SK" --fee-rate 1100 --lsp-balance-pct 50 --lsp-pubkey $LSP_PUB \
    --participant-id $N --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
    --wallet "$WALLET" --db "$TMP/c${N}.db" > "$TMP/c${N}.log" 2>&1 &
  CPID[$N]=$!
  sleep 0.3
done

( while kill -0 $LSP 2>/dev/null; do $BCLI -rpcwallet="$WALLET" generatetoaddress 1 "$MADDR" >/dev/null 2>&1; sleep 2; done ) &
MINER=$!

for i in $(seq 1 180); do
  sleep 1
  grep -qa "ladder initialized" "$TMP/lsp.log" && break
  kill -0 $LSP 2>/dev/null || break
done
grep -qa "ladder initialized" "$TMP/lsp.log" || { echo "PARTIAL-FAIL: factory 0 never created"; tail -8 "$TMP/lsp.log"; exit 1; }
# Hold the chain still until the channels are up and client 4 is gone, so the
# factory cannot reach DYING (--active-blocks 6) with every client online.
kill -9 $MINER 2>/dev/null; MINER=0
for i in $(seq 1 120); do
  sleep 1
  grep -qa "daemon loop started" "$TMP/lsp.log" && break
  kill -0 $LSP 2>/dev/null || break
done
grep -qa "daemon loop started" "$TMP/lsp.log" || { echo "PARTIAL-FAIL: LSP never reached its daemon loop"; tail -8 "$TMP/lsp.log"; exit 1; }
kill -9 "${CPID[4]}" 2>/dev/null
sleep 5
echo "factory 0 live; client 4 taken offline before DYING"
( while kill -0 $LSP 2>/dev/null; do $BCLI -rpcwallet="$WALLET" generatetoaddress 1 "$MADDR" >/dev/null 2>&1; sleep 2; done ) &
MINER=$!

for i in $(seq 1 300); do
  sleep 1
  kill -0 $LSP 2>/dev/null || break
  grep -qaE "rotation complete|auto-rotation FAILED|new factory creation failed" "$TMP/lsp.log" && { echo "outcome at ~${i}s"; break; }
done
sleep 5
kill -9 $LSP $MINER 2>/dev/null
sleep 1

echo "=== rotation key lines ==="
grep -aE "LSP rotate:|auto-rotation" "$TMP/lsp.log" | grep -v "key extracted\|stray msg" | cut -c1-180 | head -30

cnt() { local n; n=$(grep -acE "$1" "$2" 2>/dev/null) || n=0; echo "$n"; }
L="$TMP/lsp.log"
PARTIAL=$(cnt "partial — 3/4 clients cooperative" "$L")
RETIRE=$(cnt "Phase B — partial retirement of factory" "$L")
CLOSED=$(cnt "LSP rotate: factory [0-9]+ closed:|rotation close [0-9a-f]{64} recorded" "$L")
COMPLETE=$(cnt "LSP rotate: rotation complete" "$L")
SIGNED=$(cnt "LSP rotate: factory [0-9]+ created and signed over" "$L")
FUNDS=$(grep -aoE "LSP rotate: funded [0-9]+ sats, txid: [0-9a-f]{64}" "$L" | grep -oE "[0-9a-f]{64}" | sort -u | grep -c . || true)
OLD_TXID=$(grep -aoE "^LSP: funded [0-9]+ sats, txid: [0-9a-f]{64}" "$L" | grep -oE "[0-9a-f]{64}" | head -1)
OLD_VOUT=$(grep -aoE "^LSP: funding vout=[0-9]+" "$L" | grep -oE "[0-9]+$" | head -1)
OLD_UNSPENT=0
if [ -n "$OLD_TXID" ] && [ -n "$($BCLI gettxout "$OLD_TXID" "${OLD_VOUT:-0}" 2>/dev/null)" ]; then OLD_UNSPENT=1; fi

echo
echo "=== partial: partial=$PARTIAL retire=$RETIRE closed=$CLOSED fund_total=$FUNDS signed=$SIGNED complete=$COMPLETE old_funding_unspent=$OLD_UNSPENT ==="
if [ "$PARTIAL" -ge 1 ] && [ "$RETIRE" -ge 1 ] && [ "$CLOSED" -eq 0 ] && [ "$FUNDS" -eq 1 ] \
   && [ "$SIGNED" -ge 1 ] && [ "$COMPLETE" -ge 1 ] && [ "$OLD_UNSPENT" -eq 1 ]; then
  echo "PARTIAL-PASS: 3/4 clients rotated into a signed replacement over one funding; the old factory was retired, not closed (its funding $OLD_TXID:${OLD_VOUT:-0} is unspent)."
  exit 0
fi
echo "PARTIAL-FAIL: want partial>=1 retire>=1 closed=0 fund_total=1 signed>=1 complete>=1 old_funding_unspent=1"
exit 1
