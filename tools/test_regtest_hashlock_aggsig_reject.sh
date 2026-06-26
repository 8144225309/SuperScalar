#!/usr/bin/env bash
# test_regtest_hashlock_aggsig_reject.sh — #53 / trustless-completion P1.
# Adversarial drill proving the NEGATIVE of the N-party poison agg-sig verify:
# a MALICIOUS LSP (SS_CHEAT_BAD_POISON_AGGSIG) ships a corrupted poison agg-sig in
# SUBFACTORY_DONE; the sub client's verify-before-trust (D2) must REJECT it and
# persist NO worthless recourse row.  (Honest path is the sibling e2e test.)
#
# Asserts:
#   1. LSP logged the cheat (shipped a corrupted agg-sig).
#   2. EVERY participating client logged the D2 verify rejection.
#   3. NO client persisted an l_stock_poison_reveals row WITH a secret (the
#      client refused to record neutered recourse).
set -euo pipefail
BUILD_DIR="${1:-/root/SuperScalar/build}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"; CLIENT_BIN="$BUILD_DIR/superscalar_client"
N_CLIENTS="${N_CLIENTS:-4}"; PS_SUB_ARITY="${PS_SUB_ARITY:-2}"; AMOUNT="${AMOUNT:-400000}"
LSP_PORT=29959
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=(
  0000000000000000000000000000000000000000000000000000000000000002
  0000000000000000000000000000000000000000000000000000000000000003
  0000000000000000000000000000000000000000000000000000000000000004
  0000000000000000000000000000000000000000000000000000000000000005
  0000000000000000000000000000000000000000000000000000000000000006
  0000000000000000000000000000000000000000000000000000000000000007
  0000000000000000000000000000000000000000000000000000000000000008
  0000000000000000000000000000000000000000000000000000000000000009 )
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
[ -f "$REGTEST_CONF" ] || REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"
. "$(dirname "$(realpath "$0")")"/regtest_test_helpers.sh
ASAN_ENV="ASAN_OPTIONS=detect_leaks=0"
ldd "$LSP_BIN" 2>/dev/null | grep -q libasan && ASAN_ENV="ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8"
TMPDIR=$(mktemp -d /tmp/ss-aggsig-reject.XXXXXX); LSP_DB="$TMPDIR/lsp.db"; LSP_LOG="$TMPDIR/lsp.log"; WT_DB="$TMPDIR/wt.db"
MINER_WALLET="ss_cheat_leaf_miner"
PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null||true; done; cp "$LSP_LOG" /tmp/aggsig_reject_lsp.log 2>/dev/null||true; rm -rf "$TMPDIR"; }
trap cleanup EXIT

echo "=== HASHLOCK AGG-SIG REJECTION DRILL (regtest, P1) ==="
$BCLI getblockchaininfo >/dev/null 2>&1 || { bitcoind -regtest -conf="$REGTEST_CONF" -daemon; for i in $(seq 1 30); do sleep 1; $BCLI getblockchaininfo >/dev/null 2>&1 && break; done; }
$BCLI -named createwallet wallet_name=$MINER_WALLET load_on_startup=false 2>&1 | head -1 || true
$BCLI loadwallet $MINER_WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$MINER_WALLET -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null

echo "--- LSP (--enable-hashlock-poison --cheat-daemon-sub + SS_CHEAT_BAD_POISON_AGGSIG=1) ---"
env $ASAN_ENV SS_CHEAT_BAD_POISON_AGGSIG=1 "$LSP_BIN" \
    --network regtest --port $LSP_PORT --clients $N_CLIENTS --arity 3 --ps-subfactory-arity $PS_SUB_ARITY \
    --amount $AMOUNT --fee-rate 1000 --confirm-timeout 600 --step-blocks 1 \
    --seckey "$LSP_SECKEY" --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet $MINER_WALLET --db "$LSP_DB" --wt-db "$WT_DB" --cli-path "$(which bitcoin-cli)" \
    --enable-hashlock-poison --demo --cheat-daemon-sub --lsp-balance-pct 50 > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 60); do sleep 1; grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && break; kill -0 $LSP_PID 2>/dev/null || { echo "FAIL: LSP died"; tail -20 "$LSP_LOG"; exit 1; }; done

for i in $(seq 0 $((N_CLIENTS-1))); do
  env $ASAN_ENV "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $LSP_PORT \
      --seckey "${CLIENT_SECKEYS[$i]}" --fee-rate 1000 --lsp-pubkey "$LSP_PUBKEY" --participant-id $((i+1)) --daemon \
      --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} --wallet $MINER_WALLET \
      --cli-path "$(which bitcoin-cli)" --db "$TMPDIR/client_${i}.db" > "$TMPDIR/client_${i}.log" 2>&1 &
  PIDS+=($!); sleep 0.5
done
( while kill -0 $LSP_PID 2>/dev/null; do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 2; done ) &
PIDS+=($!)

echo "--- waiting for the sub advance (CHEAT DAEMON COMPLETE, timeout 420s) ---"
for i in $(seq 1 210); do sleep 2; grep -q "CHEAT DAEMON COMPLETE" "$LSP_LOG" 2>/dev/null && { echo "  advance complete"; break; }; kill -0 $LSP_PID 2>/dev/null || break; done
grep -q "CHEAT DAEMON COMPLETE" "$LSP_LOG" || { echo "FAIL: advance never completed"; tail -40 "$LSP_LOG"; exit 1; }

for p in "${PIDS[@]:-}"; do kill -TERM "$p" 2>/dev/null||true; done; sleep 3

echo "=== ASSERTIONS ==="
grep -q "SS_CHEAT_BAD_POISON_AGGSIG: shipping a CORRUPTED" "$LSP_LOG" || { echo "FAIL: LSP cheat did not fire (agg-sig not corrupted)"; exit 1; }
echo "  [1/3] LSP shipped a corrupted agg-sig"
REJECTS=0
for i in $(seq 0 $((N_CLIENTS-1))); do
  grep -q "LSP-supplied sub poison agg-sig FAILED verify" "$TMPDIR/client_${i}.log" 2>/dev/null && REJECTS=$((REJECTS+1))
done
[ "$REJECTS" -ge 1 ] || { echo "FAIL: NO client logged the D2 agg-sig rejection"; exit 1; }
echo "  [2/3] $REJECTS client(s) rejected the corrupted agg-sig (D2 verify)"
ROWS=0
for i in $(seq 0 $((N_CLIENTS-1))); do
  r=$(sqlite3 "$TMPDIR/client_${i}.db" "SELECT count(*) FROM l_stock_poison_reveals WHERE revocation_secret IS NOT NULL;" 2>/dev/null || echo 0)
  ROWS=$((ROWS + ${r:-0}))
done
[ "$ROWS" -eq 0 ] || { echo "FAIL: a client persisted $ROWS worthless reveal row(s) despite the bad agg-sig"; exit 1; }
echo "  [3/3] 0 worthless reveal rows persisted (recourse correctly refused)"
echo "=== PASS: malicious-LSP corrupted agg-sig is REJECTED; no neutered recourse persisted ==="
exit 0
