#!/usr/bin/env bash
# test_regtest_realloc.sh — happy-path leaf-realloc on regtest.
#
# Validates --test-realloc end-to-end without any adversarial overlay:
#   1. LSP + 2 clients create a k=2 PS factory (arity=2)
#   2. LSP drives the leaf-realloc ceremony (lsp_realloc_leaf)
#   3. Test PASSES when "LEAF REALLOC TEST: PASS" lands in the LSP log
#      AND no breach_detections row appears (proves the run was honest)
#
# Why this exists alongside test_regtest_cheat_realloc.sh: the cheat
# variant exercises the happy path too (the cheat fires AFTER honest
# realloc completes), but it bundles the adversarial assertion in the
# PASS criterion.  This script is the diagnostic-clarity version —
# "is leaf realloc itself working" without cheat-engine noise.
#
# Mirrors the cheat-realloc setup (N=2, arity=2, funding 200k sats,
# port 29958 to stay distinct).  Uses build-release per memory
# feedback_asan_long_running.md — ASan binaries are unstable in
# >30min RPC polling and we don't need leak coverage here.
#
# Wall time: typically <60s.

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

N_CLIENTS=2
FUNDING_SATS=200000
LSP_PORT="${LSP_PORT:-29958}"   # distinct from 29957 (cheat-realloc)
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
)
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
[ -f "$REGTEST_CONF" ] || REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

TMPDIR=$(mktemp -d /tmp/ss-realloc.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"

PIDS=()

cleanup() {
    echo
    echo "=== Cleanup ==="
    for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
    # Scoped pkill per memory feedback_pkill_scope.md.
    pkill -9 -f "superscalar_(lsp|client).*--port $LSP_PORT" 2>/dev/null || true
    # Preserve artifacts for post-mortem.
    cp "$LSP_LOG" /tmp/realloc_last_lsp.log 2>/dev/null || true
    cp "$LSP_DB"  /tmp/realloc_last_lsp.db  2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

[ -x "$LSP_BIN" ]    || { echo "FAIL: $LSP_BIN not built"; exit 2; }
[ -x "$CLIENT_BIN" ] || { echo "FAIL: $CLIENT_BIN not built"; exit 2; }

if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
    echo "FAIL: bitcoind regtest not reachable via $REGTEST_CONF"
    exit 2
fi

# Wallet bootstrap.  Per memory feedback_regtest_faucet_exhausted.md,
# reuse the established miner wallet so we don't hit subsidy-zero blocks.
$BCLI -named createwallet wallet_name=ss_cheat_leaf_miner load_on_startup=false 2>&1 | head -1 || true
$BCLI loadwallet ss_cheat_leaf_miner >/dev/null 2>&1 || true
MINE_ADDR=$($BCLI -rpcwallet=ss_cheat_leaf_miner -named getnewaddress address_type=bech32m)
$BCLI -rpcwallet=ss_cheat_leaf_miner generatetoaddress 101 "$MINE_ADDR" >/dev/null 2>&1 || true

echo "=== Leaf realloc happy-path test ==="
echo "  build   : $BUILD_DIR"
echo "  port    : $LSP_PORT"
echo "  clients : $N_CLIENTS  arity=2  funding=$FUNDING_SATS sats"
echo "  tip     : $($BCLI getblockcount)"

# --- LSP ---
echo
echo "--- LSP daemon (--demo --test-realloc; NO cheat overlay) ---"
"$LSP_BIN" \
    --network regtest \
    --port "$LSP_PORT" \
    --clients "$N_CLIENTS" \
    --arity 2 \
    --amount "$FUNDING_SATS" \
    --fee-rate 1000 \
    --confirm-timeout 600 \
    --active-blocks 6 \
    --dying-blocks 4 \
    --step-blocks 1 \
    --states-per-layer 2 \
    --seckey "$LSP_SECKEY" \
    --rpcuser "${RPCUSER:-rpcuser}" \
    --rpcpassword "${RPCPASSWORD:-rpcpass}" \
    --wallet ss_cheat_leaf_miner \
    --db "$LSP_DB" \
    --demo --test-realloc \
    --lsp-balance-pct 50 \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!
PIDS+=($LSP_PID)

for i in $(seq 1 60); do
    sleep 1
    if grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null; then
        echo "  LSP listening (PID=$LSP_PID)"
        break
    fi
    if ! kill -0 $LSP_PID 2>/dev/null; then
        echo "FAIL: LSP died before listening"
        tail -20 "$LSP_LOG"
        exit 1
    fi
done

# --- Clients ---
echo "--- Starting $N_CLIENTS clients ---"
for i in $(seq 0 $((N_CLIENTS - 1))); do
    "$CLIENT_BIN" \
        --network regtest \
        --host 127.0.0.1 --port "$LSP_PORT" \
        --seckey "${CLIENT_SECKEYS[$i]}" \
        --fee-rate 1000 \
        --lsp-pubkey "$LSP_PUBKEY" \
        --participant-id $((i + 1)) \
        --daemon \
        --rpcuser "${RPCUSER:-rpcuser}" \
        --rpcpassword "${RPCPASSWORD:-rpcpass}" \
        --wallet ss_cheat_leaf_miner \
        --db "$TMPDIR/client_${i}.db" \
        > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!)
    sleep 0.3
done

# --- Background miner ---
(
    while kill -0 $LSP_PID 2>/dev/null; do
        $BCLI -rpcwallet=ss_cheat_leaf_miner generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1
        sleep 2
    done
) &
PIDS+=($!)

# --- Wait for verdict ---
echo
echo "--- Waiting for LEAF REALLOC TEST verdict (timeout 300s) ---"
VERDICT=""
for i in $(seq 1 150); do
    sleep 2
    if grep -qE "LEAF REALLOC TEST: (PASS|FAIL|SKIP)" "$LSP_LOG" 2>/dev/null; then
        VERDICT=$(grep -oE "LEAF REALLOC TEST: (PASS|FAIL|SKIP)" "$LSP_LOG" | tail -1)
        echo "  marker: $VERDICT  (after ${i}*2s = $((i*2))s)"
        break
    fi
    kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited at iter $i"; break; }
done

LSP_EXIT=0
wait $LSP_PID 2>/dev/null || LSP_EXIT=$?
echo "--- LSP exit=$LSP_EXIT ---"

# --- Honest-run invariants ---
echo
echo "=== Honest-run checks (no cheat overlay was set) ==="
BREACH_ROWS=$(sqlite3 "$LSP_DB" "SELECT count(*) FROM breach_detections;" 2>/dev/null || echo "?")
echo "  breach_detections rows : $BREACH_ROWS  (want 0 — no cheat fired)"
# Happy-path realloc mutates leaf state but does NOT broadcast — only
# force-close or the cheat variant produces a broadcast_log row.  Print
# this for diagnostic visibility; do not assert on it.
BCAST_REALLOC=$(sqlite3 "$LSP_DB" \
    "SELECT count(*) FROM broadcast_log WHERE source LIKE '%realloc%';" \
    2>/dev/null || echo "?")
echo "  broadcast_log realloc  : $BCAST_REALLOC  (informational; expect 0 on happy path)"

case "$VERDICT" in
    "LEAF REALLOC TEST: PASS")
        if [ "$BREACH_ROWS" = "0" ]; then
            echo
            echo "=== PASS: realloc happy path validated, no spurious breach ==="
            exit 0
        else
            echo "FAIL: PASS marker present but $BREACH_ROWS breach row(s) — should be 0"
            exit 1
        fi
        ;;
    "LEAF REALLOC TEST: SKIP")
        echo "FAIL: realloc was skipped — check arity/n_clients gate"
        exit 1
        ;;
    "LEAF REALLOC TEST: FAIL")
        echo "FAIL: realloc reported FAIL"
        tail -30 "$LSP_LOG"
        exit 1
        ;;
    *)
        echo "FAIL: no LEAF REALLOC verdict marker observed in 300s"
        tail -30 "$LSP_LOG"
        exit 1
        ;;
esac
