#!/usr/bin/env bash
# Phase 5 runner — Shape 3f (N=64 ARITY=2,4 PS_SUBFACTORY_ARITY=2 STATIC_NEAR_ROOT=1)
# ALL FEATURES INTEGRATION TEST

# No setsid self-respawn — launch via `systemd-run --unit=...` for session isolation.

set -euo pipefail

if pgrep -f "superscalar_lsp.*--port ${PORT:-9954}" >/dev/null 2>&1; then
    echo "REFUSE: another superscalar_lsp is on port ${PORT:-9954}." >&2
    exit 3
fi
# shellcheck source=../../../tools/test_diag_lib.sh
source "$(dirname "$0")/../../../tools/test_diag_lib.sh"

VARIANT="${VARIANT:-V1}"
TAG="${TAG:-phase5_3f_${VARIANT}}"
WALLET="${WALLET:-superscalar_test}"
RESUME="${RESUME:-0}"
PORT="${PORT:-9954}"
AMOUNT="${AMOUNT:-1000000}"
FEE_RATE="${FEE_RATE:-1000}"
BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
WT_BIN="$BUILD_DIR/superscalar_watchtower"

NETWORK="testnet4"
RPCUSER="${RPCUSER:-testnet4rpc}"
RPCPASS="${RPCPASS:-testnet4rpcpass123}"
RPCPORT="${RPCPORT:-48332}"

LSP_DB="/tmp/ss_t4_${TAG}.db"
LSP_LOG="/tmp/ss_t4_${TAG}_lsp.log"
DONE="/tmp/ss_t4_${TAG}.done"
EVIDENCE="/tmp/ss_t4_${TAG}.evidence.md"
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"

case "$VARIANT" in
    V1) DEMO_FLAGS="--demo" ;;
    V2) DEMO_FLAGS="--demo --force-close" ;;
    V3) DEMO_FLAGS="--demo --test-ps-advance" ;;
    V4) DEMO_FLAGS="--demo --test-subfactory-advance" ;;
    V5) DEMO_FLAGS="--demo --breach-test" ;;
    V6) DEMO_FLAGS="--demo --force-close" ;;  # operator kills LSP mid-flight externally
    *)  echo "FAIL: unknown VARIANT=$VARIANT (V1..V6)" >&2; exit 2 ;;
esac

if [ "$RESUME" -ne 1 ]; then
    rm -f "$LSP_DB" "$LSP_DB"-shm "$LSP_DB"-wal "$LSP_LOG" "$DONE" "$EVIDENCE"
    for n in $(seq 2 65); do
        SK=$(printf '%064x' "$n")
        rm -f "/tmp/ss_t4_${TAG}_c${SK:60:4}.db"* "/tmp/ss_t4_${TAG}_c${SK:60:4}.log"
    done
fi

diag_setup "ss_t4_${TAG}"
diag_enable_core_dumps

emit() { printf '%s\n' "$*" >> "$EVIDENCE"; }
emit "# Shape 3f $VARIANT — incremental evidence"
emit "Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)  Wallet: $WALLET  Tag: $TAG  Variant: $VARIANT"
emit "Commit:  $(cd /root/SuperScalar && git rev-parse HEAD 2>/dev/null)"
emit ""

echo "=== Phase 5 Shape 3f $VARIANT (N=64 ARITY=2,4 k²=4 STATIC_NEAR_ROOT=1) ==="

pkill -9 -f "superscalar_(lsp|client|watchtower).*--port $PORT" 2>/dev/null || true

nohup "$LSP_BIN" \
    --network "$NETWORK" --port "$PORT" \
    --clients 64 --arity 2,4 --ps-subfactory-arity 2 --static-near-root 1 \
    --amount "$AMOUNT" --fee-rate "$FEE_RATE" \
    --active-blocks 50 --dying-blocks 20 \
    --step-blocks 5 --states-per-layer 2 \
    --confirm-timeout 86400 \
    --max-conn-rate 400 --max-handshakes 80 \
    --seckey "$LSP_SECKEY" \
    --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
    --wallet "$WALLET" --db "$LSP_DB" \
    $DEMO_FLAGS \
    > "$LSP_LOG" 2> "$(diag_stderr_path lsp)" &
LSP_PID=$!
emit "LSP pid: $LSP_PID"
diag_periodic "$LSP_PID" 60

for _ in $(seq 1 60); do
    sleep 1
    grep -q "listening on port $PORT" "$LSP_LOG" 2>/dev/null && break
    if ! kill -0 "$LSP_PID" 2>/dev/null; then
        emit "FAIL: LSP died before listen"
        tail -30 "$LSP_LOG" >> "$EVIDENCE"
        echo "EXIT=1" > "$DONE"
        exit 1
    fi
done
emit "LSP listening: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

nohup "$WT_BIN" --network "$NETWORK" --db "$LSP_DB" --poll-interval 30 \
    --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
    > "/tmp/ss_t4_${TAG}_wt.log" 2> "$(diag_stderr_path wt)" &
emit "WT  pid: $!"
sleep 2

for n in $(seq 1 64); do
    SK=$(printf '%064x' $((n + 1)))
    nohup "$CLIENT_BIN" \
        --network "$NETWORK" --host 127.0.0.1 --port "$PORT" --daemon \
        --seckey "$SK" --fee-rate "$FEE_RATE" --lsp-balance-pct 50 \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id "$n" \
        --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
        --wallet "$WALLET" --db "/tmp/ss_t4_${TAG}_c${SK:60:4}.db" \
        > "/tmp/ss_t4_${TAG}_c${SK:60:4}.log" 2> "$(diag_stderr_path client${n})" &
    sleep 0.2
done

diag_wait_lsp "$LSP_PID" "$LSP_LOG" "ss_t4_${TAG}"
EXIT=$DIAG_EXIT

diag_emit_onchain_events "$LSP_DB" "$LSP_LOG" "$EVIDENCE"
emit "## Log assertions"
for m in "shape ewt =" "static-near-root" "k²=" "sub-factory" "MSG_SUBFACTORY_DONE" "persist: ps_subfactory_chain" "watchtower: registered subfactory" "TEST PASSED" "TEST FAILED"; do
    H=$(grep -E "$m" "$LSP_LOG" | head -1 || true)
    [ -n "$H" ] && emit "- $m: $H"
done
emit ""
emit "Ended: $(date -u +%Y-%m-%dT%H:%M:%SZ)  Outcome: $([ "$EXIT" -eq 0 ] && echo PASS || echo FAIL)"

pkill -f "superscalar_client.*--port $PORT" 2>/dev/null || true
pkill -f "superscalar_watchtower.*$LSP_DB" 2>/dev/null || true
echo "EXIT=$EXIT" > "$DONE"
cat "$EVIDENCE"
exit $EXIT
