#!/usr/bin/env bash
#
# Phase 5 runner — Shape 3e (N=4 ARITY=3 PS_SUBFACTORY_ARITY=2)
#
# Env vars:
#   WALLET    bitcoind testnet4 wallet to fund factory (default superscalar_test)
#   TAG       /tmp prefix (default phase5_3e_V1) — must differ per variant
#   VARIANT   V1 | V2 | V3 | V4 (default V1) — selects --demo flags
#   RESUME    1 = preserve LSP/client DBs; 0 = wipe (default 0)
#   PORT      LSP listen port (default 9950)
#   AMOUNT    sats per channel (default 1000000)
#   FEE_RATE  sat/kvB (default 1000)
#   BUILD_DIR (default /root/SuperScalar/build-release)

# NOTE: no setsid self-respawn. Phase 5 runners launch via `systemd-run --unit=...`
# which already provides session/scope isolation (immune to systemd-logind kills
# on SSH session end). setsid here detaches from systemd-run and makes the unit
# deactivate immediately, losing journal capture.

set -euo pipefail

# Refuse to run if another LSP is already on our port (avoid the foot-gun where
# a second invocation pkills the first one's LSP).
if pgrep -f "superscalar_lsp.*--port ${PORT:-9950}" >/dev/null 2>&1; then
    echo "REFUSE: another superscalar_lsp is on port ${PORT:-9950}." >&2
    echo "        pkill it manually if it is stale, or set PORT=<other> for this run." >&2
    exit 3
fi

# shellcheck source=../../../tools/test_diag_lib.sh
source "$(dirname "$0")/../../../tools/test_diag_lib.sh"

VARIANT="${VARIANT:-V1}"
TAG="${TAG:-phase5_3e_${VARIANT}}"
WALLET="${WALLET:-superscalar_test}"
RESUME="${RESUME:-0}"
PORT="${PORT:-9950}"
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

# --- variant → LSP flag set ---
case "$VARIANT" in
    V1) DEMO_FLAGS="--demo" ;;
    V2) DEMO_FLAGS="--demo --force-close" ;;
    V3) DEMO_FLAGS="--demo --test-ps-advance" ;;
    V4) DEMO_FLAGS="--demo --test-subfactory-advance" ;;
    *)  echo "FAIL: unknown VARIANT=$VARIANT (V1|V2|V3|V4)" >&2; exit 2 ;;
esac

if [ "$RESUME" -ne 1 ]; then
    rm -f "$LSP_DB" "$LSP_DB"-shm "$LSP_DB"-wal "$LSP_LOG" "$DONE" "$EVIDENCE"
    for n in 2 3 4 5; do
        SK=$(printf '%064x' "$n")
        rm -f "/tmp/ss_t4_${TAG}_c${SK:60:4}.db"* "/tmp/ss_t4_${TAG}_c${SK:60:4}.log"
    done
fi

diag_setup "ss_t4_${TAG}"
diag_enable_core_dumps

# --- incremental evidence ---
emit() { printf '%s\n' "$*" >> "$EVIDENCE"; }
emit "# Shape 3e $VARIANT — incremental evidence"
emit "Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
emit "Wallet:  $WALLET"
emit "Tag:     $TAG"
emit "Variant: $VARIANT"
emit "Binary:  $LSP_BIN  ($(stat -c %y "$LSP_BIN" 2>/dev/null | head -1))"
emit "Commit:  $(cd /root/SuperScalar && git rev-parse HEAD 2>/dev/null)"
emit ""

echo "=== Phase 5 Shape 3e $VARIANT ==="
echo "  wallet  : $WALLET"
echo "  tag     : $TAG"
echo "  port    : $PORT"
echo "  N       : 4 clients (k²=4 via 2 sub-factories of 2 clients)"
echo "  amount  : $AMOUNT sats/channel"
echo "  variant : $VARIANT ($DEMO_FLAGS)"
echo "  resume  : $RESUME"

pkill -9 -f "superscalar_(lsp|client|watchtower).*--port $PORT" 2>/dev/null || true

# --- launch LSP ---
nohup "$LSP_BIN" \
    --network "$NETWORK" --port "$PORT" \
    --clients 4 --arity 3 --ps-subfactory-arity 2 \
    --amount "$AMOUNT" --fee-rate "$FEE_RATE" \
    --active-blocks 50 --dying-blocks 20 \
    --step-blocks 5 --states-per-layer 2 \
    --confirm-timeout 86400 \
    --seckey "$LSP_SECKEY" \
    --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
    --wallet "$WALLET" --db "$LSP_DB" \
    $DEMO_FLAGS \
    > "$LSP_LOG" 2> "$(diag_stderr_path lsp)" &
LSP_PID=$!
emit "LSP pid: $LSP_PID  cmd: $LSP_BIN --port $PORT --clients 4 --arity 3 --ps-subfactory-arity 2 $DEMO_FLAGS"
diag_periodic "$LSP_PID" 60

# --- wait for listen ---
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

# --- launch watchtower (always — V5 needs it, others record entries harmlessly) ---
nohup "$WT_BIN" \
    --network "$NETWORK" \
    --db "$LSP_DB" \
    --poll-interval 30 \
    --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
    > "/tmp/ss_t4_${TAG}_wt.log" 2> "$(diag_stderr_path wt)" &
WT_PID=$!
emit "WT  pid: $WT_PID"
sleep 2

# --- launch 4 clients with sequential seckeys 0x02..0x05 ---
for n in 1 2 3 4; do
    SK=$(printf '%064x' $((n + 1)))   # 0x02 .. 0x05
    nohup "$CLIENT_BIN" \
        --network "$NETWORK" --host 127.0.0.1 --port "$PORT" --daemon \
        --seckey "$SK" --fee-rate "$FEE_RATE" --lsp-balance-pct 50 \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id "$n" \
        --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
        --wallet "$WALLET" --db "/tmp/ss_t4_${TAG}_c${SK:60:4}.db" \
        > "/tmp/ss_t4_${TAG}_c${SK:60:4}.log" 2> "$(diag_stderr_path client${n})" &
    emit "client$n pid=$! seckey=${SK:60:4}.."
    sleep 0.3
done

# --- wait for LSP to exit ---
diag_wait_lsp "$LSP_PID" "$LSP_LOG" "ss_t4_${TAG}"
EXIT=$DIAG_EXIT

# --- harvest on-chain evidence from log ---
emit ""
emit "## On-chain events"
emit "| Event | TXID | grep marker |"
emit "|---|---|---|"
grep -oE "factory funding.* txid=[a-f0-9]+" "$LSP_LOG" | head -1 | sed 's/.*txid=/| funding | /; s/$/ | /' >> "$EVIDENCE" || true
grep -oE "tree_node_[0-9]+ broadcast OK.*txid=[a-f0-9]+" "$LSP_LOG" | sed 's/.*tree_node_/| tree_node_/; s/.broadcast OK.*txid=/ | /; s/$/ | /' >> "$EVIDENCE" || true
grep -oE "subfactory.* chain_len=[0-9]+.*txid=[a-f0-9]+" "$LSP_LOG" | sed 's/^/| subfactory | /; s/$/ | /' >> "$EVIDENCE" || true
grep -oE "FORCE CLOSE.*txid=[a-f0-9]+" "$LSP_LOG" | sed 's/^/| force-close | /; s/$/ | /' >> "$EVIDENCE" || true

# --- harvest log assertions ---
emit ""
emit "## Log assertions"
for marker in "shape ewt =" "PS sub-factory" "MSG_SUBFACTORY_DONE" "persist: ps_subfactory_chain" "TEST PASSED" "TEST FAILED"; do
    HIT=$(grep -E "$marker" "$LSP_LOG" | head -1 || true)
    [ -n "$HIT" ] && emit "- \`$marker\`: $HIT"
done

emit ""
emit "## Completion"
emit "Ended:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
emit "Outcome: $([ "$EXIT" -eq 0 ] && echo PASS || echo "FAIL exit=$EXIT")"

pkill -f "superscalar_client.*--port $PORT" 2>/dev/null || true
pkill -f "superscalar_watchtower.*$LSP_DB" 2>/dev/null || true

echo "EXIT=$EXIT" > "$DONE"
echo "evidence: $EVIDENCE"
cat "$EVIDENCE"
exit $EXIT
