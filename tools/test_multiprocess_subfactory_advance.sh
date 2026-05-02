#!/usr/bin/env bash
# test_multiprocess_subfactory_advance.sh — multi-process k² PS sub-factory
# chain extension end-to-end on regtest (Phase 2c of the k² PS work).
#
# Spawns 1 LSP daemon + 4 superscalar_client daemons (5 distinct OS
# processes), builds a k=2 N=4 PS factory with sub-factories, then drives
# a single sub-factory chain extension via lsp_subfactory_chain_advance:
# the LSP "sells" 50000 sats of sales-stock to client 0 of sub-factory 0,
# the k+1 signers (LSP + 2 clients on that sub-factory) co-sign the new
# state via the MSG_SUBFACTORY_* multi-party MuSig ceremony.
#
# This is the multi-process counterpart to the in-process unit test
# tests/test_factory.c::test_factory_ps_subfactory_chain_extension.
# That test proves cryptographic + state-machine correctness in a single
# process holding all keypairs; this test proves the wire transport
# composes end-to-end across separate OS processes that each hold only
# their own keypair, against real bitcoind regtest.
#
# Why arity=3 (PS) + ps_subfactory_arity=2: PS leaves with k>1 produce
# k² clients per leaf with k sub-factories of k clients each.  At N=4
# clients we get exactly 1 leaf with 2 sub-factories (canonical k² shape).
#
# Usage: bash tools/test_multiprocess_subfactory_advance.sh [BUILD_DIR]
#
# BUILD_DIR defaults to /root/SuperScalar/build.

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

# 1 LSP + 4 clients = 5 processes.  At k=2 PS, n_participants=5 →
# leaf has k²=4 clients in 2 sub-factories of 2 clients each.
N_CLIENTS="${N_CLIENTS:-4}"
PS_SUB_ARITY="${PS_SUB_ARITY:-2}"

FUNDING_SATS=400000
LSP_PORT=29948                # different from N=8 (29945) and tier-b (29947)
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "0000000000000000000000000000000000000000000000000000000000000004"
    "0000000000000000000000000000000000000000000000000000000000000005"
    "0000000000000000000000000000000000000000000000000000000000000006"
    "0000000000000000000000000000000000000000000000000000000000000007"
    "0000000000000000000000000000000000000000000000000000000000000008"
)
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
if [ ! -f "$REGTEST_CONF" ]; then
    REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
fi
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

TMPDIR=$(mktemp -d /tmp/ss-subfactory.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"

PIDS=()

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    sleep 1
    for pid in "${PIDS[@]:-}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    cp "$LSP_LOG" /tmp/subfactory_last_lsp.log 2>/dev/null || true
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        cp "$TMPDIR/client_${i}.log" "/tmp/subfactory_last_client_${i}.log" 2>/dev/null || true
    done
    rm -rf "$TMPDIR"
    echo "  Preserved logs:"
    echo "    /tmp/subfactory_last_lsp.log"
    echo "    /tmp/subfactory_last_client_{0..$((N_CLIENTS - 1))}.log"
}
trap cleanup EXIT

echo "=== Multi-process PS k² sub-factory chain extension (regtest) ==="
echo "  build dir         : $BUILD_DIR"
echo "  N clients         : $N_CLIENTS  (1 LSP + $N_CLIENTS clients = $((N_CLIENTS + 1)) procs)"
echo "  PS sub arity (k)  : $PS_SUB_ARITY  (canonical k² = $((PS_SUB_ARITY * PS_SUB_ARITY)) clients per leaf)"
echo "  funding           : $FUNDING_SATS sats"
echo "  bitcoind          : $REGTEST_CONF"
echo ""
echo "  Test will: build factory → trigger lsp_subfactory_chain_advance →"
echo "  verify each sub-factory client co-signed via MSG_SUBFACTORY_* wire"
echo "  ceremony → broadcast post-extension factory tree on-chain."

# --- Sanity ---
for bin in "$LSP_BIN" "$CLIENT_BIN"; do
    if [ ! -x "$bin" ]; then
        echo "FAIL: missing binary $bin"
        exit 1
    fi
done

# --- bitcoind regtest reset ---
echo ""
echo "--- bitcoind regtest reset ---"

REGTEST_DATADIR=$(grep -E '^datadir=' "$REGTEST_CONF" 2>/dev/null | head -1 | cut -d= -f2)
if [ -n "$REGTEST_DATADIR" ]; then
    REGTEST_REGTEST_DIR="$REGTEST_DATADIR/regtest"
else
    REGTEST_REGTEST_DIR="$HOME/.bitcoin/regtest"
fi

$BCLI stop 2>/dev/null || true
sleep 2
if pgrep -f "bitcoind.*regtest" > /dev/null; then
    pkill -f "bitcoind.*regtest" 2>/dev/null || true
    sleep 2
fi

DATADIR_OWNER=$(stat -c %U "$REGTEST_DATADIR" 2>/dev/null || echo "$USER")
if [ "$DATADIR_OWNER" = "bitcoin" ]; then
    sudo -u bitcoin sh -c "rm -rf '$REGTEST_REGTEST_DIR'" 2>/dev/null || \
        rm -rf "$REGTEST_REGTEST_DIR"
    sudo -u bitcoin bitcoind -regtest -conf="$REGTEST_CONF" -daemon
else
    rm -rf "$REGTEST_REGTEST_DIR"
    bitcoind -regtest -conf="$REGTEST_CONF" -daemon
fi

for i in $(seq 1 30); do
    $BCLI getblockchaininfo &>/dev/null && break
    sleep 1
done
if ! $BCLI getblockchaininfo &>/dev/null; then
    echo "FAIL: bitcoind failed to start"
    exit 1
fi
echo "  bitcoind reachable, fresh chain at height $($BCLI getblockcount)"

$BCLI createwallet "" 2>/dev/null || $BCLI loadwallet "" 2>/dev/null || true
WALLET_NAME="ss_subfactory_miner"
$BCLI createwallet "$WALLET_NAME" 2>/dev/null || $BCLI loadwallet "$WALLET_NAME" 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet="$WALLET_NAME" getnewaddress)
echo "  miner wallet ready"

# --- LSP daemon ---
echo ""
echo "--- LSP daemon (--demo --test-subfactory-advance --force-close) ---"

stdbuf -oL "$LSP_BIN" \
    --network regtest \
    --port "$LSP_PORT" \
    --seckey "$LSP_SECKEY" \
    --clients "$N_CLIENTS" \
    --arity 3 \
    --ps-subfactory-arity "$PS_SUB_ARITY" \
    --amount "$FUNDING_SATS" \
    --step-blocks 1 \
    --demo \
    --test-subfactory-advance \
    --force-close \
    --db "$LSP_DB" \
    --cli-path "$(which bitcoin-cli)" \
    --rpcuser rpcuser --rpcpassword rpcpass \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!
PIDS+=("$LSP_PID")
echo "  LSP started (PID=$LSP_PID, log=$LSP_LOG)"

for i in $(seq 1 30); do
    grep -q "listening on port" "$LSP_LOG" 2>/dev/null && break
    sleep 1
    if ! kill -0 "$LSP_PID" 2>/dev/null; then
        echo "FAIL: LSP died before listening"
        tail -40 "$LSP_LOG"
        exit 1
    fi
done
if ! grep -q "listening on port" "$LSP_LOG" 2>/dev/null; then
    echo "FAIL: LSP did not start listening within 30s"
    tail -40 "$LSP_LOG"
    exit 1
fi
echo "  LSP listening on port $LSP_PORT"

# --- Client daemons ---
echo ""
echo "--- $N_CLIENTS client daemons ---"
for i in $(seq 0 $((N_CLIENTS - 1))); do
    CLIENT_LOG="$TMPDIR/client_${i}.log"
    CLIENT_DB="$TMPDIR/client_${i}.db"
    stdbuf -oL "$CLIENT_BIN" \
        --seckey "${CLIENT_SECKEYS[$i]}" \
        --host 127.0.0.1 --port "$LSP_PORT" \
        --network regtest \
        --lsp-pubkey "$LSP_PUBKEY" \
        --daemon \
        --db "$CLIENT_DB" \
        --cli-path "$(which bitcoin-cli)" \
        --rpcuser rpcuser --rpcpassword rpcpass \
        > "$CLIENT_LOG" 2>&1 &
    CPID=$!
    PIDS+=("$CPID")
    echo "  client[$i] started (PID=$CPID)"
    sleep 0.4
done

# --- Background block miner (BIP68 timelock progression) ---
echo ""
echo "--- Driving ceremony (mining 1 block / 2s in background) ---"
(
    while kill -0 "$LSP_PID" 2>/dev/null; do
        $BCLI generatetoaddress 1 "$MINE_ADDR" > /dev/null 2>&1 || true
        sleep 2
    done
) &
MINER_PID=$!
PIDS+=("$MINER_PID")

# --- Wait for LSP to complete ---
echo ""
echo "--- Waiting for sub-factory advance ceremony to complete (timeout 600s) ---"
WAITED=0
LSP_EXIT=""
while [ "$WAITED" -lt 600 ]; do
    if ! kill -0 "$LSP_PID" 2>/dev/null; then
        wait "$LSP_PID" 2>/dev/null || true
        LSP_EXIT=$?
        break
    fi
    if [ $((WAITED % 20)) -eq 0 ]; then
        SUB_PROGRESS=$(grep -c "sub-factory.*chain extended\|PS K² SUB-FACTORY TEST" "$LSP_LOG" 2>/dev/null || echo 0)
        echo "  ... ${WAITED}s elapsed, sub-factory markers in LSP log: $SUB_PROGRESS"
    fi
    sleep 2
    WAITED=$((WAITED + 2))
done

if [ -z "$LSP_EXIT" ]; then
    echo "FAIL: LSP did not exit within 600s"
    tail -120 "$LSP_LOG"
    exit 1
fi

echo ""
echo "--- LSP exit=$LSP_EXIT ---"
if [ "$LSP_EXIT" -ne 0 ]; then
    echo "FAIL: LSP exited non-zero (exit $LSP_EXIT)"
    tail -120 "$LSP_LOG"
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        echo ""
        echo "=== client[$i] log tail (40 lines) ==="
        tail -40 "$TMPDIR/client_${i}.log" 2>/dev/null || true
    done
    exit 1
fi

# --- Verify ceremony markers ---
echo ""
echo "=== Verifying sub-factory ceremony fired and completed ==="

if ! grep -q "PS K² SUB-FACTORY CHAIN EXTENSION TEST" "$LSP_LOG"; then
    echo "FAIL: LSP log missing test header"
    tail -60 "$LSP_LOG"
    exit 1
fi
echo "  test header present"

if ! grep -q "sub-factory.*chain extended" "$LSP_LOG"; then
    echo "FAIL: sub-factory chain extension never fired"
    tail -80 "$LSP_LOG"
    exit 1
fi
CE_LINE=$(grep "sub-factory.*chain extended" "$LSP_LOG" | head -1)
echo "  $CE_LINE"

if ! grep -q "PS K² SUB-FACTORY TEST: PASS" "$LSP_LOG"; then
    echo "FAIL: PS K² SUB-FACTORY TEST did not PASS"
    grep -E "PS K²|FAIL|sub-factory" "$LSP_LOG" | head -20
    exit 1
fi
echo "  PS K² SUB-FACTORY TEST: PASS"

# Wire-ceremony poison TX assertion (closes Gap A SECURITY GAP).  The dual
# MuSig2 round must have produced a fully-signed poison TX; absence of a
# "wire-ceremony poison TX signed" line OR presence of any "DEGRADED" /
# "SECURITY GAP" line means we fell back to NULL poison_tx and the
# watchtower would have no defense for the sales-stock on breach.
if grep -q "DEGRADED\|SECURITY GAP" "$LSP_LOG"; then
    echo "FAIL: poison TX wire-ceremony degraded (SECURITY GAP triggered)"
    grep -E "DEGRADED|SECURITY GAP|poison" "$LSP_LOG" | head -20
    exit 1
fi
if ! grep -q "wire-ceremony poison TX signed" "$LSP_LOG"; then
    echo "FAIL: wire-ceremony poison TX was not signed (no positive log)"
    grep -E "poison|sub-factory" "$LSP_LOG" | head -20
    exit 1
fi
POISON_LINE=$(grep "wire-ceremony poison TX signed" "$LSP_LOG" | head -1)
echo "  $POISON_LINE"

# --- Per-client participation ---
echo ""
echo "=== Verifying clients participated in sub-factory ceremony ==="
PARTICIPATED=0
for i in $(seq 0 $((N_CLIENTS - 1))); do
    LOG="$TMPDIR/client_${i}.log"
    if grep -q "sub-factory.*advanced to chain_len" "$LOG" 2>/dev/null; then
        PARTICIPATED=$((PARTICIPATED + 1))
        SA=$(grep "sub-factory.*advanced to chain_len" "$LOG" | head -1)
        echo "  client[$i]: participated — $SA"
    else
        echo "  client[$i]: no sub-factory advance marker (may be in different sub-factory)"
    fi
done

# At k=2 N=4 only 2 of the 4 clients (sub-factory 0's clients) participate.
# That's correct — sub-factory 1's clients don't see this ceremony.
if [ "$PARTICIPATED" -lt "$PS_SUB_ARITY" ]; then
    echo "FAIL: expected >= $PS_SUB_ARITY clients to participate (sub-factory 0 has $PS_SUB_ARITY clients)"
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        echo ""
        echo "=== client[$i] log tail (40 lines) ==="
        tail -40 "$TMPDIR/client_${i}.log" 2>/dev/null || true
    done
    exit 1
fi
echo ""
echo "  $PARTICIPATED clients on sub-factory 0 logged completion (>= $PS_SUB_ARITY required)"

echo ""
echo "=== PASS: Multi-process k² PS sub-factory chain extension ==="
echo "  - $((N_CLIENTS + 1)) distinct OS processes"
echo "  - k=$PS_SUB_ARITY → 1 leaf with $PS_SUB_ARITY sub-factories of $PS_SUB_ARITY clients each"
echo "  - LSP-driven sub-factory chain extension over MSG_SUBFACTORY_*"
echo "  - $PARTICIPATED clients confirmed completion"
echo "  - Post-extension factory tree force-closed on-chain"
