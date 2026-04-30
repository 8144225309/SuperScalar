#!/usr/bin/env bash
# test_multiprocess_tier_b_rollover.sh — multi-process Tier B (Gap B + F)
#
# Spawns 1 LSP daemon + N client daemons (separate OS processes) and drives
# enough multi-party leaf advances to exhaust the per-leaf DW counter.  The
# (states_per_layer + 1)-th call to lsp_advance_leaf returns rc=-1 inside,
# which triggers lsp_run_state_advance() — the Tier B whole-tree re-sign
# ceremony added in PR #122 Phase 2.
#
# This is the multi-process counterpart to the in-process unit test
# test_factory_tier_b_state_advance_root_rollover (tests/test_factory.c).
# That test proves cryptographic + state-machine correctness in a single
# process holding all keypairs; this test proves the wire transport
# composes end-to-end across separate OS processes that each hold only
# their own keypair.
#
# Why arity-1 (DW leaves): PS leaves advance via the chain mechanism and
# never trigger rc=-1 / root rollover.  Only DW leaves can exhaust their
# per-leaf counter and force a whole-tree re-sign ceremony.
#
# Why states_per_layer=2: minimum-cost rollover.  After 2 successful
# per-leaf advances, the 3rd hits rc=-1 → Tier B fires.  Larger values
# work but cost more wall-clock time (each advance is a 2-RTT ceremony).
#
# Usage: bash tools/test_multiprocess_tier_b_rollover.sh [BUILD_DIR]
#
# BUILD_DIR defaults to /root/SuperScalar/build (matches VPS layout).

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

# 1 LSP + 4 clients = 5 distinct processes participating in the MuSig
# ceremony.  We use 4 (not 7) to keep the binary tree shape small —
# arity-1 DW with N=4 produces a tighter tree and fewer affected nodes
# during the Tier B re-sign, which is faster to verify.
N_CLIENTS="${N_CLIENTS:-4}"
STATES_PER_LAYER="${STATES_PER_LAYER:-2}"

FUNDING_SATS=400000          # 80k per signer at N=5
LSP_PORT=29947               # different from N=8 test (29945) so they can coexist
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

TMPDIR=$(mktemp -d /tmp/ss-tier-b.XXXXXX)
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
    cp "$LSP_LOG" /tmp/tier_b_last_lsp.log 2>/dev/null || true
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        cp "$TMPDIR/client_${i}.log" "/tmp/tier_b_last_client_${i}.log" 2>/dev/null || true
    done
    rm -rf "$TMPDIR"
    echo "  Preserved logs:"
    echo "    /tmp/tier_b_last_lsp.log"
    echo "    /tmp/tier_b_last_client_{0..$((N_CLIENTS - 1))}.log"
}
trap cleanup EXIT

echo "=== Multi-process Tier B state-advance rollover (regtest) ==="
echo "  build dir         : $BUILD_DIR"
echo "  tmp dir           : $TMPDIR"
echo "  N clients         : $N_CLIENTS  (1 LSP + $N_CLIENTS clients = $((N_CLIENTS + 1)) procs)"
echo "  states_per_layer  : $STATES_PER_LAYER"
echo "  funding           : $FUNDING_SATS sats"
echo "  bitcoind          : $REGTEST_CONF"
echo ""
echo "  Test will drive $((STATES_PER_LAYER + 1)) leaf-0 advances over the wire."
echo "  The last advance triggers rc=-1 in factory_advance_leaf_unsigned,"
echo "  which calls lsp_run_state_advance() to drive the Tier B ceremony."

# --- Sanity ---
for bin in "$LSP_BIN" "$CLIENT_BIN"; do
    if [ ! -x "$bin" ]; then
        echo "FAIL: missing binary $bin"
        exit 1
    fi
done

# --- bitcoind regtest reset ---
echo ""
echo "--- bitcoind regtest (full chain reset for fresh subsidy) ---"

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
WALLET_NAME="ss_tier_b_miner"
$BCLI createwallet "$WALLET_NAME" 2>/dev/null || $BCLI loadwallet "$WALLET_NAME" 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet="$WALLET_NAME" getnewaddress)
echo "  miner wallet ready"

# --- LSP daemon ---
echo ""
echo "--- LSP daemon (--demo --test-tier-b-rollover --force-close) ---"

stdbuf -oL "$LSP_BIN" \
    --network regtest \
    --port "$LSP_PORT" \
    --seckey "$LSP_SECKEY" \
    --clients "$N_CLIENTS" \
    --arity 1 \
    --states "$STATES_PER_LAYER" \
    --amount "$FUNDING_SATS" \
    --step-blocks 1 \
    --demo \
    --test-tier-b-rollover \
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
echo "--- Waiting for Tier B ceremony to complete (timeout 600s) ---"
WAITED=0
LSP_EXIT=""
while [ "$WAITED" -lt 600 ]; do
    if ! kill -0 "$LSP_PID" 2>/dev/null; then
        wait "$LSP_PID" 2>/dev/null || true
        LSP_EXIT=$?
        break
    fi
    if [ $((WAITED % 20)) -eq 0 ]; then
        TIER_B_PROGRESS=$(grep -c "running Tier B state-advance ceremony\|state advance complete" "$LSP_LOG" 2>/dev/null || echo 0)
        echo "  ... ${WAITED}s elapsed, Tier B markers in LSP log: $TIER_B_PROGRESS"
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
    echo ""
    echo "=== LSP log tail (120 lines) ==="
    tail -120 "$LSP_LOG"
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        echo ""
        echo "=== client[$i] log tail (40 lines) ==="
        tail -40 "$TMPDIR/client_${i}.log" 2>/dev/null || true
    done
    exit 1
fi

# --- Tier B markers ---
echo ""
echo "=== Verifying Tier B ceremony fired and completed ==="

if ! grep -q "TIER B STATE-ADVANCE ROLLOVER TEST" "$LSP_LOG"; then
    echo "FAIL: LSP log missing TIER B test header"
    tail -60 "$LSP_LOG"
    exit 1
fi
echo "  test header present"

if ! grep -q "running Tier B state-advance ceremony" "$LSP_LOG"; then
    echo "FAIL: rc=-1 / Tier B ceremony was never invoked — root rollover did not fire"
    echo ""
    echo "=== LSP log tail (80 lines) ==="
    tail -80 "$LSP_LOG"
    exit 1
fi
echo "  Tier B ceremony invoked (rc=-1 fired)"

if ! grep -q "state advance complete" "$LSP_LOG"; then
    echo "FAIL: state advance did not complete"
    echo ""
    echo "=== LSP log tail (80 lines) ==="
    tail -80 "$LSP_LOG"
    exit 1
fi
SA_LINE=$(grep "state advance complete" "$LSP_LOG" | head -1)
echo "  $SA_LINE"

if ! grep -q "TIER B ROLLOVER TEST: PASS" "$LSP_LOG"; then
    echo "FAIL: TIER B ROLLOVER TEST did not PASS"
    grep -E "TIER B|FAIL|epoch" "$LSP_LOG" | head -20
    exit 1
fi
echo "  TIER B ROLLOVER TEST: PASS"

# --- Per-client participation ---
echo ""
echo "=== Verifying clients participated in Tier B ceremony ==="
PARTICIPATED=0
for i in $(seq 0 $((N_CLIENTS - 1))); do
    LOG="$TMPDIR/client_${i}.log"
    if grep -q "state advance complete" "$LOG" 2>/dev/null; then
        PARTICIPATED=$((PARTICIPATED + 1))
        SA=$(grep "state advance complete" "$LOG" | head -1)
        echo "  client[$i]: participated — $SA"
    else
        echo "  client[$i]: NO 'state advance complete' marker"
    fi
done

if [ "$PARTICIPATED" -lt 1 ]; then
    echo "FAIL: no clients logged Tier B completion"
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        echo ""
        echo "=== client[$i] log tail (40 lines) ==="
        tail -40 "$TMPDIR/client_${i}.log" 2>/dev/null || true
    done
    exit 1
fi
echo ""
echo "  $PARTICIPATED / $N_CLIENTS clients logged Tier B completion"

echo ""
echo "=== PASS: Multi-process Tier B state-advance rollover ==="
echo "  - $((N_CLIENTS + 1)) distinct OS processes"
echo "  - $((STATES_PER_LAYER + 1)) leaf-0 advances driven over wire"
echo "  - rc=-1 root rollover triggered Tier B ceremony"
echo "  - All affected nodes re-signed for new epoch via MSG_PATH_*"
echo "  - $PARTICIPATED / $N_CLIENTS clients confirmed completion"
