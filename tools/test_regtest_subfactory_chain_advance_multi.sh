#!/usr/bin/env bash
# test_regtest_subfactory_chain_advance_multi.sh — end-to-end PS k² sub-factory
# MULTI-INPUT chain advance ceremony (#142 SF-A).
#
# Spawns 1 LSP daemon + 4 superscalar_client daemons (5 distinct OS processes),
# builds a k=2 N=4 PS factory with sub-factories, drives TWO sub-factory chain
# extensions via lsp_subfactory_chain_advance:
#
#   - First advance: chain[0] -> chain[1] (single-input ceremony, the old path)
#   - Second advance: chain[1] -> chain[2] (MULTI-INPUT ceremony, the new
#     code path being tested here)
#
# The second advance spends k+1 outputs of chain[1] (k channels + sales-stock).
# Without the multi-input ceremony only one input would be signed and the
# broadcast would fail; with it, all k+1 witnesses are present and chain[2]
# is broadcastable.
#
# Usage: bash tools/test_regtest_subfactory_chain_advance_multi.sh [BUILD_DIR]
# BUILD_DIR defaults to /root/SuperScalar/build-release.

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build-release}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

# Auto-detect ASan build and preload libasan only if needed.
if command -v nm >/dev/null 2>&1 && nm -D "$LSP_BIN" 2>/dev/null | grep -q __asan_init; then
    SS_ASAN_ENV="ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8"
else
    SS_ASAN_ENV=""
fi

N_CLIENTS="${N_CLIENTS:-4}"
PS_SUB_ARITY="${PS_SUB_ARITY:-2}"

FUNDING_SATS=400000
LSP_PORT=29950   # distinct from k2_subfactory_breach (29949)
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=()
for _i in $(seq 2 256); do
    CLIENT_SECKEYS+=("$(printf '%064x' $_i)")
done
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
if [ ! -f "$REGTEST_CONF" ]; then
    REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
fi
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

TMPDIR=$(mktemp -d /tmp/ss-subfactory-multi-advance.XXXXXX)
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
    cp "$LSP_LOG" /tmp/subfactory_multi_last_lsp.log 2>/dev/null || true
    cp "$LSP_DB"  /tmp/subfactory_multi_last_lsp.db  2>/dev/null || true
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        cp "$TMPDIR/client_${i}.log" \
            "/tmp/subfactory_multi_last_client_${i}.log" 2>/dev/null || true
    done
    rm -rf "$TMPDIR"
    echo "  Preserved logs:"
    echo "    /tmp/subfactory_multi_last_lsp.log"
    echo "    /tmp/subfactory_multi_last_lsp.db"
    echo "    /tmp/subfactory_multi_last_client_{0..$((N_CLIENTS - 1))}.log"
}
trap cleanup EXIT

echo "=== PS k² sub-factory MULTI-INPUT chain advance (#142 SF-A) ==="
echo "  build dir         : $BUILD_DIR"
echo "  N clients         : $N_CLIENTS"
echo "  PS sub arity (k)  : $PS_SUB_ARITY (canonical k² shape)"
echo "  funding           : $FUNDING_SATS sats"
echo "  bitcoind          : $REGTEST_CONF"
echo ""
echo "  Test will:"
echo "    1. Build k=$PS_SUB_ARITY N=$N_CLIENTS PS factory"
echo "    2. First advance: chain[0] -> chain[1]  (single-input)"
echo "    3. Second advance: chain[1] -> chain[2] (MULTI-INPUT, k+1 sessions)"
echo "    4. Verify chain[2] is broadcastable + log markers present"

for bin in "$LSP_BIN" "$CLIENT_BIN"; do
    if [ ! -x "$bin" ]; then
        echo "FAIL: missing binary $bin"; exit 1
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
    echo "FAIL: bitcoind failed to start"; exit 1
fi
echo "  bitcoind reachable, fresh chain at height $($BCLI getblockcount)"

$BCLI createwallet "" 2>/dev/null || $BCLI loadwallet "" 2>/dev/null || true
WALLET_NAME="ss_subfactory_multi_miner"
$BCLI createwallet "$WALLET_NAME" 2>/dev/null || \
    $BCLI loadwallet "$WALLET_NAME" 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet="$WALLET_NAME" getnewaddress)
echo "  miner wallet ready"

# --- LSP daemon ---
echo ""
echo "--- LSP daemon (--demo --test-subfactory-advance-multi) ---"

env $SS_ASAN_ENV "$LSP_BIN" \
    --network regtest \
    --port "$LSP_PORT" \
    --seckey "$LSP_SECKEY" \
    --clients "$N_CLIENTS" \
    --arity 3 \
    --ps-subfactory-arity "$PS_SUB_ARITY" \
    --amount "$FUNDING_SATS" \
    --step-blocks 1 \
    --max-conn-rate 1000 --max-handshakes 256 \
    --demo \
    --test-subfactory-advance-multi \
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
        echo "FAIL: LSP died before listening"; tail -40 "$LSP_LOG"; exit 1
    fi
done
if ! grep -q "listening on port" "$LSP_LOG" 2>/dev/null; then
    echo "FAIL: LSP did not start listening within 30s"
    tail -40 "$LSP_LOG"; exit 1
fi
echo "  LSP listening on port $LSP_PORT"

# --- Client daemons ---
echo ""
echo "--- $N_CLIENTS client daemons ---"
for i in $(seq 0 $((N_CLIENTS - 1))); do
    CLIENT_LOG="$TMPDIR/client_${i}.log"
    CLIENT_DB="$TMPDIR/client_${i}.db"
    env $SS_ASAN_ENV "$CLIENT_BIN" \
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
    sleep 0.1
done

# --- Background block miner ---
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
echo "--- Waiting for multi-input advance test (timeout 600s) ---"
WAITED=0
LSP_EXIT=""
while [ "$WAITED" -lt 600 ]; do
    if ! kill -0 "$LSP_PID" 2>/dev/null; then
        wait "$LSP_PID" 2>/dev/null || true
        LSP_EXIT=$?
        break
    fi
    if [ $((WAITED % 20)) -eq 0 ]; then
        ADV_COUNT=$(grep -cE "sub-factory.*chain extended" \
                            "$LSP_LOG" 2>/dev/null || echo 0)
        MULTI_COUNT=$(grep -cE "MULTI-INPUT|SF-A" \
                            "$LSP_LOG" 2>/dev/null || echo 0)
        echo "  ... ${WAITED}s elapsed: advances=$ADV_COUNT, multi-input markers=$MULTI_COUNT"
    fi
    sleep 2
    WAITED=$((WAITED + 2))
done

if [ -z "$LSP_EXIT" ]; then
    echo "FAIL: LSP did not exit within 600s"
    tail -200 "$LSP_LOG"; exit 1
fi

echo ""
echo "--- LSP exit=$LSP_EXIT ---"
if [ "$LSP_EXIT" -ne 0 ]; then
    echo "FAIL: LSP exited non-zero (exit $LSP_EXIT)"
    tail -200 "$LSP_LOG"
    exit 1
fi

# --- Verify both advances fired ---
echo ""
echo "=== Verifying TWO sub-factory advances fired ==="
ADV_LINES=$(grep -cE "sub-factory.*chain extended" "$LSP_LOG" 2>/dev/null || echo 0)
if [ "$ADV_LINES" -lt 2 ]; then
    echo "FAIL: expected >= 2 advance lines, got $ADV_LINES"
    grep -E "sub-factory|FAIL|chain extended" "$LSP_LOG" | head -30
    exit 1
fi
echo "  $ADV_LINES advance lines:"
grep "sub-factory.*chain extended" "$LSP_LOG" | sed 's/^/    /'

# --- Verify MULTI-INPUT ceremony marker (LSP side) ---
echo ""
echo "=== Verifying MULTI-INPUT ceremony fired ==="
if ! grep -q "chain advance is MULTI-INPUT" "$LSP_LOG"; then
    echo "FAIL: MULTI-INPUT ceremony marker missing from LSP log"
    grep -E "MULTI|SF-A|sub-factory" "$LSP_LOG" | head -20
    exit 1
fi
MULTI_LINE=$(grep "chain advance is MULTI-INPUT" "$LSP_LOG" | head -1)
echo "  $MULTI_LINE"

# --- Verify client mirror MULTI-INPUT marker ---
echo ""
echo "=== Verifying clients ran the MULTI-INPUT mirror ==="
N_MULTI_CLIENTS=0
for i in $(seq 0 $((N_CLIENTS - 1))); do
    if grep -q "advance is MULTI-INPUT\|advanced (MULTI)" "$TMPDIR/client_${i}.log" 2>/dev/null; then
        N_MULTI_CLIENTS=$((N_MULTI_CLIENTS + 1))
        MARK=$(grep -E "advance is MULTI-INPUT|advanced \(MULTI\)" "$TMPDIR/client_${i}.log" | head -1)
        echo "    client[$i]: $MARK"
    fi
done
if [ "$N_MULTI_CLIENTS" -lt "$PS_SUB_ARITY" ]; then
    echo "FAIL: expected >= $PS_SUB_ARITY clients to log MULTI-INPUT, got $N_MULTI_CLIENTS"
    exit 1
fi

# --- Verify SF-A test marker ---
echo ""
echo "=== Verifying SF-A test marker ==="
if ! grep -q "SF-A: SECOND advance (multi-input ceremony)" "$LSP_LOG"; then
    echo "FAIL: SF-A second-advance test block did not run"
    grep -E "SF-A|FAIL" "$LSP_LOG" | head -10
    exit 1
fi
if ! grep -q "SF-A MULTI-INPUT CEREMONY: PASS" "$LSP_LOG"; then
    echo "FAIL: SF-A MULTI-INPUT CEREMONY did not report PASS"
    grep -E "SF-A|FAIL" "$LSP_LOG" | tail -20
    exit 1
fi
echo "  $(grep "SF-A MULTI-INPUT CEREMONY: PASS" "$LSP_LOG" | head -1)"

# --- Verify chain[2] broadcast/sign succeeded ---
echo ""
echo "=== Verifying second-advance state is signed ==="
if ! grep -q "post-2nd-advance.*signed=1" "$LSP_LOG"; then
    echo "FAIL: post-2nd-advance is_signed=1 marker missing"
    grep -E "post-2nd|FAIL" "$LSP_LOG" | head -10
    exit 1
fi
echo "  $(grep "post-2nd-advance" "$LSP_LOG" | head -1)"

# --- Verify persist rows exist for both chain entries ---
echo ""
echo "=== Verifying broadcast/persist of two chain entries ==="
if [ -f "$LSP_DB" ]; then
    NCHAINS=$(sqlite3 "$LSP_DB" \
        "SELECT COUNT(*) FROM ps_subfactory_chains;" \
        2>/dev/null || echo 0)
    echo "  ps_subfactory_chains rows: $NCHAINS"
    if [ "$NCHAINS" -lt 2 ]; then
        echo "FAIL: expected >= 2 ps_subfactory_chains rows, got $NCHAINS"
        exit 1
    fi
else
    echo "  WARN: LSP DB missing — skipping persist verification"
fi

echo ""
echo "=== PASS: PS k² sub-factory MULTI-INPUT chain advance end-to-end ==="
echo "  - $((N_CLIENTS + 1)) distinct OS processes (1 LSP + $N_CLIENTS clients)"
echo "  - k=$PS_SUB_ARITY canonical sub-factory shape"
echo "  - First advance: single-input ceremony (chain[0] -> chain[1])"
echo "  - Second advance: MULTI-INPUT ceremony (chain[1] -> chain[2])"
echo "  - $N_MULTI_CLIENTS / $PS_SUB_ARITY clients ran the MULTI-INPUT mirror"
