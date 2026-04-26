#!/usr/bin/env bash
# test_multiprocess_musig_n8.sh — Phase 3 item #4 — multi-process MuSig at N=8
#
# Spawns 1 LSP daemon + 7 superscalar_client daemons (8 distinct OS processes,
# each with its own keyfile + DB), and exercises a real wire-protocol MuSig
# ceremony to build + sign + broadcast a SuperScalar arity-3 (PS) factory tree
# with N=8 signers.
#
# This is the multi-process counterpart to the in-process N=8 tests in
# tests/test_close_spendability_full.c (phase 3 item #1).  The point is to
# prove the wire protocol and ceremony actually round-trip across distinct
# processes, not just inside one binary holding all 8 keypairs.
#
# Approach: Option A (new shell script).  Reuses the LSP --demo --force-close
# flow which: connects N clients via TCP, runs the MuSig ceremony for the
# whole factory tree, broadcasts every node on regtest, and exits 0 on
# success.  We add per-client log assertions so the test fails loudly if any
# of the 8 processes failed to participate.
#
# Usage: bash tools/test_multiprocess_musig_n8.sh [BUILD_DIR]
#
# BUILD_DIR defaults to /root/SuperScalar/build (matches VPS layout).

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

# 1 LSP + 7 clients = 8 distinct processes participating in the MuSig ceremony.
N_CLIENTS=7
ARITY=3                     # PS (arity-3)
FUNDING_SATS=800000         # 100k per signer at N=8
LSP_PORT=29945
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
# Deterministic per-client seckeys 0x02..0x08 (7 clients).
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "0000000000000000000000000000000000000000000000000000000000000004"
    "0000000000000000000000000000000000000000000000000000000000000005"
    "0000000000000000000000000000000000000000000000000000000000000006"
    "0000000000000000000000000000000000000000000000000000000000000007"
    "0000000000000000000000000000000000000000000000000000000000000008"
)
# secp256k1 G xonly = client 1's pubkey when seckey=0x01.
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

# Bitcoin regtest layout.  Match the VPS conf used by phase 2 #5
# (test_bridge_econ_regtest.sh) — RPC port 18443, user rpcuser/rpcpass.
REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
if [ ! -f "$REGTEST_CONF" ]; then
    # Fallback to home-dir layout (used by tools/test_bridge_regtest.sh).
    REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
fi
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

TMPDIR=$(mktemp -d /tmp/ss-mp-musig-n8.XXXXXX)
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
    # Preserve key logs at /tmp before nuking TMPDIR.
    cp "$LSP_LOG" /tmp/mp_musig_n8_last_lsp.log 2>/dev/null || true
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        cp "$TMPDIR/client_${i}.log" "/tmp/mp_musig_n8_last_client_${i}.log" 2>/dev/null || true
    done
    rm -rf "$TMPDIR"
    echo "  Preserved logs:"
    echo "    /tmp/mp_musig_n8_last_lsp.log"
    echo "    /tmp/mp_musig_n8_last_client_{0..$((N_CLIENTS - 1))}.log"
}
trap cleanup EXIT

echo "=== Phase 3 #4: Multi-process MuSig at N=8 (regtest) ==="
echo "  build dir : $BUILD_DIR"
echo "  tmp dir   : $TMPDIR"
echo "  N clients : $N_CLIENTS  (1 LSP daemon + $N_CLIENTS client daemons = 8 procs)"
echo "  arity     : $ARITY (PS)"
echo "  funding   : $FUNDING_SATS sats"
echo "  bitcoind  : $REGTEST_CONF"

# --- Sanity ---
for bin in "$LSP_BIN" "$CLIENT_BIN"; do
    if [ ! -x "$bin" ]; then
        echo "FAIL: missing binary $bin"
        echo "       build first: cmake -S '$PROJECT_DIR' -B '$BUILD_DIR' && make -C '$BUILD_DIR' -j"
        exit 1
    fi
done

# --- bitcoind regtest ---
echo ""
echo "--- bitcoind regtest (full chain reset for fresh subsidy) ---"

# Resolve datadir from conf so the reset works regardless of layout.
REGTEST_DATADIR=$(grep -E '^datadir=' "$REGTEST_CONF" 2>/dev/null | head -1 | cut -d= -f2)
if [ -n "$REGTEST_DATADIR" ]; then
    REGTEST_REGTEST_DIR="$REGTEST_DATADIR/regtest"
else
    REGTEST_REGTEST_DIR="$HOME/.bitcoin/regtest"
fi

# Try graceful shutdown, fall back to pkill.
$BCLI stop 2>/dev/null || true
sleep 2
if pgrep -f "bitcoind.*regtest" > /dev/null; then
    pkill -f "bitcoind.*regtest" 2>/dev/null || true
    sleep 2
fi

# Reset chain (fresh subsidy).  Need bitcoin uid if the datadir is owned by it.
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
    echo "FAIL: bitcoind failed to start (check $REGTEST_CONF)"
    exit 1
fi
echo "  bitcoind reachable, fresh chain at height $($BCLI getblockcount)"

# LSP uses the DEFAULT wallet (no -rpcwallet=) on regtest for funding +
# mining.  After chain reset, the default wallet doesn't exist yet; create
# it.  The LSP itself will mine 101 blocks to a fresh address it generates,
# which gives it ~50 BTC of mature subsidy on a fresh regtest chain (block
# subsidy halves every 150 blocks, so the first 150 are 50 BTC each).
$BCLI createwallet "" 2>/dev/null || $BCLI loadwallet "" 2>/dev/null || true
DEFAULT_BAL=$($BCLI -rpcwallet="" getbalance 2>/dev/null || echo "0")
echo "  default wallet ready (balance=$DEFAULT_BAL BTC) — LSP will mine its own subsidy"

# We still need a separate wallet for the heartbeat miner that pumps blocks
# during the ceremony (BIP68 timelock progression).
WALLET_NAME="ss_mp_n8_miner"
$BCLI createwallet "$WALLET_NAME" 2>/dev/null || $BCLI loadwallet "$WALLET_NAME" 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet="$WALLET_NAME" getnewaddress)
echo "  miner wallet ready (mine_addr=${MINE_ADDR:0:18}...)"

# --- LSP daemon (process #1) ---
echo ""
echo "--- LSP daemon (--demo --force-close, $N_CLIENTS clients, arity-$ARITY) ---"

stdbuf -oL "$LSP_BIN" \
    --network regtest \
    --port "$LSP_PORT" \
    --seckey "$LSP_SECKEY" \
    --clients "$N_CLIENTS" \
    --arity "$ARITY" \
    --amount "$FUNDING_SATS" \
    --step-blocks 1 \
    --demo \
    --force-close \
    --db "$LSP_DB" \
    --cli-path "$(which bitcoin-cli)" \
    --rpcuser rpcuser --rpcpassword rpcpass \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!
PIDS+=("$LSP_PID")
echo "  LSP started (PID=$LSP_PID, log=$LSP_LOG)"

# Wait for LSP to listen before clients connect.
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

# --- 7 client daemons (processes #2..#8) ---
echo ""
echo "--- $N_CLIENTS client daemons (each its own keypair + DB) ---"
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
    echo "  client[$i] started (PID=$CPID, sk=...${CLIENT_SECKEYS[$i]: -4}, db=$CLIENT_DB)"
    sleep 0.4
done

# --- Drive the ceremony ---
# The LSP --demo flow needs blocks mined while it's working (funding tx
# confirmation, then BIP68 timelocks during force-close tree broadcast).
# Mine a block every 2 seconds in the background; bail when LSP exits.
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

# --- Wait for LSP to complete (factory build, sign, broadcast, force-close) ---
echo ""
echo "--- Waiting for force-close ceremony to complete (timeout 600s) ---"
WAITED=0
LSP_EXIT=""
while [ "$WAITED" -lt 600 ]; do
    if ! kill -0 "$LSP_PID" 2>/dev/null; then
        wait "$LSP_PID" 2>/dev/null || true
        LSP_EXIT=$?
        break
    fi
    # Heartbeat.
    if [ $((WAITED % 20)) -eq 0 ]; then
        BCAST_COUNT=$(sqlite3 "$LSP_DB" \
            "SELECT COUNT(*) FROM broadcast_log WHERE source LIKE 'tree_node_%';" \
            2>/dev/null || echo 0)
        echo "  ... ${WAITED}s elapsed, tree nodes broadcast so far: $BCAST_COUNT"
    fi
    sleep 2
    WAITED=$((WAITED + 2))
done

if [ -z "$LSP_EXIT" ]; then
    echo "FAIL: LSP did not exit within 600s — likely hung in MuSig ceremony or BIP68 wait"
    tail -80 "$LSP_LOG"
    exit 1
fi

echo ""
echo "--- LSP exit=$LSP_EXIT ---"
if [ "$LSP_EXIT" -ne 0 ]; then
    echo "FAIL: LSP --demo --force-close failed (exit $LSP_EXIT)"
    echo ""
    echo "=== LSP log tail (80 lines) ==="
    tail -80 "$LSP_LOG"
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        echo ""
        echo "=== client[$i] log tail (20 lines) ==="
        tail -20 "$TMPDIR/client_${i}.log" 2>/dev/null || true
    done
    exit 1
fi

# --- Per-process participation assertions ---
echo ""
echo "=== Verifying all $N_CLIENTS client processes participated ==="

PARTICIPATED=0
MISSING_CLIENTS=()
for i in $(seq 0 $((N_CLIENTS - 1))); do
    LOG="$TMPDIR/client_${i}.log"
    # Each client logs "persisted factory + channel + basepoints to DB" once
    # the MuSig ceremony for the factory completes successfully on its side.
    if grep -q "persisted factory + channel + basepoints to DB" "$LOG"; then
        PARTICIPATED=$((PARTICIPATED + 1))
        # Pull the client's index as the LSP saw it (helpful for debugging).
        IDX=$(grep -oE "Client [0-9]+: persisted factory" "$LOG" | head -1 | \
              awk '{print $2}' | tr -d ':' || echo "?")
        echo "  client[$i]: participated (index=$IDX)"
    else
        MISSING_CLIENTS+=("$i")
        echo "  client[$i]: NO PARTICIPATION FOUND in log"
    fi
done

if [ "$PARTICIPATED" -ne "$N_CLIENTS" ]; then
    echo ""
    echo "FAIL: only $PARTICIPATED / $N_CLIENTS clients participated in the ceremony"
    echo "      missing client indices: ${MISSING_CLIENTS[*]}"
    for i in "${MISSING_CLIENTS[@]}"; do
        echo ""
        echo "=== client[$i] log tail (40 lines) ==="
        tail -40 "$TMPDIR/client_${i}.log" 2>/dev/null || true
    done
    exit 1
fi
echo ""
echo "  ALL $N_CLIENTS clients participated in the MuSig ceremony"
echo "  Total processes: 8 (1 LSP daemon + $N_CLIENTS client daemons)"

# --- Tree broadcast assertions (LSP DB) ---
echo ""
echo "=== Verifying factory tree broadcast (LSP DB) ==="
TREE_NODE_COUNT=$(sqlite3 "$LSP_DB" \
    "SELECT COUNT(DISTINCT source) FROM broadcast_log WHERE source LIKE 'tree_node_%' AND result='ok';" \
    2>/dev/null || echo 0)
TREE_NODE_TXIDS=$(sqlite3 "$LSP_DB" \
    "SELECT source, txid FROM broadcast_log WHERE source LIKE 'tree_node_%' AND result='ok' ORDER BY id;" \
    2>/dev/null || echo "")
echo "  tree nodes broadcast successfully: $TREE_NODE_COUNT"
echo "$TREE_NODE_TXIDS" | head -8 | while IFS='|' read -r src txid; do
    [ -n "$txid" ] && echo "    $src: ${txid:0:24}..."
done
[ "$TREE_NODE_COUNT" -gt 8 ] && echo "    ... ($((TREE_NODE_COUNT - 8)) more)"

if [ "$TREE_NODE_COUNT" -lt 1 ]; then
    echo "FAIL: no tree nodes in broadcast_log"
    exit 1
fi

# --- "FORCE CLOSE COMPLETE" marker in LSP log ---
echo ""
echo "=== Verifying LSP completion marker ==="
if ! grep -q "FORCE CLOSE COMPLETE" "$LSP_LOG"; then
    echo "FAIL: LSP log missing 'FORCE CLOSE COMPLETE' marker"
    tail -40 "$LSP_LOG"
    exit 1
fi
ALL_CONFIRMED=$(grep "All .* nodes confirmed on-chain" "$LSP_LOG" | tail -1)
echo "  $ALL_CONFIRMED"

# --- On-chain conservation check ---
echo ""
echo "=== On-chain conservation ==="
ROOT_TXID=$(sqlite3 "$LSP_DB" \
    "SELECT txid FROM broadcast_log WHERE source='tree_node_0' AND result='ok' ORDER BY id LIMIT 1;" \
    2>/dev/null || echo "")
if [ -n "$ROOT_TXID" ]; then
    ROOT_OUT_SUM=$($BCLI getrawtransaction "$ROOT_TXID" 1 2>/dev/null | \
        python3 -c "
import json, sys
try:
    tx = json.load(sys.stdin)
    print(int(sum(o['value'] for o in tx['vout']) * 1e8))
except Exception:
    print(0)" 2>/dev/null || echo 0)
    echo "  root tx ${ROOT_TXID:0:24}... output sum: $ROOT_OUT_SUM sats"
    echo "  funding_sats target               : $FUNDING_SATS sats"
    if [ "$ROOT_OUT_SUM" -gt 0 ] && [ "$ROOT_OUT_SUM" -le "$FUNDING_SATS" ]; then
        FEE=$((FUNDING_SATS - ROOT_OUT_SUM))
        echo "  root-level conservation: outputs ($ROOT_OUT_SUM) <= funding ($FUNDING_SATS) "
        echo "                           delta = $FEE sats (root-tx miner fee + dust margin)"
    else
        echo "  WARN: root_out_sum=$ROOT_OUT_SUM funding_sats=$FUNDING_SATS — check fee accounting"
    fi
else
    echo "  WARN: could not pull root txid from broadcast_log"
fi

echo ""
echo "=== PASS: Phase 3 #4 — multi-process MuSig at N=8 ==="
echo "  - 8 distinct OS processes (1 LSP daemon + $N_CLIENTS client daemons)"
echo "  - Real wire-protocol MuSig ceremony for arity-$ARITY (PS) factory"
echo "  - Factory tree built, signed by all $N_CLIENTS clients, broadcast on-chain"
echo "  - $TREE_NODE_COUNT tree nodes confirmed via real bitcoind regtest"
