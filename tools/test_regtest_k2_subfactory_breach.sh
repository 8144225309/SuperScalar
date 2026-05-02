#!/usr/bin/env bash
# test_regtest_k2_subfactory_breach.sh — end-to-end PS k² sub-factory
# breach detection on regtest (Gap E test-followup, exercises Phase 4b
# watchtower coverage + Gap A poison TX builder).
#
# Spawns 1 LSP daemon + 4 superscalar_client daemons (5 distinct OS
# processes), builds a k=2 N=4 PS factory with sub-factories, drives a
# sub-factory chain extension via lsp_subfactory_chain_advance, then
# the LSP cheats by broadcasting the now-stale chain[N-1] sub-factory
# TX.  The LSP's own watchtower must detect the cheating and broadcast:
#   1. The latest signed chain[N] (response_tx)
#   2. The pre-signed poison TX (redistributes sales-stock to clients)
#
# This is the on-chain counterpart to test_subfactory_node_watch (which
# only exercises the watchtower entry registration in-memory) and the
# multi-process counterpart to test_factory_ps_subfactory_poison_tx_k2_n4
# (which only exercises the poison TX builder in-memory).
#
# Usage: bash tools/test_regtest_k2_subfactory_breach.sh [BUILD_DIR]
# BUILD_DIR defaults to /root/SuperScalar/build.

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

N_CLIENTS="${N_CLIENTS:-4}"
PS_SUB_ARITY="${PS_SUB_ARITY:-2}"

FUNDING_SATS=400000
LSP_PORT=29949                # different from existing tests (29945-29948)
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "0000000000000000000000000000000000000000000000000000000000000004"
    "0000000000000000000000000000000000000000000000000000000000000005"
)
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
if [ ! -f "$REGTEST_CONF" ]; then
    REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
fi
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

TMPDIR=$(mktemp -d /tmp/ss-subfactory-breach.XXXXXX)
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
    cp "$LSP_LOG" /tmp/subfactory_breach_last_lsp.log 2>/dev/null || true
    cp "$LSP_DB"  /tmp/subfactory_breach_last_lsp.db  2>/dev/null || true
    for i in $(seq 0 $((N_CLIENTS - 1))); do
        cp "$TMPDIR/client_${i}.log" \
            "/tmp/subfactory_breach_last_client_${i}.log" 2>/dev/null || true
    done
    rm -rf "$TMPDIR"
    echo "  Preserved logs:"
    echo "    /tmp/subfactory_breach_last_lsp.log"
    echo "    /tmp/subfactory_breach_last_lsp.db"
    echo "    /tmp/subfactory_breach_last_client_{0..$((N_CLIENTS - 1))}.log"
}
trap cleanup EXIT

echo "=== PS k² sub-factory BREACH DETECTION (regtest) ==="
echo "  build dir         : $BUILD_DIR"
echo "  N clients         : $N_CLIENTS"
echo "  PS sub arity (k)  : $PS_SUB_ARITY (canonical k² shape)"
echo "  funding           : $FUNDING_SATS sats"
echo "  bitcoind          : $REGTEST_CONF"
echo ""
echo "  Test will:"
echo "    1. Build k=$PS_SUB_ARITY N=$N_CLIENTS PS factory"
echo "    2. Advance sub-factory 0 chain (chain[0] -> chain[1])"
echo "    3. LSP broadcasts STALE chain[0] (cheating)"
echo "    4. Watchtower detects, broadcasts response_tx + poison_tx"
echo "    5. Verify both txs in broadcast_log + per-client P2TR outputs"

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
WALLET_NAME="ss_subfactory_breach_miner"
$BCLI createwallet "$WALLET_NAME" 2>/dev/null || \
    $BCLI loadwallet "$WALLET_NAME" 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet="$WALLET_NAME" getnewaddress)
echo "  miner wallet ready"

# --- LSP daemon ---
echo ""
echo "--- LSP daemon (--demo --cheat-subfactory) ---"

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
    --cheat-subfactory \
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
echo "--- Waiting for breach test to complete (timeout 600s) ---"
WAITED=0
LSP_EXIT=""
while [ "$WAITED" -lt 600 ]; do
    if ! kill -0 "$LSP_PID" 2>/dev/null; then
        wait "$LSP_PID" 2>/dev/null || true
        LSP_EXIT=$?
        break
    fi
    if [ $((WAITED % 20)) -eq 0 ]; then
        BREACH_PROGRESS=$(grep -cE "sub-factory.*chain extended|CHEAT-SUBFACTORY|SUB-FACTORY BREACH" \
                            "$LSP_LOG" 2>/dev/null || echo 0)
        echo "  ... ${WAITED}s elapsed, breach markers in LSP log: $BREACH_PROGRESS"
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

# --- Verify ceremony + breach detection markers ---
echo ""
echo "=== Verifying sub-factory advance fired ==="
if ! grep -q "sub-factory.*chain extended" "$LSP_LOG"; then
    echo "FAIL: sub-factory chain extension never fired"
    tail -120 "$LSP_LOG"; exit 1
fi
echo "  $(grep 'sub-factory.*chain extended' "$LSP_LOG" | head -1)"

echo ""
echo "=== Verifying CHEAT-SUBFACTORY broadcast ==="
if ! grep -q "CHEAT-SUBFACTORY" "$LSP_LOG"; then
    echo "FAIL: CHEAT-SUBFACTORY block did not run"
    grep -E "CHEAT|SUB-FACTORY|FAIL" "$LSP_LOG" | head -30
    exit 1
fi
if ! grep -q "Stale chain\[N-1\] broadcast:" "$LSP_LOG"; then
    echo "FAIL: stale chain[N-1] broadcast did not succeed"
    grep -E "CHEAT|stale|FAIL" "$LSP_LOG" | head -30
    exit 1
fi
STALE_LINE=$(grep "Stale chain\[N-1\] broadcast:" "$LSP_LOG" | head -1)
STALE_TXID=$(echo "$STALE_LINE" | awk '{print $NF}')
echo "  $STALE_LINE"

echo ""
echo "=== Verifying watchtower detected breach ==="
if ! grep -q "SUB-FACTORY BREACH DETECTED" "$LSP_LOG"; then
    echo "FAIL: watchtower did not detect sub-factory breach"
    grep -E "BREACH|stale|watchtower|SUB-FACTORY" "$LSP_LOG" | head -40
    exit 1
fi
DETECT_LINE=$(grep "SUB-FACTORY BREACH DETECTED" "$LSP_LOG" | head -1)
echo "  $DETECT_LINE"

echo ""
echo "=== Verifying poison TX broadcast ==="
# Note: in t/1242 the response_tx (chain[N]) and poison_tx both spend the
# same chain[N-1].sales-stock UTXO — they race, only one can win.  After
# chain[N-1] confirms (the cheat), chain[N] is INVALID (its parent input
# vanished), so response_tx broadcast attempts will fail with sendrawtransaction
# rejection.  The poison TX is the actual recourse mechanism: it
# distributes the now-orphaned sales-stock to clients pro-rata.
#
# This harness asserts only the poison TX broadcast.  The response_tx
# attempt is best-effort and its failure is expected (and logged in the
# LSP daemon as "Sub-factory response tx broadcast failed").  A future PR
# should remove the response_tx broadcast for WATCH_SUBFACTORY_NODE
# entries entirely — see watchtower.c:573-577 for the explanatory comment.
if ! grep -q "Sub-factory poison tx broadcast:" "$LSP_LOG"; then
    echo "FAIL: poison_tx was not broadcast by watchtower"
    grep -E "poison|broadcast|FAIL|BREACH|response" "$LSP_LOG" | head -40
    exit 1
fi
POISON_LINE=$(grep "Sub-factory poison tx broadcast:" "$LSP_LOG" | head -1)
POISON_TXID=$(echo "$POISON_LINE" | awk '{print $NF}')
echo "  $POISON_LINE"

# response_tx broadcast is informational only (expected to fail because its
# parent UTXO was just consumed by the cheat broadcast).
RESP_LINE=$(grep -E "Sub-factory response tx broadcast" "$LSP_LOG" | head -1)
echo "  response_tx attempt: ${RESP_LINE:-<not logged>}"

# --- Verify broadcast_log entries via SQLite ---
echo ""
echo "=== Verifying broadcast_log entries ==="
if [ -f "$LSP_DB" ]; then
    NREP=$(sqlite3 "$LSP_DB" \
        "SELECT COUNT(*) FROM broadcast_log WHERE source='subfactory_response';" \
        2>/dev/null || echo 0)
    NPOI=$(sqlite3 "$LSP_DB" \
        "SELECT COUNT(*) FROM broadcast_log WHERE source='subfactory_poison';" \
        2>/dev/null || echo 0)
    NCHEAT=$(sqlite3 "$LSP_DB" \
        "SELECT COUNT(*) FROM broadcast_log WHERE source='cheat_subfactory_stale';" \
        2>/dev/null || echo 0)
    echo "  broadcast_log rows: cheat=$NCHEAT response=$NREP poison=$NPOI"
    # response_tx may be 0 (broadcast attempt fails post-cheat by design — see
    # the response_tx-vs-poison comment above); poison + cheat are mandatory.
    if [ "$NPOI" -lt 1 ] || [ "$NCHEAT" -lt 1 ]; then
        echo "FAIL: missing broadcast_log entries (need cheat>=1 and poison>=1)"
        exit 1
    fi
else
    echo "  WARN: LSP DB missing — skipping persist log verification"
fi

# --- On-chain verification: poison TX must confirm ---
echo ""
echo "=== Verifying poison TX confirmed on chain ==="
$BCLI generatetoaddress 2 "$MINE_ADDR" > /dev/null 2>&1 || true
sleep 1
POISON_CONF=$($BCLI getrawtransaction "$POISON_TXID" 1 2>/dev/null | \
              python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('confirmations',0))" \
              2>/dev/null || echo 0)
echo "  poison TX $POISON_TXID confirmations: $POISON_CONF"
if [ "$POISON_CONF" -lt 1 ]; then
    echo "FAIL: poison TX did not confirm"
    exit 1
fi

# Verify poison TX has correct number of P2TR outputs (one per sub-factory client)
N_OUTPUTS=$($BCLI getrawtransaction "$POISON_TXID" 1 2>/dev/null | \
            python3 -c "import json,sys; d=json.load(sys.stdin); print(len([v for v in d['vout'] if v['scriptPubKey'].get('type')=='witness_v1_taproot']))" \
            2>/dev/null || echo 0)
echo "  poison TX P2TR outputs: $N_OUTPUTS (expected $PS_SUB_ARITY = k clients)"
if [ "$N_OUTPUTS" -lt "$PS_SUB_ARITY" ]; then
    echo "FAIL: poison TX missing per-client P2TR outputs"
    exit 1
fi

echo ""
echo "=== PASS: PS k² sub-factory breach detection end-to-end ==="
echo "  - $((N_CLIENTS + 1)) distinct OS processes (1 LSP + $N_CLIENTS clients)"
echo "  - k=$PS_SUB_ARITY canonical sub-factory shape"
echo "  - LSP cheated by broadcasting stale chain[N-1]"
echo "  - Watchtower detected breach, broadcast poison TX"
echo "  - Poison TX confirmed with $N_OUTPUTS per-client P2TR outputs"
