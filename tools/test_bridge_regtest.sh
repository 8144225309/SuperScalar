#!/usr/bin/env bash
# test_bridge_regtest.sh — End-to-end CLN bridge integration test on regtest
#
# Proves a payment routes from CLN through the SuperScalar factory and back.
#
# Prerequisites:
#   - bitcoind, bitcoin-cli in PATH (or ~/bin/)
#   - lightningd, lightning-cli in PATH (or ~/bin/)
#   - SuperScalar binaries built (superscalar_lsp, superscalar_client, superscalar_bridge)
#   - Python 3 with CLN plugin at tools/cln_plugin.py
#
# Usage:
#   bash tools/test_bridge_regtest.sh [BUILD_DIR]
#
# BUILD_DIR defaults to ~/superscalar-build

set -euo pipefail

BUILD_DIR="${1:-$HOME/superscalar-build}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Binaries
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
BRIDGE_BIN="$BUILD_DIR/superscalar_bridge"
PLUGIN_PY="$PROJECT_DIR/tools/cln_plugin.py"

export PATH="$HOME/bin:$PATH"

# Deterministic keys for test
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "0000000000000000000000000000000000000000000000000000000000000004"
    "0000000000000000000000000000000000000000000000000000000000000005"
)

# Regtest config
REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

# Temporary directories
TMPDIR=$(mktemp -d /tmp/ss-bridge-test.XXXXXX)
CLN_DIR="$TMPDIR/cln"
LSP_DB="$TMPDIR/lsp.db"

# Cleanup on exit
cleanup() {
    echo "=== Cleaning up ==="
    # Kill FIFO holder
    kill "${FIFO_HOLDER_PID:-}" 2>/dev/null || true

    # Kill background processes
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done

    # Stop CLN nodes
    lightning-cli --network=regtest --lightning-dir="$CLN_DIR" stop 2>/dev/null || true
    [ -d "${CLN2_DIR:-}" ] && lightning-cli --network=regtest --lightning-dir="$CLN2_DIR" stop 2>/dev/null || true

    # Stop bitcoind
    $BCLI stop 2>/dev/null || true

    # Remove temp dir
    rm -rf "$TMPDIR"
    echo "=== Cleanup complete ==="
}
trap cleanup EXIT

PIDS=()

echo "=== SuperScalar CLN Bridge Integration Test ==="
echo "Build dir: $BUILD_DIR"
echo "Temp dir:  $TMPDIR"

# --- Step 1: Start bitcoind regtest ---
echo ""
echo "--- Step 1: Starting bitcoind regtest ---"
$BCLI stop 2>/dev/null || true
sleep 1
rm -rf "$HOME/.bitcoin/regtest"
bitcoind -regtest -conf="$REGTEST_CONF" -daemon
sleep 2

# Create wallet and mine initial blocks
$BCLI createwallet "test" 2>/dev/null || $BCLI loadwallet "test" 2>/dev/null || true
ADDR=$($BCLI -rpcwallet=test getnewaddress)
$BCLI generatetoaddress 101 "$ADDR" > /dev/null
echo "bitcoind: 101 blocks mined"

# --- Step 2: Start CLN ---
echo ""
echo "--- Step 2: Starting CLN ---"
mkdir -p "$CLN_DIR"

# Start lightningd with regtest and the SuperScalar plugin
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}:$HOME/lib"
lightningd \
    --network=regtest \
    --lightning-dir="$CLN_DIR" \
    --bitcoin-cli="$(which bitcoin-cli)" \
    --bitcoin-rpcuser=rpcuser \
    --bitcoin-rpcpassword=rpcpass \
    --log-level=debug \
    --log-file="$CLN_DIR/cln.log" \
    --plugin="$PLUGIN_PY" \
    --superscalar-bridge-port=19736 \
    --bind-addr=127.0.0.1:9738 \
    --disable-plugin clnrest \
    --disable-plugin cln-grpc \
    --daemon

sleep 3
echo "CLN: started (lightning-dir=$CLN_DIR)"

# Get CLN node info
CLN_ID=$(lightning-cli --network=regtest --lightning-dir="$CLN_DIR" getinfo | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
echo "CLN: node_id=$CLN_ID"

# Fund CLN
CLN_ADDR=$(lightning-cli --network=regtest --lightning-dir="$CLN_DIR" newaddr | python3 -c "import json,sys; print(json.load(sys.stdin)['bech32'])")
$BCLI -rpcwallet=test sendtoaddress "$CLN_ADDR" 1.0 > /dev/null
$BCLI generatetoaddress 6 "$ADDR" > /dev/null
echo "CLN: funded"

# --- Step 3: Check binaries ---
echo ""
echo "--- Step 3: Checking binaries ---"
for bin in "$LSP_BIN" "$CLIENT_BIN" "$BRIDGE_BIN"; do
    if [ ! -x "$bin" ]; then
        echo "ERROR: $bin not found or not executable"
        echo "Build first: cd $BUILD_DIR && cmake $PROJECT_DIR && make -j\$(nproc)"
        exit 1
    fi
done
echo "All binaries present"

# --- Step 4: Start LSP with FIFO for CLI commands ---
echo ""
echo "--- Step 4: Starting LSP daemon (with CLI) ---"
LSP_FIFO="$TMPDIR/lsp_cmd"
mkfifo "$LSP_FIFO"
sleep infinity > "$LSP_FIFO" &
FIFO_HOLDER_PID=$!

stdbuf -oL $LSP_BIN \
    --daemon \
    --cli \
    --network regtest \
    --port 9735 \
    --seckey "$LSP_SECKEY" \
    --clients 4 \
    --db "$LSP_DB" \
    --cli-path "$(which bitcoin-cli)" \
    --rpcuser rpcuser \
    --rpcpassword rpcpass \
    --amount 100000 \
    < "$LSP_FIFO" > "$TMPDIR/lsp.log" 2>&1 &
LSP_PID=$!
PIDS+=("$LSP_PID")

# Wait for LSP to start listening before connecting clients
echo "LSP: waiting for listen socket..."
for attempt in $(seq 1 30); do
    if ! kill -0 $LSP_PID 2>/dev/null; then
        echo "FAIL: LSP process exited during startup"
        cat "$TMPDIR/lsp.log" 2>/dev/null || true
        exit 1
    fi
    if grep -q "listening on port" "$TMPDIR/lsp.log" 2>/dev/null; then
        echo "LSP: listening (after ${attempt}s)"
        break
    fi
    if [ "$attempt" -eq 30 ]; then
        echo "FAIL: LSP did not start listening within 30s"
        cat "$TMPDIR/lsp.log" 2>/dev/null || true
        exit 1
    fi
    sleep 1
done
# Extra sleep to ensure listen socket is fully open after the log message
sleep 1
echo "LSP: started (pid=$LSP_PID, fifo=$LSP_FIFO)"

# Get LSP pubkey (derive from seckey)
LSP_PUBKEY=$(python3 -c "
import hashlib, struct
# secp256k1 generator point — we just need the compressed pubkey for key 01
# For test key 01: pubkey is 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
print('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
")
echo "LSP: pubkey=$LSP_PUBKEY"

# --- Step 5: Start factory clients ---
echo ""
echo "--- Step 5: Starting 4 factory clients ---"
for i in 0 1 2 3; do
    stdbuf -oL $CLIENT_BIN \
        --seckey "${CLIENT_SECKEYS[$i]}" \
        --host 127.0.0.1 \
        --port 9735 \
        --network regtest \
        --lsp-pubkey "$LSP_PUBKEY" \
        --daemon \
        --cli-path "$(which bitcoin-cli)" \
        --rpcuser rpcuser \
        --rpcpassword rpcpass \
        > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=("$!")
    sleep 1
done
echo "Clients: 4 started, waiting for factory..."

# Wait for factory creation — poll LSP log for "entering daemon mode"
# The LSP mines its own block for funding confirmation on regtest,
# but we mine additional blocks to help any confirmation checks.
echo "Waiting for LSP to enter daemon mode..."
for attempt in $(seq 1 120); do
    # Check if LSP exited (factory creation failed)
    if ! kill -0 $LSP_PID 2>/dev/null; then
        echo "FAIL: LSP process exited during factory creation"
        echo "--- LSP log ---"
        cat "$TMPDIR/lsp.log" 2>/dev/null || true
        exit 1
    fi
    # Mine a block every 3 seconds to help confirmations
    if [ $((attempt % 3)) -eq 0 ]; then
        $BCLI generatetoaddress 1 "$ADDR" > /dev/null 2>&1 || true
    fi
    # Check for daemon mode entry
    if grep -q "entering daemon mode" "$TMPDIR/lsp.log" 2>/dev/null; then
        echo "LSP: entered daemon mode (after ${attempt}s)"
        break
    fi
    if [ "$attempt" -eq 120 ]; then
        echo "FAIL: LSP did not enter daemon mode within 120s"
        echo "--- LSP log ---"
        cat "$TMPDIR/lsp.log" 2>/dev/null || true
        exit 1
    fi
    sleep 1
done

# --- Step 6: Start bridge ---
# Use port 19736 to avoid conflict with CLN's cln-grpc plugin (which defaults to 9736)
BRIDGE_PLUGIN_PORT=19736
echo ""
echo "--- Step 6: Starting bridge daemon (plugin port $BRIDGE_PLUGIN_PORT) ---"
stdbuf -oL $BRIDGE_BIN \
    --lsp-host 127.0.0.1 \
    --lsp-port 9735 \
    --plugin-port "$BRIDGE_PLUGIN_PORT" \
    --lsp-pubkey "$LSP_PUBKEY" \
    > "$TMPDIR/bridge.log" 2>&1 &
BRIDGE_PID=$!
PIDS+=("$BRIDGE_PID")
echo "Bridge: started (pid=$BRIDGE_PID), waiting for LSP connection..."

# Poll for bridge connection (handshake can take a few seconds)
for attempt in $(seq 1 30); do
    if ! kill -0 $BRIDGE_PID 2>/dev/null; then
        echo "FAIL: Bridge process exited"
        echo "--- Bridge log ---"
        cat "$TMPDIR/bridge.log" 2>/dev/null || true
        exit 1
    fi
    if grep -q "connected to LSP" "$TMPDIR/bridge.log" 2>/dev/null; then
        echo "Bridge: connected to LSP (after ${attempt}s)"
        break
    fi
    if [ "$attempt" -eq 30 ]; then
        echo "FAIL: Bridge did not connect to LSP within 30s"
        echo "--- Bridge log ---"
        cat "$TMPDIR/bridge.log" 2>/dev/null || true
        echo "--- LSP log (last 20 lines) ---"
        tail -20 "$TMPDIR/lsp.log" 2>/dev/null || true
        exit 1
    fi
    sleep 1
done

# --- Step 7: Configure CLN plugin to connect to bridge ---
echo ""
echo "--- Step 7: Connecting CLN plugin to bridge ---"
# The plugin auto-connects on startup if configured, or we can use RPC
# to trigger connection. Check if plugin is active:
lightning-cli --network=regtest --lightning-dir="$CLN_DIR" plugin list | python3 -c "
import json, sys
plugins = json.load(sys.stdin)['plugins']
ss_plugins = [p for p in plugins if 'cln_plugin' in p.get('name', '')]
if ss_plugins:
    print(f'CLN: SuperScalar plugin active: {ss_plugins[0][\"name\"]}')
else:
    print('CLN: WARNING — SuperScalar plugin not found')
    sys.exit(1)
"
sleep 2

# --- Step 8: Verify infrastructure ---
echo ""
echo "--- Step 8: Verifying infrastructure ---"
FAIL=0

echo ""
echo "=== Component Status ==="
if kill -0 $LSP_PID 2>/dev/null; then
    echo "  LSP: running"
else
    echo "  LSP: STOPPED"
    FAIL=1
fi
if kill -0 $BRIDGE_PID 2>/dev/null; then
    echo "  Bridge: running"
else
    echo "  Bridge: STOPPED"
    FAIL=1
fi

# Check logs for successful connections
echo ""
echo "=== Connection Status ==="
if grep -q "bridge connected in daemon loop" "$TMPDIR/lsp.log" 2>/dev/null; then
    echo "  LSP: bridge connected"
else
    echo "  LSP: bridge NOT connected"
    FAIL=1
fi
if grep -q "connected to LSP" "$TMPDIR/bridge.log" 2>/dev/null; then
    echo "  Bridge: connected to LSP"
else
    echo "  Bridge: NOT connected to LSP"
    FAIL=1
fi

# Check if factory was created
echo ""
echo "=== Factory Status ==="
if grep -q "factory created\|FACTORY_READY\|channels ready" "$TMPDIR/lsp.log" 2>/dev/null; then
    echo "  Factory: CREATED"
else
    echo "  Factory: not created (clients may still be connecting)"
    FAIL=1
fi

# Dump logs on failure
if [ "$FAIL" -ne 0 ]; then
    echo ""
    echo "=== Logs (failure diagnostic) ==="
    echo "--- LSP (last 30 lines) ---"
    tail -30 "$TMPDIR/lsp.log" 2>/dev/null || true
    echo ""
    echo "--- Bridge (last 30 lines) ---"
    tail -30 "$TMPDIR/bridge.log" 2>/dev/null || true
    echo ""
    echo "--- Client 0 (last 30 lines) ---"
    tail -30 "$TMPDIR/client_0.log" 2>/dev/null || true
    echo ""
    echo "=== FAIL: CLN Bridge Integration ==="
    exit 1
fi

echo ""
echo "=== PASS: CLN Bridge Integration Infrastructure ==="
echo "All components running, bridge connected, factory created."

# --- Step 8b: Start second CLN node (sender) ---
echo ""
echo "--- Step 8b: Starting second CLN node (sender) ---"
CLN2_DIR="$TMPDIR/cln2"
mkdir -p "$CLN2_DIR"

if ! lightningd \
    --network=regtest \
    --lightning-dir="$CLN2_DIR" \
    --bitcoin-cli="$(which bitcoin-cli)" \
    --bitcoin-rpcuser=rpcuser \
    --bitcoin-rpcpassword=rpcpass \
    --log-level=debug \
    --log-file="$CLN2_DIR/cln2.log" \
    --daemon \
    --bind-addr=127.0.0.1:9737 \
    --disable-plugin clnrest \
    --disable-plugin cln-grpc; then
    echo "FAIL: CLN2 failed to start"
    cat "$CLN2_DIR/cln2.log" 2>/dev/null | tail -20 || true
    exit 1
fi
sleep 3

CLN2_ID=$(lightning-cli --network=regtest --lightning-dir="$CLN2_DIR" getinfo | \
    python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
echo "CLN2: node_id=$CLN2_ID"

# Fund node 2
CLN2_ADDR=$(lightning-cli --network=regtest --lightning-dir="$CLN2_DIR" newaddr | \
    python3 -c "import json,sys; print(json.load(sys.stdin)['bech32'])")
$BCLI -rpcwallet=test sendtoaddress "$CLN2_ADDR" 1.0 > /dev/null
$BCLI generatetoaddress 6 "$ADDR" > /dev/null
echo "CLN2: funded"

# --- Step 9: Open channel Node 2 → Node 1 ---
echo ""
echo "--- Step 9: Opening channel Node 2 → Node 1 ---"

# Wait for CLN2 to sync funds
echo "Waiting for CLN2 to sync funds..."
for attempt in $(seq 1 30); do
    BALANCE=$(lightning-cli --network=regtest --lightning-dir="$CLN2_DIR" listfunds 2>/dev/null | \
        python3 -c "import json,sys; d=json.load(sys.stdin); print(sum(o.get('amount_msat',0) for o in d.get('outputs',[])))" 2>/dev/null || echo "0")
    if [ "$BALANCE" != "0" ] && [ -n "$BALANCE" ]; then
        echo "CLN2: balance synced ($BALANCE msat, attempt $attempt)"
        break
    fi
    if [ "$attempt" -eq 30 ]; then
        echo "WARNING: CLN2 balance still 0 after 30s, proceeding anyway"
    fi
    sleep 1
done

lightning-cli --network=regtest --lightning-dir="$CLN2_DIR" connect "$CLN_ID" 127.0.0.1 9738
lightning-cli --network=regtest --lightning-dir="$CLN2_DIR" fundchannel "$CLN_ID" 500000

# Mine blocks and wait for channel to reach NORMAL state
echo "Mining blocks and waiting for channel to become NORMAL..."
for attempt in $(seq 1 60); do
    # Mine a block every 2 attempts to confirm the funding TX
    if [ $((attempt % 2)) -eq 0 ]; then
        $BCLI generatetoaddress 1 "$ADDR" > /dev/null 2>&1 || true
    fi
    CHAN_STATE=$(lightning-cli --network=regtest --lightning-dir="$CLN2_DIR" listpeerchannels 2>/dev/null | \
        python3 -c "
import json,sys
data = json.load(sys.stdin)
channels = data.get('channels', [])
for ch in channels:
    if ch.get('state') == 'CHANNELD_NORMAL':
        print('NORMAL')
        sys.exit(0)
print('NOT_READY')
" 2>/dev/null || echo "NOT_READY")
    if [ "$CHAN_STATE" = "NORMAL" ]; then
        echo "Channel Node 2 → Node 1: NORMAL (after ${attempt}s)"
        break
    fi
    if [ "$attempt" -eq 60 ]; then
        echo "FAIL: Channel did not reach NORMAL state within 60s"
        lightning-cli --network=regtest --lightning-dir="$CLN2_DIR" listpeerchannels 2>/dev/null | \
            python3 -c "import json,sys; [print(f'  {c[\"state\"]}') for c in json.load(sys.stdin).get('channels',[])]" 2>/dev/null || true
        exit 1
    fi
    sleep 1
done

# --- Step 10: Create external invoice via LSP CLI ---
echo ""
echo "--- Step 10: Creating external invoice (client 0, 600000 msat) ---"
echo "invoice 0 600000" > "$LSP_FIFO"
sleep 2
echo "Invoice command sent to LSP"

# --- Step 11: Wait for BOLT11 invoice to appear in CLN1 ---
echo ""
echo "--- Step 11: Waiting for BOLT11 invoice on CLN1 ---"
BOLT11=""
for attempt in $(seq 1 30); do
    BOLT11=$(lightning-cli --network=regtest --lightning-dir="$CLN_DIR" listinvoices | python3 -c "
import json, sys
data = json.load(sys.stdin)
for inv in data.get('invoices', []):
    label = inv.get('label', '')
    if label.startswith('superscalar-') and inv.get('status') == 'unpaid':
        print(inv.get('bolt11', ''))
        sys.exit(0)
print('')
" 2>/dev/null)
    if [ -n "$BOLT11" ]; then
        echo "Found BOLT11 invoice (attempt $attempt)"
        break
    fi
    sleep 1
done

if [ -z "$BOLT11" ]; then
    echo "FAIL: No superscalar-* invoice appeared on CLN1 within 30s"
    FAIL=1
else
    echo "BOLT11: ${BOLT11:0:40}..."

    # --- Step 12: Pay from CLN2 and verify ---
    echo ""
    echo "--- Step 12: Paying invoice from CLN2 ---"
    RESULT=$(lightning-cli --network=regtest --lightning-dir="$CLN2_DIR" pay "$BOLT11" 2>&1) || true

    SUCCESS=$(echo "$RESULT" | python3 -c "
import json, sys
try:
    r = json.load(sys.stdin)
    print('true' if r.get('status') == 'complete' else 'false')
except:
    print('false')
" 2>/dev/null)

    if [ "$SUCCESS" = "true" ]; then
        echo "=== PASS: CLN Bridge End-to-End Payment ==="
    else
        echo "=== FAIL: Payment did not complete ==="
        echo "Result: $RESULT"
        FAIL=1
    fi
fi

if [ "$FAIL" -ne 0 ]; then
    echo ""
    echo "=== Logs (failure diagnostic) ==="
    echo "--- LSP (last 30 lines) ---"
    tail -30 "$TMPDIR/lsp.log" 2>/dev/null || true
    echo ""
    echo "--- Bridge (last 30 lines) ---"
    tail -30 "$TMPDIR/bridge.log" 2>/dev/null || true
    echo ""
    echo "--- Client 0 (last 30 lines) ---"
    tail -30 "$TMPDIR/client_0.log" 2>/dev/null || true
    echo ""
    echo "=== FAIL: CLN Bridge Full Integration ==="
    exit 1
fi

echo ""
echo "=== PASS: CLN Bridge Full Integration ==="
exit 0
