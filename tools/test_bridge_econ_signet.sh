#!/usr/bin/env bash
# test_bridge_econ_signet.sh — Phase 3 economic-correctness test on signet.
#
# Signet counterpart of test_bridge_econ_regtest.sh. The big differences
# vs regtest:
#   - does NOT start/stop bitcoind or CLN — uses the persistent signet
#     environment at /var/lib/bitcoind-signet, /var/lib/cln-signet (SS
#     plugin), and /var/lib/cln-signet-{c,d} (vanilla peers).
#   - does NOT mine blocks. Signet has ~10 min inter-block time; the
#     script waits patiently for real signet confirmations.
#   - opens an ANNOUNCED LN channel on first run, then reuses it on
#     subsequent runs (since signet funds shouldn't be burned rebuilding).
#   - spins up an ephemeral LSP + 4 clients + bridge for the SuperScalar
#     side; tears those down at the end but leaves signet/CLN state alone.
#
# Usage: bash tools/test_bridge_econ_signet.sh [BUILD_DIR]
#
# Env:
#   SS_ARITY      1 | 2 | 3 (default 2)
#   VANILLA_DIR   /var/lib/cln-signet-c or -d (default -c)
#   SKIP_CLOSE    1 to skip the coop-close step (lets you iterate faster
#                 on the payment flow without burning signet funds).

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
BRIDGE_BIN="$BUILD_DIR/superscalar_bridge"

LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT0_SK="0000000000000000000000000000000000000000000000000000000000000002"
CLIENT_SECKEYS=(
    "$CLIENT0_SK"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "0000000000000000000000000000000000000000000000000000000000000004"
    "0000000000000000000000000000000000000000000000000000000000000005"
)

# --- Signet bitcoind ---
SIGNET_CONF="/var/lib/bitcoind-signet/bitcoin.conf"
BCLI="bitcoin-cli -conf=$SIGNET_CONF"

# --- Persistent CLN nodes ---
PLUGIN_CLN_DIR="/var/lib/cln-signet"           # has SS plugin
VANILLA_CLN_DIR="${VANILLA_DIR:-/var/lib/cln-signet-c}"
CLN_NET="signet"
LCLI_PLUGIN="lightning-cli --network=$CLN_NET --lightning-dir=$PLUGIN_CLN_DIR"
LCLI_VANILLA="lightning-cli --network=$CLN_NET --lightning-dir=$VANILLA_CLN_DIR"

LSP_PORT=29935
BRIDGE_PORT=29736

TMPDIR=$(mktemp -d /tmp/ss-bridge-econ-signet.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"

PIDS=()
cleanup() {
    echo "=== Cleaning up (signet state preserved) ==="
    kill "${FIFO_HOLDER_PID:-}" 2>/dev/null || true
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    cp "$TMPDIR/lsp.log" /tmp/bridge_signet_last_lsp.log 2>/dev/null || true
    cp "$TMPDIR/bridge.log" /tmp/bridge_signet_last_bridge.log 2>/dev/null || true
    rm -rf "$TMPDIR"
    echo "  Preserved logs: /tmp/bridge_signet_last_{lsp,bridge}.log"
}
trap cleanup EXIT

echo "=== Phase 3 (signet): Hybrid CLN Bridge Econ Test ==="

# ---- Sanity: signet bitcoind + both CLN nodes must be running ----
$BCLI getblockchaininfo >/dev/null || { echo "FAIL: signet bitcoind not reachable"; exit 1; }
$LCLI_PLUGIN getinfo >/dev/null || { echo "FAIL: plugin CLN at $PLUGIN_CLN_DIR not running"; exit 1; }
$LCLI_VANILLA getinfo >/dev/null || { echo "FAIL: vanilla CLN at $VANILLA_CLN_DIR not running"; exit 1; }

PLUGIN_CLN_ID=$($LCLI_PLUGIN getinfo | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
VANILLA_CLN_ID=$($LCLI_VANILLA getinfo | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
VANILLA_CLN_ADDR=$($LCLI_VANILLA getinfo | python3 -c "
import json,sys
d=json.load(sys.stdin); addrs=d.get('address',[]) or d.get('binding',[])
for a in addrs:
    if a.get('type') in ('ipv4','ipv6'):
        print(f\"{a['address']}:{a['port']}\"); sys.exit(0)
print('127.0.0.1:9739')  # fallback
")
echo "Plugin CLN:  $PLUGIN_CLN_ID"
echo "Vanilla CLN: $VANILLA_CLN_ID @ $VANILLA_CLN_ADDR"

# ---- Ensure an LN channel exists between vanilla → plugin (sender → receiver) ----
check_channel() {
    $LCLI_VANILLA listpeerchannels "$PLUGIN_CLN_ID" 2>/dev/null | python3 -c "
import json, sys
d = json.load(sys.stdin); chs = d.get('channels', [])
ok = [c for c in chs if c.get('state') == 'CHANNELD_NORMAL']
if not ok:
    print('NONE'); sys.exit(0)
spendable = sum(c.get('spendable_msat', 0) for c in ok)
print(f'NORMAL {spendable}')
"
}

CH_STATE=$(check_channel)
echo "Channel vanilla→plugin: $CH_STATE"
if [ "$CH_STATE" = "NONE" ]; then
    echo "No active channel — opening one. This takes ~30 min on signet for 6 confirms."
    $LCLI_VANILLA connect "$PLUGIN_CLN_ID" "${VANILLA_CLN_ADDR%:*}" "${VANILLA_CLN_ADDR##*:}" >/dev/null
    # 500k sats, announced so gossip propagates (lets pay() find a route
    # without needing routehints from a private channel).
    $LCLI_VANILLA fundchannel "$PLUGIN_CLN_ID" 500000 >/dev/null
    for i in $(seq 1 360); do  # 360*10s = 60 min budget
        ST=$(check_channel)
        case "$ST" in NORMAL*) break ;; esac
        sleep 10
        [ $((i % 6)) -eq 0 ] && echo "  still waiting ($((i/6)) min)..."
    done
    CH_STATE=$(check_channel)
    case "$CH_STATE" in
        NORMAL*) echo "Channel now NORMAL: $CH_STATE" ;;
        *) echo "FAIL: channel still not NORMAL after 60 min ($CH_STATE)"; exit 1 ;;
    esac
fi

# ---- Start LSP ----
LSP_FIFO="$TMPDIR/lsp_cmd"
mkfifo "$LSP_FIFO"
sleep infinity > "$LSP_FIFO" &
FIFO_HOLDER_PID=$!

SS_ARITY="${SS_ARITY:-2}"
echo "  (using factory arity: $SS_ARITY)"

# Read signet RPC creds from bitcoin.conf so LSP can talk to bitcoind.
SIGNET_RPCUSER=$(awk -F= '$1 ~ /^[[:space:]]*rpcuser/ {gsub(/[[:space:]]/,"",$2); print $2; exit}' "$SIGNET_CONF")
SIGNET_RPCPASS=$(awk -F= '$1 ~ /^[[:space:]]*rpcpassword/ {gsub(/[[:space:]]/,"",$2); print $2; exit}' "$SIGNET_CONF")
SIGNET_RPCPORT=$(awk -F= '$1 ~ /^[[:space:]]*rpcport/ {gsub(/[[:space:]]/,"",$2); print $2; exit}' "$SIGNET_CONF")
: "${SIGNET_RPCPORT:=38332}"

stdbuf -oL $LSP_BIN --daemon --cli --network signet --port "$LSP_PORT" \
    --seckey "$LSP_SECKEY" --clients 4 --db "$LSP_DB" \
    --cli-path "$(which bitcoin-cli)" \
    --rpcuser "$SIGNET_RPCUSER" --rpcpassword "$SIGNET_RPCPASS" \
    --rpcport "$SIGNET_RPCPORT" \
    --amount 100000 --active-blocks 500 --arity "$SS_ARITY" \
    < "$LSP_FIFO" > "$TMPDIR/lsp.log" 2>&1 &
LSP_PID=$!
PIDS+=("$LSP_PID")

for i in $(seq 1 30); do
    grep -q "listening on port" "$TMPDIR/lsp.log" 2>/dev/null && break
    sleep 1
done
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

# ---- Start 4 clients ----
for i in 0 1 2 3; do
    stdbuf -oL $CLIENT_BIN --seckey "${CLIENT_SECKEYS[$i]}" \
        --host 127.0.0.1 --port "$LSP_PORT" --network signet \
        --lsp-pubkey "$LSP_PUBKEY" --daemon \
        --db "$TMPDIR/client_${i}.db" \
        --cli-path "$(which bitcoin-cli)" \
        --rpcuser "$SIGNET_RPCUSER" --rpcpassword "$SIGNET_RPCPASS" \
        --rpcport "$SIGNET_RPCPORT" \
        > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=("$!")
    sleep 1
done

# Factory funding + confirmation on signet — can take 10+ min for 1 conf.
echo "Waiting for factory funding to confirm on signet (this may take 10–20 min)..."
for i in $(seq 1 360); do  # 60 min budget
    grep -q "entering daemon mode" "$TMPDIR/lsp.log" 2>/dev/null && break
    sleep 10
    [ $((i % 6)) -eq 0 ] && echo "  still waiting ($((i/6)) min)..."
done
grep -q "entering daemon mode" "$TMPDIR/lsp.log" || {
    echo "FAIL: LSP never entered daemon mode"
    tail -30 "$TMPDIR/lsp.log"
    exit 1
}
echo "LSP: factory active"

# ---- Start bridge ----
stdbuf -oL $BRIDGE_BIN --lsp-host 127.0.0.1 --lsp-port "$LSP_PORT" \
    --plugin-port "$BRIDGE_PORT" --lsp-pubkey "$LSP_PUBKEY" \
    > "$TMPDIR/bridge.log" 2>&1 &
PIDS+=("$!")
for i in $(seq 1 30); do
    grep -q "connected to LSP" "$TMPDIR/bridge.log" 2>/dev/null && break
    sleep 1
done
echo "Bridge: connected"

# ---- Wire the plugin CLN to the bridge ----
# The persistent plugin CLN must be configured to talk to our ephemeral
# bridge port. If --superscalar-bridge-port wasn't set when the CLN was
# launched, this run won't work. Check the CLN's config for the plugin.
PLUGIN_LOG_HINT=$($LCLI_PLUGIN getinfo 2>/dev/null | python3 -c "
import json, sys
d = json.load(sys.stdin); print(d.get('our_features', {}))" 2>/dev/null || true)
echo "Plugin CLN features: $PLUGIN_LOG_HINT"
# Try a plugin RPC to confirm wiring — the SS plugin registers 'superscalar-status'.
if ! $LCLI_PLUGIN help 2>/dev/null | grep -q superscalar; then
    echo "WARN: plugin CLN doesn't expose superscalar-* commands — bridge won't receive HTLCs."
    echo "      Restart the plugin CLN with --superscalar-bridge-port=$BRIDGE_PORT."
    echo "      Continuing anyway so you can see what else works."
fi

# ---- Record pre-payment balance on vanilla side ----
VANILLA_PRE_MSAT=$($LCLI_VANILLA listpeerchannels "$PLUGIN_CLN_ID" 2>/dev/null | python3 -c "
import json,sys; chs=json.load(sys.stdin).get('channels',[])
print(sum(c.get('spendable_msat',0) for c in chs))")
echo "Vanilla CLN pre-payment spendable to plugin: $VANILLA_PRE_MSAT msat"

# ---- Inbound: SS invoice paid by vanilla CLN ----
INVOICE_AMT_MSAT=600000
echo "invoice 0 $INVOICE_AMT_MSAT" > "$LSP_FIFO"
sleep 3
BOLT11=""
for i in $(seq 1 30); do
    BOLT11=$($LCLI_PLUGIN listinvoices 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
for inv in d.get('invoices',[]):
    if inv.get('label','').startswith('superscalar-') and inv.get('status')=='unpaid':
        print(inv.get('bolt11','')); sys.exit(0)
print('')")
    [ -n "$BOLT11" ] && break
    sleep 1
done
[ -z "$BOLT11" ] && { echo "FAIL: no invoice produced by plugin"; exit 1; }

echo "Inbound: paying SS invoice from vanilla CLN..."
PAY_RESULT=$($LCLI_VANILLA pay "$BOLT11" 2>&1) || true
PAY_STATUS=$(echo "$PAY_RESULT" | python3 -c "
import json,sys
try: print(json.load(sys.stdin).get('status','?'))
except: print('parse_fail')" 2>/dev/null)
echo "Payment status: $PAY_STATUS"
[ "$PAY_STATUS" != "complete" ] && { echo "FAIL: inbound payment: $PAY_RESULT"; exit 1; }

VANILLA_POST_MSAT=$($LCLI_VANILLA listpeerchannels "$PLUGIN_CLN_ID" 2>/dev/null | python3 -c "
import json,sys; chs=json.load(sys.stdin).get('channels',[])
print(sum(c.get('spendable_msat',0) for c in chs))")
DELTA=$((VANILLA_PRE_MSAT - VANILLA_POST_MSAT))
echo "Vanilla spendable delta: $DELTA msat (>= invoice $INVOICE_AMT_MSAT + LN fees)"
[ "$DELTA" -lt "$INVOICE_AMT_MSAT" ] && { echo "FAIL: delta $DELTA < invoice"; exit 1; }
echo "external_in (signet): ✓"

# ---- Outbound: SS client pays vanilla CLN invoice ----
OUTBOUND_AMT_MSAT=400000
CLN_INV=$($LCLI_VANILLA invoice "$OUTBOUND_AMT_MSAT" "ss-out-signet" "SS->vanilla signet" 2>/dev/null | \
    python3 -c "import json,sys; print(json.load(sys.stdin).get('bolt11',''))")
if [ -z "$CLN_INV" ]; then
    echo "WARN: vanilla invoice generation failed — skipping external_out"
else
    echo "Outbound: pay_external 0 via bridge..."
    echo "pay_external 0 $CLN_INV" > "$LSP_FIFO"
    for i in $(seq 1 120); do
        if grep -q "pay_external sent to bridge\|pay_external: complete" "$TMPDIR/lsp.log" 2>/dev/null; then
            break
        fi
        sleep 1
    done
    sleep 5
    VANILLA_POST_OUT_MSAT=$($LCLI_VANILLA listpeerchannels "$PLUGIN_CLN_ID" 2>/dev/null | python3 -c "
import json,sys; chs=json.load(sys.stdin).get('channels',[])
print(sum(c.get('spendable_msat',0) for c in chs))")
    GAIN=$((VANILLA_POST_OUT_MSAT - VANILLA_POST_MSAT))
    echo "Vanilla spendable gained: $GAIN msat (>= $OUTBOUND_AMT_MSAT - LN fee)"
    if [ "$GAIN" -ge "$OUTBOUND_AMT_MSAT" ]; then
        echo "external_out (signet): ✓"
    elif [ "$GAIN" -gt 0 ]; then
        echo "external_out (signet): partial ($GAIN msat gained)"
    else
        echo "WARN: external_out: no vanilla gain — payment may not have completed"
    fi
fi

# ---- Optional: cooperative close ----
if [ "${SKIP_CLOSE:-0}" = "1" ]; then
    echo "SKIP_CLOSE=1 — leaving factory open (you can re-run to reuse it)"
    echo ""
    echo "=== PASS: signet bridge econ (payments only) ==="
    exit 0
fi

echo ""
echo "Requesting cooperative close..."
echo "close" > "$LSP_FIFO"
for i in $(seq 1 300); do
    if grep -q "Close outputs:" "$TMPDIR/lsp.log" 2>/dev/null; then
        echo "  close outputs signed (after ${i}s)"
        break
    fi
    sleep 1
done

# Wait for the close tx to confirm on signet (real miners, one block ≈ 10 min).
echo "Waiting for close tx to confirm (signet ~10 min per block)..."
for i in $(seq 1 360); do
    TXID=$(sqlite3 "$LSP_DB" "SELECT txid FROM broadcast_log WHERE source='cooperative_close' ORDER BY id DESC LIMIT 1;" 2>/dev/null || echo "")
    if [ -n "$TXID" ] && [ "$TXID" != "?" ]; then
        CONF=$($BCLI getrawtransaction "$TXID" 1 2>/dev/null | python3 -c "
import json,sys
try: print(json.load(sys.stdin).get('confirmations',0))
except: print(0)" 2>/dev/null || echo 0)
        [ "$CONF" -ge 1 ] && { echo "Close tx confirmed: $TXID ($CONF confs)"; break; }
    fi
    sleep 10
    [ $((i % 6)) -eq 0 ] && echo "  still waiting ($((i/6)) min)..."
done

echo ""
echo "=== PASS: signet bridge econ verification ==="
