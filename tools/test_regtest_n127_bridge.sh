#!/usr/bin/env bash
# test_regtest_n127_bridge.sh — real-LN interop at the factory design max.
#
# A 127-client SuperScalar factory (LSP + 127 client daemons = the full
# 128-signer group) exchanging REAL Lightning payments with an external,
# vanilla (non-bLIP-56) CLN node over the bridge:
#
#   CLN2 (vanilla) ==real LN channel== CLN1 (cln_plugin.py) --> superscalar_bridge --> LSP --> factory clients
#
# Legs proven, with hard economic assertions on the EXTERNAL node:
#   INBOUND  shallow: CLN2 pays a 600k msat invoice for factory client 0
#   INBOUND  deep:    CLN2 pays a 500k msat invoice for factory client 100
#                     (high-index routing at scale — indexes past 64 were
#                      exactly where the readiness/scale bugs lived)
#   OUTBOUND:         factory client 0 pays a 400k msat CLN2 invoice
#
# PASS = all pays status=complete / invoice paid, CLN2 spendable-msat deltas
# match, the LSP stays in daemon mode, and no conservation alert fires.
#
# Owns the regtest bitcoind lifecycle (same pattern as test_bridge_regtest.sh):
# stops any running instance, wipes the default regtest datadir, restarts.
#
# Usage: bash tools/test_regtest_n127_bridge.sh [BUILD_DIR]
# Env:   N_CLIENTS (default 127)
set -uo pipefail

# systemd-run units have no HOME; everything below needs one.
HOME="${HOME:-/root}"

BUILD_DIR="${1:-/root/ss-p6-main/build}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
BRIDGE_BIN="$BUILD_DIR/superscalar_bridge"
PLUGIN_PY="$PROJECT_DIR/tools/cln_plugin.py"
export PATH="$HOME/bin:$PATH"

REGTEST_CONF="${REGTEST_CONF:-$HOME/bitcoin-regtest/bitcoin.conf}"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

N_CLIENTS="${N_CLIENTS:-127}"
DEEP_CLIENT="${DEEP_CLIENT:-100}"
ARITY="${ARITY:-2,4,8}"
AMOUNT="${AMOUNT:-$(( N_CLIENTS * 100000 ))}"
FEE_RATE="${FEE_RATE:-1000}"
PORT="${PORT:-9951}"
BRIDGE_PLUGIN_PORT=19761
CLN1_BIND=9758
CLN2_BIND=9757
TAG="regtest_n127_bridge"
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

TMPDIR=$(mktemp -d /tmp/ss-n127-bridge.XXXXXX)
CLN_DIR="$TMPDIR/cln"
CLN2_DIR="$TMPDIR/cln2"
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"
LSP_FIFO="$TMPDIR/lsp_cmd"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m[n127-bridge]\033[0m %s\n' "$*"; }

CLI1="lightning-cli --network=regtest --lightning-dir=$CLN_DIR"
CLI2="lightning-cli --network=regtest --lightning-dir=$CLN2_DIR"

cleanup() {
    echo "=== Cleaning up ==="
    kill "${FIFO_HOLDER_PID:-}" 2>/dev/null || true
    pkill -9 -f "superscalar_client.*$PORT" 2>/dev/null || true
    kill -9 "${BRIDGE_PID:-}" "${LSP_PID:-}" 2>/dev/null || true
    $CLI1 stop 2>/dev/null || true
    $CLI2 stop 2>/dev/null || true
    $BCLI stop 2>/dev/null || true
    cp "$LSP_LOG" /tmp/bridge_n127_last_lsp.log 2>/dev/null || true
    cp "$TMPDIR/bridge.log" /tmp/bridge_n127_last_bridge.log 2>/dev/null || true
    cp "$CLN_DIR/cln.log" /tmp/bridge_n127_last_cln1.log 2>/dev/null || true
    rm -rf "$TMPDIR"
    echo "=== Cleanup complete ==="
}
trap cleanup EXIT
die() { red "FAIL: $*"; tail -25 "$LSP_LOG" 2>/dev/null; exit 1; }

cln2_spendable() {
    $CLI2 listpeerchannels 2>/dev/null | python3 -c "
import json,sys
d = json.load(sys.stdin)
print(sum(int(c.get('spendable_msat', 0)) for c in d.get('channels', [])))" 2>/dev/null || echo 0
}

echo "=== N=$N_CLIENTS factory x real-LN bridge interop ==="
echo "  build=$BUILD_DIR amount=$AMOUNT deep_client=$DEEP_CLIENT"

for bin in "$LSP_BIN" "$CLIENT_BIN" "$BRIDGE_BIN"; do
    [ -x "$bin" ] || die "$bin missing"
done
[ -f "$PLUGIN_PY" ] || die "plugin $PLUGIN_PY missing"

# --- Step 1: fresh regtest bitcoind (owned lifecycle) ---
info "restarting regtest bitcoind with a fresh chain"
$BCLI stop 2>/dev/null || true
sleep 2
rm -rf "$HOME/.bitcoin/regtest"
bitcoind -regtest -conf="$REGTEST_CONF" -daemon
for i in $(seq 1 30); do $BCLI getblockchaininfo &>/dev/null && break; sleep 1; done
$BCLI getblockchaininfo &>/dev/null || die "bitcoind did not come up"
$BCLI createwallet test 2>/dev/null || $BCLI loadwallet test 2>/dev/null || true
ADDR=$($BCLI -rpcwallet=test getnewaddress)
$BCLI generatetoaddress 101 "$ADDR" > /dev/null
info "chain ready (101 blocks, wallet 'test')"

# --- Step 2: CLN1 (plugin node) + CLN2 (vanilla external) ---
mkdir -p "$CLN_DIR" "$CLN2_DIR"
lightningd --network=regtest --lightning-dir="$CLN_DIR" \
    --bitcoin-cli="$(which bitcoin-cli)" \
    --bitcoin-rpcuser=rpcuser --bitcoin-rpcpassword=rpcpass \
    --log-level=debug --log-file="$CLN_DIR/cln.log" \
    --plugin="$PLUGIN_PY" --superscalar-bridge-port="$BRIDGE_PLUGIN_PORT" \
    --bind-addr=127.0.0.1:$CLN1_BIND \
    --disable-plugin clnrest --disable-plugin cln-grpc --daemon || die "CLN1 start"
lightningd --network=regtest --lightning-dir="$CLN2_DIR" \
    --bitcoin-cli="$(which bitcoin-cli)" \
    --bitcoin-rpcuser=rpcuser --bitcoin-rpcpassword=rpcpass \
    --log-level=debug --log-file="$CLN2_DIR/cln2.log" \
    --bind-addr=127.0.0.1:$CLN2_BIND \
    --disable-plugin clnrest --disable-plugin cln-grpc --daemon || die "CLN2 start"
sleep 3
CLN_ID=$($CLI1 getinfo | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
info "CLN1 (plugin) id=$CLN_ID; CLN2 (vanilla external) up"

# Fund CLN2 (the external payer) on-chain
CLN2_ADDR=$($CLI2 newaddr | python3 -c "import json,sys; print(json.load(sys.stdin)['bech32'])")
$BCLI -rpcwallet=test sendtoaddress "$CLN2_ADDR" 1.0 > /dev/null
$BCLI generatetoaddress 6 "$ADDR" > /dev/null

# --- Step 3: LSP (127 clients) with CLI FIFO ---
mkfifo "$LSP_FIFO"; sleep infinity > "$LSP_FIFO" & FIFO_HOLDER_PID=$!
FACTORY_CLTV=$(( $($BCLI getblockcount) + 600 ))
info "starting LSP: $N_CLIENTS clients, cltv=$FACTORY_CLTV"
stdbuf -oL "$LSP_BIN" \
    --daemon --cli --network regtest --port "$PORT" \
    --seckey "$LSP_SECKEY" --clients "$N_CLIENTS" --arity "$ARITY" \
    --static-near-root 1 --amount "$AMOUNT" \
    --active-blocks 500 --cltv-timeout "$FACTORY_CLTV" \
    --step-blocks 5 --states-per-layer 2 \
    --fee-rate "$FEE_RATE" --lsp-balance-pct 50 \
    --confirm-timeout 86400 \
    --max-conn-rate 400 --max-handshakes 80 \
    --rpcuser rpcuser --rpcpassword rpcpass --rpcport 18443 \
    --wallet test --db "$LSP_DB" \
    < "$LSP_FIFO" > "$LSP_LOG" 2>&1 &
LSP_PID=$!
for i in $(seq 1 45); do
    grep -q "listening on port $PORT" "$LSP_LOG" 2>/dev/null && break
    kill -0 $LSP_PID 2>/dev/null || die "LSP died at startup"
    sleep 1
done
grep -q "listening on port $PORT" "$LSP_LOG" || die "LSP never listened"

# --- Step 4: 127 client daemons (staggered) ---
info "launching $N_CLIENTS client daemons"
for i in $(seq 1 "$N_CLIENTS"); do
    SK=$(printf '%064x' $((i + 1)))
    nohup "$CLIENT_BIN" \
        --network regtest --host 127.0.0.1 --port "$PORT" \
        --seckey "$SK" --fee-rate "$FEE_RATE" --lsp-balance-pct 50 \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id "$i" \
        --rpcuser rpcuser --rpcpassword rpcpass --rpcport 18443 \
        --wallet test --db "$TMPDIR/c${SK:60:4}.db" \
        --daemon \
        > "$TMPDIR/c${SK:60:4}.log" 2>&1 &
    sleep 0.2
done

info "waiting for factory creation + daemon mode (mining every 3s)"
DAEMON_OK=0
for attempt in $(seq 1 600); do
    kill -0 $LSP_PID 2>/dev/null || die "LSP exited during factory creation"
    [ $((attempt % 3)) -eq 0 ] && $BCLI -rpcwallet=test generatetoaddress 1 "$ADDR" > /dev/null 2>&1
    if grep -q "entering daemon mode" "$LSP_LOG" 2>/dev/null; then DAEMON_OK=1; break; fi
    sleep 1
done
[ "$DAEMON_OK" = "1" ] || die "LSP never entered daemon mode (factory creation stalled)"
green "  ok: factory created, LSP in daemon mode with $N_CLIENTS clients"

# --- Step 5: bridge + plugin connection ---
stdbuf -oL "$BRIDGE_BIN" \
    --lsp-host 127.0.0.1 --lsp-port "$PORT" \
    --plugin-port "$BRIDGE_PLUGIN_PORT" --lsp-pubkey "$LSP_PUBKEY" \
    > "$TMPDIR/bridge.log" 2>&1 &
BRIDGE_PID=$!
for i in $(seq 1 30); do
    grep -q "connected to LSP" "$TMPDIR/bridge.log" 2>/dev/null && break
    kill -0 $BRIDGE_PID 2>/dev/null || die "bridge exited"
    sleep 1
done
grep -q "connected to LSP" "$TMPDIR/bridge.log" || die "bridge never connected to LSP"
for i in $(seq 1 45); do
    grep -q "plugin connected" "$TMPDIR/bridge.log" 2>/dev/null && break
    sleep 1
done
grep -q "plugin connected" "$TMPDIR/bridge.log" || info "WARNING: plugin connection not confirmed in bridge log"
green "  ok: bridge up (LSP + plugin)"

# --- Step 6: real LN channel CLN2 -> CLN1 (push_msat = bridge return liquidity) ---
info "opening real LN channel CLN2 -> CLN1"
for i in $(seq 1 30); do
    B=$($CLI2 listfunds 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(sum(o.get('amount_msat',0) for o in d.get('outputs',[])))" 2>/dev/null || echo 0)
    [ "$B" != "0" ] && break; sleep 1
done
$CLI2 connect "$CLN_ID" 127.0.0.1 $CLN1_BIND > /dev/null
$CLI2 fundchannel -k id="$CLN_ID" amount=1500000 push_msat=300000000 > /dev/null || die "fundchannel"
for attempt in $(seq 1 90); do
    [ $((attempt % 2)) -eq 0 ] && $BCLI -rpcwallet=test generatetoaddress 1 "$ADDR" > /dev/null 2>&1
    ST=$($CLI2 listpeerchannels 2>/dev/null | python3 -c "
import json,sys
print('NORMAL' if any(c.get('state')=='CHANNELD_NORMAL' for c in json.load(sys.stdin).get('channels',[])) else 'NO')" 2>/dev/null)
    [ "$ST" = "NORMAL" ] && break
    sleep 1
done
[ "$ST" = "NORMAL" ] || die "LN channel never reached NORMAL"
green "  ok: real LN channel NORMAL (CLN2 <-> CLN1)"

FAIL=0
BASE=$(cln2_spendable)
info "CLN2 spendable baseline: $BASE msat"

# --- Step 7: INBOUND shallow — CLN2 pays factory client 0 (600k msat) ---
info "INBOUND(shallow): invoice for client 0, 600000 msat"
echo "invoice 0 600000" > "$LSP_FIFO"; sleep 3
B11=""
for i in $(seq 1 30); do
    B11=$($CLI1 listinvoices | python3 -c "
import json,sys
for inv in json.load(sys.stdin).get('invoices', []):
    if inv.get('label','').startswith('superscalar-') and inv.get('status')=='unpaid' and int(inv.get('amount_msat',0))==600000:
        print(inv.get('bolt11','')); break" 2>/dev/null)
    [ -n "$B11" ] && break; sleep 1
done
if [ -z "$B11" ]; then red "  FAIL: no 600k invoice appeared on CLN1"; FAIL=1
else
    R=$($CLI2 pay "$B11" 2>&1) || true
    OK=$(echo "$R" | python3 -c "import json,sys
try: print('y' if json.load(sys.stdin).get('status')=='complete' else 'n')
except: print('n')")
    if [ "$OK" = "y" ]; then green "  ok: inbound to client 0 complete"
    else red "  FAIL: inbound(shallow) pay: $R"; FAIL=1; fi
fi

# --- Step 8: INBOUND deep — CLN2 pays factory client $DEEP_CLIENT (500k msat) ---
info "INBOUND(deep): invoice for client $DEEP_CLIENT, 500000 msat"
echo "invoice $DEEP_CLIENT 500000" > "$LSP_FIFO"; sleep 3
B11D=""
for i in $(seq 1 30); do
    B11D=$($CLI1 listinvoices | python3 -c "
import json,sys
for inv in json.load(sys.stdin).get('invoices', []):
    if inv.get('label','').startswith('superscalar-') and inv.get('status')=='unpaid' and int(inv.get('amount_msat',0))==500000:
        print(inv.get('bolt11','')); break" 2>/dev/null)
    [ -n "$B11D" ] && break; sleep 1
done
if [ -z "$B11D" ]; then red "  FAIL: no 500k invoice appeared on CLN1 (deep client)"; FAIL=1
else
    R=$($CLI2 pay "$B11D" 2>&1) || true
    OK=$(echo "$R" | python3 -c "import json,sys
try: print('y' if json.load(sys.stdin).get('status')=='complete' else 'n')
except: print('n')")
    if [ "$OK" = "y" ]; then green "  ok: inbound to client $DEEP_CLIENT complete (high-index routing)"
    else red "  FAIL: inbound(deep) pay: $R"; FAIL=1; fi
fi

MID=$(cln2_spendable)
SPENT=$(( BASE - MID ))
if [ "$SPENT" -ge 1100000 ]; then
    green "  ok: CLN2 spent $SPENT msat (>= 1.1M inbound total, real sats left the external node)"
else
    red "  FAIL: CLN2 only spent $SPENT msat (expected >= 1100000)"; FAIL=1
fi

# --- Step 9: OUTBOUND — factory client 0 pays a real CLN2 invoice (400k msat) ---
info "OUTBOUND: client 0 pays CLN2 invoice 400000 msat"
OUT_LABEL="n127-out-$$"
OUT_INV=$($CLI2 invoice 400000 "$OUT_LABEL" "factory->external at N=127" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('bolt11',''))")
[ -n "$OUT_INV" ] || { red "  FAIL: CLN2 invoice creation"; FAIL=1; }
if [ -n "$OUT_INV" ]; then
    echo "pay_external 0 $OUT_INV" > "$LSP_FIFO"
    OUT_PAID=n
    for i in $(seq 1 60); do
        OUT_PAID=$($CLI2 listinvoices "$OUT_LABEL" 2>/dev/null | python3 -c "
import json,sys
invs=json.load(sys.stdin).get('invoices',[])
print('y' if invs and invs[0].get('status')=='paid' else 'n')" 2>/dev/null)
        [ "$OUT_PAID" = "y" ] && break; sleep 1
    done
    if [ "$OUT_PAID" = "y" ]; then green "  ok: outbound settled (CLN2 invoice paid by factory client)"
    else red "  FAIL: outbound never settled"; FAIL=1; fi
fi

END=$(cln2_spendable)
GAIN=$(( END - MID ))
if [ "$GAIN" -ge 396000 ]; then
    green "  ok: CLN2 gained $GAIN msat on the outbound leg (~400k)"
else
    red "  FAIL: CLN2 outbound gain only $GAIN msat"; FAIL=1
fi

# --- Step 10: factory health after real-LN traffic ---
kill -0 $LSP_PID 2>/dev/null && green "  ok: LSP still in daemon mode" || { red "  FAIL: LSP died"; FAIL=1; }
if grep -q "CONSERVATION VIOLATION\|refusing new HTLCs" "$LSP_LOG"; then
    red "  FAIL: conservation alert fired during bridge traffic"; FAIL=1
else
    green "  ok: no conservation alert"
fi
if grep -qE "initiating force-close|force-close broadcast|broadcasting force" "$LSP_LOG"; then
    red "  FAIL: force-close initiated during bridge traffic"; FAIL=1
else
    green "  ok: no force-close initiated"
fi

if [ "$FAIL" -eq 0 ]; then
    green "PASS: N=$N_CLIENTS factory exchanged real LN payments with an external vanilla CLN node (inbound shallow+deep, outbound, economic deltas verified)."
    exit 0
else
    red "FAIL: see assertions; logs preserved at /tmp/bridge_n127_last_*.log"
    tail -20 "$TMPDIR/bridge.log" 2>/dev/null
    exit 1
fi
