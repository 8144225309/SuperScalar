#!/usr/bin/env bash
# test_signet_n127_bridge.sh — THE capstone: 127-client factory on PUBLIC
# SIGNET exchanging real Lightning payments with an external vanilla CLN node.
#
# Same legs as test_regtest_n127_bridge.sh (inbound client 0 600k msat,
# inbound DEEP client 100 700k msat, outbound client 0 -> external 400k msat,
# hard msat-delta assertions on the external node) but on the real public
# signet chain with the persistent CLN pair:
#   /var/lib/cln-signet-c  = plugin node (bridge side)
#   /var/lib/cln-signet-d  = vanilla external node
# which already share a healthy bidirectional LN channel (no new open needed).
#
# REQUIRED env (from tools/signet_strong_keygen.py <N> <TAG> — NEVER weak keys
# on public signet): LSP_SECKEY, LSP_PUBKEY, CLIENT_KEYS_FILE (line i = client
# i seckey), RUN_SEED_FILE saved for post-run sweep.
#
# The LSP is shut down GRACEFULLY at the end so it cooperatively closes the
# factory; the close pays the LSP's raw-taproot key, recoverable with the
# strong seckey (rawtr(WIF) import + sendall — see signet sweep method).
#
# Usage: bash tools/test_signet_n127_bridge.sh [BUILD_DIR]
set -uo pipefail
HOME="${HOME:-/root}"

BUILD_DIR="${1:-/root/ss-p6-main/build}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
BRIDGE_BIN="$BUILD_DIR/superscalar_bridge"
PLUGIN_PY="$PROJECT_DIR/tools/cln_plugin.py"

SIGNET_CONF="${SIGNET_CONF:-/var/lib/bitcoind-signet/bitcoin.conf}"
BCLI="bitcoin-cli -signet -conf=$SIGNET_CONF"
RPCUSER="${RPCUSER:-signetrpc}"
RPCPASS="${RPCPASS:-signetrpcpass123}"
RPCPORT="${RPCPORT:-38332}"

: "${LSP_SECKEY:?run signet_strong_keygen.py first}"
: "${LSP_PUBKEY:?run signet_strong_keygen.py first}"
: "${CLIENT_KEYS_FILE:?run signet_strong_keygen.py first}"

N_CLIENTS="${N_CLIENTS:-127}"
DEEP_CLIENT="${DEEP_CLIENT:-100}"
ARITY="${ARITY:-2,4,8}"
AMOUNT="${AMOUNT:-$(( N_CLIENTS * 100000 ))}"
FEE_RATE="${FEE_RATE:-1000}"
PORT="${PORT:-29935}"
BRIDGE_PLUGIN_PORT="${BRIDGE_PLUGIN_PORT:-29736}"
LSP_WALLET="${LSP_WALLET:-ss_sig_n127}"
PLUGIN_CLN_DIR="${PLUGIN_CLN_DIR:-/var/lib/cln-signet-c}"
VANILLA_DIR="${VANILLA_DIR:-/var/lib/cln-signet-d}"
TAG="signet_n127_bridge"
TMPDIR=$(mktemp -d /tmp/ss-sig-n127.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"
LSP_FIFO="$TMPDIR/lsp_cmd"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m[sig-n127]\033[0m %s\n' "$*"; }

CLI1="lightning-cli --network=signet --lightning-dir=$PLUGIN_CLN_DIR"
CLI2="lightning-cli --network=signet --lightning-dir=$VANILLA_DIR"

cleanup() {
    echo "=== Cleaning up (graceful LSP close first) ==="
    kill "${FIFO_HOLDER_PID:-}" 2>/dev/null || true
    # Graceful LSP shutdown -> cooperative close broadcast (recoverable payout)
    if [ -n "${LSP_PID:-}" ] && kill -0 "$LSP_PID" 2>/dev/null; then
        kill -TERM "$LSP_PID" 2>/dev/null
        for i in $(seq 1 45); do kill -0 "$LSP_PID" 2>/dev/null || break; sleep 1; done
    fi
    pkill -9 -f "superscalar_client.*$PORT" 2>/dev/null || true
    kill -9 "${BRIDGE_PID:-}" "${LSP_PID:-}" 2>/dev/null || true
    $CLI1 -k plugin subcommand=stop plugin="$PLUGIN_PY" 2>/dev/null || true
    cp "$LSP_LOG" /tmp/sig_n127_last_lsp.log 2>/dev/null || true
    cp "$TMPDIR/bridge.log" /tmp/sig_n127_last_bridge.log 2>/dev/null || true
    cp "$LSP_DB" /tmp/sig_n127_last_lsp.db 2>/dev/null || true
    grep -aE "funding tx|cooperative close|close.*txid|SUCCESS" "$LSP_LOG" 2>/dev/null | tail -6
    rm -rf "$TMPDIR"
    echo "=== Cleanup complete (logs at /tmp/sig_n127_last_*) ==="
}
trap cleanup EXIT
die() { red "FAIL: $*"; tail -25 "$LSP_LOG" 2>/dev/null; exit 1; }

cln2_spendable() {
    $CLI2 listpeerchannels 2>/dev/null | python3 -c "
import json,sys
d = json.load(sys.stdin)
print(sum(int(c.get('spendable_msat', 0)) for c in d.get('channels', [])))" 2>/dev/null || echo 0
}

echo "=== PUBLIC SIGNET: N=$N_CLIENTS factory x real-LN bridge interop ==="
echo "  amount=$AMOUNT wallet=$LSP_WALLET deep=$DEEP_CLIENT tip=$($BCLI getblockcount)"
for bin in "$LSP_BIN" "$CLIENT_BIN" "$BRIDGE_BIN"; do [ -x "$bin" ] || die "$bin missing"; done
[ -f "$PLUGIN_PY" ] || die "plugin missing"
[ "$(wc -l < "$CLIENT_KEYS_FILE")" -ge "$N_CLIENTS" ] || die "keyfile has fewer than $N_CLIENTS keys"

BAL=$($BCLI -rpcwallet="$LSP_WALLET" getbalance 2>/dev/null || echo 0)
info "LSP wallet $LSP_WALLET balance: $BAL BTC (need ~0.13)"
python3 -c "import sys; sys.exit(0 if float('$BAL') >= 0.14 else 1)" || die "insufficient signet balance"

# CLN pair sanity: existing channel NORMAL with spendable liquidity
ST=$($CLI2 listpeerchannels | python3 -c "
import json,sys
print('NORMAL' if any(c.get('state')=='CHANNELD_NORMAL' for c in json.load(sys.stdin).get('channels',[])) else 'NO')")
[ "$ST" = "NORMAL" ] || die "persistent CLN pair channel not NORMAL"
green "  ok: persistent CLN pair channel NORMAL"

# --- LSP (127 clients) with CLI FIFO ---
mkfifo "$LSP_FIFO"; sleep infinity > "$LSP_FIFO" & FIFO_HOLDER_PID=$!
info "starting LSP on signet (:$PORT), funding from $LSP_WALLET"
stdbuf -oL "$LSP_BIN" \
    --daemon --cli --network signet --port "$PORT" \
    --seckey "$LSP_SECKEY" --clients "$N_CLIENTS" --arity "$ARITY" \
    --static-near-root 1 --amount "$AMOUNT" \
    --active-blocks 500 \
    --step-blocks 5 --states-per-layer 2 \
    --fee-rate "$FEE_RATE" --lsp-balance-pct 50 \
    --confirm-timeout 14400 \
    --max-conn-rate 400 --max-handshakes 80 \
    --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
    --wallet "$LSP_WALLET" --db "$LSP_DB" \
    < "$LSP_FIFO" > "$LSP_LOG" 2>&1 &
LSP_PID=$!
for i in $(seq 1 60); do
    grep -q "listening on port $PORT" "$LSP_LOG" 2>/dev/null && break
    kill -0 $LSP_PID 2>/dev/null || die "LSP died at startup"
    sleep 1
done
grep -q "listening on port $PORT" "$LSP_LOG" || die "LSP never listened"

info "launching $N_CLIENTS client daemons (strong keys, participant ids)"
i=0
while IFS= read -r SK && [ "$i" -lt "$N_CLIENTS" ]; do
    i=$((i + 1))
    nohup "$CLIENT_BIN" \
        --network signet --host 127.0.0.1 --port "$PORT" \
        --seckey "$SK" --fee-rate "$FEE_RATE" --lsp-balance-pct 50 \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id "$i" \
        --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
        --db "$TMPDIR/c$(printf '%03d' "$i").db" \
        --daemon \
        > "$TMPDIR/c$(printf '%03d' "$i").log" 2>&1 &
    sleep 0.2
done < "$CLIENT_KEYS_FILE"
info "$i clients launched; waiting for funding conf + daemon mode (real signet blocks, up to 90 min)"

DAEMON_OK=0
for attempt in $(seq 1 5400); do
    kill -0 $LSP_PID 2>/dev/null || die "LSP exited during factory creation"
    if grep -q "entering daemon mode" "$LSP_LOG" 2>/dev/null; then DAEMON_OK=1; break; fi
    sleep 1
done
[ "$DAEMON_OK" = "1" ] || die "factory creation did not complete in 90 min"
FUND_TXID=$(grep -aoE "funding tx(id)?[: ]+[0-9a-f]{64}" "$LSP_LOG" | grep -oE "[0-9a-f]{64}" | head -1)
green "  ok: factory live on PUBLIC SIGNET with $N_CLIENTS clients (funding ${FUND_TXID:-see-log})"

# --- bridge + dynamic plugin ---
stdbuf -oL "$BRIDGE_BIN" \
    --lsp-host 127.0.0.1 --lsp-port "$PORT" \
    --plugin-port "$BRIDGE_PLUGIN_PORT" --lsp-pubkey "$LSP_PUBKEY" \
    > "$TMPDIR/bridge.log" 2>&1 &
BRIDGE_PID=$!
# A signet LSP with 127 clients + chain RPC polling handshakes slowly; the
# original 30s window killed run 1 mid-handshake.
for j in $(seq 1 120); do
    grep -q "connected to LSP" "$TMPDIR/bridge.log" 2>/dev/null && break
    kill -0 $BRIDGE_PID 2>/dev/null || die "bridge process exited"
    sleep 1
done
grep -q "connected to LSP" "$TMPDIR/bridge.log" || die "bridge never connected to LSP (120s)"
$CLI1 -k plugin subcommand=start plugin="$PLUGIN_PY" superscalar-bridge-port="$BRIDGE_PLUGIN_PORT" > /dev/null 2>&1 || die "plugin start"
for j in $(seq 1 90); do
    grep -q "plugin connected" "$TMPDIR/bridge.log" 2>/dev/null && break; sleep 1
done
green "  ok: bridge up (LSP + plugin on persistent signet CLN)"

FAIL=0
BASE=$(cln2_spendable)
info "external node spendable baseline: $BASE msat"

pay_leg() { # $1=client_idx $2=msat $3=tagname
    echo "invoice $1 $2" > "$LSP_FIFO"; sleep 4
    local BB=""
    for k in $(seq 1 40); do
        BB=$($CLI1 listinvoices | python3 -c "
import json,sys
for inv in json.load(sys.stdin).get('invoices', []):
    if inv.get('label','').startswith('superscalar-') and inv.get('status')=='unpaid' and int(inv.get('amount_msat',0))==$2:
        print(inv.get('bolt11','')); break" 2>/dev/null)
        [ -n "$BB" ] && break; sleep 1
    done
    if [ -z "$BB" ]; then red "  FAIL: no $2 msat invoice appeared ($3)"; FAIL=1; return; fi
    local R OK
    R=$($CLI2 pay "$BB" 2>&1) || true
    OK=$(echo "$R" | python3 -c "import json,sys
try: print('y' if json.load(sys.stdin).get('status')=='complete' else 'n')
except: print('n')")
    if [ "$OK" = "y" ]; then green "  ok: $3 complete"
    else red "  FAIL: $3: $(echo "$R" | head -3)"; FAIL=1; fi
}

info "INBOUND(shallow): external -> factory client 0, 600000 msat"
pay_leg 0 600000 "inbound client 0"
info "INBOUND(deep): external -> factory client $DEEP_CLIENT, 700000 msat"
pay_leg "$DEEP_CLIENT" 700000 "inbound client $DEEP_CLIENT (high-index)"

MID=$(cln2_spendable)
NETIN=$(( BASE - MID ))
if [ "$NETIN" -ge 1300000 ]; then
    green "  ok: external node spent $NETIN msat on the two inbound legs"
else
    red "  FAIL: external node only spent $NETIN msat (expected >= 1300000)"; FAIL=1
fi

info "OUTBOUND: factory client 0 -> external node, 400000 msat"
OUT_LABEL="sig-n127-out-$$"
OUT_INV=$($CLI2 invoice 400000 "$OUT_LABEL" "factory->external signet N=127" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('bolt11',''))")
if [ -z "$OUT_INV" ]; then red "  FAIL: external invoice creation"; FAIL=1
else
    echo "pay_external 0 $OUT_INV" > "$LSP_FIFO"
    OUT_PAID=n
    for k in $(seq 1 90); do
        OUT_PAID=$($CLI2 listinvoices "$OUT_LABEL" 2>/dev/null | python3 -c "
import json,sys
invs=json.load(sys.stdin).get('invoices',[])
print('y' if invs and invs[0].get('status')=='paid' else 'n')" 2>/dev/null)
        [ "$OUT_PAID" = "y" ] && break; sleep 1
    done
    if [ "$OUT_PAID" = "y" ]; then green "  ok: outbound settled (external invoice paid from the factory)"
    else red "  FAIL: outbound never settled"; FAIL=1; fi
fi

END=$(cln2_spendable)
NET=$(( BASE - END ))
info "external node NET outflow across all legs: $NET msat (expect ~900k = 1.3M in - 400k out + fees)"
if [ "$NET" -ge 850000 ] && [ "$NET" -le 1000000 ]; then
    green "  ok: net economics consistent"
else
    red "  FAIL: net outflow $NET msat outside [850000,1000000]"; FAIL=1
fi

kill -0 $LSP_PID 2>/dev/null && green "  ok: LSP still in daemon mode" || { red "  FAIL: LSP died"; FAIL=1; }
if grep -q "CONSERVATION VIOLATION\|refusing new HTLCs" "$LSP_LOG"; then
    red "  FAIL: conservation alert during bridge traffic"; FAIL=1
else green "  ok: no conservation alert"; fi

echo "FUNDING_TXID=$FUND_TXID"
if [ "$FAIL" -eq 0 ]; then
    green "PASS: N=$N_CLIENTS factory on PUBLIC SIGNET exchanged real LN payments with an external vanilla CLN node (inbound shallow+deep, outbound, net economics verified)."
    exit 0
else
    red "FAIL: see assertions; logs at /tmp/sig_n127_last_*"
    exit 1
fi
