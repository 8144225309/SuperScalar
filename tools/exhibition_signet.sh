#!/usr/bin/env bash
# exhibition_signet.sh — REALISTIC SuperScalar signet exhibition (Delving post exhibits).
#
# The realistic economic model (NO shortcuts):
#   * NO --lsp-balance-pct  -> the LSP holds ALL channel liquidity; clients start at ~0.
#   * NO --demo --payments  -> no internal sat-shuffling among nodes.
#   * Clients earn balance ONLY via REAL inbound LN payments from a non-bLIP56 (vanilla)
#     CLN node routed through the bridge; they spend it back OUT the same way.
#   * Strong per-run keys (signet_strong_keygen.py) -> funds recoverable, never weak-sweepable.
#
# Drives the LSP FIFO CLI (lsp_channels.c): invoice / pay / buy_liquidity / pay_external / close.
# Keeps a MANIFEST (txid | role | height | vbytes) for the walkthrough page.
#
# Usage: bash tools/exhibition_signet.sh
# Env:
#   N_CLIENTS (default 4)   ARITY (default 2)   AMOUNT total sats (default 2000000)
#   FEE_RATE  sat/kvB (default 100 = 0.1 sat/vB; harness retries 1000 = 1 sat/vB if funding rejected)
#   SOAK_SECONDS (default 0)   VANILLA_DIR (default /var/lib/cln-signet-c)
#   MOVES (default 6)   SKIP_CLOSE (default 0)   TAG (default exhib_<N>_<pid>)
set -uo pipefail

N_CLIENTS="${N_CLIENTS:-4}"
ARITY="${ARITY:-2}"
AMOUNT="${AMOUNT:-2000000}"
FEE_RATE="${FEE_RATE:-100}"          # 100 sat/kvB = 0.1 sat/vB
SOAK_SECONDS="${SOAK_SECONDS:-0}"
MOVES="${MOVES:-6}"
SKIP_CLOSE="${SKIP_CLOSE:-0}"
WALLET="${WALLET:-ss_sig_n127}"
VANILLA_DIR="${VANILLA_DIR:-/var/lib/cln-signet-c}"
PLUGIN_DIR="${PLUGIN_DIR:-/var/lib/cln-signet}"
BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"
TAG="${TAG:-exhib_${N_CLIENTS}_$$}"
PORT="${PORT:-29940}"
BRIDGE_PORT="${BRIDGE_PORT:-29941}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
BRIDGE_BIN="$BUILD_DIR/superscalar_bridge"
SS_PLUGIN="${SS_PLUGIN:-$PROJECT_DIR/tools/cln_plugin.py}"

SIGNET_CONF="/var/lib/bitcoind-signet/bitcoin.conf"
BCLI="bitcoin-cli -conf=$SIGNET_CONF"
: "${SIGNET_RPCPASS:=$(sed -n 's/^rpcpassword=//p' "$SIGNET_CONF" 2>/dev/null)}"
LCLI_PLUGIN="lightning-cli --network=signet --lightning-dir=$PLUGIN_DIR"
LCLI_VANILLA="lightning-cli --network=signet --lightning-dir=$VANILLA_DIR"

WORKDIR="/tmp/${TAG}"
mkdir -p "$WORKDIR"
LSP_DB="$WORKDIR/lsp.db"
LSP_LOG="$WORKDIR/lsp.log"
BRIDGE_LOG="$WORKDIR/bridge.log"
MANIFEST="$WORKDIR/manifest.tsv"
: > "$MANIFEST"
LSP_FIFO="$WORKDIR/lsp_cmd"

info(){ printf '\033[36m[exhib]\033[0m %s\n' "$*"; }
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
red(){ printf '\033[31m%s\033[0m\n' "$*"; }

PIDS=()
cleanup(){
    set +e
    $LCLI_PLUGIN plugin stop "$SS_PLUGIN" 2>/dev/null
    [ -n "${FIFO_HOLDER_PID:-}" ] && kill "$FIFO_HOLDER_PID" 2>/dev/null
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null; done
    cp "$LSP_LOG" "/tmp/${TAG}_lsp.log" 2>/dev/null
    cp "$MANIFEST" "/tmp/${TAG}_manifest.tsv" 2>/dev/null
    info "preserved: /tmp/${TAG}_lsp.log , /tmp/${TAG}_manifest.tsv , seed: ${RUN_SEED_FILE:-?}"
}
trap cleanup EXIT

cli(){ echo "$*" > "$LSP_FIFO"; info "CLI> $*"; }

# Record a txid to the manifest with role, resolving height + vbytes from the node.
manifest_add(){  # $1=txid $2=role
    local txid="$1" role="$2" h vb
    [ -z "$txid" ] && return
    local raw; raw=$($BCLI getrawtransaction "$txid" 1 2>/dev/null)
    h=$(echo "$raw" | python3 -c "import sys,json
try: d=json.load(sys.stdin); bh=d.get('blockhash'); print(d.get('confirmations',0))
except: print('?')" 2>/dev/null)
    vb=$(echo "$raw" | python3 -c "import sys,json
try: print(json.load(sys.stdin).get('vsize','?'))
except: print('?')" 2>/dev/null)
    printf '%s\t%s\t%s\t%s\n' "$txid" "$role" "${h:-?}" "${vb:-?}" >> "$MANIFEST"
    info "manifest += $role $txid (vsize=${vb:-?})"
}

echo "=========================================================="
echo " SuperScalar REALISTIC signet exhibition"
echo " N=$N_CLIENTS arity=$ARITY amount=$AMOUNT fee=$FEE_RATE sat/kvB soak=${SOAK_SECONDS}s"
echo " vanilla peer: $VANILLA_DIR   wallet: $WALLET   tag: $TAG"
echo "=========================================================="

# ---- Sanity ----
$BCLI getblockcount >/dev/null || { red "signet bitcoind unreachable"; exit 1; }
$LCLI_PLUGIN getinfo >/dev/null || { red "plugin CLN down"; exit 1; }
$LCLI_VANILLA getinfo >/dev/null || { red "vanilla CLN down"; exit 1; }
PLUGIN_ID=$($LCLI_PLUGIN getinfo | python3 -c "import json,sys;print(json.load(sys.stdin)['id'])")
info "plugin CLN $PLUGIN_ID ; vanilla $VANILLA_DIR"

# ---- Strong per-run keys ----
eval "$(SIGNET_CONF="$SIGNET_CONF" python3 "$SCRIPT_DIR/signet_strong_keygen.py" "$N_CLIENTS" "$TAG")"
[ -n "${LSP_PUBKEY:-}" ] && [ -s "${CLIENT_KEYS_FILE:-/nonexistent}" ] || { red "keygen failed"; exit 1; }
info "strong keys ok (LSP pub ${LSP_PUBKEY:0:16}..., seed $RUN_SEED_FILE)"

$BCLI loadwallet "$WALLET" 2>/dev/null || true
BAL=$($BCLI -rpcwallet="$WALLET" getbalance)
info "funding wallet $WALLET balance: $BAL BTC"

# ---- Launch LSP (daemon+cli, NO --lsp-balance-pct, NO --demo) ----
mkfifo "$LSP_FIFO"; sleep infinity > "$LSP_FIFO" & FIFO_HOLDER_PID=$!
launch_lsp(){  # $1 = fee rate
  stdbuf -oL "$LSP_BIN" --daemon --cli --clnbridge \
    --network signet --port "$PORT" \
    --clients "$N_CLIENTS" --arity "$ARITY" --amount "$AMOUNT" \
    --active-blocks 500 --dying-blocks 100 --step-blocks 5 --states-per-layer 2 \
    --fee-rate "$1" --confirm-timeout 86400 \
    --max-conn-rate 400 --max-handshakes 80 \
    --seckey "$LSP_SECKEY" \
    --rpcuser signetrpc --rpcpassword "$SIGNET_RPCPASS" --rpcport 38332 \
    --wallet "$WALLET" --db "$LSP_DB" \
    < "$LSP_FIFO" > "$LSP_LOG" 2>&1 &
  LSP_PID=$!; PIDS+=("$LSP_PID")
}
info "launching LSP at fee $FEE_RATE sat/kvB (0.1 sat/vB)..."
launch_lsp "$FEE_RATE"
for i in $(seq 1 60); do grep -q "listening on port $PORT" "$LSP_LOG" 2>/dev/null && break
  kill -0 $LSP_PID 2>/dev/null || { red "LSP died"; tail -20 "$LSP_LOG"; exit 1; }; sleep 1; done

# ---- Launch clients (all idle --daemon, strong keys, staggered) ----
info "launching $N_CLIENTS client daemons..."
for i in $(seq 1 "$N_CLIENTS"); do
  SK=$(sed -n "${i}p" "$CLIENT_KEYS_FILE")
  stdbuf -oL "$CLIENT_BIN" --network signet --host 127.0.0.1 --port "$PORT" \
    --seckey "$SK" --fee-rate "$FEE_RATE" --lsp-pubkey "$LSP_PUBKEY" \
    --participant-id "$i" --daemon \
    --rpcuser signetrpc --rpcpassword "$SIGNET_RPCPASS" --rpcport 38332 \
    --wallet "$WALLET" --db "$WORKDIR/c${SK:0:8}.db" \
    > "$WORKDIR/c${i}.log" 2>&1 &
  PIDS+=("$!"); sleep 0.2
done

# ---- Wait for factory funding to confirm on signet ----
info "waiting for factory funding + daemon mode (signet ~10 min/block)..."
FUNDED=0
for i in $(seq 1 720); do   # 2h budget
  grep -q "entering daemon mode\|event loop" "$LSP_LOG" 2>/dev/null && { FUNDED=1; break; }
  kill -0 $LSP_PID 2>/dev/null || break
  # detect a min-relay-fee rejection -> relaunch at 1 sat/vB
  if grep -qiE "min relay fee not met|min-relay|mempool min fee" "$LSP_LOG" 2>/dev/null && [ "$FEE_RATE" = "100" ]; then
      red "0.1 sat/vB rejected by mempool floor -> relaunching at 1 sat/vB"
      kill -9 $LSP_PID 2>/dev/null; FEE_RATE=1000; launch_lsp 1000
      for j in $(seq 1 60); do grep -q "listening on port $PORT" "$LSP_LOG" 2>/dev/null && break; sleep 1; done
  fi
  sleep 10; [ $((i % 6)) -eq 0 ] && info "  ...funding wait $((i/6)) min"
done
[ "$FUNDED" = 1 ] || { red "LSP never reached daemon mode"; tail -30 "$LSP_LOG"; exit 1; }
green "factory active (N=$N_CLIENTS)"
FUND_TXID=$(sqlite3 "$LSP_DB" "SELECT txid FROM broadcast_log WHERE source LIKE '%funding%' OR source LIKE '%kickoff%' ORDER BY id LIMIT 1;" 2>/dev/null)
manifest_add "$FUND_TXID" "factory_funding"

# ---- Start bridge + load SS plugin ----
stdbuf -oL "$BRIDGE_BIN" --lsp-host 127.0.0.1 --lsp-port "$PORT" \
  --plugin-port "$BRIDGE_PORT" --lsp-pubkey "$LSP_PUBKEY" > "$BRIDGE_LOG" 2>&1 &
PIDS+=("$!")
for i in $(seq 1 30); do grep -q "connected to LSP" "$BRIDGE_LOG" 2>/dev/null && break; sleep 1; done
$LCLI_PLUGIN plugin stop "$SS_PLUGIN" 2>/dev/null || true; sleep 1
$LCLI_PLUGIN -k plugin subcommand=start plugin="$SS_PLUGIN" superscalar-bridge-port="$BRIDGE_PORT" 2>/dev/null || true
sleep 3
info "bridge up; plugin loaded"

# ---- Choreography: REAL inbound / client-to-client / liquidity sale / outbound ----
# get_bolt11 <client_idx> <msat> -> prints an SS invoice bolt11 (via the plugin registry)
get_bolt11(){
  cli "invoice $1 $2"; sleep 3
  for i in $(seq 1 30); do
    B=$($LCLI_PLUGIN listinvoices 2>/dev/null | python3 -c "import json,sys
for inv in json.load(sys.stdin).get('invoices',[]):
    if inv.get('label','').startswith('superscalar-') and inv.get('status')=='unpaid':
        print(inv.get('bolt11','')); break")
    [ -n "$B" ] && { echo "$B"; return 0; }; sleep 1
  done; return 1
}
pay_in(){  # $1 client $2 SATS  (vanilla pays -> client earns balance)
  local msat=$(( $2 * 1000 ))
  local b; b=$(get_bolt11 "$1" "$msat") || { red "no invoice for c$1"; return 1; }
  info "INBOUND: vanilla pays $2 sat -> client $1"
  $LCLI_VANILLA pay "$b" > "$WORKDIR/payin_${1}.json" 2>&1 && green "  in ok" || { red "  in FAILED:"; head -c 320 "$WORKDIR/payin_${1}.json" | tr "\n" " "; echo; }
}
pay_out(){  # $1 client $2 SATS  (client -> vanilla)
  local msat=$(( $2 * 1000 ))
  local inv; inv=$($LCLI_VANILLA invoice "$msat" "out-${TAG}-$RANDOM" "SS out" 2>/dev/null | python3 -c "import json,sys;print(json.load(sys.stdin).get('bolt11',''))")
  [ -z "$inv" ] && { red "vanilla invoice failed"; return 1; }
  info "OUTBOUND: client $1 pays $2 sat -> vanilla"
  cli "pay_external $1 $inv"; sleep 8
}

info "=== choreography (big+small; inbound capped by the ~490k-sat vanilla->plugin channel) ==="
# Seed a few clients with real inbound so they have balance to move (fits the ~490k channel).
pay_in 0 200000; sleep 5
pay_in 1 100000; sleep 5
[ "$N_CLIENTS" -gt 2 ] && { pay_in 2 50000; sleep 5; }
# Liquidity sale (client buys inbound from L-stock).
cli "buy_liquidity 1 30000"; sleep 4
# Client-to-client real HTLCs, big + small.
cli "pay 0 1 30000"; sleep 4
cli "pay 1 0 5000";  sleep 4
[ "$N_CLIENTS" -gt 2 ] && { cli "pay 0 2 15000"; sleep 4; }
# Outbound (client spends back to the outside world; refills the vanilla->plugin channel).
pay_out 0 80000
cli "status"; sleep 3

# ---- Soak ----
if [ "$SOAK_SECONDS" -gt 0 ]; then
  info "soaking ${SOAK_SECONDS}s with periodic activity..."
  SOAK_END=$(( $(date +%s) + SOAK_SECONDS ))
  r=0
  while [ "$(date +%s)" -lt "$SOAK_END" ]; do
    r=$((r+1))
    pay_in $((r % N_CLIENTS)) $(( (RANDOM % 40000) + 5000 )); sleep 30
    cli "pay $((r % N_CLIENTS)) $(((r+1) % N_CLIENTS)) $(( (RANDOM % 4000) + 500 ))"; sleep 30
    pay_out $((r % N_CLIENTS)) $(( (RANDOM % 30000) + 3000 )); sleep 30
    [ $((r % 10)) -eq 0 ] && cli "status"
    sleep 120
  done
fi

# ---- Cooperative close ----
if [ "$SKIP_CLOSE" = "1" ]; then green "SKIP_CLOSE=1 — factory left open ($TAG)"; exit 0; fi
info "cooperative close..."
cli "close"
for i in $(seq 1 360); do
  CLOSE_TXID=$(sqlite3 "$LSP_DB" "SELECT txid FROM broadcast_log WHERE source LIKE '%close%' ORDER BY id DESC LIMIT 1;" 2>/dev/null)
  [ -n "$CLOSE_TXID" ] && break; sleep 5
done
manifest_add "$CLOSE_TXID" "cooperative_close"
info "waiting for close confirmation..."
for i in $(seq 1 360); do
  C=$($BCLI getrawtransaction "$CLOSE_TXID" 1 2>/dev/null | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('confirmations',0))
except: print(0)" 2>/dev/null)
  [ "${C:-0}" -ge 1 ] 2>/dev/null && { green "close confirmed: $CLOSE_TXID ($C confs)"; break; }
  sleep 10; [ $((i % 6)) -eq 0 ] && info "  ...close wait $((i/6)) min"
done
manifest_add "$CLOSE_TXID" "cooperative_close_confirmed"

echo "=== MANIFEST ($TAG) ==="; column -t "$MANIFEST" 2>/dev/null || cat "$MANIFEST"
green "=== exhibition run complete: $TAG ==="
