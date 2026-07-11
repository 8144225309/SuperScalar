#!/usr/bin/env bash
# exhibition_jit_signet.sh — JIT channel creation on REAL signet via --test-jit.
# The LSP funds a 2-of-2 (LSP+client) JIT channel from its wallet (sendtoaddress),
# confirms at signet 3-conf depth, then the channel is OPEN. Strong keys, unique tag.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"; CLIENT_BIN="$BUILD_DIR/superscalar_client"
N_CLIENTS="${N_CLIENTS:-2}"; ARITY="${ARITY:-2}"; AMOUNT="${AMOUNT:-300000}"; FEE_RATE="${FEE_RATE:-1000}"
JIT_AMOUNT="${JIT_AMOUNT:-50000}"
LSP_PORT="${LSP_PORT:-29974}"; WALLET="${WALLET:-ss_sig_n127}"
CONFIRM_TIMEOUT="${CONFIRM_TIMEOUT:-36000}"
TAG="${TAG:-JitExhib}"
SIGNET_CONF="${SIGNET_CONF:-/var/lib/bitcoind-signet/bitcoin.conf}"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF")
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF")
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF"); RPORT=${RPORT:-38332}
BCLI="bitcoin-cli -signet -rpcuser=$RU -rpcpassword=$RP -rpcport=$RPORT"
ts(){ date -u +%H:%M:%S; }
info(){ printf '[JIT] %s\n' "$*" >&2; }

eval "$(python3 "$SCRIPT_DIR/signet_strong_keygen.py" "$N_CLIENTS" "$TAG")"
mapfile -t CKEYS < "$CLIENT_KEYS_FILE"
# protect the seed immediately (unique-tag lesson): keep a copy the harness won't overwrite
cp -n "$RUN_SEED_FILE" "/tmp/ss_seed_${TAG}_keep.txt" 2>/dev/null || true
cp -n "$CLIENT_KEYS_FILE" "/tmp/ss_clientkeys_${TAG}_keep.txt" 2>/dev/null || true
TMPDIR=$(mktemp -d /tmp/ss-signet-jit.XXXXXX); LSP_DB="$TMPDIR/lsp.db"; LSP_LOG="$TMPDIR/lsp.log"
PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null||true; done; cp "$LSP_LOG" /tmp/Jit_lsp.log 2>/dev/null||true; }
trap cleanup EXIT

$BCLI loadwallet "$WALLET" 2>/dev/null || true
echo "=== SIGNET JIT: N=$N_CLIENTS arity=$ARITY jit_amount=$JIT_AMOUNT fee=$FEE_RATE tag=$TAG ===" >&2
info "[$(ts)] strong keys (LSP ${LSP_PUBKEY:0:16}..., seed $RUN_SEED_FILE, kept /tmp/ss_seed_${TAG}_keep.txt)"
pkill -9 -f "superscalar_lsp.*--port $LSP_PORT" 2>/dev/null || true; sleep 1

"$LSP_BIN" --network signet --cli-path bitcoin-cli --rpcuser "$RU" --rpcpassword "$RP" \
    --port $LSP_PORT --clients $N_CLIENTS --arity $ARITY \
    --states-per-layer 2 --static-near-root 1 --active-blocks 6 --dying-blocks 6 \
    --amount $AMOUNT --fee-rate $FEE_RATE --lsp-balance-pct 50 \
    --jit-amount $JIT_AMOUNT \
    --confirm-timeout $CONFIRM_TIMEOUT --seckey "$LSP_SECKEY" --wallet "$WALLET" \
    --db "$LSP_DB" --demo --test-jit > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 180); do sleep 2; grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && { info "[$(ts)] LSP listening + self-funding"; break; }; kill -0 $LSP_PID 2>/dev/null || { tail -30 "$LSP_LOG" >&2; echo "FAIL: LSP died before listening"; exit 1; }; done

for i in $(seq 0 $((N_CLIENTS-1))); do
    "$CLIENT_BIN" --network signet --cli-path bitcoin-cli --rpcuser "$RU" --rpcpassword "$RP" \
        --host 127.0.0.1 --port $LSP_PORT --seckey "${CKEYS[$i]}" --fee-rate $FEE_RATE \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id $((i+1)) --daemon --auto-accept-jit --wallet "$WALLET" \
        --db "$TMPDIR/client_${i}.db" > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!); sleep 1
done

info "[$(ts)] factory building; --test-jit will run jit_channel_create for client 0; JIT funding confirms at 3 blocks..."
JIT_TXID=""; deadline=$((CONFIRM_TIMEOUT/10))
for i in $(seq 1 "$deadline"); do
    sleep 10
    t=$(grep -a 'JIT channel OPEN' "$LSP_LOG" 2>/dev/null | grep -oE 'funding=[0-9a-f]{64}' | grep -oE '[0-9a-f]{64}' | head -1)
    [ -n "$t" ] && { JIT_TXID="$t"; break; }
    if ! kill -0 $LSP_PID 2>/dev/null; then info "[$(ts)] LSP exited; final scan"; t=$(grep -a 'JIT channel OPEN' "$LSP_LOG" 2>/dev/null | grep -oE 'funding=[0-9a-f]{64}' | grep -oE '[0-9a-f]{64}' | head -1); [ -n "$t" ] && JIT_TXID="$t"; break; fi
    [ $((i % 6)) -eq 0 ] && info "  [$(ts)] waiting for JIT (height $($BCLI getblockcount 2>/dev/null))..."
done

[ -n "$JIT_TXID" ] || { echo "FAIL: no JIT channel OPEN seen"; echo "--- LSP log tail ---" >&2; tail -40 "$LSP_LOG" >&2; exit 1; }
raw=$($BCLI getrawtransaction "$JIT_TXID" true 2>/dev/null || true)
conf=$(echo "$raw" | grep -oE '"confirmations": *[0-9]+' | grep -oE '[0-9]+' | head -1)
vsize=$(echo "$raw" | grep -oE '"vsize": *[0-9]+' | grep -oE '[0-9]+' | head -1)
echo "[$(ts)] JIT CHANNEL FUNDING on signet: $JIT_TXID (conf=${conf:-0}, vsize=${vsize:-?}, amount=$JIT_AMOUNT)" >&2
echo "EXHIB_JIT_DONE $JIT_TXID"
