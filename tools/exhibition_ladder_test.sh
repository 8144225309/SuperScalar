#!/usr/bin/env bash
# exhibition_ladder_test.sh — OFF-BRIDGE mechanics validation for the realistic
# laddered lifecycle (exhibit B). Proves, cheaply and safely (parallel with A2):
#   create -> factory auto-rotates 1-2x on a short cycle (laddering) -> clients
#   go OFFLINE -> the LSP's rotation-retry limit trips and it PROACTIVELY
#   broadcasts the pre-signed distribution TX (lsp_channels.c:7385) -> clients paid.
# Seeded balances here (--lsp-balance-pct 50) since it's off-bridge; the REAL B run
# after A2 uses the bridge + --lsp-balance-pct 100 (real earned balances).
# Strong keys, 1 sat/vB (anchors on), self-funds from WALLET.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"; CLIENT_BIN="$BUILD_DIR/superscalar_client"
N_CLIENTS="${N_CLIENTS:-4}"; ARITY="${ARITY:-2}"; AMOUNT="${AMOUNT:-600000}"; FEE_RATE="${FEE_RATE:-1000}"
LSP_PORT="${LSP_PORT:-29990}"; WALLET="${WALLET:-ss_sig_n127}"
ACTIVE_BLOCKS="${ACTIVE_BLOCKS:-4}"; DYING_BLOCKS="${DYING_BLOCKS:-2}"; LADDER_ROTATIONS="${LADDER_ROTATIONS:-2}"
CONFIRM_TIMEOUT="${CONFIRM_TIMEOUT:-36000}"
SIGNET_CONF="${SIGNET_CONF:-/var/lib/bitcoind-signet/bitcoin.conf}"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF")
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF")
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF"); RPORT=${RPORT:-38332}
BCLI="bitcoin-cli -signet -rpcuser=$RU -rpcpassword=$RP -rpcport=$RPORT"
LMAN="/tmp/exhibLadder_manifest.tsv"; : > "$LMAN"
ts(){ date -u +%H:%M:%S; }
green(){ printf '\033[32m%s\033[0m\n' "$*" >&2; }; red(){ printf '\033[31m%s\033[0m\n' "$*" >&2; }; info(){ printf '[LADDER] %s\n' "$*" >&2; }

eval "$(python3 "$SCRIPT_DIR/signet_strong_keygen.py" "$N_CLIENTS" LadderTest)"
mapfile -t CKEYS < "$CLIENT_KEYS_FILE"
TMPDIR=$(mktemp -d /tmp/ss-signet-ladder.XXXXXX); LSP_DB="$TMPDIR/lsp.db"; LSP_LOG="$TMPDIR/lsp.log"; LSP_FIFO="$TMPDIR/lsp.fifo"
LSP_PID=""; CLIENT_PIDS=()
recov(){ info "RECOVERY: funded $AMOUNT from $WALLET; seed $RUN_SEED_FILE; LSP log /tmp/Ladder_lsp.log"; }
cleanup(){ kill -9 "$LSP_PID" 2>/dev/null||true; for p in "${CLIENT_PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null||true; done; kill -9 "${FIFO_HOLDER_PID:-0}" 2>/dev/null||true; cp "$LSP_LOG" /tmp/Ladder_lsp.log 2>/dev/null||true; cp "$LMAN" /tmp/Ladder_manifest.tsv 2>/dev/null||true; }
trap cleanup EXIT

$BCLI loadwallet "$WALLET" 2>/dev/null || true
echo "=== SIGNET ladder mechanics test: N=$N_CLIENTS active=$ACTIVE_BLOCKS dying=$DYING_BLOCKS rotations~$LADDER_ROTATIONS fee=$FEE_RATE ===" >&2
info "[$(ts)] strong keys (LSP ${LSP_PUBKEY:0:16}..., seed $RUN_SEED_FILE); height $($BCLI getblockcount)"
pkill -9 -f "superscalar_lsp.*--port $LSP_PORT" 2>/dev/null || true; sleep 1
mkfifo "$LSP_FIFO"; sleep infinity > "$LSP_FIFO" & FIFO_HOLDER_PID=$!

# Daemon LSP with async rotation + SHORT active/dying so it rotates repeatedly.
stdbuf -oL "$LSP_BIN" --daemon --cli --network signet --cli-path bitcoin-cli --rpcuser "$RU" --rpcpassword "$RP" \
    --port $LSP_PORT --clients $N_CLIENTS --arity $ARITY --amount $AMOUNT \
    --active-blocks $ACTIVE_BLOCKS --dying-blocks $DYING_BLOCKS --step-blocks 1 --states-per-layer 2 --static-near-root 1 \
    --async-rotation --fee-rate $FEE_RATE --confirm-timeout $CONFIRM_TIMEOUT \
    --seckey "$LSP_SECKEY" --wallet "$WALLET" --db "$LSP_DB" --lsp-balance-pct 50 \
    < "$LSP_FIFO" > "$LSP_LOG" 2>&1 &
LSP_PID=$!
for i in $(seq 1 180); do sleep 2; grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && { info "[$(ts)] LSP listening + self-funding"; break; }; kill -0 $LSP_PID 2>/dev/null || { tail -30 "$LSP_LOG" >&2; red "FAIL: LSP died before listening"; recov; exit 1; }; done

for i in $(seq 0 $((N_CLIENTS-1))); do
    "$CLIENT_BIN" --network signet --cli-path bitcoin-cli --rpcuser "$RU" --rpcpassword "$RP" \
        --host 127.0.0.1 --port $LSP_PORT --seckey "${CKEYS[$i]}" --fee-rate $FEE_RATE \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id $((i+1)) --daemon --wallet "$WALLET" \
        --db "$TMPDIR/client_${i}.db" > "$TMPDIR/client_${i}.log" 2>&1 &
    CLIENT_PIDS+=($!); sleep 1
done

# Wait for factory creation, then span ~LADDER_ROTATIONS rotation cycles.
info "[$(ts)] waiting for factory creation..."
for i in $(seq 1 180); do grep -qaE "factory active|all .* clients connected|FACTORY_PROPOSE" "$LSP_LOG" 2>/dev/null && break; sleep 5; done
CREATE_TX=$(grep -aoE "funded [0-9]+ sats, txid: [0-9a-f]{64}" "$LSP_LOG" 2>/dev/null | grep -oE "[0-9a-f]{64}" | head -1)
[ -n "$CREATE_TX" ] && { printf '%s\tladder_factory_funding\n' "$CREATE_TX" >> "$LMAN"; info "funding: $CREATE_TX"; }

START_H=$($BCLI getblockcount)
TARGET_H=$((START_H + LADDER_ROTATIONS * (ACTIVE_BLOCKS + DYING_BLOCKS) + 2))
info "[$(ts)] letting factory rotate: height $START_H -> $TARGET_H (~$LADDER_ROTATIONS cycles)"
ROT_SEEN=0
while [ "$($BCLI getblockcount 2>/dev/null)" -lt "$TARGET_H" ]; do
    sleep 20
    n=$(grep -aciE "rotat|rollover|re-sign|new epoch|refresh" "$LSP_LOG" 2>/dev/null || echo 0)
    [ "$n" -gt "$ROT_SEEN" ] && { ROT_SEEN=$n; grep -aiE "rotat|rollover|re-sign|new epoch|refresh" "$LSP_LOG" 2>/dev/null | tail -1 | sed 's/\x1b\[[0-9;]*m//g' | while read -r l; do info "  rot-marker: $l"; done; }
done
info "[$(ts)] ~$LADDER_ROTATIONS rotation cycles elapsed (rot-markers seen: $ROT_SEEN); taking clients OFFLINE to force proactive-exit distribution..."
for p in "${CLIENT_PIDS[@]}"; do kill "$p" 2>/dev/null; done

info "[$(ts)] clients offline; waiting for LSP proactive-exit distribution TX (rotation-retry-limit path)..."
DIST_TXID=""
for i in $(seq 1 $((CONFIRM_TIMEOUT/10))); do
    DIST_TXID=$(grep -aoE "distribution TX broadcast: [0-9a-f]{64}" "$LSP_LOG" 2>/dev/null | grep -oE "[0-9a-f]{64}" | head -1)
    [ -z "$DIST_TXID" ] && DIST_TXID=$(sqlite3 "$LSP_DB" "SELECT txid FROM broadcast_log WHERE source LIKE '%distrib%' ORDER BY id DESC LIMIT 1;" 2>/dev/null || true)
    [ -n "$DIST_TXID" ] && break
    sleep 10; [ $((i % 30)) -eq 0 ] && info "  ...waiting; height $($BCLI getblockcount 2>/dev/null); $(grep -aiE 'rotation.*retry|proactive|broadcasting distribution' "$LSP_LOG" 2>/dev/null | tail -1 | sed 's/\x1b\[[0-9;]*m//g')"
done
[ -n "$DIST_TXID" ] || { red "FAIL: no proactive distribution after clients offline — check rotation/proactive-exit path"; echo "--- LSP log tail ---" >&2; tail -50 "$LSP_LOG" >&2; recov; exit 1; }
printf '%s\tladder_proactive_distribution\n' "$DIST_TXID" >> "$LMAN"
green "[$(ts)] LADDER MECHANICS OK: factory rotated ~$LADDER_ROTATIONS x, then proactive-exit distribution: $DIST_TXID"
recov
echo "EXHIB_LADDER_TEST_DONE $DIST_TXID"
