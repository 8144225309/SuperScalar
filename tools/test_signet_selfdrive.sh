#!/usr/bin/env bash
# test_signet_selfdrive.sh FLAG "MARKER" [PORT] — run one LSP-self-driving test
# flag on SIGNET (0.1 sat/vB) and wait for MARKER. For in-process-WT tests where
# the LSP drives the breach + penalty/sweep and self-confirms over REAL blocks:
#   --test-ptlc-breach-chain   -> "PTLC BREACH CHAIN TEST PASSED"
#   --test-htlc-force-close    -> "HTLC FORCE-CLOSE TEST PASSED"
# Canonical scaffold seckeys; sat-careful recovery note.
set -uo pipefail
FLAG="${1:?usage: FLAG MARKER [PORT]}"; MARKER="${2:?marker}"; LSP_PORT="${3:-29969}"
BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"; CLIENT_BIN="$BUILD_DIR/superscalar_client"
N_CLIENTS="${N_CLIENTS:-2}"; AMOUNT="${AMOUNT:-250000}"; FEE_RATE="${FEE_RATE:-100}"
WALLET="${WALLET:-superscalar_lsp}"; CONFIRM_TIMEOUT="${CONFIRM_TIMEOUT:-21600}"
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
sk(){ local b; b=$(printf "%02x" $((34 + $1 * 17))); printf "${b}%.0s" {1..32}; }
SIGNET_CONF="${SIGNET_CONF:-/var/lib/bitcoind-signet/bitcoin.conf}"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF")
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF")
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF"); RPORT=${RPORT:-38332}
TAG=$(echo "$FLAG" | tr -cd 'a-z')
TMPDIR=$(mktemp -d /tmp/ss-signet-$TAG.XXXXXX); LSP_DB="$TMPDIR/lsp.db"; WT_DB="$TMPDIR/wt.db"; LSP_LOG="$TMPDIR/lsp.log"
PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null||true; done; cp "$LSP_LOG" "/tmp/${TAG}_signet_lsp.log" 2>/dev/null||true; }
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }; red(){ printf '\033[31m%s\033[0m\n' "$*"; }
ts(){ date -u +%H:%M:%S; }; tip(){ bitcoin-cli -signet -rpcuser=$RU -rpcpassword=$RP -rpcport=$RPORT getblockcount 2>/dev/null; }
recov(){ echo "--- RECOVERY: $AMOUNT sats from $WALLET; residual factory/leaf/commitment outputs spendable via LSP/client keys — sweep manually if not auto-reclaimed (cf #309). dbs $TMPDIR (lsp preserved /tmp/${TAG}_signet_lsp.log) ---"; }
echo "=== SIGNET self-drive: $FLAG (marker: '$MARKER') at 0.1 sat/vB ==="
echo "  [$(ts)] height $(tip), amount=$AMOUNT, fee=$FEE_RATE sat/kvB. signet ~10min/block — multi-hour."
pkill -9 -f "superscalar_lsp.*--port $LSP_PORT" 2>/dev/null||true; sleep 1
"$LSP_BIN" --network signet --cli-path bitcoin-cli --rpcuser "$RU" --rpcpassword "$RP" \
    --port $LSP_PORT --clients $N_CLIENTS --arity 3 \
    --active-blocks 6 --dying-blocks 4 --step-blocks 1 --states-per-layer 2 \
    --amount $AMOUNT --fee-rate $FEE_RATE \
    --confirm-timeout $CONFIRM_TIMEOUT --seckey "$LSP_SECKEY" --wallet "$WALLET" \
    --db "$LSP_DB" --wt-db "$WT_DB" --demo $FLAG --lsp-balance-pct 50 > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 120); do sleep 2; grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && { echo "  [$(ts)] LSP listening + self-funding"; break; }; kill -0 $LSP_PID 2>/dev/null||{ tail -25 "$LSP_LOG"; red "FAIL: LSP died before listening"; recov; exit 1; }; done
for i in $(seq 0 $((N_CLIENTS-1))); do
    "$CLIENT_BIN" --network signet --cli-path bitcoin-cli --rpcuser "$RU" --rpcpassword "$RP" \
        --host 127.0.0.1 --port $LSP_PORT --seckey "$(sk $i)" --fee-rate $FEE_RATE \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id $((i+1)) --daemon --wallet "$WALLET" \
        --db "$TMPDIR/client_${i}.db" > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!); sleep 1
done
echo "  [$(ts)] LSP self-driving $FLAG over real signet blocks (waiting for marker)..."
SEEN=0
for i in $(seq 1 $((CONFIRM_TIMEOUT/10))); do
    sleep 10
    grep -qF "$MARKER" "$LSP_LOG" 2>/dev/null && { SEEN=1; echo "  [$(ts)] marker seen"; break; }
    grep -qiE "TEST FAILED|scaffold_seckey_mismatch" "$LSP_LOG" 2>/dev/null && { echo "  [$(ts)] explicit test-failure marker"; break; }
    kill -0 $LSP_PID 2>/dev/null || { echo "  [$(ts)] LSP exited"; break; }
done
echo; echo "=== evidence ==="; grep -aiE "PTLC|HTLC|penalty|sweep|broadcast|PASSED|ptlc_penalty|timeout TX|confirmed" "$LSP_LOG" 2>/dev/null | tail -16
echo
if [ "$SEEN" = 1 ]; then green "PASS (signet): $FLAG fired — '$MARKER' on REAL signet at 0.1 sat/vB."; recov; exit 0
else red "FAIL (signet): '$MARKER' not observed for $FLAG"; tail -25 "$LSP_LOG"; recov; exit 1; fi
