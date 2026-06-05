#!/usr/bin/env bash
# test_signet_subfactory_breach.sh — sub-factory breach x STANDALONE trustless WT
# on SIGNET (0.1 sat/vB). LSP --demo --cheat-daemon-sub broadcasts a stale
# sub-factory node (pre-signed, no re-sign), then a secret-less standalone WT
# (--wt-db only) penalizes it from a hydrated kind=1 watch. Sat-careful recovery.
set -uo pipefail
BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"; CLIENT_BIN="$BUILD_DIR/superscalar_client"; WT_BIN="$BUILD_DIR/superscalar_watchtower"
N_CLIENTS="${N_CLIENTS:-4}"; PS_SUB_ARITY="${PS_SUB_ARITY:-2}"; AMOUNT="${AMOUNT:-400000}"; FEE_RATE="${FEE_RATE:-100}"
LSP_PORT="${LSP_PORT:-29967}"; WALLET="${WALLET:-superscalar_lsp}"; CONFIRM_TIMEOUT="${CONFIRM_TIMEOUT:-21600}"
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
sk(){ local b; b=$(printf "%02x" $((34 + $1 * 17))); printf "${b}%.0s" {1..32}; }
SIGNET_CONF="${SIGNET_CONF:-/var/lib/bitcoind-signet/bitcoin.conf}"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF")
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF")
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF"); RPORT=${RPORT:-38332}
TMPDIR=$(mktemp -d /tmp/ss-signet-sub.XXXXXX); LSP_DB="$TMPDIR/lsp.db"; WT_DB="$TMPDIR/wt.db"; LSP_LOG="$TMPDIR/lsp.log"; WT_LOG="$TMPDIR/wt.log"
PIDS=()
cleanup(){ pkill -9 -f "superscalar_watchtower.*--wt-db $WT_DB" 2>/dev/null||true; for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null||true; done; cp "$LSP_LOG" /tmp/sub_signet_lsp.log 2>/dev/null||true; cp "$WT_LOG" /tmp/sub_signet_wt.log 2>/dev/null||true; }
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }; red(){ printf '\033[31m%s\033[0m\n' "$*"; }; fail(){ red "FAIL: $*"; recov; exit 1; }
ts(){ date -u +%H:%M:%S; }; tip(){ bitcoin-cli -signet -rpcuser=$RU -rpcpassword=$RP -rpcport=$RPORT getblockcount 2>/dev/null; }
recov(){ echo "--- RECOVERY: $AMOUNT sats from $WALLET; residual sub-factory/leaf outputs spendable via LSP/client keys — sweep manually (cf #309). dbs $TMPDIR (preserved /tmp/sub_signet_*.log) ---"; }
echo "=== SIGNET: sub-factory breach x STANDALONE trustless WT (0.1 sat/vB) ==="
echo "  [$(ts)] height $(tip), amount=$AMOUNT, k=$PS_SUB_ARITY, fee=$FEE_RATE. signet ~10min/block — multi-hour."
pkill -9 -f "superscalar_lsp.*--port $LSP_PORT" 2>/dev/null||true; sleep 1
"$LSP_BIN" --network signet --cli-path bitcoin-cli --rpcuser "$RU" --rpcpassword "$RP" \
    --port $LSP_PORT --clients $N_CLIENTS --arity 3 --ps-subfactory-arity $PS_SUB_ARITY \
    --amount $AMOUNT --fee-rate $FEE_RATE --confirm-timeout $CONFIRM_TIMEOUT \
    --seckey "$LSP_SECKEY" --wallet "$WALLET" --db "$LSP_DB" --wt-db "$WT_DB" \
    --demo --lsp-balance-pct 50 --cheat-daemon-sub > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 120); do sleep 2; grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && { echo "  [$(ts)] LSP listening + self-funding"; break; }; kill -0 $LSP_PID 2>/dev/null||{ tail -25 "$LSP_LOG"; fail "LSP died before listening"; }; done
for i in $(seq 0 $((N_CLIENTS-1))); do
    "$CLIENT_BIN" --network signet --cli-path bitcoin-cli --rpcuser "$RU" --rpcpassword "$RP" \
        --host 127.0.0.1 --port $LSP_PORT --seckey "$(sk $i)" --fee-rate $FEE_RATE \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id $((i+1)) --daemon --wallet "$WALLET" \
        --db "$TMPDIR/client_${i}.db" > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!); sleep 1
done
echo "  [$(ts)] LSP driving sub-factory advance + cheat broadcast over real blocks..."
for i in $(seq 1 $((CONFIRM_TIMEOUT/10))); do sleep 10; grep -qE "CHEAT DAEMON COMPLETE" "$LSP_LOG" 2>/dev/null && { echo "  [$(ts)] cheat broadcast complete"; break; }; kill -0 $LSP_PID 2>/dev/null||{ echo "  [$(ts)] LSP exited"; break; }; done
grep -qE "CHEAT DAEMON COMPLETE" "$LSP_LOG" || fail "cheat-daemon-sub never completed"
echo "  [$(ts)] stopping LSP (SIGTERM) so wt.db WAL checkpoints for the standalone WT..."
kill -TERM $LSP_PID 2>/dev/null||true; for s in $(seq 1 30); do kill -0 $LSP_PID 2>/dev/null||{ echo "  LSP exited"; break; }; sleep 1; done
K1=$(sqlite3 "$WT_DB" "SELECT count(*) FROM wt_watches WHERE watch_kind=1;" 2>/dev/null || echo 0)
echo "  [$(ts)] wt.db sub-factory (kind=1) watches: $K1"
[ "${K1:-0}" -ge 1 ] || fail "no kind=1 watch armed"
echo "--- [$(ts)] launch STANDALONE trustless WT (--wt-db only, NO secrets) ---"
"$WT_BIN" --network signet --wt-db "$WT_DB" --poll-interval 30 --cli-path bitcoin-cli --rpcuser "$RU" --rpcpassword "$RP" > "$WT_LOG" 2>&1 &
WT_PID=$!; PIDS+=($WT_PID)
FIRED=0
for i in $(seq 1 $((CONFIRM_TIMEOUT/15))); do sleep 15; grep -qE "penalty tx\(s\) broadcast|L-stock burn tx broadcast: [0-9a-f]{64}|Latest state tx broadcast:" "$WT_LOG" 2>/dev/null && { FIRED=1; echo "  [$(ts)] standalone WT broadcast a penalty"; break; }; kill -0 $WT_PID 2>/dev/null||{ echo "  WT died"; break; }; done
grep -q "hydrated" "$WT_LOG" || fail "WT did not hydrate from wt.db"
echo; echo "=== evidence ==="; grep -aE "TRUSTLESS|hydrated|penalty tx|burn tx|Latest state" "$WT_LOG" 2>/dev/null | head -8
echo
if [ "$FIRED" = 1 ]; then green "PASS (signet): standalone trustless WT hydrated $K1 kind=1 watch(es) and penalized a sub-factory breach at 0.1 sat/vB."; recov; exit 0
else red "FAIL (signet): standalone WT did not penalize the sub-factory breach"; tail -25 "$WT_LOG"; recov; exit 1; fi
