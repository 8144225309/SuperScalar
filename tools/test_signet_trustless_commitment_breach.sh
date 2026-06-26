#!/usr/bin/env bash
# test_signet_trustless_commitment_breach.sh — channel-commitment breach x
# STANDALONE trustless WT on SIGNET (real wall-clock, 0.1 sat/vB).
#
# Mode 3 (--breach-standalone): the LSP broadcasts the CLIENT's revoked
# commitments (matching its own wt.db kind=2 watches) with NO in-process WT,
# then a secret-less standalone WT (--wt-db only) must penalize them on real
# signet blocks. Marquee trustless proof under real conditions (A already
# proved factory-node; this is channel-commitment).
#
# Sat-careful: small --amount, exactly 0.1 sat/vB, end-of-run recovery note.
# Run:  systemd-run --unit=ss-commit-signet --collect bash -lc \
#         "cd /root/SuperScalar && bash tools/test_signet_trustless_commitment_breach.sh >/tmp/commit_signet.log 2>&1"
set -uo pipefail
BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"; CLIENT_BIN="$BUILD_DIR/superscalar_client"; WT_BIN="$BUILD_DIR/superscalar_watchtower"
# 2 clients = smaller/faster factory tree on signet (each node confirms over a real
# block); AMOUNT big enough that demo payments clear the 5000-sat channel reserve
# (50000 was too small -> payments failed -> no commitments revoked -> nothing to
# penalize). 250000 over 2 channels = ~125k/channel, plenty.
N_CLIENTS="${N_CLIENTS:-2}"; AMOUNT="${AMOUNT:-250000}"; FEE_RATE="${FEE_RATE:-100}"   # 100 sat/kvB = 0.1 sat/vB
LSP_PORT="${LSP_PORT:-29959}"; WALLET="${WALLET:-superscalar_lsp}"
CONFIRM_TIMEOUT="${CONFIRM_TIMEOUT:-14400}"
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
# Canonical scaffold seckeys (client_fills 0x22/0x33/0x44/0x55) — REQUIRED: the
# commitment re-sign in the breach path uses these; A's leaf-breach used
# sequential keys (02..05) because it never re-signs a 2-of-2 commitment.
sk(){ local b; b=$(printf "%02x" $((34 + $1 * 17))); printf "${b}%.0s" {1..32}; }
SIGNET_CONF="${SIGNET_CONF:-/var/lib/bitcoind-signet/bitcoin.conf}"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF")
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF")
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF"); RPORT=${RPORT:-38332}
BCLI="bitcoin-cli -signet -rpcuser=$RU -rpcpassword=$RP -rpcport=$RPORT"
TMPDIR=$(mktemp -d /tmp/ss-signet-commit.XXXXXX); LSP_DB="$TMPDIR/lsp.db"; WT_DB="$TMPDIR/wt.db"; LSP_LOG="$TMPDIR/lsp.log"; WT_LOG="$TMPDIR/wt.log"
PIDS=()
cleanup(){ pkill -9 -f "superscalar_watchtower.*--wt-db $WT_DB" 2>/dev/null||true; for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null||true; done; for f in "$LSP_LOG" "$WT_LOG"; do cp "$f" "/tmp/commit_signet_$(basename "$f")" 2>/dev/null||true; done; }
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }; red(){ printf '\033[31m%s\033[0m\n' "$*"; }; fail(){ red "FAIL: $*"; recov; exit 1; }
ts(){ date -u +%H:%M:%S; }; tip(){ $BCLI getblockcount 2>/dev/null; }
confirm_height(){ local txid="$1" bh; bh=$($BCLI getrawtransaction "$txid" true 2>/dev/null | grep -oE '"blockhash": *"[0-9a-f]{64}"' | grep -oE "[0-9a-f]{64}" | head -1); [ -z "$bh" ] && return 1; $BCLI getblockheader "$bh" 2>/dev/null | grep -oE '"height": *[0-9]+' | grep -oE "[0-9]+" | head -1; }
wait_confirm(){ local txid="$1" budget="$2" waited=0 h; while [ "$waited" -lt "$budget" ]; do h=$(confirm_height "$txid") && { echo "$h"; return 0; }; sleep 60; waited=$((waited+60)); echo "    [$(ts)] waiting for $txid (${waited}s)..." >&2; done; return 1; }
recov(){ echo "--- RECOVERY: $AMOUNT sats funded from $WALLET; residual factory/leaf/commitment outputs are spendable via the LSP/client keys — sweep manually if not auto-reclaimed (cf #309). LSP db $LSP_DB  wt db $WT_DB (preserved /tmp/commit_signet_*.log) ---"; }

echo "=== SIGNET: channel-commitment breach x STANDALONE trustless WT (0.1 sat/vB) ==="
echo "  [$(ts)] height $(tip), amount=$AMOUNT, fee=$FEE_RATE sat/kvB. signet blocks ~10min — multi-hour run."
pkill -9 -f "superscalar_lsp.*--port $LSP_PORT" 2>/dev/null||true; sleep 1

"$LSP_BIN" --network signet --cli-path bitcoin-cli --rpcuser "$RU" --rpcpassword "$RP" \
    --port $LSP_PORT --clients $N_CLIENTS --arity 3 \
    --active-blocks 6 --dying-blocks 4 --step-blocks 1 --states-per-layer 2 \
    --amount $AMOUNT --fee-rate $FEE_RATE \
    --confirm-timeout $CONFIRM_TIMEOUT --seckey "$LSP_SECKEY" --wallet "$WALLET" \
    --db "$LSP_DB" --wt-db "$WT_DB" --demo --breach-standalone --lsp-balance-pct 50 > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 120); do sleep 2; grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && { echo "  [$(ts)] LSP listening + self-funding"; break; }; kill -0 $LSP_PID 2>/dev/null||{ tail -25 "$LSP_LOG"; fail "LSP died before listening"; }; done
for i in $(seq 0 $((N_CLIENTS-1))); do
    "$CLIENT_BIN" --network signet --cli-path bitcoin-cli --rpcuser "$RU" --rpcpassword "$RP" \
        --host 127.0.0.1 --port $LSP_PORT --seckey "$(sk $i)" --fee-rate $FEE_RATE \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id $((i+1)) --daemon --wallet "$WALLET" \
        --db "$TMPDIR/client_${i}.db" > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!); sleep 1
done

echo "--- [$(ts)] demo -> tree -> CLIENT revoked-commitment breach (NO in-process WT), over real blocks ---"
for i in $(seq 1 $((CONFIRM_TIMEOUT/10))); do
    sleep 10
    grep -qiE "CHEAT DAEMON COMPLETE" "$LSP_LOG" 2>/dev/null && { echo "  [$(ts)] breach staged + LSP finishing"; break; }
    kill -0 $LSP_PID 2>/dev/null || { echo "  [$(ts)] LSP exited"; break; }
done
for i in $(seq 1 60); do kill -0 $LSP_PID 2>/dev/null || break; sleep 2; done   # wait full exit (wt.db WAL checkpoint)

BREACH_TXID=$(grep -E "Revoked commitment broadcast" "$LSP_LOG" | head -1 | grep -oE "[0-9a-f]{64}" | head -1)
[ -n "$BREACH_TXID" ] || fail "no revoked-commitment txid in LSP log (scaffold-seckey mismatch? check log)"
K2=$(sqlite3 "$WT_DB" "SELECT count(*) FROM wt_watches WHERE watch_kind=2;" 2>/dev/null || echo 0)
echo "  [$(ts)] breach txid: $BREACH_TXID ; wt.db kind=2 watches: $K2"
[ "${K2:-0}" -ge 1 ] || fail "no kind=2 commitment watch armed"

echo "  [$(ts)] waiting for the breach commitment to CONFIRM on signet..."
H_BREACH=$(wait_confirm "$BREACH_TXID" "$CONFIRM_TIMEOUT") || fail "breach never confirmed"
echo "  [$(ts)] breach confirmed @ $H_BREACH"

echo "--- [$(ts)] launch STANDALONE trustless WT (--wt-db only, NO secrets) ---"
"$WT_BIN" --network signet --wt-db "$WT_DB" --poll-interval 30 --cli-path bitcoin-cli \
    --rpcuser "$RU" --rpcpassword "$RP" > "$WT_LOG" 2>&1 &
WT_PID=$!; PIDS+=($WT_PID)
FIRED=0
for i in $(seq 1 $((CONFIRM_TIMEOUT/15))); do
    sleep 15
    grep -qE "penalty tx\(s\) broadcast|Latest state tx broadcast:" "$WT_LOG" 2>/dev/null && { FIRED=1; echo "  [$(ts)] standalone WT broadcast a penalty"; break; }
    kill -0 $WT_PID 2>/dev/null || { echo "  WT died"; break; }
done
grep -q "hydrated" "$WT_LOG" || fail "WT did not hydrate from wt.db"
[ "$FIRED" = 1 ] || { tail -30 "$WT_LOG"; fail "standalone WT did not broadcast a penalty"; }

PEN_TXID=$(grep -oiE "Latest state tx broadcast: *[0-9a-f]{64}|penalty tx[^0-9a-f]*[0-9a-f]{64}" "$WT_LOG" | grep -oE "[0-9a-f]{64}" | tail -1)
echo "  [$(ts)] penalty txid: $PEN_TXID — waiting for it to relay + confirm at 0.1 sat/vB..."
H_PEN=$(wait_confirm "$PEN_TXID" "$CONFIRM_TIMEOUT") || fail "penalty never confirmed (relay/mining at 0.1 sat/vB?)"
PEN_OUT=$(bitcoin-cli -signet -rpcuser="$RU" -rpcpassword="$RP" -rpcport="${RPORT:-38332}" getrawtransaction "$PEN_TXID" true 2>/dev/null | grep -oE '"value": *[0-9.]+' | grep -oE '[0-9.]+' | sort -rn | head -1)
PEN_SATS=$(awk "BEGIN{printf \"%d\", ($PEN_OUT+0)*100000000}")
echo "  [$(ts)] penalty largest output: ${PEN_SATS:-0} sats (breached to_local ~30k)"
[ "${PEN_SATS:-0}" -ge 20000 ] || fail "penalty payout ${PEN_SATS} sats too small -- not a real to_local recovery"

echo
echo "=== evidence ==="
grep -aE "TRUSTLESS|hydrated|penalty tx|Latest state tx" "$WT_LOG" | head -8
echo
green "PASS (signet): a secret-less standalone trustless WT hydrated $K2 kind=2 commitment watch(es) and"
green "      penalized a PS channel-commitment breach — penalty confirmed @ $H_PEN (breach @ $H_BREACH) at"
green "      0.1 sat/vB under REAL wall-clock. Channel-commitment trustless defense PROVEN on signet."
recov
