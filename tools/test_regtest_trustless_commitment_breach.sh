#!/usr/bin/env bash
# test_regtest_trustless_commitment_breach.sh — fills the genuine missing matrix
# cell: [channel-commitment breach] x [standalone trustless WT].
#
# The cheat tests only ever exercised the IN-PROCESS watchtower for channel
# breaches; this proves a STANDALONE WT (--wt-db only, no secrets) actually
# broadcasts the penalty when a revoked CHANNEL COMMITMENT hits chain.
#
#   1. LSP --demo --cheat-daemon --wt-db: routes payments (revoking commitments
#      -> WT_KIND_CHANNEL_COMMITMENT watches mirrored into wt.db), then broadcasts
#      a revoked commitment (the breach) and SLEEPS (no in-process penalty).
#   2. Standalone trustless WT (--wt-db only) hydrates the commitment watches and
#      must detect the on-chain revoked commitment + broadcast its pre-signed penalty.
#
# Expected GREEN — confirms the channel-commitment trustless defense is wired AND
# acted upon end-to-end (not just present in wt.db).
set -uo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"; CLIENT_BIN="$BUILD_DIR/superscalar_client"; WT_BIN="$BUILD_DIR/superscalar_watchtower"
N_CLIENTS=4; PORT=29961; FEE=1100
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RU=${RU:-rpcuser}
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RP=${RP:-rpcpass}
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RPORT=${RPORT:-18443}
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"; WALLET="ss_cheat_leaf_miner"
. "$(dirname "$(realpath "$0")")"/regtest_test_helpers.sh   # pen_recovers_most (A-2, fee-bounded)
TMPDIR=$(mktemp -d /tmp/ss-tl-commit-breach.XXXXXX); LSP_DB="$TMPDIR/lsp.db"; WT_DB="$TMPDIR/wt.db"; LSP_LOG="$TMPDIR/lsp.log"; WT_LOG="$TMPDIR/wt.log"
PIDS=(); MINER_PID=""
cleanup(){ [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null||true; pkill -9 -f "superscalar_watchtower.*--wt-db $WT_DB" 2>/dev/null||true; pkill -9 -f "superscalar_(lsp|client).*--port $PORT" 2>/dev/null||true; for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null||true; done; cp "$WT_LOG" /tmp/tl_commit_breach_wt.log 2>/dev/null||true; cp "$LSP_LOG" /tmp/tl_commit_breach_lsp.log 2>/dev/null||true; }
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }; red(){ printf '\033[31m%s\033[0m\n' "$*"; }; fail(){ red "FAIL: $*"; exit 1; }
mine(){ $BCLI -rpcwallet=$WALLET generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1||true; }
# Canonical breach-launcher seckeys: must equal the breach-test's client_fills
# (byte = 0x22 + i*0x11) or the re-signed revoked commitment is an Invalid Schnorr.
sk(){ local b; b=$(printf "%02x" $((34 + $1 * 17))); printf "${b}%.0s" {1..32}; }

$BCLI -named createwallet wallet_name=$WALLET load_on_startup=false 2>/dev/null || $BCLI loadwallet $WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m); mine 101

echo "=== Trustless channel-COMMITMENT breach x STANDALONE WT (the missing matrix cell) ==="
"$LSP_BIN" --network regtest --port $PORT --demo --breach-standalone --lsp-balance-pct 50 \
    --clients $N_CLIENTS --arity 3 --amount 200000 --fee-rate $FEE --confirm-timeout 600 \
    --seckey "$LSP_SECKEY" --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" \
    --wallet "$WALLET" --db "$LSP_DB" --wt-db "$WT_DB" > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 60); do sleep 1; grep -q "listening" "$LSP_LOG" 2>/dev/null && { echo "  LSP listening"; break; }; kill -0 $LSP_PID 2>/dev/null||{ tail -20 "$LSP_LOG"; fail "LSP died"; }; done
for i in $(seq 0 $((N_CLIENTS-1))); do
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $PORT --daemon --seckey "$(sk $i)" --fee-rate $FEE \
        --lsp-balance-pct 50 --lsp-pubkey "$LSP_PUB" --participant-id $((i+1)) --rpcuser "$RU" --rpcpassword "$RP" \
        --rpcport "$RPORT" --wallet "$WALLET" --db "$TMPDIR/c${i}.db" > "$TMPDIR/c${i}.log" 2>&1 &
    PIDS+=($!); sleep 0.4
done
( while kill -0 $LSP_PID 2>/dev/null; do mine 1; sleep 2; done ) & MINER_PID=$!

echo "--- waiting for breach broadcast, then for the LSP to finish (mode 3 confirms the breach, sleeps, exits — so its wt.db WAL is checkpointed before we read kind=2) ---"
for i in $(seq 1 90); do sleep 2; grep -qiE "Revoked commitment broadcast|breach-standalone" "$LSP_LOG" 2>/dev/null && { echo "  breach broadcast (${i}*2s)"; break; }; kill -0 $LSP_PID 2>/dev/null||break; done
for i in $(seq 1 60); do kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited — wt.db flushed"; break; }; sleep 2; done

# stop the miner so the breach stays put while we bring the standalone WT up
kill -9 "$MINER_PID" 2>/dev/null||true; MINER_PID=""; sleep 1

K2=$(sqlite3 "$WT_DB" "SELECT count(*) FROM wt_watches WHERE watch_kind=2;" 2>/dev/null || echo 0)
echo "  wt.db channel-commitment (kind=2) watches available to the standalone WT: ${K2:-0}"
[ "${K2:-0}" -ge 1 ] || fail "no kind=2 commitment watch in wt.db — standalone WT would have nothing to act on"
mine 1; sleep 1   # ensure the revoked commitment is confirmed on-chain

echo "--- launch STANDALONE trustless WT (--wt-db only, NO secrets) ---"
"$WT_BIN" --network regtest --wt-db "$WT_DB" --poll-interval 3 --cli-path bitcoin-cli \
    --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" > "$WT_LOG" 2>&1 &
WT_PID=$!; PIDS+=($WT_PID)
FIRED=0
for i in $(seq 1 60); do
    sleep 2
    grep -qE "penalty tx\(s\) broadcast|Latest state tx broadcast:" "$WT_LOG" 2>/dev/null && { FIRED=1; echo "  standalone WT broadcast a penalty (${i}*2s)"; break; }
    kill -0 $WT_PID 2>/dev/null||{ echo "  WT died"; break; }
    [ $((i % 3)) -eq 0 ] && mine 1
done

echo
echo "=== evidence ==="
grep -aE "TRUSTLESS|hydrated|penalty tx|Latest state tx|commitment" "$WT_LOG" 2>/dev/null | head -10
grep -q "hydrated" "$WT_LOG" || fail "WT did not hydrate from wt.db"
echo
[ "$FIRED" = 1 ] || { red "FAIL: standalone WT did NOT broadcast a penalty for the channel-commitment breach"; tail -25 "$WT_LOG"; exit 1; }

# OUTCOME check (not just broadcast): the penalty must CONFIRM on-chain and sweep a real amount.
PEN_TXID=$(grep -oiE "Latest state tx broadcast: *[0-9a-f]{64}|penalty tx[^0-9a-f]*[0-9a-f]{64}" "$WT_LOG" | grep -oE "[0-9a-f]{64}" | tail -1)
[ -n "$PEN_TXID" ] || { tail -25 "$WT_LOG"; fail "penalty broadcast but no penalty txid in WT log"; }
echo "  penalty txid: $PEN_TXID — mining to confirm + verify payout"
PCONF=0
for i in $(seq 1 12); do mine 1; sleep 1; c=$($BCLI getrawtransaction "$PEN_TXID" true 2>/dev/null | grep -oE '"confirmations": *[0-9]+' | grep -oE '[0-9]+' | head -1); [ -n "$c" ] && [ "$c" -ge 1 ] && { PCONF=$c; break; }; done
[ "$PCONF" -ge 1 ] || fail "penalty $PEN_TXID never confirmed on-chain (broadcast != confirmed)"
PEN_SATS=$($BCLI getrawtransaction "$PEN_TXID" true 2>/dev/null | grep -oE '"value": *[0-9.]+' | grep -oE '[0-9.]+' | sort -rn | head -1)
PEN_SATS=$(awk "BEGIN{printf \"%d\", ($PEN_SATS+0)*100000000}")
echo "  penalty confirmed ($PCONF conf); largest output: ${PEN_SATS:-0} sats"
[ "${PEN_SATS:-0}" -ge 5000 ] || fail "penalty payout ${PEN_SATS} sats too small — not a real to_local recovery (dust/zero?)"
# A-2 (fee-bounded): the justice tx must recover ~all the breached to_local it sweeps (no value
# burned/leaked). Fail only on a confirmed LOW; UNKNOWN (lookup miss) does not false-fail.
RR=$(pen_recovers_most "$PEN_TXID"); echo "  A-2 recovery: $RR"
case "$RR" in LOW*) fail "penalty recovers too little of the swept to_local — value leaked/burned ($RR)";; esac

# Tier-4 reorg-robustness (opt-in: SS_REORG_REFIRE=1). The trustless model must survive a reorg:
# orphan the penalty's block and verify the penalty RE-confirms (WT re-broadcasts on reorg via
# watchtower_on_reorg + poll-loop; Core also returns the tx to mempool). The cheater's to_local
# must stay swept across the reorg. WT is still alive here (--poll-interval 3).
if [ "${SS_REORG_REFIRE:-0}" = 1 ]; then
    echo "=== REORG-REFIRE: orphan the penalty block, verify the penalty re-confirms ==="
    PBLK=$($BCLI getrawtransaction "$PEN_TXID" true 2>/dev/null | grep -oE '"blockhash": *"[0-9a-f]{64}"' | grep -oE '[0-9a-f]{64}' | head -1)
    [ -n "$PBLK" ] || fail "reorg: could not find penalty block for $PEN_TXID"
    echo "  invalidating penalty block $PBLK (orphans penalty $PEN_TXID)"
    $BCLI invalidateblock "$PBLK" 2>/dev/null
    sleep 6   # let the standalone WT poll-loop observe the vanished penalty + re-broadcast
    # Verify the reorg ACTUALLY orphaned the penalty — else the re-confirm below is vacuous.
    UC=$($BCLI getrawtransaction "$PEN_TXID" true 2>/dev/null | grep -oE '"confirmations": *[0-9]+' | grep -oE '[0-9]+' | head -1)
    { [ -z "$UC" ] || [ "$UC" -eq 0 ]; } || fail "REORG-REFIRE: invalidateblock left penalty at $UC confs — reorg ineffective, test would be vacuous"
    echo "  penalty orphaned (confs now ${UC:-0}); mining new chain to verify re-confirm"
    RECONF=0
    for i in $(seq 1 24); do mine 1; sleep 2; c=$($BCLI getrawtransaction "$PEN_TXID" true 2>/dev/null | grep -oE '"confirmations": *[0-9]+' | grep -oE '[0-9]+' | head -1); [ -n "$c" ] && [ "$c" -ge 1 ] && { RECONF=$c; break; }; done
    [ "$RECONF" -ge 1 ] || fail "REORG-REFIRE: penalty $PEN_TXID did NOT re-confirm after reorg — trustless defense LOST on reorg!"
    RSATS=$($BCLI getrawtransaction "$PEN_TXID" true 2>/dev/null | grep -oE '"value": *[0-9.]+' | grep -oE '[0-9.]+' | sort -rn | head -1)
    RSATS=$(awk "BEGIN{printf \"%d\", ($RSATS+0)*100000000}")
    [ "${RSATS:-0}" -ge 5000 ] || fail "REORG-REFIRE: re-confirmed penalty output ${RSATS} sats too small"
    grep -aiE "vanished.*reorg|re-watching|reorg detected" "$WT_LOG" 2>/dev/null | tail -2
    green "REORG-REFIRE PASS: penalty re-confirmed after orphaning its block ($RECONF conf, $RSATS sats) —"
    green "      the cheater's to_local stays swept across a reorg. Trustless defense is reorg-robust."
fi

green "PASS: a STANDALONE trustless WT (wt.db only, no secrets) hydrated $K2 channel-commitment watch(es),"
green "      broadcast AND CONFIRMED the penalty ($PCONF conf, $PEN_SATS sats swept) for a revoked-commitment"
green "      breach — outcome verified, not just broadcast. Channel-commitment trustless defense PROVEN e2e."
exit 0
