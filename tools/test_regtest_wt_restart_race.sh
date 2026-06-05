#!/usr/bin/env bash
# test_regtest_wt_restart_race.sh — Frontier A (regtest mechanics).
#
# Proves the TRUSTLESS watchtower (reads only wt.db, holds NO secrets) wins the
# penalty race against the factory CLTV, *across a restart*:
#
#   Phase 1  breach lands while NO watchtower is running (WT "down"): the LSP
#            advances a PS leaf (revoking the old state) and broadcasts the
#            stale/revoked leaf, which we confirm on-chain.
#   Phase 2  RESTART (cold): the WT is started for the first time AFTER the
#            breach — it must re-hydrate the pre-signed response from wt.db,
#            detect the breach it missed, and get the response confirmed BEFORE
#            the factory CLTV height.  We measure the block margin.
#   Phase 3  RESTART (process cycle): kill the WT and relaunch it; it must
#            re-hydrate from wt.db again and re-detect (idempotent) — proving a
#            mid-flight crash/redeploy never drops the watch.
#
# PS leaves are gated by CLTV (nSequence=0xFFFFFFFE disables CSV), so the race
# is vs the absolute factory-CLTV height, parsed live from the LSP log.
# Regtest first (this script); the signet variant adds real wall-clock at
# 0.1 sat/vB.
set -uo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
WT_BIN="$BUILD_DIR/superscalar_watchtower"

N_CLIENTS="${N_CLIENTS:-4}"
SIDE="${SIDE:-0}"
FUNDING_SATS=100000
LSP_PORT=29953
# Wide dying window => a comfortable, reliably-measurable breach->CLTV gap.
ACTIVE_BLOCKS=6
DYING_BLOCKS=18
MINER_INTERVAL=5     # slow blocks so the WT (fast poll) stays ahead of height
WT_POLL=2
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "0000000000000000000000000000000000000000000000000000000000000004"
    "0000000000000000000000000000000000000000000000000000000000000005"
)
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

TMPDIR=$(mktemp -d /tmp/ss-wt-restart-race.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"; WT_DB="$TMPDIR/wt.db"
LSP_LOG="$TMPDIR/lsp.log"; WT1_LOG="$TMPDIR/wt1.log"; WT2_LOG="$TMPDIR/wt2.log"
PIDS=(); MINER_PID=""
cleanup() {
    [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null || true
    pkill -9 -f "superscalar_watchtower.*--wt-db $WT_DB" 2>/dev/null || true
    for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
    cp "$WT1_LOG" /tmp/wt_restart_race_last_wt1.log 2>/dev/null || true
    cp "$WT2_LOG" /tmp/wt_restart_race_last_wt2.log 2>/dev/null || true
    cp "$LSP_LOG" /tmp/wt_restart_race_last_lsp.log 2>/dev/null || true
}
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
red(){ printf '\033[31m%s\033[0m\n' "$*"; }
fail(){ red "FAIL: $*"; exit 1; }

tip(){ $BCLI getblockcount 2>/dev/null; }
mine(){ $BCLI -rpcwallet=$MINER_WALLET generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1 || true; }

MINER_WALLET="ss_cheat_leaf_miner"
$BCLI -named createwallet wallet_name=$MINER_WALLET load_on_startup=false 2>/dev/null || $BCLI loadwallet $MINER_WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$MINER_WALLET -named getnewaddress address_type=bech32m)
mine 101

echo "=== Frontier A: trustless-WT RESTART-race vs factory CLTV (regtest, SIDE=$SIDE) ==="

# --- LSP: --db + --wt-db (so wt.db gets the pre-signed response) + the cheat ---
"$LSP_BIN" --network regtest --port $LSP_PORT --clients $N_CLIENTS --arity 3 \
    --amount $FUNDING_SATS --fee-rate 1000 --confirm-timeout 600 \
    --active-blocks $ACTIVE_BLOCKS --dying-blocks $DYING_BLOCKS --step-blocks 1 --states-per-layer 2 \
    --seckey "$LSP_SECKEY" --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet $MINER_WALLET --db "$LSP_DB" --wt-db "$WT_DB" \
    --demo --cheat-daemon-leaf $SIDE --lsp-balance-pct 50 > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 60); do sleep 1; grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && { echo "  LSP listening"; break; }; kill -0 $LSP_PID 2>/dev/null || { tail -25 "$LSP_LOG"; fail "LSP died before listening"; }; done

# --- clients ---
for i in $(seq 0 $((N_CLIENTS-1))); do
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $LSP_PORT \
        --seckey "${CLIENT_SECKEYS[$i]}" --fee-rate 1000 --lsp-pubkey "$LSP_PUBKEY" \
        --participant-id $((i+1)) --daemon --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
        --wallet $MINER_WALLET --db "$TMPDIR/client_${i}.db" > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!); sleep 0.5
done

# --- background miner (slow) — stopped the moment the breach is broadcast ---
( while kill -0 $LSP_PID 2>/dev/null; do mine 1; sleep $MINER_INTERVAL; done ) &
MINER_PID=$!

echo "--- Phase 1: drive the cheat (advance leaf -> revoke -> broadcast stale), NO watchtower running ---"
for i in $(seq 1 150); do sleep 2; grep -q "CHEAT DAEMON COMPLETE" "$LSP_LOG" 2>/dev/null && { echo "  cheat complete (${i}*2s)"; break; }; kill -0 $LSP_PID 2>/dev/null || break; done
grep -q "CHEAT DAEMON COMPLETE" "$LSP_LOG" || { tail -40 "$LSP_LOG"; fail "no CHEAT DAEMON COMPLETE"; }

# stop the miner so the CLTV doesn't advance while we set up the restart
kill -9 "$MINER_PID" 2>/dev/null || true; MINER_PID=""

STALE_TXID=$(grep -E "Stale pre-advance leaf broadcast" "$LSP_LOG" | head -1 | grep -oE "[0-9a-f]{64}" | head -1)
CLTV=$(grep -oE "CLTV=[0-9]+" "$LSP_LOG" | grep -oE "[0-9]+" | head -1)
[ -n "$STALE_TXID" ] || fail "no stale txid in LSP log"
[ -n "$CLTV" ] || fail "could not parse factory CLTV from LSP log"
# ensure the breach is CONFIRMED on-chain (it lands while the WT is down)
mine 1; sleep 1
H_BREACH=$(tip)
echo "  revoked leaf txid : $STALE_TXID"
echo "  factory CLTV      : $CLTV (deadline height)"
echo "  breach confirmed @ : $H_BREACH   => gap to CLTV = $((CLTV - H_BREACH)) blocks"
[ "$((CLTV - H_BREACH))" -ge 2 ] || fail "breach landed too close to CLTV (gap $((CLTV-H_BREACH))) — widen DYING_BLOCKS"

# --- guard: trustless invariant requires the LSP PRE-SIGNED the response into wt.db ---
N_W=$(sqlite3 "$WT_DB" "SELECT count(*) FROM wt_watches WHERE superseded_at IS NULL;" 2>/dev/null || echo 0)
echo "  wt.db active pre-signed watches: $N_W (want >= 1)"
[ "${N_W:-0}" -ge 1 ] || { sqlite3 "$WT_DB" ".tables" 2>&1; fail "wt.db has no pre-signed response — nothing for a trustless WT to act on"; }

# === Phase 2: RESTART (cold) — first WT launch AFTER the breach ===
echo "--- Phase 2: RESTART (cold) — launch trustless WT (--wt-db only) for the first time, post-breach ---"
"$WT_BIN" --network regtest --wt-db "$WT_DB" --poll-interval $WT_POLL --cli-path bitcoin-cli \
    --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} > "$WT1_LOG" 2>&1 &
WT_PID=$!; PIDS+=($WT_PID)
FIRED=0
for i in $(seq 1 60); do
    sleep 2
    grep -qE "penalty tx\(s\) broadcast" "$WT1_LOG" 2>/dev/null && { FIRED=1; echo "  cold-restarted WT broadcast the response (${i}*2s)"; break; }
    kill -0 $WT_PID 2>/dev/null || { echo "  WT died"; break; }
    # nudge a block occasionally so detection->confirm can progress (still well under CLTV)
    [ $((i % 3)) -eq 0 ] && mine 1
done
grep -q "TRUSTLESS" "$WT1_LOG" || fail "WT#1 did not start in trustless mode"
grep -q "hydrated" "$WT1_LOG" || fail "WT#1 did not hydrate from wt.db"
[ "$FIRED" = 1 ] || { tail -30 "$WT1_LOG"; fail "cold-restarted WT did not broadcast the response"; }

RESP_TXID=$(grep -E "Latest state tx broadcast:" "$WT1_LOG" | head -1 | grep -oE "[0-9a-f]{64}" | head -1)
[ -n "$RESP_TXID" ] || RESP_TXID=$(grep -oE "[0-9a-f]{64}" "$WT1_LOG" | head -1)
echo "  response txid: $RESP_TXID"

# confirm the response and resolve its height (txindex=1)
for k in $(seq 1 6); do mine 1; sleep 1; RBH=$($BCLI getrawtransaction "$RESP_TXID" true 2>/dev/null | grep -oE '"blockhash": *"[0-9a-f]{64}"' | grep -oE "[0-9a-f]{64}" | head -1); [ -n "$RBH" ] && break; done
[ -n "${RBH:-}" ] || fail "response tx $RESP_TXID never confirmed"
R_HEIGHT=$($BCLI getblockheader "$RBH" 2>/dev/null | grep -oE '"height": *[0-9]+' | grep -oE "[0-9]+" | head -1)
echo "  response confirmed @ height $R_HEIGHT"

MARGIN=$((CLTV - R_HEIGHT))
echo
echo "=== RACE RESULT (restarted trustless WT vs factory CLTV) ==="
echo "  breach @ $H_BREACH   response-confirmed @ $R_HEIGHT   CLTV deadline @ $CLTV"
echo "  MARGIN = CLTV - response_height = $MARGIN blocks"
[ "$MARGIN" -ge 1 ] || fail "restarted WT LOST the race (response confirmed at/after CLTV)"
green "  WON: the cold-restarted trustless WT confirmed its response $MARGIN block(s) before the CLTV."

# === Phase 3: RESTART (process cycle) — kill + relaunch, must re-hydrate ===
echo
echo "--- Phase 3: RESTART (process cycle) — kill the WT + relaunch, must re-hydrate from wt.db ---"
kill -9 "$WT_PID" 2>/dev/null || true; sleep 2
"$WT_BIN" --network regtest --wt-db "$WT_DB" --poll-interval $WT_POLL --cli-path bitcoin-cli \
    --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} > "$WT2_LOG" 2>&1 &
WT_PID=$!; PIDS+=($WT_PID)
for i in $(seq 1 10); do sleep 1; grep -q "hydrated" "$WT2_LOG" 2>/dev/null && break; done
grep -q "TRUSTLESS" "$WT2_LOG" || fail "WT#2 (relaunched) did not start in trustless mode"
HYD2=$(grep -oE "hydrated [0-9]+ watches" "$WT2_LOG" | head -1)
echo "  WT#2 re-hydrated: ${HYD2:-NONE}"
grep -q "hydrated" "$WT2_LOG" || fail "WT#2 (relaunched) did not re-hydrate from wt.db"

echo
echo "=== evidence ==="
echo "-- WT#1 (cold restart) --"; grep -aE "TRUSTLESS|hydrated|Latest state tx|penalty tx" "$WT1_LOG" | head -8
echo "-- WT#2 (process cycle) --"; grep -aE "TRUSTLESS|hydrated|Latest state tx|penalty tx" "$WT2_LOG" | head -8

echo
green "PASS: trustless WT, brought up AFTER a breach it was 'down' for, re-hydrated from wt.db (no secrets),"
green "      detected the revoked leaf, and confirmed its response $MARGIN block(s) ahead of the factory CLTV;"
green "      a subsequent kill+relaunch re-hydrated the watch (process-restart survival). [Frontier A, regtest]"
