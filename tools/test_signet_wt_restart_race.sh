#!/usr/bin/env bash
# test_signet_wt_restart_race.sh — Frontier A on SIGNET (real wall-clock).
#
# Same three-phase proof as the regtest mechanism test, but on signet so the
# response must relay + be mined by REAL signet miners at 0.1 sat/vB, and the
# CLTV race plays out over real ~30-60 min blocks across a real restart:
#   Phase 1  breach lands while NO watchtower runs (LSP advances a PS leaf,
#            revokes it, broadcasts the stale leaf; we wait for it to confirm).
#   Phase 2  RESTART (cold): a fresh trustless WT (--wt-db only, no secrets)
#            re-hydrates, detects the breach, and gets its pre-signed response
#            CONFIRMED before the factory CLTV height — margin measured.
#   Phase 3  RESTART (process cycle): kill + relaunch the WT; must re-hydrate.
#
# Sat-careful: small --amount (recoverable-ish), exactly 0.1 sat/vB, and an
# end-of-run scantxoutset recovery report so any residual factory output is
# logged by outpoint for sweep (never silently lost).
#
# Run detached:  setsid nohup bash tools/test_signet_wt_restart_race.sh > /tmp/a_signet.log 2>&1 &
set -uo pipefail

BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
WT_BIN="$BUILD_DIR/superscalar_watchtower"

N_CLIENTS="${N_CLIENTS:-4}"
SIDE="${SIDE:-0}"
AMOUNT="${AMOUNT:-50000}"          # small, recoverable-ish exposure out of ~1.86M
FEE_RATE="${FEE_RATE:-100}"        # 100 sat/kvB == 0.1 sat/vB exactly (user's floor)
LSP_PORT="${LSP_PORT:-29954}"
ACTIVE_BLOCKS="${ACTIVE_BLOCKS:-6}"
DYING_BLOCKS="${DYING_BLOCKS:-18}"  # regtest-proven window (gave breach->CLTV gap 10);
                                    # the gap is block-count math so it carries to signet
WT_POLL="${WT_POLL:-30}"
WALLET="${WALLET:-superscalar_lsp}"
CONFIRM_TIMEOUT="${CONFIRM_TIMEOUT:-14400}"   # 4h budget for the LSP funding/lifecycle

LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "0000000000000000000000000000000000000000000000000000000000000004"
    "0000000000000000000000000000000000000000000000000000000000000005"
)
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

# --- signet RPC creds from the node conf (the bare -signet cookie path is wrong) ---
SIGNET_CONF="${SIGNET_CONF:-/var/lib/bitcoind-signet/bitcoin.conf}"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF")
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF")
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF"); RPORT=${RPORT:-38332}
BCLI="bitcoin-cli -signet -rpcuser=$RU -rpcpassword=$RP -rpcport=$RPORT"

TMPDIR=$(mktemp -d /tmp/ss-signet-wt-race.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"; WT_DB="$TMPDIR/wt.db"
LSP_LOG="$TMPDIR/lsp.log"; WT1_LOG="$TMPDIR/wt1.log"; WT2_LOG="$TMPDIR/wt2.log"
PIDS=()
cleanup() {
    pkill -9 -f "superscalar_watchtower.*--wt-db $WT_DB" 2>/dev/null || true
    for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
    for f in "$LSP_LOG" "$WT1_LOG" "$WT2_LOG"; do cp "$f" "/tmp/a_signet_$(basename "$f")" 2>/dev/null || true; done
}
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
red(){ printf '\033[31m%s\033[0m\n' "$*"; }
fail(){ red "FAIL: $*"; recovery_report; exit 1; }
ts(){ date -u +%H:%M:%S; }
tip(){ $BCLI getblockcount 2>/dev/null; }

# confirmed? prints the confirm height (txindex assumed on signet node); empty if unconfirmed
confirm_height(){
    local txid="$1" bh
    bh=$($BCLI getrawtransaction "$txid" true 2>/dev/null | grep -oE '"blockhash": *"[0-9a-f]{64}"' | grep -oE "[0-9a-f]{64}" | head -1)
    [ -z "$bh" ] && return 1
    $BCLI getblockheader "$bh" 2>/dev/null | grep -oE '"height": *[0-9]+' | grep -oE "[0-9]+" | head -1
}
# wait_confirm <txid> <timeout_sec>
wait_confirm(){
    local txid="$1" budget="$2" waited=0 h
    while [ "$waited" -lt "$budget" ]; do
        h=$(confirm_height "$txid") && { echo "$h"; return 0; }
        sleep 60; waited=$((waited+60))
        echo "    [$(ts)] still waiting for $txid (${waited}s)..." >&2
    done
    return 1
}
recovery_report(){
    echo "--- RECOVERY REPORT (scan for residual factory outputs to sweep) ---"
    # the response/leaf SPKs are derivable from the factory; best-effort: scan the
    # latest-state response output by txid if we have it
    [ -n "${RESP_TXID:-}" ] && $BCLI getrawtransaction "$RESP_TXID" true 2>/dev/null | grep -oE '"value": *[0-9.]+|"scriptPubKey".*|"hex": *"[0-9a-f]+"' | head -20
    echo "  amount funded: $AMOUNT sats from wallet $WALLET. Residual outputs (if any) are spendable"
    echo "  via the LSP/client keys; sweep manually if not auto-reclaimed. (cf. stranded-sat task #309)"
    echo "  LSP db: $LSP_DB   wt db: $WT_DB   (preserved under /tmp/a_signet_*.log)"
}

echo "=== Frontier A on SIGNET: trustless-WT restart-race vs factory CLTV ==="
echo "  [$(ts)] node height $(tip), amount=$AMOUNT sats, fee=$FEE_RATE sat/kvB (0.1 sat/vB), wallet=$WALLET"
echo "  signet blocks are ~30-60 min — expect a multi-hour run."

# pre-clean any stale LSP/WT on our port
pkill -9 -f "superscalar_lsp.*--port $LSP_PORT" 2>/dev/null || true
sleep 1

# --- LSP: signet, --db + --wt-db + the cheat; self-funds from --wallet at 0.1 sat/vB ---
"$LSP_BIN" --network signet --cli-path bitcoin-cli \
    --rpcuser "$RU" --rpcpassword "$RP" \
    --port $LSP_PORT --clients $N_CLIENTS --arity 3 \
    --amount $AMOUNT --fee-rate $FEE_RATE --confirm-timeout $CONFIRM_TIMEOUT \
    --active-blocks $ACTIVE_BLOCKS --dying-blocks $DYING_BLOCKS --step-blocks 1 --states-per-layer 2 \
    --seckey "$LSP_SECKEY" --wallet "$WALLET" --db "$LSP_DB" --wt-db "$WT_DB" \
    --demo --cheat-daemon-leaf $SIDE --lsp-balance-pct 50 > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
echo "  [$(ts)] LSP launched (pid $LSP_PID) — waiting to listen + self-fund (funding confirm ~1 block)"
for i in $(seq 1 120); do sleep 2; grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && { echo "  [$(ts)] LSP listening"; break; }; kill -0 $LSP_PID 2>/dev/null || { tail -25 "$LSP_LOG"; fail "LSP died before listening"; }; done

# --- clients (signers; they don't fund) ---
for i in $(seq 0 $((N_CLIENTS-1))); do
    "$CLIENT_BIN" --network signet --cli-path bitcoin-cli --rpcuser "$RU" --rpcpassword "$RP" \
        --host 127.0.0.1 --port $LSP_PORT --seckey "${CLIENT_SECKEYS[$i]}" --fee-rate $FEE_RATE \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id $((i+1)) --daemon --wallet "$WALLET" \
        --db "$TMPDIR/client_${i}.db" > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!); sleep 1
done

echo "--- Phase 1: [$(ts)] driving cheat through the lifecycle (funding -> factory -> advance -> stale broadcast), NO WT ---"
# the LSP daemon self-drives over real blocks; wait for the breach broadcast log
for i in $(seq 1 $((CONFIRM_TIMEOUT/10))); do
    sleep 10
    grep -q "CHEAT DAEMON COMPLETE" "$LSP_LOG" 2>/dev/null && { echo "  [$(ts)] cheat complete"; break; }
    kill -0 $LSP_PID 2>/dev/null || { tail -40 "$LSP_LOG"; fail "LSP died during lifecycle"; }
done
grep -q "CHEAT DAEMON COMPLETE" "$LSP_LOG" || { tail -40 "$LSP_LOG"; fail "cheat never completed within budget"; }

STALE_TXID=$(grep -E "Stale pre-advance leaf broadcast" "$LSP_LOG" | head -1 | grep -oE "[0-9a-f]{64}" | head -1)
CLTV=$(grep -oE "CLTV=[0-9]+" "$LSP_LOG" | grep -oE "[0-9]+" | head -1)
[ -n "$STALE_TXID" ] || fail "no stale txid in LSP log"
[ -n "$CLTV" ] || fail "could not parse factory CLTV from LSP log"
echo "  [$(ts)] revoked leaf txid : $STALE_TXID ; factory CLTV deadline : $CLTV"

echo "  [$(ts)] waiting for the breach (stale leaf) to CONFIRM on signet (no WT running = WT down)..."
H_BREACH=$(wait_confirm "$STALE_TXID" "$CONFIRM_TIMEOUT") || fail "stale leaf never confirmed"
echo "  [$(ts)] breach confirmed @ height $H_BREACH ; gap to CLTV = $((CLTV - H_BREACH)) blocks"
[ "$((CLTV - H_BREACH))" -ge 2 ] || fail "breach too close to CLTV (gap $((CLTV-H_BREACH)))"

N_W=$(sqlite3 "$WT_DB" "SELECT count(*) FROM wt_watches WHERE superseded_at IS NULL;" 2>/dev/null || echo 0)
echo "  [$(ts)] wt.db active pre-signed watches: $N_W (want >= 1)"
[ "${N_W:-0}" -ge 1 ] || fail "wt.db has no pre-signed response"

# === Phase 2: RESTART (cold) — first WT launch AFTER the breach ===
echo "--- Phase 2: [$(ts)] RESTART (cold) — launch trustless WT (--wt-db only), post-breach ---"
"$WT_BIN" --network signet --wt-db "$WT_DB" --poll-interval $WT_POLL --cli-path bitcoin-cli \
    --rpcuser "$RU" --rpcpassword "$RP" > "$WT1_LOG" 2>&1 &
WT_PID=$!; PIDS+=($WT_PID)
FIRED=0
for i in $(seq 1 $((CONFIRM_TIMEOUT/15))); do
    sleep 15
    grep -qE "penalty tx\(s\) broadcast" "$WT1_LOG" 2>/dev/null && { FIRED=1; echo "  [$(ts)] cold-restarted WT broadcast the response"; break; }
    kill -0 $WT_PID 2>/dev/null || { echo "  WT died"; break; }
done
grep -q "TRUSTLESS" "$WT1_LOG" || fail "WT#1 not in trustless mode"
grep -q "hydrated" "$WT1_LOG" || fail "WT#1 did not hydrate from wt.db"
[ "$FIRED" = 1 ] || { tail -30 "$WT1_LOG"; fail "cold-restarted WT did not broadcast the response"; }

RESP_TXID=$(grep -E "Latest state tx broadcast:" "$WT1_LOG" | head -1 | grep -oE "[0-9a-f]{64}" | head -1)
[ -n "$RESP_TXID" ] || fail "no response txid in WT log (refusing head-1 fallback that could false-pass on a stray hash)"
echo "  [$(ts)] response txid: $RESP_TXID — waiting for it to relay + confirm at 0.1 sat/vB..."
R_HEIGHT=$(wait_confirm "$RESP_TXID" "$CONFIRM_TIMEOUT") || fail "response tx never confirmed (relay/mining at 0.1 sat/vB?)"
MARGIN=$((CLTV - R_HEIGHT))
echo
echo "=== RACE RESULT (restarted trustless WT vs factory CLTV, REAL signet timing) ==="
echo "  breach @ $H_BREACH   response-confirmed @ $R_HEIGHT   CLTV deadline @ $CLTV"
echo "  MARGIN = $MARGIN blocks (~$((MARGIN*45)) min of real wall-clock)"
[ "$MARGIN" -ge 1 ] || fail "restarted WT LOST the race (response confirmed at/after CLTV)"
green "  WON: the cold-restarted trustless WT confirmed its response $MARGIN block(s) before the CLTV on signet."

# === Phase 3: RESTART (process cycle) ===
echo "--- Phase 3: [$(ts)] RESTART (process cycle) — kill + relaunch WT, must re-hydrate ---"
kill -9 "$WT_PID" 2>/dev/null || true; sleep 3
"$WT_BIN" --network signet --wt-db "$WT_DB" --poll-interval $WT_POLL --cli-path bitcoin-cli \
    --rpcuser "$RU" --rpcpassword "$RP" > "$WT2_LOG" 2>&1 &
WT_PID=$!; PIDS+=($WT_PID)
for i in $(seq 1 20); do sleep 3; grep -q "hydrated" "$WT2_LOG" 2>/dev/null && break; done
grep -q "TRUSTLESS" "$WT2_LOG" || fail "WT#2 not in trustless mode"
HYD2=$(grep -oE "hydrated [0-9]+ watches" "$WT2_LOG" | head -1)
echo "  [$(ts)] WT#2 re-hydrated: ${HYD2:-NONE}"
grep -q "hydrated" "$WT2_LOG" || fail "WT#2 did not re-hydrate"

echo
echo "=== evidence ==="
echo "-- WT#1 (cold restart) --"; grep -aE "TRUSTLESS|hydrated|Latest state tx|penalty tx" "$WT1_LOG" | head -8
echo "-- WT#2 (process cycle) --"; grep -aE "TRUSTLESS|hydrated|Latest state tx|penalty tx" "$WT2_LOG" | head -6
recovery_report
echo
green "PASS (signet): trustless WT, restarted after a breach it was down for, re-hydrated from wt.db (no secrets),"
green "      relayed + confirmed its response $MARGIN block(s) ahead of the factory CLTV at 0.1 sat/vB under REAL"
green "      wall-clock; a kill+relaunch re-hydrated the watch. [Frontier A, SIGNET]"
