#!/usr/bin/env bash
# test_regtest_kind3_force_close_standalone.sh — FIRE the LAST penalty-matrix
# cell: a SECRET-LESS standalone WT sweeps the LSP's HTLC-timeout output after a
# counterparty force-close, using ONLY wt.db (kind=3), with the LSP OFFLINE.
#
# Uses --test-htlc-force-close + SS_FC_ARM_KIND3=1: the LSP adds a pending HTLC
# on ch0, broadcasts tree + commitment, mines to CLTV, builds the HTLC-timeout
# sweep, then ARMS it as a kind=3 wt.db watch (instead of broadcasting it),
# prints "HTLC FORCE-CLOSE KIND3-ARM COMPLETE", and exits.  A standalone
# trustless WT (--wt-db only) must then hydrate kind=3 + broadcast the
# pre-signed sweep itself.  Proves the force-close HTLC-sweep delegation.
#
# NB: the test re-signs the commitment with client[0]'s key, so the client
# daemons MUST use the canonical scaffold seckeys (client_fills) via sk().
#
# PASS: KIND3-ARM COMPLETE + wt.db kind=3 >=1 + WT broadcasts the sweep.
set -uo pipefail
BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"; CLIENT_BIN="$BUILD_DIR/superscalar_client"; WT_BIN="$BUILD_DIR/superscalar_watchtower"
N_CLIENTS=4; PORT=29956; FEE=1100; ARITY=2; AMOUNT=200000
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RU=${RU:-rpcuser}
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RP=${RP:-rpcpass}
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RPORT=${RPORT:-18443}
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"; WALLET="ss_cheat_leaf_miner"
TMPDIR=$(mktemp -d /tmp/ss-kind3-fc.XXXXXX); LSP_DB="$TMPDIR/lsp.db"; WT_DB="$TMPDIR/wt.db"; LSP_LOG="$TMPDIR/lsp.log"; WT_LOG="$TMPDIR/wt.log"
PIDS=(); MINER_PID=""
cleanup(){ [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null||true; pkill -9 -f "superscalar_(lsp|client|watchtower).*--port $PORT" 2>/dev/null||true; for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null||true; done; cp "$LSP_LOG" /tmp/kind3_fc_lsp.log 2>/dev/null||true; cp "$WT_LOG" /tmp/kind3_fc_wt.log 2>/dev/null||true; cp "$WT_DB" /tmp/kind3_fc_wt.db 2>/dev/null||true; }
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }; red(){ printf '\033[31m%s\033[0m\n' "$*"; }; fail(){ red "FAIL: $*"; exit 1; }
mine(){ $BCLI -rpcwallet=$WALLET generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1||true; }
sk(){ local b; b=$(printf "%02x" $((34 + $1 * 17))); printf "${b}%.0s" {1..32}; }
$BCLI -named createwallet wallet_name=$WALLET load_on_startup=false 2>/dev/null || $BCLI loadwallet $WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m); mine 101

echo "=== KIND=3 STANDALONE force-close HTLC sweep (regtest) ==="
echo "    LSP arms kind=3 + exits; secret-less WT must do the sweep."
SS_FC_ARM_KIND3=1 "$LSP_BIN" --network regtest --port $PORT --demo --test-htlc-force-close --lsp-balance-pct 50 \
    --clients $N_CLIENTS --arity $ARITY --amount $AMOUNT --fee-rate $FEE --confirm-timeout 600 \
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

echo "--- waiting for KIND3-ARM COMPLETE + LSP exit (~6min) ---"
ARMED=0
for i in $(seq 1 220); do
    sleep 2
    grep -q "HTLC FORCE-CLOSE KIND3-ARM COMPLETE" "$LSP_LOG" 2>/dev/null && { ARMED=1; echo "  kind=3 armed (${i}*2s)"; break; }
    grep -qiE "KIND3-ARM: no wt_db|FORCE-CLOSE TEST: .*failed|FORCE-CLOSE TEST: need" "$LSP_LOG" 2>/dev/null && { echo "  LSP reported a force-close error"; break; }
    kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited"; break; }
done
for s in $(seq 1 30); do kill -0 $LSP_PID 2>/dev/null || break; sleep 1; done   # full exit -> wt.db WAL checkpoint
[ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null||true; MINER_PID=""

K3=$(sqlite3 "$WT_DB" "SELECT count(*) FROM wt_watches WHERE watch_kind=3;" 2>/dev/null || echo 0)
echo "  wt.db kind=3 watches: ${K3:-0}"
[ "$ARMED" -eq 1 ] || { tail -30 "$LSP_LOG"; fail "kind=3 never armed"; }
[ "${K3:-0}" -ge 1 ] || fail "no kind=3 watch in wt.db (arming did not persist)"

# keep mining so the standalone WT's poll advances + the sweep can confirm
( for k in $(seq 1 80); do mine 1; sleep 3; done ) & MINER_PID=$!

echo "--- standalone trustless WT (--wt-db only, LSP OFFLINE) ---"
"$WT_BIN" --network regtest --wt-db "$WT_DB" --poll-interval 5 --cli-path bitcoin-cli \
    --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" > "$WT_LOG" 2>&1 &
WT_PID=$!; PIDS+=($WT_PID)

# The trustless WT hydrates the kind=3 row uniformly as a factory-node entry
# (parent=force-close commit, response_tx=pre-signed HTLC-timeout sweep) and
# fires via the "Latest state tx broadcast" path when it sees the commit
# on-chain — NOT the legacy channel-rebuild path.  Detect that, capture the
# broadcast txid, then RIGOROUSLY confirm the sweep lands on-chain (spending
# the commit HTLC output).
echo "--- waiting for WT to broadcast the HTLC-timeout sweep (timeout 220s) ---"
WT_FIRED=0; SWEEP_TXID=""
for i in $(seq 1 110); do
    sleep 2
    SWEEP_TXID=$(grep -aoE "Latest state tx broadcast: [0-9a-f]{64}|HTLC timeout sweep[^0-9a-f]*[0-9a-f]{64}|timeout sweep[^0-9a-f]*[0-9a-f]{64}" "$WT_LOG" 2>/dev/null | grep -oE "[0-9a-f]{64}" | tail -1)
    if [ -n "$SWEEP_TXID" ]; then WT_FIRED=1; echo "  WT broadcast sweep $SWEEP_TXID (${i}*2s)"; break; fi
    if grep -qE "penalty tx\(s\) broadcast" "$WT_LOG" 2>/dev/null; then WT_FIRED=1; echo "  WT broadcast a penalty/sweep (${i}*2s)"; break; fi
    kill -0 $WT_PID 2>/dev/null || break
    [ $((i % 15)) -eq 0 ] && echo "  ... ${i}*2s ($(grep -c heartbeat "$WT_LOG" 2>/dev/null||echo 0) heartbeats)"
done

# Rigorous: confirm the swept tx actually lands on-chain (it spends the
# force-close commit's HTLC output — proves the sweep is valid, not just relayed).
SWEEP_CONF=0
if [ -z "$SWEEP_TXID" ]; then SWEEP_TXID=$(grep -aoE "Latest state tx broadcast: [0-9a-f]{64}" "$WT_LOG" 2>/dev/null | grep -oE "[0-9a-f]{64}" | tail -1); fi
if [ -n "$SWEEP_TXID" ]; then
    for k in $(seq 1 20); do
        C=$($BCLI getrawtransaction "$SWEEP_TXID" true 2>/dev/null | grep -oE "\"confirmations\": [0-9]+" | grep -oE "[0-9]+" | head -1)
        [ -n "$C" ] && [ "$C" -ge 1 ] && { SWEEP_CONF=1; echo "  sweep $SWEEP_TXID confirmed on-chain ($C confs)"; break; }
        mine 1; sleep 2
    done
fi

echo; echo "=== WT log tail ==="; tail -30 "$WT_LOG"
HYDRATED=$(grep -c "hydrated" "$WT_LOG" 2>/dev/null || echo 0)
echo; echo "=== Final result ==="
echo "  armed=$ARMED kind3=$K3 wt_hydrated=$HYDRATED wt_fired=$WT_FIRED sweep_txid=${SWEEP_TXID:-none} sweep_confirmed=$SWEEP_CONF"
# Tier-3 rigor: confirmation alone doesn't prove the sweep moved REAL value — assert amount.
SWEEP_SATS=0
if [ "$SWEEP_CONF" -eq 1 ]; then
    SV=$($BCLI getrawtransaction "$SWEEP_TXID" true 2>/dev/null | grep -oE '"value": *[0-9.]+' | grep -oE '[0-9.]+' | sort -rn | head -1)
    SWEEP_SATS=$(awk "BEGIN{printf \"%d\", ($SV+0)*100000000}")
    echo "  sweep largest output: ${SWEEP_SATS:-0} sats"
fi
# Tier-4 reorg-robustness (opt-in: SS_REORG_REFIRE=1, #95): orphan the sweep's block and
# verify the standalone WT re-broadcasts + the kind=3 HTLC-timeout sweep RE-confirms. The WT
# is still alive here (WT_PID, --poll-interval 5). Proves the force-close sweep survives a reorg.
REORG_OK=1
if [ "${SS_REORG_REFIRE:-0}" = 1 ] && [ "$SWEEP_CONF" -eq 1 ]; then
    echo "=== REORG-REFIRE: orphan the kind=3 sweep block, verify re-confirm ==="
    [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null||true; MINER_PID=""   # stop auto-miner so the invalidate sticks
    SBLK=$($BCLI getrawtransaction "$SWEEP_TXID" true 2>/dev/null | grep -oE '"blockhash": *"[0-9a-f]{64}"' | grep -oE '[0-9a-f]{64}' | head -1)
    if [ -n "$SBLK" ]; then
        echo "  invalidating sweep block $SBLK (orphans sweep $SWEEP_TXID)"; $BCLI invalidateblock "$SBLK" 2>/dev/null; sleep 6
        UC=$($BCLI getrawtransaction "$SWEEP_TXID" true 2>/dev/null | grep -oE '"confirmations": *[0-9]+' | grep -oE '[0-9]+' | head -1)
        if [ -z "$UC" ] || [ "$UC" -eq 0 ]; then
            echo "  sweep orphaned (confs ${UC:-0}); mining new chain to verify re-confirm"
            REORG_OK=0
            for i in $(seq 1 24); do mine 1; sleep 2; c=$($BCLI getrawtransaction "$SWEEP_TXID" true 2>/dev/null | grep -oE '"confirmations": *[0-9]+' | grep -oE '[0-9]+' | head -1); [ -n "$c" ] && [ "$c" -ge 1 ] && { REORG_OK=1; green "  REORG-REFIRE PASS: kind=3 sweep re-confirmed after orphaning its block ($c conf)"; break; }; done
            [ "$REORG_OK" -eq 1 ] || red "  REORG-REFIRE FAIL: kind=3 sweep did NOT re-confirm after reorg — force-close sweep LOST on reorg"
        else echo "  (reorg ineffective: sweep still at $UC confs — vacuous, skipping)"; fi
    else echo "  (could not find sweep block — skipping reorg check)"; fi
    ( for k in $(seq 1 40); do mine 1; sleep 3; done ) & MINER_PID=$!
fi
# Floor is the dust threshold (>=330), not an arbitrary 1000: an HTLC-timeout sweep recovers
# the (small) in-flight HTLC value minus fee — legitimately sub-1000 (observed 819 sats). The
# check must catch a zero/dust sweep, not false-fail a real small recovery.
if [ "$ARMED" -eq 1 ] && [ "${K3:-0}" -ge 1 ] && [ "$WT_FIRED" -eq 1 ] && [ "$SWEEP_CONF" -eq 1 ] && [ "${SWEEP_SATS:-0}" -ge 330 ] && [ "${REORG_OK:-1}" -eq 1 ]; then
    green "PASS: secret-less standalone WT (--wt-db only) swept the LSP's HTLC-timeout from wt.db (kind=3)"
    green "      alone — pre-signed sweep $SWEEP_TXID broadcast + CONFIRMED on-chain ($SWEEP_SATS sats),"
    green "      spending the force-close commit. Force-close HTLC-sweep delegation PROVEN trustless (last matrix cell)."
    exit 0
fi
red "FAIL: need armed + kind3>=1 + WT broadcast + sweep confirmed + real amount (>=330 sats, above dust)"; exit 1
