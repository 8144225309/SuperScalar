#!/usr/bin/env bash
# ROTATION RESTART-RESUME drill (#332 follow-up — closes the restart-resume gap).
#
# Proves the idempotency guard in lsp_channels_rotate_factory (lsp_rotation.c:114)
# is FUND-SAFE across a real process restart. We crash the LSP at the new
# `rotate_close_broadcast` checkpoint — the ONLY window that triggers the guard:
# AFTER Phase B broadcast+confirmed the cooperative close (the dying factory's
# funding is now spent on-chain) but BEFORE Phase C created/persisted the
# replacement factory. At this instant the DB still shows the factory DYING with
# its now-spent funding, so a restart's daemon retry path re-enters rotation on
# it and MUST short-circuit via the already-spent guard — NO second close
# (double-spend) and NO second replacement-factory funding (stranded liquidity).
#
# This checkpoint is also clean: only ONE factory has ever existed at the crash
# point (Phase C never ran), so on restart there is a single DYING factory, the
# guard fires on the first ladder tick, and there is no ladder churn to pollute
# the close count.
#
# PASS: guard message present in the restart log AND the single Phase-1 close
#       confirms on-chain AND the restart did NOT run Phase B/Phase C again
#       (no re-close, no re-fund).
set -uo pipefail
cd /root/SuperScalar

CKPT="${CKPT:-rotate_close_broadcast}"
PORT="${PORT:-9974}"
TMP="/tmp/rot_resume_$CKPT"
BUILD="${BUILD:-build-release}"
CONF=/var/lib/bitcoind-regtest/bitcoin.conf
BCLI="bitcoin-cli -regtest -conf=$CONF"
WALLET="${WALLET:-ss_cheat_leaf_miner}"
LSP_SECKEY=0000000000000000000000000000000000000000000000000000000000000001
LSP_PUB=0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
DB="$TMP/lsp.db"
AMOUNT=200000

cleanup() { kill -9 ${LSP1:-0} ${LSP2:-0} ${MINER:-0} 2>/dev/null || true
            pkill -9 -f "superscalar_(lsp|client).*--port $PORT" 2>/dev/null || true; }
trap cleanup EXIT

pkill -9 -f "superscalar_(lsp|client).*--port $PORT" 2>/dev/null || true
rm -rf "$TMP"; mkdir -p "$TMP"

# robust wallet load + mature coinbases (101 like the matrix)
$BCLI loadwallet "$WALLET" >/dev/null 2>&1 || true
MADDR=$($BCLI -rpcwallet="$WALLET" -named getnewaddress address_type=bech32m 2>/dev/null)
[ -n "$MADDR" ] || { echo "RESUME-FAIL: could not get mine address"; exit 1; }
$BCLI -rpcwallet="$WALLET" generatetoaddress 101 "$MADDR" >/dev/null 2>&1
echo "wallet balance: $($BCLI -rpcwallet=$WALLET getbalance) BTC ; mine_addr=$MADDR"

LSP_ARGS=(--network regtest --port $PORT --daemon --active-blocks 6 --dying-blocks 120
  --lsp-balance-pct 50 --clients 4 --arity 2 --amount $AMOUNT --fee-rate 1100
  --confirm-timeout 86400 --seckey $LSP_SECKEY
  --rpcuser rpcuser --rpcpassword rpcpass --rpcport 18443 --wallet "$WALLET" --db "$DB")

# --- Phase 1: LSP with crash-at + 4 clients (1-based participant-id, matrix scheme) ---
SUPERSCALAR_CRASH_AT="$CKPT" "$BUILD/superscalar_lsp" "${LSP_ARGS[@]}" > "$TMP/lsp1.log" 2>&1 &
LSP1=$!
for i in $(seq 1 20); do sleep 1; grep -q listening "$TMP/lsp1.log" 2>/dev/null && break; kill -0 $LSP1 2>/dev/null || break; done
grep -q listening "$TMP/lsp1.log" || { echo "RESUME-FAIL: LSP1 never listened"; tail -8 "$TMP/lsp1.log"; exit 1; }

for N in 1 2 3 4; do
  SK=$(printf "%064x" $((N + 1)))
  "$BUILD/superscalar_client" --network regtest --host 127.0.0.1 --port $PORT --daemon \
    --seckey "$SK" --fee-rate 1100 --lsp-balance-pct 50 --lsp-pubkey $LSP_PUB \
    --participant-id $N --rpcuser rpcuser --rpcpassword rpcpass --rpcport 18443 \
    --wallet "$WALLET" --db "$TMP/c${N}.db" > "$TMP/c${N}.log" 2>&1 &
  sleep 0.3
done

# robust background miner (stops when LSP1 dies)
( while kill -0 $LSP1 2>/dev/null; do $BCLI -rpcwallet="$WALLET" generatetoaddress 1 "$MADDR" >/dev/null 2>&1; sleep 2; done ) &
MINER=$!

# wait up to 500s for the crash at rotate_close_broadcast
ABORTED=0
for i in $(seq 1 500); do
  sleep 1
  kill -0 $LSP1 2>/dev/null || { grep -q "lsp_crash_checkpoint: HIT '$CKPT'" "$TMP/lsp1.log" && ABORTED=1; break; }
done
if [ "$ABORTED" != 1 ]; then
  echo "RESUME-NOFIRE: LSP1 did not hit $CKPT in 500s"; grep -aE "LSP rotate:|DYING|auto-rotation|HIT" "$TMP/lsp1.log" | tail -12
  kill -9 $LSP1 $MINER 2>/dev/null; exit 1
fi
echo "=== Phase 1: crashed at $CKPT (close broadcast+confirmed, pre-Phase-C) ==="
grep -aE "LSP rotate:|closed:|funded .*sats|HIT" "$TMP/lsp1.log" | tail -8

# Capture the single legitimate close txid broadcast in Phase 1.
CLOSE1=$(grep -aoE "factory [0-9]+ closed: [0-9a-f]{64}" "$TMP/lsp1.log" | grep -oE "[0-9a-f]{64}" | tail -1)
echo "Phase-1 close txid: ${CLOSE1:-<none>}"
[ -n "$CLOSE1" ] || { echo "RESUME-FAIL: no Phase-1 close txid (crash landed before close?)"; exit 1; }

# --- Phase 2: RESTART (no crash-at). Daemon retry path re-enters rotation on the
#     still-DYING factory; the guard must detect funding-spent and no-op. ---
echo "=== Phase 2: restart (recovery; retry path re-enters rotation) ==="
"$BUILD/superscalar_lsp" "${LSP_ARGS[@]}" > "$TMP/lsp2.log" 2>&1 &
LSP2=$!
( while kill -0 $LSP2 2>/dev/null; do $BCLI -rpcwallet="$WALLET" generatetoaddress 1 "$MADDR" >/dev/null 2>&1; sleep 2; done ) &
MINER=$!
# Break the instant the guard fires (kill before any further ladder activity).
GUARD_RE="already spent.*idempotently|funding.*already spent"
for i in $(seq 1 120); do
  sleep 1
  kill -0 $LSP2 2>/dev/null || break
  grep -qaE "$GUARD_RE" "$TMP/lsp2.log" 2>/dev/null && { echo "guard fired at ~${i}s"; break; }
done
kill -9 $LSP2 $MINER 2>/dev/null
sleep 1

echo "=== Phase 2 markers (recovery + guard) ==="
grep -aE "recovery|recover|rotate|already spent|idempotent|FINALIZED|closed:|funded|Phase B|Phase C" "$TMP/lsp2.log" | tail -20

# --- assertions ---
# 1) guard fired (note: grep -c prints 0 AND exits 1 on no-match, so DO NOT chain
#    `|| echo 0` — that would append a SECOND 0 and corrupt the integer test).
GUARD_FIRED=$(grep -acE "$GUARD_RE" "$TMP/lsp2.log" 2>/dev/null) || GUARD_FIRED=0
# 2) restart must NOT have re-run the close or the re-fund (no-re-broadcast/no-re-fund)
RECLOSE=$(grep -acE "LSP rotate: Phase B — cooperative close|LSP rotate: factory [0-9]+ closed:" "$TMP/lsp2.log" 2>/dev/null) || RECLOSE=0
REFUND=$(grep -acE "LSP rotate: Phase C — creating new factory|LSP rotate: funded [0-9]+ sats" "$TMP/lsp2.log" 2>/dev/null) || REFUND=0
# 3) the single Phase-1 close confirmed on-chain
CONF1=$($BCLI getrawtransaction "$CLOSE1" true 2>/dev/null | grep -c '"confirmations"' || true)
CONF1=${CONF1:-0}

echo
echo "=== fund-safety: guard_fired=$GUARD_FIRED  reclose=$RECLOSE  refund=$REFUND  close1_confirmed=$CONF1 ==="
if [ "$GUARD_FIRED" -ge 1 ] && [ "$RECLOSE" -eq 0 ] && [ "$REFUND" -eq 0 ] && [ "$CONF1" -ge 1 ]; then
  echo "RESUME-PASS: restart guard fired — funding-spent detected; no re-close, no re-fund; the single Phase-1 close ($CLOSE1) is confirmed. Fund-safe idempotent restart-resume."
  exit 0
else
  echo "RESUME-FAIL: guard_fired=$GUARD_FIRED reclose=$RECLOSE refund=$REFUND close1_confirmed=$CONF1 (want guard>=1, reclose=0, refund=0, close1_confirmed>=1)"
  exit 1
fi
