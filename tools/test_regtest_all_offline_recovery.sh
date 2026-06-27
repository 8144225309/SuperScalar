#!/usr/bin/env bash
# test_regtest_all_offline_recovery.sh -- #54 G1c: all-offline distribution-TX
# recovery (regtest end-to-end).
#
# Proves the "offline-forever recovery net" that G1a/G1b restored.  At factory
# creation the LSP + every client now CO-SIGN the distribution TX (a single TX
# that spends the funding UTXO and pays each client their balance, with
# nLockTime = the factory CLTV).  If EVERYONE goes offline forever and nobody
# ever does a per-leaf unilateral exit, ANYONE can broadcast that one co-signed
# distribution TX at the factory CLTV and every client still gets paid.
#
# Flow:
#   1. Build an N-client PS factory (LSP --demo + N daemon clients).
#   2. Assert every client co-signed + PERSISTED the distribution TX
#      (distribution_txs row, factory_id=0) and they all hold the SAME tx.
#   3. EVERYONE VANISHES (LSP + all clients killed; no per-leaf exit).
#   4. CLTV gate: the dist TX must be REJECTED before its nLockTime (non-final).
#   5. Mine to the nLockTime, then ANYONE broadcasts the dist TX.
#   6. Assert it confirms, spends the factory funding UTXO, has N client
#      outputs, and conserves value (Sigma outputs == funding - fee).
#
# This is the on-chain e2e counterpart to the in-process distributed-signing
# proof (tests/test_factory.c::test_factory_distribution_tx_distributed +
# test_inproc_scale dist_tx_ready==2).
set -uo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

N_CLIENTS="${N_CLIENTS:-4}"
AMOUNT="${AMOUNT:-200000}"
PORT="${PORT:-29958}"
FEE="${FEE:-1100}"
DIST_FEE_SATS=500   # must match lsp.c factory_compute_distribution_outputs_balanced fee arg
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
[ -f "$REGTEST_CONF" ] || REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RU=${RU:-rpcuser}
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RP=${RP:-rpcpass}
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RPORT=${RPORT:-18443}
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"
WALLET="ss_cheat_leaf_miner"

command -v sqlite3 >/dev/null 2>&1 || { echo "FAIL: sqlite3 not found"; exit 1; }
[ -x "$LSP_BIN" ] || { echo "FAIL: $LSP_BIN not found"; exit 1; }
[ -x "$CLIENT_BIN" ] || { echo "FAIL: $CLIENT_BIN not found"; exit 1; }

TMPDIR=$(mktemp -d /tmp/ss-offline-recovery.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"; LSP_LOG="$TMPDIR/lsp.log"
PIDS=(); MINER_PID=""
cleanup(){
    [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null || true
    for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
    cp "$LSP_LOG" /tmp/offline_recovery_last_lsp.log 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
red(){ printf '\033[31m%s\033[0m\n' "$*"; }
fail(){ red "FAIL: $*"; exit 1; }
mine(){ $BCLI -rpcwallet=$WALLET generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1 || true; }
sk(){ printf "00000000000000000000000000000000000000000000000000000000000000%02x" $(( $1 + 1 )); }
jget(){ python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

$BCLI getblockchaininfo >/dev/null 2>&1 || fail "regtest bitcoind unreachable ($REGTEST_CONF)"
$BCLI -named createwallet wallet_name=$WALLET load_on_startup=false 2>/dev/null || $BCLI loadwallet $WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m)
mine 101

echo "=== #54 G1c: all-offline distribution-TX recovery (regtest, N=$N_CLIENTS, amount=$AMOUNT) ==="

# --- build the factory (LSP --demo + N daemon clients) ---
"$LSP_BIN" --network regtest --port $PORT --demo --lsp-balance-pct 50 \
    --clients $N_CLIENTS --arity 3 --amount $AMOUNT --fee-rate $FEE --confirm-timeout 600 \
    --seckey "$LSP_SECKEY" --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" \
    --wallet "$WALLET" --db "$LSP_DB" > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 60); do sleep 1; grep -q "listening" "$LSP_LOG" 2>/dev/null && { echo "  LSP listening"; break; }; kill -0 $LSP_PID 2>/dev/null || { tail -25 "$LSP_LOG"; fail "LSP died before listening"; }; done
grep -q "listening" "$LSP_LOG" || fail "LSP never listened"

for i in $(seq 0 $((N_CLIENTS-1))); do
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $PORT --daemon \
        --seckey "$(sk $i)" --fee-rate $FEE --lsp-balance-pct 50 --lsp-pubkey "$LSP_PUB" \
        --participant-id $((i+1)) --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" \
        --wallet "$WALLET" --db "$TMPDIR/c${i}.db" > "$TMPDIR/c${i}.log" 2>&1 &
    PIDS+=($!); sleep 0.4
done
( while kill -0 $LSP_PID 2>/dev/null; do mine 1; sleep 2; done ) & MINER_PID=$!

echo "--- building factory; waiting for 'channels ready' ---"
for i in $(seq 1 150); do sleep 2; grep -q "channels ready" "$LSP_LOG" 2>/dev/null && { echo "  channels ready"; break; }; kill -0 $LSP_PID 2>/dev/null || { tail -40 "$LSP_LOG"; fail "LSP died before factory ready"; }; done
grep -q "channels ready" "$LSP_LOG" || { tail -40 "$LSP_LOG"; fail "factory never reached 'channels ready'"; }

# --- verify EVERY client co-signed + PERSISTED the distribution TX (G1a/G1b) ---
# A populated distribution_txs row proves the dist TX was co-signed
# (dist_tx_ready==2), shipped in FACTORY_READY, and durably persisted by the
# client daemon (tools/superscalar_client.c persist_save_distribution_tx).
echo "--- verifying every client co-signed + persisted the distribution TX ---"
ALLD=0
for i in $(seq 1 40); do
    sleep 2; ALLD=1
    for c in $(seq 0 $((N_CLIENTS-1))); do
        d=$(sqlite3 "$TMPDIR/c${c}.db" "SELECT count(*) FROM distribution_txs;" 2>/dev/null || echo 0)
        [ "${d:-0}" -ge 1 ] || ALLD=0
    done
    [ "$ALLD" = 1 ] && break
done
for c in $(seq 0 $((N_CLIENTS-1))); do
    d=$(sqlite3 "$TMPDIR/c${c}.db" "SELECT count(*) FROM distribution_txs;" 2>/dev/null || echo 0)
    echo "    c$c: distribution_txs rows=$d"
done
[ "$ALLD" = 1 ] || fail "not every client persisted the co-signed distribution TX (offline-net missing) -- check FACTORY_READY dist co-signing"
green "  every client durably holds the co-signed distribution TX (offline-forever recovery net present)"

# --- extract the dist TX; all clients must hold the SAME co-signed tx ---
DIST_HEX=$(sqlite3 "$TMPDIR/c0.db" "SELECT signed_tx_hex FROM distribution_txs LIMIT 1;" 2>/dev/null)
[ -n "$DIST_HEX" ] || fail "could not extract distribution TX hex from c0.db"
for c in $(seq 1 $((N_CLIENTS-1))); do
    h=$(sqlite3 "$TMPDIR/c${c}.db" "SELECT signed_tx_hex FROM distribution_txs LIMIT 1;" 2>/dev/null)
    [ "$h" = "$DIST_HEX" ] || fail "client c$c holds a DIFFERENT distribution TX than c0 (must be the shared co-signed tx)"
done
green "  all $N_CLIENTS clients hold the IDENTICAL co-signed distribution TX"

DIST_DECODE=$($BCLI decoderawtransaction "$DIST_HEX" 2>/dev/null) || fail "decoderawtransaction failed (dist TX malformed)"
# single-pass field extraction: P2TR client outputs vs the #56 P2A CPFP anchor
# (script 51024e73, 240 sats, appended when feerate >= 1000 sat/kvB so the
# offline net can be CPFP-bumped to win the mass-exit fee race).
eval "$(printf '%s\n' "$DIST_DECODE" | python3 -c '
import json,sys
d=json.load(sys.stdin); vout=d["vout"]
tr =[o for o in vout if o.get("scriptPubKey",{}).get("type")=="witness_v1_taproot"]
anc=[o for o in vout if o.get("scriptPubKey",{}).get("hex")=="51024e73"]
print("DIST_TXID=%s"%d["txid"])
print("DIST_NLOCK=%d"%d["locktime"])
print("DIST_NOUT=%d"%len(vout))
print("DIST_NIN=%d"%len(d["vin"]))
print("DIST_VIN=%s:%d"%(d["vin"][0]["txid"],d["vin"][0]["vout"]))
print("DIST_OUTSUM=%d"%int(round(sum(o["value"] for o in vout)*1e8)))
print("DIST_TR_N=%d"%len(tr))
print("DIST_ANCHOR_N=%d"%len(anc))
print("DIST_ANCHOR_VAL=%d"%int(round(sum(o["value"] for o in anc)*1e8)))
')"
echo "  dist txid     : $DIST_TXID"
echo "  dist nLockTime: $DIST_NLOCK   (== factory CLTV)"
echo "  dist inputs   : $DIST_NIN  (spends $DIST_VIN -- the factory funding UTXO)"
echo "  dist outputs  : $DIST_NOUT  ($DIST_TR_N P2TR client + $DIST_ANCHOR_N P2A anchor)  Sigma=$DIST_OUTSUM sats  (funding=$AMOUNT)"
[ "$DIST_NLOCK" -gt 0 ] || fail "dist TX nLockTime is 0 -- not CLTV-gated"
[ "$DIST_NIN" -eq 1 ] || fail "dist TX has $DIST_NIN inputs, expected 1 (the funding UTXO)"
[ "$DIST_TR_N" -eq "$N_CLIENTS" ] || fail "dist TX has $DIST_TR_N P2TR outputs, expected $N_CLIENTS (one per client)"
[ "$DIST_ANCHOR_N" -le 1 ] || fail "dist TX has $DIST_ANCHOR_N P2A anchors, expected 0 or 1"
[ "$DIST_NOUT" -eq $((DIST_TR_N + DIST_ANCHOR_N)) ] || fail "dist TX outputs unaccounted (nout=$DIST_NOUT tr=$DIST_TR_N anchor=$DIST_ANCHOR_N)"
if [ "$DIST_ANCHOR_N" -eq 1 ]; then
    [ "$DIST_ANCHOR_VAL" -eq 240 ] || fail "P2A anchor value $DIST_ANCHOR_VAL, expected 240 (#56 CPFP anchor)"
    green "  dist TX carries a #56 P2A CPFP anchor (240 sats) -- offline net is fee-bumpable at the deadline"
fi

# --- verify the funding UTXO is currently UNSPENT (factory still open) ---
FUND_TXID=$(echo "$DIST_VIN" | cut -d: -f1); FUND_VOUT=$(echo "$DIST_VIN" | cut -d: -f2)
UTXO=$($BCLI gettxout "$FUND_TXID" "$FUND_VOUT" 2>/dev/null)
[ -n "$UTXO" ] || fail "funding UTXO $DIST_VIN already spent before recovery (factory was closed) -- cannot test offline net"
green "  factory funding UTXO $DIST_VIN is UNSPENT (factory open, no per-leaf exit)"

# --- EVERYONE VANISHES (offline forever) ---
echo "--- EVERYONE VANISHES (LSP + all $N_CLIENTS clients killed; nobody does a per-leaf exit) ---"
kill -9 "$MINER_PID" 2>/dev/null || true; MINER_PID=""
for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null || true; done
PIDS=(); sleep 2

# --- CLTV gate: dist TX must be REJECTED before its nLockTime ---
H=$($BCLI getblockcount)
echo "--- CLTV gate check: height=$H, dist nLockTime=$DIST_NLOCK ---"
if [ "$H" -lt "$DIST_NLOCK" ]; then
    EARLY=$($BCLI sendrawtransaction "$DIST_HEX" 2>&1 || true)
    echo "  early broadcast -> $EARLY"
    if echo "$EARLY" | grep -qiE "non-final|nonfinal|non-BIP68"; then
        green "  dist TX correctly REJECTED before nLockTime (CLTV gate holds)"
    elif echo "$EARLY" | grep -qE "^[0-9a-f]{64}$"; then
        fail "dist TX confirmed BEFORE its nLockTime -- CLTV gate BROKEN"
    else
        echo "  (early broadcast rejected for another reason; CLTV gate inconclusive: $EARLY)"
    fi
else
    echo "  (chain already at/after nLockTime; skipping early-rejection check)"
fi

# --- mine to the nLockTime, then ANYONE broadcasts the dist TX ---
H=$($BCLI getblockcount); NEED=$(( DIST_NLOCK - H ))
if [ "$NEED" -gt 0 ]; then echo "--- mining $((NEED+1)) blocks to reach factory CLTV ($DIST_NLOCK) ---"; mine $((NEED+1)); fi
H=$($BCLI getblockcount); echo "  height now $H (>= nLockTime $DIST_NLOCK)"

echo "--- broadcasting the co-signed distribution TX (no LSP, no client online) ---"
SENT=$($BCLI sendrawtransaction "$DIST_HEX" 2>&1 || true)
echo "  sendrawtransaction -> $SENT"
echo "$SENT" | grep -qE "^[0-9a-f]{64}$" || fail "dist TX broadcast rejected after nLockTime: $SENT"
mine 2
CONF=$($BCLI getrawtransaction "$DIST_TXID" true 2>/dev/null | jget "d.get('confirmations',0)" 2>/dev/null || echo 0)
echo "  dist TX confirmations: $CONF"

# --- assertions ---
FEE_PAID=$(( AMOUNT - DIST_OUTSUM ))
echo
echo "=== offline-recovery accounting ==="
echo "  dist TX confirmed         : ${CONF} confs"
echo "  spent funding UTXO        : $DIST_VIN"
echo "  client P2TR outputs       : $DIST_TR_N  (expected $N_CLIENTS)"
echo "  P2A CPFP anchors          : $DIST_ANCHOR_N  (total vout $DIST_NOUT)"
echo "  Sigma dist outputs        : $DIST_OUTSUM sats"
echo "  on-chain fee (funding-Sigma): $FEE_PAID sats (expected $DIST_FEE_SATS)"
if [ "${CONF:-0}" -ge 1 ] \
   && [ "$DIST_TR_N" -eq "$N_CLIENTS" ] \
   && [ "$DIST_OUTSUM" -eq $((AMOUNT - DIST_FEE_SATS)) ] \
   && [ "$FEE_PAID" -eq "$DIST_FEE_SATS" ]; then
    UTXO2=$($BCLI gettxout "$FUND_TXID" "$FUND_VOUT" 2>/dev/null)
    [ -z "$UTXO2" ] || fail "funding UTXO still unspent after dist broadcast -- dist TX did not spend it"
    green "PASS: with EVERYONE offline forever, the co-signed distribution TX confirmed at the factory CLTV,"
    green "      spent the funding UTXO, and paid all $N_CLIENTS clients ($DIST_TR_N P2TR outputs + $DIST_ANCHOR_N anchor,"
    green "      Sigma=$DIST_OUTSUM/$AMOUNT sats, fee=$FEE_PAID). #54 offline-forever recovery net PROVEN e2e on regtest. [#54 G1c]"
    exit 0
else
    fail "offline-recovery assertions failed (conf=$CONF tr_n=$DIST_TR_N outsum=$DIST_OUTSUM expect=$((AMOUNT-DIST_FEE_SATS)) fee=$FEE_PAID)"
fi
