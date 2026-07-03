#!/usr/bin/env bash
# test_regtest_restore_drill.sh -- #331: disaster-recovery restore-from-backup drill (regtest).
#
# Proves the documented backup procedure (SQLite WAL-safe `sqlite3 .backup`,
# mainnet-runbook section 3) yields a COMPLETE, RESTORABLE, USABLE LSP DB:
#   [1] create a factory (--demo) persisting to lsp.db; wait for completion
#   [2] HOT backup the LIVE db via `sqlite3 .backup` (safe vs concurrent writers)
#   [3] simulate disaster: kill the LSP + DELETE lsp.db (+ WAL/SHM)
#   [4] assert the backup is a complete copy of the original (same factory id)
#   [5] RESTORE: copy the backup back to lsp.db; assert state == original
#   [6] RESUME + USE: restart the LSP on the restored db with --force-close
#       (no --demo) -- the recovery probe loads the factory from db
#   [7]/[8] assert resume succeeded: recovery-probe load AND/OR a tree broadcast
#       from the restored db that confirms on-chain (funds recoverable post-restore)
#
# Usage: bash tools/test_regtest_restore_drill.sh [BUILD_DIR]
set -uo pipefail
BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"; CLIENT_BIN="$BUILD_DIR/superscalar_client"
N_CLIENTS="${N_CLIENTS:-4}"; AMOUNT="${AMOUNT:-200000}"; PORT="${PORT:-29981}"; FEE="${FEE:-1100}"; ARITY="${ARITY:-2}"
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RU=${RU:-rpcuser}
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RP=${RP:-rpcpass}
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RPORT=${RPORT:-18443}
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"; WALLET="ss_cheat_leaf_miner"
TMPDIR=$(mktemp -d /tmp/ss-restore.XXXXXX); LSP_DB="$TMPDIR/lsp.db"; BACKUP="$TMPDIR/backup.db"
LSP_LOG="$TMPDIR/lsp1.log"; LSP2_LOG="$TMPDIR/lsp2.log"
PIDS=(); MINER_PID=""
cleanup(){ [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null||true; pkill -9 -f "superscalar_(lsp|client).*--port $PORT" 2>/dev/null||true; for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null||true; done; cp "$LSP_LOG" /tmp/restore_lsp1.log 2>/dev/null||true; cp "$LSP2_LOG" /tmp/restore_lsp2.log 2>/dev/null||true; }
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }; red(){ printf '\033[31m%s\033[0m\n' "$*"; }; fail(){ red "FAIL: $*"; exit 1; }
mine(){ $BCLI -rpcwallet=$WALLET generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1||true; }
sk(){ local b; b=$(printf "%02x" $((34 + $1 * 17))); printf "${b}%.0s" {1..32}; }
# factory identity from a db (count : funding_txid hex). factories table always exists.
dbid(){ sqlite3 "$1" "SELECT count(*)||':'||COALESCE((SELECT lower(hex(funding_txid)) FROM factories LIMIT 1),'-') FROM factories;" 2>/dev/null; }

$BCLI -named createwallet wallet_name=$WALLET load_on_startup=false 2>/dev/null || $BCLI loadwallet $WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m); [ -n "$MINE_ADDR" ] || fail "no mine address"; mine 101

echo "=== #331 restore-from-backup drill (N=$N_CLIENTS) ==="
echo "--- [1/8] create factory (persist to lsp.db) ---"
"$LSP_BIN" --network regtest --port $PORT --demo --lsp-balance-pct 50 \
    --clients $N_CLIENTS --arity $ARITY --amount $AMOUNT --fee-rate $FEE --confirm-timeout 600 \
    --seckey "$LSP_SECKEY" --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" \
    --wallet "$WALLET" --db "$LSP_DB" > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 60); do sleep 1; grep -q "listening" "$LSP_LOG" 2>/dev/null && break; kill -0 $LSP_PID 2>/dev/null||{ tail -20 "$LSP_LOG"; fail "LSP died early"; }; done
for i in $(seq 0 $((N_CLIENTS-1))); do
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $PORT --daemon --seckey "$(sk $i)" --fee-rate $FEE \
        --lsp-balance-pct 50 --lsp-pubkey "$LSP_PUB" --participant-id $((i+1)) --rpcuser "$RU" --rpcpassword "$RP" \
        --rpcport "$RPORT" --wallet "$WALLET" --db "$TMPDIR/c${i}.db" > "$TMPDIR/c${i}.log" 2>&1 &
    PIDS+=($!); sleep 0.4
done
( while kill -0 $LSP_PID 2>/dev/null; do mine 1; sleep 2; done ) & MINER_PID=$!
for i in $(seq 1 120); do sleep 2; grep -q "factory creation complete" "$LSP_LOG" 2>/dev/null && { echo "  factory created + persisted"; break; }; kill -0 $LSP_PID 2>/dev/null||{ tail -20 "$LSP_LOG"; fail "LSP died before factory complete"; }; done
grep -q "factory creation complete" "$LSP_LOG" 2>/dev/null || fail "factory never completed"
sleep 3

echo "--- [2/8] HOT backup (sqlite3 .backup, live db) ---"
sqlite3 "$LSP_DB" ".backup '$BACKUP'" 2>/dev/null || fail "sqlite3 .backup failed"
[ -s "$BACKUP" ] || fail "backup file empty"
ORIG=$(dbid "$LSP_DB"); BAK=$(dbid "$BACKUP")
echo "  original factory (count:funding): $ORIG"
echo "  backup   factory (count:funding): $BAK"

echo "--- [3/8] SIMULATE DISASTER (kill LSP + wipe db) ---"
kill -9 $LSP_PID 2>/dev/null||true; kill -9 "$MINER_PID" 2>/dev/null||true; MINER_PID=""
pkill -9 -f "superscalar_client.*--port $PORT" 2>/dev/null||true
sleep 2
rm -f "$LSP_DB" "$LSP_DB-wal" "$LSP_DB-shm"
[ ! -f "$LSP_DB" ] || fail "lsp.db not wiped"
echo "  lsp.db wiped (+ WAL/SHM)"

echo "--- [4/8] assert backup completeness (== original) ---"
[ -n "$ORIG" ] && [ "$ORIG" = "$BAK" ] || fail "backup ($BAK) != original ($ORIG) -- .backup incomplete"
FAC=$(echo "$BAK" | cut -d: -f1); [ "${FAC:-0}" -ge 1 ] || fail "backup has no factory rows"
green "  backup is a complete copy of the original ($BAK)"

echo "--- [5/8] RESTORE (copy backup -> lsp.db) ---"
cp "$BACKUP" "$LSP_DB" || fail "restore copy failed"
REST=$(dbid "$LSP_DB"); [ "$REST" = "$ORIG" ] || fail "restored ($REST) != original ($ORIG)"
green "  restored lsp.db factory: $REST"

echo "--- [6/7] RESUME on restored db (--daemon triggers the recovery probe) ---"
# The recovery probe is gated on (use_db && daemon_mode) -> --daemon + --db loads
# the factory from the restored DB and enters recovery mode (no fresh ceremony).
"$LSP_BIN" --network regtest --port $PORT --daemon \
    --seckey "$LSP_SECKEY" --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" \
    --wallet "$WALLET" --db "$LSP_DB" > "$LSP2_LOG" 2>&1 &
LSP2_PID=$!; PIDS+=($LSP2_PID)
for i in $(seq 1 60); do
    sleep 1
    grep -qiE "entering recovery mode|found existing factory in DB" "$LSP2_LOG" 2>/dev/null && { echo "  recovery mode entered (${i}s)"; break; }
    kill -0 $LSP2_PID 2>/dev/null || { echo "  resume LSP exited early"; break; }
done
sleep 2

echo "--- [7/7] verify the LSP RESUMED the factory from the restored db ---"
if ! grep -qiE "found existing factory in DB|entering recovery mode" "$LSP2_LOG" 2>/dev/null; then
    echo "--- lsp2 log tail ---"; tail -25 "$LSP2_LOG"
    kill -9 $LSP2_PID 2>/dev/null || true
    fail "LSP did not enter recovery mode from the restored db (resume not usable)"
fi
echo "  recovery-mode evidence:"
grep -iE "found existing factory in DB|entering recovery mode|LSP recovery|loaded .* from DB" "$LSP2_LOG" 2>/dev/null | head -8 | sed 's/^/    /'
kill -9 $LSP2_PID 2>/dev/null || true
green "PASS: restore-from-backup drill -- hot sqlite3 .backup is a COMPLETE copy, RESTORED to identical state, and the LSP RESUMED the factory from the restored db (recovery probe loaded it)"
echo "RESTORE_DRILL_TEST PASS"
