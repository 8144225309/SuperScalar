#!/usr/bin/env bash
# test_regtest_trustless_commitment_gap.sh — RED proof (then green guard) for the
# trustless channel-commitment gap (#292 reopened).
#
# Runs a --demo factory with --wt-db. The demo routes payments, each revoking the
# prior channel commitment -> the LSP's IN-PROCESS watchtower_watch_revoked_commitment
# fires (proven by lsp.db old_commitments rows). The TRUSTLESS wt.db should then carry
# a matching WT_KIND_CHANNEL_COMMITMENT (=2) watch so a standalone WT (no secrets) can
# penalize a revoked-commitment broadcast.
#
# BEFORE the fix: wt.db kind=2 == 0  (RED — the gap: in-process registered, wt.db did not)
# AFTER  the fix: wt.db kind=2 >= 1  (GREEN)
#
# This is the regression guard so the cell [channel-commitment x trustless WT] can
# never silently regress again.
set -uo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"; CLIENT_BIN="$BUILD_DIR/superscalar_client"
N_CLIENTS=4; PORT=29960; FEE=1100
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RU=${RU:-rpcuser}
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RP=${RP:-rpcpass}
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$REGTEST_CONF"); RPORT=${RPORT:-18443}
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"; WALLET="ss_cheat_leaf_miner"
TMPDIR=$(mktemp -d /tmp/ss-tl-commit-gap.XXXXXX); LSP_DB="$TMPDIR/lsp.db"; WT_DB="$TMPDIR/wt.db"; LSP_LOG="$TMPDIR/lsp.log"
PIDS=(); MINER_PID=""
cleanup(){ [ -n "$MINER_PID" ] && kill -9 "$MINER_PID" 2>/dev/null||true; pkill -9 -f "superscalar_(lsp|client).*--port $PORT" 2>/dev/null||true; for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null||true; done; cp "$LSP_LOG" /tmp/tl_commit_gap_lsp.log 2>/dev/null||true; }
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }; red(){ printf '\033[31m%s\033[0m\n' "$*"; }
mine(){ $BCLI -rpcwallet=$WALLET generatetoaddress "${1:-1}" "$MINE_ADDR" >/dev/null 2>&1||true; }
sk(){ printf "00000000000000000000000000000000000000000000000000000000000000%02x" $(( $1 + 1 )); }

$BCLI -named createwallet wallet_name=$WALLET load_on_startup=false 2>/dev/null || $BCLI loadwallet $WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m); mine 101

echo "=== RED proof: does --demo --wt-db write a channel-commitment (kind=2) watch? ==="
"$LSP_BIN" --network regtest --port $PORT --demo --lsp-balance-pct 50 --clients $N_CLIENTS --arity 3 \
    --amount 200000 --fee-rate $FEE --confirm-timeout 600 --seckey "$LSP_SECKEY" \
    --rpcuser "$RU" --rpcpassword "$RP" --rpcport "$RPORT" --wallet "$WALLET" \
    --db "$LSP_DB" --wt-db "$WT_DB" > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 60); do sleep 1; grep -q "listening" "$LSP_LOG" 2>/dev/null && break; kill -0 $LSP_PID 2>/dev/null||{ tail -20 "$LSP_LOG"; red "LSP died"; exit 1; }; done
for i in $(seq 0 $((N_CLIENTS-1))); do
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $PORT --daemon --seckey "$(sk $i)" --fee-rate $FEE \
        --lsp-balance-pct 50 --lsp-pubkey "$LSP_PUB" --participant-id $((i+1)) --rpcuser "$RU" --rpcpassword "$RP" \
        --rpcport "$RPORT" --wallet "$WALLET" --db "$TMPDIR/c${i}.db" > "$TMPDIR/c${i}.log" 2>&1 &
    PIDS+=($!); sleep 0.4
done
( while kill -0 $LSP_PID 2>/dev/null; do mine 1; sleep 2; done ) & MINER_PID=$!
# let payments run (demo routes payments that revoke commitments) then settle
for i in $(seq 1 90); do sleep 2; grep -qE "channels ready" "$LSP_LOG" 2>/dev/null && break; kill -0 $LSP_PID 2>/dev/null||break; done
sleep 25   # allow the demo payment sequence to revoke commitments

echo "--- in-process watchtower DID register revoked commitments (lsp.db old_commitments)? ---"
OLDC=$(sqlite3 "$LSP_DB" "SELECT count(*) FROM old_commitments;" 2>/dev/null || echo 0)
echo "  lsp.db old_commitments rows: $OLDC  (in-process WT breach feed)"
echo "--- trustless wt.db watch_kind breakdown ---"
sqlite3 "$WT_DB" "SELECT watch_kind, count(*) FROM wt_watches GROUP BY watch_kind;" 2>/dev/null | sed 's/^/    kind=/'
K2=$(sqlite3 "$WT_DB" "SELECT count(*) FROM wt_watches WHERE watch_kind=2;" 2>/dev/null || echo 0)
echo "  wt.db WT_KIND_CHANNEL_COMMITMENT (kind=2) watches: ${K2:-0}"
echo
if [ "${K2:-0}" -ge 1 ]; then
    green "GREEN: trustless wt.db carries $K2 channel-commitment watch(es) — a standalone WT can penalize a revoked-commitment breach."
    exit 0
else
    red "RED (gap confirmed): in-process WT saw $OLDC revoked commitment(s) but wt.db has 0 channel-commitment watches."
    red "  => a standalone trustless WT (no secrets) CANNOT penalize a channel-level breach. This is the #292 gap."
    exit 1
fi
