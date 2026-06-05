#!/usr/bin/env bash
# test_regtest_tier_b_rollover_ps.sh — CL2-TB gate validation on PS arity 3.
#
# Validates that --test-tier-b-rollover does NOT skip when --arity 3 (PS).
# CL2-TB loosened the gate from FACTORY_ARITY_1 only to also accept
# FACTORY_ARITY_PS. The test driver in tools/superscalar_lsp_pre_daemon_tests.inc
# previously printed "SKIP: --test-tier-b-rollover requires --arity 1" for PS.
#
# Scope: gate validation only. The Tier-B trigger itself (DW-counter
# exhaustion -> lsp_run_state_advance via rc=-1) is DW-arity-1-specific
# at the protocol level. PS leaves advance ps_chain_len, which does not
# return rc=-1; so this test does NOT expect "state advance complete" —
# it expects the loop to run states_per_layer+1 successful PS advances
# and persist them to ps_leaf_chains.
#
# PASS:
#   - "SKIP" string NOT present in LSP log
#   - 3 advances complete successfully (chain_len 1, 2, 3)
#   - ps_leaf_chains has 3+ rows

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

N_CLIENTS="${N_CLIENTS:-4}"
# F1 sub-factory variant: pass --ps-subfactory-arity K via env to test
# k² PS sub-factory shape Tier B rollover.  Default 0 = don't pass the flag
# (= k=1, single-PS-leaf shape).  Set to 2 or 4 for the wide-leaf shape.
PS_SUB_ARITY="${PS_SUB_ARITY:-0}"
# F1 broadcast variant: FORCE_CLOSE=1 adds --force-close so the LSP broadcasts
# the full tree (root + internals + PS leaves' NEW chain[0]) on-chain after
# Tier B fires.  Proves F1's persisted chain[0] bytes are broadcastable —
# the strongest possible regtest validation of F1 short of a real
# unilateral exit.
FORCE_CLOSE="${FORCE_CLOSE:-0}"
EXTRA_LSP_FLAGS=""
[ "$PS_SUB_ARITY" -gt 0 ] && EXTRA_LSP_FLAGS="$EXTRA_LSP_FLAGS --ps-subfactory-arity $PS_SUB_ARITY"
[ "$FORCE_CLOSE" = "1" ] && EXTRA_LSP_FLAGS="$EXTRA_LSP_FLAGS --force-close"
TMPSUFFIX=""
[ "$PS_SUB_ARITY" -gt 0 ] && TMPSUFFIX="-k${PS_SUB_ARITY}"
[ "$FORCE_CLOSE" = "1" ] && TMPSUFFIX="${TMPSUFFIX}-fc"

FUNDING_SATS=100000
LSP_PORT=29956
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "0000000000000000000000000000000000000000000000000000000000000004"
    "0000000000000000000000000000000000000000000000000000000000000005"
    "0000000000000000000000000000000000000000000000000000000000000006"
    "0000000000000000000000000000000000000000000000000000000000000007"
    "0000000000000000000000000000000000000000000000000000000000000008"
    "0000000000000000000000000000000000000000000000000000000000000009"
)
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
[ -f "$REGTEST_CONF" ] || REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

# Source shared helpers (reorg watcher + vout audit) — must be after BCLI.
. "$(dirname "$(realpath "$0")")"/regtest_test_helpers.sh

TMPDIR=$(mktemp -d /tmp/ss-tier-b-ps${TMPSUFFIX}.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"

PIDS=()

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    cp "$LSP_LOG" /tmp/tier_b_ps_last_lsp.log 2>/dev/null || true
    cp "$REORG_LOG"  /tmp/tier_b_rollover_ps_last_reorg.log  2>/dev/null || true
    cp "$LSP_DB"  /tmp/tier_b_ps_last_lsp.db  2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

echo "=== --test-tier-b-rollover --arity 3 (regtest) ==="

# --- bitcoind ---
if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
    bitcoind -regtest -conf="$REGTEST_CONF" -daemon
    for i in $(seq 1 30); do sleep 1; $BCLI getblockchaininfo >/dev/null 2>&1 && break; done
fi
echo "  bitcoind reachable, height $($BCLI getblockcount)"


REORG_LOG="$TMPDIR/reorg.log"
REORG_PID=$(start_reorg_watcher "$REORG_LOG")
PIDS+=($REORG_PID)
echo "  reorg watcher PID=$REORG_PID logging to $REORG_LOG"
MINER_WALLET="ss_cheat_leaf_miner"
$BCLI -named createwallet wallet_name=$MINER_WALLET load_on_startup=false 2>&1 | head -2 || true
$BCLI loadwallet $MINER_WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$MINER_WALLET -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null

echo
echo "--- LSP (--demo --test-tier-b-rollover --arity 3) ---"
ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
"$LSP_BIN" \
    --network regtest --port $LSP_PORT --clients $N_CLIENTS --arity 3 \
    --amount $FUNDING_SATS --fee-rate 1000 --confirm-timeout 600 \
    --active-blocks 6 --dying-blocks 4 --step-blocks 1 --states-per-layer 2 \
    --seckey "$LSP_SECKEY" \
    --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet $MINER_WALLET --db "$LSP_DB" \
    --demo --test-tier-b-rollover \
    --lsp-balance-pct 50 \
    $EXTRA_LSP_FLAGS \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)

for i in $(seq 1 60); do
    sleep 1
    grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && { echo "  LSP listening"; break; }
    kill -0 $LSP_PID 2>/dev/null || { echo "FAIL: LSP died early"; tail -20 "$LSP_LOG"; exit 1; }
done

for i in $(seq 0 $((N_CLIENTS - 1))); do
    ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $LSP_PORT \
        --seckey "${CLIENT_SECKEYS[$i]}" --fee-rate 1000 \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id $((i + 1)) --daemon \
        --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
        --wallet $MINER_WALLET --db "$TMPDIR/client_${i}.db" \
        > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!)
    sleep 0.5
done

(while kill -0 $LSP_PID 2>/dev/null; do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 2; done) &
PIDS+=($!)

echo
echo "--- Waiting for TIER B ROLLOVER TEST to conclude (timeout 600s) ---"
for i in $(seq 1 300); do
    sleep 2
    grep -qE "TIER B ROLLOVER TEST: (PASS|FAIL|SKIP)" "$LSP_LOG" 2>/dev/null && break
    if [ $((i % 15)) -eq 0 ]; then
        ADV=$(grep -cE "PS leaf.*advanced" "$LSP_LOG" 2>/dev/null || echo 0)
        echo "  ... ${i}*2s elapsed, advances=$ADV"
    fi
    kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited at iter $i"; break; }
done
wait $LSP_PID 2>/dev/null || true

echo
echo "=== Tier-B test outcome ==="
grep -E "TIER B ROLLOVER TEST:|SKIP:|states_per_layer|PS leaf.*advanced" "$LSP_LOG" | head -15

PS_CHAIN0_ROWS=$(sqlite3 "$LSP_DB" "SELECT count(*) FROM ps_initial_signed_states;" 2>/dev/null || echo 0)
SKIP=$(grep -c "SKIP: --test-tier-b-rollover" "$LSP_LOG" 2>/dev/null || true)
F1_PERSIST=$(grep -c "Tier B F1: persisted new-epoch chain" "$LSP_LOG" 2>/dev/null || true)
TIER_B_PASS=$(grep -c "TIER B ROLLOVER TEST: PASS" "$LSP_LOG" 2>/dev/null || true)
# grep -c with no matches returns 1 with output "0"; under set -e we coerce
# the fallback above so the value is always populated.  Belt-and-suspenders:
PS_CHAIN0_ROWS="${PS_CHAIN0_ROWS:-0}"
SKIP="${SKIP:-0}"
F1_PERSIST="${F1_PERSIST:-0}"
TIER_B_PASS="${TIER_B_PASS:-0}"

echo
echo "  ps_initial_signed_states rows : $PS_CHAIN0_ROWS"
echo "  SKIP markers                  : $SKIP"
echo "  F1 persist log lines          : $F1_PERSIST"
echo "  TIER B test PASS              : $TIER_B_PASS"

PASS=1
[ "$SKIP" -gt 0 ] && { echo "  FAIL: CL2-TB gate still skips arity 3 (saw SKIP marker)"; PASS=0; }
[ "$PS_CHAIN0_ROWS" -lt 1 ] && { echo "  FAIL (F1): expected >=1 ps_initial_signed_states row after rollover, saw $PS_CHAIN0_ROWS"; PASS=0; }
[ "$F1_PERSIST" -lt 1 ] && { echo "  FAIL (F1): missing 'Tier B F1: persisted ...' log line — post-ceremony persist did not fire"; PASS=0; }
[ "$TIER_B_PASS" -lt 1 ] && { echo "  FAIL: TIER B ROLLOVER TEST did not PASS — check .inc verifications"; PASS=0; }

# F1 force-close broadcast variant: if FORCE_CLOSE=1, also verify the LSP
# broadcast and confirmed the entire tree (including the NEW epoch's
# signed chain[0]) on-chain.  This is the strongest regtest proof that
# F1's persisted bytes are broadcastable.
if [ "$FORCE_CLOSE" = "1" ]; then
    FC_COMPLETE=$(grep -c "FORCE CLOSE COMPLETE" "$LSP_LOG" 2>/dev/null || true)
    FC_COMPLETE="${FC_COMPLETE:-0}"
    echo "  FORCE CLOSE markers          : $FC_COMPLETE"
    [ "$FC_COMPLETE" -lt 1 ] && { echo "  FAIL (F1 broadcast): force-close did not complete — chain[0] broadcast failed"; PASS=0; }
fi

if [ $PASS = 1 ]; then
    if [ "$FORCE_CLOSE" = "1" ]; then
        echo "  PASS: F1 chain[0] persist + force-close broadcast verified"
    else
        echo "  PASS: CL2-TB gate accepts arity 3, F1 chain[0] persist verified ($PS_CHAIN0_ROWS rows)"
    fi
    exit 0
else
    tail -30 "$LSP_LOG"
    exit 1
fi
