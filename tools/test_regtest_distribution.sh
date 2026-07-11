#!/usr/bin/env bash
# test_regtest_distribution.sh — regression guard for the --test-distrib co-signed path (#439).
#
# WHY: the single-process --test-distrib scaffold used to rebuild the distribution TX with
# hardcoded demo keys (0x22/0x33...).  That is self-consistent ONLY when the funding was also
# built with those demo keys (pure single-process).  With REAL client daemons the funding is
# the aggregate of the clients' ACTUAL keys, so the demo-key rebuild produced an Invalid
# Schnorr signature on-chain (found on signet, fixed in #439 — broadcast the real co-signed
# dist_signed_tx instead).
#
# This test reproduces that condition on regtest: real client daemons (multi-process) whose
# seckeys are DELIBERATELY NOT the scaffold fill (0x22/0x33...), so the ceremony's co-signed
# dist_signed_tx is the ONLY thing that spends the funding validly.  It therefore:
#   - FAILS on a pre-#439 binary (demo-key rebuild -> "Invalid Schnorr signature"), and
#   - PASSES on a fixed binary (takes the "Using co-signed distribution TX (dist_tx_ready=2)"
#     path and the broadcast confirms).
#
# PASS requires ALL of:
#   - "Using co-signed distribution TX from creation ceremony" in the LSP log  (real path taken)
#   - "DISTRIBUTION TX TEST PASSED"
#   - the broadcast distribution txid confirms on-chain
#   - and NO "Invalid Schnorr" / "broadcast failed"
#
# Usage: test_regtest_distribution.sh [BUILD_DIR]   (default /root/SuperScalar/build, ASan)

set -uo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

N_CLIENTS=2
FUNDING_SATS=300000
LSP_PORT=29949                    # distinct from sibling regtest tests
# LSP uses the classic privkey=1 (its pubkey is well-known); the LSP key matches in both the
# funding keyagg and the scaffold rebuild, so it is NOT what triggers the bug.  The CLIENT
# keys are what must differ from the scaffold fill (0x22/0x33/0x44/0x55) to force the real
# co-signed path -- 0x02/0x03 do exactly that.
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
)

REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
[ -f "$REGTEST_CONF" ] || REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"
# Fresh wallet by default (CI's regtest starts empty, so its coinbases are funded).
# On a deep/exhausted regtest chain (0-sat coinbases) override to an accumulated wallet,
# e.g. WALLET=ss_cheat_leaf_miner (see feedback_regtest_faucet_exhausted).
WALLET="${WALLET:-ss_regtest_distrib_miner}"

TMPDIR=$(mktemp -d /tmp/ss-regtest-distrib.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"

PIDS=()
cleanup() {
    set +e
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    pkill -f "superscalar_lsp --network regtes[t].*--port $LSP_PORT" 2>/dev/null || true
    pkill -f "superscalar_client --network regtes[t].*--port $LSP_PORT" 2>/dev/null || true
    cp "$LSP_LOG" /tmp/regtest_distribution_last_lsp.log 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

echo "=========== regtest distribution co-signed-path regression (#439) ==========="
echo "  build dir : $BUILD_DIR"
echo "  clients   : $N_CLIENTS (seckeys 0x02/0x03 -- NOT the scaffold fill)"
echo "  funding   : $FUNDING_SATS sats"
echo

# --- bitcoind ---
if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
    bitcoind -regtest -conf="$REGTEST_CONF" -daemon
    for i in $(seq 1 30); do sleep 1; $BCLI getblockchaininfo >/dev/null 2>&1 && break; done
fi
echo "  bitcoind reachable, height $($BCLI getblockcount)"
$BCLI -named createwallet wallet_name=$WALLET load_on_startup=false 2>&1 | head -1 || true
$BCLI loadwallet $WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m)
$BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null
echo "  miner wallet ready"

# --- LSP: --demo --test-distrib (co-signed distribution at CLTV) ---
echo "--- LSP (--demo --test-distrib) ---"
ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
"$LSP_BIN" --network regtest --port $LSP_PORT --clients $N_CLIENTS --arity 2 \
    --amount $FUNDING_SATS --fee-rate 1000 --confirm-timeout 600 \
    --active-blocks 4 --dying-blocks 4 --step-blocks 1 --states-per-layer 2 --static-near-root 1 \
    --seckey "$LSP_SECKEY" --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet $WALLET --db "$LSP_DB" \
    --demo --test-distrib --lsp-balance-pct 50 \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 60); do
    sleep 1
    grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && { echo "  LSP listening"; break; }
    kill -0 $LSP_PID 2>/dev/null || { echo "FAIL: LSP died before listening"; tail -25 "$LSP_LOG"; exit 1; }
done

# --- real client daemons (keys 0x02/0x03) ---
for i in $(seq 0 $((N_CLIENTS-1))); do
    ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $LSP_PORT \
        --seckey "${CLIENT_SECKEYS[$i]}" --fee-rate 1000 --lsp-pubkey "$LSP_PUBKEY" \
        --participant-id $((i+1)) --daemon --rpcuser ${RPCUSER:-rpcuser} \
        --rpcpassword ${RPCPASSWORD:-rpcpass} --wallet $WALLET \
        --db "$TMPDIR/client_${i}.db" > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!); sleep 1
done

# --- drive the chain: the --test-distrib scaffold calls ADVANCE(blocks_to_cltv) which mines
#     on regtest; nudge with periodic blocks so confirmations + the CLTV wait proceed. ---
echo "--- waiting for distribution test (auto-mining) ---"
DONE=0
for i in $(seq 1 120); do
    sleep 2
    $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1 || true
    if grep -q "DISTRIBUTION TX TEST PASSED" "$LSP_LOG" 2>/dev/null; then DONE=1; break; fi
    if grep -qiE "DISTRIBUTION TX TEST: (build|broadcast) failed|Invalid Schnorr" "$LSP_LOG" 2>/dev/null; then DONE=2; break; fi
    kill -0 $LSP_PID 2>/dev/null || { DONE=3; break; }
done

echo
echo "=== assertions ==="
STRIP() { sed 's/\x1b\[[0-9;]*m//g'; }
USED_REAL=$(STRIP < "$LSP_LOG" | grep -c "Using co-signed distribution TX from creation ceremony")
PASSED=$(STRIP < "$LSP_LOG" | grep -c "DISTRIBUTION TX TEST PASSED")
BADSIG=$(STRIP < "$LSP_LOG" | grep -ciE "Invalid Schnorr|broadcast failed|build failed")
DIST_TXID=$(STRIP < "$LSP_LOG" | grep -aoE "distribution TX broadcast: [0-9a-f]{64}" | grep -oE "[0-9a-f]{64}" | head -1)
echo "  used_real_cosigned_path (dist_tx_ready=2) : $USED_REAL   (expect >=1)"
echo "  DISTRIBUTION TX TEST PASSED               : $PASSED      (expect >=1)"
echo "  Invalid-Schnorr/failed markers            : $BADSIG      (expect 0)"
echo "  distribution txid                         : ${DIST_TXID:-<none>}"

FAILED=0
[ "$USED_REAL" -ge 1 ] || { echo "  FAIL: real co-signed path NOT taken (demo-key fallback == the #439 regression)"; FAILED=1; }
[ "$PASSED"   -ge 1 ] || { echo "  FAIL: distribution test did not PASS"; FAILED=1; }
[ "$BADSIG"   -eq 0 ] || { echo "  FAIL: saw Invalid-Schnorr / broadcast-failed (the #439 bug)"; FAILED=1; }
if [ -n "$DIST_TXID" ]; then
    CONF=$($BCLI getrawtransaction "$DIST_TXID" true 2>/dev/null | STRIP | grep -oE '"confirmations": *[0-9]+' | grep -oE '[0-9]+' | head -1)
    echo "  distribution txid confirmations           : ${CONF:-0}"
    [ -n "$CONF" ] && [ "$CONF" -ge 1 ] || { echo "  FAIL: distribution txid did not confirm on-chain"; FAILED=1; }
else
    echo "  FAIL: no distribution txid broadcast"; FAILED=1
fi

echo
if [ "$FAILED" -eq 0 ]; then
    echo "PASS: --test-distrib took the real co-signed path and the distribution confirmed ($DIST_TXID)"
    exit 0
else
    echo "FAIL: regression tripped — see markers above"
    echo "--- LSP log tail ---"; STRIP < "$LSP_LOG" | tail -30
    exit 1
fi
