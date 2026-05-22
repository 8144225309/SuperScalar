#!/bin/bash
# Phase 1c validation regtest — drives lsp_advance_leaf via the POST-DAEMON
# wire ceremony path (not the pre-daemon single-process simulation path that
# every other existing leaf-advance test uses).
#
# Runs twice:
#   1. Without SS_MUSIG_STATELESS — validates legacy wire ceremony works
#   2. With SS_MUSIG_STATELESS=1   — validates Phase 1c new flow works
#
# PASS when both runs produce "POST-DAEMON WIRE LEAF ADVANCE: PASS" in the
# LSP log.

set -u
BUILD_DIR="${SUPERSCALAR_BUILD_DIR:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

N_CLIENTS=2
FUNDING_SATS=100000
LSP_PORT=29960  # distinct port
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
)
RPCUSER="${RPCUSER:-rpcuser}"
RPCPASSWORD="${RPCPASSWORD:-rpcpass}"

PIDS=()
cleanup() {
    for pid in "${PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null
    done
    wait 2>/dev/null
}
trap cleanup EXIT

run_one() {
    local label="$1"
    local stateless="$2"

    echo
    echo "================================================================"
    echo "= $label (SS_MUSIG_STATELESS=$stateless)"
    echo "================================================================"

    local TAG="wire_leaf_advance_${stateless}"
    local LSP_LOG="/tmp/${TAG}_lsp.log"
    local LSP_DB="/tmp/${TAG}.db"
    rm -f "$LSP_DB" "$LSP_LOG" /tmp/${TAG}_client*.log

    # Wallet must exist; reuse cheat_leaf miner pattern
    bitcoin-cli -regtest -rpcuser="$RPCUSER" -rpcpassword="$RPCPASSWORD" \
        createwallet ss_wire_leaf_advance_miner 2>/dev/null || true
    bitcoin-cli -regtest -rpcuser="$RPCUSER" -rpcpassword="$RPCPASSWORD" \
        -rpcwallet=ss_wire_leaf_advance_miner getnewaddress > /dev/null

    # LSP
    echo "--- LSP daemon (--demo --test-wire-leaf-advance) ---"
    SS_MUSIG_STATELESS=$stateless \
    ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
    "$LSP_BIN" \
        --network regtest \
        --port "$LSP_PORT" \
        --clients "$N_CLIENTS" \
        --arity 1 \
        --amount "$FUNDING_SATS" \
        --fee-rate 1000 \
        --confirm-timeout 600 \
        --active-blocks 6 \
        --dying-blocks 4 \
        --step-blocks 1 \
        --states-per-layer 2 \
        --seckey "$LSP_SECKEY" \
        --rpcuser "$RPCUSER" \
        --rpcpassword "$RPCPASSWORD" \
        --wallet ss_wire_leaf_advance_miner \
        --db "$LSP_DB" \
        --demo --test-wire-leaf-advance \
        --lsp-balance-pct 50 \
        > "$LSP_LOG" 2>&1 &
    LSP_PID=$!
    PIDS+=($LSP_PID)

    # Wait for LSP listening
    for i in $(seq 1 60); do
        sleep 1
        if grep -q "LSP: listening" "$LSP_LOG" 2>/dev/null; then
            break
        fi
    done
    if ! grep -q "LSP: listening" "$LSP_LOG" 2>/dev/null; then
        echo "  FAIL: LSP did not start listening (see $LSP_LOG)"
        return 1
    fi

    # Spawn clients
    for n in $(seq 0 $((N_CLIENTS - 1))); do
        local CLIENT_LOG="/tmp/${TAG}_client${n}.log"
        SS_MUSIG_STATELESS=$stateless \
        ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8 \
        "$CLIENT_BIN" \
            --network regtest \
            --host 127.0.0.1 --port "$LSP_PORT" \
            --daemon \
            --seckey "${CLIENT_SECKEYS[$n]}" \
            --fee-rate 1000 \
            --lsp-balance-pct 50 \
            --participant-id "$n" \
            --rpcuser "$RPCUSER" \
            --rpcpassword "$RPCPASSWORD" \
            --wallet ss_wire_leaf_advance_miner \
            --db "/tmp/${TAG}_client${n}.db" \
            > "$CLIENT_LOG" 2>&1 &
        PIDS+=($!)
    done

    # Wait for LSP to print PASS or FAIL for our test
    echo "--- waiting for POST-DAEMON WIRE LEAF ADVANCE result (max 180s) ---"
    local seen_result=0
    for i in $(seq 1 180); do
        sleep 1
        if grep -q "POST-DAEMON WIRE LEAF ADVANCE: PASS\|POST-DAEMON WIRE LEAF ADVANCE: FAIL" "$LSP_LOG" 2>/dev/null; then
            seen_result=1
            break
        fi
    done

    if [ "$seen_result" -eq 0 ]; then
        echo "  FAIL: never saw POST-DAEMON WIRE LEAF ADVANCE result in $LSP_LOG"
        echo "  tail of log:"
        tail -15 "$LSP_LOG" | sed 's/^/    /'
        return 1
    fi

    # Kill LSP + clients
    for pid in "${PIDS[@]}"; do kill -9 "$pid" 2>/dev/null; done
    PIDS=()
    sleep 2

    if grep -q "POST-DAEMON WIRE LEAF ADVANCE: PASS" "$LSP_LOG"; then
        echo "  RESULT: PASS"
        # Sanity: confirm stateless path was used if requested
        if [ "$stateless" = "1" ]; then
            if grep -q "lsp_advance_leaf_stateless" "$LSP_LOG" 2>/dev/null; then
                echo "  STATELESS PATH: confirmed (lsp_advance_leaf_stateless invoked)"
            else
                echo "  WARN: SS_MUSIG_STATELESS=1 set but no stateless markers in log"
                echo "        (Phase 1c dispatch may not have fired — investigate)"
            fi
        fi
        return 0
    else
        echo "  RESULT: FAIL"
        return 1
    fi
}

LEGACY_RC=0
STATELESS_RC=0

if ! run_one "RUN 1: LEGACY wire ceremony" "0"; then
    LEGACY_RC=1
fi
echo
if ! run_one "RUN 2: PHASE 1C stateless flow" "1"; then
    STATELESS_RC=1
fi

echo
echo "================================================================"
echo "= Phase 1c validation regtest result"
echo "================================================================"
echo "  RUN 1 (legacy):    $([ $LEGACY_RC    -eq 0 ] && echo PASS || echo FAIL)"
echo "  RUN 2 (stateless): $([ $STATELESS_RC -eq 0 ] && echo PASS || echo FAIL)"

[ $LEGACY_RC -eq 0 ] && [ $STATELESS_RC -eq 0 ]
