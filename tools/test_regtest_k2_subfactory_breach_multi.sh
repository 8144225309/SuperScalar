#!/usr/bin/env bash
# test_regtest_k2_subfactory_breach_multi.sh — MULTI-INPUT sub-factory
# breach detection (mainnet hygiene, hardening test).
#
# Existing k2_subfactory_breach exercises the single-input poison TX.
# This variant drives `--test-subfactory-advance-multi` so the LSP runs
# TWO chain advances back-to-back; the second exercises the multi-input
# MuSig2 ceremony (#142 SF-A). Then `--cheat-subfactory` broadcasts a
# now-stale state, and the watchtower must detect + penalize the
# multi-input breach. Catches the multi-input poison side-channel that
# the agent's earlier review flagged as a single-input mirror.
#
# Cleanly under SS_MUSIG_STATELESS=1 to exercise the stateless poison
# wiring from #336 in its multi-input form.

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

if command -v nm >/dev/null 2>&1 && nm -D "$LSP_BIN" 2>/dev/null | grep -q __asan_init; then
    SS_ASAN_ENV="ASAN_OPTIONS=detect_leaks=0 LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.8"
else
    SS_ASAN_ENV=""
fi

N_CLIENTS="${N_CLIENTS:-4}"
PS_SUB_ARITY="${PS_SUB_ARITY:-2}"
FUNDING_SATS=400000
LSP_PORT=29959                # distinct from k2_breach (29949) + restart (29957/8)
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
CLIENT_SECKEYS=()
for _i in $(seq 2 256); do CLIENT_SECKEYS+=("$(printf '%064x' $_i)"); done

REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
[ -f "$REGTEST_CONF" ] || REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

TMPDIR=$(mktemp -d /tmp/ss-subfactory-breach-multi.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"
PIDS=()

cleanup() {
    echo
    echo "=== Cleaning up ==="
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    cp "$LSP_LOG" /tmp/subfactory_breach_multi_last_lsp.log 2>/dev/null || true
    cp "$LSP_DB"  /tmp/subfactory_breach_multi_last_lsp.db  2>/dev/null || true
    # daemon-forked clients on our port — bracket-safe pattern
    pkill -f "superscalar_client.*--port $LSP_PORT" 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

echo "=== PS k² sub-factory MULTI-INPUT BREACH DETECTION (regtest) ==="
echo "  N clients         : $N_CLIENTS"
echo "  PS sub arity (k)  : $PS_SUB_ARITY"
echo "  SS_MUSIG_STATELESS: ${SS_MUSIG_STATELESS:-(default)}"
echo
echo "  Flow:"
echo "    1. LSP runs --test-subfactory-advance-multi (2 advances; 2nd is multi-input)"
echo "    2. LSP --cheat-subfactory broadcasts the now-stale chain[N-1] (multi-input state)"
echo "    3. LSP's own watchtower must detect + broadcast response_tx + multi-input poison TX"
echo

# --- bitcoind reset ---
REGTEST_DATADIR=$(grep -E '^datadir=' "$REGTEST_CONF" 2>/dev/null | head -1 | cut -d= -f2)
[ -z "$REGTEST_DATADIR" ] && REGTEST_DATADIR="$HOME/.bitcoin"
REGTEST_REGTEST_DIR="$REGTEST_DATADIR/regtest"
$BCLI stop 2>/dev/null || true; sleep 2
pkill -f "bitcoind.*regtest" 2>/dev/null || true; sleep 2
DATADIR_OWNER=$(stat -c %U "$REGTEST_DATADIR" 2>/dev/null || echo "$USER")
if [ "$DATADIR_OWNER" = "bitcoin" ]; then
    sudo -u bitcoin sh -c "rm -rf '$REGTEST_REGTEST_DIR'" 2>/dev/null || rm -rf "$REGTEST_REGTEST_DIR"
    sudo -u bitcoin bitcoind -regtest -conf="$REGTEST_CONF" -daemon
else
    rm -rf "$REGTEST_REGTEST_DIR"
    bitcoind -regtest -conf="$REGTEST_CONF" -daemon
fi
for i in $(seq 1 30); do $BCLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
$BCLI getblockchaininfo >/dev/null 2>&1 || { echo "FAIL: bitcoind"; exit 1; }
echo "  bitcoind reachable, height $($BCLI getblockcount)"

WALLET_NAME="ss_subfactory_breach_multi_miner"
$BCLI createwallet "$WALLET_NAME" 2>/dev/null || $BCLI loadwallet "$WALLET_NAME" 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet="$WALLET_NAME" getnewaddress)

# --- LSP: multi-advance + cheat ---
echo
echo "--- LSP daemon (--demo --test-subfactory-advance-multi --cheat-subfactory) ---"
env $SS_ASAN_ENV SS_MUSIG_STATELESS="${SS_MUSIG_STATELESS:-1}" "$LSP_BIN" \
    --network regtest --port "$LSP_PORT" \
    --seckey "$LSP_SECKEY" \
    --clients "$N_CLIENTS" --arity 3 \
    --ps-subfactory-arity "$PS_SUB_ARITY" \
    --amount "$FUNDING_SATS" \
    --step-blocks 1 \
    --max-conn-rate 1000 --max-handshakes 256 \
    --demo --lsp-balance-pct 50 --test-subfactory-advance-multi --cheat-subfactory \
    --db "$LSP_DB" \
    --cli-path "$(which bitcoin-cli)" \
    --rpcuser rpcuser --rpcpassword rpcpass \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=("$LSP_PID")
echo "  LSP started (PID=$LSP_PID)"

for i in $(seq 1 30); do
    grep -q "listening on port" "$LSP_LOG" 2>/dev/null && { echo "  LSP listening"; break; }
    sleep 1
    kill -0 "$LSP_PID" 2>/dev/null || { echo "FAIL: LSP died"; tail -30 "$LSP_LOG"; exit 1; }
done

# Clients
for i in $(seq 0 $((N_CLIENTS - 1))); do
    env $SS_ASAN_ENV "$CLIENT_BIN" \
        --network regtest --host 127.0.0.1 --port "$LSP_PORT" \
        --seckey "${CLIENT_SECKEYS[$i]}" \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id $((i + 1)) --daemon \
        --rpcuser rpcuser --rpcpassword rpcpass \
        --cli-path "$(which bitcoin-cli)" \
        --db "$TMPDIR/client_${i}.db" \
        > "$TMPDIR/client_${i}.log" 2>&1 &
    sleep 0.4
done

# Block miner — keeps the chain moving so confirmations land
(while kill -0 "$LSP_PID" 2>/dev/null; do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 2; done) &
PIDS+=($!)

# Wait for completion — the LSP's own WT should detect + broadcast.
# Markers: "SUB-FACTORY BREACH DETECTED" + "MULTI-INPUT advance" + penalty broadcast.
echo
echo "--- Waiting for multi-input breach detection (timeout 600s) ---"
LSP_EXIT=99
MULTI_SEEN=0
BREACH_SEEN=0
for i in $(seq 1 300); do
    sleep 2
    if grep -qE "MULTI-INPUT advance|multi-input.*MuSig|signed multi-input" "$LSP_LOG" 2>/dev/null && [ "$MULTI_SEEN" = "0" ]; then
        echo "  multi-input ceremony observed after $((i * 2))s"
        MULTI_SEEN=1
    fi
    if grep -qE "SUB-FACTORY BREACH DETECTED|penalty tx broadcast|poison.*broadcast|response_tx broadcast" "$LSP_LOG" 2>/dev/null && [ "$BREACH_SEEN" = "0" ]; then
        echo "  breach + penalty observed after $((i * 2))s"
        BREACH_SEEN=1
    fi
    if ! kill -0 "$LSP_PID" 2>/dev/null; then
        # Capture wait's exit while shielding `set -e` (ASan can exit non-zero on leak reports
        # from libsqlite3 — known pre-existing leak, doesn't affect test validity).
        LSP_EXIT=0
        wait "$LSP_PID" 2>/dev/null || LSP_EXIT=$?
        echo "  LSP exited with code $LSP_EXIT after $((i * 2))s"
        break
    fi
    if [ $((i % 15)) -eq 0 ]; then
        ADV=$(grep -cE "subfactory chain advance.*DONE" "$LSP_LOG" 2>/dev/null || echo 0)
        echo "  ... ${i}*2s elapsed, advances=$ADV multi=$MULTI_SEEN breach=$BREACH_SEEN"
    fi
done

# --- evidence ---
echo
echo "=== ceremony + breach evidence ==="
# `|| true` guards against set -o pipefail aborting when grep finds zero matches
# (which would be the FAIL case we want to evaluate explicitly below, not abort early).
(grep -E "MULTI-INPUT advance|multi-input.*MuSig|subfactory chain advance.*DONE|SUB-FACTORY BREACH DETECTED|penalty tx broadcast|poison.*broadcast|response_tx broadcast|wire-ceremony poison TX signed" "$LSP_LOG" 2>/dev/null | head -20) || true

# --- DB inspect ---
echo
echo "=== DB breach_detections (post-test) ==="
sqlite3 "$LSP_DB" "SELECT count(*) FROM breach_detections;" 2>/dev/null || echo "(table missing?)"
sqlite3 "$LSP_DB" "SELECT type, breach_height, broadcast_txid FROM breach_detections LIMIT 5;" 2>/dev/null || true

echo
echo "=== Final result ==="
PASS=1
if [ "$MULTI_SEEN" != "1" ]; then
    echo "  FAIL: multi-input ceremony marker not observed — the 2nd advance didn't fire as multi-input"
    PASS=0
fi
if [ "$BREACH_SEEN" != "1" ]; then
    echo "  FAIL: breach detection / penalty broadcast not observed — multi-input cheat went unpenalized"
    PASS=0
fi
ADV_COUNT=$(grep -cE "subfactory chain advance.*DONE" "$LSP_LOG" 2>/dev/null || echo 0)
if [ "${ADV_COUNT:-0}" -lt 2 ]; then
    echo "  FAIL: only $ADV_COUNT advance(s) completed, expected >=2 (multi mode)"
    PASS=0
fi
if [ "$PASS" = "1" ]; then
    echo "  PASS: multi-input ceremony fired + breach detected + penalty broadcast"
    exit 0
else
    echo "  See /tmp/subfactory_breach_multi_last_lsp.log + .db for details"
    exit 1
fi
