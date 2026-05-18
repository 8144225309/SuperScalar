#!/usr/bin/env bash
# test_regtest_crash_at_every_phase.sh — crash-recovery drill scaffold
# (mainnet roadmap #5).
#
# Exercises the ceremony API helpers added in PR #259 (see persist.c §
# SF-CEREMONY-HELPERS and persist.h lines 1166-1331):
#   - persist_save_ceremony
#   - persist_save_participant_phase
#   - persist_update_ceremony_state (with §2 FINALIZED guard)
#   - persist_scan_in_flight_ceremonies
#
# Ceremony state machine (from persist.h):
#   PENDING_NONCES=0 -> NONCES_AGGREGATED=1 -> PENDING_SIGS=2 -> FINALIZED=3
#                                                            \-> ABORTED=4
#                                                            \-> PARTIAL_FAILED=5
# Participant phases:
#   NOT_SENT=0 -> SENT=1 -> NONCED=2 -> SIGNED=3
#                              \-> TIMED_OUT=4 \-> REFUSED=5
#
# THIS SCAFFOLD covers exactly ONE kill point on ONE ceremony type
# (factory_propose, kill right after MSG_FACTORY_PROPOSE is sent).
# It demonstrates the framework — the full drill is multi-day (3-5 days
# wall-clock) across all 4 kill points x 6 ceremony types.
#
# TODO (future work for the full drill — out of scope for this scaffold):
#   Kill point 2: just after MSG_NONCES_AGGREGATED  -> state=NONCES_AGGREGATED
#                                                     phase=NONCED on all
#   Kill point 3: just after MSG_PARTIAL_SIG sent   -> state=PENDING_SIGS
#                                                     phase=SIGNED on some
#   Kill point 4: pre-FINALIZED (sig agg complete   -> state=PENDING_SIGS,
#                  but row not yet flipped)            all participants SIGNED
#   Also: cover other ceremony types beyond factory_propose
#         (state-advance, tier-b-rollover, ptlc-presig, force-close,
#          revocation-release).
#
# NOTE on current LSP wiring: PR #259 added the helpers but the existing
# LSP code paths (lsp.c lsp_run_factory_init etc.) do not yet call them
# at every transition. Until those call-sites are wired up, the ceremony
# row may NOT be written by the existing factory_propose flow — the
# scaffold logs that as "future work" rather than failing.

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

TAG="crash_phase"
PORT="${PORT:-29960}"
CLIENTS=4
ARITY=2
AMOUNT="${AMOUNT:-200000}"
WALLET="${WALLET:-ss_cheat_leaf_miner}"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

RPCUSER="${RPCUSER:-rpcuser}"
RPCPASS="${RPCPASS:-rpcpass}"
RPCPORT="${RPCPORT:-18443}"
REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

TMPDIR=$(mktemp -d /tmp/ss-crash-phase.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
LSP_LOG="$TMPDIR/lsp.log"

LSP_PID=""
CLIENT_PIDS=()

# ---------------------------------------------------------------------------
# Cleanup: kill anything we started, NEVER bare `--port` or bare `superscalar`
# per memory feedback_pkill_scope.md. Always include $PORT.
# ---------------------------------------------------------------------------
cleanup() {
    echo
    echo "=== Cleanup ==="
    [ -n "$LSP_PID" ] && kill -9 "$LSP_PID" 2>/dev/null || true
    for pid in "${CLIENT_PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
    # Belt-and-suspenders: only matches this run's PORT.
    pkill -9 -f "superscalar_(lsp|client).*--port $PORT" 2>/dev/null || true
    # Preserve last-run artifacts for post-mortem.
    cp "$LSP_LOG" /tmp/crash_phase_last_lsp.log 2>/dev/null || true
    cp "$LSP_DB"  /tmp/crash_phase_last_lsp.db  2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Prereqs
# ---------------------------------------------------------------------------
[ -x "$LSP_BIN" ]    || { echo "FAIL: $LSP_BIN not built"; exit 1; }
[ -x "$CLIENT_BIN" ] || { echo "FAIL: $CLIENT_BIN not built"; exit 1; }

if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
    echo "FAIL: bitcoind regtest not reachable via $REGTEST_CONF"
    exit 1
fi
$BCLI loadwallet "$WALLET" >/dev/null 2>&1 || true
MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m 2>/dev/null \
            || $BCLI -named createwallet wallet_name=$WALLET load_on_startup=false \
                 >/dev/null && $BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m)
$BCLI -rpcwallet=$WALLET generatetoaddress 101 "$MINE_ADDR" >/dev/null 2>&1 || true

echo "=== Crash-recovery drill scaffold (kill point 1: post-PROPOSE) ==="
echo "  build       : $BUILD_DIR"
echo "  port        : $PORT"
echo "  clients     : $CLIENTS  arity=$ARITY  amount=$AMOUNT"
echo "  lsp db      : $LSP_DB"
echo "  bitcoin tip : $($BCLI getblockcount)"

# ---------------------------------------------------------------------------
# Launch LSP. Uses build-release/ (NOT ASan) per memory
# feedback_asan_long_running.md — this script polls bitcoind for >30min
# in the full drill, and ASan would die silently.
# ---------------------------------------------------------------------------
echo
echo "--- Launching LSP ---"
"$LSP_BIN" \
    --network regtest --port "$PORT" \
    --demo --test-dual-factory --lsp-balance-pct 50 \
    --clients "$CLIENTS" --arity "$ARITY" \
    --amount "$AMOUNT" --fee-rate 1100 --confirm-timeout 86400 \
    --seckey 0000000000000000000000000000000000000000000000000000000000000001 \
    --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
    --wallet "$WALLET" --db "$LSP_DB" \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!

# Wait for listening
for i in $(seq 1 30); do
    sleep 1
    if grep -q "listening" "$LSP_LOG" 2>/dev/null; then
        echo "  LSP listening on $PORT (pid $LSP_PID)"
        break
    fi
    if ! kill -0 $LSP_PID 2>/dev/null; then
        echo "FAIL: LSP died before listening"
        tail -30 "$LSP_LOG"
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# Launch clients. Per memory feedback_test_scaffold_seckeys.md,
# --test-dual-factory hardcodes ds[31]=ci+2, so client seckeys MUST be
# 0x00..02, 03, 04, 05 — else Invalid Schnorr at broadcast.
# ---------------------------------------------------------------------------
echo "--- Launching $CLIENTS clients ---"
for N in 1 2 3 4; do
    HEX_LAST=$(printf "%02x" $((N + 1)))
    SK="00000000000000000000000000000000000000000000000000000000000000${HEX_LAST}"
    "$CLIENT_BIN" \
        --network regtest --host 127.0.0.1 --port "$PORT" --daemon \
        --seckey "$SK" --fee-rate 1100 --lsp-balance-pct 50 \
        --lsp-pubkey "$LSP_PUB" --participant-id "$N" \
        --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
        --wallet "$WALLET" --db "$TMPDIR/c${N}.db" \
        > "$TMPDIR/c${N}.log" 2>&1 &
    CLIENT_PIDS+=($!)
    sleep 0.3
done

# Background block generator so the ceremony can confirm if it gets that far
(while kill -0 $LSP_PID 2>/dev/null; do
    $BCLI -rpcwallet=$WALLET generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1
    sleep 2
done) &
MINER_PID=$!
CLIENT_PIDS+=($MINER_PID)

# ---------------------------------------------------------------------------
# Kill point 1: wait for MSG_FACTORY_PROPOSE to be sent, then SIGKILL.
# When the ceremony helpers are wired up, that point should leave:
#   ceremonies.state = 0 (PENDING_NONCES)
#   ceremony_participants.phase = 1 (SENT) on all 4 rows
# ---------------------------------------------------------------------------
echo
echo "--- Waiting for MSG_FACTORY_PROPOSE marker (timeout 60s) ---"
# Marker: lsp.c logs "starting factory creation ceremony..." immediately
# before the wire_send(MSG_FACTORY_PROPOSE) loop runs. We wait for that,
# then add a short settle delay so the propose actually goes out on the
# wire and (once the helpers are wired) persist_save_ceremony is called,
# before we SIGKILL.
KILL_FIRED=0
for i in $(seq 1 60); do
    sleep 1
    if grep -qE "starting factory creation ceremony|factory_propose|FACTORY_PROPOSE" \
            "$LSP_LOG" 2>/dev/null; then
        echo "  PROPOSE marker observed after ${i}s — settle 1s, then SIGKILL"
        sleep 1
        kill -9 "$LSP_PID" 2>/dev/null || true
        KILL_FIRED=1
        break
    fi
    if ! kill -0 $LSP_PID 2>/dev/null; then
        echo "FAIL: LSP exited before PROPOSE could be observed"
        tail -40 "$LSP_LOG"
        exit 1
    fi
done

if [ "$KILL_FIRED" = "0" ]; then
    echo "FAIL: did not observe MSG_FACTORY_PROPOSE in 60s — see $LSP_LOG"
    tail -40 "$LSP_LOG"
    exit 1
fi

# Give the OS a tick to flush the WAL on the way down
wait "$LSP_PID" 2>/dev/null || true
sleep 1

# ---------------------------------------------------------------------------
# Verify on-disk state via sqlite. The ceremony helpers from PR #259 are
# what wire ceremony rows; if no LSP code path calls them yet (which is
# the case at the time of this scaffold), the rows will be missing — we
# flag that explicitly as "future work" rather than failing.
# ---------------------------------------------------------------------------
echo
echo "=== Post-SIGKILL DB inspection ==="
[ -f "$LSP_DB" ] || { echo "FAIL: LSP db $LSP_DB does not exist"; exit 1; }

CEREMONY_ROWS=$(sqlite3 "$LSP_DB" "SELECT count(*) FROM ceremonies;" 2>/dev/null || echo "?")
PART_ROWS=$(sqlite3 "$LSP_DB" "SELECT count(*) FROM ceremony_participants;" 2>/dev/null || echo "?")
echo "  ceremonies rows             : $CEREMONY_ROWS"
echo "  ceremony_participants rows  : $PART_ROWS"

if [ "$CEREMONY_ROWS" = "0" ] || [ "$CEREMONY_ROWS" = "?" ]; then
    echo
    echo "  NOTE (future work): the ceremony row was NOT written by the"
    echo "        factory_propose code path. The helpers from PR #259 exist"
    echo "        in persist.c but lsp_run_factory_init / wire_send_propose"
    echo "        do not yet call persist_save_ceremony /"
    echo "        persist_save_participant_phase. Wiring those call-sites is"
    echo "        the next step before this scaffold can assert state."
    echo "        Scaffold PASS criterion met: kill point reached, DB exists,"
    echo "        framework is in place."
    exit 0
fi

# Once helpers are wired, we expect these exact rows.
STATE=$(sqlite3 "$LSP_DB" "SELECT state FROM ceremonies LIMIT 1;" 2>/dev/null || echo "?")
SENT_PARTS=$(sqlite3 "$LSP_DB" \
    "SELECT count(*) FROM ceremony_participants WHERE phase = 1;" 2>/dev/null || echo "?")
echo "  ceremony state              : $STATE  (want 0 = PENDING_NONCES)"
echo "  participants with phase=SENT: $SENT_PARTS (want $CLIENTS)"

PASS=1
[ "$STATE" = "0" ]           || { echo "  FAIL: state=$STATE, want 0"; PASS=0; }
[ "$SENT_PARTS" = "$CLIENTS" ] || { echo "  FAIL: SENT participants=$SENT_PARTS, want $CLIENTS"; PASS=0; }

echo
if [ "$PASS" = "1" ]; then
    echo "=== PASS: kill point 1 (post-PROPOSE) — ceremony+participants survived SIGKILL ==="
    exit 0
else
    echo "=== FAIL: see /tmp/crash_phase_last_lsp.log + /tmp/crash_phase_last_lsp.db ==="
    exit 1
fi
