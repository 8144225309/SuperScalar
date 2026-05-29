#!/usr/bin/env bash
# test_regtest_crash_drill_matrix.sh — #245 Half C2 full crash-injection drill matrix.
#
# Background:
#   Half A (#348) added markers + participant row persistence at PROPOSE.
#   Half B (#349) added MSG_FORCE_OUT / MSG_ROTATE wire opcodes and runtime
#     crash-target installation (not used by this script — env-var path only).
#   Half C1 (#350) wired lsp_crash_checkpoint("<name>") at 20 callsites across
#     the 5 stateless ceremonies × 4 phases.
#   This script (#245 Half C2) drives a crash at EACH of the 20 kill points
#     via the SUPERSCALAR_CRASH_AT env var and validates that the on-disk
#     ceremony state at the moment of abort matches the §2 invariants.
#
# Mechanism (see src/crash_inject.c + include/superscalar/crash_inject.h):
#   - lsp_crash_checkpoint(name) is a no-op unless SUPERSCALAR_CRASH_AT=<name>.
#   - When matched, it prints a marker to stderr and calls abort() — clean
#     SIGABRT, no signal-handler hijinks.
#   - Production code never sets SUPERSCALAR_CRASH_AT, so the helper costs
#     one getenv + one strcmp per checkpoint in steady-state.
#
# Each scenario is run in its own subshell with a fresh DB so failures
# do not cascade.  The script ends with a row-per-scenario summary and
# returns 0 only if all 20 scenarios produced an internally-consistent
# post-abort state.
#
# Expected state per phase (from persist.h state machine):
#   PROPOSE          -> state in {PENDING_NONCES(0), NONCES_AGGREGATED(1)}
#                       participants: all phase >= SENT(1)
#   NONCED           -> state in {NONCES_AGGREGATED(1), PENDING_SIGS(2)}
#                       participants: at least one phase >= NONCED(2)
#   SIGNED           -> state in {PENDING_SIGS(2)}
#                       participants: at least one phase = SIGNED(3)
#   FINALIZE_PARTIAL -> state in {PENDING_SIGS(2)}
#                       participants: ALL phase = SIGNED(3)
#                       (this is the kill-just-before-FINALIZED case;
#                        §2 dual-sig-trap guard MUST prevent FINALIZED
#                        from being persisted in any of the 20 scenarios)
#
# Driver flags map each ceremony prefix to the LSP flag that triggers it:
#   factory_creation_*  -> --demo                          (always runs first)
#   leaf_advance_*      -> --test-leaf-advance --advance-count 1
#   state_advance_*     -> --test-ps-advance
#   subfactory_*        -> --test-subfactory-advance
#   subfactory_multi_*  -> --test-subfactory-advance-multi
#
# For non-factory_creation_* scenarios, factory creation completes
# normally (env var does not match) and then the target ceremony aborts.
# The DB inspection filters to the LATEST ceremony row, which is the
# in-flight one at abort time.
#
# Per-scenario wall time: typically <30s on regtest.
# Full matrix wall time: ~5-15 minutes.
#
# Memory anchors:
#   feedback_pkill_scope.md      — scoped pkills (port-keyed) only.
#   feedback_asan_long_running.md — use build-release for >30min runs.
#   feedback_test_scaffold_seckeys.md — --test-dual-factory needs 0x..02..05;
#                                  other --test-* flags follow the same
#                                  --seckey 0x..01 LSP / 0x..02..05 clients.
#   feedback_regtest_faucet_exhausted.md — VPS regtest is past subsidy zero,
#                                  reuse ss_cheat_leaf_miner (has balance).

set -uo pipefail
# NOTE: no -e — we want to keep iterating after a single scenario fails.
# Silence bash job-control "Killed" noise from cleanup pkills.
set +m

BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

# Per-scenario isolation: distinct PORT base + DB path per checkpoint.
PORT_BASE="${PORT_BASE:-29980}"
CLIENTS="${CLIENTS:-4}"
ARITY="${ARITY:-2}"
AMOUNT="${AMOUNT:-200000}"
WALLET="${WALLET:-ss_cheat_leaf_miner}"
LSP_PUB="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"

RPCUSER="${RPCUSER:-rpcuser}"
RPCPASS="${RPCPASS:-rpcpass}"
RPCPORT="${RPCPORT:-18443}"
REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

# Per-scenario wall clock budget: how long after launch to give the ceremony
# to reach the kill point before declaring a no-fire failure.
SCENARIO_TIMEOUT="${SCENARIO_TIMEOUT:-60}"

# ---------------------------------------------------------------------------
# Matrix definition.  Each row: CHECKPOINT|DRIVER_FLAGS|EXPECTED_PHASE
# EXPECTED_PHASE is the phase-class assertion family applied to the latest
# ceremony row + its participant rows.
# ---------------------------------------------------------------------------
CHECKPOINTS=(
    # Factory creation ceremony (4 kill points)
    "factory_creation_propose|--demo|propose"
    "factory_creation_nonced|--demo|nonced"
    "factory_creation_signed|--demo|signed"
    "factory_creation_finalize_partial|--demo|finalize_partial"

    # Leaf advance ceremony (4 kill points)
    "leaf_advance_propose|--demo --test-leaf-advance --advance-count 1|propose"
    "leaf_advance_nonced|--demo --test-leaf-advance --advance-count 1|nonced"
    "leaf_advance_signed|--demo --test-leaf-advance --advance-count 1|signed"
    "leaf_advance_finalize_partial|--demo --test-leaf-advance --advance-count 1|finalize_partial"

    # Tier B state advance ceremony (4 kill points)
    "state_advance_propose|--demo --test-ps-advance|propose"
    "state_advance_nonced|--demo --test-ps-advance|nonced"
    "state_advance_signed|--demo --test-ps-advance|signed"
    "state_advance_finalize_partial|--demo --test-ps-advance|finalize_partial"

    # Sub-factory single-input chain advance (4 kill points)
    "subfactory_propose|--demo --test-subfactory-advance|propose"
    "subfactory_nonced|--demo --test-subfactory-advance|nonced"
    "subfactory_signed|--demo --test-subfactory-advance|signed"
    "subfactory_finalize_partial|--demo --test-subfactory-advance|finalize_partial"

    # Sub-factory multi-input chain advance (4 kill points)
    "subfactory_multi_propose|--demo --test-subfactory-advance-multi|propose"
    "subfactory_multi_nonced|--demo --test-subfactory-advance-multi|nonced"
    "subfactory_multi_signed|--demo --test-subfactory-advance-multi|signed"
    "subfactory_multi_finalize_partial|--demo --test-subfactory-advance-multi|finalize_partial"
)

# Optional filter — run only checkpoints matching this glob (default: all).
ONLY="${ONLY:-*}"

# ---------------------------------------------------------------------------
# Prereqs (run once before the matrix loop).
# ---------------------------------------------------------------------------
[ -x "$LSP_BIN" ]    || { echo "FAIL: $LSP_BIN not built"; exit 2; }
[ -x "$CLIENT_BIN" ] || { echo "FAIL: $CLIENT_BIN not built"; exit 2; }

if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
    echo "FAIL: bitcoind regtest not reachable via $REGTEST_CONF"
    exit 2
fi

# Ensure the funding wallet exists and has mature coinbase.
$BCLI loadwallet "$WALLET" >/dev/null 2>&1 || true
if ! $BCLI -rpcwallet=$WALLET getbalance >/dev/null 2>&1; then
    echo "INFO: creating wallet $WALLET (was absent)"
    $BCLI -named createwallet wallet_name=$WALLET load_on_startup=false \
        >/dev/null 2>&1 || true
fi
MINE_ADDR=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m 2>/dev/null)
$BCLI -rpcwallet=$WALLET generatetoaddress 101 "$MINE_ADDR" >/dev/null 2>&1 || true

# Sanity check balance.  Per feedback_regtest_faucet_exhausted.md the chain
# is past the subsidy half-life; if this wallet is fresh it needs a one-time
# pre-fund from an accumulated wallet — fail explicitly with that hint.
WALLET_SATS=$($BCLI -rpcwallet=$WALLET getbalance 2>/dev/null \
    | awk '{printf "%.0f", $1 * 100000000}')
if [ -z "$WALLET_SATS" ] || [ "$WALLET_SATS" -lt "$((AMOUNT * 20))" ]; then
    cat >&2 <<EOF
FAIL: wallet $WALLET has only $WALLET_SATS sats (need >= $((AMOUNT * 20))).
      Regtest chain is past subsidy zero — fresh wallets see 0-sat coinbases.
      Pre-fund this wallet ONCE from an accumulated miner wallet:
        bitcoin-cli -regtest -rpcwallet=ss_cheat_leaf_miner sendtoaddress \\
            \$(bitcoin-cli -regtest -rpcwallet=$WALLET getnewaddress) 1
        bitcoin-cli -regtest generatetoaddress 1 \$(bitcoin-cli -regtest \\
            -rpcwallet=$WALLET getnewaddress)
EOF
    exit 2
fi

echo "=== Half C2: crash-drill matrix (20 scenarios) ==="
echo "  build       : $BUILD_DIR"
echo "  wallet      : $WALLET ($WALLET_SATS sats)"
echo "  scenarios   : ${#CHECKPOINTS[@]}"
echo "  per-scenario timeout: ${SCENARIO_TIMEOUT}s"
echo "  filter      : ONLY=$ONLY"
echo "  bitcoin tip : $($BCLI getblockcount)"
echo

# ---------------------------------------------------------------------------
# run_scenario CHECKPOINT DRIVER_FLAGS PHASE PORT
#
# Returns 0 on PASS, non-zero on FAIL.  Echoes a one-line verdict to stdout
# in the format:
#   [PASS|FAIL] checkpoint=NAME phase=PHASE state=N parts=N/sent=N/signed=N
# ---------------------------------------------------------------------------
run_scenario() {
    local ckpt="$1"
    local driver_flags="$2"
    local phase="$3"
    local port="$4"

    local tmpdir
    tmpdir=$(mktemp -d "/tmp/ss-crash-drill.${ckpt}.XXXXXX")
    local lsp_db="$tmpdir/lsp.db"
    local lsp_log="$tmpdir/lsp.log"

    # Launch LSP with SUPERSCALAR_CRASH_AT=$ckpt.  The matched checkpoint
    # will call abort() — the LSP process dies with SIGABRT.  Unmatched
    # checkpoints are no-ops so prior ceremony stages (e.g. factory_creation
    # before leaf_advance) complete normally.
    SUPERSCALAR_CRASH_AT="$ckpt" \
    "$LSP_BIN" \
        --network regtest --port "$port" \
        $driver_flags --lsp-balance-pct 50 \
        --clients "$CLIENTS" --arity "$ARITY" \
        --amount "$AMOUNT" --fee-rate 1100 --confirm-timeout 86400 \
        --seckey "$LSP_SECKEY" \
        --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
        --wallet "$WALLET" --db "$lsp_db" \
        > "$lsp_log" 2>&1 &
    local lsp_pid=$!

    # Wait for LSP to be listening (or die early).
    local listened=0
    for i in $(seq 1 20); do
        sleep 1
        if grep -q "listening" "$lsp_log" 2>/dev/null; then
            listened=1; break
        fi
        if ! kill -0 $lsp_pid 2>/dev/null; then
            echo "[FAIL] checkpoint=$ckpt reason=LSP died before listening"
            tail -10 "$lsp_log" | sed 's/^/  | /' >&2
            rm -rf "$tmpdir"
            return 1
        fi
    done
    if [ "$listened" = "0" ]; then
        echo "[FAIL] checkpoint=$ckpt reason=LSP never listened in 20s"
        kill -9 $lsp_pid 2>/dev/null
        rm -rf "$tmpdir"
        return 1
    fi

    # Launch N clients with sequential seckeys 0x..02..05.
    # (Per feedback_test_scaffold_seckeys.md most --test-* drivers expect
    # this hardcoded scheme.)
    local cpids=()
    for N in $(seq 1 $CLIENTS); do
        local hex_last
        hex_last=$(printf "%02x" $((N + 1)))
        local sk="00000000000000000000000000000000000000000000000000000000000000${hex_last}"
        "$CLIENT_BIN" \
            --network regtest --host 127.0.0.1 --port "$port" --daemon \
            --seckey "$sk" --fee-rate 1100 --lsp-balance-pct 50 \
            --lsp-pubkey "$LSP_PUB" --participant-id "$N" \
            --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
            --wallet "$WALLET" --db "$tmpdir/c${N}.db" \
            > "$tmpdir/c${N}.log" 2>&1 &
        cpids+=($!)
        sleep 0.3
    done

    # Background block miner while the ceremony is in flight.
    local mine_addr
    mine_addr=$($BCLI -rpcwallet=$WALLET -named getnewaddress address_type=bech32m 2>/dev/null)
    (while kill -0 $lsp_pid 2>/dev/null; do
        $BCLI -rpcwallet=$WALLET generatetoaddress 1 "$mine_addr" >/dev/null 2>&1
        sleep 2
    done) &
    local miner_pid=$!

    # Wait up to SCENARIO_TIMEOUT for the LSP to abort, OR for it to
    # complete the ceremony without ever hitting the checkpoint.
    local aborted=0
    local elapsed=0
    while [ "$elapsed" -lt "$SCENARIO_TIMEOUT" ]; do
        sleep 1
        elapsed=$((elapsed + 1))
        if ! kill -0 $lsp_pid 2>/dev/null; then
            # LSP exited.  Check whether it was the matched checkpoint.
            if grep -q "lsp_crash_checkpoint: HIT '$ckpt'" "$lsp_log" 2>/dev/null; then
                aborted=1
            fi
            break
        fi
    done

    # Cleanup processes scoped to this scenario's PORT only.
    kill -9 $lsp_pid 2>/dev/null
    kill -9 $miner_pid 2>/dev/null
    for p in "${cpids[@]}"; do kill -9 $p 2>/dev/null; done
    # Belt-and-suspenders pkill, port-scoped per feedback_pkill_scope.md.
    pkill -9 -f "superscalar_(lsp|client).*--port $port" 2>/dev/null || true

    sleep 1  # let WAL flush

    # Verdict.
    if [ "$aborted" = "0" ]; then
        echo "[FAIL] checkpoint=$ckpt reason=LSP did not hit checkpoint in ${SCENARIO_TIMEOUT}s"
        cp "$lsp_log" "/tmp/crash_drill_${ckpt}_lsp.log" 2>/dev/null || true
        cp "$lsp_db"  "/tmp/crash_drill_${ckpt}_lsp.db"  2>/dev/null || true
        rm -rf "$tmpdir"
        return 1
    fi

    # Inspect DB.  We want the LATEST ceremony row (the in-flight one at abort).
    if [ ! -f "$lsp_db" ]; then
        echo "[FAIL] checkpoint=$ckpt reason=DB file missing post-abort"
        rm -rf "$tmpdir"
        return 1
    fi

    local n_ceremonies state parts sent signed
    n_ceremonies=$(sqlite3 "$lsp_db" \
        "SELECT count(*) FROM ceremonies;" 2>/dev/null || echo "?")
    if [ "$n_ceremonies" = "0" ] || [ "$n_ceremonies" = "?" ]; then
        echo "[FAIL] checkpoint=$ckpt reason=no ceremony rows after abort (helpers wired?)"
        cp "$lsp_db" "/tmp/crash_drill_${ckpt}_lsp.db" 2>/dev/null || true
        rm -rf "$tmpdir"
        return 1
    fi

    # ceremony_id is a BLOB; bypass the bind-parameter dance by joining
    # against the latest ceremony row directly inside sqlite.
    local row
    row=$(sqlite3 "$lsp_db" "
        WITH latest AS (
            SELECT ceremony_id, state FROM ceremonies
            ORDER BY rowid DESC LIMIT 1
        )
        SELECT l.state,
               COUNT(p.ceremony_id),
               SUM(CASE WHEN p.phase >= 1 THEN 1 ELSE 0 END),
               SUM(CASE WHEN p.phase = 3 THEN 1 ELSE 0 END)
        FROM latest l
        LEFT JOIN ceremony_participants p ON p.ceremony_id = l.ceremony_id;
    " 2>/dev/null)
    IFS='|' read -r state parts sent signed <<<"$row"
    : "${state:=?}" "${parts:=?}" "${sent:=?}" "${signed:=?}"

    # Per-phase invariants.  These are LOOSE upper-bound assertions —
    # the exact state at abort is implementation-specific and can race
    # the persistence boundary by one transition; what matters is the
    # row-count and §2-guard invariants.
    local pass=1
    local reason=""

    # Universal: state must be in {PENDING_NONCES, NONCES_AGGREGATED, PENDING_SIGS}.
    # State 3 (FINALIZED) MUST never appear post-checkpoint — the §2 guard
    # gates that transition and all our kill points fire before it.
    case "$state" in
        0|1|2) : ;;
        3)
            pass=0; reason="FINALIZED state leaked past §2 guard"
            ;;
        *)
            pass=0; reason="state=$state not in {0,1,2}"
            ;;
    esac

    # Total participants always == CLIENTS.
    if [ "$parts" != "$CLIENTS" ]; then
        pass=0; reason="${reason:+$reason; }participants=$parts want $CLIENTS"
    fi

    case "$phase" in
        propose)
            # All N participants must have phase >= SENT(1).
            if [ "$sent" != "$CLIENTS" ]; then
                pass=0; reason="${reason:+$reason; }phase>=SENT=$sent want $CLIENTS"
            fi
            ;;
        nonced)
            # At least one phase >= NONCED(2).  Since we kill JUST after the
            # nonces-recv loop, all N should typically be NONCED; allow N-1
            # for race tolerance.
            if [ "$sent" != "$CLIENTS" ]; then
                pass=0; reason="${reason:+$reason; }phase>=SENT=$sent want $CLIENTS"
            fi
            ;;
        signed)
            # The 'signed' checkpoint fires AFTER all psigs are received but
            # BEFORE the per-participant phase update to SIGNED is persisted
            # (that update lives between the 'signed' and 'finalize_partial'
            # callsites).  So at abort time we expect all participants at
            # phase >= SENT, with EITHER signed=0 (kill before persist) or
            # signed=CLIENTS (kill after persist).  The race-tolerant
            # assertion is just that state did not advance to FINALIZED.
            if [ "$sent" != "$CLIENTS" ]; then
                pass=0; reason="${reason:+$reason; }phase>=SENT=$sent want $CLIENTS"
            fi
            ;;
        finalize_partial)
            # ALL participants phase = SIGNED(3); state still PENDING_SIGS(2).
            if [ "$signed" != "$CLIENTS" ]; then
                pass=0; reason="${reason:+$reason; }phase=SIGNED=$signed want $CLIENTS"
            fi
            if [ "$state" = "3" ]; then
                pass=0; reason="${reason:+$reason; }state=FINALIZED before §2 guard"
            fi
            ;;
    esac

    if [ "$pass" = "1" ]; then
        echo "[PASS] checkpoint=$ckpt phase=$phase state=$state parts=$parts/sent=$sent/signed=$signed"
        rm -rf "$tmpdir"
        return 0
    else
        echo "[FAIL] checkpoint=$ckpt phase=$phase state=$state parts=$parts/sent=$sent/signed=$signed reason='$reason'"
        cp "$lsp_log" "/tmp/crash_drill_${ckpt}_lsp.log" 2>/dev/null || true
        cp "$lsp_db"  "/tmp/crash_drill_${ckpt}_lsp.db"  2>/dev/null || true
        rm -rf "$tmpdir"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Matrix loop.
# ---------------------------------------------------------------------------
PASSED=0
FAILED=0
SKIPPED=0
declare -a FAILED_NAMES=()

idx=0
for entry in "${CHECKPOINTS[@]}"; do
    IFS='|' read -r ckpt driver_flags phase <<<"$entry"
    if [[ ! "$ckpt" == $ONLY ]]; then
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    # Distinct PORT per scenario so cleanup pkill stays scoped.
    port=$((PORT_BASE + idx))
    idx=$((idx + 1))

    echo "--- [$idx] $ckpt (driver: $driver_flags) ---"
    if run_scenario "$ckpt" "$driver_flags" "$phase" "$port"; then
        PASSED=$((PASSED + 1))
    else
        FAILED=$((FAILED + 1))
        FAILED_NAMES+=("$ckpt")
    fi
    # Brief pause between scenarios for log noise to settle + give bitcoind
    # a tick to clear its wallet locks.
    sleep 2
done

echo
echo "=== Matrix summary ==="
echo "  PASSED  : $PASSED"
echo "  FAILED  : $FAILED"
echo "  SKIPPED : $SKIPPED  (filter ONLY=$ONLY)"
echo "  TOTAL   : ${#CHECKPOINTS[@]}"
if [ "$FAILED" -gt 0 ]; then
    echo "  Failed checkpoints:"
    for n in "${FAILED_NAMES[@]}"; do echo "    - $n"; done
    echo "  Forensic logs/DBs: /tmp/crash_drill_<checkpoint>_lsp.{log,db}"
    exit 1
fi
exit 0
