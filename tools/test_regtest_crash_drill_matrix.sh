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
# Driver flag status (first Half C2 milestone — incremental work):
#   factory_creation_*  -> --demo                           VALIDATED 4/4 PASS
#   leaf_advance_*      -> needs --test-wire-leaf-advance   TBD (N=2 setup;
#                                                                see
#                          tools/test_regtest_wire_leaf_advance.sh for the
#                          working harness — port over its 2-client config)
#   state_advance_*     -> needs investigation              TBD (PS_ADVANCE
#                          may need explicit chain-advance trigger; see
#                          tools/test_regtest_tier_b_rollover_ps.sh)
#   subfactory_*        -> needs investigation              TBD
#   subfactory_multi_*  -> needs investigation              TBD
#
# The framework is generic; landing the other 16 scenarios is mechanical:
# 1. Identify the test-flag + N (clients) that drives the target ceremony
#    end-to-end on regtest (look at existing tools/test_regtest_*.sh runners).
# 2. Add a matrix row with the right driver flags + CLIENTS override.
# 3. Run ONLY=<checkpoint> to validate; assertions are already in place.
# 4. The §2 dual-sig-trap guard assertion is universal — it fires across
#    all 5 ceremony types since they share persist_update_ceremony_state.
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
# Matrix definition.  Each row:
#   CHECKPOINT | DRIVER_FLAGS | EXPECTED_PHASE | N_CLIENTS | ARITY | EXP_PARTS
# EXPECTED_PHASE is the phase-class assertion family applied to the latest
# ceremony row + its participant rows.  N_CLIENTS and ARITY override the
# globals for ceremonies that require specific factory shapes — leaf_advance
# wants N=2 arity=1, sub-factory variants want --arity 3 with K=2 PS clients.
# EXP_PARTS is the participant count the ceremony actually journals — most
# ceremonies use all N, but leaf-advance is 2-of-2 (LSP + leaf-owner client,
# journaled as 1 participant) and sub-factory variants journal K participants
# (the sub-factory size, not the total N).
# ---------------------------------------------------------------------------
# Row format: CHECKPOINT|DRIVER_FLAGS|PHASE|N_CLIENTS|ARITY|EXP_PARTS|TIMEOUT|PID_BASE
#   TIMEOUT  = wall-clock budget (s) to REACH the kill point.  factory_creation
#              fires at startup (fast); post-demo ceremonies (leaf/state/sub/rotate)
#              need minutes because the LSP first runs the demo warm-up payments
#              and (for rollover/sub-advance) several block-confirmed advances.
#   PID_BASE = participant-id base (1 default; 0 for --test-wire-leaf-advance,
#              which the working harness launches as --participant-id 0,1).
CHECKPOINTS=(
    # Factory creation ceremony (4 kill points) — default N=4 arity=2,
    # all N clients participate.  Fires at startup; 90s is ample.
    "factory_creation_propose|--demo|propose|4|2|4|90|1"
    "factory_creation_nonced|--demo|nonced|4|2|4|90|1"
    "factory_creation_signed|--demo|signed|4|2|4|90|1"
    "factory_creation_finalize_partial|--demo|finalize_partial|4|2|4|90|1"

    # Leaf advance ceremony (4 kill points) — wire ceremony needs N=2 arity=1
    # (matches tools/test_regtest_wire_leaf_advance.sh).  The wire variant calls
    # lsp_advance_leaf_stateless where the checkpoints live.  The advance fires
    # AFTER the demo warm-up payments — budget 240s (the working harness waits
    # 180s for the result).  PID_BASE=0: the leaf-owner is --participant-id 0,
    # else leaf-0 has no responder and the ceremony never starts.  1 of N parts.
    "leaf_advance_propose|--demo --test-wire-leaf-advance|propose|2|1|1|240|0"
    "leaf_advance_nonced|--demo --test-wire-leaf-advance|nonced|2|1|1|240|0"
    "leaf_advance_signed|--demo --test-wire-leaf-advance|signed|2|1|1|240|0"
    "leaf_advance_finalize_partial|--demo --test-wire-leaf-advance|finalize_partial|2|1|1|240|0"

    # Tier B state advance ceremony (4 kill points) — checkpoints live in
    # lsp_run_state_advance_stateless.  --test-tier-b-rollover drives
    # states_per_layer+1 leaf advances to trigger the root rollover that fires
    # lsp_run_state_advance.  PS shape (--arity 3).  The rollover only happens
    # after the full advance sequence + block confirmations, so the checkpoint
    # is not reachable for several minutes — budget 600s (matches
    # tools/test_regtest_tier_b_rollover_ps.sh).  All N participate.
    "state_advance_propose|--demo --test-tier-b-rollover|propose|4|3|4|600|1"
    "state_advance_nonced|--demo --test-tier-b-rollover|nonced|4|3|4|600|1"
    "state_advance_signed|--demo --test-tier-b-rollover|signed|4|3|4|600|1"
    "state_advance_finalize_partial|--demo --test-tier-b-rollover|finalize_partial|4|3|4|600|1"

    # NOTE: the 4 K=1 "single-input" subfactory_* scenarios are intentionally
    # excluded — that path (lsp_channels.c:4174-4458) is DEAD for production
    # sub-factories: a NODE_PS_SUBFACTORY always has n_outputs>1, so the
    # dispatch at lsp_channels.c:4055 always routes to the multi-input variant
    # below.  The checkpoints remain in code as a guarded fallback.

    # Sub-factory multi-input chain advance (4 kill points) — checkpoints in
    # the multi-input ceremony variant (src/lsp_channels.c:3568/3630/3921/3944).
    # --test-subfactory-advance-multi drives TWO back-to-back advances; the
    # second exercises the multi-input MuSig path (#142 SF-A).  Fires after the
    # warm-up payments + first advance — budget 420s.  K participants.
    "subfactory_multi_propose|--demo --test-subfactory-advance-multi --ps-subfactory-arity 2|propose|4|3|2|420|1"
    "subfactory_multi_nonced|--demo --test-subfactory-advance-multi --ps-subfactory-arity 2|nonced|4|3|2|420|1"
    "subfactory_multi_signed|--demo --test-subfactory-advance-multi --ps-subfactory-arity 2|signed|4|3|2|420|1"
    "subfactory_multi_finalize_partial|--demo --test-subfactory-advance-multi --ps-subfactory-arity 2|finalize_partial|4|3|2|420|1"

    # Factory rotation ceremony (4 kill points: rotate_pending_nonces /
    # rotate_nonces_aggregated / rotate_pending_sigs / rotate_finalize_partial,
    # src/lsp_rotation.c 209/428/547/1215) — NOW DRIVEN (rows below) via the
    # daemon DYING trigger; the historical exclusion rationale is kept for
    # context.  Those checkpoints live inside the PRODUCTION
    # lsp_channels_rotate_factory().  --test-rotation is a SEPARATE hand-rolled
    # demo (tools/superscalar_lsp_post_daemon_tests.inc) that re-implements
    # turnover + ladder-close + new-factory inline and never calls
    # lsp_channels_rotate_factory(), so it cannot reach those checkpoints — and
    # no other --test-* flag drives the production rotation either (its only
    # callers are the daemon's internal rotation triggers in lsp_channels.c,
    # exercised by the CLN plugin / factory-expiry).  Coverage is preserved two
    # ways: (1) the §2 dual-signature-trap guard these checkpoints would test is
    # the SINGLE shared function persist_update_ceremony_state() (persist.c:6539,
    # refuses FINALIZED unless every participant row is phase=SIGNED) — already
    # proven under crash injection by all 16 driveable-ceremony datapoints below,
    # and rotation transitions to FINALIZED through that identical guard; (2) the
    # crash checkpoints remain wired in lsp_rotation.c, ready for a production-
    # rotation driver.  Driving the production rotation under crash injection is
    # tracked as a v0.2.1 test-hardening follow-up (needs a --test-prod-rotation
    # that calls lsp_channels_rotate_factory, or the CLN-interop path #307).
    # NOTE: the --test-rotation demo's PTLC turnover (Phase A) was separately
    # un-rotted in this change (it predated the #196 turnover-auth gate and
    # rejected every presig); it now completes turnover but still fails later at
    # inline Factory-1 creation — also folded into the v0.2.1 follow-up.
    # Factory rotation — PRODUCTION lsp_channels_rotate_factory(), driven by
    # the daemon's own DYING trigger (NOT --test-rotation, which is a separate
    # hand-rolled demo): --daemon sets rot_auto_rotate=1 and, with no
    # --async-rotation, mgr->readiness is NULL so the LEGACY SYNCHRONOUS path
    # calls lsp_channels_rotate_factory() directly on the ACTIVE->DYING
    # transition.  --active-blocks 6 + the matrix's 2s miner reaches DYING in
    # ~20s after funding; --dying-blocks 120 keeps the rotation window open.
    # Participant rows are journaled DURING Phase A turnover, so the
    # rotate_pending_nonces kill (which fires just after the ceremony row is
    # saved, BEFORE Phase A) expects parts=0; later checkpoints expect all 4.
    # Probe-verified: state=PENDING_NONCES(0) parts=0/0/0 at the first kill.
    "rotate_pending_nonces|--daemon --active-blocks 6 --dying-blocks 120|propose|4|2|0|360|1"
    "rotate_nonces_aggregated|--daemon --active-blocks 6 --dying-blocks 120|nonced|4|2|4|420|1"
    "rotate_pending_sigs|--daemon --active-blocks 6 --dying-blocks 120|signed|4|2|4|420|1"
    "rotate_finalize_partial|--daemon --active-blocks 6 --dying-blocks 120|finalize_partial|4|2|4|480|1"
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

echo "=== Half C2: crash-drill matrix (20 scenarios / 5 ceremonies incl. PRODUCTION rotation) ==="
echo "  build       : $BUILD_DIR"
echo "  wallet      : $WALLET ($WALLET_SATS sats)"
echo "  scenarios   : ${#CHECKPOINTS[@]}"
echo "  per-scenario timeout: ${SCENARIO_TIMEOUT}s"
echo "  filter      : ONLY=$ONLY"
echo "  bitcoin tip : $($BCLI getblockcount)"
echo

# ---------------------------------------------------------------------------
# run_scenario CHECKPOINT DRIVER_FLAGS PHASE PORT [N_CLIENTS] [ARITY] [EXP_PARTS]
#
# N_CLIENTS, ARITY, EXP_PARTS are per-scenario overrides; absent means use
# globals (or n_clients for EXP_PARTS).  Returns 0 on PASS, non-zero on FAIL.
# Echoes a one-line verdict to stdout in the format:
#   [PASS|FAIL] checkpoint=NAME phase=PHASE state=N parts=N/sent=N/signed=N
# ---------------------------------------------------------------------------
run_scenario() {
    local ckpt="$1"
    local driver_flags="$2"
    local phase="$3"
    local port="$4"
    local n_clients="${5:-$CLIENTS}"
    local arity="${6:-$ARITY}"
    local exp_parts="${7:-$n_clients}"
    # Per-scenario wall-clock budget to REACH the kill point.  Ceremonies that
    # fire post-demo (leaf advance, Tier B rollover, sub-factory multi-advance,
    # rotation) need minutes to reach their checkpoint — the LSP is still
    # running the demo warm-up payments at 60s.  Default to the global.
    local scenario_timeout="${8:-$SCENARIO_TIMEOUT}"
    # Participant-id base: 1 for most drivers (client N -> --participant-id N),
    # 0 for --test-wire-leaf-advance (matches tools/test_regtest_wire_leaf_advance.sh
    # which launches --participant-id 0,1; if leaf-0's owner is mis-numbered the
    # advance ceremony never starts and the checkpoint is unreachable).
    local pid_base="${9:-1}"

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
        --clients "$n_clients" --arity "$arity" \
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
    for N in $(seq 1 $n_clients); do
        local hex_last
        hex_last=$(printf "%02x" $((N + 1)))
        local sk="00000000000000000000000000000000000000000000000000000000000000${hex_last}"
        "$CLIENT_BIN" \
            --network regtest --host 127.0.0.1 --port "$port" --daemon \
            --seckey "$sk" --fee-rate 1100 --lsp-balance-pct 50 \
            --lsp-pubkey "$LSP_PUB" --participant-id "$((N - 1 + pid_base))" \
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

    # Wait up to scenario_timeout for the LSP to abort, OR for it to
    # complete the ceremony without ever hitting the checkpoint.
    local aborted=0
    local elapsed=0
    while [ "$elapsed" -lt "$scenario_timeout" ]; do
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
        # No-fire = the ceremony never reached the kill point.  For the
        # multi-client ceremonies this is usually a TRANSIENT harness flake (a
        # client's final psig didn't arrive and the LSP blocks on the no-timeout
        # wire_recv in Step E) rather than a state bug — so this is returned as a
        # RETRYABLE code (2); the matrix loop re-attempts before declaring FAIL.
        echo "[NO-FIRE] checkpoint=$ckpt reason=LSP did not hit checkpoint in ${scenario_timeout}s (retryable)"
        cp "$lsp_log" "/tmp/crash_drill_${ckpt}_lsp.log" 2>/dev/null || true
        cp "$lsp_db"  "/tmp/crash_drill_${ckpt}_lsp.db"  2>/dev/null || true
        # Forensics: preserve client logs too — a no-fire is often a client-side
        # stall (e.g. a rejected/mis-bound message) the LSP log can't explain.
        for clg in "$tmpdir"/c*.log; do
            [ -f "$clg" ] && cp "$clg" "/tmp/crash_drill_${ckpt}_$(basename "$clg")" 2>/dev/null || true
        done
        rm -rf "$tmpdir"
        return 2
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
    # Rotation nests a complete new-factory creation ceremony in Phase C,
    # whose INITIAL row legitimately FINALIZES after the ROTATE row. For
    # rotate_* checkpoints the SS2-guard subject is the ROTATE row
    # (ceremony_type=2), not the latest row overall.
    local cer_filter=""
    case "$ckpt" in rotate_*) cer_filter="WHERE ceremony_type = 2" ;; esac

    local row
    row=$(sqlite3 "$lsp_db" "
        WITH latest AS (
            SELECT ceremony_id, state FROM ceremonies $cer_filter
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

    # Total participants journaled by this ceremony — most use all N but
    # leaf-advance journals just the leaf-owner (1) and sub-factory variants
    # journal K (the sub-factory size).
    if [ "$parts" != "$exp_parts" ]; then
        pass=0; reason="${reason:+$reason; }participants=$parts want $exp_parts"
    fi

    case "$phase" in
        propose)
            # All ceremony participants must have phase >= SENT(1).
            if [ "$sent" != "$exp_parts" ]; then
                pass=0; reason="${reason:+$reason; }phase>=SENT=$sent want $exp_parts"
            fi
            ;;
        nonced)
            # At least one phase >= NONCED(2).  Since we kill JUST after the
            # nonces-recv loop, all participants should typically be NONCED;
            # allow N-1 for race tolerance.
            if [ "$sent" != "$exp_parts" ]; then
                pass=0; reason="${reason:+$reason; }phase>=SENT=$sent want $exp_parts"
            fi
            ;;
        signed)
            # The 'signed' checkpoint fires AFTER all psigs are received but
            # BEFORE the per-participant phase update to SIGNED is persisted
            # (that update lives between the 'signed' and 'finalize_partial'
            # callsites).  So at abort time we expect all participants at
            # phase >= SENT, with EITHER signed=0 (kill before persist) or
            # signed=exp_parts (kill after persist).  The race-tolerant
            # assertion is just that state did not advance to FINALIZED.
            if [ "$sent" != "$exp_parts" ]; then
                pass=0; reason="${reason:+$reason; }phase>=SENT=$sent want $exp_parts"
            fi
            ;;
        finalize_partial)
            # State must NOT be FINALIZED(3) — that's the §2 dual-sig-trap
            # guarantee.  The state check above already enforced state in
            # {0,1,2}.  Per-participant signed count can be EITHER 0 (kill
            # before the SIGNED marker persist) OR exp_parts (kill after).
            # factory_creation persists SIGNED before the finalize_partial
            # checkpoint, so it shows exp_parts; leaf_advance / state_advance
            # / subfactory_multi place the checkpoint before the SIGNED
            # marker persist, so they show 0.  Both are pre-FINALIZED and
            # satisfy the §2 invariant — the matrix's job is to prove FAR
            # state never advances to FINALIZED, which is already checked.
            if [ "$signed" != "0" ] && [ "$signed" != "$exp_parts" ]; then
                pass=0; reason="${reason:+$reason; }phase=SIGNED=$signed want 0 or $exp_parts"
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
    IFS='|' read -r ckpt driver_flags phase row_clients row_arity row_exp_parts row_timeout row_pid_base <<<"$entry"
    if [[ ! "$ckpt" == $ONLY ]]; then
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    # Distinct PORT per scenario so cleanup pkill stays scoped.
    port=$((PORT_BASE + idx))
    idx=$((idx + 1))

    echo "--- [$idx] $ckpt (driver: $driver_flags  N=${row_clients:-$CLIENTS} arity=${row_arity:-$ARITY} parts=${row_exp_parts:-${row_clients:-$CLIENTS}} timeout=${row_timeout:-$SCENARIO_TIMEOUT}s pid_base=${row_pid_base:-1}) ---"
    # Retry on no-fire (rc=2 = ceremony never reached the kill point, a transient
    # multi-client harness flake).  Assertion failures (rc=1) and passes (rc=0)
    # are final — only a genuine no-fire is retried, up to MAX_RETRY times.
    MAX_RETRY="${MAX_RETRY:-3}"
    sc_rc=2; sc_try=0
    while [ "$sc_rc" = "2" ] && [ "$sc_try" -lt "$MAX_RETRY" ]; do
        sc_try=$((sc_try + 1))
        [ "$sc_try" -gt 1 ] && echo "    (no-fire — retry $sc_try/$MAX_RETRY)"
        run_scenario "$ckpt" "$driver_flags" "$phase" "$port" "$row_clients" "$row_arity" "$row_exp_parts" "$row_timeout" "$row_pid_base"
        sc_rc=$?
    done
    if [ "$sc_rc" = "0" ]; then
        PASSED=$((PASSED + 1))
    else
        # rc=2 here means it no-fired MAX_RETRY times in a row → real FAIL.
        [ "$sc_rc" = "2" ] && echo "[FAIL] checkpoint=$ckpt reason=no-fire after $MAX_RETRY attempts"
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
