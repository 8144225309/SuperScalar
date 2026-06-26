#!/usr/bin/env bash
# run_rigor_matrix.sh — committed runner for the verification-rigor breach/penalty test matrix.
#
# Replaces the ad-hoc validateN scripts used during the rigor campaign. Adds two guards that
# cost real diagnosis time when they were missing:
#   - NODE-UP guard: a dead bitcoind silently fails every test as a cryptic "LSP died". This
#     restarts it (regtest is not a systemd unit on the test VPS) and fails loudly if it can't.
#   - CHAIN-RESET guard: the regtest chain was externally reset mid-session (3759 -> 578). We
#     record the start height and flag a regression so results aren't silently trusted.
# Each breach test now also clears its own leftover ports, so a zombie LSP can't block a bind.
#
# Usage:  ./run_rigor_matrix.sh [BUILD_DIR]   (default /root/SuperScalar/build-release)
#         SS_REORG_REFIRE=1 to also run the commitment reorg-refire phase.
# Exit:   0 if no FAILs (SKIPs allowed), 1 otherwise.
set -uo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build-release}"
REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
BITCOIND_BIN="${BITCOIND_BIN:-/usr/local/bin/bitcoind-jaynet}"
B="bitcoin-cli -regtest -conf=$REGTEST_CONF"
T="$(cd "$(dirname "$(realpath "$0")")" && pwd)"

ensure_node() {
    $B getblockcount >/dev/null 2>&1 && return 0
    echo "  [guard] regtest node DOWN — restarting via $BITCOIND_BIN"
    "$BITCOIND_BIN" -conf="$REGTEST_CONF" >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do sleep 2; $B getblockcount >/dev/null 2>&1 && return 0; done
    echo "  [guard] FATAL: regtest node unreachable after restart"; return 1
}

ensure_node || exit 1
START_H=$($B getblockcount 2>/dev/null || echo 0)
echo "=== RIGOR MATRIX  $(date -u)  node@$START_H  build=$BUILD_DIR ==="

# Full rigor set. crash + rollover get longer budgets; rollover last (longest).
TESTS_FAST="test_regtest_cheat_client test_regtest_ps_commitment_penalty test_regtest_trustless_commitment_breach \
test_regtest_cheat_daemon_subfactory test_regtest_cheat_daemon_leaf test_regtest_cheat_daemon_leaf_late_wt \
test_regtest_cheat_daemon_leaf_multistate test_regtest_cheat_realloc test_regtest_cheat_lstock_buy \
test_regtest_htlc_force_close test_regtest_cheat_leaf test_regtest_ptlc_breach_chain test_regtest_ptlc_breach \
test_regtest_kind3_force_close_standalone test_regtest_k2_subfactory_breach test_regtest_wt_restart_race"

P=0; F=0; S=0; FAILED=""
run() {
    local name="$1" to="${2:-900}"
    ensure_node || { echo "  [guard] node unrecoverable, aborting"; exit 1; }
    local h; h=$($B getblockcount 2>/dev/null || echo 0)
    [ "${h:-0}" -lt "${START_H:-0}" ] && echo "  [guard] WARNING: chain height regressed ($START_H -> $h) — possible external reset"
    echo "##### $name ($(date -u +%H:%MZ)) #####"
    SS_REORG_REFIRE="${SS_REORG_REFIRE:-0}" BUILD_DIR="$BUILD_DIR" timeout "$to" "$T/$name.sh" "$BUILD_DIR" > "/tmp/rigor_$name.log" 2>&1
    local rc=$?
    case $rc in
        0)  P=$((P+1)); echo "  -> PASS";;
        77) S=$((S+1)); echo "  -> SKIP (inconclusive, not a pass)";;
        *)  F=$((F+1)); FAILED="$FAILED $name(rc=$rc)"; echo "  -> FAIL rc=$rc";;
    esac
    grep -aE "A-2 recovery|REORG-REFIRE|smallest|sats swept|PASS:|FAIL:" "/tmp/rigor_$name.log" 2>/dev/null \
        | grep -avE "Updating files|Killed|generatetoaddress" | tail -2
}

for t in $TESTS_FAST; do run "$t"; done
run test_regtest_crash_at_every_phase 2700
run test_regtest_cheat_daemon_rollover 1200

echo "=== SUMMARY: PASS=$P SKIP=$S FAIL=$F ==="
[ -n "$FAILED" ] && echo "FAILED:$FAILED"
[ "$F" -eq 0 ]
