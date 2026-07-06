#!/usr/bin/env bash
# regtest_full_regression_v020.sh — v0.2.0 release-gate regtest sweep.
# Extends tools/regtest_full_regression.sh with the trustless watchtower test
# plus additional cheat/subfactory/ptlc scenarios.  Sequential execution;
# does NOT exit on first failure so we get a full pass/fail matrix.

set -uo pipefail

cd /root/SuperScalar

RUNNERS=(
    # Phase 4 trustless acceptance (must pass — v0.2.0 release gate)
    test_regtest_watchtower_trustless.sh

    # Cheat-engine campaign (7 scripts — original regression runner)
    test_regtest_cheat_leaf.sh
    test_regtest_cheat_leaf_multistate.sh
    test_regtest_cheat_client.sh
    test_regtest_cheat_daemon_leaf.sh
    test_regtest_kill_after_state_advance.sh
    test_regtest_tier_b_rollover_ps.sh
    test_regtest_cheat_daemon_subfactory.sh

    # Gap-scan efficacy: client refuses a malicious LSP's invalid factory tree
    test_regtest_bad_tree_verify.sh

    # Sub-factory + Tier B (additional)
    test_regtest_subfactory_chain_advance_multi.sh
    test_regtest_k2_subfactory_breach.sh

    # PTLC paths (5 scripts)
    test_regtest_ptlc_basic.sh
    test_regtest_ptlc_breach.sh
    test_regtest_ptlc_chain.sh
    test_regtest_ptlc_breach_chain.sh
    test_regtest_ptlc_restart.sh

    # Reorg + recovery
    test_regtest_rebroadcast_recovery.sh
    test_regtest_same_height_reorg.sh

    # Wire-level + dual factory
    test_regtest_wire_leaf_advance.sh
    test_regtest_dual_factory.sh
)

echo "===================================="
echo " v0.2.0 regtest release-gate sweep"
echo " ${#RUNNERS[@]} scripts queued"
echo " Started: $(date)"
echo "===================================="

PASS=0
FAIL=0
RESULTS=()
for r in "${RUNNERS[@]}"; do
    echo
    echo "##### running $r #####"
    # Per memory feedback_pkill_scope: bare 'superscalar' would match
    # in-flight testnet4 work.  Limit to single-binary process names.
    pkill -9 -f 'superscalar_lsp --network regtes[t]' 2>/dev/null
    pkill -9 -f 'superscalar_client --network regtes[t]' 2>/dev/null
    pkill -9 -f 'superscalar_watchtower --network regtes[t]' 2>/dev/null
    sleep 2
    if timeout 900 bash "tools/$r" > "/tmp/regression_$r.log" 2>&1; then
        echo "  PASS: $r"
        PASS=$((PASS + 1))
        RESULTS+=("PASS  $r")
    else
        rc=$?
        echo "  FAIL (rc=$rc): $r"
        FAIL=$((FAIL + 1))
        RESULTS+=("FAIL  $r (rc=$rc)")
        echo "  --- tail of log ---"
        tail -10 "/tmp/regression_$r.log"
    fi
done

echo
echo "===================================="
echo " v0.2.0 regtest sweep summary"
echo " Finished: $(date)"
echo " Passed: $PASS / ${#RUNNERS[@]}"
echo " Failed: $FAIL / ${#RUNNERS[@]}"
echo "===================================="
for r in "${RESULTS[@]}"; do echo "  $r"; done

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
