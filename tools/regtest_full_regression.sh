#!/usr/bin/env bash
# run_full_regression.sh — sequential regression sweep of all 6 cheat-engine runners.
# Stops on first failure (set -e) so we can fix and re-run.

set -uo pipefail

cd /root/SuperScalar

RUNNERS=(
    test_regtest_cheat_leaf.sh
    test_regtest_cheat_leaf_multistate.sh
    test_regtest_cheat_client.sh
    test_regtest_cheat_daemon_leaf.sh
    test_regtest_kill_after_state_advance.sh
    test_regtest_tier_b_rollover_ps.sh
    test_regtest_cheat_daemon_subfactory.sh
)

RESULTS=()
for r in "${RUNNERS[@]}"; do
    echo
    echo "##### running $r #####"
    pkill -9 -f superscalar_ 2>/dev/null
    sleep 2
    if timeout 900 bash "tools/$r" > "/tmp/regression_$r.log" 2>&1; then
        echo "  PASS: $r"
        RESULTS+=("PASS $r")
    else
        rc=$?
        echo "  FAIL (rc=$rc): $r"
        RESULTS+=("FAIL $r rc=$rc")
        tail -20 "/tmp/regression_$r.log"
    fi
done

echo
echo "==================== regression summary ===================="
for r in "${RESULTS[@]}"; do echo "  $r"; done
