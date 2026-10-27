#!/usr/bin/env bash
# Gap-filler sweep: branch regtest scripts NOT in regtest_full_regression_v020.sh,
# re-run against the CURRENT branch HEAD to confirm no regression since each landed.
# Excludes signet_* (real network) + soak (hours). Sequential, scoped pkills.
set -uo pipefail
cd /root/SuperScalar
RUNNERS=(
    test_regtest_mass_exit.sh                       # #313 self-custody (branch namesake)
    test_regtest_n64_payments.sh                    # #311 scale ring
    test_regtest_trustless_commitment_breach.sh     # standalone-WT commitment penalty
    test_regtest_ps_commitment_penalty.sh           # PS commitment breach punished
    test_regtest_kind3_force_close_standalone.sh    # kind=3 trustless sweep
    test_regtest_htlc_force_close.sh                # honest force-close HTLC sweep
    test_regtest_expiry.sh                          # #325 multi-level CLTV expiry
    test_regtest_trustless_commitment_gap.sh        # WT commitment-watch presence
    test_regtest_adversarial_reorg.sh               # reorg invalidate/reconsider
    test_regtest_cheat_daemon_leaf_late_wt.sh       # late-WT-registration breach
    test_regtest_cheat_daemon_leaf_multistate.sh    # multistate daemon breach
    test_regtest_wt_restart_race.sh                 # WT restart penalty race (regtest)
)
echo "==== gap-filler sweep: ${#RUNNERS[@]} scripts @ $(date) ===="
PASS=0; FAIL=0; declare -a FAILED=()
for r in "${RUNNERS[@]}"; do
    echo; echo "##### running $r #####"
    pkill -9 -f 'superscalar_lsp --network regtes[t]' 2>/dev/null
    pkill -9 -f 'superscalar_client --network regtes[t]' 2>/dev/null
    pkill -9 -f 'superscalar_watchtower --network regtes[t]' 2>/dev/null
    sleep 2
    if [ ! -f "tools/$r" ]; then echo "  SKIP: tools/$r not found"; continue; fi
    if timeout 900 bash "tools/$r" > "/tmp/gapfill_${r}.log" 2>&1; then
        echo "  PASS: $r"; PASS=$((PASS+1))
    else
        rc=$?; echo "  FAIL: $r (rc=$rc) -- /tmp/gapfill_${r}.log"; FAIL=$((FAIL+1)); FAILED+=("$r")
    fi
done
echo; echo "==== gap-filler summary: PASS=$PASS FAIL=$FAIL @ $(date) ===="
for f in "${FAILED[@]:-}"; do [ -n "$f" ] && echo "  FAILED: $f"; done
echo "==== GAPFILL DONE ===="
