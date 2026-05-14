#!/usr/bin/env bash
# test_regtest_k3_subfactory_breach.sh — k=3 variant of k2_subfactory_breach.
#
# k=3 means 3 sub-factories per PS leaf, 3 clients per sub-factory, k²=9
# clients per leaf.  Exercises the same code path as k=2 but with wider
# sub-factory shape — validates the keyagg/MuSig sessions still work at
# k+2 = 5 signers per sub-factory (vs 4 at k=2).
#
# Usage: bash tools/test_regtest_k3_subfactory_breach.sh [BUILD_DIR]
# Sets N_CLIENTS=9 and PS_SUB_ARITY=3, then exec's the canonical k² test.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec env N_CLIENTS=9 PS_SUB_ARITY=3 \
    bash "$SCRIPT_DIR/test_regtest_k2_subfactory_breach.sh" "$@"
