#!/usr/bin/env bash
# test_regtest_k4_subfactory_breach.sh — k=4 variant of k2_subfactory_breach.
#
# k=4 means 4 sub-factories per PS leaf, 4 clients per sub-factory, k²=16
# clients per leaf.  Exercises wider sub-factory keyagg/MuSig: k+2 = 6
# signers per sub-factory.  At FACTORY_MAX_OUTPUTS=16, this is near the
# upper bound for sub-factory arity (k_max = 15 per
# factory_set_ps_subfactory_arity cap).
#
# Usage: bash tools/test_regtest_k4_subfactory_breach.sh [BUILD_DIR]
# Sets N_CLIENTS=16 and PS_SUB_ARITY=4, then exec's the canonical k² test.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec env N_CLIENTS=16 PS_SUB_ARITY=4 \
    bash "$SCRIPT_DIR/test_regtest_k2_subfactory_breach.sh" "$@"
