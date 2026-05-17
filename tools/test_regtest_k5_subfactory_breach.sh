#!/usr/bin/env bash
# k=5 variant of k2_subfactory_breach. N_CLIENTS=25 = k^2.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec env N_CLIENTS=25 PS_SUB_ARITY=5 \
    bash "$SCRIPT_DIR/test_regtest_k2_subfactory_breach.sh" "$@"
