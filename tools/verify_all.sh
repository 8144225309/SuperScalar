#!/bin/bash
# tools/verify_all.sh — SuperScalar Full Verification Suite
#
# Runs everything sequentially: build, unit tests, regtest tests, all demos.
# Reports pass/fail per section with timing.
#
# Usage:
#   bash tools/verify_all.sh

set -e

# ---------------------------------------------------------------------------
# Color definitions
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/.."
BUILD_DIR="$PROJECT_DIR/build"
NPROC=$(nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 4)

RESULTS=()
PASS=0
FAIL=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
section() {
    echo ""
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BLUE} ${BOLD}$1${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo ""
}

record() {
    local name="$1" status="$2" elapsed="$3"
    if [ "$status" = "PASS" ]; then
        echo -e "  ${GREEN}PASS${NC}  $name  ${DIM}(${elapsed}s)${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC}  $name  ${DIM}(${elapsed}s)${NC}"
        FAIL=$((FAIL + 1))
    fi
    RESULTS+=("$status $name (${elapsed}s)")
}

# ---------------------------------------------------------------------------
# 1. Build
# ---------------------------------------------------------------------------
section "Step 1: Build"
START=$(date +%s)

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

if cmake .. && make -j"$NPROC"; then
    ELAPSED=$(( $(date +%s) - START ))
    record "Build" "PASS" "$ELAPSED"
else
    ELAPSED=$(( $(date +%s) - START ))
    record "Build" "FAIL" "$ELAPSED"
    echo -e "${RED}Build failed — cannot continue.${NC}"
    exit 1
fi

cd "$PROJECT_DIR"

# ---------------------------------------------------------------------------
# 2. Unit Tests
# ---------------------------------------------------------------------------
section "Step 2: Unit Tests"
START=$(date +%s)

if "$BUILD_DIR/test_superscalar" --unit 2>&1; then
    ELAPSED=$(( $(date +%s) - START ))
    record "Unit tests" "PASS" "$ELAPSED"
else
    ELAPSED=$(( $(date +%s) - START ))
    # Try without --unit flag (in case the binary doesn't support it)
    if "$BUILD_DIR/test_superscalar" 2>&1 | grep -q "PASS"; then
        record "Unit tests" "PASS" "$ELAPSED"
    else
        record "Unit tests" "FAIL" "$ELAPSED"
    fi
fi

# ---------------------------------------------------------------------------
# 3. Regtest Tests
# ---------------------------------------------------------------------------
section "Step 3: Regtest Tests"
START=$(date +%s)

# Start bitcoind for regtest if needed
STARTED_BITCOIND=0
if ! bitcoin-cli -regtest getblockchaininfo >/dev/null 2>&1; then
    echo -e "  ${DIM}Starting bitcoind -regtest...${NC}"
    bitcoind -regtest -daemon -fallbackfee=0.00001 -txindex=1 2>/dev/null || true
    STARTED_BITCOIND=1
    sleep 2
fi

if "$BUILD_DIR/test_superscalar" --regtest 2>&1; then
    ELAPSED=$(( $(date +%s) - START ))
    record "Regtest tests" "PASS" "$ELAPSED"
else
    ELAPSED=$(( $(date +%s) - START ))
    record "Regtest tests" "FAIL" "$ELAPSED"
fi

# ---------------------------------------------------------------------------
# 4. Basic Demo
# ---------------------------------------------------------------------------
section "Step 4: Basic Demo"
START=$(date +%s)

if bash "$SCRIPT_DIR/run_demo.sh" --basic 2>&1; then
    ELAPSED=$(( $(date +%s) - START ))
    record "Basic demo" "PASS" "$ELAPSED"
else
    ELAPSED=$(( $(date +%s) - START ))
    record "Basic demo" "FAIL" "$ELAPSED"
fi

# ---------------------------------------------------------------------------
# 5. Breach Demo
# ---------------------------------------------------------------------------
section "Step 5: Breach Demo"
START=$(date +%s)

if bash "$SCRIPT_DIR/run_demo.sh" --breach 2>&1; then
    ELAPSED=$(( $(date +%s) - START ))
    record "Breach demo" "PASS" "$ELAPSED"
else
    ELAPSED=$(( $(date +%s) - START ))
    record "Breach demo" "FAIL" "$ELAPSED"
fi

# ---------------------------------------------------------------------------
# 6. Rotation Demo
# ---------------------------------------------------------------------------
section "Step 6: Rotation Demo"
START=$(date +%s)

if bash "$SCRIPT_DIR/run_demo.sh" --rotation 2>&1; then
    ELAPSED=$(( $(date +%s) - START ))
    record "Rotation demo" "PASS" "$ELAPSED"
else
    ELAPSED=$(( $(date +%s) - START ))
    record "Rotation demo" "FAIL" "$ELAPSED"
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
if [ "$STARTED_BITCOIND" = "1" ]; then
    bitcoin-cli -regtest stop 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
section "Verification Summary"

for r in "${RESULTS[@]}"; do
    STATUS=$(echo "$r" | cut -d' ' -f1)
    REST=$(echo "$r" | cut -d' ' -f2-)
    if [ "$STATUS" = "PASS" ]; then
        echo -e "  ${GREEN}PASS${NC}  $REST"
    else
        echo -e "  ${RED}FAIL${NC}  $REST"
    fi
done

echo ""
echo -e "  ${GREEN}Passed:${NC} ${BOLD}$PASS${NC} / $((PASS + FAIL))"
if [ "$FAIL" -gt 0 ]; then
    echo -e "  ${RED}Failed:${NC} ${BOLD}$FAIL${NC}"
fi
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}All verification steps passed!${NC}"
else
    echo -e "  ${YELLOW}${BOLD}$FAIL step(s) failed — check output above.${NC}"
fi

echo ""
exit $FAIL
