#!/bin/bash
# SuperScalar Testnet4 Exhibition — run all 10 on-chain structures.
#
# Usage:
#   bash tools/exhibition_testnet4.sh [--structure N] [--all] [--parallel] [--report-dir DIR]
#
# Prerequisites:
#   - bitcoind testnet4 synced and running
#   - CLN-A and CLN-B running with funded channel (for structure 4)
#   - SuperScalar built (build/superscalar_lsp, superscalar_client, etc.)
#
# Recommended testnet4 parameters (minimize BIP68 waits):
#   --step-blocks 5 --states-per-layer 2 --active-blocks 50 --dying-blocks 20

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
ORCHESTRATOR="$SCRIPT_DIR/test_orchestrator.py"
INSPECTOR="$SCRIPT_DIR/inspect_factory.py"

# Testnet4 RPC defaults (override via environment)
NETWORK="${SS_NETWORK:-testnet4}"
RPCUSER="${SS_RPCUSER:-testnet4rpc}"
RPCPASS="${SS_RPCPASS:-testnet4rpcpass123}"
RPCPORT="${SS_RPCPORT:-48332}"

# Testnet4 CLN dirs (override via environment)
CLN_A_DIR="${SS_CLN_A_DIR:-/var/lib/cln-testnet4}"
CLN_B_DIR="${SS_CLN_B_DIR:-/var/lib/cln-testnet4-b}"

# Exhibition output
REPORT_DIR="/tmp/exhibition_testnet4"
TXID_FILE="$REPORT_DIR/exhibition_txids.json"
SUMMARY_FILE="$REPORT_DIR/exhibition_summary.md"

# Timing params for testnet4 (minimize block waits)
TIMING_ARGS="--step-blocks 5 --states-per-layer 2"
ORCH_BASE_ARGS="--network $NETWORK --rpcuser $RPCUSER --rpcpassword $RPCPASS --amount 100000"

# Port assignments (so structures can run in parallel)
PORT_BASE=9750
declare -A STRUCTURE_PORTS=(
    [1]=9750 [2]=9751 [3]=9752 [4]=9753 [5]=9754
    [6]=9755 [7]=9756 [8]=9757 [9]=9758 [10]=9759
    [11]=9760
)

# Track results
declare -A RESULTS

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ts() { date "+[%H:%M:%S]"; }

log() { echo "$(ts) $*"; }

ensure_dirs() {
    mkdir -p "$REPORT_DIR"
    # Initialize TXID collection file
    if [[ ! -f "$TXID_FILE" ]]; then
        echo '{}' > "$TXID_FILE"
    fi
}

check_prereqs() {
    log "Checking prerequisites..."

    if [[ ! -x "$BUILD_DIR/superscalar_lsp" ]]; then
        log "ERROR: superscalar_lsp not found. Build first."
        exit 1
    fi

    # Check bitcoind testnet4
    if ! bitcoin-cli -$NETWORK -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport=$RPCPORT getblockcount > /dev/null 2>&1; then
        log "ERROR: Cannot connect to bitcoind testnet4. Is it running?"
        exit 1
    fi

    local height
    height=$(bitcoin-cli -$NETWORK -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport=$RPCPORT getblockcount)
    log "bitcoind testnet4 height: $height"

    # Check wallet balance
    local balance
    balance=$(bitcoin-cli -$NETWORK -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport=$RPCPORT -rpcwallet=default getbalance 2>/dev/null || echo "0")
    log "Wallet balance: $balance BTC"
}

save_txids() {
    # Append TXIDs from a report JSON to the master txid file
    local structure_name="$1"
    local report_path="$2"

    if [[ ! -f "$report_path" ]]; then
        log "WARNING: No report at $report_path"
        return
    fi

    python3 -c "
import json, sys
master_path = '$TXID_FILE'
report_path = '$report_path'
name = '$structure_name'
try:
    with open(master_path) as f:
        master = json.load(f)
except:
    master = {}
try:
    with open(report_path) as f:
        report = json.load(f)
except:
    print('WARNING: Could not parse report', file=sys.stderr)
    sys.exit(0)
txids = {}
# Funding TX
funding = report.get('funding', {})
if funding.get('txid'):
    txids['funding'] = funding['txid']
# Factory nodes
for node in report.get('factory', {}).get('nodes', []):
    if node.get('txid'):
        txids['node_{}'.format(node['index'])] = node['txid']
# Extra TXs
for key in ['close_tx', 'burn_tx', 'distribution_tx']:
    val = report.get(key)
    if isinstance(val, dict) and val.get('txid'):
        txids[key] = val['txid']
    elif isinstance(val, str) and len(val) == 64:
        txids[key] = val
for key in ['penalty_txs', 'expiry_txs', 'htlc_timeout_txs']:
    val = report.get(key, [])
    if isinstance(val, list):
        for i, item in enumerate(val):
            if isinstance(item, dict) and item.get('txid'):
                txids['{}_{}'.format(key, i)] = item['txid']
            elif isinstance(item, str) and len(item) == 64:
                txids['{}_{}'.format(key, i)] = item
master[name] = txids
with open(master_path, 'w') as f:
    json.dump(master, f, indent=2)
print('Saved {} TXIDs for {}'.format(len(txids), name))
" 2>&1
}

run_orchestrator() {
    local name="$1"
    local port="$2"
    shift 2
    local scenario_args=("$@")

    local report_path="$REPORT_DIR/${name}_report.json"
    local log_path="$REPORT_DIR/${name}.log"

    log "--- Structure: $name (port $port) ---"

    # Run orchestrator
    python3 "$ORCHESTRATOR" \
        $ORCH_BASE_ARGS \
        --port "$port" \
        "${scenario_args[@]}" \
        -v \
        > "$log_path" 2>&1
    local rc=$?

    if [[ $rc -eq 0 ]]; then
        log "PASS: $name"
        RESULTS[$name]="PASS"
    else
        log "FAIL: $name (exit $rc)"
        RESULTS[$name]="FAIL"
    fi

    # Copy report if it exists
    local orch_report="/tmp/superscalar_test/lsp_report.json"
    if [[ -f "$orch_report" ]]; then
        cp "$orch_report" "$report_path"
        save_txids "$name" "$report_path"
    fi

    return $rc
}

# ---------------------------------------------------------------------------
# Structure runners
# ---------------------------------------------------------------------------

structure_1_cooperative() {
    run_orchestrator "01_cooperative_close" "${STRUCTURE_PORTS[1]}" \
        --scenario cooperative_close
}

structure_2_full_dw_tree() {
    # Force close broadcasts full DW tree
    run_orchestrator "02_full_dw_tree" "${STRUCTURE_PORTS[2]}" \
        --scenario all_watch
}

structure_3_lstock_burn() {
    # Needs scenario_lstock_burn in orchestrator (added by production AI)
    # Falls back to direct LSP invocation if scenario not available
    if python3 "$ORCHESTRATOR" --list 2>&1 | grep -q "lstock_burn"; then
        run_orchestrator "03_lstock_burn" "${STRUCTURE_PORTS[3]}" \
            --scenario lstock_burn
    else
        log "WARNING: scenario_lstock_burn not yet in orchestrator. Skipping."
        RESULTS["03_lstock_burn"]="SKIP"
    fi
}

structure_4_bolt11_bridge() {
    # Needs scenario_bridge_bolt11 in orchestrator OR manual steps
    if python3 "$ORCHESTRATOR" --list 2>&1 | grep -q "bridge_bolt11"; then
        run_orchestrator "04_bolt11_bridge" "${STRUCTURE_PORTS[4]}" \
            --scenario bridge_bolt11
    else
        log "WARNING: scenario_bridge_bolt11 not yet in orchestrator. Skipping."
        RESULTS["04_bolt11_bridge"]="SKIP"
    fi
}

structure_5_rotation() {
    run_orchestrator "05_rotation" "${STRUCTURE_PORTS[5]}" \
        --scenario factory_rotation
}

structure_6_dw_advance() {
    # BLOCKED by P0 dw_advance crash
    if python3 "$ORCHESTRATOR" --list 2>&1 | grep -q "dw_advance"; then
        run_orchestrator "06_dw_advance" "${STRUCTURE_PORTS[6]}" \
            --scenario dw_advance
    else
        log "WARNING: scenario_dw_advance not yet in orchestrator (also BLOCKED by P0 crash). Skipping."
        RESULTS["06_dw_advance"]="SKIP (P0 BLOCKED)"
    fi
}

structure_7_breach_penalty() {
    run_orchestrator "07_breach_penalty" "${STRUCTURE_PORTS[7]}" \
        --scenario factory_breach
}

structure_8_cltv_timeout() {
    run_orchestrator "08_cltv_timeout" "${STRUCTURE_PORTS[8]}" \
        --scenario timeout_expiry
}

structure_9_remote_client() {
    # This is a manual/interactive test — just log instructions
    log "Structure 9 (remote client) requires running run_remote_client.sh from a separate machine."
    log "  On VPS: python3 $ORCHESTRATOR $ORCH_BASE_ARGS --port ${STRUCTURE_PORTS[9]} --scenario cooperative_close"
    log "  On laptop: bash tools/run_remote_client.sh --host <LSP_HOST> --port ${STRUCTURE_PORTS[9]} --network testnet4"
    RESULTS["09_remote_client"]="MANUAL"
}

structure_10_distribution_tx() {
    if python3 "$ORCHESTRATOR" --list 2>&1 | grep -q "distribution_tx"; then
        run_orchestrator "10_distribution_tx" "${STRUCTURE_PORTS[10]}" \
            --scenario distribution_tx
    else
        log "WARNING: scenario_distribution_tx not yet in orchestrator. Skipping."
        RESULTS["10_distribution_tx"]="SKIP"
    fi
}

structure_11_jit_channel() {
    if python3 "$ORCHESTRATOR" --list 2>&1 | grep -q "jit_lifecycle"; then
        run_orchestrator "11_jit_channel" "${STRUCTURE_PORTS[11]}" \
            --scenario jit_lifecycle
    else
        log "WARNING: scenario_jit_lifecycle not yet in orchestrator. Skipping."
        RESULTS["11_jit_channel"]="SKIP"
    fi
}

# ---------------------------------------------------------------------------
# Inspection report
# ---------------------------------------------------------------------------

generate_report() {
    log "Generating inspection report..."

    if [[ ! -f "$INSPECTOR" ]]; then
        log "WARNING: inspect_factory.py not found, skipping report generation"
        return
    fi

    # Generate per-structure reports from saved report JSONs
    for report_json in "$REPORT_DIR"/*_report.json; do
        [[ -f "$report_json" ]] || continue
        local base
        base=$(basename "$report_json" _report.json)
        python3 "$INSPECTOR" \
            --report "$report_json" \
            --on-chain \
            --network "$NETWORK" \
            --rpcuser "$RPCUSER" \
            --rpcpassword "$RPCPASS" \
            --rpcport "$RPCPORT" \
            -o "$REPORT_DIR/${base}_inspection.md" 2>&1 || true
    done

    # Generate master summary
    {
        echo "# SuperScalar Testnet4 Exhibition Summary"
        echo ""
        echo "Generated: $(date -u '+%Y-%m-%d %H:%M UTC')"
        echo ""
        echo "## Results"
        echo ""
        echo "| # | Structure | Result |"
        echo "|---|-----------|--------|"
        for key in $(echo "${!RESULTS[@]}" | tr ' ' '\n' | sort); do
            echo "| | $key | ${RESULTS[$key]} |"
        done
        echo ""
        echo "## TXID Collection"
        echo ""
        if [[ -f "$TXID_FILE" ]]; then
            python3 -c "
import json
with open('$TXID_FILE') as f:
    data = json.load(f)
total = sum(len(v) for v in data.values() if isinstance(v, dict))
print('Total TXIDs collected: {}'.format(total))
print('')
for name, txids in sorted(data.items()):
    if isinstance(txids, dict):
        print('### {}'.format(name))
        for label, txid in sorted(txids.items()):
            print('- **{}:** \`{}\`'.format(label, txid))
        print('')
" 2>&1
        fi
        echo ""
        echo "## Inspection Reports"
        echo ""
        for md_file in "$REPORT_DIR"/*_inspection.md; do
            [[ -f "$md_file" ]] || continue
            echo "- $(basename "$md_file")"
        done
    } > "$SUMMARY_FILE"

    log "Summary written to $SUMMARY_FILE"
    log "TXIDs collected in $TXID_FILE"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --structure N    Run only structure N (1-11)"
    echo "  --all            Run all structures sequentially"
    echo "  --parallel       Run independent structures in parallel (2,3,7)"
    echo "  --report-dir DIR Output directory (default: /tmp/exhibition_testnet4)"
    echo "  --report-only    Only generate report from existing data"
    echo "  --list           List structures"
    echo ""
    echo "Structures:"
    echo "  1  Cooperative close"
    echo "  2  Full DW tree (force close)"
    echo "  3  L-stock burn"
    echo "  4  BOLT11 bridge payment"
    echo "  5  Factory rotation"
    echo "  6  DW advance + force close"
    echo "  7  Breach + penalty"
    echo "  8  CLTV timeout recovery"
    echo "  9  Remote client (manual)"
    echo "  10 Distribution TX (P2A anchor)"
    echo "  11 JIT channel (late-arriving client)"
}

STRUCTURE=""
RUN_ALL=false
RUN_PARALLEL=false
REPORT_ONLY=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --structure) STRUCTURE="$2"; shift 2 ;;
        --all) RUN_ALL=true; shift ;;
        --parallel) RUN_PARALLEL=true; shift ;;
        --report-dir) REPORT_DIR="$2"; TXID_FILE="$REPORT_DIR/exhibition_txids.json"; SUMMARY_FILE="$REPORT_DIR/exhibition_summary.md"; shift 2 ;;
        --report-only) REPORT_ONLY=true; shift ;;
        --list) usage; exit 0 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown: $1"; usage; exit 1 ;;
    esac
done

ensure_dirs

if $REPORT_ONLY; then
    generate_report
    exit 0
fi

check_prereqs

if [[ -n "$STRUCTURE" ]]; then
    case "$STRUCTURE" in
        1) structure_1_cooperative ;;
        2) structure_2_full_dw_tree ;;
        3) structure_3_lstock_burn ;;
        4) structure_4_bolt11_bridge ;;
        5) structure_5_rotation ;;
        6) structure_6_dw_advance ;;
        7) structure_7_breach_penalty ;;
        8) structure_8_cltv_timeout ;;
        9) structure_9_remote_client ;;
        10) structure_10_distribution_tx ;;
        11) structure_11_jit_channel ;;
        *) echo "Unknown structure: $STRUCTURE"; exit 1 ;;
    esac
elif $RUN_ALL; then
    log "=== Running all 11 structures sequentially ==="

    if $RUN_PARALLEL; then
        log "Running structures 2, 3, 7 in parallel..."
        structure_2_full_dw_tree &
        PID_2=$!
        structure_3_lstock_burn &
        PID_3=$!
        structure_7_breach_penalty &
        PID_7=$!

        # Run non-parallel ones while waiting
        structure_1_cooperative || true
        structure_4_bolt11_bridge || true
        structure_5_rotation || true

        # Wait for parallel batch
        wait $PID_2 || true
        wait $PID_3 || true
        wait $PID_7 || true

        # Continue with rest
        structure_6_dw_advance || true
        structure_8_cltv_timeout || true
        structure_9_remote_client || true
        structure_10_distribution_tx || true
        structure_11_jit_channel || true
    else
        structure_1_cooperative || true
        structure_2_full_dw_tree || true
        structure_3_lstock_burn || true
        structure_4_bolt11_bridge || true
        structure_5_rotation || true
        structure_6_dw_advance || true
        structure_7_breach_penalty || true
        structure_8_cltv_timeout || true
        structure_9_remote_client || true
        structure_10_distribution_tx || true
        structure_11_jit_channel || true
    fi
else
    echo "Specify --structure N, --all, or --list"
    usage
    exit 1
fi

# Generate final report
generate_report

# Print summary
log ""
log "=== EXHIBITION RESULTS ==="
for key in $(echo "${!RESULTS[@]}" | tr ' ' '\n' | sort); do
    log "  $key: ${RESULTS[$key]}"
done
n_pass=$(echo "${RESULTS[@]}" | tr ' ' '\n' | grep -c "PASS" || true)
n_total=${#RESULTS[@]}
log "  $n_pass/$n_total passed"
log ""
log "Reports in: $REPORT_DIR"
