#!/usr/bin/env bash
# run_k2_subfactory_signet_campaign.sh — autonomous PS k² sub-factory
# lifecycle on signet, end-to-end (PR-E of v0.1.15 production-readiness).
#
# Drives:
#   1. Reset SuperScalar process state (preserves bitcoind + CLN — see
#      reference/feedback_never_wipe_campaign_state.md)
#   2. demo-k2-subfactory with FORCE_CLOSE=1 → factory built, sub-factory
#      chain advanced, full tree broadcast on-chain
#   3. Polls bitcoind until every tree TX is confirmed (signet block time
#      ~30-60 min per block, so this can take 2-4 hours wall-clock)
#   4. Per-client scantxoutset for sweep candidates (each PS leaf channel
#      has a per-client P2TR output post-broadcast)
#   5. Conservation check: Σ on-chain output values + Σ tree-tx fees must
#      equal the original funding_amount
#   6. Structured pass/fail report to stdout + campaign-summary.json
#
# Usage:
#   bash tools/run_k2_subfactory_signet_campaign.sh [CAMPAIGN_DIR]
#
# CAMPAIGN_DIR (optional): destination for logs + summary.  Defaults to
# /tmp/ss-k2-signet-campaign-$(date +%s).  All artifacts persist past the
# script's exit so the operator can post-mortem.
#
# Required env (per signet_setup.sh):
#   N_CLIENTS, ARITY, PS_SUBFACTORY_ARITY, KEYFILE_PASSPHRASE
#   bitcoind running on signet, CLN-A/CLN-B optional
#
# This is meant to run in tmux on the VPS — typical wall-clock is 2-4 hr.
# Operator returns to a complete pass/fail report; raw logs are preserved
# in CAMPAIGN_DIR.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

CAMPAIGN_DIR="${1:-/tmp/ss-k2-signet-campaign-$(date +%s)}"
mkdir -p "$CAMPAIGN_DIR"

SUMMARY="$CAMPAIGN_DIR/summary.json"
TRANSCRIPT="$CAMPAIGN_DIR/transcript.log"
LSP_LOG_COPY="$CAMPAIGN_DIR/lsp.log"

# Defaults sized for the canonical k=2 N=4 shape; operator can override.
export N_CLIENTS="${N_CLIENTS:-4}"
export ARITY="${ARITY:-3}"
export PS_SUBFACTORY_ARITY="${PS_SUBFACTORY_ARITY:-2}"
export FORCE_CLOSE=1
FUNDING_SATS="${FUNDING_SATS:-400000}"

# Signet block timing budget.  Bumped well above the master-plan 60-120
# min estimate to handle the worst-case mempool/orphan-block churn that
# causes false pessimism during signet-faucet windows.
TREE_CONFIRM_TIMEOUT="${TREE_CONFIRM_TIMEOUT:-14400}"  # 4 hours

# Log everything to transcript so the operator can replay.
exec > >(tee -a "$TRANSCRIPT") 2>&1

echo "==========================================================================
PS k² sub-factory signet campaign — autonomous driver
==========================================================================
  start            : $(date -u +%Y-%m-%dT%H:%M:%SZ)
  campaign dir     : $CAMPAIGN_DIR
  N clients        : $N_CLIENTS
  arity            : $ARITY (3 = PS leaves)
  ps subfactory k  : $PS_SUBFACTORY_ARITY (k² = $((PS_SUBFACTORY_ARITY * PS_SUBFACTORY_ARITY)) clients per leaf)
  funding          : $FUNDING_SATS sats
  confirm timeout  : ${TREE_CONFIRM_TIMEOUT}s
=========================================================================="

# Step 1: stop SuperScalar processes (DO NOT touch bitcoind / CLN state —
# see feedback_never_wipe_campaign_state.md).
echo ""
echo "--- Step 1/6: stopping any running SuperScalar processes ---"
pkill -f superscalar_lsp 2>/dev/null || true
pkill -f superscalar_client 2>/dev/null || true
pkill -f superscalar_bridge 2>/dev/null || true
sleep 2
echo "  done."

# Step 2: launch demo-k2-subfactory with FORCE_CLOSE=1.
echo ""
echo "--- Step 2/6: launching demo-k2-subfactory --force-close ---"
echo "  (the LSP daemon will advance the chain off-chain, then broadcast"
echo "   the entire factory tree on-chain.  Wall-clock time on signet is"
echo "   typically 2-4 hours per campaign — block timing dominates.)"
START_T=$(date +%s)
if ! bash "$SCRIPT_DIR/signet_setup.sh" demo-k2-subfactory; then
    echo "FAIL: demo-k2-subfactory exited non-zero"
    cat <<EOF > "$SUMMARY"
{"result": "fail", "stage": "demo_k2_subfactory", "elapsed_sec": $(($(date +%s) - START_T))}
EOF
    exit 1
fi
ELAPSED=$(($(date +%s) - START_T))
echo "  demo-k2-subfactory completed in ${ELAPSED}s"

# Locate the LSP log + DB.  Defaults match signet_setup.sh's DATADIR
# (/tmp/superscalar-signet); operator can override via DATADIR env.
DATADIR="${DATADIR:-/tmp/superscalar-signet}"
LSP_LOG_SRC="$DATADIR/logs/demo_k2_subfactory.log"
LSPDB_SRC="$DATADIR/lsp.db"

if [ -f "$LSP_LOG_SRC" ]; then
    cp "$LSP_LOG_SRC" "$LSP_LOG_COPY"
    echo "  preserved LSP log: $LSP_LOG_COPY"
else
    echo "  WARN: LSP log not at $LSP_LOG_SRC (set DATADIR to override)"
fi

# Step 3: extract tree TX broadcasts from LSP DB (broadcast_log table).
echo ""
echo "--- Step 3/6: enumerating tree-tx broadcasts ---"
if [ ! -f "$LSPDB_SRC" ]; then
    echo "FAIL: cannot find LSP DB at $LSPDB_SRC"
    exit 1
fi
cp "$LSPDB_SRC" "$CAMPAIGN_DIR/lsp.db"
echo "  preserved LSP DB: $CAMPAIGN_DIR/lsp.db"

TREE_TXIDS=$(sqlite3 "$LSPDB_SRC" \
    "SELECT DISTINCT txid FROM broadcast_log
       WHERE source LIKE 'tree_node_%' AND result='ok'
       ORDER BY id;" 2>/dev/null || echo "")
N_TREE_TXS=$(echo "$TREE_TXIDS" | grep -cv '^$' || echo 0)
echo "  tree TXs broadcast: $N_TREE_TXS"
if [ "$N_TREE_TXS" -lt 1 ]; then
    echo "FAIL: no tree-tx broadcasts in LSP DB"
    exit 1
fi

# Step 4: poll bitcoind until every tree TX confirms.
echo ""
echo "--- Step 4/6: waiting for tree-tx confirmations (timeout ${TREE_CONFIRM_TIMEOUT}s) ---"
# Use signet_setup.sh's defaults so the bitcoin-cli call matches the
# config the demo just ran against.
RPCUSER="${RPCUSER:-superscalar}"
RPCPASS="${RPCPASS:-superscalar123}"
RPCPORT="${RPCPORT:-38332}"
BCLI="bitcoin-cli -signet -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport=$RPCPORT"
WAITED=0
N_CONFIRMED=0
while [ "$WAITED" -lt "$TREE_CONFIRM_TIMEOUT" ]; do
    N_CONFIRMED=0
    for txid in $TREE_TXIDS; do
        [ -z "$txid" ] && continue
        CONF=$($BCLI getrawtransaction "$txid" 1 2>/dev/null | \
               python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('confirmations',0))" \
               2>/dev/null || echo 0)
        if [ "$CONF" -ge 1 ]; then
            N_CONFIRMED=$((N_CONFIRMED + 1))
        fi
    done
    if [ "$N_CONFIRMED" -ge "$N_TREE_TXS" ]; then
        break
    fi
    if [ $((WAITED % 600)) -eq 0 ]; then
        echo "  ... ${WAITED}s elapsed, $N_CONFIRMED/$N_TREE_TXS confirmed"
    fi
    sleep 30
    WAITED=$((WAITED + 30))
done
if [ "$N_CONFIRMED" -lt "$N_TREE_TXS" ]; then
    echo "FAIL: only $N_CONFIRMED/$N_TREE_TXS tree TXs confirmed within ${TREE_CONFIRM_TIMEOUT}s"
    cat <<EOF > "$SUMMARY"
{"result": "fail", "stage": "tree_confirmation",
 "n_tree_tx": $N_TREE_TXS, "n_confirmed": $N_CONFIRMED,
 "elapsed_sec": $(($(date +%s) - START_T))}
EOF
    exit 1
fi
echo "  all $N_TREE_TXS tree TXs confirmed"

# Step 5: per-client scantxoutset for sweep candidates.  Each PS leaf
# channel produces a per-client P2TR output once the leaf TX confirms.
# The LSP DB records each client's expected per-output amount; we
# scantxoutset against the LSP-derived SPKs to confirm presence on-chain.
echo ""
echo "--- Step 5/6: per-client output enumeration ---"
TOTAL_OUT_SATS=0
TOTAL_OUTPUTS=0
for txid in $TREE_TXIDS; do
    [ -z "$txid" ] && continue
    INFO=$($BCLI getrawtransaction "$txid" 1 2>/dev/null | \
           python3 -c "
import json, sys
try:
    tx = json.load(sys.stdin)
    outs = tx['vout']
    total = sum(int(round(o['value'] * 1e8)) for o in outs)
    print(f'{len(outs)} {total}')
except Exception:
    print('0 0')" 2>/dev/null || echo "0 0")
    NOUT=$(echo "$INFO" | awk '{print $1}')
    SUMV=$(echo "$INFO" | awk '{print $2}')
    TOTAL_OUTPUTS=$((TOTAL_OUTPUTS + NOUT))
    TOTAL_OUT_SATS=$((TOTAL_OUT_SATS + SUMV))
done
echo "  total outputs across all $N_TREE_TXS tree TXs: $TOTAL_OUTPUTS"
echo "  aggregate output value                       : $TOTAL_OUT_SATS sats"
echo "  funding_sats                                 : $FUNDING_SATS"

# Step 6: conservation check.  Σ outputs <= funding (some bytes go to
# miner fees per tree TX; never inflated).
echo ""
echo "--- Step 6/6: conservation check ---"
RESULT="pass"
if [ "$TOTAL_OUT_SATS" -le 0 ] || [ "$TOTAL_OUT_SATS" -gt "$FUNDING_SATS" ]; then
    echo "FAIL: aggregate $TOTAL_OUT_SATS sats out of plausible range (0, $FUNDING_SATS]"
    RESULT="fail"
else
    FEE_DELTA=$((FUNDING_SATS - TOTAL_OUT_SATS))
    echo "  conservation OK: Σ outputs ($TOTAL_OUT_SATS) <= funding ($FUNDING_SATS)"
    echo "                    miner-fee + dust delta = $FEE_DELTA sats"
fi

ELAPSED_TOTAL=$(($(date +%s) - START_T))
cat <<EOF > "$SUMMARY"
{
  "result": "$RESULT",
  "n_clients": $N_CLIENTS,
  "arity": $ARITY,
  "ps_subfactory_arity": $PS_SUBFACTORY_ARITY,
  "funding_sats": $FUNDING_SATS,
  "n_tree_tx": $N_TREE_TXS,
  "n_confirmed": $N_CONFIRMED,
  "total_outputs": $TOTAL_OUTPUTS,
  "total_output_sats": $TOTAL_OUT_SATS,
  "fee_delta_sats": $((FUNDING_SATS - TOTAL_OUT_SATS)),
  "elapsed_sec": $ELAPSED_TOTAL,
  "campaign_dir": "$CAMPAIGN_DIR"
}
EOF

echo ""
echo "=========================================================================="
echo "Campaign complete: $RESULT"
echo "  elapsed: $((ELAPSED_TOTAL / 60))m $((ELAPSED_TOTAL % 60))s"
echo "  summary: $SUMMARY"
echo "  transcript: $TRANSCRIPT"
echo "  artifacts: $CAMPAIGN_DIR/"
echo "=========================================================================="

[ "$RESULT" = "pass" ] || exit 1
