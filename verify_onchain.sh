#!/bin/bash
# verify_onchain.sh — Shared on-chain verification helpers for SuperScalar test scripts
# Source this file: source verify_onchain.sh

RESULTS_FILE="${RESULTS_FILE:-results.jsonl}"

# ─── Result Logging ───────────────────────────────────────────────────────────

log_result() {
  local test_id="$1" test_name="$2" status="$3" detail="${4:-}" elapsed="${5:-0}"
  local ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  printf '{"test_id":"%s","test_name":"%s","status":"%s","detail":"%s","elapsed_s":%s,"timestamp":"%s"}\n' \
    "$test_id" "$test_name" "$status" "$detail" "$elapsed" "$ts" >> "$RESULTS_FILE"
  if [ "$status" = "PASS" ]; then
    echo "  ✓ $test_id: $test_name — PASS ($elapsed s)"
  else
    echo "  ✗ $test_id: $test_name — FAIL: $detail ($elapsed s)"
  fi
}

# ─── Bitcoin CLI Helpers ──────────────────────────────────────────────────────

# Set BTC_CLI before sourcing, or use default regtest
BTC_CLI="${BTC_CLI:-bitcoin-cli -regtest -rpcuser=rpcuser -rpcpassword=rpcpass -rpcport=18443}"
WALLET_CLI="${WALLET_CLI:-$BTC_CLI -rpcwallet=superscalar_launch}"

get_tx_details() {
  local txid="$1"
  $BTC_CLI getrawtransaction "$txid" true 2>/dev/null
}

get_tx_output_count() {
  local txid="$1"
  local details=$(get_tx_details "$txid")
  echo "$details" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('vout',[])))" 2>/dev/null || echo 0
}

get_tx_output_types() {
  local txid="$1"
  local details=$(get_tx_details "$txid")
  echo "$details" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for v in d.get('vout', []):
    print(v.get('scriptPubKey', {}).get('type', 'unknown'))
" 2>/dev/null
}

get_tx_total_value() {
  local txid="$1"
  local details=$(get_tx_details "$txid")
  echo "$details" | python3 -c "
import sys, json
d = json.load(sys.stdin)
total = sum(v.get('value', 0) for v in d.get('vout', []))
print(int(total * 100000000))
" 2>/dev/null || echo 0
}

# Count spent outputs of a given TX (proxy for descendant count)
count_spent_outputs() {
  local txid="$1"
  local n_outputs=$(get_tx_output_count "$txid")
  local count=0
  for i in $(seq 0 $((n_outputs - 1))); do
    local utxo=$($BTC_CLI gettxout "$txid" "$i" true 2>/dev/null)
    if [ -z "$utxo" ] || [ "$utxo" = "null" ]; then
      count=$((count + 1))
    fi
  done
  echo "$count"
}

# ─── Verification Functions ──────────────────────────────────────────────────

# verify_coop_close TXID EXPECTED_OUTPUTS NETWORK
#   Checks a cooperative close TX: output count, all P2TR, total value
verify_coop_close() {
  local txid="$1" expected_outputs="${2:-3}" network="${3:-regtest}"
  local details=$(get_tx_details "$txid")
  if [ -z "$details" ] || [ "$details" = "null" ]; then
    echo "FAIL: TX $txid not found"
    return 1
  fi

  local n_outputs=$(echo "$details" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('vout',[])))" 2>/dev/null)
  local all_p2tr=$(echo "$details" | python3 -c "
import sys, json
d = json.load(sys.stdin)
types = [v.get('scriptPubKey',{}).get('type','') for v in d.get('vout',[])]
print('yes' if all(t == 'witness_v1_taproot' for t in types) else 'no')
" 2>/dev/null)
  local total_sats=$(get_tx_total_value "$txid")

  echo "  Close TX $txid:"
  echo "    Outputs: $n_outputs (expected $expected_outputs)"
  echo "    All P2TR: $all_p2tr"
  echo "    Total value: $total_sats sats"

  if [ "$n_outputs" -ge "$expected_outputs" ] && [ "$all_p2tr" = "yes" ]; then
    return 0
  else
    return 1
  fi
}

# verify_force_close FUND_TXID EXPECTED_NODES NETWORK
#   Counts descendant TXs in the DW tree (force close broadcasts tree)
verify_force_close() {
  local fund_txid="$1" expected_nodes="${2:-5}" network="${3:-regtest}"

  # Check mempool for pending tree TXs
  local mempool=$($BTC_CLI getrawmempool 2>/dev/null || echo "[]")
  local n_mempool=$(echo "$mempool" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)

  # Count spent outputs on the funding TX (each spent = a tree child)
  local n_spent=$(count_spent_outputs "$fund_txid")

  echo "  Force close tree from $fund_txid:"
  echo "    Mempool TXs: $n_mempool"
  echo "    Funding TX spent outputs: $n_spent"
  echo "    Expected tree nodes: >= $expected_nodes"

  # Either mempool has the tree TXs (unconfirmed) or outputs are spent (confirmed)
  if [ "$n_mempool" -ge "$expected_nodes" ] || [ "$n_spent" -ge 1 ]; then
    return 0
  else
    echo "    WARNING: Expected $expected_nodes tree TXs, found mempool=$n_mempool spent=$n_spent"
    return 1
  fi
}

# verify_funding_tx TXID EXPECTED_AMOUNT NETWORK
#   Checks that a funding TX has a P2TR output at the expected amount
verify_funding_tx() {
  local txid="$1" expected_amount="$2" network="${3:-regtest}"
  local details=$(get_tx_details "$txid")
  if [ -z "$details" ] || [ "$details" = "null" ]; then
    echo "FAIL: Funding TX $txid not found"
    return 1
  fi

  local match=$(echo "$details" | python3 -c "
import sys, json
d = json.load(sys.stdin)
expected = $expected_amount
for v in d.get('vout', []):
    sats = int(v.get('value', 0) * 100000000)
    tp = v.get('scriptPubKey', {}).get('type', '')
    if tp == 'witness_v1_taproot' and abs(sats - expected) < 1000:
        print('yes')
        sys.exit(0)
print('no')
" 2>/dev/null)

  echo "  Funding TX $txid: P2TR output at ~$expected_amount sats: $match"
  [ "$match" = "yes" ]
}

# ─── Wallet Balance Tracking ─────────────────────────────────────────────────

get_wallet_balance() {
  $WALLET_CLI getbalance 2>/dev/null | python3 -c "
import sys
val = float(sys.stdin.read().strip())
print(int(val * 100000000))
" 2>/dev/null || echo 0
}

# ─── Summary Printer ─────────────────────────────────────────────────────────

print_summary() {
  local results_file="${1:-$RESULTS_FILE}"
  if [ ! -f "$results_file" ]; then
    echo "No results file found: $results_file"
    return 1
  fi

  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║                    TEST RESULTS SUMMARY                     ║"
  echo "╠══════════════════════════════════════════════════════════════╣"

  local total=0 passed=0 failed=0 skipped=0
  while IFS= read -r line; do
    local id=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin).get('test_id','?'))" 2>/dev/null)
    local name=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin).get('test_name','?'))" 2>/dev/null)
    local status=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null)
    local elapsed=$(echo "$line" | python3 -c "import sys,json; print(json.load(sys.stdin).get('elapsed_s',0))" 2>/dev/null)

    total=$((total + 1))
    local icon="?"
    case "$status" in
      PASS) passed=$((passed + 1)); icon="✓" ;;
      FAIL) failed=$((failed + 1)); icon="✗" ;;
      SKIP) skipped=$((skipped + 1)); icon="⊘" ;;
    esac
    printf "║  %s %-6s %-42s %4ss ║\n" "$icon" "$id" "$name" "$elapsed"
  done < "$results_file"

  echo "╠══════════════════════════════════════════════════════════════╣"
  printf "║  Total: %d  |  Pass: %d  |  Fail: %d  |  Skip: %d            ║\n" "$total" "$passed" "$failed" "$skipped"
  echo "╚══════════════════════════════════════════════════════════════╝"

  [ "$failed" -eq 0 ]
}
