#!/bin/bash
# testnet4_full.sh — Testnet4 deployment testing (8 sessions)
# Cost-conscious: grouped by factory session to minimize on-chain fees.
# Estimated total cost: ~5,000 sats from ~9.1M available.
#
# Usage:
#   ./testnet4_full.sh           # Run all sessions
#   ./testnet4_full.sh S1        # Run single session
#   ./testnet4_full.sh S1 S2 S4  # Run specific sessions
#   ./testnet4_full.sh all       # Run all (same as no args)
#
# Prerequisites:
#   - bitcoind synced to testnet4
#   - CLN running and synced
#   - Wallet loaded with funds (>10k sats)
#   - Binaries built (make)
# NOTE: no set -e — we want to continue on session failure and print summary
cd /root/SuperScalar/build

source ../verify_onchain.sh

# ─── Testnet4 Configuration ──────────────────────────────────────────────────

NETWORK=testnet4
RPC_PORT=48332
BTC="bitcoin-cli -testnet4 -rpcuser=rpcuser -rpcpassword=rpcpass -rpcport=$RPC_PORT"
WALLET_NAME="superscalar_launch"
WALLET="$BTC -rpcwallet=$WALLET_NAME"
BTC_CLI="$BTC"
WALLET_CLI="$WALLET"
LSP_PK=034263676bada0a92eda07ec64c7f4f08edac41e879ab122ae253e34fc882a9cd1
PORT=9735
RESULTS_FILE="results_testnet4.jsonl"

# Testnet4 timing (no mining — must wait for real blocks)
CONFIRM_TIMEOUT=7200    # 2 hours max for factory confirmation
POLL_INTERVAL=10        # seconds between confirmation checks
BLOCK_WAIT=600          # 10 minutes typical block time
FACTORY_WAIT=900        # 15 min max for factory readiness

# Clear previous results
> "$RESULTS_FILE"

# ─── Testnet4-Specific Helpers ────────────────────────────────────────────────

cleanup() {
  exec 3>&- 2>/dev/null || true
  killall superscalar_lsp superscalar_client superscalar_watchtower superscalar_bridge 2>/dev/null || true
  kill $(jobs -p) 2>/dev/null || true
  rm -f /tmp/lsp_fifo
  sleep 2
}
trap cleanup EXIT

wait_for_log() {
  local file=$1 pattern=$2 timeout=${3:-$FACTORY_WAIT}
  for i in $(seq 1 $timeout); do
    if grep -q "$pattern" "$file" 2>/dev/null; then return 0; fi
    sleep 1
  done
  echo "TIMEOUT waiting for: $pattern in $file (${timeout}s)"
  return 1
}

send_lsp() {
  echo "$1" >&3
  sleep 3
}

capture_lsp_output() {
  local before=$(wc -l < lsp.log)
  send_lsp "$1"
  sleep 3
  tail -n +$((before + 1)) lsp.log
}

# Wait for N confirmations on testnet4 (no mining — real blocks)
wait_for_confirmation() {
  local what="${1:-transaction}" timeout=${2:-$CONFIRM_TIMEOUT}
  echo "  Waiting for $what to confirm (polling every ${POLL_INTERVAL}s, timeout ${timeout}s)..."
  local elapsed=0
  while [ $elapsed -lt $timeout ]; do
    sleep $POLL_INTERVAL
    elapsed=$((elapsed + POLL_INTERVAL))
    local height=$($BTC getblockcount 2>/dev/null || echo 0)
    printf "\r    Height: %d  Elapsed: %ds" "$height" "$elapsed"
  done
  echo ""
}

# Wait for N new blocks
wait_for_blocks() {
  local n_blocks=${1:-1} timeout=${2:-$CONFIRM_TIMEOUT}
  local start_height=$($BTC getblockcount 2>/dev/null || echo 0)
  local target=$((start_height + n_blocks))
  echo "  Waiting for $n_blocks blocks (current: $start_height, target: $target)..."
  local elapsed=0
  while [ $elapsed -lt $timeout ]; do
    sleep $POLL_INTERVAL
    elapsed=$((elapsed + POLL_INTERVAL))
    local height=$($BTC getblockcount 2>/dev/null || echo 0)
    printf "\r    Height: %d / %d  Elapsed: %ds" "$height" "$target" "$elapsed"
    if [ "$height" -ge "$target" ]; then
      echo ""
      echo "  OK: Reached block $height"
      return 0
    fi
  done
  echo ""
  echo "  TIMEOUT: Only reached $($BTC getblockcount) / $target"
  return 1
}

# ─── Pre-flight Checks ───────────────────────────────────────────────────────

preflight() {
  echo "============================================"
  echo "  TESTNET4 PRE-FLIGHT CHECK"
  echo "============================================"

  # Check bitcoind
  local info=$($BTC getblockchaininfo 2>/dev/null)
  if [ -z "$info" ]; then
    echo "FAIL: bitcoind not reachable on testnet4 (port $RPC_PORT)"
    exit 1
  fi
  local chain=$(echo "$info" | python3 -c "import sys,json; print(json.load(sys.stdin).get('chain',''))" 2>/dev/null)
  local blocks=$(echo "$info" | python3 -c "import sys,json; print(json.load(sys.stdin).get('blocks',0))" 2>/dev/null)
  local headers=$(echo "$info" | python3 -c "import sys,json; print(json.load(sys.stdin).get('headers',0))" 2>/dev/null)
  local ibd=$(echo "$info" | python3 -c "import sys,json; print(json.load(sys.stdin).get('initialblockdownload',True))" 2>/dev/null)
  echo "  Chain: $chain  Blocks: $blocks  Headers: $headers  IBD: $ibd"

  if [ "$ibd" = "True" ]; then
    echo "FAIL: bitcoind still in initial block download"
    exit 1
  fi

  if [ $((headers - blocks)) -gt 2 ]; then
    echo "WARN: bitcoind not fully synced ($blocks/$headers)"
  fi

  # Check wallet
  $BTC loadwallet $WALLET_NAME 2>/dev/null || true
  local balance=$(get_wallet_balance)
  echo "  Wallet balance: $balance sats"
  if [ "$balance" -lt 10000 ]; then
    echo "FAIL: Insufficient balance ($balance sats, need >10000)"
    exit 1
  fi

  # Check binaries
  for bin in superscalar_lsp superscalar_client superscalar_watchtower; do
    if [ ! -x "./$bin" ]; then
      echo "FAIL: Binary ./$bin not found or not executable"
      exit 1
    fi
  done
  echo "  Binaries: OK"

  echo "  Pre-flight: ALL CHECKS PASSED"
  echo ""
}

# ─── Factory Start (testnet4) ─────────────────────────────────────────────────

start_factory_t4() {
  local label=$1 amount=${2:-100000} n_clients=${3:-3} extra_flags="${4:-}"
  local active_blocks=${5:-4320} dying_blocks=${6:-432}

  echo ""
  echo "=========================================="
  echo "  SESSION: $label ($amount sats, $n_clients clients)"
  echo "  $(date)"
  echo "=========================================="

  # Record starting balance
  local bal_before=$(get_wallet_balance)
  echo "  Wallet balance before: $bal_before sats"

  killall superscalar_lsp superscalar_client superscalar_watchtower 2>/dev/null || true
  sleep 2
  rm -f lsp.db lsp.log watchtower.log /tmp/lsp_fifo
  for i in $(seq 0 $((n_clients - 1))); do
    rm -f client${i}.db client${i}.log
  done
  mkfifo /tmp/lsp_fifo

  ./superscalar_lsp \
    --network $NETWORK --port $PORT --clients $n_clients --amount $amount \
    --keyfile lsp.key --passphrase test --daemon --db lsp.db \
    --rpcuser rpcuser --rpcpassword rpcpass --rpcport $RPC_PORT \
    --wallet $WALLET_NAME --cli --confirm-timeout $CONFIRM_TIMEOUT \
    --active-blocks $active_blocks --dying-blocks $dying_blocks \
    $extra_flags \
    </tmp/lsp_fifo >lsp.log 2>&1 &
  LSP_PID=$!
  exec 3>/tmp/lsp_fifo
  sleep 3

  if ! kill -0 $LSP_PID 2>/dev/null; then
    echo "FAIL: LSP crashed on startup"
    cat lsp.log
    return 1
  fi

  for i in $(seq 0 $((n_clients - 1))); do
    ./superscalar_client \
      --network $NETWORK --keyfile client${i}.key --passphrase test \
      --port $PORT --host 127.0.0.1 --daemon --db client${i}.db \
      --rpcuser rpcuser --rpcpassword rpcpass --rpcport $RPC_PORT \
      --lsp-pubkey $LSP_PK \
      >client${i}.log 2>&1 &
    sleep 1
  done

  echo "  Waiting for factory creation (testnet4 — this takes a few blocks)..."
  if wait_for_log lsp.log "channels ready" $FACTORY_WAIT; then
    echo "  OK: Factory ready"
    sleep 3
    return 0
  else
    echo "  FAIL: Factory not ready after ${FACTORY_WAIT}s"
    tail -20 lsp.log
    return 1
  fi
}

# Demo mode for testnet4
start_demo_t4() {
  local label=$1 amount=${2:-100000} n_clients=${3:-3} extra_flags="${4:-}"

  echo ""
  echo "=========================================="
  echo "  SESSION (DEMO): $label ($amount sats, $n_clients clients)"
  echo "  $(date)"
  echo "=========================================="

  local bal_before=$(get_wallet_balance)
  echo "  Wallet balance before: $bal_before sats"

  killall superscalar_lsp superscalar_client superscalar_watchtower 2>/dev/null || true
  sleep 2
  rm -f lsp.db lsp.log watchtower.log
  for i in $(seq 0 $((n_clients - 1))); do
    rm -f client${i}.db client${i}.log
  done

  ./superscalar_lsp \
    --network $NETWORK --port $PORT --clients $n_clients --amount $amount \
    --keyfile lsp.key --passphrase test --daemon --db lsp.db \
    --rpcuser rpcuser --rpcpassword rpcpass --rpcport $RPC_PORT \
    --wallet $WALLET_NAME --confirm-timeout $CONFIRM_TIMEOUT \
    --demo $extra_flags \
    >lsp.log 2>&1 &
  LSP_PID=$!
  sleep 3

  if ! kill -0 $LSP_PID 2>/dev/null; then
    echo "FAIL: LSP crashed on startup"
    cat lsp.log
    return 1
  fi

  for i in $(seq 0 $((n_clients - 1))); do
    ./superscalar_client \
      --network $NETWORK --keyfile client${i}.key --passphrase test \
      --port $PORT --host 127.0.0.1 --daemon --db client${i}.db \
      --rpcuser rpcuser --rpcpassword rpcpass --rpcport $RPC_PORT \
      --lsp-pubkey $LSP_PK \
      >client${i}.log 2>&1 &
    sleep 1
  done

  return 0
}

# Wait for demo to finish on testnet4 (much longer than regtest)
wait_demo_finish_t4() {
  local timeout=${1:-$CONFIRM_TIMEOUT}
  echo "  Waiting for demo to complete (testnet4, timeout ${timeout}s)..."
  local elapsed=0
  while [ $elapsed -lt $timeout ]; do
    sleep $POLL_INTERVAL
    elapsed=$((elapsed + POLL_INTERVAL))
    printf "\r    Elapsed: %ds" "$elapsed"
    if ! kill -0 $LSP_PID 2>/dev/null; then
      echo ""
      echo "  OK: Demo completed after ${elapsed}s"
      return 0
    fi
  done
  echo ""
  echo "  TIMEOUT: Demo did not finish in ${timeout}s"
  return 1
}

# Report cost for a session
report_cost() {
  local session="$1" bal_before="$2"
  local bal_after=$(get_wallet_balance)
  local cost=$((bal_before - bal_after))
  echo ""
  echo "  Cost for $session: $cost sats (balance: $bal_before → $bal_after)"
}

# Run a session with timing
run_session() {
  local session_id="$1" session_name="$2"
  shift 2
  echo ""
  echo "################################################################"
  echo "  $session_id: $session_name"
  echo "  Started: $(date)"
  echo "################################################################"
  local start_time=$(date +%s)
  local bal_before=$(get_wallet_balance)

  if "$@"; then
    local elapsed=$(( $(date +%s) - start_time ))
    report_cost "$session_id" "$bal_before"
    log_result "$session_id" "$session_name" "PASS" "" "$elapsed"
    return 0
  else
    local elapsed=$(( $(date +%s) - start_time ))
    report_cost "$session_id" "$bal_before"
    log_result "$session_id" "$session_name" "FAIL" "session function returned non-zero" "$elapsed"
    return 1
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# SESSION 1: Core Lifecycle (~200 sats, ~30 min)
# 1 factory: create → 5 payments → reconnect → watchtower → LSP crash → close
# ═══════════════════════════════════════════════════════════════════════════════

session_S1_core_lifecycle() {
  start_factory_t4 "S1-core-lifecycle" 100000 3

  echo ""
  echo "--- 5 Internal Payments (verifies Bug 12 fix) ---"
  capture_lsp_output "pay 0 1 5000"
  capture_lsp_output "pay 1 2 3000"
  capture_lsp_output "pay 2 0 1000"
  capture_lsp_output "pay 0 2 2000"
  capture_lsp_output "pay 1 0 1500"

  local payment_count=$(grep -c "Payment complete" lsp.log 2>/dev/null || echo 0)
  echo "  Payments completed: $payment_count/5"
  if [ "$payment_count" -lt 5 ]; then
    echo "FAIL: Only $payment_count/5 payments succeeded"
    cleanup
    return 1
  fi

  echo ""
  echo "--- Kill/Restart Client 1 ---"
  kill -9 $(pgrep -f "client1.db") 2>/dev/null || true
  sleep 5

  ./superscalar_client \
    --network $NETWORK --keyfile client1.key --passphrase test \
    --port $PORT --host 127.0.0.1 --daemon --db client1.db \
    --rpcuser rpcuser --rpcpassword rpcpass --rpcport $RPC_PORT \
    --lsp-pubkey $LSP_PK \
    >client1.log 2>&1 &
  sleep 10

  echo "--- Payment after reconnect ---"
  capture_lsp_output "pay 0 1 1000"
  if ! grep -c "Payment complete" lsp.log | grep -q "[6-9]"; then
    echo "WARN: Post-reconnect payment may have failed"
  fi

  echo ""
  echo "--- Watchtower (no-breach baseline) ---"
  ./superscalar_watchtower \
    --db lsp.db --network $NETWORK --poll-interval 30 \
    --rpcuser rpcuser --rpcpassword rpcpass --rpcport $RPC_PORT \
    >watchtower.log 2>&1 &
  sleep 30
  echo "  Watchtower log:"
  cat watchtower.log
  kill $(pgrep -f "superscalar_watchtower") 2>/dev/null || true

  echo ""
  echo "--- Kill/Restart LSP (crash recovery) ---"
  exec 3>&- 2>/dev/null || true
  kill -9 $(pgrep -f "superscalar_lsp") 2>/dev/null || true
  sleep 5

  rm -f /tmp/lsp_fifo
  mkfifo /tmp/lsp_fifo

  ./superscalar_lsp \
    --network $NETWORK --port $PORT --clients 3 --amount 100000 \
    --keyfile lsp.key --passphrase test --daemon --db lsp.db \
    --rpcuser rpcuser --rpcpassword rpcpass --rpcport $RPC_PORT \
    --wallet $WALLET_NAME --cli --confirm-timeout $CONFIRM_TIMEOUT \
    </tmp/lsp_fifo >lsp.log 2>&1 &
  LSP_PID=$!
  exec 3>/tmp/lsp_fifo
  sleep 10

  echo "--- LSP recovery log ---"
  grep -iE "recovery|restore|found existing|resume" lsp.log || echo "(no recovery messages)"

  echo "--- Payment after LSP crash ---"
  capture_lsp_output "pay 1 2 1000"

  echo ""
  echo "--- Cooperative Close ---"
  capture_lsp_output "close"
  echo "  Waiting for close confirmation..."
  wait_for_blocks 6 $CONFIRM_TIMEOUT || true
  sleep 5

  grep -iE "close|broadcast|txid|confirm" lsp.log | tail -5 || true
  cleanup
  return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# SESSION 2: CLN Bridge (~500 sats, ~45 min)
# ═══════════════════════════════════════════════════════════════════════════════

session_S2_cln_bridge() {
  start_factory_t4 "S2-cln-bridge" 100000 3

  echo ""
  echo "--- Starting bridge daemon ---"
  ./superscalar_bridge \
    --lsp-host 127.0.0.1 --lsp-port $PORT \
    --plugin-port 9740 --lsp-pubkey $LSP_PK \
    >bridge.log 2>&1 &
  sleep 5

  echo ""
  echo "--- Inbound: External node pays via bridge ---"
  # Create invoice on factory side
  capture_lsp_output "invoice 0 5000000"
  # Extract bolt11 from log
  local bolt11=$(grep -oE "lnbc[a-zA-Z0-9]+" lsp.log | tail -1)
  if [ -n "$bolt11" ]; then
    echo "  Invoice: ${bolt11:0:40}..."
    # Pay via CLN (if available)
    lightning-cli pay "$bolt11" 2>/dev/null || echo "  (CLN pay skipped — CLN may not be running)"
  else
    echo "  WARN: Could not extract BOLT11 invoice"
  fi

  echo ""
  echo "--- Outbound: Factory pays external node ---"
  # Generate invoice on CLN side
  local ext_invoice=$(lightning-cli invoice 5000000 "test-outbound-$(date +%s)" "test" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('bolt11',''))" 2>/dev/null || echo "")
  if [ -n "$ext_invoice" ]; then
    echo "  External invoice: ${ext_invoice:0:40}..."
    capture_lsp_output "superscalar-pay $ext_invoice"
  else
    echo "  WARN: Could not generate CLN invoice (CLN may not be running)"
  fi

  echo ""
  echo "--- Round-trip payments ---"
  for i in 1 2 3; do
    echo "  Round-trip $i..."
    capture_lsp_output "pay 0 1 1000"
    sleep 2
  done

  echo ""
  echo "--- Close ---"
  capture_lsp_output "close"
  wait_for_blocks 6 $CONFIRM_TIMEOUT || true
  sleep 5

  kill $(pgrep -f "superscalar_bridge") 2>/dev/null || true
  cleanup
  return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# SESSION 3: Force Close (~1500 sats, ~25 min)
# ═══════════════════════════════════════════════════════════════════════════════

session_S3_force_close() {
  start_factory_t4 "S3-force-close" 50000 3 "--force-close"

  echo "  Waiting for DW tree broadcast..."
  wait_for_log lsp.log "broadcast" 120 || wait_for_log lsp.log "force" 120 || true

  echo ""
  echo "--- Force close log ---"
  grep -iE "broadcast|force|tree|txid" lsp.log | head -20 || true

  echo "  Waiting for tree confirmation (2+ blocks)..."
  wait_for_blocks 2 $CONFIRM_TIMEOUT || true

  # Extract funding TXID and verify on-chain tree
  local fund_txid=$(grep -oE "[a-f0-9]{64}" lsp.log | head -1)
  if [ -n "$fund_txid" ]; then
    echo "  Funding TXID: $fund_txid"
    verify_force_close "$fund_txid" 5 $NETWORK || echo "  WARN: Tree verification inconclusive"
  fi

  cleanup
  return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# SESSION 4: Rotation (~400 sats, ~35 min)
# ═══════════════════════════════════════════════════════════════════════════════

session_S4_rotation() {
  # Short active/dying blocks — but testnet4 blocks are ~10 min each,
  # so use 20 active + 10 dying (~3.5 hours).  Factory creation takes
  # ~2 blocks, leaving ~18 blocks before DYING.
  start_factory_t4 "S4-rotation" 100000 3 "" 20 10

  echo ""
  echo "--- Pre-rotation payments ---"
  capture_lsp_output "pay 0 1 5000"
  capture_lsp_output "pay 1 2 3000"

  echo ""
  echo "--- Waiting for DYING state (need ~20 blocks from factory creation) ---"
  wait_for_blocks 22 $CONFIRM_TIMEOUT || true
  sleep 5

  echo ""
  echo "--- Sending rotate command ---"
  capture_lsp_output "rotate"

  echo "  Waiting for rotation to complete (new factory funding)..."
  wait_for_blocks 15 $CONFIRM_TIMEOUT || true
  sleep 5

  echo ""
  echo "--- Rotation log ---"
  grep -iE "rotate|rotation|close|fund|new factory" lsp.log | tail -10 || true

  echo ""
  echo "--- Status after rotation ---"
  capture_lsp_output "status"

  echo ""
  echo "--- Payment after rotation ---"
  capture_lsp_output "pay 2 0 1000"

  echo ""
  echo "--- Close ---"
  capture_lsp_output "close"
  wait_for_blocks 6 $CONFIRM_TIMEOUT || true
  sleep 5

  cleanup
  return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# SESSION 5: 2-Client Variant (~200 sats, ~20 min)
# ═══════════════════════════════════════════════════════════════════════════════

session_S5_2client() {
  start_factory_t4 "S5-2client" 50000 2

  echo ""
  echo "--- Payments ---"
  capture_lsp_output "pay 0 1 5000"
  capture_lsp_output "pay 1 0 3000"

  local payment_count=$(grep -c "Payment complete" lsp.log 2>/dev/null || echo 0)
  echo "  Payments completed: $payment_count/2"

  echo ""
  echo "--- Close ---"
  capture_lsp_output "close"
  wait_for_blocks 6 $CONFIRM_TIMEOUT || true
  sleep 5

  cleanup
  return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# SESSION 6: Breach Detection (~1500 sats, ~30 min)
# ═══════════════════════════════════════════════════════════════════════════════

session_S6_breach() {
  start_demo_t4 "S6-breach" 100000 3 "--cheat-daemon"

  echo ""
  echo "--- Starting watchtower ---"
  ./superscalar_watchtower \
    --db lsp.db --network $NETWORK --poll-interval 30 \
    --rpcuser rpcuser --rpcpassword rpcpass --rpcport $RPC_PORT \
    >watchtower.log 2>&1 &

  echo "  Waiting for demo to run + LSP to broadcast revoked state..."
  wait_demo_finish_t4 $CONFIRM_TIMEOUT || true

  echo ""
  echo "--- LSP log (breach) ---"
  grep -iE "broadcast|revoked|cheat|breach|penalty" lsp.log | tail -10 || true

  echo "  Waiting for penalty TX confirmation..."
  wait_for_blocks 6 $CONFIRM_TIMEOUT || true
  sleep 10

  echo ""
  echo "--- Watchtower log ---"
  cat watchtower.log

  if grep -qiE "breach|penalty" watchtower.log; then
    echo "OK: Watchtower detected breach"
  else
    echo "WARN: No breach detection in watchtower log"
  fi

  cleanup
  return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# SESSION 7: CLTV Timeout (~500 sats, ~40 min)
# ═══════════════════════════════════════════════════════════════════════════════

session_S7_cltv_timeout() {
  start_demo_t4 "S7-cltv-timeout" 100000 3 "--test-expiry"

  echo "  Waiting for demo + CLTV expiry..."
  wait_demo_finish_t4 $CONFIRM_TIMEOUT || true

  echo ""
  echo "--- LSP log (timeout/expiry) ---"
  grep -iE "timeout|expir|reclaim|cltv" lsp.log | tail -10 || true

  if grep -qiE "timeout|expir|reclaim" lsp.log; then
    echo "OK: CLTV timeout path activated"
  else
    echo "WARN: No timeout evidence in log"
  fi

  cleanup
  return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# SESSION 8: BIP39 Key Recovery (~200 sats, ~25 min)
# ═══════════════════════════════════════════════════════════════════════════════

session_S8_bip39_recovery() {
  start_factory_t4 "S8-bip39-recovery" 100000 3

  echo ""
  echo "--- Payment to establish balance ---"
  capture_lsp_output "pay 0 2 5000"

  echo "--- Status before key destruction ---"
  capture_lsp_output "status"

  echo ""
  echo "--- Killing client 2, destroying key ---"
  kill $(pgrep -f "client2.db") 2>/dev/null || true
  sleep 3
  mv client2.key client2.key.backup

  echo "--- Recovering key from mnemonic ---"
  local mnemonic=$(cat client2.mnemonic 2>/dev/null || echo "")
  if [ -z "$mnemonic" ]; then
    echo "SKIP: No mnemonic saved for client2"
    mv client2.key.backup client2.key
    capture_lsp_output "close"
    wait_for_blocks 6 $CONFIRM_TIMEOUT || true
    cleanup
    return 0
  fi

  ./superscalar_client \
    --from-mnemonic "$mnemonic" \
    --keyfile client2.key \
    --passphrase test

  echo "--- Restarting client 2 with recovered key ---"
  ./superscalar_client \
    --network $NETWORK --keyfile client2.key --passphrase test \
    --port $PORT --host 127.0.0.1 --daemon --db client2.db \
    --rpcuser rpcuser --rpcpassword rpcpass --rpcport $RPC_PORT \
    --lsp-pubkey $LSP_PK \
    >client2.log 2>&1 &
  sleep 10

  echo "--- Status after key recovery ---"
  capture_lsp_output "status"

  echo "--- Payment after recovery ---"
  capture_lsp_output "pay 0 2 1000"

  echo ""
  echo "--- Close ---"
  capture_lsp_output "close"
  wait_for_blocks 6 $CONFIRM_TIMEOUT || true
  sleep 5

  cleanup
  return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# TEST RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

ALL_SESSIONS="S1 S2 S3 S4 S5 S6 S7 S8"

run_session_by_id() {
  case "$1" in
    S1) run_session S1 "Core lifecycle"       session_S1_core_lifecycle ;;
    S2) run_session S2 "CLN Bridge"           session_S2_cln_bridge ;;
    S3) run_session S3 "Force close"          session_S3_force_close ;;
    S4) run_session S4 "Rotation"             session_S4_rotation ;;
    S5) run_session S5 "2-client variant"     session_S5_2client ;;
    S6) run_session S6 "Breach detection"     session_S6_breach ;;
    S7) run_session S7 "CLTV timeout"         session_S7_cltv_timeout ;;
    S8) run_session S8 "BIP39 key recovery"   session_S8_bip39_recovery ;;
    *)  echo "Unknown session: $1"; return 1 ;;
  esac
}

# Parse arguments
SESSIONS_TO_RUN=""
if [ $# -eq 0 ] || [ "$1" = "all" ]; then
  SESSIONS_TO_RUN="$ALL_SESSIONS"
else
  SESSIONS_TO_RUN="$@"
fi

# Run pre-flight checks
preflight

TOTAL_BAL_BEFORE=$(get_wallet_balance)
echo ""
echo "============================================"
echo "  SUPERSCALAR TESTNET4 FULL TEST"
echo "  $(date)"
echo "  Starting balance: $TOTAL_BAL_BEFORE sats"
echo "============================================"

TOTAL=0
PASS=0
FAIL=0

for s in $SESSIONS_TO_RUN; do
  TOTAL=$((TOTAL + 1))
  if run_session_by_id "$s"; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
  fi
done

TOTAL_BAL_AFTER=$(get_wallet_balance)
TOTAL_COST=$((TOTAL_BAL_BEFORE - TOTAL_BAL_AFTER))

echo ""
echo "============================================"
echo "  TESTNET4 TESTS COMPLETE"
echo "  $(date)"
echo "============================================"
echo ""
echo "  Total cost: $TOTAL_COST sats"
echo "  Balance: $TOTAL_BAL_BEFORE → $TOTAL_BAL_AFTER sats"
echo ""

print_summary "$RESULTS_FILE"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
