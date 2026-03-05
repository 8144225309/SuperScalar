#!/bin/bash
set -e
cd /root/SuperScalar/build

BTC="bitcoin-cli -regtest -rpcuser=rpcuser -rpcpassword=rpcpass -rpcport=18443"
WALLET="$BTC -rpcwallet=superscalar_launch"
LSP_PK=034263676bada0a92eda07ec64c7f4f08edac41e879ab122ae253e34fc882a9cd1
PORT=9738

cleanup() {
  echo ""
  echo "=== CLEANUP ==="
  # Close persistent FIFO writer (fd 3) if open
  exec 3>&- 2>/dev/null || true
  killall superscalar_lsp superscalar_client superscalar_watchtower 2>/dev/null || true
  kill $(jobs -p) 2>/dev/null || true
  rm -f /tmp/lsp_fifo
  sleep 2
}
trap cleanup EXIT

mine() {
  $WALLET -generate $1 >/dev/null 2>&1
}

wait_for_log() {
  local file=$1 pattern=$2 timeout=${3:-60}
  for i in $(seq 1 $timeout); do
    if grep -q "$pattern" "$file" 2>/dev/null; then return 0; fi
    sleep 1
  done
  echo "TIMEOUT waiting for: $pattern in $file"
  return 1
}

send_lsp() {
  echo "$1" >&3
  sleep 2
}

capture_lsp_output() {
  local before=$(wc -l < lsp.log)
  send_lsp "$1"
  sleep 2
  tail -n +$((before + 1)) lsp.log
}

start_factory() {
  local label=$1 amount=${2:-150000} extra_lsp_flags="${3:-}"
  local active_blocks=${4:-4320} dying_blocks=${5:-432}
  echo ""
  echo "=========================================="
  echo "  STARTING FACTORY: $label ($amount sats)"
  echo "=========================================="

  killall superscalar_lsp superscalar_client 2>/dev/null || true
  sleep 2
  rm -f lsp.db client0.db client1.db client2.db lsp.log client0.log client1.log client2.log
  rm -f /tmp/lsp_fifo
  mkfifo /tmp/lsp_fifo

  # Start LSP with FIFO for stdin (cli mode).
  # Use a persistent file descriptor (fd 3) held open for the lifetime of
  # the script.  The old "cat /tmp/lsp_fifo | ..." approach broke when each
  # "echo > /tmp/lsp_fifo" opened+closed the write end, causing cat to see
  # EOF and exit — killing the pipe to stdin.
  ./superscalar_lsp \
    --network regtest --port $PORT --clients 3 --amount $amount \
    --keyfile lsp.key --passphrase test --daemon --db lsp.db \
    --rpcuser rpcuser --rpcpassword rpcpass --rpcport 18443 \
    --wallet superscalar_launch --cli --confirm-timeout 60 \
    --active-blocks $active_blocks --dying-blocks $dying_blocks \
    $extra_lsp_flags \
    </tmp/lsp_fifo >lsp.log 2>&1 &
  LSP_PID=$!
  # Open persistent writer — keeps FIFO alive across multiple writes
  exec 3>/tmp/lsp_fifo
  sleep 2

  if ! kill -0 $LSP_PID 2>/dev/null; then
    echo "FAIL: LSP crashed on startup"
    cat lsp.log
    return 1
  fi

  # Start clients
  for i in 0 1 2; do
    ./superscalar_client \
      --network regtest --keyfile client${i}.key --passphrase test \
      --port $PORT --host 127.0.0.1 --daemon --db client${i}.db \
      --rpcuser rpcuser --rpcpassword rpcpass --rpcport 18443 \
      --lsp-pubkey $LSP_PK \
      >client${i}.log 2>&1 &
    sleep 1
  done

  # Mine blocks until factory is ready
  for i in $(seq 1 20); do
    mine 1
    sleep 2
    if grep -q "channels ready" lsp.log 2>/dev/null; then
      echo "OK: Factory ready after $i blocks"
      sleep 2
      return 0
    fi
  done
  echo "FAIL: Factory not ready after 20 blocks"
  cat lsp.log
  return 1
}

########################################
echo "============================================"
echo "  SUPERSCALAR REGTEST FULL TEST"
echo "  $(date)"
echo "============================================"

# Ensure wallet loaded
$BTC loadwallet superscalar_launch 2>/dev/null || true
mine 1

########################################
# TEST 1: Factory + Internal Payments
########################################
echo ""
echo "########## TEST 1: Factory + Internal Payments ##########"

start_factory "test1-payments"

echo ""
echo "--- Status before payments ---"
capture_lsp_output "status"

echo ""
echo "--- Payment: 0 -> 1, 5000 sats ---"
capture_lsp_output "pay 0 1 5000"

echo ""
echo "--- Payment: 1 -> 2, 3000 sats ---"
capture_lsp_output "pay 1 2 3000"

echo ""
echo "--- Payment: 2 -> 0, 1000 sats ---"
capture_lsp_output "pay 2 0 1000"

echo ""
echo "--- Payment: 0 -> 2, 2000 sats ---"
capture_lsp_output "pay 0 2 2000"

echo ""
echo "--- Payment: 1 -> 0, 1500 sats ---"
capture_lsp_output "pay 1 0 1500"

echo ""
echo "--- Status after payments ---"
capture_lsp_output "status"

# Close factory 1
echo ""
echo "--- Closing factory 1 ---"
capture_lsp_output "close"
sleep 3
mine 6
sleep 3

echo "--- Close result ---"
grep -iE "close|broadcast|txid|shut" lsp.log || echo "(no close messages)"

cleanup

########################################
# TEST 2: Crash Recovery
########################################
echo ""
echo "########## TEST 2: Crash Recovery ##########"

start_factory "test2-crash"

echo "--- Pre-crash payment: 0 -> 1, 5000 ---"
capture_lsp_output "pay 0 1 5000"

echo ""
echo "--- Killing client 1 ---"
kill -9 $(pgrep -f "client1.db") 2>/dev/null || echo "no client1 found"
sleep 3

echo "--- Restarting client 1 ---"
./superscalar_client \
  --network regtest --keyfile client1.key --passphrase test \
  --port $PORT --host 127.0.0.1 --daemon --db client1.db \
  --rpcuser rpcuser --rpcpassword rpcpass --rpcport 18443 \
  --lsp-pubkey $LSP_PK \
  >client1.log 2>&1 &
sleep 5

echo "--- Status after client 1 restart ---"
capture_lsp_output "status"

echo ""
echo "--- Payment after client crash: 0 -> 1, 1000 ---"
capture_lsp_output "pay 0 1 1000"

echo ""
echo "--- Killing LSP ---"
exec 3>&- 2>/dev/null || true  # close old FIFO writer
kill -9 $(pgrep -f "superscalar_lsp") 2>/dev/null || true
sleep 3

# Re-create FIFO for new LSP
rm -f /tmp/lsp_fifo
mkfifo /tmp/lsp_fifo

echo "--- Restarting LSP ---"
./superscalar_lsp \
  --network regtest --port $PORT --clients 3 --amount 150000 \
  --keyfile lsp.key --passphrase test --daemon --db lsp.db \
  --rpcuser rpcuser --rpcpassword rpcpass --rpcport 18443 \
  --wallet superscalar_launch --cli --confirm-timeout 60 \
  </tmp/lsp_fifo >lsp.log 2>&1 &
exec 3>/tmp/lsp_fifo  # re-open persistent writer
sleep 5

echo "--- LSP recovery log ---"
grep -iE "recovery|restore|found existing|channels ready|resume" lsp.log || echo "(no recovery messages)"

echo ""
echo "--- Status after LSP restart ---"
capture_lsp_output "status"

echo ""
echo "--- Payment after LSP crash: 1 -> 2, 1000 ---"
capture_lsp_output "pay 1 2 1000"

echo ""
echo "--- Closing test 2 ---"
capture_lsp_output "close"
sleep 3
mine 6
sleep 3
cleanup

########################################
# TEST 3: Watchtower (no-breach baseline)
########################################
echo ""
echo "########## TEST 3: Watchtower ##########"

start_factory "test3-watchtower"

echo "--- Starting watchtower ---"
./superscalar_watchtower \
  --db lsp.db \
  --network regtest \
  --poll-interval 5 \
  --rpcuser rpcuser \
  --rpcpassword rpcpass \
  --rpcport 18443 \
  >watchtower.log 2>&1 &

mine 3
sleep 15

echo "--- Watchtower log ---"
cat watchtower.log

kill $(pgrep -f "superscalar_watchtower") 2>/dev/null || true

echo ""
echo "--- Closing test 3 ---"
capture_lsp_output "close"
sleep 3
mine 6
sleep 3
cleanup

########################################
# TEST 4: Factory Rotation
########################################
echo ""
echo "########## TEST 4: Factory Rotation ##########"

# Use short active/dying blocks so factory reaches DYING state quickly
start_factory "test4-rotation" 150000 "" 10 5

echo "--- Payments before rotation ---"
capture_lsp_output "pay 0 1 5000"
capture_lsp_output "pay 1 2 3000"

echo ""
echo "--- Status before rotation ---"
capture_lsp_output "status"

# Mine blocks to push factory into DYING state (active_blocks=10)
echo ""
echo "--- Mining blocks to trigger DYING state ---"
for i in $(seq 1 12); do
  mine 1
  sleep 1
done
sleep 3

echo ""
echo "--- Sending rotate command ---"
capture_lsp_output "rotate"

# Mine blocks for rotation close + new factory fund
for i in $(seq 1 15); do
  mine 1
  sleep 2
done

echo ""
echo "--- Rotation log ---"
grep -iE "rotate|rotation|close|fund|new factory|factory creation" lsp.log || echo "(no rotation messages)"

echo ""
echo "--- Status after rotation ---"
capture_lsp_output "status"

echo ""
echo "--- Payment after rotation: 2 -> 0, 1000 ---"
capture_lsp_output "pay 2 0 1000"

echo ""
echo "--- Final close ---"
capture_lsp_output "close"
sleep 3
mine 6
sleep 3
cleanup

########################################
# TEST 5: BIP39 Key Recovery
########################################
echo ""
echo "########## TEST 5: BIP39 Key Recovery ##########"

start_factory "test5-bip39"

echo "--- Payment to establish balance ---"
capture_lsp_output "pay 0 2 5000"
echo "--- Status before key destruction ---"
capture_lsp_output "status"

echo ""
echo "--- Killing client 2, destroying key ---"
kill $(pgrep -f "client2.db") 2>/dev/null || true
sleep 2
mv client2.key client2.key.backup

echo "--- Recovering key from mnemonic ---"
# Read the mnemonic we generated earlier
CLIENT2_MNEMONIC=$(cat client2.mnemonic 2>/dev/null || echo "")
if [ -z "$CLIENT2_MNEMONIC" ]; then
  echo "SKIP: No mnemonic saved for client2 (client2.mnemonic not found)"
  echo "This test requires mnemonics to be saved during key generation."
  mv client2.key.backup client2.key
else
  ./superscalar_client \
    --from-mnemonic "$CLIENT2_MNEMONIC" \
    --keyfile client2.key \
    --passphrase test

  echo "--- Restarting client 2 with recovered key ---"
  ./superscalar_client \
    --network regtest --keyfile client2.key --passphrase test \
    --port $PORT --host 127.0.0.1 --daemon --db client2.db \
    --rpcuser rpcuser --rpcpassword rpcpass --rpcport 18443 \
    --lsp-pubkey $LSP_PK \
    >client2.log 2>&1 &
  sleep 5

  echo "--- Status after key recovery ---"
  capture_lsp_output "status"

  echo ""
  echo "--- Payment after recovery: 0 -> 2, 1000 ---"
  capture_lsp_output "pay 0 2 1000"
fi

echo ""
echo "--- Closing test 5 ---"
capture_lsp_output "close"
sleep 3
mine 6
sleep 3
cleanup

########################################
echo ""
echo "============================================"
echo "  ALL REGTEST TESTS COMPLETE"
echo "  $(date)"
echo "============================================"
echo ""
echo "Tests run:"
echo "  1. Factory + Internal Payments"
echo "  2. Crash Recovery (client + LSP)"
echo "  3. Watchtower (no-breach baseline)"
echo "  4. Factory Rotation"
echo "  5. BIP39 Key Recovery"
echo ""
echo "Not testable on regtest (no CLN):"
echo "  - CLN Bridge (inbound/outbound Lightning)"
echo "  - Breach Detection (--demo mode has DB bug)"
echo "  - CLTV Timeout Recovery (--demo dependency)"
