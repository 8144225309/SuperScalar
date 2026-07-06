#!/usr/bin/env bash
# test_regtest_bad_tree_verify.sh — gap-scan EFFICACY test: a client REFUSES a
# malicious/buggy LSP that ships an INVALID factory tree in FACTORY_READY.
#
# The HIGH gap-scan fix made the client call factory_verify_all on the tree it
# receives (client_apply_factory_ready) and REFUSE on failure.  SAFETY (valid trees
# are not refused) is proven by every green creation test; this proves EFFICACY:
# with SS_CHEAT_BAD_TREE_SIG the LSP corrupts one node's aggregate signature AFTER its
# own Phase-B verify, so it ships a genuinely bad tree that the honest path never
# emits -- the client MUST refuse (without the fix it would accept an unverifiable
# tree and later be unable to self-exit = frozen funds).
#
# PASS: LSP logs "SS_CHEAT_BAD_TREE_SIG: corrupted node" AND >=1 client logs
#       "REFUSING factory" / "tree failed signature verification".
set -uo pipefail
BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"; CLIENT_BIN="$BUILD_DIR/superscalar_client"
N_CLIENTS="${N_CLIENTS:-4}"; LSP_PORT=29983
FUNDING_SATS=100000
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "0000000000000000000000000000000000000000000000000000000000000004"
    "0000000000000000000000000000000000000000000000000000000000000005"
)
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
[ -f "$REGTEST_CONF" ] || REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"
TMPDIR=$(mktemp -d /tmp/ss-bad-tree.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"; LSP_LOG="$TMPDIR/lsp.log"
MINER_WALLET="ss_cheat_leaf_miner"; PIDS=(); MINE_PID=""
cleanup(){ [ -n "$MINE_PID" ] && kill -9 "$MINE_PID" 2>/dev/null||true; for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null||true; done; cp "$LSP_LOG" /tmp/bad_tree_lsp.log 2>/dev/null||true; for i in $(seq 0 $((N_CLIENTS-1))); do cp "$TMPDIR/client_${i}.log" "/tmp/bad_tree_client_${i}.log" 2>/dev/null||true; done; rm -rf "$TMPDIR"; }
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }; red(){ printf '\033[31m%s\033[0m\n' "$*"; }; fail(){ red "FAIL: $*"; exit 1; }
$BCLI -named createwallet wallet_name=$MINER_WALLET load_on_startup=false 2>/dev/null || $BCLI loadwallet $MINER_WALLET 2>/dev/null || true
MINE_ADDR=$($BCLI -rpcwallet=$MINER_WALLET -named getnewaddress address_type=bech32m); $BCLI generatetoaddress 101 "$MINE_ADDR" >/dev/null

echo "=== BAD-TREE efficacy drill (gap-scan): client must REFUSE an invalid factory tree ==="
SS_CHEAT_BAD_TREE_SIG=1 "$LSP_BIN" --network regtest --port $LSP_PORT --clients $N_CLIENTS --arity 3 \
    --amount $FUNDING_SATS --fee-rate 1000 --confirm-timeout 600 \
    --active-blocks 6 --dying-blocks 4 --step-blocks 1 --states-per-layer 2 \
    --seckey "$LSP_SECKEY" --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} \
    --wallet $MINER_WALLET --db "$LSP_DB" --demo --lsp-balance-pct 50 \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 60); do sleep 1; grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && break; kill -0 $LSP_PID 2>/dev/null || { tail -20 "$LSP_LOG"; fail "LSP exited before listening"; }; done
for i in $(seq 0 $((N_CLIENTS - 1))); do
    "$CLIENT_BIN" --network regtest --host 127.0.0.1 --port $LSP_PORT --seckey "${CLIENT_SECKEYS[$i]}" \
        --fee-rate 1000 --lsp-pubkey "$LSP_PUBKEY" --participant-id $((i + 1)) --daemon \
        --rpcuser ${RPCUSER:-rpcuser} --rpcpassword ${RPCPASSWORD:-rpcpass} --wallet $MINER_WALLET \
        --db "$TMPDIR/client_${i}.db" > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!); sleep 0.5
done
( while kill -0 $LSP_PID 2>/dev/null; do $BCLI generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1; sleep 2; done ) & MINE_PID=$!

echo "--- Waiting for a client to receive + REFUSE the corrupted FACTORY_READY (timeout 260s) ---"
REFUSED=0
for i in $(seq 1 130); do
    sleep 2
    if grep -rqiE "REFUSING factory|tree failed signature verification|tree aggregate signatures INVALID" "$TMPDIR"/client_*.log 2>/dev/null; then
        REFUSED=1; echo "  client refused after ~$((i*2))s"; break
    fi
done
kill -9 $MINE_PID 2>/dev/null || true; MINE_PID=""

echo "=== assertions ==="
grep -q "SS_CHEAT_BAD_TREE_SIG: corrupted node" "$LSP_LOG" || fail "LSP did not arm the bad-tree cheat (corruption not logged)"
green "  OK: LSP corrupted a tree node aggregate sig in FACTORY_READY"
[ "$REFUSED" = 1 ] || { echo "  --- client log tails ---"; for i in $(seq 0 $((N_CLIENTS-1))); do echo "  client $i:"; tail -6 "$TMPDIR/client_${i}.log" 2>/dev/null; done; fail "no client REFUSED the invalid tree -- the HIGH factory_verify_all fix did not fire"; }
NREF=$(grep -rliE "REFUSING factory|tree failed signature verification|tree aggregate signatures INVALID" "$TMPDIR"/client_*.log 2>/dev/null | wc -l)
green "  OK: $NREF/$N_CLIENTS clients REFUSED the invalid factory tree (client-side factory_verify_all fired)"
green "PASS: malicious-LSP bad tree -> client refuses (efficacy proven, not just safety)"
exit 0
