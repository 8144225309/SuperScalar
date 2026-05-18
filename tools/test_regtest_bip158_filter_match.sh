#!/usr/bin/env bash
# test_regtest_bip158_filter_match.sh — BIP-158 filter match for a
# factory-relevant SPK (#216, GH #264).
#
# 1. Spin up isolated regtest bitcoind with -blockfilterindex=1
#    -peerblockfilters=1.
# 2. Mine 110 maturity blocks.
# 3. Generate a fresh bech32m (P2TR) "factory funding" address — the SPK
#    pattern matches what a SuperScalar factory_init output produces (32-byte
#    x-only key wrapped in OP_1 OP_PUSH32).
# 4. Send funds to the address (mimicking factory funding TX).
# 5. Mine 1 block to confirm.
# 6. Drive the light-client via test_bip158_e2e_helper --mode match — must
#    report >= 1 filter hit and downloaded block.
#
# Exit 0 = PASS, non-zero = FAIL.

set -euo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build-release}"
HELPER="$BUILD_DIR/test_bip158_e2e_helper"

TAG="bip158_match"
DATADIR="${DATADIR:-/tmp/ss_rt_${TAG}_bitcoind}"
RPCPORT="${RPCPORT:-29503}"
P2PPORT="${P2PPORT:-29504}"
RPCUSER="bip158test"
RPCPASS="bip158pass"
WALLET="bip158_match_wallet"
LOG="/tmp/ss_rt_${TAG}.log"

pkill -9 -f "bitcoind.*-datadir=$DATADIR" 2>/dev/null || true
pkill -9 -f "test_bip158_e2e_helper.*--rpcport $RPCPORT" 2>/dev/null || true
rm -rf "$DATADIR" "$LOG"
mkdir -p "$DATADIR"

cleanup() {
    local rc=$?
    pkill -9 -f "bitcoind.*-datadir=$DATADIR" 2>/dev/null || true
    pkill -9 -f "test_bip158_e2e_helper.*--rpcport $RPCPORT" 2>/dev/null || true
    rm -rf "$DATADIR"
    return $rc
}
trap cleanup EXIT INT TERM

cat > "$DATADIR/bitcoin.conf" << EOF
regtest=1
blockfilterindex=1
peerblockfilters=1
fallbackfee=0.00001
txindex=1
server=1
listen=1
discover=0
[regtest]
rpcuser=$RPCUSER
rpcpassword=$RPCPASS
rpcport=$RPCPORT
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
port=$P2PPORT
bind=127.0.0.1:$P2PPORT
EOF

echo "=== BIP-158 filter-match test (#216, GH #264) ==="
echo "  datadir=$DATADIR  rpcport=$RPCPORT  p2p=$P2PPORT"

bitcoind -datadir="$DATADIR" -daemon -pid="$DATADIR/bitcoind.pid" 2>&1 | tee -a "$LOG" >/dev/null
sleep 1

BCLI="bitcoin-cli -regtest -datadir=$DATADIR -rpcuser=$RPCUSER -rpcpassword=$RPCPASS -rpcport=$RPCPORT"
for i in $(seq 1 30); do
    $BCLI getblockchaininfo >/dev/null 2>&1 && break
    sleep 1
done
$BCLI getblockchaininfo >/dev/null 2>&1 || { echo "FAIL: bitcoind never came up"; exit 1; }

$BCLI createwallet "$WALLET" >/dev/null 2>&1 || $BCLI loadwallet "$WALLET" >/dev/null 2>&1 || true

MINE_ADDR=$($BCLI -rpcwallet="$WALLET" getnewaddress "" bech32m)
echo "  Mining 110 blocks for maturity..."
$BCLI -rpcwallet="$WALLET" generatetoaddress 110 "$MINE_ADDR" >/dev/null

# Generate a "factory funding" P2TR address — SPK is 0x51 0x20 || xonly_pk.
# SuperScalar factory_init produces exactly this script-pubkey shape.
FUND_ADDR=$($BCLI -rpcwallet="$WALLET" getnewaddress "factory_funding" bech32m)
FUND_SPK=$($BCLI -rpcwallet="$WALLET" getaddressinfo "$FUND_ADDR" \
            | python3 -c 'import json,sys; print(json.load(sys.stdin)["scriptPubKey"])')
echo "  factory funding addr: $FUND_ADDR"
echo "  factory funding SPK : $FUND_SPK"

# Send funds (mimic factory funding TX) and confirm.
TXID=$($BCLI -rpcwallet="$WALLET" sendtoaddress "$FUND_ADDR" 0.005)
echo "  funding txid: $TXID"
TIP_BEFORE=$($BCLI getblockcount)
$BCLI -rpcwallet="$WALLET" generatetoaddress 1 "$MINE_ADDR" >/dev/null
TIP=$($BCLI getblockcount)
BLOCKHASH=$($BCLI getblockhash "$TIP")
echo "  funding confirmed at height $TIP (block $BLOCKHASH)"

# Run the helper in match mode against the funding SPK. The helper must:
#   1. sync filter headers up to tip
#   2. fetch the cfilter for the funding block
#   3. find that the filter matches our SPK
#   4. download the full block + cache the funding tx
echo ""
echo "--- match mode: verify SPK appears in filter stream ---"
echo "  NOTE: using --no-p2p (RPC fallback) due to known bug in P2P sync_headers"
echo "        (see test_bip158_e2e_helper.c::seed_near_tip_header for details)."
set +e
"$HELPER" \
    --mode match \
    --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" \
    --rpcport "$RPCPORT" --p2p-port "$P2PPORT" \
    --datadir "$DATADIR" \
    --watch-spk "$FUND_SPK" \
    --expected-tip "$TIP" --timeout-sec 60 --no-p2p 2>&1 | tee -a "$LOG"
RC=${PIPESTATUS[0]}
set -e

if [ "$RC" -eq 0 ]; then
    if grep -q "total_matches=[1-9]" "$LOG"; then
        echo ""
        echo "=== PASS: BIP-158 filter detected factory-funding SPK ==="
        exit 0
    else
        echo "=== FAIL: helper exited 0 but reported 0 matches (unexpected) ==="
        tail -30 "$LOG"
        exit 1
    fi
else
    echo "=== FAIL: helper exit=$RC (factory SPK not detected in filter stream) ==="
    tail -40 "$LOG"
    exit 1
fi
