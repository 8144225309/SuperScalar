#!/bin/bash
set -e

BITCOIND=/home/pirq/bin/bitcoind
DATADIR=/tmp/claude-bip158-debug
RPCPORT=28445
P2PPORT=28446
RPCUSER=claudetest
RPCPASS=claudepass

rm -rf $DATADIR
mkdir -p $DATADIR
cat > $DATADIR/bitcoin.conf << 'EOF'
chain=regtest
blockfilterindex=1
peerblockfilters=1
fallbackfee=0.00001
[regtest]
rpcuser=claudetest
rpcpassword=claudepass
rpcport=28445
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
port=28446
bind=127.0.0.1
EOF

$BITCOIND -datadir=$DATADIR -daemon -pid=$DATADIR/bitcoind.pid
sleep 3

CLI="/home/pirq/bin/bitcoin-cli -rpcport=$RPCPORT -rpcuser=$RPCUSER -rpcpassword=$RPCPASS"

$CLI createwallet test_wallet 2>/dev/null || true
ADDR=$($CLI getnewaddress)
$CLI generatetoaddress 101 $ADDR > /dev/null

WATCH_ADDR=$($CLI getnewaddress)
echo "Watch addr: $WATCH_ADDR"

TXID=$($CLI sendtoaddress $WATCH_ADDR 0.001)
$CLI generatetoaddress 1 $ADDR > /dev/null
TIP=$($CLI getblockcount)
BLOCKHASH=$($CLI getblockhash $TIP)
echo "Block hash: $BLOCKHASH"
echo "Tip: $TIP"
echo "Fund txid: $TXID"

echo "--- getblockfilter output ---"
$CLI getblockfilter $BLOCKHASH basic

echo "--- Block outputs ---"
$CLI getblock $BLOCKHASH 2 | python3 -c "
import sys, json
d = json.load(sys.stdin)
for tx in d['tx']:
    txid = tx['txid']
    print('tx', txid[:16] + '...')
    for i, vout in enumerate(tx['vout']):
        spk = vout['scriptPubKey']['hex']
        print('  out[' + str(i) + ']:', spk)
"

echo "--- Funding tx inputs ---"
$CLI getrawtransaction $TXID true | python3 -c "
import sys, json
d = json.load(sys.stdin)
for i, vin in enumerate(d['vin']):
    if 'txid' in vin:
        print('in[' + str(i) + ']: prevout txid=' + vin['txid'] + ' vout=' + str(vin['vout']))
    else:
        print('in[' + str(i) + ']: coinbase')
"

kill $(cat $DATADIR/bitcoind.pid) 2>/dev/null || true
rm -rf $DATADIR
echo "DONE"
