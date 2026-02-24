#!/bin/bash
export PATH="$HOME/bitcoin-28.0/bin:$PATH"
echo "=== Wallet Balances ==="
for w in superscalar_lsp test_penalty test_dw test_factory test_ladder_life test_channels; do
    bal=$(bitcoin-cli -regtest -rpcwallet="$w" getbalance 2>&1)
    echo "$w: $bal"
done

echo ""
echo "=== Block height ==="
bitcoin-cli -regtest getblockcount

echo ""
echo "=== Try mining 1 block to superscalar_lsp ==="
addr=$(bitcoin-cli -regtest -rpcwallet=superscalar_lsp getnewaddress 2>&1)
echo "Address: $addr"
if [ -n "$addr" ]; then
    result=$(bitcoin-cli -regtest generatetoaddress 1 "$addr" 2>&1)
    echo "Mine result: $result"
fi

echo ""
echo "=== Updated balance ==="
bitcoin-cli -regtest -rpcwallet=superscalar_lsp getbalance 2>&1
