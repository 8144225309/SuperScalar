# shape-3e-N4-ARITY3-K2 V2 - Commands

Proves: Force-close traversal of k2 shape: root + 2 sub-factory chain[0] + 4 client sweeps + 2 sales-stock sweeps. All TXs at 1 sat/vB.

Fee ceiling: **1 sat/vB** (FEE_RATE=1000 sat/kvB). Every TX in this run obeys.


## Pre-flight
```
ssh root@68.168.216.243 'free -h | head -2; bitcoin-cli -datadir=/var/lib/bitcoind-testnet4 -rpcuser=testnet4rpc -rpcpassword=testnet4rpcpass123 -rpcport=48332 -rpcwallet=ss_pool_6 getbalance'
```

## Sync repo on VPS
```
ssh root@68.168.216.243 'cd /root/SuperScalar-phase5 && git fetch origin feat-testnet4-phase5-scaffold && git reset --hard origin/feat-testnet4-phase5-scaffold'
```

## Launch
```
ssh root@68.168.216.243 'systemd-run --unit=ss-t4-phase5-3e-V2.service \
  --setenv WALLET=ss_pool_6 --setenv TAG=phase5_3e_V2 --setenv VARIANT=V2 \
  bash /root/SuperScalar-phase5/docs/testnet4-phase5/shape-3e-N4-ARITY3-K2/runner.sh'
```
Variant V2 -> `--demo --force-close`. Port 9950.

## Monitor
```
ssh root@68.168.216.243 'tail -f /tmp/ss_t4_phase5_3e_V2_lsp.log'
ssh root@68.168.216.243 'journalctl -u ss-t4-phase5-3e-V2.service -f'
```

## Sweep-back (run after PASS or FAIL)
```
ssh root@68.168.216.243 'bash /root/SuperScalar-phase5/docs/testnet4-phase5/sweep-back.sh ss_pool_6'
```
fee_rate=1 sat/vB. Echoes sweep-back txid; capture into V2-results.md.

## Stop (if needed)
```
ssh root@68.168.216.243 'systemctl stop ss-t4-phase5-3e-V2.service'
```
