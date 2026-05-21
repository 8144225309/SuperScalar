# shape-3a-N8-ARITY3 V1 - Commands

Proves: Uniform PS leaf baseline (no sub-factory, no static-near-root). Smallest pure-PS test; regression target if 3e fails.

Fee ceiling: **1 sat/vB** (FEE_RATE=1000 sat/kvB). Every TX in this run obeys.


## Pre-flight
```
ssh root@68.168.216.243 'free -h | head -2; bitcoin-cli -datadir=/var/lib/bitcoind-testnet4 -rpcuser=testnet4rpc -rpcpassword=testnet4rpcpass123 -rpcport=48332 -rpcwallet=ss_pool_2 getbalance'
```

## Sync repo on VPS
```
ssh root@68.168.216.243 'cd /root/SuperScalar-phase5 && git fetch origin feat-testnet4-phase5-scaffold && git reset --hard origin/feat-testnet4-phase5-scaffold'
```

## Launch
```
ssh root@68.168.216.243 'systemd-run --unit=ss-t4-phase5-3a-V1.service \
  --setenv WALLET=ss_pool_2 --setenv TAG=phase5_3a_V1 --setenv VARIANT=V1 \
  bash /root/SuperScalar-phase5/docs/testnet4-phase5/shape-3a-N8-ARITY3/runner.sh'
```
Variant V1 -> `--demo`. Port 9951.

## Monitor
```
ssh root@68.168.216.243 'tail -f /tmp/ss_t4_phase5_3a_V1_lsp.log'
ssh root@68.168.216.243 'journalctl -u ss-t4-phase5-3a-V1.service -f'
```

## Sweep-back (run after PASS or FAIL)
```
ssh root@68.168.216.243 'bash /root/SuperScalar-phase5/docs/testnet4-phase5/sweep-back.sh ss_pool_2'
```
fee_rate=1 sat/vB. Echoes sweep-back txid; capture into V1-results.md.

## Stop (if needed)
```
ssh root@68.168.216.243 'systemctl stop ss-t4-phase5-3a-V1.service'
```
