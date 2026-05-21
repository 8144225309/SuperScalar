# shape-3epp-N16-ARITY3-K2 V4 - Commands

Proves: Sub-factory chain advance on one of 8 sub-factories; the other 7 stable. Validates cohort isolation under load. (Use after pool 1 sweeps back from 3e V1.)

Fee ceiling: **1 sat/vB** (FEE_RATE=1000 sat/kvB). Every TX in this run obeys.


## Pre-flight
```
ssh root@68.168.216.243 'free -h | head -2; bitcoin-cli -datadir=/var/lib/bitcoind-testnet4 -rpcuser=testnet4rpc -rpcpassword=testnet4rpcpass123 -rpcport=48332 -rpcwallet=ss_pool_1 getbalance'
```

## Sync repo on VPS
```
ssh root@68.168.216.243 'cd /root/SuperScalar-phase5 && git fetch origin feat-testnet4-phase5-scaffold && git reset --hard origin/feat-testnet4-phase5-scaffold'
```

## Launch
```
ssh root@68.168.216.243 'systemd-run --unit=ss-t4-phase5-3epp-V4.service \
  --setenv WALLET=ss_pool_1 --setenv TAG=phase5_3epp_V4 --setenv VARIANT=V4 \
  bash /root/SuperScalar-phase5/docs/testnet4-phase5/shape-3epp-N16-ARITY3-K2/runner.sh'
```
Variant V4 -> `--demo --test-subfactory-advance`. Port 9953.

## Monitor
```
ssh root@68.168.216.243 'tail -f /tmp/ss_t4_phase5_3epp_V4_lsp.log'
ssh root@68.168.216.243 'journalctl -u ss-t4-phase5-3epp-V4.service -f'
```

## Sweep-back (run after PASS or FAIL)
```
ssh root@68.168.216.243 'bash /root/SuperScalar-phase5/docs/testnet4-phase5/sweep-back.sh ss_pool_1'
```
fee_rate=1 sat/vB. Echoes sweep-back txid; capture into V4-results.md.

## Stop (if needed)
```
ssh root@68.168.216.243 'systemctl stop ss-t4-phase5-3epp-V4.service'
```
