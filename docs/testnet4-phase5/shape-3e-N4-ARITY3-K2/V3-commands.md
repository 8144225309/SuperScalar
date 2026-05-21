# shape-3e-N4-ARITY3-K2 V3 - Commands

Proves: PS leaf TX chaining + client_ps_signed_inputs double-spend defense across N advances; sub-factory state stable across leaf advances.

Fee ceiling: **1 sat/vB** (FEE_RATE=1000 sat/kvB). Every TX in this run obeys.


## Pre-flight
```
ssh root@68.168.216.243 'free -h | head -2; bitcoin-cli -datadir=/var/lib/bitcoind-testnet4 -rpcuser=testnet4rpc -rpcpassword=testnet4rpcpass123 -rpcport=48332 -rpcwallet=ss_pool_7 getbalance'
```

## Sync repo on VPS
```
ssh root@68.168.216.243 'cd /root/SuperScalar-phase5 && git fetch origin feat-testnet4-phase5-scaffold && git reset --hard origin/feat-testnet4-phase5-scaffold'
```

## Launch
```
ssh root@68.168.216.243 'systemd-run --unit=ss-t4-phase5-3e-V3.service \
  --setenv WALLET=ss_pool_7 --setenv TAG=phase5_3e_V3 --setenv VARIANT=V3 \
  bash /root/SuperScalar-phase5/docs/testnet4-phase5/shape-3e-N4-ARITY3-K2/runner.sh'
```
Variant V3 -> `--demo --test-ps-advance`. Port 9950.

## Monitor
```
ssh root@68.168.216.243 'tail -f /tmp/ss_t4_phase5_3e_V3_lsp.log'
ssh root@68.168.216.243 'journalctl -u ss-t4-phase5-3e-V3.service -f'
```

## Sweep-back (run after PASS or FAIL)
```
ssh root@68.168.216.243 'bash /root/SuperScalar-phase5/docs/testnet4-phase5/sweep-back.sh ss_pool_7'
```
fee_rate=1 sat/vB. Echoes sweep-back txid; capture into V3-results.md.

## Stop (if needed)
```
ssh root@68.168.216.243 'systemctl stop ss-t4-phase5-3e-V3.service'
```
