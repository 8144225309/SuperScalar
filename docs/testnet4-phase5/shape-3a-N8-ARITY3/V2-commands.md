# shape-3a-N8-ARITY3 V2 - Commands

Proves: Uniform PS force-close: 8 leaves broadcast + each client sweep at PS leaf channel output.

Fee ceiling: **1 sat/vB** (FEE_RATE=1000 sat/kvB). Every TX in this run obeys.


## Pre-flight
```
ssh root@68.168.216.243 'free -h | head -2; bitcoin-cli -datadir=/var/lib/bitcoind-testnet4 -rpcuser=testnet4rpc -rpcpassword=testnet4rpcpass123 -rpcport=48332 -rpcwallet=ss_pool_3 getbalance'
```

## Sync repo on VPS
```
ssh root@68.168.216.243 'cd /root/SuperScalar-phase5 && git fetch origin feat-testnet4-phase5-scaffold && git reset --hard origin/feat-testnet4-phase5-scaffold'
```

## Launch
```
ssh root@68.168.216.243 'systemd-run --unit=ss-t4-phase5-3a-V2.service \
  --setenv WALLET=ss_pool_3 --setenv TAG=phase5_3a_V2 --setenv VARIANT=V2 \
  bash /root/SuperScalar-phase5/docs/testnet4-phase5/shape-3a-N8-ARITY3/runner.sh'
```
Variant V2 -> `--demo --force-close`. Port 9951.

## Monitor
```
ssh root@68.168.216.243 'tail -f /tmp/ss_t4_phase5_3a_V2_lsp.log'
ssh root@68.168.216.243 'journalctl -u ss-t4-phase5-3a-V2.service -f'
```

## Sweep-back (run after PASS or FAIL)
```
ssh root@68.168.216.243 'bash /root/SuperScalar-phase5/docs/testnet4-phase5/sweep-back.sh ss_pool_3'
```
fee_rate=1 sat/vB. Echoes sweep-back txid; capture into V2-results.md.

## Stop (if needed)
```
ssh root@68.168.216.243 'systemctl stop ss-t4-phase5-3a-V2.service'
```
