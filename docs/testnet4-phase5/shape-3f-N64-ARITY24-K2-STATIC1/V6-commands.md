# shape-3f-N64-ARITY24-K2-STATIC1 V6 - Commands

Proves: INTEGRATION mid-flight restart: kill LSP mid-ceremony; restart; resume. (Gated on #245 SF-CRASH-INJECT-WIRE; may slip to v0.2.1.)

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
ssh root@68.168.216.243 'systemd-run --unit=ss-t4-phase5-3f-V6.service \
  --setenv WALLET=ss_pool_7 --setenv TAG=phase5_3f_V6 --setenv VARIANT=V6 \
  bash /root/SuperScalar-phase5/docs/testnet4-phase5/shape-3f-N64-ARITY24-K2-STATIC1/runner.sh'
```
Variant V6 -> `--demo --force-close`. Port 9954.

## Monitor
```
ssh root@68.168.216.243 'tail -f /tmp/ss_t4_phase5_3f_V6_lsp.log'
ssh root@68.168.216.243 'journalctl -u ss-t4-phase5-3f-V6.service -f'
```

## Sweep-back (run after PASS or FAIL)
```
ssh root@68.168.216.243 'bash /root/SuperScalar-phase5/docs/testnet4-phase5/sweep-back.sh ss_pool_7'
```
fee_rate=1 sat/vB. Echoes sweep-back txid; capture into V6-results.md.

## Stop (if needed)
```
ssh root@68.168.216.243 'systemctl stop ss-t4-phase5-3f-V6.service'
```
