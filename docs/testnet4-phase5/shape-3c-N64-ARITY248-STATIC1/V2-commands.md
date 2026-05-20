# shape-3c-N64-ARITY248-STATIC1 V2 - Commands

Proves: Scale-canonical from signet-ps-n8-procedure.md sec.3c: N=64 ARITY=2,4,8 STATIC_NEAR_ROOT=1 force-close on real chain. Currently in flight (task #189, started 2026-05-19T17:00 UTC).

Fee ceiling: **1 sat/vB** (FEE_RATE=1000 sat/kvB). Every TX in this run obeys.
Uses the existing tools/ runner (predates Phase 5 docs).

## Pre-flight
```
ssh root@68.168.216.243 'free -h | head -2; bitcoin-cli -datadir=/var/lib/bitcoind-testnet4 -rpcuser=testnet4rpc -rpcpassword=testnet4rpcpass123 -rpcport=48332 -rpcwallet=superscalar_test getbalance'
```

## Sync repo on VPS
```
ssh root@68.168.216.243 'cd /root/SuperScalar-phase5 && git fetch origin feat-testnet4-phase5-scaffold && git reset --hard origin/feat-testnet4-phase5-scaffold'
```

## Launch
```
ssh root@68.168.216.243 'systemd-run --unit=ss-t4-phase5-3c-V2.service \
  --setenv WALLET=superscalar_test --setenv TAG=phase5_3c_V2 --setenv VARIANT=V2 \
  bash /root/SuperScalar/tools/test_testnet4_n64_ps_lifecycle.sh'
```
Variant V2 -> `--demo --force-close`. Port 9940.

## Monitor
```
ssh root@68.168.216.243 'tail -f /tmp/ss_t4_phase5_3c_V2_lsp.log'
ssh root@68.168.216.243 'journalctl -u ss-t4-phase5-3c-V2.service -f'
```

## Sweep-back (run after PASS or FAIL)
```
ssh root@68.168.216.243 'bash /root/SuperScalar-phase5/docs/testnet4-phase5/sweep-back.sh superscalar_test'
```
fee_rate=1 sat/vB. Echoes sweep-back txid; capture into V2-results.md.

## Stop (if needed)
```
ssh root@68.168.216.243 'systemctl stop ss-t4-phase5-3c-V2.service'
```
