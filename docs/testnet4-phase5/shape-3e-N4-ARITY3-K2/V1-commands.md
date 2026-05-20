# Shape 3e V1 — Commands (k² lifecycle, cooperative close)

What this test proves: first real-chain execution of the k² PS sub-factory shape
from t/1242. Validates initial sub-factory MuSig (k+1 signers, k+1 outputs per
sub-factory), v21 `ps_subfactory_chains` chain[0] persistence, watchtower
sub-factory registration, and cooperative close traversal of sub-factory
outputs.

## Pre-flight
```
ssh root@68.168.216.243 'free -h; bitcoin-cli -datadir=/var/lib/bitcoind-testnet4 -rpcuser=testnet4rpc -rpcpassword=testnet4rpcpass123 -rpcport=48332 -rpcwallet=ss_pool_1 getbalance'
```
Required: ≥3 GB available RAM; pool 1 balance ≥ 4M sats confirmed.

## Sync repo + worktree on VPS
```
ssh root@68.168.216.243 'cd /root/SuperScalar-phase5 && git fetch origin feat-testnet4-phase5-scaffold && git reset --hard origin/feat-testnet4-phase5-scaffold'
```

## Launch (fee rate at 1 sat/vB ceiling)
```
ssh root@68.168.216.243 'systemd-run --unit=ss-t4-phase5-3e-V1.service \
  --setenv WALLET=ss_pool_1 --setenv TAG=phase5_3e_V1 --setenv VARIANT=V1 \
  bash /root/SuperScalar-phase5/docs/testnet4-phase5/shape-3e-N4-ARITY3-K2/runner.sh'
```

The runner's defaults: `--clients 4 --arity 3 --ps-subfactory-arity 2`,
AMOUNT=1000000 sats/channel, FEE_RATE=1000 sat/kvB = **1.0 sat/vB**,
PORT=9950, --demo (cooperative close path).

## Monitor
```
ssh root@68.168.216.243 'tail -f /tmp/ss_t4_phase5_3e_V1_lsp.log'
ssh root@68.168.216.243 'journalctl -u ss-t4-phase5-3e-V1.service -f'
```

## Expected log markers (filled into V1-results.md as observed)
- `shape ewt = N blocks (BOLT 2016 ceiling = 2016)` — startup CLI accepted shape
- `all 4 clients connected`
- `funding TX broadcast at fee_rate=1000 sat/kvB (1.0000 sat/vB)`
- `waiting for confirmation of <txid>...`
- `sub-factory 0 built: 3 outputs, 3 signers`
- `sub-factory 1 built: 3 outputs, 3 signers`
- `persist: ps_subfactory_chain entry leaf=0 sub=0 chain_len=1`
- `persist: ps_subfactory_chain entry leaf=0 sub=1 chain_len=1`
- `watchtower: registered subfactory node N`
- `cooperative close ... txid=<hex>`
- `LIFECYCLE TEST PASSED` (or fail marker)

## Sweep-back (run after PASS or FAIL)
```
ssh root@68.168.216.243 'bash /root/SuperScalar-phase5/docs/testnet4-phase5/sweep-back.sh ss_pool_1'
```
Uses `fee_rate=1` sat/vB. Echoes the sweep-back txid; capture into V1-results.md.

## Stop (if needed)
```
ssh root@68.168.216.243 'systemctl stop ss-t4-phase5-3e-V1.service'
```
