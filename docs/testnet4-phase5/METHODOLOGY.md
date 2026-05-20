# Methodology — testnet4 Phase 5 campaign

## Workflow per shape × variant

1. **Pre-flight checks**
   - `free -h` shows ≥3 GB available after subtracting in-flight tests
   - Target `ss_pool_N` shows confirmed balance ≥ shape AMOUNT × N_CLIENTS × 1.5 (overhead for fees and chain advances)
   - `build-release` binaries are fresh (per `feedback_build_staleness_cmake`: rebuild if any lib touched since last run)

2. **Launch**
   ```
   ssh root@68.168.216.243 'setsid systemd-run --unit=ss-t4-<shape>-V<n>.service \
     --setenv WALLET=ss_pool_<N> --setenv TAG=phase5_<shape>_V<n> \
     bash /root/SuperScalar/docs/testnet4-phase5/<shape>/runner.sh'
   ```
   `systemd-run --unit=` survives SSH session end (per `feedback_testnet4_setsid_required`).

3. **Monitor**
   - LSP log at `/tmp/ss_t4_phase5_<shape>_V<n>_lsp.log`
   - stderr at `/tmp/ss_t4_phase5_<shape>_V<n>_diag/lsp.stderr`
   - predeath snapshot rotates per `diag_periodic` (60s cadence)
   - Incremental evidence appended to `/tmp/ss_t4_phase5_<shape>_V<n>.evidence.md`
   - `journalctl -u ss-t4-<shape>-V<n>.service -f` for unit-level events

4. **On completion (PASS or FAIL)**
   - Copy `/tmp/ss_t4_phase5_<shape>_V<n>.evidence.md` into repo at `docs/testnet4-phase5/<shape>/V<n>-<name>.md`
   - Run sweep-back (see below)
   - Update `README.md` status matrix
   - Update `/root/SuperScalar-ops/t4-pool-ledger.txt`

5. **Sweep-back** (REQUIRED, even on FAIL)
   ```
   ssh root@68.168.216.243 'RPC="bitcoin-cli -datadir=/var/lib/bitcoind-testnet4 \
       -rpcuser=testnet4rpc -rpcpassword=testnet4rpcpass123 -rpcport=48332"
   DEST=$($RPC -rpcwallet=superscalar_test getnewaddress "sweepback-<pool>-$(date +%s)")
   $RPC -rpcwallet=<pool> -named sendall recipients="[\"$DEST\"]" fee_rate=1.1'
   ```
   Record sweep-back txid in the V<n>.md doc's Sweep-back section.

## Fee ceiling — 1 sat/vB MAX

**Hard rule.** Every transaction in the campaign — funding, tree broadcast, sub-factory chain[N], force-close commits, per-leaf sweeps, sweep-back — uses **fee_rate ≤ 1 sat/vB** (equivalently `--fee-rate ≤ 1000` sat/kvB on LSP CLI, or `fee_rate=1` on bitcoind RPC).

Testnet4 wallet's `mintxfee` is also 1 sat/vB, so this is the tightest value the wallet will accept. NEVER use a higher fee rate (the earlier 1.1 sat/vB multiwithdraw + 8 sat/vB CPFP were the only exceptions, both pre-rule). If a TX gets stuck in mempool, prefer waiting over fee-bumping — testnet4 reorg/mempool turnover surfaces the test, not a fee discipline failure.

## Per-test file structure

Every shape × variant gets **two files** (the test plan + the evidence):

- `<shape>/V<n>-commands.md` — the exact env vars, systemd-run launch line, expected log markers, and sweep-back command. Frozen at write time so the test is reproducible later.
- `<shape>/V<n>-results.md` — txids, block heights, conservation math, sweep-back txid. Filled in as the run progresses.

The two-file split keeps inputs (commands) and outputs (results) auditable separately for later examination.

## Conservation math
For every PASS run, verify:
```
funding_in_sats = sum(all sweep output sats) + sum(all tx fees) + leftover_unspent_in_pool
```
Where `funding_in_sats` is the AMOUNT the LSP locked into the factory funding TX,
`sweep output sats` is each per-leaf / per-client sweep destination value, and
`tx fees` covers factory funding + tree broadcast + force-close commits + per-leaf sweeps.

The runner emits a conservation block to its evidence file at completion. If
the math is off by more than 1000 sats, mark FAIL and investigate.

## Resumability rules
Set `RESUME=1` in the launch environment to skip the `rm -f $LSP_DB ...` wipe.
Use when:
- A run crashed mid-ceremony and the LSP DB has recoverable state
- A run was killed for VPS RAM pressure and you want to resume

Do NOT resume when:
- The test's purpose is to validate first-run behavior (e.g. V1 lifecycle from scratch)
- The LSP DB shows schema version mismatch vs the binary
- V6 (mid-flight restart) — that variant intentionally starts fresh and kills mid-flight

## RAM budget
Per-process estimates from in-flight measurement:
- LSP base: ~200 MB
- Each client: ~35 MB
- Watchtower: ~5 MB
- Per-shape:
  - N=4 (3e): ~340 MB
  - N=8 (3a, 3b): ~480 MB
  - N=16 (3e+): ~760 MB
  - N=64 (3c, 3f): ~2.5 GB

Parallel-launch rule: total RAM of (in-flight + new) < 75% of `free -h` available.

## Diag helpers (already in `tools/test_diag_lib.sh`)
- `diag_setup <tag>` — forensics dir, start.txt
- `diag_enable_core_dumps` — ulimit + core_pattern → diag dir
- `diag_stderr_path <name>` — returns `$DIAG_DIR/<name>.stderr`
- `diag_periodic <pid>` — 60s `/proc` snapshots + rotating predeath
- `diag_wait_lsp <pid> <log> <tag>` — waits, captures forensics on non-zero exit

Each runner sources this lib; no per-shape diag plumbing needed.

## Common bugs to flag in evidence
- Invalid Schnorr signature → record sighash hex + verify against musig keyagg order
- Build staleness (cmake left client/wt vs LSP mismatched) → confirm all 3 binaries SHA-match
- Wallet `gettransaction -5` → testnet4 mempool dropped a TX, re-broadcast at higher fee
- SIGTERM at ~5-31min → systemd-logind kill (should be impossible under `systemd-run`, file as regression if seen)
