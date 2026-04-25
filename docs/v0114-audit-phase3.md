# v0.1.14 Audit — Phase 3 Plan

Phase 2 (PRs #89-#95) closed the accounting matrix and production-shape gaps.
Phase 3 closes the **scale + coordination** gap: every test we ran in phase 2
either was unit-only at scale (N=64, N=128) or was at small N on real chain
(N=2-3 PS on regtest, N=3 PS on signet). The middle ground — **PS at N>=8 on a
real chain with full accounting** — is untested.

**Release status:** SUSPENDED. v0.1.14 stays held until the user explicitly
releases it.

**Severity rule:** every item runs at full severity. Every party's delta
must be asserted via `econ_assert_wallet_deltas` (not just LSP + one client).
Every TX broadcast on a real chain. No skip flags, no stubs.

## Items

Status legend: `[ ]` not started · `[~]` in progress · `[x]` complete

### 1. PS at N=8 and N=16 on regtest with full accounting  `[~]`

Five new tests in `tests/test_close_spendability_full.c`:

- `test_regtest_ps_full_lifecycle_n8` — N=8 (LSP + 7 clients), all leaves
  at chain_len=0, build -> broadcast tree -> sweep all 7 channels + L-stocks
  -> assert per-party deltas for **all 8 parties** + conservation
- `test_regtest_ps_heterogeneous_chains_n8` — N=8, chain_lens
  {5, 3, 1, 0, 0, 2, 4} across 7 leaves, full sweep + accounting
- `test_regtest_ps_full_lifecycle_n16` — N=16, all leaves chain_len=0
  (16-way MuSig at root, 15 leaves swept), all 16 parties' deltas exact
- `test_regtest_ps_heterogeneous_chains_n16` — N=16, mixed chain_lens
  across 15 leaves, full sweep + accounting for 16 parties
- `test_regtest_ps_old_state_broadcast_fails_n8` — adversarial: leaf 0
  advanced to chain_len=2; broadcast chain[0] then chain[2]; attempt to
  broadcast stashed chain[1] AFTER chain[2] confirms must fail with
  `bad-txns-inputs-missingorspent`. Proves PS non-revocability at the
  chain level (not just persist defense)

### 2. PS at N=32 on regtest with full accounting  `[ ]`

Two new tests:

- `test_regtest_ps_full_lifecycle_n32` — N=32 (LSP + 31 clients), all
  leaves chain_len=0, full sweep + accounting for all 32 parties
- `test_regtest_ps_heterogeneous_chains_n32` — same but with mixed
  chain_lens across the 31 leaves

Gated on item #1 finding nothing. ~5 min added test runtime.

### 3. PS at N=8 on signet with chain-advance, end-to-end  `[ ]`

Real signet, real adversarial network, real LSP + 7 client processes
coordinating off-chain via the wire protocol, real on-signet broadcast
of factory tree + chain advances + sweeps. Closes the "regtest is too
clean" gap.

Specifics: extend `tools/signet_setup.sh` (task #68) to support PS arity
at N=8, then run a multi-advance lifecycle on signet with state recording.

### 4. Multi-process MuSig coordination  `[ ]`

Real distinct `superscalar_client` processes (not single-process holding
all keypairs). One LSP daemon + N=8 client processes participating in a
real factory build via the wire protocol. Measures: does the MuSig
coordination round actually complete? What's the latency? Are there
protocol bugs that the in-process tests masked?

This is the biggest delta between "tests pass" and "actually works on
mainnet."

## Execution log

| # | PR | Status | Notes |
|---|----|--------|-------|
| 1 | TBD | `[~]` | branch `test/phase3-ps-regtest-scale` — 5 cells implemented |
| 2 | TBD | `[ ]` | not started — gated on #1 |
| 3 | TBD | `[ ]` | not started |
| 4 | TBD | `[ ]` | not started |

## Done means

For an item to be marked `[x]`:

1. PR is open with all sub-cells implemented (no stubs)
2. CI green on all required checks (Linux, macOS, sanitizers, TSan, regtest, coverage)
3. VPS regtest run shows pass with full accounting output
4. PR merged to main
5. This file's execution log updated

## Out of scope for Phase 3

- Anything beyond N=32 on regtest (covered by unit tests up to N=128)
- Mainnet — too early without signet validation first
- v0.1.14 release prep — handled separately when the user calls for it
