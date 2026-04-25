# v0.1.14 Audit — Phase 3 Plan

Phase 2 of the v0.1.14 audit (PRs #89-#95) closed the HTLC × force-close,
HTLC × breach, PS chain-advance accounting, JIT recovery close, hybrid CLN,
mixed-arity production lifecycle, and N=128 PS stress cells. This document
is the working plan for Phase 3: the remaining gaps that must close before
v0.1.14 ships.

**Release status:** SUSPENDED. Do not tag, push, or release v0.1.14 until
the user explicitly says so.

**Severity rule:** every item runs at full severity. No scope reduction,
no skip-on-CI flags, no "TODO" stubs. Each test must include conservation
assertion AND per-party `econ_assert_wallet_deltas`. Tests that exercise
on-chain paths must broadcast and confirm on regtest, not stop at sighash
verification.

## Items

Status legend: `[ ]` not started · `[~]` in progress · `[x]` complete

### 1. PS at N=8 / N=16 on regtest with full per-party accounting  `[~]`

Phase 2 #3 covered PS chain-advance at N=3 on real chain; Phase 2 #7
covered PS at N=64 / N=128 in unit tests with fake txids. The middle
ground — N≥8 on real chain with full per-party accounting — is untested.

Tests in `tests/test_close_spendability_full.c`:

- `test_regtest_ps_full_lifecycle_n8` — N=8, all 7 PS leaves chain_len=0,
  every leaf swept, per-party deltas asserted for all 8 parties.
- `test_regtest_ps_heterogeneous_chains_n8` — N=8, chain_lens
  `{5,3,1,0,0,2,4}` across 7 leaves, per-party deltas asserted.
- `test_regtest_ps_full_lifecycle_n16` — N=16, all 15 PS leaves
  chain_len=0, per-party deltas asserted for all 16 parties.
- `test_regtest_ps_heterogeneous_chains_n16` — N=16, mixed chain_lens
  `{0,1,2,0,5,0,3,0,1,4,0,2,0,1,5}` across 15 leaves, per-party deltas.
- `test_regtest_ps_old_state_broadcast_fails_n8` — adversarial: leaf 0
  advanced to chain_len=2; chain[0] then chain[2] broadcast and confirmed
  (chain[1] also broadcast in between to satisfy parent dependency); a
  second broadcast attempt of chain[1] AFTER chain[2] confirms must FAIL
  with `bad-txns-inputs-missingorspent`. Proves PS non-revocability at
  the chain level.

For each: build PS factory, fund from regtest faucet (≥5M sats to
survive N×fee deductions), broadcast every signed tree node + every
chain advance, sweep all leaves with 2-of-2 MuSig per channel + LSP-solo
per L-stock, conservation across the entire tree, per-party econ deltas
for all N parties.

## Execution log

| # | PR | Status | Notes |
|---|----|--------|-------|
| 1 |    | `[~]` | branch `test/phase3-ps-regtest-scale` — 5 cells implemented |

## Done means

For an item to be marked `[x]`:

1. PR is open with all sub-cells implemented (no stubs)
2. CI green on all required checks (Linux, macOS, sanitizers, TSan, regtest, coverage)
3. VPS regtest run shows pass with full accounting output (`econ_print_summary`)
4. PR merged to main
5. `docs/accounting-chart-c.md` updated to reflect the new coverage
6. This file's execution log updated

## Out of scope for Phase 3

- Anything signet/mainnet — phase 3 is regtest-only
- New economic flows beyond what the code already supports
- v0.1.14 release prep — handled separately when the user calls for it
