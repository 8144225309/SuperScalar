# Accounting Coverage Chart C

This document maps every (arity × close-method × HTLC-state) cell of the
SuperScalar accounting matrix to the test that verifies it. Cells without
a verifying test are flagged as gaps, with reasoning for why they are or
are not blockers for a release.

This chart exists because the user has suspended the v0.1.14 release until
"all parts of the SuperScalar accounting and Pseudo-Spilman are complete
and can be run with many different configs and outcomes." Use this chart
to drive that completion.

## The matrix

- **Arity dimension:** 3 values — `ARITY_1`, `ARITY_2`, `ARITY_PS`
- **Close-method dimension:** 6 values — `coop`, `force-to_remote`, `force-to_local`,
  `breach`, `rotation`, `PS-advance` (PS-only)
- **HTLC-state dimension:** 2 values — `no-HTLC`, `HTLC-mid-flight`

Total: 3 × 6 × 2 = 36 logical cells. Three cells are degenerate (`PS-advance`
on `ARITY_1` and `ARITY_2` makes no sense), leaving 33 meaningful cells.

## Verification conventions

| Symbol | Meaning |
|---|---|
| ✓ | Cell verified by a passing test that asserts both spendability AND accounting conservation |
| S | Cell verified for spendability only (no accounting assertion) |
| E | Cell verified for accounting only (no on-chain spendability assertion) |
| — | Degenerate cell (does not exist in the design) |
| ✗ | Cell is a gap; no test exists |

## Chart C: no-HTLC slice

| Close method | ARITY_1 | ARITY_2 | ARITY_PS |
|---|---|---|---|
| coop | ✓ `run_coop_close_for_arity(ARITY_1)` + `test_regtest_econ_arity1_baseline` | ✓ `run_coop_close_for_arity(ARITY_2)` + `test_regtest_econ_arity2_baseline` | ✓ `run_coop_close_for_arity(ARITY_PS)` + `test_regtest_econ_arity_ps_baseline` |
| force-to_remote | S `test_regtest_force_close_to_remote` | S | S |
| force-to_local | S `test_regtest_force_close_to_local` | S | S |
| breach | S `test_regtest_breach_penalty_spendability` | S | S |
| rotation | ✓ `run_rotation_for_arity(ARITY_1)` + `test_regtest_econ_rotation_arity1` | ✓ `run_rotation_for_arity(ARITY_2)` + `test_regtest_econ_rotation_arity2` | ✓ `run_rotation_for_arity(ARITY_PS)` + `test_regtest_econ_rotation_arity_ps` |
| PS-advance | — | — | ✓ `test_regtest_econ_ps_advance` (in-process); on-chain chain advance + sweep covered by `test_regtest_full_force_close_and_sweep_arity_ps_chain_len2` and `..._chain_len5` (Phase 2 #3) |
| full-tree | ✓ `test_regtest_full_force_close_and_sweep_arity1` | (pending PR by #137 agent) | (pending PR by #137 agent) |

## Chart C: HTLC-mid-flight slice

| Close method | ARITY_1 | ARITY_2 | ARITY_PS |
|---|---|---|---|
| coop | ✗ | ✗ | ✗ |
| force-to_remote | S `test_regtest_htlc_in_flight_spendability` (arity-1 only) | ✗ | ✗ |
| force-to_local | ✓ `test_regtest_htlc_force_to_local_arity1` | ✓ `test_regtest_htlc_force_to_local_arity2` | ✓ `test_regtest_htlc_force_to_local_arity_ps` |
| breach | ✓ `test_regtest_htlc_breach_arity1` | ✓ `test_regtest_htlc_breach_arity2` | ✓ `test_regtest_htlc_breach_arity_ps` |
| rotation | ✗ | ✗ | ✗ |
| PS-advance | — | — | ✗ |

## Gap analysis

### High-priority gaps (block release)

None of the no-HTLC cells are gaps. Every (arity × close-method) combination
has at least spendability coverage; most have full accounting. The pending
#137 PR closes the last two no-HTLC `full-tree` cells.

### Medium-priority gaps (should fill before mainnet)

- **`HTLC-mid-flight × force-to_local × any arity`** — exercising the CSV
  recovery branch when an HTLC is unresolved is the realistic scenario
  for a force-close where someone needs to wait out the timeout. Currently
  zero coverage.
- **`HTLC-mid-flight × breach × any arity`** — penalty TX behavior when
  the breached commit has an unresolved HTLC needs explicit accounting
  verification (the punisher should sweep both `to_local` AND the HTLC
  output).

### Low-priority gaps (acceptable deferral)

- **`HTLC-mid-flight × coop × any arity`** — coop close when an HTLC is
  in flight is unusual; in practice the channel is drained first. Could
  be tested but not load-bearing.
- **`HTLC-mid-flight × rotation × any arity`** — rotation while HTLCs
  are pending is forbidden by design (the in-flight HTLC must resolve
  before the rotation can settle). Worth a *negative* test that asserts
  rotation refuses to run with pending HTLCs.

### Out of scope for Chart C

- **JIT channel close** — separate flow with full coverage:
  - `test_regtest_jit_recovery_close_coop_full` ✓ (coop close, per-party
    deltas + conservation)
  - `test_regtest_jit_recovery_close_force_full` ✓ (force-close with
    CSV to_local sweep + immediate to_remote sweep, per-party deltas +
    conservation)
  - `test_regtest_econ_jit_cooperative_close` ✓ (close-amount econ formula)
  - `test_regtest_jit_daemon_trigger` (JIT lifecycle + funding)
  JIT channels exist outside the arity-dependent factory tree, so the
  close shape is arity-invariant — the two `_full` cells above cover
  all 3 Chart C "arity" cells for the JIT row.
- **Buy-liquidity flows** — covered by Chart B (existing).
- **Hybrid CLN boundary** — `test_regtest_hybrid_cln_arity2_payment` ✓
  exercises a real BOLT11 payment routed across the
  `[CLN-2] → [CLN-1+SS-plugin] → [LSP daemon] → [SS arity-2 leaf] → [Client_0]`
  topology with conservation + per-party `econ_assert_wallet_deltas`. CLN
  not present in GitHub Actions; VPS regtest is the source of truth for
  this cell.

## Test runtime budget

The full Chart C suite (existing + pending PRs) runs in approximately
~3-4 minutes on a regtest VM. Each new HTLC-mid-flight cell would add
~10-15s. Filling all 11 missing HTLC cells would push runtime to ~6 min,
which is acceptable for the regtest CI tier.

## How to extend this chart

When adding a new test that covers a Chart C cell:

1. Mark the cell ✓/S/E in this chart with the test function name
2. If the test is regtest, register it under the `Fund Settlement: Regtest
   Spendability` block in `tests/test_main.c`
3. If the test asserts accounting conservation, link it to `econ_assert_wallet_deltas`
4. If the test reveals a real bug, file an issue and update CHANGELOG.md
   under the Unreleased section (do NOT cut a release until the user explicitly says so)

## Related documents

- `docs/factory-arity.md` — design of the three arity options
- `docs/pseudo-spilman.md` — non-revocability contract for PS leaves
- `.claude/V0_1_14_AUDIT_TODO.md` — overall audit status (gitignored,
  internal tracking)
