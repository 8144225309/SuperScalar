# v0.1.14 Audit — Phase 2 Plan

Phase 1 of the v0.1.14 audit (PRs #78-#82, #83-#87) closed the ZmnSCPxj
safety invariants, the PS double-spend defense, mixed-arity CLI, and the
arity-1/2/PS sweep accounting cells. This document is the working plan
for Phase 2: the remaining gaps that must close before v0.1.14 ships.

**Release status:** SUSPENDED. Do not tag, push, or release v0.1.14
until the user explicitly says so. The plan below feeds into the
release-readiness vote that the user owns.

**Severity rule:** every item runs at full severity. No scope reduction,
no skip-on-CI flags, no "TODO" stubs. Each test must include conservation
assertion AND per-party `econ_assert_wallet_deltas`. Tests that exercise
on-chain paths must broadcast and confirm on regtest, not stop at
sighash verification.

## Items

Status legend: `[ ]` not started · `[~]` in progress · `[x]` complete

### 1. HTLC × force-to_local × {arity-1, arity-2, arity-PS}  `[x]`

Force-close while an HTLC is unresolved and the closer must wait out
the CSV delay on `to_local`. Tests:

- `test_regtest_htlc_force_to_local_arity1` — single-client leaf, force-close
  with one HTLC mid-flight (HTLC_RECEIVED on LSP side), CSV-delay sweep
  of `to_local`, HTLC-timeout sweep of HTLC output, conservation check.
- `test_regtest_htlc_force_to_local_arity2` — same shape on a 2-client leaf.
- `test_regtest_htlc_force_to_local_arity_ps` — same shape on a PS leaf,
  using the factory-consensus channel key.

For each cell:
- Build factory at the appropriate arity, fund from regtest faucet
- Open inner LN channel, add an HTLC via `channel_add_htlc(HTLC_RECEIVED)`
- Build + sign + broadcast LSP's commitment with HTLC output
- Mine `csv` blocks to satisfy BIP-68 on `to_local`
- LSP sweeps `to_local` via CSV script-path
- LSP sweeps HTLC output via the HTLC-timeout path (waiting cltv blocks)
- `econ_assert_wallet_deltas` verifies LSP receives `local_amt + htlc_amt - sweep_fees`
  and the originator gets back nothing (timeout, not preimage)
- Conservation: `Σ(swept) + Σ(fees) == fund_amount`

### 2. HTLC × breach × {arity-1, arity-2, arity-PS}  `[x]`

Breach a state that has an unresolved HTLC. Penalty TX must sweep BOTH
`to_local` (revoked) AND the HTLC output. Tests:

- `test_regtest_htlc_breach_arity1`
- `test_regtest_htlc_breach_arity2`
- `test_regtest_htlc_breach_arity_ps`

For each cell:
- Build factory + open inner LN channel
- Advance commitment to state N+1 (with HTLC), then re-broadcast state N
  (the breach) — counterparty has the revocation secret for N
- Counterparty broadcasts penalty TX that sweeps `to_local` via revocation
  AND sweeps the HTLC output via the revocation branch
- `econ_assert_wallet_deltas`: the punisher receives the full balance
  including HTLC value; the breacher gets zero
- Conservation: `Σ(swept) + Σ(fees) == fund_amount`

### 3. PS chain-advance sweep with accounting  `[x]`

#137 covered PS at `chain_len=0`. Extend to `chain_len >= 2`:

- `test_regtest_full_force_close_and_sweep_arity_ps_chain_len2`
- `test_regtest_full_force_close_and_sweep_arity_ps_chain_len5`

For each:
- Build PS factory, advance leaf 0 N times (using split-round leaf advance
  from `test_factory_ps_split_round_leaf_advance` as the model)
- Force-close the chain — broadcast all chain TXs in order with proper spacing
- Sweep final state's channel output (vout 0) and L-stock (vout 1, from
  the chain[0] TX which still has it)
- Verify accounting: each advance subtracted `fee_per_tx` from channel,
  ending channel sweep equals `initial_chan - N*fee - sweep_fee`

### 4. JIT recovery close spendability (#107)  `[~]`

Last open spendability cell from Chart C. JIT close shape is arity-invariant
(2-of-2 between LSP + JIT client, outside the factory tree), so a single
pair of cells covers all 3 Chart C "arity" cells for the JIT row:

- `test_regtest_jit_recovery_close_coop_full` — 2-of-2 MuSig coop close TX
  with LSP P2TR + client P2TR outputs; each party sweeps its own output.
- `test_regtest_jit_recovery_close_force_full` — LSP broadcasts a real
  BOLT-2 commitment_tx with to_local + to_remote; client sweeps to_remote
  immediately via per-commit BIP-341 keypath; LSP waits CSV(10) blocks
  then sweeps to_local via channel_build_to_local_sweep.

Both cells assert per-party deltas via `econ_assert_wallet_deltas` AND
conservation `Σ(swept) + Σ(fees) == jit_funding_amount`. The force cell
applies COMMIT_FEE_RESERVE = 1500 sats from PR #89/#90/#91.

### 5. Hybrid CLN test (#73)  `[~]`

One side SuperScalar factory, other side vanilla CLN channel:

- `test_regtest_hybrid_cln_arity2_payment` — SuperScalar leaf channel
  routes a payment to a regular CLN channel; both sides settle
  independently; accounting holds across the boundary

Requires CLN running on the regtest VPS (already configured in MEMORY).

### 6. Mixed-arity production lifecycle  `[ ]`

We loosened the CLI in #81 + wrote `docs/factory-arity.md`, but no
end-to-end test runs a `2,4,8` mixed-arity factory through a full lifecycle:

- `test_regtest_mixed_arity_2_4_8_lifecycle` — build with
  `factory_set_level_arity({2,4,8}, 3)`, open ≥7 client channels,
  route 1 payment through each, force-close, sweep all leaves, verify
  conservation across the entire mixed-arity tree

### 7. PS at N=128 stress  `[x]`

Matrix in #136 only goes to N=64. Add a build-only N=128 cell:

- `test_factory_ps_build_n128` — 128-way MuSig aggregation, build,
  sign, verify. No advance required (we already verified advance at N=64).

If this fails due to DW_MAX_LAYERS or stack constraints, document the
ceiling and surface it to the user as a hard limit.

## Execution log

| # | PR | Status | Notes |
|---|----|--------|-------|
| 1 | #89 | `[x]` | 3 cells PASS on VPS regtest with full conservation + per-party econ deltas |
| 2 | #90 | `[x]` | 3 HTLC×breach cells merged; commit-fee reserve applied |
| 3 | #91 | `[x]` | 2 cells (chain_len=2, chain_len=5) PASS on VPS; merged |
| 4 | #92 | `[x]` | 2 cells (coop, force) PASS on VPS; merged |
| 5 | #93 | `[x]` | Real CLN+LSP+SS topology; payment routed across boundary; merged (CI gap: no CLN in GitHub Actions, VPS is source of truth) |
| 6 | #94 | `[x]` | Mixed `{2,4,8}` factory at N=12 (1 LSP + 11 clients) → 6 leaves (5 arity-2 + 1 arity-1, 11 client channels). Tree broadcast on regtest VPS, all 6 leaves swept with conservation + per-party `econ_assert_wallet_deltas` for all 12 parties; merged |
| 7 | #95 | `[x]` | `test_factory_ps_build_n128` builds + 128-way MuSig signs + verifies a 506-node PS tree at N=128 (1 LSP + 127 clients → 127 PS leaves, depth 7, 8 DW layers — exactly DW_MAX_LAYERS). Required raising `FACTORY_MAX_LEAVES` 64→128 (one-line, ~1.5KB struct growth) so the static `leaf_layers[]` / `leaf_node_indices[]` arrays in `factory_t` accommodate 127 PS leaves. The unilateral-close ceiling is now `DW_MAX_LAYERS=8` → tree of up to 128 PS leaves (= N=129 PS, but FACTORY_MAX_SIGNERS=128 binds first). Merged. |

## Done means

For an item to be marked `[x]`:

1. PR is open with all sub-cells implemented (no stubs)
2. CI green on all required checks (Linux, macOS, sanitizers, TSan, regtest, coverage)
3. VPS regtest run shows pass with full accounting output (`econ_print_summary`)
4. PR merged to main
5. `docs/accounting-chart-c.md` updated to reflect the new coverage
6. This file's execution log updated

## Out of scope for Phase 2

- Anything signet/mainnet — phase 2 is regtest-only
- New economic flows beyond what the code already supports
- v0.1.14 release prep — handled separately when the user calls for it
