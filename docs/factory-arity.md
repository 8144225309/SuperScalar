# Factory arity: picking the right tree shape

SuperScalar factories are timeout-tree-structured Decker–Wattenhofer
trees with **Pseudo-Spilman (PS) leaves** as the canonical leaf
mechanism. Each internal level's branching factor ("arity") is
configurable independently of the others via the `--arity` CLI flag.
Picking the wrong shape at large client counts stacks too much BIP-68
CSV delay along the exit path and pushes HTLC `final_cltv_expiry` past
BOLT's 2016-block ceiling — clients routed through the factory then
refuse to accept forwards because the worst-case exit time exceeds what
they consider safe. This doc explains the tradeoff and recommends
shapes.

**See also:** [docs/pseudo-spilman.md](pseudo-spilman.md) — design and
non-revocability contract for PS leaves: why they have no revocation
keys, and how the `client_ps_signed_inputs` persist table prevents
double-signing.

## Pseudo-Spilman is the canonical leaf

For new deployments, **use `--arity 3` (Pseudo-Spilman)** at the leaf
level. PS is the headline ZmnSCPxj design and offers strict advantages
over the older Decker-Wattenhofer leaf mechanisms:

| Property | DW arity-1/-2 (legacy) | PS arity-3 (canonical) |
|---|---|---|
| Per-leaf CSV consumption per state advance | High (decrementing nSequence) | **Zero** (TX chaining) |
| Per-state revocation keys + watchtower | Required | **Not needed** for leaf state |
| Inner BOLT-2 HTLCs (bidirectional) | Yes | **Yes** (verified in regtest) |
| Number of state advances before exhaustion | Bounded by `states_per_layer × DW_MAX_LAYERS` | **Bounded only by channel amount** (one fee per advance) |
| Online cohort for state advance | Leaf cohort (1 or 2 clients + LSP) | Leaf cohort (1 client + LSP) |

**Migration / legacy:** `--arity 1` (single-client DW) and `--arity 2`
(two-client DW) remain implemented for backward compatibility with
older deployments. New deployments should not use them.

## The arity types

| Value | Mechanism | Status |
|-------|-----------|--------|
| `3` / `FACTORY_ARITY_PS` | **Pseudo-Spilman chained leaves** — TX chaining instead of DW nSequence; zero per-leaf CSV; chain-level non-revocability | **Canonical, recommended for all new deployments** |
| `2` | Two-client leaves, 3-of-3 DW with shared state | Legacy (kept for migration) |
| `1` | Single-client leaves, 2-of-2 DW with per-leaf independent counter | Legacy (kept for migration) |
| `4`+ | Wide branching for mid-tree / near-root levels (interior fan-out, no leaf semantics) | Caps tree depth as client count scales |

Arities `1`, `2`, and `3` describe distinct leaf/state mechanisms.
Values `≥ 4` are pure branching factors applied at interior tree
levels — they don't change the leaf state machine, just how many
children fan out at that level.

## ZmnSCPxj's canonical recommendation

From the Delving Bitcoin thread ([t/1242](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories-with-pseudo-spilman-leaves/1242)):

> "The best arity for leaf nodes is 2 … The tree can have low arity near
> the leaves, then increase the arity when building nodes a few levels
> away from the leaves. Beyond a few layers away from the leaves, we
> could entirely remove state transactions (i.e. those with decrementing
> nSequences) … a root timeout-sig-tree that backs multiple
> timeout-tree-structured Decker-Wattenhofer mechanisms."

> "Kickoff nodes may also have an arity of 1 … this reduces the number of
> affected clients if one client wants to unilaterally exit."

The canonical SuperScalar shape combines:

1. **Low-arity leaves** (PS for new deployments; arity-2 DW for legacy)
2. **Wider arity mid-tree** (e.g. `4`, `8`) to cap total tree depth
3. **Static near-root** — kickoff-only nodes near the root with no DW
   state transitions, only CLTV timeouts

Reason to prefer higher arity mid-tree and at the root: every DW state
layer contributes `step_blocks * (states_per_layer - 1)` blocks of
BIP-68 CSV to the exit path. Deep trees of uniform low arity stack
this delay linearly in tree depth. Mid-tree wide branching collapses
multiple levels into one, capping total depth. Static-near-root removes
state transitions from the levels closest to the root, eliminating
their CSV contribution entirely.

## Current implementation status (v0.1.x)

**As of this document's commit, the implementation has delivered the
full canonical SuperScalar design — TRUE N-way mixed-arity interior
branching + static-near-root variant (Phases 0-4 of the mixed-arity
plan, all merged):**

- PS leaves at any N (proven on regtest at N=2-32 with full per-party
  accounting; unit-tested at N=64 and N=128)
- DW arity-1 and arity-2 leaves (legacy, kept for migration)
- **TRUE N-way interior branching (Phase 2 — merged in PR #104).**
  `--arity 2,4,8` produces an authentic 3-level fan-out: root arity-2 →
  mid arity-4 → leaves arity-8 (per `arity_at_depth`). Unit tests assert
  per-level `n_outputs` and full N=64 lifecycle is exercised on regtest
  with per-party `econ_assert_wallet_deltas`.
- **N-way leaves (Phase 2 — merged in PR #104).** Arity-A leaves produce
  `A + 1` outputs (A channels + 1 L-stock). Unit-tested at A=8 (9 outputs,
  per-channel MuSig SPK distinct).
- **Static-near-root variant (Phase 3 — merged in PR #105).**
  `--static-near-root N` turns the top N tree depths into kickoff-only
  nodes (no paired `NODE_STATE`, no DW counter, only CLTV-timeout escape
  via `nsequence=0xFFFFFFFE`). DW counter `n_layers` shifts by `N`,
  eliminating CSV contribution from those layers entirely. Children of a
  static node spend its outputs directly (no state intermediary).
  Unit-tested + regtest-tested at N=12 `{2,4}` `static_threshold=1` with
  full per-party `econ_assert_wallet_deltas`.
- **CLI hardening + BOLT-2016 ceiling check (Phase 4 — this commit).**
  `--arity` accepts 1-15 per level; the LSP refuses to start when the
  configured shape's worst-path ewt exceeds BOLT's 2016-block
  `final_cltv_expiry` ceiling, with the error pointing operators at
  this document. Implemented in `cli_arity.c` against
  `factory_compute_ewt_for_shape()` (pure-math simulator); covered by
  `test_cli_arity_*` unit tests asserting the specific error strings.

The supported deployment ceiling is now **N=128 clients per factory**
with mixed arity `{2,4,8}` + `--static-near-root 2` (unit-tested with
per-shape ewt assertion) — well within BOLT 2016. End-to-end regtest
at N=64 with `{2,4,8}` and N=12 with `{2,4} + static-near-root=1` is
also exercised.

## Recommended shapes (canonical, all available today)

All of these are implemented and unit-tested as of v0.1.14+:

| Client count | Recommended shape | Leaf type | Notes |
|---|---|---|---|
| ≤ 16 | `--arity 3` (uniform PS) | PS | Depth ≤ 4, no mixed needed |
| 17-32 | `--arity 3,4` (PS root, DW arity-4 leaves) | DW arity-4 | Adds one fan-out level |
| 33-64 | `--arity 2,4,8` | DW arity-8 | ZmnSCPxj's canonical mid-tree shape |
| 65-128 | `--arity 2,4,8 --static-near-root 1` | DW arity-8 | Static gate at root reduces depth contribution |
| 65-128 | `--arity 2,4,8 --static-near-root 2` | DW arity-8 | The design target — only two DW layers remain |

The CLI rejects any combination whose worst-path `ewt` would exceed BOLT
2016 with a clear error pointing at this document.

## Worked examples (mainnet defaults: step_blocks=144, states_per_layer=4)

Each layer contributes `144 * (4-1) = 432` blocks of CSV. PS leaves
contribute 0 (the leaf layer is subtracted from the running total). All
values are produced by the same `factory_compute_ewt_for_shape()` the
CLI uses for validation.

| Clients | `--arity` | `--static-near-root` | Leaf type | Tree depth | DW layers (after PS subtraction) | ewt blocks | vs BOLT 2016 |
|---|---|---|---|---|---|---|---|
|   8 | `3` (uniform PS)              | 0 | PS  | 3 | 3 | 1296 | Under |
|  16 | `3` (uniform PS)              | 0 | PS  | 4 | 4 | 1728 | Under |
|  32 | `3,4` (PS root, DW arity-4 leaves) | 0 | DW arity-4 | 2 | 3 | 1296 | Under |
|  64 | `2,4,8` (DW arity-8 leaves)   | 0 | DW arity-8 | 3 | 4 | 1728 | Under |
| 128 | `2,4,8` (DW arity-8 leaves)   | 0 | DW arity-8 | 3 | 4 | 1728 | Under |
| 128 | `2,4,8`                       | 1 | DW arity-8 | 3 | 3 | 1296 | Generous slack |
| 128 | `2,4,8`                       | 2 | DW arity-8 | 3 | 2 |  864 | The design target |
|  32 | `3` (uniform PS — too deep)   | 0 | PS  | 5 | 5 | 2160 | **EXCEEDS — rejected** |
|  64 | `2` (uniform binary DW)       | 0 | DW arity-2 | 6 | 6 | 2592 | **EXCEEDS — rejected** |
| 128 | `2` (uniform binary DW)       | 0 | DW arity-2 | 7 | 8 (capped) | 3456 | **EXCEEDS — rejected** |

Regtest and testnet deployments use `step_blocks = 10` (not 144), so the
CSV budget is non-binding at any client count — but that's a test
artifact, not a property of the design. The CLI validator uses the
operator's actual `--step-blocks` value, so regtest runs never trip the
ceiling.

## CSV budget math

The factory's worst-case `early_warning_time` is the sum across all DW
layers of `step_blocks * (states_per_layer - 1)`, with one leaf-layer's
worth subtracted when any leaf is a PS leaf (TX chaining replaces
nSequence at the leaf). For static-near-root, the top N depths
contribute zero — the DW counter only carries layers `[N, depth]`.

Closed form: `ewt = (depth + 1 - static_threshold) * step_blocks * (states_per_layer - 1)`,
clamped to `[1 * per_layer, DW_MAX_LAYERS * per_layer]`, then minus
`per_layer` if any leaf is PS.

The `factory_compute_ewt_for_shape()` API in `factory.h` returns this
value for any candidate `(level_arities, leaf_arity, n_clients,
static_threshold, step_blocks, states_per_layer)` tuple without
building or signing anything. The CLI calls it once per startup before
spending capital on funding.

## Setting the arity (current capability)

Single arity (applies uniformly):

```
superscalar_lsp --arity 3 --clients 16 ...
```

Mixed per-level CLI now produces TRUE N-way fan-out (Phase 2 merged):

```
# 64 clients, mixed PS leaves + arity-4 mid + arity-2 root:
superscalar_lsp --arity 2,4,3 --clients 64 ...

# 64 clients, all-DW mixed (no PS): root arity-2 → mid arity-4 → leaves arity-8:
superscalar_lsp --arity 2,4,8 --clients 64 ...
```

Supported values today are 1–15 per level (capped because arity-A
leaves need A+1 outputs and `FACTORY_MAX_OUTPUTS = 16`). The CLI
rejects shape combinations whose worst-path ewt would exceed BOLT 2016
with a clear error string referencing this document.

## Implementation pointers

- `include/superscalar/factory.h:15` — `FACTORY_MAX_OUTPUTS = 16` (Phase 1
  bumped from 8 → 16 to support up to arity-15 leaves with L-stock)
- `include/superscalar/factory.h:185-190` — `uint8_t level_arity[FACTORY_MAX_LEVELS=8]`
- `src/factory.c::factory_set_level_arity` — populates per-level arity
- `src/factory.c::arity_at_depth` — lookup; last entry wraps deeper levels
- `src/factory.c::subtree_is_leaf, split_clients_for_arity` — core N-way
  splitter (Phase 2). For arity-2 falls back to legacy binary algorithm
  bit-identically (tested by `test_factory_nway_backward_compat`).
- `src/factory.c::build_subtree` — N-way recursive builder (Phase 2);
  also handles static-near-root depths (Phase 3) by emitting kickoff-only
  nodes with `is_static_only = 1`
- `src/factory.c::setup_nway_leaf_outputs` — N-way leaf outputs:
  N channels + 1 L-stock (Phase 2)
- `src/factory.c::simulate_tree` — N-way tree shape simulator (Phase 2)
- `src/factory.c::dw_n_layers_for` — translates `tree_depth +
  static_threshold` to DW counter `n_layers` (Phase 3)
- `src/factory.c::factory_set_static_near_root` — public API to set the
  static-near-root threshold (Phase 3)
- `src/factory.c::node_nsequence` — returns `0xFFFFFFFE` for `is_static_only`
  nodes (Phase 3)
- `tools/superscalar_lsp.c` — default `leaf_arity` (3 = PS, Phase 0);
  delegates `--arity` and `--static-near-root` parsing + BOLT-2016
  ceiling check to `cli_arity.c` (Phase 4)
- `include/superscalar/cli_arity.h` + `src/cli_arity.c` —
  `cli_parse_arity_spec()`, `cli_parse_static_near_root()`,
  `cli_validate_shape_for_bolt2016()` (Phase 4)
- `src/factory.c::factory_compute_ewt_for_shape` — pure-math ewt
  simulator the CLI uses for validation, no factory_t needed (Phase 4)
- `tests/test_cli_arity.c` — unit tests asserting specific error
  strings for each invalid input + ewt math for canonical shapes
  (Phase 4)

## Caveats

- The `factory_set_arity()` legacy API (single-value) remains for
  backward compatibility. New code should use `--arity` on the CLI
  (which maps to `factory_set_level_arity` when a comma-list is passed).
- Arity changes between rotations are allowed, but clients must be
  online during the rotation window to accept the new shape.
- The CSV numbers above assume `step_blocks = 144` and
  `states_per_layer = 4`. Changing either rescales the budget; the
  mixed-arity guidance stays directionally correct but the specific
  recommended shapes shift.
- DW arity-1 and arity-2 leaves remain in the codebase and are tested,
  but new deployments should default to `--arity 3` (PS) per the
  canonical design.
