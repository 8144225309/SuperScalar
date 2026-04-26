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

**As of this document's commit, the implementation is undergoing a
phased upgrade to deliver the full canonical design:**

- ✅ PS leaves at any N (proven on regtest at N=2-32 with full per-party
  accounting; unit-tested at N=64 and N=128)
- ✅ DW arity-1 and arity-2 leaves (legacy)
- ⚠️ **TRUE N-way interior branching: NOT YET IMPLEMENTED.** Currently
  the builder treats arities ≥4 as a leaf-size hint only; the resulting
  tree is binary regardless of `--arity 2,4,8` input. This is being
  fixed in the upcoming "Phase 2" work
  ([implementation plan](https://github.com/8144225309/SuperScalar/pull/_TBD_)).
- ⚠️ **Static-near-root variant: NOT YET IMPLEMENTED.** Coming in
  "Phase 3" of the same work.

Until N-way + static-near-root land, the supported deployment ceiling
is **N=16 clients per factory** with uniform `--arity 3` (PS). Beyond
N=16 you need either:
- Multiple factories of ≤16 clients each (works today), OR
- Wait for Phase 2/3 to land for single-factory N>16 with mixed arity

The deployment table below shows the **target shapes** once N-way + static-near-root are implemented. Use the "Today" column for current capability.

## Recommended shapes (target vs today)

| Client count | Today (canonical) | Target (after N-way + static) | Notes |
|---|---|---|---|
| ≤ 8 | `--arity 3` (uniform PS) | same | Depth stays shallow; no mixed needed |
| 9-16 | `--arity 3` (uniform PS) | same | Still under BOLT 2016 with binary interior |
| 17-32 | run multiple factories of ≤16 each | `--arity 3,4` (PS leaves + arity-4 mid) | Adds one fan-out level |
| 33-64 | run multiple factories of ≤16 each | `--arity 3,4,8` | ZmnSCPxj's canonical mid-tree shape |
| 65-127 | run multiple factories of ≤16 each | `--arity 3,4,8 --static-near-root 1` or `--arity 3,2,4,8` | Static gate at root for further depth reduction |

**Today, uniform `--arity 3` is safe up to 16 clients per factory on
mainnet.** For higher client counts, the supported scale path is to run
multiple factories.

## CSV budget math

With `FACTORY_MAX_SIGNERS = 128` (1 LSP + up to 127 clients) and mainnet
defaults (`step_blocks = 144`, `states_per_layer = 4`, giving
`144 * (4-1) = 432` blocks of CSV per layer):

| Shape | Tree depth | DW layers | Worst-path CSV | vs BOLT 2016 |
|---|---|---|---|---|
| Uniform PS, 16 clients | 4 layers | 4 | ~1728 blocks | Under |
| Uniform PS, 8 clients | 3 layers | 3 | ~1296 blocks | Under |
| Uniform PS, 64 clients (binary today) | 6 layers | 6 | ~2592 blocks | **EXCEEDS** |
| Uniform PS, 128 clients (binary today) | 7 layers | 7 | ~3024 blocks | **EXCEEDS** |
| **Target:** PS leaves + `{2,4,8}` interior, 64 clients | 3 layers | 3 | ~1296 blocks | Under (after Phase 2) |
| **Target:** PS + `{2,4,8}` + `static_near_root=1`, 128 clients | 4 layers | 3 | ~1296 blocks | Under (after Phase 3) |
| **Target:** PS + `{2,4,8}` + `static_near_root=2`, 128 clients | 4 layers | 2 | ~864 blocks | Generous slack (after Phase 3) |

Regtest and testnet deployments use `step_blocks = 10` (not 144), so
CSV budget is non-binding at any client count — but that's a test
artifact, not a property of the design.

## Setting the arity (current capability)

Single arity (applies uniformly):

```
superscalar_lsp --arity 3 --clients 16 ...
```

Mixed per-level CLI accepts the syntax today but the builder collapses
to binary internal tree. After Phase 2 lands, this will produce the
TRUE N-way fan-out:

```
# Target after Phase 2 — 64 clients, mixed PS leaves + arity-4 mid + arity-8 root:
superscalar_lsp --arity 3,4,8 --clients 64 ...
```

Supported values today are 1–16 per level. The CLI should reject
shape combinations that would exceed BOLT 2016 (Phase 4 work).

## Implementation pointers

- `include/superscalar/factory.h:15` — `FACTORY_MAX_OUTPUTS = 8` (will
  bump to 16 in Phase 1 to support arity-15 leaves with L-stock)
- `include/superscalar/factory.h:185-190` — `uint8_t level_arity[FACTORY_MAX_LEVELS=8]`
- `src/factory.c:606-622` — `factory_set_level_arity()` populates per-level arity
- `src/factory.c:554-560` — `arity_at_depth()` lookup; last entry wraps deeper levels
- `src/factory.c:781-939` — `build_subtree()` (currently binary; Phase 2 makes N-way)
- `src/factory.c:564-604` — `simulate_tree()` (currently binary; Phase 2 makes N-way)
- `tools/superscalar_lsp.c:1036` — default `leaf_arity` (currently 2; updated to 3 in Phase 0)

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
