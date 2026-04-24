# Factory arity: picking the right tree shape

SuperScalar factories are Decker–Wattenhofer trees. Each internal level's
branching factor ("arity") is configurable independently of the others
via the `--arity` CLI flag. Picking the wrong shape at large client
counts stacks too much BIP-68 CSV delay along the exit path and pushes
HTLC `final_cltv_expiry` past BOLT's 2016-block ceiling — clients
routed through the factory then refuse to accept forwards because the
worst-case exit time exceeds what they consider safe. This doc explains
the tradeoff and recommends shapes.

## The three arity types

| Value | Meaning | Primary use |
|-------|---------|-------------|
| `1`   | Single-client leaves, 2-of-2 DW with per-leaf independent counter | Low-uptime clients; smallest exit blast radius per client |
| `2`   | Two-client leaves, 3-of-3 DW with shared state | "Best arity for leaf nodes" per ZmnSCPxj — smallest online cohort (2 clients + LSP) for leaf updates |
| `3` / `FACTORY_ARITY_PS` | Pseudo-Spilman chained leaves, 2-of-2 with TX chaining instead of DW nSequence | LSP-unidirectional liquidity sales; zero CLTV delta contribution |
| `4`+  | Wide branching for mid-tree / near-root levels | Caps tree depth as client count scales |

Arities `1`, `2`, and `3` describe distinct leaf/state mechanisms. Values
`>= 4` are pure branching factors applied at interior tree levels —
they don't change the leaf state machine, just how many children fan
out at that level.

## The ZmnSCPxj recommended shape

From the Delving Bitcoin thread ([t/1242](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories-with-pseudo-spilman-leaves/1242)):

> "The best arity for leaf nodes is 2 … The tree can have low arity near
> the leaves, then increase the arity when building nodes a few levels
> away from the leaves. Beyond a few layers away from the leaves, we
> could entirely remove state transactions (i.e. those with decrementing
> nSequences) … a root timeout-sig-tree that backs multiple
> timeout-tree-structured Decker-Wattenhofer mechanisms."

And:

> "Kickoff nodes may also have an arity of 1 … this reduces the number of
> affected clients if one client wants to unilaterally exit."

Reason to prefer higher arity mid-tree and at the root: every additional
DW state layer contributes `step_blocks * (states_per_layer - 1)` blocks
of BIP-68 CSV to the exit path. Deep trees of uniform low arity stack
this delay linearly in tree depth. Mid-tree wide branching collapses
multiple levels into one, capping total depth.

## The math at our target scale

With `FACTORY_MAX_SIGNERS = 128` (1 LSP + up to 127 clients) and mainnet
defaults (`step_blocks = 144`, `states_per_layer = 4`, giving
`144 * (4-1) = 432` blocks of CSV per layer):

| Shape | Tree depth | Worst-path CSV | vs BOLT 2016-block ceiling |
|-------|-----------|----------------|-----------------------------|
| Uniform arity-2, 127 clients | 7 layers | ~3024 blocks (~21 days) | **EXCEEDS** |
| Mixed 2 / 4 / 8 (leaf / mid / root), 127 clients | 4 layers | ~1728 blocks (~12 days) | Under, but tight |
| Uniform arity-2, 16 clients | 4 layers | ~1728 blocks | Under |
| Uniform arity-2, 8 clients | 3 layers | ~1296 blocks | Under |

**Uniform arity-2 is safe up to ~16 clients on mainnet.** Beyond that,
mixed arity is required for the `final_cltv_expiry` budget to hold.
On regtest with `step_blocks = 10`, uniform arity-2 is fine at any
supported client count — but that's a test artifact, not a property of
the design.

## Setting the arity

Single arity (applies uniformly):

```
superscalar_lsp --arity 2 --clients 8 ...
```

Mixed per-level (comma-separated, deepest → shallowest, the last entry
applies to all deeper levels):

```
# 127 clients, mixed 2/4/8 — ZmnSCPxj's recommended shape:
superscalar_lsp --arity 2,4,8 --clients 127 ...

# 32 clients, mixed 2/4:
superscalar_lsp --arity 2,4 --clients 32 ...
```

Supported values are 1–16 per level. Values `1`, `2`, and `3` (PS) are
the leaf-mechanism choices; `4`+ are pure branching factors for
interior levels.

## Recommendation by deployment

| Client count | Recommended `--arity` | Why |
|-------------|----------------------|-----|
| ≤ 8 | `2` (uniform) | Depth stays shallow; no need for mixed |
| 9–16 | `2` (uniform) | Still under BOLT ceiling |
| 17–32 | `2,4` | One extra level of fan-out at the root |
| 33–64 | `2,4,8` | ZmnSCPxj's canonical mid-tree shape |
| 65–127 | `2,4,8` or `2,2,4,8` | Add a leaf-kickoff layer for exit isolation |

Regtest and testnet deployments at any client count may use uniform
arity-2 — the `step_blocks` scaling makes the CSV budget nonbinding.

## Implementation

- `include/superscalar/factory.h:185-190` — `uint8_t level_arity[FACTORY_MAX_LEVELS=8]`.
- `src/factory.c:606-622` — `factory_set_level_arity()` populates it and
  re-initializes the DW counter from the resulting depth.
- `src/factory.c:554-560` — `arity_at_depth()` lookup; last entry wraps.
- `src/factory.c:849-895` — `build_subtree()` branches per depth.
- `tools/superscalar_lsp.c:1261-1290` — `--arity` parsing (comma or single).

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
