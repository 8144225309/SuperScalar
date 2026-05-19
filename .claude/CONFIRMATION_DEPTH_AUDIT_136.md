# Confirmation depth policy audit (ticket #136)

**Date:** 2026-05-19
**Status:** Findings ready for lib team action.
**Mainnet gate item:** §10 audit prereq #5.
**Helper:** `regtest_network_safe_confirmation_depth()` at `src/regtest.c:1551`
returning regtest=1, signet/testnet/testnet4=3, mainnet=6, unknown=6.

## Scope

Walk every raw-integer comparison on a `get_confirmations()` result and decide
whether it is a **finality check** (where the value must be the per-network
safe depth) or a **presence/height/loop-control** check (where a small integer
is correct and the helper would be wrong).

## Method

```
grep -rn -E "confs\s*(<|>|>=|<=|==|!=)\s*[0-9]+" src/
```

Each hit reviewed in context. `get_confirmations` returns:
- `>= 1` confirmation count when confirmed,
- `0` in mempool,
- `-1` not found anywhere.

## Findings

### A. Real finality checks — should call the helper

#### A1. `src/sweeper.c:440`
```c
if (confs >= 3) {
    /* Confirmed — remove entry */
    e->state = SWEEP_CONFIRMED;
    ...
}
```
**Verdict:** This decides when a sweep TX is final enough to retire its entry
from the active list. On mainnet this is UNDER-confirming (helper returns 6).
**Fix:**
```c
int safe = regtest_network_safe_confirmation_depth(sw->rt);
if (confs >= safe) { ... }
```
Note: `sweeper_t` may not currently hold a `regtest_t *`; if not, threading
that through is the small adjacent change.

#### A2. `src/factory_recovery.c:188`
```c
if (nodes[i].confs < 1) return 0;
```
**Verdict:** Leaf-node finality is what gates whether the factory is
recoverable. Magic-1 is wrong on mainnet (we'd accept a single-conf reorg
risk for what should be 6).
**Fix:** Replace `1` with the helper's value.

### B. Not finality — keep as-is

These are presence / height-recording / loop-control checks. The helper's
network-tuned value would change semantics, not just numerics.

| Site | Code | Why it's NOT finality |
|---|---|---|
| `src/sweeper.c:447` | `if (confs < 0)` | TX not found anywhere — sentinel check, value is the API's not-found sentinel. |
| `src/sweeper.c:464` | `if (confs >= 1)` | Records `confirmed_height` once any confirmation exists. Block-height capture, not finality. |
| `src/jit_channel.c:819` | `if (fund_confs < 0)` | TX not found sentinel — same as sweeper:447. |
| `src/jit_channel.c:851` | `if (commit_confs >= 0)` | Commitment TX **exists somewhere** (mempool or chain). Presence flag for state transition, not finality. |
| `src/lsp_channels.c:7401` | `if (confs < 1) continue;` | Loop-control: skip txids that haven't appeared on-chain yet at all. Pre-screening, not finality. |
| `src/factory_recovery.c:231` | `if (nd->confs >= 1 \|\| broadcast_done[i]) continue;` | Skip nodes that are already on-chain or already broadcast. Bookkeeping, not finality. |
| `src/factory_recovery.c:249` | `parent_ok = par && ((par->confs >= 1) \|\| ...);` | Parent presence test. The finality decision is upstream at line 188 (A2). |
| `src/factory_recovery.c:353` | `if (chain && nodes[i].confs >= 1) n_confirmed++;` | Count nodes that exist on-chain. Tallying, not finality. |
| `src/factory_recovery.c:356` | `if (chain && nodes[i].confs >= 1) n_leaf_confirmed++;` | Same. |
| `src/lsp_fund.c:164` | `if (min_confs < 1) min_confs = 1;` | Clamp user-supplied minimum to ≥1. Input sanitization. |

### C. Sites the original report mis-flagged

Carried for traceability — sites originally cited but not confirmed as
finality checks by this audit. (Not bugs; just clarifying.)

- `src/sweeper.c:464` — flagged as raw `1`; actual semantic is height
  recording (see B above).
- `src/lsp_channels.c:6942` — line number stale; nearest match
  (`lsp_channels.c:7401`) is loop-control, not finality (see B above).
- `src/jit_channel.c:851` — flagged as raw `commit_confs` propagation;
  actual semantic is presence (see B above).

## Summary

| Finality sites to fix | Sites to leave alone |
|---|---|
| 2 | 10 |

Both A1 and A2 are one-line changes plus the small adjacency of making the
`regtest_t *` reachable from the call site (already reachable in some lib
plumbing; needs a one-arg threading for sweeper).

## Effect on §10 audit prereq #5

> Confirmation depth policy (#136) enforced for every code path that depends
> on funding finality.

The two fixes above close the gap. After they land, this checkbox can flip
to `[x]`.
