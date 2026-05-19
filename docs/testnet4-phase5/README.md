# testnet4 Phase 5 — v0.2 PS-SuperScalar release validation

Purpose: prove on real chain that every canonical SuperScalar shape from the
design docs works end-to-end. Evidence captured here gates the **v0.2 tag**.

References:
- `docs/pseudo-spilman.md` — PS leaf design contract (no revocation by design)
- `docs/factory-arity.md` — wide-leaf + mixed-arity + static-near-root shapes
- `docs/ps-subfactories.md` — k² sub-factory ceremony (Phase 1-4 merged)
- `docs/signet-ps-n8-procedure.md` — the original manual procedure being lifted to t4
- `docs/testnet4-phase5/METHODOLOGY.md` — how to run, conservation math, sweep-back protocol

## Shape × variant matrix

Status legend: `[ ]` pending, `[~]` in flight, `[x]` PASS, `[!]` FAIL.

| Shape | N | ARITY | static | k (sub) | V1 lifecycle | V2 force-close | V3 chain-advance | V4 sub-factory adv | V5 breach+WT | V6 mid-flight restart |
|---|---:|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| [3a](shape-3a-N8-ARITY3/) | 8 | 3 | 0 | 1 | `[ ]` | `[ ]` | — | — | — | — |
| [3b](shape-3b-N8-ARITY34-STATIC1/) | 8 | 3,4 | 1 | 1 | `[ ]` | `[ ]` | — | — | — | — |
| [3c](shape-3c-N64-ARITY248-STATIC1/) | 64 | 2,4,8 | 1 | 1 | — | `[~]` | — | — | — | — |
| [3e](shape-3e-N4-ARITY3-K2/) | 4 | 3 | 0 | 2 | `[ ]` | `[ ]` | `[ ]` | `[ ]` | — | — |
| [3e+](shape-3epp-N16-ARITY3-K2/) | 16 | 3 | 0 | 2 | — | `[ ]` | `[ ]` | `[ ]` | — | — |
| [3f](shape-3f-N64-ARITY24-K2-STATIC1/) | 64 | 2,4 | 1 | 2 | `[ ]` | `[ ]` | `[ ]` | `[ ]` | `[ ]` | `[ ]` |
| 3d (N=128) | 128 | 2,4,8 | 2 | 1 | DEFERRED to v0.3 — gated on #212 SF-SCALE-128 regtest pass |

Total: **18 runs** for v0.2 (excluding 3d). 3f is the all-features integration
test; runs last so simpler-shape regressions surface first.

## Definition of done (v0.2 tag)
1. 17 of 18 variants documented with on-chain evidence (V6 may slip to v0.2.1)
2. Conservation math holds for every PASS run
3. All sat draws from pools recorded; all pools swept back to `superscalar_test`
4. CLN testnet4 stash UNTOUCHED beyond the initial 1 BTC draw

## Pool ledger
Operational state: `/root/SuperScalar-ops/t4-pool-ledger.txt` on the VPS.
Updated as each shape×variant is assigned, runs, and sweeps back.
