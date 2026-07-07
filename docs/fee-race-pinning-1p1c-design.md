# Fee-race hardening: pinning resistance + submitpackage 1p1c — design (#97)

Design-only (no code yet). Assessed against `main` on 2026-07-06. This is the last
mainnet-track item on the trustless-completion roadmap (docs/trustless-completion-plan.md
Layer 3 "Win the fee-race"). It also closes gap-scan **WT F5** (fee_bump metadata inert).

## 1. Scope — what #97 actually is

The fee-race *mechanism* is **already done and proven** (roadmap P2a/P2b/P3, regtest +
real signet). #97 is **not** "build fee-bumping." It is the **last-mile mainnet
reliability layer**: making the (existing) CPFP recourse win against a *realistic
adversary* — a high dynamic mempool min-feerate and deliberate **pinning** — not just a
frictionless regtest/signet mempool.

"Done" = the standalone WT's recourse confirms before its CSV/CLTV deadline even when
(a) the recourse parent is below the node's dynamic min-feerate, and (b) an adversary
tries to pin or replace-cycle it — proven adversarially on regtest and on signet.

## 2. Current state (read from the code)

### 2.1 What exists and is proven
- **Deadline-aware CPFP escalator** — `htlc_fee_bump.c`: linear feerate ramp
  `start → max` as the deadline approaches, RBF-threshold gating, urgency, and a
  **persisted schedule** so a mid-bump WT restart resumes instead of rebasing
  (`watchtower.c:1704–1742`, `persist_save_pending`). Proven: roadmap **P2a**
  (`SS_HIFEE_BUMP=1`) bumped a deprioritised penalty 5501→11399 sat/kvB to confirm.
- **P2A anchors on every force-close cascade tx** — commitment (`use_cpfp_anchor`,
  PR #391) and all six factory-tree node builders (`use_tree_anchor`, PR #392). Keyless
  P2A (`51024e73`), proven present + spendable on **real signet**.
- **TRUC/v3 where it matters most** — the commitment (`channel.c:949`) and the channel
  revocation penalty (`channel.c:1252/1421`, RBF via nSequence `0xFFFFFFFD`) are v3.
- **Client-driven poison CPFP** — the #53 L-stock poison is fixed-fee (agg-sig binds its
  outputs ⇒ not RBF-able); its only bump is CPFP on the client's own `tr(client_key)`
  output. Proven: roadmap **P2b** (poison confirmed in 1 block).

### 2.2 The two mainnet gaps

**Gap 1 — CPFP is two separate `sendrawtransaction`s, not a package.** The broadcast
layer only has `sendrawtransaction` (`chain_backend_rpc.c:261`; no `submitpackage`
anywhere). The WT CPFP loop *first requires the parent already in the mempool*
(`watchtower.c:1697–1702`, `parent_in_mempool` pre-flight → otherwise
`"CPFP skipped: parent not in mempool"`), then broadcasts the child separately
(`send_raw_tx`, `:1713`). On mainnet, when the **dynamic mempool min-feerate exceeds the
recourse's baked-in feerate**, `sendrawtransaction(parent)` is rejected
(`"min relay fee not met"`, handled at `regtest.c:986`) → the parent never enters → the
escalator has nothing to attach the child to → **the recourse cannot be fee-bumped into a
block.** This is WT F5 / #52 in its sharpest form: raising the *child's* feerate is
useless if the *parent* can't enter the mempool. Regtest/signet never exposed this because
their min-feerate floor is ~0.

**Gap 2 — pinning is untested, and the v2 recourse txs are pin-vulnerable.** The
factory-tree nodes (`factory.c:2331`, `nVersion=2`) and the HTLC penalty (`channel.c:2686`,
v2 *intentionally* — "TRUC allows only 1 unconfirmed descendant per V3 tx") are v2. A v2
parent's P2A anchor has **no descendant-size limit**, so an adversary can attach a large
low-feerate child to the *keyless* anchor and pin it. The v3 txs (commitment, channel
penalty) are pin-resistant by TRUC's 1-child/1000-vB rule — but this has **never been
adversarially tested**. All existing "wins the race" proofs run in a frictionless mempool.

## 3. Design — three workstreams

### W1 — `submitpackage` 1p1c broadcast (fixes Gap 1; highest value)

Replace the two-step CPFP with an atomic **1-parent-1-child** package submission.

- **RPC layer** (`chain_backend_rpc.c` + `regtest.c` for tests): add a `submitpackage`
  method. Params `[[parent_hex, child_hex]]` (+ optional `maxfeerate`/`maxburnamount`).
  Parse the per-tx results (`txid`, `vsize`, `fees`) and the package-level message; map
  the error taxonomy (partial acceptance, `package-not-child-of-parent`,
  `already-in-mempool`, `package-fee-too-low`).
- **WT broadcast** (`watchtower.c` CPFP loop): when a recourse needs bumping, build the
  package `[recourse_parent, cpfp_child]` and `submitpackage` it — instead of depending on
  the parent already being in the mempool. This carries the parent in **even below the
  dynamic min** (the child's fee lifts the *package* feerate over the floor). The
  `parent_in_mempool` pre-flight is *relaxed for the package path* (the whole point is the
  parent may not be in the mempool yet); keep the two-step path as a fallback.
- **Package-aware feerate** (`htlc_fee_bump`): today `htlc_fee_bump_calc_feerate` sizes the
  child's fee for the *child's* vsize. For 1p1c it must size the child so the **package**
  feerate `(parent_fee + child_fee) / (parent_vsize + child_vsize)` clears the target,
  since the parent contributes ~0 fee. Parent vsize is known at registration → add a
  package-feerate helper.
- **Persist the package, not a bare child**: the restart-resume schedule
  (`persist_save_pending`, `:1720`) must record enough to re-`submitpackage` the pair, not
  re-broadcast a child whose parent is absent.
- **Fallback / capability probe**: probe `submitpackage` support once (Core ≥ 24 for the
  RPC); on absence or package rejection, fall back to the current two-step broadcast.
- **Client self-exit path**: mirror 1p1c for the client's own CPFP in the force-close
  cascade (the client is the fee payer there).

### W2 — TRUC/v3 pin-resistance (addresses Gap 2; scope-lever, likely audit-driven)

For a P2A anchor to be *pin-resistant* (not merely CPFP-able) its parent must be v3/TRUC:
the 1-child + 1000-vB descendant caps stop a low-feerate pin, and TRUC children are
replaceable so the honest party can out-bid. Per-tx decision:

| Recourse tx | Version now | Recommendation |
|---|---|---|
| Commitment | v3 ✓ | keep; add adversarial pin test |
| Channel revocation penalty | v3 ✓ | keep; add adversarial pin test |
| L-stock poison | audit | likely v3 so its client-CPFP output is pin-resistant. **Caveat:** if the agg-sig commits to nVersion, changing it re-derives the sighash ⇒ a *construction* re-sign, not a hot-path change |
| Factory-tree nodes | v2 | **hard** — see below |
| HTLC penalty | v2 (intentional) | revisit "multiple HTLC descendants" rationale vs 1p1c-per-HTLC |

**Why tree-v3 is hard** (per roadmap Increment-2 notes): TRUC forbids a v3 child spending
a v2 parent, so pin-hardening a *leaf* node's anchor means the **whole tree chain** to it
must be v3; and TRUC's single-unconfirmed-child rule interacts awkwardly with multi-child
internal nodes and the 1000-vB descendant cap at N≈127. **Recommendation:** keep the tree
v2 for now and rely on: (a) tree txs are only broadcast in a *self-exit cascade the client
controls*, so the client can 1p1c each node via its own anchor; (b) the pinning surface is
bounded — the adversary controls neither the tree tx's other inputs nor its outputs, only
the shared *keyless* anchor, and a P2A child is itself replaceable. **Let W3 decide**:
convert to v3 only if the adversarial campaign exhibits a real exploit.

### W3 — Adversarial fee-race / pinning campaign (turns W2 from opinion into evidence)

The missing coverage: a *realistic-adversary* harness (regtest + signet).

- **Dynamic-floor test**: raise `-minrelaytxfee`/`-blockmintxfee` (or fill the mempool) so
  the recourse parent is below the floor. Prove `submitpackage` 1p1c confirms it; **control**
  = the current two-step path fails with `parent not in mempool`. *(This pairing is the W1
  proof — the floor test and W1 land together.)*
- **Pin test**: adversary attaches a large low-feerate child to the recourse's keyless P2A
  anchor before the honest child. Prove the honest CPFP still wins (v3 → TRUC replacement)
  or characterise the v2 residual precisely.
- **Replace-cycling test**: adversary RBF-cycles a competing spend near the deadline to
  evict the honest recourse repeatedly. Prove the escalator + 1p1c re-fires and confirms
  before the CSV/CLTV.
- **Signet propagation**: repeat the floor + 1p1c case on real signet (needs a v28+ path to
  a miner for 1p1c *relay*, not just local acceptance).

## 4. Design decisions / options

- **Bitcoin Core requirement.** `submitpackage` RPC: v24+. 1p1c package **relay** (network
  propagation to miners): **v28+**. For the WT's *own* node, v24 gets the package into its
  mempool; for it to reach miners, the path must include v28+ peers (increasingly common).
  Document the minimum and the fallback; the WT should still two-step-broadcast on older
  nodes.
- **Ephemeral anchors.** Our anchors are already keyless P2A (`51024e73`) matching BIP-431 —
  no change needed. (We move 240 sats out rather than a 0-fee output; the child can still
  bump. Sibling-eviction is a v28 nicety, not required.)
- **Who funds the child?** 1p1c does *not* remove the need for the WT to hold sats: the
  child spends the 240-sat anchor but must add real fee, so it needs a **funded WT input**.
  This ties into the WT operational/funding model (#62/#63) — confirm
  `watchtower_build_cpfp_tx` sources a funded input, and document the reserve.
- **Do not** casually change the agg-sig-bound poison outputs (re-sign coupling); treat any
  poison-version change as a construction migration.

## 5. Recommended phasing

1. **W1a** — `submitpackage` RPC + WT 1p1c broadcast + package-aware feerate + persist the
   package. Validate with **W3's dynamic-floor test** (they prove each other).
2. **W3** — the full adversarial campaign (floor, pin, replace-cycle). This *exposes*
   exactly which v2 txs (if any) are exploitably pinnable.
3. **W2** — targeted v3 conversions driven by W3 findings (poison first if needed; tree
   only if W3 shows a real exploit).
4. Signet propagation proof; fold the fee policy + Core-version requirement into
   `docs/mainnet-runbook.md`.

## 6. Risks / open questions

- `submitpackage` result parsing is fiddly (partial acceptance, already-in-mempool). Needs
  a careful, well-tested mapping.
- Restart mid-bump must re-submit the **package**, not a bare child (persist model change).
- WT child funding (the "who pays" question) is a real ops dependency, not just plumbing.
- Tree-v3's interaction with 16-output/multi-child internal nodes and the 1000-vB TRUC
  descendant cap at N≈127 — needs a dedicated spike if W3 forces it.

**The one decision for you:** how far to push **W2 (tree-v3)** vs. document-the-residual.
W1 + W3 deliver the bulk of the mainnet value (reliable CPFP below the floor + adversarial
proof). Full tree-v3 is a large, safety-critical accounting change that is probably best
sequenced *after* the external audit tells us whether the v2 tree residual is acceptable.
