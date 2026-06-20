# SuperScalar Trustless Hardening — Design & Test Plan (path to "perfect", and how we prove it)

Synthesis of the deep design dive (2026-06-20, 4 opus agents + Delving research). Companion to
`trustless-model-research-findings.md` (the problem inventory) and `test-harness-rigor-audit.md` (the bar).

## Executive summary
Two fixes decide "no security flaws": **#52 fee-bump** and **#53 revocation-gated poison**. Both are
**smaller than first framed — the machinery largely exists and is bypassed or unfunded, not missing.**
Atomicity (#46) is a known 2-phase protocol, no exotic crypto. The decisive *proof* is a **high-fee
mempool harness** with an anti-vacuity control. Adaptor signatures are NOT needed for state advance.

---

## 1. #52 Fee-bump — machinery EXISTS; the gap is funding + package relay + proof
**What already exists:** penalties are pre-signed **nVersion=3 (TRUC)** with a **BIP-433 P2A anchor**
(channel.h:20, channel.c:919); a full LND-style CPFP escalator exists (`watchtower_build_cpfp_tx`
watchtower.c:1645, `htlc_fee_bump`, CLI `--bump-budget-pct`/`--max-bump-fee`).
**The only real gap:** `watchtower_build_cpfp_tx` bails when `wt->wallet==NULL` (watchtower.c:1653) — a
secret-less standalone WT has no funds to pay the CPFP child. The P2A anchor is **anyone-can-spend**, so
no signing/secret is needed to bump — only money. So:
- **Fix:** designate a **funded external bumper** = the **client's** recovery daemon (already holds funds+keys).
  It scans the mempool/chain for the persisted penalty's P2A anchor outpoint and CPFPs it with its OWN
  UTXO+sig — fully trustless, WT signs nothing new. Reuses `watchtower_build_cpfp_tx`+`wallet_source_rpc`,
  just run where the money is.
- **Critical code change:** submit parent+child as a **1p1c package via `submitpackage`** (Core 28+), not
  bare `send_raw_tx` — so a below-min-relay parent still propagates. This is the single most important change.
- **Backstop (2-party commitment penalty ONLY):** pre-sign K≈3 conservative RBF fee-tiers so a lone WT can
  step up unaided. NOT viable for N-of-N poison/factory recourse (K full ceremonies too heavy).
- **Floor the registration feerate** so the bare parent always clears minrelayfee.
- **Residual (fundamental):** no funded bumper online + spike beyond top tier → miss. Same wall LND hits;
  mitigate with client self-interest, multiple/paid bumpers, WT liveness alert (#326). 
**The #52 task is partly EMPIRICAL:** the bump path was never proven under fee pressure (all greens were
low-fee). Proving it (§5 high-fee harness) is half the deliverable.
Sources: BIP-431 TRUC, BIP-433 P2A, Core 28 submitpackage, LND wtpolicy (static fee = the status quo bug).

## 2. #53 Revocation-gated poison — infra EXISTS but is BYPASSED; closes A AND B
**What already exists (vestigial):** `factory.revocation_secrets[]`, `l_stock_hashes[]` (=SHA256(secret)),
`factory_generate_flat_secrets()` (factory.h:288-304, factory.c:3131-3196), and `l_stock_hashes` are
**already shipped to clients in FACTORY_PROPOSE** (wire.c:658). A hashlock leaf builder exists
(tapscript.c:46). **But `build_l_stock_spk` (factory.c:238) ignores all of it** and the poison is pre-signed
over the **key-path** (factory.c:3257) → valid against the LIVE state = Scenario B.
**Fix (wire up the bypassed infra):**
- L-stock output Tapscript: key-path = leaf N-of-N (legit reallocation, unchanged); **Leaf P (NEW) =
  `OP_SIZE 0x20 OP_EQUALVERIFY OP_SHA256 <H_state> OP_EQUALVERIFY <agg_xonly> OP_CHECKSIG`** (hashlock +
  N-of-N checksig); Leaf L = existing LSP L&CSV fallback.
- **Move the poison MuSig sig from key-path → Leaf-P script-path sighash** (same `poison_signing_session`,
  only the message changes); preimage is a non-signed witness element added at broadcast. **REPLACE, do not
  augment** — if the key-path poison sig is still produced, B remains.
- Per-state secret revealed on advance; client verifies `SHA256(secret_s)==H_s` **before** countersigning
  s+1 (fail-closed, mirror `channel_verify_revocation_secret` channel.c:597) + write-through to wt.db
  (so the standalone WT can fire it — ties #44/#45/#55).
- **The real work = re-index secrets from global-epoch → per-(leaf, state-counter)** (and per chain-extension
  for PS/sub-factory sales-stock); the current global-epoch index can't gate per-leaf supersession.
**A/B closure:** B — a live state's secret is never revealed → Leaf-P preimage check fails → poison
unspendable. A — client holds both the pre-signed poison_s AND secret_s exactly when s is revoked → always
has recourse. **Adaptor sigs unnecessary** (a revocation secret is punishment-only, safe to reveal last).
The channel-commitment flow already proves the shape (client.c:356-445).

## 3. #46 Atomic advance — 2-phase protocol; DELETE the degradation path
The recourse is already bundled into the advance messages, so the fix is NOT more bundling. Two real breaks:
(1) the **silent poison-degradation** path (commits state w/o poison = live Scenario A), (2) inverted
completion asymmetry (2-of-2 client completes first; N-of-N LSP completes first).
**Minimal closure = (i)+(iii):**
- **Phase 1:** sign the new state to **UNIVERSAL** completion — make **ALL_PSIGS mandatory for EVERY ceremony
  incl. the 2-of-2 leaf** (today only Tier-B has it, lsp_channels.c:2543; the 2-of-2 client is sole completer).
  Add per-partial `musig_partial_sig_verify` gates (R3/R4) so a garbage psig can't DoS/force-degrade.
- **Phase 2:** reveal the old-state recourse secret, **verify-before-accept**, only after Phase 1 is universal.
- **DELETE** the `leaf_poison_prepared=0`/`poison_prepared[k]=0` "advance anyway" continuations → replace with
  hard abort + stay on old state. Advance-commit becomes conditional on recourse **by construction**.
- Adaptor sigs (iv): over-engineering here; keep scoped to PTLC assisted-exit (#57).

## 4. #54 Offline-tolerant rollover — tree-level, not signature-level
You CANNOT make one N-of-N MuSig node both atomic and tolerant of a missing signer (MuSig has no threshold).
Canonical SuperScalar tolerates offline by **tree partitioning** (a stalled leaf doesn't block other subtrees;
absent party keeps its prior fully-signed branch via the **overlap window**, lsp_channels.c:1960, and rolls
over later) + proactive exit at the deadline. The revocation framing (#53) is what makes "some advanced, some
not" a SAFE steady state. So: roll per-subtree among online members; isolate/timeout absentees → unilateral
exit; never the current strict all-N freeze (lsp_channels.c:1996/2176/2435).

## 5. TEST STRATEGY — prove it under fire (the decisive part)
**Load-bearing primitive: a high-fee mempool simulator on regtest** (dedicated `-blockmaxweight=8000`
instance; a `flood_fee_floor RATE` pump that keeps the mempool saturated above the penalty's fixed feerate,
replenished per block; `prioritisetransaction` for surgical single-tx stall; `-minrelaytxfee` for the
rejection leg). Block selection is ancestor-feerate, so a WT CPFP child on the P2A anchor raises the package
feerate above the floor → next small block includes parent+child = the exact thing we prove.
**MANDATORY anti-vacuity control:** first prove a *non-bumping* penalty (`--max-bump-fee 1`) genuinely STAYS
stuck at deadline−1 in the same environment, else "the bump saved it" is vacuous (mirror the SS_REORG_REFIRE
orphan-verification lesson).

### Test matrix (PASS = exact on-chain assertion; reuse `pen_recovers_most` fee-bounded + per-client min≥330)
| # | Name | Attack | Assertion |
|---|---|---|---|
|1a|hifee_commitment_penalty_confirms|revoked commitment under congestion|control stuck@deadline−1 AND bumped penalty confirms ≤ deadline, spends to_local, recovers ≥90%|
|1b|hifee_penalty_floor_rejection|minrelayfee > penalty feerate|pre-bump `testmempoolaccept`=min-relay-not-met; post-bump package confirms ≤ deadline|
|2|scenario_a_client_abort|LSP `--cheat-advance-no-recourse`|state counter FROZEN; only prior state broadcastable (`assert_no_new_state`)|
|3|scenario_b_poison_rejected|client `--cheat-recourse-no-commit` broadcasts live-state+poison|poison `testmempoolaccept`=script-verify-fail; L-stock UTXO still unspent (`gettxout`)|
|4+|revocation_poison_superseded_only|broadcast revoked S0|S0 poison has valid witness, confirms, sweeps S0|
|4−|revocation_poison_live_rejected|attempt S1(live) poison|poison REJECTED (no revealed secret); honest live state unpunished|
|5|rollover_offline_client_degrade|kill 1 client mid-rollover|per-subtree progress OR clean confirmed exit; NEVER all-N freeze|
|6|mass_exit_feerace|N=8-16 force-close at one CLTV under congestion|all N (or policy subset) confirm ≤ CLTV; conservation holds|
|7|feebump_escalation_ladder|floor raised 25→50→100 sat/vB|successive CPFP children; confirms ≤ deadline within budget; ≤ `--max-bump-fee`|

### Property/unit invariants (in `test_adversarial_verify.c`, fee-free, catch the bug pre-e2e)
- INV-1 advance⇒recourse: no state commit without a verified recourse for the superseded state.
- INV-2 poison witness ⟺ revocation: poison for a non-revoked state has NO satisfying witness.
- INV-3 no live-state penalty: the builder cannot construct a penalty against the live commitment.
- INV-4 anchor⇒bumpable: every anchored penalty has P2A vout1 + populated fee_bump; a no-anchor penalty's
  feerate is above any plausible floor (else it's an undefendable fixed-fee liability — #52 residue).
- INV-5 L-stock conservation: after any rejected exploit, Σ L-stock outputs unchanged.

### New harness primitives (regtest_hifee_helpers.sh)
`flood_fee_floor`/`stop_fee_floor`, `assert_stuck_then_bumped`, `deprioritize_tx`, `with_hifee_node`,
`assert_no_new_state`, `assert_tx_rejected`; plus 3 test-only `--cheat-advance-no-recourse` /
`--cheat-recourse-no-commit` drivers (add to the #9 mainnet-unreachable sweep).
**regtest = primary** (rows 1-7 + INV-*; only regtest gives controllable fee/deadline). **signet =
re-validate rows 1a + 7** (real fee market) with the 2-stage confirm budget + sat discipline.

## 6. Sequencing (decided)
1. **#53 revocation poison** (closes A+B at the root; unblocks rows 3/4 + INV-1/2/3) — wire up the bypassed infra.
2. **#46 atomic 2-phase + delete degradation** (depends on #53's recourse-secret being the Phase-2 object).
3. **#52 fee-bump** = client bumper + submitpackage + the high-fee harness (§5) — proves rows 1/7 + INV-4.
4. **#45/#55** finish wt_db coverage (PTLC, burn, kind-3) + write-through the revealed secret.
5. **#54 offline-tolerant rollover** (tree partition + overlap window) → row 5.
6. **#48-51** retry/abort/escalation liveness; **#56/#57/#58** mass-exit + investigations.
Definition of "perfect": every matrix row + every INV green on regtest under the high-fee harness with the
anti-vacuity control, then rows 1a/7 re-proven on real signet.
