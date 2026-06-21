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

## 5d. #53-B3b-part-2 — DAEMON/WIRE INTEGRATION PLAN (researched 2026-06-21, 4 opus agents)
The in-process poison construction+signing layer (#53-A/B1/B3a/B3b-1) is proven. Wiring it into the live
LSP↔client daemon protocol is larger than first scoped — three research findings reshape it:

**F1 (gating prerequisite). Enabling hashlock BREAKS the advance unless the client builds the matching
2-leaf L-stock SPK.** The leaf STATE tx's last output IS the L-stock; if the LSP builds a 2-leaf {Leaf-P,Leaf-L}
SPK and the client builds the legacy single-leaf SPK, the leaf tx bytes differ → MuSig co-sign mismatch →
the whole advance fails (not just the poison). The client only gets H over the wire (it has no seed). The
existing `l_stock_hashes` wire (wire.c:660 build / client.c:1894,2001 parse) is **per-EPOCH flat** — the WRONG
shape; #53 H is **per-(leaf,state)** = SHA256(tagged(seed‖leaf_agg‖state_counter)). And `factory_set_l_stock_hashes`
(factory.c:3366) only fills the flat array; it never sets node->l_stock_hash/has_l_stock_hash. So the client
builds the single-leaf SPK and never enables the path.

**F2. The leaf-advance ceremony (the PRIMARY 2-of-2 PS-leaf path) was NOT covered by B3a's retarget.** In
`lsp_advance_leaf_stateless` (lsp_channels.c:1353-1933) the CLIENT aggregates the poison sig
(`final_poison_sig`, client.c:3857) and returns it in FINAL; the LSP `finalize_signed_tx` at lsp_channels.c:1754
builds a KEY-PATH witness. B3a only retargeted the Tier-B `complete_node_poison` path (lsp_channels.c:2511).
So with hashlock on, the leaf-advance poison finalize must ALSO store the agg sig (script-path) + assemble
-with-secret later, on BOTH the LSP finalize (1754) and the client aggregate (3857).

**F3. Reveal carriers + timing.** DONE is broadcast to ALL clients (leaf-advance, lsp_channels.c:1880-1883) /
epoch-only (Tier-B MSG_PATH_SIGN_DONE) — neither can carry a leaf-specific secret. Use NEW messages
`MSG_LEAF_ADVANCE_REVEAL`(0x8C) {leaf_side, revoked_state, secret32} sent targeted to client_fds[leaf_side]
just before DONE (1880); `MSG_STATE_ADV_REVEAL`(0x8D) {epoch, n, secrets_per_leaf flat blob} per-affected-leaf
in/after the WT loop (2570-2630). Unifying rule: **old_counter = leaf->l_stock_state_counter − 1** at the reveal
point (counter is always bumped by then). Encode via wire_json_add_hex (template: revoke_and_ack revocation_secret
wire.c:844). Daemon enable goes in src/lsp.c between :437 (set_shachain_seed) and :442 (build_tree) — NOT in
superscalar_lsp.c (factory_init_from_pubkeys lsp.c:413 wipes use_hashlock_poison); seed must be a REAL random
seed (flat-secrets leaves shachain_seed zeroed). Client persist: new table `l_stock_poison_reveals` (schema
v37→v38) {factory_id, leaf_node_idx, state_counter, l_stock_hash, secret(sealed), agg_sig, unsigned_tx,
leaf_script, control_block}; verify-then-persist mirroring channel_receive_revocation_flat (channel.c:625);
persist BEFORE adopting new state (#59). B4 degradation = ~80 "reset_poison+clear-flag+continue" sites across
5 ceremony families × LSP+client → gated hard-abort (`return 0` + stay on old state) when use_hashlock_poison
(LSP) / has_l_stock_hash (client).

**SEQUENCED INCREMENTS (each built+tested before the next; in-process proof, then B6 flips the daemon flag):**
- **B3b.2a (PREREQUISITE):** ship per-(leaf,state) H to the client + client maps it onto node->l_stock_hash/
  has_l_stock_hash after factory_build_tree (creation + per-advance). Prove: client-built leaf L-stock SPK ==
  LSP-built SPK (so the advance co-signs). Gates everything.
- **B3b.2b:** retarget the leaf-advance poison finalize (LSP 1754 + client 3857) to script-path (store agg_sig).
- **B3b.2c:** reveal — MSG_*_REVEAL; LSP derives secret(leaf, counter−1) + sends after poison-complete; gated.
- **B3b.2d:** client verify (SHA256==H_old, fail-closed) + persist (v38 table) before adopting new state (#59);
  LSP "reveal-owed" journal for restart re-send.
- **B3b.2e:** daemon enable — `--enable-hashlock-poison` + random seed + factory_enable_hashlock_poison @ lsp.c.
- **B4:** delete degradation (gated hard-abort) at the ~80 sites.
- **B6:** e2e — hashlock factory, advance a leaf, LSP broadcasts the stale OLD state, client/WT assembles the
  poison from the PERSISTED secret + broadcasts, poison confirms + redistributes, under high fee (the gold proof).

## 5b. #59 Reveal state machine (PINNED — the commit point that closes residual Scenario A)
The advance leaf state s→s+1 is a **two-phase commit** whose commit point is the secret reveal:
- **Phase 1 (recourse first):** exchange + per-partial-verify ALL psigs for BOTH (a) the new leaf tx s+1 AND
  (b) poison_s over Leaf-P(H_s). UNIVERSAL ALL_PSIGS (no sole completer). Nothing observable changes yet.
- **Phase 2 (commit = reveal):** LSP reveals secret_s; client checks `SHA256(secret_s)==H_s` (H_s baked into
  state s's L-stock SPK), **fail-closed** (mismatch ⇒ ABORT, stay on s). Only on success does the client
  advance its **live-state pointer** s→s+1.
**The load-bearing invariant:** the client's live pointer advances **iff** it has durably persisted
`(poison_s co-sig ∧ verified secret_s)`. Persist order = (1) write recourse-for-s, fsync, (2) then bump live
pointer. Crash between ⇒ on restart live is still s, recourse-for-s present, re-drive Phase 2 idempotently.
**Why no residual A:** during the Phase-1→reveal window the mutually-live state is STILL s, so the LSP
broadcasting s is *honest* (not theft); broadcasting any r<s is covered by the already-held
poison_r+secret_r. The LSP only gives away secret_s (its own punishment key) last, which can only hurt the
LSP. So "committed-without-recourse" is unreachable: recourse (Phase 1) strictly precedes commit (Phase 2),
and commit is exactly the moment the client gains the secret. Mirrors Poon-Dryja `revoke_and_ack` ordering
and `channel_verify_revocation_secret` (channel.c:597). #46 makes Phase-1 ALL_PSIGS mandatory + deletes the
"advance anyway" degradation so Phase 2 is never reachable without full recourse.

## 5c. #53-A implementation map (the crypto core — purely additive until #53-B sets the hash)
- `build_l_stock_spk` + the key-path signer both route through ONE `build_l_stock_taptree(f,node,&P,&L,root,&two)`
  helper (no SPK/tweak drift). Tree = {Leaf P, Leaf L} iff `node->has_l_stock_hash`, else legacy {Leaf L}.
- Leaf P = `tapscript_build_l_stock_poison_leaf` = the audited offered-HTLC-success bytes
  (`OP_SIZE 0x20 OP_EQUALVERIFY OP_SHA256 <H_s> OP_EQUALVERIFY <agg_xonly> OP_CHECKSIG`).
- Poison signs the **UNtweaked** agg key (`musig_sign_all_local`) over the **Leaf-P script-path** sighash
  (`compute_tapscript_sighash`); witness = `[sig, secret, Leaf-P script, 2-leaf control block]`
  (`finalize_script_path_tx_preimage`). nVersion=2 — bumpable via the client-owned poison outputs (no P2A
  needed; #60 satisfied by output structure). REPLACES the key-path poison: `factory_sign_l_stock_poison_tx`
  (key-path) refuses once `has_l_stock_hash` (so the B-vulnerable key-path sig is never produced; #53-B).

## 6. Sequencing (decided)
1. **#53 revocation poison** (closes A+B at the root; unblocks rows 3/4 + INV-1/2/3) — wire up the bypassed infra.
2. **#46 atomic 2-phase + delete degradation** (depends on #53's recourse-secret being the Phase-2 object).
3. **#52 fee-bump** = client bumper + submitpackage + the high-fee harness (§5) — proves rows 1/7 + INV-4.
4. **#45/#55** finish wt_db coverage (PTLC, burn, kind-3) + write-through the revealed secret.
5. **#54 offline-tolerant rollover** (tree partition + overlap window) → row 5.
6. **#48-51** retry/abort/escalation liveness; **#56/#57/#58** mass-exit + investigations.
Definition of "perfect": every matrix row + every INV green on regtest under the high-fee harness with the
anti-vacuity control, then rows 1a/7 re-proven on real signet.
