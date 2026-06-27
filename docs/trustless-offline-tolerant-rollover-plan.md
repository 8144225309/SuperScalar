# #54 — Offline-tolerant rollover: complete understanding + design

**Status:** design (no code yet). Researched 2026-06-26 across `src/factory.c`, `src/lsp_channels.c`,
`src/lsp_rotation.c`, `src/lsp.c`, `src/channel.c`, `src/tapscript.c`, and `docs/`. This supersedes the
earlier (wrong) read that #54 needs a taproot construction redesign.

---

## TL;DR

The construction is a **timeout-tree** and is *already* built for offline-tolerance. Offline-tolerance is
**mostly present**, not absent:

- **PS leaf advances are 2-of-2 (LSP + that one client)** — one offline client only blocks *its own* leaf,
  never the others (`lsp_advance_leaf_stateless`, lsp_channels.c:1354/1455/1510).
- **Sub-factory chain advances are N-of-N over the *sub*'s clients only** — other subs' clients can be
  offline (`lsp_subfactory_chain_advance_stateless`, lsp_channels.c:4213/4243).
- **Lifetime extension already tolerates offline via *partial rotation*** — Phase A skips offline clients,
  and if not everyone is online it spins up a NEW factory for the online subset and leaves the absent client
  to exit the old factory (`lsp_rotation.c:276-281, 537-564, 745-762, 886-918`).
- **Every output except the funding root has an LSP-alone-after-timeout escape** (staggered CLTV on tree
  nodes, CSV on L-stock) so the LSP can always recover after timeouts and clients race those timeouts
  (factory.c:186-201, 219-269, 1467-1484).
- **The overlap window is inherent** — an absent client's prior fully-signed branch stays valid; it can exit
  or roll over later.

So the only *strict all-N* spend in the whole construction is the **funding UTXO** (spent once by the
pre-signed root kickoff at broadcast). There is **no construction-level barrier** to offline-tolerance.

**The two real gaps are in the ceremony/lifecycle layer, not the construction:**

- **G1 (SAFETY, keystone):** the **stateless** factory-creation path builds the distribution TX *unsigned*
  and never co-signs it (`lsp.c:510-523`). The distribution TX is the **offline-forever auto-recovery net**
  (nLockTime = factory CLTV; anyone broadcasts it at the deadline to pay every client their balance). Without
  it, the partial-rotation story "leave the absent client to exit the old factory" has no automatic payout —
  the client must come online before the CLTV and force-close, or its balance can be swept by the LSP's
  CLTV-recovery leaf. The legacy creation path co-signs it; the stateless path (the validated default) does
  not. **This is the heart of #54: an isolated/absent client must still get its money.**

- **G2 (LIVENESS):** the **Tier-B root rollover** hard-aborts (`return 0`) on any offline client
  (lsp_channels.c:2285-2295, 2544-2566) — the "strict all-N freeze" the design doc flags at
  lsp_channels.c:1996/2176/2435. It does NOT threaten funds (it re-signs within the same CLTV; the old epoch
  stays valid), but it's a blunt failure, and PS leaf advances *fall through* to it when the DW counter is
  exhausted (lsp_channels.c:1445-1452), so a single offline client can then block other leaves' advances.

No taproot/construction change is required for either gap.

---

## 1. The construction (what we're working with)

### 1.1 Two independent on-chain time bounds (do not conflate)

1. **DW relative-timelock state machine (nSequence)** — the root/intermediate `NODE_STATE` nodes form a
   Decker-Wattenhofer counter; advances decrement nSequence so the newest tree confirms first. Finite
   (`states_per_layer × step`); exhaustion triggers a **Tier-B rollover** (epoch++). *Within-lifetime
   cycling, not lifetime extension.* PS leaves themselves set nSequence `0xFFFFFFFE` (BIP-68 disabled) and
   order states by TX-chaining instead.

2. **Absolute CLTV deadline (`f->cltv_timeout`)** — the hard deadline by which clients must exit. It is the
   root state's nLockTime / longest CLTV, the CLTV-recovery leaf height on every channel/leaf output, and the
   distribution TX's nLockTime. **Assigned only at creation/rotation/DB-load; never mutated in place**
   (writers: lsp.c:428, persist.c:2404, client.c:1020/1994). The only way it moves out is rotation to a
   *new* factory.

### 1.2 The timeout-tree escapes (offline-tolerance is built in)

| Output | Internal key | Timeout/subset escape |
|---|---|---|
| Funding UTXO | N-of-N (all) | **none** — all-N key-path (the one strict-all-N spend; pre-signed at setup) |
| Tree node (non-root kickoff/state) | N-of-N (subtree) | **LSP alone after staggered CLTV** (factory.c:186-201, 1467-1484) |
| PS sub-factory *entry* | N-of-N (sub) | none (key-path only) |
| Per-client channel funding | **2-of-2 (LSP+client)** | + LSP alone after factory/node CLTV |
| L-stock | N-of-N (leaf) | **LSP alone after CSV** (Leaf L, 144 blk) |
| Distribution TX | pre-signed payout | nLockTime = CLTV; **anyone** broadcasts at deadline |

### 1.3 Who signs each ceremony

| Ceremony | Signers | Offline tolerance | Moves CLTV? |
|---|---|---|---|
| PS leaf advance | 2-of-2 (LSP + that leaf's client) | other clients offline OK | no |
| Sub-factory chain advance | N-of-N over the *sub* | other subs' clients offline OK | no |
| **Tier-B root rollover** | **N-of-N over whole factory** | **none — `return 0`** | no (re-signs within CLTV) |
| Rotation / new-factory creation | N-of-N over the *new* factory | full close needs all; else **partial** | **yes (only here)** |

---

## 2. What offline-tolerance already exists

- **Per-leaf / per-sub isolation** (1.3 rows 1-2): a stalled client only stalls its own leaf/sub.
- **Partial rotation** (`lsp_rotation.c`): on rotation with absent clients — Phase A *skips* them
  (276-281); full cooperative close requires all online, else downgrade to **partial** (537-564); partial =
  old factory NOT closed, "expires naturally, distribution TX protects participants" (745-762); a brand-new
  factory is created for the online subset only (886-918); absent client is left to exit the old factory.
- **Proactive exit** (#50): bounded retry → broadcast distribution TX before the CLTV (lsp_channels.c:7234-7301).
- **Abort/intent-to-exit notice** (#49/#51, PR #397): clients are told `MSG_CEREMONY_ABORT` (RETRY_LIMIT) so
  they stop waiting + check their watchtower.
- **Overlap window:** prior fully-signed branches remain valid; absent client can exit/roll over later.

The documented client guarantee is **"safe as long as you come online before the factory CLTV"**
(client-user-guide.md:125,129). Offline-*forever* recovery is the *bonus* delivered by the distribution TX
(`test_regtest_all_offline_recovery`, testing-guide.md:318-322) — and that bonus is exactly what G1 breaks
in the stateless path.

---

## 3. The gaps + design

### G1 (keystone, SAFETY) — co-sign + persist the distribution TX in the stateless creation ceremony

**Problem.** `lsp.c:510-523` builds the dist TX unsigned and never co-signs it under the stateless signer
(the default). `lsp_rotation.c:1032-1040` only copies a *signed* dist TX "if available" — so partial
rotations inherit no dist TX either. Net: in a stateless-path factory, an absent/abandoned client has no
automatic payout at the CLTV; `factory_recovery_run` (factory_recovery.c:381) has nothing signed to
broadcast. This makes the partial-rotation "leave the absent client to the dist TX" story unsound for the
stateless path.

**Design.** Add one more all-N MuSig signing pass to the stateless factory-creation ceremony (everyone is
online at creation by definition), producing a fully-signed distribution TX, and persist it via the existing
`persist_save_distribution_tx` (persist.c:6572). Mechanically identical to how the ceremony already
co-signs each tree node; the dist TX is just one more transaction over the funding-output keyagg with
nLockTime = `f->cltv_timeout`. Set `f->dist_tx_ready` so rotation (lsp_rotation.c:1034) copies it forward.
Mirror into the rotation/new-factory creation path so partial-rotation subsets also get a signed dist TX.

**Fund-safety.** The dist TX pays each participant their creation-time balance at the CLTV. Co-signing it at
creation (all-N online) is safe — it is the canonical "everyone exits at the deadline" fallback and adds no
new spend path (the outputs already exist as the construction's intended payout). It strictly *adds* recourse
for absent clients; it removes none.

**Caveat to design carefully:** the dist TX reflects *creation-time* balances. After PS leaf / sub-factory
advances change balances, the creation-time dist TX is stale for the moved amounts. This is the same property
the legacy path has, and the deeper guarantee remains the client's own force-close (current commitment) +
CLTV-recovery. The dist TX is the *offline-forever* net at roughly creation-time allocation. Document this
precisely; do not over-claim it tracks live balances. (A live-balance dist TX is a larger future item.)

### G2 (LIVENESS) — Tier-B root rollover graceful degradation

**Problem.** Tier-B aborts hard on any offline client (lsp_channels.c:2285-2295, 2544-2566). PS leaf advance
falls through to Tier-B when the DW counter exhausts (1445-1452), so one offline client can then block other
leaves.

**Design (no construction change).** The root state is genuinely all-N, so we cannot *advance the root*
without everyone — and we should not pretend to. Instead make the failure graceful:

1. **Tolerate transient absence (overlap window):** on a Tier-B all-N shortfall, do NOT treat it as terminal.
   The current epoch's tree remains valid; defer the DW-epoch refresh and keep serving per-leaf/per-sub
   advances that don't need the absent client. (Today the hard `return 0` is what the design doc calls the
   "freeze.")
2. **Escalate to the existing partial-rotation path on *persistent* absence**, rather than just failing — i.e.
   wire the Tier-B shortfall into the same DYING/`lsp_rotation` machinery that already isolates absentees and
   builds a new factory for the online subset. This realizes "isolate/timeout absentees → unilateral exit"
   using machinery that already exists (G3).
3. **Break the leaf→Tier-B fall-through coupling under absence:** when a PS leaf advance would fall through to
   a Tier-B that can't reach all-N, prefer extending the leaf's overlap window / deferring the root tick over
   blocking the leaf, so other leaves keep advancing. (Bounds the blast radius to the absent client's own
   leaf, matching the PS per-leaf isolation property.)

**Fund-safety.** Pure liveness — no new spend path, no change to what's broadcastable. The old epoch stays
valid; G1's signed dist TX + the timeout-tree escapes remain the recovery floor.

### G3 (VERIFY + TEST) — partial-rotation offline path end-to-end with the signed dist TX

Partial rotation already exists; with G1 landed it becomes *sound*. Deliverable: an e2e regtest drill —
N-client factory, kill one client, drive a rollover/rotation, assert (a) the online subset continues in a new
factory, (b) the absent client's funds are recoverable via the *signed* dist TX at the CLTV
(`test_regtest_all_offline_recovery`-style, but stateless path), (c) never an all-N freeze / mass-exit of the
online subset. Maps to the design doc's matrix row 5 (`rollover_offline_client_degrade`).

---

## 4. What we explicitly do NOT do (and why)

- **No taproot / funding construction redesign.** The all-N funding root is fine: the timeout-tree already
  gives every lower output an LSP-after-timeout escape, and the signed dist TX (G1) gives absent clients an
  automatic payout. Continuing the *same* on-chain factory without an absent client is impossible (all-N
  funding) and unnecessary — lifetime extension is rotation-to-a-new-factory, which already does partial.
- **No "exclude + cash out + continue same factory."** That would require subset-spending of the funding —
  not supported, and not needed given partial rotation.
- **No live-balance distribution TX** (tracks post-advance balances). Larger future item; out of scope here.

---

## 5. Staging (each a reviewable PR; G1 first — it's the safety keystone)

1. **G1a** — co-sign + persist the distribution TX in the stateless factory-creation ceremony; set
   `dist_tx_ready`; unit + regtest (`test_regtest_all_offline_recovery` must pass on the *stateless* path).
2. **G1b** — carry the signed dist TX through rotation / partial-rotation (new factory for the online subset
   gets a signed dist TX).
3. **G2** — Tier-B graceful degradation (overlap-window tolerance + escalate-to-partial-rotation + break the
   leaf fall-through under absence).
4. **G3** — e2e offline-rotation drill (matrix row 5) on the stateless path.

Order rationale: G1 is fund-safety (do first); G2/G3 are liveness/coverage on top. Each is consensus-adjacent
and lands with tests + a reviewable diff.

---

## 5a. CONFIRMED 2026-06-26: stateless IS the production creation path (G1 is critical-path)

Verified, not assumed: `lsp_run_factory_creation` (lsp.c:778) **unconditionally** delegates to
`lsp_run_factory_creation_stateless` (lsp.c:784) — there is no separate legacy creation path left — and the
daemon sets `SS_MUSIG_STATELESS=1` itself (tools/superscalar_lsp.c:1867). So **every factory created in
production today has an UNSIGNED distribution TX** (`dist_tx_ready` stays 1; reaches 2 = signed only via
client.c:888 which never triggers because the LSP never sends a signed dist TX). The offline-forever
auto-recovery net and partial-rotation's "absent client protected by the dist TX" are therefore **unsound as
shipped**. G1 is on the critical path.

**G1a scope (infra already half-present):** `factory_build_distribution_tx_unsigned` (factory.c:4185) already
computes `f->dist_sighash` (factory.h:431, called at lsp.c:521); the single-process signed builder
`factory_build_distribution_tx` (factory.c:4099) shows the witness/finalize shape; the client already applies
`distribution_tx_hex` from `MSG_FACTORY_READY` -> `dist_tx_ready=2` (client.c:878-888). The missing middle is
the **distributed MuSig co-signing over `dist_sighash`** using the funding keyagg (= node[0].keyagg), then
attaching `distribution_tx_hex` to FACTORY_READY + persisting via `persist_save_distribution_tx`
(persist.c:6572). **Design choice (recommend the safer one): an ISOLATED dist-TX signing round after the
node-signing completes (one new nonce+psig message pair), rather than widening the proven 3-message creation
ceremony** — isolates risk to the new code path.

## 6. Open questions for review

1. **Offline-forever scope:** is offline-forever auto-recovery (the dist TX) an intended guarantee for the
   stateless path, or acceptable to keep as "come online before CLTV"? G1 assumes we want the dist TX net
   restored (recommended — it's the canonical SuperScalar fallback and partial-rotation depends on it).
2. **Tier-B escalation trigger:** escalate to partial rotation immediately on a confirmed-persistent absence,
   or only once the factory is already DYING? (Leaning: only when DYING or DW-counter critically low, to
   avoid churning rotations on transient blips.)
3. **Dist-TX staleness:** confirm we're content with a creation-time-balance dist TX as the offline-forever
   net (with the client's own force-close as the live-balance guarantee), deferring a live-balance dist TX.
