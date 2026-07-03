# Pre-Mainnet Design Decisions

This document settles the five open pre-mainnet design questions (internal tasks
#57, #58, #62, #63, #64) with a **recommended decision**, the **residual risk**,
and the resulting **external-audit scope** for each. It is the input that scopes
the mainnet security audit.

## The load-bearing invariant (validate this first)

**Client fund safety does not depend on any of the five questions below.**

- A client's **channel balance** is protected by the Poon–Dryja revocation
  penalty, recovered *separately* from and *independently* of factory size,
  client balance, or the number of leaves/signers (`docs/poison-tx.md`).
- A client can **always unilaterally self-exit**: broadcast its persisted
  factory tree (`factory_recovery_run`, `client_force_close_from_db`, the #313
  self-custody path) and sweep `to_local` after the CSV delay. The basic sweep
  is **self-funded** — the fee is deducted from the swept output
  (`src/sweeper.c`), so it needs no external UTXO.

The five questions therefore concern, in order of real risk:

- **Q4** — winning a *contested fee-race* (the one genuine residual);
- **Q2** — the *strength of the poison deterrent* (not client-fund safety);
- **Q1** — the *cost/UX* of exiting an online-but-unhelpful LSP;
- **Q3 / Q5** — the *operational* model and *backup/upgrade* policy.

**Absent a contested fee-race, no honest client loses funds.** The auditor's
first task is to confirm that claim; everything below is second-order.

---

## Q1 — Assisted-exit PTLC fair-exchange (#57)

**Question.** Should we implement a *negotiated cheap exit* for a client whose
LSP is online but unhelpful (won't cooperatively close on good terms)?

**Current state.** Exits that exist: unilateral force-close self-exit (#313),
`to_local` sweep after CSV, LSP-agreed cooperative close, `--on-lsp-forgery
close`, and the CPFP-able distribution-TX recovery backstop. Adaptor-signature
infrastructure exists (`src/adaptor.c`) but is wired only into rotation/turnover
— **there is no client-initiated assisted exit**. The canonical design
(`docs/trustless-hardening-design-and-test-plan.md`) explicitly defers this as
over-engineering; the PTLC fair-exchange of "help me exit cheaply in exchange
for X" is a canonically hard/unsolved problem.

**Decision: DO NOT implement for v0.2.x.** Fund safety is already met by
unilateral self-exit. Assisted exit is a *cost/UX optimization* (a cheaper,
faster exit), not a safety requirement, and it adds adaptor-based protocol
surface for a canonically unsolved fair-exchange. Defer as a post-audit UX
enhancement.

**Residual risk.** An online-but-unhelpful LSP can force a client into a
*more expensive* unilateral exit (extra on-chain cost + the CSV wait). Funds are
safe; the exit is dearer. (This interacts with Q4: the expensive exit must be
*affordable* — see the fee-reserve decision.)

**Audit scope.** Confirm the unilateral self-exit path is **always available and
sufficient** (persisted tree + recovery net), and that no LSP behavior — stalling,
withholding, refusing to cooperate — can *block* it (only make it costlier).

---

## Q2 — Poison/recourse sizing vs large balances + sockpuppet leaves (#58)

**Question.** Is the L-stock poison / recourse economically sound (a) at very
large client balances and (b) against a malicious LSP that spins up sockpuppet
client-leaves to dilute or game recourse?

**Current state.** `compute_l_stock_poison_per_client` (`src/factory.c`) splits
the LSP's **L-stock** equally among clients (`per_client = (l_stock − fee) /
n_clients`, fails below the 546-sat dust floor, fixed 1000-sat CPFP-able fee).
Crucially, each client's **channel balance is recovered separately** via the
Poon–Dryja penalty, *not* via the poison. The canonical design acknowledges the
poison is a **fixed, limited** deterrent.

**Decision.** Three-part:
1. **Client channel funds are safe regardless** of balance size or sockpuppet
   count — they are PD-penalty-covered, independent of the poison.
2. **The L-stock poison is a bounded *deterrent***, not a client-fund-recovery
   mechanism: it makes LSP cheating unprofitable by burning/redistributing the
   LSP's *own* L-stock. Keep the canonical fixed-poison design.
3. **Commission a game-theoretic bound (the substance of #58):** quantify the
   LSP's maximum profit-from-cheating given (a) large honest balances and
   (b) N sockpuppet leaves that dilute the equal split. If that profit is
   *unbounded* (dilution makes cheating net-positive), add a mitigation —
   e.g. poison sized to per-leaf balance-at-risk, or a cap on sockpuppet
   dilution. If bounded and negative, document the bound and ship as-is.

**Residual risk.** Sockpuppet leaves dilute the per-client poison share, so an
LSP running many sockpuppets faces a *weaker* penalty for cheating. It still
forfeits its L-stock, and honest clients' **channel funds remain PD-safe** — the
risk is to *deterrence strength*, not client principal.

**Audit scope.** (1) Confirm the PD channel penalty — not the poison — is the
fund-safety guarantee. (2) Review the #58 game-theoretic bound: can an LSP make
cheating net-profitable via sockpuppets or against a whale client?

---

## Q3 — Watchtower + CPFP-bumper operational model (#62)

**Question.** Who runs the standalone watchtower and funds the CPFP fee-bumper,
and what is the "secret-less" trust nuance?

**Current state.** The standalone WT is secret-less (`--wt-db` only; holds no
signing keys; the guarantee is `nm`-verifiable — `docs/watchtower-trustless-schema.md`).
The CPFP bumper is funded via `--bump-wallet`: the WT spends *that wallet's*
UTXOs to CPFP the anyone-can-spend P2A anchor, signing the child with the
bump-wallet owner's key — so **"who pays the bump" = whoever funds
`--bump-wallet`**. A deadline-driven escalator with `--max-bump-fee` /
`--bump-budget-pct` caps drives it. **Design-intent divergence:** the plan
(`design-and-test-plan.md`) says the bumper *should* be the **client's** own
recovery daemon (the party holding funds + keys); as-shipped it is the WT's
`--bump-wallet`.

**Decision.** The mechanism is sound; **specify the operational model**:
- **Canonical (self-custody): each client runs its own watchtower and funds its
  own bumper.** The party with funds at risk pays to defend them — this matches
  the design intent and the trustless model.
- **The LSP MAY run a WT with `--bump-wallet` as a liveness/defense
  *convenience*** for its clients, but this is a *trust assumption*, not a
  guarantee, and is not a substitute for client-side defense.
- Size the bump reserve to a worst-case fee-race (see Q4). Adopt
  `submitpackage` 1p1c where the node supports it.
- **Fix the stale operator-guide §8** (still documents the removed `--db lsp.db`
  invocation; omits `--wt-db` / `--bump-wallet`) — done on the release-realign PR.

**Residual risk.** A client that runs *no* watchtower and holds *no* bump funds
depends on the LSP-run convenience bumper (a trust assumption) or loses a
contested fee-race. This folds directly into Q4.

**Audit scope.** The operational trust model (who defends whom), the
secret-less guarantee (`nm`-verified), and bump-funding adequacy under fee
pressure.

---

## Q4 — Fee-reserve / deposit-insurance (#63)  ← the one real must-decide

**Question.** Can a client whose entire balance is locked inside the factory pay
the on-chain fee to force-exit and, critically, to *win a contested fee-race*?

**Current state.** The uncontested self-exit is **self-funded** (fee from the
swept output, `src/sweeper.c`) — a fully-in-factory client *can* exit without
external UTXOs when unopposed. But **winning a contested fee-race requires
external funds**: the P2A anchors are anyone-can-spend and a CPFP child must be
funded by an external UTXO; the bumper bails when it has no wallet. There is
**no client-side fee-reserve mechanism** today. The completion plan marks this
Layer ("Afford") **explicitly OPEN**.

**Decision: adopt a documented client fee-reserve requirement.** A client MUST
hold a small **external (out-of-factory) UTXO reserve**, sized to fund one
worst-case CPFP bump of its exit/penalty transaction at a high target feerate —
analogous to the Lightning channel-reserve requirement. Document it as a client
operational prerequisite (client guide + runbook), compute a concrete minimum
(max anchor-CPFP vsize × a conservative high feerate), and emit a **warning when
a client operates with zero external reserve**. (Future option: an automatic
"deposit-insurance" split that reserves a fraction outside the factory.)

**Residual risk (the sharpest pre-mainnet risk).** A client that ignores the
guidance and keeps *all* funds in-factory can still exit *uncontested*, but
cannot guarantee winning a *contested* fee-race under mempool pressure — its
penalty/exit could be outpaced or pinned. This is the pre-mainnet residual the
audit should stress hardest.

**Audit scope.** The fee-race / transaction-pinning scenario end-to-end; whether
the recommended reserve size defeats known pinning vectors; interaction with
BIP-431 TRUC + package relay (1p1c).

---

## Q5 — Construction migration + backup-restore (#64)

**Question.** Is there a migration path for *existing live factories* across a
construction/protocol change, and does backup-restore cover the *new* secrets
(hashlock poison intents, revocation, distribution TX)?

**Current state.** SQLite schema migration is at v39 with a tested ladder
(v1→v39, data-preserving, idempotent — `tests/test_persist.c`). Encrypted backup
(`src/backup.c`: ChaCha20-Poly1305, PBKDF2 600k) covers DB + keyfile; a
`--backup-dir` pre-rotation snapshot exists. The **new secrets are persisted**
(`l_stock_poison_reveals`, `revocation_secrets`, `distribution_tx`) and thus
covered by the whole-DB backup; the poison seed is re-derived, not stored.
**Gap:** a construction/factory-*shape* change applies to **new factories
only** — existing on-chain factories keep their original SPK and continue to
work; there is **no in-flight construction upgrade**, and **no end-to-end
restore drill** exercises the new secret tables specifically.

**Decision.** Two-part:
1. **Construction changes are forward-only, by design.** Existing on-chain
   factories are never mutated; they continue operating and drain/close under
   their original construction, and clients migrate by cooperatively closing +
   re-opening under the new construction. This is correct and safe (a live
   factory's on-chain structure cannot be rewritten). **Document it as policy.**
2. **Add an end-to-end restore drill** proving the new secret tables restore
   correctly and that, after restore, a factory resumes *and a client can still
   fully exit / a WT can still fire recourse*. The DB/keyfile backup mechanism
   itself is sound; the missing piece is the recourse-preserving restore proof.

**Residual risk.** An operator who upgrades mid-flight without draining old
factories runs two constructions in parallel (supported, but operationally
complex). A restore that silently drops a new secret table would break recourse
— which is exactly what the drill must catch.

**Audit scope.** Backup/restore of the new secrets (does a restored client/WT
retain *full* recourse?); the forward-only construction policy; the
pre-rotation snapshot's completeness.

---

## Consolidated external-audit scope

1. **Fund-safety invariant (highest priority):** prove a client's channel funds
   are recoverable via PD penalty + unilateral self-exit under *every* LSP
   misbehavior, independent of factory size, balance, sybil leaves, and the
   poison. (Q1, Q2)
2. **Contested fee-race / pinning (Q4):** the sharpest residual. Validate the
   client fee-reserve sizing and the CPFP/TRUC/1p1c defense against pinning.
3. **Poison deterrent game-theory (Q2):** bound the LSP's max profit-from-cheating
   under sockpuppets and whale clients.
4. **Watchtower operational trust model (Q3):** secret-less guarantee + who
   defends/funds whom.
5. **Backup/restore recourse-preservation (Q5):** a restored client/WT retains
   full recourse; forward-only construction policy.

## Decision → task mapping

| Q | Task | Decision |
|---|---|---|
| Q1 | #57 | **Defer** assisted exit; safety met by unilateral self-exit. |
| Q2 | #58 | Keep fixed poison; **commission the sockpuppet/large-balance game-theoretic bound**. |
| Q3 | #62 | **Client-side WT + bumper is canonical**; LSP `--bump-wallet` is a convenience; fix operator-guide §8. |
| Q4 | #63 | **Adopt a documented client fee-reserve requirement** (the key must-do). |
| Q5 | #64 | **Construction changes are forward-only**; add a recourse-preserving restore drill. |

None of these blocks the v0.2.0 tag (a signet/testnet release); all are inputs to
the mainnet audit and the pre-mainnet hardening track.
