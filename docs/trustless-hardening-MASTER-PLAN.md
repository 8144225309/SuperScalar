# Trustless Hardening — MASTER EXECUTION PLAN (frozen sequencing)

The index that ties the design together. Detailed designs live in:
- `trustless-model-research-findings.md` — the verified problem inventory (R1-R8, A/B, canonical divergence)
- `trustless-hardening-design-and-test-plan.md` — concrete fix designs + the high-fee test strategy
- `cl4-rollover-remediation-plan.md` — the rollover thread
- Canonical comparison + corrections recorded in memory `project_test_harness_rigor`.
Tasks: #44-64. This doc = the dependency order + critical path + the gating bar.

## Verified ground truth (so we don't re-litigate)
- Canonical (ZmnSCPxj raw posts): fixed pre-signed poison + Poon-Dryja CHANNEL revocation + DW newest-wins;
  NO hashlock-secret, NO watchtower. "The poisoning is fixed, the protection it provides is limited."
- Ours: hashlock-revocation L-stock poison (OUR extension, closes Scenario B canonical leaves open) +
  standalone WT (addition, closes offline-at-breach) + 2-phase atomicity. Faithful skeleton, stronger
  on B/atomicity/offline-breach; carries forward the fixed-payout-sizing limit.
- A CONFIRMED; B CONFIRMED for 2-of-2 PS leaves. G1 (#44) done+proven (low-fee). G2 (#45) HTLC done, PTLC owed.

## Dependency graph (what gates what)
- #61 (multi-input keyagg check) ── gates ──> #53 SUB-FACTORY path (PS-leaf 2-of-2 path is independent)
- #59 (reveal state machine) ── baked into ──> #53 + #46 (design, not follow-on)
- #53 (hashlock poison) <── coupled ──> #52 (fee-bump): poison must be bumpable to win the L&CSV race (#60)
- #46 (atomic 2-phase) ── depends on ──> #53 (the recourse secret IS the Phase-2 object)
- #54 (offline-tolerant rollover) ── needs ──> the overlap-window + #53 (makes "partially advanced" safe)
- #45/#55 (wt_db coverage) ── needs ──> the revealed secret write-through from #53
- #62/#63/#64 (UX/ops: WT model, fee-reserve, migration/restore) ── inform but don't block core crypto

## Phases (execution order)
**Phase 0 — prereqs (verify/design before code):**
  - #61 verify multi-input keyagg vs per-(leaf,state) secret index → confirm 2-of-2 PS path is clean to start.
  - #59 pin the reveal state machine (commit-then-reveal window + escalation + crash-consistency).
  - Freeze this graph.
**Phase 1 — CORE SECURITY (coupled chunk, proven TOGETHER under high-fee):**
  - #53 PS-leaf hashlock Leaf P + move poison sig to script-path + per-(leaf,state) secret index.
  - #59 reveal-on-advance + verify-before-accept + escalation, crash-durable.
  - #46 universal mandatory ALL_PSIGS + per-partial verify + DELETE the degradation path.
  - #52 make the poison/penalty P2A-bumpable + client CPFP bumper + submitpackage.
  - Prove: matrix rows 1-4 + INV-1..5 under the high-fee harness with anti-vacuity controls.
**Phase 2 — coverage + liveness floor:**
  - #45 PTLC→wt_db; #55 burn(kind0)/force-close-kind3-CLTV/JIT→wt_db + wire supersede_watch.
  - #54 offline-tolerant rollover (per-subtree + overlap window) → row 5.
**Phase 3 — liveness UX + remaining:**
  - #48 fresh-nonce retry; #49 abort msg; #50 escalation policy; #51 escalation notice.
  - #56 mass-exit fee-race (row 6); #57 assisted-exit investigate; #58 poison sizing/sybil.
  - #37 rollover cheat (now unblocked by #53/#46).
**Phase 4 — productionization:**
  - #62 WT/bumper operational model; #63 fee-reserve/deposit-insurance; #64 migration + secret backup/restore.
  - Re-prove rows 1a/7 on real signet; #9 cheat-flags unreachable on mainnet; audit prep (#10 runbook §10).

## Definition of "perfect" (the gate)
Every test-matrix row (1-7) + every invariant (INV-1..5) GREEN on regtest **under the high-fee harness with
the anti-vacuity control**, the A and B exploits actually attempted and REJECTED, no regression in the full
matrix, then rows 1a/7 re-proven on real signet. Plus: the construction documented as our extension (not
canonical) for the auditor.

## Discipline (non-negotiable)
- Critical-path crypto code in the MAIN THREAD (no agents). Agents only for bounded research.
- Anti-vacuity control on EVERY new adversarial test (the campaign's whole reason for existing).
- Re-run the full matrix + high-fee variant after each construction change.
- Push from LOCAL (creds not on VPS); detached VPS runs + poll local .output; scoped pkill.

## NOW: start of Phase 0 → Phase 1 on the 2-of-2 PS-leaf path.
