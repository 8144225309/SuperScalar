# Test-Harness Verification-Rigor Audit

**Status:** open remediation. **Date found:** 2026-06-18. **Tracking:** tasks #34 (Tier-1), #35 (Tier-2/3/4).

This document records a systemic class of false-pass bugs found in the breach/penalty
test harness, the root cause, the standard we hold tests to now, and the full
severity-ranked remediation list. It is the single source of truth so nothing is missed.

---

## 1. The bug class

**Tests assert that the defense *machinery fired*, not that it produced the correct
*economic outcome*.** A trustless-security test must prove the adversarial outcome —
the cheater provably loses the exact breached value and the victim recovers it, to a
key they control — not merely that "a penalty was broadcast."

Five concrete sub-patterns (A–E):

- **A. Wrong-artifact confirmation.** A txid is extracted with `grep -oE "[0-9a-f]{64}" "$LOG" | head -1`, which grabs the *first* hash in the log — the **breach/observed** txid, not the **penalty/sweep** txid. "penalty confirmed @ H" then re-confirms the breach. Also appears as a `head -1` *fallback* after a correct extraction.
- **B. Broadcast ≠ confirmed.** PASS is set when the watchtower *broadcasts* a penalty (a log line / `sendrawtransaction` accepted to mempool), with no on-chain **confirmation** check.
- **C. No amount/outcome assertion.** A penalty that fires is asserted, but the swept **amount** is never checked. A penalty paying dust, or to the wrong party, still PASSes.
- **D. Undefined-helper call.** A script calls a helper (e.g. `wait_confirm`) it never defines and doesn't source → command-not-found (false FAIL, or a silently-ignored no-op).
- **E. Existence masquerading as correctness.** Asserting a watch was *registered/armed* but not that it *fired*; grepping a log string that prints regardless of success; checking a tx entered the mempool but not that it won the race / confirmed; accepting a known false-positive branch.

## 2. How it was found (and how we missed it)

Found by pulling on "**inspect the payout for accuracy**" during the signet breach re-run.
The signet `commitment_breach` test was confirming the **breach** txid as if it were the
penalty (pattern A), PASSed on **broadcast** (B), and never checked the **amount** (C).
The fixed re-run then proved the real penalty paid **30,871 sats**, matching the
breached `to_local` — the exact verification that had been missing.

**The smoking gun — `tools/test_regtest_cheat_client.sh:186`** (the headline cheat test):
its own comment specifies the fix *and warns about the exact bug*:

> `# CL7 (#218): programmatically assert net-delta(cheater) <= 0 … Without this, the`
> `# test PASSes by side-effect of the WT broadcasting, but doesn't verify the`
> `# trustless guarantee.`

…and then never implements it — it counts `broadcast_log result='ok'` rows and prints
"→ cheater net <= 0" without ever computing it.

**Root cause:** these were *existence checks masquerading as correctness checks*.
1. **Lazy precision** — `head -1` = "grab any plausible txid," not "grab *the penalty*."
2. **Coincidental passing** — the breach txid *does* confirm (the cheater broadcast it), so `wait_confirm` succeeded for the *wrong reason*; on the happy path the machinery fired *and* the breach confirmed, so a wrong assertion held for months.
3. **Documented-TODO-as-false-pass** — the most dangerous variant (cheat_client): a comment promises rigor the code never delivers, and GREEN masks it.

Lesson: **a defense that *runs* is not a defense that *works*.** A penalty that fires but
pays the wrong amount/party is a catastrophic real-world failure an existence check passes.

## 3. The standard (and models that already meet it)

Every breach/penalty/sweep test must assert the **adversarial outcome**:
1. the **correct artifact** — penalty/sweep txid extracted from an *anchored* line (never `head -1`);
2. it **confirmed on-chain** (`wait_confirm` / `getrawtransaction` blockhash / `gettxout` / confirmations ≥ N), not just broadcast;
3. the **amount is right** — swept ≈ breached `to_local` (or pro-rata redistribution), to a key the victim controls;
4. the **cheater nets ≤ 0** (beyond expected dust);
5. **no latent false-passes** — no undefined helpers, no log-greps that print regardless, no escape-hatch `exit 0`.

**Good models already in the tree (copy these):**
- `tools/test_regtest_crash_drill_matrix.sh` — enforces the §2 invariant (state must never be `FINALIZED(3)` post-checkpoint); no-fire → retry-then-FAIL.
- `tools/test_regtest_mass_exit.sh` — real **amount conservation** (`ACTUAL` within `[70% EXPECT, EXPECT+slack]` and `≤ AMOUNT`) over confirmed commitments.
- `tools/test_signet_scale_payments.sh` / `test_regtest_n64_payments.sh` — anchored close-txid + on-chain confirm + sat conservation with `fee ≤ 1%`.
- `tools/test_regtest_rotation_restart_resume.sh` — idempotency + on-chain confirm of the single close.
- The **fixed signet trio** (PR #384): `test_signet_trustless_commitment_breach.sh`, `test_signet_subfactory_breach.sh`, `test_signet_wt_restart_race.sh`.

## 4. Severity-ranked findings

### Tier 1 — can PASS while the protocol silently misbehaves
| # | File:line | Class | Gap → fix |
|---|-----------|-------|-----------|
| 1 | `test_regtest_cheat_client.sh:186` | C/E/B | Comment promises net-delta(cheater)≤0; code only counts `broadcast_log result='ok'`. **Implement the sat net-delta** (confirmed sats to cheater vs stealable; require ≤0). |
| 2 | `test_regtest_ps_commitment_penalty.sh:58,69` | B/C/E | PASS on an LSP "penalty broadcast" log line + wt.db arming. **Confirm penalty txid spends the revoked commitment + assert value.** |
| 3 | `test_regtest_trustless_commitment_breach.sh:76,86` | B/C | Regtest twin of the fixed signet test; PASS on WT broadcast line. **Port the signet wait_confirm + real-txid + amount fix.** |
| 4 | `test_regtest_cheat_daemon_{subfactory,leaf,leaf_late_wt,rollover}.sh` (~:218/:259/:188/:203) | B/C | Broadcast-line PASS; weaker than the confirming `k2` sibling. **Confirm poison/penalty txid + amount.** |
| 5 | `test_regtest_cheat_daemon_leaf_multistate.sh:349` | E | Accepts Tier-B-neutralization as PASS — the false-positive its sibling `cheat_leaf_multistate.sh:189` explicitly rejects. **Remove the Tier-B PASS branch; require WT-defense confirmation.** |
| 6 | `test_regtest_cheat_realloc.sh:208` / `test_regtest_cheat_lstock_buy.sh:204` | B/C | Two log-line existence counts. **Confirm on-chain + assert redistributed amount.** |
| 7 | `test_regtest_crash_at_every_phase.sh:226` | E | `exit 0` when zero ceremony rows written (escape hatch). **Make no-rows branch SKIP/XFAIL, not pass.** |

### Tier 2 — marker-only (rigor delegated to unseen C `.inc` assertions)
| File:line | Note |
|-----------|------|
| `test_regtest_htlc_force_close.sh:64` | "broadcast + confirmed" claimed; harness verifies neither. `kind3` sibling shows how to confirm. |
| `test_regtest_ptlc_breach_chain.sh:71` | "real chain" billed; marker-only. PTLC hits BIP-431 TRUC (`ptlc_penalty=0` risk) — exactly where a zero-value penalty could slip through. |
| `test_signet_selfdrive.sh:51,57` | PASS = single `grep -qF "…TEST PASSED"`, on signet. |
| `test_regtest_cheat_leaf.sh` | PASS = `grep -q "LEAF ADVANCE TEST PASSED"`; `broadcast_log` dumped but not asserted. |
| `test_regtest_ptlc_breach.sh:77` | In-process builder by design (no broadcast); marker-only defensible, name oversells. |

**Fix (common):** after the marker, extract the penalty/sweep txid + confirm on-chain + assert amount.

### Tier 3 — confirms on-chain but misses the amount (class C only)
| File:line | Gap → fix |
|-----------|-----------|
| `test_regtest_kind3_force_close_standalone.sh:111` | Confirms the sweep (`confirmations ≥ 1`, correct `tail -1`) but never the **value** or that it spent the HTLC output. **Add value + correct-input assertion.** |
| `test_regtest_k2_subfactory_breach.sh:347` (+ `k3`–`k6` wrappers that `exec` it) | Confirms the poison TX + checks output **count** but not per-client **amounts**. `assert_vout_distribution` (in `regtest_test_helpers.sh`) exists for this. **Assert pro-rata distribution.** |

### Tier 4 — minor / latent / by-design
- `test_regtest_wt_restart_race.sh:141` — class A `head -1` **fallback** after a correct anchored extraction. **Fail instead of falling back to any hex** (same fix already applied to the signet twin).
- `test_regtest_adversarial_reorg.sh:226`, `test_regtest_same_height_reorg.sh:136` — PASS = WT *logs* "REORG"; never proves watches survive + a penalty re-fires post-reorg. **Assert post-reorg penalty.**
- `test_regtest_rebroadcast_recovery.sh:282` — PASS on the resend log line; reconfirmation unverified (acknowledged). **Confirm the resent tx on a chain that retains it (testnet4/signet).**
- `test_regtest_cheat_jit.sh:226` — class E **by design** (`project_jit_no_wt_registration`: detection is the defense, no penalty). Acceptable.
- `test_regtest_cheat_dust_race.sh`, `test_regtest_cheat_backup_restore.sh` — honestly-scoped smoke tests; names oversell.
- `test_regtest_watchtower_trustless.sh` — strong on trustless invariants (byte-level secret scan, `/proc/maps`, `nm`, `--db` refusal); header overclaims "end-to-end detect+react" but PASS only checks arming/hydration. **Reconcile header to actual assertions.**
- `test_regtest_trustless_commitment_gap.sh:65` — arming regression guard by design; depends on #3 (Tier-1) to prove firing.

### Already fixed (PR #384, signet)
- `test_signet_trustless_commitment_breach.sh` — real penalty txid + `wait_confirm` + amount ≥ 20k (validated: 30,871 sats).
- `test_signet_subfactory_breach.sh` — added `wait_confirm`/`confirm_height` + penalty-confirm + amount ≥ 5k.
- `test_signet_wt_restart_race.sh` — dropped the `head -1` fallback.

### Daemon (operational, not a repo test, but same spirit)
- `_recover_our_keys.py` taproot sweep — fixed to use `descriptorprocesspsbt` (was leaving taproot inputs unsigned → stranded 99,750 sats). Validation pending.

## 6. Re-run findings (2026-06-18 signet matrix)

The fixed signet trio was re-run on real signet. Verdicts: **commitment_breach PASS**,
**wt_restart_race PASS**, **subfactory_breach reported FAIL** — investigated below.

- **commitment_breach — PASS (proven at confirmation level).** Real penalty confirmed,
  largest output **30,871 sats** ≈ breached `to_local`. This is the proof the old
  broadcast-only check never gave.
- **subfactory_breach — FALSE FAIL; the *defense* is proven on-chain.** The standalone WT
  hydrated the kind=1 sub-factory watch, broadcast the latest-state penalty
  `cf4e4bf…a79dcc`, and it **confirmed (24 confs)**: it spends the breach
  `c79aeb…c1fb6c` (3 inputs) and redistributes **132,800 sats** to 3 honest outputs
  (55,416 + 44,333 + 33,051). Sub-factory trustless defense **PROVEN on signet at the
  confirmation level** — *not* a protocol gap.
  - **Root cause of the FAIL:** the sub-factory breach is a **2-stage** confirmation —
    the stale chain (`c79aeb`) must confirm *first*, then the latest-state penalty
    (`cf4e4bf`) can spend it. That is ~2× the block-waits of the single-stage commitment
    penalty (which spends an already-confirmed commitment). `wait_confirm`'s budget ran
    out before signet's variable block timing produced *both* confirmations; the penalty
    confirmed shortly after the test gave up.
  - **Lesson (refines §3, not a regression of it):** a confirmation check is correct, but
    its budget must cover the *longest confirmation chain* the defense requires. Multi-stage
    breach→penalty paths (sub-factory, force-close) need a budget ≥ N sequential confirms.
    The fix is a 2-stage-aware budget — **never** revert to broadcast-only to "make it green."
  - **Fix:** give the sub-factory penalty confirm a budget sized for 2 sequential signet
    confirmations, and make the timeout message say "not confirmed within budget — re-check
    on-chain (signet 2-stage breach→penalty can exceed this)" instead of implying the
    defense failed. Also note the cosmetic WT log label ("FACTORY BREACH" printed for a
    kind=1 sub-factory watch — the LSP log correctly says "SUB-FACTORY BREACH").

## 7. Remediation status

### Tier 1 — COMPLETE (#34)
All seven Tier-1 rows now assert the adversarial OUTCOME (real txid → on-chain confirm →
amount/net-delta), not that machinery fired. Branch `test/harness-rigor-remediation`:
| # | File | Fix | Commit |
|---|------|-----|--------|
| 1 | `cheat_client.sh` | net-delta(cheater)≤0 on-chain: real defense txids, confirm ≥1, amount ≥5k, cheater's stale tx yields no surviving value | b34a6c5 |
| 2 | `ps_commitment_penalty.sh` | extract penalty txid, confirm, amount ≥5k | 77575ae |
| 3 | `trustless_commitment_breach.sh` | port signet fix: anchored txid, mine-confirm, amount ≥5k | 1c1eb05 |
| 4 | `cheat_daemon_{subfactory,leaf,leaf_late_wt,rollover}.sh` | response_txid (+log fallback), confirm (10-blk loop, 2-stage tolerant), amount >dust | 97b9fc1 |
| 5 | `cheat_daemon_leaf_multistate.sh` | drop Tier-B false-PASS → SKIP(77); WT path now confirms response on-chain + amount | 70b7dc7 |
| 6 | `cheat_realloc.sh` / `cheat_lstock_buy.sh` | defense txid, confirm, redistribution amount >dust | 5cff584 |
| 7 | `crash_at_every_phase.sh` | escape-hatch `exit 0` → SKIP `exit 77` | f2108d4 |
| (T4) | `wt_restart_race.sh` | drop head-1 fallback | f2108d4 |
| (signet) | `subfactory_breach.sh` | 2-stage-aware confirm budget (proven cf4e4bf, 132,800 sats) | b5484d4 |

**Validated on VPS regtest (2026-06-19), each PASS verifying the real on-chain amount:**
| test | result | proof |
|------|--------|-------|
| `trustless_commitment_breach` | PASS | penalty confirmed, 11843 sats swept |
| `cheat_client` | PASS | defense 53e3f4 confirmed, 11150 sats, "cheater net ≤0 verified on-chain" |
| `wt_restart_race` | PASS | re-hydrated from wt.db, no head-1 fallback |
| `crash_at_every_phase` | PASS | rc=0, state invariant held across kill points |
| `ps_commitment_penalty` | PASS | penalty bbfd92 confirmed, 11843 sats |
| `cheat_daemon_subfactory` | PASS | response 48a697 confirmed, 55416 sats |
| `cheat_daemon_leaf` | PASS | response e4140d confirmed, 11950 sats |
| `cheat_daemon_leaf_late_wt` | PASS | response 4d3a49 confirmed, 11950 sats (10-blk-late WT) |
| `cheat_realloc` | PASS | defense confirmed on-chain |
| `cheat_lstock_buy` | rc=0 (re-confirm value in #3) | redistribution defense |
| `cheat_daemon_rollover` | rc=1 — **pre-existing ASan flakiness** (test LD_PRELOADs libasan; LSP died before detection, so the 3-signal gate failed and my confirm code never ran). Re-run in #3. |
| `cheat_daemon_leaf_multistate` | rc=126 — **real bug found**: script was mode 100644 (not +x). The matrix runs via `bash x.sh` so it was masked; the runner execs directly → 126. Fixed (02f83d0). Re-run in #3. |

getrawtransaction (txindex on), mine-to-confirm loop, and amount extraction all work on the
VPS regtest. **9/12 Tier-1 green** (commitment, cheat_client, wt_restart, crash, ps_commitment,
subfactory, leaf, leaf_late_wt, realloc); multistate fixed (+x) + rollover (ASan infra) re-running in #3.

### Tier 2 — DONE (validating in run #3)
| File | Fix | Commit |
|------|-----|--------|
| `htlc_force_close.sh` | marker → independent HTLC timeout-sweep txid + on-chain confirm + amount | 69e2529 |
| `cheat_leaf.sh` | marker → WT defense confirmed on-chain+amount, OR (CLTV-gated leaf) a real detection signal | 69e2529 |
| `ptlc_breach_chain.sh` | marker → ptlc_penalty count≥1 (TRUC catch) + penalty txid confirmed on-chain + amount>dust | 46984d4 |
| `ptlc_breach.sh` | marker → ptlc_penalty count≥1 OR built txid (in-process by design; message reconciled) | 46984d4 |

### Tier 3 — DONE (validating in run #3)
`kind3` swept-amount assert (480a6a3); `k2` per-client min-output >dust, inherited by k3–k6 wrappers (a472458).

### Tier 4 — partial
`watchtower_trustless.sh` overclaiming header reconciled (0c3d8f4). **Still OPEN:**
`test_signet_selfdrive.sh` (signet marker-only), `adversarial_reorg`/`same_height_reorg`
(prove a penalty RE-fires post-reorg, not just that "REORG" was logged), `rebroadcast_recovery`
(reconfirm the resent tx on a chain that retains it).

## 5. Remediation plan
1. **Tier 1** (#34): worst-first, each = extract real txid → `wait_confirm` → assert amount/net-delta. PR against `integration/security-e2e`.
2. **Tier 3** (#35): add amount/distribution assertions (helpers exist).
3. **Tier 4** latent: `wt_restart_race` fallback, crash escape-hatch, multistate Tier-B branch.
4. **Tier 2**: add harness-side confirm+amount after the C marker.
5. **Headers/names**: reconcile overclaiming docstrings to actual assertions.

Every fix copies the standard in §3 and the models listed there. Re-run each fixed test
(regtest is reliable + fast) to confirm it still PASSes for the *right* reason.
