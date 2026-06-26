# Hashlock-poison DAEMON INTEGRATION — phased plan (new PR: `trustless-hashlock-daemon`)

Stacked on `trustless-model-hardening` (PR #386), which has all the unit/interpreter-proven layers:
crypto core, per-(leaf,state) secret derivation, multi-process ceremony→Leaf-P, old-state targeting,
client SPK mirror+wire, `MSG_LSTOCK_REVEAL`, persist `l_stock_poison_reveals` (v38). This PR makes the
feature LIVE in the LSP↔client daemons and proves it end-to-end. Scope = the **leaf-advance path**
(`lsp_advance_leaf_stateless`, the 2-of-2 PS-leaf — the master-plan priority); Tier-B rollover + sub-factory
are a parallel follow-on (same pattern).

## The crux found by code review (the high-level plan missed it)
Enabling hashlock changes the leaf STATE tx (its last output is the 2-leaf L-stock SPK).  So at EACH advance,
beyond revealing the old secret, the protocol must thread the per-(leaf,state) hash:
1. **Ship `H_new`**: the client has no seed, so the LSP must ship the advancing leaf's NEW-state hash so the
   client builds the IDENTICAL new leaf-state SPK (else the MuSig co-sign of the new state mismatches → the
   advance fails — not just the poison).
2. **Capture `H_old`**: the poison co-signed during the advance must target the SUPERSEDED state's output
   (`H_old`), but by poison-prep time both sides have already advanced (`node->l_stock_hash == H_new`).  So
   both sides must capture `H_old` *before* the advance and pass it as `override_hash32` to
   `factory_session_prepare_poison_tx_leaf` (the B3b-part-1 deferred per-site capture lands here).
3. **Reveal `secret_old`**: after the new state signs, the LSP reveals `secret(leaf, old_counter)`; the client
   verifies `SHA256==H_old` and persists for standalone recourse.

## Verified injection points (file:line)
LSP `lsp_advance_leaf_stateless` (src/lsp_channels.c 1353–1933):
- advance bumps counter: `factory_advance_leaf_unsigned` @1418 (so capture `H_old` from `f->nodes[pre_node_idx].l_stock_hash` BEFORE 1418).
- PROPOSE build/send: @1468/1469 (ship `H_new = node->l_stock_hash` here — after the advance, it's H_new).
- poison prep: @1441 (pass `override = H_old`).
- DONE broadcast: @1894–1899.  REVEAL send goes right AFTER, targeted to the leaf's client(s) (not broadcast).
- `factory_session_reset_poison` @1891 clears session fields — irrelevant: the reveal secret is re-derived
  from the seed via `factory_derive_l_stock_secret`, not read from the session.

Client `client_handle_leaf_advance_stateless` (src/client.c 3534–3910):
- parse PROPOSE @3547; `node_idx` @3563; capture `H_old = node->l_stock_hash` @3564 (before any change);
  mirror `H_new` (from PROPOSE) via `factory_set_node_l_stock_hash` BEFORE the local advance @3566.
- poison prep @3597 (pass `override = H_old`).
- recv DONE @3909.  recv REVEAL right after when `node->poison_is_scriptpath`; verify
  `SHA256(secret)==node->poison_l_stock_hash` (=H_old, set in prep); persist; THEN return success (#59 order).

LSP factory creation `src/lsp.c::lsp_run_factory_creation_stateless`: seed @436, build_tree @442, PROPOSE @448.
`factory_enable_hashlock_poison(f)` goes between 437 and 442 (NOT superscalar_lsp.c — factory_init_from_pubkeys
@lsp.c:413 wipes use_hashlock_poison).

## Phases (each committed; phases 1–3 are interdependent, first provable at Phase 4 / B6)

**Phase 1 — advance H plumbing (leaf-advance).** Ship `H_new` in `MSG_LEAF_ADVANCE_PROPOSE` (add an optional
`l_stock_hash` field); client mirrors it before its advance; both sides capture `H_old` + pass it as the poison
`override`. Result: a hashlock-enabled leaf advance co-signs the new state correctly AND co-signs the poison
against the OLD state.

**Phase 2 — reveal (leaf-advance).** LSP derives `secret(leaf, counter−1)` + sends `MSG_LSTOCK_REVEAL` to the
leaf's client(s) after DONE (gated on `f->use_hashlock_poison` + poison-eligible). Client recv (when
`poison_is_scriptpath`) → verify fail-closed → `persist_save_l_stock_poison` (the ceremony's poison fields) +
`persist_update_l_stock_secret`.

**Phase 3 — daemon enable.** `--enable-hashlock-poison` CLI flag in superscalar_lsp.c → set a real random
`factory_set_shachain_seed` + an `lsp->enable_hashlock_poison` flag; call `factory_enable_hashlock_poison(f)`
in `lsp.c` between seed-set and build_tree. (Client needs no flag — it mirrors per-node H off the wire.)

**Phase 4 — B6 e2e (the proof for phases 1–3).** Extend a breach harness: launch LSP (`--enable-hashlock-poison`)
+ client + WT on regtest; advance a leaf (so a state is superseded + the reveal fires + the client persists);
have the LSP broadcast the STALE old leaf state; the client/WT assembles the Leaf-P poison from the PERSISTED
secret and broadcasts it; assert it CONFIRMS and redistributes the L-stock (economic outcome), under fee
pressure. Anti-vacuity: a control where the secret was never revealed → poison unspendable.

**Phase 5 — B4 delete degradation (gated).** Convert the ~80 "reset_poison + clear-flag + continue" sites
(lsp_channels.c + client.c) to hard-abort (`return 0`, stay on old state) WHEN `f->use_hashlock_poison`
(LSP) / `node->has_l_stock_hash` (client). Re-prove with B6 + a full regression (legacy key-path path
unchanged when the flag is off).

## Testing per phase
- Phases 1–3: build-clean + full unit regression after each (catch wire/ceremony/daemon regressions); the
  legacy path (flag off) must stay green — these phases are no-ops until Phase 3 flips the flag.
- Phase 4: the B6 e2e is the end-to-end proof of 1–3 (on-chain confirm + amount + anti-vacuity).
- Phase 5: B6 (still green) + full regression (legacy untouched) + a degradation-abort assertion.

## Phase 4 — CORRECTED by code review (the plan-doc above under-scoped it)

Code review (2026-06-21) found `factory_assemble_poison_with_secret` is wired into **no
broadcast path** — only unit tests.  The breach-response path (watchtower.c) still
broadcasts a static pre-built `burn_tx`, which for the key-path poison was the whole TX
but for the hashlock poison CANNOT exist at registration time (the secret isn't revealed
yet).  So Phase 4 needs CODE before the e2e test, split:

- **Phase 4a (primitive, DONE):** `factory_assemble_poison_from_template()` — standalone
  assembly from the exact fields persisted in `l_stock_poison_reveals` (unsigned tx, agg
  sig, leaf script, control block, target hash, revealed secret), with the
  SHA256(secret)==hash fail-closed guard.  `factory_assemble_poison_with_secret` now
  delegates to it (DRY).  Proven in the regtest ceremony test: from_template output is
  byte-identical to with_secret AND `testmempoolaccept` ACCEPTS it, with wrong-secret
  refused.  This is the persist-driven recourse primitive both the client and any
  client-fed WT will call.

- **Phase 4b (client recourse driver):** a client-side path that, on a superseded leaf
  appearing on-chain, loads its persisted reveal row (`persist_load_l_stock_poison`),
  assembles via `factory_assemble_poison_from_template`, and broadcasts.  For the e2e
  PROOF this is a clearly-marked test driver (a `--test-*` flag / small tool), NOT yet
  the production recourse loop — see the architecture note below.

- **Phase 4c (daemon e2e):** LSP `--enable-hashlock-poison --cheat-daemon-leaf` + client
  daemons advance over the wire (the LIVE Phase 1–2 reveal path fires: the client
  persists a real `l_stock_poison_reveals` row); the LSP broadcasts the STALE superseded
  leaf; the client recourse driver assembles-from-persist + broadcasts; assert CONFIRM +
  L-stock redistribution (amount) + anti-vacuity (no reveal → unspendable).

### ARCHITECTURE NOTE (surfaced for the user; default chosen to keep momentum)
Who assembles the hashlock poison?  The standalone `superscalar_watchtower` reads a
**secret-less** wt_db — by design it CANNOT hold the LSP-revealed preimage, so it cannot
assemble a hashlock poison alone.  Only the party that received the reveal (the CLIENT, or
a WT the client explicitly feeds revealed secrets) can.  This is the crux of #62 (WT
operational model) and reshapes the "trustless WT" story for the L-stock poison
specifically.  DEFAULT taken: the recourse is **client-driven** (the client holds its own
revealed secrets); the secret-less third-party WT remains the recourse for the
non-hashlock paths (factory/sub-factory/commitment penalties).  Feeding revealed secrets
to a delegated WT is the explicit follow-on under #62 — NOT folded into this PR.

## STATUS — Phases 1-4 COMPLETE + PROVEN (2026-06-21)
- Phase 1 (advance H plumbing), Phase 2 (reveal-on-advance), Phase 3 (daemon
  `--enable-hashlock-poison`): committed; FULL BUILD + 1507/1507 unit + regtest
  advance spot-checks green (inert with the flag off).
- Phase 4a (`factory_assemble_poison_from_template` + DRY): regtest ceremony test
  proves from_template == with_secret byte-for-byte AND `testmempoolaccept`
  ACCEPTS; wrong-secret refused.
- Phase 4b (`superscalar_lstock_recover`): builds; usage + anti-vacuity smokes.
- Phase 4c (daemon e2e, `test_regtest_hashlock_poison_e2e.sh`): **GREEN on
  regtest** — LSP `--enable-hashlock-poison --cheat-daemon-leaf` advances a PS
  leaf over the live wire, client[0] PERSISTS the reveal (node=5 state=0), the
  recourse tool assembles the poison from the persisted template+secret, it
  CONFIRMS on-chain (txid ae6a4f62…, 11150 sats L-stock recaptured), and the
  no-reveal control REFUSES (exit 5).  First live exercise of the reveal wire +
  the assemble-from-persist recourse; no prevout/wire bug.

## Phase 5 — B4 degrade->hard-abort — DONE + REVIEWED (2026-06-21)
A degraded advance that revokes the old state WITHOUT co-signing the Leaf-P poison
re-opens Scenario A/B.  Implemented as a single fail-closed guard per side, placed
at the commit point, that subsumes every degrade-and-continue site:
- client.c (security-critical): before shipping FINAL (the revocation commit),
  refuse if `has_l_stock_hash && poison_required_c && !leaf_poison_prepared_c`.
- lsp_channels.c: symmetric honest-LSP guard after poison verify/finalize, before
  register/persist/DONE; also clears node->is_signed + signed_tx on abort.
Self-review refinement (commit 914f9fc): gate on `poison_required` (old state has a
protectable, non-dust L-stock) so the guard never false-aborts when no poison was
ever needed (dust / no old state); still fail-closed on no-watchtower / cheat.
Test hook `SS_CHEAT_OMIT_POISON` + `test_regtest_hashlock_poison_abort.sh` prove
the client actually refuses (no reveal persisted, advance does not complete).

## VALIDATION — full 5-gate run GREEN on 914f9fc (2026-06-21)
FULL BUILD OK; 1507/1507 unit; legacy regtest advances 1/1 (flag off unchanged);
4c happy-path e2e PASS (poison confirmed, 11150 sats recaptured, no-reveal exit 5);
degradation-abort PASS (client refused, 0 reveals persisted).  Phases 1-5 done.
Follow-ons (separate PRs): Tier-B rollover, sub-factory (blocked on multi-input
keyagg bug), #59 reveal crash matrix, #62 delegated-WT secret feeding.

## #59 (crash-consistency) — tracked separately
The reveal is the last LSP→client step; a crash between new-state-signed and secret-persisted is the residual
window. Phase 2 persists the secret in-handler before returning success (verify-before-accept). The full
"live-pointer advances only on durable recourse" refinement + a crash matrix is task #59 (follow-on), not this PR.
