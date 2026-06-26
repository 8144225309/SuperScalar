# Sub-factory hashlock L-stock poison — plan (branch `trustless-subfactory-hashlock`)

Extends the hashlock-gated L-stock poison (#387 leaf-advance + #388 crash/restart) to the
**sub-factory (k≥2) multi-input ceremony**, where a canonical PS factory holds its channels.
Without this, a k≥2 factory's sub-level sales-stock is still key-path → Scenario B open there.
Stacked on `trustless-hashlock-reveal-crash` (#388).

## What investigation found (corrects stale assumptions)
- **The multi-input keyagg bug (#283/#61) is ALREADY FIXED.** lsp_channels.c:3712+ uses per-input
  keyaggs (`sub->input_keyaggs[i]`: channel inputs 2-of-2, sales-stock N-of-N), per-input signing
  sessions, `factory_session_get_input_signer_slot`. So #61 is NOT a blocker.
- **The sub-factory multi-input poison ceremony EXISTS but is KEY-PATH.** The prepare call at
  lsp_channels.c:3534-3537 passes `override_hash32 = NULL` with the literal placeholder
  `/* #53-B3b: capture sub H_old when daemon hashlock on */` — the exact analog of the
  leaf-advance placeholder filled in #387 Phase 1.
- **The sub sales-stock IS hashlock-gated at INITIAL build**: setup_ps_leaf_with_subfactories →
  setup_nway_leaf_outputs (factory.c:1266) → set_leaf_l_stock_output (1399) → apply_l_stock_hashlock.
  So for a hashlock factory `sub->has_l_stock_hash` is set + the prepare (factory.c:3151
  `if (override_hash32 || sub->has_l_stock_hash)`) already takes the hashlock path.
- **PREREQUISITE GAP — the sub sales-stock hash is STATIC across sub states.** The sub-advance
  `factory_subfactory_chain_advance_unsigned` (factory.c:2616) → `rebuild_node_tx` (2195) rebuilds
  the tx from existing output SPKs; it does NOT bump `l_stock_state_counter` or re-derive the
  sales-stock SPK. So every sub state shares the state-0 hash. Revealing one sub secret would
  compromise the hashlock for ALL sub states (reopening Scenario B). The leaf path avoids this via
  `update_l_stock_for_leaf` (factory.c:2400, bumps counter + re-derives); the sub path needs the same.
- The deterministic per-factory seed (#388) already covers sub nodes (seed is per-factory; secrets
  are keyed by the sub node's agg xonly + state counter — distinct from leaves automatically).

## Phases (mirror #387/#388; each committed + validated)
- **Phase 0 — per-state sub sales-stock hash (PREREQUISITE).** On each sub-advance, bump
  `sub->l_stock_state_counter` + re-derive the sales-stock SPK (apply_l_stock_hashlock) so each sub
  state commits a DISTINCT hash. Likely: call the leaf-style update (or inline the bump+re-derive)
  inside `factory_subfactory_chain_advance_unsigned` after the amounts mutate / inside
  rebuild_node_tx for NODE_PS_SUBFACTORY. Unit-prove distinct hashes per sub state. CRITICAL — the
  per-state revocation model depends on it.
- **Phase 1 — H plumbing.** Capture sub H_old before the advance; pass as override at
  lsp_channels.c:3537 (replace the NULL placeholder). Ship sub H_new in the sub-factory
  PROPOSE_INTENT; client mirrors via factory_set_node_l_stock_hash before its sub-advance.
- **Phase 2 — reveal.** After the sub-factory DONE, LSP reveals secret(sub_node, old_counter) via
  MSG_LSTOCK_REVEAL (array API already supports it); client verifies + persists.
- **Phase 3 — fail-closed guard.** Mirror the leaf guard: when use_hashlock_poison, the sub-advance
  must abort if the sub poison wasn't co-signed (no revoke without recourse), gated on
  poison_required (sub sales-stock non-dust).
- **Phase 4 — client mirror.** The client's sub-factory multi-input handler mirrors Phases 0-3
  (per-state hash, H_old/H_new, reveal recv+persist, guard).
- **Phase 5 — e2e.** Sub-factory cheat harness with --enable-hashlock-poison: advance a sub channel
  → reveal → persist → LSP broadcasts the stale sub state → client assembles the sub poison from the
  persisted reveal → confirm + redistribution + anti-vacuity. Then signet.

## Reuse (no rework)
factory_derive_lstock_seed / factory_derive_l_stock_secret (sub nodes keyed by agg xonly automatically);
factory_session_prepare_poison_tx_subfactory (already override-aware, factory.c:3151);
factory_assemble_poison_from_template + superscalar_lstock_recover (node-indexed, works for sub nodes);
MSG_LSTOCK_REVEAL[_REQUEST] array wire; persist l_stock_poison_reveals (keyed by node_idx); v39 flag.

## Notes
- This is a #387-scale effort (both sides + the Phase-0 prerequisite). The poison assembly +
  recourse + persist + restart-resume all carry over unchanged (node-indexed).
- The multi-input poison signs the sales-stock input against the sub N-of-N keyagg (correct — the
  sales-stock IS the sub N-of-N output; the per-channel 2-of-2 keyaggs are for the CHANNEL inputs,
  already handled by #283).

## Implementation status — DONE (commits 49383ba, 26dc6de, 6c6e2b9)

What the build actually required, vs the plan above (some plan steps turned out to be no-ops
because the existing infra was already generic):

- **Phase 0 (49383ba):** `factory_subfactory_chain_advance_unsigned` bumps the counter +
  re-derives the sales-stock SPK when `sub->has_l_stock_hash` (factory.c). Unit-proven by
  `test_factory_subfactory_lstock_per_state_hash` (distinct H per state + superseded-secret
  stability + a non-hashlock STATIC-SPK control).
- **Phase 1 (26dc6de):** LSP ships H_new in `SUBFACTORY_PROPOSE_INTENT` (multi at
  lsp_channels.c ~3605, single too); client mirrors at the parent-handler top (covers both
  paths). The H_old-capture in the plan is UNNECESSARY: sub poison-prep runs BEFORE the advance,
  so the NULL override already snapshots H_old (unlike the leaf, which preps after the advance and
  must pass H_old explicitly). `factory_set_node_l_stock_hash` updates only `node_l_stock_hashes[]`,
  not `sub->l_stock_hash`, so prep still sees H_old even with the mirror set first.
- **Signing:** NO new code. `factory_session_finalize_node_poison` / `_complete_node_poison`
  are node-generic + already scriptpath-aware (untweaked agg) from #387; once Phase 0 makes
  prep set `poison_is_scriptpath`, the sub poison co-signs correctly.
- **Phase 2 (26dc6de + 9e12d44):** LSP reveals secret_old to EVERY sub client after DONE
  (sales-stock is N-of-N; all are beneficiaries). **N-party agg-sig gap (9e12d44):** unlike the
  2-party leaf (whose client aggregates the poison locally), only the LSP aggregates the N-party
  sub poison, so the client never had `poison_agg_sig`. Fix: the LSP ships the aggregated 64-byte
  poison sig in `SUBFACTORY_DONE` (optional field). The client captures it on DONE, persists the
  recourse TEMPLATE (agg-sig present, secret NULL), then verify-persists the secret from the
  reveal; the poison-session reset is deferred past both. Crash recovery is then symmetric with
  the leaf: template durable pre-reveal, 0x8D `MSG_LSTOCK_REVEAL_REQUEST` (#388, node-generic)
  re-fetches the secret.
- **Phase 3 (26dc6de):** LSP + client fail-closed abort when a poison was economically REQUIRED
  (non-dust sales-stock) but NOT co-signed. `poison_required` is decoupled from the
  watchtower/operational prep gate, mirroring the leaf guard.
- **Phase 4:** folded into the client edits above (per-state hash is shared advance code; H_new
  mirror, reveal recv+persist, guard all added to the client multi handler).
- **Defense-in-depth:** the single-input sub paths are unreachable for real (k>=1) subs
  (n_outputs>1 always dispatches multi). The LSP refuses single-input under hashlock; the client
  refuses a single-input PROPOSE for a hashlock sub (closes a malicious-LSP downgrade vector).
- **Phase 5 (6c6e2b9):** `test_regtest_hashlock_poison_subfactory_e2e.sh` — the existing
  `--cheat-daemon-sub` already drives the stateless multi path (`lsp_subfactory_chain_advance`
  forwards unconditionally to `..._stateless`), so combining it with `--enable-hashlock-poison`
  exercises Phases 0-4 over the LIVE wire ceremony. Then client-driven recourse: assemble the sub
  poison from the persisted reveal, broadcast vs the cheat's stale chain[N-1], assert CONFIRM +
  non-dust sales-stock recapture + anti-vacuity.

Validation: build OK + full unit suite 1510/1510 (incl. the new Phase-0 test). Regtest GREEN:
- T1 no-regression (non-hashlock multi sub advance, k=2): PASS.
- T2 hashlock e2e: PASS — live multi-input advance -> per-state H -> reveal -> client
  verify-persist -> assemble -> broadcast vs the cheat's stale chain[N-1] -> CONFIRM,
  21,667 sats sales-stock recaptured; anti-vacuity (no secret -> exit 5) enforced.
The first e2e run caught a real N-party gap (only the LSP aggregates the sub poison; the
client never had poison_agg_sig) -> fixed by shipping the agg-sig in SUBFACTORY_DONE (9e12d44).

Adversarial-review hardening (736620f): the N-party agg-sig crosses the wire, so it is now
VERIFIED before trust on BOTH sides (mirror of the leaf LSP verify at lsp_channels.c ~1782) --
client verifies the LSP-supplied agg-sig vs its own poison sighash + untweaked sub agg key
before persisting (a malicious LSP can't hand it worthless recourse); LSP self-verifies the
aggregate before shipping (catches a bad co-signer partial -> degrade -> fail-closed abort).
Honest flow unchanged; regtest T1+T2 RE-GREEN with the hardening.

Signet to follow (cryptographic flow is network-independent; regtest is the gate).
