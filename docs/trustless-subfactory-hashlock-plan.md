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
