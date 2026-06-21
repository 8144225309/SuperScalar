# Hashlock poison — TIER-B ROLLOVER integration (branch `trustless-hashlock-tierb`)

Stacked on `trustless-hashlock-daemon` (PR #387), which made the hashlock L-stock poison
LIVE for the **leaf-advance** path (advance H plumbing → reveal → assemble-from-persist →
fail-closed guard, proven e2e on regtest). This branch applies the SAME pattern to the
**Tier-B rollover** ceremony, which re-signs the non-PS-leaf nodes for a new epoch.

## Scope + the key difference vs leaf-advance
- LSP: `lsp_run_state_advance_stateless` (src/lsp_channels.c:2062). Client: the Tier-B
  handler near src/client.c:4031 ("Mirrors lsp_run_state_advance_stateless").
- Tier-B poisons the **non-PS-leaf** nodes (intermediates/factory nodes that carry an
  L-stock output): the per-node prep gate is `!an->is_ps_leaf && had_old && old_no >= 2 &&
  amount > fee+dust` (lsp_channels.c:2191). PS leaves carry their poison in their own
  sub-factory chain (the leaf-advance path).
- The difference from leaf-advance: everything is a **loop over `affected[]`** (multiple
  nodes per rollover), so H_old / H_new / reveal / guard are all PER-NODE. The per-node
  arrays are already scaffolded (poison_prepared[k], poison_old_txid[k], … at 2154-2167).
- No new daemon flag: `--enable-hashlock-poison` already sets factory-wide
  `use_hashlock_poison`; Tier-B inherits it.

## Phase 0 — VERIFY non-PS-leaf nodes get hashlock SPKs at build
`apply_l_stock_hashlock` runs via `set_leaf_l_stock_output` (factory.c). Confirm the
non-PS-leaf node build paths route through it so these nodes carry the 2-leaf hashlock
L-stock SPK when `use_hashlock_poison` (else there's nothing to target). If a build path
is missed, fix it before the rest (mirrors how the leaf path was already covered).

## Verified injection points (file:line)
LSP `lsp_run_state_advance_stateless` (2062-2763):
- Per-node poison prep loop @2168-2201. The override is the literal placeholder at 2197:
  `NULL /* #53-B3b: capture per-node H_old when daemon hashlock on */`. Capture
  `H_old[k] = f->nodes[affected[k]].l_stock_hash` BEFORE the node is re-signed to the new
  epoch, and pass it as `override_hash32` here.
- PROPOSE_INTENT build/send @2234 (`wire_build_state_adv_propose_intent`). It carries NO
  per-node hashes today — add a per-affected-node `H_new` map so the seedless client builds
  the IDENTICAL new-state SPK for each affected node (else the co-sign mismatches). H_new[k]
  is derivable as `sha256(secret(node, new_counter))` — derive per affected node when
  `use_hashlock_poison`.
- Per-node watchtower register + `factory_session_reset_poison` loop ends @2716.
- Step 11.5 persist @2721; DONE broadcast @2744-2748. REVEAL goes right after DONE.

REVEAL: reuse `MSG_LSTOCK_REVEAL` — its wire API (`wire_build_lstock_reveal(node_idx[],
revoked_state[], secrets[][32], n)`) ALREADY takes arrays, so ONE message carries every
affected node's (node_idx, old_counter, secret_old). Send it to all clients (or per
affected client) after DONE; gate on `use_hashlock_poison` + the node's poison co-signed.

Client (src/client.c ~4031): parse PROPOSE_INTENT per-node H_new + mirror via
`factory_set_node_l_stock_hash` BEFORE building each affected node's new state; capture each
H_old before; pass override per node in its poison prep; recv MSG_LSTOCK_REVEAL after DONE,
verify `SHA256(secret)==poison_l_stock_hash` per node (fail-closed), persist each via
`persist_save_l_stock_poison` + `persist_update_l_stock_secret`.

## Phases (each committed; provable at Phase 4 / the e2e)
1. **Phase 1 — H plumbing (per-node).** PROPOSE_INTENT ships per-node H_new; client mirrors
   each; both capture per-node H_old + pass as the poison override. A hashlock Tier-B
   rollover co-signs every new state correctly AND co-signs each poison against the OLD state.
2. **Phase 2 — reveal (array).** After DONE, LSP sends one `MSG_LSTOCK_REVEAL` with all
   affected (node, old_counter, secret); client verifies + persists each row.
3. **Phase 3 — fail-closed guard (per-node).** Before the rollover commits (persist @2721 /
   DONE), if ANY affected node had `poison_required && !poison_prepared[k]` when
   `use_hashlock_poison`, abort the whole rollover (stay on the old epoch). Mirror the
   leaf-advance guard's `poison_required` gating (no false-abort on dust/no-old-state).
   Client mirrors: refuse to ship its Tier-B FINAL if any required poison wasn't co-signed.
4. **Phase 4 — e2e.** Extend a Tier-B harness with `--enable-hashlock-poison`: drive a
   root rollover, assert each affected node persists a reveal row, broadcast a superseded
   intermediate state, assemble its poison from the persisted reveal (superscalar_lstock_recover
   already handles any node_idx), confirm on-chain + redistribution; anti-vacuity per node.
   Plus the degradation-abort (SS_CHEAT_OMIT_POISON) for the rollover.

## Reuse from PR #387 (no rework)
- `factory_assemble_poison_from_template` + `superscalar_lstock_recover` (node-indexed).
- `MSG_LSTOCK_REVEAL` array wire API.
- persist `l_stock_poison_reveals` (keyed by node_idx + state_counter — already per-node).
- The `poison_required` gating discipline + the fail-closed guard shape.

## Prereq / known blockers
- Multi-input nodes: Tier-B already refuses them (lsp_channels.c:2140) — consistent with the
  multi-input keyagg bug (sub-factory). Sub-factory poison is a SEPARATE follow-on.
- #59 reveal crash matrix applies here too (more reveals per ceremony).
