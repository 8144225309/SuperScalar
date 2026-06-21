# Hashlock poison — REVEAL-STEP CRASH/ABORT state machine (#59, branch `trustless-hashlock-reveal-crash`)

Stacked on `trustless-hashlock-daemon` (PR #387). Hardens the leaf-advance reveal step that
#387 made live, closing the residual commit-without-reveal window.

## The window (characterized from the live code)
Leaf advance, hashlock on:
- **Client commit point**: ship `MSG_LEAF_ADVANCE_FINAL` (client.c:3917) — hands the LSP the
  new-state signature, so the old state is superseded.
- **Secret durable**: only at client.c:3977 `persist_save_l_stock_poison` (template) + 3983
  `persist_update_l_stock_secret`, AFTER recv DONE (3928) + recv `MSG_LSTOCK_REVEAL` (3968).
- **LSP side**: DONE broadcast (lsp_channels.c:1942) → reveal (1964). The LSP does NOT persist
  the secret (it re-derives from the seed on demand).

Three crash/abort gaps, in order of severity:
1. **Reveal never arrives → NO row persisted** (client.c:3996 `else` just logs). LSP crash
   between DONE (1942) and reveal (1964), or a dropped connection, leaves the client with a
   co-signed poison it has NO persisted record of → on restart it cannot even detect that a
   secret is missing → cannot recover. THE core gap.
2. **Client crash between FINAL (3917) and the persist (3977/3983)**: revoked, no secret.
3. **Template + secret are persisted as two calls** (3977 then 3983); a crash between leaves a
   template-only row (already the desired recoverable state — see Phase 1).

## Severity: degraded-recourse, not outright theft
Without the secret the client still holds the new state's `signed_tx` and can OVERRIDE the
LSP's superseded-state broadcast via the DW/CLTV mechanism — so theft is still PREVENTED; what
is lost in the window is the poison PUNISHMENT (L-stock redistribution). The fix restores the
punishment durably; the override is the interim backstop. (This refines the "residual
Scenario A" framing in the task: it is a no-poison window with theft-prevention intact.)

## Design — persist-template-at-co-sign + restart re-request
The "live pointer advances only on durable recourse" refinement, made recoverable:

1. **Phase 1 — persist the template at co-sign (before the commit).** Right before shipping
   FINAL (after the Phase 5 guard, client.c ~3917), persist the poison TEMPLATE with a NULL
   secret (`persist_save_l_stock_poison`; the row's `revocation_secret` stays NULL until the
   reveal). At reveal, only `persist_update_l_stock_secret`. Now a co-signed-but-unrevealed
   poison ALWAYS leaves a template-only row → restart can DETECT the missing secret. Closes
   gap #1's undetectability. (client.c)
2. **Phase 2 — restart/reconnect re-request.** On client startup (and on LSP reconnect), scan
   `l_stock_poison_reveals` for rows with `revocation_secret IS NULL`; for each, send a new
   `MSG_LSTOCK_REVEAL_REQUEST{node_idx, state_counter}`. LSP handler re-derives
   `factory_derive_l_stock_secret` and replies with `MSG_LSTOCK_REVEAL` (idempotent: the
   client re-verifies SHA256==H_old and `persist_update_l_stock_secret`). Recovers gaps #1/#2.
   (new wire opcode + client startup scan + LSP request handler)
3. **Phase 3 — crash matrix.** Reuse the crash-injection harness (`lsp_crash_checkpoint` /
   `SS_CRASH_AT`, client equivalent). Crash at: after FINAL/before template-persist; after
   template/before reveal; after reveal/before secret-update; LSP after-DONE/before-reveal.
   After each: restart, run the Phase-2 recovery, assert the client ends with a usable secret
   (assemble the poison via `superscalar_lstock_recover` + testmempoolaccept/confirm).
   Anti-vacuity: a crash where recovery is suppressed → no secret → tool refuses.

## STATUS (2026-06-21)
- Phase 1 (template-at-commit): DONE — build + 1507 unit + 4c e2e green (recourse intact).
- Phase 2a (`persist_load_pending_l_stock_poison`): DONE — build + unit (pending scan) green.
- Phase 2b (`MSG_LSTOCK_REVEAL_REQUEST` 0x8D codec): DONE — build + 1508 unit green.
- Phase 2c (dispatch wiring): NEXT — LSP handles 0x8D -> `factory_derive_l_stock_secret`
  -> reply MSG_LSTOCK_REVEAL (find the LSP per-client dispatch loop, ~lsp_channels.c:4990+);
  client on startup/reconnect runs `persist_load_pending_l_stock_poison` -> sends 0x8D ->
  recv reveal -> verify (SHA256==H_old) + `persist_update_l_stock_secret` (reuse the
  client.c:3966 verify path; find the client connect/startup flow). Keystone — wires both
  daemon message loops; do with fresh attention.
- Phase 3 (crash matrix): after 2c.

## Reuse from #387
`MSG_LSTOCK_REVEAL` (request can be a sibling opcode), `persist_save/update/load_l_stock_poison`
(the template-only row is just save-without-update), `superscalar_lstock_recover`,
`factory_derive_l_stock_secret` (LSP re-derives).

## Notes
- The LSP needs no secret persistence — it re-derives from the seed for any (node, state), so
  the re-request handler is cheap + stateless.
- Tier-B (when/if done) has MORE reveals per ceremony; the same Phase-2 scan recovers them
  uniformly (the row is keyed by node_idx + state_counter).
