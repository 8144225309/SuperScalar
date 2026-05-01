# Tier B: Multi-party state-advance ceremony

## Background

A SuperScalar factory's tree of unsigned transactions includes nSequence
(BIP-68 relative locktime) values that decrement at every state advance,
per the Decker-Wattenhofer construction.  When any tree node's nSequence
changes, that node's TX must be re-signed by its participants
(N-of-N MuSig over the leaf signers, or the full participant set for
interior nodes).

In the worst case (root layer rolls over), every node in the tree needs
re-signing — that's the "state-advance ceremony" this document specs.

## Two existing primitives this builds on

- **Tier A (`factory_advance` in `src/factory.c`)** — single-process
  state advance.  Calls `dw_counter_advance` + `update_l_stock_outputs`
  + `build_all_unsigned_txs` + `factory_sign_all`.  Works because the
  test process holds every leaf signer's keypair.  Ships in PR #112,
  exercised by `test_regtest_nway_n64_dw_advance_resign_lifecycle` at
  the canonical N=64 mixed-arity shape.

- **Per-leaf realloc ceremony (`lsp_realloc_leaf` in
  `src/lsp_channels.c`)** — multi-party ceremony for a SINGLE leaf node
  re-sign (a `factory_set_leaf_amounts` change with the DW counter
  advancing at the leaf layer).  Uses `MSG_LEAF_REALLOC_*` wire
  messages.  Currently arity-2-only (gated behind `f->leaf_arity ==
  FACTORY_ARITY_2` check).

This Tier B ceremony is the **whole-tree** equivalent of the per-leaf
realloc — handles the case where the leaf's DW counter rolls over and
the root layer (and everything below) needs to advance.

## What zmn does and doesn't spec (per t/1242)

Reviewed the t/1242 thread for design constraints:

- ✅ State advance via decrementing nSequence — confirmed mechanism.
- ✅ Lifetime / expiry — confirmed factories have an `active_blocks`
  + `dying_blocks` lifetime; rotation invites clients to migrate to a
  new factory before expiry.
- ❌ The signing ceremony itself (round structure, message types,
  failure modes) — **NOT specified**.  zmn explicitly disclaims
  expertise on the ceremony.
- ❌ Watchtower behavior at rotation — **NOT specified**.

So the ceremony shape is a reference-implementation choice within the
constraints zmn does spec.  This document records the choice and its
rationale.

## Wire ceremony

### Messages (already reserved in `include/superscalar/wire.h`)

- `MSG_STATE_ADVANCE_PROPOSE` (0x55) — LSP → all clients.  Payload:
  `{ "epoch": N+1 }`.  Signals "advance from current epoch to epoch
  N+1; everyone do the prep."
- `MSG_PATH_NONCE_BUNDLE`   (0x60) — Client → LSP.  Payload:
  `{ "entries": [ {"node": i, "slot": s, "nonce": <hex 66B>}, ... ] }`.
  Bundles the client's pubnonce contribution for every node it signs
  (= all nodes containing the client in `signer_indices`).
- `MSG_PATH_ALL_NONCES`     (0x61) — LSP → all clients.  Same shape as
  `_NONCE_BUNDLE` but containing the LSP's nonces + every client's
  nonces, so each client can finalize their session for each node.
- `MSG_PATH_PSIG_BUNDLE`    (0x62) — Client → LSP.  Payload:
  `{ "entries": [ {"node": i, "slot": s, "psig": <hex 32B>}, ... ] }`.
- `MSG_PATH_SIGN_DONE`      (0x63) — LSP → all clients.  Acknowledges
  the new state is fully signed; everyone updates their local DB.

### Round structure (2 round trips)

```
LSP                                 Clients
 │                                     │
 │  STATE_ADVANCE_PROPOSE (epoch N+1)  │
 ├────────────────────────────────────►│
 │                                     │  prep: dw_counter_advance,
 │                                     │        update_l_stock,
 │                                     │        build_unsigned_txs
 │  PATH_NONCE_BUNDLE  (per-node       │
 │◄────────────────────────────────────┤    pubnonces from this client)
 │     [aggregate over all clients]    │
 │  PATH_ALL_NONCES                    │
 ├────────────────────────────────────►│  (clients finalize sessions)
 │  PATH_PSIG_BUNDLE   (per-node       │
 │◄────────────────────────────────────┤    partial sigs from client)
 │     [aggregate, write signed_tx]    │
 │  PATH_SIGN_DONE                     │
 ├────────────────────────────────────►│
```

Two round trips, plus the propose.  Bundled per-node so the wire
overhead is bounded by `O(n_signers per node)`, not `O(n_nodes)`
round trips.

### Per-node signing internals (single-process and wire-ceremony share)

For each node, both single-process and wire ceremony use:

- `factory_session_init_node(f, node_idx)` — initializes the MuSig2
  session for the node's keyagg.
- `factory_session_set_nonce(f, node_idx, signer_slot, &pubnonce)` —
  one call per signer.
- `factory_session_finalize_node(f, node_idx)` — after all nonces are
  in, computes the sighash and aggregates the nonces.
- `factory_session_set_partial_sig(f, node_idx, signer_slot, &psig)` —
  one call per signer.
- `factory_session_complete_node(f, node_idx)` — aggregates partial
  sigs and writes the final signed_tx.

The wire ceremony coordinates the EXCHANGE of nonces and psigs between
parties; the cryptographic operations are identical.

## Failure modes and recovery

| Failure | Effect | Recovery |
|---|---|---|
| Client times out during nonce exchange | LSP aborts ceremony with timeout | On-chain factory unchanged; LSP retries later (state stays at old epoch) |
| Client sends invalid nonce | LSP aborts ceremony | Same as above; LSP can retry without that client (rotation forces them out — see "Liveness" below) |
| LSP fails between PSIG_BUNDLE collect and SIGN_DONE | Clients see no DONE; consider state advance unconfirmed | New state was signed by quorum on LSP side but not distributed.  On reconnect, LSP can re-broadcast SIGN_DONE.  Pre-signed poison TX from OLD epoch remains valid until SIGN_DONE confirms |
| Chain reorg deeper than active state | Old state TX may resurface in mempool | Watchtower handles this via the existing pre-signed poison TX flow (PR #121) — broadcasts poison on detection of stale-state confirmation |
| Partial sig invalid (cryptographic) | LSP aborts | Same as offline client; can retry |

### Liveness ("clients must come online during dying period")

Per zmn (t/1242):
> *"clients need to come online on the specific times that the LSP is
> constructing the new factory. If they miss the exact time, they need
> to try on the next day"*

> *"if they miss the last day of the dying period they MUST exit the
> mechanism, with all the costs implied by the exit"*

So the ceremony is fundamentally synchronous: every client must be
online at advance time.  An offline client during state advance triggers
either (a) ceremony retry, or (b) eventual rotation that forces the
client to unilateral exit.

## Watchtower coordination during state transitions (Gap F)

Pre-signed poison TXs are bound to a specific (state TX txid, L-stock
vout, L-stock amount).  After a state advance:

- The OLD state's pre-signed poison TX remains valid for spending the
  OLD state's L-stock UTXO (which only exists if the LSP cheats by
  broadcasting OLD state).
- A NEW poison TX is signed for the NEW state.
- The watchtower must keep BOTH (and earlier ones too) until each is
  no longer relevant — either confirmed-and-buried-deep enough that no
  reorg risk exists, or until the factory itself is rotated to a new
  outpoint.

### Storage cost

Poison TX is ~250 bytes.  At 16 state advances per epoch × 8 leaves at
N=64 = 128 poison TXs per epoch × ~250B = ~32 KB per factory at the
end of epoch.  Acceptable.

### Overlap window protocol

When a state advance completes:

1. LSP signs and stores the new poison TX for the NEW state.
2. LSP keeps the OLD state's poison TX in the watchtower DB.
3. Watchtower monitors mempool/chain for ANY of the past states' L-stock
   UTXOs being spent.  If detected, broadcast the matching poison TX.
4. After the NEW state is confirmed N blocks deep (say N=144 blocks
   ≈ 1 day), the older states are safe to garbage-collect.

This is the "overlap window" — the period during which old + new poison
TXs are simultaneously stored.

## Implementation status

- ✅ Wire message ID `MSG_STATE_ADVANCE_PROPOSE` defined (Phase 1).
- ✅ Reserved `MSG_PATH_*` IDs (0x60-0x63) documented as Tier B's
  ceremony messages (Phase 1).
- ✅ This design doc (Phase 1).
- ✅ `lsp_run_state_advance()` implementation in `src/lsp_channels.c`
  (Phase 2).  Drives the full bundled ceremony over the wire.
- ✅ `client_handle_state_advance()` in `src/client.c` (Phase 2).
  Bundled-MuSig client side; integrates into the existing dispatch
  loop alongside `client_handle_leaf_advance`.
- ✅ Watchtower per-state poison TX (Gap F overlap window) — after
  ceremony completes, fresh poison TX is built for each leaf's NEW
  state and registered with the watchtower; OLD entries are kept
  (additive insertion ⇒ overlap window).
- ✅ Hook-up: the TODO at `lsp_channels.c::lsp_advance_leaf` rc=-1
  branch now calls `lsp_run_state_advance` instead of skipping.
- ✅ Unit test `test_factory_tier_b_state_advance_root_rollover`
  exercises the per-node split-round MuSig pipeline through a real
  root rollover (states_per_layer × N advances), verifies every
  affected node ends with a fresh signed_tx for the new epoch, and
  proves the factory state machine is healthy enough to advance
  again post-ceremony.
- ✅ Multi-process regtest test driving root rollover end-to-end on
  bitcoind: `tools/test_multiprocess_tier_b_rollover.sh` spawns 1 LSP
  + 4 client daemons (5 distinct OS processes) at `--arity 1
  --states-per-layer 2`, drives 3 leaf-0 advances over the wire (the
  3rd hits rc=-1 inside `lsp_advance_leaf` and triggers
  `lsp_run_state_advance`).  Verifies LSP log contains "running Tier
  B state-advance ceremony" and "state advance complete", and every
  client logs "state advance complete, epoch N (M nodes signed)".
  Then `--force-close` broadcasts the post-rollover tree on regtest
  to confirm the new-epoch signed TXs are valid on-chain.

The cryptographic and state-machine correctness is verified by the
unit test; the wire transport is now also verified end-to-end by the
multi-process test.  Both compose: 14 nodes re-signed for the new
epoch via bundled MuSig over 5 separate OS processes, and the
post-rollover tree confirms on regtest.

## Cross-references

- Tier A (single-process): `src/factory.c::factory_advance` (PR #112)
- Per-leaf realloc ceremony (smaller cousin):
  `src/lsp_channels.c::lsp_realloc_leaf`
- Wire IDs: `include/superscalar/wire.h` (MSG_STATE_ADVANCE_PROPOSE +
  MSG_PATH_*)
- Watchtower foundation: `src/watchtower.c`
- Factory creation ceremony to mirror: `src/lsp.c::lsp_run_factory_creation`
- Open task tracking: `.claude/CANONICAL_DESIGN_GAPS.md` Gap B + F
