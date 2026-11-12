# Pseudo-Spilman (PS) Leaves: Design and Non-Revocability Contract

This is a design note. The audience is future engineers asking "where are
the revocation keys for PS leaves?" — the answer is they don't exist by
design, and that is correct. This doc records why.

## Background

**Pseudo-Spilman (PS, arity 3) is the canonical SuperScalar leaf
mechanism.** All new deployments should default to it. The DW arity-1
and arity-2 leaves remain implemented for backward compatibility but
are not recommended for new factories.

See [docs/factory-arity.md](factory-arity.md) for picking shapes at
deployment time; this doc focuses on the state-invalidation mechanism.

| Arity constant | Leaf shape | State ordering | Status |
|---|---|---|---|
| `FACTORY_ARITY_PS` | LSP + client, 2-of-2 with chained TX advances | Pseudo-Spilman (TX chaining) | **Canonical, default** |
| `FACTORY_ARITY_2` | Two clients + LSP, 3-of-3 | Decker–Wattenhofer (decrementing nSequence) | Legacy |
| `FACTORY_ARITY_1` | Single client + LSP, 2-of-2 | Decker–Wattenhofer (decrementing nSequence) | Legacy |

The PS leaf design is from ZmnSCPxj. References:

- Bitcoin Optech "SuperScalar" deepdive
- Delving Bitcoin "SuperScalar" thread t/1242

## When to use PS vs DW

**Use PS (`--arity 3`) for:**
- All new factory deployments
- Any deployment expecting many state advances per channel (PS adds
  per-advance fee but no CSV consumption; DW exhausts the state machine
  after `states_per_layer × DW_MAX_LAYERS` advances and forces rotation)
- Any deployment where the simpler trust model (no revocation keys, no
  watchtower for leaf state) is preferred

**Use DW arity-1 / arity-2 only for:**
- Migrating existing deployments that pre-date PS support
- Interop with peers that don't yet implement PS

**Both PS and DW leaves support bidirectional inner BOLT-2 channels** —
the "PS is unidirectional" framing in older docs refers only to
leaf-level state advances (which only the LSP triggers), NOT to HTLC
flow. Verified by regtest tests `test_regtest_htlc_force_to_local_arity_ps`
and `test_regtest_htlc_breach_arity_ps`.

**Payments never advance a leaf.** A payment moves balances inside the
inner channels and leaves the factory tree untouched. The channel's
funding outpoint is output 0 of the leaf transaction that existed when the
channel opened; a leaf advance (PS: a new chain transaction spending that
output; DW: a new leaf txid with a lower nSequence) replaces that
transaction and does **not** move the channel onto the new outpoint, so
commitments signed before the advance cannot be broadcast after the
advanced leaf confirms. The same holds for a whole-tree state advance and
for a sub-factory advance. Until advances re-anchor channels, both sides
refuse them:

- The LSP entry points `lsp_channels_advance_ps_leaf` and
  `lsp_factory_tick_root` refuse while an open channel is funded by the
  leaf — whatever its balances — or by any leaf of the factory when the
  advance would roll over into a whole-tree state advance. Their
  `allow_live_channel` argument exists only for the harness flags that
  exercise the ceremonies (`--test-leaf-advance`, `--test-wire-leaf-advance`,
  `--test-ps-advance`, `--test-tier-b-rollover`).
- The client refuses every leaf, state and sub-factory advance proposal
  with an error, before changing its tree or producing a nonce. The
  harness-only client flag `--test-allow-tree-advance` (refused on mainnet)
  lifts this for the ceremony tests.

Verified by `tools/test_regtest_payment_no_leaf_advance.sh` and the unit
tests `test_payment_leaves_leaf_untouched_arity_ps` / `_arity1` and
`test_client_refuses_tree_advances`.

## Why PS is non-revocable

Decker–Wattenhofer leaves order their states using **decrementing
nSequence** values. State N+1 has a smaller `nSequence` than state N, so
under BIP-68 it can confirm sooner if both are broadcast — newer states
always win the broadcast race.

Pseudo-Spilman uses a different mechanism: **TX chaining**. Each new
state is a NEW transaction whose input is the channel-output UTXO of the
PREVIOUS state's TX. Once state N+1 is co-signed, state N's signature
loses meaning: state N's child TX (which would attempt to spend state
N's channel output) and state N+1 (which spends the same output)
double-spend each other on chain, and only one of them can be the
ancestor of the latest valid state.

Therefore PS leaves do NOT need:

- Per-state revocation secrets
- Breach detection
- Penalty transactions
- Watchtower coverage of the leaf state itself

What PS DOES need (and SuperScalar implements):

- A **double-spend defense** against a malicious counterparty trying to
  get the LSP to co-sign a second TX that spends the same parent UTXO
  before the chain has converged. SuperScalar enforces this with the
  `client_ps_signed_inputs` persist table — an LSP/client that has
  already signed off on a TX consuming `(parent_txid, parent_vout)`
  refuses to sign a second one.

This is a deliberate ZmnSCPxj design choice, not a missing feature.

## How it's implemented in this codebase

### TX chaining (src/factory.c)

- `setup_ps_leaf_outputs` (factory.c:699) builds the initial PS leaf
  with `outputs[0]` = channel output (factory consensus key, so chain
  state N+1 signed under `node->keyagg` verifies on-chain) and
  `outputs[1]` = L-stock.
- `rebuild_node_tx` (factory.c:1363) — for any PS leaf with
  `ps_chain_len > 0`, the new TX's input is `(node->ps_prev_txid, 0)`,
  i.e. the prior chain TX's channel output (factory.c:1371-1373).
- `node_nsequence` (factory.c:143) returns `0xFFFFFFFE` for PS leaves
  (factory.c:147) — BIP-68 disabled because chain ordering is enforced
  by the spend graph, not relative timelocks. The header comment at
  factory.c:140 captures this explicitly.
- The same MuSig keyagg (`node->keyagg`) is reused across the chain, so
  every state TX in the chain spends to the same SPK.

### Double-spend defense (src/persist.c, src/client.c)

- Schema v20 introduced the persist table (persist.c:822-832):

  ```sql
  CREATE TABLE client_ps_signed_inputs (
      factory_id INTEGER NOT NULL,
      leaf_node_idx INTEGER NOT NULL,
      parent_txid BLOB NOT NULL,        -- 32 bytes
      parent_vout INTEGER NOT NULL,
      sighash BLOB NOT NULL,            -- 32 bytes BIP-341 sighash
      partial_sig BLOB NOT NULL,        -- our 32-byte partial sig, zero-padded to 36
      created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
      PRIMARY KEY (factory_id, parent_txid, parent_vout)
  );
  ```

  The v20 migration comment in persist.c states the rule: no row = sign
  and record, matching sighash = idempotent retry, conflicting sighash =
  double-spend attempt, refuse; any lookup or insert error = refuse.

- `client_handle_leaf_advance_stateless` (src/client.c) computes the
  BIP-341 sighash of the proposed spend and calls
  `persist_check_ps_signed_input` BEFORE generating any nonce.  A row
  with a different sighash for this `(factory_id, parent_txid,
  parent_vout)` is refused with a log line naming the parent; a row
  with the same sighash is an idempotent retry and is re-signed; a
  lookup error is refused.

- After signing, `persist_save_ps_signed_input` INSERTs the record
  BEFORE the `MSG_LEAF_ADVANCE_FINAL` wire send, and the ceremony aborts
  if that insert does not succeed.  The full rule, including every
  failure and crash point, is the next section.

- PS sub-factory chain advances (`client_handle_subfactory_advance`) use
  the same table, one row per input: a sub-factory chain[N+1] spends
  every output of chain[N], so the client records `(factory_id, chain[N]
  txid, vout)` for each input it signs.  See "Sub-factory chain advances:
  per-input record" at the end of the next section.

### Record-and-refuse: ordering and failure semantics

The record is the whole defense, so the path that writes and reads it
fails closed.  Everything below is `client_handle_leaf_advance_stateless`
in `src/client.c` plus `persist_check_ps_signed_input` /
`persist_save_ps_signed_input` in `src/persist.c`.  The client holds no
open transaction during the ceremony (no `persist_begin` in client.c),
so each statement is its own autocommit transaction.

This path runs only where the client co-signs a leaf advance at all, which
it does not by default (see the refusal above); it is the rule that must hold
before advances are ever enabled for clients, and it is exercised today by the
harness opt-in (`--test-allow-tree-advance`).

**Order.** For a PS leaf with `ps_chain_len > 0` and a persist handle
installed (`client_set_persist`):

1. **sighash** — compute the BIP-341 sighash of the proposed spend of
   `(ps_prev_txid, 0)` from the unsigned tx and the prev output, both
   known right after the local advance.  This is the value the record is
   compared on.
2. **check** — `persist_check_ps_signed_input`, three-way: error / not
   found / found (+ the stored sighash).
3. **nonces** — generate our secnonce, send `CLIENT_PUBNONCE`, receive
   `LSP_RESPONSE`.
4. **bind** — the session's message (`signing_session.msg32`, fixed by
   `factory_session_finalize_node`) must equal the sighash from step 1,
   or the client refuses.  The record always describes what is signed.
5. **partial sig** — `musig_create_partial_sig` (consumes and zeroes the
   state secnonce).
6. **durable INSERT** — `persist_save_ps_signed_input`: a plain `INSERT`
   under the table's PRIMARY KEY, never `INSERT OR REPLACE`.  The
   connection runs `journal_mode=WAL` with `synchronous=FULL`, so when
   the call returns `PS_SAVE_RECORDED` the row has been fsync'd.  Our
   partial sig has not entered the signing session yet.
7. **complete** — put both partial sigs into the session and aggregate
   them into the final signature.
8. **send** — `MSG_LEAF_ADVANCE_FINAL`.  This is the first point at which
   anything derived from our partial signature leaves the process.

Nothing between steps 6 and 8 touches the database, so the record is on
disk before the signature can be observed by anyone else.  Both
secnonces and both of our partial sigs live in one struct owned by a
wrapper around the ceremony, which zeroes it on every exit.  That matters
for the poison secnonce: it is not consumed when the poison degrades
before signing.

**Rule for each outcome.**

| Step | Outcome | Action |
|---|---|---|
| 1 sighash | cannot be computed | refuse, before any nonce exists |
| 2 check | database error (prepare/step failure, malformed row) | refuse — "unknown" is never read as "not found" |
| 2 check | no row | proceed |
| 2 check | row with the same sighash | proceed: idempotent retry, re-sign the same message with a fresh nonce |
| 2 check | row with a different sighash | refuse (double-spend attempt) |
| 4 bind | session message differs from the sighash checked in step 2 | refuse, before signing |
| 6 insert | `PS_SAVE_RECORDED` — inserted, or an identical row was already there | proceed to complete + send |
| 6 insert | `PS_SAVE_CONFLICT` — key conflict and the existing row has a different sighash | abort: our partial sig never entered the session and is zeroed; no complete, no send |
| 6 insert | `PS_SAVE_ERROR` — any other SQLite failure, or an ambiguous conflict re-read | abort, as above |

Two ceremonies on the same parent can both pass step 2 (there is no row
yet when either of them looks).  Step 6 is the arbiter: the PRIMARY KEY
lets exactly one `INSERT` through; the other re-reads the row and lands
on the same-sighash or different-sighash rule above.  The first record
is never overwritten.

**Why re-sign instead of replaying the stored partial sig.** A MuSig2
partial signature is bound to the session's aggregate nonce.  On a retry
the LSP generates a fresh nonce, so the stored partial sig would not
verify against the new session, and it is never replayed.  Signing the
same message twice with two fresh nonces is safe — what MuSig2 forbids is
reusing a secnonce, and `musig_create_partial_sig` zeroes it on use.

The `partial_sig` column is therefore only a record of what was released
the first time: our 32-byte partial sig, zero-padded to 36 bytes, from
the first signing of that parent.  A same-sighash retry does not update
it, and it cannot be verified on its own because the session's nonces are
not stored.

**What an abort leaves behind.** Every refusal and abort above returns
after `factory_advance_leaf_unsigned` has already advanced the client's
in-memory leaf (as every other failure return in this handler always
has).  The client's factory is then one state ahead of anything signed,
so the LSP's retry of the same advance only lines up once the client
reloads its factory from persist, i.e. after a restart.  The
record-and-refuse rules hold across that reload because they are keyed on
the parent outpoint and sighash in the database, not on in-memory state.
This change removes the case where the record itself blocked the identical
retry; it does not make a failed advance resumable in place.

**Crash points and what a restart does.** Client-side
`lsp_crash_checkpoint` names, reachable through `SUPERSCALAR_CRASH_AT`
or `lsp_crash_set_target`:

| Checkpoint | Where | State after the crash | Restart, LSP retries the same tx | Restart, LSP proposes a different spend of the same parent |
|---|---|---|---|---|
| `ps_record_pre_save` | partial sig exists (not yet in the session), before the INSERT | no row, nothing sent | signs and records normally | signs and records normally — nothing was recorded, and the first partial sig never left the process |
| `ps_record_post_save` | INSERT durable, before FINAL | row present, LSP never received FINAL | same sighash → idempotent, succeeds | refused |
| `ps_record_post_final` | after FINAL left | row present, LSP holds the signature | same sighash → idempotent | refused |

#### Sub-factory chain advances: per-input record

A `NODE_PS_SUBFACTORY` chain[N+1] spends all k+1 outputs of chain[N] (the
k channel outputs and the sales-stock), nothing revokes it, and the LSP
chooses `channel_idx` and `delta_sats`.  If the client co-signs
chain[N] → chain[N+1] and later is back at chain[N] (a restart that
reloads an older sub-factory state), the LSP can propose a different
chain[N+1] — another delta, or the same delta into another channel — and,
without a record, get a second valid spend of the same outputs co-signed.
The sales-stock poison does not cover this: it punishes broadcasting a
superseded state, not a sibling of the current one.

The multi-input ceremony behind `client_handle_subfactory_advance`
(`src/client.c`) applies the rules above per input.  The client signs two
of the k+1 inputs — its own channel input (2-of-2 with the LSP) and the
sales-stock input (N-of-N) — and records one row for each, keyed
`(0, chain[N] txid, vout i)`, with that input's BIP-341 sighash
(`compute_taproot_sighash_multi`; `SIGHASH_DEFAULT` commits to every input
and output, so each row names the whole transaction) and the sub-factory's
node index as `leaf_node_idx`.  Order:

1. **input count and sub-factory** — the `PROPOSE_INTENT`'s `n_inputs`
   must equal the number of chain[N] outputs, which is what the chain tx
   spends, and its `subfactory_id` must be the sub-factory that
   `(leaf_side, sub_idx)` names (the node the local advance mutates);
   otherwise refuse before any local change.  There is no single-input
   sub-factory ceremony: no sub-factory chain tx has one input, and the
   ceremony that `n_inputs == 1` used to select signed the node-level
   session, whose message (`compute_node_sighash`'s single-prevout
   preimage) is not the sighash of any input of the tx, and recorded
   nothing.  It was removed.
2. **sighash + check, every signed input**, before any nonce.  An error on
   any input refuses; a row with a different sighash on any input refuses;
   a row with the same sighash is an idempotent retry.
3. **nonces** — `CLIENT_PUBNONCES`, then `LSP_RESPONSE`.
4. **bind, then partial sig, per input** — the input session's `msg32`
   must equal that input's sighash from step 2.  The partial sigs stay in
   a secrets struct that a wrapper zeroes on every exit; they do not enter
   the sessions yet.
5. **INSERT every signed input**, in ascending order, each a plain
   `INSERT` (autocommit, fsync'd on return).  Anything but
   `PS_SAVE_RECORDED` on any input aborts: nothing is sent.
6. **psigs into the sessions**, then **send** `CLIENT_FINAL_PSIGS` — the
   first point at which our partial sigs leave the process.

**Multi-input atomicity.** The INSERTs are separate statements, so an
abort between two of them leaves the earlier rows behind.  That is safe.
Each row names exactly the transaction that was being signed, so the
identical retry passes it and records the rest; any different chain[N+1]
spends that input too (a sub-factory chain tx always spends all of
chain[N]'s outputs) and is refused at step 2, before any nonce.  Every
ceremony inserts the same input set in the same order, so one that loses
an INSERT race to a different spend loses it at its first input and
records nothing.

The sales-stock poison co-signed in the same ceremony also spends
chain[N]'s sales-stock, on purpose (it is the penalty for broadcasting the
superseded chain[N]); it is neither checked nor recorded.

| Checkpoint | Where | Restart, LSP retries the same tx | Restart, LSP proposes a different spend of chain[N] |
|---|---|---|---|
| `ps_sub_record_pre_save` | partial sigs exist, before the first INSERT | signs and records | signs and records — nothing was recorded or sent |
| `ps_sub_record_post_save` | every INSERT durable, before `CLIENT_FINAL_PSIGS` | idempotent, succeeds | refused |
| `ps_sub_record_post_final` | after `CLIENT_FINAL_PSIGS` left | idempotent | refused |

As for the leaf, every refusal and abort after step 1 returns after the
local advance (`factory_subfactory_chain_advance_unsigned`), so the client
has to reload its factory before the LSP's retry lines up.  And as for the
leaf, the record lives in the client's persist database: restoring that
database from a backup taken before the record was written loses the
record with it.

**Tests.** `tests/test_ps_refusal.c` drives the real handler in a forked
client over a socketpair against an on-disk DB, with the parent playing
the LSP, and asserts on whether `MSG_LEAF_ADVANCE_FINAL` was sent for: an
injected check error, an injected insert error, a sighash failure, a
conflicting record, an identical record, the concurrent-insert race, and
the three crash checkpoints with restart.
`tests/test_ps_subfactory_refusal.c` does the same for sub-factory chain
advances (N=5, k=2; the client signs inputs 0 and 2 of 3), with the parent
also playing the sub-factory's other client and verifying every input's
aggregated signature, and asserts on whether `CLIENT_FINAL_PSIGS` was
sent for: conflicting re-proposals (other delta, other channel), the
identical retry after a crash, injected check / insert / sighash failures,
the INSERT race, a failed second-input INSERT, the three crash checkpoints
with restart, an `n_inputs` or `subfactory_id` that does not match (refused
before any local change), a second advance (chain[1] → chain[2]), and a
hashlock sub-factory with the poison active (an honest advance, whose poison
verifies, and an insert error, which sends no poison partial sig).
`tests/test_persist.c::test_persist_ps_signed_input_arbiter` covers the
persist layer.  The fault hook is `persist_test_set_ps_hook`
(test-only; a NULL check in production).

### Watchtower

- `src/watchtower.c` watches inner BOLT-2/3 channels for breach using
  per-commitment revocation keys and penalty TX construction.
- It contains no `ps_leaf` references — there is no "old state" to
  detect for a PS leaf because old states are unspendable once the
  chain advances.

## Comparison to BOLT-2 channels

| Property | BOLT-2 LN channel | DW leaf (arity 1, 2) | PS leaf |
|---|---|---|---|
| Revocation keys | yes (per-commit) | no | no |
| Penalty TX | yes | no | no |
| Watchtower needed | yes | no (uses CSV) | no (uses chain) |
| State invalidation | revocation + breach detect | decrementing nSequence | TX chaining + double-spend defense |
| Off-chain renegotiation | new commit TX | new state TX (lower nSequence) | new state TX (spends prior chan output) |

## What SuperScalar still uses revocation FOR

Inner Lightning channels riding on top of the leaves are standard
BOLT-2/3 channels. They retain:

- Per-commitment revocation keys (`src/channel.c`)
- HTLC commitment TX with revocation paths (`src/htlc_commit.c`)
- Watchtower coverage (`src/watchtower.c`)

This is correct and orthogonal: the leaf is a non-revocable container,
and the channel inside is a normal LN channel.

## Tested invariants

Cross-references for the test cases that pin this contract:

- `tests/test_factory.c::test_factory_ps_leaf_build_n64`
  (test_factory.c:5008) — PS leaf chain scales to N=64 (250 nodes, 63
  leaves), exercising the same-key, chained-spend topology at width.
- `tests/test_channels.c::test_client_ps_double_spend_defense_refuses`
  — defense blocks a second-sign attempt against the same
  `(parent_txid, parent_vout)` with a different sighash.
- `tests/test_ps_refusal.c` — failure semantics of the record-and-refuse
  path: check error, insert error, sighash failure, conflicting and
  identical records, the concurrent-insert race, crash + restart.
- `tests/test_ps_subfactory_refusal.c` — the same for sub-factory chain
  advances, per input: conflicting re-proposals, the identical retry,
  injected failures, a partial record, crash + restart, an input count or
  sub-factory that does not match, a second advance, and a hashlock
  sub-factory with the poison active.
- `tests/test_close_spendability_full.c::test_regtest_ps_chain_close_spendability`
  (test_close_spendability_full.c:1197) — final state of a PS chain is
  spendable on regtest, end to end.
- `tests/test_persist.c` — schema v20 round-trip for the
  `client_ps_signed_inputs` table.

If you change PS leaf construction, the double-spend check, or the
persist schema, run all of them. They are the contract test suite for
this doc.

## See also

- [`docs/jit-and-rollback.md`](jit-and-rollback.md) — what happens when
  a JIT operation (buy-liquidity, realloc, bridge HTLC) fails partway
  through.  Per zmn's t/1242, SuperScalar uses **cut-through** as the
  reconciliation mechanism, not a per-realloc rollback hashlock.
