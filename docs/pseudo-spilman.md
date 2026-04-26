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
      partial_sig BLOB NOT NULL,        -- 36 bytes (32 wire + pad)
      created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
      PRIMARY KEY (factory_id, parent_txid, parent_vout)
  );
  ```

  The header comment at persist.c:815-819 documents the three-state
  consultation: no row = sign fresh, matching sighash = idempotent
  retry, conflicting sighash = double-spend attempt, refuse.

- `client_handle_leaf_advance` (client.c:2620-2638) calls
  `persist_check_ps_signed_input` BEFORE generating any nonce. If a row
  already exists for this `(factory_id, parent_txid, parent_vout)`, it
  refuses with an explicit log line naming the conflicting prev txid.
  The header comment at client.c:2615-2618 explains why we do not
  attempt replay-based idempotency: that risks MuSig nonce-reuse
  footguns, so refusal is the conservative choice.

- After signing succeeds, `persist_save_ps_signed_input`
  (client.c:2715-2734) records the partial sig BEFORE the
  `LEAF_ADVANCE_PSIG` wire send. A crash between record and send is
  safe — the retry will see the row and refuse to sign anew, leaving
  the counterparty to either complete from the recorded sig or abort
  the leaf.

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
  (test_channels.c:4048) — defense blocks a second-sign attempt against
  the same `(parent_txid, parent_vout)`.
- `tests/test_close_spendability_full.c::test_regtest_ps_chain_close_spendability`
  (test_close_spendability_full.c:1197) — final state of a PS chain is
  spendable on regtest, end to end.
- `tests/test_persist.c` — schema v20 round-trip for the
  `client_ps_signed_inputs` table.

If you change PS leaf construction, the double-spend check, or the
persist schema, run all four. They are the contract test suite for this
doc.
