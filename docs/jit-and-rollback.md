# JIT operations and rollback semantics

This document defines what happens during and after a JIT-style operation
inside a SuperScalar factory — **buy-liquidity**, **invoice register**,
**leaf reallocation**, **bridge HTLC forward** — and how failure mid-flight
is reconciled.

The short version: SuperScalar's design (per ZmnSCPxj's
[Delving Bitcoin t/1242](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories-with-pseudo-spilman-leaves/1242))
relies on **cut-through** to reconcile JIT-allocation state, not on a
separate rollback protocol with its own escape hatches.

## What zmn's design says

> "when client `A` wants to buy inbound liquidity, and `B` is online and
> the sub-factory with `A` and `B` has available funds, the LSP can use
> the pseudo-Spilman factory to create a new channel"
> — t/1242

> "Later, if the leaf node needs to be updated anyway (for example, if
> C and D buy enough inbound liquidity from the LSP that they need to
> get liquidity from the A, B, and L channel factory) the LSP can
> cut-through the state of the pseudo-Spilman factory"
> — t/1242

The thread does **not** specify a separate rollback / undo mechanism for
JIT operations.  Failure is handled implicitly by the next state update.

## The rollback contract this implementation provides

### Failure mid-`lsp_realloc_leaf` (the realloc-with-resign primitive)

`lsp_realloc_leaf` (`src/lsp_channels.c`) advances the DW counter in
**Step 1**, then runs a 3-of-3 split-round MuSig2 ceremony in Steps 2-7
to co-sign the new leaf-state TX.  If any step after Step 1 fails:

| State component | Effect of failure |
|---|---|
| **On-chain factory** | unchanged — the previously-signed leaf state is the latest valid one |
| **DW counter** (in-memory) | one slot consumed (the failed-to-finalize state); subsequent advances skip it |
| **Channel `local_amount` / `remote_amount`** | unchanged — `lsp_channels_buy_liquidity` updates these only AFTER `lsp_realloc_leaf` returns success (`lsp_channels.c` near line 2000) |
| **Persisted invoices / HTLC origins** | unchanged — invoice registration is purely in-memory + persist; never advances counter |

The DW counter slot loss is the only "cost" of a mid-realloc failure.
It does not impair the factory's operability — subsequent realloc
attempts simply use the next slot.  The factory continues to function
exactly as if the failed realloc had never been attempted.

### Failure mid-bridge-HTLC-forward

When the bridge daemon's HTLC times out or the destination client
declines mid-flight, the LSP rolls back per the BOLT-2 channel HTLC
state machine (no factory state mutation occurs — only per-channel
HTLC accounting changes).  This is a per-channel concern, not a
factory-level one.

### Failure during cooperative close

`lsp_run_cooperative_close` either signs the close TX successfully or
returns failure without spending the funding output.  No partial state
is committed: success ⇒ close TX broadcast; failure ⇒ factory continues
operating from current state.

## Why this matches "cut-through" rather than needing an escape hatch

Cut-through means: when the next legitimate state update happens
(another realloc, a coop close, a rotation), it consolidates over any
failed-mid-flight attempts.  Three properties make this safe in
SuperScalar:

1. **No on-chain commitment is published mid-flight.** The realloc
   ceremony co-signs an unsigned TX in memory; the on-chain factory is
   not mutated until the ceremony completes.  Failure leaves the
   on-chain state unmoved.
2. **DW counter slot loss is bounded.** A leaf has many state slots
   (default `states_per_layer` = 4 per DW layer); losing one to a
   failed realloc does not strand the leaf.  Repeated failures eventually
   exhaust the layer, at which point root-layer rotation refreshes the
   shape (the same mechanism used for normal scheduled rotations).
3. **Channel-internal HTLC accounting is per-BOLT-2 and reversible
   without factory involvement.**  HTLCs that fail mid-flight unwind
   via the BOLT-2 commitment state machine on each channel, independent
   of factory tree state.

## What we deliberately do NOT have

A novel "realloc rollback hashlock" on the L-stock SPK (e.g., a
secret-keyed taproot leaf that lets a single party unilaterally claw
back the L-stock if a JIT allocation fails) — **this is not in zmn's
spec and is not needed.**  Adding such a path would:

- introduce a new spend authority on L-stock beyond the
  `or(N-of-N, L&CSV)` zmn specifies (see Gap G in
  `.claude/CANONICAL_DESIGN_GAPS.md`),
- complicate watchtower coordination (an extra hashlock to track per
  realloc),
- not solve any failure mode that cut-through doesn't already handle.

The CLN plugin (or any higher-layer JIT orchestrator) should treat
failed JIT requests as "retry from a fresh state" rather than expecting
a factory-level undo.

## Cross-references

- Realloc primitive: `src/lsp_channels.c::lsp_realloc_leaf`
- Buy-liquidity wrapper: `src/lsp_channels.c::lsp_channels_buy_liquidity`
- Invoice register: `src/lsp_bridge.c::lsp_channels_register_invoice`
- DW counter: `include/superscalar/dw_state.h`
- Cut-through quote: t/1242 (Delving Bitcoin)
