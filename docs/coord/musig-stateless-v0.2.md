# MuSig2 Stateless Signer — Wallet Team Coordination (v0.2)

**Date:** 2026-05-29
**From:** SuperScalar core
**To:** Wallet team
**Scope:** v0.2.0 release readiness

## TL;DR

SuperScalar v0.2 ships with a BIP-327 compliant stateless MuSig2 signer.
The wallet-side implementation needs verification on three points before
the release tag. If your impl already matches, just reply with confirmation;
if not, the diffs below identify what changes.

## Background

Per the 2026-05-22 memo on stateless-signer redesign (citing BIP-327
and Bitcoin Core PR #29675), persisting MuSig2 secnonces across a
network wait is a footgun: a process restart can resurface the same
secnonce against a different sighash and leak the signer's seckey.

SuperScalar v0.2 redesigned its LSP signer to hold secnonces in
memory only, never crossing a persistence boundary. The change
landed across:

  - PR #271 (Phase 1) — wire codec + reordered round 2 + MSG_CEREMONY_ABORT, feature-gated
  - PR #342 (Phase 2) — default-flip to stateless signer + regtest/signet validation
  - PR #344 (Phase 3) — delete legacy `musig_nonce_pool_*` API + drop `nonce_pools` schema
  - PR #274 — nonce-safety unit + fuzz tests

Current state on `main` (`b1cb451..4a934de`): legacy code path is gone.
`SS_MUSIG_LEGACY=1` is now a no-op.

## What we need verified on the wallet side

### 1. No secnonce persistence

The wallet's signer must hold the round-1 secnonce in memory only, from
the moment it generates it until either:
  - the round-2 partial signature is produced and emitted, or
  - the ceremony aborts (see #3).

After either path, zero out the secnonce buffer. **Never** write the
secnonce to disk, journal, log, or any shared memory region.

If your impl currently persists the secnonce (e.g. to allow a restart-
in-the-middle ceremony to resume), that is exactly the design we
removed and the path that the BIP-327 review flagged. Replace it with
a "ceremony fails on restart mid-flight" model.

### 2. Reordered round 2

In the new flow, the signer receives the aggregated public nonces and
emits its partial signature in a **single synchronous turn**, with no
network wait between holding the secnonce and using it. Concretely:

```
recv MSG_AGGREGATED_PUBNONCES
   ↓
load aggregated pubnonces + own secnonce (in memory)
   ↓
compute partial signature
   ↓
zero secnonce buffer
   ↓
send MSG_PARTIAL_SIGNATURE
```

There must be no `send(); recv(); send()` pattern that holds the
secnonce across the middle `recv()`. If your impl issues an explicit
"NONCED" ack and then waits before signing, that's the legacy flow —
collapse it.

Reference: `src/lsp_channels.c::lsp_run_state_advance_stateless` at
the call to `secp256k1_musig_partial_sign`, surrounded by secnonce
load + zero in the same function.

### 3. MSG_CEREMONY_ABORT handling

If the ceremony coordinator (LSP, in SuperScalar) sends
`MSG_CEREMONY_ABORT` (opcode `0x83`), the signer must:

  1. zero any in-flight secnonce buffers,
  2. drop the in-progress ceremony state from memory (no journal,
     since per #1 there should be no journal),
  3. acknowledge with whatever your wire-layer-level ack mechanism is
     (in SuperScalar, the dispatcher consumes it without reply),
  4. NOT retry — a fresh ceremony will be initiated by the coordinator
     if needed.

The abort opcode and its codec live in `src/wire.c` + `include/superscalar/wire.h`.

## Schema migration impact

In SuperScalar's own DB, the v0.2 migration drops the `nonce_pools`
table. If your wallet was reading from a SuperScalar-shared schema,
update your queries; otherwise this is internal.

The new ceremony state table is `ceremony_participants`, but it
tracks ceremony progress (PROPOSE → SENT → NONCED → SIGNED → FINALIZED)
and **does not** store secnonces. It's safe to read.

## Threat model recap

The attack the redesign closes:

  1. Wallet generates secnonce N for ceremony C against sighash S1.
  2. Wallet persists N (the bad design).
  3. Wallet crashes after persist, before sign.
  4. Wallet restarts, loads N, BUT the coordinator has meanwhile
     restarted ceremony C with a different message → different sighash S2.
  5. Wallet signs S2 with the same N that was prepared for S1.
  6. seckey is now extractable from the two partials.

With in-memory-only N: step 3 loses N. The wallet can't resume; it
must restart the ceremony from round 1, generating fresh N. No leak.

## What we'd like back from you

Please reply (PR / email / chat — your preference) with one of:

  - **"Confirmed, our signer matches the three points above."** Include
    a pointer to the relevant code location so we can cite it in the
    v0.2 release notes' Credits section.

  - **"We need changes: <list>."** We can coordinate timing — if changes
    are needed, the v0.2 tag will wait. Current ETA is 3-6 weeks.

  - **"We were already stateless, here's how to verify."** Even better;
    please share the test path.

## Reference

- BIP-327: https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
- Bitcoin Core PR #29675 (the original prompt for this redesign)
- SuperScalar PRs: #271, #274, #342, #344
- SuperScalar tasks: #270-275 (#275 is this coordination item)
- This memo lives at `docs/coord/musig-stateless-v0.2.md` in the
  SuperScalar repo.

No deadline pressure — but if you can ack within the next week, it
unblocks the release-notes Credits section. Thanks.
