# L-stock SPK and Poison Transaction (canonical SuperScalar design)

This document covers the L-stock spend conditions and the "poison
transaction" cheating-recovery mechanism implemented per ZmnSCPxj's
SuperScalar design at
[Delving Bitcoin t/1242](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories-with-pseudo-spilman-leaves/1242).

It supersedes the older t/1143 design that destroyed L-stock value via
`OP_RETURN` on cheat detection.

## L-stock SPK

```
internal key  = MuSig(LSP, client_1, ..., client_K)         "A & B & L"
script-leaf   = <csv_blocks> CSV DROP <LSP_xonly> CHECKSIG  "L & CSV"
```

In zmn's t/1242 ASCII (for an arity-2 leaf with 2 clients, A and B):

```
+-----+---------+
|     |  A&B&L  | pseudo-Spilman factory
| 432 |or(L&CSV)|
|     |         |
+-----+---------+
```

Two paths to spend the L-stock UTXO:

1. **Cooperative N-of-N MuSig** (key-path) — used by both:
   - The legitimate cooperative close path: all leaf signers
     (LSP + clients) co-sign together to spend L-stock.
   - The pre-signed **poison transaction** that activates if the LSP
     publishes an old (revoked) leaf state.

2. **L-alone after a CSV delay** (script-path) — the LSP's unilateral
   fallback.  Gated by a relative-locktime delay (`L_STOCK_CSV_DEFAULT_BLOCKS`,
   default 144 blocks ≈ 1 day on mainnet) to give clients / watchtowers
   time to broadcast the matching pre-signed poison TX before the LSP can
   drain L-stock alone.  Configurable per factory via
   `factory_set_l_stock_csv()`.

Implementation: `src/factory.c::build_l_stock_spk()`.

## Poison TX

When an LSP publishes a stale leaf state, anyone (any client or
watchtower) can broadcast the matching **pre-signed poison transaction**
to redirect the L-stock value to the leaf's clients.

Per zmn's t/1242 example:

> Channel with `A`: 10 units → entirely goes to `A`.
> Channel with `B`: 10 units → entirely goes to `B`.
> LSP liquidity stock: 20 → split: 10 to `A`, 10 to `B`.

The channel outputs are recovered via the standard Poon-Dryja revocation
penalty (already implemented in `src/channel.c`).  The L-stock recovery
is the new poison TX:

- **Input** (1): the L-stock UTXO from the stale leaf state TX
- **Outputs** (1 per non-LSP signer): equal share of
  `(L-stock amount - fee)`, paid to a key-path-only `P2TR(client_xonly)`
  for each client.  Any client can sweep their output unilaterally with
  their own seckey.
- **Witness**: 64-byte Schnorr signature from the leaf's N-of-N MuSig
  key-path (A&B&L), pre-signed at leaf-state-advance time.

Implementation:
- `factory_build_l_stock_poison_tx_unsigned()` builds the unsigned TX
  + computes the BIP-341 keypath sighash.
- `factory_sign_l_stock_poison_tx()` (single-process) co-signs with all
  leaf participants via `musig_sign_taproot` and returns the witnessed TX.
- The wire-ceremony equivalent (where each client signs remotely via
  split-round MuSig2) is a follow-up PR — for now the single-process
  flow is what `factory_build_burn_tx` (the watchtower call site) uses.

## Why this is correct vs zmn's design

| Aspect | zmn's t/1242 | This implementation |
|---|---|---|
| L-stock internal key | `A & B & L` (N-of-N MuSig) | `node->keyagg.agg_pubkey` over leaf signers ✅ |
| L-stock script-leaf | `or(L & CSV)` — LSP after CSV | `<csv> CSV DROP <LSP> CHECKSIG` ✅ |
| Poison TX trigger | OLD leaf state TX confirmed on chain | OLD leaf state's L-stock UTXO becomes spendable ✅ |
| Poison TX outputs | 1 per non-LSP client | 1 per non-LSP signer ✅ |
| Per-client amount | Equal split (zmn's example: 10 to A, 10 to B) | `(amount - fee) / n_clients`, with rounding remainder to LAST recipient ✅ |
| Per-client SPK | Each client controls their output | `P2TR(client_xonly)` — client's own pubkey, key-path-only ✅ |
| Pre-signing | Implied (the poison TX must be ready before old state is broadcast) | Co-signed at leaf-state-advance time via N-of-N MuSig over leaf signers ✅ |
| CSV value | Unspecified — operator choice | Default 144 blocks; configurable via `factory_set_l_stock_csv()` |

The CSV value is the only operator-tunable parameter; everything else is
spec-aligned.  144 blocks ≈ 1 day is a reasonable default — long enough
for watchtowers to react under network congestion, short enough that an
honest LSP isn't blocked indefinitely.

## Security argument: the LSP is economically punished if it cheats

Cheating = LSP publishes a STALE (already-revoked) leaf state, hoping to
roll back a state where it had more capital allocated to L-stock or to
its own channel side.

**What happens if LSP publishes stale state:**

1. The stale leaf state TX's L-stock UTXO appears on chain.
2. The matching pre-signed poison TX (already in clients'/watchtowers'
   hands from when that state was advanced past) is now valid.
3. Anyone can broadcast the poison TX.  Per t/1242: *"any client can
   trivially CPFP the 'poisoning' transaction"* — clients have unilateral
   control of their share, so they have direct economic incentive to
   CPFP if needed.
4. L-stock value is redirected to clients (equal split).  The LSP gets
   **nothing** from L-stock.
5. The leaf's channel outputs (A&L, B&L) are also recoverable to
   clients via the Poon-Dryja revocation penalty (separate mechanism).
6. Net: cheater LSP loses (a) all L-stock capital + (b) all channel
   capital that was its share at the time of the stale state.

The LSP would only cheat if the gain from publishing an old state
exceeded both losses.  Since the stale state by definition had LESS
favorable balance for the LSP than the new state (otherwise why
advance?), and the poison TX strips the entire L-stock + all channel
sides go to clients via PD penalty, the LSP is strictly worse off
publishing stale state.

## Anti-griefing analysis (the load-bearing question for production)

### Q1: Can a client preemptively drain L-stock by signing a poison TX alone?

**No.**  The poison TX's authority is the leaf's **N-of-N MuSig**, which
requires every leaf signer (LSP + every client in the leaf) to
participate in signing.  A single client cannot produce a valid
signature alone; nor can clients collude *without* the LSP — the LSP's
share of the MuSig is required.

### Q2: Can a malicious client trigger the poison TX by broadcasting a stale leaf state themselves?

**Mostly no, by economic design.**  Two layers:

(a) **Decker-Wattenhofer state ordering.**  Per the DW design, newer
states have *lower* `nSequence` (relative locktime) than older ones, so
when the kickoff TX confirms, the LSP can race to broadcast the latest
state — which confirms first under BIP-68 — and supersede the stale
state the client tried to publish.

(b) **Static-near-root.** For root-level cheating attempts, the
"static-near-root" variant we ship (PR #105, Phase 3 of the mixed-arity
plan) means the root state TX has no `nSequence` ordering at all — the
root output is unconditionally spendable by the next-layer's kickoff.
Stale-root broadcasting doesn't create a window the client can exploit.

(c) **Even if the client's stale-state broadcast succeeded** (e.g., the
LSP is offline and can't race), the client's *own* channel side gets
revoked under Poon-Dryja, so the L-stock share they recover via the
poison TX is offset by the PD penalty paid to their counterparty.  Net
client gain is bounded — typically negative if the client had ANY
channel balance at the time of the stale state.

(d) The client also has a strong **honest exit path**: cooperative
close at any time gives them their channel balance + their share of any
L-stock improvement that's been negotiated.  Cheating to grief is
costlier than just leaving cooperatively.

### Q3: Can the LSP grief by refusing to co-sign legitimate state advances?

The LSP has **no incentive to refuse** because:
- L-stock is part of LSP's capital.  Refusing to advance state freezes
  the LSP's own L-stock too.
- Clients can **cooperatively close** at any time (current state's
  funding output is N-of-N spendable cooperatively).  An LSP that
  refuses service simply gets force-exited.
- The CSV gate on the L-stock script-path means LSP-alone unilateral
  exit is not immediate — the LSP must wait `csv_blocks`, during which
  clients can broadcast the poison TX of any *previously-revoked* state
  (if the LSP attempts to publish one).  If the LSP attempts to drain
  L-stock via the script-path with the LATEST state, that's a
  legitimate exit and clients have no grievance.

### Q4: Can the LSP unilaterally drain L-stock without waiting CSV?

**Only by getting all clients to co-sign**, which is the cooperative
N-of-N path.  Without client cooperation, the LSP must use the
script-path, which is gated by `csv_blocks`.  During that delay, clients
have time to either:
- Co-sign cooperatively if it's a legitimate close, or
- Broadcast a previous state's poison TX if the LSP cheated in the past
  and never got punished.

This is why the CSV value matters: too short and clients can't react;
too long and honest LSP exits are slow.  The default 144 blocks
(~1 day on mainnet) is a reasonable balance — operators can override
per deployment via `factory_set_l_stock_csv()`.

### Q5: Can a watchtower be tricked into broadcasting the poison TX during a legitimate close?

**No.**  A legitimate cooperative close spends the *funding output*
(the factory root), which never publishes any leaf state TX on chain.
The poison TX requires the leaf state TX's L-stock UTXO to exist — that
only happens if the leaf state TX was force-broadcast.  A force-close
of the LATEST state is also fine: that L-stock UTXO has its own poison
TX, but the broadcast is by the LSP itself (legitimate force-close),
and the LSP doesn't broadcast its own poison TX.

The watchtower only needs to broadcast a poison TX when it sees a
*stale* leaf state TX confirmed on chain — distinguishable from the
LATEST state because the LATEST state is what the watchtower itself was
told about most recently.

## Migration

This change affects only **future** factories:

- Existing on-chain factories were built with the OLD t/1143 SPK
  structure (LSP-alone-key-path + hashlock-script-path).  Their
  cheating-recovery still uses the OLD `OP_RETURN` burn TX, which is
  pre-built and stored by the watchtower at advance time.  These
  continue to work.  Factories built after this PR use the new SPK +
  poison TX, registered with the watchtower the same way.

- The shachain hashlock secrets are still used for **channel-level**
  revocation (Poon-Dryja) inside the leaves — that mechanism is
  unchanged.  Only the L-stock SPK and the burn-vs-poison TX semantics
  changed.

## ⚠️ SECURITY-CRITICAL: multi-process production gap

**Status (2026-05-02):** wire-ceremony poison TX is now implemented for
**3 of 4** ceremony paths.  Multi-process LSPs running these flows
produce a fully-signed L-stock / sales-stock poison TX via a second
MuSig2 round bundled with each state advance.

| Ceremony path | Status | PR |
|---|---|---|
| `lsp_subfactory_chain_advance` (k² PS chain extension) | ✅ wire-ceremony | #136 |
| `lsp_advance_leaf` (DW per-leaf state advance) | ✅ wire-ceremony | #137 |
| `lsp_realloc_leaf` (per-leaf fund reallocation) | ✅ wire-ceremony | #138 |
| `lsp_run_state_advance` (Tier B root rollover) | ⏳ single-process fallback only | TODO |

**Remaining gap — Tier B root rollover** (`lsp_run_state_advance`):
- Triggered when a leaf's per-leaf DW counter exhausts and the root layer advances
- Re-signs N nodes simultaneously using `MSG_PATH_*` bundle messages and nonce pools
- Watchtower hook at `src/lsp_channels.c:2195+` still uses
  `factory_build_burn_tx` (single-process) for each affected leaf
- In multi-process mode the `lsp_have_all_signer_keypairs` guard skips
  the build, registering the watchtower with `NULL` poison_tx for that
  rotation — operators see a SECURITY GAP stderr warning per leaf

**Frequency**: Tier B rotation fires roughly once per N leaf advances (the
per-leaf DW counter exhausts after `states_per_layer` advances).  Per-leaf
advances now have full poison TX defense, but the rare rotation event
falls back to NULL until Tier B gets the same wire-ceremony treatment.

**The 3 closed paths cover the common case** — every payment-driven state
advance, every k² sub-factory chain extension, and every per-leaf realloc
already produces a real signed poison TX in multi-process mode.  Mainnet
deployments that anticipate root rollovers should still wait for Tier B.

**Single-process / signet self-tests / `--demo` deployments are
unaffected on all 4 paths** (the in-process key availability path is
exercised end-to-end by unit tests).

## What's deferred to a follow-up PR

This PR ships the **single-process** poison TX flow only.  The
wire-ceremony equivalent must coordinate a split-round MuSig2 round
across all leaf signers (LSP + clients in separate processes) to
gather partial sigs from each client over the poison TX sighash, then
aggregate.  This is the same shape as the existing state-advance
ceremony — a second round on a different sighash.  Estimated 2-3 days
of plumbing (no crypto redesign).

The single-process flow shipped here is sufficient for:
- Unit testing of the new SPK + TX shape
- Watchtower integration in single-LSP deployments where the LSP holds
  all keys (test fixtures, signet self-tests)
- The `factory_build_burn_tx` shim that the watchtower call site uses

**Tracked in `.claude/CANONICAL_DESIGN_GAPS.md` Gap A (status:
SECURITY-CRITICAL, BLOCKS PRODUCTION).**
