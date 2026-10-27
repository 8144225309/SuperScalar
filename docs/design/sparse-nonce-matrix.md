# Sparse nonce matrix for `MSG_FACTORY_LSP_RESPONSE` (0x87)

Status: designed, not yet implemented. Tracked as internal task #131.

## Problem

The factory-creation ceremony forwards every signer's per-node pubnonce to
every client so each can build the aggnonce for the multi-signer nodes it
signs. Today that ships as a **dense** matrix: `n_nodes x n_participants`
cells of 66 bytes, hex-encoded into one flat string under
`all_signer_pubnonces` (`src/lsp.c:659-666`, `src/wire.c:1783`).

Almost all of it is zeros. A node's signer set is its subtree's clients plus
the LSP (`src/factory.c:1676-1680`), so a node at depth d has far fewer than
`n_participants` signers. Only slots `[0, n_signers)` of each row are ever
written; the rest are `calloc` zeros that are serialized, hex-encoded,
AEAD-encrypted, transmitted, parsed and decoded — and never read.

Measured density on the default PS shape (`--arity 3`):

| clients | n_nodes | dense cells | used cells | density |
|---|---|---|---|---|
| 128 | 510 | 65,790 | 2,558 | 3.89% |
| 300 | 1,198 | 360,598 | 6,774 | **1.88%** |
| 512 | 2,046 | 1,049,598 | 12,286 | 1.17% |

**98% of what we transmit at N=300 is padding.**

### This is a correctness wall, not just a slow path

The dense message breaches `WIRE_MAX_FRAME_SIZE` (16 MB,
`include/superscalar/wire.h:229`):

- default PS shape: over the cap at **N ~ 178**
- our harness shape (`ARITY=2,4,8`, `--static-near-root 2`): 5.84 MB/client at
  N=300 and 9.95 MB at N=512 — fits — but at N=1024 the tree gains a level
  (64 leaves x capacity 8 = 512 clients max), `n_nodes` jumps 147 -> 1171 and
  the message becomes **~158 MB**.

So **N=1024 is unreachable without this change.** N=512 is reachable without
it.

Until this lands, `wire_send` and `wire_send_many` refuse oversize frames with
a clear error naming the message type and size, instead of writing a frame the
peer rejects as malformed (commit `d51ce6a`).

## What a client actually needs — verified

A client reads a nonce cell at exactly one site, `src/client.c:1815`, and the
loop around it is bounded twice over:

- `src/client.c:1794` — `if (my_slot[nidx] < 0) continue;` skips every node the
  client does not sign
- `src/client.c:1811` — `size_t ns = factory->nodes[nidx].n_signers;` bounds the
  slot loop by the node's own signer count, not `n_participants`

MuSig agrees: `musig_session_set_pubnonce` rejects `slot >= n_signers`
(`src/musig.c:312`) and `musig_session_finalize_nonces` requires exactly
`n_signers` collected (`src/musig.c:330`).

Nothing else needs the matrix. Tree verification is nonce-free — the client
rebuilds the tree and Schnorr-verifies each `signed_tx` against
`node->tweaked_pubkey` (`src/factory.c:2345-2367`). The LSP's per-node partial
sigs are explicitly discarded client-side (`(void)lsp_psig_per_node;`,
`src/client.c:1787`), and `musig_verify_partial_sig` is never called on the
factory path at all (only `src/channel.c:1664`).

## Two candidate layouts

**A. Per-client path slice.** Send each client only the rows for nodes on its
own root->leaf path. Smallest possible payload (~117 kB/client at N=300), but
the plaintext differs per client, so it gives up `wire_send_many`'s
serialize-once optimization (`src/wire.c:409-424`) and needs N cJSON builds
and N prints.

**B. Global sparse blob.** Send all nodes but only `n_signers` slots each,
same bytes to everyone. Larger per client (~1.08 MiB at N=300) but identical
for all peers, so `wire_send_many` still prints once and only the AEAD is
per-peer.

### Decision: B

Measured LSP-side cost at N=300 (crypto-profiling agent, Release build):

| | build | print | AEAD x300 | LSP total |
|---|---|---|---|---|
| dense (today) | 137.4 ms | 96.7 ms | 16.7 s | **27.4 s** |
| B, global sparse | 1.10 ms | 2.00 ms | ~180 ms | **~0.18 s** |
| A, per-client path | ~N x 0.3 ms | — | ~21 ms | ~0.11 s |

A is ~70 ms better than B out of a 27.4 s starting point. That is not worth
the extra machinery: B keeps the broadcast path intact, mirrors a pattern
already proven in this repo, and is a far smaller diff.

B also clears the frame cap with room to spare — the blob is `sum(n_signers)`
cells, which grows about `N x depth`, not `N^2`. At N=512 that is ~12.3k cells
= 1.62 MiB hex against a 16 MB cap.

## Format

Precedent: the Tier-B state-advance ceremony **already does exactly this** —
variable stride, prefix offsets recomputed independently on both sides
(`src/lsp_channels.c:2546-2561` builds it, `src/client.c:4823-4828` reads it),
with a strict total-length assert at `src/client.c:4852`. Factory creation is
the outlier still using a fixed stride.

Layout: iterate `nidx = 0 .. n_nodes-1` ascending; append each node's
`n_signers x 66` bytes, slots ascending. Both sides derive:

```
offset[j] = sum over i<j of n_signers(i)      /* one O(n_nodes) pass */
cell(node j, slot s) = blob + (offset[j] + s) * 66
```

Field name changes to `sparse_signer_pubnonces` so the layout is explicit
rather than inferred from a length, with the dense `all_signer_pubnonces` still
parsed on receive during the transition.

### Do NOT sparsify

- **`all_dist_pubnonces`** — a separate field (`src/lsp.c:839-840`), not part of
  the matrix. The distribution TX is one root-level N-of-N session and the
  client consumes every slot (`src/client.c:1766`). Irreducibly `66*(N+1)`.
- **`dist_client_amounts`** — the client rebuilds the identical dist TX from
  every client's amount (`src/client.c:1755`).

## Compatibility

Old client + new LSP: `have_matrix` length-inference fails
(`src/client.c:1789`), co-signer nonces never get set, and the ceremony dies
loudly at `factory_session_finalize_node` (`nonces_collected != n_signers`).
Not silent corruption, but a hard break — so the new client must accept both
layouts, keyed on which field is present.

No persistence impact: creation persists only the ceremony row and participant
phases (`src/lsp.c:411`, `:588`, `:1025`). No nonce matrix is stored, so no
schema migration.

A capability hook already exists if staged rollout is wanted — `HELLO` carries
feature booleans (`src/wire.c:676`) parsed at `src/lsp.c:250-253`.

## Risk

Packed offsets make both sides depend on agreeing about every node's
`n_signers`, where the dense layout only depended on `n_participants`. A tree
mismatch therefore yields garbage nonces rather than a later mismatch. The
failure is still safe — bad partial sigs are caught by the LSP's ceremony-time
`factory_verify_all`, which triggers the bounded `SS_NONCE_RETRY_MAX` retry and
then aborts, broadcasting nothing — but it would present as flakiness. Mitigate
with the exact total-length assert, as Tier B does.

## Call sites

- LSP `src/lsp.c` (all in `lsp_run_factory_creation_stateless`): `:659` stride,
  `:666`/`:668` alloc + dist row, `:705`/`:761` dist writes, `:725`/`:780`
  nonce writes, `:829-831` response build, `:860-884` broadcast
- Codec `src/wire.c:1762-1824`, `include/superscalar/wire.h:659-670`
- Client `src/client.c`: `:1675-1687` alloc/parse, `:1789` `have_matrix`,
  `:1810-1826` the read

Rotation shares this message (`lsp_rotation.c:988` -> `lsp.c:1053` ->
`lsp_run_factory_creation_stateless`), so it must be re-tested too.

There is **no codec unit test** for `wire_build/parse_factory_lsp_response`
today. Add one covering both layouts and the length assert.

## Not fixed by this

Every client calls `factory_build_tree()` (`src/client.c:1112`, `:2338`) and so
derives every node's aggregate key — ~380 ms at N=300, about 75% of it in
`musig_aggregate_keys`, times N clients. That is inherent to the trust model
(the client must independently derive what it signs), so reducing it means
path-only verification, which is a design change and not this change.
