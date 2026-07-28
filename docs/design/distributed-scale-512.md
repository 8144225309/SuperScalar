# Real distributed payments at N=512 / N=1024

**Status:** design proposal. Nothing here is implemented.
**Goal:** run SuperScalar at 512 and 1024 clients with the *same fidelity we have
at 127* — separate client instances, real sockets, real Noise handshakes, real
wire protocol, real per-payment commitment ceremonies — on the hardware we have,
without buying a bigger box.

## 1. What is and is not proven today

| level | fidelity | max N proven |
|---|---|---|
| in-process manager (`test_inproc_factory_lifecycle`) | real factory, real channels, real HTLCs, **full BOLT-2 ceremony** (partial-sig → cryptographic verify → aggregate → revoke_and_ack). One process, no sockets, both endpoints driven locally. | **10,000** (and 1023/512 settled on real signet) |
| daemon swarm (`superscalar_lsp` + N × `superscalar_client`) | separate processes, real sockets/Noise/wire, real reconnection | **127** |

The gap is not cryptography and not transaction size — a 1024-of-1024 MuSig2
aggregate signature and a 1024-output cooperative close are both proven on
signet. The gap is that **N=512 daemons do not fit in RAM**, so the distributed
protocol has never been exercised above 127.

Today's daemon startup crash (`factory_set_*` NULL-deref, fixed in #452) is the
concrete cost of that gap: the unit suite never runs daemon `main()`, and the
in-process harness bypasses sockets, so a crash in the primary binary reached
`main` unnoticed. Any test tier that actually starts daemons would have caught it.

## 2. Why it doesn't fit — measured, not estimated

Struct sizes on current `main`:

```
sizeof(factory_node_t)    = 23,816 B      <- x n_nodes, per client
sizeof(factory_t)         = 264,408 B     (epoch arrays dominate)
sizeof(channel_t)         =  86,696 B     of which nonce pool = 67,600 B (78%)
```

**Every client rebuilds and retains the entire tree.** `src/client.c:1112` calls
`factory_build_tree()` — the client reconstructs the tree deterministically from
(pubkeys, funding, arity) to verify the LSP's claims, which is correct, but it
then keeps all of it:

| N | tree nodes | tree bytes **per client** | × N |
|---|---|---|---|
| 127 | ~506 | 11.5 MB | ~1.5 GB (fits — this is why 127 works) |
| 512 | 2,046 | 46.5 MB | **~28 GB** |
| 1024 | 4,090 | 92.9 MB | **~100 GB** |

Cost grows as O(N) per client and therefore **O(N²) for the swarm**. That is the
whole problem.

## 3. The fix: a client does not need O(N) state

A client must be able to (a) verify its own leaf pays it the right amount and
(b) unilaterally exit. Both need only the **root→leaf path plus, at each level,
the sibling outputs' SPKs and amounts** — never other clients' subtrees.

```
path-only at N=512:  ~11 nodes = 0.25 MB   (vs 46.5 MB)   ~186x smaller
```

This is a **product** improvement before it is a test improvement: a phone wallet
should not carry tens of MB of strangers' tree data.

Because the client *builds* the tree rather than receiving it, this is a contained
change inside `build_subtree` (a "retain only the path to leaf L" mode) — **no
wire-protocol change, no renegotiation with the LSP.**

Two supporting trims:

- **Right-size MuSig nonce pools.** 67.6 KB of the 86.7 KB `channel_t` is a
  256-slot pool. 16 slots → `channel_t` ≈ 20 KB. Also saves ~34 MB on the LSP at
  512 channels.
- **Lazy `input_signer_indices`.** The fixed `[FACTORY_MAX_OUTPUTS][FACTORY_MAX_SIGNERS]`
  array is 16 KB of every 23.8 KB node and is unused for default (k=1) PS.
  Allocating it only for multi-input sub-factory nodes takes `factory_node_t` to
  ~7.4 KB, helping both sides.

### Resulting budget

| configuration | per client | N=512 | N=1024 |
|---|---|---|---|
| today (full tree, process) | ~56 MB | 28 GB ❌ | 100 GB ❌ |
| path-only, own process | ~4–8 MB | 2.5–4 GB ✅ | 5–8 GB ⚠️ |
| path-only, **thread** | ~0.3 MB | ~0.3 GB ✅ | ~0.5 GB ✅ |

## 4. Harness tiers

Each tier buys specific realism. They compose; none replaces the others.

| tier | shape | N=512 cost | what it proves that the tier below does not |
|---|---|---|---|
| **T1** in-process (exists) | 1 process, no sockets | 181 MB | protocol, crypto, settlement conservation |
| **T2** threads + real sockets | N client threads, each own channel + path, real wire to the LSP over loopback | ~0.3–0.5 GB | wire codec, ceremony interleaving, concurrency, reconnection, **daemon startup paths** |
| **T3** processes, path-only | N real processes; `fork()` after secp init so the 1.2 MB context is COW-shared | ~2.5–4 GB | OS process isolation, per-process crash/restart, real fd limits |
| **T4** rolling participation | K≈32 concurrent real clients cycled in waves | ~0.3 GB at **any** N | the real distributed ceremony at arbitrary N under bounded RAM |

**T2 is the best realism-per-byte** and is the tier that would have caught today's
crash. T4 is the only tier that scales to 1024+ real clients without new hardware.

### Threading feasibility (measured)

Mutable file-scope state on the client path:

```
client.c 3   wire.c 6   client_reconnect.c 0   channel.c 0   musig.c 0   peer_mgr.c 0
```

**Nine mutable globals total**, all simple scalars (`g_slot_hint`,
`g_client_nk_server_pubkey_set`, `g_client_funding_pending_reorg`, + 6 in `wire.c`).
Making them `_Thread_local` — or moving them into a client context struct — is a
small mechanical change, not a rewrite. There is no architectural barrier to
running N clients in one address space.

## 5. Phases

Each phase is independently mergeable and independently useful.

**P0 — Baseline instrumentation.** Record actual per-process RSS for LSP and
client at N=127 (not extrapolated). Add an RSS sample to the swarm harness so
every later claim is measured.
*Accept:* a committed baseline table for N=8/64/127.

**P1 — Lean client (the load-bearing change).**
Path-only tree retention + lazy `input_signer_indices` + right-sized nonce pools.
*Accept:* per-client RSS at N=127 drops ≥5×; N=512 daemon swarm fits under 4 GB;
suite stays 1522/1522; **tree-verify efficacy test still passes** (see Risks).

**P2 — T2 thread swarm.** `_Thread_local` the 9 globals; add a `superscalar_swarm`
harness running N clients as threads with real sockets to a real LSP.
*Accept:* N=512 create → payments → coop close on regtest, real wire throughout;
per-client reconciliation `output_i == received_i − sent_i`.

**P3 — T3 process swarm at 512.** `fork()`-after-secp-init; raise fd limits.
*Accept:* N=512 on regtest, then one signet run with the full audit bundle.

**P4 — Liveness reality (the actual finding).** Measure offline tolerance:
how many clients may drop before an N-of-N cooperative close fails, how long
reconnection convergence takes at 512 (the #447 gate), and what the force-close
fallback costs.
*Accept:* a published curve of dropout-rate vs close success at N=127/512.

**P5 — 1024 via T4.** Rolling participation for the creation ceremony.
*Accept:* N=1024 real distributed create + close under 1 GB.

## 6. Risks

- **Path-only must not weaken tree verification.** A client verifies its own leaf
  amount and that the path chains to the funding outpoint; sibling *amounts* do
  not affect that client's safety, but the existing bad-tree-refusal guarantee
  must be preserved exactly. P1 is gated on the tree-verify efficacy test
  continuing to pass, plus an explicit adversarial case (LSP serves a valid path
  inside an invalid tree).
- **Thread-shared state is a new failure class.** T2 shares an address space, so a
  bug in one client can corrupt another — a false-negative risk that T3 does not
  have. T2 findings should be confirmed on T3 before being called proven.
- **T2/T3 still do not model the network.** No latency, loss, reordering, or
  partition. Those need netem or a real multi-host run and are out of scope here.
- **The honest ceiling is protocol, not harness.** A 24 h soak at N=127 lost
  30/127 daemons, and an N-of-N cooperative close needs every one of them. Scaling
  the *test* to 512 will confirm the problem worsens; it cannot fix it. P4 exists
  to quantify that, and the real remedies (offline tolerance, multi-tx close —
  see #449) are separate protocol work.

## 7. Non-goals

- Changing the wire protocol (P1 deliberately avoids it).
- Raising `FACTORY_MAX_*` compile-time defaults; per-instance config already covers it.
- Replacing the in-process manager — T1 stays the fast path for scale/crypto work.
- Buying larger hardware. Every number above targets the existing box, with
  headroom to run on half of it.
