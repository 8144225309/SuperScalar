# Real distributed payments at N=512 / N=1024

**Status:** design proposal. Nothing here is implemented.
**Goal:** run SuperScalar at 512 and 1024 clients with the *same fidelity we have
at 127* — separate client instances, real sockets, real Noise handshakes, real
wire protocol, real per-payment commitment ceremonies — on the hardware we have,
without buying a bigger box.

## 0. MEASURED RESULTS — read this before the projections below

A falsification run (real `superscalar_lsp` + N × `superscalar_client`, real
sockets, regtest, pct-100 lifecycle: onboard-at-zero → LN seed → c2c economy →
(N+1)-output cooperative close with per-client reconciliation) produced:

| N | outcome | wall | LSP RSS | per client | swarm total | close |
|---|---|---|---|---|---|---|
| 127 | **PASS** | 569 s | 46.4 MB | 21.0 MB | 2.65 GB | 128 outs |
| 160 | **PASS** | 577 s | 50.3 MB | 22.3 MB | 3.55 GB | 161 outs |
| 192 | **PASS** | 663 s | 54.4 MB | 26.5 MB | 4.49 GB | 193 outs (`a25d8541…`) |
| **224** | **PASS** | 818 s | 107.1 MB | 24.7 MB | 5.52 GB | **225 outs** (`c9e4ee08…`) |
| 256 | **FAIL** | 4 s | — | — | — | refused at startup |

Every PASS reconciled **sat-for-sat, no skim**, with clients onboarded at zero.

### The actual wall is a compile-time cap, not a resource

N=256 did not run out of anything. It was **refused before listening**:

```
Error: --clients must be 1..255 (the LSP co-signs every factory:
       clients + 1 <= 256-signer MuSig cap)
```

That is `FACTORY_MAX_SIGNERS = 256`. The per-instance `factory_config` that lifts
it already exists and is used by the in-process manager (which reaches 10,000) —
**the daemon was simply never wired to use it.** At 224 the swarm used 5.5 GB of a
9 GB budget with all 224 client processes healthy, so nothing was close to
exhausted.

### Revised, empirically-grounded staircase

| range | status | what it needs |
|---|---|---|
| **N ≤ 255** | **works today, unmodified** (224 full lifecycle, 255 FACTORY LIVE) | nothing |
| 256 – 511 | blocked by **53 fixed-size arrays**, many on the stack | convert them to heap sized to `n_participants` — see below |
| ≥ 512 | additionally blocked by memory (~27 GB extrapolated) | path-only client (§3) |

### The 255 cap is LOAD-BEARING — tested, not assumed

An earlier revision of this doc claimed row 2 was "one config cap … a *small*
change, not a project." **That was wrong, and removing the cap proved it.**

The library side genuinely does scale: musig sessions size their pubnonces to the
actual signer count, and `factory_config_fit()` grows `factory_t`'s arrays to the
participant count. So lifting `superscalar_lsp`'s `--clients` guard *looks* safe.
It is not. Running N=256 with the guard removed produced:

```
*** stack smashing detected ***: terminated
=== CRASH (signal 6) ===  ... main+0x4e49
```

Memory corruption during factory creation — because the daemon path still declares
**53 fixed `[FACTORY_MAX_SIGNERS]` arrays**, many of them on the stack, and
`n_participants = 257` runs off the end of every one:

| file | count |
|---|---|
| `src/lsp_channels.c` | 12 |
| `src/client.c` | 11 |
| `src/lsp.c` | 7 |
| `tools/superscalar_lsp.c` | 3 (the crash site) |
| `src/ladder.c` | 3 |
| `src/persist.c` | 1 |

The guard is therefore **restored deliberately**, with a comment that says so, so
an over-large `--clients` is a clear error rather than a smash. Lifting it is a
real piece of work — 53 conversions, each needing correct free/error paths — and
it must land *before* the cap moves, not after.

**Lesson for sequencing:** the library scaling and the daemon scaling are separate
problems. `factory_config_fit()` is necessary but nowhere near sufficient, and the
cheap-looking config change was a trap that only an actual run at N=256 exposed.

### Secondary finding: wall-clock is the next practical limit

The seed phase is **sequential** — N `lsppay` calls × ~6 round-trips each. It grew
127→224 as 569 s→818 s, with ~11.5 min of the 224 run spent seeding alone.
Memory is not what will make N=512 painful to test; serialized onboarding is.
Batching/pipelining the seed loop is cheap and should precede any large-N run.

**Three predictions in the earlier draft were wrong, and the measurements win:**

1. **N=192 already works with real daemons, unchanged.** The "127 ceiling" was
   never a limit anyone had hit — it was simply the largest N previously tried.
   That is a free ~1.5× with no code change.
2. **The wire-frame limit (§3b B1) did NOT fire** — zero frame errors at any N.
   The dense `nodes × n_participants` matrix at `client.c:1675` is evidently not
   what a pseudo-Spilman ceremony exercises: PS leaves are 2-of-2, so the
   all-signer matrix is far smaller than the worst case computed there. **B1 is
   NOT the gating blocker.** It may still bite for non-PS shapes; unverified.
3. **The LSP is not a scaling factor** — 46→54 MB, essentially flat in N.

**What survives:** per-client memory is the real wall, and it grows ~0.085 MB per
added client from a ~21 MB floor. Extrapolating from measurement, not arithmetic:
N=256 ≈ 8.2 GB, **N=512 ≈ 27 GB**. So §3 (path-only client) remains the
load-bearing fix — but for the reason in §2, not §3b.

Where it actually breaks is being measured (224/256); §3b's ordering claim
("B1 gates everything above ~250") is **withdrawn**.

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

## 3b. Non-memory blockers (necessary in addition to §3)

Fixing per-client memory is **necessary but not sufficient**. Four further limits
bite between N=256 and N=1024, and the first is not a memory problem at all.

### B1 — Ceremony matrices exceed the wire frame (the real ceiling)

`WIRE_MAX_FRAME_SIZE = 16 MB`, commented "needed for ALL_NONCES at N=64+". A dense
all-signers × all-nodes nonce matrix is `N × n_nodes × 66 B`:

| N | dense matrix | vs 16 MB frame |
|---|---|---|
| 127 | **4.0 MB** | fits — *this is why 127 works* |
| 512 | **65.9 MB** | ✗ 4× over |
| 1024 | **263.6 MB** | ✗ 16× over |

So even with perfect memory efficiency the **ceremony messages themselves** stop
fitting somewhere around N≈250. The same applies to the partial-sig matrix.

**CONFIRMED IN CODE** (`src/client.c:1675`) — this is not an estimate:

```c
size_t mtx_stride = (size_t)factory->n_participants * 66;  /* tight stride = actual signer count */
unsigned char *all_pn = calloc(nn, mtx_stride);
...
have_matrix = (got_matrix_len == (uint32_t)(nn * mtx_stride));   /* received over the wire */
```

The matrix is `n_nodes × n_participants × 66 B` **dense**, and `got_matrix_len`
shows it crosses the wire whole. The stride fix introduced for the N≥127 abort
narrowed the stride from `FACTORY_MAX_SIGNERS` (256) to the actual participant
count — a **constant-factor** win, not a sparsity win.

It is also a **memory** hit, not only a wire limit: that single `calloc` is
~69 MB per client at N=512, on top of the 46.5 MB tree.

*Fix — make it sparse, not merely strided.* A signer participates only in the
nodes on its own root→leaf path (~11 at N=512), never in all 2,046. Sum over
nodes of the **actual** signer-set size is **O(N log N)**:

| N | dense (today) | sparse (O(N log N)) | reduction |
|---|---|---|---|
| 127 | 4.3 MB | ~150 KB | ~29× |
| 512 | 69.3 MB | ~743 KB | ~93× |
| 1024 | 277 MB | ~1.6 MB | ~173× |

Every frame then stays far under 16 MB at any N, and the per-client transient
allocation disappears with it. The same treatment is required for the partial-sig
(`0x89`) matrix.

### B2 — `select()` breaks (and is UB) past fd 1023

Four `select()` sites remain in `src/lsp_demo.c` (the CLI/demo path, including the
`lsppay` drain loop). `FD_SETSIZE` is **1024**; `FD_SET(fd, …)` with `fd ≥ 1024`
writes past the `fd_set` — a stack smash, not a graceful error. Fine at 512,
**hard blocker at ~1024**. *Fix:* convert those four to `poll()` (the core loop
already uses poll/epoll in 8 places).

### B3 — File-descriptor ceiling

`ulimit -n` is **1024**. The LSP needs ≈ N + ~20 (clients + listener + bitcoind
RPC + sqlite + stdio): ~532 at N=512 (fits), **~1044 at N=1024 (does not)**.
*Fix:* raise to 65536 in the harness/service unit.

### B4 — `LSP_MAX_CLIENTS` default

Defaults to **256**, overridable with `--max-connections`. Not a code change, but
it will silently cap a 512 run if forgotten. *Fix:* set explicitly in the harness
and assert the effective cap at startup.

### Ordering consequence

B1 gates everything above ~250 and is protocol-level, so it should be validated
**before** the memory work — otherwise P1 could land, look successful, and still
fail at 512 for an unrelated reason.

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

**P0 — Baseline + B1 spike (do FIRST).** Verify the nonce/psig matrices stride per participant at N=512/1024 (§3b B1) BEFORE the memory work — a dense path anywhere caps us near N≈250 regardless of RAM. Set `--max-connections`, raise `ulimit -n`, convert the four `lsp_demo.c` `select()` sites to `poll()`.
*Accept:* a 512-client ceremony message trace with max frame < 16 MB, and a committed RSS baseline for N=8/64/127.

**P0b — Baseline instrumentation.** Record actual per-process RSS for LSP and
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
