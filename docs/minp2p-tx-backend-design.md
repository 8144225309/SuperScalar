# minp2p — minimal Bitcoin P2P TX backend (design)

**Status:** Design draft. Tracked as **SF-MINP2P-TX-BACKEND**.
**Author:** LSP team, 2026-05-20.
**Related:** SF-RECOVERY-REBROADCAST (#259, PR #302), SF-WT-TRUSTLESS (#248, PR #294/#301), SF-CSV-WAIT (#247).

## Goal

Give the LSP and the trustless WT a self-contained way to broadcast TXs and
verify their on-chain / mempool state **without requiring a local bitcoind**
and **without relying on any single source of truth**.

The blunt "if `getmempoolentry` returns nothing, resend" of PR #302 closed a
real gap but exposed two deeper questions:

1. How do we verify *network-side* TX state, not just our own bitcoind's
   view? — when bitcoind has gone quiet or is being actively misled.
2. How does an operator who doesn't run bitcoind get any of this at all? —
   trustless WT operators in particular shouldn't have to bring a full node.

minp2p answers both with a small persistent P2P peer pool + a queue of
TX-state tasks worked at a polite, paced rate. It is the trustless
counterpart to the existing RPC chain backend, sitting on top of the same
polymorphic interface (`chain_backend->probe_tx_state(...)`).

## What this is NOT

- **Not a port of `rawrelay`**. RawRelay's fresh-dial-per-broadcast pattern
  is right for a one-shot CLI policy probe; it is wrong for a daemon that
  needs to operate continuously for weeks. Fresh-dial leaks our "this IP
  scans the network" fingerprint and is the canonical ban pattern.
- **Not a replacement for `src/bip158_backend.c`**. BIP-158 keeps doing
  chain sync via NODE_COMPACT_FILTERS peers. minp2p does TX-level
  operations against a different pool.
- **Not a full Bitcoin node**. We don't validate, don't relay other
  peers' inv, don't serve blocks. We are a polite small participant.

## Architecture

```
                +-----------------------------------------+
                |             chain_backend_t             |
                |   probe_tx_state(txid) -> StateEnum     |
                |   broadcast_tx(hex)    -> result        |
                |   get_height()         -> int           |
                +-------------+-----------+---------------+
                              |           |
              +---------------+           +---------------+
              |                                           |
+-------------v-----------+              +----------------v---------------+
|   chain_backend_rpc     |              |   chain_backend_minp2p  (new)  |
|   (existing)            |              |                                |
|                         |              |   +----------+    +---------+  |
|   bitcoind via JSON-RPC |              |   | TX queue |    | Peer    |  |
|                         |              |   |          |    | pool    |  |
|   testmempoolaccept     |              |   +----+-----+    +----+----+  |
|   sendrawtransaction    |              |        |               |       |
|   getmempoolentry       |              |        v               v       |
|   gettransaction        |              |   +----+---------------+----+  |
|                         |              |   |       worker             |  |
+-------------------------+              |   |  paced K-of-N fan-out    |  |
                                         |   +--------------------------+  |
                                         +--------------------------------+
                                                       |
                                            +----------+----------+
                                            | bitcoin P2P (TCP)   |
                                            |   ping/pong         |
                                            |   getdata MSG_TX    |
                                            |   inv  MSG_TX       |
                                            |   tx                |
                                            |   (optional: Tor    |
                                            |    SOCKS via tor.c) |
                                            +---------------------+
```

The polymorphic `chain_backend_t` is the key abstraction. Recovery logic
calls `chain_backend->probe_tx_state(txid)` and gets one of:

```c
enum {
    TX_STATE_CONFIRMED,     /* on the canonical chain */
    TX_STATE_IN_MEMPOOL,    /* not on chain, but in mempool */
    TX_STATE_EVICTED,       /* nowhere in our view; resendable */
    TX_STATE_ABANDONED,     /* wallet/RPC explicitly gave up (conflicted, etc.) — operator action */
    TX_STATE_UNKNOWN,       /* probe didn't reach consensus; try again */
};
```

Both backends implement this. The recovery loop is backend-agnostic.

## Peer pool

### Size and behaviour
- **5 persistent outbound connections** (operator-tunable, default 5)
- Connect on LSP startup, hold open
- Standard Bitcoin Core ping/pong every 90s — looks like any other small
  honest node from the peer's perspective
- Reconnect from candidate cache on death (zero DNS lookups)
- Slow rotation: every 6–12h, drop 1 peer + dial 1 fresh from candidate
  cache (operator-tunable)
- Optional: route all connections through Tor SOCKS at `127.0.0.1:9050`
  (`src/tor.c` already exists)

### DNS seeder usage policy

This is the question that has to be answered precisely because DNS seeders
are a shared community resource.

- **At LSP startup**: query the 5–6 hardcoded Bitcoin Core DNS seeders
  (`seed.bitcoin.sipa.be`, `dnsseed.bluematt.me`, `dnsseed.bitcoin.dashjr.org`,
  `seed.bitcoinstats.com`, `seed.bitcoin.jonasschnelli.ch`, `seed.btc.petertodd.org`).
  This is **one DNS event per process lifetime** in the normal case.
- **Cache to disk**: write the resolved IPs to `<datadir>/peers.cache` so
  subsequent LSP restarts skip DNS entirely.
- **Long-running daemon**: zero DNS queries after startup, period.
- **Pool drain pathological case**: if all 5 peers die *and* the candidate
  cache is exhausted (we burned through every fallback IP from the original
  bootstrap), then *and only then* re-query DNS. Add a 10-minute floor between
  consecutive DNS re-queries so a buggy network can't burst us.
- **Reboot loop scenario**: if an operator restarts the LSP 100 times in a
  day (development or systemd-respawn pathology), peer cache survives, so
  we still only hit DNS at the original cache-creation moment.

**Realistic DNS load**: 1 query per LSP install lifetime under normal
operation. Maybe 1 per day under chaotic ops. Never per-TX, never per-restart.

This is well below any seeder's rate limit and indistinguishable from any
other lite-client bootstrap.

## TX queue and worker

### Task types

```c
enum {
    MINP2P_TASK_PROBE,                /* (txid)        -> {peers_HAS, peers_NOTFOUND, peers_TIMEOUT} */
    MINP2P_TASK_BROADCAST,            /* (hex)         -> {peers_accepted, peers_rejected} */
    MINP2P_TASK_PROBE_THEN_BROADCAST, /* (txid, hex)   -> as above; sends only if all probes NOTFOUND */
};
```

The **PROBE_THEN_BROADCAST** primitive is the optimal task for eviction
recovery: ask K peers if they have it, and only push if they don't. No
wasted broadcast, no spam.

### Worker pacing

- Worker pulls one task at a time from the queue
- Per-task, fan out to **K of N** connected peers (K=3 default, N=5)
- Per-peer rate limit: **at most one minp2p task per 3 seconds**
- Aggregate cap: **at most 5 tasks/30s** across the whole worker

Math: at K=3, N=5, the worker sends ~1 task per 3s. Even a 50-deep queue
drains in ~2.5 minutes. Per-peer that's 1 op/30s on average — well below
any peer's spam threshold (Bitcoin Core defaults to disconnect-after-rate-
limit at 10+ inv/sec/peer).

### Queue persistence

**This is the resilience gap to close before this lands.**

- Task queue must persist to `lsp.db` so tasks survive LSP restart
- New table `minp2p_tasks(id, type, txid, raw_hex, created_at, last_attempt_at, attempts, status)`
- On startup, walk in-flight tasks, re-attempt or expire them
- TX hex is already in `broadcast_log.raw_hex` — `minp2p_tasks` references
  by id, doesn't duplicate hex
- Cap queue depth at 100 by default; operator-tunable; alert on cap-hit

### K-of-N consensus rules

To defend against a malicious peer lying about probe results:

- Treat as `IN_MEMPOOL` only if **at least K=2 of N peers reply HAS**
- Treat as `EVICTED` only if **all probed peers reply NOTFOUND** (no lying-by-omission can fake this)
- Treat as `UNKNOWN` if `peer_count < K` (insufficient quorum, retry next iteration)
- Operator-tunable: `--minp2p-quorum-k 2`

This means a single dishonest peer can't make us skip a needed rebroadcast,
and a single dishonest peer can't make us spam unnecessary rebroadcasts.

## Reusing what already exists in the codebase

| Concern | Existing module | Reuse plan |
|---|---|---|
| Bitcoin P2P wire codec | `src/p2p_bitcoin.c` | direct call into version/verack/ping/pong/inv/getdata/tx serializers |
| Persistent task queue | `src/lsp_queue.c` | reuse the queue primitive |
| DNS resolution | libc `getaddrinfo` | one helper, ~30 LOC |
| Tor SOCKS routing | `src/tor.c` | wrap the connect() call |
| TX hex storage | `broadcast_log.raw_hex` | already there |
| Metrics | `src/prometheus_exporter.c` | new gauges + counters |

Net-new code is small because the wire layer is already there. We just
need pool-management + queue-worker + the polymorphic backend interface.

## Engineering goals and how each is met

| Goal | Mechanism |
|---|---|
| Don't depend on local bitcoind | minp2p talks Bitcoin P2P directly, no RPC dependency |
| Avoid getting banned by peers | 5-conn pool + ping/pong + 1-task/3s/peer rate limit + slow rotation |
| Avoid looking like a probe scanner | persistent connections, normal small-node fingerprint |
| Handle big TX stacks gracefully | queue absorbs burst, paced worker drains, depth-cap + operator alert |
| "Ask first, send if not there" | PROBE_THEN_BROADCAST task type |
| Privacy | optional Tor SOCKS; slow peer rotation; K-of-N fan-out spreads queries |
| Resilient like the rest of SuperScalar | task queue persisted to lsp.db; restart-aware (gap — see Resilience section) |
| Independent WT verification (#248) | WT spawns its own minp2p instance; doesn't share state with LSP's |
| Operator without bitcoind can still run | yes — minp2p is fully standalone |

## Resilience checklist

This is the section that needs to be checked against the "is it as
resilient as the rest of the SuperScalar codebase" bar.

| Resilience property | Status | Where it lives / what closes the gap |
|---|---|---|
| Peer pool replenishment from cached IPs | ✓ designed | candidate cache + reconnect logic |
| Fall back to DNS only if cache exhausted | ✓ designed | 10-minute floor between re-queries |
| Task queue persistence across restart | ⚠ DESIGN GAP | new `minp2p_tasks` table in v37 schema bump |
| Crash recovery on startup | ⚠ DESIGN GAP | walk in-flight tasks, re-attempt or expire |
| Idempotent task execution | ✓ designed | sendrawtransaction is idempotent; getdata is read-only |
| Reorg awareness | ⚠ DESIGN GAP | needs integration with R1–R6 — if a previously-confirmed TX gets reorg'd out, queue a fresh probe task |
| Operator alerts on pool death | ⚠ DESIGN GAP | systemd journal + Prometheus metric `minp2p_peers_connected{value=0}` |
| Operator alerts on queue saturation | ⚠ DESIGN GAP | Prometheus + log line + optional bridge notify hook |
| Peer ban handling (they ban us, we move on) | ✓ designed | connection death triggers fresh dial from cache |
| K-of-N consensus against malicious peers | ✓ designed | quorum rules above |
| Telemetry / dashboard visibility | ✓ designed | Prometheus exporter wire-up |
| Regtest test coverage | ⚠ DESIGN GAP | mockable at chain_backend interface; need scaffold |

**Net**: 4 design gaps for full resilience parity. All addressable; total
additional effort ~200–300 LOC + corresponding tests. Phasing below
sequences them so we don't block on the gap closure.

## Ban-risk analysis

### Single-LSP normal operation
- 5 persistent connections
- ~1 TX broadcast per channel close / rotation / few hours
- Maybe 1 probe-then-broadcast per day per channel
- Per-peer load: <1 op/hour, far under any rate limit
- **Verdict**: zero ban risk.

### High-throughput LSP (factory rotation, force-close storm)
- Worst-case burst: 30 TXs queued at once (16 PS leaves × 2 + a few sweeps)
- Worker drains at ~1 task/3s/peer × 5 peers = ~1.7 tasks/sec aggregate
- Drain time: ~18 seconds
- Per-peer over that window: ~3.6 ops/peer
- **Verdict**: noisier than normal, still well under Bitcoin Core's typical
  inv-flood thresholds. No ban.

### Pathological "1000 TX stack"
- Queue cap at 100 prevents this from being submitted in the first place
- Operator alert fires; bridge can notify operator + dashboard
- **Verdict**: doesn't reach the peer layer; mitigated at the queue boundary.

### Reboot loop
- Peer cache survives, DNS not hit
- Peers see "small node came back online" — normal pattern
- **Verdict**: no ban.

### Adversarial peer scenario (peer tries to provoke ban)
- We only respond to ping with pong, accept incoming inv/tx as informational
- Don't forward, don't validate-and-relay
- A malicious peer can't get us to misbehave because we don't take actions
  based on their unsolicited messages
- **Verdict**: peer can ignore us or disconnect us, but can't make us
  misbehave to a third peer.

## Open questions to pin down before implementation

1. **Quorum K default**: 2 of 3 fan-out? 2 of 5? Defaults matter — too
   high and we waste probes; too low and a single dishonest peer poisons us.
   *Proposed default: K=2 of N=3-fan-out, with 5-peer pool. Operator-tunable.*

2. **PROBE_THEN_BROADCAST timing semantics**: when peers all reply NOTFOUND,
   do we push immediately or wait one second to confirm peer-side propagation
   from earlier broadcasts? *Proposed: push immediately, then re-probe in 15s
   to verify network-side propagation succeeded.*

3. **`testmempoolaccept` pre-check in minp2p?**: bitcoind has it; minp2p
   doesn't. *Proposed: minp2p skips the dry-run, just sends the inv. The peer
   itself will reject if invalid (logged as "peer rejected, mark unrecoverable
   in lsp.db"). Trade simplicity for graceful failure rather than dry-run.*

4. **Cache file format**: peers.cache as plain text IPv4 lines (one per line)
   vs JSON. *Proposed: plain text, one `host:port` per line. Trivial to inspect
   and bootstrap manually.*

5. **What network does minp2p start with?** Mainnet seeders only? Or
   per-network seeders? *Proposed: switch on `--network` flag; testnet4 has
   its own seeders, signet has its own, mainnet has its own.*

6. **Backend selection priority**: when both RPC and minp2p are configured,
   which is primary? *Proposed: RPC primary (faster, more diagnostic), minp2p
   used as second-opinion + as fallback if RPC unavailable. Operator can flip
   via `--probe-tx-backend-primary={rpc,minp2p}`.*

7. **WT-side minp2p instance — entirely separate from LSP's?** If yes,
   the WT has its own peer cache, its own queue. *Proposed: yes, fully
   separate. WT is a different process; sharing would create the same
   trust coupling we're trying to avoid.*

## Implementation phasing

5 PRs, properly stacked.

### PR α — Generic `chain_backend.probe_tx_state` interface + RPC impl (~150 LOC, half day)
- `include/superscalar/chain_backend.h`: add `probe_tx_state` + state enum
- `src/chain_backend_rpc.c`: implement using testmempoolaccept + gettransaction.walletconflicts/abandoned
- Recovery loop calls `chain_backend->probe_tx_state(...)` polymorphically
- Net result: PR #302 becomes a more honest version with explicit `EVICTED`,
  `ABANDONED`, `UNKNOWN` states; operators with bitcoind get diagnostics today

### PR β — minp2p core: peer pool + DNS bootstrap + connection lifecycle (~300 LOC, ~1.5 days)
- `src/chain_backend_minp2p.c`, `include/superscalar/chain_backend_minp2p.h`
- DNS seeder query helper (one-shot at startup; cache to `<datadir>/peers.cache`)
- Outbound peer connect + version/verack + ping/pong loop
- Slow peer rotation
- Optional Tor SOCKS wrapper
- Initially implements only `chain_backend.get_height()` — minimal to validate
  wiring before the queue + worker land

### PR γ — TX queue + workers + PROBE / BROADCAST / PROBE_THEN_BROADCAST tasks (~250 LOC, ~1 day)
- Reuse `src/lsp_queue.c`
- Schema v37 bump: `minp2p_tasks` table with persistence + crash-recovery
- Worker pulls task, fan-out to K-of-N peers, aggregates, calls back
- Rate limits: 1 task/3s/peer
- Queue depth cap + operator alert

### PR δ — wire minp2p into recovery + WT trustless path (~80 LOC, half day)
- Recovery loop's `probe_tx_state(...)` consults both backends, takes K-of-N consensus
- WT trustless (#248) Phase 2 gets its own minp2p instance
- Operator flags: `--minp2p-enabled`, `--minp2p-peer-count`, `--minp2p-rotation-hours`,
  `--minp2p-quorum-k`, `--minp2p-tor-socks`

### PR ε — test scaffolds + metrics (~200 LOC, half day)
- Unit tests for queue + task lifecycle
- Mock-peer harness for probe-then-broadcast aggregation
- Optional regtest scaffold: real regtest bitcoind + minp2p peer
- Prometheus metrics: `minp2p_peers_connected`, `minp2p_queue_depth`,
  `minp2p_tx_probes_total{result=…}`, `minp2p_tx_broadcasts_total{result=…}`

**Total**: ~5 days focused work, ~1000 LOC, properly stacked.

## Comparison vs what other LN implementations do

| Property | Bitcoin Core | LND/bitcoind | LND/Neutrino | CLN | **SuperScalar w/ minp2p** |
|---|---|---|---|---|---|
| TX broadcast | `walletbroadcast=true` silent | RPC | Neutrino P2P | RPC | minp2p paced queue |
| TX state probe | RPC gettransaction | RPC | filter scan | RPC | minp2p + RPC consensus |
| Eviction recovery | implicit, internal | LND rebroadcaster | similar | per-block rebroadcast | active K-of-N + reseed |
| Multi-source verification | no | no | no | no | **yes** |
| WT independent verification | n/a | n/a | n/a | n/a | **yes** (WT has own minp2p) |
| Privacy (Tor) | bitcoind config | optional | optional | optional | optional via `src/tor.c` |

That last column is where SuperScalar earns its complexity — the multi-source
+ trustless-WT story has no precedent in production LN implementations, but
it falls naturally out of the polymorphic chain backend + minp2p design.

## References

- `tools/superscalar_lsp.c:798` — current CSV-wait broadcast retry loop (#247)
- `src/regtest.c:1518` — current `regtest_wait_for_stable_confirmation` (#259 fix is here)
- `src/p2p_bitcoin.c` — Bitcoin P2P wire codec (reuse)
- `src/bip158_backend.c` — BIP-158 chain-sync peer pool (parallel; not shared with minp2p)
- `src/lsp_queue.c` — queue primitive (reuse)
- `src/tor.c` — SOCKS routing (reuse)
- `docs/watchtower-trustless-schema.md` (PR #294) — the trustless-WT model that minp2p complements
- [rawrelay](https://github.com/8144225309/rawrelay) — the conceptual ancestor for direct-dial broadcast
