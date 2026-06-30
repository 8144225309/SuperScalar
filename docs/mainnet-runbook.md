# Mainnet Operator Runbook

Canonical operator runbook for running SuperScalar LSPs in production.
This document expands the pre-launch checklist (task #151) into the full
operational manual: deployment topology, backups, HSM, TLS, monitoring,
and incident response.

For day-one setup mechanics (build, network selection, flag reference),
see [lsp-operator-guide.md](lsp-operator-guide.md). This document assumes
the operator has a working signet deployment and now needs to harden it
for real-money operation.

> **Mainnet is not yet supported.** Several sections below are gated on
> features that have not landed (HSM integration, etc.). Each gated
> section is marked with a TODO referencing the blocking task. The
> mainnet activation gate (Section 10) is the canonical list of audit
> prerequisites that must close before `--network mainnet` is safe.

---

## 1. Pre-launch checklist

Before pointing any production LSP at mainnet, every item in this list
must have an objective "done" answer. Items below derive from the
pre-mainnet ops checklist drafted under task #151.

### Code / audit prerequisites

- [ ] Schema migrations through v34 (ceremony_participants) applied
      and tested on a populated DB (per #185)
- [ ] Factory funding canonical-chain guard active (#125-#129); no
      open issues against `lsp_channels_revalidate_funding`
- [ ] Watchtower restart audit complete for R1/R5 (tasks #135 and #161 — signoff in PR #287 commit body)
- [ ] Force-close cost calculator validated against on-chain replay
      (per #72 dashboard query and #136 confirmation-depth policy)
- [ ] PTLC balance + chain-validation production threading merged
      (per #253, gates non-trivial routed payments)
- [ ] SF-AUDIT prerequisites (#152) all green — see Section 10

### Operational prerequisites

- [ ] Bitcoin Core 28.1+ fully synced on mainnet with `-txindex=1`
      and `-blockfilterindex=1` (BIP-158 scanning required by the
      watchtower)
- [ ] Funded mainnet wallet with at least `factory_amount +
      reserve_for_force_close_fees + rotation_buffer`
- [ ] Persistent LSP key generated via BIP39 mnemonic
      (`--generate-mnemonic`), 24 words written down and stored
      offline; passphrase recorded in a separate offline location
- [ ] Static public IP or stable Tor hidden service address
- [ ] Inbound port 9735/tcp (or chosen `--port`) reachable
- [ ] Backup destination (separate host or object store) reachable
      and write-tested
- [ ] On-call rotation defined with documented escalation path
- [ ] Out-of-band channel to each client operator (force-close
      response requires reaching clients on a non-LN channel)

### Documentation prerequisites

- [ ] Client onboarding doc points at this runbook for incident
      escalation
- [ ] CLN bridge operator (if used) knows where the LSP pubkey lives
      and has pinned it via `--lsp-pubkey` (see Section 5)
- [ ] Dashboard installed on a host that is NOT the LSP host (so a
      crashed LSP does not also lose monitoring)

---

## 2. Deployment topology

### Single-node (recommended for v1)

```
+----------------------------------+
|   LSP host                       |
|   - bitcoind (mainnet, txindex)  |
|   - superscalar_lsp --daemon     |
|   - SQLite DB on local NVMe      |
+----------------------------------+
            |
            | inbound 9735/tcp
            v
        clients...
```

This is the supported topology for mainnet v1. bitcoind co-located on
the same host as the LSP keeps the RPC path local (lower latency on
`gettxout`, `getrawtransaction`, and the BIP-158 scan that the
watchtower hot-path uses).

### Separate bitcoind (advanced)

Supported but adds a failure mode: if the network between the LSP and
bitcoind partitions, the watchtower stops scanning blocks and the
heartbeat reorg detector cannot run. Acceptable only if the link is
private and monitored.

### HA / multi-node

**Not supported in v1.** SuperScalar holds private signing material
(LSP seckey, MuSig2 nonces) that cannot safely be replicated. Active /
active is unsafe; active / passive with manual failover is possible
in principle but requires a tested cutover playbook and a strict rule
that the passive node must NEVER run while the active node holds an
unclosed factory.

TODO: HA story depends on HSM integration (Section 4) — until the
seckey lives behind a quorum signer, all HA configurations risk
double-signing.

### Network requirements

| Resource | Minimum | Notes |
|----------|---------|-------|
| Inbound port | 1 TCP | Default 9735, set via `--port` |
| Outbound | unrestricted | bitcoind P2P (8333), bridge daemon (if used) |
| Public IP or Tor | required | Clients must reach the LSP without NAT punching |
| Latency client to LSP | < 500 ms p99 | Ceremony timeouts assume this; mainnet uses 120s per-message budget |

### DB size projections

Order-of-magnitude only. Real numbers depend on payment volume and
rotation cadence.

| Clients | Active factories | DB at 30 days |
|---------|------------------|---------------|
| 4 | 1 | ~50 MB |
| 16 | 1 | ~200 MB |
| 64 | 1-2 | ~1 GB |
| 256 | 4+ | TODO: depends on factory scale work (`feat/factory-scale-128`) |

Growth drivers: `signing_rounds` (one row per signer per ceremony),
`old_commitments` (one row per commitment per channel), and the
append-only forensic tables `reorg_events` and `breach_detections`
(v29).

---

## 3. Backup rotation policy

The LSP DB is the single most important piece of state on the host.
Losing it while a factory is open means losing the ability to
cooperatively close — recovery falls back to on-chain CLTV timeout.

### What to back up

| Artifact | Why | Frequency |
|----------|-----|-----------|
| LSP DB (`lsp.db` + `lsp.db-wal` + `lsp.db-shm`) | Channel state, commitments, watchtower entries | Hourly hot, daily cold |
| LSP keyfile (`lsp.key`) | Identity + signing | Once, after generation, offline only |
| BIP39 mnemonic | Disaster recovery if keyfile is lost | Once, offline, two geographic locations |
| Watchtower DB (if separate, currently same file) | Penalty TX cache | Same as LSP DB |
| Client onboarding records (out of band) | Knowing who is in each factory | On change |
| bitcoind `wallet.dat` | Funding wallet | After every refill |

### SQLite WAL strategy

SuperScalar runs SQLite in WAL mode. A naive `cp lsp.db backup.db`
captures the main file but NOT the WAL contents, leading to a stale or
corrupt backup. The required procedure:

```bash
# Online hot backup (LSP running) — uses sqlite3 .backup command,
# which is safe against concurrent writers.
sqlite3 /var/lib/superscalar/lsp.db ".backup '/backup/staging/lsp.db'"
# Then copy /backup/staging/lsp.db to off-host storage.
```

Do NOT use `cp` or `rsync` against a live DB. Per the watchtower test
scaffold lessons (commit ed6e5f4, task #178), even cold backup needs a
checkpoint first:

```bash
# Cold backup (LSP stopped or quiesced)
sqlite3 /var/lib/superscalar/lsp.db "PRAGMA wal_checkpoint(TRUNCATE);"
cp /var/lib/superscalar/lsp.db /backup/cold/lsp-$(date +%Y%m%d).db
```

### Rotation cadence

- **Hourly hot backups** retained 48 hours
- **Daily cold backups** retained 30 days
- **Weekly off-site archive** retained 1 year
- **Pre-rotation snapshot** taken automatically before every factory
  rotation (TODO: not yet wired into the rotation handler — depends
  on a new hook around the lsp_channels rotation entry point)

### Restore drill

A backup is only useful if a restore has been tested end-to-end. At
least once per quarter:

1. Spin up a clean host
2. Restore the most recent hot backup
3. Start `superscalar_lsp` with the same `--seckey` / `--keyfile`
   and `--db` paths
4. Verify the daemon reads its previous state, the watchtower
   rehydrates (per the WT restart audit), and `heartbeat` returns
   to steady state
5. Tear down the test host

Document the time-to-recovery from each drill. The number is the SLO
the operator can credibly offer clients.

An automated, repeatable version of this drill is
`tools/test_regtest_restore_drill.sh` (regtest): it performs the hot
`sqlite3 .backup`, wipes the live DB, restores from the backup, asserts the
restored DB is identical (same factory funding outpoint), and confirms the LSP
resumes the factory from the restored DB (the `--daemon` recovery probe loads it,
logging "found existing factory in DB, entering recovery mode"). Run it
pre-release / in CI so the restore path cannot silently regress.

---

## 4. HSM integration

**Status: not yet implemented.** The LSP currently holds its 32-byte
seckey on the local filesystem (`--keyfile`, optionally encrypted
with `--passphrase`). Mainnet should not run this way long-term, but
mainnet v1 may.

### Current key storage

- BIP39 mnemonic (recommended) — 24 words derive the key via
  m/1039'/0'/0'. Mnemonic is the disaster-recovery anchor; keyfile
  is the operational copy.
- Encrypted keyfile — passphrase encrypts the keyfile at rest; the
  daemon needs the passphrase at startup.
- Random keyfile — no recovery if lost.

Where the key is used at runtime: MuSig2 partial signing inside
ceremonies (factory creation, cooperative close, rotation, PTLC
turnover, subfactory poison), and the static Noise handshake when
clients connect with `--lsp-pubkey`.

### HSM-vs-file tradeoffs

| Property | Encrypted keyfile | HSM |
|----------|-------------------|-----|
| Operational complexity | Low | High |
| Cold-storage friendly | Mnemonic offline | Quorum custody possible |
| Compromise blast radius | Full key extraction if host is rooted | Signing oracle only — no key extraction |
| Performance | Native speed | Round-trip per partial-signature (latency adds to every ceremony) |
| HA story | None | Quorum signing enables HA |

### Key rotation procedure

TODO: this section depends on an issue not yet filed — there is no
in-protocol key rotation. The only path today is:

1. Cooperatively close every factory the LSP participates in
2. Stop the LSP
3. Generate a new key
4. Restart the LSP with the new keyfile
5. Re-onboard every client

No way to rotate the LSP key while factories are open. Designing an
in-protocol rotation primitive is open work.

---

## 5. TLS / Noise handshake

SuperScalar uses Noise (not TLS) for transport security between clients
and the LSP, and between the bridge and the LSP.

### Current handshake modes

- **NN (unauthenticated)** — default. Clients connect without
  verifying the LSP's identity. Vulnerable to MITM if the operator
  cannot vouch for the network path. The LSP prints a warning at
  startup.
- **KK (authenticated, both sides pinned)** — clients pass
  `--lsp-pubkey HEX` (33-byte compressed pubkey). Required for the
  bridge daemon (`superscalar_bridge --lsp-pubkey`) in production.

The LSP prints its static pubkey at startup:

```
LSP: clients should use --lsp-pubkey 02abcdef...
```

### What changes for mainnet

- Document the LSP pubkey out of band (web page, signed Twitter post,
  etc.) so clients can verify before connecting
- Bridge MUST run with `--lsp-pubkey`; do not accept the
  unauthenticated-NN warning in production
- Tor hidden-service onion address is itself a pubkey-pinning
  mechanism (the .onion encodes the long-term key); if you run only
  over Tor and never share a clear-net address, KK is less critical
  but still recommended defense in depth

### Pinning the LSP pubkey

The pubkey is derived from the seckey at startup and printed once.
Capture it from the launch logs:

```bash
./superscalar_lsp ... 2>&1 | grep "LSP: clients should use"
# Output: LSP: clients should use --lsp-pubkey 02abc...
```

Publish that hex string in your operator-of-record location. Any
client connecting without it is connecting unauthenticated.

---

## 6. Monitoring playbook

### What to alert on

| Signal | Source | Severity | Action |
|--------|--------|----------|--------|
| Any new row in `reorg_events` (any class) | v29 forensic table — schema: `(id, timestamp, old_tip, new_tip, n_entries_reset)` | Page | Run Section 8 reorg incident playbook. Reorg class is inferred from `old_tip` vs `new_tip`: backward = HEIGHT_REGRESSION, same height = SAME_HEIGHT, forward with prev-hash change = FORWARD_REORG. |
| `n_entries_reset > 0` in any `reorg_events` row | v29 forensic table | Page | Reorg invalidated in-flight watchtower entries; verify re-broadcast on new chain |
| New row in `breach_detections` (column: `timestamp`) | v29 forensic table — schema: `(id, timestamp, channel_id, expected_commit_num, txid_seen, height_seen, response_txid)` | Page | Section 7 force-close playbook; if `response_txid` is non-null, watchtower already broadcast the penalty TX |
| `signing_rounds` row with `slow_signer` flag | v26 ceremony forensics | Warn | One signer holding up a ceremony; check that client's connectivity |
| Ceremony stuck in `PERSIST_CEREMONY_STATE_PENDING_SIGS` > 10 min | `ceremony_participants` (v34) | Page | One or more signers offline mid-ceremony |
| bitcoind RPC unreachable | LSP log | Page | Watchtower scanning is stopped |
| Disk free < 20% on DB volume | OS | Warn | Free space or expand volume |
| LSP process restart loop | OS / systemd | Page | Check crash recovery; do NOT auto-restart if DB is corrupt |
| Funding wallet balance below threshold | bitcoin-cli | Warn | Refill before next ceremony |

### Grafana / Prometheus integration

The LSP has a native Prometheus exporter (`src/prometheus_exporter.c`, shipped in PR #276). Enable it with:

```bash
./superscalar_lsp ... --prometheus-port 9090
```

The endpoint exposes ceremony counts, watchtower-event totals, reorg-detector status, factory lifecycle gauges, and broadcast-log counters in standard Prometheus text format. Scrape with Grafana, Victoriametrics, or any Prometheus-compatible collector.

Two complementary sources if you need data the exporter doesn't surface:

1. **SQLite forensic tables**: scrape via a sidecar that runs dashboard SQL queries (see `tools/dashboard.py`) and emits Prometheus text-format metrics. The dashboard computes force-close cost (#72), payment counts, and breach status; surface its API output as Prometheus metrics if Grafana panels need the same data as the dashboard tabs.
2. **LSP stderr log**: structured lines for ceremony events, watchtower events, and reorg detection. Pipe through `vector`, `fluentd`, or `journalctl --output=json` and feed into Loki / Promtail.

The Live Monitor tab (added in #255) is the real-time human-facing equivalent of the same data.

### Log volumes

Expect ~10 lines/minute steady-state per active factory, spiking to
~100 lines during a ceremony or a reorg. Retain 30 days of logs;
they are the primary forensic source if a forensic table row
references a ceremony that has since been garbage-collected.

---

## 7. Force-close incident response

A client triggers force-close by broadcasting a unilateral commitment
TX instead of cooperatively closing. This is expected behavior in
some cases (client believes the LSP is unresponsive or cheating) and
adversarial in others (client trying to cheat).

### Detection

The watchtower's chain backend (BIP-158 scanner or RPC poller) sees
the on-chain TX and inserts a row into `breach_detections` if the
confirmed commitment number is stale relative to the channel's
current state. For a current-state force close (not a breach), the
event lands in the WATCH_FORCE_CLOSE table (`force_close_watches`,
v28) instead.

### Playbook

1. **Confirm the event class**
   - Stale state → row in `breach_detections` → watchtower has
     already broadcast a penalty TX (the response_txid_hex column
     records what it sent). Skip to step 4.
   - Current state → row in `force_close_watches` → no breach,
     just an exit. Continue.

2. **Estimate the cost**
   - Use the dashboard force-close cost query (#72). It joins
     `force_close_watches` against the fee-per-tx table and
     returns expected sats burned to fees.
   - Inputs: factory_id, current fee_rate (sat/kvB), number of HTLCs
     in flight at force-close time.

3. **Verify confirmation depth**
   - Per #136, mainnet requires N=6 confirmations before treating
     the force-close as final. Do not begin HTLC sweep planning
     until depth >= 6.

4. **Verify watchtower response**
   - Query `breach_detections.response_txid_hex`
   - Run `bitcoin-cli getrawtransaction <txid> 1` on the response
     TX; verify it is in a block or in mempool with reasonable fee
   - If not in mempool, the watchtower failed to broadcast — this
     is a P0. Investigate via the WT restart audit doc.

5. **Sweep timeline**
   - HTLC sweeps run on CSV-delay timers. Monitor
     `pending_penalty_broadcasts` for bump cycles. Each bump
     consumes the fee budget; out-of-budget bumps stop and the
     operator must manually CPFP.

6. **Post-incident**
   - Snapshot the DB before any cleanup
   - File a post-mortem referencing the `breach_detections` row
     id and the on-chain txids
   - Communicate with the client out of band; their force-close
     usually has a reason

### Cost calculator inputs

The dashboard query #72 takes:
- factory_id
- current fee_rate
- number of HTLCs to sweep
- CSV delay (encoded in commitment)
- expected confirmation depth (per #136)

Output: sats burned to fees plus a worst-case if every HTLC requires
its own sweep TX.

---

## 8. Reorg incident response

A reorg threatens correctness in two ways: (1) the factory funding TX
could un-confirm or move to a non-canonical chain (#125-#129), and
(2) a watchtower penalty TX could likewise un-confirm.

### Detection

Three reorg classes are recorded as `reorg_events.severity` values:

- **HEIGHT_REGRESSION** — tip moved backward. Always a reorg.
- **FORWARD_REORG** — tip moved forward but the previous hash no
  longer agrees. A reorg of the previous tip block.
- **SAME_HEIGHT** — tip hash changed at the same height. A 1-block
  reorg.

Both the daemon main-loop reorg detector (per PR #201) and the
heartbeat detector (`lsp_channels.c` around line 6382) populate
this table. Per the WT restart audit, both are wired correctly.

### Playbook

1. **Identify the reorg depth**
   - `SELECT old_tip, new_tip, n_entries_reset FROM reorg_events
     ORDER BY id DESC LIMIT 5;`
   - n_entries_reset is the count of watchtower in-memory entries
     whose `penalty_broadcast` flag was cleared (they will be
     re-broadcast on the new chain)

2. **Verify factory funding canonicality**
   - `lsp_channels_revalidate_funding` runs automatically (#125)
     and revalidates every factory funding TX against the new tip
   - If a factory's funding TX is no longer canonical, the LSP
     marks the factory `funding_pending_reorg` (#211, v31), sends
     `MSG_FUNDING_REORG` to clients (#212), and freezes new
     ceremonies until the funding TX re-confirms on the new chain
   - If the funding TX is permanently gone (e.g. evicted from
     mempool past expiry, #215), the factory must be re-opened

3. **Verify subfactory chain state was reset**
   - PR #208 wires `factory_reset_all_subfactory_chains` to the
     reorg handler; this drops in-memory `ps_chain_len` on
     PS_SUBFACTORY nodes so the next chain extension re-derives
     from the on-chain state

4. **Verify watchtower re-scan**
   - The watchtower's penalty broadcasts are idempotent in the
     sense that the daemon will re-broadcast on the new chain if
     the penalty TX is missing
   - Manually verify by checking `pending_penalty_broadcasts` for
     any rows that should be in-flight

5. **Post-incident**
   - Reorgs deeper than 6 blocks on mainnet are extraordinarily
     rare; if you see one, file a chain-team alert (not just a
     SuperScalar alert)

### Confirmation depth assumptions

Per #136, mainnet treats 6 confirmations as final for funding TXs.
Tools that depend on funding finality (rotation, splice, JIT) must
not run against factories whose funding TX has < 6 confirmations.

---

## 9. Capacity planning

Numbers below are extrapolated from signet runs at N=4 to N=16. They
are starting points, not guarantees.

### Resource budget per factory

| Shape | RAM (LSP) | CPU during ceremony | Disk |
|-------|-----------|---------------------|------|
| N=4, k=1 | < 100 MB | 1 core, ~5s | ~50 MB DB |
| N=16, k=1 | < 250 MB | 1 core, ~20s | ~200 MB DB |
| N=64, k=4 | < 1 GB | 2-4 cores, ~90s | ~1 GB DB |
| N=128, k=8 | TODO (`feat/factory-scale-128`) | TODO | TODO |
| N=256+ | not supported | n/a | n/a |

k = number of PS subfactories (see [superscalar.win](https://superscalar.win) for the design).

### Signing time projections at N >= 64

The bottleneck at scale is the MuSig2 nonce + partial-signature round
trip. Each round is a single broadcast from each participant, but the
LSP must wait for the slowest one. Empirically:

- p50: dominated by 1-2 RTT to the slowest signer
- p99: dominated by the per-message timeout (120s on
  signet/testnet4/mainnet)

The `slow_signer` flag on `signing_rounds` (v26) identifies the
laggard for forensic follow-up.

At N=64 with healthy clients, expect signing rounds to complete in
under 30 seconds end-to-end. At N=128 with one or more slow signers,
expect rounds to walk up to the 120s timeout.

### Disk projection

Hot data scales linearly in clients × channels-per-client × commitment
count. The watchtower retains old commitments per channel; they age
out at rotation. Forensic tables (`reorg_events`, `breach_detections`,
`signing_rounds`) are append-only and small.

---

## 10. Mainnet activation gate

The audit prerequisites tracked under #152 (SF-AUDIT) are the canonical
gate for flipping the kill switch from `mainnet refused` to
`mainnet permitted`. Each item below must be objectively true.

### Audit prereqs (#152 SF-AUDIT)

- [ ] All schema migrations v1..v34 covered by upgrade tests on a
      populated DB
- [x] Watchtower restart audit (#135, #161) signed off (per PR #287 commit body)
- [ ] Reorg correctness audit (#125-#129) signed off
- [ ] Force-close cost calculator validated against on-chain replay
      (#72)
- [ ] Confirmation depth policy (#136) enforced for every code path
      that depends on funding finality
- [x] PTLC production threading merged (#253) — gates non-trivial
      routed payments
- [ ] CLN bridge security review (#175 / #176 follow-ups for
      watchtower breach recording) signed off
- [x] PTLC presig gating (#196, #256) and factory tree sign refusal
      without chain backend (#197, #257) both verified to refuse
      under hostile inputs
- [ ] Ceremony finalization guard (#199, #259) tested under crash
      injection at every state boundary
- [x] Splice path either fully implemented or explicitly disabled
      (currently a wire-codec stub per #198, #260)

### Operational prereqs

- [x] At least one full restore drill completed in the last quarter
      (automated + proven: tools/test_regtest_restore_drill.sh -- hot sqlite3
      .backup -> wipe -> restore -> LSP resumes the factory from the restored DB;
      regtest PASS. Soak validated via tools/test_regtest_soak_advances.sh: 50
      advances persisted + WT defends from the oldest stale state.)
- [ ] At least one full reorg drill (forced via regtest invalidate)
      completed in the last quarter
- [ ] At least one full force-close drill (client-initiated breach
      attempt) completed in the last quarter
- [ ] Mnemonic offline copies verified in two locations
- [ ] On-call rotation acknowledged by all parties

### External prereqs

- [ ] Third-party security review delivered (TODO: not yet
      commissioned — depends on funding)
- [ ] HSM integration decision made: ship without (file keyfile),
      or block on HSM work (Section 4)
- [ ] Public LSP pubkey published in operator-of-record location
      (Section 5)

Until every box above is checked, `--network mainnet` should be
treated as "configured but not safe to operate."

---

## Appendix: cross-references

- Pre-launch checklist origin: task #151
- Audit umbrella: #152 (SF-AUDIT)
- Reorg correctness: #125-#129, PRs #201, #208, #210, #211, #212, #215
- Watchtower restart: #135, #161, signoff in PR #287 commit body
- Confirmation depth: #136
- Force-close cost: #72, dashboard `tools/dashboard.py`
- Schema v29 forensic tables: `include/superscalar/persist.h:778-794`
- Schema v34 ceremony participants: PR #252 (#185)
- PTLC production threading: #253
