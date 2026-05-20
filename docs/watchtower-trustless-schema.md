# Watchtower trustless schema design

**Status:** Design draft. Tracked as SF-WT-TRUSTLESS (mainnet-blocker per
issue #289 §6).
**Goal:** WT process literally cannot read penalty/revocation secrets,
even if compromised or running on hostile hardware.

## The problem today

The standalone watchtower (`superscalar_watchtower`) opens the **LSP's
SQLite database** read-only:

```
tools/superscalar_watchtower.c:30:  --db PATH  SQLite database (read-only) shared with LSP
tools/superscalar_watchtower.c:106: persist_open(&db, db_path);
```

The LSP DB contains secret columns the WT does NOT need:

- `channels.revocation_secret`  (32 bytes, per-channel)
- `signing_rounds.partial_signature`  (per-round, 36 bytes)
- `ceremony_participants.revocation_secret`  (32 bytes, per participant)
- `client_ps_signed_inputs.partial_sig`  (36 bytes, per leaf)
- `factory_node` material that would allow re-signing state

A compromised WT binary, a malicious operator at the WT host, or anyone
with shell access to the WT process can `sqlite3 lsp.db ".dump"` and
extract all secrets. The WT having READ access today implicitly trusts
the WT host with everything the LSP holds.

This violates the design principle stated in `docs/pseudo-spilman.md`:
the WT exists to broadcast pre-signed response TXs on observation, not
to hold key material.

## The trustless model

WT process needs ONLY:

1. **Watch targets**: `(outpoint, scriptpubkey)` it should monitor for spends.
2. **Pre-signed response TXs**: raw signed TX hex to broadcast on observation.
3. **Fee-bump policy** (CPFP/RBF anchor): the bump-budget metadata.
4. **Health log**: heartbeats + reorg events + broadcast outcomes (write-only).

WT process MUST NOT have:

- Any column readable by sqlite3 that yields a 32-byte secret.
- Any path that lets the WT sign a new TX.
- Any ability to claim funds.

## Architecture — separate DB file

Cleanest: split into TWO SQLite files.

```
/var/lib/lsp/                                   /var/lib/wt/
├── lsp.db          (LSP-owned, secrets)        └── watchtower.db   (WT-owned, no secrets)
├── lsp.db-wal                                       wt_watches
└── lsp.db-shm                                       wt_responses
                                                     wt_health
                                                     wt_meta
                          ^                                 ^
                          |                                 |
                          +-------- LSP writes -------------+
                                     (one-way; WT never reads lsp.db)
```

The LSP, on each ceremony completion or state advance, derives the
trustless entries and writes them into `watchtower.db`. The WT process
opens `watchtower.db` exclusively and never sees `lsp.db`.

## Schema (proposed v36)

```sql
-- Outpoints + scriptpubkeys the WT watches for chain spends.
-- Updated by LSP after each ceremony advance; the response_tx points
-- to wt_responses for the pre-signed broadcast.
CREATE TABLE wt_watches (
    watch_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    factory_id        INTEGER NOT NULL,         -- opaque LSP-side handle
    parent_txid       BLOB NOT NULL,            -- 32 bytes
    parent_vout       INTEGER NOT NULL,
    parent_value_sat  INTEGER NOT NULL,
    parent_spk        BLOB NOT NULL,            -- the scriptpubkey to watch
    csv_delay         INTEGER NOT NULL,         -- how many blocks after spend before stale-state validity opens
    response_id       INTEGER NOT NULL,         -- FK to wt_responses
    superseded_at     INTEGER,                  -- non-null = this entry no longer canonical (chain advanced)
    registered_at     INTEGER NOT NULL DEFAULT (strftime('%s','now')),

    FOREIGN KEY (response_id) REFERENCES wt_responses(response_id)
);

-- Pre-signed response TXs. The TX is fully signed offline by the LSP
-- using key material that lives ONLY in lsp.db. The hex stored here is
-- what the WT calls sendrawtransaction with — no signing happens in WT.
CREATE TABLE wt_responses (
    response_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    response_tx_hex   TEXT NOT NULL,            -- fully signed, ready for sendrawtransaction
    response_txid     BLOB NOT NULL,            -- 32 bytes, derived from hex; indexed
    fee_bump_anchor   BLOB,                     -- pre-signed CPFP child TX hex if applicable
    fee_bump_budget   INTEGER NOT NULL DEFAULT 0, -- max sats LSP authorized for fee escalation
    fee_bump_deadline INTEGER NOT NULL DEFAULT 0  -- absolute block height
);
CREATE INDEX wt_responses_txid_idx ON wt_responses(response_txid);

-- Observability + broadcast journal. Write-only from WT.
CREATE TABLE wt_responses_broadcast (
    broadcast_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    watch_id          INTEGER NOT NULL,
    observed_spend_txid    BLOB NOT NULL,      -- the on-chain spend that triggered
    observed_at_height     INTEGER NOT NULL,
    response_broadcast_txid BLOB,              -- our response TX as it landed
    response_broadcast_at  INTEGER,
    broadcast_result       TEXT NOT NULL,      -- 'sent' | 'rejected' | 'replaced' | 'confirmed'
    bitcoind_error         TEXT,               -- non-null if 'rejected'

    FOREIGN KEY (watch_id) REFERENCES wt_watches(watch_id)
);

-- WT process health. Read by dashboard; written by WT every poll interval.
CREATE TABLE wt_health (
    heartbeat_at      INTEGER PRIMARY KEY,     -- unix ts
    chain_height      INTEGER NOT NULL,
    n_active_watches  INTEGER NOT NULL,
    last_reorg_at     INTEGER,                 -- nullable
    last_reorg_depth  INTEGER
);

-- Schema metadata.
CREATE TABLE wt_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT INTO wt_meta (key, value) VALUES ('schema_version', '36');
INSERT INTO wt_meta (key, value) VALUES ('lsp_pubkey_authoritative', '<hex>');
```

**No column in `watchtower.db` is a secret.** Verifying: `parent_txid`,
`parent_vout`, `parent_value_sat`, `parent_spk` are all already on-chain
once the parent confirms. `response_tx_hex` is a pre-signed TX —
revealed in mempool the moment WT broadcasts it. `csv_delay` is public.
Fee-bump metadata is non-secret operational policy.

## Hand-off mechanism — LSP writes into watchtower.db

Two viable paths:

### Path A: LSP opens watchtower.db with write perms

The LSP holds a writer handle to `watchtower.db` alongside `lsp.db`.
After each ceremony completion (`lsp_run_factory_creation`,
`lsp_run_factory_rotation`, `lsp_subfactory_chain_advance`, etc.) it
derives the watchable entries and INSERTs them. The WT opens
`watchtower.db` read-only.

Pros: simplest; no extra process; transactional w/ LSP state if WT DB
opens both files in the same SQLite session via ATTACH.

Cons: LSP needs write perms on the WT DB path. If LSP host and WT host
are separate (the eventual deployment model), this needs a delivery
mechanism.

### Path B: hand-off over the plugin protocol

The CLN plugin (when SuperScalar runs as a plugin) writes the watchable
entries via an RPC the WT side serves. Decouples LSP host from WT host.

Path A is right for v0.2; Path B is the eventual plugin-architecture
target.

## Migration

1. `persist_v36_create_watchtower_db()` — creates `watchtower.db` if
   missing, runs the CREATE TABLE DDL above.
2. `persist_v36_derive_wt_from_lsp(lsp_db, wt_db)` — one-shot tool that
   reads existing `force_close_watches` / `watchtower_pending` rows from
   `lsp.db` and re-emits them into `wt_watches` + `wt_responses`. Run
   once per existing channel to bring the new model up to date with
   live deployments.
3. `superscalar_watchtower --wt-db <path>` — new CLI flag. Old `--db
   <lsp_db_path>` deprecated with a warning that points at this doc.
4. Drop the `watchtower_keys` table from `lsp.db` (no longer needed).
5. Drop `persist_load_channel_for_watchtower`, `persist_load_revocations_flat`
   from the WT side — these were the leaky reads.

## Threat-model contrast

| Adversary action | Today | Post-trustless |
|---|---|---|
| `sqlite3 wt.db ".dump"` on WT host | Reveals every revocation secret + partial sig | Reveals only outpoints + pre-signed response TXs (all eventually public on chain) |
| Compromised WT binary | Can sign new state, extract funds | Can broadcast a (legitimate) response TX or refuse to; cannot derive new TXs |
| WT host stolen | Channel keys exfil | No key material; attacker gains nothing the chain doesn't already expose |
| WT process refuses to broadcast | Same fault tolerance | Same; user can run >1 WT against same `watchtower.db` for redundancy |

## What this does NOT solve

- **WT availability**: a WT that refuses to broadcast is still bad. The
  user must run >1 WT, or accept the risk. Trustless schema doesn't
  fix this — separate concern.
- **Operator securing lsp.db**: LSP DB still has all the secrets. The
  operator must still LUKS-encrypt the LSP host and follow the runbook.
  This change only firewalls off the WT host as a smaller-trust
  surface.
- **Chain-side observation primitive**: the WT still uses BIP-157/158
  or RPC scanning to detect spends. That's orthogonal to schema.

## Phasing

### Phase 1 — schema + LSP-side write (this PR after design freeze)
- Add `wt_watches`/`wt_responses`/`wt_responses_broadcast`/`wt_health`/`wt_meta` to a NEW DB file
- LSP-side helper: `persist_wt_register(wt_db, factory_id, parent_outpoint, parent_spk, csv_delay, response_tx_hex, fee_bump_meta)`
- LSP calls this after each ceremony advance
- Old `watchtower_pending` table in `lsp.db` kept temporarily for backward compat
- New `superscalar_watchtower --wt-db <path>` flag, falls back to `--db` with deprecation warning

### Phase 2 — WT-side reads switch over (next PR)
- `superscalar_watchtower` refactor: stop opening `lsp.db`; open only `watchtower.db`
- Drop `persist_load_force_close_watches`, `persist_load_channel_for_watchtower`,
  `persist_load_revocations_flat` from the watchtower binary's link set
- Verification step: launch a regtest end-to-end with `sqlite3 lsp.db
  "SELECT count(*) FROM channels WHERE revocation_secret IS NOT NULL;"`
  and `sqlite3 wt.db "SELECT count(*) FROM sqlite_master WHERE sql LIKE '%secret%';"` —
  expect non-zero LSP, zero WT.

### Phase 3 — drop legacy WT tables from lsp.db (cleanup PR)
- Drop `watchtower_keys`, `watchtower_pending` from `lsp.db`
- Schema migration `v36 -> v37`: DROP TABLE
- All references in code already removed by Phase 2

### Phase 4 — regtest test: trustless invariant
- `tools/test_regtest_watchtower_trustless.sh` — boots LSP + WT (separate DBs),
  runs full cheat-engine breach scenario, asserts:
  - WT broadcasts response TX successfully
  - `sqlite3 watchtower.db ".dump"` contains no row where a 32-byte BLOB matches
    a known revocation/channel secret from `lsp.db`
- Add to `tests/test_regtest_*.sh` battery, gate the trustless-schema PR on it
  passing.

## Definition of done

1. Schema v36 ships with `wt_watches`, `wt_responses`, `wt_responses_broadcast`,
   `wt_health`, `wt_meta` in a separate `watchtower.db` file.
2. `superscalar_watchtower --wt-db <path>` works end-to-end on regtest cheat-engine.
3. `superscalar_watchtower --db <lsp.db>` deprecated; warns and exits.
4. Phase 4 regtest test PASSES: dumping `watchtower.db` reveals zero secrets.
5. Issue #289 §6 checkbox flips ☑.

## Out of scope (for this design)

- Phase 5 testnet4 validation (separate effort; runs as part of v0.2
  campaign once the schema lands)
- Plugin RPC hand-off (path B above) — v0.3 work
- Multi-WT redundancy/quorum — separate design
- Hardware-key signing by LSP — not in WT's scope

## References

- `docs/pseudo-spilman.md` §watchtower — original design intent
- `docs/mainnet-runbook.md` §10 #6 — runbook gate item
- Issue #289 §6 — mainnet-key-architecture umbrella
- `src/persist.c:179, 317, 321, 1271` — current secret-bearing columns
- `src/watchtower.c:238` — current `persist_load_force_close_watches` callsite
- `tools/superscalar_watchtower.c:30, 106` — current `--db <lsp.db>` open
