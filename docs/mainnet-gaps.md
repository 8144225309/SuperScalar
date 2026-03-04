# Mainnet Readiness Gaps

Verified gaps between the current SuperScalar implementation and
mainnet-safe operation. Each item was checked against the codebase
to confirm it is real and unaddressed (or only partially addressed).

Status legend: **OPEN** = unaddressed, **PARTIAL** = partially mitigated,
**BY DESIGN** = accepted tradeoff for the prototype.

---

## Critical (must fix before mainnet funds)

### 1. UTXO Management — OPEN
The funding transaction is created by a single `bitcoin-cli createrawtransaction`
call with a hardcoded UTXO. No coin selection, no change output handling, no
multi-input support. A real deployment needs proper wallet-grade UTXO management
(coin selection heuristics, change derivation, consolidation).

**Files:** `tools/superscalar_lsp.c` (funding TX construction), `src/regtest.c`

### 2. RBF Fee Bumping on Funding TX — PARTIAL
Tree transactions have CPFP via P2A anchor outputs (`src/tx_builder.c`). However
the funding TX itself is created by `bitcoin-cli` and has no built-in RBF
or CPFP path. If the funding TX gets stuck, the operator can manually
`bitcoin-cli bumpfee`, but there is no automated retry or fee escalation.

**Mitigation:** Manual `bumpfee` via bitcoin-cli. Adequate for regtest/signet;
needs automation for mainnet.

### 3. External Watchtower — OPEN
The watchtower (`src/watchtower.c`) runs in-process, polling the same bitcoind.
A mainnet deployment needs an independent external watchtower service that
monitors for stale-state broadcasts even when the LSP is offline.

**Files:** `src/watchtower.c`, `include/superscalar/watchtower.h`

### 4. Single-Threaded Event Loop — OPEN
The LSP daemon (`src/lsp_channels.c`, `tools/superscalar_lsp.c`) uses a
single-threaded `select()` loop. With 4 clients this is fine; with hundreds
it becomes a bottleneck. Needs thread pool or async I/O (epoll/kqueue) for
mainnet scale.

**Files:** `src/lsp_channels.c` (event loop at ~L1760), `src/lsp_bridge.c`

### 5. nLockTime Anti-Fee-Sniping — FIXED
~~Cooperative close transactions used `nLockTime=0`, making them vulnerable
to fee sniping attacks.~~

Fixed: cooperative close now sets `nLockTime=current_height` (BIP
anti-fee-sniping). The LSP includes `current_height` in `CLOSE_PROPOSE`
so both parties build the same sighash. Tree node transactions correctly
use `nLockTime=0` (they rely on `nSequence`-based relative timelocks).

### 6. Hardcoded Limits — OPEN
Several constants are `#define`s that work for the prototype but need
per-deployment configuration for mainnet:

- `FACTORY_MAX_SIGNERS 16` / `FACTORY_MAX_NODES 64` / `FACTORY_MAX_LEAVES 16`
- `DUST_LIMIT_SATS 546` (could change with relay policy)
- `select()` FD ceiling (1024 on many systems)

**Files:** `include/superscalar/factory.h`, `src/factory.c`

### 7. Backup & Recovery — PARTIAL
Key material is persisted (`src/persist.c` — SQLite DB with keyfile,
channel state, factory metadata). However there is no encrypted backup
export, no seed-phrase-based recovery, and no remote backup protocol.
Loss of the SQLite DB means loss of channel state.

**Mitigation:** Keyfile + DB exist. Operator can back up the file.
Needs proper encrypted export and seed-based re-derivation for mainnet.

**Files:** `src/persist.c`, `include/superscalar/persist.h`

---

## Moderate (should fix, but non-blocking for testnet)

### 8. JSON Wire Protocol — OPEN
All wire messages are JSON over TCP (`src/wire.c`). This works but is:
- Verbose (wastes bandwidth vs. binary TLV)
- Parse-heavy (cJSON allocations per message)
- Not compatible with the BOLT wire format

Noise NK encryption is in place, so confidentiality is handled. But a
production protocol should use length-prefixed binary TLV (like BOLT #8).

**Files:** `src/wire.c`, `include/superscalar/wire.h`

---

## By Design (accepted tradeoffs)

### 9. No Onion Routing
Payments are forwarded via direct HTLC between LSP and clients. There
is no onion-routed multi-hop within the factory. This is by design:
the factory is a single-hop hub-and-spoke topology. Cross-factory
routing goes through the Lightning Network via the LSP's CLN node.

### 10. No BOLT #7 Gossip
Factory channels are off-chain constructs with no on-chain funding
output visible to the network. Standard BOLT #7 `channel_announcement`
requires an on-chain UTXO proof. Instead, the LSP generates synthetic
SCIDs (`factory_derive_scid`) and advertises route hints in BOLT #11
invoices, which is the correct approach for private/virtual channels.

### 11. BOLT #11 Invoice Encoding
Invoice creation is delegated to CLN (`lightning-cli invoice`). The
SuperScalar code provides the route hints (SCID + fee + CLTV) and CLN
handles encoding. This is the right division of labor — no need to
reimplement BOLT #11 encoding in C.

---

## Summary

| # | Gap                          | Status     | Mainnet Blocker? |
|---|------------------------------|------------|------------------|
| 1 | UTXO management              | OPEN       | Yes              |
| 2 | RBF fee bumping (funding TX) | PARTIAL    | No (manual ok)   |
| 3 | External watchtower          | OPEN       | Yes              |
| 4 | Single-threaded event loop   | OPEN       | Yes (at scale)   |
| 5 | nLockTime anti-fee-sniping   | **FIXED**  | —                |
| 6 | Hardcoded limits             | OPEN       | Yes (at scale)   |
| 7 | Backup & recovery            | PARTIAL    | Yes              |
| 8 | JSON wire protocol           | OPEN       | No (functional)  |
| 9 | Onion routing                | BY DESIGN  | No               |
| 10| BOLT #7 gossip               | BY DESIGN  | No               |
| 11| BOLT #11 encoding            | BY DESIGN  | No               |

**Mainnet blockers (must-fix):** #1, #3, #4 (at scale), #6 (at scale), #7

**Nice-to-have before mainnet:** #2 (automation), #8 (performance)

**Already handled:** #5 (fixed), #9-#11 (by design)
