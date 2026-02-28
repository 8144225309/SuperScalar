# Design Path Forward

Where we are, what we verified, what's broken, and what to build next.

Point-in-time snapshot from 2026-02-27 at commit `5366261`.

---

## Current State: Everything Passes

### Automated Tests

| Suite | Count | Result |
|-------|------:|--------|
| Unit tests (`--unit`) | 337 | 337/337 PASS |
| Regtest integration (`--regtest`) | 41 | 41/41 PASS |
| **Total automated** | **378** | **378/378 PASS** |

### Orchestrator Scenarios (20/20 PASS)

Multi-process adversarial tests using real Bitcoin Core regtest. Each scenario
launches separate LSP + client processes, creates a real factory on-chain, and
exercises a specific failure or lifecycle path.

| Scenario | What it tests | Result |
|----------|--------------|--------|
| `all_watch` | All 4 clients detect LSP breach via watchtower | PASS |
| `partial_watch` | 2/4 clients online detect breach, 2 offline miss it | PASS |
| `nobody_home` | All clients offline — breach goes undetected (expected) | PASS |
| `late_arrival` | Clients restart after breach, detect via watchtower DB | PASS |
| `cooperative_close` | Normal demo then cooperative close TX confirmed | PASS |
| `timeout_expiry` | All clients vanish, LSP reclaims via CLTV timeout | PASS |
| `factory_breach` | LSP broadcasts old factory tree, clients detect + respond | PASS |
| `jit_lifecycle` | Factory expires, JIT channels trigger, rotation managed | PASS |
| `factory_rotation` | Auto-rotation when factory enters DYING state | PASS |
| `timeout_recovery` | Demo payments then LSP timeout reclaim | PASS |
| `full_lifecycle` | Factory create → payments → watchtower → cooperative close | PASS |
| `ladder_breach` | DYING factory → rotation creates new factory → old expires | PASS |
| `turnover_abort` | Client killed mid-PTLC turnover, reconnects to finish | PASS |
| `lsp_crash_recovery` | LSP SIGKILL + restart with same DB, clients reconnect | PASS |
| `client_crash_htlc` | Client crashes during payment, LSP continues operating | PASS |
| `mass_departure_jit` | 3/4 clients vanish, remaining client still functional | PASS |
| `watchtower_late_arrival` | Breach confirmed while offline, clients detect on restart | PASS |
| `routing_fee` | Factory with routing fees; verify fee deduction in balances | PASS |
| `cli_payments` | Interactive CLI; pipe pay/status/close to LSP stdin | PASS |
| `profit_shared` | Profit-shared economics; fees accumulated + settled | PASS |

### LSP Test Flags (4/4 PASS)

End-to-end tests using dedicated LSP flags, each creating a real factory
with real Bitcoin transactions:

| Flag | What it tests | Result |
|------|---------------|--------|
| `--test-rotation` | PTLC key turnover → new factory creation → close old | PASS |
| `--test-distrib` | Mine past CLTV → broadcast pre-signed distribution TX | PASS |
| `--test-turnover` | Extract all 4 client keys via adaptor signatures | PASS |
| `--force-close` | Broadcast full factory tree (6 nodes), all confirmed | PASS |

---

## Bug Found & Fixed: NK/NN Noise Handshake Mismatch

### Root Cause

`superscalar_lsp.c:1168` unconditionally sets `lsp.use_nk = 1`, making the LSP
always perform a Noise NK (server-authenticated) handshake. But the orchestrator
and all three demo scripts never passed `--lsp-pubkey` to clients, so clients
attempted Noise NN (unauthenticated). NK and NN are incompatible Noise protocol
patterns — the first encrypted message after handshake is garbled, causing
`expected HELLO from client 0` / `expected HELLO_ACK` failures.

### Impact

All multi-process demos and all 17 orchestrator scenarios were silently broken.
The 41 regtest integration tests were unaffected because they use in-process
function calls (no actual TCP connections or Noise handshakes).

### Fix (commit `5366261`)

Added a deterministic LSP seckey (`01` — the secp256k1 generator key) and its
known compressed pubkey to all 4 tool scripts. The LSP gets `--seckey`, clients
get `--lsp-pubkey`. This matches the pattern already used by
`test_bridge_regtest.sh` (the only script that was doing NK correctly).

| File | Change |
|------|--------|
| `tools/test_orchestrator.py` | Added `LSP_SECKEY`/`LSP_PUBKEY` constants; pass `--seckey` to LSP, `--lsp-pubkey` to clients |
| `tools/run_demo.sh` | Added `LSP_SECKEY`/`LSP_PUBKEY`; pass to LSP and all client invocations |
| `tools/demo.sh` | Same pattern |
| `tools/manual_demo.sh` | Same pattern |

### Lesson

The regtest test suite tests protocol logic thoroughly but doesn't exercise
the Noise transport layer because it runs everything in-process. Any feature
that only manifests in real TCP connections (Noise handshake, reconnection
timing, port binding) needs multi-process testing. The orchestrator fills
this gap — but only if it's actually runnable.

---

## Complete Feature Coverage Matrix

### Legend

- **Y** = tested at this level
- **-** = not tested at this level
- **Gap**: No = full coverage, Low = unit-tested but no e2e, **YES** = real gap

### Core Protocol

| Feature | Unit | Regtest | Orchestrator | Manual Flag | Gap |
|---------|:----:|:-------:|:------------:|:-----------:|:---:|
| Factory creation (5-of-5 MuSig2) | Y | Y | Y | - | No |
| DW state advance (epoch cycling) | Y | Y | Y | - | No |
| Cooperative close | Y | Y | Y | - | No |
| Force close (broadcast tree) | Y | Y | - | Y | No |
| CLTV timeout reclaim | Y | Y | Y | Y | No |
| Distribution TX fallback | Y | Y | - | Y | No |
| PTLC key turnover (adaptor sigs) | Y | Y | - | Y | No |
| Factory rotation (full lifecycle) | Y | Y | Y | Y | No |
| Factory ladder (multi-factory) | Y | Y | Y | - | No |
| Partial rotation (3/4 clients) | Y | Y | - | - | No |
| Partial rotation (2/4 clients) | Y | - | - | - | Low |
| Epoch reset (cooperative) | Y | Y | - | - | No |
| Path-scoped signing | Y | - | - | - | Low |

### Channels & Payments

| Feature | Unit | Regtest | Orchestrator | Manual Flag | Gap |
|---------|:----:|:-------:|:------------:|:-----------:|:---:|
| HTLC add/fulfill/fail | Y | Y | Y | - | No |
| Commitment signing | Y | Y | Y | - | No |
| Revocation exchange | Y | Y | Y | - | No |
| Breach detection (LSP-side) | Y | Y | Y | - | No |
| Breach detection (client-side) | Y | Y | Y | - | No |
| Watchtower (mempool monitoring) | Y | Y | Y | - | No |
| Watchtower (late detection) | Y | Y | Y | - | No |
| CPFP penalty bump | Y | Y | - | - | No |
| Routing fee (ppm = 0, default) | Y | Y | Y | - | No |
| Routing fee (ppm > 0) | Y | - | Y | - | No |
| LSP balance % = 50 (default) | Y | Y | Y | - | No |
| LSP balance % != 50 | Y | - | - | - | Low |

### JIT Channel Fallback

| Feature | Unit | Regtest | Orchestrator | Manual Flag | Gap |
|---------|:----:|:-------:|:------------:|:-----------:|:---:|
| JIT offer/accept/ready | Y | Y | Y | - | No |
| JIT channel migration | Y | Y | - | - | No |
| JIT routing (factory unavailable) | Y | Y | Y | - | No |
| JIT watchtower integration | Y | Y | - | - | No |
| JIT persistence | Y | Y | - | - | No |
| `--no-jit` disable flag | Y | - | - | - | Low |
| Offline detection (120s timeout) | Y | Y | Y | - | No |

### Crash Recovery & Resilience

| Feature | Unit | Regtest | Orchestrator | Manual Flag | Gap |
|---------|:----:|:-------:|:------------:|:-----------:|:---:|
| LSP crash + restart (same DB) | Y | Y | Y | - | No |
| Client crash during payment | - | Y | Y | - | No |
| Client reconnection (5s retry) | - | Y | Y | - | No |
| Mass client departure (3/4) | - | - | Y | - | No |
| Nonce pool crash safety | Y | Y | - | - | No |
| Persistence round-trip | Y | Y | Y | - | No |

### Network & Security

| Feature | Unit | Regtest | Orchestrator | Manual Flag | Gap |
|---------|:----:|:-------:|:------------:|:-----------:|:---:|
| Network: regtest | Y | Y | Y | Y | No |
| Network: signet | - | - | - | - | **YES** |
| Network: testnet | - | - | - | - | **YES** |
| Network: mainnet | - | - | - | - | (intentional) |
| Noise NN handshake | Y | - | - | - | Low |
| Noise NK handshake | Y | Y | Y | - | No |
| Encrypted keyfile (AES-256-GCM) | Y | - | - | - | Low |
| Tor hidden service (`--onion`) | - | - | - | - | Low |
| Tor proxy (`--tor-proxy`) | Y | - | - | - | Low |

### CLN Bridge

| Feature | Unit | Regtest | Orchestrator | Manual Flag | Gap |
|---------|:----:|:-------:|:------------:|:-----------:|:---:|
| Bridge handshake (NN + NK) | Y | Y | - | - | No |
| Inbound payment (LN → factory) | Y | Y | - | - | Low |
| Outbound payment (factory → LN) | Y | Y | - | - | Low |
| Invoice registry | Y | Y | - | - | No |
| HTLC origin tracking | Y | Y | - | - | No |
| Multi-hop routing | - | - | - | - | **YES** |

### Configuration Modes

| Feature | Unit | Regtest | Orchestrator | Manual Flag | Gap |
|---------|:----:|:-------:|:------------:|:-----------:|:---:|
| Placement: sequential (default) | Y | Y | Y | - | No |
| Placement: inward | Y | - | - | - | Low |
| Placement: outward | Y | - | - | - | Low |
| Economic: lsp-takes-all (default) | Y | Y | Y | - | No |
| Economic: profit-shared | Y | - | Y | - | No |
| Arity: 2 (default, paired leaves) | Y | Y | Y | - | No |
| Arity: 1 (single client per leaf) | Y | Y | - | - | Low |
| Large factory (N = 8, 12, 16) | Y | - | - | - | Low |
| Daemon mode | - | Y | Y | - | No |
| Demo mode | - | Y | Y | Y | No |
| Interactive CLI (`--cli`) | - | - | Y | - | No |
| Settlement interval tuning | Y | - | - | - | Low |

---

## Real Gaps: What Needs Work

These features have no end-to-end coverage. They either lack integration tests
entirely or have only unit-level math tests with no multi-process verification.

### 1. Interactive CLI (`--cli`) — CLOSED

**Status:** Orchestrator scenario `cli_payments` pipes `status`, `pay`, and
`close` commands to LSP stdin and verifies each is processed.

### 2. Routing Fees (ppm > 0) — CLOSED

**Status:** Orchestrator scenario `routing_fee` starts LSP with
`--routing-fee-ppm 100` and verifies fee deduction evidence in logs/report.

### 3. Profit-Shared Economics — CLOSED

**Status:** Orchestrator scenario `profit_shared` runs LSP in profit-shared
mode with short settlement interval and verifies settlement/fee evidence.

### 4. Signet / Testnet

**Status:** The code handles non-regtest networks (different CLTV defaults,
different timing constants, real block waiting). The orchestrator supports
`--network signet`. But no CI or automated test runs on these networks.

**What's missing:** A slow CI job (or manual script) that runs
`cooperative_close` on signet. This would verify:
- Real wallet funding (faucet or pre-funded)
- Real block timing (~10 min)
- Real confirmation waiting
- Real CLTV timeout calculation

**Effort:** Medium. The orchestrator already supports `--network signet`. The
blockers are: (a) signet wallet must be pre-funded, (b) runs take 30+ minutes.

### 5. Tor Integration — PARTIALLY CLOSED

**Status:** Unit tests exist for `tor_parse_proxy_arg()` (normal + edge cases)
and a SOCKS5 mock server test in `test_bridge.c`. Full integration (Tor daemon
+ hidden service creation + routed payment) still needs a Docker container.

### 6. Multi-Hop Lightning

**Status:** The bridge handles one hop: CLN node → bridge → LSP → factory
client (inbound) and reverse (outbound). Multi-hop routing through multiple
LSPs or across the broader Lightning Network is not implemented.

**What's missing:** This is a protocol-level gap, not just a testing gap. The
current design assumes a single LSP with direct bridge connectivity. Multi-hop
would require route finding, onion routing, and HTLC forwarding across LSPs.

**Effort:** Very high. This is future protocol work, not just test infrastructure.

---

## Low-Priority Gaps: Unit-Tested but Not End-to-End

These features work correctly in isolation (verified by unit tests) but lack
multi-process integration coverage. They're lower risk because the unit tests
exercise the actual code paths — the gap is only that we haven't verified them
through real TCP/Noise connections.

| Feature | Risk | Why it's low-risk |
|---------|------|-------------------|
| Placement inward/outward | Low | Sort function is tested; tree structure is identical regardless of client order |
| Arity-1 trees | Low | 15+ unit tests + regtest coverage; just not in orchestrator |
| `--no-jit` flag | Low | Disabling JIT is just skipping the JIT init path |
| Noise NN handshake | Low | NN is strictly simpler than NK; if NK works, NN's crypto works too |
| Large factories (N > 4) | Medium | Unit tests go up to N=16; signing complexity scales but is mathematically identical |
| Encrypted keyfile | Low | AES-256-GCM tested; the file I/O wrapper is trivial |
| Partial rotation (2/4) | Low | 3/4 is tested in regtest; 2/4 uses the same code path with different threshold |
| Path-scoped signing | Medium | Optimizes signing for subtree-only re-signing; unit-tested but not exercised in real factories |
| Tor proxy (SOCKS5) | Low | tor_parse_proxy_arg + SOCKS5 mock tested in test_bridge.c |
| Tor hidden service | Medium | tor_create_hidden_service untested; needs live Tor daemon |

---

## Orchestrator Improvements — COMPLETED

### Auto-Fund Wallet — DONE

`Orchestrator.__init__` now auto-funds both `orchestrator` and
`superscalar_lsp` wallets when running on regtest. No manual wallet setup
required.

### Demo Script RPC Auth — DONE

All three demo scripts (`demo.sh`, `run_demo.sh`, `manual_demo.sh`) now accept
`RPCUSER` and `RPCPASSWORD` environment variables. When set, these are injected
into all `bitcoin-cli` calls and forwarded to LSP/client invocations.

### CRLF Line Endings — DONE

`.gitattributes` enforces LF line endings for `*.sh`, `*.py`, `*.yml`, `*.yaml`,
`*.json`, `*.md`, `*.c`, and `*.h` files.

---

## Wire Protocol Summary (53 Messages)

For reference — the complete wire protocol as of this snapshot:

| Category | Messages | IDs |
|----------|----------|-----|
| Handshake | HELLO, HELLO_ACK | 0x01-0x02 |
| Factory Setup | FACTORY_PROPOSE, NONCE_BUNDLE, ALL_NONCES, PSIG_BUNDLE, FACTORY_READY | 0x10-0x14 |
| Cooperative Close | CLOSE_PROPOSE, CLOSE_NONCE, CLOSE_ALL_NONCES, CLOSE_PSIG, CLOSE_DONE | 0x20-0x24 |
| Channel Ops | CHANNEL_READY, UPDATE_ADD_HTLC, COMMITMENT_SIGNED, REVOKE_AND_ACK, UPDATE_FULFILL_HTLC, UPDATE_FAIL_HTLC, CLOSE_REQUEST, CHANNEL_NONCES, REGISTER_INVOICE | 0x30-0x38 |
| Bridge | BRIDGE_HELLO, BRIDGE_HELLO_ACK, BRIDGE_ADD_HTLC, BRIDGE_FULFILL_HTLC, BRIDGE_FAIL_HTLC, BRIDGE_SEND_PAY, BRIDGE_PAY_RESULT | 0x40-0x46 |
| Reconnection | RECONNECT, RECONNECT_ACK | 0x48-0x49 |
| Invoice | CREATE_INVOICE, INVOICE_CREATED | 0x4A-0x4B |
| PTLC Turnover | PTLC_PRESIG, PTLC_ADAPTED_SIG, PTLC_COMPLETE | 0x4C-0x4E |
| Basepoints | CHANNEL_BASEPOINTS | 0x4F |
| LSP Revocation | LSP_REVOKE_AND_ACK | 0x50 |
| JIT Channel | JIT_OFFER, JIT_ACCEPT, JIT_READY, JIT_MIGRATE | 0x51-0x54 |
| Epoch Reset | EPOCH_RESET_PROPOSE, EPOCH_RESET_PSIG, EPOCH_RESET_DONE | 0x55-0x57 |
| Per-Leaf Advance | LEAF_ADVANCE_PROPOSE, LEAF_ADVANCE_PSIG, LEAF_ADVANCE_DONE | 0x58-0x5A |
| Path-Scoped Signing | PATH_NONCE_BUNDLE, PATH_ALL_NONCES, PATH_PSIG_BUNDLE, PATH_SIGN_DONE | 0x60-0x63 |
| Error | ERROR | 0xFF |

---

## Persistence Schema (27 Tables)

The SQLite persistence layer stores everything needed for crash recovery:

- Factory state (nodes, DW counter, shachain seeds, revocation secrets, lifecycle)
- Channel state (local/remote amounts, commitment number, HTLCs, basepoints)
- Watchtower entries (old commitments for breach detection)
- JIT channels (state, funding txid, migration target)
- Nonce pool (prevents duplicate signing after restart)
- Wire message audit log
- Profit settlement ledger
- Client invoice store (payment_hash → preimage)
- HTLC origin tracking (bridge correlation)

---

## Architecture: What's Proven vs Theoretical

### Proven (tested end-to-end with real Bitcoin transactions)

- N+1-of-N+1 MuSig2 cooperative signing (5-of-5 factory)
- Decker-Wattenhofer state machine (2-layer, 4 states per layer)
- Factory tree construction (kickoff → state layers → leaf channels)
- HTLC forwarding between factory clients
- Cooperative close (single on-chain TX recovers all funds)
- Force close (broadcast full tree, wait for relative timelocks)
- Breach detection + penalty (both LSP-side and client-side)
- PTLC key turnover via adaptor signatures (extract all client keys)
- Factory ladder rotation (ACTIVE → DYING → new factory → close old)
- JIT channel fallback (fund individual channels when factory unavailable)
- Crash recovery (LSP and client restart with persistent DB)
- Encrypted transport (Noise NK with pinned server pubkey)
- Bridge to CLN (inbound + outbound Lightning payments)
- Profit-shared economics (orchestrator scenario with settlement verification)
- Interactive CLI (orchestrator scenario piping stdin commands)
- Routing fee deduction (orchestrator scenario with ppm > 0)

### Partially Proven (unit-tested logic, not full e2e)

- Placement optimization (inward/outward sort functions work)
- Large factories (N=16 tree construction works)
- Arity-1 trees (single client per leaf, 3 DW layers)
- Epoch reset (cooperative DW counter reset)
- Path-scoped signing (subtree-only re-signing optimization)
- Tor SOCKS5 proxy (unit-tested parse + mock; no live Tor daemon)

### Not Yet Tested

- Signet/testnet operation (real block timing, real faucet funding)
- Tor hidden services (onion address creation via control port)
- Multi-hop Lightning routing (beyond single bridge hop)

---

## Recommended Next Steps (Priority Order)

### Completed

1. ~~**Add `.gitattributes`**~~ — DONE
2. ~~**Orchestrator auto-fund**~~ — DONE
3. ~~**Routing fee e2e test**~~ — DONE (`routing_fee` scenario)
4. ~~**CLI stdin test**~~ — DONE (`cli_payments` scenario)
5. ~~**Demo script RPC auth**~~ — DONE (env var support in all 3 scripts)
6. ~~**Profit-shared scenario**~~ — DONE (`profit_shared` scenario)
7. ~~**Docker image**~~ — DONE (Dockerfile + docker-compose.yml + entrypoint)
8. ~~**Tor unit tests**~~ — DONE (parse_proxy_arg + SOCKS5 mock in test_bridge.c)

### Short-term (1-3 days each)

1. **Signet smoke test** — slow CI job running `cooperative_close` on signet

### Completed

2. ~~**Fuzz testing**~~ — DONE (5 libFuzzer harnesses + CI job)
3. ~~**Coverage measurement**~~ — DONE (`ENABLE_COVERAGE` cmake option + CI artifact)
4. ~~**Bridge end-to-end**~~ — DONE (CI regtest job with Bitcoin Core)
5. ~~**Property-based testing**~~ — DONE (10 property tests with random inputs)
6. ~~**Tor full integration**~~ — DONE (`--tor-only`, `--bind`, `--tor-password-file` + 5 unit tests)
7. ~~**Bridge reliability**~~ — DONE (heartbeat, reconnect, stale detection)

### Long-term (1+ month)

8. **Multi-hop routing** — protocol-level work for cross-LSP payments
9. **Pre-built release binaries** — CI workflow for Linux/macOS/Windows artifacts
10. **Signet long-running test** — factory that lives through multiple rotation cycles

---

## Test Infrastructure Summary

| Layer | Tool | Count | Runtime |
|-------|------|------:|---------|
| Unit | `test_superscalar --unit` | 337 | ~2 seconds |
| Regtest | `test_superscalar --regtest` | 41 | ~60 seconds |
| Orchestrator | `test_orchestrator.py --scenario all` | 20 | ~18 minutes |
| LSP flags | Manual (rotation, distrib, turnover, force-close) | 4 | ~5 minutes |
| Demo scripts | `run_demo.sh --basic/--breach/--rotation` | 3 | ~3 minutes |
| CI | GitHub Actions (Linux + macOS + sanitizers + cppcheck + regtest + coverage + fuzz) | 7 jobs | ~10 minutes |
| Docker | `docker run superscalar unit/test/demo` | 3 modes | varies |
| **Total** | | **387+** | **~28 minutes** |
