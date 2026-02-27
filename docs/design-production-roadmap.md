# SuperScalar: Production Roadmap — From Prototype to Long-Running Factory

> **Version 3** — updated after implementing Tier 1-2 items and interactive CLI.
> Items 1, 5, and 8 are complete. Protocol bug found and fixed during item 1.

## Current State (2026-02-27)

360 tests (319 unit + 41 regtest), all passing. The cryptographic protocol
is correct. The factory lifecycle works end-to-end on regtest with real
Bitcoin transactions. TCP reconnection proven over real network. Rotation
retry with backoff prevents fund lockup. Interactive CLI enables daemon-mode
demos without scripted sequences.

---

## Assumption Validation

Before planning, we traced every claim to source code. Results:

| # | Original Claim | Verdict | Evidence |
|---|----------------|---------|----------|
| 1 | Only LSP can initiate payments | **WRONG** | Clients send MSG_UPDATE_ADD_HTLC with dest_client field; LSP forwards (lsp_channels.c:484-600) |
| 2 | No test runs >1 payment cycle | **WRONG** | test_regtest_multi_payment runs 4 payments in one event loop (test_channels.c:934) |
| 3 | PTLC failure → stuck, no retry | ~~Correct~~ **FIXED** | Rotation retry with exponential backoff + distribution TX fallback (lsp_rotation.c) |
| 4 | TCP reconnection never tested | ~~Correct~~ **FIXED** | test_regtest_tcp_reconnect: real TCP, SIGKILL, Noise NN reconnect, state verified |
| 5 | Bridge persistence doesn't exist | **WRONG** | persist_save_invoice() and persist_save_htlc_origin() exist and are called (persist.h:256-283) |
| 6 | Dynamic client entry unsupported | **Correct** | Factory n_participants fixed at creation; no add-participant API |
| 7 | Offline detection never tested | **WRONG** | test_last_message_time_update and test_offline_detection_flag exist (test_jit.c:42-79) |
| 8 | JIT never tested with daemon trigger | ~~Correct~~ **FIXED** | JIT daemon trigger tested via orchestrator `jit_lifecycle` scenario |
| 9 | No soak/long-running test | **Correct** | All tests complete in ≤500ms; no multi-second test exists |
| 10 | Waiting room needs new factory | **Correct** | MuSig2 aggregation immutable after creation; tree cannot add signers |

---

## What Works End-to-End (Regtest-Proven)

Tested with real Bitcoin transactions and/or real TCP between processes:

- Factory creation over TCP (5-of-5 MuSig2, forked client processes)
- Multi-payment sequences (4 payments, real preimage validation, balance tracking)
- Cooperative close (single on-chain tx)
- Breach detection + penalty (LSP-side and client-side watchtowers)
- PTLC key turnover via adaptor signatures
- Crash recovery (LSP restart from DB, clients reconnect — tested twice)
- DW state exhaustion (graceful degradation, coop close still works)
- HTLC timeout/success paths (both resolution paths on real chain)
- Penalty with active HTLCs (sweep to_local + HTLC outputs)
- Mempool breach detection (pre-confirmation)
- Distribution TX fallback (nLockTime, all-offline recovery)
- Bridge NK handshake + bridge payment over TCP
- CPFP penalty fee bumping with P2A anchors
- Client-initiated payments (client sends ADD_HTLC to LSP, LSP routes)
- Bridge invoice/HTLC origin persistence (survives crashes)
- Offline detection (120s timeout, unit-tested)
- **TCP reconnection** (SIGKILL client, reconnect over real TCP, state verified)
- **Rotation retry with backoff** (exponential delay, distribution TX fallback after 3 failures)
- **Interactive CLI** (pay/status/rotate/close commands via stdin in daemon loop)

## Confirmed Gaps (Remaining)

| Gap | Severity | Status |
|-----|----------|--------|
| ~~PTLC rotation failure → factory stuck~~ | ~~High~~ | **FIXED** — retry with exponential backoff + dist TX fallback |
| ~~TCP reconnection never integration-tested~~ | ~~High~~ | **FIXED** — test_regtest_tcp_reconnect (real TCP, SIGKILL, Noise NN) |
| ~~No interactive CLI~~ | ~~Low~~ | **FIXED** — `--cli` flag, pay/status/rotate/close in daemon loop |
| ~~JIT daemon trigger path untested~~ | ~~Medium~~ | **FIXED** — orchestrator `jit_lifecycle` scenario exercises daemon→factory_expired→JIT path |
| Dynamic client entry impossible | Medium | Factory tree immutable; new clients must wait for next factory |
| No soak/stress test | Medium | Longest test is 500ms; no multi-minute or multi-hour runs |
| Daemon loop integration test | Medium | Each feature unit-tested; never tested together in daemon context |
| No external API/RPC | Low | Wire protocol + SQLite + CLI only; no JSON-RPC or socket interface |
| Ladder over wire never tested | Low | Ladder regtest tests are in-process, not forked TCP |

### Protocol Bug Found and Fixed

During TCP reconnection test development, a protocol ordering mismatch was
discovered in `client_run_reconnect()`:

- **LSP sends:** MSG_RECONNECT (recv) → CHANNEL_NONCES (send) → CHANNEL_NONCES (recv) → RECONNECT_ACK (send)
- **Client expected:** MSG_RECONNECT (send) → RECONNECT_ACK (recv) → ... → CHANNEL_NONCES (recv)

The client expected ACK before nonces, but the LSP sends nonces first.
This was masked by unit tests that used socketpair with the correct order.
Fixed by reordering client_run_reconnect() to match the LSP's actual
protocol: Send RECONNECT → Load basepoints → Init channel → Recv NONCES →
Send NONCES → Recv ACK.

---

## Items REMOVED From Roadmap

| Cut Item | Why |
|----------|-----|
| ~~B1. MSG_PAY_REQUEST~~ | **Already works.** Clients send MSG_UPDATE_ADD_HTLC with dest_client. No new message needed. |
| ~~A2. Wire-level payment test~~ | **Already exists.** test_regtest_multi_payment runs 4 client-to-client payments over wire. |
| ~~D2. Bridge persistence~~ | **Already exists.** persist_save_invoice() and persist_save_htlc_origin() are called and tested. |
| ~~Phase B: Client-Initiated Payments~~ | **Already works.** The entire Phase B premise was wrong. |

---

## Completed Items

### ✓ Item 1: TCP reconnection integration test

`test_regtest_tcp_reconnect` in test_channels.c:
- Forks 4 clients connected via real TCP
- Runs 1 payment (ADD_HTLC + FULFILL_HTLC)
- Kills client B with SIGKILL (real TCP close, FIN/RST)
- Forks new reconnect child with same key
- Reconnect child: wire_connect → Noise NN → MSG_RECONNECT → CHANNEL_NONCES exchange → RECONNECT_ACK
- LSP: accept → Noise HS → lsp_channels_handle_reconnect
- Verifies: fd reconnected, local/remote amounts preserved, commitment_number preserved, offline_detected cleared

Also fixed protocol ordering bug in client_run_reconnect() (see above).

### ✓ Item 5: Rotation retry with backoff

New fields on `lsp_channel_mgr_t`:
- `rot_retry_count[8]` — per-factory failure count
- `rot_last_attempt_block[8]` — block height of last failed attempt
- `rot_max_retries` — configurable (default: 3)
- `rot_retry_base_delay` — configurable (default: 10 blocks, doubles per retry)

Helper functions in `lsp_rotation.c`:
- `lsp_rotation_should_retry()` — returns 1 (retry), -1 (fallback), 0 (wait)
- `lsp_rotation_record_failure()` — increment count, save block height
- `lsp_rotation_record_success()` — reset retry state

Daemon loop behavior:
1. Factory transitions ACTIVE → DYING: first rotation attempt
2. If fails: retry after 20 blocks, then 40 (delay = base * 2^retries, exponential backoff)
3. After 3 failures: broadcast distribution TX as fallback (fund recovery)
4. Retry state preserved across successful rotations (save/restore in lsp_channels_init)

3 unit tests: `test_rotation_retry_backoff`, `test_rotation_retry_success_resets`, `test_rotation_retry_defaults`

### ✓ Item 8: Interactive CLI

`--cli` flag on `superscalar_lsp` enables stdin commands in daemon loop:
- `pay <from> <to> <amount>` — calls `lsp_channels_initiate_payment()`
- `status` — prints channels (local/remote/cn/fd), factory state, ladder info
- `rotate` — calls `lsp_channels_rotate_factory()`
- `close` — sets shutdown flag for cooperative close
- `help` — shows available commands

Implementation: STDIN_FILENO added to daemon loop's select() fd_set when
`mgr->cli_enabled` is set. fgets + sscanf parsing, ~70 lines of code.

---

## Remaining Roadmap

### Tier 1: Prove the Daemon Works (continued)

**2. Daemon loop integration test** (2-3 days)

A regtest test that starts LSP with lsp_channels_run_daemon_loop (not demo
sequence), forks 4 clients, runs 10 payments via the daemon loop, checks
watchtower ran and fee estimator polled.

**3. Block-height rotation test** (2-3 days)

Creates factory with --active-blocks=20, mines 21 blocks, verifies daemon
loop triggers rotation automatically, runs payment in new factory.

### ✓ Item 4: JIT daemon trigger test

Orchestrator `jit_lifecycle` scenario: mines past active + dying blocks,
verifies daemon loop triggers JIT channel creation, runs a payment over
the JIT channel.

### Tier 3: Dynamic Participation (New Feature)

**6. Waiting room + rotation inclusion** (3-5 days)

New clients join on next rotation via MSG_WAITING/MSG_WAIT_COMPLETE wire
messages and a waiting room data structure on the LSP.

**7. Graceful client departure** (2-3 days)

MSG_DEPART wire message triggers partial cooperative close for departing
client. Remaining clients continue.

### Tier 4: Operational Tooling

**9. Soak test** (3-5 days)

Python script: 1-hour loop with random payments, client kills/restarts,
block-triggered rotations, balance consistency checks.

**10. UNIX socket status API** (2-3 days)

JSON over UNIX domain socket for external tooling.

### Tier 5: Polish

**11-14.** Prometheus metrics, event stream, JSON-RPC, SDK — as needed.

---

## Pluggable Channel Factories: Architectural North Star

ZmnSCPxj's "Pluggable Channel Factories" proposal (Delving Bitcoin, 2024)
describes how factory channels can integrate with existing Lightning node
software rather than requiring a standalone implementation:

### Core Idea

Factory-hosted channels appear as **plugins to the base LN node** (CLN,
LDK, or LND). The factory protocol manages the tree of transactions and
MuSig2 signing, but individual channels behave exactly like normal Lightning
channels from the node's perspective.

### How It Works

1. **New TLVs on `open_channel`**: Factory channels carry a TLV indicating
   they are factory-hosted. The base node treats them as 0-conf channels
   (the factory funding TX is the "virtual" funding).

2. **Splicing infrastructure reused**: When a factory rotates, the channel
   "splices" into the new factory's tree. From the base node's perspective,
   this is a splice-in/splice-out operation on an existing channel.

3. **Plugin handles factory protocol**: The factory creation ceremony,
   PTLC key turnover, DW state advances, and tree signing are handled by
   a plugin/module. The base node handles commitment transactions, HTLCs,
   and routing as normal.

4. **bLIP specification**: A bLIP (Bitcoin Lightning Improvement Proposal)
   PR #56 is being drafted to standardize the TLV extensions.

### Relevance to SuperScalar

SuperScalar currently implements the full stack: factory tree, channels,
HTLCs, wire protocol, persistence, and routing. For production deployment,
the channel layer could be replaced by CLN/LDK/LND's battle-tested
implementation, with SuperScalar providing only the factory layer.

This is an architectural decision for the future, not an immediate task.
The current standalone implementation is correct and complete for testing
the factory protocol itself. Pluggability would be the path to production
use with real funds on mainnet.

### What Would Change

| Component | Current (standalone) | Pluggable |
|-----------|---------------------|-----------|
| Channel state machine | Custom (channel.c) | CLN/LDK/LND |
| HTLC forwarding | Custom (lsp_channels.c) | Base node gossip/routing |
| Commitment transactions | Custom (channel.c) | Base node |
| Factory tree + MuSig2 | Custom (factory.c) | **Kept** — this is the core |
| PTLC key turnover | Custom (adaptor.c) | **Kept** |
| DW state machine | Custom (dw.c) | **Kept** |
| Wire protocol | Custom (wire.c) | Replaced by LN peer protocol + TLVs |
| Persistence | Custom (persist.c) | Base node DB + factory extension |

The factory-specific code (~40% of the codebase) would be preserved.
The channel/routing code (~30%) would be replaced by the base node.
The infrastructure code (~30%) would be adapted.

---

## Success Criteria

**"Realistic long-running factory"** means:

1. LSP daemon runs for 24+ hours without crash or memory growth
2. ~~Clients can disconnect and reconnect over real TCP~~ **PROVEN** (test_regtest_tcp_reconnect)
3. Payments flow continuously (client-initiated, not just LSP scripted)
4. Factory rotates automatically when block height triggers DYING state
5. JIT channels activate when factory expires
6. ~~Rotation failure doesn't lock funds permanently~~ **FIXED** (retry + dist TX fallback)
7. New clients can join on next rotation cycle
8. ~~External tools can query status and trigger operations~~ **DONE** (interactive CLI)

Items 2, 6, 8 are complete. Items 1, 3-5 require the remaining Tier 1 tests.
Item 7 requires Tier 3 (waiting room).

**Minimum viable "it works for real":** Tier 1 items 2-4 (daemon tests).
The hardest gaps (TCP reconnect, rotation retry, CLI) are already closed.
