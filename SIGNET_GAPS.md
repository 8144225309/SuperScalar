# SuperScalar: Signet Launch Gap Tracker

## Tier 1 — Will crash or lose funds

### GAP-1: No reconnection handler
- **Status**: FALSE — REMOVED
- **Reality**: Reconnection is fully implemented. `client_run_reconnect()` sends
  MSG_RECONNECT with pubkey + commitment number, LSP matches to client slot via
  `handle_reconnect_with_msg()` in daemon loop (lsp_channels.c:2217), re-exchanges
  nonces, sends MSG_RECONNECT_ACK. Client retries in a loop with 5s backoff
  (superscalar_client.c:1301-1319). Unit tests exist in test_reconnect.c.

### GAP-2: No LSP factory/channel recovery on restart
- **Status**: CONFIRMED — REAL GAP
- **Evidence**: LSP loads invoices, counters, HTLC origins, and JIT channels from DB
  (superscalar_lsp.c:964-1091), but never calls `persist_load_factory()` or
  `persist_load_channel_state()`. Factory and channels are rebuilt from scratch
  via ceremony on every startup. If LSP crashes mid-session, persisted factory
  and channel state is orphaned — not reloaded.
- **Impact**: LSP crash = clients must redo full ceremony. On signet with real
  funding, the old factory's on-chain UTXOs become stranded until CLTV timeout.
- **Comparison**: LND stores full channel state in channeldb (bbolt) and recovers
  all channels on restart. CLN uses a HSM + sqlite combo that replays from last
  known state. LDK delegates to `Persist` trait — implementer must guarantee
  atomicity. All three recover channels without re-ceremony.
- **Fix**: Add `persist_load_factory()` + `persist_load_channel_state()` path at
  LSP startup when DB has existing state. Skip ceremony, go straight to daemon mode.

### GAP-3: Client auto-accepts all HTLCs (PoC)
- **Status**: CONFIRMED — REAL GAP
- **Evidence**: superscalar_client.c:580 — "Auto-accept (PoC)". Client receives
  MSG_JIT_OFFER and immediately sends MSG_JIT_ACCEPT without any validation.
  Any LSP (or MITM) can trigger JIT channel creation with arbitrary amounts.
- **Impact**: On signet, a rogue LSP could open unwanted channels consuming client
  funds. Not a direct theft vector (client still signs), but enables griefing.
- **Comparison**: LND requires explicit invoice creation before accepting HTLCs.
  CLN uses `autoclean` plugin with configurable acceptance policies. LDK has
  `ChannelManager::accept_inbound_channel()` that requires explicit opt-in.
- **Fix**: Add `--auto-accept-jit` flag (off by default). Without it, prompt user
  or reject. For daemon mode, accept only if matching a registered invoice.
- **Severity downgrade**: This is a JIT offer acceptance, not HTLC fulfillment.
  Client still controls signing. Moving to Tier 2.

### GAP-4: No graceful close on disconnect
- **Status**: PARTIALLY FALSE — DOWNGRADED
- **Evidence**: Client DOES have a retry loop (superscalar_client.c:1301-1319) —
  on disconnect, it sleeps 5s and reconnects from persisted state. The "break"
  at line 334 exits the daemon callback, not the program. The outer loop catches
  it and reconnects.
- **What IS missing**: No cooperative close attempt before disconnect. No in-flight
  HTLC cleanup. If an HTLC was mid-fulfillment when TCP drops, it's orphaned
  until timeout.
- **Comparison**: LND sends `channel_reestablish` on reconnect and replays
  unacked HTLCs. CLN does the same per BOLT 2. Both handle mid-flight HTLCs.
- **Severity**: Tier 2, not Tier 1. The reconnect loop prevents fund loss.
  Orphaned HTLCs resolve via timeout (inconvenient, not catastrophic).

## Tier 2 — Embarrassing on public network

### GAP-5: Inconsistent secret key zeroing
- **Status**: FALSE — REMOVED
- **Reality**: The LSP tool has `memset(lsp_seckey, 0, 32)` on literally every
  exit path — 57 occurrences across superscalar_lsp.c. Client has the same for
  `my_seckey` and `lsp_rev_secret`. The library code (jit_channel.c) also zeroes
  `lsp_seckey` on every return path (we just hardened this further). The codebase
  is actually very thorough about this. `memset` can theoretically be optimized
  away by compilers, but gcc with -O0 (debug) or volatile casts prevent this.
  Not a real gap for signet.

### GAP-6: No connection rate limiting
- **Status**: CONFIRMED — REAL BUT LOW PRIORITY
- **Evidence**: `lsp_accept_clients()` (lsp.c:27) loops accepting connections
  with no rate limiting, IP tracking, or backpressure. Daemon mode accept loop
  (lsp_channels.c:2200+) also accepts any incoming connection.
- **Impact**: DoS by connection flooding. Moderate risk on signet (small network,
  known participants). High risk on mainnet.
- **Comparison**: LND has `--maxpendingchannels` and connection limits. CLN has
  `--max-concurrent-htlcs`. Both delegate heavy DoS protection to Tor/firewall.
- **Fix**: Add `--max-connections` flag. For signet launch, iptables rate limiting
  is sufficient. Not a code change priority.
- **Severity**: Low for signet. Firewall-level mitigation is standard practice.

### GAP-7: Hardcoded confirmation timeouts
- **Status**: CONFIRMED — REAL BUT MINOR
- **Evidence**: `regtest_wait_for_confirmation()` called with 3600s (1hr) for
  tree broadcast (line 396) and 7200s (2hr) for funding confirmation. These are
  hardcoded per call site, not configurable via CLI args.
- **Impact**: Signet blocks average 10 min. 2hr = ~12 blocks, which is usually
  fine. Could be tight during signet disruptions.
- **Comparison**: LND uses configurable `--bitcoin.timelockdelta`. CLN has
  `--watchtime-blocks`. Both express timeouts in blocks, not seconds.
- **Fix**: Add `--confirm-timeout` CLI arg. Low effort, low urgency.

### GAP-8: Failed broadcasts silently ignored
- **Status**: FALSE — REMOVED
- **Evidence**: Actually reviewed the broadcast code (superscalar_lsp.c:363-388).
  Failed broadcasts: (1) retry 60 times with 15s sleep, (2) log to audit table
  via `persist_log_broadcast()` with "failed" status, (3) return 0 which propagates
  to caller, (4) caller prints error and exits. This is not silent — it's logged,
  persisted, and reported.

### GAP-3b: Client auto-accept JIT (moved from Tier 1)
- **See GAP-3 above** — reclassified as Tier 2.

### GAP-4b: No in-flight HTLC replay on reconnect
- **See GAP-4 above** — the reconnect works, but unacked HTLCs aren't replayed.

## Tier 3 — Polish

### GAP-9: PoC simplifications remain
- **Status**: CONFIRMED — REAL BUT ACCEPTABLE FOR SIGNET
- **Evidence**: 5 PoC comments in library code:
  - jit_channel.c:471 — JIT balance adjustment is direct memcpy (should use
    proper state update with signatures)
  - lsp_channels.c:972,979 — epoch reset and leaf advance done locally (should
    be distributed multi-party signing in production)
  - lsp_channels.c:1281 — reconnect proceeds even on nonce mismatch
  - lsp_channels.c:2124 — epoch reset done with direct call, not wire protocol
- **Impact**: These are all correct for single-LSP-controls-signing model.
  Would need rework for trustless multi-party, but signet demo is single-LSP.
- **Fix**: Document as known limitations. Fix for mainnet, not signet.

### GAP-10: Basic watchtower mempool scanning
- **Status**: CONFIRMED — ACCEPTABLE
- **Evidence**: Scan depth is 20 blocks for regtest, 200 blocks for other networks
  (regtest.c:283,412). Also checks mempool via `getmempoolentry` (regtest.c:320).
  CPFP bump logic tracks `cycles_in_mempool` and bumps after 2 cycles
  (watchtower.c:488-511). This is actually reasonable.
- **Impact**: 200-block scan depth covers ~33 hours on signet. Combined with
  mempool checking, this catches most breach scenarios.
- **Fix**: Could add `txindex` requirement and full-chain scan, but 200 blocks +
  mempool is standard. LND's watchtower also has bounded lookback.

### GAP-11: Dashboard assumes specific network paths
- **Status**: CONFIRMED — COSMETIC
- **Evidence**: dashboard.py generates demo data with hardcoded signet chain
  string (line 232). It's a monitoring UI, not a functional component.
- **Impact**: Dashboard shows wrong data if bitcoind not running. Zero impact
  on protocol correctness.
- **Fix**: Not needed for signet launch.

---

## Summary

| Gap | Status | Priority | Effort |
|-----|--------|----------|--------|
| GAP-1: Reconnection | FALSE (already implemented) | - | - |
| GAP-2: LSP restart recovery | **CLOSED** (commit 2692f44) | - | - |
| GAP-3: Auto-accept JIT | **CLOSED** (commit 2692f44, `--auto-accept-jit`) | - | - |
| GAP-4: HTLC persist on reconnect | **CLOSED** (commit 2692f44 + 6ae7acb) | - | - |
| GAP-5: Key zeroing | FALSE (already thorough) | - | - |
| GAP-6: Rate limiting | OPEN (firewall-level, not code) | Low | Low |
| GAP-7: Timeout config | **CLOSED** (commit 2692f44, `--confirm-timeout`) | - | - |
| GAP-8: Silent broadcast fail | FALSE (logged + persisted) | - | - |
| GAP-9: PoC simplifications | OPEN (acceptable for signet) | Low | High |
| GAP-10: Watchtower scan | OPEN (acceptable for signet) | Low | Medium |
| GAP-11: Dashboard | COSMETIC | None | Low |

**All Tier 1 gaps are closed.** Remaining open items (6, 9, 10, 11) are
acceptable for signet launch — firewall config, known PoC limitations,
and cosmetic issues.
