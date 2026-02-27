# SuperScalar: Test Coverage & Signet Readiness Analysis

> **Point-in-time audit from 2026-02-24.** The test suite has grown from
> 255 to 360 tests (319 unit + 41 regtest) since this document was written.
> Several gaps identified below have been closed. See
> [SIGNET_GAPS.md](../SIGNET_GAPS.md) for current gap status.

**Date:** 2026-02-24
**Build:** 255/255 tests passing (232 unit + 23 regtest)
**Commit:** 1e4e6e6 (post musig_pubkey_agg API fix)

---

## Part 1: What We Tested

### Unit Tests (232)

Every core module in isolation:

- **DW state machine** — nSequence odometer, multi-layer counters, exhaustion
- **MuSig2** — key aggregation, signing, split-round, nonce pools, 5-of-5
- **Transaction builder** — P2TR, sighash, witness finalization
- **Tapscript** — timeout scripts, control blocks, multi-level trees
- **Factory tree** — build, sign, advance, epoch reset, per-leaf advance, coop close
- **Shachain** — L-stock burn paths
- **Channels** — Poon-Dryja commitments, revocation, penalty, HTLCs
- **Adaptor sigs + PTLC key turnover**
- **Wire protocol** — 49 message types, framing, serialization
- **Persistence** — 19 SQLite tables, round-trip save/load
- **CLN bridge** — handshake, invoice registry, inbound/outbound flows
- **Watchtower** — breach detection, CPFP anchors, penalty bumping
- **Encrypted transport** — ChaCha20-Poly1305, Noise handshake
- **JIT channels** — offer/accept/ready/migrate, watchtower integration
- **Arity-1 leaves** — per-client leaf mode, 14-node trees
- **Edge cases** — dust limits, reserve enforcement, HTLC limits, double-fulfill rejection

### Regtest Integration (23)

Real Bitcoin Core transactions:

- Factory funding + DW state broadcast + confirmation
- Old-state-first attack (correctly rejected)
- MuSig2 on-chain spend
- nSequence enforcement (BIP-68 rejection before maturity)
- Full 6-node factory tree broadcast + confirmation
- CLTV timeout script-path spend
- Shachain burn tx
- Unilateral close (commitment + CSV wait + to-local spend)
- Penalty tx on revoked commitment
- HTLC success + timeout spends
- Factory + channel cooperative close
- PTLC key turnover + coop close
- Ladder lifecycle (ACTIVE -> DYING -> EXPIRED)
- Ladder migration (Factory 1 close -> Factory 2 create)
- Distribution tx fallback (nLockTime enforcement)
- Wire protocol factory ceremony (arity-2 and arity-1)
- Intra-factory payments with balance verification
- Multi-hop payments (4 payments across 4 clients, balances verified on-chain)
- CPFP penalty fee bumping (breach -> penalty -> anchor bump)

---

## Part 2: Test Coverage Gaps

*Verified against source code 2026-02-24. Items marked [RETRACTED] were found incorrect on audit.*

### Critical (funds-at-risk scenarios)

1. **Watchtower capacity overflow** — global limit of WATCHTOWER_MAX_WATCH = 64 entries (src/noise.c:116). Returns 0 when full (no silent drop), but an attacker broadcasting many old states could exhaust the table. Not 16 as originally stated.
2. **[RETRACTED] HTLC forwarding races** — the LSP event loop is single-threaded (select() in lsp_channels.c:2037-2243). Messages are processed sequentially, one at a time. Concurrent ADD/FULFILL/FAIL races are architecturally impossible. Not a real concern.
3. **Cooperative close blocking** — if one client doesn't send CLOSE_NONCE, wire_recv() in lsp.c:430 blocks indefinitely with no timeout. Cleanup sends ERROR to other clients (lsp_abort_ceremony) but does NOT close sockets. Funds are not lost but the LSP hangs.
4. **Database transaction isolation** — CONFIRMED. Multi-step saves (factory + participants in persist.c:289-357, tree nodes in persist.c:1117-1215) are NOT wrapped in BEGIN/COMMIT transactions. WAL mode is set but doesn't help with multi-statement atomicity. Crash mid-save leaves inconsistent state.

### High (DoS / crash vectors)

5. **[RETRACTED] Malformed wire messages** — on audit, wire.c properly validates JSON fields. cJSON_GetObjectItem calls are followed by null/type checks throughout. The wire_json_get_hex helper (wire.c:372) checks !item || !cJSON_IsString. Cannot find 3-5 unchecked examples. Wire parsing is well-defended.
6. **Noise FD table overflow** — MAX_ENCRYPTED_FDS = 16 (src/noise.c:116). When full, prints error to stderr but fd is NOT encrypted. Subsequent wire_send/wire_recv on that fd would transmit plaintext. No test covers this.
7. **Message ordering violations** — no enforcement that ceremony messages arrive in valid order. Not tested.
8. **Partial message framing** — no test for TCP fragmentation, truncated messages, trailing garbage.

### Medium (operational resilience)

9. **JIT + factory channel race** — single-threaded architecture reduces but doesn't eliminate concern. A client could have a JIT channel funded on-chain while simultaneously joining a factory ceremony. No test covers the interaction.
10. **Reconnection state mismatch** — reconnect after partial channel update (COMMITMENT_SIGNED sent but REVOKE not received). Not tested.
11. **LSP revocation delivery failure** — wire_send fails sending LSP's revocation secret. Client can't detect LSP breaches. Not tested.
12. **Bridge plugin timeouts** — plugin connects but never sends a message. Bridge hangs on blocking read. Not tested.

---

## Part 3: Signet Readiness

### Already signet-ready (verified against source)

- **Network abstraction** — regtest.c build_cli_prefix() (lines 37-62) handles regtest/signet/testnet/mainnet
- **Mine-blocks guarded** — regtest.c:185: `if (strcmp(rt->network, "regtest") != 0) return 0;`
- **DW timelocks** — BIP-68 relative, parameterized by step_blocks, no hardcoded block heights in factory.c/channel.c/dw_state.c
- **Fee estimation** — fee.c:21 uses estimatesmartfee RPC, clamped to min 1000 sat/kvB (fee.c:40)
- **Confirmation polling** — regtest.c:499-520: 5s/10s for regtest, 15s/120s for signet, exponential backoff
- **Confirmation timeouts already network-aware** — call sites use 3600s (regtest) vs 7200s (signet) e.g. superscalar_lsp.c:760-761
- **Persistence** — SQLite with WAL mode, state survives crashes
- **Signet tooling** — signet_setup.sh (1200+ lines, real implementation with subcommands) and signet_diagnose.sh (800+ lines, diagnostics + emergency fee bumping)

### Gaps to close

| Gap | Effort | Risk | Verified |
|-----|--------|------|----------|
| run_demo.sh hardcoded to regtest (line 84: `NETWORK="regtest"`), needs --signet flag | 1-2 hours | Low | Yes — no --network flag exists |
| Cooperative close blocks indefinitely on missing CLOSE_NONCE (lsp.c:430) — needs timeout on wire_recv | 2-3 hours | Medium | Yes — blocking call, no timeout |
| No mempool stuck-tx detection/auto-bump in payment critical paths (manual tools exist in signet_diagnose.sh but aren't integrated) | 6-8 hours | Medium | Yes — manual only |
| Logging doesn't distinguish "in mempool waiting for signet block" from "not broadcast" | 2-3 hours | Low | Yes — regtest.c:514 is generic |
| Noise FD table full = plaintext fallback with no warning to callers | 1-2 hours | Medium | Yes — silent degradation |
| persist.c multi-step saves need BEGIN/COMMIT transaction wrapping | 3-4 hours | Medium | Yes — confirmed no transactions |

### [REMOVED] Items that turned out to be non-issues

- ~~Confirmation timeout values implicit at call sites~~ — actually already network-aware (3600s vs 7200s)
- ~~Wire protocol assumes well-formed JSON~~ — actually well-validated with null checks throughout
- ~~HTLC forwarding race conditions~~ — single-threaded select loop, impossible
- ~~No signet validation script~~ — signet_setup.sh already handles this

### Revised Estimate

The prototype is closer to signet-ready than initially assessed (~90%). The signet infrastructure already exists and is substantial. Key remaining work:

- **Must fix:** Cooperative close timeout (blocking wire_recv)
- **Should fix:** persist.c transaction wrapping, noise FD overflow handling
- **Nice to have:** run_demo.sh --signet flag, better mempool logging

Estimated effort to signet-deployable: **~1 week** of focused work, not 2-4 weeks as originally stated.
