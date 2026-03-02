# Release Plan: v0.1.0

## Option A: Lightweight (git tag only)

```bash
git tag -a v0.1.0 -m "v0.1.0: Decker-Wattenhofer channel factory prototype

SuperScalar implements Decker-Wattenhofer channel factories for Bitcoin
Lightning Network. This is the first tagged release — a functional
prototype validated on regtest.

Core:
- Factory tree construction with variable-N participants and arity-1/2 leaves
- MuSig2 N-of-N signing with split-round nonce/psig exchange
- Poon-Dryja channels with HTLC routing (add/fulfill/fail)
- Cooperative close, unilateral close with penalty enforcement
- Decker-Wattenhofer epoch counter with per-leaf advances
- PTLC/adaptor signature support for key turnover

Infrastructure:
- SQLite persistence with schema versioning and crash recovery
- Encrypted transport (Noise NK handshake + ChaCha20-Poly1305)
- CLN bridge plugin for Lightning Network interop
- JIT channel fallback for offline participants
- Watchtower with CPFP anchor bumping
- Ladder factory manager with continuous rotation
- Reconnect with commitment reconciliation and HTLC replay

Testing:
- 359 unit tests, 20 orchestrator tests, 5 integration scripts
- CI: 7 GitHub Actions jobs (Linux, macOS, sanitizers, cppcheck, regtest, coverage, fuzz)
- 5 libFuzzer targets

Tooling:
- Docker support (demo/test/unit modes)
- CLI daemon with interactive commands
- Tor/SOCKS5 proxy support

Status: regtest-validated prototype. Not production-ready."

git push origin v0.1.0
```

Shows up in repo tags. Minimal effort, permanent reference point.

---

## Option B: Full GitHub Release

### Step 1: Create release notes file

Save to `docs/RELEASE-v0.1.0.md` (or pass inline).

### Step 2: Create release

```bash
gh release create v0.1.0 \
  --title "v0.1.0: Decker-Wattenhofer Channel Factory Prototype" \
  --notes-file docs/RELEASE-v0.1.0.md
```

### Release Notes Content

```markdown
## What is SuperScalar?

SuperScalar implements [Decker-Wattenhofer channel factories](https://tik-old.ee.ethz.ch/file/716b955c130e6c703fac336ea17b1670/duplex-micropayment-channels.pdf)
for the Bitcoin Lightning Network. Channel factories allow multiple
participants to share a single on-chain UTXO while maintaining independent
payment channels, dramatically reducing on-chain footprint.

This is the first tagged release — a functional prototype validated on
Bitcoin regtest.

## Features

### Core Protocol
- Factory tree construction with variable-N participants (3–16)
- Arity-1 and arity-2 leaf modes (per-client vs shared leaves)
- MuSig2 N-of-N signing with distributed split-round ceremony
- Poon-Dryja payment channels with bidirectional revocation
- HTLC routing: add, fulfill, fail with proper commitment exchange
- Cooperative close with per-client balance settlement
- Unilateral close with penalty enforcement via watchtower
- Decker-Wattenhofer epoch counter with per-leaf advances
- PTLC / adaptor signature support for key turnover
- Subtree-scoped signing (only affected leaves re-sign)

### Infrastructure
- **Persistence**: SQLite with schema versioning, crash recovery, and
  per-operation channel state persistence
- **Encrypted transport**: Noise NK handshake + ChaCha20-Poly1305 AEAD
- **CLN bridge**: Plugin for Core Lightning interop (inbound/outbound payments)
- **JIT channels**: Fallback funding for offline factory participants
- **Watchtower**: Breach detection with CPFP anchor fee bumping
- **Ladder manager**: Continuous factory rotation with partial close support
- **Reconnection**: Commitment number reconciliation (BOLT #2) and HTLC replay
- **Fee estimation**: Dynamic fee policy with configurable routing fees

### Tooling
- Docker support (`docker-compose up` for demo)
- CLI daemon with interactive commands (pay, status, rotate, close, rebalance)
- Tor / SOCKS5 proxy support for .onion connectivity
- Encrypted keyfile storage (AES-256-GCM)

## Testing

| Category | Count |
|----------|-------|
| Unit tests | 359 |
| Orchestrator tests | 20 |
| Integration scripts | 5 |
| Fuzz targets (libFuzzer) | 5 |

### CI Pipeline (7 jobs)
- Linux (gcc) + macOS (clang) builds
- AddressSanitizer + UndefinedBehaviorSanitizer
- cppcheck static analysis
- Bitcoin Core regtest integration
- lcov code coverage
- libFuzzer continuous fuzzing

## Build

```bash
mkdir build && cd build
cmake .. && make -j$(nproc)
./test_superscalar --unit    # 359 tests
./test_superscalar --all     # + regtest (requires bitcoind)
```

Or with Docker:
```bash
docker-compose up            # demo mode
docker-compose run superscalar unit   # unit tests
```

## Status

Regtest-validated prototype. Tested against Bitcoin Core 28.1 and Core
Lightning. Not audited, not production-ready. See `docs/gaps-and-changes.md`
for the known gap roadmap.
```

### Step 3: Verify

```bash
gh release view v0.1.0
```

---

## Pre-Release Checklist

Before either option, all of these must pass:

- [ ] `make -j$(nproc)` — clean build, zero warnings
- [ ] `./test_superscalar --unit` — 359/359 pass
- [ ] `cmake -DENABLE_SANITIZERS=ON && make && ASAN_OPTIONS=detect_leaks=0 ./test_superscalar --unit` — 359/359 pass
- [ ] `python3 tools/manual_tests.py` — 20 orchestrator tests pass
- [ ] `python3 tools/test_boundary.py` — boundary tests pass
- [ ] `python3 tools/test_stress.py` — stress tests pass
- [ ] `python3 tools/test_cli_cmds.py` — CLI command tests pass
- [ ] `python3 tools/test_persist_recovery.py` — persistence recovery tests pass
- [ ] GitHub Actions CI green on current HEAD
- [ ] `docker build .` succeeds
- [ ] No uncommitted changes (`git status` clean)
