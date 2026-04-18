# Contributing to SuperScalar

SuperScalar is an early-stage Bitcoin Lightning channel factory implementation. We need testers, reviewers, and contributors.

## How to Help

### Test on Signet

The most valuable contribution right now is running SuperScalar on signet or testnet and reporting what happens. Even a 2-client factory running for a few days produces data we can't get from unit tests.

See the [Running on Signet](README.md#running-on-signet) guide to get started.

### Report Bugs

Open an issue at [github.com/8144225309/SuperScalar/issues](https://github.com/8144225309/SuperScalar/issues).

Include:
- Network (signet, testnet4, regtest)
- SuperScalar version (`./superscalar_lsp --version`)
- Bitcoin Core version (`bitcoind --version`)
- OS (`uname -a`)
- Steps to reproduce
- Relevant logs (LSP, client, bridge)
- DB files if possible (`lsp.db`, `client.db`)

### Review Code

The [internal audit](docs/mainnet-audit.md) is a good starting point. High-value review targets:

| Area | Files | Why |
|------|-------|-----|
| Cryptography | `src/musig.c`, `src/tapscript.c`, `src/channel.c` | MuSig2 signing, commitment construction, revocation |
| Transport | `src/noise.c`, `src/crypto_aead.c`, `src/wire.c` | Noise NK handshake, AEAD encryption, wire framing |
| Key material | `src/keyfile.c`, `src/backup.c`, `src/bip39.c`, `src/hd_key.c` | Key storage, backup encryption, mnemonic derivation |
| State machine | `src/dw_state.c`, `src/factory.c`, `src/ladder.c` | DW invalidation, factory tree, ladder rotation |
| Persistence | `src/persist.c` | SQLite schema, crash recovery |

### Submit Patches

1. Fork the repo
2. Create a branch (`git checkout -b fix-description`)
3. Make your changes
4. Run tests: `cd build && ./test_superscalar --unit`
5. Run with sanitizers (see below)
6. Open a pull request

## Code Standards

- C11, compiled with `-Wall -Wextra -Werror`
- No warnings allowed — CI enforces this
- Static analysis via cppcheck on every push
- Test anything you add — the test binary is `test_superscalar`

## Memory safety / CI

Every PR runs under multiple sanitizers in parallel:

| CI job | What it catches |
|---|---|
| `Linux (sanitizers)` | AddressSanitizer + UBSan + LeakSanitizer. Heap overflows, use-after-free, undefined behavior, and **memory leaks fail the build** (no silent reporting). |
| `Linux (TSan)` | ThreadSanitizer. Data races and lock-ordering deadlocks. |
| `Fuzz Testing` | libFuzzer + ASan on 7 harnesses, 5 min each. |
| `Static Analysis` | cppcheck with `--error-exitcode=1`. |

Run them locally before opening a PR:

```bash
# ASan + UBSan + LSan (catches leaks — must pass)
cmake -B build-asan -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON
cmake --build build-asan -j
ASAN_OPTIONS=detect_leaks=1 LSAN_OPTIONS=exitcode=23 \
    build-asan/test_superscalar --unit

# TSan (data races)
cmake -B build-tsan -DCMAKE_BUILD_TYPE=Debug -DENABLE_TSAN=ON
cmake --build build-tsan -j
build-tsan/test_superscalar --unit

# MSan (uninitialized reads — clang only, see note below)
CC=clang cmake -B build-msan -DCMAKE_BUILD_TYPE=Debug -DENABLE_MSAN=ON
cmake --build build-msan -j
build-msan/test_superscalar --unit
```

If LSan reports a leak in third-party code that cannot be fixed, add a
suppression in `test/sanitizer_suppressions/lsan.supp` with a comment
explaining why.

MSan is not in CI because libssl/libsqlite are uninstrumented and produce
false positives; continuous MSan coverage comes from OSS-Fuzz (see
`oss-fuzz/`) where the full dependency chain is instrumented.

## Build

```bash
git clone https://github.com/8144225309/SuperScalar.git
cd SuperScalar
mkdir -p build && cd build
cmake .. && make -j$(nproc)
./test_superscalar --unit    # 418 tests, all must pass
```

## Questions

Use [GitHub Discussions](https://github.com/8144225309/SuperScalar/discussions) for questions, ideas, and coordination.
