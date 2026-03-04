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
4. Run tests: `cd build && ./test_superscalar --unit` (all 415 must pass)
5. Run with sanitizers: `cmake .. -DENABLE_SANITIZERS=ON && make -j$(nproc) && ./test_superscalar --unit`
6. Open a pull request

## Code Standards

- C11, compiled with `-Wall -Wextra -Werror`
- No warnings allowed — CI enforces this
- Static analysis via cppcheck on every push
- AddressSanitizer + UBSan in CI
- Test anything you add — the test binary is `test_superscalar`

## Build

```bash
git clone https://github.com/8144225309/SuperScalar.git
cd SuperScalar
mkdir -p build && cd build
cmake .. && make -j$(nproc)
./test_superscalar --unit    # 415 tests, all must pass
```

## Questions

Use [GitHub Discussions](https://github.com/8144225309/SuperScalar/discussions) for questions, ideas, and coordination.
