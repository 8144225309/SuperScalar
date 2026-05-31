# SuperScalar

[![CI](https://github.com/8144225309/SuperScalar/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/8144225309/SuperScalar/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/8144225309/SuperScalar)](https://github.com/8144225309/SuperScalar/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

SuperScalar is an implementation of [ZmnSCPxj's SuperScalar design](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories-with-pseudo-spilman-leaves/1242) — laddered timeout-tree-structured Decker–Wattenhofer channel factories for Bitcoin. The protocol combines Decker–Wattenhofer invalidation, MuSig2 timeout-sig-trees, Poon–Dryja Lightning channels at the leaves, and an LSP-mediated topology. No consensus changes required.

## What's here

| Area | What's implemented |
|---|---|
| **Cryptography** | MuSig2 (BIP-327 stateless signer), Schnorr adaptor signatures, PTLC key turnover, shachain revocation, 2-leaf taptree with script-path revocation penalty |
| **Transport** | BOLT #8 Noise_XK encrypted transport, BOLT #7 gossip, Tor + SOCKS5 |
| **Wire protocol** | BOLT #2/#4/#11/#12, LSPS0/1/2, MPP + AMP, blinded paths, dual-fund v2, cooperative close |
| **Persistence** | SQLite3 with 60+ tables, crash recovery, idempotent additive migrations |
| **Security** | **Trustless watchtower** (cannot read revocation secrets, even if compromised), breach detection + penalty broadcast, L-stock poison TXs, per-client close addresses, encrypted keyfiles (PBKDF2 600K iterations), BIP-39 seed recovery |
| **Operations** | Web dashboard, JSON diagnostic reports, interactive CLI, Prometheus exporter, configurable economics |
| **Testing** | Unit + regtest + signet + testnet4 evidence campaigns; CI matrix (Linux/macOS/ARM64 + AddressSanitizer + TSan + cppcheck + libFuzzer + Regtest integration + Coverage) |

## Quick start

Build on a fresh Ubuntu 24.04 in five commands:

```bash
sudo apt install -y build-essential cmake libsqlite3-dev pkg-config
git clone https://github.com/8144225309/SuperScalar.git
cd SuperScalar
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

This produces four binaries in `build/`:

| Binary | Role |
|---|---|
| `superscalar_lsp` | Liquidity Service Provider — coordinates the factory ceremony, holds channels with N clients, routes payments |
| `superscalar_client` | Client node — participates in a factory, opens channels with the LSP, sends/receives payments |
| `superscalar_bridge` | Optional bridge between two SuperScalar instances (cross-factory payments) |
| `superscalar_watchtower` | Standalone trustless watchtower — monitors chain for breaches against a `wt.db` of pre-signed responses; never reads secrets |

For a regtest demo end-to-end in one command, see [`docs/demo-walkthrough.md`](docs/demo-walkthrough.md).

For signet operation, see [`docs/signet-ps-n8-procedure.md`](docs/signet-ps-n8-procedure.md).

For mainnet operators, see [`docs/mainnet-runbook.md`](docs/mainnet-runbook.md).

## Build options

| Option | Purpose |
|---|---|
| `-DCMAKE_BUILD_TYPE=Release` | Optimized release build (default for binary releases) |
| `-DCMAKE_BUILD_TYPE=Debug` | Debug symbols + sanitizer-friendly |
| `-DENABLE_SANITIZERS=ON` | AddressSanitizer + UndefinedBehaviorSanitizer (debug only) |
| `-DENABLE_TSAN=ON` | ThreadSanitizer (cannot combine with `-DENABLE_SANITIZERS`) |
| `-DBUILD_TESTING=ON` | Build the `test_superscalar` binary (default ON) |

## Testing

```bash
cd build && ctest -V          # full unit suite
bash tools/regtest_full_regression_v020.sh   # regtest integration sweep
bash tools/test_regtest_crash_drill_matrix.sh   # crash-injection matrix
```

See [`docs/testing-guide.md`](docs/testing-guide.md) for the full test taxonomy.

## Documentation

| Topic | Doc |
|---|---|
| Pseudo-Spilman leaves | [`docs/pseudo-spilman.md`](docs/pseudo-spilman.md) |
| Factory arity + wide leaf | [`docs/factory-arity.md`](docs/factory-arity.md) |
| PS k² sub-factories | [`docs/ps-subfactories.md`](docs/ps-subfactories.md) |
| Poison-TX security model | [`docs/poison-tx.md`](docs/poison-tx.md) |
| Trustless watchtower schema | [`docs/watchtower-trustless-schema.md`](docs/watchtower-trustless-schema.md) |
| Rotation ceremony | [`docs/rotation-ceremony.md`](docs/rotation-ceremony.md) |
| JIT channels + rollback | [`docs/jit-and-rollback.md`](docs/jit-and-rollback.md) |
| LSP operator guide | [`docs/lsp-operator-guide.md`](docs/lsp-operator-guide.md) |
| Mainnet runbook | [`docs/mainnet-runbook.md`](docs/mainnet-runbook.md) |
| Client / user guide | [`docs/client-user-guide.md`](docs/client-user-guide.md) |
| Testnet4 quickstart | [`docs/testnet4-quickstart.md`](docs/testnet4-quickstart.md) |
| Release process | [`docs/release-process.md`](docs/release-process.md) |

## Architecture sketch

A SuperScalar factory is a tree-shaped Bitcoin transaction graph held by the LSP and N clients in an N-of-N MuSig2 keyagg. Decker–Wattenhofer state layers let any participant unilaterally exit by broadcasting a chain of decrementing-`nSequence` transactions. Lightning channels live at the leaves. The LSP coordinates the multi-party ceremony but cannot move funds unilaterally.

```
                       factory_funding_tx (N-of-N MuSig2)
                                  │
                          kickoff_root + state_root
                                  │
                ┌─────────────────┴─────────────────┐
              kickoff_L1                          state_L1
                │                                    │
        ┌───────┴───────┐                    (next state if rolled)
     leaf_A          leaf_B
        │              │
   channel_outputs   channel_outputs
        │              │
    [HTLCs]         [HTLCs]
```

In a PS (Pseudo-Spilman) configuration, leaves chain advance by appending new states to a per-leaf chain (no nSequence decrement). In a sub-factory configuration (k≥2 clients per leaf), each leaf wraps a smaller sub-factory whose state advances independently.

## Modules

| Module | Source | What it does |
|---|---|---|
| Factory state | `src/factory.c` | DW state machine, MuSig2 keyagg, tree construction |
| Channels | `src/channel.c` | BOLT-2 commitment, HTLC, force-close |
| LSP runtime | `src/lsp_channels.c`, `tools/superscalar_lsp.c` | Multi-client ceremony, routing, demo flows |
| Client runtime | `src/client.c`, `tools/superscalar_client.c` | Wallet, peer connection, ceremony participation |
| Watchtower | `src/watchtower.c`, `tools/superscalar_watchtower.c` | Trustless WT, pre-signed response broadcast |
| Persistence | `src/persist.c`, `src/persist_wt.c` | SQLite schema, migrations, crash recovery |
| Wire codec | `src/wire.c`, `include/superscalar/wire.h` | BOLT framing, MuSig ceremony opcodes |
| Crypto | `src/musig.c`, secp256k1-zkp | MuSig2 (BIP-327 stateless), Schnorr, taproot |

## Known limitations

- **Mainnet support** requires explicit `--accept-risk-mainnet` until v0.3.
- **N=128** factory scale validated in regtest; testnet4 validation deferred to v0.3.
- **Windows binaries** not built (POSIX-only paths in regtest + signal handling); contributions welcome.
- **CLN bLIP-56 plugin** lives in a separate [`superscalar-cln`](https://github.com/8144225309/superscalar-cln) repo and is not built here.
- **Splice support** has the BOLT-2 wire codec but the runtime state machine is a stub (`#210`).

## Security

Found a vulnerability? See [`SECURITY.md`](SECURITY.md). Please **do not** open a public issue for security-sensitive matters.

The trustless watchtower is the v0.2.0 headline feature — a compromised standalone `superscalar_watchtower` cannot read revocation secrets. Verify in one command:

```bash
nm -D --defined-only build/superscalar_watchtower | grep -E "persist_load_(basepoints|revocations_flat|channel_for_watchtower|flat_secrets|commitment_sig)"
# Expected: empty output
```

See [`docs/watchtower-trustless-schema.md`](docs/watchtower-trustless-schema.md) for the trust model.

## Contributing

PRs welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md) for the development workflow, code style, and review process. Releases follow the procedure in [`docs/release-process.md`](docs/release-process.md).

For design discussion, the [delvingbitcoin thread](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories-with-pseudo-spilman-leaves/1242) is the canonical venue.

## License

MIT. See [`LICENSE`](LICENSE).

## Related projects

- [SuperScalar CLN bridge](https://github.com/8144225309/superscalar-cln) — bLIP-56 plugin to hybrid-route between SuperScalar and a Core Lightning node
- [superscalar.win](https://superscalar.win) — public-facing project site
