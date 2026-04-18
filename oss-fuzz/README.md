# OSS-Fuzz integration

This directory holds the files required to onboard SuperScalar into
[Google's OSS-Fuzz](https://google.github.io/oss-fuzz/) continuous
fuzzing service.

## What's here

- `build.sh` — invoked by OSS-Fuzz's build container; configures CMake with
  `ENABLE_FUZZING=ON` and copies the resulting fuzz binaries + seed corpora
  to `$OUT`.
- `Dockerfile` — base-builder image with SuperScalar's build dependencies.
- `project.yaml` — project metadata (contacts, sanitizers, engines).
- `corpora/<target>/` (optional) — seed inputs that accelerate discovery.

## Fuzz targets

The in-repo fuzz harnesses in `../fuzz/` are built unchanged:

| Target | What it fuzzes |
|---|---|
| `fuzz_wire_recv` | `wire_recv` parser (framed JSON over TCP) |
| `fuzz_wire_parse_json` | `wire_parse_json` (length-prefixed cJSON) |
| `fuzz_tx_sighash` | BIP-341 taproot sighash computation |
| `fuzz_persist_load` | SQLite-backed factory/channel deserialization |
| `fuzz_hex_decode` | hex decode with various length and content |
| `fuzz_noise_handshake` | Noise XK/NK handshake state machine |
| `fuzz_aead_decrypt` | ChaCha20-Poly1305 decryption |

## Onboarding procedure

1. Fork [`google/oss-fuzz`](https://github.com/google/oss-fuzz).
2. Create `projects/superscalar/` and copy this directory's contents into it.
3. Submit a PR to `google/oss-fuzz` following their
   [new-project guide](https://google.github.io/oss-fuzz/getting-started/new-project-guide/).
4. Once merged, OSS-Fuzz builds and runs the fuzzers 24/7. Bug reports
   go to the email addresses in `project.yaml`.

Nothing in this directory affects normal CI — it only matters once
OSS-Fuzz is pointing at the repo.
