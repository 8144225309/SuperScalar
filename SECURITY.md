# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SuperScalar, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

Email your findings to the maintainer via GitHub's private vulnerability reporting:

1. Go to https://github.com/8144225309/SuperScalar/security/advisories
2. Click "New draft security advisory"
3. Fill in the details and submit

Alternatively, contact the maintainer directly through GitHub.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected files/functions if known
- Potential impact (fund loss, denial of service, information disclosure, etc.)
- Suggested fix if you have one

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 1 week
- **Fix**: Depends on severity — critical issues (fund-loss risk) are prioritized immediately

### Scope

The following are in scope:

- All code in `src/` and `include/` (cryptography, channel state, wire protocol, persistence, transport)
- Key material handling (`keyfile.c`, `backup.c`, `bip39.c`, `hd_key.c`, `noise.c`)
- Subprocess execution (`regtest.c`)
- The LSP, client, bridge, and watchtower binaries (`tools/`)

The following are out of scope:

- Demo scripts and test tooling (`tools/run_demo.sh`, `tools/test_orchestrator.py`, etc.)
- The web dashboard (`tools/dashboard.py`) — it reads data only and is not designed for public exposure
- Third-party dependencies (secp256k1-zkp, cJSON, OpenSSL) — report those to their respective projects

## Current Security Status

SuperScalar is pre-1.0 software. It has not been externally audited. Use on signet/testnet for testing only. Mainnet use is not recommended until a formal security audit is completed.

No external security audit has been performed yet. Use on mainnet at your own risk.

## Security Features

- Encrypted keyfiles (PBKDF2-HMAC-SHA256, 600K iterations)
- Encrypted backup/restore (PBKDF2 + ChaCha20-Poly1305 AEAD)
- BIP39 mnemonic seed recovery
- Noise NK authenticated encrypted transport
- Per-IP connection rate limiting
- Shell-free subprocess execution (fork/execvp on POSIX)
- Client-side and standalone watchtowers with automatic penalty broadcast
- Revocation-based channel security (Poon-Dryja)
- Shachain-based factory invalidation with burn path
