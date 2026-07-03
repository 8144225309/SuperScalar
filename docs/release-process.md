# Release Process

This document describes the SuperScalar release process. It is adapted from
Bitcoin Core's `doc/release-process.md` to match SuperScalar's scope (smaller
team, no translation pipeline, CMake-based build, single Tier-1 platform).

Releases follow the pattern `vMAJOR.MINOR.PATCH`:

- **Major / minor releases** cut a release candidate (`-rc1`, `-rc2`, …) first,
  soak for 1–2 weeks while operators test, fix bugs as discovered, and only
  promote `-final` after the soak.
- **Patch releases** for emergent bugs may skip the RC cycle when scope is
  surgical and the regression has been reproduced on regtest.

## Branch policy

- `main` is always releasable. Feature work merges via PR.
- A release branch (`v0.2.x`) is cut from `main` at the time of the first RC
  for a new minor/major release. Subsequent patch releases on that minor track
  cherry-pick fixes from `main` onto the release branch.
- The release branch is protected: only the release manager (or a delegate)
  pushes tags.

## Roles

| Role | Responsibilities |
|---|---|
| **Release Manager (RM)** | Owns the schedule, cuts RCs, signs tags, publishes binaries, writes the release-day announcement. |
| **Reviewer(s)** | Validate RC binaries on at least one Tier-1 platform; report regressions before `-final`. |

## Release checklist

The checklist below is intended to be copy-pasted into a GitHub issue at the
start of each release cycle so progress is visible.

### Pre-RC

- [ ] All blocking issues / PRs labeled `release-blocker` for the target
      release are merged into `main`.
- [ ] `CHANGELOG.md` reflects every user-visible change since the previous
      tag. Move the `## Unreleased` section to `## vX.Y.Z — YYYY-MM-DD` (date
      is the planned release date, not the RC cut date).
- [ ] `docs/release-notes/release-notes-X.Y.Z.md` exists and has been reviewed.
- [ ] `README.md` reflects the new release (no stale phase-N badges, no PR
      number lists from intermediate development).
- [ ] Regtest sweep passes on `main`: `tools/regtest_full_regression_v020.sh`.
- [ ] Crash-injection drill matrix passes 16/16 reachable: `tools/test_regtest_crash_drill_matrix.sh`.
- [ ] Critical-path testnet4 evidence captured for at least:
      - N=64 multi-arity PS lifecycle (shape 3c V2 in `docs/testnet4-phase5/`)
      - N=64 PS-k=2 full-features run (shape 3f V1)
- [ ] All N=64 force-close trees demonstrated to broadcast cleanly under
      BIP-68 CSV-wait gating.

### Cutting an RC

- [ ] Create release branch (first RC only): `git checkout -b vX.Y.x` from
      `main`.
- [ ] Bump version in CMakeLists.txt + any user-facing version strings to
      `X.Y.Z-rcN`.
- [ ] Tag `vX.Y.Z-rcN` (signed): `git tag -s vX.Y.Z-rcN -m "vX.Y.Z release
      candidate N"` — see "Tag signing" below.
- [ ] Push branch + tag: `git push origin vX.Y.x vX.Y.Z-rcN`.
- [ ] Verify CI green on the tag.
- [ ] Verify release.yml workflow built binaries for every supported
      platform and uploaded them to the draft GitHub Release.
- [ ] Generate `SHA256SUMS` and detached signature `SHA256SUMS.asc` (see
      "Hashing and signing" below). Upload to the Release.
- [ ] Publish the GitHub Release as a **pre-release** (not "latest"). Title:
      `vX.Y.Z-rcN`.
- [ ] Announce RC: short note in delvingbitcoin thread + project channels.
      Request operator soak testing.

### RC soak

- [ ] Operators run the RC against their own testnet/signet/regtest
      environments for ≥ 1 week (minor releases) or ≥ 2 weeks (major
      releases).
- [ ] Any regression filed against the RC tag triggers a new commit on the
      release branch and a new RC (`-rcN+1`). The previous RC is left
      published but no longer recommended.
- [ ] If no regressions during the soak period, promote to `-final`.

### Cutting `-final`

- [ ] All RC-fix commits cherry-picked / merged onto the release branch.
- [ ] Final version bump in CMakeLists.txt to `X.Y.Z` (drop `-rcN`).
- [ ] Final `CHANGELOG.md` date update if the release date moved.
- [ ] Tag `vX.Y.Z` (signed): `git tag -s vX.Y.Z -m "vX.Y.Z"`.
- [ ] Push the tag: `git push origin vX.Y.Z`.
- [ ] Verify release.yml built every platform.
- [ ] Generate `SHA256SUMS` + `SHA256SUMS.asc`; upload to Release.
- [ ] Mark the GitHub Release as "Latest release" (not pre-release).
- [ ] Announcement post (delvingbitcoin + project channels) with:
      - one-paragraph summary of what's in the release
      - link to release notes
      - SHA256 of each artifact
      - your GPG key fingerprint for tag verification
- [ ] Open a `## Unreleased` section in `CHANGELOG.md` on `main` for the
      next cycle.
- [ ] Sat-balance ledger audit on any testnet wallets used during the
      release campaign — sweep back to the canonical operator wallet.

## Tag signing

Release tags MUST be signed with a GPG key whose fingerprint has been
published to the project's primary contact channels. To configure:

```
git config --global user.signingkey <YOUR-GPG-KEY-FINGERPRINT>
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

For an air-gapped signing flow (recommended for v0.2.0+), the RM creates the
tag locally and pushes it; the rest of the team validates via:

```
git verify-tag vX.Y.Z
```

## Hashing and signing release artifacts

After `release.yml` has uploaded all platform binaries to the GitHub Release
draft:

```
# Download all artifacts attached to the draft Release
gh release download vX.Y.Z --repo 8144225309/SuperScalar -D /tmp/artifacts

# Generate SHA256SUMS in a deterministic order
cd /tmp/artifacts
sha256sum *.tar.gz > SHA256SUMS

# Sign with GPG
gpg --detach-sign --armor SHA256SUMS  # produces SHA256SUMS.asc

# Upload both
gh release upload vX.Y.Z SHA256SUMS SHA256SUMS.asc \
    --repo 8144225309/SuperScalar --clobber
```

Anyone downloading the release can verify integrity:

```
sha256sum -c SHA256SUMS    # checks file hashes
gpg --verify SHA256SUMS.asc SHA256SUMS  # checks signature against RM's key
```

## Build outputs

`.github/workflows/release.yml` builds release artifacts for every supported
platform automatically on Release publish. For v0.2.0 the supported set is:

| Platform | Trigger |
|---|---|
| Linux x86_64 | `build-linux` job |
| Linux ARM64 | `build-linux-arm64` job (QEMU) |
| macOS x86_64 / arm64 | `build-macos` job |

Windows binaries are **not** built (POSIX-only paths + signal handling; see
README "Known limitations"). Each job produces a tarball named
`superscalar-vX.Y.Z-<platform>.tar.gz` containing the four release
binaries (`superscalar_lsp`, `superscalar_client`, `superscalar_bridge`,
`superscalar_watchtower`) plus `README.md`, `LICENSE`, `CHANGELOG.md`, and
`SECURITY.md`.

## Post-release maintenance

- The release branch (`v0.2.x`) remains open for ≥ 1 minor cycle so that
  emergency patch releases can be cut against the released version while
  `main` evolves toward the next minor.
- Security fixes that apply to the released version are backported to the
  release branch and cut as `vX.Y.(Z+1)`. The patch release skips the RC
  cycle when the fix is small and the regression has been reproduced on
  regtest.

## Deprecating older releases

Once two newer minor versions have shipped (e.g. v0.4.0 makes v0.2.x EOL),
the EOL release branch is announced as no longer receiving security
support. The branch is kept on GitHub for historical reference but no
further commits are accepted.
