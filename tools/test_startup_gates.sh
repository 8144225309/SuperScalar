#!/usr/bin/env bash
# Start-up refusals of the daemon binaries.
#
# Usage: tools/test_startup_gates.sh [BUILD_DIR]     (default: build)
#
# Runs superscalar_lsp, superscalar_client and superscalar_watchtower with
# command lines that must be refused before the daemon does anything, and
# checks the exit status and the message.  It covers what the unit tests of
# network_startup_gates() cannot: that each binary passes its own flags to the
# check and exits when it fails, for both spellings of mainnet.
#
# No bitcoind is needed and none is contacted: every case must exit at the
# start-up check.  As a second line of defence every command points the RPC
# at port 1, where nothing listens, and has a time limit.
set -u

B=$(cd "${1:-build}" 2>/dev/null && pwd) || { echo "FAIL: build directory not found"; exit 1; }
LSP=$B/superscalar_lsp
CLIENT=$B/superscalar_client
WT=$B/superscalar_watchtower
KEY=1111111111111111111111111111111111111111111111111111111111111111
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
# Every command runs with an empty HOME and an empty working directory, so a
# file created in a default location is seen as well as one at a given path.
mkdir "$TMP/home" "$TMP/cwd" "$TMP/files"
F=$TMP/files

fail=0
n=0

# expect_refusal "<text expected in the output>" command...
expect_refusal() {
    local want=$1; shift
    n=$((n + 1))
    local out rc
    out=$(cd "$TMP/cwd" && HOME="$TMP/home" XDG_CONFIG_HOME="$TMP/home/.config" \
          XDG_DATA_HOME="$TMP/home/.local/share" timeout -s KILL 30 "$@" --rpcport 1 2>&1)
    rc=$?
    if [ "$rc" -ne 1 ] || ! printf '%s' "$out" | grep -qF -- "$want"; then
        echo "FAIL: expected exit 1 with \"$want\" from: $*"
        echo "      exit status $rc; output:"
        printf '%s\n' "$out" | head -5 | sed 's/^/      | /'
        fail=1
    fi
}

for bin in "$LSP" "$CLIENT" "$WT"; do
    [ -x "$bin" ] || { echo "FAIL: $bin not found (build first)"; exit 1; }
done

for NET in mainnet bitcoin; do
    # Risk acknowledgement: all three daemons.
    expect_refusal "mainnet operation refused" "$LSP" --network "$NET"
    expect_refusal "mainnet operation refused" "$CLIENT" --network "$NET" --keyfile "$F/none.key"
    expect_refusal "mainnet operation refused" "$WT" --network "$NET" --wt-db "$F/wt.db"

    # Secret key on the command line: LSP and client.
    expect_refusal "--seckey is refused on mainnet" \
        "$LSP" --network "$NET" --i-accept-the-risk --seckey "$KEY"
    expect_refusal "--seckey is refused on mainnet" \
        "$CLIENT" --network "$NET" --i-accept-the-risk --seckey "$KEY" --db "$F/c.db"

    # Test scaffolding in the arguments and in the environment: all three.
    expect_refusal "refused on mainnet" "$LSP" --network "$NET" --i-accept-the-risk --cheat-daemon
    expect_refusal "refused on mainnet" "$CLIENT" --network "$NET" --i-accept-the-risk --cheat-daemon
    expect_refusal "refused on mainnet" "$CLIENT" --network "$NET" --i-accept-the-risk --test-allow-tree-advance
    expect_refusal "--enable-rotation-experimental is refused on mainnet" \
        "$CLIENT" --network "$NET" --i-accept-the-risk --enable-rotation-experimental
    expect_refusal "refused on mainnet" \
        "$WT" --network "$NET" --i-accept-the-risk --wt-db "$F/wt.db" --test-flag
    expect_refusal "refused on mainnet" \
        env SS_CHEAT_DUST_RACE=1 "$LSP" --network "$NET" --i-accept-the-risk
    expect_refusal "refused on mainnet" \
        env SUPERSCALAR_CRASH_ALLOW=1 "$CLIENT" --network "$NET" --i-accept-the-risk
    expect_refusal "refused on mainnet" \
        env SS_KILL_AT=1 "$WT" --network "$NET" --i-accept-the-risk --wt-db "$F/wt.db"

    # Experimental JIT channels: the LSP opt-in.
    expect_refusal "--enable-jit-experimental is refused on mainnet" \
        "$LSP" --network "$NET" --i-accept-the-risk --enable-jit-experimental

    # Experimental factory rotation: the LSP opt-in, and the test mode that
    # implies it.
    expect_refusal "--enable-rotation-experimental is refused on mainnet" \
        "$LSP" --network "$NET" --i-accept-the-risk --enable-rotation-experimental
    expect_refusal "--test-rotation is test/cheat scaffolding and is refused on mainnet" \
        "$LSP" --network "$NET" --i-accept-the-risk --test-rotation

    # A tree with nodes that cannot be fee-bumped: tests only.
    expect_refusal "--allow-anchorless-tree is refused on mainnet" \
        "$LSP" --network "$NET" --i-accept-the-risk --allow-anchorless-tree

    # Persistent state: --db for LSP and client, --wt-db for the LSP.
    expect_refusal "mainnet requires --db" "$LSP" --network "$NET" --i-accept-the-risk
    expect_refusal "mainnet requires --db" \
        "$CLIENT" --network "$NET" --i-accept-the-risk --keyfile "$F/none.key"
    expect_refusal "mainnet requires --wt-db" \
        "$LSP" --network "$NET" --i-accept-the-risk --db "$F/l.db"
done

# Chain names that are not supported.
expect_refusal "unknown --network" "$LSP" --network livenet
expect_refusal "unknown --network" "$CLIENT" --network livenet --seckey "$KEY"
expect_refusal "unknown --network" "$WT" --network livenet --wt-db "$F/wt.db"

# The client on a non-regtest chain needs a pinned LSP key, and says so before
# it creates the keyfile it was pointed at.
expect_refusal "--lsp-pubkey required" \
    "$CLIENT" --network signet --seckey "$KEY" --rpcuser u --rpcpassword p
expect_refusal "--lsp-pubkey required" \
    "$CLIENT" --network signet --keyfile "$F/new.key" --rpcuser u --rpcpassword p

# Async rotation is a rotation option: it needs the rotation opt-in.
expect_refusal "--async-rotation needs --enable-rotation-experimental" \
    "$LSP" --network regtest --async-rotation

# The well-known lookup is a direct connection: refused when Tor is in use.
expect_refusal "cannot be used with --tor-proxy" \
    "$CLIENT" --network regtest --seckey "$KEY" --lsp 127.0.0.1 \
    --tor-proxy 127.0.0.1:1 --tor-only
expect_refusal "cannot be used with --tor-proxy" \
    "$CLIENT" --network regtest --seckey "$KEY" --lsp 127.0.0.1 --tor-proxy 127.0.0.1:1

# No case may have created anything: not at a path it was given, not in its
# working directory, not under HOME.
created=$(find "$TMP" -mindepth 2 | sed "s|^$TMP/||")
if [ -n "$created" ]; then
    echo "FAIL: a refused start-up created files: $(printf '%s' "$created" | tr '\n' ' ')"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "start-up gates: FAILED"
    exit 1
fi
echo "start-up gates: all $n refusals OK"
