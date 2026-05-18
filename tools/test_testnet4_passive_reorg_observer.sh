#!/usr/bin/env bash

# Self-respawn in own session so systemd-logind cleanup on SSH session end
# doesn't kill us mid-run (lesson from 2026-05-18 dual #112/#189 deaths).
# Skip if already respawned or if running interactively (stdin is a tty).
if [ -z "${_SS_TESTNET4_DETACHED:-}" ] && [ ! -t 0 ]; then
    export _SS_TESTNET4_DETACHED=1
    exec setsid "$0" "$@"
fi

# test_testnet4_passive_reorg_observer.sh — long-running passive observer
# that records any natural testnet4 reorg the standalone watchtower
# detects.
#
# The watchtower's reorg detection logic was validated synthetically on
# regtest (test_regtest_same_height_reorg.sh — forces a same-height
# reorg via bitcoin-cli invalidateblock + remine).  This runner is the
# real-chain counterpart: just let the WT run on testnet4 indefinitely
# and log every reorg it observes naturally.
#
# Designed to run for hours-to-days.  Run via tmux or nohup; check
# `/tmp/passive_reorg_observer.log` periodically.
#
# Usage: bash tools/test_testnet4_passive_reorg_observer.sh [WT_DB]
# WT_DB defaults to any LSP-side persisted DB (auto-detects most recent).

set -uo pipefail

BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"
WT_BIN="$BUILD_DIR/superscalar_watchtower"
WT_LOG="${WT_LOG:-/tmp/passive_reorg_observer.log}"
WT_DB="${1:-}"

if [ -z "$WT_DB" ]; then
    # Use the most-recent campaign LSP DB so the WT has entries to watch
    WT_DB=$(ls -t /tmp/ss_t4_*.db 2>/dev/null | head -1)
    if [ -z "$WT_DB" ]; then
        echo "FAIL: no LSP DB found; pass one explicitly"
        exit 1
    fi
fi

echo "=== Passive testnet4 reorg observer ==="
echo "  WT binary: $WT_BIN"
echo "  WT DB    : $WT_DB"
echo "  WT log   : $WT_LOG"
echo "  Started  : $(date -u)"
echo
echo "Notes:"
echo "  - The WT logs every block height tick + any reorg event."
echo "  - Run for as long as you can; testnet4 reorgs are unscheduled but"
echo "    do occur (typically 1-2 per day across the testnet4 network)."
echo "  - To stop: pkill -f superscalar_watchtower (this runner uses"
echo "    --poll-interval 30 for low overhead)."
echo

"$WT_BIN" \
    --network testnet4 \
    --db "$WT_DB" \
    --poll-interval 30 \
    --rpcuser testnet4rpc \
    --rpcpassword testnet4rpcpass123 \
    --rpcport 48332 \
    2>&1 | tee -a "$WT_LOG"
