#!/usr/bin/env bash
# Auto-restart wrapper for passive observer — survives WT signal-induced exits.
WT_DB="${1:-/tmp/ss_t4_observer_seed.db}"
WT_BIN="/root/SuperScalar/build-release/superscalar_watchtower"
WT_LOG="${WT_LOG:-/tmp/passive_reorg_observer.log}"
RESTART_COUNT=0
echo "=== Passive WT wrapper started $(date -u) ===" | tee -a "$WT_LOG"
while true; do
    RESTART_COUNT=$((RESTART_COUNT + 1))
    echo "[wrapper] WT start #$RESTART_COUNT at $(date -u)" | tee -a "$WT_LOG"
    "$WT_BIN" \
        --network testnet4 \
        --db "$WT_DB" \
        --poll-interval 30 \
        --rpcuser testnet4rpc \
        --rpcpassword testnet4rpcpass123 \
        --rpcport 48332 \
        2>&1 | tee -a "$WT_LOG" || true
    echo "[wrapper] WT exited after $(($(date +%s) - $(date -d '1 minute ago' +%s) )) iter, restarting in 10s" | tee -a "$WT_LOG"
    sleep 10
done
