#!/usr/bin/env bash
# regtest_hifee_helpers.sh — high-fee mempool simulator for proving trustless
# recourse confirms UNDER FEE PRESSURE (trustless-hardening test plan §5).
#
# Why this exists: every breach/penalty test to date ran on a near-empty, low-fee
# regtest mempool, so the watchtower fee-bump path is wired-but-unproven. A fixed-
# feerate penalty that gets stuck under congestion misses its CSV/CLTV deadline and
# the cheater wins (task #52 R1). These primitives let a test (a) stall a penalty
# under realistic fee pressure and (b) assert it still confirms before the deadline.
#
# ANTI-VACUITY DISCIPLINE: a high-fee test MUST first prove a NON-bumping penalty
# genuinely stays stuck in the same environment (the control leg), or "the bump
# saved it" is a vacuous pass. Use assert_unconfirmed on the control, then
# assert_confirmed_by on the bumped main leg. Mirrors the SS_REORG_REFIRE
# orphan-verification lesson in the rigor audit.
#
# Two stall mechanisms (use per test):
#   - SURGICAL: stall_tx (prioritisetransaction) deterministically deprioritises ONE
#     txid for mining. No flood, no flakiness — ideal to demonstrate "this exact
#     penalty never gets mined" (the #52 gap demo).
#   - SUSTAINED: flood_fee_floor keeps the mempool saturated above the penalty's
#     feerate so it's crowded out of every block — realistic congestion. Requires a
#     small-block node (with_hifee_node, -blockmaxweight) or it's swallowed by the 4MB default.
#
# Usage: source after BCLI is defined. All fns take BCLI as needed; pumps write a
# sentinel PID file so stop_fee_floor can kill them (pattern mirrors start_reorg_watcher).

_HIFEE_PUMP_PIDFILE="${TMPDIR:-/tmp}/.hifee_pump.pid"

hifee_log() { printf '\033[35m[hifee]\033[0m %s\n' "$*"; }

# --- SURGICAL stall: deprioritise a specific txid so miners never select it ---
# stall_tx BCLI TXID   — make TXID effectively unmineable on this node
stall_tx() {
    local bcli="$1" txid="$2"
    $bcli prioritisetransaction "$txid" 0 -10000000000 >/dev/null 2>&1 \
        && hifee_log "stalled $txid (prioritise -10e9)" \
        || hifee_log "WARN: prioritisetransaction failed for $txid"
}
# unstall_tx BCLI TXID — undo the stall (restore normal priority)
unstall_tx() {
    local bcli="$1" txid="$2"
    $bcli prioritisetransaction "$txid" 0 10000000000 >/dev/null 2>&1
    hifee_log "unstalled $txid"
}

# --- SUSTAINED congestion: keep the mempool saturated above RATE sat/vB ---
# flood_fee_floor RATE_SATVB WALLET BCLI   — background pump; replenishes per loop.
# Pre-fund WALLET with many coinbase outputs first. Self-spends recycle outputs.
flood_fee_floor() {
    local rate="$1" w="$2" bcli="$3"
    ( while :; do
        local cnt; cnt=$($bcli getmempoolinfo 2>/dev/null | grep -oE '"size":[ ]*[0-9]+' | grep -oE '[0-9]+' | head -1)
        cnt=${cnt:-0}
        while [ "$cnt" -lt 40 ]; do
            local addr; addr=$($bcli -rpcwallet="$w" getnewaddress 2>/dev/null) || break
            $bcli -rpcwallet="$w" -named sendtoaddress address="$addr" amount=0.0005 \
                fee_rate="$rate" subtractfeefromamount=true >/dev/null 2>&1 || break
            cnt=$((cnt+1))
        done
        sleep 1
      done ) &
    echo $! > "$_HIFEE_PUMP_PIDFILE"
    hifee_log "fee-floor pump started @ ${rate} sat/vB (pid $(cat "$_HIFEE_PUMP_PIDFILE"))"
}
stop_fee_floor() {
    [ -f "$_HIFEE_PUMP_PIDFILE" ] || return 0
    local pid; pid=$(cat "$_HIFEE_PUMP_PIDFILE")
    kill "$pid" 2>/dev/null; kill -9 "$pid" 2>/dev/null
    rm -f "$_HIFEE_PUMP_PIDFILE"
    hifee_log "fee-floor pump stopped"
}

# --- assertions ---
# tx_confs BCLI TXID -> echoes confirmations (0 if in mempool, empty if unknown)
tx_confs() {
    local bcli="$1" txid="$2"
    $bcli getrawtransaction "$txid" true 2>/dev/null | grep -oE '"confirmations":[ ]*[0-9]+' | grep -oE '[0-9]+' | head -1
}
# assert_unconfirmed BCLI TXID  — PASS if TXID exists but is NOT confirmed (control leg)
assert_unconfirmed() {
    local bcli="$1" txid="$2" c; c=$(tx_confs "$bcli" "$txid")
    if [ -z "$c" ] || [ "$c" -eq 0 ]; then
        hifee_log "OK: $txid still unconfirmed (control stall is real)"; return 0
    fi
    hifee_log "VACUOUS-FAIL: $txid confirmed ($c) despite stall — simulator not biting"; return 78
}
# assert_confirmed_by BCLI TXID DEADLINE_H — PASS if confirmed at height <= DEADLINE_H
assert_confirmed_by() {
    local bcli="$1" txid="$2" deadline="$3"
    local raw cur conf txh
    raw=$($bcli getrawtransaction "$txid" true 2>/dev/null)
    conf=$(echo "$raw" | grep -oE '"confirmations":[ ]*[0-9]+' | grep -oE '[0-9]+' | head -1)
    [ -n "$conf" ] && [ "$conf" -ge 1 ] || { hifee_log "FAIL: $txid never confirmed"; return 1; }
    cur=$($bcli getblockcount 2>/dev/null)
    txh=$((cur - conf + 1))
    if [ "$txh" -le "$deadline" ]; then
        hifee_log "OK: $txid confirmed @${txh} <= deadline ${deadline}"; return 0
    fi
    hifee_log "FAIL: $txid confirmed @${txh} AFTER deadline ${deadline} (recourse lost the race)"; return 1
}

# --- dedicated small-block node for SUSTAINED congestion tests ---
# with_hifee_node DATADIR PORT RPCPORT BITCOIND_BIN CONF   — start a -blockmaxweight=8000
# regtest instance so a tx flood actually crowds out the penalty. Caller tears down.
# Returns the BCLI string for the instance on fd via echo (BCLI_HIFEE=...).
start_hifee_node() {
    local datadir="$1" port="$2" rpcport="$3" bin="$4" conf="$5"
    mkdir -p "$datadir"
    "$bin" -regtest -datadir="$datadir" -port="$port" -rpcport="$rpcport" \
        -blockmaxweight=8000 -maxmempool=50 -fallbackfee=0.0001 \
        -conf="$conf" -daemon >/dev/null 2>&1 || true
    sleep 3
    hifee_log "hifee node up: datadir=$datadir rpcport=$rpcport blockmaxweight=8000"
    echo "bitcoin-cli -regtest -datadir=$datadir -rpcport=$rpcport"
}
stop_hifee_node() {
    local datadir="$1" rpcport="$2"
    bitcoin-cli -regtest -datadir="$datadir" -rpcport="$rpcport" stop >/dev/null 2>&1 || true
    sleep 2
    hifee_log "hifee node stopped ($datadir)"
}
