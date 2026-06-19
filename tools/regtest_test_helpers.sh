#!/usr/bin/env bash
# regtest_test_helpers.sh — shared helpers for test_regtest_*.sh runners.
#
# Source with:
#   . "$(dirname "$(realpath "$0")")"/regtest_test_helpers.sh
#
# Requires BCLI to be set to a bitcoin-cli invocation against the target
# network/conf BEFORE sourcing.
#
# Exports:
#   start_reorg_watcher LOG_PATH         — background-poll getbestblockhash + height
#                                          and log same-height-or-rewind reorgs
#                                          to LOG_PATH. Echoes the watcher PID.
#   assert_vout_distribution TXID EXPECT — decode TXID via bitcoin-cli, compare
#                                          vouts to EXPECT (space-separated sats
#                                          per vout, in order). Returns 0 on
#                                          match, 1 on mismatch.
#   sum_vouts TXID                       — print sum of vout amounts in sats.
#   require_node_up                      — assert the node ($BCLI) is reachable; else exit 78
#                                          with a clear message (a dead node otherwise fails
#                                          every downstream test as a cryptic "LSP died").
#   pen_recovers_most TXID [PCT]         — assert sum(outputs) >= PCT% (default 90) of
#                                          sum(input prevout values): the penalty/sweep
#                                          recovers ~all it spends (catches fee-burn/value
#                                          loss). Echoes "OK|LOW|UNKNOWN <out> <in>".

# --- require_node_up ---
# A dead bitcoind makes every downstream test fail as a cryptic "LSP died". Call this right
# after BCLI is set (post-source) to fail loudly + early instead.
require_node_up() {
    $BCLI getblockcount >/dev/null 2>&1 && return 0
    echo "FATAL: regtest node not reachable via [$BCLI] — start bitcoind-regtest before running." >&2
    exit 78
}

# --- pen_recovers_most TXID [PCT] ---
# Outcome-amount check (audit F1/F3): the penalty/sweep must pay out ~all the value it sweeps.
# Looks up each input's prevout value; asserts sum(outputs) >= PCT% of sum(inputs). Default 90
# (regtest sweep fees are <2%, so 90% is generous + param-robust — it scales with the actual
# swept value, unlike an absolute floor). Returns 1 on LOW/UNKNOWN.
pen_recovers_most() {
    local txid="${1:?usage: pen_recovers_most TXID [PCT]}" pct="${2:-90}" praw out insum=0 pair pt pv val
    praw=$($BCLI getrawtransaction "$txid" true 2>/dev/null) || return 1
    out=$(printf '%s' "$praw" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(sum(int(round(v["value"]*1e8)) for v in d["vout"]))' 2>/dev/null)
    for pair in $(printf '%s' "$praw" | python3 -c 'import json,sys;d=json.load(sys.stdin);print("\n".join(v["txid"]+":"+str(v["vout"]) for v in d["vin"]))' 2>/dev/null); do
        pt=${pair%:*}; pv=${pair#*:}
        val=$($BCLI getrawtransaction "$pt" true 2>/dev/null | python3 -c "import json,sys;print(int(round(json.load(sys.stdin)['vout'][$pv]['value']*1e8)))" 2>/dev/null)
        insum=$((insum + ${val:-0}))
    done
    [ "${insum:-0}" -gt 0 ] || { echo "UNKNOWN ${out:-0} 0"; return 1; }
    if [ "${out:-0}" -ge "$(( insum * pct / 100 ))" ]; then echo "OK ${out:-0} $insum"; return 0; else echo "LOW ${out:-0} $insum"; return 1; fi
}

# --- start_reorg_watcher LOG_PATH ---
# Polls every 2s. Detects:
#   1. Height regression (height_now < last_height) — classic reorg
#   2. Same-height block-hash change (best_hash_now != last_hash_at_height)
# Both written as a one-line event to LOG_PATH.
#
# Implementation note: the watcher detaches its stdin/stdout from the
# calling shell so `REORG_PID=$(start_reorg_watcher ...)` doesn't block
# on the inherited fd. The watcher's PID is written to a sentinel file
# and the function reads it back.
start_reorg_watcher() {
    local log="${1:?usage: start_reorg_watcher LOG_PATH}"
    : > "$log"
    local pidfile="${log}.watcher.pid"
    (
        last_height=-1
        last_hash=""
        while true; do
            h=$($BCLI getblockcount 2>/dev/null) || { sleep 2; continue; }
            bh=$($BCLI getbestblockhash 2>/dev/null) || { sleep 2; continue; }
            if [ -n "$last_hash" ]; then
                if [ "$h" -lt "$last_height" ]; then
                    echo "$(date -u +%FT%TZ) HEIGHT_REGRESSION $last_height -> $h" >> "$log"
                elif [ "$h" = "$last_height" ] && [ "$bh" != "$last_hash" ]; then
                    echo "$(date -u +%FT%TZ) SAME_HEIGHT_REORG height=$h $last_hash -> $bh" >> "$log"
                fi
            fi
            last_height=$h
            last_hash=$bh
            sleep 2
        done
    ) </dev/null >/dev/null 2>&1 &
    local pid=$!
    echo "$pid" > "$pidfile"
    echo "$pid"
}

# --- sum_vouts TXID ---
sum_vouts() {
    local txid="${1:?usage: sum_vouts TXID}"
    $BCLI getrawtransaction "$txid" 1 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    print(sum(int(round(v["value"] * 1e8)) for v in d.get("vout", [])))
except Exception:
    print(0)
'
}

# --- assert_vout_distribution TXID "v0 v1 ..." ---
# EXPECT is a space-separated list of expected sat amounts per vout, in order.
assert_vout_distribution() {
    local txid="${1:?usage: assert_vout_distribution TXID EXPECT}"
    local expect="${2:?usage: assert_vout_distribution TXID EXPECT}"
    local actual
    actual=$($BCLI getrawtransaction "$txid" 1 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    print(" ".join(str(int(round(v["value"] * 1e8))) for v in d.get("vout", [])))
except Exception:
    print("")
')
    if [ "$actual" = "$expect" ]; then
        echo "  vout audit OK [$txid]: $actual"
        return 0
    else
        echo "  vout audit FAIL [$txid]: actual=[$actual] expected=[$expect]"
        return 1
    fi
}

# --- print_vouts TXID ---
# Diagnostic only — show vout breakdown without asserting.
print_vouts() {
    local txid="${1:?usage: print_vouts TXID}"
    $BCLI getrawtransaction "$txid" 1 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    print(f"  tx {sys.argv[1][:16]}...  confs={d.get(\"confirmations\", 0)}  vouts:")
    for i, v in enumerate(d.get("vout", [])):
        print(f"    [{i}] {int(round(v[\"value\"] * 1e8))} sats")
except Exception:
    pass
' "$txid"
}
