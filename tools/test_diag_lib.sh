#!/usr/bin/env bash
# test_diag_lib.sh — shared diagnostic helpers for SuperScalar test scripts.
#
# Sourced by test_*.sh.  Provides:
#   diag_setup <TAG>        : prepare per-test diag dir under /tmp/<TAG>_diag/
#   diag_periodic <PID>     : start a 60s-cadence /proc snapshot recorder
#   diag_wait_lsp <PID> <LOG> <TAG>  : safely wait $PID (no set -e short-circuit),
#                                      on non-zero exit runs diag_on_lsp_death,
#                                      sets DIAG_EXIT for caller.
#   diag_on_lsp_death <PID> <LOG> <TAG> <EXIT>  : capture forensics bundle.
#
# Forensics bundle (in /tmp/<TAG>_diag/):
#   exit.txt          numeric exit code + decoded signal name
#   lsp.log.tail      last 100 lines of LSP log
#   lsp.log.sha256    sha of full log
#   journal.txt       journalctl slice across the death window
#   bitcoind.txt      chain tip / mempool / wallet state
#   proc-status.txt   /proc/$PID/status snapshot (best effort post-death)
#   audit-kills.txt   ausearch hits for that pid (signal attribution)
#   timeseries.ndjson per-60s snapshot from diag_periodic (if started)
#
# Reusable. No SuperScalar-specific assumptions in the helpers themselves —
# the test script passes in TAG, LSP_LOG path, etc.

# Never source this twice (idempotent guard)
[ "${_TEST_DIAG_LIB_LOADED:-}" = "1" ] && return 0
_TEST_DIAG_LIB_LOADED=1

diag_setup() {
    local tag="$1"
    DIAG_DIR="/tmp/${tag}_diag"
    mkdir -p "$DIAG_DIR"
    rm -f "$DIAG_DIR"/*.txt "$DIAG_DIR"/*.ndjson "$DIAG_DIR"/lsp.log.* \
          "$DIAG_DIR"/*.stderr 2>/dev/null || true
    echo "diag: forensics dir = $DIAG_DIR"
    # Record service start time so we can slice journal precisely.
    date -u +%Y-%m-%dT%H:%M:%SZ > "$DIAG_DIR/start.txt"
}

# diag_enable_core_dumps
# Lifts the RLIMIT_CORE soft limit and points the kernel core_pattern (best
# effort — needs root for sysctl) at DIAG_DIR so SIGSEGV/SIGABRT leaves a
# core file in the forensics bundle.
diag_enable_core_dumps() {
    ulimit -c unlimited 2>/dev/null || true
    if [ -w /proc/sys/kernel/core_pattern ] 2>/dev/null; then
        echo "${DIAG_DIR}/core.%e.%p.%t" > /proc/sys/kernel/core_pattern 2>/dev/null || true
    fi
    [ -w /proc/sys/kernel/core_uses_pid ] && \
        echo 1 > /proc/sys/kernel/core_uses_pid 2>/dev/null || true
    {
        echo "ulimit_c: $(ulimit -c 2>/dev/null)"
        echo "core_pattern: $(cat /proc/sys/kernel/core_pattern 2>/dev/null)"
    } > "$DIAG_DIR/core_config.txt"
    echo "diag: core dumps -> $DIAG_DIR/core.* (ulimit_c=$(ulimit -c 2>/dev/null))"
}

# diag_stderr_path <name>
# Returns a per-name stderr path under DIAG_DIR.  Use like:
#   "$BIN" args > "$LOG" 2> "$(diag_stderr_path lsp)" &
diag_stderr_path() {
    echo "${DIAG_DIR:-/tmp}/$1.stderr"
}

# diag_periodic <PID> [interval_sec]
# Starts a background recorder writing one ndjson line every N seconds with
# /proc/$PID/{status,stat,oom_score,io}.  Stops automatically when $PID exits.
# Caller can run more than once to record multiple PIDs to separate files.
diag_periodic() {
    local pid="$1"
    local interval="${2:-60}"
    local out="$DIAG_DIR/timeseries.${pid}.ndjson"
    (
        while kill -0 "$pid" 2>/dev/null; do
            if [ -r "/proc/$pid/status" ]; then
                local ts vmrss vmsize threads state oom_score io_read io_write
                ts=$(date -u +%s)
                vmrss=$(awk '/^VmRSS:/{print $2}' /proc/$pid/status 2>/dev/null)
                vmsize=$(awk '/^VmSize:/{print $2}' /proc/$pid/status 2>/dev/null)
                threads=$(awk '/^Threads:/{print $2}' /proc/$pid/status 2>/dev/null)
                state=$(awk '/^State:/{print $2}' /proc/$pid/status 2>/dev/null)
                oom_score=$(cat /proc/$pid/oom_score 2>/dev/null || echo 0)
                io_read=$(awk '/^read_bytes:/{print $2}' /proc/$pid/io 2>/dev/null || echo 0)
                io_write=$(awk '/^write_bytes:/{print $2}' /proc/$pid/io 2>/dev/null || echo 0)
                printf '{"ts":%s,"pid":%s,"vmrss_kb":%s,"vmsize_kb":%s,"threads":%s,"state":"%s","oom_score":%s,"io_read":%s,"io_write":%s}\n' \
                    "$ts" "$pid" "${vmrss:-0}" "${vmsize:-0}" "${threads:-0}" "${state:-?}" \
                    "$oom_score" "$io_read" "$io_write" >> "$out"
            fi
            sleep "$interval"
        done
    ) &
    DIAG_PERIODIC_PID=$!
    echo "diag: periodic recorder pid=$DIAG_PERIODIC_PID -> $out"
}

# Internal: decode exit code into human-readable form
_decode_exit() {
    local ec="$1"
    if [ "$ec" -ge 128 ]; then
        local signo=$((ec - 128))
        local signame
        signame=$(kill -l "$signo" 2>/dev/null || echo "?")
        echo "signal $signo (SIG${signame})"
    elif [ "$ec" -eq 0 ]; then
        echo "clean exit 0"
    else
        echo "exit code $ec"
    fi
}

# diag_on_lsp_death <PID> <LSP_LOG> <TAG> <EXIT_CODE>
diag_on_lsp_death() {
    local pid="$1"
    local lsp_log="$2"
    local tag="$3"
    local exit_code="$4"
    local diag_dir="/tmp/${tag}_diag"
    mkdir -p "$diag_dir"

    echo "=================================================="
    echo "diag: LSP pid=$pid died at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "diag: $(_decode_exit "$exit_code")"
    echo "diag: bundle = $diag_dir"
    echo "=================================================="

    # 1. Exit code interpretation
    {
        echo "pid: $pid"
        echo "exit_code_raw: $exit_code"
        echo "interpretation: $(_decode_exit "$exit_code")"
        echo "died_at_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$diag_dir/exit.txt"

    # 2. LSP log tail + checksum (best effort — log may be absent if very early death)
    if [ -r "$lsp_log" ]; then
        tail -100 "$lsp_log" > "$diag_dir/lsp.log.tail" 2>/dev/null || true
        sha256sum "$lsp_log" > "$diag_dir/lsp.log.sha256" 2>/dev/null || true
        stat -c "%y %s %n" "$lsp_log" >> "$diag_dir/lsp.log.sha256" 2>/dev/null || true
    fi

    # 3. Journal slice — from (5 min before death) to (1 min after)
    local since_ts until_ts
    since_ts=$(date -u --date='5 minutes ago' +%Y-%m-%d\ %H:%M:%S)
    until_ts=$(date -u --date='1 minute' +%Y-%m-%d\ %H:%M:%S)
    journalctl --since "$since_ts" --until "$until_ts" --no-pager \
        > "$diag_dir/journal.txt" 2>/dev/null || true

    # 4. Bitcoind state (chain tip + mempool count) — covers reorg/confirm-window deaths
    {
        if command -v bitcoin-cli >/dev/null 2>&1; then
            for net_args in \
                "-signet -datadir=/var/lib/bitcoind-signet" \
                "-datadir=/var/lib/bitcoind-testnet4 -rpcuser=testnet4rpc -rpcpassword=$(sed -n 's/^rpcpassword=//p' /var/lib/bitcoind-testnet4/bitcoin.conf 2>/dev/null) -rpcport=48332" \
            ; do
                echo "=== bitcoin-cli $net_args ==="
                bitcoin-cli $net_args getblockchaininfo 2>&1 | head -25
                echo "--- mempool ---"
                bitcoin-cli $net_args getmempoolinfo 2>&1 | head -10
                echo ""
            done
        fi
    } > "$diag_dir/bitcoind.txt" 2>&1

    # 5. /proc/$PID snapshot (only useful if process is still in transition).
    # /proc/$PID survives briefly after death — try, ignore failure.
    if [ -d "/proc/$pid" ]; then
        cat "/proc/$pid/status" > "$diag_dir/proc-status.txt" 2>/dev/null || true
        readlink "/proc/$pid/exe" >> "$diag_dir/proc-status.txt" 2>/dev/null || true
    fi

    # 6. Audit kill records for this pid (signal attribution)
    if command -v ausearch >/dev/null 2>&1; then
        # Both as caller AND as target — we want to know if anyone killed it, and
        # what kills the LSP itself issued.
        {
            echo "=== events where pid $pid was the killer ==="
            ausearch -k lsp-kills -p "$pid" --start today 2>&1 | tail -50
            echo ""
            echo "=== events targeting pid $pid (a0=$pid in syscall args) ==="
            # ausearch can't filter on a0 directly; grep the raw log
            grep "a0=$(printf '%x' "$pid")" /var/log/audit/audit.log 2>/dev/null | tail -20
        } > "$diag_dir/audit-kills.txt"
    fi

    # 7. Stop the periodic recorder if we started one
    if [ -n "${DIAG_PERIODIC_PID:-}" ] && kill -0 "$DIAG_PERIODIC_PID" 2>/dev/null; then
        kill "$DIAG_PERIODIC_PID" 2>/dev/null || true
    fi

    echo "diag: bundle written. Contents:"
    ls -la "$diag_dir/" 2>&1
}

# diag_wait_lsp <PID> <LSP_LOG> <TAG>
# Drop-in replacement for "wait $LSP_PID; EXIT=$?".  Disables errexit around
# the wait so the exit code is captured no matter what.  Sets global DIAG_EXIT.
# If the LSP died with non-zero exit, runs diag_on_lsp_death automatically.
diag_wait_lsp() {
    local pid="$1"
    local lsp_log="$2"
    local tag="$3"
    local prev_errexit
    case "$-" in
        *e*) prev_errexit=1 ;;
        *)   prev_errexit=0 ;;
    esac
    set +e
    wait "$pid"
    DIAG_EXIT=$?
    [ "$prev_errexit" = "1" ] && set -e
    if [ "$DIAG_EXIT" -ne 0 ]; then
        diag_on_lsp_death "$pid" "$lsp_log" "$tag" "$DIAG_EXIT" || true
    fi
}

# diag_emit_onchain_events <LSP_DB> <LSP_LOG> <EVIDENCE_FILE>
#
# Phase 5 runners' shared "## On-chain events" section emitter. Replaces the
# previous per-runner grep that missed half the LSP's log formats (txid=
# vs. txid: vs. bare confirmed: <hex>). Prefers a sqlite3 dump of the
# broadcast_log table (the LSP's authoritative record); falls back to a
# log grep that matches both txid=<hex> and txid: <hex> patterns so older
# ceremonies that pre-date the broadcast_log journal still get captured.
#
# Writes a markdown table to the evidence file. Safe to call when LSP_DB
# is absent (legacy runners), in which case only the grep fallback runs.
diag_emit_onchain_events() {
    local lsp_db="$1"
    local lsp_log="$2"
    local evidence="$3"
    {
        printf '\n## On-chain events\n\n'
        printf '| source | txid | result |\n'
        printf '|---|---|---|\n'
    } >> "$evidence"
    if [ -f "$lsp_db" ]; then
        sqlite3 -separator '|' "$lsp_db" \
            "SELECT source, txid, result FROM broadcast_log ORDER BY id;" \
            2>/dev/null \
            | awk -F'|' 'NF>=2 { printf "| %s | %s | %s |\n", $1, $2, $3 }' \
            >> "$evidence" || true
    fi
    # Fallback grep catches anything broadcast_log missed. Matches both
    # `txid=<hex>` (tree_node broadcasts) and `txid: <hex>` (cooperative
    # close success line).
    grep -oE "(funding|tree_node_[0-9]+|FORCE CLOSE|cooperative close|subfactory|breach|response)[^[:space:]]*[[:space:]]+txid[:=][[:space:]]*[a-f0-9]+" \
        "$lsp_log" 2>/dev/null | sort -u >> "$evidence" || true
}
