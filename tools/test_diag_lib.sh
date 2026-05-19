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
          "$DIAG_DIR"/*.stderr "$DIAG_DIR"/predeath_* "$DIAG_DIR"/core.* 2>/dev/null || true
    echo "diag: forensics dir = $DIAG_DIR"
    # Record service start time so we can slice journal precisely.
    date -u +%Y-%m-%dT%H:%M:%SZ > "$DIAG_DIR/start.txt"
}

# diag_enable_core_dumps
# Lifts the RLIMIT_CORE soft limit and points the kernel core-pattern (best
# effort — needs root for sysctl) at DIAG_DIR so a SIGSEGV/SIGABRT leaves
# a usable core file in the forensics bundle.
diag_enable_core_dumps() {
    ulimit -c unlimited 2>/dev/null || true
    if [ -w /proc/sys/kernel/core_pattern ] 2>/dev/null; then
        echo "${DIAG_DIR}/core.%e.%p.%t" > /proc/sys/kernel/core_pattern 2>/dev/null || true
    fi
    # core_uses_pid keeps the %p in the name if pattern wasn't writable
    [ -w /proc/sys/kernel/core_uses_pid ] && \
        echo 1 > /proc/sys/kernel/core_uses_pid 2>/dev/null || true
    {
        echo "ulimit_c: $(ulimit -c 2>/dev/null)"
        echo "core_pattern: $(cat /proc/sys/kernel/core_pattern 2>/dev/null)"
        echo "core_uses_pid: $(cat /proc/sys/kernel/core_uses_pid 2>/dev/null)"
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
    local snap="$DIAG_DIR/predeath_${pid}"  # rotating snapshot prefix
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

                # Rotating predeath snapshot: overwrites each interval so the
                # post-death handler always has a recent /proc capture even if
                # the kernel reaped the process between death and handler run.
                cat /proc/$pid/status > "${snap}_status.txt" 2>/dev/null || true
                cat /proc/$pid/stat   > "${snap}_stat.txt"   2>/dev/null || true
                readlink /proc/$pid/exe > "${snap}_exe.txt"  2>/dev/null || true
                # The last few lines of any file referenced via /proc/$pid/fd
                # would be too much; track just the open-fd count as a smoke
                # signal for fd leaks.
                if [ -d "/proc/$pid/fd" ]; then
                    ls /proc/$pid/fd 2>/dev/null | wc -l > "${snap}_nfd.txt" || true
                fi
                date -u +%Y-%m-%dT%H:%M:%SZ > "${snap}_ts.txt"
            fi
            sleep "$interval"
        done
    ) &
    DIAG_PERIODIC_PID=$!
    echo "diag: periodic recorder pid=$DIAG_PERIODIC_PID -> $out (predeath snapshots: ${snap}_*)"
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
                "-datadir=/var/lib/bitcoind-testnet4 -rpcuser=testnet4rpc -rpcpassword=testnet4rpcpass123 -rpcport=48332" \
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

    # 5b. Predeath snapshot — last /proc capture written by diag_periodic.
    # Lives independently of post-death /proc reaping; safe to rely on.
    {
        for f in "${diag_dir}/predeath_${pid}_"*; do
            [ -r "$f" ] || continue
            echo "=== ${f##*/} ==="
            cat "$f" 2>/dev/null
            echo
        done
    } > "$diag_dir/predeath.txt" 2>&1

    # 5c. Separated stderr tail — useful when the LSP log captures stdout-only
    # diagnostics but the death cause is a stderr-only assertion / glibc abort.
    local stderr_path="${diag_dir}/lsp.stderr"
    if [ -r "$stderr_path" ]; then
        tail -200 "$stderr_path" > "$diag_dir/lsp.stderr.tail" 2>/dev/null || true
    fi

    # 5d. Core file — if ulimit + core_pattern were set up at boot, a SIGSEGV/
    # SIGABRT/SIGBUS leaves a core in DIAG_DIR.  Match by pid OR by name pattern.
    {
        ls -la "$diag_dir/core."* 2>/dev/null
        # Default kernel pattern may dump in CWD; check there too.
        find /tmp -maxdepth 2 -name "core.*${pid}*" -newer "$diag_dir/start.txt" 2>/dev/null
        find . -maxdepth 1 -name "core.*${pid}*" 2>/dev/null
    } > "$diag_dir/core_files.txt" 2>&1

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
