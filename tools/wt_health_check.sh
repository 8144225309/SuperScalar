#!/usr/bin/env bash
# wt_health_check.sh — watchtower liveness alert for mainnet ops (mainnet-gate §10).
#
# A trustless watchtower that is silently DOWN during a breach is the worst
# failure mode: penalties never fire and the cheater's revoked state confirms.
# This Nagios/monit-style check parses the WT's heartbeat log and returns
# CRITICAL if the last heartbeat is older than the staleness threshold, so an
# operator is paged BEFORE the breach-response (CSV) window is missed.
#
# Wire into cron / systemd-timer / monit, e.g. every minute:
#   */1 * * * * /path/wt_health_check.sh /var/log/superscalar/wt.log 120 || alert
#
# Exit codes:  0 = OK,  2 = CRITICAL,  3 = UNKNOWN (bad usage / log missing)
#
# usage: wt_health_check.sh <wt_log_path> [max_stale_secs]
set -uo pipefail
LOG="${1:-}"; MAX_STALE="${2:-120}"   # default: alert if no heartbeat in 2 minutes
if [ -z "$LOG" ]; then
    echo "UNKNOWN: usage: $0 <wt_log_path> [max_stale_secs]"; exit 3
fi
if [ ! -f "$LOG" ]; then
    echo "CRITICAL: WT log '$LOG' not found — watchtower process not running?"; exit 2
fi

# Heartbeat lines look like: "[1780596390] heartbeat height=7278 entries=17"
LAST_TS=$(grep -aoE "\[[0-9]+\] heartbeat" "$LOG" 2>/dev/null | tail -1 | grep -oE "[0-9]+" | head -1)
if [ -z "$LAST_TS" ]; then
    echo "CRITICAL: no heartbeat ever logged in '$LOG' — watchtower never reached its poll loop?"; exit 2
fi

NOW=$(date -u +%s)
AGE=$(( NOW - LAST_TS ))
if [ "$AGE" -lt 0 ]; then AGE=0; fi

if [ "$AGE" -gt "$MAX_STALE" ]; then
    echo "CRITICAL: watchtower heartbeat is ${AGE}s stale (threshold ${MAX_STALE}s) — WT may be DOWN; revoked-state breaches will go unpunished. Investigate + restart immediately."
    exit 2
fi
echo "OK: watchtower alive — last heartbeat ${AGE}s ago (threshold ${MAX_STALE}s)"
exit 0
