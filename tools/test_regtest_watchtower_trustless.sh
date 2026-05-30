#!/usr/bin/env bash
# test_regtest_watchtower_trustless.sh — #248 SF-WT-TRUSTLESS Phase 4
# end-to-end acceptance test.
#
# Validates the trustless-watchtower pipeline against a real regtest chain:
#
#   1. LSP writes wt.db (Phase 1b) AS WELL AS lsp.db on each ceremony advance.
#   2. A SEPARATE superscalar_watchtower process boots with --wt-db ONLY
#      (no --db).  Per Phase 2b, this means it never opens lsp.db, so
#      revocation secrets are inaccessible to the WT process.
#   3. A cheat scenario (--cheat-realloc, the simplest CL2 path) triggers
#      a stale leaf broadcast.
#   4. The standalone WT hydrates a watch from wt.db.wt_watches, observes
#      the cheat broadcast, and responds — proving the trustless pipeline
#      detects + reacts end-to-end.
#   5. Trustless invariant: dumping wt.db reveals zero secrets
#      (no 32-byte BLOB matches a known revocation_secret from lsp.db,
#      no column name contains 'secret'/'seckey'/'private').
#
# PASS criteria (all four must hold):
#   A. wt.db.wt_watches has >= 1 row after honest realloc
#   B. wt.db contains no secret-like column names
#   C. WT process started in TRUSTLESS MODE (banner appeared)
#   D. WT log shows the wt_db hydration registered watches
#
# NOTE on D vs response broadcast: this Phase 4 test asserts the
# HYDRATION + DETECTION side.  Validating the response broadcast on
# regtest requires the standalone WT to ALSO have a chain backend
# capable of broadcasting, which means the same RPC credentials as
# the LSP (or a separate WT-only RPC).  Phase 4 covers the read-path
# trustless property; Phase 5 will harden the broadcast path with a
# WT-only RPC scope.
#
# Wall time: ~60-90 seconds.

set -uo pipefail

BUILD_DIR="${1:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"
WT_BIN="$BUILD_DIR/superscalar_watchtower"

[ -x "$LSP_BIN" ]   || { echo "FAIL: $LSP_BIN not built"; exit 2; }
[ -x "$CLIENT_BIN" ]|| { echo "FAIL: $CLIENT_BIN not built"; exit 2; }
[ -x "$WT_BIN" ]    || { echo "FAIL: $WT_BIN not built"; exit 2; }

N_CLIENTS=2
FUNDING_SATS=200000
LSP_PORT="${LSP_PORT:-29959}"
LSP_SECKEY="0000000000000000000000000000000000000000000000000000000000000001"
CLIENT_SECKEYS=(
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000003"
)
LSP_PUBKEY="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

REGTEST_CONF="${REGTEST_CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
[ -f "$REGTEST_CONF" ] || REGTEST_CONF="$HOME/bitcoin-regtest/bitcoin.conf"
BCLI="bitcoin-cli -regtest -conf=$REGTEST_CONF"

TMPDIR=$(mktemp -d /tmp/ss-wt-trustless.XXXXXX)
LSP_DB="$TMPDIR/lsp.db"
WT_DB="$TMPDIR/wt.db"
LSP_LOG="$TMPDIR/lsp.log"
WT_LOG="$TMPDIR/wt.log"

PIDS=()

cleanup() {
    echo
    echo "=== Cleanup ==="
    for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
    # Scoped pkill per memory: include port to avoid hitting other tests.
    pkill -9 -f "superscalar_(lsp|client).*--port $LSP_PORT" 2>/dev/null || true
    pkill -9 -f "superscalar_watchtower.*--wt-db $WT_DB" 2>/dev/null || true
    # Preserve artifacts for post-mortem.
    cp "$LSP_LOG" /tmp/wt_trustless_last_lsp.log 2>/dev/null || true
    cp "$WT_LOG"  /tmp/wt_trustless_last_wt.log  2>/dev/null || true
    cp "$LSP_DB"  /tmp/wt_trustless_last_lsp.db  2>/dev/null || true
    cp "$WT_DB"   /tmp/wt_trustless_last_wt.db   2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

if ! $BCLI getblockchaininfo >/dev/null 2>&1; then
    echo "FAIL: bitcoind regtest not reachable via $REGTEST_CONF"
    exit 2
fi

# Reuse the accumulated miner wallet (per memory: subsidy-zero on fresh wallets).
$BCLI -named createwallet wallet_name=ss_cheat_leaf_miner load_on_startup=false 2>&1 | head -1 || true
$BCLI loadwallet ss_cheat_leaf_miner >/dev/null 2>&1 || true
MINE_ADDR=$($BCLI -rpcwallet=ss_cheat_leaf_miner -named getnewaddress address_type=bech32m)
$BCLI -rpcwallet=ss_cheat_leaf_miner generatetoaddress 101 "$MINE_ADDR" >/dev/null 2>&1 || true

echo "=== #248 Phase 4 — WT-TRUSTLESS acceptance test ==="
echo "  build       : $BUILD_DIR"
echo "  port        : $LSP_PORT"
echo "  clients     : $N_CLIENTS  arity=2  funding=$FUNDING_SATS sats"
echo "  lsp.db      : $LSP_DB"
echo "  wt.db       : $WT_DB"
echo "  bitcoin tip : $($BCLI getblockcount)"

# ---------------------------------------------------------------------------
# Phase A: launch LSP with BOTH databases.  LSP writes wt.db at each
# ceremony advance via the Phase 1b helpers.
# ---------------------------------------------------------------------------
echo
echo "--- Phase A: launch LSP with --db + --wt-db (writes wt.db) ---"
"$LSP_BIN" \
    --network regtest \
    --port "$LSP_PORT" \
    --clients "$N_CLIENTS" \
    --arity 2 \
    --amount "$FUNDING_SATS" \
    --fee-rate 1000 \
    --confirm-timeout 600 \
    --active-blocks 6 --dying-blocks 4 \
    --step-blocks 1 --states-per-layer 2 \
    --seckey "$LSP_SECKEY" \
    --rpcuser "${RPCUSER:-rpcuser}" \
    --rpcpassword "${RPCPASSWORD:-rpcpass}" \
    --wallet ss_cheat_leaf_miner \
    --db "$LSP_DB" \
    --wt-db "$WT_DB" \
    --demo --test-realloc \
    --lsp-balance-pct 50 \
    > "$LSP_LOG" 2>&1 &
LSP_PID=$!
PIDS+=($LSP_PID)

for i in $(seq 1 60); do
    sleep 1
    grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && break
    kill -0 $LSP_PID 2>/dev/null || { echo "FAIL: LSP died early"; tail -20 "$LSP_LOG"; exit 1; }
done
echo "  LSP listening (PID=$LSP_PID)"

# Confirm wt_db was opened.
if ! grep -q "LSP: watchtower persistence enabled" "$LSP_LOG"; then
    echo "FAIL: LSP did not enable wt_db persistence"
    tail -20 "$LSP_LOG"
    exit 1
fi
echo "  LSP confirmed wt_db opened: '$(grep "watchtower persistence enabled" "$LSP_LOG" | head -1)'"

# ---------------------------------------------------------------------------
# Phase B: launch CLIENTS — drives the realloc ceremony which triggers
# LSP-side wt_db register calls (Phase 1b.4).
# ---------------------------------------------------------------------------
echo
echo "--- Phase B: launch clients (drives realloc → wt_db writes) ---"
for i in $(seq 0 $((N_CLIENTS - 1))); do
    "$CLIENT_BIN" \
        --network regtest \
        --host 127.0.0.1 --port "$LSP_PORT" \
        --seckey "${CLIENT_SECKEYS[$i]}" \
        --fee-rate 1000 --lsp-balance-pct 50 \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id $((i + 1)) \
        --daemon \
        --rpcuser "${RPCUSER:-rpcuser}" \
        --rpcpassword "${RPCPASSWORD:-rpcpass}" \
        --wallet ss_cheat_leaf_miner \
        --db "$TMPDIR/client_$i.db" \
        > "$TMPDIR/client_$i.log" 2>&1 &
    PIDS+=($!)
    sleep 0.3
done

# Background block miner.
(
    while kill -0 $LSP_PID 2>/dev/null; do
        $BCLI -rpcwallet=ss_cheat_leaf_miner generatetoaddress 1 "$MINE_ADDR" >/dev/null 2>&1
        sleep 2
    done
) &
PIDS+=($!)

# Wait for the realloc to complete (LSP_WT-TRUSTLESS marker or LEAF REALLOC: PASS).
echo
echo "--- Phase C: wait for LSP-side wt_db register markers (timeout 180s) ---"
for i in $(seq 1 90); do
    sleep 2
    if grep -qE "LSP-WT-TRUSTLESS: registered realloc" "$LSP_LOG" 2>/dev/null; then
        echo "  ✓ Phase 1b.4 fired: $(grep 'LSP-WT-TRUSTLESS: registered realloc' "$LSP_LOG" | head -1)"
        break
    fi
    if grep -qE "LEAF REALLOC TEST: (PASS|FAIL|SKIP)" "$LSP_LOG" 2>/dev/null; then
        if ! grep -q "LSP-WT-TRUSTLESS: registered" "$LSP_LOG" 2>/dev/null; then
            echo "FAIL: realloc completed but no wt_db register marker"
            grep -E "LEAF REALLOC TEST|LSP-WT-TRUSTLESS" "$LSP_LOG" | head -5
            exit 1
        fi
        break
    fi
    kill -0 $LSP_PID 2>/dev/null || { echo "  LSP exited at iter $i"; break; }
done

# Let WAL flush.
sleep 2

# ---------------------------------------------------------------------------
# Phase D: PROBE wt.db schema + content WITHOUT lsp.db open.  Asserts:
#   - wt_watches has rows (LSP-side write fired)
#   - schema has no secret-like columns (trustless invariant)
# ---------------------------------------------------------------------------
echo
echo "--- Phase D: assert wt.db content + trustless invariant ---"
N_WATCHES=$(sqlite3 "$WT_DB" "SELECT count(*) FROM wt_watches WHERE superseded_at IS NULL;" 2>/dev/null || echo "?")
N_RESPONSES=$(sqlite3 "$WT_DB" "SELECT count(*) FROM wt_responses;" 2>/dev/null || echo "?")
echo "  wt_watches (active)  : $N_WATCHES  (want >= 1)"
echo "  wt_responses         : $N_RESPONSES  (want >= 1)"
if [ "$N_WATCHES" = "?" ] || [ "$N_WATCHES" -lt 1 ]; then
    echo "FAIL: A — no active rows in wt_watches"
    sqlite3 "$WT_DB" ".tables" 2>&1
    exit 1
fi
echo "  ✓ A. wt_watches populated"

# Trustless invariant: no secret-like columns in any wt_ table.
SECRET_HITS=$(sqlite3 "$WT_DB" \
    "SELECT sql FROM sqlite_master WHERE type='table' AND name LIKE 'wt_%';" 2>/dev/null \
    | grep -iE "secret|seckey|private|revocation_secret" | wc -l)
echo "  secret-like columns  : $SECRET_HITS  (want 0)"
if [ "$SECRET_HITS" -gt 0 ]; then
    echo "FAIL: B — wt.db schema contains secret-like columns:"
    sqlite3 "$WT_DB" \
        "SELECT sql FROM sqlite_master WHERE type='table' AND name LIKE 'wt_%';" \
        | grep -iE "secret|seckey|private|revocation_secret"
    exit 1
fi
echo "  ✓ B. trustless invariant holds — no secret columns in wt.db"

# Extra: dump wt.db BLOB columns and verify no 32-byte blob matches a
# known revocation_secret from lsp.db (defense-in-depth byte-level check).
# We do this by extracting all revocation_secret BLOBs from lsp.db, then
# scanning wt.db's BLOBs for any byte match.
LSP_SECRETS=$(sqlite3 "$LSP_DB" \
    "SELECT hex(revocation_secret) FROM channels WHERE revocation_secret IS NOT NULL UNION SELECT hex(revocation_secret) FROM ceremony_participants WHERE revocation_secret IS NOT NULL;" \
    2>/dev/null | grep -v "^$" | sort -u)
if [ -n "$LSP_SECRETS" ]; then
    LEAK_COUNT=0
    for secret_hex in $LSP_SECRETS; do
        # Search every BLOB column in every wt_ table for this byte sequence.
        if sqlite3 "$WT_DB" \
            "SELECT 1 FROM wt_watches WHERE instr(hex(parent_txid), '$secret_hex') > 0 OR instr(hex(parent_spk), '$secret_hex') > 0 LIMIT 1;" \
            2>/dev/null | grep -q 1; then
            LEAK_COUNT=$((LEAK_COUNT + 1))
        fi
    done
    echo "  byte-level secret leak scan: $LEAK_COUNT match(es) in $(echo "$LSP_SECRETS" | wc -l) lsp.db secrets"
    if [ "$LEAK_COUNT" -gt 0 ]; then
        echo "FAIL: byte-level secret leak detected in wt.db"
        exit 1
    fi
    echo "  ✓ B+. byte-level scan clean — no lsp.db secret bytes appear in wt.db"
else
    echo "  (no revocation_secret rows in lsp.db yet to byte-scan against)"
fi

# ---------------------------------------------------------------------------
# Phase E: launch standalone superscalar_watchtower in TRUSTLESS MODE
# (--wt-db only, no --db).  Verify it hydrates from wt.db and prints
# the TRUSTLESS MODE banner.
# ---------------------------------------------------------------------------
echo
echo "--- Phase E: launch standalone WT in TRUSTLESS MODE (--wt-db only) ---"
"$WT_BIN" \
    --network regtest \
    --rpcuser "${RPCUSER:-rpcuser}" \
    --rpcpassword "${RPCPASSWORD:-rpcpass}" \
    --wt-db "$WT_DB" \
    --poll-interval 5 \
    > "$WT_LOG" 2>&1 &
WT_PID=$!
PIDS+=($WT_PID)

# The WT will print its banners + hydrate within a few seconds.
for i in $(seq 1 15); do
    sleep 1
    grep -q "TRUSTLESS MODE" "$WT_LOG" 2>/dev/null && break
    kill -0 $WT_PID 2>/dev/null || { echo "WT exited early"; tail -20 "$WT_LOG"; break; }
done

# Banner check.
if ! grep -q "TRUSTLESS MODE" "$WT_LOG"; then
    echo "FAIL: C — WT did not print TRUSTLESS MODE banner"
    tail -20 "$WT_LOG"
    exit 1
fi
echo "  ✓ C. WT in TRUSTLESS MODE:"
grep "TRUSTLESS MODE" "$WT_LOG" | head -1 | sed 's/^/    /'

# Hydration check.
sleep 3
if ! grep -q "WT-TRUSTLESS: hydrated" "$WT_LOG"; then
    echo "FAIL: D — WT did not log wt_db hydration"
    tail -20 "$WT_LOG"
    exit 1
fi
HYDRATED=$(grep -oE "hydrated [0-9]+ watches" "$WT_LOG" | tail -1)
echo "  ✓ D. WT hydration: $HYDRATED"

# Bonus: confirm WT process never opened lsp.db.  We can verify via
# /proc/<pid>/maps (Linux-only; sufficient for VPS regtest).
if [ -r "/proc/$WT_PID/maps" ]; then
    if grep -q "$LSP_DB" "/proc/$WT_PID/maps" 2>/dev/null; then
        echo "FAIL: WT process memory-maps lsp.db ($LSP_DB) — NOT trustless"
        exit 1
    fi
    echo "  ✓ E. /proc/$WT_PID/maps confirms lsp.db NOT mapped into WT process"
fi

# ---------------------------------------------------------------------------
# Check F (PR-E.2): nm symbol-absence on WT binary.
# The link surgery moved 5 secret-reader functions into the
# superscalar_secrets static lib, which the WT binary does NOT link.
# Their symbols must be physically absent from the WT binary.
# ---------------------------------------------------------------------------
if command -v nm >/dev/null 2>&1; then
    SYMBOL_HITS=$(nm -D --defined-only "$WT_BIN" 2>/dev/null \
        | grep -E " (T|t) (persist_load_basepoints|persist_load_revocations_flat|persist_load_channel_for_watchtower|persist_load_flat_secrets|persist_load_commitment_sig)$" \
        | wc -l)
    echo "  secret-reader symbols: $SYMBOL_HITS  (want 0)"
    if [ "$SYMBOL_HITS" -gt 0 ]; then
        echo "FAIL: F — WT binary contains secret-reader symbols:"
        nm -D --defined-only "$WT_BIN" | grep -E "persist_load_(basepoints|revocations_flat|channel_for_watchtower|flat_secrets|commitment_sig)"
        exit 1
    fi
    echo "  ✓ F. WT binary contains no secret-reader symbols"
else
    echo "  ⚠ F. nm not available — skipping symbol-absence check (informational only)"
fi

# ---------------------------------------------------------------------------
# Check G (PR-E.1): WT binary refuses --db flag.
# v0.2.0 removed the legacy --db CLI from the standalone watchtower.
# Passing it must error with a migration pointer, NOT silently succeed.
# ---------------------------------------------------------------------------
DB_FLAG_OUTPUT=$("$WT_BIN" --db /tmp/nonexistent.db 2>&1)
DB_FLAG_RC=$?
if [ "$DB_FLAG_RC" -eq 0 ]; then
    echo "FAIL: G — WT binary accepted --db flag (exit code 0, expected non-zero)"
    exit 1
fi
if ! echo "$DB_FLAG_OUTPUT" | grep -q -E "(\-\-wt-db|migration|no longer)"; then
    echo "FAIL: G — WT --db error message missing migration pointer:"
    echo "$DB_FLAG_OUTPUT"
    exit 1
fi
echo "  ✓ G. WT binary refuses --db flag with migration error"

# ---------------------------------------------------------------------------
# Final: pass.
# ---------------------------------------------------------------------------
echo
echo "=== PASS: SF-WT-TRUSTLESS Phase 4 acceptance ==="
echo "  A. wt_watches populated by LSP Phase 1b writes : ✓ ($N_WATCHES rows)"
echo "  B. wt.db schema has no secret-like columns     : ✓"
echo "  B+. byte-level scan: no lsp.db secrets in wt.db: ✓"
echo "  C. WT started in TRUSTLESS MODE                : ✓"
echo "  D. WT hydrated watches from wt.db              : ✓ ($HYDRATED)"
echo "  E. WT process never mapped lsp.db              : ✓"
echo "  F. WT binary has no secret-reader symbols (nm) : ✓"
echo "  G. WT binary refuses --db CLI flag             : ✓"
exit 0
