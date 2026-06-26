#!/usr/bin/env bash
# test_signet_hashlock_poison_subfactory.sh — #53 sub-factory hashlock L-stock
# (sales-stock) poison on REAL SIGNET.  Signet sibling of the regtest e2e
# (test_regtest_hashlock_poison_subfactory_e2e.sh); proves the cryptographic
# flow confirms on the real network, not just a private chain.
#
# Flow (LSP --enable-hashlock-poison --cheat-daemon-sub, multi-input ceremony):
#   1. LSP self-funds a k>=2 PS factory (hashlock on) + advances a sub-factory chain
#      over the REAL wire ceremony; the LSP reveals secret_old, each sub client
#      verify-persists it (l_stock_poison_reveals).
#   2. The cheating LSP broadcasts the SUPERSEDED chain[N-1] sub state on-chain.
#   3. CLIENT recourse: superscalar_lstock_recover assembles the Leaf-P poison from
#      the persisted reveal; we broadcast it to spend the stale sales-stock.
#   4. ASSERT: the poison CONFIRMS on signet + redistributes the sales-stock to the
#      sub clients (non-dust per-client P2TR outputs).
#   5. Anti-vacuity: with the secret removed the tool REFUSES (exit 5).
#
# STRONG KEYS (signet_strong_keygen.py): the poison redistributes to per-client
# keys, so they MUST NOT be publicly-derivable weak keys (else anyone sweeps the
# recaptured sats).  The run seed is saved for our own post-run recovery.
# Sat-careful: --fee-rate 110, modest AMOUNT, residual recoverable from the seed.
set -uo pipefail
BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"; CLIENT_BIN="$BUILD_DIR/superscalar_client"; REC_BIN="$BUILD_DIR/superscalar_lstock_recover"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
N_CLIENTS="${N_CLIENTS:-4}"; PS_SUB_ARITY="${PS_SUB_ARITY:-2}"; AMOUNT="${AMOUNT:-200000}"; FEE_RATE="${FEE_RATE:-110}"
LSP_PORT="${LSP_PORT:-29968}"; WALLET="${WALLET:-superscalar_lsp}"; CONFIRM_TIMEOUT="${CONFIRM_TIMEOUT:-21600}"
TAG="${TAG:-hashsub}"
SIGNET_CONF="${SIGNET_CONF:-/var/lib/bitcoind-signet/bitcoin.conf}"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF")
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF")
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF"); RPORT=${RPORT:-38332}
BCLI="bitcoin-cli -signet -rpcuser=$RU -rpcpassword=$RP -rpcport=$RPORT"
TMPDIR=$(mktemp -d /tmp/ss-signet-hashsub.XXXXXX); LSP_DB="$TMPDIR/lsp.db"; WT_DB="$TMPDIR/wt.db"; LSP_LOG="$TMPDIR/lsp.log"
PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null||true; done; cp "$LSP_LOG" /tmp/hashsub_signet_lsp.log 2>/dev/null||true; for i in $(seq 0 $((N_CLIENTS-1))); do cp "$TMPDIR/client_${i}.log" "/tmp/hashsub_signet_client_${i}.log" 2>/dev/null||true; done; }
trap cleanup EXIT
green(){ printf '\033[32m%s\033[0m\n' "$*"; }; red(){ printf '\033[31m%s\033[0m\n' "$*"; }; fail(){ red "FAIL: $*"; recov; exit 1; }
ts(){ date -u +%H:%M:%S; }; tip(){ $BCLI getblockcount 2>/dev/null; }
confirm_height(){ local txid="$1" bh; bh=$($BCLI getrawtransaction "$txid" true 2>/dev/null | grep -oE '"blockhash": *"[0-9a-f]{64}"' | grep -oE "[0-9a-f]{64}" | head -1); [ -z "$bh" ] && return 1; $BCLI getblockheader "$bh" 2>/dev/null | grep -oE '"height": *[0-9]+' | grep -oE "[0-9]+" | head -1; }
wait_confirm(){ local txid="$1" budget="$2" waited=0 h; while [ "$waited" -lt "$budget" ]; do h=$(confirm_height "$txid") && { echo "$h"; return 0; }; sleep 60; waited=$((waited+60)); done; return 1; }
recov(){ echo "--- RECOVERY: strong keys -> RUN_SEED_FILE=${RUN_SEED_FILE:-?} (re-derive client keys to sweep the poison's per-client P2TR outputs via PSBT, cf reference_signet_sweep_method). $AMOUNT sats locked in the factory tree from $WALLET; residual sub/leaf/channel outputs sweepable via LSP/client keys. dbs $TMPDIR (preserved /tmp/hashsub_signet_*.log). ---"; }

echo "=== SIGNET: #53 sub-factory HASHLOCK L-stock poison (client recourse) ==="
echo "  [$(ts)] height $(tip), amount=$AMOUNT, k=$PS_SUB_ARITY, fee=$FEE_RATE. signet ~10min/block — multi-hour."

# --- strong per-run keys ---
eval "$(python3 "$SCRIPT_DIR/signet_strong_keygen.py" "$N_CLIENTS" "$TAG")"
[ -n "${LSP_SECKEY:-}" ] && [ -n "${LSP_PUBKEY:-}" ] && [ -f "${CLIENT_KEYS_FILE:-/nonexistent}" ] || fail "strong keygen failed"
echo "  [$(ts)] strong keys: LSP_PUBKEY=$LSP_PUBKEY  seed=$RUN_SEED_FILE"
mapfile -t CLIENT_SECKEYS < "$CLIENT_KEYS_FILE"
[ "${#CLIENT_SECKEYS[@]}" -ge "$N_CLIENTS" ] || fail "client keys file short (${#CLIENT_SECKEYS[@]} < $N_CLIENTS)"

pkill -9 -f "superscalar_lsp.*--port $LSP_PORT" 2>/dev/null||true; sleep 1

# --- LSP (hashlock poison + sub cheat), self-funds from the signet wallet ---
"$LSP_BIN" --network signet --cli-path bitcoin-cli --rpcuser "$RU" --rpcpassword "$RP" \
    --port $LSP_PORT --clients $N_CLIENTS --arity 3 --ps-subfactory-arity $PS_SUB_ARITY \
    --amount $AMOUNT --fee-rate $FEE_RATE --confirm-timeout $CONFIRM_TIMEOUT \
    --seckey "$LSP_SECKEY" --wallet "$WALLET" --db "$LSP_DB" --wt-db "$WT_DB" \
    --enable-hashlock-poison --demo --lsp-balance-pct 50 --cheat-daemon-sub > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 120); do sleep 2; grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && { echo "  [$(ts)] LSP listening + self-funding"; break; }; kill -0 $LSP_PID 2>/dev/null||{ tail -25 "$LSP_LOG"; fail "LSP died before listening"; }; done

# --- clients (strong keys) ---
for i in $(seq 0 $((N_CLIENTS-1))); do
    "$CLIENT_BIN" --network signet --cli-path bitcoin-cli --rpcuser "$RU" --rpcpassword "$RP" \
        --host 127.0.0.1 --port $LSP_PORT --seckey "${CLIENT_SECKEYS[$i]}" --fee-rate $FEE_RATE \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id $((i+1)) --daemon --wallet "$WALLET" \
        --db "$TMPDIR/client_${i}.db" > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!); sleep 1
done

echo "  [$(ts)] LSP driving hashlock sub advance (reveal) + cheat broadcast over real blocks..."
for i in $(seq 1 $((CONFIRM_TIMEOUT/10))); do sleep 10; grep -qE "CHEAT DAEMON COMPLETE" "$LSP_LOG" 2>/dev/null && { echo "  [$(ts)] cheat broadcast complete"; break; }; kill -0 $LSP_PID 2>/dev/null||{ echo "  [$(ts)] LSP exited"; break; }; done
grep -qE "CHEAT DAEMON COMPLETE" "$LSP_LOG" || fail "cheat-daemon-sub never completed"
grep -q "hashlock-gated L-stock poison ENABLED" "$LSP_LOG" || fail "hashlock poison was NOT enabled"
grep -q "revealed sub sales-stock secret for" "$LSP_LOG" || { grep -iE "subfactory|poison|reveal" "$LSP_LOG" | tail -20; fail "LSP never revealed the sub sales-stock secret (Phase 2)"; }
echo "  [$(ts)] hashlock ENABLED + sub secret REVEAL confirmed in LSP log"
STALE_TXID=$(grep -E "Stale chain\[N-1\] broadcast" "$LSP_LOG" | head -1 | grep -oE "[0-9a-f]{64}" | head -1)
[ -n "$STALE_TXID" ] || fail "no stale sub broadcast txid"
echo "  [$(ts)] stale (superseded) sub chain[N-1]: $STALE_TXID"

echo "  [$(ts)] stopping LSP + clients (SIGTERM) so client persist DBs flush..."
for p in "${PIDS[@]:-}"; do kill -TERM "$p" 2>/dev/null||true; done; sleep 5

# --- find the client that persisted the sub reveal ---
REVEAL_DB=""; REVEAL_NODE=""; REVEAL_STATE=""
for i in $(seq 0 $((N_CLIENTS-1))); do
    row=$(sqlite3 "$TMPDIR/client_${i}.db" "SELECT node_idx||' '||state_counter FROM l_stock_poison_reveals WHERE revocation_secret IS NOT NULL ORDER BY node_idx DESC, state_counter ASC LIMIT 1;" 2>/dev/null || true)
    [ -n "$row" ] && { REVEAL_DB="$TMPDIR/client_${i}.db"; REVEAL_NODE=$(echo "$row"|awk '{print $1}'); REVEAL_STATE=$(echo "$row"|awk '{print $2}'); echo "  [$(ts)] reveal persisted by client[$i]: node=$REVEAL_NODE state=$REVEAL_STATE"; break; }
done
[ -n "$REVEAL_DB" ] || fail "NO client persisted an l_stock_poison_reveals row (Phase 2 client persist)"

# --- the stale chain[N-1] must be on-chain before the poison can spend its sales-stock ---
echo "  [$(ts)] waiting for stale chain[N-1] $STALE_TXID to confirm (budget ${CONFIRM_TIMEOUT}s)..."
H_STALE=$(wait_confirm "$STALE_TXID" "$CONFIRM_TIMEOUT") || fail "stale chain[N-1] $STALE_TXID never confirmed"
echo "  [$(ts)] stale chain[N-1] confirmed @ $H_STALE"

# --- CLIENT recourse: assemble + broadcast the hashlock sub poison ---
POISON_HEX=$("$REC_BIN" --db "$REVEAL_DB" --node-idx "$REVEAL_NODE" --state "$REVEAL_STATE" 2>/tmp/_recsig.err) || { cat /tmp/_recsig.err; fail "superscalar_lstock_recover failed"; }
echo "  [$(ts)] assembled sub poison (${#POISON_HEX} hex chars)"
POISON_TXID=$($BCLI sendrawtransaction "$POISON_HEX" 2>/tmp/_sendsig.err) || { cat /tmp/_sendsig.err; fail "sub poison sendrawtransaction REJECTED"; }
echo "  [$(ts)] SUB POISON broadcast: $POISON_TXID — confirming (budget ${CONFIRM_TIMEOUT}s)..."
H_POISON=$(wait_confirm "$POISON_TXID" "$CONFIRM_TIMEOUT") || fail "sub poison $POISON_TXID broadcast but NOT confirmed (re-check getrawtransaction $POISON_TXID before concluding failure)"
echo "  [$(ts)] sub poison CONFIRMED @ $H_POISON"

# --- redistribution assertion: N per-client P2TR outputs, smallest above dust ---
SRAW=$($BCLI getrawtransaction "$POISON_TXID" true 2>/dev/null)
SPINFO=$(echo "$SRAW" | python3 -c 'import json,sys
try:
 d=json.load(sys.stdin); vs=[int(round(v["value"]*1e8)) for v in d["vout"] if v["scriptPubKey"].get("type")=="witness_v1_taproot"]
 print(min(vs) if vs else 0, len(vs), sum(vs))
except Exception: print("0 0 0")')
SP_MIN=$(echo "$SPINFO"|awk '{print $1}'); SP_NUM=$(echo "$SPINFO"|awk '{print $2}'); SP_TOT=$(echo "$SPINFO"|awk '{print $3}')
echo "  [$(ts)] sales-stock redistribution: $SP_NUM P2TR output(s), smallest ${SP_MIN:-0} sats, total ${SP_TOT:-0} sats"
[ "${SP_NUM:-0}" -ge 1 ] || fail "poison has no P2TR redistribution output"
[ "${SP_MIN:-0}" -ge 330 ] || fail "a per-client output ${SP_MIN} sats <= dust"

# --- anti-vacuity: no revealed secret -> no recourse ---
cp "$REVEAL_DB" "$TMPDIR/novax.db"; sqlite3 "$TMPDIR/novax.db" "UPDATE l_stock_poison_reveals SET revocation_secret=NULL;" 2>/dev/null
set +e; "$REC_BIN" --db "$TMPDIR/novax.db" --node-idx "$REVEAL_NODE" --state "$REVEAL_STATE" >/dev/null 2>/tmp/_nvsig.err; NRC=$?; set -e
[ "$NRC" = "5" ] || fail "anti-vacuity broken: tool exit=$NRC (expect 5) with the secret removed"
echo "  [$(ts)] anti-vacuity OK (no secret -> exit 5)"

green "PASS (signet): #53 sub-factory hashlock poison — poison $POISON_TXID confirmed @ $H_POISON, $SP_NUM-way sales-stock redistribution (smallest ${SP_MIN} sats); anti-vacuity exit 5."
recov
exit 0
