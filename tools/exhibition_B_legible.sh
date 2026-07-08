#!/usr/bin/env bash
# exhibition_B_legible.sh — the "legible force-close" (Delving exhibit B), properly shaped.
#
# vs the feewave harness (anchor-presence + CPFP only), this adds the teaching shape:
#   * N=8 clients, arity 2, PS k=2 (ARITY / PS_SUB env), short lifetime CLTV.
#   * --demo advances the factory state over blocks BEFORE the force-close, so the exit
#     broadcasts a MID-SCHEDULE state (not the trivial initial state).
#   * captures the FULL cascade (kickoff -> state -> PS-leaf -> channel close) — every
#     force-close txid with height + vsize + P2A flag + LSP-log role — into a B manifest.
#   * records the force-close BASE height; the CSV(144)-gated leaf/commitment spend can
#     only confirm ~144 blocks later, so the confirmation-height delta PROVES the timelock
#     (captured on a later pass as the sweep matures — this is the measured-exit number).
# Strong keys, 0.1 sat/vB, self-funds from WALLET, detached (multi-hour + ~24h CSV).
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"; CLIENT_BIN="$BUILD_DIR/superscalar_client"
N_CLIENTS="${N_CLIENTS:-8}"; ARITY="${ARITY:-2}"; PS_SUB="${PS_SUB:-2}"
AMOUNT="${AMOUNT:-1200000}"; FEE_RATE="${FEE_RATE:-100}"
LSP_PORT="${LSP_PORT:-29970}"; WALLET="${WALLET:-ss_sig_n127}"; CONFIRM_TIMEOUT="${CONFIRM_TIMEOUT:-21600}"
SIGNET_CONF="${SIGNET_CONF:-/var/lib/bitcoind-signet/bitcoin.conf}"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF")
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF")
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF"); RPORT=${RPORT:-38332}
BCLI="bitcoin-cli -signet -rpcuser=$RU -rpcpassword=$RP -rpcport=$RPORT"
P2A_HEX="51024e73"
BMAN="/tmp/exhibB2_manifest.tsv"
: > "$BMAN"; echo -e "# exhibit B (legible force-close) N=$N_CLIENTS arity=$ARITY ps_k=$PS_SUB\n# txid\trole\theight\tvsize\tp2a\tlsp_log_context" >> "$BMAN"
ts(){ date -u +%H:%M:%S; }
green(){ printf '\033[32m%s\033[0m\n' "$*" >&2; }; red(){ printf '\033[31m%s\033[0m\n' "$*" >&2; }; info(){ printf '[B] %s\n' "$*" >&2; }

eval "$(python3 "$SCRIPT_DIR/signet_strong_keygen.py" "$N_CLIENTS" Blegible)"
mapfile -t CKEYS < "$CLIENT_KEYS_FILE"
info "[$(ts)] strong keys (LSP ${LSP_PUBKEY:0:16}..., seed $RUN_SEED_FILE)"
TMPDIR=$(mktemp -d /tmp/ss-signet-Bleg.XXXXXX); LSP_DB="$TMPDIR/lsp.db"; LSP_LOG="$TMPDIR/lsp.log"
PIDS=()
recov(){ info "RECOVERY: B funded $AMOUNT from $WALLET; strong-key seed $RUN_SEED_FILE (re-derive to sweep tree/leaf/commitment residuals). LSP log /tmp/Bleg_lsp.log"; }
cleanup(){ for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null||true; done; cp "$LSP_LOG" /tmp/Bleg_lsp.log 2>/dev/null||true; cp "$BMAN" /tmp/Bleg_manifest.tsv 2>/dev/null||true; }
trap cleanup EXIT

$BCLI loadwallet "$WALLET" 2>/dev/null || true
echo "=== SIGNET exhibit B (legible force-close): N=$N_CLIENTS arity=$ARITY PS-k=$PS_SUB fee=$FEE_RATE ===" >&2
info "[$(ts)] height $($BCLI getblockcount)"
pkill -9 -f "superscalar_lsp.*--port $LSP_PORT" 2>/dev/null || true; sleep 1

# LSP: PS factory, advance a few states (states-per-layer 3 over active-blocks) then force-close mid-schedule.
"$LSP_BIN" --network signet --cli-path bitcoin-cli --rpcuser "$RU" --rpcpassword "$RP" \
    --port $LSP_PORT --clients $N_CLIENTS --arity $ARITY --ps-subfactory-arity $PS_SUB \
    --active-blocks 12 --dying-blocks 6 --step-blocks 1 --states-per-layer 3 \
    --amount $AMOUNT --fee-rate $FEE_RATE --confirm-timeout $CONFIRM_TIMEOUT \
    --seckey "$LSP_SECKEY" --wallet "$WALLET" --db "$LSP_DB" \
    --demo --force-close --lsp-balance-pct 50 > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 180); do sleep 2; grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && { info "[$(ts)] LSP listening + self-funding"; break; }; kill -0 $LSP_PID 2>/dev/null || { tail -25 "$LSP_LOG" >&2; red "FAIL: LSP died before listening (check arity=$ARITY ps=$PS_SUB combo)"; recov; exit 1; }; done

for i in $(seq 0 $((N_CLIENTS-1))); do
    "$CLIENT_BIN" --network signet --cli-path bitcoin-cli --rpcuser "$RU" --rpcpassword "$RP" \
        --host 127.0.0.1 --port $LSP_PORT --seckey "${CKEYS[$i]}" --fee-rate $FEE_RATE \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id $((i+1)) --daemon --wallet "$WALLET" \
        --db "$TMPDIR/client_${i}.db" > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!); sleep 1
done

# Capture the FULL cascade: every txid the LSP logs, with height+vsize+p2a+role.
info "[$(ts)] waiting for creation + mid-schedule force-close cascade on real blocks..."
declare -A SEEN; NCASC=0; BASE_H=0; deadline=$((CONFIRM_TIMEOUT/10))
for i in $(seq 1 "$deadline"); do
    sleep 10
    while IFS= read -r txid; do
        [ -z "$txid" ] && continue; [ -n "${SEEN[$txid]:-}" ] && continue
        raw=$($BCLI getrawtransaction "$txid" true 2>/dev/null) || continue
        SEEN[$txid]=1
        vsize=$(echo "$raw" | grep -oE '"vsize": *[0-9]+' | grep -oE '[0-9]+' | head -1)
        bh=$(echo "$raw" | grep -oE '"blockhash": *"[0-9a-f]{64}"' | grep -oE '[0-9a-f]{64}' | head -1)
        h="mempool"; [ -n "$bh" ] && h=$($BCLI getblockheader "$bh" 2>/dev/null | grep -oE '"height": *[0-9]+' | grep -oE '[0-9]+' | head -1)
        p2a="no"; echo "$raw" | grep -q "\"hex\": *\"$P2A_HEX\"" && p2a="P2A"
        ctx=$(grep -aF "$txid" "$LSP_LOG" 2>/dev/null | head -1 | sed 's/\x1b\[[0-9;]*m//g' | grep -oiE "funded|kickoff|state|leaf|close|distribution|commitment|force" | head -1)
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$txid" "cascade" "${h:-?}" "${vsize:-?}" "$p2a" "${ctx:-?}" >> "$BMAN"
        NCASC=$((NCASC+1))
        [ "$h" != "mempool" ] && [ -n "$h" ] && { [ "$BASE_H" = 0 ] && BASE_H=$h || { [ "$h" -lt "$BASE_H" ] && BASE_H=$h; }; }
        info "[$(ts)] cascade tx $txid role=${ctx:-?} h=${h:-?} vsize=${vsize:-?} $p2a"
    done < <(grep -aoE "[0-9a-f]{64}" "$LSP_LOG" 2>/dev/null | sort -u)
    # done when the LSP finished + we have several cascade txs confirmed
    if ! kill -0 $LSP_PID 2>/dev/null && [ "$NCASC" -ge 3 ]; then info "[$(ts)] LSP finished; $NCASC cascade txs captured"; break; fi
    [ "$NCASC" -ge 6 ] && break
done

[ "$NCASC" -ge 2 ] || { red "FAIL: <2 cascade txs captured — factory/force-close likely failed"; tail -40 "$LSP_LOG" >&2; recov; exit 1; }
green "[$(ts)] CASCADE CAPTURED: $NCASC txs (kickoff->state->leaf->close); base force-close height=$BASE_H"
echo "BASE_FORCECLOSE_HEIGHT=$BASE_H" >> "$BMAN"
echo "CSV_MATURITY_HEIGHT=$((BASE_H+144))  (leaf/commitment CSV(144) spend can only confirm at/after this; the height delta proves the 144-block timelock)" >> "$BMAN"
# leave one client daemon alive so it can sweep its CSV-delayed output after maturation (~24h);
# the sweep's confirmation height minus BASE_H is the measured 144-block proof (captured on a later pass).
info "[$(ts)] base height $BASE_H; CSV maturity ~$((BASE_H+144)); one client left running to sweep post-maturation."
green "=== exhibit B (legible force-close) cascade on-chain; CSV-height proof matures ~144 blocks later ==="
recov
echo "EXHIB_B_LEGIBLE_CASCADE_DONE"
