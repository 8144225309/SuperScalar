#!/usr/bin/env bash
# exhibition_distribution_signet.sh — distribution-TX-at-expiry on REAL signet.
#
# Fills the post's last placeholder: "The LSP's daemon broadcasts [the distribution
# TX] automatically once the factory expires ... [txid: distribution TX at expiry]."
#
# Signet can't mine on demand, so instead of the regtest "mine past CLTV" path we
# build a MINIMIZED tree (N=2, arity 2, tiny DW steps, one static-near-root level)
# with a SHORT absolute --cltv-timeout, then let the real signet chain reach that
# height. At FACTORY_EXPIRED the LSP auto-broadcasts the pre-signed, client-favored
# distribution TX (lsp_channels.c:7182). Strong keys, 0.1 sat/vB, self-funds.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${BUILD_DIR:-/root/SuperScalar/build-release}"
LSP_BIN="$BUILD_DIR/superscalar_lsp"; CLIENT_BIN="$BUILD_DIR/superscalar_client"
N_CLIENTS="${N_CLIENTS:-8}"; ARITY="${ARITY:-2}"; AMOUNT="${AMOUNT:-800000}"; FEE_RATE="${FEE_RATE:-100}"
LSP_PORT="${LSP_PORT:-29980}"; WALLET="${WALLET:-ss_sig_n127}"
DIST_SHORT="${DIST_SHORT:-24}"           # blocks from now until factory expiry (~4h @ 10min)
CONFIRM_TIMEOUT="${CONFIRM_TIMEOUT:-36000}"   # 10h: covers the ~4h wait + confirmations
SIGNET_CONF="${SIGNET_CONF:-/var/lib/bitcoind-signet/bitcoin.conf}"
RU=$(awk -F= '/^[[:space:]]*rpcuser/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF")
RP=$(awk -F= '/^[[:space:]]*rpcpassword/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF")
RPORT=$(awk -F= '/^[[:space:]]*rpcport/{gsub(/ /,"",$2);print $2;exit}' "$SIGNET_CONF"); RPORT=${RPORT:-38332}
BCLI="bitcoin-cli -signet -rpcuser=$RU -rpcpassword=$RP -rpcport=$RPORT"
DMAN="/tmp/exhibDist_manifest.tsv"; : > "$DMAN"
ts(){ date -u +%H:%M:%S; }
green(){ printf '\033[32m%s\033[0m\n' "$*" >&2; }; red(){ printf '\033[31m%s\033[0m\n' "$*" >&2; }; info(){ printf '[DIST] %s\n' "$*" >&2; }

eval "$(python3 "$SCRIPT_DIR/signet_strong_keygen.py" "$N_CLIENTS" DistExpiry)"
mapfile -t CKEYS < "$CLIENT_KEYS_FILE"
TMPDIR=$(mktemp -d /tmp/ss-signet-dist.XXXXXX); LSP_DB="$TMPDIR/lsp.db"; LSP_LOG="$TMPDIR/lsp.log"
PIDS=()
recov(){ info "RECOVERY: funded $AMOUNT from $WALLET; seed $RUN_SEED_FILE; LSP log /tmp/Dist_lsp.log"; }
cleanup(){ for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null||true; done; cp "$LSP_LOG" /tmp/Dist_lsp.log 2>/dev/null||true; cp "$DMAN" /tmp/Dist_manifest.tsv 2>/dev/null||true; }
trap cleanup EXIT

$BCLI loadwallet "$WALLET" 2>/dev/null || true
CUR=$($BCLI getblockcount); CLTV=$((CUR + DIST_SHORT))
echo "=== SIGNET distribution-at-expiry: N=$N_CLIENTS arity=$ARITY cltv=$CLTV (now $CUR + $DIST_SHORT) fee=$FEE_RATE ===" >&2
info "[$(ts)] strong keys (LSP ${LSP_PUBKEY:0:16}..., seed $RUN_SEED_FILE)"
pkill -9 -f "superscalar_lsp.*--port $LSP_PORT" 2>/dev/null || true; sleep 1

# Minimized tree + short absolute CLTV + --test-distrib (broadcast distribution at expiry).
"$LSP_BIN" --network signet --cli-path bitcoin-cli --rpcuser "$RU" --rpcpassword "$RP" \
    --port $LSP_PORT --clients $N_CLIENTS --arity $ARITY \
    --step-blocks 1 --states-per-layer 2 --static-near-root 1 \
    --active-blocks $((DIST_SHORT/2)) --dying-blocks $((DIST_SHORT/2)) \
    --cltv-timeout $CLTV --amount $AMOUNT --fee-rate $FEE_RATE --lsp-balance-pct 50 \
    --confirm-timeout $CONFIRM_TIMEOUT --seckey "$LSP_SECKEY" --wallet "$WALLET" \
    --db "$LSP_DB" --demo --test-distrib > "$LSP_LOG" 2>&1 &
LSP_PID=$!; PIDS+=($LSP_PID)
for i in $(seq 1 180); do sleep 2; grep -q "listening on port $LSP_PORT" "$LSP_LOG" 2>/dev/null && { info "[$(ts)] LSP listening + self-funding"; break; }; kill -0 $LSP_PID 2>/dev/null || { tail -30 "$LSP_LOG" >&2; red "FAIL: LSP died before listening (CLTV $CLTV may be too short for the tree; bump DIST_SHORT)"; recov; exit 1; }; done

for i in $(seq 0 $((N_CLIENTS-1))); do
    "$CLIENT_BIN" --network signet --cli-path bitcoin-cli --rpcuser "$RU" --rpcpassword "$RP" \
        --host 127.0.0.1 --port $LSP_PORT --seckey "${CKEYS[$i]}" --fee-rate $FEE_RATE \
        --lsp-pubkey "$LSP_PUBKEY" --participant-id $((i+1)) --daemon --wallet "$WALLET" \
        --db "$TMPDIR/client_${i}.db" > "$TMPDIR/client_${i}.log" 2>&1 &
    PIDS+=($!); sleep 1
done

info "[$(ts)] factory building; will wait for signet to reach expiry height $CLTV, then the LSP auto-broadcasts the distribution TX..."
# Watch for the distribution broadcast (or a rejection) up to the confirm timeout.
DIST_TXID=""; deadline=$((CONFIRM_TIMEOUT/10))
for i in $(seq 1 "$deadline"); do
    sleep 10
    # LSP prints: "LSP: distribution TX broadcast: <txid>"
    t=$(grep -aoE "distribution TX broadcast: [0-9a-f]{64}" "$LSP_LOG" 2>/dev/null | grep -oE "[0-9a-f]{64}" | head -1)
    [ -n "$t" ] && { DIST_TXID="$t"; break; }
    if ! kill -0 $LSP_PID 2>/dev/null; then info "[$(ts)] LSP exited; scanning log for a distribution txid"; t=$(grep -aoE "distribution TX broadcast: [0-9a-f]{64}" "$LSP_LOG" 2>/dev/null | grep -oE "[0-9a-f]{64}" | head -1); [ -n "$t" ] && DIST_TXID="$t"; break; fi
    h=$($BCLI getblockcount 2>/dev/null); [ $((i % 6)) -eq 0 ] && info "  [$(ts)] height $h / expiry $CLTV"
done

[ -n "$DIST_TXID" ] || { red "FAIL: no distribution TX broadcast seen"; echo "--- LSP log tail ---" >&2; tail -40 "$LSP_LOG" >&2; recov; exit 1; }
# Confirm on-chain + record.
raw=$($BCLI getrawtransaction "$DIST_TXID" true 2>/dev/null || true)
vsize=$(echo "$raw" | grep -oE '"vsize": *[0-9]+' | grep -oE '[0-9]+' | head -1)
nout=$(echo "$raw" | grep -c '"scriptPubKey"')
printf '%s\tdistribution_at_expiry\tcltv=%s\tvsize=%s\touts=%s\n' "$DIST_TXID" "$CLTV" "${vsize:-?}" "${nout:-?}" >> "$DMAN"
green "[$(ts)] DISTRIBUTION TX at expiry broadcast on signet: $DIST_TXID (cltv $CLTV, vsize ${vsize:-?}, outs ${nout:-?})"
info "waiting 1 conf..."
for i in $(seq 1 $((CONFIRM_TIMEOUT/10))); do sleep 10; c=$($BCLI getrawtransaction "$DIST_TXID" true 2>/dev/null | grep -oE '"confirmations": *[0-9]+' | grep -oE '[0-9]+' | head -1); [ -n "$c" ] && [ "$c" -ge 1 ] && { green "  confirmed ($c conf)"; break; }; done
recov
echo "EXHIB_DISTRIBUTION_DONE $DIST_TXID"
