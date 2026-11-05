#!/usr/bin/env bash
# ROTATION KEY-CUSTODY drill: what a completed factory rotation leaves the LSP
# able to do on its own, and what it does to the clients' balances.
#
# One LSP and four client daemons build a factory, make payments so the
# balances differ from the default split, then the factory reaches DYING and
# the LSP rotates it into a replacement.  The drill then checks the
# properties a rotation must keep.  Each check prints SAFE or UNSAFE:
#
#   ORDER        no client factory secret reaches the LSP before the
#                replacement factory is funded and signed (the client must
#                already hold its own signed exit path there).
#   CLOSE_PAYEE  the old factory's close does not pay the clients' balances
#                to an LSP-controlled address; a co-signed close into the new
#                factory must have exactly one output, the replacement's
#                funding, under keys other than the old factory's.
#   BALANCES     every client's channel balance is the same after the rotation
#                (LSP view and client view), and the new tree carries it.
#   PAY_AFTER    a payment over the replacement factory succeeds, and no client
#                rejects the LSP's revocation for it.
#   KEYS_AT_REST the LSP's database holds no client secret key in the clear,
#                and none at all once the old factory is closed on chain (a
#                partial rotation keeps the released keys, sealed, while the
#                old factory still holds the clients that did not move).  The
#                seal key is derived from the LSP's own secret on the same
#                host: it protects against leaks of the database alone (a
#                backup), not of the host.
#   IDENTITY     no client key the LSP holds is a client's identity (--seckey)
#                key: a client signs each factory with its own derived key.
#   PAYOUT_KEYS  --export-factory-keys gives descriptors Bitcoin Core accepts,
#                and the tr() one pays the client's distribution-TX output.
#   RESTART      a client restarted from its DB after the rotation reloads its
#                factory key and reconnects by its identity key.
#   LSP_ALONE    the LSP cannot spend the replacement factory's funding output
#                by itself.  The drill builds that spend from key material the
#                LSP holds (its own --seckey plus the keys in its database),
#                signs it with a key-path signature and broadcasts it.  If it
#                confirms, every client's exit path in the replacement factory
#                is gone.  This runs last: it destroys the replacement.
#
# MODE=partial takes client 4 offline before DYING, so only a partial rotation
# is possible (the RESTART check then restarts client 3, which moved), and adds:
#   REPLACEMENT  every client that handed over its key holds a signed
#                replacement factory.
#   STRANDED     no replacement funding is left unspent without a signed
#                factory over it.
#   STAYER       the client that stayed in the old factory reconnects after the
#                rotation, is told that factory is retired, and exits it: its
#                old tree's root, broadcast from its own DB, confirms; the
#                LSP's database still holds that factory's tree and channels.
#
# PASS (exit 0) only if every check is SAFE.  Exit 1 if any check is UNSAFE
# or (MODE=full) the rotation did not complete; exit 2 = setup failure.
#
# Node/wallet are overridable so the drill can run against any private regtest
# node: REPO CONF RPCPORT RPCUSER RPCPASS WALLET PORT BUILD; ARITY sets the
# factory shape (--arity, default 1).
set -uo pipefail
REPO="${REPO:-/root/SuperScalar}"
cd "$REPO" || exit 2

MODE="${MODE:-full}"               # full | partial (client 4 offline at DYING)
ARITY="${ARITY:-1}"                # factory shape passed to --arity
PORT="${PORT:-9975}"
TMP="/tmp/rot_keys_${MODE}_$PORT"
N_ROT=4; [ "$MODE" = partial ] && N_ROT=3
BUILD="${BUILD:-build-release}"
CONF="${CONF:-/var/lib/bitcoind-regtest/bitcoin.conf}"
RPCPORT="${RPCPORT:-18443}"
RPCUSER="${RPCUSER:-rpcuser}"
RPCPASS="${RPCPASS:-rpcpass}"
BCLI="bitcoin-cli -regtest -conf=$CONF"
WALLET="${WALLET:-ss_cheat_leaf_miner}"
LSP_SECKEY=0000000000000000000000000000000000000000000000000000000000000001
LSP_PUB=0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
DB="$TMP/lsp.db"
AMOUNT=200000
SPEND_WALLET="rot_keys_lsp_alone_$PORT"

cleanup() { for p in ${LSP:-} ${MINER:-} ${HOLD:-}; do kill -9 "$p" 2>/dev/null; done
            pkill -9 -f "superscalar_(lsp|client).*--port $PORT " 2>/dev/null || true; }
trap cleanup EXIT

pkill -9 -f "superscalar_(lsp|client).*--port $PORT " 2>/dev/null || true
rm -rf "$TMP"; mkdir -p "$TMP"
L="$TMP/lsp.log"

$BCLI loadwallet "$WALLET" >/dev/null 2>&1 || true
MADDR=$($BCLI -rpcwallet="$WALLET" -named getnewaddress address_type=bech32m 2>/dev/null)
[ -n "$MADDR" ] || { echo "KEYS-SETUP-FAIL: could not get mine address"; exit 2; }
$BCLI -rpcwallet="$WALLET" generatetoaddress 101 "$MADDR" >/dev/null 2>&1

start_miner() { ( while kill -0 $LSP 2>/dev/null; do
                    $BCLI -rpcwallet="$WALLET" generatetoaddress 1 "$MADDR" >/dev/null 2>&1; sleep 2
                  done ) & MINER=$!; }
stop_miner()  { [ -n "${MINER:-}" ] && { kill -9 "$MINER" 2>/dev/null; wait "$MINER" 2>/dev/null; }; MINER=; }
cli()         { echo "$1" > "$TMP/cli"; }
wait_log()    { # wait_log <file> <ERE> <secs>
  local i; for i in $(seq 1 "$3"); do grep -qaE "$2" "$1" 2>/dev/null && return 0
    kill -0 $LSP 2>/dev/null || return 1; sleep 1; done; return 1; }
cnt()         { local n; n=$(grep -acE "$1" "$2" 2>/dev/null) || n=0; echo "$n"; }

declare -A CPID
mkfifo "$TMP/cli"
sleep infinity > "$TMP/cli" & HOLD=$!

LSP_ARGS=(--network regtest --port $PORT --daemon --cli --active-blocks 12 --dying-blocks 120
  --lsp-balance-pct 50 --clients 4 --arity "$ARITY" --amount $AMOUNT --fee-rate 1100
  --confirm-timeout 86400 --seckey $LSP_SECKEY
  --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" --wallet "$WALLET" --db "$DB")
stdbuf -oL "$BUILD/superscalar_lsp" "${LSP_ARGS[@]}" < "$TMP/cli" > "$L" 2>&1 &
LSP=$!
wait_log "$L" "listening" 20 || { echo "KEYS-SETUP-FAIL: LSP never listened"; tail -8 "$L"; exit 2; }

start_client() { # start_client <N>: client N (seckey N+1), log appended
  local N=$1 SK
  SK=$(printf "%064x" $((N + 1)))
  stdbuf -oL "$BUILD/superscalar_client" --network regtest --host 127.0.0.1 --port $PORT --daemon \
    --seckey "$SK" --fee-rate 1100 --lsp-balance-pct 50 --lsp-pubkey $LSP_PUB \
    --participant-id $N --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
    --wallet "$WALLET" --db "$TMP/c${N}.db" >> "$TMP/c${N}.log" 2>&1 &
  CPID[$N]=$!
}
for N in 1 2 3 4; do
  start_client $N
  sleep 0.3
done

start_miner
wait_log "$L" "ladder initialized" 180 || { echo "KEYS-SETUP-FAIL: factory 0 never created"; tail -8 "$L"; exit 2; }
# Hold the chain until the payments are done, so the factory cannot reach
# DYING first.
stop_miner
wait_log "$L" "daemon loop started" 120 || { echo "KEYS-SETUP-FAIL: no daemon loop"; tail -8 "$L"; exit 2; }
sleep 3

# --- Payments: move the balances away from the default split ---
for P in "0 1 7000" "2 3 4000" "1 2 1500"; do
  before=$(cnt "CLI: pay (succeeded|FAILED)" "$L")
  cli "pay $P"
  for i in $(seq 1 30); do sleep 1; [ "$(cnt "CLI: pay (succeeded|FAILED)" "$L")" -gt "$before" ] && break; done
done
PRE_OK=$(cnt "CLI: pay succeeded" "$L")
echo "pre-rotation payments: $PRE_OK/3 succeeded"
sleep 2
cli "status"; sleep 2
grep -aE "^  Channel [0-9]+: local=" "$L" | tail -4 > "$TMP/pre_status"
echo "=== pre-rotation balances (LSP view; remote = client) ==="; cat "$TMP/pre_status"

if [ "$MODE" = partial ]; then
  # Client 4 goes offline before DYING: the rotation can only be partial.
  kill -9 "${CPID[4]}" 2>/dev/null
  sleep 5
  echo "client 4 taken offline before DYING"
fi

# --- Rotation ---
start_miner
wait_log "$L" "LSP rotate: rotation complete|auto-rotation FAILED|new factory creation failed" 400
stop_miner     # a replacement with --active-blocks 12 must not reach DYING too
COMPLETE=$(cnt "LSP rotate: rotation complete" "$L")
echo "=== rotation key lines ==="
grep -aE "LSP rotate:|auto-rotation" "$L" | grep -v "stray msg" | cut -c1-170 | head -40
if [ "$COMPLETE" -lt 1 ] && [ "$MODE" != partial ]; then
  echo "KEYS-FAIL: the rotation did not complete"; exit 1
fi

POST_OK=0; POST_DONE=0
if [ "$COMPLETE" -ge 1 ]; then
  # Clients reconnect from their databases after the rotation.
  for i in $(seq 1 60); do
    sleep 1
    [ "$(grep -l "rotation complete, reconnecting" "$TMP"/c?.log 2>/dev/null | wc -l)" -ge "$N_ROT" ] && break
  done
  sleep 8
  cli "status"; sleep 2
  grep -aE "^  Channel [0-9]+: local=" "$L" | tail -"$N_ROT" > "$TMP/post_status"
  grep -aE "^  Leaf [0-9]+: " "$L" | tail -4 > "$TMP/post_leaves"
  echo "=== post-rotation balances (LSP view) ==="; cat "$TMP/post_status"; cat "$TMP/post_leaves"
  echo "=== client view at rotation ==="
  grep -ahE "rotation channel [0-9]+ ready|REFUSING rotation|rotation complete, reconnecting" "$TMP"/c?.log | cut -c1-150

  before=$(cnt "CLI: pay (succeeded|FAILED)" "$L")
  cli "pay 1 0 1000"     # client index 1 has spare balance above its reserve
  for i in $(seq 1 30); do sleep 1; [ "$(cnt "CLI: pay (succeeded|FAILED)" "$L")" -gt "$before" ] && break; done
  POST_OK=$(( $(cnt "CLI: pay succeeded" "$L") - PRE_OK ))
  POST_DONE=$(( $(cnt "CLI: pay (succeeded|FAILED)" "$L") - before ))

  # Restart a client that moved from its DB (it takes no part in the payment
  # above): it must reload its factory key and reconnect by its identity key.
  RC=4; [ "$MODE" = partial ] && RC=3
  kill -9 "${CPID[$RC]}" 2>/dev/null; sleep 2
  echo "--- client $RC restarted ---" >> "$TMP/c$RC.log"
  start_client $RC
  for i in $(seq 1 60); do
    sleep 1
    sed -n "/client $RC restarted/,\$p" "$TMP/c$RC.log" | grep -qa "reconnected (channel=" && break
  done
  RESTART_LOG=$(sed -n "/client $RC restarted/,\$p" "$TMP/c$RC.log" | grep -aE "factory key|reconnected \(channel|REFUSING" | tr '\n' ' ' | cut -c1-200)
fi

UNSAFE=0
verdict() { # verdict <name> <0=safe|1=unsafe> <detail>
  if [ "$2" = 0 ]; then echo "CHECK $1: SAFE -- $3"; else echo "CHECK $1: UNSAFE -- $3"; UNSAFE=1; fi; }
echo
echo "=================== checks ($MODE) ==================="

# --- ORDER: key reveal vs replacement funded + signed ---
LN_X=$(grep -naE "key extracted via wire PTLC|released its old factory key" "$L" | head -1 | cut -d: -f1)
LN_F=$(grep -naE "LSP rotate: funded [0-9]+ sats" "$L" | head -1 | cut -d: -f1)
LN_S=$(grep -naE "LSP rotate: factory [0-9]+ created and signed over" "$L" | head -1 | cut -d: -f1)
N_X=$(cnt "key extracted via wire PTLC|released its old factory key" "$L")
if [ -n "$LN_X" ] && { [ -z "$LN_S" ] || [ "$LN_X" -lt "$LN_S" ] || [ -z "$LN_F" ] || [ "$LN_X" -lt "$LN_F" ]; }; then
  verdict ORDER 1 "$N_X client keys extracted at log line $LN_X; replacement funded at line ${LN_F:-never}, signed at line ${LN_S:-never}"
else
  verdict ORDER 0 "no key left a client before the replacement was funded and signed (release=${LN_X:-none} signed=${LN_S:-none} funded=${LN_F:-none})"
fi

# --- CLOSE_PAYEE: where the old factory's close sends the client balances ---
CLOSE_TXID=$(grep -aoE "LSP rotate: factory [0-9]+ closed: [0-9a-f]{64}" "$L" | grep -oE "[0-9a-f]{64}" | head -1)
LSP_ADDR=$(grep -aoE "close outputs to wallet address [a-z0-9]+" "$L" | awk '{print $NF}' | head -1)
if [ -n "$CLOSE_TXID" ]; then
  # The close pays the LSP wallet, so the wallet knows it (no -txindex needed).
  $BCLI -rpcwallet="$WALLET" gettransaction "$CLOSE_TXID" true true > "$TMP/close.json" 2>/dev/null
  read -r N_OUT N_LSP SATS_LSP < <(python3 - "$TMP/close.json" "${LSP_ADDR:-none}" <<'PY'
import json, sys
tx = json.load(open(sys.argv[1]))["decoded"]; a = sys.argv[2]
outs = tx["vout"]; mine = [o for o in outs if o["scriptPubKey"].get("address") == a]
print(len(outs), len(mine), round(sum(o["value"] for o in mine) * 1e8))
PY
)
  echo "close $CLOSE_TXID: $N_OUT outputs, $N_LSP pay the LSP wallet address $LSP_ADDR ($SATS_LSP sats)"
  if [ "${N_LSP:-0}" -gt 1 ]; then
    verdict CLOSE_PAYEE 1 "all client balance outputs of the close ($N_LSP of $N_OUT outputs, $SATS_LSP sats) pay the LSP's own wallet address"
  else
    verdict CLOSE_PAYEE 0 "client outputs of the close do not pay the LSP wallet"
  fi
else
  CIN_CLOSE=$(grep -aoE "LSP rotate: close [0-9a-f]{64} of factory [0-9]+ built" "$L" | grep -oE "[0-9a-f]{64}" | head -1)
  if [ -n "$CIN_CLOSE" ] && [ "$COMPLETE" -ge 1 ]; then
    # Co-signed close into the new factory: one output, the replacement's
    # funding, under keys that are not the old factory's.
    read -r C_NOUT C_SPK C_AMT < <($BCLI getrawtransaction "$CIN_CLOSE" 1 2>/dev/null | python3 -c '
import json,sys; t=json.load(sys.stdin); o=t["vout"]
print(len(o), o[0]["scriptPubKey"]["hex"], round(o[0]["value"]*1e8))' 2>/dev/null)
    O_TXID=$(grep -aoE "^LSP: funded [0-9]+ sats, txid: [0-9a-f]{64}" "$L" | grep -oE "[0-9a-f]{64}" | head -1)
    O_VOUT=$(grep -aoE "^LSP: funding vout=[0-9]+" "$L" | grep -oE "[0-9]+$" | head -1)
    O_SPK=$($BCLI getrawtransaction "$O_TXID" 1 2>/dev/null | python3 -c '
import json,sys; t=json.load(sys.stdin); print(t["vout"][int(sys.argv[1])]["scriptPubKey"]["hex"])' "${O_VOUT:-0}" 2>/dev/null)
    if [ "${C_NOUT:-0}" = 1 ] && [ -n "$C_SPK" ] && [ "$C_SPK" != "$O_SPK" ]; then
      verdict CLOSE_PAYEE 0 "co-signed close $CIN_CLOSE has one output ($C_AMT sats) and it is the replacement's funding, under fresh keys (old SPK ${O_SPK:0:16}.., new ${C_SPK:0:16}..)"
    else
      verdict CLOSE_PAYEE 1 "close $CIN_CLOSE: outputs=${C_NOUT:-?} spk=${C_SPK:-?} old_spk=${O_SPK:-?}"
    fi
  else
    verdict CLOSE_PAYEE 0 "no cooperative close of the old factory"
  fi
fi

if [ "$COMPLETE" -lt 1 ]; then
  # --- REPLACEMENT: a client that handed over its key must be in a signed
  #     replacement factory ---
  verdict REPLACEMENT 1 "the rotation did not complete ($(grep -aoE "new factory creation failed|auto-rotation FAILED[^\n]*" "$L" | head -1)); $N_X client(s) handed over their factory key and hold no replacement factory"
  # --- STRANDED: the replacement funding must be spendable by a signed tree ---
  OLD_TXID=$(grep -aoE "^LSP: funded [0-9]+ sats, txid: [0-9a-f]{64}" "$L" | grep -oE "[0-9a-f]{64}" | head -1)
  OLD_VOUT=$(grep -aoE "^LSP: funding vout=[0-9]+" "$L" | grep -oE "[0-9]+$" | head -1)
  RF=$(grep -aoE "LSP rotate: funded [0-9]+ sats, txid: [0-9a-f]{64}, vout=[0-9]+" "$L" | tail -1)
  RF_TXID=$(echo "$RF" | grep -oE "[0-9a-f]{64}"); RF_VOUT=$(echo "$RF" | grep -oE "vout=[0-9]+" | cut -d= -f2)
  spk_of() { $BCLI gettxout "$1" "$2" 2>/dev/null | python3 -c 'import json,sys; j=json.load(sys.stdin); print(j["scriptPubKey"]["hex"], round(j["value"]*1e8))' 2>/dev/null; }
  OLD_SPK=$(spk_of "$OLD_TXID" "${OLD_VOUT:-0}"); RF_SPK=""
  [ -n "$RF_TXID" ] && RF_SPK=$(spk_of "$RF_TXID" "$RF_VOUT")
  if [ -n "$RF_SPK" ]; then
    same="different"; [ "${RF_SPK% *}" = "${OLD_SPK% *}" ] && same="the SAME"
    verdict STRANDED 1 "replacement funding $RF_TXID:$RF_VOUT (${RF_SPK#* } sats) is unspent with no signed factory over it; its output key is $same key as the old factory's (aggregate over all 5 participants, including the offline client)"
  else
    verdict STRANDED 0 "no unspent replacement funding without a factory"
  fi
  echo "old factory funding $OLD_TXID:${OLD_VOUT:-0} unspent: $([ -n "$OLD_SPK" ] && echo "yes (${OLD_SPK#* } sats)" || echo no)"
fi

if [ "$COMPLETE" -ge 1 ] && [ "$MODE" = partial ]; then
  # --- REPLACEMENT: every client that released its key holds the replacement ---
  REL=$(cnt "released its old factory key" "$L"); MISS=""
  for N in $(seq 1 "$N_ROT"); do
    grep -qa "old factory key released" "$TMP/c$N.log" || continue
    grep -qa "switched to the replacement factory" "$TMP/c$N.log" || MISS="$MISS c$N"
  done
  if [ -z "$MISS" ] && [ "$REL" -ge 1 ]; then
    verdict REPLACEMENT 0 "$REL client(s) released their key, each after switching to the signed, funded replacement"
  else
    verdict REPLACEMENT 1 "released=$REL; without the replacement:${MISS:- none}"
  fi
  # --- STRANDED: the replacement funding is the signed factory's ---
  RF=$(grep -aoE "LSP rotate: funded [0-9]+ sats, txid: [0-9a-f]{64}, vout=[0-9]+" "$L" | tail -1)
  RF_TXID=$(echo "$RF" | grep -oE "[0-9a-f]{64}")
  SG=$(grep -aoE "LSP rotate: factory [0-9]+ created and signed over [0-9a-f]{64}" "$L" | grep -oE "[0-9a-f]{64}" | tail -1)
  if [ -n "$RF_TXID" ] && [ "$RF_TXID" = "$SG" ]; then
    verdict STRANDED 0 "the one replacement funding $RF_TXID was signed over before it was broadcast"
  else
    verdict STRANDED 1 "replacement funding ${RF_TXID:-none}, signed over ${SG:-none}"
  fi
fi

# --- BALANCES: per-client balance before vs after ---
BAL_BAD=0; BAL_DETAIL=""
[ "$COMPLETE" -ge 1 ] && for c in $(seq 0 $((N_ROT - 1))); do
  pre=$(grep -aE "^  Channel $c: " "$TMP/pre_status" | sed -E 's/.*local=([0-9]+) remote=([0-9]+).*/\1 \2/')
  post=$(grep -aE "^  Channel $c: " "$TMP/post_status" | sed -E 's/.*local=([0-9]+) remote=([0-9]+).*/\1 \2/')
  BAL_DETAIL="$BAL_DETAIL ch$c[pre lsp/client=${pre// //} post=${post// //}]"
  [ "${pre#* }" = "${post#* }" ] && [ -n "$pre" ] || BAL_BAD=1
done
# The client must see the same balance as the LSP.
[ "$COMPLETE" -ge 1 ] && for N in $(seq 1 "$N_ROT"); do
  cl=$(grep -aoE "rotation channel [0-9]+ ready \(local=[0-9]+, remote=[0-9]+\)" "$TMP/c$N.log" | tail -1)
  [ -n "$cl" ] && BAL_DETAIL="$BAL_DETAIL c$N:'${cl#rotation channel }'"
  grep -qa "REFUSING rotation" "$TMP/c$N.log" && { BAL_BAD=1; BAL_DETAIL="$BAL_DETAIL c$N:REFUSED"; }
  # Both sides must sign commitments over the same channel funding amount
  # (a taproot sighash commits to it).
  lf=$(sqlite3 "$DB" "SELECT funding_amount FROM channels WHERE factory_id=0 AND slot=$((N - 1)) ORDER BY id DESC LIMIT 1;" 2>/dev/null)
  cf=$(sqlite3 "$TMP/c$N.db" "SELECT local_amount||'/'||funding_amount FROM channels ORDER BY id DESC LIMIT 1;" 2>/dev/null)
  BAL_DETAIL="$BAL_DETAIL c$N-db[client/funding=$cf lsp-funding=$lf]"
  [ "${cf#*/}" = "$lf" ] || BAL_BAD=1
done
if [ "$COMPLETE" -ge 1 ]; then
  verdict BALANCES $BAL_BAD "$BAL_DETAIL"
  # --- PAY_AFTER ---
  REJ=""
  for N in 1 2 3 4; do
    sed -n '/rotation complete, reconnecting/,$p' "$TMP/c$N.log" 2>/dev/null |
      grep -qa "LSP revocation FAILED verification" && REJ="$REJ c$N"
  done
  if [ "$POST_OK" -ge 1 ] && [ -n "$REJ" ]; then
    verdict PAY_AFTER 1 "the LSP reports pay 1->0 succeeded, but client(s) $REJ rejected the LSP's revocation as forged and halted"
  elif [ "$POST_OK" -ge 1 ]; then verdict PAY_AFTER 0 "pay 1->0 after rotation succeeded"
  else verdict PAY_AFTER 1 "pay 1->0 after rotation: ${POST_DONE} result line(s), 0 succeeded ($(grep -aE "CLI: pay|LSP: .*(fail|FAIL|reject)" "$L" | tail -2 | tr '\n' ' ' | cut -c1-200))"; fi
fi

# --- RESTART: a client restart reloads its factory key ---
if [ "$COMPLETE" -ge 1 ]; then
  if echo "$RESTART_LOG" | grep -q "reloaded" && echo "$RESTART_LOG" | grep -q "reconnected"; then
    verdict RESTART 0 "client $RC restarted: $RESTART_LOG"
  else
    verdict RESTART 1 "client $RC restarted: ${RESTART_LOG:-no reconnect}"
  fi
fi

# --- KEYS_AT_REST ---
CLOSE_CONF=0
[ -s "$TMP/close.json" ] && CLOSE_CONF=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("confirmations",0))' "$TMP/close.json" 2>/dev/null || echo 0)
sqlite3 "$DB" "SELECT factory_id, client_idx, extracted_key FROM departed_clients ORDER BY factory_id, client_idx;" > "$TMP/departed.txt" 2>/dev/null
N_DEP=$(grep -c . "$TMP/departed.txt")
N_PLAIN=$(awk -F'|' 'length($3)==64' "$TMP/departed.txt" | grep -c .)
IDENT=0
while IFS='|' read -r fid cidx key; do
  [ "$key" = "$(printf "%064x" $((cidx + 1)))" ] && IDENT=$((IDENT + 1))
done < "$TMP/departed.txt"
if [ "$IDENT" -gt 0 ]; then
  verdict IDENTITY 1 "$IDENT of the $N_DEP client key(s) the LSP holds equal the client's own --seckey (its identity key)"
else
  verdict IDENTITY 0 "none of the $N_DEP client key(s) the LSP holds is a client's identity key"
fi
N_SEALED=$(awk -F'|' 'index($3,"dk1:")==1' "$TMP/departed.txt" | grep -c .)
OLD_OPEN=0
O_TXID=$(grep -aoE "^LSP: funded [0-9]+ sats, txid: [0-9a-f]{64}" "$L" | grep -oE "[0-9a-f]{64}" | head -1)
O_VOUT=$(grep -aoE "^LSP: funding vout=[0-9]+" "$L" | grep -oE "[0-9]+$" | head -1)
[ -n "$O_TXID" ] && [ -n "$($BCLI gettxout "$O_TXID" "${O_VOUT:-0}" 2>/dev/null)" ] && OLD_OPEN=1
if [ "$N_DEP" -gt 0 ] && [ "$N_PLAIN" -eq 0 ] && [ "$N_SEALED" -eq "$N_DEP" ] && [ "$OLD_OPEN" -eq 1 ] && [ "$IDENT" -eq 0 ]; then
  verdict KEYS_AT_REST 0 "the $N_DEP released key(s) are sealed (none in the clear) while the old factory is still open for the clients that did not move"
elif [ "$N_DEP" -gt 0 ]; then
  verdict KEYS_AT_REST 1 "old factory close confirmations: $CLOSE_CONF (old funding unspent: $OLD_OPEN); departed_clients holds $N_DEP client secret key(s) ($N_PLAIN as plaintext hex, $N_SEALED sealed); $IDENT of them equal the client's own --seckey (its identity and channel key)"
else
  verdict KEYS_AT_REST 0 "no client secret key left in the LSP database"
fi

# --- STAYER: the client that stayed is told to exit, and can ---
if [ "$MODE" = partial ] && [ "$COMPLETE" -ge 1 ]; then
  echo "--- client 4 back after the rotation ---" >> "$TMP/c4.log"
  start_client 4
  for i in $(seq 1 40); do
    sleep 1
    grep -qa "a client of a factory retired by a partial rotation" "$L" && break
  done
  TOLD=$(cnt "a client of a factory retired by a partial rotation" "$L")
  kill -9 "${CPID[4]}" 2>/dev/null; sleep 1
  ROOT=$(sqlite3 "$TMP/c4.db" "SELECT txid FROM tree_nodes WHERE factory_id = 0 AND (parent_index IS NULL OR parent_index < 0) LIMIT 1;" 2>/dev/null)
  timeout 180 "$BUILD/superscalar_client" --network regtest --seckey "$(printf "%064x" 5)" \
    --db "$TMP/c4.db" --force-close --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" \
    --rpcport "$RPCPORT" --wallet "$WALLET" > "$TMP/c4-exit.log" 2>&1
  $BCLI -rpcwallet="$WALLET" generatetoaddress 1 "$MADDR" >/dev/null 2>&1
  ROOT_CONF=$($BCLI getrawtransaction "$ROOT" 1 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("confirmations",0))' 2>/dev/null)
  # The LSP kept the old factory (tree, channels) under its retired ids.
  RET_TREE=$(sqlite3 "$DB" "SELECT COUNT(*) FROM tree_nodes WHERE factory_id >= 65536 AND factory_id < 131072;" 2>/dev/null)
  RET_CH=$(sqlite3 "$DB" "SELECT COUNT(*) FROM channels WHERE factory_id >= 65536 AND factory_id < 131072;" 2>/dev/null)
  if [ "${TOLD:-0}" -ge 1 ] && [ "${ROOT_CONF:-0}" -ge 1 ] && [ "${RET_TREE:-0}" -ge 1 ] && [ "${RET_CH:-0}" -ge 4 ]; then
    verdict STAYER 0 "client 4 reconnected, was told its factory is retired, and its exit confirmed (old root ${ROOT:0:16}.. $ROOT_CONF conf); the LSP kept the old factory ($RET_TREE tree rows, $RET_CH channels)"
  else
    verdict STAYER 1 "told=$TOLD old root ${ROOT:-none} confirmations=${ROOT_CONF:-0} kept tree=${RET_TREE:-0} channels=${RET_CH:-0} ($(tail -2 "$TMP/c4-exit.log" | tr '\n' ' ' | cut -c1-160))"
  fi
fi

# --- PAYOUT_KEYS: the exported descriptors pay this client's outputs ---
EXP=$("$BUILD/superscalar_client" --network regtest --seckey "$(printf "%064x" 2)" \
        --db "$TMP/c1.db" --export-factory-keys 2>/dev/null)
TRD=$(echo "$EXP" | awk '/distribution TX/{d=$3} END{print d}')
RAWD=$(echo "$EXP" | awk '/cooperative close/{d=$3} END{print d}')
DIST_HEX=$(sqlite3 "$TMP/c1.db" "SELECT signed_tx_hex FROM distribution_txs ORDER BY factory_id DESC LIMIT 1;" 2>/dev/null)
PAY_DETAIL="no exported descriptor"
PAY_BAD=1
if [ -n "$TRD" ] && [ -n "$RAWD" ] && [ -n "$DIST_HEX" ]; then
  # The checksums are the ones Bitcoin Core computes, and the tr() key is the
  # output key of client 1's output in its stored distribution TX.
  CK_RAW=$($BCLI getdescriptorinfo "${RAWD%#*}" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["checksum"])' 2>/dev/null)
  TR_PUB=$($BCLI getdescriptorinfo "${TRD%#*}" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["descriptor"])' 2>/dev/null)
  TR_ADDR=$($BCLI deriveaddresses "$TR_PUB" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)[0])' 2>/dev/null)
  IN_DIST=$($BCLI decoderawtransaction "$DIST_HEX" 2>/dev/null | python3 -c 'import json,sys; a=sys.argv[1]; t=json.load(sys.stdin); print(sum(1 for o in t["vout"] if o["scriptPubKey"].get("address")==a))' "$TR_ADDR" 2>/dev/null)
  PAY_DETAIL="rawtr checksum ours=${RAWD#*#} core=${CK_RAW:-?}; tr() address ${TR_ADDR:-?} is ${IN_DIST:-0} output(s) of client 1's distribution TX"
  [ "${RAWD#*#}" = "$CK_RAW" ] && [ "${IN_DIST:-0}" -ge 1 ] && PAY_BAD=0
fi
verdict PAYOUT_KEYS $PAY_BAD "$PAY_DETAIL"

# --- LSP_ALONE: key-path spend of the replacement funding, LSP-held keys only ---
NEW_FUND=$(grep -aoE "LSP rotate: funded [0-9]+ sats, txid: [0-9a-f]{64}, vout=[0-9]+" "$L" | tail -1)
NEW_TXID=$(echo "$NEW_FUND" | grep -oE "[0-9a-f]{64}")
NEW_VOUT=$(echo "$NEW_FUND" | grep -oE "vout=[0-9]+" | cut -d= -f2)
if [ -z "$NEW_TXID" ] && [ -n "${CIN_CLOSE:-}" ] && [ "$COMPLETE" -ge 1 ]; then
  NEW_TXID=$CIN_CLOSE; NEW_VOUT=0
fi
SPENT_BY=""
# Client 1's own signed root kickoff of the replacement: its first exit step.
kickoff_accept() {
  local hex; hex=$(sqlite3 "$TMP/c1.db" "SELECT signed_tx_hex FROM tree_nodes WHERE node_index=0 ORDER BY factory_id DESC LIMIT 1;" 2>/dev/null)
  [ -n "$hex" ] || { echo "no-signed-kickoff"; return; }
  $BCLI testmempoolaccept "[\"$hex\"]" 2>/dev/null | python3 -c 'import json,sys; r=json.load(sys.stdin)[0]; print("allowed" if r.get("allowed") else r.get("reject-reason","rejected"))'
}
KICK_BEFORE=$(kickoff_accept)
echo "client 1's signed kickoff of the replacement, before the LSP-alone spend: $KICK_BEFORE"
if [ -n "$NEW_TXID" ]; then
  NEW_SPK=$($BCLI gettxout "$NEW_TXID" "$NEW_VOUT" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["scriptPubKey"]["hex"])' 2>/dev/null)
  # The aggregate key of [LSP, client 1..N] (MuSig2 KeyAgg, BIP327) from the
  # LSP's own secret and the client secrets in its database; WIF on success.
  WIF=$(python3 - "$LSP_SECKEY" "$TMP/departed.txt" "${NEW_SPK:-}" <<'PY'
import hashlib, sys
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    if a == b: l = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else: l = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (l * l - a[0] - b[0]) % P
    return (x, (l * (a[0] - x) - a[1]) % P)
def mul(k, pt=G):
    r = None
    while k:
        if k & 1: r = add(r, pt)
        pt = add(pt, pt); k >>= 1
    return r
def ser(pt): return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")
def th(tag, m):
    t = hashlib.sha256(tag.encode()).digest(); return hashlib.sha256(t + t + m).digest()
secs = [int(sys.argv[1], 16)]
rows = [l.strip().split("|") for l in open(sys.argv[2]) if l.strip()]
if not rows:
    sys.stderr.write("lsp-held keys: the LSP holds no client key at all\n")
    sys.exit(1)
fid0 = min(int(r[0]) for r in rows)                  # the rotated (dying) factory
rows = sorted((int(r[1]), r[2]) for r in rows if int(r[0]) == fid0)
secs += [int(k, 16) for _, k in rows]
pks = [ser(mul(s)) for s in secs]
L = th("KeyAgg list", b"".join(pks))
pk2 = next((p for p in pks[1:] if p != pks[0]), None)
coef = [1 if p == pk2 else int.from_bytes(th("KeyAgg coefficient", L + p), "big") % N for p in pks]
d = sum(a * s for a, s in zip(coef, secs)) % N      # Q = d*G
Q = mul(d)
t = int.from_bytes(th("TapTweak", Q[0].to_bytes(32, "big")), "big")
Pe = Q if Q[1] % 2 == 0 else (Q[0], P - Q[1])
out = add(Pe, mul(t))
spk = "5120" + out[0].to_bytes(32, "big").hex()
want = sys.argv[3] if len(sys.argv) > 3 else ""
sys.stderr.write("lsp-held keys: 1 LSP + %d client(s); aggregate output key spk=%s; "
                 "replacement funding spk=%s; match=%s\n" % (len(rows), spk, want, spk == want))
if spk != want: sys.exit(1)
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
raw = b"\xef" + d.to_bytes(32, "big") + b"\x01"
raw += hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
n = int.from_bytes(raw, "big"); s = ""
while n: n, r = divmod(n, 58); s = B58[r] + s
print(s)
PY
)
  if [ -n "$WIF" ]; then
    $BCLI -named createwallet wallet_name="$SPEND_WALLET" blank=true >/dev/null 2>&1
    DESC=$($BCLI getdescriptorinfo "tr($WIF)" | python3 -c 'import json,sys; print(json.load(sys.stdin)["checksum"])')
    $BCLI -rpcwallet="$SPEND_WALLET" importdescriptors "[{\"desc\":\"tr($WIF)#$DESC\",\"timestamp\":0}]" > "$TMP/import.json" 2>&1
    DEST=$($BCLI -rpcwallet="$WALLET" -named getnewaddress address_type=bech32m)
    $BCLI -rpcwallet="$SPEND_WALLET" -named sendall recipients="[\"$DEST\"]" fee_rate=5 \
      options="{\"inputs\":[{\"txid\":\"$NEW_TXID\",\"vout\":$NEW_VOUT}]}" > "$TMP/sendall.json" 2>&1
    SPENT_BY=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("txid",""))' "$TMP/sendall.json" 2>/dev/null)
    [ -n "$SPENT_BY" ] && $BCLI -rpcwallet="$WALLET" generatetoaddress 1 "$MADDR" >/dev/null 2>&1
    sed 's/^/  sendall: /' "$TMP/sendall.json" | head -5
  fi
fi
if [ -n "$SPENT_BY" ]; then
  INFO=$($BCLI -rpcwallet="$SPEND_WALLET" gettransaction "$SPENT_BY" true true | python3 -c '
import json,sys; j=json.load(sys.stdin); t=j["decoded"]
w=t["vin"][0].get("txinwitness",[])
print("confirmations=%s inputs=%d witness_items=%d sig_bytes=%d" % (j.get("confirmations",0), len(t["vin"]), len(w), len(w[0])//2 if w else 0))')
  KICK_AFTER=$(kickoff_accept)
  STILL=$($BCLI gettxout "$NEW_TXID" "$NEW_VOUT" 2>/dev/null)
  verdict LSP_ALONE 1 "replacement funding $NEW_TXID:$NEW_VOUT spent by $SPENT_BY, signed only with LSP-held keys ($INFO; outpoint unspent now: ${STILL:+yes}${STILL:-no}; client 1's signed kickoff: before=$KICK_BEFORE after=$KICK_AFTER)"
else
  verdict LSP_ALONE 0 "the LSP's key material does not sign for the replacement funding ${NEW_TXID:-?}:${NEW_VOUT:-?}"
fi

echo
if [ "$UNSAFE" = 0 ]; then echo "KEYS-PASS: every check SAFE"; exit 0; fi
echo "KEYS-FAIL: at least one check UNSAFE"
exit 1
