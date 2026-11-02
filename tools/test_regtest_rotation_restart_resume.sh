#!/usr/bin/env bash
# ROTATION RESTART-RESUME drill: a crash AFTER the irreversible Phase B close
# must be completed by the restarted LSP, never abandoned or repeated.
#
# Phase B (the dying factory's cooperative close) pays every client's channel
# balance to the LSP wallet, so from that moment until Phase C has created and
# signed the replacement factory the clients' funds exist only in the LSP's
# wallet and books.  We crash the LSP at one of two checkpoints in that window:
#
#   CKPT=rotate_close_broadcast    close confirmed, replacement NOT yet funded
#   CKPT=rotate_replacement_funded replacement funded + confirmed, NOT signed
#                                  (the state the profiles-NULL crash left)
#
# Further checkpoints around every irreversible step (each step is recorded
# BEFORE it happens, so a crash right after it is resumable):
#
#   CKPT=rotate_close_sent            close broadcast, NOT yet confirmed
#   CKPT=rotate_funding_sent          replacement funding broadcast, NOT confirmed
#   CKPT=rotate_ceremony_before_ready the creation ceremony aggregated every
#                                     signature; NO client has FACTORY_READY
#   CKPT=rotate_ceremony_signed       the ceremony delivered the signed tree to
#                                     the clients; nothing persisted yet
#
# then restart it (recovery mode, same DB).  The persisted rotation-progress
# marker must make the restarted LSP resume once the clients reconnect:
#
# PASS: the restart resumes (no second close), funds the replacement at most
#       once in total (exactly once across both runs), runs exactly ONE
#       rotation ceremony and signs the replacement ("rotation complete"), and
#       the single Phase-1 close is confirmed.
# PASS for rotate_ceremony_before_ready: nobody received the tree, so the
#       restart runs the ceremony again (one ceremony before the crash, one
#       after), never re-closes, never funds again.
# PASS for rotate_ceremony_signed: the clients may hold the signed tree, so the
#       restart runs a ceremony again ONLY over a byte-identical tree (the
#       tree rebuilt from the recorded parameters has the digest recorded
#       right before FACTORY_READY) -- the clients can never hold two
#       different trees over one output -- and never re-closes or funds again.
#
# Node/wallet are overridable so the drill can run against any private regtest
# node: REPO CONF RPCPORT RPCUSER RPCPASS WALLET PORT BUILD.
set -uo pipefail
REPO="${REPO:-/root/SuperScalar}"
cd "$REPO" || exit 1

CKPT="${CKPT:-rotate_close_broadcast}"
PORT="${PORT:-9974}"
TMP="/tmp/rot_resume_${CKPT}_$PORT"
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

cleanup() { kill -9 ${LSP1:-0} ${LSP2:-0} ${MINER:-0} 2>/dev/null || true
            pkill -9 -f "superscalar_(lsp|client).*--port $PORT " 2>/dev/null || true; }
trap cleanup EXIT

pkill -9 -f "superscalar_(lsp|client).*--port $PORT " 2>/dev/null || true
rm -rf "$TMP"; mkdir -p "$TMP"

$BCLI loadwallet "$WALLET" >/dev/null 2>&1 || true
MADDR=$($BCLI -rpcwallet="$WALLET" -named getnewaddress address_type=bech32m 2>/dev/null)
[ -n "$MADDR" ] || { echo "RESUME-FAIL: could not get mine address"; exit 1; }
$BCLI -rpcwallet="$WALLET" generatetoaddress 101 "$MADDR" >/dev/null 2>&1
echo "wallet balance: $($BCLI -rpcwallet=$WALLET getbalance) BTC ; mine_addr=$MADDR ; ckpt=$CKPT"

# --arity 1: a bare `--arity 2` (no shape setter) currently trips the separate
# startup profiles-NULL crash in tools/superscalar_lsp.c (fixed separately).
LSP_ARGS=(--network regtest --port $PORT --daemon --active-blocks 6 --dying-blocks 120
  --lsp-balance-pct 50 --clients 4 --arity 1 --amount $AMOUNT --fee-rate 1100
  --confirm-timeout 86400 --seckey $LSP_SECKEY
  --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" --wallet "$WALLET" --db "$DB")

# --- Phase 1: LSP with crash-at + 4 clients (1-based participant-id, matrix scheme) ---
SUPERSCALAR_CRASH_AT="$CKPT" "$BUILD/superscalar_lsp" "${LSP_ARGS[@]}" > "$TMP/lsp1.log" 2>&1 &
LSP1=$!
for i in $(seq 1 20); do sleep 1; grep -q listening "$TMP/lsp1.log" 2>/dev/null && break; kill -0 $LSP1 2>/dev/null || break; done
grep -q listening "$TMP/lsp1.log" || { echo "RESUME-FAIL: LSP1 never listened"; tail -8 "$TMP/lsp1.log"; exit 1; }

for N in 1 2 3 4; do
  SK=$(printf "%064x" $((N + 1)))
  "$BUILD/superscalar_client" --network regtest --host 127.0.0.1 --port $PORT --daemon \
    --seckey "$SK" --fee-rate 1100 --lsp-balance-pct 50 --lsp-pubkey $LSP_PUB \
    --participant-id $N --rpcuser "$RPCUSER" --rpcpassword "$RPCPASS" --rpcport "$RPCPORT" \
    --wallet "$WALLET" --db "$TMP/c${N}.db" > "$TMP/c${N}.log" 2>&1 &
  sleep 0.3
done

( while kill -0 $LSP1 2>/dev/null; do $BCLI -rpcwallet="$WALLET" generatetoaddress 1 "$MADDR" >/dev/null 2>&1; sleep 2; done ) &
MINER=$!

ABORTED=0
for i in $(seq 1 500); do
  sleep 1
  kill -0 $LSP1 2>/dev/null || { grep -q "lsp_crash_checkpoint: HIT '$CKPT'" "$TMP/lsp1.log" && ABORTED=1; break; }
done
if [ "$ABORTED" != 1 ]; then
  echo "RESUME-NOFIRE: LSP1 did not hit $CKPT in 500s"; grep -aE "LSP rotate:|DYING|auto-rotation|HIT" "$TMP/lsp1.log" | tail -12
  exit 1
fi
kill -9 $MINER 2>/dev/null
echo "=== Phase 1: crashed at $CKPT ==="
grep -aE "LSP rotate:|closed:|funded .*sats|HIT" "$TMP/lsp1.log" | tail -8

# The close and the funding are recorded (and logged) BEFORE their broadcast.
CLOSE1=$(grep -aoE "rotation close [0-9a-f]{64} recorded|factory [0-9]+ closed: [0-9a-f]{64}" "$TMP/lsp1.log" | grep -oE "[0-9a-f]{64}" | tail -1)
FUND1=$(grep -aoE "replacement funding [0-9a-f]{64} recorded|LSP rotate: funded [0-9]+ sats, txid: [0-9a-f]{64}" "$TMP/lsp1.log" | grep -oE "[0-9a-f]{64}" | tail -1)
echo "Phase-1 close txid: ${CLOSE1:-<none>}   Phase-1 replacement funding: ${FUND1:-<none>}"
[ -n "$CLOSE1" ] || { echo "RESUME-FAIL: no Phase-1 close txid (crash landed before close?)"; exit 1; }

# --- Phase 2: RESTART (no crash-at).  Recovery loads the progress marker and
#     resumes Phase C once the 4 still-running clients reconnect. ---
echo "=== Phase 2: restart (recovery must resume Phase C) ==="
"$BUILD/superscalar_lsp" "${LSP_ARGS[@]}" > "$TMP/lsp2.log" 2>&1 &
LSP2=$!
( while kill -0 $LSP2 2>/dev/null; do $BCLI -rpcwallet="$WALLET" generatetoaddress 1 "$MADDR" >/dev/null 2>&1; sleep 2; done ) &
MINER=$!
for i in $(seq 1 300); do
  sleep 1
  kill -0 $LSP2 2>/dev/null || break
  grep -qaE "rotation complete|new factory creation failed|HOLD:" "$TMP/lsp2.log" 2>/dev/null && { echo "outcome at ~${i}s"; break; }
done
# keep mining ~15 blocks so the recovered (already-rotated) old factory passes
# its restarted ACTIVE->DYING point: it must not be rotated again (and a held
# rotation must not run a second ceremony meanwhile).
sleep 30
kill -9 $LSP2 $MINER 2>/dev/null
sleep 1

# Phase-2 verdicts are scoped to the RESUMED rotation: lsp2.log up to its first
# "rotation complete".  With --active-blocks 6 and ~15 blocks mined after it,
# the replacement factory reaches DYING on its own schedule and is rotated
# normally (factory 1 -> 2 -> ...); those later rotations are not re-closes of
# the interrupted factory and must not count against the resume.
L2="$TMP/lsp2.log"; R2="$TMP/lsp2.resume.log"
END2=$(grep -anm1 "LSP rotate: rotation complete" "$L2" | cut -d: -f1)
if [ -n "$END2" ]; then head -n "$END2" "$L2" > "$R2"; else cp "$L2" "$R2"; fi
RFID=$(grep -aoE "rotation of factory [0-9]+" "$L2" | grep -oE "[0-9]+$" | head -1)

echo "=== Phase 2 markers (resumed rotation) ==="
grep -aE "recovery: rotation|resum|already funded|rotate|FINALIZED|closed:|funded|Phase B|Phase C|created and signed" "$R2" | tail -20
echo "=== Phase 2 after the resume (later rotations of replacement factories) ==="
tail -n +"$(( ${END2:-0} + 1 ))" "$L2" | grep -aE "ladder factory|starting rotation|closed:|created and signed|rotation complete|no DYING|rotation failed" | cut -c1-160 | tail -12

cnt() { local n; n=$(grep -acE "$1" "$2" 2>/dev/null) || n=0; echo "$n"; }
RESUMED=$(cnt "resuming rotation of factory|resuming Phase C" "$R2")
HOLD=$(cnt "HOLD:" "$L2")
IDENT=$(cnt "byte-identical to the delivered one" "$L2")
RERUN=$(cnt "stopped before any FACTORY_READY" "$L2")
# Tree digests recorded right before FACTORY_READY, before and after the restart.
D1=$(grep -aoE "replacement tree [0-9a-f]{64} recorded" "$TMP/lsp1.log" | grep -oE "[0-9a-f]{64}" | tail -1)
D2=$(grep -aoE "replacement tree [0-9a-f]{64} recorded" "$R2" | grep -oE "[0-9a-f]{64}" | tail -1)
SAME_TREE=0; [ -n "$D1" ] && [ "$D1" = "$D2" ] && SAME_TREE=1
RECLOSE=$(cnt "LSP rotate: Phase B — cooperative close|LSP rotate: factory [0-9]+ closed:|rotation close [0-9a-f]{64} recorded" "$R2")
# Rotation ceremonies (the initial factory's ceremony in phase 1 does not count).
SIGN_P1=$(awk '/LSP rotate: starting rotation/{f=1} f && /FACTORY_PROPOSE sent/{n++} END{print n+0}' "$TMP/lsp1.log")
SIGN_P2=$(cnt "FACTORY_PROPOSE sent" "$R2")
COMPLETE=$(cnt "LSP rotate: rotation complete" "$R2")
LATER=$(( $(cnt "LSP rotate: rotation complete" "$L2") - COMPLETE ))
# Whole log: the interrupted factory itself must never be rotated/closed again
# (the recovered old factory's lifecycle restarts at ACTIVE after a restart).
REROT=$(cnt "LSP rotate: no DYING/EXPIRED factory found|rotation failed [0-9]+ times" "$L2")
if [ -n "$RFID" ]; then
  REROT=$(( REROT + $(cnt "(starting rotation for|cooperative close of) factory $RFID([^0-9]|\$)|factory $RFID closed:" "$L2") ))
fi
CONF1=$($BCLI getrawtransaction "$CLOSE1" true 2>/dev/null | grep -c '"confirmations"' || true)
CONF1=${CONF1:-0}
# Every replacement funding is recorded before its broadcast ("replacement
# funding <txid> recorded"); one adopted from the wallet is announced as such.
# Distinct fundings across both runs:
FUNDS=$(grep -ahoE "replacement funding [0-9a-f]{64} recorded|already sent a replacement funding [0-9a-f]{64}" "$TMP/lsp1.log" "$R2" | grep -oE "[0-9a-f]{64}" | sort -u)
FUND_TOTAL=$(printf "%s\n" "$FUNDS" | grep -c . || true)
SIGNED_OVER=$(grep -aoE "created and signed over [0-9a-f]{64}" "$R2" | grep -oE "[0-9a-f]{64}" | tail -1)
SAME_FUND=1
if [ -n "$FUND1" ] && [ -n "$SIGNED_OVER" ] && [ "$SIGNED_OVER" != "$FUND1" ]; then SAME_FUND=0; fi

echo
echo "=== fund-safety: ckpt=$CKPT resumed=$RESUMED hold=$HOLD rerun_before_ready=$RERUN identical_tree=$IDENT same_tree_digest=$SAME_TREE reclose=$RECLOSE fund_total=$FUND_TOTAL same_funding=$SAME_FUND signings_phase1=$SIGN_P1 signings_phase2=$SIGN_P2 complete=$COMPLETE rerotate=$REROT close1_confirmed=$CONF1 later_rotations=$LATER ==="
COMMON_OK=0
if [ "$RECLOSE" -eq 0 ] && [ "$FUND_TOTAL" -eq 1 ] && [ "$SAME_FUND" -eq 1 ] && [ "$HOLD" -eq 0 ] \
   && [ "$COMPLETE" -ge 1 ] && [ "$REROT" -eq 0 ] && [ "$CONF1" -ge 1 ] && [ "$SIGN_P2" -eq 1 ]; then
  COMMON_OK=1
fi
case "$CKPT" in
  rotate_ceremony_before_ready)
    if [ "$COMMON_OK" -eq 1 ] && [ "$SIGN_P1" -eq 1 ] && [ "$RERUN" -ge 1 ]; then
      echo "RESUME-PASS: crash before any FACTORY_READY: nobody held the tree, the restart ran the ceremony again; no re-close, exactly one replacement funding ($FUNDS)."
      exit 0
    fi
    echo "RESUME-FAIL: want rerun_before_ready>=1 hold=0 signings_phase1=1 signings_phase2=1 complete>=1 reclose=0 fund_total=1 same_funding=1 rerotate=0 close1_confirmed>=1"
    exit 1 ;;
  rotate_ceremony_signed)
    if [ "$COMMON_OK" -eq 1 ] && [ "$SIGN_P1" -eq 1 ] && [ "$IDENT" -ge 1 ] && [ "$SAME_TREE" -eq 1 ]; then
      echo "RESUME-PASS: crash after FACTORY_READY: the restart ran a ceremony again only over the byte-identical tree ($D1); no re-close, exactly one replacement funding ($FUNDS)."
      exit 0
    fi
    echo "RESUME-FAIL: want identical_tree>=1 same_tree_digest=1 hold=0 signings_phase1=1 signings_phase2=1 complete>=1 reclose=0 fund_total=1 same_funding=1 rerotate=0 close1_confirmed>=1"
    exit 1 ;;
esac
if [ "$COMMON_OK" -eq 1 ] && [ "$RESUMED" -ge 1 ] && [ "$SIGN_P1" -eq 0 ]; then
  echo "RESUME-PASS: restart resumed after the close ($CLOSE1): no re-close, exactly one replacement funding ($FUNDS), exactly one rotation ceremony, replacement signed."
  exit 0
fi
echo "RESUME-FAIL: want resumed>=1 reclose=0 fund_total=1 same_funding=1 hold=0 signings_phase1=0 signings_phase2=1 complete>=1 rerotate=0 close1_confirmed>=1"
exit 1
