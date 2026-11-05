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
# With every client online and able to, a rotation closes the old factory
# straight into the new one (co-signed, fresh client keys, nothing revealed),
# so those checkpoints are:
#
#   CKPT=rotate_close_built          the unsigned close is recorded
#   CKPT=rotate_ceremony_before_ready the replacement's signatures are
#                                     aggregated; no client has FACTORY_READY
#   CKPT=rotate_ceremony_signed      clients hold the signed replacement tree
#   CKPT=rotate_initial_commitments  clients hold their initial commitments
#   CKPT=rotate_close_signing        the close ceremony is about to start
#   CKPT=rotate_close_signed         the close is aggregated, not yet recorded
#                                     (no client got CLOSE_DONE)
#   CKPT=rotate_close_sent           the close is recorded with the
#                                     replacement and broadcast
#
# A partial rotation (CKPT=rotate_part_*; the LSP takes the partial path with
# every client online, SS_TEST_ROTATE_PARTIAL, regtest only):
#
#   CKPT=rotate_part_built     the replacement funding is built and recorded
#                              in the marker, nothing signed
#   CKPT=rotate_part_signed    the clients hold the signed replacement tree;
#                              the replacement is not recorded, not funded
#   CKPT=rotate_part_recorded  the replacement and the owed releases are
#                              recorded; the funding is NOT broadcast
#   CKPT=rotate_part_funded    the funding is confirmed; no release asked yet
#   CKPT=rotate_part_released  one client released; the others are owed
#
# PASS for these: built/signed: the first funding never confirms (it was
# never broadcast) and the restart drops that rotation, then rotates again
# with one new funding; recorded: the restart rebroadcasts the recorded
# funding, no other; funded/released: no new funding at all.  In every case
# exactly one replacement funding confirms, every client switches and
# releases once (the owed releases are asked for again after the restart),
# the LSP then closes the old factory alone, and the released keys are
# deleted once that close is buried.
#
# PASS for these: exactly ONE close is ever built for the old factory, the
# restart completes the rotation over it ("rotation complete"), the close
# confirms, no client key is revealed (no Phase A), and every client switches
# to the replacement.  Before rotate_close_sent the restart runs the ceremony
# again over the recorded close; after it the restart only finishes.
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

PART=0
case "$CKPT" in rotate_part_*) PART=1 ;; esac
LSP_ENV=()
[ "$PART" = 1 ] && LSP_ENV=(SS_TEST_ROTATE_PARTIAL=1)

# --- Phase 1: LSP with crash-at + 4 clients (1-based participant-id, matrix scheme) ---
env "${LSP_ENV[@]}" SUPERSCALAR_CRASH_AT="$CKPT" "$BUILD/superscalar_lsp" "${LSP_ARGS[@]}" > "$TMP/lsp1.log" 2>&1 &
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
CLOSE1=$(grep -aoE "rotation close [0-9a-f]{64} recorded|factory [0-9]+ closed: [0-9a-f]{64}|LSP rotate: close [0-9a-f]{64} of factory [0-9]+ built" "$TMP/lsp1.log" | grep -oE "[0-9a-f]{64}" | tail -1)
CIN=0
grep -qa "LSP rotate: close into the new factory" "$TMP/lsp1.log" && CIN=1
FUND1=$(grep -aoE "replacement funding [0-9a-f]{64} recorded|LSP rotate: funded [0-9]+ sats, txid: [0-9a-f]{64}" "$TMP/lsp1.log" | grep -oE "[0-9a-f]{64}" | tail -1)
echo "Phase-1 close txid: ${CLOSE1:-<none>}   Phase-1 replacement funding: ${FUND1:-<none>}"
cnt() { local n; n=$(grep -acE "$1" "$2" 2>/dev/null) || n=0; echo "$n"; }

if [ "$PART" = 1 ]; then
  F1=$(grep -aoE "replacement funding [0-9a-f]{64}:[0-9]+ built" "$TMP/lsp1.log" | grep -oE "[0-9a-f]{64}" | head -1)
  [ -n "$F1" ] || { echo "RESUME-FAIL: no partial replacement funding built in phase 1"; exit 1; }
  # The factory the interrupted rotation replaces (the first one).
  O1=$(grep -aoE "^LSP: funded [0-9]+ sats, txid: [0-9a-f]{64}" "$TMP/lsp1.log" | grep -oE "[0-9a-f]{64}" | head -1)
  echo "=== Phase 2: restart (partial rotation) ==="
  # Past the record the restarted LSP's live factory is the replacement: give
  # it a longer life than 6 blocks, so it is not itself rotated before the
  # releases it is owed come in.
  LSP_ARGS2=("${LSP_ARGS[@]}")
  case "$CKPT" in
    rotate_part_built|rotate_part_signed) ;;
    *) for i in "${!LSP_ARGS2[@]}"; do
         [ "${LSP_ARGS2[$i]}" = "--active-blocks" ] && LSP_ARGS2[$((i + 1))]=60
       done ;;
  esac
  env "${LSP_ENV[@]}" "$BUILD/superscalar_lsp" "${LSP_ARGS2[@]}" > "$TMP/lsp2.log" 2>&1 &
  LSP2=$!
  ( while kill -0 $LSP2 2>/dev/null; do $BCLI -rpcwallet="$WALLET" generatetoaddress 1 "$MADDR" >/dev/null 2>&1; sleep 2; done ) &
  MINER=$!
  for i in $(seq 1 400); do
    sleep 1
    kill -0 $LSP2 2>/dev/null || break
    grep -qa "the old factory $O1 is closed" "$TMP/lsp2.log" && { echo "keys deleted at ~${i}s"; break; }
  done
  sleep 3
  kill -9 $LSP2 $MINER 2>/dev/null
  sleep 1
  # Verdicts are scoped to the interrupted rotation: lsp2.log up to the
  # LSP's own close of that old factory (with --active-blocks 6 the
  # replacement later reaches DYING and is rotated in turn).
  L2="$TMP/lsp2.resume.log"
  END2=$(grep -anm1 "every client of the old factory $O1 released its key" "$TMP/lsp2.log" | cut -d: -f1)
  if [ -n "$END2" ]; then head -n "$END2" "$TMP/lsp2.log" > "$L2"; else cp "$TMP/lsp2.log" "$L2"; fi
  echo "=== Phase 2 (partial) ==="
  grep -aE "LSP recovery: (a partial|this factory replaces|[0-9]+ of [0-9]+ release)|replacement funding|released its old factory key|closing it alone|old factory close|is closed|deleted|rotation complete|asked client" "$L2" | cut -c1-170 | head -30
  # Every replacement funding ever built, and which confirmed.
  FUNDS=$(grep -ahoE "replacement funding [0-9a-f]{64}:[0-9]+ built" "$TMP/lsp1.log" "$L2" | grep -oE "[0-9a-f]{64}" | sort -u)
  N_CONF=0; CONF_F=""
  for f in $FUNDS; do
    c=$($BCLI getrawtransaction "$f" 1 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("confirmations",0))' 2>/dev/null)
    [ "${c:-0}" -ge 1 ] && { N_CONF=$((N_CONF + 1)); CONF_F=$f; }
  done
  F1_CONF=0; [ "$CONF_F" = "$F1" ] && F1_CONF=1
  N_FUNDS=$(printf "%s\n" $FUNDS | grep -c . || true)
  DROPPED=$(cnt "LSP recovery: a partial rotation of this factory stopped before its replacement was recorded" "$L2")
  # The recorded funding is rebroadcast first thing at startup, before the
  # daemon can spend from the wallet (or, failing that, by the resume step).
  REBC_START=$(cnt "LSP recovery: rebroadcast the recorded replacement funding $F1 before any wallet use" "$L2")
  REBC=$(( REBC_START + $(cnt "replacement funding $F1 was not on the network" "$L2") ))
  OWED=$(cnt "LSP recovery: [0-9]+ of [0-9]+ release\(s\) still owed" "$L2")
  REL=$(grep -ahoE "client [0-9]+ released its old factory key \(verified release\)" "$TMP/lsp1.log" "$L2" | sort -u | wc -l)
  REL_LINES=$(grep -ahE "client [0-9]+ released its old factory key \(verified release\)" "$TMP/lsp1.log" "$L2" | wc -l)
  WD=$(grep -aoE "the old factory $O1 released its key — closing it alone: close [0-9a-f]{64} recorded" "$TMP/lsp2.log" | grep -oE "close [0-9a-f]{64}" | grep -oE "[0-9a-f]{64}" | sort -u)
  N_WD=$(printf "%s\n" $WD | grep -c . || true)
  WD_CONF=0
  [ -n "$WD" ] && WD_CONF=$($BCLI getrawtransaction "$WD" 1 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("confirmations",0))' 2>/dev/null)
  DELETED=$(cnt "the old factory $O1 is closed .*the released keys kept for it are deleted" "$TMP/lsp2.log")
  LEFT=$(sqlite3 "$DB" "SELECT COUNT(*) FROM departed_clients WHERE factory_id = (SELECT retired_id FROM part_rotations WHERE old_txid = '$O1');" 2>/dev/null)
  SWITCHED=0
  for N in 1 2 3 4; do grep -qa "switched to the replacement factory" "$TMP/c$N.log" && SWITCHED=$((SWITCHED + 1)); done
  echo
  echo "=== fund-safety: ckpt=$CKPT fundings_built=$N_FUNDS confirmed=$N_CONF first_confirmed=$F1_CONF dropped=$DROPPED rebroadcast=$REBC (at startup $REBC_START) owed_loaded=$OWED released=$REL/4 (lines $REL_LINES) clients_switched=$SWITCHED/4 winddown_closes=$N_WD close_conf=${WD_CONF:-0} keys_deleted=$DELETED keys_left=${LEFT:-?} ==="
  OK=0
  if [ "$N_CONF" -eq 1 ] && [ "$REL" -eq 4 ] && [ "$REL_LINES" -eq 4 ] && [ "$SWITCHED" -eq 4 ] &&
     [ "$N_WD" -eq 1 ] && [ "${WD_CONF:-0}" -ge 6 ] && [ "$DELETED" -ge 1 ] && [ "${LEFT:-1}" -eq 0 ]; then
    case "$CKPT" in
      rotate_part_built|rotate_part_signed)
        [ "$DROPPED" -ge 1 ] && [ "$F1_CONF" -eq 0 ] && [ "$N_FUNDS" -eq 2 ] && OK=1 ;;
      rotate_part_recorded)
        [ "$F1_CONF" -eq 1 ] && [ "$N_FUNDS" -eq 1 ] && [ "$REBC_START" -ge 1 ] && OK=1 ;;
      *)
        [ "$F1_CONF" -eq 1 ] && [ "$N_FUNDS" -eq 1 ] && [ "$OWED" -ge 1 ] && OK=1 ;;
    esac
  fi
  if [ "$OK" = 1 ]; then
    echo "RESUME-PASS: crash at $CKPT: one replacement funding confirmed ($CONF_F), every client switched and released once, the LSP closed the old factory alone ($WD) and deleted the released keys."
    exit 0
  fi
  echo "=== on failure: the clients' rotation lines, and the LSP's reconnects ==="
  for N in 1 2 3 4; do
    grep -aiE "rotation|release|switched|refus|reconnect" "$TMP/c$N.log" | tail -10 | sed "s/^/  c$N: /" | cut -c1-200
  done
  grep -aE "reconnect|release|asked" "$TMP/lsp2.log" | head -20 | sed "s/^/  lsp2: /" | cut -c1-200
  echo "RESUME-FAIL: want confirmed=1 released=4/4 (4 lines) clients_switched=4/4 winddown_closes=1 close_conf>=6 keys_deleted>=1 keys_left=0 and (built/signed: dropped>=1 first_confirmed=0 fundings_built=2; recorded: first_confirmed=1 fundings_built=1 rebroadcast_at_startup>=1; funded/released: first_confirmed=1 fundings_built=1 owed_loaded>=1)"
  exit 1
fi
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

if [ "$CIN" = 1 ]; then
  CLOSES=$(grep -ahoE "LSP rotate: close [0-9a-f]{64} of factory [0-9]+ built" "$TMP/lsp1.log" "$R2" | grep -oE "[0-9a-f]{64}" | sort -u)
  N_CLOSES=$(printf "%s\n" "$CLOSES" | grep -c . || true)
  COMPLETE=$(cnt "LSP rotate: rotation complete" "$R2")
  REVEALED=$(( $(cnt "key extracted via wire PTLC|Phase A — PTLC key turnover" "$TMP/lsp1.log") + $(cnt "key extracted via wire PTLC|Phase A — PTLC key turnover" "$R2") ))
  RERAN=$(cnt "close into the new factory \(all [0-9]+ clients online, over the recorded close\)" "$R2")
  FINISHED=$(cnt "replaced its predecessor by a co-signed close" "$R2")
  CONF1=$($BCLI getrawtransaction "$CLOSE1" true 2>/dev/null | grep -c '"confirmations"' || true)
  SWITCHED=0
  for N in 1 2 3 4; do grep -qa "switched to the replacement factory" "$TMP/c$N.log" && SWITCHED=$((SWITCHED + 1)); done
  echo "=== Phase 2 (close into the new factory) ==="
  grep -aE "LSP recovery: this factory replaced|close into the new factory|close [0-9a-f]{64}|rotation complete" "$R2" | cut -c1-170 | tail -8
  echo
  echo "=== fund-safety: ckpt=$CKPT closes_built=$N_CLOSES reran_over_recorded=$RERAN finished_after_restart=$FINISHED complete=$COMPLETE close_confirmed=$CONF1 keys_revealed=$REVEALED clients_switched=$SWITCHED/4 ==="
  OK=0
  if [ "$N_CLOSES" -eq 1 ] && [ "$COMPLETE" -ge 1 ] && [ "${CONF1:-0}" -ge 1 ] &&
     [ "$REVEALED" -eq 0 ] && [ "$SWITCHED" -eq 4 ]; then
    case "$CKPT" in
      rotate_close_sent) [ "$FINISHED" -ge 1 ] && OK=1 ;;
      *) [ "$RERAN" -ge 1 ] && OK=1 ;;
    esac
  fi
  if [ "$OK" = 1 ]; then
    echo "RESUME-PASS: crash at $CKPT: the restart completed the close into the new factory over the one recorded close ($CLOSE1), confirmed; no key revealed; all clients switched."
    exit 0
  fi
  echo "RESUME-FAIL: want closes_built=1 complete>=1 close_confirmed>=1 keys_revealed=0 clients_switched=4/4 and (rotate_close_sent: finished_after_restart>=1; else reran_over_recorded>=1)"
  exit 1
fi
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
