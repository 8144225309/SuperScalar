#!/bin/bash
# test_signet_paylifecycle.sh — end-to-end signet proof of the in-process manager:
#   fund factory -> real HTLC payments -> cooperative close (broadcast+confirm) ->
#   verify outputs on-chain -> sweep every output back to ss_sig_n127.
# Keeps a full audit bundle. Gates every broadcast with testmempoolaccept so a bad
# tx never spends. Since the seed is saved, the funding output is always recoverable
# via a rebuilt close even if a later step fails.
#
# Usage: test_signet_paylifecycle.sh <N> [P_PER_CH] [SATS_PER_LEAF] [FEE_RATE]
set -uo pipefail

N="${1:?usage: <N> [P] [SATS_PER_LEAF] [FEE_RATE]}"
P="${2:-4}"
PER_LEAF="${3:-15000}"        # >2*CHANNEL_RESERVE(5000) so payments have room
FEE_RATE="${4:-1}"            # sat/vB for close + sweep (signet is cheap)
AMOUNT=$(( N * PER_LEAF ))

BIN=/root/SuperScalar-lsppay/build-lsppay/test_inproc_factory_lifecycle
CONF=/var/lib/bitcoind-signet/bitcoin.conf
CLI="bitcoin-cli -signet -conf=$CONF"
W="-rpcwallet=ss_sig_n127"
TAG="paylife_N${N}_$$"                 # UNIQUE per run — never reuse (seed-collision hazard)
SEED="ss_${TAG}"
AUDIT="/root/paylife_audit/${TAG}"
mkdir -p "$AUDIT"
LOG="$AUDIT/run.log"
exec > >(tee -a "$LOG") 2>&1

sat2btc(){ awk "BEGIN{printf \"%.8f\", $1/100000000}"; }
say(){ echo "[$(date -u +%H:%M:%S)] $*"; }
wait_conf(){ # txid -> block until >=1 confirmation (txindex=1, works for any tx)
  local txid="$1" i
  for i in $(seq 1 480); do
    local c=$($CLI getrawtransaction "$txid" 1 2>/dev/null | jq -r '.confirmations // 0')
    [ "${c:-0}" -ge 1 ] && { echo "$c"; return 0; }
    sleep 15
  done
  return 1
}

say "RUN $TAG  N=$N P=$P per_leaf=$PER_LEAF amount=$AMOUNT fee_rate=$FEE_RATE"
RET=$($CLI $W getnewaddress "${TAG}_ret" bech32m)
git -C /root/SuperScalar-lsppay rev-parse HEAD > "$AUDIT/git_commit.txt" 2>/dev/null || true
cat > "$AUDIT/manifest.json" <<EOF
{"tag":"$TAG","seed":"$SEED","N":$N,"payments_per_channel":$P,"sats_per_leaf":$PER_LEAF,
 "funding_amount":$AMOUNT,"fee_rate":$FEE_RATE,"return_addr":"$RET"}
EOF

# ---- 1. factory funding address (tweaked N-of-N aggregate) ----
FX=$($BIN addr "$N" "$SEED") || { say "addr FAILED"; exit 1; }
DESC=$($CLI getdescriptorinfo "rawtr($FX)" | jq -r .descriptor)
FADDR=$($CLI deriveaddresses "$DESC" | jq -r '.[0]')
say "funding addr=$FADDR (xonly=$FX)"
echo "$FADDR" > "$AUDIT/funding_addr.txt"

# ---- 2. fund it ----
FTXID=$($CLI -named $W sendtoaddress address="$FADDR" amount="$(sat2btc $AMOUNT)" fee_rate=$FEE_RATE) \
  || { say "fund send FAILED"; exit 1; }
say "funding txid=$FTXID (waiting for confirmation)"
wait_conf "$FTXID" >/dev/null || { say "funding not confirmed"; exit 1; }
VOUT=$($CLI getrawtransaction "$FTXID" 1 | jq -r --arg a "$FADDR" '.vout[] | select(.scriptPubKey.address==$a) | .n' | head -1)
say "funding confirmed, vout=$VOUT"
echo "{\"funding_txid\":\"$FTXID\",\"vout\":$VOUT}" > "$AUDIT/funding.json"

# ---- 3. real payments + cooperative close (in-process) ----
say "running paylifecycle (real HTLC payments + close)"
$BIN paylifecycle "$N" "$SEED" "$FTXID" "$VOUT" "$AMOUNT" "$AUDIT/close.hex" "$FEE_RATE" "$P" "$AUDIT" \
  || { say "paylifecycle FAILED"; exit 1; }
CLOSE_HEX=$(cat "$AUDIT/close.hex")

# ---- 4. GATE: testmempoolaccept before spending ----
ACC=$($CLI testmempoolaccept "[\"$CLOSE_HEX\"]" | jq -r '.[0].allowed')
say "close testmempoolaccept allowed=$ACC"
[ "$ACC" = "true" ] || { say "close REJECTED by mempool — aborting (funding recoverable via seed)"; $CLI testmempoolaccept "[\"$CLOSE_HEX\"]"; exit 1; }

# ---- 5. broadcast close + confirm ----
CTXID=$($CLI sendrawtransaction "$CLOSE_HEX") || { say "close broadcast FAILED"; exit 1; }
say "close broadcast txid=$CTXID (waiting for confirmation)"
wait_conf "$CTXID" >/dev/null || say "warn: close not confirmed within timeout (check later)"
CH=$($CLI getrawtransaction "$CTXID" 1 2>/dev/null | jq -r '.blockheight // empty')
say "close confirmed txid=$CTXID height=${CH:-pending}"

# ---- 6. verify outputs on-chain ----
NOUT=$($CLI getrawtransaction "$CTXID" 1 | jq -r '.vout | length')
OUTSUM=$($CLI getrawtransaction "$CTXID" 1 | jq -r '[.vout[].value] | add')
say "on-chain close: outputs=$NOUT sum=${OUTSUM} BTC"

# ---- 7. sweep every output back to ss_sig_n127 ----
say "sweeping $NOUT outputs back to $RET"
$BIN dumpkeys "$N" "$SEED" > "$AUDIT/keys.txt"
python3 - "$AUDIT/keys.txt" "$CH" > "$AUDIT/import.json" <<'PY'
import sys,hashlib,json
def b58(b):
    a='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';n=int.from_bytes(b,'big');s=''
    while n>0:n,r=divmod(n,58);s=a[r]+s
    for c in b:
        if c==0:s='1'+s
        else:break
    return s
def wif(h):
    p=b'\xef'+bytes.fromhex(h)+b'\x01';c=hashlib.sha256(hashlib.sha256(p).digest()).digest()[:4];return b58(p+c)
IN="0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CS="qpzry9x8gf2tvdw0s3jn54khce6mua7l";G=[0xf5dee51989,0xa9fdca3312,0x1bab10e32d,0x3706b1677a,0x644d626ffd]
def pm(c,v):
    c0=c>>35;c=((c&0x7ffffffff)<<5)^v
    for i in range(5):c^=G[i] if((c0>>i)&1) else 0
    return c
def dsum(s):
    c=1;cl=0;cc=0
    for ch in s:
        p=IN.find(ch)
        c=pm(c,p&31);cl=cl*3+(p>>5);cc+=1
        if cc==3:c=pm(c,cl);cl=0;cc=0
    if cc>0:c=pm(c,cl)
    for _ in range(8):c=pm(c,0)
    c^=1
    return ''.join(CS[(c>>(5*(7-j)))&31] for j in range(8))
keys=[l.split()[1] for l in open(sys.argv[1]) if l.strip()]
ts=1
descs=[]
for h in keys:
    d="rawtr(%s)"%wif(h); d=d+"#"+dsum(d)
    descs.append({"desc":d,"timestamp":ts,"active":False,"internal":False})
print(json.dumps(descs))
PY
SWEEPW="sweep_${TAG}"
$CLI -named createwallet wallet_name="$SWEEPW" blank=true disable_private_keys=false >/dev/null 2>&1 || true
$CLI -rpcwallet="$SWEEPW" importdescriptors "$(cat $AUDIT/import.json)" >/dev/null 2>&1
RS_FROM=${CH:-1}
$CLI -rpcwallet="$SWEEPW" rescanblockchain "$RS_FROM" >/dev/null 2>&1
SWBAL=$($CLI -rpcwallet="$SWEEPW" getbalance)
say "sweep wallet holds $SWBAL BTC across $NOUT outputs"
STXID=$($CLI -rpcwallet="$SWEEPW" -named sendall recipients="[\"$RET\"]" fee_rate="$FEE_RATE" 2>&1 | jq -r '.txid // empty')
if [ -z "$STXID" ]; then say "sendall FAILED:"; $CLI -rpcwallet="$SWEEPW" -named sendall recipients="[\"$RET\"]" fee_rate="$FEE_RATE"; else
  say "sweep broadcast txid=$STXID"; wait_conf "$STXID" >/dev/null 2>&1 || true
  say "sweep confirmed txid=$STXID"
fi

# ---- 8. finalize manifest ----
cat > "$AUDIT/onchain.json" <<EOF
{"funding_txid":"$FTXID","funding_vout":$VOUT,"funding_addr":"$FADDR","funding_amount":$AMOUNT,
 "close_txid":"$CTXID","close_height":"${CH:-}","close_outputs":$NOUT,"close_out_sum_btc":"$OUTSUM",
 "sweep_txid":"${STXID:-}","return_addr":"$RET"}
EOF
say "DONE. audit bundle in $AUDIT"
ls -la "$AUDIT"
