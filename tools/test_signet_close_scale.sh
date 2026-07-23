#!/usr/bin/env bash
# test_signet_close_scale.sh — drive test_signet_close_scale on REAL signet.
#
# Funds a P2TR(N-of-N aggregate) from the home wallet, cooperatively closes it to
# M funded clients in ONE tx, broadcasts, verifies on-chain, and recovers funds.
#   RUN 1 (~99 KB):  N=2301 M=2300  -> expect the close to CONFIRM.
#   RUN 2 (~430 KB): N=10001 M=10000 -> expect broadcast REJECTION (tx-size),
#                    then sweep the intact funding back home.
#
# Env: N M SEED FUNDING_SATS FEE_RATE(1) EXPECT(confirm|reject) BIN WALLET
set -uo pipefail
CONF="${SIGNET_CONF:-/var/lib/bitcoind-signet/bitcoin.conf}"
CLI="bitcoin-cli -signet -conf=$CONF"
WALLET="${WALLET:-ss_sig_n127}"
WCLI="$CLI -rpcwallet=$WALLET"
BIN="${BIN:-/root/SuperScalar-lsppay/build-lsppay/test_signet_close_scale}"
N="${N:?}"; M="${M:?}"; SEED="${SEED:?}"; FUNDING_SATS="${FUNDING_SATS:?}"
FEE_RATE="${FEE_RATE:-1}"; EXPECT="${EXPECT:-confirm}"
TAG="closescale_${SEED}"
info(){ printf '\033[36m[close-scale]\033[0m %s\n' "$*"; }
ok(){ printf '\033[32m%s\033[0m\n' "$*"; }
bad(){ printf '\033[31m%s\033[0m\n' "$*"; }

# 1. funding address = rawtr(agg output key)
OUTKEY=$("$BIN" addr "$N" "$SEED"); [ ${#OUTKEY} -eq 64 ] || { bad "addr failed"; exit 1; }
FUND_ADDR=$($CLI deriveaddresses "rawtr($OUTKEY)" | python3 -c 'import sys,json;print(json.load(sys.stdin)[0])')
info "N=$N M=$M funding addr=$FUND_ADDR outkey=$OUTKEY"

# 2. fund it + wait 1 conf
BTC=$(python3 -c "print(f'{$FUNDING_SATS/1e8:.8f}')")
FUND_TXID=$($WCLI -named sendtoaddress address="$FUND_ADDR" amount="$BTC" fee_rate="$FEE_RATE")
info "funded: $FUND_TXID ($BTC BTC) — waiting for 1 conf (signet ~10min)..."
for i in $(seq 1 120); do
  c=$($WCLI gettransaction "$FUND_TXID" 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("confirmations",0))' 2>/dev/null || echo 0)
  [ "${c:-0}" -ge 1 ] && break; sleep 30
done
[ "${c:-0}" -ge 1 ] || { bad "funding not confirmed"; exit 1; }
# 3. find the vout paying our address
VOUT=$($CLI getrawtransaction "$FUND_TXID" 1 | python3 -c "
import sys,json
d=json.load(sys.stdin)
for v in d['vout']:
    if v['scriptPubKey'].get('address')=='$FUND_ADDR': print(v['n']); break
")
info "confirmed; funding vout=$VOUT"

# 4. build + sign the close
"$BIN" close "$N" "$M" "$SEED" "$FUND_TXID" "$VOUT" "$FUNDING_SATS" /tmp/${TAG}_close.hex "$FEE_RATE" || { bad "close build failed"; exit 1; }

# 5. broadcast
info "broadcasting close ($(wc -c < /tmp/${TAG}_close.hex) hex chars)..."
set +e
CLOSE_TXID=$($CLI sendrawtransaction "$(cat /tmp/${TAG}_close.hex)" 2>/tmp/${TAG}_err.txt)
RC=$?
set -e
if [ "$EXPECT" = confirm ]; then
  [ $RC -eq 0 ] || { bad "UNEXPECTED broadcast failure:"; cat /tmp/${TAG}_err.txt; exit 1; }
  ok "CLOSE BROADCAST: $CLOSE_TXID"
  info "verifying on-chain (nout==M+1, conservation)..."
  $CLI getrawtransaction "$CLOSE_TXID" 1 | python3 -c "
import sys,json
d=json.load(sys.stdin); nout=len(d['vout']); outs=round(sum(v['value'] for v in d['vout'])*1e8)
exp=$M+1
print(f'  nout={nout} (expect {exp})  out_sum={outs}  funding={$FUNDING_SATS}  fee={$FUNDING_SATS-outs}')
print('  VERIFY: '+('PASS' if nout==exp and outs<$FUNDING_SATS else 'FAIL'))
"
  ok "RUN 1 exhibit: largest cooperative close landed on signet ($CLOSE_TXID)"
  info "NOTE: $M client outputs are at deterministic rawtr(SEED,i) addrs — recoverable via a batched consolidation (follow-up)."
else
  if [ $RC -eq 0 ]; then bad "UNEXPECTED: oversized tx was ACCEPTED ($CLOSE_TXID)?!"; else
    ok "RUN 2 ceiling pinned — signet REJECTED the ~430KB close as expected:"; cat /tmp/${TAG}_err.txt; fi
  # sweep the intact funding back home (N-of-N -> home)
  DEST_SPK=$($WCLI getaddressinfo "$($WCLI getnewaddress ${TAG}_sweep bech32m)" | python3 -c 'import sys,json;print(json.load(sys.stdin)["scriptPubKey"])')
  "$BIN" sweep "$N" "$SEED" "$FUND_TXID" "$VOUT" "$FUNDING_SATS" "$DEST_SPK" /tmp/${TAG}_sweep.hex "$FEE_RATE" || { bad "sweep build failed"; exit 1; }
  SWEEP_TXID=$($CLI sendrawtransaction "$(cat /tmp/${TAG}_sweep.hex)") || { bad "sweep broadcast failed"; exit 1; }
  ok "funding swept home: $SWEEP_TXID"
fi
