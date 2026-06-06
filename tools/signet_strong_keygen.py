#!/usr/bin/env python3
# Strong per-run key generation for SIGNET (and any shared/real network) test
# runs, so factory ceremony keys are NOT publicly-derivable weak keys (privkey
# 1,2,3...). Deterministic test keys are fine on regtest (private chain) but on
# public signet they leave funds anyone can sweep -- see the 3 BTC that sat at
# wpkh(privkey=3). Keys are derived from a random 32-byte seed via SHA-256, so
# they're unpredictable to outsiders but reproducible from the saved seed (so we
# can recover/sweep our own outputs afterward).
#
# Usage: signet_strong_keygen.py <N_CLIENTS> <TAG> [SEED_HEX]
# Emits shell-evalable LSP_SECKEY/LSP_PUBKEY/CLIENT_KEYS_FILE/RUN_SEED_FILE,
# writes the per-client seckeys to CLIENT_KEYS_FILE (line i = client i), and
# saves the seed to RUN_SEED_FILE for later recovery.
import sys, json, subprocess, hashlib, os, re
CONF = os.environ.get("SIGNET_CONF", "/var/lib/bitcoind-signet/bitcoin.conf")
def cli(*a):
    return subprocess.run(["bitcoin-cli","-signet","-conf="+CONF,*a],
                          capture_output=True, text=True).stdout.strip()
B58="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58c(p):
    d=p+hashlib.sha256(hashlib.sha256(p).digest()).digest()[:4];n=int.from_bytes(d,"big");s=""
    while n>0:n,r=divmod(n,58);s=B58[r]+s
    for b in d:
        if b==0:s="1"+s
        else:break
    return s
def wif(h): return b58c(bytes([0xEF])+bytes.fromhex(h)+bytes([0x01]))

N   = int(sys.argv[1])
TAG = sys.argv[2]
seed = sys.argv[3] if len(sys.argv) > 3 else os.urandom(32).hex()

# secp256k1 group order; reject (astronomically unlikely) out-of-range derivations
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
def derive(role):
    for ctr in range(256):
        h = hashlib.sha256(bytes.fromhex(seed) + ("%s|%d" % (role, ctr)).encode()).hexdigest()
        if 0 < int(h,16) < ORDER:
            return h
    raise SystemExit("keygen exhausted (impossible)")

lsp_sk = derive("lsp")
info = json.loads(cli("getdescriptorinfo", "pk(%s)" % wif(lsp_sk)))["descriptor"]
m = re.search(r"pk\(([0-9a-fA-F]+)\)", info)
if not m: raise SystemExit("could not derive LSP pubkey via bitcoind")
lsp_pub = m.group(1)

ckfile   = "/tmp/ss_signet_clientkeys_%s.txt" % TAG
seedfile = "/tmp/ss_signet_seed_%s.txt" % TAG
with open(ckfile, "w") as f:
    for i in range(1, N+1):
        f.write(derive("client%d" % i) + "\n")
os.chmod(ckfile, 0o600)
open(seedfile, "w").write(seed + "\n"); os.chmod(seedfile, 0o600)

print("LSP_SECKEY=%s"   % lsp_sk)
print("LSP_PUBKEY=%s"   % lsp_pub)
print("CLIENT_KEYS_FILE=%s" % ckfile)
print("RUN_SEED_FILE=%s" % seedfile)
