# Design: co-location test manager (factory-scale signing on one box)

Status: **design + measured**. A signet-only **test apparatus** — never
production. Runs factory-scale cooperative-close ceremonies on one box and
verifies on-chain that every payout landed where it should.

## 0. Measured result: for the close ceremony, in-memory is optimal — paging is NOT needed

The whole point of paging was to avoid holding N heavyweight participants in RAM.
But the **cooperative close is a key-path spend of the funding N-of-N** — it does
not touch the DW tree, so a participant's resident state is only **~400 B**
(seckey derivable; secnonce 132 + pubnonce 132 + partial 36). Measured on the VPS
with the in-memory conductor (`tools/test_signet_close_scale.c`):

```
N=2301  signers, M=2300 funded  -> vsize  99,013 vB, self-verify OK, conserves
N=10001 signers, M=10000 funded -> vsize 430,113 vB, self-verify OK, conserves
   signing 10,001 signers: 1.5 s, ~6 MB RAM
```

Extrapolated, the in-memory conductor scales the close to **~1,000,000 signers in
<500 MB** on a 15 GB box. **So the disk-paging apparatus below is deliberately
NOT built for the close-scale tests** — it would be premature. It remains the
roadmap for the one case that genuinely needs it: a **faithful full-client
simulation**, where each participant holds a real 53 MB `factory_t` and only a
handful fit in RAM at once. Build the pager when (and only when) that feature is
pursued; the working-group knob below is how it plugs in.

## 1. Why paging (deferred — for faithful full-client sim / >>1M only)

The naive co-location test runs one heavyweight process per participant
(~70 MB each — the full `factory_t`). 2,300 → 161 GB, 10,000 → impossible. That
is a **test co-location artifact**: in production those are 10,000 separate
devices. The fix is a single **manager** process that plays all N participants
but never holds more than a bounded **working group** in RAM at once.

Honest note on the number: for the *cooperative-close* ceremony the per-signer
state that must persist is tiny (~330 B: seckey is derivable, secnonce 132,
pubnonce 132, partial 36), so 10k fits in a few MB even unpaged. Paging is built
anyway because it (a) scales the same harness to ~1M, (b) is required the moment
we want *faithful* per-client simulation (each `factory_t` is 53 MB → only a
handful fit → must page), and (c) makes "bring a node up/down at will" trivial.
The working-group size is a knob: set it to N at 10k, or to a small group at 1M.

## 2. Core principle: derive identity, persist only the ephemeral

- **Participant identity is deterministic** — `seckey_i = tagged_sha256(SEED,i)`.
  Never stored; re-derived on demand. So "load a participant" costs ~0 for keys.
- **Only ephemeral secnonces must persist** — they are generated in MuSig round 1
  and consumed in round 2, and must **never be reused** (BIP-327; reuse leaks the
  key). Persist them to disk with a write-ahead `used` flag.
- **Balances / output keys / results** live in the DB for post-test verification.

## 3. Data model (SQLite `sim.db`)

```
participants(id PK, balance_sats, out_key BLOB)          -- who gets paid what
ceremony(id PK, msg32 BLOB, phase, working_group, funding_txid, funding_vout, funding_sats)
nonces(ceremony_id, participant_id, secnonce BLOB, pubnonce BLOB, used INT)   -- ephemeral, PK(cer,part)
agg(ceremony_id, running_aggnonce BLOB, running_partialagg BLOB, n_folded)    -- streaming checkpoints
result(ceremony_id, close_txid, broadcast_ok, node_error)
payout_check(ceremony_id, participant_id, expected_sats, onchain_sats, ok)    -- verification
```

Peak RAM ≈ `working_group × per-participant-state + O(1) running aggregate`.
Disk ≈ `N × (secnonce+pubnonce+partial ≈ 200 B)` + balances.

## 4. Ceremony as group-paged passes (crash-safe)

A MuSig2 cooperative close is one aggregate over one funding UTXO. It is a strict
2-round protocol, but each round is embarrassingly parallel across signers, so it
pages cleanly:

1. **FUND** — aggregate all N pubkeys → key-path funding key; fund `P2TR(agg)` on
   signet (one UTXO). (Key aggregation needs all N pubkeys once; 10k = 640 KB fits;
   at ~1M, aggregate incrementally / from a paged pubkey file.)
2. **NONCE (round 1), paged** — for each group of `working_group`: derive keys,
   `musig_generate_nonce`, **write (secnonce,pubnonce, used=0)** to `nonces`,
   free the group. Then aggregate pubnonces into `agg.running_aggnonce` (a read
   pass; pubnonces are 132 B each, streamed).
3. **SESSION** — `nonce_process(aggnonce, msg=close_sighash, tweaked_cache)`.
4. **SIGN (round 2), paged + crash-safe** — for each group: derive keys, **load
   secnonces, set `used=1` and COMMIT before signing** (write-ahead), then
   `partial_sign`, fold into `agg.running_partialagg`, free the group.
5. **AGGREGATE + BROADCAST** — finalize the 64-byte sig, attach witness,
   `sendrawtransaction`, record `result`.

**Crash-safety (the only genuinely hard part):** if the manager dies after
`used=1` for any nonce, those nonces are **burned** — on restart the ceremony
**aborts round 2 and restarts round 1 with fresh nonces** (never resumes a used
secnonce). A crash can only *lose* a nonce, never reuse one. This mirrors the
project's stateless-signer discipline; the DB just makes it durable and auditable.

Streaming aggregation note: `secp256k1_musig_nonce_agg` / `partial_sig_agg` take
arrays, but both are point/scalar sums — foldable incrementally (sum the R1,R2
points; sum the partial scalars mod n). At 10k the arrays fit (1.3 MB / 360 KB)
so we can call the library directly; incremental folding is the ~1M path.

## 5. Bring participants up / down at will

There are **no processes or sockets** — a "node" is a DB row + derivable keys.
"Up" = load its row into the working group; "down" = flush + free. The manager
just streams groups. This is what replaces the daemon-per-client model and
eliminates the reconnect storms / races entirely.

## 6. Post-test verification ("everything went where it should")

After the close confirms:
- **Per-payout reconciliation** — for each funded participant, find its output in
  the close tx by `out_key`/spk and assert `onchain_sats == expected balance`;
  write `payout_check`. Assert `Σ outputs + fee == funding`.
- **Conservation + count** — assert output count == funded (minus dust-folded).
- **Sweep-home** — since every key is deterministic from SEED, sweep all funded
  outputs (and any LSP output / the funding on the rejected run) back to the home
  wallet; assert the sweep confirms. No sats stranded.

## 7. The two target runs (single-tx, via this manager)

1. **~99 KB valid** — `signers=2300 funded=2300` → ~99 KB close → **broadcasts +
   confirms on real signet** → verify all ~2,300 payouts → sweep home. The
   "largest cooperative close that lands on-chain" exhibit.
2. **~430 KB oversized** — `signers=10000 funded=10000` → manager builds + signs
   (paged) → broadcast → **signet rejects (`tx-size`/non-standard)** → record the
   exact error, pinning the ceiling → sweep the funding back.

`working_group` set to fit the box (e.g., 1,000). Both runs stay under ~100 MB.

## 8. Build plan

- **Step 0 (done):** `tools/test_signet_close_scale.c` — the in-memory ceremony
  *core* (derive → aggregate → build M-output close → `musig_sign_taproot` →
  self-verify → serialize), proving the tx/signing path on the reused, tested
  builders. It currently holds all N in RAM (fine ≤ ~50k).
- **Step 1:** wrap the core in the SQLite pager (derive-on-demand, disk secnonces,
  group passes, write-ahead `used`), driven by `working_group`.
- **Step 2:** the signet orchestration wrapper (`.sh`): fund `P2TR(agg)`, find the
  vout, call the manager, broadcast, then run the verification + sweep passes.
- **Step 3:** run #1 (99 KB, confirms) and #2 (430 KB, rejected); capture exhibits.

## 9. Non-goals / limits

- Test harness only — not a production signing path (production is distributed).
- Does **not** exercise the wire/reconnect protocol (that stays on the ≤127
  multi-process harness). It validates **crypto + tx construction + on-chain
  behavior at scale**, with full fund-flow verification.
- Multi-tx cooperative close (payouts beyond one standard tx) is a separate
  feature — see `docs/design/multi-tx-cooperative-close.md`.
