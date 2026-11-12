# SuperScalar threat model

This document says who can attack a SuperScalar factory, what each attacker
controls, and what each attacker must not be able to do. It also lists the
trust and online assumptions and the timing parameters.

The numbered safety properties are in [invariants.md](invariants.md). The
channel update rules are in
[channel-update-protocol.md](channel-update-protocol.md).

## 1. System summary

A factory is one on-chain funding output shared by one host (the LSP,
participant 0) and N members (clients). The funding output is the root of a
pre-signed tree of transactions. Each leaf of the tree is a pseudo-Spilman
(PS) leaf, and each leaf funds one two-party Lightning channel between the
host and one member. Payments move only channel state; they never change the
tree.

Design source: ZmnSCPxj's SuperScalar posts on Delving Bitcoin (threads
t/1143, t/1242, t/1252, t/2098, t/2705).

### Design decisions for 1.0

1. **Advanceless tree.** Every level is a static kickoff level. There is no
   Decker-Wattenhofer (DW) state layer. Each PS leaf has exactly one member.
   A factory's life is extended only by rotating into a new factory, never by
   refreshing it in place. Liquidity sales and shared leaves come in 1.1.
2. **One payout date (T0) for the whole tree.** At T0 every member can
   receive its full channel capacity through the pre-signed distribution
   transaction (the inverted timeout default).
3. **Fees.** The pre-signed tree fee rate is a factory term that the host
   proposes. The default is 100 sat/kvB (0.1 sat/vB). A rate of 0 is allowed.
   Every pre-signed transaction is version 3 (TRUC) with exactly one P2A
   anchor. Whoever wants a transaction confirmed pays the real fee at exit,
   by CPFP on the anchor. There is no fee reserve.
4. **No legacy paths.** There are no compatibility paths for older clients
   or older database formats.
5. **Rotation** is off in 1.0. When it lands it follows the design: close
   into a new factory with fresh per-factory keys. A member hands over a key
   only for a channel it has emptied.

### Terms

| Term | Meaning |
|---|---|
| host | the LSP, participant 0 |
| member | a client, participants 1..N |
| T0 | the factory's single payout date (absolute block height) |
| R | reorg margin in blocks, a factory term |
| c | per-transaction confirmation allowance in blocks, a factory term |
| s | outage and congestion allowance in blocks, a factory term |
| H_force | the last height at which the host can start publishing a member's path and still have it confirm by T0 − R |
| path | every tree transaction from the root to a member's leaf, then its commitment |
| durable | written in a committed SQLite transaction |

## 2. Attackers

For each attacker: what it controls, and what it must not be able to do. The
invariant numbers point to the precise statements.

### 2.1 Malicious host (LSP)

**Controls:** its own keys and database; every message it sends; the order
and timing of every ceremony; the funding wallet; the proposal parameters;
which members it serves; the bridge to the outside Lightning network; when
it goes offline. It can keep any key it is given.

**Must not be able to:**
- take any member's balance, or any part of a member's payout (INV-01,
  INV-03, INV-05, INV-07);
- make a member sign a transaction the member did not rebuild itself
  (INV-11);
- move a member's balance by an update the member did not authorise
  (INV-28);
- get a member's preimage for less than the invoice amount (INV-74);
- leave a member without a signed, broadcastable exit at any moment (INV-02,
  INV-21);
- broadcast a revoked state without being punished (INV-24);
- give dust balances to itself (INV-09);
- keep a member in the factory past T0, or move T0 (INV-39, INV-40);
- break a member's exit by restarting with a different tree (INV-51).

### 2.2 Malicious member

**Controls:** its own keys and database; its messages; when it is online;
its own on-chain coins; whether it publishes its path early.

**Must not be able to:**
- take more than its own balance, from the host or from another member
  (INV-01, INV-07);
- publish a revoked commitment without being punished (INV-24);
- make the host fail an HTLC upstream while the member can still claim it
  downstream (INV-29);
- make a commitment unrelayable, for example by adding many HTLCs (INV-33,
  INV-47);
- hold up the host's service to other members (INV-56);
- take over another member's session (INV-55);
- force the whole tree on chain, or raise other members' exit cost (INV-06,
  INV-07);
- leave the host unable to recover its own channel balance before T0
  (INV-10, INV-21).

### 2.3 Colluding members

**Controls:** the union of the keys, messages and timing of a subset of
members, with or without the host. A member can be a sockpuppet of the host.

**Must not be able to:** reduce an honest member's exit below its latest
balance, or its payout below its capacity, including by publishing part of
the tree (INV-05, INV-07).

### 2.4 Outside BOLT8 peer

**Controls:** any number of TCP connections to the host; any bytes it sends;
any public key it claims; knowledge of every member's public key.

**Must not be able to:** read or change another session's state; replace a
member's connection; cause any wallet-funded broadcast; hold the host's main
loop beyond a bounded time; exhaust bounded resources (INV-55, INV-56,
INV-58).

### 2.5 CLN bridge or plugin

**Controls:** the HTLCs it offers into the factory (amount, hash, expiry);
fulfil and fail results for outbound payments; when it is connected.

**Must not be able to:** move member funds; make the host pay twice; make
the host accept an HTLC that outlives the factory or leaves the host no
margin (INV-57, INV-32).

### 2.6 Watchtower

**Controls:** an honest but faulty tower can drop watches, miss blocks, or
respond late. A compromised tower can refuse to act.

**Must not be able to:** steal; respond to an honest publication; stop
watching without the operator knowing (INV-43, INV-44, INV-45).

### 2.7 Chain reorg

**Controls:** the last R blocks.

**Must not be able to:** cause any fund-losing action, or a permanent
freeze. A chain-backend outage must not be read as a reorg (INV-54).

### 2.8 Fee spike

**Controls:** the feerate needed to confirm within a deadline.

**Must not be able to:** make an exit impossible for a party that is willing
to pay; make one member pay for another's exit (INV-46, INV-47, INV-48).

### 2.9 Crash at any instruction

**Controls:** the process stops at any instruction and restarts from its own
database. Disk writes may fail.

**Must not be able to:** make a party broadcast a state it revoked, sign two
different transactions for the same slot, or lose the data its exit needs
(INV-20, INV-22, INV-23, INV-50, INV-75).

## 3. Trust assumptions

No party trusts any other party for funds. Each party trusts only:
- its own key material and database;
- a chain backend that is honest about the best chain to depth R (it may be
  down; it must not lie);
- that miners include a transaction paying the market rate within the
  allowances c and s;
- that at least one copy of its own database survives.

The watchtower is trusted for liveness only, never for funds. It holds no
secret that can produce a new signature (INV-44).

Not covered: miner censorship beyond R plus the allowances; a fee spike that
outlasts the allowances; loss of every copy of a party's database.

## 4. Timing parameters

### 4.1 Values

| Quantity | Value |
|---|---|
| Commitment CSV delay (to_self_delay) | 144 blocks |
| Funding confirmations before a factory is live | 6 on mainnet, 3 on other public networks, 1 on regtest |
| T0 | created + active + dying + margin, with margin ≥ R + s + c · (longest path length); default active 4320 and dying 432 blocks on mainnet |
| H_force | T0 − R − s − c · (path length) for the longest path. The advanceless tree has no relative-lock term. |
| HTLC expiry | below T0 − R, and at least the path's exit distance plus allowances above the tip |
| Forwarding delta | the host's downstream expiry is at least one forwarding delta below the upstream expiry, for factory and bridge HTLCs alike |
| Tree fee rate | a factory term; default 100 sat/kvB, 0 allowed; each member sets a ceiling (`--max-tree-fee-rate`) |
| HTLC and PTLC outputs per commitment | at most 228, the most that fit in 10,000 vB |
| Members per factory | at most 255; at most 230 when the factory has a distribution transaction (10,000 vB) |

R, c and s are carried in the proposal as factory terms.

### 4.2 Who must be online, when, and for how long

**Member.**
- Online for the creation ceremony (minutes), until it holds its whole path,
  its payout and its commitment 0.
- Online for each payment it sends or receives, for the length of one update
  (seconds).
- The member (or its tower) checks the chain at least once every
  to_self_delay − c − s blocks, to punish a revoked host commitment.
- For an incoming HTLC, online before the HTLC's expiry to fulfil it.
- If nothing is published, the member may stay offline until T0. From T0 it
  (or its tower) publishes the distribution transaction and bumps it until
  it is R deep (INV-04).

**Host.**
- Online continuously. Every update needs it.
- Starts publishing every unsettled member's path no later than H_force,
  without waiting for any member (INV-10).
- Checks the chain at least once every to_self_delay − c − s blocks to
  punish a revoked member commitment.
- Fails or settles every HTLC before its expiry minus the forwarding delta,
  downstream before upstream (INV-29).

**Watchtower.**
- Checks the chain at least once every to_self_delay − c − s blocks for
  each watched channel.

## 5. Out of scope

- Liquidity sales, shared leaves, DW state layers and their poison
  transactions: 1.1. Their invariants are listed for that release.
- Rotation: off in 1.0. Its invariants are listed for when it lands.
- JIT channels: opt-in; INV-71.
- Splicing and channels with outside Lightning peers: standard BOLT 2.
