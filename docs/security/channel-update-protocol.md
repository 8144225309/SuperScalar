# Channel update protocol

Status: specification for the shared channel-update engine.

This document specifies how a host and one member change the state of their
channel. One engine implements it, and every channel update in the host and
member daemons goes through that engine. The model is BOLT 2; the
differences come from MuSig2 commitments and from the factory.

Statements marked **Required** are what the engine must do. The invariants it
serves are in [invariants.md](invariants.md); the attackers are in
[threat-model.md](threat-model.md).

## 1. Model

- A **channel** is a two-party channel between the host (H) and one member
  (M). In 1.0 its funding outpoint is one output of the member's PS leaf. The
  outpoint never changes in 1.0.
- Each side has its own **commitment transaction** at each commitment number
  n: C_H(n) and C_M(n). Both spend the funding outpoint by the MuSig2 key path
  of the 2-of-2 key. Each commitment pays the holder's balance to a
  CSV-delayed, revocable output and the other side's balance to an immediate
  output, plus one output per non-dust HTLC and one P2A anchor (INV-46).
- **Required:** the channel has one commitment number n shared by both
  sides. A round moves both sides from n to n + 1. Both C_H(n + 1) and
  C_M(n + 1) describe the same balances and the same HTLC set.
- A **round** carries one or more **updates**, signs both new commitments,
  and revokes both old ones. The host opens every round (section 4.1).
- Balances and HTLC amounts are kept in millisatoshi. A commitment pays
  each balance and each HTLC rounded down to whole satoshis; the remainder
  goes to the commitment fee, as in BOLT 3.
- Each side holds a **per-commitment secret** s_X(n) for each n, and has
  sent the point P_X(n) = s_X(n)·G to the other side before C_X(n) is built.
  Revealing s_X(n) revokes C_X(n).

## 2. Update kinds

### 2.1 In 1.0

| Kind | Who may send | Effect |
|---|---|---|
| `update_add_htlc` | the side that pays | moves `amount` from the sender's balance into a new HTLC |
| `update_fulfill_htlc` | the side the HTLC pays | removes the HTLC and credits its receiver; carries the preimage |
| `update_fail_htlc` | the side the HTLC pays | removes the HTLC and refunds its offerer |
| `update_fee` | the host | sets the commitment fee rate for the next commitment, within the bounds in the proposal |

"Who may send" names the side the update acts for. The member does not open
rounds: it offers its updates to the host, which carries them in its next
round or refuses them (section 4.1).

**Required:** a party accepts an update only if the sender is allowed to send
it (table above). In particular a member accepts `update_add_htlc` from the
host only as an HTLC the host offers (INV-28).

**Required:** a party may refuse a proposed update before any commitment
that contains it is signed. The refusal names the update and removes it
with no other state change. A payment from the host to a member is an
ordinary add followed by an ordinary fulfil.

**Required:** `update_fee` changes only the commitment fee rate. The rate is
bounded by the proposal (default: the factory term rate). Fees above the term
are paid at exit by CPFP, not by `update_fee`.

### 2.2 Later releases

| Kind | Release | Note |
|---|---|---|
| re-anchor (move a channel to a new funding outpoint after a DW state change) | 1.1 | needs INV-24 on both outpoints, hand-over-hand |
| tree moves: leaf advance, state advance, sub-factory advance, PS rollover | 1.1 | refused in 1.0 (INV-39) |
| realloc (move value between outputs of a leaf) | 1.1 | refused in 1.0 (INV-39) |
| splice | later | not a factory update in 1.0 |
| JIT open | opt-in | must meet INV-71 |
| liquidity sale | 1.1 | a new channel, not an update of an existing one (INV-69) |

**Required:** the engine rejects these kinds in 1.0 with an error and no
state change.

## 3. Messages

All messages carry `channel_id`. All integers are checked against bounds
before use (INV-58).

| Message | Fields | Sent by |
|---|---|---|
| `update_add_htlc` | `id`, `amount_msat`, `payment_hash`, `cltv_expiry`, routing data | payer |
| `update_fulfill_htlc` | `id`, `preimage` | payee |
| `update_fail_htlc` | `id`, `reason` | payee |
| `update_fee` | `feerate_per_kvb` | host |
| `commitment_signed` | `n` (the new number), `psig` (32 bytes, the sender's MuSig2 partial signature on the receiver's C(n)), `nonce_index`, `update_digest` | host to open a round; member only in answer to it |
| `revoke_and_ack` | `n_revoked`, `secret` (32 bytes), `next_point` (33 bytes, P(n_revoked + 2)) | either |
| `nonces` | `first_index`, list of 66-byte public nonces | either |
| `channel_reestablish` | see section 6 | either, first after connect |
| `error` | `reason` | either |

`update_digest` is SHA256 over the serialised list of updates in the round,
in order. Both sides compute it. A mismatch is an error.

## 4. One round, message by message

Proposer X, responder Y, both at number n (each holds C_X(n) and C_Y(n) fully
signed, and has revoked n − 1).

1. X → Y: one or more update messages.
2. X persists `X.SENT(n + 1)` (section 5). X → Y: `commitment_signed(n + 1)`
   with X's partial signature on C_Y(n + 1).
3. Y checks each update (sender allowed, amounts, CLTV rule INV-32, HTLC cap
   INV-33, conservation INV-27), rebuilds C_Y(n + 1), checks the digest,
   verifies X's partial signature, makes its own and aggregates.
4. Y persists `Y.HOLDS(n + 1)`. Y → X: `commitment_signed(n + 1)` with Y's
   partial signature on C_X(n + 1), then `revoke_and_ack(n)` with s_Y(n)
   and P_Y(n + 2).
5. X verifies Y's partial signature and aggregates C_X(n + 1). X verifies
   s_Y(n) against P_Y(n) at the choke point (INV-25), builds the penalty for
   C_Y(n), and registers it with its tower (INV-24, INV-45).
6. X persists `X.HOLDS(n + 1)`. X → Y: `revoke_and_ack(n)` with s_X(n) and
   P_X(n + 2).
7. Y verifies s_X(n), builds and registers the penalty for C_X(n), and
   persists `Y.DONE(n + 1)`. X persists `X.DONE(n + 1)` after step 6 is sent;
   that write needs nothing beyond step 6's.

A fulfil adds two rules: the payee checks the HTLC against its invoice
(amount, expiry, not already paid; INV-74), and persists its armed on-chain
success claim (INV-30), before it sends `update_fulfill_htlc`. The host forwards the
preimage upstream only after `X.HOLDS` or `Y.HOLDS` on the downstream channel
shows the HTLC removed.

### 4.1 Who opens a round

**Required:** the host opens every round. The member offers updates: it asks
the host to add an HTLC (to pay), to fulfil or fail an HTLC the host offered
it. An offer is durable on the member before it leaves, with the success
claim of any fulfil, and stays until a round carries it or the host refuses
it. The host carries an offer byte for byte, as an update that acts for the
member, or refuses it with a reason. The member accepts a round's update
that acts for itself only if it is one of its own offers (INV-28). A
`commitment_signed` from the member that does not answer the host's open
round is refused.

Options considered:

- **Either side opens rounds** (BOLT 2 style). Each side may send updates and
  `commitment_signed` at any time.
- **The host opens every round.** The member offers; the host signs first.

Why the host opens rounds in SuperScalar:

- A round signs one commitment per side with MuSig2. The nonce indices of the
  two sides advance in step, one per signature, so signatures must come in
  one order. With one side opening every round the order is given; with two,
  simultaneous rounds need a tie-break and leave the losing side with a
  signature over a second commitment for one number.
- The factory is hub and spoke: every channel has the host on one side, and
  the host routes every payment.
- The host is always online; members may not be.
- Refusal is simple: the host refuses an offer before anything is signed.
- The host can carry several offers, and its own updates, in one round.

What it gives up:

- About half a round trip of latency on payments the member starts: the
  offer has to reach the host before the round opens.
- The member cannot force a round. If the host does not carry or refuse its
  offers, the member's recourse is a unilateral exit on its latest
  commitment. That adds no trust: a host that stops answering already leaves
  the member that recourse and no other.
- There is no symmetric BOLT 2 mode between host and member.
- The host debits a member's channel only through a payment the member asked
  for: an offered add.
- One round at a time per channel; carrying several updates per round
  offsets it.

Revisiting it: either-side opening can be added later as a negotiated
feature. Table 6.2 row 12 already defines what happens when both sides
propose at once.

## 5. Persisted states and the persist-before-release rule

### 5.1 States of one update

| Side | State | Durable content, written in one SQLite transaction | Written before |
|---|---|---|---|
| proposer | `SENT(n + 1)` | the update list, its digest, the txid of C_Y(n + 1) the proposer signed, the proposer's own s_X(n + 2) | sending `commitment_signed` |
| responder | `HOLDS(n + 1)` | the update list, C_Y(n + 1) fully signed (raw transaction), balances and HTLC rows for n + 1, the txid of C_X(n + 1) it signed, s_Y(n + 2) | sending `commitment_signed` and `revoke_and_ack` |
| proposer | `HOLDS(n + 1)` | C_X(n + 1) fully signed, balances and HTLC rows for n + 1, s_Y(n), P_Y(n + 2), penalty for C_Y(n) and its tower entry | sending `revoke_and_ack` |
| responder | `DONE(n + 1)` | s_X(n), P_X(n + 2), penalty for C_X(n) and its tower entry | nothing (may be lost and rebuilt from the peer's retransmission) |

**Required:** a party marks its own s_X(n) as released in the same
transaction that stores C_X(n + 1). It never broadcasts a commitment whose
secret is marked released (INV-23).

**Required:** each write is one SQLite transaction. A failed `BEGIN`,
write or `COMMIT` aborts the round before anything is sent (INV-50). No
transaction stays open while the party waits for a peer (INV-75).

### 5.2 Transaction boundaries

The rule is: **persist before releasing a signature or a secret.**

- Before any `commitment_signed` leaves: the update list and the txid of the
  signed commitment are durable. This makes a retransmission sign the same
  bytes (INV-20).
- Before any `revoke_and_ack` leaves: the new commitment, fully signed, is
  durable, with the per-commitment secret for n + 2 whose point the message
  carries (INV-22, INV-26).
- Before any `update_fulfill_htlc` leaves: the success claim is durable
  (INV-30).
- Before an upstream fail: the downstream removal is durable on both sides
  (INV-29).


## 6. Reconnect reconciliation

### 6.1 The message

**Required:** after the transport handshake, and after the member has proved
its key (INV-55), each side sends `channel_reestablish`:

| Field | Meaning |
|---|---|
| `next_commitment_number` | the number of the newest commitment this side holds fully signed, plus 1 |
| `next_revocation_number` | the number of the newest own commitment this side has revoked, plus 1 |
| `last_remote_secret` | the newest per-commitment secret received from the peer (or zeros) |
| `my_current_point` | this side's point for its newest held commitment |
| `sent_digest` | the update digest of a round in `SENT` state, or zeros |

Then both sides exchange fresh nonces (section 7) before any signature.

### 6.2 Reconciliation table

Let mine = (H, V) be my newest held number and my newest revoked number, and
peer = (H', V') the peer's claim. At rest at n both sides are (n, n − 1).

| # | My state | Peer's claim | Meaning | My action |
|---|---|---|---|---|
| 1 | idle (n, n−1) | idle (n, n−1) | in step | none. Re-propose any update not yet in a `SENT` record. |
| 2 | proposer `SENT(n+1)`, (n, n−1) | (n, n−1), no `HOLDS(n+1)` | disconnect after my `commitment_signed`, before the peer persisted | resend the same updates from the `SENT` record and `commitment_signed(n+1)` with a fresh nonce over the same transaction. The digest must match. |
| 3 | proposer `SENT(n+1)`, (n, n−1) | responder `HOLDS(n+1)`: (n+1, n) | disconnect before the peer's `revoke_and_ack` reached me | peer resends its `commitment_signed(n+1)` (fresh nonce, same transaction) and `revoke_and_ack(n)`. I continue at step 5. |
| 4 | responder `HOLDS(n+1)`: (n+1, n) | proposer `SENT(n+1)`, (n, n−1) | same as 3, seen from the responder | resend `commitment_signed(n+1)` and `revoke_and_ack(n)` with the same secret. |
| 5 | proposer `HOLDS(n+1)`: (n+1, n−1) or (n+1, n) | responder `HOLDS(n+1)`: (n+1, n) | disconnect before my `revoke_and_ack` reached the peer | resend `revoke_and_ack(n)` with the same secret. |
| 6 | responder `HOLDS(n+1)`: (n+1, n) | proposer `HOLDS(n+1)`: (n+1, n) | same as 5, seen from the responder | wait for the peer's `revoke_and_ack(n)`. |
| 7 | (n+1, n) | (n+1, n) | done | none; both write `DONE` if missing. |
| 8 | any | H' > my newest signed-by-me number | peer claims a commitment I never signed | error, fail the channel, alert. Do not adopt the claim. Exit on my own latest state. |
| 9 | any | `last_remote_secret` is a secret of mine newer than my V | I lost data: I revoked a state my database calls current | **do not broadcast anything.** Ask the peer to force-close, and alert. |
| 10 | any | V' < the newest peer secret I hold | the peer lost data | tell the peer (its own last secret in my `last_remote_secret`). Exit unilaterally on my latest commitment if I hold one. |
| 11 | any | H' < H − 1 or H' > H + 1 | more than one round apart | treat as 8, 9 or 10 by the secrets; otherwise error. |
| 12 | `SENT(n+1)` | `SENT(n+1)` with a different digest | both proposed at once (only with either-side opening, section 4.1) | the host's round wins; the member drops its `SENT` record and re-proposes after. |

**Required:** a party never adopts the peer's numbers, balances or HTLC set
as its own. It only resends what its own `SENT` or `HOLDS` record says.

**Required:** a disconnect after `commitment_signed` and before
`revoke_and_ack` (rows 2 to 4) never leads to a second, different commitment
with the same number.


## 7. Nonce lifecycle

**Required:**
- Each side keeps, per channel and per connection, a pool of secret nonces
  in memory only. Secret nonces are never written to disk (INV-16).
- At connect, each side sends `nonces` with the public half of its pool,
  indexed from 0. A reconnect discards both pools and starts again from 0.
- A partial signature names the index of the receiver's public nonce it
  used. The sender draws its own next secret nonce. Both indices increase by
  one per signature. A party refuses an index that is not its next unused
  one.
- A secret nonce is consumed when drawn, whether or not the signature
  succeeds.
- A retransmission after reconnect uses new nonces over the same message
  (the same commitment transaction). Section 5 makes the bytes the same.
- When a pool falls below a threshold (for example 32 left), its owner sends
  more `nonces` with the next indices. A channel never stops because a pool
  ran out (INV-72).
- Tree ceremonies use the stateless pattern: the host generates, uses and
  zeroes its nonce in one step with no receive in between.

## 8. Concurrency

**Required:**
- One round at a time per channel. A message for a channel that arrives
  while a round on that channel is open is appended to that channel's queue,
  in arrival order, and handled after the round ends. It is never dropped
  (INV-36).
- Offers from the member that arrive while a round is open are queued and
  become the host's pending requests when it ends.
- Queues are bounded. A full queue fails the connection with `error`, which
  starts reconciliation. It never drops a message silently.
- Rounds on different channels do not block each other. The host's wait for
  one member is bounded and does not hold up any other member (INV-56).
- A forwarded payment is two rounds on two channels. The downstream add
  waits for the upstream round to reach `HOLDS` on the host. The upstream
  fulfil waits for the downstream fulfil round to reach `HOLDS` on the host.
  The upstream fail waits for the downstream removal to reach `DONE`
  (INV-29).

## 9. Failure handling

**Required:**
- A verification failure (partial signature, revocation secret, digest,
  conservation, CLTV) aborts the round, sends `error`, and leaves the
  previous state in force. Nothing from the failed round is stored.
- A timeout disconnects. Reconnect reconciles. A timeout never removes an
  HTLC locally (INV-31).
- An HTLC that cannot be resolved off chain before its deadline is resolved
  on chain: the party that is owed publishes and claims.


## 10. Engine interface (informative)

One function per event, all on the same state machine:

- `engine_propose(channel, updates[])` → `SENT` or refusal;
- `engine_on_message(channel, msg)` → next messages and a durable write;
- `engine_on_reconnect(channel, peer_reestablish)` → actions from table 6.2;
- `engine_on_block(channel, height)` → deadline actions: never a local
  removal; only "go on chain".

Every update path becomes a call to `engine_propose` with a list of
updates, followed by the state machine. The host's forwarding logic decides
what to propose and in which order (section 8), not how to sign.

## 11. Tests the engine needs

- A protocol model test that drives two engines through every interleaving
  of the messages in one round, with a disconnect and a crash at every step,
  and checks INV-20, INV-22, INV-23, INV-27, INV-29 and INV-36 after each.
- An invariant checker that runs after every durable write in the unit and
  regtest suites and checks: conservation (INV-27); held commitment number
  ≥ every released secret's number + 1 (INV-23); one signed txid per
  (channel, number) (INV-20); every revoked counterparty number has a stored
  secret and a tower entry (INV-24).
