# SuperScalar safety invariants

These are the numbered safety properties of a SuperScalar factory. Every
review and every pull request names the invariants it touches, for example
"implements INV-22" or "must not break INV-24". Each invariant is one
testable statement. The attackers are those of
[threat-model.md](threat-model.md); the channel update rules are in
[channel-update-protocol.md](channel-update-protocol.md).

## Field key

- **Required:** the statement the implementation must satisfy.
- **Defends against:** the attacker or attackers (threat-model section 2).
- **Release:** 1.0, 1.1, rotation (off in 1.0), or opt-in.

Enforcement and test coverage are tracked separately and checked in review.

Every invariant marked 1.0 is to have three tests: a positive test (an
honest run holds), a negative test (an attacker is refused), and a
fix-undone test (revert the enforcing code and the negative test fails).

---

## A. Exit and payout

**INV-01 — Exit with the exact balance, host absent.**
- Required: At any height before T0, a member that has only its own durable database and a chain backend can get its path and its latest commitment confirmed, with no message from the host or any other member, and then sweep exactly its off-chain balance, less only fees it chooses to pay.
- Defends against: malicious or absent host; colluding members; crash.
- Release: 1.0..

**INV-02 — The member holds its whole path.**
- Required: Before a member accepts a channel, and after every state change it signs, it durably holds every transaction on its own path (tree transactions, its payout, its commitment) fully signed and verified.
- Defends against: host withholding signatures; host vanishing.
- Release: 1.0..

**INV-03 — The payout pays at least capacity.**
- Required: The distribution transaction is non-final until T0 and pays each member at least its channel capacity as carried in the proposal, on a key the member controls. It has no host output. No single member pays for the anchor.
- Defends against: absent host; malicious host.
- Release: 1.0..

**INV-04 — Members act at T0.**
- Required: From T0 on, every member daemon (or its tower) broadcasts the payout of every unspent shared output on its path and re-bumps it until it is R deep, whether or not the host is reachable.
- Defends against: absent host.
- Release: 1.0..

**INV-05 — No host-only branch.**
- Required: No shared output (funding, kickoff, PS leaf, channel) has any script path the host alone can satisfy.
- Defends against: malicious host after T0.
- Release: 1.0..

**INV-06 — An exit publishes only its own path.**
- Required: A member's unilateral exit broadcasts only the transactions on its own path plus its commitment.
- Defends against: one member forcing the whole tree on chain.
- Release: 1.0..

**INV-07 — Isolation.**
- Required: No coalition that excludes member m, with or without the host, can make m receive less than its latest balance if m exits, or less than its INV-03 amount if m waits for T0.
- Defends against: colluding members; host with sockpuppets.
- Release: 1.0..

**INV-08 — Cooperative close acceptance.**
- Required: A member signs a cooperative close only if it pays the member at least its latest channel balance (including its share of pending HTLCs that are its own), on a key the member controls and has not revealed.
- Defends against: malicious host.
- Release: 1.0..

**INV-09 — Dust never goes to the host.**
- Required: A member balance too small for its own output goes to the transaction fee, never to a host output.
- Defends against: malicious host.
- Release: 1.0..

**INV-10 — The host forces in time.**
- Required: Unless the funding output is spent cooperatively R deep, the host starts, no later than H_force, publishing every path of every member it has not settled, from a commitment it holds itself, so that each confirms by T0 − R.
- Defends against: silent or drained members (protects the host's funds).
- Release: 1.0..

## B. Factory signing

**INV-11 — Sign only what you rebuilt.**
- Required: No party produces a partial signature or a revocation for a transaction unless it rebuilt that transaction itself, from its own durable state plus the agreed proposal, and found it byte-equal.
- Defends against: malicious host or member.
- Release: 1.0..

**INV-12 — Check the funding before relying on it.**
- Required: A member treats a factory as live only after the funding outpoint is confirmed at the safe depth, unspent, of the proposed value, with a script byte-equal to the aggregate key the member computed.
- Defends against: phantom or double-spent funding; reorg.
- Release: 1.0..

**INV-13 — No funds committed before a signed exit.**
- Required: No party moves value into an output it cannot unilaterally exit from. The host broadcasts the funding only after it holds every tree transaction and the payout fully signed and every commitment 0 exchanged. A party adds an HTLC only into a commitment it will hold fully signed before it revokes the previous one.
- Defends against: one member stalling and locking host coins; host funding a tree members cannot exit.
- Release: 1.0..

**INV-14 — The proposal fixes every signed byte.**
- Required: The proposal carries, and both sides persist, every parameter that determines a signed byte: protocol id, network, per-member capacity, shape, T0, R, c, s, tree fee rate, commitment fee rate, member keys.
- Defends against: divergent rebuilds; host changing parameters; restart drift.
- Release: 1.0..

**INV-15 — Domain separation.**
- Required: Per-factory member keys and per-commitment seeds are derived (hardened) with the network and factory id; the proposal and handshake commit to `factory_protocol_id = SHA256("SuperScalar/1")`. Existing key aggregation and tags are not changed.
- Defends against: cross-factory and cross-network replay.
- Release: 1.0..

**INV-16 — Nonces are used once.**
- Required: Each MuSig2 secret nonce is generated fresh, used for at most one partial signature, never persisted, and never regenerated for a session that already produced a signature. A retransmitted signature uses a new nonce pair over byte-identical message data (see INV-20).
- Defends against: key extraction by a co-signer who replays a session; crash.
- Release: 1.0..

**INV-17 — Verify every partial signature before using any.**
- Required: Every received partial signature is verified against its signer's key and nonce before it is aggregated or relayed. In a round with several transactions nothing is aggregated until every partial of every transaction has verified. A failure names the signer.
- Defends against: a member producing a publishable parent with an unsignable child; a forged relayed partial.
- Release: 1.0..

**INV-18 — Phase order in a signing round.**
- Required: In every round the payouts of new outputs and both sides' commitments on new channel outpoints are signed and stored (phase A) before any signature for the transactions creating those outputs is released (phase B). Any failure aborts the round on every side.
- Defends against: host keeping the children of a new state.
- Release: 1.0..

**INV-19 — Never sign a second spend.**
- Required: A party never signs a second, different transaction spending an outpoint it already signed a spend of. The record is durable before the first signature leaves and survives restart and reorg messages.
- Defends against: conflicting spends after a crash or database restore.
- Release: 1.0..

## C. Channel updates

**INV-20 — One commitment per (channel, number, funding outpoint).**
- Required: For each (channel, commitment number, funding outpoint) a party signs at most one commitment transaction. Numbers only increase. A retransmission after reconnect signs the same bytes.
- Defends against: equivocation; restart replay; a member keeping a first version after a rollback.
- Release: 1.0..

**INV-21 — Both sides hold a commitment.**
- Required: From commitment 0 on, each side durably holds a fully signed commitment of its own for the channel's funding outpoint, which it can broadcast.
- Defends against: a silent member taking full capacity at T0; a member stranded without an exit.
- Release: 1.0..

**INV-22 — Persist before release.**
- Required: No party sends a revocation secret, a partial signature, a fulfil or a preimage until the state it depends on is durable in one database transaction: before `REVOKE_AND_ACK`, the new commitment fully signed, its per-commitment secrets, and the update set; before a fulfil, the claim armed (INV-30); before `COMMITMENT_SIGNED`, the update set and the signed transaction's digest.
- Defends against: crash at any instruction.
- Release: 1.0..

**INV-23 — Never broadcast a revoked state.**
- Required: A party never broadcasts a commitment whose per-commitment secret it has released. Its force-close uses only its latest unrevoked commitment, read from durable state that INV-22 keeps ahead of every released secret.
- Defends against: crash; operator error (a punishable broadcast loses the whole balance).
- Release: 1.0..

**INV-24 — Every revoked commitment can be punished, on every outpoint used.**
- Required: For every counterparty commitment a party has revoked, on every funding outpoint that commitment could spend, the party durably holds the verified revocation secret and a valid penalty (and HTLC sweeps), registered with its tower, before it uses the next state.
- Defends against: malicious host or member publishing old state.
- Release: 1.0..

**INV-25 — Verify counterparty secrets at one choke point.**
- Required: Every counterparty secret or signature that gates fund safety (revocation secret, commitment signature, preimage) is verified at a single choke point before it is stored or used. A failed check fails the channel and arms nothing.
- Defends against: garbage revocations (unpunishable breach).
- Release: 1.0..

**INV-26 — Per-commitment secrets are durable and scoped.**
- Required: Every per-commitment secret whose point was sent to the counterparty is durable before the point leaves. Secrets are never reused across channels, factories or rotations.
- Defends against: a channel that can no longer revoke after a restart; false forgery halts.
- Release: 1.0..

**INV-27 — Conservation across every update kind.**
- Required: For add, fulfil, fail and fee updates, both sides check before signing that local + remote + Σ active HTLC amounts + per-HTLC fees equals the funding amount minus the commitment fee, and refuse to sign otherwise.
- Defends against: arithmetic bugs; a counterparty that proposes an inconsistent state.
- Release: 1.0..

**INV-28 — Only the owner authorises a debit.**
- Required: A member's balance decreases only through an HTLC the member itself offered in a message it sent, or a fee update within agreed bounds. The host's balance likewise. A party refuses any update that debits it without its own request.
- Defends against: malicious host.
- Release: 1.0..

**INV-29 — An HTLC is never failed upstream while it is claimable downstream.**
- Required: The host fails an incoming (upstream) HTLC only after the matching downstream HTLC is removed from every commitment the downstream party holds unrevoked, or has timed out on chain.
- Defends against: a member withholding `REVOKE_AND_ACK`; a stalled bridge.
- Release: 1.0..

**INV-30 — An HTLC is claimable before its preimage is revealed.**
- Required: A party that reveals, or has learned, a preimage for an HTLC it is owed has an on-chain success claim armed and durable before it reveals the preimage, and can confirm it before the timeout path is valid.
- Defends against: a sender withholding `REVOKE_AND_ACK` and taking the HTLC back by timeout.
- Release: 1.0..

**INV-31 — HTLCs are resolved only by protocol.**
- Required: No party removes, fails or settles an HTLC except through a signed update both sides committed to, or on chain.
- Defends against: malicious host dropping payments; state divergence.
- Release: 1.0..

**INV-32 — HTLC deadlines fit inside the factory.**
- Required: An HTLC is added in either direction, including from the bridge, only if expiry < T0 − R and expiry − tip is at least the path's exit distance plus allowances. The host's downstream expiry is at least one forwarding delta below the upstream expiry. The member checks the same rule.
- Defends against: a counterparty running out the clock.
- Release: 1.0..

**INV-33 — Commitments stay relayable.**
- Required: Both sides refuse an HTLC that would make either commitment exceed 10,000 vB or fail default relay. The cap is derived from that limit.
- Defends against: HTLC stuffing so the host's commitment cannot relay.
- Release: 1.0..

**INV-34 — Reserve asymmetry.**
- Required: The member imposes a reserve on the host; the host imposes none on the member.
- Defends against: host draining its side to nothing left to lose.
- Release: 1.0..

**INV-35 — Payments never change the tree.**
- Required: A payment changes only channel state. No tree transaction, PS chain or payout is created, re-signed or replaced by a payment.
- Defends against: self-invalidating exits.
- Release: 1.0..

**INV-36 — Messages that arrive mid-update are queued, never dropped.**
- Required: A message for a channel that arrives while an update on that channel is in progress is queued in order and processed after it. A full queue fails the connection with an error; it never drops a message.
- Defends against: state divergence; lost HTLCs.
- Release: 1.0..

**INV-37 — Reconnect reconciles without equivocation.**
- Required: On reconnect each side derives its action from its own durable state and the peer's claim, as in the table in channel-update-protocol.md. A party never adopts a peer's claim as its own state, never signs a different commitment for a number it already signed, and a party that learns it is behind never broadcasts.
- Defends against: malicious peer; crash; data loss.
- Release: 1.0..

## D. Tree and timing

**INV-38 — The 1.0 shape.**
- Required: A 1.0 binary on mainnet builds only factories whose levels are all static and whose every leaf is a one-member PS leaf, and refuses any other shape at start-up and in a proposal.
- Defends against: shapes with known holes.
- Release: 1.0..

**INV-39 — No tree advance and no extension in place.**
- Required: After creation no code path re-signs, ticks, rolls over or advances any tree transaction, and no signature makes any transaction valid later than T0. Life is extended only by rotation.
- Defends against: self-invalidating exits; trapping members past T0.
- Release: 1.0..

**INV-40 — One payout date, computed one way.**
- Required: Every factory has one T0, computed by one function as created + active + dying + margin with margin ≥ R + s + c · (longest path). Creation is refused if H_force falls before the end of the dying period.
- Defends against: payouts valid too early or too late.
- Release: 1.0..

**INV-41 — Exit delay is bounded.**
- Required: The worst-case exit delay is computed from the built transactions and is at most 2016 blocks; both sides check it. For the 1.0 shape the relative-lock part is 0.
- Defends against: HTLC budget blow-up.
- Release: 1.0..

**INV-42 — Accepted sizes work end to end.**
- Required: For every member count the binaries accept, creation, every member's exit and restart complete, and every message and pre-signed transaction fits its limit. Larger counts are refused at start-up.
- Defends against: silent truncation; half-built factories.
- Release: 1.0..

## E. Watchtower

**INV-43 — The tower acts only on true breaches.**
- Required: A tower broadcasts a response only when a watched outpoint is spent by a revoked transaction.
- Defends against: faulty tower.
- Release: 1.0..

**INV-44 — The tower holds no secrets.**
- Required: The tower process can read no revocation secret, private key or partial signature, and cannot make a new signature. It only broadcasts pre-signed responses.
- Defends against: compromised tower.
- Release: 1.0..

**INV-45 — The tower never silently drops a watch.**
- Required: Registering a watch either succeeds durably or fails the update that needed it. Reload restores every entry. The tower can hold a watch for every state the party will sign.
- Defends against: faulty tower; long-lived channels.
- Release: 1.0..

## F. Fees

**INV-46 — Every pre-signed transaction is TRUC with one P2A at the term rate.**
- Required: Every pre-signed transaction (tree, distribution, commitment, penalty, HTLC claim) is version 3, at most 10,000 vB, pays exactly the agreed term rate for its exact vsize, and has exactly one P2A anchor (0-value at rate 0). It relays alone at or above the node's floor, else as a one-parent-one-child package.
- Defends against: exits that cannot reach the chain at the decided rate.
- Release: 1.0..

**INV-47 — Bounded exit fees.**
- Required: The fee a member must pay to exit is bounded by a number fixed at creation: its path length times the CPFP cost of one package at the rate it chooses. No counterparty action (HTLC stuffing, pinning, a larger transaction, an anchor value) can raise it, and no member pays for another member's transactions.
- Defends against: malicious host or member raising another's exit cost.
- Release: 1.0..

**INV-48 — A member can bump alone.**
- Required: A member can raise the fee of every transaction on its path and its payout without the host, using the anchor and its own coin or output.
- Defends against: absent host at a fee spike.
- Release: 1.0..

**INV-49 — The host can afford a forced exit.**
- Required: From H_force, the host holds enough confirmed wallet coins to bump, at the same time, every package at the busiest level of a full forced exit. Creation is refused otherwise.
- Defends against: colluding members forcing every path.
- Release: 1.0..

## G. Persistence and crash

**INV-50 — Safe after a crash anywhere.**
- Required: After a crash at any instruction and a restart from its own database, every party can still exit (INV-01), still meets its duties (INV-10), and never signs anything that conflicts with what it signed before. A failed database write is fatal for the operation that needed it.
- Defends against: crash.
- Release: 1.0..

**INV-51 — Reload equals the signed tree.**
- Required: The tree rebuilt on restart or reconnect has txids byte-equal to the signed rows. Any mismatch stops the party before it signs or publishes.
- Defends against: wrong-tree exits after restart.
- Release: 1.0..

**INV-52 — Nothing needed for an exit is deleted.**
- Required: No party deletes a signed transaction, payout, revocation secret, penalty or channel record until the outpoint it spends is spent R deep by something else.
- Defends against: crash and restore; a wiped record.
- Release: 1.0..

**INV-53 — Record before broadcast.**
- Required: Every wallet-funded transaction (funding, fee child) is durable, with what is needed to recover its outputs, before it is broadcast.
- Defends against: crash after broadcast.
- Release: 1.0..

**INV-54 — Reorgs up to R and backend outages are safe.**
- Required: Every decision that depends on confirmation needs depth R and is re-evaluated after a reorg of depth ≤ R. A backend error is never read as "not found". Neither causes a fund-losing action or a permanent freeze.
- Defends against: reorg; backend failure.
- Release: 1.0..

## H. Peers and bridge

**INV-55 — An unauthenticated peer cannot touch another session.**
- Required: The host acts on no message that affects a member's channel or factory, and replaces no member connection, until the peer has proved possession of that member's key over the current transcript.
- Defends against: outside peer; impersonation.
- Release: 1.0..

**INV-56 — Outside peers and members cannot stall the host.**
- Required: No peer holds the host's main loop beyond a bounded time, causes any wallet-funded broadcast, or exhausts a bounded resource.
- Defends against: outside peer; malicious member.
- Release: 1.0..

**INV-57 — The bridge cannot move member funds.**
- Required: Host and bridge authenticate each other. Every bridge HTLC passes the same checks as a member HTLC (INV-32). A rogue bridge can at most fail or delay payments.
- Defends against: CLN bridge or plugin; a peer claiming to be the bridge.
- Release: 1.0..

**INV-58 — Hostile input is rejected safely.**
- Required: Every message is bounds-checked; no peer-supplied length indexes past an allocation; no freed memory is read; every state machine rejects out-of-order messages with no state change.
- Defends against: every peer.
- Release: 1.0..

## I. Rotation

**INV-59 — The new factory comes first.**
- Required: A member releases an old-factory key, or signs any old-factory spend that does not pay it its balance, only after it holds the complete new factory (path, payout, both commitments 0) and the new funding is confirmed R deep (INV-12).
- Defends against: malicious host; crash mid-rotation.
- Release: rotation..

**INV-60 — A key is handed over only for an emptied channel.**
- Required: A member reveals an old-factory key only when its old channel balance is zero, no HTLC is pending, and its last old commitment is revoked.
- Defends against: malicious host spending a member's balance with its key.
- Release: rotation..

**INV-61 — Fresh keys per factory.**
- Required: Every factory uses member keys derived (hardened) per factory and bound by INV-15. No key revealed for one factory controls any output of any other.
- Defends against: host spending a rotated factory alone.
- Release: rotation..

**INV-62 — No double payment across factories.**
- Required: After rotated members hold the new factory, the host spends the old funding output R deep before the old T0 − R, in a durable, resumable step.
- Defends against: host crash between "new live" and "old spent".
- Release: rotation..

**INV-63 — A member who does not rotate is unaffected.**
- Required: A member that does not take part keeps its old position, payout and commitments valid.
- Defends against: offline members; host stranding stayers.
- Release: rotation..

## J. Operations and process

**INV-64 — Safe defaults.**
- Required: A 1.0 binary starts with sales, tree advances, rotation and JIT off. It refuses test and cheat flags and unauthenticated transports on any network other than regtest.
- Defends against: misconfiguration.
- Release: 1.0..

**INV-65 — Deadlines are visible and alarmed.**
- Required: The host exposes per factory T0, H_force, blocks remaining, per-member last-seen, pending HTLCs against the cap, and fee-coin sufficiency, and alerts before H_force. A member warns before T0.
- Defends against: operator missing the force-out window.
- Release: 1.0..

**INV-66 — Invariant tests gate merges.**
- Required: Every 1.0 invariant has positive, negative and fix-undone tests in required CI. A skip fails the job.
- Defends against: regressions; vacuous tests.
- Release: 1.0..

**INV-67 — Wire ids and schema versions are unique.**
- Required: Each wire id and schema version is assigned once; CI fails on a duplicate.
- Defends against: misrouted messages; ambiguous databases.
- Release: 1.0..

**INV-68 — Members are warned about their fee reserve.**
- Required: A member computes the on-chain coin it would need to win a contested exit and warns while it holds less. It is never required.
- Defends against: contested fee races.
- Release: 1.0..

## K. Later releases

**INV-69 — A sale makes a new channel.**
- Required: A liquidity sale spends only the current stock output and creates a new channel plus the remaining stock. Existing channels keep their outpoints.
- Defends against: Moving existing channels; a co-signer acting for the host.
- Release: 1.1.

**INV-70 — Shared-leaf coverage.**
- Required: In a shared leaf a member's spendable balance never exceeds what every ancestor payout pays it, unless it holds the design's client reserve.
- Defends against: A leaf-mate shifting value; a host underpaying a member.
- Release: 1.1.

**INV-71 — JIT channels meet the channel invariants.**
- Required: A JIT channel has its own key, commitment 0 both ways before its funding is broadcast, the factory's T0, and satisfies INV-01, INV-21, INV-24 and INV-53.
- Defends against: Malicious host sweeping JIT funds; members without a JIT exit.
- Release: opt-in.

## L. Engine resources and payee rules

**INV-72 — Signing resources are replenished, not exhausted.**
- Required: A channel never stops working because a per-connection resource ran out. Nonces are replenished in-protocol before a pool empties.
- Defends against: A counterparty that forces repeated reconnects.
- Release: 1.0..

**INV-73 — A member's own payments are never re-sent by the host.**
- Required: The host forwards an HTLC to a member exactly once per upstream HTLC. A replay after reconnect re-sends the same update (same id, amount, hash, expiry), never a new one.
- Defends against: double crediting or double debiting after reconnect.
- Release: 1.0..

**INV-74 — A preimage is released only for full payment.**
- Required: A payee reveals a preimage only for an HTLC whose amount is at least its invoice amount, whose expiry meets the invoice's final CLTV plus the path's exit distance, and only once per invoice. Preimages come from a secure random source.
- Defends against: malicious host underpaying a member's invoice and keeping the difference; a host guessing a preimage.
- Release: 1.0..

**INV-75 — No database transaction is held open across a network wait.**
- Required: Each durable write of the update protocol is opened and committed without waiting on any peer in between. A write made by one channel's round never depends on another channel's round for its commit.
- Defends against: crash; a slow peer delaying the durability of unrelated state.
- Release: 1.0..
