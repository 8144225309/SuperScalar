#ifndef SUPERSCALAR_CLIENT_H
#define SUPERSCALAR_CLIENT_H

#include "channel.h"
#include "factory.h"
#include "fee_estimator.h"
#include "persist.h"
#include "chain_backend.h"
#include <stdio.h>
#include "wire.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

/* Run the client-side factory creation + cooperative close ceremony.
   Connects to LSP at host:port, performs HELLO handshake, builds factory,
   generates nonces/psigs, and does cooperative close.
   Returns 1 on success, 0 on failure. */
int client_run_ceremony(secp256k1_context *ctx,
                        const secp256k1_keypair *keypair,
                        const char *host, int port);

/* Callback for automated (non-interactive) channel operations.
   fd: wire connection to LSP.
   channel: the client's channel with the LSP.
   my_index: participant index (1..N).
   ctx: secp256k1 context.
   keypair: client's keypair (needed for close ceremony in daemon mode).
   factory: the factory (needed for close ceremony in daemon mode).
   n_participants: number of participants in the factory.
   user_data: opaque pointer for test harness.
   Return 1: caller runs close ceremony.
   Return 0: error.
   Return 2: callback already handled close, caller skips it. */
typedef int (*client_channel_cb_t)(int fd, channel_t *channel,
                                    uint32_t my_index,
                                    secp256k1_context *ctx,
                                    const secp256k1_keypair *keypair,
                                    factory_t *factory,
                                    size_t n_participants,
                                    void *user_data);

/* Initialize a channel for a client within a factory (used by reconnect and sweep). */
int client_init_channel(channel_t *ch, secp256k1_context *ctx,
                         const factory_t *factory,
                         const secp256k1_keypair *keypair,
                         uint32_t my_index,
                         const secp256k1_pubkey *remote_payment_bp,
                         const secp256k1_pubkey *remote_delayed_bp,
                         const secp256k1_pubkey *remote_revocation_bp,
                         const secp256k1_pubkey *remote_htlc_bp,
                         const unsigned char *local_pay_sec32,
                         const unsigned char *local_delay_sec32,
                         const unsigned char *local_revoc_sec32,
                         const unsigned char *local_htlc_sec32,
                         fee_estimator_t *fee_est);

/* Set the minimum acceptable profit share in basis points.  If > 0 and
   the LSP's FACTORY_PROPOSE offers less, the client refuses to sign.
   0 = accept any terms (default). */
void client_set_min_profit_bps(uint16_t bps);

/* Channel capacity terms checked before signing a factory: refuse unless the
   member's own channel output is exactly expect_sats (0 = any) and at least
   min_sats (0 = any).  The capacity is logged either way. */
void client_set_capacity_terms(uint64_t expect_sats, uint64_t min_sats);

/* Refuse a factory whose proposed opening split gives the LSP more than
   pct percent of each channel (default 100 = any). */
void client_set_max_lsp_balance_pct(uint16_t pct);

/* This member's own ceiling on the factory's pre-signed tree rate (sat/kvB):
   a FACTORY_PROPOSE (creation or rotation) above it is refused, so an LSP
   cannot spend a member's channel on pre-signed fees.  Default
   CLIENT_DEFAULT_MAX_TREE_FEE_RATE (10 sat/vB); 0 = no ceiling.  Set from
   --max-tree-fee-rate; nothing has to match the LSP. */
#define CLIENT_DEFAULT_MAX_TREE_FEE_RATE 10000
void client_set_max_tree_fee_rate(uint64_t sat_per_kvb);
uint64_t client_max_tree_fee_rate(void);

/* 1 if sat_per_kvb is within this member's ceiling (0 is always). */
int client_tree_fee_rate_acceptable(uint64_t sat_per_kvb);

/* What the chain says about a transaction output. */
typedef struct {
    uint64_t      amount_sats;
    unsigned char spk[64];
    size_t        spk_len;
    int           confirmations;   /* 0 = mempool only */
    int           unspent;         /* 1 unspent, 0 spent, -1 could not tell */
} client_funding_output_t;

/* Chain lookup used to verify a factory funding output before the client
   signs anything for the factory.  Fills *out and returns 1 if the output
   txid32:vout (txid in internal byte order) is known to the chain source,
   0 if it is not or the source failed.  The decision is not the callback's:
   client_check_factory_funding compares the result with what the client
   derived itself. */
typedef int (*client_verify_funding_fn)(const unsigned char *txid32,
                                         uint32_t vout,
                                         client_funding_output_t *out,
                                         void *ctx);

/* Funding check for a factory the client has built from a proposal, used
   for the first factory and for every rotation, before any signature:
     - the client's own key sits at its index in the participant set;
     - the funding script in the proposal is the script the client derives
       from that participant set (the root node's spending script);
     - the chain lookup finds the output with EXACTLY that script and
       EXACTLY the proposed amount, unspent, with at least one confirmation
       (an unconfirmed funding output is never accepted).
   Without a lookup the factory is refused, unless
   client_set_allow_unverified_funding(1) was called.  Returns 1 to proceed. */
int client_check_factory_funding(const factory_t *f, uint32_t my_index,
                                  const secp256k1_pubkey *my_pubkey);

/* Harness only: accept factories without any chain lookup (in-process tests
   and regtest scaffolds without RPC credentials).  Off by default. */
void client_set_allow_unverified_funding(int allow);

/* FACTORY_READY handler.  Every tree node the LSP sends must be the client's
   own transaction for that node carrying one signature that verifies; the
   client's own serialization is what gets stored.  Every node this client
   signs for (its path from the root to its leaf) must be present.  A signed
   distribution transaction, if sent, must pass
   client_verify_distribution_tx against the client's own build.  Returns
   the number of nodes applied, or -1 to refuse the factory. */
int client_apply_factory_ready(factory_t *f, const cJSON *json, uint32_t my_index);

/* 1 if offered is the distribution transaction locktime this client derives
   for f (factory_distribution_locktime). */
int client_dist_locktime_acceptable(const factory_t *f, uint32_t offered);

/* Full capacity of member my_index's channel in f: its leaf output less the
   base commitment fee, i.e. the channel's two balances together at open.
   This is what the distribution transaction owes the member.  0 if the
   member has no channel output in f.  With member capacities
   (factory_set_member_capacities) it is the member's capacity-rule payout
   instead: its full capacity plus its share of its leaf's stock and of the
   rest of the budget. */
uint64_t client_member_channel_capacity(const factory_t *f, uint32_t my_index);

/* Distribution payout check, shared by every place that accepts or relies on
   a distribution transaction: 1 if tx pays the key-path-only taproot output
   of member_pubkey at least required_sats in total. */
int client_distribution_pays_member(const secp256k1_context *ctx,
                                     const unsigned char *tx, size_t tx_len,
                                     const secp256k1_pubkey *member_pubkey,
                                     uint64_t required_sats);

/* The condition for accepting factory f, at first open and at rotation: f
   carries a fully co-signed, verified distribution transaction
   (dist_tx_ready == 2) that pays member my_index (key my_pubkey) at least
   its full channel capacity. */
int client_factory_exit_acceptable(const secp256k1_context *ctx, const factory_t *f,
                                    uint32_t my_index,
                                    const secp256k1_pubkey *my_pubkey);

/* Depth the funding output must have before a factory is accepted.  The
   client tool sets network_funding_confs(network, --funding-confs), whose
   default is the depth the LSP waits for by default; library default 1. */
void client_set_funding_min_confs(int confs);

/* Factory rotation is experimental and off unless enabled
   (--enable-rotation-experimental, refused on mainnet).  While off the
   client refuses ROTATION_BEGIN, the key turnover and rotation proposals. */
void client_set_allow_rotation(int allow);
int client_rotation_allowed(void);

/* Run the full ceremony with optional channel operations.
   If channel_cb is NULL, behaves identically to client_run_ceremony
   (creates factory then immediately closes).
   If channel_cb is non-NULL, calls it after CHANNEL_READY and before close.
   verify_funding is the chain lookup for client_check_factory_funding; with
   NULL the factory is refused unless unverified funding was allowed.
   (Historic wording follows.)
   If verify_funding is non-NULL, called to verify the on-chain funding TX
   before signing the factory tree.  Pass verify_ctx for the callback. */
int client_run_with_channels(secp256k1_context *ctx,
                              const secp256k1_keypair *keypair,
                              const char *host, int port,
                              client_channel_cb_t channel_cb,
                              void *user_data,
                              client_verify_funding_fn verify_funding,
                              void *verify_ctx);

/* The scriptPubKey a client is paid to in a cooperative close: P2TR whose
   output key is the client's own factory key.  The client derives it from
   its own key; it is never taken from the LSP's proposal.  Writes 34 bytes.
   Returns 1 on success. */
int client_close_script(const secp256k1_context *ctx,
                         const secp256k1_pubkey *my_pubkey,
                         unsigned char *spk_out34);

/* What a proposed close pays this client: the outputs that carry its own
   close script and are at or above the dust limit.  An output below the dust
   limit is not a payment the client can count on and is ignored.  Writes
   their total and how many there are; an honest LSP pays each client with
   exactly one output (lsp_channels_build_close_outputs).  Returns 1 on
   success, 0 if the script cannot be derived or the total overflows. */
int client_close_amount_to_client(const secp256k1_context *ctx,
                                   const secp256k1_pubkey *my_pubkey,
                                   const tx_output_t *outputs,
                                   size_t n_outputs,
                                   uint64_t *paid_sats_out,
                                   size_t *n_paying_out);

/* How many blocks the nLockTime of a proposed close may lie above the
   client's own chain tip.  The LSP sets nLockTime to its current height; the
   margin only has to absorb the client's view of the chain lagging by a few
   blocks.  Six blocks is about an hour. */
#define CLIENT_CLOSE_LOCKTIME_MARGIN 6

/* Decide whether the nLockTime of a proposed close is acceptable.  A signed
   close that cannot confirm yet is a transaction the LSP can hold back and
   use later, so the lock must be near the present:
     - 0 imposes no lock and is always acceptable;
     - a height is acceptable only if the client knows its chain tip
       (tip_height != 0) and the height is at most
       tip_height + CLIENT_CLOSE_LOCKTIME_MARGIN;
     - a time-based lock (>= 500000000) is never acceptable.
   Returns 1 if acceptable. */
int client_close_locktime_acceptable(uint32_t locktime, uint32_t tip_height);

/* Source of the client's own chain tip height, used to bound the nLockTime
   of close proposals.  fn returns the height, or 0 if it is not known.
   With no source set the tip is unknown. */
typedef uint32_t (*client_chain_tip_fn)(void *ctx);
void client_set_chain_tip_source(client_chain_tip_fn fn, void *ctx);
uint32_t client_chain_tip(void);

/* A chain backend can be briefly unreachable or a few blocks behind.  When
   the tip a close proposal has to be judged by is unknown, or too low for
   the proposal's nLockTime, the close ceremony asks the source again, up to
   `attempts` times in all, `delay_ms` apart, before it decides.  Defaults:
   CLIENT_CHAIN_TIP_ATTEMPTS and CLIENT_CHAIN_TIP_RETRY_MS. */
#define CLIENT_CHAIN_TIP_ATTEMPTS 5
#define CLIENT_CHAIN_TIP_RETRY_MS 1000
void client_set_chain_tip_retry(unsigned attempts, unsigned delay_ms);

/* What the client knows about cooperative closes it has signed for one
   factory.

   Once the client has released a partial signature for a close, the LSP may
   be able to complete and broadcast that close at any later time, whatever
   it reports back.  From that moment the factory is frozen for this client:
   it takes part in no further channel update and no leaf or state advance of
   that factory, and signs only another close that pays it at least
   paid_sats.  A unilateral exit stays possible.

   With db set the record is written before the partial signature is sent
   and client_close_state_init reads it back, so it survives a restart. */
typedef struct {
    int signed_close;           /* 1 once a partial signature was released */
    uint64_t paid_sats;         /* what that close pays this client's script */
    unsigned char sighash[32];  /* sighash of that close transaction */
    int refused;                /* set by client_do_close_ceremony: 1 if it
                                   ended by refusing what the LSP proposed */
    int unverifiable;           /* set by client_do_close_ceremony: 1 if it
                                   ended because the client could not check
                                   the proposal (no chain tip, or its own
                                   records unreadable).  Nothing was signed
                                   or recorded; the same proposal may be
                                   acceptable when tried again */
    int record_error;           /* set by client_close_state_init: the record
                                   could not be read from db */
    persist_t *db;              /* where the record is kept, or NULL */
} client_close_state_t;

/* Reset cs and load the record for factory from db (db may be NULL).  If
   the record cannot be read, cs->record_error is set and the ceremony will
   not sign until it can be. */
void client_close_state_init(client_close_state_t *cs, persist_t *db,
                              const factory_t *factory);

/* The freeze condition, in one place: 1 if this client must treat the
   factory as frozen, because a close of it was signed (cs->signed_close) or
   because the record that would say so cannot be read (cs->record_error).
   Not being able to tell is not the same as nothing having been signed.
   While the record is unreadable it is read again on every call, so an
   error that passes clears itself; cs is updated with what was found.
   Every message loop of the client tool gates on this. */
int client_close_state_frozen(client_close_state_t *cs,
                               const factory_t *factory);

/* client_close_state_frozen for a caller that keeps no state: reads the
   database set with client_set_persist. */
int client_close_signed_for_factory(const factory_t *factory);

/* 1 if the state of ch accounts for the whole funding output: local +
   remote + every active HTLC and PTLC with the commitment fee taken for it
   when it was added == funding_amount - base commitment fee. */
int client_channel_balanced(const channel_t *ch);

/* While a signed close of the factory is outstanding, a client acts only on
   a close proposal, keepalives and the LSP's own revocations (which only add
   to what the client can prove).  Returns 1 if a message of this type may
   still be processed.  Shared by every message loop of the client tool. */
int client_close_frozen_allows_msg(uint8_t msg_type);

/* Decide whether a cooperative-close proposal is safe for this client to sign.
   Returns 1 only if
     - no HTLC or PTLC is pending on ch,
     - the channel state accounts for the whole funding output: local +
       remote + active HTLCs == funding_amount - base commitment fee (an HTLC
       missing from the list makes this fail), and
     - exactly one output at or above the dust limit carries the client's
       own close script, and it pays at least ch->local_amount (no output is
       required for a balance below the dust limit; more than one is always
       refused).
   Outputs to any other script are ignored regardless of amount.
   ch == NULL means the client never opened a channel in this factory; it is
   then owed nothing and any outputs are acceptable (returns 1). */
int client_close_outputs_acceptable(const secp256k1_context *ctx,
                                     const secp256k1_pubkey *my_pubkey,
                                     const channel_t *ch,
                                     const tx_output_t *outputs,
                                     size_t n_outputs);

/* Perform the cooperative close ceremony on an already-received CLOSE_PROPOSE.
   If initial_msg is non-NULL, it is the already-received CLOSE_PROPOSE message;
   otherwise we recv it from the wire.
   ch is the client's channel in this factory.  Before signing, the client
   requires the proposal to pay at least ch->local_amount to its own close
   script (client_close_script) and refuses while any HTLC is pending; see
   client_close_outputs_acceptable.  Pass NULL only when the client never
   opened a channel in this factory and so holds no balance; with NULL the
   client still refuses if its database holds a channel for this factory.
   A client with no database at all cannot have carried a channel over from
   an earlier run (reconnecting to a factory needs the database), so with no
   database and no channel it is owed nothing and may sign.
   current_height is the client's own chain tip (0 if unknown); the proposal's
   nLockTime must satisfy client_close_locktime_acceptable against it.  If it
   does not, the tip source is asked again for a bounded time
   (client_set_chain_tip_retry).  A height that still cannot be judged
   because no tip is known ends the ceremony as unverifiable, not refused.
   cs is the client's close state for this factory.  The ceremony records
   the close in it (and in cs->db) before sending the partial signature;
   once cs->signed_close is set it refuses leaf and state advances that
   arrive during the ceremony and any proposal paying the client less than
   cs->paid_sats.  Pass NULL to use a state private to this call, loaded
   from and saved to the database set with client_set_persist.
   Returns 1 on success and 0 otherwise.  cs->refused: the client declined
   the terms.  cs->unverifiable: the client could not check the proposal;
   nothing was signed or recorded and the LSP may try again.  Neither: the
   ceremony failed for another reason (malformed or unexpected message, LSP
   error, lost connection). */
int client_do_close_ceremony(int fd, secp256k1_context *ctx,
                               const secp256k1_keypair *keypair,
                               const secp256k1_pubkey *my_pubkey,
                               factory_t *factory,
                               size_t n_participants,
                               const wire_msg_t *initial_msg,
                               uint32_t current_height,
                               const channel_t *ch,
                               client_close_state_t *cs,
                               int repropose_depth);

/* Reconnect to LSP using persisted state from SQLite.
   Loads factory + channel from DB, sends MSG_RECONNECT, receives
   MSG_RECONNECT_ACK, re-exchanges nonces, then calls channel_cb.
   Returns 1 on success, 0 when the attempt failed or the connection was lost
   (the caller may try again), and CLIENT_RECONNECT_REFUSED when the stored
   factory does not load as the signed tree: every further attempt is
   refused the same way, so the caller must stop. */
#define CLIENT_RECONNECT_REFUSED (-1)
int client_run_reconnect(secp256k1_context *ctx,
                           const secp256k1_keypair *keypair,
                           const char *host, int port,
                           persist_t *db,
                           client_channel_cb_t channel_cb,
                           void *user_data);

/* Perform factory rotation: create a new factory from an already-received
   FACTORY_PROPOSE message (no HELLO handshake).
   Overwrites factory_out and channel_out with the new factory/channel.
   Returns 1 on success. */
int client_do_factory_rotation(int fd, secp256k1_context *ctx,
                                const secp256k1_keypair *keypair,
                                uint32_t my_index,
                                size_t n_participants,
                                const secp256k1_pubkey *all_pubkeys,
                                factory_t *factory_out,
                                channel_t *channel_out,
                                const wire_msg_t *initial_propose);

/* --- Client-side channel message handlers --- */

/* Send ADD_HTLC to LSP for payment to dest_client.
   Adds the HTLC to the local channel state (HTLC_OFFERED) before sending.
   payment_hash: 32-byte hash (caller generates).
   Returns 1 on success. */
int client_send_payment(int fd, channel_t *ch, uint64_t amount_sats,
                         const unsigned char *payment_hash32,
                         uint32_t cltv_expiry, uint32_t dest_client);

/* Handle incoming COMMITMENT_SIGNED from LSP.
   Verifies and sends REVOKE_AND_ACK back. Returns 1 on success. */
/* Co-sign the LSP's own commitment at ch's current number into msg
   (host_commit_psig, host_commit_nonce_index).  Returns 1 if attached. */
int client_add_host_commit_sig(channel_t *ch, cJSON *msg);
/* 1 if every LSP commitment this member co-signed below its current number
   is revoked; client_fulfill_payment releases no preimage before. */
int client_host_old_commitments_revoked(const channel_t *ch);
/* Load the LSP's revocation secrets this member stored for channel_id into
   ch (after a restart or a reconnect rebuilds the channel). */
int client_restore_host_revocations(channel_t *ch, persist_t *db, uint32_t channel_id);
/* MSG_CHANNEL_NONCES with "refresh" between updates: take the LSP's fresh
   nonces, make a fresh pool and reply with its nonces.  Returns 1 if sent. */
int client_handle_nonce_refresh(int fd, channel_t *ch, secp256k1_context *ctx,
                                const wire_msg_t *msg);

int client_handle_commitment_signed(int fd, channel_t *ch,
                                      secp256k1_context *ctx,
                                      const wire_msg_t *msg);

/* Channel open: handle the LSP's COMMITMENT_SIGNED for commitment 0.
   Verifies the LSP's partial signature over the client's initial commitment
   transaction, aggregates it with the client's own and stores the result in
   ch->latest_commitment_sig.  Nothing is revoked and no REVOKE_AND_ACK is
   sent: there is no earlier commitment.  Returns 1 on success; 0 if the
   message is malformed, is not for commitment 0, or the signature does not
   verify (the channel must not be used). */
int client_handle_initial_commitment_signed(channel_t *ch, const wire_msg_t *msg);

/* Channel open and rotation: receive the LSP's COMMITMENT_SIGNED for
   commitment 0 from fd (keepalive pings are skipped) and accept it only if
   the channel's opening balances account for the whole funding output
   (balances == funding - base commitment fee) and the signature verifies.
   Returns 1 if ch now holds a signed commitment 0, 0 otherwise. */
int client_recv_initial_commitment(int fd, channel_t *ch, uint32_t my_index);

/* A rotation in progress keeps the factory being left under id 0, with its
   channel and commitment, and stores the factory being entered under this
   id until the new channel's commitment 0 is saved.  A factory on record
   under this id therefore means "a rotation started and did not finish": it
   is the durable marker the client checks at start-up and in --force-close. */
#define CLIENT_ROTATION_PENDING_FACTORY_ID 1u

/* Store f (verified tree, verified signed distribution transaction) as the
   pending factory.  Nothing recorded for factory 0 is changed.  One database
   transaction.  Returns 1 on success. */
int client_rotation_save_pending(persist_t *db, const factory_t *f,
                                  secp256k1_context *ctx);

/* 1 if the last client_do_factory_rotation call stored a pending factory. */
int client_rotation_new_factory_saved(void);

/* Chain lookup used when a rotation proposes a new factory (the same
   callback client_run_with_channels takes for the first factory, which also
   installs it). */
void client_set_funding_verifier(client_verify_funding_fn fn, void *ctx);

/* Distribution transaction check.  signed_tx is what the LSP sent;
   unsigned_tx and sighash32 are the client's own construction of the same
   transaction; funding_spk34 is the factory funding script.  Returns 1 only
   if signed_tx is byte for byte the client's transaction carrying one
   key-path signature that verifies under the funding output key. */
int client_verify_distribution_tx(const secp256k1_context *ctx,
                                   const unsigned char *unsigned_tx, size_t unsigned_len,
                                   const unsigned char *sighash32,
                                   const unsigned char *funding_spk34,
                                   const unsigned char *signed_tx, size_t signed_len);

/* Amount a (signed or unsigned, single-input) transaction pays to the
   key-path-only taproot output of pubkey; 0 if it has no such output. */
uint64_t client_tx_amount_to_pubkey(const secp256k1_context *ctx,
                                     const unsigned char *tx, size_t len,
                                     const secp256k1_pubkey *pubkey);

/* What --force-close may publish.  Returns
     1  publish the tree of factory 0 and the stored commitment;
     0  publish no tree; *dist_factory_out names the factory whose
        distribution transaction may be offered;
    -1  the chain could not be read well enough to decide: publish nothing.
   A tree is published only when a commitment for a channel in it is on
   disk.  With a rotation pending, the factory being left is used while its
   funding output is unspent AND after this client's own root transaction
   has spent it (the exit is then under way and must be continued); only a
   funding output spent by something else moves the client to the pending
   factory's distribution transaction.  Lines describing the decision go to
   out. */
int client_force_close_plan(persist_t *db, chain_backend_t *chain,
                             uint32_t *dist_factory_out, FILE *out);

/* Write the channel's latest fully signed commitment transaction
   (ch->latest_commitment_sig over the commitment at ch->commitment_number)
   to the signed_commitments table, so it can be broadcast from the database
   alone.  Returns 1 if the row was written, 0 otherwise (including when the
   channel holds no commitment signature). */
int client_persist_latest_commitment(persist_t *db, uint32_t channel_id,
                                       const channel_t *ch);

/* Revocation-verification standard (client side): verify the LSP's revealed
   per-commitment secret against the LSP's committed per-commitment point, then
   retain it (so the user can detect an LSP breach) and track the LSP's next
   point. Mirrors the LSP-side handler. Returns 1 on success (verified+stored, or
   nothing to revoke yet at commitment 0); 0 if the secret is invalid (caller
   should fail the channel) or the message is malformed. See
   doc/revocation-verification-standard.md. */
int client_handle_lsp_revoke_and_ack(channel_t *ch, secp256k1_context *ctx,
                                       const wire_msg_t *msg);

/* Item-1 escalation policy: how the client responds once it DETECTS a forged LSP
   revocation (i.e. client_handle_lsp_revoke_and_ack returned 0 — fail-closed). In
   every mode the bad secret is refused and NO watchtower is armed from it; the
   modes differ only in what the client does NEXT. A client that cannot obtain a
   valid LSP revocation holds an un-penalizable old LSP state, so continuing to
   build new states is the riskiest choice. Selectable via --on-lsp-forgery.
   NOTE: PS (Pseudo-Spilman) leaves are CLTV-gated rather than revocation-gated,
   so a forged LSP revocation is less severe on a PS leaf than on a revocation-
   gated leaf; the policy is applied uniformly today (see doc). */
typedef enum {
    LSP_FORGERY_CONTINUE = 0,  /* refuse + no WT-arm, keep the session (legacy)   */
    LSP_FORGERY_HALT     = 1,  /* + stop accepting new commitments, CRITICAL alert*/
    LSP_FORGERY_CLOSE    = 2,  /* + force-close on the last fully-verified state   */
} lsp_forgery_response_t;

/* Parse an --on-lsp-forgery argument ("continue"|"halt"|"close") into the enum;
   returns -1 on an unrecognised value. */
int client_parse_forgery_response(const char *s);

/* Handle incoming ADD_HTLC from LSP (we are the payee).
   Returns 1 on success. */
int client_handle_add_htlc(channel_t *ch, const wire_msg_t *msg);

/* Apply an UPDATE_FAIL_HTLC from the LSP to the channel.
   An HTLC the LSP never took (uncommitted) is rolled back and nothing
   follows.  A committed one is failed, the amount returns to whoever
   offered it, and the LSP's COMMITMENT_SIGNED follows as after a fulfil.
   Returns 1 if the HTLC was removed; *committed_out says which case. */
int client_handle_fail_htlc(channel_t *ch, const wire_msg_t *msg,
                             int *committed_out, uint64_t *htlc_id_out);

/* Handle async / unsolicited LSP->client notifications (MSG_FUNDING_REORG,
   MSG_CEREMONY_ABORT).  Returns 1 if handled (caller still frees msg->json), 0
   otherwise.  Shared by the ceremony recv path (wire_recv_handle_ping) and the
   client daemon dispatch so both handle them identically. */
int client_handle_async_msg(const wire_msg_t *msg);

/* Send FULFILL_HTLC to LSP (reveal preimage for received HTLC).
   Returns 1 on success. */
int client_fulfill_payment(int fd, channel_t *ch,
                             uint64_t htlc_id,
                             const unsigned char *preimage32);

/* Amount rule for an LSP-proposed leaf reallocation.  Evaluated entirely
   against the client's own tree: the client must be a signer of the leaf,
   the amounts must cover exactly the leaf's reallocatable outputs and
   conserve their total, and the output funding this client's channel
   (located with factory_client_to_leaf, never from the message) must not be
   smaller than it is now.  Returns 1 if the amounts satisfy the rule.

   Passing this rule does NOT make a reallocation signable.  A reallocation
   replaces the leaf transaction, and the client's channel and commitments
   are not moved to the new leaf output, so a client that co-signs one loses
   its unilateral exit even when its amount is unchanged.  The rule is only
   one precondition for a future ceremony that also re-anchors the channel;
   client_handle_leaf_realloc does not consult it and refuses everything. */
int client_leaf_realloc_acceptable(const factory_t *factory,
                                    uint32_t my_index, int leaf_side,
                                    const uint64_t *amounts, size_t n_amounts);

/* Handle a LEAF_REALLOC_PROPOSE from the LSP: always refuse.
   Sends an error to the LSP, reveals no nonce, produces no signature and
   leaves the factory untouched.  Always returns 0. */
int client_handle_leaf_realloc(int fd, secp256k1_context *ctx,
                                const secp256k1_keypair *keypair,
                                factory_t *factory,
                                uint32_t my_index,
                                const wire_msg_t *propose_msg);

/* Handle a LEAF_ADVANCE_PROPOSE from the LSP (DW or PS leaf advance).
   Advances local leaf state, generates partial sig, sends LEAF_ADVANCE_PSIG,
   waits for LEAF_ADVANCE_DONE. Returns 1 on success.

   PS double-spend defense (record-and-refuse): if client_set_persist() has
   been called with a non-NULL handle, the PS advance path computes the
   sighash of the proposed spend, consults client_ps_signed_inputs BEFORE
   any nonce exists, and REFUSES if this client has already co-signed a
   DIFFERENT TX spending the same (parent_txid, parent_vout) -- or if that
   lookup fails at all.  A matching sighash is an idempotent retry and is
   re-signed.  After signing, the record is INSERTed (durable; first record
   wins) BEFORE MSG_LEAF_ADVANCE_FINAL is sent; if the insert fails, or
   loses to a conflicting record, the ceremony aborts and nothing is sent.
   See ZmnSCPxj §"Pseudo-Spilman wide leaves" — PS has no revocation, so
   the client's refusal is the only thing preventing an LSP double-spend.
   When no persist is set, the defense is skipped (tests / in-process usage
   only — real clients must call client_set_persist at startup).  The full
   rule: docs/pseudo-spilman.md, "Record-and-refuse: ordering and failure
   semantics". */
int client_handle_leaf_advance(int fd, secp256k1_context *ctx,
                                 const secp256k1_keypair *keypair,
                                 factory_t *factory,
                                 uint32_t my_index,
                                 const wire_msg_t *propose_msg);

/* Handler for MSG_STATE_ADVANCE_PROPOSE (Tier B ceremony, Gap B + F).
   Drives the client side of the multi-party state-advance ceremony when
   the LSP has detected a per-leaf DW counter rollover.

   Round structure (see docs/rotation-ceremony.md):
     receive STATE_ADVANCE_PROPOSE  ← caller passes propose_msg
     advance local DW counter (must hit -1 / root rollover)
     init MuSig session for every non-PS-leaf node where this client signs
     send PATH_NONCE_BUNDLE         (own pubnonces)
     receive PATH_ALL_NONCES        (every signer's nonce per node)
     finalize sessions
     send PATH_PSIG_BUNDLE          (own partial sigs)
     receive PATH_SIGN_DONE

   Returns 1 on success, 0 on any failure (parse / advance / crypto). */
int client_handle_state_advance(int fd, secp256k1_context *ctx,
                                  const secp256k1_keypair *keypair,
                                  factory_t *factory,
                                  uint32_t my_index,
                                  const wire_msg_t *propose_msg);

/* Sub-factory chain extension client handler (Gap E followup Phase 2b,
   t/1242 k² PS).  The LSP is "selling sales-stock to a client";
   every co-signer of the sub-factory must participate.  Drives the
   wire ceremony: parses PROPOSE → applies chain advance locally →
   sends NONCE → waits for ALL_NONCES → finalizes session → sends
   PSIG → waits for DONE.  Returns 1 on success, 0 on any failure.

   PS double-spend defense (record-and-refuse, per input): chain[N+1]
   spends every output of chain[N] and is not revocable, and the LSP
   picks channel_idx and delta_sats.  A PROPOSE_INTENT whose n_inputs is
   not the number of chain[N] outputs, or whose subfactory_id is not the
   sub-factory that (leaf_side, sub_idx) names, is refused.  With
   client_set_persist() set, for every input this client signs the
   handler computes the BIP-341 sighash and consults
   client_ps_signed_inputs BEFORE any nonce (error -> refuse; a recorded
   DIFFERENT spend of that (txid, vout) -> refuse; the same sighash ->
   idempotent retry), binds each sighash to the session message it signs,
   and INSERTs one row per signed input BEFORE
   MSG_SUBFACTORY_CLIENT_FINAL_PSIGS is sent.  If any insert fails or
   loses to a conflicting record, the ceremony aborts and nothing is sent.
   Rules: docs/pseudo-spilman.md, "Record-and-refuse". */
int client_handle_subfactory_advance(int fd, secp256k1_context *ctx,
                                       const secp256k1_keypair *keypair,
                                       factory_t *factory,
                                       uint32_t my_index,
                                       const wire_msg_t *propose_msg);

/* Set (or clear) the persistence handle used for the PS double-spend
   defense, for the checks the close ceremony makes against the client's
   own records, and for refusing leaf and state advances of a factory whose
   close this client has already signed. Pass NULL to disable. Must be
   called before any PS advance or close happens; safe to call once at
   startup. */
void client_set_persist(persist_t *persist);

/* The client refuses every leaf, state and sub-factory advance: none of
   them moves its channel onto the tree they produce, so co-signing one
   would leave the channel without a unilateral exit.  allow != 0 lifts the
   refusal for harnesses that exercise those ceremonies with real clients;
   it must never be set for a client holding real funds.  Off by default. */
void client_set_allow_tree_advance(int allow);

/* Set the LSP's static pubkey for NK (server-authenticated) noise handshake.
   If set (non-NULL), all future connections use Noise NK instead of NN.
   If NULL (default), falls back to NN with no server authentication. */
void client_set_lsp_pubkey(const secp256k1_pubkey *pubkey);

/* Set a slot hint to send in HELLO. Range 1..n_clients. 0 = no hint (default).
   When set, the LSP places this client at the requested slot in the keyagg
   array, making the funding address deterministic across restarts. */
void client_set_slot_hint(int slot_hint);

#endif /* SUPERSCALAR_CLIENT_H */
