#ifndef SUPERSCALAR_CLIENT_H
#define SUPERSCALAR_CLIENT_H

#include "channel.h"
#include "factory.h"
#include "fee_estimator.h"
#include "persist.h"
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

/* Optional callback to verify the funding TX on-chain before signing the
   factory tree.  If provided to client_run_with_channels, called after
   FACTORY_PROPOSE is parsed and before any tree signing.  Return 1 if the
   funding TX at txid:vout has at least expected_sats, 0 to abort.
   ctx is the opaque pointer passed alongside the callback. */
typedef int (*client_verify_funding_fn)(const unsigned char *txid32,
                                         uint32_t vout,
                                         uint64_t expected_sats,
                                         void *ctx);

/* Run the full ceremony with optional channel operations.
   If channel_cb is NULL, behaves identically to client_run_ceremony
   (creates factory then immediately closes).
   If channel_cb is non-NULL, calls it after CHANNEL_READY and before close.
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

/* 1 if the database set with client_set_persist shows, or cannot rule out,
   that this client has signed a cooperative close of the factory. */
int client_close_signed_for_factory(const factory_t *factory);

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
   Returns 1 on success. */
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
int client_handle_commitment_signed(int fd, channel_t *ch,
                                      secp256k1_context *ctx,
                                      const wire_msg_t *msg);

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

   PS double-spend defense: if client_set_persist() has been called with
   a non-NULL handle, the PS advance path consults client_ps_signed_inputs
   before signing and REFUSES if this client has already co-signed a TX
   spending the same (parent_txid, parent_vout). See ZmnSCPxj §"Pseudo-
   Spilman wide leaves" — PS has no revocation, so the client's refusal
   is the only thing preventing an LSP double-spend. When no persist is
   set, the defense is skipped (tests / in-process usage only — real
   clients must call client_set_persist at startup). */
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
   PSIG → waits for DONE.  Returns 1 on success, 0 on any failure. */
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

/* Set the LSP's static pubkey for NK (server-authenticated) noise handshake.
   If set (non-NULL), all future connections use Noise NK instead of NN.
   If NULL (default), falls back to NN with no server authentication. */
void client_set_lsp_pubkey(const secp256k1_pubkey *pubkey);

/* Set a slot hint to send in HELLO. Range 1..n_clients. 0 = no hint (default).
   When set, the LSP places this client at the requested slot in the keyagg
   array, making the funding address deterministic across restarts. */
void client_set_slot_hint(int slot_hint);

#endif /* SUPERSCALAR_CLIENT_H */
