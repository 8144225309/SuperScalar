#ifndef SUPERSCALAR_CLIENT_ROTATION_H
#define SUPERSCALAR_CLIENT_ROTATION_H

/* Client side of a rotation by a co-signed close into the new factory
   (every old client online).  Nothing is revealed: the client sends a fresh
   factory key, checks the replacement (its funding is the old factory's
   close, rebuilt here from the old factory), signs the replacement tree,
   gets its channel and an LSP-signed initial commitment, stores all of it in
   a side DB, and only then signs the close with its old key.  The side DB
   becomes the main DB once the client's own chain source shows the close at
   the safe depth; until then the old factory stays the live one (watched,
   and frozen once the close may be signed). */

#include <stdint.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include "superscalar/persist.h"
#include "superscalar/factory.h"
#include "superscalar/channel.h"
#include "superscalar/wire.h"
#include "superscalar/regtest.h"
#include "superscalar/client.h"

/* Whether this client announces "rotation_v": it needs a DB, a pinned LSP
   context and its own chain source (set once at startup). */
void client_cin_set_capable(int capable);
int client_cin_capable(void);

/* The chain source used to check the close (its height and confirmations)
   and the depth at which the switch happens. */
void client_cin_set_chain(regtest_t *rt, int safe_depth);
int client_cin_safe_depth(void);

/* 1 while a signed close of the old factory may exist (state close_signed):
   the old channel takes no payment and no other rotation until the close
   resolves.  Refreshed from the DB at startup and on a switch. */
int client_cin_frozen(void);
void client_cin_refresh_frozen(persist_t *db);
/* Frozen for the factory funded by FUNDING_TXID32 (internal order; NULL:
   any factory). */
int client_cin_frozen_for(const unsigned char *funding_txid32);

/* While frozen for the factory FUNDING_TXID32 (NULL: any): 1 if message M
   must be refused (an incoming HTLC, a PTLC key turnover, or any rotation
   that is not the close into the new factory already in progress). */
int client_cin_refuse_while_frozen(const wire_msg_t *m, const unsigned char *funding_txid32);

/* The index of the factory key KP in DB's key rows (1 found). */
int client_key_index_of(persist_t *db, secp256k1_context *ctx, const secp256k1_keypair *kp,
                        uint32_t *idx_out);

/* The client's own view of a signed rotation ROW: confirmations of the close
   (CLOSE_CONFS) and of another transaction spending the old funding
   (OTHER_CONFS), each -1 if not seen.  Works without txindex and after any
   absence: the wallet / txindex / recent blocks first, then the close's
   output in the UTXO set, then the transactions it knows by txid (the
   replacement's tree in the side DB; the old tree's root and distribution
   TX in DB), then the blocks from the close's height (pruned blocks are
   skipped with a warning). */
void client_cin_chain_view(regtest_t *rt, persist_t *db,
                           const persist_client_rotation_t *row,
                           int *close_confs, int *other_confs);

/* 1 if OLD_F's funding output is unspent on RT (a rotation is refused
   otherwise). */
int client_cin_old_funding_unspent(regtest_t *rt, const factory_t *old_f);

/* The one gate for the old PTLC key turnover, wherever a message is
   received: a new client never completes it (it would reveal the key it
   signs its factory with).  A PTLC_PRESIG is answered with MSG_ERROR.
   Returns 1 if M is a turnover message (the caller drops it). */
int client_refuse_key_turnover(int fd, const wire_msg_t *m);

/* Receive until a message of type EXPECTED arrives (1) or TIMEOUT_SEC pass /
   the connection fails / MSG_ERROR arrives (0), inside a payment flow.
   Turnover messages are refused (client_refuse_key_turnover); every other
   message, a rotation begin included, is handed to QUEUE (which takes its
   JSON) for the daemon loop, or dropped if QUEUE is NULL. */
typedef void (*client_queue_fn)(void *arg, const wire_msg_t *m);
int client_recv_expected(int fd, wire_msg_t *msg, int timeout_sec, uint8_t expected,
                         client_queue_fn queue, void *queue_arg);

/* The close's nLockTime height is not in the future: at most TIP + 1. */
int client_cin_check_close_height(uint32_t close_height, int tip);

/* Digest (hex) of a replacement tree: every node's unsigned transaction. */
int client_cin_tree_digest(const factory_t *f, char out_hex[65]);

/* Bind tree F to the replacement funding CLOSE_TXID (display hex): 1 if F is
   the first tree signed over it, or the same tree again; 0 if a different
   tree was signed over it before (or on error). */
int client_cin_bind_tree(persist_t *db, const char *close_txid, const factory_t *f);

/* MSG_ROTATION_BEGIN {"v":1,"mode":"close_into_new"}: reserve (or, for a
   retry of the same old factory, reuse) the replacement's factory key and
   answer MSG_ROTATION_KEY.  Needs DB and the identity keypair / LSP context
   set in client.h.  Returns 1 if the key was sent. */
/* 1 if the old channel has no HTLC in flight (a rotation is refused
   otherwise: the replacement carries the old balances). */
int client_cin_channel_quiet(const channel_t *ch);

int client_cin_on_begin(int fd, secp256k1_context *ctx, persist_t *db,
                        const factory_t *old_f, const channel_t *old_ch,
                        const cJSON *begin);

/* MSG_FACTORY_PROPOSE carrying "rotation": {"mode":"close_into_new"}.  Runs
   the whole client side up to MSG_ROTATION_DONE.  OLD_KP is the old
   factory's key.  Every tree signed over a close is bound to it: a re-run
   over the same close signs only the same tree.  Returns 1 when our chain
   source shows the close at the safe depth (the caller reconnects after
   client_cin_resolve promotes the side DB), 0 otherwise (the old factory
   stays the live one). */
int client_cin_run(int fd, secp256k1_context *ctx, persist_t *db, const char *db_path,
                   const secp256k1_keypair *old_kp, factory_t *old_f, channel_t *old_ch,
                   uint32_t my_index, const wire_msg_t *propose);

/* Startup / before a reconnect: act on an open rotation row (broadcast a
   known signed close, or make the side DB the main DB once RT shows the
   close at the safe depth; a stored replacement is never dropped while the
   old factory is unresolved; once RT shows the old funding spent at the safe
   depth by another transaction the row is abandoned and the freeze lifted).  RT NULL: nothing is promoted.  Returns 1 if
   the DB was replaced (the caller chooses its factory key again). */
int client_cin_resolve(persist_t *db, const char *db_path, regtest_t *rt);

/* RECONNECT: add "rotation_v" and, while a signed close is pending,
   "rotation_pending": its txid. */
void client_cin_reconnect_fields(persist_t *db, cJSON *reconnect);

/* MSG_ROTATION_DONE received on reconnect: keep the signed close if its txid
   is the pending close's (the LSP's "confirmed" is only a hint).  Returns 1
   if it matched the pending rotation. */
int client_cin_on_rotation_done(persist_t *db, const cJSON *done);

typedef enum {
    CLIENT_CIN_NONE = 0,
    CLIENT_CIN_WAIT,           /* signed; close not at the safe depth, nothing to send */
    CLIENT_CIN_BROADCAST,      /* signed; we hold the signed close: send it */
    CLIENT_CIN_PROMOTE,        /* the close is at the safe depth: side DB -> main DB */
} client_cin_action_t;

/* CLOSE_CONFS: confirmations of the close on the client's own chain source
   (-1 unknown). */
client_cin_action_t client_cin_resolve_action(const char *state, int close_confs,
                                              int has_close_hex);

/* Check a proposed replacement before signing anything: PKS (n, LSP first)
   hold the old LSP key first and no key of the old factory; FUNDING_SPK is
   their aggregate key; the funding is output 0 of the old factory's close
   rebuilt here (paying FUNDING_AMOUNT at CLOSE_HEIGHT) and FUNDING_TXID32
   (internal order) is its txid; the close fee is below 2% of the old funding.
   Returns 1 if acceptable; otherwise 0 with a reason in WHY. */
int client_cin_check_close(const secp256k1_context *ctx, const factory_t *old_f,
                           const secp256k1_pubkey *pks, size_t n,
                           const unsigned char *funding_spk, size_t spk_len,
                           uint64_t funding_amount, uint32_t funding_vout,
                           const unsigned char funding_txid32[32], uint32_t close_height,
                           const char **why);

/* --- Partial rotation with verified release ("rotation_v" 2) ---
   MSG_FACTORY_PROPOSE carrying "rotation": {"mode":"partial", "pubkeys": the
   LSP and the fresh keys of the clients moving}.  Signs the replacement over
   the LSP's (unbroadcast) funding with the same checks as a close into the
   new factory, stores it, and on MSG_ROTATION_RELEASE_REQ releases the old
   factory key only if: the funding is confirmed at the safe depth on our
   chain with the proposed amount and script, the binding is exactly our
   position and the LSP's receipt over it verifies, the old key is a
   per-factory key bound to this LSP (never the identity key), no JIT
   channel is open, and the old channel is unchanged.  "released" is written
   before the key is sent.  Returns 1 once released (client_cin_resolve then
   makes the side DB the main DB before the reconnect). */
int client_part_run(int fd, secp256k1_context *ctx, persist_t *db, const char *db_path,
                    const secp256k1_keypair *old_kp, factory_t *old_f, channel_t *old_ch,
                    const wire_msg_t *propose);

/* The release decision for a MSG_ROTATION_RELEASE_REQ (REQ_TXID32,
   REQ_BINDING32, RECEIPT64): NULL if the old key may be released (then
   BINDING_OUT32 is our own binding and *OLD_IDX_OUT the old key's index),
   else the reason.  NF is the replacement we signed, BIND its funding, NPK
   and SLOT our key and slot there, CARRIED our verified balance in it,
   LSP_PK the LSP's key. */
const char *client_part_release_check(regtest_t *rt, persist_t *db, secp256k1_context *ctx,
                                      const factory_t *old_f, const secp256k1_pubkey *lsp_pk,
                                      const secp256k1_keypair *old_kp, const channel_t *old_ch,
                                      const factory_t *nf, const client_funding_bind_t *bind,
                                      const secp256k1_pubkey *npk, uint32_t slot,
                                      uint64_t carried, const unsigned char req_txid32[32],
                                      const unsigned char req_binding32[32],
                                      const unsigned char receipt64[64],
                                      unsigned char binding_out32[32], uint32_t *old_idx_out);

/* MSG_ROTATION_RELEASE_REQ received later (after the switch to the funded
   replacement F, which is our factory now): the same release checks, with
   the old key and carried balance from the rotation row.  Returns 1 if the
   key was released. */
int client_part_on_release_req(int fd, secp256k1_context *ctx, persist_t *db,
                               const factory_t *f, const cJSON *req);

/* 1 if REQ (a release request) is for a partial rotation we signed whose
   funding is now at the safe depth on our own chain, but we still run the
   old factory: the client ends the session, switches (client_cin_resolve)
   and is asked again after it reconnects. */
int client_part_switch_due(persist_t *db, const cJSON *req);

/* Whether a JIT channel is open (its key must not be released with the
   factory key). */
void client_part_set_jit_active(int active);

/* 1 if OLD_KP may be released: not the identity key, and a factory-key row
   with a non-zero (pinned) LSP context; *IDX_OUT gets its index. */
int client_part_key_releasable(persist_t *db, secp256k1_context *ctx,
                               const secp256k1_keypair *old_kp, uint32_t *idx_out);

/* 1 if OLD_KP is this client's key in OLD_F (a participant other than the
   LSP) and may be released (client_part_key_releasable); *IDX_OUT gets its
   index and PUB_HEX_OUT its compressed pubkey (hex).  A partial rotation is
   refused before anything is signed otherwise. */
int client_part_old_key_ok(persist_t *db, secp256k1_context *ctx,
                           const secp256k1_keypair *old_kp, const factory_t *old_f,
                           uint32_t *idx_out, char pub_hex_out[67]);

/* 1 if TXID32:VOUT (internal order) is in RT's UTXO set at the safe depth,
   paying AMOUNT to SPK34. */
int client_part_funding_confirmed(regtest_t *rt, const unsigned char txid32[32], uint32_t vout,
                                  uint64_t amount, const unsigned char spk34[34]);

#endif /* SUPERSCALAR_CLIENT_ROTATION_H */
