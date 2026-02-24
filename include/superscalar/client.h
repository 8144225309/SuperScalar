#ifndef SUPERSCALAR_CLIENT_H
#define SUPERSCALAR_CLIENT_H

#include "channel.h"
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

/* Run the full ceremony with optional channel operations.
   If channel_cb is NULL, behaves identically to client_run_ceremony
   (creates factory then immediately closes).
   If channel_cb is non-NULL, calls it after CHANNEL_READY and before close. */
int client_run_with_channels(secp256k1_context *ctx,
                              const secp256k1_keypair *keypair,
                              const char *host, int port,
                              client_channel_cb_t channel_cb,
                              void *user_data);

/* Perform the cooperative close ceremony on an already-received CLOSE_PROPOSE.
   If initial_msg is non-NULL, it is the already-received CLOSE_PROPOSE message;
   otherwise we recv it from the wire.
   Returns 1 on success. */
int client_do_close_ceremony(int fd, secp256k1_context *ctx,
                               const secp256k1_keypair *keypair,
                               const secp256k1_pubkey *my_pubkey,
                               factory_t *factory,
                               size_t n_participants,
                               const wire_msg_t *initial_msg);

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

/* Handle incoming ADD_HTLC from LSP (we are the payee).
   Returns 1 on success. */
int client_handle_add_htlc(channel_t *ch, const wire_msg_t *msg);

/* Send FULFILL_HTLC to LSP (reveal preimage for received HTLC).
   Returns 1 on success. */
int client_fulfill_payment(int fd, channel_t *ch,
                             uint64_t htlc_id,
                             const unsigned char *preimage32);

#endif /* SUPERSCALAR_CLIENT_H */
