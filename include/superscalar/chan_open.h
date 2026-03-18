/*
 * chan_open.h — BOLT #2 channel establishment (open_channel / accept_channel)
 *               and channel_reestablish for external LN peers.
 *
 * Handles the full channel open flow:
 *   Outbound: open_channel → accept_channel → funding_created →
 *             funding_signed → channel_ready
 *   Inbound:  open_channel → accept_channel → funding_created →
 *             funding_signed → channel_ready
 *   Reconnect: channel_reestablish (BOLT #2 §3) with DLP detection.
 *
 * Spec: BOLT #2 §§2-3.
 * Reference: CLN openingd/openingd.c, LDK channel_establishment.
 */

#ifndef SUPERSCALAR_CHAN_OPEN_H
#define SUPERSCALAR_CHAN_OPEN_H

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>
#include "channel.h"
#include "peer_mgr.h"

/* BOLT #2 wire message types */
#define CHAN_MSG_OPEN_CHANNEL        32
#define CHAN_MSG_ACCEPT_CHANNEL      33
#define CHAN_MSG_FUNDING_CREATED     34
#define CHAN_MSG_FUNDING_SIGNED      35
#define CHAN_MSG_CHANNEL_READY       40
#define CHAN_MSG_REESTABLISH         136
#define CHAN_MSG_OPEN_CHANNEL2       78    /* dual-fund v2 */
#define CHAN_MSG_ACCEPT_CHANNEL2     79

/* Validation limits (CLN / LDK defaults) */
#define CHAN_OPEN_MAX_TO_SELF_DELAY  144   /* blocks (~1 day) */
#define CHAN_OPEN_MIN_DUST_LIMIT     546   /* satoshis (P2TR dust) */
#define CHAN_OPEN_MAX_RESERVE_RATIO  100   /* reserve ≤ funding / 100 */

/* Parameters for initiating a channel open */
typedef struct {
    uint64_t funding_sats;          /* channel capacity */
    uint64_t push_msat;             /* initial balance to push to peer */
    uint32_t feerate_per_kw;        /* on-chain fee rate */
    uint32_t to_self_delay;         /* CSV delay for local outputs */
    uint64_t max_htlc_value_msat;   /* max in-flight */
    uint64_t channel_reserve_sats;  /* minimum balance */
    uint64_t htlc_minimum_msat;     /* minimum HTLC size */
    uint16_t max_accepted_htlcs;    /* default 483 */
    int      announce_channel;      /* 1 = public channel */
    int      zero_conf;             /* 1 = send minimum_depth=0 (LSPS2 / Phoenix compat) */
    /* Local channel keys (from channel_t) */
    unsigned char funding_pubkey[33];
    unsigned char revocation_basepoint[33];
    unsigned char payment_basepoint[33];
    unsigned char delayed_payment_basepoint[33];
    unsigned char htlc_basepoint[33];
    unsigned char first_per_commitment_point[33];
} chan_open_params_t;

/*
 * Initiate a channel open to peer peer_idx.
 * Sends open_channel, waits for accept_channel, builds funding tx,
 * sends funding_created, waits for funding_signed, then
 * waits for channel_ready.
 *
 * ch_out: initialised channel_t on success.
 * Returns 1 on success, 0 on failure.
 */
int chan_open_outbound(peer_mgr_t *mgr, int peer_idx,
                       const chan_open_params_t *params,
                       secp256k1_context *ctx,
                       channel_t *ch_out);

/*
 * Process an inbound open_channel message from peer peer_idx.
 * open_msg: raw BOLT #2 open_channel payload (excluding 2-byte type).
 * open_len: payload length.
 * Sends accept_channel, waits for funding_created, sends funding_signed,
 * waits for channel_ready.
 *
 * ch_out: initialised channel_t on success.
 * Returns 1 on success, 0 on failure.
 */
int chan_open_inbound(peer_mgr_t *mgr, int peer_idx,
                      const unsigned char *open_msg, size_t open_len,
                      secp256k1_context *ctx,
                      channel_t *ch_out);

/*
 * Handle channel_reestablish after reconnect (BOLT #2 §3).
 * Exchanges next_commitment_number and next_revocation_number.
 * Triggers force-close if DLP (data loss protection) detected.
 *
 * Returns 1 if channel is in sync, 0 if force-close initiated.
 */
int chan_reestablish(peer_mgr_t *mgr, int peer_idx,
                     secp256k1_context *ctx,
                     channel_t *ch);

/*
 * Build a raw open_channel message payload.
 * Fills buf (caller supplies; at least 300 bytes).
 * Returns number of bytes written, or 0 on error.
 */
size_t chan_build_open_channel(const unsigned char chain_hash[32],
                               const unsigned char temp_chan_id[32],
                               const chan_open_params_t *p,
                               unsigned char *buf, size_t buf_cap);

/*
 * Build a raw accept_channel message payload.
 * Returns bytes written.
 */
size_t chan_build_accept_channel(const unsigned char temp_chan_id[32],
                                 const chan_open_params_t *p,
                                 unsigned char *buf, size_t buf_cap);

/*
 * Process an inbound open_channel2 message (type 78, BOLT #2 v2 dual-fund).
 * Zero-contribution mode: we accept with no funding input of our own.
 * Sends accept_channel2 (type 79) with funding_satoshis=0.
 * msg includes the 2-byte type prefix (type 78).
 * Returns 1 on success, 0 on validation failure.
 */
int chan_open_inbound_v2(peer_mgr_t *mgr, int peer_idx,
                          const unsigned char *msg, size_t msg_len,
                          secp256k1_context *ctx,
                          channel_t *ch_out);

#endif /* SUPERSCALAR_CHAN_OPEN_H */
