#ifndef SUPERSCALAR_SPLICE_H
#define SUPERSCALAR_SPLICE_H

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>
#include "channel.h"
#include "tx_builder.h"
#include "musig.h"
#include "peer_mgr.h"

/*
 * Channel splicing implementation (BOLT 2 §4.9 + CLN/Eclair/LDK implementations).
 *
 * Flow:
 *   1. Both sides exchange MSG_STFU / MSG_STFU_ACK (quiescence)
 *   2. Initiator sends splice_init (new funding amount + optional inputs)
 *   3. Acceptor sends splice_ack
 *   4. Both sign new 2-of-2 P2TR funding tx
 *   5. After confirmation: both send splice_locked
 *   6. channel_apply_splice_update() updates channel state
 *
 * Wire message types:
 *   0x68: MSG_STFU (legacy)
 *   0x69: MSG_STFU_ACK (legacy)
 *   140:  stfu (BOLT #2 quiescence, type 0x008C)
 *   141:  stfu_reply (BOLT #2 quiescence, type 0x008D)
 *   78:   splice_init
 *   79:   splice_ack
 *   80:   splice_locked
 */

/* Wire type numbers */
#define SPLICE_MSG_STFU          0x0068
#define SPLICE_MSG_STFU_ACK      0x0069
#define SPLICE_MSG_SPLICE_INIT   78
#define SPLICE_MSG_SPLICE_ACK    79
#define SPLICE_MSG_SPLICE_LOCKED 80
#define MSG_SPLICING_SIGNED      0x004b   /* mutual partial-sig exchange (BOLT #2 ss4.9) */

/* BOLT #2 quiescence handshake (latest spec, required for splice) */
#define BOLT2_STFU        140   /* 0x008C - quiescence request (BOLT #2 latest spec) */
#define BOLT2_STFU_REPLY  141   /* 0x008D - quiescence acknowledgement (BOLT #2 latest spec) */

/* Quiescence state */
#define SPLICE_STATE_NONE       0
#define SPLICE_STATE_STFU_SENT  1
#define SPLICE_STATE_QUIESCENT  2
#define SPLICE_STATE_PENDING    3  /* splice tx broadcast, waiting for confirm */

typedef struct {
    uint64_t      new_funding_amount;
    unsigned char new_funding_spk[34];    /* new P2TR scriptPubKey */
    size_t        new_funding_spk_len;
    int           initiator;              /* 1 if local side initiated */
} splice_init_t;

typedef struct {
    uint64_t      acceptor_contribution;  /* optional extra input from acceptor */
} splice_ack_t;

/*
 * Build a MSG_STFU payload (quiescence request).
 * channel_id: 4-byte channel identifier (LE).
 * Returns heap-allocated payload (caller must free), sets *len_out.
 */
unsigned char *splice_build_stfu(uint32_t channel_id, size_t *len_out);

/*
 * Parse a MSG_STFU_ACK payload.
 * Returns 1 if valid.
 */
int splice_parse_stfu_ack(const unsigned char *payload, size_t len,
                           uint32_t *channel_id_out);

/*
 * Build the splice funding transaction (2-input: old funding + optional extra).
 * Uses nVersion=2 (splice txs are not CPFP children).
 * out: tx_buf_t to write into (caller-initialised).
 * Returns 1 on success.
 */
int splice_build_funding_tx(tx_buf_t *out,
                              const unsigned char *old_funding_txid32,
                              uint32_t old_funding_vout,
                              uint64_t new_funding_amount,
                              const unsigned char *new_funding_spk34);

/*
 * Compute the 2-of-2 MuSig2 P2TR scriptPubKey for a splice funding output.
 * Returns 1 on success, 0 on failure.
 */
int splice_compute_funding_spk(const secp256k1_context *secp,
                                unsigned char spk34_out[34],
                                const secp256k1_pubkey *local_pubkey,
                                const secp256k1_pubkey *remote_pubkey);

/*
 * Build a splice_init wire message (type 78).
 *
 * channel_id32: 32-byte channel_id.
 * relative_satoshis: signed funding delta (positive = increase).
 * funding_feerate_perkw: on-chain fee rate for splice tx.
 * local_funding_pubkey33: our new funding pubkey (33 bytes).
 * buf: output buffer (at least 128 bytes).
 * Returns bytes written, or 0 on error.
 */
size_t splice_build_splice_init(const unsigned char channel_id32[32],
                                 int64_t relative_satoshis,
                                 uint32_t funding_feerate_perkw,
                                 const unsigned char local_funding_pubkey33[33],
                                 unsigned char *buf, size_t buf_cap);

/*
 * Parse a splice_init wire message (type 78).
 * Returns 1 on success.
 */
int splice_parse_splice_init(const unsigned char *msg, size_t msg_len,
                              unsigned char channel_id32_out[32],
                              int64_t *relative_satoshis_out,
                              uint32_t *feerate_out,
                              unsigned char funding_pubkey33_out[33]);

/*
 * Build a splice_ack wire message (type 79).
 * Returns bytes written.
 */
size_t splice_build_splice_ack(const unsigned char channel_id32[32],
                                int64_t relative_satoshis,
                                const unsigned char local_funding_pubkey33[33],
                                unsigned char *buf, size_t buf_cap);

/*
 * Build a splice_locked wire message (type 80).
 * splice_txid32: 32-byte txid of the confirmed splice transaction.
 * Returns bytes written.
 */
size_t splice_build_splice_locked(const unsigned char channel_id32[32],
                                   const unsigned char splice_txid32[32],
                                   unsigned char *buf, size_t buf_cap);

/*
 * Parse splice_locked wire message.
 * Returns 1 if valid.
 */
int splice_parse_splice_locked(const unsigned char *msg, size_t msg_len,
                                unsigned char channel_id32_out[32],
                                unsigned char splice_txid32_out[32]);

/*
 * Update a channel_t after the splice funding tx is confirmed.
 * new_txid32: internal-byte-order txid of the splice tx.
 * new_vout: output index of the new 2-of-2 output.
 * Returns 1 on success.
 */
int channel_apply_splice_update(channel_t *ch,
                                  const unsigned char *new_txid32,
                                  uint32_t new_vout,
                                  uint64_t new_funding_amount);

/* ---- BOLT #2 §4.9.2 Interactive Transaction Construction ---- */

/* Wire message types for dual-funding / splicing interactive tx */
#define MSG_TX_ADD_INPUT      66
#define MSG_TX_ADD_OUTPUT     67
#define MSG_TX_REMOVE_INPUT   68
#define MSG_TX_REMOVE_OUTPUT  69
#define MSG_TX_COMPLETE       70
#define MSG_TX_SIGNATURES     71

#define SPLICE_TX_MAX_SCRIPT  520  /* max scriptPubKey length */

/*
 * Build tx_add_input (type 66).
 * Wire: type(2)+channel_id(32)+serial_id(8)+prevtxid(32)+vout(4)+sequence(4) = 82 bytes
 */
size_t splice_build_tx_add_input(const unsigned char channel_id[32],
                                  uint64_t serial_id,
                                  const unsigned char prevtxid[32],
                                  uint32_t prevtx_vout,
                                  uint32_t sequence,
                                  unsigned char *buf, size_t buf_cap);

int splice_parse_tx_add_input(const unsigned char *msg, size_t msg_len,
                               unsigned char channel_id_out[32],
                               uint64_t *serial_id_out,
                               unsigned char prevtxid_out[32],
                               uint32_t *prevtx_vout_out,
                               uint32_t *sequence_out);

/*
 * Build tx_add_output (type 67).
 * Wire: type(2)+channel_id(32)+serial_id(8)+sats(8)+script_len(2)+script = 52+script_len
 */
size_t splice_build_tx_add_output(const unsigned char channel_id[32],
                                   uint64_t serial_id,
                                   uint64_t sats,
                                   const unsigned char *script,
                                   uint16_t script_len,
                                   unsigned char *buf, size_t buf_cap);

int splice_parse_tx_add_output(const unsigned char *msg, size_t msg_len,
                                unsigned char channel_id_out[32],
                                uint64_t *serial_id_out,
                                uint64_t *sats_out,
                                unsigned char *script_out,
                                uint16_t *script_len_out);

/*
 * Build tx_remove_input/output (type 68/69).
 * Wire: type(2)+channel_id(32)+serial_id(8) = 42 bytes
 */
size_t splice_build_tx_remove_input(const unsigned char channel_id[32],
                                     uint64_t serial_id,
                                     unsigned char *buf, size_t buf_cap);

size_t splice_build_tx_remove_output(const unsigned char channel_id[32],
                                      uint64_t serial_id,
                                      unsigned char *buf, size_t buf_cap);

int splice_parse_tx_remove(const unsigned char *msg, size_t msg_len,
                            uint16_t expected_type,
                            unsigned char channel_id_out[32],
                            uint64_t *serial_id_out);

/*
 * Build/parse tx_complete (type 70).
 * Wire: type(2)+channel_id(32) = 34 bytes
 */
size_t splice_build_tx_complete(const unsigned char channel_id[32],
                                 unsigned char *buf, size_t buf_cap);

int splice_parse_tx_complete(const unsigned char *msg, size_t msg_len,
                              unsigned char channel_id_out[32]);

/*
 * Build/parse tx_signatures (type 71).
 * Wire: type(2)+channel_id(32)+txid(32)+witness_len(2)+witness = 68+witness_len
 */
size_t splice_build_tx_signatures(const unsigned char channel_id[32],
                                   const unsigned char txid[32],
                                   const unsigned char *witness,
                                   uint16_t witness_len,
                                   unsigned char *buf, size_t buf_cap);

int splice_parse_tx_signatures(const unsigned char *msg, size_t msg_len,
                                unsigned char channel_id_out[32],
                                unsigned char txid_out[32],
                                unsigned char *witness_out,
                                uint16_t *witness_len_out);

/* Phase 4: parse_splice_ack + splicing_signed */
int splice_parse_splice_ack(const unsigned char *msg, size_t msg_len,
                              unsigned char channel_id32_out[32],
                              int64_t *relative_satoshis_out,
                              unsigned char pubkey_out[33]);

size_t splice_build_splicing_signed(const unsigned char channel_id[32],
                                     const unsigned char partial_sig64[64],
                                     unsigned char *buf, size_t buf_cap);

int splice_parse_splicing_signed(const unsigned char *msg, size_t msg_len,
                                  unsigned char channel_id_out[32],
                                  unsigned char partial_sig_out[64]);

/* ---- BOLT #2 Quiescence Handshake (types 140/141) ---- */

/*
 * Per-channel quiescence state (BOLT #2 §2.7).
 * Used by splice_send_stfu / splice_handle_stfu / splice_handle_stfu_reply.
 */
typedef enum {
    QUIESCE_NONE      = 0,  /* normal operation */
    QUIESCE_INITIATED = 1,  /* we sent stfu, waiting for stfu_reply */
    QUIESCE_RECEIVED  = 2,  /* peer sent stfu, we must reply */
    QUIESCE_ACTIVE    = 3,  /* both sides quiesced; safe to splice */
} quiesce_state_t;

typedef struct {
    unsigned char channel_id[32];
    quiesce_state_t state;
    int initiator;   /* 1 = we initiated, 0 = peer initiated */
} channel_quiesce_t;

/*
 * Send stfu (type 140) to peer to begin quiescence on channel_id.
 * Returns 0 on success, -1 on error.
 */
int splice_send_stfu(peer_mgr_t *pmgr, int peer_idx,
                     const unsigned char channel_id[32]);

/*
 * Handle incoming stfu (type 140) -- send stfu_reply (type 141) back.
 * If *qs_state == QUIESCE_INITIATED (cross-initiation), sets QUIESCE_ACTIVE
 * without sending a reply (both sides already sent stfu).
 * Returns 0 on success, -1 on error.
 */
int splice_handle_stfu(peer_mgr_t *pmgr, int peer_idx,
                       const unsigned char channel_id[32],
                       quiesce_state_t *qs_state);

/*
 * Handle incoming stfu_reply (type 141) -- marks channel as fully quiesced.
 * Returns 0 on success, -1 if not in QUIESCE_INITIATED state (unexpected).
 */
int splice_handle_stfu_reply(const unsigned char channel_id[32],
                              quiesce_state_t *qs_state);

#endif /* SUPERSCALAR_SPLICE_H */
