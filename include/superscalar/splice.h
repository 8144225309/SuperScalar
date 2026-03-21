#ifndef SUPERSCALAR_SPLICE_H
#define SUPERSCALAR_SPLICE_H

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>
#include "channel.h"
#include "tx_builder.h"
#include "musig.h"

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
 *   0x68: MSG_STFU
 *   0x69: MSG_STFU_ACK
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
#define MSG_SPLICING_SIGNED      0x004b   /* mutual partial-sig exchange (BOLT #2 §4.9) */

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
 * Parse a splice_ack wire message (type 79).
 * Symmetric to splice_build_splice_ack.
 * Returns 1 on success.
 */
int splice_parse_splice_ack(const unsigned char *msg, size_t msg_len,
                              unsigned char channel_id32_out[32],
                              int64_t *relative_satoshis_out,
                              unsigned char pubkey_out[33]);

/*
 * Build a splicing_signed wire message (type 0x004b).
 * type(2) + channel_id(32) + partial_sig(64) = 98 bytes.
 * Returns bytes written, or 0 on error.
 */
size_t splice_build_splicing_signed(const unsigned char channel_id[32],
                                     const unsigned char partial_sig64[64],
                                     unsigned char *buf, size_t buf_cap);

/*
 * Parse a splicing_signed wire message (type 0x004b).
 * Returns 1 on success.
 */
int splice_parse_splicing_signed(const unsigned char *msg, size_t msg_len,
                                  unsigned char channel_id_out[32],
                                  unsigned char partial_sig_out[64]);

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


/* ---- Interactive Transaction Construction (BOLT #2 §4.9.2) ---- */
/* Reference: CLN dual_open_control.c, LDK channel.rs, Eclair ChannelTypes.scala */

#define MSG_TX_ADD_INPUT      66  /* 0x0042 */
#define MSG_TX_ADD_OUTPUT     67  /* 0x0043 */
#define MSG_TX_REMOVE_INPUT   68  /* 0x0044 */
#define MSG_TX_REMOVE_OUTPUT  69  /* 0x0045 */
#define MSG_TX_COMPLETE       70  /* 0x0046 */
#define MSG_TX_SIGNATURES     71  /* 0x0047 */

#define SPLICE_TX_MAX_SCRIPT  35

/*
 * Build tx_add_input (type 66).
 * Simplified: uses prevtxid(32) instead of the full serialized prev tx.
 * Wire: type(2) + channel_id(32) + serial_id(8) + prevtxid(32) +
 *        prevtx_vout(4) + sequence(4) = 82 bytes.
 * Returns bytes written, or 0 on error.
 */
size_t splice_build_tx_add_input(const unsigned char channel_id[32],
                                  uint64_t serial_id,
                                  const unsigned char prevtxid[32],
                                  uint32_t prevtx_vout, uint32_t sequence,
                                  unsigned char *buf, size_t buf_cap);

/* Parse tx_add_input (type 66). Returns 1 on success. */
int splice_parse_tx_add_input(const unsigned char *msg, size_t msg_len,
                               unsigned char channel_id_out[32],
                               uint64_t *serial_id_out,
                               unsigned char prevtxid_out[32],
                               uint32_t *prevtx_vout_out,
                               uint32_t *sequence_out);

/*
 * Build tx_add_output (type 67).
 * Wire: type(2) + channel_id(32) + serial_id(8) + sats(8) +
 *        script_len(2) + script(var).
 * Returns bytes written, or 0 on error.
 */
size_t splice_build_tx_add_output(const unsigned char channel_id[32],
                                   uint64_t serial_id, uint64_t sats,
                                   const unsigned char *script,
                                   uint16_t script_len,
                                   unsigned char *buf, size_t buf_cap);

/* Parse tx_add_output (type 67). Returns 1 on success. */
int splice_parse_tx_add_output(const unsigned char *msg, size_t msg_len,
                                unsigned char channel_id_out[32],
                                uint64_t *serial_id_out,
                                uint64_t *sats_out,
                                unsigned char *script_out,
                                uint16_t *script_len_out);

/*
 * Build tx_remove_input (type 68).
 * Wire: type(2) + channel_id(32) + serial_id(8) = 42 bytes.
 */
size_t splice_build_tx_remove_input(const unsigned char channel_id[32],
                                     uint64_t serial_id,
                                     unsigned char *buf, size_t buf_cap);

/*
 * Build tx_remove_output (type 69).
 * Wire: type(2) + channel_id(32) + serial_id(8) = 42 bytes.
 */
size_t splice_build_tx_remove_output(const unsigned char channel_id[32],
                                      uint64_t serial_id,
                                      unsigned char *buf, size_t buf_cap);

/*
 * Parse tx_remove_input or tx_remove_output (types 68/69).
 * Returns 1 on success.
 */
int splice_parse_tx_remove(const unsigned char *msg, size_t msg_len,
                            uint16_t expected_type,
                            unsigned char channel_id_out[32],
                            uint64_t *serial_id_out);

/*
 * Build tx_complete (type 70).
 * Wire: type(2) + channel_id(32) = 34 bytes.
 */
size_t splice_build_tx_complete(const unsigned char channel_id[32],
                                 unsigned char *buf, size_t buf_cap);

/* Parse tx_complete (type 70). Returns 1 on success. */
int splice_parse_tx_complete(const unsigned char *msg, size_t msg_len,
                              unsigned char channel_id_out[32]);

/*
 * Build tx_signatures (type 71).
 * Wire: type(2) + channel_id(32) + txid(32) + wit_len(2) + witness(var).
 * Returns bytes written, or 0 on error.
 */
size_t splice_build_tx_signatures(const unsigned char channel_id[32],
                                   const unsigned char txid[32],
                                   const unsigned char *witness,
                                   uint16_t witness_len,
                                   unsigned char *buf, size_t buf_cap);

/* Parse tx_signatures (type 71). Returns 1 on success. */
int splice_parse_tx_signatures(const unsigned char *msg, size_t msg_len,
                                unsigned char channel_id_out[32],
                                unsigned char txid_out[32],
                                unsigned char *witness_out,
                                uint16_t *witness_len_out);

#endif /* SUPERSCALAR_SPLICE_H */
