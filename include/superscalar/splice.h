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

#endif /* SUPERSCALAR_SPLICE_H */
