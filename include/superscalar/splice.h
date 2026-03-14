#ifndef SUPERSCALAR_SPLICE_H
#define SUPERSCALAR_SPLICE_H

#include <stdint.h>
#include <stddef.h>
#include "channel.h"
#include "tx_builder.h"

/*
 * Channel splicing implementation (BOLT 2 draft).
 *
 * Flow:
 *   1. Both sides exchange MSG_STFU / MSG_STFU_ACK (quiescence)
 *   2. Initiator sends MSG_SPLICE_INIT (new funding amount + scriptPubKey)
 *   3. Acceptor sends MSG_SPLICE_ACK
 *   4. Both sign new 2-of-2 P2TR funding tx
 *   5. After confirmation: both send MSG_SPLICE_LOCKED
 *   6. channel_apply_splice_update() updates channel state
 *
 * Wire message types (in wire.h):
 *   0x68: MSG_STFU
 *   0x69: MSG_STFU_ACK
 *   0x6A: MSG_SPLICE_INIT
 *   0x6B: MSG_SPLICE_ACK
 *   0x6C: MSG_SPLICE_LOCKED
 */

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
