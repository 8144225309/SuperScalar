#include "superscalar/splice.h"
#include "superscalar/tx_builder.h"
#include "superscalar/sha256.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

unsigned char *splice_build_stfu(uint32_t channel_id, size_t *len_out)
{
    /* Simple 4-byte channel_id payload */
    unsigned char *buf = (unsigned char *)malloc(4);
    if (!buf) return NULL;
    buf[0] = (unsigned char)(channel_id & 0xff);
    buf[1] = (unsigned char)((channel_id >> 8) & 0xff);
    buf[2] = (unsigned char)((channel_id >> 16) & 0xff);
    buf[3] = (unsigned char)((channel_id >> 24) & 0xff);
    *len_out = 4;
    return buf;
}

int splice_parse_stfu_ack(const unsigned char *payload, size_t len,
                           uint32_t *channel_id_out)
{
    if (!payload || len < 4 || !channel_id_out) return 0;
    *channel_id_out = (uint32_t)payload[0]        |
                      ((uint32_t)payload[1] <<  8) |
                      ((uint32_t)payload[2] << 16) |
                      ((uint32_t)payload[3] << 24);
    return 1;
}

int splice_build_funding_tx(tx_buf_t *out,
                              const unsigned char *old_funding_txid32,
                              uint32_t old_funding_vout,
                              uint64_t new_funding_amount,
                              const unsigned char *new_funding_spk34)
{
    if (!out || !old_funding_txid32 || !new_funding_spk34) return 0;

    tx_buf_reset(out);

    /* nVersion = 2 (splice txs are not CPFP children) */
    tx_buf_write_u32_le(out, 2);
    /* 1 input: the old funding output */
    tx_buf_write_varint(out, 1);
    tx_buf_write_bytes(out, old_funding_txid32, 32);
    tx_buf_write_u32_le(out, old_funding_vout);
    tx_buf_write_varint(out, 0);             /* empty scriptSig */
    tx_buf_write_u32_le(out, 0xFFFFFFFD);    /* nSequence (RBF) */
    /* 1 output: new funding P2TR */
    tx_buf_write_varint(out, 1);
    tx_buf_write_u64_le(out, new_funding_amount);
    tx_buf_write_varint(out, 34);
    tx_buf_write_bytes(out, new_funding_spk34, 34);
    /* nLockTime = 0 */
    tx_buf_write_u32_le(out, 0);

    return !out->oom;
}

int channel_apply_splice_update(channel_t *ch,
                                  const unsigned char *new_txid32,
                                  uint32_t new_vout,
                                  uint64_t new_funding_amount)
{
    if (!ch || !new_txid32) return 0;

    memcpy(ch->funding_txid, new_txid32, 32);
    ch->funding_vout   = new_vout;
    ch->funding_amount = new_funding_amount;
    ch->channel_quiescent = 0;  /* splice complete, resume normal operation */
    memset(ch->splice_pending_txid, 0, 32);
    return 1;
}
