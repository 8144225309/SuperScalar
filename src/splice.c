#include "superscalar/splice.h"
#include "superscalar/tx_builder.h"
#include "superscalar/musig.h"
#include "superscalar/sha256.h"
#include <secp256k1_extrakeys.h>
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

int splice_compute_funding_spk(const secp256k1_context *secp,
                                unsigned char spk34_out[34],
                                const secp256k1_pubkey *local_pubkey,
                                const secp256k1_pubkey *remote_pubkey)
{
    if (!secp || !spk34_out || !local_pubkey || !remote_pubkey) return 0;

    /* Aggregate local + remote keys into a single MuSig2 internal key */
    secp256k1_pubkey pks[2] = { *local_pubkey, *remote_pubkey };
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(secp, &ka, pks, 2)) return 0;

    /* BIP 341 key-path tweak: tag_hash("TapTweak", internal_key_bytes) */
    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(secp, internal_ser, &ka.agg_pubkey)) return 0;

    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);

    secp256k1_pubkey tweaked_full;
    if (!secp256k1_xonly_pubkey_tweak_add(secp, &tweaked_full, &ka.agg_pubkey, tweak))
        return 0;

    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(secp, &tweaked_xonly, NULL, &tweaked_full))
        return 0;

    /* OP_1 <32-byte-x-only-key> */
    build_p2tr_script_pubkey(spk34_out, &tweaked_xonly);
    return 1;
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

/* ---- Splice wire protocol completion (Phase 5) ---- */

static void put_u16_be(unsigned char *b, uint16_t v) {
    b[0] = (unsigned char)(v >> 8);
    b[1] = (unsigned char)(v);
}
static void put_u32_be(unsigned char *b, uint32_t v) {
    b[0] = (unsigned char)(v >> 24); b[1] = (unsigned char)(v >> 16);
    b[2] = (unsigned char)(v >>  8); b[3] = (unsigned char)(v);
}
static void put_i64_be(unsigned char *b, int64_t v) {
    for (int i = 7; i >= 0; i--) b[7-i] = (unsigned char)((uint64_t)v >> (i*8));
}
static uint16_t get_u16_be(const unsigned char *b) {
    return ((uint16_t)b[0] << 8) | b[1];
}
static int64_t get_i64_be(const unsigned char *b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return (int64_t)v;
}
static uint32_t get_u32_be(const unsigned char *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
         | ((uint32_t)b[2] <<  8) |  (uint32_t)b[3];
}

size_t splice_build_splice_init(const unsigned char channel_id32[32],
                                 int64_t relative_satoshis,
                                 uint32_t funding_feerate_perkw,
                                 const unsigned char local_funding_pubkey33[33],
                                 unsigned char *buf, size_t buf_cap)
{
    /* type(2) + channel_id(32) + relative_satoshis(8) + feerate(4) +
       funding_pubkey(33) = 79 bytes */
    if (buf_cap < 79) return 0;
    size_t pos = 0;
    put_u16_be(buf + pos, SPLICE_MSG_SPLICE_INIT); pos += 2;
    memcpy(buf + pos, channel_id32, 32); pos += 32;
    put_i64_be(buf + pos, relative_satoshis); pos += 8;
    put_u32_be(buf + pos, funding_feerate_perkw); pos += 4;
    memcpy(buf + pos, local_funding_pubkey33, 33); pos += 33;
    return pos;
}

int splice_parse_splice_init(const unsigned char *msg, size_t msg_len,
                              unsigned char channel_id32_out[32],
                              int64_t *relative_satoshis_out,
                              uint32_t *feerate_out,
                              unsigned char funding_pubkey33_out[33])
{
    if (!msg || msg_len < 79) return 0;
    if (get_u16_be(msg) != SPLICE_MSG_SPLICE_INIT) return 0;
    if (channel_id32_out) memcpy(channel_id32_out, msg + 2, 32);
    if (relative_satoshis_out) *relative_satoshis_out = get_i64_be(msg + 34);
    if (feerate_out) *feerate_out = get_u32_be(msg + 42);
    if (funding_pubkey33_out) memcpy(funding_pubkey33_out, msg + 46, 33);
    return 1;
}

size_t splice_build_splice_ack(const unsigned char channel_id32[32],
                                int64_t relative_satoshis,
                                const unsigned char local_funding_pubkey33[33],
                                unsigned char *buf, size_t buf_cap)
{
    /* type(2) + channel_id(32) + relative_satoshis(8) + funding_pubkey(33) = 75 */
    if (buf_cap < 75) return 0;
    size_t pos = 0;
    put_u16_be(buf + pos, SPLICE_MSG_SPLICE_ACK); pos += 2;
    memcpy(buf + pos, channel_id32, 32); pos += 32;
    put_i64_be(buf + pos, relative_satoshis); pos += 8;
    memcpy(buf + pos, local_funding_pubkey33, 33); pos += 33;
    return pos;
}

size_t splice_build_splice_locked(const unsigned char channel_id32[32],
                                   const unsigned char splice_txid32[32],
                                   unsigned char *buf, size_t buf_cap)
{
    /* type(2) + channel_id(32) + splice_txid(32) = 66 */
    if (buf_cap < 66) return 0;
    size_t pos = 0;
    put_u16_be(buf + pos, SPLICE_MSG_SPLICE_LOCKED); pos += 2;
    memcpy(buf + pos, channel_id32, 32); pos += 32;
    memcpy(buf + pos, splice_txid32, 32); pos += 32;
    return pos;
}

int splice_parse_splice_locked(const unsigned char *msg, size_t msg_len,
                                unsigned char channel_id32_out[32],
                                unsigned char splice_txid32_out[32])
{
    if (!msg || msg_len < 66) return 0;
    if (get_u16_be(msg) != SPLICE_MSG_SPLICE_LOCKED) return 0;
    if (channel_id32_out) memcpy(channel_id32_out, msg + 2, 32);
    if (splice_txid32_out) memcpy(splice_txid32_out, msg + 34, 32);
    return 1;
}

/* ---- Phase 4 additions: parse_splice_ack + splicing_signed ---- */

int splice_parse_splice_ack(const unsigned char *msg, size_t msg_len,
                              unsigned char channel_id32_out[32],
                              int64_t *relative_satoshis_out,
                              unsigned char pubkey_out[33])
{
    /* type(2) + channel_id(32) + relative_satoshis(8) + funding_pubkey(33) = 75 */
    if (!msg || msg_len < 75) return 0;
    if (get_u16_be(msg) != SPLICE_MSG_SPLICE_ACK) return 0;
    if (channel_id32_out)       memcpy(channel_id32_out, msg + 2, 32);
    if (relative_satoshis_out)  *relative_satoshis_out = get_i64_be(msg + 34);
    if (pubkey_out)             memcpy(pubkey_out, msg + 42, 33);
    return 1;
}

size_t splice_build_splicing_signed(const unsigned char channel_id[32],
                                     const unsigned char partial_sig64[64],
                                     unsigned char *buf, size_t buf_cap)
{
    /* type(2) + channel_id(32) + partial_sig(64) = 98 bytes */
    if (buf_cap < 98) return 0;
    size_t pos = 0;
    put_u16_be(buf + pos, MSG_SPLICING_SIGNED); pos += 2;
    memcpy(buf + pos, channel_id, 32);          pos += 32;
    memcpy(buf + pos, partial_sig64, 64);        pos += 64;
    return pos;
}

int splice_parse_splicing_signed(const unsigned char *msg, size_t msg_len,
                                  unsigned char channel_id_out[32],
                                  unsigned char partial_sig_out[64])
{
    if (!msg || msg_len < 98) return 0;
    if (get_u16_be(msg) != MSG_SPLICING_SIGNED) return 0;
    if (channel_id_out)   memcpy(channel_id_out,   msg + 2,  32);
    if (partial_sig_out)  memcpy(partial_sig_out,  msg + 34, 64);
    return 1;
}

/* ---- Interactive Transaction Construction (BOLT #2 §4.9.2) ---- */

static void put_u64_be(unsigned char *b, uint64_t v) {
    for (int i = 7; i >= 0; i--) b[7-i] = (unsigned char)(v >> (i*8));
}
static uint64_t get_u64_be(const unsigned char *b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

/* tx_add_input (type 66): type(2)+cid(32)+serial(8)+txid(32)+vout(4)+seq(4)=82 */
size_t splice_build_tx_add_input(const unsigned char channel_id[32],
                                  uint64_t serial_id,
                                  const unsigned char prevtxid[32],
                                  uint32_t prevtx_vout, uint32_t sequence,
                                  unsigned char *buf, size_t buf_cap)
{
    if (!channel_id || !prevtxid || !buf || buf_cap < 82) return 0;
    size_t pos = 0;
    put_u16_be(buf + pos, (uint16_t)MSG_TX_ADD_INPUT); pos += 2;
    memcpy(buf + pos, channel_id, 32); pos += 32;
    put_u64_be(buf + pos, serial_id); pos += 8;
    memcpy(buf + pos, prevtxid, 32); pos += 32;
    put_u32_be(buf + pos, prevtx_vout); pos += 4;
    put_u32_be(buf + pos, sequence); pos += 4;
    return pos;
}

int splice_parse_tx_add_input(const unsigned char *msg, size_t msg_len,
                               unsigned char channel_id_out[32],
                               uint64_t *serial_id_out,
                               unsigned char prevtxid_out[32],
                               uint32_t *prevtx_vout_out,
                               uint32_t *sequence_out)
{
    if (!msg || msg_len < 82) return 0;
    if (get_u16_be(msg) != MSG_TX_ADD_INPUT) return 0;
    if (channel_id_out)  memcpy(channel_id_out, msg + 2, 32);
    if (serial_id_out)   *serial_id_out   = get_u64_be(msg + 34);
    if (prevtxid_out)    memcpy(prevtxid_out, msg + 42, 32);
    if (prevtx_vout_out) *prevtx_vout_out = get_u32_be(msg + 74);
    if (sequence_out)    *sequence_out    = get_u32_be(msg + 78);
    return 1;
}

/* tx_add_output (type 67): type(2)+cid(32)+serial(8)+sats(8)+slen(2)+script(var) */
size_t splice_build_tx_add_output(const unsigned char channel_id[32],
                                   uint64_t serial_id, uint64_t sats,
                                   const unsigned char *script, uint16_t script_len,
                                   unsigned char *buf, size_t buf_cap)
{
    size_t need = 2 + 32 + 8 + 8 + 2 + script_len;
    if (!channel_id || !buf || buf_cap < need) return 0;
    size_t pos = 0;
    put_u16_be(buf + pos, (uint16_t)MSG_TX_ADD_OUTPUT); pos += 2;
    memcpy(buf + pos, channel_id, 32); pos += 32;
    put_u64_be(buf + pos, serial_id); pos += 8;
    put_u64_be(buf + pos, sats); pos += 8;
    put_u16_be(buf + pos, script_len); pos += 2;
    if (script && script_len > 0) { memcpy(buf + pos, script, script_len); pos += script_len; }
    return pos;
}

int splice_parse_tx_add_output(const unsigned char *msg, size_t msg_len,
                                unsigned char channel_id_out[32],
                                uint64_t *serial_id_out, uint64_t *sats_out,
                                unsigned char *script_out, uint16_t *script_len_out)
{
    if (!msg || msg_len < 54) return 0;
    if (get_u16_be(msg) != MSG_TX_ADD_OUTPUT) return 0;
    uint16_t slen = (uint16_t)(((uint16_t)msg[50] << 8) | msg[51]);
    if (msg_len < (size_t)(52 + slen)) return 0;
    if (channel_id_out) memcpy(channel_id_out, msg + 2, 32);
    if (serial_id_out)  *serial_id_out = get_u64_be(msg + 34);
    if (sats_out)       *sats_out      = get_u64_be(msg + 42);
    if (script_len_out) *script_len_out = slen;
    if (script_out && slen > 0) memcpy(script_out, msg + 52, slen);
    return 1;
}

/* tx_remove_input (type 68) and tx_remove_output (type 69):
   type(2)+cid(32)+serial(8) = 42 bytes */
size_t splice_build_tx_remove_input(const unsigned char channel_id[32],
                                     uint64_t serial_id,
                                     unsigned char *buf, size_t buf_cap)
{
    if (!channel_id || !buf || buf_cap < 42) return 0;
    put_u16_be(buf, (uint16_t)MSG_TX_REMOVE_INPUT);
    memcpy(buf + 2, channel_id, 32);
    put_u64_be(buf + 34, serial_id);
    return 42;
}

size_t splice_build_tx_remove_output(const unsigned char channel_id[32],
                                      uint64_t serial_id,
                                      unsigned char *buf, size_t buf_cap)
{
    if (!channel_id || !buf || buf_cap < 42) return 0;
    put_u16_be(buf, (uint16_t)MSG_TX_REMOVE_OUTPUT);
    memcpy(buf + 2, channel_id, 32);
    put_u64_be(buf + 34, serial_id);
    return 42;
}

int splice_parse_tx_remove(const unsigned char *msg, size_t msg_len,
                            uint16_t expected_type,
                            unsigned char channel_id_out[32],
                            uint64_t *serial_id_out)
{
    if (!msg || msg_len < 42) return 0;
    if (get_u16_be(msg) != expected_type) return 0;
    if (channel_id_out) memcpy(channel_id_out, msg + 2, 32);
    if (serial_id_out)  *serial_id_out = get_u64_be(msg + 34);
    return 1;
}

/* tx_complete (type 70): type(2)+cid(32) = 34 bytes */
size_t splice_build_tx_complete(const unsigned char channel_id[32],
                                 unsigned char *buf, size_t buf_cap)
{
    if (!channel_id || !buf || buf_cap < 34) return 0;
    put_u16_be(buf, (uint16_t)MSG_TX_COMPLETE);
    memcpy(buf + 2, channel_id, 32);
    return 34;
}

int splice_parse_tx_complete(const unsigned char *msg, size_t msg_len,
                              unsigned char channel_id_out[32])
{
    if (!msg || msg_len < 34) return 0;
    if (get_u16_be(msg) != MSG_TX_COMPLETE) return 0;
    if (channel_id_out) memcpy(channel_id_out, msg + 2, 32);
    return 1;
}

/* tx_signatures (type 71): type(2)+cid(32)+txid(32)+wit_len(2)+witness(var) */
size_t splice_build_tx_signatures(const unsigned char channel_id[32],
                                   const unsigned char txid[32],
                                   const unsigned char *witness,
                                   uint16_t witness_len,
                                   unsigned char *buf, size_t buf_cap)
{
    size_t need = 2 + 32 + 32 + 2 + witness_len;
    if (!channel_id || !txid || !buf || buf_cap < need) return 0;
    size_t pos = 0;
    put_u16_be(buf + pos, (uint16_t)MSG_TX_SIGNATURES); pos += 2;
    memcpy(buf + pos, channel_id, 32); pos += 32;
    memcpy(buf + pos, txid, 32); pos += 32;
    put_u16_be(buf + pos, witness_len); pos += 2;
    if (witness && witness_len > 0) { memcpy(buf + pos, witness, witness_len); pos += witness_len; }
    return pos;
}

int splice_parse_tx_signatures(const unsigned char *msg, size_t msg_len,
                                unsigned char channel_id_out[32],
                                unsigned char txid_out[32],
                                unsigned char *witness_out,
                                uint16_t *witness_len_out)
{
    if (!msg || msg_len < 68) return 0;
    if (get_u16_be(msg) != MSG_TX_SIGNATURES) return 0;
    uint16_t wlen = (uint16_t)(((uint16_t)msg[66] << 8) | msg[67]);
    if (msg_len < (size_t)(68 + wlen)) return 0;
    if (channel_id_out)  memcpy(channel_id_out, msg + 2, 32);
    if (txid_out)        memcpy(txid_out, msg + 34, 32);
    if (witness_len_out) *witness_len_out = wlen;
    if (witness_out && wlen > 0) memcpy(witness_out, msg + 68, wlen);
    return 1;
}
