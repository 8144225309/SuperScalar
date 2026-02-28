#include "superscalar/tx_builder.h"
#include <string.h>
#include <stdlib.h>

extern void sha256(const unsigned char *data, size_t len, unsigned char *out32);
extern void sha256_double(const unsigned char *data, size_t len, unsigned char *out32);
extern void sha256_tagged(const char *tag, const unsigned char *data, size_t data_len,
                           unsigned char *out32);
extern void reverse_bytes(unsigned char *data, size_t len);

void tx_buf_write_u8(tx_buf_t *buf, uint8_t val) {
    tx_buf_ensure(buf, 1);
    buf->data[buf->len++] = val;
}

void tx_buf_write_u16_le(tx_buf_t *buf, uint16_t val) {
    tx_buf_ensure(buf, 2);
    buf->data[buf->len++] = (unsigned char)(val & 0xff);
    buf->data[buf->len++] = (unsigned char)((val >> 8) & 0xff);
}

void tx_buf_write_u32_le(tx_buf_t *buf, uint32_t val) {
    tx_buf_ensure(buf, 4);
    buf->data[buf->len++] = (unsigned char)(val & 0xff);
    buf->data[buf->len++] = (unsigned char)((val >> 8) & 0xff);
    buf->data[buf->len++] = (unsigned char)((val >> 16) & 0xff);
    buf->data[buf->len++] = (unsigned char)((val >> 24) & 0xff);
}

void tx_buf_write_u64_le(tx_buf_t *buf, uint64_t val) {
    tx_buf_ensure(buf, 8);
    for (int i = 0; i < 8; i++)
        buf->data[buf->len++] = (unsigned char)((val >> (i * 8)) & 0xff);
}

void tx_buf_write_varint(tx_buf_t *buf, uint64_t val) {
    if (val < 0xfd) {
        tx_buf_write_u8(buf, (uint8_t)val);
    } else if (val <= 0xffff) {
        tx_buf_write_u8(buf, 0xfd);
        tx_buf_write_u16_le(buf, (uint16_t)val);
    } else if (val <= 0xffffffff) {
        tx_buf_write_u8(buf, 0xfe);
        tx_buf_write_u32_le(buf, (uint32_t)val);
    } else {
        tx_buf_write_u8(buf, 0xff);
        tx_buf_write_u64_le(buf, val);
    }
}

void tx_buf_write_bytes(tx_buf_t *buf, const unsigned char *data, size_t len) {
    tx_buf_ensure(buf, len);
    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
}

void build_p2tr_script_pubkey(unsigned char *out34, const secp256k1_xonly_pubkey *key) {
    out34[0] = 0x51; /* OP_1 */
    out34[1] = 0x20; /* PUSHBYTES_32 */
    secp256k1_xonly_pubkey_serialize(secp256k1_context_static, out34 + 2, key);
}

int build_unsigned_tx_with_locktime(
    tx_buf_t *out,
    unsigned char *txid_out32,
    const unsigned char *funding_txid,
    uint32_t funding_vout,
    uint32_t nsequence,
    uint32_t nlocktime,
    const tx_output_t *outputs,
    size_t n_outputs
) {
    tx_buf_reset(out);

    tx_buf_write_u32_le(out, 2);           /* nVersion */
    tx_buf_write_varint(out, 1);           /* 1 input */
    tx_buf_write_bytes(out, funding_txid, 32);
    tx_buf_write_u32_le(out, funding_vout);
    tx_buf_write_varint(out, 0);           /* empty scriptSig */
    tx_buf_write_u32_le(out, nsequence);

    tx_buf_write_varint(out, n_outputs);
    for (size_t i = 0; i < n_outputs; i++) {
        tx_buf_write_u64_le(out, outputs[i].amount_sats);
        tx_buf_write_varint(out, outputs[i].script_pubkey_len);
        tx_buf_write_bytes(out, outputs[i].script_pubkey, outputs[i].script_pubkey_len);
    }

    tx_buf_write_u32_le(out, nlocktime);

    if (txid_out32) {
        sha256_double(out->data, out->len, txid_out32);
        reverse_bytes(txid_out32, 32);
    }

    return 1;
}

int build_unsigned_tx(
    tx_buf_t *out,
    unsigned char *txid_out32,
    const unsigned char *funding_txid,
    uint32_t funding_vout,
    uint32_t nsequence,
    const tx_output_t *outputs,
    size_t n_outputs
) {
    return build_unsigned_tx_with_locktime(out, txid_out32, funding_txid, funding_vout,
                                            nsequence, 0, outputs, n_outputs);
}

static void write_u32_le(unsigned char *buf, uint32_t val) {
    buf[0] = (unsigned char)(val & 0xff);
    buf[1] = (unsigned char)((val >> 8) & 0xff);
    buf[2] = (unsigned char)((val >> 16) & 0xff);
    buf[3] = (unsigned char)((val >> 24) & 0xff);
}

static void write_u64_le(unsigned char *buf, uint64_t val) {
    for (int i = 0; i < 8; i++)
        buf[i] = (unsigned char)((val >> (i * 8)) & 0xff);
}

/*
 * BIP-341 sighash for key-path spend (SIGHASH_DEFAULT).
 * Assumes single-input tx built by build_unsigned_tx.
 */
int compute_taproot_sighash(
    unsigned char *sighash_out32,
    const unsigned char *unsigned_tx,
    size_t tx_len,
    uint32_t input_index,
    const unsigned char *prev_scriptpubkey,
    size_t prev_spk_len,
    uint64_t prev_amount,
    uint32_t nsequence
) {
    unsigned char nversion_le[4], nlocktime_le[4];
    memcpy(nversion_le, unsigned_tx, 4);
    memcpy(nlocktime_le, unsigned_tx + tx_len - 4, 4);

    /* prevouts = txid(32) + vout(4) starting at offset 5 */
    unsigned char prevouts_data[36];
    memcpy(prevouts_data, unsigned_tx + 5, 36);

    unsigned char sha_prevouts[32];
    sha256(prevouts_data, 36, sha_prevouts);

    unsigned char amount_le[8];
    write_u64_le(amount_le, prev_amount);
    unsigned char sha_amounts[32];
    sha256(amount_le, 8, sha_amounts);

    /* scriptpubkeys hash: varint(len) || scriptpubkey */
    size_t spk_ser_len = 1 + prev_spk_len;
    unsigned char *spk_ser = (unsigned char *)malloc(spk_ser_len);
    if (!spk_ser) return 0;
    spk_ser[0] = (unsigned char)prev_spk_len;
    memcpy(spk_ser + 1, prev_scriptpubkey, prev_spk_len);
    unsigned char sha_scriptpubkeys[32];
    sha256(spk_ser, spk_ser_len, sha_scriptpubkeys);
    free(spk_ser);

    unsigned char seq_le[4];
    write_u32_le(seq_le, nsequence);
    unsigned char sha_sequences[32];
    sha256(seq_le, 4, sha_sequences);

    /* outputs hash: skip output_count varint at offset 46 */
    size_t out_start = 46;
    out_start++; /* 1-byte varint for count < 253 */
    size_t outputs_data_len = tx_len - 4 - out_start;
    unsigned char sha_outputs[32];
    sha256(unsigned_tx + out_start, outputs_data_len, sha_outputs);

    /* Assemble sighash preimage */
    unsigned char msg[175];
    size_t pos = 0;

    msg[pos++] = 0x00; /* epoch */
    msg[pos++] = 0x00; /* SIGHASH_DEFAULT */
    memcpy(msg + pos, nversion_le, 4); pos += 4;
    memcpy(msg + pos, nlocktime_le, 4); pos += 4;
    memcpy(msg + pos, sha_prevouts, 32); pos += 32;
    memcpy(msg + pos, sha_amounts, 32); pos += 32;
    memcpy(msg + pos, sha_scriptpubkeys, 32); pos += 32;
    memcpy(msg + pos, sha_sequences, 32); pos += 32;
    memcpy(msg + pos, sha_outputs, 32); pos += 32;
    msg[pos++] = 0x00; /* key-path, no annex */
    write_u32_le(msg + pos, input_index); pos += 4;

    sha256_tagged("TapSighash", msg, pos, sighash_out32);
    return 1;
}

int finalize_signed_tx(
    tx_buf_t *out,
    const unsigned char *unsigned_tx,
    size_t unsigned_tx_len,
    const unsigned char *sig64
) {
    tx_buf_reset(out);

    tx_buf_write_bytes(out, unsigned_tx, 4);   /* nVersion */
    tx_buf_write_u8(out, 0x00);                /* segwit marker */
    tx_buf_write_u8(out, 0x01);                /* segwit flag */

    /* inputs + outputs (between nVersion and nLockTime) */
    tx_buf_write_bytes(out, unsigned_tx + 4, unsigned_tx_len - 8);

    /* witness: 1 item, 64-byte schnorr sig */
    tx_buf_write_varint(out, 1);
    tx_buf_write_varint(out, 64);
    tx_buf_write_bytes(out, sig64, 64);

    tx_buf_write_bytes(out, unsigned_tx + unsigned_tx_len - 4, 4); /* nLockTime */
    return 1;
}
