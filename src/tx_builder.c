#include "superscalar/tx_builder.h"
#include <string.h>
#include <stdlib.h>

#include "superscalar/sha256.h"
extern void reverse_bytes(unsigned char *data, size_t len);

void tx_buf_write_u8(tx_buf_t *buf, uint8_t val) {
    tx_buf_ensure(buf, 1);
    if (buf->oom) return;
    buf->data[buf->len++] = val;
}

void tx_buf_write_u16_le(tx_buf_t *buf, uint16_t val) {
    tx_buf_ensure(buf, 2);
    if (buf->oom) return;
    buf->data[buf->len++] = (unsigned char)(val & 0xff);
    buf->data[buf->len++] = (unsigned char)((val >> 8) & 0xff);
}

void tx_buf_write_u32_le(tx_buf_t *buf, uint32_t val) {
    tx_buf_ensure(buf, 4);
    if (buf->oom) return;
    buf->data[buf->len++] = (unsigned char)(val & 0xff);
    buf->data[buf->len++] = (unsigned char)((val >> 8) & 0xff);
    buf->data[buf->len++] = (unsigned char)((val >> 16) & 0xff);
    buf->data[buf->len++] = (unsigned char)((val >> 24) & 0xff);
}

void tx_buf_write_u64_le(tx_buf_t *buf, uint64_t val) {
    tx_buf_ensure(buf, 8);
    if (buf->oom) return;
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
    if (buf->oom) return;
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

    if (out->oom) return 0;

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

int build_unsigned_tx_multi(
    tx_buf_t *out,
    unsigned char *txid_out32,
    const tx_input_t *inputs,
    size_t n_inputs,
    const tx_output_t *outputs,
    size_t n_outputs,
    uint32_t nVersion,
    uint32_t nlocktime
) {
    if (!out || !inputs || n_inputs == 0 || (!outputs && n_outputs > 0))
        return 0;
    tx_buf_reset(out);

    tx_buf_write_u32_le(out, nVersion);
    tx_buf_write_varint(out, n_inputs);
    for (size_t i = 0; i < n_inputs; i++) {
        tx_buf_write_bytes(out, inputs[i].prev_txid, 32);
        tx_buf_write_u32_le(out, inputs[i].prev_vout);
        tx_buf_write_varint(out, 0);           /* empty scriptSig */
        tx_buf_write_u32_le(out, inputs[i].nsequence);
    }

    tx_buf_write_varint(out, n_outputs);
    for (size_t i = 0; i < n_outputs; i++) {
        tx_buf_write_u64_le(out, outputs[i].amount_sats);
        tx_buf_write_varint(out, outputs[i].script_pubkey_len);
        tx_buf_write_bytes(out, outputs[i].script_pubkey,
                           outputs[i].script_pubkey_len);
    }

    tx_buf_write_u32_le(out, nlocktime);

    if (out->oom) return 0;

    if (txid_out32) {
        sha256_double(out->data, out->len, txid_out32);
        reverse_bytes(txid_out32, 32);
    }
    return 1;
}

int build_unsigned_tx_v(
    tx_buf_t *out,
    unsigned char *txid_out32,
    const unsigned char *funding_txid,
    uint32_t funding_vout,
    uint32_t nsequence,
    const tx_output_t *outputs,
    size_t n_outputs,
    uint32_t nVersion
) {
    tx_buf_reset(out);

    tx_buf_write_u32_le(out, nVersion);    /* nVersion (explicit) */
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

    tx_buf_write_u32_le(out, 0);           /* nLockTime = 0 */

    if (out->oom) return 0;

    if (txid_out32) {
        sha256_double(out->data, out->len, txid_out32);
        reverse_bytes(txid_out32, 32);
    }

    return 1;
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

    /* outputs hash: skip the output_count varint at offset 46.  The varint is
       1 byte for < 253 outputs, but 3 bytes (0xfd + u16) for 253..65535 and
       5 bytes (0xfe + u32) beyond — a large cooperative close (>=253 clients)
       has a multi-byte count, and assuming 1 byte here mis-hashes the outputs
       and yields an invalid key-path signature. Decode the varint length. */
    size_t out_start = 46;
    unsigned char cnt_tag = unsigned_tx[out_start];
    if (cnt_tag < 0xfd)       out_start += 1;
    else if (cnt_tag == 0xfd) out_start += 3;
    else if (cnt_tag == 0xfe) out_start += 5;
    else                      out_start += 9;
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
    return !out->oom;
}

/* Compute the byte length of a varint given its value. */
static size_t varint_size(uint64_t v) {
    if (v < 0xfd)        return 1;
    if (v <= 0xffff)     return 3;
    if (v <= 0xffffffff) return 5;
    return 9;
}

int compute_taproot_sighash_multi(
    unsigned char *sighash_out32,
    const unsigned char *unsigned_tx,
    size_t tx_len,
    uint32_t input_index,
    size_t n_inputs,
    const unsigned char * const *prev_scriptpubkeys,
    const size_t *prev_spk_lens,
    const uint64_t *prev_amounts,
    const uint32_t *nsequences
) {
    if (!sighash_out32 || !unsigned_tx || !prev_scriptpubkeys ||
        !prev_spk_lens || !prev_amounts || !nsequences) return 0;
    if (n_inputs == 0) return 0;
    if ((size_t)input_index >= n_inputs) return 0;
    if (tx_len < 8) return 0;

    unsigned char nversion_le[4], nlocktime_le[4];
    memcpy(nversion_le, unsigned_tx, 4);
    memcpy(nlocktime_le, unsigned_tx + tx_len - 4, 4);

    /* Locate the inputs section in the serialized tx.
       Layout: [nVersion(4)][varint(n_inputs)][input × n_inputs][varint(n_outputs)][outputs][nLockTime(4)]
       Each input: [prev_txid(32)][prev_vout(4)][varint(scriptSig_len)=0][nSequence(4)] = 41 bytes.
       (scriptSig is empty in unsigned TXs we build, so its varint is a single 0x00 byte.) */
    size_t n_inputs_varint_len = varint_size((uint64_t)n_inputs);
    size_t inputs_start = 4 + n_inputs_varint_len;
    const size_t each_input_len = 32 + 4 + 1 + 4;
    size_t outputs_start = inputs_start + each_input_len * n_inputs;
    if (outputs_start + 4 > tx_len) return 0;

    /* sha_prevouts: SHA256 of all (txid + vout) concatenated, in tx order.
       Read them straight from the tx bytes — that guarantees we hash
       exactly what bitcoin will hash. */
    unsigned char *prevouts_concat = (unsigned char *)malloc(36 * n_inputs);
    if (!prevouts_concat) return 0;
    for (size_t i = 0; i < n_inputs; i++) {
        size_t off = inputs_start + each_input_len * i;
        memcpy(prevouts_concat + 36 * i, unsigned_tx + off, 36);
    }
    unsigned char sha_prevouts[32];
    sha256(prevouts_concat, 36 * n_inputs, sha_prevouts);
    free(prevouts_concat);

    /* sha_amounts: SHA256 of all 8-byte LE amounts concatenated. */
    unsigned char *amounts_concat = (unsigned char *)malloc(8 * n_inputs);
    if (!amounts_concat) return 0;
    for (size_t i = 0; i < n_inputs; i++)
        write_u64_le(amounts_concat + 8 * i, prev_amounts[i]);
    unsigned char sha_amounts[32];
    sha256(amounts_concat, 8 * n_inputs, sha_amounts);
    free(amounts_concat);

    /* sha_scriptpubkeys: SHA256 of (varint(spk_len) || spk) per input concatenated. */
    size_t spk_total = 0;
    for (size_t i = 0; i < n_inputs; i++) {
        if (prev_spk_lens[i] >= 0xfd) return 0;  /* SPKs in our usage are <253 bytes */
        spk_total += 1 + prev_spk_lens[i];
    }
    unsigned char *spk_concat = (unsigned char *)malloc(spk_total);
    if (!spk_concat) return 0;
    size_t spk_pos = 0;
    for (size_t i = 0; i < n_inputs; i++) {
        spk_concat[spk_pos++] = (unsigned char)prev_spk_lens[i];
        memcpy(spk_concat + spk_pos, prev_scriptpubkeys[i], prev_spk_lens[i]);
        spk_pos += prev_spk_lens[i];
    }
    unsigned char sha_scriptpubkeys[32];
    sha256(spk_concat, spk_total, sha_scriptpubkeys);
    free(spk_concat);

    /* sha_sequences: SHA256 of all 4-byte LE sequences concatenated. */
    unsigned char *seq_concat = (unsigned char *)malloc(4 * n_inputs);
    if (!seq_concat) return 0;
    for (size_t i = 0; i < n_inputs; i++)
        write_u32_le(seq_concat + 4 * i, nsequences[i]);
    unsigned char sha_sequences[32];
    sha256(seq_concat, 4 * n_inputs, sha_sequences);
    free(seq_concat);

    /* sha_outputs: SHA256 of the entire outputs section (excluding the
       leading varint(n_outputs)).  In single-input compute_taproot_sighash
       we hardcoded the +1 byte skip; here we read the actual varint length. */
    size_t out_count_varint_off = outputs_start;
    /* peek varint len; outputs in our usage always have small varint */
    uint8_t b0 = unsigned_tx[out_count_varint_off];
    size_t out_count_varint_len = (b0 < 0xfd) ? 1 : (b0 == 0xfd ? 3 : (b0 == 0xfe ? 5 : 9));
    size_t outputs_data_start = outputs_start + out_count_varint_len;
    if (outputs_data_start + 4 > tx_len) return 0;
    size_t outputs_data_len = tx_len - 4 - outputs_data_start;
    unsigned char sha_outputs[32];
    sha256(unsigned_tx + outputs_data_start, outputs_data_len, sha_outputs);

    /* Assemble preimage (BIP-341 §4.2 key-path, SIGHASH_DEFAULT, no annex). */
    unsigned char msg[175];
    size_t pos = 0;
    msg[pos++] = 0x00;                                 /* epoch */
    msg[pos++] = 0x00;                                 /* SIGHASH_DEFAULT */
    memcpy(msg + pos, nversion_le,  4);  pos += 4;
    memcpy(msg + pos, nlocktime_le, 4);  pos += 4;
    memcpy(msg + pos, sha_prevouts,      32); pos += 32;
    memcpy(msg + pos, sha_amounts,       32); pos += 32;
    memcpy(msg + pos, sha_scriptpubkeys, 32); pos += 32;
    memcpy(msg + pos, sha_sequences,     32); pos += 32;
    memcpy(msg + pos, sha_outputs,       32); pos += 32;
    msg[pos++] = 0x00;                                 /* spend_type: key-path, no annex */
    write_u32_le(msg + pos, input_index); pos += 4;

    sha256_tagged("TapSighash", msg, pos, sighash_out32);
    return 1;
}

int finalize_signed_tx_multi(
    tx_buf_t *out,
    const unsigned char *unsigned_tx,
    size_t unsigned_tx_len,
    size_t n_inputs,
    const unsigned char *sig64s
) {
    if (!out || !unsigned_tx || !sig64s) return 0;
    if (n_inputs == 0) return 0;
    if (unsigned_tx_len < 8) return 0;

    tx_buf_reset(out);

    tx_buf_write_bytes(out, unsigned_tx, 4);   /* nVersion */
    tx_buf_write_u8(out, 0x00);                /* segwit marker */
    tx_buf_write_u8(out, 0x01);                /* segwit flag */

    /* inputs + outputs (everything between nVersion and nLockTime) */
    tx_buf_write_bytes(out, unsigned_tx + 4, unsigned_tx_len - 8);

    /* witness data: one stack-of-1 64-byte schnorr sig per input, in input order. */
    for (size_t i = 0; i < n_inputs; i++) {
        tx_buf_write_varint(out, 1);
        tx_buf_write_varint(out, 64);
        tx_buf_write_bytes(out, sig64s + 64 * i, 64);
    }

    tx_buf_write_bytes(out, unsigned_tx + unsigned_tx_len - 4, 4); /* nLockTime */
    return !out->oom;
}
