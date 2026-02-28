#include "superscalar/tapscript.h"
#include "superscalar/tx_builder.h"
#include <string.h>
#include <stdlib.h>

extern void sha256(const unsigned char *data, size_t len, unsigned char *out32);
extern void sha256_double(const unsigned char *data, size_t len, unsigned char *out32);
extern void sha256_tagged(const char *tag, const unsigned char *data, size_t data_len,
                           unsigned char *out32);
extern void reverse_bytes(unsigned char *data, size_t len);

/* Encode locktime as minimal CScriptNum (little-endian, with sign bit handling).
   Uses OP_0 for 0, OP_1..OP_16 for 1..16 (BIP342 MINIMALDATA), data push otherwise. */
static size_t encode_scriptnum(unsigned char *out, uint32_t val) {
    if (val == 0) {
        out[0] = 0x00;  /* OP_0 */
        return 1;
    }
    if (val <= 16) {
        out[0] = 0x50 + (unsigned char)val;  /* OP_1(0x51)..OP_16(0x60) */
        return 1;
    }

    unsigned char tmp[5];
    size_t n = 0;
    uint32_t v = val;
    while (v > 0) {
        tmp[n++] = (unsigned char)(v & 0xff);
        v >>= 8;
    }
    /* If the high bit of the last byte is set, add a 0x00 byte
       (CScriptNum uses sign-magnitude, we need positive) */
    if (tmp[n - 1] & 0x80)
        tmp[n++] = 0x00;

    /* Write push opcode + data */
    out[0] = (unsigned char)n;  /* OP_PUSHBYTES_N for 1..75 */
    memcpy(out + 1, tmp, n);
    return 1 + n;
}

void tapscript_build_hashlock(tapscript_leaf_t *leaf,
                               const unsigned char *hash32) {
    size_t pos = 0;

    leaf->script[pos++] = 0x82;  /* OP_SIZE */
    leaf->script[pos++] = 0x01;  /* OP_PUSHBYTES_1 */
    leaf->script[pos++] = 0x20;  /* 32 */
    leaf->script[pos++] = 0x88;  /* OP_EQUALVERIFY */
    leaf->script[pos++] = 0xa8;  /* OP_SHA256 */
    leaf->script[pos++] = 0x20;  /* OP_PUSHBYTES_32 */
    memcpy(leaf->script + pos, hash32, 32);
    pos += 32;
    leaf->script[pos++] = 0x87;  /* OP_EQUAL */

    leaf->script_len = pos;  /* 37 bytes */
    tapscript_compute_leaf_hash(leaf);
}

int tapscript_build_cltv_timeout(
    tapscript_leaf_t *leaf,
    uint32_t locktime,
    const secp256k1_xonly_pubkey *lsp_pubkey,
    const secp256k1_context *ctx
) {
    size_t pos = 0;

    /* <locktime> as CScriptNum push */
    pos += encode_scriptnum(leaf->script + pos, locktime);

    /* OP_CHECKLOCKTIMEVERIFY */
    leaf->script[pos++] = 0xb1;

    /* OP_DROP */
    leaf->script[pos++] = 0x75;

    /* <32-byte x-only pubkey> push */
    leaf->script[pos++] = 0x20;  /* OP_PUSHBYTES_32 */
    if (!secp256k1_xonly_pubkey_serialize(ctx, leaf->script + pos, lsp_pubkey))
        return 0;
    pos += 32;

    /* OP_CHECKSIG */
    leaf->script[pos++] = 0xac;

    leaf->script_len = pos;

    /* Compute leaf hash */
    tapscript_compute_leaf_hash(leaf);
    return 1;
}

int tapscript_build_csv_delay(
    tapscript_leaf_t *leaf,
    uint32_t delay,
    const secp256k1_xonly_pubkey *pubkey,
    const secp256k1_context *ctx
) {
    size_t pos = 0;

    /* <delay> as CScriptNum push */
    pos += encode_scriptnum(leaf->script + pos, delay);

    /* OP_CHECKSEQUENCEVERIFY */
    leaf->script[pos++] = 0xb2;

    /* OP_DROP */
    leaf->script[pos++] = 0x75;

    /* <32-byte x-only pubkey> push */
    leaf->script[pos++] = 0x20;  /* OP_PUSHBYTES_32 */
    if (!secp256k1_xonly_pubkey_serialize(ctx, leaf->script + pos, pubkey))
        return 0;
    pos += 32;

    /* OP_CHECKSIG */
    leaf->script[pos++] = 0xac;

    leaf->script_len = pos;
    tapscript_compute_leaf_hash(leaf);
    return 1;
}

void tapscript_compute_leaf_hash(tapscript_leaf_t *leaf) {
    /* TapLeaf = tagged_hash("TapLeaf", leaf_version(1) || compact_size(script_len) || script) */
    size_t data_len = 1 + 1 + leaf->script_len;  /* leaf_version + varint + script */
    /* For scripts up to 252 bytes, compact_size is 1 byte */
    unsigned char *data = (unsigned char *)malloc(data_len);
    if (!data) { memset(leaf->leaf_hash, 0, 32); return; }

    data[0] = TAPSCRIPT_LEAF_VERSION;  /* 0xc0 */
    data[1] = (unsigned char)leaf->script_len;  /* compact_size (< 253) */
    memcpy(data + 2, leaf->script, leaf->script_len);

    sha256_tagged("TapLeaf", data, data_len, leaf->leaf_hash);
    free(data);
}

void tapscript_merkle_root(unsigned char *root_out32,
                           const tapscript_leaf_t *leaves, size_t n_leaves) {
    if (n_leaves == 1) {
        memcpy(root_out32, leaves[0].leaf_hash, 32);
        return;
    }

    /* For 2 leaves: TapBranch = tagged_hash("TapBranch", sorted(left, right)) */
    if (n_leaves == 2) {
        unsigned char branch_data[64];
        /* Lexicographic sort */
        if (memcmp(leaves[0].leaf_hash, leaves[1].leaf_hash, 32) <= 0) {
            memcpy(branch_data, leaves[0].leaf_hash, 32);
            memcpy(branch_data + 32, leaves[1].leaf_hash, 32);
        } else {
            memcpy(branch_data, leaves[1].leaf_hash, 32);
            memcpy(branch_data + 32, leaves[0].leaf_hash, 32);
        }
        sha256_tagged("TapBranch", branch_data, 64, root_out32);
        return;
    }

    /* For now, only 1 or 2 leaves supported */
    memset(root_out32, 0, 32);
}

int tapscript_tweak_pubkey(
    const secp256k1_context *ctx,
    secp256k1_xonly_pubkey *tweaked_out,
    int *parity_out,
    const secp256k1_xonly_pubkey *internal_key,
    const unsigned char *merkle_root32
) {
    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, internal_key))
        return 0;

    /* TapTweak = tagged_hash("TapTweak", internal_key || merkle_root) */
    unsigned char tweak_data[64];
    memcpy(tweak_data, internal_ser, 32);
    memcpy(tweak_data + 32, merkle_root32, 32);

    unsigned char tweak[32];
    sha256_tagged("TapTweak", tweak_data, 64, tweak);

    secp256k1_pubkey tweaked_full;
    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked_full, internal_key, tweak))
        return 0;

    int parity = 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, tweaked_out, &parity, &tweaked_full))
        return 0;

    if (parity_out)
        *parity_out = parity;

    return 1;
}

int tapscript_build_control_block(
    unsigned char *out, size_t *out_len,
    int output_parity,
    const secp256k1_xonly_pubkey *internal_key,
    const secp256k1_context *ctx
) {
    /* Single-leaf tree: control block = [leaf_version | parity_bit] || internal_key(32) */
    /* Total: 33 bytes, no merkle path needed */
    out[0] = TAPSCRIPT_LEAF_VERSION | (output_parity & 1);

    if (!secp256k1_xonly_pubkey_serialize(ctx, out + 1, internal_key))
        return 0;

    *out_len = 33;
    return 1;
}

/* Helper: write u32 little-endian */
static void write_u32_le(unsigned char *buf, uint32_t val) {
    buf[0] = (unsigned char)(val & 0xff);
    buf[1] = (unsigned char)((val >> 8) & 0xff);
    buf[2] = (unsigned char)((val >> 16) & 0xff);
    buf[3] = (unsigned char)((val >> 24) & 0xff);
}

/* Helper: write u64 little-endian */
static void write_u64_le(unsigned char *buf, uint64_t val) {
    for (int i = 0; i < 8; i++)
        buf[i] = (unsigned char)((val >> (i * 8)) & 0xff);
}

int compute_tapscript_sighash(
    unsigned char *sighash_out32,
    const unsigned char *unsigned_tx, size_t tx_len,
    uint32_t input_index,
    const unsigned char *prev_spk, size_t prev_spk_len,
    uint64_t prev_amount, uint32_t nsequence,
    const tapscript_leaf_t *leaf
) {
    unsigned char nversion_le[4], nlocktime_le[4];
    memcpy(nversion_le, unsigned_tx, 4);
    memcpy(nlocktime_le, unsigned_tx + tx_len - 4, 4);

    /* prevouts = txid(32) + vout(4) at offset 5 */
    unsigned char prevouts_data[36];
    memcpy(prevouts_data, unsigned_tx + 5, 36);

    unsigned char sha_prevouts[32];
    sha256(prevouts_data, 36, sha_prevouts);

    unsigned char amount_le[8];
    write_u64_le(amount_le, prev_amount);
    unsigned char sha_amounts[32];
    sha256(amount_le, 8, sha_amounts);

    /* scriptpubkeys hash */
    size_t spk_ser_len = 1 + prev_spk_len;
    unsigned char *spk_ser = (unsigned char *)malloc(spk_ser_len);
    spk_ser[0] = (unsigned char)prev_spk_len;
    memcpy(spk_ser + 1, prev_spk, prev_spk_len);
    unsigned char sha_scriptpubkeys[32];
    sha256(spk_ser, spk_ser_len, sha_scriptpubkeys);
    free(spk_ser);

    unsigned char seq_le[4];
    write_u32_le(seq_le, nsequence);
    unsigned char sha_sequences[32];
    sha256(seq_le, 4, sha_sequences);

    /* outputs hash */
    size_t out_start = 46;
    out_start++;  /* 1-byte varint for count < 253 */
    size_t outputs_data_len = tx_len - 4 - out_start;
    unsigned char sha_outputs[32];
    sha256(unsigned_tx + out_start, outputs_data_len, sha_outputs);

    /* Assemble sighash preimage:
       Same as key-path up to spend_type, then:
       - spend_type = 0x02 (script-path, no annex)
       - input_index
       Then extension:
       - tapleaf_hash(32)
       - key_version(1) = 0x00
       - codeseparator_pos(4) = 0xFFFFFFFF
    */
    unsigned char msg[175 + 37];  /* key-path (175) - 1 (spend_type change already counted) + extension (37) */
    size_t pos = 0;

    msg[pos++] = 0x00;  /* epoch */
    msg[pos++] = 0x00;  /* SIGHASH_DEFAULT */
    memcpy(msg + pos, nversion_le, 4); pos += 4;
    memcpy(msg + pos, nlocktime_le, 4); pos += 4;
    memcpy(msg + pos, sha_prevouts, 32); pos += 32;
    memcpy(msg + pos, sha_amounts, 32); pos += 32;
    memcpy(msg + pos, sha_scriptpubkeys, 32); pos += 32;
    memcpy(msg + pos, sha_sequences, 32); pos += 32;
    memcpy(msg + pos, sha_outputs, 32); pos += 32;
    msg[pos++] = 0x02;  /* spend_type: script-path, no annex */
    write_u32_le(msg + pos, input_index); pos += 4;

    /* Script-path extension */
    memcpy(msg + pos, leaf->leaf_hash, 32); pos += 32;
    msg[pos++] = 0x00;  /* key_version */
    write_u32_le(msg + pos, 0xFFFFFFFF); pos += 4;  /* codeseparator_pos = -1 */

    sha256_tagged("TapSighash", msg, pos, sighash_out32);
    return 1;
}

int build_unsigned_tx_locktime(
    tx_buf_t *out,
    unsigned char *txid_out32,
    const unsigned char *input_txid,
    uint32_t input_vout,
    uint32_t nsequence,
    uint32_t nlocktime,
    const tx_output_t *outputs,
    size_t n_outputs
) {
    tx_buf_reset(out);

    tx_buf_write_u32_le(out, 2);             /* nVersion */
    tx_buf_write_varint(out, 1);             /* 1 input */
    tx_buf_write_bytes(out, input_txid, 32);
    tx_buf_write_u32_le(out, input_vout);
    tx_buf_write_varint(out, 0);             /* empty scriptSig */
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

int finalize_script_path_tx(
    tx_buf_t *out,
    const unsigned char *unsigned_tx, size_t unsigned_tx_len,
    const unsigned char *sig64,
    const unsigned char *script, size_t script_len,
    const unsigned char *control_block, size_t control_block_len
) {
    tx_buf_reset(out);

    tx_buf_write_bytes(out, unsigned_tx, 4);   /* nVersion */
    tx_buf_write_u8(out, 0x00);                /* segwit marker */
    tx_buf_write_u8(out, 0x01);                /* segwit flag */

    /* inputs + outputs (between nVersion and nLockTime) */
    tx_buf_write_bytes(out, unsigned_tx + 4, unsigned_tx_len - 8);

    /* witness: 3 items: [sig(64), script(var), control_block(33)] */
    tx_buf_write_varint(out, 3);

    /* Item 1: signature */
    tx_buf_write_varint(out, 64);
    tx_buf_write_bytes(out, sig64, 64);

    /* Item 2: script */
    tx_buf_write_varint(out, script_len);
    tx_buf_write_bytes(out, script, script_len);

    /* Item 3: control block */
    tx_buf_write_varint(out, control_block_len);
    tx_buf_write_bytes(out, control_block, control_block_len);

    /* nLockTime */
    tx_buf_write_bytes(out, unsigned_tx + unsigned_tx_len - 4, 4);
    return 1;
}

/* --- HTLC script builders --- */

int tapscript_build_htlc_offered_success(tapscript_leaf_t *leaf,
    const unsigned char *payment_hash32,
    const secp256k1_xonly_pubkey *remote_htlcpubkey,
    const secp256k1_context *ctx)
{
    size_t pos = 0;

    /* OP_SIZE <0x20> OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUALVERIFY <remote_key> OP_CHECKSIG */
    leaf->script[pos++] = 0x82;  /* OP_SIZE */
    leaf->script[pos++] = 0x01;  /* OP_PUSHBYTES_1 */
    leaf->script[pos++] = 0x20;  /* 32 */
    leaf->script[pos++] = 0x88;  /* OP_EQUALVERIFY */
    leaf->script[pos++] = 0xa8;  /* OP_SHA256 */
    leaf->script[pos++] = 0x20;  /* OP_PUSHBYTES_32 */
    memcpy(leaf->script + pos, payment_hash32, 32);
    pos += 32;
    leaf->script[pos++] = 0x88;  /* OP_EQUALVERIFY */
    leaf->script[pos++] = 0x20;  /* OP_PUSHBYTES_32 */
    if (!secp256k1_xonly_pubkey_serialize(ctx, leaf->script + pos, remote_htlcpubkey))
        return 0;
    pos += 32;
    leaf->script[pos++] = 0xac;  /* OP_CHECKSIG */

    leaf->script_len = pos;
    tapscript_compute_leaf_hash(leaf);
    return 1;
}

int tapscript_build_htlc_offered_timeout(tapscript_leaf_t *leaf,
    uint32_t cltv_expiry, uint32_t to_self_delay,
    const secp256k1_xonly_pubkey *local_htlcpubkey,
    const secp256k1_context *ctx)
{
    size_t pos = 0;

    /* <cltv> OP_CLTV OP_DROP <csv> OP_CSV OP_DROP <local_key> OP_CHECKSIG */
    pos += encode_scriptnum(leaf->script + pos, cltv_expiry);
    leaf->script[pos++] = 0xb1;  /* OP_CHECKLOCKTIMEVERIFY */
    leaf->script[pos++] = 0x75;  /* OP_DROP */
    pos += encode_scriptnum(leaf->script + pos, to_self_delay);
    leaf->script[pos++] = 0xb2;  /* OP_CHECKSEQUENCEVERIFY */
    leaf->script[pos++] = 0x75;  /* OP_DROP */
    leaf->script[pos++] = 0x20;  /* OP_PUSHBYTES_32 */
    if (!secp256k1_xonly_pubkey_serialize(ctx, leaf->script + pos, local_htlcpubkey))
        return 0;
    pos += 32;
    leaf->script[pos++] = 0xac;  /* OP_CHECKSIG */

    leaf->script_len = pos;
    tapscript_compute_leaf_hash(leaf);
    return 1;
}

int tapscript_build_htlc_received_success(tapscript_leaf_t *leaf,
    const unsigned char *payment_hash32, uint32_t to_self_delay,
    const secp256k1_xonly_pubkey *local_htlcpubkey,
    const secp256k1_context *ctx)
{
    size_t pos = 0;

    /* OP_SIZE <0x20> OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUALVERIFY <csv> OP_CSV OP_DROP <local_key> OP_CHECKSIG */
    leaf->script[pos++] = 0x82;  /* OP_SIZE */
    leaf->script[pos++] = 0x01;  /* OP_PUSHBYTES_1 */
    leaf->script[pos++] = 0x20;  /* 32 */
    leaf->script[pos++] = 0x88;  /* OP_EQUALVERIFY */
    leaf->script[pos++] = 0xa8;  /* OP_SHA256 */
    leaf->script[pos++] = 0x20;  /* OP_PUSHBYTES_32 */
    memcpy(leaf->script + pos, payment_hash32, 32);
    pos += 32;
    leaf->script[pos++] = 0x88;  /* OP_EQUALVERIFY */
    pos += encode_scriptnum(leaf->script + pos, to_self_delay);
    leaf->script[pos++] = 0xb2;  /* OP_CHECKSEQUENCEVERIFY */
    leaf->script[pos++] = 0x75;  /* OP_DROP */
    leaf->script[pos++] = 0x20;  /* OP_PUSHBYTES_32 */
    if (!secp256k1_xonly_pubkey_serialize(ctx, leaf->script + pos, local_htlcpubkey))
        return 0;
    pos += 32;
    leaf->script[pos++] = 0xac;  /* OP_CHECKSIG */

    leaf->script_len = pos;
    tapscript_compute_leaf_hash(leaf);
    return 1;
}

int tapscript_build_htlc_received_timeout(tapscript_leaf_t *leaf,
    uint32_t cltv_expiry,
    const secp256k1_xonly_pubkey *remote_htlcpubkey,
    const secp256k1_context *ctx)
{
    /* Identical structure to cltv_timeout: <cltv> OP_CLTV OP_DROP <key> OP_CHECKSIG */
    return tapscript_build_cltv_timeout(leaf, cltv_expiry, remote_htlcpubkey, ctx);
}

/* --- 2-leaf control block --- */

int tapscript_build_control_block_2leaf(
    unsigned char *out, size_t *out_len,
    int output_parity,
    const secp256k1_xonly_pubkey *internal_key,
    const tapscript_leaf_t *sibling_leaf,
    const secp256k1_context *ctx)
{
    /* 2-leaf tree: control block = [leaf_version | parity_bit] || internal_key(32) || sibling_leaf_hash(32) */
    /* Total: 65 bytes */
    out[0] = TAPSCRIPT_LEAF_VERSION | (output_parity & 1);

    if (!secp256k1_xonly_pubkey_serialize(ctx, out + 1, internal_key))
        return 0;

    memcpy(out + 33, sibling_leaf->leaf_hash, 32);

    *out_len = 65;
    return 1;
}

/* --- Preimage witness finalizer --- */

int finalize_script_path_tx_preimage(
    tx_buf_t *out,
    const unsigned char *unsigned_tx, size_t unsigned_tx_len,
    const unsigned char *sig64,
    const unsigned char *preimage, size_t preimage_len,
    const unsigned char *script, size_t script_len,
    const unsigned char *control_block, size_t control_block_len)
{
    tx_buf_reset(out);

    tx_buf_write_bytes(out, unsigned_tx, 4);   /* nVersion */
    tx_buf_write_u8(out, 0x00);                /* segwit marker */
    tx_buf_write_u8(out, 0x01);                /* segwit flag */

    /* inputs + outputs (between nVersion and nLockTime) */
    tx_buf_write_bytes(out, unsigned_tx + 4, unsigned_tx_len - 8);

    /* witness: 4 items: [sig(64), preimage(32), script(var), control_block(65)] */
    tx_buf_write_varint(out, 4);

    /* Item 1: signature */
    tx_buf_write_varint(out, 64);
    tx_buf_write_bytes(out, sig64, 64);

    /* Item 2: preimage */
    tx_buf_write_varint(out, preimage_len);
    tx_buf_write_bytes(out, preimage, preimage_len);

    /* Item 3: script */
    tx_buf_write_varint(out, script_len);
    tx_buf_write_bytes(out, script, script_len);

    /* Item 4: control block */
    tx_buf_write_varint(out, control_block_len);
    tx_buf_write_bytes(out, control_block, control_block_len);

    /* nLockTime */
    tx_buf_write_bytes(out, unsigned_tx + unsigned_tx_len - 4, 4);
    return 1;
}
