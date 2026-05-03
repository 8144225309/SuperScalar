#include "superscalar/tx_builder.h"
#include "superscalar/types.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
#include "superscalar/sha256.h"

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define TEST_ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { \
        printf("  FAIL: %s (line %d): %s (got %ld, expected %ld)\n", \
               __func__, __LINE__, msg, (long)(a), (long)(b)); \
        return 0; \
    } \
} while(0)

int test_tx_buf_primitives(void) {
    tx_buf_t buf;
    tx_buf_init(&buf, 64);

    tx_buf_write_u8(&buf, 0xab);
    TEST_ASSERT_EQ(buf.len, 1, "u8 length");
    TEST_ASSERT_EQ(buf.data[0], 0xab, "u8 value");

    tx_buf_reset(&buf);
    tx_buf_write_u32_le(&buf, 0x01020304);
    TEST_ASSERT_EQ(buf.len, 4, "u32 length");
    TEST_ASSERT_EQ(buf.data[0], 0x04, "u32 LE byte 0");
    TEST_ASSERT_EQ(buf.data[1], 0x03, "u32 LE byte 1");
    TEST_ASSERT_EQ(buf.data[2], 0x02, "u32 LE byte 2");
    TEST_ASSERT_EQ(buf.data[3], 0x01, "u32 LE byte 3");

    tx_buf_reset(&buf);
    tx_buf_write_u64_le(&buf, 0x0807060504030201ULL);
    TEST_ASSERT_EQ(buf.len, 8, "u64 length");
    TEST_ASSERT_EQ(buf.data[0], 0x01, "u64 LE byte 0");
    TEST_ASSERT_EQ(buf.data[7], 0x08, "u64 LE byte 7");

    tx_buf_free(&buf);
    return 1;
}

int test_varint_encoding(void) {
    tx_buf_t buf;
    tx_buf_init(&buf, 64);

    /* single byte: < 0xfd */
    tx_buf_write_varint(&buf, 1);
    TEST_ASSERT_EQ(buf.len, 1, "varint 1 length");
    TEST_ASSERT_EQ(buf.data[0], 0x01, "varint 1 value");

    tx_buf_reset(&buf);
    tx_buf_write_varint(&buf, 0xfc);
    TEST_ASSERT_EQ(buf.len, 1, "varint 0xfc length");
    TEST_ASSERT_EQ(buf.data[0], 0xfc, "varint 0xfc value");

    /* 3-byte: 0xfd prefix + u16 LE */
    tx_buf_reset(&buf);
    tx_buf_write_varint(&buf, 0xfd);
    TEST_ASSERT_EQ(buf.len, 3, "varint 0xfd length");
    TEST_ASSERT_EQ(buf.data[0], 0xfd, "varint 0xfd prefix");
    TEST_ASSERT_EQ(buf.data[1], 0xfd, "varint 0xfd low byte");
    TEST_ASSERT_EQ(buf.data[2], 0x00, "varint 0xfd high byte");

    tx_buf_reset(&buf);
    tx_buf_write_varint(&buf, 0x0100);
    TEST_ASSERT_EQ(buf.len, 3, "varint 256 length");
    TEST_ASSERT_EQ(buf.data[0], 0xfd, "varint 256 prefix");
    TEST_ASSERT_EQ(buf.data[1], 0x00, "varint 256 low byte");
    TEST_ASSERT_EQ(buf.data[2], 0x01, "varint 256 high byte");

    tx_buf_free(&buf);
    return 1;
}

int test_build_p2tr_script_pubkey(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    unsigned char seckey[32] = {
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    };

    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, seckey)) return 0;
    secp256k1_xonly_pubkey xpk;
    if (!secp256k1_keypair_xonly_pub(ctx, &xpk, NULL, &kp)) return 0;

    unsigned char spk[34];
    build_p2tr_script_pubkey(spk, &xpk);

    /* OP_1 (0x51) OP_PUSHBYTES_32 (0x20) <32-byte-key> */
    TEST_ASSERT_EQ(spk[0], 0x51, "OP_1");
    TEST_ASSERT_EQ(spk[1], 0x20, "OP_PUSHBYTES_32");

    unsigned char xpk_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, xpk_ser, &xpk)) return 0;
    TEST_ASSERT(memcmp(spk + 2, xpk_ser, 32) == 0, "key bytes match");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_build_unsigned_tx(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    unsigned char funding_txid[32];
    memset(funding_txid, 0xaa, 32);

    unsigned char seckey[32];
    memset(seckey, 0x03, 32);
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, seckey)) return 0;
    secp256k1_xonly_pubkey xpk;
    if (!secp256k1_keypair_xonly_pub(ctx, &xpk, NULL, &kp)) return 0;

    tx_output_t output;
    output.amount_sats = 50000;
    build_p2tr_script_pubkey(output.script_pubkey, &xpk);
    output.script_pubkey_len = 34;

    tx_buf_t buf;
    tx_buf_init(&buf, 256);
    unsigned char txid[32];

    TEST_ASSERT(build_unsigned_tx(&buf, txid, funding_txid, 0, 144, &output, 1),
                "build unsigned tx");

    TEST_ASSERT(buf.len > 0, "tx has data");

    /* nVersion = 2 (LE) at offset 0 */
    TEST_ASSERT_EQ(buf.data[0], 0x02, "nVersion byte 0");
    TEST_ASSERT_EQ(buf.data[1], 0x00, "nVersion byte 1");
    TEST_ASSERT_EQ(buf.data[2], 0x00, "nVersion byte 2");
    TEST_ASSERT_EQ(buf.data[3], 0x00, "nVersion byte 3");

    TEST_ASSERT_EQ(buf.data[4], 0x01, "input count");                  /* offset 4 */
    TEST_ASSERT(memcmp(buf.data + 5, funding_txid, 32) == 0, "prev txid"); /* offset 5 */
    TEST_ASSERT_EQ(buf.data[37], 0x00, "prev vout");                   /* offset 37 */
    TEST_ASSERT_EQ(buf.data[41], 0x00, "scriptsig len");               /* offset 41 */

    /* nSequence = 144 = 0x90 (LE) at offset 42 */
    TEST_ASSERT_EQ(buf.data[42], 0x90, "nsequence byte 0");
    TEST_ASSERT_EQ(buf.data[43], 0x00, "nsequence byte 1");
    TEST_ASSERT_EQ(buf.data[44], 0x00, "nsequence byte 2");
    TEST_ASSERT_EQ(buf.data[45], 0x00, "nsequence byte 3");

    /* nLockTime = 0 at end */
    TEST_ASSERT_EQ(buf.data[buf.len - 4], 0x00, "nlocktime byte 0");
    TEST_ASSERT_EQ(buf.data[buf.len - 3], 0x00, "nlocktime byte 1");
    TEST_ASSERT_EQ(buf.data[buf.len - 2], 0x00, "nlocktime byte 2");
    TEST_ASSERT_EQ(buf.data[buf.len - 1], 0x00, "nlocktime byte 3");

    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (txid[i] != 0) { all_zero = 0; break; }
    }
    TEST_ASSERT(!all_zero, "txid should be non-zero");

    tx_buf_free(&buf);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_build_unsigned_tx_multi(void) {
    /* Multi-input variant for the v0.1.15 #207 fix.  Asserts the wire
       format encodes N inputs correctly + each input's nsequence is
       independent + the txid hashes deterministically. */
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    /* 3 distinct inputs (e.g. chain[N-1]'s 2 channel outputs + sales-stock). */
    tx_input_t inputs[3];
    memset(inputs[0].prev_txid, 0xa1, 32); inputs[0].prev_vout = 0; inputs[0].nsequence = 0xFFFFFFFE;
    memset(inputs[1].prev_txid, 0xa1, 32); inputs[1].prev_vout = 1; inputs[1].nsequence = 0xFFFFFFFE;
    memset(inputs[2].prev_txid, 0xa1, 32); inputs[2].prev_vout = 2; inputs[2].nsequence = 144;

    /* Mock outputs (k+1 = 3). */
    unsigned char seckey[32]; memset(seckey, 0x05, 32);
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, seckey)) return 0;
    secp256k1_xonly_pubkey xpk;
    if (!secp256k1_keypair_xonly_pub(ctx, &xpk, NULL, &kp)) return 0;

    tx_output_t outs[3];
    for (int i = 0; i < 3; i++) {
        outs[i].amount_sats = 40000 + (uint64_t)i * 1000;
        build_p2tr_script_pubkey(outs[i].script_pubkey, &xpk);
        outs[i].script_pubkey_len = 34;
    }

    tx_buf_t buf; tx_buf_init(&buf, 512);
    unsigned char txid[32];

    TEST_ASSERT(build_unsigned_tx_multi(&buf, txid, inputs, 3, outs, 3, 2, 0),
                "multi-input build");

    /* Wire format spot-checks:
       offset 0..3: nVersion=2 (LE)
       offset 4: input count varint = 3
       offset 5..36: input[0].prev_txid
       offset 37..40: input[0].prev_vout=0
       offset 41: scriptSig len = 0
       offset 42..45: input[0].nsequence=0xFFFFFFFE */
    TEST_ASSERT_EQ(buf.data[0], 0x02, "nVersion byte 0");
    TEST_ASSERT_EQ(buf.data[4], 0x03, "input count = 3");
    TEST_ASSERT(memcmp(buf.data + 5, inputs[0].prev_txid, 32) == 0,
                "input[0] txid");
    TEST_ASSERT_EQ(buf.data[37], 0x00, "input[0] vout = 0");
    TEST_ASSERT_EQ(buf.data[42], 0xFE, "input[0] nseq[0] = 0xFE");
    TEST_ASSERT_EQ(buf.data[43], 0xFF, "input[0] nseq[1] = 0xFF");
    TEST_ASSERT_EQ(buf.data[44], 0xFF, "input[0] nseq[2] = 0xFF");
    TEST_ASSERT_EQ(buf.data[45], 0xFF, "input[0] nseq[3] = 0xFF");

    /* input[1]: at offset 46, txid (32) + vout (4) + scriptsig_len(1) + nseq(4) = 41 bytes */
    TEST_ASSERT(memcmp(buf.data + 46, inputs[1].prev_txid, 32) == 0,
                "input[1] txid");
    TEST_ASSERT_EQ(buf.data[78], 0x01, "input[1] vout = 1");

    /* input[2]: at offset 87, with nseq = 144 = 0x90 */
    TEST_ASSERT_EQ(buf.data[87 + 32], 0x02, "input[2] vout = 2");
    TEST_ASSERT_EQ(buf.data[87 + 32 + 4 + 1], 0x90, "input[2] nseq = 144");

    /* txid is non-zero */
    int all_zero = 1;
    for (int i = 0; i < 32; i++) if (txid[i]) { all_zero = 0; break; }
    TEST_ASSERT(!all_zero, "multi-input txid is non-zero");

    /* Determinism — re-build with same inputs, expect identical bytes */
    tx_buf_t buf2; tx_buf_init(&buf2, 512);
    unsigned char txid2[32];
    TEST_ASSERT(build_unsigned_tx_multi(&buf2, txid2, inputs, 3, outs, 3, 2, 0),
                "multi-input rebuild");
    TEST_ASSERT(buf.len == buf2.len, "deterministic length");
    TEST_ASSERT(memcmp(buf.data, buf2.data, buf.len) == 0,
                "deterministic bytes");
    TEST_ASSERT(memcmp(txid, txid2, 32) == 0, "deterministic txid");

    /* Argument validation */
    TEST_ASSERT(!build_unsigned_tx_multi(&buf, NULL, NULL, 3, outs, 3, 2, 0),
                "null inputs rejected");
    TEST_ASSERT(!build_unsigned_tx_multi(&buf, NULL, inputs, 0, outs, 3, 2, 0),
                "zero inputs rejected");

    tx_buf_free(&buf);
    tx_buf_free(&buf2);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_finalize_signed_tx(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    unsigned char funding_txid[32];
    memset(funding_txid, 0xbb, 32);

    unsigned char seckey[32];
    memset(seckey, 0x04, 32);
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, seckey)) return 0;
    secp256k1_xonly_pubkey xpk;
    if (!secp256k1_keypair_xonly_pub(ctx, &xpk, NULL, &kp)) return 0;

    tx_output_t output;
    output.amount_sats = 40000;
    build_p2tr_script_pubkey(output.script_pubkey, &xpk);
    output.script_pubkey_len = 34;

    tx_buf_t unsigned_buf;
    tx_buf_init(&unsigned_buf, 256);
    build_unsigned_tx(&unsigned_buf, NULL, funding_txid, 0, 288, &output, 1);

    unsigned char sig[64];
    memset(sig, 0xcc, 64);

    tx_buf_t signed_buf;
    tx_buf_init(&signed_buf, 512);
    TEST_ASSERT(finalize_signed_tx(&signed_buf, unsigned_buf.data, unsigned_buf.len, sig),
                "finalize signed tx");

    TEST_ASSERT_EQ(signed_buf.data[0], 0x02, "signed nVersion byte 0");
    TEST_ASSERT_EQ(signed_buf.data[4], 0x00, "segwit marker");
    TEST_ASSERT_EQ(signed_buf.data[5], 0x01, "segwit flag");

    /* witness adds: marker(1) + flag(1) + varint(1) + varint(64) + sig(64) = 68 bytes */
    TEST_ASSERT(signed_buf.len == unsigned_buf.len + 2 + 66,
                "signed tx length = unsigned + marker/flag + witness");

    TEST_ASSERT_EQ(signed_buf.data[signed_buf.len - 4], 0x00, "signed nlocktime");

    tx_buf_free(&unsigned_buf);
    tx_buf_free(&signed_buf);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* For n_inputs=1, compute_taproot_sighash_multi must match
   compute_taproot_sighash byte-for-byte.  Anchors the multi-input variant
   against the existing single-input implementation. */
int test_compute_taproot_sighash_multi_matches_single_for_n1(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    unsigned char prev_txid[32]; memset(prev_txid, 0xa1, 32);
    unsigned char seckey[32];   memset(seckey, 0x07, 32);
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, seckey)) return 0;
    secp256k1_xonly_pubkey xpk;
    if (!secp256k1_keypair_xonly_pub(ctx, &xpk, NULL, &kp)) return 0;

    tx_output_t output = {0};
    output.amount_sats = 50000;
    build_p2tr_script_pubkey(output.script_pubkey, &xpk);
    output.script_pubkey_len = 34;

    unsigned char prev_spk[34];
    build_p2tr_script_pubkey(prev_spk, &xpk);
    uint64_t prev_amount = 100000;
    uint32_t nseq = 0xFFFFFFFE;

    /* Build the same TX two ways: single-input and multi-input(n=1). */
    tx_buf_t single_buf; tx_buf_init(&single_buf, 256);
    TEST_ASSERT(build_unsigned_tx(&single_buf, NULL, prev_txid, 0, nseq,
                                    &output, 1),
                "build single-input");

    tx_input_t inp = {0};
    memcpy(inp.prev_txid, prev_txid, 32);
    inp.prev_vout = 0;
    inp.nsequence = nseq;
    tx_buf_t multi_buf; tx_buf_init(&multi_buf, 256);
    TEST_ASSERT(build_unsigned_tx_multi(&multi_buf, NULL, &inp, 1, &output, 1, 2, 0),
                "build multi-input n=1");

    /* The two byte streams must be identical. */
    TEST_ASSERT_EQ(single_buf.len, multi_buf.len, "n=1 lengths match");
    TEST_ASSERT(memcmp(single_buf.data, multi_buf.data, single_buf.len) == 0,
                "n=1 bytes match");

    /* Both sighash functions must produce identical 32-byte output. */
    unsigned char sh_single[32], sh_multi[32];
    TEST_ASSERT(compute_taproot_sighash(sh_single, single_buf.data, single_buf.len,
                                          0, prev_spk, 34, prev_amount, nseq),
                "single-input sighash");

    const unsigned char *spks[1] = { prev_spk };
    size_t spk_lens[1] = { 34 };
    uint64_t amounts[1] = { prev_amount };
    uint32_t seqs[1] = { nseq };
    TEST_ASSERT(compute_taproot_sighash_multi(sh_multi, multi_buf.data, multi_buf.len,
                                                0, 1, spks, spk_lens, amounts, seqs),
                "multi-input sighash n=1");

    TEST_ASSERT(memcmp(sh_single, sh_multi, 32) == 0,
                "single == multi sighash for n=1");

    tx_buf_free(&single_buf);
    tx_buf_free(&multi_buf);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* For n_inputs=3, sighashes for input_index=0..2 must all differ from
   each other (the input_index is mixed into the preimage), and changing
   any per-input field must change the sighash. */
int test_compute_taproot_sighash_multi_n3_input_binding(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    unsigned char seckey[32]; memset(seckey, 0x09, 32);
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, seckey)) return 0;
    secp256k1_xonly_pubkey xpk;
    if (!secp256k1_keypair_xonly_pub(ctx, &xpk, NULL, &kp)) return 0;

    tx_input_t inputs[3];
    memset(inputs[0].prev_txid, 0xa1, 32); inputs[0].prev_vout = 0; inputs[0].nsequence = 0xFFFFFFFE;
    memset(inputs[1].prev_txid, 0xa1, 32); inputs[1].prev_vout = 1; inputs[1].nsequence = 0xFFFFFFFE;
    memset(inputs[2].prev_txid, 0xa1, 32); inputs[2].prev_vout = 2; inputs[2].nsequence = 0xFFFFFFFE;

    tx_output_t outs[3];
    for (int i = 0; i < 3; i++) {
        outs[i].amount_sats = 30000 + (uint64_t)i * 1000;
        build_p2tr_script_pubkey(outs[i].script_pubkey, &xpk);
        outs[i].script_pubkey_len = 34;
    }

    tx_buf_t buf; tx_buf_init(&buf, 512);
    TEST_ASSERT(build_unsigned_tx_multi(&buf, NULL, inputs, 3, outs, 3, 2, 0),
                "build n=3 multi");

    unsigned char prev_spk[34];
    build_p2tr_script_pubkey(prev_spk, &xpk);
    const unsigned char *spks[3] = { prev_spk, prev_spk, prev_spk };
    size_t spk_lens[3] = { 34, 34, 34 };
    uint64_t amounts[3] = { 50000, 60000, 70000 };
    uint32_t seqs[3] = { 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFE };

    unsigned char sh[3][32];
    for (uint32_t i = 0; i < 3; i++) {
        TEST_ASSERT(compute_taproot_sighash_multi(sh[i], buf.data, buf.len,
                                                   i, 3, spks, spk_lens, amounts, seqs),
                    "multi sighash per-input");
    }
    /* Each sighash must differ — input_index mixes into the preimage. */
    TEST_ASSERT(memcmp(sh[0], sh[1], 32) != 0, "sh[0] != sh[1]");
    TEST_ASSERT(memcmp(sh[1], sh[2], 32) != 0, "sh[1] != sh[2]");
    TEST_ASSERT(memcmp(sh[0], sh[2], 32) != 0, "sh[0] != sh[2]");

    /* Changing one prev_amount must change the sighash for ALL inputs
       (sha_amounts is shared across inputs in the BIP-341 preimage). */
    amounts[1] = 60001;
    unsigned char sh2[32];
    TEST_ASSERT(compute_taproot_sighash_multi(sh2, buf.data, buf.len,
                                                0, 3, spks, spk_lens, amounts, seqs),
                "sighash with bumped amount");
    TEST_ASSERT(memcmp(sh[0], sh2, 32) != 0,
                "amount mutation propagates to sighash");

    tx_buf_free(&buf);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* finalize_signed_tx_multi must:
   - emit segwit marker/flag
   - attach exactly N witness records, each {1, 64, sig}
   - place nLockTime at the end
   - for n=1, equal finalize_signed_tx byte-for-byte */
int test_finalize_signed_tx_multi(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    unsigned char seckey[32]; memset(seckey, 0x0b, 32);
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, seckey)) return 0;
    secp256k1_xonly_pubkey xpk;
    if (!secp256k1_keypair_xonly_pub(ctx, &xpk, NULL, &kp)) return 0;

    /* Build n=3 unsigned multi-input tx */
    tx_input_t inputs[3];
    memset(inputs[0].prev_txid, 0xa1, 32); inputs[0].prev_vout = 0; inputs[0].nsequence = 0xFFFFFFFE;
    memset(inputs[1].prev_txid, 0xa1, 32); inputs[1].prev_vout = 1; inputs[1].nsequence = 0xFFFFFFFE;
    memset(inputs[2].prev_txid, 0xa1, 32); inputs[2].prev_vout = 2; inputs[2].nsequence = 0xFFFFFFFE;
    tx_output_t outs[3];
    for (int i = 0; i < 3; i++) {
        outs[i].amount_sats = 30000;
        build_p2tr_script_pubkey(outs[i].script_pubkey, &xpk);
        outs[i].script_pubkey_len = 34;
    }
    tx_buf_t unsigned_buf; tx_buf_init(&unsigned_buf, 512);
    TEST_ASSERT(build_unsigned_tx_multi(&unsigned_buf, NULL, inputs, 3, outs, 3, 2, 0),
                "build unsigned");

    /* Distinct sigs per input so we can spot-check ordering */
    unsigned char sigs[3 * 64];
    memset(sigs + 0  * 64, 0xc1, 64);
    memset(sigs + 1  * 64, 0xc2, 64);
    memset(sigs + 2  * 64, 0xc3, 64);

    tx_buf_t signed_buf; tx_buf_init(&signed_buf, 1024);
    TEST_ASSERT(finalize_signed_tx_multi(&signed_buf, unsigned_buf.data,
                                          unsigned_buf.len, 3, sigs),
                "finalize multi");

    /* nVersion + segwit marker + flag */
    TEST_ASSERT_EQ(signed_buf.data[0], 0x02, "nVersion");
    TEST_ASSERT_EQ(signed_buf.data[4], 0x00, "segwit marker");
    TEST_ASSERT_EQ(signed_buf.data[5], 0x01, "segwit flag");

    /* Each witness adds varint(1) + varint(64) + 64 = 66 bytes; 3 witnesses = 198 */
    TEST_ASSERT(signed_buf.len == unsigned_buf.len + 2 + 3 * 66,
                "signed length = unsigned + marker/flag + 3 witnesses");

    /* Locate witness section: directly before the trailing 4-byte nLockTime.
       Each witness is 66 bytes; first witness starts at signed_buf.len - 4 - 198. */
    size_t wit_start = signed_buf.len - 4 - 3 * 66;
    /* witness 0 */
    TEST_ASSERT_EQ(signed_buf.data[wit_start + 0], 0x01, "wit0 stack count");
    TEST_ASSERT_EQ(signed_buf.data[wit_start + 1], 0x40, "wit0 sig len = 64");
    TEST_ASSERT_EQ(signed_buf.data[wit_start + 2], 0xc1, "wit0 sig byte");
    /* witness 1 */
    TEST_ASSERT_EQ(signed_buf.data[wit_start + 66 + 2], 0xc2, "wit1 sig byte");
    /* witness 2 */
    TEST_ASSERT_EQ(signed_buf.data[wit_start + 132 + 2], 0xc3, "wit2 sig byte");

    /* nLockTime at end */
    TEST_ASSERT_EQ(signed_buf.data[signed_buf.len - 4], 0x00, "nlocktime byte 0");

    /* For n=1, finalize_signed_tx_multi must match finalize_signed_tx. */
    tx_buf_t u1; tx_buf_init(&u1, 256);
    TEST_ASSERT(build_unsigned_tx_multi(&u1, NULL, inputs, 1, outs, 3, 2, 0),
                "build n=1");
    unsigned char one_sig[64]; memset(one_sig, 0xee, 64);
    tx_buf_t s_a, s_b;
    tx_buf_init(&s_a, 512); tx_buf_init(&s_b, 512);
    TEST_ASSERT(finalize_signed_tx(&s_a, u1.data, u1.len, one_sig),
                "single finalize");
    TEST_ASSERT(finalize_signed_tx_multi(&s_b, u1.data, u1.len, 1, one_sig),
                "multi finalize n=1");
    TEST_ASSERT_EQ(s_a.len, s_b.len, "n=1 finalize lengths match");
    TEST_ASSERT(memcmp(s_a.data, s_b.data, s_a.len) == 0,
                "n=1 finalize bytes match");

    /* Argument validation */
    TEST_ASSERT(!finalize_signed_tx_multi(&signed_buf, NULL, 100, 3, sigs),
                "null tx rejected");
    TEST_ASSERT(!finalize_signed_tx_multi(&signed_buf, unsigned_buf.data, unsigned_buf.len, 0, sigs),
                "zero inputs rejected");

    tx_buf_free(&unsigned_buf);
    tx_buf_free(&signed_buf);
    tx_buf_free(&u1);
    tx_buf_free(&s_a);
    tx_buf_free(&s_b);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Phase C: V3/TRUC CPFP — build_unsigned_tx_v with nVersion=3 */
int test_v3_cpfp_tx_version(void)
{
    unsigned char funding_txid[32];
    memset(funding_txid, 0xcc, 32);

    tx_output_t output;
    output.amount_sats = 10000;
    memset(output.script_pubkey, 0x51, 34);
    output.script_pubkey[0] = 0x51;
    output.script_pubkey[1] = 0x20;
    output.script_pubkey_len = 34;

    tx_buf_t buf;
    tx_buf_init(&buf, 256);

    TEST_ASSERT(build_unsigned_tx_v(&buf, NULL, funding_txid, 0, 0xFFFFFFFE,
                                     &output, 1, 3),
                "build_unsigned_tx_v nVersion=3 should succeed");
    TEST_ASSERT(buf.len >= 4, "tx has data");
    /* nVersion = 3 (LE) at offset 0 */
    TEST_ASSERT_EQ(buf.data[0], 0x03, "nVersion byte 0 == 3 (TRUC)");
    TEST_ASSERT_EQ(buf.data[1], 0x00, "nVersion byte 1 == 0");
    TEST_ASSERT_EQ(buf.data[2], 0x00, "nVersion byte 2 == 0");
    TEST_ASSERT_EQ(buf.data[3], 0x00, "nVersion byte 3 == 0");

    tx_buf_free(&buf);
    return 1;
}

/* Phase C: standard channel tx must still use nVersion=2 */
int test_v2_channel_tx_version(void)
{
    unsigned char funding_txid[32];
    memset(funding_txid, 0xdd, 32);

    tx_output_t output;
    output.amount_sats = 50000;
    memset(output.script_pubkey, 0, 34);
    output.script_pubkey[0] = 0x51;
    output.script_pubkey[1] = 0x20;
    output.script_pubkey_len = 34;

    tx_buf_t buf;
    tx_buf_init(&buf, 256);

    TEST_ASSERT(build_unsigned_tx(&buf, NULL, funding_txid, 0, 144, &output, 1),
                "build_unsigned_tx (V2) should succeed");
    TEST_ASSERT_EQ(buf.data[0], 0x02, "standard tx nVersion=2 byte 0");
    TEST_ASSERT_EQ(buf.data[1], 0x00, "standard tx nVersion byte 1");

    tx_buf_free(&buf);
    return 1;
}
