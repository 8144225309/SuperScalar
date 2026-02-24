#include "superscalar/tx_builder.h"
#include "superscalar/types.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void sha256(const unsigned char *data, size_t len, unsigned char *out32);
extern void sha256_double(const unsigned char *data, size_t len, unsigned char *out32);

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
    secp256k1_keypair_create(ctx, &kp, seckey);
    secp256k1_xonly_pubkey xpk;
    secp256k1_keypair_xonly_pub(ctx, &xpk, NULL, &kp);

    unsigned char spk[34];
    build_p2tr_script_pubkey(spk, &xpk);

    /* OP_1 (0x51) OP_PUSHBYTES_32 (0x20) <32-byte-key> */
    TEST_ASSERT_EQ(spk[0], 0x51, "OP_1");
    TEST_ASSERT_EQ(spk[1], 0x20, "OP_PUSHBYTES_32");

    unsigned char xpk_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, xpk_ser, &xpk);
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
    secp256k1_keypair_create(ctx, &kp, seckey);
    secp256k1_xonly_pubkey xpk;
    secp256k1_keypair_xonly_pub(ctx, &xpk, NULL, &kp);

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

int test_finalize_signed_tx(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    unsigned char funding_txid[32];
    memset(funding_txid, 0xbb, 32);

    unsigned char seckey[32];
    memset(seckey, 0x04, 32);
    secp256k1_keypair kp;
    secp256k1_keypair_create(ctx, &kp, seckey);
    secp256k1_xonly_pubkey xpk;
    secp256k1_keypair_xonly_pub(ctx, &xpk, NULL, &kp);

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
