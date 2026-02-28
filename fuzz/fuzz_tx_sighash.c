/*
 * fuzz_tx_sighash.c — libFuzzer harness for compute_taproot_sighash().
 *
 * Feeds raw byte buffers as unsigned transactions into the sighash
 * computation.  The function uses hardcoded offsets (e.g. out_start=46)
 * that assume single-input transactions — malformed input must not
 * cause out-of-bounds access.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "superscalar/tx_builder.h"

extern int compute_taproot_sighash(
    unsigned char *sighash_out32,
    const unsigned char *unsigned_tx,
    size_t tx_len,
    uint32_t input_index,
    const unsigned char *prev_scriptpubkey,
    size_t prev_spk_len,
    uint64_t prev_amount,
    uint32_t nsequence
);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 60) return 0;  /* need minimum tx-like data */

    unsigned char sighash[32];

    /* Use first 34 bytes as a fake P2TR scriptpubkey */
    unsigned char spk[34];
    memset(spk, 0, sizeof(spk));
    spk[0] = 0x51;  /* OP_1 */
    spk[1] = 0x20;  /* OP_PUSHBYTES_32 */
    if (size >= 34)
        memcpy(spk + 2, data, 32);

    /* Try computing sighash — should not crash even on malformed tx */
    compute_taproot_sighash(
        sighash,
        data, size,
        0,          /* input_index */
        spk, 34,    /* prev_scriptpubkey */
        100000,     /* prev_amount (sats) */
        0xFFFFFFFD  /* nsequence */
    );

    /* Also test tx_buf_write_* primitives */
    tx_buf_t buf;
    tx_buf_init(&buf, 64);

    if (size >= 4) {
        uint32_t val;
        memcpy(&val, data, 4);
        tx_buf_write_u32_le(&buf, val);
    }
    if (size >= 8) {
        uint64_t val;
        memcpy(&val, data, 8);
        tx_buf_write_u64_le(&buf, val);
        tx_buf_write_varint(&buf, val);
    }

    tx_buf_free(&buf);
    return 0;
}
