/*
 * fuzz_aead_decrypt.c — libFuzzer harness for aead_decrypt().
 *
 * Carves key(32) + nonce(12) + tag(16) + ciphertext from the fuzz input
 * and calls aead_decrypt.  Must never crash on any input.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "superscalar/crypto_aead.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Need at least key(32) + nonce(12) + tag(16) = 60 bytes + 1 byte ct */
    if (size < 61) return 0;

    const unsigned char *key   = data;
    const unsigned char *nonce = data + 32;
    const unsigned char *tag   = data + 32 + 12;
    const unsigned char *ct    = data + 32 + 12 + 16;
    size_t ct_len = size - 60;

    unsigned char pt[4096];
    size_t use_len = ct_len < sizeof(pt) ? ct_len : sizeof(pt);

    /* Decrypt — returns 0 on auth failure, 1 on success. Must never crash. */
    aead_decrypt(pt, ct, use_len, tag, NULL, 0, key, nonce);

    return 0;
}
