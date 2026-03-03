/*
 * ChaCha20-Poly1305 AEAD per RFC 7539
 *
 * Uses OpenSSL EVP for side-channel hardening and hardware acceleration.
 */
#include "superscalar/crypto_aead.h"
#include "superscalar/types.h"
#include <string.h>
#include <openssl/evp.h>

#define AEAD_TAG_LEN 16

int aead_encrypt(unsigned char *ciphertext, unsigned char tag[16],
                 const unsigned char *plaintext, size_t pt_len,
                 const unsigned char *aad, size_t aad_len,
                 const unsigned char key[32], const unsigned char nonce[12]) {
    int ret = 0;
    int outlen = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1)
        goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1)
        goto cleanup;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    /* AAD */
    if (aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &outlen, aad, (int)aad_len) != 1)
            goto cleanup;
    }

    /* Encrypt */
    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, (int)pt_len) != 1)
        goto cleanup;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &outlen) != 1)
        goto cleanup;

    /* Get tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AEAD_TAG_LEN, tag) != 1)
        goto cleanup;

    ret = 1;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int aead_decrypt(unsigned char *plaintext,
                 const unsigned char *ciphertext, size_t ct_len,
                 const unsigned char tag[16],
                 const unsigned char *aad, size_t aad_len,
                 const unsigned char key[32], const unsigned char nonce[12]) {
    int ret = 0;
    int outlen = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1)
        goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1)
        goto cleanup;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    /* AAD */
    if (aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &outlen, aad, (int)aad_len) != 1)
            goto cleanup;
    }

    /* Decrypt */
    if (EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, (int)ct_len) != 1)
        goto cleanup;

    /* Set expected tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AEAD_TAG_LEN,
                            (void *)tag) != 1)
        goto cleanup;

    /* Verify tag */
    if (EVP_DecryptFinal_ex(ctx, plaintext + outlen, &outlen) != 1)
        goto cleanup;

    ret = 1;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}
