#ifndef SUPERSCALAR_CRYPTO_AEAD_H
#define SUPERSCALAR_CRYPTO_AEAD_H

#include <stddef.h>

/* AEAD encrypt: ChaCha20-Poly1305 (RFC 7539 Section 2.8).
   Encrypts plaintext, produces ciphertext (same length) and 16-byte tag.
   AAD (additional authenticated data) is authenticated but not encrypted.
   Returns 1 on success. */
int aead_encrypt(unsigned char *ciphertext, unsigned char tag[16],
                 const unsigned char *plaintext, size_t pt_len,
                 const unsigned char *aad, size_t aad_len,
                 const unsigned char key[32], const unsigned char nonce[12]);

/* AEAD decrypt: ChaCha20-Poly1305 (RFC 7539 Section 2.8).
   Decrypts ciphertext, verifies tag. Returns 1 on success, 0 on auth failure. */
int aead_decrypt(unsigned char *plaintext,
                 const unsigned char *ciphertext, size_t ct_len,
                 const unsigned char tag[16],
                 const unsigned char *aad, size_t aad_len,
                 const unsigned char key[32], const unsigned char nonce[12]);

#endif /* SUPERSCALAR_CRYPTO_AEAD_H */
