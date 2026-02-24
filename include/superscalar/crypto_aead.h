#ifndef SUPERSCALAR_CRYPTO_AEAD_H
#define SUPERSCALAR_CRYPTO_AEAD_H

#include <stdint.h>
#include <stddef.h>

/* ChaCha20 block function: transforms 16x uint32 state in place */
void chacha20_block(uint32_t out[16], const uint32_t in[16]);

/* ChaCha20 stream cipher (RFC 7539 Section 2.4).
   Encrypts/decrypts in-place: out = in XOR keystream.
   counter: initial block counter (usually 1 for AEAD). */
void chacha20_encrypt(unsigned char *out, const unsigned char *in, size_t len,
                      const unsigned char key[32], uint32_t counter,
                      const unsigned char nonce[12]);

/* Poly1305 one-shot MAC (RFC 7539 Section 2.5).
   Computes 16-byte tag over msg using one-time key. */
void poly1305_auth(unsigned char tag[16], const unsigned char *msg, size_t len,
                   const unsigned char key[32]);

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
