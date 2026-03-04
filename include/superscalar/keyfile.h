#ifndef SUPERSCALAR_KEYFILE_H
#define SUPERSCALAR_KEYFILE_H

#include <stddef.h>
#include <secp256k1.h>

/* v1 format: [nonce:12][ct:32][tag:16] = 60 bytes (HKDF, 1 HMAC) */
#define KEYFILE_SIZE_V1 60
#define KEYFILE_SIZE    KEYFILE_SIZE_V1  /* backward compat for existing code */

/* v2 format: [magic "SK02":4][iters BE:4][salt:16][nonce:12][ct:32][tag:16] = 84 bytes */
#define KEYFILE_SIZE_V2 84
#define KEYFILE_PBKDF2_ITERATIONS 600000
#define KEYFILE_MAGIC "SK02"

/* Save secret key to encrypted file (always writes v2 format).
   Derives encryption key from passphrase via PBKDF2-HMAC-SHA256 (600K iterations). */
int keyfile_save(const char *path, const unsigned char *seckey32,
                 const char *passphrase);

/* Load secret key from encrypted file (auto-detects v1 or v2). */
int keyfile_load(const char *path, unsigned char *seckey32_out,
                 const char *passphrase);

/* Generate random keypair and save to file (v2 format). */
int keyfile_generate(const char *path, unsigned char *seckey32_out,
                     const char *passphrase, secp256k1_context *ctx);

/* Check if keyfile needs upgrade (returns 1 if v1 format). */
int keyfile_needs_upgrade(const char *path);

/* Generate key from HD seed and save to file (v2 format). */
int keyfile_generate_from_seed(const char *path, unsigned char *seckey32_out,
                                const char *passphrase,
                                const unsigned char *seed, size_t seed_len,
                                const char *derivation_path);

#endif /* SUPERSCALAR_KEYFILE_H */
