#ifndef SUPERSCALAR_KEYFILE_H
#define SUPERSCALAR_KEYFILE_H

#include <stddef.h>
#include <secp256k1.h>

/* Keyfile format: [12-byte nonce][32-byte encrypted key][16-byte tag] = 60 bytes */
#define KEYFILE_SIZE 60

/* Save secret key to encrypted file.
   Derives encryption key from passphrase via HKDF. */
int keyfile_save(const char *path, const unsigned char *seckey32,
                 const char *passphrase);

/* Load secret key from encrypted file. */
int keyfile_load(const char *path, unsigned char *seckey32_out,
                 const char *passphrase);

/* Generate random keypair and save to file. */
int keyfile_generate(const char *path, unsigned char *seckey32_out,
                     const char *passphrase, secp256k1_context *ctx);

#endif /* SUPERSCALAR_KEYFILE_H */
