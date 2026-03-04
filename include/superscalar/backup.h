#ifndef SUPERSCALAR_BACKUP_H
#define SUPERSCALAR_BACKUP_H

#include <stddef.h>

/*
 * Encrypted backup archive format:
 *
 *   v1: [magic "SSBK0001" 8][version 1][salt 32][nonce 12][ciphertext N][tag 16]
 *       Key derivation: HKDF-SHA256(passphrase, salt)
 *
 *   v2: [magic "SSBK0002" 8][version 2][iters 4 BE][salt 32][nonce 12][ciphertext N][tag 16]
 *       Key derivation: PBKDF2-HMAC-SHA256(passphrase, salt, iters)
 *
 * Plaintext layout (before encryption):
 *   [db_len 4 LE][db_data ...][keyfile_len 4 LE][keyfile_data ...]
 *
 * Encryption: ChaCha20-Poly1305 AEAD (magic+version as AAD)
 */

#define BACKUP_MAGIC_V1 "SSBK0001"
#define BACKUP_MAGIC    "SSBK0002"
#define BACKUP_MAGIC_LEN 8
#define BACKUP_VERSION_V1 1
#define BACKUP_VERSION    2
#define BACKUP_SALT_LEN 32
#define BACKUP_NONCE_LEN 12
#define BACKUP_TAG_LEN 16
#define BACKUP_PBKDF2_ITERATIONS 600000
#define BACKUP_HEADER_LEN_V1 (BACKUP_MAGIC_LEN + 1 + BACKUP_SALT_LEN + BACKUP_NONCE_LEN)
#define BACKUP_HEADER_LEN (BACKUP_MAGIC_LEN + 1 + 4 + BACKUP_SALT_LEN + BACKUP_NONCE_LEN)

/* Create an encrypted backup of DB + keyfile.
   Returns 1 on success, 0 on error. */
int backup_create(const char *db_path, const char *keyfile_path,
                  const char *backup_path, const unsigned char *passphrase,
                  size_t passphrase_len);

/* Verify backup integrity without extracting.
   Returns 1 if valid, 0 on error or corrupt. */
int backup_verify(const char *backup_path, const unsigned char *passphrase,
                  size_t passphrase_len);

/* Restore DB + keyfile from encrypted backup.
   Returns 1 on success, 0 on error. */
int backup_restore(const char *backup_path, const char *dest_db_path,
                   const char *dest_keyfile_path, const unsigned char *passphrase,
                   size_t passphrase_len);

#endif /* SUPERSCALAR_BACKUP_H */
