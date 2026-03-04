#ifndef SUPERSCALAR_BACKUP_H
#define SUPERSCALAR_BACKUP_H

#include <stddef.h>

/*
 * Encrypted backup archive format:
 *   [magic 8][version 1][salt 32][nonce 12][ciphertext N][tag 16]
 *
 * Plaintext layout (before encryption):
 *   [db_len 4 LE][db_data ...][keyfile_len 4 LE][keyfile_data ...]
 *
 * Key derivation: HKDF-SHA256(passphrase, salt) -> 32-byte encryption key
 * Encryption: ChaCha20-Poly1305 AEAD (magic+version as AAD)
 */

#define BACKUP_MAGIC "SSBK0001"
#define BACKUP_MAGIC_LEN 8
#define BACKUP_VERSION 1
#define BACKUP_SALT_LEN 32
#define BACKUP_NONCE_LEN 12
#define BACKUP_TAG_LEN 16
#define BACKUP_HEADER_LEN (BACKUP_MAGIC_LEN + 1 + BACKUP_SALT_LEN + BACKUP_NONCE_LEN)

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
