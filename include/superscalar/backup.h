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
/* Iteration counts accepted when reading a backup.  The count comes from the
   file, so it is bounded: a huge value would stall the reader. */
#define BACKUP_PBKDF2_MIN_ITERATIONS 100000
#define BACKUP_PBKDF2_MAX_ITERATIONS 10000000
#define BACKUP_HEADER_LEN_V1 (BACKUP_MAGIC_LEN + 1 + BACKUP_SALT_LEN + BACKUP_NONCE_LEN)
#define BACKUP_HEADER_LEN (BACKUP_MAGIC_LEN + 1 + 4 + BACKUP_SALT_LEN + BACKUP_NONCE_LEN)

/* Create an encrypted backup of DB + keyfile.
   The backup is written atomically with mode 0600; a backup already at
   backup_path is replaced only once the new one is complete on disk.
   Returns 1 on success, 0 on error (including a failed write). */
int backup_create(const char *db_path, const char *keyfile_path,
                  const char *backup_path, const unsigned char *passphrase,
                  size_t passphrase_len);

/* Verify backup integrity without extracting.
   Returns 1 if valid, 0 on error or corrupt.

   Permissions: when a backup is read (verify or restore), and when the
   keyfile is read for a new backup, a file that group or others can access
   is tightened to mode 0600, with a warning on stderr.  That happens only
   once the content is recognised as a backup (or keyfile), and only if it is
   a regular file owned by the caller with one hard link that is not reached
   through a symbolic link.  Anything else is left as it is, with a warning,
   and is still read: a backup on read-only media can be restored. */
int backup_verify(const char *backup_path, const unsigned char *passphrase,
                  size_t passphrase_len);

/* Restore DB + keyfile from encrypted backup.
   A restore never replaces anything: it fails without writing if anything
   exists at dest_db_path, at its SQLite sidecars (dest_db_path + "-wal",
   "-shm" and "-journal") or at dest_keyfile_path.

   Both files are written with mode 0600 and are complete on disk before
   either appears at its destination; the keyfile is put in place first, then
   the database.  A failure normally leaves neither behind.  It is not a
   single atomic step, though:
     - if the database cannot be put in place and the keyfile then cannot be
       removed again, the keyfile stays and an error naming it is printed;
     - if the process is killed between the two steps, the keyfile is there
       without the database.
   In both cases the next restore is refused until the keyfile is removed.
   Returns 1 on success, 0 on error. */
int backup_restore(const char *backup_path, const char *dest_db_path,
                   const char *dest_keyfile_path, const unsigned char *passphrase,
                   size_t passphrase_len);

/* The first path that stops a restore to these destinations because
   something already exists there (the database, its "-wal", "-shm" or
   "-journal" sidecar, or the keyfile), written to buf; NULL if nothing does. */
const char *backup_restore_blocked_by(const char *dest_db_path,
                                     const char *dest_keyfile_path,
                                     char *buf, size_t buf_len);

#endif /* SUPERSCALAR_BACKUP_H */
