#include "superscalar/backup.h"
#include "superscalar/crypto_aead.h"
#include "superscalar/keyfile.h"
#include "superscalar/secure_file.h"
#include "superscalar/types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>

/* From noise.c */
extern void hkdf_extract(unsigned char prk[32], const unsigned char *salt, size_t salt_len,
                          const unsigned char *ikm, size_t ikm_len);
extern void hkdf_expand(unsigned char *okm, size_t okm_len, const unsigned char prk[32],
                         const unsigned char *info, size_t info_len);

/* Read a whole regular file from an open descriptor into a malloc'd buffer.
   Caller frees.  Returns NULL on error. */
static unsigned char *read_fd(int fd, size_t *len_out) {
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0 ||
        st.st_size > 100 * 1024 * 1024)  /* 100MB sanity limit */
        return NULL;

    size_t size = (size_t)st.st_size;
    unsigned char *buf = malloc(size ? size : 1);
    if (!buf) return NULL;

    size_t n = 0;
    while (n < size) {
        ssize_t r = read(fd, buf + n, size - n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        n += (size_t)r;
    }
    if (n != size) { free(buf); return NULL; }

    *len_out = size;
    return buf;
}

/* Does this look like a keyfile (v1 or v2)? */
static int is_keyfile_content(const unsigned char *data, size_t len) {
    return len == KEYFILE_SIZE_V1 ||
           (len == KEYFILE_SIZE_V2 && memcmp(data, KEYFILE_MAGIC, 4) == 0);
}

/* Read entire file into malloc'd buffer. Caller frees. Returns NULL on error. */
static unsigned char *read_file(const char *path, size_t *len_out) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (fsize < 0 || fsize > 100 * 1024 * 1024) { /* 100MB sanity limit */
        fclose(fp);
        return NULL;
    }

    unsigned char *buf = malloc((size_t)fsize);
    if (!buf) { fclose(fp); return NULL; }

    size_t n = fread(buf, 1, (size_t)fsize, fp);
    fclose(fp);
    if (n != (size_t)fsize) { free(buf); return NULL; }

    *len_out = (size_t)fsize;
    return buf;
}

/* v1 KDF: HKDF-SHA256 (kept for reading old backups). */
static void derive_backup_key_v1(unsigned char key[32],
                                  const unsigned char *passphrase, size_t passphrase_len,
                                  const unsigned char salt[32]) {
    static const unsigned char info[] = "superscalar-backup-encryption";
    unsigned char prk[32];
    hkdf_extract(prk, salt, BACKUP_SALT_LEN, passphrase, passphrase_len);
    hkdf_expand(key, 32, prk, info, sizeof(info) - 1);
    secure_zero(prk, 32);
}

/* v2 KDF: PBKDF2-HMAC-SHA256 with configurable iterations. */
static int derive_backup_key_v2(unsigned char key[32],
                                 const unsigned char *passphrase, size_t passphrase_len,
                                 const unsigned char *salt, size_t salt_len,
                                 int iterations) {
    int ok = PKCS5_PBKDF2_HMAC((const char *)passphrase, (int)passphrase_len,
                                 salt, (int)salt_len,
                                 iterations, EVP_sha256(),
                                 32, key);
    return ok == 1;
}

/* Write len as 4 LE bytes into buf. */
static void write_u32_le(unsigned char *buf, uint32_t val) {
    buf[0] = (unsigned char)(val & 0xFF);
    buf[1] = (unsigned char)((val >> 8) & 0xFF);
    buf[2] = (unsigned char)((val >> 16) & 0xFF);
    buf[3] = (unsigned char)((val >> 24) & 0xFF);
}

/* Read 4 LE bytes from buf. */
static uint32_t read_u32_le(const unsigned char *buf) {
    return (uint32_t)buf[0]
         | ((uint32_t)buf[1] << 8)
         | ((uint32_t)buf[2] << 16)
         | ((uint32_t)buf[3] << 24);
}

int backup_create(const char *db_path, const char *keyfile_path,
                  const char *backup_path, const unsigned char *passphrase,
                  size_t passphrase_len) {
    if (!db_path || !keyfile_path || !backup_path || !passphrase || !passphrase_len)
        return 0;

    /* Read source files */
    size_t db_len = 0, kf_len = 0;
    unsigned char *db_data = read_file(db_path, &db_len);
    if (!db_data) return 0;

    /* The keyfile is read from the descriptor whose permissions are checked.
       A keyfile left group/world-accessible is tightened where that is ours
       to do (see secure_file_restrict); either way the backup goes ahead. */
    int kf_via_symlink = 0;
    int kf_fd = secure_file_open_read(keyfile_path, &kf_via_symlink);
    if (kf_fd < 0) { free(db_data); return 0; }
    unsigned char *kf_data = read_fd(kf_fd, &kf_len);
    if (kf_data && is_keyfile_content(kf_data, kf_len))
        (void)secure_file_restrict(kf_fd, keyfile_path, kf_via_symlink);
    close(kf_fd);
    if (!kf_data) { free(db_data); return 0; }

    /* Build plaintext: [db_len:4][db_data][kf_len:4][kf_data] */
    size_t pt_len = 4 + db_len + 4 + kf_len;
    unsigned char *plaintext = malloc(pt_len);
    if (!plaintext) { free(db_data); free(kf_data); return 0; }

    write_u32_le(plaintext, (uint32_t)db_len);
    memcpy(plaintext + 4, db_data, db_len);
    write_u32_le(plaintext + 4 + db_len, (uint32_t)kf_len);
    memcpy(plaintext + 4 + db_len + 4, kf_data, kf_len);

    free(db_data);
    free(kf_data);

    /* Generate random salt + nonce */
    unsigned char salt[BACKUP_SALT_LEN];
    unsigned char nonce[BACKUP_NONCE_LEN];
    FILE *urand = fopen("/dev/urandom", "rb");
    if (!urand) { free(plaintext); return 0; }
    int ok = (fread(salt, 1, BACKUP_SALT_LEN, urand) == BACKUP_SALT_LEN)
          && (fread(nonce, 1, BACKUP_NONCE_LEN, urand) == BACKUP_NONCE_LEN);
    fclose(urand);
    if (!ok) { free(plaintext); return 0; }

    /* Derive key via PBKDF2 */
    unsigned char key[32];
    if (!derive_backup_key_v2(key, passphrase, passphrase_len,
                               salt, BACKUP_SALT_LEN, BACKUP_PBKDF2_ITERATIONS)) {
        free(plaintext);
        return 0;
    }

    /* Build AAD = magic + version */
    unsigned char aad[BACKUP_MAGIC_LEN + 1];
    memcpy(aad, BACKUP_MAGIC, BACKUP_MAGIC_LEN);
    aad[BACKUP_MAGIC_LEN] = BACKUP_VERSION;

    /* Encrypt */
    unsigned char *ciphertext = malloc(pt_len);
    unsigned char tag[BACKUP_TAG_LEN];
    if (!ciphertext) {
        secure_zero(key, 32);
        free(plaintext);
        return 0;
    }

    int enc_ok = aead_encrypt(ciphertext, tag, plaintext, pt_len,
                               aad, sizeof(aad), key, nonce);
    secure_zero(key, 32);
    secure_zero(plaintext, pt_len);
    free(plaintext);

    if (!enc_ok) { free(ciphertext); return 0; }

    /* Assemble the file (v2: magic + version + iters_BE + salt + nonce + ct + tag)
       and write it in one atomic step: a failed write is reported and leaves
       a backup already at backup_path intact. */
    size_t out_len = BACKUP_HEADER_LEN + pt_len + BACKUP_TAG_LEN;
    unsigned char *out = malloc(out_len);
    if (!out) { free(ciphertext); return 0; }

    unsigned char *o = out;
    memcpy(o, BACKUP_MAGIC, BACKUP_MAGIC_LEN);
    o += BACKUP_MAGIC_LEN;
    *o++ = BACKUP_VERSION;
    uint32_t iters = BACKUP_PBKDF2_ITERATIONS;
    *o++ = (unsigned char)(iters >> 24);
    *o++ = (unsigned char)(iters >> 16);
    *o++ = (unsigned char)(iters >> 8);
    *o++ = (unsigned char)(iters);
    memcpy(o, salt, BACKUP_SALT_LEN);
    o += BACKUP_SALT_LEN;
    memcpy(o, nonce, BACKUP_NONCE_LEN);
    o += BACKUP_NONCE_LEN;
    memcpy(o, ciphertext, pt_len);
    o += pt_len;
    memcpy(o, tag, BACKUP_TAG_LEN);
    free(ciphertext);

    int written = secure_file_write_atomic(backup_path, out, out_len, 1);
    free(out);
    return written;
}

/* Internal: decrypt backup, return plaintext. Auto-detects v1/v2. Caller frees. */
static unsigned char *backup_decrypt(const char *backup_path,
                                      const unsigned char *passphrase,
                                      size_t passphrase_len,
                                      size_t *pt_len_out) {
    if (!backup_path || !passphrase || !passphrase_len)
        return NULL;

    /* One descriptor is opened, read, and (once the content is known to be a
       backup) has its permissions checked. */
    int via_symlink = 0;
    int fd = secure_file_open_read(backup_path, &via_symlink);
    if (fd < 0) return NULL;
    size_t file_len = 0;
    unsigned char *file_data = read_fd(fd, &file_len);
    if (!file_data) { close(fd); return NULL; }

    /* Determine format by magic bytes */
    int is_v2 = 0;
    if (file_len > BACKUP_MAGIC_LEN &&
        memcmp(file_data, BACKUP_MAGIC, BACKUP_MAGIC_LEN) == 0 &&
        file_data[BACKUP_MAGIC_LEN] == BACKUP_VERSION) {
        is_v2 = 1;
    }

    size_t hdr_len = is_v2 ? BACKUP_HEADER_LEN : BACKUP_HEADER_LEN_V1;

    /* Validate minimum size */
    if (file_len < hdr_len + BACKUP_TAG_LEN) {
        close(fd);
        free(file_data);
        return NULL;
    }

    /* v1: check magic "SSBK0001" + version 1 */
    if (!is_v2) {
        if (memcmp(file_data, BACKUP_MAGIC_V1, BACKUP_MAGIC_LEN) != 0 ||
            file_data[BACKUP_MAGIC_LEN] != BACKUP_VERSION_V1) {
            close(fd);
            free(file_data);
            return NULL;
        }
    }

    /* It is a backup.  One left group/world-accessible is tightened where
       that is ours to do; where it is not (read-only media, another owner, a
       link) it is still read. */
    (void)secure_file_restrict(fd, backup_path, via_symlink);
    close(fd);

    const unsigned char *salt;
    const unsigned char *nonce_ptr;
    unsigned char key[32];
    unsigned char aad[BACKUP_MAGIC_LEN + 1];

    if (is_v2) {
        /* v2: [magic 8][ver 1][iters_BE 4][salt 32][nonce 12][ct][tag 16] */
        uint32_t iters = ((uint32_t)file_data[9] << 24)
                       | ((uint32_t)file_data[10] << 16)
                       | ((uint32_t)file_data[11] << 8)
                       | (uint32_t)file_data[12];
        salt = file_data + 13;
        nonce_ptr = salt + BACKUP_SALT_LEN;

        if (iters < BACKUP_PBKDF2_MIN_ITERATIONS ||
            iters > BACKUP_PBKDF2_MAX_ITERATIONS) {
            free(file_data);
            return NULL;
        }
        if (!derive_backup_key_v2(key, passphrase, passphrase_len,
                                   salt, BACKUP_SALT_LEN, (int)iters)) {
            free(file_data);
            return NULL;
        }
        memcpy(aad, BACKUP_MAGIC, BACKUP_MAGIC_LEN);
        aad[BACKUP_MAGIC_LEN] = BACKUP_VERSION;
    } else {
        /* v1: [magic 8][ver 1][salt 32][nonce 12][ct][tag 16] */
        salt = file_data + BACKUP_MAGIC_LEN + 1;
        nonce_ptr = salt + BACKUP_SALT_LEN;

        derive_backup_key_v1(key, passphrase, passphrase_len, salt);
        memcpy(aad, BACKUP_MAGIC_V1, BACKUP_MAGIC_LEN);
        aad[BACKUP_MAGIC_LEN] = BACKUP_VERSION_V1;
    }

    const unsigned char *ct = file_data + hdr_len;
    size_t ct_len = file_len - hdr_len - BACKUP_TAG_LEN;
    const unsigned char *tag = ct + ct_len;

    /* Decrypt */
    unsigned char *plaintext = malloc(ct_len);
    if (!plaintext) {
        secure_zero(key, 32);
        free(file_data);
        return NULL;
    }

    int dec_ok = aead_decrypt(plaintext, ct, ct_len, tag,
                               aad, sizeof(aad), key, nonce_ptr);
    secure_zero(key, 32);
    free(file_data);

    if (!dec_ok) {
        free(plaintext);
        return NULL;
    }

    *pt_len_out = ct_len;
    return plaintext;
}

int backup_verify(const char *backup_path, const unsigned char *passphrase,
                  size_t passphrase_len) {
    size_t pt_len = 0;
    unsigned char *pt = backup_decrypt(backup_path, passphrase, passphrase_len, &pt_len);
    if (!pt) return 0;

    /* Validate internal structure: must have at least 8 bytes for two length fields */
    int valid = 0;
    if (pt_len >= 8) {
        size_t db_len = read_u32_le(pt);
        if (db_len <= pt_len - 8) {
            size_t kf_len = read_u32_le(pt + 4 + db_len);
            if (kf_len == pt_len - 8 - db_len)
                valid = 1;
        }
    }

    secure_zero(pt, pt_len);
    free(pt);
    return valid;
}

const char *backup_restore_blocked_by(const char *dest_db_path,
                                     const char *dest_keyfile_path,
                                     char *buf, size_t buf_len) {
    if (!dest_db_path || !dest_keyfile_path || !buf || buf_len == 0) return NULL;

    /* The SQLite sidecars count too: a write-ahead log or rollback journal
       left over from another database would be replayed into the restored
       one. */
    static const char *const db_suffixes[] = { "", "-wal", "-shm", "-journal" };
    for (size_t i = 0; i < sizeof(db_suffixes) / sizeof(db_suffixes[0]); i++) {
        int n = snprintf(buf, buf_len, "%s%s", dest_db_path, db_suffixes[i]);
        if (n < 0 || (size_t)n >= buf_len || secure_file_exists(buf)) return buf;
    }
    int n = snprintf(buf, buf_len, "%s", dest_keyfile_path);
    if (n < 0 || (size_t)n >= buf_len || secure_file_exists(buf)) return buf;
    return NULL;
}

int backup_restore(const char *backup_path, const char *dest_db_path,
                   const char *dest_keyfile_path, const unsigned char *passphrase,
                   size_t passphrase_len) {
    if (!dest_db_path || !dest_keyfile_path) return 0;

    /* A restore never replaces anything: the files already there may be the
       only copy of a key or of channel state. */
    char blocker[4096];
    if (backup_restore_blocked_by(dest_db_path, dest_keyfile_path,
                                  blocker, sizeof(blocker)))
        return 0;

    size_t pt_len = 0;
    unsigned char *pt = backup_decrypt(backup_path, passphrase, passphrase_len, &pt_len);
    if (!pt) return 0;

    /* Parse plaintext: [db_len:4][db_data][kf_len:4][kf_data] */
    int ok = 0;
    char *staged_db = NULL, *staged_kf = NULL;
    if (pt_len < 8) goto done;

    size_t db_len = read_u32_le(pt);
    if (db_len > pt_len - 8) goto done;

    size_t kf_len = read_u32_le(pt + 4 + db_len);
    if (kf_len != pt_len - 8 - db_len) goto done;

    const unsigned char *db_data = pt + 4;
    const unsigned char *kf_data = pt + 4 + db_len + 4;

    /* Write both files completely before either appears at its destination,
       so a failed write leaves nothing behind. */
    staged_db = secure_file_stage(dest_db_path, db_data, db_len);
    if (!staged_db) goto done;
    staged_kf = secure_file_stage(dest_keyfile_path, kf_data, kf_len);
    if (!staged_kf) goto done;

    /* The keyfile goes into place first.  If the process dies between the two
       steps, what is left is the key without a database: a later start loads
       that key and begins with empty state.  The other order would leave a
       database with no key, and a later start would create a new, unrelated
       key beside it. */
    int kf_placed = secure_file_commit(staged_kf, dest_keyfile_path, 0);
    staged_kf = NULL;
    if (!kf_placed) goto done;

    int db_placed = secure_file_commit(staged_db, dest_db_path, 0);
    staged_db = NULL;
    if (!db_placed) {
        /* Nothing was at dest_keyfile_path before this call: take it back
           out, and say so if that fails, because the restore is then
           incomplete rather than undone. */
        if (remove(dest_keyfile_path) != 0)
            fprintf(stderr,
                "Error: the restore failed after the keyfile had been written, and\n"
                "  %s could not be removed (%s).\n"
                "  Remove it by hand before running --restore again.\n",
                dest_keyfile_path, strerror(errno));
        goto done;
    }
    ok = 1;

done:
    secure_file_discard(staged_db);
    secure_file_discard(staged_kf);
    secure_zero(pt, pt_len);
    free(pt);
    return ok;
}
