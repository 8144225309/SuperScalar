#include "superscalar/backup.h"
#include "superscalar/crypto_aead.h"
#include "superscalar/types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

/* From noise.c */
extern void hkdf_extract(unsigned char prk[32], const unsigned char *salt, size_t salt_len,
                          const unsigned char *ikm, size_t ikm_len);
extern void hkdf_expand(unsigned char *okm, size_t okm_len, const unsigned char prk[32],
                         const unsigned char *info, size_t info_len);

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

    unsigned char *kf_data = read_file(keyfile_path, &kf_len);
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

    /* Write backup file (v2: magic + version + iters_BE + salt + nonce + ct + tag) */
    FILE *fp = fopen(backup_path, "wb");
    if (!fp) { free(ciphertext); return 0; }

    size_t written = 0;
    written += fwrite(BACKUP_MAGIC, 1, BACKUP_MAGIC_LEN, fp);
    unsigned char ver = BACKUP_VERSION;
    written += fwrite(&ver, 1, 1, fp);
    unsigned char iters_be[4];
    uint32_t iters = BACKUP_PBKDF2_ITERATIONS;
    iters_be[0] = (unsigned char)(iters >> 24);
    iters_be[1] = (unsigned char)(iters >> 16);
    iters_be[2] = (unsigned char)(iters >> 8);
    iters_be[3] = (unsigned char)(iters);
    written += fwrite(iters_be, 1, 4, fp);
    written += fwrite(salt, 1, BACKUP_SALT_LEN, fp);
    written += fwrite(nonce, 1, BACKUP_NONCE_LEN, fp);
    written += fwrite(ciphertext, 1, pt_len, fp);
    written += fwrite(tag, 1, BACKUP_TAG_LEN, fp);
    fclose(fp);
    free(ciphertext);

    return (written == BACKUP_HEADER_LEN + pt_len + BACKUP_TAG_LEN) ? 1 : 0;
}

/* Internal: decrypt backup, return plaintext. Auto-detects v1/v2. Caller frees. */
static unsigned char *backup_decrypt(const char *backup_path,
                                      const unsigned char *passphrase,
                                      size_t passphrase_len,
                                      size_t *pt_len_out) {
    if (!backup_path || !passphrase || !passphrase_len)
        return NULL;

    size_t file_len = 0;
    unsigned char *file_data = read_file(backup_path, &file_len);
    if (!file_data) return NULL;

    /* Determine format by magic bytes */
    int is_v2 = 0;
    if (file_len >= BACKUP_MAGIC_LEN &&
        memcmp(file_data, BACKUP_MAGIC, BACKUP_MAGIC_LEN) == 0 &&
        file_data[BACKUP_MAGIC_LEN] == BACKUP_VERSION) {
        is_v2 = 1;
    }

    size_t hdr_len = is_v2 ? BACKUP_HEADER_LEN : BACKUP_HEADER_LEN_V1;

    /* Validate minimum size */
    if (file_len < hdr_len + BACKUP_TAG_LEN) {
        free(file_data);
        return NULL;
    }

    /* v1: check magic "SSBK0001" + version 1 */
    if (!is_v2) {
        if (memcmp(file_data, BACKUP_MAGIC_V1, BACKUP_MAGIC_LEN) != 0 ||
            file_data[BACKUP_MAGIC_LEN] != BACKUP_VERSION_V1) {
            free(file_data);
            return NULL;
        }
    }

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
        uint32_t db_len = read_u32_le(pt);
        if (4 + db_len + 4 <= pt_len) {
            uint32_t kf_len = read_u32_le(pt + 4 + db_len);
            if (4 + db_len + 4 + kf_len == pt_len)
                valid = 1;
        }
    }

    secure_zero(pt, pt_len);
    free(pt);
    return valid;
}

int backup_restore(const char *backup_path, const char *dest_db_path,
                   const char *dest_keyfile_path, const unsigned char *passphrase,
                   size_t passphrase_len) {
    if (!dest_db_path || !dest_keyfile_path) return 0;

    size_t pt_len = 0;
    unsigned char *pt = backup_decrypt(backup_path, passphrase, passphrase_len, &pt_len);
    if (!pt) return 0;

    /* Parse plaintext */
    if (pt_len < 8) { free(pt); return 0; }

    uint32_t db_len = read_u32_le(pt);
    if (4 + db_len + 4 > pt_len) { free(pt); return 0; }

    uint32_t kf_len = read_u32_le(pt + 4 + db_len);
    if (4 + db_len + 4 + kf_len != pt_len) { free(pt); return 0; }

    const unsigned char *db_data = pt + 4;
    const unsigned char *kf_data = pt + 4 + db_len + 4;

    /* Write DB */
    FILE *fp = fopen(dest_db_path, "wb");
    if (!fp) { secure_zero(pt, pt_len); free(pt); return 0; }
    size_t w = fwrite(db_data, 1, db_len, fp);
    fclose(fp);
    if (w != db_len) { secure_zero(pt, pt_len); free(pt); return 0; }

    /* Write keyfile */
    fp = fopen(dest_keyfile_path, "wb");
    if (!fp) { secure_zero(pt, pt_len); free(pt); return 0; }
    w = fwrite(kf_data, 1, kf_len, fp);
    fclose(fp);

    int ok = (w == kf_len);
    secure_zero(pt, pt_len);
    free(pt);
    return ok;
}
