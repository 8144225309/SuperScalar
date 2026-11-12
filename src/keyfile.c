#include "superscalar/keyfile.h"
#include "superscalar/hd_key.h"
#include "superscalar/secure_file.h"
#include "superscalar/types.h"
#include <secp256k1_extrakeys.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>

/* From noise.c */
extern void hkdf_extract(unsigned char prk[32], const unsigned char *salt, size_t salt_len,
                          const unsigned char *ikm, size_t ikm_len);
extern void hkdf_expand(unsigned char *okm, size_t okm_len, const unsigned char prk[32],
                         const unsigned char *info, size_t info_len);

/* From crypto_aead.c */
extern int aead_encrypt(unsigned char *ciphertext, unsigned char tag[16],
                         const unsigned char *plaintext, size_t pt_len,
                         const unsigned char *aad, size_t aad_len,
                         const unsigned char key[32], const unsigned char nonce[12]);
extern int aead_decrypt(unsigned char *plaintext,
                         const unsigned char *ciphertext, size_t ct_len,
                         const unsigned char tag[16],
                         const unsigned char *aad, size_t aad_len,
                         const unsigned char key[32], const unsigned char nonce[12]);

/* Legacy v1 KDF: single HMAC via HKDF (kept for loading old keyfiles). */
static void derive_key_v1(unsigned char *key_out32, const char *passphrase) {
    static const unsigned char salt[] = "superscalar-keyfile-v1";
    static const unsigned char info[] = "keyfile-encryption";

    unsigned char prk[32];
    hkdf_extract(prk, salt, sizeof(salt) - 1,
                 (const unsigned char *)passphrase, strlen(passphrase));
    hkdf_expand(key_out32, 32, prk, info, sizeof(info) - 1);
    secure_zero(prk, 32);
}

/* v2 KDF: PBKDF2-HMAC-SHA256 with configurable iterations. */
static int derive_key_v2(unsigned char *key_out32, const char *passphrase,
                          const unsigned char *salt, size_t salt_len,
                          int iterations) {
    int ok = PKCS5_PBKDF2_HMAC(passphrase, (int)strlen(passphrase),
                                 salt, (int)salt_len,
                                 iterations, EVP_sha256(),
                                 32, key_out32);
    return ok == 1;
}

/* Encrypt seckey32 and write it to path in v2 format.  replace selects whether
   a file already at path is replaced or makes the call fail. */
static int keyfile_write(const char *path, const unsigned char *seckey32,
                         const char *passphrase, int replace) {
    if (!path || !seckey32 || !passphrase) return 0;

    /* v2 format: [magic:4][iters_BE:4][salt:16][nonce:12][ct:32][tag:16] = 84 bytes */
    unsigned char file[KEYFILE_SIZE_V2];
    unsigned char *salt = file + 8;
    unsigned char *nonce = file + 24;
    unsigned char *ciphertext = file + 36;
    unsigned char *tag = file + 68;

    memcpy(file, KEYFILE_MAGIC, 4);
    uint32_t iters = KEYFILE_PBKDF2_ITERATIONS;
    file[4] = (unsigned char)((iters >> 24) & 0xFF);
    file[5] = (unsigned char)((iters >> 16) & 0xFF);
    file[6] = (unsigned char)((iters >> 8) & 0xFF);
    file[7] = (unsigned char)(iters & 0xFF);

    /* Generate random salt and nonce */
    FILE *urand = fopen("/dev/urandom", "rb");
    if (!urand) return 0;
    if (fread(salt, 1, 16, urand) != 16 ||
        fread(nonce, 1, 12, urand) != 12) {
        fclose(urand);
        return 0;
    }
    fclose(urand);

    /* Derive encryption key via PBKDF2 */
    unsigned char enc_key[32];
    if (!derive_key_v2(enc_key, passphrase, salt, 16, KEYFILE_PBKDF2_ITERATIONS)) {
        return 0;
    }

    int ok = aead_encrypt(ciphertext, tag, seckey32, 32, NULL, 0, enc_key, nonce);
    secure_zero(enc_key, 32);
    if (!ok) return 0;

    return secure_file_write_atomic(path, file, sizeof(file), replace);
}

int keyfile_save(const char *path, const unsigned char *seckey32,
                 const char *passphrase) {
    return keyfile_write(path, seckey32, passphrase, 1);
}

typedef enum {
    LOAD_OK = 0,
    LOAD_FAILED,        /* missing, unreadable, not a keyfile, wrong passphrase */
    LOAD_INSECURE_MODE  /* a keyfile, but readable by every user: not used */
} load_result_t;

static load_result_t keyfile_decrypt(const unsigned char *buf, size_t n,
                                     unsigned char *seckey32_out,
                                     const char *passphrase);

static load_result_t keyfile_load_checked(const char *path,
                                          unsigned char *seckey32_out,
                                          const char *passphrase) {
    if (!path || !seckey32_out || !passphrase) return LOAD_FAILED;

    int via_symlink = 0;
    int fd = secure_file_open_read(path, &via_symlink);
    if (fd < 0) return LOAD_FAILED;

    /* Read one byte more than a keyfile holds, to see where the file ends. */
    unsigned char buf[KEYFILE_SIZE_V2 + 1];
    size_t n = 0;
    for (;;) {
        ssize_t r = read(fd, buf + n, sizeof(buf) - n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        n += (size_t)r;
        if (n == sizeof(buf)) break;
    }

    int is_keyfile = (n == KEYFILE_SIZE_V2 && memcmp(buf, KEYFILE_MAGIC, 4) == 0) ||
                     n == KEYFILE_SIZE_V1;
    if (!is_keyfile) {
        /* Not a keyfile: its permissions are none of our business. */
        close(fd);
        secure_zero(buf, sizeof(buf));
        return LOAD_FAILED;
    }

    /* The key must not be readable by other users.  Where the file is ours
       to change it is tightened to 0600.  Where it is not (another owner, a
       read-only mount, a link):
         - group access is accepted with a warning: that is how a key is
           shared with a service account;
         - world access is refused: the key is not used. */
    struct stat st;
    unsigned mode = fstat(fd, &st) == 0 ? (unsigned)(st.st_mode & 0777) : 0;
    secure_file_access_t access = secure_file_restrict(fd, path, via_symlink);
    close(fd);
    if (access == SECURE_FILE_WORLD_ACCESSIBLE) {
        fprintf(stderr,
            "Error: keyfile %s is readable by every user on this host (mode 0%o)\n"
            "  and its mode could not be changed, so it is not used.\n"
            "  As the file's owner run: chmod 600 %s\n"
            "  (for a mounted secret, set the mount's file mode to 0400 or 0440).\n",
            path, mode, path);
        secure_zero(buf, sizeof(buf));
        return LOAD_INSECURE_MODE;
    }

    load_result_t result = keyfile_decrypt(buf, n, seckey32_out, passphrase);
    secure_zero(buf, sizeof(buf));
    return result;
}

int keyfile_load(const char *path, unsigned char *seckey32_out,
                 const char *passphrase) {
    return keyfile_load_checked(path, seckey32_out, passphrase) == LOAD_OK;
}

/* Decrypt the content of a recognised keyfile (v1 or v2). */
static load_result_t keyfile_decrypt(const unsigned char *buf, size_t n,
                                     unsigned char *seckey32_out,
                                     const char *passphrase) {
    if (n == KEYFILE_SIZE_V2 && memcmp(buf, KEYFILE_MAGIC, 4) == 0) {
        /* v2 format */
        uint32_t iters = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                          ((uint32_t)buf[6] << 8) | (uint32_t)buf[7];
        const unsigned char *salt = buf + 8;
        const unsigned char *nonce = buf + 24;
        const unsigned char *ciphertext = buf + 36;
        const unsigned char *tag = buf + 68;

        if (iters < KEYFILE_PBKDF2_MIN_ITERATIONS ||
            iters > KEYFILE_PBKDF2_MAX_ITERATIONS)
            return LOAD_FAILED;

        unsigned char enc_key[32];
        if (!derive_key_v2(enc_key, passphrase, salt, 16, (int)iters)) {
            return LOAD_FAILED;
        }

        int ok = aead_decrypt(seckey32_out, ciphertext, 32, tag,
                               NULL, 0, enc_key, nonce);
        secure_zero(enc_key, 32);
        return ok ? LOAD_OK : LOAD_FAILED;
    }

    if (n == KEYFILE_SIZE_V1) {
        /* v1 format: [nonce:12][ct:32][tag:16] */
        const unsigned char *nonce = buf;
        const unsigned char *ciphertext = buf + 12;
        const unsigned char *tag = buf + 44;

        unsigned char enc_key[32];
        derive_key_v1(enc_key, passphrase);

        int ok = aead_decrypt(seckey32_out, ciphertext, 32, tag,
                               NULL, 0, enc_key, nonce);
        secure_zero(enc_key, 32);
        return ok ? LOAD_OK : LOAD_FAILED;
    }

    return LOAD_FAILED; /* unknown format */
}

int keyfile_generate(const char *path, unsigned char *seckey32_out,
                     const char *passphrase, secp256k1_context *ctx) {
    if (!path || !seckey32_out || !passphrase || !ctx) return 0;

    /* Generate random secret key */
    FILE *urand = fopen("/dev/urandom", "rb");
    if (!urand) return 0;

    unsigned char seckey[32];
    int valid = 0;
    for (int attempts = 0; attempts < 100 && !valid; attempts++) {
        if (fread(seckey, 1, 32, urand) != 32) {
            fclose(urand);
            return 0;
        }
        /* Verify it's a valid secret key */
        secp256k1_keypair kp;
        valid = secp256k1_keypair_create(ctx, &kp, seckey);
    }
    fclose(urand);

    if (!valid) return 0;

    /* Save to file (v2 format); never over a file that is already there */
    if (!keyfile_write(path, seckey, passphrase, 0)) {
        secure_zero(seckey, 32);
        return 0;
    }

    memcpy(seckey32_out, seckey, 32);
    secure_zero(seckey, 32);
    return 1;
}

int keyfile_exists(const char *path) {
    /* Anything at the path counts, and so does a path that cannot be
       examined: only a definite "not there" allows a new key to be made. */
    return secure_file_exists(path);
}

keyfile_open_result_t keyfile_load_or_generate(const char *path,
                                               unsigned char *seckey32_out,
                                               const char *passphrase,
                                               secp256k1_context *ctx) {
    if (!path || !seckey32_out || !passphrase || !ctx)
        return KEYFILE_OPEN_GENERATE_FAILED;

    if (keyfile_exists(path)) {
        switch (keyfile_load_checked(path, seckey32_out, passphrase)) {
        case LOAD_OK:            return KEYFILE_OPEN_LOADED;
        case LOAD_INSECURE_MODE: return KEYFILE_OPEN_INSECURE_MODE;
        default:                 return KEYFILE_OPEN_LOAD_FAILED;
        }
    }

    return keyfile_generate(path, seckey32_out, passphrase, ctx)
               ? KEYFILE_OPEN_GENERATED : KEYFILE_OPEN_GENERATE_FAILED;
}

int keyfile_needs_upgrade(const char *path) {
    if (!path) return 0;
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;

    /* Check file size: v1 = 60, v2 = 84 */
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fclose(fp);

    return (size == KEYFILE_SIZE_V1) ? 1 : 0;
}

int keyfile_generate_from_seed(const char *path, unsigned char *seckey32_out,
                                const char *passphrase,
                                const unsigned char *seed, size_t seed_len,
                                const char *derivation_path) {
    if (!path || !seckey32_out || !passphrase || !seed || seed_len == 0)
        return 0;

    const char *dp = derivation_path ? derivation_path : "m/1039'/0'/0'";

    unsigned char derived_key[32];
    if (!hd_key_derive_path(seed, seed_len, dp, derived_key))
        return 0;

    if (!keyfile_write(path, derived_key, passphrase, 0)) {
        secure_zero(derived_key, 32);
        return 0;
    }

    memcpy(seckey32_out, derived_key, 32);
    secure_zero(derived_key, 32);
    return 1;
}
