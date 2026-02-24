#include "superscalar/keyfile.h"
#include <secp256k1_extrakeys.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

/* Derive a 32-byte encryption key from a passphrase using HKDF. */
static void derive_key(unsigned char *key_out32, const char *passphrase) {
    static const unsigned char salt[] = "superscalar-keyfile-v1";
    static const unsigned char info[] = "keyfile-encryption";

    unsigned char prk[32];
    hkdf_extract(prk, salt, sizeof(salt) - 1,
                 (const unsigned char *)passphrase, strlen(passphrase));
    hkdf_expand(key_out32, 32, prk, info, sizeof(info) - 1);
    memset(prk, 0, 32);
}

int keyfile_save(const char *path, const unsigned char *seckey32,
                 const char *passphrase) {
    if (!path || !seckey32 || !passphrase) return 0;

    /* Derive encryption key */
    unsigned char enc_key[32];
    derive_key(enc_key, passphrase);

    /* Generate random nonce */
    unsigned char nonce[12];
    FILE *urand = fopen("/dev/urandom", "rb");
    if (urand) {
        if (fread(nonce, 1, 12, urand) != 12) {
            fclose(urand);
            memset(enc_key, 0, 32);
            return 0;
        }
        fclose(urand);
    } else {
        /* Deterministic fallback for testing environments without /dev/urandom */
        memset(nonce, 0x01, 12);
    }

    /* Encrypt */
    unsigned char ciphertext[32];
    unsigned char tag[16];
    aead_encrypt(ciphertext, tag, seckey32, 32, NULL, 0, enc_key, nonce);

    /* Write: [nonce 12][ciphertext 32][tag 16] = 60 bytes */
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        memset(enc_key, 0, 32);
        return 0;
    }

    size_t written = 0;
    written += fwrite(nonce, 1, 12, fp);
    written += fwrite(ciphertext, 1, 32, fp);
    written += fwrite(tag, 1, 16, fp);
    fclose(fp);

    memset(enc_key, 0, 32);
    return (written == KEYFILE_SIZE) ? 1 : 0;
}

int keyfile_load(const char *path, unsigned char *seckey32_out,
                 const char *passphrase) {
    if (!path || !seckey32_out || !passphrase) return 0;

    /* Read file */
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;

    unsigned char buf[KEYFILE_SIZE];
    size_t n = fread(buf, 1, KEYFILE_SIZE, fp);
    fclose(fp);
    if (n != KEYFILE_SIZE) return 0;

    /* Parse components */
    unsigned char *nonce = buf;           /* 12 bytes */
    unsigned char *ciphertext = buf + 12; /* 32 bytes */
    unsigned char *tag = buf + 44;        /* 16 bytes */

    /* Derive decryption key */
    unsigned char enc_key[32];
    derive_key(enc_key, passphrase);

    /* Decrypt and verify */
    int ok = aead_decrypt(seckey32_out, ciphertext, 32, tag,
                           NULL, 0, enc_key, nonce);

    memset(enc_key, 0, 32);
    return ok ? 1 : 0;
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

    /* Save to file */
    if (!keyfile_save(path, seckey, passphrase)) {
        memset(seckey, 0, 32);
        return 0;
    }

    memcpy(seckey32_out, seckey, 32);
    memset(seckey, 0, 32);
    return 1;
}
