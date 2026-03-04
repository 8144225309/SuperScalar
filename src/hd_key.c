#include "superscalar/hd_key.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>

extern void secure_zero(void *p, size_t n);

/* secp256k1 group order n (big-endian) */
static const unsigned char SECP256K1_ORDER[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};

/* Compare two 32-byte big-endian numbers. Returns -1, 0, or 1. */
static int cmp_be256(const unsigned char *a, const unsigned char *b) {
    for (int i = 0; i < 32; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

/* Check if 32-byte big-endian value is zero. */
static int is_zero_be256(const unsigned char *a) {
    for (int i = 0; i < 32; i++) {
        if (a[i] != 0) return 0;
    }
    return 1;
}

/* Add two 32-byte big-endian numbers modulo the secp256k1 order.
   result = (a + b) mod n. Returns 1 on success. */
static int add_mod_order(unsigned char *result,
                          const unsigned char *a,
                          const unsigned char *b) {
    /* Add with carry */
    unsigned char sum[32];
    uint16_t carry = 0;
    for (int i = 31; i >= 0; i--) {
        uint16_t s = (uint16_t)a[i] + (uint16_t)b[i] + carry;
        sum[i] = (unsigned char)(s & 0xFF);
        carry = s >> 8;
    }

    /* Reduce modulo n: if sum >= n, subtract n */
    if (carry || cmp_be256(sum, SECP256K1_ORDER) >= 0) {
        uint16_t borrow = 0;
        for (int i = 31; i >= 0; i--) {
            int16_t d = (int16_t)sum[i] - (int16_t)SECP256K1_ORDER[i] - borrow;
            if (d < 0) {
                d += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            result[i] = (unsigned char)d;
        }
    } else {
        memcpy(result, sum, 32);
    }

    secure_zero(sum, 32);
    return 1;
}

/* HMAC-SHA512 wrapper. */
static int hmac_sha512(const unsigned char *key, size_t key_len,
                        const unsigned char *data, size_t data_len,
                        unsigned char *out64) {
    unsigned int md_len = 64;
    unsigned char *result = HMAC(EVP_sha512(), key, (int)key_len,
                                  data, data_len, out64, &md_len);
    return (result != NULL && md_len == 64) ? 1 : 0;
}

int hd_key_from_seed(const unsigned char *seed, size_t seed_len,
                     unsigned char *master_key_out32,
                     unsigned char *chain_code_out32) {
    if (!seed || !master_key_out32 || !chain_code_out32 || seed_len == 0)
        return 0;

    static const unsigned char key[] = "Bitcoin seed";
    unsigned char I[64];

    if (!hmac_sha512(key, 12, seed, seed_len, I))
        return 0;

    /* IL = master secret key, IR = chain code */
    /* Validate: IL must be < n and non-zero (BIP32 spec) */
    if (is_zero_be256(I) || cmp_be256(I, SECP256K1_ORDER) >= 0) {
        secure_zero(I, 64);
        return 0;
    }

    memcpy(master_key_out32, I, 32);
    memcpy(chain_code_out32, I + 32, 32);
    secure_zero(I, 64);
    return 1;
}

int hd_key_derive_child(const unsigned char *parent_key32,
                         const unsigned char *parent_chain_code32,
                         uint32_t index,
                         unsigned char *child_key_out32,
                         unsigned char *child_chain_code_out32) {
    if (!parent_key32 || !parent_chain_code32 ||
        !child_key_out32 || !child_chain_code_out32)
        return 0;

    /* Only hardened derivation supported */
    if (!(index & HD_HARDENED))
        return 0;

    /* Data = 0x00 || parent_key (32 bytes) || index (4 bytes big-endian) = 37 bytes */
    unsigned char data[37];
    data[0] = 0x00;
    memcpy(data + 1, parent_key32, 32);
    data[33] = (unsigned char)((index >> 24) & 0xFF);
    data[34] = (unsigned char)((index >> 16) & 0xFF);
    data[35] = (unsigned char)((index >> 8) & 0xFF);
    data[36] = (unsigned char)(index & 0xFF);

    unsigned char I[64];
    if (!hmac_sha512(parent_chain_code32, 32, data, 37, I)) {
        secure_zero(data, 37);
        return 0;
    }
    secure_zero(data, 37);

    /* IL = left 32 bytes */
    unsigned char *IL = I;
    unsigned char *IR = I + 32;

    /* Validate IL < n */
    if (cmp_be256(IL, SECP256K1_ORDER) >= 0) {
        secure_zero(I, 64);
        return 0;
    }

    /* child_key = (IL + parent_key) mod n */
    if (!add_mod_order(child_key_out32, IL, parent_key32)) {
        secure_zero(I, 64);
        return 0;
    }

    /* child_key must not be zero */
    if (is_zero_be256(child_key_out32)) {
        secure_zero(I, 64);
        return 0;
    }

    memcpy(child_chain_code_out32, IR, 32);
    secure_zero(I, 64);
    return 1;
}

int hd_key_derive_path(const unsigned char *seed, size_t seed_len,
                       const char *path, unsigned char *key_out32) {
    if (!seed || !path || !key_out32 || seed_len == 0)
        return 0;

    /* Path must start with "m" */
    if (path[0] != 'm')
        return 0;

    unsigned char key[32], chain_code[32];
    if (!hd_key_from_seed(seed, seed_len, key, chain_code))
        return 0;

    const char *p = path + 1;
    while (*p) {
        if (*p == '/') {
            p++;
            /* Parse index */
            char *end;
            unsigned long idx = strtoul(p, &end, 10);
            if (end == p || idx > 0x7FFFFFFF) {
                secure_zero(key, 32);
                secure_zero(chain_code, 32);
                return 0;
            }
            p = end;

            /* Must be hardened (trailing ') */
            if (*p != '\'') {
                secure_zero(key, 32);
                secure_zero(chain_code, 32);
                return 0;
            }
            p++;

            uint32_t child_idx = (uint32_t)idx | HD_HARDENED;
            unsigned char child_key[32], child_cc[32];
            if (!hd_key_derive_child(key, chain_code, child_idx,
                                      child_key, child_cc)) {
                secure_zero(key, 32);
                secure_zero(chain_code, 32);
                return 0;
            }
            memcpy(key, child_key, 32);
            memcpy(chain_code, child_cc, 32);
            secure_zero(child_key, 32);
            secure_zero(child_cc, 32);
        } else {
            secure_zero(key, 32);
            secure_zero(chain_code, 32);
            return 0;
        }
    }

    memcpy(key_out32, key, 32);
    secure_zero(key, 32);
    secure_zero(chain_code, 32);
    return 1;
}
