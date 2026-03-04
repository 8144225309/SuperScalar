#include "superscalar/bip39.h"
#include "superscalar/sha256.h"
#include "superscalar/types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#include "bip39_wordlist.h"

/* Binary search the sorted BIP39 wordlist. Returns index 0-2047 or -1. */
static int word_index(const char *word) {
    int lo = 0, hi = 2047;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int cmp = strcmp(word, bip39_wordlist_en[mid]);
        if (cmp == 0) return mid;
        if (cmp < 0) hi = mid - 1;
        else lo = mid + 1;
    }
    return -1;
}

int bip39_entropy_to_mnemonic(const unsigned char *entropy, size_t entropy_len,
                               char *mnemonic_out, size_t mnemonic_max) {
    if (!entropy || !mnemonic_out) return 0;

    /* BIP39: 128 bits (16 bytes) -> 12 words, 256 bits (32 bytes) -> 24 words */
    size_t cs_bits;  /* checksum bits */
    if (entropy_len == 16)      cs_bits = 4;
    else if (entropy_len == 20) cs_bits = 5;
    else if (entropy_len == 24) cs_bits = 6;
    else if (entropy_len == 28) cs_bits = 7;
    else if (entropy_len == 32) cs_bits = 8;
    else return 0;

    /* Compute SHA-256 checksum */
    unsigned char hash[32];
    sha256(entropy, entropy_len, hash);

    /* Build combined bit buffer: entropy || first cs_bits of hash */
    size_t total_bits = entropy_len * 8 + cs_bits;
    size_t n_words = total_bits / 11;

    /* We need entropy_len + 1 bytes to hold entropy + checksum byte */
    unsigned char *buf = malloc(entropy_len + 1);
    if (!buf) return 0;
    memcpy(buf, entropy, entropy_len);
    buf[entropy_len] = hash[0];  /* only need first byte for cs_bits <= 8 */

    /* Extract 11-bit groups */
    mnemonic_out[0] = '\0';
    size_t out_pos = 0;

    for (size_t w = 0; w < n_words; w++) {
        size_t bit_offset = w * 11;
        /* Extract 11 bits starting at bit_offset */
        int idx = 0;
        for (int b = 0; b < 11; b++) {
            size_t pos = bit_offset + (size_t)b;
            size_t byte_idx = pos / 8;
            int bit_idx = 7 - (int)(pos % 8);
            if (buf[byte_idx] & (1 << bit_idx))
                idx |= (1 << (10 - b));
        }

        const char *word = bip39_wordlist_en[idx];
        size_t wlen = strlen(word);

        if (w > 0) {
            if (out_pos + 1 >= mnemonic_max) { free(buf); return 0; }
            mnemonic_out[out_pos++] = ' ';
        }
        if (out_pos + wlen >= mnemonic_max) { free(buf); return 0; }
        memcpy(mnemonic_out + out_pos, word, wlen);
        out_pos += wlen;
    }

    mnemonic_out[out_pos] = '\0';
    free(buf);
    return 1;
}

size_t bip39_mnemonic_to_entropy(const char *mnemonic,
                                  unsigned char *entropy_out, size_t entropy_max) {
    if (!mnemonic || !entropy_out) return 0;

    /* Tokenize words — work on a copy */
    size_t mlen = strlen(mnemonic);
    char *copy = malloc(mlen + 1);
    if (!copy) return 0;
    memcpy(copy, mnemonic, mlen + 1);

    /* Count and collect word indices */
    int indices[24];
    size_t n_words = 0;

    char *saveptr = NULL;
    char *tok = strtok_r(copy, " \t\n", &saveptr);
    while (tok && n_words < 24) {
        int idx = word_index(tok);
        if (idx < 0) { free(copy); return 0; } /* unknown word */
        indices[n_words++] = idx;
        tok = strtok_r(NULL, " \t\n", &saveptr);
    }
    free(copy);

    /* Valid word counts: 12, 15, 18, 21, 24 */
    if (n_words < 12 || n_words > 24 || n_words % 3 != 0)
        return 0;

    size_t total_bits = n_words * 11;
    size_t cs_bits = total_bits / 33;  /* ENT/32 = cs_bits, total = ENT + cs */
    size_t ent_bits = total_bits - cs_bits;
    size_t ent_bytes = ent_bits / 8;

    if (ent_bytes > entropy_max) return 0;

    /* Reconstruct bit buffer from 11-bit indices */
    size_t buf_len = (total_bits + 7) / 8;
    unsigned char *buf = calloc(buf_len, 1);
    if (!buf) return 0;

    for (size_t w = 0; w < n_words; w++) {
        int idx = indices[w];
        size_t bit_offset = w * 11;
        for (int b = 0; b < 11; b++) {
            if (idx & (1 << (10 - b))) {
                size_t pos = bit_offset + (size_t)b;
                buf[pos / 8] |= (unsigned char)(1 << (7 - (pos % 8)));
            }
        }
    }

    /* Extract entropy (first ent_bytes) */
    memcpy(entropy_out, buf, ent_bytes);

    /* Verify checksum */
    unsigned char hash[32];
    sha256(entropy_out, ent_bytes, hash);

    /* Compare first cs_bits of hash with extracted checksum bits */
    unsigned char cs_from_data = buf[ent_bytes];
    unsigned char cs_from_hash = hash[0];
    /* Mask to cs_bits */
    unsigned char mask = (unsigned char)(0xFF << (8 - cs_bits));

    free(buf);

    if ((cs_from_data & mask) != (cs_from_hash & mask))
        return 0;  /* checksum mismatch */

    return ent_bytes;
}

int bip39_validate(const char *mnemonic) {
    unsigned char entropy[32];
    return bip39_mnemonic_to_entropy(mnemonic, entropy, sizeof(entropy)) > 0;
}

int bip39_generate(int word_count, char *mnemonic_out, size_t mnemonic_max) {
    size_t entropy_len;
    if (word_count == 12)      entropy_len = 16;
    else if (word_count == 15) entropy_len = 20;
    else if (word_count == 18) entropy_len = 24;
    else if (word_count == 21) entropy_len = 28;
    else if (word_count == 24) entropy_len = 32;
    else return 0;

    unsigned char entropy[32];
    FILE *urand = fopen("/dev/urandom", "rb");
    if (!urand) return 0;
    int ok = (fread(entropy, 1, entropy_len, urand) == entropy_len);
    fclose(urand);
    if (!ok) return 0;

    int ret = bip39_entropy_to_mnemonic(entropy, entropy_len, mnemonic_out, mnemonic_max);
    secure_zero(entropy, sizeof(entropy));
    return ret;
}

int bip39_mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                            unsigned char *seed_out) {
    if (!mnemonic || !seed_out) return 0;

    /* Salt = "mnemonic" + passphrase */
    const char *pass = passphrase ? passphrase : "";
    size_t salt_len = 8 + strlen(pass);
    char *salt = malloc(salt_len + 1);
    if (!salt) return 0;
    memcpy(salt, "mnemonic", 8);
    memcpy(salt + 8, pass, strlen(pass));
    salt[salt_len] = '\0';

    int ok = PKCS5_PBKDF2_HMAC(mnemonic, (int)strlen(mnemonic),
                                 (const unsigned char *)salt, (int)salt_len,
                                 2048, EVP_sha512(),
                                 64, seed_out);

    free(salt);
    return ok == 1;
}
