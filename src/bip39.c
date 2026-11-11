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

#define BIP39_MAX_WORDS 24
/* Longest wordlist entry is 8 letters. */
#define BIP39_MAX_WORD_LEN 8

static int is_separator(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

/* Split a phrase into wordlist indices.  Words may be separated, preceded and
   followed by any amount of ASCII whitespace.  Rejects words that are not in
   the wordlist and phrases whose length is not 12, 15, 18, 21 or 24 words. */
static bip39_status_t parse_words(const char *mnemonic,
                                  int indices[BIP39_MAX_WORDS], size_t *n_words_out) {
    size_t n_words = 0;
    const char *p = mnemonic;

    for (;;) {
        while (is_separator(*p)) p++;
        if (*p == '\0') break;

        const char *start = p;
        while (*p != '\0' && !is_separator(*p)) p++;
        size_t len = (size_t)(p - start);

        if (len > BIP39_MAX_WORD_LEN) return BIP39_ERR_UNKNOWN_WORD;
        char word[BIP39_MAX_WORD_LEN + 1];
        memcpy(word, start, len);
        word[len] = '\0';
        int idx = word_index(word);
        secure_zero(word, sizeof(word));
        if (idx < 0) return BIP39_ERR_UNKNOWN_WORD;

        if (n_words == BIP39_MAX_WORDS) return BIP39_ERR_WORD_COUNT;
        indices[n_words++] = idx;
    }

    if (n_words < 12 || n_words % 3 != 0) return BIP39_ERR_WORD_COUNT;

    *n_words_out = n_words;
    return BIP39_OK;
}

/* Parse and checksum-verify a phrase.  On success fills indices/n_words and,
   if entropy_out is non-NULL, the entropy (up to 32 bytes) and its length. */
static bip39_status_t decode(const char *mnemonic,
                             int indices[BIP39_MAX_WORDS], size_t *n_words_out,
                             unsigned char *entropy_out, size_t *entropy_len_out) {
    if (!mnemonic) return BIP39_ERR_WORD_COUNT;

    size_t n_words = 0;
    bip39_status_t st = parse_words(mnemonic, indices, &n_words);
    if (st != BIP39_OK) return st;

    size_t total_bits = n_words * 11;
    size_t cs_bits = total_bits / 33;  /* ENT/32 = cs_bits, total = ENT + cs */
    size_t ent_bytes = (total_bits - cs_bits) / 8;

    /* Reconstruct bit buffer from 11-bit indices: 24 words = 264 bits = 33 bytes */
    unsigned char buf[33];
    memset(buf, 0, sizeof(buf));
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

    /* Compare the first cs_bits of SHA-256(entropy) with the checksum bits */
    unsigned char hash[32];
    sha256(buf, ent_bytes, hash);
    unsigned char mask = (unsigned char)(0xFF << (8 - cs_bits));
    int cs_ok = (buf[ent_bytes] & mask) == (hash[0] & mask);

    if (cs_ok) {
        if (entropy_out) memcpy(entropy_out, buf, ent_bytes);
        if (entropy_len_out) *entropy_len_out = ent_bytes;
        if (n_words_out) *n_words_out = n_words;
    }
    secure_zero(buf, sizeof(buf));
    secure_zero(hash, sizeof(hash));
    return cs_ok ? BIP39_OK : BIP39_ERR_CHECKSUM;
}

size_t bip39_mnemonic_to_entropy(const char *mnemonic,
                                  unsigned char *entropy_out, size_t entropy_max) {
    if (!mnemonic || !entropy_out) return 0;

    int indices[BIP39_MAX_WORDS];
    unsigned char entropy[32];
    size_t ent_bytes = 0;
    bip39_status_t st = decode(mnemonic, indices, NULL, entropy, &ent_bytes);
    secure_zero(indices, sizeof(indices));

    if (st == BIP39_OK && ent_bytes <= entropy_max)
        memcpy(entropy_out, entropy, ent_bytes);
    else
        ent_bytes = 0;
    secure_zero(entropy, sizeof(entropy));
    return ent_bytes;
}

bip39_status_t bip39_check(const char *mnemonic) {
    int indices[BIP39_MAX_WORDS];
    bip39_status_t st = decode(mnemonic, indices, NULL, NULL, NULL);
    secure_zero(indices, sizeof(indices));
    return st;
}

const char *bip39_status_str(bip39_status_t status) {
    switch (status) {
    case BIP39_OK:
        return "valid";
    case BIP39_ERR_WORD_COUNT:
        return "a recovery phrase has 12, 15, 18, 21 or 24 words";
    case BIP39_ERR_UNKNOWN_WORD:
        return "it contains a word that is not in the BIP39 English wordlist "
               "(words are lower-case)";
    case BIP39_ERR_CHECKSUM:
        return "the checksum does not match (a word is wrong or out of order)";
    }
    return "invalid";
}

int bip39_validate(const char *mnemonic) {
    return bip39_check(mnemonic) == BIP39_OK;
}

int bip39_normalize(const char *mnemonic, char *out, size_t out_max) {
    if (!out || out_max == 0) return 0;
    out[0] = '\0';

    int indices[BIP39_MAX_WORDS];
    size_t n_words = 0;
    if (decode(mnemonic, indices, &n_words, NULL, NULL) != BIP39_OK) {
        secure_zero(indices, sizeof(indices));
        return 0;
    }

    size_t pos = 0;
    int ok = 1;
    for (size_t w = 0; w < n_words && ok; w++) {
        const char *word = bip39_wordlist_en[indices[w]];
        size_t wlen = strlen(word);
        if (pos + (w > 0) + wlen >= out_max) {
            ok = 0;
            break;
        }
        if (w > 0) out[pos++] = ' ';
        memcpy(out + pos, word, wlen);
        pos += wlen;
    }
    secure_zero(indices, sizeof(indices));

    if (!ok) {
        secure_zero(out, out_max);
        return 0;
    }
    out[pos] = '\0';
    return 1;
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

    /* The seed is a hash of the phrase text, so any phrase would "work" and a
       typo would silently give a different wallet.  Only a phrase that passes
       validation is used, in its canonical single-space form. */
    char words[BIP39_MAX_WORDS * (BIP39_MAX_WORD_LEN + 1)];
    if (!bip39_normalize(mnemonic, words, sizeof(words))) return 0;

    /* Salt = "mnemonic" + passphrase */
    const char *pass = passphrase ? passphrase : "";
    size_t salt_len = 8 + strlen(pass);
    char *salt = malloc(salt_len + 1);
    if (!salt) {
        secure_zero(words, sizeof(words));
        return 0;
    }
    memcpy(salt, "mnemonic", 8);
    memcpy(salt + 8, pass, strlen(pass));
    salt[salt_len] = '\0';

    int ok = PKCS5_PBKDF2_HMAC(words, (int)strlen(words),
                                 (const unsigned char *)salt, (int)salt_len,
                                 2048, EVP_sha512(),
                                 64, seed_out);

    secure_zero(words, sizeof(words));
    secure_zero(salt, salt_len);
    free(salt);
    return ok == 1;
}
