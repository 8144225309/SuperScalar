#ifndef SUPERSCALAR_BIP39_H
#define SUPERSCALAR_BIP39_H

#include <stddef.h>

/*
 * BIP39 mnemonic word support.
 *
 * Converts between entropy bytes and mnemonic word sequences (12 or 24 words),
 * then derives a 64-byte BIP39 seed via PBKDF2-HMAC-SHA512 (2048 rounds).
 * The seed feeds into BIP32 (hd_key.h) to produce deterministic keys.
 */

/* Generate entropy and encode as mnemonic.
   word_count: 12 (128-bit) or 24 (256-bit).
   mnemonic_out: buffer for space-separated words (at least 256 bytes for 24 words).
   Returns 1 on success, 0 on error. */
int bip39_generate(int word_count, char *mnemonic_out, size_t mnemonic_max);

/* Encode entropy bytes to mnemonic words.
   entropy: 16 bytes (12 words) or 32 bytes (24 words).
   Returns 1 on success. */
int bip39_entropy_to_mnemonic(const unsigned char *entropy, size_t entropy_len,
                               char *mnemonic_out, size_t mnemonic_max);

/* Decode mnemonic words back to entropy bytes.
   Returns entropy length on success, 0 on error (bad word/checksum). */
size_t bip39_mnemonic_to_entropy(const char *mnemonic,
                                  unsigned char *entropy_out, size_t entropy_max);

/* Why a mnemonic is not acceptable. */
typedef enum {
    BIP39_OK = 0,
    BIP39_ERR_WORD_COUNT,     /* not 12, 15, 18, 21 or 24 words */
    BIP39_ERR_UNKNOWN_WORD,   /* a word is not in the English wordlist */
    BIP39_ERR_CHECKSUM        /* words are valid but the checksum is not */
} bip39_status_t;

/* Check a mnemonic: word count, wordlist membership, checksum.  Words may be
   separated and surrounded by any amount of ASCII whitespace. */
bip39_status_t bip39_check(const char *mnemonic);

/* Human-readable reason for a bip39_check() result. */
const char *bip39_status_str(bip39_status_t status);

/* Validate mnemonic: correct word count, all words in list, checksum OK.
   Returns 1 if valid, 0 if invalid. */
int bip39_validate(const char *mnemonic);

/* Write the canonical form of a valid mnemonic (words separated by exactly
   one space, no leading or trailing whitespace) to out.  out_max of 256 is
   enough for any phrase.  Returns 1 on success, 0 if the mnemonic is invalid
   or out is too small. */
int bip39_normalize(const char *mnemonic, char *out, size_t out_max);

/* Derive 64-byte BIP39 seed from mnemonic + optional passphrase.
   Uses PBKDF2-HMAC-SHA512 with 2048 iterations.
   The mnemonic must be valid (see bip39_check); it is normalised before
   derivation, so extra whitespace does not change the seed.  An invalid
   mnemonic is refused: nothing is derived and 0 is returned.
   passphrase may be NULL or "" for no passphrase.
   seed_out must be at least 64 bytes. Returns 1 on success. */
int bip39_mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                            unsigned char *seed_out);

#endif /* SUPERSCALAR_BIP39_H */
