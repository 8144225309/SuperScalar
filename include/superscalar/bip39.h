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

/* Validate mnemonic: correct word count, all words in list, checksum OK.
   Returns 1 if valid, 0 if invalid. */
int bip39_validate(const char *mnemonic);

/* Derive 64-byte BIP39 seed from mnemonic + optional passphrase.
   Uses PBKDF2-HMAC-SHA512 with 2048 iterations.
   passphrase may be NULL or "" for no passphrase.
   seed_out must be at least 64 bytes. Returns 1 on success. */
int bip39_mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                            unsigned char *seed_out);

#endif /* SUPERSCALAR_BIP39_H */
