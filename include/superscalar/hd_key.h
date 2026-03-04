#ifndef SUPERSCALAR_HD_KEY_H
#define SUPERSCALAR_HD_KEY_H

#include <stddef.h>
#include <stdint.h>

/* BIP32 hardened child index flag */
#define HD_HARDENED 0x80000000u

/* Derive master key and chain code from seed.
   seed: BIP39 seed bytes (typically 16-64 bytes).
   Uses HMAC-SHA512("Bitcoin seed", seed).
   Returns 1 on success, 0 on error (e.g., IL >= group order). */
int hd_key_from_seed(const unsigned char *seed, size_t seed_len,
                     unsigned char *master_key_out32,
                     unsigned char *chain_code_out32);

/* Derive a hardened child key.
   Only hardened derivation (index >= 0x80000000) is supported.
   Returns 1 on success, 0 on error. */
int hd_key_derive_child(const unsigned char *parent_key32,
                         const unsigned char *parent_chain_code32,
                         uint32_t index,
                         unsigned char *child_key_out32,
                         unsigned char *child_chain_code_out32);

/* Derive key at a BIP32 path string.
   Path format: "m/purpose'/coin'/account'" (e.g., "m/1039'/0'/0'").
   Only hardened components (with ') are accepted.
   Returns 1 on success, 0 on error (including non-hardened components). */
int hd_key_derive_path(const unsigned char *seed, size_t seed_len,
                       const char *path, unsigned char *key_out32);

#endif /* SUPERSCALAR_HD_KEY_H */
