#ifndef SUPERSCALAR_BECH32M_H
#define SUPERSCALAR_BECH32M_H

#include <stddef.h>

/*
 * BIP 350 bech32m encoder/decoder.
 *
 * bech32m constant: 0x2bc830a3
 * Charset: "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
 *
 * bech32m_encode: encode raw bytes as a bech32m string with the given HRP.
 *   hrp       : human-readable part (e.g. "lno", "lni")
 *   data      : raw bytes to encode
 *   data_len  : byte count
 *   out       : output buffer (must be at least bech32m_encode_len(hrp, data_len) bytes)
 *   out_cap   : capacity of out
 * Returns 1 on success, 0 on error (e.g. output buffer too small).
 *
 * bech32m_decode: decode a bech32m string into raw bytes.
 *   str          : null-terminated bech32m input string
 *   hrp_expected : expected HRP (case-insensitive); if NULL any HRP is accepted
 *   out          : caller-allocated output buffer for decoded bytes
 *   out_len      : set to number of decoded bytes on success
 *   out_cap      : capacity of out
 * Returns 1 on success (checksum valid, HRP matches), 0 on error.
 */

int bech32m_encode(const char *hrp,
                   const unsigned char *data, size_t data_len,
                   char *out, size_t out_cap);

int bech32m_decode(const char *str,
                   const char *hrp_expected,
                   unsigned char *out, size_t *out_len,
                   size_t out_cap);

#endif /* SUPERSCALAR_BECH32M_H */
