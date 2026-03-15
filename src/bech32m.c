#include "superscalar/bech32m.h"
#include <stdint.h>
#include <string.h>
#include <ctype.h>

/* BIP 350 bech32m constant */
#define BECH32M_CONST 0x2bc830a3UL

/* Maximum sizes for internal buffers */
#define BECH32M_MAX_HRP   83
#define BECH32M_MAX_DATA5 1024

/* bech32m charset */
static const char CHARSET[32] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/* Reverse lookup: maps ASCII char → 5-bit value, or -1 for invalid */
static int8_t charset_rev[128];
static int charset_rev_init = 0;

static void init_charset_rev(void) {
    if (charset_rev_init) return;
    for (int i = 0; i < 128; i++) charset_rev[i] = -1;
    for (int i = 0; i < 32; i++) {
        charset_rev[(unsigned char)CHARSET[i]] = (int8_t)i;
    }
    charset_rev_init = 1;
}

/* BIP 173/350 GF(2^32) polymod */
static uint32_t bech32_polymod(const uint8_t *values, size_t len) {
    uint32_t c = 1;
    for (size_t i = 0; i < len; i++) {
        uint8_t c0 = (uint8_t)(c >> 25);
        c = ((c & 0x1ffffffUL) << 5) ^ values[i];
        if (c0 & 1)  c ^= 0x3b6a57b2UL;
        if (c0 & 2)  c ^= 0x26508e6dUL;
        if (c0 & 4)  c ^= 0x1ea119faUL;
        if (c0 & 8)  c ^= 0x3d4233ddUL;
        if (c0 & 16) c ^= 0x2a1462b3UL;
    }
    return c;
}

/* Compute bech32m checksum given HRP and 5-bit data (including checksum placeholder). */
static uint32_t bech32m_checksum(const char *hrp, size_t hrp_len,
                                  const uint8_t *data5, size_t data5_len) {
    /* Total polymod input:
       high(hrp[i]) for each hrp char,
       0 separator,
       low(hrp[i]) for each hrp char,
       data5[0..data5_len-1],
       6 zero bytes */
    uint8_t buf[BECH32M_MAX_HRP * 2 + 1 + BECH32M_MAX_DATA5 + 6];
    size_t pos = 0;
    if (hrp_len * 2 + 1 + data5_len + 6 > sizeof(buf)) return 0;

    for (size_t i = 0; i < hrp_len; i++)
        buf[pos++] = (uint8_t)((unsigned char)hrp[i] >> 5);
    buf[pos++] = 0;
    for (size_t i = 0; i < hrp_len; i++)
        buf[pos++] = (uint8_t)((unsigned char)hrp[i] & 0x1f);
    for (size_t i = 0; i < data5_len; i++)
        buf[pos++] = data5[i];
    for (size_t i = 0; i < 6; i++)
        buf[pos++] = 0;

    uint32_t pm = bech32_polymod(buf, pos);
    return pm ^ BECH32M_CONST;
}

/* Convert 8-bit bytes to 5-bit groups (big-endian bit stream).
   Returns number of 5-bit values written, or 0 on buffer overflow. */
static size_t bytes_to_5bit(const unsigned char *data, size_t data_len,
                              uint8_t *out, size_t out_cap) {
    uint32_t acc = 0;
    int bits = 0;
    size_t pos = 0;
    for (size_t i = 0; i < data_len; i++) {
        acc = (acc << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            if (pos >= out_cap) return 0;
            out[pos++] = (uint8_t)((acc >> bits) & 0x1f);
        }
    }
    if (bits > 0) {
        if (pos >= out_cap) return 0;
        out[pos++] = (uint8_t)((acc << (5 - bits)) & 0x1f);
    }
    return pos;
}

/* Convert 5-bit groups back to 8-bit bytes.
   Returns number of bytes written, or 0 on error. */
static size_t fivebit_to_bytes(const uint8_t *data5, size_t data5_len,
                                unsigned char *out, size_t out_cap) {
    uint32_t acc = 0;
    int bits = 0;
    size_t pos = 0;
    for (size_t i = 0; i < data5_len; i++) {
        acc = (acc << 5) | data5[i];
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (pos >= out_cap) return 0;
            out[pos++] = (unsigned char)((acc >> bits) & 0xff);
        }
    }
    /* Remaining bits must be zero padding, <= 4 bits */
    if (bits >= 5) return 0;
    if (bits > 0 && (acc & ((1u << bits) - 1u)) != 0) return 0;
    return pos;
}

int bech32m_encode(const char *hrp,
                   const unsigned char *data, size_t data_len,
                   char *out, size_t out_cap) {
    if (!hrp || !data || !out) return 0;
    init_charset_rev();

    size_t hrp_len = strlen(hrp);
    if (hrp_len == 0 || hrp_len > BECH32M_MAX_HRP) return 0;

    /* Convert data to 5-bit groups */
    uint8_t data5[BECH32M_MAX_DATA5];
    size_t data5_len = bytes_to_5bit(data, data_len, data5, sizeof(data5));
    if (!data5_len && data_len > 0) return 0;

    /* Output: hrp + "1" + data5 chars + 6 checksum chars + NUL */
    size_t need = hrp_len + 1 + data5_len + 6 + 1;
    if (out_cap < need) return 0;

    /* Compute checksum over data5 */
    /* Normalise HRP to lowercase for checksum */
    char hrp_lower[BECH32M_MAX_HRP + 1];
    for (size_t i = 0; i < hrp_len; i++)
        hrp_lower[i] = (char)tolower((unsigned char)hrp[i]);
    hrp_lower[hrp_len] = '\0';

    uint32_t chk = bech32m_checksum(hrp_lower, hrp_len, data5, data5_len);

    /* Write output characters (lower case) */
    size_t pos = 0;
    for (size_t i = 0; i < hrp_len; i++) out[pos++] = hrp_lower[i];
    out[pos++] = '1';
    for (size_t i = 0; i < data5_len; i++) out[pos++] = CHARSET[data5[i]];
    /* Append 6 checksum characters */
    for (int i = 5; i >= 0; i--)
        out[pos++] = CHARSET[(chk >> (i * 5)) & 0x1f];
    out[pos] = '\0';
    return 1;
}

int bech32m_decode(const char *str,
                   const char *hrp_expected,
                   unsigned char *out, size_t *out_len,
                   size_t out_cap) {
    if (!str || !out || !out_len) return 0;
    init_charset_rev();

    size_t slen = strlen(str);
    if (slen < 8) return 0;

    /* Find the last '1' separator */
    int sep = -1;
    for (int i = (int)slen - 1; i >= 0; i--) {
        if (str[i] == '1') { sep = i; break; }
    }
    if (sep < 1) return 0;
    if ((int)slen - sep - 1 < 6) return 0;

    size_t hrp_len = (size_t)sep;
    if (hrp_len > BECH32M_MAX_HRP) return 0;
    size_t total5_len = slen - hrp_len - 1;  /* data5 + 6 checksum */
    size_t data5_len  = total5_len - 6;

    if (total5_len > BECH32M_MAX_DATA5) return 0;

    /* Decode all characters after separator to 5-bit values */
    uint8_t vals[BECH32M_MAX_DATA5];
    for (size_t i = 0; i < total5_len; i++) {
        unsigned char c = (unsigned char)tolower((unsigned char)str[hrp_len + 1 + i]);
        if (c >= 128 || charset_rev[c] < 0) return 0;
        vals[i] = (uint8_t)charset_rev[c];
    }

    /* Lower-case HRP */
    char hrp_lower[BECH32M_MAX_HRP + 1];
    for (size_t i = 0; i < hrp_len; i++)
        hrp_lower[i] = (char)tolower((unsigned char)str[i]);
    hrp_lower[hrp_len] = '\0';

    /* Verify checksum: recompute checksum from data-only portion and compare to the
       6 chars actually present in the encoded string. */
    uint32_t expected_chk = bech32m_checksum(hrp_lower, hrp_len, vals, data5_len);
    /* Decode the 6 checksum chars from the encoded string (they sit at the end of vals[]) */
    uint32_t actual_chk = 0;
    for (int i = 5; i >= 0; i--)
        actual_chk |= ((uint32_t)vals[data5_len + (size_t)(5 - i)]) << (i * 5);
    if (expected_chk != actual_chk) return 0;

    /* Check HRP */
    if (hrp_expected) {
        size_t exp_len = strlen(hrp_expected);
        if (exp_len != hrp_len) return 0;
        for (size_t i = 0; i < hrp_len; i++) {
            if ((char)tolower((unsigned char)hrp_expected[i]) != hrp_lower[i])
                return 0;
        }
    }

    /* Convert 5-bit data (excluding checksum) back to bytes */
    size_t byte_len = fivebit_to_bytes(vals, data5_len, out, out_cap);
    if (!byte_len && data5_len > 0) return 0;
    *out_len = byte_len;
    return 1;
}
