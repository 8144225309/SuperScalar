#include "superscalar/types.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void tx_buf_init(tx_buf_t *buf, size_t initial_cap) {
    buf->data = (unsigned char *)malloc(initial_cap);
    buf->len = 0;
    buf->cap = initial_cap;
}

void tx_buf_free(tx_buf_t *buf) {
    free(buf->data);
    buf->data = NULL;
    buf->len = 0;
    buf->cap = 0;
}

void tx_buf_reset(tx_buf_t *buf) {
    buf->len = 0;
}

void tx_buf_ensure(tx_buf_t *buf, size_t additional) {
    if (buf->len + additional > buf->cap) {
        size_t new_cap = buf->cap * 2;
        if (new_cap < buf->len + additional)
            new_cap = buf->len + additional;
        buf->data = (unsigned char *)realloc(buf->data, new_cap);
        buf->cap = new_cap;
    }
}

/* --- Hex --- */

static const char hex_chars[] = "0123456789abcdef";

void hex_encode(const unsigned char *data, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hex_chars[(data[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hex_chars[data[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

int hex_decode(const char *hex, unsigned char *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > out_len) return 0;
    for (size_t i = 0; i < hex_len / 2; i++) {
        int hi = hex_digit(hex[i * 2]);
        int lo = hex_digit(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return (int)(hex_len / 2);
}

/* --- SHA-256 --- */

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static void sha256_transform(uint32_t state[8], const unsigned char block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4] << 24)
             | ((uint32_t)block[i*4+1] << 16)
             | ((uint32_t)block[i*4+2] << 8)
             | ((uint32_t)block[i*4+3]);
    }
    for (int i = 16; i < 64; i++)
        w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + SIGMA1(e) + CH(e, f, g) + sha256_k[i] + w[i];
        uint32_t t2 = SIGMA0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256(const unsigned char *data, size_t len, unsigned char *out32) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };

    size_t i;
    for (i = 0; i + 64 <= len; i += 64)
        sha256_transform(state, data + i);

    unsigned char block[64];
    size_t remaining = len - i;
    memcpy(block, data + i, remaining);
    block[remaining] = 0x80;

    if (remaining >= 56) {
        memset(block + remaining + 1, 0, 64 - remaining - 1);
        sha256_transform(state, block);
        memset(block, 0, 56);
    } else {
        memset(block + remaining + 1, 0, 56 - remaining - 1);
    }

    uint64_t bit_len = (uint64_t)len * 8;
    block[56] = (unsigned char)(bit_len >> 56);
    block[57] = (unsigned char)(bit_len >> 48);
    block[58] = (unsigned char)(bit_len >> 40);
    block[59] = (unsigned char)(bit_len >> 32);
    block[60] = (unsigned char)(bit_len >> 24);
    block[61] = (unsigned char)(bit_len >> 16);
    block[62] = (unsigned char)(bit_len >> 8);
    block[63] = (unsigned char)(bit_len);
    sha256_transform(state, block);

    for (int j = 0; j < 8; j++) {
        out32[j*4]   = (unsigned char)(state[j] >> 24);
        out32[j*4+1] = (unsigned char)(state[j] >> 16);
        out32[j*4+2] = (unsigned char)(state[j] >> 8);
        out32[j*4+3] = (unsigned char)(state[j]);
    }
}

void sha256_double(const unsigned char *data, size_t len, unsigned char *out32) {
    unsigned char tmp[32];
    sha256(data, len, tmp);
    sha256(tmp, 32, out32);
}

/* Tagged hash per BIP-340/341: SHA256(SHA256(tag) || SHA256(tag) || data) */
void sha256_tagged(const char *tag, const unsigned char *data, size_t data_len,
                   unsigned char *out32) {
    unsigned char tag_hash[32];
    sha256((const unsigned char *)tag, strlen(tag), tag_hash);

    size_t total = 64 + data_len;
    unsigned char *buf = (unsigned char *)malloc(total);
    memcpy(buf, tag_hash, 32);
    memcpy(buf + 32, tag_hash, 32);
    memcpy(buf + 64, data, data_len);
    sha256(buf, total, out32);
    free(buf);
}

void reverse_bytes(unsigned char *data, size_t len) {
    for (size_t i = 0; i < len / 2; i++) {
        unsigned char tmp = data[i];
        data[i] = data[len - 1 - i];
        data[len - 1 - i] = tmp;
    }
}
