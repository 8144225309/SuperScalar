/* ChaCha20-Poly1305 AEAD per RFC 7539 */
#include "superscalar/crypto_aead.h"
#include <string.h>
#include <stdlib.h>

/* --- ChaCha20 --- */

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QR(a, b, c, d)   \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);

void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    memcpy(x, in, 64);

    for (int i = 0; i < 10; i++) {
        /* Column rounds */
        QR(x[0], x[4], x[ 8], x[12])
        QR(x[1], x[5], x[ 9], x[13])
        QR(x[2], x[6], x[10], x[14])
        QR(x[3], x[7], x[11], x[15])
        /* Diagonal rounds */
        QR(x[0], x[5], x[10], x[15])
        QR(x[1], x[6], x[11], x[12])
        QR(x[2], x[7], x[ 8], x[13])
        QR(x[3], x[4], x[ 9], x[14])
    }

    for (int i = 0; i < 16; i++)
        out[i] = x[i] + in[i];
}

static uint32_t load32_le(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32_le(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v);
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16);
    p[3] = (unsigned char)(v >> 24);
}

void chacha20_encrypt(unsigned char *out, const unsigned char *in, size_t len,
                      const unsigned char key[32], uint32_t counter,
                      const unsigned char nonce[12]) {
    /* Set up initial state: "expand 32-byte k" */
    uint32_t state[16];
    state[0]  = 0x61707865;
    state[1]  = 0x3320646e;
    state[2]  = 0x79622d32;
    state[3]  = 0x6b206574;
    for (int i = 0; i < 8; i++)
        state[4 + i] = load32_le(key + i * 4);
    state[12] = counter;
    state[13] = load32_le(nonce);
    state[14] = load32_le(nonce + 4);
    state[15] = load32_le(nonce + 8);

    size_t off = 0;
    while (off < len) {
        uint32_t block[16];
        chacha20_block(block, state);

        unsigned char keystream[64];
        for (int i = 0; i < 16; i++)
            store32_le(keystream + i * 4, block[i]);

        size_t chunk = len - off;
        if (chunk > 64) chunk = 64;

        for (size_t i = 0; i < chunk; i++)
            out[off + i] = in[off + i] ^ keystream[i];

        off += chunk;
        state[12]++;  /* increment counter */
    }
}

/* --- Poly1305 --- */

/* Poly1305 using 130-bit arithmetic with 5x 26-bit limbs.
   This is a straightforward implementation following RFC 7539. */

static void poly1305_init(uint32_t r[5], uint32_t h[5], uint32_t pad[4],
                           const unsigned char key[32]) {
    /* r = key[0..15] clamped */
    r[0] = (load32_le(key +  0))       & 0x3ffffff;
    r[1] = (load32_le(key +  3) >> 2)  & 0x3ffff03;
    r[2] = (load32_le(key +  6) >> 4)  & 0x3ffc0ff;
    r[3] = (load32_le(key +  9) >> 6)  & 0x3f03fff;
    r[4] = (load32_le(key + 12) >> 8)  & 0x00fffff;

    /* h = 0 */
    h[0] = h[1] = h[2] = h[3] = h[4] = 0;

    /* pad = key[16..31] */
    pad[0] = load32_le(key + 16);
    pad[1] = load32_le(key + 20);
    pad[2] = load32_le(key + 24);
    pad[3] = load32_le(key + 28);
}

static void poly1305_block(uint32_t h[5], const uint32_t r[5],
                            const unsigned char *m, int final_block) {
    uint32_t hibit = final_block ? 0 : (1 << 24);  /* 2^128 bit */

    /* h += m */
    uint32_t s0 = load32_le(m +  0);
    uint32_t s1 = load32_le(m +  4);
    uint32_t s2 = load32_le(m +  8);
    uint32_t s3 = load32_le(m + 12);

    h[0] += (s0)                     & 0x3ffffff;
    h[1] += ((s0 >> 26) | (s1 << 6))  & 0x3ffffff;
    h[2] += ((s1 >> 20) | (s2 << 12)) & 0x3ffffff;
    h[3] += ((s2 >> 14) | (s3 << 18)) & 0x3ffffff;
    h[4] += (s3 >> 8) | hibit;

    /* h *= r (mod 2^130 - 5) */
    uint64_t r0 = r[0], r1 = r[1], r2 = r[2], r3 = r[3], r4 = r[4];
    uint64_t s1_5 = r1 * 5, s2_5 = r2 * 5, s3_5 = r3 * 5, s4_5 = r4 * 5;

    uint64_t d0 = (uint64_t)h[0]*r0 + (uint64_t)h[1]*s4_5 + (uint64_t)h[2]*s3_5 +
                  (uint64_t)h[3]*s2_5 + (uint64_t)h[4]*s1_5;
    uint64_t d1 = (uint64_t)h[0]*r1 + (uint64_t)h[1]*r0 + (uint64_t)h[2]*s4_5 +
                  (uint64_t)h[3]*s3_5 + (uint64_t)h[4]*s2_5;
    uint64_t d2 = (uint64_t)h[0]*r2 + (uint64_t)h[1]*r1 + (uint64_t)h[2]*r0 +
                  (uint64_t)h[3]*s4_5 + (uint64_t)h[4]*s3_5;
    uint64_t d3 = (uint64_t)h[0]*r3 + (uint64_t)h[1]*r2 + (uint64_t)h[2]*r1 +
                  (uint64_t)h[3]*r0 + (uint64_t)h[4]*s4_5;
    uint64_t d4 = (uint64_t)h[0]*r4 + (uint64_t)h[1]*r3 + (uint64_t)h[2]*r2 +
                  (uint64_t)h[3]*r1 + (uint64_t)h[4]*r0;

    /* Partial reduction mod 2^130-5 */
    uint32_t c;
    c = (uint32_t)(d0 >> 26); h[0] = (uint32_t)d0 & 0x3ffffff;
    d1 += c;
    c = (uint32_t)(d1 >> 26); h[1] = (uint32_t)d1 & 0x3ffffff;
    d2 += c;
    c = (uint32_t)(d2 >> 26); h[2] = (uint32_t)d2 & 0x3ffffff;
    d3 += c;
    c = (uint32_t)(d3 >> 26); h[3] = (uint32_t)d3 & 0x3ffffff;
    d4 += c;
    c = (uint32_t)(d4 >> 26); h[4] = (uint32_t)d4 & 0x3ffffff;
    h[0] += c * 5;
    c = h[0] >> 26; h[0] &= 0x3ffffff;
    h[1] += c;
}

void poly1305_auth(unsigned char tag[16], const unsigned char *msg, size_t len,
                   const unsigned char key[32]) {
    uint32_t r[5], h[5], pad[4];
    poly1305_init(r, h, pad, key);

    /* Process full 16-byte blocks */
    size_t off = 0;
    while (off + 16 <= len) {
        poly1305_block(h, r, msg + off, 0);
        off += 16;
    }

    /* Final partial block */
    if (off < len) {
        unsigned char last[16];
        size_t rem = len - off;
        memcpy(last, msg + off, rem);
        last[rem] = 1;  /* padding bit */
        memset(last + rem + 1, 0, 16 - rem - 1);
        poly1305_block(h, r, last, 1);
    }

    /* Full carry chain */
    uint32_t c;
    c = h[1] >> 26; h[1] &= 0x3ffffff; h[2] += c;
    c = h[2] >> 26; h[2] &= 0x3ffffff; h[3] += c;
    c = h[3] >> 26; h[3] &= 0x3ffffff; h[4] += c;
    c = h[4] >> 26; h[4] &= 0x3ffffff; h[0] += c * 5;
    c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += c;

    /* Compute h - (2^130 - 5) and select */
    uint32_t g[5];
    g[0] = h[0] + 5; c = g[0] >> 26; g[0] &= 0x3ffffff;
    g[1] = h[1] + c; c = g[1] >> 26; g[1] &= 0x3ffffff;
    g[2] = h[2] + c; c = g[2] >> 26; g[2] &= 0x3ffffff;
    g[3] = h[3] + c; c = g[3] >> 26; g[3] &= 0x3ffffff;
    g[4] = h[4] + c - (1 << 26);

    /* Select h or g based on top bit of g[4] */
    uint32_t mask = (g[4] >> 31) - 1;  /* mask = 0xffffffff if g >= 2^130-5, 0 otherwise */
    for (int i = 0; i < 5; i++)
        h[i] = (h[i] & ~mask) | (g[i] & mask);

    /* Convert h from 5x26-bit limbs to 4x32-bit words, then add pad */
    uint64_t acc;
    uint32_t h32[4];
    acc  = (uint64_t)h[0] | ((uint64_t)h[1] << 26);
    h32[0] = (uint32_t)acc; acc >>= 32;
    /* acc already has h[1]>>6 as carry; add h[2]'s contribution at bit 20 */
    acc += ((uint64_t)h[2] << 20);
    h32[1] = (uint32_t)acc; acc >>= 32;
    acc += ((uint64_t)h[3] << 14);
    h32[2] = (uint32_t)acc; acc >>= 32;
    acc += ((uint64_t)h[4] << 8);
    h32[3] = (uint32_t)acc;

    /* h += pad (with carry) */
    acc = (uint64_t)h32[0] + pad[0]; h32[0] = (uint32_t)acc; acc >>= 32;
    acc += (uint64_t)h32[1] + pad[1]; h32[1] = (uint32_t)acc; acc >>= 32;
    acc += (uint64_t)h32[2] + pad[2]; h32[2] = (uint32_t)acc; acc >>= 32;
    acc += (uint64_t)h32[3] + pad[3]; h32[3] = (uint32_t)acc;

    store32_le(tag +  0, h32[0]);
    store32_le(tag +  4, h32[1]);
    store32_le(tag +  8, h32[2]);
    store32_le(tag + 12, h32[3]);
}

/* --- AEAD (RFC 7539 Section 2.8) --- */

/* Pad to 16-byte boundary: write zero bytes as needed */
static void pad16(unsigned char *buf, size_t *pos, size_t data_len) {
    size_t rem = data_len % 16;
    if (rem > 0) {
        size_t pad = 16 - rem;
        memset(buf + *pos, 0, pad);
        *pos += pad;
    }
}

static void store64_le(unsigned char *p, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        p[i] = (unsigned char)(v & 0xff);
        v >>= 8;
    }
}

int aead_encrypt(unsigned char *ciphertext, unsigned char tag[16],
                 const unsigned char *plaintext, size_t pt_len,
                 const unsigned char *aad, size_t aad_len,
                 const unsigned char key[32], const unsigned char nonce[12]) {
    /* 1. Generate Poly1305 one-time key (counter=0) */
    unsigned char poly_key[64];
    memset(poly_key, 0, 64);
    chacha20_encrypt(poly_key, poly_key, 64, key, 0, nonce);
    /* Only first 32 bytes used as Poly1305 key */

    /* 2. Encrypt plaintext with ChaCha20 (counter=1) */
    chacha20_encrypt(ciphertext, plaintext, pt_len, key, 1, nonce);

    /* 3. Construct Poly1305 input: AAD || pad || ciphertext || pad || len(AAD) || len(ct) */
    size_t mac_data_len = 0;
    if (aad_len > 0) {
        mac_data_len += aad_len;
        mac_data_len += (16 - (aad_len % 16)) % 16;
    }
    mac_data_len += pt_len;
    mac_data_len += (16 - (pt_len % 16)) % 16;
    mac_data_len += 16; /* two 8-byte lengths */

    unsigned char *mac_data = (unsigned char *)malloc(mac_data_len);
    if (!mac_data) return 0;

    size_t pos = 0;
    if (aad_len > 0) {
        memcpy(mac_data + pos, aad, aad_len);
        pos += aad_len;
        pad16(mac_data, &pos, aad_len);
    }
    memcpy(mac_data + pos, ciphertext, pt_len);
    pos += pt_len;
    pad16(mac_data, &pos, pt_len);
    store64_le(mac_data + pos, (uint64_t)aad_len); pos += 8;
    store64_le(mac_data + pos, (uint64_t)pt_len);  pos += 8;

    poly1305_auth(tag, mac_data, pos, poly_key);
    free(mac_data);
    return 1;
}

int aead_decrypt(unsigned char *plaintext,
                 const unsigned char *ciphertext, size_t ct_len,
                 const unsigned char tag[16],
                 const unsigned char *aad, size_t aad_len,
                 const unsigned char key[32], const unsigned char nonce[12]) {
    /* 1. Generate Poly1305 one-time key (counter=0) */
    unsigned char poly_key[64];
    memset(poly_key, 0, 64);
    chacha20_encrypt(poly_key, poly_key, 64, key, 0, nonce);

    /* 2. Verify tag first */
    size_t mac_data_len = 0;
    if (aad_len > 0) {
        mac_data_len += aad_len;
        mac_data_len += (16 - (aad_len % 16)) % 16;
    }
    mac_data_len += ct_len;
    mac_data_len += (16 - (ct_len % 16)) % 16;
    mac_data_len += 16;

    unsigned char *mac_data = (unsigned char *)malloc(mac_data_len);
    if (!mac_data) return 0;

    size_t pos = 0;
    if (aad_len > 0) {
        memcpy(mac_data + pos, aad, aad_len);
        pos += aad_len;
        pad16(mac_data, &pos, aad_len);
    }
    memcpy(mac_data + pos, ciphertext, ct_len);
    pos += ct_len;
    pad16(mac_data, &pos, ct_len);
    store64_le(mac_data + pos, (uint64_t)aad_len); pos += 8;
    store64_le(mac_data + pos, (uint64_t)ct_len);  pos += 8;

    unsigned char computed_tag[16];
    poly1305_auth(computed_tag, mac_data, pos, poly_key);
    free(mac_data);

    /* Constant-time comparison */
    unsigned char diff = 0;
    for (int i = 0; i < 16; i++)
        diff |= computed_tag[i] ^ tag[i];
    if (diff != 0)
        return 0;

    /* 3. Decrypt */
    chacha20_encrypt(plaintext, ciphertext, ct_len, key, 1, nonce);
    return 1;
}
