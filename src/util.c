#include "superscalar/types.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>

/* Volatile function pointer prevents the compiler from optimizing away
   the memset call when the buffer is "dead" after zeroing.
   Same approach as libsodium and Bitcoin Core. */
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = memset;

void secure_zero(void *ptr, size_t len) {
    secure_memset_ptr(ptr, 0, len);
}

void tx_buf_init(tx_buf_t *buf, size_t initial_cap) {
    buf->data = (unsigned char *)malloc(initial_cap);
    if (!buf->data) { buf->len = 0; buf->cap = 0; return; }
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
        unsigned char *new_data = (unsigned char *)realloc(buf->data, new_cap);
        if (!new_data) return;
        buf->data = new_data;
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

/* --- SHA-256 (OpenSSL EVP) --- */

void sha256(const unsigned char *data, size_t len, unsigned char *out32) {
    unsigned int md_len = 32;
    EVP_Digest(data, len, out32, &md_len, EVP_sha256(), NULL);
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

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { memset(out32, 0, 32); return; }
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, tag_hash, 32);
    EVP_DigestUpdate(ctx, tag_hash, 32);
    EVP_DigestUpdate(ctx, data, data_len);
    EVP_DigestFinal_ex(ctx, out32, NULL);
    EVP_MD_CTX_free(ctx);
}

void reverse_bytes(unsigned char *data, size_t len) {
    for (size_t i = 0; i < len / 2; i++) {
        unsigned char tmp = data[i];
        data[i] = data[len - 1 - i];
        data[len - 1 - i] = tmp;
    }
}
