/*
 * stateless_invoice.c — HMAC-derived payment secrets for scalable invoicing
 */

#include "superscalar/stateless_invoice.h"
#include "superscalar/noise.h"
#include "superscalar/sha256.h"
#include <string.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>

/* -----------------------------------------------------------------------
 * Constant-time memcmp (prevent timing side-channel on secret comparison)
 * --------------------------------------------------------------------- */
static int ct_memcmp(const unsigned char *a, const unsigned char *b, size_t len)
{
    volatile unsigned char diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= a[i] ^ b[i];
    return (diff == 0) ? 1 : 0;
}

/* -----------------------------------------------------------------------
 * Random bytes from /dev/urandom
 * --------------------------------------------------------------------- */
static int get_random(unsigned char *buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, len);
    close(fd);
    return (n == (ssize_t)len) ? 1 : 0;
}

/* -----------------------------------------------------------------------
 * HMAC helper: key is always 32 bytes
 * Wraps noise.h hmac_sha256(out, key, key_len, data, data_len)
 * --------------------------------------------------------------------- */
static void hmac32(const unsigned char key[32],
                   const unsigned char *data, size_t data_len,
                   unsigned char out[32])
{
    hmac_sha256(out, key, 32, data, data_len);
}

/* -----------------------------------------------------------------------
 * Level 1: Stateless payment_secret derivation
 * --------------------------------------------------------------------- */

void stateless_invoice_derive_secret(const unsigned char node_key[32],
                                      const unsigned char payment_hash[32],
                                      unsigned char       secret_out[32])
{
    if (!node_key || !payment_hash || !secret_out) {
        if (secret_out) memset(secret_out, 0, 32);
        return;
    }

    /* data = label(24) || payment_hash(32) */
    const char *label = STATELESS_LABEL_SECRET;   /* "stateless:payment_secret" */
    size_t label_len = sizeof(STATELESS_LABEL_SECRET) - 1;  /* exclude NUL */
    size_t data_len = label_len + 32;
    unsigned char data[64];  /* label ≤ 32 bytes, so 64 is safe */
    memcpy(data, label, label_len);
    memcpy(data + label_len, payment_hash, 32);

    hmac32(node_key, data, data_len, secret_out);
}

int stateless_invoice_verify_secret(const unsigned char node_key[32],
                                     const unsigned char payment_hash[32],
                                     const unsigned char presented_secret[32])
{
    if (!node_key || !payment_hash || !presented_secret) return 0;

    unsigned char expected[32];
    stateless_invoice_derive_secret(node_key, payment_hash, expected);
    int ok = ct_memcmp(expected, presented_secret, 32);
    memset(expected, 0, 32);
    return ok;
}

/* -----------------------------------------------------------------------
 * Level 2: Fully stateless (preimage + secret from nonce)
 * --------------------------------------------------------------------- */

int stateless_invoice_gen_nonce(unsigned char nonce_out[32])
{
    if (!nonce_out) return 0;
    return get_random(nonce_out, 32);
}

void stateless_invoice_derive_preimage(const unsigned char node_key[32],
                                        const unsigned char nonce[32],
                                        unsigned char       preimage_out[32])
{
    if (!node_key || !nonce || !preimage_out) {
        if (preimage_out) memset(preimage_out, 0, 32);
        return;
    }

    const char *label = STATELESS_LABEL_PREIMAGE;  /* "stateless:preimage" */
    size_t label_len = sizeof(STATELESS_LABEL_PREIMAGE) - 1;
    size_t data_len = label_len + 32;
    unsigned char data[64];
    memcpy(data, label, label_len);
    memcpy(data + label_len, nonce, 32);

    hmac32(node_key, data, data_len, preimage_out);
}

int stateless_invoice_from_nonce(const unsigned char node_key[32],
                                  const unsigned char nonce[32],
                                  unsigned char payment_hash_out[32],
                                  unsigned char preimage_out[32],
                                  unsigned char secret_out[32])
{
    if (!node_key || !nonce) return 0;

    unsigned char preimage[32];
    stateless_invoice_derive_preimage(node_key, nonce, preimage);
    sha256(preimage, 32, payment_hash_out);
    stateless_invoice_derive_secret(node_key, payment_hash_out, secret_out);

    if (preimage_out) memcpy(preimage_out, preimage, 32);
    memset(preimage, 0, 32);
    return 1;
}

int stateless_invoice_claim(const unsigned char node_key[32],
                             const unsigned char nonce[32],
                             const unsigned char payment_hash[32],
                             const unsigned char presented_secret[32],
                             unsigned char       preimage_out[32])
{
    if (preimage_out) memset(preimage_out, 0, 32);
    if (!node_key || !nonce || !payment_hash || !presented_secret) return 0;

    /* Derive preimage from nonce */
    unsigned char preimage[32];
    stateless_invoice_derive_preimage(node_key, nonce, preimage);

    /* Verify payment_hash == SHA256(preimage) */
    unsigned char expected_hash[32];
    sha256(preimage, 32, expected_hash);
    if (!ct_memcmp(expected_hash, payment_hash, 32)) {
        memset(preimage, 0, 32);
        return 0;
    }

    /* Verify payment_secret */
    if (!stateless_invoice_verify_secret(node_key, payment_hash, presented_secret)) {
        memset(preimage, 0, 32);
        return 0;
    }

    if (preimage_out) memcpy(preimage_out, preimage, 32);
    memset(preimage, 0, 32);
    return 1;
}

/* -----------------------------------------------------------------------
 * Utilities
 * --------------------------------------------------------------------- */

int stateless_invoice_check_preimage(const unsigned char payment_hash[32],
                                      const unsigned char preimage[32])
{
    if (!payment_hash || !preimage) return 0;
    unsigned char computed[32];
    sha256(preimage, 32, computed);
    return ct_memcmp(computed, payment_hash, 32);
}

int stateless_invoice_generate_l1(const unsigned char node_key[32],
                                   unsigned char preimage_out[32],
                                   unsigned char payment_hash_out[32],
                                   unsigned char secret_out[32])
{
    if (!node_key) return 0;

    unsigned char preimage[32];
    if (!get_random(preimage, 32)) return 0;

    unsigned char hash[32];
    sha256(preimage, 32, hash);

    unsigned char secret[32];
    stateless_invoice_derive_secret(node_key, hash, secret);

    if (preimage_out)      memcpy(preimage_out, preimage, 32);
    if (payment_hash_out)  memcpy(payment_hash_out, hash, 32);
    if (secret_out)        memcpy(secret_out, secret, 32);

    memset(preimage, 0, 32);
    memset(secret, 0, 32);
    return 1;
}
