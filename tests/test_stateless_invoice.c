/*
 * test_stateless_invoice.c — Tests for HMAC-derived stateless invoices
 *
 * PR #47: Stateless Invoice (no-table payment secret derivation)
 */

#include "superscalar/stateless_invoice.h"
#include "superscalar/sha256.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

static void fill(unsigned char *buf, int len, unsigned char val)
{
    for (int i = 0; i < len; i++) buf[i] = val;
}

/* -----------------------------------------------------------------------
 * SI1: derive_secret is deterministic (same inputs → same output)
 * --------------------------------------------------------------------- */
int test_si_derive_secret_deterministic(void)
{
    unsigned char key[32], hash[32];
    fill(key, 32, 0xAA);
    fill(hash, 32, 0xBB);

    unsigned char s1[32], s2[32];
    stateless_invoice_derive_secret(key, hash, s1);
    stateless_invoice_derive_secret(key, hash, s2);

    ASSERT(memcmp(s1, s2, 32) == 0, "SI1: same inputs → same secret");

    int all_zero = 1;
    for (int i = 0; i < 32; i++) if (s1[i]) { all_zero = 0; break; }
    ASSERT(!all_zero, "secret is not all zeros");
    return 1;
}

/* -----------------------------------------------------------------------
 * SI2: different keys → different secrets
 * --------------------------------------------------------------------- */
int test_si_different_keys(void)
{
    unsigned char key1[32], key2[32], hash[32];
    fill(key1, 32, 0x11); fill(key2, 32, 0x22); fill(hash, 32, 0x33);

    unsigned char s1[32], s2[32];
    stateless_invoice_derive_secret(key1, hash, s1);
    stateless_invoice_derive_secret(key2, hash, s2);

    ASSERT(memcmp(s1, s2, 32) != 0, "SI2: different keys → different secrets");
    return 1;
}

/* -----------------------------------------------------------------------
 * SI3: different payment_hashes → different secrets
 * --------------------------------------------------------------------- */
int test_si_different_hashes(void)
{
    unsigned char key[32], h1[32], h2[32];
    fill(key, 32, 0x55); fill(h1, 32, 0x11); fill(h2, 32, 0x22);

    unsigned char s1[32], s2[32];
    stateless_invoice_derive_secret(key, h1, s1);
    stateless_invoice_derive_secret(key, h2, s2);

    ASSERT(memcmp(s1, s2, 32) != 0, "SI3: different hashes → different secrets");
    return 1;
}

/* -----------------------------------------------------------------------
 * SI4: verify_secret returns true for correct presented secret
 * --------------------------------------------------------------------- */
int test_si_verify_secret_correct(void)
{
    unsigned char key[32], hash[32], secret[32];
    fill(key, 32, 0xCC); fill(hash, 32, 0xDD);

    stateless_invoice_derive_secret(key, hash, secret);

    int ok = stateless_invoice_verify_secret(key, hash, secret);
    ASSERT(ok == 1, "SI4: verify_secret correct secret → true");
    return 1;
}

/* -----------------------------------------------------------------------
 * SI5: verify_secret returns false for wrong secret
 * --------------------------------------------------------------------- */
int test_si_verify_secret_wrong(void)
{
    unsigned char key[32], hash[32], wrong_secret[32];
    fill(key, 32, 0xEE); fill(hash, 32, 0xFF); fill(wrong_secret, 32, 0x01);

    int ok = stateless_invoice_verify_secret(key, hash, wrong_secret);
    ASSERT(ok == 0, "SI5: wrong secret → false");
    return 1;
}

/* -----------------------------------------------------------------------
 * SI6: derive_preimage is deterministic
 * --------------------------------------------------------------------- */
int test_si_derive_preimage_deterministic(void)
{
    unsigned char key[32], nonce[32];
    fill(key, 32, 0x12); fill(nonce, 32, 0x34);

    unsigned char p1[32], p2[32];
    stateless_invoice_derive_preimage(key, nonce, p1);
    stateless_invoice_derive_preimage(key, nonce, p2);

    ASSERT(memcmp(p1, p2, 32) == 0, "SI6: same nonce → same preimage");

    int all_zero = 1;
    for (int i = 0; i < 32; i++) if (p1[i]) { all_zero = 0; break; }
    ASSERT(!all_zero, "preimage not all zeros");
    return 1;
}

/* -----------------------------------------------------------------------
 * SI7: from_nonce produces consistent preimage + hash + secret
 * --------------------------------------------------------------------- */
int test_si_from_nonce(void)
{
    unsigned char key[32], nonce[32];
    fill(key, 32, 0x56); fill(nonce, 32, 0x78);

    unsigned char hash[32], preimage[32], secret[32];
    int ok = stateless_invoice_from_nonce(key, nonce, hash, preimage, secret);
    ASSERT(ok == 1, "SI7: from_nonce succeeds");

    /* Verify SHA256(preimage) == payment_hash */
    unsigned char computed_hash[32];
    sha256(preimage, 32, computed_hash);
    ASSERT(memcmp(computed_hash, hash, 32) == 0, "SHA256(preimage) == hash");

    /* Verify secret matches derived secret */
    unsigned char expected_secret[32];
    stateless_invoice_derive_secret(key, hash, expected_secret);
    ASSERT(memcmp(secret, expected_secret, 32) == 0, "secret matches derived");

    return 1;
}

/* -----------------------------------------------------------------------
 * SI8: claim succeeds with correct nonce, hash, and secret
 * --------------------------------------------------------------------- */
int test_si_claim_success(void)
{
    unsigned char key[32], nonce[32];
    fill(key, 32, 0x9A); fill(nonce, 32, 0xBC);

    unsigned char payment_hash[32], preimage[32], secret[32];
    stateless_invoice_from_nonce(key, nonce, payment_hash, preimage, secret);

    unsigned char claimed_preimage[32];
    int ok = stateless_invoice_claim(key, nonce, payment_hash, secret,
                                      claimed_preimage);
    ASSERT(ok == 1, "SI8: claim succeeds");
    ASSERT(memcmp(claimed_preimage, preimage, 32) == 0, "claimed preimage matches");
    return 1;
}

/* -----------------------------------------------------------------------
 * SI9: claim fails with wrong nonce (hash mismatch)
 * --------------------------------------------------------------------- */
int test_si_claim_wrong_nonce(void)
{
    unsigned char key[32], nonce[32], wrong_nonce[32];
    fill(key, 32, 0xDE); fill(nonce, 32, 0xF0); fill(wrong_nonce, 32, 0x01);

    unsigned char payment_hash[32], preimage[32], secret[32];
    stateless_invoice_from_nonce(key, nonce, payment_hash, preimage, secret);

    unsigned char claimed_preimage[32];
    int ok = stateless_invoice_claim(key, wrong_nonce, payment_hash, secret,
                                      claimed_preimage);
    ASSERT(ok == 0, "SI9: wrong nonce → claim fails");

    int all_zero = 1;
    for (int i = 0; i < 32; i++) if (claimed_preimage[i]) { all_zero = 0; break; }
    ASSERT(all_zero, "output preimage zeroed on failure");
    return 1;
}

/* -----------------------------------------------------------------------
 * SI10: claim fails with wrong payment_secret
 * --------------------------------------------------------------------- */
int test_si_claim_wrong_secret(void)
{
    unsigned char key[32], nonce[32];
    fill(key, 32, 0x11); fill(nonce, 32, 0x22);

    unsigned char payment_hash[32], preimage[32], secret[32];
    stateless_invoice_from_nonce(key, nonce, payment_hash, preimage, secret);

    /* Tamper with the secret */
    secret[0] ^= 0xFF;

    unsigned char claimed_preimage[32];
    int ok = stateless_invoice_claim(key, nonce, payment_hash, secret,
                                      claimed_preimage);
    ASSERT(ok == 0, "SI10: wrong secret → claim fails");
    return 1;
}

/* -----------------------------------------------------------------------
 * SI11: check_preimage correctly validates SHA256
 * --------------------------------------------------------------------- */
int test_si_check_preimage(void)
{
    unsigned char preimage[32], hash[32];
    fill(preimage, 32, 0x42);
    sha256(preimage, 32, hash);

    ASSERT(stateless_invoice_check_preimage(hash, preimage) == 1,
           "SI11: valid preimage → true");

    /* Tamper with preimage */
    preimage[0] ^= 0x01;
    ASSERT(stateless_invoice_check_preimage(hash, preimage) == 0,
           "tampered preimage → false");
    return 1;
}

/* -----------------------------------------------------------------------
 * SI12: generate_l1 produces valid preimage + hash + secret
 * --------------------------------------------------------------------- */
int test_si_generate_l1(void)
{
    unsigned char key[32];
    fill(key, 32, 0x55);

    unsigned char preimage[32], payment_hash[32], secret[32];
    int ok = stateless_invoice_generate_l1(key, preimage, payment_hash, secret);
    ASSERT(ok == 1, "SI12: generate_l1 succeeds");

    /* SHA256(preimage) == payment_hash */
    ASSERT(stateless_invoice_check_preimage(payment_hash, preimage) == 1,
           "preimage reveals hash");

    /* Secret verifies correctly */
    ASSERT(stateless_invoice_verify_secret(key, payment_hash, secret) == 1,
           "secret verifies");

    /* Two calls produce different results (random) */
    unsigned char preimage2[32], hash2[32], secret2[32];
    stateless_invoice_generate_l1(key, preimage2, hash2, secret2);
    ASSERT(memcmp(preimage, preimage2, 32) != 0, "each call different");
    return 1;
}

/* -----------------------------------------------------------------------
 * SI13: NULL safety
 * --------------------------------------------------------------------- */
int test_si_null_safety(void)
{
    unsigned char key[32], hash[32], secret[32], preimage[32], nonce[32];
    fill(key, 32, 0xAA); fill(hash, 32, 0xBB);
    fill(secret, 32, 0xCC); fill(nonce, 32, 0xDD);

    /* NULL inputs — no crash */
    stateless_invoice_derive_secret(NULL, hash, secret);
    stateless_invoice_derive_secret(key, NULL, secret);
    stateless_invoice_derive_secret(key, hash, NULL);

    ASSERT(stateless_invoice_verify_secret(NULL, hash, secret) == 0,
           "NULL key → 0");
    ASSERT(stateless_invoice_verify_secret(key, NULL, secret) == 0,
           "NULL hash → 0");
    ASSERT(stateless_invoice_verify_secret(key, hash, NULL) == 0,
           "NULL secret → 0");

    stateless_invoice_derive_preimage(NULL, nonce, preimage);
    stateless_invoice_derive_preimage(key, NULL, preimage);
    stateless_invoice_derive_preimage(key, nonce, NULL);

    ASSERT(stateless_invoice_from_nonce(NULL, nonce, hash, preimage, secret) == 0,
           "from_nonce NULL key → 0");
    ASSERT(stateless_invoice_from_nonce(key, NULL, hash, preimage, secret) == 0,
           "from_nonce NULL nonce → 0");

    /* claim with NULL inputs */
    ASSERT(stateless_invoice_claim(NULL, nonce, hash, secret, preimage) == 0,
           "claim NULL key → 0");

    ASSERT(stateless_invoice_check_preimage(NULL, preimage) == 0,
           "check_preimage NULL hash → 0");
    ASSERT(stateless_invoice_check_preimage(hash, NULL) == 0,
           "check_preimage NULL preimage → 0");

    ASSERT(stateless_invoice_generate_l1(NULL, preimage, hash, secret) == 0,
           "generate_l1 NULL key → 0");

    return 1;
}
