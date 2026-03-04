#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "superscalar/bip39.h"
#include "superscalar/hd_key.h"
#include "superscalar/keyfile.h"
#include "superscalar/types.h"

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

/* Helper: hex string to bytes */
static int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len) {
    size_t hlen = strlen(hex);
    if (hlen != out_len * 2) return 0;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return 0;
        out[i] = (unsigned char)byte;
    }
    return 1;
}

/* Test 1: 128-bit entropy -> 12-word mnemonic round-trip.
   Vector from BIP39 spec (trezor/python-mnemonic):
   entropy: 00000000000000000000000000000000
   mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" */
int test_bip39_entropy_roundtrip_12(void) {
    unsigned char entropy[16];
    memset(entropy, 0, sizeof(entropy));

    char mnemonic[512];
    TEST_ASSERT(bip39_entropy_to_mnemonic(entropy, 16, mnemonic, sizeof(mnemonic)),
                "entropy_to_mnemonic failed");

    TEST_ASSERT(strcmp(mnemonic,
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about") == 0,
        "12-word mnemonic mismatch");

    /* Round-trip: mnemonic back to entropy */
    unsigned char recovered[16];
    size_t rlen = bip39_mnemonic_to_entropy(mnemonic, recovered, sizeof(recovered));
    TEST_ASSERT(rlen == 16, "recovered entropy length mismatch");
    TEST_ASSERT(memcmp(recovered, entropy, 16) == 0, "recovered entropy mismatch");

    return 1;
}

/* Test 2: 256-bit entropy -> 24-word mnemonic round-trip.
   Vector: all zeros -> specific 24-word phrase */
int test_bip39_entropy_roundtrip_24(void) {
    unsigned char entropy[32];
    memset(entropy, 0, sizeof(entropy));

    char mnemonic[1024];
    TEST_ASSERT(bip39_entropy_to_mnemonic(entropy, 32, mnemonic, sizeof(mnemonic)),
                "24-word entropy_to_mnemonic failed");

    /* First word should be "abandon" for all-zero entropy */
    TEST_ASSERT(strncmp(mnemonic, "abandon ", 8) == 0,
                "24-word mnemonic should start with 'abandon'");

    /* Count words */
    int wc = 1;
    for (const char *p = mnemonic; *p; p++)
        if (*p == ' ') wc++;
    TEST_ASSERT(wc == 24, "should produce exactly 24 words");

    /* Round-trip */
    unsigned char recovered[32];
    size_t rlen = bip39_mnemonic_to_entropy(mnemonic, recovered, sizeof(recovered));
    TEST_ASSERT(rlen == 32, "24-word recovered entropy length mismatch");
    TEST_ASSERT(memcmp(recovered, entropy, 32) == 0, "24-word recovered entropy mismatch");

    return 1;
}

/* Test 3: Validate good mnemonic */
int test_bip39_validate_good(void) {
    const char *good = "abandon abandon abandon abandon abandon abandon "
                       "abandon abandon abandon abandon abandon about";
    TEST_ASSERT(bip39_validate(good), "valid mnemonic should pass");
    return 1;
}

/* Test 4: Validate bad checksum (change last word) */
int test_bip39_validate_bad_checksum(void) {
    const char *bad = "abandon abandon abandon abandon abandon abandon "
                      "abandon abandon abandon abandon abandon abandon";
    TEST_ASSERT(!bip39_validate(bad), "bad checksum should fail");
    return 1;
}

/* Test 5: Validate bad word */
int test_bip39_validate_bad_word(void) {
    const char *bad = "abandon abandon abandon abandon abandon abandon "
                      "abandon abandon abandon abandon abandon zzzznotaword";
    TEST_ASSERT(!bip39_validate(bad), "unknown word should fail");
    return 1;
}

/* Test 6: Seed derivation against official vector.
   From trezor/python-mnemonic test vectors:
   Mnemonic: "abandon abandon abandon abandon abandon abandon
              abandon abandon abandon abandon abandon about"
   Passphrase: "TREZOR"
   Expected seed (hex): c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e7e24990e04ee4c7c
                         9eb5fcda4341fa8e421ef1672ced6ee1fea7138cfa58f5ec01e2c1d7bff00aa8 */
int test_bip39_seed_derivation(void) {
    const char *mnemonic = "abandon abandon abandon abandon abandon abandon "
                           "abandon abandon abandon abandon abandon about";
    const char *passphrase = "TREZOR";
    const char *expected_hex =
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
        "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";

    unsigned char expected[64];
    TEST_ASSERT(hex_to_bytes(expected_hex, expected, 64), "hex decode failed");

    unsigned char seed[64];
    TEST_ASSERT(bip39_mnemonic_to_seed(mnemonic, passphrase, seed),
                "mnemonic_to_seed failed");

    TEST_ASSERT(memcmp(seed, expected, 64) == 0, "seed mismatch vs TREZOR vector");

    return 1;
}

/* Test 7: Seed derivation with empty passphrase (different result). */
int test_bip39_seed_no_passphrase(void) {
    const char *mnemonic = "abandon abandon abandon abandon abandon abandon "
                           "abandon abandon abandon abandon abandon about";

    unsigned char seed_no_pass[64];
    unsigned char seed_trezor[64];

    TEST_ASSERT(bip39_mnemonic_to_seed(mnemonic, "", seed_no_pass),
                "seed no-pass failed");
    TEST_ASSERT(bip39_mnemonic_to_seed(mnemonic, "TREZOR", seed_trezor),
                "seed trezor failed");

    /* Seeds must differ with different passphrases */
    TEST_ASSERT(memcmp(seed_no_pass, seed_trezor, 64) != 0,
                "different passphrases should produce different seeds");

    /* NULL passphrase should equal empty passphrase */
    unsigned char seed_null[64];
    TEST_ASSERT(bip39_mnemonic_to_seed(mnemonic, NULL, seed_null),
                "seed null-pass failed");
    TEST_ASSERT(memcmp(seed_no_pass, seed_null, 64) == 0,
                "NULL and empty passphrase should produce same seed");

    return 1;
}

/* Test 8: Non-trivial entropy vector.
   Vector from trezor/python-mnemonic:
   entropy: 7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f
   mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow" */
int test_bip39_vector_7f(void) {
    unsigned char entropy[16];
    memset(entropy, 0x7f, sizeof(entropy));

    char mnemonic[512];
    TEST_ASSERT(bip39_entropy_to_mnemonic(entropy, 16, mnemonic, sizeof(mnemonic)),
                "entropy_to_mnemonic failed");

    TEST_ASSERT(strcmp(mnemonic,
        "legal winner thank year wave sausage worth useful "
        "legal winner thank yellow") == 0,
        "7f-vector mnemonic mismatch");

    return 1;
}

/* Test 9: Generate produces valid mnemonic (12 and 24 words). */
int test_bip39_generate(void) {
    char mnemonic12[512];
    TEST_ASSERT(bip39_generate(12, mnemonic12, sizeof(mnemonic12)),
                "generate 12 words failed");
    TEST_ASSERT(bip39_validate(mnemonic12), "generated 12-word mnemonic invalid");

    /* Count words */
    int wc = 1;
    for (const char *p = mnemonic12; *p; p++)
        if (*p == ' ') wc++;
    TEST_ASSERT(wc == 12, "should generate 12 words");

    char mnemonic24[1024];
    TEST_ASSERT(bip39_generate(24, mnemonic24, sizeof(mnemonic24)),
                "generate 24 words failed");
    TEST_ASSERT(bip39_validate(mnemonic24), "generated 24-word mnemonic invalid");

    wc = 1;
    for (const char *p = mnemonic24; *p; p++)
        if (*p == ' ') wc++;
    TEST_ASSERT(wc == 24, "should generate 24 words");

    return 1;
}

/* Test 10: End-to-end integration: mnemonic -> seed -> keyfile. */
int test_bip39_keyfile_integration(void) {
    const char *mnemonic = "abandon abandon abandon abandon abandon abandon "
                           "abandon abandon abandon abandon abandon about";
    const char *keyfile_path = "/tmp/test_bip39_keyfile.key";
    const char *passphrase = "test-pass";

    /* Derive BIP39 seed */
    unsigned char seed[64];
    TEST_ASSERT(bip39_mnemonic_to_seed(mnemonic, "", seed),
                "mnemonic_to_seed failed");

    /* Generate keyfile from seed */
    unsigned char seckey[32];
    TEST_ASSERT(keyfile_generate_from_seed(keyfile_path, seckey, passphrase,
                seed, 64, NULL),
                "keyfile_generate_from_seed failed");

    /* Load it back */
    unsigned char loaded[32];
    TEST_ASSERT(keyfile_load(keyfile_path, loaded, passphrase),
                "keyfile_load failed");

    TEST_ASSERT(memcmp(seckey, loaded, 32) == 0,
                "loaded key should match generated key");

    /* Deterministic: same mnemonic should produce same key */
    unsigned char seckey2[32];
    TEST_ASSERT(keyfile_generate_from_seed("/tmp/test_bip39_kf2.key", seckey2,
                passphrase, seed, 64, NULL),
                "second keyfile_generate_from_seed failed");
    TEST_ASSERT(memcmp(seckey, seckey2, 32) == 0,
                "same mnemonic should produce same key");

    secure_zero(seed, sizeof(seed));
    secure_zero(seckey, sizeof(seckey));
    secure_zero(seckey2, sizeof(seckey2));
    secure_zero(loaded, sizeof(loaded));

    remove(keyfile_path);
    remove("/tmp/test_bip39_kf2.key");
    return 1;
}
