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

    remove(keyfile_path);
    remove("/tmp/test_bip39_kf2.key");

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

/* Official BIP39 English test vectors (trezor/python-mnemonic vectors.json,
   passphrase "TREZOR"): entropy, mnemonic, seed. */
static const struct {
    const char *entropy_hex;
    const char *mnemonic;
    const char *seed_hex;
} BIP39_VECTORS[] = {
    { "00000000000000000000000000000000",
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon about",
      "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
      "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04" },
    { "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
      "legal winner thank year wave sausage worth useful legal winner thank yellow",
      "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f"
      "a457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607" },
    { "80808080808080808080808080808080",
      "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
      "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30"
      "fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8" },
    { "ffffffffffffffffffffffffffffffff",
      "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
      "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13"
      "332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069" },
    { "000000000000000000000000000000000000000000000000",
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon abandon abandon abandon agent",
      "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca"
      "06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa" },
    { "0000000000000000000000000000000000000000000000000000000000000000",
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon art",
      "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971"
      "70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8" },
    { "8080808080808080808080808080808080808080808080808080808080808080",
      "letter advice cage absurd amount doctor acoustic avoid letter advice cage "
      "absurd amount doctor acoustic avoid letter advice cage absurd amount doctor "
      "acoustic bless",
      "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09"
      "e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f" },
    { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
      "zoo zoo zoo zoo vote",
      "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e16"
      "13912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad" },
    { "9e885d952ad362caeb4efe34a8e91bd2",
      "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
      "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e547"
      "6c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028" },
    { "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
      "void come effort suffer camp survey warrior heavy shoot primary clutch crush "
      "open amazing screen patrol group space point ten exist slush involve unfold",
      "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0"
      "e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998" },
};
#define N_BIP39_VECTORS (sizeof(BIP39_VECTORS) / sizeof(BIP39_VECTORS[0]))

/* Every official vector: entropy -> mnemonic, mnemonic -> entropy, validity
   and seed. */
int test_bip39_official_vectors(void) {
    for (size_t i = 0; i < N_BIP39_VECTORS; i++) {
        size_t ent_len = strlen(BIP39_VECTORS[i].entropy_hex) / 2;
        unsigned char entropy[32], recovered[32], expected_seed[64], seed[64];
        TEST_ASSERT(hex_to_bytes(BIP39_VECTORS[i].entropy_hex, entropy, ent_len),
                    "entropy hex");
        TEST_ASSERT(hex_to_bytes(BIP39_VECTORS[i].seed_hex, expected_seed, 64),
                    "seed hex");

        char mnemonic[512];
        TEST_ASSERT(bip39_entropy_to_mnemonic(entropy, ent_len, mnemonic, sizeof(mnemonic)),
                    "entropy_to_mnemonic");
        TEST_ASSERT(strcmp(mnemonic, BIP39_VECTORS[i].mnemonic) == 0,
                    "mnemonic matches vector");

        TEST_ASSERT(bip39_check(BIP39_VECTORS[i].mnemonic) == BIP39_OK, "vector is valid");
        TEST_ASSERT(bip39_mnemonic_to_entropy(BIP39_VECTORS[i].mnemonic, recovered,
                                              sizeof(recovered)) == ent_len,
                    "entropy length");
        TEST_ASSERT(memcmp(recovered, entropy, ent_len) == 0, "entropy matches vector");

        TEST_ASSERT(bip39_mnemonic_to_seed(BIP39_VECTORS[i].mnemonic, "TREZOR", seed),
                    "mnemonic_to_seed");
        TEST_ASSERT(memcmp(seed, expected_seed, 64) == 0, "seed matches vector");
    }
    return 1;
}

/* Each kind of defect is reported as what it is. */
int test_bip39_check_reports_reason(void) {
    /* Valid 12-word vector with one word changed to another wordlist word. */
    TEST_ASSERT(bip39_check("legal winner thank year wave sausage worth useful "
                            "legal winner thank year") == BIP39_ERR_CHECKSUM,
                "substituted word breaks the checksum");
    /* Two words swapped. */
    TEST_ASSERT(bip39_check("winner legal thank year wave sausage worth useful "
                            "legal winner thank yellow") == BIP39_ERR_CHECKSUM,
                "swapped words break the checksum");
    /* A one-letter typo. */
    TEST_ASSERT(bip39_check("legal winner thank year wave sausage worth usefull "
                            "legal winner thank yellow") == BIP39_ERR_UNKNOWN_WORD,
                "misspelt word is unknown");
    TEST_ASSERT(bip39_check("Legal winner thank year wave sausage worth useful "
                            "legal winner thank yellow") == BIP39_ERR_UNKNOWN_WORD,
                "capitalised word is unknown");
    TEST_ASSERT(bip39_check("legal winner thank year wave sausage worth useful "
                            "legal winner thank yellowyellowyellow") == BIP39_ERR_UNKNOWN_WORD,
                "overlong word is unknown");

    TEST_ASSERT(bip39_check(NULL) == BIP39_ERR_WORD_COUNT, "NULL");
    TEST_ASSERT(bip39_check("") == BIP39_ERR_WORD_COUNT, "empty phrase");
    TEST_ASSERT(bip39_check("   \t\n") == BIP39_ERR_WORD_COUNT, "whitespace only");
    TEST_ASSERT(bip39_check("legal winner thank year wave sausage worth useful "
                            "legal winner thank") == BIP39_ERR_WORD_COUNT,
                "11 words");
    TEST_ASSERT(bip39_check("legal winner thank year wave sausage worth useful "
                            "legal winner thank yellow abandon") == BIP39_ERR_WORD_COUNT,
                "13 words");

    /* A valid 24-word phrase followed by more words is not a valid phrase. */
    char long_phrase[512];
    snprintf(long_phrase, sizeof(long_phrase), "%s abandon", BIP39_VECTORS[5].mnemonic);
    TEST_ASSERT(bip39_check(long_phrase) == BIP39_ERR_WORD_COUNT, "25 words");
    TEST_ASSERT(!bip39_validate(long_phrase), "25 words do not validate");
    unsigned char entropy[32];
    TEST_ASSERT(bip39_mnemonic_to_entropy(long_phrase, entropy, sizeof(entropy)) == 0,
                "25 words give no entropy");

    for (int st = BIP39_OK; st <= BIP39_ERR_CHECKSUM; st++) {
        const char *msg = bip39_status_str((bip39_status_t)st);
        TEST_ASSERT(msg != NULL && msg[0] != '\0', "every status has a message");
    }
    return 1;
}

/* A phrase that fails validation must never produce a seed: the wallet it
   would open is not the one the user is trying to recover. */
int test_bip39_seed_refuses_invalid_mnemonic(void) {
    static const char *const bad[] = {
        /* substituted word (checksum) */
        "legal winner thank year wave sausage worth useful legal winner thank year",
        /* misspelt word */
        "legal winner thank year wave sausage worth usefull legal winner thank yellow",
        /* a word missing */
        "legal winner thank year wave sausage worth useful legal winner thank",
        /* swapped words */
        "winner legal thank year wave sausage worth useful legal winner thank yellow",
        "",
    };
    static const unsigned char untouched[64] = { 0 };

    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        unsigned char seed[64];
        memset(seed, 0, sizeof(seed));
        TEST_ASSERT(!bip39_mnemonic_to_seed(bad[i], "", seed),
                    "invalid mnemonic must not yield a seed");
        TEST_ASSERT(memcmp(seed, untouched, 64) == 0, "seed buffer not written");

        char norm[256];
        TEST_ASSERT(!bip39_normalize(bad[i], norm, sizeof(norm)),
                    "invalid mnemonic does not normalise");
        TEST_ASSERT(norm[0] == '\0', "no normalised text for an invalid mnemonic");
    }
    return 1;
}

/* Extra whitespace is not part of the phrase: the same words always give the
   same seed, the one from the official vector. */
int test_bip39_whitespace_normalized(void) {
    const char *canonical = BIP39_VECTORS[1].mnemonic;
    static const char *const variants[] = {
        "  legal winner thank year wave sausage worth useful legal winner thank yellow",
        "legal winner thank year wave sausage worth useful legal winner thank yellow\n",
        "legal  winner thank year wave sausage worth useful legal winner thank yellow",
        "legal\twinner thank year wave sausage worth useful legal winner thank yellow",
        " legal winner\nthank year  wave sausage\tworth useful legal winner thank yellow \r\n",
    };

    unsigned char expected[64];
    TEST_ASSERT(hex_to_bytes(BIP39_VECTORS[1].seed_hex, expected, 64), "seed hex");

    for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); i++) {
        TEST_ASSERT(bip39_check(variants[i]) == BIP39_OK, "variant is valid");

        char norm[256];
        TEST_ASSERT(bip39_normalize(variants[i], norm, sizeof(norm)), "normalize");
        TEST_ASSERT(strcmp(norm, canonical) == 0, "normalised to the canonical phrase");

        unsigned char seed[64];
        TEST_ASSERT(bip39_mnemonic_to_seed(variants[i], "TREZOR", seed), "seed");
        TEST_ASSERT(memcmp(seed, expected, 64) == 0,
                    "whitespace variant gives the vector seed");
    }

    char small[16];
    TEST_ASSERT(!bip39_normalize(canonical, small, sizeof(small)),
                "output buffer too small is an error");
    return 1;
}
