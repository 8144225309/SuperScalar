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
   Expected seed (hex): c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553
                         1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04 */
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

/* The official BIP39 English test vectors: all 24 entries of vectors.json in
   trezor/python-mnemonic (entropy, mnemonic, seed with passphrase "TREZOR").
   They cover 12-, 18- and 24-word phrases. */
typedef struct {
    const char *entropy_hex;
    const char *mnemonic;
    const char *seed_hex;
} bip39_vector_t;

static const bip39_vector_t BIP39_VECTORS[] = {
    { "00000000000000000000000000000000",
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon about",
      "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
      "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04" },
    { "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
      "legal winner thank year wave sausage worth useful legal winner thank "
      "yellow",
      "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f"
      "a457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607" },
    { "80808080808080808080808080808080",
      "letter advice cage absurd amount doctor acoustic avoid letter advice cage "
      "above",
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
    { "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
      "legal winner thank year wave sausage worth useful legal winner thank year "
      "wave sausage worth useful legal will",
      "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a"
      "0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd" },
    { "808080808080808080808080808080808080808080808080",
      "letter advice cage absurd amount doctor acoustic avoid letter advice cage "
      "absurd amount doctor acoustic avoid letter always",
      "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc2"
      "7fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65" },
    { "ffffffffffffffffffffffffffffffffffffffffffffffff",
      "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
      "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a7"
      "6379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528" },
    { "0000000000000000000000000000000000000000000000000000000000000000",
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon art",
      "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971"
      "70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8" },
    { "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
      "legal winner thank year wave sausage worth useful legal winner thank year "
      "wave sausage worth useful legal winner thank year wave sausage worth title",
      "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a40"
      "21b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87" },
    { "8080808080808080808080808080808080808080808080808080808080808080",
      "letter advice cage absurd amount doctor acoustic avoid letter advice cage "
      "absurd amount doctor acoustic avoid letter advice cage absurd amount "
      "doctor acoustic bless",
      "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09"
      "e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f" },
    { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
      "zoo zoo zoo zoo zoo vote",
      "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e16"
      "13912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad" },
    { "9e885d952ad362caeb4efe34a8e91bd2",
      "ozone drill grab fiber curtain grace pudding thank cruise elder eight "
      "picnic",
      "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e547"
      "6c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028" },
    { "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
      "gravity machine north sort system female filter attitude volume fold club "
      "stay feature office ecology stable narrow fog",
      "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e"
      "4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac" },
    { "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
      "hamster diagram private dutch cause delay private meat slide toddler razor "
      "book happy fancy gospel tennis maple dilemma loan word shrug inflict delay "
      "length",
      "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d2"
      "0b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440" },
    { "c0ba5a8e914111210f2bd131f3d5e08d",
      "scheme spot photo card baby mountain device kick cradle pact join borrow",
      "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fc"
      "a05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612" },
    { "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
      "horn tenant knee talent sponsor spell gate clip pulse soap slush warm "
      "silver nephew swap uncle crack brave",
      "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853"
      "c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d" },
    { "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
      "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft "
      "ostrich alcohol speed nation flash devote level hobby quick inner drive "
      "ghost inside",
      "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6"
      "fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d" },
    { "23db8160a31d3e0dca3688ed941adbf3",
      "cat swing flag economy stadium alone churn speed unique patch report train",
      "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b592"
      "05a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5" },
    { "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
      "light rule cinnamon wrap drastic word pride squirrel upgrade then income "
      "fatal apart sustain crack supply proud access",
      "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b7"
      "82925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02" },
    { "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
      "all hour make first leader extend hole alien behind guard gospel lava path "
      "output census museum junior mass reopen famous sing advance salt reform",
      "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6"
      "df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d" },
    { "f30f8c1da665478f49b001d94c5fc452",
      "vessel ladder alter error federal sibling chat ability sun glass valve "
      "picture",
      "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090b"
      "f9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f" },
    { "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
      "scissors invite lock maple supreme raw rapid void congress muscle digital "
      "elegant little brisk hair mango congress clump",
      "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4"
      "f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88" },
    { "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
      "void come effort suffer camp survey warrior heavy shoot primary clutch "
      "crush open amazing screen patrol group space point ten exist slush involve "
      "unfold",
      "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0"
      "e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998" },
};
#define N_BIP39_VECTORS (sizeof(BIP39_VECTORS) / sizeof(BIP39_VECTORS[0]))

/* The official set has no 15- or 21-word phrase.  These fill the gap: 160-
   and 224-bit entropy, with mnemonic and seed (passphrase "TREZOR") computed
   by a separate reference implementation of the BIP39 algorithm that
   reproduces all 24 official vectors. */
static const bip39_vector_t BIP39_VECTORS_15_21[] = {
    { "0000000000000000000000000000000000000000",
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon address",
      "fa08713f46bf5cb48728ceb70e3aae1bc53c5cb7b4e29c5610261d1cbb7be3be"
      "d4d805256fec515754d2be35974fc5da678168e9d9bb0cb70948026923b0def3" },
    { "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
      "legal winner thank year wave sausage worth useful legal winner thank year "
      "wave sausage wise",
      "f938c2f3ebd11f1c9057b713d977b5260e4282a57811ab163a9708c4ce153079"
      "83ac24c4451c7cb353b2002d0a1ee8a404fa59f0f6aa8323fa9bb61248cf4808" },
    { "8080808080808080808080808080808080808080",
      "letter advice cage absurd amount doctor acoustic avoid letter advice cage "
      "absurd amount doctor accident",
      "bc40a19ec918698b32e3e13ed906006d9e3b9987ba7dee6fc53a824774cc5be6"
      "8f89b865bbfbac21b2fb99c016e214f54f239f77dd99881c1b81de275c60be3d" },
    { "ffffffffffffffffffffffffffffffffffffffff",
      "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrist",
      "bfee6f9d2bcfa1331bd6482a24abca521e5f7e769498b9a0146672194c7356e4"
      "e409be22bc379c8b64fee2aa24b54d3ec20d10a083eaa5d1d6b4b365941ad37c" },
    { "69ed8e78cd245e17a46202dc897c10fb78aa7fd4",
      "hazard hockey owner olympic echo armed muscle doctor symptom episode "
      "aerobic want melt divide fashion",
      "2d4b7283f4ba4b4e8f090cdffe4dd0f8774f554e75b64b7ad96c4185bec75eaf"
      "aaa6ad70408ccef1d8ecf5ff3bd5806b1265c9f15d0a2dafa54e1ca10320267e" },
    { "00000000000000000000000000000000000000000000000000000000",
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon admit",
      "e7dadc189d2e8d07ac278d9ec98a1d2d327e4a6b7df494c00cbf2cbf2d3543da"
      "c7000fc72d4ada8d9997dc8db388ff22c6d79f604a7455f2df5534a28eee04c6" },
    { "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
      "legal winner thank year wave sausage worth useful legal winner thank year "
      "wave sausage worth useful legal winner thank year viable",
      "99c0597b2bef5ca4859e21075fee0fc931747a30469b6f564d95f74913c357ac"
      "eb55221b4f4fe6965e871340b45754b1ae59e53da1797b69b30c5fa40ec105b8" },
    { "80808080808080808080808080808080808080808080808080808080",
      "letter advice cage absurd amount doctor acoustic avoid letter advice cage "
      "absurd amount doctor acoustic avoid letter advice cage absurd apart",
      "708f0487a927474944ed882e5f05954656bd82bebcf4119b1233e90ee8b27b16"
      "d48a77be2c2aceecc32b07a94a5e9a04d94856a2b9fd7c2362ac4153420ef2e6" },
    { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
      "zoo zoo veteran",
      "4aa0af4ca02ef1d9fa675cd02aa06d318425564e7fadd3d51b6165cc56d77398"
      "f28d8522073cd036c2a4a24a83e919211c84500d96cb120084e613ff5fcd96c1" },
    { "3ea4cc13a3edc47bd067eb1c1b5754385dc0983edca4a2ae33cbd03b",
      "dirt chapter agent elephant sword digital dose word bright survey steak "
      "idle swing equal window nest pencil immense very parrot reveal",
      "3b3de79d6227d15c80af907e6e95b3d8b3a21a3bc8cb537466d6f583fbe0d0b5"
      "07f820805b4100434a704120b79d01cd76672f5753dce32ee5f00819f7707f5d" },
};
#define N_BIP39_VECTORS_15_21 \
    (sizeof(BIP39_VECTORS_15_21) / sizeof(BIP39_VECTORS_15_21[0]))

/* Check one vector in every direction: entropy -> mnemonic, mnemonic ->
   entropy, validity and seed.  Returns the phrase length in words, 0 on a
   mismatch. */
static size_t check_vector(const bip39_vector_t *v) {
    size_t ent_len = strlen(v->entropy_hex) / 2;
    unsigned char entropy[32], recovered[32], expected_seed[64], seed[64];
    if (!hex_to_bytes(v->entropy_hex, entropy, ent_len)) return 0;
    if (!hex_to_bytes(v->seed_hex, expected_seed, 64)) return 0;

    char mnemonic[512];
    if (!bip39_entropy_to_mnemonic(entropy, ent_len, mnemonic, sizeof(mnemonic))) return 0;
    if (strcmp(mnemonic, v->mnemonic) != 0) return 0;

    if (bip39_check(v->mnemonic) != BIP39_OK) return 0;
    if (bip39_mnemonic_to_entropy(v->mnemonic, recovered, sizeof(recovered)) != ent_len)
        return 0;
    if (memcmp(recovered, entropy, ent_len) != 0) return 0;

    if (!bip39_mnemonic_to_seed(v->mnemonic, "TREZOR", seed)) return 0;
    if (memcmp(seed, expected_seed, 64) != 0) return 0;

    size_t n_words = 1;
    for (const char *c = v->mnemonic; *c; c++) {
        if (*c == ' ') n_words++;
    }
    return n_words;
}

/* Every official vector, in every direction. */
int test_bip39_official_vectors(void) {
    size_t by_length[25] = { 0 };
    TEST_ASSERT(N_BIP39_VECTORS == 24, "the official set has 24 vectors");
    for (size_t i = 0; i < N_BIP39_VECTORS; i++) {
        size_t n_words = check_vector(&BIP39_VECTORS[i]);
        if (n_words == 0)
            printf("  official vector %zu does not match\n", i);
        TEST_ASSERT(n_words == 12 || n_words == 18 || n_words == 24,
                    "official vector matches");
        by_length[n_words]++;
    }
    TEST_ASSERT(by_length[12] == 8 && by_length[18] == 8 && by_length[24] == 8,
                "eight vectors each of 12, 18 and 24 words");
    return 1;
}

/* 15- and 21-word phrases (160- and 224-bit entropy), and the phrase lengths
   around them that are not valid. */
int test_bip39_15_and_21_words(void) {
    size_t by_length[25] = { 0 };
    for (size_t i = 0; i < N_BIP39_VECTORS_15_21; i++) {
        size_t n_words = check_vector(&BIP39_VECTORS_15_21[i]);
        if (n_words == 0)
            printf("  15/21-word vector %zu does not match\n", i);
        TEST_ASSERT(n_words == 15 || n_words == 21, "vector matches");
        by_length[n_words]++;
    }
    TEST_ASSERT(by_length[15] == 5 && by_length[21] == 5,
                "five vectors each of 15 and 21 words");

    /* Generated phrases of these lengths validate and round-trip. */
    static const int counts[] = { 15, 21 };
    for (size_t i = 0; i < 2; i++) {
        char generated[512], normalized[256];
        unsigned char entropy[32], seed[64];
        TEST_ASSERT(bip39_generate(counts[i], generated, sizeof(generated)), "generate");
        TEST_ASSERT(bip39_check(generated) == BIP39_OK, "generated phrase is valid");
        TEST_ASSERT(bip39_mnemonic_to_entropy(generated, entropy, sizeof(entropy)) ==
                        (size_t)counts[i] * 4 / 3,
                    "entropy length for the phrase length");
        TEST_ASSERT(bip39_normalize(generated, normalized, sizeof(normalized)) &&
                    strcmp(generated, normalized) == 0, "generated phrase is canonical");
        TEST_ASSERT(bip39_mnemonic_to_seed(generated, "", seed), "seed");
    }

    /* One word short or long of 15 and of 21 is a word-count error; a
       phrase of the right length with one word changed fails the checksum. */
    for (size_t v = 0; v < N_BIP39_VECTORS_15_21; v++) {
        const char *phrase = BIP39_VECTORS_15_21[v].mnemonic;
        char longer[512], shorter[512], altered[512];

        snprintf(longer, sizeof(longer), "%s abandon", phrase);
        TEST_ASSERT(bip39_check(longer) == BIP39_ERR_WORD_COUNT, "16 or 22 words");

        snprintf(shorter, sizeof(shorter), "%s", phrase);
        *strrchr(shorter, ' ') = '\0';
        TEST_ASSERT(bip39_check(shorter) == BIP39_ERR_WORD_COUNT, "14 or 20 words");

        /* Same length, first word replaced by a different wordlist word. */
        const char *rest = strchr(phrase, ' ');
        snprintf(altered, sizeof(altered), "%s%s",
                 strncmp(phrase, "zoo ", 4) == 0 ? "abandon" : "zoo", rest);
        TEST_ASSERT(bip39_check(altered) == BIP39_ERR_CHECKSUM,
                    "a changed word breaks the checksum");
        unsigned char seed[64];
        TEST_ASSERT(!bip39_mnemonic_to_seed(altered, "TREZOR", seed),
                    "no seed from the altered phrase");
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
    snprintf(long_phrase, sizeof(long_phrase), "%s abandon", BIP39_VECTORS[8].mnemonic);
    TEST_ASSERT(bip39_check(long_phrase) == BIP39_ERR_WORD_COUNT, "25 words");
    TEST_ASSERT(!bip39_validate(long_phrase), "25 words do not validate");
    unsigned char entropy[32];
    TEST_ASSERT(bip39_mnemonic_to_entropy(long_phrase, entropy, sizeof(entropy)) == 0,
                "25 words give no entropy");

    /* A phrase of the wrong length is a word-count error whatever its words
       are: the count is what the user has to fix first. */
    snprintf(long_phrase, sizeof(long_phrase), "%s notaword", BIP39_VECTORS[8].mnemonic);
    TEST_ASSERT(bip39_check(long_phrase) == BIP39_ERR_WORD_COUNT,
                "25 words, the last one unknown");
    TEST_ASSERT(bip39_check("legal winner thank year wave sausage worth usefull "
                            "legal winner thank") == BIP39_ERR_WORD_COUNT,
                "11 words, one misspelt");
    TEST_ASSERT(bip39_check("one two three") == BIP39_ERR_WORD_COUNT, "3 words");

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
