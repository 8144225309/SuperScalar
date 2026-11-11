#include "superscalar/keyfile.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define TEST_ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { \
        printf("  FAIL: %s (line %d): %s (got %ld, expected %ld)\n", \
               __func__, __LINE__, msg, (long)(a), (long)(b)); \
        return 0; \
    } \
} while(0)

/* From noise.c */
extern void hkdf_extract(unsigned char prk[32], const unsigned char *salt, size_t salt_len,
                          const unsigned char *ikm, size_t ikm_len);
extern void hkdf_expand(unsigned char *okm, size_t okm_len, const unsigned char prk[32],
                         const unsigned char *info, size_t info_len);
extern int aead_encrypt(unsigned char *ciphertext, unsigned char tag[16],
                         const unsigned char *plaintext, size_t pt_len,
                         const unsigned char *aad, size_t aad_len,
                         const unsigned char key[32], const unsigned char nonce[12]);

/* ---- Test: v2 round-trip (generate + load) ---- */

int test_keyfile_v2_roundtrip(void) {
    const char *path = "/tmp/test_keyfile_v2.key";
    unlink(path);

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char seckey[32];
    TEST_ASSERT(keyfile_generate(path, seckey, "testpass123", ctx),
                "generate v2 keyfile");

    /* File should be v2 size (84 bytes) */
    TEST_ASSERT(!keyfile_needs_upgrade(path), "should not need upgrade");

    /* Load and verify */
    unsigned char loaded[32];
    TEST_ASSERT(keyfile_load(path, loaded, "testpass123"), "load v2 keyfile");
    TEST_ASSERT(memcmp(seckey, loaded, 32) == 0, "secret key matches");

    secp256k1_context_destroy(ctx);
    unlink(path);
    return 1;
}

/* ---- Test: v1 backward compatibility ---- */

int test_keyfile_v1_compat(void) {
    const char *path = "/tmp/test_keyfile_v1_compat.key";
    unlink(path);

    /* Manually construct a v1 keyfile using the old KDF */
    unsigned char seckey[32];
    memset(seckey, 0x42, 32);

    /* Derive key using v1 KDF (HKDF) */
    static const unsigned char salt[] = "superscalar-keyfile-v1";
    static const unsigned char info[] = "keyfile-encryption";
    unsigned char prk[32], enc_key[32];
    hkdf_extract(prk, salt, sizeof(salt) - 1,
                 (const unsigned char *)"oldpass", 7);
    hkdf_expand(enc_key, 32, prk, info, sizeof(info) - 1);

    /* Generate nonce */
    unsigned char nonce[12];
    FILE *urand = fopen("/dev/urandom", "rb");
    TEST_ASSERT(urand != NULL, "urandom");
    TEST_ASSERT(fread(nonce, 1, 12, urand) == 12, "read nonce");
    fclose(urand);

    /* Encrypt */
    unsigned char ciphertext[32], tag[16];
    aead_encrypt(ciphertext, tag, seckey, 32, NULL, 0, enc_key, nonce);

    /* Write v1 format: [nonce:12][ct:32][tag:16] = 60 bytes */
    FILE *fp = fopen(path, "wb");
    TEST_ASSERT(fp != NULL, "open for write");
    fwrite(nonce, 1, 12, fp);
    fwrite(ciphertext, 1, 32, fp);
    fwrite(tag, 1, 16, fp);
    fclose(fp);

    /* Should detect as needing upgrade */
    TEST_ASSERT(keyfile_needs_upgrade(path), "v1 needs upgrade");

    /* Load should work with v1 auto-detection */
    unsigned char loaded[32];
    TEST_ASSERT(keyfile_load(path, loaded, "oldpass"), "load v1 keyfile");
    TEST_ASSERT(memcmp(loaded, seckey, 32) == 0, "v1 secret matches");

    unlink(path);
    return 1;
}

/* ---- Test: wrong passphrase on v2 ---- */

int test_keyfile_wrong_passphrase_v2(void) {
    const char *path = "/tmp/test_keyfile_wrongpw.key";
    unlink(path);

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char seckey[32];
    TEST_ASSERT(keyfile_generate(path, seckey, "correct-pass", ctx),
                "generate");

    /* Loading with wrong passphrase should fail */
    unsigned char loaded[32];
    TEST_ASSERT(!keyfile_load(path, loaded, "wrong-pass"),
                "wrong passphrase rejected");

    secp256k1_context_destroy(ctx);
    unlink(path);
    return 1;
}

/* ---- HD Key Derivation Tests ---- */

#include "superscalar/hd_key.h"

/* Utility to decode hex string to bytes */
static int hex_to_bytes(const char *hex, unsigned char *out, size_t max_len) {
    size_t hex_len = strlen(hex);
    size_t byte_len = hex_len / 2;
    if (byte_len > max_len) return 0;
    for (size_t i = 0; i < byte_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2*i, "%02x", &byte) != 1) return 0;
        out[i] = (unsigned char)byte;
    }
    return (int)byte_len;
}

/* BIP32 Test Vector 1: master from seed */
int test_hd_master_from_seed(void) {
    /* BIP32 TV1 seed: 000102030405060708090a0b0c0d0e0f */
    unsigned char seed[16];
    hex_to_bytes("000102030405060708090a0b0c0d0e0f", seed, 16);

    unsigned char master_key[32], chain_code[32];
    TEST_ASSERT(hd_key_from_seed(seed, 16, master_key, chain_code),
                "derive master from seed");

    /* Expected master secret key (BIP32 TV1):
       e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35 */
    unsigned char expected_key[32];
    hex_to_bytes("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
                 expected_key, 32);
    TEST_ASSERT(memcmp(master_key, expected_key, 32) == 0, "master key matches BIP32 TV1");

    /* Expected chain code:
       873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508 */
    unsigned char expected_cc[32];
    hex_to_bytes("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
                 expected_cc, 32);
    TEST_ASSERT(memcmp(chain_code, expected_cc, 32) == 0, "chain code matches BIP32 TV1");

    return 1;
}

/* BIP32 Test Vector 1: m/0' */
int test_hd_derive_child(void) {
    /* Start from TV1 master */
    unsigned char seed[16];
    hex_to_bytes("000102030405060708090a0b0c0d0e0f", seed, 16);

    unsigned char master_key[32], master_cc[32];
    TEST_ASSERT(hd_key_from_seed(seed, 16, master_key, master_cc), "master");

    unsigned char child_key[32], child_cc[32];
    TEST_ASSERT(hd_key_derive_child(master_key, master_cc,
                                     0 | HD_HARDENED,
                                     child_key, child_cc),
                "derive m/0'");

    /* Expected m/0' key:
       edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea */
    unsigned char expected_key[32];
    hex_to_bytes("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
                 expected_key, 32);
    TEST_ASSERT(memcmp(child_key, expected_key, 32) == 0,
                "m/0' key matches BIP32 TV1");

    /* Expected m/0' chain code:
       47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141 */
    unsigned char expected_cc[32];
    hex_to_bytes("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
                 expected_cc, 32);
    TEST_ASSERT(memcmp(child_cc, expected_cc, 32) == 0,
                "m/0' chain code matches BIP32 TV1");

    return 1;
}

/* hd_key_derive_path: multi-level + non-hardened rejection */
int test_hd_derive_path(void) {
    unsigned char seed[16];
    hex_to_bytes("000102030405060708090a0b0c0d0e0f", seed, 16);

    /* Derive m/0' via path API and compare with manual derivation */
    unsigned char path_key[32];
    TEST_ASSERT(hd_key_derive_path(seed, 16, "m/0'", path_key),
                "derive path m/0'");

    unsigned char expected[32];
    hex_to_bytes("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
                 expected, 32);
    TEST_ASSERT(memcmp(path_key, expected, 32) == 0,
                "path m/0' matches manual derivation");

    /* Multi-level: m/0'/1' should work */
    unsigned char ml_key[32];
    TEST_ASSERT(hd_key_derive_path(seed, 16, "m/0'/1'", ml_key),
                "derive multi-level m/0'/1'");

    /* Non-hardened path should be rejected */
    unsigned char bad_key[32];
    TEST_ASSERT(!hd_key_derive_path(seed, 16, "m/0'/1", bad_key),
                "non-hardened rejected");

    /* Just "m" returns master key */
    unsigned char m_key[32];
    TEST_ASSERT(hd_key_derive_path(seed, 16, "m", m_key), "path 'm' works");
    unsigned char master[32], cc[32];
    hd_key_from_seed(seed, 16, master, cc);
    TEST_ASSERT(memcmp(m_key, master, 32) == 0, "path 'm' = master key");

    return 1;
}

/* keyfile_generate_from_seed: deterministic, same seed = same key */
int test_keyfile_from_seed(void) {
    const char *path1 = "/tmp/test_kf_seed1.key";
    const char *path2 = "/tmp/test_kf_seed2.key";
    const char *path3 = "/tmp/test_kf_seed3.key";
    unlink(path1);
    unlink(path2);
    unlink(path3);

    unsigned char seed[16];
    hex_to_bytes("000102030405060708090a0b0c0d0e0f", seed, 16);

    unsigned char key1[32], key2[32], key3[32];

    /* Same seed + same path = same key */
    TEST_ASSERT(keyfile_generate_from_seed(path1, key1, "pass",
                                            seed, 16, "m/1039'/0'/0'"),
                "generate from seed 1");
    TEST_ASSERT(keyfile_generate_from_seed(path2, key2, "pass",
                                            seed, 16, "m/1039'/0'/0'"),
                "generate from seed 2");
    TEST_ASSERT(memcmp(key1, key2, 32) == 0, "same seed+path = same key");

    /* Same seed + different path = different key */
    TEST_ASSERT(keyfile_generate_from_seed(path3, key3, "pass",
                                            seed, 16, "m/1039'/0'/1'"),
                "generate from seed 3 (different path)");
    TEST_ASSERT(memcmp(key1, key3, 32) != 0, "different path = different key");

    /* Verify saved file can be loaded */
    unsigned char loaded[32];
    TEST_ASSERT(keyfile_load(path1, loaded, "pass"), "load seed-derived keyfile");
    TEST_ASSERT(memcmp(loaded, key1, 32) == 0, "loaded matches derived");

    unlink(path1);
    unlink(path2);
    unlink(path3);
    return 1;
}

/* Mode bits of a file, or -1 if it cannot be stat'ed. */
static int file_mode(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (int)(st.st_mode & 07777);
}

/* The keyfile holds the node's secret key: it must be owner-only whatever the
   umask is, and whatever mode a file already at that path had. */
int test_keyfile_created_owner_only(void) {
    const char *path = "/tmp/test_keyfile_mode.key";
    unlink(path);

    unsigned char seckey[32];
    memset(seckey, 0x42, 32);

    mode_t old_umask = umask(0);
    int saved = keyfile_save(path, seckey, "pass");
    int mode_fresh = file_mode(path);

    /* A permissive file already at the path must not keep its mode. */
    int chmod_ok = (chmod(path, 0644) == 0);
    int resaved = keyfile_save(path, seckey, "pass");
    int mode_resaved = file_mode(path);
    umask(old_umask);

    TEST_ASSERT(saved, "keyfile_save");
    TEST_ASSERT_EQ(mode_fresh, 0600, "new keyfile mode");
    TEST_ASSERT(chmod_ok, "chmod 0644");
    TEST_ASSERT(resaved, "keyfile_save over existing file");
    TEST_ASSERT_EQ(mode_resaved, 0600, "rewritten keyfile mode");

    unlink(path);
    return 1;
}

/* Read a whole (small) file; returns its length, or -1 if it cannot be read. */
static long slurp(const char *path, unsigned char *buf, size_t max) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    size_t n = fread(buf, 1, max, fp);
    fclose(fp);
    return (long)n;
}

static int spit(const char *path, const unsigned char *buf, size_t len) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return 0;
    size_t n = fwrite(buf, 1, len, fp);
    return fclose(fp) == 0 && n == len;
}

/* No file at the path: a key is created; the next start loads that same key. */
int test_keyfile_load_or_generate_new_path(void) {
    const char *path = "/tmp/test_keyfile_open_new.key";
    unlink(path);

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char first[32], second[32];
    TEST_ASSERT_EQ(keyfile_load_or_generate(path, first, "pw", ctx),
                   KEYFILE_OPEN_GENERATED, "first start creates the key");
    TEST_ASSERT(keyfile_exists(path), "keyfile exists after creation");
    TEST_ASSERT_EQ(keyfile_load_or_generate(path, second, "pw", ctx),
                   KEYFILE_OPEN_LOADED, "second start loads the key");
    TEST_ASSERT(memcmp(first, second, 32) == 0, "same key on both starts");

    secp256k1_context_destroy(ctx);
    unlink(path);
    return 1;
}

/* A wrong (or empty) passphrase must fail the start-up and must not cost the
   operator the key that is in the file. */
int test_keyfile_wrong_passphrase_keeps_file(void) {
    const char *path = "/tmp/test_keyfile_open_wrongpw.key";
    unlink(path);

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char original[32];
    TEST_ASSERT(keyfile_generate(path, original, "right-pass", ctx), "generate");

    unsigned char before[128], after[128];
    long before_len = slurp(path, before, sizeof(before));
    TEST_ASSERT_EQ(before_len, KEYFILE_SIZE_V2, "keyfile size");

    static const char *const wrong[] = { "wrong-pass", "" };
    for (size_t i = 0; i < sizeof(wrong) / sizeof(wrong[0]); i++) {
        unsigned char out[32];
        TEST_ASSERT_EQ(keyfile_load_or_generate(path, out, wrong[i], ctx),
                       KEYFILE_OPEN_LOAD_FAILED, "wrong passphrase is an error");
        long after_len = slurp(path, after, sizeof(after));
        TEST_ASSERT_EQ(after_len, before_len, "keyfile length unchanged");
        TEST_ASSERT(memcmp(before, after, (size_t)before_len) == 0,
                    "keyfile bytes unchanged");
    }

    unsigned char reloaded[32];
    TEST_ASSERT(keyfile_load(path, reloaded, "right-pass"),
                "original key still loads with the right passphrase");
    TEST_ASSERT(memcmp(original, reloaded, 32) == 0, "original key intact");

    secp256k1_context_destroy(ctx);
    unlink(path);
    return 1;
}

/* A file that is not a loadable keyfile (truncated, garbage, empty) is left
   exactly as it is: it may be the only remaining copy of a damaged key. */
int test_keyfile_corrupt_file_kept(void) {
    const char *path = "/tmp/test_keyfile_open_corrupt.key";

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char garbage[40];
    memset(garbage, 0x5A, sizeof(garbage));
    static const size_t lens[] = { sizeof(garbage), 0 };

    for (size_t i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        unlink(path);
        TEST_ASSERT(spit(path, garbage, lens[i]), "write unloadable file");

        unsigned char out[32], after[128];
        TEST_ASSERT_EQ(keyfile_load_or_generate(path, out, "pw", ctx),
                       KEYFILE_OPEN_LOAD_FAILED, "unloadable file is an error");
        long after_len = slurp(path, after, sizeof(after));
        TEST_ASSERT_EQ(after_len, (long)lens[i], "file length unchanged");
        TEST_ASSERT(memcmp(garbage, after, lens[i]) == 0, "file bytes unchanged");
    }

    secp256k1_context_destroy(ctx);
    unlink(path);
    return 1;
}

/* The generators create key material; neither may replace an existing file. */
int test_keyfile_generate_refuses_existing(void) {
    const char *path = "/tmp/test_keyfile_noclobber.key";
    unlink(path);

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char original[32], out[32];
    TEST_ASSERT(keyfile_generate(path, original, "pw", ctx), "generate");

    unsigned char before[128], after[128];
    long before_len = slurp(path, before, sizeof(before));
    TEST_ASSERT_EQ(before_len, KEYFILE_SIZE_V2, "keyfile size");

    TEST_ASSERT(!keyfile_generate(path, out, "pw", ctx),
                "keyfile_generate refuses an existing file");

    unsigned char seed[16];
    memset(seed, 0x07, sizeof(seed));
    TEST_ASSERT(!keyfile_generate_from_seed(path, out, "pw", seed, sizeof(seed), NULL),
                "keyfile_generate_from_seed refuses an existing file");

    TEST_ASSERT_EQ(slurp(path, after, sizeof(after)), before_len, "length unchanged");
    TEST_ASSERT(memcmp(before, after, (size_t)before_len) == 0, "bytes unchanged");

    secp256k1_context_destroy(ctx);
    unlink(path);
    return 1;
}

/* keyfile_save replaces the file in one step and leaves no temporary file
   behind, on success or on failure. */
int test_keyfile_save_replaces_atomically(void) {
    const char *dir = "/tmp/test_keyfile_atomic.d";
    const char *path = "/tmp/test_keyfile_atomic.d/node.key";
    unlink(path);
    rmdir(dir);
    TEST_ASSERT(mkdir(dir, 0700) == 0, "mkdir");

    unsigned char key_a[32], key_b[32], loaded[32];
    memset(key_a, 0x11, 32);
    memset(key_b, 0x22, 32);

    TEST_ASSERT(keyfile_save(path, key_a, "pw"), "first save");
    struct stat st_a, st_b;
    TEST_ASSERT(stat(path, &st_a) == 0, "stat first");

    TEST_ASSERT(keyfile_save(path, key_b, "pw"), "second save");
    TEST_ASSERT(stat(path, &st_b) == 0, "stat second");
    /* Replaced by rename of a complete new file, not rewritten in place. */
    TEST_ASSERT(st_a.st_ino != st_b.st_ino, "file replaced, not truncated");
    TEST_ASSERT(keyfile_load(path, loaded, "pw"), "load after replace");
    TEST_ASSERT(memcmp(loaded, key_b, 32) == 0, "new key stored");

    /* The path is a directory: the save fails and nothing is left behind. */
    TEST_ASSERT(!keyfile_save(dir, key_a, "pw"), "save onto a directory fails");

    int entries = 0;
    DIR *d = opendir(dir);
    TEST_ASSERT(d != NULL, "opendir");
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0)
            entries++;
    }
    closedir(d);
    TEST_ASSERT_EQ(entries, 1, "only the keyfile is in its directory");

    d = opendir("/tmp");
    TEST_ASSERT(d != NULL, "opendir /tmp");
    int stray = 0;
    while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, "test_keyfile_atomic.d.", 22) == 0)
            stray++;
    }
    closedir(d);
    TEST_ASSERT_EQ(stray, 0, "no temporary file left after a failed save");

    unlink(path);
    rmdir(dir);
    return 1;
}

/* A keyfile path that is a symbolic link is never written through: saving
   over the link and generating at it both fail, and the link's target is
   neither replaced nor created.  Reading a key through a link is fine. */
int test_keyfile_symlink_path(void) {
    const char *target = "/tmp/test_keyfile_symlink_target.key";
    const char *link_path = "/tmp/test_keyfile_symlink.key";
    const char *dangling = "/tmp/test_keyfile_symlink_dangling.key";
    const char *missing = "/tmp/test_keyfile_symlink_missing.key";
    unlink(target);
    unlink(link_path);
    unlink(dangling);
    unlink(missing);

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char key_a[32], key_b[32], out[32];
    memset(key_a, 0x31, 32);
    memset(key_b, 0x32, 32);
    TEST_ASSERT(keyfile_save(target, key_a, "pw"), "save target");
    TEST_ASSERT(symlink(target, link_path) == 0, "symlink");
    TEST_ASSERT(symlink(missing, dangling) == 0, "dangling symlink");

    unsigned char before[128], after[128];
    long before_len = slurp(target, before, sizeof(before));

    TEST_ASSERT(keyfile_load(link_path, out, "pw"), "load through a symlink");
    TEST_ASSERT(memcmp(out, key_a, 32) == 0, "key read through the link");

    TEST_ASSERT(!keyfile_save(link_path, key_b, "pw"), "save over a symlink is refused");
    TEST_ASSERT(!keyfile_generate(link_path, out, "pw", ctx),
                "generate at a symlink is refused");
    TEST_ASSERT_EQ(keyfile_load_or_generate(link_path, out, "wrong", ctx),
                   KEYFILE_OPEN_LOAD_FAILED, "unloadable key behind a symlink is an error");
    TEST_ASSERT_EQ(slurp(target, after, sizeof(after)), before_len, "target length unchanged");
    TEST_ASSERT(memcmp(before, after, (size_t)before_len) == 0, "target bytes unchanged");

    /* A dangling link is something at the path, so no key is generated, and
       nothing is created where the link points. */
    TEST_ASSERT(keyfile_exists(dangling), "a dangling link counts as existing");
    TEST_ASSERT(!keyfile_save(dangling, key_b, "pw"), "save over a dangling link is refused");
    TEST_ASSERT(!keyfile_generate(dangling, out, "pw", ctx),
                "generate at a dangling link is refused");
    TEST_ASSERT_EQ(keyfile_load_or_generate(dangling, out, "pw", ctx),
                   KEYFILE_OPEN_LOAD_FAILED, "a dangling link is an error, not a new key");
    struct stat st;
    TEST_ASSERT(lstat(missing, &st) != 0, "nothing created at the link target");
    TEST_ASSERT(lstat(dangling, &st) == 0 && S_ISLNK(st.st_mode), "link still a link");
    TEST_ASSERT(lstat(link_path, &st) == 0 && S_ISLNK(st.st_mode), "link still a link");

    secp256k1_context_destroy(ctx);
    unlink(target);
    unlink(link_path);
    unlink(dangling);
    return 1;
}
