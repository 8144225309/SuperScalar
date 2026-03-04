#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "superscalar/backup.h"

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

/* Helper: write bytes to a temp file */
static int write_test_file(const char *path, const unsigned char *data, size_t len) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return 0;
    size_t w = fwrite(data, 1, len, fp);
    fclose(fp);
    return (w == len) ? 1 : 0;
}

/* Helper: read file into buffer, return length */
static size_t read_test_file(const char *path, unsigned char *buf, size_t max) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;
    size_t n = fread(buf, 1, max, fp);
    fclose(fp);
    return n;
}

int test_backup_create_verify_restore(void) {
    const char *db_path = "/tmp/test_backup_db.sqlite";
    const char *kf_path = "/tmp/test_backup_kf.key";
    const char *bak_path = "/tmp/test_backup.bak";
    const char *rest_db = "/tmp/test_backup_restored_db.sqlite";
    const char *rest_kf = "/tmp/test_backup_restored_kf.key";

    /* Create test DB and keyfile with known content */
    unsigned char db_data[128];
    unsigned char kf_data[60];
    for (size_t i = 0; i < sizeof(db_data); i++) db_data[i] = (unsigned char)(i ^ 0xAA);
    for (size_t i = 0; i < sizeof(kf_data); i++) kf_data[i] = (unsigned char)(i ^ 0x55);

    TEST_ASSERT(write_test_file(db_path, db_data, sizeof(db_data)), "write db");
    TEST_ASSERT(write_test_file(kf_path, kf_data, sizeof(kf_data)), "write kf");

    const unsigned char *pass = (const unsigned char *)"test-passphrase-123";
    size_t pass_len = strlen((const char *)pass);

    /* Create backup */
    TEST_ASSERT(backup_create(db_path, kf_path, bak_path, pass, pass_len),
                "backup_create failed");

    /* Verify backup */
    TEST_ASSERT(backup_verify(bak_path, pass, pass_len),
                "backup_verify failed");

    /* Restore */
    TEST_ASSERT(backup_restore(bak_path, rest_db, rest_kf, pass, pass_len),
                "backup_restore failed");

    /* Compare restored files byte-for-byte */
    unsigned char restored_db[256];
    size_t rdb_len = read_test_file(rest_db, restored_db, sizeof(restored_db));
    TEST_ASSERT(rdb_len == sizeof(db_data), "restored db size mismatch");
    TEST_ASSERT(memcmp(restored_db, db_data, sizeof(db_data)) == 0,
                "restored db content mismatch");

    unsigned char restored_kf[128];
    size_t rkf_len = read_test_file(rest_kf, restored_kf, sizeof(restored_kf));
    TEST_ASSERT(rkf_len == sizeof(kf_data), "restored keyfile size mismatch");
    TEST_ASSERT(memcmp(restored_kf, kf_data, sizeof(kf_data)) == 0,
                "restored keyfile content mismatch");

    /* Cleanup temp files */
    remove(db_path);
    remove(kf_path);
    remove(bak_path);
    remove(rest_db);
    remove(rest_kf);

    return 1;
}

int test_backup_wrong_passphrase(void) {
    const char *db_path = "/tmp/test_bak_wrong_db.sqlite";
    const char *kf_path = "/tmp/test_bak_wrong_kf.key";
    const char *bak_path = "/tmp/test_bak_wrong.bak";

    unsigned char db_data[] = "test database content";
    unsigned char kf_data[] = "test keyfile content!!";

    TEST_ASSERT(write_test_file(db_path, db_data, sizeof(db_data) - 1), "write db");
    TEST_ASSERT(write_test_file(kf_path, kf_data, sizeof(kf_data) - 1), "write kf");

    const unsigned char *pass = (const unsigned char *)"correct-pass";
    const unsigned char *wrong = (const unsigned char *)"wrong-password";

    TEST_ASSERT(backup_create(db_path, kf_path, bak_path, pass, 12),
                "backup_create failed");

    /* Verify with wrong passphrase should fail */
    TEST_ASSERT(!backup_verify(bak_path, wrong, 14),
                "backup_verify should fail with wrong passphrase");

    /* Restore with wrong passphrase should fail */
    TEST_ASSERT(!backup_restore(bak_path, "/tmp/x_db", "/tmp/x_kf", wrong, 14),
                "backup_restore should fail with wrong passphrase");

    remove(db_path);
    remove(kf_path);
    remove(bak_path);

    return 1;
}

int test_backup_corrupt_file(void) {
    const char *db_path = "/tmp/test_bak_corrupt_db.sqlite";
    const char *kf_path = "/tmp/test_bak_corrupt_kf.key";
    const char *bak_path = "/tmp/test_bak_corrupt.bak";

    unsigned char db_data[] = "corruption test db data";
    unsigned char kf_data[] = "corruption test kf data";

    TEST_ASSERT(write_test_file(db_path, db_data, sizeof(db_data) - 1), "write db");
    TEST_ASSERT(write_test_file(kf_path, kf_data, sizeof(kf_data) - 1), "write kf");

    const unsigned char *pass = (const unsigned char *)"pass123";

    TEST_ASSERT(backup_create(db_path, kf_path, bak_path, pass, 7),
                "backup_create failed");

    /* Read backup, flip a byte in the ciphertext, write back */
    unsigned char bak_buf[4096];
    size_t bak_len = read_test_file(bak_path, bak_buf, sizeof(bak_buf));
    TEST_ASSERT(bak_len > BACKUP_HEADER_LEN + BACKUP_TAG_LEN,
                "backup file too small");

    /* Flip a byte in the ciphertext region */
    bak_buf[BACKUP_HEADER_LEN + 2] ^= 0xFF;
    TEST_ASSERT(write_test_file(bak_path, bak_buf, bak_len), "write corrupt");

    /* Verify should fail */
    TEST_ASSERT(!backup_verify(bak_path, pass, 7),
                "backup_verify should fail on corrupt file");

    remove(db_path);
    remove(kf_path);
    remove(bak_path);

    return 1;
}
