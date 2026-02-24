#include "superscalar/shachain.h"
#include <stdio.h>
#include <string.h>

extern void sha256(const unsigned char *data, size_t len, unsigned char *out32);

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

#define TEST_ASSERT_MEM_EQ(a, b, len, msg) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

static const unsigned char test_seed[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

/* Test: derive elements at various indices, verify determinism and uniqueness */
int test_shachain_generation(void) {
    unsigned char elem0[32], elem1[32], elem_max[32], elem0_again[32];
    uint64_t max_idx = (UINT64_C(1) << SHACHAIN_INDEX_BITS) - 1;

    shachain_from_seed(test_seed, 0, elem0);
    shachain_from_seed(test_seed, 1, elem1);
    shachain_from_seed(test_seed, max_idx, elem_max);
    shachain_from_seed(test_seed, 0, elem0_again);

    /* Same seed+index produces same result */
    TEST_ASSERT_MEM_EQ(elem0, elem0_again, 32, "deterministic generation");

    /* Different indices produce different elements */
    TEST_ASSERT(memcmp(elem0, elem1, 32) != 0, "index 0 != index 1");
    TEST_ASSERT(memcmp(elem0, elem_max, 32) != 0, "index 0 != index max");
    TEST_ASSERT(memcmp(elem1, elem_max, 32) != 0, "index 1 != index max");

    /* Index 0 means no bits set -> no flips -> output = seed */
    TEST_ASSERT_MEM_EQ(elem0, test_seed, 32, "index 0 is seed itself");

    return 1;
}

/* Test: element at index N can derive element at N+1 when they differ in lowest bit */
int test_shachain_derivation_property(void) {
    uint64_t max_idx = (UINT64_C(1) << SHACHAIN_INDEX_BITS) - 1;

    /* Index 0 (binary: ...000) should be able to derive index 1 (binary: ...001)
       because they differ only in bit 0, and bit 0 is 0 in index 0. */
    unsigned char elem0[32], elem1[32], derived1[32];
    shachain_from_seed(test_seed, 0, elem0);
    shachain_from_seed(test_seed, 1, elem1);

    /* Derive index 1 from index 0: flip bit 0, hash */
    unsigned char tmp[32];
    memcpy(tmp, elem0, 32);
    tmp[0] ^= 1;
    sha256(tmp, 32, derived1);
    TEST_ASSERT_MEM_EQ(derived1, elem1, 32, "elem0 derives elem1");

    /* Index with bit pattern ...10 can derive ...11 */
    unsigned char elem2[32], elem3[32];
    shachain_from_seed(test_seed, 2, elem2);
    shachain_from_seed(test_seed, 3, elem3);

    memcpy(tmp, elem2, 32);
    tmp[0] ^= 1;  /* flip bit 0 */
    unsigned char derived3[32];
    sha256(tmp, 32, derived3);
    TEST_ASSERT_MEM_EQ(derived3, elem3, 32, "elem2 derives elem3");

    /* Epoch mapping: epoch 0 -> highest index, epoch 1 -> highest-1, etc. */
    uint64_t idx0 = shachain_epoch_to_index(0);
    uint64_t idx1 = shachain_epoch_to_index(1);
    TEST_ASSERT_EQ(idx0, max_idx, "epoch 0 -> max index");
    TEST_ASSERT_EQ(idx1, max_idx - 1, "epoch 1 -> max-1");
    TEST_ASSERT(idx0 > idx1, "epoch 0 > epoch 1 (descending)");

    return 1;
}

