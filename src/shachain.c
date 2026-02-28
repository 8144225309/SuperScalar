#include "superscalar/shachain.h"
#include <string.h>

#include "superscalar/sha256.h"

#define SHACHAIN_MAX_INDEX ((UINT64_C(1) << SHACHAIN_INDEX_BITS) - 1)

/* Derive element at index from seed using BOLT #3 algorithm.
   Iterate bits 47..0: if bit is set in index, flip that bit in value and hash. */
void shachain_from_seed(const unsigned char *seed32, uint64_t index,
                         unsigned char *out32) {
    unsigned char value[32];
    memcpy(value, seed32, 32);

    for (int bit = SHACHAIN_INDEX_BITS - 1; bit >= 0; bit--) {
        if (index & (UINT64_C(1) << bit)) {
            int byte_idx = bit / 8;
            int bit_within_byte = bit % 8;
            value[byte_idx] ^= (1 << bit_within_byte);
            sha256(value, 32, value);
        }
    }

    memcpy(out32, value, 32);
}

/* Map factory epoch N to shachain index (2^48 - 1) - N.
   Epoch 0 maps to highest index (revealed first). */
uint64_t shachain_epoch_to_index(uint32_t epoch) {
    return SHACHAIN_MAX_INDEX - (uint64_t)epoch;
}

