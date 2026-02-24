#ifndef SUPERSCALAR_SHACHAIN_H
#define SUPERSCALAR_SHACHAIN_H

#include <stdint.h>
#include <stddef.h>

#define SHACHAIN_INDEX_BITS 48

/* Derive element at index from seed (generator side, BOLT #3 algorithm) */
void shachain_from_seed(const unsigned char *seed32, uint64_t index,
                         unsigned char *out32);

/* Map factory epoch to shachain index (descending order) */
uint64_t shachain_epoch_to_index(uint32_t epoch);

#endif /* SUPERSCALAR_SHACHAIN_H */
