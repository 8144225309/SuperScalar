#ifndef SUPERSCALAR_SHA256_H
#define SUPERSCALAR_SHA256_H

#include <stddef.h>

void sha256(const unsigned char *data, size_t len, unsigned char *out32);
void sha256_double(const unsigned char *data, size_t len, unsigned char *out32);
void sha256_tagged(const char *tag, const unsigned char *data, size_t data_len,
                   unsigned char *out32);

#endif /* SUPERSCALAR_SHA256_H */
