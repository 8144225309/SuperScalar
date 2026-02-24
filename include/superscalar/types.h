#ifndef SUPERSCALAR_TYPES_H
#define SUPERSCALAR_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct { unsigned char data[32]; } hash256_t;
typedef struct { unsigned char data[33]; } pubkey33_t;
typedef struct { unsigned char data[32]; } seckey_t;

typedef struct {
    hash256_t txid;
    uint32_t  vout;
} outpoint_t;

typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
} tx_buf_t;

void tx_buf_init(tx_buf_t *buf, size_t initial_cap);
void tx_buf_free(tx_buf_t *buf);
void tx_buf_reset(tx_buf_t *buf);
void tx_buf_ensure(tx_buf_t *buf, size_t additional);

#endif /* SUPERSCALAR_TYPES_H */
