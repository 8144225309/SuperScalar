#ifndef SUPERSCALAR_WIRE_TLV_H
#define SUPERSCALAR_WIRE_TLV_H

#include <stdint.h>
#include <stddef.h>

/* TLV (Type-Length-Value) codec for BOLT-compatible wire protocol.
   Format: [type:2 BE][length:2 BE][value:length] per record, concatenated. */

typedef struct {
    uint16_t type;
    uint16_t length;
    const unsigned char *value;  /* points into decode buffer (not owned) */
} tlv_t;

/* Encode N TLV records into a single buffer.
   Caller frees *buf_out. Returns 1 on success. */
int wire_tlv_encode(const tlv_t *records, size_t n,
                    unsigned char **buf_out, size_t *len_out);

/* Decode a buffer into TLV records.
   Caller frees *records_out via wire_tlv_free().
   value pointers reference the input buf (do not free buf while using records).
   Returns 1 on success, 0 on truncated/malformed input. */
int wire_tlv_decode(const unsigned char *buf, size_t len,
                    tlv_t **records_out, size_t *n_out);

/* Free decoded TLV records array. */
void wire_tlv_free(tlv_t *records, size_t n);

#endif /* SUPERSCALAR_WIRE_TLV_H */
