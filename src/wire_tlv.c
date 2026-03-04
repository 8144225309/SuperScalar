#include "superscalar/wire_tlv.h"
#include <stdlib.h>
#include <string.h>

/* TLV record overhead: 2 bytes type + 2 bytes length */
#define TLV_HEADER_SIZE 4

static void write_u16_be(unsigned char *buf, uint16_t val) {
    buf[0] = (unsigned char)(val >> 8);
    buf[1] = (unsigned char)(val & 0xFF);
}

static uint16_t read_u16_be(const unsigned char *buf) {
    return (uint16_t)((buf[0] << 8) | buf[1]);
}

int wire_tlv_encode(const tlv_t *records, size_t n,
                    unsigned char **buf_out, size_t *len_out) {
    if (!buf_out || !len_out) return 0;
    *buf_out = NULL;
    *len_out = 0;

    /* Calculate total size */
    size_t total = 0;
    for (size_t i = 0; i < n; i++)
        total += TLV_HEADER_SIZE + records[i].length;

    if (total == 0 && n == 0) {
        /* Empty encoding is valid */
        *buf_out = NULL;
        *len_out = 0;
        return 1;
    }

    unsigned char *buf = malloc(total);
    if (!buf) return 0;

    size_t offset = 0;
    for (size_t i = 0; i < n; i++) {
        write_u16_be(buf + offset, records[i].type);
        offset += 2;
        write_u16_be(buf + offset, records[i].length);
        offset += 2;
        if (records[i].length > 0 && records[i].value) {
            memcpy(buf + offset, records[i].value, records[i].length);
            offset += records[i].length;
        }
    }

    *buf_out = buf;
    *len_out = total;
    return 1;
}

int wire_tlv_decode(const unsigned char *buf, size_t len,
                    tlv_t **records_out, size_t *n_out) {
    if (!records_out || !n_out) return 0;
    *records_out = NULL;
    *n_out = 0;

    if (len == 0) return 1;  /* empty is valid */
    if (!buf) return 0;

    /* First pass: count records */
    size_t count = 0;
    size_t offset = 0;
    while (offset < len) {
        if (offset + TLV_HEADER_SIZE > len) return 0;  /* truncated header */
        uint16_t vlen = read_u16_be(buf + offset + 2);
        if (offset + TLV_HEADER_SIZE + vlen > len) return 0;  /* truncated value */
        offset += TLV_HEADER_SIZE + vlen;
        count++;
    }

    if (count == 0) return 1;

    tlv_t *records = calloc(count, sizeof(tlv_t));
    if (!records) return 0;

    /* Second pass: fill records */
    offset = 0;
    for (size_t i = 0; i < count; i++) {
        records[i].type = read_u16_be(buf + offset);
        records[i].length = read_u16_be(buf + offset + 2);
        records[i].value = (records[i].length > 0) ? (buf + offset + TLV_HEADER_SIZE) : NULL;
        offset += TLV_HEADER_SIZE + records[i].length;
    }

    *records_out = records;
    *n_out = count;
    return 1;
}

void wire_tlv_free(tlv_t *records, size_t n) {
    (void)n;
    free(records);
}
