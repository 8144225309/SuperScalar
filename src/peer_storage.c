/*
 * peer_storage.c — BOLT #9 peer storage messages (types 7 and 9)
 *
 * See peer_storage.h for the full API description.
 */

#include "superscalar/peer_storage.h"
#include "superscalar/peer_mgr.h"
#include <string.h>
#include <stdint.h>

static void put_u16(unsigned char *b, uint16_t v) {
    b[0] = (unsigned char)(v >> 8);
    b[1] = (unsigned char)(v);
}
static uint16_t get_u16(const unsigned char *b) {
    return ((uint16_t)b[0] << 8) | b[1];
}

size_t peer_storage_build(uint16_t type,
                           const unsigned char *blob, uint16_t blob_len,
                           unsigned char *buf, size_t buf_cap)
{
    size_t msg_len = 2 + 2 + (size_t)blob_len;
    if (buf_cap < msg_len) return 0;

    size_t pos = 0;
    put_u16(buf + pos, type);    pos += 2;
    put_u16(buf + pos, blob_len); pos += 2;
    memcpy(buf + pos, blob, blob_len); pos += blob_len;
    return pos;
}

int peer_storage_parse(const unsigned char *msg, size_t msg_len,
                        uint16_t *type_out,
                        unsigned char *blob_out, uint16_t *blob_len_out,
                        size_t blob_buf_cap)
{
    /* Minimum: type(2) + blob_len(2) = 4 bytes */
    if (msg_len < 4) return 0;

    uint16_t type = get_u16(msg);
    if (type != BOLT9_PEER_STORAGE && type != BOLT9_YOUR_PEER_STORAGE)
        return 0;

    uint16_t blen = get_u16(msg + 2);
    if (msg_len < (size_t)(4 + blen)) return 0;
    if (blen > blob_buf_cap) return 0;

    *type_out = type;
    memcpy(blob_out, msg + 4, blen);
    *blob_len_out = blen;
    return 1;
}

int peer_storage_send(peer_mgr_t *mgr, int peer_idx,
                       const unsigned char *blob, uint16_t blob_len)
{
    unsigned char buf[4 + PEER_STORAGE_MAX_BLOB];
    size_t len = peer_storage_build(BOLT9_PEER_STORAGE, blob, blob_len,
                                     buf, sizeof(buf));
    if (!len) return 0;
    return peer_mgr_send(mgr, peer_idx, buf, len);
}

int peer_storage_send_reply(peer_mgr_t *mgr, int peer_idx,
                              const unsigned char *blob, uint16_t blob_len)
{
    unsigned char buf[4 + PEER_STORAGE_MAX_BLOB];
    size_t len = peer_storage_build(BOLT9_YOUR_PEER_STORAGE, blob, blob_len,
                                     buf, sizeof(buf));
    if (!len) return 0;
    return peer_mgr_send(mgr, peer_idx, buf, len);
}
