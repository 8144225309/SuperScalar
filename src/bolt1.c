/*
 * bolt1.c — BOLT #1 fundamental message building and parsing.
 *
 * Reference: lightning/bolts BOLT #1 and BOLT #9
 *            CLN: lightningd/connect_control.c
 *            LDK: ln/peers_manager.rs
 */

#include "superscalar/bolt1.h"
#include <string.h>
#include <stdint.h>

static void put_u16_be(unsigned char *b, uint16_t v) {
    b[0] = (unsigned char)(v >> 8);
    b[1] = (unsigned char)(v);
}
static uint16_t get_u16_be(const unsigned char *b) {
    return ((uint16_t)b[0] << 8) | b[1];
}

/*
 * Encode feature bits (uint64_t) to big-endian wire bytes.
 * Returns number of bytes written to buf (0 if too small).
 * The encoding uses the minimum number of bytes needed.
 * Bit N is in byte[len-1 - N/8], position N%8.
 */
static size_t encode_features(uint64_t features, unsigned char *buf, size_t cap,
                               size_t *len_out)
{
    if (features == 0) {
        *len_out = 0;
        return 0;
    }
    /* Find highest bit set */
    int highest = 63;
    while (highest >= 0 && !((features >> highest) & 1)) highest--;
    size_t nbytes = (size_t)(highest / 8) + 1;
    if (nbytes > cap) return 1;  /* signal overflow */
    memset(buf, 0, nbytes);
    for (int i = 0; i < 64; i++) {
        if ((features >> i) & 1) {
            /* bit i → byte at offset (nbytes - 1 - i/8), position i%8 */
            size_t byte_idx = nbytes - 1 - (size_t)(i / 8);
            buf[byte_idx] |= (unsigned char)(1u << (i % 8));
        }
    }
    *len_out = nbytes;
    return 0;
}

/*
 * Decode big-endian wire feature bytes to uint64_t bitfield.
 */
static uint64_t decode_features(const unsigned char *buf, size_t len)
{
    uint64_t result = 0;
    if (len > 8) len = 8;  /* truncate to 64 bits */
    for (size_t i = 0; i < len; i++) {
        size_t byte_from_end = len - 1 - i;
        for (int bit = 0; bit < 8; bit++) {
            if ((buf[i] >> bit) & 1) {
                size_t abs_bit = byte_from_end * 8 + (size_t)bit;
                if (abs_bit < 64)
                    result |= (UINT64_C(1) << abs_bit);
            }
        }
    }
    return result;
}

/* ---- init (type 16) ---- */

size_t bolt1_build_init(uint64_t local_features,
                         unsigned char *buf, size_t buf_cap)
{
    /* Wire: type(2) + gflen(2) + globalfeatures(gflen) + lflen(2) + localfeatures(lflen) */
    if (!buf || buf_cap < 8) return 0;

    unsigned char feat_bytes[BOLT1_MAX_FEATURE_BYTES];
    size_t feat_len = 0;
    if (local_features != 0) {
        if (encode_features(local_features, feat_bytes, sizeof(feat_bytes), &feat_len))
            return 0;  /* overflow */
    }

    size_t needed = 2 + 2 + 0 + 2 + feat_len;  /* type + gflen(0) + lflen + features */
    if (buf_cap < needed) return 0;

    size_t p = 0;
    put_u16_be(buf + p, BOLT1_MSG_INIT); p += 2;
    put_u16_be(buf + p, 0);             p += 2;  /* globalfeatures_len = 0 */
    put_u16_be(buf + p, (uint16_t)feat_len); p += 2;
    if (feat_len > 0) { memcpy(buf + p, feat_bytes, feat_len); p += feat_len; }
    return p;
}

int bolt1_parse_init(const unsigned char *msg, size_t msg_len,
                      bolt1_init_t *out)
{
    if (!msg || msg_len < 6 || !out) return 0;
    if (get_u16_be(msg) != BOLT1_MSG_INIT) return 0;

    uint16_t gflen = get_u16_be(msg + 2);
    if (msg_len < (size_t)(4 + gflen + 2)) return 0;

    out->global_features = decode_features(msg + 4, gflen);

    uint16_t lflen = get_u16_be(msg + 4 + gflen);
    if (msg_len < (size_t)(4 + gflen + 2 + lflen)) return 0;

    out->local_features = decode_features(msg + 4 + gflen + 2, lflen);
    return 1;
}

/* ---- ping (type 18) ---- */

size_t bolt1_build_ping(uint16_t num_pong_bytes,
                         unsigned char *buf, size_t buf_cap)
{
    /* type(2) + num_pong_bytes(2) + ignored_len(2) + ignored(ignored_len) */
    if (!buf || buf_cap < 6) return 0;
    size_t p = 0;
    put_u16_be(buf + p, BOLT1_MSG_PING); p += 2;
    put_u16_be(buf + p, num_pong_bytes); p += 2;
    put_u16_be(buf + p, 0);             p += 2;  /* ignored_len = 0 */
    return p;
}

size_t bolt1_build_pong(uint16_t byteslen,
                         unsigned char *buf, size_t buf_cap)
{
    /* type(2) + byteslen(2) + bytes(byteslen) */
    size_t needed = 4 + byteslen;
    if (!buf || buf_cap < needed) return 0;
    size_t p = 0;
    put_u16_be(buf + p, BOLT1_MSG_PONG); p += 2;
    put_u16_be(buf + p, byteslen);       p += 2;
    memset(buf + p, 0, byteslen);        p += byteslen;
    return p;
}

int bolt1_parse_ping(const unsigned char *msg, size_t msg_len,
                      bolt1_ping_t *out)
{
    if (!msg || msg_len < 6 || !out) return 0;
    if (get_u16_be(msg) != BOLT1_MSG_PING) return 0;
    out->num_pong_bytes = get_u16_be(msg + 2);
    out->ignored_len    = get_u16_be(msg + 4);
    return 1;
}

/* ---- error (17) / warning (1) ---- */

static size_t build_error_or_warning(uint16_t mtype,
                                      const unsigned char channel_id[32],
                                      const char *data,
                                      unsigned char *buf, size_t buf_cap)
{
    size_t dlen = data ? strlen(data) : 0;
    size_t needed = 2 + 32 + 2 + dlen;
    if (!buf || buf_cap < needed) return 0;
    size_t p = 0;
    put_u16_be(buf + p, mtype); p += 2;
    if (channel_id) { memcpy(buf + p, channel_id, 32); }
    else            { memset(buf + p, 0, 32); }
    p += 32;
    put_u16_be(buf + p, (uint16_t)dlen); p += 2;
    if (dlen > 0) { memcpy(buf + p, data, dlen); p += dlen; }
    return p;
}

size_t bolt1_build_error(const unsigned char channel_id[32],
                          const char *data,
                          unsigned char *buf, size_t buf_cap)
{
    return build_error_or_warning(BOLT1_MSG_ERROR, channel_id, data, buf, buf_cap);
}

size_t bolt1_build_warning(const unsigned char channel_id[32],
                             const char *data,
                             unsigned char *buf, size_t buf_cap)
{
    return build_error_or_warning(BOLT1_MSG_WARNING, channel_id, data, buf, buf_cap);
}

int bolt1_parse_error(const unsigned char *msg, size_t msg_len,
                       bolt1_error_t *out)
{
    if (!msg || msg_len < 36 || !out) return 0;
    uint16_t mtype = get_u16_be(msg);
    if (mtype != BOLT1_MSG_ERROR && mtype != BOLT1_MSG_WARNING) return 0;

    memcpy(out->channel_id, msg + 2, 32);
    uint16_t dlen = get_u16_be(msg + 34);
    if (msg_len < (size_t)(36 + dlen)) return 0;

    out->data_len = dlen;
    size_t copy = dlen < sizeof(out->data) - 1 ? dlen : sizeof(out->data) - 1;
    if (copy > 0) memcpy(out->data, msg + 36, copy);
    out->data[copy] = '\0';
    return 1;
}

/* ---- feature helpers ---- */

int bolt1_has_feature(uint64_t features, int bit)
{
    if (bit < 0 || bit >= 64) return 0;
    return (features >> bit) & 1 ? 1 : 0;
}

int bolt1_check_mandatory_features(uint64_t peer_features, uint64_t known_bits)
{
    /* Any even bit set in peer_features that is NOT in known_bits is a
     * mandatory unknown feature — we must disconnect per BOLT #1 §2. */
    for (int bit = 0; bit < 64; bit += 2) {  /* check even bits only */
        if ((peer_features >> bit) & 1) {
            if (!((known_bits >> bit) & 1))
                return 0;  /* unknown mandatory feature */
        }
    }
    return 1;
}
