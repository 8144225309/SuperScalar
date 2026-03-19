/*
 * trampoline.c — BOLT #4 trampoline routing.
 *
 * Reference:
 *   Phoenix (ACINQ): github.com/ACINQ/phoenix
 *   BOLT #4 PR #716: trampoline routing proposal
 *   CLN: plugins/renepay; LDK: lightning/src/ln/
 */

#include "superscalar/trampoline.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

/* ---- Minimal bigsize (VarInt) encoding ---- */

static size_t encode_bigsize(uint64_t v, unsigned char *out, size_t cap)
{
    if (v < 0xfd) {
        if (cap < 1) return 0;
        out[0] = (unsigned char)v; return 1;
    } else if (v < 0x10000) {
        if (cap < 3) return 0;
        out[0] = 0xfd;
        out[1] = (unsigned char)(v >> 8);
        out[2] = (unsigned char)v;
        return 3;
    } else if (v < 0x100000000ULL) {
        if (cap < 5) return 0;
        out[0] = 0xfe;
        out[1] = (unsigned char)(v >> 24); out[2] = (unsigned char)(v >> 16);
        out[3] = (unsigned char)(v >> 8);  out[4] = (unsigned char)v;
        return 5;
    } else {
        if (cap < 9) return 0;
        out[0] = 0xff;
        for (int i = 1; i <= 8; i++)
            out[i] = (unsigned char)(v >> (8 * (8 - i)));
        return 9;
    }
}

static size_t decode_bigsize(const unsigned char *in, size_t in_len, uint64_t *out)
{
    if (in_len < 1) return 0;
    if (in[0] < 0xfd) { *out = in[0]; return 1; }
    if (in[0] == 0xfd) {
        if (in_len < 3) return 0;
        *out = ((uint64_t)in[1] << 8) | in[2]; return 3;
    }
    if (in[0] == 0xfe) {
        if (in_len < 5) return 0;
        *out = ((uint64_t)in[1] << 24) | ((uint64_t)in[2] << 16) |
               ((uint64_t)in[3] << 8)  | in[4];
        return 5;
    }
    /* 0xff */
    if (in_len < 9) return 0;
    *out = 0;
    for (int i = 1; i <= 8; i++) *out = (*out << 8) | in[i];
    return 9;
}

/* ---- TLV helpers ---- */

/* Write a TLV field: type(bigsize) + length(bigsize) + value */
static size_t write_tlv(unsigned char *buf, size_t cap,
                         uint64_t type, const unsigned char *val, size_t vlen)
{
    size_t p = 0;
    size_t n = encode_bigsize(type, buf + p, cap - p); if (!n) return 0; p += n;
    n = encode_bigsize((uint64_t)vlen, buf + p, cap - p); if (!n) return 0; p += n;
    if (p + vlen > cap) return 0;
    if (vlen) memcpy(buf + p, val, vlen);
    p += vlen;
    return p;
}

/* Write a TLV field with a uint64 big-endian value */
static size_t write_tlv_u64be(unsigned char *buf, size_t cap,
                                uint64_t type, uint64_t val)
{
    unsigned char be[8];
    for (int i = 7; i >= 0; i--) { be[i] = (unsigned char)(val & 0xff); val >>= 8; }
    return write_tlv(buf, cap, type, be, 8);
}

/* Write a TLV field with a uint32 big-endian value */
static size_t write_tlv_u32be(unsigned char *buf, size_t cap,
                                uint64_t type, uint32_t val)
{
    unsigned char be[4];
    be[0] = (unsigned char)(val >> 24); be[1] = (unsigned char)(val >> 16);
    be[2] = (unsigned char)(val >> 8);  be[3] = (unsigned char)val;
    return write_tlv(buf, cap, type, be, 4);
}

/* ---- Trampoline hop payload ---- */

size_t trampoline_build_hop_payload(const trampoline_hop_t *hop,
                                     unsigned char *buf, size_t buf_cap)
{
    if (!hop || !buf || buf_cap < 64) return 0;

    size_t p = 0, n;

    /* type 2: amt_to_forward (u64 BE) */
    n = write_tlv_u64be(buf + p, buf_cap - p, 2, hop->amt_msat);
    if (!n) return 0;
    p += n;

    /* type 4: outgoing_cltv_value (u32 BE) */
    n = write_tlv_u32be(buf + p, buf_cap - p, 4, hop->cltv_expiry);
    if (!n) return 0;
    p += n;

    /* type 14 (0x0e): next trampoline node pubkey (33 bytes) */
    n = write_tlv(buf + p, buf_cap - p, 0x0e, hop->pubkey, 33);
    if (!n) return 0;
    p += n;

    return p;
}

int trampoline_parse_hop_payload(const unsigned char *buf, size_t buf_len,
                                  trampoline_hop_t *hop_out)
{
    if (!buf || !hop_out || buf_len < 4) return 0;
    memset(hop_out, 0, sizeof(*hop_out));

    size_t p = 0;
    while (p < buf_len) {
        uint64_t type, length;
        size_t n = decode_bigsize(buf + p, buf_len - p, &type);
        if (!n) break;
        p += n;
        n = decode_bigsize(buf + p, buf_len - p, &length);
        if (!n) break;
        p += n;
        if (p + length > buf_len) break;

        if (type == 2 && length == 8) {
            uint64_t v = 0;
            for (int i = 0; i < 8; i++) v = (v << 8) | buf[p + i];
            hop_out->amt_msat = v;
        } else if (type == 4 && length == 4) {
            hop_out->cltv_expiry = ((uint32_t)buf[p] << 24) |
                                    ((uint32_t)buf[p+1] << 16) |
                                    ((uint32_t)buf[p+2] << 8) | buf[p+3];
        } else if (type == 0x0e && length == 33) {
            memcpy(hop_out->pubkey, buf + p, 33);
        }
        p += (size_t)length;
    }

    /* Require at least amt and cltv */
    return (hop_out->amt_msat > 0 || hop_out->cltv_expiry > 0) ? 1 : 0;
}

/* ---- Fee estimation (Phoenix defaults) ---- */

int trampoline_estimate_fees(trampoline_hop_t *hop, uint64_t dest_amount_msat)
{
    if (!hop || dest_amount_msat == 0) return 0;

    /* Phoenix fee model: 0.1% of amount, minimum 100 msat */
    uint64_t fee = dest_amount_msat / 1000;  /* 0.1% */
    if (fee < 100) fee = 100;

    hop->fee_msat   = fee;
    hop->amt_msat   = dest_amount_msat + fee;
    /* Use Phoenix default CLTV delta of 288 blocks */
    if (hop->cltv_expiry == 0)
        hop->cltv_expiry = 288;

    return 1;
}

uint64_t trampoline_path_total_fees(const trampoline_path_t *path)
{
    if (!path || path->n_hops == 0) return 0;
    uint64_t total = 0;
    for (int i = 0; i < path->n_hops; i++)
        total += path->hops[i].fee_msat;
    return total;
}

/* ---- Route hint encoding ---- */

size_t trampoline_build_invoice_hint(const trampoline_hop_t *trampoline,
                                      unsigned char *buf, size_t buf_cap)
{
    if (!trampoline || !buf || buf_cap < 51) return 0;

    size_t p = 0;
    /* Route hint hop: pubkey(33) + short_channel_id(8) + fee_base(4) +
     *                  fee_proportional(4) + cltv_expiry_delta(2) = 51 bytes */
    memcpy(buf + p, trampoline->pubkey, 33); p += 33;
    /* scid = 0 for trampoline (no specific channel) */
    memset(buf + p, 0, 8); p += 8;
    /* fee_base_msat = 100 (Phoenix default) */
    buf[p++] = 0; buf[p++] = 0; buf[p++] = 0; buf[p++] = 100;
    /* fee_proportional_millionths = 1000 (0.1%) */
    buf[p++] = 0; buf[p++] = 0; buf[p++] = 0x03; buf[p++] = 0xe8;
    /* cltv_expiry_delta = 288 */
    buf[p++] = 0x01; buf[p++] = 0x20;  /* 288 = 0x0120 */
    return p;
}

int trampoline_parse_invoice_hint(const unsigned char *buf, size_t buf_len,
                                   trampoline_hop_t *hop_out)
{
    if (!buf || !hop_out || buf_len < 51) return 0;

    memset(hop_out, 0, sizeof(*hop_out));
    memcpy(hop_out->pubkey, buf, 33);
    /* skip scid (8 bytes) */
    /* fee_base_msat */
    uint32_t fee_base = ((uint32_t)buf[41] << 24) | ((uint32_t)buf[42] << 16) |
                         ((uint32_t)buf[43] << 8) | buf[44];
    /* cltv_expiry_delta */
    uint16_t cltv = ((uint16_t)buf[49] << 8) | buf[50];
    hop_out->cltv_expiry = cltv;
    hop_out->fee_msat    = fee_base;

    /* A hint is a trampoline hint if cltv_delta is large (>= 100 blocks) */
    return (cltv >= 100) ? 1 : 0;
}

/* ---- Path building ---- */

int trampoline_build_single_hop_path(trampoline_path_t *path,
                                      const unsigned char trampoline_pubkey[33],
                                      const unsigned char dest_pubkey[33],
                                      uint64_t amount_msat,
                                      uint32_t cltv_final)
{
    if (!path || !trampoline_pubkey || !dest_pubkey || amount_msat == 0)
        return 0;

    memset(path, 0, sizeof(*path));

    /* Set destination */
    memcpy(path->dest_pubkey, dest_pubkey, 33);
    path->dest_amt_msat = amount_msat;
    path->dest_cltv     = cltv_final;

    /* Single trampoline hop */
    trampoline_hop_t *hop = &path->hops[0];
    memcpy(hop->pubkey, trampoline_pubkey, 33);
    hop->amt_msat    = amount_msat;
    hop->cltv_expiry = cltv_final + 288; /* add safety margin */

    trampoline_estimate_fees(hop, amount_msat);
    path->n_hops = 1;
    return 1;
}
