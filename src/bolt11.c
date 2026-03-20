/*
 * bolt11.c — BOLT #11 invoice decode/encode
 *
 * bech32-encoded lnbc/lnbs/lntb/lnbcrt strings.
 * Spec: https://github.com/lightning/bolts/blob/master/11-payment-encoding.md
 * Reference: CLN common/bolt11.c (most complete), LDK lightning-invoice crate.
 *
 * Encoding overview:
 *   HRP  = "ln" + network + optional_amount_multiplier
 *   DATA = timestamp(35 bits) || tagged_fields || signature(520 bits)
 *   All DATA is 5-bit groups; bech32 checksum appended.
 *
 * We reuse the bech32m.c polymod and charset but use bech32 constant (not bech32m).
 */

#include "superscalar/bolt11.h"
#include "superscalar/sha256.h"
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

/* ---- bech32 constants (BOLT #11 uses bech32, not bech32m) ---- */
#define BECH32_CONST  1UL
#define CHARSET "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

static int8_t g_charset_rev[128];
static int    g_charset_rev_ok = 0;

static void init_rev(void) {
    if (g_charset_rev_ok) return;
    for (int i = 0; i < 128; i++) g_charset_rev[i] = -1;
    for (int i = 0; i < 32; i++)
        g_charset_rev[(unsigned char)CHARSET[i]] = (int8_t)i;
    g_charset_rev_ok = 1;
}

/* ---- polymod (BIP 173) ---- */
static uint32_t bech32_polymod(const uint8_t *v, size_t n) {
    uint32_t c = 1;
    for (size_t i = 0; i < n; i++) {
        uint8_t c0 = (uint8_t)(c >> 25);
        c = ((c & 0x1ffffffUL) << 5) ^ v[i];
        if (c0 & 1)  c ^= 0x3b6a57b2UL;
        if (c0 & 2)  c ^= 0x26508e6dUL;
        if (c0 & 4)  c ^= 0x1ea119faUL;
        if (c0 & 8)  c ^= 0x3d4233ddUL;
        if (c0 & 16) c ^= 0x2a1462b3UL;
    }
    return c;
}

static uint32_t bech32_checksum_val(const char *hrp, size_t hrp_len,
                                     const uint8_t *data5, size_t d5_len) {
    uint8_t buf[1024];
    size_t pos = 0;
    if (hrp_len * 2 + 1 + d5_len + 6 > sizeof(buf)) return 0;
    for (size_t i = 0; i < hrp_len; i++) buf[pos++] = (uint8_t)((unsigned char)hrp[i] >> 5);
    buf[pos++] = 0;
    for (size_t i = 0; i < hrp_len; i++) buf[pos++] = (uint8_t)((unsigned char)hrp[i] & 0x1f);
    for (size_t i = 0; i < d5_len;  i++) buf[pos++] = data5[i];
    for (int i = 0; i < 6; i++) buf[pos++] = 0;
    return bech32_polymod(buf, pos) ^ BECH32_CONST;
}

/* ---- 5-bit ↔ 8-bit conversion ---- */
static size_t bytes_to_5bit(const unsigned char *in, size_t in_len,
                              uint8_t *out, size_t out_cap) {
    uint32_t acc = 0; int bits = 0; size_t pos = 0;
    for (size_t i = 0; i < in_len; i++) {
        acc = (acc << 8) | in[i]; bits += 8;
        while (bits >= 5) {
            bits -= 5;
            if (pos >= out_cap) return 0;
            out[pos++] = (uint8_t)((acc >> bits) & 0x1f);
        }
    }
    if (bits > 0) {
        if (pos >= out_cap) return 0;
        out[pos++] = (uint8_t)((acc << (5 - bits)) & 0x1f);
    }
    return pos;
}

static size_t fivebit_to_bytes(const uint8_t *in, size_t in_len,
                                unsigned char *out, size_t out_cap) {
    uint32_t acc = 0; int bits = 0; size_t pos = 0;
    for (size_t i = 0; i < in_len; i++) {
        acc = (acc << 5) | in[i]; bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (pos >= out_cap) return 0;
            out[pos++] = (unsigned char)((acc >> bits) & 0xff);
        }
    }
    if (bits >= 5) return 0;
    if (bits > 0 && (acc & ((1u << bits) - 1u))) return 0;
    return pos;
}

/* ---- Read N bits from a 5-bit array at bit offset *off ---- */
static uint64_t read_bits(const uint8_t *d5, size_t d5_len,
                           size_t *off, int nbits) {
    uint64_t v = 0;
    for (int i = 0; i < nbits; i++) {
        size_t byte_idx = *off / 5;
        int    bit_idx  = 4 - (int)(*off % 5);
        if (byte_idx >= d5_len) return 0;
        v = (v << 1) | ((d5[byte_idx] >> bit_idx) & 1);
        (*off)++;
    }
    return v;
}

/* ---- Write N bits (up to 64) into 5-bit array at bit offset *off ---- */
static void write_bits(uint8_t *d5, size_t d5_cap,
                        size_t *off, uint64_t val, int nbits) {
    for (int i = nbits - 1; i >= 0; i--) {
        size_t byte_idx = *off / 5;
        int    bit_idx  = 4 - (int)(*off % 5);
        if (byte_idx >= d5_cap) return;
        if ((val >> i) & 1)
            d5[byte_idx] |= (uint8_t)(1 << bit_idx);
        else
            d5[byte_idx] &= (uint8_t)~(1 << bit_idx);
        (*off)++;
    }
}

/* ---- Parse network from HRP ---- */
static int parse_network(const char *hrp, size_t hrp_len,
                          char network_out[8], uint64_t *amount_msat_out) {
    /* HRP = "ln" + network + optional_amount */
    if (hrp_len < 4) return 0;
    if (hrp[0] != 'l' || hrp[1] != 'n') return 0;

    /* networks: bc, bs, tb, bcrt */
    static const char *nets[] = {"bc", "bs", "tb", "bcrt", NULL};
    int net_len = 0;
    for (int i = 0; nets[i]; i++) {
        int nl = (int)strlen(nets[i]);
        if ((int)hrp_len >= 2 + nl &&
            memcmp(hrp + 2, nets[i], (size_t)nl) == 0) {
            /* Check that next char is digit or end */
            int after = 2 + nl;
            if ((int)hrp_len == after || isdigit((unsigned char)hrp[after])) {
                strncpy(network_out, nets[i], 7);
                network_out[7] = '\0';
                net_len = nl;
                break;
            }
        }
    }
    if (net_len == 0) return 0;

    /* Parse optional amount (digits + optional multiplier) */
    *amount_msat_out = 0;
    size_t amt_start = (size_t)(2 + net_len);
    if (amt_start == hrp_len) return 1; /* no amount */

    uint64_t n = 0;
    size_t i = amt_start;
    while (i < hrp_len && isdigit((unsigned char)hrp[i]))
        n = n * 10 + (uint64_t)(hrp[i++] - '0');

    /* multiplier */
    uint64_t msat = 0;
    if (i == hrp_len) {
        /* no multiplier: n is in BTC; convert to msat */
        msat = n * 100000000ULL * 1000ULL;
    } else if (i == hrp_len - 1) {
        switch (hrp[i]) {
        case 'm': msat = n * 100000ULL;      break; /* milli-BTC */
        case 'u': msat = n * 100ULL;         break; /* micro-BTC */
        case 'n': msat = n / 10;             break; /* nano-BTC */
        case 'p': msat = n / 10000;          break; /* pico-BTC */
        default: return 0;
        }
    } else return 0;

    *amount_msat_out = msat;
    return 1;
}

/* ---- Build HRP ---- */
static int build_hrp(const bolt11_invoice_t *inv, char *hrp, size_t hrp_cap) {
    if (!inv || !hrp) return 0;
    size_t pos = 0;
    /* "ln" + network */
    int n = snprintf(hrp + pos, hrp_cap - pos, "ln%s", inv->network);
    if (n < 0 || (size_t)n >= hrp_cap - pos) return 0;
    pos += (size_t)n;

    if (inv->has_amount && inv->amount_msat > 0) {
        /* Choose smallest unit that gives integer value */
        uint64_t m = inv->amount_msat;
        const char *sfx = "";
        uint64_t val = 0;
        if (m % 100000 == 0) {        val = m / 100000; sfx = "m"; }
        else if (m % 100 == 0) {      val = m / 100;    sfx = "u"; }
        else if (m % 10 == 0 && m >= 10) { val = m / 10; sfx = "n"; }
        else {                         val = m * 10;     sfx = "p"; }
        n = snprintf(hrp + pos, hrp_cap - pos, "%llu%s",
                     (unsigned long long)val, sfx);
        if (n < 0 || (size_t)n >= hrp_cap - pos) return 0;
        pos += (size_t)n;
    }
    hrp[pos] = '\0';
    return 1;
}

/* ---- BOLT #11 decode ---- */

int bolt11_decode(secp256k1_context *ctx,
                  const char *invoice_str,
                  bolt11_invoice_t *out) {
    if (!invoice_str || !out || !ctx) return 0;
    init_rev();
    memset(out, 0, sizeof(*out));
    out->expiry = 3600;
    out->min_final_cltv_expiry = 18;

    /* Find the last '1' separator */
    size_t slen = strlen(invoice_str);
    int sep = -1;
    for (int i = (int)slen - 1; i >= 0; i--) {
        if (invoice_str[i] == '1') { sep = i; break; }
    }
    if (sep < 4) return 0; /* "lnbc" minimum */

    size_t hrp_len = (size_t)sep;
    char hrp[128];
    if (hrp_len >= sizeof(hrp)) return 0;
    for (size_t i = 0; i < hrp_len; i++)
        hrp[i] = (char)tolower((unsigned char)invoice_str[i]);
    hrp[hrp_len] = '\0';

    /* Decode 5-bit values after separator */
    size_t d5_total = slen - hrp_len - 1;
    if (d5_total < 110) return 0; /* 35-bit ts + 104 sig bits minimum */
    uint8_t d5[4096];
    if (d5_total > sizeof(d5)) return 0;
    for (size_t i = 0; i < d5_total; i++) {
        unsigned char c = (unsigned char)tolower((unsigned char)invoice_str[hrp_len + 1 + i]);
        if (c >= 128 || g_charset_rev[c] < 0) return 0;
        d5[i] = (uint8_t)g_charset_rev[c];
    }

    /* Verify bech32 checksum */
    size_t d5_data = d5_total - 6;
    uint32_t chk = bech32_checksum_val(hrp, hrp_len, d5, d5_data);
    uint32_t encoded_chk = 0;
    for (int i = 5; i >= 0; i--)
        encoded_chk |= ((uint32_t)d5[d5_data + (size_t)(5-i)]) << (i*5);
    if (chk != encoded_chk) return 0;

    /* Parse network + amount from HRP */
    uint64_t hrp_amount = 0;
    if (!parse_network(hrp, hrp_len, out->network, &hrp_amount)) return 0;
    if (hrp_amount > 0) {
        out->amount_msat = hrp_amount;
        out->has_amount = 1;
    }

    /* DATA section: timestamp (35 bits) + tagged fields + signature (520 bits) */
    /* Signature is the last 520 bits = 104 5-bit groups */
    if (d5_data < 7 + 104) return 0; /* 35 bits + at least 104 for sig */
    size_t sig5_start = d5_data - 104;

    size_t off = 0;
    out->timestamp = (uint32_t)read_bits(d5, sig5_start, &off, 35);

    /* Parse tagged fields */
    while (off < sig5_start * 5) {
        if (off + 15 > sig5_start * 5) break;
        uint8_t tag    = (uint8_t)read_bits(d5, sig5_start, &off, 5);
        uint64_t flen  = read_bits(d5, sig5_start, &off, 10);
        if (off + flen * 5 > sig5_start * 5) break;

        /* Extract field bits to a temporary 5-bit array */
        uint8_t fdata5[512];
        size_t fdata5_len = (size_t)flen;
        if (fdata5_len > sizeof(fdata5)) { off += flen * 5; continue; }
        for (size_t k = 0; k < fdata5_len; k++)
            fdata5[k] = (uint8_t)read_bits(d5, sig5_start, &off, 5);

        switch (tag) {
        case 1: { /* p: payment_hash (52 5-bit groups = 32 bytes) */
            if (fdata5_len == 52) {
                unsigned char tmp[32];
                if (fivebit_to_bytes(fdata5, 52, tmp, 32) == 32)
                    memcpy(out->payment_hash, tmp, 32);
            }
            break;
        }
        case 4: { /* x: expiry */
            uint64_t exp = 0;
            for (size_t k = 0; k < fdata5_len; k++)
                exp = (exp << 5) | fdata5[k];
            out->expiry = (uint32_t)exp;
            break;
        }
        case 5: { /* h: description_hash (52 groups = 32 bytes) */
            if (fdata5_len == 52) {
                unsigned char tmp[32];
                if (fivebit_to_bytes(fdata5, 52, tmp, 32) == 32) {
                    memcpy(out->description_hash, tmp, 32);
                    out->has_description_hash = 1;
                }
            }
            break;
        }
        case 6: { /* c: min_final_cltv_expiry */
            uint64_t clv = 0;
            for (size_t k = 0; k < fdata5_len; k++)
                clv = (clv << 5) | fdata5[k];
            out->min_final_cltv_expiry = (int)clv;
            break;
        }
        case 9: { /* f: fallback address — skip */
            break;
        }
        case 13: { /* d: description string */
            unsigned char desc_bytes[640];
            size_t dlen = fivebit_to_bytes(fdata5, fdata5_len,
                                            desc_bytes, sizeof(desc_bytes) - 1);
            if (dlen > 0) {
                if (dlen >= BOLT11_MAX_DESCRIPTION)
                    dlen = BOLT11_MAX_DESCRIPTION - 1;
                memcpy(out->description, desc_bytes, dlen);
                out->description[dlen] = '\0';
            }
            break;
        }
        case 16: { /* n: payee pubkey (53 5-bit groups = 33 bytes) */
            if (fdata5_len == 53) {
                unsigned char tmp[33];
                if (fivebit_to_bytes(fdata5, 53, tmp, 33) == 33)
                    memcpy(out->payee_pubkey, tmp, 33);
            }
            break;
        }
        case 18: { /* s: payment_secret (52 5-bit groups = 32 bytes) */
            if (fdata5_len == 52) {
                unsigned char tmp[32];
                if (fivebit_to_bytes(fdata5, 52, tmp, 32) == 32) {
                    memcpy(out->payment_secret, tmp, 32);
                    out->has_payment_secret = 1;
                }
            }
            break;
        }
        case 27: { /* m: payment_metadata */
            unsigned char mbytes[64];
            size_t mlen = fivebit_to_bytes(fdata5, fdata5_len,
                                            mbytes, sizeof(mbytes));
            if (mlen > 0) {
                if (mlen > 64) mlen = 64;
                memcpy(out->metadata, mbytes, mlen);
                out->metadata_len = mlen;
                out->has_metadata  = 1;
            }
            break;
        }
        case 20: { /* f (features) */
            if (fdata5_len <= 4) {
                uint16_t feat = 0;
                for (size_t k = 0; k < fdata5_len; k++)
                    feat = (uint16_t)((feat << 5) | fdata5[k]);
                out->features = feat;
            }
            break;
        }
        case 3: { /* r: route hints */
            if (out->n_hints >= BOLT11_MAX_ROUTE_HINTS) break;
            /* Each hop hint: pubkey(33) + scid(8) + fee_base(4) + fee_ppm(4) + cltv(2) = 51 bytes */
            unsigned char rbytes[512];
            size_t rlen = fivebit_to_bytes(fdata5, fdata5_len, rbytes, sizeof(rbytes));
            size_t roff = 0;
            bolt11_route_hint_t *rh = &out->hints[out->n_hints++];
            rh->n_hops = 0;
            while (roff + 51 <= rlen && rh->n_hops < BOLT11_MAX_HOPS_PER_HINT) {
                bolt11_hop_hint_t *hop = &rh->hops[rh->n_hops++];
                memcpy(hop->pubkey, rbytes + roff, 33); roff += 33;
                hop->short_channel_id = 0;
                for (int k = 0; k < 8; k++)
                    hop->short_channel_id = (hop->short_channel_id << 8) | rbytes[roff++];
                hop->fee_base_msat = ((uint32_t)rbytes[roff] << 24) |
                                     ((uint32_t)rbytes[roff+1] << 16) |
                                     ((uint32_t)rbytes[roff+2] <<  8) |
                                      (uint32_t)rbytes[roff+3]; roff += 4;
                hop->fee_ppm = ((uint32_t)rbytes[roff] << 24) |
                               ((uint32_t)rbytes[roff+1] << 16) |
                               ((uint32_t)rbytes[roff+2] <<  8) |
                                (uint32_t)rbytes[roff+3]; roff += 4;
                hop->cltv_expiry_delta = ((uint16_t)rbytes[roff] << 8) |
                                          rbytes[roff+1]; roff += 2;
            }
            break;
        }
        default:
            /* Unknown tag: skip */
            break;
        }
    }

    /* ---- Verify signature ---- */
    /* Signature: last 104 5-bit groups = 65 bytes:
       recovery_flag(1 bit) [stored in last 5-bit group as high bit]
       sig(64 bytes) */
    unsigned char sig65[65];
    /* 104 * 5 = 520 bits; convert the 520 bits to bytes */
    uint8_t *sig5 = d5 + sig5_start;
    /* sig5 encodes: 512 bits of ECDSA sig + 8 bits of recovery flag → 65 bytes */
    unsigned char sig_bytes[66];
    size_t sbs = fivebit_to_bytes(sig5, 104, sig_bytes, sizeof(sig_bytes));
    if (sbs < 65) return 0;
    /* CLN convention: last byte of sig_bytes is the recovery flag (0 or 1) */
    sig65[0] = sig_bytes[64]; /* recovery flag */
    memcpy(sig65 + 1, sig_bytes, 64);

    /* Sighash: SHA256(hrp_bytes || data5_without_sig) */
    /* hrp_bytes = raw bytes of HRP as-is */
    unsigned char sighash[32];
    {
        /* msg = hrp_bytes || data5_bits_flattened_to_bytes (data portion only, not sig) */
        /* Per BOLT #11: hash = SHA256(HRP as ASCII bytes || 5-bit data as bytes with leftover) */
        /* Exact: SHA256(hrp_ascii_bytes || data5_including_sig_as_8bit_with_padding) */
        /* Actually per spec: sign over SHA256(hrp || data5_without_sig) where data5_without_sig */
        /* is the raw bech32 5-bit stream bytes (0x00..0x1f per group) packed 8 per 5 */
        /* CLN approach: msg = hrp_bytes || data5_bytes (raw 5-bit values, not decoded) */
        /* where data5_bytes = the raw 5-bit octets in a byte array */
        uint8_t *msg = (uint8_t *)malloc(hrp_len + sig5_start);
        if (!msg) return 0;
        memcpy(msg, hrp, hrp_len);
        memcpy(msg + hrp_len, d5, sig5_start);
        sha256(msg, hrp_len + sig5_start, sighash);
        free(msg);
    }

    /* Recover pubkey */
    secp256k1_ecdsa_recoverable_signature rec_sig;
    int recovery_id = sig65[0] & 0x01;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
            ctx, &rec_sig, sig65 + 1, recovery_id)) return 0;

    secp256k1_pubkey recovered_pub;
    if (!secp256k1_ecdsa_recover(ctx, &recovered_pub, &rec_sig, sighash)) return 0;

    /* If 'n' tagged field was absent, use recovered key */
    if (out->payee_pubkey[0] == 0x00) {
        size_t publen = 33;
        secp256k1_ec_pubkey_serialize(ctx, out->payee_pubkey, &publen,
                                      &recovered_pub, SECP256K1_EC_COMPRESSED);
    }

    return 1;
}

/* ---- BOLT #11 encode ---- */

int bolt11_encode(const bolt11_invoice_t *inv,
                  const unsigned char node_privkey[32],
                  secp256k1_context *ctx,
                  char *out, size_t out_cap) {
    if (!inv || !node_privkey || !ctx || !out) return 0;
    init_rev();

    /* Build HRP */
    char hrp[128];
    if (!build_hrp(inv, hrp, sizeof(hrp))) return 0;
    size_t hrp_len = strlen(hrp);

    /* Build 5-bit data stream: timestamp(35) + tagged fields + sig(104) */
    uint8_t d5[4096];
    memset(d5, 0, sizeof(d5));
    size_t off = 0; /* bit offset */

    /* Timestamp: 35 bits */
    write_bits(d5, sizeof(d5), &off, (uint64_t)inv->timestamp, 35);

    /* Tagged fields */
    /* Helper: write tag + 10-bit length + fdata5 */
#define WRITE_FIELD(tag, fdata5_ptr, fdata5_len) do { \
    write_bits(d5, sizeof(d5), &off, (tag), 5); \
    write_bits(d5, sizeof(d5), &off, (fdata5_len), 10); \
    for (size_t _k = 0; _k < (size_t)(fdata5_len); _k++) \
        write_bits(d5, sizeof(d5), &off, (fdata5_ptr)[_k], 5); \
} while(0)

    /* p: payment_hash */
    {
        uint8_t f[52];
        bytes_to_5bit(inv->payment_hash, 32, f, 52);
        WRITE_FIELD(1, f, 52);
    }

    /* s: payment_secret */
    if (inv->has_payment_secret) {
        uint8_t f[52];
        bytes_to_5bit(inv->payment_secret, 32, f, 52);
        WRITE_FIELD(18, f, 52);
    }

    /* m: payment_metadata (type 27) */
    if (inv->has_metadata && inv->metadata_len > 0) {
        uint8_t f[128];
        size_t f_len = bytes_to_5bit(inv->metadata, inv->metadata_len,
                                      f, sizeof(f));
        if (f_len > 0) WRITE_FIELD(27, f, f_len);
    }

    /* d: description */
    if (inv->description[0] && !inv->has_description_hash) {
        size_t dlen = strlen(inv->description);
        uint8_t f[512];
        size_t f_len = bytes_to_5bit((unsigned char *)inv->description, dlen, f, sizeof(f));
        if (f_len > 0) WRITE_FIELD(13, f, f_len);
    }

    /* h: description_hash */
    if (inv->has_description_hash) {
        uint8_t f[52];
        bytes_to_5bit(inv->description_hash, 32, f, 52);
        WRITE_FIELD(5, f, 52);
    }

    /* x: expiry (if non-default) */
    if (inv->expiry != 3600) {
        uint8_t f[8];
        size_t f_len = 0;
        uint32_t exp = inv->expiry;
        /* minimal encoding */
        if (exp < (1u << 5))       { f_len = 1; f[0] = (uint8_t)exp; }
        else if (exp < (1u << 10)) { f_len = 2; f[0] = (uint8_t)(exp >> 5); f[1] = (uint8_t)(exp & 0x1f); }
        else if (exp < (1u << 15)) { f_len = 3; f[0] = (uint8_t)(exp >> 10); f[1] = (uint8_t)((exp >> 5) & 0x1f); f[2] = (uint8_t)(exp & 0x1f); }
        else                       { f_len = 4; f[0] = (uint8_t)(exp >> 15); f[1] = (uint8_t)((exp >> 10) & 0x1f); f[2] = (uint8_t)((exp >> 5) & 0x1f); f[3] = (uint8_t)(exp & 0x1f); }
        WRITE_FIELD(4, f, f_len);
    }

    /* c: min_final_cltv_expiry */
    if (inv->min_final_cltv_expiry != 18) {
        uint8_t f[4];
        size_t f_len = 0;
        int clv = inv->min_final_cltv_expiry;
        if (clv < 32)      { f_len = 1; f[0] = (uint8_t)clv; }
        else if (clv < 1024){ f_len = 2; f[0] = (uint8_t)(clv >> 5); f[1] = (uint8_t)(clv & 0x1f); }
        else               { f_len = 3; f[0] = (uint8_t)(clv >> 10); f[1] = (uint8_t)((clv >> 5) & 0x1f); f[2] = (uint8_t)(clv & 0x1f); }
        WRITE_FIELD(6, f, f_len);
    }

    /* n: payee pubkey */
    if (inv->payee_pubkey[0] != 0) {
        uint8_t f[54];
        size_t f_len = bytes_to_5bit(inv->payee_pubkey, 33, f, sizeof(f));
        WRITE_FIELD(16, f, f_len);
    }

    /* r: route hints */
    for (int i = 0; i < inv->n_hints; i++) {
        const bolt11_route_hint_t *rh = &inv->hints[i];
        unsigned char rbuf[51 * 8];
        size_t rpos = 0;
        for (int j = 0; j < rh->n_hops; j++) {
            const bolt11_hop_hint_t *hop = &rh->hops[j];
            memcpy(rbuf + rpos, hop->pubkey, 33); rpos += 33;
            for (int k = 7; k >= 0; k--)
                rbuf[rpos++] = (unsigned char)((hop->short_channel_id >> (k*8)) & 0xff);
            rbuf[rpos++] = (unsigned char)(hop->fee_base_msat >> 24);
            rbuf[rpos++] = (unsigned char)(hop->fee_base_msat >> 16);
            rbuf[rpos++] = (unsigned char)(hop->fee_base_msat >> 8);
            rbuf[rpos++] = (unsigned char)(hop->fee_base_msat);
            rbuf[rpos++] = (unsigned char)(hop->fee_ppm >> 24);
            rbuf[rpos++] = (unsigned char)(hop->fee_ppm >> 16);
            rbuf[rpos++] = (unsigned char)(hop->fee_ppm >> 8);
            rbuf[rpos++] = (unsigned char)(hop->fee_ppm);
            rbuf[rpos++] = (unsigned char)(hop->cltv_expiry_delta >> 8);
            rbuf[rpos++] = (unsigned char)(hop->cltv_expiry_delta);
        }
        if (rpos > 0) {
            uint8_t f[512];
            size_t f_len = bytes_to_5bit(rbuf, rpos, f, sizeof(f));
            WRITE_FIELD(3, f, f_len);
        }
    }
#undef WRITE_FIELD

    /* Pad to byte boundary */
    size_t d5_len = (off + 4) / 5; /* number of 5-bit groups */

    /* Sign: sighash = SHA256(hrp_bytes || d5[0..d5_len]) */
    unsigned char sighash[32];
    {
        uint8_t *msg = (uint8_t *)malloc(hrp_len + d5_len);
        if (!msg) return 0;
        memcpy(msg, hrp, hrp_len);
        memcpy(msg + hrp_len, d5, d5_len);
        sha256(msg, hrp_len + d5_len, sighash);
        free(msg);
    }

    /* Sign with recoverable ECDSA */
    secp256k1_ecdsa_recoverable_signature rec_sig;
    if (!secp256k1_ecdsa_sign_recoverable(ctx, &rec_sig, sighash,
                                          node_privkey, NULL, NULL)) return 0;

    unsigned char compact[64];
    int recovery_id = 0;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(
        ctx, compact, &recovery_id, &rec_sig);

    /* sig bytes: compact(64) || recovery_flag(1) = 65 bytes → 104 5-bit groups */
    unsigned char sig65[65];
    memcpy(sig65, compact, 64);
    sig65[64] = (unsigned char)recovery_id;
    uint8_t sig5[104];
    size_t s5_len = bytes_to_5bit(sig65, 65, sig5, sizeof(sig5));
    if (s5_len != 104) return 0;

    /* Append sig to d5 */
    if (d5_len + 104 + 6 > sizeof(d5)) return 0;
    memcpy(d5 + d5_len, sig5, 104);
    d5_len += 104;

    /* Compute and append bech32 checksum (6 groups) */
    uint32_t chk = bech32_checksum_val(hrp, hrp_len, d5, d5_len);
    for (int i = 5; i >= 0; i--)
        d5[d5_len++] = (uint8_t)((chk >> (i*5)) & 0x1f);

    /* Build output string */
    size_t needed = hrp_len + 1 + d5_len + 1;
    if (out_cap < needed) return 0;
    size_t pos2 = 0;
    for (size_t i = 0; i < hrp_len; i++) out[pos2++] = hrp[i];
    out[pos2++] = '1';
    for (size_t i = 0; i < d5_len; i++) out[pos2++] = CHARSET[d5[i]];
    out[pos2] = '\0';
    return 1;
}
