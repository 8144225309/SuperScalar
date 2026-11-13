/*
 * onion_last_hop.c — BOLT #4 final-hop Sphinx onion decryption
 *
 * Decrypts the innermost onion layer for the receiving node.
 *
 * Key derivation:
 *   shared_secret = SHA256(secp256k1_ec_point_mul(ephemeral_pub, node_priv))
 *   rho           = HMAC-SHA256(key="rho", data=shared_secret)
 *   stream        = ChaCha20(rho, nonce=0)[0..ONION_HOPS_DATA_SIZE]
 *   plain         = hops_data XOR stream
 *
 * Hop payload format (TLV-based, BOLT #4 §4.1.2.1):
 *   BigSize(payload_len) || tlv_stream(payload_len) || HMAC(32)
 */

#include "superscalar/onion_last_hop.h"
#include "superscalar/noise.h"     /* hmac_sha256 */
#include <secp256k1_ecdh.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>

/* ---- ChaCha20 bare stream (no Poly1305 tag) ---- */

static int chacha20_stream(const unsigned char key[32],
                            unsigned char *out, size_t len) {
    if (len == 0) return 1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    /* EVP_chacha20 IV: counter(4 LE) || nonce(12) — all zeros for BOLT #4 */
    static const unsigned char zero_iv[16] = {0};

    int ok = 0;
    unsigned char *zeros = (unsigned char *)calloc(len, 1);
    if (!zeros) goto out;

    int outlen = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, zero_iv) != 1) goto out;
    if (EVP_EncryptUpdate(ctx, out, &outlen, zeros, (int)len) != 1) goto out;
    ok = 1;

out:
    free(zeros);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* ---- BOLT #4 "generate_key": HMAC-SHA256(key=tag, data=ss) ---- */

static void generate_key(const char *tag,
                          const unsigned char ss[32],
                          unsigned char out[32]) {
    hmac_sha256(out,
                (const unsigned char *)tag, strlen(tag),
                ss, 32);
}

/* ---- ECDH ---- */

int onion_ecdh_shared_secret(secp256k1_context *ctx,
                              const unsigned char node_priv32[32],
                              const unsigned char ephemeral_pub33[33],
                              unsigned char ss_out[32]) {
    if (!ctx || !node_priv32 || !ephemeral_pub33 || !ss_out) return 0;

    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_parse(ctx, &pub, ephemeral_pub33, 33)) return 0;

    /* secp256k1_ecdh returns SHA256(x_coordinate) by default */
    return secp256k1_ecdh(ctx, ss_out, &pub, node_priv32, NULL, NULL);
}

/* ---- Rho key ---- */

void onion_generate_rho(const unsigned char shared_secret[32],
                        unsigned char rho_out[32]) {
    generate_key("rho", shared_secret, rho_out);
}

/* ---- XOR with ChaCha20 stream ---- */

int onion_xor_stream(const unsigned char *hops_data, size_t hops_len,
                     const unsigned char rho[32],
                     unsigned char *out) {
    if (!hops_data || !rho || !out || hops_len == 0) return 0;

    unsigned char *stream = (unsigned char *)malloc(hops_len);
    if (!stream) return 0;

    if (!chacha20_stream(rho, stream, hops_len)) {
        free(stream);
        return 0;
    }

    for (size_t i = 0; i < hops_len; i++)
        out[i] = hops_data[i] ^ stream[i];

    free(stream);
    return 1;
}

/* ---- BigSize varint decoder ---- */

/* Returns bytes consumed (1, 3, 5, or 9), or 0 on error.
   Writes decoded value to *val_out. */
static size_t decode_bigsize(const unsigned char *buf, size_t buf_len,
                              uint64_t *val_out) {
    if (buf_len < 1) return 0;
    uint8_t first = buf[0];
    if (first < 0xFD) {
        *val_out = first;
        return 1;
    } else if (first == 0xFD) {
        if (buf_len < 3) return 0;
        *val_out = ((uint64_t)buf[1] << 8) | buf[2];
        return 3;
    } else if (first == 0xFE) {
        if (buf_len < 5) return 0;
        *val_out = ((uint64_t)buf[1] << 24) | ((uint64_t)buf[2] << 16)
                 | ((uint64_t)buf[3] <<  8) |  (uint64_t)buf[4];
        return 5;
    } else { /* 0xFF */
        if (buf_len < 9) return 0;
        *val_out = ((uint64_t)buf[1] << 56) | ((uint64_t)buf[2] << 48)
                 | ((uint64_t)buf[3] << 40) | ((uint64_t)buf[4] << 32)
                 | ((uint64_t)buf[5] << 24) | ((uint64_t)buf[6] << 16)
                 | ((uint64_t)buf[7] <<  8) |  (uint64_t)buf[8];
        return 9;
    }
}

/* ---- TLV stream parser ---- */

/* A big-endian integer of len bytes (0..8) */
static uint64_t read_tu(const unsigned char *v, size_t len) {
    uint64_t x = 0;
    for (size_t i = 0; i < len; i++) x = (x << 8) | v[i];
    return x;
}

int onion_parse_tlv_payload(const unsigned char *payload, size_t payload_len,
                             onion_hop_payload_t *out) {
    if (!payload || !out) return 0;
    memset(out, 0, sizeof(*out));

    size_t off = 0;
    while (off < payload_len) {
        uint64_t type, length;
        size_t consumed;

        consumed = decode_bigsize(payload + off, payload_len - off, &type);
        if (consumed == 0) break;
        off += consumed;

        consumed = decode_bigsize(payload + off, payload_len - off, &length);
        if (consumed == 0) break;
        off += consumed;

        if (off + length > payload_len) break;

        const unsigned char *val = payload + off;
        off += (size_t)length;

        switch (type) {
        /* BOLT 4 writes these as truncated integers (tu64 / tu32: big
           endian, no leading zero bytes), so any length up to the full
           width is read. */
        case 2: /* amt_to_forward: tu64 */
            if (length <= 8) {
                out->amt_to_forward = read_tu(val, (size_t)length);
                out->has_amt = 1;
            }
            break;
        case 4: /* outgoing_cltv_value: tu32 */
            if (length <= 4) {
                out->outgoing_cltv_value = (uint32_t)read_tu(val, (size_t)length);
                out->has_cltv = 1;
            }
            break;
        case 8: /* payment_data: payment_secret(32) || total_msat (tu64) */
            if (length >= 32 && length <= 40) {
                memcpy(out->payment_secret, val, 32);
                out->total_msat = read_tu(val + 32, (size_t)length - 32);
                out->has_payment_data = 1;
            }
            break;
        case 6: /* short_channel_id: u64 BE (relay hop next-hop SCID) */
            if (length == 8) {
                out->short_channel_id = ((uint64_t)val[0] << 56)
                    | ((uint64_t)val[1] << 48) | ((uint64_t)val[2] << 40)
                    | ((uint64_t)val[3] << 32) | ((uint64_t)val[4] << 24)
                    | ((uint64_t)val[5] << 16) | ((uint64_t)val[6] <<  8)
                    |  (uint64_t)val[7];
                out->has_scid = 1;
            }
            break;
        case 0x0c: /* trampoline hop payload */
            if (length <= 256) {
                memcpy(out->trampoline_payload, val, (size_t)length);
                out->trampoline_payload_len = (size_t)length;
                out->has_trampoline = 1;
            }
            break;
        case 0x0e: /* nested trampoline onion (future use) */
            break;
        default:
            /* Unknown TLV: skip (even types are required, odd are optional).
               For simplicity, skip all unknown types. */
            break;
        }
    }

    return (out->has_amt && out->has_cltv) ? 1 : 0;
}

/* ---- High-level decrypt ---- */

int onion_last_hop_decrypt(secp256k1_context *ctx,
                            const unsigned char node_priv32[32],
                            const unsigned char onion_packet[ONION_PACKET_SIZE],
                            onion_hop_payload_t *payload_out) {
    if (!ctx || !node_priv32 || !onion_packet || !payload_out) return 0;

    /* version byte must be 0 */
    if (onion_packet[0] != 0x00) return 0;

    const unsigned char *ephemeral_pub = onion_packet + 1;  /* 33 bytes */
    const unsigned char *hops_data     = onion_packet + 34; /* 1300 bytes */

    /* Derive shared secret */
    unsigned char ss[32];
    if (!onion_ecdh_shared_secret(ctx, node_priv32, ephemeral_pub, ss)) return 0;

    /* Derive rho key */
    unsigned char rho[32];
    onion_generate_rho(ss, rho);

    /* Decrypt hops_data */
    unsigned char plain[ONION_HOPS_DATA_SIZE];
    if (!onion_xor_stream(hops_data, ONION_HOPS_DATA_SIZE, rho, plain)) return 0;

    /* Parse BigSize prefix */
    uint64_t payload_len;
    size_t hdr_bytes = decode_bigsize(plain, ONION_HOPS_DATA_SIZE, &payload_len);
    if (hdr_bytes == 0) return 0;
    if (hdr_bytes + payload_len + 32 > ONION_HOPS_DATA_SIZE) return 0;

    /* Parse TLV payload */
    return onion_parse_tlv_payload(plain + hdr_bytes, (size_t)payload_len,
                                   payload_out);
}

int onion_final_hop_decode(secp256k1_context *ctx,
                           const unsigned char node_priv32[32],
                           const unsigned char onion_packet[ONION_PACKET_SIZE],
                           const unsigned char *assoc_data, size_t assoc_len,
                           onion_hop_payload_t *payload_out) {
    if (!ctx || !node_priv32 || !onion_packet || !payload_out ||
        (!assoc_data && assoc_len)) return 0;
    if (onion_packet[0] != 0x00) return 0;

    const unsigned char *eph = onion_packet + 1;
    const unsigned char *hops = onion_packet + 34;
    const unsigned char *hmac = onion_packet + 34 + ONION_HOPS_DATA_SIZE;

    unsigned char ss[32], mu[32], rho[32], expect[32];
    if (!onion_ecdh_shared_secret(ctx, node_priv32, eph, ss)) return 0;
    generate_key("mu", ss, mu);

    unsigned char *mac_in = (unsigned char *)malloc(ONION_HOPS_DATA_SIZE + assoc_len);
    if (!mac_in) return 0;
    memcpy(mac_in, hops, ONION_HOPS_DATA_SIZE);
    if (assoc_len) memcpy(mac_in + ONION_HOPS_DATA_SIZE, assoc_data, assoc_len);
    hmac_sha256(expect, mu, 32, mac_in, ONION_HOPS_DATA_SIZE + assoc_len);
    free(mac_in);
    unsigned char diff = 0;
    for (int i = 0; i < 32; i++) diff |= (unsigned char)(expect[i] ^ hmac[i]);
    if (diff) return 0;

    generate_key("rho", ss, rho);
    unsigned char plain[ONION_HOPS_DATA_SIZE];
    if (!onion_xor_stream(hops, ONION_HOPS_DATA_SIZE, rho, plain)) return 0;

    uint64_t plen;
    size_t hdr = decode_bigsize(plain, ONION_HOPS_DATA_SIZE, &plen);
    if (hdr == 0 || plen == 0 || hdr + plen + 32 > ONION_HOPS_DATA_SIZE) return 0;
    /* the last hop: no packet follows */
    for (size_t i = 0; i < 32; i++)
        if (plain[hdr + plen + i] != 0) return 0;

    memset(payload_out, 0, sizeof(*payload_out));
    return onion_parse_tlv_payload(plain + hdr, (size_t)plen, payload_out);
}
