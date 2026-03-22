/*
 * onion_msg.c — BOLT #12 Onion Messages (type 513)
 *
 * Single-hop onion message build and decrypt using:
 *   - secp256k1 ECDH (via onion_last_hop.c)
 *   - ChaCha20 stream cipher (via onion_xor_stream)
 *   - HMAC-SHA256 (via noise.h)
 *
 * Reference: BOLT #12, LDK lightning/src/onion_message/
 */

#include "superscalar/onion_msg.h"
#include "superscalar/onion_last_hop.h"   /* onion_ecdh_shared_secret, onion_xor_stream */
#include "superscalar/noise.h"             /* hmac_sha256 */
#include <secp256k1.h>
#include <string.h>
#include <stdint.h>

/* ---- Wire helpers ---- */

static void put_u16(unsigned char *b, uint16_t v) {
    b[0] = (unsigned char)(v >> 8);
    b[1] = (unsigned char)v;
}

static uint16_t get_u16(const unsigned char *b) {
    return ((uint16_t)b[0] << 8) | b[1];
}

/* ---- BigSize encode (BOLT varlen integer) ---- */

static size_t write_bigsize(unsigned char *buf, size_t buf_cap, size_t pos, uint64_t v) {
    if (v < 0xfd) {
        if (pos >= buf_cap) return 0;
        buf[pos++] = (unsigned char)v;
        return pos;
    }
    if (v <= 0xffff) {
        if (pos + 3 > buf_cap) return 0;
        buf[pos++] = 0xfd;
        buf[pos++] = (unsigned char)(v >> 8);
        buf[pos++] = (unsigned char)v;
        return pos;
    }
    if (v <= 0xffffffff) {
        if (pos + 5 > buf_cap) return 0;
        buf[pos++] = 0xfe;
        buf[pos++] = (unsigned char)(v >> 24);
        buf[pos++] = (unsigned char)(v >> 16);
        buf[pos++] = (unsigned char)(v >> 8);
        buf[pos++] = (unsigned char)v;
        return pos;
    }
    if (pos + 9 > buf_cap) return 0;
    buf[pos++] = 0xff;
    for (int i = 7; i >= 0; i--) buf[pos++] = (unsigned char)(v >> (i * 8));
    return pos;
}

/* BigSize decode: returns bytes consumed, 0 on error */
static int read_bigsize(const unsigned char *buf, size_t buf_len, size_t pos, uint64_t *out) {
    if (pos >= buf_len) return 0;
    unsigned char b0 = buf[pos];
    if (b0 < 0xfd) { *out = b0; return 1; }
    if (b0 == 0xfd) {
        if (pos + 3 > buf_len) return 0;
        *out = ((uint64_t)buf[pos+1] << 8) | buf[pos+2];
        return 3;
    }
    if (b0 == 0xfe) {
        if (pos + 5 > buf_len) return 0;
        *out = ((uint64_t)buf[pos+1] << 24) | ((uint64_t)buf[pos+2] << 16) |
               ((uint64_t)buf[pos+3] << 8)  | buf[pos+4];
        return 5;
    }
    /* 0xff */
    if (pos + 9 > buf_len) return 0;
    *out = 0;
    for (int i = 1; i <= 8; i++) *out = (*out << 8) | buf[pos+i];
    return 9;
}

/* ---- Derive crypto keys from shared secret ---- */

static void derive_key(const char *tag,
                        const unsigned char ss[32],
                        unsigned char out[32]) {
    hmac_sha256(out, (const unsigned char *)tag, strlen(tag), ss, 32);
}

/* =========================================================
 * Wire encode / decode
 * ========================================================= */

size_t onion_msg_encode(const unsigned char path_key[33],
                        const unsigned char *pkt, size_t pkt_len,
                        unsigned char *out, size_t out_cap)
{
    if (!path_key || !pkt || !out) return 0;
    if (pkt_len > 0xffff) return 0;

    /* type(2) + path_key(33) + pkt_len(2) + pkt */
    size_t total = 2 + 33 + 2 + pkt_len;
    if (out_cap < total) return 0;

    size_t p = 0;
    put_u16(out + p, (uint16_t)ONION_MSG_TYPE); p += 2;
    memcpy(out + p, path_key, 33);              p += 33;
    put_u16(out + p, (uint16_t)pkt_len);        p += 2;
    memcpy(out + p, pkt, pkt_len);              p += pkt_len;
    return p;
}

int onion_msg_decode(const unsigned char *msg, size_t msg_len,
                     unsigned char path_key_out[33],
                     const unsigned char **pkt_out, size_t *pkt_len_out)
{
    if (!msg || !path_key_out || !pkt_out || !pkt_len_out) return 0;
    /* Minimum: type(2) + path_key(33) + pkt_len(2) = 37 */
    if (msg_len < 37) return 0;

    uint16_t type = get_u16(msg);
    if (type != ONION_MSG_TYPE) return 0;

    memcpy(path_key_out, msg + 2, 33);
    uint16_t pkt_len = get_u16(msg + 35);
    if (msg_len < (size_t)(37 + pkt_len)) return 0;

    *pkt_out     = msg + 37;
    *pkt_len_out = pkt_len;
    return 1;
}

/* =========================================================
 * Build single-hop packet
 * ========================================================= */

size_t onion_msg_build(secp256k1_context *ctx,
                       const unsigned char session_key[32],
                       const unsigned char dest_pub33[33],
                       const unsigned char *app_payload, size_t app_len,
                       uint64_t app_tlv_type,
                       unsigned char path_key_out[33],
                       unsigned char *pkt_out, size_t pkt_cap)
{
    if (!ctx || !session_key || !dest_pub33 || !app_payload || !path_key_out || !pkt_out)
        return 0;
    if (app_len > ONION_MSG_APP_MAX) return 0;

    /* 1. Compute path_key (= session_key * G) */
    secp256k1_pubkey ephem_pub;
    if (!secp256k1_ec_pubkey_create(ctx, &ephem_pub, session_key)) return 0;
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, path_key_out, &pub_len,
                                   &ephem_pub, SECP256K1_EC_COMPRESSED);

    /* 2. Compute shared secret: ECDH(dest_pub33, session_key) */
    unsigned char ss[32];
    if (!onion_ecdh_shared_secret(ctx, session_key, dest_pub33, ss)) return 0;

    /* 3. Derive rho (stream cipher key) and mu (HMAC key) */
    unsigned char rho[32], mu[32];
    derive_key("rho", ss, rho);
    derive_key("mu",  ss, mu);

    /* 4. Build TLV payload: type(bigsize) + len(bigsize) + data */
    unsigned char tlv_buf[ONION_MSG_APP_MAX + 20];
    size_t tlv_pos = 0;

    tlv_pos = write_bigsize(tlv_buf, sizeof(tlv_buf), tlv_pos, app_tlv_type);
    if (!tlv_pos) return 0;
    size_t before = tlv_pos;
    tlv_pos = write_bigsize(tlv_buf, sizeof(tlv_buf), tlv_pos, app_len);
    if (tlv_pos == before) return 0;
    if (tlv_pos + app_len > sizeof(tlv_buf)) return 0;
    memcpy(tlv_buf + tlv_pos, app_payload, app_len);
    tlv_pos += app_len;

    /* 5. Encrypt TLV: ChaCha20(key=rho) XOR plaintext */
    unsigned char encrypted[ONION_MSG_APP_MAX + 20];
    if (!onion_xor_stream(tlv_buf, tlv_pos, rho, encrypted)) return 0;

    /* 6. HMAC over ciphertext */
    unsigned char mac[32];
    hmac_sha256(mac, mu, 32, encrypted, tlv_pos);

    /* 7. Packet: version(1) + path_key(33) + ciphertext + hmac(32) */
    size_t pkt_size = 1 + 33 + tlv_pos + 32;
    if (pkt_cap < pkt_size) return 0;

    size_t p = 0;
    pkt_out[p++] = 0x00; /* version */
    memcpy(pkt_out + p, path_key_out, 33); p += 33;
    memcpy(pkt_out + p, encrypted, tlv_pos); p += tlv_pos;
    memcpy(pkt_out + p, mac, 32); p += 32;
    return p;
}

/* =========================================================
 * Decrypt final-hop packet
 * ========================================================= */

int onion_msg_recv_final(secp256k1_context *ctx,
                          const unsigned char our_priv[32],
                          const unsigned char path_key[33],
                          const unsigned char *pkt, size_t pkt_len,
                          unsigned char *app_data_out, size_t app_buf_cap,
                          size_t *app_len_out,
                          uint64_t *app_tlv_type_out)
{
    if (!ctx || !our_priv || !path_key || !pkt) return 0;
    /* version(1) + ephemeral_key(33) + at_least_1_byte_payload + hmac(32) */
    if (pkt_len < 67) return 0;
    if (pkt[0] != 0x00) return 0; /* version must be 0 */

    /* Shared secret using path_key for ECDH */
    unsigned char ss[32];
    if (!onion_ecdh_shared_secret(ctx, our_priv, path_key, ss)) return 0;

    /* Derive keys */
    unsigned char rho[32], mu[32];
    derive_key("rho", ss, rho);
    derive_key("mu",  ss, mu);

    /* Encrypted payload: bytes after version(1)+ephemeral_key(33), before hmac(32) */
    const unsigned char *encrypted = pkt + 34;
    size_t enc_len = pkt_len - 34 - 32;
    const unsigned char *expected_mac = pkt + pkt_len - 32;

    /* Verify HMAC */
    unsigned char computed_mac[32];
    hmac_sha256(computed_mac, mu, 32, encrypted, enc_len);
    if (memcmp(computed_mac, expected_mac, 32) != 0) return 0;

    /* Decrypt */
    unsigned char plaintext[ONION_MSG_APP_MAX + 20];
    if (enc_len > sizeof(plaintext)) return 0;
    if (!onion_xor_stream(encrypted, enc_len, rho, plaintext)) return 0;

    /* Parse TLV: type(bigsize) + len(bigsize) + data */
    uint64_t tlv_type = 0, tlv_data_len = 0;
    size_t pos = 0;

    int n = read_bigsize(plaintext, enc_len, pos, &tlv_type);
    if (!n) return 0;
    pos += n;

    n = read_bigsize(plaintext, enc_len, pos, &tlv_data_len);
    if (!n) return 0;
    pos += n;

    if (pos + tlv_data_len > enc_len) return 0;
    if (tlv_data_len > app_buf_cap) return 0;

    if (app_data_out)
        memcpy(app_data_out, plaintext + pos, (size_t)tlv_data_len);
    if (app_len_out)
        *app_len_out = (size_t)tlv_data_len;
    if (app_tlv_type_out)
        *app_tlv_type_out = tlv_type;
    return 1;
}
