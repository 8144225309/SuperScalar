/*
 * onion_msg_relay.c — Multi-hop onion message relay (BOLT #7 / BOLT #12)
 */

#include "superscalar/onion_msg_relay.h"
#include "superscalar/onion_last_hop.h"   /* onion_ecdh_shared_secret, onion_xor_stream */
#include "superscalar/noise.h"             /* hmac_sha256 */
#include "superscalar/sha256.h"            /* sha256 */
#include <secp256k1.h>
#include <string.h>
#include <stdint.h>

/* -----------------------------------------------------------------------
 * Internal helpers
 * --------------------------------------------------------------------- */

static void derive_key(const char *tag,
                        const unsigned char ss[32],
                        unsigned char out[32])
{
    hmac_sha256(out, (const unsigned char *)tag, strlen(tag), ss, 32);
}

static size_t write_bigsize(unsigned char *buf, size_t cap, size_t pos, uint64_t v)
{
    if (v < 0xfd) {
        if (pos >= cap) return 0;
        buf[pos++] = (unsigned char)v;
        return pos;
    }
    if (v <= 0xffff) {
        if (pos + 3 > cap) return 0;
        buf[pos++] = 0xfd;
        buf[pos++] = (unsigned char)(v >> 8);
        buf[pos++] = (unsigned char)v;
        return pos;
    }
    if (v <= 0xffffffff) {
        if (pos + 5 > cap) return 0;
        buf[pos++] = 0xfe;
        buf[pos++] = (unsigned char)(v >> 24);
        buf[pos++] = (unsigned char)(v >> 16);
        buf[pos++] = (unsigned char)(v >> 8);
        buf[pos++] = (unsigned char)v;
        return pos;
    }
    return 0;
}

static int read_bigsize(const unsigned char *buf, size_t len, size_t pos, uint64_t *out)
{
    if (pos >= len) return 0;
    unsigned char b0 = buf[pos];
    if (b0 < 0xfd) { *out = b0; return 1; }
    if (b0 == 0xfd) {
        if (pos + 3 > len) return 0;
        *out = ((uint64_t)buf[pos+1] << 8) | buf[pos+2];
        return 3;
    }
    if (b0 == 0xfe) {
        if (pos + 5 > len) return 0;
        *out = ((uint64_t)buf[pos+1] << 24) | ((uint64_t)buf[pos+2] << 16) |
               ((uint64_t)buf[pos+3] << 8)  | buf[pos+4];
        return 5;
    }
    if (pos + 9 > len) return 0;
    *out = 0;
    for (int i = 1; i <= 8; i++) *out = (*out << 8) | buf[pos + i];
    return 9;
}

/*
 * Encrypt a raw TLV byte stream into an onion packet.
 * (Like onion_msg_build but takes pre-built TLV bytes instead of type+data.)
 */
static size_t encrypt_pkt(secp256k1_context *ctx,
                            const unsigned char session_key[32],
                            const unsigned char dest_pub33[33],
                            const unsigned char *tlv_bytes, size_t tlv_len,
                            unsigned char path_key_out[33],
                            unsigned char *pkt_out, size_t pkt_cap)
{
    /* Compute path_key = session_key * G */
    secp256k1_pubkey ephem_pub;
    if (!secp256k1_ec_pubkey_create(ctx, &ephem_pub, session_key)) return 0;
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, path_key_out, &pub_len,
                                   &ephem_pub, SECP256K1_EC_COMPRESSED);

    /* Shared secret */
    unsigned char ss[32];
    if (!onion_ecdh_shared_secret(ctx, session_key, dest_pub33, ss)) return 0;

    /* Derive rho (stream key) and mu (HMAC key) */
    unsigned char rho[32], mu[32];
    derive_key("rho", ss, rho);
    derive_key("mu",  ss, mu);

    /* Encrypt TLV bytes */
    unsigned char encrypted[ONION_MSG_RELAY_APP_MAX + ONION_MSG_RELAY_PKT_MAX + 64];
    if (tlv_len > sizeof(encrypted)) return 0;
    if (!onion_xor_stream(tlv_bytes, tlv_len, rho, encrypted)) return 0;

    /* HMAC over ciphertext */
    unsigned char mac[32];
    hmac_sha256(mac, mu, 32, encrypted, tlv_len);

    /* Packet: version(1) + path_key(33) + ciphertext + hmac(32) */
    size_t pkt_size = 1 + 33 + tlv_len + 32;
    if (pkt_cap < pkt_size) return 0;

    size_t p = 0;
    pkt_out[p++] = 0x00; /* version */
    memcpy(pkt_out + p, path_key_out, 33); p += 33;
    memcpy(pkt_out + p, encrypted, tlv_len); p += tlv_len;
    memcpy(pkt_out + p, mac, 32); p += 32;
    return p;
}

/* -----------------------------------------------------------------------
 * Build relay hop payload
 * --------------------------------------------------------------------- */

size_t onion_msg_relay_build_hop_payload(
    const unsigned char next_node_id[33],
    const unsigned char *inner_pkt, size_t inner_pkt_len,
    unsigned char *out, size_t out_cap)
{
    if (!next_node_id || !inner_pkt || !out) return 0;

    size_t pos = 0;

    /* TLV type 4: next_node_id (33 bytes) */
    pos = write_bigsize(out, out_cap, pos, ONION_MSG_RELAY_TLV_NEXT_NODE);
    if (!pos) return 0;
    size_t prev = pos;
    pos = write_bigsize(out, out_cap, pos, 33);
    if (pos == prev) return 0;
    if (pos + 33 > out_cap) return 0;
    memcpy(out + pos, next_node_id, 33);
    pos += 33;

    /* TLV type 6: inner_pkt */
    prev = pos;
    pos = write_bigsize(out, out_cap, pos, ONION_MSG_RELAY_TLV_INNER_PKT);
    if (pos == prev) return 0;
    prev = pos;
    pos = write_bigsize(out, out_cap, pos, inner_pkt_len);
    if (pos == prev) return 0;
    if (pos + inner_pkt_len > out_cap) return 0;
    memcpy(out + pos, inner_pkt, inner_pkt_len);
    pos += inner_pkt_len;

    return pos;
}

/* -----------------------------------------------------------------------
 * Peel one relay hop
 * --------------------------------------------------------------------- */

int onion_msg_relay_peel(secp256k1_context *ctx,
                          const unsigned char our_priv[32],
                          const unsigned char path_key[33],
                          const unsigned char *pkt, size_t pkt_len,
                          onion_msg_relay_result_t *result)
{
    if (!ctx || !our_priv || !path_key || !pkt || !result) return 0;
    /* version(1) + ephemeral_key(33) + payload(≥1) + hmac(32) */
    if (pkt_len < 67) return 0;
    if (pkt[0] != 0x00) return 0;

    /* Shared secret */
    unsigned char ss[32];
    if (!onion_ecdh_shared_secret(ctx, our_priv, path_key, ss)) return 0;

    /* Derive rho and mu */
    unsigned char rho[32], mu[32];
    derive_key("rho", ss, rho);
    derive_key("mu",  ss, mu);

    const unsigned char *encrypted = pkt + 34;
    size_t enc_len = pkt_len - 34 - 32;
    const unsigned char *expected_mac = pkt + pkt_len - 32;

    /* Verify HMAC */
    unsigned char computed_mac[32];
    hmac_sha256(computed_mac, mu, 32, encrypted, enc_len);
    if (memcmp(computed_mac, expected_mac, 32) != 0) return 0;

    /* Decrypt */
    unsigned char plaintext[ONION_MSG_RELAY_APP_MAX + ONION_MSG_RELAY_PKT_MAX + 64];
    if (enc_len > sizeof(plaintext)) return 0;
    if (!onion_xor_stream(encrypted, enc_len, rho, plaintext)) return 0;

    /* Parse TLV stream */
    memset(result, 0, sizeof(*result));

    size_t pos = 0;
    int found_next_node = 0;

    while (pos < enc_len) {
        uint64_t tlv_type = 0, tlv_len = 0;
        int n;

        n = read_bigsize(plaintext, enc_len, pos, &tlv_type);
        if (!n) break;
        pos += n;

        n = read_bigsize(plaintext, enc_len, pos, &tlv_len);
        if (!n) break;
        pos += n;

        if (pos + tlv_len > enc_len) break;

        switch (tlv_type) {
        case ONION_MSG_RELAY_TLV_NEXT_NODE:       /* 4 */
            if (tlv_len == 33) {
                memcpy(result->next_node_id, plaintext + pos, 33);
                found_next_node = 1;
            }
            break;

        case ONION_MSG_RELAY_TLV_INNER_PKT:       /* 6 */
            if (tlv_len <= ONION_MSG_RELAY_PKT_MAX) {
                memcpy(result->inner_pkt, plaintext + pos, (size_t)tlv_len);
                result->inner_pkt_len = (size_t)tlv_len;
            }
            break;

        default:
            /* Unknown TLV — treat as app payload if no relay marker seen yet */
            if (!found_next_node && tlv_len <= ONION_MSG_RELAY_APP_MAX) {
                memcpy(result->app_data, plaintext + pos, (size_t)tlv_len);
                result->app_data_len = (size_t)tlv_len;
                result->app_tlv_type = tlv_type;
            }
            break;
        }

        pos += (size_t)tlv_len;
    }

    result->is_final = found_next_node ? 0 : 1;

    /* Compute next_path_key for forwarding (if relay hop) */
    if (!result->is_final) {
        onion_msg_relay_next_path_key(ctx, our_priv, path_key, result->next_path_key);
    }

    return 1;
}

/* -----------------------------------------------------------------------
 * Compute next_path_key (blinding factor update)
 * --------------------------------------------------------------------- */

int onion_msg_relay_next_path_key(secp256k1_context *ctx,
                                   const unsigned char our_priv[32],
                                   const unsigned char path_key[33],
                                   unsigned char next_path_key_out[33])
{
    if (!ctx || !our_priv || !path_key || !next_path_key_out) return 0;

    /* Shared secret */
    unsigned char ss[32];
    if (!onion_ecdh_shared_secret(ctx, our_priv, path_key, ss)) return 0;

    /* blinding_factor = SHA256(path_key(33) || shared_secret(32)) */
    unsigned char bf_input[65];
    memcpy(bf_input, path_key, 33);
    memcpy(bf_input + 33, ss, 32);
    unsigned char bf[32];
    sha256(bf_input, 65, bf);

    /* next_path_key = path_key * blinding_factor */
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, path_key, 33)) return 0;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &pk, bf)) return 0;

    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, next_path_key_out, &len, &pk,
                                   SECP256K1_EC_COMPRESSED);
    return 1;
}

/* -----------------------------------------------------------------------
 * Build a 2-hop relay onion message
 * --------------------------------------------------------------------- */

size_t onion_msg_relay_build2(secp256k1_context *ctx,
                               const unsigned char session_key_relay[32],
                               const unsigned char session_key_final[32],
                               const unsigned char relay_pub[33],
                               const unsigned char dest_pub[33],
                               const unsigned char *app_data, size_t app_data_len,
                               uint64_t app_tlv_type,
                               unsigned char relay_path_key_out[33],
                               unsigned char *outer_pkt_out, size_t outer_pkt_cap)
{
    if (!ctx || !session_key_relay || !session_key_final ||
        !relay_pub || !dest_pub || !app_data || !relay_path_key_out || !outer_pkt_out)
        return 0;
    if (app_data_len > ONION_MSG_RELAY_APP_MAX) return 0;

    /* Step 1: Build app TLV for final hop: {app_tlv_type: app_data} */
    unsigned char app_tlv[ONION_MSG_RELAY_APP_MAX + 16];
    size_t app_tlv_pos = 0;
    app_tlv_pos = write_bigsize(app_tlv, sizeof(app_tlv), app_tlv_pos, app_tlv_type);
    if (!app_tlv_pos) return 0;
    size_t prev = app_tlv_pos;
    app_tlv_pos = write_bigsize(app_tlv, sizeof(app_tlv), app_tlv_pos, app_data_len);
    if (app_tlv_pos == prev) return 0;
    if (app_tlv_pos + app_data_len > sizeof(app_tlv)) return 0;
    memcpy(app_tlv + app_tlv_pos, app_data, app_data_len);
    app_tlv_pos += app_data_len;

    /* Step 2: Build inner packet (session_key_final → dest) */
    unsigned char inner_path_key[33];
    unsigned char inner_pkt[ONION_MSG_RELAY_PKT_MAX];
    size_t inner_pkt_len = encrypt_pkt(ctx, session_key_final, dest_pub,
                                        app_tlv, app_tlv_pos,
                                        inner_path_key, inner_pkt, sizeof(inner_pkt));
    if (!inner_pkt_len) return 0;

    /* Step 3: Build relay hop payload: {TLV4: dest_pub, TLV6: inner_pkt} */
    unsigned char relay_payload[ONION_MSG_RELAY_PKT_MAX + 64];
    size_t relay_payload_len = onion_msg_relay_build_hop_payload(
        dest_pub, inner_pkt, inner_pkt_len, relay_payload, sizeof(relay_payload));
    if (!relay_payload_len) return 0;

    /* Step 4: Build outer packet (session_key_relay → relay_node) */
    return encrypt_pkt(ctx, session_key_relay, relay_pub,
                        relay_payload, relay_payload_len,
                        relay_path_key_out, outer_pkt_out, outer_pkt_cap);
}
