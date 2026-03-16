/*
 * gossip.c — BOLT #7 gossip message construction
 *
 * node_announcement / channel_announcement / channel_update / timestamp_filter
 * Signatures: 64-byte Schnorr (secp256k1_schnorrsig_sign32) over
 * SHA256(SHA256(type || data_after_signature))
 */

#include "superscalar/gossip.h"
#include "superscalar/sha256.h"
#include "superscalar/types.h"

#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

/* --- Chain hashes (genesis block SHA256d, byte order as used in BOLT #7) --- */

/* Bitcoin mainnet genesis SHA256d (little-endian) */
const unsigned char GOSSIP_CHAIN_HASH_MAINNET[32] = {
    0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
    0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
    0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
    0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* Testnet3 genesis SHA256d */
const unsigned char GOSSIP_CHAIN_HASH_TESTNET[32] = {
    0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71,
    0x08, 0xf4, 0xa3, 0x0f, 0xd9, 0xce, 0xc3, 0xae,
    0xba, 0x79, 0x97, 0x20, 0x84, 0xe9, 0x0e, 0xad,
    0x01, 0xea, 0x33, 0x09, 0x00, 0x00, 0x00, 0x00
};

/* Signet genesis SHA256d */
const unsigned char GOSSIP_CHAIN_HASH_SIGNET[32] = {
    0xf6, 0x1e, 0xee, 0x3b, 0x63, 0xa3, 0x80, 0xa4,
    0x77, 0xa0, 0x63, 0xaf, 0x32, 0xb2, 0xbb, 0xc9,
    0x7c, 0x9f, 0xf9, 0xf0, 0x1f, 0x2c, 0x42, 0x25,
    0xe9, 0x73, 0x98, 0x81, 0x08, 0x00, 0x00, 0x00
};

/* --- Wire encoding helpers --- */

static void write_be16(unsigned char *p, uint16_t v) {
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)(v);
}

static void write_be32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)(v);
}

static void write_be64(unsigned char *p, uint64_t v) {
    p[0] = (unsigned char)(v >> 56);
    p[1] = (unsigned char)(v >> 48);
    p[2] = (unsigned char)(v >> 40);
    p[3] = (unsigned char)(v >> 32);
    p[4] = (unsigned char)(v >> 24);
    p[5] = (unsigned char)(v >> 16);
    p[6] = (unsigned char)(v >> 8);
    p[7] = (unsigned char)(v);
}

/* --- Signature helpers --- */

/*
 * Sign the "signable data": type(2) || data_after_sig
 * The signed data starts at msg[0] (type bytes) then skips the 64-byte sig
 * field and continues to the end of the message.
 *
 * msg layout: type(2) || sig(64) || rest
 * => signed = type(2) || rest = msg[0..1] || msg[66..msg_len-1]
 */
static int sign_gossip_msg(unsigned char sig64_out[64],
                            secp256k1_context *ctx,
                            const unsigned char node_priv32[32],
                            const unsigned char *msg, size_t msg_len) {
    if (msg_len < 66) return 0;

    /* Build: type(2) || msg[66..] */
    size_t data_len = 2 + (msg_len - 66);
    unsigned char *data = (unsigned char *)malloc(data_len);
    if (!data) return 0;

    memcpy(data, msg, 2);                      /* type */
    memcpy(data + 2, msg + 66, msg_len - 66);  /* rest */

    unsigned char hash[32];
    sha256_double(data, data_len, hash);
    free(data);

    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, node_priv32)) return 0;

    int ok = secp256k1_schnorrsig_sign32(ctx, sig64_out, hash, &kp, NULL);
    secure_zero(&kp, sizeof(kp));
    return ok;
}

/*
 * Verify a gossip message signature.
 * Recovers node_id from bytes 66..98 (node_id field in node_announcement).
 * For channel_update the node_id is not in the message — caller provides it.
 */
static int verify_gossip_sig(secp256k1_context *ctx,
                               const unsigned char sig64[64],
                               const unsigned char node_id33[33],
                               const unsigned char *msg, size_t msg_len) {
    if (msg_len < 66) return 0;

    size_t data_len = 2 + (msg_len - 66);
    unsigned char *data = (unsigned char *)malloc(data_len);
    if (!data) return 0;

    memcpy(data, msg, 2);
    memcpy(data + 2, msg + 66, msg_len - 66);

    unsigned char hash[32];
    sha256_double(data, data_len, hash);
    free(data);

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, node_id33, 33)) return 0;

    secp256k1_xonly_pubkey xpk;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &xpk, NULL, &pk)) return 0;

    return secp256k1_schnorrsig_verify(ctx, sig64, hash, 32, &xpk);
}

/* --- node_announcement --- */

size_t gossip_build_node_announcement(
    unsigned char *out, size_t out_cap,
    secp256k1_context *ctx,
    const unsigned char node_priv32[32],
    uint32_t         timestamp,
    const unsigned char rgb[3],
    const char      *alias_utf8,
    const char      *ipv4_addr,
    uint16_t         port) {

    if (!out || !ctx || !node_priv32) return 0;

    /* features: empty (0 bytes), flen = 0 */
    uint16_t flen = 0;

    /* address: type 1 (IPv4) = 1 + 4 + 2 = 7 bytes, or empty */
    uint8_t addr_buf[7];
    uint16_t addrlen = 0;
    if (ipv4_addr && port > 0) {
        struct in_addr ia;
        if (inet_pton(AF_INET, ipv4_addr, &ia) == 1) {
            addr_buf[0] = 0x01;  /* type 1 = IPv4 */
            memcpy(addr_buf + 1, &ia.s_addr, 4);
            addr_buf[5] = (unsigned char)(port >> 8);
            addr_buf[6] = (unsigned char)(port);
            addrlen = 7;
        }
    }

    /* Total size:
       type(2) + sig(64) + flen(2) + features(0) + timestamp(4)
       + node_id(33) + rgb(3) + alias(32) + addrlen(2) + addrs(addrlen) */
    size_t total = 2 + 64 + 2 + flen + 4 + 33 + 3 + 32 + 2 + addrlen;
    if (total > out_cap) return 0;

    size_t off = 0;
    write_be16(out + off, GOSSIP_MSG_NODE_ANNOUNCEMENT); off += 2;

    /* Signature placeholder (64 zeros) */
    memset(out + off, 0, 64); off += 64;

    /* features (empty) */
    write_be16(out + off, flen); off += 2;

    /* timestamp */
    write_be32(out + off, timestamp); off += 4;

    /* node_id: derive from priv */
    secp256k1_pubkey node_pub;
    if (!secp256k1_ec_pubkey_create(ctx, &node_pub, node_priv32)) return 0;
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, out + off, &pub_len, &node_pub,
                                   SECP256K1_EC_COMPRESSED);
    off += 33;

    /* rgb_color */
    if (rgb) {
        memcpy(out + off, rgb, 3);
    } else {
        memset(out + off, 0, 3);
    }
    off += 3;

    /* alias: 32 bytes NUL-padded */
    memset(out + off, 0, 32);
    if (alias_utf8) {
        size_t alen = strlen(alias_utf8);
        if (alen > 32) alen = 32;
        memcpy(out + off, alias_utf8, alen);
    }
    off += 32;

    /* addrlen + addresses */
    write_be16(out + off, addrlen); off += 2;
    if (addrlen > 0) {
        memcpy(out + off, addr_buf, addrlen);
        off += addrlen;
    }

    /* Sign the message */
    unsigned char sig64[64];
    if (!sign_gossip_msg(sig64, ctx, node_priv32, out, off)) return 0;

    /* Place signature at bytes 2..65 */
    memcpy(out + 2, sig64, 64);

    return off;
}

int gossip_verify_node_announcement(secp256k1_context *ctx,
                                     const unsigned char *msg, size_t msg_len) {
    /* node_announcement layout: type(2) + sig(64) + flen(2) + features(flen)
       + timestamp(4) + node_id(33) + ... */
    if (!ctx || !msg || msg_len < 66 + 2 + 4 + 33) return 0;

    const unsigned char *sig64 = msg + 2;

    /* flen field is at offset 66 */
    uint16_t flen = ((uint16_t)msg[66] << 8) | msg[67];
    size_t node_id_off = 66 + 2 + flen + 4;
    if (node_id_off + 33 > msg_len) return 0;

    const unsigned char *node_id33 = msg + node_id_off;

    return verify_gossip_sig(ctx, sig64, node_id33, msg, msg_len);
}

/* --- channel_announcement --- */

size_t gossip_build_channel_announcement_unsigned(
    unsigned char *out, size_t out_cap,
    const unsigned char chain_hash32[32],
    uint64_t         short_channel_id,
    const unsigned char node_id_1_33[33],
    const unsigned char node_id_2_33[33],
    const unsigned char bitcoin_key_1_33[33],
    const unsigned char bitcoin_key_2_33[33]) {

    if (!out || !chain_hash32 || !node_id_1_33 || !node_id_2_33 ||
        !bitcoin_key_1_33 || !bitcoin_key_2_33) return 0;

    /* type(2) + 4×sig(64) + flen(2) + features(0) + chain_hash(32)
       + scid(8) + node_id1(33) + node_id2(33) + btc_key1(33) + btc_key2(33) */
    size_t total = 2 + 4*64 + 2 + 0 + 32 + 8 + 33 + 33 + 33 + 33;
    if (total > out_cap) return 0;

    size_t off = 0;
    write_be16(out + off, GOSSIP_MSG_CHANNEL_ANNOUNCEMENT); off += 2;

    /* Four signature placeholders */
    memset(out + off, 0, 4 * 64); off += 4 * 64;

    /* features (empty) */
    write_be16(out + off, 0); off += 2;

    /* chain_hash */
    memcpy(out + off, chain_hash32, 32); off += 32;

    /* short_channel_id */
    write_be64(out + off, short_channel_id); off += 8;

    /* node_id_1, node_id_2, bitcoin_key_1, bitcoin_key_2 */
    memcpy(out + off, node_id_1_33,    33); off += 33;
    memcpy(out + off, node_id_2_33,    33); off += 33;
    memcpy(out + off, bitcoin_key_1_33,33); off += 33;
    memcpy(out + off, bitcoin_key_2_33,33); off += 33;

    return off;
}

/* --- channel_update --- */

size_t gossip_build_channel_update(
    unsigned char *out, size_t out_cap,
    secp256k1_context *ctx,
    const unsigned char node_priv32[32],
    const unsigned char chain_hash32[32],
    uint64_t         short_channel_id,
    uint32_t         timestamp,
    uint8_t          message_flags,
    uint8_t          channel_flags,
    uint16_t         cltv_expiry_delta,
    uint64_t         htlc_minimum_msat,
    uint32_t         fee_base_msat,
    uint32_t         fee_proportional_millionths,
    uint64_t         htlc_maximum_msat) {

    if (!out || !ctx || !node_priv32 || !chain_hash32) return 0;

    int has_max = (message_flags & GOSSIP_UPDATE_MSGFLAG_HTLC_MAX) != 0;

    /* type(2) + sig(64) + chain_hash(32) + scid(8) + timestamp(4)
       + msg_flags(1) + chan_flags(1) + cltv(2) + htlc_min(8)
       + fee_base(4) + fee_ppm(4) [+ htlc_max(8)] */
    size_t total = 2 + 64 + 32 + 8 + 4 + 1 + 1 + 2 + 8 + 4 + 4
                   + (has_max ? 8 : 0);
    if (total > out_cap) return 0;

    size_t off = 0;
    write_be16(out + off, GOSSIP_MSG_CHANNEL_UPDATE); off += 2;

    /* Signature placeholder */
    memset(out + off, 0, 64); off += 64;

    memcpy(out + off, chain_hash32, 32); off += 32;
    write_be64(out + off, short_channel_id); off += 8;
    write_be32(out + off, timestamp); off += 4;
    out[off++] = message_flags;
    out[off++] = channel_flags;
    write_be16(out + off, cltv_expiry_delta); off += 2;
    write_be64(out + off, htlc_minimum_msat); off += 8;
    write_be32(out + off, fee_base_msat); off += 4;
    write_be32(out + off, fee_proportional_millionths); off += 4;
    if (has_max) {
        write_be64(out + off, htlc_maximum_msat); off += 8;
    }

    /* Sign */
    unsigned char sig64[64];
    if (!sign_gossip_msg(sig64, ctx, node_priv32, out, off)) return 0;
    memcpy(out + 2, sig64, 64);

    return off;
}

/* --- gossip_timestamp_filter --- */

size_t gossip_build_timestamp_filter(
    unsigned char *out, size_t out_cap,
    const unsigned char chain_hash32[32],
    uint32_t         first_timestamp,
    uint32_t         timestamp_range) {

    if (!out || !chain_hash32) return 0;

    /* type(2) + chain_hash(32) + first_timestamp(4) + timestamp_range(4) */
    size_t total = 2 + 32 + 4 + 4;
    if (total > out_cap) return 0;

    size_t off = 0;
    write_be16(out + off, GOSSIP_MSG_TIMESTAMP_FILTER); off += 2;
    memcpy(out + off, chain_hash32, 32); off += 32;
    write_be32(out + off, first_timestamp); off += 4;
    write_be32(out + off, timestamp_range); off += 4;

    return off;
}
