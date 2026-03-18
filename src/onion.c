/*
 * onion.c — BOLT #4 multi-hop Sphinx onion packet construction
 *
 * Builds and peels 1366-byte onion packets using:
 *   - Per-hop ECDH (secp256k1_ecdh)
 *   - ChaCha20 stream cipher (via onion_last_hop.c primitives)
 *   - HMAC-SHA256 per layer
 *   - Filler construction per BOLT #4
 *
 * Spec: BOLT #4. Reference: CLN common/onion.c, LDK onion_utils.rs.
 */

#include "superscalar/onion.h"
#include "superscalar/onion_last_hop.h"
#include "superscalar/noise.h"       /* hmac_sha256 */
#include "superscalar/sha256.h"
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>

/* ---- Onion packet layout ---- */
/* version(1) + ephemeral_pub(33) + hops_data(1300) + hmac(32) = 1366 */
#define HOP_DATA_SIZE   1300
#define HMAC_SIZE       32

/* ---- Key generation from shared secret ---- */
static void bolt4_generate_key(const char *tag,
                                const unsigned char ss[32],
                                unsigned char out[32]) {
    hmac_sha256(out, (const unsigned char *)tag, strlen(tag), ss, 32);
}

/* ---- ChaCha20 stream ---- */
static int chacha20_stream(const unsigned char key[32],
                            unsigned char *out, size_t len) {
    if (len == 0) return 1;
    EVP_CIPHER_CTX *ctx2 = EVP_CIPHER_CTX_new();
    if (!ctx2) return 0;
    static const unsigned char zero_iv[16] = {0};
    unsigned char *zeros = (unsigned char *)calloc(len, 1);
    if (!zeros) { EVP_CIPHER_CTX_free(ctx2); return 0; }
    int outlen = 0;
    int ok = (EVP_EncryptInit_ex(ctx2, EVP_chacha20(), NULL, key, zero_iv) == 1 &&
              EVP_EncryptUpdate(ctx2, out, &outlen, zeros, (int)len) == 1);
    free(zeros);
    EVP_CIPHER_CTX_free(ctx2);
    return ok;
}

/* ---- Build a minimal TLV hop payload in 5-bit format ---- */
/*
 * Returns number of bytes written into buf.
 * For relay hops: amt_to_forward, outgoing_cltv, short_channel_id (type 6)
 * For final hop:  amt_to_forward, outgoing_cltv, payment_data (type 8)
 *                 + keysend preimage (type 5482373484) if has_keysend
 */
static size_t build_hop_payload(const onion_hop_t *hop,
                                 unsigned char *buf, size_t buf_cap) {
    size_t pos = 0;

#define WRITE_BIGSIZE(v) do { \
    uint64_t _v = (v); \
    if (_v < 0xfd) { \
        if (pos >= buf_cap) return 0; \
        buf[pos++] = (unsigned char)_v; \
    } else if (_v <= 0xffff) { \
        if (pos + 3 > buf_cap) return 0; \
        buf[pos++] = 0xfd; \
        buf[pos++] = (unsigned char)(_v >> 8); \
        buf[pos++] = (unsigned char)(_v); \
    } else if (_v <= 0xffffffff) { \
        if (pos + 5 > buf_cap) return 0; \
        buf[pos++] = 0xfe; \
        buf[pos++] = (unsigned char)(_v >> 24); \
        buf[pos++] = (unsigned char)(_v >> 16); \
        buf[pos++] = (unsigned char)(_v >> 8); \
        buf[pos++] = (unsigned char)(_v); \
    } else { \
        if (pos + 9 > buf_cap) return 0; \
        buf[pos++] = 0xff; \
        for (int _i = 7; _i >= 0; _i--) buf[pos++] = (unsigned char)((_v) >> (_i*8)); \
    } \
} while(0)

#define WRITE_U64_BE(v) do { \
    if (pos + 8 > buf_cap) return 0; \
    for (int _i = 7; _i >= 0; _i--) buf[pos++] = (unsigned char)((v) >> (_i*8)); \
} while(0)

#define WRITE_U32_BE(v) do { \
    if (pos + 4 > buf_cap) return 0; \
    buf[pos++] = (unsigned char)((v) >> 24); \
    buf[pos++] = (unsigned char)((v) >> 16); \
    buf[pos++] = (unsigned char)((v) >> 8); \
    buf[pos++] = (unsigned char)(v); \
} while(0)

    /* type=2, len=8, amt_to_forward */
    WRITE_BIGSIZE(2); WRITE_BIGSIZE(8); WRITE_U64_BE(hop->amount_msat);

    /* type=4, len=4, outgoing_cltv */
    WRITE_BIGSIZE(4); WRITE_BIGSIZE(4); WRITE_U32_BE(hop->cltv_expiry);

    if (!hop->is_final) {
        /* type=6, len=8, short_channel_id */
        WRITE_BIGSIZE(6); WRITE_BIGSIZE(8); WRITE_U64_BE(hop->short_channel_id);
    } else {
        /* type=8, len=40, payment_data: payment_secret(32) + total_msat(8) */
        WRITE_BIGSIZE(8); WRITE_BIGSIZE(40);
        if (pos + 32 > buf_cap) return 0;
        memcpy(buf + pos, hop->payment_secret, 32); pos += 32;
        WRITE_U64_BE(hop->total_msat);

        /* keysend preimage: type=5482373484, len=32, preimage */
        if (hop->has_keysend) {
            WRITE_BIGSIZE(5482373484ULL);
            WRITE_BIGSIZE(32);
            if (pos + 32 > buf_cap) return 0;
            memcpy(buf + pos, hop->keysend_preimage, 32); pos += 32;
        }
        /* AMP TLV type 14: set_id(32) + child_index(1) + share(32) = 65 bytes */
        if (hop->has_amp) {
            if (pos + 2 + 65 <= buf_cap) {
                buf[pos++] = 14;    /* type */
                buf[pos++] = 65;    /* length */
                memcpy(buf + pos, hop->amp_set_id, 32); pos += 32;
                buf[pos++] = hop->amp_child_index;
                memcpy(buf + pos, hop->amp_root_share, 32); pos += 32;
            }
        }
    }

    return pos;

#undef WRITE_BIGSIZE
#undef WRITE_U64_BE
#undef WRITE_U32_BE
}

/* ---- Onion build ---- */

int onion_build(const onion_hop_t *hops, int n_hops,
                const unsigned char session_key[32],
                secp256k1_context *ctx,
                unsigned char onion_out[ONION_PACKET_SIZE]) {
    if (!hops || n_hops <= 0 || n_hops > ONION_MAX_HOPS ||
        !session_key || !ctx || !onion_out) return 0;

    /* ---- Step 1: Generate ephemeral keypairs per hop ---- */
    unsigned char e_priv[ONION_MAX_HOPS][32];
    unsigned char e_pub[ONION_MAX_HOPS][33];
    unsigned char ss[ONION_MAX_HOPS][32];        /* shared secret per hop */
    unsigned char rho[ONION_MAX_HOPS][32];
    unsigned char mu[ONION_MAX_HOPS][32];
    unsigned char blinding[ONION_MAX_HOPS][32];  /* blinding factor */

    /* e_priv[0] = session_key */
    memcpy(e_priv[0], session_key, 32);

    for (int i = 0; i < n_hops; i++) {
        secp256k1_pubkey epub;
        if (!secp256k1_ec_pubkey_create(ctx, &epub, e_priv[i])) return 0;
        size_t pub_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, e_pub[i], &pub_len,
                                      &epub, SECP256K1_EC_COMPRESSED);

        /* shared_secret = SHA256(secp256k1_ecdh(e_priv[i], hop_pub)) */
        secp256k1_pubkey hop_pub;
        if (!secp256k1_ec_pubkey_parse(ctx, &hop_pub, hops[i].pubkey, 33)) return 0;
        if (!secp256k1_ecdh(ctx, ss[i], &hop_pub, e_priv[i], NULL, NULL)) return 0;

        /* rho = HMAC-SHA256("rho", ss) */
        bolt4_generate_key("rho", ss[i], rho[i]);
        /* mu  = HMAC-SHA256("mu",  ss) */
        bolt4_generate_key("mu",  ss[i], mu[i]);

        if (i + 1 < n_hops) {
            /* blinding_factor = SHA256(e_pub[i] || ss[i]) */
            unsigned char blend_in[65];
            memcpy(blend_in, e_pub[i], 33);
            memcpy(blend_in + 33, ss[i], 32);
            sha256(blend_in, 65, blinding[i]);

            /* e_priv[i+1] = e_priv[i] * blinding[i] (scalar mul) */
            memcpy(e_priv[i+1], e_priv[i], 32);
            if (!secp256k1_ec_seckey_tweak_mul(ctx, e_priv[i+1], blinding[i]))
                return 0;
        }
    }

    /* ---- Step 2: Build hop payloads + filler ---- */
    /*
     * Filler: the padding that appears at the end of the hops_data
     * after inner layers are decrypted. Built by XOR-ing the stream
     * at the right offset for each hop (except the last).
     *
     * We process hops in reverse (innermost first) so we can compute
     * the MAC chain.
     */

    /* For each hop, compute TLV payload + length prefix */
    unsigned char payloads[ONION_MAX_HOPS][256];
    size_t payload_lens[ONION_MAX_HOPS];
    unsigned char framed[ONION_MAX_HOPS][260]; /* BigSize(len) + payload */
    size_t framed_lens[ONION_MAX_HOPS];

    for (int i = 0; i < n_hops; i++) {
        payload_lens[i] = build_hop_payload(&hops[i], payloads[i], sizeof(payloads[i]));
        if (payload_lens[i] == 0) return 0;

        /* Frame: BigSize(payload_len) + payload */
        size_t fpos = 0;
        unsigned char *fb = framed[i];
        uint64_t plen = payload_lens[i];
        if (plen < 0xfd) {
            fb[fpos++] = (unsigned char)plen;
        } else {
            fb[fpos++] = 0xfd;
            fb[fpos++] = (unsigned char)(plen >> 8);
            fb[fpos++] = (unsigned char)(plen);
        }
        memcpy(fb + fpos, payloads[i], payload_lens[i]);
        fpos += payload_lens[i];
        framed_lens[i] = fpos;
    }

    /* ---- Step 3: Assemble hops_data from innermost hop outward ---- */

    /*
     * outer_shift[i] = total bytes that hops 0..i-1 will shift off when
     * they forward the onion.  The last outer_shift[i] bytes of hops_data_i
     * must be zero so that the HMAC covers the same view that hop i sees.
     * This implements the BOLT #4 filler property.
     */
    size_t outer_shift[ONION_MAX_HOPS];
    outer_shift[0] = 0;
    for (int i = 1; i < n_hops; i++)
        outer_shift[i] = outer_shift[i-1] + framed_lens[i-1] + HMAC_SIZE;

    unsigned char hops_data[HOP_DATA_SIZE];
    memset(hops_data, 0, HOP_DATA_SIZE);

    unsigned char next_hmac[HMAC_SIZE];
    memset(next_hmac, 0, HMAC_SIZE); /* innermost HMAC is all-zeros */

    for (int i = n_hops - 1; i >= 0; i--) {
        size_t flen = framed_lens[i] + HMAC_SIZE;

        /* Shift existing hops_data right by flen (to make room for this hop) */
        if (flen < HOP_DATA_SIZE)
            memmove(hops_data + flen, hops_data, HOP_DATA_SIZE - flen);
        /* Zero the space we just freed at the front */
        memset(hops_data, 0, flen < HOP_DATA_SIZE ? flen : HOP_DATA_SIZE);

        /* Write framed payload + next_hmac into hops_data[0..flen) */
        if (framed_lens[i] > HOP_DATA_SIZE) return 0;
        memcpy(hops_data, framed[i], framed_lens[i]);
        if (framed_lens[i] + HMAC_SIZE <= HOP_DATA_SIZE)
            memcpy(hops_data + framed_lens[i], next_hmac, HMAC_SIZE);

        /* Encrypt the entire hops_data with rho[i] */
        unsigned char *stream = (unsigned char *)malloc(HOP_DATA_SIZE);
        if (!stream) return 0;
        if (!chacha20_stream(rho[i], stream, HOP_DATA_SIZE)) {
            free(stream);
            return 0;
        }
        for (int k = 0; k < HOP_DATA_SIZE; k++)
            hops_data[k] ^= stream[k];
        free(stream);

        /*
         * Zero out the tail bytes that outer hops will shift off.
         * This ensures HMAC_i is computed over the same bytes that hop i
         * will actually receive (with those tail bytes zero-padded).
         */
        if (outer_shift[i] > 0 && outer_shift[i] < HOP_DATA_SIZE)
            memset(hops_data + HOP_DATA_SIZE - outer_shift[i], 0, outer_shift[i]);

        /* Compute HMAC over (hops_data || e_pub[i]) using mu[i] */
        unsigned char mac_input[HOP_DATA_SIZE + 33];
        memcpy(mac_input, hops_data, HOP_DATA_SIZE);
        memcpy(mac_input + HOP_DATA_SIZE, e_pub[i], 33);
        hmac_sha256(next_hmac, mu[i], 32, mac_input, sizeof(mac_input));
    }

    /* ---- Step 4: Assemble final packet ---- */
    onion_out[0] = 0x00; /* version */
    memcpy(onion_out + 1, e_pub[0], 33);
    memcpy(onion_out + 34, hops_data, HOP_DATA_SIZE);
    memcpy(onion_out + 34 + HOP_DATA_SIZE, next_hmac, HMAC_SIZE);
    return 1;
}

/* ---- Onion peel (relay node) ---- */

int onion_peel(const unsigned char node_priv32[32],
               secp256k1_context *ctx,
               const unsigned char onion_in[ONION_PACKET_SIZE],
               unsigned char onion_out[ONION_PACKET_SIZE],
               onion_hop_payload_t *payload_out,
               int *is_final) {
    if (!node_priv32 || !ctx || !onion_in || !onion_out || !payload_out || !is_final)
        return 0;

    if (onion_in[0] != 0x00) return 0;

    const unsigned char *eph_pub33 = onion_in + 1;
    const unsigned char *hops_data = onion_in + 34;
    const unsigned char *pkt_hmac  = onion_in + 34 + HOP_DATA_SIZE;

    /* Derive shared secret */
    unsigned char ss[32];
    if (!onion_ecdh_shared_secret(ctx, node_priv32, eph_pub33, ss)) return 0;

    /* Derive rho, mu */
    unsigned char rho[32], mu[32];
    bolt4_generate_key("rho", ss, rho);
    bolt4_generate_key("mu",  ss, mu);

    /* Verify HMAC */
    unsigned char mac_input[HOP_DATA_SIZE + 33];
    memcpy(mac_input, hops_data, HOP_DATA_SIZE);
    memcpy(mac_input + HOP_DATA_SIZE, eph_pub33, 33);
    unsigned char expected_hmac[32];
    hmac_sha256(expected_hmac, mu, 32, mac_input, sizeof(mac_input));
    if (memcmp(expected_hmac, pkt_hmac, HMAC_SIZE) != 0) return 0;

    /* Decrypt hops_data */
    unsigned char plain[HOP_DATA_SIZE];
    if (!onion_xor_stream(hops_data, HOP_DATA_SIZE, rho, plain)) return 0;

    /* Parse TLV hop payload from plain */
    /* BigSize(len) at plain[0..] */
    uint64_t plen = 0;
    size_t hdr = 0;
    {
        unsigned char first = plain[0];
        if (first < 0xfd) { plen = first; hdr = 1; }
        else if (first == 0xfd && HOP_DATA_SIZE >= 3) {
            plen = ((uint64_t)plain[1] << 8) | plain[2]; hdr = 3;
        } else return 0;
    }
    if (hdr + plen + HMAC_SIZE > HOP_DATA_SIZE) return 0;

    /* Parse TLV */
    memset(payload_out, 0, sizeof(*payload_out));
    if (!onion_parse_tlv_payload(plain + hdr, (size_t)plen, payload_out))
        return 0;

    /* Determine if we're the final hop: next_hop scid == 0 (TLV type 6 absent) */
    *is_final = (payload_out->has_payment_data != 0);

    /* Build next-hop onion: shift hops_data left, pad with zeros at end */
    size_t hop_total = hdr + (size_t)plen + HMAC_SIZE;
    unsigned char next_hops_data[HOP_DATA_SIZE];
    memset(next_hops_data, 0, HOP_DATA_SIZE);
    if (hop_total < HOP_DATA_SIZE)
        memcpy(next_hops_data, plain + hop_total, HOP_DATA_SIZE - hop_total);

    /* Compute next ephemeral pubkey = e_pub * SHA256(e_pub || ss) */
    unsigned char blend_in[65];
    memcpy(blend_in, eph_pub33, 33);
    memcpy(blend_in + 33, ss, 32);
    unsigned char blinding[32];
    sha256(blend_in, 65, blinding);

    unsigned char next_eph[33];
    secp256k1_pubkey next_epub;
    if (!secp256k1_ec_pubkey_parse(ctx, &next_epub, eph_pub33, 33)) return 0;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &next_epub, blinding)) return 0;
    size_t next_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, next_eph, &next_len,
                                  &next_epub, SECP256K1_EC_COMPRESSED);

    /* Extract next HMAC (was at plain[hdr + plen]) */
    unsigned char next_hmac2[32];
    memcpy(next_hmac2, plain + hdr + (size_t)plen, HMAC_SIZE);

    /* Assemble next onion */
    onion_out[0] = 0x00;
    memcpy(onion_out + 1, next_eph, 33);
    memcpy(onion_out + 34, next_hops_data, HOP_DATA_SIZE);
    memcpy(onion_out + 34 + HOP_DATA_SIZE, next_hmac2, HMAC_SIZE);
    return 1;
}

/* ---- Onion error decryption ---- */

int onion_error_decrypt(const unsigned char (*session_keys)[32], int n_hops,
                        secp256k1_context *ctx,
                        const unsigned char error_onion[256],
                        unsigned char out_plaintext[256],
                        int *out_failing_hop) {
    if (!session_keys || n_hops <= 0 || !ctx || !error_onion ||
        !out_plaintext || !out_failing_hop) return 0;

    *out_failing_hop = -1;

    /* For each hop (from closest to farthest), peel one layer of the error */
    unsigned char cur[256];
    memcpy(cur, error_onion, 256);

    for (int i = 0; i < n_hops; i++) {
        /* Derive ammag (error stream key) from session_key */
        unsigned char ss[32];
        /* The session key IS the shared secret already (built by onion_build) */
        memcpy(ss, session_keys[i], 32);

        unsigned char ammag[32];
        bolt4_generate_key("ammag", ss, ammag);

        /* XOR cur with ChaCha20(ammag) stream of 256 bytes */
        unsigned char stream[256];
        if (!chacha20_stream(ammag, stream, 256)) return 0;
        for (int k = 0; k < 256; k++) cur[k] ^= stream[k];

        /* Check if this layer contains a valid HMAC:
           cur[0..31] = HMAC, cur[32..255] = payload */
        unsigned char um[32];
        bolt4_generate_key("um", ss, um);
        unsigned char check[32];
        hmac_sha256(check, um, 32, cur + 32, 224);
        if (memcmp(check, cur, 32) == 0) {
            *out_failing_hop = i;
            memcpy(out_plaintext, cur + 32, 224);
            return 1;
        }
    }
    /* Could not identify failing hop; return outer plaintext anyway */
    memcpy(out_plaintext, cur + 32, 224);
    return 0;
}
