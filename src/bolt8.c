/*
 * bolt8.c — BOLT #8 Noise_XK_secp256k1_ChaChaPoly_SHA256
 *
 * Differences from noise.c (NK pattern):
 *   - XK: initiator has a static key; 3 DH ops (ee, es, se) vs 2
 *   - Prologue: ASCII string "lightning" per BOLT #8 spec
 *   - Nonce: big-endian 12 bytes (not little-endian)
 *   - Key rotation: every 1000 messages per direction
 *   - Fixed act sizes: 50 / 50 / 66 bytes
 *   - Post-handshake framing: 2-byte BE length + Poly1305 tags
 *
 * All crypto primitives (secp256k1, ChaCha20-Poly1305, HKDF) are
 * reused from the existing library; only wiring is new here.
 */

#include "superscalar/bolt8.h"
#include "superscalar/noise.h"       /* hmac_sha256, hkdf_extract, hkdf_expand */
#include "superscalar/crypto_aead.h"
#include "superscalar/sha256.h"
#include "superscalar/types.h"

#include <secp256k1_ecdh.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

/* --- Internal helpers --- */

/* BOLT #8 HKDF: 2-output derivation.
   (out_ck, out_k) = HKDF(ck, ikm)
   Uses existing hkdf_extract + hkdf_expand(64 bytes, empty info).
   T(1) = HMAC(prk, 0x01)           → out_ck
   T(2) = HMAC(prk, T(1) || 0x02)   → out_k  */
static void bolt8_hkdf2(unsigned char out_ck[32], unsigned char out_k[32],
                         const unsigned char ck[32],
                         const unsigned char *ikm, size_t ikm_len) {
    unsigned char prk[32];
    unsigned char okm[64];
    hkdf_extract(prk, ck, 32, ikm, ikm_len);
    hkdf_expand(okm, 64, prk, NULL, 0);
    memcpy(out_ck, okm, 32);
    memcpy(out_k, okm + 32, 32);
    secure_zero(prk, 32);
    secure_zero(okm, 64);
}

/* h = SHA256(h || data) */
static void mix_hash(unsigned char h[32], const unsigned char *data, size_t len) {
    /* max call: 32 (h) + 49 (encrypted static pub + tag) = 81 bytes — stack safe */
    unsigned char buf[32 + 66];  /* 66 is the max (act3) */
    memcpy(buf, h, 32);
    if (len > 66) {
        /* Fallback for safety — shouldn't happen in BOLT #8 */
        unsigned char *tmp = (unsigned char *)malloc(32 + len);
        if (!tmp) return;
        memcpy(tmp, h, 32);
        memcpy(tmp + 32, data, len);
        sha256(tmp, 32 + len, h);
        free(tmp);
        return;
    }
    memcpy(buf + 32, data, len);
    sha256(buf, 32 + len, h);
}

/* Encode nonce as 12-byte little-endian per BOLT #8:
   4 zero bytes || 8-byte LE counter */
static void bolt8_nonce(unsigned char nonce[12], uint64_t n) {
    nonce[0] = 0; nonce[1] = 0; nonce[2] = 0; nonce[3] = 0;
    nonce[4]  = (unsigned char)(n);
    nonce[5]  = (unsigned char)(n >>  8);
    nonce[6]  = (unsigned char)(n >> 16);
    nonce[7]  = (unsigned char)(n >> 24);
    nonce[8]  = (unsigned char)(n >> 32);
    nonce[9]  = (unsigned char)(n >> 40);
    nonce[10] = (unsigned char)(n >> 48);
    nonce[11] = (unsigned char)(n >> 56);
}

/* AEAD_Encrypt(key, nonce_counter, aad=h, plaintext) → ciphertext || tag
   out_buf must be pt_len + 16 bytes. */
static int b8_encrypt(unsigned char *out_buf,
                       const unsigned char key[32], uint64_t n,
                       const unsigned char *aad, size_t aad_len,
                       const unsigned char *pt, size_t pt_len) {
    unsigned char nonce[12];
    bolt8_nonce(nonce, n);
    return aead_encrypt(out_buf, out_buf + pt_len,
                        pt, pt_len, aad, aad_len, key, nonce);
}

/* AEAD_Decrypt(key, nonce_counter, aad=h, ciphertext || tag) → plaintext
   in_buf is ct_len + 16 bytes (tag at in_buf + ct_len). */
static int b8_decrypt(unsigned char *out_pt,
                       const unsigned char key[32], uint64_t n,
                       const unsigned char *aad, size_t aad_len,
                       const unsigned char *in_buf, size_t ct_len) {
    unsigned char nonce[12];
    bolt8_nonce(nonce, n);
    return aead_decrypt(out_pt, in_buf, ct_len, in_buf + ct_len,
                        aad, aad_len, key, nonce);
}

/* Serialize a secp256k1 pubkey to 33-byte compressed format */
static int pub_serialize(secp256k1_context *ctx,
                          unsigned char out33[33],
                          const secp256k1_pubkey *pub) {
    size_t len = 33;
    return secp256k1_ec_pubkey_serialize(ctx, out33, &len, pub,
                                          SECP256K1_EC_COMPRESSED);
}

/* ECDH then derive new (ck, temp_k) from the result */
static int dh_and_mix(unsigned char ck[32], unsigned char temp_k[32],
                       secp256k1_context *ctx,
                       const secp256k1_pubkey *pub,
                       const unsigned char priv32[32]) {
    unsigned char shared[32];
    if (!secp256k1_ecdh(ctx, shared, pub, priv32, NULL, NULL)) {
        secure_zero(shared, 32);
        return 0;
    }
    bolt8_hkdf2(ck, temp_k, ck, shared, 32);
    secure_zero(shared, 32);
    return 1;
}

/* --- Handshake initialization --- */

void bolt8_hs_init(bolt8_hs_t *hs, const unsigned char rs_pub33[33]) {
    static const char *protocol_name =
        "Noise_XK_secp256k1_ChaChaPoly_SHA256";

    /* h = SHA256(protocol_name) */
    sha256((const unsigned char *)protocol_name,
           strlen(protocol_name), hs->h);

    /* ck = h */
    memcpy(hs->ck, hs->h, 32);

    /* h = SHA256(h || prologue)  where prologue = "lightning" per BOLT #8 spec */
    mix_hash(hs->h, (const unsigned char *)"lightning", 9);

    /* h = SHA256(h || rs.pub) — mix in responder's static pubkey */
    mix_hash(hs->h, rs_pub33, 33);

    memset(hs->temp_k, 0, 32);
    memset(hs->re_pub, 0, 33);
    memset(hs->e_priv, 0, 32);
}

/* --- Act 1 --- */

int bolt8_act1_create(bolt8_hs_t *hs, secp256k1_context *ctx,
                      const unsigned char e_priv32[32],
                      const unsigned char rs_pub33[33],
                      unsigned char act1_out[BOLT8_ACT1_SIZE]) {
    if (!hs || !ctx || !e_priv32 || !rs_pub33 || !act1_out) return 0;

    /* Derive e.pub from e.priv */
    secp256k1_pubkey e_pub;
    if (!secp256k1_ec_pubkey_create(ctx, &e_pub, e_priv32)) return 0;

    unsigned char e_pub33[33];
    if (!pub_serialize(ctx, e_pub33, &e_pub)) return 0;

    /* h = SHA256(h || e.pub) */
    mix_hash(hs->h, e_pub33, 33);

    /* es DH: ECDH(e.priv, rs.pub) → derive (ck, temp_k1) */
    secp256k1_pubkey rs_pub;
    if (!secp256k1_ec_pubkey_parse(ctx, &rs_pub, rs_pub33, 33)) return 0;

    if (!dh_and_mix(hs->ck, hs->temp_k, ctx, &rs_pub, e_priv32)) return 0;

    /* c = AEAD_Encrypt(temp_k1, n=0, h, b"") → 16-byte tag only */
    unsigned char c[16];
    if (!b8_encrypt(c, hs->temp_k, 0, hs->h, 32, NULL, 0)) return 0;

    /* h = SHA256(h || c) */
    mix_hash(hs->h, c, 16);

    /* Build act1: version(1) || e.pub(33) || c(16) */
    act1_out[0] = 0x00;
    memcpy(act1_out + 1, e_pub33, 33);
    memcpy(act1_out + 34, c, 16);

    /* Store e.priv for act2_process (ee DH) */
    memcpy(hs->e_priv, e_priv32, 32);

    return 1;
}

int bolt8_act1_process(bolt8_hs_t *hs, secp256k1_context *ctx,
                       const unsigned char act1_in[BOLT8_ACT1_SIZE],
                       const unsigned char rs_priv32[32]) {
    if (!hs || !ctx || !act1_in || !rs_priv32) return 0;

    /* Version must be 0 */
    if (act1_in[0] != 0x00) return 0;

    const unsigned char *re_pub33 = act1_in + 1;
    const unsigned char *c        = act1_in + 34;

    /* Parse initiator's ephemeral pubkey */
    secp256k1_pubkey re_pub;
    if (!secp256k1_ec_pubkey_parse(ctx, &re_pub, re_pub33, 33)) return 0;

    /* h = SHA256(h || re.pub) */
    mix_hash(hs->h, re_pub33, 33);

    /* es DH: ECDH(rs.priv, re.pub) → derive (ck, temp_k1) */
    if (!dh_and_mix(hs->ck, hs->temp_k, ctx, &re_pub, rs_priv32)) return 0;

    /* Verify c: AEAD_Decrypt(temp_k1, n=0, h, c) → empty plaintext + tag check */
    if (!b8_decrypt(NULL, hs->temp_k, 0, hs->h, 32, c, 0)) return 0;

    /* h = SHA256(h || c) */
    mix_hash(hs->h, c, 16);

    /* Store initiator's ephemeral pubkey for act2_create (ee DH) */
    memcpy(hs->re_pub, re_pub33, 33);

    return 1;
}

/* --- Act 2 --- */

int bolt8_act2_create(bolt8_hs_t *hs, secp256k1_context *ctx,
                      const unsigned char e_priv32[32],
                      unsigned char act2_out[BOLT8_ACT2_SIZE]) {
    if (!hs || !ctx || !e_priv32 || !act2_out) return 0;

    /* Derive e.pub from e.priv */
    secp256k1_pubkey e_pub;
    if (!secp256k1_ec_pubkey_create(ctx, &e_pub, e_priv32)) return 0;

    unsigned char e_pub33[33];
    if (!pub_serialize(ctx, e_pub33, &e_pub)) return 0;

    /* h = SHA256(h || e.pub) */
    mix_hash(hs->h, e_pub33, 33);

    /* ee DH: ECDH(e.priv_responder, re.pub_initiator) → derive (ck, temp_k2) */
    secp256k1_pubkey re_pub;
    if (!secp256k1_ec_pubkey_parse(ctx, &re_pub, hs->re_pub, 33)) return 0;

    if (!dh_and_mix(hs->ck, hs->temp_k, ctx, &re_pub, e_priv32)) return 0;

    /* c = AEAD_Encrypt(temp_k2, n=0, h, b"") → 16-byte tag */
    unsigned char c[16];
    if (!b8_encrypt(c, hs->temp_k, 0, hs->h, 32, NULL, 0)) return 0;

    /* h = SHA256(h || c) */
    mix_hash(hs->h, c, 16);

    /* Build act2: version(1) || e.pub(33) || c(16) */
    act2_out[0] = 0x00;
    memcpy(act2_out + 1, e_pub33, 33);
    memcpy(act2_out + 34, c, 16);

    /* Store e.priv for act3_process (se DH) */
    memcpy(hs->e_priv, e_priv32, 32);

    return 1;
}

int bolt8_act2_process(bolt8_hs_t *hs, secp256k1_context *ctx,
                       const unsigned char act2_in[BOLT8_ACT2_SIZE]) {
    if (!hs || !ctx || !act2_in) return 0;

    /* Version must be 0 */
    if (act2_in[0] != 0x00) return 0;

    const unsigned char *re_pub33 = act2_in + 1;
    const unsigned char *c        = act2_in + 34;

    /* Parse responder's ephemeral pubkey */
    secp256k1_pubkey re_pub;
    if (!secp256k1_ec_pubkey_parse(ctx, &re_pub, re_pub33, 33)) return 0;

    /* h = SHA256(h || re.pub) */
    mix_hash(hs->h, re_pub33, 33);

    /* ee DH: ECDH(e.priv_initiator, re.pub_responder) → derive (ck, temp_k2)
       hs->e_priv was set during act1_create */
    if (!dh_and_mix(hs->ck, hs->temp_k, ctx, &re_pub, hs->e_priv)) return 0;

    /* Verify c: AEAD_Decrypt(temp_k2, n=0, h, c) */
    if (!b8_decrypt(NULL, hs->temp_k, 0, hs->h, 32, c, 0)) return 0;

    /* h = SHA256(h || c) */
    mix_hash(hs->h, c, 16);

    /* Store responder's ephemeral pubkey for act3_create (se DH) */
    memcpy(hs->re_pub, re_pub33, 33);

    return 1;
}

/* --- Act 3 --- */

int bolt8_act3_create(bolt8_hs_t *hs, secp256k1_context *ctx,
                      const unsigned char s_priv32[32],
                      unsigned char act3_out[BOLT8_ACT3_SIZE],
                      bolt8_state_t *state_out) {
    if (!hs || !ctx || !s_priv32 || !act3_out || !state_out) return 0;

    /* Derive s.pub from s.priv */
    secp256k1_pubkey s_pub;
    if (!secp256k1_ec_pubkey_create(ctx, &s_pub, s_priv32)) return 0;

    unsigned char s_pub33[33];
    if (!pub_serialize(ctx, s_pub33, &s_pub)) return 0;

    /* c = AEAD_Encrypt(temp_k2, n=1, h, s.pub) → 33 cipher + 16 tag = 49 bytes */
    unsigned char c[49];
    if (!b8_encrypt(c, hs->temp_k, 1, hs->h, 32, s_pub33, 33)) return 0;

    /* h = SHA256(h || c) */
    mix_hash(hs->h, c, 49);

    /* se DH: ECDH(s.priv_initiator, re.pub_responder) → derive (ck, temp_k3)
       hs->re_pub was set during act2_process */
    secp256k1_pubkey re_pub;
    if (!secp256k1_ec_pubkey_parse(ctx, &re_pub, hs->re_pub, 33)) return 0;

    if (!dh_and_mix(hs->ck, hs->temp_k, ctx, &re_pub, s_priv32)) return 0;

    /* t = AEAD_Encrypt(temp_k3, n=0, h, b"") → 16-byte tag */
    unsigned char t[16];
    if (!b8_encrypt(t, hs->temp_k, 0, hs->h, 32, NULL, 0)) return 0;

    /* Build act3: version(1) || c(49) || t(16) */
    act3_out[0] = 0x00;
    memcpy(act3_out + 1, c, 49);
    memcpy(act3_out + 50, t, 16);

    /* Final transport key derivation: (sk, rk) = HKDF(ck, b"") */
    bolt8_hkdf2(state_out->sk, state_out->rk, hs->ck, NULL, 0);
    memcpy(state_out->ck, hs->ck, 32);
    state_out->sn = 0;
    state_out->rn = 0;

    /* Clear sensitive data */
    secure_zero(hs->e_priv, 32);
    secure_zero(hs->temp_k, 32);
    secure_zero(c, 49);

    return 1;
}

int bolt8_act3_process(bolt8_hs_t *hs, secp256k1_context *ctx,
                       const unsigned char act3_in[BOLT8_ACT3_SIZE],
                       bolt8_state_t *state_out) {
    if (!hs || !ctx || !act3_in || !state_out) return 0;

    /* Version must be 0 */
    if (act3_in[0] != 0x00) return 0;

    const unsigned char *c = act3_in + 1;   /* 49 bytes: encrypted s.pub + tag */
    const unsigned char *t = act3_in + 50;  /* 16 bytes: final tag */

    /* Decrypt initiator's static pubkey: AEAD_Decrypt(temp_k2, n=1, h, c) */
    unsigned char is_pub33[33];
    if (!b8_decrypt(is_pub33, hs->temp_k, 1, hs->h, 32, c, 33)) return 0;

    /* h = SHA256(h || c) */
    mix_hash(hs->h, c, 49);

    /* se DH: ECDH(e.priv_responder, is.pub_initiator) → derive (ck, temp_k3)
       hs->e_priv was set during act2_create */
    secp256k1_pubkey is_pub;
    if (!secp256k1_ec_pubkey_parse(ctx, &is_pub, is_pub33, 33)) {
        secure_zero(is_pub33, 33);
        return 0;
    }

    if (!dh_and_mix(hs->ck, hs->temp_k, ctx, &is_pub, hs->e_priv)) {
        secure_zero(is_pub33, 33);
        return 0;
    }

    /* Verify t: AEAD_Decrypt(temp_k3, n=0, h, t) */
    if (!b8_decrypt(NULL, hs->temp_k, 0, hs->h, 32, t, 0)) {
        secure_zero(is_pub33, 33);
        return 0;
    }

    /* Final transport key derivation: responder gets (rk, sk) = HKDF(ck, b"")
       (first output is initiator's send key = responder's recv key) */
    bolt8_hkdf2(state_out->rk, state_out->sk, hs->ck, NULL, 0);
    memcpy(state_out->ck, hs->ck, 32);
    state_out->sn = 0;
    state_out->rn = 0;

    /* Clear sensitive data */
    secure_zero(hs->e_priv, 32);
    secure_zero(hs->temp_k, 32);
    secure_zero(is_pub33, 33);

    return 1;
}

/* --- Key rotation --- */

static void rotate_key(unsigned char ck[32], unsigned char key[32]) {
    /* (ck, key) = HKDF(ck, key) */
    unsigned char new_ck[32], new_key[32];
    bolt8_hkdf2(new_ck, new_key, ck, key, 32);
    memcpy(ck, new_ck, 32);
    memcpy(key, new_key, 32);
    secure_zero(new_ck, 32);
    secure_zero(new_key, 32);
}

/* --- Post-handshake message framing --- */

int bolt8_write_message(bolt8_state_t *state,
                        const unsigned char *msg, size_t msg_len,
                        unsigned char *out_buf) {
    if (!state || !msg || !out_buf) return 0;
    if (msg_len > 65535) return 0;  /* BOLT #8 length field is 2 bytes */

    /* Rotate send key if at 1000 messages; reset nonce per BOLT #8 spec */
    if (state->sn == 1000) {
        rotate_key(state->ck, state->sk);
        state->sn = 0;
    }

    unsigned char nonce[12];
    unsigned char len_be[2];
    len_be[0] = (unsigned char)(msg_len >> 8);
    len_be[1] = (unsigned char)(msg_len);

    /* Encrypt length: AEAD(sk, sn, b"", len_be) → 2 + 16 bytes */
    bolt8_nonce(nonce, state->sn);
    if (!aead_encrypt(out_buf, out_buf + 2,
                      len_be, 2, NULL, 0, state->sk, nonce)) return 0;
    state->sn++;

    /* Encrypt message body: AEAD(sk, sn+1, b"", msg) → msg_len + 16 bytes */
    bolt8_nonce(nonce, state->sn);
    if (!aead_encrypt(out_buf + 18, out_buf + 18 + msg_len,
                      msg, msg_len, NULL, 0, state->sk, nonce)) return 0;
    state->sn++;

    return 1;
}

int bolt8_read_message(bolt8_state_t *state,
                       const unsigned char *in_buf, size_t total_len,
                       unsigned char *out_msg, size_t *out_msg_len) {
    if (!state || !in_buf || !out_msg || !out_msg_len) return 0;
    if (total_len < 18 + 16) return 0;  /* minimum: 18 header + 16 body tag */

    /* Rotate recv key if at 1000 messages; reset nonce per BOLT #8 spec */
    if (state->rn == 1000) {
        rotate_key(state->ck, state->rk);
        state->rn = 0;
    }

    unsigned char nonce[12];
    unsigned char len_be[2];

    /* Decrypt length: AEAD(rk, rn, b"", header[18]) → 2 bytes */
    bolt8_nonce(nonce, state->rn);
    if (!aead_decrypt(len_be, in_buf, 2, in_buf + 2,
                      NULL, 0, state->rk, nonce)) return 0;
    state->rn++;

    size_t msg_len = ((size_t)len_be[0] << 8) | len_be[1];
    if (total_len < 18 + msg_len + 16) return 0;  /* buffer too small */

    /* Decrypt message: AEAD(rk, rn+1, b"", body) → msg_len bytes */
    bolt8_nonce(nonce, state->rn);
    if (!aead_decrypt(out_msg, in_buf + 18, msg_len, in_buf + 18 + msg_len,
                      NULL, 0, state->rk, nonce)) return 0;
    state->rn++;

    *out_msg_len = msg_len;
    return 1;
}

/* --- I/O wrappers --- */

static int b8_write_all(int fd, const unsigned char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n <= 0) return 0;
        sent += (size_t)n;
    }
    return 1;
}

static int b8_read_all(int fd, unsigned char *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) return 0;
        got += (size_t)n;
    }
    return 1;
}

int bolt8_send(bolt8_state_t *state, int fd,
               const unsigned char *msg, size_t msg_len) {
    if (!state || fd < 0 || !msg) return 0;
    if (msg_len > 65535) return 0;

    size_t buf_len = msg_len + BOLT8_MSG_OVERHEAD;
    unsigned char *buf = (unsigned char *)malloc(buf_len);
    if (!buf) return 0;

    int ok = bolt8_write_message(state, msg, msg_len, buf)
             && b8_write_all(fd, buf, buf_len);

    secure_zero(buf, buf_len);
    free(buf);
    return ok;
}

int bolt8_recv(bolt8_state_t *state, int fd,
               unsigned char *out_msg, size_t *out_msg_len, size_t max_len) {
    if (!state || fd < 0 || !out_msg || !out_msg_len) return 0;

    /* Read 18-byte header (2-byte encrypted length + 16-byte tag) */
    unsigned char header[18];
    if (!b8_read_all(fd, header, 18)) return 0;

    /* Rotate recv key if at 1000 messages; reset nonce per BOLT #8 spec */
    if (state->rn == 1000) {
        rotate_key(state->ck, state->rk);
        state->rn = 0;
    }

    /* Decrypt length: AEAD(rk, rn, b"", header) → 2 bytes */
    unsigned char nonce[12];
    unsigned char len_be[2];
    bolt8_nonce(nonce, state->rn);
    if (!aead_decrypt(len_be, header, 2, header + 2,
                      NULL, 0, state->rk, nonce)) return 0;
    state->rn++;

    size_t msg_len = ((size_t)len_be[0] << 8) | len_be[1];
    if (msg_len > max_len) return 0;  /* connection unrecoverable past this point */

    /* Read body (msg_len + 16-byte tag) */
    size_t body_len = msg_len + 16;
    unsigned char *body = (unsigned char *)malloc(body_len);
    if (!body) return 0;

    if (!b8_read_all(fd, body, body_len)) {
        free(body);
        return 0;
    }

    /* Decrypt body: AEAD(rk, rn+1, b"", body) → msg_len bytes */
    bolt8_nonce(nonce, state->rn);
    if (!aead_decrypt(out_msg, body, msg_len, body + msg_len,
                      NULL, 0, state->rk, nonce)) {
        secure_zero(body, body_len);
        free(body);
        return 0;
    }
    state->rn++;

    secure_zero(body, body_len);
    free(body);
    *out_msg_len = msg_len;
    return 1;
}

/* --- Outbound connection helper --- */

static void set_socket_timeout_ms(int fd, int ms) {
    struct timeval tv;
    tv.tv_sec  = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

int bolt8_connect(int fd,
                  secp256k1_context *ctx,
                  const unsigned char our_priv32[32],
                  const unsigned char their_pub33[33],
                  int timeout_ms,
                  bolt8_state_t *state_out) {
    if (fd < 0 || !ctx || !our_priv32 || !their_pub33 || !state_out) return 0;

    bolt8_hs_t hs;
    bolt8_hs_init(&hs, their_pub33);

    /* Generate ephemeral key for act1 */
    unsigned char e_priv[32];
    FILE *rnd = fopen("/dev/urandom", "rb");
    if (!rnd || fread(e_priv, 1, 32, rnd) != 32) {
        if (rnd) fclose(rnd);
        return 0;
    }
    fclose(rnd);

    /* Act 1: build and send */
    set_socket_timeout_ms(fd, timeout_ms);
    unsigned char act1[BOLT8_ACT1_SIZE];
    if (!bolt8_act1_create(&hs, ctx, e_priv, their_pub33, act1)) {
        secure_zero(e_priv, 32);
        return 0;
    }
    secure_zero(e_priv, 32);

    ssize_t n = write(fd, act1, BOLT8_ACT1_SIZE);
    if (n != BOLT8_ACT1_SIZE) return 0;

    /* Act 2: read from responder */
    unsigned char act2[BOLT8_ACT2_SIZE];
    {
        size_t got = 0;
        while (got < BOLT8_ACT2_SIZE) {
            ssize_t r = read(fd, act2 + got, BOLT8_ACT2_SIZE - got);
            if (r <= 0) return 0;
            got += (size_t)r;
        }
    }
    if (!bolt8_act2_process(&hs, ctx, act2)) return 0;

    /* Act 3: build and send */
    unsigned char act3[BOLT8_ACT3_SIZE];
    if (!bolt8_act3_create(&hs, ctx, our_priv32, act3, state_out)) return 0;

    n = write(fd, act3, BOLT8_ACT3_SIZE);
    if (n != BOLT8_ACT3_SIZE) {
        secure_zero(state_out, sizeof(*state_out));
        return 0;
    }

    /* Reset to blocking (no timeout) after successful handshake */
    set_socket_timeout_ms(fd, 0);

    return 1;
}
