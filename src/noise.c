/* ECDH handshake + HMAC-SHA256/HKDF + per-fd encryption state */
#include "superscalar/noise.h"
#include "superscalar/types.h"
#include <secp256k1_ecdh.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

extern void sha256(const unsigned char *, size_t, unsigned char *);

/* --- HMAC-SHA256 (RFC 2104) --- */

void hmac_sha256(unsigned char out[32], const unsigned char *key, size_t key_len,
                 const unsigned char *data, size_t data_len) {
    unsigned char k_pad[64];
    unsigned char i_pad[64];
    unsigned char o_pad[64];

    /* If key > 64 bytes, hash it first */
    unsigned char key_hash[32];
    if (key_len > 64) {
        sha256(key, key_len, key_hash);
        key = key_hash;
        key_len = 32;
    }

    memset(k_pad, 0, 64);
    memcpy(k_pad, key, key_len);

    for (int i = 0; i < 64; i++) {
        i_pad[i] = k_pad[i] ^ 0x36;
        o_pad[i] = k_pad[i] ^ 0x5c;
    }

    /* inner = SHA256(i_pad || data)
       Stack buffer covers all callers (max ~97 bytes data). */
    size_t inner_len = 64 + data_len;
    unsigned char inner_stack[256];
    unsigned char *inner_buf = (inner_len <= sizeof(inner_stack))
        ? inner_stack : (unsigned char *)malloc(inner_len);
    memcpy(inner_buf, i_pad, 64);
    memcpy(inner_buf + 64, data, data_len);
    unsigned char inner_hash[32];
    sha256(inner_buf, inner_len, inner_hash);
    if (inner_buf != inner_stack) free(inner_buf);

    /* outer = SHA256(o_pad || inner_hash) */
    unsigned char outer_buf[64 + 32];
    memcpy(outer_buf, o_pad, 64);
    memcpy(outer_buf + 64, inner_hash, 32);
    sha256(outer_buf, 96, out);

    secure_zero(k_pad, 64);
    secure_zero(i_pad, 64);
    secure_zero(o_pad, 64);
}

/* --- HKDF (RFC 5869) --- */

void hkdf_extract(unsigned char prk[32], const unsigned char *salt, size_t salt_len,
                  const unsigned char *ikm, size_t ikm_len) {
    if (salt == NULL || salt_len == 0) {
        unsigned char zero_salt[32];
        memset(zero_salt, 0, 32);
        hmac_sha256(prk, zero_salt, 32, ikm, ikm_len);
    } else {
        hmac_sha256(prk, salt, salt_len, ikm, ikm_len);
    }
}

void hkdf_expand(unsigned char *okm, size_t okm_len,
                 const unsigned char prk[32],
                 const unsigned char *info, size_t info_len) {
    size_t n = (okm_len + 31) / 32;
    unsigned char t[32];
    size_t t_len = 0;
    size_t off = 0;

    for (size_t i = 1; i <= n; i++) {
        /* T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
           Stack buffer covers all callers (max ~50 bytes input). */
        size_t input_len = t_len + info_len + 1;
        unsigned char input_stack[128];
        unsigned char *input = (input_len <= sizeof(input_stack))
            ? input_stack : (unsigned char *)malloc(input_len);
        if (t_len > 0)
            memcpy(input, t, t_len);
        memcpy(input + t_len, info, info_len);
        input[t_len + info_len] = (unsigned char)i;

        hmac_sha256(t, prk, 32, input, input_len);
        if (input != input_stack) free(input);
        t_len = 32;

        size_t chunk = okm_len - off;
        if (chunk > 32) chunk = 32;
        memcpy(okm + off, t, chunk);
        off += chunk;
    }
}

/* --- Low-level I/O helpers (replicated to avoid circular deps with wire.c) --- */

static int noise_write_all(int fd, const unsigned char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n <= 0) return 0;
        sent += (size_t)n;
    }
    return 1;
}

static int noise_read_all(int fd, unsigned char *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) return 0;
        got += (size_t)n;
    }
    return 1;
}

/* --- Per-fd encryption state table (dynamically grown) --- */

#define FD_TABLE_INITIAL_CAP 16

typedef struct {
    int fd;
    noise_state_t state;
    int active;
    int requires_encryption;  /* set once handshake is attempted */
} fd_noise_entry_t;

static fd_noise_entry_t *fd_table = NULL;
static int fd_table_cap = 0;
static int fd_table_inited = 0;

static int ensure_fd_table(void) {
    if (!fd_table_inited) {
        fd_table_cap = FD_TABLE_INITIAL_CAP;
        fd_table = (fd_noise_entry_t *)calloc((size_t)fd_table_cap,
                                               sizeof(fd_noise_entry_t));
        if (!fd_table) {
            fprintf(stderr, "noise: initial fd table alloc failed\n");
            fd_table_cap = 0;
            return 0;
        }
        for (int i = 0; i < fd_table_cap; i++)
            fd_table[i].fd = -1;
        fd_table_inited = 1;
    }
    return 1;
}

/* Double the table capacity */
static int grow_fd_table(void) {
    int new_cap = fd_table_cap * 2;
    fd_noise_entry_t *new_table = (fd_noise_entry_t *)calloc((size_t)new_cap,
                                                              sizeof(fd_noise_entry_t));
    if (!new_table) return 0;
    for (int i = 0; i < new_cap; i++)
        new_table[i].fd = -1;
    memcpy(new_table, fd_table, (size_t)fd_table_cap * sizeof(fd_noise_entry_t));
    free(fd_table);
    fd_table = new_table;
    fd_table_cap = new_cap;
    return 1;
}

int wire_set_encryption(int fd, const noise_state_t *ns) {
    if (!ensure_fd_table()) return 0;
    /* Find existing entry (active or placeholder from wire_mark_encryption_required) */
    int free_slot = -1;
    for (int i = 0; i < fd_table_cap; i++) {
        if (fd_table[i].fd == fd) {
            /* Reuse this slot — preserves requires_encryption flag */
            fd_table[i].state = *ns;
            fd_table[i].active = 1;
            return 1;
        }
        if (!fd_table[i].active && fd_table[i].fd == -1 && free_slot < 0)
            free_slot = i;
    }
    if (free_slot < 0) {
        free_slot = fd_table_cap;
        if (!grow_fd_table()) {
            fprintf(stderr, "noise: fd table grow failed\n");
            return 0;
        }
    }
    fd_table[free_slot].fd = fd;
    fd_table[free_slot].state = *ns;
    fd_table[free_slot].active = 1;
    return 1;
}

void wire_clear_encryption(int fd) {
    if (!ensure_fd_table()) return;
    for (int i = 0; i < fd_table_cap; i++) {
        if (fd_table[i].fd == fd) {
            if (fd_table[i].active)
                secure_zero(&fd_table[i].state, sizeof(noise_state_t));
            fd_table[i].active = 0;
            fd_table[i].requires_encryption = 0;
            fd_table[i].fd = -1;
            return;
        }
    }
}

noise_state_t *wire_get_encryption(int fd) {
    if (!ensure_fd_table()) return NULL;
    for (int i = 0; i < fd_table_cap; i++) {
        if (fd_table[i].active && fd_table[i].fd == fd)
            return &fd_table[i].state;
    }
    return NULL;
}

int wire_mark_encryption_required(int fd) {
    if (!ensure_fd_table()) return 0;
    /* Mark in existing entry if present, otherwise allocate a slot */
    for (int i = 0; i < fd_table_cap; i++) {
        if (fd_table[i].fd == fd) {
            fd_table[i].requires_encryption = 1;
            return 1;
        }
    }
    /* No entry yet — create a placeholder (active=0 but flag set) */
    for (int i = 0; i < fd_table_cap; i++) {
        if (!fd_table[i].active && fd_table[i].fd == -1) {
            fd_table[i].fd = fd;
            fd_table[i].requires_encryption = 1;
            return 1;
        }
    }
    /* Table full — grow and set */
    if (!grow_fd_table()) {
        fprintf(stderr, "noise: fd table grow failed, refusing connection\n");
        return 0;
    }
    for (int i = 0; i < fd_table_cap; i++) {
        if (fd_table[i].fd == -1) {
            fd_table[i].fd = fd;
            fd_table[i].requires_encryption = 1;
            return 1;
        }
    }
    return 0;
}

int wire_is_encryption_required(int fd) {
    if (!ensure_fd_table()) return 1;  /* fail safe: require encryption */
    for (int i = 0; i < fd_table_cap; i++) {
        if (fd_table[i].fd == fd)
            return fd_table[i].requires_encryption;
    }
    return 0;
}

/* --- Handshake --- */

/* Derive symmetric keys from ECDH shared secret.
   Initiator uses: send_key="initiator", recv_key="responder"
   Responder swaps them. */
static void derive_keys(noise_state_t *ns, const unsigned char shared[32],
                         int is_initiator) {
    /* prk = HKDF-Extract(salt="superscalar-v1", ikm=shared) */
    unsigned char prk[32];
    const char *salt = "superscalar-v1";
    hkdf_extract(prk, (const unsigned char *)salt, strlen(salt), shared, 32);

    unsigned char key_init[32], key_resp[32];
    const char *info_init = "initiator";
    const char *info_resp = "responder";
    hkdf_expand(key_init, 32, prk, (const unsigned char *)info_init, strlen(info_init));
    hkdf_expand(key_resp, 32, prk, (const unsigned char *)info_resp, strlen(info_resp));

    if (is_initiator) {
        memcpy(ns->send_key, key_init, 32);
        memcpy(ns->recv_key, key_resp, 32);
    } else {
        memcpy(ns->send_key, key_resp, 32);
        memcpy(ns->recv_key, key_init, 32);
    }
    ns->send_nonce = 0;
    ns->recv_nonce = 0;

    secure_zero(prk, 32);
    secure_zero(key_init, 32);
    secure_zero(key_resp, 32);
}

/*
 * SECURITY NOTE — Noise NN pattern (no server authentication)
 *
 * The NN handshake provides forward-secret encryption but does NOT
 * authenticate either party.  A network-level attacker can MITM the
 * connection by intercepting both ephemeral key exchanges.
 *
 * Mitigations (deploy at least one):
 *   1. Run over Tor hidden services (`.onion`) — Tor provides
 *      authentication + encryption at the transport layer.
 *   2. Pin the server's static key out-of-band and upgrade to the
 *      NK or XX Noise pattern (future protocol change).
 *   3. Use an authenticated tunnel (WireGuard, SSH port-forward).
 *
 * For the current PoC the NN pattern is acceptable because the
 * factory protocol itself uses adaptor signatures that bind to
 * long-lived on-chain keys, limiting what a MITM can achieve.
 */
int noise_handshake_initiator(noise_state_t *ns, int fd,
                               secp256k1_context *ctx) {
    /* Generate ephemeral keypair */
    unsigned char eph_sec[32];
    secp256k1_pubkey eph_pub;

    /* Use randomness from /dev/urandom */
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 0;
    if (fread(eph_sec, 1, 32, f) != 32) { fclose(f); return 0; }
    fclose(f);

    if (!secp256k1_ec_seckey_verify(ctx, eph_sec)) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &eph_pub, eph_sec)) return 0;

    /* Send our ephemeral pubkey (33 bytes compressed) */
    unsigned char pub_ser[33];
    size_t pub_len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, pub_ser, &pub_len, &eph_pub,
                                        SECP256K1_EC_COMPRESSED)) {
        secure_zero(eph_sec, 32);
        return 0;
    }
    if (!noise_write_all(fd, pub_ser, 33)) {
        secure_zero(eph_sec, 32);
        return 0;
    }

    /* Receive responder's ephemeral pubkey */
    unsigned char remote_ser[33];
    if (!noise_read_all(fd, remote_ser, 33)) {
        secure_zero(eph_sec, 32);
        return 0;
    }
    secp256k1_pubkey remote_pub;
    if (!secp256k1_ec_pubkey_parse(ctx, &remote_pub, remote_ser, 33)) {
        secure_zero(eph_sec, 32);
        return 0;
    }

    /* ECDH */
    unsigned char shared[32];
    if (!secp256k1_ecdh(ctx, shared, &remote_pub, eph_sec, NULL, NULL)) {
        secure_zero(eph_sec, 32);
        return 0;
    }

    /* Derive symmetric keys */
    derive_keys(ns, shared, 1);

    secure_zero(eph_sec, 32);
    secure_zero(shared, 32);
    return 1;
}

int noise_handshake_responder(noise_state_t *ns, int fd,
                               secp256k1_context *ctx) {
    /* Receive initiator's ephemeral pubkey */
    unsigned char remote_ser[33];
    if (!noise_read_all(fd, remote_ser, 33)) return 0;

    secp256k1_pubkey remote_pub;
    if (!secp256k1_ec_pubkey_parse(ctx, &remote_pub, remote_ser, 33))
        return 0;

    /* Generate our ephemeral keypair */
    unsigned char eph_sec[32];
    secp256k1_pubkey eph_pub;

    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 0;
    if (fread(eph_sec, 1, 32, f) != 32) { fclose(f); return 0; }
    fclose(f);

    if (!secp256k1_ec_seckey_verify(ctx, eph_sec)) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &eph_pub, eph_sec)) return 0;

    /* Send our ephemeral pubkey */
    unsigned char pub_ser[33];
    size_t pub_len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, pub_ser, &pub_len, &eph_pub,
                                        SECP256K1_EC_COMPRESSED)) {
        secure_zero(eph_sec, 32);
        return 0;
    }
    if (!noise_write_all(fd, pub_ser, 33)) {
        secure_zero(eph_sec, 32);
        return 0;
    }

    /* ECDH */
    unsigned char shared[32];
    if (!secp256k1_ecdh(ctx, shared, &remote_pub, eph_sec, NULL, NULL)) {
        secure_zero(eph_sec, 32);
        return 0;
    }

    /* Derive symmetric keys (is_initiator=0, so keys swapped) */
    derive_keys(ns, shared, 0);

    secure_zero(eph_sec, 32);
    secure_zero(shared, 32);
    return 1;
}
