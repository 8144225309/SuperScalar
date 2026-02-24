#ifndef SUPERSCALAR_NOISE_H
#define SUPERSCALAR_NOISE_H

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>

/* Per-connection encryption state (after successful handshake) */
typedef struct {
    unsigned char send_key[32];
    unsigned char recv_key[32];
    uint64_t send_nonce;       /* incremented per message */
    uint64_t recv_nonce;
} noise_state_t;

/* Perform ECDH handshake as initiator (client side).
   Generates ephemeral keypair, sends pubkey, receives remote pubkey,
   derives symmetric keys via HKDF.
   Returns 1 on success, 0 on failure. */
int noise_handshake_initiator(noise_state_t *ns, int fd,
                               secp256k1_context *ctx);

/* Perform ECDH handshake as responder (LSP side).
   Receives initiator pubkey, generates ephemeral keypair, sends pubkey,
   derives symmetric keys via HKDF.
   Returns 1 on success, 0 on failure. */
int noise_handshake_responder(noise_state_t *ns, int fd,
                               secp256k1_context *ctx);

/* Register encryption state for an fd.
   After this, wire_send/wire_recv on this fd will encrypt/decrypt. */
void wire_set_encryption(int fd, const noise_state_t *ns);

/* Clear encryption state for an fd. */
void wire_clear_encryption(int fd);

/* Look up noise state for an fd. Returns NULL if none registered. */
noise_state_t *wire_get_encryption(int fd);

/* Crypto primitives used by handshake */
void hmac_sha256(unsigned char out[32], const unsigned char *key, size_t key_len,
                 const unsigned char *data, size_t data_len);
void hkdf_extract(unsigned char prk[32], const unsigned char *salt, size_t salt_len,
                  const unsigned char *ikm, size_t ikm_len);
void hkdf_expand(unsigned char *okm, size_t okm_len,
                 const unsigned char prk[32],
                 const unsigned char *info, size_t info_len);

#endif /* SUPERSCALAR_NOISE_H */
