#include "superscalar/blinded_path.h"
#include "superscalar/crypto_aead.h"
#include "superscalar/sha256.h"
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_extrakeys.h>

/*
 * BOLT #12 blinded path implementation.
 *
 * Build (sender side):
 *   intro_seckey32  = ephemeral secret e
 *   introduction_node_id = e*G  (= blinding_point, carried in the payment)
 *
 *   For each hop i:
 *     ss_i           = ECDH(e, node_pubkeys[i])
 *     blinding_factor= SHA256("blinded_node_id" || ss_i)
 *     blinded_node_i = node_pubkeys[i] * blinding_factor
 *     aead_key       = blinding_factor   (= SHA256("blinded_node_id"||ss_i))
 *     plaintext      = node_pubkeys[i+1] (next hop) || zero-pad to 48 bytes
 *     encrypted_data = ChaCha20-Poly1305(aead_key, nonce=0,
 *                                        aad=blinded_node_id, pt=plaintext)
 *                      → 48-byte ciphertext + 16-byte Poly1305 tag = 64 bytes
 *
 * Unblind (introduction node, hop 0 receiver):
 *   intro_seckey32  = hop 0's OWN private key   (≠ the ephemeral e)
 *   introduction_node_id stored in path = e*G
 *   ss_0            = ECDH(hop0_privkey, e*G)   = ECDH(e, hop0_pubkey) [same]
 *   Derive aead_key, decrypt hops[0].encrypted_recipient_data → next_node_id
 */

/* ---- Helper: derive AEAD key from shared_secret ---- */
static void derive_aead_key(const unsigned char shared_secret[32],
                              unsigned char key_out[32])
{
    /* key = SHA256(SHA256("blinded_node_id") || shared_secret) */
    const char *tag = "blinded_node_id";
    unsigned char tag_hash[32];
    sha256((const unsigned char *)tag, 15, tag_hash);
    unsigned char buf[64];
    memcpy(buf,      tag_hash,      32);
    memcpy(buf + 32, shared_secret, 32);
    sha256(buf, 64, key_out);
}

int blinded_path_build(blinded_path_t *path,
                        secp256k1_context *ctx,
                        const unsigned char (*node_pubkeys)[33],
                        size_t n_hops,
                        const unsigned char *intro_seckey32)
{
    if (!path || !ctx || !node_pubkeys || n_hops == 0 || n_hops > BLINDED_PATH_MAX_HOPS)
        return 0;
    if (!intro_seckey32) return 0;

    memset(path, 0, sizeof(*path));
    path->n_hops = n_hops;

    /* introduction_node_id = e*G (the blinding_point carried in the payment) */
    secp256k1_keypair intro_kp;
    if (!secp256k1_keypair_create(ctx, &intro_kp, intro_seckey32)) return 0;
    secp256k1_pubkey intro_pub;
    if (!secp256k1_keypair_pub(ctx, &intro_pub, &intro_kp)) return 0;
    {
        size_t sz = 33;
        secp256k1_ec_pubkey_serialize(ctx, path->introduction_node_id, &sz,
                                       &intro_pub, SECP256K1_EC_COMPRESSED);
    }

    for (size_t i = 0; i < n_hops; i++) {
        secp256k1_pubkey hop_pub;
        if (!secp256k1_ec_pubkey_parse(ctx, &hop_pub, node_pubkeys[i], 33))
            return 0;

        /* ss_i = ECDH(e, hop_i_pubkey) */
        unsigned char shared_secret[32];
        if (!secp256k1_ecdh(ctx, shared_secret, &hop_pub, intro_seckey32,
                             NULL, NULL)) return 0;

        /* Blinding factor = SHA256("blinded_node_id" || ss_i) */
        unsigned char blinding_factor[32];
        derive_aead_key(shared_secret, blinding_factor);

        /* blinded_node_id = hop_pub * blinding_factor */
        secp256k1_pubkey blinded_pub = hop_pub;
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &blinded_pub, blinding_factor))
            return 0;
        {
            size_t sz = 33;
            secp256k1_ec_pubkey_serialize(ctx, path->hops[i].blinded_node_id, &sz,
                                           &blinded_pub, SECP256K1_EC_COMPRESSED);
        }

        /* AEAD key = blinding_factor (= SHA256("blinded_node_id" || ss_i)) */
        unsigned char aead_key[32];
        memcpy(aead_key, blinding_factor, 32);

        /* Nonce: 12 zero bytes (single-use per hop) */
        unsigned char nonce[12];
        memset(nonce, 0, 12);

        /* Plaintext: next_node_id (33 bytes) + zero-padding to 48 bytes */
        unsigned char plaintext[48];
        memset(plaintext, 0, 48);
        if (i + 1 < n_hops)
            memcpy(plaintext, node_pubkeys[i + 1], 33);

        /* Encrypt: AAD = blinded_node_id (33 bytes) */
        unsigned char ciphertext[48];
        unsigned char tag[16];
        if (!aead_encrypt(ciphertext, tag,
                           plaintext, 48,
                           path->hops[i].blinded_node_id, 33,
                           aead_key, nonce)) return 0;

        /* Store: 48 bytes ciphertext + 16 bytes tag = 64 bytes */
        memcpy(path->hops[i].encrypted_recipient_data,       ciphertext, 48);
        memcpy(path->hops[i].encrypted_recipient_data + 48,  tag,        16);
        path->hops[i].encrypted_len = 64;
    }

    return 1;
}

int blinded_path_unblind_first_hop(const blinded_path_t *path,
                                    secp256k1_context *ctx,
                                    const unsigned char *intro_seckey32,
                                    unsigned char *next_node_id33)
{
    if (!path || !ctx || !intro_seckey32 || !next_node_id33) return 0;
    if (path->n_hops < 2) return 0;

    /*
     * intro_seckey32 = hop 0's own private key.
     * path->introduction_node_id = e*G (blinding_point from sender).
     * ss_0 = ECDH(hop0_privkey, e*G) = ECDH(e, hop0_pubkey)  [same value].
     */
    secp256k1_pubkey blinding_point;
    if (!secp256k1_ec_pubkey_parse(ctx, &blinding_point,
                                    path->introduction_node_id, 33)) return 0;

    unsigned char shared_secret[32];
    if (!secp256k1_ecdh(ctx, shared_secret, &blinding_point, intro_seckey32,
                         NULL, NULL)) return 0;

    /* Derive AEAD key */
    unsigned char aead_key[32];
    derive_aead_key(shared_secret, aead_key);

    /* Decrypt hops[0].encrypted_recipient_data */
    unsigned char nonce[12];
    memset(nonce, 0, 12);

    const unsigned char *ct  = path->hops[0].encrypted_recipient_data;
    const unsigned char *tag = path->hops[0].encrypted_recipient_data + 48;

    unsigned char plaintext[48];
    if (!aead_decrypt(plaintext, ct, 48, tag,
                       path->hops[0].blinded_node_id, 33,  /* AAD */
                       aead_key, nonce)) return 0;

    /* Extract next_node_id from first 33 bytes of plaintext */
    memcpy(next_node_id33, plaintext, 33);
    return 1;
}
