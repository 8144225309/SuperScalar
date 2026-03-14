#include "superscalar/blinded_path.h"
#include "superscalar/sha256.h"
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_extrakeys.h>

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

    /* First hop: introduction node = our own pubkey */
    secp256k1_keypair intro_kp;
    if (!secp256k1_keypair_create(ctx, &intro_kp, intro_seckey32)) return 0;
    secp256k1_pubkey intro_pub;
    if (!secp256k1_keypair_pub(ctx, &intro_pub, &intro_kp)) return 0;
    {
        size_t sz = 33;
        secp256k1_ec_pubkey_serialize(ctx, path->introduction_node_id, &sz,
                                       &intro_pub, SECP256K1_EC_COMPRESSED);
    }

    /* For each hop, compute ECDH blinded node id:
       1. shared_secret = secp256k1_ecdh(intro_seckey, node_pubkey)
       2. blinding_factor = SHA256("blinded_node_id" || shared_secret)
       3. blinded_node_id = node_pubkey * blinding_factor  */
    for (size_t i = 0; i < n_hops; i++) {
        /* Parse hop pubkey */
        secp256k1_pubkey hop_pub;
        if (!secp256k1_ec_pubkey_parse(ctx, &hop_pub, node_pubkeys[i], 33)) return 0;

        /* ECDH: shared = SHA256(x-coordinate of intro_seckey * hop_pub) */
        unsigned char shared_secret[32];
        if (!secp256k1_ecdh(ctx, shared_secret, &hop_pub, intro_seckey32,
                             NULL, NULL)) return 0;

        /* Blinding factor = SHA256("blinded_node_id" || shared_secret) */
        const char *tag = "blinded_node_id";
        unsigned char bf_input[32 + 32];  /* tag hash + shared_secret */
        unsigned char tag_hash[32];
        sha256((const unsigned char *)tag, strlen(tag), tag_hash);
        memcpy(bf_input, tag_hash, 32);
        memcpy(bf_input + 32, shared_secret, 32);
        unsigned char blinding_factor[32];
        sha256(bf_input, 64, blinding_factor);

        /* Blinded node id = hop_pub * blinding_factor */
        secp256k1_pubkey blinded_pub = hop_pub;
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &blinded_pub, blinding_factor)) return 0;
        {
            size_t sz = 33;
            secp256k1_ec_pubkey_serialize(ctx, path->hops[i].blinded_node_id, &sz,
                                           &blinded_pub, SECP256K1_EC_COMPRESSED);
        }

        /* Encrypted data: SHA256(shared_secret || node_pubkey) as simplified placeholder */
        unsigned char enc_input[64];
        memcpy(enc_input, shared_secret, 32);
        memcpy(enc_input + 32, node_pubkeys[i], 32);
        sha256(enc_input, 64, path->hops[i].encrypted_recipient_data);
        path->hops[i].encrypted_len = 32;
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

    /* Simplified: return the blinded node id of hop[1] directly */
    memcpy(next_node_id33, path->hops[1].blinded_node_id, 33);
    (void)intro_seckey32;
    return 1;
}
