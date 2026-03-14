#include "superscalar/blinded_path.h"
#include "superscalar/sha256.h"
#include <string.h>
#include <secp256k1.h>
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

    /* For each hop, compute ECDH with intro_seckey and next hop's pubkey.
       Store blinded node id as the next hop's pubkey (simplified). */
    for (size_t i = 0; i < n_hops; i++) {
        memcpy(path->hops[i].blinded_node_id, node_pubkeys[i], 33);
        /* Encrypted data: SHA256(intro_seckey || node_pubkey[i]) as placeholder */
        unsigned char ecdh_input[65];
        memcpy(ecdh_input, intro_seckey32, 32);
        memcpy(ecdh_input + 32, node_pubkeys[i], 33);
        unsigned char ecdh_hash[32];
        sha256_double(ecdh_input, 65, ecdh_hash);
        memcpy(path->hops[i].encrypted_recipient_data, ecdh_hash, 32);
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
