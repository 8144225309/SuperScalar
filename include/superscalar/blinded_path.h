#ifndef SUPERSCALAR_BLINDED_PATH_H
#define SUPERSCALAR_BLINDED_PATH_H

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>

#define BLINDED_PATH_MAX_HOPS 8

typedef struct {
    unsigned char blinded_node_id[33]; /* 33-byte compressed pubkey */
    unsigned char encrypted_recipient_data[64];
    size_t        encrypted_len;
} blinded_hop_t;

typedef struct {
    unsigned char      introduction_node_id[33]; /* first hop (LSP pubkey) */
    blinded_hop_t      hops[BLINDED_PATH_MAX_HOPS];
    size_t             n_hops;
} blinded_path_t;

/*
 * Build a blinded path with n_hops. First hop uses intro_seckey for ECDH.
 * ctx: secp256k1 context with SIGN capability.
 * node_pubkeys[i]: 33-byte compressed public key of hop i.
 * Returns 1 on success.
 */
int blinded_path_build(blinded_path_t *path,
                        secp256k1_context *ctx,
                        const unsigned char (*node_pubkeys)[33],
                        size_t n_hops,
                        const unsigned char *intro_seckey32);

/*
 * Unblind the first hop of a path (for the introduction node).
 * Returns 1 on success, fills next_node_id33 with the next hop's pubkey.
 */
int blinded_path_unblind_first_hop(const blinded_path_t *path,
                                    secp256k1_context *ctx,
                                    const unsigned char *intro_seckey32,
                                    unsigned char *next_node_id33);

#endif /* SUPERSCALAR_BLINDED_PATH_H */
