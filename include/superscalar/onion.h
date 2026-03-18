/*
 * onion.h — BOLT #4 multi-hop Sphinx onion packet construction
 *
 * Builds a 1366-byte onion packet for outbound payments.
 * Reuses crypto primitives from onion_last_hop.c (ChaCha20, HMAC-SHA256, ECDH).
 *
 * Spec: BOLT #4 https://github.com/lightning/bolts/blob/master/04-onion-routing.md
 * Reference: CLN common/onion.c, LDK lightning/src/ln/onion_utils.rs
 */

#ifndef SUPERSCALAR_ONION_H
#define SUPERSCALAR_ONION_H

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>
#include "onion_last_hop.h"   /* ONION_PACKET_SIZE, ONION_HOPS_DATA_SIZE */

#define ONION_MAX_HOPS  20

typedef struct {
    unsigned char pubkey[33];       /* hop's node pubkey */
    uint64_t      amount_msat;      /* forwarded amount at this hop */
    uint32_t      cltv_expiry;      /* absolute CLTV at this hop */
    uint64_t      short_channel_id; /* outgoing channel (0 for final hop) */
    /* Final-hop fields */
    unsigned char payment_secret[32];
    uint64_t      total_msat;       /* for MPP: total payment amount */
    int           is_final;         /* 1 for the last hop (destination) */
    /* Keysend: preimage embedded in TLV type 5482373484 */
    unsigned char keysend_preimage[32];
    int           has_keysend;
    /* AMP (Atomic Multi-Path) fields — TLV type 14 per BOLT draft */
    unsigned char amp_root_share[32]; /* per-shard secret share */
    unsigned char amp_set_id[32];     /* identifies the AMP set */
    uint8_t       amp_child_index;    /* shard index 0..N-1 */
    int           has_amp;
} onion_hop_t;

/*
 * Build a BOLT #4 onion packet.
 * hops[0] = first hop (immediate peer); hops[n_hops-1] = destination.
 * session_key: 32 random bytes for per-payment ECDH key generation.
 * onion_out: exactly ONION_PACKET_SIZE (1366) bytes.
 * Returns 1 on success, 0 on error.
 */
int onion_build(const onion_hop_t *hops, int n_hops,
                const unsigned char session_key[32],
                secp256k1_context *ctx,
                unsigned char onion_out[ONION_PACKET_SIZE]);

/*
 * Decrypt one onion layer (for intermediate relaying).
 * Peels one layer and returns the inner packet and the next-hop payload.
 * Used by the HTLC forwarding engine.
 * Returns 1 on success.
 */
int onion_peel(const unsigned char node_priv32[32],
               secp256k1_context *ctx,
               const unsigned char onion_in[ONION_PACKET_SIZE],
               unsigned char onion_out[ONION_PACKET_SIZE],
               onion_hop_payload_t *payload_out,
               int *is_final);

/*
 * Decrypt a failure onion (error message propagated back toward sender).
 * session_keys: per-hop ephemeral keys used during onion_build.
 * n_hops: number of hops in the original route.
 * error_onion: 256-byte encrypted error blob (BOLT #4 §5).
 * out_plaintext: 256-byte buffer for decrypted error.
 * out_failing_hop: index of the hop that generated the error (0 = first), or -1.
 * Returns 1 if successfully decrypted at some hop.
 */
int onion_error_decrypt(const unsigned char (*session_keys)[32], int n_hops,
                        secp256k1_context *ctx,
                        const unsigned char error_onion[256],
                        unsigned char out_plaintext[256],
                        int *out_failing_hop);

#endif /* SUPERSCALAR_ONION_H */
