#include "superscalar/channel.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

extern void sha256(const unsigned char *, size_t, unsigned char *);
extern void sha256_tagged(const char *, const unsigned char *, size_t,
                           unsigned char *);
extern void reverse_bytes(unsigned char *, size_t);

/* ---- Key derivation (BOLT #3) ---- */

/* Simple: derived = basepoint + SHA256(per_commitment_point || basepoint) * G */
int channel_derive_pubkey(const secp256k1_context *ctx, secp256k1_pubkey *derived,
                           const secp256k1_pubkey *basepoint,
                           const secp256k1_pubkey *per_commitment_point) {
    unsigned char pcp_ser[33], bp_ser[33];
    size_t len = 33;

    if (!secp256k1_ec_pubkey_serialize(ctx, pcp_ser, &len, per_commitment_point,
                                        SECP256K1_EC_COMPRESSED))
        return 0;
    len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, bp_ser, &len, basepoint,
                                        SECP256K1_EC_COMPRESSED))
        return 0;

    /* tweak = SHA256(per_commitment_point || basepoint) */
    unsigned char hash_input[66];
    memcpy(hash_input, pcp_ser, 33);
    memcpy(hash_input + 33, bp_ser, 33);

    unsigned char tweak[32];
    sha256(hash_input, 66, tweak);

    /* derived = basepoint + tweak * G */
    *derived = *basepoint;
    if (!secp256k1_ec_pubkey_tweak_add(ctx, derived, tweak))
        return 0;

    return 1;
}

/* Two-scalar revocation:
   revocation_key = revocation_basepoint * SHA256(rb || pcp)
                  + per_commitment_point * SHA256(pcp || rb) */
int channel_derive_revocation_pubkey(const secp256k1_context *ctx,
                                      secp256k1_pubkey *derived,
                                      const secp256k1_pubkey *revocation_basepoint,
                                      const secp256k1_pubkey *per_commitment_point) {
    unsigned char rb_ser[33], pcp_ser[33];
    size_t len = 33;

    if (!secp256k1_ec_pubkey_serialize(ctx, rb_ser, &len, revocation_basepoint,
                                        SECP256K1_EC_COMPRESSED))
        return 0;
    len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, pcp_ser, &len, per_commitment_point,
                                        SECP256K1_EC_COMPRESSED))
        return 0;

    /* h1 = SHA256(rb || pcp) */
    unsigned char buf[66];
    memcpy(buf, rb_ser, 33);
    memcpy(buf + 33, pcp_ser, 33);
    unsigned char h1[32];
    sha256(buf, 66, h1);

    /* h2 = SHA256(pcp || rb) */
    memcpy(buf, pcp_ser, 33);
    memcpy(buf + 33, rb_ser, 33);
    unsigned char h2[32];
    sha256(buf, 66, h2);

    /* term1 = revocation_basepoint * h1 */
    secp256k1_pubkey term1 = *revocation_basepoint;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &term1, h1))
        return 0;

    /* term2 = per_commitment_point * h2 */
    secp256k1_pubkey term2 = *per_commitment_point;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &term2, h2))
        return 0;

    /* revocation_key = term1 + term2 */
    const secp256k1_pubkey *terms[2] = { &term1, &term2 };
    if (!secp256k1_ec_pubkey_combine(ctx, derived, terms, 2))
        return 0;

    return 1;
}

/* Private key: derived_secret = base_secret + SHA256(pcp || basepoint) */
int channel_derive_privkey(const secp256k1_context *ctx, unsigned char *derived32,
                            const unsigned char *base_secret32,
                            const secp256k1_pubkey *per_commitment_point) {
    /* Compute basepoint from base_secret */
    secp256k1_pubkey basepoint;
    if (!secp256k1_ec_pubkey_create(ctx, &basepoint, base_secret32))
        return 0;

    unsigned char pcp_ser[33], bp_ser[33];
    size_t len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, pcp_ser, &len, per_commitment_point,
                                        SECP256K1_EC_COMPRESSED))
        return 0;
    len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, bp_ser, &len, &basepoint,
                                        SECP256K1_EC_COMPRESSED))
        return 0;

    unsigned char hash_input[66];
    memcpy(hash_input, pcp_ser, 33);
    memcpy(hash_input + 33, bp_ser, 33);

    unsigned char tweak[32];
    sha256(hash_input, 66, tweak);

    /* derived = base_secret + tweak */
    memcpy(derived32, base_secret32, 32);
    if (!secp256k1_ec_seckey_tweak_add(ctx, derived32, tweak))
        return 0;

    return 1;
}

/* Revocation privkey: rb_secret * h1 + pcp_secret * h2 */
int channel_derive_revocation_privkey(const secp256k1_context *ctx,
                                       unsigned char *derived32,
                                       const unsigned char *revocation_basepoint_secret32,
                                       const unsigned char *per_commitment_secret32,
                                       const secp256k1_pubkey *revocation_basepoint,
                                       const secp256k1_pubkey *per_commitment_point) {
    unsigned char rb_ser[33], pcp_ser[33];
    size_t len = 33;

    if (!secp256k1_ec_pubkey_serialize(ctx, rb_ser, &len, revocation_basepoint,
                                        SECP256K1_EC_COMPRESSED))
        return 0;
    len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, pcp_ser, &len, per_commitment_point,
                                        SECP256K1_EC_COMPRESSED))
        return 0;

    /* h1 = SHA256(rb || pcp) */
    unsigned char buf[66];
    memcpy(buf, rb_ser, 33);
    memcpy(buf + 33, pcp_ser, 33);
    unsigned char h1[32];
    sha256(buf, 66, h1);

    /* h2 = SHA256(pcp || rb) */
    memcpy(buf, pcp_ser, 33);
    memcpy(buf + 33, rb_ser, 33);
    unsigned char h2[32];
    sha256(buf, 66, h2);

    /* term1 = rb_secret * h1 */
    unsigned char term1[32];
    memcpy(term1, revocation_basepoint_secret32, 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, term1, h1))
        return 0;

    /* term2 = pcp_secret * h2 */
    unsigned char term2[32];
    memcpy(term2, per_commitment_secret32, 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, term2, h2))
        return 0;

    /* derived = term1 + term2 */
    memcpy(derived32, term1, 32);
    if (!secp256k1_ec_seckey_tweak_add(ctx, derived32, term2))
        return 0;

    memset(term1, 0, 32);
    memset(term2, 0, 32);
    return 1;
}

/* ---- Channel state ---- */

int channel_init(channel_t *ch, secp256k1_context *ctx,
                  const unsigned char *local_funding_secret32,
                  const secp256k1_pubkey *local_funding_pubkey,
                  const secp256k1_pubkey *remote_funding_pubkey,
                  const unsigned char *funding_txid, uint32_t funding_vout,
                  uint64_t funding_amount,
                  const unsigned char *funding_spk, size_t funding_spk_len,
                  uint64_t local_amount, uint64_t remote_amount,
                  uint32_t to_self_delay) {
    memset(ch, 0, sizeof(*ch));
    ch->ctx = ctx;

    ch->local_funding_pubkey = *local_funding_pubkey;
    ch->remote_funding_pubkey = *remote_funding_pubkey;
    memcpy(ch->local_funding_secret, local_funding_secret32, 32);

    if (!secp256k1_keypair_create(ctx, &ch->local_funding_keypair,
                                    local_funding_secret32))
        return 0;

    /* MuSig key aggregation: try both orderings and pick the one matching
       funding_spk. This ensures the channel's keyagg matches the factory's
       key ordering regardless of which side (LSP or client) we are. */
    {
        int ordering_found = 0;
        secp256k1_pubkey orderings[2][2] = {
            { *local_funding_pubkey, *remote_funding_pubkey },
            { *remote_funding_pubkey, *local_funding_pubkey }
        };

        for (int order = 0; order < 2 && !ordering_found; order++) {
            musig_keyagg_t ka;
            if (!musig_aggregate_keys(ctx, &ka, orderings[order], 2))
                continue;

            /* Compute taproot-tweaked P2TR SPK from this keyagg */
            unsigned char internal_ser[32];
            if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey))
                continue;
            unsigned char twk[32];
            sha256_tagged("TapTweak", internal_ser, 32, twk);

            secp256k1_pubkey tweaked_full;
            if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked_full,
                                                    &ka.agg_pubkey, twk))
                continue;
            secp256k1_xonly_pubkey tweaked_xonly;
            if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL,
                                                     &tweaked_full))
                continue;
            unsigned char test_spk[34];
            build_p2tr_script_pubkey(test_spk, &tweaked_xonly);

            if (funding_spk_len == 34 && memcmp(test_spk, funding_spk, 34) == 0) {
                ch->funding_keyagg = ka;
                ch->local_funding_signer_idx = (order == 0) ? 0 : 1;
                ordering_found = 1;
            }
        }

        if (!ordering_found) {
            /* Fallback: use [local, remote] (for tests not using factory SPKs) */
            secp256k1_pubkey pks[2] = { *local_funding_pubkey, *remote_funding_pubkey };
            if (!musig_aggregate_keys(ctx, &ch->funding_keyagg, pks, 2))
                return 0;
            ch->local_funding_signer_idx = 0;
        }
    }

    memcpy(ch->funding_txid, funding_txid, 32);
    ch->funding_vout = funding_vout;
    ch->funding_amount = funding_amount;
    memcpy(ch->funding_spk, funding_spk, funding_spk_len);
    ch->funding_spk_len = funding_spk_len;

    ch->local_amount = local_amount;
    ch->remote_amount = remote_amount;
    ch->to_self_delay = to_self_delay;
    ch->fee_rate_sat_per_kvb = 1000;  /* default: 1 sat/vB */
    ch->funder_is_local = 0;
    ch->commitment_number = 0;

    /* Generate random per-commitment secrets for cn=0 and cn=1.
       cn=0 is needed for first commitment, cn=1 for first next_per_commitment_point. */
    channel_generate_local_pcs(ch, 0);
    channel_generate_local_pcs(ch, 1);

    return 1;
}

int channel_set_local_basepoints(channel_t *ch,
                                   const unsigned char *payment_secret32,
                                   const unsigned char *delayed_payment_secret32,
                                   const unsigned char *revocation_secret32) {
    memcpy(ch->local_payment_basepoint_secret, payment_secret32, 32);
    if (!secp256k1_ec_pubkey_create(ch->ctx, &ch->local_payment_basepoint,
                                     payment_secret32))
        return 0;

    memcpy(ch->local_delayed_payment_basepoint_secret,
           delayed_payment_secret32, 32);
    if (!secp256k1_ec_pubkey_create(ch->ctx, &ch->local_delayed_payment_basepoint,
                                     delayed_payment_secret32))
        return 0;

    memcpy(ch->local_revocation_basepoint_secret, revocation_secret32, 32);
    if (!secp256k1_ec_pubkey_create(ch->ctx, &ch->local_revocation_basepoint,
                                     revocation_secret32))
        return 0;

#if BASEPOINT_DIAG
    {
        unsigned char s1[33], s2[33], s3[33];
        size_t l = 33;
        secp256k1_ec_pubkey_serialize(ch->ctx, s1, &l, &ch->local_payment_basepoint, SECP256K1_EC_COMPRESSED);
        l = 33;
        secp256k1_ec_pubkey_serialize(ch->ctx, s2, &l, &ch->local_delayed_payment_basepoint, SECP256K1_EC_COMPRESSED);
        l = 33;
        secp256k1_ec_pubkey_serialize(ch->ctx, s3, &l, &ch->local_revocation_basepoint, SECP256K1_EC_COMPRESSED);
        fprintf(stderr, "DIAG basepoint: set local pay=%02x%02x%02x%02x delay=%02x%02x%02x%02x revoc=%02x%02x%02x%02x\n",
                s1[0],s1[1],s1[2],s1[3], s2[0],s2[1],s2[2],s2[3], s3[0],s3[1],s3[2],s3[3]);
    }
#endif
    return 1;
}

void channel_set_remote_basepoints(channel_t *ch,
                                     const secp256k1_pubkey *payment,
                                     const secp256k1_pubkey *delayed_payment,
                                     const secp256k1_pubkey *revocation) {
    ch->remote_payment_basepoint = *payment;
    ch->remote_delayed_payment_basepoint = *delayed_payment;
    ch->remote_revocation_basepoint = *revocation;

#if BASEPOINT_DIAG
    {
        unsigned char s1[33], s2[33], s3[33];
        size_t l = 33;
        secp256k1_ec_pubkey_serialize(ch->ctx, s1, &l, payment, SECP256K1_EC_COMPRESSED);
        l = 33;
        secp256k1_ec_pubkey_serialize(ch->ctx, s2, &l, delayed_payment, SECP256K1_EC_COMPRESSED);
        l = 33;
        secp256k1_ec_pubkey_serialize(ch->ctx, s3, &l, revocation, SECP256K1_EC_COMPRESSED);
        fprintf(stderr, "DIAG basepoint: set remote pay=%02x%02x%02x%02x delay=%02x%02x%02x%02x revoc=%02x%02x%02x%02x\n",
                s1[0],s1[1],s1[2],s1[3], s2[0],s2[1],s2[2],s2[3], s3[0],s3[1],s3[2],s3[3]);
    }
#endif
}

/* ---- Random basepoint generation ---- */

#ifndef BASEPOINT_DIAG
#define BASEPOINT_DIAG 0
#endif

int channel_generate_random_basepoints(channel_t *ch) {
    unsigned char ps[32], ds[32], rs[32], hs[32];
    if (!channel_read_random_bytes(ps, 32) || !channel_read_random_bytes(ds, 32) ||
        !channel_read_random_bytes(rs, 32) || !channel_read_random_bytes(hs, 32)) {
        return 0;
    }

#if BASEPOINT_DIAG
    fprintf(stderr, "DIAG basepoint: generated random (pay=%02x%02x..., delay=%02x%02x..., "
            "revoc=%02x%02x..., htlc=%02x%02x...)\n",
            ps[0], ps[1], ds[0], ds[1], rs[0], rs[1], hs[0], hs[1]);
#endif

    if (!channel_set_local_basepoints(ch, ps, ds, rs)) {
        memset(ps, 0, 32); memset(ds, 0, 32);
        memset(rs, 0, 32); memset(hs, 0, 32);
        return 0;
    }
    if (!channel_set_local_htlc_basepoint(ch, hs)) {
        memset(ps, 0, 32); memset(ds, 0, 32);
        memset(rs, 0, 32); memset(hs, 0, 32);
        return 0;
    }

    memset(ps, 0, 32);
    memset(ds, 0, 32);
    memset(rs, 0, 32);
    memset(hs, 0, 32);
    return 1;
}

/* ---- Per-commitment secret flat storage ---- */

int channel_read_random_bytes(unsigned char *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, len);
    close(fd);
    return (n == (ssize_t)len);
}

int channel_generate_local_pcs(channel_t *ch, uint64_t commitment_num) {
    if (commitment_num >= CHANNEL_MAX_SECRETS) return 0;
    if (!channel_read_random_bytes(ch->local_pcs[commitment_num], 32))
        return 0;
    if (commitment_num + 1 > ch->n_local_pcs)
        ch->n_local_pcs = (size_t)(commitment_num + 1);
    return 1;
}

int channel_get_local_pcs(const channel_t *ch, uint64_t commitment_num,
                           unsigned char *secret_out32) {
    if (commitment_num >= CHANNEL_MAX_SECRETS) return 0;
    if (commitment_num >= ch->n_local_pcs) return 0;
    memcpy(secret_out32, ch->local_pcs[commitment_num], 32);
    return 1;
}

void channel_set_local_pcs(channel_t *ch, uint64_t commitment_num,
                            const unsigned char *secret32) {
    if (commitment_num >= CHANNEL_MAX_SECRETS) return;
    memcpy(ch->local_pcs[commitment_num], secret32, 32);
    if (commitment_num + 1 > ch->n_local_pcs)
        ch->n_local_pcs = (size_t)(commitment_num + 1);
}

void channel_set_remote_pcp(channel_t *ch, uint64_t commitment_num,
                             const secp256k1_pubkey *pcp) {
    /* Check if this commitment_num already occupies a slot */
    for (int i = 0; i < 2; i++) {
        if (ch->remote_pcp_valid[i] && ch->remote_pcp_nums[i] == commitment_num) {
            ch->remote_pcps[i] = *pcp;
            return;
        }
    }
    /* Find an empty slot */
    for (int i = 0; i < 2; i++) {
        if (!ch->remote_pcp_valid[i]) {
            ch->remote_pcps[i] = *pcp;
            ch->remote_pcp_nums[i] = commitment_num;
            ch->remote_pcp_valid[i] = 1;
            return;
        }
    }
    /* Both slots occupied — evict the one with the smaller commitment_num */
    int evict = (ch->remote_pcp_nums[0] <= ch->remote_pcp_nums[1]) ? 0 : 1;
    ch->remote_pcps[evict] = *pcp;
    ch->remote_pcp_nums[evict] = commitment_num;
    ch->remote_pcp_valid[evict] = 1;
}

int channel_get_remote_pcp(const channel_t *ch, uint64_t commitment_num,
                            secp256k1_pubkey *pcp_out) {
    /* Check both stored slots */
    for (int i = 0; i < 2; i++) {
        if (ch->remote_pcp_valid[i] && ch->remote_pcp_nums[i] == commitment_num) {
            *pcp_out = ch->remote_pcps[i];
            return 1;
        }
    }
    /* For old commitments, derive from received revocation secret */
    uint64_t max_stored = 0;
    for (int i = 0; i < 2; i++) {
        if (ch->remote_pcp_valid[i] && ch->remote_pcp_nums[i] > max_stored)
            max_stored = ch->remote_pcp_nums[i];
    }
    if (commitment_num < max_stored) {
        unsigned char secret[32];
        if (!channel_get_received_revocation(ch, commitment_num, secret))
            return 0;
        int ok = secp256k1_ec_pubkey_create(ch->ctx, pcp_out, secret);
        secure_zero(secret, 32);
        return ok;
    }
    return 0;
}

int channel_receive_revocation_flat(channel_t *ch, uint64_t commitment_num,
                                      const unsigned char *secret32) {
    if (commitment_num >= CHANNEL_MAX_SECRETS) return 0;
    memcpy(ch->received_revocations[commitment_num], secret32, 32);
    ch->received_revocation_valid[commitment_num] = 1;
    return 1;
}

int channel_get_received_revocation(const channel_t *ch, uint64_t commitment_num,
                                      unsigned char *secret_out32) {
    if (commitment_num >= CHANNEL_MAX_SECRETS) return 0;
    if (!ch->received_revocation_valid[commitment_num]) return 0;
    memcpy(secret_out32, ch->received_revocations[commitment_num], 32);
    return 1;
}

int channel_get_per_commitment_point(const channel_t *ch, uint64_t commitment_num,
                                      secp256k1_pubkey *point_out) {
    unsigned char secret[32];
    if (!channel_get_local_pcs(ch, commitment_num, secret))
        return 0;
    int ok = secp256k1_ec_pubkey_create(ch->ctx, point_out, secret);
    secure_zero(secret, 32);
    return ok;
}

int channel_get_per_commitment_secret(const channel_t *ch, uint64_t commitment_num,
                                       unsigned char *secret_out32) {
    return channel_get_local_pcs(ch, commitment_num, secret_out32);
}

/* ---- Commitment TX ---- */

/* Internal implementation with optional pcp_override.
   If pcp_override is non-NULL, use that PCP instead of looking up from local_pcs. */
static int channel_build_commitment_tx_impl(const channel_t *ch,
                                              tx_buf_t *unsigned_tx_out,
                                              unsigned char *txid_out32,
                                              const secp256k1_pubkey *pcp_override) {
    /* 1. Derive per_commitment_point */
    secp256k1_pubkey pcp;
    if (pcp_override) {
        pcp = *pcp_override;
    } else if (!channel_get_per_commitment_point(ch, ch->commitment_number, &pcp)) {
        return 0;
    }

    /* 2. Derive revocation pubkey (from remote's revocation_basepoint + our pcp) */
    secp256k1_pubkey revocation_pubkey;
    if (!channel_derive_revocation_pubkey(ch->ctx, &revocation_pubkey,
                                            &ch->remote_revocation_basepoint, &pcp))
        return 0;

    /* 3. Derive delayed_payment pubkey */
    secp256k1_pubkey delayed_pubkey;
    if (!channel_derive_pubkey(ch->ctx, &delayed_pubkey,
                                &ch->local_delayed_payment_basepoint, &pcp))
        return 0;

    /* 4. Derive remote_payment pubkey */
    secp256k1_pubkey remote_payment_pubkey;
    if (!channel_derive_pubkey(ch->ctx, &remote_payment_pubkey,
                                &ch->remote_payment_basepoint, &pcp))
        return 0;

    /* 5. Build to-local output: P2TR(revocation_key, csv_script) */
    secp256k1_xonly_pubkey revocation_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &revocation_xonly, NULL,
                                             &revocation_pubkey))
        return 0;

    secp256k1_xonly_pubkey delayed_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &delayed_xonly, NULL,
                                             &delayed_pubkey))
        return 0;

    tapscript_leaf_t csv_leaf;
    if (!tapscript_build_csv_delay(&csv_leaf, ch->to_self_delay, &delayed_xonly,
                                    ch->ctx))
        return 0;

    unsigned char merkle_root[32];
    tapscript_merkle_root(merkle_root, &csv_leaf, 1);

    secp256k1_xonly_pubkey to_local_tweaked;
    if (!tapscript_tweak_pubkey(ch->ctx, &to_local_tweaked, NULL,
                                 &revocation_xonly, merkle_root))
        return 0;

    /* Count active HTLCs */
    size_t n_active_htlcs = 0;
    for (size_t i = 0; i < ch->n_htlcs; i++) {
        if (ch->htlcs[i].state == HTLC_STATE_ACTIVE)
            n_active_htlcs++;
    }

    tx_output_t outputs[2 + MAX_HTLCS];

    /* to-local */
    build_p2tr_script_pubkey(outputs[0].script_pubkey, &to_local_tweaked);
    outputs[0].script_pubkey_len = 34;
    outputs[0].amount_sats = ch->local_amount;

    /* 6. Build to-remote output: P2TR(remote_payment_key) with key-path-only */
    secp256k1_xonly_pubkey remote_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &remote_xonly, NULL,
                                             &remote_payment_pubkey))
        return 0;

    /* Key-path-only tweak: TapTweak(key, empty) */
    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ch->ctx, internal_ser, &remote_xonly))
        return 0;
    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);

    secp256k1_pubkey remote_tweaked_full;
    if (!secp256k1_xonly_pubkey_tweak_add(ch->ctx, &remote_tweaked_full,
                                            &remote_xonly, tweak))
        return 0;
    secp256k1_xonly_pubkey remote_tweaked;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &remote_tweaked, NULL,
                                             &remote_tweaked_full))
        return 0;

    build_p2tr_script_pubkey(outputs[1].script_pubkey, &remote_tweaked);
    outputs[1].script_pubkey_len = 34;
    outputs[1].amount_sats = ch->remote_amount;

    /* 7. Build HTLC outputs */
    size_t out_idx = 2;
    if (n_active_htlcs > 0) {
        /* Derive HTLC keys */
        secp256k1_pubkey local_htlc_pub, remote_htlc_pub;
        channel_derive_pubkey(ch->ctx, &local_htlc_pub,
                              &ch->local_htlc_basepoint, &pcp);
        channel_derive_pubkey(ch->ctx, &remote_htlc_pub,
                              &ch->remote_htlc_basepoint, &pcp);

        secp256k1_xonly_pubkey local_htlc_xonly, remote_htlc_xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &local_htlc_xonly, NULL,
                                                 &local_htlc_pub))
            return 0;
        if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &remote_htlc_xonly, NULL,
                                                 &remote_htlc_pub))
            return 0;

        for (size_t i = 0; i < ch->n_htlcs; i++) {
            if (ch->htlcs[i].state != HTLC_STATE_ACTIVE)
                continue;

            tapscript_leaf_t success_leaf, timeout_leaf;

            if (ch->htlcs[i].direction == HTLC_OFFERED) {
                if (!tapscript_build_htlc_offered_success(&success_leaf,
                        ch->htlcs[i].payment_hash, &remote_htlc_xonly, ch->ctx))
                    return 0;
                if (!tapscript_build_htlc_offered_timeout(&timeout_leaf,
                        ch->htlcs[i].cltv_expiry, ch->to_self_delay,
                        &local_htlc_xonly, ch->ctx))
                    return 0;
            } else {
                if (!tapscript_build_htlc_received_success(&success_leaf,
                        ch->htlcs[i].payment_hash, ch->to_self_delay,
                        &local_htlc_xonly, ch->ctx))
                    return 0;
                if (!tapscript_build_htlc_received_timeout(&timeout_leaf,
                        ch->htlcs[i].cltv_expiry, &remote_htlc_xonly, ch->ctx))
                    return 0;
            }

            /* 2-leaf merkle root */
            tapscript_leaf_t htlc_leaves[2] = { success_leaf, timeout_leaf };
            unsigned char htlc_merkle[32];
            tapscript_merkle_root(htlc_merkle, htlc_leaves, 2);

            /* Tweak revocation key with HTLC taptree */
            secp256k1_xonly_pubkey htlc_tweaked;
            if (!tapscript_tweak_pubkey(ch->ctx, &htlc_tweaked, NULL,
                                         &revocation_xonly, htlc_merkle))
                return 0;

            build_p2tr_script_pubkey(outputs[out_idx].script_pubkey,
                                     &htlc_tweaked);
            outputs[out_idx].script_pubkey_len = 34;
            outputs[out_idx].amount_sats = ch->htlcs[i].amount_sats;
            out_idx++;
        }
    }

    /* 8. Build unsigned tx */
    if (!build_unsigned_tx(unsigned_tx_out, txid_out32,
                            ch->funding_txid, ch->funding_vout,
                            0xFFFFFFFE, outputs, out_idx))
        return 0;

    /* Convert display-order txid to internal byte order (wire format),
       matching factory convention where node->txid is wire format. */
    if (txid_out32)
        reverse_bytes(txid_out32, 32);

    return 1;
}

int channel_build_commitment_tx(const channel_t *ch,
                                  tx_buf_t *unsigned_tx_out,
                                  unsigned char *txid_out32) {
    return channel_build_commitment_tx_impl(ch, unsigned_tx_out, txid_out32, NULL);
}

int channel_build_commitment_tx_for_remote(const channel_t *ch,
                                             tx_buf_t *unsigned_tx_out,
                                             unsigned char *txid_out32) {
    /* Get the remote's per-commitment point */
    secp256k1_pubkey remote_pcp;
    if (!channel_get_remote_pcp(ch, ch->commitment_number, &remote_pcp))
        return 0;

    /* Create a shallow copy with local/remote swapped to represent
       the remote party's view of their own commitment transaction. */
    channel_t rv = *ch;

    /* Swap amounts */
    rv.local_amount = ch->remote_amount;
    rv.remote_amount = ch->local_amount;

    /* Swap basepoints: remote's "local" = our "remote" and vice versa */
    rv.local_delayed_payment_basepoint = ch->remote_delayed_payment_basepoint;
    rv.remote_revocation_basepoint = ch->local_revocation_basepoint;
    rv.remote_payment_basepoint = ch->local_payment_basepoint;
    rv.local_htlc_basepoint = ch->remote_htlc_basepoint;
    rv.remote_htlc_basepoint = ch->local_htlc_basepoint;

    /* Flip HTLC directions: what we offered, they received */
    for (size_t i = 0; i < rv.n_htlcs; i++) {
        if (rv.htlcs[i].direction == HTLC_OFFERED)
            rv.htlcs[i].direction = HTLC_RECEIVED;
        else
            rv.htlcs[i].direction = HTLC_OFFERED;
    }

    return channel_build_commitment_tx_impl(&rv, unsigned_tx_out, txid_out32, &remote_pcp);
}

int channel_sign_commitment(const channel_t *ch,
                              tx_buf_t *signed_tx_out,
                              const tx_buf_t *unsigned_tx,
                              const secp256k1_keypair *remote_keypair) {
    /* Compute sighash */
    unsigned char sighash[32];
    if (!compute_taproot_sighash(sighash, unsigned_tx->data, unsigned_tx->len,
                                  0, ch->funding_spk, ch->funding_spk_len,
                                  ch->funding_amount, 0xFFFFFFFE))
        return 0;

    /* Sign with MuSig2 (all-local for testing).
       Keypair ordering must match the keyagg ordering. */
    secp256k1_keypair kps[2];
    if (ch->local_funding_signer_idx == 0) {
        kps[0] = ch->local_funding_keypair;
        kps[1] = *remote_keypair;
    } else {
        kps[0] = *remote_keypair;
        kps[1] = ch->local_funding_keypair;
    }

    musig_keyagg_t keyagg_copy = ch->funding_keyagg;
    unsigned char sig64[64];
    if (!musig_sign_taproot(ch->ctx, sig64, sighash, kps, 2, &keyagg_copy, NULL))
        return 0;

    /* Finalize */
    if (!finalize_signed_tx(signed_tx_out, unsigned_tx->data, unsigned_tx->len,
                              sig64))
        return 0;

    return 1;
}

/* ---- Revocation + Penalty ---- */

int channel_get_revocation_secret(const channel_t *ch, uint64_t old_commitment_num,
                                    unsigned char *secret_out32) {
    return channel_get_per_commitment_secret(ch, old_commitment_num, secret_out32);
}

int channel_receive_revocation(channel_t *ch, uint64_t commitment_num,
                                 const unsigned char *secret32) {
    return channel_receive_revocation_flat(ch, commitment_num, secret32);
}

void channel_set_fee_rate(channel_t *ch, uint64_t fee_rate_sat_per_kvb) {
    if (!ch) return;
    ch->fee_rate_sat_per_kvb = fee_rate_sat_per_kvb;
}

int channel_near_exhaustion(const channel_t *ch) {
    if (!ch) return 0;
    return ch->commitment_number >= CHANNEL_SECRETS_WARNING_THRESHOLD;
}

int channel_build_penalty_tx(const channel_t *ch,
                               tx_buf_t *penalty_tx_out,
                               const unsigned char *commitment_txid,
                               uint32_t to_local_vout,
                               uint64_t to_local_amount,
                               const unsigned char *to_local_spk,
                               size_t to_local_spk_len,
                               uint64_t old_commitment_num,
                               const unsigned char *anchor_spk,
                               size_t anchor_spk_len) {
    /* 1. Retrieve per_commitment_secret from received revocations */
    unsigned char pcp_secret[32];
    if (!channel_get_received_revocation(ch, old_commitment_num, pcp_secret))
        return 0;

    /* 2. Compute per_commitment_point from secret */
    secp256k1_pubkey pcp;
    if (!secp256k1_ec_pubkey_create(ch->ctx, &pcp, pcp_secret))
        return 0;

    /* 3. Derive revocation privkey:
       Uses our revocation_basepoint_secret + their per_commitment_secret */
    unsigned char revocation_privkey[32];
    if (!channel_derive_revocation_privkey(ch->ctx, revocation_privkey,
                                             ch->local_revocation_basepoint_secret,
                                             pcp_secret,
                                             &ch->local_revocation_basepoint, &pcp))
        return 0;

    /* 4. Derive delayed_payment pubkey (needed to reconstruct taptree) */
    secp256k1_pubkey delayed_pubkey;
    if (!channel_derive_pubkey(ch->ctx, &delayed_pubkey,
                                &ch->remote_delayed_payment_basepoint, &pcp))
        return 0;

    /* 5. Rebuild CSV tapscript leaf + merkle root */
    secp256k1_xonly_pubkey delayed_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &delayed_xonly, NULL,
                                             &delayed_pubkey))
        return 0;

    tapscript_leaf_t csv_leaf;
    if (!tapscript_build_csv_delay(&csv_leaf, ch->to_self_delay, &delayed_xonly,
                                    ch->ctx))
        return 0;

    unsigned char merkle_root[32];
    tapscript_merkle_root(merkle_root, &csv_leaf, 1);

    /* 6. Compute taproot tweak for the revocation key */
    secp256k1_pubkey revocation_pubkey;
    if (!secp256k1_ec_pubkey_create(ch->ctx, &revocation_pubkey, revocation_privkey))
        return 0;

    secp256k1_xonly_pubkey revocation_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &revocation_xonly, NULL,
                                             &revocation_pubkey))
        return 0;

    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ch->ctx, internal_ser, &revocation_xonly))
        return 0;

    unsigned char tweak_data[64];
    memcpy(tweak_data, internal_ser, 32);
    memcpy(tweak_data + 32, merkle_root, 32);
    unsigned char tweak[32];
    sha256_tagged("TapTweak", tweak_data, 64, tweak);

    /* Create keypair and apply taproot tweak */
    secp256k1_keypair tweaked_kp;
    if (!secp256k1_keypair_create(ch->ctx, &tweaked_kp, revocation_privkey))
        return 0;
    if (!secp256k1_keypair_xonly_tweak_add(ch->ctx, &tweaked_kp, tweak))
        return 0;

    /* 7. Build penalty tx output: P2TR(local_payment_basepoint) key-path-only */
    secp256k1_xonly_pubkey local_pay_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &local_pay_xonly, NULL,
                                             &ch->local_payment_basepoint))
        return 0;

    /* Key-path-only tweak for output */
    unsigned char out_internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ch->ctx, out_internal_ser, &local_pay_xonly))
        return 0;
    unsigned char out_tweak[32];
    sha256_tagged("TapTweak", out_internal_ser, 32, out_tweak);

    secp256k1_pubkey out_tweaked_full;
    if (!secp256k1_xonly_pubkey_tweak_add(ch->ctx, &out_tweaked_full,
                                            &local_pay_xonly, out_tweak))
        return 0;
    secp256k1_xonly_pubkey out_tweaked;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &out_tweaked, NULL,
                                             &out_tweaked_full))
        return 0;

    /* Fee: computed from fee rate.
       With P2A anchor: ~165 vB (1-in, 2-out). Without: ~152 vB (1-in, 1-out). */
    int has_anchor = (anchor_spk && anchor_spk_len == P2A_SPK_LEN);
    uint64_t vsize = has_anchor ? 165 : 152;
    uint64_t anchor_amount = ANCHOR_OUTPUT_AMOUNT;
    uint64_t penalty_fee = (ch->fee_rate_sat_per_kvb * vsize + 999) / 1000;
    uint64_t deduction = penalty_fee + (has_anchor ? anchor_amount : 0);
    uint64_t penalty_amount = to_local_amount > deduction ? to_local_amount - deduction : 0;

    tx_output_t outputs[2];
    size_t n_outputs = 1;
    build_p2tr_script_pubkey(outputs[0].script_pubkey, &out_tweaked);
    outputs[0].script_pubkey_len = 34;
    outputs[0].amount_sats = penalty_amount;

    if (has_anchor) {
        memcpy(outputs[1].script_pubkey, anchor_spk, P2A_SPK_LEN);
        outputs[1].script_pubkey_len = P2A_SPK_LEN;
        outputs[1].amount_sats = anchor_amount;
        n_outputs = 2;
    }

    /* 8. Build unsigned penalty tx */
    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 256);
    unsigned char penalty_txid[32];
    if (!build_unsigned_tx(&unsigned_tx, penalty_txid,
                            commitment_txid, to_local_vout,
                            0xFFFFFFFE, outputs, n_outputs)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* 9. Compute key-path sighash + sign */
    unsigned char sighash[32];
    if (!compute_taproot_sighash(sighash, unsigned_tx.data, unsigned_tx.len,
                                  0, to_local_spk, to_local_spk_len,
                                  to_local_amount, 0xFFFFFFFE)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    unsigned char sig64[64];
    if (!secp256k1_schnorrsig_sign32(ch->ctx, sig64, sighash, &tweaked_kp, NULL)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* 10. Finalize */
    if (!finalize_signed_tx(penalty_tx_out, unsigned_tx.data, unsigned_tx.len,
                              sig64)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    tx_buf_free(&unsigned_tx);
    secure_zero(revocation_privkey, 32);
    secure_zero(pcp_secret, 32);
    return 1;
}

/* ---- Distributed commitment signing (Phase 12) ---- */

int channel_init_nonce_pool(channel_t *ch, size_t count) {
    unsigned char seckey[32];
    memcpy(seckey, ch->local_funding_secret, 32);
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(ch->ctx, &pk, seckey)) {
        secure_zero(seckey, 32);
        return 0;
    }
    int ok = musig_nonce_pool_generate(ch->ctx, &ch->local_nonce_pool,
                                         count, seckey, &pk,
                                         &ch->funding_keyagg.cache);
    secure_zero(seckey, 32);
    ch->remote_nonce_count = 0;
    ch->remote_nonce_next = 0;
    return ok;
}

int channel_set_remote_pubnonces(channel_t *ch,
                                   const unsigned char pubnonces[][66],
                                   size_t count) {
    if (count > MUSIG_NONCE_POOL_MAX) count = MUSIG_NONCE_POOL_MAX;
    for (size_t i = 0; i < count; i++)
        memcpy(ch->remote_pubnonces_ser[i], pubnonces[i], 66);
    ch->remote_nonce_count = count;
    ch->remote_nonce_next = 0;
    return 1;
}

int channel_create_commitment_partial_sig(
    channel_t *ch,
    unsigned char *partial_sig32_out,
    uint32_t *nonce_index_out)
{
    /* 1. Determine nonce index = remote_nonce_next (consumed in order) */
    uint32_t nidx = (uint32_t)ch->remote_nonce_next;
    if (nidx >= ch->remote_nonce_count) return 0;

    /* 2. Build the REMOTE's commitment tx and compute sighash.
       In Lightning protocol, COMMITMENT_SIGNED contains a signature
       for the remote party's commitment transaction. */
    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 512);
    unsigned char txid[32];
    if (!channel_build_commitment_tx_for_remote(ch, &unsigned_tx, txid)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    unsigned char sighash[32];
    if (!compute_taproot_sighash(sighash, unsigned_tx.data, unsigned_tx.len,
                                  0, ch->funding_spk, ch->funding_spk_len,
                                  ch->funding_amount, 0xFFFFFFFE)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }
    tx_buf_free(&unsigned_tx);

    /* 3. Draw local nonce */
    secp256k1_musig_secnonce *my_secnonce;
    secp256k1_musig_pubnonce my_pubnonce;
    if (!musig_nonce_pool_next(&ch->local_nonce_pool, &my_secnonce, &my_pubnonce))
        return 0;

    /* 4. Parse peer's pubnonce at this index */
    secp256k1_musig_pubnonce peer_pubnonce;
    if (!musig_pubnonce_parse(ch->ctx, &peer_pubnonce,
                               ch->remote_pubnonces_ser[nidx]))
        return 0;

    /* 5. Set up MuSig2 signing session (2-of-2) */
    musig_signing_session_t session;
    musig_session_init(&session, &ch->funding_keyagg, 2);

    /* Place nonces in correct signer order */
    if (ch->local_funding_signer_idx == 0) {
        musig_session_set_pubnonce(&session, 0, &my_pubnonce);
        musig_session_set_pubnonce(&session, 1, &peer_pubnonce);
    } else {
        musig_session_set_pubnonce(&session, 0, &peer_pubnonce);
        musig_session_set_pubnonce(&session, 1, &my_pubnonce);
    }

    /* Finalize with key-path-only taproot tweak (merkle_root = NULL) */
    if (!musig_session_finalize_nonces(ch->ctx, &session, sighash, NULL, NULL))
        return 0;

    /* 6. Create partial sig */
    secp256k1_musig_partial_sig psig;
    if (!musig_create_partial_sig(ch->ctx, &psig, my_secnonce,
                                    &ch->local_funding_keypair, &session))
        return 0;

    /* 7. Serialize */
    if (!musig_partial_sig_serialize(ch->ctx, partial_sig32_out, &psig))
        return 0;

    *nonce_index_out = nidx;
    ch->remote_nonce_next++;
    return 1;
}

int channel_verify_and_aggregate_commitment_sig(
    channel_t *ch,
    const unsigned char *peer_partial_sig32,
    uint32_t peer_nonce_index,
    unsigned char *full_sig64_out)
{
    /* 1. Build commitment tx and compute sighash */
    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 512);
    unsigned char txid[32];
    if (!channel_build_commitment_tx(ch, &unsigned_tx, txid)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    unsigned char sighash[32];
    if (!compute_taproot_sighash(sighash, unsigned_tx.data, unsigned_tx.len,
                                  0, ch->funding_spk, ch->funding_spk_len,
                                  ch->funding_amount, 0xFFFFFFFE)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }
    tx_buf_free(&unsigned_tx);

    /* 2. Draw local nonce at peer_nonce_index.
       We consume nonces in order, so this should be our next nonce. */
    secp256k1_musig_secnonce *my_secnonce;
    secp256k1_musig_pubnonce my_pubnonce;
    if (!musig_nonce_pool_next(&ch->local_nonce_pool, &my_secnonce, &my_pubnonce))
        return 0;

    /* 3. Parse peer's pubnonce at peer_nonce_index */
    if (peer_nonce_index >= ch->remote_nonce_count) return 0;
    secp256k1_musig_pubnonce peer_pubnonce;
    if (!musig_pubnonce_parse(ch->ctx, &peer_pubnonce,
                               ch->remote_pubnonces_ser[peer_nonce_index]))
        return 0;

    /* 4. Set up MuSig2 signing session */
    musig_signing_session_t session;
    musig_session_init(&session, &ch->funding_keyagg, 2);

    if (ch->local_funding_signer_idx == 0) {
        musig_session_set_pubnonce(&session, 0, &my_pubnonce);
        musig_session_set_pubnonce(&session, 1, &peer_pubnonce);
    } else {
        musig_session_set_pubnonce(&session, 0, &peer_pubnonce);
        musig_session_set_pubnonce(&session, 1, &my_pubnonce);
    }

    if (!musig_session_finalize_nonces(ch->ctx, &session, sighash, NULL, NULL))
        return 0;

    /* 5. Parse peer's partial sig */
    secp256k1_musig_partial_sig peer_psig;
    if (!musig_partial_sig_parse(ch->ctx, &peer_psig, peer_partial_sig32))
        return 0;

    /* 6. Verify peer's partial sig */
    secp256k1_pubkey peer_pubkey = ch->remote_funding_pubkey;
    if (!musig_verify_partial_sig(ch->ctx, &peer_psig, &peer_pubnonce,
                                    &peer_pubkey, &session))
        return 0;

    /* 7. Create our own partial sig */
    secp256k1_musig_partial_sig my_psig;
    if (!musig_create_partial_sig(ch->ctx, &my_psig, my_secnonce,
                                    &ch->local_funding_keypair, &session))
        return 0;

    /* 8. Aggregate both partial sigs in correct order */
    secp256k1_musig_partial_sig sigs[2];
    if (ch->local_funding_signer_idx == 0) {
        sigs[0] = my_psig;
        sigs[1] = peer_psig;
    } else {
        sigs[0] = peer_psig;
        sigs[1] = my_psig;
    }

    if (!musig_aggregate_partial_sigs(ch->ctx, full_sig64_out, &session, sigs, 2))
        return 0;

    ch->remote_nonce_next++;
    return 1;
}

/* ---- HTLC basepoints ---- */

int channel_set_local_htlc_basepoint(channel_t *ch,
                                       const unsigned char *htlc_secret32) {
    memcpy(ch->local_htlc_basepoint_secret, htlc_secret32, 32);
    if (!secp256k1_ec_pubkey_create(ch->ctx, &ch->local_htlc_basepoint,
                                     htlc_secret32))
        return 0;
    return 1;
}

void channel_set_remote_htlc_basepoint(channel_t *ch,
                                         const secp256k1_pubkey *htlc_basepoint) {
    ch->remote_htlc_basepoint = *htlc_basepoint;
}

/* ---- HTLC operations ---- */

int channel_add_htlc(channel_t *ch, htlc_direction_t direction,
                      uint64_t amount_sats, const unsigned char *payment_hash32,
                      uint32_t cltv_expiry, uint64_t *htlc_id_out) {
    if (ch->n_htlcs >= MAX_HTLCS)
        return 0;
    if (ch->commitment_number + 1 >= CHANNEL_MAX_SECRETS)
        return 0;  /* commitment number would overflow storage */

    /* Reject HTLC amount below dust */
    if (amount_sats < CHANNEL_DUST_LIMIT_SATS)
        return 0;

    /* Check sufficient balance from offerer + reserve */
    if (direction == HTLC_OFFERED) {
        if (amount_sats > ch->local_amount)
            return 0;
        if (ch->local_amount - amount_sats < CHANNEL_RESERVE_SATS)
            return 0;
        ch->local_amount -= amount_sats;
    } else {
        if (amount_sats > ch->remote_amount)
            return 0;
        if (ch->remote_amount - amount_sats < CHANNEL_RESERVE_SATS)
            return 0;
        ch->remote_amount -= amount_sats;
    }

    /* Dynamic fee: each HTLC adds 43 vB to commitment tx */
    uint64_t per_htlc_fee = (ch->fee_rate_sat_per_kvb * 43 + 999) / 1000;
    uint64_t *funder_bal = ch->funder_is_local ? &ch->local_amount : &ch->remote_amount;
    if (*funder_bal < per_htlc_fee) {
        /* Rollback HTLC amount deduction */
        if (direction == HTLC_OFFERED) ch->local_amount += amount_sats;
        else ch->remote_amount += amount_sats;
        return 0;
    }
    *funder_bal -= per_htlc_fee;

    htlc_t *h = &ch->htlcs[ch->n_htlcs++];
    h->direction = direction;
    h->state = HTLC_STATE_ACTIVE;
    h->amount_sats = amount_sats;
    memcpy(h->payment_hash, payment_hash32, 32);
    memset(h->payment_preimage, 0, 32);
    h->cltv_expiry = cltv_expiry;
    h->id = ch->next_htlc_id++;

    if (htlc_id_out)
        *htlc_id_out = h->id;

    ch->commitment_number++;
    channel_generate_local_pcs(ch, ch->commitment_number + 1);
    return 1;
}

int channel_fulfill_htlc(channel_t *ch, uint64_t htlc_id,
                           const unsigned char *preimage32) {
    if (ch->commitment_number + 1 >= CHANNEL_MAX_SECRETS)
        return 0;
    /* Find HTLC by id */
    htlc_t *h = NULL;
    for (size_t i = 0; i < ch->n_htlcs; i++) {
        if (ch->htlcs[i].id == htlc_id && ch->htlcs[i].state == HTLC_STATE_ACTIVE) {
            h = &ch->htlcs[i];
            break;
        }
    }
    if (!h) return 0;

    /* Verify SHA256(preimage) == payment_hash */
    unsigned char computed_hash[32];
    sha256(preimage32, 32, computed_hash);
    if (memcmp(computed_hash, h->payment_hash, 32) != 0)
        return 0;

    /* Credit the recipient */
    if (h->direction == HTLC_OFFERED) {
        /* Local offered -> remote is recipient */
        ch->remote_amount += h->amount_sats;
    } else {
        /* Remote offered -> local is recipient */
        ch->local_amount += h->amount_sats;
    }

    /* Refund per-HTLC fee to funder */
    uint64_t per_htlc_fee = (ch->fee_rate_sat_per_kvb * 43 + 999) / 1000;
    if (ch->funder_is_local) ch->local_amount += per_htlc_fee;
    else ch->remote_amount += per_htlc_fee;

    memcpy(h->payment_preimage, preimage32, 32);
    h->state = HTLC_STATE_FULFILLED;
    ch->commitment_number++;
    channel_generate_local_pcs(ch, ch->commitment_number + 1);
    return 1;
}

int channel_fail_htlc(channel_t *ch, uint64_t htlc_id) {
    if (ch->commitment_number + 1 >= CHANNEL_MAX_SECRETS)
        return 0;
    /* Find HTLC by id */
    htlc_t *h = NULL;
    for (size_t i = 0; i < ch->n_htlcs; i++) {
        if (ch->htlcs[i].id == htlc_id && ch->htlcs[i].state == HTLC_STATE_ACTIVE) {
            h = &ch->htlcs[i];
            break;
        }
    }
    if (!h) return 0;

    /* Return funds to offerer */
    if (h->direction == HTLC_OFFERED) {
        ch->local_amount += h->amount_sats;
    } else {
        ch->remote_amount += h->amount_sats;
    }

    /* Refund per-HTLC fee to funder */
    uint64_t per_htlc_fee = (ch->fee_rate_sat_per_kvb * 43 + 999) / 1000;
    if (ch->funder_is_local) ch->local_amount += per_htlc_fee;
    else ch->remote_amount += per_htlc_fee;

    h->state = HTLC_STATE_FAILED;
    ch->commitment_number++;
    channel_generate_local_pcs(ch, ch->commitment_number + 1);
    return 1;
}

/* ---- HTLC timeout enforcement ---- */

int channel_check_htlc_timeouts(channel_t *ch, uint32_t current_height) {
    int failed = 0;
    for (size_t i = 0; i < ch->n_htlcs; i++) {
        if (ch->htlcs[i].state == HTLC_STATE_ACTIVE &&
            ch->htlcs[i].cltv_expiry > 0 &&
            current_height >= ch->htlcs[i].cltv_expiry) {
            channel_fail_htlc(ch, ch->htlcs[i].id);
            failed++;
        }
    }
    return failed;
}

/* ---- Cooperative close ---- */

int channel_build_cooperative_close_tx(
    const channel_t *ch,
    tx_buf_t *close_tx_out,
    unsigned char *txid_out32,
    const secp256k1_keypair *remote_keypair,
    const tx_output_t *outputs,
    size_t n_outputs)
{
    /* 1. Build unsigned tx spending the channel funding UTXO */
    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 256);
    unsigned char display_txid[32];

    if (!build_unsigned_tx(&unsigned_tx, txid_out32 ? display_txid : NULL,
                            ch->funding_txid, ch->funding_vout,
                            0xFFFFFFFEu,
                            outputs, n_outputs)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    if (txid_out32) {
        memcpy(txid_out32, display_txid, 32);
        reverse_bytes(txid_out32, 32);  /* display -> internal */
    }

    /* 2. Compute BIP-341 key-path sighash */
    unsigned char sighash[32];
    if (!compute_taproot_sighash(sighash, unsigned_tx.data, unsigned_tx.len,
                                  0, ch->funding_spk, ch->funding_spk_len,
                                  ch->funding_amount, 0xFFFFFFFEu)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* 3. Sign with 2-of-2 MuSig (same pattern as channel_sign_commitment) */
    secp256k1_keypair kps[2];
    if (ch->local_funding_signer_idx == 0) {
        kps[0] = ch->local_funding_keypair;
        kps[1] = *remote_keypair;
    } else {
        kps[0] = *remote_keypair;
        kps[1] = ch->local_funding_keypair;
    }

    musig_keyagg_t keyagg_copy = ch->funding_keyagg;
    unsigned char sig64[64];
    if (!musig_sign_taproot(ch->ctx, sig64, sighash, kps, 2,
                             &keyagg_copy, NULL)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* 4. Finalize */
    if (!finalize_signed_tx(close_tx_out, unsigned_tx.data, unsigned_tx.len,
                              sig64)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    tx_buf_free(&unsigned_tx);
    return 1;
}

/* ---- Channel update ---- */

int channel_update(channel_t *ch, int64_t delta_sats) {
    /* Positive delta: local pays remote. Negative: remote pays local. */
    if (delta_sats > 0 && (uint64_t)delta_sats > ch->local_amount)
        return 0;
    if (delta_sats < 0 && (uint64_t)(-delta_sats) > ch->remote_amount)
        return 0;

    ch->local_amount = (uint64_t)((int64_t)ch->local_amount - delta_sats);
    ch->remote_amount = (uint64_t)((int64_t)ch->remote_amount + delta_sats);
    ch->commitment_number++;
    channel_generate_local_pcs(ch, ch->commitment_number + 1);
    return 1;
}

void channel_update_funding(channel_t *ch,
                              const unsigned char *new_funding_txid,
                              uint32_t new_funding_vout,
                              uint64_t new_funding_amount,
                              const unsigned char *new_funding_spk,
                              size_t new_funding_spk_len) {
    memcpy(ch->funding_txid, new_funding_txid, 32);
    ch->funding_vout = new_funding_vout;
    ch->funding_amount = new_funding_amount;
    memcpy(ch->funding_spk, new_funding_spk, new_funding_spk_len);
    ch->funding_spk_len = new_funding_spk_len;
}

/* ---- HTLC resolution transactions ---- */

/* Helper: rebuild HTLC taptree leaves for a given HTLC at htlc_index.
   Derives keys from the channel's commitment state at commitment_number. */
static int channel_rebuild_htlc_leaves(
    const channel_t *ch, size_t htlc_index, uint64_t commit_num,
    tapscript_leaf_t *success_leaf, tapscript_leaf_t *timeout_leaf,
    secp256k1_xonly_pubkey *revocation_xonly_out)
{
    const htlc_t *h = &ch->htlcs[htlc_index];

    secp256k1_pubkey pcp;
    if (!channel_get_per_commitment_point(ch, commit_num, &pcp))
        return 0;

    /* Derive revocation pubkey */
    secp256k1_pubkey revocation_pubkey;
    if (!channel_derive_revocation_pubkey(ch->ctx, &revocation_pubkey,
                                            &ch->remote_revocation_basepoint, &pcp))
        return 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, revocation_xonly_out, NULL,
                                             &revocation_pubkey))
        return 0;

    /* Derive HTLC keys */
    secp256k1_pubkey local_htlc_pub, remote_htlc_pub;
    if (!channel_derive_pubkey(ch->ctx, &local_htlc_pub,
                                &ch->local_htlc_basepoint, &pcp))
        return 0;
    if (!channel_derive_pubkey(ch->ctx, &remote_htlc_pub,
                                &ch->remote_htlc_basepoint, &pcp))
        return 0;

    secp256k1_xonly_pubkey local_htlc_xonly, remote_htlc_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &local_htlc_xonly, NULL,
                                             &local_htlc_pub))
        return 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &remote_htlc_xonly, NULL,
                                             &remote_htlc_pub))
        return 0;

    /* Build leaves based on direction */
    if (h->direction == HTLC_OFFERED) {
        if (!tapscript_build_htlc_offered_success(success_leaf,
                h->payment_hash, &remote_htlc_xonly, ch->ctx))
            return 0;
        if (!tapscript_build_htlc_offered_timeout(timeout_leaf,
                h->cltv_expiry, ch->to_self_delay,
                &local_htlc_xonly, ch->ctx))
            return 0;
    } else {
        if (!tapscript_build_htlc_received_success(success_leaf,
                h->payment_hash, ch->to_self_delay,
                &local_htlc_xonly, ch->ctx))
            return 0;
        if (!tapscript_build_htlc_received_timeout(timeout_leaf,
                h->cltv_expiry, &remote_htlc_xonly, ch->ctx))
            return 0;
    }

    return 1;
}

int channel_build_htlc_success_tx(const channel_t *ch, tx_buf_t *signed_tx_out,
    const unsigned char *commitment_txid, uint32_t htlc_vout,
    uint64_t htlc_amount, const unsigned char *htlc_spk, size_t htlc_spk_len,
    size_t htlc_index)
{
    const htlc_t *h = &ch->htlcs[htlc_index];

    /* Rebuild taptree leaves */
    tapscript_leaf_t success_leaf, timeout_leaf;
    secp256k1_xonly_pubkey revocation_xonly;
    if (!channel_rebuild_htlc_leaves(ch, htlc_index, ch->commitment_number,
                                      &success_leaf, &timeout_leaf,
                                      &revocation_xonly))
        return 0;

    /* Determine nSequence:
       - Received HTLC success: local is broadcaster, CSV delay applies
       - Offered HTLC success: remote claims, no CSV */
    uint32_t nsequence;
    if (h->direction == HTLC_RECEIVED) {
        nsequence = ch->to_self_delay;  /* CSV for broadcaster's claim */
    } else {
        nsequence = 0xFFFFFFFE;  /* no CSV, but enable locktime */
    }

    /* Build destination output: P2TR(local_payment_basepoint) key-path-only */
    secp256k1_xonly_pubkey dest_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &dest_xonly, NULL,
                                             &ch->local_payment_basepoint))
        return 0;

    unsigned char dest_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ch->ctx, dest_ser, &dest_xonly))
        return 0;
    unsigned char dest_tweak[32];
    sha256_tagged("TapTweak", dest_ser, 32, dest_tweak);

    secp256k1_pubkey dest_tweaked_full;
    if (!secp256k1_xonly_pubkey_tweak_add(ch->ctx, &dest_tweaked_full,
                                            &dest_xonly, dest_tweak))
        return 0;
    secp256k1_xonly_pubkey dest_tweaked;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &dest_tweaked, NULL,
                                             &dest_tweaked_full))
        return 0;

    uint64_t htlc_fee = (ch->fee_rate_sat_per_kvb * 180 + 999) / 1000;
    uint64_t out_amount = htlc_amount > htlc_fee ? htlc_amount - htlc_fee : 0;
    tx_output_t output;
    build_p2tr_script_pubkey(output.script_pubkey, &dest_tweaked);
    output.script_pubkey_len = 34;
    output.amount_sats = out_amount;

    /* Build unsigned tx */
    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 256);
    unsigned char txid[32];
    if (!build_unsigned_tx(&unsigned_tx, txid,
                            commitment_txid, htlc_vout,
                            nsequence, &output, 1)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* Compute tapscript sighash for success leaf */
    unsigned char sighash[32];
    if (!compute_tapscript_sighash(sighash, unsigned_tx.data, unsigned_tx.len,
                                    0, htlc_spk, htlc_spk_len,
                                    htlc_amount, nsequence,
                                    &success_leaf)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* Derive signing key */
    secp256k1_pubkey pcp;
    if (!channel_get_per_commitment_point(ch, ch->commitment_number, &pcp)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    unsigned char signing_key[32];
    const unsigned char *base_secret;
    if (h->direction == HTLC_RECEIVED) {
        /* Local claims received HTLC with local_htlc_key */
        base_secret = ch->local_htlc_basepoint_secret;
    } else {
        /* Remote claims offered HTLC - for testing, we use remote's key.
           In practice, local_htlc is used since we hold the secret for our own
           success path. But offered success is remote's path, so this function
           would only be called by the remote side. For testing symmetry,
           we sign with local_htlc_basepoint_secret (caller sets it up accordingly). */
        base_secret = ch->local_htlc_basepoint_secret;
    }
    if (!channel_derive_privkey(ch->ctx, signing_key, base_secret, &pcp)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ch->ctx, &kp, signing_key)) {
        secure_zero(signing_key, 32);
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    unsigned char sig64[64];
    if (!secp256k1_schnorrsig_sign32(ch->ctx, sig64, sighash, &kp, NULL)) {
        secure_zero(signing_key, 32);
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* Build 2-leaf control block */
    int output_parity;
    tapscript_leaf_t htlc_leaves[2] = { success_leaf, timeout_leaf };
    unsigned char htlc_merkle[32];
    tapscript_merkle_root(htlc_merkle, htlc_leaves, 2);

    secp256k1_xonly_pubkey htlc_tweaked;
    tapscript_tweak_pubkey(ch->ctx, &htlc_tweaked, &output_parity,
                            &revocation_xonly, htlc_merkle);

    unsigned char control_block[65];
    size_t cb_len;
    tapscript_build_control_block_2leaf(control_block, &cb_len,
                                         output_parity, &revocation_xonly,
                                         &timeout_leaf, ch->ctx);

    /* Finalize with 4-item witness: [sig, preimage, script, control_block] */
    finalize_script_path_tx_preimage(signed_tx_out,
        unsigned_tx.data, unsigned_tx.len,
        sig64, h->payment_preimage, 32,
        success_leaf.script, success_leaf.script_len,
        control_block, cb_len);

    secure_zero(signing_key, 32);
    tx_buf_free(&unsigned_tx);
    return 1;
}

int channel_build_htlc_timeout_tx(const channel_t *ch, tx_buf_t *signed_tx_out,
    const unsigned char *commitment_txid, uint32_t htlc_vout,
    uint64_t htlc_amount, const unsigned char *htlc_spk, size_t htlc_spk_len,
    size_t htlc_index)
{
    const htlc_t *h = &ch->htlcs[htlc_index];

    /* Rebuild taptree leaves */
    tapscript_leaf_t success_leaf, timeout_leaf;
    secp256k1_xonly_pubkey revocation_xonly;
    if (!channel_rebuild_htlc_leaves(ch, htlc_index, ch->commitment_number,
                                      &success_leaf, &timeout_leaf,
                                      &revocation_xonly))
        return 0;

    /* Determine nSequence and nLocktime:
       - Offered HTLC timeout: local is broadcaster, CSV delay applies, CLTV via nLocktime
       - Received HTLC timeout: remote reclaims, no CSV, CLTV via nLocktime */
    uint32_t nsequence;
    if (h->direction == HTLC_OFFERED) {
        nsequence = ch->to_self_delay;  /* CSV for broadcaster's reclaim */
    } else {
        nsequence = 0xFFFFFFFE;  /* no CSV, but enable locktime */
    }

    /* Build destination output */
    secp256k1_xonly_pubkey dest_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &dest_xonly, NULL,
                                             &ch->local_payment_basepoint))
        return 0;

    unsigned char dest_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ch->ctx, dest_ser, &dest_xonly))
        return 0;
    unsigned char dest_tweak[32];
    sha256_tagged("TapTweak", dest_ser, 32, dest_tweak);

    secp256k1_pubkey dest_tweaked_full;
    if (!secp256k1_xonly_pubkey_tweak_add(ch->ctx, &dest_tweaked_full,
                                            &dest_xonly, dest_tweak))
        return 0;
    secp256k1_xonly_pubkey dest_tweaked;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &dest_tweaked, NULL,
                                             &dest_tweaked_full))
        return 0;

    uint64_t htlc_fee = (ch->fee_rate_sat_per_kvb * 180 + 999) / 1000;
    uint64_t out_amount = htlc_amount > htlc_fee ? htlc_amount - htlc_fee : 0;
    tx_output_t output;
    build_p2tr_script_pubkey(output.script_pubkey, &dest_tweaked);
    output.script_pubkey_len = 34;
    output.amount_sats = out_amount;

    /* Build unsigned tx with nLocktime = cltv_expiry */
    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 256);
    unsigned char txid[32];
    if (!build_unsigned_tx_locktime(&unsigned_tx, txid,
                                     commitment_txid, htlc_vout,
                                     nsequence, h->cltv_expiry,
                                     &output, 1)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* Compute tapscript sighash for timeout leaf */
    unsigned char sighash[32];
    if (!compute_tapscript_sighash(sighash, unsigned_tx.data, unsigned_tx.len,
                                    0, htlc_spk, htlc_spk_len,
                                    htlc_amount, nsequence,
                                    &timeout_leaf)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* Derive signing key */
    secp256k1_pubkey pcp;
    if (!channel_get_per_commitment_point(ch, ch->commitment_number, &pcp)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    unsigned char signing_key[32];
    if (!channel_derive_privkey(ch->ctx, signing_key,
                                 ch->local_htlc_basepoint_secret, &pcp)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ch->ctx, &kp, signing_key)) {
        secure_zero(signing_key, 32);
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    unsigned char sig64[64];
    if (!secp256k1_schnorrsig_sign32(ch->ctx, sig64, sighash, &kp, NULL)) {
        secure_zero(signing_key, 32);
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* Build 2-leaf control block (spending timeout, sibling = success) */
    int output_parity;
    tapscript_leaf_t htlc_leaves[2] = { success_leaf, timeout_leaf };
    unsigned char htlc_merkle[32];
    tapscript_merkle_root(htlc_merkle, htlc_leaves, 2);

    secp256k1_xonly_pubkey htlc_tweaked;
    tapscript_tweak_pubkey(ch->ctx, &htlc_tweaked, &output_parity,
                            &revocation_xonly, htlc_merkle);

    unsigned char control_block[65];
    size_t cb_len;
    tapscript_build_control_block_2leaf(control_block, &cb_len,
                                         output_parity, &revocation_xonly,
                                         &success_leaf, ch->ctx);

    /* Finalize with 3-item witness: [sig, script, control_block] */
    finalize_script_path_tx(signed_tx_out,
        unsigned_tx.data, unsigned_tx.len,
        sig64, timeout_leaf.script, timeout_leaf.script_len,
        control_block, cb_len);

    secure_zero(signing_key, 32);
    tx_buf_free(&unsigned_tx);
    return 1;
}

int channel_build_htlc_penalty_tx(const channel_t *ch, tx_buf_t *penalty_tx_out,
    const unsigned char *commitment_txid, uint32_t htlc_vout,
    uint64_t htlc_amount, const unsigned char *htlc_spk, size_t htlc_spk_len,
    uint64_t old_commitment_num, size_t htlc_index,
    const unsigned char *anchor_spk, size_t anchor_spk_len)
{
    /* 1. Retrieve per_commitment_secret from received revocations */
    unsigned char pcp_secret[32];
    if (!channel_get_received_revocation(ch, old_commitment_num, pcp_secret))
        return 0;

    /* 2. Compute per_commitment_point from secret */
    secp256k1_pubkey pcp;
    if (!secp256k1_ec_pubkey_create(ch->ctx, &pcp, pcp_secret))
        return 0;

    /* 3. Derive revocation privkey */
    unsigned char revocation_privkey[32];
    if (!channel_derive_revocation_privkey(ch->ctx, revocation_privkey,
                                             ch->local_revocation_basepoint_secret,
                                             pcp_secret,
                                             &ch->local_revocation_basepoint, &pcp))
        return 0;

    /* 4. Rebuild HTLC taptree to get the merkle root for the tweak.
       We need to derive the HTLC keys from the counterparty's perspective.
       The remote channel published this commitment, so "local" in the scripts
       is remote's keys and "remote" is our keys. */
    secp256k1_pubkey remote_htlc_pub, local_htlc_pub;
    if (!channel_derive_pubkey(ch->ctx, &remote_htlc_pub,
                                &ch->remote_htlc_basepoint, &pcp))
        return 0;
    if (!channel_derive_pubkey(ch->ctx, &local_htlc_pub,
                                &ch->local_htlc_basepoint, &pcp))
        return 0;

    /* Note: from the remote's commitment perspective, their "local" htlc key
       uses remote_htlc_basepoint and their "remote" htlc key uses local_htlc_basepoint */

    secp256k1_xonly_pubkey remote_htlc_xonly, local_htlc_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &remote_htlc_xonly, NULL,
                                             &remote_htlc_pub))
        return 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &local_htlc_xonly, NULL,
                                             &local_htlc_pub))
        return 0;

    /* Build leaves. From the broadcaster's (remote's) perspective:
       - "local_htlcpubkey" = remote_htlc_pub (broadcaster's key)
       - "remote_htlcpubkey" = local_htlc_pub (non-broadcaster's key) */
    const htlc_t *h = &ch->htlcs[htlc_index];
    tapscript_leaf_t success_leaf, timeout_leaf;

    if (h->direction == HTLC_OFFERED) {
        /* From our perspective this is offered. On remote's commitment,
           this appears as a received HTLC. */
        if (!tapscript_build_htlc_received_success(&success_leaf,
                h->payment_hash, ch->to_self_delay,
                &remote_htlc_xonly, ch->ctx))
            return 0;
        if (!tapscript_build_htlc_received_timeout(&timeout_leaf,
                h->cltv_expiry, &local_htlc_xonly, ch->ctx))
            return 0;
    } else {
        /* From our perspective this is received. On remote's commitment,
           this appears as an offered HTLC. */
        if (!tapscript_build_htlc_offered_success(&success_leaf,
                h->payment_hash, &local_htlc_xonly, ch->ctx))
            return 0;
        if (!tapscript_build_htlc_offered_timeout(&timeout_leaf,
                h->cltv_expiry, ch->to_self_delay,
                &remote_htlc_xonly, ch->ctx))
            return 0;
    }

    tapscript_leaf_t htlc_leaves[2] = { success_leaf, timeout_leaf };
    unsigned char htlc_merkle[32];
    tapscript_merkle_root(htlc_merkle, htlc_leaves, 2);

    /* 5. Derive revocation pubkey and compute tap tweak */
    secp256k1_pubkey revocation_pubkey;
    if (!secp256k1_ec_pubkey_create(ch->ctx, &revocation_pubkey, revocation_privkey))
        return 0;

    secp256k1_xonly_pubkey revocation_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &revocation_xonly, NULL,
                                             &revocation_pubkey))
        return 0;

    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ch->ctx, internal_ser, &revocation_xonly))
        return 0;

    unsigned char tweak_data[64];
    memcpy(tweak_data, internal_ser, 32);
    memcpy(tweak_data + 32, htlc_merkle, 32);
    unsigned char taptweak[32];
    sha256_tagged("TapTweak", tweak_data, 64, taptweak);

    /* Create keypair and apply taproot tweak */
    secp256k1_keypair tweaked_kp;
    if (!secp256k1_keypair_create(ch->ctx, &tweaked_kp, revocation_privkey))
        return 0;
    if (!secp256k1_keypair_xonly_tweak_add(ch->ctx, &tweaked_kp, taptweak))
        return 0;

    /* 6. Build output */
    secp256k1_xonly_pubkey local_pay_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &local_pay_xonly, NULL,
                                             &ch->local_payment_basepoint))
        return 0;

    unsigned char out_internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ch->ctx, out_internal_ser, &local_pay_xonly))
        return 0;
    unsigned char out_tweak[32];
    sha256_tagged("TapTweak", out_internal_ser, 32, out_tweak);

    secp256k1_pubkey out_tweaked_full;
    if (!secp256k1_xonly_pubkey_tweak_add(ch->ctx, &out_tweaked_full,
                                            &local_pay_xonly, out_tweak))
        return 0;
    secp256k1_xonly_pubkey out_tweaked;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &out_tweaked, NULL,
                                             &out_tweaked_full))
        return 0;

    /* Fee: with P2A anchor ~165 vB, without ~152 vB */
    int has_anchor = (anchor_spk && anchor_spk_len == P2A_SPK_LEN);
    uint64_t vsize = has_anchor ? 165 : 152;
    uint64_t anchor_amount = ANCHOR_OUTPUT_AMOUNT;
    uint64_t htlc_penalty_fee = (ch->fee_rate_sat_per_kvb * vsize + 999) / 1000;
    uint64_t deduction = htlc_penalty_fee + (has_anchor ? anchor_amount : 0);
    uint64_t penalty_amount = htlc_amount > deduction ? htlc_amount - deduction : 0;

    tx_output_t outputs[2];
    size_t n_outputs = 1;
    build_p2tr_script_pubkey(outputs[0].script_pubkey, &out_tweaked);
    outputs[0].script_pubkey_len = 34;
    outputs[0].amount_sats = penalty_amount;

    if (has_anchor) {
        memcpy(outputs[1].script_pubkey, anchor_spk, P2A_SPK_LEN);
        outputs[1].script_pubkey_len = P2A_SPK_LEN;
        outputs[1].amount_sats = anchor_amount;
        n_outputs = 2;
    }

    /* 7. Build unsigned penalty tx */
    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 256);
    unsigned char penalty_txid[32];
    if (!build_unsigned_tx(&unsigned_tx, penalty_txid,
                            commitment_txid, htlc_vout,
                            0xFFFFFFFE, outputs, n_outputs)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* 8. Compute key-path sighash + sign */
    unsigned char sighash[32];
    if (!compute_taproot_sighash(sighash, unsigned_tx.data, unsigned_tx.len,
                                  0, htlc_spk, htlc_spk_len,
                                  htlc_amount, 0xFFFFFFFE)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    unsigned char sig64[64];
    if (!secp256k1_schnorrsig_sign32(ch->ctx, sig64, sighash, &tweaked_kp, NULL)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* 9. Finalize */
    if (!finalize_signed_tx(penalty_tx_out, unsigned_tx.data, unsigned_tx.len,
                              sig64)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    tx_buf_free(&unsigned_tx);
    secure_zero(revocation_privkey, 32);
    secure_zero(pcp_secret, 32);
    return 1;
}
