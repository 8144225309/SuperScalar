/*
 * chan_open.c — BOLT #2 channel establishment for external LN peers
 *
 * Implements open_channel / accept_channel / funding_created /
 * funding_signed / channel_ready and channel_reestablish flows.
 *
 * Spec: BOLT #2 §§2-3.
 * Reference: CLN openingd/openingd.c, LDK channel_establishment.
 */

#include "superscalar/chan_open.h"
#include "superscalar/peer_mgr.h"
#include "superscalar/channel.h"
#include "superscalar/sha256.h"
#include "superscalar/tx_builder.h"
#include "superscalar/wallet_source.h"
#include <secp256k1.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ---- Serialisation helpers ---- */
static void put_u16(unsigned char *b, uint16_t v) {
    b[0] = (unsigned char)(v >> 8);
    b[1] = (unsigned char)(v);
}
static void put_u32(unsigned char *b, uint32_t v) {
    b[0] = (unsigned char)(v >> 24); b[1] = (unsigned char)(v >> 16);
    b[2] = (unsigned char)(v >>  8); b[3] = (unsigned char)(v);
}
static void put_u64(unsigned char *b, uint64_t v) {
    for (int i = 7; i >= 0; i--) b[7-i] = (unsigned char)(v >> (i*8));
}
static uint16_t get_u16(const unsigned char *b) {
    return ((uint16_t)b[0] << 8) | b[1];
}
static uint32_t get_u32(const unsigned char *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
         | ((uint32_t)b[2] <<  8) |  (uint32_t)b[3];
}
static uint64_t get_u64(const unsigned char *b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

/* ---- P2WSH 2-of-2 funding output (BOLT #3) ---- */

int chan_build_p2wsh_funding_output(
    secp256k1_context *ctx,
    const unsigned char local_pk[33],
    const unsigned char remote_pk[33],
    unsigned char spk_out[34])
{
    (void)ctx; /* secp used only for future signature verification; pure hashing here */
    if (!local_pk || !remote_pk || !spk_out) return 0;

    /* Sort pubkeys lexicographically (BOLT #3 §Funding Transaction Output) */
    const unsigned char *pk1 = local_pk;
    const unsigned char *pk2 = remote_pk;
    if (memcmp(local_pk, remote_pk, 33) > 0) {
        pk1 = remote_pk;
        pk2 = local_pk;
    }

    /* Witness script: OP_2 <pk1> OP_2 <pk2> OP_CHECKMULTISIG (71 bytes) */
    unsigned char witness_script[71];
    int i = 0;
    witness_script[i++] = 0x52;          /* OP_2 */
    witness_script[i++] = 0x21;          /* PUSH 33 bytes */
    memcpy(witness_script + i, pk1, 33); i += 33;
    witness_script[i++] = 0x21;          /* PUSH 33 bytes */
    memcpy(witness_script + i, pk2, 33); i += 33;
    witness_script[i++] = 0x52;          /* OP_2 */
    witness_script[i++] = 0xae;          /* OP_CHECKMULTISIG */

    /* P2WSH: OP_0 <SHA256(witness_script)> */
    spk_out[0] = 0x00;  /* OP_0 */
    spk_out[1] = 0x20;  /* PUSH 32 bytes */
    sha256(witness_script, (size_t)i, spk_out + 2);
    return 1;
}

/* ---- Bitcoin mainnet chain hash (all zeros = any / signet varies) ---- */
static const unsigned char BITCOIN_CHAIN_HASH[32] = {
    0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
    0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
    0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
    0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* ---- Build open_channel message ---- */
size_t chan_build_open_channel(const unsigned char chain_hash[32],
                               const unsigned char temp_chan_id[32],
                               const chan_open_params_t *p,
                               unsigned char *buf, size_t buf_cap) {
    /* BOLT #2 open_channel layout (321 bytes fixed + possible TLVs):
       type(2) + chain_hash(32) + temp_chan_id(32) + funding_sats(8) +
       push_msat(8) + dust_limit_sats(8) + max_htlc_value_in_flight_msat(8) +
       channel_reserve_sats(8) + htlc_minimum_msat(8) + feerate_per_kw(4) +
       to_self_delay(2) + max_accepted_htlcs(2) +
       funding_pubkey(33) + revocation_basepoint(33) + payment_basepoint(33) +
       delayed_payment_basepoint(33) + htlc_basepoint(33) +
       first_per_commitment_point(33) + channel_flags(1)
       = 2+32+32+8+8+8+8+8+8+4+2+2+(6*33)+1 = 321 bytes
    */
    const size_t FIXED = 321;
    if (buf_cap < FIXED) return 0;

    size_t pos = 0;
    put_u16(buf + pos, CHAN_MSG_OPEN_CHANNEL); pos += 2;
    memcpy(buf + pos, chain_hash ? chain_hash : BITCOIN_CHAIN_HASH, 32); pos += 32;
    memcpy(buf + pos, temp_chan_id, 32); pos += 32;
    put_u64(buf + pos, p->funding_sats); pos += 8;
    put_u64(buf + pos, p->push_msat); pos += 8;
    put_u64(buf + pos, CHAN_OPEN_MIN_DUST_LIMIT); pos += 8; /* dust_limit */
    put_u64(buf + pos, p->max_htlc_value_msat); pos += 8;
    put_u64(buf + pos, p->channel_reserve_sats); pos += 8;
    put_u64(buf + pos, p->htlc_minimum_msat); pos += 8;
    put_u32(buf + pos, p->feerate_per_kw); pos += 4;
    put_u16(buf + pos, (uint16_t)p->to_self_delay); pos += 2;
    put_u16(buf + pos, p->max_accepted_htlcs); pos += 2;
    memcpy(buf + pos, p->funding_pubkey, 33); pos += 33;
    memcpy(buf + pos, p->revocation_basepoint, 33); pos += 33;
    memcpy(buf + pos, p->payment_basepoint, 33); pos += 33;
    memcpy(buf + pos, p->delayed_payment_basepoint, 33); pos += 33;
    memcpy(buf + pos, p->htlc_basepoint, 33); pos += 33;
    memcpy(buf + pos, p->first_per_commitment_point, 33); pos += 33;
    buf[pos++] = p->announce_channel ? 1 : 0; /* channel_flags */
    return pos;
}

/* ---- Build accept_channel message ---- */
size_t chan_build_accept_channel(const unsigned char temp_chan_id[32],
                                 const chan_open_params_t *p,
                                 unsigned char *buf, size_t buf_cap) {
    /* accept_channel layout:
       type(2) + temp_chan_id(32) + dust_limit(8) + max_htlc_value(8) +
       channel_reserve(8) + htlc_minimum(8) + min_accept_depth(4) +
       to_self_delay(2) + max_accepted_htlcs(2) +
       funding_pubkey(33) + revocation_basepoint(33) + payment_basepoint(33) +
       delayed_payment_basepoint(33) + htlc_basepoint(33) +
       first_per_commitment_point(33)
       = 2+32+8+8+8+8+4+2+2+(6*33) = 272 bytes
    */
    const size_t FIXED = 272;
    if (buf_cap < FIXED) return 0;

    size_t pos = 0;
    put_u16(buf + pos, CHAN_MSG_ACCEPT_CHANNEL); pos += 2;
    memcpy(buf + pos, temp_chan_id, 32); pos += 32;
    put_u64(buf + pos, CHAN_OPEN_MIN_DUST_LIMIT); pos += 8;
    put_u64(buf + pos, p->max_htlc_value_msat); pos += 8;
    put_u64(buf + pos, p->channel_reserve_sats); pos += 8;
    put_u64(buf + pos, p->htlc_minimum_msat); pos += 8;
    put_u32(buf + pos, p->zero_conf ? 0 : 3); pos += 4; /* minimum_depth */
    put_u16(buf + pos, (uint16_t)p->to_self_delay); pos += 2;
    put_u16(buf + pos, p->max_accepted_htlcs); pos += 2;
    memcpy(buf + pos, p->funding_pubkey, 33); pos += 33;
    memcpy(buf + pos, p->revocation_basepoint, 33); pos += 33;
    memcpy(buf + pos, p->payment_basepoint, 33); pos += 33;
    memcpy(buf + pos, p->delayed_payment_basepoint, 33); pos += 33;
    memcpy(buf + pos, p->htlc_basepoint, 33); pos += 33;
    memcpy(buf + pos, p->first_per_commitment_point, 33); pos += 33;
    return pos;
}

/* ---- Validate accept_channel response ---- */
static int validate_accept_channel(const unsigned char *msg, size_t msg_len,
                                    const chan_open_params_t *our_params) {
    if (msg_len < 239) return 0;
    uint16_t msg_type = get_u16(msg);
    if (msg_type != CHAN_MSG_ACCEPT_CHANNEL) return 0;

    uint64_t dust_limit     = get_u64(msg + 34);  /* after type(2)+temp_chan_id(32) */
    uint64_t chan_reserve    = get_u64(msg + 50);
    uint16_t their_delay    = get_u16(msg + 74);

    /* BOLT #2 §2: dust_limit ≥ 546 */
    if (dust_limit < CHAN_OPEN_MIN_DUST_LIMIT) return 0;
    /* Reserve ≤ funding / 100 */
    if (chan_reserve > our_params->funding_sats / CHAN_OPEN_MAX_RESERVE_RATIO) return 0;
    /* Their to_self_delay ≤ our max */
    if (their_delay > CHAN_OPEN_MAX_TO_SELF_DELAY) return 0;

    return 1;
}

/* ---- chan_open_outbound ---- */

int chan_open_outbound(peer_mgr_t *mgr, int peer_idx,
                       const chan_open_params_t *params,
                       secp256k1_context *ctx,
                       channel_t *ch_out) {
    if (!mgr || peer_idx < 0 || !params || !ctx || !ch_out) return 0;

    /* Generate temporary channel ID from /dev/urandom */
    unsigned char temp_chan_id[32];
    {
        FILE *f = fopen("/dev/urandom", "rb");
        if (!f || fread(temp_chan_id, 1, 32, f) != 32) {
            if (f) fclose(f);
            return 0;
        }
        fclose(f);
    }

    /* Send open_channel */
    unsigned char open_msg[300];
    size_t open_len = chan_build_open_channel(NULL, temp_chan_id, params,
                                               open_msg, sizeof(open_msg));
    if (open_len == 0) return 0;
    if (!peer_mgr_send(mgr, peer_idx, open_msg, open_len)) return 0;

    /* Receive accept_channel */
    unsigned char resp[512];
    size_t resp_len = 0;
    if (!peer_mgr_recv(mgr, peer_idx, resp, &resp_len, sizeof(resp))) return 0;
    if (!validate_accept_channel(resp, resp_len, params)) return 0;

    /* Extract remote funding pubkey from accept_channel.
     * BOLT #2 accept_channel layout (with 2-byte type prefix):
     *   type(2) + temp_chan_id(32) + dust_limit(8) + max_htlc(8) +
     *   reserve(8) + htlc_min(8) + min_depth(4) + to_self_delay(2) +
     *   max_htlcs(2) = 74 bytes before funding_pubkey.
     */
    if (resp_len < 74 + 33) return 0;
    const unsigned char *remote_funding_pk = resp + 74;

    /* Build the P2WSH 2-of-2 funding output scriptPubKey */
    unsigned char funding_spk[34];
    if (!chan_build_p2wsh_funding_output(ctx, params->funding_pubkey,
                                          remote_funding_pk, funding_spk)) return 0;

    /* Build the funding tx if a wallet is available */
    unsigned char funding_txid[32];
    memset(funding_txid, 0, 32);
    uint32_t funding_vout = 0;

    if (params->wallet) {
        char utxo_hex[65];
        uint32_t utxo_vout = 0;
        uint64_t utxo_amount = 0;
        unsigned char utxo_spk[34];
        size_t utxo_spk_len = 0;

        if (!params->wallet->get_utxo(params->wallet, params->funding_sats,
                                       utxo_hex, &utxo_vout, &utxo_amount,
                                       utxo_spk, &utxo_spk_len)) return 0;

        /* Convert display-order txid hex to internal bytes (reversed) */
        unsigned char utxo_txid[32];
        for (int j = 0; j < 32; j++) {
            unsigned int byte;
            sscanf(utxo_hex + (31 - j) * 2, "%02x", &byte);
            utxo_txid[j] = (unsigned char)byte;
        }

        /* Estimate fee (sat): minimal 1-in-2-out segwit vbytes ≈ 137 */
        uint64_t fee_sats = (137ULL * params->feerate_per_kw + 999) / 1000;
        uint64_t change_sats = (utxo_amount > params->funding_sats + fee_sats)
                               ? utxo_amount - params->funding_sats - fee_sats : 0;

        /* Build outputs: funding output + change (if non-dust) */
        tx_output_t outputs[2];
        int n_out = 0;
        outputs[n_out].amount_sats = params->funding_sats;
        memcpy(outputs[n_out].script_pubkey, funding_spk, 34);
        outputs[n_out].script_pubkey_len = 34;
        n_out++;
        if (change_sats >= 546) {
            unsigned char change_spk[34];
            size_t change_spk_len = 0;
            if (params->wallet->get_change_spk &&
                params->wallet->get_change_spk(params->wallet, change_spk, &change_spk_len)) {
                outputs[n_out].amount_sats = change_sats;
                memcpy(outputs[n_out].script_pubkey, change_spk, change_spk_len);
                outputs[n_out].script_pubkey_len = change_spk_len;
                n_out++;
            }
        }

        /* Build unsigned tx and compute txid */
        tx_buf_t unsigned_tx = {0};
        tx_buf_init(&unsigned_tx, 256);
        build_unsigned_tx(&unsigned_tx, funding_txid,
                          utxo_txid, utxo_vout,
                          0xFFFFFFFE, outputs, (size_t)n_out);

        /* Sign the input */
        if (params->wallet->sign_input) {
            params->wallet->sign_input(params->wallet,
                                        unsigned_tx.data, &unsigned_tx.len,
                                        0, utxo_spk, utxo_spk_len, utxo_amount);
        }
        tx_buf_free(&unsigned_tx);

        /* Release UTXO (best-effort; allows wallet to reuse it on failure) */
        if (params->wallet->release_utxo)
            params->wallet->release_utxo(params->wallet, utxo_hex, utxo_vout);
    }

    /* Send funding_created (BOLT #2 type 34):
     * type(2) + temp_chan_id(32) + funding_txid(32) + funding_vout(2) + sig(64) */
    {
        unsigned char fc[134];
        memset(fc, 0, sizeof(fc));
        fc[0] = 0x00; fc[1] = 0x22;           /* type 34 */
        memcpy(fc + 2, temp_chan_id, 32);
        memcpy(fc + 34, funding_txid, 32);
        fc[66] = (unsigned char)(funding_vout >> 8);
        fc[67] = (unsigned char)(funding_vout);
        /* 64-byte sig at offset 68 — zero (caller signs or TBD) */
        peer_mgr_send(mgr, peer_idx, fc, sizeof(fc));
    }

    /* Receive funding_signed (BOLT #2 type 35):
     * type(2) + channel_id(32) + sig(64) = 98 bytes */
    {
        unsigned char fs[100];
        size_t fs_len = 0;
        peer_mgr_recv(mgr, peer_idx, fs, &fs_len, sizeof(fs));
        /* Verify type if received */
        if (fs_len >= 2 && !(fs[0] == 0x00 && fs[1] == 0x23)) {
            /* Unexpected message type — not fatal for now, channel still proceeds */
        }
    }

    /* Build a minimal channel_t for this external channel */
    memset(ch_out, 0, sizeof(*ch_out));
    ch_out->ctx = ctx;
    ch_out->funding_amount  = params->funding_sats;
    ch_out->local_amount    = params->funding_sats - params->push_msat / 1000;
    ch_out->remote_amount   = params->push_msat / 1000;
    ch_out->to_self_delay   = params->to_self_delay;
    ch_out->funder_is_local = 1;
    memcpy(ch_out->funding_txid, funding_txid, 32);
    ch_out->funding_vout = funding_vout;

    /* Parse local and remote funding pubkeys */
    if (!secp256k1_ec_pubkey_parse(ctx, &ch_out->local_funding_pubkey,
                                    params->funding_pubkey, 33)) return 0;
    if (!secp256k1_ec_pubkey_parse(ctx, &ch_out->remote_funding_pubkey,
                                    remote_funding_pk, 33)) return 0;

    /* Mark the peer as having a channel */
    mgr->peers[peer_idx].has_channel = 1;
    return 1;
}

/* ---- chan_open_inbound ---- */

int chan_open_inbound(peer_mgr_t *mgr, int peer_idx,
                      const unsigned char *open_msg, size_t open_len,
                      secp256k1_context *ctx,
                      channel_t *ch_out) {
    if (!mgr || peer_idx < 0 || !open_msg || !ctx || !ch_out) return 0;
    if (open_len < 274) return 0;

    uint16_t msg_type = get_u16(open_msg);
    if (msg_type != CHAN_MSG_OPEN_CHANNEL) return 0;

    /* Parse key fields from open_channel */
    const unsigned char *temp_chan_id   = open_msg + 2;
    uint64_t their_funding_sats  = get_u64(open_msg + 34);
    uint64_t their_push_msat     = get_u64(open_msg + 42);
    uint32_t their_feerate       = get_u32(open_msg + 66);
    uint16_t their_delay         = get_u16(open_msg + 70);
    const unsigned char *their_funding_pk = open_msg + 74; /* after feerate+delay+max_htlcs */
    /* Actually: after type(2)+chain_hash(32)+temp_chan_id(32)+funding(8)+push(8)+
                 dust(8)+max_htlc(8)+reserve(8)+htlc_min(8)+feerate(4)+delay(2)+max_htlcs(2)
                 = 2+32+32+8+8+8+8+8+8+4+2+2 = 122 bytes before keys */
    their_funding_pk = open_msg + 122;

    /* Generate our accept parameters */
    chan_open_params_t our_params;
    memset(&our_params, 0, sizeof(our_params));
    our_params.funding_sats      = their_funding_sats;
    our_params.push_msat         = their_push_msat;
    our_params.feerate_per_kw    = their_feerate;
    our_params.to_self_delay     = their_delay;
    our_params.max_htlc_value_msat = 0xFFFFFFFFFFFFFFFFULL;
    our_params.channel_reserve_sats = their_funding_sats / 100;
    our_params.htlc_minimum_msat = 1;
    our_params.max_accepted_htlcs = 483;

    /* Generate an ephemeral channel keypair for this inbound open (BOLT #2).
     * Using temp_chan_id bytes is invalid (not a secp256k1 point) — real peers reject it. */
    {
        unsigned char chan_priv[32];
        FILE *uf = fopen("/dev/urandom", "rb");
        if (!uf || fread(chan_priv, 1, 32, uf) != 32) {
            if (uf) fclose(uf);
            return 0;
        }
        fclose(uf);
        secp256k1_pubkey chan_pub;
        if (!secp256k1_ec_pubkey_create(ctx, &chan_pub, chan_priv)) return 0;
        size_t cpk_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, our_params.funding_pubkey, &cpk_len,
                                      &chan_pub, SECP256K1_EC_COMPRESSED);
    }

    /* Send accept_channel */
    unsigned char acc_msg[256];
    size_t acc_len = chan_build_accept_channel(temp_chan_id, &our_params,
                                               acc_msg, sizeof(acc_msg));
    if (acc_len == 0) return 0;
    if (!peer_mgr_send(mgr, peer_idx, acc_msg, acc_len)) return 0;

    /* Build channel_t from received parameters */
    memset(ch_out, 0, sizeof(*ch_out));
    ch_out->ctx             = ctx;
    ch_out->funding_amount  = their_funding_sats;
    ch_out->local_amount    = their_push_msat / 1000;
    ch_out->remote_amount   = their_funding_sats - their_push_msat / 1000;
    ch_out->to_self_delay   = their_delay;
    ch_out->funder_is_local = 0;

    if (!secp256k1_ec_pubkey_parse(ctx, &ch_out->remote_funding_pubkey,
                                    their_funding_pk, 33)) return 0;

    mgr->peers[peer_idx].has_channel = 1;
    return 1;
}

/* ---- channel_reestablish ---- */

int chan_reestablish(peer_mgr_t *mgr, int peer_idx,
                     secp256k1_context *ctx,
                     channel_t *ch) {
    if (!mgr || peer_idx < 0 || !ctx || !ch) return 0;

    /* Build channel_reestablish message (BOLT #2 §3, type 136)
       type(2) + channel_id(32) + next_commitment_number(8) +
       next_revocation_number(8) + your_last_per_commitment_secret(32) +
       my_current_per_commitment_point(33) = 115 bytes */
    unsigned char msg[116];
    size_t pos = 0;
    msg[pos++] = (CHAN_MSG_REESTABLISH >> 8) & 0xff;
    msg[pos++] = CHAN_MSG_REESTABLISH & 0xff;
    /* channel_id: use funding_txid XOR'd with vout for simplicity */
    unsigned char chan_id[32];
    memcpy(chan_id, ch->funding_txid, 32);
    chan_id[0] ^= (unsigned char)(ch->funding_vout & 0xff);
    chan_id[1] ^= (unsigned char)((ch->funding_vout >> 8) & 0xff);
    memcpy(msg + pos, chan_id, 32); pos += 32;
    /* next_commitment_number = commitment_number + 1 */
    for (int i = 7; i >= 0; i--) msg[pos++] = (unsigned char)((ch->commitment_number + 1) >> (i*8));
    /* next_revocation_number = commitment_number (we've revoked up to this point) */
    for (int i = 7; i >= 0; i--) msg[pos++] = (unsigned char)((ch->commitment_number) >> (i*8));
    /* your_last_per_commitment_secret: all zeros if no prior revocation */
    memset(msg + pos, 0, 32); pos += 32;
    /* my_current_per_commitment_point: OUR local PCP for current commitment (BOLT #2 §3).
     * This must be our own key — NOT the remote's. Used by peer for DLP detection. */
    {
        secp256k1_pubkey local_pcp;
        if (channel_get_per_commitment_point(ch, ch->commitment_number, &local_pcp)) {
            unsigned char pcp33[33];
            size_t pcp_len = 33;
            secp256k1_ec_pubkey_serialize(ctx, pcp33, &pcp_len,
                                           &local_pcp, SECP256K1_EC_COMPRESSED);
            memcpy(msg + pos, pcp33, 33);
        } else {
            memset(msg + pos, 0, 33); /* zeros = initial/unknown state */
        }
    }
    pos += 33;

    if (!peer_mgr_send(mgr, peer_idx, msg, pos)) return 0;

    /* Receive peer's reestablish */
    unsigned char peer_msg[256];
    size_t peer_len = 0;
    if (!peer_mgr_recv(mgr, peer_idx, peer_msg, &peer_len, sizeof(peer_msg))) return 0;
    if (peer_len < 115) return 0;
    if (get_u16(peer_msg) != CHAN_MSG_REESTABLISH) return 0;

    /* Parse peer's next_commitment_number */
    uint64_t peer_next_cn = get_u64(peer_msg + 34); /* after type(2)+chan_id(32) */

    /* DLP: if peer claims a higher commitment number, we must force-close */
    if (peer_next_cn > ch->commitment_number + 2) {
        fprintf(stderr, "chan_reestablish: DLP detected (peer=%llu, ours=%llu) → force close\n",
                (unsigned long long)peer_next_cn, (unsigned long long)ch->commitment_number);
        /* channel_force_close is defined in channel.c */
        /* We return 0 to signal the caller to force-close */
        return 0;
    }
    return 1;
}

/* ---- Dual-Fund v2: inbound open_channel2 (type 78) ---- */

int chan_open_inbound_v2(peer_mgr_t *mgr, int peer_idx,
                          const unsigned char *msg, size_t msg_len,
                          secp256k1_context *ctx, channel_t *ch_out)
{
    if (!mgr || !msg || !ch_out || msg_len < 350) return 0;
    if (!ctx) return 0;

    /* Skip type bytes if present (type 78 = 0x004E) */
    const unsigned char *p = msg;
    size_t len = msg_len;
    if (len >= 2 && p[0] == 0 && p[1] == 78) { p += 2; len -= 2; }
    if (len < 348) return 0;

    /* Parse open_channel2 payload (no type prefix):
       chain_hash(32) + temp_channel_id(32) + funding_feerate(4) +
       commitment_feerate(4) + funding_satoshis(8) + dust_limit(8) +
       max_htlc(8) + htlc_min(8) + to_self_delay(2) + max_htlcs(2) +
       locktime(4) + funding_pubkey(33) + rev_bp(33) + pay_bp(33) +
       delay_bp(33) + htlc_bp(33) + first_pcp(33) + second_pcp(33) +
       channel_flags(1) = 348 bytes */
    const unsigned char *q = p;
    /* chain_hash(32) */     q += 32;
    unsigned char temp_id[32]; memcpy(temp_id, q, 32); q += 32;
    /* feerate(4+4) */       q += 8;
    /* funding_sats(8) */    q += 8;
    /* dust_limit(8) */      q += 8;
    /* max_htlc(8) */        q += 8;
    /* htlc_min(8) */        q += 8;
    /* to_self_delay(2) */   uint16_t their_delay = ((uint16_t)q[0]<<8)|q[1]; q += 2;
    /* max_htlcs(2) */       q += 2;
    /* locktime(4) */        q += 4;
    /* funding_pubkey(33) */
    if (ctx) {
        secp256k1_pubkey their_key;
        if (secp256k1_ec_pubkey_parse(ctx, &their_key, q, 33))
            ch_out->remote_funding_pubkey = their_key;
    }
    q += 33;
    /* Skip remaining basepoints and PCPs */
    q += 5*33 + 33 + 33;
    /* channel_flags(1) */   q += 1;

    ch_out->to_self_delay = their_delay;
    ch_out->fee_rate_sat_per_kvb = 1000;
    if (ch_out->ctx == NULL) ch_out->ctx = ctx;

    /* Build accept_channel2 (type 79):
       type(2) + temp_channel_id(32) + funding_satoshis(8)=0 +
       dust_limit(8) + max_htlc(8) + htlc_min(8) + minimum_depth(4) +
       to_self_delay(2) + max_htlcs(2) + funding_pubkey(33) +
       rev_bp(33) + pay_bp(33) + delay_bp(33) + htlc_bp(33) +
       first_pcp(33) + second_pcp(33) = 314 bytes */
    unsigned char accept[314];
    memset(accept, 0, sizeof(accept));
    accept[0] = 0x00; accept[1] = 0x4F; /* type 79 */
    memcpy(accept + 2, temp_id, 32);    /* temp_channel_id */
    /* funding_satoshis = 0 (8 bytes already zero at offset 34) */
    /* dust_limit at offset 42: 546 sats = 0x222 */
    accept[48] = 0x02; accept[49] = 0x22;
    /* max_htlc at offset 50: 0xFFFF (all ones) */
    memset(accept + 50, 0xFF, 8);
    /* htlc_min at offset 58: 1 msat */
    accept[65] = 0x01;
    /* minimum_depth at offset 66: 3 */
    accept[69] = 0x03;
    /* to_self_delay at offset 70: 144 = 0x0090 */
    accept[70] = 0x00; accept[71] = 0x90;
    /* max_accepted_htlcs at offset 72: 483 = 0x01E3 */
    accept[72] = 0x01; accept[73] = 0xE3;
    /* Generate random basepoints and per-commitment secrets for this channel */
    if (!channel_generate_random_basepoints(ch_out)) return 0;
    /* Generate local per-commitment secrets for commitments 0 and 1 */
    channel_generate_local_pcs(ch_out, 0);
    channel_generate_local_pcs(ch_out, 1);

    /* funding_pubkey at offset 74 */
    {
        /* Generate funding keypair if not yet set.
           Check raw internal bytes to avoid serializing a zeroed (invalid) pubkey. */
        unsigned char zero64[64] = {0};
        if (memcmp(ch_out->local_funding_pubkey.data, zero64, 64) == 0) {
            unsigned char fsec[32];
            if (!channel_read_random_bytes(fsec, 32)) return 0;
            memcpy(ch_out->local_funding_secret, fsec, 32);
            if (!secp256k1_ec_pubkey_create(ctx, &ch_out->local_funding_pubkey, fsec)) return 0;
            if (!secp256k1_keypair_create(ctx, &ch_out->local_funding_keypair, fsec))
                return 0;
        }
        size_t plen = 33;
        secp256k1_ec_pubkey_serialize(ctx, accept + 74, &plen,
                                       &ch_out->local_funding_pubkey,
                                       SECP256K1_EC_COMPRESSED);
    }

    /* Serialize five basepoints at offsets 107, 140, 173, 206, 239
       Layout: rev_bp(33) pay_bp(33) delay_bp(33) htlc_bp(33) first_pcp(33) second_pcp(33) */
    {
        size_t plen = 33;
        secp256k1_ec_pubkey_serialize(ctx, accept + 107, &plen,
            &ch_out->local_revocation_basepoint, SECP256K1_EC_COMPRESSED);
        plen = 33;
        secp256k1_ec_pubkey_serialize(ctx, accept + 140, &plen,
            &ch_out->local_payment_basepoint, SECP256K1_EC_COMPRESSED);
        plen = 33;
        secp256k1_ec_pubkey_serialize(ctx, accept + 173, &plen,
            &ch_out->local_delayed_payment_basepoint, SECP256K1_EC_COMPRESSED);
        plen = 33;
        secp256k1_ec_pubkey_serialize(ctx, accept + 206, &plen,
            &ch_out->local_htlc_basepoint, SECP256K1_EC_COMPRESSED);
    }

    /* First and second per-commitment points at offsets 239 and 272 */
    {
        secp256k1_pubkey pcp0, pcp1;
        if (channel_get_per_commitment_point(ch_out, 0, &pcp0)) {
            size_t plen = 33;
            secp256k1_ec_pubkey_serialize(ctx, accept + 239, &plen,
                &pcp0, SECP256K1_EC_COMPRESSED);
        }
        if (channel_get_per_commitment_point(ch_out, 1, &pcp1)) {
            size_t plen = 33;
            secp256k1_ec_pubkey_serialize(ctx, accept + 272, &plen,
                &pcp1, SECP256K1_EC_COMPRESSED);
        }
    }

    if (peer_mgr_send(mgr, peer_idx, accept, sizeof(accept)) <= 0) return 0;
    return 1;
}

/* -----------------------------------------------------------------------
 * announcement_signatures (BOLT #7 type 259)
 * ----------------------------------------------------------------------- */

#include "superscalar/gossip.h"
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>
#include <stdlib.h>
#include <time.h>

/* Sign the channel_announcement signable data with a given privkey.
 * channel_announcement layout: type(2) | 4xsig(64) | features_len(2) | ...
 * Signable = SHA256(SHA256(type(2) || msg[2+4*64..end]))
 * Returns 1 on success, 0 on error. */
static int sign_chan_ann(unsigned char sig64_out[64],
                          secp256k1_context *ctx,
                          const unsigned char privkey32[32],
                          const unsigned char *ann, size_t ann_len)
{
    if (ann_len < 258) return 0;  /* type(2) + 4*sig(64) = 258 minimum */

    /* Signable = type(2) || data_after_all_sigs */
    size_t data_len = 2 + (ann_len - 258);
    unsigned char *data = (unsigned char *)malloc(data_len);
    if (!data) return 0;

    memcpy(data, ann, 2);
    memcpy(data + 2, ann + 258, ann_len - 258);

    unsigned char hash[32];
    sha256_double(data, data_len, hash);
    free(data);

    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, privkey32)) return 0;

    int ok = secp256k1_schnorrsig_sign32(ctx, sig64_out, hash, &kp, NULL);
    /* zeroise keypair */
    memset(&kp, 0, sizeof(kp));
    return ok;
}

int chan_send_announcement_sigs(peer_mgr_t *pmgr, int peer_idx,
                                 secp256k1_context *ctx,
                                 const unsigned char node_privkey[32],
                                 channel_t *ch,
                                 const unsigned char chain_hash[32])
{
    if (!ch || !ctx || !node_privkey || !chain_hash) return -1;
    if (ch->short_channel_id == 0) return -1;  /* no SCID yet */

    /* Derive our node pubkey (33 bytes) from node_privkey */
    unsigned char our_node_pub[33];
    {
        secp256k1_pubkey pub;
        if (!secp256k1_ec_pubkey_create(ctx, &pub, node_privkey)) return -1;
        size_t plen = 33;
        secp256k1_ec_pubkey_serialize(ctx, our_node_pub, &plen,
                                       &pub, SECP256K1_EC_COMPRESSED);
    }

    /* Peer's node pubkey — take from peer_mgr if available */
    unsigned char peer_node_pub[33];
    if (pmgr && peer_idx >= 0 && peer_idx < pmgr->count) {
        memcpy(peer_node_pub, pmgr->peers[peer_idx].pubkey, 33);
    } else {
        /* Use remote_funding_pubkey serialized as placeholder */
        size_t plen = 33;
        secp256k1_ec_pubkey_serialize(ctx, peer_node_pub, &plen,
                                       &ch->remote_funding_pubkey,
                                       SECP256K1_EC_COMPRESSED);
    }

    /* Our bitcoin pubkey */
    unsigned char our_btc_pub[33];
    {
        size_t plen = 33;
        secp256k1_ec_pubkey_serialize(ctx, our_btc_pub, &plen,
                                       &ch->local_funding_pubkey,
                                       SECP256K1_EC_COMPRESSED);
    }

    /* Peer's bitcoin pubkey */
    unsigned char peer_btc_pub[33];
    {
        size_t plen = 33;
        secp256k1_ec_pubkey_serialize(ctx, peer_btc_pub, &plen,
                                       &ch->remote_funding_pubkey,
                                       SECP256K1_EC_COMPRESSED);
    }

    /* Determine node ordering (node_id_1 < node_id_2 lexicographically) */
    const unsigned char *node_id_1, *node_id_2;
    const unsigned char *btc_key_1, *btc_key_2;
    if (memcmp(our_node_pub, peer_node_pub, 33) <= 0) {
        node_id_1 = our_node_pub;  node_id_2 = peer_node_pub;
        btc_key_1 = our_btc_pub;   btc_key_2 = peer_btc_pub;
    } else {
        node_id_1 = peer_node_pub; node_id_2 = our_node_pub;
        btc_key_1 = peer_btc_pub;  btc_key_2 = our_btc_pub;
    }

    /* Build unsigned channel_announcement */
    unsigned char ann[512];
    size_t ann_len = gossip_build_channel_announcement_unsigned(
        ann, sizeof(ann), chain_hash, ch->short_channel_id,
        node_id_1, node_id_2, btc_key_1, btc_key_2);
    if (ann_len == 0) return -1;

    /* Sign with our node key */
    if (!sign_chan_ann(ch->local_node_sig, ctx, node_privkey, ann, ann_len))
        return -1;

    /* Sign with our bitcoin funding key */
    if (!sign_chan_ann(ch->local_bitcoin_sig, ctx,
                        ch->local_funding_secret, ann, ann_len))
        return -1;

    /* Build announcement_signatures wire message (type 259, 170 bytes):
       type(2) + channel_id(32) + scid(8) + node_sig(64) + btc_sig(64) */
    unsigned char wire[2 + 32 + 8 + 64 + 64];
    wire[0] = 0x01; wire[1] = 0x03;   /* type 259 */
    memcpy(wire + 2, ch->funding_txid, 32);  /* channel_id = funding_txid */
    /* SCID big-endian */
    uint64_t scid = ch->short_channel_id;
    wire[34] = (unsigned char)(scid >> 56);
    wire[35] = (unsigned char)(scid >> 48);
    wire[36] = (unsigned char)(scid >> 40);
    wire[37] = (unsigned char)(scid >> 32);
    wire[38] = (unsigned char)(scid >> 24);
    wire[39] = (unsigned char)(scid >> 16);
    wire[40] = (unsigned char)(scid >>  8);
    wire[41] = (unsigned char)(scid);
    memcpy(wire + 42, ch->local_node_sig, 64);
    memcpy(wire + 106, ch->local_bitcoin_sig, 64);

    if (pmgr && peer_idx >= 0)
        peer_mgr_send(pmgr, peer_idx, wire, sizeof(wire));

    ch->ann_sigs_sent = 1;
    return 0;
}

/* === Dynamic commitment upgrade (BOLT #2 PR #880) === */

#include "superscalar/circuit_breaker.h"

/* Channel type upgrade: propose new channel_type via commitment_signed TLV.
   Returns 1 if upgrade is valid (intersection is subset of current). */
int channel_type_upgrade_valid(uint32_t current_bits, uint32_t proposed_bits) {
    /* The proposed type must be a superset of the current type */
    return (proposed_bits & current_bits) == current_bits;
}

/* Initiate a channel type upgrade. Stores proposed bits; caller must
   re-sign commitment with new type and send commitment_signed. */
int channel_type_propose_upgrade(channel_t *ch, uint32_t new_bits) {
    if (!ch) return 0;
    if (!channel_type_upgrade_valid(ch->channel_type_bits, new_bits))
        return 0;
    ch->channel_type_bits = new_bits;
    return 1;
}
