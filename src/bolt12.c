#include "superscalar/bolt12.h"
#include "superscalar/bech32m.h"
#include "superscalar/sha256.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* -----------------------------------------------------------------------
 * Real bech32m codec for offers (lno1...)
 * Uses BIP 350 bech32m (HRP = "lno") via src/bech32m.c
 * --------------------------------------------------------------------- */

#define BOLT12_OFFER_HRP "lno"

static int b32encode(const unsigned char *data, size_t data_len,
                      char *out, size_t out_cap)
{
    return bech32m_encode(BOLT12_OFFER_HRP, data, data_len, out, out_cap);
}

static int b32decode(const char *str, unsigned char *out, size_t *len_out, size_t cap)
{
    return bech32m_decode(str, BOLT12_OFFER_HRP, out, len_out, cap);
}

/* Serialise offer to bytes for encoding */
static size_t offer_to_bytes(const offer_t *o, unsigned char *buf, size_t cap)
{
    size_t pos = 0;
    if (pos + 33 > cap) return 0;
    memcpy(buf + pos, o->node_id, 33); pos += 33;
    if (pos + 8 > cap) return 0;
    uint64_t amt = o->amount_msat;
    for (int i = 0; i < 8; i++) { buf[pos++] = (unsigned char)(amt & 0xff); amt >>= 8; }
    size_t desc_len = strlen(o->description);
    if (desc_len > 255) desc_len = 255;
    if (pos + 1 + desc_len > cap) return 0;
    buf[pos++] = (unsigned char)desc_len;
    memcpy(buf + pos, o->description, desc_len); pos += desc_len;
    return pos;
}

int offer_encode(const offer_t *o, char *out, size_t out_cap)
{
    if (!o || !out) return 0;
    unsigned char tmp[512];
    size_t tmp_len = offer_to_bytes(o, tmp, sizeof(tmp));
    if (!tmp_len) return 0;
    return b32encode(tmp, tmp_len, out, out_cap);
}

int offer_decode(const char *bech32m, offer_t *o_out)
{
    if (!bech32m || !o_out) return 0;
    unsigned char tmp[512];
    size_t tmp_len = 0;
    if (!b32decode(bech32m, tmp, &tmp_len, sizeof(tmp))) return 0;
    if (tmp_len < 42) return 0;  /* minimum: 33 (node_id) + 8 (amount) + 1 (desc_len) */

    memset(o_out, 0, sizeof(*o_out));
    size_t pos = 0;
    memcpy(o_out->node_id, tmp + pos, 33); pos += 33;
    uint64_t amt = 0;
    for (int i = 0; i < 8; i++) { amt |= ((uint64_t)tmp[pos+i] << (i*8)); } pos += 8;
    o_out->amount_msat = amt;
    o_out->has_amount = (amt > 0);
    size_t desc_len = tmp[pos++];
    if (pos + desc_len > tmp_len) return 0;
    if (desc_len >= BOLT12_OFFER_MAX_DESC) desc_len = BOLT12_OFFER_MAX_DESC - 1;
    memcpy(o_out->description, tmp + pos, desc_len);
    o_out->description[desc_len] = '\0';
    return 1;
}

/* -----------------------------------------------------------------------
 * Signing helpers — tagged hash "BOLT12Signature" || fields
 * --------------------------------------------------------------------- */

static void bolt12_sighash(const unsigned char *data, size_t len,
                             unsigned char *hash32)
{
    sha256_tagged("BOLT12Signature", data, len, hash32);
}

int invoice_request_sign(invoice_request_t *req, secp256k1_context *ctx,
                          const unsigned char *seckey32)
{
    if (!req || !ctx || !seckey32) return 0;

    unsigned char msg[73];
    memcpy(msg, req->offer_id, 32);
    memcpy(msg + 32, req->payer_key, 33);
    uint64_t amt = req->amount_msat;
    for (int i = 0; i < 8; i++) { msg[65+i] = (unsigned char)(amt & 0xff); amt >>= 8; }

    unsigned char sighash[32];
    bolt12_sighash(msg, 73, sighash);

    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, seckey32)) return 0;

    unsigned char aux[32] = {0};
    return secp256k1_schnorrsig_sign32(ctx, req->sig, sighash, &kp, aux);
}

int invoice_request_verify(const invoice_request_t *req, secp256k1_context *ctx)
{
    if (!req || !ctx) return 0;

    unsigned char msg[73];
    memcpy(msg, req->offer_id, 32);
    memcpy(msg + 32, req->payer_key, 33);
    uint64_t amt = req->amount_msat;
    for (int i = 0; i < 8; i++) { msg[65+i] = (unsigned char)(amt & 0xff); amt >>= 8; }

    unsigned char sighash[32];
    bolt12_sighash(msg, 73, sighash);

    secp256k1_xonly_pubkey xpk;
    if (!secp256k1_xonly_pubkey_parse(ctx, &xpk, req->payer_key + 1)) return 0;
    return secp256k1_schnorrsig_verify(ctx, req->sig, sighash, 32, &xpk);
}

int invoice_sign(invoice_t *inv, secp256k1_context *ctx,
                  const unsigned char *node_seckey32)
{
    if (!inv || !ctx || !node_seckey32) return 0;

    unsigned char msg[72];
    memcpy(msg, inv->payment_hash, 32);
    memcpy(msg + 32, inv->offer_id, 32);
    uint64_t amt = inv->amount_msat;
    for (int i = 0; i < 8; i++) { msg[64+i] = (unsigned char)(amt & 0xff); amt >>= 8; }

    unsigned char sighash[32];
    bolt12_sighash(msg, 72, sighash);

    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, node_seckey32)) return 0;

    unsigned char aux[32] = {0};
    return secp256k1_schnorrsig_sign32(ctx, inv->node_sig, sighash, &kp, aux);
}

int invoice_verify(const invoice_t *inv, secp256k1_context *ctx,
                    const unsigned char *node_id33)
{
    if (!inv || !ctx || !node_id33) return 0;

    unsigned char msg[72];
    memcpy(msg, inv->payment_hash, 32);
    memcpy(msg + 32, inv->offer_id, 32);
    uint64_t amt = inv->amount_msat;
    for (int i = 0; i < 8; i++) { msg[64+i] = (unsigned char)(amt & 0xff); amt >>= 8; }

    unsigned char sighash[32];
    bolt12_sighash(msg, 72, sighash);

    secp256k1_xonly_pubkey xpk;
    if (!secp256k1_xonly_pubkey_parse(ctx, &xpk, node_id33 + 1)) return 0;
    return secp256k1_schnorrsig_verify(ctx, inv->node_sig, sighash, 32, &xpk);
}
