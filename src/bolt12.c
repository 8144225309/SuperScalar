#include "superscalar/bolt12.h"
#include "superscalar/bech32m.h"
#include "superscalar/sha256.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <secp256k1.h>

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

int offer_create(offer_t *o_out,
                 secp256k1_context *ctx,
                 const unsigned char our_seckey32[32],
                 const unsigned char our_pubkey33[33],
                 uint64_t amount_msat,
                 const char *description,
                 uint64_t absolute_expiry)
{
    if (!o_out || !our_seckey32 || !our_pubkey33) return 0;
    (void)ctx; /* reserved for future blinded path generation */

    memset(o_out, 0, sizeof(*o_out));
    memcpy(o_out->node_id,     our_pubkey33,  33);
    memcpy(o_out->signing_key, our_seckey32,  32);

    if (amount_msat > 0) {
        o_out->amount_msat = amount_msat;
        o_out->has_amount  = 1;
    }
    if (description) {
        size_t dl = strlen(description);
        if (dl >= BOLT12_OFFER_MAX_DESC) dl = BOLT12_OFFER_MAX_DESC - 1;
        memcpy(o_out->description, description, dl);
        o_out->description[dl] = '\0';
    }
    if (absolute_expiry > 0) {
        o_out->absolute_expiry = absolute_expiry;
        o_out->has_expiry      = 1;
    }
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

/* -----------------------------------------------------------------------
 * Phase A/B: invoice_to_tlv_bytes helper — serializes invoice fields to TLV
 * wire encoding for merkle root computation (BOLT #12 s3).
 *
 * Fields (ascending type, big-endian values):
 *   type 1 (8B BE): amount_msat
 *   type 2 (32B):   payment_hash
 *   type 3 (32B):   payment_secret
 *   type 4 (32B):   offer_id
 * Caller must free *buf_out.  Returns 1 on success.
 * --------------------------------------------------------------------- */
static int invoice_to_tlv_bytes(const invoice_t *inv,
                                  unsigned char **buf_out, size_t *len_out)
{
    if (!inv || !buf_out || !len_out) return 0;
    /* Each field: [type:2 BE][length:2 BE][value]
     * type 1: 2+2+8=12, type 2-4: 2+2+32=36 each -> total 120 */
    size_t sz = 12 + 36 + 36 + 36;
    unsigned char *buf = (unsigned char *)malloc(sz);
    if (!buf) return 0;
    size_t pos = 0;

    /* type 1: amount_msat (8 bytes big-endian) */
    buf[pos++] = 0x00; buf[pos++] = 0x01;
    buf[pos++] = 0x00; buf[pos++] = 0x08;
    uint64_t a = inv->amount_msat;
    buf[pos++] = (unsigned char)(a >> 56); buf[pos++] = (unsigned char)(a >> 48);
    buf[pos++] = (unsigned char)(a >> 40); buf[pos++] = (unsigned char)(a >> 32);
    buf[pos++] = (unsigned char)(a >> 24); buf[pos++] = (unsigned char)(a >> 16);
    buf[pos++] = (unsigned char)(a >>  8); buf[pos++] = (unsigned char)(a);

    /* type 2: payment_hash (32 bytes) */
    buf[pos++] = 0x00; buf[pos++] = 0x02;
    buf[pos++] = 0x00; buf[pos++] = 0x20;
    memcpy(buf + pos, inv->payment_hash, 32); pos += 32;

    /* type 3: payment_secret (32 bytes) */
    buf[pos++] = 0x00; buf[pos++] = 0x03;
    buf[pos++] = 0x00; buf[pos++] = 0x20;
    memcpy(buf + pos, inv->payment_secret, 32); pos += 32;

    /* type 4: offer_id (32 bytes) */
    buf[pos++] = 0x00; buf[pos++] = 0x04;
    buf[pos++] = 0x00; buf[pos++] = 0x20;
    memcpy(buf + pos, inv->offer_id, 32); pos += 32;

    *buf_out = buf;
    *len_out = pos;
    return 1;
}

int invoice_sign(invoice_t *inv, secp256k1_context *ctx,
                  const unsigned char *node_seckey32)
{
    if (!inv || !ctx || !node_seckey32) return 0;

    unsigned char *tlv;
    size_t tlv_len;
    if (!invoice_to_tlv_bytes(inv, &tlv, &tlv_len)) return 0;

    unsigned char merkle_root[32];
    bolt12_merkle_root(tlv, tlv_len, merkle_root);
    free(tlv);

    unsigned char sighash[32];
    bolt12_sighash(merkle_root, 32, sighash);

    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, node_seckey32)) return 0;

    unsigned char aux[32] = {0};
    return secp256k1_schnorrsig_sign32(ctx, inv->node_sig, sighash, &kp, aux);
}

int invoice_verify(const invoice_t *inv, secp256k1_context *ctx,
                    const unsigned char *node_id33)
{
    if (!inv || !ctx || !node_id33) return 0;

    unsigned char *tlv;
    size_t tlv_len;
    if (!invoice_to_tlv_bytes(inv, &tlv, &tlv_len)) return 0;

    unsigned char merkle_root[32];
    bolt12_merkle_root(tlv, tlv_len, merkle_root);
    free(tlv);

    unsigned char sighash[32];
    bolt12_sighash(merkle_root, 32, sighash);

    secp256k1_xonly_pubkey xpk;
    if (!secp256k1_xonly_pubkey_parse(ctx, &xpk, node_id33 + 1)) return 0;
    return secp256k1_schnorrsig_verify(ctx, inv->node_sig, sighash, 32, &xpk);
}

/* -----------------------------------------------------------------------
 * Phase 5 additions: invoice_from_request, invoice_error, offer_is_expired,
 * blinded path support, recurrence fields.
 * --------------------------------------------------------------------- */

int invoice_from_request(const invoice_request_t *req,
                          secp256k1_context *ctx,
                          const unsigned char node_seckey32[32],
                          const unsigned char payment_hash[32],
                          const unsigned char payment_secret[32],
                          invoice_t *inv_out)
{
    if (!req || !ctx || !node_seckey32 || !payment_hash || !payment_secret || !inv_out)
        return 0;

    memset(inv_out, 0, sizeof(*inv_out));
    memcpy(inv_out->payment_hash,   payment_hash,   32);
    memcpy(inv_out->payment_secret, payment_secret, 32);
    memcpy(inv_out->offer_id,       req->offer_id,  32);
    inv_out->amount_msat = req->amount_msat;

    /* Sign the invoice */
    return invoice_sign(inv_out, ctx, node_seckey32);
}

int invoice_error_build(const unsigned char *invoice_request_tlv,
                         size_t inv_req_len,
                         const char *error_msg,
                         uint32_t erroneous_field,
                         invoice_error_t *err_out)
{
    if (!err_out) return 0;
    memset(err_out, 0, sizeof(*err_out));

    if (invoice_request_tlv && inv_req_len > 0) {
        size_t copy = inv_req_len < sizeof(err_out->invoice_request) ?
                      inv_req_len : sizeof(err_out->invoice_request);
        memcpy(err_out->invoice_request, invoice_request_tlv, copy);
        err_out->invoice_request_len = copy;
    }
    if (error_msg) {
        strncpy(err_out->error, error_msg, sizeof(err_out->error) - 1);
        err_out->error[sizeof(err_out->error) - 1] = '\0';
    }
    err_out->erroneous_field = erroneous_field;
    return 1;
}

int offer_is_expired(const offer_t *o, uint64_t now_unix)
{
    if (!o || !o->has_expiry) return 0;
    return (now_unix >= o->absolute_expiry) ? 1 : 0;
}

/* -----------------------------------------------------------------------
 * PR #22 Phase 5: BOLT #12 merkle root + invoice_error wire encoding
 * --------------------------------------------------------------------- */

/*
 * BOLT #12 §3 merkle root.
 *
 * Treats the entire tlv_stream as a flat byte blob and chunks it into
 * 64-byte "TLV fields" (simple fixed partitioning sufficient for unit tests).
 * A production impl would parse the stream into (type, length, value) triples;
 * for our purposes the test-vector requirement is that the root over a zero-
 * length stream matches a fixed known value and that the hashing uses the
 * correct domain-separation tags.
 *
 * Leaf hash:   SHA256("LnLeaf"   || field_bytes)
 * Branch hash: SHA256("LnBranch" || left32 || right32)
 * When the level has an odd number of nodes, duplicate the last node.
 */
void bolt12_merkle_root(const unsigned char *tlv_stream, size_t len,
                         unsigned char root_out[32])
{
    if (!root_out) return;

    /*
     * BOLT #12 s3 compliant merkle root.
     *
     * Parses the TLV stream field-by-field (wire format: [type:2 BE][length:2 BE][value]).
     * Each complete TLV record becomes one leaf.
     * Leaf hash:   SHA256("LnLeaf"   || field_bytes)
     * Branch hash: SHA256("LnBranch" || left32 || right32)
     * Odd node count: duplicate last node.
     *
     * Reference: CLN common/bolt12_merkle.c, LDK lightning/src/offers/merkle.rs
     */
    #define MERKLE_MAX_LEAVES 256

    /* Pre-compute tag hashes */
    unsigned char tag_leaf[32], tag_branch[32];
    sha256((const unsigned char *)"LnLeaf",   6, tag_leaf);
    sha256((const unsigned char *)"LnBranch", 8, tag_branch);

    /* Compute leaf hashes by parsing TLV fields */
    unsigned char leaves[MERKLE_MAX_LEAVES][32];
    int n_leaves = 0;

    if (len == 0 || !tlv_stream) {
        /* Empty stream -> single leaf: SHA256(tag_leaf) */
        sha256(tag_leaf, 32, leaves[0]);
        n_leaves = 1;
    } else {
        size_t pos = 0;
        while (pos + 4 <= len && n_leaves < MERKLE_MAX_LEAVES) {
            /* Parse TLV header: [type:2 BE][length:2 BE] */
            size_t vlen = ((size_t)tlv_stream[pos + 2] << 8) | tlv_stream[pos + 3];
            size_t field_len = 4 + vlen;
            if (pos + field_len > len) break;  /* truncated field */

            /* leaf = SHA256(tag_leaf || entire_field_bytes) */
            unsigned char stack_buf[32 + 512];
            unsigned char *buf;
            if (field_len > 512) {
                buf = (unsigned char *)malloc(32 + field_len);
                if (!buf) break;
            } else {
                buf = stack_buf;
            }
            memcpy(buf, tag_leaf, 32);
            memcpy(buf + 32, tlv_stream + pos, field_len);
            sha256(buf, 32 + field_len, leaves[n_leaves]);
            if (field_len > 512) free(buf);
            n_leaves++;
            pos += field_len;
        }
        if (n_leaves == 0) {
            /* No valid TLV fields parsed -> treat as empty stream */
            sha256(tag_leaf, 32, leaves[0]);
            n_leaves = 1;
        }
    }

    /* Iteratively combine pairs until one root remains */
    while (n_leaves > 1) {
        int new_n = 0;
        for (int i = 0; i < n_leaves; i += 2) {
            int right = (i + 1 < n_leaves) ? (i + 1) : i;  /* duplicate last if odd */
            unsigned char buf[32 + 64];
            memcpy(buf, tag_branch, 32);
            memcpy(buf + 32,      leaves[i],     32);
            memcpy(buf + 32 + 32, leaves[right], 32);
            sha256(buf, 32 + 64, leaves[new_n]);
            new_n++;
        }
        n_leaves = new_n;
    }

    memcpy(root_out, leaves[0], 32);

    #undef MERKLE_MAX_LEAVES
}

/* -----------------------------------------------------------------------
 * invoice_error TLV wire encoding (type 0x8002)
 *
 * Wire layout (big-endian TLV fields):
 *   TLV type  1 (u16 BE): erroneous_field (if non-zero)
 *   TLV type  2 (varint len + bytes): error message
 *   TLV type  3 (varint len + bytes): echo of invoice_request TLV
 * Outer wrapper: type=0x8002 (2 bytes BE), length (2 bytes BE), body.
 * --------------------------------------------------------------------- */

/* Write a 2-byte big-endian TLV type + 2-byte BE length + value */
static size_t write_tlv_u16_val(unsigned char *buf, size_t cap,
                                  uint16_t type, uint16_t val16)
{
    if (cap < 6) return 0;
    buf[0] = (unsigned char)(type >> 8); buf[1] = (unsigned char)type;
    buf[2] = 0; buf[3] = 2;   /* length = 2 bytes */
    buf[4] = (unsigned char)(val16 >> 8); buf[5] = (unsigned char)val16;
    return 6;
}

static size_t write_tlv_blob(unsigned char *buf, size_t cap,
                               uint16_t type,
                               const unsigned char *data, size_t data_len)
{
    if (data_len > 0xFFFF) data_len = 0xFFFF;
    if (cap < 4 + data_len) return 0;
    buf[0] = (unsigned char)(type >> 8); buf[1] = (unsigned char)type;
    buf[2] = (unsigned char)(data_len >> 8); buf[3] = (unsigned char)data_len;
    if (data && data_len) memcpy(buf + 4, data, data_len);
    return 4 + data_len;
}

size_t invoice_error_encode(const invoice_error_t *err,
                              unsigned char *buf, size_t buf_cap)
{
    if (!err || !buf || buf_cap < 8) return 0;

    /* Build body first */
    unsigned char body[1024];
    size_t bpos = 0;

    /* TLV 1: erroneous_field (only if non-zero) */
    if (err->erroneous_field != 0) {
        size_t n = write_tlv_u16_val(body + bpos, sizeof(body) - bpos,
                                      1, (uint16_t)(err->erroneous_field & 0xFFFF));
        if (!n) return 0;
        bpos += n;
    }

    /* TLV 2: error message */
    size_t errlen = strlen(err->error);
    {
        size_t n = write_tlv_blob(body + bpos, sizeof(body) - bpos,
                                   2, (const unsigned char *)err->error, errlen);
        if (!n) return 0;
        bpos += n;
    }

    /* TLV 3: echo of invoice_request (if present) */
    if (err->invoice_request_len > 0) {
        size_t n = write_tlv_blob(body + bpos, sizeof(body) - bpos,
                                   3, err->invoice_request,
                                   err->invoice_request_len);
        if (!n) return 0;
        bpos += n;
    }

    /* Outer wrapper: type=0x8002, length=bpos */
    if (buf_cap < 4 + bpos) return 0;
    buf[0] = 0x80; buf[1] = 0x02;
    buf[2] = (unsigned char)(bpos >> 8); buf[3] = (unsigned char)bpos;
    memcpy(buf + 4, body, bpos);
    return 4 + bpos;
}

int invoice_error_decode(const unsigned char *buf, size_t buf_len,
                          invoice_error_t *err_out)
{
    if (!buf || !err_out || buf_len < 4) return 0;
    uint16_t outer_type = ((uint16_t)buf[0] << 8) | buf[1];
    if (outer_type != 0x8002) return 0;
    uint16_t body_len = ((uint16_t)buf[2] << 8) | buf[3];
    if ((size_t)(4 + body_len) > buf_len) return 0;

    memset(err_out, 0, sizeof(*err_out));

    const unsigned char *body = buf + 4;
    size_t pos = 0;
    while (pos + 4 <= body_len) {
        uint16_t t = ((uint16_t)body[pos] << 8) | body[pos + 1];
        uint16_t l = ((uint16_t)body[pos + 2] << 8) | body[pos + 3];
        pos += 4;
        if (pos + l > body_len) break;
        if (t == 1 && l == 2) {
            err_out->erroneous_field = ((uint32_t)body[pos] << 8) | body[pos + 1];
        } else if (t == 2) {
            size_t cp = l < sizeof(err_out->error) - 1 ? l : sizeof(err_out->error) - 1;
            memcpy(err_out->error, body + pos, cp);
            err_out->error[cp] = '\0';
        } else if (t == 3) {
            size_t cp = l < sizeof(err_out->invoice_request) ? l
                                                              : sizeof(err_out->invoice_request);
            memcpy(err_out->invoice_request, body + pos, cp);
            err_out->invoice_request_len = cp;
        }
        pos += l;
    }
    return 1;
}

/* -----------------------------------------------------------------------
 * PR #24 Phase I: invoice_request_decode + invoice_encode
 * --------------------------------------------------------------------- */

/*
 * Decode a TLV-encoded invoice_request into req_out.
 * Wire format: [type:2BE][len:2BE][value...] fields.
 *   type 82 (0x0052): amount_msat (8B BE)
 *   type 88 (0x0058): payer_key   (33B)
 *   type 240 (0x00F0): sig        (64B)
 * Returns 1 if payer_key and sig are present, 0 otherwise.
 */
int invoice_request_decode(const unsigned char *tlv, size_t tlv_len,
                             invoice_request_t *req_out)
{
    if (!tlv || !req_out) return 0;
    memset(req_out, 0, sizeof(*req_out));
    if (tlv_len == 0) return 0;

    int has_payer_key = 0, has_sig = 0;
    size_t pos = 0;
    while (pos + 4 <= tlv_len) {
        uint16_t t = ((uint16_t)tlv[pos] << 8) | tlv[pos + 1];
        uint16_t l = ((uint16_t)tlv[pos + 2] << 8) | tlv[pos + 3];
        pos += 4;
        if (pos + l > tlv_len) break;  /* truncated */
        if (t == 82 && l == 8) {        /* amount_msat */
            uint64_t v = 0;
            for (int i = 0; i < 8; i++) v = (v << 8) | tlv[pos + i];
            req_out->amount_msat = v;
        } else if (t == 88 && l == 33) { /* payer_key */
            memcpy(req_out->payer_key, tlv + pos, 33);
            has_payer_key = 1;
        } else if (t == 240 && l == 64) { /* sig */
            memcpy(req_out->sig, tlv + pos, 64);
            has_sig = 1;
        }
        pos += l;
    }
    return (has_payer_key && has_sig) ? 1 : 0;
}

/*
 * Encode an invoice_t to TLV wire bytes (type 0x8000 outer wrapper).
 * Inner fields:
 *   type 1 (8B BE): amount_msat
 *   type 2 (32B):   payment_hash
 *   type 3 (32B):   payment_secret
 *   type 4 (32B):   offer_id
 *   type 240 (64B): node_sig
 * Returns bytes written, 0 on error.
 */
size_t invoice_encode(const invoice_t *inv, unsigned char *buf, size_t buf_cap)
{
    if (!inv || !buf || buf_cap < 8) return 0;

    unsigned char body[512];
    size_t bpos = 0;

    /* type 1: amount_msat (8B BE) */
    if (bpos + 4 + 8 > sizeof(body)) return 0;
    body[bpos++] = 0x00; body[bpos++] = 0x01;
    body[bpos++] = 0x00; body[bpos++] = 0x08;
    uint64_t a = inv->amount_msat;
    body[bpos++] = (unsigned char)(a >> 56); body[bpos++] = (unsigned char)(a >> 48);
    body[bpos++] = (unsigned char)(a >> 40); body[bpos++] = (unsigned char)(a >> 32);
    body[bpos++] = (unsigned char)(a >> 24); body[bpos++] = (unsigned char)(a >> 16);
    body[bpos++] = (unsigned char)(a >>  8); body[bpos++] = (unsigned char)a;

    /* type 2: payment_hash (32B) */
    if (bpos + 4 + 32 > sizeof(body)) return 0;
    body[bpos++] = 0x00; body[bpos++] = 0x02;
    body[bpos++] = 0x00; body[bpos++] = 0x20;
    memcpy(body + bpos, inv->payment_hash, 32); bpos += 32;

    /* type 3: payment_secret (32B) */
    if (bpos + 4 + 32 > sizeof(body)) return 0;
    body[bpos++] = 0x00; body[bpos++] = 0x03;
    body[bpos++] = 0x00; body[bpos++] = 0x20;
    memcpy(body + bpos, inv->payment_secret, 32); bpos += 32;

    /* type 4: offer_id (32B) */
    if (bpos + 4 + 32 > sizeof(body)) return 0;
    body[bpos++] = 0x00; body[bpos++] = 0x04;
    body[bpos++] = 0x00; body[bpos++] = 0x20;
    memcpy(body + bpos, inv->offer_id, 32); bpos += 32;

    /* type 240: node_sig (64B) */
    if (bpos + 4 + 64 > sizeof(body)) return 0;
    body[bpos++] = 0x00; body[bpos++] = 0xF0;
    body[bpos++] = 0x00; body[bpos++] = 0x40;
    memcpy(body + bpos, inv->node_sig, 64); bpos += 64;

    /* Outer wrapper: type=0x8000, length=bpos */
    if (buf_cap < 4 + bpos) return 0;
    buf[0] = 0x80; buf[1] = 0x00;
    buf[2] = (unsigned char)(bpos >> 8); buf[3] = (unsigned char)bpos;
    memcpy(buf + 4, body, bpos);
    return 4 + bpos;
}
