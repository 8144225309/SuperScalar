/*
 * test_htlc_claim.c — on-chain HTLC-success claims (BOLT #5).
 *
 * A payee that has revealed a preimage must be able to claim the HTLC on
 * chain when the commitment still holding it is broadcast (e.g. the sender
 * withholds its revoke_and_ack), before the sender can time it out.
 *
 * Unit tests:
 *   test_htlc_claim_local_commit     claim from our own commitment
 *   test_htlc_claim_remote_commit    claim from the counterparty's
 *   test_htlc_claim_preimage_script  success-leaf script + fail-closed checks
 */

#include "superscalar/channel.h"
#include "superscalar/musig.h"
#include "superscalar/tapscript.h"
#include "superscalar/tx_builder.h"
#include "superscalar/sha256.h"
#include <secp256k1_schnorrsig.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int  hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while (0)

static const unsigned char LSP_SECKEY[32] = { [31] = 0x01 };
static const unsigned char CLI_SECKEY[32] = { [31] = 0x02 };

/* ------------------------------------------------------------------ */
/* Channel pair: LSP and client views of one channel                    */
/* ------------------------------------------------------------------ */

typedef struct {
    secp256k1_context *ctx;
    secp256k1_keypair lsp_kp, cli_kp;
    channel_t lsp, cli;
    unsigned char fund_spk[34];
    unsigned char preimage[32];
    unsigned char hash[32];
    uint64_t lsp_htlc_id, cli_htlc_id;
} pair_t;

static int pair_fund_spk(secp256k1_context *ctx, const secp256k1_pubkey *a,
                         const secp256k1_pubkey *b, unsigned char *spk34,
                         unsigned char *xonly32)
{
    secp256k1_pubkey pks[2] = { *a, *b };
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks, 2)) return 0;
    unsigned char agg[32];
    secp256k1_xonly_pubkey_serialize(ctx, agg, &ka.agg_pubkey);
    unsigned char tweak[32];
    sha256_tagged("TapTweak", agg, 32, tweak);
    secp256k1_pubkey tpk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tpk, &ka.cache, tweak))
        return 0;
    secp256k1_xonly_pubkey tpx;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &tpx, NULL, &tpk);
    build_p2tr_script_pubkey(spk34, &tpx);
    if (xonly32) secp256k1_xonly_pubkey_serialize(ctx, xonly32, &tpx);
    return 1;
}

/* Initialise both views over funding (txid, vout, amount), exchange
   basepoints and the first per-commitment points. */
static int pair_init(pair_t *p, secp256k1_context *ctx,
                     const unsigned char *fund_txid, uint32_t fund_vout,
                     uint64_t fund_amount, uint32_t csv)
{
    memset(p, 0, sizeof(*p));
    p->ctx = ctx;
    secp256k1_keypair_create(ctx, &p->lsp_kp, LSP_SECKEY);
    secp256k1_keypair_create(ctx, &p->cli_kp, CLI_SECKEY);
    secp256k1_pubkey lpk, cpk;
    secp256k1_keypair_pub(ctx, &lpk, &p->lsp_kp);
    secp256k1_keypair_pub(ctx, &cpk, &p->cli_kp);
    if (!pair_fund_spk(ctx, &lpk, &cpk, p->fund_spk, NULL)) return 0;

    uint64_t lsp_amt = 50000, cli_amt = fund_amount - 50000 - 500;
    if (!channel_init(&p->lsp, ctx, LSP_SECKEY, &lpk, &cpk, fund_txid,
                      fund_vout, fund_amount, p->fund_spk, 34,
                      lsp_amt, cli_amt, csv))
        return 0;
    if (!channel_init(&p->cli, ctx, CLI_SECKEY, &cpk, &lpk, fund_txid,
                      fund_vout, fund_amount, p->fund_spk, 34,
                      cli_amt, lsp_amt, csv))
        return 0;
    p->lsp.funder_is_local = 1;     /* as lsp_channels_init / client.c */
    p->cli.funder_is_local = 0;
    channel_generate_random_basepoints(&p->lsp);
    channel_generate_random_basepoints(&p->cli);
    channel_set_remote_basepoints(&p->lsp, &p->cli.local_payment_basepoint,
        &p->cli.local_delayed_payment_basepoint,
        &p->cli.local_revocation_basepoint);
    channel_set_remote_basepoints(&p->cli, &p->lsp.local_payment_basepoint,
        &p->lsp.local_delayed_payment_basepoint,
        &p->lsp.local_revocation_basepoint);
    channel_set_remote_htlc_basepoint(&p->lsp, &p->cli.local_htlc_basepoint);
    channel_set_remote_htlc_basepoint(&p->cli, &p->lsp.local_htlc_basepoint);
    for (uint64_t cn = 0; cn <= 1; cn++) {
        secp256k1_pubkey a, b;
        channel_get_per_commitment_point(&p->lsp, cn, &a);
        channel_get_per_commitment_point(&p->cli, cn, &b);
        channel_set_remote_pcp(&p->lsp, cn, &b);
        channel_set_remote_pcp(&p->cli, cn, &a);
    }
    memset(p->preimage, 0x5A, 32);
    sha256(p->preimage, 32, p->hash);
    return 1;
}

/* Add one HTLC.  client_pays: client offers to the LSP; else LSP offers. */
static int pair_add_htlc(pair_t *p, int client_pays, uint64_t amount,
                         uint32_t cltv)
{
    if (!channel_add_htlc(&p->lsp, client_pays ? HTLC_RECEIVED : HTLC_OFFERED,
                          amount, p->hash, cltv, &p->lsp_htlc_id))
        return 0;
    if (!channel_add_htlc(&p->cli, client_pays ? HTLC_OFFERED : HTLC_RECEIVED,
                          amount, p->hash, cltv, &p->cli_htlc_id))
        return 0;
    return 1;
}

static void pair_cleanup(pair_t *p)
{
    channel_cleanup(&p->lsp);
    channel_cleanup(&p->cli);
}

/* ------------------------------------------------------------------ */
/* Transaction parsing (tests only; single-byte varints)                */
/* ------------------------------------------------------------------ */

typedef struct {
    unsigned char prev_txid[32];
    uint32_t prev_vout, sequence, locktime;
    size_t n_out;
    uint64_t out_amount[4];
    unsigned char out_spk[4][34];
    size_t n_wit;
    const unsigned char *wit[8];
    size_t wit_len[8];
    unsigned char txid_display[32];
} ptx_t;

static uint32_t rd32(const unsigned char *b)
{
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}

static int ptx_parse(const unsigned char *tx, size_t len, ptx_t *o)
{
    memset(o, 0, sizeof(*o));
    if (len < 12) return 0;
    int segwit = (tx[4] == 0x00 && tx[5] == 0x01);
    size_t ofs = segwit ? 6 : 4;
    size_t body_start = ofs;
    if (tx[ofs++] != 1) return 0;
    memcpy(o->prev_txid, tx + ofs, 32);
    o->prev_vout = rd32(tx + ofs + 32);
    ofs += 36;
    size_t ss = tx[ofs++];
    ofs += ss;
    o->sequence = rd32(tx + ofs);
    ofs += 4;
    o->n_out = tx[ofs++];
    if (o->n_out > 4) return 0;
    for (size_t v = 0; v < o->n_out; v++) {
        uint64_t a = 0;
        for (int b = 0; b < 8; b++) a |= (uint64_t)tx[ofs + b] << (8 * b);
        o->out_amount[v] = a;
        size_t sl = tx[ofs + 8];
        if (sl == 34) memcpy(o->out_spk[v], tx + ofs + 9, 34);
        ofs += 9 + sl;
    }
    size_t body_end = ofs;
    if (segwit) {
        o->n_wit = tx[ofs++];
        if (o->n_wit > 8) return 0;
        for (size_t w = 0; w < o->n_wit; w++) {
            o->wit_len[w] = tx[ofs++];
            o->wit[w] = tx + ofs;
            ofs += o->wit_len[w];
        }
    }
    if (ofs + 4 != len) return 0;
    o->locktime = rd32(tx + ofs);

    /* txid = dsha256(version | body | locktime) */
    size_t nw_len = 4 + (body_end - body_start) + 4;
    unsigned char *nw = malloc(nw_len);
    if (!nw) return 0;
    memcpy(nw, tx, 4);
    memcpy(nw + 4, tx + body_start, body_end - body_start);
    memcpy(nw + 4 + (body_end - body_start), tx + ofs, 4);
    sha256_double(nw, nw_len, o->txid_display);
    reverse_bytes(o->txid_display, 32);
    free(nw);
    return 1;
}

/* Find the output paying spk34 in an unsigned commitment. */
static int find_vout(const tx_buf_t *tx, const unsigned char *spk34,
                     uint32_t *vout, uint64_t *amount)
{
    ptx_t t;
    if (!ptx_parse(tx->data, tx->len, &t)) return 0;
    for (size_t v = 0; v < t.n_out; v++)
        if (memcmp(t.out_spk[v], spk34, 34) == 0) {
            *vout = (uint32_t)v;
            *amount = t.out_amount[v];
            return 1;
        }
    return 0;
}

static const unsigned char UNIT_FUND_TXID[32] = { [0 ... 31] = 0x11 };

/* ------------------------------------------------------------------ */
/* Unit tests                                                           */
/* ------------------------------------------------------------------ */

/* Claim from our own commitment: the LSP received an HTLC and broadcasts
   its commitment.  The claim must match the HTLC output and agree byte for
   byte with the existing (regtest-proven) received-HTLC success builder. */
int test_htlc_claim_local_commit(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init");
    TEST_ASSERT(pair_add_htlc(&p, 1, 5000, 500), "add htlc");

    tx_buf_t uc;
    tx_buf_init(&uc, 1024);
    unsigned char ct[32];
    TEST_ASSERT(channel_build_commitment_tx(&p.lsp, &uc, ct), "build commit");

    secp256k1_pubkey pcp;
    TEST_ASSERT(channel_get_per_commitment_point(&p.lsp,
                    p.lsp.commitment_number, &pcp), "pcp");
    unsigned char spk[34];
    TEST_ASSERT(channel_htlc_claim_spk(&p.lsp, HTLC_CLAIM_LOCAL_COMMIT, &pcp,
                    p.hash, 500, spk), "claim spk");
    uint32_t vout; uint64_t amt;
    TEST_ASSERT(find_vout(&uc, spk, &vout, &amt), "claim spk is on commitment");
    TEST_ASSERT(vout == 2 && amt == 5000, "HTLC output at vout 2");

    tx_buf_t claim;
    tx_buf_init(&claim, 512);
    uint64_t out_amt = 0;
    TEST_ASSERT(channel_build_htlc_claim_tx(&p.lsp, &claim,
                    HTLC_CLAIM_LOCAL_COMMIT, &pcp, ct, vout, amt, spk,
                    p.hash, p.preimage, 500, 0, &out_amt, NULL), "build claim");

    /* Cross-check with the existing builder for a received HTLC. */
    memcpy(p.lsp.htlcs[0].payment_preimage, p.preimage, 32);
    tx_buf_t old;
    tx_buf_init(&old, 512);
    TEST_ASSERT(channel_build_htlc_success_tx(&p.lsp, &old, ct, vout, amt,
                    spk, 34, 0), "build reference");
    TEST_ASSERT(old.len == claim.len &&
                memcmp(old.data, claim.data, old.len) == 0,
                "local claim identical to reference success tx");

    ptx_t t;
    TEST_ASSERT(ptx_parse(claim.data, claim.len, &t), "parse claim");
    TEST_ASSERT(t.sequence == 10, "nSequence = to_self_delay (CSV)");
    TEST_ASSERT(t.locktime == 0, "no CLTV wait on the success path");
    TEST_ASSERT(t.n_wit == 4, "witness = sig, preimage, script, control");
    TEST_ASSERT(t.wit_len[1] == 32 && memcmp(t.wit[1], p.preimage, 32) == 0,
                "preimage in witness");
    TEST_ASSERT(t.n_out == 1 && t.out_amount[0] == out_amt,
                "single output with reported amount");

    tx_buf_free(&uc); tx_buf_free(&claim); tx_buf_free(&old);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Claim from the counterparty's commitment: the client offered the HTLC
   and broadcasts its own commitment (the one it holds signed).  The LSP's
   remote view must reproduce that txid and HTLC output, and the claim must
   carry a valid signature for the offered-HTLC success leaf. */
int test_htlc_claim_remote_commit(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init");
    TEST_ASSERT(pair_add_htlc(&p, 1, 7000, 600), "add htlc");

    tx_buf_t cli_c, lsp_view;
    tx_buf_init(&cli_c, 1024); tx_buf_init(&lsp_view, 1024);
    unsigned char cli_txid[32], view_txid[32];
    TEST_ASSERT(channel_build_commitment_tx(&p.cli, &cli_c, cli_txid),
                "client commitment");
    TEST_ASSERT(channel_build_commitment_tx_for_remote(&p.lsp, &lsp_view,
                    view_txid), "LSP view of client commitment");
    TEST_ASSERT(memcmp(cli_txid, view_txid, 32) == 0,
                "LSP's remote view matches the client's commitment");

    secp256k1_pubkey pcp, cli_pcp;
    uint64_t cn = p.lsp.commitment_number;
    TEST_ASSERT(channel_get_remote_pcp(&p.lsp, cn, &pcp), "remote pcp");
    channel_get_per_commitment_point(&p.cli, cn, &cli_pcp);
    TEST_ASSERT(secp256k1_ec_pubkey_cmp(ctx, &pcp, &cli_pcp) == 0,
                "remote pcp is the client's");

    unsigned char spk[34], spk_wrong_side[34];
    TEST_ASSERT(channel_htlc_claim_spk(&p.lsp, HTLC_CLAIM_REMOTE_COMMIT, &pcp,
                    p.hash, 600, spk), "claim spk");
    uint32_t vout; uint64_t amt;
    TEST_ASSERT(find_vout(&cli_c, spk, &vout, &amt),
                "claim spk is on the client's commitment");
    TEST_ASSERT(vout == 2 && amt == 7000, "HTLC output at vout 2");
    channel_htlc_claim_spk(&p.lsp, HTLC_CLAIM_LOCAL_COMMIT, &pcp, p.hash, 600,
                           spk_wrong_side);
    TEST_ASSERT(memcmp(spk, spk_wrong_side, 34) != 0,
                "remote and local trees differ");

    tx_buf_t claim;
    tx_buf_init(&claim, 512);
    uint64_t out_amt = 0;
    unsigned char claim_txid[32];
    TEST_ASSERT(channel_build_htlc_claim_tx(&p.lsp, &claim,
                    HTLC_CLAIM_REMOTE_COMMIT, &pcp, cli_txid, vout, amt, spk,
                    p.hash, p.preimage, 600, 0, &out_amt, claim_txid),
                "build claim");

    ptx_t t;
    TEST_ASSERT(ptx_parse(claim.data, claim.len, &t), "parse claim");
    TEST_ASSERT(memcmp(t.prev_txid, cli_txid, 32) == 0 && t.prev_vout == vout,
                "spends the HTLC output");
    TEST_ASSERT(t.sequence == 0xFFFFFFFD, "no CSV on the offered success leaf");
    TEST_ASSERT(t.locktime == 0, "no CLTV wait");
    TEST_ASSERT(memcmp(t.txid_display, claim_txid, 32) == 0, "reported txid");
    TEST_ASSERT(t.n_wit == 4 && t.wit_len[0] == 64, "4-item witness");
    TEST_ASSERT(t.wit_len[1] == 32 && memcmp(t.wit[1], p.preimage, 32) == 0,
                "preimage in witness");

    /* The script is the offered-HTLC success leaf for OUR htlc key under
       the client's per-commitment point. */
    secp256k1_pubkey our_htlc;
    TEST_ASSERT(channel_derive_pubkey(ctx, &our_htlc,
                    &p.lsp.local_htlc_basepoint, &pcp), "derive key");
    secp256k1_xonly_pubkey our_x;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &our_x, NULL, &our_htlc);
    tapscript_leaf_t leaf;
    tapscript_build_htlc_offered_success(&leaf, p.hash, &our_x, ctx);
    TEST_ASSERT(t.wit_len[2] == leaf.script_len &&
                memcmp(t.wit[2], leaf.script, leaf.script_len) == 0,
                "witness script = offered success leaf");
    TEST_ASSERT(t.wit_len[3] == 65, "2-leaf control block");

    /* Verify the signature over the tapscript sighash. */
    tx_output_t out;
    memcpy(out.script_pubkey, t.out_spk[0], 34);
    out.script_pubkey_len = 34;
    out.amount_sats = t.out_amount[0];
    tx_buf_t ut;
    tx_buf_init(&ut, 256);
    unsigned char ut_txid[32];
    TEST_ASSERT(build_unsigned_tx(&ut, ut_txid, cli_txid, vout, t.sequence,
                                  &out, 1), "rebuild unsigned");
    unsigned char sighash[32];
    TEST_ASSERT(compute_tapscript_sighash(sighash, ut.data, ut.len, 0, spk, 34,
                    amt, t.sequence, &leaf), "sighash");
    TEST_ASSERT(secp256k1_schnorrsig_verify(ctx, t.wit[0], sighash, 32,
                                             &our_x), "signature valid");
    TEST_ASSERT(out_amt == amt - channel_htlc_claim_fee(&p.lsp),
                "default fee: the channel rule");

    /* An explicit fee is paid as given; the same fee rebuilds the same tx. */
    tx_buf_t c2, c3;
    tx_buf_init(&c2, 512); tx_buf_init(&c3, 512);
    uint64_t out2 = 0;
    unsigned char txid2[32], txid3[32];
    TEST_ASSERT(channel_build_htlc_claim_tx(&p.lsp, &c2,
                    HTLC_CLAIM_REMOTE_COMMIT, &pcp, cli_txid, vout, amt, spk,
                    p.hash, p.preimage, 600, 900, &out2, txid2) &&
                channel_build_htlc_claim_tx(&p.lsp, &c3,
                    HTLC_CLAIM_REMOTE_COMMIT, &pcp, cli_txid, vout, amt, spk,
                    p.hash, p.preimage, 600, 900, NULL, txid3),
                "build with an explicit fee");
    TEST_ASSERT(out2 == amt - 900, "explicit fee paid");
    TEST_ASSERT(memcmp(txid2, txid3, 32) == 0 &&
                memcmp(txid2, claim_txid, 32) != 0, "deterministic per fee");
    TEST_ASSERT(!channel_build_htlc_claim_tx(&p.lsp, &c3,
                    HTLC_CLAIM_REMOTE_COMMIT, &pcp, cli_txid, vout, amt, spk,
                    p.hash, p.preimage, 600, amt - 500, NULL, NULL),
                "fee leaving a dust output refused");
    tx_buf_free(&c2); tx_buf_free(&c3);

    tx_buf_free(&ut); tx_buf_free(&claim);
    tx_buf_free(&cli_c); tx_buf_free(&lsp_view);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Success-leaf scripts and the builder's fail-closed checks. */
int test_htlc_claim_preimage_script(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init");
    TEST_ASSERT(pair_add_htlc(&p, 1, 7000, 600), "add htlc");

    secp256k1_pubkey pcp;
    TEST_ASSERT(channel_get_remote_pcp(&p.lsp, p.lsp.commitment_number, &pcp),
                "pcp");
    tx_buf_t cli_c;
    tx_buf_init(&cli_c, 1024);
    unsigned char cli_txid[32];
    TEST_ASSERT(channel_build_commitment_tx(&p.cli, &cli_c, cli_txid), "commit");
    unsigned char spk[34];
    channel_htlc_claim_spk(&p.lsp, HTLC_CLAIM_REMOTE_COMMIT, &pcp, p.hash, 600,
                           spk);
    uint32_t vout; uint64_t amt;
    TEST_ASSERT(find_vout(&cli_c, spk, &vout, &amt), "HTLC output");

    tx_buf_t claim;
    tx_buf_init(&claim, 512);
    TEST_ASSERT(channel_build_htlc_claim_tx(&p.lsp, &claim,
                    HTLC_CLAIM_REMOTE_COMMIT, &pcp, cli_txid, vout, amt, spk,
                    p.hash, p.preimage, 600, 0, NULL, NULL), "good claim");
    ptx_t t;
    TEST_ASSERT(ptx_parse(claim.data, claim.len, &t), "parse");

    /* OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUALVERIFY <key> OP_CHECKSIG */
    const unsigned char *s = t.wit[2];
    TEST_ASSERT(t.wit_len[2] == 4 + 2 + 32 + 1 + 33 + 1, "script length");
    TEST_ASSERT(s[0] == 0x82 && s[1] == 0x01 && s[2] == 0x20 && s[3] == 0x88 &&
                s[4] == 0xa8 && s[5] == 0x20, "size/sha256 prefix");
    TEST_ASSERT(memcmp(s + 6, p.hash, 32) == 0, "payment hash in script");
    TEST_ASSERT(s[38] == 0x88 && s[39] == 0x20 && s[72] == 0xac,
                "equalverify, key, checksig");
    unsigned char h[32];
    sha256(t.wit[1], 32, h);
    TEST_ASSERT(memcmp(h, s + 6, 32) == 0, "witness preimage hashes to script hash");

    /* The received-HTLC success leaf (our commitment) adds the CSV. */
    secp256k1_pubkey lpcp;
    channel_get_per_commitment_point(&p.lsp, p.lsp.commitment_number, &lpcp);
    tx_buf_t lc;
    tx_buf_init(&lc, 1024);
    unsigned char lct[32];
    TEST_ASSERT(channel_build_commitment_tx(&p.lsp, &lc, lct), "local commit");
    unsigned char lspk[34];
    channel_htlc_claim_spk(&p.lsp, HTLC_CLAIM_LOCAL_COMMIT, &lpcp, p.hash, 600,
                           lspk);
    uint32_t lv; uint64_t la;
    TEST_ASSERT(find_vout(&lc, lspk, &lv, &la), "local HTLC output");
    tx_buf_t lcl;
    tx_buf_init(&lcl, 512);
    TEST_ASSERT(channel_build_htlc_claim_tx(&p.lsp, &lcl,
                    HTLC_CLAIM_LOCAL_COMMIT, &lpcp, lct, lv, la, lspk,
                    p.hash, p.preimage, 600, 0, NULL, NULL), "local claim");
    ptx_t lt;
    TEST_ASSERT(ptx_parse(lcl.data, lcl.len, &lt), "parse local");
    const unsigned char *ls = lt.wit[2];
    TEST_ASSERT(ls[38] == 0x88 && ls[39] == 0x5a && ls[40] == 0xb2 &&
                ls[41] == 0x75, "<10> OP_CSV OP_DROP after the hash check");

    /* Fail closed: wrong preimage, wrong script (other side's tree). */
    unsigned char bad[32];
    memcpy(bad, p.preimage, 32);
    bad[0] ^= 1;
    tx_buf_t x;
    tx_buf_init(&x, 512);
    TEST_ASSERT(!channel_build_htlc_claim_tx(&p.lsp, &x,
                    HTLC_CLAIM_REMOTE_COMMIT, &pcp, cli_txid, vout, amt, spk,
                    p.hash, bad, 600, 0, NULL, NULL), "wrong preimage refused");
    TEST_ASSERT(!channel_build_htlc_claim_tx(&p.lsp, &x,
                    HTLC_CLAIM_LOCAL_COMMIT, &pcp, cli_txid, vout, amt, spk,
                    p.hash, p.preimage, 600, 0, NULL, NULL),
                "script mismatch refused");
    TEST_ASSERT(!channel_build_htlc_claim_tx(&p.lsp, &x,
                    HTLC_CLAIM_REMOTE_COMMIT, &pcp, cli_txid, vout, amt, spk,
                    p.hash, p.preimage, 601, 0, NULL, NULL),
                "wrong CLTV (different script) refused");

    tx_buf_free(&x); tx_buf_free(&lcl); tx_buf_free(&lc);
    tx_buf_free(&claim); tx_buf_free(&cli_c);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}
