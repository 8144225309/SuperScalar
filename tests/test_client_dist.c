/* Unit tests for the client's distribution-TX broadcast (client_dist.c):
   verification of the stored TX, and the decision against the chain --
   never before nLockTime, never once the funding output is spent. */

#include "superscalar/client_dist.h"
#include "superscalar/tx_builder.h"
#include "superscalar/sha256.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);

#define T_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while (0)

#define LOCKTIME 302u

typedef struct {
    secp256k1_context *ctx;
    unsigned char funding_txid[32];
    uint32_t funding_vout;
    uint64_t funding_amount;
    unsigned char spk[34];
    secp256k1_pubkey member;    /* paid by output 0 (BIP-86) */
    tx_buf_t signed_tx;
} dist_fixture_t;

/* A distribution-shaped TX: one input spending the funding output (key
   path), two P2TR outputs and a P2A anchor, signed by the funding key. */
static int fixture_build(dist_fixture_t *fx, uint32_t nsequence, uint32_t locktime) {
    memset(fx, 0, sizeof(*fx));
    fx->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char sk[32];
    memset(sk, 0x5a, 32);
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey xk;
    if (!secp256k1_keypair_create(fx->ctx, &kp, sk) ||
        !secp256k1_keypair_xonly_pub(fx->ctx, &xk, NULL, &kp)) return 0;
    build_p2tr_script_pubkey(fx->spk, &xk);
    memset(fx->funding_txid, 0xab, 32);
    fx->funding_vout = 1;
    fx->funding_amount = 400000;

    tx_output_t outs[3];
    memset(outs, 0, sizeof(outs));
    for (int i = 0; i < 2; i++) {
        outs[i].amount_sats = 199000;
        memcpy(outs[i].script_pubkey, fx->spk, 34);
        outs[i].script_pubkey[2] ^= (unsigned char)(i + 1);
        outs[i].script_pubkey_len = 34;
    }
    /* output 0 pays the member's key the way distribution outputs do */
    {
        unsigned char msk[32], ser[32], tw[32];
        memset(msk, 0x33, 32);
        secp256k1_xonly_pubkey mx, mt;
        secp256k1_pubkey mfull;
        if (!secp256k1_ec_pubkey_create(fx->ctx, &fx->member, msk) ||
            !secp256k1_xonly_pubkey_from_pubkey(fx->ctx, &mx, NULL, &fx->member) ||
            !secp256k1_xonly_pubkey_serialize(fx->ctx, ser, &mx)) return 0;
        sha256_tagged("TapTweak", ser, 32, tw);
        if (!secp256k1_xonly_pubkey_tweak_add(fx->ctx, &mfull, &mx, tw) ||
            !secp256k1_xonly_pubkey_from_pubkey(fx->ctx, &mt, NULL, &mfull)) return 0;
        build_p2tr_script_pubkey(outs[0].script_pubkey, &mt);
    }
    outs[2].amount_sats = 240;
    outs[2].script_pubkey[0] = 0x51; outs[2].script_pubkey[1] = 0x02;
    outs[2].script_pubkey[2] = 0x4e; outs[2].script_pubkey[3] = 0x73;
    outs[2].script_pubkey_len = 4;

    tx_buf_t utx;
    tx_buf_init(&utx, 256);
    unsigned char sighash[32], sig[64];
    int ok = build_unsigned_tx_with_locktime(&utx, NULL, fx->funding_txid,
                                             fx->funding_vout, nsequence, locktime,
                                             outs, 3) &&
             compute_taproot_sighash(sighash, utx.data, utx.len, 0, fx->spk, 34,
                                     fx->funding_amount, nsequence) &&
             secp256k1_schnorrsig_sign32(fx->ctx, sig, sighash, &kp, NULL);
    tx_buf_init(&fx->signed_tx, 512);
    ok = ok && finalize_signed_tx(&fx->signed_tx, utx.data, utx.len, sig);
    tx_buf_free(&utx);
    return ok;
}

static void fixture_free(dist_fixture_t *fx) {
    tx_buf_free(&fx->signed_tx);
    if (fx->ctx) secp256k1_context_destroy(fx->ctx);
}

static int verify_fx(dist_fixture_t *fx, const unsigned char *tx, size_t len,
                     client_dist_tx_t *d, char *err) {
    return client_dist_verify(fx->ctx, tx, len, fx->funding_txid, fx->funding_vout,
                              fx->funding_amount, fx->spk, 34, LOCKTIME,
                              &fx->member, 199000, d, err, 160);
}

int test_client_dist_verify_accepts_signed(void) {
    dist_fixture_t fx;
    T_ASSERT(fixture_build(&fx, 0xFFFFFFFEu, LOCKTIME), "fixture");
    client_dist_tx_t d;
    char err[160] = {0};
    T_ASSERT(verify_fx(&fx, fx.signed_tx.data, fx.signed_tx.len, &d, err), err);
    T_ASSERT(d.locktime == LOCKTIME, "locktime");
    T_ASSERT(d.n_outputs == 3, "three outputs");
    T_ASSERT(d.funding_vout == 1, "funding vout");
    T_ASSERT(d.tx_len == fx.signed_tx.len &&
             memcmp(d.tx, fx.signed_tx.data, d.tx_len) == 0, "tx copied");
    /* txid: double SHA-256 of the non-witness serialization, display order */
    tx_buf_t utx;
    tx_buf_init(&utx, 256);
    tx_buf_write_bytes(&utx, fx.signed_tx.data, 4);
    tx_buf_write_bytes(&utx, fx.signed_tx.data + 6, fx.signed_tx.len - 6 - 4 - 66);
    tx_buf_write_bytes(&utx, fx.signed_tx.data + fx.signed_tx.len - 4, 4);
    unsigned char h[32], disp[32];
    char hex[65];
    sha256_double(utx.data, utx.len, h);
    for (int i = 0; i < 32; i++) disp[i] = h[31 - i];
    hex_encode(disp, 32, hex);
    hex[64] = '\0';
    tx_buf_free(&utx);
    T_ASSERT(strcmp(hex, d.txid_hex) == 0, "txid");
    client_dist_free(&d);
    fixture_free(&fx);
    return 1;
}

int test_client_dist_verify_rejects(void) {
    dist_fixture_t fx;
    T_ASSERT(fixture_build(&fx, 0xFFFFFFFEu, LOCKTIME), "fixture");
    client_dist_tx_t d;
    char err[160];
    size_t len = fx.signed_tx.len;
    unsigned char *tx = malloc(len);
    T_ASSERT(tx, "alloc");

    /* another funding outpoint */
    T_ASSERT(!client_dist_verify(fx.ctx, fx.signed_tx.data, len, fx.funding_txid, 0,
                                 fx.funding_amount, fx.spk, 34, 0, NULL, 0, &d, err, sizeof(err)),
             "wrong vout accepted");
    T_ASSERT(strstr(err, "funding output") != NULL, err);
    /* another funding amount: the BIP-341 sighash commits to it */
    T_ASSERT(!client_dist_verify(fx.ctx, fx.signed_tx.data, len, fx.funding_txid, 1,
                                 fx.funding_amount + 1, fx.spk, 34, 0, NULL, 0, &d, err, sizeof(err)),
             "wrong amount accepted");
    T_ASSERT(strstr(err, "signature") != NULL, err);
    /* bound to the member's terms: the factory CLTV timeout and its share */
    T_ASSERT(!client_dist_verify(fx.ctx, fx.signed_tx.data, len, fx.funding_txid, 1,
                                 fx.funding_amount, fx.spk, 34, LOCKTIME + 1, &fx.member,
                                 0, &d, err, sizeof(err)), "other nLockTime accepted");
    T_ASSERT(strstr(err, "CLTV timeout") != NULL, err);
    T_ASSERT(!client_dist_verify(fx.ctx, fx.signed_tx.data, len, fx.funding_txid, 1,
                                 fx.funding_amount, fx.spk, 34, LOCKTIME, &fx.member,
                                 199001, &d, err, sizeof(err)), "short share accepted");
    T_ASSERT(strstr(err, "pays this member") != NULL, err);
    {
        secp256k1_pubkey other;
        unsigned char osk[32];
        memset(osk, 0x44, 32);
        T_ASSERT(secp256k1_ec_pubkey_create(fx.ctx, &other, osk), "other key");
        T_ASSERT(!client_dist_verify(fx.ctx, fx.signed_tx.data, len, fx.funding_txid, 1,
                                     fx.funding_amount, fx.spk, 34, LOCKTIME, &other,
                                     1, &d, err, sizeof(err)), "pays another key: accepted");
    }
    /* an output amount changed after signing */
    memcpy(tx, fx.signed_tx.data, len);
    tx[4 + 2 + 1 + 36 + 1 + 4 + 1] ^= 0x01;
    T_ASSERT(!verify_fx(&fx, tx, len, &d, err), "altered output accepted");
    T_ASSERT(strstr(err, "signature") != NULL, err);
    /* nLockTime changed after signing */
    memcpy(tx, fx.signed_tx.data, len);
    tx[len - 4] ^= 0x01;
    T_ASSERT(!verify_fx(&fx, tx, len, &d, err), "altered nLockTime accepted");
    /* truncated */
    T_ASSERT(!verify_fx(&fx, fx.signed_tx.data, len - 1, &d, err), "truncated accepted");
    /* no witness (unsigned serialization) */
    memcpy(tx, fx.signed_tx.data, len);
    tx[4] = 0x02;
    T_ASSERT(!verify_fx(&fx, tx, len, &d, err), "non-segwit accepted");
    free(tx);
    fixture_free(&fx);

    /* final nSequence: nLockTime would not apply */
    T_ASSERT(fixture_build(&fx, 0xFFFFFFFFu, LOCKTIME), "fixture final");
    T_ASSERT(!verify_fx(&fx, fx.signed_tx.data, fx.signed_tx.len, &d, err),
             "final nSequence accepted");
    T_ASSERT(strstr(err, "nSequence") != NULL, err);
    fixture_free(&fx);
    /* time-based nLockTime */
    T_ASSERT(fixture_build(&fx, 0xFFFFFFFEu, 600000000u), "fixture time");
    T_ASSERT(!verify_fx(&fx, fx.signed_tx.data, fx.signed_tx.len, &d, err),
             "time nLockTime accepted");
    fixture_free(&fx);
    return 1;
}

/* --- mock chain --- */
typedef struct {
    int tip;
    int dist_confs;             /* get_confirmations(dist) */
    int funding_unspent;        /* is_outpoint_unspent(funding) */
    int dist_out_unspent;       /* is_outpoint_unspent(dist, *) */
    int send_ok;
    int n_sends;
    char sent_hex[2048];
    char dist_txid[65];
} mock_chain_t;

static mock_chain_t g_mock;

static int m_height(chain_backend_t *c) { (void)c; return g_mock.tip; }
static int m_confs(chain_backend_t *c, const char *txid) {
    (void)c;
    return strcmp(txid, g_mock.dist_txid) == 0 ? g_mock.dist_confs : -1;
}
static int m_unspent(chain_backend_t *c, const char *txid, uint32_t vout) {
    (void)c; (void)vout;
    return strcmp(txid, g_mock.dist_txid) == 0 ? g_mock.dist_out_unspent
                                               : g_mock.funding_unspent;
}
static int m_send(chain_backend_t *c, const char *hex, char *txid_out) {
    (void)c;
    g_mock.n_sends++;
    snprintf(g_mock.sent_hex, sizeof(g_mock.sent_hex), "%s", hex);
    if (txid_out) snprintf(txid_out, 65, "%s", g_mock.dist_txid);
    return g_mock.send_ok;
}

static void mock_init(chain_backend_t *c, const client_dist_tx_t *d) {
    memset(c, 0, sizeof(*c));
    memset(&g_mock, 0, sizeof(g_mock));
    c->get_block_height = m_height;
    c->get_confirmations = m_confs;
    c->is_outpoint_unspent = m_unspent;
    c->send_raw_tx = m_send;
    snprintf(g_mock.dist_txid, sizeof(g_mock.dist_txid), "%s", d->txid_hex);
    g_mock.dist_confs = -1;
    g_mock.funding_unspent = 1;
    g_mock.dist_out_unspent = 0;
    g_mock.send_ok = 1;
}

int test_client_dist_step_never_early(void) {
    dist_fixture_t fx;
    T_ASSERT(fixture_build(&fx, 0xFFFFFFFEu, LOCKTIME), "fixture");
    client_dist_tx_t d;
    char err[160];
    T_ASSERT(verify_fx(&fx, fx.signed_tx.data, fx.signed_tx.len, &d, err), err);
    chain_backend_t c;
    mock_init(&c, &d);
    int tip = 0;

    g_mock.tip = (int)LOCKTIME - 1;
    T_ASSERT(client_dist_step(&c, &d, NULL, &tip, NULL) == CLIENT_DIST_NOT_YET, "not yet");
    T_ASSERT(tip == (int)LOCKTIME - 1, "tip out");
    g_mock.tip = 0;
    T_ASSERT(client_dist_step(&c, &d, NULL, NULL, NULL) == CLIENT_DIST_NOT_YET, "tip 0");
    g_mock.tip = -1;
    T_ASSERT(client_dist_step(&c, &d, NULL, NULL, NULL) == CLIENT_DIST_NO_CHAIN, "no tip");
    T_ASSERT(g_mock.n_sends == 0, "sent before nLockTime");

    /* due: tip == nLockTime, funding unspent */
    g_mock.tip = (int)LOCKTIME;
    T_ASSERT(client_dist_step(&c, &d, NULL, NULL, NULL) == CLIENT_DIST_BROADCAST, "due");
    T_ASSERT(g_mock.n_sends == 1, "one send");
    char hex[2048];
    hex_encode(fx.signed_tx.data, fx.signed_tx.len, hex);
    hex[fx.signed_tx.len * 2] = '\0';
    T_ASSERT(strcmp(hex, g_mock.sent_hex) == 0, "sent the stored tx");

    /* refused by the node: reported, sent again next time */
    g_mock.send_ok = 0;
    T_ASSERT(client_dist_step(&c, &d, NULL, NULL, NULL) == CLIENT_DIST_REFUSED, "refused");
    T_ASSERT(g_mock.n_sends == 2, "resent");

    /* caller-supplied broadcaster is used instead of send_raw_tx */
    g_mock.send_ok = 1;
    T_ASSERT(client_dist_step(&c, &d, m_send, NULL, NULL) == CLIENT_DIST_BROADCAST, "hook");
    T_ASSERT(g_mock.n_sends == 3, "hook sent");
    client_dist_free(&d);
    fixture_free(&fx);
    return 1;
}

int test_client_dist_step_spent_and_confirmed(void) {
    dist_fixture_t fx;
    T_ASSERT(fixture_build(&fx, 0xFFFFFFFEu, LOCKTIME), "fixture");
    client_dist_tx_t d;
    char err[160];
    T_ASSERT(verify_fx(&fx, fx.signed_tx.data, fx.signed_tx.len, &d, err), err);
    chain_backend_t c;
    mock_init(&c, &d);
    g_mock.tip = (int)LOCKTIME + 50;

    /* funding spent by another tx (tree, close): nothing sent */
    g_mock.funding_unspent = 0;
    T_ASSERT(client_dist_step(&c, &d, NULL, NULL, NULL) == CLIENT_DIST_FUNDING_SPENT, "spent");
    T_ASSERT(g_mock.n_sends == 0, "sent after funding spent");
    /* funding spent by the distribution TX itself, seen through its outputs */
    g_mock.dist_out_unspent = 1;
    T_ASSERT(client_dist_step(&c, &d, NULL, NULL, NULL) == CLIENT_DIST_CONFIRMED, "via outputs");
    /* in mempool / confirmed by txid */
    g_mock.dist_out_unspent = 0;
    g_mock.dist_confs = 0;
    T_ASSERT(client_dist_step(&c, &d, NULL, NULL, NULL) == CLIENT_DIST_IN_MEMPOOL, "mempool");
    g_mock.dist_confs = 3;
    T_ASSERT(client_dist_step(&c, &d, NULL, NULL, NULL) == CLIENT_DIST_CONFIRMED, "confirmed");
    T_ASSERT(g_mock.n_sends == 0, "no send when already published");
    /* the backend cannot tell whether the funding output is spent (an
       HTTP-RPC error, or no is_outpoint_unspent at all): the TX is sent,
       but whether the node takes it or refuses it, nothing is settled */
    g_mock.dist_confs = -1;
    g_mock.funding_unspent = -1;
    int sends = g_mock.n_sends;
    g_mock.send_ok = 0;
    client_dist_status_t s1 = client_dist_step(&c, &d, NULL, NULL, NULL);
    T_ASSERT(s1 == CLIENT_DIST_FUNDING_UNKNOWN, "refused, funding unknown");
    T_ASSERT(!client_dist_settles(s1), "a refused TX with unknown funding is no exit");
    g_mock.send_ok = 1;
    c.is_outpoint_unspent = NULL;
    s1 = client_dist_step(&c, &d, NULL, NULL, NULL);
    T_ASSERT(s1 == CLIENT_DIST_FUNDING_UNKNOWN, "accepted, funding unknown");
    T_ASSERT(!client_dist_settles(s1), "unknown funding never settles");
    T_ASSERT(g_mock.n_sends == sends + 2, "still sent");
    /* known unspent: refused and sent counts as the exit */
    c.is_outpoint_unspent = m_unspent;
    g_mock.funding_unspent = 1;
    g_mock.send_ok = 0;
    T_ASSERT(client_dist_settles(client_dist_step(&c, &d, NULL, NULL, NULL)),
             "refused with the funding output there settles");
    T_ASSERT(!client_dist_settles(CLIENT_DIST_FUNDING_SPENT) &&
             !client_dist_settles(CLIENT_DIST_NOT_YET), "tree cases");
    int confs = 0;
    g_mock.dist_confs = 4;
    T_ASSERT(client_dist_step(&c, &d, NULL, NULL, &confs) == CLIENT_DIST_CONFIRMED &&
             confs == 4, "confirmations reported");
    client_dist_free(&d);
    fixture_free(&fx);
    return 1;
}
