/*
 * test_htlc_claim.c — on-chain HTLC-success claims (BOLT #5).
 *
 * A payee that has revealed a preimage must be able to claim the HTLC on
 * chain when the commitment still holding it is broadcast (e.g. the sender
 * withholds its revoke_and_ack), before the sender can time it out.
 *
 * Unit tests (mock chain):
 *   test_htlc_claim_local_commit          claim from our own commitment
 *   test_htlc_claim_remote_commit         claim from the counterparty's
 *   test_htlc_claim_preimage_script       success-leaf script + fail-closed checks
 *   test_htlc_claim_schema_columns_any_version  claim columns at any version
 *   test_htlc_claim_newer_revocation_keeps_claim  revoking N+1 keeps N's claim
 *   test_htlc_claim_same_hash_two_outputs one claim per HTLC output
 *   test_htlc_claim_dust_not_armed        no claim that would leave dust; fee
 *   test_htlc_claim_pending_lookup_and_prune  no search; superseded dropped
 *   test_htlc_claim_superseded_reorg      superseded only once buried final
 *   test_htlc_claim_spent_output_seen     a spent HTLC output is not "absent"
 *   test_htlc_claim_armed_expiry          armed claims never broadcast expire
 *   test_htlc_claim_watch_armed_from_known  watch armed from a known preimage
 *   test_htlc_claim_watch_then_arm        watch, then arm with the preimage
 *   test_htlc_claim_registration_fails_closed  no claim that is not on disk
 *   test_htlc_claim_filter_backend        BIP 158-style backend
 *   test_htlc_claim_preimage_sealed       preimage sealed at rest
 *   test_htlc_claim_penalty_spent         our penalty spent it: not lost
 *   test_htlc_claim_persist_reload        sweeper persistence across a reload
 *   test_htlc_claim_schema_upgrade        pending_sweeps claim-column migration
 *   test_htlc_claim_priority_timing       claim timing vs the CLTV / timeout path
 *   test_htlc_claim_lsp_sender_selection  LSP arms claims on sender channels
 *   test_htlc_claim_lsp_fulfil_handler    the LSP fulfil handler arms the claim
 *   test_htlc_claim_lsp_bridge_handler    the bridge pay-result handler too
 *   test_htlc_claim_client_without_lsp    client claims from its DB alone
 *   test_htlc_claim_withheld_raa_second_htlc  sender keeps N: A and B claimed
 *   test_htlc_claim_garbled_raa_fails_channel  invalid revocation fails it
 *   test_htlc_claim_unrevoked_after_add   add without an answer: N watched
 *   test_htlc_claim_add_sender_watched    handle_add_htlc, sender leg
 *   test_htlc_claim_add_dest_watched      handle_add_htlc, destination leg
 *   test_htlc_claim_bridge_add_watched    bridge add, no rollback over a CS
 *   test_htlc_claim_payee_fulfil_watched  payee leg: watched, not fatal
 *   test_htlc_claim_settlement_garbled_raa  profit settlement update
 *   test_htlc_claim_rollback_behind_signed  no second commitment at a number
 *   test_htlc_claim_no_second_commitment  sign / resend rules, on disk
 *   test_htlc_claim_failed_reconnect_told failed channel: client told
 *   test_htlc_claim_slow_sender_recovers  late revocation restores it
 *   test_htlc_claim_reconnect_behind_rolled_back  back to the unrevoked one
 *   test_htlc_claim_replay_watched        HTLC replay on reconnect
 *   test_htlc_claim_behind_sender_recovers  one behind: rolled back, recovers
 *   test_htlc_claim_spoofed_reconnect_restored  impostor one behind: undone
 *   test_htlc_claim_spoofed_reconnect_keeps_channel  impostor: nothing failed
 *   test_htlc_claim_failed_reconnect_other_cn_told  failed: only its cn resumes
 *   test_htlc_claim_late_revocation_keeps_claims  no snapshot: claims kept
 *   test_htlc_claim_secure_watches_commitment  securing watches the rest
 *   test_htlc_claim_pong_before_raa_keeps_sender  PONG before the revocation
 *   test_htlc_claim_strays_before_raa  strays in every revocation wait
 *   test_htlc_claim_failed_no_lsp_revocation  none on a failed channel
 *   test_htlc_claim_failed_mark_without_row  failed mark without a row
 *   test_htlc_claim_unarmed_preimage_kept preimage kept when no claim arms
 *   test_htlc_claim_failed_rotation_ready failed channel, rotation goes on
 *   test_htlc_claim_bridge_result_during_payee_wait   pay result queued
 *   test_htlc_claim_bridge_result_during_sender_wait  same, sender wait
 *   test_htlc_claim_lsp_sibling_reorg     LSP claim survives a reorg
 * Regtest drills (bitcoind):
 *   test_regtest_htlc_claim_lsp_payee          sender = client
 *   test_regtest_htlc_claim_lsp_payee_restart  same, payee restarts
 *   test_regtest_htlc_claim_client_payee       sender = LSP
 */

#include "superscalar/regtest.h"   /* before chain_backend.h: regtest init */
#include "superscalar/channel.h"
#include "superscalar/sweeper.h"
#include "superscalar/persist.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/lsp_channels_internal.h"
#include "superscalar/client.h"
#include "superscalar/chain_backend.h"
#include "superscalar/musig.h"
#include "superscalar/tapscript.h"
#include "superscalar/tx_builder.h"
#include "superscalar/sha256.h"
#include "superscalar/readiness.h"
#include <secp256k1_schnorrsig.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>

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

/* ------------------------------------------------------------------ */
/* Mock chain backend                                                   */
/* ------------------------------------------------------------------ */

#define MOCK_MAX 16
typedef struct {
    chain_backend_t base;
    int height;
    char txid[MOCK_MAX][65];
    int conf_height[MOCK_MAX];    /* 0 = mempool, >0 = block height */
    size_t n;
    int unspent;                  /* 0: every outpoint reads as spent */
    /* Outpoints spent by a known transaction (prevout -> spender). */
    char spent_prev[MOCK_MAX][65];
    uint32_t spent_vout[MOCK_MAX];
    char spent_by[MOCK_MAX][65];
    size_t n_spent;
    size_t n_misses;              /* get_confirmations of unknown txids */
    size_t n_sent;
    unsigned char last_sent[1024];
    size_t last_sent_len;
    size_t n_registered;          /* register_script calls */
    unsigned char registered[MOCK_MAX][34];
} mock_chain_t;

static int mk_idx(mock_chain_t *m, const char *txid)
{
    for (size_t i = 0; i < m->n; i++)
        if (strcmp(m->txid[i], txid) == 0) return (int)i;
    return -1;
}

static int mk_height(chain_backend_t *b) { return ((mock_chain_t *)b)->height; }

static int mk_confs(chain_backend_t *b, const char *txid)
{
    mock_chain_t *m = (mock_chain_t *)b;
    int i = mk_idx(m, txid);
    if (i < 0) { m->n_misses++; return -1; }
    if (m->conf_height[i] == 0) return 0;
    return m->height - m->conf_height[i] + 1;
}

static bool mk_mempool(chain_backend_t *b, const char *txid)
{
    mock_chain_t *m = (mock_chain_t *)b;
    int i = mk_idx(m, txid);
    return i >= 0 && m->conf_height[i] == 0;
}

/* gettxout with the mempool: the output exists (its tx is known) and no
   known transaction spends it. */
static int mk_unspent(chain_backend_t *b, const char *txid, uint32_t vout)
{
    mock_chain_t *m = (mock_chain_t *)b;
    if (!m->unspent || mk_idx(m, txid) < 0) return 0;
    for (size_t i = 0; i < m->n_spent; i++)
        if (strcmp(m->spent_prev[i], txid) == 0 && m->spent_vout[i] == vout &&
            mk_idx(m, m->spent_by[i]) >= 0)
            return 0;
    return 1;
}

static void mk_put(mock_chain_t *m, const char *txid, int conf_height)
{
    int i = mk_idx(m, txid);
    if (i < 0) {
        if (m->n >= MOCK_MAX) return;
        i = (int)m->n++;
        memcpy(m->txid[i], txid, 65);
    }
    m->conf_height[i] = conf_height;
}

/* Forget a transaction (evicted from the mempool, or reorged out). */
static void mk_forget(mock_chain_t *m, const char *txid)
{
    int i = mk_idx(m, txid);
    if (i < 0) return;
    m->n--;
    memcpy(m->txid[i], m->txid[m->n], 65);
    m->conf_height[i] = m->conf_height[m->n];
}

/* Record that spender spends prev:vout (spender itself is put with
   conf_height). */
static void mk_spend(mock_chain_t *m, const char *prev, uint32_t vout,
                     const char *spender, int conf_height)
{
    if (m->n_spent >= MOCK_MAX) return;
    memcpy(m->spent_prev[m->n_spent], prev, 65);
    m->spent_vout[m->n_spent] = vout;
    memcpy(m->spent_by[m->n_spent], spender, 65);
    m->n_spent++;
    mk_put(m, spender, conf_height);
}

static int mk_send(chain_backend_t *b, const char *hex, char *txid_out)
{
    mock_chain_t *m = (mock_chain_t *)b;
    size_t len = strlen(hex) / 2;
    if (len > sizeof(m->last_sent)) return 0;
    hex_decode(hex, m->last_sent, len);
    m->last_sent_len = len;
    ptx_t t;
    if (!ptx_parse(m->last_sent, len, &t)) return 0;
    char txid[65], prev[65];
    hex_encode(t.txid_display, 32, txid);
    unsigned char pd[32];
    memcpy(pd, t.prev_txid, 32);
    reverse_bytes(pd, 32);
    hex_encode(pd, 32, prev);
    mk_spend(m, prev, t.prev_vout, txid, 0);
    if (txid_out) memcpy(txid_out, txid, 65);
    m->n_sent++;
    return 1;
}

static int mk_register(chain_backend_t *b, const unsigned char *spk,
                       size_t len)
{
    mock_chain_t *m = (mock_chain_t *)b;
    if (len == 34 && m->n_registered < MOCK_MAX)
        memcpy(m->registered[m->n_registered], spk, 34);
    m->n_registered++;
    return 1;
}

static void mock_init(mock_chain_t *m, int height)
{
    memset(m, 0, sizeof(*m));
    m->base.get_block_height = mk_height;
    m->base.get_confirmations = mk_confs;
    m->base.is_in_mempool = mk_mempool;
    m->base.is_outpoint_unspent = mk_unspent;
    m->base.send_raw_tx = mk_send;
    m->base.is_regtest = 1;
    conf_targets_default(&m->base.conf);
    m->height = height;
    m->unspent = 1;
}

static void txid_internal_to_hex(const unsigned char *txid32, char *hex65)
{
    unsigned char d[32];
    memcpy(d, txid32, 32);
    reverse_bytes(d, 32);
    hex_encode(d, 32, hex65);
}

static channel_t *g_lookup_ch;
static channel_t *lookup_one(void *arg, uint32_t id)
{
    (void)arg; (void)id;
    return g_lookup_ch;
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

    /* Registration refuses what it cannot claim. */
    sweeper_t sw;
    mock_chain_t m;
    mock_init(&m, 100);
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, NULL, NULL),
                "sweeper");
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, bad) < 0,
                "registration with wrong preimage refused");
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.cli, 0, 0,
                    HTLC_CLAIM_LOCAL_COMMIT, p.cli_htlc_id, p.preimage) < 0,
                "registration for an HTLC we offered refused");
    TEST_ASSERT(sw.n_entries == 0, "nothing registered");
    sweeper_cleanup(&sw);

    tx_buf_free(&x); tx_buf_free(&lcl); tx_buf_free(&lc);
    tx_buf_free(&claim); tx_buf_free(&cli_c);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}

static int count_rows(persist_t *db, const char *type)
{
    sqlite3_stmt *st;
    int n = -1;
    if (sqlite3_prepare_v2(db->db,
            "SELECT COUNT(*) FROM pending_sweeps WHERE sweep_type = ?;",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, type, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

/* The claim survives a restart: register, drop the HTLC from channel state
   (as channel_fulfill_htlc does), reload from the DB, then claim. */
int test_htlc_claim_persist_reload(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    char path[] = "/tmp/ss_htlc_claim_XXXXXX";
    int fd = mkstemp(path);
    TEST_ASSERT(fd >= 0, "temp db");
    close(fd);              /* empty 0600 file: opened as a new DB */

    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init");
    TEST_ASSERT(pair_add_htlc(&p, 1, 7000, 150), "add htlc");
    g_lookup_ch = &p.lsp;

    persist_t db;
    TEST_ASSERT(persist_open(&db, path), "open db");
    mock_chain_t m;
    mock_init(&m, 100);
    sweeper_t sw;
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, &db, NULL),
                "sweeper init");
    sweeper_set_channel_lookup(&sw, lookup_one, NULL);
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1,
                "register");
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1 &&
                sw.n_entries == 1, "re-register is idempotent");
    sweep_entry_t before = sw.entries[0];
    TEST_ASSERT(count_rows(&db, "htlc_success") == 1, "one row persisted");

    unsigned char cli_txid[32];
    tx_buf_t cc;
    tx_buf_init(&cc, 1024);
    channel_build_commitment_tx(&p.cli, &cc, cli_txid);
    tx_buf_free(&cc);
    TEST_ASSERT(memcmp(before.source_txid, cli_txid, 32) == 0,
                "source is the client's commitment");

    /* Preimage revealed: the HTLC leaves channel state. */
    TEST_ASSERT(channel_fulfill_htlc(&p.lsp, p.lsp_htlc_id, p.preimage),
                "fulfill");
    TEST_ASSERT(p.lsp.n_htlcs == 0, "HTLC compacted away");

    /* Restart. */
    sweeper_cleanup(&sw);
    persist_close(&db);
    TEST_ASSERT(persist_open(&db, path), "reopen db");
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, &db, NULL),
                "sweeper reload");
    sweeper_set_channel_lookup(&sw, lookup_one, NULL);
    TEST_ASSERT(sw.n_entries == 1, "claim reloaded");
    sweep_entry_t *e = &sw.entries[0];
    TEST_ASSERT(e->type == SWEEP_HTLC_SUCCESS, "type");
    TEST_ASSERT(e->claim_side == HTLC_CLAIM_REMOTE_COMMIT, "side");
    TEST_ASSERT(memcmp(e->preimage, p.preimage, 32) == 0, "preimage");
    TEST_ASSERT(memcmp(e->payment_hash, p.hash, 32) == 0, "hash");
    TEST_ASSERT(memcmp(e->htlc_spk, before.htlc_spk, 34) == 0, "spk");
    TEST_ASSERT(memcmp(e->commit_point, before.commit_point, 33) == 0, "pcp");
    TEST_ASSERT(memcmp(e->source_txid, cli_txid, 32) == 0, "source txid");
    TEST_ASSERT(e->source_vout == before.source_vout &&
                e->amount_sats == 7000 && e->cltv_expiry == 150 &&
                e->csv_delay == 0, "vout/amount/cltv/csv");

    /* Commitment confirms: claim from the reloaded entry alone. */
    char ct_hex[65];
    txid_internal_to_hex(cli_txid, ct_hex);
    mk_put(&m, ct_hex, 100);
    TEST_ASSERT(sweeper_check(&sw) == 1 && m.n_sent == 1, "claim broadcast");

    secp256k1_pubkey pcp;
    secp256k1_ec_pubkey_parse(ctx, &pcp, before.commit_point, 33);
    tx_buf_t ref;
    tx_buf_init(&ref, 512);
    TEST_ASSERT(channel_build_htlc_claim_tx(&p.lsp, &ref,
                    HTLC_CLAIM_REMOTE_COMMIT, &pcp, cli_txid,
                    before.source_vout, 7000, before.htlc_spk, p.hash,
                    p.preimage, 150, 0, NULL, NULL), "reference claim");
    TEST_ASSERT(ref.len == m.last_sent_len &&
                memcmp(ref.data, m.last_sent, ref.len) == 0,
                "broadcast = claim built from reloaded entry");
    tx_buf_free(&ref);
    char claim_txid[65];
    memcpy(claim_txid, sw.entries[0].sweep_txid, 65);
    TEST_ASSERT(sw.entries[0].state == SWEEP_BROADCAST && claim_txid[0],
                "tracked as broadcast");

    /* Restart again while the claim is in flight: same row, same txid, and
       no second broadcast of a tx the chain already knows. */
    sweeper_cleanup(&sw);
    persist_close(&db);
    TEST_ASSERT(persist_open(&db, path), "reopen db 2");
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, &db, NULL),
                "sweeper reload 2");
    sweeper_set_channel_lookup(&sw, lookup_one, NULL);
    TEST_ASSERT(count_rows(&db, "htlc_success") == 1, "state updated in place");
    TEST_ASSERT(sw.n_entries == 1 && sw.entries[0].state == SWEEP_BROADCAST &&
                strcmp(sw.entries[0].sweep_txid, claim_txid) == 0,
                "broadcast state survives restart");
    sweeper_check(&sw);
    TEST_ASSERT(m.n_sent == 1, "no resend while in mempool");

    /* Evicted from the mempool: rebuilt and rebroadcast (same txid). */
    mk_forget(&m, claim_txid);
    sweeper_check(&sw);
    TEST_ASSERT(m.n_sent == 2 && sw.entries[0].state == SWEEP_BROADCAST &&
                strcmp(sw.entries[0].sweep_txid, claim_txid) == 0,
                "rebroadcast after eviction");

    /* Buried: entry and row go; with a destination, the output is swept. */
    memset(sw.dest_spk, 0, 34);
    sw.dest_spk[0] = 0x51; sw.dest_spk[1] = 0x20; sw.dest_spk[2] = 0x77;
    sw.dest_spk_len = 34;
    m.height = 101;
    mk_put(&m, claim_txid, 101);
    sweeper_check(&sw);
    TEST_ASSERT(count_rows(&db, "htlc_success") == 0, "claim row removed");
    TEST_ASSERT(sw.n_entries == 1 &&
                sw.entries[0].type == SWEEP_HTLC_SUCCESS_OUTPUT,
                "claim output registered");
    TEST_ASSERT(m.n_sent == 3, "claim output swept");
    ptx_t st;
    TEST_ASSERT(ptx_parse(m.last_sent, m.last_sent_len, &st), "parse sweep");
    char prev_hex[65];
    txid_internal_to_hex(st.prev_txid, prev_hex);
    TEST_ASSERT(strcmp(prev_hex, claim_txid) == 0 && st.prev_vout == 0,
                "sweep spends the claim output");
    TEST_ASSERT(memcmp(st.out_spk[0], sw.dest_spk, 34) == 0, "to destination");

    sweeper_cleanup(&sw);
    persist_close(&db);
    unlink(path);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Upgrade from v39: a pre-existing pending_sweeps row survives, the claim
   columns appear, and re-running the claim-column step is harmless. */
int test_htlc_claim_schema_upgrade(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    char path[] = "/tmp/ss_htlc_upgrade_XXXXXX";
    int fd = mkstemp(path);
    TEST_ASSERT(fd >= 0, "temp db");
    close(fd);

    sqlite3 *raw = NULL;
    TEST_ASSERT(sqlite3_open(path, &raw) == SQLITE_OK, "raw open");
    TEST_ASSERT(sqlite3_exec(raw,
        "CREATE TABLE schema_version (version INTEGER NOT NULL,"
        "  applied_at INTEGER DEFAULT (strftime('%s','now')));"
        "INSERT INTO schema_version (version) VALUES (39);"
        "CREATE TABLE pending_sweeps ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT, sweep_type TEXT NOT NULL,"
        "  state INTEGER NOT NULL DEFAULT 0, source_txid TEXT NOT NULL,"
        "  source_vout INTEGER NOT NULL, amount_sats INTEGER NOT NULL,"
        "  csv_delay INTEGER NOT NULL DEFAULT 0,"
        "  confirmed_height INTEGER NOT NULL DEFAULT 0,"
        "  channel_id INTEGER NOT NULL, factory_id INTEGER NOT NULL,"
        "  commitment_number INTEGER NOT NULL DEFAULT 0,"
        "  sweep_txid TEXT DEFAULT '',"
        "  created_at INTEGER DEFAULT (strftime('%s','now')));"
        "INSERT INTO pending_sweeps (sweep_type, state, source_txid, "
        "  source_vout, amount_sats, csv_delay, channel_id, factory_id) "
        "VALUES ('to_local', 0, "
        "  'abababababababababababababababababababababababababababababababab',"
        "  0, 50000, 144, 2, 1);",
        NULL, NULL, NULL) == SQLITE_OK, "build a v39 DB");
    sqlite3_close(raw);

    persist_t db;
    TEST_ASSERT(persist_open(&db, path), "open migrates v39 -> current");
    TEST_ASSERT(persist_schema_version(&db) == PERSIST_SCHEMA_VERSION, "version");

    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init");
    TEST_ASSERT(pair_add_htlc(&p, 1, 7000, 150), "add htlc");
    mock_chain_t m;
    mock_init(&m, 100);
    sweeper_t sw;
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, &db, NULL),
                "sweeper");
    TEST_ASSERT(sw.n_entries == 1 && sw.entries[0].type == SWEEP_TO_LOCAL &&
                sw.entries[0].amount_sats == 50000 &&
                sw.entries[0].csv_delay == 144, "old row kept");
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1,
                "claim stored in the upgraded table");
    sweeper_cleanup(&sw);
    persist_close(&db);

    /* Re-run the claim-column step on the populated table. */
    TEST_ASSERT(sqlite3_open(path, &raw) == SQLITE_OK, "raw reopen");
    TEST_ASSERT(sqlite3_exec(raw, "DELETE FROM schema_version;"
                "INSERT INTO schema_version (version) VALUES (39);",
                NULL, NULL, NULL) == SQLITE_OK, "back to v39");
    sqlite3_close(raw);
    TEST_ASSERT(persist_open(&db, path), "re-migrate");
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, &db, NULL),
                "sweeper reload");
    int found = 0;
    for (size_t i = 0; i < sw.n_entries; i++)
        if (sw.entries[i].type == SWEEP_HTLC_SUCCESS &&
            memcmp(sw.entries[i].preimage, p.preimage, 32) == 0)
            found = 1;
    TEST_ASSERT(sw.n_entries == 2 && found, "both rows intact after re-run");

    sweeper_cleanup(&sw);
    persist_close(&db);
    unlink(path);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Give the LSP view the client's per-commitment point for cn, as a
   revoke_and_ack would. */
static int pair_send_pcp(pair_t *p, uint64_t cn)
{
    secp256k1_pubkey pt;
    if (!channel_get_per_commitment_point(&p->cli, cn, &pt)) return 0;
    channel_set_remote_pcp(&p->lsp, cn, &pt);
    return 1;
}

/* The client's commitment (txid, display hex) in its current state. */
static int pair_cli_commit(pair_t *p, unsigned char *txid32, char *hex65)
{
    tx_buf_t c;
    tx_buf_init(&c, 1024);
    int ok = channel_build_commitment_tx(&p->cli, &c, txid32);
    tx_buf_free(&c);
    if (ok && hex65) txid_internal_to_hex(txid32, hex65);
    return ok;
}

/* A valid revocation of a LATER commitment leaves the claim on an earlier
   commitment the client never revoked. */
int test_htlc_claim_newer_revocation_keeps_claim(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init");
    TEST_ASSERT(pair_add_htlc(&p, 1, 7000, 600), "client pays A");
    g_lookup_ch = &p.lsp;
    mock_chain_t m;
    mock_init(&m, 100);
    sweeper_t sw;
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, NULL, NULL),
                "sweeper");
    sweeper_set_channel_lookup(&sw, lookup_one, NULL);

    uint64_t n = p.lsp.commitment_number;
    unsigned char txn[32];
    char txn_hex[65];
    TEST_ASSERT(pair_cli_commit(&p, txn, txn_hex), "client commitment N");
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1,
                "claim armed on N");

    /* Commitment N+1 (a second HTLC), validly revoked; N never is. */
    unsigned char h2[32];
    memset(h2, 0x77, 32);
    uint64_t i1, i2;
    TEST_ASSERT(channel_add_htlc(&p.lsp, HTLC_RECEIVED, 6000, h2, 600, &i1) &&
                channel_add_htlc(&p.cli, HTLC_OFFERED, 6000, h2, 600, &i2),
                "second HTLC: N+1");
    TEST_ASSERT(pair_send_pcp(&p, n + 1) && pair_send_pcp(&p, n + 2),
                "points N+1, N+2");
    unsigned char secret[32];
    TEST_ASSERT(channel_get_per_commitment_secret(&p.cli, n + 1, secret) &&
                channel_receive_revocation(&p.lsp, n + 1, secret),
                "valid revocation of N+1");
    TEST_ASSERT(sweeper_cancel_htlc_success(&sw, 0, n + 1) == 0,
                "revoking N+1 cancels nothing on N");
    TEST_ASSERT(!channel_get_received_revocation(&p.lsp, n, secret),
                "N was never revoked");
    sweeper_check(&sw);
    TEST_ASSERT(sw.n_entries == 1, "claim on N kept by the check cycle");
    mk_put(&m, txn_hex, 100);
    sweeper_check(&sw);
    TEST_ASSERT(m.n_sent == 1, "claim sent when N confirms");

    sweeper_cleanup(&sw);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Two HTLCs with the same payment hash and CLTV have the same script; each
   output gets its own claim. */
int test_htlc_claim_same_hash_two_outputs(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init");
    uint64_t a1, a2, c1, c2;
    TEST_ASSERT(channel_add_htlc(&p.lsp, HTLC_RECEIVED, 7000, p.hash, 600, &a1) &&
                channel_add_htlc(&p.cli, HTLC_OFFERED, 7000, p.hash, 600, &c1),
                "first part");
    TEST_ASSERT(channel_add_htlc(&p.lsp, HTLC_RECEIVED, 9000, p.hash, 600, &a2) &&
                channel_add_htlc(&p.cli, HTLC_OFFERED, 9000, p.hash, 600, &c2),
                "second part, same hash and CLTV");
    TEST_ASSERT(pair_send_pcp(&p, 2), "point 2");
    g_lookup_ch = &p.lsp;
    mock_chain_t m;
    mock_init(&m, 100);
    sweeper_t sw;
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, NULL, NULL),
                "sweeper");
    sweeper_set_channel_lookup(&sw, lookup_one, NULL);
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, a1, p.preimage) == 1 &&
                sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, a2, p.preimage) == 1,
                "both armed");
    TEST_ASSERT(sw.n_entries == 2, "two claims");
    TEST_ASSERT(sw.entries[0].source_vout == 2 && sw.entries[0].amount_sats == 7000 &&
                sw.entries[1].source_vout == 3 && sw.entries[1].amount_sats == 9000,
                "each claim on its own output");
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, a2, p.preimage) == 1 &&
                sw.n_entries == 2, "re-registering is idempotent");

    unsigned char ct[32];
    char ct_hex[65];
    TEST_ASSERT(pair_cli_commit(&p, ct, ct_hex), "client commitment");
    TEST_ASSERT(memcmp(sw.entries[0].source_txid, ct, 32) == 0, "source");
    mk_put(&m, ct_hex, 100);
    sweeper_check(&sw);
    TEST_ASSERT(m.n_sent == 2, "both outputs claimed");

    sweeper_cleanup(&sw);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* An HTLC above the commitment dust limit whose claim output would be
   dust is not armed (nothing would ever be broadcast for it). */
int test_htlc_claim_dust_not_armed(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init");
    TEST_ASSERT(pair_add_htlc(&p, 1, 650, 150), "650-sat HTLC");
    g_lookup_ch = &p.lsp;
    mock_chain_t m;
    mock_init(&m, 100);
    sweeper_t sw;
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, NULL, NULL),
                "sweeper");
    sweeper_set_channel_lookup(&sw, lookup_one, NULL);
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 0,
                "not claimable: not armed");
    TEST_ASSERT(sw.n_entries == 0, "no entry");

    /* The fee estimator raises the claim fee: a 1500-sat HTLC is claimable
       at the channel rate but not at 6000 sat/kvB. */
    TEST_ASSERT(pair_add_htlc(&p, 1, 1500, 150), "1500-sat HTLC");
    TEST_ASSERT(pair_send_pcp(&p, 2), "point 2");
    fee_estimator_static_t fe;
    fee_estimator_static_init(&fe, 6000);
    sweeper_t sf;
    TEST_ASSERT(sweeper_init(&sf, ctx, NULL, NULL, 0, &m.base, NULL,
                             &fe.base), "sweeper with estimator");
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1,
                "armed at the channel rate");
    TEST_ASSERT(sw.entries[0].claim_amount ==
                1500 - channel_htlc_claim_fee(&p.lsp), "channel fee");
    TEST_ASSERT(sweeper_add_htlc_success(&sf, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 0 &&
                sf.n_entries == 0, "not armed at the estimator's rate");
    fee_estimator_static_init(&fe, 3000);
    TEST_ASSERT(sweeper_add_htlc_success(&sf, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1 &&
                sf.entries[0].claim_amount == 1500 - fee_for_htlc_tx(&fe.base),
                "estimator fee used when higher");

    sweeper_cleanup(&sf);
    sweeper_cleanup(&sw);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A pending claim whose commitment never reaches the chain costs no
   search for that commitment (an outpoint lookup answers), and a claim on
   a commitment that lost to another commitment of the channel is dropped. */
int test_htlc_claim_pending_lookup_and_prune(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init");
    TEST_ASSERT(pair_add_htlc(&p, 1, 7000, 600), "client pays A");
    g_lookup_ch = &p.lsp;
    mock_chain_t m;
    mock_init(&m, 100);
    sweeper_t sw;
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, NULL, NULL),
                "sweeper");
    sweeper_set_channel_lookup(&sw, lookup_one, NULL);
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1,
                "claim on N");
    for (int k = 0; k < 5; k++) {
        m.height++;
        sweeper_check(&sw);
    }
    TEST_ASSERT(sw.n_entries == 1 && m.n_sent == 0, "still pending");
    TEST_ASSERT(m.n_misses == 0, "no lookup of a commitment not on chain");

    /* The client moves to N+1 (a second HTLC) without revoking N; A is on
       both, and claimed on both. */
    unsigned char h2[32];
    memset(h2, 0x66, 32);
    uint64_t b1, b2;
    TEST_ASSERT(channel_add_htlc(&p.lsp, HTLC_RECEIVED, 5000, h2, 600, &b1) &&
                channel_add_htlc(&p.cli, HTLC_OFFERED, 5000, h2, 600, &b2),
                "N+1");
    TEST_ASSERT(pair_send_pcp(&p, 2), "point N+1");
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1 &&
                sw.n_entries == 2, "claim on N+1 as well");
    unsigned char t1[32];
    char t1_hex[65];
    TEST_ASSERT(pair_cli_commit(&p, t1, t1_hex), "client commitment N+1");
    mk_put(&m, t1_hex, m.height);
    sweeper_check(&sw);
    TEST_ASSERT(m.n_sent == 1, "claimed from N+1");
    uint32_t depth = sweeper_final_depth(&sw);
    TEST_ASSERT(depth == 6, "final depth 6, on regtest too");
    for (uint32_t d = 1; d < depth; d++) {
        sweeper_check(&sw);
        TEST_ASSERT(sw.n_entries == 2,
                    "claim on N kept while N+1 is not final (reorg)");
        m.height++;
    }
    sweeper_check(&sw);
    TEST_ASSERT(sw.n_entries == 1 &&
                memcmp(sw.entries[0].source_txid, t1, 32) == 0,
                "claim on N dropped once N+1 is final");
    TEST_ASSERT(m.n_misses <= 1,
                "an absent commitment is looked up at most every 6 blocks");

    sweeper_cleanup(&sw);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A commitment superseded by another of the same channel keeps its claim
   until that other one is buried final, as seen on the chain then: a
   one-block reorg that swaps them still finds the claim. */
int test_htlc_claim_superseded_reorg(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init");
    TEST_ASSERT(pair_add_htlc(&p, 1, 7000, 600), "A on N");
    g_lookup_ch = &p.lsp;
    unsigned char c1[32], c2[32];
    char c1_hex[65], c2_hex[65];
    TEST_ASSERT(pair_cli_commit(&p, c1, c1_hex), "commitment N");
    mock_chain_t m;
    mock_init(&m, 100);
    sweeper_t sw;
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, NULL, NULL),
                "sweeper");
    sweeper_set_channel_lookup(&sw, lookup_one, NULL);
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1,
                "A armed on N");
    unsigned char hb[32];
    memset(hb, 0x4B, 32);
    uint64_t i1, i2;
    TEST_ASSERT(channel_add_htlc(&p.lsp, HTLC_RECEIVED, 5000, hb, 600, &i1) &&
                channel_add_htlc(&p.cli, HTLC_OFFERED, 5000, hb, 600, &i2) &&
                pair_send_pcp(&p, 2), "N+1 (A and B), never revoking N");
    TEST_ASSERT(pair_cli_commit(&p, c2, c2_hex), "commitment N+1");
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1 &&
                sw.n_entries == 2, "A armed on N+1 too");

    mk_put(&m, c2_hex, 100);                 /* N+1 mined */
    sweeper_check(&sw);
    sweeper_check(&sw);
    int on_c1 = 0;
    for (size_t i = 0; i < sw.n_entries; i++)
        if (memcmp(sw.entries[i].source_txid, c1, 32) == 0) on_c1 = 1;
    TEST_ASSERT(on_c1, "claim on N kept at one confirmation of N+1");

    /* A one-block reorg mines N instead. */
    mk_forget(&m, c2_hex);
    m.n_spent = 0;
    mk_put(&m, c1_hex, 100);
    size_t before = m.n_sent;
    sweeper_check(&sw);
    sweeper_check(&sw);
    on_c1 = 0;
    for (size_t i = 0; i < sw.n_entries; i++)
        if (memcmp(sw.entries[i].source_txid, c1, 32) == 0 &&
            sw.entries[i].state == SWEEP_BROADCAST) on_c1 = 1;
    TEST_ASSERT(on_c1 && m.n_sent > before, "A claimed on N after the reorg");

    /* A record of N+1 confirmed long ago that the chain no longer has does
       not supersede N either. */
    sweeper_t sx;
    mock_chain_t mx;
    mock_init(&mx, 100);
    TEST_ASSERT(sweeper_init(&sx, ctx, NULL, NULL, 0, &mx.base, NULL, NULL),
                "sweeper x");
    sweeper_set_channel_lookup(&sx, lookup_one, NULL);
    TEST_ASSERT(sweeper_add_htlc_success(&sx, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1,
                "claim on N+1");
    sx.entries[0].confirmed_height = 50;     /* stale: reorged out */
    sweep_entry_t on_n;
    memset(&on_n, 0, sizeof(on_n));
    int found = 0;
    for (size_t i = 0; i < sw.n_entries; i++)
        if (memcmp(sw.entries[i].source_txid, c1, 32) == 0) {
            on_n = sw.entries[i];
            found = 1;
        }
    TEST_ASSERT(found, "claim on N");
    on_n.id = 0;
    on_n.state = SWEEP_PENDING;
    on_n.confirmed_height = 0;
    on_n.sweep_txid[0] = '\0';
    TEST_ASSERT(sx.n_entries < sx.entries_cap, "room");
    sx.entries[sx.n_entries++] = on_n;
    mx.height = 200;
    sweeper_check(&sx);
    int kept = 0;
    for (size_t i = 0; i < sx.n_entries; i++)
        if (memcmp(sx.entries[i].source_txid, c1, 32) == 0) kept = 1;
    TEST_ASSERT(kept, "not superseded by a commitment the chain does not have");
    sweeper_cleanup(&sx);

    sweeper_cleanup(&sw);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* An armed claim whose HTLC output is already spent when first looked at
   (the outpoint lookup reads it like an absent commitment) still finds
   its commitment, and goes once the output is lost past the CLTV,
   instead of waiting forever. */
int test_htlc_claim_spent_output_seen(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init");
    TEST_ASSERT(pair_add_htlc(&p, 1, 7000, 600), "A on N");
    g_lookup_ch = &p.lsp;
    unsigned char ct[32];
    char ct_hex[65];
    TEST_ASSERT(pair_cli_commit(&p, ct, ct_hex), "commitment N");
    mock_chain_t m;
    mock_init(&m, 700);
    sweeper_t sw;
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, NULL, NULL),
                "sweeper");
    sweeper_set_channel_lookup(&sw, lookup_one, NULL);
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1,
                "armed");
    char spender[65];
    memset(spender, 'e', 64);
    spender[64] = '\0';
    mk_put(&m, ct_hex, 650);
    mk_spend(&m, ct_hex, sw.entries[0].source_vout, spender, 690);
    sweeper_check(&sw);
    TEST_ASSERT(sw.n_entries == 1 && sw.entries[0].confirmed_height == 0,
                "output spent: looks absent at first");
    m.height += SWEEPER_REBROADCAST_BLOCKS;
    sweeper_check(&sw);
    TEST_ASSERT(sw.n_entries == 0 && m.n_sent == 0,
                "commitment found, output lost past the CLTV: dropped");
    TEST_ASSERT(sweeper_pending_claims(&sw) == 0, "nothing left to wait for");
    sweeper_cleanup(&sw);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Armed claims on commitments that never reach the chain expire: on our
   own commitment past CLTV plus the grace, on the counterparty's past
   CLTV plus SWEEPER_REMOTE_CLAIM_HORIZON. */
int test_htlc_claim_armed_expiry(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init");
    TEST_ASSERT(pair_add_htlc(&p, 0, 20000, 150), "LSP pays the client");
    mock_chain_t m;
    mock_init(&m, 100);
    sweeper_t sw;
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, NULL, NULL),
                "sweeper");
    g_lookup_ch = &p.cli;
    sweeper_set_channel_lookup(&sw, lookup_one, NULL);
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.cli, 0, 0,
                    HTLC_CLAIM_LOCAL_COMMIT, p.cli_htlc_id, p.preimage) == 1,
                "client claim on its own commitment");
    m.height = 155;
    sweeper_check(&sw);
    TEST_ASSERT(sw.n_entries == 1, "kept until CLTV + grace");
    m.height = 156;
    sweeper_check(&sw);
    TEST_ASSERT(sw.n_entries == 0 && sweeper_pending_claims(&sw) == 0,
                "local claim never broadcast: expired");
    sweeper_cleanup(&sw);

    pair_t q;
    TEST_ASSERT(pair_init(&q, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init q");
    TEST_ASSERT(pair_add_htlc(&q, 1, 7000, 150), "client pays the LSP");
    mock_init(&m, 100);
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, NULL, NULL),
                "sweeper 2");
    g_lookup_ch = &q.lsp;
    sweeper_set_channel_lookup(&sw, lookup_one, NULL);
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &q.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, q.lsp_htlc_id, q.preimage) == 1,
                "LSP claim on the client's commitment");
    m.height = 156;
    sweeper_check(&sw);
    TEST_ASSERT(sw.n_entries == 1,
                "kept past the CLTV: the client's timeout waits its CSV");
    m.height = 150 + SWEEPER_REMOTE_CLAIM_HORIZON - 1;
    sweeper_check(&sw);
    TEST_ASSERT(sw.n_entries == 1, "kept within the horizon");
    m.height = 150 + SWEEPER_REMOTE_CLAIM_HORIZON;
    sweeper_check(&sw);
    TEST_ASSERT(sw.n_entries == 0, "expired past CLTV + horizon");
    sweeper_cleanup(&sw);
    pair_cleanup(&q);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A watch on a commitment of a channel whose armed claim already holds the
   HTLC's preimage is armed at once. */
int test_htlc_claim_watch_armed_from_known(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init");
    TEST_ASSERT(pair_add_htlc(&p, 1, 7000, 600), "A on N");
    mock_chain_t m;
    mock_init(&m, 100);
    sweeper_t sw;
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, NULL, NULL),
                "sweeper");
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1,
                "armed on N");
    unsigned char hb[32];
    memset(hb, 0x4B, 32);
    uint64_t i1, i2;
    TEST_ASSERT(channel_add_htlc(&p.lsp, HTLC_RECEIVED, 5000, hb, 600, &i1) &&
                channel_add_htlc(&p.cli, HTLC_OFFERED, 5000, hb, 600, &i2) &&
                pair_send_pcp(&p, 2), "N+1");
    TEST_ASSERT(sweeper_watch_htlc(&sw, &p.lsp, 0, 0, p.lsp_htlc_id) == 1 &&
                sweeper_watch_htlc(&sw, &p.lsp, 0, 0, i1) == 1 &&
                sw.n_entries == 3, "A and B watched on N+1");
    TEST_ASSERT(sweeper_pending_claims(&sw) == 2, "A armed there at once, B not");
    sweeper_cleanup(&sw);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Watching an HTLC before its preimage is known: no chain lookups, kept
   across a restart, armed by the preimage, dropped after the CLTV. */
int test_htlc_claim_watch_then_arm(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    char path[] = "/tmp/ss_htlc_watch_XXXXXX";
    int fd = mkstemp(path);
    TEST_ASSERT(fd >= 0, "temp db");
    close(fd);
    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init");
    TEST_ASSERT(pair_add_htlc(&p, 1, 7000, 150), "add");
    g_lookup_ch = &p.lsp;
    persist_t db;
    TEST_ASSERT(persist_open(&db, path), "db");
    mock_chain_t m;
    mock_init(&m, 100);
    sweeper_t sw;
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, &db, NULL),
                "sweeper");
    sweeper_set_channel_lookup(&sw, lookup_one, NULL);
    TEST_ASSERT(sweeper_watch_htlc(&sw, &p.lsp, 0, 0, p.lsp_htlc_id) == 1,
                "watched");
    TEST_ASSERT(sweeper_pending_claims(&sw) == 0, "not an armed claim");
    unsigned char ct[32];
    char ct_hex[65];
    TEST_ASSERT(pair_cli_commit(&p, ct, ct_hex), "commitment");
    mk_put(&m, ct_hex, 100);
    sweeper_check(&sw);
    TEST_ASSERT(m.n_sent == 0 && sw.entries[0].confirmed_height == 0,
                "nothing to send without the preimage");

    sweeper_cleanup(&sw);
    persist_close(&db);
    TEST_ASSERT(persist_open(&db, path), "reopen");
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, &db, NULL),
                "reload");
    sweeper_set_channel_lookup(&sw, lookup_one, NULL);
    TEST_ASSERT(sw.n_entries == 1 && sweeper_pending_claims(&sw) == 0,
                "watch reloaded, still unarmed");
    unsigned char other[32];
    memset(other, 0x01, 32);
    TEST_ASSERT(sweeper_supply_preimage(&sw, 0, other) == 0,
                "another preimage arms nothing");
    TEST_ASSERT(sweeper_supply_preimage(&sw, 1, p.preimage) == 0,
                "a watch on another channel is not armed");
    TEST_ASSERT(sweeper_supply_preimage(&sw, 0, p.preimage) == 1 &&
                sweeper_pending_claims(&sw) == 1, "armed");
    sweeper_cleanup(&sw);
    persist_close(&db);
    TEST_ASSERT(persist_open(&db, path), "reopen 2");
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, &db, NULL),
                "reload 2");
    sweeper_set_channel_lookup(&sw, lookup_one, NULL);
    TEST_ASSERT(sweeper_pending_claims(&sw) == 1 &&
                memcmp(sw.entries[0].preimage, p.preimage, 32) == 0,
                "armed state persisted");
    sweeper_check(&sw);
    TEST_ASSERT(m.n_sent == 1, "claimed");

    /* An unarmed watch goes once the HTLC has expired. */
    sweeper_t sx;
    mock_chain_t mx;
    mock_init(&mx, 100);
    TEST_ASSERT(sweeper_init(&sx, ctx, NULL, NULL, 0, &mx.base, NULL, NULL),
                "sweeper x");
    sweeper_set_channel_lookup(&sx, lookup_one, NULL);
    TEST_ASSERT(sweeper_watch_htlc(&sx, &p.lsp, 0, 0, p.lsp_htlc_id) == 1,
                "watched x");
    mx.height = 155;
    sweeper_check(&sx);
    TEST_ASSERT(sx.n_entries == 1, "kept until past the CLTV");
    mx.height = 156;
    sweeper_check(&sx);
    TEST_ASSERT(sx.n_entries == 0 && mx.n_misses == 0,
                "dropped after the CLTV, without lookups");
    sweeper_cleanup(&sx);

    sweeper_cleanup(&sw);
    persist_close(&db);
    unlink(path);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Registration fails closed: no claim that is not on disk. */
int test_htlc_claim_registration_fails_closed(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init");
    TEST_ASSERT(pair_add_htlc(&p, 1, 7000, 150), "add");
    g_lookup_ch = &p.lsp;
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "db");
    mock_chain_t m;
    mock_init(&m, 100);
    sweeper_t sw;
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, &db, NULL),
                "sweeper");
    sweeper_set_channel_lookup(&sw, lookup_one, NULL);

    /* Inside an open transaction the row would not be durable yet. */
    TEST_ASSERT(sqlite3_exec(db.db, "BEGIN;", NULL, NULL, NULL) == SQLITE_OK,
                "begin");
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == -1,
                "refused inside a transaction");
    TEST_ASSERT(sweeper_watch_htlc(&sw, &p.lsp, 0, 0, p.lsp_htlc_id) == -1,
                "watch refused too");
    TEST_ASSERT(sw.n_entries == 0, "nothing in memory");
    sqlite3_exec(db.db, "ROLLBACK;", NULL, NULL, NULL);

    /* Arming a watch inside a transaction: refused. */
    TEST_ASSERT(sweeper_watch_htlc(&sw, &p.lsp, 0, 0, p.lsp_htlc_id) == 1,
                "watched");
    sqlite3_exec(db.db, "BEGIN;", NULL, NULL, NULL);
    TEST_ASSERT(sweeper_supply_preimage(&sw, 0, p.preimage) == -1,
                "arming refused inside a transaction");
    sqlite3_exec(db.db, "ROLLBACK;", NULL, NULL, NULL);
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1 &&
                sw.n_entries == 1 && sweeper_pending_claims(&sw) == 1,
                "arming the same output later works");

    /* The row cannot be written: no claim. */
    TEST_ASSERT(sweeper_cancel_htlc_success(&sw, 0, p.lsp.commitment_number) == 1,
                "cleared");
    TEST_ASSERT(sqlite3_exec(db.db, "DROP TABLE pending_sweeps;", NULL, NULL,
                             NULL) == SQLITE_OK, "break the table");
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == -1,
                "refused when the row cannot be written");
    TEST_ASSERT(sw.n_entries == 0, "and nothing in memory");

    sweeper_cleanup(&sw);
    persist_close(&db);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A filter-based backend (no outpoint lookup, no mempool view): the claim
   output is watched so its confirmation can be seen, and while it is not
   seen it is resent every few blocks, not every cycle. */
int test_htlc_claim_filter_backend(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init");
    TEST_ASSERT(pair_add_htlc(&p, 1, 7000, 600), "add");
    g_lookup_ch = &p.lsp;
    mock_chain_t m;
    mock_init(&m, 100);
    m.base.is_outpoint_unspent = NULL;
    m.base.register_script = mk_register;
    sweeper_t sw;
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, NULL, NULL),
                "sweeper");
    sweeper_set_channel_lookup(&sw, lookup_one, NULL);
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1,
                "armed");
    TEST_ASSERT(m.n_registered == 1 &&
                memcmp(m.registered[0], sw.entries[0].htlc_spk, 34) == 0,
                "HTLC script watched");
    char ct_hex[65];
    txid_internal_to_hex(sw.entries[0].source_txid, ct_hex);
    mk_put(&m, ct_hex, 100);
    sweeper_check(&sw);
    TEST_ASSERT(m.n_sent == 1, "claimed");
    ptx_t t;
    TEST_ASSERT(ptx_parse(m.last_sent, m.last_sent_len, &t), "parse");
    TEST_ASSERT(m.n_registered == 2 &&
                memcmp(m.registered[1], t.out_spk[0], 34) == 0,
                "claim output watched");

    /* The backend does not see the claim until it is mined. */
    char claim_txid[65];
    memcpy(claim_txid, sw.entries[0].sweep_txid, 65);
    mk_forget(&m, claim_txid);
    for (int k = 0; k < SWEEPER_REBROADCAST_BLOCKS - 1; k++) {
        m.height++;
        sweeper_check(&sw);
    }
    TEST_ASSERT(m.n_sent == 1 && sw.entries[0].state == SWEEP_BROADCAST,
                "no resend every cycle");
    m.height++;
    sweeper_check(&sw);
    TEST_ASSERT(m.n_sent == 2 &&
                strcmp(sw.entries[0].sweep_txid, claim_txid) == 0,
                "resent after a few blocks, same tx");
    mk_put(&m, claim_txid, m.height);
    sweeper_check(&sw);
    TEST_ASSERT(sw.n_entries == 0, "seen confirmed through its output: done");

    sweeper_cleanup(&sw);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* With at-rest encryption on, the preimage is not stored in the clear. */
int test_htlc_claim_preimage_sealed(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    char path[] = "/tmp/ss_htlc_seal_XXXXXX";
    int fd = mkstemp(path);
    TEST_ASSERT(fd >= 0, "temp db");
    close(fd);
    unsigned char root[32];
    memset(root, 0x42, 32);
    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init");
    TEST_ASSERT(pair_add_htlc(&p, 1, 7000, 150), "add");
    g_lookup_ch = &p.lsp;
    persist_t db;
    TEST_ASSERT(persist_open(&db, path) &&
                persist_set_encryption_key(&db, root) &&
                persist_apply_encryption(&db), "encrypted db");
    mock_chain_t m;
    mock_init(&m, 100);
    sweeper_t sw;
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, &db, NULL),
                "sweeper");
    sweeper_set_channel_lookup(&sw, lookup_one, NULL);
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1,
                "armed");
    char pre_hex[65];
    hex_encode(p.preimage, 32, pre_hex);
    sqlite3_stmt *st;
    TEST_ASSERT(sqlite3_prepare_v2(db.db, "SELECT preimage FROM pending_sweeps;",
                                   -1, &st, NULL) == SQLITE_OK &&
                sqlite3_step(st) == SQLITE_ROW, "row");
    const char *stored = (const char *)sqlite3_column_text(st, 0);
    int clear = stored && strstr(stored, pre_hex) != NULL;
    int nonempty = stored && stored[0];
    sqlite3_finalize(st);
    TEST_ASSERT(nonempty && !clear, "preimage sealed at rest");
    sweeper_cleanup(&sw);
    persist_close(&db);

    TEST_ASSERT(persist_open(&db, path) &&
                persist_set_encryption_key(&db, root) &&
                persist_apply_encryption(&db), "reopen with the key");
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, &db, NULL) &&
                sw.n_entries == 1 &&
                memcmp(sw.entries[0].preimage, p.preimage, 32) == 0,
                "preimage opened on reload");
    sweeper_cleanup(&sw);
    persist_close(&db);
    unlink(path);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}


static int pending_sweeps_has(sqlite3 *db, const char *col)
{
    sqlite3_stmt *st;
    int have = 0;
    if (sqlite3_prepare_v2(db, "PRAGMA table_info(pending_sweeps);", -1, &st,
                           NULL) != SQLITE_OK)
        return 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *n = (const char *)sqlite3_column_text(st, 1);
        if (n && strcmp(n, col) == 0) have = 1;
    }
    sqlite3_finalize(st);
    return have;
}

static int db_version_of(const char *path)
{
    sqlite3 *raw = NULL;
    int v = -1;
    if (sqlite3_open(path, &raw) != SQLITE_OK) return -1;
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(raw, "SELECT MAX(version) FROM schema_version;",
                           -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
    sqlite3_close(raw);
    return v;
}

/* The claim columns are added whatever version the DB carries (another
   change may have used the next number for something else), and a step
   that cannot add them fails the open without recording the version. */
int test_htlc_claim_schema_columns_any_version(void)
{
    static const char *const v39_base =
        "CREATE TABLE schema_version (version INTEGER NOT NULL,"
        "  applied_at INTEGER DEFAULT (strftime('%s','now')));";
    static const char *const sweeps =
        "CREATE TABLE pending_sweeps ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT, sweep_type TEXT NOT NULL,"
        "  state INTEGER NOT NULL DEFAULT 0, source_txid TEXT NOT NULL,"
        "  source_vout INTEGER NOT NULL, amount_sats INTEGER NOT NULL,"
        "  csv_delay INTEGER NOT NULL DEFAULT 0,"
        "  confirmed_height INTEGER NOT NULL DEFAULT 0,"
        "  channel_id INTEGER NOT NULL, factory_id INTEGER NOT NULL,"
        "  commitment_number INTEGER NOT NULL DEFAULT 0,"
        "  sweep_txid TEXT DEFAULT '',"
        "  created_at INTEGER DEFAULT (strftime('%s','now')));";

    /* Stamped 44 by a build without these columns. */
    char path[] = "/tmp/ss_htlc_cols_XXXXXX";
    int fd = mkstemp(path);
    TEST_ASSERT(fd >= 0, "temp db");
    close(fd);
    sqlite3 *raw = NULL;
    TEST_ASSERT(sqlite3_open(path, &raw) == SQLITE_OK, "raw open");
    TEST_ASSERT(sqlite3_exec(raw, v39_base, NULL, NULL, NULL) == SQLITE_OK &&
                sqlite3_exec(raw, sweeps, NULL, NULL, NULL) == SQLITE_OK &&
                sqlite3_exec(raw, "INSERT INTO schema_version (version) "
                             "VALUES (44);", NULL, NULL, NULL) == SQLITE_OK,
                "a DB at 44 without the claim columns");
    sqlite3_close(raw);
    persist_t db;
    TEST_ASSERT(persist_open(&db, path), "open");
    TEST_ASSERT(pending_sweeps_has(db.db, "preimage") &&
                pending_sweeps_has(db.db, "claim_amount") &&
                pending_sweeps_has(db.db, "commit_point"),
                "claim columns added");
    TEST_ASSERT(persist_schema_version(&db) == PERSIST_SCHEMA_VERSION,
                "version current");
    persist_close(&db);
    TEST_ASSERT(persist_open(&db, path), "reopen is a no-op");
    persist_close(&db);
    unlink(path);

    /* The columns cannot be added: the open fails, the version stays. */
    char path2[] = "/tmp/ss_htlc_cols2_XXXXXX";
    fd = mkstemp(path2);
    TEST_ASSERT(fd >= 0, "temp db 2");
    close(fd);
    TEST_ASSERT(sqlite3_open(path2, &raw) == SQLITE_OK, "raw open 2");
    TEST_ASSERT(sqlite3_exec(raw, v39_base, NULL, NULL, NULL) == SQLITE_OK &&
                sqlite3_exec(raw, "CREATE VIEW pending_sweeps AS SELECT 1 "
                             "AS id;", NULL, NULL, NULL) == SQLITE_OK &&
                sqlite3_exec(raw, "INSERT INTO schema_version (version) "
                             "VALUES (39);", NULL, NULL, NULL) == SQLITE_OK,
                "a DB whose pending_sweeps cannot take a column");
    sqlite3_close(raw);
    TEST_ASSERT(!persist_open(&db, path2), "open fails");
    TEST_ASSERT(db_version_of(path2) == 39, "version not recorded");
    unlink(path2);
    return 1;
}

/* The commitment is revoked after its claim went out, and our penalty
   spends the HTLC output: the claim is dropped at once, not kept until
   the CLTV and reported as lost to the timeout path. */
int test_htlc_claim_penalty_spent(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init");
    TEST_ASSERT(pair_add_htlc(&p, 1, 7000, 600), "add");
    g_lookup_ch = &p.lsp;
    mock_chain_t m;
    mock_init(&m, 100);
    sweeper_t sw;
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, NULL, NULL),
                "sweeper");
    sweeper_set_channel_lookup(&sw, lookup_one, NULL);
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1,
                "armed");
    char ct_hex[65];
    txid_internal_to_hex(sw.entries[0].source_txid, ct_hex);
    mk_put(&m, ct_hex, 100);
    sweeper_check(&sw);
    TEST_ASSERT(m.n_sent == 1, "claim sent");
    char ours[65];
    memcpy(ours, sw.entries[0].sweep_txid, 65);

    unsigned char secret[32];
    TEST_ASSERT(channel_get_per_commitment_secret(&p.cli, 1, secret) &&
                channel_receive_revocation(&p.lsp, 1, secret),
                "commitment revoked");
    mk_forget(&m, ours);
    mk_spend(&m, ct_hex, sw.entries[0].source_vout,
             "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
             0);
    m.height = 101;
    sweeper_check(&sw);
    TEST_ASSERT(sw.n_entries == 0 && m.n_sent == 1,
                "dropped: the penalty took the output");
    sweeper_cleanup(&sw);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Timing: claim as soon as possible, ahead of the CLTV; keep trying when
   late; give up only once the counterparty's timeout has clearly won;
   revoked commitments are cancelled. */
int test_htlc_claim_priority_timing(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init");
    TEST_ASSERT(pair_add_htlc(&p, 1, 7000, 150), "add htlc");
    g_lookup_ch = &p.lsp;

    mock_chain_t m;
    mock_init(&m, 100);
    sweeper_t sw;
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, NULL, NULL),
                "sweeper");
    sweeper_set_channel_lookup(&sw, lookup_one, NULL);

    /* Remote commitment: claim in the same cycle it is seen confirmed,
       50 blocks before the CLTV, via the success leaf. */
    TEST_ASSERT(sweeper_add_htlc_success(&sw, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1,
                "register remote");
    char ct_hex[65];
    txid_internal_to_hex(sw.entries[0].source_txid, ct_hex);
    sweeper_check(&sw);
    TEST_ASSERT(m.n_sent == 0, "nothing before the commitment confirms");
    mk_put(&m, ct_hex, 100);
    sweeper_check(&sw);
    TEST_ASSERT(m.n_sent == 1, "claimed at once (height 100, cltv 150)");
    ptx_t t;
    TEST_ASSERT(ptx_parse(m.last_sent, m.last_sent_len, &t), "parse");
    TEST_ASSERT(t.n_wit == 4 && memcmp(t.wit[1], p.preimage, 32) == 0 &&
                t.locktime == 0, "success path, not the timeout path");

    /* Local commitment: claimable once BIP 68 lets it into the next block. */
    sweeper_t sl;
    mock_chain_t ml;
    mock_init(&ml, 100);
    TEST_ASSERT(sweeper_init(&sl, ctx, NULL, NULL, 0, &ml.base, NULL, NULL),
                "sweeper local");
    sweeper_set_channel_lookup(&sl, lookup_one, NULL);
    TEST_ASSERT(sweeper_add_htlc_success(&sl, &p.lsp, 0, 0,
                    HTLC_CLAIM_LOCAL_COMMIT, p.lsp_htlc_id, p.preimage) == 1,
                "register local");
    TEST_ASSERT(sl.entries[0].csv_delay == 10, "local claim carries CSV");
    char lct_hex[65];
    txid_internal_to_hex(sl.entries[0].source_txid, lct_hex);
    mk_put(&ml, lct_hex, 100);
    ml.height = 108;
    sweeper_check(&sl);
    TEST_ASSERT(ml.n_sent == 0, "not before the CSV");
    ml.height = 109;
    sweeper_check(&sl);
    TEST_ASSERT(ml.n_sent == 1, "claimed for the first block the CSV allows");
    sweeper_cleanup(&sl);

    /* Late: commitment only confirms after the CLTV.  Still try. */
    sweeper_t sz;
    mock_chain_t mz;
    mock_init(&mz, 160);
    TEST_ASSERT(sweeper_init(&sz, ctx, NULL, NULL, 0, &mz.base, NULL, NULL),
                "sweeper late");
    sweeper_set_channel_lookup(&sz, lookup_one, NULL);
    TEST_ASSERT(sweeper_add_htlc_success(&sz, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1,
                "register late");
    mk_put(&mz, ct_hex, 158);
    sweeper_check(&sz);
    TEST_ASSERT(mz.n_sent == 1, "late claim still attempted");
    sweeper_cleanup(&sz);

    /* Our claim leaves the mempool and another transaction spends the
       HTLC output: keep the entry until well past the CLTV, then drop it. */
    sweeper_t sp;
    mock_chain_t mp;
    mock_init(&mp, 151);
    TEST_ASSERT(sweeper_init(&sp, ctx, NULL, NULL, 0, &mp.base, NULL, NULL),
                "sweeper spent");
    sweeper_set_channel_lookup(&sp, lookup_one, NULL);
    TEST_ASSERT(sweeper_add_htlc_success(&sp, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1,
                "register spent");
    mk_put(&mp, ct_hex, 151);
    sweeper_check(&sp);
    TEST_ASSERT(mp.n_sent == 1 && sp.entries[0].state == SWEEP_BROADCAST,
                "claim sent");
    char ours[65];
    memcpy(ours, sp.entries[0].sweep_txid, 65);
    mk_forget(&mp, ours);
    mk_spend(&mp, ct_hex, sp.entries[0].source_vout,
             "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
             0);
    mp.height = 152;
    sweeper_check(&sp);
    TEST_ASSERT(sp.n_entries == 1 && mp.n_sent == 1,
                "kept, not resent, while the race may still turn");
    mp.height = 156;
    sweeper_check(&sp);
    TEST_ASSERT(sp.n_entries == 0, "dropped once the timeout has clearly won");
    sweeper_cleanup(&sp);

    /* A revoked commitment's claim is cancelled before it reaches chain. */
    sweeper_t sc;
    mock_chain_t mc;
    mock_init(&mc, 100);
    TEST_ASSERT(sweeper_init(&sc, ctx, NULL, NULL, 0, &mc.base, NULL, NULL),
                "sweeper cancel");
    sweeper_set_channel_lookup(&sc, lookup_one, NULL);
    TEST_ASSERT(sweeper_add_htlc_success(&sc, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1,
                "register cancel");
    TEST_ASSERT(sweeper_cancel_htlc_success(&sc, 1, p.lsp.commitment_number) == 0,
                "other channel untouched");
    TEST_ASSERT(sweeper_cancel_htlc_success(&sc, 0,
                    p.lsp.commitment_number - 1) == 0,
                "older revocation does not cancel");
    TEST_ASSERT(sweeper_cancel_htlc_success(&sc, 0, p.lsp.commitment_number) == 1,
                "revocation of that commitment cancels");
    mk_put(&mc, ct_hex, 100);
    sweeper_check(&sc);
    TEST_ASSERT(mc.n_sent == 0, "cancelled claim not broadcast");
    sweeper_cleanup(&sc);

    /* Revocation arriving through any path prunes the claim; a garbled
       revoke_and_ack does not. */
    sweeper_t sr;
    mock_chain_t mr;
    mock_init(&mr, 100);
    TEST_ASSERT(sweeper_init(&sr, ctx, NULL, NULL, 0, &mr.base, NULL, NULL),
                "sweeper revoke");
    sweeper_set_channel_lookup(&sr, lookup_one, NULL);
    TEST_ASSERT(sweeper_add_htlc_success(&sr, &p.lsp, 0, 0,
                    HTLC_CLAIM_REMOTE_COMMIT, p.lsp_htlc_id, p.preimage) == 1,
                "register revoke");
    uint64_t cn = p.lsp.commitment_number;
    unsigned char secret[32], garbled[32];
    TEST_ASSERT(channel_get_per_commitment_secret(&p.cli, cn, secret),
                "client secret");
    memcpy(garbled, secret, 32);
    garbled[31] ^= 0x01;
    TEST_ASSERT(!channel_receive_revocation(&p.lsp, cn, garbled),
                "garbled revocation rejected");
    sweeper_check(&sr);
    TEST_ASSERT(sr.n_entries == 1, "claim kept after a garbled revocation");
    TEST_ASSERT(channel_receive_revocation(&p.lsp, cn, secret),
                "valid revocation accepted");
    sweeper_check(&sr);
    TEST_ASSERT(sr.n_entries == 0, "claim pruned once that commitment is revoked");
    sweeper_cleanup(&sr);

    sweeper_cleanup(&sw);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ------------------------------------------------------------------ */
/* LSP message handlers, in process                                     */
/* ------------------------------------------------------------------ */

/* Exchange nonce pools both ways, as MSG_CHANNEL_NONCES does. */
static int pair_nonces(pair_t *p)
{
    static unsigned char ser[MUSIG_NONCE_POOL_MAX][66];
    if (!channel_init_nonce_pool(&p->lsp, MUSIG_NONCE_POOL_MAX) ||
        !channel_init_nonce_pool(&p->cli, MUSIG_NONCE_POOL_MAX))
        return 0;
    for (size_t i = 0; i < p->lsp.local_nonce_pool.count; i++)
        if (!musig_pubnonce_serialize(p->ctx, ser[i],
                &p->lsp.local_nonce_pool.nonces[i].pubnonce))
            return 0;
    if (!channel_set_remote_pubnonces(&p->cli, ser,
                                      p->lsp.local_nonce_pool.count))
        return 0;
    for (size_t i = 0; i < p->cli.local_nonce_pool.count; i++)
        if (!musig_pubnonce_serialize(p->ctx, ser[i],
                &p->cli.local_nonce_pool.nonces[i].pubnonce))
            return 0;
    return channel_set_remote_pubnonces(&p->lsp, ser,
                                        p->cli.local_nonce_pool.count);
}

/* An LSP with a sender channel (index 0) and a payee channel (index 1),
   each wired to a socketpair whose far end plays the client.  The sender
   paid the payee 7000 sats through the LSP; both HTLCs are on commitment
   1.  The LSP manager owns copies of the LSP-side channels. */
typedef struct {
    pair_t s, p;
    lsp_channel_mgr_t *mgr;
    lsp_t *lsp;
    int cli_fd[2];
    unsigned char s_commit[32];    /* sender commitment 1 (holds the HTLC) */
    char s_commit_hex[65];
    mock_chain_t m;
    sweeper_t sw;
    persist_t db;
    char path[64];
} lspnet_t;

static int lspnet_init(lspnet_t *n, secp256k1_context *ctx)
{
    static const unsigned char FUND_P[32] = { [0 ... 31] = 0x33 };
    memset(n, 0, sizeof(*n));
    if (!pair_init(&n->s, ctx, UNIT_FUND_TXID, 0, 100000, 10) ||
        !pair_init(&n->p, ctx, FUND_P, 0, 100000, 10) ||
        !pair_nonces(&n->s) || !pair_nonces(&n->p))
        return 0;
    if (!pair_add_htlc(&n->s, 1, 7000, 600) ||     /* sender offers */
        !pair_add_htlc(&n->p, 0, 7000, 560))       /* LSP offers payee */
        return 0;
    if (!pair_send_pcp(&n->s, 2) || !pair_send_pcp(&n->p, 2)) return 0;
    if (!pair_cli_commit(&n->s, n->s_commit, n->s_commit_hex)) return 0;

    snprintf(n->path, sizeof(n->path), "/tmp/ss_htlc_lspnet_XXXXXX");
    int fd = mkstemp(n->path);
    if (fd < 0) return 0;
    close(fd);
    if (!persist_open(&n->db, n->path)) return 0;

    n->mgr = calloc(1, sizeof(lsp_channel_mgr_t));
    n->lsp = calloc(1, sizeof(lsp_t));
    if (!n->mgr || !n->lsp) return 0;
    n->mgr->entries = calloc(2, sizeof(lsp_channel_entry_t));
    n->lsp->client_fds = calloc(2, sizeof(int));
    if (!n->mgr->entries || !n->lsp->client_fds) return 0;
    n->mgr->n_channels = 2;
    n->mgr->ctx = ctx;
    n->mgr->bridge_fd = -1;
    n->mgr->persist = &n->db;
    n->mgr->entries[0].channel = n->s.lsp;
    n->mgr->entries[0].channel_id = 0;
    n->mgr->entries[1].channel = n->p.lsp;
    n->mgr->entries[1].channel_id = 1;
    n->lsp->n_clients = 2;
    n->lsp->listen_fd = -1;
    for (int i = 0; i < 2; i++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 0;
        n->lsp->client_fds[i] = sv[0];
        n->cli_fd[i] = sv[1];
    }
    mock_init(&n->m, 100);
    if (!sweeper_init(&n->sw, ctx, NULL, NULL, 0, &n->m.base, &n->db, NULL))
        return 0;
    return lsp_channels_attach_sweeper(n->mgr, &n->sw);
}

static void lspnet_free(lspnet_t *n)
{
    lsp_channels_free_deferred_bridge(n->mgr);
    lsp_channels_drop_pending_updates(n->mgr);
    sweeper_cleanup(&n->sw);
    for (int i = 0; i < 2; i++) {
        if (n->lsp && n->lsp->client_fds && n->lsp->client_fds[i] >= 0)
            close(n->lsp->client_fds[i]);
        if (n->cli_fd[i] > 0) close(n->cli_fd[i]);
    }
    if (n->mgr && n->mgr->entries) {
        channel_cleanup(&n->mgr->entries[0].channel);
        channel_cleanup(&n->mgr->entries[1].channel);
        free(n->mgr->entries);
    }
    free(n->mgr);
    if (n->lsp) free(n->lsp->client_fds);
    free(n->lsp);
    channel_cleanup(&n->s.cli);
    channel_cleanup(&n->p.cli);
    persist_close(&n->db);
    unlink(n->path);
}

/* The client of pair x answers the LSP commitment_signed: revoke its
   previous commitment (garbled on request) and give its next point. */
static int client_send_raa(pair_t *x, int fd, uint32_t chan_id, int garble)
{
    uint64_t cn = x->cli.commitment_number;
    unsigned char sec[32];
    secp256k1_pubkey next;
    if (!channel_get_per_commitment_secret(&x->cli, cn - 1, sec) ||
        !channel_get_per_commitment_point(&x->cli, cn + 1, &next))
        return 0;
    if (garble) sec[0] ^= 1;
    cJSON *j = wire_build_revoke_and_ack(chan_id, sec, x->ctx, &next);
    int ok = wire_send(fd, MSG_REVOKE_AND_ACK, j);
    cJSON_Delete(j);
    memset(sec, 0, 32);
    return ok;
}

/* Messages of type t waiting on a client end (all are read). */
static int drain_count(int fd, uint8_t t)
{
    int n = 0;
    for (;;) {
        struct pollfd pf = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&pf, 1, 0) <= 0 || !(pf.revents & POLLIN)) break;
        wire_msg_t m;
        if (!wire_recv(fd, &m)) break;
        if (m.msg_type == t) n++;
        if (m.json) cJSON_Delete(m.json);
    }
    return n;
}

/* The payee reveals the preimage to the LSP: it fulfils on its side and
   queues its revoke_and_ack for the commitment_signed that follows. */
static int payee_fulfils(lspnet_t *n, wire_msg_t *msg)
{
    if (!channel_fulfill_htlc(&n->p.cli, n->p.cli_htlc_id, n->p.preimage) ||
        !client_send_raa(&n->p, n->cli_fd[1], 1, 0))
        return 0;
    msg->msg_type = MSG_UPDATE_FULFILL_HTLC;
    msg->json = wire_build_update_fulfill_htlc(n->p.lsp_htlc_id, n->p.preimage);
    return msg->json != NULL;
}

/* The production fulfil handler arms the claim on the sender channel
   before the preimage goes back to the sender; a sender that then
   withholds its revoke_and_ack and broadcasts the commitment holding the
   HTLC is claimed against. */
int test_htlc_claim_lsp_fulfil_handler(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup");
    wire_msg_t msg;
    TEST_ASSERT(payee_fulfils(&n, &msg), "payee fulfils");
    shutdown(n.cli_fd[0], SHUT_WR);          /* sender: no revoke_and_ack */
    lsp_channels_handle_msg(n.mgr, n.lsp, 1, &msg);
    cJSON_Delete(msg.json);

    TEST_ASSERT(drain_count(n.cli_fd[0], MSG_UPDATE_FULFILL_HTLC) == 1,
                "preimage went back to the sender");
    TEST_ASSERT(n.sw.n_entries == 1 && n.sw.entries[0].channel_id == 0 &&
                n.sw.entries[0].claim_side == HTLC_CLAIM_REMOTE_COMMIT &&
                memcmp(n.sw.entries[0].source_txid, n.s_commit, 32) == 0 &&
                memcmp(n.sw.entries[0].preimage, n.s.preimage, 32) == 0,
                "claim armed on the sender commitment that holds the HTLC");
    TEST_ASSERT(count_rows(&n.db, "htlc_success") == 1, "and on disk");

    mk_put(&n.m, n.s_commit_hex, 100);
    sweeper_check(&n.sw);
    TEST_ASSERT(n.m.n_sent == 1, "claimed when the sender broadcasts it");
    lspnet_free(&n);

    /* A valid revoke_and_ack retires the claim. */
    TEST_ASSERT(lspnet_init(&n, ctx), "setup 2");
    TEST_ASSERT(payee_fulfils(&n, &msg), "payee fulfils 2");
    TEST_ASSERT(channel_fulfill_htlc(&n.s.cli, n.s.cli_htlc_id, n.s.preimage) &&
                client_send_raa(&n.s, n.cli_fd[0], 0, 0), "sender revokes");
    lsp_channels_handle_msg(n.mgr, n.lsp, 1, &msg);
    cJSON_Delete(msg.json);
    TEST_ASSERT(drain_count(n.cli_fd[0], MSG_UPDATE_FULFILL_HTLC) == 1,
                "sender fulfilled");
    TEST_ASSERT(n.sw.n_entries == 0 && count_rows(&n.db, "htlc_success") == 0,
                "claim cancelled by the verified revocation");
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* The bridge pay-result handler does the same for an outbound payment. */
int test_htlc_claim_lsp_bridge_handler(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup");
    htlc_origin_t origin;
    memset(&origin, 0, sizeof(origin));
    memcpy(origin.payment_hash, n.s.hash, 32);
    origin.request_id = 7;
    origin.sender_idx = 0;
    origin.sender_htlc_id = n.s.lsp_htlc_id;
    origin.active = 1;
    n.mgr->htlc_origins = &origin;
    n.mgr->n_htlc_origins = 1;
    shutdown(n.cli_fd[0], SHUT_WR);          /* sender: no revoke_and_ack */
    wire_msg_t msg;
    msg.msg_type = MSG_BRIDGE_PAY_RESULT;
    msg.json = wire_build_bridge_pay_result(7, 1, n.s.preimage);
    lsp_channels_handle_bridge_msg(n.mgr, n.lsp, &msg);
    cJSON_Delete(msg.json);
    n.mgr->htlc_origins = NULL;
    n.mgr->n_htlc_origins = 0;

    TEST_ASSERT(drain_count(n.cli_fd[0], MSG_UPDATE_FULFILL_HTLC) == 1,
                "preimage went to the sender");
    TEST_ASSERT(n.sw.n_entries == 1 && n.sw.entries[0].channel_id == 0 &&
                memcmp(n.sw.entries[0].source_txid, n.s_commit, 32) == 0,
                "claim armed on the sender commitment");
    mk_put(&n.m, n.s_commit_hex, 100);
    sweeper_check(&n.sw);
    TEST_ASSERT(n.m.n_sent == 1, "claimed");
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Store the client signature of its current commitment, as
   client_handle_commitment_signed does after verifying the LSP's. */
static int pair_client_signed(pair_t *p)
{
    tx_buf_t uc, sc;
    tx_buf_init(&uc, 1024);
    tx_buf_init(&sc, 2048);
    unsigned char txid[32];
    ptx_t t;
    int ok = channel_build_commitment_tx(&p->cli, &uc, txid) &&
             channel_sign_commitment(&p->cli, &sc, &uc, &p->lsp_kp) &&
             ptx_parse(sc.data, sc.len, &t) && t.n_wit == 1 &&
             t.wit_len[0] == 64;
    if (ok) {
        memcpy(p->cli.latest_commitment_sig, t.wit[0], 64);
        p->cli.has_latest_commitment_sig = 1;
    }
    tx_buf_free(&uc);
    tx_buf_free(&sc);
    return ok;
}

/* A client claims from its persisted state alone: the LSP gone, the
   client restarted, no live channel.  A client also never arms a claim on
   (or reveals a preimage against) a commitment it does not hold signed. */
int test_htlc_claim_client_without_lsp(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    char path[] = "/tmp/ss_htlc_cli_XXXXXX";
    int fd = mkstemp(path);
    TEST_ASSERT(fd >= 0, "temp db");
    close(fd);
    const uint32_t idx = 3;                /* the client row in its DB */
    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init");
    TEST_ASSERT(pair_add_htlc(&p, 0, 20000, 600), "LSP pays the client");
    persist_t db;
    TEST_ASSERT(persist_open(&db, path) &&
                persist_save_channel(&db, &p.cli, 0, idx) &&
                persist_save_basepoints(&db, idx, &p.cli), "client db");
    mock_chain_t m;
    mock_init(&m, 100);
    sweeper_t sw;
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, &db, NULL),
                "sweeper");
    client_htlc_claims_attach(&sw, &db, ctx);
    client_set_htlc_live_channel(&p.cli);
    client_set_htlc_sweeper(&sw, idx);
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    /* Not holding the current commitment signed: preimage kept. */
    TEST_ASSERT(!client_fulfill_payment(sv[0], &p.cli, p.cli_htlc_id,
                                        p.preimage), "fulfil refused");
    TEST_ASSERT(sw.n_entries == 0 && drain_count(sv[1],
                MSG_UPDATE_FULFILL_HTLC) == 0, "no claim, nothing sent");

    TEST_ASSERT(pair_client_signed(&p), "client holds it signed");
    unsigned char ct[32];
    char ct_hex[65];
    TEST_ASSERT(pair_cli_commit(&p, ct, ct_hex), "commitment");

    TEST_ASSERT(client_fulfill_payment(sv[0], &p.cli, p.cli_htlc_id,
                                       p.preimage), "client fulfils");
    TEST_ASSERT(drain_count(sv[1], MSG_UPDATE_FULFILL_HTLC) == 1, "revealed");
    TEST_ASSERT(sw.n_entries == 1 && sw.entries[0].channel_id == idx &&
                sw.entries[0].claim_side == HTLC_CLAIM_LOCAL_COMMIT &&
                memcmp(sw.entries[0].source_txid, ct, 32) == 0,
                "claim armed on the signed commitment");
    sweep_entry_t armed = sw.entries[0];
    close(sv[0]); close(sv[1]);

    /* The LSP never signs again and goes away; the client restarts. */
    client_set_htlc_live_channel(NULL);
    client_set_htlc_sweeper(NULL, 0);
    sweeper_cleanup(&sw);
    persist_close(&db);
    TEST_ASSERT(persist_open(&db, path), "reopen");
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, &db, NULL) &&
                sw.n_entries == 1, "claim reloaded");
    client_htlc_claims_attach(&sw, &db, ctx);

    mk_put(&m, ct_hex, 100);
    TEST_ASSERT(client_run_htlc_claims(&sw) == 1 && m.n_sent == 0,
                "pending through the CSV");
    m.height = 109;
    TEST_ASSERT(client_run_htlc_claims(&sw) == 1 && m.n_sent == 1,
                "claimed from the DB state, no session");
    tx_buf_t ref;
    tx_buf_init(&ref, 512);
    secp256k1_pubkey pcp;
    TEST_ASSERT(secp256k1_ec_pubkey_parse(ctx, &pcp, armed.commit_point, 33) &&
                channel_build_htlc_claim_tx(&p.cli, &ref, HTLC_CLAIM_LOCAL_COMMIT,
                    &pcp, ct, armed.source_vout, armed.amount_sats,
                    armed.htlc_spk, p.hash, p.preimage, armed.cltv_expiry,
                    armed.amount_sats - armed.claim_amount, NULL, NULL),
                "reference claim from the live channel");
    TEST_ASSERT(ref.len == m.last_sent_len &&
                memcmp(ref.data, m.last_sent, ref.len) == 0,
                "same claim as from the live channel");
    tx_buf_free(&ref);
    mk_put(&m, sw.entries[0].sweep_txid, 109);
    TEST_ASSERT(client_run_htlc_claims(&sw) == 0, "settled");

    client_htlc_claims_attach(NULL, NULL, NULL);
    sweeper_cleanup(&sw);
    persist_close(&db);
    unlink(path);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Second HTLC on both legs, with its own preimage, after lspnet_init. */
static int lspnet_add_second(lspnet_t *n, unsigned char *pre_b)
{
    unsigned char hb[32];
    memset(pre_b, 0x3C, 32);
    sha256(pre_b, 32, hb);
    uint64_t i1, i2;
    if (!channel_add_htlc(&n->mgr->entries[0].channel, HTLC_RECEIVED, 9000,
                          hb, 600, &i1) ||
        !channel_add_htlc(&n->s.cli, HTLC_OFFERED, 9000, hb, 600, &i2) ||
        !channel_add_htlc(&n->mgr->entries[1].channel, HTLC_OFFERED, 9000,
                          hb, 560, &i1) ||
        !channel_add_htlc(&n->p.cli, HTLC_RECEIVED, 9000, hb, 560, &i2))
        return 0;
    for (int k = 0; k < 2; k++) {
        pair_t *x = k ? &n->p : &n->s;
        secp256k1_pubkey pt;
        if (!channel_get_per_commitment_point(&x->cli, 3, &pt)) return 0;
        channel_set_remote_pcp(&n->mgr->entries[k].channel, 3, &pt);
    }
    return pair_cli_commit(&n->s, n->s_commit, n->s_commit_hex);
}

/* The payee reveals preimage pre for its HTLC htlc_id. */
static int payee_fulfils_htlc(lspnet_t *n, uint64_t htlc_id,
                              const unsigned char *pre, wire_msg_t *msg)
{
    if (!channel_fulfill_htlc(&n->p.cli, htlc_id, pre) ||
        !client_send_raa(&n->p, n->cli_fd[1], 1, 0))
        return 0;
    msg->msg_type = MSG_UPDATE_FULFILL_HTLC;
    msg->json = wire_build_update_fulfill_htlc(htlc_id, pre);
    return msg->json != NULL;
}

/* Withholding alone: the sender has HTLCs A and B on commitment N.  The
   payee fulfils A; the sender takes the preimage and never revokes N.
   The payee then fulfils B: the LSP has paid it, so B must be claimable
   on N too, and the sender must not get B's preimage. */
int test_htlc_claim_withheld_raa_second_htlc(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    unsigned char pre_b[32];
    TEST_ASSERT(lspnet_init(&n, ctx) && lspnet_add_second(&n, pre_b),
                "sender has A and B on N, payee has both");
    uint64_t a_id = n.p.cli_htlc_id, b_id = a_id + 1;
    shutdown(n.cli_fd[0], SHUT_WR);          /* sender never answers */

    wire_msg_t msg;
    TEST_ASSERT(payee_fulfils_htlc(&n, a_id, n.p.preimage, &msg), "fulfil A");
    lsp_channels_handle_msg(n.mgr, n.lsp, 1, &msg);
    cJSON_Delete(msg.json);
    TEST_ASSERT(n.mgr->entries[0].channel.revocation_failed,
                "sender channel failed: N not revoked");
    TEST_ASSERT(n.lsp->client_fds[0] < 0, "sender disconnected");

    TEST_ASSERT(payee_fulfils_htlc(&n, b_id, pre_b, &msg), "fulfil B");
    lsp_channels_handle_msg(n.mgr, n.lsp, 1, &msg);
    cJSON_Delete(msg.json);
    TEST_ASSERT(drain_count(n.cli_fd[0], MSG_UPDATE_FULFILL_HTLC) == 1,
                "only A was revealed to the sender");

    mk_put(&n.m, n.s_commit_hex, 100);       /* sender broadcasts N */
    sweeper_check(&n.sw);
    TEST_ASSERT(n.m.n_sent == 2, "both HTLC outputs on N claimed");
    lspnet_free(&n);

    /* Same, but the sender broadcasts N+1 (B only). */
    TEST_ASSERT(lspnet_init(&n, ctx) && lspnet_add_second(&n, pre_b),
                "setup 2");
    shutdown(n.cli_fd[0], SHUT_WR);
    TEST_ASSERT(payee_fulfils_htlc(&n, a_id, n.p.preimage, &msg), "fulfil A 2");
    lsp_channels_handle_msg(n.mgr, n.lsp, 1, &msg);
    cJSON_Delete(msg.json);
    TEST_ASSERT(channel_fulfill_htlc(&n.s.cli, n.s.cli_htlc_id, n.s.preimage),
                "sender applies A");
    unsigned char t1[32];
    char t1_hex[65];
    TEST_ASSERT(pair_cli_commit(&n.s, t1, t1_hex), "sender commitment N+1");
    TEST_ASSERT(payee_fulfils_htlc(&n, b_id, pre_b, &msg), "fulfil B 2");
    lsp_channels_handle_msg(n.mgr, n.lsp, 1, &msg);
    cJSON_Delete(msg.json);
    mk_put(&n.m, t1_hex, 100);
    sweeper_check(&n.sw);
    TEST_ASSERT(n.m.n_sent == 1, "B claimed on N+1");
    n.m.height += sweeper_final_depth(&n.sw) - 1;
    sweeper_check(&n.sw);
    TEST_ASSERT(n.sw.n_entries == 1 && n.sw.entries[0].state == SWEEP_BROADCAST,
                "claims on N dropped once N+1 is buried final");
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A revoke_and_ack that does not verify (with a well-formed next point)
   fails the channel: the next point is not stored, the LSP revocation is
   not sent, the claim on the unrevoked commitment stays, the mark is
   persisted, and the client is not heard from again. */
int test_htlc_claim_garbled_raa_fails_channel(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup");
    TEST_ASSERT(persist_save_channel(&n.db, &n.mgr->entries[0].channel, 0, 0),
                "sender channel row");
    wire_msg_t msg;
    TEST_ASSERT(payee_fulfils(&n, &msg), "payee fulfils");
    TEST_ASSERT(channel_fulfill_htlc(&n.s.cli, n.s.cli_htlc_id, n.s.preimage) &&
                client_send_raa(&n.s, n.cli_fd[0], 0, 1),
                "sender answers with a garbled revocation");
    lsp_channels_handle_msg(n.mgr, n.lsp, 1, &msg);
    cJSON_Delete(msg.json);

    channel_t *sc = &n.mgr->entries[0].channel;
    unsigned char secret[32];
    secp256k1_pubkey pt;
    TEST_ASSERT(sc->revocation_failed, "sender channel failed");
    TEST_ASSERT(!channel_get_received_revocation(sc, 1, secret),
                "no revocation stored");
    TEST_ASSERT(!channel_get_remote_pcp(sc, 3, &pt), "next point not stored");
    TEST_ASSERT(drain_count(n.cli_fd[0], MSG_LSP_REVOKE_AND_ACK) == 0,
                "no LSP revocation sent");
    TEST_ASSERT(n.sw.n_entries == 1 && n.sw.entries[0].channel_id == 0 &&
                memcmp(n.sw.entries[0].preimage, n.s.preimage, 32) == 0,
                "claim on the unrevoked commitment kept");
    TEST_ASSERT(persist_channel_is_failed(&n.db, 0), "failure persisted");
    TEST_ASSERT(persist_save_channel(&n.db, sc, 0, 0) &&
                persist_channel_is_failed(&n.db, 0), "kept when re-saved");

    /* Nothing more is signed for the channel or taken from its client. */
    unsigned char psig[32];
    uint32_t nidx;
    uint64_t id;
    TEST_ASSERT(!channel_create_commitment_partial_sig(sc, psig, &nidx) &&
                !channel_add_htlc(sc, HTLC_RECEIVED, 1000, n.s.hash, 600, &id),
                "no new commitment, no new HTLC");
    wire_msg_t late;
    late.msg_type = MSG_UPDATE_FAIL_HTLC;
    late.json = wire_build_update_fail_htlc(0, "late");
    TEST_ASSERT(!lsp_channels_handle_msg(n.mgr, n.lsp, 0, &late),
                "message from the failed channel dropped");
    cJSON_Delete(late.json);

    mk_put(&n.m, n.s_commit_hex, 100);
    sweeper_check(&n.sw);
    TEST_ASSERT(n.m.n_sent == 1, "claimed when the sender broadcasts");
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A client that does not answer an add keeps the commitment the add
   replaced.  The channel goes on, but the HTLCs on that commitment were
   watched, so a preimage revealed later is claimable there too. */
int test_htlc_claim_unrevoked_after_add(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup: A on N");
    channel_t *sc = &n.mgr->entries[0].channel;
    TEST_ASSERT(lsp_channels_watch_commitment(n.mgr, 0) && n.sw.n_entries == 1,
                "add path: A watched on N");
    unsigned char h2[32];
    memset(h2, 0x66, 32);
    uint64_t i1, i2;
    TEST_ASSERT(channel_add_htlc(sc, HTLC_RECEIVED, 5000, h2, 600, &i1) &&
                channel_add_htlc(&n.s.cli, HTLC_OFFERED, 5000, h2, 600, &i2),
                "sender adds B: N+1");
    secp256k1_pubkey next;
    TEST_ASSERT(!lsp_channels_take_revocation(n.mgr, n.lsp, 0, NULL, 0, &next),
                "no revoke_and_ack");
    TEST_ASSERT(!sc->revocation_failed, "an add without an answer does not fail");

    /* A preimage of A arrives later (payee fulfils). */
    TEST_ASSERT(lsp_channels_register_htlc_claim(n.mgr, 0, n.s.lsp_htlc_id,
                                                 n.s.preimage) == 1,
                "armed on N+1");
    TEST_ASSERT(sweeper_pending_claims(&n.sw) == 2,
                "and on N, where the watch was");
    mk_put(&n.m, n.s_commit_hex, 100);       /* the sender broadcasts N */
    sweeper_check(&n.sw);
    TEST_ASSERT(n.m.n_sent == 1, "A claimed on N");

    /* With a valid revocation the watch goes. */
    lspnet_free(&n);
    TEST_ASSERT(lspnet_init(&n, ctx), "setup 2");
    sc = &n.mgr->entries[0].channel;
    TEST_ASSERT(lsp_channels_watch_commitment(n.mgr, 0) && n.sw.n_entries == 1,
                "watched");
    TEST_ASSERT(channel_add_htlc(sc, HTLC_RECEIVED, 5000, h2, 600, &i1) &&
                channel_add_htlc(&n.s.cli, HTLC_OFFERED, 5000, h2, 600, &i2),
                "N+1 again");
    TEST_ASSERT(client_send_raa(&n.s, n.cli_fd[0], 0, 0), "sender revokes N");
    wire_msg_t ack;
    TEST_ASSERT(wire_recv(n.lsp->client_fds[0], &ack), "LSP reads it");
    TEST_ASSERT(lsp_channels_take_revocation(n.mgr, n.lsp, 0, &ack, 0, &next),
                "valid revocation");
    cJSON_Delete(ack.json);
    TEST_ASSERT(n.sw.n_entries == 0, "watch dropped");
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Every LSP path that replaces a client commitment                     */
/* ------------------------------------------------------------------ */

static void lsp_dump_claims(const sweeper_t *sw)
{
    for (size_t i = 0; i < sw->n_entries; i++)
        printf("  entry %zu type %d channel %u cn %llu vout %u armed %d\n", i,
               (int)sw->entries[i].type, sw->entries[i].channel_id,
               (unsigned long long)sw->entries[i].commitment_number,
               sw->entries[i].source_vout,
               sw->entries[i].preimage[0] || sw->entries[i].preimage[1]);
}

/* Client 1 (the payee) offers HTLC Y (preimage pre_y) on its commitment,
   which then becomes the one at n->pn (number 2).  The LSP has the
   client's point for 3. */
static int lspnet_payee_offers(lspnet_t *n, unsigned char *pre_y,
                               uint64_t *y_id)
{
    unsigned char hy[32];
    memset(pre_y, 0x71, 32);
    sha256(pre_y, 32, hy);
    uint64_t yc;
    if (!channel_add_htlc(&n->mgr->entries[1].channel, HTLC_RECEIVED, 4000,
                          hy, 1500, y_id) ||
        !channel_add_htlc(&n->p.cli, HTLC_OFFERED, 4000, hy, 1500, &yc))
        return 0;
    secp256k1_pubkey pt;
    if (!channel_get_per_commitment_point(&n->p.cli, 3, &pt)) return 0;
    channel_set_remote_pcp(&n->mgr->entries[1].channel, 3, &pt);
    return 1;
}

/* An add whose sender never revokes the commitment it replaces: that
   commitment (handle_add_htlc, sender leg) is watched, so the preimage
   of an HTLC on it, learned later, is claimed there. */
int test_htlc_claim_add_sender_watched(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup: A on sender commitment 1");
    n.mgr->entries[1].ready = 1;
    channel_t *sc = &n.mgr->entries[0].channel;
    unsigned char hx[32];
    memset(hx, 0x5D, 32);
    uint64_t cid;
    TEST_ASSERT(channel_add_htlc(&n.s.cli, HTLC_OFFERED, 3000, hx, 1500, &cid),
                "sender adds X");
    shutdown(n.cli_fd[0], SHUT_WR);          /* and never revokes 1 */
    wire_msg_t add;
    add.msg_type = MSG_UPDATE_ADD_HTLC;
    add.json = wire_build_update_add_htlc(cid, 3000 * 1000, hx, 1500);
    cJSON_AddNumberToObject(add.json, "dest_client", 1);
    lsp_channels_handle_msg(n.mgr, n.lsp, 0, &add);
    cJSON_Delete(add.json);
    TEST_ASSERT(sc->commitment_number == 2 && !sc->revocation_failed,
                "commitment 2 signed, unanswered, channel open");

    wire_msg_t msg;
    TEST_ASSERT(payee_fulfils(&n, &msg), "payee fulfils A");
    lsp_channels_handle_msg(n.mgr, n.lsp, 1, &msg);
    cJSON_Delete(msg.json);
    TEST_ASSERT(drain_count(n.cli_fd[0], MSG_UPDATE_FULFILL_HTLC) == 0,
                "no preimage to a sender with a revocation outstanding");
    lsp_dump_claims(&n.sw);
    mk_put(&n.m, n.s_commit_hex, 100);       /* the sender broadcasts 1 */
    sweeper_check(&n.sw);
    TEST_ASSERT(n.m.n_sent == 1, "A claimed on commitment 1");
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Same for the destination of a forward (handle_add_htlc, dest leg): the
   commitment the add replaces holds an HTLC the destination offered. */
int test_htlc_claim_add_dest_watched(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup");
    n.mgr->entries[1].ready = 1;
    unsigned char pre_y[32];
    uint64_t y_id;
    TEST_ASSERT(lspnet_payee_offers(&n, pre_y, &y_id), "client 1 offers Y");
    unsigned char pn[32];
    char pn_hex[65];
    TEST_ASSERT(pair_cli_commit(&n.p, pn, pn_hex), "its commitment 2");

    unsigned char hx[32];
    memset(hx, 0x5D, 32);
    uint64_t cid;
    TEST_ASSERT(channel_add_htlc(&n.s.cli, HTLC_OFFERED, 3000, hx, 1500, &cid) &&
                client_send_raa(&n.s, n.cli_fd[0], 0, 0),
                "client 0 adds X for client 1 and revokes");
    shutdown(n.cli_fd[1], SHUT_WR);          /* client 1 never revokes 2 */
    wire_msg_t add;
    add.msg_type = MSG_UPDATE_ADD_HTLC;
    add.json = wire_build_update_add_htlc(cid, 3000 * 1000, hx, 1500);
    cJSON_AddNumberToObject(add.json, "dest_client", 1);
    lsp_channels_handle_msg(n.mgr, n.lsp, 0, &add);
    cJSON_Delete(add.json);
    TEST_ASSERT(n.mgr->entries[1].channel.commitment_number == 3 &&
                !n.mgr->entries[1].channel.revocation_failed,
                "X forwarded on commitment 3, unanswered");

    TEST_ASSERT(lsp_channels_secure_preimage(n.mgr, n.lsp, 1, y_id, pre_y),
                "Y's preimage learned");
    mk_put(&n.m, pn_hex, 100);
    sweeper_check(&n.sw);
    TEST_ASSERT(n.m.n_sent == 1, "Y claimed on commitment 2");
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Same for an inbound bridge payment (lsp_channels_handle_bridge_msg). */
int test_htlc_claim_bridge_add_watched(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup");
    unsigned char pre_y[32];
    uint64_t y_id;
    TEST_ASSERT(lspnet_payee_offers(&n, pre_y, &y_id), "client 1 offers Y");
    unsigned char pn[32];
    char pn_hex[65];
    TEST_ASSERT(pair_cli_commit(&n.p, pn, pn_hex), "its commitment 2");
    unsigned char pre_z[32], hz[32];
    memset(pre_z, 0x72, 32);
    sha256(pre_z, 32, hz);
    n.mgr->invoices = calloc(4, sizeof(invoice_entry_t));
    n.mgr->invoices_cap = 4;
    TEST_ASSERT(lsp_channels_register_invoice(n.mgr, hz, pre_z, 1, 5000 * 1000),
                "invoice of client 1");
    shutdown(n.cli_fd[1], SHUT_WR);          /* client 1 never revokes 2 */
    wire_msg_t m;
    m.msg_type = MSG_BRIDGE_ADD_HTLC;
    m.json = wire_build_bridge_add_htlc(hz, 5000 * 1000, 1500, 77);
    lsp_channels_handle_bridge_msg(n.mgr, n.lsp, &m);
    cJSON_Delete(m.json);
    TEST_ASSERT(n.mgr->entries[1].channel.commitment_number == 3,
                "bridge HTLC on commitment 3, unanswered");
    int kept = 0;
    for (size_t h = 0; h < n.mgr->entries[1].channel.n_htlcs; h++)
        if (memcmp(n.mgr->entries[1].channel.htlcs[h].payment_hash, hz, 32) == 0)
            kept = 1;
    TEST_ASSERT(kept, "not rolled back over the commitment signed with it");

    TEST_ASSERT(lsp_channels_secure_preimage(n.mgr, n.lsp, 1, y_id, pre_y),
                "Y's preimage learned");
    mk_put(&n.m, pn_hex, 100);
    sweeper_check(&n.sw);
    TEST_ASSERT(n.m.n_sent == 1, "Y claimed on commitment 2");
    free(n.mgr->invoices);
    free(n.mgr->htlc_origins);
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A payee that fulfils and does not revoke: its channel is not failed for
   that (the commitment it keeps pays it no more, and nothing more can be
   signed for it), and the commitment the fulfil replaced, holding an HTLC
   the payee offered, is watched. */
int test_htlc_claim_payee_fulfil_watched(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup");
    unsigned char pre_y[32];
    uint64_t y_id;
    TEST_ASSERT(lspnet_payee_offers(&n, pre_y, &y_id), "payee offers Y");
    unsigned char pn[32];
    char pn_hex[65];
    TEST_ASSERT(pair_cli_commit(&n.p, pn, pn_hex), "payee commitment 2");
    TEST_ASSERT(channel_fulfill_htlc(&n.p.cli, n.p.cli_htlc_id, n.p.preimage),
                "payee fulfils A");
    shutdown(n.cli_fd[1], SHUT_WR);          /* and never revokes 2 */
    TEST_ASSERT(channel_fulfill_htlc(&n.s.cli, n.s.cli_htlc_id, n.s.preimage) &&
                client_send_raa(&n.s, n.cli_fd[0], 0, 0), "sender revokes");
    wire_msg_t msg;
    msg.msg_type = MSG_UPDATE_FULFILL_HTLC;
    msg.json = wire_build_update_fulfill_htlc(n.p.lsp_htlc_id, n.p.preimage);
    lsp_channels_handle_msg(n.mgr, n.lsp, 1, &msg);
    cJSON_Delete(msg.json);
    channel_t *pc = &n.mgr->entries[1].channel;
    secp256k1_pubkey pt;
    TEST_ASSERT(pc->commitment_number == 3 && !pc->revocation_failed,
                "payee not failed for a missing revocation");
    TEST_ASSERT(!channel_get_remote_pcp(pc, 4, &pt), "but no next point");
    TEST_ASSERT(drain_count(n.cli_fd[1], MSG_LSP_REVOKE_AND_ACK) == 0,
                "and no LSP revocation");
    TEST_ASSERT(drain_count(n.cli_fd[0], MSG_UPDATE_FULFILL_HTLC) == 1,
                "the payment settled upstream");

    TEST_ASSERT(lsp_channels_secure_preimage(n.mgr, n.lsp, 1, y_id, pre_y),
                "Y's preimage learned");
    mk_put(&n.m, pn_hex, 100);
    sweeper_check(&n.sw);
    TEST_ASSERT(n.m.n_sent == 1, "Y claimed on payee commitment 2");
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Profit settlement adds an HTLC to a client's channel: like any update,
   it watches the commitment it replaces, and a revocation that does not
   verify fails the channel (no next point, no LSP revocation). */
int test_htlc_claim_settlement_garbled_raa(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup: A on sender commitment 1");
    static factory_t f;
    static participant_profile_t prof[3];
    memset(&f, 0, sizeof(f));
    memset(prof, 0, sizeof(prof));
    prof[1].profit_share_bps = 5000;
    f.n_participants = 3;
    f.profiles = prof;
    f.cltv_timeout = 1000;
    n.mgr->economic_mode = ECON_PROFIT_SHARED;
    n.mgr->accumulated_fees_sats = 2000;
    n.mgr->entries[0].accumulated_fees_sats = 2000;
    unsigned char dh[32];
    memset(dh, 0x11, 32);
    uint64_t cid;
    TEST_ASSERT(channel_add_htlc(&n.s.cli, HTLC_RECEIVED, 1000, dh, 500, &cid),
                "client applies the settlement add (commitment 2)");
    TEST_ASSERT(client_send_raa(&n.s, n.cli_fd[0], 0, 1),
                "client answers with a revocation that does not verify");
    shutdown(n.cli_fd[0], SHUT_WR);
    lsp_channels_settle_via_payment(n.mgr, n.lsp, &f);
    channel_t *sc = &n.mgr->entries[0].channel;
    secp256k1_pubkey pt;
    TEST_ASSERT(sc->revocation_failed, "channel failed");
    TEST_ASSERT(!channel_get_remote_pcp(sc, 3, &pt), "no next point stored");
    TEST_ASSERT(drain_count(n.cli_fd[0], MSG_LSP_REVOKE_AND_ACK) == 0 &&
                drain_count(n.cli_fd[0], MSG_REVOKE_AND_ACK) == 0,
                "no LSP revocation");

    wire_msg_t msg;
    TEST_ASSERT(payee_fulfils(&n, &msg), "payee fulfils A");
    lsp_channels_handle_msg(n.mgr, n.lsp, 1, &msg);
    cJSON_Delete(msg.json);
    lsp_dump_claims(&n.sw);
    mk_put(&n.m, n.s_commit_hex, 100);       /* sender broadcasts 1 */
    sweeper_check(&n.sw);
    TEST_ASSERT(n.m.n_sent == 1, "A claimed on unrevoked commitment 1");
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A state behind a commitment the LSP signed (here: rolled back after an
   unanswered add) is never signed again at that number: an update that
   would is refused and undone, before the preimage goes out.  The
   commitment the client may hold there was watched when it was signed. */
int test_htlc_claim_rollback_behind_signed(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup: A on sender commitment 1");
    n.mgr->entries[1].ready = 1;
    channel_t *sc = &n.mgr->entries[0].channel;
    uint64_t sv_local = sc->local_amount, sv_remote = sc->remote_amount;
    size_t sv_n = sc->n_htlcs;
    unsigned char hx[32];
    memset(hx, 0x5D, 32);
    uint64_t cid;
    TEST_ASSERT(channel_add_htlc(&n.s.cli, HTLC_OFFERED, 3000, hx, 600, &cid),
                "client adds X (its commitment 2: A and X)");
    unsigned char old2[32];
    char old2_hex[65];
    TEST_ASSERT(pair_cli_commit(&n.s, old2, old2_hex), "client commitment 2");
    shutdown(n.cli_fd[0], SHUT_WR);          /* never revokes 1 */
    wire_msg_t add;
    add.msg_type = MSG_UPDATE_ADD_HTLC;
    add.json = wire_build_update_add_htlc(cid, 3000 * 1000, hx, 600);
    cJSON_AddNumberToObject(add.json, "dest_client", 1);
    lsp_channels_handle_msg(n.mgr, n.lsp, 0, &add);
    cJSON_Delete(add.json);
    TEST_ASSERT(sc->commitment_number == 2 && !sc->revocation_failed,
                "add signed commitment 2, channel open");
    /* Roll the channel back to commitment 1, as a rollback would. */
    sc->local_amount = sv_local;
    sc->remote_amount = sv_remote;
    sc->commitment_number = 1;
    sc->n_htlcs = sv_n;
    wire_msg_t msg;
    TEST_ASSERT(payee_fulfils(&n, &msg), "payee fulfils A");
    lsp_channels_handle_msg(n.mgr, n.lsp, 1, &msg);
    cJSON_Delete(msg.json);
    TEST_ASSERT(!sc->revocation_failed && sc->commitment_number == 1 &&
                sc->n_htlcs == sv_n,
                "no second commitment 2: A's settle refused and undone, "
                "the channel kept");
    TEST_ASSERT(drain_count(n.cli_fd[0], MSG_UPDATE_FULFILL_HTLC) == 0,
                "preimage not revealed");
    lsp_dump_claims(&n.sw);
    mk_put(&n.m, old2_hex, 100);             /* client broadcasts its 2 */
    sweeper_check(&n.sw);
    TEST_ASSERT(n.m.n_sent == 1, "A claimed on the commitment 2 it holds");
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* lsp_channels_update_sign never signs a different commitment at a number
   already signed (the update is undone instead, the channel kept); the
   reconnect resend only resends the identical one. */
int test_htlc_claim_no_second_commitment(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup");
    lsp_channel_entry_t *en = &n.mgr->entries[0];
    en->has_signed = 1;
    en->signed_cn = en->channel.commitment_number;
    memset(en->signed_txid, 0xAB, 32);       /* another commitment there */
    TEST_ASSERT(!lsp_channels_resend_commitment_signed(n.mgr, n.lsp, 0) &&
                !en->channel.revocation_failed &&
                drain_count(n.cli_fd[0], MSG_COMMITMENT_SIGNED) == 0,
                "resend: nothing sent, channel kept");
    channel_t *ec = &en->channel;
    uint64_t cn0 = ec->commitment_number, l0 = ec->local_amount;
    size_t nh0 = ec->n_htlcs;
    lsp_update_t u;
    TEST_ASSERT(lsp_channels_update_begin(n.mgr, 0, &u), "an update begins");
    unsigned char hy[32];
    memset(hy, 0x3C, 32);
    uint64_t yid;
    TEST_ASSERT(channel_add_htlc(ec, HTLC_OFFERED, 2000, hy, 500, &yid),
                "the LSP adds Y");
    en->signed_cn = cn0 + 1;                 /* another commitment there */
    TEST_ASSERT(!lsp_channels_update_sign(n.mgr, n.lsp, &u) && u.undone &&
                !ec->revocation_failed &&
                drain_count(n.cli_fd[0], MSG_COMMITMENT_SIGNED) == 0,
                "update: refused, the channel kept");
    TEST_ASSERT(ec->commitment_number == cn0 && ec->n_htlcs == nh0 &&
                ec->local_amount == l0, "and the add undone");
    lsp_channels_update_end(&u);
    uint64_t scn = 0;
    unsigned char stx[32];
    TEST_ASSERT(!persist_channel_is_failed(&n.db, 0), "nothing failed on disk");

    /* The identical commitment is resent, and its record is on disk. */
    lspnet_free(&n);
    TEST_ASSERT(lspnet_init(&n, ctx), "setup 2");
    en = &n.mgr->entries[0];
    lsp_update_t v;
    memset(&v, 0, sizeof(v));
    v.idx = 0;
    v.ch = &en->channel;
    v.chan_id = en->channel_id;
    TEST_ASSERT(lsp_channels_update_sign(n.mgr, n.lsp, &v) &&
                drain_count(n.cli_fd[0], MSG_COMMITMENT_SIGNED) == 1,
                "signed once");
    TEST_ASSERT(persist_load_remote_signed(&n.db, 0, &scn, stx) &&
                scn == en->channel.commitment_number &&
                memcmp(stx, en->signed_txid, 32) == 0, "recorded on disk");
    TEST_ASSERT(lsp_channels_resend_commitment_signed(n.mgr, n.lsp, 0) &&
                drain_count(n.cli_fd[0], MSG_COMMITMENT_SIGNED) == 1,
                "the same commitment resent");
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* The client end of a reconnect: MSG_RECONNECT at cn, then (optionally)
   the client's nonces. */
static int lspnet_reconnect_msgs(pair_t *x, int fd, uint64_t cn, int nonces)
{
    secp256k1_pubkey pk;
    secp256k1_keypair_pub(x->ctx, &pk, &x->cli_kp);
    cJSON *r = wire_build_reconnect(x->ctx, &pk, cn);
    int ok = wire_send(fd, MSG_RECONNECT, r);
    cJSON_Delete(r);
    if (!ok || !nonces) return ok;
    static unsigned char ser[MUSIG_NONCE_POOL_MAX][66];
    if (!channel_init_nonce_pool(&x->cli, MUSIG_NONCE_POOL_MAX)) return 0;
    for (size_t i = 0; i < x->cli.local_nonce_pool.count; i++)
        if (!musig_pubnonce_serialize(x->ctx, ser[i],
                &x->cli.local_nonce_pool.nonces[i].pubnonce))
            return 0;
    cJSON *nm = wire_build_channel_nonces(0, ser, x->cli.local_nonce_pool.count);
    ok = wire_send(fd, MSG_CHANNEL_NONCES, nm);
    cJSON_Delete(nm);
    return ok;
}

static void lspnet_client_pubkeys(lspnet_t *n)
{
    n->lsp->client_pubkeys = calloc(2, sizeof(secp256k1_pubkey));
    secp256k1_keypair_pub(n->s.ctx, &n->lsp->client_pubkeys[0], &n->s.cli_kp);
    /* the payee's client key: any other key */
    unsigned char k[32];
    memset(k, 0x07, 32);
    secp256k1_ec_pubkey_create(n->s.ctx, &n->lsp->client_pubkeys[1], k);
}

/* An MSG_ERROR saying the channel failed (WIRE_ERROR_CHANNEL_FAILED). */
static int is_channel_failed(const wire_msg_t *m)
{
    if (m->msg_type != MSG_ERROR || !m->json) return 0;
    cJSON *s = cJSON_GetObjectItem(m->json, "message");
    return s && cJSON_IsString(s) &&
           strncmp(s->valuestring, WIRE_ERROR_CHANNEL_FAILED,
                   strlen(WIRE_ERROR_CHANNEL_FAILED)) == 0;
}

/* The first message waiting on fd: 1 if it says the channel failed. */
static int got_channel_failed(int fd)
{
    struct pollfd pf = { .fd = fd, .events = POLLIN, .revents = 0 };
    if (poll(&pf, 1, 2000) <= 0) return 0;
    wire_msg_t m;
    if (!wire_recv(fd, &m)) return 0;
    int r = is_channel_failed(&m);
    if (m.json) cJSON_Delete(m.json);
    return r;
}

/* A failed channel that cannot be restored: its client is told so when
   the channel fails and on every reconnect, then disconnected. */
int test_htlc_claim_failed_reconnect_told(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup");
    lspnet_client_pubkeys(&n);
    lsp_channels_fail_channel(n.mgr, n.lsp, 0, "a test failure", 0);
    TEST_ASSERT(got_channel_failed(n.cli_fd[0]), "told when it failed");
    TEST_ASSERT(n.lsp->client_fds[0] < 0, "and disconnected");
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    TEST_ASSERT(lspnet_reconnect_msgs(&n.s, sv[1], 1, 1), "client reconnects");
    TEST_ASSERT(!lsp_channels_handle_reconnect(n.mgr, n.lsp, sv[0]),
                "reconnect not resumed");
    TEST_ASSERT(got_channel_failed(sv[1]), "told again, before any nonces");
    TEST_ASSERT(n.lsp->client_fds[0] < 0, "not reattached");
    close(sv[1]);
    free(n.lsp->client_pubkeys);
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* An honest sender too slow to revoke after a fulfil: its channel fails
   and it is told.  It reconnects with the revocation: the very commitment
   it was waiting on is resent, the valid answer restores the channel, and
   the LSP's own revocation follows. */
int test_htlc_claim_slow_sender_recovers(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup");
    lspnet_client_pubkeys(&n);
    TEST_ASSERT(persist_save_channel(&n.db, &n.mgr->entries[0].channel, 0, 0),
                "sender channel row");
    wire_msg_t msg;
    TEST_ASSERT(payee_fulfils(&n, &msg), "payee fulfils A");
    shutdown(n.cli_fd[0], SHUT_WR);          /* the sender is too slow */
    lsp_channels_handle_msg(n.mgr, n.lsp, 1, &msg);
    cJSON_Delete(msg.json);
    channel_t *sc = &n.mgr->entries[0].channel;
    TEST_ASSERT(sc->revocation_failed && n.mgr->entries[0].fail_recoverable,
                "failed, recoverably");
    TEST_ASSERT(drain_count(n.cli_fd[0], MSG_UPDATE_FULFILL_HTLC) == 1,
                "it had the preimage");
    TEST_ASSERT(sweeper_pending_claims(&n.sw) == 1, "A claimable on 1");

    /* It applied the fulfil (commitment 2) and reconnects with it. */
    TEST_ASSERT(channel_fulfill_htlc(&n.s.cli, n.s.cli_htlc_id, n.s.preimage),
                "sender applies A");
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    TEST_ASSERT(lspnet_reconnect_msgs(&n.s, sv[1], 2, 1) &&
                client_send_raa(&n.s, sv[1], 0, 0),
                "reconnect at 2, nonces, revocation of 1");
    TEST_ASSERT(lsp_channels_handle_reconnect(n.mgr, n.lsp, sv[0]),
                "reconnect resumed");
    TEST_ASSERT(!sc->revocation_failed && !persist_channel_is_failed(&n.db, 0),
                "channel restored, also on disk");
    unsigned char secret[32];
    TEST_ASSERT(channel_get_received_revocation(sc, 1, secret), "1 revoked");
    TEST_ASSERT(sweeper_pending_claims(&n.sw) == 0,
                "claim on 1 retired by the revocation");
    int n_cs = 0, n_rev = 0, n_ack = 0;
    for (;;) {
        struct pollfd pf = { .fd = sv[1], .events = POLLIN, .revents = 0 };
        if (poll(&pf, 1, 0) <= 0) break;
        wire_msg_t m;
        if (!wire_recv(sv[1], &m)) break;
        n_cs += m.msg_type == MSG_COMMITMENT_SIGNED;
        n_rev += m.msg_type == MSG_LSP_REVOKE_AND_ACK;
        n_ack += m.msg_type == MSG_RECONNECT_ACK;
        if (m.json) cJSON_Delete(m.json);
    }
    TEST_ASSERT(n_cs == 1 && n_rev == 1 && n_ack == 1,
                "commitment resent, LSP revocation, reconnect ack");

    /* Without the revocation it stays failed, and says why. */
    lsp_channels_fail_channel(n.mgr, n.lsp, 0, "again", 1);
    TEST_ASSERT(got_channel_failed(sv[1]), "told when it failed again");
    close(sv[1]);
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair 2");
    TEST_ASSERT(lspnet_reconnect_msgs(&n.s, sv[1], 2, 1), "reconnect, mute");
    shutdown(sv[1], SHUT_WR);
    TEST_ASSERT(!lsp_channels_handle_reconnect(n.mgr, n.lsp, sv[0]) &&
                sc->revocation_failed, "stays failed");
    int told = 0;
    for (;;) {
        struct pollfd pf = { .fd = sv[1], .events = POLLIN, .revents = 0 };
        if (poll(&pf, 1, 0) <= 0) break;
        wire_msg_t m;
        if (!wire_recv(sv[1], &m)) break;
        if (is_channel_failed(&m)) told = 1;
        if (m.json) cJSON_Delete(m.json);
    }
    TEST_ASSERT(told, "told why");
    close(sv[1]);
    free(n.lsp->client_pubkeys);
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A client reconnecting one behind a commitment the LSP signed, whose
   previous commitment it never revoked: the channel goes back to the
   commitment the client holds, nothing is failed, and the signed one stays
   the only one that can be signed next.  A fulfil that would sign a
   different commitment 2 is refused before the preimage goes out, and the
   commitment 2 the client may hold is claimed against. */
int test_htlc_claim_reconnect_behind_rolled_back(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup: A on sender commitment 1");
    lspnet_client_pubkeys(&n);
    n.mgr->entries[1].ready = 1;
    TEST_ASSERT(persist_save_channel(&n.db, &n.mgr->entries[0].channel, 0, 0),
                "sender channel row (commitment 1)");
    channel_t *sc = &n.mgr->entries[0].channel;
    unsigned char hx[32];
    memset(hx, 0x5D, 32);
    uint64_t cid;
    TEST_ASSERT(channel_add_htlc(&n.s.cli, HTLC_OFFERED, 3000, hx, 600, &cid),
                "client adds X (its commitment 2)");
    unsigned char old2[32];
    char old2_hex[65];
    TEST_ASSERT(pair_cli_commit(&n.s, old2, old2_hex), "client commitment 2");
    shutdown(n.cli_fd[0], SHUT_WR);
    wire_msg_t add;
    add.msg_type = MSG_UPDATE_ADD_HTLC;
    add.json = wire_build_update_add_htlc(cid, 3000 * 1000, hx, 600);
    cJSON_AddNumberToObject(add.json, "dest_client", 1);
    lsp_channels_handle_msg(n.mgr, n.lsp, 0, &add);
    cJSON_Delete(add.json);
    TEST_ASSERT(sc->commitment_number == 2, "LSP signed commitment 2");

    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    TEST_ASSERT(lspnet_reconnect_msgs(&n.s, sv[1], 1, 1), "reconnect at 1");
    shutdown(sv[1], SHUT_WR);
    TEST_ASSERT(lsp_channels_handle_reconnect(n.mgr, n.lsp, sv[0]),
                "resumed at 1");
    lsp_channel_entry_t *en = &n.mgr->entries[0];
    TEST_ASSERT(!sc->revocation_failed && sc->commitment_number == 1 &&
                en->signed_cn == 2 && en->rolled_back != NULL,
                "rolled back to 1, commitment 2 kept aside, channel open");
    TEST_ASSERT(!persist_channel_is_failed(&n.db, 0), "nothing on disk");

    wire_msg_t msg;
    TEST_ASSERT(payee_fulfils(&n, &msg), "payee fulfils A");
    lsp_channels_handle_msg(n.mgr, n.lsp, 1, &msg);
    cJSON_Delete(msg.json);
    TEST_ASSERT(sc->commitment_number == 1 && !sc->revocation_failed,
                "no other commitment 2 signed");
    TEST_ASSERT(drain_count(sv[1], MSG_UPDATE_FULFILL_HTLC) == 0,
                "preimage not revealed");
    close(sv[1]);
    mk_put(&n.m, old2_hex, 100);
    sweeper_check(&n.sw);
    TEST_ASSERT(n.m.n_sent == 1, "A claimed on the commitment 2 it holds");
    free(n.lsp->client_pubkeys);
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* The HTLC replay on reconnect is an update like any other: the sender's
   commitment it replaces is watched, and a missing revocation stops the
   replay (no next point). */
int test_htlc_claim_replay_watched(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup: A on client 0's commitment 1");
    lspnet_client_pubkeys(&n);
    /* Z, from client 1 to client 0, waits for client 0. */
    unsigned char pre_z[32], hz[32];
    memset(pre_z, 0x73, 32);
    sha256(pre_z, 32, hz);
    uint64_t zid;
    n.mgr->invoices = calloc(4, sizeof(invoice_entry_t));
    n.mgr->invoices_cap = 4;
    TEST_ASSERT(lsp_channels_register_invoice(n.mgr, hz, pre_z, 0, 2000 * 1000) &&
                channel_add_htlc(&n.mgr->entries[1].channel, HTLC_RECEIVED,
                                 2000, hz, 1500, &zid), "Z queued for client 0");
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    TEST_ASSERT(lspnet_reconnect_msgs(&n.s, sv[1], 1, 1), "client 0 reconnects");
    shutdown(sv[1], SHUT_WR);                /* and never revokes 1 */
    n.lsp->factory.n_nodes = 1;              /* a live factory: replay */
    TEST_ASSERT(lsp_channels_handle_reconnect(n.mgr, n.lsp, sv[0]),
                "reconnected");
    n.lsp->factory.n_nodes = 0;
    channel_t *sc = &n.mgr->entries[0].channel;
    TEST_ASSERT(sc->commitment_number == 2 && !sc->revocation_failed,
                "Z replayed on commitment 2, unanswered");

    wire_msg_t msg;
    TEST_ASSERT(payee_fulfils(&n, &msg), "payee fulfils A");
    lsp_channels_handle_msg(n.mgr, n.lsp, 1, &msg);
    cJSON_Delete(msg.json);
    lsp_dump_claims(&n.sw);
    mk_put(&n.m, n.s_commit_hex, 100);       /* client 0 broadcasts 1 */
    sweeper_check(&n.sw);
    TEST_ASSERT(n.m.n_sent == 1, "A claimed on commitment 1");
    close(sv[1]);
    free(n.lsp->client_pubkeys);
    free(n.mgr->invoices);
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Messages waiting on fd, by type (all are read). */
typedef struct { int cs, ful, ack, lsp_rev, failed; } lspnet_seen_t;

static lspnet_seen_t lspnet_seen(int fd)
{
    lspnet_seen_t s = { 0, 0, 0, 0, 0 };
    for (;;) {
        struct pollfd pf = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&pf, 1, 0) <= 0 || !(pf.revents & POLLIN)) break;
        wire_msg_t m;
        if (!wire_recv(fd, &m)) break;
        s.cs += m.msg_type == MSG_COMMITMENT_SIGNED;
        s.ful += m.msg_type == MSG_UPDATE_FULFILL_HTLC;
        s.ack += m.msg_type == MSG_RECONNECT_ACK;
        s.lsp_rev += m.msg_type == MSG_LSP_REVOKE_AND_ACK;
        s.failed += is_channel_failed(&m);
        if (m.json) cJSON_Delete(m.json);
    }
    return s;
}

/* The sender of lspnet_init is too slow to revoke after the back-fulfil
   of A: its channel fails, recoverably, at a signed commitment 2. */
static int lspnet_sender_fails_slow(lspnet_t *n)
{
    wire_msg_t msg;
    if (!persist_save_channel(&n->db, &n->mgr->entries[0].channel, 0, 0) ||
        !payee_fulfils(n, &msg))
        return 0;
    shutdown(n->cli_fd[0], SHUT_WR);
    lsp_channels_handle_msg(n->mgr, n->lsp, 1, &msg);
    cJSON_Delete(msg.json);
    const lsp_channel_entry_t *en = &n->mgr->entries[0];
    return en->channel.revocation_failed && en->fail_recoverable &&
           en->channel.commitment_number == 2 && en->signed_cn == 2;
}

/* An honest sender crashed after the LSP's back-fulfil of A, before it
   stored or revoked anything: its channel failed for want of the
   revocation.  It comes back one behind, at commitment 1, which it never
   revoked.  The LSP rolls back to 1 and settles A again: the very
   commitment 2 it signed is signed again, the sender revokes 1, and the
   channel is restored, also on disk. */
int test_htlc_claim_behind_sender_recovers(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup");
    lspnet_client_pubkeys(&n);
    TEST_ASSERT(lspnet_sender_fails_slow(&n),
                "sender failed recoverably at signed commitment 2");
    lsp_channel_entry_t *en = &n.mgr->entries[0];
    channel_t *sc = &en->channel;
    unsigned char signed2[32];
    memcpy(signed2, en->signed_txid, 32);
    TEST_ASSERT(persist_channel_is_failed(&n.db, 0), "failure on disk");

    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    TEST_ASSERT(lspnet_reconnect_msgs(&n.s, sv[1], 1, 1),
                "it reconnects at 1, with nonces");
    TEST_ASSERT(channel_fulfill_htlc(&n.s.cli, n.s.cli_htlc_id, n.s.preimage) &&
                client_send_raa(&n.s, sv[1], 0, 0),
                "and revokes 1 once A is settled again");
    TEST_ASSERT(lsp_channels_handle_reconnect(n.mgr, n.lsp, sv[0]),
                "reconnect resumed");
    TEST_ASSERT(!sc->revocation_failed && !persist_channel_is_failed(&n.db, 0),
                "channel restored, also on disk");
    TEST_ASSERT(sc->commitment_number == 2 && en->signed_cn == 2 &&
                memcmp(en->signed_txid, signed2, 32) == 0 && !en->rolled_back,
                "the same commitment 2 signed again");
    unsigned char secret[32];
    TEST_ASSERT(channel_get_received_revocation(sc, 1, secret), "1 revoked");
    lspnet_seen_t s = lspnet_seen(sv[1]);
    TEST_ASSERT(s.ack == 1 && s.ful == 1 && s.cs == 1 && s.lsp_rev == 1 &&
                s.failed == 0,
                "ack, A's fulfil, commitment 2, LSP revocation; no close");
    close(sv[1]);
    free(n.lsp->client_pubkeys);
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* While an honest sender's revocation is outstanding (it holds commitment
   2, not yet revoked 1), someone who knows only its public key reconnects
   "one behind" and goes silent.  The LSP rolls back to 1 in memory, but
   fails nothing and writes nothing; when the sender reconnects with
   commitment 2, that commitment is restored and resent, and the sender's
   revocation of 1 is taken as usual. */
int test_htlc_claim_spoofed_reconnect_restored(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup");
    lspnet_client_pubkeys(&n);
    n.mgr->entries[1].ready = 1;
    TEST_ASSERT(persist_save_channel(&n.db, &n.mgr->entries[0].channel, 0, 0),
                "sender channel row");
    lsp_channel_entry_t *en = &n.mgr->entries[0];
    channel_t *sc = &en->channel;
    unsigned char hx[32];
    memset(hx, 0x5E, 32);
    uint64_t cid;
    TEST_ASSERT(channel_add_htlc(&n.s.cli, HTLC_OFFERED, 3000, hx, 600, &cid),
                "sender adds X (its commitment 2)");
    shutdown(n.cli_fd[0], SHUT_WR);          /* its answer is late */
    wire_msg_t add;
    add.msg_type = MSG_UPDATE_ADD_HTLC;
    add.json = wire_build_update_add_htlc(cid, 3000 * 1000, hx, 600);
    cJSON_AddNumberToObject(add.json, "dest_client", 1);
    lsp_channels_handle_msg(n.mgr, n.lsp, 0, &add);
    cJSON_Delete(add.json);
    TEST_ASSERT(sc->commitment_number == 2 && !sc->revocation_failed &&
                en->pending_revoke, "commitment 2 signed, revocation of 1 due");
    unsigned char signed2[32];
    memcpy(signed2, en->signed_txid, 32);

    int a[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, a) == 0, "socketpair");
    TEST_ASSERT(lspnet_reconnect_msgs(&n.s, a[1], 1, 0),
                "an impostor reconnects at 1");
    shutdown(a[1], SHUT_WR);
    lsp_channels_handle_reconnect(n.mgr, n.lsp, a[0]);
    close(a[1]);
    uint64_t scn = 0;
    unsigned char stx[32];
    TEST_ASSERT(!sc->revocation_failed && !persist_channel_is_failed(&n.db, 0),
                "nothing failed, in memory or on disk");
    TEST_ASSERT(persist_load_remote_signed(&n.db, 0, &scn, stx) && scn == 2 &&
                memcmp(stx, signed2, 32) == 0, "signed record unchanged");
    TEST_ASSERT(lspnet_seen(n.cli_fd[0]).failed == 0,
                "the sender is not told to close");

    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair 2");
    TEST_ASSERT(lspnet_reconnect_msgs(&n.s, sv[1], 2, 1) &&
                client_send_raa(&n.s, sv[1], 0, 0),
                "the sender reconnects at 2 and revokes 1");
    TEST_ASSERT(lsp_channels_handle_reconnect(n.mgr, n.lsp, sv[0]),
                "reconnect resumed");
    TEST_ASSERT(sc->commitment_number == 2 && !sc->revocation_failed &&
                !en->rolled_back && memcmp(en->signed_txid, signed2, 32) == 0,
                "commitment 2 restored");
    unsigned char secret[32];
    TEST_ASSERT(channel_get_received_revocation(sc, 1, secret), "1 revoked");
    lspnet_seen_t s = lspnet_seen(sv[1]);
    TEST_ASSERT(s.cs == 1 && s.ack == 1 && s.failed == 0,
                "commitment 2 resent, reconnect ack, no close");
    close(sv[1]);
    free(n.lsp->client_pubkeys);
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* One honest update on the sender channel: the payee fulfils, the sender
   revokes.  Afterwards the LSP has signed sender commitment 2. */
static int lspnet_honest_round(lspnet_t *n)
{
    wire_msg_t msg;
    if (!payee_fulfils(n, &msg)) return 0;
    if (!channel_fulfill_htlc(&n->s.cli, n->s.cli_htlc_id, n->s.preimage) ||
        !client_send_raa(&n->s, n->cli_fd[0], 0, 0))
        return 0;
    lsp_channels_handle_msg(n->mgr, n->lsp, 1, &msg);
    cJSON_Delete(msg.json);
    drain_count(n->cli_fd[0], MSG_UPDATE_FULFILL_HTLC);
    return 1;
}

/* MSG_RECONNECT carries only a public key and a commitment number.  A
   third party that knows an honest, connected client's public key cannot
   get that client's channel failed (or the client told to close it) by
   reconnecting behind it. */
int test_htlc_claim_spoofed_reconnect_keeps_channel(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup");
    lspnet_client_pubkeys(&n);
    TEST_ASSERT(persist_save_channel(&n.db, &n.mgr->entries[0].channel, 0, 0),
                "sender channel row");
    TEST_ASSERT(lspnet_honest_round(&n), "honest update");
    lsp_channel_entry_t *en = &n.mgr->entries[0];
    TEST_ASSERT(en->channel.commitment_number == 2 && en->has_signed &&
                en->signed_cn == 2 && !en->channel.revocation_failed,
                "sender at signed commitment 2, open");
    int fd0 = n.lsp->client_fds[0];

    for (uint64_t cn = 0; cn < 2; cn++) {
        int sv[2];
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
        TEST_ASSERT(lspnet_reconnect_msgs(&n.s, sv[1], cn, 0), "reconnect msg");
        TEST_ASSERT(!lsp_channels_handle_reconnect(n.mgr, n.lsp, sv[0]),
                    "refused");
        close(sv[1]);
    }
    TEST_ASSERT(!en->channel.revocation_failed &&
                !persist_channel_is_failed(&n.db, 0) &&
                en->channel.commitment_number == 2,
                "honest channel not failed, not rolled back");
    TEST_ASSERT(n.lsp->client_fds[0] == fd0, "its connection kept");
    TEST_ASSERT(!got_channel_failed(n.cli_fd[0]),
                "honest client not told to close its channel");
    free(n.lsp->client_pubkeys);
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A recoverably failed channel resumes only at the commitment it failed
   at (or one behind it, rolled back): a reconnect at any other number is
   told the channel failed and changes nothing. */
int test_htlc_claim_failed_reconnect_other_cn_told(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup");
    lspnet_client_pubkeys(&n);
    TEST_ASSERT(lspnet_sender_fails_slow(&n), "sender failed at 2");
    channel_t *sc = &n.mgr->entries[0].channel;
    TEST_ASSERT(channel_fulfill_htlc(&n.s.cli, n.s.cli_htlc_id, n.s.preimage),
                "sender applies A");
    const uint64_t other[2] = { 3, 0 };
    for (int k = 0; k < 2; k++) {
        int sv[2];
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
        TEST_ASSERT(lspnet_reconnect_msgs(&n.s, sv[1], other[k], 1) &&
                    client_send_raa(&n.s, sv[1], 0, 0), "reconnect elsewhere");
        TEST_ASSERT(!lsp_channels_handle_reconnect(n.mgr, n.lsp, sv[0]),
                    "not resumed");
        TEST_ASSERT(got_channel_failed(sv[1]), "told the channel failed");
        TEST_ASSERT(sc->revocation_failed && sc->commitment_number == 2 &&
                    n.lsp->client_fds[0] < 0, "still failed, at 2, detached");
        close(sv[1]);
    }
    free(n.lsp->client_pubkeys);
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A late revocation after a restart, when what the revoked commitment held
   is no longer known: the channel is restored, but the commitment cannot
   go to the watchtower, so its HTLC claims stay. */
int test_htlc_claim_late_revocation_keeps_claims(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup");
    lspnet_client_pubkeys(&n);
    TEST_ASSERT(lspnet_sender_fails_slow(&n), "sender failed at 2");
    TEST_ASSERT(sweeper_pending_claims(&n.sw) == 1, "A claimable on 1");
    lsp_channels_drop_pending_updates(n.mgr);    /* as a restart does */
    TEST_ASSERT(channel_fulfill_htlc(&n.s.cli, n.s.cli_htlc_id, n.s.preimage),
                "sender applies A");
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    TEST_ASSERT(lspnet_reconnect_msgs(&n.s, sv[1], 2, 1) &&
                client_send_raa(&n.s, sv[1], 0, 0),
                "reconnect at 2, nonces, revocation of 1");
    TEST_ASSERT(lsp_channels_handle_reconnect(n.mgr, n.lsp, sv[0]),
                "reconnect resumed");
    channel_t *sc = &n.mgr->entries[0].channel;
    unsigned char secret[32];
    TEST_ASSERT(!sc->revocation_failed &&
                channel_get_received_revocation(sc, 1, secret),
                "restored, 1 revoked");
    TEST_ASSERT(sweeper_pending_claims(&n.sw) == 1,
                "the claim on 1 kept: 1 is not with the watchtower");
    close(sv[1]);
    free(n.lsp->client_pubkeys);
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Securing a preimage on a channel that cannot be updated watches its
   current commitment too: every HTLC the client offered there (B as well
   as A) is then claimed once its preimage is learned. */
int test_htlc_claim_secure_watches_commitment(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup");
    unsigned char pre_b[32], hb[32];
    TEST_ASSERT(lspnet_add_second(&n, pre_b), "A and B on sender commitment 2");
    sha256(pre_b, 32, hb);
    lsp_channels_fail_channel(n.mgr, n.lsp, 0, "a test failure", 0);
    TEST_ASSERT(lsp_channels_settle_received(n.mgr, n.lsp, 0, n.s.lsp_htlc_id,
                                             n.s.preimage), "A secured");
    int watch_b = 0;
    for (size_t i = 0; i < n.sw.n_entries; i++) {
        const sweep_entry_t *e = &n.sw.entries[i];
        int armed = 0;
        for (size_t k = 0; k < 32; k++) armed |= e->preimage[k];
        if (e->type == SWEEP_HTLC_SUCCESS && e->channel_id == 0 &&
            e->commitment_number == 2 && !armed &&
            memcmp(e->payment_hash, hb, 32) == 0)
            watch_b = 1;
    }
    TEST_ASSERT(watch_b, "B watched on commitment 2");
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* The daemon pings every client every 30 s and clients answer PONG.  A
   PONG that reaches the LSP just before the sender's valid revoke_and_ack
   (sender leg of a fulfil) does not fail the channel. */
int test_htlc_claim_pong_before_raa_keeps_sender(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup");
    wire_msg_t msg;
    TEST_ASSERT(payee_fulfils(&n, &msg), "payee fulfils A");
    cJSON *pong = cJSON_CreateObject();
    TEST_ASSERT(wire_send(n.cli_fd[0], MSG_PONG, pong), "sender PONG queued");
    cJSON_Delete(pong);
    TEST_ASSERT(channel_fulfill_htlc(&n.s.cli, n.s.cli_htlc_id, n.s.preimage) &&
                client_send_raa(&n.s, n.cli_fd[0], 0, 0),
                "then its valid revocation");
    lsp_channels_handle_msg(n.mgr, n.lsp, 1, &msg);
    cJSON_Delete(msg.json);
    channel_t *sc = &n.mgr->entries[0].channel;
    unsigned char secret[32];
    TEST_ASSERT(!sc->revocation_failed, "honest sender not failed");
    TEST_ASSERT(channel_get_received_revocation(sc, 1, secret),
                "its revocation taken");
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A benign message a client may send at any time (kind 0 PONG, 1
   QUEUE_POLL, 2 REGISTER_INVOICE). */
static int send_stray(lspnet_t *n, int fd, int kind)
{
    static const uint8_t type[3] = { MSG_PONG, MSG_QUEUE_POLL,
                                     MSG_REGISTER_INVOICE };
    cJSON *j;
    if (kind == 2) {
        unsigned char pre[32], h[32];
        memset(pre, 0x61 + kind, 32);
        sha256(pre, 32, h);
        j = wire_build_register_invoice(h, pre, 1000 * 1000, 0);
    } else {
        j = cJSON_CreateObject();
    }
    (void)n;
    int ok = j && wire_send(fd, type[kind], j);
    if (j) cJSON_Delete(j);
    return ok;
}

static int lspnet_invoices(lspnet_t *n)
{
    n->mgr->invoices = calloc(8, sizeof(invoice_entry_t));
    n->mgr->invoices_cap = 8;
    return n->mgr->invoices != NULL;
}

/* Every wait for a client's revoke_and_ack drains the benign messages the
   client may send meanwhile, so an honest client is never failed (or its
   revocation lost) for a PONG, QUEUE_POLL or REGISTER_INVOICE sent just
   before it: the sender leg of a fulfil, the commitment resent on
   reconnect, a bridge HTLC's destination and a profit settlement. */
int test_htlc_claim_strays_before_raa(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char secret[32];
    for (int kind = 0; kind < 3; kind++) {
        lspnet_t n;
        wire_msg_t msg;

        /* Sender leg of a fulfil. */
        TEST_ASSERT(lspnet_init(&n, ctx) && lspnet_invoices(&n), "setup");
        TEST_ASSERT(payee_fulfils(&n, &msg), "payee fulfils A");
        TEST_ASSERT(send_stray(&n, n.cli_fd[0], kind) &&
                    channel_fulfill_htlc(&n.s.cli, n.s.cli_htlc_id,
                                         n.s.preimage) &&
                    client_send_raa(&n.s, n.cli_fd[0], 0, 0),
                    "sender: a stray, then its revocation");
        lsp_channels_handle_msg(n.mgr, n.lsp, 1, &msg);
        cJSON_Delete(msg.json);
        TEST_ASSERT(!n.mgr->entries[0].channel.revocation_failed &&
                    channel_get_received_revocation(&n.mgr->entries[0].channel,
                                                    1, secret),
                    "fulfil: sender revoked 1, not failed");
        free(n.mgr->invoices);
        lspnet_free(&n);

        /* The commitment resent on reconnect. */
        TEST_ASSERT(lspnet_init(&n, ctx) && lspnet_invoices(&n), "setup 2");
        lspnet_client_pubkeys(&n);
        TEST_ASSERT(lspnet_sender_fails_slow(&n), "sender failed at 2");
        TEST_ASSERT(channel_fulfill_htlc(&n.s.cli, n.s.cli_htlc_id,
                                         n.s.preimage), "sender applies A");
        int sv[2];
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
        TEST_ASSERT(lspnet_reconnect_msgs(&n.s, sv[1], 2, 1) &&
                    send_stray(&n, sv[1], kind) &&
                    client_send_raa(&n.s, sv[1], 0, 0),
                    "reconnect at 2, a stray, then the revocation");
        TEST_ASSERT(lsp_channels_handle_reconnect(n.mgr, n.lsp, sv[0]) &&
                    !n.mgr->entries[0].channel.revocation_failed,
                    "reconnect: channel restored");
        close(sv[1]);
        free(n.lsp->client_pubkeys);
        free(n.mgr->invoices);
        lspnet_free(&n);

        /* A bridge HTLC's destination. */
        TEST_ASSERT(lspnet_init(&n, ctx) && lspnet_invoices(&n), "setup 3");
        unsigned char pre_z[32], hz[32];
        memset(pre_z, 0x72, 32);
        sha256(pre_z, 32, hz);
        uint64_t zid;
        TEST_ASSERT(lsp_channels_register_invoice(n.mgr, hz, pre_z, 1,
                                                  5000 * 1000) &&
                    channel_add_htlc(&n.p.cli, HTLC_RECEIVED, 5000, hz, 1500,
                                     &zid),
                    "invoice of client 1, which applies the add");
        TEST_ASSERT(send_stray(&n, n.cli_fd[1], kind) &&
                    client_send_raa(&n.p, n.cli_fd[1], 1, 0),
                    "client 1: a stray, then its revocation");
        msg.msg_type = MSG_BRIDGE_ADD_HTLC;
        msg.json = wire_build_bridge_add_htlc(hz, 5000 * 1000, 1500, 77);
        lsp_channels_handle_bridge_msg(n.mgr, n.lsp, &msg);
        cJSON_Delete(msg.json);
        TEST_ASSERT(!n.mgr->entries[1].channel.revocation_failed &&
                    channel_get_received_revocation(&n.mgr->entries[1].channel,
                                                    1, secret),
                    "bridge: client 1 revoked 1");
        free(n.mgr->invoices);
        free(n.mgr->htlc_origins);
        lspnet_free(&n);

        /* A profit settlement. */
        TEST_ASSERT(lspnet_init(&n, ctx) && lspnet_invoices(&n), "setup 4");
        static factory_t f;
        static participant_profile_t prof[3];
        memset(&f, 0, sizeof(f));
        memset(prof, 0, sizeof(prof));
        prof[1].profit_share_bps = 5000;
        f.n_participants = 3;
        f.profiles = prof;
        f.cltv_timeout = 1000;
        n.mgr->economic_mode = ECON_PROFIT_SHARED;
        n.mgr->accumulated_fees_sats = 2000;
        n.mgr->entries[0].accumulated_fees_sats = 2000;
        unsigned char dh[32];
        memset(dh, 0x11, 32);
        uint64_t cid;
        TEST_ASSERT(channel_add_htlc(&n.s.cli, HTLC_RECEIVED, 1000, dh, 500,
                                     &cid) &&
                    send_stray(&n, n.cli_fd[0], kind) &&
                    client_send_raa(&n.s, n.cli_fd[0], 0, 0),
                    "client: the settlement add, a stray, its revocation");
        shutdown(n.cli_fd[0], SHUT_WR);
        lsp_channels_settle_via_payment(n.mgr, n.lsp, &f);
        TEST_ASSERT(!n.mgr->entries[0].channel.revocation_failed &&
                    channel_get_received_revocation(&n.mgr->entries[0].channel,
                                                    1, secret),
                    "settlement: client revoked 1");
        free(n.mgr->invoices);
        lspnet_free(&n);
    }
    secp256k1_context_destroy(ctx);
    return 1;
}

/* No LSP revocation is ever sent on a failed channel. */
int test_htlc_claim_failed_no_lsp_revocation(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup");
    lsp_send_revocation(n.mgr, n.lsp, 0, 0);
    TEST_ASSERT(drain_count(n.cli_fd[0], MSG_LSP_REVOKE_AND_ACK) == 1,
                "sent on an open channel");
    lsp_channels_fail_channel(n.mgr, NULL, 0, "a test failure", 0);
    lsp_send_revocation(n.mgr, n.lsp, 0, 0);
    TEST_ASSERT(drain_count(n.cli_fd[0], MSG_LSP_REVOKE_AND_ACK) == 0,
                "not on a failed one");
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* The failed mark needs no channels row, keeps whether it can be cleared,
   and survives reopening the database. */
int test_htlc_claim_failed_mark_without_row(void)
{
    char path[] = "/tmp/ss_htlc_failmark_XXXXXX";
    int fd = mkstemp(path);
    TEST_ASSERT(fd >= 0, "temp db");
    close(fd);
    persist_t db;
    TEST_ASSERT(persist_open(&db, path), "open");
    int rec = -1;
    TEST_ASSERT(!persist_channel_failure(&db, 7, &rec) && rec == 0, "not failed");
    TEST_ASSERT(persist_mark_channel_failed(&db, 7, "no revocation", 1) &&
                persist_mark_channel_failed(&db, 8, "conflict", 0),
                "marked, no channels rows");
    persist_close(&db);
    TEST_ASSERT(persist_open(&db, path), "reopen");
    TEST_ASSERT(persist_channel_failure(&db, 7, &rec) && rec == 1,
                "7 failed, recoverable");
    TEST_ASSERT(persist_channel_failure(&db, 8, &rec) && rec == 0,
                "8 failed, not recoverable");
    TEST_ASSERT(persist_clear_channel_failed(&db, 7) &&
                !persist_channel_is_failed(&db, 7) &&
                persist_channel_is_failed(&db, 8), "7 cleared");
    persist_close(&db);
    unlink(path);
    return 1;
}

/* When no claim can be armed (here: inside a transaction), the preimage
   is kept on disk, the channel fails, and the retry arms the claim. */
int test_htlc_claim_unarmed_preimage_kept(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    TEST_ASSERT(lspnet_init(&n, ctx), "setup");
    TEST_ASSERT(persist_begin(&n.db), "open a transaction");
    TEST_ASSERT(!lsp_channels_settle_received(n.mgr, n.lsp, 0, n.s.lsp_htlc_id,
                                              n.s.preimage),
                "not settled: no claim could be armed");
    TEST_ASSERT(persist_commit(&n.db), "commit");
    TEST_ASSERT(n.mgr->entries[0].channel.revocation_failed &&
                !n.mgr->entries[0].fail_recoverable, "channel failed");
    TEST_ASSERT(drain_count(n.cli_fd[0], MSG_UPDATE_FULFILL_HTLC) == 0,
                "preimage not revealed");
    uint32_t ch[4];
    uint64_t id[4];
    unsigned char pre[4][32];
    TEST_ASSERT(persist_load_pending_preimages(&n.db, ch, id, pre, 4) == 1 &&
                ch[0] == 0 && id[0] == n.s.lsp_htlc_id &&
                memcmp(pre[0], n.s.preimage, 32) == 0, "preimage on disk");
    TEST_ASSERT(sweeper_pending_claims(&n.sw) == 0, "no claim yet");
    lsp_channels_retry_pending_preimages(n.mgr);
    TEST_ASSERT(sweeper_pending_claims(&n.sw) == 1, "claim armed on retry");
    TEST_ASSERT(persist_load_pending_preimages(&n.db, ch, id, pre, 4) == 0,
                "and the stored preimage dropped");
    mk_put(&n.m, n.s_commit_hex, 100);
    sweeper_check(&n.sw);
    TEST_ASSERT(n.m.n_sent == 1, "claimed");
    lspnet_free(&n);

    /* A bridge pay result whose claim cannot be armed keeps its origin. */
    TEST_ASSERT(lspnet_init(&n, ctx), "setup 2");
    htlc_origin_t origin;
    memset(&origin, 0, sizeof(origin));
    memcpy(origin.payment_hash, n.s.hash, 32);
    origin.request_id = 5;
    origin.sender_idx = 0;
    origin.sender_htlc_id = n.s.lsp_htlc_id;
    origin.active = 1;
    n.mgr->htlc_origins = &origin;
    n.mgr->n_htlc_origins = 1;
    wire_msg_t pr;
    pr.msg_type = MSG_BRIDGE_PAY_RESULT;
    pr.json = wire_build_bridge_pay_result(5, 1, n.s.preimage);
    TEST_ASSERT(persist_begin(&n.db), "open a transaction 2");
    lsp_channels_handle_bridge_msg(n.mgr, n.lsp, &pr);
    TEST_ASSERT(persist_commit(&n.db), "commit 2");
    cJSON_Delete(pr.json);
    TEST_ASSERT(origin.active, "origin kept: the HTLC is not claimable yet");
    lsp_channels_retry_pending_preimages(n.mgr);
    TEST_ASSERT(!origin.active && sweeper_pending_claims(&n.sw) == 1,
                "retired once the retry armed the claim");
    n.mgr->htlc_origins = NULL;
    n.mgr->n_htlc_origins = 0;
    lspnet_free(&n);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* A failed channel does not hold back rotation of the others. */
int test_htlc_claim_failed_rotation_ready(void)
{
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    lsp_channel_entry_t en[3];
    memset(en, 0, sizeof(en));
    mgr.entries = en;
    mgr.n_channels = 3;
    readiness_tracker_t rt;
    readiness_init(&rt, 0, 3, NULL);
    mgr.readiness = &rt;
    readiness_set_connected(&rt, 0, 1);
    readiness_set_ready(&rt, 0, 1);
    readiness_set_connected(&rt, 1, 1);
    readiness_set_ready(&rt, 1, 1);
    TEST_ASSERT(!lsp_rotation_clients_ready(&mgr), "client 2 not ready");
    en[2].channel.revocation_failed = CHANNEL_FAILED_DURABLE;
    TEST_ASSERT(lsp_rotation_clients_ready(&mgr),
                "client 2's channel failed: it stays, the others rotate");
    en[0].channel.revocation_failed = CHANNEL_FAILED_DURABLE;
    en[1].channel.revocation_failed = CHANNEL_FAILED_DURABLE;
    TEST_ASSERT(!lsp_rotation_clients_ready(&mgr), "nobody left to rotate");
    return 1;
}

/* ---- The bridge during a client update ---- */

/* A bridge pay result read while the payee leg of a fulfil waits for its
   revocation is not handled inside that update: its claim is armed at
   once, and the result is handled afterwards.  The sender never revokes:
   B, paid out through the bridge, must be claimable on whichever of its
   commitments the sender broadcasts. */
int test_htlc_claim_bridge_result_during_payee_wait(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    unsigned char pre_b[32];
    TEST_ASSERT(lspnet_init(&n, ctx) && lspnet_add_second(&n, pre_b),
                "sender: A (intra-factory) and B (paid out via bridge)");
    htlc_origin_t *origin = calloc(1, sizeof(*origin));
    TEST_ASSERT(origin != NULL, "origin");
    sha256(pre_b, 32, origin->payment_hash);
    origin->request_id = 9;
    origin->sender_idx = 0;
    origin->sender_htlc_id = n.s.lsp_htlc_id + 1;
    origin->active = 1;
    n.mgr->htlc_origins = origin;
    n.mgr->n_htlc_origins = 1;
    int bsv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, bsv) == 0, "bridge pair");
    n.mgr->bridge_fd = bsv[0];
    cJSON *pr = wire_build_bridge_pay_result(9, 1, pre_b);
    TEST_ASSERT(wire_send(bsv[1], MSG_BRIDGE_PAY_RESULT, pr), "pay result queued");
    cJSON_Delete(pr);
    shutdown(n.cli_fd[0], SHUT_WR);          /* sender never revokes */

    wire_msg_t msg;
    TEST_ASSERT(payee_fulfils(&n, &msg), "payee fulfils A");
    lsp_channels_handle_msg(n.mgr, n.lsp, 1, &msg);
    cJSON_Delete(msg.json);
    TEST_ASSERT(origin->active && n.mgr->n_deferred_bridge == 1,
                "pay result queued, origin kept");
    lsp_dump_claims(&n.sw);
    TEST_ASSERT(channel_fulfill_htlc(&n.s.cli, n.s.cli_htlc_id, n.s.preimage),
                "sender applies A");
    unsigned char c3[32];
    char c3_hex[65];
    TEST_ASSERT(pair_cli_commit(&n.s, c3, c3_hex), "commitment 3 (B only)");
    mk_put(&n.m, c3_hex, 100);
    sweeper_check(&n.sw);
    TEST_ASSERT(n.m.n_sent == 1, "B claimed on commitment 3");

    lsp_channels_drain_deferred_bridge(n.mgr, n.lsp);
    TEST_ASSERT(!origin->active && n.mgr->n_deferred_bridge == 0,
                "handled afterwards: origin retired once B is claimable");
    TEST_ASSERT(drain_count(n.cli_fd[0], MSG_UPDATE_FULFILL_HTLC) == 1,
                "only A's preimage went to the failed sender");
    n.mgr->bridge_fd = -1;
    close(bsv[0]);
    close(bsv[1]);
    lspnet_free(&n);
    free(origin);
    secp256k1_context_destroy(ctx);
    return 1;
}

#include <pthread.h>
static int g_bridge_wfd;
static unsigned char g_bridge_pre[32];
static void *late_pay_result(void *arg)
{
    (void)arg;
    sleep(2);       /* after the payee leg: inside the sender's wait */
    cJSON *pr = wire_build_bridge_pay_result(9, 1, g_bridge_pre);
    wire_send(g_bridge_wfd, MSG_BRIDGE_PAY_RESULT, pr);
    cJSON_Delete(pr);
    return NULL;
}

/* Same, but the pay result arrives while the fulfil waits for the
   sender's own revocation (which never comes). */
int test_htlc_claim_bridge_result_during_sender_wait(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    lspnet_t n;
    unsigned char pre_b[32];
    TEST_ASSERT(lspnet_init(&n, ctx) && lspnet_add_second(&n, pre_b),
                "sender: A (intra-factory) and B (paid out via bridge)");
    htlc_origin_t *origin = calloc(1, sizeof(*origin));
    TEST_ASSERT(origin != NULL, "origin");
    sha256(pre_b, 32, origin->payment_hash);
    origin->request_id = 9;
    origin->sender_idx = 0;
    origin->sender_htlc_id = n.s.lsp_htlc_id + 1;
    origin->active = 1;
    n.mgr->htlc_origins = origin;
    n.mgr->n_htlc_origins = 1;
    int bsv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, bsv) == 0, "bridge pair");
    n.mgr->bridge_fd = bsv[0];
    g_bridge_wfd = bsv[1];
    memcpy(g_bridge_pre, pre_b, 32);
    pthread_t th;
    TEST_ASSERT(pthread_create(&th, NULL, late_pay_result, NULL) == 0, "thread");
    wire_msg_t msg;
    TEST_ASSERT(payee_fulfils(&n, &msg), "payee fulfils A");
    lsp_channels_handle_msg(n.mgr, n.lsp, 1, &msg);   /* ~30 s: sender mute */
    cJSON_Delete(msg.json);
    pthread_join(th, NULL);
    TEST_ASSERT(origin->active && n.mgr->n_deferred_bridge == 1,
                "pay result queued, origin kept");
    lsp_dump_claims(&n.sw);
    TEST_ASSERT(channel_fulfill_htlc(&n.s.cli, n.s.cli_htlc_id, n.s.preimage),
                "sender applies A");
    unsigned char c3[32];
    char c3_hex[65];
    TEST_ASSERT(pair_cli_commit(&n.s, c3, c3_hex), "commitment 3 (B only)");
    mk_put(&n.m, c3_hex, 100);
    sweeper_check(&n.sw);
    TEST_ASSERT(n.m.n_sent == 1, "B claimed on commitment 3");
    lsp_channels_drain_deferred_bridge(n.mgr, n.lsp);
    TEST_ASSERT(!origin->active, "origin retired once B is claimable");
    n.mgr->bridge_fd = -1;
    close(bsv[0]);
    close(bsv[1]);
    lspnet_free(&n);
    free(origin);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* An LSP claim on commitment 1, superseded by commitment 2 confirming,
   survives a one-block reorg that mines 1 instead. */
int test_htlc_claim_lsp_sibling_reorg(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init");
    TEST_ASSERT(pair_add_htlc(&p, 1, 7000, 600), "A on 1");
    unsigned char c1[32];
    char c1_hex[65];
    TEST_ASSERT(pair_cli_commit(&p, c1, c1_hex), "commitment 1");
    lsp_channel_mgr_t *mgr = calloc(1, sizeof(*mgr));
    TEST_ASSERT(mgr != NULL, "mgr");
    mgr->entries = calloc(1, sizeof(lsp_channel_entry_t));
    TEST_ASSERT(mgr->entries != NULL, "entries");
    mgr->n_channels = 1;
    mgr->entries[0].channel = p.lsp;
    channel_t *lch = &mgr->entries[0].channel;
    mock_chain_t m;
    mock_init(&m, 100);
    sweeper_t sw;
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, NULL, NULL), "sw");
    lsp_channels_attach_sweeper(mgr, &sw);
    TEST_ASSERT(lsp_channels_watch_commitment(mgr, 0), "watch 1");
    unsigned char hb[32];
    memset(hb, 0x4B, 32);
    uint64_t i1, i2;
    TEST_ASSERT(channel_add_htlc(lch, HTLC_RECEIVED, 5000, hb, 600, &i1) &&
                channel_add_htlc(&p.cli, HTLC_OFFERED, 5000, hb, 600, &i2),
                "B: 2");
    TEST_ASSERT(pair_send_pcp(&p, 2), "pcp 2");
    {
        secp256k1_pubkey pt;
        channel_get_per_commitment_point(&p.cli, 2, &pt);
        channel_set_remote_pcp(lch, 2, &pt);
    }
    unsigned char c2[32];
    char c2_hex[65];
    TEST_ASSERT(pair_cli_commit(&p, c2, c2_hex), "commitment 2");
    TEST_ASSERT(lsp_channels_register_htlc_claim(mgr, 0, p.lsp_htlc_id,
                p.preimage) == 1, "A armed on 2 and on 1");
    mk_put(&m, c2_hex, 100);                 /* 2 mined (1 conf) */
    sweeper_check(&sw);
    sweeper_check(&sw);
    mk_forget(&m, c2_hex);                   /* one-block reorg: 1 instead */
    m.n_spent = 0;
    mk_put(&m, c1_hex, 100);
    sweeper_check(&sw);
    sweeper_check(&sw);
    int covers1 = 0;
    for (size_t i = 0; i < sw.n_entries; i++)
        if (memcmp(sw.entries[i].source_txid, c1, 32) == 0) covers1 = 1;
    TEST_ASSERT(covers1, "claim on 1 still there after the reorg");
    sweeper_cleanup(&sw);
    free(mgr->entries);
    free(mgr);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* LSP forwarding A -> B: when B's preimage arrives, the claim is armed on
   the sender A's channel (against A's commitment) and not on B's. */
int test_htlc_claim_lsp_sender_selection(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    static const unsigned char FUND_B[32] = { [0 ... 31] = 0x22 };
    pair_t a, b;
    TEST_ASSERT(pair_init(&a, ctx, UNIT_FUND_TXID, 0, 100000, 10), "init A");
    TEST_ASSERT(pair_init(&b, ctx, FUND_B, 0, 100000, 10), "init B");
    TEST_ASSERT(pair_add_htlc(&a, 1, 7000, 600), "A pays LSP");
    TEST_ASSERT(pair_add_htlc(&b, 0, 7000, 560), "LSP pays B");

    lsp_channel_mgr_t *mgr = calloc(1, sizeof(*mgr));
    TEST_ASSERT(mgr != NULL, "mgr");
    mgr->entries = calloc(2, sizeof(lsp_channel_entry_t));
    TEST_ASSERT(mgr->entries != NULL, "entries");
    mgr->n_channels = 2;
    mgr->entries[0].channel = a.lsp;
    mgr->entries[1].channel = b.lsp;

    TEST_ASSERT(lsp_channels_register_sender_claims(mgr, 1, a.preimage) == 0,
                "no sweeper attached: nothing registered");

    mock_chain_t m;
    mock_init(&m, 100);
    sweeper_t sw;
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &m.base, NULL, NULL),
                "sweeper");
    TEST_ASSERT(lsp_channels_attach_sweeper(mgr, &sw), "attach");
    TEST_ASSERT(lsp_channels_register_sender_claims(mgr, 1, a.preimage) == 1,
                "one sender claim");
    TEST_ASSERT(sw.n_entries == 1 && sw.entries[0].channel_id == 0 &&
                sw.entries[0].claim_side == HTLC_CLAIM_REMOTE_COMMIT,
                "armed on the sender's channel, against its commitment");
    unsigned char a_txid[32];
    tx_buf_t ac;
    tx_buf_init(&ac, 1024);
    TEST_ASSERT(channel_build_commitment_tx(&a.cli, &ac, a_txid), "A commit");
    tx_buf_free(&ac);
    TEST_ASSERT(memcmp(sw.entries[0].source_txid, a_txid, 32) == 0,
                "source = the commitment the sender holds signed");
    TEST_ASSERT(sw.get_channel(sw.get_channel_arg, 0) ==
                &mgr->entries[0].channel, "lookup resolves the LSP channel");

    sweeper_cleanup(&sw);
    free(mgr->entries);
    free(mgr);
    pair_cleanup(&a);
    pair_cleanup(&b);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Regtest drills                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    regtest_t rt;
    chain_backend_t chain;
    char mine_addr[128];
    unsigned char fund_txid[32];
    uint32_t fund_vout;
    uint64_t fund_amount;
} drill_t;

static int drill_setup(drill_t *d, secp256k1_context *ctx, const char *wallet)
{
    memset(d, 0, sizeof(*d));
    if (!regtest_init(&d->rt)) return -1;
    regtest_create_wallet(&d->rt, wallet);
    if (!regtest_get_new_address(&d->rt, d->mine_addr, sizeof(d->mine_addr)))
        return 0;
    if (!regtest_fund_from_faucet(&d->rt, 1.0))
        regtest_mine_blocks(&d->rt, 101, d->mine_addr);
    chain_backend_regtest_init(&d->chain, &d->rt);

    secp256k1_keypair a, b;
    secp256k1_keypair_create(ctx, &a, LSP_SECKEY);
    secp256k1_keypair_create(ctx, &b, CLI_SECKEY);
    secp256k1_pubkey pa, pb;
    secp256k1_keypair_pub(ctx, &pa, &a);
    secp256k1_keypair_pub(ctx, &pb, &b);
    unsigned char spk[34], xonly[32];
    if (!pair_fund_spk(ctx, &pa, &pb, spk, xonly)) return 0;
    char addr[128], txid_hex[65];
    if (!regtest_derive_p2tr_address(&d->rt, xonly, addr, sizeof(addr)))
        return 0;
    if (!regtest_fund_address(&d->rt, addr, 0.001, txid_hex)) return 0;
    regtest_mine_blocks(&d->rt, 1, d->mine_addr);
    d->fund_vout = UINT32_MAX;
    for (uint32_t v = 0; v < 4; v++) {
        uint64_t amt = 0; unsigned char s[64]; size_t sl = 0;
        if (regtest_get_tx_output(&d->rt, txid_hex, v, &amt, s, &sl) &&
            sl == 34 && memcmp(s, spk, 34) == 0) {
            d->fund_vout = v; d->fund_amount = amt; break;
        }
    }
    if (d->fund_vout == UINT32_MAX) return 0;
    hex_decode(txid_hex, d->fund_txid, 32);
    reverse_bytes(d->fund_txid, 32);
    return 1;
}

/* Sign (both keys, in-process) and broadcast holder's own commitment. */
static int broadcast_commitment(drill_t *d, channel_t *holder,
                                const secp256k1_keypair *other_kp,
                                unsigned char *txid32, char *txid_hex)
{
    tx_buf_t uc, sc;
    tx_buf_init(&uc, 1024); tx_buf_init(&sc, 2048);
    int ok = channel_build_commitment_tx(holder, &uc, txid32) &&
             channel_sign_commitment(holder, &sc, &uc, other_kp);
    if (ok) {
        char *hex = malloc(sc.len * 2 + 1);
        ok = hex != NULL;
        if (ok) {
            hex_encode(sc.data, sc.len, hex);
            ok = regtest_send_raw_tx(&d->rt, hex, txid_hex);
            free(hex);
        }
    }
    tx_buf_free(&uc); tx_buf_free(&sc);
    return ok;
}

static int send_tx(drill_t *d, const tx_buf_t *tx, char *txid_out)
{
    char *hex = malloc(tx->len * 2 + 1);
    if (!hex) return 0;
    hex_encode(tx->data, tx->len, hex);
    int ok = regtest_send_raw_tx(&d->rt, hex, txid_out);
    free(hex);
    return ok;
}

/* Attack: client pays the LSP; LSP reveals the preimage; the client keeps
   its revoke_and_ack and broadcasts the commitment still holding the HTLC,
   intending to take it back after the CLTV.  The LSP must claim first.
   restart: the LSP restarts (sweeper reloaded from its DB) between the
   commitment confirming and the claim. */
static int run_lsp_payee(int restart)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    drill_t d;
    int s = drill_setup(&d, ctx, restart ? "htlc_claim_lsp_rs" : "htlc_claim_lsp");
    if (s < 0) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    TEST_ASSERT(s == 1, "drill setup");

    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, d.fund_txid, d.fund_vout, d.fund_amount, 10),
                "pair");
    int h0 = regtest_get_block_height(&d.rt);
    uint32_t cltv = (uint32_t)h0 + 25;
    TEST_ASSERT(pair_add_htlc(&p, 1, 20000, cltv), "client adds HTLC");

    /* LSP side: manager with one channel and a persistent sweeper. */
    char path[] = "/tmp/ss_htlc_drill_XXXXXX";
    int fd = mkstemp(path);
    TEST_ASSERT(fd >= 0, "temp db");
    close(fd);              /* empty 0600 file: opened as a new DB */
    persist_t db;
    TEST_ASSERT(persist_open(&db, path), "lsp db");
    lsp_channel_mgr_t *mgr = calloc(1, sizeof(*mgr));
    TEST_ASSERT(mgr != NULL, "mgr");
    mgr->entries = calloc(1, sizeof(lsp_channel_entry_t));
    TEST_ASSERT(mgr->entries != NULL, "entries");
    mgr->n_channels = 1;
    memcpy(&mgr->entries[0].channel, &p.lsp, sizeof(channel_t));
    channel_t *lch = &mgr->entries[0].channel;
    sweeper_t sw;
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &d.chain, &db, NULL),
                "sweeper");
    lsp_channels_attach_sweeper(mgr, &sw);
    char dest_addr[128];
    TEST_ASSERT(regtest_get_new_address(&d.rt, dest_addr, sizeof(dest_addr)),
                "dest addr");
    size_t dl = 0;
    TEST_ASSERT(regtest_get_address_scriptpubkey(&d.rt, dest_addr, sw.dest_spk,
                                                 &dl) && dl == 34, "dest spk");
    sw.dest_spk_len = 34;

    /* LSP reveals the preimage: production hook, then the fulfil. */
    int reg = lsp_channels_register_htlc_claim(mgr, 0, p.lsp_htlc_id,
                                               p.preimage);
    TEST_ASSERT(channel_fulfill_htlc(lch, p.lsp_htlc_id, p.preimage),
                "LSP fulfils");
    /* The client never sends its revoke_and_ack: nothing cancels the claim. */

    /* Attacker broadcasts the commitment it holds and pre-builds its
       HTLC-timeout from it. */
    unsigned char ct[32];
    char ct_hex[65];
    TEST_ASSERT(broadcast_commitment(&d, &p.cli, &p.lsp_kp, ct, ct_hex),
                "client broadcasts commitment holding the HTLC");
    regtest_mine_blocks(&d.rt, 1, d.mine_addr);
    TEST_ASSERT(regtest_get_confirmations(&d.rt, ct_hex) >= 1,
                "commitment confirmed");
    uint32_t vout = 2;
    uint64_t amt = 0; unsigned char spk[64]; size_t sl = 0;
    TEST_ASSERT(regtest_get_tx_output(&d.rt, ct_hex, vout, &amt, spk, &sl) &&
                sl == 34 && amt == 20000, "HTLC output on chain");
    tx_buf_t tmo;
    tx_buf_init(&tmo, 512);
    TEST_ASSERT(channel_build_htlc_timeout_tx(&p.cli, &tmo, ct, vout, amt,
                                              spk, 34, 0),
                "attacker timeout built");

    int reloaded = 1;
    if (restart) {
        sweeper_cleanup(&sw);
        persist_close(&db);
        TEST_ASSERT(persist_open(&db, path), "lsp db reopen");
        TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &d.chain, &db, NULL),
                    "sweeper reload");
        lsp_channels_attach_sweeper(mgr, &sw);
        size_t dl2 = 0;
        regtest_get_address_scriptpubkey(&d.rt, dest_addr, sw.dest_spk, &dl2);
        sw.dest_spk_len = 34;
        reloaded = (sw.n_entries == 1 &&
                    sw.entries[0].type == SWEEP_HTLC_SUCCESS);
        printf("  payee restarted; claim %sreloaded from DB\n",
               reloaded ? "" : "NOT ");
    }

    /* Payee's cycle: claim. */
    int claimed = 0;
    if (sweeper_check(&sw) == 1 && sw.n_entries == 1 &&
        sw.entries[0].state == SWEEP_BROADCAST) {
        char claim_txid[65];
        memcpy(claim_txid, sw.entries[0].sweep_txid, 65);
        int hb = regtest_get_block_height(&d.rt);
        TEST_ASSERT((uint32_t)hb < cltv, "claim broadcast before the CLTV");
        regtest_mine_blocks(&d.rt, 1, d.mine_addr);
        TEST_ASSERT(regtest_get_confirmations(&d.rt, claim_txid) >= 1,
                    "claim confirmed");
        printf("  claim %s confirmed at height %d (cltv %u)\n", claim_txid,
               hb + 1, cltv);
        TEST_ASSERT(regtest_outpoint_unspent(&d.rt, ct_hex, vout) == 0,
                    "HTLC output spent by the claim");

        /* Buried -> claim output swept to the destination. */
        sweeper_check(&sw);
        TEST_ASSERT(sw.n_entries == 1 &&
                    sw.entries[0].type == SWEEP_HTLC_SUCCESS_OUTPUT &&
                    sw.entries[0].state == SWEEP_BROADCAST,
                    "claim output sweep broadcast");
        char sweep_txid[65];
        memcpy(sweep_txid, sw.entries[0].sweep_txid, 65);
        regtest_mine_blocks(&d.rt, 1, d.mine_addr);
        TEST_ASSERT(regtest_get_confirmations(&d.rt, sweep_txid) >= 1,
                    "sweep confirmed");
        sweeper_check(&sw);
        TEST_ASSERT(sw.n_entries == 0, "all entries done");
        claimed = 1;
    }

    /* Attacker: CLTV and CSV reached, the timeout must fail. */
    int h = regtest_get_block_height(&d.rt);
    if ((uint32_t)h < cltv + 10)
        regtest_mine_blocks(&d.rt, (int)(cltv + 10 - (uint32_t)h), d.mine_addr);
    char tmo_txid[65];
    int tmo_ok = send_tx(&d, &tmo, tmo_txid);
    if (tmo_ok) {
        regtest_mine_blocks(&d.rt, 1, d.mine_addr);
        printf("  ATTACK SUCCEEDED: sender's timeout %s confirmed=%d — the "
               "payee lost the HTLC\n", tmo_txid,
               regtest_get_confirmations(&d.rt, tmo_txid) >= 1);
    } else {
        printf("  sender's timeout claim rejected after CLTV\n");
    }
    TEST_ASSERT(reg == 1, "claim registered before reveal");
    TEST_ASSERT(reloaded, "claim reloaded after restart");
    TEST_ASSERT(claimed, "payee claimed the HTLC on chain");
    TEST_ASSERT(!tmo_ok, "sender's timeout rejected (HTLC already claimed)");

    tx_buf_free(&tmo);
    sweeper_cleanup(&sw);
    persist_close(&db);
    unlink(path);
    channel_cleanup(lch);
    free(mgr->entries);
    free(mgr);
    channel_cleanup(&p.cli);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_regtest_htlc_claim_lsp_payee(void) { return run_lsp_payee(0); }
int test_regtest_htlc_claim_lsp_payee_restart(void) { return run_lsp_payee(1); }

/* Client as payee: the LSP offered the HTLC, the client revealed the
   preimage (production client_fulfill_payment) and the LSP never signed
   the next commitment.  The client's latest signed commitment still holds
   the HTLC; it broadcasts it and claims via its CSV-delayed success leaf
   before the LSP's timeout (CLTV, no CSV) becomes valid. */
int test_regtest_htlc_claim_client_payee(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    drill_t d;
    int s = drill_setup(&d, ctx, "htlc_claim_cli");
    if (s < 0) {
        printf("  SKIP: bitcoind not available\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    TEST_ASSERT(s == 1, "drill setup");

    pair_t p;
    TEST_ASSERT(pair_init(&p, ctx, d.fund_txid, d.fund_vout, d.fund_amount, 10),
                "pair");
    int h0 = regtest_get_block_height(&d.rt);
    uint32_t cltv = (uint32_t)h0 + 25;
    TEST_ASSERT(pair_add_htlc(&p, 0, 20000, cltv), "LSP adds HTLC");

    /* Client signs + holds commitment (built now; broadcast below). */
    tx_buf_t uc, sc;
    tx_buf_init(&uc, 1024); tx_buf_init(&sc, 2048);
    unsigned char ct[32];
    TEST_ASSERT(channel_build_commitment_tx(&p.cli, &uc, ct) &&
                channel_sign_commitment(&p.cli, &sc, &uc, &p.lsp_kp),
                "client commitment signed");

    /* Attacker (LSP) timeout on the client's commitment: CLTV, no CSV,
       LSP key.  Built from a copy of the client's view with the LSP's HTLC
       secret, which yields exactly the received-HTLC timeout leaf. */
    char ct_hex[65];
    txid_internal_to_hex(ct, ct_hex);
    channel_t atk = p.cli;
    memcpy(atk.local_htlc_basepoint_secret, p.lsp.local_htlc_basepoint_secret, 32);

    sweeper_t sw;
    TEST_ASSERT(sweeper_init(&sw, ctx, NULL, NULL, 0, &d.chain, NULL, NULL),
                "client sweeper");
    g_lookup_ch = &p.cli;
    sweeper_set_channel_lookup(&sw, lookup_one, NULL);
    client_set_htlc_sweeper(&sw, 0);
    TEST_ASSERT(pair_client_signed(&p), "client holds its commitment signed");

    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    /* Attacker's timeout tx needs the HTLC still present in the copy. */
    uint32_t vout = 2;
    uint64_t amt = 20000;
    unsigned char spk[34];
    {
        ptx_t ut;
        TEST_ASSERT(ptx_parse(uc.data, uc.len, &ut) && ut.n_out >= 3,
                    "parse commitment");
        memcpy(spk, ut.out_spk[2], 34);
        TEST_ASSERT(ut.out_amount[2] == amt, "HTLC at vout 2");
    }
    tx_buf_t tmo;
    tx_buf_init(&tmo, 512);
    TEST_ASSERT(channel_build_htlc_timeout_tx(&atk, &tmo, ct, vout, amt, spk,
                                              34, 0), "attacker timeout built");

    TEST_ASSERT(client_fulfill_payment(sv[0], &p.cli, p.cli_htlc_id,
                                       p.preimage), "client fulfils");
    int reg = (sw.n_entries == 1 &&
               sw.entries[0].claim_side == HTLC_CLAIM_LOCAL_COMMIT &&
               memcmp(sw.entries[0].source_txid, ct, 32) == 0);
    close(sv[0]); close(sv[1]);
    /* No COMMITMENT_SIGNED from the LSP: nothing cancels the claim. */

    char bt[65];
    {
        char *hex = malloc(sc.len * 2 + 1);
        TEST_ASSERT(hex != NULL, "alloc");
        hex_encode(sc.data, sc.len, hex);
        int ok = regtest_send_raw_tx(&d.rt, hex, bt);
        free(hex);
        TEST_ASSERT(ok, "client broadcasts its commitment");
    }
    regtest_mine_blocks(&d.rt, 1, d.mine_addr);
    TEST_ASSERT(regtest_get_confirmations(&d.rt, ct_hex) >= 1,
                "commitment confirmed");

    int claimed = 0;
    for (int i = 0; i < 12 && !claimed; i++) {
        sweeper_check(&sw);
        if (sw.n_entries == 1 && sw.entries[0].state == SWEEP_BROADCAST) {
            claimed = 1;
            break;
        }
        regtest_mine_blocks(&d.rt, 1, d.mine_addr);
    }
    if (claimed) {
        char claim_txid[65];
        memcpy(claim_txid, sw.entries[0].sweep_txid, 65);
        int hb = regtest_get_block_height(&d.rt);
        TEST_ASSERT((uint32_t)hb < cltv, "claim before the CLTV");
        regtest_mine_blocks(&d.rt, 1, d.mine_addr);
        TEST_ASSERT(regtest_get_confirmations(&d.rt, claim_txid) >= 1,
                    "claim confirmed");
        printf("  client claim %s confirmed at height %d (cltv %u)\n",
               claim_txid, hb + 1, cltv);
        sweeper_check(&sw);
        TEST_ASSERT(sw.n_entries == 0, "claim buried, entry done");
    }

    int h = regtest_get_block_height(&d.rt);
    if ((uint32_t)h < cltv + 1)
        regtest_mine_blocks(&d.rt, (int)(cltv + 1 - (uint32_t)h), d.mine_addr);
    char tmo_txid[65];
    int tmo_ok = send_tx(&d, &tmo, tmo_txid);
    if (tmo_ok) {
        regtest_mine_blocks(&d.rt, 1, d.mine_addr);
        printf("  ATTACK SUCCEEDED: LSP's timeout %s confirmed=%d — the "
               "client lost the HTLC\n", tmo_txid,
               regtest_get_confirmations(&d.rt, tmo_txid) >= 1);
    } else {
        printf("  LSP's timeout claim rejected after CLTV\n");
    }
    TEST_ASSERT(reg, "claim registered on the client's own commitment");
    TEST_ASSERT(claimed, "claim broadcast once the CSV allows");
    TEST_ASSERT(!tmo_ok, "LSP's timeout rejected (HTLC already claimed)");

    client_set_htlc_sweeper(NULL, 0);
    tx_buf_free(&tmo); tx_buf_free(&uc); tx_buf_free(&sc);
    sweeper_cleanup(&sw);
    pair_cleanup(&p);
    secp256k1_context_destroy(ctx);
    return 1;
}
