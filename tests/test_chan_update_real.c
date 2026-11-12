/* Channel-update engine over channel_t: real MuSig2 signatures, real
   commitments and penalties, every message through the wire codec.  The
   regtest drills put a revoked commitment on chain and confirm its
   penalty, and confirm a member's unilateral exit. */

#include "superscalar/chan_update.h"
#include "superscalar/chan_update_ops.h"
#include "superscalar/chan_update_wire.h"
#include "superscalar/channel.h"
#include "superscalar/musig.h"
#include "superscalar/persist.h"
#include "superscalar/regtest.h"
#include "superscalar/sha256.h"
#include "superscalar/tx_builder.h"
#include "superscalar/wire.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <cJSON.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void sha256_tagged(const char *tag, const unsigned char *data, size_t len, unsigned char *out32);

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define TEST_ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { \
        printf("  FAIL: %s (line %d): %s (got %ld, expected %ld)\n", \
               __func__, __LINE__, msg, (long)(a), (long)(b)); \
        return 0; \
    } \
} while(0)

/* ------------------------------------------------------------------ */
/* Wire codec                                                          */
/* ------------------------------------------------------------------ */

static void upd(cu_update_t *u, uint8_t kind, uint8_t sender, uint64_t id, uint64_t amt) {
    memset(u, 0, sizeof(*u));
    u->kind = kind; u->sender = sender; u->id = id; u->amount_msat = amt;
    memset(u->payment_hash, 0x42, 32);
    memset(u->preimage, 0x24, 32);
    u->cltv_expiry = 812345; u->reason = 0x400f; u->feerate_per_kvb = 2500;
}

static int roundtrip(cu_side_t from, const cu_msg_t *m, size_t n, uint8_t want_type,
                     cu_msg_t *out, size_t *nout) {
    uint8_t type = 0;
    cJSON *j = NULL;
    size_t used = cu_wire_encode(from, m, n, &type, &j);
    if (used != n || type != want_type) { cJSON_Delete(j); return 0; }
    char *s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    cJSON *back = cJSON_Parse(s);
    free(s);
    int ok = back && cu_wire_decode(type, back, out, 40, nout);
    cJSON_Delete(back);
    return ok;
}

int test_cu_wire_roundtrip(void) {
    cu_msg_t m[4], out[40];
    size_t n = 0;
    memset(m, 0, sizeof(m));
    /* The host's round: updates and commitment_signed in one message. */
    m[0].type = CU_MSG_ADD;     upd(&m[0].upd, CU_UPD_ADD, CU_HOST, 7, 18446744073709551000ull);
    m[1].type = CU_MSG_FULFILL; upd(&m[1].upd, CU_UPD_FULFILL, CU_MEMBER, 3, 0);
    m[2].type = CU_MSG_COMMIT_SIG; m[2].n = 9; memset(m[2].psig, 0x11, 32);
    m[2].nonce_index = 4000000000u; memset(m[2].digest, 0x22, 32);
    for (int i = 0; i < 3; i++) m[i].channel_id = 77;
    TEST_ASSERT(roundtrip(CU_HOST, m, 3, MSG_CU_ROUND, out, &n), "round");
    TEST_ASSERT_EQ(n, 3, "three engine messages");
    TEST_ASSERT(out[0].upd.amount_msat == 18446744073709551000ull, "64-bit amount exact");
    TEST_ASSERT(memcmp(&out[1].upd.preimage, m[1].upd.preimage, 32) == 0 && out[1].upd.sender == CU_MEMBER, "fulfil");
    TEST_ASSERT(out[2].type == CU_MSG_COMMIT_SIG && out[2].n == 9 && out[2].nonce_index == 4000000000u
                && memcmp(out[2].digest, m[2].digest, 32) == 0, "signature");
    unsigned char d1[32], d2[32];
    cu_update_t a[2] = { m[0].upd, m[1].upd }, b[2] = { out[0].upd, out[1].upd };
    cu_digest(a, 2, d1); cu_digest(b, 2, d2);
    TEST_ASSERT(memcmp(d1, d2, 32) == 0, "digest survives the wire");

    /* The member's offer: updates only. */
    TEST_ASSERT(roundtrip(CU_MEMBER, m, 2, MSG_CU_OFFER, out, &n) && n == 2, "offer");
    /* The host never sends updates without opening a round. */
    {
        uint8_t t; cJSON *j = NULL;
        TEST_ASSERT(cu_wire_encode(CU_HOST, m, 2, &t, &j) == 0, "host updates need a signature");
    }
    /* Member signature, revocation, reestablish, refusal, error. */
    TEST_ASSERT(roundtrip(CU_MEMBER, &m[2], 1, MSG_CU_COMMIT_SIG, out, &n) && n == 1, "member cs");
    memset(&m[3], 0, sizeof(m[3]));
    m[3].type = CU_MSG_REVOKE; m[3].n = 12; memset(m[3].secret, 0x33, 32); memset(m[3].next_point, 0x02, 33);
    TEST_ASSERT(roundtrip(CU_HOST, &m[3], 1, MSG_CU_REVOKE, out, &n) && out[0].n == 12
                && memcmp(out[0].next_point, m[3].next_point, 33) == 0, "revoke");
    memset(&m[3], 0, sizeof(m[3]));
    m[3].type = CU_MSG_REESTABLISH; m[3].re.next_commitment_number = 5; m[3].re.next_revocation_number = 4;
    memset(m[3].re.sent_digest, 0x44, 32);
    TEST_ASSERT(roundtrip(CU_MEMBER, &m[3], 1, MSG_CU_REESTABLISH, out, &n)
                && out[0].re.next_commitment_number == 5 && out[0].re.sent_digest[31] == 0x44, "reestablish");
    memset(&m[3], 0, sizeof(m[3]));
    m[3].type = CU_MSG_REFUSE; upd(&m[3].upd, CU_UPD_ADD, CU_MEMBER, 2, 1000); m[3].code = -3;
    TEST_ASSERT(roundtrip(CU_HOST, &m[3], 1, MSG_CU_REFUSE, out, &n) && out[0].code == -3
                && out[0].upd.id == 2, "refuse");
    memset(&m[3], 0, sizeof(m[3]));
    m[3].type = CU_MSG_ERROR; m[3].code = -11;
    TEST_ASSERT(roundtrip(CU_HOST, &m[3], 1, MSG_CU_ERROR, out, &n) && out[0].code == -11, "error");

    /* Nonces. */
    unsigned char pub[3][66], back[8][66];
    for (int i = 0; i < 3; i++) memset(pub[i], 0x10 + i, 66);
    cJSON *j = cu_wire_nonces(77, 128, pub, 3);
    uint32_t ch = 0, first = 0;
    TEST_ASSERT(cu_wire_parse_nonces(j, &ch, &first, back, 8, &n) && ch == 77 && first == 128 && n == 3
                && memcmp(back[2], pub[2], 66) == 0, "nonces");
    cJSON_Delete(j);
    return 1;
}

static int decode_text(uint8_t type, const char *text) {
    cu_msg_t out[40];
    size_t n = 0;
    cJSON *j = cJSON_Parse(text);
    int ok = j && cu_wire_decode(type, j, out, 40, &n);
    cJSON_Delete(j);
    return ok;
}

int test_cu_wire_rejects(void) {
    const char *h32 = "4242424242424242424242424242424242424242424242424242424242424242";
    char good[1024], bad[1024];
    snprintf(good, sizeof(good),
        "{\"channel_id\":1,\"updates\":[{\"kind\":1,\"sender\":0,\"id\":\"1\",\"amount_msat\":\"1000\","
        "\"payment_hash\":\"%s\",\"preimage\":\"%s\",\"cltv_expiry\":10,\"reason\":0,\"feerate_per_kvb\":\"0\"}]}",
        h32, h32);
    TEST_ASSERT(decode_text(MSG_CU_OFFER, good), "a good offer decodes");
    struct { const char *from, *to, *what; } cases[] = {
        { "\"amount_msat\":\"1000\"", "\"amount_msat\":\"18446744073709551616\"", "amount above 2^64" },
        { "\"amount_msat\":\"1000\"", "\"amount_msat\":1000", "amount as a JSON number" },
        { "\"amount_msat\":\"1000\"", "\"amount_msat\":\"-1\"", "negative amount" },
        { "\"amount_msat\":\"1000\"", "\"amount_msat\":\"0100\"", "leading zero" },
        { "\"kind\":1", "\"kind\":16", "a later-release kind" },
        { "\"kind\":1", "\"kind\":1.5", "a fractional kind" },
        { "\"sender\":0", "\"sender\":2", "an unknown sender" },
        { "\"cltv_expiry\":10", "\"cltv_expiry\":4294967296", "expiry above 32 bits" },
        { "\"channel_id\":1", "\"channel_id\":-1", "negative channel id" },
        { "\"payment_hash\":\"4242", "\"payment_hash\":\"42", "short hash" },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const char *at = strstr(good, cases[i].from);
        TEST_ASSERT(at != NULL, "case applies");
        size_t pre = (size_t)(at - good);
        snprintf(bad, sizeof(bad), "%.*s%s%s", (int)pre, good, cases[i].to, at + strlen(cases[i].from));
        if (decode_text(MSG_CU_OFFER, bad)) {
            printf("  FAIL: %s: accepted %s\n", __func__, cases[i].what);
            return 0;
        }
    }
    /* Too many updates. */
    {
        size_t cap = 64 * 400 + 64;
        char *big = malloc(cap);
        TEST_ASSERT(big != NULL, "alloc");
        size_t off = (size_t)snprintf(big, cap, "{\"channel_id\":1,\"updates\":[");
        const char *item = strstr(good, "{\"kind\"");
        size_t ilen = strlen(item) - 2;   /* without "]}" */
        for (int i = 0; i < CU_MAX_UPDATES + 1; i++)
            off += (size_t)snprintf(big + off, cap - off, "%s%.*s", i ? "," : "", (int)ilen, item);
        snprintf(big + off, cap - off, "]}");
        int ok = decode_text(MSG_CU_OFFER, big);
        free(big);
        TEST_ASSERT(!ok, "more than CU_MAX_UPDATES refused");
    }
    TEST_ASSERT(!decode_text(0x33, good), "an id that is not the engine's");
    return 1;
}

/* ------------------------------------------------------------------ */
/* Two real sides                                                      */
/* ------------------------------------------------------------------ */

#define FUND_SATS 200000ull
#define RTIP 500

typedef struct {
    char path[256];
    persist_t db;
    channel_t ch;
    cu_chops_t ops;
    cu_chan_t *c;
    cu_config_t cfg;
} rside_t;

typedef struct {
    uint8_t type;
    char *text;
} wmsg_t;

typedef struct {
    secp256k1_context *ctx;
    rside_t s[2];
    wmsg_t pipe[2][256];
    size_t n_pipe[2];
    size_t wire_msgs;
    cu_state_t init;
    unsigned char spk[34];
    unsigned char ftxid[32];
    uint32_t fvout;
    secp256k1_xonly_pubkey out_key;
} rnet_t;

static const unsigned char HOST_KEY[32] = { [0 ... 31] = 0x5a };
static const unsigned char MEMBER_KEY[32] = { [0 ... 31] = 0x6b };
static int g_rseq = 0;

static int funding_spk(secp256k1_context *ctx, const secp256k1_pubkey *a, const secp256k1_pubkey *b,
                       unsigned char spk[34], secp256k1_xonly_pubkey *out_key) {
    secp256k1_pubkey pks[2] = { *a, *b };
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks, 2)) return 0;
    unsigned char ser[32], tweak[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, ser, &ka.agg_pubkey)) return 0;
    sha256_tagged("TapTweak", ser, 32, tweak);
    secp256k1_pubkey tw;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tw, &ka.cache, tweak)) return 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, out_key, NULL, &tw)) return 0;
    build_p2tr_script_pubkey(spk, out_key);
    return 1;
}

static void push(rnet_t *n, int to, uint8_t type, cJSON *j) {
    char *t = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    n->pipe[to][n->n_pipe[to]].type = type;
    n->pipe[to][n->n_pipe[to]].text = t;
    n->n_pipe[to]++;
}

/* Everything one side produced goes out through the wire codec, and any
   nonce top-up it needs goes first. */
static int flush(rnet_t *n, int i) {
    rside_t *s = &n->s[i];
    uint32_t first;
    unsigned char pub[CU_NONCE_BATCH][66];
    size_t np = 0;
    if (!cu_chops_topup(&s->ops, &first, pub, &np)) return 0;
    if (np) push(n, 1 - i, MSG_CU_NONCES, cu_wire_nonces(s->cfg.channel_id, first, pub, np));
    size_t k = 0;
    while (s->c && k < s->c->n_out) {
        uint8_t type;
        cJSON *j = NULL;
        size_t used = cu_wire_encode((cu_side_t)i, &s->c->out[k], s->c->n_out - k, &type, &j);
        if (!used) return 0;
        push(n, 1 - i, type, j);
        k += used;
    }
    if (s->c) cu_clear_outputs(s->c);
    return 1;
}

static int deliver(rnet_t *n, int to) {
    wmsg_t w = n->pipe[to][0];
    memmove(&n->pipe[to][0], &n->pipe[to][1], (n->n_pipe[to] - 1) * sizeof(wmsg_t));
    n->n_pipe[to]--;
    n->wire_msgs++;
    cJSON *j = cJSON_Parse(w.text);
    free(w.text);
    if (!j) return CU_ERR_PROTOCOL;
    int rc = CU_OK;
    if (w.type == MSG_CU_NONCES) {
        uint32_t ch, first;
        unsigned char pub[CU_NONCE_BATCH][66];
        size_t np;
        rc = cu_wire_parse_nonces(j, &ch, &first, pub, CU_NONCE_BATCH, &np)
          && cu_chops_peer_nonces(&n->s[to].ops, first, (const unsigned char (*)[66])pub, np)
           ? CU_OK : CU_ERR_PROTOCOL;
    } else {
        cu_msg_t m[CU_MAX_UPDATES + 1];
        size_t nm = 0;
        if (!cu_wire_decode(w.type, j, m, CU_MAX_UPDATES + 1, &nm)) rc = CU_ERR_PROTOCOL;
        for (size_t i = 0; rc == CU_OK && i < nm; i++) rc = cu_on_message(n->s[to].c, &m[i]);
    }
    cJSON_Delete(j);
    if (!flush(n, to)) return CU_ERR_PROTOCOL;
    return rc;
}

static int rrun(rnet_t *n) {
    int turn = 0;
    while (n->n_pipe[0] || n->n_pipe[1]) {
        int to = n->n_pipe[turn] ? turn : 1 - turn;
        turn = 1 - turn;
        int rc = deliver(n, to);
        if (rc != CU_OK) {
            printf("  delivery to side %d failed: %d\n", to, rc);
            return rc;
        }
    }
    return CU_OK;
}

static void drop_pipes(rnet_t *n) {
    for (int i = 0; i < 2; i++) {
        for (size_t k = 0; k < n->n_pipe[i]; k++) free(n->pipe[i][k].text);
        n->n_pipe[i] = 0;
    }
}

/* A new connection: fresh nonces both ways, then channel_reestablish. */
static int rconnect(rnet_t *n, int reestablish) {
    drop_pipes(n);
    for (int i = 0; i < 2; i++) {
        unsigned char pub[CU_NONCE_BATCH][66];
        size_t np;
        if (n->s[i].c) cu_on_disconnect(n->s[i].c);
        if (!cu_chops_connect(&n->s[i].ops, pub, &np)) return 0;
        push(n, 1 - i, MSG_CU_NONCES, cu_wire_nonces(n->s[i].cfg.channel_id, 0, pub, np));
    }
    if (!reestablish) {
        while (n->n_pipe[0] || n->n_pipe[1])
            for (int to = 0; to < 2; to++) if (n->n_pipe[to] && deliver(n, to) != CU_OK) return 0;
        return 1;
    }
    for (int i = 0; i < 2; i++) {
        cu_msg_t m;
        if (cu_reestablish_msg(n->s[i].c, &m) != CU_OK) return 0;
        uint8_t type;
        cJSON *j = NULL;
        if (!cu_wire_encode((cu_side_t)i, &m, 1, &type, &j)) return 0;
        push(n, 1 - i, type, j);
    }
    return rrun(n) == CU_OK;
}

static int side_load(rnet_t *n, int i) {
    rside_t *s = &n->s[i];
    if (!s->c) s->c = calloc(1, sizeof(cu_chan_t));
    if (!s->c || cu_load(s->c, &s->db, &s->cfg, &CU_CHANNEL_OPS, &s->ops, n->ctx) != CU_OK) return 0;
    cu_on_block(s->c, RTIP);
    cu_clear_outputs(s->c);
    return 1;
}

/* Channel set-up on a given funding outpoint, then commitment 0 both ways. */
static int rnet_init(rnet_t *n, const unsigned char ftxid[32], uint32_t fvout, uint64_t member_msat) {
    memset(n, 0, sizeof(*n));
    n->ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_pubkey pk[2];
    if (!secp256k1_ec_pubkey_create(n->ctx, &pk[0], HOST_KEY)) return 0;
    if (!secp256k1_ec_pubkey_create(n->ctx, &pk[1], MEMBER_KEY)) return 0;
    if (!funding_spk(n->ctx, &pk[0], &pk[1], n->spk, &n->out_key)) return 0;
    memcpy(n->ftxid, ftxid, 32);
    n->fvout = fvout;
    int seq = g_rseq++;
    for (int i = 0; i < 2; i++) {
        rside_t *s = &n->s[i];
        snprintf(s->path, sizeof(s->path), "/tmp/test_cur_%d_%d_%d.db", (int)getpid(), seq, i);
        unlink(s->path);
        mode_t old = umask(077);
        int ok = persist_open(&s->db, s->path);
        umask(old);
        if (!ok) return 0;
        sqlite3_exec(s->db.db, "PRAGMA synchronous=OFF;", NULL, NULL, NULL);
        if (!channel_init(&s->ch, n->ctx, i == 0 ? HOST_KEY : MEMBER_KEY, &pk[i], &pk[1 - i],
                          ftxid, fvout, FUND_SATS, n->spk, 34, 0, 0, 6))
            return 0;
        if (!channel_generate_random_basepoints(&s->ch)) return 0;
        s->ch.use_cpfp_anchor = 1;
        s->ch.funder_is_local = i == 0;
        memset(&s->cfg, 0, sizeof(s->cfg));
        s->cfg.side = (cu_side_t)i;
        s->cfg.channel_id = 3;
        memcpy(s->cfg.funding_txid, ftxid, 32);
        s->cfg.funding_vout = fvout;
        s->cfg.capacity_msat = FUND_SATS * 1000;
        s->cfg.host_reserve_msat = 0;
        s->cfg.max_htlcs = 30;
        s->cfg.fee_min_per_kvb = 253;
        s->cfg.fee_max_per_kvb = 50000;
        s->cfg.cltv_deadline = 100000;
        s->cfg.min_cltv_headroom = 40;
        s->cfg.onchain_margin = 10;
        if (!cu_chops_init(&s->ops, &s->ch, (cu_side_t)i, s->cfg.channel_id, NULL)) return 0;
    }
    for (int i = 0; i < 2; i++) {
        channel_t *a = &n->s[i].ch, *b = &n->s[1 - i].ch;
        channel_set_remote_basepoints(a, &b->local_payment_basepoint, &b->local_delayed_payment_basepoint,
                                      &b->local_revocation_basepoint);
        channel_set_remote_htlc_basepoint(a, &b->local_htlc_basepoint);
    }
    /* The opening state: the member's balance is not whole satoshis. */
    memset(&n->init, 0, sizeof(n->init));
    n->init.feerate_per_kvb = 1000;
    n->init.fee_msat = cu_chops_commit_fee_msat(NULL, &n->init);
    n->init.member_msat = member_msat;
    n->init.host_msat = FUND_SATS * 1000 - member_msat - n->init.fee_msat;

    /* Commitment 0, both ways. */
    unsigned char sec[2][2][32];
    secp256k1_pubkey pt[2][2];
    for (int i = 0; i < 2; i++)
        for (int k = 0; k < 2; k++) {
            if (!channel_read_random_bytes(sec[i][k], 32)) return 0;
            if (!secp256k1_ec_pubkey_create(n->ctx, &pt[i][k], sec[i][k])) return 0;
        }
    if (!rconnect(n, 0)) return 0;
    unsigned char psig_h[32], psig_m[32], signed_h[32], signed_m[32], sig[64];
    unsigned char *tx = malloc(CU_TX_MAX);
    size_t len;
    uint32_t idx_h, idx_m;
    int ok = tx
        && cu_open_sign(&n->s[0].ops, &n->init, &pt[1][0], psig_h, &idx_h, signed_h)
        && (len = CU_TX_MAX, cu_open_verify(&n->s[1].ops, &n->init, sec[1][0], psig_h, idx_h, tx, &len, sig))
        && cu_open_sign(&n->s[1].ops, &n->init, &pt[0][0], psig_m, &idx_m, signed_m)
        && cu_create(&n->s[1].db, &n->s[1].cfg, &n->init, sec[1][0], sec[1][1], &pt[0][0], &pt[0][1],
                     tx, len, sig, signed_m) == CU_OK
        && (len = CU_TX_MAX, cu_open_verify(&n->s[0].ops, &n->init, sec[0][0], psig_m, idx_m, tx, &len, sig))
        && cu_create(&n->s[0].db, &n->s[0].cfg, &n->init, sec[0][0], sec[0][1], &pt[1][0], &pt[1][1],
                     tx, len, sig, signed_h) == CU_OK
        && idx_h == 0 && idx_m == 1;
    free(tx);
    return ok && side_load(n, 0) && side_load(n, 1);
}

static void rnet_free(rnet_t *n) {
    drop_pipes(n);
    for (int i = 0; i < 2; i++) {
        free(n->s[i].c);
        n->s[i].c = NULL;
        channel_cleanup(&n->s[i].ch);
        persist_close(&n->s[i].db);
        unlink(n->s[i].path);
        char p[300];
        snprintf(p, sizeof(p), "%s-wal", n->s[i].path); unlink(p);
        snprintf(p, sizeof(p), "%s-shm", n->s[i].path); unlink(p);
    }
    secp256k1_context_destroy(n->ctx);
}

/* The latest commitment of side i carries a valid key-path signature for
   the funding output, and pays balances rounded down to whole satoshis. */
static int check_latest(rnet_t *n, int i, char *why, size_t wl) {
    unsigned char tx[4096], sig[64], msg[32];
    size_t len = sizeof(tx);
    uint64_t num = 0;
    if (cu_latest_commitment(n->s[i].c, tx, &len, sig, &num) != CU_OK) { snprintf(why, wl, "no latest"); return 0; }
    if (!compute_taproot_sighash(msg, tx, len, 0, n->spk, 34, FUND_SATS, 0xFFFFFFFE)) { snprintf(why, wl, "sighash"); return 0; }
    if (!secp256k1_schnorrsig_verify(n->ctx, sig, msg, 32, &n->out_key)) {
        snprintf(why, wl, "side %d commitment %llu: signature does not verify", i, (unsigned long long)num);
        return 0;
    }
    /* output 0 = holder's balance (the host's pays the anchor) */
    size_t off = 4 + 1 + 32 + 4 + 1 + 4 + 1;
    uint64_t amt = 0;
    for (int k = 7; k >= 0; k--) amt = (amt << 8) | tx[off + (size_t)k];
    const cu_state_t *st = &n->s[i].c->st;
    uint64_t want = (i == 0 ? st->host_msat : st->member_msat) / 1000;
    if (i == 0) want -= ANCHOR_OUTPUT_AMOUNT;
    if (amt != want) {
        snprintf(why, wl, "side %d to_local %llu, want %llu", i, (unsigned long long)amt, (unsigned long long)want);
        return 0;
    }
    return 1;
}

static int count_rows(persist_t *db, const char *sql) {
    sqlite3_stmt *st;
    int c = -1;
    if (sqlite3_prepare_v2(db->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    if (sqlite3_step(st) == SQLITE_ROW) c = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return c;
}

static void radd(cu_update_t *u, uint64_t id, uint64_t msat, unsigned seed) {
    unsigned char pre[32];
    memset(u, 0, sizeof(*u));
    u->kind = CU_UPD_ADD;
    u->id = id;
    u->amount_msat = msat;
    memset(pre, (int)seed, 32);
    sha256(pre, 32, u->payment_hash);
    u->cltv_expiry = RTIP + 200;
}

static int host_round(rnet_t *n, const cu_update_t *u, size_t k) {
    int rc = cu_propose(n->s[0].c, u, k);
    if (rc != CU_OK) return rc;
    if (!flush(n, 0)) return CU_ERR_PROTOCOL;
    return rrun(n);
}

/* The member asks; the host carries every pending request. */
static int member_round(rnet_t *n, const cu_update_t *u, size_t k) {
    int rc = cu_offer(n->s[1].c, u, k);
    if (rc != CU_OK) return rc;
    if (!flush(n, 1)) return CU_ERR_PROTOCOL;
    rc = rrun(n);
    if (rc != CU_OK) return rc;
    size_t nr = 0;
    const cu_update_t *r = cu_requests(n->s[0].c, &nr);
    cu_update_t copy[CU_MAX_UPDATES];
    memcpy(copy, r, nr * sizeof(cu_update_t));
    return host_round(n, copy, nr);
}

static int rest_ok(rnet_t *n, uint64_t held, char *why, size_t wl) {
    for (int i = 0; i < 2; i++) {
        if (n->s[i].c->rec.phase != CU_PHASE_IDLE || n->s[i].c->rec.held != held) {
            snprintf(why, wl, "side %d phase %d held %llu", i, n->s[i].c->rec.phase,
                     (unsigned long long)n->s[i].c->rec.held);
            return 0;
        }
        if (!check_latest(n, i, why, wl)) return 0;
        if (!cu_check_invariants(&n->s[i].db, 3, FUND_SATS * 1000, why, wl)) return 0;
    }
    return 1;
}

int test_cu_real_rounds(void) {
    unsigned char ftxid[32];
    char why[256] = "";
    memset(ftxid, 0xcd, 32);
    rnet_t *n = calloc(1, sizeof(*n));
    TEST_ASSERT(n && rnet_init(n, ftxid, 0, 50000123), "open with commitment 0 both ways");
    TEST_ASSERT(rest_ok(n, 0, why, sizeof(why)), why);

    /* The host pays the member 20000.5 sat; the member fulfils. */
    cu_update_t u;
    radd(&u, 0, 20000500, 1);
    TEST_ASSERT_EQ(host_round(n, &u, 1), CU_OK, "host add");
    TEST_ASSERT(rest_ok(n, 1, why, sizeof(why)), why);
    memset(&u, 0, sizeof(u));
    u.kind = CU_UPD_FULFILL;
    u.id = 0;
    memset(u.preimage, 1, 32);
    TEST_ASSERT_EQ(member_round(n, &u, 1), CU_OK, "member fulfil");
    TEST_ASSERT(rest_ok(n, 2, why, sizeof(why)), why);
    TEST_ASSERT_EQ(n->s[1].c->st.member_msat, 50000123 + 20000500, "member paid, in msat");
    TEST_ASSERT_EQ(count_rows(&n->s[1].db, "SELECT COUNT(*) FROM chan_update_claim;"), 1,
                   "member's claim armed before the preimage left");

    /* The member pays (an offered add); the host fails it. */
    radd(&u, 0, 3000000, 2);
    TEST_ASSERT_EQ(member_round(n, &u, 1), CU_OK, "member pays");
    TEST_ASSERT(rest_ok(n, 3, why, sizeof(why)), why);
    memset(&u, 0, sizeof(u));
    u.kind = CU_UPD_FAIL;
    u.id = 0;
    TEST_ASSERT_EQ(host_round(n, &u, 1), CU_OK, "host fails it");
    TEST_ASSERT(rest_ok(n, 4, why, sizeof(why)), why);

    /* Penalties: every revoked member commitment has its signed penalty in
       the host's tower rows, and the other way round. */
    TEST_ASSERT_EQ(count_rows(&n->s[0].db, "SELECT COUNT(*) FROM old_commitments WHERE channel_id=3"
                                           " AND signed_penalty_tx_hex IS NOT NULL;"), 4, "host tower rows");
    TEST_ASSERT_EQ(count_rows(&n->s[1].db, "SELECT COUNT(*) FROM old_commitments WHERE channel_id=3"
                                           " AND signed_penalty_tx_hex IS NOT NULL;"), 4, "member tower rows");

    /* A disconnect mid-round: new nonces, the same transactions. */
    radd(&u, 1, 1000000, 3);
    TEST_ASSERT_EQ(cu_propose(n->s[0].c, &u, 1), CU_OK, "propose");
    TEST_ASSERT(flush(n, 0), "flush");
    TEST_ASSERT_EQ(deliver(n, 1), CU_OK, "member answers");
    TEST_ASSERT(rconnect(n, 1), "reconnect with fresh nonces");
    TEST_ASSERT(rest_ok(n, 5, why, sizeof(why)), why);

    /* Many rounds: the nonce batches are topped up in-protocol (INV-72). */
    for (int r = 0; r < 40; r++) {
        cu_update_t a;
        radd(&a, 2 + (uint64_t)r, 1000000 + (uint64_t)r, (unsigned)(10 + r));
        TEST_ASSERT_EQ(host_round(n, &a, 1), CU_OK, "add round");
        memset(&a, 0, sizeof(a));
        a.kind = CU_UPD_FAIL;
        a.id = 2 + (uint64_t)r;
        TEST_ASSERT_EQ(member_round(n, &a, 1), CU_OK, "fail round");
    }
    TEST_ASSERT(rest_ok(n, 85, why, sizeof(why)), why);
    TEST_ASSERT(n->s[0].ops.next > CU_NONCE_BATCH * 2, "past two nonce batches");
    rnet_free(n);
    free(n);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Regtest drills                                                      */
/* ------------------------------------------------------------------ */

static int fund_channel(regtest_t *rt, const unsigned char spk[34], const secp256k1_xonly_pubkey *key,
                        secp256k1_context *ctx, const char *mine_addr,
                        unsigned char txid_out[32], uint32_t *vout_out) {
    unsigned char ser[32];
    char addr[128], txid_hex[65];
    if (!secp256k1_xonly_pubkey_serialize(ctx, ser, key)) return 0;
    if (!regtest_derive_p2tr_address(rt, ser, addr, sizeof(addr))) return 0;
    if (!regtest_fund_address(rt, addr, (double)FUND_SATS / 1e8, txid_hex)) return 0;
    regtest_mine_blocks(rt, 1, mine_addr);
    char params[160];
    snprintf(params, sizeof(params), "\"%s\" true true", txid_hex);
    char *res = regtest_exec(rt, "gettransaction", params);
    if (!res) return 0;
    cJSON *j = cJSON_Parse(res);
    free(res);
    char want[69];
    hex_encode(spk, 34, want);
    int found = 0;
    cJSON *vouts = j ? cJSON_GetObjectItem(cJSON_GetObjectItem(j, "decoded"), "vout") : NULL;
    for (int i = 0; vouts && i < cJSON_GetArraySize(vouts); i++) {
        cJSON *v = cJSON_GetArrayItem(vouts, i);
        cJSON *h = cJSON_GetObjectItem(cJSON_GetObjectItem(v, "scriptPubKey"), "hex");
        if (h && cJSON_IsString(h) && strcmp(h->valuestring, want) == 0) {
            *vout_out = (uint32_t)cJSON_GetObjectItem(v, "n")->valueint;
            found = 1;
        }
    }
    cJSON_Delete(j);
    if (!found) return 0;
    hex_decode(txid_hex, txid_out, 32);
    for (int i = 0; i < 16; i++) { unsigned char t = txid_out[i]; txid_out[i] = txid_out[31 - i]; txid_out[31 - i] = t; }
    return 1;
}

static int broadcast(regtest_t *rt, const unsigned char *tx, size_t len, char txid_hex[65]) {
    char *hex = malloc(len * 2 + 1);
    if (!hex) return 0;
    hex_encode(tx, len, hex);
    int ok = regtest_send_raw_tx(rt, hex, txid_hex);
    free(hex);
    return ok;
}

static int regtest_setup(regtest_t *rt, const char *wallet, char *mine_addr) {
    if (!regtest_init(rt)) return 0;
    regtest_create_wallet(rt, wallet);
    regtest_get_new_address(rt, mine_addr, 128);
    if (!regtest_fund_from_faucet(rt, 1.0)) regtest_mine_blocks(rt, 101, mine_addr);
    return 1;
}

int test_regtest_cu_breach_penalty(void) {
    regtest_t rt;
    char mine[128], why[256] = "";
    TEST_ASSERT(regtest_setup(&rt, "test_cu_breach", mine), "bitcoind");
    rnet_t *n = calloc(1, sizeof(*n));
    TEST_ASSERT(n != NULL, "alloc");
    /* The funding key does not depend on the outpoint: build it first. */
    {
        rnet_t *probe = calloc(1, sizeof(*probe));
        unsigned char z[32] = {0};
        TEST_ASSERT(probe && rnet_init(probe, z, 0, 60000000), "probe");
        memcpy(n->spk, probe->spk, 34);
        n->out_key = probe->out_key;
        n->ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        rnet_free(probe);
        free(probe);
    }
    unsigned char ftxid[32];
    uint32_t fvout = 0;
    TEST_ASSERT(fund_channel(&rt, n->spk, &n->out_key, n->ctx, mine, ftxid, &fvout), "fund channel");
    secp256k1_context_destroy(n->ctx);
    TEST_ASSERT(rnet_init(n, ftxid, fvout, 60000000), "open on chain funding");

    /* The member keeps its commitment 0. */
    unsigned char c0[4096], sig0[64];
    size_t c0len = sizeof(c0);
    TEST_ASSERT_EQ(cu_latest_commitment(n->s[1].c, c0, &c0len, sig0, NULL), CU_OK, "member C(0)");

    /* The host pays the member; the member fulfils: commitment 0 is revoked. */
    cu_update_t u;
    radd(&u, 0, 30000000, 7);
    TEST_ASSERT_EQ(host_round(n, &u, 1), CU_OK, "add");
    memset(&u, 0, sizeof(u));
    u.kind = CU_UPD_FULFILL;
    memset(u.preimage, 7, 32);
    TEST_ASSERT_EQ(member_round(n, &u, 1), CU_OK, "fulfil");
    TEST_ASSERT(rest_ok(n, 2, why, sizeof(why)), why);

    /* Breach: the member broadcasts its revoked commitment 0. */
    tx_buf_t signed0;
    tx_buf_init(&signed0, 1024);
    TEST_ASSERT(cu_chops_finalize(c0, c0len, sig0, &signed0), "finalize C(0)");
    char breach_txid[65], pen_txid[65];
    TEST_ASSERT(broadcast(&rt, signed0.data, signed0.len, breach_txid), "revoked commitment relays");
    tx_buf_free(&signed0);
    regtest_mine_blocks(&rt, 1, mine);
    TEST_ASSERT(regtest_get_confirmations(&rt, breach_txid) > 0, "revoked commitment confirmed");

    /* The host's tower row holds the signed penalty for commitment 0. */
    sqlite3_stmt *st;
    TEST_ASSERT(sqlite3_prepare_v2(n->s[0].db.db, "SELECT signed_penalty_tx_hex, txid FROM old_commitments"
                                   " WHERE channel_id=3 AND commit_num=0;", -1, &st, NULL) == SQLITE_OK, "query");
    TEST_ASSERT(sqlite3_step(st) == SQLITE_ROW, "tower row for 0");
    const char *pen_hex = (const char *)sqlite3_column_text(st, 0);
    TEST_ASSERT(pen_hex != NULL, "penalty bytes");
    char *pen = strdup(pen_hex);
    sqlite3_finalize(st);
    int sent = regtest_send_raw_tx(&rt, pen, pen_txid);
    if (!sent) printf("  penalty %s\n", pen);
    free(pen);
    TEST_ASSERT(sent, "penalty relays");
    regtest_mine_blocks(&rt, 1, mine);
    TEST_ASSERT(regtest_get_confirmations(&rt, pen_txid) > 0, "penalty confirmed");
    printf("  breach %s punished by %s\n", breach_txid, pen_txid);
    rnet_free(n);
    free(n);
    return 1;
}

int test_regtest_cu_unilateral_exit(void) {
    regtest_t rt;
    char mine[128], why[256] = "";
    TEST_ASSERT(regtest_setup(&rt, "test_cu_exit", mine), "bitcoind");
    rnet_t *n = calloc(1, sizeof(*n));
    TEST_ASSERT(n != NULL, "alloc");
    {
        rnet_t *probe = calloc(1, sizeof(*probe));
        unsigned char z[32] = {0};
        TEST_ASSERT(probe && rnet_init(probe, z, 0, 70000000), "probe");
        memcpy(n->spk, probe->spk, 34);
        n->out_key = probe->out_key;
        n->ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        rnet_free(probe);
        free(probe);
    }
    unsigned char ftxid[32];
    uint32_t fvout = 0;
    TEST_ASSERT(fund_channel(&rt, n->spk, &n->out_key, n->ctx, mine, ftxid, &fvout), "fund channel");
    secp256k1_context_destroy(n->ctx);
    TEST_ASSERT(rnet_init(n, ftxid, fvout, 70000000), "open");
    cu_update_t u;
    radd(&u, 0, 25000000, 9);
    TEST_ASSERT_EQ(member_round(n, &u, 1), CU_OK, "member pays");
    TEST_ASSERT(rest_ok(n, 1, why, sizeof(why)), why);

    /* Both latest commitments relay; then the member's confirms. */
    for (int i = 0; i < 2; i++) {
        unsigned char tx[4096], sig[64];
        size_t len = sizeof(tx);
        TEST_ASSERT_EQ(cu_latest_commitment(n->s[i].c, tx, &len, sig, NULL), CU_OK, "latest");
        tx_buf_t s;
        tx_buf_init(&s, 1024);
        TEST_ASSERT(cu_chops_finalize(tx, len, sig, &s), "finalize");
        char hex_tx[65];
        char *hex = malloc(s.len * 2 + 1);
        hex_encode(s.data, s.len, hex);
        char params[8192];
        snprintf(params, sizeof(params), "[\"%s\"]", hex);
        char *res = regtest_exec(&rt, "testmempoolaccept", params);
        int allowed = res && strstr(res, "\"allowed\":true") != NULL;
        if (!allowed) printf("  side %d: %s\n", i, res ? res : "(no answer)");
        free(res);
        TEST_ASSERT(allowed, "latest commitment relays");
        if (i == 1) {
            TEST_ASSERT(regtest_send_raw_tx(&rt, hex, hex_tx), "member exits");
            regtest_mine_blocks(&rt, 1, mine);
            TEST_ASSERT(regtest_get_confirmations(&rt, hex_tx) > 0, "exit confirmed");
            printf("  member exit %s confirmed\n", hex_tx);
        }
        free(hex);
        tx_buf_free(&s);
    }
    rnet_free(n);
    free(n);
    return 1;
}
