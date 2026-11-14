/* The engine session over real sockets: host and member in two processes,
   each on its own database, with real MuSig2 signatures.  Commitment 0 both
   ways at open, member requests carried by host rounds, a host fail, and a
   disconnect in the middle of a round resumed on a new connection. */

#include "superscalar/chan_update_session.h"
#include "superscalar/musig.h"
#include "superscalar/sha256.h"
#include "superscalar/tx_builder.h"
#include <secp256k1_extrakeys.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern void sha256_tagged(const char *tag, const unsigned char *data, size_t len, unsigned char *out32);

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define S_FUND 200000ull
#define S_TIP 500
#define S_WAIT 60

typedef struct {
    persist_t db;
    char path[256];
    channel_t ch;
    cu_config_t cfg;
    cu_session_t s;
} sside_t;

static void seed(unsigned char out[32], int side, int k) {
    unsigned char b[3] = { 's', (unsigned char)side, (unsigned char)k };
    sha256(b, 3, out);
}

static int side_setup(sside_t *x, int side, secp256k1_context *ctx, const char *tag) {
    unsigned char fk[2][32], sec[2][4][32];
    secp256k1_pubkey fpk[2];
    for (int i = 0; i < 2; i++) {
        seed(fk[i], i, 9);
        if (!secp256k1_ec_pubkey_create(ctx, &fpk[i], fk[i])) return 0;
        for (int k = 0; k < 4; k++) seed(sec[i][k], i, k);
    }
    /* The funding output: MuSig2 of the two keys, key path only. */
    secp256k1_pubkey pks[2] = { fpk[0], fpk[1] };
    musig_keyagg_t ka;
    unsigned char ser[32], tweak[32], spk[34];
    if (!musig_aggregate_keys(ctx, &ka, pks, 2)) return 0;
    secp256k1_xonly_pubkey_serialize(ctx, ser, &ka.agg_pubkey);
    sha256_tagged("TapTweak", ser, 32, tweak);
    secp256k1_pubkey tw;
    secp256k1_xonly_pubkey out;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tw, &ka.cache, tweak)) return 0;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &out, NULL, &tw);
    build_p2tr_script_pubkey(spk, &out);
    unsigned char ftxid[32];
    memset(ftxid, 0x5e, 32);
    if (!channel_init(&x->ch, ctx, fk[side], &fpk[side], &fpk[1 - side], ftxid, 0, S_FUND,
                      spk, 34, 0, 0, 6))
        return 0;
    if (!channel_set_local_basepoints(&x->ch, sec[side][0], sec[side][1], sec[side][2])) return 0;
    if (!channel_set_local_htlc_basepoint(&x->ch, sec[side][3])) return 0;
    secp256k1_pubkey rb[4];
    for (int k = 0; k < 4; k++)
        if (!secp256k1_ec_pubkey_create(ctx, &rb[k], sec[1 - side][k])) return 0;
    channel_set_remote_basepoints(&x->ch, &rb[0], &rb[1], &rb[2]);
    channel_set_remote_htlc_basepoint(&x->ch, &rb[3]);
    x->ch.use_cpfp_anchor = 1;
    x->ch.funder_is_local = side == CU_HOST;
    memset(&x->cfg, 0, sizeof(x->cfg));
    x->cfg.side = (cu_side_t)side;
    x->cfg.channel_id = 5;
    memcpy(x->cfg.funding_txid, ftxid, 32);
    x->cfg.capacity_msat = S_FUND * 1000;
    x->cfg.max_htlcs = 30;
    x->cfg.fee_min_per_kvb = 100;
    x->cfg.fee_max_per_kvb = 50000;
    x->cfg.cltv_deadline = 100000;
    x->cfg.min_cltv_headroom = 40;
    x->cfg.onchain_margin = 10;
    snprintf(x->path, sizeof(x->path), "/tmp/test_cus_%s_%d_%d.db", tag, (int)getpid(), side);
    unlink(x->path);
    mode_t old = umask(077);
    int ok = persist_open(&x->db, x->path);
    umask(old);
    if (ok) sqlite3_exec(x->db.db, "PRAGMA synchronous=OFF;", NULL, NULL, NULL);
    return ok;
}

static void initial(cu_state_t *st) {
    memset(st, 0, sizeof(*st));
    st->feerate_per_kvb = 100;    /* the factory term rate, 0.1 sat/vB */
    st->fee_msat = cu_chops_commit_fee_msat(NULL, st);
    st->member_msat = 40000000;
    st->host_msat = S_FUND * 1000 - st->member_msat - st->fee_msat;
}

static void add(cu_update_t *u, uint64_t id, uint64_t msat, int seedv) {
    unsigned char pre[32];
    memset(u, 0, sizeof(*u));
    u->kind = CU_UPD_ADD;
    u->id = id;
    u->amount_msat = msat;
    memset(pre, seedv, 32);
    sha256(pre, 32, u->payment_hash);
    u->cltv_expiry = S_TIP + 200;
}

/* The member's side of the script; its exit status is the result. */
static int member_script(int fd_a, int fd_b) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    sside_t *m = calloc(1, sizeof(*m));
    cu_state_t *st = malloc(sizeof(*st));
    char why[256];
    if (!ctx || !m || !st || !side_setup(m, CU_MEMBER, ctx, "a")) return 10;
    initial(st);
    if (!cu_session_open(&m->s, fd_a, &m->db, &m->cfg, &m->ch, ctx, st, S_TIP, S_WAIT)) return 11;
    if (cu_session_wait(&m->s, CU_WAIT_REST, 1, S_WAIT) != CU_OK) return 12;
    cu_update_t u;
    memset(&u, 0, sizeof(u));
    u.kind = CU_UPD_FULFILL;
    u.id = 0;
    memset(u.preimage, 1, 32);
    if (cu_session_offer(&m->s, &u, 1) != CU_OK) return 13;
    if (cu_session_wait(&m->s, CU_WAIT_REST, 2, S_WAIT) != CU_OK) return 14;
    add(&u, 0, 3000000, 2);
    if (cu_session_offer(&m->s, &u, 1) != CU_OK) return 15;
    if (cu_session_wait(&m->s, CU_WAIT_REST, 4, S_WAIT) != CU_OK) return 16;   /* carried, then failed */
    /* The host goes away in the middle of the next round. */
    int rc = cu_session_wait(&m->s, CU_WAIT_REST, 5, S_WAIT);
    if (rc == CU_OK) return 17;
    cu_session_disconnect(&m->s);
    close(fd_a);
    if (!cu_session_resume(&m->s, fd_b, &m->db, &m->cfg, &m->ch, ctx, S_TIP)) return 18;
    if (cu_session_wait(&m->s, CU_WAIT_REST, 5, S_WAIT) != CU_OK) return 19;
    if (!cu_check_invariants(&m->db, 5, S_FUND * 1000, why, sizeof(why))) return 20;
    if (m->s.c->st.member_msat != 40000000 + 20000000) return 21;
    return 0;
}

int test_cu_session_sockets(void) {
    int a[2], b[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, a) == 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, b) == 0,
                "socketpairs");
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) {
        signal(SIGPIPE, SIG_IGN);
        alarm(240);
        close(a[0]);
        close(b[0]);
        _exit(member_script(a[1], b[1]));
    }
    void (*old_pipe)(int) = signal(SIGPIPE, SIG_IGN);
    close(a[1]);
    close(b[1]);
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    sside_t *h = calloc(1, sizeof(*h));
    cu_state_t *st = malloc(sizeof(*st));
    char why[256] = "";
    int ok = ctx && h && st && side_setup(h, CU_HOST, ctx, "a");
    if (ok) initial(st);
    ok = ok && cu_session_open(&h->s, a[0], &h->db, &h->cfg, &h->ch, ctx, st, S_TIP, S_WAIT);
    cu_update_t u;
    add(&u, 0, 20000000, 1);
    /* The host pays the member; the member fulfils; the member pays; the
       host fails that. */
    ok = ok && cu_session_round(&h->s, &u, 1) == CU_OK
            && cu_session_wait(&h->s, CU_WAIT_REST, 1, S_WAIT) == CU_OK
            && cu_session_wait(&h->s, CU_WAIT_REQUEST, 1, S_WAIT) == CU_OK
            && cu_session_round(&h->s, NULL, 0) == CU_OK
            && cu_session_wait(&h->s, CU_WAIT_REST, 2, S_WAIT) == CU_OK
            && cu_session_wait(&h->s, CU_WAIT_REQUEST, 2, S_WAIT) == CU_OK
            && cu_session_round(&h->s, NULL, 0) == CU_OK
            && cu_session_wait(&h->s, CU_WAIT_REST, 3, S_WAIT) == CU_OK;
    memset(&u, 0, sizeof(u));
    u.kind = CU_UPD_FAIL;
    u.id = 0;
    ok = ok && cu_session_round(&h->s, &u, 1) == CU_OK
            && cu_session_wait(&h->s, CU_WAIT_REST, 4, S_WAIT) == CU_OK;
    /* A round opened, then the connection lost before any answer. */
    add(&u, 1, 1000000, 3);
    ok = ok && cu_session_round(&h->s, &u, 1) == CU_OK;
    cu_session_disconnect(&h->s);
    close(a[0]);
    ok = ok && cu_session_resume(&h->s, b[0], &h->db, &h->cfg, &h->ch, ctx, S_TIP)
            && cu_session_wait(&h->s, CU_WAIT_REST, 5, S_WAIT) == CU_OK
            && cu_check_invariants(&h->db, 5, S_FUND * 1000, why, sizeof(why));
    int status = 0;
    if (!ok) kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    signal(SIGPIPE, old_pipe);
    if (!ok) printf("  host side failed (%s), engine rc %d\n", why, h ? h->s.last_rc : 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        printf("  member exit status %d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    int member_ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    int held = ok ? (int)h->s.c->rec.held : -1;
    if (h) {
        cu_session_free(&h->s);
        channel_cleanup(&h->ch);
        persist_close(&h->db);
        unlink(h->path);
    }
    char p[300];
    snprintf(p, sizeof(p), "/tmp/test_cus_a_%d_1.db", (int)pid);
    unlink(p);
    free(h); free(st);
    if (ctx) secp256k1_context_destroy(ctx);
    close(b[0]);
    TEST_ASSERT(ok, "host script");
    TEST_ASSERT(member_ok, "member script");
    TEST_ASSERT(held == 5, "both at 5");
    return 1;
}
