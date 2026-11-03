/* Revocation fail-closed tests.

   A peer that answers a commitment update with a revocation secret that does
   not verify keeps an older commitment that can never be penalised.  These
   tests drive the real handlers with a garbage REVOKE_AND_ACK and check that
   the ceremony fails and nothing that depends on the revocation happens:
   no watch is registered, the LSP does not reveal its own revocation, the
   channel refuses further updates and the peer is disconnected.  Each case
   has a control run with the correct secret through the same harness.

   client -> LSP:  UPDATE_ADD_HTLC, sender side (nothing is forwarded)
                   UPDATE_FULFILL_HTLC, payee side; with an upstream sender,
                     settlement upstream still completes
                   BRIDGE_ADD_HTLC
                   reconnect, pending COMMITMENT_SIGNED retransmit
   LSP -> client:  client_accept_lsp_revocation (both client daemon paths)
   Also: a revoked commitment that cannot be watched fails the channel, and
   which failures are persisted (not those caused on a session opened by an
   unauthenticated reconnect).
*/

#include "superscalar/channel.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/lsp_channels_internal.h"
#include "superscalar/jit_channel.h"
#include "superscalar/lsp.h"
#include "superscalar/watchtower.h"
#include "superscalar/client.h"
#include "superscalar/persist.h"
#include "superscalar/wire.h"
#include "superscalar/fee.h"
#include "superscalar/musig.h"
#include "superscalar/sha256.h"
#include "cJSON.h"
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define RFC_NONCES 16
#define RFC_MAX 2

/* In-process LSP with n client channels.  The client end of each
   socketpair is driven by the test; client_ch[i] mirrors client i's keys. */
typedef struct {
    secp256k1_context *ctx;
    size_t n;
    lsp_t lsp;
    lsp_channel_mgr_t mgr;
    channel_t client_ch[RFC_MAX];
    secp256k1_pubkey client_pk[RFC_MAX];
    unsigned char pubnonces[RFC_MAX][RFC_NONCES][66];
    watchtower_t wt;
    fee_estimator_static_t fee;
    persist_t db;
    int has_db;
    int sv[RFC_MAX][2];
} rfc_t;

/* Messages one client received from the LSP. */
typedef struct {
    int lsp_revs, adds, fulfills, sigs, acks, nonces;
} rfc_inbox_t;

typedef struct {
    int ret;          /* handler return */
    size_t n_watch;   /* watchtower entries afterwards */
    int stored;       /* revocation secret stored */
    int lsp_revs;     /* MSG_LSP_REVOKE_AND_ACK messages the LSP sent */
    int fd_open;      /* client still connected */
    int add_ok;       /* a further HTLC could be added on the channel */
} rfc_result_t;

static void *rfc_failing_realloc(void *p, size_t n) { (void)p; (void)n; return NULL; }

static int rfc_setup(rfc_t *f, size_t n, int with_db) {
    f->n = n;
    f->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char lsp_sec[32];
    memset(lsp_sec, 0x11, 32);
    secp256k1_pubkey lsp_pk;
    if (!secp256k1_ec_pubkey_create(f->ctx, &lsp_pk, lsp_sec)) return 0;

    f->lsp.client_fds = calloc(n, sizeof(int));
    f->lsp.client_pubkeys = calloc(n, sizeof(secp256k1_pubkey));
    if (!f->lsp.client_fds || !f->lsp.client_pubkeys) return 0;
    f->lsp.clients_cap = n;
    f->lsp.n_clients = n;
    f->lsp.ctx = f->ctx;
    f->lsp.lsp_pubkey = lsp_pk;
    f->lsp.listen_fd = -1;
    f->lsp.bridge_fd = -1;

    f->mgr.ctx = f->ctx;
    f->mgr.n_channels = n;
    f->mgr.entries = calloc(n, sizeof(lsp_channel_entry_t));
    f->mgr.invoices = calloc(MAX_INVOICE_REGISTRY, sizeof(invoice_entry_t));
    f->mgr.htlc_origins = calloc(MAX_HTLC_ORIGINS, sizeof(htlc_origin_t));
    if (!f->mgr.entries || !f->mgr.invoices || !f->mgr.htlc_origins) return 0;
    f->mgr.entries_cap = n;
    f->mgr.invoices_cap = MAX_INVOICE_REGISTRY;
    f->mgr.htlc_origins_cap = MAX_HTLC_ORIGINS;
    f->mgr.bridge_fd = -1;
    f->mgr.next_request_id = 1;
    htlc_inbound_init(&f->mgr.htlc_inbound);
    fee_estimator_static_init(&f->fee, 1000);
    if (!watchtower_init(&f->wt, n, NULL, (fee_estimator_t *)&f->fee, NULL)) return 0;
    f->mgr.watchtower = &f->wt;
    if (with_db) {
        if (!persist_open(&f->db, NULL)) return 0;
        f->has_db = 1;
        f->mgr.persist = &f->db;
    }

    unsigned char funding_spk[34] = {0x51, 0x20};
    memset(funding_spk + 2, 0xBB, 32);
    for (size_t i = 0; i < n; i++) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, f->sv[i]) != 0) return 0;
        f->lsp.client_fds[i] = f->sv[i][0];
        unsigned char client_sec[32];
        memset(client_sec, 0x22 + (int)i, 32);
        if (!secp256k1_ec_pubkey_create(f->ctx, &f->client_pk[i], client_sec)) return 0;
        f->lsp.client_pubkeys[i] = f->client_pk[i];

        lsp_channel_entry_t *e = &f->mgr.entries[i];
        e->channel_id = (uint32_t)i;
        e->ready = 1;
        e->last_message_time = time(NULL);
        channel_t *ch = &e->channel;
        channel_t *cc = &f->client_ch[i];
        unsigned char funding_txid[32];
        memset(funding_txid, 0xA0 + (int)i, 32);
        if (!channel_init(ch, f->ctx, lsp_sec, &lsp_pk, &f->client_pk[i], funding_txid,
                          0, 1000000, funding_spk, 34, 500000, 499846, 144)) return 0;
        ch->funder_is_local = 1;
        if (!channel_init(cc, f->ctx, client_sec, &f->client_pk[i], &lsp_pk,
                          funding_txid, 0, 1000000, funding_spk, 34,
                          499846, 500000, 144)) return 0;
        if (!channel_generate_random_basepoints(ch)) return 0;
        if (!channel_generate_random_basepoints(cc)) return 0;
        channel_set_remote_basepoints(ch, &cc->local_payment_basepoint,
            &cc->local_delayed_payment_basepoint, &cc->local_revocation_basepoint);
        channel_set_remote_htlc_basepoint(ch, &cc->local_htlc_basepoint);
        channel_set_remote_basepoints(cc, &ch->local_payment_basepoint,
            &ch->local_delayed_payment_basepoint, &ch->local_revocation_basepoint);
        channel_set_remote_htlc_basepoint(cc, &ch->local_htlc_basepoint);
        for (uint64_t cn = 2; cn <= 4; cn++)
            if (!channel_generate_local_pcs(cc, cn)) return 0;

        /* MuSig2 nonces: the LSP signs with its pool against the client's. */
        if (!channel_init_nonce_pool(ch, RFC_NONCES)) return 0;
        if (!channel_init_nonce_pool(cc, RFC_NONCES)) return 0;
        for (size_t k = 0; k < RFC_NONCES; k++)
            if (!musig_pubnonce_serialize(f->ctx, f->pubnonces[i][k],
                    &cc->local_nonce_pool.nonces[k].pubnonce)) return 0;
        if (!channel_set_remote_pubnonces(ch,
                (const unsigned char (*)[66])f->pubnonces[i], RFC_NONCES)) return 0;
    }
    return 1;
}

static void rfc_teardown(rfc_t *f) {
    watchtower_cleanup(&f->wt);
    if (f->mgr.jit_channels) {
        jit_channel_t *jits = (jit_channel_t *)f->mgr.jit_channels;
        for (size_t k = 0; k < f->mgr.n_jit_channels; k++)
            channel_cleanup(&jits[k].channel);
        free(f->mgr.jit_channels);
        f->mgr.jit_channels = NULL;
    }
    lsp_channels_cleanup(&f->mgr);
    for (size_t i = 0; i < f->n; i++) {
        channel_cleanup(&f->client_ch[i]);
        if (f->lsp.client_fds && f->lsp.client_fds[i] >= 0) close(f->lsp.client_fds[i]);
        close(f->sv[i][1]);
    }
    free(f->lsp.client_fds);
    free(f->lsp.client_pubkeys);
    if (f->has_db) persist_close(&f->db);
    secp256k1_context_destroy(f->ctx);
}

/* Give the LSP client i's per-commitment point for `cn`. */
static int rfc_point(rfc_t *f, size_t i, uint64_t cn) {
    secp256k1_pubkey p;
    if (!channel_get_per_commitment_point(&f->client_ch[i], cn, &p)) return 0;
    channel_set_remote_pcp(&f->mgr.entries[i].channel, cn, &p);
    return 1;
}

/* Queue client i's REVOKE_AND_ACK for `revoked_cn` on fd.  With valid == 0
   the secret is a well-formed scalar that is NOT the client's
   per-commitment secret, so secret*G != the committed point. */
static int rfc_queue_raa_on(rfc_t *f, size_t i, int fd, uint64_t revoked_cn, int valid) {
    unsigned char secret[32];
    if (valid) {
        if (!channel_get_revocation_secret(&f->client_ch[i], revoked_cn, secret)) return 0;
    } else {
        memset(secret, 0x5a, 32);
    }
    secp256k1_pubkey next;
    if (!channel_get_per_commitment_point(&f->client_ch[i], revoked_cn + 2, &next)) return 0;
    cJSON *j = wire_build_revoke_and_ack((uint32_t)i, secret, f->ctx, &next);
    int ok = j && wire_send(fd, MSG_REVOKE_AND_ACK, j);
    cJSON_Delete(j);
    return ok;
}

static int rfc_queue_raa(rfc_t *f, size_t i, uint64_t revoked_cn, int valid) {
    return rfc_queue_raa_on(f, i, f->sv[i][1], revoked_cn, valid);
}

static void rfc_count(rfc_inbox_t *in, uint8_t msg_type) {
    switch (msg_type) {
    case MSG_LSP_REVOKE_AND_ACK:  in->lsp_revs++; break;
    case MSG_UPDATE_ADD_HTLC:     in->adds++; break;
    case MSG_UPDATE_FULFILL_HTLC: in->fulfills++; break;
    case MSG_COMMITMENT_SIGNED:   in->sigs++; break;
    case MSG_RECONNECT_ACK:       in->acks++; break;
    case MSG_CHANNEL_NONCES:      in->nonces++; break;
    default: break;
    }
}

/* Read everything the LSP sent on fd (stops at EOF or after 1s idle). */
static void rfc_drain(int fd, rfc_inbox_t *in) {
    wire_msg_t m;
    while (wire_recv_timeout(fd, &m, 1)) {
        rfc_count(in, m.msg_type);
        if (m.json) cJSON_Delete(m.json);
    }
}

/* The client end of a reconnect, read while the handler runs.

   The handlers run on the test's thread, so whatever they send waits in the
   socket until they return.  A reconnect's CHANNEL_NONCES carries the LSP's
   whole nonce pool (about 35 KB): that fits in a Linux AF_UNIX socket buffer
   but not in the 8 KB macOS default, where the LSP's send blocks until
   SO_SNDTIMEO, fails, and the reconnect ends before the step under test.
   So the client end is read on a second thread.  It only reads bytes (the
   wire layer's per-fd table is not thread-safe); the frames are counted
   after the join.  rfc_peer_socketpair also sets the buffers to that 8 KB,
   so Linux runs these tests under the same limit as macOS. */
typedef struct {
    int fd;
    unsigned char *buf;
    size_t len, cap;
    int stop;
    pthread_mutex_t mu;
    pthread_t th;
} rfc_peer_t;

#define RFC_PEER_SOCKBUF 8192

static int rfc_peer_socketpair(int sv[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 0;
    int b = RFC_PEER_SOCKBUF;
    for (int k = 0; k < 2; k++) {
        setsockopt(sv[k], SOL_SOCKET, SO_SNDBUF, &b, sizeof b);
        setsockopt(sv[k], SOL_SOCKET, SO_RCVBUF, &b, sizeof b);
    }
    return 1;
}

static void *rfc_peer_main(void *arg) {
    rfc_peer_t *p = (rfc_peer_t *)arg;
    for (;;) {
        struct pollfd pfd;
        pfd.fd = p->fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int pr = poll(&pfd, 1, 100);
        if (pr < 0 && errno == EINTR) continue;
        if (pr < 0) break;
        if (pr == 0) {
            /* Idle.  Once the handler has returned it sends nothing more,
               so everything it sent has been read. */
            pthread_mutex_lock(&p->mu);
            int stop = p->stop;
            pthread_mutex_unlock(&p->mu);
            if (stop) break;
            continue;
        }
        if (p->len == p->cap) {
            size_t ncap = p->cap ? p->cap * 2 : 65536;
            unsigned char *nb = (unsigned char *)realloc(p->buf, ncap);
            if (!nb) break;
            p->buf = nb;
            p->cap = ncap;
        }
        ssize_t n = read(p->fd, p->buf + p->len, p->cap - p->len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;  /* EOF: the LSP closed the connection */
        p->len += (size_t)n;
    }
    return NULL;
}

static int rfc_peer_start(rfc_peer_t *p, int fd) {
    memset(p, 0, sizeof *p);
    p->fd = fd;
    if (pthread_mutex_init(&p->mu, NULL) != 0) return 0;
    if (pthread_create(&p->th, NULL, rfc_peer_main, p) != 0) {
        pthread_mutex_destroy(&p->mu);
        return 0;
    }
    return 1;
}

/* Call after the handler returned: stop the reader and count the whole
   (plaintext) frames it read.  A frame cut short is not counted. */
static void rfc_peer_finish(rfc_peer_t *p, rfc_inbox_t *in) {
    pthread_mutex_lock(&p->mu);
    p->stop = 1;
    pthread_mutex_unlock(&p->mu);
    pthread_join(p->th, NULL);
    pthread_mutex_destroy(&p->mu);
    memset(in, 0, sizeof *in);
    size_t off = 0;
    while (p->len - off >= 5) {
        const unsigned char *h = p->buf + off;
        uint32_t flen = ((uint32_t)h[0] << 24) | ((uint32_t)h[1] << 16) |
                        ((uint32_t)h[2] << 8) | (uint32_t)h[3];
        if (flen < 1 || p->len - off - 4 < flen) break;
        rfc_count(in, h[4]);
        off += 4 + (size_t)flen;
    }
    free(p->buf);
    p->buf = NULL;
}

static int rfc_stored(rfc_t *f, size_t i, uint64_t cn) {
    unsigned char s[32];
    return channel_get_received_revocation(&f->mgr.entries[i].channel, cn, s);
}

/* Hand msg to the LSP as if client i sent it; consumes j. */
static int rfc_send(rfc_t *f, size_t i, uint8_t type, cJSON *j) {
    wire_msg_t msg;
    memset(&msg, 0, sizeof msg);
    msg.msg_type = type;
    msg.json = j;
    int ret = lsp_channels_handle_msg(&f->mgr, &f->lsp, i, &msg);
    cJSON_Delete(j);
    return ret;
}

static void rfc_collect(rfc_t *f, size_t i, uint64_t revoked_cn, rfc_result_t *r) {
    r->n_watch = f->wt.n_entries;
    r->stored = rfc_stored(f, i, revoked_cn);
    rfc_inbox_t in;
    memset(&in, 0, sizeof in);
    rfc_drain(f->sv[i][1], &in);
    r->lsp_revs = in.lsp_revs;
    r->fd_open = f->lsp.client_fds[i] >= 0;
    unsigned char h2[32];
    memset(h2, 0x33, 32);
    uint64_t hid2;
    r->add_ok = channel_add_htlc(&f->mgr.entries[i].channel, HTLC_OFFERED, 5000,
                                 h2, 500, &hid2);
}

static void rfc_print(const char *what, const rfc_result_t *r) {
    printf("\n    %s: ret=%d stored=%d watches=%zu lsp_revocations_sent=%d "
           "client_connected=%d further_add_ok=%d", what, r->ret, r->stored,
           r->n_watch, r->lsp_revs, r->fd_open, r->add_ok);
}

/* The client (payee) fulfils an HTLC the LSP offered, then answers the LSP's
   COMMITMENT_SIGNED with a REVOKE_AND_ACK for commitment 1.  With
   break_watch the watch table cannot take the revoked commitment. */
static int rfc_fulfill_scenario(int valid, int break_watch, rfc_result_t *r) {
    rfc_t *f = calloc(1, sizeof(*f));
    if (!f || !rfc_setup(f, 1, 0)) return 0;
    channel_t *ch = &f->mgr.entries[0].channel;
    unsigned char preimage[32], hash[32];
    memset(preimage, 0x77, 32);
    sha256(preimage, 32, hash);
    uint64_t hid;
    if (!channel_add_htlc(ch, HTLC_OFFERED, 10000, hash, 500, &hid)) return 0;  /* cn 1 */
    if (!rfc_point(f, 0, 1) || !rfc_point(f, 0, 2)) return 0;
    if (!rfc_queue_raa(f, 0, 1, valid)) return 0;
    size_t saved_cap = f->wt.entries_cap;
    if (break_watch) {
        f->wt.entries_cap = 0;
        f->wt.entries_realloc = rfc_failing_realloc;
    }
    r->ret = rfc_send(f, 0, MSG_UPDATE_FULFILL_HTLC,
                      wire_build_update_fulfill_htlc(hid, preimage));
    f->wt.entries_cap = saved_cap;
    f->wt.entries_realloc = NULL;
    rfc_collect(f, 0, 1, r);
    rfc_teardown(f);
    free(f);
    return 1;
}

/* An inbound bridge HTLC is offered to the client, which answers the LSP's
   COMMITMENT_SIGNED with a REVOKE_AND_ACK for commitment 0. */
static int rfc_bridge_add_scenario(int valid, rfc_result_t *r) {
    rfc_t *f = calloc(1, sizeof(*f));
    if (!f || !rfc_setup(f, 1, 0)) return 0;
    unsigned char preimage[32], hash[32];
    memset(preimage, 0x66, 32);
    sha256(preimage, 32, hash);
    if (!lsp_channels_register_invoice(&f->mgr, hash, preimage, 0, 10000000)) return 0;
    if (!rfc_point(f, 0, 0) || !rfc_point(f, 0, 1)) return 0;   /* verify cn 0, sign cn 1 */
    if (!rfc_queue_raa(f, 0, 0, valid)) return 0;
    wire_msg_t msg;
    memset(&msg, 0, sizeof msg);
    msg.msg_type = MSG_BRIDGE_ADD_HTLC;
    msg.json = wire_build_bridge_add_htlc(hash, 10000000, 1000, 7);
    r->ret = lsp_channels_handle_bridge_msg(&f->mgr, &f->lsp, &msg);
    cJSON_Delete(msg.json);
    rfc_collect(f, 0, 0, r);
    rfc_teardown(f);
    free(f);
    return 1;
}

#define RFC_EXPECT_FAILED(r) do { \
    TEST_ASSERT((r).stored == 0, "garbage secret not stored"); \
    TEST_ASSERT((r).n_watch == 0, "no watch registered for an unrevoked commitment"); \
    TEST_ASSERT((r).lsp_revs == 0, "LSP did not reveal its own revocation"); \
    TEST_ASSERT((r).fd_open == 0, "client disconnected"); \
    TEST_ASSERT((r).add_ok == 0, "channel refuses further updates"); \
    TEST_ASSERT((r).ret == 0, "ceremony reported as failed"); \
} while (0)

#define RFC_EXPECT_OK(r) do { \
    TEST_ASSERT((r).ret == 1, "control: ceremony succeeds"); \
    TEST_ASSERT((r).stored == 1, "control: secret stored"); \
    TEST_ASSERT((r).n_watch == 1, "control: revoked commitment watched"); \
    TEST_ASSERT((r).lsp_revs == 1, "control: LSP revocation sent"); \
    TEST_ASSERT((r).fd_open == 1, "control: client still connected"); \
    TEST_ASSERT((r).add_ok == 1, "control: channel keeps working"); \
} while (0)

int test_lsp_fulfill_rejects_invalid_revocation(void) {
    rfc_result_t r;
    memset(&r, 0, sizeof r);
    TEST_ASSERT(rfc_fulfill_scenario(0, 0, &r), "harness");
    rfc_print("invalid RAA", &r);
    RFC_EXPECT_FAILED(r);
    memset(&r, 0, sizeof r);
    TEST_ASSERT(rfc_fulfill_scenario(1, 0, &r), "harness (control)");
    rfc_print("valid RAA (control)", &r);
    printf("\n  ");
    RFC_EXPECT_OK(r);
    return 1;
}

int test_lsp_bridge_add_rejects_invalid_revocation(void) {
    rfc_result_t r;
    memset(&r, 0, sizeof r);
    TEST_ASSERT(rfc_bridge_add_scenario(0, &r), "harness");
    rfc_print("invalid RAA", &r);
    RFC_EXPECT_FAILED(r);
    memset(&r, 0, sizeof r);
    TEST_ASSERT(rfc_bridge_add_scenario(1, &r), "harness (control)");
    rfc_print("valid RAA (control)", &r);
    printf("\n  ");
    RFC_EXPECT_OK(r);
    return 1;
}

/* A valid revocation whose revoked commitment cannot be registered with the
   watchtower fails the channel just the same. */
int test_lsp_watch_failure_fails_channel(void) {
    rfc_result_t r;
    memset(&r, 0, sizeof r);
    TEST_ASSERT(rfc_fulfill_scenario(1, 1, &r), "harness");
    rfc_print("valid RAA, watch table full", &r);
    printf("\n  ");
    TEST_ASSERT(r.stored == 1, "the verified secret is kept");
    TEST_ASSERT(r.n_watch == 0, "nothing could be watched");
    TEST_ASSERT(r.lsp_revs == 0, "LSP did not reveal its own revocation");
    TEST_ASSERT(r.fd_open == 0, "client disconnected");
    TEST_ASSERT(r.add_ok == 0, "channel refuses further updates");
    TEST_ASSERT(r.ret == 0, "ceremony reported as failed");
    return 1;
}

/* Client 0 sends an HTLC for client 1.  The LSP signs the sender's new
   commitment and waits for its revocation; only then may it forward. */
static int rfc_add_sender_scenario(int valid, rfc_result_t *r,
                                   rfc_inbox_t *dest_in, size_t *dest_htlcs) {
    rfc_t *f = calloc(1, sizeof(*f));
    if (!f || !rfc_setup(f, 2, 0)) return 0;
    for (size_t i = 0; i < 2; i++)
        if (!rfc_point(f, i, 0) || !rfc_point(f, i, 1)) return 0;
    if (!rfc_queue_raa(f, 0, 0, valid)) return 0;   /* sender revokes cn 0 */
    if (!rfc_queue_raa(f, 1, 0, 1)) return 0;       /* dest, read only if forwarded */
    unsigned char preimage[32], hash[32];
    memset(preimage, 0x55, 32);
    sha256(preimage, 32, hash);
    cJSON *j = wire_build_update_add_htlc(0, 10000000, hash, 500);
    cJSON_AddNumberToObject(j, "dest_client", 1);
    r->ret = rfc_send(f, 0, MSG_UPDATE_ADD_HTLC, j);
    rfc_collect(f, 0, 0, r);
    rfc_drain(f->sv[1][1], dest_in);
    *dest_htlcs = f->mgr.entries[1].channel.n_htlcs;
    rfc_teardown(f);
    free(f);
    return 1;
}

int test_lsp_add_sender_rejects_invalid_revocation(void) {
    rfc_result_t r;
    rfc_inbox_t dest;
    size_t dest_htlcs = 0;
    memset(&r, 0, sizeof r);
    memset(&dest, 0, sizeof dest);
    TEST_ASSERT(rfc_add_sender_scenario(0, &r, &dest, &dest_htlcs), "harness");
    rfc_print("invalid sender RAA", &r);
    printf(" dest_adds=%d dest_htlcs=%zu", dest.adds, dest_htlcs);
    RFC_EXPECT_FAILED(r);
    TEST_ASSERT(dest.adds == 0 && dest.sigs == 0, "nothing forwarded to the destination");
    TEST_ASSERT(dest_htlcs == 0, "no HTLC on the destination channel");

    memset(&r, 0, sizeof r);
    memset(&dest, 0, sizeof dest);
    TEST_ASSERT(rfc_add_sender_scenario(1, &r, &dest, &dest_htlcs), "harness (control)");
    rfc_print("valid sender RAA (control)", &r);
    printf(" dest_adds=%d dest_htlcs=%zu\n  ", dest.adds, dest_htlcs);
    TEST_ASSERT(r.ret == 1, "control: HTLC forwarded");
    TEST_ASSERT(r.stored == 1 && r.lsp_revs == 1 && r.fd_open == 1,
                "control: sender revocation accepted and answered");
    TEST_ASSERT(r.n_watch == 2, "control: both revoked commitments watched");
    TEST_ASSERT(dest.adds == 1 && dest.sigs == 1, "control: destination got the HTLC");
    TEST_ASSERT(dest_htlcs == 1, "control: HTLC on the destination channel");
    return 1;
}

/* Client 0 paid client 1 through the LSP.  The payee fulfils and answers
   with a garbage revocation: its channel fails, but the LSP still settles
   upstream, since it holds the preimage and only collects what it is owed. */
int test_lsp_fulfill_settles_upstream_after_invalid_revocation(void) {
    rfc_t *f = calloc(1, sizeof(*f));
    TEST_ASSERT(f && rfc_setup(f, 2, 0), "harness");
    channel_t *sender = &f->mgr.entries[0].channel;
    channel_t *payee = &f->mgr.entries[1].channel;
    unsigned char preimage[32], hash[32];
    memset(preimage, 0x44, 32);
    sha256(preimage, 32, hash);
    uint64_t hid0, hid1;
    TEST_ASSERT(channel_add_htlc(sender, HTLC_RECEIVED, 10000, hash, 500, &hid0), "sender htlc");
    TEST_ASSERT(channel_add_htlc(payee, HTLC_OFFERED, 10000, hash, 500, &hid1), "payee htlc");
    for (size_t i = 0; i < 2; i++)
        TEST_ASSERT(rfc_point(f, i, 1) && rfc_point(f, i, 2), "points");
    TEST_ASSERT(rfc_queue_raa(f, 1, 1, 0), "payee garbage RAA");
    TEST_ASSERT(rfc_queue_raa(f, 0, 1, 1), "sender valid RAA");
    uint64_t sender_local_before = sender->local_amount;

    int ret = rfc_send(f, 1, MSG_UPDATE_FULFILL_HTLC,
                       wire_build_update_fulfill_htlc(hid1, preimage));
    rfc_inbox_t sin, pin;
    memset(&sin, 0, sizeof sin);
    memset(&pin, 0, sizeof pin);
    rfc_drain(f->sv[0][1], &sin);
    rfc_drain(f->sv[1][1], &pin);
    size_t active = 0;
    for (size_t h = 0; h < sender->n_htlcs; h++)
        if (sender->htlcs[h].state == HTLC_STATE_ACTIVE) active++;
    printf("\n    payee: failed=%d connected=%d lsp_revs=%d | sender: fulfills=%d "
           "sigs=%d lsp_revs=%d active_htlcs=%zu gained=%llu\n  ",
           payee->revocation_failed, f->lsp.client_fds[1] >= 0, pin.lsp_revs,
           sin.fulfills, sin.sigs, sin.lsp_revs, active,
           (unsigned long long)(sender->local_amount - sender_local_before));

    TEST_ASSERT(ret == 0, "handler reports the payee failure");
    TEST_ASSERT(payee->revocation_failed != 0, "payee channel failed");
    TEST_ASSERT(rfc_stored(f, 1, 1) == 0, "payee garbage secret not stored");
    TEST_ASSERT(f->lsp.client_fds[1] < 0, "payee disconnected");
    TEST_ASSERT(pin.lsp_revs == 0, "no LSP revocation to the payee");
    TEST_ASSERT(sin.fulfills == 1 && sin.sigs == 1, "upstream sender got FULFILL + CS");
    TEST_ASSERT(sin.lsp_revs == 1, "upstream ceremony completed");
    TEST_ASSERT(rfc_stored(f, 0, 1) == 1, "sender revocation stored");
    TEST_ASSERT(active == 0, "sender HTLC settled");
    /* + the HTLC, plus the commitment fee the HTLC output no longer costs */
    TEST_ASSERT(sender->local_amount >= sender_local_before + 10000, "LSP collected the HTLC");
    TEST_ASSERT(!sender->revocation_failed && f->lsp.client_fds[0] >= 0,
                "sender channel unaffected");
    TEST_ASSERT(f->wt.n_entries == 1, "only the sender's revoked commitment watched");
    rfc_teardown(f);
    free(f);
    return 1;
}

/* Queue MSG_RECONNECT for client i on fd. */
static int rfc_queue_reconnect(rfc_t *f, size_t i, int fd) {
    cJSON *j = wire_build_reconnect(f->ctx, &f->client_pk[i],
                                    f->mgr.entries[i].channel.commitment_number);
    int ok = j && wire_send(fd, MSG_RECONNECT, j);
    cJSON_Delete(j);
    return ok;
}

/* A reconnect attempt by client i is refused: the handler fails and sends
   the client nothing (no nonce exchange, no ack). */
static int rfc_reconnect_refused(rfc_t *f, size_t i) {
    int rc[2];
    if (!rfc_peer_socketpair(rc)) return 0;
    if (!rfc_queue_reconnect(f, i, rc[1])) return 0;
    rfc_peer_t peer;
    if (!rfc_peer_start(&peer, rc[1])) return 0;
    int ret = lsp_channels_handle_reconnect(&f->mgr, &f->lsp, rc[0]);
    rfc_inbox_t in;
    rfc_peer_finish(&peer, &in);
    close(rc[1]);
    return ret == 0 && in.nonces == 0 && in.acks == 0;
}

typedef struct {
    int ret, failed, persisted, stored, acks, pending_cleared, refused_again;
    int nonces, sigs;  /* CHANNEL_NONCES and COMMITMENT_SIGNED the LSP sent */
} rfc_rc_result_t;

/* The LSP signed commitment 1 and the client went away before revoking 0.
   It reconnects; the LSP retransmits COMMITMENT_SIGNED and waits for the
   revocation before acknowledging the reconnect. */
static int rfc_reconnect_scenario(int valid, rfc_rc_result_t *r) {
    rfc_t *f = calloc(1, sizeof(*f));
    if (!f || !rfc_setup(f, 1, 1)) return 0;
    channel_t *ch = &f->mgr.entries[0].channel;
    unsigned char hash[32];
    memset(hash, 0x99, 32);
    uint64_t hid;
    if (!channel_add_htlc(ch, HTLC_OFFERED, 10000, hash, 500, &hid)) return 0;  /* cn 1 */
    if (!rfc_point(f, 0, 0) || !rfc_point(f, 0, 1)) return 0;
    if (!persist_save_channel(&f->db, ch, 0, 0)) return 0;
    if (!persist_save_pending_cs(&f->db, 0, 1)) return 0;

    int rc[2];
    if (!rfc_peer_socketpair(rc)) return 0;
    if (!rfc_queue_reconnect(f, 0, rc[1])) return 0;
    cJSON *nj = wire_build_channel_nonces(0,
        (const unsigned char (*)[66])f->pubnonces[0], RFC_NONCES);
    int ok = nj && wire_send(rc[1], MSG_CHANNEL_NONCES, nj);
    cJSON_Delete(nj);
    if (!ok || !rfc_queue_raa_on(f, 0, rc[1], 0, valid)) return 0;

    rfc_peer_t peer;
    if (!rfc_peer_start(&peer, rc[1])) return 0;
    r->ret = lsp_channels_handle_reconnect(&f->mgr, &f->lsp, rc[0]);
    rfc_inbox_t in;
    rfc_peer_finish(&peer, &in);
    close(rc[1]);
    r->acks = in.acks;
    r->nonces = in.nonces;
    r->sigs = in.sigs;
    r->failed = ch->revocation_failed;
    r->persisted = persist_channel_is_failed(&f->db, 0);
    r->stored = rfc_stored(f, 0, 0);
    uint64_t pcn = 0;
    r->pending_cleared = !persist_load_pending_cs(&f->db, 0, &pcn) || pcn == 0;
    r->refused_again = valid ? 0 : rfc_reconnect_refused(f, 0);
    rfc_teardown(f);
    free(f);
    return 1;
}

/* The reconnect retransmit path fails closed, and because MSG_RECONNECT
   does not authenticate the client, the failure is not persisted. */
int test_lsp_reconnect_retransmit_rejects_invalid_revocation(void) {
    rfc_rc_result_t r;
    memset(&r, 0, sizeof r);
    TEST_ASSERT(rfc_reconnect_scenario(0, &r), "harness");
    printf("\n    invalid RAA: ret=%d nonces=%d sigs=%d failed=%d persisted=%d "
           "stored=%d acks=%d refused_again=%d", r.ret, r.nonces, r.sigs, r.failed,
           r.persisted, r.stored, r.acks, r.refused_again);
    /* The reconnect must get as far as the revocation: an earlier step that
       fails would also leave no ack and no stored secret. */
    TEST_ASSERT(r.nonces == 1, "LSP sent CHANNEL_NONCES (nonce exchange reached)");
    TEST_ASSERT(r.sigs == 1, "LSP retransmitted COMMITMENT_SIGNED (revocation reached)");
    TEST_ASSERT(r.ret == 0, "reconnect fails");
    TEST_ASSERT(r.acks == 0, "no RECONNECT_ACK");
    TEST_ASSERT(r.stored == 0, "garbage secret not stored");
    TEST_ASSERT(r.failed == CHANNEL_FAILED_SESSION, "channel failed for this process");
    TEST_ASSERT(r.persisted == 0, "failure from an unauthenticated session not persisted");
    TEST_ASSERT(r.refused_again, "further reconnects refused");

    memset(&r, 0, sizeof r);
    TEST_ASSERT(rfc_reconnect_scenario(1, &r), "harness (control)");
    printf("\n    valid RAA (control): ret=%d nonces=%d sigs=%d failed=%d stored=%d "
           "acks=%d pending_cleared=%d\n  ", r.ret, r.nonces, r.sigs, r.failed,
           r.stored, r.acks, r.pending_cleared);
    TEST_ASSERT(r.nonces == 1 && r.sigs == 1, "control: CS retransmitted");
    TEST_ASSERT(r.ret == 1 && r.acks == 1, "control: reconnect completes");
    TEST_ASSERT(r.stored == 1, "control: secret stored");
    TEST_ASSERT(r.failed == 0, "control: channel not failed");
    TEST_ASSERT(r.pending_cleared, "control: pending CS cleared");
    return 1;
}

/* Which failures are persisted: a failure caused by the peer on a session
   from the factory or rotation ceremony (the client signed with its key)
   survives a restart; on a session opened by MSG_RECONNECT it lives in
   memory only, so an impostor cannot fail an honest client's channel for
   good; a failure the peer did not cause is persisted either way.  JIT
   channels follow the same rules, and a client with any failed channel is
   refused as a whole. */
int test_failed_mark_durable_vs_reconnect_session(void) {
    rfc_t *f = calloc(1, sizeof(*f));
    TEST_ASSERT(f && rfc_setup(f, 2, 1), "harness");
    for (size_t i = 0; i < 2; i++)
        TEST_ASSERT(persist_save_channel(&f->db, &f->mgr.entries[i].channel, 0,
                                         (uint32_t)i), "save channel");
    jit_channel_t *jits = calloc(2, sizeof(jit_channel_t));
    jit_channel_t *loaded = calloc(2, sizeof(jit_channel_t));
    TEST_ASSERT(jits && loaded, "alloc");
    for (size_t i = 0; i < 2; i++) {
        jits[i].jit_channel_id = 0x8000 | (uint32_t)i;
        jits[i].client_idx = i;
        jits[i].state = JIT_STATE_OPEN;
        TEST_ASSERT(persist_save_jit_channel(&f->db, &jits[i]), "save jit");
    }
    f->mgr.jit_channels = jits;
    f->mgr.n_jit_channels = 2;
    size_t nload = 0;

    /* Client 0, authenticated session: its JIT channel fails. */
    lsp_channels_fail_channel(&f->mgr, &f->lsp, 0, &jits[0].channel, 1, "test");
    TEST_ASSERT(jits[0].channel.revocation_failed == CHANNEL_FAILED_DURABLE,
                "JIT failure is durable");
    TEST_ASSERT(!f->mgr.entries[0].channel.revocation_failed,
                "factory channel not marked by the JIT failure");
    TEST_ASSERT(f->lsp.client_fds[0] < 0, "client 0 disconnected");
    persist_load_jit_channels(&f->db, loaded, 2, &nload);
    TEST_ASSERT(nload == 2 && loaded[0].channel.revocation_failed == CHANNEL_FAILED_DURABLE &&
                loaded[1].channel.revocation_failed == 0, "JIT mark persisted");
    unsigned char h[32];
    memset(h, 0x12, 32);
    cJSON *j = wire_build_update_add_htlc(0, 5000000, h, 500);
    cJSON_AddNumberToObject(j, "dest_client", 1);
    TEST_ASSERT(rfc_send(f, 0, MSG_UPDATE_ADD_HTLC, j) == 0, "message dropped");
    TEST_ASSERT(f->mgr.entries[0].channel.n_htlcs == 0 &&
                f->mgr.entries[1].channel.n_htlcs == 0, "nothing added");
    TEST_ASSERT(rfc_reconnect_refused(f, 0), "client 0 reconnect refused");

    /* Client 0's factory channel, same session: persisted. */
    lsp_channels_fail_channel(&f->mgr, &f->lsp, 0, NULL, 1, "test");
    TEST_ASSERT(f->mgr.entries[0].channel.revocation_failed == CHANNEL_FAILED_DURABLE,
                "factory failure is durable");
    TEST_ASSERT(persist_channel_is_failed(&f->db, 0) == 1, "factory mark persisted");

    /* Client 1's session was opened by MSG_RECONNECT. */
    f->mgr.entries[1].session_unauthenticated = 1;
    lsp_channels_fail_channel(&f->mgr, &f->lsp, 1, NULL, 1, "test");
    TEST_ASSERT(f->mgr.entries[1].channel.revocation_failed == CHANNEL_FAILED_SESSION,
                "failure kept in memory");
    TEST_ASSERT(persist_channel_is_failed(&f->db, 1) == 0, "not persisted");
    TEST_ASSERT(f->lsp.client_fds[1] < 0, "client 1 disconnected");
    TEST_ASSERT(rfc_reconnect_refused(f, 1), "refused for the life of this process");
    for (size_t i = 0; i < 2; i++)
        TEST_ASSERT(persist_save_channel(&f->db, &f->mgr.entries[i].channel, 0,
                                         (uint32_t)i), "re-save channel");
    TEST_ASSERT(persist_channel_is_failed(&f->db, 0) == 1 &&
                persist_channel_is_failed(&f->db, 1) == 0,
                "re-saving keeps each mark as it is");

    /* Not caused by the peer (the watch could not be registered): durable
       even on the unauthenticated session. */
    lsp_channels_fail_channel(&f->mgr, &f->lsp, 1, &jits[1].channel, 0, "test");
    TEST_ASSERT(jits[1].channel.revocation_failed == CHANNEL_FAILED_DURABLE,
                "local failure is durable");
    persist_load_jit_channels(&f->db, loaded, 2, &nload);
    TEST_ASSERT(nload == 2 && loaded[1].channel.revocation_failed == CHANNEL_FAILED_DURABLE,
                "local failure persisted");
    for (size_t i = 0; i < 2; i++) channel_cleanup(&loaded[i].channel);
    free(loaded);
    rfc_teardown(f);
    free(f);
    return 1;
}

/* LSP -> client: the client daemon applies MSG_LSP_REVOKE_AND_ACK through
   client_accept_lsp_revocation (both the inline and the inbox path). */
int test_client_rejects_invalid_lsp_revocation(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char lsp_sec[32], client_sec[32];
    memset(lsp_sec, 0x11, 32);
    memset(client_sec, 0x22, 32);
    secp256k1_pubkey lsp_pk, client_pk;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &lsp_pk, lsp_sec), "lsp pk");
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &client_pk, client_sec), "client pk");
    unsigned char funding_txid[32];
    memset(funding_txid, 0xAA, 32);
    unsigned char funding_spk[34] = {0x51, 0x20};
    memset(funding_spk + 2, 0xBB, 32);

    channel_t *lsp_ch = calloc(1, sizeof(channel_t));
    channel_t *client_ch = calloc(1, sizeof(channel_t));
    TEST_ASSERT(lsp_ch && client_ch, "alloc");
    TEST_ASSERT(channel_init(lsp_ch, ctx, lsp_sec, &lsp_pk, &client_pk, funding_txid, 0,
                             1000000, funding_spk, 34, 500000, 499846, 144), "lsp ch");
    TEST_ASSERT(channel_init(client_ch, ctx, client_sec, &client_pk, &lsp_pk, funding_txid, 0,
                             1000000, funding_spk, 34, 499846, 500000, 144), "client ch");
    TEST_ASSERT(channel_generate_random_basepoints(lsp_ch), "bp");
    TEST_ASSERT(channel_generate_random_basepoints(client_ch), "bp");
    channel_set_remote_basepoints(client_ch, &lsp_ch->local_payment_basepoint,
        &lsp_ch->local_delayed_payment_basepoint, &lsp_ch->local_revocation_basepoint);
    channel_set_remote_basepoints(lsp_ch, &client_ch->local_payment_basepoint,
        &client_ch->local_delayed_payment_basepoint, &client_ch->local_revocation_basepoint);
    TEST_ASSERT(channel_generate_local_pcs(lsp_ch, 2), "lsp pcs 2");
    secp256k1_pubkey p;
    for (uint64_t cn = 0; cn < 2; cn++) {
        TEST_ASSERT(channel_get_per_commitment_point(lsp_ch, cn, &p), "lsp pcp");
        channel_set_remote_pcp(client_ch, cn, &p);
    }
    secp256k1_pubkey next;
    TEST_ASSERT(channel_get_per_commitment_point(lsp_ch, 2, &next), "lsp pcp 2");
    lsp_ch->commitment_number = 1;
    client_ch->commitment_number = 1;

    fee_estimator_static_t fee;
    fee_estimator_static_init(&fee, 1000);
    watchtower_t wt;
    TEST_ASSERT(watchtower_init(&wt, 1, NULL, (fee_estimator_t *)&fee, NULL), "wt");

    /* Forged: a valid scalar that is not the LSP's secret for commitment 0. */
    unsigned char forged[32];
    memset(forged, 0x5a, 32);
    wire_msg_t m;
    memset(&m, 0, sizeof m);
    m.msg_type = MSG_LSP_REVOKE_AND_ACK;
    m.json = wire_build_revoke_and_ack(0, forged, ctx, &next);
    int rv = client_accept_lsp_revocation(client_ch, ctx, &m, &wt,
                client_ch->local_amount, client_ch->remote_amount, NULL, 0);
    cJSON_Delete(m.json);
    unsigned char got[32];
    printf("\n    forged LSP revocation: outcome=%d stored=%d watches=%zu\n  ", rv,
           channel_get_received_revocation(client_ch, 0, got), wt.n_entries);
    TEST_ASSERT(wt.n_entries == 0, "no watch armed from a forged LSP revocation");
    TEST_ASSERT(rv == CLIENT_LSP_REV_REJECTED, "forged LSP revocation rejected");
    TEST_ASSERT(channel_get_received_revocation(client_ch, 0, got) == 0,
                "forged secret not stored");
    TEST_ASSERT(wt.n_entries == 0, "no watch armed from a forged LSP revocation");

    /* Control: the real secret is accepted and the revoked commitment watched. */
    unsigned char real[32];
    TEST_ASSERT(channel_get_revocation_secret(lsp_ch, 0, real), "lsp secret 0");
    m.json = wire_build_revoke_and_ack(0, real, ctx, &next);
    rv = client_accept_lsp_revocation(client_ch, ctx, &m, &wt,
                client_ch->local_amount, client_ch->remote_amount, NULL, 0);
    cJSON_Delete(m.json);
    TEST_ASSERT(rv == CLIENT_LSP_REV_OK, "control: real LSP revocation accepted");
    TEST_ASSERT(channel_get_received_revocation(client_ch, 0, got) == 1 &&
                memcmp(got, real, 32) == 0, "control: secret stored");
    TEST_ASSERT(wt.n_entries == 1, "control: revoked LSP commitment watched");
    TEST_ASSERT(wt.entries[0].signed_penalty_tx != NULL, "control: penalty pre-built");

    watchtower_cleanup(&wt);
    channel_cleanup(lsp_ch);
    channel_cleanup(client_ch);
    free(lsp_ch);
    free(client_ch);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* The failed mark survives a restart: it is stored on the channels row. */
int test_failed_channel_mark_persists(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open db");
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char a[32], b[32];
    memset(a, 0x11, 32);
    memset(b, 0x22, 32);
    secp256k1_pubkey pa, pb;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &pa, a), "pa");
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &pb, b), "pb");
    unsigned char txid[32];
    memset(txid, 0xAA, 32);
    unsigned char spk[34] = {0x51, 0x20};
    memset(spk + 2, 0xBB, 32);
    channel_t *ch = calloc(1, sizeof(channel_t));
    TEST_ASSERT(ch && channel_init(ch, ctx, a, &pa, &pb, txid, 0, 100000, spk, 34,
                                   50000, 49846, 144), "channel");
    TEST_ASSERT(persist_save_channel(&db, ch, 0, 3), "save channel 3");
    TEST_ASSERT(persist_channel_is_failed(&db, 3) == 0, "fresh channel not failed");
    TEST_ASSERT(persist_mark_channel_failed(&db, 3), "mark failed");
    TEST_ASSERT(persist_channel_is_failed(&db, 3) == 1, "mark read back");
    TEST_ASSERT(persist_update_channel_balance(&db, 3, 1, 2, 5), "balance update");
    TEST_ASSERT(persist_channel_is_failed(&db, 3) == 1, "balance updates keep the mark");
    /* The saved state follows the channel object. */
    ch->revocation_failed = CHANNEL_FAILED_DURABLE;
    TEST_ASSERT(persist_save_channel(&db, ch, 0, 3), "re-save failed channel");
    TEST_ASSERT(persist_channel_is_failed(&db, 3) == 1, "re-saving keeps the mark");
    ch->revocation_failed = CHANNEL_FAILED_SESSION;
    TEST_ASSERT(persist_save_channel(&db, ch, 0, 3), "save session-failed channel");
    TEST_ASSERT(persist_channel_is_failed(&db, 3) == 0, "a session-only failure is never written");
    ch->revocation_failed = 0;
    TEST_ASSERT(persist_save_channel(&db, ch, 0, 3), "save a new channel at the slot");
    TEST_ASSERT(persist_channel_is_failed(&db, 3) == 0, "a new channel at the slot starts open");
    TEST_ASSERT(persist_channel_is_failed(&db, 4) == 0, "unknown channel not failed");
    channel_cleanup(ch);
    free(ch);
    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}

/* jit_channels.revocation_failed is schema v41.  A DB from main (v39), or
   from the change that takes v40 (funding_anchors, reorg_tips), lacks the
   column; one from an earlier build of this change may already have it at
   v40.  Each must open, end at the current version with the column, and
   keep its JIT rows. */
static int rfc_migrate_case(int start_version, int drop_column) {
    char path[96];
    snprintf(path, sizeof path, "/tmp/test_ss_jitmig_%d_%d_%d.db",
             start_version, drop_column, (int)getpid());
    char wal[112], shm[112];
    snprintf(wal, sizeof wal, "%s-wal", path);
    snprintf(shm, sizeof shm, "%s-shm", path);
    unlink(path);
    persist_t db;
    if (!persist_open(&db, path)) return 0;
    jit_channel_t *jit = calloc(1, sizeof(jit_channel_t));
    if (!jit) return 0;
    jit->jit_channel_id = 0x8001;
    jit->client_idx = 1;
    jit->state = JIT_STATE_OPEN;
    jit->channel.local_amount = 1234;
    int ok = persist_save_jit_channel(&db, jit);
    if (ok && drop_column)
        ok = sqlite3_exec(db.db, "ALTER TABLE jit_channels DROP COLUMN revocation_failed;",
                          NULL, NULL, NULL) == SQLITE_OK;
    char sql[128];
    snprintf(sql, sizeof sql, "DELETE FROM schema_version; "
             "INSERT INTO schema_version (version) VALUES (%d);", start_version);
    if (ok)
        ok = sqlite3_exec(db.db, sql, NULL, NULL, NULL) == SQLITE_OK;
    persist_close(&db);

    int result = 0;
    if (ok && persist_open(&db, path)) {
        size_t n = 0;
        memset(jit, 0, sizeof *jit);
        persist_load_jit_channels(&db, jit, 1, &n);
        int kept = n == 1 && jit->jit_channel_id == 0x8001 &&
                   jit->channel.local_amount == 1234 &&
                   jit->channel.revocation_failed == 0;
        int marked = persist_mark_jit_failed(&db, 0x8001);
        memset(jit, 0, sizeof *jit);
        persist_load_jit_channels(&db, jit, 1, &n);
        int reloaded = n == 1 && jit->channel.revocation_failed == CHANNEL_FAILED_DURABLE;
        int version = persist_schema_version(&db);
        printf("\n    from v%d (%s): version=%d row_kept=%d mark=%d reload=%d",
               start_version, drop_column ? "no column" : "has column",
               version, kept, marked, reloaded);
        result = kept && marked && reloaded && version == PERSIST_SCHEMA_VERSION;
        persist_close(&db);
    }
    free(jit);
    unlink(path);
    unlink(wal);
    unlink(shm);
    return result;
}

int test_persist_jit_failed_column_migration(void) {
    TEST_ASSERT(rfc_migrate_case(39, 1), "DB at v39 (main) migrates");
    TEST_ASSERT(rfc_migrate_case(40, 1), "DB at v40 without the column migrates");
    TEST_ASSERT(rfc_migrate_case(40, 0), "DB at v40 that already has the column opens");
    printf("\n  ");
    return 1;
}
