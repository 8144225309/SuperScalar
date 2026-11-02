/* Rotation resume state machine (lsp_rotation_resume) and the records it
   runs on: a mock chain backend, an in-memory DB, and no client online
   unless a test says so -- so no step that needs clients (funding, the
   creation ceremony) can run, and every broadcast is visible to the test. */
#include "superscalar/lsp_channels.h"
#include "superscalar/persist.h"
#include "superscalar/ladder.h"
#include "superscalar/factory.h"
#include "superscalar/chain_backend.h"
#include "superscalar/tx_builder.h"
#include "superscalar/wallet_source.h"
#include "superscalar/regtest.h"
#include "cJSON.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while (0)

/* ---- mock chain backend ---- */
typedef struct {
    chain_backend_t base;
    int height;
    char conf_txid[4][65];
    int conf_n[4];
    size_t n_conf;
    char mempool[4][65];
    size_t n_mempool;
    int outpoint_unspent;          /* answer for every other outpoint query */
    char spent_txid[4][65];        /* outpoints answered "spent" */
    uint32_t spent_vout[4];
    size_t n_spent;
    int send_ok;
    size_t n_sent;
    char sent[4][128];             /* each broadcast hex (truncated) */
} mock_chain_t;

static int mc_height(chain_backend_t *self) { return ((mock_chain_t *)self)->height; }
static int mc_confs(chain_backend_t *self, const char *txid) {
    mock_chain_t *m = (mock_chain_t *)self;
    for (size_t i = 0; i < m->n_conf; i++)
        if (strcmp(m->conf_txid[i], txid) == 0) return m->conf_n[i];
    for (size_t i = 0; i < m->n_mempool; i++)
        if (strcmp(m->mempool[i], txid) == 0) return 0;
    return -1;
}
static bool mc_mempool(chain_backend_t *self, const char *txid) {
    mock_chain_t *m = (mock_chain_t *)self;
    for (size_t i = 0; i < m->n_mempool; i++)
        if (strcmp(m->mempool[i], txid) == 0) return true;
    return false;
}
static int mc_unspent(chain_backend_t *self, const char *txid, uint32_t vout) {
    mock_chain_t *m = (mock_chain_t *)self;
    for (size_t i = 0; i < m->n_spent; i++)
        if (strcmp(m->spent_txid[i], txid) == 0 && m->spent_vout[i] == vout) return 0;
    return m->outpoint_unspent;
}
static int mc_send(chain_backend_t *self, const char *hex, char *txid_out) {
    mock_chain_t *m = (mock_chain_t *)self;
    if (m->n_sent < 4) snprintf(m->sent[m->n_sent], sizeof(m->sent[0]), "%s", hex);
    m->n_sent++;
    if (txid_out) txid_out[0] = '\0';
    return m->send_ok;
}
static void mc_confirm(mock_chain_t *m, const char *txid, int n) {
    snprintf(m->conf_txid[m->n_conf], 65, "%s", txid);
    m->conf_n[m->n_conf++] = n;
}
static void mc_to_mempool(mock_chain_t *m, const char *txid) {
    snprintf(m->mempool[m->n_mempool++], 65, "%s", txid);
}

/* ---- test rig ---- */
#define DYING_HEX "aa00000000000000000000000000000000000000000000000000000000000011"
#define CLOSE1    "c100000000000000000000000000000000000000000000000000000000000001"
#define CLOSE2    "c200000000000000000000000000000000000000000000000000000000000002"
#define FUND1     "f100000000000000000000000000000000000000000000000000000000000001"

typedef struct {
    lsp_channel_mgr_t *mgr;
    lsp_t *lsp;
    ladder_t *lad;
    persist_t db;
    mock_chain_t chain;
    int fee_dummy;
} rig_t;

static int rig_init(rig_t *r) {
    memset(r, 0, sizeof(*r));
    if (!persist_open(&r->db, ":memory:")) return 0;
    r->mgr = calloc(1, sizeof(lsp_channel_mgr_t));
    r->lsp = calloc(1, sizeof(lsp_t));
    r->lad = calloc(1, sizeof(ladder_t));
    if (!r->mgr || !r->lsp || !r->lad) return 0;

    r->chain.base.get_block_height = mc_height;
    r->chain.base.get_confirmations = mc_confs;
    r->chain.base.is_in_mempool = mc_mempool;
    r->chain.base.is_outpoint_unspent = mc_unspent;
    r->chain.base.send_raw_tx = mc_send;
    r->chain.height = 500;
    r->chain.send_ok = 1;
    r->chain.outpoint_unspent = 1;

    lsp_channel_mgr_t *m = r->mgr;
    m->chain_be = &r->chain.base;
    m->persist = &r->db;
    m->ladder = r->lad;
    m->rot_fee_est = &r->fee_dummy;      /* never used: no client is online */
    m->rot_funding_sats = 200000;
    m->n_channels = 2;
    m->entries = calloc(2, sizeof(lsp_channel_entry_t));
    if (!m->entries) return 0;
    m->entries[0].channel.funding_amount = 50000;
    m->entries[1].channel.funding_amount = 60000;

    r->lsp->n_clients = 2;
    r->lsp->client_fds = malloc(2 * sizeof(int));
    if (!r->lsp->client_fds) return 0;
    r->lsp->client_fds[0] = r->lsp->client_fds[1] = -1;

    unsigned char disp[32];
    hex_decode(DYING_HEX, disp, 32);
    r->lad->n_factories = 1;
    r->lad->factories[0].is_initialized = 1;
    r->lad->factories[0].factory_id = 0;
    for (int i = 0; i < 32; i++)
        r->lad->factories[0].factory.funding_txid[i] = disp[31 - i];
    r->lad->factories[0].factory.funding_vout = 0;

    lsp_rotation_progress_t *rp = &m->rot_progress;
    memcpy(rp->dying_funding_txid, r->lad->factories[0].factory.funding_txid, 32);
    rp->dying_funding_vout = 0;
    rp->new_funding_vout = UINT32_MAX;
    return 1;
}

static void rig_free(rig_t *r) {
    if (r->mgr) {
        lsp_rotation_progress_clear(r->mgr);
        free(r->mgr->entries);
    }
    if (r->lsp) {
        factory_free(&r->lsp->factory);
        free(r->lsp->client_fds);
    }
    free(r->mgr);
    free(r->lsp);
    free(r->lad);
    persist_close(&r->db);
}

/* Persist the in-memory marker at PHASE (the state a crash would leave). */
static int rig_mark(rig_t *r, int phase) {
    lsp_rotation_progress_t *rp = &r->mgr->rot_progress;
    rp->phase = phase;
    persist_rotation_progress_t row;
    memset(&row, 0, sizeof(row));
    row.dying_funding_vout = rp->dying_funding_vout;
    row.phase = phase;
    memcpy(row.close_txid, rp->close_txid, 65);
    memcpy(row.new_funding_txid, rp->new_funding_txid, 65);
    row.new_funding_hex = rp->new_funding_hex;
    row.new_funding_vout = rp->new_funding_vout;
    return persist_save_rotation_progress(&r->db, DYING_HEX, &row);
}

/* Phase on disk, or -1 if no row. */
static int rig_disk_phase(rig_t *r) {
    persist_rotation_progress_t row;
    memset(&row, 0, sizeof(row));
    if (!persist_load_rotation_progress(&r->db, DYING_HEX, &row, 0)) return -1;
    free(row.new_funding_hex);
    return row.phase;
}

static int rig_resume(rig_t *r) {
    r->chain.height++;                 /* one attempt per block */
    return lsp_rotation_resume(r->mgr, r->lsp);
}

/* ---- tests ---- */

int test_rotation_resume_close_in_mempool(void) {
    rig_t r;
    TEST_ASSERT(rig_init(&r), "rig");
    snprintf(r.mgr->rot_progress.close_txid, 65, "%s", CLOSE1);
    TEST_ASSERT(persist_add_rotation_close(&r.db, DYING_HEX, CLOSE1, "c1hex"), "record close");
    TEST_ASSERT(rig_mark(&r, LSP_ROT_PROGRESS_CLOSING), "mark");
    mc_to_mempool(&r.chain, CLOSE1);
    TEST_ASSERT(rig_resume(&r) == 0, "nothing completes");
    TEST_ASSERT(r.mgr->rot_progress.phase == LSP_ROT_PROGRESS_CLOSING, "still CLOSING");
    TEST_ASSERT(r.chain.n_sent == 0, "no broadcast while the close is in the mempool");
    rig_free(&r);
    return 1;
}

int test_rotation_resume_close_dropped_rebroadcast(void) {
    rig_t r;
    TEST_ASSERT(rig_init(&r), "rig");
    snprintf(r.mgr->rot_progress.close_txid, 65, "%s", CLOSE1);
    TEST_ASSERT(persist_add_rotation_close(&r.db, DYING_HEX, CLOSE1, "c1hex"), "record close");
    TEST_ASSERT(rig_mark(&r, LSP_ROT_PROGRESS_CLOSING), "mark");
    r.chain.outpoint_unspent = 1;               /* dying funding still unspent */
    TEST_ASSERT(rig_resume(&r) == 0, "waits for the rebroadcast close");
    TEST_ASSERT(r.chain.n_sent == 1 && strcmp(r.chain.sent[0], "c1hex") == 0,
                "the RECORDED close is rebroadcast");
    TEST_ASSERT(r.mgr->rot_progress.phase == LSP_ROT_PROGRESS_CLOSING, "still CLOSING");

    /* The node refuses it and the funding is still unspent: the marker is
       cleared (a new rotation may close again); the close stays recorded. */
    r.chain.send_ok = 0;
    TEST_ASSERT(rig_resume(&r) == 0, "no completion");
    TEST_ASSERT(r.mgr->rot_progress.phase == LSP_ROT_PROGRESS_NONE, "marker cleared");
    TEST_ASSERT(rig_disk_phase(&r) == LSP_ROT_PROGRESS_NONE, "cleared on disk");
    TEST_ASSERT(r.lad->factories[0].partial_rotation_done == 0, "factory may rotate again");
    char closes[4][65];
    TEST_ASSERT(persist_list_rotation_closes(&r.db, DYING_HEX, closes, 4) == 1,
                "the close stays recorded");
    rig_free(&r);
    return 1;
}

int test_rotation_resume_close_funding_spent_by_other(void) {
    rig_t r;
    TEST_ASSERT(rig_init(&r), "rig");
    snprintf(r.mgr->rot_progress.close_txid, 65, "%s", CLOSE1);
    TEST_ASSERT(persist_add_rotation_close(&r.db, DYING_HEX, CLOSE1, "c1hex"), "record close");
    TEST_ASSERT(rig_mark(&r, LSP_ROT_PROGRESS_CLOSING), "mark");
    r.chain.outpoint_unspent = 0;   /* spent, but by none of the recorded closes */
    TEST_ASSERT(rig_resume(&r) == 0, "nothing to resume");
    TEST_ASSERT(r.mgr->rot_progress.phase == LSP_ROT_PROGRESS_NONE, "marker cleared");
    TEST_ASSERT(rig_disk_phase(&r) == LSP_ROT_PROGRESS_NONE, "cleared on disk");
    TEST_ASSERT(r.chain.n_sent == 0, "nothing broadcast");
    rig_free(&r);
    return 1;
}

int test_rotation_resume_earlier_close_confirmed(void) {
    rig_t r;
    TEST_ASSERT(rig_init(&r), "rig");
    /* Close 1 was evicted, the rotation re-closed with close 2 -- then close 1
       confirmed after all: it is this factory's close. */
    TEST_ASSERT(persist_add_rotation_close(&r.db, DYING_HEX, CLOSE1, "c1hex"), "close 1");
    TEST_ASSERT(persist_add_rotation_close(&r.db, DYING_HEX, CLOSE2, "c2hex"), "close 2");
    snprintf(r.mgr->rot_progress.close_txid, 65, "%s", CLOSE2);
    TEST_ASSERT(rig_mark(&r, LSP_ROT_PROGRESS_CLOSING), "mark");
    mc_confirm(&r.chain, CLOSE1, 3);
    r.chain.outpoint_unspent = 0;
    TEST_ASSERT(rig_resume(&r) == 0, "clients offline: no Phase C yet");
    TEST_ASSERT(r.mgr->rot_progress.phase == LSP_ROT_PROGRESS_CLOSED, "CLOSED");
    TEST_ASSERT(strcmp(r.mgr->rot_progress.close_txid, CLOSE1) == 0, "tracks close 1");
    TEST_ASSERT(rig_disk_phase(&r) == LSP_ROT_PROGRESS_CLOSED, "CLOSED on disk");
    TEST_ASSERT(r.chain.n_sent == 0, "nothing broadcast, nothing funded");
    rig_free(&r);
    return 1;
}

int test_rotation_resume_funding_dropped_rebroadcast(void) {
    rig_t r;
    TEST_ASSERT(rig_init(&r), "rig");
    lsp_rotation_progress_t *rp = &r.mgr->rot_progress;
    snprintf(rp->close_txid, 65, "%s", CLOSE1);
    snprintf(rp->new_funding_txid, 65, "%s", FUND1);
    rp->new_funding_hex = strdup("f1hex");
    TEST_ASSERT(rig_mark(&r, LSP_ROT_PROGRESS_FUNDING), "mark");
    TEST_ASSERT(rig_resume(&r) == 0, "waits for the rebroadcast funding");
    TEST_ASSERT(r.chain.n_sent == 1 && strcmp(r.chain.sent[0], "f1hex") == 0,
                "the RECORDED funding is rebroadcast");
    TEST_ASSERT(rp->phase == LSP_ROT_PROGRESS_FUNDING, "still FUNDING");

    r.chain.send_ok = 0;            /* refused: never a different funding */
    TEST_ASSERT(rig_resume(&r) == 0, "operator attention");
    TEST_ASSERT(rp->phase == LSP_ROT_PROGRESS_FUNDING, "still FUNDING");
    TEST_ASSERT(r.chain.n_sent == 2 && strcmp(r.chain.sent[1], "f1hex") == 0,
                "only the recorded funding was ever broadcast");
    rig_free(&r);
    return 1;
}

int test_rotation_resume_funding_confirmed_fixes_params(void) {
    rig_t r;
    TEST_ASSERT(rig_init(&r), "rig");
    lsp_rotation_progress_t *rp = &r.mgr->rot_progress;
    snprintf(rp->close_txid, 65, "%s", CLOSE1);
    snprintf(rp->new_funding_txid, 65, "%s", FUND1);
    rp->new_funding_hex = strdup("f1hex");
    TEST_ASSERT(rig_mark(&r, LSP_ROT_PROGRESS_FUNDING), "mark");
    mc_confirm(&r.chain, FUND1, 1);
    TEST_ASSERT(rig_resume(&r) == 0, "clients offline: no ceremony");
    TEST_ASSERT(rp->phase == LSP_ROT_PROGRESS_FUNDED, "FUNDED");
    TEST_ASSERT(rp->new_funding_vout == 0 && rp->new_funding_amount == 200000, "output");
    TEST_ASSERT(rp->new_cltv == (uint32_t)r.chain.height + 1008, "CLTV fixed");
    TEST_ASSERT(rp->n_dist_amounts == 2 && rp->dist_amounts[0] == 50000 &&
                rp->dist_amounts[1] == 60000, "distribution amounts fixed");
    TEST_ASSERT(r.chain.n_sent == 0, "nothing broadcast");

    /* The parameters survive a restart unchanged. */
    uint64_t dist[8];
    persist_rotation_progress_t row;
    memset(&row, 0, sizeof(row));
    row.dist_amounts = dist;
    TEST_ASSERT(persist_load_rotation_progress(&r.db, DYING_HEX, &row, 8), "load");
    TEST_ASSERT(row.phase == LSP_ROT_PROGRESS_FUNDED && row.new_cltv == rp->new_cltv &&
                row.n_dist_amounts == 2 && dist[1] == 60000, "params on disk");
    TEST_ASSERT(row.new_funding_hex && strcmp(row.new_funding_hex, "f1hex") == 0, "hex");
    free(row.new_funding_hex);
    rig_free(&r);
    return 1;
}

/* Crash during the ceremony BEFORE its first FACTORY_READY: the marker is
   SIGNING (no SIGNING_READY), so no client holds the signed tree -- the
   resume goes back to FUNDED and will run the ceremony again. */
int test_rotation_resume_signing_before_ready_reruns(void) {
    rig_t r;
    TEST_ASSERT(rig_init(&r), "rig");
    lsp_rotation_progress_t *rp = &r.mgr->rot_progress;
    snprintf(rp->close_txid, 65, "%s", CLOSE1);
    snprintf(rp->new_funding_txid, 65, "%s", FUND1);
    rp->new_funding_vout = 0;
    rp->new_funding_amount = 200000;
    TEST_ASSERT(rig_mark(&r, LSP_ROT_PROGRESS_SIGNING), "mark");
    TEST_ASSERT(rig_resume(&r) == 0, "clients offline: no ceremony yet");
    TEST_ASSERT(rp->phase == LSP_ROT_PROGRESS_FUNDED, "back to FUNDED");
    TEST_ASSERT(rig_disk_phase(&r) == LSP_ROT_PROGRESS_FUNDED, "FUNDED on disk");
    TEST_ASSERT(r.chain.n_sent == 0, "nothing broadcast, nothing funded");
    rig_free(&r);
    return 1;
}

/* SIGNING_READY (clients may hold the signed tree) is never lowered by the
   resume: it waits for the clients and then gates any ceremony on a
   byte-identical tree (lsp_rotation_signed_tree_matches). */
int test_rotation_resume_signing_ready_kept(void) {
    rig_t r;
    TEST_ASSERT(rig_init(&r), "rig");
    lsp_rotation_progress_t *rp = &r.mgr->rot_progress;
    snprintf(rp->close_txid, 65, "%s", CLOSE1);
    snprintf(rp->new_funding_txid, 65, "%s", FUND1);
    rp->new_funding_vout = 0;
    rp->new_funding_amount = 200000;
    TEST_ASSERT(rig_mark(&r, LSP_ROT_PROGRESS_SIGNING_READY), "mark");
    for (int i = 0; i < 3; i++)
        TEST_ASSERT(rig_resume(&r) == 0, "clients offline: nothing completes");
    TEST_ASSERT(rp->phase == LSP_ROT_PROGRESS_SIGNING_READY, "still SIGNING_READY");
    TEST_ASSERT(rig_disk_phase(&r) == LSP_ROT_PROGRESS_SIGNING_READY, "on disk too");
    TEST_ASSERT(r.chain.n_sent == 0, "nothing broadcast");
    rig_free(&r);
    return 1;
}

/* The ceremony's hook recorded SIGNING_READY and then the first FACTORY_READY
   send failed (ceremony_ready_sent == 0): the marker is NOT lowered to FUNDED
   -- bytes may have reached the client.  The next resume, with the clients
   back, goes through the byte-identical-tree gate (here it cannot rebuild the
   tree, so it holds) and sends nothing.  Without SIGNING_READY the same
   failure goes back to FUNDED. */
int test_rotation_failed_ceremony_keeps_signing_ready(void) {
    rig_t r;
    TEST_ASSERT(rig_init(&r), "rig");
    lsp_rotation_progress_t *rp = &r.mgr->rot_progress;
    snprintf(rp->close_txid, 65, "%s", CLOSE1);
    snprintf(rp->new_funding_txid, 65, "%s", FUND1);
    rp->new_funding_vout = 0;
    rp->new_funding_amount = 200000;

    TEST_ASSERT(rig_mark(&r, LSP_ROT_PROGRESS_SIGNING), "mark SIGNING");
    TEST_ASSERT(lsp_rotation_ceremony_failed(r.mgr, 0, 0) == LSP_ROT_PROGRESS_FUNDED,
                "no marker, nothing sent: back to FUNDED");

    memset(rp->tree_digest, 'a', 64);
    rp->tree_digest[64] = '\0';
    TEST_ASSERT(rig_mark(&r, LSP_ROT_PROGRESS_SIGNING_READY), "hook wrote SIGNING_READY");
    TEST_ASSERT(lsp_rotation_ceremony_failed(r.mgr, 0, 0) == LSP_ROT_PROGRESS_SIGNING_READY,
                "first send failed after the marker: stays SIGNING_READY");
    TEST_ASSERT(rig_disk_phase(&r) == LSP_ROT_PROGRESS_SIGNING_READY, "on disk too");

    int sp[2][2];
    for (int i = 0; i < 2; i++) {
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sp[i]) == 0, "socketpair");
        r.lsp->client_fds[i] = sp[i][0];
    }
    TEST_ASSERT(rig_resume(&r) == 0, "no ceremony");
    TEST_ASSERT(rp->phase == LSP_ROT_PROGRESS_SIGNING_READY, "still SIGNING_READY");
    TEST_ASSERT(rp->hold_reported == 1, "the gate held (tree not rebuilt identically)");
    TEST_ASSERT(r.chain.n_sent == 0, "nothing broadcast");
    for (int i = 0; i < 2; i++) {
        struct pollfd pfd = { .fd = sp[i][1], .events = POLLIN };
        TEST_ASSERT(poll(&pfd, 1, 20) == 0, "no FACTORY_PROPOSE to any client");
        close(sp[i][0]);
        close(sp[i][1]);
        r.lsp->client_fds[i] = -1;
    }
    rig_free(&r);
    return 1;
}

/* A real segwit TX from regtest, used as a recorded funding below. */
static const char FUNDING_HEX[] =
    "020000000001019b05cf432e788f7d7a31c0b0590d02c0ab2e8a0ab50d6f9f7d58aa962402e44c"
    "0000000000feffffff0975850100000000002251207aaf8430bbbbf158ee931683f9c0ea842c4b"
    "75a15ea03d932aa719d138e36f976186010000000000225120ca17ddda776110bbfdaf779dd291"
    "f16bfefdd3341d73d07d45a2b8fa97211a5f6186010000000000225120cb9fff860e438351cf8c"
    "4c6049d08194bff07420e7b5b49ddd25e5d5e767d76d618601000000000022512074d866a5a0ce"
    "ae208684947acbaa604ab66ab6daf122a1c7bf4125132ffe8ecd61860100000000002251200fc2"
    "d26643a00df519177e3c079bcfdc3af3b61b0b8543c987969fa4586fd7ec618601000000000022"
    "5120124d6aa0d0a4fa8b0b265588976441198bf42b5d106cf2dc1d6b683d07e9c6c26186010000"
    "000000225120fdb3b97cde5fc1d03a9940d371a5ab18b3371a71b3be7e1b6e08dac994da30fe61"
    "860100000000002251207c1da16b6337eae34d16cef3b455c31dc0ea78be350db78e099b9424f3"
    "31ce42f0000000000000000451024e730140a6d8dd6826a569afddd5909746b295d32700b91353"
    "7631330298bfbc0f297d97074e0045786d9aae77fd2258fb0abbcb4ab257919c17d416ffa65ca5"
    "7eb1e40e58190000";

/* The recorded funding is neither confirmed nor in the mempool and one of its
   inputs is spent by another CONFIRMED TX: the record can never confirm, so
   it is dropped and a new funding may be built.  With the input still unspent
   the recorded TX is rebroadcast instead. */
int test_rotation_resume_funding_record_dead(void) {
    size_t n = strlen(FUNDING_HEX) / 2;
    unsigned char *tx = malloc(n);
    TEST_ASSERT(tx && hex_decode(FUNDING_HEX, tx, n) == (int)n, "decode");
    unsigned char prev[2][32];
    uint32_t vouts[2];
    size_t n_in = 0;
    TEST_ASSERT(tx_parse_inputs(tx, n, prev, vouts, 2, &n_in) && n_in == 1, "inputs");
    free(tx);
    unsigned char rb[32];
    char in_txid[65];
    for (int i = 0; i < 32; i++) rb[i] = prev[0][31 - i];
    hex_encode(rb, 32, in_txid);

    for (int dead = 0; dead <= 1; dead++) {
        rig_t r;
        TEST_ASSERT(rig_init(&r), "rig");
        lsp_rotation_progress_t *rp = &r.mgr->rot_progress;
        snprintf(rp->close_txid, 65, "%s", CLOSE1);
        snprintf(rp->new_funding_txid, 65, "%s", FUND1);
        rp->new_funding_hex = strdup(FUNDING_HEX);
        TEST_ASSERT(rig_mark(&r, LSP_ROT_PROGRESS_FUNDING), "mark");
        mc_confirm(&r.chain, in_txid, 10);            /* the input's TX is confirmed */
        if (dead) {
            snprintf(r.chain.spent_txid[0], 65, "%s", in_txid);
            r.chain.spent_vout[0] = vouts[0];
            r.chain.n_spent = 1;
        }
        TEST_ASSERT(rig_resume(&r) == 0, "clients offline: no new funding yet");
        if (dead) {
            /* Just seen: the conflicting spend is only 1 block deep. */
            TEST_ASSERT(rp->phase == LSP_ROT_PROGRESS_FUNDING && rp->new_funding_hex,
                        "a shallow conflicting spend: wait, not dropped");
            TEST_ASSERT(r.chain.n_sent == 0, "not rebroadcast while it conflicts");
            /* Reorg-safe deep (the network's funding / close depth). */
            int need = chain_close_confs(&r.chain.base, 0);
            if (chain_funding_confs(&r.chain.base, 0) > need)
                need = chain_funding_confs(&r.chain.base, 0);
            r.chain.height += need - 2;     /* rig_resume adds the last block */
            TEST_ASSERT(rig_resume(&r) == 0, "clients offline: no new funding yet");
            TEST_ASSERT(rp->phase == LSP_ROT_PROGRESS_CLOSED, "record dropped: CLOSED");
            TEST_ASSERT(rig_disk_phase(&r) == LSP_ROT_PROGRESS_CLOSED, "on disk");
            TEST_ASSERT(rp->new_funding_txid[0] == '\0' && !rp->new_funding_hex,
                        "record cleared");
            TEST_ASSERT(r.chain.n_sent == 0, "the dead TX is not rebroadcast");
        } else {
            TEST_ASSERT(rp->phase == LSP_ROT_PROGRESS_FUNDING, "still FUNDING");
            TEST_ASSERT(r.chain.n_sent == 1 &&
                        strncmp(r.chain.sent[0], FUNDING_HEX, 100) == 0,
                        "the recorded funding is rebroadcast");
        }
        rig_free(&r);
    }
    return 1;
}

/* ---- light-client wallet mock: counts reservations and releases ---- */
typedef struct {
    wallet_source_t base;
    int reserved, released;
    char last_released[65];
} mock_wallet_t;

static int mw_get_utxo(wallet_source_t *self, uint64_t min_sats, char txid_hex[65],
                       uint32_t *vout, uint64_t *amount, unsigned char *spk,
                       size_t *spk_len) {
    mock_wallet_t *w = (mock_wallet_t *)self;
    (void)min_sats;
    snprintf(txid_hex, 65, "%s",
             "abababababababababababababababababababababababababababababababab");
    *vout = 1;
    *amount = 500000;
    spk[0] = 0x51; spk[1] = 0x20;
    memset(spk + 2, 0x33, 32);
    *spk_len = 34;
    w->reserved++;
    return 1;
}
static int mw_change_spk(wallet_source_t *self, unsigned char *spk, size_t *spk_len) {
    (void)self;
    spk[0] = 0x51; spk[1] = 0x20;
    memset(spk + 2, 0x44, 32);
    *spk_len = 34;
    return 1;
}
static int mw_sign(wallet_source_t *self, unsigned char *tx, size_t *tx_len, size_t idx,
                   const unsigned char *spk, size_t spk_len, uint64_t amt) {
    (void)self; (void)tx; (void)tx_len; (void)idx; (void)spk; (void)spk_len; (void)amt;
    return 1;                                   /* left unsigned: parses as legacy */
}
static void mw_release(wallet_source_t *self, const char *txid_hex, uint32_t vout) {
    mock_wallet_t *w = (mock_wallet_t *)self;
    (void)vout;
    snprintf(w->last_released, 65, "%s", txid_hex);
    w->released++;
}

/* Light-client funding: the reserved wallet UTXO is released on every abort
   before the broadcast (here: the FUNDING marker cannot be written), kept
   while a recorded-but-unsent funding waits for its rebroadcast, and released
   once that rebroadcast succeeds. */
int test_rotation_funding_abort_releases_wallet_input(void) {
    rig_t r;
    TEST_ASSERT(rig_init(&r), "rig");
    int sp[2][2];
    for (int i = 0; i < 2; i++) {
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sp[i]) == 0, "socketpair");
        r.lsp->client_fds[i] = sp[i][0];
    }
    mock_wallet_t w;
    memset(&w, 0, sizeof(w));
    w.base.get_utxo = mw_get_utxo;
    w.base.get_change_spk = mw_change_spk;
    w.base.sign_input = mw_sign;
    w.base.release_utxo = mw_release;
    lsp_channel_mgr_t *m = r.mgr;
    m->wallet_src = &w.base;
    m->rot_fund_spk[0] = 0x51; m->rot_fund_spk[1] = 0x20;
    memset(m->rot_fund_spk + 2, 0x55, 32);
    m->rot_fund_spk_len = 34;
    lsp_rotation_progress_t *rp = &m->rot_progress;
    snprintf(rp->close_txid, 65, "%s", CLOSE1);
    TEST_ASSERT(rig_mark(&r, LSP_ROT_PROGRESS_CLOSED), "mark");

    /* 1. the FUNDING record cannot be written: not broadcast, UTXO released */
    TEST_ASSERT(persist_begin(&r.db), "caller transaction");
    TEST_ASSERT(rig_resume(&r) == 0, "aborts");
    persist_rollback(&r.db);
    TEST_ASSERT(w.reserved == 1 && w.released == 1, "reserved UTXO released on abort");
    TEST_ASSERT(r.chain.n_sent == 0, "nothing broadcast");
    TEST_ASSERT(rp->phase == LSP_ROT_PROGRESS_CLOSED && !rp->new_funding_hex,
                "nothing recorded");

    /* 2. recorded, broadcast refused: the UTXO stays reserved for the rebroadcast */
    r.chain.send_ok = 0;
    TEST_ASSERT(rig_resume(&r) == 0, "broadcast fails");
    TEST_ASSERT(w.reserved == 2 && w.released == 1, "reservation kept");
    TEST_ASSERT(rp->phase == LSP_ROT_PROGRESS_FUNDING && rp->new_funding_hex &&
                rp->fund_reserved == 1, "recorded funding, input reserved");
    TEST_ASSERT(r.chain.n_sent == 1, "one broadcast attempt");

    /* 3. the resume rebroadcasts the recorded TX, then releases the UTXO */
    r.chain.send_ok = 1;
    TEST_ASSERT(rig_resume(&r) == 0, "waits for the confirmation");
    TEST_ASSERT(r.chain.n_sent == 2 && strcmp(r.chain.sent[0], r.chain.sent[1]) == 0,
                "the same recorded TX is rebroadcast");
    TEST_ASSERT(w.released == 2 && rp->fund_reserved == 0, "released after broadcast");
    TEST_ASSERT(w.reserved == 2, "no second funding was built");

    for (int i = 0; i < 2; i++) {
        close(sp[i][0]);
        close(sp[i][1]);
        r.lsp->client_fds[i] = -1;
    }
    m->wallet_src = NULL;
    rig_free(&r);
    return 1;
}

/* Marker writes are standalone: refused while a caller transaction is open
   (a rollback would silently undo them). */
int test_rotation_marker_refused_in_open_txn(void) {
    rig_t r;
    TEST_ASSERT(rig_init(&r), "rig");
    snprintf(r.mgr->rot_progress.close_txid, 65, "%s", CLOSE1);
    TEST_ASSERT(persist_add_rotation_close(&r.db, DYING_HEX, CLOSE1, "c1hex"), "record close");
    TEST_ASSERT(rig_mark(&r, LSP_ROT_PROGRESS_CLOSING), "mark");
    mc_confirm(&r.chain, CLOSE1, 2);
    TEST_ASSERT(persist_begin(&r.db), "caller transaction");
    TEST_ASSERT(rig_resume(&r) == 0, "step fails");
    TEST_ASSERT(r.mgr->rot_progress.phase == LSP_ROT_PROGRESS_CLOSING,
                "in-memory phase unchanged when the write is refused");
    persist_rollback(&r.db);
    TEST_ASSERT(rig_disk_phase(&r) == LSP_ROT_PROGRESS_CLOSING, "disk unchanged");
    TEST_ASSERT(rig_resume(&r) == 0, "clients offline");
    TEST_ASSERT(r.mgr->rot_progress.phase == LSP_ROT_PROGRESS_CLOSED, "then CLOSED");
    rig_free(&r);
    return 1;
}

/* The spent-funding guard (no marker) recognizes a recorded rotation close
   and resumes instead of retiring the factory as "already rotated". */
int test_rotation_spent_guard_resumes_logged_close(void) {
    rig_t r;
    TEST_ASSERT(rig_init(&r), "rig");
    ladder_factory_t *lf = &r.lad->factories[0];
    lf->cached_state = FACTORY_DYING;
    lf->is_funded = 1;
    lsp_rotation_progress_clear(r.mgr);                 /* no marker at all */
    TEST_ASSERT(persist_add_rotation_close(&r.db, DYING_HEX, CLOSE1, "c1hex"), "record close");
    mc_confirm(&r.chain, CLOSE1, 4);
    r.chain.outpoint_unspent = 0;
    TEST_ASSERT(lsp_channels_rotate_factory(r.mgr, r.lsp) == 0, "clients offline");
    TEST_ASSERT(r.mgr->rot_progress.phase == LSP_ROT_PROGRESS_CLOSED, "resumed to CLOSED");
    TEST_ASSERT(strcmp(r.mgr->rot_progress.close_txid, CLOSE1) == 0, "the logged close");
    TEST_ASSERT(lf->partial_rotation_done == 1, "not offered for rotation again");
    TEST_ASSERT(r.chain.n_sent == 0, "no re-close, no funding");
    rig_free(&r);
    return 1;
}

int test_rotation_find_logged_close(void) {
    rig_t r;
    TEST_ASSERT(rig_init(&r), "rig");
    char out[65];
    TEST_ASSERT(lsp_rotation_find_logged_close(r.mgr, r.mgr->rot_progress.dying_funding_txid,
                                               out) == 0, "none recorded");
    TEST_ASSERT(persist_add_rotation_close(&r.db, DYING_HEX, CLOSE1, "c1hex"), "close 1");
    TEST_ASSERT(persist_add_rotation_close(&r.db, DYING_HEX, CLOSE2, "c2hex"), "close 2");
    TEST_ASSERT(lsp_rotation_find_logged_close(r.mgr, r.mgr->rot_progress.dying_funding_txid,
                                               out) == 0, "neither on chain");
    mc_to_mempool(&r.chain, CLOSE2);
    TEST_ASSERT(lsp_rotation_find_logged_close(r.mgr, r.mgr->rot_progress.dying_funding_txid,
                                               out) == 1 && strcmp(out, CLOSE2) == 0,
                "close 2 in the mempool");
    mc_confirm(&r.chain, CLOSE1, 1);
    TEST_ASSERT(lsp_rotation_find_logged_close(r.mgr, r.mgr->rot_progress.dying_funding_txid,
                                               out) == 2 && strcmp(out, CLOSE1) == 0,
                "a confirmed close wins");
    rig_free(&r);
    return 1;
}

int test_rotation_progress_persist_roundtrip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    uint64_t amounts[3] = { 1, 2000000000000ULL, 777 };
    persist_rotation_progress_t w;
    memset(&w, 0, sizeof(w));
    w.dying_funding_vout = 3;
    w.dying_factory_id = 7;
    w.phase = LSP_ROT_PROGRESS_FUNDED;
    snprintf(w.close_txid, 65, "%s", CLOSE1);
    snprintf(w.new_funding_txid, 65, "%s", FUND1);
    w.new_funding_hex = "0200beef";
    w.new_funding_vout = 1;
    w.new_funding_amount = 800000;
    w.new_cltv = 1234;
    w.dist_amounts = amounts;
    w.n_dist_amounts = 3;
    TEST_ASSERT(persist_save_rotation_progress(&db, DYING_HEX, &w), "save");
    uint64_t back[8] = {0};
    persist_rotation_progress_t r;
    memset(&r, 0, sizeof(r));
    r.dist_amounts = back;
    TEST_ASSERT(persist_load_rotation_progress(&db, DYING_HEX, &r, 8), "load");
    TEST_ASSERT(r.dying_funding_vout == 3 && r.dying_factory_id == 7 &&
                r.phase == LSP_ROT_PROGRESS_FUNDED, "ids + phase");
    TEST_ASSERT(strcmp(r.close_txid, CLOSE1) == 0 && strcmp(r.new_funding_txid, FUND1) == 0,
                "txids");
    TEST_ASSERT(r.new_funding_hex && strcmp(r.new_funding_hex, "0200beef") == 0, "hex");
    TEST_ASSERT(r.new_funding_vout == 1 && r.new_funding_amount == 800000 &&
                r.new_cltv == 1234, "output + cltv");
    TEST_ASSERT(r.n_dist_amounts == 3 && back[1] == 2000000000000ULL && back[2] == 777,
                "distribution amounts");
    free(r.new_funding_hex);

    TEST_ASSERT(persist_add_rotation_close(&db, DYING_HEX, CLOSE1, "aa"), "close 1");
    TEST_ASSERT(persist_add_rotation_close(&db, DYING_HEX, CLOSE2, "bb"), "close 2");
    TEST_ASSERT(persist_add_rotation_close(&db, DYING_HEX, CLOSE1, "zz"), "idempotent");
    char closes[4][65];
    TEST_ASSERT(persist_list_rotation_closes(&db, DYING_HEX, closes, 4) == 2 &&
                strcmp(closes[0], CLOSE1) == 0 && strcmp(closes[1], CLOSE2) == 0,
                "every close, oldest first");
    char *h = persist_load_rotation_close_hex(&db, DYING_HEX, CLOSE1);
    TEST_ASSERT(h && strcmp(h, "aa") == 0, "first record kept");
    free(h);
    persist_close(&db);
    return 1;
}

/* A real segwit TX from regtest: 1 input, 9 outputs, key-path witness. */
static const char SEGWIT_HEX[] =
    "020000000001019b05cf432e788f7d7a31c0b0590d02c0ab2e8a0ab50d6f9f7d58aa962402e44c"
    "0000000000feffffff0975850100000000002251207aaf8430bbbbf158ee931683f9c0ea842c4b"
    "75a15ea03d932aa719d138e36f976186010000000000225120ca17ddda776110bbfdaf779dd291"
    "f16bfefdd3341d73d07d45a2b8fa97211a5f6186010000000000225120cb9fff860e438351cf8c"
    "4c6049d08194bff07420e7b5b49ddd25e5d5e767d76d618601000000000022512074d866a5a0ce"
    "ae208684947acbaa604ab66ab6daf122a1c7bf4125132ffe8ecd61860100000000002251200fc2"
    "d26643a00df519177e3c079bcfdc3af3b61b0b8543c987969fa4586fd7ec618601000000000022"
    "5120124d6aa0d0a4fa8b0b265588976441198bf42b5d106cf2dc1d6b683d07e9c6c26186010000"
    "000000225120fdb3b97cde5fc1d03a9940d371a5ab18b3371a71b3be7e1b6e08dac994da30fe61"
    "860100000000002251207c1da16b6337eae34d16cef3b455c31dc0ea78be350db78e099b9424f3"
    "31ce42f0000000000000000451024e730140a6d8dd6826a569afddd5909746b295d32700b91353"
    "7631330298bfbc0f297d97074e0045786d9aae77fd2258fb0abbcb4ab257919c17d416ffa65ca5"
    "7eb1e40e58190000";
static const char SEGWIT_TXID[] =
    "80331bb629934cf6ec8e656a5fc4bda3cdfb33be1f02833e8b9b86569d8210da";

int test_tx_txid_from_bytes(void) {
    size_t n = strlen(SEGWIT_HEX) / 2;
    unsigned char *tx = malloc(n);
    TEST_ASSERT(tx && hex_decode(SEGWIT_HEX, tx, n) == (int)n, "decode");
    unsigned char txid[32], rb[32];
    char disp[65];
    TEST_ASSERT(tx_txid_from_bytes(tx, n, txid), "segwit parses");
    for (int i = 0; i < 32; i++) rb[i] = txid[31 - i];
    hex_encode(rb, 32, disp);
    TEST_ASSERT(strcmp(disp, SEGWIT_TXID) == 0, "segwit txid matches bitcoind");

    /* The same TX without marker, flag and witness (legacy serialization)
       has the same txid. */
    size_t wit_start = n - 4 - 66;          /* 1 item of 64 bytes + 2 length bytes */
    unsigned char *legacy = malloc(n);
    TEST_ASSERT(legacy, "alloc");
    memcpy(legacy, tx, 4);
    memcpy(legacy + 4, tx + 6, wit_start - 6);
    memcpy(legacy + 4 + (wit_start - 6), tx + n - 4, 4);
    size_t ln = 4 + (wit_start - 6) + 4;
    TEST_ASSERT(tx_txid_from_bytes(legacy, ln, txid), "legacy parses");
    for (int i = 0; i < 32; i++) rb[i] = txid[31 - i];
    hex_encode(rb, 32, disp);
    TEST_ASSERT(strcmp(disp, SEGWIT_TXID) == 0, "legacy txid matches");

    TEST_ASSERT(!tx_txid_from_bytes(tx, n - 1, txid), "truncated TX rejected");
    TEST_ASSERT(!tx_txid_from_bytes(legacy, ln + 1, txid), "trailing byte rejected");
    free(legacy);
    free(tx);
    return 1;
}

/* bitcoind wallet: the inputs regtest_build_signed_payment locks (so nothing
   else spends them before the broadcast) are released by
   regtest_unlock_tx_inputs when the TX is abandoned. */
static int rr_locked_count(regtest_t *rt) {
    char *res = regtest_exec(rt, "listlockunspent", "");
    if (!res) return -1;
    cJSON *a = cJSON_Parse(res);
    free(res);
    int n = (a && cJSON_IsArray(a)) ? cJSON_GetArraySize(a) : -1;
    cJSON_Delete(a);
    return n;
}

int test_regtest_rotation_funding_unlock(void) {
    regtest_t rt;
    TEST_ASSERT(regtest_init(&rt), "bitcoind not running");
    regtest_create_wallet(&rt, "test_rot_unlock");
    char addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, addr, sizeof(addr)), "address");
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, addr);
    int before = rr_locked_count(&rt);
    TEST_ASSERT(before >= 0, "listlockunspent");
    char txid[65];
    char *hex = regtest_build_signed_payment(&rt, addr, 0.001, txid);
    TEST_ASSERT(hex, "build");
    TEST_ASSERT(rr_locked_count(&rt) > before, "inputs locked until broadcast");
    TEST_ASSERT(regtest_unlock_tx_inputs(&rt, hex) > 0, "unlock");
    TEST_ASSERT(rr_locked_count(&rt) == before, "inputs released on abandon");
    free(hex);
    return 1;
}
