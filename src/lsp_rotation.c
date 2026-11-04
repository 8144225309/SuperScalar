/* Factory rotation extracted from lsp_channels.c */
#include "superscalar/lsp_channels.h"
#include "superscalar/lsp_channels_internal.h"
#include "superscalar/wire.h"
#include "superscalar/jit_channel.h"
#include "superscalar/lsp_fund.h"
#include "superscalar/chain_backend.h"
#include "superscalar/fee.h"
#include "superscalar/persist.h"
#include "superscalar/factory.h"
#include "superscalar/ladder.h"
#include "superscalar/regtest.h"
#include "superscalar/adaptor.h"
#include "superscalar/musig.h"
#include "superscalar/readiness.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#include "superscalar/sha256.h"
#include "superscalar/lsp.h"
#include "superscalar/crash_inject.h"
#include "superscalar/tx_builder.h"
extern void hex_encode(const unsigned char *, size_t, char *);
extern int hex_decode(const char *, unsigned char *, size_t);
extern void reverse_bytes(unsigned char *, size_t);

/* --- Rotation retry helpers --- */

int lsp_rotation_should_retry(const lsp_channel_mgr_t *mgr,
                              uint32_t factory_id, uint32_t cur_height) {
    if (!(mgr->rot_attempted_mask & (1u << (factory_id & 31))))
        return 0;  /* never attempted */
    uint32_t idx = factory_id % 8;
    uint32_t retries = mgr->rot_retry_count[idx];
    uint32_t max_ret = mgr->rot_max_retries > 0 ? mgr->rot_max_retries : 3;
    if (retries > max_ret)
        return 0;   /* fallback already done */
    if (retries >= max_ret)
        return -1;  /* exhausted — time for fallback */
    /* Reorg guard: if height went backward, allow immediate retry */
    if (cur_height < mgr->rot_last_attempt_block[idx])
        return 1;  /* height regressed (reorg) — safe to retry now */
    /* Exponential backoff: base * 2^retries blocks (clamped to prevent overflow) */
    uint32_t base = mgr->rot_retry_base_delay > 0 ? mgr->rot_retry_base_delay : 2;
    uint32_t shift = retries < 30 ? retries : 30;
    uint32_t delay = base * (1u << shift);
    if (cur_height >= mgr->rot_last_attempt_block[idx] + delay)
        return 1;   /* enough blocks elapsed — retry now */
    return 0;        /* waiting for backoff */
}

void lsp_rotation_record_failure(lsp_channel_mgr_t *mgr,
                                 uint32_t factory_id, uint32_t cur_height) {
    uint32_t idx = factory_id % 8;
    mgr->rot_retry_count[idx]++;
    mgr->rot_last_attempt_block[idx] = cur_height;
}

void lsp_rotation_record_success(lsp_channel_mgr_t *mgr, uint32_t factory_id) {
    uint32_t idx = factory_id % 8;
    mgr->rot_retry_count[idx] = 0;
    mgr->rot_last_attempt_block[idx] = 0;
    /* Clear attempted mask so retry logic won't fire for this factory */
    mgr->rot_attempted_mask &= ~(1u << (factory_id & 31));
}

/* --- Rotation progress past the irreversible Phase B close ---

   Phase B (the dying factory's cooperative close) is the point of no return:
   the close pays every client's channel balance to the LSP wallet, so until
   Phase C has created AND signed the replacement factory, the clients' funds
   exist only in the LSP's wallet and books.  mgr->rot_progress (mirrored in
   the rotation_progress table) records how far such a rotation got, so a
   failure -- or a crash and restart -- after the close resumes Phase C
   (re-using an already-broadcast replacement funding TX, never funding twice)
   instead of re-running Phase A/B or reporting the spent funding as
   "already rotated". */

static regtest_t *rot_rt(const lsp_channel_mgr_t *mgr) {
    return mgr->watchtower ? mgr->watchtower->rt : NULL;
}

static void rot_txid_display(const unsigned char *txid32, char out[65]) {
    unsigned char rb[32];
    for (int i = 0; i < 32; i++) rb[i] = txid32[31 - i];
    hex_encode(rb, 32, out);
}

static int rot_chain_height(lsp_channel_mgr_t *mgr) {
    chain_backend_t *cb = (chain_backend_t *)mgr->chain_be;
    if (cb && cb->get_block_height) return cb->get_block_height(cb);
    regtest_t *rt = rot_rt(mgr);
    return rt ? regtest_get_block_height(rt) : -1;
}

static int rot_tx_confirmations(lsp_channel_mgr_t *mgr, const char *txid) {
    chain_backend_t *cb = (chain_backend_t *)mgr->chain_be;
    if (cb && cb->get_confirmations) return cb->get_confirmations(cb, txid);
    regtest_t *rt = rot_rt(mgr);
    return rt ? regtest_get_confirmations(rt, txid) : -1;
}

static int rot_tx_in_mempool(lsp_channel_mgr_t *mgr, const char *txid) {
    chain_backend_t *cb = (chain_backend_t *)mgr->chain_be;
    if (cb && cb->is_in_mempool) return cb->is_in_mempool(cb, txid) ? 1 : 0;
    regtest_t *rt = rot_rt(mgr);
    return (rt && regtest_is_in_mempool(rt, txid)) ? 1 : 0;
}

/* 1 = unspent, 0 = spent, -1 = unknown. */
static int rot_outpoint_unspent(lsp_channel_mgr_t *mgr, const char *txid_disp,
                                uint32_t vout) {
    chain_backend_t *cb = (chain_backend_t *)mgr->chain_be;
    if (cb && cb->is_outpoint_unspent) return cb->is_outpoint_unspent(cb, txid_disp, vout);
    regtest_t *rt = rot_rt(mgr);
    return rt ? regtest_outpoint_unspent(rt, txid_disp, vout) : -1;
}

static void rot_progress_to_row(lsp_rotation_progress_t *rp,
                                persist_rotation_progress_t *row) {
    memset(row, 0, sizeof(*row));
    row->dying_funding_vout = rp->dying_funding_vout;
    row->dying_factory_id = rp->dying_factory_id;
    row->phase = rp->phase;
    memcpy(row->close_txid, rp->close_txid, sizeof(row->close_txid));
    memcpy(row->new_funding_txid, rp->new_funding_txid, sizeof(row->new_funding_txid));
    row->new_funding_hex = rp->new_funding_hex;          /* borrowed */
    row->new_funding_vout = rp->new_funding_vout;
    row->new_funding_amount = rp->new_funding_amount;
    row->new_cltv = rp->new_cltv;
    row->dist_amounts = rp->dist_amounts;
    row->n_dist_amounts = rp->n_dist_amounts;
    memcpy(row->tree_digest, rp->tree_digest, sizeof(row->tree_digest));
    row->dist_tx_hex = rp->dist_tx_hex;                  /* borrowed */
}

/* Write mgr->rot_progress.  Returns 0 if it could not be recorded: every
   caller treats that as a failed rotation step (a marker that is not on disk
   cannot guard the irreversible step that follows it).

   Marker writes are standalone statements on mgr->persist.  No caller
   transaction may be open: a later rollback of that transaction would
   silently undo the marker.  (SIGNED is the one exception, written on
   purpose inside the factory-persist transaction -- not through here.) */
static int rot_progress_persist(lsp_channel_mgr_t *mgr) {
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    persist_t *db = (persist_t *)mgr->persist;
    if (!db) return 1;                       /* no DB: in-memory marker only */
    if (persist_in_transaction(db)) {
        fprintf(stderr, "LSP rotate: BUG: rotation marker write (phase %d) inside an "
                "open transaction -- refusing\n", rp->phase);
        return 0;
    }
    char dtx[65];
    rot_txid_display(rp->dying_funding_txid, dtx);
    persist_rotation_progress_t row;
    rot_progress_to_row(rp, &row);
    if (!persist_save_rotation_progress(db, dtx, &row)) {
        fprintf(stderr, "LSP rotate: could not persist rotation progress (phase %d) "
                "-- stopping this rotation step\n", rp->phase);
        return 0;
    }
    return 1;
}

/* Move to PHASE and record it; on failure the in-memory phase is unchanged. */
static int rot_progress_set_phase(lsp_channel_mgr_t *mgr, int phase) {
    int old = mgr->rot_progress.phase;
    mgr->rot_progress.phase = phase;
    if (!rot_progress_persist(mgr)) {
        mgr->rot_progress.phase = old;
        return 0;
    }
    return 1;
}

/* Light client: release a funding input still reserved in the wallet. */
static void rot_release_reservation(lsp_channel_mgr_t *mgr) {
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    wallet_source_t *ws = (wallet_source_t *)mgr->wallet_src;
    if (rp->fund_reserved && ws && ws->release_utxo)
        ws->release_utxo(ws, rp->fund_reserved_txid, rp->fund_reserved_vout);
    rp->fund_reserved = 0;
}

void lsp_rotation_progress_clear(lsp_channel_mgr_t *mgr) {
    if (!mgr) return;
    rot_release_reservation(mgr);
    free(mgr->rot_progress.new_funding_hex);
    free(mgr->rot_progress.dist_tx_hex);
    memset(&mgr->rot_progress, 0, sizeof(mgr->rot_progress));
}

int lsp_rotation_progress_pending(const lsp_channel_mgr_t *mgr) {
    return mgr && mgr->rot_progress.phase >= LSP_ROT_PROGRESS_CLOSING &&
           mgr->rot_progress.phase <= LSP_ROT_PROGRESS_SIGNING_READY;
}

int lsp_rotation_load_progress(lsp_channel_mgr_t *mgr,
                               const unsigned char *dying_funding_txid32,
                               uint32_t dying_funding_vout) {
    if (!mgr || !mgr->persist || !dying_funding_txid32) return 0;
    char dtx[65];
    rot_txid_display(dying_funding_txid32, dtx);
    lsp_rotation_progress_t *rp = malloc(sizeof(*rp));
    if (!rp) return 0;
    memset(rp, 0, sizeof(*rp));
    persist_rotation_progress_t row;
    memset(&row, 0, sizeof(row));
    row.dist_amounts = rp->dist_amounts;
    if (!persist_load_rotation_progress((persist_t *)mgr->persist, dtx, &row,
                                        FACTORY_MAX_SIGNERS)) {
        free(rp);
        return 0;
    }
    if (row.dying_funding_vout != dying_funding_vout ||
        row.phase < LSP_ROT_PROGRESS_CLOSING || row.phase > LSP_ROT_PROGRESS_SIGNING_READY) {
        free(row.new_funding_hex);
        free(row.dist_tx_hex);
        free(rp);
        return 0;
    }
    rp->phase = row.phase;
    rp->dying_factory_id = row.dying_factory_id;
    memcpy(rp->dying_funding_txid, dying_funding_txid32, 32);
    rp->dying_funding_vout = row.dying_funding_vout;
    memcpy(rp->close_txid, row.close_txid, sizeof(rp->close_txid));
    memcpy(rp->new_funding_txid, row.new_funding_txid, sizeof(rp->new_funding_txid));
    rp->new_funding_hex = row.new_funding_hex;           /* ownership moves */
    rp->new_funding_vout = row.new_funding_vout;
    rp->new_funding_amount = row.new_funding_amount;
    rp->new_cltv = row.new_cltv;
    rp->n_dist_amounts = row.n_dist_amounts;
    memcpy(rp->tree_digest, row.tree_digest, sizeof(rp->tree_digest));
    rp->dist_tx_hex = row.dist_tx_hex;                   /* ownership moves */
    lsp_rotation_progress_clear(mgr);
    mgr->rot_progress = *rp;
    free(rp);
    return 1;
}

int lsp_rotation_find_logged_close(lsp_channel_mgr_t *mgr,
                                   const unsigned char *dying_funding_txid32,
                                   char *close_txid_out65) {
    if (!mgr || !mgr->persist || !dying_funding_txid32) return 0;
    char dtx[65];
    rot_txid_display(dying_funding_txid32, dtx);
    char closes[16][65];
    size_t n = persist_list_rotation_closes((persist_t *)mgr->persist, dtx, closes, 16);
    int best = 0;
    for (size_t i = 0; i < n; i++) {
        if (rot_tx_confirmations(mgr, closes[i]) >= 1) {
            if (close_txid_out65) memcpy(close_txid_out65, closes[i], 65);
            return 2;
        }
        if (!best && rot_tx_in_mempool(mgr, closes[i])) {
            if (close_txid_out65) memcpy(close_txid_out65, closes[i], 65);
            best = 1;
        }
    }
    return best;
}

/* Broadcast a signed TX (hex) through the configured chain. */
static int rot_send_hex(lsp_channel_mgr_t *mgr, const char *hex, char *txid_out65) {
    chain_backend_t *cb = (chain_backend_t *)mgr->chain_be;
    if (cb && cb->send_raw_tx) return cb->send_raw_tx(cb, hex, txid_out65);
    regtest_t *rt = rot_rt(mgr);
    return rt ? regtest_send_raw_tx(rt, hex, txid_out65) : 0;
}

/* A replacement funding TX built and signed but not (yet) broadcast, and
   what holds its wallet inputs: bitcoind locks them (fundrawtransaction
   lockUnspents); a light-client wallet keeps one UTXO reserved. */
typedef struct {
    char *hex;
    char txid[65];
    int light;
    char res_txid[65];
    uint32_t res_vout;
} rot_funding_tx_t;

static int rot_build_funding_tx(lsp_channel_mgr_t *mgr, rot_funding_tx_t *b) {
    memset(b, 0, sizeof(*b));
    regtest_t *rt = rot_rt(mgr);
    if (rt) {
        b->hex = regtest_build_signed_payment(rt, mgr->rot_fund_addr,
                                              (double)mgr->rot_funding_sats / 100000000.0,
                                              b->txid);
        return b->hex != NULL;
    }
    wallet_source_t *ws = (wallet_source_t *)mgr->wallet_src;
    if (!ws || !mgr->chain_be) {
        fprintf(stderr, "LSP rotate: no wallet/chain for light-client funding\n");
        return 0;
    }
    b->hex = lsp_fund_spk_build(ws, mgr->rot_fund_spk, mgr->rot_fund_spk_len,
                                mgr->rot_funding_sats, 0, b->txid,
                                b->res_txid, &b->res_vout);
    b->light = b->hex != NULL;
    return b->hex != NULL;
}

/* The TX will never be broadcast: give its wallet inputs back. */
static void rot_funding_abandon(lsp_channel_mgr_t *mgr, rot_funding_tx_t *b) {
    wallet_source_t *ws = (wallet_source_t *)mgr->wallet_src;
    regtest_t *rt = rot_rt(mgr);
    if (b->light) {
        if (ws && ws->release_utxo) ws->release_utxo(ws, b->res_txid, b->res_vout);
    } else if (b->hex && rt && regtest_unlock_tx_inputs(rt, b->hex) < 0) {
        fprintf(stderr, "LSP rotate: WARNING: could not unlock the abandoned funding "
                "TX's wallet inputs (lockunspent)\n");
    }
    free(b->hex);
    memset(b, 0, sizeof(*b));
}

/* 1 if TXID:VOUT -- an output of a CONFIRMED TX -- is spent in the chain,
   0 if not, -1 if unknown. */
static int rot_input_spent_confirmed(lsp_channel_mgr_t *mgr, const char *txid,
                                     uint32_t vout) {
    if (rot_tx_confirmations(mgr, txid) < 1) return -1;
    regtest_t *rt = rot_rt(mgr);
    if (rt) return regtest_outpoint_spent_in_chain(rt, txid, vout);
    chain_backend_t *cb = (chain_backend_t *)mgr->chain_be;
    if (cb && cb->is_outpoint_unspent) {
        int u = cb->is_outpoint_unspent(cb, txid, vout);
        return u == 0 ? 1 : (u == 1 ? 0 : -1);
    }
    return -1;
}

/* 1 if an input of the recorded funding is spent in the chain (its TX
   confirmed), 0 if none is. */
static int rot_funding_input_spent(lsp_channel_mgr_t *mgr) {
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    if (!rp->new_funding_hex) return 0;
    size_t n = strlen(rp->new_funding_hex) / 2;
    unsigned char *bytes = malloc(n ? n : 1);
    unsigned char (*prev)[32] = calloc(64, 32);
    uint32_t vouts[64];
    size_t n_in = 0;
    int ok = bytes && prev && hex_decode(rp->new_funding_hex, bytes, n) == (int)n &&
             tx_parse_inputs(bytes, n, prev, vouts, 64, &n_in);
    int spent = 0;
    for (size_t i = 0; ok && !spent && i < n_in && i < 64; i++) {
        char disp[65];
        rot_txid_display(prev[i], disp);
        if (rot_input_spent_confirmed(mgr, disp, vouts[i]) == 1) spent = 1;
    }
    free(bytes);
    free(prev);
    return spent;
}

/* Depth a spend that conflicts with the recorded funding must reach before
   the record is dropped: the network's funding / close confirmation setting
   (regtest 1). */
static int rot_conflict_safe_depth(lsp_channel_mgr_t *mgr) {
    chain_backend_t *cb = (chain_backend_t *)mgr->chain_be;
    if (cb) {
        int r = cb->is_regtest || mgr->rot_is_regtest;
        int f = chain_funding_confs(cb, r), c = chain_close_confs(cb, r);
        return f > c ? f : c;
    }
    regtest_t *rt = rot_rt(mgr);
    if (rt) return regtest_network_safe_confirmation_depth(rt);
    return CONF_DEFAULT_CLOSE;
}

/* Depth of the confirmed TX that spends an input of the recorded funding:
   from the bitcoind wallet when it knows the funding (conflicted = negative
   confirmations), otherwise how many blocks the spend has been seen in the
   chain.  0 = no such spend (a reorg that undid it resets the count). */
static int rot_funding_conflict_depth(lsp_channel_mgr_t *mgr) {
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    regtest_t *rt = rot_rt(mgr);
    if (rt && rp->new_funding_txid[0]) {
        int d = regtest_wallet_conflict_depth(rt, rp->new_funding_txid);
        if (d > 0) return d;
    }
    if (!rot_funding_input_spent(mgr)) {
        rp->conflict_seen_height = 0;
        return 0;
    }
    int h = rot_chain_height(mgr);
    if (h <= 0) return 0;
    if (rp->conflict_seen_height == 0 || (uint32_t)h < rp->conflict_seen_height)
        rp->conflict_seen_height = (uint32_t)h;
    return h - (int)rp->conflict_seen_height + 1;
}

/* Called by the creation ceremony right before the first FACTORY_READY:
   record SIGNING_READY with the tree's digest and its signed distribution
   TX.  Refusing (the marker cannot be written) aborts the ceremony while no
   client holds the tree. */
static int rot_before_factory_ready(void *lsp_v, const factory_t *f, void *ctx) {
    (void)lsp_v;
    lsp_channel_mgr_t *mgr = (lsp_channel_mgr_t *)ctx;
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    /* Restart drill: every signature is aggregated, no client has
       FACTORY_READY yet. */
    lsp_crash_checkpoint("rotate_ceremony_before_ready");
    unsigned char d[32];
    if (!lsp_factory_tree_digest(f, d)) {
        fprintf(stderr, "LSP rotate: could not digest the replacement tree -- not "
                "delivering it\n");
        return 0;
    }
    char dh[65];
    hex_encode(d, 32, dh);
    char *dist = NULL;
    if (f->dist_tx_ready == 2 && f->dist_signed_tx.len > 0) {
        dist = malloc(f->dist_signed_tx.len * 2 + 1);
        if (!dist) return 0;
        hex_encode(f->dist_signed_tx.data, f->dist_signed_tx.len, dist);
    }
    char saved_digest[65];
    memcpy(saved_digest, rp->tree_digest, sizeof(saved_digest));
    char *saved_dist = rp->dist_tx_hex;
    int saved_phase = rp->phase;
    memcpy(rp->tree_digest, dh, sizeof(rp->tree_digest));
    rp->dist_tx_hex = dist;
    if (!rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_SIGNING_READY)) {
        memcpy(rp->tree_digest, saved_digest, sizeof(rp->tree_digest));
        rp->dist_tx_hex = saved_dist;
        rp->phase = saved_phase;
        free(dist);
        return 0;
    }
    free(saved_dist);
    printf("LSP rotate: replacement tree %s recorded (SIGNING_READY); delivering "
           "FACTORY_READY\n", dh);
    fflush(stdout);
    return 1;
}

int lsp_rotation_signed_tree_matches(lsp_channel_mgr_t *mgr, lsp_t *lsp) {
    if (!mgr || !lsp) return -1;
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    if (strlen(rp->tree_digest) != 64 || !rp->new_funding_txid[0] ||
        rp->new_funding_vout == UINT32_MAX)
        return -1;
    unsigned char ftxid[32];
    if (hex_decode(rp->new_funding_txid, ftxid, 32) != 32) return -1;
    reverse_bytes(ftxid, 32);
    const uint64_t *sa = lsp->dist_client_amounts;
    size_t sn = lsp->dist_n_client_amounts;
    lsp->dist_client_amounts = rp->dist_amounts;
    lsp->dist_n_client_amounts = rp->n_dist_amounts;
    unsigned char d[32];
    int ok = lsp_factory_creation_digest(lsp, lsp->client_pubkeys, lsp->n_clients,
                                         ftxid, rp->new_funding_vout,
                                         rp->new_funding_amount,
                                         mgr->rot_fund_spk, mgr->rot_fund_spk_len,
                                         mgr->rot_step_blocks,
                                         mgr->rot_states_per_layer, rp->new_cltv, d);
    lsp->dist_client_amounts = sa;
    lsp->dist_n_client_amounts = sn;
    if (!ok) return -1;
    char dh[65];
    hex_encode(d, 32, dh);
    return strcmp(dh, rp->tree_digest) == 0 ? 1 : 0;
}

int lsp_rotation_ceremony_failed(lsp_channel_mgr_t *mgr, size_t delivered,
                                 int delivered_before) {
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    if (delivered == 0 && !delivered_before &&
        rp->phase != LSP_ROT_PROGRESS_SIGNING_READY) {
        /* The hook never recorded SIGNING_READY and nothing was sent: no
           client can hold the signed tree, so the ceremony may run again. */
        fprintf(stderr, "LSP rotate: new factory creation failed before its signed tree "
                "could reach any client (rotation stays resumable over the recorded "
                "funding)\n");
        if (rp->phase != LSP_ROT_PROGRESS_FUNDED &&
            !rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_FUNDED))
            fprintf(stderr, "LSP rotate: could not record FUNDED; the restart "
                    "re-runs the ceremony from the marker on disk\n");
    } else {
        /* SIGNING_READY was recorded: a FACTORY_READY may have reached a client
           (even a failed first send can deliver bytes).  Never lowered; any
           further ceremony goes through the byte-identical-tree gate. */
        fprintf(stderr, "LSP rotate: new factory creation failed after SIGNING_READY "
                "(%zu FACTORY_READY sent%s) -- held at SIGNING_READY: a ceremony runs "
                "again only over a byte-identical tree\n", delivered,
                delivered_before ? ", an earlier ceremony may have delivered" : "");
    }
    return rp->phase;
}

/* SIGNING_READY and the tree cannot be rebuilt byte-identically: hold, and
   tell the operator exactly what is recorded and what to do. */
static void rot_report_signing_hold(lsp_channel_mgr_t *mgr, int why) {
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    if (rp->hold_reported) return;
    rp->hold_reported = 1;
    char dtx[65], dist_txid[65] = "(none recorded)";
    rot_txid_display(rp->dying_funding_txid, dtx);
    if (rp->dist_tx_hex) {
        size_t n = strlen(rp->dist_tx_hex) / 2;
        unsigned char *b = malloc(n ? n : 1);
        unsigned char t[32];
        if (b && hex_decode(rp->dist_tx_hex, b, n) == (int)n && tx_txid_from_bytes(b, n, t))
            rot_txid_display(t, dist_txid);
        free(b);
    }
    fprintf(stderr,
        "LSP rotate: HOLD: FACTORY_READY for the replacement over %s:%u was (or may "
        "have been) delivered -- recorded tree digest %s -- and the tree rebuilt now %s: "
        "NOT signing a different tree over that output.\n"
        "LSP rotate: operator: (1) keep the DB: rotation_progress row of dying funding "
        "%s holds the funding, CLTV %u, the distribution amounts and the tree digest.\n"
        "LSP rotate: operator: (2) if the mismatch is configuration (factory shape, the "
        "client set or order, step blocks, states per layer), restart with the "
        "configuration the rotation ran with; a multi-level shape is not restored from "
        "the DB on restart (known gap). The resume runs the ceremony again as soon as "
        "the rebuilt tree matches.\n"
        "LSP rotate: operator: (3) otherwise broadcast the recorded signed distribution "
        "TX %s (rotation_progress.dist_tx_hex, sendrawtransaction) after block %u: it "
        "pays every client its recorded amount from the replacement funding.\n",
        rp->new_funding_txid, rp->new_funding_vout, rp->tree_digest,
        why == 0 ? "differs" : "could not be rebuilt", dtx, rp->new_cltv,
        dist_txid, rp->new_cltv);
}

/* The replacement funding output (rot_fund_spk) of TXID. */
static int rot_find_funding_output(lsp_channel_mgr_t *mgr, const char *txid,
                                   uint32_t *vout, uint64_t *amount) {
    regtest_t *rt = rot_rt(mgr);
    if (rt) {
        for (uint32_t v = 0; v < 4; v++) {
            uint64_t amt = 0;
            unsigned char spk[256];
            size_t spk_len = 0;
            regtest_get_tx_output(rt, txid, v, &amt, spk, &spk_len);
            if (amt > 0 && spk_len == mgr->rot_fund_spk_len &&
                memcmp(spk, mgr->rot_fund_spk, mgr->rot_fund_spk_len) == 0) {
                *vout = v;
                *amount = amt;
                return 1;
            }
        }
        return 0;
    }
    /* Light client: lsp_fund_spk_build puts the target at vout 0. */
    *vout = 0;
    *amount = mgr->rot_funding_sats;
    return 1;
}

/* Fix the ceremony parameters once, when the replacement funding is
   confirmed: every ceremony over that funding (first run or after a restart)
   then builds byte-identical transactions.  (The hashlock-poison seed is
   derived from the LSP key + the funding outpoint, so it is fixed too.) */
static void rot_fix_ceremony_params(lsp_channel_mgr_t *mgr) {
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    int h = rot_chain_height(mgr);
    rp->new_cltv = h > 0 ? (uint32_t)h + (mgr->rot_is_regtest ? 35u : 1008u) : 0;
    rp->n_dist_amounts = 0;
    for (size_t c = 0; c < mgr->n_channels && c < FACTORY_MAX_SIGNERS; c++)
        rp->dist_amounts[rp->n_dist_amounts++] = mgr->entries[c].channel.funding_amount;
}

static int rotation_create_replacement(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                       ladder_t *lad, uint32_t dying_id,
                                       int partial, persist_t *rot_db,
                                       const unsigned char *rot_cer_id,
                                       int rot_cer_persisted);

/* --- Factory rotation --- */


/* Dry-run the replacement factory's setup over PKS (the clients that will be
   in it): allocation, tree shape, hashlock poison -- the exact code
   lsp_run_factory_creation runs, via lsp_factory_creation_preflight -- and,
   on a bitcoind wallet that does not auto-mine, whether the wallet can fund
   it (CLOSE_INFLOW_SATS: what a full close pays back to it first).  Changes
   nothing.  Returns 1 when Phase C would build. */
static int rotation_preflight(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                              const secp256k1_pubkey *pks, size_t n_pks,
                              size_t min_pks, uint64_t close_inflow_sats) {
    uint64_t pf_amounts[FACTORY_MAX_SIGNERS];
    size_t pf_n_amounts = 0;
    for (size_t c = 0; c < mgr->n_channels && c < FACTORY_MAX_SIGNERS; c++)
        pf_amounts[pf_n_amounts++] = mgr->entries[c].channel.funding_amount;
    int pf_h = rot_chain_height(mgr);
    uint32_t pf_cltv = pf_h > 0
        ? (uint32_t)pf_h + (mgr->rot_is_regtest ? 35u : 1008u) : 0;
    const uint64_t *pf_saved_amts = lsp->dist_client_amounts;
    size_t pf_saved_n = lsp->dist_n_client_amounts;
    lsp->dist_client_amounts = pf_amounts;
    lsp->dist_n_client_amounts = pf_n_amounts;
    int pf_ok = n_pks >= min_pks &&
        lsp_factory_creation_preflight(lsp, pks, n_pks, mgr->rot_funding_sats,
                                       mgr->rot_fund_spk, mgr->rot_fund_spk_len,
                                       mgr->rot_step_blocks,
                                       mgr->rot_states_per_layer, pf_cltv);
    lsp->dist_client_amounts = pf_saved_amts;
    lsp->dist_n_client_amounts = pf_saved_n;
    regtest_t *rt = mgr->watchtower ? mgr->watchtower->rt : NULL;
    if (pf_ok && rt && !mgr->rot_is_regtest) {
        double pf_bal = regtest_get_balance(rt);
        double pf_in = (double)close_inflow_sats / 100000000.0;
        double pf_need = (double)mgr->rot_funding_sats / 100000000.0;
        if (pf_bal + pf_in < pf_need) {
            fprintf(stderr, "LSP rotate: preflight: wallet %.8f + close inflow %.8f "
                    "< %.8f needed for the replacement factory\n",
                    pf_bal, pf_in, pf_need);
            pf_ok = 0;
        }
    }
    return pf_ok;
}

int lsp_channels_rotate_factory(lsp_channel_mgr_t *mgr, lsp_t *lsp) {
    if (!mgr || !lsp || !mgr->ladder) return 0;

    ladder_t *lad = (ladder_t *)mgr->ladder;
    fee_estimator_t *fe = (fee_estimator_t *)mgr->rot_fee_est;
    if (!fe) return 0;

    /* A rotation that already crossed its irreversible Phase B close is
       resumed, never restarted: re-running Phase A/B would try to close a
       funding output that is already spent. */
    if (lsp_rotation_progress_pending(mgr))
        return lsp_rotation_resume(mgr, lsp);

    /* Find the DYING (or EXPIRED) factory to rotate from.
       Factory may skip DYING if blocks mine faster than the daemon polls. */
    ladder_factory_t *dying = ladder_get_dying(lad);
    if (!dying) {
        /* Fallback: look for the first EXPIRED factory that hasn't been rotated */
        for (size_t i = 0; i < lad->n_factories; i++) {
            if (lad->factories[i].cached_state == FACTORY_EXPIRED &&
                lad->factories[i].is_initialized &&
                !lad->factories[i].partial_rotation_done) {
                dying = &lad->factories[i];
                break;
            }
        }
    }
    if (!dying) {
        fprintf(stderr, "LSP rotate: no DYING/EXPIRED factory found\n");
        return 0;
    }
    uint32_t dying_id = dying->factory_id;

    /* #332 restart-resume idempotency guard.  On a crash mid-rotation AFTER the
       Phase B cooperative close was broadcast but BEFORE the ROTATE ceremony
       reached FINALIZED, a restart re-enters here via the daemon retry path
       (the factory is still DYING and the in-memory retry/attempt state was
       reset by the fresh process).  Re-running Phase B would rebuild a
       DIFFERENT close (fresh wallet address) and rebroadcast it — a double-spend
       the mempool rejects — and Phase C could re-fund a SECOND replacement
       factory from the LSP wallet, stranding LSP liquidity.  If the dying
       factory's funding outpoint is already spent AND the rotation-progress
       marker shows it was this LSP's own rotation close, the replacement
       factory still has to be created: resume Phase C (lsp_rotation_resume;
       no re-close, never a second funding).  Spent with no marker (e.g. by the
       distribution TX, or a DB from before the marker existed): nothing to
       rotate -- retire idempotently (clear retry state).  Fail OPEN — act only on a DEFINITIVE spent (0); proceed
       normally on unspent (1) or unknown/error/unimplemented (-1) so a transient
       chain hiccup can never block a legitimate rotation. */
    if (dying->is_funded) {
        regtest_t *grt = mgr->watchtower ? mgr->watchtower->rt : NULL;
        chain_backend_t *gchain = (chain_backend_t *)mgr->chain_be;
        if (grt || (gchain && gchain->is_outpoint_unspent)) {
            /* funding_txid is stored internal-order; the display txid that
               gettxout expects is the byte-reverse (see factory_recovery.c). */
            unsigned char rb[32];
            char fund_disp[65];
            memcpy(rb, dying->factory.funding_txid, 32);
            for (int bi = 0; bi < 16; bi++) {
                unsigned char tmp = rb[bi]; rb[bi] = rb[31 - bi]; rb[31 - bi] = tmp;
            }
            for (int bi = 0; bi < 32; bi++)
                snprintf(fund_disp + bi * 2, 3, "%02x", rb[bi]);
            int unspent = (gchain && gchain->is_outpoint_unspent)
                ? gchain->is_outpoint_unspent(gchain, fund_disp, dying->factory.funding_vout)
                : regtest_outpoint_unspent(grt, fund_disp, dying->factory.funding_vout);
            if (unspent == 0 &&
                lsp_rotation_load_progress(mgr, dying->factory.funding_txid,
                                           dying->factory.funding_vout)) {
                printf("LSP rotate: factory %u funding %s:%u already spent by this "
                       "LSP's rotation close %s — resuming Phase C (no re-close)\n",
                       dying_id, fund_disp, dying->factory.funding_vout,
                       mgr->rot_progress.close_txid);
                fflush(stdout);
                return lsp_rotation_resume(mgr, lsp);
            }
            if (unspent == 0) {
                /* No pending marker, but the spender may still be one of this
                   LSP's recorded rotation closes (a marker cleared after an
                   eviction, then that close confirmed after all): resume. */
                char logged[65];
                int lc = lsp_rotation_find_logged_close(mgr, dying->factory.funding_txid,
                                                        logged);
                if (lc > 0) {
                    printf("LSP rotate: factory %u funding %s:%u was spent by this LSP's "
                           "recorded rotation close %s (%s) — resuming (no re-close)\n",
                           dying_id, fund_disp, dying->factory.funding_vout, logged,
                           lc == 2 ? "confirmed" : "in the mempool");
                    fflush(stdout);
                    lsp_rotation_progress_clear(mgr);
                    mgr->rot_progress.dying_factory_id = dying_id;
                    memcpy(mgr->rot_progress.dying_funding_txid,
                           dying->factory.funding_txid, 32);
                    mgr->rot_progress.dying_funding_vout = dying->factory.funding_vout;
                    snprintf(mgr->rot_progress.close_txid,
                             sizeof(mgr->rot_progress.close_txid), "%s", logged);
                    mgr->rot_progress.new_funding_vout = UINT32_MAX;
                    if (!rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_CLOSING)) {
                        lsp_rotation_progress_clear(mgr);
                        return 0;
                    }
                    return lsp_rotation_resume(mgr, lsp);
                }
            }
            if (unspent == 0) {
                printf("LSP rotate: factory %u funding %s:%u already spent — a prior "
                       "attempt already broadcast the close; completing rotation "
                       "idempotently (no re-broadcast, no re-fund)\n",
                       dying_id, fund_disp, dying->factory.funding_vout);
                fflush(stdout);
                dying->partial_rotation_done = 1;             /* drop from rotation candidates */
                lsp_rotation_record_success(mgr, dying_id);   /* clear retry/attempt state */
                return 1;                                     /* fund-safe idempotent success */
            }
        }
    }

    printf("LSP rotate: starting rotation for factory %u\n", dying_id);
    fflush(stdout);

    /* Preflight BEFORE Phase A.  Phase A hands each cooperating client's
       factory key to this LSP, so a deterministic Phase C failure must be
       caught while no key has left a client and the old factory needs nothing
       from them.  Checked over the clients online now (the set Phase A will
       ask); the pre-close preflight below re-checks the final, possibly
       partial, set. */
    {
        secp256k1_pubkey *pre_pks = calloc(lsp->n_clients ? lsp->n_clients : 1,
                                           sizeof(secp256k1_pubkey));
        if (!pre_pks) return 0;
        size_t n_pre = 0;
        for (size_t i = 0; i < lsp->n_clients; i++)
            if (lsp->client_fds[i] >= 0)
                pre_pks[n_pre++] = lsp->client_pubkeys[i];
        int all_online = (n_pre == lsp->n_clients);
        int pre_ok = rotation_preflight(mgr, lsp, pre_pks, n_pre,
                                        all_online ? 1u : 2u,
                                        all_online ? dying->factory.funding_amount_sats : 0);
        free(pre_pks);
        if (!pre_ok) {
            fprintf(stderr, "LSP rotate: preflight FAILED — aborting BEFORE key "
                    "turnover; factory %u is untouched and no client key was "
                    "requested (%zu/%zu clients online)\n",
                    dying_id, n_pre, lsp->n_clients);
            return 0;
        }
    }

    /* Drain any in-flight HTLCs before rotation.
       If HTLCs are mid-flight during rotation, they get stranded because
       the old factory is freed. Fail them cleanly first. */
    {
        int htlcs_pending = 0;
        for (size_t c = 0; c < mgr->n_channels; c++) {
            channel_t *ch = &mgr->entries[c].channel;
            for (size_t h = 0; h < ch->n_htlcs; h++) {
                if (ch->htlcs[h].state == HTLC_STATE_ACTIVE)
                    htlcs_pending++;
            }
        }
        if (htlcs_pending > 0) {
            printf("LSP rotate: draining %d in-flight HTLCs before rotation\n",
                   htlcs_pending);
            for (size_t c = 0; c < mgr->n_channels; c++) {
                channel_t *ch = &mgr->entries[c].channel;
                for (size_t h = 0; h < ch->n_htlcs; ) {
                    if (ch->htlcs[h].state == HTLC_STATE_ACTIVE) {
                        channel_fail_htlc(ch, ch->htlcs[h].id);
                        /* channel_fail_htlc removes the entry, don't increment h */
                    } else {
                        h++;
                    }
                }
            }
        }
    }

    /* Build combined keypair/pubkey arrays for adaptor protocol */
    size_t n_total = 1 + lsp->n_clients;
    secp256k1_keypair rot_kps[FACTORY_MAX_SIGNERS];
    secp256k1_pubkey rot_pks[FACTORY_MAX_SIGNERS];

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(mgr->ctx, &lsp_kp, mgr->rot_lsp_seckey))
        return 0;
    rot_kps[0] = lsp_kp;
    if (!secp256k1_keypair_pub(mgr->ctx, &rot_pks[0], &lsp_kp))
        return 0;
    for (size_t i = 0; i < lsp->n_clients; i++) {
        rot_pks[i + 1] = lsp->client_pubkeys[i];
        /* We don't have client secret keys — only their pubkeys.
           Build dummy keypairs for the keyagg; actual signing uses
           the adaptor protocol (presig + adapt over wire). */
        rot_kps[i + 1] = lsp_kp;  /* placeholder — not used for signing */
    }

    musig_keyagg_t rot_ka;
    musig_aggregate_keys(mgr->ctx, &rot_ka, rot_pks, n_total);

    /* SF-PTLC-TURNOVER-AUTH #196: build context-bound turnover_msg.
       Old constant turnover_msg let a malicious LSP send unrelated
       presigs at any moment.  Now bound to (dying_factory_txid,
       new_factory_nonce, rotation_epoch) hashed via wire_compute_turnover_msg.
       The client receives the same context in a precursor ROTATION_BEGIN
       and refuses any presig whose turnover_msg doesn't match. */
    unsigned char dying_factory_txid[32];
    memcpy(dying_factory_txid, dying->factory.funding_txid, 32);
    unsigned char new_factory_nonce[32];
    {
        FILE *urn = fopen("/dev/urandom", "rb");
        if (!urn) {
            fprintf(stderr, "LSP rotate: cannot open /dev/urandom for nonce\n");
            return 0;
        }
        size_t got = fread(new_factory_nonce, 1, 32, urn);
        fclose(urn);
        if (got != 32) {
            fprintf(stderr, "LSP rotate: /dev/urandom short read\n");
            return 0;
        }
    }
    uint64_t rotation_epoch = (uint64_t)time(NULL);
    unsigned char turnover_msg[32];
    wire_compute_turnover_msg(dying_factory_txid, new_factory_nonce,
                                rotation_epoch, turnover_msg);

    /* #245 Gap A: persist a ROTATE ceremony row so a crash anywhere from
       here onward leaves a recoverable trail. The INITIAL ceremony was
       derived from (dying_factory_txid, INITIAL, epoch=0) at factory
       creation time; we link parent_ceremony_id back to it so forensic
       walks can follow the chain INITIAL → ROTATE → (next INITIAL for
       the rotated-into factory). rot_cer_persisted gates every later
       persist_update_ceremony_state call — when lsp->db is NULL (legacy
       deployments) the rotation runs unchanged. */
    unsigned char rot_cer_id[8] = {0};
    unsigned char rot_parent_cer_id[8] = {0};
    int rot_cer_persisted = 0;
    persist_t *rot_db = (persist_t *)mgr->persist;
    if (rot_db) {
        lsp_ceremony_derive_id(dying_factory_txid,
                                PERSIST_CEREMONY_TYPE_ROTATE,
                                rotation_epoch, rot_cer_id);
        lsp_ceremony_derive_id(dying_factory_txid,
                                PERSIST_CEREMONY_TYPE_INITIAL,
                                /* epoch at INITIAL = 0 */ 0,
                                rot_parent_cer_id);
        if (!persist_save_ceremony(rot_db, rot_cer_id, dying_factory_txid,
                                    PERSIST_CEREMONY_TYPE_ROTATE,
                                    rot_parent_cer_id,
                                    /*started_at_block*/ 0,
                                    /*deadline_block*/ 0)) {
            fprintf(stderr, "LSP rotate: persist_save_ceremony(ROTATE) failed (continuing)\n");
        } else {
            rot_cer_persisted = 1;
        }
        lsp_crash_checkpoint("rotate_pending_nonces");
    }

    /* --- Phase A: PTLC key turnover over wire --- */
    printf("LSP rotate: Phase A — PTLC key turnover\n");

    /* SF-PTLC-HARDEN (#217): journal the turnover ceremony to signing_rounds
     * so the dashboard / operator-mode can see "X/Y clients turned over key"
     * after the fact (slow signers, refuses, timeouts).  Same pattern as
     * Tier B rollover at lsp_channels.c:2080.  Failure to journal is
     * non-fatal — the ceremony continues. */
    int64_t ptlc_round_id = -1;
    if (mgr->persist) {
        persist_save_signing_round_start((persist_t *)mgr->persist,
                                           /* factory_id = */ dying_id,
                                           /* node_idx = */ 0,
                                           "ptlc_turnover",
                                           (uint32_t)rotation_epoch,
                                           (uint32_t)lsp->n_clients,
                                           &ptlc_round_id);
    }

    size_t turnover_ok = 0, turnover_fail = 0;
    for (size_t ci = 0; ci < lsp->n_clients; ci++) {
        if (lsp->client_fds[ci] < 0) {
            printf("LSP rotate: client %zu offline, skipping turnover\n", ci);
            turnover_fail++;
            continue;
        }

        uint32_t pidx = (uint32_t)(ci + 1);
        secp256k1_pubkey client_pk = rot_pks[pidx];

        unsigned char presig[64];
        int nonce_parity;
        musig_keyagg_t ka_copy = rot_ka;
        if (!adaptor_create_turnover_presig(mgr->ctx, presig, &nonce_parity,
                                              turnover_msg, rot_kps, n_total,
                                              &ka_copy, NULL, &client_pk)) {
            fprintf(stderr, "LSP rotate: presig failed client %zu, skipping\n", ci);
            if (rot_cer_persisted) {
                unsigned char pk33[33];
                lsp_ceremony_get_client_pubkey33(lsp, ci, pk33);
                persist_save_participant_phase(rot_db, rot_cer_id, pk33,
                                                PERSIST_CEREMONY_PHASE_REFUSED,
                                                NULL, NULL, 0, 0);
            }
            turnover_fail++;
            continue;
        }

        /* SF-PTLC-TURNOVER-AUTH #196: send rotation context to client
           BEFORE the presig so the client can validate the upcoming presig
           against the context. */
        {
            cJSON *rb = wire_build_rotation_begin(dying_factory_txid,
                                                    new_factory_nonce,
                                                    rotation_epoch);
            if (!wire_send(lsp->client_fds[ci], MSG_ROTATION_BEGIN, rb)) {
                cJSON_Delete(rb);
                fprintf(stderr, "LSP rotate: send ROTATION_BEGIN failed client %zu, skipping\n", ci);
                wire_close(lsp->client_fds[ci]);
                lsp->client_fds[ci] = -1;
                turnover_fail++;
                continue;
            }
            cJSON_Delete(rb);
        }

        /* Send PTLC_PRESIG to client */
        cJSON *pm = wire_build_ptlc_presig(presig, nonce_parity, turnover_msg);
        if (!wire_send(lsp->client_fds[ci], MSG_PTLC_PRESIG, pm)) {
            cJSON_Delete(pm);
            fprintf(stderr, "LSP rotate: send presig failed client %zu, skipping\n", ci);
            wire_close(lsp->client_fds[ci]);
            lsp->client_fds[ci] = -1;
            if (rot_cer_persisted) {
                unsigned char pk33[33];
                lsp_ceremony_get_client_pubkey33(lsp, ci, pk33);
                persist_save_participant_phase(rot_db, rot_cer_id, pk33,
                                                PERSIST_CEREMONY_PHASE_REFUSED,
                                                NULL, NULL, 0, 0);
            }
            turnover_fail++;
            continue;
        }
        cJSON_Delete(pm);
        if (rot_cer_persisted) {
            unsigned char pk33[33];
            lsp_ceremony_get_client_pubkey33(lsp, ci, pk33);
            persist_save_participant_phase(rot_db, rot_cer_id, pk33,
                                            PERSIST_CEREMONY_PHASE_SENT,
                                            NULL, NULL, 0, 0);
        }

        /* Wait for PTLC_ADAPTED_SIG (60s wall-clock).
           Discard stray messages (e.g. MSG_REVOKE_AND_ACK or
           MSG_COMMITMENT_SIGNED from concurrent flows) rather than
           failing the whole rotation. */
        wire_msg_t resp;
        memset(&resp, 0, sizeof(resp));
        {
            struct timeval t_rot_start, t_rot_now;
            gettimeofday(&t_rot_start, NULL);
            int got_sig = 0;
            while (1) {
                gettimeofday(&t_rot_now, NULL);
                int elapsed = (int)(t_rot_now.tv_sec - t_rot_start.tv_sec);
                int remain  = 60 - elapsed;
                if (remain <= 0) break;
                if (!wire_recv_timeout(lsp->client_fds[ci], &resp, remain)) break;
                if (resp.msg_type == MSG_PTLC_ADAPTED_SIG) { got_sig = 1; break; }
                if (resp.msg_type == MSG_ERROR) {
                    if (resp.json) cJSON_Delete(resp.json);
                    memset(&resp, 0, sizeof(resp));
                    break;
                }
                /* Discard stray message and keep waiting */
                fprintf(stderr, "LSP rotate: discarding stray msg 0x%02x from client %zu\n",
                        resp.msg_type, ci);
                if (resp.json) cJSON_Delete(resp.json);
                memset(&resp, 0, sizeof(resp));
            }
            if (!got_sig) {
                if (resp.json) cJSON_Delete(resp.json);
                fprintf(stderr, "LSP rotate: no adapted_sig from client %zu, skipping\n", ci);
                if (rot_cer_persisted) {
                    unsigned char pk33[33];
                    lsp_ceremony_get_client_pubkey33(lsp, ci, pk33);
                    persist_save_participant_phase(rot_db, rot_cer_id, pk33,
                                                    PERSIST_CEREMONY_PHASE_TIMED_OUT,
                                                    NULL, NULL, 0, 0);
                }
                turnover_fail++;
                continue;
            }
        }

        unsigned char adapted_sig[64];
        if (!wire_parse_ptlc_adapted_sig(resp.json, adapted_sig)) {
            cJSON_Delete(resp.json);
            fprintf(stderr, "LSP rotate: parse adapted_sig failed client %zu, skipping\n", ci);
            if (rot_cer_persisted) {
                unsigned char pk33[33];
                lsp_ceremony_get_client_pubkey33(lsp, ci, pk33);
                persist_save_participant_phase(rot_db, rot_cer_id, pk33,
                                                PERSIST_CEREMONY_PHASE_REFUSED,
                                                NULL, NULL, 0, 0);
            }
            turnover_fail++;
            continue;
        }
        cJSON_Delete(resp.json);

        /* Extract client's secret key */
        unsigned char extracted[32];
        if (!adaptor_extract_secret(mgr->ctx, extracted, adapted_sig, presig,
                                      nonce_parity)) {
            fprintf(stderr, "LSP rotate: extract failed client %zu, skipping\n", ci);
            if (rot_cer_persisted) {
                unsigned char pk33[33];
                lsp_ceremony_get_client_pubkey33(lsp, ci, pk33);
                persist_save_participant_phase(rot_db, rot_cer_id, pk33,
                                                PERSIST_CEREMONY_PHASE_REFUSED,
                                                NULL, NULL, 0, 0);
            }
            turnover_fail++;
            continue;
        }
        if (!adaptor_verify_extracted_key(mgr->ctx, extracted, &client_pk)) {
            fprintf(stderr, "LSP rotate: verify failed client %zu, skipping\n", ci);
            if (rot_cer_persisted) {
                unsigned char pk33[33];
                lsp_ceremony_get_client_pubkey33(lsp, ci, pk33);
                persist_save_participant_phase(rot_db, rot_cer_id, pk33,
                                                PERSIST_CEREMONY_PHASE_REFUSED,
                                                NULL, NULL, 0, 0);
            }
            turnover_fail++;
            continue;
        }

        ladder_record_key_turnover(lad, dying_id, pidx, extracted);
        if (mgr->persist)
            persist_save_departed_client((persist_t *)mgr->persist,
                                          dying_id, pidx, extracted);

        /* Send PTLC_COMPLETE */
        cJSON *cm = wire_build_ptlc_complete();
        wire_send(lsp->client_fds[ci], MSG_PTLC_COMPLETE, cm);
        cJSON_Delete(cm);

        turnover_ok++;
        if (ptlc_round_id > 0 && mgr->persist) {
            persist_save_signing_round_participant_psig(
                (persist_t *)mgr->persist, ptlc_round_id,
                (uint32_t)(ci + 1), "verified");
        }
        if (rot_cer_persisted) {
            unsigned char pk33[33];
            lsp_ceremony_get_client_pubkey33(lsp, ci, pk33);
            persist_save_participant_phase(rot_db, rot_cer_id, pk33,
                                            PERSIST_CEREMONY_PHASE_SIGNED,
                                            NULL, NULL, 0, 0);
        }
        printf("LSP rotate: client %zu key extracted via wire PTLC\n", ci + 1);
    }
    printf("LSP rotate: Phase A complete — %zu/%zu clients cooperated (%zu failed)\n",
           turnover_ok, lsp->n_clients, turnover_fail);

    /* #245 Gap A: Phase A finished — every cooperating client is now at
       SIGNED, the non-cooperating ones are at REFUSED/TIMED_OUT. Bump
       the ceremony state to NONCES_AGGREGATED so a restart sees we've
       cleared the first round. */
    if (rot_cer_persisted) {
        if (!persist_update_ceremony_state(rot_db, rot_cer_id,
                PERSIST_CEREMONY_STATE_NONCES_AGGREGATED)) {
            fprintf(stderr, "LSP rotate: persist_update_ceremony_state(NONCES_AGGREGATED) failed (continuing)\n");
        }
        lsp_crash_checkpoint("rotate_nonces_aggregated");
    }

    /* SF-PTLC-HARDEN (#217): finalize the journal row.  partial = some
     * clients failed; success = all OK.  result_txid is NULL because
     * turnover doesn't produce a single on-chain TX (it's a per-client
     * key extraction). */
    if (ptlc_round_id > 0 && mgr->persist) {
        const char *result = (turnover_fail == 0) ? "success" : "partial";
        char detail[128];
        snprintf(detail, sizeof(detail),
                 "ok=%zu fail=%zu n_clients=%zu",
                 turnover_ok, turnover_fail, lsp->n_clients);
        persist_save_signing_round_done((persist_t *)mgr->persist,
                                          ptlc_round_id,
                                          /* nonces_collected = */ (uint32_t)turnover_ok,
                                          /* partial_sigs_collected = */ (uint32_t)turnover_ok,
                                          result,
                                          /* result_txid = */ NULL,
                                          (turnover_fail == 0) ? NULL : detail);
    }

    /* Probe client sockets: detect fds that are still positive but the
       remote end has closed (e.g., client disconnected after MSG_ERROR from
       a prior failed rotation).  Without this, subsequent checks would see
       stale fds as "online" and proceed with an irreversible close TX. */
    for (size_t i = 0; i < lsp->n_clients; i++) {
        if (lsp->client_fds[i] < 0) continue;
        char probe;
        int rc = recv(lsp->client_fds[i], &probe, 1, MSG_PEEK | MSG_DONTWAIT);
        if (rc == 0) {
            /* EOF: remote end closed */
            printf("LSP rotate: client %zu socket closed (stale fd), marking offline\n", i);
            wire_close(lsp->client_fds[i]);
            lsp->client_fds[i] = -1;
        }
        /* rc > 0: data waiting (client still alive)
           rc < 0 && errno == EAGAIN/EWOULDBLOCK: no data but socket open (alive) */
    }

    /* Phase A.5: Close active JIT channels using extracted keys */
    if (mgr->jit_channels) {
        ladder_factory_t *dying_lf = ladder_get_by_id(lad, dying_id);
        chain_backend_t *jit_chain_be = (chain_backend_t *)mgr->chain_be;
        if (jit_chain_be) {
            for (size_t c = 0; c < mgr->n_channels; c++) {
                if (!jit_channel_is_active(mgr, c)) continue;
                size_t pidx = c + 1; /* participant index: 0=LSP, 1..N=clients */
                if (!dying_lf || !dying_lf->client_departed[pidx]) {
                    fprintf(stderr, "LSP rotate: client %zu JIT active but "
                            "key not extracted\n", c);
                    continue;
                }
                if (jit_channel_cooperative_close(mgr, c,
                        dying_lf->extracted_keys[pidx], jit_chain_be)) {
                    printf("LSP rotate: closed JIT channel for client %zu\n", c);
                } else {
                    fprintf(stderr, "LSP rotate: WARNING: could not close JIT "
                            "for client %zu (key mismatch or broadcast failure)\n",
                            c);
                }
            }
        }
    }

    /* Check if all online clients departed (full close) or partial.
       Even if all keys are extracted, only do full close when ALL clients
       are currently online — the close TX is irreversible, and the new
       factory ceremony requires every participant. */
    int full_close = ladder_can_close(lad, dying_id);
    int partial = 0;
    if (full_close) {
        size_t n_online = 0;
        for (size_t i = 0; i < lsp->n_clients; i++) {
            if (lsp->client_fds[i] >= 0)
                n_online++;
        }
        if (n_online < lsp->n_clients) {
            printf("LSP rotate: all keys extracted but only %zu/%zu online — "
                   "downgrading to partial rotation\n", n_online, lsp->n_clients);
            full_close = 0;
            partial = 1;
        }
    }
    if (!full_close && !partial) {
        partial = ladder_can_partial_close(lad, dying_id);
        if (!partial) {
            fprintf(stderr, "LSP rotate: < 2 clients departed, cannot rotate\n");
            return 0;
        }
        printf("LSP rotate: partial — %zu/%zu clients cooperative\n",
               dying->n_departed, dying->factory.n_participants - 1);
    }

    /* --- Phase B: Cooperative close OR partial retirement --- */
    regtest_t *rt = mgr->watchtower ? mgr->watchtower->rt : NULL;
    chain_backend_t *chain_be = (chain_backend_t *)mgr->chain_be;
    wallet_source_t *wallet_src = (wallet_source_t *)mgr->wallet_src;
    if (!rt && !chain_be) {
        fprintf(stderr, "LSP rotate: no chain connection\n");
        if (rot_cer_persisted) {
            persist_update_ceremony_state(rot_db, rot_cer_id,
                                           PERSIST_CEREMONY_STATE_ABORTED);
            persist_update_ceremony_artifacts(rot_db, rot_cer_id, NULL, NULL, NULL,
                                               /*has_abort_reason*/ 1,
                                               PERSIST_CEREMONY_PHASE_REFUSED);
        }
        return 0;
    }

    /* --- Pre-close preflight: nothing irreversible has happened yet ---
       Everything after Phase B that can fail deterministically is checked
       HERE, while the old factory is still live: the replacement factory's
       participants are online, its setup builds (allocation, tree shape,
       hashlock poison -- the exact code lsp_run_factory_creation runs, via
       lsp_factory_creation_preflight), and a bitcoind wallet that does not
       auto-mine will be able to fund it.  A failure aborts with the old
       factory untouched; the retry path tries again later. */
    {
        size_t n_pf = 0;
        secp256k1_pubkey *pf_pks = calloc(lsp->n_clients ? lsp->n_clients : 1,
                                          sizeof(secp256k1_pubkey));
        if (!pf_pks) return 0;
        if (partial) {
            uint32_t pf_coop[FACTORY_MAX_SIGNERS];
            size_t pf_n_coop = ladder_get_cooperative_clients(lad, dying_id,
                                                              pf_coop, FACTORY_MAX_SIGNERS);
            for (size_t i = 0; i < pf_n_coop; i++) {
                uint32_t ci = pf_coop[i];
                if (ci >= 1 && ci <= lsp->n_clients && lsp->client_fds[ci - 1] >= 0)
                    pf_pks[n_pf++] = lsp->client_pubkeys[ci - 1];
            }
        } else {
            for (size_t i = 0; i < lsp->n_clients; i++)
                pf_pks[n_pf++] = lsp->client_pubkeys[i];
        }
        /* A full close pays the old factory's funds back to this wallet
           before Phase C funds the replacement. */
        int pf_ok = rotation_preflight(mgr, lsp, pf_pks, n_pf, partial ? 2u : 1u,
                                       full_close ? dying->factory.funding_amount_sats : 0);
        free(pf_pks);
        if (!pf_ok) {
            fprintf(stderr, "LSP rotate: preflight FAILED — aborting BEFORE the close; "
                    "factory %u is untouched\n", dying_id);
            if (rot_cer_persisted) {
                persist_update_ceremony_state(rot_db, rot_cer_id,
                                               PERSIST_CEREMONY_STATE_ABORTED);
                persist_update_ceremony_artifacts(rot_db, rot_cer_id, NULL, NULL, NULL,
                                                   /*has_abort_reason*/ 1,
                                                   PERSIST_CEREMONY_PHASE_REFUSED);
            }
            return 0;
        }
    }

    /* #245 Gap A: Phase B is about to commit the close/partial-retire TX.
       Bump state to PENDING_SIGS so a crash here re-enters with the right
       context — we no longer need to redo Phase A turnover, but we DO need
       to re-broadcast the close TX from a persisted source. */
    if (rot_cer_persisted) {
        if (!persist_update_ceremony_state(rot_db, rot_cer_id,
                PERSIST_CEREMONY_STATE_PENDING_SIGS)) {
            fprintf(stderr, "LSP rotate: persist_update_ceremony_state(PENDING_SIGS) failed (continuing)\n");
        }
        lsp_crash_checkpoint("rotate_pending_sigs");
    }

    if (full_close) {
        /* Full cooperative close of dying factory */
        printf("LSP rotate: Phase B — cooperative close of factory %u\n", dying_id);

        /* Get a wallet-controlled address for close outputs (UTXO recycling) */
        char wallet_addr[128];
        unsigned char wallet_spk[64];
        size_t wallet_spk_len = 0;
        const unsigned char *close_spk = NULL;
        size_t close_spk_len = 0;

        if (rt &&
            regtest_get_new_address(rt, wallet_addr, sizeof(wallet_addr)) &&
            regtest_get_address_scriptpubkey(rt, wallet_addr, wallet_spk, &wallet_spk_len)) {
            close_spk = wallet_spk;
            close_spk_len = wallet_spk_len;
            printf("LSP rotate: close outputs to wallet address %s\n", wallet_addr);
        } else if (!rt && wallet_src &&
                   wallet_src->get_change_spk(wallet_src, wallet_spk, &wallet_spk_len)) {
            close_spk = wallet_spk;
            close_spk_len = wallet_spk_len;
            printf("LSP rotate: close outputs to HD wallet SPK\n");
        } else {
            fprintf(stderr, "LSP rotate: WARNING: wallet address fetch failed, "
                    "using factory funding SPK (funds may strand)\n");
        }

        tx_output_t rot_outputs[FACTORY_MAX_SIGNERS];
        size_t close_vsize = 68 + 43 * n_total;
        uint64_t close_fee = fee_estimate(fe, close_vsize);
        if (close_fee == 0) {
            close_fee = (close_vsize * FEE_FLOOR_SAT_PER_KVB + 999) / 1000;
            if (close_fee == 0) close_fee = 1;
            fprintf(stderr, "LSP rotate: WARNING: fee estimation returned 0, "
                    "using %.1f sat/vB floor (%llu sats)\n",
                    (double)FEE_FLOOR_SAT_PER_KVB / 1000.0,
                    (unsigned long long)close_fee);
        }
        size_t n_close = lsp_channels_build_close_outputs(mgr, &lsp->factory,
                                                            rot_outputs, close_fee,
                                                            close_spk, close_spk_len);
        if (n_close == 0) {
            const unsigned char *fb_spk = close_spk ? close_spk : mgr->rot_fund_spk;
            size_t fb_spk_len = close_spk ? close_spk_len : 34;
            uint64_t per = (lsp->factory.funding_amount_sats - close_fee) / n_total;
            for (size_t ti = 0; ti < n_total; ti++) {
                rot_outputs[ti].amount_sats = per;
                memcpy(rot_outputs[ti].script_pubkey, fb_spk, fb_spk_len);
                rot_outputs[ti].script_pubkey_len = fb_spk_len;
            }
            rot_outputs[n_total - 1].amount_sats =
                lsp->factory.funding_amount_sats - close_fee - per * (n_total - 1);
            n_close = n_total;
        }

        tx_buf_t rot_close_tx;
        tx_buf_init(&rot_close_tx, 512);
        if (!ladder_build_close(lad, dying_id, &rot_close_tx, rot_outputs, n_close,
                                  chain_be ? (uint32_t)chain_be->get_block_height(chain_be) :
                                  (rt ? (uint32_t)regtest_get_block_height(rt) : 0))) {
            fprintf(stderr, "LSP rotate: ladder_build_close failed\n");
            tx_buf_free(&rot_close_tx);
            return 0;
        }

        char *rc_hex = malloc(rot_close_tx.len * 2 + 1);
        if (!rc_hex) {
            fprintf(stderr, "LSP rotate: malloc failed for close TX hex\n");
            tx_buf_free(&rot_close_tx);
            return 0;
        }
        hex_encode(rot_close_tx.data, rot_close_tx.len, rc_hex);
        char rc_txid[65];
        {
            unsigned char rc_txid32[32];
            if (!tx_txid_from_bytes(rot_close_tx.data, rot_close_tx.len, rc_txid32)) {
                fprintf(stderr, "LSP rotate: could not compute the close TX's txid\n");
                free(rc_hex);
                tx_buf_free(&rot_close_tx);
                return 0;
            }
            rot_txid_display(rc_txid32, rc_txid);
        }
        tx_buf_free(&rot_close_tx);

        /* Point of no return: once on the network the close pays every
           client's balance to this wallet.  Record it (txid + signed hex, in
           rotation_closes too) BEFORE broadcasting, so a crash right after the
           broadcast still finds it and resumes Phase C. */
        lsp_rotation_progress_clear(mgr);
        mgr->rot_progress.dying_factory_id = dying_id;
        memcpy(mgr->rot_progress.dying_funding_txid, dying->factory.funding_txid, 32);
        mgr->rot_progress.dying_funding_vout = dying->factory.funding_vout;
        snprintf(mgr->rot_progress.close_txid, sizeof(mgr->rot_progress.close_txid),
                 "%s", rc_txid);
        mgr->rot_progress.new_funding_vout = UINT32_MAX;
        if (mgr->persist) {
            char dtx[65];
            rot_txid_display(dying->factory.funding_txid, dtx);
            if (persist_in_transaction((persist_t *)mgr->persist) ||
                !persist_add_rotation_close((persist_t *)mgr->persist, dtx, rc_txid, rc_hex)) {
                fprintf(stderr, "LSP rotate: could not record the close TX -- NOT "
                        "broadcasting it (factory %u untouched)\n", dying_id);
                free(rc_hex);
                lsp_rotation_progress_clear(mgr);
                return 0;
            }
        }
        if (!rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_CLOSING)) {
            fprintf(stderr, "LSP rotate: NOT broadcasting the close (factory %u "
                    "untouched)\n", dying_id);
            free(rc_hex);
            lsp_rotation_progress_clear(mgr);
            return 0;
        }
        printf("LSP rotate: rotation close %s recorded; broadcasting\n", rc_txid);
        fflush(stdout);
        char rc_sent_txid[65] = {0};
        int rc_sent = rot_send_hex(mgr, rc_hex, rc_sent_txid);
        if (mgr->persist) {
            persist_log_broadcast((persist_t *)mgr->persist, rc_txid, "rotation_close",
                                  rc_hex, rc_sent ? "ok" : "failed");
        }
        free(rc_hex);
        /* Restart drill: the close is on the network (or at least recorded),
           not yet confirmed. */
        lsp_crash_checkpoint("rotate_close_sent");
        if (!rc_sent && !rot_tx_in_mempool(mgr, rc_txid) &&
            rot_tx_confirmations(mgr, rc_txid) < 1) {
            fprintf(stderr, "LSP rotate: close TX broadcast failed -- factory %u stays "
                    "open; the recorded close stays known\n", dying_id);
            (void)rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_NONE);
            lsp_rotation_progress_clear(mgr);
            return 0;
        }

        if (mgr->rot_is_regtest) {
            regtest_mine_blocks(rt, 1, mgr->rot_mine_addr);
        } else {
            int rot_timeout = mgr->confirm_timeout_secs > 0 ?
                              mgr->confirm_timeout_secs : 7200;
            printf("LSP rotate: waiting for close TX confirmation...\n");
            int confirmed = 0;
            for (int attempt = 0; attempt < 2; attempt++) {
                if (chain_be) {
                    if (lsp_wait_for_confirmation_service(chain_be, rc_txid, rot_timeout,
                                                           chain_close_confs(chain_be, chain_be->is_regtest), mgr, lsp)) {
                        confirmed = 1; break;
                    }
                    if (chain_be->is_in_mempool(chain_be, rc_txid)) {
                        fprintf(stderr, "LSP rotate: close TX still in mempool, "
                                "extending wait (attempt %d)\n", attempt + 1);
                        continue;
                    }
                } else {
                    /* R2 + R3 (mainnet pre-flight): reorg-resilient + network-safe
                       confirmation depth (regtest=1, signet/testnet4=3, mainnet=6). */
                    int safe_depth_close = regtest_network_safe_confirmation_depth(rt);
                    if (regtest_wait_for_stable_confirmation(rt, rc_txid,
                                                              safe_depth_close,
                                                              /*max_reorg_depth=*/3,
                                                              rot_timeout) >= 1) {
                        confirmed = 1; break;
                    }
                    if (regtest_is_in_mempool(rt, rc_txid)) {
                        fprintf(stderr, "LSP rotate: close TX still in mempool, "
                                "extending wait (attempt %d)\n", attempt + 1);
                        continue;
                    }
                }
                fprintf(stderr, "LSP rotate: close TX %s dropped from mempool\n",
                        rc_txid);
                break;
            }
            if (!confirmed) {
                fprintf(stderr, "LSP rotate: close TX not confirmed after retries\n");
                return 0;
            }
        }
        printf("LSP rotate: factory %u closed: %s\n", dying_id, rc_txid);
        /* Mark as rotated so CLI "rotate" won't try to rotate it again */
        dying->partial_rotation_done = 1;
        if (!rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_CLOSED)) {
            /* Stays CLOSING on disk: the resume sees the close confirmed. */
            return 0;
        }
        /* The dying factory's funding is spent: its distribution TX can never
           confirm.  Drop it so the EXPIRED auto-broadcast does not try. */
        tx_buf_free(&dying->distribution_tx);
        /* #332 restart-resume drill checkpoint: the close is broadcast +
           confirmed (funding now spent on-chain, every client balance now in
           this wallet) but the replacement factory has NOT been created yet.
           A crash here leaves the CLOSED progress marker, so the restarted LSP
           resumes Phase C (lsp_rotation_resume): no re-close, exactly one
           replacement funding. */
        lsp_crash_checkpoint("rotate_close_broadcast");
        /* CL4-rollover (#250): the mid-window adversarial broadcast that
           used to live here was dead code on the regtest test path —
           lsp_channels_rotate_factory only runs under --daemon (mgr->
           rot_auto_rotate = daemon_mode in superscalar_lsp.c) but the
           test wrapper test_regtest_cheat_daemon_rollover.sh uses --demo
           with --test-tier-b-rollover.  Adversarial scaffolding now
           lives in tools/superscalar_lsp_pre_daemon_tests.inc inside
           test_tier_b_rollover (mirrors the CL2 cheat-realloc precedent:
           cheat logic in _tests.inc, not production library code). */

    } else {
        /* Partial rotation: skip cooperative close, old factory expires naturally.
           The distribution TX (nLockTime) protects all participants. */
        printf("LSP rotate: Phase B — partial retirement of factory %u "
               "(distribution TX on expiry)\n", dying_id);
        dying->partial_rotation_done = 1;
        /* CL4-rollover (#250): see comment in the full-close branch above —
           mid-window cheat broadcast moved into _pre_daemon_tests.inc. */

        if (mgr->persist) {
            const char *st = "dying";
            persist_save_ladder_factory((persist_t *)mgr->persist,
                dying_id, st, dying->is_funded, dying->is_initialized,
                dying->n_departed, dying->factory.created_block,
                dying->factory.active_blocks, dying->factory.dying_blocks,
                dying->partial_rotation_done);
        }
    }

    return rotation_create_replacement(mgr, lsp, lad, dying_id, partial,
                                       rot_db, rot_cer_id, rot_cer_persisted);
}

/* Phase C + D: fund the replacement factory (unless a recorded earlier
   attempt already did), create + sign it over that output, store + persist
   it, and reinitialize the channels with the carried balances.  Shared by a
   fresh rotation (right after Phase B) and lsp_rotation_resume.  A full
   rotation (close recorded in mgr->rot_progress) records each step so any
   failure here stays resumable. */
static int rotation_create_replacement(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                       ladder_t *lad, uint32_t dying_id,
                                       int partial, persist_t *rot_db,
                                       const unsigned char *rot_cer_id,
                                       int rot_cer_persisted) {
    fee_estimator_t *fe = (fee_estimator_t *)mgr->rot_fee_est;
    regtest_t *rt = rot_rt(mgr);
    chain_backend_t *chain_be = (chain_backend_t *)mgr->chain_be;
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    /* Full rotation whose close is recorded: every step is resumable. */
    int track = !partial && rp->phase >= LSP_ROT_PROGRESS_CLOSED;
    if (!fe || (!rt && !chain_be)) return 0;

    /* --- Phase C: Create new factory --- */
    printf("LSP rotate: Phase C — creating new factory\n");

    /* Participants must be online BEFORE funding (this used to be checked
       only after the funding confirmed, stranding the new funding output
       whenever a client had dropped). */
    {
        size_t need = 0, on = 0;
        if (partial) {
            uint32_t pc[FACTORY_MAX_SIGNERS];
            size_t npc = ladder_get_cooperative_clients(lad, dying_id, pc,
                                                        FACTORY_MAX_SIGNERS);
            for (size_t i = 0; i < npc; i++)
                if (pc[i] >= 1 && pc[i] <= lsp->n_clients &&
                    lsp->client_fds[pc[i] - 1] >= 0)
                    on++;
            need = 2;
        } else {
            for (size_t i = 0; i < lsp->n_clients; i++)
                if (lsp->client_fds[i] >= 0) on++;
            need = lsp->n_clients;
        }
        if (on < need) {
            fprintf(stderr, "LSP rotate: only %zu participant(s) online (need %zu) — "
                    "not funding the replacement factory%s\n", on, need,
                    track ? " (rotation stays resumable)" : "");
            return 0;
        }
    }

    char fund_txid_hex[65];
    uint64_t fund_amount = 0;
    uint32_t fund_vout = 0;
    if (track && (rp->phase == LSP_ROT_PROGRESS_FUNDED ||
                  rp->phase == LSP_ROT_PROGRESS_SIGNING_READY) &&
        rp->new_funding_txid[0] && rp->new_funding_vout != UINT32_MAX) {
        /* Resume: the replacement funding is recorded and confirmed.  NEVER
           fund a second time -- create the factory over it. */
        snprintf(fund_txid_hex, sizeof(fund_txid_hex), "%s", rp->new_funding_txid);
        fund_vout = rp->new_funding_vout;
        fund_amount = rp->new_funding_amount;
        printf("LSP rotate: replacement factory already funded by an earlier "
               "attempt (%s:%u, %d conf) — not re-funding\n", fund_txid_hex, fund_vout,
               rot_tx_confirmations(mgr, fund_txid_hex));
    } else if (track && rp->phase != LSP_ROT_PROGRESS_CLOSED) {
        fprintf(stderr, "LSP rotate: rotation is at phase %d, not CLOSED -- not "
                "funding a replacement\n", rp->phase);
        return 0;
    } else {
        /* Fund new factory */
        if (mgr->rot_is_regtest) {
            /* Ensure wallet has funds */
            double bal = regtest_get_balance(rt);
            if (bal < 0.01) {
                regtest_mine_blocks(rt, 10, mgr->rot_mine_addr);
            }
        } else if (rt) {
            double bal = regtest_get_balance(rt);
            double needed = (double)mgr->rot_funding_sats / 100000000.0;
            if (bal < needed) {
                fprintf(stderr, "LSP rotate: insufficient balance %.8f (need %.8f)\n",
                        bal, needed);
                return 0;
            }
        }
        /* In light-client mode: skip balance check; the build fails if no UTXO */

        /* Build + sign the funding TX, record it (txid + hex), THEN broadcast:
           a crash after the broadcast finds the recorded funding and never
           funds a second replacement. */
        rot_funding_tx_t fb;
        if (!rot_build_funding_tx(mgr, &fb)) {
            fprintf(stderr, "LSP rotate: fund new factory failed (could not build the "
                    "funding TX)\n");
            return 0;
        }
        snprintf(fund_txid_hex, sizeof(fund_txid_hex), "%s", fb.txid);
        if (track) {
            snprintf(rp->new_funding_txid, sizeof(rp->new_funding_txid), "%s",
                     fund_txid_hex);
            free(rp->new_funding_hex);
            rp->new_funding_hex = strdup(fb.hex);
            rp->new_funding_vout = UINT32_MAX;
            rp->new_funding_amount = 0;
            if (!rp->new_funding_hex ||
                !rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_FUNDING)) {
                fprintf(stderr, "LSP rotate: could not record the replacement funding "
                        "-- NOT broadcasting it (its wallet inputs are released)\n");
                rp->new_funding_txid[0] = '\0';
                free(rp->new_funding_hex);
                rp->new_funding_hex = NULL;
                rot_funding_abandon(mgr, &fb);
                return 0;
            }
            printf("LSP rotate: replacement funding %s recorded; broadcasting\n",
                   fund_txid_hex);
            fflush(stdout);
        }
        char f_sent_txid[65] = {0};
        int f_sent = rot_send_hex(mgr, fb.hex, f_sent_txid);
        if (mgr->persist)
            persist_log_broadcast((persist_t *)mgr->persist, fund_txid_hex,
                                  "rotation_funding", fb.hex, f_sent ? "ok" : "failed");
        /* Restart drill: the funding is sent (and recorded), not confirmed. */
        lsp_crash_checkpoint("rotate_funding_sent");
        if (!f_sent && !rot_tx_in_mempool(mgr, fund_txid_hex) &&
            rot_tx_confirmations(mgr, fund_txid_hex) < 1) {
            if (track) {
                /* Recorded: the resume rebroadcasts this TX, never a different
                   one, so its inputs stay locked / reserved. */
                if (fb.light) {
                    rp->fund_reserved = 1;
                    memcpy(rp->fund_reserved_txid, fb.res_txid, 65);
                    rp->fund_reserved_vout = fb.res_vout;
                }
                free(fb.hex);
                fprintf(stderr, "LSP rotate: replacement funding broadcast failed "
                        "(recorded: the resume rebroadcasts this TX, never a different "
                        "one)\n");
            } else {
                rot_funding_abandon(mgr, &fb);
                fprintf(stderr, "LSP rotate: replacement funding broadcast failed\n");
            }
            return 0;
        }
        /* On the network: a light-client reservation has done its job. */
        if (fb.light) {
            wallet_source_t *ws = (wallet_source_t *)mgr->wallet_src;
            if (ws && ws->release_utxo) ws->release_utxo(ws, fb.res_txid, fb.res_vout);
        }
        free(fb.hex);
        if (mgr->rot_is_regtest) {
            regtest_mine_blocks(rt, 1, mgr->rot_mine_addr);
        } else {
            int rot_timeout = mgr->confirm_timeout_secs > 0 ?
                              mgr->confirm_timeout_secs : 7200;
            printf("LSP rotate: waiting for funding confirmation...\n");
            int confirmed = 0;
            for (int attempt = 0; attempt < 2; attempt++) {
                if (chain_be) {
                    if (lsp_wait_for_confirmation_service(chain_be, fund_txid_hex, rot_timeout,
                                                           chain_funding_confs(chain_be, chain_be->is_regtest), mgr, lsp)) {
                        confirmed = 1; break;
                    }
                    if (chain_be->is_in_mempool(chain_be, fund_txid_hex)) {
                        fprintf(stderr, "LSP rotate: funding TX still in mempool, "
                                "extending wait (attempt %d)\n", attempt + 1);
                        continue;
                    }
                } else {
                    /* R2 + R3 (mainnet pre-flight): reorg-resilient + network-safe
                       confirmation depth (regtest=1, signet/testnet4=3, mainnet=6). */
                    int safe_depth_fund = regtest_network_safe_confirmation_depth(rt);
                    if (regtest_wait_for_stable_confirmation(rt, fund_txid_hex,
                                                              safe_depth_fund,
                                                              /*max_reorg_depth=*/3,
                                                              rot_timeout) >= 1) {
                        confirmed = 1; break;
                    }
                    if (regtest_is_in_mempool(rt, fund_txid_hex)) {
                        fprintf(stderr, "LSP rotate: funding TX still in mempool, "
                                "extending wait (attempt %d)\n", attempt + 1);
                        continue;
                    }
                }
                fprintf(stderr, "LSP rotate: funding TX dropped from mempool\n");
                break;
            }
            if (!confirmed) {
                fprintf(stderr, "LSP rotate: funding TX not confirmed after retries%s\n",
                        track ? " (stays FUNDING: the resume confirms or rebroadcasts it)" : "");
                return 0;
            }
        }
        if (!rot_find_funding_output(mgr, fund_txid_hex, &fund_vout, &fund_amount)) {
            fprintf(stderr, "LSP rotate: could not find funding output\n");
            return 0;
        }
        if (track) {
            rp->new_funding_vout = fund_vout;
            rp->new_funding_amount = fund_amount;
            rot_fix_ceremony_params(mgr);
            if (!rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_FUNDED))
                return 0;                  /* stays FUNDING on disk: resumable */
        }
    }

    unsigned char fund_txid[32];
    hex_decode(fund_txid_hex, fund_txid, 32);
    reverse_bytes(fund_txid, 32);
    printf("LSP rotate: funded %llu sats, txid: %s, vout=%u\n",
           (unsigned long long)fund_amount, fund_txid_hex, fund_vout);
    if (track) {
        /* Never create over an outpoint that is already gone. */
        if (rot_outpoint_unspent(mgr, fund_txid_hex, fund_vout) == 0) {
            fprintf(stderr, "LSP rotate: replacement funding %s:%u is already SPENT — "
                    "cannot create the factory over it (operator attention)\n",
                    fund_txid_hex, fund_vout);
            return 0;
        }
    }
    /* Restart drill: replacement funded + confirmed, not yet signed -- the
       exact state the profiles-NULL crash left behind. */
    lsp_crash_checkpoint("rotate_replacement_funded");

    /* For partial rotation: remap client arrays to cooperative subset */
    int saved_client_fds[LSP_MAX_CLIENTS];
    secp256k1_pubkey saved_client_pks[LSP_MAX_CLIENTS];
    secp256k1_pubkey saved_client_ids[LSP_MAX_CLIENTS];
    size_t n_coop = 0;

    memset(saved_client_fds, -1, sizeof(saved_client_fds));
    memset(saved_client_pks, 0, sizeof(saved_client_pks));
    memset(saved_client_ids, 0, sizeof(saved_client_ids));

    if (partial) {
        memcpy(saved_client_fds, lsp->client_fds, sizeof(saved_client_fds));
        memcpy(saved_client_pks, lsp->client_pubkeys, sizeof(saved_client_pks));
        if (lsp->client_identity_pubkeys)
            memcpy(saved_client_ids, lsp->client_identity_pubkeys,
                   sizeof(saved_client_ids));

        uint32_t coop[FACTORY_MAX_SIGNERS];
        n_coop = ladder_get_cooperative_clients(lad, dying_id,
                                                 coop, FACTORY_MAX_SIGNERS);

        /* Remap to contiguous indices, skipping clients whose fd went stale */
        size_t n_online = 0;
        for (size_t i = 0; i < n_coop; i++) {
            int fd = saved_client_fds[coop[i] - 1];
            if (fd >= 0) {
                lsp->client_fds[n_online] = fd;
                lsp->client_pubkeys[n_online] = saved_client_pks[coop[i] - 1];
                if (lsp->client_identity_pubkeys)
                    lsp->client_identity_pubkeys[n_online] =
                        saved_client_ids[coop[i] - 1];
                n_online++;
            } else {
                printf("LSP rotate: cooperative client %u went offline, skipping\n",
                       coop[i]);
            }
        }
        if (n_online < 2) {
            fprintf(stderr, "LSP rotate: only %zu online clients, need >= 2\n",
                    n_online);
            /* Restore original client arrays */
            memcpy(lsp->client_fds, saved_client_fds, sizeof(saved_client_fds));
            memcpy(lsp->client_pubkeys, saved_client_pks, sizeof(saved_client_pks));
            if (lsp->client_identity_pubkeys)
                memcpy(lsp->client_identity_pubkeys, saved_client_ids, sizeof(saved_client_ids));
            lsp->n_clients = (size_t)mgr->n_channels;
            return 0;
        }
        lsp->n_clients = n_online;
        printf("LSP rotate: remapped %zu/%zu cooperative clients for new factory\n",
               n_online, n_coop);
    } else {
        /* Full close: verify all clients still online */
        size_t n_online = 0;
        for (size_t i = 0; i < lsp->n_clients; i++) {
            if (lsp->client_fds[i] >= 0)
                n_online++;
        }
        if (n_online < lsp->n_clients) {
            printf("LSP rotate: %zu/%zu clients online for full close\n",
                   n_online, lsp->n_clients);
        }
    }

    /* Re-verify ALL participating clients are still connected (checked
       before funding too, but the confirmation wait can be long).  Factory
       creation sends FACTORY_PROPOSE to every client; abort before it if any
       dropped -- a full rotation stays resumable. */
    {
        size_t online = 0;
        for (size_t i = 0; i < lsp->n_clients; i++) {
            if (lsp->client_fds[i] >= 0)
                online++;
        }
        if (online < lsp->n_clients) {
            fprintf(stderr, "LSP rotate: only %zu/%zu clients online before "
                    "factory creation, aborting (factory preserved)\n",
                    online, lsp->n_clients);
            if (partial) {
                memcpy(lsp->client_fds, saved_client_fds, sizeof(saved_client_fds));
                memcpy(lsp->client_pubkeys, saved_client_pks, sizeof(saved_client_pks));
                if (lsp->client_identity_pubkeys)
                    memcpy(lsp->client_identity_pubkeys, saved_client_ids, sizeof(saved_client_ids));
                lsp->n_clients = (size_t)mgr->n_channels;
            }
            return 0;
        }
    }

    /* Do NOT factory_free the old factory here.  lsp_run_factory_creation
       captures its template (shape, participant profiles, secret mode) and
       then releases it itself.  Freeing it first is what crashed rotation once
       #451/#453 made the factory arrays heap-allocated (f->profiles == NULL at
       the template capture), and it would drop the profiles even with a
       NULL-safe creation path.  Ladder entries are detached copies
       (factory_detach_txbufs), so the live factory owns its arrays.  If an
       earlier failed attempt left the live factory without arrays,
       re-establish them and carry the profiles from the dying factory's
       ladder copy. */
    {
        ladder_factory_t *src_lf = ladder_get_by_id(lad, dying_id);
        if (!lsp->factory.profiles &&
            factory_alloc_default_arrays(&lsp->factory) &&
            src_lf && src_lf->factory.profiles) {
            size_t np = src_lf->factory.config.max_signers;
            if (np > lsp->factory.config.max_signers)
                np = lsp->factory.config.max_signers;
            memcpy(lsp->factory.profiles, src_lf->factory.profiles,
                   np * sizeof(participant_profile_t));
        }
    }
    lsp->factory.leaf_arity = (factory_arity_t)mgr->rot_leaf_arity;

    /* Ceremony parameters.  A tracked rotation fixed them when its funding
       confirmed (FUNDED), so every ceremony over this funding -- the first run
       or one after a restart -- builds byte-identical transactions. */
    uint32_t new_cltv = 0;
    uint64_t rot_dist_amounts[FACTORY_MAX_SIGNERS];
    size_t n_rot_dist = 0;
    if (track) {
        if (rp->n_dist_amounts == 0) {
            rot_fix_ceremony_params(mgr);
            if (!rot_progress_persist(mgr)) {
                if (partial) {
                    memcpy(lsp->client_fds, saved_client_fds, sizeof(saved_client_fds));
                    memcpy(lsp->client_pubkeys, saved_client_pks, sizeof(saved_client_pks));
                    if (lsp->client_identity_pubkeys)
                        memcpy(lsp->client_identity_pubkeys, saved_client_ids, sizeof(saved_client_ids));
                    lsp->n_clients = (size_t)mgr->n_channels;
                }
                return 0;
            }
        }
        new_cltv = rp->new_cltv;
        n_rot_dist = rp->n_dist_amounts;
        memcpy(rot_dist_amounts, rp->dist_amounts, n_rot_dist * sizeof(uint64_t));
    } else {
        int cur_h = rot_chain_height(mgr);
        if (cur_h > 0)
            new_cltv = (uint32_t)cur_h + (mgr->rot_is_regtest ? 35u : 1008u);
        /* Per-client account_limit (channel capacity) for the new factory's
           distribution TX: each client's contracted capacity on CLTV expiry,
           not their current balance (which would let the LSP protect
           accumulated fees simply by going dark). */
        for (size_t c = 0; c < mgr->n_channels && c < FACTORY_MAX_SIGNERS; c++)
            rot_dist_amounts[n_rot_dist++] = mgr->entries[c].channel.funding_amount;
    }

    /* The replacement's ladder slot must exist BEFORE its ceremony: once the
       clients hold its signed tree there is no backing out. */
    if (lad->n_factories >= LADDER_MAX_FACTORIES)
        ladder_evict_expired(lad);
    if (lad->n_factories >= LADDER_MAX_FACTORIES) {
        fprintf(stderr, "LSP rotate: no ladder slots available — not running the "
                "creation ceremony\n");
        if (partial) {
            memcpy(lsp->client_fds, saved_client_fds, sizeof(saved_client_fds));
            memcpy(lsp->client_pubkeys, saved_client_pks, sizeof(saved_client_pks));
            if (lsp->client_identity_pubkeys)
                memcpy(lsp->client_identity_pubkeys, saved_client_ids, sizeof(saved_client_ids));
            lsp->n_clients = (size_t)mgr->n_channels;
        }
        return 0;
    }

    /* A ceremony over this funding may already have delivered its signed
       tree (SIGNING_READY): run one again only if it builds exactly the same
       transactions, so the clients can never hold two different trees over
       one output. */
    int delivered_before = track && rp->phase == LSP_ROT_PROGRESS_SIGNING_READY;
    if (delivered_before) {
        int m = lsp_rotation_signed_tree_matches(mgr, lsp);
        if (m != 1) {
            rot_report_signing_hold(mgr, m);
            if (partial) {
                memcpy(lsp->client_fds, saved_client_fds, sizeof(saved_client_fds));
                memcpy(lsp->client_pubkeys, saved_client_pks, sizeof(saved_client_pks));
                if (lsp->client_identity_pubkeys)
                    memcpy(lsp->client_identity_pubkeys, saved_client_ids, sizeof(saved_client_ids));
                lsp->n_clients = (size_t)mgr->n_channels;
            }
            return 0;
        }
        printf("LSP rotate: the tree rebuilt from the recorded parameters is "
               "byte-identical to the delivered one (digest %s) — running the "
               "ceremony again over the same transactions\n", rp->tree_digest);
        fflush(stdout);
    }

    /* SIGNING: a ceremony may start; no client holds its tree yet.  The
       ceremony's before_factory_ready hook records SIGNING_READY right before
       the first FACTORY_READY.  (A SIGNING_READY marker is never lowered.) */
    if (track && !delivered_before) {
        rp->hold_reported = 0;
        if (!rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_SIGNING)) {
            if (partial) {
                memcpy(lsp->client_fds, saved_client_fds, sizeof(saved_client_fds));
                memcpy(lsp->client_pubkeys, saved_client_pks, sizeof(saved_client_pks));
                if (lsp->client_identity_pubkeys)
                    memcpy(lsp->client_identity_pubkeys, saved_client_ids, sizeof(saved_client_ids));
                lsp->n_clients = (size_t)mgr->n_channels;
            }
            return 0;
        }
    }
    if (track) {
        lsp->before_factory_ready = rot_before_factory_ready;
        lsp->before_factory_ready_ctx = mgr;
    }

    lsp->dist_client_amounts = rot_dist_amounts;
    lsp->dist_n_client_amounts = n_rot_dist;

    /* Run factory creation ceremony (sends FACTORY_PROPOSE to clients) */
    int created = lsp_run_factory_creation(lsp,
                                           fund_txid, fund_vout,
                                           fund_amount,
                                           mgr->rot_fund_spk, mgr->rot_fund_spk_len,
                                           mgr->rot_step_blocks,
                                           mgr->rot_states_per_layer, new_cltv);
    lsp->before_factory_ready = NULL;
    lsp->before_factory_ready_ctx = NULL;
    if (!created) {
        if (!track)
            fprintf(stderr, "LSP rotate: new factory creation failed\n");
        else
            (void)lsp_rotation_ceremony_failed(mgr, lsp->ceremony_ready_sent,
                                               delivered_before);
        /* lsp->factory holds the caller's template again (arrays allocated;
           see lsp_run_factory_creation's failure path).  Restore the client
           arrays so the daemon can keep servicing connections. */
        if (partial) {
            memcpy(lsp->client_fds, saved_client_fds, sizeof(saved_client_fds));
            memcpy(lsp->client_pubkeys, saved_client_pks, sizeof(saved_client_pks));
            if (lsp->client_identity_pubkeys)
                memcpy(lsp->client_identity_pubkeys, saved_client_ids, sizeof(saved_client_ids));
            lsp->n_clients = (size_t)mgr->n_channels;
        }
        lsp->dist_client_amounts = NULL;
        lsp->dist_n_client_amounts = 0;
        return 0;
    }
    lsp->dist_client_amounts = NULL;
    lsp->dist_n_client_amounts = 0;
    /* Restart drill: the clients hold the signed tree (SIGNING_READY);
       nothing persisted yet. */
    lsp_crash_checkpoint("rotate_ceremony_signed");

    /* Set lifecycle for new factory */
    {
        int cur_h = rot_chain_height(mgr);
        if (cur_h > 0)
            factory_set_lifecycle(&lsp->factory, (uint32_t)cur_h,
                                  lad->active_blocks, lad->dying_blocks);
    }
    lsp->factory.fee = fe;

    /* Persist the new factory and record SIGNED in ONE transaction: the marker
       says "signed" exactly when the signed replacement is on disk. */
    if (mgr->persist) {
        persist_t *db = (persist_t *)mgr->persist;
        if (!persist_begin(db)) {
            fprintf(stderr, "LSP rotate: CRITICAL: persist_begin failed for the signed "
                    "replacement%s\n", track ? " (held at SIGNING: operator attention)" : "");
            return 0;
        }
        int pok = persist_save_factory(db, &lsp->factory, mgr->ctx, 0) &&
                  persist_save_tree_nodes(db, &lsp->factory, 0) &&
                  lsp_save_client_identities(lsp, db, mgr->ctx, 0);
        if (pok && track) {
            char dtx[65];
            rot_txid_display(rp->dying_funding_txid, dtx);
            persist_rotation_progress_t row;
            rp->phase = LSP_ROT_PROGRESS_SIGNED;
            rot_progress_to_row(rp, &row);
            pok = persist_save_rotation_progress(db, dtx, &row);
            if (!pok) rp->phase = LSP_ROT_PROGRESS_SIGNING_READY;
        }
        if (!pok) {
            persist_rollback(db);
            fprintf(stderr, "LSP rotate: CRITICAL: the replacement is signed but could not "
                    "be persisted -- rolled back%s\n",
                    track ? "; held at SIGNING_READY" : "");
            return 0;
        }
        if (!persist_commit(db)) {
            if (track) rp->phase = LSP_ROT_PROGRESS_SIGNING_READY;
            fprintf(stderr, "LSP rotate: CRITICAL: commit of the signed replacement "
                    "failed%s\n", track ? "; held at SIGNING_READY" : "");
            return 0;
        }
    } else if (track) {
        rp->phase = LSP_ROT_PROGRESS_SIGNED;
    }

    /* Store new factory in its ladder slot (checked free before the ceremony) */
    {
        ladder_factory_t *lf_new = &lad->factories[lad->n_factories];
        memset(lf_new, 0, sizeof(*lf_new));
        lf_new->factory = lsp->factory;
        factory_detach_txbufs(&lf_new->factory);
        lf_new->factory_id = lad->next_factory_id++;
        lf_new->is_initialized = 1;
        lf_new->is_funded = 1;
        lf_new->cached_state = FACTORY_ACTIVE;
        /* #90: copy the SIGNED distribution TX from the ceremony (only
           dist_tx_ready == 2); leave the slot empty otherwise rather than
           broadcast an invalid TX.  Offline clients hold their own co-signed
           copy (wire.c ships dist_signed_tx), so fund safety is unaffected. */
        (void)ladder_factory_store_distribution_tx(lf_new, &lsp->factory);
        lad->n_factories++;
    }

    printf("LSP rotate: factory %u created and signed over %s:%u "
           "(replaces factory %u)\n",
           lad->factories[lad->n_factories - 1].factory_id,
           fund_txid_hex, fund_vout, dying_id);

    /* Close fds for uncooperative clients (partial rotation only) */
    if (partial) {
        uint32_t uncoop[FACTORY_MAX_SIGNERS];
        size_t n_uncoop = ladder_get_uncooperative_clients(lad, dying_id,
                                                            uncoop, FACTORY_MAX_SIGNERS);
        for (size_t i = 0; i < n_uncoop; i++) {
            int fd = saved_client_fds[uncoop[i] - 1];
            if (fd >= 0) wire_close(fd);
        }
        printf("LSP rotate: closed %zu uncooperative client connections\n", n_uncoop);
    }

    /* --- Phase D: Reinitialize channels --- */
    printf("LSP rotate: Phase D — reinitializing channels\n");

    /* Save rotation + infrastructure state before lsp_channels_init memset */
    int saved_bridge_fd = mgr->bridge_fd;
    watchtower_t *saved_wt = mgr->watchtower;
    void *saved_persist = mgr->persist;
    void *saved_ladder = mgr->ladder;
    /* JIT channel state preserved across reinit */
    void *saved_jit = mgr->jit_channels;
    size_t saved_n_jit = mgr->n_jit_channels;
    int saved_jit_enabled = mgr->jit_enabled;
    uint64_t saved_jit_funding = mgr->jit_funding_sats;
    unsigned char saved_seckey[32];
    memcpy(saved_seckey, mgr->rot_lsp_seckey, 32);
    void *saved_fee_est = mgr->rot_fee_est;
    unsigned char saved_fund_spk[34];
    memcpy(saved_fund_spk, mgr->rot_fund_spk, 34);
    size_t saved_fund_spk_len = mgr->rot_fund_spk_len;
    char saved_fund_addr[128];
    memcpy(saved_fund_addr, mgr->rot_fund_addr, 128);
    char saved_mine_addr[128];
    memcpy(saved_mine_addr, mgr->rot_mine_addr, 128);
    uint16_t saved_step_blocks = mgr->rot_step_blocks;
    uint32_t saved_spl = mgr->rot_states_per_layer;
    int saved_leaf_arity = mgr->rot_leaf_arity;
    int saved_is_regtest = mgr->rot_is_regtest;
    uint64_t saved_funding_sats = mgr->rot_funding_sats;
    int saved_auto_rotate = mgr->rot_auto_rotate;
    uint32_t saved_attempted_mask = mgr->rot_attempted_mask;
    uint8_t  saved_retry_count[8];
    uint32_t saved_last_attempt_block[8];
    uint32_t saved_max_retries = mgr->rot_max_retries;
    uint32_t saved_retry_base_delay = mgr->rot_retry_base_delay;
    memcpy(saved_retry_count, mgr->rot_retry_count, sizeof(saved_retry_count));
    memcpy(saved_last_attempt_block, mgr->rot_last_attempt_block,
           sizeof(saved_last_attempt_block));
    int saved_cli_enabled = mgr->cli_enabled;
    int saved_confirm_timeout = mgr->confirm_timeout_secs;

    /* Save channel balances so rotation preserves them (not reset to 50/50) */
    size_t saved_n_channels = mgr->n_channels;
    uint64_t saved_ch_local[FACTORY_MAX_SIGNERS];
    uint64_t saved_ch_remote[FACTORY_MAX_SIGNERS];
    for (size_t c = 0; c < saved_n_channels && c < FACTORY_MAX_SIGNERS; c++) {
        saved_ch_local[c] = mgr->entries[c].channel.local_amount;
        saved_ch_remote[c] = mgr->entries[c].channel.remote_amount;
    }

    /* lsp_channels_init zeroes mgr: carry the rotation marker across it. */
    lsp_rotation_progress_t *saved_rp = malloc(sizeof(*saved_rp));
    if (!saved_rp) {
        secure_zero(saved_seckey, 32);
        return 0;
    }
    *saved_rp = mgr->rot_progress;
    if (!lsp_channels_init(mgr, mgr->ctx, &lsp->factory,
                            saved_seckey, lsp->n_clients)) {
        mgr->rot_progress = *saved_rp;
        free(saved_rp);
        fprintf(stderr, "LSP rotate: channel reinit failed\n");
        secure_zero(saved_seckey, 32);
        if (rot_cer_persisted) {
            persist_update_ceremony_state(rot_db, rot_cer_id,
                                           PERSIST_CEREMONY_STATE_ABORTED);
            persist_update_ceremony_artifacts(rot_db, rot_cer_id, NULL, NULL, NULL,
                                               1, PERSIST_CEREMONY_PHASE_REFUSED);
        }
        return 0;
    }

    /* Restore saved state */
    mgr->rot_progress = *saved_rp;
    free(saved_rp);
    mgr->bridge_fd = saved_bridge_fd;
    mgr->watchtower = saved_wt;
    mgr->persist = saved_persist;
    mgr->ladder = saved_ladder;
    memcpy(mgr->rot_lsp_seckey, saved_seckey, 32);
    secure_zero(saved_seckey, 32);
    mgr->rot_fee_est = saved_fee_est;
    memcpy(mgr->rot_fund_spk, saved_fund_spk, 34);
    mgr->rot_fund_spk_len = saved_fund_spk_len;
    memcpy(mgr->rot_fund_addr, saved_fund_addr, 128);
    memcpy(mgr->rot_mine_addr, saved_mine_addr, 128);
    mgr->rot_step_blocks = saved_step_blocks;
    mgr->rot_states_per_layer = saved_spl;
    mgr->rot_leaf_arity = saved_leaf_arity;
    mgr->rot_is_regtest = saved_is_regtest;
    mgr->rot_funding_sats = saved_funding_sats;
    mgr->rot_auto_rotate = saved_auto_rotate;
    mgr->rot_attempted_mask = saved_attempted_mask;
    memcpy(mgr->rot_retry_count, saved_retry_count, sizeof(saved_retry_count));
    memcpy(mgr->rot_last_attempt_block, saved_last_attempt_block,
           sizeof(saved_last_attempt_block));
    mgr->rot_max_retries = saved_max_retries;
    mgr->rot_retry_base_delay = saved_retry_base_delay;
    mgr->jit_channels = saved_jit;
    mgr->n_jit_channels = saved_n_jit;
    mgr->jit_enabled = saved_jit_enabled;
    mgr->jit_funding_sats = saved_jit_funding;
    mgr->cli_enabled = saved_cli_enabled;
    mgr->confirm_timeout_secs = saved_confirm_timeout;

    /* Restore channel balances from old factory (carry across rotation).
       Only apply if the old (usable) balance fits within the new channel
       capacity.  funding_amount is the GROSS on-chain amount; the base
       commitment fee is reserved from it, so the conservation invariant
       (lsp_channels.c) checks local + remote + htlc_sum == funding_amount -
       base_commit_fee.  The carried local/remote is a usable total, so the
       gross funding_amount must add the base commit fee back — otherwise the
       checker sees a deficit of exactly base_commit_fee on every channel and
       the LSP refuses all new HTLCs after a rotation.  Use the same fee rate
       the channels are about to be set to below (and that the checker reads
       from ch->fee_rate_sat_per_kvb). */
    uint64_t rot_fee_rate = fe->get_rate(fe, FEE_TARGET_NORMAL);
    uint64_t rot_base_commit_fee = (rot_fee_rate * 154 + 999) / 1000;
    for (size_t c = 0; c < mgr->n_channels && c < saved_n_channels; c++) {
        channel_t *ch = &mgr->entries[c].channel;
        uint64_t old_total = saved_ch_local[c] + saved_ch_remote[c];
        uint64_t new_usable = ch->local_amount + ch->remote_amount;
        if (old_total > 0 && old_total <= new_usable) {
            ch->local_amount = saved_ch_local[c];
            ch->remote_amount = saved_ch_remote[c];
            ch->funding_amount = old_total + rot_base_commit_fee;
        }
        /* else: new factory has different capacity, keep default split */
    }

    if (!lsp_channels_exchange_basepoints(mgr, lsp)) {
        fprintf(stderr, "LSP rotate: basepoint exchange failed\n");
        return 0;
    }

    /* Set fee rate on all new channels — the same rate used above to size
       the restored channels' gross funding_amount, so the conservation
       checker reads a consistent base_commit_fee. */
    for (size_t c = 0; c < mgr->n_channels; c++)
        mgr->entries[c].channel.fee_rate_sat_per_kvb = rot_fee_rate;

    if (!lsp_channels_send_ready(mgr, lsp)) {
        fprintf(stderr, "LSP rotate: send_ready failed\n");
        return 0;
    }

    /* Watchtower channel-pointer rebind dropped in #208 A3.1b: the
       watchtower no longer derefs live channel state — penalty TX bytes
       are pre-built at revocation receive time inside
       watchtower_watch_revoked_commitment. */

    /* Persist new channel state (transactional) */
    if (mgr->persist) {
        persist_t *db = (persist_t *)mgr->persist;
        if (!persist_begin(db)) {
            fprintf(stderr, "LSP rotate: persist_begin failed for channels\n");
            return 0;
        }
        int ch_ok = 1;
        for (size_t c = 0; c < mgr->n_channels; c++) {
            channel_t *ch = &mgr->entries[c].channel;
            if (!persist_save_channel(db, ch, 0, (uint32_t)c) ||
                !persist_save_basepoints(db, (uint32_t)c, ch)) {
                ch_ok = 0;
                break;
            }
            /* Persist remote PCPs (cn=0,1) so reconnect doesn't load
               stale values from the old channel at the same slot. */
            unsigned char pcp_ser[33];
            size_t pcp_len = 33;
            secp256k1_pubkey pcp;
            if (channel_get_remote_pcp(ch, 0, &pcp) &&
                secp256k1_ec_pubkey_serialize(mgr->ctx, pcp_ser, &pcp_len,
                    &pcp, SECP256K1_EC_COMPRESSED))
                persist_save_remote_pcp(db, (uint32_t)c, 0, pcp_ser);
            pcp_len = 33;
            if (channel_get_remote_pcp(ch, 1, &pcp) &&
                secp256k1_ec_pubkey_serialize(mgr->ctx, pcp_ser, &pcp_len,
                    &pcp, SECP256K1_EC_COMPRESSED))
                persist_save_remote_pcp(db, (uint32_t)c, 1, pcp_ser);
            /* And the LSP's own per-commitment secrets for cn=0,1.  A client
               reconnect restores them from the DB; without this it restored
               the OLD channel's secrets at the same slot, so the LSP's first
               revocation on the new channel did not match the point it had
               sent, and the client refused it as forged. */
            for (uint64_t cn = 0; cn <= 1 && ch_ok; cn++) {
                unsigned char pcs[32];
                if (!channel_get_local_pcs(ch, cn, pcs) ||
                    !persist_save_local_pcs(db, (uint32_t)c, cn, pcs))
                    ch_ok = 0;
                secure_zero(pcs, sizeof(pcs));
            }
            if (!ch_ok) break;
        }
        if (ch_ok) {
            persist_commit(db);
        } else {
            fprintf(stderr, "LSP rotate: channel persist failed, rolling back\n");
            persist_rollback(db);
            if (rot_cer_persisted) {
                persist_update_ceremony_state(rot_db, rot_cer_id,
                                               PERSIST_CEREMONY_STATE_ABORTED);
                persist_update_ceremony_artifacts(rot_db, rot_cer_id, NULL, NULL, NULL,
                                                   1, PERSIST_CEREMONY_PHASE_REFUSED);
            }
            return 0;
        }
    }

    /* Migrate any active JIT channels into the new factory */
    for (size_t c = 0; c < mgr->n_channels; c++) {
        if (jit_channel_is_active(mgr, c)) {
            printf("LSP rotate: migrating JIT channel for client %zu\n", c);
            jit_channel_migrate(mgr, lsp, c, 0);
        }
    }

    /* #245 Gap A: rotation complete. Try FINALIZED — the dual-signature-trap
       guard (persist.c:6836) refuses unless every participant row is at
       phase=SIGNED. That's correct semantics for a full rotation; on a
       partial rotation some participants are at REFUSED/TIMED_OUT and the
       guard will (correctly) refuse, so fall back to PARTIAL_FAILED. */
    if (rot_cer_persisted) {
        lsp_crash_checkpoint("rotate_finalize_partial");
        if (!persist_update_ceremony_state(rot_db, rot_cer_id,
                PERSIST_CEREMONY_STATE_FINALIZED)) {
            /* Expected on partial rotation — fall back. The guard already
               logged WHY. */
            if (!persist_update_ceremony_state(rot_db, rot_cer_id,
                    PERSIST_CEREMONY_STATE_PARTIAL_FAILED)) {
                fprintf(stderr, "LSP rotate: persist_update_ceremony_state(PARTIAL_FAILED) failed (continuing)\n");
            }
        }
    }

    if (track) {
        /* Phase D done: nothing left to resume for this rotation. */
        (void)rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_DONE);
        lsp_rotation_progress_clear(mgr);
    }

    printf("LSP rotate: rotation complete — new factory active with %zu channels\n",
           mgr->n_channels);
    return 1;
}

/* CLOSING: 1 = a recorded close is confirmed (now CLOSED), 0 = wait,
   -1 = nothing to resume (marker cleared). */
static int rot_resume_close(lsp_channel_mgr_t *mgr, ladder_factory_t *dying,
                            uint32_t dying_id) {
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    regtest_t *rt = rot_rt(mgr);
    char found[65];
    int lc;
    if (mgr->persist) {
        lc = lsp_rotation_find_logged_close(mgr, rp->dying_funding_txid, found);
    } else {
        snprintf(found, sizeof(found), "%s", rp->close_txid);
        lc = rot_tx_confirmations(mgr, found) >= 1 ? 2 :
             (rot_tx_in_mempool(mgr, found) ? 1 : 0);
    }
    if (lc == 1 && mgr->rot_is_regtest && rt) {
        regtest_mine_blocks(rt, 1, mgr->rot_mine_addr);
        if (rot_tx_confirmations(mgr, found) >= 1) lc = 2;
    }
    if (lc == 2) {
        snprintf(rp->close_txid, sizeof(rp->close_txid), "%s", found);
        printf("LSP rotate: rotation close %s of factory %u is confirmed\n",
               rp->close_txid, dying_id);
        if (dying) tx_buf_free(&dying->distribution_tx);
        return rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_CLOSED) ? 1 : 0;
    }
    if (lc == 1) {
        printf("LSP rotate: rotation close %s still unconfirmed — waiting\n", found);
        return 0;
    }

    /* None of the recorded closes is confirmed or in the mempool. */
    char dtx[65];
    rot_txid_display(rp->dying_funding_txid, dtx);
    int un = rot_outpoint_unspent(mgr, dtx, rp->dying_funding_vout);
    if (un < 0) return 0;                          /* chain state unknown: later */
    if (un == 1) {
        char *hex = mgr->persist
            ? persist_load_rotation_close_hex((persist_t *)mgr->persist, dtx, rp->close_txid)
            : NULL;
        if (hex) {
            char t[65] = {0};
            int ok = rot_send_hex(mgr, hex, t);
            free(hex);
            if (ok) {
                printf("LSP rotate: rotation close %s of factory %u was not on the "
                       "network — rebroadcast it\n", rp->close_txid, dying_id);
                return 0;
            }
        }
        printf("LSP rotate: rotation close %s could not be rebroadcast and factory %u's "
               "funding is unspent — clearing the progress marker; a new rotation may "
               "run (every recorded close stays known)\n", rp->close_txid, dying_id);
        if (dying) dying->partial_rotation_done = 0;
    } else {
        fprintf(stderr, "LSP rotate: factory %u's funding was spent by a TX that is none "
                "of this LSP's recorded rotation closes — nothing to resume\n", dying_id);
    }
    (void)rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_NONE);
    lsp_rotation_progress_clear(mgr);
    return -1;
}

/* CLOSED with no funding recorded: a funding this wallet already sent after
   the close (its record lost) is adopted instead of funding again.
   1 = adopted (now FUNDING), 0 = none found, -1 = could not record. */
static int rot_adopt_wallet_funding(lsp_channel_mgr_t *mgr, ladder_t *lad) {
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    regtest_t *rt = rot_rt(mgr);
    if (!rt || rp->new_funding_txid[0]) return 0;  /* light client: the FUNDING
                                                      record is the only source */
    int cconf = rot_tx_confirmations(mgr, rp->close_txid);
    int h = rot_chain_height(mgr);
    int min_h = (cconf >= 1 && h > 0) ? h - cconf + 1 : 0;
    char (*excl)[65] = calloc(LADDER_MAX_FACTORIES + 1, 65);
    if (!excl) return 0;
    size_t ne = 0;
    for (size_t i = 0; i < lad->n_factories && ne < LADDER_MAX_FACTORIES; i++)
        rot_txid_display(lad->factories[i].factory.funding_txid, excl[ne++]);
    char txid[65];
    int found = regtest_find_wallet_send(rt, mgr->rot_fund_addr, mgr->rot_funding_sats,
                                         min_h, (const char (*)[65])excl, ne, txid);
    free(excl);
    if (!found) return 0;
    printf("LSP rotate: this wallet already sent a replacement funding %s after the "
           "close — adopting it, not funding again\n", txid);
    snprintf(rp->new_funding_txid, sizeof(rp->new_funding_txid), "%s", txid);
    free(rp->new_funding_hex);
    rp->new_funding_hex = NULL;
    rp->new_funding_vout = UINT32_MAX;
    rp->new_funding_amount = 0;
    return rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_FUNDING) ? 1 : -1;
}

/* FUNDING: 1 = confirmed (now FUNDED), 0 = wait, -1 = operator attention. */
static int rot_resume_funding(lsp_channel_mgr_t *mgr) {
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    regtest_t *rt = rot_rt(mgr);
    const char *ft = rp->new_funding_txid;
    int fconf = rot_tx_confirmations(mgr, ft);
    if (fconf < 1 && mgr->rot_is_regtest && rt && rot_tx_in_mempool(mgr, ft)) {
        regtest_mine_blocks(rt, 1, mgr->rot_mine_addr);
        fconf = rot_tx_confirmations(mgr, ft);
    }
    if (fconf >= 1) {
        uint32_t v = 0;
        uint64_t amt = 0;
        if (!rot_find_funding_output(mgr, ft, &v, &amt)) {
            fprintf(stderr, "LSP rotate: no replacement funding output in %s "
                    "(operator attention)\n", ft);
            return -1;
        }
        rp->new_funding_vout = v;
        rp->new_funding_amount = amt;
        rot_fix_ceremony_params(mgr);
        if (!rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_FUNDED)) return 0;
        printf("LSP rotate: replacement funding %s:%u is confirmed\n", ft, v);
        return 1;
    }
    if (rot_tx_in_mempool(mgr, ft)) {
        printf("LSP rotate: replacement funding %s still unconfirmed — waiting\n", ft);
        return 0;
    }
    int cdepth = rot_funding_conflict_depth(mgr);
    if (cdepth > 0) {
        int need = rot_conflict_safe_depth(mgr);
        if (cdepth < need) {
            printf("LSP rotate: an input of the recorded replacement funding %s is "
                   "spent by another TX only %d block(s) deep (need %d) — waiting "
                   "before dropping the record\n", ft, cdepth, need);
            return 0;
        }
        /* The conflicting spend is reorg-safe deep: the record can never
           confirm.  Fund anew -- still exactly one replacement funding can
           ever confirm.  Its other inputs go back to the wallet and the wallet
           stops rebroadcasting it. */
        printf("LSP rotate: recorded replacement funding %s can never confirm (an "
               "input is spent by another TX %d block(s) deep) — dropping the "
               "record; a new funding will be built\n", ft, cdepth);
        regtest_t *drt = rot_rt(mgr);
        if (drt && rp->new_funding_hex) {
            (void)regtest_unlock_tx_inputs(drt, rp->new_funding_hex);
            (void)regtest_abandon_tx(drt, ft);
        }
        rp->conflict_seen_height = 0;
        rot_release_reservation(mgr);
        rp->new_funding_txid[0] = '\0';
        free(rp->new_funding_hex);
        rp->new_funding_hex = NULL;
        rp->new_funding_vout = UINT32_MAX;
        rp->new_funding_amount = 0;
        return rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_CLOSED) ? 1 : 0;
    }
    if (rp->new_funding_hex) {
        char t[65] = {0};
        if (rot_send_hex(mgr, rp->new_funding_hex, t)) {
            printf("LSP rotate: replacement funding %s was not on the network — "
                   "rebroadcast the recorded TX\n", ft);
            rot_release_reservation(mgr);
            return 0;
        }
    }
    if (!rp->hold_reported) {
        fprintf(stderr, "LSP rotate: replacement funding %s is neither confirmed nor in "
                "the mempool and could not be rebroadcast — NOT funding a second "
                "time (operator attention)\n", ft);
        rp->hold_reported = 1;
    }
    return -1;
}

int lsp_rotation_resume(lsp_channel_mgr_t *mgr, lsp_t *lsp) {
    if (!mgr || !lsp || !mgr->ladder || !lsp_rotation_progress_pending(mgr))
        return 0;
    ladder_t *lad = (ladder_t *)mgr->ladder;
    lsp_rotation_progress_t *rp = &mgr->rot_progress;

    /* At most one attempt per block: the daemon tick, the retry path and the
       CLI can all land here. */
    int h = rot_chain_height(mgr);
    if (h > 0 && rp->last_attempt_height == (uint32_t)h) return 0;
    if (h > 0) rp->last_attempt_height = (uint32_t)h;

    /* Factory ids are not stable across a restart (the recovered factory is
       id 0): find the dying slot by its funding outpoint. */
    ladder_factory_t *dying = NULL;
    for (size_t i = 0; i < lad->n_factories; i++) {
        ladder_factory_t *lf = &lad->factories[i];
        if (lf->is_initialized &&
            lf->factory.funding_vout == rp->dying_funding_vout &&
            memcmp(lf->factory.funding_txid, rp->dying_funding_txid, 32) == 0) {
            dying = lf;
            break;
        }
    }
    uint32_t dying_id = dying ? dying->factory_id : rp->dying_factory_id;
    if (dying) dying->partial_rotation_done = 1;   /* never re-run Phase A/B on it */

    if (rp->phase == LSP_ROT_PROGRESS_SIGNING) {
        /* SIGNING without SIGNING_READY: the ceremony stopped before its first
           FACTORY_READY, so no client holds its signed tree -- run it again. */
        printf("LSP rotate: the creation ceremony over %s:%u stopped before any "
               "FACTORY_READY (nobody holds its tree) — running it again\n",
               rp->new_funding_txid, rp->new_funding_vout);
        if (!rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_FUNDED)) return 0;
    }
    if (rp->phase == LSP_ROT_PROGRESS_CLOSING &&
        rot_resume_close(mgr, dying, dying_id) <= 0)
        return 0;
    if (rp->phase == LSP_ROT_PROGRESS_CLOSED &&
        rot_adopt_wallet_funding(mgr, lad) < 0)
        return 0;
    if (rp->phase == LSP_ROT_PROGRESS_FUNDING &&
        rot_resume_funding(mgr) <= 0)
        return 0;
    if (!mgr->rot_fee_est) return 0;

    size_t on = 0;
    for (size_t i = 0; i < lsp->n_clients; i++)
        if (lsp->client_fds[i] >= 0) on++;
    int funded = rp->phase == LSP_ROT_PROGRESS_FUNDED ||
                 rp->phase == LSP_ROT_PROGRESS_SIGNING_READY;
    printf("LSP rotate: resuming rotation of factory %u — close %s confirmed, "
           "replacement %s%s%s; completing Phase C (%zu/%zu clients online)\n",
           dying_id, rp->close_txid,
           funded ? "already funded: " : "not yet funded",
           funded ? rp->new_funding_txid : "",
           rp->phase == LSP_ROT_PROGRESS_SIGNING_READY ? " (FACTORY_READY delivered before)" : "",
           on, lsp->n_clients);
    fflush(stdout);
    if (on < lsp->n_clients) return 0;

    int ok = rotation_create_replacement(mgr, lsp, lad, dying_id, /*partial*/ 0,
                                         NULL, NULL, 0);
    if (ok) lsp_rotation_record_success(mgr, dying_id);
    return ok;
}

int lsp_check_rotation_readiness(lsp_channel_mgr_t *mgr, lsp_t *lsp) {
    if (!mgr->readiness)
        return 0;

    readiness_tracker_t *rt = (readiness_tracker_t *)mgr->readiness;
    if (!readiness_all_ready(rt))
        return 0;

    printf("LSP rotate: all %zu clients ready — firing async rotation ceremony\n",
           rt->n_clients);

    int result = lsp_channels_rotate_factory(mgr, lsp);
    readiness_reset(rt);
    return result ? 1 : 0;
}
