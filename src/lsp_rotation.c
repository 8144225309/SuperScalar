/* Factory rotation extracted from lsp_channels.c */
#include <secp256k1_schnorrsig.h>
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

static int cin_record_load(lsp_channel_mgr_t *mgr);

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
    free(mgr->rot_progress.cin_signed_close_hex);
    memset(&mgr->rot_progress, 0, sizeof(mgr->rot_progress));
}

int lsp_rotation_progress_pending(const lsp_channel_mgr_t *mgr) {
    /* A close into the new factory is past the close only once it is fully
       signed and recorded (CIN_CLOSING).  Before that the old factory is the
       live one, nobody holds a signed close, and the normal retry limit and
       distribution-TX fallback apply. */
    return mgr && ((mgr->rot_progress.phase >= LSP_ROT_PROGRESS_CLOSING &&
                    mgr->rot_progress.phase <= LSP_ROT_PROGRESS_SIGNING_READY) ||
                   mgr->rot_progress.phase == LSP_ROT_PROGRESS_CIN_CLOSING ||
                   mgr->rot_progress.phase == LSP_ROT_PROGRESS_CIN_CLOSED);
}

int lsp_rotation_cin_preclose(const lsp_channel_mgr_t *mgr,
                              const unsigned char *dying_funding_txid32) {
    return mgr && dying_funding_txid32 &&
           LSP_ROT_PROGRESS_IS_CIN(mgr->rot_progress.phase) &&
           mgr->rot_progress.phase <= LSP_ROT_PROGRESS_CIN_CLOSE_SIGNING &&
           memcmp(mgr->rot_progress.dying_funding_txid, dying_funding_txid32, 32) == 0;
}

int lsp_rotation_progress_resumable(const lsp_channel_mgr_t *mgr) {
    return mgr && (lsp_rotation_progress_pending(mgr) ||
                   (LSP_ROT_PROGRESS_IS_CIN(mgr->rot_progress.phase) &&
                    mgr->rot_progress.phase <= LSP_ROT_PROGRESS_CIN_CLOSE_SIGNING) ||
                   mgr->rot_progress.phase == LSP_ROT_PROGRESS_PART_FUNDING ||
                   mgr->rot_progress.phase == LSP_ROT_PROGRESS_PART_FUNDED);
}

int lsp_rotation_cin_note_failure(lsp_rotation_progress_t *rp, uint32_t height,
                                  uint32_t max_retries, uint32_t base_delay) {
    if (!rp) return 0;
    if (max_retries == 0) max_retries = 3;
    if (base_delay == 0) base_delay = 2;
    rp->cin_failures++;
    if (rp->cin_failures > max_retries) return 0;
    uint32_t shift = rp->cin_failures < 20 ? rp->cin_failures : 20;
    rp->cin_next_try_height = height + base_delay * (1u << shift);
    return 1;
}

int lsp_rotation_cin_abandon(lsp_channel_mgr_t *mgr,
                             const unsigned char *dying_funding_txid32) {
    if (!lsp_rotation_cin_preclose(mgr, dying_funding_txid32)) return 0;
    /* No full signature of the recorded close exists (the LSP records it
       before anyone can hold it), so the rotation can be dropped. */
    printf("LSP rotate: abandoning the unsigned close %s into a new factory\n",
           mgr->rot_progress.close_txid);
    fflush(stdout);
    (void)rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_DONE);
    lsp_rotation_progress_clear(mgr);
    return 1;
}

static int rot_load_progress_row(lsp_channel_mgr_t *mgr,
                                 const unsigned char *dying_funding_txid32,
                                 uint32_t dying_funding_vout, int dropped_cin);

int lsp_rotation_load_progress(lsp_channel_mgr_t *mgr,
                               const unsigned char *dying_funding_txid32,
                               uint32_t dying_funding_vout) {
    return rot_load_progress_row(mgr, dying_funding_txid32, dying_funding_vout, 0);
}

int lsp_rotation_cin_reload_recorded(lsp_channel_mgr_t *mgr,
                                     const unsigned char *dying_funding_txid32,
                                     uint32_t dying_funding_vout, uint32_t dying_factory_id) {
    if (!rot_load_progress_row(mgr, dying_funding_txid32, dying_funding_vout, 1)) return 0;
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    rp->dying_factory_id = dying_factory_id;
    rp->phase = LSP_ROT_PROGRESS_CIN_CLOSE_BUILT;
    if (!rot_progress_persist(mgr)) {
        lsp_rotation_progress_clear(mgr);
        return 0;
    }
    printf("LSP rotate: reusing the recorded close %s of this factory (never fully "
           "signed)\n", rp->close_txid);
    fflush(stdout);
    return 1;
}

static int rot_load_progress_row(lsp_channel_mgr_t *mgr,
                                 const unsigned char *dying_funding_txid32,
                                 uint32_t dying_funding_vout, int dropped_cin) {
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
    if (dropped_cin && row.phase == LSP_ROT_PROGRESS_DONE && row.close_txid[0] &&
        row.new_funding_amount > 0)
        row.phase = LSP_ROT_PROGRESS_CIN_CLOSE_BUILT;   /* checked against its record below */
    else if (dropped_cin)
        row.phase = LSP_ROT_PROGRESS_NONE;
    if (row.dying_funding_vout != dying_funding_vout ||
        ((row.phase < LSP_ROT_PROGRESS_CLOSING || row.phase > LSP_ROT_PROGRESS_SIGNING_READY) &&
         !LSP_ROT_PROGRESS_IS_CIN(row.phase))) {
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
    if (LSP_ROT_PROGRESS_IS_CIN(mgr->rot_progress.phase) && !cin_record_load(mgr)) {
        fprintf(stderr, "LSP rotate: the close-into-new record of the rotation is missing "
                "-- ignoring its marker\n");
        lsp_rotation_progress_clear(mgr);
        return 0;
    }
    if (dropped_cin && (!LSP_ROT_PROGRESS_IS_CIN(mgr->rot_progress.phase) ||
                        mgr->rot_progress.cin_signed_close_hex)) {
        lsp_rotation_progress_clear(mgr);   /* not a dropped close into a new factory */
        return 0;
    }
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
    int ready_phase = LSP_ROT_PROGRESS_IS_CIN(saved_phase)
                          ? LSP_ROT_PROGRESS_CIN_SIGNING_READY
                          : LSP_ROT_PROGRESS_SIGNING_READY;
    if (!rot_progress_set_phase(mgr, ready_phase)) {
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
uint64_t lsp_rotation_commit_fee_rate(void *fee_estimator) {
    fee_estimator_t *fe = (fee_estimator_t *)fee_estimator;
    uint64_t r = (fe && fe->get_rate) ? fe->get_rate(fe, FEE_TARGET_NORMAL) : 0;
    if (r < CHANNEL_COMMIT_FEE_RATE_MIN) r = CHANNEL_COMMIT_FEE_RATE_MIN;
    if (r > CHANNEL_COMMIT_FEE_RATE_MAX) r = CHANNEL_COMMIT_FEE_RATE_MAX;
    return r;
}

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
static int lsp_rotation_close_into_new(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                       ladder_factory_t *dying);
static int lsp_rotation_cin_resume(lsp_channel_mgr_t *mgr, lsp_t *lsp);
static int lsp_rotation_partial(lsp_channel_mgr_t *mgr, lsp_t *lsp, ladder_factory_t *dying,
                                const unsigned char *in_set);

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
    if (mgr->part_rel.valid &&
        memcmp(mgr->part_rel.new_txid, dying->factory.funding_txid, 32) == 0)
        memset(&mgr->part_rel, 0, sizeof(mgr->part_rel));

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

    /* Every client online and able to: close the old factory straight into
       the new one, co-signed, with fresh client keys.  No key leaves anyone. */
    int cin_ok = lsp_rotation_cin_eligible(mgr, lsp) &&
                 memcmp(lsp->factory.funding_txid, dying->factory.funding_txid, 32) == 0;
    if (cin_ok && superscalar_cheat_allowed() && getenv("SS_TEST_ROTATE_PARTIAL")) {
        /* Regtest only: the partial path with every client (wind-down tests). */
        printf("LSP rotate: SS_TEST_ROTATE_PARTIAL: partial rotation although every "
               "client is online\n");
        cin_ok = 0;
    }
    if (cin_ok)
        return lsp_rotation_close_into_new(mgr, lsp, dying);
    /* A recorded, unsigned close into the new factory: only that ceremony may
       run for this factory (another close could race it).  Until every client
       is back this attempt fails, so the retry limit, and then the
       distribution TX, still apply. */
    if (lsp_rotation_cin_preclose(mgr, dying->factory.funding_txid)) {
        fprintf(stderr, "LSP rotate: factory %u has a recorded close into a new factory "
                "that is not signed yet; it needs every client online\n", dying_id);
        return 0;
    }
    /* Some clients offline or not upgraded: the able ones move with a
       verified release.  No client key is asked for the old way once any
       client of the factory is upgraded. */
    if (lsp_rotation_any_upgraded(lsp) &&
        memcmp(lsp->factory.funding_txid, dying->factory.funding_txid, 32) == 0) {
        unsigned char in_set[LSP_MAX_CLIENTS];
        memset(in_set, 0, sizeof(in_set));
        if (lsp_rotation_partial_set(mgr, lsp, in_set) == 0) {
            fprintf(stderr, "LSP rotate: no client of factory %u can take part in a "
                    "rotation now\n", dying_id);
            return 0;
        }
        return lsp_rotation_partial(mgr, lsp, dying, in_set);
    }

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
    uint64_t rot_fee_rate = lsp_rotation_commit_fee_rate(fe);
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

static int lsp_rotation_part_resume(lsp_channel_mgr_t *mgr, lsp_t *lsp);

int lsp_rotation_resume(lsp_channel_mgr_t *mgr, lsp_t *lsp) {
    if (!mgr || !lsp || !mgr->ladder || !lsp_rotation_progress_resumable(mgr))
        return 0;
    ladder_t *lad = (ladder_t *)mgr->ladder;
    lsp_rotation_progress_t *rp = &mgr->rot_progress;

    /* At most one attempt per block: the daemon tick, the retry path and the
       CLI can all land here. */
    int h = rot_chain_height(mgr);
    if (h > 0 && rp->last_attempt_height == (uint32_t)h) return 0;
    if (h > 0) rp->last_attempt_height = (uint32_t)h;

    if (LSP_ROT_PROGRESS_IS_CIN(rp->phase))
        return lsp_rotation_cin_resume(mgr, lsp);
    if (LSP_ROT_PROGRESS_IS_PART(rp->phase))
        return lsp_rotation_part_resume(mgr, lsp);

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

/* ===================================================================
   Close into the new factory (every old client online).

   No key leaves anyone.  Each client sends a fresh factory key; the LSP
   builds the UNSIGNED cooperative close of the old factory whose single
   output is the replacement's funding output (its txid is fixed before any
   signature); the replacement's creation ceremony runs over that outpoint;
   the new channels are set up and each client gets an LSP-signed initial
   commitment; each client checks all of it, stores it, and only then signs
   the close with its OLD key.  The close is recorded together with the
   replacement before any client can hold the signed close; then it is
   broadcast.  Until it confirms the old factory stays valid, after it the
   replacement is: exactly one of the two worlds happens.
   =================================================================== */

lsp_cin_resume_action_t lsp_rotation_cin_resume_action(int phase, int close_confs,
                                                       int in_mempool, int all_online) {
    if (!LSP_ROT_PROGRESS_IS_CIN(phase)) return LSP_CIN_RESUME_NONE;
    if (phase <= LSP_ROT_PROGRESS_CIN_CLOSE_SIGNING)
        return all_online ? LSP_CIN_RESUME_RERUN : LSP_CIN_RESUME_WAIT;
    if (phase == LSP_ROT_PROGRESS_CIN_CLOSED || close_confs >= 1)
        return LSP_CIN_RESUME_FINISH;
    return in_mempool ? LSP_CIN_RESUME_WAIT : LSP_CIN_RESUME_REBROADCAST;
}

static int cin_pk_eq(const secp256k1_context *ctx, const secp256k1_pubkey *a,
                     const secp256k1_pubkey *b) {
    unsigned char sa[33], sb[33];
    size_t la = 33, lb = 33;
    return secp256k1_ec_pubkey_serialize(ctx, sa, &la, a, SECP256K1_EC_COMPRESSED) &&
           secp256k1_ec_pubkey_serialize(ctx, sb, &lb, b, SECP256K1_EC_COMPRESSED) &&
           memcmp(sa, sb, 33) == 0;
}

int lsp_rotation_cin_check_keys(const secp256k1_context *ctx,
                                const secp256k1_pubkey *lsp_pk,
                                const secp256k1_pubkey *old_pks, size_t n_old,
                                const secp256k1_pubkey *identity_pks,
                                const secp256k1_pubkey *client_pks, size_t n,
                                const char **why) {
    const char *dummy;
    if (!why) why = &dummy;
    *why = NULL;
    if (!ctx || !lsp_pk || !client_pks || n == 0) { *why = "bad arguments"; return 0; }
    for (size_t i = 0; i < n; i++) {
        if (cin_pk_eq(ctx, &client_pks[i], lsp_pk)) { *why = "a key equals the LSP key"; return 0; }
        for (size_t j = 0; old_pks && j < n_old; j++)
            if (cin_pk_eq(ctx, &client_pks[i], &old_pks[j])) {
                *why = "a key is reused from the old factory";
                return 0;
            }
        for (size_t j = 0; identity_pks && j < n; j++)
            if (cin_pk_eq(ctx, &client_pks[i], &identity_pks[j])) {
                *why = "a key is a client identity key";
                return 0;
            }
        for (size_t j = i + 1; j < n; j++)
            if (cin_pk_eq(ctx, &client_pks[i], &client_pks[j])) {
                *why = "two clients sent the same key";
                return 0;
            }
    }
    return 1;
}

int lsp_rotation_cin_carry(uint64_t old_lsp, uint64_t old_client, uint64_t new_usable,
                           uint64_t reserve, uint64_t *new_lsp, uint64_t *new_client) {
    (void)old_lsp;
    if (!new_lsp || !new_client || new_usable < old_client) return 0;
    if (new_usable - old_client < reserve) return 0;
    *new_client = old_client;
    *new_lsp = new_usable - old_client;
    return 1;
}

int lsp_rotation_cin_eligible(const lsp_channel_mgr_t *mgr, const lsp_t *lsp) {
    if (!mgr || !lsp || !lsp->client_rotation_v || lsp->n_clients == 0 ||
        mgr->n_channels != lsp->n_clients)
        return 0;
    for (size_t i = 0; i < lsp->n_clients; i++) {
        if (lsp->client_fds[i] < 0 || lsp->client_rotation_v[i] < 1 ||
            mgr->entries[i].offline_detected)
            return 0;
    }
    return 1;
}

static void cin_pks_to_hex(const lsp_rotation_progress_t *rp, char *out) {
    for (size_t i = 0; i < rp->n_cin_pubkeys; i++)
        hex_encode(rp->cin_pubkeys[i], 33, out + i * 66);
    out[rp->n_cin_pubkeys * 66] = '\0';
}

static int cin_pks_from_hex(lsp_rotation_progress_t *rp, const char *hex) {
    size_t len = hex ? strlen(hex) : 0;
    if (len == 0 || len % 66 != 0 || len / 66 > FACTORY_MAX_SIGNERS) return 0;
    rp->n_cin_pubkeys = len / 66;
    for (size_t i = 0; i < rp->n_cin_pubkeys; i++) {
        char one[67];
        memcpy(one, hex + i * 66, 66);
        one[66] = '\0';
        if (hex_decode(one, rp->cin_pubkeys[i], 33) != 33) return 0;
    }
    return 1;
}

/* Write the CIN record (participants, height, signed close) next to the
   progress row.  Standalone statement (or inside the caller's transaction). */
static int cin_record_save(lsp_channel_mgr_t *mgr) {
    persist_t *db = (persist_t *)mgr->persist;
    if (!db) return 1;
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    char dtx[65];
    rot_txid_display(rp->dying_funding_txid, dtx);
    char *pk_hex = malloc(rp->n_cin_pubkeys * 66 + 1);
    if (!pk_hex) return 0;
    cin_pks_to_hex(rp, pk_hex);
    int ok = persist_save_rotation_cin(db, dtx, pk_hex, rp->cin_close_height,
                                       rp->cin_signed_close_hex);
    free(pk_hex);
    return ok;
}

static int cin_record_load(lsp_channel_mgr_t *mgr) {
    persist_t *db = (persist_t *)mgr->persist;
    if (!db) return 0;
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    char dtx[65];
    rot_txid_display(rp->dying_funding_txid, dtx);
    char *pk_hex = NULL, *sh = NULL;
    uint32_t h = 0;
    if (persist_load_rotation_cin(db, dtx, &pk_hex, &h, &sh) != 1) return 0;
    int ok = cin_pks_from_hex(rp, pk_hex);
    free(pk_hex);
    rp->cin_close_height = h;
    free(rp->cin_signed_close_hex);
    rp->cin_signed_close_hex = sh;
    return ok;
}


/* Build the unsigned close of OLD paying OUTPUT (the replacement funding);
   TXID32 (internal order) and its hex. */
static int cin_build_close(const factory_t *old, const tx_output_t *output, uint32_t height,
                           unsigned char txid32[32], char **hex_out) {
    tx_buf_t tx;
    tx_buf_init(&tx, 256);
    unsigned char sighash[32];
    int ok = factory_build_cooperative_close_unsigned((factory_t *)old, &tx, sighash,
                                                      output, 1, height) &&
             tx_txid_from_bytes(tx.data, tx.len, txid32);
    if (ok && hex_out) {
        *hex_out = malloc(tx.len * 2 + 1);
        if (*hex_out) hex_encode(tx.data, tx.len, *hex_out);
        else ok = 0;
    }
    tx_buf_free(&tx);
    return ok;
}

/* ROTATION_BEGIN(v=1, close_into_new) to every client; collect each
   client's fresh replacement key. */
int lsp_rotation_channels_quiet(const lsp_channel_mgr_t *mgr, const unsigned char *in_set) {
    if (!mgr) return 0;
    for (size_t c = 0; c < mgr->n_channels; c++) {
        if (in_set && !in_set[c]) continue;
        const channel_t *ch = &mgr->entries[c].channel;
        for (size_t h = 0; h < ch->n_htlcs; h++)
            if (ch->htlcs[h].state == HTLC_STATE_ACTIVE) return 0;
    }
    return 1;
}

/* A message a client sends while the LSP waits for its rotation key. */
static int rot_is_channel_msg(uint8_t t) {
    return t == MSG_UPDATE_ADD_HTLC || t == MSG_UPDATE_FULFILL_HTLC ||
           t == MSG_UPDATE_FAIL_HTLC || t == MSG_COMMITMENT_SIGNED ||
           t == MSG_REVOKE_AND_ACK;
}

/* ROTATION_BEGIN {v, mode} to the clients IDX[0..m) (old slot order) and
   their MSG_ROTATION_KEY into OUT[0..m). */
static int rot_collect_keys(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                            const unsigned char *dying_txid32, secp256k1_pubkey *out,
                            const size_t *idx, size_t m, const char *mode, int v) {
    unsigned char nonce[32];
    if (!channel_read_random_bytes(nonce, 32)) return 0;
    uint64_t epoch = (uint64_t)time(NULL);
    for (size_t k = 0; k < m; k++) {
        size_t i = idx[k];
        cJSON *rb = wire_build_rotation_begin(dying_txid32, nonce, epoch);
        cJSON_AddNumberToObject(rb, "v", v);
        cJSON_AddStringToObject(rb, "mode", mode);
        int sent = wire_send(lsp->client_fds[i], MSG_ROTATION_BEGIN, rb);
        cJSON_Delete(rb);
        if (!sent) {
            fprintf(stderr, "LSP rotate: send ROTATION_BEGIN to client %zu failed\n", i);
            return 0;
        }
    }
    for (size_t k = 0; k < m; k++) {
        size_t i = idx[k];
        secp256k1_pubkey *slot_out = &out[k];
        int got = 0;
        for (int tries = 0; tries < 64 && !got; tries++) {
            wire_msg_t m;
            memset(&m, 0, sizeof(m));
            if (!wire_recv_timeout(lsp->client_fds[i], &m, 60)) break;
            if (m.msg_type == MSG_ROTATION_KEY) {
                unsigned char d[32];
                got = wire_parse_rotation_key(m.json, mgr->ctx, slot_out, d) &&
                      memcmp(d, dying_txid32, 32) == 0;
                if (!got)
                    fprintf(stderr, "LSP rotate: bad ROTATION_KEY from client %zu\n", i);
                cJSON_Delete(m.json);
                if (!got) return 0;
            } else if (m.msg_type == MSG_ERROR) {
                fprintf(stderr, "LSP rotate: client %zu refused the rotation\n", i);
                cJSON_Delete(m.json);
                return 0;
            } else if (rot_is_channel_msg(m.msg_type) && i < mgr->n_channels) {
                /* Channel traffic (a payment, a preimage): handle it as usual,
                   never drop it, and try the rotation again later. */
                fprintf(stderr, "LSP rotate: client %zu sent channel traffic (0x%02x) during "
                        "the rotation -- handling it; rotation retried later\n", i,
                        m.msg_type);
                (void)lsp_channels_handle_msg(mgr, lsp, i, &m);
                cJSON_Delete(m.json);
                return 0;
            } else {
                if (m.json) cJSON_Delete(m.json);      /* ping and such: keep waiting */
            }
        }
        if (!got) {
            fprintf(stderr, "LSP rotate: no ROTATION_KEY from client %zu\n", i);
            return 0;
        }
    }
    return 1;
}

static int cin_collect_keys(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                            const unsigned char *dying_txid32, secp256k1_pubkey *out) {
    size_t idx[FACTORY_MAX_SIGNERS];
    size_t n = lsp->n_clients < FACTORY_MAX_SIGNERS ? lsp->n_clients : FACTORY_MAX_SIGNERS;
    for (size_t i = 0; i < n; i++) idx[i] = i;
    return rot_collect_keys(mgr, lsp, dying_txid32, out, idx, n, "close_into_new", 1);
}

static void cin_tell_abort(lsp_t *lsp, const char *why) {
    for (size_t i = 0; i < lsp->n_clients; i++) {
        if (lsp->client_fds[i] < 0) continue;
        cJSON *e = wire_build_error(why);
        wire_send(lsp->client_fds[i], MSG_ERROR, e);
        cJSON_Delete(e);
    }
}

static int cin_wait_confirm(lsp_channel_mgr_t *mgr, lsp_t *lsp, const char *txid) {
    regtest_t *rt = rot_rt(mgr);
    chain_backend_t *chain_be = (chain_backend_t *)mgr->chain_be;
    if (mgr->rot_is_regtest && rt) {
        regtest_mine_blocks(rt, 1, mgr->rot_mine_addr);
        return rot_tx_confirmations(mgr, txid) >= 1;
    }
    int timeout = mgr->confirm_timeout_secs > 0 ? mgr->confirm_timeout_secs : 7200;
    if (chain_be)
        return lsp_wait_for_confirmation_service(chain_be, txid, timeout,
                   chain_close_confs(chain_be, chain_be->is_regtest), mgr, lsp) ? 1 : 0;
    if (rt)
        return regtest_wait_for_stable_confirmation(rt, txid,
                   regtest_network_safe_confirmation_depth(rt), 3, timeout) >= 1;
    return 0;
}

/* Everything the close's before-CLOSE_DONE hook persists. */
typedef struct {
    lsp_channel_mgr_t *mgr;
    lsp_t *lsp;
    lsp_channel_mgr_t *tm;          /* the replacement's channels */
    const char *close_txid;         /* recorded (display) */
} cin_closing_ctx_t;

/* The close is fully signed and nobody else holds it yet: record it with
   the replacement factory and channels, in ONE transaction, as CIN_CLOSING. */
static int cin_record_closing(void *vctx, const tx_buf_t *signed_tx) {
    cin_closing_ctx_t *c = (cin_closing_ctx_t *)vctx;
    lsp_channel_mgr_t *mgr = c->mgr;
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    unsigned char t32[32];
    char t_disp[65];
    if (!tx_txid_from_bytes(signed_tx->data, signed_tx->len, t32)) return 0;
    rot_txid_display(t32, t_disp);
    if (strcmp(t_disp, c->close_txid) != 0) {
        fprintf(stderr, "LSP rotate: the signed close %s is not the recorded close %s\n",
                t_disp, c->close_txid);
        return 0;
    }
    char *hex = malloc(signed_tx->len * 2 + 1);
    if (!hex) return 0;
    hex_encode(signed_tx->data, signed_tx->len, hex);
    lsp_crash_checkpoint("rotate_close_signed");
    persist_t *db = (persist_t *)mgr->persist;
    char *saved_hex = rp->cin_signed_close_hex;
    rp->cin_signed_close_hex = hex;
    int saved_phase = rp->phase;
    rp->phase = LSP_ROT_PROGRESS_CIN_CLOSING;
    if (db) {
        char dtx[65];
        rot_txid_display(rp->dying_funding_txid, dtx);
        int ok = persist_begin(db);
        ok = ok && persist_add_rotation_close(db, dtx, c->close_txid, hex);
        ok = ok && cin_record_save(mgr);
        ok = ok && persist_save_factory(db, &c->lsp->factory, mgr->ctx, 0) &&
             persist_save_tree_nodes(db, &c->lsp->factory, 0) &&
             lsp_save_client_identities(c->lsp, db, mgr->ctx, 0);
        for (size_t i = 0; ok && i < c->tm->n_channels; i++) {
            channel_t *ch = &c->tm->entries[i].channel;
            ok = persist_save_channel(db, ch, 0, (uint32_t)i) &&
                 persist_save_basepoints(db, (uint32_t)i, ch);
            for (uint64_t cn = 0; ok && cn <= 1; cn++) {
                secp256k1_pubkey pcp;
                unsigned char ser[33], pcs[32];
                size_t len = 33;
                if (channel_get_remote_pcp(ch, cn, &pcp) &&
                    secp256k1_ec_pubkey_serialize(mgr->ctx, ser, &len, &pcp,
                                                  SECP256K1_EC_COMPRESSED))
                    ok = persist_save_remote_pcp(db, (uint32_t)i, cn, ser);
                if (ok && channel_get_local_pcs(ch, cn, pcs))
                    ok = persist_save_local_pcs(db, (uint32_t)i, cn, pcs);
                secure_zero(pcs, sizeof(pcs));
            }
        }
        if (ok) {
            persist_rotation_progress_t row;
            rot_progress_to_row(rp, &row);
            ok = persist_save_rotation_progress(db, dtx, &row);
        }
        if (!ok || !persist_commit(db)) {
            if (persist_in_transaction(db)) persist_rollback(db);
            fprintf(stderr, "LSP rotate: CRITICAL: could not record the signed close "
                    "with the replacement -- abandoning the close\n");
            rp->cin_signed_close_hex = saved_hex;
            rp->phase = saved_phase;
            secure_zero(hex, strlen(hex));
            free(hex);
            return 0;
        }
    }
    free(saved_hex);
    printf("LSP rotate: close %s fully signed and recorded with the replacement "
           "(CIN_CLOSING)\n", c->close_txid);
    fflush(stdout);
    return 1;
}

/* Move the replacement's channels from TM into MGR (old channels freed). */
static void cin_adopt_channels(lsp_channel_mgr_t *mgr, lsp_channel_mgr_t *tm) {
    for (size_t i = 0; i < mgr->n_channels; i++)
        channel_cleanup(&mgr->entries[i].channel);
    free(mgr->entries);
    mgr->entries = tm->entries;
    mgr->n_channels = tm->n_channels;
    mgr->entries_cap = tm->entries_cap;
    mgr->leaf_arity = tm->leaf_arity;
    for (size_t i = 0; i < mgr->n_channels; i++)
        if (mgr->persist)
            channel_set_persist(&mgr->entries[i].channel, (persist_t *)mgr->persist,
                                (uint32_t)i);
    tm->entries = NULL;
    tm->n_channels = 0;
    lsp_channels_cleanup(tm);           /* tm's own invoice / origin arrays */
    free(tm);
}

static void cin_drop_channels(lsp_channel_mgr_t *tm) {
    if (!tm) return;
    lsp_channels_cleanup(tm);
    free(tm);
}

/* After CIN_CLOSED: ladder bookkeeping, tell the clients, clear the marker. */
static int cin_finish(lsp_channel_mgr_t *mgr, lsp_t *lsp, ladder_factory_t *dying) {
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    if (rp->phase != LSP_ROT_PROGRESS_CIN_CLOSED &&
        !rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_CIN_CLOSED))
        return 0;
    if (dying) {
        dying->partial_rotation_done = 1;
        tx_buf_free(&dying->distribution_tx);  /* its funding is spent */
    }
    snprintf(mgr->rot_last_cin_close_txid, sizeof(mgr->rot_last_cin_close_txid), "%s",
             rp->close_txid);
    free(mgr->rot_last_cin_close_hex);
    mgr->rot_last_cin_close_hex = rp->cin_signed_close_hex
                                      ? strdup(rp->cin_signed_close_hex) : NULL;
    for (size_t i = 0; i < lsp->n_clients; i++) {
        if (lsp->client_fds[i] < 0) continue;
        cJSON *d = wire_build_rotation_done(rp->close_txid, rp->cin_signed_close_hex, 1);
        wire_send(lsp->client_fds[i], MSG_ROTATION_DONE, d);
        cJSON_Delete(d);
    }
    (void)rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_DONE);
    printf("LSP rotate: rotation complete — close %s confirmed; new factory active "
           "with %zu channels (no key revealed)\n", rp->close_txid, mgr->n_channels);
    fflush(stdout);
    lsp_rotation_progress_clear(mgr);
    return 1;
}

static int cin_tree_matches(lsp_channel_mgr_t *mgr, lsp_t *lsp, const unsigned char *spk) {
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    if (strlen(rp->tree_digest) != 64) return -1;
    unsigned char ftxid[32];
    if (hex_decode(rp->new_funding_txid, ftxid, 32) != 32) return -1;
    reverse_bytes(ftxid, 32);
    const uint64_t *sa = lsp->dist_client_amounts;
    size_t sn = lsp->dist_n_client_amounts;
    lsp->dist_client_amounts = rp->dist_amounts;
    lsp->dist_n_client_amounts = rp->n_dist_amounts;
    unsigned char d[32];
    int ok = lsp_factory_creation_digest(lsp, lsp->client_pubkeys, lsp->n_clients,
                                         ftxid, 0, rp->new_funding_amount, spk, 34,
                                         mgr->rot_step_blocks, mgr->rot_states_per_layer,
                                         rp->new_cltv, d);
    lsp->dist_client_amounts = sa;
    lsp->dist_n_client_amounts = sn;
    if (!ok) return -1;
    char dh[65];
    hex_encode(d, 32, dh);
    return strcmp(dh, rp->tree_digest) == 0 ? 1 : 0;
}

/* Run (or re-run over the recorded close) the close-into-new rotation of the
   live factory, which is DYING.  Returns 1 when the replacement is active. */
static int lsp_rotation_close_into_new(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                       ladder_factory_t *dying) {
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    fee_estimator_t *fe = (fee_estimator_t *)mgr->rot_fee_est;
    ladder_t *lad = (ladder_t *)mgr->ladder;
    if (!fe || !lad || !dying) return 0;
    factory_t *old = &lsp->factory;
    if (memcmp(old->funding_txid, dying->factory.funding_txid, 32) != 0 ||
        old->funding_vout != dying->factory.funding_vout) {
        fprintf(stderr, "LSP rotate: the live factory is not the dying one -- not "
                "rotating by a close into the new factory\n");
        return 0;
    }
    size_t n = lsp->n_clients;
    /* A close of this factory recorded by an earlier, dropped attempt is used
       again: a client that signed it signs no other close of its factory. */
    if (!lsp_rotation_cin_preclose(mgr, old->funding_txid))
        (void)lsp_rotation_cin_reload_recorded(mgr, old->funding_txid, old->funding_vout,
                                               dying->factory_id);
    int resuming = rp->phase >= LSP_ROT_PROGRESS_CIN_CLOSE_BUILT &&
                   rp->phase <= LSP_ROT_PROGRESS_CIN_CLOSE_SIGNING &&
                   memcmp(rp->dying_funding_txid, old->funding_txid, 32) == 0;
    printf("LSP rotate: close into the new factory (all %zu clients online%s)\n", n,
           resuming ? ", over the recorded close" : "");
    fflush(stdout);

    /* No HTLC may be in flight across the switch: the old channels' balances
       are what the replacement carries.  Wait for them to settle (the
       rotation is retried) instead of failing them on this side only. */
    if (!lsp_rotation_channels_quiet(mgr, NULL)) {
        fprintf(stderr, "LSP rotate: an HTLC is in flight on a channel of factory %u -- "
                "not rotating yet\n", dying->factory_id);
        return 0;
    }

    /* C0/C1: fresh keys. */
    secp256k1_pubkey new_pks[FACTORY_MAX_SIGNERS];
    if (!cin_collect_keys(mgr, lsp, old->funding_txid, new_pks)) {
        cin_tell_abort(lsp, "rotation aborted: keys");
        return 0;
    }
    {
        const char *why = NULL;
        if (!lsp_rotation_cin_check_keys(mgr->ctx, &lsp->lsp_pubkey, old->pubkeys,
                                         old->n_participants, lsp->client_identity_pubkeys
                                             ? lsp->client_identity_pubkeys : NULL,
                                         new_pks, n, &why)) {
            fprintf(stderr, "LSP rotate: refusing the replacement keys: %s\n", why);
            cin_tell_abort(lsp, "rotation aborted: keys not fresh");
            return 0;
        }
    }
    secp256k1_pubkey parts[FACTORY_MAX_SIGNERS];
    parts[0] = lsp->lsp_pubkey;
    for (size_t i = 0; i < n; i++) parts[i + 1] = new_pks[i];
    if (resuming) {
        int same = rp->n_cin_pubkeys == n + 1;
        for (size_t i = 0; same && i <= n; i++) {
            unsigned char ser[33];
            size_t len = 33;
            same = secp256k1_ec_pubkey_serialize(mgr->ctx, ser, &len, &parts[i],
                                                 SECP256K1_EC_COMPRESSED) &&
                   memcmp(ser, rp->cin_pubkeys[i], 33) == 0;
        }
        if (!same) {
            /* No full signature of the recorded close exists (phase is at most
               CIN_CLOSE_SIGNING), and a close over other keys has another txid:
               the recorded one can never be completed.  Start over. */
            printf("LSP rotate: the clients' replacement keys changed; the recorded close "
                   "%s was never fully signed and is dropped\n", rp->close_txid);
            (void)rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_NONE);
            lsp_rotation_progress_clear(mgr);
            resuming = 0;
        }
    }

    /* C2: the unsigned close paying the replacement funding. */
    unsigned char spk[34];
    if (!factory_funding_spk_for(mgr->ctx, parts, n + 1, spk)) return 0;
    tx_output_t out;
    memset(&out, 0, sizeof(out));
    memcpy(out.script_pubkey, spk, 34);
    out.script_pubkey_len = 34;
    unsigned char close_txid32[32];
    char close_disp[65];
    if (!resuming) {
        /* One key-path input, one P2TR output: about 111 vB.  The close is
           signed by everyone and cannot be fee-bumped, so round up. */
        const size_t close_vsize = 125;
        uint64_t fee = fee_estimate(fe, close_vsize);
        if (fee < close_vsize) fee = close_vsize;          /* >= 1 sat/vB */
        if (fee == 0 || fee >= old->funding_amount_sats / 50) {
            fprintf(stderr, "LSP rotate: close fee %llu too high for a close into the "
                    "new factory\n", (unsigned long long)fee);
            cin_tell_abort(lsp, "rotation aborted: fee");
            return 0;
        }
        int h = rot_chain_height(mgr);
        if (h <= 0) { cin_tell_abort(lsp, "rotation aborted: no chain"); return 0; }
        out.amount_sats = old->funding_amount_sats - fee;
        char *hex = NULL;
        if (!cin_build_close(old, &out, (uint32_t)h, close_txid32, &hex)) {
            cin_tell_abort(lsp, "rotation aborted: close");
            return 0;
        }
        rot_txid_display(close_txid32, close_disp);
        lsp_rotation_progress_clear(mgr);
        rp->dying_factory_id = dying->factory_id;
        memcpy(rp->dying_funding_txid, old->funding_txid, 32);
        rp->dying_funding_vout = old->funding_vout;
        snprintf(rp->close_txid, sizeof(rp->close_txid), "%s", close_disp);
        snprintf(rp->new_funding_txid, sizeof(rp->new_funding_txid), "%s", close_disp);
        rp->new_funding_hex = hex;                       /* the UNSIGNED close */
        rp->new_funding_vout = 0;
        rp->new_funding_amount = out.amount_sats;
        rp->cin_close_height = (uint32_t)h;
        rp->n_cin_pubkeys = n + 1;
        for (size_t i = 0; i <= n; i++) {
            size_t len = 33;
            secp256k1_ec_pubkey_serialize(mgr->ctx, rp->cin_pubkeys[i], &len, &parts[i],
                                          SECP256K1_EC_COMPRESSED);
        }
        rot_fix_ceremony_params(mgr);
        rp->phase = LSP_ROT_PROGRESS_CIN_CLOSE_BUILT;
        if (!cin_record_save(mgr) || !rot_progress_persist(mgr)) {
            lsp_rotation_progress_clear(mgr);
            cin_tell_abort(lsp, "rotation aborted: record");
            return 0;
        }
        printf("LSP rotate: close %s of factory %u built (unsigned): pays %llu sats into "
               "the replacement funding\n", close_disp, dying->factory_id,
               (unsigned long long)out.amount_sats);
        fflush(stdout);
        lsp_crash_checkpoint("rotate_close_built");
    } else {
        out.amount_sats = rp->new_funding_amount;
        if (!cin_build_close(old, &out, rp->cin_close_height, close_txid32, NULL)) return 0;
        rot_txid_display(close_txid32, close_disp);
        if (strcmp(close_disp, rp->close_txid) != 0) {
            fprintf(stderr, "LSP rotate: the close rebuilt from the record (%s) is not the "
                    "recorded close %s -- holding\n", close_disp, rp->close_txid);
            cin_tell_abort(lsp, "rotation aborted: record mismatch");
            return 0;
        }
    }

    /* C3: the replacement over close:0, with the fresh keys. */
    secp256k1_pubkey *saved_pks = malloc(n * sizeof(secp256k1_pubkey));
    if (!saved_pks) return 0;
    memcpy(saved_pks, lsp->client_pubkeys, n * sizeof(secp256k1_pubkey));
    for (size_t i = 0; i < n; i++) lsp->client_pubkeys[i] = new_pks[i];
    factory_t old_f;
    if (!lsp_factory_detach(lsp, &old_f)) {
        memcpy(lsp->client_pubkeys, saved_pks, n * sizeof(secp256k1_pubkey));
        free(saved_pks);
        return 0;
    }
    lsp->factory.leaf_arity = (factory_arity_t)mgr->rot_leaf_arity;
    cJSON *rot = cJSON_CreateObject();
    cJSON_AddStringToObject(rot, "mode", "close_into_new");
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i <= n; i++) {
        char h66[67];
        hex_encode(rp->cin_pubkeys[i], 33, h66);
        cJSON_AddItemToArray(arr, cJSON_CreateString(h66));
    }
    cJSON_AddItemToObject(rot, "pubkeys", arr);
    cJSON_AddNumberToObject(rot, "close_height", (double)rp->cin_close_height);
    {
        char od[65];
        rot_txid_display(old_f.funding_txid, od);
        cJSON_AddStringToObject(rot, "old_txid", od);
        cJSON_AddNumberToObject(rot, "old_vout", (double)old_f.funding_vout);
    }
    lsp_channel_mgr_t *tm = NULL;
    int ok = 1;
    int delivered_before = rp->phase == LSP_ROT_PROGRESS_CIN_SIGNING_READY;
    if (delivered_before && cin_tree_matches(mgr, lsp, spk) != 1) {
        fprintf(stderr, "LSP rotate: the replacement tree delivered before cannot be "
                "rebuilt byte-identically -- holding (no second tree over %s:0)\n",
                rp->close_txid);
        ok = 0;
    }
    if (ok && !delivered_before && !rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_CIN_SIGNING))
        ok = 0;
    if (ok) {
        lsp->propose_rotation = rot;
        lsp->before_factory_ready = rot_before_factory_ready;
        lsp->before_factory_ready_ctx = mgr;
        lsp->dist_client_amounts = rp->dist_amounts;
        lsp->dist_n_client_amounts = rp->n_dist_amounts;
        ok = lsp_run_factory_creation(lsp, close_txid32, 0, rp->new_funding_amount, spk, 34,
                                      mgr->rot_step_blocks, mgr->rot_states_per_layer,
                                      rp->new_cltv);
        lsp->propose_rotation = NULL;
        lsp->before_factory_ready = NULL;
        lsp->before_factory_ready_ctx = NULL;
        lsp->dist_client_amounts = NULL;
        lsp->dist_n_client_amounts = 0;
        if (!ok) {
            fprintf(stderr, "LSP rotate: replacement creation ceremony failed\n");
            if (rp->phase == LSP_ROT_PROGRESS_CIN_SIGNING)
                (void)rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_CIN_CLOSE_BUILT);
        }
    }
    cJSON_Delete(rot);
    if (ok) {
        lsp->factory.fee = fe;
        int ch_h = rot_chain_height(mgr);
        if (ch_h > 0)
            factory_set_lifecycle(&lsp->factory, (uint32_t)ch_h, lad->active_blocks,
                                  lad->dying_blocks);
        lsp_crash_checkpoint("rotate_ceremony_signed");
    }

    /* Channels over the replacement, built aside: the old ones stay intact
       until the close is recorded. */
    if (ok) {
        tm = calloc(1, sizeof(*tm));
        ok = tm != NULL;
        if (ok) {
            tm->routing_fee_ppm = mgr->routing_fee_ppm;
            tm->lsp_balance_pct = mgr->lsp_balance_pct;
            tm->fee = mgr->fee;
            tm->persist = NULL;          /* nothing reaches the DB before CIN_CLOSING */
            ok = lsp_channels_init(tm, mgr->ctx, &lsp->factory, mgr->rot_lsp_seckey, n);
            if (!ok) { free(tm); tm = NULL; }
        }
    }
    if (ok) {
        uint64_t rate = lsp_rotation_commit_fee_rate(fe);
        uint64_t base_fee = (rate * 154 + 999) / 1000;
        for (size_t c = 0; ok && c < n; c++) {
            channel_t *nc = &tm->entries[c].channel;
            const channel_t *oc = &mgr->entries[c].channel;
            uint64_t usable = nc->funding_amount > base_fee ? nc->funding_amount - base_fee : 0;
            uint64_t l = 0, r = 0;
            if (!lsp_rotation_cin_carry(oc->local_amount, oc->remote_amount, usable, 0, &l, &r)) {
                fprintf(stderr, "LSP rotate: client %zu's balance %llu does not fit the "
                        "replacement channel (%llu)\n", c,
                        (unsigned long long)oc->remote_amount, (unsigned long long)usable);
                ok = 0;
                break;
            }
            nc->local_amount = l;
            nc->remote_amount = r;
            nc->fee_rate_sat_per_kvb = rate;
        }
    }
    if (ok) ok = lsp_channels_exchange_basepoints(tm, lsp) && lsp_channels_send_ready(tm, lsp);
    /* Each client gets an LSP-signed initial commitment (cn 0) with its
       carried balance, so its exit from the replacement is complete before it
       signs the close. */
    for (size_t c = 0; ok && c < n; c++) {
        unsigned char psig[32];
        uint32_t nidx = 0;
        channel_t *nc = &tm->entries[c].channel;
        if (!channel_create_commitment_partial_sig(nc, psig, &nidx)) { ok = 0; break; }
        cJSON *cs = wire_build_commitment_signed(tm->entries[c].channel_id, 0, psig, nidx);
        ok = wire_send(lsp->client_fds[c], MSG_COMMITMENT_SIGNED, cs);
        cJSON_Delete(cs);
    }
    if (ok) lsp_crash_checkpoint("rotate_initial_commitments");

    /* C4: the close, signed by everyone with the OLD keys. */
    if (ok && !rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_CIN_CLOSE_SIGNING)) ok = 0;
    tx_buf_t signed_close;
    tx_buf_init(&signed_close, 256);
    if (ok) {
        lsp_crash_checkpoint("rotate_close_signing");
        cin_closing_ctx_t cc = { mgr, lsp, tm, rp->close_txid };
        int rc = 0;
        for (int attempt = 0; attempt < 3; attempt++) {
            rc = lsp_run_cooperative_close_with(lsp, &old_f, &signed_close, &out, 1,
                                                rp->cin_close_height,
                                                cin_record_closing, &cc);
            if (rc != 2) break;
        }
        ok = rc == 1 && rp->phase == LSP_ROT_PROGRESS_CIN_CLOSING;
        if (!ok) fprintf(stderr, "LSP rotate: the close ceremony did not complete\n");
    }
    if (!ok) {
        /* Nothing irreversible happened: the old factory and channels are the
           live ones again.  The marker keeps the recorded close for a retry. */
        cin_drop_channels(tm);
        lsp_factory_reattach(lsp, &old_f);
        memcpy(lsp->client_pubkeys, saved_pks, n * sizeof(secp256k1_pubkey));
        free(saved_pks);
        tx_buf_free(&signed_close);
        if (rp->phase != LSP_ROT_PROGRESS_CIN_CLOSING)
            cin_tell_abort(lsp, "rotation aborted");
        return 0;
    }

    /* From here the replacement is the live factory (recorded as such). */
    free(saved_pks);
    cin_adopt_channels(mgr, tm);
    factory_free(&old_f);
    {
        char sent[65] = {0};
        int sent_ok = rot_send_hex(mgr, rp->cin_signed_close_hex, sent);
        if (mgr->persist)
            persist_log_broadcast((persist_t *)mgr->persist, rp->close_txid,
                                  "rotation_close_into_new", rp->cin_signed_close_hex,
                                  sent_ok ? "ok" : "failed");
        printf("LSP rotate: close %s broadcast%s\n", rp->close_txid,
               sent_ok ? "" : " FAILED (the resume rebroadcasts it)");
        fflush(stdout);
    }
    tx_buf_free(&signed_close);
    lsp_crash_checkpoint("rotate_close_sent");

    /* Ladder slot for the replacement. */
    if (lad->n_factories >= LADDER_MAX_FACTORIES) ladder_evict_expired(lad);
    if (lad->n_factories < LADDER_MAX_FACTORIES) {
        ladder_factory_t *lf_new = &lad->factories[lad->n_factories];
        memset(lf_new, 0, sizeof(*lf_new));
        lf_new->factory = lsp->factory;
        factory_detach_txbufs(&lf_new->factory);
        lf_new->factory_id = lad->next_factory_id++;
        lf_new->is_initialized = 1;
        lf_new->is_funded = 1;
        lf_new->cached_state = FACTORY_ACTIVE;
        (void)ladder_factory_store_distribution_tx(lf_new, &lsp->factory);
        lad->n_factories++;
    }
    dying = ladder_get_by_id(lad, rp->dying_factory_id);
    if (!cin_wait_confirm(mgr, lsp, rp->close_txid)) {
        fprintf(stderr, "LSP rotate: close %s not confirmed yet (the resume waits)\n",
                rp->close_txid);
        return 0;
    }
    return cin_finish(mgr, lsp, dying);
}


/* ===================================================================
   Partial rotation with verified release (some old clients offline or not
   upgraded).  The clients online and able now (M) move into a replacement
   the LSP funds to their fresh keys, signed before it is funded.  Once the
   funding is confirmed each of them checks its position from its own data
   and only then releases its old factory key (MSG_ROTATION_RELEASE), against
   an LSP receipt over exactly that position.  The other clients stay in the
   old factory, which is left as it is (their exits and its distribution TX
   are unchanged).
   =================================================================== */

int lsp_rotation_client_is_legacy(const lsp_t *lsp, size_t c) {
    if (!lsp || c >= lsp->n_clients) return 1;
    if (!lsp->client_identity_pubkeys) return 1;
    static const unsigned char zero[sizeof(secp256k1_pubkey)];
    const secp256k1_pubkey *id = &lsp->client_identity_pubkeys[c];
    if (memcmp(id, zero, sizeof(zero)) == 0) return 1;  /* "same as the factory key" */
    unsigned char a[33], b[33];
    size_t la = 33, lb = 33;
    if (!secp256k1_ec_pubkey_serialize(lsp->ctx, a, &la, id, SECP256K1_EC_COMPRESSED) ||
        !secp256k1_ec_pubkey_serialize(lsp->ctx, b, &lb, &lsp->client_pubkeys[c],
                                       SECP256K1_EC_COMPRESSED))
        return 1;
    return memcmp(a, b, 33) == 0;
}

size_t lsp_rotation_partial_set(const lsp_channel_mgr_t *mgr, const lsp_t *lsp,
                                unsigned char *in_set) {
    size_t m = 0;
    if (!mgr || !lsp || !in_set) return 0;
    for (size_t c = 0; c < lsp->n_clients && c < mgr->n_channels; c++) {
        in_set[c] = 0;
        if (lsp->client_fds[c] < 0 || !lsp->client_rotation_v ||
            lsp->client_rotation_v[c] < 2 || mgr->entries[c].offline_detected)
            continue;
        /* A JIT channel signed with the client's key is closed first. */
        jit_channel_t *j = jit_channel_find((void *)mgr, c);
        if (j && j->state != JIT_STATE_NONE && j->state != JIT_STATE_CLOSED) continue;
        /* A legacy factory (the client signs with its identity key) has
           nothing that may ever be released. */
        if (lsp_rotation_client_is_legacy(lsp, c)) continue;
        in_set[c] = 1;
        m++;
    }
    return m;
}

int lsp_rotation_any_upgraded(const lsp_t *lsp) {
    if (!lsp || !lsp->client_rotation_v) return 0;
    for (size_t c = 0; c < lsp->n_clients; c++)
        if (lsp->client_rotation_v[c] >= 1) return 1;
    return 0;
}

static int rot_rd_varint(const unsigned char *t, size_t len, size_t *off, uint64_t *v) {
    if (*off >= len) return 0;
    unsigned char b = t[(*off)++];
    if (b < 0xfd) { *v = b; return 1; }
    size_t n = b == 0xfd ? 2 : (b == 0xfe ? 4 : 8);
    if (*off + n > len) return 0;
    *v = 0;
    for (size_t i = 0; i < n; i++) *v |= (uint64_t)t[*off + i] << (8 * i);
    *off += n;
    return 1;
}

/* The output of TX_HEX paying SPK34: its index and amount. */
static int rot_hex_find_output(const char *tx_hex, const unsigned char *spk34,
                               uint32_t *vout, uint64_t *amount) {
    size_t hl = tx_hex ? strlen(tx_hex) : 0;
    if (hl < 20 || hl % 2) return 0;
    unsigned char *t = malloc(hl / 2);
    if (!t || hex_decode(tx_hex, t, hl / 2) != (int)(hl / 2)) { free(t); return 0; }
    size_t len = hl / 2, off = 4;
    int ok = 0;
    if (t[4] == 0x00 && t[5] == 0x01) off = 6;
    uint64_t n_in = 0, n_out = 0, sl = 0;
    if (!rot_rd_varint(t, len, &off, &n_in)) goto done;
    for (uint64_t i = 0; i < n_in; i++) {
        if (off + 36 > len) goto done;
        off += 36;
        if (!rot_rd_varint(t, len, &off, &sl) || sl > len || off + sl + 4 > len) goto done;
        off += sl + 4;
    }
    if (!rot_rd_varint(t, len, &off, &n_out)) goto done;
    for (uint64_t i = 0; i < n_out; i++) {
        if (off + 8 > len) goto done;
        uint64_t a = 0;
        for (int b = 0; b < 8; b++) a |= (uint64_t)t[off + b] << (8 * b);
        off += 8;
        if (!rot_rd_varint(t, len, &off, &sl) || sl > len || off + sl > len) goto done;
        if (sl == 34 && memcmp(t + off, spk34, 34) == 0) {
            *vout = (uint32_t)i;
            *amount = a;
            ok = 1;
            goto done;
        }
        off += sl;
    }
done:
    free(t);
    return ok;
}

typedef struct {
    int *fds;
    secp256k1_pubkey *pks;
    secp256k1_pubkey *ids;
    uint8_t *rv;
    size_t n;
} rot_client_save_t;

static int rot_clients_save(const lsp_t *lsp, rot_client_save_t *s) {
    memset(s, 0, sizeof(*s));
    s->n = lsp->n_clients;
    s->fds = malloc(s->n * sizeof(int));
    s->pks = malloc(s->n * sizeof(secp256k1_pubkey));
    s->ids = malloc(s->n * sizeof(secp256k1_pubkey));
    s->rv = malloc(s->n);
    if (!s->fds || !s->pks || !s->ids || !s->rv) return 0;
    memcpy(s->fds, lsp->client_fds, s->n * sizeof(int));
    memcpy(s->pks, lsp->client_pubkeys, s->n * sizeof(secp256k1_pubkey));
    if (lsp->client_identity_pubkeys)
        memcpy(s->ids, lsp->client_identity_pubkeys, s->n * sizeof(secp256k1_pubkey));
    else
        memcpy(s->ids, lsp->client_pubkeys, s->n * sizeof(secp256k1_pubkey));
    if (lsp->client_rotation_v) memcpy(s->rv, lsp->client_rotation_v, s->n);
    else memset(s->rv, 0, s->n);
    return 1;
}

static void rot_clients_restore(lsp_t *lsp, const rot_client_save_t *s) {
    memcpy(lsp->client_fds, s->fds, s->n * sizeof(int));
    memcpy(lsp->client_pubkeys, s->pks, s->n * sizeof(secp256k1_pubkey));
    if (lsp->client_identity_pubkeys)
        memcpy(lsp->client_identity_pubkeys, s->ids, s->n * sizeof(secp256k1_pubkey));
    if (lsp->client_rotation_v) memcpy(lsp->client_rotation_v, s->rv, s->n);
    lsp->n_clients = s->n;
}

static void rot_clients_free(rot_client_save_t *s) {
    free(s->fds); free(s->pks); free(s->ids); free(s->rv);
    memset(s, 0, sizeof(*s));
}

/* lsp's client slots become the subset IDX[0..m) with the new keys. */
static void rot_clients_remap(lsp_t *lsp, const rot_client_save_t *s, const size_t *idx,
                              size_t m, const secp256k1_pubkey *new_pks) {
    for (size_t j = 0; j < m; j++) {
        lsp->client_fds[j] = s->fds[idx[j]];
        lsp->client_pubkeys[j] = new_pks[j];
        if (lsp->client_identity_pubkeys) lsp->client_identity_pubkeys[j] = s->ids[idx[j]];
        if (lsp->client_rotation_v) lsp->client_rotation_v[j] = s->rv[idx[j]];
    }
    for (size_t j = m; j < s->n; j++) lsp->client_fds[j] = -1;
    lsp->n_clients = m;
}

/* The replacement, its channels and the client identities, recorded in ONE
   transaction before its funding is broadcast. */
static void rot_tell_abort_set(lsp_t *lsp, const size_t *idx, size_t m, const char *why) {
    for (size_t k = 0; k < m; k++) {
        size_t i = idx[k];
        if (i >= lsp->n_clients || lsp->client_fds[i] < 0) continue;
        cJSON *e = wire_build_error(why);
        wire_send(lsp->client_fds[i], MSG_ERROR, e);
        cJSON_Delete(e);
    }
}

int lsp_rotation_partial_may_start(const lsp_channel_mgr_t *mgr) {
    return lsp_rotation_channels_quiet(mgr, NULL);
}

int lsp_rotation_part_is_retired(const lsp_channel_mgr_t *mgr, const secp256k1_pubkey *pk) {
    if (!mgr || !pk) return 0;
    secp256k1_context *ctx = mgr->ctx;
    for (size_t i = 0; i < mgr->n_part_retired; i++)
        if (cin_pk_eq(ctx, &mgr->part_retired_ids[i], pk)) return 1;
    if (!mgr->persist) return 0;
    size_t n = persist_load_retired_channels((persist_t *)mgr->persist, NULL, NULL, (size_t)-1);
    if (n == 0) return 0;
    unsigned char (*ids)[33] = calloc(n, 33);
    if (!ids) return 0;
    n = persist_load_retired_channels((persist_t *)mgr->persist, NULL, ids, n);
    unsigned char ser[33];
    size_t l = 33;
    int found = 0;
    if (secp256k1_ec_pubkey_serialize(ctx, ser, &l, pk, SECP256K1_EC_COMPRESSED))
        for (size_t i = 0; i < n && !found; i++)
            found = memcmp(ids[i], ser, 33) == 0;
    free(ids);
    return found;
}

static void part_rel_fill(lsp_channel_mgr_t *mgr, lsp_t *lsp, const factory_t *old_f,
                          const size_t *idx, size_t m, const secp256k1_pubkey *new_pks,
                          const uint64_t *carried, const unsigned char ftxid32[32],
                          uint32_t fvout, size_t n_old) {
    memset(&mgr->part_rel, 0, sizeof(mgr->part_rel));
    if (!factory_tree_digest(&lsp->factory, mgr->part_rel.digest)) return;
    mgr->part_rel.dying_id = mgr->rot_progress.dying_factory_id;
    mgr->part_rel.n_old = (uint32_t)n_old;
    memcpy(mgr->part_rel.old_txid, old_f->funding_txid, 32);
    mgr->part_rel.old_vout = old_f->funding_vout;
    memcpy(mgr->part_rel.new_txid, ftxid32, 32);
    mgr->part_rel.new_vout = fvout;
    mgr->part_rel.m = m;
    for (size_t j = 0; j < m; j++) {
        size_t l = 33;
        secp256k1_ec_pubkey_serialize(mgr->ctx, mgr->part_rel.old_pk[j], &l,
                                      &old_f->pubkeys[idx[j] + 1], SECP256K1_EC_COMPRESSED);
        l = 33;
        secp256k1_ec_pubkey_serialize(mgr->ctx, mgr->part_rel.new_pk[j], &l, &new_pks[j],
                                      SECP256K1_EC_COMPRESSED);
        mgr->part_rel.old_slot[j] = (uint32_t)idx[j];
        mgr->part_rel.carried[j] = carried[j];
    }
    mgr->part_rel.old_cltv = old_f->cltv_timeout;
    mgr->part_rel.valid = 1;
}

/* The old factory's ladder slot (this process), found by its funding. */
static ladder_factory_t *part_ladder_slot(lsp_channel_mgr_t *mgr) {
    ladder_t *lad = (ladder_t *)mgr->ladder;
    for (size_t i = 0; lad && i < lad->n_factories; i++) {
        ladder_factory_t *lf = &lad->factories[i];
        if (lf->is_initialized && lf->factory.funding_vout == mgr->part_rel.old_vout &&
            memcmp(lf->factory.funding_txid, mgr->part_rel.old_txid, 32) == 0)
            return lf;
    }
    return NULL;
}

static void part_binding(const lsp_channel_mgr_t *mgr, size_t j, unsigned char out[32]) {
    factory_release_binding(mgr->part_rel.old_txid, mgr->part_rel.old_vout,
                            mgr->part_rel.new_txid, mgr->part_rel.new_vout,
                            mgr->part_rel.digest, mgr->part_rel.new_pk[j],
                            mgr->part_rel.carried[j], (uint32_t)(j + 1), out);
}

static int part_send_release_req(lsp_channel_mgr_t *mgr, lsp_t *lsp, size_t j) {
    if (!mgr->part_rel.valid || j >= mgr->part_rel.m || j >= lsp->n_clients ||
        lsp->client_fds[j] < 0 || mgr->part_rel.released[j])
        return 0;
    unsigned char bind[32], sig[64], aux[32];
    secp256k1_keypair lkp;
    part_binding(mgr, j, bind);
    int ok = secp256k1_keypair_create(mgr->ctx, &lkp, mgr->rot_lsp_seckey) &&
             channel_read_random_bytes(aux, 32) &&
             secp256k1_schnorrsig_sign32(mgr->ctx, sig, bind, &lkp, aux);
    secure_zero(&lkp, sizeof(lkp));
    if (!ok) return 0;
    cJSON *rq = wire_build_rotation_release_req(mgr->part_rel.new_txid, bind, sig);
    ok = rq && wire_send(lsp->client_fds[j], MSG_ROTATION_RELEASE_REQ, rq);
    cJSON_Delete(rq);
    return ok;
}

int lsp_rotation_part_on_reconnect(lsp_channel_mgr_t *mgr, lsp_t *lsp, size_t c) {
    if (!mgr || !lsp || !mgr->part_rel.valid || c >= mgr->part_rel.m ||
        mgr->part_rel.released[c])
        return 0;
    if (!mgr->part_rel.funded) {
        char t[65];
        rot_txid_display(mgr->part_rel.new_txid, t);
        if (rot_tx_confirmations(mgr, t) < 1) return 0;
        mgr->part_rel.funded = 1;
    }
    int ok = part_send_release_req(mgr, lsp, c);
    if (ok)
        printf("LSP rotate: asked client %zu again for its old factory key\n", c);
    return ok;
}

#define LSP_PART_REASK_BLOCKS 3

size_t lsp_rotation_part_reask(lsp_channel_mgr_t *mgr, lsp_t *lsp) {
    if (!mgr || !lsp || !mgr->part_rel.valid || mgr->rot_progress.phase != LSP_ROT_PROGRESS_NONE)
        return 0;
    int h = rot_chain_height(mgr);
    if (h <= 0 || (mgr->part_reask_height &&
                   (uint32_t)h < mgr->part_reask_height + LSP_PART_REASK_BLOCKS))
        return 0;
    mgr->part_reask_height = (uint32_t)h;
    size_t asked = 0;
    for (size_t j = 0; j < mgr->part_rel.m; j++)
        if (!mgr->part_rel.released[j] && lsp_rotation_part_on_reconnect(mgr, lsp, j))
            asked++;
    return asked;
}

int lsp_rotation_part_on_release(lsp_channel_mgr_t *mgr, lsp_t *lsp, size_t c,
                                 const cJSON *json) {
    (void)lsp;
    if (!mgr || !json || !mgr->part_rel.valid || c >= mgr->part_rel.m) return 0;
    if (mgr->part_rel.released[c]) return 1;
    if (!mgr->part_rel.settled[c]) {
        /* Only with the revocation of its latest old commitment: otherwise
           that commitment still pays the client the balance it carried. */
        fprintf(stderr, "LSP rotate: client %zu sent its key before settling its old "
                "channel -- not counted\n", (size_t)mgr->part_rel.old_slot[c]);
        return 0;
    }
    unsigned char bind[32], b2[32], sk[32], ser[33];
    secp256k1_pubkey pub;
    size_t l = 33;
    part_binding(mgr, c, bind);
    int ok = wire_parse_rotation_release(json, b2, sk) && memcmp(b2, bind, 32) == 0 &&
             secp256k1_ec_pubkey_create(mgr->ctx, &pub, sk) &&
             secp256k1_ec_pubkey_serialize(mgr->ctx, ser, &l, &pub, SECP256K1_EC_COMPRESSED) &&
             memcmp(ser, mgr->part_rel.old_pk[c], 33) == 0;
    uint32_t old_slot = mgr->part_rel.old_slot[c];
    uint32_t pidx = old_slot + 1;           /* its participant index in the old factory */
    persist_t *db = (persist_t *)mgr->persist;
    if (ok && db) {
        /* The key and the end of what is owed, together. */
        char otx[65];
        rot_txid_display(mgr->part_rel.old_txid, otx);
        int own = !persist_in_transaction(db);
        ok = (!own || persist_begin(db)) &&
             persist_save_departed_client(db, mgr->part_rel.retired_id, pidx, sk) &&
             persist_set_part_released(db, otx, (uint32_t)c);
        if (own) {
            if (ok) ok = persist_commit(db);
            else persist_rollback(db);
        }
    }
    if (ok) {
        ladder_factory_t *lf = part_ladder_slot(mgr);
        if (lf) (void)ladder_record_key_turnover((ladder_t *)mgr->ladder, lf->factory_id,
                                                 pidx, sk);
    }
    secure_zero(sk, sizeof(sk));
    if (!ok) {
        fprintf(stderr, "LSP rotate: client %zu sent a release that does not match its old "
                "factory key\n", (size_t)old_slot);
        return 0;
    }
    mgr->part_rel.released[c] = 1;
    printf("LSP rotate: client %zu released its old factory key (verified release)\n",
           (size_t)old_slot);
    fflush(stdout);
    if (mgr->rot_progress.phase == LSP_ROT_PROGRESS_NONE)
        (void)lsp_rotation_winddown_tick(mgr, 1);      /* the last one: close now */
    return 1;
}

/* ---- The settlement of a mover's old channel (part of its release) ---- */

uint32_t lsp_rotation_part_old_channel_id(const lsp_channel_mgr_t *mgr, size_t c) {
    return LSP_RETIRED_CHANNEL_ID(mgr->part_rel.retired_id - LSP_RETIRED_FACTORY_ID(0),
                                  mgr->part_rel.old_slot[c]);
}

int lsp_rotation_part_release_row(lsp_channel_mgr_t *mgr, size_t c,
                                  persist_part_release_t *out) {
    persist_t *db = (persist_t *)mgr->persist;
    if (!db) return 0;
    persist_part_release_t *rel = calloc(FACTORY_MAX_SIGNERS, sizeof(*rel));
    if (!rel) return 0;
    char otx[65];
    rot_txid_display(mgr->part_rel.old_txid, otx);
    size_t n = persist_load_part_releases(db, otx, rel, FACTORY_MAX_SIGNERS);
    int found = 0;
    for (size_t k = 0; k < n && !found; k++)
        if (rel[k].j == c) { *out = rel[k]; found = 1; }
    free(rel);
    return found;
}

/* The loader of a mover's old channel lives with the other secret loaders
   (lsp_init_from_db.c); the LSP daemon registers it. */
static int (*g_part_old_loader)(lsp_channel_mgr_t *, size_t, channel_t *) = NULL;

void lsp_rotation_set_old_channel_loader(int (*fn)(lsp_channel_mgr_t *, size_t, channel_t *)) {
    g_part_old_loader = fn;
}

static int part_load_old(lsp_channel_mgr_t *mgr, size_t c, channel_t *ch) {
    return g_part_old_loader && g_part_old_loader(mgr, c, ch);
}

int lsp_rotation_settle_offer(channel_t *ch, uint64_t carried, int already,
                              const unsigned char client_nonce66[66],
                              wire_rotation_settle_t *out) {
    if (!ch || !client_nonce66 || !out) return 0;
    for (size_t i = 0; i < ch->n_htlcs; i++)
        if (ch->htlcs[i].state == HTLC_STATE_ACTIVE) return 0;
    for (size_t i = 0; i < ch->n_ptlcs; i++)
        if (ch->ptlcs[i].state == PTLC_STATE_ACTIVE) return 0;
    if (!already) {
        uint64_t mv = ch->remote_amount < carried ? ch->remote_amount : carried;
        ch->remote_amount -= mv;
        ch->local_amount += mv;
        ch->commitment_number++;
    }
    if (!channel_init_nonce_pool(ch, 1) ||
        !channel_set_remote_pubnonces(ch, (const unsigned char (*)[66])client_nonce66, 1) ||
        !musig_pubnonce_serialize(ch->ctx, out->pubnonce, &ch->local_nonce_pool.nonces[0].pubnonce) ||
        !channel_create_commitment_partial_sig(ch, out->partial_sig, &out->nonce_index))
        return 0;
    out->commitment_number = ch->commitment_number;
    out->client_amount = ch->remote_amount;
    out->lsp_amount = ch->local_amount;
    out->fee_rate = ch->fee_rate_sat_per_kvb;
    return 1;
}

int lsp_rotation_part_on_settle_req(lsp_channel_mgr_t *mgr, lsp_t *lsp, size_t c,
                                    const cJSON *json) {
    if (!mgr || !lsp || !json || !mgr->part_rel.valid || c >= mgr->part_rel.m ||
        c >= lsp->n_clients || lsp->client_fds[c] < 0 || mgr->part_rel.released[c])
        return 0;
    unsigned char ot[32], nonce[66];
    uint64_t cn = 0;
    if (!wire_parse_rotation_settle_req(json, ot, &cn, nonce) ||
        memcmp(ot, mgr->part_rel.old_txid, 32) != 0)
        return 0;
    channel_t ch;
    if (!part_load_old(mgr, c, &ch)) {
        fprintf(stderr, "LSP rotate: the old channel of client %zu could not be loaded -- no "
                "settlement\n", (size_t)mgr->part_rel.old_slot[c]);
        return 0;
    }
    int already = mgr->part_rel.settled[c];
    wire_rotation_settle_t s;
    memset(&s, 0, sizeof(s));
    int ok = (already ? cn + 1 == ch.commitment_number : cn == ch.commitment_number) &&
             lsp_rotation_settle_offer(&ch, mgr->part_rel.carried[c], already, nonce, &s);
    if (ok) {
        memcpy(s.old_txid, mgr->part_rel.old_txid, 32);
        cJSON *m = wire_build_rotation_settle(&s);
        ok = m && wire_send(lsp->client_fds[c], MSG_ROTATION_SETTLE, m);
        cJSON_Delete(m);
    } else {
        fprintf(stderr, "LSP rotate: client %zu asked to settle its old channel at commitment "
                "%llu (ours: %llu) -- refused\n", (size_t)mgr->part_rel.old_slot[c],
                (unsigned long long)cn, (unsigned long long)ch.commitment_number);
        cJSON *e = wire_build_error("settlement refused");
        if (e) { wire_send(lsp->client_fds[c], MSG_ERROR, e); cJSON_Delete(e); }
    }
    channel_cleanup(&ch);
    return ok;
}

int lsp_rotation_part_on_settle_ack(lsp_channel_mgr_t *mgr, lsp_t *lsp, size_t c,
                                    const cJSON *json) {
    (void)lsp;
    if (!mgr || !json || !mgr->part_rel.valid || c >= mgr->part_rel.m) return 0;
    uint32_t cid_w = 0;
    unsigned char sec[32], np[33];
    if (!wire_parse_revoke_and_ack(json, &cid_w, sec, np)) return 0;
    channel_t ch;
    if (!part_load_old(mgr, c, &ch)) {
        secure_zero(sec, sizeof(sec));
        return 0;
    }
    size_t slot = (size_t)mgr->part_rel.old_slot[c];
    int ok;
    if (mgr->part_rel.settled[c]) {
        /* Answered again: the revocation is already held. */
        ok = ch.commitment_number > 0 &&
             channel_verify_revocation_secret(&ch, ch.commitment_number - 1, sec);
        secure_zero(sec, sizeof(sec));
        channel_cleanup(&ch);
        return ok;
    }
    uint64_t old_cn = ch.commitment_number;
    uint64_t old_local = ch.local_amount, old_remote = ch.remote_amount;
    if (!channel_verify_revocation_secret(&ch, old_cn, sec)) {
        fprintf(stderr, "LSP rotate: client %zu sent an INVALID revocation of its old "
                "commitment %llu -- not settled\n", slot, (unsigned long long)old_cn);
        secure_zero(sec, sizeof(sec));
        channel_cleanup(&ch);
        return 0;
    }
    persist_t *db = (persist_t *)mgr->persist;
    uint32_t cid = lsp_rotation_part_old_channel_id(mgr, c);
    char otx[65];
    rot_txid_display(mgr->part_rel.old_txid, otx);
    uint64_t mv = old_remote < mgr->part_rel.carried[c] ? old_remote : mgr->part_rel.carried[c];
    int own = !persist_in_transaction(db);
    ok = !own || persist_begin(db);
    /* The revocation, the watch on the revoked commitment (its penalty built
       now and kept), and the settled state, together. */
    ok = ok && channel_receive_revocation(&ch, old_cn, sec);
    char wtx[65] = "none";
    if (ok && mgr->watchtower) {
        watchtower_t *wt = mgr->watchtower;
        size_t before = wt->n_entries;
        watchtower_watch_revoked_commitment(wt, &ch, cid, old_cn, old_local, old_remote,
                                            NULL, 0, NULL, 0);
        if (wt->n_entries > before) {
            unsigned char d[32];
            memcpy(d, wt->entries[before].txid, 32);
            reverse_bytes(d, 32);
            hex_encode(d, 32, wtx);
        }
    }
    ok = ok && persist_update_channel_balance(db, cid, old_local + mv, old_remote - mv,
                                              old_cn + 1) &&
         persist_set_part_settled(db, otx, (uint32_t)c);
    if (own) {
        if (ok) ok = persist_commit(db);
        else persist_rollback(db);
    }
    secure_zero(sec, sizeof(sec));
    channel_cleanup(&ch);
    if (!ok) {
        fprintf(stderr, "LSP rotate: could not record the settlement of client %zu\n", slot);
        return 0;
    }
    mgr->part_rel.settled[c] = 1;
    printf("LSP rotate: client %zu settled its old channel: %llu sats back to the LSP, its "
           "old commitment %llu revoked and watched (%s)\n", slot, (unsigned long long)mv,
           (unsigned long long)old_cn, wtx);
    fflush(stdout);
    return 1;
}

static int part_save_record(lsp_channel_mgr_t *mgr, persist_t *db, const factory_t *old_f) {
    if (!mgr->part_rel.valid || old_f->n_participants != (size_t)mgr->part_rel.n_old + 1)
        return 0;
    persist_part_rotation_t *r = calloc(1, sizeof(*r));
    if (!r) return 0;
    rot_txid_display(mgr->part_rel.old_txid, r->old_txid);
    r->old_vout = mgr->part_rel.old_vout;
    r->retired_id = mgr->part_rel.retired_id;
    rot_txid_display(mgr->part_rel.new_txid, r->new_txid);
    r->new_vout = mgr->part_rel.new_vout;
    memcpy(r->digest, mgr->part_rel.digest, 32);
    r->n_old = mgr->part_rel.n_old;
    r->m = (uint32_t)mgr->part_rel.m;
    r->old_amount = old_f->funding_amount_sats;
    r->old_cltv = old_f->cltv_timeout;
    int ok = 1;
    for (size_t i = 0; ok && i < old_f->n_participants; i++) {
        size_t l = 33;
        ok = secp256k1_ec_pubkey_serialize(mgr->ctx, r->old_pks[i], &l, &old_f->pubkeys[i],
                                           SECP256K1_EC_COMPRESSED);
    }
    snprintf(r->state, sizeof(r->state), "releasing");
    /* Keep the old factory's signed distribution TX: the sweep of the
       released-key payout outputs needs it (txid is witness-independent, so
       the unsigned copy would do, but the signed one is what confirms). */
    if (old_f->dist_tx_ready == 2 && old_f->dist_signed_tx.len > 0) {
        r->dist_hex = malloc(old_f->dist_signed_tx.len * 2 + 1);
        if (r->dist_hex) hex_encode(old_f->dist_signed_tx.data, old_f->dist_signed_tx.len,
                                    r->dist_hex);
    } else if (old_f->dist_unsigned_tx.len > 0) {
        r->dist_hex = malloc(old_f->dist_unsigned_tx.len * 2 + 1);
        if (r->dist_hex) hex_encode(old_f->dist_unsigned_tx.data, old_f->dist_unsigned_tx.len,
                                    r->dist_hex);
    }
    ok = ok && persist_save_part_rotation(db, r);
    for (size_t j = 0; ok && j < mgr->part_rel.m; j++) {
        persist_part_release_t rel;
        memset(&rel, 0, sizeof(rel));
        rel.j = (uint32_t)j;
        rel.old_slot = mgr->part_rel.old_slot[j];
        memcpy(rel.old_pk, mgr->part_rel.old_pk[j], 33);
        memcpy(rel.new_pk, mgr->part_rel.new_pk[j], 33);
        rel.carried = mgr->part_rel.carried[j];
        /* Its channel output in the old tree: the old channel's funding,
           which a released key and the LSP's key spend together. */
        size_t ni = 0;
        uint32_t lv = 0;
        ok = factory_client_to_leaf(old_f, rel.old_slot, &ni, &lv) && ni < old_f->n_nodes &&
             lv < old_f->nodes[ni].n_outputs &&
             old_f->nodes[ni].outputs[lv].script_pubkey_len == 34 &&
             rel.old_slot + 1 < old_f->n_participants;
        if (ok) {
            const factory_node_t *nd = &old_f->nodes[ni];
            musig_keyagg_t ka;
            uint32_t si = 0;
            rot_txid_display(nd->txid, rel.leaf_txid);
            rel.leaf_vout = lv;
            rel.leaf_amount = nd->outputs[lv].amount_sats;
            memcpy(rel.leaf_spk, nd->outputs[lv].script_pubkey, 34);
            rel.leaf_cltv = nd->cltv_timeout;
            ok = channel_discover_funding_keyagg(mgr->ctx, &old_f->pubkeys[0],
                                                 &old_f->pubkeys[rel.old_slot + 1],
                                                 &old_f->pubkeys[0], old_f->cltv_timeout,
                                                 nd->cltv_timeout, rel.leaf_spk, 34, &ka, &si,
                                                 rel.leaf_merkle, &rel.has_leaf_merkle);
        }
        ok = ok && persist_save_part_release(db, r->old_txid, &rel);
    }
    free(r->dist_hex);
    free(r);
    return ok;
}

static int part_record_replacement(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                   lsp_channel_mgr_t *tm, const factory_t *old_f,
                                   const rot_client_save_t *sv) {
    persist_t *db = (persist_t *)mgr->persist;
    if (!db) {
        mgr->part_rel.retired_id = LSP_RETIRED_FACTORY_ID(0);
        return 1;
    }
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    char dtx[65];
    rot_txid_display(rp->dying_funding_txid, dtx);
    /* Not the ladder id: those restart at 0 with every restart. */
    uint32_t ri = persist_next_retired_index(db);
    int ok = persist_begin(db);
    /* The old factory stays: its signed tree, its participants and
       identities, every old channel and all their per-channel rows (secrets,
       points, commitment signatures, HTLCs, watch entries) move under the
       retired factory's own ids before factory 0 and the slot ids are reused,
       so the LSP can still answer its states and punish revoked commitments,
       and the clients that stayed can exit it. */
    uint32_t rf = LSP_RETIRED_FACTORY_ID(ri);
    mgr->part_rel.retired_id = rf;
    if (ok) {
        lsp_t old_view = *lsp;
        old_view.client_pubkeys = sv->pks;
        old_view.client_identity_pubkeys = sv->ids;
        old_view.n_clients = sv->n;
        ok = persist_save_factory(db, (factory_t *)old_f, mgr->ctx, rf) &&
             persist_save_tree_nodes(db, old_f, rf) &&
             lsp_save_client_identities(&old_view, db, mgr->ctx, rf);
    }
    for (size_t c = 0; ok && c < sv->n; c++) {
        uint32_t rcid = LSP_RETIRED_CHANNEL_ID(ri, c);
        unsigned char id33[33];
        size_t l33 = 33;
        ok = persist_retire_channel_rows(db, 0, rf, (uint32_t)c, rcid) &&
             secp256k1_ec_pubkey_serialize(mgr->ctx, id33, &l33, &sv->ids[c],
                                           SECP256K1_EC_COMPRESSED) &&
             persist_save_retired_channel(db, rcid, rf, (uint32_t)c, id33);
    }
    /* Fewer participants than the old factory: none of its rows may stay. */
    ok = ok && sqlite3_exec(db->db, "DELETE FROM factory_participants WHERE factory_id = 0;"
                            "DELETE FROM tree_nodes WHERE factory_id = 0;",
                            NULL, NULL, NULL) == SQLITE_OK;
    ok = ok && persist_save_factory(db, &lsp->factory, mgr->ctx, 0) &&
         persist_save_tree_nodes(db, &lsp->factory, 0) &&
         lsp_save_client_identities(lsp, db, mgr->ctx, 0);
    for (size_t i = 0; ok && i < tm->n_channels; i++) {
        channel_t *ch = &tm->entries[i].channel;
        ok = persist_save_channel(db, ch, 0, (uint32_t)i) &&
             persist_save_basepoints(db, (uint32_t)i, ch);
        for (uint64_t cn = 0; ok && cn <= 1; cn++) {
            secp256k1_pubkey pcp;
            unsigned char ser[33], pcs[32];
            size_t len = 33;
            if (channel_get_remote_pcp(ch, cn, &pcp) &&
                secp256k1_ec_pubkey_serialize(mgr->ctx, ser, &len, &pcp,
                                              SECP256K1_EC_COMPRESSED))
                ok = persist_save_remote_pcp(db, (uint32_t)i, cn, ser);
            if (ok && channel_get_local_pcs(ch, cn, pcs))
                ok = persist_save_local_pcs(db, (uint32_t)i, cn, pcs);
            secure_zero(pcs, sizeof(pcs));
        }
    }
    /* What is owed for the old factory, kept until it is resolved. */
    ok = ok && part_save_record(mgr, db, old_f);
    if (ok) {
        rp->phase = LSP_ROT_PROGRESS_PART_FUNDING;
        persist_rotation_progress_t row;
        rot_progress_to_row(rp, &row);
        ok = persist_save_rotation_progress(db, dtx, &row);
    }
    if (!ok || !persist_commit(db)) {
        if (persist_in_transaction(db)) persist_rollback(db);
        return 0;
    }
    return 1;
}

static int lsp_rotation_partial(lsp_channel_mgr_t *mgr, lsp_t *lsp, ladder_factory_t *dying,
                                const unsigned char *in_set) {
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    fee_estimator_t *fe = (fee_estimator_t *)mgr->rot_fee_est;
    ladder_t *lad = (ladder_t *)mgr->ladder;
    regtest_t *rt = rot_rt(mgr);
    if (!fe || !lad || !dying) return 0;
    factory_t *old = &lsp->factory;
    if (memcmp(old->funding_txid, dying->factory.funding_txid, 32) != 0) {
        fprintf(stderr, "LSP rotate: the live factory is not the dying one -- no partial "
                "rotation\n");
        return 0;
    }
    size_t n_old = lsp->n_clients, idx[FACTORY_MAX_SIGNERS], m = 0;
    for (size_t c = 0; c < n_old && m < FACTORY_MAX_SIGNERS - 1; c++)
        if (in_set[c]) idx[m++] = c;
    if (m == 0) return 0;
    if (!lsp_rotation_partial_may_start(mgr)) {
        fprintf(stderr, "LSP rotate: an HTLC is in flight on a channel of factory %u -- "
                "not rotating yet\n", dying->factory_id);
        return 0;
    }
    printf("LSP rotate: partial rotation with verified release: %zu/%zu clients online "
           "and able\n", m, n_old);
    fflush(stdout);

    /* Fresh keys from M. */
    secp256k1_pubkey new_pks[FACTORY_MAX_SIGNERS], ids[FACTORY_MAX_SIGNERS];
    if (!rot_collect_keys(mgr, lsp, old->funding_txid, new_pks, idx, m, "partial", 2)) {
        rot_tell_abort_set(lsp, idx, m, "rotation aborted: keys");
        return 0;
    }
    for (size_t j = 0; j < m; j++)
        ids[j] = lsp->client_identity_pubkeys ? lsp->client_identity_pubkeys[idx[j]]
                                              : lsp->client_pubkeys[idx[j]];
    {
        const char *why = NULL;
        if (!lsp_rotation_cin_check_keys(mgr->ctx, &lsp->lsp_pubkey, old->pubkeys,
                                         old->n_participants, ids, new_pks, m, &why)) {
            fprintf(stderr, "LSP rotate: refusing the replacement keys: %s\n", why);
            rot_tell_abort_set(lsp, idx, m, "rotation aborted: keys not fresh");
            return 0;
        }
    }
    secp256k1_pubkey parts[FACTORY_MAX_SIGNERS];
    parts[0] = lsp->lsp_pubkey;
    for (size_t j = 0; j < m; j++) parts[j + 1] = new_pks[j];
    unsigned char spk[34];
    if (!factory_funding_spk_for(mgr->ctx, parts, m + 1, spk)) return 0;

    /* The funding to THESE keys, built and signed but not broadcast. */
    rot_funding_tx_t fb;
    memset(&fb, 0, sizeof(fb));
    {
        char saved_addr[sizeof(mgr->rot_fund_addr)];
        unsigned char saved_spk[34];
        size_t saved_len = mgr->rot_fund_spk_len;
        memcpy(saved_addr, mgr->rot_fund_addr, sizeof(saved_addr));
        memcpy(saved_spk, mgr->rot_fund_spk, 34);
        int aok = 1;
        if (rt) aok = regtest_derive_p2tr_address(rt, spk + 2, mgr->rot_fund_addr,
                                                  sizeof(mgr->rot_fund_addr));
        memcpy(mgr->rot_fund_spk, spk, 34);
        mgr->rot_fund_spk_len = 34;
        if (mgr->rot_is_regtest && rt && regtest_get_balance(rt) < 0.01)
            regtest_mine_blocks(rt, 10, mgr->rot_mine_addr);
        int bok = aok && rot_build_funding_tx(mgr, &fb);
        memcpy(mgr->rot_fund_addr, saved_addr, sizeof(saved_addr));
        memcpy(mgr->rot_fund_spk, saved_spk, 34);
        mgr->rot_fund_spk_len = saved_len;
        if (!bok) {
            fprintf(stderr, "LSP rotate: could not build the replacement funding\n");
            rot_tell_abort_set(lsp, idx, m, "rotation aborted: funding");
            return 0;
        }
    }
    uint32_t fvout = 0;
    uint64_t famount = 0;
    unsigned char ftxid32[32];
    if (!rot_hex_find_output(fb.hex, spk, &fvout, &famount) ||
        hex_decode(fb.txid, ftxid32, 32) != 32) {
        fprintf(stderr, "LSP rotate: the built funding does not pay the new keys\n");
        rot_funding_abandon(mgr, &fb);
        rot_tell_abort_set(lsp, idx, m, "rotation aborted: funding");
        return 0;
    }
    reverse_bytes(ftxid32, 32);
    printf("LSP rotate: replacement funding %s:%u built (not broadcast): %llu sats to "
           "the %zu clients' fresh keys\n", fb.txid, fvout, (unsigned long long)famount, m);
    fflush(stdout);

    /* The marker, before anything else. */
    lsp_rotation_progress_clear(mgr);
    rp->dying_factory_id = dying->factory_id;
    memcpy(rp->dying_funding_txid, old->funding_txid, 32);
    rp->dying_funding_vout = old->funding_vout;
    snprintf(rp->new_funding_txid, sizeof(rp->new_funding_txid), "%s", fb.txid);
    rp->new_funding_hex = strdup(fb.hex);
    rp->new_funding_vout = fvout;
    rp->new_funding_amount = famount;
    {
        int h = rot_chain_height(mgr);
        rp->new_cltv = h > 0 ? (uint32_t)h + (mgr->rot_is_regtest ? 35u : 1008u) : 0;
    }
    /* The replacement is sized for M from its own funding: its distribution
       TX splits that funding as at creation (each share covers the client's
       new channel), not by the old channel capacities. */
    rp->n_dist_amounts = 0;
    rp->phase = LSP_ROT_PROGRESS_PART_BUILT;
    if (!rp->new_funding_hex || !rot_progress_persist(mgr)) {
        lsp_rotation_progress_clear(mgr);
        rot_funding_abandon(mgr, &fb);
        rot_tell_abort_set(lsp, idx, m, "rotation aborted: record");
        return 0;
    }
    lsp_crash_checkpoint("rotate_part_built");

    /* The replacement over that outpoint, with M only. */
    rot_client_save_t sv;
    if (!rot_clients_save(lsp, &sv)) { rot_clients_free(&sv); return 0; }
    rot_clients_remap(lsp, &sv, idx, m, new_pks);
    factory_t old_f;
    if (!lsp_factory_detach(lsp, &old_f)) {
        rot_clients_restore(lsp, &sv);
        rot_clients_free(&sv);
        rot_funding_abandon(mgr, &fb);
        return 0;
    }
    lsp->factory.leaf_arity = (factory_arity_t)mgr->rot_leaf_arity;
    cJSON *rot = cJSON_CreateObject();
    cJSON_AddStringToObject(rot, "mode", "partial");
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i <= m; i++) {
        unsigned char ser[33];
        size_t len = 33;
        char h66[67];
        secp256k1_ec_pubkey_serialize(mgr->ctx, ser, &len, &parts[i], SECP256K1_EC_COMPRESSED);
        hex_encode(ser, 33, h66);
        cJSON_AddItemToArray(arr, cJSON_CreateString(h66));
    }
    cJSON_AddItemToObject(rot, "pubkeys", arr);
    {
        char od[65];
        rot_txid_display(old_f.funding_txid, od);
        cJSON_AddStringToObject(rot, "old_txid", od);
        cJSON_AddNumberToObject(rot, "old_vout", (double)old_f.funding_vout);
    }
    int ok = rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_PART_SIGNING);
    if (ok) {
        lsp->propose_rotation = rot;
        lsp->dist_client_amounts = NULL;
        lsp->dist_n_client_amounts = 0;
        ok = lsp_run_factory_creation(lsp, ftxid32, fvout, famount, spk, 34,
                                      mgr->rot_step_blocks, mgr->rot_states_per_layer,
                                      rp->new_cltv);
        lsp->propose_rotation = NULL;
        lsp->dist_client_amounts = NULL;
        lsp->dist_n_client_amounts = 0;
        if (!ok) fprintf(stderr, "LSP rotate: replacement creation ceremony failed\n");
    }
    cJSON_Delete(rot);
    if (ok) {
        lsp->factory.fee = fe;
        int ch_h = rot_chain_height(mgr);
        if (ch_h > 0)
            factory_set_lifecycle(&lsp->factory, (uint32_t)ch_h, lad->active_blocks,
                                  lad->dying_blocks);
        printf("LSP rotate: factory %u created and signed over %s:%u (replaces factory %u)\n",
               lad->next_factory_id, fb.txid, fvout, dying->factory_id);
        fflush(stdout);
        lsp_crash_checkpoint("rotate_part_signed");
    }

    /* Channels for M, each carrying that client's balance (by identity, not
       by old slot), with an LSP-signed initial commitment. */
    lsp_channel_mgr_t *tm = NULL;
    if (ok) {
        tm = calloc(1, sizeof(*tm));
        ok = tm != NULL;
        if (ok) {
            tm->routing_fee_ppm = mgr->routing_fee_ppm;
            tm->lsp_balance_pct = mgr->lsp_balance_pct;
            tm->fee = mgr->fee;
            tm->persist = NULL;
            ok = lsp_channels_init(tm, mgr->ctx, &lsp->factory, mgr->rot_lsp_seckey, m);
            if (!ok) { free(tm); tm = NULL; }
        }
    }
    uint64_t carried[FACTORY_MAX_SIGNERS];
    if (ok) {
        uint64_t rate = lsp_rotation_commit_fee_rate(fe);
        uint64_t base_fee = (rate * 154 + 999) / 1000;
        for (size_t j = 0; ok && j < m; j++) {
            channel_t *nc = &tm->entries[j].channel;
            const channel_t *oc = &mgr->entries[idx[j]].channel;
            uint64_t usable = nc->funding_amount > base_fee ? nc->funding_amount - base_fee : 0;
            uint64_t l = 0, r = 0;
            if (!lsp_rotation_cin_carry(oc->local_amount, oc->remote_amount, usable, 0, &l, &r)) {
                fprintf(stderr, "LSP rotate: client %zu's balance does not fit the "
                        "replacement channel\n", idx[j]);
                ok = 0;
                break;
            }
            nc->local_amount = l;
            nc->remote_amount = r;
            nc->fee_rate_sat_per_kvb = rate;
            carried[j] = r;
        }
    }
    if (ok) ok = lsp_channels_exchange_basepoints(tm, lsp) && lsp_channels_send_ready(tm, lsp);
    for (size_t j = 0; ok && j < m; j++) {
        unsigned char psig[32];
        uint32_t nidx = 0;
        channel_t *nc = &tm->entries[j].channel;
        if (!channel_create_commitment_partial_sig(nc, psig, &nidx)) { ok = 0; break; }
        cJSON *cs = wire_build_commitment_signed(tm->entries[j].channel_id, 0, psig, nidx);
        ok = wire_send(lsp->client_fds[j], MSG_COMMITMENT_SIGNED, cs);
        cJSON_Delete(cs);
    }
    /* Recorded on this side before the funding goes out, with the
       releases it makes owed. */
    if (ok) part_rel_fill(mgr, lsp, &old_f, idx, m, new_pks, carried, ftxid32, fvout, sv.n);
    if (ok && !part_record_replacement(mgr, lsp, tm, &old_f, &sv)) {
        fprintf(stderr, "LSP rotate: could not record the replacement -- not funding it\n");
        ok = 0;
    }
    if (ok) {
        printf("LSP rotate: replacement funding %s recorded with the replacement factory\n",
               fb.txid);
        fflush(stdout);
        lsp_crash_checkpoint("rotate_part_recorded");
    }
    if (!ok) {
        memset(&mgr->part_rel, 0, sizeof(mgr->part_rel));
        cin_drop_channels(tm);
        lsp_factory_reattach(lsp, &old_f);
        rot_clients_restore(lsp, &sv);
        rot_clients_free(&sv);
        rot_funding_abandon(mgr, &fb);
        (void)rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_DONE);
        lsp_rotation_progress_clear(mgr);
        rot_tell_abort_set(lsp, idx, m, "rotation aborted");
        return 0;
    }

    /* From here the replacement is the live factory for M. */
    {
        char sent[65] = {0};
        int sent_ok = rot_send_hex(mgr, fb.hex, sent);
        if (mgr->persist)
            persist_log_broadcast((persist_t *)mgr->persist, fb.txid,
                                  "rotation_partial_funding", fb.hex, sent_ok ? "ok" : "failed");
        printf("LSP rotate: funded %llu sats, txid: %s, vout=%u%s\n",
               (unsigned long long)famount, fb.txid, fvout,
               sent_ok ? "" : " (broadcast FAILED; the record keeps it)");
        fflush(stdout);
    }
    mgr->n_part_retired = 0;
    for (size_t c = 0; c < n_old; c++)
        if (!in_set[c] && mgr->n_part_retired < FACTORY_MAX_SIGNERS)
            mgr->part_retired_ids[mgr->n_part_retired++] = sv.ids[c];
    cin_adopt_channels(mgr, tm);
    if (lad->n_factories >= LADDER_MAX_FACTORIES) ladder_evict_expired(lad);
    if (lad->n_factories < LADDER_MAX_FACTORIES) {
        ladder_factory_t *lf_new = &lad->factories[lad->n_factories];
        memset(lf_new, 0, sizeof(*lf_new));
        lf_new->factory = lsp->factory;
        factory_detach_txbufs(&lf_new->factory);
        lf_new->factory_id = lad->next_factory_id++;
        lf_new->is_initialized = 1;
        lf_new->is_funded = 1;
        lf_new->cached_state = FACTORY_ACTIVE;
        (void)ladder_factory_store_distribution_tx(lf_new, &lsp->factory);
        lad->n_factories++;
    }
    dying = ladder_get_by_id(lad, rp->dying_factory_id);
    if (dying) dying->partial_rotation_done = 1;
    if (!cin_wait_confirm(mgr, lsp, fb.txid)) {
        fprintf(stderr, "LSP rotate: replacement funding %s not confirmed yet; no key is "
                "released before it is\n", fb.txid);
        rot_clients_free(&sv);
        factory_free(&old_f);
        free(fb.hex);
        return 0;
    }
    (void)rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_PART_FUNDED);
    lsp_crash_checkpoint("rotate_part_funded");

    /* Verified release: a receipt over exactly this position, then the key.
       A release still owed is asked for again when that client reconnects. */
    mgr->part_rel.funded = 1;
    size_t released = 0;
    for (size_t j = 0; j < m; j++) {
        if (!part_send_release_req(mgr, lsp, j)) continue;
        wire_msg_t rm;
        memset(&rm, 0, sizeof(rm));
        int got = 0;
        for (int tries = 0; tries < 16 && !got; tries++) {
            if (!wire_recv_timeout(lsp->client_fds[j], &rm, 600)) break;
            if (rm.msg_type == MSG_ROTATION_RELEASE) { got = 1; break; }
            /* The settlement of its old channel comes first. */
            if (rm.msg_type == MSG_ROTATION_SETTLE_REQ)
                (void)lsp_rotation_part_on_settle_req(mgr, lsp, j, rm.json);
            else if (rm.msg_type == MSG_ROTATION_SETTLE_ACK)
                (void)lsp_rotation_part_on_settle_ack(mgr, lsp, j, rm.json);
            if (rm.json) cJSON_Delete(rm.json);
            rm.json = NULL;
            if (rm.msg_type == MSG_ERROR) break;
        }
        if (!got) {
            fprintf(stderr, "LSP rotate: client %zu did not release its old factory key "
                    "(asked again when it reconnects)\n", idx[j]);
            continue;
        }
        if (lsp_rotation_part_on_release(mgr, lsp, j, rm.json) && ++released == 1)
            lsp_crash_checkpoint("rotate_part_released");
        cJSON_Delete(rm.json);
    }
    fflush(stdout);
    if (mgr->persist && dying)
        persist_save_ladder_factory((persist_t *)mgr->persist, dying->factory_id, "dying",
                                    dying->is_funded, dying->is_initialized, dying->n_departed,
                                    dying->factory.created_block, dying->factory.active_blocks,
                                    dying->factory.dying_blocks, 1);
    (void)rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_DONE);
    lsp_rotation_progress_clear(mgr);
    rot_clients_free(&sv);
    factory_free(&old_f);
    free(fb.hex);
    if (mgr->readiness) readiness_reset((readiness_tracker_t *)mgr->readiness);
    printf("LSP rotate: rotation complete — partial: %zu/%zu clients moved into the new "
           "factory, %zu released their old factory key; the old factory stays for the "
           "others\n", m, n_old, released);
    fflush(stdout);
    (void)lsp_rotation_winddown_tick(mgr, 1);
    return 1;
}

/* Resume a partial rotation's marker (lsp_rotation_resume).  FUNDING: the
   recorded funding, rebroadcast if it is not on the network (never another
   one); FUNDED: the releases still owed are asked for. */
static int lsp_rotation_part_resume(lsp_channel_mgr_t *mgr, lsp_t *lsp) {
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    regtest_t *rt = rot_rt(mgr);
    char ft[65];
    snprintf(ft, sizeof(ft), "%s", rp->new_funding_txid);
    if (rp->phase != LSP_ROT_PROGRESS_PART_FUNDING && rp->phase != LSP_ROT_PROGRESS_PART_FUNDED)
        return 0;
    if (rp->phase == LSP_ROT_PROGRESS_PART_FUNDING) {
        if (rot_tx_confirmations(mgr, ft) < 1 && !rot_tx_in_mempool(mgr, ft)) {
            char t[65] = {0};
            if (!rp->new_funding_hex || !rot_send_hex(mgr, rp->new_funding_hex, t)) {
                if (!rp->hold_reported) {
                    fprintf(stderr, "LSP rotate: the recorded replacement funding %s is "
                            "neither confirmed nor in the mempool and could not be "
                            "rebroadcast -- NOT funding another (operator attention)\n", ft);
                    rp->hold_reported = 1;
                }
                return 0;
            }
            if (mgr->persist)
                persist_log_broadcast((persist_t *)mgr->persist, ft,
                                      "rotation_partial_funding", rp->new_funding_hex, "ok");
            printf("LSP rotate: replacement funding %s was not on the network — "
                   "rebroadcast the recorded TX\n", ft);
        }
        if (rot_tx_confirmations(mgr, ft) < 1 && mgr->rot_is_regtest && rt &&
            rot_tx_in_mempool(mgr, ft))
            regtest_mine_blocks(rt, 1, mgr->rot_mine_addr);
        if (rot_tx_confirmations(mgr, ft) < 1) {
            printf("LSP rotate: replacement funding %s still unconfirmed — waiting\n", ft);
            fflush(stdout);
            return 0;
        }
        if (!rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_PART_FUNDED)) return 0;
        printf("LSP rotate: replacement funding %s is confirmed\n", ft);
    }
    size_t owed = 0, asked = 0;
    if (mgr->part_rel.valid) {
        mgr->part_rel.funded = 1;
        for (size_t j = 0; j < mgr->part_rel.m; j++) {
            if (mgr->part_rel.released[j]) continue;
            owed++;
            if (part_send_release_req(mgr, lsp, j)) asked++;
        }
    }
    (void)rot_progress_set_phase(mgr, LSP_ROT_PROGRESS_DONE);
    lsp_rotation_progress_clear(mgr);
    printf("LSP rotate: rotation complete — partial rotation resumed, replacement "
           "funding %s confirmed; %zu release(s) still owed (%zu asked now, the others "
           "when those clients reconnect)\n", ft, owed, asked);
    fflush(stdout);
    return 1;
}

static int part_rel_restore(lsp_channel_mgr_t *mgr, const persist_part_rotation_t *r,
                            size_t *owed_out) {
    persist_part_release_t *rel = calloc(FACTORY_MAX_SIGNERS, sizeof(*rel));
    if (!rel) return 0;
    size_t n = persist_load_part_releases((persist_t *)mgr->persist, r->old_txid, rel,
                                          FACTORY_MAX_SIGNERS);
    memset(&mgr->part_rel, 0, sizeof(mgr->part_rel));
    int ok = n == r->m && r->m > 0 && r->m < FACTORY_MAX_SIGNERS &&
             hex_decode(r->old_txid, mgr->part_rel.old_txid, 32) == 32 &&
             hex_decode(r->new_txid, mgr->part_rel.new_txid, 32) == 32;
    size_t owed = 0;
    for (size_t k = 0; ok && k < n; k++) {
        uint32_t j = rel[k].j;
        if (j >= r->m) { ok = 0; break; }
        memcpy(mgr->part_rel.old_pk[j], rel[k].old_pk, 33);
        memcpy(mgr->part_rel.new_pk[j], rel[k].new_pk, 33);
        mgr->part_rel.old_slot[j] = rel[k].old_slot;
        mgr->part_rel.carried[j] = rel[k].carried;
        mgr->part_rel.released[j] = rel[k].released ? 1 : 0;
        mgr->part_rel.settled[j] = rel[k].settled ? 1 : 0;
        if (!rel[k].released) owed++;
    }
    free(rel);
    if (!ok) {
        memset(&mgr->part_rel, 0, sizeof(mgr->part_rel));
        return 0;
    }
    reverse_bytes(mgr->part_rel.old_txid, 32);
    reverse_bytes(mgr->part_rel.new_txid, 32);
    mgr->part_rel.old_vout = r->old_vout;
    mgr->part_rel.new_vout = r->new_vout;
    memcpy(mgr->part_rel.digest, r->digest, 32);
    mgr->part_rel.m = r->m;
    mgr->part_rel.n_old = r->n_old;
    mgr->part_rel.retired_id = r->retired_id;
    mgr->part_rel.old_cltv = r->old_cltv;
    mgr->part_rel.dying_id = UINT32_MAX;          /* not in this process's ladder */
    mgr->part_rel.valid = 1;
    if (owed_out) *owed_out = owed;
    return 1;
}

int lsp_rotation_part_load(lsp_channel_mgr_t *mgr, regtest_t *rt,
                           const unsigned char *live_txid32, uint32_t live_vout) {
    if (!mgr || !mgr->persist || !live_txid32) return 0;
    persist_t *db = (persist_t *)mgr->persist;
    char live[65];
    rot_txid_display(live_txid32, live);
    int any = 0;
    persist_rotation_progress_t row;
    uint64_t amounts[FACTORY_MAX_SIGNERS];

    /* Stopped before the replacement was recorded: the live factory is still
       the old one, and the funding was never broadcast. */
    memset(&row, 0, sizeof(row));
    row.dist_amounts = amounts;
    if (persist_load_rotation_progress(db, live, &row, FACTORY_MAX_SIGNERS) &&
        row.dying_funding_vout == live_vout &&
        (row.phase == LSP_ROT_PROGRESS_PART_BUILT || row.phase == LSP_ROT_PROGRESS_PART_SIGNING)) {
        int ph = row.phase;
        if (rt && row.new_funding_hex && regtest_unlock_tx_inputs(rt, row.new_funding_hex) < 0)
            fprintf(stderr, "LSP recovery: could not unlock the wallet inputs of the "
                    "dropped replacement funding %s\n", row.new_funding_txid);
        row.phase = LSP_ROT_PROGRESS_DONE;
        if (persist_save_rotation_progress(db, live, &row)) {
            printf("LSP recovery: a partial rotation of this factory stopped before its "
                   "replacement was recorded (phase %d) — dropped; its funding %s was "
                   "never broadcast\n", ph, row.new_funding_txid);
            any = 1;
        }
    }
    free(row.new_funding_hex);
    free(row.dist_tx_hex);

    /* The live factory is a partial rotation's replacement. */
    char dtx[65];
    memset(&row, 0, sizeof(row));
    row.dist_amounts = amounts;
    if (mgr->rot_progress.phase == LSP_ROT_PROGRESS_NONE &&
        persist_find_rotation_by_new_funding(db, live, dtx) == 1 &&
        persist_load_rotation_progress(db, dtx, &row, FACTORY_MAX_SIGNERS) &&
        (row.phase == LSP_ROT_PROGRESS_PART_FUNDING || row.phase == LSP_ROT_PROGRESS_PART_FUNDED)) {
        lsp_rotation_progress_t *rp = &mgr->rot_progress;
        lsp_rotation_progress_clear(mgr);
        if (hex_decode(dtx, rp->dying_funding_txid, 32) == 32) {
            reverse_bytes(rp->dying_funding_txid, 32);
            rp->phase = row.phase;
            rp->dying_factory_id = row.dying_factory_id;
            rp->dying_funding_vout = row.dying_funding_vout;
            snprintf(rp->new_funding_txid, sizeof(rp->new_funding_txid), "%s", live);
            rp->new_funding_hex = row.new_funding_hex;       /* ownership moves */
            row.new_funding_hex = NULL;
            rp->new_funding_vout = row.new_funding_vout;
            rp->new_funding_amount = row.new_funding_amount;
            rp->new_cltv = row.new_cltv;
            /* A PART_FUNDING funding was recorded but its wallet-input
               locks are in-memory and gone after the restart.  Rebroadcast it
               (and re-lock its inputs) FIRST THING, before the daemon does
               anything that could spend from the wallet and invalidate it. */
            if (rp->phase == LSP_ROT_PROGRESS_PART_FUNDING && rp->new_funding_hex &&
                rot_tx_confirmations(mgr, live) < 1 && !rot_tx_in_mempool(mgr, live)) {
                char t[65] = {0};
                if (rt) (void)regtest_lock_tx_inputs(rt, rp->new_funding_hex);
                if (rot_send_hex(mgr, rp->new_funding_hex, t)) {
                    persist_log_broadcast(db, live, "rotation_partial_funding",
                                          rp->new_funding_hex, "ok");
                    printf("LSP recovery: rebroadcast the recorded replacement funding %s "
                           "before any wallet use\n", live);
                } else if (rt) {
                    (void)regtest_lock_tx_inputs(rt, rp->new_funding_hex);
                }
            }
            printf("LSP recovery: this factory replaces %s in a partial rotation (phase %d) "
                   "— %s\n", dtx, row.phase,
                   row.phase == LSP_ROT_PROGRESS_PART_FUNDING
                       ? "its recorded funding is confirmed or rebroadcast"
                       : "the releases still owed are asked for again");
            any = 1;
        }
    }
    free(row.new_funding_hex);
    free(row.dist_tx_hex);

    /* The releases still owed for the old factory. */
    persist_part_rotation_t *rows = calloc(LADDER_MAX_FACTORIES, sizeof(*rows));
    if (!rows) return any;
    size_t n = persist_load_part_rotations(db, rows, LADDER_MAX_FACTORIES, 1);
    for (size_t i = 0; i < n; i++) {
        size_t owed = 0;
        if (strcmp(rows[i].new_txid, live) == 0 && rows[i].new_vout == live_vout &&
            strcmp(rows[i].state, "releasing") == 0 && part_rel_restore(mgr, &rows[i], &owed)) {
            printf("LSP recovery: %zu of %u release(s) still owed for the old factory %s — "
                   "asked again when those clients reconnect\n", owed, rows[i].m,
                   rows[i].old_txid);
            any = 1;
        }
        free(rows[i].close_hex);
        free(rows[i].dist_hex);
    }
    free(rows);
    fflush(stdout);
    return any;
}

/* ===================================================================
   Winding down the old factory of a partial rotation (see lsp_channels.h).
   =================================================================== */

lsp_wd_action_t lsp_rotation_winddown_action(const char *state, uint32_t n_old, uint32_t m,
                                             uint32_t n_released, int close_confs,
                                             int funding_spent, int dist_present,
                                             int dist_buried, uint32_t n_released_unresolved,
                                             uint32_t n_leaf_unspent, uint32_t n_leaf_pending,
                                             int past_cltv_margin, int regtest) {
    if (!state || strcmp(state, "done") == 0) return LSP_WD_NONE;
    /* The LSP's own close (no stayer): keys go once it is buried. */
    if (strcmp(state, "closing") == 0)
        return close_confs >= LSP_WD_CLOSE_DEPTH(regtest) ? LSP_WD_DELETE : LSP_WD_WAIT;
    if (strcmp(state, "releasing") != 0) return LSP_WD_NONE;
    /* Every client moved and released and the old funding is still there: the
       LSP can close it alone. */
    if (m > 0 && m == n_old && n_released == m && !funding_spent)
        return LSP_WD_CLOSE;
    /* Otherwise the old factory resolves on its own (stayers, or the dist TX
       at the CLTV).  Keys are deleted only when nothing a released key guards
       is unspent. */
    if (!funding_spent) return LSP_WD_NONE;
    if (n_released_unresolved > 0 || n_leaf_unspent > 0) return LSP_WD_SWEEP;
    if (n_leaf_pending > 0) return LSP_WD_WAIT;         /* spent, not buried yet */
    if (dist_present)
        return dist_buried ? LSP_WD_DELETE : LSP_WD_WAIT;   /* swept and buried */
    /* The tree spent the funding (no dist output can appear), and every
       moved client's channel output that reached the chain is swept or spent
       and buried.  One that appears later is still the LSP's: the client's
       latest old commitment pays it to the LSP, an earlier one is revoked
       (the watch entries use the revocations, not the keys). */
    if (past_cltv_margin) return LSP_WD_DELETE;
    return LSP_WD_NONE;
}

/* P2TR of the taproot-tweaked released key (its distribution-TX payout). */
static int wd_payout_spk(const secp256k1_context *ctx, const unsigned char *key_pub33,
                         unsigned char spk_out34[34]) {
    secp256k1_pubkey pk;
    secp256k1_xonly_pubkey xo, outx;
    secp256k1_pubkey outp;
    unsigned char ser[32], tweak[32];
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, key_pub33, 33) ||
        !secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &pk) ||
        !secp256k1_xonly_pubkey_serialize(ctx, ser, &xo))
        return 0;
    sha256_tagged("TapTweak", ser, 32, tweak);
    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &outp, &xo, tweak) ||
        !secp256k1_xonly_pubkey_from_pubkey(ctx, &outx, NULL, &outp))
        return 0;
    build_p2tr_script_pubkey(spk_out34, &outx);
    return 1;
}

int lsp_rotation_sweep_build(const secp256k1_context *ctx, const unsigned char *key32,
                             const unsigned char *src_txid32, uint32_t src_vout,
                             uint64_t src_amount, const unsigned char *src_spk34,
                             const unsigned char *out_spk, size_t out_spk_len,
                             uint64_t fee, tx_buf_t *signed_out, char txid_out[65]) {
    if (!ctx || !key32 || !src_txid32 || !src_spk34 || !out_spk || !signed_out || !txid_out)
        return 0;
    if (out_spk_len == 0 || out_spk_len > 34 || src_amount <= fee + 330) return 0;
    secp256k1_keypair kp;
    secp256k1_pubkey pub;
    unsigned char want[34];
    if (!secp256k1_keypair_create(ctx, &kp, key32) ||
        !secp256k1_keypair_pub(ctx, &pub, &kp)) {
        secure_zero(&kp, sizeof(kp));
        return 0;
    }
    unsigned char pub33[33];
    size_t l = 33;
    int ok = secp256k1_ec_pubkey_serialize(ctx, pub33, &l, &pub, SECP256K1_EC_COMPRESSED) &&
             wd_payout_spk(ctx, pub33, want) && memcmp(want, src_spk34, 34) == 0;
    /* Tweak the signing key to the output key. */
    secp256k1_xonly_pubkey xo;
    unsigned char ser[32], tweak[32];
    if (ok) ok = secp256k1_xonly_pubkey_from_pubkey(ctx, &xo, NULL, &pub) &&
                 secp256k1_xonly_pubkey_serialize(ctx, ser, &xo);
    if (ok) { sha256_tagged("TapTweak", ser, 32, tweak);
              ok = secp256k1_keypair_xonly_tweak_add(ctx, &kp, tweak); }
    tx_output_t out;
    memset(&out, 0, sizeof(out));
    out.amount_sats = src_amount - fee;
    memcpy(out.script_pubkey, out_spk, out_spk_len);
    out.script_pubkey_len = out_spk_len;
    tx_buf_t utx;
    tx_buf_init(&utx, 256);
    unsigned char dtxid[32], sh[32], sig[64], aux[32];
    memset(aux, 0, 32);
    ok = ok && build_unsigned_tx_with_locktime(&utx, dtxid, src_txid32, src_vout,
                                               0xFFFFFFFDu, 0, &out, 1) &&
         compute_taproot_sighash(sh, utx.data, utx.len, 0, src_spk34, 34, src_amount,
                                 0xFFFFFFFDu) &&
         secp256k1_schnorrsig_sign32(ctx, sig, sh, &kp, aux) &&
         finalize_signed_tx(signed_out, utx.data, utx.len, sig);
    if (ok) hex_encode(dtxid, 32, txid_out);
    tx_buf_free(&utx);
    secure_zero(&kp, sizeof(kp));
    return ok;
}

int lsp_rotation_winddown_build(const secp256k1_context *ctx,
                                const unsigned char *lsp_seckey32,
                                const persist_part_rotation_t *r,
                                const unsigned char (*keys)[32], const tx_output_t *out,
                                uint32_t locktime, tx_buf_t *signed_out, char txid_out[65]) {
    if (!ctx || !lsp_seckey32 || !r || !keys || !out || !signed_out || !txid_out) return 0;
    size_t n = (size_t)r->n_old + 1;
    if (n < 2 || n > FACTORY_MAX_SIGNERS || out->amount_sats == 0 ||
        out->amount_sats >= r->old_amount)
        return 0;
    secp256k1_pubkey *pks = calloc(n, sizeof(*pks));
    secp256k1_keypair *kps = calloc(n, sizeof(*kps));
    int ok = pks && kps;
    for (size_t i = 0; ok && i < n; i++) {
        secp256k1_pubkey kp;
        unsigned char ser[33];
        size_t l = 33;
        /* Each key must be that participant's: a wrong one signs nothing. */
        ok = secp256k1_ec_pubkey_parse(ctx, &pks[i], r->old_pks[i], 33) &&
             secp256k1_keypair_create(ctx, &kps[i], i == 0 ? lsp_seckey32 : keys[i]) &&
             secp256k1_keypair_pub(ctx, &kp, &kps[i]) &&
             secp256k1_ec_pubkey_serialize(ctx, ser, &l, &kp, SECP256K1_EC_COMPRESSED) &&
             memcmp(ser, r->old_pks[i], 33) == 0;
    }
    unsigned char spk[34], ot[32], dtxid[32], sh[32], sig[64];
    musig_keyagg_t ka;
    tx_buf_t utx;
    tx_buf_init(&utx, 256);
    ok = ok && factory_funding_spk_for(ctx, pks, n, spk) &&
         musig_aggregate_keys(ctx, &ka, pks, n) &&
         hex_decode(r->old_txid, ot, 32) == 32;
    if (ok) reverse_bytes(ot, 32);
    ok = ok && build_unsigned_tx_with_locktime(&utx, dtxid, ot, r->old_vout, 0xFFFFFFFEu,
                                               locktime, out, 1) &&
         compute_taproot_sighash(sh, utx.data, utx.len, 0, spk, 34, r->old_amount,
                                 0xFFFFFFFEu) &&
         musig_sign_taproot(ctx, sig, sh, kps, n, &ka, NULL) &&
         finalize_signed_tx(signed_out, utx.data, utx.len, sig);
    if (ok) hex_encode(dtxid, 32, txid_out);
    tx_buf_free(&utx);
    if (kps) secure_zero(kps, n * sizeof(*kps));
    free(kps);
    free(pks);
    return ok;
}

static ladder_factory_t *wd_ladder_slot(lsp_channel_mgr_t *mgr, const char *old_txid,
                                        uint32_t old_vout) {
    ladder_t *lad = (ladder_t *)mgr->ladder;
    unsigned char t[32];
    if (!lad || hex_decode(old_txid, t, 32) != 32) return NULL;
    reverse_bytes(t, 32);
    for (size_t i = 0; i < lad->n_factories; i++) {
        ladder_factory_t *lf = &lad->factories[i];
        if (lf->is_initialized && lf->factory.funding_vout == old_vout &&
            memcmp(lf->factory.funding_txid, t, 32) == 0)
            return lf;
    }
    return NULL;
}

/* Build, record, then broadcast the close (never a second one: the record
   is checked first by the caller's state). */
/* An LSP-controlled P2TR (or wallet) output script for close/sweep outputs. */
static int wd_wallet_spk(lsp_channel_mgr_t *mgr, char addr_out[128],
                         unsigned char *spk, size_t *spk_len) {
    regtest_t *rt = rot_rt(mgr);
    wallet_source_t *ws = (wallet_source_t *)mgr->wallet_src;
    if (addr_out) addr_out[0] = '\0';
    if (rt && regtest_get_new_address(rt, addr_out, 128) &&
        regtest_get_address_scriptpubkey(rt, addr_out, spk, spk_len))
        return 1;
    if (!rt && ws && ws->get_change_spk && ws->get_change_spk(ws, spk, spk_len))
        return 1;
    return 0;
}

/* Sweep every unspent distribution-TX output that pays a released key of R
   to the LSP wallet.  Returns the number still unresolved (unspent) after. */
static uint32_t wd_sweep(lsp_channel_mgr_t *mgr, persist_part_rotation_t *r,
                         const persist_part_release_t *rel, size_t nr,
                         const char *dist_disp) {
    persist_t *db = (persist_t *)mgr->persist;
    size_t np = (size_t)r->n_old + 1;
    int *dep = calloc(np, sizeof(int));
    unsigned char (*keys)[32] = calloc(np, 32);
    char addr[128];
    unsigned char wspk[64];
    size_t wl = 0;
    int have_wallet = dep && keys && wd_wallet_spk(mgr, addr, wspk, &wl) && wl && wl <= 34;
    size_t have_keys = (dep && keys)
        ? persist_load_departed_clients(db, r->retired_id, dep, keys, np) : 0;
    (void)have_keys;
    fee_estimator_t *fe = (fee_estimator_t *)mgr->rot_fee_est;
    uint64_t fee = fe ? fee_estimate(fe, 112) : 0;
    if (fee == 0) fee = (112 * FEE_FLOOR_SAT_PER_KVB + 999) / 1000;
    uint32_t unresolved = 0;
    for (size_t k = 0; k < nr; k++) {
        if (!rel[k].released) continue;
        unsigned char spk[34];
        uint32_t vout = 0;
        uint64_t amt = 0;
        if (!r->dist_hex || !wd_payout_spk(mgr->ctx, rel[k].old_pk, spk) ||
            !rot_hex_find_output(r->dist_hex, spk, &vout, &amt))
            continue;                       /* no such payout output */
        if (rot_outpoint_unspent(mgr, dist_disp, vout) != 1)
            continue;                       /* already spent (by us or anyone): resolved */
        unresolved++;
        uint32_t pidx = rel[k].old_slot + 1;
        if (!have_wallet || pidx >= np || !dep[pidx]) continue;
        unsigned char dtxid[32];
        if (hex_decode(dist_disp, dtxid, 32) != 32) continue;
        reverse_bytes(dtxid, 32);
        tx_buf_t stx;
        tx_buf_init(&stx, 256);
        char t[65] = {0};
        if (lsp_rotation_sweep_build(mgr->ctx, keys[pidx], dtxid, vout, amt, spk, wspk, wl,
                                     fee, &stx, t)) {
            char *hx = malloc(stx.len * 2 + 1);
            if (hx) {
                hex_encode(stx.data, stx.len, hx);
                char sent[65] = {0};
                int sok = rot_send_hex(mgr, hx, sent);
                persist_log_broadcast(db, t, "rotation_release_sweep", hx,
                                      sok ? "ok" : "failed");
                printf("LSP rotate: sweeping released-key distribution output %s:%u "
                       "(%llu sats) to the LSP wallet%s — %s\n", dist_disp, vout,
                       (unsigned long long)amt, addr[0] ? addr : "",
                       sok ? "broadcast" : "not yet (retried next block)");
                free(hx);
            }
        }
        tx_buf_free(&stx);
    }
    if (keys) secure_zero(keys, np * 32);
    free(keys);
    free(dep);
    fflush(stdout);
    return unresolved;
}

int lsp_rotation_leaf_sweep_build(const secp256k1_context *ctx,
                                  const unsigned char *lsp_seckey32,
                                  const unsigned char *key32,
                                  const persist_part_release_t *rel,
                                  const unsigned char *out_spk, size_t out_spk_len,
                                  uint64_t fee, tx_buf_t *signed_out, char txid_out[65]) {
    if (!ctx || !lsp_seckey32 || !key32 || !rel || !rel->leaf_txid[0] || !out_spk ||
        !signed_out || !txid_out || out_spk_len == 0 || out_spk_len > 34 ||
        rel->leaf_amount <= fee + 330)
        return 0;
    secp256k1_keypair kp[2];
    secp256k1_pubkey pk[2];
    secp256k1_xonly_pubkey target;
    int ok = secp256k1_keypair_create(ctx, &kp[0], lsp_seckey32) &&
             secp256k1_keypair_create(ctx, &kp[1], key32) &&
             secp256k1_keypair_pub(ctx, &pk[0], &kp[0]) &&
             secp256k1_keypair_pub(ctx, &pk[1], &kp[1]) &&
             rel->leaf_spk[0] == 0x51 && rel->leaf_spk[1] == 0x20 &&
             secp256k1_xonly_pubkey_parse(ctx, &target, rel->leaf_spk + 2);
    unsigned char lt[32], dtxid[32], sh[32], sig[64];
    tx_output_t out;
    memset(&out, 0, sizeof(out));
    out.amount_sats = rel->leaf_amount - fee;
    memcpy(out.script_pubkey, out_spk, out_spk_len);
    out.script_pubkey_len = out_spk_len;
    tx_buf_t utx;
    tx_buf_init(&utx, 256);
    ok = ok && hex_decode(rel->leaf_txid, lt, 32) == 32;
    if (ok) reverse_bytes(lt, 32);
    ok = ok && build_unsigned_tx_with_locktime(&utx, dtxid, lt, rel->leaf_vout, 0xFFFFFFFDu,
                                               0, &out, 1) &&
         compute_taproot_sighash(sh, utx.data, utx.len, 0, rel->leaf_spk, 34,
                                 rel->leaf_amount, 0xFFFFFFFDu);
    /* Both signer orders (the channel's key order is not recorded); only a
       signature valid for the output key is used. */
    int signed_ok = 0;
    for (int order = 0; ok && order < 2 && !signed_ok; order++) {
        secp256k1_pubkey pks[2] = { pk[order], pk[1 - order] };
        secp256k1_keypair kps[2] = { kp[order], kp[1 - order] };
        musig_keyagg_t ka;
        signed_ok = musig_aggregate_keys(ctx, &ka, pks, 2) &&
                    musig_sign_taproot(ctx, sig, sh, kps, 2, &ka,
                                       rel->has_leaf_merkle ? rel->leaf_merkle : NULL) &&
                    secp256k1_schnorrsig_verify(ctx, sig, sh, 32, &target);
        secure_zero(kps, sizeof(kps));
    }
    ok = ok && signed_ok && finalize_signed_tx(signed_out, utx.data, utx.len, sig);
    if (ok) hex_encode(dtxid, 32, txid_out);
    tx_buf_free(&utx);
    secure_zero(kp, sizeof(kp));
    return ok;
}

size_t lsp_rotation_leaf_sweep_vsize(int cltv_path) {
    /* One input, one output: the key path's witness is one signature; the
       CLTV path's also carries the script and the control block. */
    return cltv_path ? 140 : 112;
}

int lsp_rotation_leaf_timeout_sweep_build(const secp256k1_context *ctx,
                                          const unsigned char *lsp_seckey32,
                                          const persist_part_release_t *rel,
                                          uint32_t factory_cltv,
                                          const unsigned char *out_spk, size_t out_spk_len,
                                          uint64_t fee, tx_buf_t *signed_out,
                                          char txid_out[65]) {
    if (!ctx || !lsp_seckey32 || !rel || !rel->leaf_txid[0] || !rel->has_leaf_merkle ||
        !out_spk || !signed_out || !txid_out || out_spk_len == 0 || out_spk_len > 34 ||
        rel->leaf_amount <= fee + 330)
        return 0;
    secp256k1_keypair lkp;
    secp256k1_pubkey lpk, cpk;
    secp256k1_xonly_pubkey lx;
    int ok = secp256k1_keypair_create(ctx, &lkp, lsp_seckey32) &&
             secp256k1_keypair_pub(ctx, &lpk, &lkp) &&
             secp256k1_xonly_pubkey_from_pubkey(ctx, &lx, NULL, &lpk) &&
             secp256k1_ec_pubkey_parse(ctx, &cpk, rel->old_pk, 33);
    /* The script leaf whose root is the recorded one. */
    tapscript_leaf_t leaf;
    uint32_t cltv = 0;
    uint32_t cands[2] = { rel->leaf_cltv, factory_cltv };
    for (int i = 0; ok && i < 2 && !cltv; i++) {
        unsigned char mr[32];
        if (cands[i] > 0 && tapscript_build_cltv_timeout(&leaf, cands[i], &lx, ctx) &&
            tapscript_merkle_root(mr, &leaf, 1) && memcmp(mr, rel->leaf_merkle, 32) == 0)
            cltv = cands[i];
    }
    ok = ok && cltv > 0;
    /* The internal key (either signer order) whose tweak is the output key. */
    musig_keyagg_t ka;
    int parity = 0, found = 0;
    for (int order = 0; ok && order < 2 && !found; order++) {
        secp256k1_pubkey pks[2] = { order ? cpk : lpk, order ? lpk : cpk };
        secp256k1_xonly_pubkey tw;
        unsigned char ser[32];
        found = musig_aggregate_keys(ctx, &ka, pks, 2) &&
                tapscript_tweak_pubkey(ctx, &tw, &parity, &ka.agg_pubkey, rel->leaf_merkle) &&
                secp256k1_xonly_pubkey_serialize(ctx, ser, &tw) &&
                memcmp(ser, rel->leaf_spk + 2, 32) == 0;
    }
    ok = ok && found && rel->leaf_spk[0] == 0x51 && rel->leaf_spk[1] == 0x20;
    tx_output_t out;
    memset(&out, 0, sizeof(out));
    out.amount_sats = rel->leaf_amount - fee;
    memcpy(out.script_pubkey, out_spk, out_spk_len);
    out.script_pubkey_len = out_spk_len;
    tx_buf_t utx;
    tx_buf_init(&utx, 256);
    unsigned char lt[32], dtxid[32], sh[32], sig[64], aux[32], cb[65];
    size_t cbl = 0;
    memset(aux, 0, 32);
    ok = ok && hex_decode(rel->leaf_txid, lt, 32) == 32;
    if (ok) reverse_bytes(lt, 32);
    ok = ok && build_unsigned_tx_with_locktime(&utx, dtxid, lt, rel->leaf_vout, 0xFFFFFFFEu,
                                               cltv, &out, 1) &&
         compute_tapscript_sighash(sh, utx.data, utx.len, 0, rel->leaf_spk, 34,
                                   rel->leaf_amount, 0xFFFFFFFEu, &leaf) &&
         secp256k1_schnorrsig_sign32(ctx, sig, sh, &lkp, aux) &&
         tapscript_build_control_block(cb, &cbl, parity, &ka.agg_pubkey, ctx) &&
         finalize_script_path_tx(signed_out, utx.data, utx.len, sig, leaf.script,
                                 leaf.script_len, cb, cbl);
    if (ok) hex_encode(dtxid, 32, txid_out);
    tx_buf_free(&utx);
    secure_zero(&lkp, sizeof(lkp));
    return ok;
}

/* Every moved client's channel output in the old tree that is on chain:
   sweep the unspent ones (released key + the LSP's key) to the LSP wallet;
   track the spent ones until buried.  Counts into *UNSPENT, *PENDING and
   *MISSING (not on chain).  SWEEP: 0 none, 1 with the released keys, 2 by the
   LSP alone (its CLTV script leaf; the keys are gone). */
static void wd_leaf_scan(lsp_channel_mgr_t *mgr, persist_part_rotation_t *r,
                         persist_part_release_t *rel, size_t nr, int h, int do_sweep,
                         uint32_t *unspent, uint32_t *pending, uint32_t *missing) {
    persist_t *db = (persist_t *)mgr->persist;
    size_t np = (size_t)r->n_old + 1;
    int *dep = NULL;
    unsigned char (*keys)[32] = NULL;
    int depth = LSP_WD_CLOSE_DEPTH(mgr->rot_is_regtest);
    for (size_t k = 0; k < nr; k++) {
        persist_part_release_t *x = &rel[k];
        if (!x->released || !x->leaf_txid[0]) continue;
        if (rot_tx_confirmations(mgr, x->leaf_txid) < 1) {
            if (rot_tx_in_mempool(mgr, x->leaf_txid)) (*pending)++;
            else (*missing)++;
            continue;                       /* not on chain (yet) */
        }
        int un = rot_outpoint_unspent(mgr, x->leaf_txid, x->leaf_vout);
        if (un == 0) {
            int sc = x->sweep_txid[0] ? rot_tx_confirmations(mgr, x->sweep_txid) : -1;
            if (!x->spent_height && h > 0) {
                x->spent_height = (uint32_t)h;
                (void)persist_set_part_leaf_state(db, r->old_txid, x->j, x->sweep_txid,
                                                  x->spent_height);
            }
            if (sc >= depth || (x->spent_height && h > 0 &&
                                (uint64_t)h >= (uint64_t)x->spent_height + (uint64_t)depth))
                continue;                   /* spent and buried */
            (*pending)++;
            continue;
        }
        if (un != 1) { (*pending)++; continue; }
        (*unspent)++;
        if (x->spent_height)                /* a spend that was reorged out */
            (void)persist_set_part_leaf_state(db, r->old_txid, x->j, x->sweep_txid,
                                              x->spent_height = 0);
        if (!do_sweep) continue;
        if (do_sweep == 2) {
            if (h <= 0 || (uint32_t)h < r->old_cltv) continue;
        } else if (!dep) {
            dep = calloc(np, sizeof(int));
            keys = calloc(np, 32);
            if (!dep || !keys) break;
            (void)persist_load_departed_clients(db, r->retired_id, dep, keys, np);
        }
        uint32_t pidx = x->old_slot + 1;
        char addr[128];
        unsigned char wspk[64];
        size_t wl = 0;
        if ((do_sweep == 1 && (pidx >= np || !dep[pidx])) ||
            !wd_wallet_spk(mgr, addr, wspk, &wl) || !wl || wl > 34)
            continue;
        fee_estimator_t *fe = (fee_estimator_t *)mgr->rot_fee_est;
        size_t vb = lsp_rotation_leaf_sweep_vsize(do_sweep == 2);
        uint64_t fee = fe ? fee_estimate(fe, vb) : 0;
        if (fee == 0) fee = (vb * FEE_FLOOR_SAT_PER_KVB + 999) / 1000;
        tx_buf_t stx;
        tx_buf_init(&stx, 256);
        char t[65] = {0};
        int built = do_sweep == 1
            ? lsp_rotation_leaf_sweep_build(mgr->ctx, mgr->rot_lsp_seckey, keys[pidx], x, wspk,
                                            wl, fee, &stx, t)
            : lsp_rotation_leaf_timeout_sweep_build(mgr->ctx, mgr->rot_lsp_seckey, x,
                                                    r->old_cltv, wspk, wl, fee, &stx, t);
        if (built) {
            char *hx = malloc(stx.len * 2 + 1);
            if (hx) {
                hex_encode(stx.data, stx.len, hx);
                /* Recorded before it is sent. */
                snprintf(x->sweep_txid, sizeof(x->sweep_txid), "%s", t);
                (void)persist_set_part_leaf_state(db, r->old_txid, x->j, x->sweep_txid, 0);
                char sent[65] = {0};
                int sok = rot_send_hex(mgr, hx, sent);
                persist_log_broadcast(db, t, "rotation_leaf_sweep", hx, sok ? "ok" : "failed");
                printf("LSP rotate: a moved client's old-tree channel output %s:%u (%llu sats) "
                       "is on chain -- sweeping it to the LSP wallet %s: %s %s\n",
                       x->leaf_txid, x->leaf_vout, (unsigned long long)x->leaf_amount,
                       do_sweep == 1 ? "with its released key" : "through its CLTV path", t,
                       sok ? "broadcast" : "not accepted now (retried next block)");
                free(hx);
            }
        }
        tx_buf_free(&stx);
    }
    if (keys) secure_zero(keys, np * 32);
    free(keys);
    free(dep);
    fflush(stdout);
}

static int wd_close(lsp_channel_mgr_t *mgr, persist_part_rotation_t *r, int height) {
    persist_t *db = (persist_t *)mgr->persist;
    int un = rot_outpoint_unspent(mgr, r->old_txid, r->old_vout);
    if (un != 1) {
        if (un == 0)
            printf("LSP rotate: the old factory %s is already spent -- no close of its "
                   "own; the released keys go once it is resolved on chain\n", r->old_txid);
        return 0;
    }
    tx_output_t out;
    memset(&out, 0, sizeof(out));
    char addr[128] = {0};
    unsigned char wspk[64];
    size_t wl = 0;
    if (!wd_wallet_spk(mgr, addr, wspk, &wl)) {
        fprintf(stderr, "LSP rotate: no wallet address for the old factory's close\n");
        return 0;
    }
    if (wl == 0 || wl > sizeof(out.script_pubkey)) return 0;
    memcpy(out.script_pubkey, wspk, wl);
    out.script_pubkey_len = wl;
    size_t vsize = 68 + 43;
    uint64_t fee = mgr->rot_fee_est ? fee_estimate((fee_estimator_t *)mgr->rot_fee_est, vsize) : 0;
    if (fee == 0) fee = (vsize * FEE_FLOOR_SAT_PER_KVB + 999) / 1000;
    if (r->old_amount <= fee + 330) return 0;
    out.amount_sats = r->old_amount - fee;

    size_t n = (size_t)r->n_old + 1;
    int *dep = calloc(n, sizeof(int));
    unsigned char (*keys)[32] = calloc(n, 32);
    tx_buf_t stx;
    tx_buf_init(&stx, 256);
    char txid[65] = {0};
    int ok = dep && keys &&
             persist_load_departed_clients(db, r->retired_id, dep, keys, n) == n - 1 &&
             lsp_rotation_winddown_build(mgr->ctx, mgr->rot_lsp_seckey, r,
                                         (const unsigned char (*)[32])keys, &out,
                                         height > 0 ? (uint32_t)height : 0, &stx, txid);
    if (keys) secure_zero(keys, n * 32);
    free(keys);
    free(dep);
    char *hex = ok ? malloc(stx.len * 2 + 1) : NULL;
    if (hex) hex_encode(stx.data, stx.len, hex);
    tx_buf_free(&stx);
    if (!hex) {
        fprintf(stderr, "LSP rotate: could not build the old factory %s's close from the "
                "released keys\n", r->old_txid);
        return 0;
    }
    /* Recorded before it can be broadcast. */
    snprintf(r->state, sizeof(r->state), "closing");
    snprintf(r->close_txid, sizeof(r->close_txid), "%s", txid);
    free(r->close_hex);
    r->close_hex = hex;
    if (!persist_save_part_rotation(db, r)) {
        fprintf(stderr, "LSP rotate: could not record the old factory's close -- not "
                "broadcasting it\n");
        return 0;
    }
    printf("LSP rotate: every client of the old factory %s released its key — closing it "
           "alone: close %s recorded (%llu sats to %s)\n", r->old_txid, txid,
           (unsigned long long)out.amount_sats, addr[0] ? addr : "this wallet");
    char sent[65] = {0};
    int sok = rot_send_hex(mgr, hex, sent);
    persist_log_broadcast(db, txid, "rotation_winddown_close", hex, sok ? "ok" : "failed");
    printf("LSP rotate: old factory close %s %s\n", txid,
           sok ? "broadcast" : "not broadcast yet (rebroadcast from the record)");
    fflush(stdout);
    return 1;
}

static int wd_delete(lsp_channel_mgr_t *mgr, persist_part_rotation_t *r, int confs,
                     int closed_by_us, int keep_watching) {
    persist_t *db = (persist_t *)mgr->persist;
    char prev[16];
    snprintf(prev, sizeof(prev), "%s", r->state);
    snprintf(r->state, sizeof(r->state), "%s", keep_watching ? "watching" : "done");
    int ok = persist_begin(db) && persist_delete_departed_clients(db, r->retired_id) &&
             persist_save_part_rotation(db, r);
    if (ok) ok = persist_commit(db);
    else if (persist_in_transaction(db)) persist_rollback(db);
    if (!ok) {
        snprintf(r->state, sizeof(r->state), "%s", prev);
        return 0;
    }
    ladder_factory_t *lf = wd_ladder_slot(mgr, r->old_txid, r->old_vout);
    if (lf) {
        secure_zero(lf->extracted_keys, sizeof(lf->extracted_keys));
        memset(lf->client_departed, 0, sizeof(lf->client_departed));
        lf->n_departed = 0;
        if (closed_by_us) tx_buf_free(&lf->distribution_tx);   /* nothing left to broadcast */
    }
    if (mgr->part_rel.valid) {
        char o[65];
        rot_txid_display(mgr->part_rel.old_txid, o);
        if (strcmp(o, r->old_txid) == 0)
            memset(&mgr->part_rel, 0, sizeof(mgr->part_rel));   /* nothing owed any more */
    }
    if (closed_by_us)
        printf("LSP rotate: the old factory %s is closed (%s, %d confirmations); the "
               "released keys kept for it are deleted\n", r->old_txid, r->close_txid, confs);
    else
        printf("LSP rotate: the old factory %s is resolved on chain and every released-key "
               "output has been swept and buried (or can no longer appear); the released "
               "keys kept for it are deleted%s\n", r->old_txid,
               keep_watching ? " (a moved client's old-tree output not on chain yet stays "
                               "watched: the LSP takes it through its CLTV path)" : "");
    fflush(stdout);
    return 1;
}

int lsp_rotation_winddown_tick(lsp_channel_mgr_t *mgr, int force) {
    if (!mgr || !mgr->persist) return 0;
    persist_t *db = (persist_t *)mgr->persist;
    if (persist_in_transaction(db)) return 0;
    int h = rot_chain_height(mgr);
    if (!force && h > 0 && mgr->part_wd_height == (uint32_t)h) return 0;
    if (h > 0) mgr->part_wd_height = (uint32_t)h;
    persist_part_rotation_t *rows = calloc(LADDER_MAX_FACTORIES, sizeof(*rows));
    persist_part_release_t *rel = calloc(FACTORY_MAX_SIGNERS, sizeof(*rel));
    if (!rows || !rel) { free(rows); free(rel); return 0; }
    size_t n = persist_load_part_rotations(db, rows, LADDER_MAX_FACTORIES, 1);
    int did = 0;
    for (size_t i = 0; i < n; i++) {
        persist_part_rotation_t *r = &rows[i];
        size_t nr = persist_load_part_releases(db, r->old_txid, rel, FACTORY_MAX_SIGNERS);
        uint32_t released = 0;
        for (size_t k = 0; k < nr; k++) released += rel[k].released ? 1 : 0;
        int confs = r->close_txid[0] ? rot_tx_confirmations(mgr, r->close_txid) : -1;
        int funding_spent = rot_outpoint_unspent(mgr, r->old_txid, r->old_vout) == 0;
        /* The old factory's distribution TX and its released-key payout outputs. */
        char dist_disp[65] = {0};
        int dist_present = 0, dist_buried = 0;
        uint32_t n_unresolved = 0;
        if (r->dist_hex) {
            size_t dn = strlen(r->dist_hex) / 2;
            unsigned char *db2 = malloc(dn ? dn : 1);
            unsigned char dt[32];
            if (db2 && hex_decode(r->dist_hex, db2, dn) == (int)dn &&
                tx_txid_from_bytes(db2, dn, dt))
                rot_txid_display(dt, dist_disp);
            free(db2);
        }
        if (dist_disp[0]) {
            int dc = rot_tx_confirmations(mgr, dist_disp);
            dist_present = dc >= 1 || rot_tx_in_mempool(mgr, dist_disp);
            dist_buried = dc >= LSP_WD_CLOSE_DEPTH(mgr->rot_is_regtest);
            for (size_t k = 0; k < nr; k++) {
                unsigned char spk[34];
                uint32_t vout = 0;
                uint64_t amt = 0;
                if (rel[k].released && wd_payout_spk(mgr->ctx, rel[k].old_pk, spk) &&
                    rot_hex_find_output(r->dist_hex, spk, &vout, &amt) &&
                    rot_outpoint_unspent(mgr, dist_disp, vout) == 1)
                    n_unresolved++;
            }
        }
        int past_cltv = h > 0 && r->old_cltv > 0 &&
                        (uint64_t)h >= (uint64_t)r->old_cltv + LSP_WD_CLTV_MARGIN(mgr->rot_is_regtest);
        /* The moved clients' channel outputs in the old tree (only once the
           funding is spent can any tree transaction be on chain). */
        uint32_t n_leaf_unspent = 0, n_leaf_pending = 0, n_leaf_missing = 0;
        if (funding_spent && strcmp(r->state, "releasing") == 0)
            wd_leaf_scan(mgr, r, rel, nr, h, 1, &n_leaf_unspent, &n_leaf_pending,
                         &n_leaf_missing);
        if (strcmp(r->state, "watching") == 0) {
            /* The keys are gone; a moved client's old-tree output that shows
               up now is the LSP's through its CLTV path.  Done once every
               one of them reached the chain and is spent and buried. */
            wd_leaf_scan(mgr, r, rel, nr, h, 2, &n_leaf_unspent, &n_leaf_pending,
                         &n_leaf_missing);
            if (n_leaf_unspent == 0 && n_leaf_pending == 0 && n_leaf_missing == 0) {
                snprintf(r->state, sizeof(r->state), "done");
                if (persist_save_part_rotation(db, r))
                    printf("LSP rotate: every moved client's old-tree output of %s is spent "
                           "and buried\n", r->old_txid);
            }
            free(r->close_hex);
            free(r->dist_hex);
            continue;
        }
        lsp_wd_action_t a = lsp_rotation_winddown_action(r->state, r->n_old, r->m, released,
                                                         confs, funding_spent, dist_present,
                                                         dist_buried, n_unresolved,
                                                         n_leaf_unspent, n_leaf_pending,
                                                         past_cltv, mgr->rot_is_regtest);
        switch (a) {
        case LSP_WD_CLOSE:
            did |= wd_close(mgr, r, h);
            break;
        case LSP_WD_SWEEP:
            if (n_unresolved > 0) (void)wd_sweep(mgr, r, rel, nr, dist_disp);
            did = 1;                        /* the tree outputs were swept by the scan */
            break;
        case LSP_WD_DELETE:
            did |= wd_delete(mgr, r, confs, strcmp(r->state, "closing") == 0 &&
                                            confs >= LSP_WD_CLOSE_DEPTH(mgr->rot_is_regtest),
                             strcmp(r->state, "releasing") == 0 && n_leaf_missing > 0);
            break;
        case LSP_WD_WAIT:
            if (strcmp(r->state, "releasing") == 0 && n_unresolved > 0)
                (void)wd_sweep(mgr, r, rel, nr, dist_disp);
            /* a "closing" wait falls through to the close rebroadcast below */
            if (strcmp(r->state, "closing") == 0 && confs < 1 && r->close_hex &&
                !rot_tx_in_mempool(mgr, r->close_txid)) {
                char t[65] = {0};
                if (rot_send_hex(mgr, r->close_hex, t))
                    printf("LSP rotate: the old factory's close %s was not on the "
                           "network — rebroadcast it\n", r->close_txid);
            }
            break;
        default:
            /* Clients stayed and the old factory is still unresolved at its
               CLTV: publish its recorded distribution TX (as the design's
               EXPIRED handling does), so it resolves and the released-key
               payout outputs can be swept.  Rebroadcast each block until it
               is on the network; a stayer may publish it first. */
            if (strcmp(r->state, "releasing") == 0 && !funding_spent && !dist_present &&
                r->dist_hex && r->old_cltv > 0 && h > 0 && (uint32_t)h >= r->old_cltv) {
                char t[65] = {0};
                if (rot_send_hex(mgr, r->dist_hex, t)) {
                    persist_log_broadcast(db, dist_disp, "rotation_old_distribution",
                                          r->dist_hex, "ok");
                    printf("LSP rotate: the old factory %s is unresolved at its CLTV — "
                           "published its distribution TX %s\n", r->old_txid, dist_disp);
                    did = 1;
                }
            }
            break;
        }
        free(r->close_hex);
        free(r->dist_hex);
    }
    free(rows);
    free(rel);
    fflush(stdout);
    return did;
}

/* Resume a CIN marker (lsp_rotation_resume). */
static int lsp_rotation_cin_resume(lsp_channel_mgr_t *mgr, lsp_t *lsp) {
    lsp_rotation_progress_t *rp = &mgr->rot_progress;
    ladder_t *lad = (ladder_t *)mgr->ladder;
    ladder_factory_t *dying = NULL;
    for (size_t i = 0; lad && i < lad->n_factories; i++) {
        ladder_factory_t *lf = &lad->factories[i];
        if (lf->is_initialized && lf->factory.funding_vout == rp->dying_funding_vout &&
            memcmp(lf->factory.funding_txid, rp->dying_funding_txid, 32) == 0) {
            dying = lf;
            break;
        }
    }
    int confs = rp->close_txid[0] ? rot_tx_confirmations(mgr, rp->close_txid) : -1;
    int mem = rp->close_txid[0] ? rot_tx_in_mempool(mgr, rp->close_txid) : 0;
    lsp_cin_resume_action_t a = lsp_rotation_cin_resume_action(
        rp->phase, confs, mem, lsp_rotation_cin_eligible(mgr, lsp));
    if (rp->phase <= LSP_ROT_PROGRESS_CIN_CLOSE_SIGNING) {
        /* Not signed yet: re-run with backoff; give up after the retry limit
           (nobody holds the signed close, the old factory and its
           distribution TX stay as they are). */
        int h = rot_chain_height(mgr);
        if (h > 0 && rp->cin_next_try_height && (uint32_t)h < rp->cin_next_try_height)
            return 0;
        if (a == LSP_CIN_RESUME_RERUN && dying && lsp_rotation_close_into_new(mgr, lsp, dying))
            return 1;
        if (!lsp_rotation_cin_preclose(mgr, rp->dying_funding_txid))
            return 0;                       /* moved on (or was replaced) */
        if (!lsp_rotation_cin_note_failure(rp, h > 0 ? (uint32_t)h : 0,
                                           mgr->rot_max_retries, mgr->rot_retry_base_delay)) {
            fprintf(stderr, "LSP rotate: the close into the new factory failed %u times\n",
                    rp->cin_failures);
            (void)lsp_rotation_cin_abandon(mgr, rp->dying_funding_txid);
        }
        return 0;
    }
    switch (a) {
    case LSP_CIN_RESUME_RERUN:
        if (!dying) {
            fprintf(stderr, "LSP rotate: the dying factory of the recorded close is not in "
                    "the ladder -- holding\n");
            return 0;
        }
        return lsp_rotation_close_into_new(mgr, lsp, dying);
    case LSP_CIN_RESUME_REBROADCAST:
        if (rp->cin_signed_close_hex) {
            char t[65] = {0};
            if (rot_send_hex(mgr, rp->cin_signed_close_hex, t))
                printf("LSP rotate: rebroadcast the recorded close %s\n", rp->close_txid);
        }
        if (mgr->rot_is_regtest && rot_rt(mgr))
            regtest_mine_blocks(rot_rt(mgr), 1, mgr->rot_mine_addr);
        return 0;
    case LSP_CIN_RESUME_FINISH:
        return cin_finish(mgr, lsp, dying);
    case LSP_CIN_RESUME_WAIT:
    case LSP_CIN_RESUME_NONE:
    default:
        if (rp->phase == LSP_ROT_PROGRESS_CIN_CLOSING && mgr->rot_is_regtest && rot_rt(mgr))
            regtest_mine_blocks(rot_rt(mgr), 1, mgr->rot_mine_addr);
        return 0;
    }
}

int lsp_rotation_load_cin_progress(lsp_channel_mgr_t *mgr,
                                   const unsigned char *live_funding_txid32) {
    if (!mgr || !mgr->persist || !live_funding_txid32) return 0;
    char ft[65], dtx[65];
    rot_txid_display(live_funding_txid32, ft);
    if (persist_find_rotation_by_new_funding((persist_t *)mgr->persist, ft, dtx) != 1)
        return 0;
    unsigned char d32[32];
    if (hex_decode(dtx, d32, 32) != 32) return 0;
    reverse_bytes(d32, 32);
    persist_rotation_progress_t row;
    memset(&row, 0, sizeof(row));
    uint64_t amounts[FACTORY_MAX_SIGNERS];
    row.dist_amounts = amounts;
    if (!persist_load_rotation_progress((persist_t *)mgr->persist, dtx, &row,
                                        FACTORY_MAX_SIGNERS) ||
        (row.phase != LSP_ROT_PROGRESS_CIN_CLOSING &&
         row.phase != LSP_ROT_PROGRESS_CIN_CLOSED)) {
        free(row.new_funding_hex);
        free(row.dist_tx_hex);
        return 0;
    }
    free(row.new_funding_hex);
    free(row.dist_tx_hex);
    return lsp_rotation_load_progress(mgr, d32, row.dying_funding_vout) &&
           LSP_ROT_PROGRESS_IS_CIN(mgr->rot_progress.phase);
}
