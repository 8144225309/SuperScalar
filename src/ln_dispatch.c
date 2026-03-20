/*
 * ln_dispatch.c — LN peer message dispatch loop
 *
 * Reads BOLT #2 messages from connected peers via peer_mgr and dispatches
 * to the HTLC forwarding engine.
 *
 * Reference: LDK ChannelManager::process_pending_events(),
 *            CLN lightningd/peer_htlcs.c, LND htlcswitch/switch.go
 */

#include "superscalar/ln_dispatch.h"
#include "superscalar/htlc_commit.h"
#include "superscalar/invoice.h"
#include "superscalar/bolt12.h"
#include "superscalar/bolt1.h"
#include "superscalar/lsps.h"
#include "superscalar/onion_last_hop.h"   /* ONION_PACKET_SIZE */
#include "superscalar/chan_open.h"
#include "superscalar/payment.h"
#include "superscalar/chan_close.h"
#include "superscalar/gossip_store.h"
#include "superscalar/gossip.h"
#include "superscalar/lsp_queue.h"
#include "superscalar/persist.h"
#include "superscalar/ptlc_commit.h"
#include "superscalar/tx_builder.h"
#include "superscalar/splice.h"
#include "superscalar/stateless_invoice.h"
#include "superscalar/circuit_breaker.h"
#include "superscalar/sha256.h"
#include <string.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>

/* ---- Wire message type constants (BOLT #2) ---- */
#define MSG_UPDATE_ADD_HTLC       128   /* 0x0080 */
#define MSG_UPDATE_FULFILL_HTLC   130   /* 0x0082 */
#define MSG_UPDATE_FAIL_HTLC      131   /* 0x0083 */
#define MSG_COMMITMENT_SIGNED     132   /* 0x0084 */
#define MSG_REVOKE_AND_ACK        133   /* 0x0085 */
#define MSG_CHANNEL_REESTABLISH   136   /* 0x0088 */
#define MSG_UPDATE_FAIL_MALFORMED 135   /* 0x0087 */
#define MSG_ANNOUNCEMENT_SIGS     259   /* 0x0103 */
#define MSG_INVOICE_REQUEST      0x8001 /* BOLT #12 direct wire */

static uint16_t rd16(const unsigned char *b)
{
    return ((uint16_t)b[0] << 8) | b[1];
}

static uint64_t rd64(const unsigned char *b)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

static uint32_t rd32(const unsigned char *b)
{
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
         | ((uint32_t)b[2] <<  8) |  (uint32_t)b[3];
}

/* ---- Gossip query helper ---- */
typedef struct {
    ln_dispatch_t *d;
    int peer_idx;
    /* For range queries: collect SCIDs to include in reply_channel_range */
    uint64_t scids[256];
    int n_scids;
} gossip_send_ctx_t;

/* Called per-channel from gossip_store_get_channels_by_scids / _in_range.
   Sends channel_announcement + channel_update(s) to the querying peer. */
static void send_channel_data_cb(uint64_t scid,
                                  const unsigned char *node1,
                                  const unsigned char *node2,
                                  void *userdata)
{
    gossip_send_ctx_t *ctx = (gossip_send_ctx_t *)userdata;
    ln_dispatch_t *d = ctx->d;
    int peer_idx = ctx->peer_idx;

    /* Collect SCID for range reply */
    if (ctx->n_scids < 256)
        ctx->scids[ctx->n_scids++] = scid;

    if (!d->pmgr || peer_idx < 0) return;

    /* channel_announcement (unsigned — we relay what we have) */
    unsigned char ann[300];
    size_t ann_len = gossip_build_channel_announcement_unsigned(
        ann, sizeof(ann), GOSSIP_CHAIN_HASH_MAINNET, scid,
        node1, node2, node1, node2);
    if (ann_len > 0)
        peer_mgr_send(d->pmgr, peer_idx, ann, ann_len);

    /* channel_update for each direction we have data for */
    for (int dir = 0; dir <= 1; dir++) {
        uint32_t fee_base = 0, fee_ppm = 0;
        uint16_t cltv = 0;
        uint32_t ts = 0;
        if (!gossip_store_get_channel_update(d->gs, scid, dir,
                                              &fee_base, &fee_ppm, &cltv, &ts))
            continue;
        unsigned char upd[160];
        size_t upd_len = gossip_build_channel_update(
            upd, sizeof(upd), d->ctx, d->our_privkey,
            GOSSIP_CHAIN_HASH_MAINNET, scid, ts,
            GOSSIP_UPDATE_MSGFLAG_HTLC_MAX, (uint8_t)dir,
            cltv, 1, fee_base, fee_ppm, 0);
        if (upd_len > 0)
            peer_mgr_send(d->pmgr, peer_idx, upd, upd_len);
    }
}

int ln_dispatch_process_msg(ln_dispatch_t *d, int peer_idx,
                             const unsigned char *msg, size_t msg_len)
{
    if (!d || !msg || msg_len < 2) return -1;

    uint16_t msg_type = rd16(msg);

    switch (msg_type) {

    case MSG_UPDATE_ADD_HTLC: {
        /*
         * update_add_htlc (type 128):
         *   channel_id(32) + htlc_id(8) + amount_msat(8) +
         *   payment_hash(32) + cltv_expiry(4) + onion(1366) = 1452 bytes total
         *   (excluding 2-byte type prefix → payload starts at msg+2)
         */
        if (msg_len < 2 + 32 + 8 + 8 + 32 + 4 + ONION_PACKET_SIZE) {
            fprintf(stderr, "ln_dispatch: update_add_htlc too short (%zu)\n", msg_len);
            return -1;
        }
        const unsigned char *p = msg + 2;
        /* channel_id: p[0..31] */
        uint64_t htlc_id    = rd64(p + 32);
        uint64_t amount_msat = rd64(p + 40);
        /* payment_hash: p[48..79] */
        uint32_t cltv        = rd32(p + 80);
        const unsigned char *onion = p + 84;

        htlc_forward_entry_t fwd_out;
        int result = htlc_forward_process(
            d->fwd, d->mpp, d->our_privkey, d->ctx,
            onion,
            htlc_id, (uint64_t)peer_idx,
            amount_msat, cltv,
            &fwd_out);


        /* Phase K / Gap 3: JIT intercept */
        if (result == FORWARD_RELAY && d->jit_pending) {
            lsps2_pending_t *jit = lsps2_pending_lookup(d->jit_pending,
                                                          fwd_out.next_hop_scid);
            if (jit) {
                int covered = lsps2_handle_intercept_htlc(d->jit_pending,
                                                            fwd_out.next_hop_scid,
                                                            fwd_out.out_amount_msat,
                                                            NULL, NULL);
                /* Gap 3: cost covered — open channel then relay */
                if (covered == 1 && d->jit_open_cb)
                    d->jit_open_cb(d->jit_cb_ctx, fwd_out.next_hop_scid,
                                   fwd_out.out_amount_msat,
                                   (size_t)peer_idx, htlc_id);
            }
        }
        if (result == FORWARD_FINAL) {
            /* We are the final hop — claim invoice and send update_fulfill_htlc */
            const unsigned char *channel_id   = p;      /* p[0..31] */
            const unsigned char *payment_hash = p + 48; /* p[48..79] */
            if (d->invoices) {
                /* Locate the invoice entry for this payment_hash */
                bolt11_invoice_entry_t *inv_entry = NULL;
                for (int _i = 0; _i < d->invoices->count; _i++) {
                    if (d->invoices->entries[_i].active &&
                        memcmp(d->invoices->entries[_i].payment_hash,
                               payment_hash, 32) == 0) {
                        inv_entry = &d->invoices->entries[_i];
                        break;
                    }
                }

                /* Phase C: verify HMAC-derived payment_secret (stateless Level 1)
                 * Only enforced for invoices created with has_stateless_secret=1. */
                if (inv_entry && inv_entry->has_stateless_secret &&
                    fwd_out.has_payment_secret) {
                    if (!stateless_invoice_verify_secret(d->our_privkey,
                                                         payment_hash,
                                                         fwd_out.payment_secret)) {
                        if (d->pmgr && peer_idx >= 0) {
                            static const unsigned char bad_secret[2] = {0x40, 0x0F};
                            htlc_commit_send_fail(d->pmgr, peer_idx,
                                                  channel_id, htlc_id,
                                                  bad_secret, sizeof(bad_secret));
                        }
                        return (int)msg_type;
                    }
                }

                unsigned char preimage[32];
                int claimed = 0;

                /* Phase PR56 Level 2: derive preimage from stored nonce */
                if (inv_entry && inv_entry->has_stateless_preimage &&
                    fwd_out.has_payment_secret) {
                    claimed = stateless_invoice_claim(d->our_privkey,
                                                      inv_entry->stateless_nonce,
                                                      payment_hash,
                                                      fwd_out.payment_secret,
                                                      preimage);
                    if (claimed) inv_entry->settled = 1;
                }

                /* Level 1 / stored-preimage fallback */
                if (!claimed)
                    claimed = invoice_claim(d->invoices, payment_hash,
                                            amount_msat, preimage);

                if (claimed) {
                    if (d->pmgr && peer_idx >= 0)
                        htlc_commit_send_fulfill(d->pmgr, peer_idx,
                                                 channel_id, htlc_id, preimage);
                    invoice_settle(d->invoices, payment_hash);
                    /* Startup/shutdown: persist the settled state so it
                     * survives a restart (PR #72). */
                    if (d->persist && inv_entry) {
                        inv_entry->settled = 1;
                        persist_save_ln_invoice((persist_t *)d->persist, inv_entry);
                    }
                } else {
                    /* No matching / valid invoice — send unknown_payment_hash */
                    if (d->pmgr && peer_idx >= 0) {
                        static const unsigned char unknown_payment[2] = {0x40, 0x04};
                        htlc_commit_send_fail(d->pmgr, peer_idx,
                                              channel_id, htlc_id,
                                              unknown_payment, sizeof(unknown_payment));
                    }
                }
            }
        } else if (result == FORWARD_FAIL) {
            /* Onion decryption failed — send update_fail_malformed_htlc (BOLT #2) */
            if (d->pmgr && peer_idx >= 0) {
                unsigned char sha256_of_onion[32];
                sha256(onion, ONION_PACKET_SIZE, sha256_of_onion);
                htlc_commit_send_fail_malformed(d->pmgr, peer_idx,
                                                p,        /* channel_id p[0..31] */
                                                htlc_id,
                                                sha256_of_onion,
                                                0x8003);  /* INVALID_ONION_HMAC */
            }
        }
        /* Phase N: copy in_channel_id into forward entry */
        if (result == FORWARD_RELAY) {
            htlc_forward_entry_t *fe = &d->fwd->entries[d->fwd->count - 1];
            memcpy(fe->in_channel_id, p, 32); /* p[0..31] = channel_id */
        }
        return (int)msg_type;
    }

    case MSG_UPDATE_FULFILL_HTLC: {
        /*
         * update_fulfill_htlc (type 130):
         *   channel_id(32) + htlc_id(8) + payment_preimage(32) = 72 bytes payload
         */
        if (msg_len < 2 + 32 + 8 + 32) return -1;
        const unsigned char *p = msg + 2;
        uint64_t htlc_id       = rd64(p + 32);
        const unsigned char *preimage = p + 40;

        htlc_forward_settle(d->fwd, htlc_id, (uint64_t)peer_idx, preimage);
        return (int)msg_type;
    }

    case MSG_UPDATE_FAIL_HTLC: {
        /*
         * update_fail_htlc (type 131):
         *   channel_id(32) + htlc_id(8) + len(2) + reason(len) bytes
         */
        if (msg_len < 2 + 32 + 8 + 2) return -1;
        const unsigned char *p = msg + 2;
        uint64_t htlc_id       = rd64(p + 32);
        uint16_t reason_len    = ((uint16_t)p[40] << 8) | p[41];
        const unsigned char *reason = p + 42;
        if (msg_len < (size_t)(2 + 32 + 8 + 2 + reason_len)) return -1;

        unsigned char out_error[256];
        htlc_forward_fail(d->fwd, htlc_id, (uint64_t)peer_idx,
                          reason, reason_len, out_error);
        return (int)msg_type;
    }

    case MSG_COMMITMENT_SIGNED:
    case MSG_REVOKE_AND_ACK: {
        /* Phase M: dispatch to htlc_commit layer for full round-trip */
        if (msg_len < 2 + 32) return -1;
        const unsigned char *channel_id = msg + 2;
        channel_t *ch = (d->peer_channels && peer_idx >= 0)
                        ? d->peer_channels[peer_idx] : NULL;
        if (ch && d->pmgr)
            htlc_commit_dispatch(d->pmgr, peer_idx, ch, d->ctx,
                                  channel_id, msg, msg_len);
        return (int)msg_type;
    }

    case MSG_CHANNEL_REESTABLISH: {
        /* Phase M: run channel reestablish after reconnect */
        channel_t *ch = (d->peer_channels && peer_idx >= 0)
                        ? d->peer_channels[peer_idx] : NULL;
        if (ch && d->pmgr) {
            int r = chan_reestablish(d->pmgr, peer_idx, d->ctx, ch);
            if (r == 0 && d->watchtower) {
                /* DLP detected: peer is ahead — register for sweep */
                fprintf(stderr, "ln_dispatch: DLP peer %d — force close\n", peer_idx);
                watchtower_set_channel(d->watchtower, (size_t)peer_idx, ch);
            }
        }
        return (int)msg_type;
    }

    case 134: { /* update_fee: channel_id(32) + feerate_per_kw(4) */
        if (msg_len < 2 + 32 + 4) return -1;
        channel_t *ch = (d->peer_channels && peer_idx >= 0)
                        ? d->peer_channels[peer_idx] : NULL;
        if (ch)
            htlc_commit_recv_update_fee(ch, msg, msg_len,
                                         BOLT2_UPDATE_FEE_FLOOR,
                                         BOLT2_UPDATE_FEE_CEILING);
        return 134;
    }

    case MSG_UPDATE_FAIL_MALFORMED: {
        /*
         * update_fail_malformed_htlc (type 135):
         *   channel_id(32) + htlc_id(8) + sha256_of_onion(32) + failure_code(2) = 74 bytes
         */
        if (msg_len >= 2 + 74) {
            const unsigned char *p = msg + 2;
            uint64_t htlc_id = rd64(p + 32);
            unsigned char out_error[256];
            htlc_forward_fail(d->fwd, htlc_id, (uint64_t)peer_idx, NULL, 0, out_error);
        }
        return (int)msg_type;
    }

    case MSG_INVOICE_REQUEST: {
        /*
         * BOLT #12 invoice_request (type 0x8001):
         * Decode TLV, verify sig, build and sign invoice, reply with 0x8000.
         * If decode or verify fails, send invoice_error (0x8002).
         */
        const unsigned char *payload = msg + 2;
        size_t payload_len = msg_len - 2;
        invoice_request_t req;
        memset(&req, 0, sizeof(req));
        if (invoice_request_decode(payload, payload_len, &req) &&
            invoice_request_verify(&req, d->ctx)) {
            unsigned char payment_hash[32], payment_secret[32];
            memset(payment_hash,   0xAA, 32);
            memset(payment_secret, 0xBB, 32);
            invoice_t inv;
            if (invoice_from_request(&req, d->ctx, d->our_privkey,
                                      payment_hash, payment_secret, &inv)) {
                unsigned char resp[512];
                size_t resp_len = invoice_encode(&inv, resp, sizeof(resp));
                if (resp_len > 0 && d->pmgr && peer_idx >= 0)
                    peer_mgr_send(d->pmgr, peer_idx, resp, resp_len);
            }
        } else {
            invoice_error_t err;
            invoice_error_build(payload, payload_len,
                                "invoice_request decode/verify failed", 0, &err);
            unsigned char err_buf[1024];
            size_t err_len = invoice_error_encode(&err, err_buf, sizeof(err_buf));
            if (err_len > 0 && d->pmgr && peer_idx >= 0)
                peer_mgr_send(d->pmgr, peer_idx, err_buf, err_len);
        }
        return (int)msg_type;
    }

    case 0x4C:
    case 0x4D: {
        channel_t *ch = (d->peer_channels) ? d->peer_channels[peer_idx] : NULL;
        if (ch && d->pmgr)
            ptlc_commit_dispatch(d->pmgr, peer_idx, ch, d->ctx, msg, msg_len);
        return (int)msg_type;
    }
    case 78: { /* open_channel2 (0x4E) / splice_init (quiescent) / PTLC_COMPLETE */
        channel_t *ch = (d->peer_channels) ? d->peer_channels[peer_idx] : NULL;
        if (ch && ch->channel_quiescent && msg_len == 79) {
            /* splice_init: 2(type)+32(cid)+8(amount)+4(feerate)+33(funding_pubkey) = 79 */
            memset(ch->splice_pending_txid, 0, 32);
            ch->channel_quiescent = SPLICE_STATE_PENDING;
        } else if (msg_len >= 350) {
            /* open_channel2 */
            if (ch && d->ctx)
                chan_open_inbound_v2(d->pmgr, peer_idx, msg, msg_len, d->ctx, ch);
        } else {
            /* PTLC_COMPLETE (0x4E) */
            if (ch && d->pmgr)
                ptlc_commit_dispatch(d->pmgr, peer_idx, ch, d->ctx, msg, msg_len);
        }
        return (int)SPLICE_MSG_SPLICE_INIT;
    }
    case 0x6D: { /* MSG_QUEUE_POLL: client requesting pending work items */
        if (!d->persist) return 0x6D;
        queue_entry_t entries[16];
        size_t n = queue_drain((persist_t *)d->persist,
                                (uint32_t)peer_idx, entries, 16);
        unsigned char resp[4096];
        resp[0] = 0x00; resp[1] = 0x6E;
        uint16_t count16 = (uint16_t)n;
        resp[2] = (count16 >> 8) & 0xFF;
        resp[3] = count16 & 0xFF;
        size_t off = 4;
        for (size_t k = 0; k < n && off + 20 <= sizeof(resp); k++) {
            uint64_t eid = entries[k].id;
            for (int b = 7; b >= 0; b--) { resp[off++] = (eid >> (b*8)) & 0xFF; }
            uint32_t rt = (uint32_t)entries[k].request_type;
            for (int b = 3; b >= 0; b--) { resp[off++] = (rt >> (b*8)) & 0xFF; }
            uint32_t fi = entries[k].factory_id;
            for (int b = 3; b >= 0; b--) { resp[off++] = (fi >> (b*8)) & 0xFF; }
            uint32_t ci = entries[k].client_idx;
            for (int b = 3; b >= 0; b--) { resp[off++] = (ci >> (b*8)) & 0xFF; }
        }
        if (d->pmgr && peer_idx >= 0)
            peer_mgr_send(d->pmgr, peer_idx, resp, off);
        return 0x6D;
    }
    case 0x6F: { /* MSG_QUEUE_DONE: client acknowledges processed item IDs */
        if (!d->persist) return 0x6F;
        if (msg_len < 4) return -1;
        uint16_t count = ((uint16_t)msg[2] << 8) | msg[3];
        size_t off = 4;
        for (uint16_t k = 0; k < count && off + 8 <= msg_len; k++) {
            uint64_t eid = 0;
            for (int b = 0; b < 8; b++) eid = (eid << 8) | msg[off++];
            queue_delete((persist_t *)d->persist, eid);
        }
        return 0x6F;
    }
    case 261: { /* query_short_channel_ids */
        if (!d->gs) return 261;
#define QS_MAX 256
        uint64_t scids[QS_MAX];
        int n = gossip_parse_query_scids(msg, msg_len, NULL, scids, QS_MAX);
        if (n < 0) return -1;
        /* Send channel_announcement + channel_update(s) for each known SCID */
        gossip_send_ctx_t gctx;
        memset(&gctx, 0, sizeof(gctx));
        gctx.d = d; gctx.peer_idx = peer_idx;
        if (n > 0)
            gossip_store_get_channels_by_scids(d->gs, scids, n,
                                               send_channel_data_cb, &gctx);
        /* reply_short_channel_ids_end: complete=1 */
        unsigned char reply[35];
        size_t rlen = gossip_build_reply_scids_end(reply, sizeof(reply),
                                                    GOSSIP_CHAIN_HASH_MAINNET, 1);
        if (rlen > 0 && d->pmgr && peer_idx >= 0)
            peer_mgr_send(d->pmgr, peer_idx, reply, rlen);
        return 261;
    }
    case 262: { /* reply_short_channel_ids_end — received, ignore */
        return 262;
    }
    case 263: { /* query_channel_range */
        if (!d->gs) return 263;
        uint32_t first_block = 0, num_blocks_val = 0;
        unsigned char ch32[32];
        if (!gossip_parse_query_range(msg, msg_len, ch32, &first_block, &num_blocks_val))
            return -1;
        /* Collect SCIDs and send channel data for each */
        gossip_send_ctx_t gctx;
        memset(&gctx, 0, sizeof(gctx));
        gctx.d = d; gctx.peer_idx = peer_idx;
        gossip_store_get_channels_in_range(d->gs, first_block, num_blocks_val,
                                           send_channel_data_cb, &gctx);
        /* reply_channel_range with the collected SCID list */
        unsigned char reply[1024];
        size_t rlen = gossip_build_reply_range(reply, sizeof(reply),
                                                ch32, first_block, num_blocks_val,
                                                gctx.scids, gctx.n_scids, 1);
        if (rlen > 0 && d->pmgr && peer_idx >= 0)
            peer_mgr_send(d->pmgr, peer_idx, reply, rlen);
        return 263;
    }
    case 264: { /* reply_channel_range — received from peer, store SCIDs */
        return 264;
    }
    case 38: { /* shutdown: channel_id(32) + spk_len(2) + spk */
        if (msg_len < 36) return -1;
        unsigned char cid[32];
        unsigned char their_spk[CHAN_CLOSE_MAX_SPK_LEN];
        uint16_t their_spk_len = 0;
        if (!chan_close_recv_shutdown(msg, msg_len, cid, their_spk,
                                      &their_spk_len, sizeof(their_spk)))
            return -1;
        channel_t *ch = (d->peer_channels) ? d->peer_channels[peer_idx] : NULL;
        if (ch) {
            /* Store peer's closing scriptpubkey */
            memcpy(ch->close_their_spk, their_spk, their_spk_len);
            ch->close_their_spk_len = their_spk_len;
            ch->close_state |= 2; /* RECV_SHUTDOWN */
            if (!(ch->close_state & 1)) {
                /* Mirror: send our shutdown too */
                ch->close_state |= 1; /* SENT_SHUTDOWN */
                if (d->pmgr && peer_idx >= 0)
                    chan_close_send_shutdown(d->pmgr, peer_idx, cid,
                                             ch->close_our_spk, ch->close_our_spk_len);
            }
        }
        return 38;
    }
    case 39: { /* closing_signed: channel_id(32) + fee(8) + sig(64) */
        if (msg_len < 76) return -1;
        unsigned char cid[32];
        uint64_t their_fee = 0;
        unsigned char sig[64];
        if (!chan_close_recv_closing_signed(msg, msg_len, cid, &their_fee, sig))
            return -1;
        channel_t *ch = (d->peer_channels) ? d->peer_channels[peer_idx] : NULL;
        if (ch && (ch->close_state & 3) == 3) {
            if (ch->close_our_fee_sat == 0)
                ch->close_our_fee_sat = their_fee;
            uint64_t counter = chan_close_negotiate_fee(ch->close_our_fee_sat, their_fee);
            ch->close_their_fee_sat = their_fee;
            if (counter == their_fee) {
                ch->close_state = 5; /* DONE — fees agreed */
                memcpy(ch->close_remote_sig, sig, 64);
                /* Build and broadcast the closing tx */
                if (d->broadcast_tx_cb && ch->funding_spk_len > 0 &&
                    ch->close_our_spk_len > 0 && ch->close_their_spk_len > 0) {
                    uint64_t agreed_fee = their_fee;
                    tx_output_t outs[2];
                    memset(outs, 0, sizeof(outs));
                    memcpy(outs[0].script_pubkey, ch->close_our_spk,   ch->close_our_spk_len);
                    outs[0].script_pubkey_len = ch->close_our_spk_len;
                    outs[0].amount_sats = (ch->local_amount > agreed_fee * 1000 ?
                                           (ch->local_amount - agreed_fee * 1000) / 1000 : 0);
                    memcpy(outs[1].script_pubkey, ch->close_their_spk, ch->close_their_spk_len);
                    outs[1].script_pubkey_len = ch->close_their_spk_len;
                    outs[1].amount_sats = ch->remote_amount / 1000;
                    tx_buf_t close_tx;
                    memset(&close_tx, 0, sizeof(close_tx));
                    if (channel_build_cooperative_close_tx(
                            ch, &close_tx, NULL,
                            &ch->local_funding_keypair,
                            outs, 2) &&
                        close_tx.data && close_tx.len > 0) {
                        d->broadcast_tx_cb(d->broadcast_tx_ctx,
                                           close_tx.data, close_tx.len);
                    }
                    tx_buf_free(&close_tx);
                }
            } else {
                ch->close_our_fee_sat = counter;
                ch->close_state = 4; /* NEGOTIATING */
                unsigned char dummy_sig[64] = {0};
                if (d->pmgr && peer_idx >= 0)
                    chan_close_send_closing_signed(d->pmgr, peer_idx, cid, counter, dummy_sig);
            }
        }
        return 39;
    }
    case 0x68: { /* MSG_STFU - channel quiescence request */
        channel_t *ch = (d->peer_channels) ? d->peer_channels[peer_idx] : NULL;
        if (ch) ch->channel_quiescent = 1;
        return (int)SPLICE_MSG_STFU;
    }
    case 0x69: /* MSG_STFU_ACK */
        return (int)SPLICE_MSG_STFU_ACK;
    case BOLT2_STFU: { /* stfu (type 140, 0x008C) — BOLT #2 quiescence request */
        /* Wire: type(2) + channel_id(32) = 34 bytes total */
        if (msg_len < 2 + 32) return -1;
        const unsigned char *channel_id = msg + 2;
        if (d->pmgr && peer_idx >= 0) {
            quiesce_state_t qs = QUIESCE_NONE;
            splice_handle_stfu(d->pmgr, peer_idx, channel_id, &qs);
        }
        return BOLT2_STFU;
    }
    case BOLT2_STFU_REPLY: { /* stfu_reply (type 141, 0x008D) — peer acknowledged quiescence */
        /* Wire: type(2) + channel_id(32) = 34 bytes total */
        if (msg_len < 2 + 32) return -1;
        return BOLT2_STFU_REPLY;
    }
    case SPLICE_MSG_SPLICE_ACK: /* splice_ack: pass through */
        return (int)SPLICE_MSG_SPLICE_ACK;
    case MSG_TX_ADD_INPUT:
        return MSG_TX_ADD_INPUT;
    case MSG_TX_ADD_OUTPUT:
        return MSG_TX_ADD_OUTPUT;
    case MSG_TX_REMOVE_INPUT:
        return MSG_TX_REMOVE_INPUT;
    case MSG_TX_REMOVE_OUTPUT:
        return MSG_TX_REMOVE_OUTPUT;
    case MSG_TX_COMPLETE: { /* tx_complete - both sides done adding inputs/outputs */
        channel_t *ch = (d->peer_channels) ? d->peer_channels[peer_idx] : NULL;
        if (ch && ch->channel_quiescent) ch->channel_quiescent = 2;
        return MSG_TX_COMPLETE;
    }
    case MSG_TX_SIGNATURES:
        return MSG_TX_SIGNATURES;
    case SPLICE_MSG_SPLICE_LOCKED: { /* splice_locked (80): apply new funding */
        channel_t *ch = (d->peer_channels) ? d->peer_channels[peer_idx] : NULL;
        if (ch && msg_len >= 66) {
            unsigned char splice_txid[32];
            if (splice_parse_splice_locked(msg, msg_len, NULL, splice_txid))
                channel_apply_splice_update(ch, splice_txid, 0, ch->funding_amount);
        }
        return (int)SPLICE_MSG_SPLICE_LOCKED;
    }
        case BOLT1_MSG_WARNING: /* warning (type 1) - log and continue */
        return BOLT1_MSG_WARNING;
    case BOLT1_MSG_INIT: { /* init (type 16) - feature negotiation */
        bolt1_init_t init_parsed;
        bolt1_parse_init(msg, msg_len, &init_parsed);
        /* Store negotiated features if peer_mgr supports it */
        return BOLT1_MSG_INIT;
    }
    case BOLT1_MSG_ERROR: /* error (type 17) - log and return */
        return BOLT1_MSG_ERROR;
    case BOLT1_MSG_PING: { /* ping (type 18) - send pong */
        bolt1_ping_t ping;
        if (bolt1_parse_ping(msg, msg_len, &ping) &&
            d->pmgr && peer_idx >= 0 && ping.num_pong_bytes <= 65531) {
            unsigned char pong_buf[65535];
            size_t pong_len = bolt1_build_pong(ping.num_pong_bytes,
                                                pong_buf, sizeof(pong_buf));
            if (pong_len > 0)
                peer_mgr_send(d->pmgr, peer_idx, pong_buf, pong_len);
        }
        return BOLT1_MSG_PING;
    }
    case BOLT1_MSG_PONG: /* pong (type 19) - ignore */
        return BOLT1_MSG_PONG;
    case 256:  /* channel_announcement */
    case 257:  /* node_announcement */
    case 258:  /* channel_update */
    case 265:  /* gossip_timestamp_filter */ {
        if (d->gi) {
            const unsigned char *payload = msg;
            gossip_ingest_message(d->gi, payload, msg_len, (uint32_t)time(NULL));
        }
        return (int)msg_type;
    }

    case MSG_ANNOUNCEMENT_SIGS: {
        /* announcement_signatures (type 259):
         * channel_id(32) + scid(8) + node_sig(64) + bitcoin_sig(64) = 168 + 2 type */
        if (msg_len < 2 + 32 + 8 + 64 + 64) return -1;
        const unsigned char *p = msg + 2;
        /* p[0..31] = channel_id, p[32..39] = scid,
           p[40..103] = node_sig, p[104..167] = bitcoin_sig */
        const unsigned char *channel_id = p;
        const unsigned char *node_sig   = p + 40;
        const unsigned char *btc_sig    = p + 104;
        if (d->peer_channels && peer_idx >= 0 && peer_idx < PEER_MGR_MAX_PEERS) {
            channel_t *ch = d->peer_channels[peer_idx];
            if (ch && memcmp(ch->funding_txid, channel_id, 32) == 0) {
                memcpy(ch->remote_node_sig,    node_sig, 64);
                memcpy(ch->remote_bitcoin_sig, btc_sig,  64);
                ch->ann_sigs_recv = 1;
            }
        }
        return (int)msg_type;
    }

        default:
        /* Unknown type — silently ignore per BOLT #1 §2 */
        return 0;
    }
}

void ln_dispatch_run(ln_dispatch_t *d)
{
    if (!d || !d->pmgr || !d->shutdown_flag) return;

    unsigned char msg_buf[2048];
    size_t msg_len;

    while (!*d->shutdown_flag) {
        /* Build fd_set from all connected peers */
        fd_set rfds;
        FD_ZERO(&rfds);
        int maxfd = -1;

        for (int i = 0; i < d->pmgr->count; i++) {
            int fd = d->pmgr->peers[i].fd;
            if (fd >= 0) {
                FD_SET(fd, &rfds);
                if (fd > maxfd) maxfd = fd;
            }
        }

        if (maxfd < 0) {
            /* No connected peers — attempt reconnects then sleep */
            struct timeval tv = { 0, 100000 };  /* 100 ms */
            select(0, NULL, NULL, NULL, &tv);
            peer_mgr_reconnect_all(d->pmgr, d->peer_channels,
                                    (uint32_t)time(NULL));
            continue;
        }

        struct timeval tv = { 0, 100000 };  /* 100 ms timeout */
        int sel = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        /* Gap 2: expire stale JIT pending entries on each tick */
        if (d->jit_pending) lsps2_pending_expire(d->jit_pending);
        /* Phase O: reconnect any peers whose backoff timer has expired */
        uint32_t now_ts = (uint32_t)time(NULL);
        peer_mgr_reconnect_all(d->pmgr, d->peer_channels, now_ts);
        /* Phase P: expire stale payment attempts */
        if (d->payments)
            payment_check_timeouts(d->payments, NULL, d->fwd, d->mpp,
                                    d->pmgr, d->ctx, d->our_privkey, now_ts);
        if (sel <= 0) continue;

        for (int i = 0; i < d->pmgr->count && !*d->shutdown_flag; i++) {
            int fd = d->pmgr->peers[i].fd;
            if (fd < 0 || !FD_ISSET(fd, &rfds)) continue;

            msg_len = sizeof(msg_buf);
            int r = peer_mgr_recv(d->pmgr, i, msg_buf, &msg_len, sizeof(msg_buf));
            if (!r) {
                /* Phase O: transient disconnect — retain slot for reconnect */
                uint32_t backoff = (uint32_t)(5u << (d->pmgr->peers[i].reconnect_attempts < 6
                                              ? (unsigned)d->pmgr->peers[i].reconnect_attempts : 6u));
                if (backoff > 300) backoff = 300;
                peer_mgr_mark_disconnected(d->pmgr, i, backoff);
                continue;
            }

            ln_dispatch_process_msg(d, i, msg_buf, msg_len);
            ln_dispatch_flush_relay(d);
        }
    }
}

/* -----------------------------------------------------------------------
 * Phase N: relay pump — flush FORWARD_STATE_PENDING_OUT HTLCs to next peers
 * --------------------------------------------------------------------- */
int ln_dispatch_flush_relay(ln_dispatch_t *d)
{
    if (!d || !d->fwd || !d->pmgr) return 0;
    int sent = 0;

    for (int i = 0; i < d->fwd->count; i++) {
        htlc_forward_entry_t *e = &d->fwd->entries[i];
        if (e->state != FORWARD_STATE_PENDING_OUT) continue;

        /* Find outbound peer by SCID */
        int out_idx = peer_mgr_find_by_scid(d->pmgr, e->next_hop_scid);
        if (out_idx < 0) continue; /* peer not connected yet */

        channel_t *ch = (d->peer_channels) ? d->peer_channels[out_idx] : NULL;
        if (!ch) continue; /* no channel state for this peer */

        /* Use funding_txid as BOLT #2 channel_id (approximation) */
        uint64_t htlc_id_out = 0;
        int ok = htlc_commit_add_and_sign(d->pmgr, out_idx, ch, d->ctx,
                                           ch->funding_txid,
                                           e->out_amount_msat,
                                           e->payment_hash,
                                           e->out_cltv,
                                           e->next_onion,
                                           &htlc_id_out);
        if (ok) {
            e->out_htlc_id = htlc_id_out;
            e->out_chan_id  = e->next_hop_scid;
            e->state        = FORWARD_STATE_INFLIGHT;
            sent++;
        } else {
            e->state = FORWARD_STATE_FAILED;
        }
    }
    return sent;
}

/* -----------------------------------------------------------------------
 * Startup state restore — load persisted invoices into dispatch tables.
 * Called once after d->persist and d->invoices are set, before the loop.
 * --------------------------------------------------------------------- */

/* Callback context for persist_load_ln_peer_channels */
typedef struct {
    ln_dispatch_t *d;
    int count;
} channel_restore_ctx_t;

static void restore_channel_cb(const unsigned char channel_id[32],
                                const unsigned char peer_pubkey[33],
                                uint64_t capacity_sat,
                                uint64_t local_balance_msat,
                                uint64_t remote_balance_msat,
                                int state,
                                const char *peer_host,
                                uint16_t peer_port,
                                void *ctx_)
{
    channel_restore_ctx_t *ctx = (channel_restore_ctx_t *)ctx_;
    ln_dispatch_t *d = ctx->d;
    (void)state;

    if (!d->peer_channels) return;

    /* Find a free slot — zero funding_amount indicates unused entry */
    for (int i = 0; i < PEER_MGR_MAX_PEERS; i++) {
        if (!d->peer_channels[i]) continue;
        channel_t *ch = d->peer_channels[i];
        if (ch->funding_amount == 0) {
            /* Restore minimal fields; full key rebuild happens on reconnect */
            memcpy(ch->funding_txid, channel_id, 32);
            ch->funding_amount      = capacity_sat;
            ch->local_amount        = local_balance_msat / 1000;
            ch->remote_amount       = remote_balance_msat / 1000;
            ctx->count++;
            /* Trigger reconnect if we have a host/port saved */
            if (d->pmgr && peer_host && strlen(peer_host) > 0 && peer_port > 0)
                peer_mgr_connect(d->pmgr, peer_host, peer_port, peer_pubkey);
            break;
        }
    }
}

int ln_dispatch_load_state(ln_dispatch_t *d)
{
    if (!d || !d->persist) return -1;
    int total = 0;

    /* Load BOLT #11 invoices from SQLite into the in-memory invoice table */
    if (d->invoices) {
        int n = persist_load_ln_invoices((persist_t *)d->persist, d->invoices);
        if (n < 0) return -1;
        total += n;
    }

    /* Restore peer channel state from ln_peer_channels table */
    if (d->peer_channels) {
        channel_restore_ctx_t cctx = { d, 0 };
        persist_load_ln_peer_channels((persist_t *)d->persist,
                                      restore_channel_cb, &cctx);
        total += cctx.count;

    /* Load circuit breaker limits from DB */
    if (d->cb)
        persist_load_circuit_breaker_peers((persist_t *)d->persist, d->cb);
    }

    return total;
}
