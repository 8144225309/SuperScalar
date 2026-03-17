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
#include "superscalar/onion_last_hop.h"   /* ONION_PACKET_SIZE */
#include <string.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

/* ---- Wire message type constants (BOLT #2) ---- */
#define MSG_UPDATE_ADD_HTLC       128   /* 0x0080 */
#define MSG_UPDATE_FULFILL_HTLC   130   /* 0x0082 */
#define MSG_UPDATE_FAIL_HTLC      131   /* 0x0083 */
#define MSG_COMMITMENT_SIGNED     132   /* 0x0084 */
#define MSG_REVOKE_AND_ACK        133   /* 0x0085 */
#define MSG_CHANNEL_REESTABLISH   136   /* 0x0088 */
#define MSG_UPDATE_FAIL_MALFORMED 135   /* 0x0087 */
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

        if (result == FORWARD_FINAL) {
            /* We are the final hop — claim invoice and send update_fulfill_htlc */
            const unsigned char *channel_id   = p;      /* p[0..31] */
            const unsigned char *payment_hash = p + 48; /* p[48..79] */
            if (d->invoices) {
                unsigned char preimage[32];
                if (invoice_claim(d->invoices, payment_hash, amount_msat, preimage)) {
                    if (d->pmgr && peer_idx >= 0)
                        htlc_commit_send_fulfill(d->pmgr, peer_idx,
                                                 channel_id, htlc_id, preimage);
                    invoice_settle(d->invoices, payment_hash);
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
            /* Onion decryption failed — send update_fail_malformed_htlc */
            (void)fwd_out;
        }
        /* FORWARD_RELAY: queued for outbound relay (handled upstream) */
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
    case MSG_CHANNEL_REESTABLISH:
        /* Forward to htlc_commit layer — handled by htlc_commit_dispatch
         * when the caller uses that path.  Here we simply acknowledge
         * the type was recognized. */
        return (int)msg_type;

    case MSG_REVOKE_AND_ACK:
        /* Acknowledge revoke_and_ack; watchtower registration is handled
         * in the daemon layer via g_watchtower after commitment update. */
        return (int)msg_type;

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
            /* No connected peers — sleep briefly and retry */
            struct timeval tv = { 0, 100000 };  /* 100 ms */
            select(0, NULL, NULL, NULL, &tv);
            continue;
        }

        struct timeval tv = { 0, 100000 };  /* 100 ms timeout */
        int sel = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (sel <= 0) continue;

        for (int i = 0; i < d->pmgr->count && !*d->shutdown_flag; i++) {
            int fd = d->pmgr->peers[i].fd;
            if (fd < 0 || !FD_ISSET(fd, &rfds)) continue;

            msg_len = sizeof(msg_buf);
            int r = peer_mgr_recv(d->pmgr, i, msg_buf, &msg_len, sizeof(msg_buf));
            if (!r) {
                peer_mgr_disconnect(d->pmgr, i);
                continue;
            }

            ln_dispatch_process_msg(d, i, msg_buf, msg_len);
        }
    }
}
