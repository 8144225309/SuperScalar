/*
 * ptlc_commit.c — PTLC state machine (Point Time-Locked Contracts)
 *
 * Manages adaptor-signature based payments for the SuperScalar factory.
 * Message types: 0x4C (PTLC_PRESIG), 0x4D (PTLC_ADAPTED_SIG), 0x4E (PTLC_COMPLETE)
 */

#include "superscalar/ptlc_commit.h"
#include "superscalar/channel.h"
#include "superscalar/peer_mgr.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

/* Minimum capacity for PTLC array growth */
#define PTLC_INIT_CAP 8

/* PTLC safety gate (task #104).

   PTLC machinery (channel ops, wire protocol, watchtower sweep loop, ptlcs
   persistence table) is built — but the breach-defense feed is incomplete:
   nothing populates watchtower_entry_t.ptlc_outputs, so the sweep loop at
   watchtower.c:947 is unreachable.  Until the Phase 0 audit (task #103)
   confirms the full threat surface and the breach-defense PRs land, refuse
   any production attempt to create a real PTLC output.

   Today's call surface is benign — ptlc_commit_add_and_sign + the
   meaningful overload of channel_add_ptlc are only invoked from tests.
   This gate is defense in depth against future refactors accidentally
   wiring a production callsite.

   Tests opt in by setting ptlc_safety_set_enabled(1) at start of the test
   that needs to exercise real PTLCs. */
static int g_ptlc_safety_enabled = 0;

void ptlc_safety_set_enabled(int enabled) {
    g_ptlc_safety_enabled = enabled ? 1 : 0;
}

int ptlc_safety_is_enabled(void) {
    return g_ptlc_safety_enabled;
}

static uint16_t rd16_be(const unsigned char *b)
{
    return ((uint16_t)b[0] << 8) | b[1];
}

int channel_add_ptlc(channel_t *ch, ptlc_direction_t dir,
                      uint64_t amount_sats,
                      const secp256k1_pubkey *point,
                      uint32_t cltv_expiry, uint64_t *id_out)
{
    if (!ch) return 0;

    /* Safety gate (task #104): refuse real PTLCs in production until breach
       defense lands.  Degenerate calls (amount=0 AND point=NULL) used by the
       inbound wire dispatch for pre_sig storage still pass through, since
       they create no on-chain output value. */
    if (!g_ptlc_safety_enabled && (amount_sats > 0 || point != NULL)) {
        fprintf(stderr,
            "channel_add_ptlc: refused (PTLC support gated; see task #104 / Phase 0 audit)\n");
        return 0;
    }

    /* #182: deduct amount + per-PTLC commit fee from the sender. Mirrors
       channel_add_htlc balance accounting; without this the commit TX
       outputs exceed funding and broadcast fails with bad-txns-in-belowout. */
    if (amount_sats > 0) {
        if (dir == PTLC_OFFERED) {
            if (ch->local_amount < amount_sats + CHANNEL_RESERVE_SATS) {
                fprintf(stderr,
                    "channel_add_ptlc: refused OFFERED — local %" PRIu64
                    " < amount %" PRIu64 " + reserve %d\n",
                    ch->local_amount, amount_sats, CHANNEL_RESERVE_SATS);
                return 0;
            }
            ch->local_amount -= amount_sats;
        } else { /* PTLC_RECEIVED */
            if (ch->remote_amount < amount_sats + CHANNEL_RESERVE_SATS) {
                fprintf(stderr,
                    "channel_add_ptlc: refused RECEIVED — remote %" PRIu64
                    " < amount %" PRIu64 " + reserve %d\n",
                    ch->remote_amount, amount_sats, CHANNEL_RESERVE_SATS);
                return 0;
            }
            ch->remote_amount -= amount_sats;
        }
    }
    /* Per-PTLC commit fee — same 43 vB shape as HTLCs. */
    uint64_t per_ptlc_fee = (ch->fee_rate_sat_per_kvb * 43 + 999) / 1000;
    uint64_t *funder_bal = ch->funder_is_local ? &ch->local_amount : &ch->remote_amount;
    if (amount_sats > 0 && *funder_bal < per_ptlc_fee) {
        /* Rollback amount deduction. */
        if (dir == PTLC_OFFERED) ch->local_amount += amount_sats;
        else ch->remote_amount += amount_sats;
        fprintf(stderr,
            "channel_add_ptlc: refused — funder_bal %" PRIu64
            " < per_ptlc_fee %" PRIu64 "\n",
            *funder_bal, per_ptlc_fee);
        return 0;
    }
    if (amount_sats > 0) *funder_bal -= per_ptlc_fee;

    /* Grow array if needed */
    if (ch->n_ptlcs >= ch->ptlcs_cap) {
        size_t new_cap = ch->ptlcs_cap ? ch->ptlcs_cap * 2 : PTLC_INIT_CAP;
        ptlc_t *new_arr = (ptlc_t *)realloc(ch->ptlcs, new_cap * sizeof(ptlc_t));
        if (!new_arr) {
            /* Rollback. */
            if (amount_sats > 0) {
                if (dir == PTLC_OFFERED) ch->local_amount += amount_sats;
                else ch->remote_amount += amount_sats;
                *funder_bal += per_ptlc_fee;
            }
            return 0;
        }
        ch->ptlcs = new_arr;
        ch->ptlcs_cap = new_cap;
    }

    ptlc_t *p = &ch->ptlcs[ch->n_ptlcs];
    memset(p, 0, sizeof(*p));
    p->direction   = dir;
    p->state       = PTLC_STATE_ACTIVE;
    p->amount_sats = amount_sats;
    p->cltv_expiry = cltv_expiry;
    p->id          = ch->next_ptlc_id++;
    p->fee_at_add  = amount_sats > 0 ? per_ptlc_fee : 0;
    if (point) p->payment_point = *point;

    if (id_out) *id_out = p->id;
    ch->n_ptlcs++;
    return 1;
}

int channel_settle_ptlc(channel_t *ch, uint64_t ptlc_id,
                         const unsigned char adapted_sig64[64])
{
    if (!ch) return 0;
    for (size_t i = 0; i < ch->n_ptlcs; i++) {
        ptlc_t *p = &ch->ptlcs[i];
        if (p->id == ptlc_id && p->state == PTLC_STATE_ACTIVE) {
            /* #182: credit recipient + refund fee to funder. */
            if (p->amount_sats > 0) {
                if (p->direction == PTLC_OFFERED) {
                    /* Local offered → remote receives. */
                    ch->remote_amount += p->amount_sats;
                } else {
                    ch->local_amount += p->amount_sats;
                }
                uint64_t *funder_bal = ch->funder_is_local
                    ? &ch->local_amount : &ch->remote_amount;
                *funder_bal += p->fee_at_add;
            }
            if (adapted_sig64)
                memcpy(p->adapted_sig, adapted_sig64, 64);
            p->has_adapted_sig = (adapted_sig64 != NULL);
            p->state = PTLC_STATE_SETTLED;
            return 1;
        }
    }
    return 0;
}

int channel_fail_ptlc(channel_t *ch, uint64_t ptlc_id)
{
    if (!ch) return 0;
    for (size_t i = 0; i < ch->n_ptlcs; i++) {
        ptlc_t *p = &ch->ptlcs[i];
        if (p->id == ptlc_id && p->state == PTLC_STATE_ACTIVE) {
            /* #182: refund amount to original sender + fee to funder. */
            if (p->amount_sats > 0) {
                if (p->direction == PTLC_OFFERED) {
                    ch->local_amount += p->amount_sats;
                } else {
                    ch->remote_amount += p->amount_sats;
                }
                uint64_t *funder_bal = ch->funder_is_local
                    ? &ch->local_amount : &ch->remote_amount;
                *funder_bal += p->fee_at_add;
            }
            p->state = PTLC_STATE_FAILED;
            return 1;
        }
    }
    return 0;
}

/* ptlc_commit_dispatch: handle PTLC wire messages
 *
 * Type 0x4C (PTLC_PRESIG): type(2) + ptlc_id(8) + pre_sig(64) = 74 bytes min
 * Type 0x4D (PTLC_ADAPTED_SIG): type(2) + ptlc_id(8) + adapted_sig(64) = 74 bytes min
 * Type 0x4E (PTLC_COMPLETE): type(2) + ptlc_id(8) = 10 bytes min
 */
int ptlc_commit_dispatch(peer_mgr_t *mgr, int peer_idx,
                          channel_t *ch,
                          secp256k1_context *ctx,
                          const unsigned char *msg, size_t msg_len)
{
    (void)mgr; (void)peer_idx; (void)ctx;
    if (!msg || msg_len < 2) return -1;

    uint16_t msg_type = rd16_be(msg);

    switch (msg_type) {
    case 0x4C: { /* PTLC_PRESIG */
        if (msg_len < 74) return -1;
        if (!ch) return 0x4C;
        uint64_t ptlc_id = 0;
        for (int b = 0; b < 8; b++) ptlc_id = (ptlc_id << 8) | msg[2 + b];
        /* Find PTLC by id and store pre_sig */
        for (size_t i = 0; i < ch->n_ptlcs; i++) {
            if (ch->ptlcs[i].id == ptlc_id) {
                memcpy(ch->ptlcs[i].pre_sig, msg + 10, 64);
                ch->ptlcs[i].has_pre_sig = 1;
                break;
            }
        }
        /* If not found, add a new received PTLC */
        if (ch->n_ptlcs == 0) {
            uint64_t id_out = 0;
            channel_add_ptlc(ch, PTLC_RECEIVED, 0, NULL, 0, &id_out);
            if (ch->n_ptlcs > 0) {
                memcpy(ch->ptlcs[ch->n_ptlcs-1].pre_sig, msg + 10, 64);
                ch->ptlcs[ch->n_ptlcs-1].has_pre_sig = 1;
            }
        }
        return 0x4C;
    }
    case 0x4D: { /* PTLC_ADAPTED_SIG */
        if (msg_len < 74) return -1;
        if (!ch) return 0x4D;
        uint64_t ptlc_id = 0;
        for (int b = 0; b < 8; b++) ptlc_id = (ptlc_id << 8) | msg[2 + b];
        channel_settle_ptlc(ch, ptlc_id, msg + 10);
        return 0x4D;
    }
    case 0x4E: { /* PTLC_COMPLETE */
        if (msg_len < 10) return -1;
        if (!ch) return 0x4E;
        /* Mark PTLC acknowledged */
        uint64_t ptlc_id = 0;
        for (int b = 0; b < 8; b++) ptlc_id = (ptlc_id << 8) | msg[2 + b];
        /* Already settled — just acknowledge */
        return 0x4E;
    }
    default:
        return -1;
    }
}

/* === PTLC commitment round-trip message senders === */

static void wr16(unsigned char *b, uint16_t v) {
    b[0] = (unsigned char)(v >> 8);
    b[1] = (unsigned char)(v);
}

static void wr64(unsigned char *b, uint64_t v) {
    for (int i = 7; i >= 0; i--) { b[i] = (unsigned char)(v & 0xFF); v >>= 8; }
}

/* Send PTLC add (custom type 0x4B):
   type(2) + channel_id(32) + ptlc_id(8) + amount(8) + payment_point(33) + cltv(4) */
int ptlc_commit_send_add(peer_mgr_t *mgr, int peer_idx,
                           const unsigned char channel_id[32],
                           uint64_t ptlc_id, uint64_t amount_sats,
                           const unsigned char payment_point33[33],
                           uint32_t cltv_expiry)
{
    if (!mgr || !channel_id) return 0;
    unsigned char msg[2 + 32 + 8 + 8 + 33 + 4];
    wr16(msg, 0x4B);
    memcpy(msg + 2, channel_id, 32);
    wr64(msg + 34, ptlc_id);
    wr64(msg + 42, amount_sats);
    memcpy(msg + 50, payment_point33, 33);
    msg[83] = (unsigned char)(cltv_expiry >> 24);
    msg[84] = (unsigned char)(cltv_expiry >> 16);
    msg[85] = (unsigned char)(cltv_expiry >> 8);
    msg[86] = (unsigned char)(cltv_expiry);
    return peer_mgr_send(mgr, peer_idx, msg, sizeof(msg));
}

/* Send PTLC_PRESIG (type 0x4C): type(2) + ptlc_id(8) + pre_sig(64) = 74 */
int ptlc_commit_send_presig(peer_mgr_t *mgr, int peer_idx,
                              uint64_t ptlc_id,
                              const unsigned char pre_sig[64])
{
    if (!mgr || !pre_sig) return 0;
    unsigned char msg[74];
    wr16(msg, 0x4C);
    wr64(msg + 2, ptlc_id);
    memcpy(msg + 10, pre_sig, 64);
    return peer_mgr_send(mgr, peer_idx, msg, sizeof(msg));
}

/* Send PTLC_ADAPTED_SIG (type 0x4D): type(2) + ptlc_id(8) + adapted_sig(64) = 74 */
int ptlc_commit_send_adapted_sig(peer_mgr_t *mgr, int peer_idx,
                                   uint64_t ptlc_id,
                                   const unsigned char adapted_sig[64])
{
    if (!mgr || !adapted_sig) return 0;
    unsigned char msg[74];
    wr16(msg, 0x4D);
    wr64(msg + 2, ptlc_id);
    memcpy(msg + 10, adapted_sig, 64);
    return peer_mgr_send(mgr, peer_idx, msg, sizeof(msg));
}

/* Send PTLC_COMPLETE (type 0x4E): type(2) + ptlc_id(8) = 10 */
int ptlc_commit_send_complete(peer_mgr_t *mgr, int peer_idx,
                                uint64_t ptlc_id)
{
    if (!mgr) return 0;
    unsigned char msg[10];
    wr16(msg, 0x4E);
    wr64(msg + 2, ptlc_id);
    return peer_mgr_send(mgr, peer_idx, msg, sizeof(msg));
}

/* Full PTLC add + commitment round-trip:
   1. Add PTLC to channel
   2. Send PTLC add message
   3. Trigger commitment_signed (caller handles) */
int ptlc_commit_add_and_sign(peer_mgr_t *mgr, int peer_idx,
                               channel_t *ch, secp256k1_context *ctx,
                               const unsigned char channel_id[32],
                               uint64_t amount_sats,
                               const secp256k1_pubkey *payment_point,
                               uint32_t cltv_expiry,
                               uint64_t *ptlc_id_out)
{
    if (!ch || !payment_point || !channel_id) return 0;
    (void)ctx;

    uint64_t id;
    if (!channel_add_ptlc(ch, PTLC_OFFERED, amount_sats, payment_point,
                            cltv_expiry, &id))
        return 0;
    if (ptlc_id_out) *ptlc_id_out = id;

    /* Serialize payment_point for wire */
    if (mgr) {
        unsigned char pp33[33];
        size_t plen = 33;
        secp256k1_ec_pubkey_serialize(ctx, pp33, &plen, payment_point,
                                       SECP256K1_EC_COMPRESSED);
        ptlc_commit_send_add(mgr, peer_idx, channel_id, id, amount_sats,
                              pp33, cltv_expiry);
    }
    return 1;
}

/* Settle a PTLC with adapted signature + send PTLC_ADAPTED_SIG */
int ptlc_commit_settle_and_sign(peer_mgr_t *mgr, int peer_idx,
                                  channel_t *ch, secp256k1_context *ctx,
                                  uint64_t ptlc_id,
                                  const unsigned char adapted_sig64[64])
{
    (void)ctx;
    if (!ch || !adapted_sig64) return 0;
    if (!channel_settle_ptlc(ch, ptlc_id, adapted_sig64)) return 0;
    if (mgr)
        ptlc_commit_send_adapted_sig(mgr, peer_idx, ptlc_id, adapted_sig64);
    return 1;
}

/* Fail a PTLC */
int ptlc_commit_fail_and_sign(peer_mgr_t *mgr, int peer_idx,
                                channel_t *ch, secp256k1_context *ctx,
                                uint64_t ptlc_id)
{
    (void)ctx;
    if (!ch) return 0;
    if (!channel_fail_ptlc(ch, ptlc_id)) return 0;
    /* Send PTLC_COMPLETE as acknowledgment of failure */
    if (mgr)
        ptlc_commit_send_complete(mgr, peer_idx, ptlc_id);
    return 1;
}
