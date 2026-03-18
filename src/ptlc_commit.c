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

/* Minimum capacity for PTLC array growth */
#define PTLC_INIT_CAP 8

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

    /* Grow array if needed */
    if (ch->n_ptlcs >= ch->ptlcs_cap) {
        size_t new_cap = ch->ptlcs_cap ? ch->ptlcs_cap * 2 : PTLC_INIT_CAP;
        ptlc_t *new_arr = (ptlc_t *)realloc(ch->ptlcs, new_cap * sizeof(ptlc_t));
        if (!new_arr) return 0;
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
        if (ch->ptlcs[i].id == ptlc_id) {
            if (adapted_sig64)
                memcpy(ch->ptlcs[i].adapted_sig, adapted_sig64, 64);
            ch->ptlcs[i].has_adapted_sig = (adapted_sig64 != NULL);
            ch->ptlcs[i].state = PTLC_STATE_SETTLED;
            return 1;
        }
    }
    return 0;
}

int channel_fail_ptlc(channel_t *ch, uint64_t ptlc_id)
{
    if (!ch) return 0;
    for (size_t i = 0; i < ch->n_ptlcs; i++) {
        if (ch->ptlcs[i].id == ptlc_id) {
            ch->ptlcs[i].state = PTLC_STATE_FAILED;
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
