#ifndef SUPERSCALAR_CHAN_UPDATE_OPS_H
#define SUPERSCALAR_CHAN_UPDATE_OPS_H

/* The commitment layer of the channel-update engine over channel_t.
 *
 * - Commitments are built by channel_build_commitment_at from the engine's
 *   state: each balance and HTLC rounded down to whole satoshis (the
 *   remainder goes to the commitment fee, BOLT 3), HTLC directions from the
 *   offerer, the anchor paid by the host's output.
 * - Signatures are MuSig2 over the funding output's key path.  Each
 *   connection has one signature index, shared by both sides: every
 *   partial signature, in either direction, uses both sides' nonces at the
 *   next index and moves it on by one.  Secret nonces stay in memory.
 * - A revoked peer commitment gets its penalty built from the exact
 *   transaction this side signed, and its tower row (old_commitments, with
 *   the signed penalty) written in the engine's transaction.
 * - A fulfil's claim (the preimage and the HTLC) is written in the
 *   engine's transaction before the preimage leaves.
 */

#include "chan_update.h"
#include "channel.h"
#include "musig.h"
#include "watchtower.h"

#define CU_NONCE_BATCH 64     /* nonces sent at a time */
#define CU_NONCE_LOW   16     /* top up below this many */

typedef struct {
    uint32_t base;            /* signature index of the first nonce */
    size_t   count;           /* 0 = slot empty */
    musig_nonce_pool_t pool;
} cu_own_nonces_t;

typedef struct {
    uint32_t base;
    size_t   count;
    unsigned char pub[CU_NONCE_BATCH][66];
} cu_peer_nonces_t;

typedef struct {
    channel_t *ch;            /* keys, basepoints, funding, delays, fee rates */
    cu_side_t side;
    uint32_t  channel_id;     /* tower rows */
    watchtower_t *wt;         /* optional: also watched in memory */
    uint32_t  next;           /* next signature index on this connection */
    uint32_t  own_end;        /* first index without an own nonce */
    uint32_t  peer_end;       /* first index without a peer nonce */
    cu_own_nonces_t  own[2];
    cu_peer_nonces_t peer[2];
} cu_chops_t;

extern const cu_ops_t CU_CHANNEL_OPS;

int cu_chops_init(cu_chops_t *o, channel_t *ch, cu_side_t side, uint32_t channel_id,
                  watchtower_t *wt);

/* A new connection: both index spaces restart at 0.  Fills this side's
   first public nonces (for MSG_CU_NONCES, first index 0). */
int cu_chops_connect(cu_chops_t *o, unsigned char pub[][66], size_t *n);

/* More own nonces, from the end of the last batch, when fewer than
   CU_NONCE_LOW unused remain.  Returns 1 with *n > 0 to send, 1 with
   *n = 0 when none is needed, 0 on error. */
int cu_chops_topup(cu_chops_t *o, uint32_t *first, unsigned char pub[][66], size_t *n);

/* The peer's public nonces for indices first .. first + n - 1; first must
   be the end of what the peer sent before. */
int cu_chops_peer_nonces(cu_chops_t *o, uint32_t first, const unsigned char pub[][66], size_t n);

/* ---- commitment 0, both ways (INV-21) ----
   Order: the host signs the member's C(0) (index 0); the member verifies
   its own C(0) (index 0), then signs the host's (index 1); the host
   verifies its own (index 1).  Each side then records the channel with
   cu_create (its own C(0) and signature, the txid of the peer's C(0) it
   signed).  Nothing is funded before both sides hold their own C(0). */
int cu_open_sign(cu_chops_t *o, const cu_state_t *initial, const secp256k1_pubkey *peer_p0,
                 unsigned char psig[32], uint32_t *idx, unsigned char peer_c0_txid[32]);
int cu_open_verify(cu_chops_t *o, const cu_state_t *initial, const unsigned char s0[32],
                   const unsigned char peer_psig[32], uint32_t idx,
                   unsigned char *tx, size_t *tx_len, unsigned char sig64[64]);

/* A commitment with its key-path witness, ready to broadcast. */
int cu_chops_finalize(const unsigned char *tx, size_t len, const unsigned char sig64[64],
                      tx_buf_t *out);

/* The fee of a commitment of st, msat (the cu_ops_t member, exposed for
   cu_state_t set-up). */
uint64_t cu_chops_commit_fee_msat(void *ctx, const cu_state_t *st);

#endif /* SUPERSCALAR_CHAN_UPDATE_OPS_H */
