#ifndef SUPERSCALAR_CHAN_UPDATE_H
#define SUPERSCALAR_CHAN_UPDATE_H

/* Channel-update engine.
 *
 * One state machine, used by the host and by the member, that moves a
 * channel from commitment number n to n + 1 as docs/security/
 * channel-update-protocol.md specifies.  The host opens every round
 * (protocol section "Who opens a round"): the member offers updates
 * (cu_offer), the host either carries them in its next round or refuses
 * them (cu_refuse), and a member message that would open a round is
 * refused.
 *
 *   proposer X (host)                       responder Y (member)
 *   SENT(n+1)  [write]  -- updates, commitment_signed(n+1) -->
 *                                           HOLDS(n+1) [write]
 *              <-- commitment_signed(n+1), revoke_and_ack(n) --
 *   verify s_Y(n), arm the penalty for C_Y(n)
 *   HOLDS(n+1) [write]  -- revoke_and_ack(n) -->
 *   DONE       [write]                      verify s_X(n), arm the penalty
 *                                           DONE [write]
 *
 * Every [write] is one SQLite transaction, committed before any message
 * that depends on it is placed in the outbox.  The engine performs no I/O:
 * the caller sends the outbox after the call returns, so a signature or a
 * secret can only leave after the state it depends on is durable.  No call
 * waits for a peer, so no transaction is ever open across a peer wait; a
 * call made while the database is inside a transaction is refused.
 *
 * Balances and HTLCs are kept in absolute terms (host / member), so both
 * sides hold byte-identical states for every number.  Amounts are msat
 * everywhere; a retransmission resends the stored update, never a
 * re-derived one.
 *
 * Messages that arrive while a round is open are queued in arrival order
 * and handled when the round ends; a full queue is an error that fails the
 * connection, never a silent drop.
 *
 * Reconnect reconciliation is the pure function cu_reconcile() of this
 * side's durable state and the peer's channel_reestablish claim.
 */

#include <stdint.h>
#include <stddef.h>
#include <secp256k1.h>
#include "persist.h"

#define CU_MAX_UPDATES   32     /* updates in one round */
#define CU_HTLC_CAP      128    /* HTLCs a state can hold (cfg.max_htlcs <= this) */
#define CU_QUEUE_CAP     64     /* per-channel and per-peer queue bound */
#define CU_OUTBOX_CAP    (2 * CU_MAX_UPDATES + 8)
#define CU_EVENT_CAP     (2 * CU_MAX_UPDATES + 8)
#define CU_TX_MAX        65536  /* serialized commitment transaction bound */
#define CU_VIEW_SECRETS  8

typedef enum { CU_HOST = 0, CU_MEMBER = 1 } cu_side_t;
#define CU_OTHER(s) ((cu_side_t)(1 - (int)(s)))

/* Return codes. */
enum {
    CU_OK            = 0,
    CU_ERR_ARG       = -1,   /* bad call */
    CU_ERR_BUSY      = -2,   /* a round is open; propose again when idle */
    CU_ERR_INVALID   = -3,   /* update fails a check (sender, amount, CLTV, cap, conservation) */
    CU_ERR_KIND      = -4,   /* update kind not available in this release */
    CU_ERR_PROTOCOL  = -5,   /* message out of order or inconsistent */
    CU_ERR_VERIFY    = -6,   /* signature, secret or digest failed verification */
    CU_ERR_DB        = -7,   /* durable write failed; nothing was released */
    CU_ERR_QUEUE_FULL= -8,   /* queue bound reached: fail the connection */
    CU_ERR_HALTED    = -9,   /* channel failed or data loss detected */
    CU_ERR_CRASHED   = -10,  /* test hook stopped the call (simulated crash) */
    CU_ERR_ROLE      = -11,  /* only the host opens a round; the member offers */
};

/* Update kinds.  1.0 has the first four; the rest are refused with
   CU_ERR_KIND and no state change. */
typedef enum {
    CU_UPD_ADD       = 1,
    CU_UPD_FULFILL   = 2,
    CU_UPD_FAIL      = 3,
    CU_UPD_FEE       = 4,
    CU_UPD_REANCHOR  = 16,
    CU_UPD_TREE_MOVE = 17,
    CU_UPD_REALLOC   = 18,
    CU_UPD_SPLICE    = 19,
    CU_UPD_JIT_OPEN  = 20,
} cu_kind_t;

typedef struct {
    uint8_t  kind;              /* cu_kind_t */
    uint8_t  sender;            /* cu_side_t: who asked for it.  The member's are its own
                                   durable offers; a message never makes one up. */
    uint64_t id;                /* HTLC id (add: the sender's next id) */
    uint64_t amount_msat;       /* add */
    uint8_t  payment_hash[32];  /* add */
    uint8_t  preimage[32];      /* fulfil */
    uint32_t cltv_expiry;       /* add */
    uint32_t reason;            /* fail */
    uint64_t feerate_per_kvb;   /* fee */
} cu_update_t;

typedef struct {
    uint64_t id;
    uint8_t  offerer;           /* cu_side_t that sent the add (pays) */
    uint64_t amount_msat;
    uint8_t  payment_hash[32];
    uint32_t cltv_expiry;
} cu_htlc_t;

/* The state one commitment number describes.  Identical on both sides. */
typedef struct {
    uint64_t host_msat;
    uint64_t member_msat;
    uint64_t feerate_per_kvb;
    uint64_t fee_msat;            /* commitment fee, paid by the host */
    uint64_t next_htlc_id[2];     /* per offerer */
    size_t   n_htlcs;
    cu_htlc_t htlcs[CU_HTLC_CAP];
} cu_state_t;

/* Channel terms.  The funding outpoint and capacity are also durable and
   checked on load. */
typedef struct {
    cu_side_t side;
    uint32_t  channel_id;
    uint8_t   funding_txid[32];
    uint32_t  funding_vout;
    uint64_t  capacity_msat;
    uint64_t  host_reserve_msat;  /* INV-34: the member imposes it on the host */
    uint32_t  max_htlcs;          /* INV-33: from the relay size limit */
    uint64_t  fee_min_per_kvb;    /* update_fee bounds (the proposal's) */
    uint64_t  fee_max_per_kvb;
    uint32_t  cltv_deadline;      /* INV-32: expiry < T0 - R */
    uint32_t  min_cltv_headroom;  /* INV-32: expiry - tip >= this */
    uint32_t  onchain_margin;     /* report "go on chain" this many blocks before expiry */
} cu_config_t;

/* Operations the engine needs from the commitment layer.  The engine owns
   the protocol (order, persistence, checks); these own the transactions and
   the MuSig2 signing.  Partial signatures use nonces from the per-connection
   pool, which is never written to disk. */
typedef struct {
    /* Build holder's unsigned commitment at number n for state st, keyed by
       holder's per-commitment point.  Deterministic: same inputs, same
       bytes. */
    int (*build_commitment)(void *ctx, cu_side_t holder, uint64_t n,
                            const cu_state_t *st,
                            const secp256k1_pubkey *holder_point,
                            unsigned char *tx, size_t *tx_len,
                            unsigned char txid[32]);
    /* Commitment fee (msat) for st at st->feerate_per_kvb. */
    uint64_t (*commit_fee_msat)(void *ctx, const cu_state_t *st);
    /* This side's partial signature on the peer's commitment; draws the
       next secret nonce of the pool and names the peer's nonce index. */
    int (*sign_peer)(void *ctx, uint64_t n, const unsigned char *tx, size_t tx_len,
                     unsigned char psig[32], uint32_t *nonce_index);
    /* Verify the peer's partial signature on this side's commitment and
       aggregate the full signature. */
    int (*verify_aggregate)(void *ctx, uint64_t n, const unsigned char *tx, size_t tx_len,
                            const unsigned char psig[32], uint32_t nonce_index,
                            unsigned char sig64[64]);
    /* Build the penalty for the peer's revoked commitment n (tx) and
       register it with the tower.  Runs inside the engine's transaction and
       writes through db; a failure aborts the transaction. */
    int (*arm_penalty)(void *ctx, persist_t *db, uint64_t n,
                       const unsigned char secret[32],
                       const unsigned char *tx, size_t tx_len);
    /* Arm the on-chain success claim for h before its preimage leaves
       (INV-30).  Runs inside the engine's transaction. */
    int (*arm_claim)(void *ctx, persist_t *db, uint64_t n, const cu_htlc_t *h,
                     const unsigned char preimage[32]);
    /* A new connection: discard both nonce pools (indices restart at 0). */
    void (*reset_nonces)(void *ctx);
    /* A peer signature that will not be aggregated (a simultaneous
       proposal that lost): its nonce index is used up all the same, so the
       pools stay in step.  Optional. */
    void (*skip_signature)(void *ctx, uint32_t nonce_index);
} cu_ops_t;

typedef enum { CU_PHASE_IDLE = 0, CU_PHASE_SENT = 1, CU_PHASE_HOLDS = 2 } cu_phase_t;
typedef enum { CU_PROPOSER = 0, CU_RESPONDER = 1 } cu_round_role_t;
typedef enum {
    CU_HALT_NONE      = 0,
    CU_HALT_FAILED    = 1,   /* peer claimed a commitment this side never signed, or a bad claim */
    CU_HALT_DATA_LOSS = 2,   /* this side is behind its own revocations: never broadcast */
    CU_HALT_PEER_LOST = 3,   /* the peer lost data: exit on this side's latest commitment */
} cu_halt_t;

/* channel_reestablish (protocol section 6.1). */
typedef struct {
    uint64_t next_commitment_number;   /* newest held fully signed + 1 */
    uint64_t next_revocation_number;   /* newest own revoked + 1 */
    uint8_t  last_remote_secret[32];   /* newest secret received from the peer, or zeros */
    uint8_t  my_current_point[33];     /* point of the newest held commitment */
    uint8_t  sent_digest[32];          /* digest of a round in SENT, or zeros */
} cu_reestablish_t;

typedef enum {
    CU_MSG_ADD = 1, CU_MSG_FULFILL, CU_MSG_FAIL, CU_MSG_FEE,
    CU_MSG_COMMIT_SIG, CU_MSG_REVOKE, CU_MSG_REESTABLISH,
    CU_MSG_REFUSE, CU_MSG_ERROR,
} cu_msg_type_t;

typedef struct {
    uint8_t  type;                 /* cu_msg_type_t */
    uint32_t channel_id;
    cu_update_t upd;               /* ADD/FULFILL/FAIL/FEE; REFUSE names upd.kind + upd.id */
    uint64_t n;                    /* COMMIT_SIG: the new number; REVOKE: n_revoked */
    uint8_t  psig[32];
    uint32_t nonce_index;
    uint8_t  digest[32];
    uint8_t  secret[32];           /* REVOKE */
    uint8_t  next_point[33];       /* REVOKE: P(n_revoked + 2) */
    cu_reestablish_t re;           /* REESTABLISH */
    int32_t  code;                 /* ERROR / REFUSE reason */
} cu_msg_t;

typedef enum {
    CU_EV_UPDATE_RECEIVED = 1,  /* peer offered an update (may be refused until signed) */
    CU_EV_HTLC_ADDED,           /* add durable at this side's HOLDS */
    CU_EV_HTLC_FULFILLED,       /* removal durable at HOLDS; preimage known */
    CU_EV_HTLC_FAILED,          /* removal durable at DONE (upstream fail may follow) */
    CU_EV_FEE_CHANGED,
    CU_EV_ROUND_DONE,           /* n = new number */
    CU_EV_PROPOSAL_DROPPED,     /* this side's round lost a simultaneous proposal; upd to re-propose */
    CU_EV_REFUSED,              /* peer refused an offered update (upd) */
    CU_EV_GO_ONCHAIN,           /* htlc near expiry: resolve on chain; never a local removal */
    CU_EV_PEER_ERROR,
    CU_EV_HALTED,               /* code = cu_halt_t */
} cu_event_type_t;

typedef struct {
    uint8_t   type;
    uint64_t  n;
    cu_htlc_t htlc;
    uint8_t   preimage[32];
    cu_update_t upd;
    int32_t   code;
} cu_event_t;

/* Durable per-channel record (table cu_channel). */
typedef struct {
    uint8_t  phase;          /* cu_phase_t */
    uint8_t  round_role;     /* cu_round_role_t */
    uint8_t  halted;         /* cu_halt_t */
    uint64_t held;           /* newest own commitment held fully signed */
    int64_t  revoked;        /* newest own commitment revoked, -1 none */
    int64_t  peer_revoked;   /* newest peer secret held, -1 none */
    size_t   n_round;
    cu_update_t round[CU_MAX_UPDATES];
    uint8_t  digest[32];
} cu_rec_t;

/* Simulated-crash points (tests).  BEFORE_* fire with the transaction open
   (the engine rolls it back); AFTER_* fire after COMMIT and before any
   dependent message reaches the outbox. */
typedef enum {
    CU_CP_SENT_BEFORE = 1, CU_CP_SENT_AFTER,
    CU_CP_RESP_HOLDS_BEFORE, CU_CP_RESP_HOLDS_AFTER,
    CU_CP_PROP_HOLDS_BEFORE, CU_CP_PROP_HOLDS_AFTER,
    CU_CP_PROP_DONE_BEFORE,  CU_CP_PROP_DONE_AFTER,
    CU_CP_RESP_DONE_BEFORE,  CU_CP_RESP_DONE_AFTER,
    CU_CP_OFFER_BEFORE,      CU_CP_OFFER_AFTER,
    CU_CP_COUNT
} cu_crash_point_t;

/* Hook result: 0 continue, 1 crash, 2 fail the write. */
typedef int (*cu_crash_hook_t)(void *ctx, int point);

typedef struct {
    /* fixed at load */
    cu_config_t cfg;
    const cu_ops_t *ops;
    void *ops_ctx;
    persist_t *db;
    secp256k1_context *secp;

    /* durable mirror */
    cu_rec_t rec;
    cu_state_t st;                 /* state of commitment rec.held */

    /* memory only (per connection) */
    uint32_t tip;
    cu_update_t peer_updates[CU_MAX_UPDATES];   /* host: member requests; member: the round */
    size_t n_peer_updates;
    cu_update_t offered[CU_MAX_UPDATES];        /* member: its durable offers, in order */
    size_t n_offered;
    int have_peer_cs;                            /* proposer: responder's signature verified */
    unsigned char peer_cs_sig[64];
    cu_msg_t deferred[CU_QUEUE_CAP];             /* arrived mid-round, in order */
    size_t n_deferred;

    /* results of the last calls, for the caller */
    cu_msg_t out[CU_OUTBOX_CAP];
    size_t n_out;
    cu_event_t ev[CU_EVENT_CAP];
    size_t n_ev;

    cu_crash_hook_t crash_hook;
    void *crash_ctx;
} cu_chan_t;

/* ---- lifecycle ---- */

/* Record commitment 0 of a new channel: initial state, this side's
   per-commitment secrets s(0) and s(1), the peer's points P(0) and P(1),
   this side's fully signed C(0), and the txid of the peer's C(0) this side
   signed.  One transaction. */
int cu_create(persist_t *db, const cu_config_t *cfg, const cu_state_t *initial,
              const unsigned char my_s0[32], const unsigned char my_s1[32],
              const secp256k1_pubkey *peer_p0, const secp256k1_pubkey *peer_p1,
              const unsigned char *my_c0_tx, size_t my_c0_len,
              const unsigned char my_c0_sig[64],
              const unsigned char peer_c0_txid[32]);

/* Load a channel from its durable record.  The funding outpoint and
   capacity in cfg must match the record. */
int cu_load(cu_chan_t *c, persist_t *db, const cu_config_t *cfg,
            const cu_ops_t *ops, void *ops_ctx, secp256k1_context *secp);

/* ---- events ---- */

/* Host: open a round: SENT, then the updates and commitment_signed in the
   outbox.  An update with sender CU_MEMBER must be one of the member's
   pending requests (cu_requests), byte for byte; any other is the host's
   own.  The member gets CU_ERR_ROLE. */
int cu_propose(cu_chan_t *c, const cu_update_t *u, size_t n);

/* Member: ask the host for updates (add = pay, fulfil, fail).  The offers
   are durable before they leave, with the success claim of any fulfil
   (INV-30); they stay until a round carries them or the host refuses
   them, and are offered again after a reconnect.  The host gets
   CU_ERR_ROLE. */
int cu_offer(cu_chan_t *c, const cu_update_t *u, size_t n);

/* Host: the member's pending requests, oldest first. */
const cu_update_t *cu_requests(const cu_chan_t *c, size_t *n);

/* Host: refuse a pending member request, with a reason. */
int cu_refuse(cu_chan_t *c, uint8_t kind, uint64_t id, int32_t reason);

/* One inbound message.  Mid-round messages are queued, not dropped. */
int cu_on_message(cu_chan_t *c, const cu_msg_t *m);

/* Connection lost: memory-only state of the connection is discarded. */
void cu_on_disconnect(cu_chan_t *c);

/* This side's channel_reestablish. */
int cu_reestablish_msg(cu_chan_t *c, cu_msg_t *out);

/* Chain tip.  Reports HTLCs that must go on chain; never removes one. */
int cu_on_block(cu_chan_t *c, uint32_t height);

/* This side's latest commitment, for a unilateral exit.  Refused when its
   secret is released (INV-23) or the channel detected its own data loss. */
int cu_latest_commitment(cu_chan_t *c, unsigned char *tx, size_t *tx_len,
                         unsigned char sig64[64], uint64_t *n_out);

static inline void cu_clear_outputs(cu_chan_t *c) { c->n_out = 0; c->n_ev = 0; }

/* ---- reconciliation (pure) ---- */

enum {
    CU_ACT_NONE         = 0,
    CU_ACT_RESEND_RAA   = 1u << 0,  /* revoke_and_ack(revoked) with the same secret */
    CU_ACT_RESEND_ROUND = 1u << 1,  /* proposer: the SENT updates + commitment_signed */
    CU_ACT_RESEND_CS    = 1u << 2,  /* responder: commitment_signed(held) */
    CU_ACT_WAIT         = 1u << 3,  /* the peer resends */
    CU_ACT_DROP_SENT    = 1u << 4,  /* member yields a simultaneous proposal */
    CU_ACT_MARK_DONE    = 1u << 5,
    CU_ACT_FAIL         = 1u << 6,  /* fail the channel, alert, never adopt the claim */
    CU_ACT_DATA_LOSS    = 1u << 7,  /* never broadcast; ask the peer to close */
    CU_ACT_PEER_LOST    = 1u << 8,  /* tell the peer; exit on own latest commitment */
};

typedef struct {
    cu_side_t side;
    uint8_t   phase, round_role;
    uint64_t  held;
    int64_t   revoked;
    int64_t   peer_revoked;
    uint64_t  signed_max;            /* newest peer commitment number this side signed */
    uint8_t   digest[32];            /* this side's open round */
    size_t    n_secrets;             /* own secrets revoked-3 .. revoked+4, to name last_remote_secret */
    int64_t   secret_num[CU_VIEW_SECRETS];
    uint8_t   secret[CU_VIEW_SECRETS][32];
} cu_view_t;

typedef struct {
    int      row;                    /* row of the protocol's table 6.2 (0 = invalid claim) */
    unsigned actions;                /* CU_ACT_* */
} cu_reconcile_t;

/* Pure: the action table of protocol section 6.2. */
cu_reconcile_t cu_reconcile(const cu_view_t *mine, const cu_reestablish_t *peer);

/* Fill a view from the durable state. */
int cu_view(cu_chan_t *c, cu_view_t *v);

/* ---- per-peer queue ---- */

typedef struct {
    cu_msg_t q[CU_QUEUE_CAP];
    size_t head, len;
} cu_queue_t;

/* 0 when full: the caller fails the connection. */
int cu_queue_push(cu_queue_t *q, const cu_msg_t *m);
/* Hand every queued message to its channel, in order. */
int cu_queue_drain(cu_queue_t *q, cu_chan_t **chans, size_t n_chans);

/* ---- helpers ---- */

/* SHA256 over the serialized update list (protocol section 3). */
void cu_digest(const cu_update_t *u, size_t n, unsigned char out[32]);

/* Apply updates in a round opened by `proposer` to in; each update acts for
   its sender.  The member opens nothing, so its updates appear either in
   its own offers (proposer CU_MEMBER) or in a host round.  Checks
   INV-27/28/32/33/34. */
int cu_apply(const cu_config_t *cfg, const cu_ops_t *ops, void *ops_ctx,
             uint32_t tip, cu_side_t proposer, const cu_state_t *in,
             const cu_update_t *u, size_t n, cu_state_t *out);

/* Checks the durable record of one channel (protocol section 11): every
   stored state conserves value; the held number is above every released
   own secret; the held commitment is signed; every revoked peer number has
   its secret.  Returns 1 if all hold, else 0 with why filled. */
int cu_check_invariants(persist_t *db, uint32_t channel_id, uint64_t capacity_msat,
                        char *why, size_t why_len);

#endif /* SUPERSCALAR_CHAN_UPDATE_H */
