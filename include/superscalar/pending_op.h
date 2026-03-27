#ifndef SUPERSCALAR_PENDING_OP_H
#define SUPERSCALAR_PENDING_OP_H

#include "wire.h"
#include "musig.h"
#include "channel.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/*
 * Pending operation queue — async ceremony dispatch.
 *
 * Replaces all blocking wire_recv_timeout calls in the daemon loop.
 * Each ceremony registers what it's waiting for (client, message type,
 * callback). The daemon loop dispatches incoming messages to pending ops.
 * No function ever blocks waiting for a specific response.
 */

/* Forward declarations to avoid circular includes */
typedef struct lsp_channel_mgr lsp_channel_mgr_t;
typedef struct lsp lsp_t;

/* --- Pending operation types --- */
typedef enum {
    PENDING_NONE = 0,

    /* HTLC Add Ceremony (2-phase: sender RAA, then dest RAA) */
    PENDING_HTLC_ADD_SENDER_RAA,
    PENDING_HTLC_ADD_DEST_RAA,

    /* HTLC Fulfill Ceremony (2-phase: payee RAA, then sender RAA) */
    PENDING_FULFILL_PAYEE_RAA,
    PENDING_FULFILL_SENDER_RAA,

    /* Leaf Advance (single wait for PSIG) */
    PENDING_LEAF_ADVANCE_PSIG,

    /* Leaf Realloc (multi-step: nonces, then psigs) */
    PENDING_REALLOC_NONCE,
    PENDING_REALLOC_PSIG,

    /* Bridge Fulfill (single wait for RAA) */
    PENDING_BRIDGE_FULFILL_RAA,

    /* Rotation (per-client PTLC adapted sig) */
    PENDING_ROTATION_ADAPTED_SIG,
} pending_op_type_t;

/* --- Ceremony-specific state --- */

typedef struct {
    size_t sender_idx;
    size_t dest_idx;
    uint64_t htlc_id;
    uint64_t amount_msat;
    unsigned char payment_hash[32];
    uint32_t cltv_expiry;
    uint64_t old_local;
    uint64_t old_remote;
    htlc_t *old_htlcs;          /* heap-allocated snapshot, freed on completion */
    size_t old_n_htlcs;
    int phase;                   /* 0=sender_raa, 1=dest_raa */
} pending_htlc_add_state_t;

typedef struct {
    size_t client_idx;
    size_t sender_idx;
    unsigned char preimage[32];
    unsigned char payment_hash[32];
    uint64_t htlc_id;
    uint64_t sender_htlc_id;
    uint64_t old_local;
    uint64_t old_remote;
    htlc_t *old_htlcs;
    size_t old_n_htlcs;
    int phase;                   /* 0=payee_raa, 1=sender_raa */
} pending_fulfill_state_t;

typedef struct {
    int leaf_side;
    size_t node_idx;
    uint32_t client_participant;
    secp256k1_musig_secnonce lsp_secnonce;
    unsigned char lsp_seckey[32];
    int lsp_slot;
} pending_leaf_advance_state_t;

typedef struct {
    int leaf_side;
    size_t node_idx;
    uint32_t clients[2];
    uint64_t amounts[8];
    size_t n_amounts;
    secp256k1_musig_secnonce lsp_secnonce;
    unsigned char lsp_seckey[32];
    int lsp_slot;
    unsigned char all_pubnonces[3][66];
    int nonces_received;
    int psigs_received;
    int phase;                   /* 0=nonces, 1=psigs */
    int current_client;          /* which client we're waiting on (0 or 1) */
} pending_realloc_state_t;

typedef struct {
    size_t client_idx;
    uint64_t htlc_id;
    unsigned char payment_hash[32];
    uint64_t old_local;
    uint64_t old_remote;
    htlc_t *old_htlcs;
    size_t old_n_htlcs;
} pending_bridge_fulfill_state_t;

/* --- The pending operation --- */

#define MAX_PENDING_OPS 64

typedef struct pending_op {
    pending_op_type_t type;
    size_t client_idx;           /* which client we're waiting on */
    uint8_t expected_msg_type;   /* MSG_REVOKE_AND_ACK, etc. */
    time_t deadline;             /* 0 = no timeout */
    int drain_stray;             /* dispatch benign stray messages */

    union {
        pending_htlc_add_state_t       htlc_add;
        pending_fulfill_state_t        fulfill;
        pending_leaf_advance_state_t   leaf_advance;
        pending_realloc_state_t        realloc;
        pending_bridge_fulfill_state_t bridge_fulfill;
    } state;

    struct pending_op *next;     /* per-client linked list */
    int in_use;                  /* pool management */
} pending_op_t;

/* --- Pool API --- */

typedef struct {
    pending_op_t pool[MAX_PENDING_OPS];
    size_t count;                /* number of active ops */
} pending_op_pool_t;

void pending_op_pool_init(pending_op_pool_t *p);

/* Allocate a pending op from the pool. Returns NULL if full. */
pending_op_t *pending_op_alloc(pending_op_pool_t *p);

/* Free a pending op back to the pool. */
void pending_op_free(pending_op_pool_t *p, pending_op_t *op);

/* --- Per-client dispatch --- */

/* Insert op into a client's pending list. */
void pending_op_insert(pending_op_t **client_head, pending_op_t *op);

/* Remove op from a client's pending list. */
void pending_op_remove(pending_op_t **client_head, pending_op_t *op);

/* Find a pending op matching the given message type for a client.
   Returns NULL if no match. */
pending_op_t *pending_op_find_for_msg(pending_op_t *client_head,
                                       uint8_t msg_type);

/* Cancel and free all pending ops for a client (on disconnect). */
void pending_op_cancel_all(pending_op_pool_t *p, pending_op_t **client_head);

/* Check if a message is a benign stray that should be drained. */
int pending_op_is_stray(uint8_t msg_type);

/* Sweep all clients for timed-out ops. Calls on_timeout for each. */
void pending_op_timeout_sweep(pending_op_pool_t *p,
                               pending_op_t **client_heads,
                               size_t n_clients, time_t now);

#endif /* SUPERSCALAR_PENDING_OP_H */
