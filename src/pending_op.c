#include "superscalar/pending_op.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Secure zero for secret key material */
extern void secure_zero_bytes(void *p, size_t n);
#define sz(p, n) do { volatile unsigned char *_v = (volatile unsigned char *)(p); size_t _n = (n); while (_n--) *_v++ = 0; } while(0)

void pending_op_pool_init(pending_op_pool_t *p) {
    memset(p, 0, sizeof(*p));
    for (int i = 0; i < MAX_PENDING_OPS; i++) {
        p->pool[i].in_use = 0;
        p->pool[i].type = PENDING_NONE;
        p->pool[i].next = NULL;
    }
    p->count = 0;
}

pending_op_t *pending_op_alloc(pending_op_pool_t *p) {
    if (!p) return NULL;
    for (int i = 0; i < MAX_PENDING_OPS; i++) {
        if (!p->pool[i].in_use) {
            memset(&p->pool[i], 0, sizeof(pending_op_t));
            p->pool[i].in_use = 1;
            p->count++;
            return &p->pool[i];
        }
    }
    fprintf(stderr, "pending_op: pool exhausted (%d/%d)\n",
            (int)p->count, MAX_PENDING_OPS);
    return NULL;
}

void pending_op_free(pending_op_pool_t *p, pending_op_t *op) {
    if (!p || !op) return;

    /* Zero secret key material in ceremony state */
    switch (op->type) {
    case PENDING_HTLC_ADD_SENDER_RAA:
    case PENDING_HTLC_ADD_DEST_RAA:
        if (op->state.htlc_add.old_htlcs) {
            free(op->state.htlc_add.old_htlcs);
            op->state.htlc_add.old_htlcs = NULL;
        }
        break;
    case PENDING_FULFILL_PAYEE_RAA:
    case PENDING_FULFILL_SENDER_RAA:
        if (op->state.fulfill.old_htlcs) {
            free(op->state.fulfill.old_htlcs);
            op->state.fulfill.old_htlcs = NULL;
        }
        break;
    case PENDING_LEAF_ADVANCE_PSIG:
        sz(op->state.leaf_advance.lsp_seckey, 32);
        break;
    case PENDING_REALLOC_NONCE:
    case PENDING_REALLOC_PSIG:
        sz(op->state.realloc.lsp_seckey, 32);
        break;
    default:
        break;
    }

    op->in_use = 0;
    op->type = PENDING_NONE;
    op->next = NULL;
    if (p->count > 0) p->count--;
}

void pending_op_insert(pending_op_t **client_head, pending_op_t *op) {
    if (!client_head || !op) return;
    op->next = *client_head;
    *client_head = op;
}

void pending_op_remove(pending_op_t **client_head, pending_op_t *op) {
    if (!client_head || !op) return;
    pending_op_t **pp = client_head;
    while (*pp) {
        if (*pp == op) {
            *pp = op->next;
            op->next = NULL;
            return;
        }
        pp = &(*pp)->next;
    }
}

pending_op_t *pending_op_find_for_msg(pending_op_t *client_head,
                                       uint8_t msg_type) {
    pending_op_t *op = client_head;
    while (op) {
        if (op->expected_msg_type == msg_type)
            return op;
        op = op->next;
    }
    return NULL;
}

void pending_op_cancel_all(pending_op_pool_t *p, pending_op_t **client_head) {
    if (!p || !client_head) return;
    while (*client_head) {
        pending_op_t *op = *client_head;
        *client_head = op->next;
        fprintf(stderr, "pending_op: cancelling type=%d for disconnected client\n",
                op->type);
        pending_op_free(p, op);
    }
}

int pending_op_is_stray(uint8_t msg_type) {
    switch (msg_type) {
    case MSG_REGISTER_INVOICE:
    case MSG_CLOSE_REQUEST:
    case MSG_LSPS_REQUEST:
    case MSG_QUEUE_POLL:
    case MSG_QUEUE_DONE:
        return 1;
    default:
        return 0;
    }
}

void pending_op_timeout_sweep(pending_op_pool_t *p,
                               pending_op_t **client_heads,
                               size_t n_clients, time_t now) {
    if (!p || !client_heads) return;
    for (size_t c = 0; c < n_clients; c++) {
        pending_op_t **pp = &client_heads[c];
        while (*pp) {
            if ((*pp)->deadline > 0 && now >= (*pp)->deadline) {
                pending_op_t *expired = *pp;
                *pp = expired->next;
                fprintf(stderr, "pending_op: timeout type=%d client=%zu\n",
                        expired->type, c);
                pending_op_free(p, expired);
                continue;
            }
            pp = &(*pp)->next;
        }
    }
}
