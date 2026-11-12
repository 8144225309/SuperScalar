#ifndef SUPERSCALAR_CLIENT_DIST_H
#define SUPERSCALAR_CLIENT_DIST_H

/* Client side of a factory's distribution transaction: the pre-signed
   nLockTime transaction that spends the funding output and pays the
   members at the factory's end date.  The client publishes it itself once
   the chain reaches its nLockTime and the funding output is still unspent,
   so it is paid without the LSP. */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <secp256k1.h>
#include "superscalar/chain_backend.h"
#include "superscalar/persist.h"

typedef struct {
    unsigned char *tx;          /* signed transaction (heap) */
    size_t tx_len;
    char txid_hex[65];          /* display order */
    uint32_t locktime;          /* nLockTime, a block height */
    char funding_txid_hex[65];  /* outpoint it spends, display order */
    uint32_t funding_vout;
    size_t n_outputs;
} client_dist_tx_t;

typedef enum {
    CLIENT_DIST_NONE = 0,       /* no distribution TX stored for the factory */
    CLIENT_DIST_INVALID,        /* the stored TX failed verification */
    CLIENT_DIST_NO_CHAIN,       /* the chain tip is unknown */
    CLIENT_DIST_NOT_YET,        /* the tip is below its nLockTime */
    CLIENT_DIST_BROADCAST,      /* sent to the node now */
    CLIENT_DIST_IN_MEMPOOL,     /* already in the mempool */
    CLIENT_DIST_REFUSED,        /* due, funding output unspent, node refused it */
    CLIENT_DIST_CONFIRMED,      /* on chain */
    CLIENT_DIST_FUNDING_SPENT,  /* the funding output is spent by another tx */
    CLIENT_DIST_FUNDING_UNKNOWN /* due, but the backend cannot tell whether the
                                   funding output is unspent: sent, settles nothing */
} client_dist_status_t;

/* Broadcast hook: chain->send_raw_tx when NULL. */
typedef int (*client_dist_send_fn)(chain_backend_t *chain, const char *tx_hex,
                                   char *txid_out);

/* Check a signed distribution TX against the factory it belongs to: one
   input spending exactly the funding outpoint, a height nLockTime, a final
   witness of one 64-byte signature that verifies (BIP-341 key path,
   SIGHASH_DEFAULT) against the funding output key.  The signature covers
   every output and the nLockTime, and can only exist if every member,
   this client included, signed this transaction.  On success fills *out
   (out->tx is a copy) and returns 1; otherwise writes the reason to err. */
int client_dist_verify(const secp256k1_context *ctx,
                       const unsigned char *tx, size_t tx_len,
                       const unsigned char *funding_txid32, uint32_t funding_vout,
                       uint64_t funding_amount,
                       const unsigned char *funding_spk, size_t funding_spk_len,
                       client_dist_tx_t *out, char *err, size_t errlen);

/* Read factory_id's distribution TX and factory from db and verify it.
   1 = loaded and verified, 0 = none stored, -1 = stored but not usable
   (reason in err). */
int client_dist_load(persist_t *db, secp256k1_context *ctx, uint32_t factory_id,
                     client_dist_tx_t *out, char *err, size_t errlen);

void client_dist_free(client_dist_tx_t *d);

/* One decision against the chain.  Never sends before the tip has reached
   d->locktime, and never once the funding output is known spent.  When the
   backend cannot tell (no is_outpoint_unspent, or an error) the TX is still
   sent, but the result is CLIENT_DIST_FUNDING_UNKNOWN, which settles
   nothing.  *tip_out / *confs_out, if given, receive the tip and the TX's
   confirmation count (-1 when unknown, e.g. when it is seen confirmed only
   through its unspent outputs). */
client_dist_status_t client_dist_step(chain_backend_t *chain,
                                      const client_dist_tx_t *d,
                                      client_dist_send_fn send, int *tip_out,
                                      int *confs_out);

/* 1 if the status makes the distribution TX this factory's exit, so the
   tree must not be published: in the mempool, confirmed, or due with the
   funding output known unspent (sent, or refused and sent again later). */
int client_dist_settles(client_dist_status_t s);

const char *client_dist_status_str(client_dist_status_t s);

/* Daemon watch: re-reads the stored TX (re-verifying it only when it
   changed), runs client_dist_step at most every interval_s seconds, and
   reports each change of status on out.  Returns the last status. */
typedef struct {
    client_dist_tx_t d;
    unsigned char *raw;         /* stored bytes last verified */
    size_t raw_len;
    int raw_state;              /* load result for raw: 1, 0 or -1 */
    int checked;                /* raw/raw_state are set */
    int loaded;                 /* 1 verified, -1 unusable, 0 none */
    client_dist_status_t last;
    int reported;               /* last has been reported */
    time_t last_check;
} client_dist_watch_t;

client_dist_status_t client_dist_watch(client_dist_watch_t *w, persist_t *db,
                                       secp256k1_context *ctx,
                                       chain_backend_t *chain,
                                       client_dist_send_fn send,
                                       unsigned interval_s, FILE *out);

void client_dist_watch_free(client_dist_watch_t *w);

/* Unilateral exit: before the factory tree is published, decide whether
   the distribution TX settles the factory instead.  Publishing the tree
   spends the funding output, after which the distribution TX can never
   confirm; once the TX is due it is the exit (after its nLockTime the
   tree's timeout paths are open as well).  Returns 1 when the
   distribution TX settles the factory (client_dist_settles): the caller
   must then publish nothing of the tree.  Returns 0 when the tree is the
   exit: TX not yet due, funding output spent or its state unknown, or no
   usable TX. */
int client_dist_force_close(persist_t *db, chain_backend_t *chain,
                            client_dist_send_fn send, FILE *out);

#endif /* SUPERSCALAR_CLIENT_DIST_H */
