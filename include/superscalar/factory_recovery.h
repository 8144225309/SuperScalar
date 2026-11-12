/*
 * factory_recovery.h — startup recovery scan and CLI recovery for DW factories
 *
 * Follows the CLN/LND pattern: on daemon start, reconcile DB state with
 * on-chain reality. For each non-closed factory:
 *   1. Check which tree nodes are confirmed on chain.
 *   2. Broadcast any nodes whose parent is confirmed but they are not yet.
 *   3. Mark factory 'closed' in DB once all leaf nodes confirm.
 *
 * Also exposes the same logic as JSON-RPC methods (listfactories /
 * recoverfactory) so an operator can trigger recovery manually without
 * restarting the daemon.
 *
 * References: CLN startup scan (lightningd/opening_control.c),
 *             LND (lnwallet/wallet.go publishTransaction),
 *             Bitcoin Core SCB (BIP 157/158 recovery flow).
 */

#ifndef SUPERSCALAR_FACTORY_RECOVERY_H
#define SUPERSCALAR_FACTORY_RECOVERY_H

#include "superscalar/persist.h"
#include "superscalar/chain_backend.h"
#include <cJSON.h>
#include <stdint.h>
#include <stddef.h>

/*
 * Scan all non-closed factories on daemon startup.
 *
 * Never broadcasts: an active factory's tree must not be published just
 * because its funding confirmed.  For each factory it refreshes the tree
 * nodes' confirmations and marks the factory 'closed' in the DB if all
 * leaf nodes are confirmed.  'closed' says the tree is on chain, not that
 * the channel outputs of its leaves have been spent.
 *
 * chain may be NULL — in that case the scan is a no-op (returns 0).
 * Returns number of factories examined.
 */
int factory_recovery_scan(persist_t *p, chain_backend_t *chain);

/*
 * Build a JSON array describing every factory in the DB and its
 * on-chain status.  Used by the 'listfactories' JSON-RPC method.
 *
 * Each element: {factory_id, funding_txid, funding_vout,
 *                funding_amount_sats, state, created_at,
 *                n_tree_nodes, n_confirmed, n_leaf, n_leaf_confirmed,
 *                funding_confs}
 * plus tree_error (string) when the persisted tree is incomplete.
 *
 * chain may be NULL (omits confirmation counts).
 * Caller must cJSON_Delete() the returned object.
 */
cJSON *factory_recovery_list(persist_t *p, chain_backend_t *chain);

/*
 * Outcome of one factory_recovery_run pass.  The counts are over the
 * transactions the run has to publish: the whole tree, or one exit path.
 */
typedef struct {
    int n_tree_nodes;       /* nodes in the persisted tree */
    int n_target;           /* transactions this run has to publish */
    int n_confirmed;
    int n_in_mempool;       /* includes the ones broadcast by this pass */
    int n_broadcast;        /* accepted by the node during this pass */
    int n_waiting;          /* parent not confirmed yet, or a relative
                               timelock still running: run again later */
    int n_rejected;         /* refused although the parent is buried deep
                               enough and any height lock has passed:
                               waiting will not cure it (fee below the
                               node's floor, input spent by another
                               transaction, policy) */
    int published;          /* 1 = every target is confirmed or in mempool */
    int leaf_node;          /* exit-path run: node index of the leaf, else -1 */
    int retained_leaf;      /* the leaf is a kept earlier version of that node */
    int first_unpublished;  /* lowest target node not yet published, or -1 */
    int reject_node;        /* first rejected node, or -1 */
    char reject_why[96];    /* why it was rejected */
} factory_recovery_result_t;

/* What recovery reads from a serialized transaction. */
typedef struct {
    char     txid[65];       /* display hex */
    char     prev_txid[65];  /* first input's outpoint, display hex */
    uint32_t prev_vout;
    uint32_t nsequence;      /* first input */
    uint32_t locktime;
    size_t   n_outputs;
} factory_recovery_tx_info_t;

/* Parse a serialized transaction (with or without witness).  Returns 1 on
   success. */
int factory_recovery_tx_info(const unsigned char *tx, size_t len,
                             factory_recovery_tx_info_t *out);

/*
 * Run one force-close pass for one factory: broadcast every target tree
 * node whose parent is confirmed.  Nodes become broadcastable level by
 * level as relative timelocks expire, so call it again after new blocks
 * until res->published.
 *
 * leaf_txid NULL publishes the whole tree.  Otherwise it is the txid
 * (display hex) of one tree node, and only the path from the root to that
 * node is published: a client's unilateral exit.  When the tree has moved
 * past that txid (an advance replaced the leaf), the copy the client kept
 * in client_funding_leaf is published in place of the current row; without
 * one the run is an error, because the current row spends the output the
 * client's commitment needs.  A node waiting on its relative or absolute
 * height lock counts as waiting; one refused for any other reason as
 * rejected, with the reason in res.
 *
 * The tree is loaded in full, whatever its size.  The pass is an error, and
 * nothing is reported as published, when the persisted tree is incomplete
 * (missing or non-contiguous nodes, a parent that is not in the tree), when
 * leaf_txid is not a node of it, or when a target node has no signed
 * transaction.  An exit path with such a hole broadcasts nothing.
 *
 * Writes a human-readable result string to status_out (up to cap bytes).
 * res may be NULL.  Returns 1 if the pass ran without error (res->published
 * says whether it is finished), 0 on error.
 */
int factory_recovery_run(persist_t *p, chain_backend_t *chain,
                         uint32_t factory_id, const char *leaf_txid,
                         factory_recovery_result_t *res,
                         char *status_out, size_t cap);

/*
 * Find the leaf a client exits through: the transaction its latest signed
 * commitment spends, or, without a readable commitment, the funding txid of
 * the channel rows of factory_id.  Writes it to txid_out (display hex).
 * Returns 1 if found, 0 if the DB names none, -1 if the channel rows name
 * several or on a DB error.
 */
int factory_recovery_client_leaf(persist_t *p, uint32_t factory_id,
                                 char txid_out[65]);

/*
 * Sweep unspent leaf outputs of a specific factory.
 *
 * Finds all confirmed leaf state TXs, parses their outputs, and for each
 * unspent output whose P2TR key matches the LSP's x-only pubkey attempts a
 * key-path Schnorr spend sending funds to dest_spk.
 *
 * Precision: only sweeps outputs where the LSP is the sole key-path signer.
 * MuSig2 (client+LSP) outputs are reported as "requires_client_key" without
 * attempting a broadcast.
 *
 * Parameters:
 *   ctx           — secp256k1 context (SIGN|VERIFY)
 *   lsp_seckey32  — LSP's 32-byte private key
 *   factory_id    — which factory to sweep
 *   dest_spk      — destination scriptPubKey (e.g. P2TR of LSP wallet)
 *   dest_spk_len  — length of dest_spk (34 for P2TR)
 *   fee_sats      — fee per sweep TX (flat)
 *   dry_run       — 1 = report only, 0 = broadcast
 *
 * Returns a JSON array of per-output result objects:
 *   {txid, vout, amount_sats, spk_hex, status}
 * where status is one of: "swept", "dry_run", "requires_client_key",
 *   "insufficient_funds", "broadcast_failed", "already_spent".
 * Caller must cJSON_Delete() the result.
 */
cJSON *factory_sweep_run(persist_t *p, chain_backend_t *chain,
                         secp256k1_context *ctx,
                         const unsigned char *lsp_seckey32,
                         uint32_t factory_id,
                         const unsigned char *dest_spk,
                         size_t dest_spk_len,
                         uint64_t fee_sats,
                         int dry_run);

#endif /* SUPERSCALAR_FACTORY_RECOVERY_H */
