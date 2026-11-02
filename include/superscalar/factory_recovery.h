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
 * Per-pass outcome of factory_recovery_run.  Counts are over publishable TXs:
 * one per tree node, plus every Pseudo-Spilman chain entry (chain[0..N]).
 */
typedef struct {
    int n_tree_nodes;   /* tree_nodes rows loaded for the factory */
    int n_txs;          /* publishable TXs (tree nodes + PS chain entries) */
    int n_confirmed;
    int n_in_mempool;   /* already in the mempool before this pass */
    int n_broadcast;    /* accepted this pass (dry run: would broadcast) */
    int n_waiting;      /* parent unpublished, or a relative / absolute
                           timelock not yet reached: retry after more blocks */
    int n_failed;       /* needed but impossible: bytes missing, history
                           incomplete, nodes not loaded, or rejected although
                           every input and timelock was satisfied */
    int settled;        /* every leaf's current TX confirmed at safe depth */
    int dry_run;
    int first_fail_node;        /* -1 when not tied to one node */
    int first_fail_chain_pos;   /* -1 = plain tree TX */
    char first_fail_why[96];
} factory_recovery_result_t;

/*
 * Scan all non-closed factories on daemon startup (and after a reorg).
 *
 * This NEVER broadcasts: an active factory's tree must not be published just
 * because its funding confirmed.  It refreshes confirmations and marks a
 * factory 'closed' once every leaf's current TX is confirmed.  It is not a
 * rebroadcast path: Core re-mempools reorged-out transactions itself, and
 * persist_retry_pending_broadcasts / persist_service_queued_broadcasts retry
 * queued ones.  Publishing a tree is always an explicit factory_recovery_run.
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
 *                n_tree_nodes, n_txs, n_confirmed, n_leaf, n_leaf_confirmed,
 *                funding_confs}
 *
 * chain may be NULL (omits confirmation counts).
 * Caller must cJSON_Delete() the returned object.
 */
cJSON *factory_recovery_list(persist_t *p, chain_backend_t *chain);

/*
 * Run one force-close pass for one factory: publish every TX (tree nodes and
 * full PS chains, root down) whose inputs and timelocks allow it now.  Call
 * again after more blocks until res->settled; TXs waiting on a timelock are
 * not failures.
 *
 * Writes a human-readable summary to status_out (up to cap bytes).
 * Returns 1 when the pass had no failure (it may still be waiting), 0 when
 * anything needed could not be published: no DB / chain / factory, tree
 * nodes not all loaded, a node or chain entry without signed bytes, or a TX
 * rejected although everything it depends on was available.
 */
int factory_recovery_run(persist_t *p, chain_backend_t *chain,
                         uint32_t factory_id,
                         char *status_out, size_t cap);

/*
 * As factory_recovery_run, with a per-pass result.  dry_run = 1 reports what
 * a pass would broadcast (n_broadcast) without sending anything or marking
 * the factory closed.  res may be NULL.
 */
int factory_recovery_run_ex(persist_t *p, chain_backend_t *chain,
                            uint32_t factory_id, int dry_run,
                            factory_recovery_result_t *res,
                            char *status_out, size_t cap);

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
