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
 * For each factory whose funding TX is confirmed:
 *   - Find tree nodes with signed_tx_hex but not yet confirmed on chain.
 *   - Broadcast any node whose parent is confirmed (topological order).
 *   - Mark factory 'closed' in DB if all leaf nodes are confirmed.
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
 *
 * chain may be NULL (omits confirmation counts).
 * Caller must cJSON_Delete() the returned object.
 */
cJSON *factory_recovery_list(persist_t *p, chain_backend_t *chain);

/*
 * Run recovery for one factory: broadcast broadcastable tree nodes.
 * Writes a human-readable result string to status_out (up to cap bytes).
 * Returns 1 if any broadcast succeeded, 0 otherwise.
 */
int factory_recovery_run(persist_t *p, chain_backend_t *chain,
                         uint32_t factory_id,
                         char *status_out, size_t cap);

#endif /* SUPERSCALAR_FACTORY_RECOVERY_H */
