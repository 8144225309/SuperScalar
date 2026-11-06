#ifndef SUPERSCALAR_CPFP_H
#define SUPERSCALAR_CPFP_H

/*
 * Broadcasting pre-signed transactions with CPFP through their P2A anchor.
 *
 * A pre-signed transaction (factory tree node, distribution TX, commitment)
 * carries a fee fixed when it was signed.  When that fee is below what the
 * node's mempool accepts, or below the rate needed to confirm in time, the
 * transaction is submitted as a 1-parent-1-child package with a child that
 * spends its keyless P2A anchor and pays for both (Bitcoin Core
 * `submitpackage`).  A TRUC (nVersion 3) parent may sit below the minimum
 * relay feerate inside such a package; a non-TRUC parent may not.
 *
 * The child is funded from a wallet_source_t (wallet UTXO + change).  With no
 * wallet, or no spendable UTXO, the child spends the anchor alone and pays its
 * 240 sats as fee into an OP_RETURN output.
 */

#include <stdint.h>
#include <stddef.h>
#include "superscalar/tx_builder.h"
#include "superscalar/wallet_source.h"
#include "superscalar/regtest.h"
#include "superscalar/chain_backend.h"
#include "superscalar/fee_estimator.h"

#define CPFP_MAX_INPUTS 64

/* Parsed view of a serialized transaction. */
typedef struct {
    uint32_t version;
    size_t n_inputs;
    unsigned char in_txid[CPFP_MAX_INPUTS][32];   /* internal byte order */
    uint32_t in_vout[CPFP_MAX_INPUTS];
    size_t n_outputs;
    uint64_t out_total;
    int anchor_vout;                /* first P2A output, -1 if none */
    uint64_t anchor_amount;
    size_t vsize;
    unsigned char txid[32];         /* internal byte order */
    char txid_hex[65];              /* display order */
} cpfp_tx_info_t;

/* Parse tx (segwit or legacy serialization).  Returns 1 on success. */
int cpfp_parse_tx(const unsigned char *tx, size_t len, cpfp_tx_info_t *out);

/* Fee a child of child_vsize must pay so the package
   (parent_fee + child_fee) / (parent_vsize + child_vsize) reaches pkg_rate
   (sat/kvB).  Never less than the child's own fee at pkg_rate. */
uint64_t cpfp_child_fee(uint64_t parent_fee, size_t parent_vsize,
                        size_t child_vsize, uint64_t pkg_rate);

/* Virtual size of the anchor-only child (P2A input, one OP_RETURN output). */
#define CPFP_ANCHOR_ONLY_CHILD_VSIZE 65

/* Build and sign a child spending parent's P2A anchor.  nVersion follows the
   parent (TRUC children for TRUC parents).  With a wallet, adds one confirmed
   wallet UTXO and a change output so the package reaches pkg_rate; without
   one (or when the wallet has no UTXO) builds the anchor-only child.
   parent_fee: fee the parent pays.  *child_fee_out (optional): fee paid by the
   child; *used_wallet_out (optional): 1 if a wallet UTXO was spent.
   Returns 1 on success. */
int cpfp_build_anchor_child(wallet_source_t *wallet,
                            const cpfp_tx_info_t *parent,
                            uint64_t parent_fee, uint64_t pkg_rate,
                            tx_buf_t *child_out, uint64_t *child_fee_out,
                            int *used_wallet_out);

/* Outcome of cpfp_send_presigned.  Every value but CPFP_FAILED means the
   parent is in the mempool or a block. */
typedef enum {
    CPFP_FAILED       = 0,   /* nothing new in the mempool */
    CPFP_SENT_ALONE   = 1,   /* parent relayed on its own */
    CPFP_SENT_PACKAGE = 2,   /* parent + anchor child accepted as a package */
    CPFP_KNOWN        = 3,   /* parent already in the mempool or a block */
    CPFP_PARENT_ONLY  = 4,   /* submitpackage accepted the parent on its own and
                                rejected the child: the parent is in the
                                mempool, below the target rate */
    CPFP_BUMPED       = 5,   /* the parent was in the mempool below the target
                                rate; a new child on its anchor now brings it
                                there */
    CPFP_BUMP_FAILED  = 6,   /* the parent is in the mempool below the target
                                rate and stays there: no child could be built
                                within the budget, or the node refused it */
} cpfp_result_t;

/* Most a CPFP child pays when the caller sets no budget, in sats. */
#define CPFP_DEFAULT_MAX_CHILD_FEE 50000

/* Broadcast a pre-signed tx through bitcoind RPC (rt), or raise it if it is
   already in the mempool.  The rate it must reach is the node's mempool
   minimum, the minimum relay feerate and target_rate (sat/kvB, 0 = none),
   whichever is highest.
   - Not in the mempool: it goes alone when it pays that rate; otherwise, if
     it has a P2A anchor, as a package with a CPFP child funded from wallet
     (NULL = anchor-only child).
   - In the mempool: if neither its own ancestor feerate nor that of any
     child of it reaches the rate, a child on its anchor is sent that brings
     the package to the rate plus 10%, replacing the anchor's current spender
     (RBF; for a TRUC parent its only child, by sibling eviction) and paying
     for it and all its descendants: a child we sent earlier (its coin is
     the wallet's, see wallet_source_t.owns_coin) is replaced spending the
     same coin; anyone else's child, anchor-only or funded from another
     wallet, is outbid with a coin of ours.  Calling this again on every
     retry keeps the package at the current rate.  CPFP_BUMP_FAILED when no
     child could raise it.
   A child pays at most max_child_fee sats (0 = CPFP_DEFAULT_MAX_CHILD_FEE).
   txid_out (optional) receives the parent txid.  Returns a cpfp_result_t. */
cpfp_result_t cpfp_send_presigned(regtest_t *rt, wallet_source_t *wallet,
                                  uint64_t target_rate, uint64_t max_child_fee,
                                  const char *tx_hex, char *txid_out);

/* Oldest Bitcoin Core (getnetworkinfo "version") that relays the exit:
   TRUC transactions, P2A anchors and 1-parent-1-child package relay
   through submitpackage all need 28.0. */
#define CPFP_MIN_NODE_VERSION 280000

/* 0, after an error naming the version, when the node behind rt is older
   than CPFP_MIN_NODE_VERSION; 1 otherwise (also when rt is NULL or the
   version cannot be read, with a warning). */
int cpfp_check_node_version(regtest_t *rt);

/* Process-wide defaults for broadcast paths that only hold a chain backend
   (factory recovery, client force-close).  rt NULL disables packaging.
   urgent (optional): its FEE_TARGET_URGENT rate is the target_rate, so a
   pre-signed tx too cheap to confirm within a couple of blocks is bumped.
   max_child_fee: budget per child (0 = CPFP_DEFAULT_MAX_CHILD_FEE). */
void cpfp_set_default(regtest_t *rt, wallet_source_t *wallet,
                      fee_estimator_t *urgent, uint64_t max_child_fee);

/* Broadcast with the defaults set by cpfp_set_default; without them, a plain
   cb->send_raw_tx (CPFP_SENT_ALONE or CPFP_FAILED). */
cpfp_result_t cpfp_send_default(chain_backend_t *cb, const char *tx_hex,
                                char *txid_out);

#endif /* SUPERSCALAR_CPFP_H */
