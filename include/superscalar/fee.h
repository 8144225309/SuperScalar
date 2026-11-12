#ifndef SUPERSCALAR_FEE_H
#define SUPERSCALAR_FEE_H

#include <stdint.h>
#include <stddef.h>
#include "superscalar/fee_estimator.h"

struct regtest_t;  /* forward declaration */

/* -----------------------------------------------------------------------
 * Backwards-compatibility shims (deprecated — use fee_estimator_*.h APIs)
 *
 * fee_init: callers MUST pass a pointer to a fee_estimator_static_t that
 * is cast to fee_estimator_t *.  e.g.:
 *   fee_estimator_static_t fe;
 *   fee_init((fee_estimator_t *)&fe, 1000);
 * --------------------------------------------------------------------- */
void fee_init(fee_estimator_t *fe, uint64_t default_rate_sat_per_kvb);

/* Deprecated: calls fe->update() if set; ignored for static estimators. */
int fee_update_from_node(fee_estimator_t *fe, void *rt, int target_blocks);

/* -----------------------------------------------------------------------
 * Fee helpers — call through the vtable
 *
 * Every helper below returns ceil(rate x vsize / 1000) in sats, 0 when the
 * rate is 0 (no estimate), and FEE_INVALID when the fee would exceed
 * FEE_MAX_SATS (the 21M BTC money supply): no transaction can pay it, so a
 * caller that gets FEE_INVALID must fail rather than build the transaction.
 * --------------------------------------------------------------------- */

/* Largest fee any transaction can pay: the money supply, in sats. */
#define FEE_MAX_SATS 2100000000000000ULL
/* Returned by the fee helpers when the fee exceeds FEE_MAX_SATS. */
#define FEE_INVALID  UINT64_MAX

/* General-purpose: fee for a transaction of given virtual size (NORMAL rate). */
uint64_t fee_estimate(fee_estimator_t *fe, size_t vsize_bytes);

/* Penalty tx is ~165 vB — uses URGENT rate (next 1-2 blocks). */
uint64_t fee_for_penalty_tx(fee_estimator_t *fe);

/* HTLC resolution tx is ~180 vB — uses URGENT rate. */
uint64_t fee_for_htlc_tx(fee_estimator_t *fe);

/* CPFP child tx is ~264 vB (2-in keypath, 1-out P2TR) — uses URGENT rate. */
uint64_t fee_for_cpfp_child(fee_estimator_t *fe);

/* fee_commitment_tx_at at fe's NORMAL rate (0 without a rate): for a
   channel whose rate follows an estimate (JIT).  Factory channels use the
   factory's agreed rate. */
uint64_t fee_for_commitment_tx(fee_estimator_t *fe, size_t n_htlcs);

/* Virtual size of a signed commitment with n_htlcs HTLC/PTLC outputs: one
   key-path input, to_local, to_remote, the HTLC outputs and the P2A anchor
   (167 vB with none). */
size_t fee_commitment_tx_vsize(size_t n_htlcs);

/* Fee of that commitment at the channel's agreed rate (sat/kvB): the one
   place the commitment fee is computed, by both co-signers.  The base fee
   (n_htlcs 0) is reserved out of the channel funding; each HTLC/PTLC output
   adds fee_commitment_tx_at(rate, n + 1) - fee_commitment_tx_at(rate, n). */
uint64_t fee_commitment_tx_at(uint64_t sat_per_kvb, size_t n_htlcs);

/* -----------------------------------------------------------------------
 * Exact sizing for pre-signed transactions
 *
 * A pre-signed transaction pays exactly its agreed rate for its real virtual
 * size; whatever more the network asks for at broadcast time is paid by a
 * child on its P2A anchor (cpfp.h).  The relay floor is read from the node
 * (getnetworkinfo relayfee), FEE_FLOOR_SAT_PER_KVB only when it reports
 * none.
 * --------------------------------------------------------------------- */

/* Serialized sizes used by the vsize helpers. */
#define FEE_P2TR_OUTPUT_BYTES     43   /* 8 amount + 1 len + 34 spk */
#define FEE_P2A_OUTPUT_BYTES      13   /* 8 amount + 1 len + 4 spk  */
#define FEE_KEYPATH_WITNESS_BYTES 66   /* 1 item count + 1 len + 64-byte sig */

/* Virtual size of a transaction whose inputs all have empty scriptSigs.
   outputs_bytes: serialized size of all outputs (each 8 + varint + spk).
   witness_bytes: serialized witness of all inputs (0 = legacy serialization,
   no marker/flag). */
size_t fee_tx_vsize(size_t n_inputs, size_t n_outputs, size_t outputs_bytes,
                    size_t witness_bytes);

/* Virtual size of a transaction with n_inputs taproot key-path inputs,
   n_p2tr P2TR outputs and n_p2a P2A anchor outputs. */
size_t fee_keypath_tx_vsize(size_t n_inputs, size_t n_p2tr, size_t n_p2a);

/* ceil(sat_per_kvb * vsize / 1000); FEE_INVALID above FEE_MAX_SATS. */
uint64_t fee_at_rate(uint64_t sat_per_kvb, size_t vsize);

#endif /* SUPERSCALAR_FEE_H */
