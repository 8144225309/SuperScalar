#ifndef SUPERSCALAR_TAPSCRIPT_H
#define SUPERSCALAR_TAPSCRIPT_H

#include "types.h"
#include "tx_builder.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <stdint.h>

#define TAPSCRIPT_MAX_SCRIPT 128
#define TAPSCRIPT_LEAF_VERSION 0xc0

typedef struct {
    unsigned char script[TAPSCRIPT_MAX_SCRIPT];
    size_t script_len;
    unsigned char leaf_hash[32];
} tapscript_leaf_t;

/* Build hashlock script: OP_SIZE <0x20> OP_EQUALVERIFY OP_SHA256 <hash32> OP_EQUAL */
void tapscript_build_hashlock(tapscript_leaf_t *leaf,
                               const unsigned char *hash32);

/* Build CLTV timeout script: <locktime> OP_CLTV OP_DROP <L_pubkey> OP_CHECKSIG */
int tapscript_build_cltv_timeout(
    tapscript_leaf_t *leaf,
    uint32_t locktime,
    const secp256k1_xonly_pubkey *lsp_pubkey,
    const secp256k1_context *ctx
);

/* Build CSV delay script: <delay> OP_CSV OP_DROP <pubkey> OP_CHECKSIG */
int tapscript_build_csv_delay(
    tapscript_leaf_t *leaf,
    uint32_t delay,
    const secp256k1_xonly_pubkey *pubkey,
    const secp256k1_context *ctx
);

/* Compute TapLeaf hash for a populated leaf */
void tapscript_compute_leaf_hash(tapscript_leaf_t *leaf);

/* Compute merkle root from leaves (single leaf: root = leaf_hash) */
void tapscript_merkle_root(unsigned char *root_out32,
                           const tapscript_leaf_t *leaves, size_t n_leaves);

/* Tweak internal key with merkle root -> output key */
int tapscript_tweak_pubkey(
    const secp256k1_context *ctx,
    secp256k1_xonly_pubkey *tweaked_out,
    int *parity_out,
    const secp256k1_xonly_pubkey *internal_key,
    const unsigned char *merkle_root32
);

/* Build control block for script-path spend of a single-leaf tree */
int tapscript_build_control_block(
    unsigned char *out, size_t *out_len,
    int output_parity,
    const secp256k1_xonly_pubkey *internal_key,
    const secp256k1_context *ctx
);

/* BIP-341 script-path sighash (SIGHASH_DEFAULT) */
int compute_tapscript_sighash(
    unsigned char *sighash_out32,
    const unsigned char *unsigned_tx, size_t tx_len,
    uint32_t input_index,
    const unsigned char *prev_spk, size_t prev_spk_len,
    uint64_t prev_amount, uint32_t nsequence,
    const tapscript_leaf_t *leaf
);

/* Build unsigned tx with custom nLockTime */
int build_unsigned_tx_locktime(
    tx_buf_t *out,
    unsigned char *txid_out32,
    const unsigned char *input_txid,
    uint32_t input_vout,
    uint32_t nsequence,
    uint32_t nlocktime,
    const tx_output_t *outputs,
    size_t n_outputs
);

/* Finalize tx with script-path witness: [sig, script, control_block] */
int finalize_script_path_tx(
    tx_buf_t *out,
    const unsigned char *unsigned_tx, size_t unsigned_tx_len,
    const unsigned char *sig64,
    const unsigned char *script, size_t script_len,
    const unsigned char *control_block, size_t control_block_len
);

/* --- HTLC script builders --- */

/* Offered HTLC success leaf (remote claims with preimage, no CSV):
   OP_SIZE <0x20> OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUALVERIFY <remote_key> OP_CHECKSIG */
int tapscript_build_htlc_offered_success(tapscript_leaf_t *leaf,
    const unsigned char *payment_hash32,
    const secp256k1_xonly_pubkey *remote_htlcpubkey,
    const secp256k1_context *ctx);

/* Offered HTLC timeout leaf (local reclaims after CLTV + CSV):
   <cltv> OP_CLTV OP_DROP <csv> OP_CSV OP_DROP <local_key> OP_CHECKSIG */
int tapscript_build_htlc_offered_timeout(tapscript_leaf_t *leaf,
    uint32_t cltv_expiry, uint32_t to_self_delay,
    const secp256k1_xonly_pubkey *local_htlcpubkey,
    const secp256k1_context *ctx);

/* Received HTLC success leaf (local claims with preimage + CSV):
   OP_SIZE <0x20> OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUALVERIFY <csv> OP_CSV OP_DROP <local_key> OP_CHECKSIG */
int tapscript_build_htlc_received_success(tapscript_leaf_t *leaf,
    const unsigned char *payment_hash32, uint32_t to_self_delay,
    const secp256k1_xonly_pubkey *local_htlcpubkey,
    const secp256k1_context *ctx);

/* Received HTLC timeout leaf (remote reclaims after CLTV, no CSV):
   <cltv> OP_CLTV OP_DROP <remote_key> OP_CHECKSIG */
int tapscript_build_htlc_received_timeout(tapscript_leaf_t *leaf,
    uint32_t cltv_expiry,
    const secp256k1_xonly_pubkey *remote_htlcpubkey,
    const secp256k1_context *ctx);

/* Build control block for script-path spend of a 2-leaf tree.
   out must be >= 65 bytes. Result: [leaf_version|parity] || internal_key(32) || sibling_hash(32) */
int tapscript_build_control_block_2leaf(
    unsigned char *out, size_t *out_len,
    int output_parity,
    const secp256k1_xonly_pubkey *internal_key,
    const tapscript_leaf_t *sibling_leaf,
    const secp256k1_context *ctx);

/* Finalize tx with script-path witness including preimage:
   [sig, preimage, script, control_block] (4 witness items) */
int finalize_script_path_tx_preimage(
    tx_buf_t *out,
    const unsigned char *unsigned_tx, size_t unsigned_tx_len,
    const unsigned char *sig64,
    const unsigned char *preimage, size_t preimage_len,
    const unsigned char *script, size_t script_len,
    const unsigned char *control_block, size_t control_block_len);

#endif /* SUPERSCALAR_TAPSCRIPT_H */
