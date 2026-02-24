#ifndef SUPERSCALAR_TX_BUILDER_H
#define SUPERSCALAR_TX_BUILDER_H

#include "types.h"
#include <secp256k1_extrakeys.h>

/* Serialization primitives */
void tx_buf_write_u8(tx_buf_t *buf, uint8_t val);
void tx_buf_write_u16_le(tx_buf_t *buf, uint16_t val);
void tx_buf_write_u32_le(tx_buf_t *buf, uint32_t val);
void tx_buf_write_u64_le(tx_buf_t *buf, uint64_t val);
void tx_buf_write_varint(tx_buf_t *buf, uint64_t val);
void tx_buf_write_bytes(tx_buf_t *buf, const unsigned char *data, size_t len);

/* P2TR scriptPubKey: OP_1 <32-byte-x-only-key>. out34 must be >= 34 bytes. */
void build_p2tr_script_pubkey(unsigned char *out34, const secp256k1_xonly_pubkey *key);

typedef struct {
    uint64_t amount_sats;
    unsigned char script_pubkey[34];
    size_t script_pubkey_len;
} tx_output_t;

/* Build unsigned single-input tx with custom nLockTime. */
int build_unsigned_tx_with_locktime(
    tx_buf_t *out,
    unsigned char *txid_out32,     /* can be NULL */
    const unsigned char *funding_txid,
    uint32_t funding_vout,
    uint32_t nsequence,
    uint32_t nlocktime,
    const tx_output_t *outputs,
    size_t n_outputs
);

/* Build unsigned single-input tx (nVersion=2, nLockTime=0). */
int build_unsigned_tx(
    tx_buf_t *out,
    unsigned char *txid_out32,     /* can be NULL */
    const unsigned char *funding_txid,
    uint32_t funding_vout,
    uint32_t nsequence,
    const tx_output_t *outputs,
    size_t n_outputs
);

/* BIP-341 sighash (key-path, SIGHASH_DEFAULT). */
int compute_taproot_sighash(
    unsigned char *sighash_out32,
    const unsigned char *unsigned_tx,
    size_t tx_len,
    uint32_t input_index,
    const unsigned char *prev_scriptpubkey,
    size_t prev_spk_len,
    uint64_t prev_amount,
    uint32_t nsequence
);

/* Attach 64-byte Schnorr witness to unsigned tx. */
int finalize_signed_tx(
    tx_buf_t *out,
    const unsigned char *unsigned_tx,
    size_t unsigned_tx_len,
    const unsigned char *sig64
);

#endif /* SUPERSCALAR_TX_BUILDER_H */
