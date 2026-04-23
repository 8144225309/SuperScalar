#include "spend_helpers.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int  hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

int spend_find_vout_by_spk(regtest_t *rt,
                            const char *txid_hex,
                            const unsigned char *spk, size_t spk_len,
                            uint64_t *amount_out) {
    if (!rt || !txid_hex || !spk || spk_len == 0) return -2;
    for (uint32_t v = 0; v < 32; v++) {
        uint64_t amount = 0;
        unsigned char out_spk[64];
        size_t out_spk_len = 0;
        if (!regtest_get_tx_output(rt, txid_hex, v, &amount, out_spk, &out_spk_len))
            break;
        if (out_spk_len == spk_len && memcmp(out_spk, spk, spk_len) == 0) {
            if (amount_out) *amount_out = amount;
            return (int)v;
        }
    }
    return -1;
}

int spend_build_p2tr_raw_keypath(secp256k1_context *ctx,
                                  const unsigned char *seckey32,
                                  const char *in_txid_hex,
                                  uint32_t in_vout,
                                  uint64_t in_amount_sats,
                                  const unsigned char *in_spk, size_t in_spk_len,
                                  const unsigned char *dest_spk, size_t dest_spk_len,
                                  uint64_t fee_sats,
                                  tx_buf_t *tx_out) {
    if (!ctx || !seckey32 || !in_txid_hex || !in_spk || !dest_spk || !tx_out) return 0;
    if (in_amount_sats <= fee_sats) return 0;

    /* Parse display-order txid (hex) into internal byte order for tx input. */
    unsigned char in_txid_internal[32];
    if (!hex_decode(in_txid_hex, in_txid_internal, sizeof(in_txid_internal)))
        return 0;
    reverse_bytes(in_txid_internal, 32);

    /* Single output: dest_spk with amount = in_amount - fee. */
    tx_output_t outs[1];
    memset(outs, 0, sizeof(outs));
    outs[0].amount_sats = in_amount_sats - fee_sats;
    if (dest_spk_len > sizeof(outs[0].script_pubkey)) return 0;
    memcpy(outs[0].script_pubkey, dest_spk, dest_spk_len);
    outs[0].script_pubkey_len = dest_spk_len;

    /* Build unsigned tx. nSequence=0xFFFFFFFE (BIP-68 disabled, anti-fee-snipe). */
    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 256);
    if (!build_unsigned_tx(&unsigned_tx, NULL,
                            in_txid_internal, in_vout,
                            0xFFFFFFFEu, outs, 1)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* BIP-341 sighash over the single input spending in_spk with in_amount. */
    unsigned char sighash[32];
    if (!compute_taproot_sighash(sighash, unsigned_tx.data, unsigned_tx.len,
                                   0, in_spk, in_spk_len,
                                   in_amount_sats, 0xFFFFFFFEu)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* Sign with raw seckey. close_spk / lsp_close_spk use the raw xonly as
       the taproot output key (no BIP-341 taptweak), so we sign with the
       untweaked key. */
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, seckey32)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }
    unsigned char sig64[64];
    if (!secp256k1_schnorrsig_sign32(ctx, sig64, sighash, &kp, NULL)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* Finalize: attach 64-byte Schnorr witness. */
    tx_buf_init(tx_out, 256);
    if (!finalize_signed_tx(tx_out, unsigned_tx.data, unsigned_tx.len, sig64)) {
        tx_buf_free(&unsigned_tx);
        tx_buf_free(tx_out);
        return 0;
    }
    tx_buf_free(&unsigned_tx);
    return 1;
}

int spend_broadcast_and_mine(regtest_t *rt,
                              const char *tx_hex,
                              int n_blocks,
                              char *txid_out) {
    if (!rt || !tx_hex || !txid_out) return 0;
    char addr[128];
    if (!regtest_get_new_address(rt, addr, sizeof(addr))) return 0;
    if (!regtest_send_raw_tx(rt, tx_hex, txid_out)) return 0;
    if (n_blocks > 0 && !regtest_mine_blocks(rt, n_blocks, addr)) return 0;
    return regtest_get_confirmations(rt, txid_out) >= 1;
}
