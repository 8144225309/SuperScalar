#include "superscalar/lsp_fund.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

extern int  hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern void reverse_bytes(unsigned char *data, size_t len);

/*
 * Build an unsigned Bitcoin transaction (legacy encoding — no segwit marker).
 * 1 input, n_outputs outputs. wallet->sign_input will add the witness.
 * Returns byte length written into out (always < 512 for 1-in 2-out P2TR).
 */
static size_t build_unsigned_tx(unsigned char *out,
                                 const unsigned char *txid32_internal,
                                 uint32_t vout_idx,
                                 const unsigned char *spk1, size_t spk1_len,
                                 uint64_t amt1,
                                 const unsigned char *spk2, size_t spk2_len,
                                 uint64_t amt2,
                                 int n_outputs)
{
    size_t pos = 0;

#define WU32LE(v) do { uint32_t _v=(v); \
    out[pos++]=_v&0xff; out[pos++]=(_v>>8)&0xff; \
    out[pos++]=(_v>>16)&0xff; out[pos++]=(_v>>24)&0xff; } while(0)
#define WU64LE(v) do { uint64_t _v=(v); \
    for(int _i=0;_i<8;_i++) out[pos++]=(_v>>(_i*8))&0xff; } while(0)
#define WU8(v)  out[pos++]=(unsigned char)(v)

    WU32LE(2);                          /* nVersion = 2 */
    WU8(0x01);                          /* input count = 1 */
    memcpy(out+pos, txid32_internal, 32); pos += 32;
    WU32LE(vout_idx);                   /* vout */
    WU8(0x00);                          /* scriptSig len = 0 */
    WU32LE(0xFFFFFFFDu);                /* sequence: RBF */
    WU8((unsigned char)n_outputs);      /* output count */
    WU64LE(amt1);                       /* output 1 amount */
    WU8((unsigned char)spk1_len);
    memcpy(out+pos, spk1, spk1_len); pos += spk1_len;
    if (n_outputs >= 2) {
        WU64LE(amt2);                   /* output 2 amount */
        WU8((unsigned char)spk2_len);
        memcpy(out+pos, spk2, spk2_len); pos += spk2_len;
    }
    WU32LE(0);                          /* nLocktime = 0 */

#undef WU32LE
#undef WU64LE
#undef WU8
    return pos;
}

int lsp_fund_spk(wallet_source_t *wallet, chain_backend_t *chain,
                 const unsigned char *target_spk, size_t target_spk_len,
                 uint64_t amount_sats, uint64_t fee_rate_kvb,
                 char *txid_out_65)
{
    if (!wallet || !chain || !target_spk || target_spk_len == 0 || amount_sats == 0)
        return 0;
    if (fee_rate_kvb == 0)
        fee_rate_kvb = 110; /* default: 0.11 sat/vB */

    /* Estimate fee: 1-in 2-out P2TR key-path ~200 vbytes */
    uint64_t fee_sats = (200 * fee_rate_kvb + 999) / 1000;
    if (fee_sats < 1) fee_sats = 1;

    /* Select UTXO large enough to cover amount + fee */
    char in_txid_hex[65];
    uint32_t in_vout;
    uint64_t in_amount;
    unsigned char in_spk[34];
    size_t in_spk_len = 0;
    if (!wallet->get_utxo(wallet, amount_sats + fee_sats,
                           in_txid_hex, &in_vout, &in_amount,
                           in_spk, &in_spk_len)) {
        fprintf(stderr, "lsp_fund_spk: no UTXO >= %llu sats\n",
                (unsigned long long)(amount_sats + fee_sats));
        return 0;
    }

    /* Compute change; absorb dust into fee */
    uint64_t change_sats = in_amount - amount_sats - fee_sats;
    int n_outputs = (change_sats >= 546) ? 2 : 1;
    if (n_outputs == 1) fee_sats += change_sats;

    /* Get change SPK */
    unsigned char chg_spk[34];
    size_t chg_spk_len = 0;
    if (n_outputs == 2) {
        if (!wallet->get_change_spk(wallet, chg_spk, &chg_spk_len)) {
            if (wallet->release_utxo) wallet->release_utxo(wallet, in_txid_hex, in_vout);
            return 0;
        }
    }

    /* Convert display-order txid hex → internal-order bytes */
    unsigned char in_txid_bytes[32];
    hex_decode(in_txid_hex, in_txid_bytes, 32);
    reverse_bytes(in_txid_bytes, 32);

    /* Build unsigned TX (max ~137 bytes base) */
    unsigned char tx_raw[512];
    size_t tx_len = build_unsigned_tx(tx_raw, in_txid_bytes, in_vout,
                                       target_spk, target_spk_len, amount_sats,
                                       n_outputs == 2 ? chg_spk : NULL,
                                       n_outputs == 2 ? chg_spk_len : 0,
                                       n_outputs == 2 ? change_sats : 0,
                                       n_outputs);

    /* sign_input needs extra room for the witness (~68 bytes) */
    unsigned char signed_tx[512 + 128];
    memcpy(signed_tx, tx_raw, tx_len);
    size_t signed_len = tx_len;

    if (!wallet->sign_input(wallet, signed_tx, &signed_len, 0,
                            in_spk, in_spk_len, in_amount)) {
        fprintf(stderr, "lsp_fund_spk: sign_input failed\n");
        if (wallet->release_utxo) wallet->release_utxo(wallet, in_txid_hex, in_vout);
        return 0;
    }

    /* Hex-encode signed TX */
    char *hex = malloc(signed_len * 2 + 1);
    if (!hex) {
        if (wallet->release_utxo) wallet->release_utxo(wallet, in_txid_hex, in_vout);
        return 0;
    }
    hex_encode(signed_tx, signed_len, hex);

    /* Broadcast */
    char tmp_txid[65] = {0};
    int ok = chain->send_raw_tx(chain, hex, tmp_txid);
    free(hex);
    if (wallet->release_utxo) wallet->release_utxo(wallet, in_txid_hex, in_vout);

    if (!ok) {
        fprintf(stderr, "lsp_fund_spk: broadcast failed\n");
        return 0;
    }
    if (txid_out_65) memcpy(txid_out_65, tmp_txid, 65);
    return 1;
}

int lsp_wait_for_confirmation(chain_backend_t *chain, const char *txid_hex,
                               int timeout_secs)
{
    if (!chain || !txid_hex) return 0;
    int waited = 0;
    while (waited < timeout_secs) {
        int confs = chain->get_confirmations(chain, txid_hex);
        if (confs >= 1) return 1;
        sleep(15);
        waited += 15;
    }
    return 0;
}
