#include "superscalar/wallet_source.h"
#include "superscalar/regtest.h"
#include "cJSON.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

extern int  hex_decode(const char *hex, unsigned char *out, size_t out_len);

/* -----------------------------------------------------------------------
 * get_utxo: wraps regtest_get_utxo_for_bump
 * --------------------------------------------------------------------- */
static int rpc_get_utxo(wallet_source_t *self,
                         uint64_t min_sats,
                         char txid_hex[65],
                         uint32_t *vout,
                         uint64_t *amount,
                         unsigned char *spk,
                         size_t *spk_len)
{
    wallet_source_rpc_t *ws = (wallet_source_rpc_t *)self;
    return regtest_get_utxo_for_bump((regtest_t *)ws->rt, min_sats,
                                      txid_hex, vout, amount,
                                      spk, spk_len);
}

/* -----------------------------------------------------------------------
 * get_change_spk: new wallet address via regtest_get_new_address +
 *                 getaddressinfo to resolve to a raw scriptPubKey.
 * --------------------------------------------------------------------- */
static int rpc_get_change_spk(wallet_source_t *self,
                               unsigned char *spk,
                               size_t *spk_len)
{
    wallet_source_rpc_t *ws = (wallet_source_rpc_t *)self;
    regtest_t *rt = (regtest_t *)ws->rt;

    char addr[128];
    if (!regtest_get_new_address(rt, addr, sizeof(addr)))
        return 0;

    char params[256];
    snprintf(params, sizeof(params), "\"%s\"", addr);
    char *info = regtest_exec(rt, "getaddressinfo", params);
    if (!info) return 0;

    cJSON *json = cJSON_Parse(info);
    free(info);
    if (!json) return 0;

    cJSON *spk_hex = cJSON_GetObjectItem(json, "scriptPubKey");
    if (!spk_hex || !cJSON_IsString(spk_hex)) {
        cJSON_Delete(json);
        return 0;
    }
    int decoded = hex_decode(spk_hex->valuestring, spk, 64);
    cJSON_Delete(json);
    if (decoded <= 0) return 0;
    *spk_len = (size_t)decoded;
    return 1;
}

/* -----------------------------------------------------------------------
 * sign_input: wraps regtest_sign_raw_tx_with_wallet.
 *
 * The watchtower CPFP tx has two inputs:
 *   input 0 — P2A anchor (anyone-can-spend, no signing needed)
 *   input 1 — wallet UTXO (this is what we sign)
 *
 * We hex-encode the unsigned tx, call signrawtransactionwithwallet,
 * then decode the result back into the caller's buffer.
 * require_complete=0 because the P2A input will never have a signature.
 * --------------------------------------------------------------------- */
static int rpc_sign_input(wallet_source_t *self,
                           unsigned char *tx, size_t *tx_len,
                           size_t input_idx,
                           const unsigned char *spk, size_t spk_len,
                           uint64_t amount_sats)
{
    (void)input_idx; (void)spk; (void)spk_len; (void)amount_sats;
    wallet_source_rpc_t *ws = (wallet_source_rpc_t *)self;
    regtest_t *rt = (regtest_t *)ws->rt;

    /* Hex-encode the unsigned tx */
    size_t hex_len = (*tx_len) * 2 + 1;
    char *unsigned_hex = malloc(hex_len);
    if (!unsigned_hex) return 0;

    /* hex_encode declared extern in watchtower.c — use our own inline loop */
    static const char hexchars[] = "0123456789abcdef";
    for (size_t i = 0; i < *tx_len; i++) {
        unsigned_hex[i * 2]     = hexchars[(tx[i] >> 4) & 0xF];
        unsigned_hex[i * 2 + 1] = hexchars[ tx[i]       & 0xF];
    }
    unsigned_hex[*tx_len * 2] = '\0';

    char *signed_hex = regtest_sign_raw_tx_with_wallet(rt, unsigned_hex, NULL, 0);
    free(unsigned_hex);
    if (!signed_hex) return 0;

    size_t signed_len = strlen(signed_hex) / 2;
    if (signed_len > *tx_len + 512) {
        /* Buffer probably too small — shouldn't happen for a 2-input tx */
        free(signed_hex);
        return 0;
    }
    hex_decode(signed_hex, tx, signed_len);
    free(signed_hex);
    *tx_len = signed_len;
    return 1;
}

/* -----------------------------------------------------------------------
 * Public init
 * --------------------------------------------------------------------- */
void wallet_source_rpc_init(wallet_source_rpc_t *ws, void *rt)
{
    if (!ws) return;
    memset(ws, 0, sizeof(*ws));
    ws->base.get_utxo      = rpc_get_utxo;
    ws->base.get_change_spk = rpc_get_change_spk;
    ws->base.sign_input    = rpc_sign_input;
    ws->base.free          = NULL;
    ws->rt = rt;
}
