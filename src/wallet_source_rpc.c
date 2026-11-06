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
 * build_prevtxs_json: build a JSON prevtxs array for signrawtransactionwithwallet.
 *
 * Parses the non-segwit serialised tx to extract each input's txid/vout, then
 * calls gettxout (which includes mempool UTXOs) to retrieve the scriptPubKey
 * and amount.  This is needed so that Taproot signing (BIP 341 sha_amounts)
 * covers ALL input amounts — not just the wallet's own UTXOs.
 *
 * Returns a malloc'd JSON string like:
 *   [{"txid":"...","vout":N,"scriptPubKey":"...","amount":X.XXXXXXXX}, ...]
 * or NULL if nothing useful was found.
 * --------------------------------------------------------------------- */
static char *build_prevtxs_json(regtest_t *rt, const wallet_source_rpc_t *ws,
                                 const unsigned char *tx, size_t tx_len)
{
    if (!rt || !tx || tx_len < 6) return NULL;

    static const char hexchars[] = "0123456789abcdef";

    /* Skip nVersion (4 bytes) */
    const unsigned char *p = tx + 4;

    /* vin count — single-byte varint only (≤ 252 inputs) */
    uint8_t n_in = *p++;
    if (n_in == 0 || n_in > 252) return NULL;

    /* Allocate generous JSON buffer */
    size_t json_cap = (size_t)n_in * 256 + 8;
    char *json = (char *)malloc(json_cap);
    if (!json) return NULL;

    size_t jlen = 0;
    json[jlen++] = '[';
    int added = 0;

    for (uint8_t i = 0; i < n_in; i++) {
        if ((size_t)(p - tx) + 41 > tx_len) break;

        /* txid: 32 bytes internal order → reverse to display order */
        char txid_disp[65];
        for (int j = 31; j >= 0; j--) {
            txid_disp[(31 - j) * 2]     = hexchars[(p[j] >> 4) & 0xF];
            txid_disp[(31 - j) * 2 + 1] = hexchars[ p[j]       & 0xF];
        }
        txid_disp[64] = '\0';
        p += 32;

        /* vout: 4 bytes LE */
        uint32_t vout = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
        p += 4;

        /* scriptSig length (varint) — skip it */
        if ((size_t)(p - tx) >= tx_len) break;
        size_t ss_len = (uint8_t)*p++;
        if (ss_len == 0xfd) {
            if ((size_t)(p - tx) + 2 > tx_len) break;
            ss_len = (size_t)p[0] | ((size_t)p[1] << 8);
            p += 2;
        }
        if ((size_t)(p - tx) + ss_len + 4 > tx_len) break;
        p += ss_len + 4;  /* skip scriptSig + nSequence */

        /* Look up this prevout — gettxout includes mempool UTXOs by default */
        char params[140];
        snprintf(params, sizeof(params), "\"%s\" %u true", txid_disp, vout);
        char *result = regtest_exec(rt, "gettxout", params);
        cJSON *gto = NULL;
        if (result) {
            gto = cJSON_Parse(result);
            free(result);
        }
        if (!gto || !cJSON_GetObjectItem(gto, "value")) {
            /* Spent in the mempool (the coin of a child being replaced): the
               chain state still has it. */
            snprintf(params, sizeof(params), "\"%s\" %u false", txid_disp, vout);
            char *r2 = regtest_exec(rt, "gettxout", params);
            cJSON *g2 = r2 ? cJSON_Parse(r2) : NULL;
            free(r2);
            if (g2 && cJSON_GetObjectItem(g2, "value")) {
                cJSON_Delete(gto);
                gto = g2;
            } else {
                cJSON_Delete(g2);
            }
        }
        if ((!gto || !cJSON_GetObjectItem(gto, "value")) && ws && ws->has_hint &&
            vout == ws->hint_vout && strcmp(txid_disp, ws->hint_txid) == 0) {
            if (added) {
                if (jlen + 1 < json_cap) json[jlen++] = ',';
            }
            int n = snprintf(json + jlen, json_cap - jlen,
                "{\"txid\":\"%s\",\"vout\":%u,"
                "\"scriptPubKey\":\"%s\",\"amount\":%.8f}",
                txid_disp, vout, ws->hint_spk_hex,
                (double)ws->hint_amount / 100000000.0);
            if (n > 0 && (size_t)n < json_cap - jlen) {
                jlen += (size_t)n;
                added++;
            }
            cJSON_Delete(gto);
            continue;
        }
        if (!gto) continue;

        cJSON *val  = cJSON_GetObjectItem(gto, "value");
        cJSON *spko = cJSON_GetObjectItem(gto, "scriptPubKey");
        cJSON *hex  = spko ? cJSON_GetObjectItem(spko, "hex") : NULL;

        if (val && cJSON_IsNumber(val) && hex && cJSON_IsString(hex)) {
            if (added) {
                if (jlen + 1 < json_cap) json[jlen++] = ',';
            }
            int n = snprintf(json + jlen, json_cap - jlen,
                "{\"txid\":\"%s\",\"vout\":%u,"
                "\"scriptPubKey\":\"%s\",\"amount\":%.8f}",
                txid_disp, vout, hex->valuestring, val->valuedouble);
            if (n > 0 && (size_t)n < json_cap - jlen) {
                jlen += (size_t)n;
                added++;
            }
        }
        cJSON_Delete(gto);
    }

    if (jlen + 1 < json_cap) json[jlen++] = ']';
    json[jlen] = '\0';

    if (!added) { free(json); return NULL; }
    return json;
}

/* Outpoint (display-order txid) spent by input idx of a serialized tx
   (legacy or segwit encoding).  Returns 1 if found. */
static int tx_input_outpoint(const unsigned char *tx, size_t len, size_t idx,
                             char txid_out[65], uint32_t *vout_out)
{
    static const char hexchars[] = "0123456789abcdef";
    if (!tx || len < 10) return 0;
    size_t pos = (tx[4] == 0x00 && tx[5] == 0x01) ? 6 : 4;
    size_t n_in = tx[pos++];
    if (n_in >= 0xfd || idx >= n_in) return 0;
    for (size_t i = 0; i < n_in; i++) {
        if (pos + 37 > len) return 0;
        if (i == idx) {
            for (int j = 31; j >= 0; j--) {
                txid_out[(31 - j) * 2]     = hexchars[(tx[pos + j] >> 4) & 0xF];
                txid_out[(31 - j) * 2 + 1] = hexchars[ tx[pos + j]       & 0xF];
            }
            txid_out[64] = '\0';
            *vout_out = (uint32_t)tx[pos + 32] | ((uint32_t)tx[pos + 33] << 8) |
                        ((uint32_t)tx[pos + 34] << 16) | ((uint32_t)tx[pos + 35] << 24);
            return 1;
        }
        pos += 36;
        size_t ss = tx[pos++];
        if (ss >= 0xfd || pos + ss + 4 > len) return 0;
        pos += ss + 4;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * sign_input: signrawtransactionwithwallet on input input_idx.
 *
 * A CPFP child has two inputs:
 *   input 0 — P2A anchor (anyone-can-spend, no signing needed)
 *   input 1 — wallet UTXO (this is what we sign)
 *
 * prevtxs is built from gettxout for each input (so that Taproot sighash
 * sha_amounts covers all input amounts, including the unconfirmed P2A
 * anchor).  Succeeds only when the wallet signed input_idx: a coin that is
 * not the wallet's comes back unsigned and is a failure.
 * --------------------------------------------------------------------- */
static int rpc_sign_input(wallet_source_t *self,
                           unsigned char *tx, size_t *tx_len,
                           size_t input_idx,
                           const unsigned char *spk, size_t spk_len,
                           uint64_t amount_sats)
{
    (void)spk; (void)spk_len; (void)amount_sats;
    wallet_source_rpc_t *ws = (wallet_source_rpc_t *)self;
    regtest_t *rt = (regtest_t *)ws->rt;

    char in_txid[65];
    uint32_t in_vout = 0;
    if (!tx_input_outpoint(tx, *tx_len, input_idx, in_txid, &in_vout)) return 0;

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

    /* Build prevtxs so signrawtransactionwithwallet has all input amounts.
     * This is critical for Taproot signing (BIP 341 sha_amounts covers ALL
     * inputs).  The P2A anchor (input 0) is from the unconfirmed penalty tx
     * in the mempool; gettxout with include_mempool=true finds it. */
    char *prevtxs = build_prevtxs_json(rt, ws, tx, *tx_len);
    size_t plen = strlen(unsigned_hex) + (prevtxs ? strlen(prevtxs) : 0) + 16;
    char *params = malloc(plen);
    if (!params) { free(unsigned_hex); free(prevtxs); return 0; }
    /* single quotes: the RPC call goes through /bin/sh */
    if (prevtxs) snprintf(params, plen, "\"%s\" '%s'", unsigned_hex, prevtxs);
    else         snprintf(params, plen, "\"%s\"", unsigned_hex);
    free(unsigned_hex);
    free(prevtxs);
    char *result = regtest_exec(rt, "signrawtransactionwithwallet", params);
    free(params);
    cJSON *json = result ? cJSON_Parse(result) : NULL;
    free(result);
    if (!json) return 0;

    /* "complete" is false whenever any input lacks a signature, the keyless
       anchor included; what matters is that input_idx has none of the
       errors signrawtransactionwithwallet lists per unsigned input. */
    cJSON *hex = cJSON_GetObjectItem(json, "hex");
    int ok = hex && cJSON_IsString(hex);
    if (ok && !cJSON_IsTrue(cJSON_GetObjectItem(json, "complete"))) {
        cJSON *errors = cJSON_GetObjectItem(json, "errors");
        if (!errors || !cJSON_IsArray(errors)) ok = 0;
        for (int i = 0; ok && i < cJSON_GetArraySize(errors); i++) {
            cJSON *e = cJSON_GetArrayItem(errors, i);
            cJSON *et = cJSON_GetObjectItem(e, "txid");
            cJSON *ev = cJSON_GetObjectItem(e, "vout");
            if (!et || !cJSON_IsString(et) || !ev || !cJSON_IsNumber(ev)) continue;
            if (strcmp(et->valuestring, in_txid) != 0 ||
                (uint32_t)ev->valuedouble != in_vout) continue;
            cJSON *msg = cJSON_GetObjectItem(e, "error");
            fprintf(stderr, "wallet: cannot sign input %zu (%s:%u): %s\n",
                    input_idx, in_txid, in_vout,
                    (msg && cJSON_IsString(msg)) ? msg->valuestring : "?");
            ok = 0;
        }
    }
    size_t signed_len = ok ? strlen(hex->valuestring) / 2 : 0;
    /* the caller's buffer holds the unsigned tx plus 512 bytes */
    if (ok && signed_len > *tx_len + 512) ok = 0;
    if (ok && hex_decode(hex->valuestring, tx, signed_len) != (int)signed_len) ok = 0;
    if (ok) *tx_len = signed_len;
    cJSON_Delete(json);
    return ok;
}

/* -----------------------------------------------------------------------
 * owns_coin: the coin's scriptPubKey belongs to the wallet (ismine).
 * --------------------------------------------------------------------- */
static int rpc_owns_coin(wallet_source_t *self, const char *txid_hex,
                          uint32_t vout, const unsigned char *spk,
                          size_t spk_len)
{
    (void)txid_hex; (void)vout;
    wallet_source_rpc_t *ws = (wallet_source_rpc_t *)self;
    regtest_t *rt = (regtest_t *)ws->rt;
    static const char hexchars[] = "0123456789abcdef";
    if (!spk || spk_len == 0 || spk_len > 64) return 0;
    char params[160];
    size_t n = 0;
    params[n++] = '"';
    for (size_t i = 0; i < spk_len; i++) {
        params[n++] = hexchars[(spk[i] >> 4) & 0xF];
        params[n++] = hexchars[ spk[i]       & 0xF];
    }
    params[n++] = '"';
    params[n] = '\0';
    char *r = regtest_exec(rt, "decodescript", params);
    cJSON *d = r ? cJSON_Parse(r) : NULL;
    free(r);
    cJSON *addr = d ? cJSON_GetObjectItem(d, "address") : NULL;
    int mine = 0;
    if (addr && cJSON_IsString(addr) && strlen(addr->valuestring) < 120) {
        snprintf(params, sizeof(params), "\"%s\"", addr->valuestring);
        char *ri = regtest_exec(rt, "getaddressinfo", params);
        cJSON *info = ri ? cJSON_Parse(ri) : NULL;
        free(ri);
        cJSON *im = info ? cJSON_GetObjectItem(info, "ismine") : NULL;
        mine = im && cJSON_IsTrue(im);
        cJSON_Delete(info);
    }
    cJSON_Delete(d);
    return mine;
}

/* -----------------------------------------------------------------------
 * release_utxo: unlock a UTXO previously locked by rpc_get_utxo.
 * --------------------------------------------------------------------- */
static void rpc_release_utxo(wallet_source_t *self,
                              const char *txid_hex, uint32_t vout)
{
    wallet_source_rpc_t *ws = (wallet_source_rpc_t *)self;
    regtest_release_utxo((regtest_t *)ws->rt, txid_hex, vout);
}

/* -----------------------------------------------------------------------
 * Public init
 * --------------------------------------------------------------------- */
void wallet_source_rpc_set_prevout_hint(wallet_source_rpc_t *ws,
                                        const char *txid_hex, uint32_t vout,
                                        const char *spk_hex, uint64_t amount_sats)
{
    if (!ws) return;
    if (!txid_hex || !spk_hex || strlen(txid_hex) != 64 ||
        strlen(spk_hex) >= sizeof(ws->hint_spk_hex)) {
        ws->has_hint = 0;
        return;
    }
    memcpy(ws->hint_txid, txid_hex, 65);
    ws->hint_vout = vout;
    strcpy(ws->hint_spk_hex, spk_hex);
    ws->hint_amount = amount_sats;
    ws->has_hint = 1;
}

void wallet_source_rpc_init(wallet_source_rpc_t *ws, void *rt)
{
    if (!ws) return;
    memset(ws, 0, sizeof(*ws));
    ws->base.get_utxo       = rpc_get_utxo;
    ws->base.get_change_spk = rpc_get_change_spk;
    ws->base.sign_input     = rpc_sign_input;
    ws->base.release_utxo   = rpc_release_utxo;
    ws->base.owns_coin      = rpc_owns_coin;
    ws->base.free           = NULL;
    ws->base.type           = WALLET_SOURCE_RPC;
    ws->rt = rt;
}
