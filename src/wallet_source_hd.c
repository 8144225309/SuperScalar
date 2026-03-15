#include "superscalar/wallet_source_hd.h"
#include "superscalar/hd_key.h"
#include "superscalar/sha256.h"
#include "superscalar/tapscript.h"
#include "superscalar/bip158_backend.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

extern void secure_zero(void *p, size_t n);

/* -----------------------------------------------------------------------
 * P2TR derivation helpers
 * --------------------------------------------------------------------- */

/*
 * Derive the P2TR scriptPubKey and tweaked secret key for address index.
 * Path: m/86'/coin_type'/0'/index' (all hardened).
 * Returns 1 on success.
 */
int wallet_source_hd_derive(const wallet_source_hd_t *ws, uint32_t index,
                              unsigned char spk_out[34],
                              unsigned char seckey_out[32])
{
    if (!ws || !ws->ctx || !spk_out) return 0;

    /* Derive internal private key */
    char path[64];
    snprintf(path, sizeof(path), "m/86'/%u'/0'/%u'", ws->coin_type, index);

    unsigned char internal_key[32];
    if (!hd_key_derive_path(ws->seed, ws->seed_len, path, internal_key))
        return 0;

    /* Create keypair from internal key */
    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(ws->ctx, &keypair, internal_key)) {
        secure_zero(internal_key, 32);
        return 0;
    }
    secure_zero(internal_key, 32);

    /* Get x-only public key (internal key) */
    secp256k1_xonly_pubkey xonly_pk;
    if (!secp256k1_keypair_xonly_pub(ws->ctx, &xonly_pk, NULL, &keypair))
        return 0;

    unsigned char pk_bytes[32];
    secp256k1_xonly_pubkey_serialize(ws->ctx, pk_bytes, &xonly_pk);

    /* BIP 341 key-path tweak (no script tree): t = tagged_hash("TapTweak", pk_bytes) */
    unsigned char tweak[32];
    sha256_tagged("TapTweak", pk_bytes, 32, tweak);

    /* Apply tweak to keypair */
    if (!secp256k1_keypair_xonly_tweak_add(ws->ctx, &keypair, tweak))
        return 0;

    /* Get tweaked x-only output key */
    secp256k1_xonly_pubkey output_pk;
    if (!secp256k1_keypair_xonly_pub(ws->ctx, &output_pk, NULL, &keypair))
        return 0;

    unsigned char output_pk_bytes[32];
    secp256k1_xonly_pubkey_serialize(ws->ctx, output_pk_bytes, &output_pk);

    /* P2TR SPK: OP_1 (0x51) OP_PUSHBYTES_32 (0x20) <32-byte output key> */
    spk_out[0] = 0x51;
    spk_out[1] = 0x20;
    memcpy(spk_out + 2, output_pk_bytes, 32);

    /* Tweaked private key for signing (may be NULL if caller doesn't need it) */
    if (seckey_out)
        secp256k1_keypair_sec(ws->ctx, seckey_out, &keypair);

    return 1;
}

/* -----------------------------------------------------------------------
 * vtable: get_utxo
 * --------------------------------------------------------------------- */
static int hd_get_utxo(wallet_source_t *self,
                        uint64_t min_sats,
                        char txid_hex[65],
                        uint32_t *vout,
                        uint64_t *amount,
                        unsigned char *spk,
                        size_t *spk_len)
{
    wallet_source_hd_t *ws = (wallet_source_hd_t *)self;
    if (!ws->db) return 0;

    uint32_t key_index = 0;
    int found = persist_get_hd_utxo(ws->db, min_sats,
                                     txid_hex, vout, amount, &key_index);
    if (!found) return 0;

    /* Fill scriptPubKey from the pre-derived spks cache */
    if (key_index < ws->n_spks) {
        memcpy(spk, ws->spks[key_index], 34);
        *spk_len = 34;
    } else {
        /* Re-derive on cache miss */
        if (!wallet_source_hd_derive(ws, key_index, spk, NULL))
            return 0;
        *spk_len = 34;
    }
    return 1;
}

/* -----------------------------------------------------------------------
 * vtable: get_change_spk
 * --------------------------------------------------------------------- */
static int hd_get_change_spk(wallet_source_t *self,
                               unsigned char *spk,
                               size_t *spk_len)
{
    wallet_source_hd_t *ws = (wallet_source_hd_t *)self;
    uint32_t idx = ws->next_index;

    unsigned char new_spk[34];
    if (!wallet_source_hd_derive(ws, idx, new_spk, NULL))
        return 0;

    /* Register with BIP 158 if not already in cache */
    if (idx >= ws->n_spks && ws->bip158) {
        chain_backend_t *cb = &ws->bip158->base;
        cb->register_script(cb, new_spk, 34);
    }

    /* Advance index and persist */
    ws->next_index = idx + 1;
    if (ws->db)
        persist_save_hd_next_index(ws->db, ws->next_index);

    memcpy(spk, new_spk, 34);
    *spk_len = 34;
    return 1;
}

/* -----------------------------------------------------------------------
 * vtable: sign_input
 *
 * Signs input at input_idx using SIGHASH_ALL|ANYONECANPAY (0x81).
 * The signed tx is segwit-encoded: version || 0x00 0x01 || vin || vout ||
 * witness[0]=empty witness[1]=<sig65> || locktime
 * --------------------------------------------------------------------- */
static int hd_sign_input(wallet_source_t *self,
                          unsigned char *tx, size_t *tx_len,
                          size_t input_idx,
                          const unsigned char *spk, size_t spk_len,
                          uint64_t amount_sats)
{
    wallet_source_hd_t *ws = (wallet_source_hd_t *)self;
    if (!ws->ctx || !tx || !tx_len || !spk || spk_len != 34) return 0;

    /* Find which key_index this SPK belongs to */
    uint32_t key_index = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < ws->n_spks; i++) {
        if (memcmp(ws->spks[i], spk, 34) == 0) {
            key_index = i;
            break;
        }
    }
    if (key_index == 0xFFFFFFFFu) {
        /* Cache miss — try deriving up to next_index */
        unsigned char tmp_spk[34];
        for (uint32_t i = ws->n_spks; i < ws->next_index + ws->lookahead; i++) {
            if (!wallet_source_hd_derive(ws, i, tmp_spk, NULL)) break;
            if (memcmp(tmp_spk, spk, 34) == 0) { key_index = i; break; }
        }
    }
    if (key_index == 0xFFFFFFFFu) return 0;

    /* Derive tweaked private key for this index */
    unsigned char seckey[32];
    unsigned char sign_spk[34];
    if (!wallet_source_hd_derive(ws, key_index, sign_spk, seckey))
        return 0;

    /* Determine nsequence of input_idx from the unsigned tx */
    const unsigned char *p = tx + 4;
    size_t rem = *tx_len - 4;
    uint64_t vin_count; size_t vl;
#define RD_VI(p, rem, out, vl) do { \
    if ((rem) < 1) { secure_zero(seckey,32); return 0; } \
    if ((p)[0] < 0xfd) { (out) = (p)[0]; (vl) = 1; } \
    else if ((p)[0] == 0xfd && (rem) >= 3) { (out) = (uint64_t)(p)[1] | ((uint64_t)(p)[2] << 8); (vl) = 3; } \
    else { secure_zero(seckey,32); return 0; } \
} while(0)
    RD_VI(p, rem, vin_count, vl); p += vl; rem -= vl;
    if (input_idx >= vin_count) { secure_zero(seckey,32); return 0; }

    uint32_t nsequence = 0;
    for (uint64_t i = 0; i < vin_count; i++) {
        if (rem < 36) { secure_zero(seckey,32); return 0; }
        p += 36; rem -= 36;
        uint64_t ss_len;
        RD_VI(p, rem, ss_len, vl); p += vl + ss_len; rem -= vl + ss_len;
        if (rem < 4) { secure_zero(seckey,32); return 0; }
        if (i == input_idx) {
            nsequence = (uint32_t)p[0] | ((uint32_t)p[1]<<8) |
                        ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
        }
        p += 4; rem -= 4;
    }
#undef RD_VI

    /* Compute BIP 341 key-path sighash (ANYONECANPAY|ALL) */
    unsigned char sighash[32];
    if (!compute_keypath_sighash_anyonecanpay(sighash, tx, *tx_len,
                                               (uint32_t)input_idx,
                                               spk, spk_len,
                                               amount_sats, nsequence)) {
        secure_zero(seckey, 32);
        return 0;
    }

    /* Sign with secp256k1 Schnorr */
    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(ws->ctx, &keypair, seckey)) {
        secure_zero(seckey, 32);
        return 0;
    }
    secure_zero(seckey, 32);

    unsigned char aux_rand[32];
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { if (fread(aux_rand, 1, 32, f) != 32) memset(aux_rand, 0, 32); fclose(f); }
    else   memset(aux_rand, 0, 32);

    unsigned char sig64[64];
    if (!secp256k1_schnorrsig_sign32(ws->ctx, sig64, sighash, &keypair, aux_rand)) {
        secure_zero(aux_rand, 32);
        return 0;
    }
    secure_zero(aux_rand, 32);

    /*
     * Build segwit-encoded signed tx.
     * Format: version(4) 0x00 0x01 vin outputs witness[each_input] locktime(4)
     *
     * The unsigned tx is: version(4) vin vout locktime(4) (legacy, no segwit marker).
     * We need to insert the segwit marker/flag after version and add witnesses
     * after outputs.
     *
     * vin_count inputs, each gets:
     *   - input_idx: witness = 01 41 <sig64> 0x81
     *   - all others: witness = 00 (empty, 0 items — for P2A anyone-can-spend)
     *
     * Max signed tx size: orig_len + 2 (marker/flag) + vin_count*1 (empty witnesses) + 66 (65-byte sig witness)
     */
    size_t max_signed = *tx_len + 2 + (size_t)vin_count * 1 + 68;
    unsigned char *signed_tx = (unsigned char *)malloc(max_signed);
    if (!signed_tx) return 0;

    size_t wpos = 0;
    const unsigned char *src = tx;
    size_t src_rem = *tx_len;

    /* nVersion (4 bytes) */
    memcpy(signed_tx + wpos, src, 4); wpos += 4; src += 4; src_rem -= 4;
    /* segwit marker + flag */
    signed_tx[wpos++] = 0x00;
    signed_tx[wpos++] = 0x01;

    /* Copy vin + vout + (up to locktime) verbatim */
    size_t payload_len = src_rem - 4;  /* everything except locktime */
    memcpy(signed_tx + wpos, src, payload_len);
    wpos     += payload_len;
    src      += payload_len;
    src_rem  -= payload_len;

    /* Append witnesses for each input */
    for (uint64_t i = 0; i < vin_count; i++) {
        if (i == input_idx) {
            /* 1 witness item, 65 bytes: <sig64> || 0x81 */
            signed_tx[wpos++] = 0x01;  /* 1 item */
            signed_tx[wpos++] = 0x41;  /* 65 bytes */
            memcpy(signed_tx + wpos, sig64, 64); wpos += 64;
            signed_tx[wpos++] = 0x81;  /* hash_type appended */
        } else {
            signed_tx[wpos++] = 0x00;  /* 0 witness items */
        }
    }

    /* nLocktime (4 bytes) */
    memcpy(signed_tx + wpos, src, 4); wpos += 4;

    /* Write back */
    if (wpos <= *tx_len + 512) {
        memcpy(tx, signed_tx, wpos);
        *tx_len = wpos;
    }
    free(signed_tx);
    return 1;
}

/* -----------------------------------------------------------------------
 * UTXO scanning callbacks (registered with bip158_backend)
 * --------------------------------------------------------------------- */

static void hd_utxo_found(const char *txid_hex,
                            uint32_t vout_idx,
                            uint64_t amount_sats,
                            const unsigned char *spk,
                            size_t spk_len,
                            void *ctx)
{
    wallet_source_hd_t *ws = (wallet_source_hd_t *)ctx;
    if (!ws->db || spk_len != 34) return;

    /* Check if this output matches any of our pre-derived SPKs */
    for (uint32_t i = 0; i < ws->n_spks; i++) {
        if (memcmp(ws->spks[i], spk, 34) == 0) {
            persist_save_hd_utxo(ws->db, txid_hex, vout_idx, amount_sats, i);
            fprintf(stderr, "HD wallet: received UTXO %s:%u (%.8f BTC) at index %u\n",
                    txid_hex, vout_idx, (double)amount_sats / 100000000.0, i);
            return;
        }
    }
}

static void hd_utxo_spent(const char *txid_hex,
                            const uint8_t prev_txid32[32],
                            uint32_t prev_vout,
                            void *ctx)
{
    wallet_source_hd_t *ws = (wallet_source_hd_t *)ctx;
    if (!ws->db) return;
    (void)txid_hex;

    /* Convert internal-order txid to display-order hex */
    static const char hx[] = "0123456789abcdef";
    char prev_txid_hex[65];
    for (int k = 0; k < 32; k++) {
        prev_txid_hex[(31 - k) * 2]     = hx[(prev_txid32[k] >> 4) & 0xf];
        prev_txid_hex[(31 - k) * 2 + 1] = hx[ prev_txid32[k]       & 0xf];
    }
    prev_txid_hex[64] = '\0';

    persist_mark_hd_utxo_spent(ws->db, prev_txid_hex, prev_vout);
}

/* -----------------------------------------------------------------------
 * Public init
 * --------------------------------------------------------------------- */

static void hd_free(wallet_source_t *self)
{
    wallet_source_hd_t *ws = (wallet_source_hd_t *)self;
    free(ws->spks);
    ws->spks = NULL;
}

int wallet_source_hd_init(wallet_source_hd_t *ws,
                           const unsigned char *seed, size_t seed_len,
                           secp256k1_context *ctx,
                           persist_t *db,
                           bip158_backend_t *bip158,
                           const char *network,
                           uint32_t lookahead)
{
    if (!ws || !seed || seed_len == 0 || !ctx) return 0;

    memset(ws, 0, sizeof(*ws));
    ws->base.get_utxo      = hd_get_utxo;
    ws->base.get_change_spk = hd_get_change_spk;
    ws->base.sign_input    = hd_sign_input;
    ws->base.free          = hd_free;
    ws->ctx      = ctx;
    ws->db       = db;
    ws->bip158   = bip158;

    if (seed_len > 64) seed_len = 64;
    memcpy(ws->seed, seed, seed_len);
    ws->seed_len = seed_len;

    /* coin_type: 1 for testnet variants, 0 for mainnet */
    ws->coin_type = 0;
    if (network) {
        if (strcmp(network, "testnet3") == 0 || strcmp(network, "testnet") == 0 ||
            strcmp(network, "signet") == 0    || strcmp(network, "regtest") == 0)
            ws->coin_type = 1;
    }

    /* Load next_index from DB */
    if (db)
        ws->next_index = persist_load_hd_next_index(db);

    /* Set lookahead window size */
    ws->lookahead = (lookahead == 0) ? HD_WALLET_LOOKAHEAD : lookahead;

    /* Heap-allocate the SPK cache */
    ws->spks = malloc(ws->lookahead * sizeof(*ws->spks));
    if (!ws->spks) return 0;

    /* Pre-derive first ws->lookahead addresses */
    uint32_t n = 0;
    for (uint32_t i = 0; i < ws->lookahead; i++) {
        if (!wallet_source_hd_derive(ws, i, ws->spks[i], NULL))
            break;
        n++;
    }
    ws->n_spks = n;

    /* Register scripts with BIP 158 backend */
    if (bip158 && n > 0) {
        chain_backend_t *cb = &bip158->base;
        for (uint32_t i = 0; i < n; i++)
            cb->register_script(cb, ws->spks[i], 34);

        /* Set UTXO tracking callbacks */
        bip158_backend_set_utxo_cb(bip158, hd_utxo_found, hd_utxo_spent, ws);
    }

    return 1;
}

int wallet_source_hd_get_address(const wallet_source_hd_t *ws, uint32_t index,
                                   char *addr_out, size_t addr_cap)
{
    /* For now, return hex of the P2TR SPK — callers can convert to bech32m */
    if (!ws || !addr_out || addr_cap < 69) return 0;
    unsigned char spk[34];
    if (index < ws->n_spks)
        memcpy(spk, ws->spks[index], 34);
    else if (!wallet_source_hd_derive(ws, index, spk, NULL))
        return 0;

    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 34; i++) {
        addr_out[i * 2]     = hx[(spk[i] >> 4) & 0xf];
        addr_out[i * 2 + 1] = hx[ spk[i]       & 0xf];
    }
    addr_out[68] = '\0';
    return 1;
}
