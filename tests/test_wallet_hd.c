#include "superscalar/wallet_source_hd.h"
#include "superscalar/persist.h"
#include "superscalar/hd_key.h"
#include "superscalar/sha256.h"
#include "superscalar/bip39.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* Fixed test seed (32 bytes of 0x42) */
static const unsigned char TEST_SEED[32] = {
    0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,
    0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,
    0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,
    0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,
};

/* -----------------------------------------------------------------------
 * Test 1: derive a P2TR SPK — check it is 34 bytes starting with 0x51 0x20
 * --------------------------------------------------------------------- */
int test_hd_wallet_derives_p2tr(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    ASSERT(ctx != NULL, "secp256k1_context_create failed");

    wallet_source_hd_t ws;
    int ok = wallet_source_hd_init(&ws, TEST_SEED, 32, ctx, NULL, NULL, "regtest", HD_WALLET_LOOKAHEAD);
    ASSERT(ok == 1, "wallet_source_hd_init failed");
    ASSERT(ws.n_spks == HD_WALLET_LOOKAHEAD, "should have derived lookahead addresses");
    ASSERT(ws.coin_type == 1, "coin_type=1 for regtest");
    ASSERT(ws.spks[0][0] == 0x51, "SPK[0] starts with OP_1 (0x51)");
    ASSERT(ws.spks[0][1] == 0x20, "SPK[0] has OP_PUSHBYTES_32 (0x20)");

    /* Two different indices must give different SPKs */
    ASSERT(memcmp(ws.spks[0], ws.spks[1], 34) != 0, "index 0 != index 1");

    if (ws.base.free) ws.base.free(&ws.base);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * Test 2: derive key + sign a dummy sighash, verify with secp256k1
 * --------------------------------------------------------------------- */
int test_hd_wallet_sign_verify(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "ctx");

    wallet_source_hd_t ws;
    ASSERT(wallet_source_hd_init(&ws, TEST_SEED, 32, ctx, NULL, NULL, "regtest", HD_WALLET_LOOKAHEAD), "init");

    /* Get tweaked seckey for index 0 */
    unsigned char spk[34], seckey[32];
    ASSERT(wallet_source_hd_derive(&ws, 0, spk, seckey), "derive");

    /* Create keypair and sign a fake sighash */
    secp256k1_keypair kp;
    ASSERT(secp256k1_keypair_create(ctx, &kp, seckey), "keypair_create");

    unsigned char msg[32];
    memset(msg, 0xAB, 32);
    unsigned char aux[32];
    memset(aux, 0x00, 32);

    unsigned char sig64[64];
    ASSERT(secp256k1_schnorrsig_sign32(ctx, sig64, msg, &kp, aux), "schnorrsig_sign32");

    /* Verify with the tweaked output x-only pubkey from the SPK */
    secp256k1_xonly_pubkey xonly_pk;
    ASSERT(secp256k1_xonly_pubkey_parse(ctx, &xonly_pk, spk + 2), "xonly_pubkey_parse");
    ASSERT(secp256k1_schnorrsig_verify(ctx, sig64, msg, 32, &xonly_pk), "schnorrsig_verify");

    extern void secure_zero(void *p, size_t n);
    secure_zero(seckey, 32);
    if (ws.base.free) ws.base.free(&ws.base);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * Test 3: UTXO persistence round-trip
 * --------------------------------------------------------------------- */
int test_hd_wallet_utxo_persist(void)
{
    persist_t db;
    ASSERT(persist_open(&db, ":memory:"), "persist_open");

    ASSERT(persist_save_hd_utxo(&db, "aabbccdd00000000000000000000000000000000000000000000000000000000", 0, 500000, 3), "save_utxo");

    char txid[65]; uint32_t vout; uint64_t amt; uint32_t kidx;
    ASSERT(persist_get_hd_utxo(&db, 100000, txid, &vout, &amt, &kidx), "get_utxo found");
    ASSERT(vout == 0, "vout");
    ASSERT(amt  == 500000, "amount");
    ASSERT(kidx == 3, "key_index");

    /* No UTXO >= 600000 */
    ASSERT(!persist_get_hd_utxo(&db, 600000, txid, &vout, &amt, &kidx), "no utxo > balance");

    /* Mark spent */
    ASSERT(persist_mark_hd_utxo_spent(&db, "aabbccdd00000000000000000000000000000000000000000000000000000000", 0), "mark_spent");
    ASSERT(!persist_get_hd_utxo(&db, 1, txid, &vout, &amt, &kidx), "spent utxo not returned");

    /* next_index round-trip */
    ASSERT(persist_save_hd_next_index(&db, 42), "save_next_idx");
    ASSERT(persist_load_hd_next_index(&db) == 42, "load_next_idx");

    persist_close(&db);
    return 1;
}

/* -----------------------------------------------------------------------
 * Test 4: p2p_scan_block_full fires output callback
 *         Build a minimal 1-input/1-output legacy tx in a dummy block and
 *         verify the callback fires with correct txid, amount, and SPK.
 * --------------------------------------------------------------------- */
#include "superscalar/p2p_bitcoin.h"
#include "superscalar/sha256.h"

typedef struct { int count; uint64_t last_amount; unsigned char last_spk[34]; size_t last_spk_len; } scan_full_ctx_t;

static void full_output_cb(const char *txid_hex, uint32_t vout_idx,
                            uint64_t amount_sats, const unsigned char *spk,
                            size_t spk_len, void *ctx)
{
    (void)txid_hex; (void)vout_idx;
    scan_full_ctx_t *sc = (scan_full_ctx_t *)ctx;
    sc->count++;
    sc->last_amount = amount_sats;
    if (spk_len <= 34) { memcpy(sc->last_spk, spk, spk_len); sc->last_spk_len = spk_len; }
}

int test_p2p_scan_block_full_output(void)
{
    /* Minimal block: 80-byte header + 1 tx */
    /* Tx: version(4) vin_count(1) txid(32) vout(4) ss(1=0) seq(4) vout_count(1) amount(8) spk_len(1) spk(22) locktime(4) */
    unsigned char p2wpkh_spk[22] = {0x00, 0x14, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19};
    uint64_t tx_amount = 123456789ULL;

    unsigned char tx[4+1+32+4+1+4+1+8+1+22+4];
    size_t pos = 0;
    /* version = 1 LE */
    tx[pos++]=1; tx[pos++]=0; tx[pos++]=0; tx[pos++]=0;
    tx[pos++]=1; /* 1 input */
    memset(tx+pos, 0xAA, 32); pos+=32; /* prev txid */
    memset(tx+pos, 0, 4); pos+=4;       /* prev vout = 0 */
    tx[pos++]=0;                         /* scriptSig len = 0 */
    tx[pos++]=0xFF; tx[pos++]=0xFF; tx[pos++]=0xFF; tx[pos++]=0xFF; /* seq */
    tx[pos++]=1; /* 1 output */
    for (int i=0;i<8;i++) tx[pos++]=(unsigned char)(tx_amount>>(i*8));
    tx[pos++]=22; /* spk len */
    memcpy(tx+pos, p2wpkh_spk, 22); pos+=22;
    tx[pos++]=0; tx[pos++]=0; tx[pos++]=0; tx[pos++]=0; /* locktime */
    size_t tx_len = pos;

    /* Build block: 80-byte header + varint(1) + tx */
    size_t block_len = 80 + 1 + tx_len;
    unsigned char *block = (unsigned char *)calloc(1, block_len);
    ASSERT(block != NULL, "malloc block");
    /* header: all zeros (not validated here) */
    block[80] = 1; /* 1 tx */
    memcpy(block + 81, tx, tx_len);

    scan_full_ctx_t sc = {0};
    int n = p2p_scan_block_full(block, block_len, full_output_cb, NULL, &sc);
    free(block);

    ASSERT(n == 1, "processed 1 tx");
    ASSERT(sc.count == 1, "output callback fired once");
    ASSERT(sc.last_amount == tx_amount, "output amount correct");
    ASSERT(sc.last_spk_len == 22, "output spk_len correct");
    ASSERT(memcmp(sc.last_spk, p2wpkh_spk, 22) == 0, "output spk correct");

    return 1;
}

/* -----------------------------------------------------------------------
 * Test 5: BIP 39 round-trip — generate mnemonic, derive seed, same address
 *         as direct seed
 * --------------------------------------------------------------------- */
int test_hd_wallet_bip39_roundtrip(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    ASSERT(ctx != NULL, "ctx");

    /* Generate a 24-word mnemonic */
    char mnemonic[300];
    ASSERT(bip39_generate(24, mnemonic, sizeof(mnemonic)), "bip39_generate");

    /* Derive seed from mnemonic (no passphrase) */
    unsigned char seed_from_mnemonic[64];
    ASSERT(bip39_mnemonic_to_seed(mnemonic, "", seed_from_mnemonic), "mnemonic_to_seed");

    /* Initialize HD wallet with the derived seed */
    wallet_source_hd_t ws1, ws2;
    ASSERT(wallet_source_hd_init(&ws1, seed_from_mnemonic, 64, ctx, NULL, NULL, "regtest", HD_WALLET_LOOKAHEAD), "init ws1");

    /* Do it again with same seed — should produce identical address */
    ASSERT(wallet_source_hd_init(&ws2, seed_from_mnemonic, 64, ctx, NULL, NULL, "regtest", HD_WALLET_LOOKAHEAD), "init ws2");
    ASSERT(memcmp(ws1.spks[0], ws2.spks[0], 34) == 0, "same seed → same address[0]");
    ASSERT(memcmp(ws1.spks[0], ws2.spks[1], 34) != 0, "address[0] != address[1]");

    if (ws1.base.free) ws1.base.free(&ws1.base);
    if (ws2.base.free) ws2.base.free(&ws2.base);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * Test 6: same mnemonic + different passphrase → different addresses
 * --------------------------------------------------------------------- */
int test_hd_wallet_passphrase_isolation(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    ASSERT(ctx != NULL, "ctx");

    char mnemonic[300];
    ASSERT(bip39_generate(24, mnemonic, sizeof(mnemonic)), "bip39_generate");

    unsigned char seed_no_pass[64], seed_with_pass[64];
    ASSERT(bip39_mnemonic_to_seed(mnemonic, "", seed_no_pass), "seed no pass");
    ASSERT(bip39_mnemonic_to_seed(mnemonic, "mypassphrase", seed_with_pass), "seed with pass");

    wallet_source_hd_t ws_no, ws_pass;
    ASSERT(wallet_source_hd_init(&ws_no, seed_no_pass, 64, ctx, NULL, NULL, "regtest", HD_WALLET_LOOKAHEAD), "init no pass");
    ASSERT(wallet_source_hd_init(&ws_pass, seed_with_pass, 64, ctx, NULL, NULL, "regtest", HD_WALLET_LOOKAHEAD), "init with pass");

    /* Different passphrase must produce different addresses */
    ASSERT(memcmp(ws_no.spks[0], ws_pass.spks[0], 34) != 0, "different passphrase → different address");

    if (ws_no.base.free) ws_no.base.free(&ws_no.base);
    if (ws_pass.base.free) ws_pass.base.free(&ws_pass.base);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * Test 7: dynamic lookahead — init with lookahead=5, verify n_spks == 5
 * --------------------------------------------------------------------- */
int test_hd_wallet_dynamic_lookahead(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    ASSERT(ctx != NULL, "ctx");

    wallet_source_hd_t ws;
    ASSERT(wallet_source_hd_init(&ws, TEST_SEED, 32, ctx, NULL, NULL, "regtest", 5), "init lookahead=5");
    ASSERT(ws.n_spks == 5, "n_spks should be 5");
    ASSERT(ws.lookahead == 5, "lookahead field should be 5");
    /* All 5 SPKs should be valid P2TR */
    for (uint32_t i = 0; i < 5; i++) {
        ASSERT(ws.spks[i][0] == 0x51, "SPK[i] starts with OP_1");
        ASSERT(ws.spks[i][1] == 0x20, "SPK[i] has OP_PUSHBYTES_32");
    }

    if (ws.base.free) ws.base.free(&ws.base);
    secp256k1_context_destroy(ctx);
    return 1;
}
