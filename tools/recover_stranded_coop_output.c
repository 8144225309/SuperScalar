/*
 * recover_stranded_coop_output: sweep a satoshis-locked N-of-N factory
 * funding output back to a caller-controlled address, using all N
 * participants' seckeys in an offline MuSig2 ceremony.
 *
 * Context: prior to the lsp_close_spk fix (PR #68), cooperative-close tx
 * routed the LSP's share to factory->funding_spk — the N-of-N MuSig
 * address. Those outputs are only spendable if all N parties re-cooperate.
 * For our signet test factories we hold every participant's seckey, so we
 * run the ceremony in-process and produce a valid BIP-341 key-path
 * signature.
 *
 * Usage:
 *   recover_stranded_coop_output \
 *     --input-txid   <hex64> \
 *     --input-vout   <n> \
 *     --input-amount <sats> \
 *     --lsp-seckey   <hex64> \
 *     --client-seckeys <hex64>,<hex64>,...  (variadic, n_clients of them) \
 *     --dest-spk     <hex>   (34-byte P2TR SPK to send to) \
 *     --fee          <sats> \
 *     [--broadcast]          (if omitted, just print tx hex)
 *
 * The funding_spk is reconstructed internally as:
 *     MuSig-KeyAgg(pubkeys...)  then BIP-341 taptweak with empty merkle.
 */

#include "superscalar/musig.h"
#include "superscalar/tx_builder.h"
#include "superscalar/regtest.h"
#include "superscalar/sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int  hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

static int parse_hex32(const char *hex, unsigned char out[32]) {
    if (strlen(hex) != 64) return 0;
    return hex_decode(hex, out, 32);
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s --input-txid HEX64 --input-vout N --input-amount SATS\n"
        "       --lsp-seckey HEX64 --client-seckeys HEX64,HEX64,...\n"
        "       --dest-spk HEX --fee SATS [--broadcast] [--network signet]\n", argv0);
}

int main(int argc, char **argv) {
    const char *in_txid_hex = NULL;
    uint32_t in_vout = 0;
    uint64_t in_amount = 0;
    const char *lsp_sk_hex = NULL;
    const char *client_sks_csv = NULL;
    const char *dest_spk_hex = NULL;
    uint64_t fee = 500;
    int do_broadcast = 0;
    const char *network = "signet";

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--input-txid")    && i+1 < argc) in_txid_hex   = argv[++i];
        else if (!strcmp(argv[i], "--input-vout")    && i+1 < argc) in_vout       = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--input-amount")  && i+1 < argc) in_amount     = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--lsp-seckey")    && i+1 < argc) lsp_sk_hex    = argv[++i];
        else if (!strcmp(argv[i], "--client-seckeys")&& i+1 < argc) client_sks_csv= argv[++i];
        else if (!strcmp(argv[i], "--dest-spk")      && i+1 < argc) dest_spk_hex  = argv[++i];
        else if (!strcmp(argv[i], "--fee")           && i+1 < argc) fee           = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--broadcast"))                   do_broadcast  = 1;
        else if (!strcmp(argv[i], "--network")       && i+1 < argc) network       = argv[++i];
        else { usage(argv[0]); return 1; }
    }
    if (!in_txid_hex || !lsp_sk_hex || !client_sks_csv || !dest_spk_hex || in_amount == 0) {
        usage(argv[0]); return 1;
    }
    if (in_amount <= fee) {
        fprintf(stderr, "input_amount <= fee\n"); return 1;
    }

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Parse seckeys. Party 0 = LSP, 1..n = clients. */
    unsigned char seckeys[16][32];
    size_t n_signers = 1;
    if (!parse_hex32(lsp_sk_hex, seckeys[0])) {
        fprintf(stderr, "bad lsp-seckey hex\n"); return 1;
    }
    /* split client_sks_csv on ',' */
    {
        char buf[1024]; strncpy(buf, client_sks_csv, sizeof(buf) - 1); buf[sizeof(buf)-1] = '\0';
        char *save = NULL;
        for (char *tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
            if (n_signers >= 16) { fprintf(stderr, "too many signers\n"); return 1; }
            if (!parse_hex32(tok, seckeys[n_signers])) {
                fprintf(stderr, "bad client seckey hex: %s\n", tok); return 1;
            }
            n_signers++;
        }
    }
    printf("Signers: %zu (1 LSP + %zu clients)\n", n_signers, n_signers - 1);

    /* Derive keypairs + pubkeys. */
    secp256k1_keypair kps[16];
    secp256k1_pubkey  pks[16];
    for (size_t i = 0; i < n_signers; i++) {
        if (!secp256k1_keypair_create(ctx, &kps[i], seckeys[i])) {
            fprintf(stderr, "keypair_create failed (signer %zu)\n", i); return 1;
        }
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) {
            fprintf(stderr, "keypair_pub failed (signer %zu)\n", i); return 1;
        }
    }

    /* Reconstruct MuSig aggregate + BIP-341 taptweak-with-empty-merkle SPK. */
    musig_keyagg_t keyagg;
    if (!musig_aggregate_keys(ctx, &keyagg, pks, n_signers)) {
        fprintf(stderr, "musig_aggregate_keys failed\n"); return 1;
    }

    unsigned char agg_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, agg_ser, &keyagg.agg_pubkey)) return 1;
    unsigned char tweak[32];
    sha256_tagged("TapTweak", agg_ser, 32, tweak);

    musig_keyagg_t ka_for_spk = keyagg;  /* don't mutate original */
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &ka_for_spk.cache, tweak)) {
        fprintf(stderr, "tweak_add failed\n"); return 1;
    }
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) return 1;

    unsigned char reconstructed_spk[34];
    build_p2tr_script_pubkey(reconstructed_spk, &tweaked_xonly);
    {
        char hx[69]; hex_encode(reconstructed_spk, 34, hx); hx[68] = '\0';
        printf("Reconstructed funding SPK: %s\n", hx);
    }

    /* Parse dest SPK. */
    size_t dest_spk_len = strlen(dest_spk_hex) / 2;
    if (dest_spk_len > 64) { fprintf(stderr, "dest-spk too long\n"); return 1; }
    unsigned char dest_spk[64];
    if (!hex_decode(dest_spk_hex, dest_spk, dest_spk_len)) {
        fprintf(stderr, "bad dest-spk hex\n"); return 1;
    }

    /* Build unsigned tx: 1 in (stranded UTXO) → 1 out (dest - fee). */
    unsigned char in_txid_internal[32];
    if (!hex_decode(in_txid_hex, in_txid_internal, 32)) {
        fprintf(stderr, "bad input-txid hex\n"); return 1;
    }
    reverse_bytes(in_txid_internal, 32);

    tx_output_t outs[1];
    memset(outs, 0, sizeof(outs));
    outs[0].amount_sats = in_amount - fee;
    memcpy(outs[0].script_pubkey, dest_spk, dest_spk_len);
    outs[0].script_pubkey_len = dest_spk_len;

    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 256);
    if (!build_unsigned_tx(&unsigned_tx, NULL, in_txid_internal, in_vout,
                            0xFFFFFFFEu, outs, 1)) {
        fprintf(stderr, "build_unsigned_tx failed\n"); return 1;
    }

    /* BIP-341 sighash over the single input. */
    unsigned char sighash[32];
    if (!compute_taproot_sighash(sighash, unsigned_tx.data, unsigned_tx.len,
                                   0, reconstructed_spk, 34,
                                   in_amount, 0xFFFFFFFEu)) {
        fprintf(stderr, "compute_taproot_sighash failed\n"); return 1;
    }

    /* Offline MuSig2 ceremony: all n signers, BIP-341 tweak with empty merkle. */
    unsigned char sig64[64];
    if (!musig_sign_taproot(ctx, sig64, sighash, kps, n_signers, &keyagg, NULL)) {
        fprintf(stderr, "musig_sign_taproot failed\n"); return 1;
    }

    /* Verify sig against tweaked xonly — pre-flight before broadcast. */
    if (!secp256k1_schnorrsig_verify(ctx, sig64, sighash, 32, &tweaked_xonly)) {
        fprintf(stderr, "Schnorr self-verify FAILED — aborting broadcast\n"); return 1;
    }
    printf("Schnorr self-verify: OK\n");

    /* Attach witness + print hex. */
    tx_buf_t signed_tx;
    tx_buf_init(&signed_tx, 256);
    if (!finalize_signed_tx(&signed_tx, unsigned_tx.data, unsigned_tx.len, sig64)) {
        fprintf(stderr, "finalize_signed_tx failed\n"); return 1;
    }
    char tx_hex[signed_tx.len * 2 + 1];
    hex_encode(signed_tx.data, signed_tx.len, tx_hex);
    tx_hex[signed_tx.len * 2] = '\0';
    printf("Signed tx hex:\n%s\n", tx_hex);

    /* Broadcast via bitcoin-cli if requested. */
    if (do_broadcast) {
        char cmd[8192];
        const char *rpc_args = "";
        if (!strcmp(network, "signet")) {
            rpc_args = "-signet -rpcuser=signetrpc -rpcpassword=signetrpcpass123 -rpcport=38332";
        } else if (!strcmp(network, "regtest")) {
            rpc_args = "-regtest -rpcuser=rpcuser -rpcpassword=rpcpass -rpcport=18443";
        } else {
            fprintf(stderr, "unknown network %s\n", network); return 1;
        }
        snprintf(cmd, sizeof(cmd),
                 "bitcoin-cli %s sendrawtransaction %s", rpc_args, tx_hex);
        printf("Broadcasting: %s\n", cmd);
        int rc = system(cmd);
        if (rc != 0) {
            fprintf(stderr, "broadcast failed (exit %d)\n", rc);
            return 1;
        }
        printf("Broadcast OK\n");
    } else {
        printf("(Not broadcast — re-run with --broadcast to send)\n");
    }

    secp256k1_context_destroy(ctx);
    return 0;
}
