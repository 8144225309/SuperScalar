/* test_signet_close_scale.c — conductor-lite cooperative-close SCALE harness.
 *
 * The cooperative close is a KEY-PATH spend of the factory funding output (the
 * N-of-N MuSig2 aggregate) to one output per funded client.  It never touches
 * the DW tree, so this harness needs no factory_t (no 53 MB/client), no daemons
 * and no tree ceremony: it simulates all N signers in one process, holding only
 * N keypairs + the running MuSig aggregate (~6 MB even at N=10,000, seconds).
 *
 * It exercises the REAL close-signing path (musig_sign_taproot -> the same
 * dynamic musig_sign_all_local proven to 2048 signers) and the REAL tx builder
 * (build_unsigned_tx / compute_taproot_sighash / finalize_signed_tx), then
 * self-verifies the aggregate before anything is broadcast.
 *
 * Purpose: prove close-tx construction + N-of-N aggregate signing + on-chain
 * size at scale, and pin the standardness ceiling with a real node error.
 *   Run 1 (~2,300 funded): ~99 KB close that lands on signet.
 *   Run 2 (~10,000 funded): ~430 KB close that our code builds + signs and the
 *          network rejects (tx-size / non-standard).
 *
 * Signet RPC orchestration (fund the address, find the vout, broadcast) is done
 * by the wrapper test_signet_close_scale.sh; this tool is pure crypto+tx and is
 * deterministic from SEED, so funds are always recoverable.
 *
 * Modes:
 *   test_signet_close_scale addr  <N> <SEED>
 *       -> prints the funding output x-only key (hex); wrapper funds rawtr(hex).
 *   test_signet_close_scale close <N> <M> <SEED> <FUND_TXID> <VOUT> <AMOUNT_SATS> <OUTFILE> [FEE_RATE]
 *       -> builds+signs+self-verifies the close paying M funded clients; writes
 *          the signed tx hex to OUTFILE; prints signer/output counts, serialized
 *          size, weight, vsize and the standardness verdict.
 */
#include "superscalar/musig.h"
#include "superscalar/tx_builder.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_musig.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int  hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

#define DUST_LIMIT      546
#define STD_MAX_VSIZE   100000   /* MAX_STANDARD_TX_WEIGHT / 4 */

/* Deterministic STRONG per-signer seckey (no weak keys on public signet):
   tagged_sha256("SSCloseScale", "SEED:i:bump") until a valid scalar. */
static int derive_seckey(const secp256k1_context *ctx, const char *seed,
                         size_t i, unsigned char sk[32]) {
    char buf[160];
    for (uint32_t bump = 0; bump < 1024; bump++) {
        int n = snprintf(buf, sizeof buf, "%s:%zu:%u", seed, i, bump);
        secp256k1_tagged_sha256(ctx, sk, (const unsigned char *)"SSCloseScale", 12,
                                (const unsigned char *)buf, (size_t)n);
        if (secp256k1_ec_seckey_verify(ctx, sk)) return 1;
    }
    return 0;
}

/* Aggregate N deterministic pubkeys; also return keypairs (caller frees). */
static int build_signers(const secp256k1_context *ctx, const char *seed, size_t N,
                         secp256k1_keypair **kps_out, secp256k1_pubkey **pks_out,
                         musig_keyagg_t *ka_out) {
    secp256k1_keypair *kps = calloc(N, sizeof(*kps));
    secp256k1_pubkey  *pks = calloc(N, sizeof(*pks));
    if (!kps || !pks) { free(kps); free(pks); return 0; }
    for (size_t i = 0; i < N; i++) {
        unsigned char sk[32];
        if (!derive_seckey(ctx, seed, i, sk) ||
            !secp256k1_keypair_create(ctx, &kps[i], sk) ||
            !secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) {
            free(kps); free(pks); return 0;
        }
    }
    if (!musig_aggregate_keys(ctx, ka_out, pks, N)) { free(kps); free(pks); return 0; }
    *kps_out = kps; *pks_out = pks;
    return 1;
}

/* BIP-341 key-path output key = internal(agg) tweaked by TapTweak(agg) (no script tree). */
static int funding_output_key(const secp256k1_context *ctx, const musig_keyagg_t *ka,
                              secp256k1_xonly_pubkey *out_key) {
    unsigned char xser[32], tweak[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, xser, &ka->agg_pubkey)) return 0;
    secp256k1_tagged_sha256(ctx, tweak, (const unsigned char *)"TapTweak", 8, xser, 32);
    secp256k1_musig_keyagg_cache cc = ka->cache;
    secp256k1_pubkey tpk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tpk, &cc, tweak)) return 0;
    return secp256k1_xonly_pubkey_from_pubkey(ctx, out_key, NULL, &tpk);
}

int main(int argc, char **argv) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    if (argc >= 4 && !strcmp(argv[1], "addr")) {
        size_t N = strtoull(argv[2], NULL, 10);
        const char *seed = argv[3];
        secp256k1_keypair *kps; secp256k1_pubkey *pks; musig_keyagg_t ka;
        if (!build_signers(ctx, seed, N, &kps, &pks, &ka)) { fprintf(stderr, "signer setup failed\n"); return 1; }
        secp256k1_xonly_pubkey ok; if (!funding_output_key(ctx, &ka, &ok)) { fprintf(stderr, "tweak failed\n"); return 1; }
        unsigned char ser[32]; secp256k1_xonly_pubkey_serialize(ctx, ser, &ok);
        char hex[65]; hex_encode(ser, 32, hex); hex[64] = 0;
        printf("%s\n", hex);   /* wrapper: bitcoin-cli deriveaddresses "rawtr(<hex>)" */
        free(kps); free(pks);
        return 0;
    }

    if (argc >= 9 && !strcmp(argv[1], "close")) {
        size_t N = strtoull(argv[2], NULL, 10);
        size_t M = strtoull(argv[3], NULL, 10);           /* funded clients */
        const char *seed = argv[4];
        const char *txid_hex = argv[5];
        uint32_t vout = (uint32_t)strtoul(argv[6], NULL, 10);
        uint64_t amount = strtoull(argv[7], NULL, 10);    /* funding UTXO value */
        const char *outfile = argv[8];
        uint64_t fee_rate = (argc >= 10) ? strtoull(argv[9], NULL, 10) : 1;  /* sat/vB */

        if (M + 1 > N) { fprintf(stderr, "need funded M(%zu)+LSP <= N(%zu)\n", M, N); return 1; }

        secp256k1_keypair *kps; secp256k1_pubkey *pks; musig_keyagg_t ka;
        if (!build_signers(ctx, seed, N, &kps, &pks, &ka)) { fprintf(stderr, "signer setup failed\n"); return 1; }

        secp256k1_xonly_pubkey fund_key;
        if (!funding_output_key(ctx, &ka, &fund_key)) { fprintf(stderr, "tweak failed\n"); return 1; }
        unsigned char funding_spk[34]; build_p2tr_script_pubkey(funding_spk, &fund_key);

        /* Close outputs: [0] = LSP (signer 0), [1..M] = funded clients (signers 1..M).
           Each funded client is paid to rawtr(its own x-only key) — recoverable from SEED.
           Empty channels (signers M+1..N-1) get nothing — the real dust-fold behavior. */
        tx_output_t *outs = calloc(M + 1, sizeof(tx_output_t));
        if (!outs) { fprintf(stderr, "oom outputs\n"); return 1; }
        size_t n_out = 1;
        uint64_t client_sum = 0;
        for (size_t i = 1; i <= M; i++) {
            uint64_t amt = 700 + (uint64_t)(i % 600);   /* 700..1299 sats, all > dust, varied */
            secp256k1_xonly_pubkey xo; secp256k1_keypair_xonly_pub(ctx, &xo, NULL, &kps[i]);
            build_p2tr_script_pubkey(outs[n_out].script_pubkey, &xo);
            outs[n_out].script_pubkey_len = 34;
            outs[n_out].amount_sats = amt;
            client_sum += amt;
            n_out++;
        }
        /* fee from an estimate of the final vsize (key-path: witness ~ negligible weight) */
        uint64_t est_vsize = 11 /*version+locktime+counts*/ + 58 /*p2tr input*/ + (uint64_t)n_out * 43;
        uint64_t fee = est_vsize * fee_rate;
        if (amount < client_sum + fee + DUST_LIMIT) {
            fprintf(stderr, "funding %llu too small for %zu clients (need >= %llu + fee %llu + LSP dust)\n",
                    (unsigned long long)amount, M, (unsigned long long)client_sum, (unsigned long long)fee);
            return 1;
        }
        secp256k1_xonly_pubkey lsp_xo; secp256k1_keypair_xonly_pub(ctx, &lsp_xo, NULL, &kps[0]);
        build_p2tr_script_pubkey(outs[0].script_pubkey, &lsp_xo);
        outs[0].script_pubkey_len = 34;
        outs[0].amount_sats = amount - client_sum - fee;

        /* Build, sighash, N-of-N sign (key-path, no script tree), self-verify. */
        unsigned char txid_le[32];
        if (hex_decode(txid_hex, txid_le, 32) != 32) { fprintf(stderr, "bad txid\n"); return 1; }
        reverse_bytes(txid_le, 32);

        tx_buf_t utx; tx_buf_init(&utx, 1u << 20);
        if (!build_unsigned_tx(&utx, NULL, txid_le, vout, 0xFFFFFFFDu, outs, n_out)) { fprintf(stderr, "build_unsigned_tx fail\n"); return 1; }
        unsigned char sighash[32];
        if (!compute_taproot_sighash(sighash, utx.data, utx.len, 0, funding_spk, 34, amount, 0xFFFFFFFDu)) { fprintf(stderr, "sighash fail\n"); return 1; }
        unsigned char sig[64];
        if (!musig_sign_taproot(ctx, sig, sighash, kps, N, &ka, NULL)) { fprintf(stderr, "musig_sign_taproot fail\n"); return 1; }
        if (!secp256k1_schnorrsig_verify(ctx, sig, sighash, 32, &fund_key)) {
            fprintf(stderr, "SELF-VERIFY FAILED — not writing tx\n"); return 1;
        }
        tx_buf_t stx; tx_buf_init(&stx, 1u << 20);
        if (!finalize_signed_tx(&stx, utx.data, utx.len, sig)) { fprintf(stderr, "finalize fail\n"); return 1; }

        uint64_t weight = (uint64_t)utx.len * 4 + (stx.len - utx.len);  /* non-witness*4 + witness */
        uint64_t vsize  = (weight + 3) / 4;

        FILE *f = fopen(outfile, "w");
        if (!f) { fprintf(stderr, "cannot write %s\n", outfile); return 1; }
        char *hx = malloc(stx.len * 2 + 1); hex_encode(stx.data, stx.len, hx); hx[stx.len * 2] = 0;
        fputs(hx, f); fclose(f);

        printf("close-scale: signers=%zu funded=%zu outputs=%zu\n", N, M, n_out);
        printf("  in=%llu client_sum=%llu fee=%llu(@%llu sat/vB) lsp=%llu conserves=%s\n",
               (unsigned long long)amount, (unsigned long long)client_sum, (unsigned long long)fee,
               (unsigned long long)fee_rate, (unsigned long long)outs[0].amount_sats,
               (amount == outs[0].amount_sats + client_sum + fee) ? "yes" : "NO");
        printf("  serialized=%zu B  weight=%llu wu  vsize=%llu vB  self_verify=OK\n",
               stx.len, (unsigned long long)weight, (unsigned long long)vsize);
        printf("  standardness(<=%d vB): %s\n", STD_MAX_VSIZE,
               vsize <= STD_MAX_VSIZE ? "WITHIN — expect relay" : "OVER — expect tx-size rejection");
        printf("  hex written to %s\n", outfile);
        free(hx); free(outs); free(kps); free(pks);
        return 0;
    }

    if (argc >= 9 && !strcmp(argv[1], "sweep")) {
        /* Spend the N-of-N funding UTXO to a single dest scriptPubKey (recover funds,
           e.g. after RUN 2's oversized close is rejected). N-of-N key-path signed. */
        size_t N = strtoull(argv[2], NULL, 10);
        const char *seed = argv[3];
        const char *txid_hex = argv[4];
        uint32_t vout = (uint32_t)strtoul(argv[5], NULL, 10);
        uint64_t amount = strtoull(argv[6], NULL, 10);
        const char *dest_spk_hex = argv[7];
        const char *outfile = argv[8];
        uint64_t fee_rate = (argc >= 10) ? strtoull(argv[9], NULL, 10) : 1;

        secp256k1_keypair *kps; secp256k1_pubkey *pks; musig_keyagg_t ka;
        if (!build_signers(ctx, seed, N, &kps, &pks, &ka)) { fprintf(stderr, "signer setup failed\n"); return 1; }
        secp256k1_xonly_pubkey fund_key;
        if (!funding_output_key(ctx, &ka, &fund_key)) { fprintf(stderr, "tweak failed\n"); return 1; }
        unsigned char funding_spk[34]; build_p2tr_script_pubkey(funding_spk, &fund_key);

        tx_output_t o; memset(&o, 0, sizeof o);
        if (hex_decode(dest_spk_hex, o.script_pubkey, 34) < 1) { fprintf(stderr, "bad dest spk\n"); return 1; }
        o.script_pubkey_len = (strlen(dest_spk_hex) / 2);
        uint64_t fee = (uint64_t)(11 + 58 + 43) * fee_rate;
        if (amount <= fee + DUST_LIMIT) { fprintf(stderr, "amount too small for fee\n"); return 1; }
        o.amount_sats = amount - fee;

        unsigned char txid_le[32];
        if (hex_decode(txid_hex, txid_le, 32) != 32) { fprintf(stderr, "bad txid\n"); return 1; }
        reverse_bytes(txid_le, 32);
        tx_buf_t utx; tx_buf_init(&utx, 4096);
        if (!build_unsigned_tx(&utx, NULL, txid_le, vout, 0xFFFFFFFDu, &o, 1)) { fprintf(stderr, "build fail\n"); return 1; }
        unsigned char sighash[32];
        if (!compute_taproot_sighash(sighash, utx.data, utx.len, 0, funding_spk, 34, amount, 0xFFFFFFFDu)) { fprintf(stderr, "sighash fail\n"); return 1; }
        unsigned char sig[64];
        if (!musig_sign_taproot(ctx, sig, sighash, kps, N, &ka, NULL)) { fprintf(stderr, "sign fail\n"); return 1; }
        if (!secp256k1_schnorrsig_verify(ctx, sig, sighash, 32, &fund_key)) { fprintf(stderr, "SELF-VERIFY FAILED\n"); return 1; }
        tx_buf_t stx; tx_buf_init(&stx, 4096);
        if (!finalize_signed_tx(&stx, utx.data, utx.len, sig)) { fprintf(stderr, "finalize fail\n"); return 1; }
        FILE *f = fopen(outfile, "w");
        if (!f) { fprintf(stderr, "cannot write %s\n", outfile); return 1; }
        char *hx = malloc(stx.len * 2 + 1); hex_encode(stx.data, stx.len, hx); hx[stx.len * 2] = 0;
        fputs(hx, f); fclose(f);
        printf("sweep: signers=%zu in=%llu out=%llu fee=%llu self_verify=OK -> %s\n",
               N, (unsigned long long)amount, (unsigned long long)o.amount_sats, (unsigned long long)fee, outfile);
        free(hx); free(kps); free(pks);
        return 0;
    }

    fprintf(stderr,
        "usage:\n"
        "  %s addr  <N> <SEED>\n"
        "  %s close <N> <M_FUNDED> <SEED> <FUND_TXID> <VOUT> <AMOUNT_SATS> <OUTFILE> [FEE_RATE]\n"
        "  %s sweep <N> <SEED> <FUND_TXID> <VOUT> <AMOUNT_SATS> <DEST_SPK_HEX> <OUTFILE> [FEE_RATE]\n",
        argv[0], argv[0], argv[0]);
    return 1;
}
