/* test_inproc_factory_lifecycle.c — single-process REAL-factory lifecycle at scale.
 *
 * Builds a REAL Decker-Wattenhofer factory (real tree + real node signatures) with
 * N+1 signers, then cooperatively closes it to per-client outputs — all in ONE
 * process holding ONE factory_t (~53 MB), no daemons, no wire, no reconnect races.
 * This is why it fits a small box: the 70 MB/client cost of the daemon harness was
 * N separate factory_t copies; here there is exactly one.
 *
 * Uses the in-process factory API the test suite already exercises:
 *   factory_init -> factory_set_arity(PS) -> factory_set_funding ->
 *   factory_build_tree -> factory_sign_all_with_retry ->
 *   factory_build_cooperative_close   (which uses the >=253-output sighash fix)
 *
 * Milestone 1 (this file): CREATE + SIGN + CLOSE at N, proving one-process scale.
 * Payments are modelled as a per-client settlement distribution; faithful HTLC
 * flow (factory_advance_leaf) is milestone 2.
 *
 * Modes (crypto only; signet fund/broadcast handled by the wrapper .sh):
 *   addr      <N> <SEED>                    -> funding output x-only key (hex)
 *   lifecycle <N> <M_FUNDED> <SEED> <FUND_TXID> <VOUT> <AMOUNT> <OUTFILE> [FEE_RATE]
 *             -> build+sign the factory, cooperatively close to M funded clients,
 *                write the signed close hex; print tree/sign/close status + size.
 */
#include "superscalar/factory.h"
#include "superscalar/musig.h"
#include "superscalar/tx_builder.h"
#include "superscalar/sha256.h"
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

#define DUST_LIMIT 546

static int derive_seckey(const secp256k1_context *ctx, const char *seed, size_t i, unsigned char sk[32]) {
    char buf[160];
    for (uint32_t b = 0; b < 1024; b++) {
        int n = snprintf(buf, sizeof buf, "%s:%zu:%u", seed, i, b);
        secp256k1_tagged_sha256(ctx, sk, (const unsigned char *)"SSInprocFactory", 15,
                                (const unsigned char *)buf, (size_t)n);
        if (secp256k1_ec_seckey_verify(ctx, sk)) return 1;
    }
    return 0;
}

/* N+1 keypairs (idx 0 = LSP) + the taproot funding output key/spk. */
static int build_keys(const secp256k1_context *ctx, const char *seed, size_t n_signers,
                      secp256k1_keypair *kps, secp256k1_pubkey *pks,
                      secp256k1_xonly_pubkey *fund_key, unsigned char fund_spk[34]) {
    for (size_t i = 0; i < n_signers; i++) {
        unsigned char sk[32];
        if (!derive_seckey(ctx, seed, i, sk) ||
            !secp256k1_keypair_create(ctx, &kps[i], sk) ||
            !secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks, n_signers)) return 0;
    unsigned char ser[32], tweak[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, ser, &ka.agg_pubkey)) return 0;
    sha256_tagged("TapTweak", ser, 32, tweak);
    musig_keyagg_t tmp = ka; secp256k1_pubkey tw;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tw, &tmp.cache, tweak)) return 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, fund_key, NULL, &tw)) return 0;
    build_p2tr_script_pubkey(fund_spk, fund_key);
    return 1;
}

int main(int argc, char **argv) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    if (argc >= 4 && !strcmp(argv[1], "addr")) {
        size_t N = strtoull(argv[2], NULL, 10), ns = N + 1;
        secp256k1_keypair *kps = calloc(ns, sizeof(*kps));
        secp256k1_pubkey  *pks = calloc(ns, sizeof(*pks));
        secp256k1_xonly_pubkey fk; unsigned char spk[34];
        if (!kps || !pks || !build_keys(ctx, argv[3], ns, kps, pks, &fk, spk)) { fprintf(stderr, "keygen failed\n"); return 1; }
        unsigned char ser[32]; secp256k1_xonly_pubkey_serialize(ctx, ser, &fk);
        char hex[65]; hex_encode(ser, 32, hex); hex[64] = 0; printf("%s\n", hex);
        return 0;
    }

    if (argc >= 9 && !strcmp(argv[1], "lifecycle")) {
        size_t N = strtoull(argv[2], NULL, 10);       /* clients */
        size_t M = strtoull(argv[3], NULL, 10);       /* funded clients */
        const char *seed = argv[4];
        const char *txid_hex = argv[5];
        uint32_t vout = (uint32_t)strtoul(argv[6], NULL, 10);
        uint64_t amount = strtoull(argv[7], NULL, 10);
        const char *outfile = argv[8];
        uint64_t fee_rate = (argc >= 10) ? strtoull(argv[9], NULL, 10) : 1;
        size_t ns = N + 1;
        if (M > N) { fprintf(stderr, "M(%zu) > N(%zu)\n", M, N); return 1; }

        secp256k1_keypair *kps = calloc(ns, sizeof(*kps));
        secp256k1_pubkey  *pks = calloc(ns, sizeof(*pks));
        secp256k1_xonly_pubkey fund_key; unsigned char fund_spk[34];
        if (!kps || !pks || !build_keys(ctx, seed, ns, kps, pks, &fund_key, fund_spk)) { fprintf(stderr, "keygen failed\n"); return 1; }

        /* --- REAL factory: init -> set_funding -> build_tree -> sign_all --- */
        factory_t *f = calloc(1, sizeof(factory_t));
        if (!f) { fprintf(stderr, "oom factory_t (%zu MB)\n", sizeof(factory_t) >> 20); return 1; }
        /* Config sized to THIS factory: max_signers = ns.  The default cap is
           FACTORY_MAX_SIGNERS (256), which would reject N>255 at factory_init /
           factory_build_tree.  We raise the cap PER INSTANCE rather than bumping
           the compile-time #define, so the daemon's fixed [FACTORY_MAX_SIGNERS]
           arrays stay small — only this single-process manager grows.  max_nodes
           is seeded generously for the PS shape (~4 nodes/client); build_tree
           grows it by realloc if needed. */
        factory_config_t cfg; factory_config_default(&cfg);
        cfg.max_signers = (uint32_t)ns;
        cfg.max_leaves  = (uint32_t)(N + 1);          /* PS: one leaf per client */
        cfg.max_nodes   = (uint32_t)(ns * 8 + 64);
        factory_init_with_config(f, ctx, kps, ns, 1, 4, &cfg);
        factory_set_arity(f, FACTORY_ARITY_PS);
        unsigned char txid_le[32];
        if (hex_decode(txid_hex, txid_le, 32) != 32) { fprintf(stderr, "bad txid\n"); return 1; }
        reverse_bytes(txid_le, 32);
        factory_set_funding(f, txid_le, vout, amount, fund_spk, 34);
        if (!factory_build_tree(f)) { fprintf(stderr, "factory_build_tree FAILED\n"); return 1; }
        printf("  factory: tree built (%zu nodes, %zu-signer PS)\n", f->n_nodes, ns);
        if (!factory_sign_all_with_retry(f, 3)) { fprintf(stderr, "factory_sign_all FAILED\n"); return 1; }
        printf("  factory: all nodes signed\n");

        /* --- Settlement distribution: M funded clients (varied), LSP gets remainder.
               (Milestone 1: models payment outcome; faithful HTLC flow is next.) --- */
        tx_output_t *outs = calloc(M + 1, sizeof(tx_output_t));
        size_t n_out = 1; uint64_t client_sum = 0;
        for (size_t i = 1; i <= M; i++) {
            uint64_t amt = 700 + (uint64_t)(i % 600);
            secp256k1_xonly_pubkey xo; secp256k1_keypair_xonly_pub(ctx, &xo, NULL, &kps[i]);
            build_p2tr_script_pubkey(outs[n_out].script_pubkey, &xo);
            outs[n_out].script_pubkey_len = 34; outs[n_out].amount_sats = amt;
            client_sum += amt; n_out++;
        }
        uint64_t est_vsize = 11 + 58 + (uint64_t)n_out * 43;
        uint64_t fee = est_vsize * fee_rate;
        if (amount < client_sum + fee + DUST_LIMIT) { fprintf(stderr, "funding too small\n"); return 1; }
        secp256k1_xonly_pubkey lxo; secp256k1_keypair_xonly_pub(ctx, &lxo, NULL, &kps[0]);
        build_p2tr_script_pubkey(outs[0].script_pubkey, &lxo);
        outs[0].script_pubkey_len = 34; outs[0].amount_sats = amount - client_sum - fee;

        /* --- Cooperative close (uses the >=253-output sighash fix) --- */
        tx_buf_t close_tx; tx_buf_init(&close_tx, 1u << 20);
        if (!factory_build_cooperative_close(f, &close_tx, NULL, outs, n_out, 0)) {
            fprintf(stderr, "factory_build_cooperative_close FAILED\n"); return 1;
        }
        FILE *fp = fopen(outfile, "w"); if (!fp) { fprintf(stderr, "cannot write %s\n", outfile); return 1; }
        char *hx = malloc(close_tx.len * 2 + 1); hex_encode(close_tx.data, close_tx.len, hx); hx[close_tx.len * 2] = 0;
        fputs(hx, fp); fclose(fp);
        printf("inproc-lifecycle: signers=%zu funded=%zu outputs=%zu  close_tx=%zu B  conserves=%s\n",
               ns, M, n_out, close_tx.len,
               (amount == outs[0].amount_sats + client_sum + fee) ? "yes" : "NO");
        printf("  hex -> %s\n", outfile);
        free(hx); free(outs);
        return 0;
    }

    fprintf(stderr,
        "usage:\n"
        "  %s addr      <N> <SEED>\n"
        "  %s lifecycle <N> <M_FUNDED> <SEED> <FUND_TXID> <VOUT> <AMOUNT> <OUTFILE> [FEE_RATE]\n",
        argv[0], argv[0]);
    return 1;
}
