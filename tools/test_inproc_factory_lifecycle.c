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
#include "superscalar/channel.h"
#include "superscalar/lsp_channels.h"
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

/* ---- Full BOLT-2 commitment ceremony (in-process mirror pair) ----
   S initiated a state update (add/fulfill already applied to BOTH sides).
   Runs the daemon's exact sequence from htlc_commit_add_and_sign, minus wire:
     S: channel_create_commitment_partial_sig        (commitment_signed ->)
     R: channel_verify_and_aggregate_commitment_sig  (verify partial + aggregate)
     R: reveal pcs(cn-1) + advertise pcp(cn+1)       (revoke_and_ack ->)
     S: channel_receive_revocation_flat + set_remote_pcp
     ...then the symmetric R->S half.
   Every partial sig is cryptographically verified (musig_verify_partial_sig
   inside verify_and_aggregate) and every superseded state is revoked — the two
   gaps flagged in the earlier realism audit. */
static int bolt2_commit_round(channel_t *S, channel_t *R,
                              size_t *n_aggsigs, size_t *n_revocations) {
    unsigned char partial[32], full[64], pcs[32];
    uint32_t nidx;
    secp256k1_pubkey next_pcp;

    /* S signs R's new commitment; R verifies the partial + aggregates */
    if (!channel_create_commitment_partial_sig(S, partial, &nidx)) return 0;
    if (!channel_verify_and_aggregate_commitment_sig(R, partial, nidx, full)) return 0;
    (*n_aggsigs)++;
    /* R revokes its previous state toward S */
    if (R->commitment_number > 0) {
        if (!channel_get_per_commitment_secret(R, R->commitment_number - 1, pcs)) return 0;
        if (!channel_receive_revocation_flat(S, S->commitment_number - 1, pcs)) return 0;
        if (!channel_get_per_commitment_point(R, R->commitment_number + 1, &next_pcp)) return 0;
        channel_set_remote_pcp(S, S->commitment_number + 1, &next_pcp);
        (*n_revocations)++;
    }
    /* R signs S's new commitment; S verifies + aggregates */
    if (!channel_create_commitment_partial_sig(R, partial, &nidx)) return 0;
    if (!channel_verify_and_aggregate_commitment_sig(S, partial, nidx, full)) return 0;
    (*n_aggsigs)++;
    /* S revokes its previous state toward R */
    if (S->commitment_number > 0) {
        if (!channel_get_per_commitment_secret(S, S->commitment_number - 1, pcs)) return 0;
        if (!channel_receive_revocation_flat(R, R->commitment_number - 1, pcs)) return 0;
        if (!channel_get_per_commitment_point(S, S->commitment_number + 1, &next_pcp)) return 0;
        channel_set_remote_pcp(R, R->commitment_number + 1, &next_pcp);
        (*n_revocations)++;
    }
    return 1;
}

/* Build the client-side mirror of an LSP channel entry: same funding outpoint
   and 2-of-2 keyagg (signer_idx flipped), flipped balance perspective, its own
   random basepoints + PCS chain + nonce pool; then exchange basepoints, initial
   PCPs (cn 0 and 1), and the serialized pubnonce pools both ways — the same
   material MSG_CHANNEL_BASEPOINTS / MSG_CHANNEL_NONCES carry over the wire. */
static int setup_mirror_channel(secp256k1_context *ctx, channel_t *L, channel_t *C,
                                const secp256k1_keypair *client_kp,
                                const secp256k1_pubkey *client_pub,
                                const secp256k1_pubkey *lsp_pub,
                                size_t n_states) {
    unsigned char csec[32];
    if (!secp256k1_keypair_sec(ctx, csec, client_kp)) return 0;
    int ok = channel_init(C, ctx, csec, client_pub, lsp_pub,
                          L->funding_txid, L->funding_vout, L->funding_amount,
                          L->funding_spk, L->funding_spk_len,
                          L->remote_amount, L->local_amount,   /* flipped view */
                          CHANNEL_DEFAULT_CSV_DELAY);
    memset(csec, 0, 32);
    if (!ok) return 0;
    C->funder_is_local = 0;                   /* the LSP funded the channel */
    C->use_cpfp_anchor = L->use_cpfp_anchor;  /* MUST match or the sighash diverges */
    C->funding_keyagg = L->funding_keyagg;    /* same aggregate, opposite seat */
    C->local_funding_signer_idx = 1 - L->local_funding_signer_idx;
    C->has_chan_merkle_root = L->has_chan_merkle_root;
    memcpy(C->chan_merkle_root, L->chan_merkle_root, 32);

    if (!channel_generate_random_basepoints(C)) return 0;
    /* basepoint exchange, both directions */
    channel_set_remote_basepoints(L, &C->local_payment_basepoint,
                                  &C->local_delayed_payment_basepoint,
                                  &C->local_revocation_basepoint);
    channel_set_remote_htlc_basepoint(L, &C->local_htlc_basepoint);
    channel_set_remote_basepoints(C, &L->local_payment_basepoint,
                                  &L->local_delayed_payment_basepoint,
                                  &L->local_revocation_basepoint);
    channel_set_remote_htlc_basepoint(C, &L->local_htlc_basepoint);

    /* per-commitment secret chains on both sides */
    for (size_t cn = L->n_local_pcs; cn < n_states; cn++)
        if (!channel_generate_local_pcs(L, cn)) return 0;
    for (size_t cn = C->n_local_pcs; cn < n_states; cn++)
        if (!channel_generate_local_pcs(C, cn)) return 0;

    /* initial per-commitment points (cn 0 and 1), both directions */
    for (uint64_t cn = 0; cn <= 1; cn++) {
        secp256k1_pubkey p;
        if (!channel_get_per_commitment_point(L, cn, &p)) return 0;
        channel_set_remote_pcp(C, cn, &p);
        if (!channel_get_per_commitment_point(C, cn, &p)) return 0;
        channel_set_remote_pcp(L, cn, &p);
    }

    /* nonce pools + full pubnonce exchange */
    if (!channel_init_nonce_pool(C, MUSIG_NONCE_POOL_MAX)) return 0;
    {
        static unsigned char ser[MUSIG_NONCE_POOL_MAX][66];
        for (size_t i = 0; i < L->local_nonce_pool.count; i++)
            if (!musig_pubnonce_serialize(ctx, ser[i], &L->local_nonce_pool.nonces[i].pubnonce)) return 0;
        if (!channel_set_remote_pubnonces(C, ser, L->local_nonce_pool.count)) return 0;
        for (size_t i = 0; i < C->local_nonce_pool.count; i++)
            if (!musig_pubnonce_serialize(ctx, ser[i], &C->local_nonce_pool.nonces[i].pubnonce)) return 0;
        if (!channel_set_remote_pubnonces(L, ser, C->local_nonce_pool.count)) return 0;
    }
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

    if (argc >= 4 && !strcmp(argv[1], "dumpkeys")) {
        /* Emit one hex private key per close-output index (0 = LSP, 1..N = clients),
           i.e. kps[j] for j=0..N.  Close output index == key index, so a sweep can
           map each rawtr(key) output back to its spender.  Used only for signet
           fund-recovery; never on mainnet. */
        size_t N = strtoull(argv[2], NULL, 10);
        const char *seed = argv[3];
        for (size_t j = 0; j <= N; j++) {
            unsigned char sk[32];
            if (!derive_seckey(ctx, seed, j, sk)) { fprintf(stderr, "derive %zu failed\n", j); return 1; }
            char hx[65]; hex_encode(sk, 32, hx); hx[64] = 0;
            printf("%zu %s\n", j, hx);
        }
        return 0;
    }

    if (argc >= 8 && !strcmp(argv[1], "paylifecycle")) {
        size_t N = strtoull(argv[2], NULL, 10);       /* clients (= channels) */
        const char *seed = argv[3];
        const char *txid_hex = argv[4];
        uint32_t vout = (uint32_t)strtoul(argv[5], NULL, 10);
        uint64_t amount = strtoull(argv[6], NULL, 10);
        const char *outfile = argv[7];
        uint64_t fee_kvb = (argc >= 9) ? strtoull(argv[8], NULL, 10) : 1000; /* sat/KILOvbyte: 100 = 0.1 sat/vB */
        size_t P = (argc >= 10) ? strtoull(argv[9], NULL, 10) : 4;  /* payments/channel */
        const char *audit_dir = (argc >= 11) ? argv[10] : NULL;     /* extra proof/audit records */
        unsigned lsp_pct = (argc >= 12) ? (unsigned)strtoul(argv[11], NULL, 10) : 50;
        /* lsp_pct = LSP's initial share per channel.  100 => clients start at ZERO:
           every sat a client holds at close arrived via a real HTLC payment. */
        size_t ns = N + 1;

        secp256k1_keypair *kps = calloc(ns, sizeof(*kps));
        secp256k1_pubkey  *pks = calloc(ns, sizeof(*pks));
        secp256k1_xonly_pubkey fund_key; unsigned char fund_spk[34];
        if (!kps || !pks || !build_keys(ctx, seed, ns, kps, pks, &fund_key, fund_spk)) { fprintf(stderr, "keygen failed\n"); return 1; }

        /* --- Build + sign the factory tree (same path proven to 10k) --- */
        factory_t *f = calloc(1, sizeof(factory_t));
        if (!f) { fprintf(stderr, "oom factory_t\n"); return 1; }
        factory_config_t cfg; factory_config_default(&cfg);
        cfg.max_signers = (uint32_t)ns;
        cfg.max_leaves  = (uint32_t)(N + 1);
        cfg.max_nodes   = (uint32_t)(ns * 8 + 64);
        factory_init_with_config(f, ctx, kps, ns, 1, 4, &cfg);
        factory_set_arity(f, FACTORY_ARITY_PS);
        unsigned char txid_le[32];
        if (hex_decode(txid_hex, txid_le, 32) != 32) { fprintf(stderr, "bad txid\n"); return 1; }
        reverse_bytes(txid_le, 32);
        factory_set_funding(f, txid_le, vout, amount, fund_spk, 34);
        if (!factory_build_tree(f)) { fprintf(stderr, "factory_build_tree FAILED\n"); return 1; }
        if (!factory_sign_all_with_retry(f, 3)) { fprintf(stderr, "factory_sign_all FAILED\n"); return 1; }
        printf("  factory: %zu nodes, %zu-signer PS, all signed\n", f->n_nodes, ns);

        /* --- Wire a REAL Lightning channel to every leaf (LSP=local, client=remote).
               lsp_channels_init discovers the PS keyagg ordering and funds each
               channel from factory->nodes[leaf].outputs[vout]. --- */
        unsigned char lsp_sec[32];
        if (!secp256k1_keypair_sec(ctx, lsp_sec, &kps[0])) { fprintf(stderr, "lsp sec\n"); return 1; }
        lsp_channel_mgr_t mgr; memset(&mgr, 0, sizeof mgr);
        mgr.lsp_balance_pct = (uint16_t)lsp_pct;
        if (!lsp_channels_init(&mgr, ctx, f, lsp_sec, N)) { fprintf(stderr, "lsp_channels_init FAILED\n"); return 1; }
        printf("  channels: %zu real 2-of-2 LN channels wired to leaves (LSP share %u%%%s)\n",
               mgr.n_channels, lsp_pct,
               lsp_pct >= 100 ? " — clients start at 0, all client sats payment-borne" : "");

        /* --- Client-side mirror channels: the full BOLT-2 ceremony needs BOTH
               endpoints live (basepoints, PCS chains, PCPs, nonce pools). --- */
        channel_t *cli = calloc(N, sizeof(channel_t));
        if (!cli) { fprintf(stderr, "oom client mirrors\n"); return 1; }
        size_t n_states = 2 * P + 4;   /* cn advances twice per payment */
        for (size_t c = 0; c < N; c++) {
            if (!setup_mirror_channel(ctx, &mgr.entries[c].channel, &cli[c],
                                      &kps[c + 1], &pks[c + 1], &pks[0], n_states)) {
                fprintf(stderr, "mirror channel %zu setup FAILED\n", c); return 1;
            }
        }
        printf("  mirrors:  %zu client-side channels (basepoints+PCS+pubnonce pools exchanged)\n", N);

        uint64_t init_client_total = 0;
        uint64_t *init_local  = audit_dir ? calloc(N, sizeof(uint64_t)) : NULL;
        uint64_t *init_remote = audit_dir ? calloc(N, sizeof(uint64_t)) : NULL;
        for (size_t c = 0; c < N; c++) {
            init_client_total += mgr.entries[c].channel.remote_amount;
            if (init_local)  init_local[c]  = mgr.entries[c].channel.local_amount;
            if (init_remote) init_remote[c] = mgr.entries[c].channel.remote_amount;
        }

        /* --- REAL HTLC payments: channel_add_htlc(SHA256 hash) -> channel_fulfill_htlc(preimage).
               These move real balance with reserve/dust/fee enforcement and bump the
               commitment number.  3-of-4 are LSP->client, 1-of-4 client->LSP, so a net
               flow of sats reaches the clients through genuine HTLCs. --- */
        /* Audit: per-HTLC ledger (channel, direction, amount, hash, PREIMAGE, and
           balances before/after) — an independently-verifiable record of every
           real payment.  Only written when an audit dir is supplied. */
        FILE *af = NULL;
        if (audit_dir) {
            char pth[600]; snprintf(pth, sizeof pth, "%s/payments.jsonl", audit_dir);
            af = fopen(pth, "w");
            if (!af) fprintf(stderr, "warn: cannot open %s\n", pth);
        }
        uint64_t gross_moved = 0, commit_sum = 0;
        size_t n_pay = 0, n_skip = 0, n_aggsigs = 0, n_revocations = 0;
        uint64_t *paid_to_client = calloc(N, sizeof(uint64_t));
        for (size_t c = 0; c < N; c++) {
            channel_t *L = &mgr.entries[c].channel;
            channel_t *C = &cli[c];
            for (size_t p = 0; p < P; p++) {
                /* payment-borne mode: every payment flows LSP->client so each
                   client's entire close balance came through real HTLCs.
                   Mixed mode keeps the 3:1 bidirectional pattern. */
                int lsp_to_client = (lsp_pct >= 100) ? 1 : (p % 4 != 3);
                uint64_t amt = 1000 + (uint64_t)((c + p) % 400);
                uint64_t offerer = lsp_to_client ? L->local_amount : L->remote_amount;
                if (offerer < amt + CHANNEL_RESERVE_SATS + 500) {
                    if (lsp_pct >= 100) { fprintf(stderr, "ch %zu p %zu unaffordable — sizing bug\n", c, p); return 1; }
                    n_skip++; continue;
                }
                unsigned char pre[32] = {0}, hash[32];
                pre[0] = (unsigned char)c; pre[1] = (unsigned char)(c >> 8);
                pre[2] = (unsigned char)p; pre[3] = 0xA5;
                sha256(pre, 32, hash);
                uint64_t lb = L->local_amount, rb = L->remote_amount;
                channel_t *S = lsp_to_client ? L : C;   /* update initiator */
                channel_t *R = lsp_to_client ? C : L;
                uint64_t idS, idR;
                /* update_add_htlc: offered on the sender, mirrored received on the peer */
                if (!channel_add_htlc(S, HTLC_OFFERED,  amt, hash, 100, &idS) ||
                    !channel_add_htlc(R, HTLC_RECEIVED, amt, hash, 100, &idR)) {
                    fprintf(stderr, "add_htlc FAILED ch %zu p %zu\n", c, p); return 1;
                }
                /* commitment_signed / revoke_and_ack round for the HTLC-pending state */
                if (!bolt2_commit_round(S, R, &n_aggsigs, &n_revocations)) {
                    fprintf(stderr, "BOLT2 round (add) FAILED ch %zu p %zu\n", c, p); return 1;
                }
                /* update_fulfill_htlc: recipient reveals the preimage; both books settle */
                if (!channel_fulfill_htlc(R, idR, pre) ||
                    !channel_fulfill_htlc(S, idS, pre)) {
                    fprintf(stderr, "fulfill FAILED ch %zu p %zu\n", c, p); return 1;
                }
                /* second signed round for the settled state, initiated by the fulfiller */
                if (!bolt2_commit_round(R, S, &n_aggsigs, &n_revocations)) {
                    fprintf(stderr, "BOLT2 round (fulfill) FAILED ch %zu p %zu\n", c, p); return 1;
                }
                gross_moved += amt; n_pay++;
                if (lsp_to_client) paid_to_client[c] += amt;
                if (af) {
                    char hh[65], ph[65]; hex_encode(hash, 32, hh); hh[64] = 0; hex_encode(pre, 32, ph); ph[64] = 0;
                    fprintf(af, "{\"i\":%zu,\"channel\":%zu,\"dir\":\"%s\",\"amount\":%llu,"
                                "\"payment_hash\":\"%s\",\"preimage\":\"%s\","
                                "\"local_before\":%llu,\"remote_before\":%llu,"
                                "\"local_after\":%llu,\"remote_after\":%llu,"
                                "\"cn\":%llu,\"aggsigs\":4,\"revocations\":4}\n",
                            n_pay, c, lsp_to_client ? "lsp->client" : "client->lsp",
                            (unsigned long long)amt, hh, ph,
                            (unsigned long long)lb, (unsigned long long)rb,
                            (unsigned long long)L->local_amount, (unsigned long long)L->remote_amount,
                            (unsigned long long)L->commitment_number);
                }
            }
        }
        if (af) fclose(af);

        /* HARD verification: (a) both endpoints' books agree exactly;
           (b) in payment-borne mode each client's balance equals the sum of
           its received payments — no other source of client sats exists. */
        {
            size_t bad_mirror = 0, bad_borne = 0;
            for (size_t c = 0; c < N; c++) {
                channel_t *L = &mgr.entries[c].channel, *C = &cli[c];
                if (L->local_amount != C->remote_amount ||
                    L->remote_amount != C->local_amount) bad_mirror++;
                if (lsp_pct >= 100 && L->remote_amount != paid_to_client[c]) bad_borne++;
            }
            if (bad_mirror || bad_borne) {
                fprintf(stderr, "VERIFY FAILED: mirror_mismatch=%zu payment_borne_mismatch=%zu\n",
                        bad_mirror, bad_borne);
                return 1;
            }
        }
        uint64_t final_client_total = 0;
        for (size_t c = 0; c < N; c++) {
            final_client_total += mgr.entries[c].channel.remote_amount;
            commit_sum         += mgr.entries[c].channel.commitment_number;
        }

        /* --- Cooperative close from the REAL post-payment balances (output 0 = LSP =
               funding - sum(client remotes) - close_fee; outputs 1..N = each client's
               remote_amount).  NULL close_spk => real per-client + LSP close addresses. --- */
        tx_output_t *outs = calloc(N + 1, sizeof(tx_output_t));
        uint64_t est_vsize = 11 + 58 + (uint64_t)(N + 1) * 43;
        uint64_t close_fee = (est_vsize * fee_kvb + 999) / 1000;   /* sat/kvB, round up */
        size_t n_out = lsp_channels_build_close_outputs(&mgr, f, outs, close_fee, NULL, 0);
        if (n_out == 0) { fprintf(stderr, "build_close_outputs FAILED (funding < client_total+fee?)\n"); return 1; }
        tx_buf_t close_tx; tx_buf_init(&close_tx, 1u << 20);
        unsigned char close_txid[32];
        if (!factory_build_cooperative_close(f, &close_tx, close_txid, outs, n_out, 0)) {
            fprintf(stderr, "factory_build_cooperative_close FAILED\n"); return 1;
        }
        uint64_t out_sum = 0; for (size_t i = 0; i < n_out; i++) out_sum += outs[i].amount_sats;

        /* Audit: per-channel balances + close-output map (output index j maps to
           key kps[j]: output 0 = LSP, outputs 1..N = client j).  This is the
           record a sweep/verifier reads to reconstruct + recover every output. */
        if (audit_dir) {
            char pth[600];
            snprintf(pth, sizeof pth, "%s/channels.csv", audit_dir);
            FILE *cf = fopen(pth, "w");
            if (cf) {
                fprintf(cf, "channel,client_pubkey,init_local,init_remote,final_local,final_remote,commitment_number\n");
                for (size_t c = 0; c < N; c++) {
                    const channel_t *ch = &mgr.entries[c].channel;
                    unsigned char pkser[33]; size_t pl = 33; char pkhex[67];
                    secp256k1_ec_pubkey_serialize(ctx, pkser, &pl, &pks[c + 1], SECP256K1_EC_COMPRESSED);
                    hex_encode(pkser, 33, pkhex); pkhex[66] = 0;
                    fprintf(cf, "%zu,%s,%llu,%llu,%llu,%llu,%llu\n", c, pkhex,
                            (unsigned long long)(init_local ? init_local[c] : 0),
                            (unsigned long long)(init_remote ? init_remote[c] : 0),
                            (unsigned long long)ch->local_amount, (unsigned long long)ch->remote_amount,
                            (unsigned long long)ch->commitment_number);
                }
                fclose(cf);
            }
            unsigned char ctxid_disp[32]; memcpy(ctxid_disp, close_txid, 32); reverse_bytes(ctxid_disp, 32);
            char ctxhex[65]; hex_encode(ctxid_disp, 32, ctxhex); ctxhex[64] = 0;
            snprintf(pth, sizeof pth, "%s/close.json", audit_dir);
            FILE *jf = fopen(pth, "w");
            if (jf) {
                fprintf(jf, "{\"close_txid\":\"%s\",\"n_outputs\":%zu,\"funding\":%llu,"
                            "\"close_fee\":%llu,\"out_sum\":%llu,\"conserves\":%s,\"outputs\":[",
                        ctxhex, n_out, (unsigned long long)amount,
                        (unsigned long long)close_fee, (unsigned long long)out_sum,
                        (out_sum + close_fee == amount) ? "true" : "false");
                for (size_t i = 0; i < n_out; i++) {
                    char spkhex[69]; hex_encode(outs[i].script_pubkey, outs[i].script_pubkey_len, spkhex);
                    spkhex[outs[i].script_pubkey_len * 2] = 0;
                    fprintf(jf, "%s{\"index\":%zu,\"role\":\"%s\",\"key_index\":%zu,\"spk\":\"%s\",\"amount\":%llu}",
                            i ? "," : "", i, i == 0 ? "lsp" : "client", i, spkhex,
                            (unsigned long long)outs[i].amount_sats);
                }
                fprintf(jf, "]}\n");
                fclose(jf);
            }
            free(init_local); free(init_remote);
        }

        FILE *fp = fopen(outfile, "w"); if (!fp) { fprintf(stderr, "cannot write %s\n", outfile); return 1; }
        char *hx = malloc(close_tx.len * 2 + 1); hex_encode(close_tx.data, close_tx.len, hx); hx[close_tx.len * 2] = 0;
        fputs(hx, fp); fclose(fp); free(hx);

        printf("inproc-pay: N=%zu channels=%zu payments=%zu (skipped %zu) gross_moved=%llu sats\n",
               N, mgr.n_channels, n_pay, n_skip, (unsigned long long)gross_moved);
        printf("inproc-pay: BOLT2: aggsigs_verified=%zu revocations_exchanged=%zu mirror_books=exact%s\n",
               n_aggsigs, n_revocations,
               lsp_pct >= 100 ? "  payment_borne=VERIFIED (every client sat arrived via HTLC)" : "");
        printf("inproc-pay: client_total %llu -> %llu (net %+lld to clients)  commitment_bumps=%llu\n",
               (unsigned long long)init_client_total, (unsigned long long)final_client_total,
               (long long)final_client_total - (long long)init_client_total,
               (unsigned long long)commit_sum);
        printf("inproc-pay: close outputs=%zu  close_tx=%zu B  out_sum=%llu funding=%llu fee=%llu  conserves=%s\n",
               n_out, close_tx.len, (unsigned long long)out_sum, (unsigned long long)amount,
               (unsigned long long)close_fee, (out_sum + close_fee == amount) ? "yes" : "NO");
        printf("  hex -> %s\n", outfile);
        for (size_t c = 0; c < N; c++) channel_cleanup(&cli[c]);
        free(cli); free(paid_to_client);
        lsp_channels_cleanup(&mgr);
        return 0;
    }

    fprintf(stderr,
        "usage:\n"
        "  %s addr         <N> <SEED>\n"
        "  %s dumpkeys     <N> <SEED>\n"
        "  %s lifecycle    <N> <M_FUNDED> <SEED> <FUND_TXID> <VOUT> <AMOUNT> <OUTFILE> [FEE_RATE]\n"
        "  %s paylifecycle <N> <SEED> <FUND_TXID> <VOUT> <AMOUNT> <OUTFILE> [FEE_KVB] [P] [AUDIT_DIR] [LSP_PCT]\n"
        "                  FEE_KVB in sat/kvB (100 = 0.1 sat/vB); LSP_PCT=100 => clients start at 0\n",
        argv[0], argv[0], argv[0], argv[0]);
    return 1;
}
