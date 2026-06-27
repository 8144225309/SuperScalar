/* test_inproc_scale.c — single-process N-client factory-creation scale harness.
 *
 * WHY: validating that channel creation works at N=64 and N=128 by spawning N
 * real `superscalar_client --daemon` processes OOMs a shared box (each daemon
 * carries a bitcoind-RPC poller + SQLite WAL + full address space).  The pure
 * crypto/tree at N=128 is already proven by the unit test
 * (test_factory_ps_build_n128), but that bypasses the multi-client WIRE
 * ceremony + persist.  This harness closes that gap: it drives the REAL
 * production ceremony entry points — lsp_run_factory_creation on the LSP side,
 * client_run_with_channels on each client side — in ONE process, with each
 * client in a fork()ed child (fork, not threads, so each client gets a clean
 * copy of client.c's process globals: no races).
 *
 * Factory creation is fully chainless (lsp_run_factory_creation and the client
 * ceremony are pure wire+crypto), so this uses a FAKE funding txid + the real
 * N+1-party MuSig-aggregate taptweaked funding SPK.  No bitcoind, no sats.
 *
 * Usage:  test_inproc_scale <N_CLIENTS>
 *   N_CLIENTS = number of client participants (e.g. 64, 128).
 *   The factory has N_CLIENTS+1 signers (LSP + clients) and N_CLIENTS PS leaves
 *   (1 channel per client).
 * Exit 0 = factory created + every node signed + verified at this N.
 */

#include "superscalar/lsp.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/client.h"
#include "superscalar/factory.h"
#include "superscalar/musig.h"
#include "superscalar/tx_builder.h"
#include "superscalar/sha256.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

/* build_p2tr_script_pubkey is declared in tx_builder.h (included above). */

/* Deterministic per-participant seckey: index 0 = LSP, 1..N = clients.
 * Matches the spread used by test_factory_ps_build_n128 so keys stay distinct
 * past 250. */
static void derive_sk(unsigned char sk[32], size_t idx) {
    memset(sk, 0, 32);
    sk[31] = (unsigned char)((idx % 250) + 1);
    sk[0]  = 0x80;
    sk[1]  = (unsigned char)(idx / 250);
}

/* Channel callback: we only want to validate CREATION + CHANNEL_READY at scale,
 * not payments.  Return 2 = "callback already handled close, caller skips it",
 * so the client exits cleanly right after CHANNEL_READY without a close
 * ceremony. */
static int harness_channel_cb(int fd, channel_t *channel, uint32_t my_index,
                              secp256k1_context *ctx,
                              const secp256k1_keypair *keypair,
                              factory_t *factory, size_t n_participants,
                              void *user_data) {
    (void)fd; (void)channel; (void)my_index; (void)ctx; (void)keypair;
    (void)factory; (void)n_participants; (void)user_data;
    return 2;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    if (argc < 2) {
        fprintf(stderr, "usage: %s <N_CLIENTS>\n", argv[0]);
        return 2;
    }
    int N = atoi(argv[1]);
    if (N < 1 || N > 255) {
        fprintf(stderr, "N_CLIENTS must be 1..255 (got %d)\n", N);
        return 2;
    }
    size_t n_signers = (size_t)N + 1; /* LSP + N clients */

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) { fprintf(stderr, "ctx create failed\n"); return 1; }

    /* All N+1 keypairs (idx 0 = LSP). */
    secp256k1_keypair *kps = calloc(n_signers, sizeof(secp256k1_keypair));
    secp256k1_pubkey  *pks = calloc(n_signers, sizeof(secp256k1_pubkey));
    if (!kps || !pks) { fprintf(stderr, "alloc failed\n"); return 1; }
    for (size_t i = 0; i < n_signers; i++) {
        unsigned char sk[32];
        derive_sk(sk, i);
        if (!secp256k1_keypair_create(ctx, &kps[i], sk)) {
            fprintf(stderr, "keypair_create idx=%zu failed\n", i);
            return 1;
        }
        secp256k1_keypair_pub(ctx, &pks[i], &kps[i]);
    }

    /* Funding SPK = BIP-341 taptweak of the (N+1)-way MuSig aggregate. */
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks, n_signers)) {
        fprintf(stderr, "musig_aggregate_keys (%zu-way) failed\n", n_signers);
        return 1;
    }
    unsigned char ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, ser, &ka.agg_pubkey);
    unsigned char tweak[32];
    sha256_tagged("TapTweak", ser, 32, tweak);
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &ka.cache, tweak)) {
        fprintf(stderr, "taptweak failed\n");
        return 1;
    }
    secp256k1_xonly_pubkey fund_xo;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &fund_xo, NULL, &tweaked_pk);
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &fund_xo);

    /* Fake funding outpoint — creation is chainless, no verify_funding cb. */
    unsigned char funding_txid[32];
    memset(funding_txid, 0xCC, 32);
    uint64_t funding_amount = 100000000ULL; /* 1 BTC, ample for N=128 tree */

    int port = 19000 + (getpid() % 2000);

    printf("[scale] N=%d clients (%zu signers), port=%d, PS arity\n",
           N, n_signers, port);

    /* Bind+listen BEFORE forking so every client can connect immediately
     * (avoids a connect-before-listen race). */
    int rc = 0;
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    if (!lsp_init(lsp, ctx, &kps[0], port, (size_t)N)) {
        fprintf(stderr, "[scale] lsp_init failed\n");
        free(lsp); return 1;
    }
    factory_set_arity(&lsp->factory, FACTORY_ARITY_PS);

    /* Fork N client children (the listen socket already exists). */
    pid_t *child = calloc((size_t)N, sizeof(pid_t));
    for (int c = 0; c < N; c++) {
        pid_t pid = fork();
        if (pid == 0) {
            /* child: stagger connects MONOTONICALLY so each client arrives at
             * roughly the LSP's sequential accept+Noise-handshake rate.  The
             * LSP handshakes clients one at a time; without spreading, clients
             * deep in the queue exceed their handshake recv timeout before the
             * LSP reaches them ("noise handshake failed").  ~40ms/client keeps
             * the pipeline smooth (N=128 => ~5s connect spread). */
            usleep((useconds_t)c * 40000);
            secp256k1_context *cctx = secp256k1_context_create(
                SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
            secp256k1_keypair ckp;
            unsigned char csk[32];
            derive_sk(csk, (size_t)(c + 1)); /* clients are idx 1..N */
            secp256k1_keypair_create(cctx, &ckp, csk);
            int ok = client_run_with_channels(cctx, &ckp, "127.0.0.1", port,
                                               harness_channel_cb, NULL,
                                               NULL, NULL);
            secp256k1_context_destroy(cctx);
            _exit(ok ? 0 : 1);
        } else if (pid < 0) {
            fprintf(stderr, "fork failed at client %d\n", c);
            rc = 1; goto reap;
        }
        child[c] = pid;
    }

    /* Parent: run the LSP side of the ceremony. */
    if (!lsp_accept_clients(lsp)) {
        fprintf(stderr, "[scale] lsp_accept_clients failed (backlog/scale?)\n");
        rc = 1; goto reap;
    }
    printf("[scale] accepted %d clients\n", N);

    if (!lsp_run_factory_creation(lsp, funding_txid, 0, funding_amount,
                                  fund_spk, 34, /*step*/10, /*states*/4,
                                  /*cltv*/5000)) {
        fprintf(stderr, "[scale] lsp_run_factory_creation FAILED at N=%d\n", N);
        rc = 1; goto reap;
    }
    printf("[scale] factory creation ceremony complete: %zu nodes, %d leaves\n",
           lsp->factory.n_nodes, lsp->factory.n_leaf_nodes);

    /* #54 G1b: with a real CLTV, the stateless creation ceremony now co-signs the
       distribution TX (the offline-forever recovery net).  Assert it was fully
       co-signed across the LSP + all N forked clients (dist_tx_ready==2). */
    if (lsp->factory.dist_tx_ready != 2 || lsp->factory.dist_signed_tx.len == 0) {
        fprintf(stderr, "[scale] G1b: distribution TX NOT co-signed at N=%d "
                "(dist_tx_ready=%d, len=%zu)\n", N,
                lsp->factory.dist_tx_ready, lsp->factory.dist_signed_tx.len);
        rc = 1; goto reap;
    }
    printf("[scale] G1b: distribution TX co-signed (%zu bytes)\n",
           lsp->factory.dist_signed_tx.len);

    if (!factory_verify_all(&lsp->factory)) {
        fprintf(stderr, "[scale] factory_verify_all FAILED\n");
        rc = 1; goto reap;
    }
    if (lsp->factory.n_leaf_nodes != N) {
        fprintf(stderr, "[scale] expected %d leaf channels, got %d\n",
                N, lsp->factory.n_leaf_nodes);
        rc = 1; goto reap;
    }

    /* Bring each client's channel to CHANNEL_READY (the real per-client
     * channel-establishment handshake). */
    {
        lsp_channel_mgr_t mgr;
        memset(&mgr, 0, sizeof(mgr));
        unsigned char lsp_sk[32];
        derive_sk(lsp_sk, 0);
        if (!lsp_channels_init(&mgr, ctx, &lsp->factory, lsp_sk, (size_t)N)) {
            fprintf(stderr, "[scale] lsp_channels_init failed\n");
            rc = 1; goto reap;
        }
        if (!lsp_channels_exchange_basepoints(&mgr, lsp)) {
            fprintf(stderr, "[scale] exchange_basepoints failed\n");
            rc = 1; goto reap;
        }
        if (!lsp_channels_send_ready(&mgr, lsp)) {
            fprintf(stderr, "[scale] send_ready failed\n");
            rc = 1; goto reap;
        }
        printf("[scale] all %d channels reached CHANNEL_READY\n", N);
    }

reap:
    {
        int failed_children = 0;
        for (int c = 0; c < N; c++) {
            int st = 0;
            if (child[c] > 0) {
                waitpid(child[c], &st, 0);
                if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) failed_children++;
            }
        }
        if (failed_children) {
            fprintf(stderr, "[scale] %d/%d client children failed\n",
                    failed_children, N);
            rc = 1;
        } else {
            printf("[scale] all %d client children exited 0\n", N);
        }
    }

    if (rc == 0)
        printf("[scale] PASS: channel creation works for N=%d users\n", N);
    else
        printf("[scale] FAIL at N=%d\n", N);

    free(child); free(kps); free(pks);
    return rc;
}
