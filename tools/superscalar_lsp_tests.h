/*
 * superscalar_lsp_tests.h — Declarations for test harness functions
 * extracted from superscalar_lsp.c.
 *
 * Each function corresponds to a --test-* or --breach-test CLI flag.
 * They receive a shared context struct that bundles the local variables
 * from main() that the test blocks need.
 */
#ifndef SUPERSCALAR_LSP_TESTS_H
#define SUPERSCALAR_LSP_TESTS_H

#include "superscalar/lsp.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/regtest.h"
#include "superscalar/report.h"
#include "superscalar/persist.h"
#include "superscalar/fee.h"
#include "superscalar/ladder.h"
#include "superscalar/factory.h"
#include <signal.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

/* Shared context passed from main() to every extracted test function. */
typedef struct {
    /* Core objects */
    lsp_channel_mgr_t *mgr;
    lsp_t             *lsp;
    secp256k1_context *ctx;
    secp256k1_keypair *lsp_kp;       /* pointer to stack-local in main */
    unsigned char     *lsp_seckey;    /* 32 bytes, zeroed on exit */
    regtest_t         *rt;
    report_t          *rpt;
    persist_t         *db;           /* NULL if no persistence */
    persist_t         *g_db;         /* global broadcast audit log */
    ladder_t          *lad;
    fee_estimator_t   *fee_est;

    /* Addresses / SPKs */
    char              *mine_addr;    /* mining/change address */
    unsigned char     *fund_spk;     /* 34-byte funding script pubkey */
    char              *fund_addr;    /* bech32m funding address */

    /* Factory creation parameters */
    int                n_clients;
    size_t             n_total;      /* 1 + n_clients */
    uint16_t           step_blocks;
    int                states_per_layer;
    int                leaf_arity;
    uint8_t           *level_arities;
    size_t             n_level_arity;
    uint32_t           active_blocks;
    uint32_t           dying_blocks;
    int64_t            cltv_timeout_arg;
    uint64_t           funding_sats;

    /* Runtime flags */
    int                is_regtest;
    int                use_db;
    int                confirm_timeout_secs;
    int                breach_test;  /* 0=off, 1=breach, 2=cheat-daemon */

    /* Pre-demo balances (for breach/expiry tests) */
    uint64_t           init_local;
    uint64_t           init_remote;

    /* Network name */
    const char        *network;

    /* Shutdown flag */
    volatile sig_atomic_t *g_shutdown;
} lsp_test_ctx_t;

/*
 * Helper: advance chain by N blocks (mine on regtest, poll on non-regtest).
 * Wraps advance_chain() using fields from ctx.
 */
int lsp_test_advance(lsp_test_ctx_t *ctx, int n);

/*
 * Each function returns the process exit code:
 *   0 = test passed (caller should exit)
 *   1 = test failed (caller should exit)
 *  -1 = test did not run / not applicable (caller should continue)
 *
 * When the return is 0 or 1 the test function has already closed the
 * report and freed test-local resources, but the caller is still
 * responsible for the final cleanup (lsp_cleanup, secp256k1_context_destroy,
 * memset lsp_seckey, persist_close, etc).
 */

int lsp_test_dw_exhibition(lsp_test_ctx_t *ctx);
int lsp_test_leaf_advance(lsp_test_ctx_t *ctx);
int lsp_test_dual_factory(lsp_test_ctx_t *ctx);
int lsp_test_bridge(lsp_test_ctx_t *ctx);
int lsp_test_breach(lsp_test_ctx_t *ctx);
int lsp_test_expiry(lsp_test_ctx_t *ctx);
int lsp_test_distrib(lsp_test_ctx_t *ctx);
int lsp_test_turnover(lsp_test_ctx_t *ctx);
int lsp_test_rebalance(lsp_test_ctx_t *ctx);
int lsp_test_batch_rebalance(lsp_test_ctx_t *ctx);
int lsp_test_realloc(lsp_test_ctx_t *ctx);

#endif /* SUPERSCALAR_LSP_TESTS_H */
