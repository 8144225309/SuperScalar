/*
 * test_regtest_hybrid_cln.c — Phase 2 item #5 of the v0.1.14 audit.
 *
 * End-to-end hybrid test: real BOLT11 payment crosses the SuperScalar /
 * Core Lightning boundary.
 *
 *   [vanilla CLN-2] --LN-channel--> [CLN-1+SS-plugin] --bridge-->
 *       [LSP daemon] --SuperScalar arity-2 leaf channel--> [Client_0]
 *
 * The CLN-2 node generates a BOLT11 invoice that was created by the SS
 * client (via the bridge), CLN-2 routes payment to CLN-1, the SS plugin
 * forwards the HTLC to the LSP via the bridge, the LSP fulfills it on
 * the inner factory channel, the preimage propagates back, and CLN-2's
 * payment completes.  The factory is then cooperatively closed and we
 * verify the on-chain accounting:
 *
 *   1. close_txid is in the LSP's broadcast_log and confirmed
 *   2. per-party close-tx outputs match the economic formula
 *      (LSP recovers funding − INVOICE − close_fee; client_0 gets INVOICE;
 *       clients 1-3 get 0)
 *   3. conservation: Σoutputs + close_fee == funding_amount
 *   4. per-party wallet delta (UTXO scan): each party's
 *      P2TR(xonly(pk(seckey))) UTXO holds exactly the expected amount
 *      after the close — proves the on-chain accounting boundary
 *
 * Setup is delegated to tools/test_bridge_econ_regtest.sh which already
 * spins up bitcoind regtest, lightningd (CLN1+plugin and CLN2), the LSP
 * daemon, the bridge, and 4 SuperScalar clients in a coordinated manner.
 *
 * Severity invariants:
 *   - Real CLN node (lightningd v25.x), not a mock
 *   - Real bitcoind regtest (port 18443)
 *   - Real BOLT11 payment routed end-to-end via lightning-cli
 *   - Conservation assertion + per-party econ_assert_wallet_deltas
 *   - No --skip-on-CI flag; only skips when lightningd is genuinely
 *     absent (CI gap surfaces explicitly via the SKIP message and
 *     a follow-up ticket).  VPS / dev with lightningd run at full severity.
 */

#include "econ_helpers.h"
#include "spend_helpers.h"
#include "superscalar/regtest.h"
#include "superscalar/sha256.h"
#include "superscalar/tx_builder.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int  hex_decode(const char *hex, unsigned char *out, size_t out_len);

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

/* tests/test_main.c uses TEST_SKIP_CODE = 2 to mark a SKIP. */
#define TEST_SKIP 2

/* Match the seckeys hard-coded in tools/test_bridge_econ_regtest.sh. */
static const unsigned char HYBRID_LSP_SECKEY[32] = {
    [0 ... 30] = 0, [31] = 0x01
};
static const unsigned char HYBRID_CLIENT_SECKEYS[4][32] = {
    { [0 ... 30] = 0, [31] = 0x02 },  /* client 0 — payment dest */
    { [0 ... 30] = 0, [31] = 0x03 },
    { [0 ... 30] = 0, [31] = 0x04 },
    { [0 ... 30] = 0, [31] = 0x05 },
};
static const char *HYBRID_NAMES[5] = {
    "LSP", "client_0", "client_1", "client_2", "client_3",
};

/* Conservation invariants the shell driver guarantees. */
#define HYBRID_FACTORY_FUNDING_SATS  100000ULL  /* --amount 100000 */
#define HYBRID_INVOICE_MSAT          600000ULL  /* INVOICE_AMT_MSAT */
#define HYBRID_INVOICE_SATS          (HYBRID_INVOICE_MSAT / 1000ULL) /* 600 */
#define HYBRID_CLOSE_FEE_SATS        500ULL    /* lsp_channels close_fee */

/* Per-party wallet-delta tolerance.  The close-tx output amounts match
 * exactly (we've already validated this in econ_assert_close_amounts);
 * the UTXO scan via scantxoutset returns exact sat amounts — so 0
 * tolerance is required.  Allow a tiny slack only for any future
 * msat→sat rounding the LSP might introduce. */
#define HYBRID_DELTA_TOL_SATS        0

/* Locate the lightningd binary on PATH.  If absent, the test is
 * legitimately un-runnable in this environment (e.g. CI without CLN
 * pre-installed) and we surface a SKIP rather than a false fail.
 * VPS regtest always has lightningd at /usr/local/bin. */
static int lightningd_available(void) {
    int rc = system("command -v lightningd >/dev/null 2>&1");
    return rc == 0;
}

/* Locate the project root.  Required env var SS_PROJECT_DIR overrides;
 * else fall back to /root/SuperScalar (VPS canonical path). */
static const char *project_dir(void) {
    const char *env = getenv("SS_PROJECT_DIR");
    if (env && *env) return env;
    return "/root/SuperScalar";
}

/* Run the shell test driver and capture its exit status + close txid.
 *
 * The driver encapsulates: bitcoind reset, CLN1+plugin, CLN2, LSP,
 * bridge, 4 clients, channel open, BOLT11 invoice, payment, coop close.
 * It logs `Close tx: <txid>` to stdout once the close confirms — we
 * stream stdout to the test log AND scrape that line for the txid. */
static int run_shell_driver(char *close_txid_out, size_t close_txid_max) {
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             "bash %s/tools/test_bridge_econ_regtest.sh %s/build 2>&1",
             project_dir(), project_dir());

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        printf("  FAIL: popen failed for shell driver\n");
        return 0;
    }

    char line[8192];
    int saw_close_txid = 0;
    int saw_pass = 0;
    close_txid_out[0] = '\0';

    while (fgets(line, sizeof(line), fp)) {
        printf("    [shell] %s", line);
        fflush(stdout);

        const char *p = strstr(line, "Close tx: ");
        if (p && !saw_close_txid) {
            p += strlen("Close tx: ");
            size_t n = 0;
            while (n < 64 && n < close_txid_max - 1 && p[n] &&
                   ((p[n] >= '0' && p[n] <= '9') ||
                    (p[n] >= 'a' && p[n] <= 'f') ||
                    (p[n] >= 'A' && p[n] <= 'F'))) {
                close_txid_out[n] = p[n];
                n++;
            }
            close_txid_out[n] = '\0';
            if (n == 64) saw_close_txid = 1;
        }

        if (strstr(line, "PASS: Phase 3")) saw_pass = 1;
    }

    int rc = pclose(fp);
    if (rc != 0) {
        printf("  FAIL: shell driver exited rc=%d "
               "(WIFEXITED=%d WEXITSTATUS=%d)\n",
               rc, WIFEXITED(rc), WIFEXITSTATUS(rc));
        return 0;
    }
    if (!saw_pass) {
        printf("  FAIL: shell driver did not emit PASS marker\n");
        return 0;
    }
    if (!saw_close_txid) {
        printf("  FAIL: shell driver did not emit close txid\n");
        return 0;
    }
    return 1;
}

/*
 * test_regtest_hybrid_cln_arity2_payment
 *
 * Real CLN ↔ SuperScalar arity-2 boundary test.  Drives the existing
 * shell harness (which spins up two CLN nodes, one with the SS plugin)
 * and then verifies, in C, the on-chain accounting of the resulting
 * cooperative close.
 *
 * The accounting is done via econ_helpers, which scans the on-chain
 * UTXO set (via scantxoutset) for each party's expected close-output
 * SPK.  Because the LSP uses mgr->lsp_close_spk (P2TR of LSP's factory
 * pubkey) and each client uses mgr->entries[c].close_spk (P2TR of
 * their factory pubkey), the seckey-derived P2TR SPKs in econ_register_party
 * align exactly with the on-chain SPKs that lsp_channels_build_close_outputs
 * emits — see src/lsp_channels.c:163-211.
 *
 * Invariants asserted:
 *   - per-party close-tx output amounts == economic formula
 *   - conservation: Σoutputs + close_fee == funding_amount  (100000 sats)
 *   - per-party UTXO delta == close-amount (msat-perfect for 600 sats
 *     reaching client_0 from CLN-2)
 */
int test_regtest_hybrid_cln_arity2_payment(void) {
    /* CI gate: skip cleanly if lightningd is not installed. */
    if (!lightningd_available()) {
        printf("  SKIP: lightningd not on PATH (CI without CLN). "
               "VPS coverage is the source of truth for this cell — "
               "see docs/v0114-audit-phase2.md item #5.\n");
        return TEST_SKIP;
    }

    /* Verify the shell driver and binaries exist. */
    char path[512];
    snprintf(path, sizeof(path),
             "%s/tools/test_bridge_econ_regtest.sh", project_dir());
    if (access(path, R_OK) != 0) {
        printf("  SKIP: shell driver %s not found "
               "(set SS_PROJECT_DIR if your tree lives elsewhere)\n", path);
        return TEST_SKIP;
    }
    snprintf(path, sizeof(path), "%s/build/superscalar_lsp", project_dir());
    if (access(path, X_OK) != 0) {
        printf("  SKIP: %s not built\n", path);
        return TEST_SKIP;
    }
    snprintf(path, sizeof(path), "%s/build/superscalar_client", project_dir());
    if (access(path, X_OK) != 0) {
        printf("  SKIP: %s not built\n", path);
        return TEST_SKIP;
    }
    snprintf(path, sizeof(path), "%s/build/superscalar_bridge", project_dir());
    if (access(path, X_OK) != 0) {
        printf("  SKIP: %s not built\n", path);
        return TEST_SKIP;
    }

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    TEST_ASSERT(ctx, "secp ctx");

    /* --- Drive the shell harness end-to-end --- */
    char close_txid[80];
    printf("  driving shell harness "
           "(bitcoind regtest + CLN1+plugin + CLN2 + LSP + bridge + 4 clients)\n");
    if (!run_shell_driver(close_txid, sizeof(close_txid))) {
        secp256k1_context_destroy(ctx);
        return 0;
    }
    printf("  shell harness PASS, close_txid=%s\n", close_txid);

    /* --- Re-attach to the same bitcoind regtest the shell test used --- */
    /* The shell test uses /root/bitcoin-regtest/bitcoin.conf with port
     * 18443, default rpcuser/rpcpass.  We use init_full so we pin to
     * port 18443 explicitly (avoids clashing with any other regtest
     * configs in env). */
    regtest_t rt;
    if (!regtest_init_full(&rt, "regtest", "bitcoin-cli",
                            "rpcuser", "rpcpass", NULL, 18443)) {
        printf("  FAIL: cannot reconnect to regtest after shell harness\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }

    /* --- Set up econ_ctx with the canonical seckeys the shell uses --- */
    econ_ctx_t ectx;
    econ_ctx_init(&ectx, &rt, ctx);
    TEST_ASSERT(econ_register_party(&ectx, 0, HYBRID_NAMES[0],
                                      HYBRID_LSP_SECKEY),
                "register LSP party");
    for (size_t i = 0; i < 4; i++) {
        TEST_ASSERT(econ_register_party(&ectx, i + 1, HYBRID_NAMES[i + 1],
                                          HYBRID_CLIENT_SECKEYS[i]),
                    "register client party");
    }

    /* --- Conservation + per-output check on the close tx --- */
    /* Expected economic formula (lsp_balance_pct=100 default,
     * single client receives the payment):
     *   LSP        = funding - INVOICE - close_fee
     *   client_0   = INVOICE  (its remote_amount after fulfillment)
     *   client_1-3 = 0        (did not transact; outputs dust-reclaimed
     *                          into LSP — clients 1-3's seckey-derived SPK
     *                          will not appear in the close tx)
     *
     * lsp_channels.c:3050-3056: any output < 546 sats (dust) is folded
     * back into the LSP output.  Since clients 1-3 have remote=0 they
     * are dust-reclaimed and do NOT contribute outputs — so expected[i]=0
     * tells econ_assert_close_amounts to accept "no matching vout".
     */
    uint64_t expected_close[5] = {
        HYBRID_FACTORY_FUNDING_SATS - HYBRID_INVOICE_SATS - HYBRID_CLOSE_FEE_SATS,
        HYBRID_INVOICE_SATS,
        0, 0, 0,
    };
    if (!econ_assert_close_amounts(&ectx, close_txid, HYBRID_CLOSE_FEE_SATS,
                                     HYBRID_FACTORY_FUNDING_SATS,
                                     expected_close)) {
        printf("  FAIL: close-amount/conservation econ assert\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }

    /* --- Per-party wallet delta --- */
    /* Each party's expect_close_spk was 0 sats pre-test (the SPKs only
     * exist on chain after the close).  Synthesize pre-snap=0 then
     * post-snap to assert delta = expected_close. */
    for (size_t i = 0; i < ectx.n_parties; i++) {
        ectx.parties[i].pre_balance_sats = 0;
    }
    if (!econ_snap_post(&ectx)) {
        printf("  FAIL: econ_snap_post\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }

    uint64_t expected_delta[5];
    memcpy(expected_delta, expected_close, sizeof(expected_close));
    if (!econ_assert_wallet_deltas(&ectx, expected_delta,
                                    HYBRID_DELTA_TOL_SATS)) {
        printf("  FAIL: per-party wallet-delta econ assert\n");
        econ_print_summary(&ectx);
        secp256k1_context_destroy(ctx);
        return 0;
    }

    econ_print_summary(&ectx);

    printf("  hybrid CLN <-> SuperScalar arity-2: payment crossed boundary, "
           "%llu sats arrived at client_0, conservation holds, "
           "per-party deltas match\n",
           (unsigned long long)HYBRID_INVOICE_SATS);

    secp256k1_context_destroy(ctx);
    return 1;
}
