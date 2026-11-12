/*
 * test_chain_lookup_errors.c — chain lookups whose answer is unknown or
 * conflicted, and what their callers do with them.
 *
 * The lookups run against a stand-in bitcoin-cli (a shell script written
 * per test, rpcport 0 so no HTTP is tried) that logs each RPC method it is
 * asked for and answers from a fixed table.
 *
 *   test_regtest_conf_stops_at_first_unreachable
 *       regtest_get_confirmations() returns REGTEST_CONF_RPC_ERROR on the
 *       first call bitcoind does not answer, including the first
 *       gettransaction, and does not go on scanning blocks.
 *   test_regtest_conf_conflicted_wallet_tx
 *       the wallet's negative confirmations for a conflicted TX map to
 *       REGTEST_CONF_CONFLICTED, never to -1 / REGTEST_CONF_RPC_ERROR.
 *   test_jit_revalidate_rpc_outage_keeps_open
 *   test_jit_force_close_rpc_outage_keeps_open
 *       an unreachable node neither reverts an open JIT channel to
 *       FUNDING nor marks it closed.
 */

#include "superscalar/regtest.h"
#include "superscalar/chain_backend.h"
#include "superscalar/jit_channel.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/watchtower.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/* Defined in jit_channel.c; no header declares it. */
extern int jit_channels_revalidate_funding(void *mgr_ptr);

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define TEST_ASSERT_GOTO(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        goto done; \
    } \
} while(0)

static const char *TXID =
    "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

/* bitcoin-cli's own output when it cannot reach bitcoind. */
#define FAKE_UNREACHABLE \
    "echo 'error: Could not connect to the server 127.0.0.1:18443'; exit 1"
/* bitcoind's answer for an unknown TX. */
#define FAKE_NOT_FOUND \
    "echo 'error code: -5'; echo 'error message:'; " \
    "echo 'No such mempool or blockchain transaction'; exit 5"

typedef struct {
    char dir[64];
    regtest_t rt;
} fake_cli_t;

/* Write <dir>/bitcoin-cli: it appends the RPC method to <dir>/calls, then
   runs the sh case arms in `cases` ("pattern) action ;;").  A method with
   no arm gets bitcoind's "Method not found" error. */
static int fake_cli_make(fake_cli_t *fc, const char *cases) {
    memset(fc, 0, sizeof(*fc));
    snprintf(fc->dir, sizeof(fc->dir), "/tmp/ss-fake-cli-XXXXXX");
    if (!mkdtemp(fc->dir)) { fc->dir[0] = '\0'; return 0; }
    char path[128];
    snprintf(path, sizeof(path), "%s/bitcoin-cli", fc->dir);
    FILE *fp = fopen(path, "w");
    if (!fp) return 0;
    fprintf(fp,
        "#!/bin/sh\n"
        "m=\n"
        "for a in \"$@\"; do case \"$a\" in -*) ;; *) m=\"$a\"; break ;; esac; done\n"
        "echo \"$m\" >> '%s/calls'\n"
        "case \"$m\" in\n"
        "%s\n"
        "*) echo 'error code: -32601'; echo 'error message:'; "
        "echo 'Method not found'; exit 1 ;;\n"
        "esac\n"
        "exit 0\n", fc->dir, cases);
    fclose(fp);
    if (chmod(path, 0755) != 0) return 0;
    snprintf(fc->rt.cli_path, sizeof(fc->rt.cli_path), "%s", path);
    snprintf(fc->rt.rpcuser, sizeof(fc->rt.rpcuser), "rpcuser");
    snprintf(fc->rt.rpcpassword, sizeof(fc->rt.rpcpassword), "rpcpass");
    snprintf(fc->rt.network, sizeof(fc->rt.network), "regtest");
    fc->rt.rpcport = 0;        /* bitcoin-cli only, no HTTP attempt */
    fc->rt.scan_depth = 10;
    return 1;
}

/* Calls logged so far: of `method`, or of any method when NULL. */
static int fake_cli_calls(const fake_cli_t *fc, const char *method) {
    char path[128], line[128];
    snprintf(path, sizeof(path), "%s/calls", fc->dir);
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    int n = 0;
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0';
        if (!method || strcmp(line, method) == 0) n++;
    }
    fclose(fp);
    return n;
}

static void fake_cli_remove(const fake_cli_t *fc) {
    char path[128];
    if (!fc->dir[0]) return;
    snprintf(path, sizeof(path), "%s/calls", fc->dir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/bitcoin-cli", fc->dir);
    unlink(path);
    rmdir(fc->dir);
}

int test_regtest_conf_stops_at_first_unreachable(void) {
    int rc = 0;
    fake_cli_t down, mid;
    memset(&down, 0, sizeof(down));
    memset(&mid, 0, sizeof(mid));

    /* No call is answered: one call, then -2. */
    TEST_ASSERT_GOTO(fake_cli_make(&down, "*) " FAKE_UNREACHABLE " ;;"),
                     "fake cli (down)");
    int conf = regtest_get_confirmations(&down.rt, TXID);
    int calls = fake_cli_calls(&down, NULL);
    printf("\n    node down: conf=%d after %d call(s) (gettransaction=%d)",
           conf, calls, fake_cli_calls(&down, "gettransaction"));
    TEST_ASSERT_GOTO(conf == REGTEST_CONF_RPC_ERROR, "node down: RPC error");
    TEST_ASSERT_GOTO(calls == 1 && fake_cli_calls(&down, "gettransaction") == 1,
                     "node down: stops after the first gettransaction");

    /* The TX lookups answer "not found", then bitcoind goes away during the
       block scan: the scan stops at the first unanswered getblockhash. */
    TEST_ASSERT_GOTO(fake_cli_make(&mid,
        "gettransaction|getrawtransaction) " FAKE_NOT_FOUND " ;;\n"
        "getblockcount) echo 200 ;;\n"
        "getblockhash) " FAKE_UNREACHABLE " ;;"), "fake cli (mid-scan)");
    conf = regtest_get_confirmations(&mid.rt, TXID);
    printf("\n    node lost mid-scan: conf=%d, getblockhash calls=%d "
           "(scan depth %d)\n   ", conf, fake_cli_calls(&mid, "getblockhash"),
           mid.rt.scan_depth);
    TEST_ASSERT_GOTO(conf == REGTEST_CONF_RPC_ERROR, "mid-scan: RPC error");
    TEST_ASSERT_GOTO(fake_cli_calls(&mid, "getblockhash") == 1,
                     "mid-scan: stops at the first unanswered getblockhash");
    rc = 1;
done:
    fake_cli_remove(&down);
    fake_cli_remove(&mid);
    return rc;
}

int test_regtest_conf_conflicted_wallet_tx(void) {
    int rc = 0;
    fake_cli_t fc[4];
    memset(fc, 0, sizeof(fc));
    /* gettransaction "confirmations" as the wallet reports it, and the
       value regtest_get_confirmations must return. */
    const int wallet_conf[4] = { -2, -1, 0, 5 };
    const int expected[4] = { REGTEST_CONF_CONFLICTED, REGTEST_CONF_CONFLICTED,
                              0, 5 };
    for (int i = 0; i < 4; i++) {
        char cases[256];
        snprintf(cases, sizeof(cases),
                 "gettransaction) echo '{\"txid\": \"%s\", \"confirmations\": %d}' ;;",
                 TXID, wallet_conf[i]);
        TEST_ASSERT_GOTO(fake_cli_make(&fc[i], cases), "fake cli");
        int conf = regtest_get_confirmations(&fc[i].rt, TXID);
        printf("\n    wallet confirmations %d -> %d", wallet_conf[i], conf);
        TEST_ASSERT_GOTO(conf == expected[i], "wallet confirmations mapped");
    }
    printf("\n   ");
    TEST_ASSERT_GOTO(REGTEST_CONF_CONFLICTED != REGTEST_CONF_RPC_ERROR &&
                     REGTEST_CONF_CONFLICTED != -1, "distinct codes");
    rc = 1;
done:
    for (int i = 0; i < 4; i++) fake_cli_remove(&fc[i]);
    return rc;
}

/* A manager with one OPEN JIT channel for client 0, its funding TXID set. */
static int jit_mgr_one_open(lsp_channel_mgr_t *mgr, watchtower_t *wt,
                            regtest_t *rt) {
    memset(mgr, 0, sizeof(*mgr));
    memset(wt, 0, sizeof(*wt));
    jit_channel_t *j = calloc(1, sizeof(jit_channel_t));
    if (!j) return 0;
    j->state = JIT_STATE_OPEN;
    j->client_idx = 0;
    j->jit_channel_id = JIT_CHANNEL_ID_BASE;
    j->funding_confirmed = 1;
    snprintf(j->funding_txid_hex, sizeof(j->funding_txid_hex), "%s", TXID);
    mgr->jit_channels = j;
    mgr->n_jit_channels = 1;
    mgr->jit_channels_cap = 1;
    wt->rt = rt;
    mgr->watchtower = wt;
    return 1;
}

int test_jit_revalidate_rpc_outage_keeps_open(void) {
    int rc = 0;
    fake_cli_t down;
    lsp_channel_mgr_t mgr;
    watchtower_t wt;
    memset(&down, 0, sizeof(down));
    memset(&mgr, 0, sizeof(mgr));
    TEST_ASSERT_GOTO(fake_cli_make(&down, "*) " FAKE_UNREACHABLE " ;;"), "fake cli");
    TEST_ASSERT_GOTO(jit_mgr_one_open(&mgr, &wt, &down.rt), "jit mgr");
    jit_channel_t *j = (jit_channel_t *)mgr.jit_channels;
    int reverted = jit_channels_revalidate_funding(&mgr);
    printf("\n    outage: reverted=%d state=%d (OPEN=%d)\n   ", reverted,
           (int)j->state, (int)JIT_STATE_OPEN);
    TEST_ASSERT_GOTO(reverted == 0 && j->state == JIT_STATE_OPEN &&
                     j->funding_confirmed == 1,
                     "outage does not revert an open JIT channel");
    rc = 1;
done:
    free(mgr.jit_channels);
    fake_cli_remove(&down);
    return rc;
}

int test_jit_force_close_rpc_outage_keeps_open(void) {
    int rc = 0;
    fake_cli_t down;
    lsp_channel_mgr_t mgr;
    watchtower_t wt;
    chain_backend_t cb;
    memset(&down, 0, sizeof(down));
    memset(&mgr, 0, sizeof(mgr));
    memset(&cb, 0, sizeof(cb));
    TEST_ASSERT_GOTO(fake_cli_make(&down, "*) " FAKE_UNREACHABLE " ;;"), "fake cli");
    TEST_ASSERT_GOTO(jit_mgr_one_open(&mgr, &wt, &down.rt), "jit mgr");
    chain_backend_regtest_init(&cb, &down.rt);
    jit_channel_t *j = (jit_channel_t *)mgr.jit_channels;
    int r = jit_channel_force_close(&mgr, 0, &cb);
    printf("\n    outage: force_close=%d state=%d (OPEN=%d, CLOSED=%d)\n   ", r,
           (int)j->state, (int)JIT_STATE_OPEN, (int)JIT_STATE_CLOSED);
    TEST_ASSERT_GOTO(r == 0 && j->state == JIT_STATE_OPEN,
                     "outage does not mark the JIT channel closed");
    rc = 1;
done:
    free(mgr.jit_channels);
    fake_cli_remove(&down);
    return rc;
}
