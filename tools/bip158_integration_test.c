/*
 * bip158_integration_test — end-to-end integration test for the BIP 158 backend.
 *
 * Requires a running bitcoind at the address/port configured below:
 *   -regtest -blockfilterindex=1 -peerblockfilters=1
 *   -rpcport=BIP158_RPCPORT  -port=BIP158_P2PPORT
 *   -rpcuser=BIP158_RPCUSER  -rpcpassword=BIP158_RPCPASS
 *
 * Run via:  tests/run_bip158_integration.sh
 * Or manually after starting bitcoind with the matching config.
 *
 * Tests:
 *   A. Phase 3 — RPC-backed filter scan finds a funded script
 *   B. Phase 4 — P2P filter scan finds the same funded script
 *   C. Negative — unregistered script produces zero matches
 */

#include "superscalar/bip158_backend.h"
#include "superscalar/regtest.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * Isolated bitcoind connection parameters (must match run_bip158_integration.sh)
 * Override via environment variables BIP158_RPCPORT / BIP158_P2PPORT.
 * ------------------------------------------------------------------------- */
#define DEFAULT_BITCOINCLI  "/home/pirq/bin/bitcoin-cli"
#define DEFAULT_DATADIR     "/tmp/claude-bip158-itest"
#define DEFAULT_RPCPORT     28443
#define DEFAULT_P2PPORT     28444
#define DEFAULT_RPCUSER     "claudetest"
#define DEFAULT_RPCPASS     "claudepass"
#define DEFAULT_WALLET      "bip158_itest"

static int g_pass = 0, g_fail = 0;
static int g_p2pport = DEFAULT_P2PPORT;
static int g_rpcport = DEFAULT_RPCPORT;

#define CHECK(cond, label) do { \
    if (cond) { printf("    PASS: %s\n", (label)); g_pass++; } \
    else       { printf("    FAIL: %s\n", (label)); g_fail++; } \
} while(0)

/* Initialise a regtest_t pointing at our isolated node */
static int init_rt(regtest_t *rt)
{
    int ok = regtest_init_full(rt, "regtest",
                               DEFAULT_BITCOINCLI,
                               DEFAULT_RPCUSER, DEFAULT_RPCPASS,
                               DEFAULT_DATADIR, g_rpcport);
    if (ok)
        strncpy(rt->wallet, DEFAULT_WALLET, sizeof(rt->wallet) - 1);
    return ok;
}

/* Diagnostic callback: print every output SPK in a block and check for match */
typedef struct { const unsigned char *want_spk; size_t want_len; int found; } spk_scan_t;
static void spk_dump_cb(const char *txid_hex,
                         size_t n_outputs,
                         const unsigned char **spks,
                         const size_t *spk_lens,
                         void *ctx)
{
    spk_scan_t *sc = (spk_scan_t *)ctx;
    printf("      tx %.16s... : %zu outputs\n", txid_hex, n_outputs);
    for (size_t i = 0; i < n_outputs; i++) {
        printf("        out[%zu] (%zu bytes):", i, spk_lens[i]);
        for (size_t j = 0; j < spk_lens[i]; j++) printf(" %02x", spks[i][j]);
        if (sc->want_len == spk_lens[i] &&
            memcmp(sc->want_spk, spks[i], spk_lens[i]) == 0) {
            printf(" <-- MATCH");
            sc->found = 1;
        }
        printf("\n");
    }
}

/* -------------------------------------------------------------------------
 * Setup: create wallet, mine 101 blocks so coinbase is spendable.
 * Returns 1 on success.
 * ------------------------------------------------------------------------- */
static int setup_wallet(regtest_t *rt)
{
    /* create/load wallet — safe to call even if it already exists */
    regtest_create_wallet(rt, DEFAULT_WALLET);

    int height = regtest_get_block_height(rt);
    if (height < 0) {
        fprintf(stderr, "setup_wallet: cannot get block height\n");
        return 0;
    }

    /* Need at least 101 blocks for coinbase maturity */
    if (height < 101) {
        char mine_addr[128] = {0};
        if (!regtest_get_new_address(rt, mine_addr, sizeof(mine_addr))) {
            fprintf(stderr, "setup_wallet: get_new_address failed\n");
            return 0;
        }
        int needed = 101 - height;
        printf("  Mining %d blocks for coinbase maturity...\n", needed);
        if (!regtest_mine_blocks(rt, needed, mine_addr)) {
            fprintf(stderr, "setup_wallet: mine_blocks failed\n");
            return 0;
        }
    }
    return 1;
}

/* -------------------------------------------------------------------------
 * Test A: Phase 3 — RPC-backed compact filter scan
 * 1. Register a fresh address's scriptPubKey with the backend
 * 2. Fund that address so a tx referencing our script lands on-chain
 * 3. Mine 1 block to confirm
 * 4. Run bip158_backend_scan() — must return >= 1 match
 * 5. get_confirmations() on the funding txid — must be >= 1
 * ------------------------------------------------------------------------- */
static int test_a_phase3_rpc(void)
{
    printf("\n[A] Phase 3: RPC-backed scan\n");

    regtest_t rt;
    if (!init_rt(&rt)) {
        printf("    SKIP: cannot connect to isolated bitcoind on port %d\n", g_rpcport);
        return 0;
    }
    if (!setup_wallet(&rt)) return 0;

    /* Get a fresh address and its scriptPubKey */
    char watch_addr[128] = {0};
    CHECK(regtest_get_new_address(&rt, watch_addr, sizeof(watch_addr)),
          "get_new_address");
    printf("    Watch address: %s\n", watch_addr);

    unsigned char spk[34];
    size_t spk_len = 0;
    CHECK(regtest_get_address_scriptpubkey(&rt, watch_addr, spk, &spk_len),
          "get_address_scriptpubkey");
    CHECK(spk_len > 0, "scriptpubkey non-empty");

    /* Initialise backend, register the script */
    bip158_backend_t backend;
    bip158_backend_init(&backend, "regtest");
    bip158_backend_set_rpc(&backend, &rt);
    CHECK(backend.base.register_script(&backend.base, spk, spk_len),
          "register_script");

    /* Fund the watched address from the wallet */
    char fund_txid[65] = {0};
    CHECK(regtest_fund_address(&rt, watch_addr, 0.001, fund_txid),
          "fund_address (create tx to watched script)");
    printf("    Fund txid: %.16s...\n", fund_txid);

    /* Mine 1 block to confirm the funding tx */
    char miner_addr[128] = {0};
    regtest_get_new_address(&rt, miner_addr, sizeof(miner_addr));
    CHECK(regtest_mine_blocks(&rt, 1, miner_addr), "mine 1 confirmation block");

    int tip = regtest_get_block_height(&rt);
    printf("    Tip height: %d\n", tip);

    /* Diagnose: dump registered SPK and scan block to find it */
    {
        printf("    Registered SPK (%zu bytes):", spk_len);
        for (size_t i = 0; i < spk_len; i++) printf(" %02x", spk[i]);
        printf("\n");

        char diag_hash[65] = {0};
        if (regtest_get_block_hash(&rt, tip, diag_hash, sizeof(diag_hash))) {
            printf("    Block %d hash: %s\n", tip, diag_hash);
            printf("    SPKs in block (via getblock verbosity-2):\n");
            spk_scan_t sc = { spk, spk_len, 0 };
            regtest_scan_block_txs(&rt, diag_hash, spk_dump_cb, &sc);
            printf("    SPK found in block by RPC scan: %s\n", sc.found ? "YES" : "NO");

            /* Also dump the raw filter */
            unsigned char diag_filter[65536];
            size_t diag_len = 0;
            unsigned char diag_key[16];
            if (regtest_get_block_filter(&rt, diag_hash, diag_filter, &diag_len,
                                          sizeof(diag_filter), diag_key)) {
                printf("    Filter: %zu bytes, key:", diag_len);
                for (int i = 0; i < 16; i++) printf(" %02x", diag_key[i]);
                printf("\n    Filter hex:");
                for (size_t i = 0; i < diag_len && i < 32; i++)
                    printf(" %02x", diag_filter[i]);
                printf("\n");
                int direct = bip158_scan_filter(&backend, diag_filter, diag_len, diag_key);
                printf("    bip158_scan_filter(direct) = %d\n", direct);
            }
        }
    }

    /* Scan from (tip-1) so we only process the just-mined block */
    backend.tip_height = tip - 1;
    int matches = bip158_backend_scan(&backend);
    printf("    bip158_backend_scan() = %d\n", matches);
    CHECK(matches >= 1, "scan returns >= 1 match");

    /* Verify the cache was populated */
    int confs = backend.base.get_confirmations(&backend.base, fund_txid);
    printf("    get_confirmations(%s...) = %d\n", fund_txid, confs);
    CHECK(confs >= 1, "get_confirmations >= 1");

    bip158_backend_free(&backend);
    printf("  [A] %s\n", (matches >= 1 && confs >= 1) ? "PASS" : "FAIL");
    return (matches >= 1 && confs >= 1);
}

/* -------------------------------------------------------------------------
 * Test B: Phase 4 — P2P compact filter download
 * Same setup as A, but uses P2P getcfilters/cfilter for filter fetching.
 * RPC is still used for block-hash lookup and full-block scan on hit.
 * ------------------------------------------------------------------------- */
static int test_b_phase4_p2p(void)
{
    printf("\n[B] Phase 4: P2P compact filter scan\n");

    regtest_t rt;
    if (!init_rt(&rt)) {
        printf("    SKIP: cannot connect to isolated bitcoind on port %d\n", g_rpcport);
        return 0;
    }
    if (!setup_wallet(&rt)) return 0;

    /* Get a DIFFERENT fresh address so this test is independent */
    char watch_addr[128] = {0};
    regtest_get_new_address(&rt, watch_addr, sizeof(watch_addr));
    printf("    Watch address: %s\n", watch_addr);

    unsigned char spk[34];
    size_t spk_len = 0;
    regtest_get_address_scriptpubkey(&rt, watch_addr, spk, &spk_len);
    CHECK(spk_len > 0, "scriptpubkey non-empty");

    bip158_backend_t backend;
    bip158_backend_init(&backend, "regtest");
    bip158_backend_set_rpc(&backend, &rt);
    backend.base.register_script(&backend.base, spk, spk_len);

    /* Fund and confirm */
    char fund_txid[65] = {0};
    CHECK(regtest_fund_address(&rt, watch_addr, 0.001, fund_txid),
          "fund_address");
    printf("    Fund txid: %.16s...\n", fund_txid);

    char miner_addr[128] = {0};
    regtest_get_new_address(&rt, miner_addr, sizeof(miner_addr));
    CHECK(regtest_mine_blocks(&rt, 1, miner_addr), "mine 1 confirmation block");

    int tip = regtest_get_block_height(&rt);
    printf("    Tip height: %d\n", tip);

    /* Connect P2P to our isolated node */
    int p2p_ok = bip158_backend_connect_p2p(&backend, "127.0.0.1", g_p2pport);
    printf("    P2P connect to 127.0.0.1:%d: %s\n",
           g_p2pport, p2p_ok ? "OK" : "FAILED");
    CHECK(p2p_ok, "P2P connect");

    if (!p2p_ok) {
        bip158_backend_free(&backend);
        return 0;
    }

    /* Scan from (tip-1) — filter fetched via P2P, block scan still via RPC */
    backend.tip_height = tip - 1;
    int matches = bip158_backend_scan(&backend);
    printf("    bip158_backend_scan() (P2P path) = %d\n", matches);
    CHECK(matches >= 1, "P2P scan returns >= 1 match");

    int confs = backend.base.get_confirmations(&backend.base, fund_txid);
    printf("    get_confirmations = %d\n", confs);
    CHECK(confs >= 1, "get_confirmations >= 1 (P2P path)");

    bip158_backend_free(&backend);
    printf("  [B] %s\n", (matches >= 1 && confs >= 1) ? "PASS" : "FAIL");
    return (matches >= 1 && confs >= 1);
}

/* -------------------------------------------------------------------------
 * Test C: Negative — unregistered script produces zero matches
 * Mine 1 block; watch a script that was NEVER funded.
 * The GCS filter for that block must not match our random script.
 * (There is a ~1/784931 chance of a false positive — acceptable.)
 * ------------------------------------------------------------------------- */
static int test_c_no_match(void)
{
    printf("\n[C] Negative: unregistered script → 0 matches\n");

    regtest_t rt;
    if (!init_rt(&rt)) {
        printf("    SKIP\n");
        return 0;
    }
    if (!setup_wallet(&rt)) return 0;

    /* Register a random 34-byte P2TR-look-alike script that's never been funded */
    unsigned char rand_spk[34];
    memset(rand_spk, 0, 34);
    rand_spk[0] = 0x51; rand_spk[1] = 0x20;
    for (int i = 2; i < 34; i++) rand_spk[i] = (unsigned char)(i * 37 + 99);

    bip158_backend_t backend;
    bip158_backend_init(&backend, "regtest");
    bip158_backend_set_rpc(&backend, &rt);
    backend.base.register_script(&backend.base, rand_spk, 34);

    /* Mine 1 block to give the scan something to check */
    char miner_addr[128] = {0};
    regtest_get_new_address(&rt, miner_addr, sizeof(miner_addr));
    regtest_mine_blocks(&rt, 1, miner_addr);

    int tip = regtest_get_block_height(&rt);
    backend.tip_height = tip - 1;

    int matches = bip158_backend_scan(&backend);
    printf("    bip158_backend_scan() for random script = %d\n", matches);
    /* Expect 0; a false positive is statistically possible but extremely rare */
    CHECK(matches == 0, "random unregistered script: 0 matches");

    bip158_backend_free(&backend);
    printf("  [C] %s\n", matches == 0 ? "PASS" : "FAIL (rare false positive)");
    return (matches == 0);
}

/* -------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */
int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    const char *env_rpc = getenv("BIP158_RPCPORT");
    const char *env_p2p = getenv("BIP158_P2PPORT");
    if (env_rpc) g_rpcport = atoi(env_rpc);
    if (env_p2p) g_p2pport = atoi(env_p2p);

    printf("=== BIP 158 Integration Tests ===\n");
    printf("RPC port: %d   P2P port: %d\n", g_rpcport, g_p2pport);

    test_a_phase3_rpc();
    test_b_phase4_p2p();
    test_c_no_match();

    printf("\n==============================\n");
    printf("Results: %d/%d passed\n", g_pass, g_pass + g_fail);
    return (g_fail > 0) ? 1 : 0;
}
