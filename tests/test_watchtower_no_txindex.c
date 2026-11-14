/*
 * test_watchtower_no_txindex.c — the watchtower finds a breach by scanning
 * blocks; it does not need -txindex.
 *
 * The node is a stand-in bitcoin-cli (a shell script written per test) that
 * answers like a node without a transaction index: gettransaction and
 * getrawtransaction say "No such mempool or blockchain transaction" for the
 * watched txid, although the txid is in a block that getblock returns.
 * That block is 40 blocks below the tip, deeper than the tower's usual
 * search window.
 *
 *   test_watchtower_finds_breach_below_window
 *       the database stores the height the tower last searched from; the
 *       tower searches every block from there, finds the breach and sends
 *       the penalty, then moves the stored height up.
 *   test_watchtower_window_without_floor
 *       control: with no stored height the usual window is all that is
 *       searched; the same block is not reached, so nothing is sent.
 *       This shows the node answers as described.
 */

#include "superscalar/regtest.h"
#include "superscalar/chain_backend.h"
#include "superscalar/watchtower.h"
#include "superscalar/persist_wt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define TEST_ASSERT_GOTO(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        goto done; \
    } \
} while(0)

static const char *WT_TXID =
    "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

typedef struct {
    char dir[64];
    regtest_t rt;
} wt_fake_t;

/* A node at height 100 with no transaction index.  Block 60 holds WT_TXID. */
static int wt_fake_make(wt_fake_t *f) {
    memset(f, 0, sizeof(*f));
    snprintf(f->dir, sizeof(f->dir), "/tmp/ss-fake-wt-XXXXXX");
    if (!mkdtemp(f->dir)) { f->dir[0] = '\0'; return 0; }
    char path[128];
    snprintf(path, sizeof(path), "%s/bitcoin-cli", f->dir);
    FILE *fp = fopen(path, "w");
    if (!fp) return 0;
    fprintf(fp,
        "#!/bin/sh\n"
        "m=\n"
        "for a in \"$@\"; do case \"$a\" in -*) ;; *) m=\"$a\"; break ;; esac; done\n"
        "echo \"$m\" >> '%s/calls'\n"
        "case \"$m\" in\n"
        "getblockcount) echo 100 ;;\n"
        "getblockhash) for a in \"$@\"; do l=$a; done; echo \"\\\"hash$l\\\"\" ;;\n"
        "getblock) case \"$*\" in\n"
        "  *hash60*) echo '{\"confirmations\":41,\"tx\":[\"%s\"]}' ;;\n"
        "  *) echo '{\"confirmations\":1,\"tx\":[]}' ;; esac ;;\n"
        "gettransaction|getrawtransaction|getmempoolentry)\n"
        "  echo 'error code: -5'; echo 'error message:'; "
        "echo 'No such mempool or blockchain transaction'; exit 5 ;;\n"
        "*) echo 'error code: -32601'; echo 'error message:'; "
        "echo 'Method not found'; exit 1 ;;\n"
        "esac\n"
        "exit 0\n", f->dir, WT_TXID);
    fclose(fp);
    if (chmod(path, 0755) != 0) return 0;
    snprintf(f->rt.cli_path, sizeof(f->rt.cli_path), "%s", path);
    snprintf(f->rt.rpcuser, sizeof(f->rt.rpcuser), "rpcuser");
    snprintf(f->rt.rpcpassword, sizeof(f->rt.rpcpassword), "rpcpass");
    snprintf(f->rt.network, sizeof(f->rt.network), "regtest");
    f->rt.rpcport = 0;
    f->rt.scan_depth = 10;
    return 1;
}

/* Calls so far that try to put the penalty on the network. */
static int wt_fake_sends(const wt_fake_t *f) {
    char path[128], line[128];
    snprintf(path, sizeof(path), "%s/calls", f->dir);
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    int n = 0;
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0';
        if (!strcmp(line, "sendrawtransaction") ||
            !strcmp(line, "testmempoolaccept") ||
            !strcmp(line, "submitpackage"))
            n++;
    }
    fclose(fp);
    return n;
}

static void wt_fake_remove(const wt_fake_t *f) {
    char path[128];
    if (!f->dir[0]) return;
    snprintf(path, sizeof(path), "%s/calls", f->dir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/bitcoin-cli", f->dir);
    unlink(path);
    rmdir(f->dir);
}

/* A tower with one watched commitment txid and pre-signed penalty bytes. */
static int wt_make_tower(watchtower_t *wt, regtest_t *rt) {
    if (!watchtower_init(wt, 0, rt, NULL, NULL)) return 0;
    unsigned char txid[32];
    memset(txid, 0xcd, 32);
    unsigned char spk[34] = {0x51, 0x20};
    memset(spk + 2, 0xaa, 32);
    unsigned char penalty[120];
    memset(penalty, 0x01, sizeof(penalty));
    watchtower_watch_oracular(wt, 0, 1, txid, 0, 10000, spk, 34,
                              penalty, sizeof(penalty));
    /* as a tower hydrated from its database: no registration height */
    wt->entries[0].registered_height = 0;
    return wt->n_entries == 1;
}

int test_watchtower_finds_breach_below_window(void) {
    int rc = 0;
    wt_fake_t f;
    watchtower_t wt;
    persist_wt_t pwt;
    char db_path[128] = "";
    int have_wt = 0, have_db = 0;
    memset(&pwt, 0, sizeof(pwt));

    TEST_ASSERT_GOTO(wt_fake_make(&f), "fake cli");
    snprintf(db_path, sizeof(db_path), "%s/wt.db", f.dir);
    TEST_ASSERT_GOTO(persist_wt_open(&pwt, db_path), "open wt db");
    have_db = 1;
    TEST_ASSERT_GOTO(persist_wt_set_scan_from(&pwt, 50), "store scan floor");

    TEST_ASSERT_GOTO(wt_make_tower(&wt, &f.rt), "tower");
    have_wt = 1;
    wt.scan_db = &pwt;

    watchtower_check(&wt);
    int sends = wt_fake_sends(&f);
    printf("\n    penalty send calls: %d", sends);
    TEST_ASSERT_GOTO(sends > 0,
        "the breach in a block 40 below the tip was found without -txindex");

    int h = 0;
    TEST_ASSERT_GOTO(persist_wt_get_scan_from(&pwt, &h), "floor still stored");
    printf("; stored floor now %d", h);
    TEST_ASSERT_GOTO(h > 50 && h <= 100, "the stored floor moved up");
    rc = 1;
done:
    if (have_wt) watchtower_cleanup(&wt);
    if (have_db) persist_wt_close(&pwt);
    unlink(db_path);
    {
        char p2[140];
        snprintf(p2, sizeof(p2), "%s-wal", db_path); unlink(p2);
        snprintf(p2, sizeof(p2), "%s-shm", db_path); unlink(p2);
    }
    wt_fake_remove(&f);
    return rc;
}

int test_watchtower_window_without_floor(void) {
    int rc = 0;
    wt_fake_t f;
    watchtower_t wt;
    int have_wt = 0;

    TEST_ASSERT_GOTO(wt_fake_make(&f), "fake cli");
    TEST_ASSERT_GOTO(wt_make_tower(&wt, &f.rt), "tower");
    have_wt = 1;

    watchtower_check(&wt);
    TEST_ASSERT_GOTO(wt_fake_sends(&f) == 0,
        "without a stored floor only the usual window is searched");
    rc = 1;
done:
    if (have_wt) watchtower_cleanup(&wt);
    wt_fake_remove(&f);
    return rc;
}
