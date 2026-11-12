/* Unit tests for lsp_check_rotation_readiness().
   Tests the null/not-ready early-exit paths, which do not call
   lsp_channels_rotate_factory() and require no live LSP state. */

#include "superscalar/lsp_channels.h"
#include "superscalar/readiness.h"
#include "superscalar/ladder.h"
#include "superscalar/lsp.h"
#include "superscalar/chain_backend.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

/* Test 1: readiness == NULL — returns 0 without touching lsp. */
int test_rotation_readiness_null(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    /* mgr.readiness is NULL */
    TEST_ASSERT(lsp_check_rotation_readiness(&mgr, NULL) == 0,
                "returns 0 when readiness is NULL");
    return 1;
}

/* Test 2: readiness set but no clients connected — returns 0. */
int test_rotation_readiness_none_connected(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));

    readiness_tracker_t rt;
    readiness_init(&rt, 1, 3, NULL);
    mgr.readiness = &rt;

    /* No clients connected or ready */
    TEST_ASSERT(lsp_check_rotation_readiness(&mgr, NULL) == 0,
                "returns 0 when no clients ready");
    return 1;
}

/* Test 3: partial readiness (2/3 ready) — returns 0. */
int test_rotation_readiness_partial(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));

    readiness_tracker_t rt;
    readiness_init(&rt, 1, 3, NULL);

    /* Connect and mark ready: clients 0 and 1, but not 2 */
    readiness_set_connected(&rt, 0, 1);
    readiness_set_ready(&rt, 0, QUEUE_REQ_ROTATION);
    readiness_set_connected(&rt, 1, 1);
    readiness_set_ready(&rt, 1, QUEUE_REQ_ROTATION);

    mgr.readiness = &rt;

    TEST_ASSERT(lsp_check_rotation_readiness(&mgr, NULL) == 0,
                "returns 0 when only 2/3 clients ready");
    /* Tracker should be unmodified — reset not called on partial */
    TEST_ASSERT(readiness_count_ready(&rt) == 2, "tracker unchanged");
    return 1;
}


/* --- Rotation is off unless the operator opts in --- */

/* A chain backend that reports every outpoint as spent and counts the calls.
   With the dying factory's funding "already spent", an enabled rotation
   completes at once through the restart-resume guard, which touches nothing
   but the chain query and the ladder entry: a positive control that needs no
   clients, wallet or node. */
static int g_rot_chain_calls;
static int rot_mock_outpoint_spent(chain_backend_t *self, const char *txid_hex,
                                   uint32_t vout) {
    (void)self; (void)txid_hex; (void)vout;
    g_rot_chain_calls++;
    return 0;
}

/* Builds mgr + ladder with one DYING, funded factory. */
static ladder_t *rot_fixture(lsp_channel_mgr_t *mgr, chain_backend_t *chain,
                             lsp_t *lsp) {
    ladder_t *lad = calloc(1, sizeof(*lad));
    if (!lad) return NULL;
    lad->n_factories = 1;
    lad->factories[0].factory_id = 0;
    lad->factories[0].cached_state = FACTORY_DYING;
    lad->factories[0].is_initialized = 1;
    lad->factories[0].is_funded = 1;
    memset(mgr, 0, sizeof(*mgr));
    memset(chain, 0, sizeof(*chain));
    memset(lsp, 0, sizeof(*lsp));
    chain->is_outpoint_unspent = rot_mock_outpoint_spent;
    mgr->ladder = lad;
    mgr->chain_be = chain;
    mgr->rot_fee_est = (void *)chain;   /* only checked for non-NULL first */
    g_rot_chain_calls = 0;
    return lad;
}

/* A manager as lsp_channels_init leaves it has rotation off, and every
   rotation request is refused before anything is looked at.  Enabling it
   (positive control) lets the same request through. */
int test_rotation_refused_without_opt_in(void) {
    lsp_channel_mgr_t mgr;
    chain_backend_t chain;
    lsp_t lsp;
    ladder_t *lad = rot_fixture(&mgr, &chain, &lsp);
    TEST_ASSERT(lad != NULL, "alloc");

    TEST_ASSERT(mgr.rot_enabled == 0 && mgr.rot_auto_rotate == 0,
                "rotation is off in a zeroed manager");
    TEST_ASSERT(lsp_channels_rotate_factory(&mgr, &lsp) == 0,
                "rotation refused without the opt-in");
    TEST_ASSERT(g_rot_chain_calls == 0, "refused before any chain query");
    TEST_ASSERT(lad->factories[0].partial_rotation_done == 0,
                "the dying factory is left alone");

    /* Automatic-only (no opt-in) is still off. */
    lsp_channels_set_rotation(&mgr, 0, 1);
    TEST_ASSERT(mgr.rot_enabled == 0 && mgr.rot_auto_rotate == 0,
                "daemon mode alone does not turn rotation on");
    TEST_ASSERT(lsp_channels_rotate_factory(&mgr, &lsp) == 0,
                "still refused");
    TEST_ASSERT(g_rot_chain_calls == 0, "still no chain query");

    /* Positive control: with the opt-in the request goes through. */
    lsp_channels_set_rotation(&mgr, 1, 1);
    TEST_ASSERT(mgr.rot_enabled == 1 && mgr.rot_auto_rotate == 1,
                "opt-in + daemon mode: automatic rotation");
    TEST_ASSERT(lsp_channels_rotate_factory(&mgr, &lsp) == 1,
                "rotation runs with the opt-in");
    TEST_ASSERT(g_rot_chain_calls == 1, "it reached the chain query");
    TEST_ASSERT(lad->factories[0].partial_rotation_done == 1,
                "the dying factory was retired");

    /* Opt-in without daemon mode: manual rotation only. */
    lsp_channels_set_rotation(&mgr, 1, 0);
    TEST_ASSERT(mgr.rot_enabled == 1 && mgr.rot_auto_rotate == 0,
                "opt-in alone: no automatic rotation");
    free(lad);
    return 1;
}

/* The async-rotation path (every client ready) and the CLI "rotate" command
   end in the same refusal. */
int test_rotation_triggers_refused_without_opt_in(void) {
    lsp_channel_mgr_t mgr;
    chain_backend_t chain;
    lsp_t lsp;
    ladder_t *lad = rot_fixture(&mgr, &chain, &lsp);
    TEST_ASSERT(lad != NULL, "alloc");

    readiness_tracker_t rt;
    readiness_init(&rt, 0, 2, NULL);
    for (uint32_t i = 0; i < 2; i++) {
        readiness_set_connected(&rt, i, 1);
        readiness_set_ready(&rt, i, QUEUE_REQ_ROTATION);
    }
    mgr.readiness = &rt;
    TEST_ASSERT(readiness_all_ready(&rt), "every client ready");
    TEST_ASSERT(lsp_check_rotation_readiness(&mgr, &lsp) == 0,
                "all-ready async gate does not rotate without the opt-in");
    TEST_ASSERT(g_rot_chain_calls == 0, "no chain query");
    TEST_ASSERT(lad->factories[0].partial_rotation_done == 0, "factory untouched");

    volatile sig_atomic_t shut = 0;
    TEST_ASSERT(lsp_channels_handle_cli_line(&mgr, &lsp, "rotate", &shut) == 1,
                "CLI rotate is a known command");
    TEST_ASSERT(g_rot_chain_calls == 0 && shut == 0, "CLI rotate does nothing");
    TEST_ASSERT(lad->factories[0].partial_rotation_done == 0, "factory untouched");

    /* Positive control: the same all-ready gate rotates with the opt-in. */
    readiness_init(&rt, 0, 2, NULL);
    for (uint32_t i = 0; i < 2; i++) {
        readiness_set_connected(&rt, i, 1);
        readiness_set_ready(&rt, i, QUEUE_REQ_ROTATION);
    }
    lsp_channels_set_rotation(&mgr, 1, 1);
    TEST_ASSERT(lsp_check_rotation_readiness(&mgr, &lsp) == 1,
                "all-ready async gate rotates with the opt-in");
    TEST_ASSERT(lad->factories[0].partial_rotation_done == 1, "factory retired");
    free(lad);
    return 1;
}
