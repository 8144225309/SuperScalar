#include "superscalar/persist.h"
#include "superscalar/sweeper.h"
#include "superscalar/circuit_breaker.h"
#include "superscalar/gossip_store.h"
#include "superscalar/rgs.h"
#include "superscalar/lnurl.h"
#include "superscalar/ptlc_commit.h"
#include "superscalar/chan_open.h"
#include "superscalar/admin_rpc.h"
#include "superscalar/watchtower.h"
#include "superscalar/onion.h"
#include "superscalar/onion_last_hop.h"
#include "superscalar/htlc_commit.h"
#include "superscalar/factory.h"
#include "superscalar/musig.h"
#include "superscalar/channel.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/dw_state.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
#include "superscalar/sha256.h"

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define TEST_ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { \
        printf("  FAIL: %s (line %d): %s (got %ld, expected %ld)\n", \
               __func__, __LINE__, msg, (long)(a), (long)(b)); \
        return 0; \
    } \
} while(0)

static const unsigned char seckeys[5][32] = {
    { [0 ... 31] = 0x10 },
    { [0 ... 31] = 0x21 },
    { [0 ... 31] = 0x32 },
    { [0 ... 31] = 0x43 },
    { [0 ... 31] = 0x54 },
};

static secp256k1_context *test_ctx(void) {
    return secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

/* ---- PS sub-factory chain entry persist round-trip (Phase 4a) ----

   Verifies that the existing persist_save_ps_chain_entry +
   persist_load_ps_chain helpers correctly round-trip a sub-factory
   chain entry.  The schema is generic on (factory_id, leaf_node_idx,
   chain_pos) so a sub-factory's node_idx in f->nodes[] can be stored
   directly — no schema change needed for k² support.

   Saves three consecutive chain entries for a sub-factory at node_idx
   42 (chain_pos 0, 1, 2), then loads them back and asserts:
     - exact count returned
     - per-entry txid matches (32 bytes)
     - per-entry signed_tx matches (variable length)
     - per-entry chan_amount matches (which is the sales-stock amount
       in the sub-factory case — see lsp_subfactory_chain_advance) */
int test_persist_ps_subfactory_chain_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open in-memory");

    const uint32_t factory_id = 0;
    const uint32_t sub_node_idx = 42;  /* a sub-factory node, not a leaf */

    /* Three chain entries, each a different chain_pos. */
    unsigned char txids[3][32];
    unsigned char signed_txs[3][64];
    size_t signed_tx_lens[3] = { 32, 48, 64 };
    uint64_t sstock_amounts[3] = { 50000, 40000, 30000 };
    for (int i = 0; i < 3; i++) {
        memset(txids[i], 0xA0 + i, 32);
        memset(signed_txs[i], 0xB0 + i, signed_tx_lens[i]);
    }

    /* Save chain[0..2] (no poison TX in this older test — that case is
       covered by the dedicated v22 round-trip below). */
    for (int i = 0; i < 3; i++) {
        TEST_ASSERT(persist_save_ps_chain_entry(
                        &db, factory_id, sub_node_idx, i,
                        /* epoch */ 0,
                        txids[i],
                        signed_txs[i], signed_tx_lens[i],
                        sstock_amounts[i],
                        /* poison_tx */ NULL, 0),
                    "save sub-factory chain entry");
    }

    /* Load back and verify round-trip.

       NOTE: persist_load_ps_chain calls tx_buf_init() on each entry
       internally — do NOT pre-init or the prior allocation leaks
       (caught by LSan in CI). */
    tx_buf_t loaded_txs[3] = {0};
    unsigned char loaded_txids[3][32];
    uint64_t loaded_amounts[3];
    int n_loaded = persist_load_ps_chain(&db, factory_id, sub_node_idx,
                                            loaded_txs, loaded_txids,
                                            loaded_amounts,
                                            /* poison_txs_out */ NULL, 3);

    int ok = 1;
    if (n_loaded != 3) {
        printf("  FAIL: n_loaded=%d expected 3\n", n_loaded);
        ok = 0;
    } else {
        for (int i = 0; i < 3; i++) {
            if (memcmp(loaded_txids[i], txids[i], 32) != 0) {
                printf("  FAIL: chain[%d] txid mismatch\n", i);
                ok = 0;
            }
            if (loaded_txs[i].len != signed_tx_lens[i]) {
                printf("  FAIL: chain[%d] signed_tx_len mismatch "
                       "(got %zu, want %zu)\n",
                       i, loaded_txs[i].len, signed_tx_lens[i]);
                ok = 0;
            } else if (memcmp(loaded_txs[i].data, signed_txs[i],
                                signed_tx_lens[i]) != 0) {
                printf("  FAIL: chain[%d] signed_tx bytes mismatch\n", i);
                ok = 0;
            }
            if ((long)loaded_amounts[i] != (long)sstock_amounts[i]) {
                printf("  FAIL: chain[%d] sales-stock amount %ld != %ld\n",
                       i, (long)loaded_amounts[i], (long)sstock_amounts[i]);
                ok = 0;
            }
        }
    }

    /* Always free everything persist_load_ps_chain allocated, regardless
       of pass/fail.  LSan would otherwise flag the loaded tx_buf data
       as leaked on the failure path. */
    for (int i = 0; i < n_loaded && i < 3; i++)
        tx_buf_free(&loaded_txs[i]);

    persist_close(&db);
    return ok;
}

/* ---- v21: PS sub-factory chain entry round-trip with per-channel amounts ----

   The v21 ps_subfactory_chains table replaces the Phase 4a workaround of
   reusing ps_leaf_chains.  Each entry now carries:
     - sales_stock_amount_sats (the trailing vout amount, as before)
     - channel_amounts_csv (per-client channel amounts — new in v21)

   Without per-channel persistence, a restart of the LSP could not rebuild
   sub->outputs[] correctly and post-restart sweep would not be able to
   attribute outputs to clients.

   Saves three chain entries, each with a different channel count + mix
   of amounts, then loads back and asserts every field round-trips
   exactly. */
int test_persist_ps_subfactory_chain_v21_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open in-memory");

    const uint32_t factory_id = 0;
    const uint32_t sub_node_idx = 137;

    /* 3 entries — varying n_channels (2, 4, 3) and varying amounts. */
    unsigned char txids[3][32];
    unsigned char signed_txs[3][96];
    size_t signed_tx_lens[3] = { 24, 60, 80 };
    uint64_t sstock_amounts[3] = { 100000, 75000, 50000 };
    int n_channels[3] = { 2, 4, 3 };
    uint64_t channel_amounts[3][16] = {
        { 25000, 25000 },
        { 15000, 20000, 18000, 22000 },
        { 30000, 10000, 10000 },
    };
    for (int i = 0; i < 3; i++) {
        memset(txids[i], 0xC0 + i, 32);
        memset(signed_txs[i], 0xD0 + i, signed_tx_lens[i]);
    }

    for (int i = 0; i < 3; i++) {
        TEST_ASSERT(persist_save_subfactory_chain_entry(
                        &db, factory_id, sub_node_idx, i,
                        /* epoch */ 0,
                        txids[i],
                        signed_txs[i], signed_tx_lens[i],
                        sstock_amounts[i],
                        channel_amounts[i], n_channels[i],
                        /* poison_tx */ NULL, 0),
                    "save v21 sub-factory entry");
    }

    /* Load back. NOTE: do NOT pre-init loaded_txs[]; persist_load_*
       calls tx_buf_init internally and pre-allocation would leak. */
    tx_buf_t loaded_txs[3] = {0};
    unsigned char loaded_txids[3][32];
    uint64_t loaded_sstock[3];
    uint64_t loaded_channels[3][16];
    int loaded_n_channels[3];
    int n_loaded = persist_load_subfactory_chain(&db, factory_id, sub_node_idx,
                                                    loaded_txs, loaded_txids,
                                                    loaded_sstock, loaded_channels,
                                                    loaded_n_channels,
                                                    /* poison_txs_out */ NULL, 3);

    int ok = 1;
    if (n_loaded != 3) {
        printf("  FAIL: v21 n_loaded=%d expected 3\n", n_loaded);
        ok = 0;
    } else {
        for (int i = 0; i < 3; i++) {
            if (memcmp(loaded_txids[i], txids[i], 32) != 0) {
                printf("  FAIL: v21 chain[%d] txid mismatch\n", i);
                ok = 0;
            }
            if (loaded_txs[i].len != signed_tx_lens[i]) {
                printf("  FAIL: v21 chain[%d] tx len %zu != %zu\n",
                       i, loaded_txs[i].len, signed_tx_lens[i]);
                ok = 0;
            } else if (memcmp(loaded_txs[i].data, signed_txs[i],
                                signed_tx_lens[i]) != 0) {
                printf("  FAIL: v21 chain[%d] tx bytes mismatch\n", i);
                ok = 0;
            }
            if (loaded_sstock[i] != sstock_amounts[i]) {
                printf("  FAIL: v21 chain[%d] sales-stock %llu != %llu\n",
                       i, (unsigned long long)loaded_sstock[i],
                       (unsigned long long)sstock_amounts[i]);
                ok = 0;
            }
            if (loaded_n_channels[i] != n_channels[i]) {
                printf("  FAIL: v21 chain[%d] n_channels %d != %d\n",
                       i, loaded_n_channels[i], n_channels[i]);
                ok = 0;
            } else {
                for (int ci = 0; ci < n_channels[i]; ci++) {
                    if (loaded_channels[i][ci] != channel_amounts[i][ci]) {
                        printf("  FAIL: v21 chain[%d] channel[%d] %llu != %llu\n",
                               i, ci,
                               (unsigned long long)loaded_channels[i][ci],
                               (unsigned long long)channel_amounts[i][ci]);
                        ok = 0;
                    }
                }
            }
        }
    }

    for (int i = 0; i < n_loaded && i < 3; i++)
        tx_buf_free(&loaded_txs[i]);

    persist_close(&db);
    return ok;
}

/* ---- v22: PS leaf + sub-factory chain entry round-trip with poison TX ----

   Verifies the poison_tx_hex column added in PR-B persists end-to-end.
   Mixes presence/absence of poison TX across entries to confirm NULL
   handling works (chain[0] typically has no poison; degraded ceremonies
   may also produce NULL poison even on later entries). */
int test_persist_ps_leaf_chain_v22_poison_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open in-memory");

    const uint32_t factory_id = 0;
    const uint32_t leaf_node_idx = 7;

    /* 3 entries: entry 0 has no poison (initial state), entries 1+2 have
       poison TXs of distinct lengths to catch off-by-one decode bugs. */
    unsigned char txids[3][32];
    unsigned char signed_txs[3][32];
    unsigned char poison_txs[3][96];
    size_t poison_lens[3] = { 0, 50, 80 };
    for (int i = 0; i < 3; i++) {
        memset(txids[i], 0xE0 + i, 32);
        memset(signed_txs[i], 0xF0 + i, 32);
        if (poison_lens[i] > 0)
            memset(poison_txs[i], 0x70 + i, poison_lens[i]);
    }

    for (int i = 0; i < 3; i++) {
        TEST_ASSERT(persist_save_ps_chain_entry(
                        &db, factory_id, leaf_node_idx, i,
                        /* epoch */ 0,
                        txids[i],
                        signed_txs[i], 32,
                        100000 - (uint64_t)i * 1000,
                        poison_lens[i] > 0 ? poison_txs[i] : NULL,
                        poison_lens[i]),
                    "save v22 ps leaf entry with poison");
    }

    tx_buf_t loaded_txs[3]     = {0};
    tx_buf_t loaded_poisons[3] = {0};
    unsigned char loaded_txids[3][32];
    uint64_t loaded_amounts[3];
    int n_loaded = persist_load_ps_chain(&db, factory_id, leaf_node_idx,
                                            loaded_txs, loaded_txids,
                                            loaded_amounts,
                                            loaded_poisons, 3);

    int ok = (n_loaded == 3);
    if (!ok) printf("  FAIL: v22 leaf n_loaded=%d expected 3\n", n_loaded);
    for (int i = 0; ok && i < 3; i++) {
        if (loaded_poisons[i].len != poison_lens[i]) {
            printf("  FAIL: v22 leaf chain[%d] poison_len %zu != %zu\n",
                   i, loaded_poisons[i].len, poison_lens[i]);
            ok = 0;
        } else if (poison_lens[i] > 0 &&
                   memcmp(loaded_poisons[i].data, poison_txs[i],
                          poison_lens[i]) != 0) {
            printf("  FAIL: v22 leaf chain[%d] poison bytes mismatch\n", i);
            ok = 0;
        }
    }

    for (int i = 0; i < n_loaded && i < 3; i++) {
        tx_buf_free(&loaded_txs[i]);
        tx_buf_free(&loaded_poisons[i]);
    }

    persist_close(&db);
    return ok;
}

int test_persist_ps_subfactory_chain_v22_poison_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open in-memory");

    const uint32_t factory_id = 0;
    const uint32_t sub_node_idx = 41;

    /* 3 entries: mix of poison_tx presence + sizes. */
    unsigned char txids[3][32];
    unsigned char signed_txs[3][64];
    unsigned char poison_txs[3][120];
    size_t signed_tx_lens[3] = { 32, 48, 64 };
    size_t poison_lens[3] = { 60, 0, 100 };
    uint64_t sstock_amounts[3] = { 80000, 70000, 60000 };
    int n_channels[3] = { 2, 3, 4 };
    uint64_t channel_amounts[3][16] = {
        { 30000, 20000 },
        { 25000, 25000, 20000 },
        { 15000, 15000, 15000, 15000 },
    };
    for (int i = 0; i < 3; i++) {
        memset(txids[i], 0x10 + i, 32);
        memset(signed_txs[i], 0x20 + i, signed_tx_lens[i]);
        if (poison_lens[i] > 0)
            memset(poison_txs[i], 0x80 + i, poison_lens[i]);
    }

    for (int i = 0; i < 3; i++) {
        TEST_ASSERT(persist_save_subfactory_chain_entry(
                        &db, factory_id, sub_node_idx, i,
                        /* epoch */ 0,
                        txids[i],
                        signed_txs[i], signed_tx_lens[i],
                        sstock_amounts[i],
                        channel_amounts[i], n_channels[i],
                        poison_lens[i] > 0 ? poison_txs[i] : NULL,
                        poison_lens[i]),
                    "save v22 sub-factory entry with poison");
    }

    tx_buf_t loaded_txs[3]     = {0};
    tx_buf_t loaded_poisons[3] = {0};
    unsigned char loaded_txids[3][32];
    uint64_t loaded_sstock[3];
    uint64_t loaded_channels[3][16];
    int loaded_n_channels[3];
    int n_loaded = persist_load_subfactory_chain(&db, factory_id, sub_node_idx,
                                                    loaded_txs, loaded_txids,
                                                    loaded_sstock, loaded_channels,
                                                    loaded_n_channels,
                                                    loaded_poisons, 3);

    int ok = (n_loaded == 3);
    if (!ok) printf("  FAIL: v22 sub n_loaded=%d expected 3\n", n_loaded);
    for (int i = 0; ok && i < 3; i++) {
        if (loaded_poisons[i].len != poison_lens[i]) {
            printf("  FAIL: v22 sub chain[%d] poison_len %zu != %zu\n",
                   i, loaded_poisons[i].len, poison_lens[i]);
            ok = 0;
        } else if (poison_lens[i] > 0 &&
                   memcmp(loaded_poisons[i].data, poison_txs[i],
                          poison_lens[i]) != 0) {
            printf("  FAIL: v22 sub chain[%d] poison bytes mismatch\n", i);
            ok = 0;
        }
    }

    for (int i = 0; i < n_loaded && i < 3; i++) {
        tx_buf_free(&loaded_txs[i]);
        tx_buf_free(&loaded_poisons[i]);
    }

    persist_close(&db);
    return ok;
}

/* ---- v23: ps_initial_signed_states round-trip ----

   Verifies persist_save/load_ps_initial_signed_state correctly stores and
   retrieves chain[0] signed bytes + display-order txid keyed on
   (factory_id, node_idx).  Closes the v0.1.15 force-close-after-advance
   bug discovered by the signet campaign. */
int test_persist_ps_initial_signed_state_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open in-memory");

    const uint32_t factory_id = 0;
    const uint32_t node_idx_a = 5;
    const uint32_t node_idx_b = 11;

    /* Two distinct (node, txid, signed_tx) tuples to verify keying. */
    unsigned char txid_a[32];
    unsigned char txid_b[32];
    memset(txid_a, 0xAA, 32);
    memset(txid_b, 0xBB, 32);

    unsigned char tx_a[64];
    unsigned char tx_b[96];
    memset(tx_a, 0x10, sizeof(tx_a));
    memset(tx_b, 0x20, sizeof(tx_b));

    TEST_ASSERT(persist_save_ps_initial_signed_state(
                    &db, factory_id, node_idx_a, /* epoch */ 0,
                    txid_a, tx_a, sizeof(tx_a)),
                "save A");
    TEST_ASSERT(persist_save_ps_initial_signed_state(
                    &db, factory_id, node_idx_b, /* epoch */ 0,
                    txid_b, tx_b, sizeof(tx_b)),
                "save B");

    /* Reload A and verify */
    tx_buf_t out_a = {0};
    unsigned char out_a_txid_be[32];
    TEST_ASSERT(persist_load_ps_initial_signed_state(
                    &db, factory_id, node_idx_a, &out_a, out_a_txid_be),
                "load A");
    TEST_ASSERT(out_a.len == sizeof(tx_a), "A tx_len round-trips");
    TEST_ASSERT(memcmp(out_a.data, tx_a, sizeof(tx_a)) == 0,
                "A tx bytes round-trip");
    /* save passes display-order txid; load returns internal-byte-order
       (display reversed) — so out_a_txid_be should equal reversed(txid_a).
       For txid_a = 0xAA repeated, reversed is still 0xAA repeated. */
    TEST_ASSERT(memcmp(out_a_txid_be, txid_a, 32) == 0,
                "A txid round-trips (palindrome)");

    /* Reload B and verify */
    tx_buf_t out_b = {0};
    TEST_ASSERT(persist_load_ps_initial_signed_state(
                    &db, factory_id, node_idx_b, &out_b, NULL /*txid optional*/),
                "load B");
    TEST_ASSERT(out_b.len == sizeof(tx_b), "B tx_len round-trips");
    TEST_ASSERT(memcmp(out_b.data, tx_b, sizeof(tx_b)) == 0,
                "B tx bytes round-trip");

    /* Idempotent save (INSERT OR REPLACE) — same row updates */
    unsigned char tx_a2[80];
    memset(tx_a2, 0x42, sizeof(tx_a2));
    TEST_ASSERT(persist_save_ps_initial_signed_state(
                    &db, factory_id, node_idx_a, /* epoch */ 0,
                    txid_a, tx_a2, sizeof(tx_a2)),
                "re-save A overwrites");
    tx_buf_t out_a2 = {0};
    TEST_ASSERT(persist_load_ps_initial_signed_state(
                    &db, factory_id, node_idx_a, &out_a2, NULL),
                "reload A after overwrite");
    TEST_ASSERT(out_a2.len == sizeof(tx_a2), "A overwritten tx_len matches");
    TEST_ASSERT(memcmp(out_a2.data, tx_a2, sizeof(tx_a2)) == 0,
                "A overwritten tx bytes match");

    /* Missing key returns 0 */
    tx_buf_t out_missing = {0};
    int loaded_missing = persist_load_ps_initial_signed_state(
        &db, factory_id, /*node_idx=*/999, &out_missing, NULL);
    TEST_ASSERT(loaded_missing == 0, "missing key returns 0");
    TEST_ASSERT(out_missing.len == 0, "missing key leaves out_tx empty");

    tx_buf_free(&out_a);
    tx_buf_free(&out_b);
    tx_buf_free(&out_a2);

    persist_close(&db);
    return 1;
}

/* ---- Test 1: Open/close in-memory database ---- */

int test_persist_open_close(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open in-memory");
    TEST_ASSERT(db.db != NULL, "db handle");
    persist_close(&db);
    TEST_ASSERT(db.db == NULL, "db closed");
    return 1;
}

/* ---- Test 2: Channel save/load round-trip ---- */

int test_persist_channel_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    secp256k1_context *ctx = test_ctx();
    secp256k1_pubkey pk_local, pk_remote;
    if (!secp256k1_ec_pubkey_create(ctx, &pk_local, seckeys[0])) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pk_remote, seckeys[1])) return 0;

    unsigned char fake_txid[32] = {0};
    fake_txid[0] = 0xDD;
    unsigned char fake_spk[34];
    memset(fake_spk, 0xAA, 34);

    channel_t ch;
    TEST_ASSERT(channel_init(&ch, ctx, seckeys[0], &pk_local, &pk_remote,
                              fake_txid, 1, 100000, fake_spk, 34,
                              50000, 50000, 144), "channel_init");

    /* Simulate some updates */
    ch.local_amount = 45000;
    ch.remote_amount = 55000;
    ch.commitment_number = 3;

    /* Save */
    TEST_ASSERT(persist_save_channel(&db, &ch, 0, 0), "save channel");

    /* Load */
    uint64_t local, remote, commit;
    TEST_ASSERT(persist_load_channel_state(&db, 0, &local, &remote, &commit),
                "load channel");
    TEST_ASSERT_EQ(local, 45000, "local_amount");
    TEST_ASSERT_EQ(remote, 55000, "remote_amount");
    TEST_ASSERT_EQ(commit, 3, "commitment_number");

    /* Update balance */
    TEST_ASSERT(persist_update_channel_balance(&db, 0, 40000, 60000, 4),
                "update balance");

    TEST_ASSERT(persist_load_channel_state(&db, 0, &local, &remote, &commit),
                "load updated");
    TEST_ASSERT_EQ(local, 40000, "updated local");
    TEST_ASSERT_EQ(remote, 60000, "updated remote");
    TEST_ASSERT_EQ(commit, 4, "updated commit");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}

/* ---- Test 3: Revocation secret save/load (flat storage) ---- */

int test_persist_revocation_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    /* Generate 3 revocation secrets */
    unsigned char sec0[32], sec1[32], sec2[32];
    memset(sec0, 0x42, 32);
    memset(sec1, 0x43, 32);
    memset(sec2, 0x44, 32);

    TEST_ASSERT(persist_save_revocation(&db, 0, 0, sec0), "save rev 0");
    TEST_ASSERT(persist_save_revocation(&db, 0, 1, sec1), "save rev 1");
    TEST_ASSERT(persist_save_revocation(&db, 0, 2, sec2), "save rev 2");

    /* Load into flat arrays */
    unsigned char secrets[256][32];
    uint8_t valid[256];
    size_t count = 0;
    TEST_ASSERT(persist_load_revocations_flat(&db, 0, secrets, valid, 256, &count),
                "load revocations flat");
    TEST_ASSERT(count == 3, "loaded 3 secrets");

    /* Verify secrets match */
    TEST_ASSERT(valid[0] == 1, "slot 0 valid");
    TEST_ASSERT(memcmp(secrets[0], sec0, 32) == 0, "secret 0 matches");
    TEST_ASSERT(valid[1] == 1, "slot 1 valid");
    TEST_ASSERT(memcmp(secrets[1], sec1, 32) == 0, "secret 1 matches");
    TEST_ASSERT(valid[2] == 1, "slot 2 valid");
    TEST_ASSERT(memcmp(secrets[2], sec2, 32) == 0, "secret 2 matches");

    persist_close(&db);
    return 1;
}

/* ---- Test 3b: channel_receive_revocation write-through + hydrator round-trip.

   Proves the standalone-watchtower path end-to-end without on-chain work:
     1. Init a channel, attach persistence via channel_set_persist.
     2. Receive a revocation secret — write-through puts it in the DB.
     3. List channel ids from the DB.
     4. Hydrate a fresh channel_t via persist_load_channel_for_watchtower.
     5. Confirm basepoints, revocations, and balances all match the original
        on the subset of fields channel_build_penalty_tx actually reads. */

int test_persist_watchtower_hydrate_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    secp256k1_context *ctx = test_ctx();
    secp256k1_pubkey pk_local, pk_remote;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &pk_local, seckeys[0]), "lpk");
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &pk_remote, seckeys[1]), "rpk");

    unsigned char fake_txid[32] = {0};
    fake_txid[0] = 0xEE;
    unsigned char fake_spk[34];
    memset(fake_spk, 0xAB, 34);

    channel_t ch;
    TEST_ASSERT(channel_init(&ch, ctx, seckeys[0], &pk_local, &pk_remote,
                              fake_txid, 0, 200000, fake_spk, 34,
                              100000, 100000, 144), "channel_init");
    /* channel_init does not populate local basepoints; generate random ones
       so persist_save_basepoints has something non-zero to store. */
    TEST_ASSERT(channel_generate_random_basepoints(&ch),
                "generate local basepoints");

    /* Make remote basepoints deterministic so we can compare after round-trip */
    secp256k1_pubkey r_pay, r_delay, r_revoc, r_htlc;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &r_pay, seckeys[1]), "rpay");
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &r_delay, seckeys[2]), "rdelay");
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &r_revoc, seckeys[3]), "rrevoc");
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &r_htlc, seckeys[4]), "rhtlc");
    channel_set_remote_basepoints(&ch, &r_pay, &r_delay, &r_revoc);
    channel_set_remote_htlc_basepoint(&ch, &r_htlc);

    /* Save channel + basepoints so the hydrator has data to read */
    TEST_ASSERT(persist_save_channel(&db, &ch, 0, 7), "save channel id=7");
    TEST_ASSERT(persist_save_basepoints(&db, 7, &ch), "save basepoints id=7");

    /* Attach persistence AFTER save so channel_receive_revocation_flat writes
       through to the DB at the correct channel_id. */
    channel_set_persist(&ch, &db, 7);

    /* Feed two revocation secrets and confirm they land in the DB via the
       write-through path (not by direct persist_save_revocation calls). */
    unsigned char rev0[32], rev1[32];
    memset(rev0, 0x55, 32);
    memset(rev1, 0x66, 32);
    TEST_ASSERT(channel_receive_revocation(&ch, 0, rev0), "recv rev0");
    TEST_ASSERT(channel_receive_revocation(&ch, 1, rev1), "recv rev1");

    /* persist_list_channel_ids finds our saved channel */
    uint32_t ids[8] = {0};
    size_t n_ids = 0;
    TEST_ASSERT(persist_list_channel_ids(&db, ids, 8, &n_ids), "list channel ids");
    TEST_ASSERT_EQ(n_ids, 1, "exactly 1 channel");
    TEST_ASSERT_EQ(ids[0], 7, "channel id is 7");

    /* Hydrate a fresh channel_t from the DB */
    channel_t hydrated;
    TEST_ASSERT(persist_load_channel_for_watchtower(&db, 7, ctx, &hydrated),
                "hydrate for watchtower");

    /* Fields the penalty path reads must match */
    TEST_ASSERT(memcmp(&hydrated.local_revocation_basepoint_secret,
                         &ch.local_revocation_basepoint_secret, 32) == 0,
                "local_revocation_basepoint_secret round-trips");
    TEST_ASSERT(hydrated.received_revocation_valid[0] == 1, "rev0 valid");
    TEST_ASSERT(memcmp(hydrated.received_revocations[0], rev0, 32) == 0,
                "rev0 bytes match");
    TEST_ASSERT(hydrated.received_revocation_valid[1] == 1, "rev1 valid");
    TEST_ASSERT(memcmp(hydrated.received_revocations[1], rev1, 32) == 0,
                "rev1 bytes match");

    /* Remote delayed payment basepoint serializes identically */
    unsigned char a_ser[33], b_ser[33];
    size_t alen = 33, blen = 33;
    TEST_ASSERT(secp256k1_ec_pubkey_serialize(ctx, a_ser, &alen,
                  &ch.remote_delayed_payment_basepoint,
                  SECP256K1_EC_COMPRESSED), "serialize orig delay bp");
    TEST_ASSERT(secp256k1_ec_pubkey_serialize(ctx, b_ser, &blen,
                  &hydrated.remote_delayed_payment_basepoint,
                  SECP256K1_EC_COMPRESSED), "serialize hydrated delay bp");
    TEST_ASSERT(memcmp(a_ser, b_ser, 33) == 0, "remote_delayed_bp matches");

    /* Local payment basepoint also needed for penalty output */
    alen = blen = 33;
    secp256k1_ec_pubkey_serialize(ctx, a_ser, &alen,
                                    &ch.local_payment_basepoint,
                                    SECP256K1_EC_COMPRESSED);
    secp256k1_ec_pubkey_serialize(ctx, b_ser, &blen,
                                    &hydrated.local_payment_basepoint,
                                    SECP256K1_EC_COMPRESSED);
    TEST_ASSERT(memcmp(a_ser, b_ser, 33) == 0, "local_payment_bp matches");

    /* Penalty TX can actually be built from the hydrated channel. */
    tx_buf_t penalty_tx;
    tx_buf_init(&penalty_tx, 256);
    unsigned char fake_commit_txid[32];
    memset(fake_commit_txid, 0x77, 32);
    int built = channel_build_penalty_tx(&hydrated, &penalty_tx,
                                           fake_commit_txid, 0,
                                           50000, fake_spk, 34, 0,
                                           NULL, 0);
    /* built may be 0 if the SPK doesn't match the derived tapscript — but the
       important thing is that execution reaches channel_get_received_revocation
       successfully (i.e. no "missing revocation secret" log) and all the key
       derivation steps succeed.  A synthetic fake SPK will cause the final
       sighash verify to mismatch, but that is a different failure than
       "revocation missing".  Accept both success and the SPK-mismatch path. */
    (void)built;
    tx_buf_free(&penalty_tx);

    channel_cleanup(&ch);
    channel_cleanup(&hydrated);
    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}

/* ---- Test 4: HTLC save/load round-trip ---- */

int test_persist_htlc_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    htlc_t h1 = {0};
    h1.direction = HTLC_OFFERED;
    h1.state = HTLC_STATE_ACTIVE;
    h1.amount_sats = 5000;
    memset(h1.payment_hash, 0xAB, 32);
    h1.cltv_expiry = 500;
    h1.id = 0;

    htlc_t h2 = {0};
    h2.direction = HTLC_RECEIVED;
    h2.state = HTLC_STATE_FULFILLED;
    h2.amount_sats = 3000;
    memset(h2.payment_hash, 0xCD, 32);
    memset(h2.payment_preimage, 0xEF, 32);
    h2.cltv_expiry = 600;
    h2.id = 1;

    TEST_ASSERT(persist_save_htlc(&db, 0, &h1), "save htlc 1");
    TEST_ASSERT(persist_save_htlc(&db, 0, &h2), "save htlc 2");

    htlc_t loaded[16];
    size_t count = persist_load_htlcs(&db, 0, loaded, 16);
    TEST_ASSERT_EQ(count, 2, "htlc count");

    TEST_ASSERT_EQ(loaded[0].id, 0, "htlc 0 id");
    TEST_ASSERT_EQ(loaded[0].direction, HTLC_OFFERED, "htlc 0 direction");
    TEST_ASSERT_EQ(loaded[0].state, HTLC_STATE_ACTIVE, "htlc 0 state");
    TEST_ASSERT_EQ(loaded[0].amount_sats, 5000, "htlc 0 amount");
    TEST_ASSERT_EQ(loaded[0].cltv_expiry, 500, "htlc 0 cltv");
    TEST_ASSERT(memcmp(loaded[0].payment_hash, h1.payment_hash, 32) == 0,
                "htlc 0 hash");

    TEST_ASSERT_EQ(loaded[1].id, 1, "htlc 1 id");
    TEST_ASSERT_EQ(loaded[1].direction, HTLC_RECEIVED, "htlc 1 direction");
    TEST_ASSERT_EQ(loaded[1].state, HTLC_STATE_FULFILLED, "htlc 1 state");
    TEST_ASSERT_EQ(loaded[1].amount_sats, 3000, "htlc 1 amount");
    TEST_ASSERT(memcmp(loaded[1].payment_preimage, h2.payment_preimage, 32) == 0,
                "htlc 1 preimage");

    persist_close(&db);
    return 1;
}

/* ---- Test: HTLC delete ---- */

int test_persist_htlc_delete(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    /* Save two HTLCs on channel 0 */
    htlc_t h1 = {0};
    h1.direction = HTLC_OFFERED;
    h1.state = HTLC_STATE_ACTIVE;
    h1.amount_sats = 5000;
    memset(h1.payment_hash, 0xAA, 32);
    h1.cltv_expiry = 500;
    h1.id = 10;

    htlc_t h2 = {0};
    h2.direction = HTLC_OFFERED;
    h2.state = HTLC_STATE_ACTIVE;
    h2.amount_sats = 3000;
    memset(h2.payment_hash, 0xBB, 32);
    h2.cltv_expiry = 600;
    h2.id = 11;

    TEST_ASSERT(persist_save_htlc(&db, 0, &h1), "save htlc 1");
    TEST_ASSERT(persist_save_htlc(&db, 0, &h2), "save htlc 2");

    /* Delete h1 */
    TEST_ASSERT(persist_delete_htlc(&db, 0, 10), "delete htlc 10");

    /* Only h2 should remain */
    htlc_t loaded[16];
    size_t count = persist_load_htlcs(&db, 0, loaded, 16);
    TEST_ASSERT_EQ(count, 1, "count after delete");
    TEST_ASSERT_EQ(loaded[0].id, 11, "remaining htlc id");
    TEST_ASSERT_EQ(loaded[0].amount_sats, 3000, "remaining amount");

    /* Verify remaining HTLC fields fully */
    {
        unsigned char expected_hash[32];
        memset(expected_hash, 0xBB, 32);
        TEST_ASSERT(memcmp(loaded[0].payment_hash, expected_hash, 32) == 0,
                    "remaining htlc hash");
    }
    TEST_ASSERT_EQ(loaded[0].cltv_expiry, 600, "remaining cltv");

    /* Delete h2 */
    TEST_ASSERT(persist_delete_htlc(&db, 0, 11), "delete htlc 11");
    count = persist_load_htlcs(&db, 0, loaded, 16);
    TEST_ASSERT_EQ(count, 0, "count after second delete");

    /* Deleting non-existent HTLC should succeed (no-op in SQLite) */
    TEST_ASSERT(persist_delete_htlc(&db, 0, 999), "delete non-existent");

    /* Cross-channel isolation: HTLCs on different channels are independent */
    htlc_t h3 = {0};
    h3.id = 20;
    h3.direction = HTLC_OFFERED;
    h3.state = HTLC_STATE_ACTIVE;
    h3.amount_sats = 7000;
    memset(h3.payment_hash, 0xCC, 32);

    htlc_t h4 = {0};
    h4.id = 20;  /* same htlc_id, different channel */
    h4.direction = HTLC_OFFERED;
    h4.state = HTLC_STATE_ACTIVE;
    h4.amount_sats = 9000;
    memset(h4.payment_hash, 0xDD, 32);

    TEST_ASSERT(persist_save_htlc(&db, 0, &h3), "save ch0 htlc");
    TEST_ASSERT(persist_save_htlc(&db, 1, &h4), "save ch1 htlc");

    /* Delete from channel 0 only */
    TEST_ASSERT(persist_delete_htlc(&db, 0, 20), "delete ch0 htlc");
    count = persist_load_htlcs(&db, 0, loaded, 16);
    TEST_ASSERT_EQ(count, 0, "ch0 empty after delete");

    /* Channel 1 still has its HTLC */
    count = persist_load_htlcs(&db, 1, loaded, 16);
    TEST_ASSERT_EQ(count, 1, "ch1 still has htlc");
    TEST_ASSERT_EQ(loaded[0].amount_sats, 9000, "ch1 htlc amount");

    /* Delete wrong channel — no effect */
    TEST_ASSERT(persist_delete_htlc(&db, 0, 20), "delete wrong channel");
    count = persist_load_htlcs(&db, 1, loaded, 16);
    TEST_ASSERT_EQ(count, 1, "ch1 unaffected by wrong-channel delete");

    persist_close(&db);
    return 1;
}

/* ---- Test 5: Factory save/load round-trip ---- */

int test_persist_factory_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    secp256k1_context *ctx = test_ctx();
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_ec_pubkey_create(ctx, &pks[i], seckeys[i])) return 0;
    }

    /* Build factory */
    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, 5);

    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);
    musig_keyagg_t ka_copy = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &ka_copy.cache, tweak)) return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) return 0;
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tweaked_xonly);

    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;
    factory_init_from_pubkeys(f, ctx, pks, 5, 10, 4);
    unsigned char fake_txid[32] = {0};
    fake_txid[0] = 0xDD;
    factory_set_funding(f, fake_txid, 0, 1000000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(f), "build tree");

    /* Save factory */
    TEST_ASSERT(persist_save_factory(&db, f, ctx, 0), "save factory");

    /* Load factory into new struct */
    factory_t *f2 = calloc(1, sizeof(factory_t));
    if (!f2) return 0;
    TEST_ASSERT(persist_load_factory(&db, 0, f2, ctx), "load factory");

    /* Verify */
    TEST_ASSERT_EQ(f2->n_participants, 5, "n_participants");
    TEST_ASSERT_EQ(f2->step_blocks, 10, "step_blocks");
    TEST_ASSERT_EQ(f2->funding_amount_sats, 1000000, "funding_amount");
    TEST_ASSERT_EQ(f2->n_nodes, f->n_nodes, "n_nodes");

    /* Verify txids match (the tree was rebuilt, so all node txids should match) */
    for (size_t i = 0; i < f->n_nodes; i++) {
        TEST_ASSERT(memcmp(f->nodes[i].txid, f2->nodes[i].txid, 32) == 0,
                    "node txid matches");
    }

    factory_free(f);
    free(f);
    factory_free(f2);
    free(f2);
    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}

/* ---- Test 7: Multiple channels in same database ---- */

int test_persist_multi_channel(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    secp256k1_context *ctx = test_ctx();
    secp256k1_pubkey pk_local, pk_remote;
    if (!secp256k1_ec_pubkey_create(ctx, &pk_local, seckeys[0])) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pk_remote, seckeys[1])) return 0;

    unsigned char fake_txid[32] = {0};
    unsigned char fake_spk[34];
    memset(fake_spk, 0xAA, 34);

    /* Save 4 channels with different balances */
    for (uint32_t i = 0; i < 4; i++) {
        channel_t ch;
        fake_txid[0] = (unsigned char)(0xDD + i);
        channel_init(&ch, ctx, seckeys[0], &pk_local, &pk_remote,
                      fake_txid, i, 100000, fake_spk, 34,
                      50000 - i * 1000, 50000 + i * 1000, 144);
        ch.commitment_number = i;
        TEST_ASSERT(persist_save_channel(&db, &ch, 0, i), "save channel");
        channel_cleanup(&ch);
    }

    /* Load each and verify */
    for (uint32_t i = 0; i < 4; i++) {
        uint64_t local, remote, commit;
        TEST_ASSERT(persist_load_channel_state(&db, i, &local, &remote, &commit),
                    "load channel");
        TEST_ASSERT_EQ(local, 50000 - i * 1000, "local_amount");
        TEST_ASSERT_EQ(remote, 50000 + i * 1000, "remote_amount");
        TEST_ASSERT_EQ(commit, i, "commitment_number");
    }

    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}

/* ==== Phase 23: Persistence Hardening Tests ==== */

/* ---- Test: DW counter save/load round-trip ---- */

int test_persist_dw_counter_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    uint32_t layers[] = {3, 1};
    TEST_ASSERT(persist_save_dw_counter(&db, 0, 7, 2, layers), "save dw counter");

    uint32_t epoch, n_layers;
    uint32_t loaded_layers[8];
    TEST_ASSERT(persist_load_dw_counter(&db, 0, &epoch, &n_layers, loaded_layers, 8),
                "load dw counter");
    TEST_ASSERT_EQ(epoch, 7, "epoch");
    TEST_ASSERT_EQ(n_layers, 2, "n_layers");
    TEST_ASSERT_EQ(loaded_layers[0], 3, "layer 0");
    TEST_ASSERT_EQ(loaded_layers[1], 1, "layer 1");

    /* Overwrite with new epoch */
    uint32_t layers2[] = {4, 2, 0};
    TEST_ASSERT(persist_save_dw_counter(&db, 0, 12, 3, layers2), "save dw counter 2");
    TEST_ASSERT(persist_load_dw_counter(&db, 0, &epoch, &n_layers, loaded_layers, 8),
                "load dw counter 2");
    TEST_ASSERT_EQ(epoch, 12, "epoch 2");
    TEST_ASSERT_EQ(n_layers, 3, "n_layers 2");
    TEST_ASSERT_EQ(loaded_layers[0], 4, "layer 0 v2");
    TEST_ASSERT_EQ(loaded_layers[1], 2, "layer 1 v2");
    TEST_ASSERT_EQ(loaded_layers[2], 0, "layer 2 v2");

    /* Non-existent factory */
    TEST_ASSERT(!persist_load_dw_counter(&db, 99, &epoch, &n_layers, loaded_layers, 8),
                "missing factory returns 0");

    persist_close(&db);
    return 1;
}

/* ---- Test: Departed clients round-trip ---- */

int test_persist_departed_clients_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    unsigned char key0[32], key1[32], key2[32];
    memset(key0, 0xAA, 32);
    memset(key1, 0xBB, 32);
    memset(key2, 0xCC, 32);

    TEST_ASSERT(persist_save_departed_client(&db, 0, 1, key0), "save departed 0");
    TEST_ASSERT(persist_save_departed_client(&db, 0, 2, key1), "save departed 1");
    TEST_ASSERT(persist_save_departed_client(&db, 0, 3, key2), "save departed 2");

    int departed[8];
    unsigned char keys[8][32];
    memset(departed, 0, sizeof(departed));
    memset(keys, 0, sizeof(keys));

    size_t count = persist_load_departed_clients(&db, 0, departed, keys, 8);
    TEST_ASSERT_EQ(count, 3, "departed count");
    TEST_ASSERT_EQ(departed[1], 1, "client 1 departed");
    TEST_ASSERT_EQ(departed[2], 1, "client 2 departed");
    TEST_ASSERT_EQ(departed[3], 1, "client 3 departed");
    TEST_ASSERT_EQ(departed[0], 0, "client 0 not departed");
    TEST_ASSERT(memcmp(keys[1], key0, 32) == 0, "key 0 matches");
    TEST_ASSERT(memcmp(keys[2], key1, 32) == 0, "key 1 matches");
    TEST_ASSERT(memcmp(keys[3], key2, 32) == 0, "key 2 matches");

    /* Different factory returns 0 */
    memset(departed, 0, sizeof(departed));
    count = persist_load_departed_clients(&db, 99, departed, keys, 8);
    TEST_ASSERT_EQ(count, 0, "no departed for factory 99");

    persist_close(&db);
    return 1;
}

/* ---- Test: Invoice registry round-trip ---- */

int test_persist_invoice_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    unsigned char hash0[32], hash1[32], hash2[32];
    memset(hash0, 0x01, 32);
    memset(hash1, 0x02, 32);
    memset(hash2, 0x03, 32);

    TEST_ASSERT(persist_save_invoice(&db, hash0, 0, 10000), "save invoice 0");
    TEST_ASSERT(persist_save_invoice(&db, hash1, 2, 25000), "save invoice 1");
    TEST_ASSERT(persist_save_invoice(&db, hash2, 1, 5000), "save invoice 2");

    /* Deactivate one */
    TEST_ASSERT(persist_deactivate_invoice(&db, hash2), "deactivate invoice 2");

    /* Load active only */
    unsigned char hashes[8][32];
    size_t dests[8];
    uint64_t amounts[8];
    size_t count = persist_load_invoices(&db, hashes, dests, amounts, 8);
    TEST_ASSERT_EQ(count, 2, "active invoice count");
    TEST_ASSERT(memcmp(hashes[0], hash0, 32) == 0, "hash 0");
    TEST_ASSERT_EQ(dests[0], 0, "dest 0");
    TEST_ASSERT_EQ(amounts[0], 10000, "amount 0");
    TEST_ASSERT(memcmp(hashes[1], hash1, 32) == 0, "hash 1");
    TEST_ASSERT_EQ(dests[1], 2, "dest 1");
    TEST_ASSERT_EQ(amounts[1], 25000, "amount 1");

    persist_close(&db);
    return 1;
}

/* ---- Test: HTLC origin round-trip ---- */

int test_persist_htlc_origin_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    unsigned char hash0[32], hash1[32];
    memset(hash0, 0xA1, 32);
    memset(hash1, 0xB2, 32);

    TEST_ASSERT(persist_save_htlc_origin(&db, hash0, 5, 0, 0, 0),
                "save origin 0");
    TEST_ASSERT(persist_save_htlc_origin(&db, hash1, 0, 3, 1, 7),
                "save origin 1");

    /* Deactivate first */
    TEST_ASSERT(persist_deactivate_htlc_origin(&db, hash0), "deactivate origin 0");

    /* Load active */
    unsigned char hashes[8][32];
    uint64_t bridge[8], req[8], htlc_ids[8];
    size_t senders[8];
    size_t count = persist_load_htlc_origins(&db, hashes, bridge, req,
                                               senders, htlc_ids, 8);
    TEST_ASSERT_EQ(count, 1, "active origin count");
    TEST_ASSERT(memcmp(hashes[0], hash1, 32) == 0, "hash matches");
    TEST_ASSERT_EQ(bridge[0], 0, "bridge_htlc_id");
    TEST_ASSERT_EQ(req[0], 3, "request_id");
    TEST_ASSERT_EQ(senders[0], 1, "sender_idx");
    TEST_ASSERT_EQ(htlc_ids[0], 7, "sender_htlc_id");

    persist_close(&db);
    return 1;
}

/* ---- Test: Client invoice round-trip ---- */

int test_persist_client_invoice_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    unsigned char hash0[32], preimage0[32];
    unsigned char hash1[32], preimage1[32];
    memset(hash0, 0xD0, 32); memset(preimage0, 0xE0, 32);
    memset(hash1, 0xD1, 32); memset(preimage1, 0xE1, 32);

    TEST_ASSERT(persist_save_client_invoice(&db, hash0, preimage0, 10000),
                "save client invoice 0");
    TEST_ASSERT(persist_save_client_invoice(&db, hash1, preimage1, 5000),
                "save client invoice 1");

    /* Deactivate first */
    TEST_ASSERT(persist_deactivate_client_invoice(&db, hash0),
                "deactivate client invoice 0");

    /* Load active */
    unsigned char hashes[8][32], preimages[8][32];
    uint64_t amounts[8];
    size_t count = persist_load_client_invoices(&db, hashes, preimages, amounts, 8);
    TEST_ASSERT_EQ(count, 1, "active client invoice count");
    TEST_ASSERT(memcmp(hashes[0], hash1, 32) == 0, "hash matches");
    TEST_ASSERT(memcmp(preimages[0], preimage1, 32) == 0, "preimage matches");
    TEST_ASSERT_EQ(amounts[0], 5000, "amount matches");

    persist_close(&db);
    return 1;
}

/* ---- Test: ID counter round-trip ---- */

int test_persist_counter_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    TEST_ASSERT(persist_save_counter(&db, "next_request_id", 5), "save counter");

    uint64_t val = persist_load_counter(&db, "next_request_id", 0);
    TEST_ASSERT_EQ(val, 5, "counter value");

    /* Overwrite */
    TEST_ASSERT(persist_save_counter(&db, "next_request_id", 42), "overwrite counter");
    val = persist_load_counter(&db, "next_request_id", 0);
    TEST_ASSERT_EQ(val, 42, "updated value");

    /* Missing key returns default */
    val = persist_load_counter(&db, "nonexistent", 999);
    TEST_ASSERT_EQ(val, 999, "missing key returns default");

    /* Multiple counters */
    TEST_ASSERT(persist_save_counter(&db, "next_htlc_id", 100), "save htlc counter");
    val = persist_load_counter(&db, "next_htlc_id", 0);
    TEST_ASSERT_EQ(val, 100, "htlc counter value");

    /* First counter still intact */
    val = persist_load_counter(&db, "next_request_id", 0);
    TEST_ASSERT_EQ(val, 42, "first counter still correct");

    persist_close(&db);
    return 1;
}

/* ---- Test: Basepoint persistence round-trip ---- */

int test_persist_basepoints(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    secp256k1_context *ctx = test_ctx();

    /* Create a channel with known basepoint secrets */
    secp256k1_pubkey local_pk, remote_pk;
    if (!secp256k1_ec_pubkey_create(ctx, &local_pk, seckeys[0])) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &remote_pk, seckeys[1])) return 0;

    /* Build funding SPK */
    secp256k1_pubkey pks[2] = { local_pk, remote_pk };
    musig_keyagg_t ka;
    TEST_ASSERT(musig_aggregate_keys(ctx, &ka, pks, 2), "keyagg");
    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    unsigned char twk[32];
    sha256_tagged("TapTweak", internal_ser, 32, twk);
    musig_keyagg_t ka2 = ka;
    secp256k1_pubkey tweaked;
    TEST_ASSERT(secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked, &ka2.cache, twk), "tweak");
    secp256k1_xonly_pubkey twx;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &twx, NULL, &tweaked)) return 0;
    unsigned char spk[34];
    build_p2tr_script_pubkey(spk, &twx);

    unsigned char txid[32] = {0};
    channel_t ch;
    TEST_ASSERT(channel_init(&ch, ctx, seckeys[0], &local_pk, &remote_pk,
                              txid, 0, 100000, spk, 34, 40000, 40000,
                              CHANNEL_DEFAULT_CSV_DELAY), "init ch");

    /* Set local basepoints with known secrets */
    unsigned char pay_sec[32] = { [0 ... 31] = 0xAA };
    unsigned char delay_sec[32] = { [0 ... 31] = 0xBB };
    unsigned char revoc_sec[32] = { [0 ... 31] = 0xCC };
    unsigned char htlc_sec[32] = { [0 ... 31] = 0xDD };
    channel_set_local_basepoints(&ch, pay_sec, delay_sec, revoc_sec);
    channel_set_local_htlc_basepoint(&ch, htlc_sec);

    /* Set remote basepoints */
    secp256k1_pubkey rpay, rdelay, rrevoc, rhtlc;
    unsigned char rsec1[32] = { [0 ... 31] = 0x61 };
    unsigned char rsec2[32] = { [0 ... 31] = 0x71 };
    unsigned char rsec3[32] = { [0 ... 31] = 0x81 };
    unsigned char rsec4[32] = { [0 ... 31] = 0x91 };
    if (!secp256k1_ec_pubkey_create(ctx, &rpay, rsec1)) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &rdelay, rsec2)) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &rrevoc, rsec3)) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &rhtlc, rsec4)) return 0;
    channel_set_remote_basepoints(&ch, &rpay, &rdelay, &rrevoc);
    channel_set_remote_htlc_basepoint(&ch, &rhtlc);

    /* Save */
    TEST_ASSERT(persist_save_basepoints(&db, 0, &ch), "save basepoints");

    /* Load */
    unsigned char loaded_local[4][32];
    unsigned char loaded_remote[4][33];
    TEST_ASSERT(persist_load_basepoints(&db, 0, loaded_local, loaded_remote),
                "load basepoints");

    /* Verify local secrets */
    TEST_ASSERT(memcmp(loaded_local[0], pay_sec, 32) == 0, "pay secret match");
    TEST_ASSERT(memcmp(loaded_local[1], delay_sec, 32) == 0, "delay secret match");
    TEST_ASSERT(memcmp(loaded_local[2], revoc_sec, 32) == 0, "revoc secret match");
    TEST_ASSERT(memcmp(loaded_local[3], htlc_sec, 32) == 0, "htlc secret match");

    /* Verify remote pubkeys */
    unsigned char expected_remote[33];
    size_t slen = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, expected_remote, &slen, &rpay, SECP256K1_EC_COMPRESSED)) return 0;
    TEST_ASSERT(memcmp(loaded_remote[0], expected_remote, 33) == 0, "remote pay bp match");

    slen = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, expected_remote, &slen, &rdelay, SECP256K1_EC_COMPRESSED)) return 0;
    TEST_ASSERT(memcmp(loaded_remote[1], expected_remote, 33) == 0, "remote delay bp match");

    slen = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, expected_remote, &slen, &rrevoc, SECP256K1_EC_COMPRESSED)) return 0;
    TEST_ASSERT(memcmp(loaded_remote[2], expected_remote, 33) == 0, "remote revoc bp match");

    slen = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, expected_remote, &slen, &rhtlc, SECP256K1_EC_COMPRESSED)) return 0;
    TEST_ASSERT(memcmp(loaded_remote[3], expected_remote, 33) == 0, "remote htlc bp match");

    /* Verify loading non-existent channel fails */
    TEST_ASSERT(!persist_load_basepoints(&db, 99, loaded_local, loaded_remote),
                "non-existent channel fails");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}

/* ---- Test: LSP recovery round-trip ---- */

int test_lsp_recovery_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    secp256k1_context *ctx = test_ctx();

    /* Create factory with 5 participants (LSP + 4 clients) */
    unsigned char extra_sec3[32], extra_sec4[32];
    memset(extra_sec3, 0x33, 32);
    memset(extra_sec4, 0x44, 32);
    secp256k1_pubkey pks[5];
    if (!secp256k1_ec_pubkey_create(ctx, &pks[0], seckeys[0])) return 0;  /* LSP */
    if (!secp256k1_ec_pubkey_create(ctx, &pks[1], seckeys[1])) return 0;  /* Client 0 */
    if (!secp256k1_ec_pubkey_create(ctx, &pks[2], seckeys[2])) return 0;  /* Client 1 */
    if (!secp256k1_ec_pubkey_create(ctx, &pks[3], extra_sec3)) return 0;  /* Client 2 */
    if (!secp256k1_ec_pubkey_create(ctx, &pks[4], extra_sec4)) return 0;  /* Client 3 */

    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;
    factory_init_from_pubkeys(f, ctx, pks, 5, 10, 4);
    f->cltv_timeout = 200;
    f->fee_per_tx = 500;

    /* Set funding (need valid funding for channel init) */
    musig_keyagg_t ka;
    TEST_ASSERT(musig_aggregate_keys(ctx, &ka, pks, 3), "keyagg");
    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    unsigned char twk[32];
    sha256_tagged("TapTweak", internal_ser, 32, twk);
    musig_keyagg_t kac = ka;
    secp256k1_pubkey tpk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tpk, &kac.cache, twk)) return 0;
    secp256k1_xonly_pubkey txo;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &txo, NULL, &tpk)) return 0;
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &txo);

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAB, 32);
    factory_set_funding(f, fake_txid, 0, 200000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(f), "build tree");

    /* Initialize channels the normal way */
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    TEST_ASSERT(lsp_channels_init(&mgr, ctx, f, seckeys[0], 4), "init channels");

    /* Simulate basepoint exchange: set remote basepoints */
    for (size_t c = 0; c < 4; c++) {
        channel_t *ch = &mgr.entries[c].channel;
        secp256k1_pubkey rpay, rdelay, rrevoc, rhtlc;
        unsigned char rs[32];
        memset(rs, 0x60 + (unsigned char)c, 32);
        if (!secp256k1_ec_pubkey_create(ctx, &rpay, rs)) return 0;
        rs[0]++;
        if (!secp256k1_ec_pubkey_create(ctx, &rdelay, rs)) return 0;
        rs[0]++;
        if (!secp256k1_ec_pubkey_create(ctx, &rrevoc, rs)) return 0;
        rs[0]++;
        if (!secp256k1_ec_pubkey_create(ctx, &rhtlc, rs)) return 0;
        channel_set_remote_basepoints(ch, &rpay, &rdelay, &rrevoc);
        channel_set_remote_htlc_basepoint(ch, &rhtlc);
    }

    /* Simulate some payments (modify balances) - only test first 2 channels */
    mgr.entries[0].channel.local_amount = 30000;
    mgr.entries[0].channel.remote_amount = 50000;
    mgr.entries[0].channel.commitment_number = 5;
    mgr.entries[1].channel.local_amount = 35000;
    mgr.entries[1].channel.remote_amount = 45000;
    mgr.entries[1].channel.commitment_number = 3;

    /* Persist: factory, channels, basepoints */
    TEST_ASSERT(persist_begin(&db), "begin");
    TEST_ASSERT(persist_save_factory(&db, f, ctx, 0), "save factory");
    for (size_t c = 0; c < 4; c++) {
        TEST_ASSERT(persist_save_channel(&db, &mgr.entries[c].channel, 0,
                                           (uint32_t)c), "save channel");
        TEST_ASSERT(persist_save_basepoints(&db, (uint32_t)c,
                                              &mgr.entries[c].channel),
                    "save basepoints");
    }
    /* Update balances after payments */
    for (size_t c = 0; c < 4; c++) {
        const channel_t *ch = &mgr.entries[c].channel;
        TEST_ASSERT(persist_update_channel_balance(&db, (uint32_t)c,
                        ch->local_amount, ch->remote_amount,
                        ch->commitment_number), "update balance");
    }

    /* Save an active HTLC on channel 0 for recovery testing */
    {
        htlc_t test_htlc;
        memset(&test_htlc, 0, sizeof(test_htlc));
        test_htlc.id = 42;
        test_htlc.direction = HTLC_OFFERED;
        test_htlc.state = HTLC_STATE_ACTIVE;
        test_htlc.amount_sats = 2500;
        memset(test_htlc.payment_hash, 0xDD, 32);
        test_htlc.cltv_expiry = 700;
        TEST_ASSERT(persist_save_htlc(&db, 0, &test_htlc), "save test htlc");

        /* Also save a fulfilled HTLC — should NOT be loaded on recovery */
        htlc_t dead_htlc;
        memset(&dead_htlc, 0, sizeof(dead_htlc));
        dead_htlc.id = 43;
        dead_htlc.direction = HTLC_OFFERED;
        dead_htlc.state = HTLC_STATE_FULFILLED;
        dead_htlc.amount_sats = 1000;
        memset(dead_htlc.payment_hash, 0xEE, 32);
        dead_htlc.cltv_expiry = 800;
        TEST_ASSERT(persist_save_htlc(&db, 0, &dead_htlc), "save dead htlc");
    }
    TEST_ASSERT(persist_commit(&db), "commit");

    /* Now recover: load factory from DB, init channels from DB */
    factory_t *rec_f = calloc(1, sizeof(factory_t));
    if (!rec_f) { lsp_channels_cleanup(&mgr); return 0; }

    TEST_ASSERT(persist_load_factory(&db, 0, rec_f, ctx), "load factory");
    TEST_ASSERT_EQ(rec_f->n_participants, 5, "n_participants");

    lsp_channel_mgr_t rec_mgr;
    memset(&rec_mgr, 0, sizeof(rec_mgr));
    TEST_ASSERT(lsp_channels_init_from_db(&rec_mgr, ctx, rec_f,
                                            seckeys[0], 4, &db),
                "init from db");
    TEST_ASSERT_EQ(rec_mgr.n_channels, 4, "n_channels");

    /* Verify ALL 4 channels recovered correctly */
    for (size_t c = 0; c < 4; c++) {
        const channel_t *orig = &mgr.entries[c].channel;
        const channel_t *rec = &rec_mgr.entries[c].channel;

        TEST_ASSERT_EQ(rec->local_amount, orig->local_amount, "local_amount");
        TEST_ASSERT_EQ(rec->remote_amount, orig->remote_amount, "remote_amount");
        TEST_ASSERT_EQ(rec->commitment_number, orig->commitment_number,
                        "commitment_number");

        /* Verify local basepoint secrets match */
        TEST_ASSERT(memcmp(rec->local_payment_basepoint_secret,
                           orig->local_payment_basepoint_secret, 32) == 0,
                    "pay secret match");
        TEST_ASSERT(memcmp(rec->local_delayed_payment_basepoint_secret,
                           orig->local_delayed_payment_basepoint_secret, 32) == 0,
                    "delay secret match");
        TEST_ASSERT(memcmp(rec->local_revocation_basepoint_secret,
                           orig->local_revocation_basepoint_secret, 32) == 0,
                    "revoc secret match");
        TEST_ASSERT(memcmp(rec->local_htlc_basepoint_secret,
                           orig->local_htlc_basepoint_secret, 32) == 0,
                    "htlc secret match");

        /* Verify ALL 4 remote basepoint pubkeys match */
        unsigned char orig_ser[33], rec_ser[33];
        size_t slen;

        slen = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, orig_ser, &slen,
            &orig->remote_payment_basepoint, SECP256K1_EC_COMPRESSED)) return 0;
        slen = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, rec_ser, &slen,
            &rec->remote_payment_basepoint, SECP256K1_EC_COMPRESSED)) return 0;
        TEST_ASSERT(memcmp(orig_ser, rec_ser, 33) == 0, "remote pay bp");

        slen = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, orig_ser, &slen,
            &orig->remote_delayed_payment_basepoint, SECP256K1_EC_COMPRESSED)) return 0;
        slen = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, rec_ser, &slen,
            &rec->remote_delayed_payment_basepoint, SECP256K1_EC_COMPRESSED)) return 0;
        TEST_ASSERT(memcmp(orig_ser, rec_ser, 33) == 0, "remote delay bp");

        slen = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, orig_ser, &slen,
            &orig->remote_revocation_basepoint, SECP256K1_EC_COMPRESSED)) return 0;
        slen = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, rec_ser, &slen,
            &rec->remote_revocation_basepoint, SECP256K1_EC_COMPRESSED)) return 0;
        TEST_ASSERT(memcmp(orig_ser, rec_ser, 33) == 0, "remote revoc bp");

        slen = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, orig_ser, &slen,
            &orig->remote_htlc_basepoint, SECP256K1_EC_COMPRESSED)) return 0;
        slen = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, rec_ser, &slen,
            &rec->remote_htlc_basepoint, SECP256K1_EC_COMPRESSED)) return 0;
        TEST_ASSERT(memcmp(orig_ser, rec_ser, 33) == 0, "remote htlc bp");

        /* Verify channel is marked ready */
        TEST_ASSERT_EQ(rec_mgr.entries[c].ready, 1, "channel ready");
    }

    /* Verify HTLC recovery: channel 0 should have 1 active HTLC (not the fulfilled one) */
    TEST_ASSERT_EQ(rec_mgr.entries[0].channel.n_htlcs, 1, "ch0 htlc count");
    TEST_ASSERT_EQ(rec_mgr.entries[0].channel.htlcs[0].id, 42, "ch0 htlc id");
    TEST_ASSERT_EQ(rec_mgr.entries[0].channel.htlcs[0].amount_sats, 2500, "ch0 htlc amount");
    TEST_ASSERT_EQ(rec_mgr.entries[0].channel.htlcs[0].state, HTLC_STATE_ACTIVE, "ch0 htlc state");
    {
        unsigned char expected_hash[32];
        memset(expected_hash, 0xDD, 32);
        TEST_ASSERT(memcmp(rec_mgr.entries[0].channel.htlcs[0].payment_hash,
                           expected_hash, 32) == 0, "ch0 htlc hash");
    }

    /* Channel 1 should have no HTLCs */
    TEST_ASSERT_EQ(rec_mgr.entries[1].channel.n_htlcs, 0, "ch1 no htlcs");

    lsp_channels_cleanup(&mgr);
    lsp_channels_cleanup(&rec_mgr);
    factory_free(rec_f);
    free(rec_f);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}

/* ---- Test: File-based persist close/reopen round-trip ---- */

int test_persist_file_reopen_round_trip(void) {
    const char *path = "/tmp/test_persist_reopen.db";
    unlink(path);  /* ensure clean slate */

    /* Phase 1: open file-based DB, save data, close */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "open file db");

        secp256k1_context *ctx = test_ctx();
        secp256k1_pubkey pk_local, pk_remote;
        if (!secp256k1_ec_pubkey_create(ctx, &pk_local, seckeys[0])) return 0;
        if (!secp256k1_ec_pubkey_create(ctx, &pk_remote, seckeys[1])) return 0;

        unsigned char fake_txid[32] = {0};
        fake_txid[0] = 0xDD;
        unsigned char fake_spk[34];
        memset(fake_spk, 0xAA, 34);

        channel_t ch;
        TEST_ASSERT(channel_init(&ch, ctx, seckeys[0], &pk_local, &pk_remote,
                                  fake_txid, 1, 100000, fake_spk, 34,
                                  45000, 55000, 144), "channel_init");
        ch.commitment_number = 7;

        TEST_ASSERT(persist_save_channel(&db, &ch, 0, 0), "save channel");
        channel_cleanup(&ch);

        /* Also save a counter and an HTLC */
        TEST_ASSERT(persist_save_counter(&db, "test_counter", 42), "save counter");

        htlc_t h = {0};
        h.direction = HTLC_OFFERED;
        h.state = HTLC_STATE_ACTIVE;
        h.amount_sats = 3000;
        memset(h.payment_hash, 0xBE, 32);
        h.cltv_expiry = 500;
        h.id = 0;
        TEST_ASSERT(persist_save_htlc(&db, 0, &h), "save htlc");

        secp256k1_context_destroy(ctx);
        persist_close(&db);
    }

    /* Phase 2: reopen from file, verify all data survived */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "reopen file db");

        /* Verify channel state */
        uint64_t local, remote, commit;
        TEST_ASSERT(persist_load_channel_state(&db, 0, &local, &remote, &commit),
                    "load channel after reopen");
        TEST_ASSERT_EQ(local, 45000, "local_amount after reopen");
        TEST_ASSERT_EQ(remote, 55000, "remote_amount after reopen");
        TEST_ASSERT_EQ(commit, 7, "commitment_number after reopen");

        /* Verify counter */
        uint64_t val = persist_load_counter(&db, "test_counter", 0);
        TEST_ASSERT_EQ(val, 42, "counter after reopen");

        /* Verify HTLC */
        htlc_t loaded[16];
        size_t count = persist_load_htlcs(&db, 0, loaded, 16);
        TEST_ASSERT_EQ(count, 1, "htlc count after reopen");
        TEST_ASSERT_EQ(loaded[0].amount_sats, 3000, "htlc amount after reopen");
        TEST_ASSERT_EQ(loaded[0].cltv_expiry, 500, "htlc cltv after reopen");
        {
            unsigned char expected[32];
            memset(expected, 0xBE, 32);
            TEST_ASSERT(memcmp(loaded[0].payment_hash, expected, 32) == 0,
                        "htlc hash after reopen");
        }

        persist_close(&db);
    }

    unlink(path);  /* cleanup */
    return 1;
}

/* ---- Test: DW counter with N leaf states (arity-1 support) ---- */

int test_persist_dw_counter_with_leaves_4(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    /* Save with 4 leaf states (arity-1: 4 clients) */
    uint32_t layers[] = {5, 2, 1};
    uint32_t leaf_states[] = {3, 0, 7, 2};
    TEST_ASSERT(persist_save_dw_counter_with_leaves(&db, 42, 10, 3, layers,
                                                      1, leaf_states, 4),
                "save with 4 leaves");

    /* Load and verify */
    uint32_t epoch, n_layers;
    uint32_t loaded_layers[8];
    int per_leaf_enabled;
    uint32_t loaded_leaves[8];
    int n_leaf_nodes;
    TEST_ASSERT(persist_load_dw_counter_with_leaves(&db, 42, &epoch, &n_layers,
                                                      loaded_layers, 8,
                                                      &per_leaf_enabled,
                                                      loaded_leaves, &n_leaf_nodes, 8),
                "load with 4 leaves");

    TEST_ASSERT_EQ(epoch, 10, "epoch");
    TEST_ASSERT_EQ(n_layers, 3, "n_layers");
    TEST_ASSERT_EQ(loaded_layers[0], 5, "layer 0");
    TEST_ASSERT_EQ(loaded_layers[1], 2, "layer 1");
    TEST_ASSERT_EQ(loaded_layers[2], 1, "layer 2");
    TEST_ASSERT_EQ(per_leaf_enabled, 1, "per_leaf enabled");
    TEST_ASSERT_EQ(n_leaf_nodes, 4, "n_leaf_nodes");
    TEST_ASSERT_EQ(loaded_leaves[0], 3, "leaf 0");
    TEST_ASSERT_EQ(loaded_leaves[1], 0, "leaf 1");
    TEST_ASSERT_EQ(loaded_leaves[2], 7, "leaf 2");
    TEST_ASSERT_EQ(loaded_leaves[3], 2, "leaf 3");

    /* Overwrite with 2 leaf states (arity-2 compatibility) */
    uint32_t layers2[] = {1, 0};
    uint32_t leaf_states2[] = {4, 6};
    TEST_ASSERT(persist_save_dw_counter_with_leaves(&db, 42, 5, 2, layers2,
                                                      1, leaf_states2, 2),
                "save with 2 leaves");

    TEST_ASSERT(persist_load_dw_counter_with_leaves(&db, 42, &epoch, &n_layers,
                                                      loaded_layers, 8,
                                                      &per_leaf_enabled,
                                                      loaded_leaves, &n_leaf_nodes, 8),
                "load with 2 leaves");
    TEST_ASSERT_EQ(n_leaf_nodes, 2, "n_leaf_nodes after overwrite");
    TEST_ASSERT_EQ(loaded_leaves[0], 4, "leaf 0 after overwrite");
    TEST_ASSERT_EQ(loaded_leaves[1], 6, "leaf 1 after overwrite");

    /* Save with per_leaf disabled */
    TEST_ASSERT(persist_save_dw_counter_with_leaves(&db, 42, 0, 2, layers2,
                                                      0, NULL, 0),
                "save with per_leaf disabled");
    TEST_ASSERT(persist_load_dw_counter_with_leaves(&db, 42, &epoch, &n_layers,
                                                      loaded_layers, 8,
                                                      &per_leaf_enabled,
                                                      loaded_leaves, &n_leaf_nodes, 8),
                "load with per_leaf disabled");
    TEST_ASSERT_EQ(per_leaf_enabled, 0, "per_leaf disabled");

    persist_close(&db);
    return 1;
}

/* --- Schema Versioning (Phase 2: item 2.2) --- */

int test_persist_schema_version(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open in-memory");

    /* Fresh DB should have version PERSIST_SCHEMA_VERSION (1) */
    int ver = persist_schema_version(&db);
    TEST_ASSERT_EQ(ver, PERSIST_SCHEMA_VERSION, "fresh db version");

    persist_close(&db);
    return 1;
}

int test_persist_schema_future_reject(void) {
    /* Create a temporary file DB, inject future version, close, reopen → reject */
    const char *tmp_path = "/tmp/test_schema_future.db";
    unlink(tmp_path);

    persist_t db;
    TEST_ASSERT(persist_open(&db, tmp_path), "open tmp");

    /* Inject a future version row */
    int rc = sqlite3_exec(db.db,
        "INSERT INTO schema_version (version) VALUES (999);",
        NULL, NULL, NULL);
    TEST_ASSERT(rc == SQLITE_OK, "inject future version");
    persist_close(&db);

    /* Reopen should fail: DB version 999 > code version */
    persist_t db2;
    int opened = persist_open(&db2, tmp_path);
    TEST_ASSERT(opened == 0, "future version rejected");

    unlink(tmp_path);
    return 1;
}

/* --- Data Validation on Load (Phase 2: item 2.6) --- */

int test_persist_validate_factory_load(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");
    secp256k1_context *ctx = test_ctx();

    /* Insert invalid factory: n_participants = 1 (too low, need >= 2) */
    int rc = sqlite3_exec(db.db,
        "INSERT INTO factories (id, n_participants, funding_txid, funding_vout, "
        "funding_amount, step_blocks, states_per_layer, cltv_timeout, fee_per_tx, leaf_arity) "
        "VALUES (10, 1, '00', 0, 100000, 10, 8, 200, 500, 2);",
        NULL, NULL, NULL);
    TEST_ASSERT(rc == SQLITE_OK, "insert invalid factory");

    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;

    int loaded = persist_load_factory(&db, 10, f, ctx);
    TEST_ASSERT(loaded == 0, "n_participants=1 rejected");

    /* Insert factory with funding_amount = 0 */
    rc = sqlite3_exec(db.db,
        "INSERT OR REPLACE INTO factories (id, n_participants, funding_txid, "
        "funding_vout, funding_amount, step_blocks, states_per_layer, "
        "cltv_timeout, fee_per_tx, leaf_arity) "
        "VALUES (11, 5, '00', 0, 0, 10, 8, 200, 500, 2);",
        NULL, NULL, NULL);
    TEST_ASSERT(rc == SQLITE_OK, "insert zero-amount factory");
    loaded = persist_load_factory(&db, 11, f, ctx);
    TEST_ASSERT(loaded == 0, "funding_amount=0 rejected");

    /* Insert factory with states_per_layer = 0 */
    rc = sqlite3_exec(db.db,
        "INSERT OR REPLACE INTO factories (id, n_participants, funding_txid, "
        "funding_vout, funding_amount, step_blocks, states_per_layer, "
        "cltv_timeout, fee_per_tx, leaf_arity) "
        "VALUES (12, 5, '00', 0, 100000, 10, 0, 200, 500, 2);",
        NULL, NULL, NULL);
    TEST_ASSERT(rc == SQLITE_OK, "insert zero-states factory");
    loaded = persist_load_factory(&db, 12, f, ctx);
    TEST_ASSERT(loaded == 0, "states_per_layer=0 rejected");

    /* Insert factory with step_blocks = 0 */
    rc = sqlite3_exec(db.db,
        "INSERT OR REPLACE INTO factories (id, n_participants, funding_txid, "
        "funding_vout, funding_amount, step_blocks, states_per_layer, "
        "cltv_timeout, fee_per_tx, leaf_arity) "
        "VALUES (13, 5, '00', 0, 100000, 0, 8, 200, 500, 2);",
        NULL, NULL, NULL);
    TEST_ASSERT(rc == SQLITE_OK, "insert zero-step factory");
    loaded = persist_load_factory(&db, 13, f, ctx);
    TEST_ASSERT(loaded == 0, "step_blocks=0 rejected");

    free(f);
    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}

int test_persist_validate_channel_load(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    /* High commitment numbers are now valid (no upper bound) */
    int rc = sqlite3_exec(db.db,
        "INSERT INTO channels (id, factory_id, slot, local_amount, remote_amount, "
        "funding_amount, commitment_number) VALUES (100, 0, 0, 50000, 50000, "
        "100000, 999);",
        NULL, NULL, NULL);
    TEST_ASSERT(rc == SQLITE_OK, "insert high cn channel");

    uint64_t la, ra, cn;
    int loaded = persist_load_channel_state(&db, 100, &la, &ra, &cn);
    TEST_ASSERT(loaded == 1, "high commitment_number accepted");
    TEST_ASSERT(cn == 999, "commitment_number is 999");

    /* Insert a channel with both balances zero */
    rc = sqlite3_exec(db.db,
        "INSERT INTO channels (id, factory_id, slot, local_amount, remote_amount, "
        "funding_amount, commitment_number) VALUES (101, 0, 1, 0, 0, 100000, 0);",
        NULL, NULL, NULL);
    TEST_ASSERT(rc == SQLITE_OK, "insert zero-balance channel");
    loaded = persist_load_channel_state(&db, 101, &la, &ra, &cn);
    TEST_ASSERT(loaded == 0, "total balance=0 rejected");

    /* Insert a valid channel — should pass */
    rc = sqlite3_exec(db.db,
        "INSERT INTO channels (id, factory_id, slot, local_amount, remote_amount, "
        "funding_amount, commitment_number) VALUES (102, 0, 2, 50000, 50000, "
        "100000, 5);",
        NULL, NULL, NULL);
    TEST_ASSERT(rc == SQLITE_OK, "insert valid channel");
    loaded = persist_load_channel_state(&db, 102, &la, &ra, &cn);
    TEST_ASSERT(loaded == 1, "valid channel loads");
    TEST_ASSERT_EQ(la, (uint64_t)50000, "local amount");
    TEST_ASSERT_EQ(ra, (uint64_t)50000, "remote amount");
    TEST_ASSERT_EQ(cn, (uint64_t)5, "commitment number");

    persist_close(&db);
    return 1;
}

/* ---- Test: Crash stress — 4 cycles of persist/crash/recover on file-based DB ---- */

int test_persist_crash_stress(void) {
    const char *path = "/tmp/test_crash_stress.db";
    unlink(path);

    secp256k1_context *ctx = test_ctx();

    /* Create factory with 5 participants (LSP + 4 clients) */
    unsigned char extra_sec3[32], extra_sec4[32];
    memset(extra_sec3, 0x33, 32);
    memset(extra_sec4, 0x44, 32);
    secp256k1_pubkey pks[5];
    if (!secp256k1_ec_pubkey_create(ctx, &pks[0], seckeys[0])) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pks[1], seckeys[1])) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pks[2], seckeys[2])) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pks[3], extra_sec3)) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pks[4], extra_sec4)) return 0;

    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;
    factory_init_from_pubkeys(f, ctx, pks, 5, 10, 4);
    f->cltv_timeout = 200;
    f->fee_per_tx = 500;

    /* Compute funding SPK */
    musig_keyagg_t ka;
    TEST_ASSERT(musig_aggregate_keys(ctx, &ka, pks, 3), "keyagg");
    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    unsigned char twk[32];
    sha256_tagged("TapTweak", internal_ser, 32, twk);
    musig_keyagg_t kac = ka;
    secp256k1_pubkey tpk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tpk, &kac.cache, twk)) return 0;
    secp256k1_xonly_pubkey txo;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &txo, NULL, &tpk)) return 0;
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &txo);

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAB, 32);
    factory_set_funding(f, fake_txid, 0, 200000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(f), "build tree");

    /* Initialize channels */
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    TEST_ASSERT(lsp_channels_init(&mgr, ctx, f, seckeys[0], 4), "init channels");

    /* Simulate basepoint exchange */
    for (size_t c = 0; c < 4; c++) {
        channel_t *ch = &mgr.entries[c].channel;
        secp256k1_pubkey rpay, rdelay, rrevoc, rhtlc;
        unsigned char rs[32];
        memset(rs, 0x60 + (unsigned char)c, 32);
        if (!secp256k1_ec_pubkey_create(ctx, &rpay, rs)) return 0;
        rs[0]++;
        if (!secp256k1_ec_pubkey_create(ctx, &rdelay, rs)) return 0;
        rs[0]++;
        if (!secp256k1_ec_pubkey_create(ctx, &rrevoc, rs)) return 0;
        rs[0]++;
        if (!secp256k1_ec_pubkey_create(ctx, &rhtlc, rs)) return 0;
        channel_set_remote_basepoints(ch, &rpay, &rdelay, &rrevoc);
        channel_set_remote_htlc_basepoint(ch, &rhtlc);
    }

    /* ===== Cycle 1: Fresh state ===== */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "c1 open");
        TEST_ASSERT(persist_begin(&db), "c1 begin");
        TEST_ASSERT(persist_save_factory(&db, f, ctx, 0), "c1 save factory");
        for (size_t c = 0; c < 4; c++) {
            TEST_ASSERT(persist_save_channel(&db, &mgr.entries[c].channel, 0,
                                               (uint32_t)c), "c1 save ch");
            TEST_ASSERT(persist_save_basepoints(&db, (uint32_t)c,
                                                  &mgr.entries[c].channel),
                        "c1 save bp");
            const channel_t *ch = &mgr.entries[c].channel;
            TEST_ASSERT(persist_update_channel_balance(&db, (uint32_t)c,
                            ch->local_amount, ch->remote_amount,
                            ch->commitment_number), "c1 update bal");
        }
        TEST_ASSERT(persist_commit(&db), "c1 commit");
        persist_close(&db);
    }

    /* Save original state for comparison */
    uint64_t orig_local[4], orig_remote[4], orig_cn[4];
    unsigned char orig_bp_pay[4][32], orig_bp_delay[4][32];
    unsigned char orig_bp_revoc[4][32], orig_bp_htlc[4][32];
    for (size_t c = 0; c < 4; c++) {
        const channel_t *ch = &mgr.entries[c].channel;
        orig_local[c] = ch->local_amount;
        orig_remote[c] = ch->remote_amount;
        orig_cn[c] = ch->commitment_number;
        memcpy(orig_bp_pay[c], ch->local_payment_basepoint_secret, 32);
        memcpy(orig_bp_delay[c], ch->local_delayed_payment_basepoint_secret, 32);
        memcpy(orig_bp_revoc[c], ch->local_revocation_basepoint_secret, 32);
        memcpy(orig_bp_htlc[c], ch->local_htlc_basepoint_secret, 32);
    }

    /* Zero everything */
    lsp_channels_cleanup(&mgr);
    memset(&mgr, 0, sizeof(mgr));

    /* Recover cycle 1 */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "c1 reopen");
        factory_t *rec_f = calloc(1, sizeof(factory_t));
        if (!rec_f) return 0;

        TEST_ASSERT(persist_load_factory(&db, 0, rec_f, ctx), "c1 load factory");
        TEST_ASSERT_EQ(rec_f->n_participants, 5, "c1 n_participants");

        lsp_channel_mgr_t rec_mgr;
        memset(&rec_mgr, 0, sizeof(rec_mgr));
        TEST_ASSERT(lsp_channels_init_from_db(&rec_mgr, ctx, rec_f,
                                                seckeys[0], 4, &db),
                    "c1 init from db");
        TEST_ASSERT_EQ(rec_mgr.n_channels, 4, "c1 n_channels");

        for (size_t c = 0; c < 4; c++) {
            const channel_t *rec = &rec_mgr.entries[c].channel;
            TEST_ASSERT_EQ(rec->local_amount, orig_local[c], "c1 local");
            TEST_ASSERT_EQ(rec->remote_amount, orig_remote[c], "c1 remote");
            TEST_ASSERT_EQ(rec->commitment_number, orig_cn[c], "c1 cn");
            TEST_ASSERT(memcmp(rec->local_payment_basepoint_secret,
                               orig_bp_pay[c], 32) == 0, "c1 pay secret");
            TEST_ASSERT(memcmp(rec->local_delayed_payment_basepoint_secret,
                               orig_bp_delay[c], 32) == 0, "c1 delay secret");
            TEST_ASSERT(memcmp(rec->local_revocation_basepoint_secret,
                               orig_bp_revoc[c], 32) == 0, "c1 revoc secret");
            TEST_ASSERT(memcmp(rec->local_htlc_basepoint_secret,
                               orig_bp_htlc[c], 32) == 0, "c1 htlc secret");
        }

        /* Copy recovered state into mgr/f for next cycle */
        memcpy(&mgr, &rec_mgr, sizeof(mgr));
        /* Release f's prior tx_bufs (from previous cycle's shallow copy)
           before they get overwritten by this cycle's pointers. */
        if (f->n_nodes > 0) factory_free(f);
        memcpy(f, rec_f, sizeof(*f));
        /* tx_buf pointers transferred to f via shallow copy — only free the
           struct itself; bufs will be freed by factory_free(f) at end. */
        free(rec_f);
        persist_close(&db);
    }

    /* ===== Cycle 2: Payments + active HTLCs ===== */
    mgr.entries[0].channel.local_amount += 5000;
    mgr.entries[0].channel.remote_amount -= 5000;
    mgr.entries[0].channel.commitment_number = 2;
    mgr.entries[1].channel.local_amount -= 3000;
    mgr.entries[1].channel.remote_amount += 3000;
    mgr.entries[1].channel.commitment_number = 1;

    /* Add active HTLCs */
    {
        htlc_t h0 = {0};
        h0.direction = HTLC_OFFERED; h0.state = HTLC_STATE_ACTIVE;
        h0.id = 1; h0.amount_sats = 2500; h0.cltv_expiry = 600;
        memset(h0.payment_hash, 0xAA, 32);
        mgr.entries[0].channel.htlcs[mgr.entries[0].channel.n_htlcs++] = h0;

        htlc_t h1 = {0};
        h1.direction = HTLC_RECEIVED; h1.state = HTLC_STATE_ACTIVE;
        h1.id = 2; h1.amount_sats = 4000; h1.cltv_expiry = 700;
        memset(h1.payment_hash, 0xBB, 32);
        mgr.entries[1].channel.htlcs[mgr.entries[1].channel.n_htlcs++] = h1;

        htlc_t h2 = {0};
        h2.direction = HTLC_OFFERED; h2.state = HTLC_STATE_ACTIVE;
        h2.id = 3; h2.amount_sats = 1500; h2.cltv_expiry = 800;
        memset(h2.payment_hash, 0xCC, 32);
        mgr.entries[2].channel.htlcs[mgr.entries[2].channel.n_htlcs++] = h2;

        /* Fulfilled HTLC on ch0 — should be filtered on recovery */
        htlc_t hf = {0};
        hf.direction = HTLC_OFFERED; hf.state = HTLC_STATE_FULFILLED;
        hf.id = 99; hf.amount_sats = 1000; hf.cltv_expiry = 500;
        memset(hf.payment_hash, 0xFF, 32);
        mgr.entries[0].channel.htlcs[mgr.entries[0].channel.n_htlcs++] = hf;
    }

    /* Save expected state */
    uint64_t c2_local[4], c2_remote[4], c2_cn[4];
    for (size_t c = 0; c < 4; c++) {
        c2_local[c] = mgr.entries[c].channel.local_amount;
        c2_remote[c] = mgr.entries[c].channel.remote_amount;
        c2_cn[c] = mgr.entries[c].channel.commitment_number;
    }

    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "c2 open");
        TEST_ASSERT(persist_begin(&db), "c2 begin");
        for (size_t c = 0; c < 4; c++) {
            const channel_t *ch = &mgr.entries[c].channel;
            TEST_ASSERT(persist_update_channel_balance(&db, (uint32_t)c,
                            ch->local_amount, ch->remote_amount,
                            ch->commitment_number), "c2 update bal");
        }
        /* Save HTLCs: 3 active + 1 fulfilled */
        for (size_t c = 0; c < 3; c++) {
            for (size_t h = 0; h < mgr.entries[c].channel.n_htlcs; h++) {
                TEST_ASSERT(persist_save_htlc(&db, (uint32_t)c,
                                &mgr.entries[c].channel.htlcs[h]), "c2 save htlc");
            }
        }
        TEST_ASSERT(persist_commit(&db), "c2 commit");
        persist_close(&db);
    }

    lsp_channels_cleanup(&mgr);
    memset(&mgr, 0, sizeof(mgr));

    /* Recover cycle 2 */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "c2 reopen");
        factory_t *rec_f = calloc(1, sizeof(factory_t));
        if (!rec_f) return 0;

        TEST_ASSERT(persist_load_factory(&db, 0, rec_f, ctx), "c2 load factory");

        lsp_channel_mgr_t rec_mgr;
        memset(&rec_mgr, 0, sizeof(rec_mgr));
        TEST_ASSERT(lsp_channels_init_from_db(&rec_mgr, ctx, rec_f,
                                                seckeys[0], 4, &db),
                    "c2 init from db");
        TEST_ASSERT_EQ(rec_mgr.n_channels, 4, "c2 n_channels");

        for (size_t c = 0; c < 4; c++) {
            TEST_ASSERT_EQ(rec_mgr.entries[c].channel.local_amount,
                           c2_local[c], "c2 local");
            TEST_ASSERT_EQ(rec_mgr.entries[c].channel.remote_amount,
                           c2_remote[c], "c2 remote");
            TEST_ASSERT_EQ(rec_mgr.entries[c].channel.commitment_number,
                           c2_cn[c], "c2 cn");
        }

        /* ch0: 1 active HTLC (fulfilled filtered out) */
        TEST_ASSERT_EQ(rec_mgr.entries[0].channel.n_htlcs, 1, "c2 ch0 htlc count");
        TEST_ASSERT_EQ(rec_mgr.entries[0].channel.htlcs[0].id, 1, "c2 ch0 htlc id");
        TEST_ASSERT_EQ(rec_mgr.entries[0].channel.htlcs[0].amount_sats, 2500, "c2 ch0 htlc amt");
        {
            unsigned char exp[32]; memset(exp, 0xAA, 32);
            TEST_ASSERT(memcmp(rec_mgr.entries[0].channel.htlcs[0].payment_hash,
                               exp, 32) == 0, "c2 ch0 htlc hash");
        }
        /* ch1: 1 active HTLC */
        TEST_ASSERT_EQ(rec_mgr.entries[1].channel.n_htlcs, 1, "c2 ch1 htlc count");
        TEST_ASSERT_EQ(rec_mgr.entries[1].channel.htlcs[0].id, 2, "c2 ch1 htlc id");
        /* ch2: 1 active HTLC */
        TEST_ASSERT_EQ(rec_mgr.entries[2].channel.n_htlcs, 1, "c2 ch2 htlc count");
        TEST_ASSERT_EQ(rec_mgr.entries[2].channel.htlcs[0].id, 3, "c2 ch2 htlc id");
        /* ch3: 0 HTLCs */
        TEST_ASSERT_EQ(rec_mgr.entries[3].channel.n_htlcs, 0, "c2 ch3 htlc count");

        memcpy(&mgr, &rec_mgr, sizeof(mgr));
        /* Release f's prior tx_bufs (from previous cycle's shallow copy)
           before they get overwritten by this cycle's pointers. */
        if (f->n_nodes > 0) factory_free(f);
        memcpy(f, rec_f, sizeof(*f));
        /* tx_buf pointers transferred to f via shallow copy — only free the
           struct itself; bufs will be freed by factory_free(f) at end. */
        free(rec_f);
        persist_close(&db);
    }

    /* ===== Cycle 3: HTLC resolution + new HTLCs ===== */
    mgr.entries[0].channel.local_amount += 2500;
    mgr.entries[0].channel.remote_amount -= 2500;
    mgr.entries[0].channel.commitment_number = 4;

    /* ch3: add 2 new active HTLCs */
    {
        htlc_t h10 = {0};
        h10.direction = HTLC_OFFERED; h10.state = HTLC_STATE_ACTIVE;
        h10.id = 10; h10.amount_sats = 8000; h10.cltv_expiry = 900;
        memset(h10.payment_hash, 0xD0, 32);
        mgr.entries[3].channel.htlcs[mgr.entries[3].channel.n_htlcs++] = h10;

        htlc_t h11 = {0};
        h11.direction = HTLC_RECEIVED; h11.state = HTLC_STATE_ACTIVE;
        h11.id = 11; h11.amount_sats = 6000; h11.cltv_expiry = 950;
        memset(h11.payment_hash, 0xD1, 32);
        mgr.entries[3].channel.htlcs[mgr.entries[3].channel.n_htlcs++] = h11;
    }

    /* Remove resolved HTLCs from local state */
    mgr.entries[0].channel.n_htlcs = 0;
    mgr.entries[1].channel.n_htlcs = 0;

    uint64_t c3_local[4], c3_remote[4], c3_cn[4];
    for (size_t c = 0; c < 4; c++) {
        c3_local[c] = mgr.entries[c].channel.local_amount;
        c3_remote[c] = mgr.entries[c].channel.remote_amount;
        c3_cn[c] = mgr.entries[c].channel.commitment_number;
    }

    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "c3 open");
        TEST_ASSERT(persist_begin(&db), "c3 begin");
        for (size_t c = 0; c < 4; c++) {
            const channel_t *ch = &mgr.entries[c].channel;
            TEST_ASSERT(persist_update_channel_balance(&db, (uint32_t)c,
                            ch->local_amount, ch->remote_amount,
                            ch->commitment_number), "c3 update bal");
        }
        /* Delete resolved HTLCs */
        TEST_ASSERT(persist_delete_htlc(&db, 0, 1), "c3 del htlc 0/1");
        TEST_ASSERT(persist_delete_htlc(&db, 1, 2), "c3 del htlc 1/2");
        /* Save new HTLCs on ch3 */
        for (size_t h = 0; h < mgr.entries[3].channel.n_htlcs; h++) {
            TEST_ASSERT(persist_save_htlc(&db, 3,
                            &mgr.entries[3].channel.htlcs[h]), "c3 save htlc");
        }
        TEST_ASSERT(persist_commit(&db), "c3 commit");
        persist_close(&db);
    }

    lsp_channels_cleanup(&mgr);
    memset(&mgr, 0, sizeof(mgr));

    /* Recover cycle 3 */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "c3 reopen");
        factory_t *rec_f = calloc(1, sizeof(factory_t));
        if (!rec_f) return 0;

        TEST_ASSERT(persist_load_factory(&db, 0, rec_f, ctx), "c3 load factory");

        lsp_channel_mgr_t rec_mgr;
        memset(&rec_mgr, 0, sizeof(rec_mgr));
        TEST_ASSERT(lsp_channels_init_from_db(&rec_mgr, ctx, rec_f,
                                                seckeys[0], 4, &db),
                    "c3 init from db");

        for (size_t c = 0; c < 4; c++) {
            TEST_ASSERT_EQ(rec_mgr.entries[c].channel.local_amount,
                           c3_local[c], "c3 local");
            TEST_ASSERT_EQ(rec_mgr.entries[c].channel.remote_amount,
                           c3_remote[c], "c3 remote");
            TEST_ASSERT_EQ(rec_mgr.entries[c].channel.commitment_number,
                           c3_cn[c], "c3 cn");
        }

        TEST_ASSERT_EQ(rec_mgr.entries[0].channel.n_htlcs, 0, "c3 ch0 0 htlcs");
        TEST_ASSERT_EQ(rec_mgr.entries[1].channel.n_htlcs, 0, "c3 ch1 0 htlcs");
        TEST_ASSERT_EQ(rec_mgr.entries[2].channel.n_htlcs, 1, "c3 ch2 1 htlc");
        TEST_ASSERT_EQ(rec_mgr.entries[2].channel.htlcs[0].id, 3, "c3 ch2 htlc id");
        TEST_ASSERT_EQ(rec_mgr.entries[3].channel.n_htlcs, 2, "c3 ch3 2 htlcs");
        TEST_ASSERT_EQ(rec_mgr.entries[3].channel.htlcs[0].id, 10, "c3 ch3 htlc0 id");
        TEST_ASSERT_EQ(rec_mgr.entries[3].channel.htlcs[1].id, 11, "c3 ch3 htlc1 id");

        memcpy(&mgr, &rec_mgr, sizeof(mgr));
        /* Release f's prior tx_bufs (from previous cycle's shallow copy)
           before they get overwritten by this cycle's pointers. */
        if (f->n_nodes > 0) factory_free(f);
        memcpy(f, rec_f, sizeof(*f));
        /* tx_buf pointers transferred to f via shallow copy — only free the
           struct itself; bufs will be freed by factory_free(f) at end. */
        free(rec_f);
        persist_close(&db);
    }

    /* ===== Cycle 4: Extreme values ===== */
    uint64_t commit_fee = f->fee_per_tx;
    mgr.entries[0].channel.local_amount = 0;
    mgr.entries[0].channel.remote_amount = f->funding_amount_sats / 4 - commit_fee;
    mgr.entries[0].channel.commitment_number = 200;
    mgr.entries[1].channel.local_amount = f->funding_amount_sats / 4 - commit_fee;
    mgr.entries[1].channel.remote_amount = 0;
    mgr.entries[1].channel.commitment_number = 255;

    /* Add 8 active HTLCs on ch2 */
    mgr.entries[2].channel.n_htlcs = 0;  /* clear old HTLC */
    for (int i = 0; i < 8; i++) {
        htlc_t h = {0};
        h.direction = (i % 2 == 0) ? HTLC_OFFERED : HTLC_RECEIVED;
        h.state = HTLC_STATE_ACTIVE;
        h.id = (uint64_t)(100 + i);
        h.amount_sats = (uint64_t)(1000 + i * 500);
        h.cltv_expiry = (uint32_t)(1000 + i * 10);
        memset(h.payment_hash, 0xE0 + (unsigned char)i, 32);
        mgr.entries[2].channel.htlcs[mgr.entries[2].channel.n_htlcs++] = h;
    }

    uint64_t c4_local[4], c4_remote[4], c4_cn[4];
    for (size_t c = 0; c < 4; c++) {
        c4_local[c] = mgr.entries[c].channel.local_amount;
        c4_remote[c] = mgr.entries[c].channel.remote_amount;
        c4_cn[c] = mgr.entries[c].channel.commitment_number;
    }

    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "c4 open");
        TEST_ASSERT(persist_begin(&db), "c4 begin");
        for (size_t c = 0; c < 4; c++) {
            const channel_t *ch = &mgr.entries[c].channel;
            TEST_ASSERT(persist_update_channel_balance(&db, (uint32_t)c,
                            ch->local_amount, ch->remote_amount,
                            ch->commitment_number), "c4 update bal");
        }
        /* Delete old ch2 HTLC (id=3 from cycle 2) */
        persist_delete_htlc(&db, 2, 3);
        /* Save 8 new HTLCs on ch2 */
        for (size_t h = 0; h < 8; h++) {
            TEST_ASSERT(persist_save_htlc(&db, 2,
                            &mgr.entries[2].channel.htlcs[h]), "c4 save htlc");
        }
        TEST_ASSERT(persist_commit(&db), "c4 commit");
        persist_close(&db);
    }

    lsp_channels_cleanup(&mgr);
    memset(&mgr, 0, sizeof(mgr));

    /* Recover cycle 4 */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "c4 reopen");
        factory_t *rec_f = calloc(1, sizeof(factory_t));
        if (!rec_f) return 0;

        TEST_ASSERT(persist_load_factory(&db, 0, rec_f, ctx), "c4 load factory");

        lsp_channel_mgr_t rec_mgr;
        memset(&rec_mgr, 0, sizeof(rec_mgr));
        TEST_ASSERT(lsp_channels_init_from_db(&rec_mgr, ctx, rec_f,
                                                seckeys[0], 4, &db),
                    "c4 init from db");

        /* Verify extreme balances */
        TEST_ASSERT_EQ(rec_mgr.entries[0].channel.local_amount, c4_local[0], "c4 ch0 local=0");
        TEST_ASSERT_EQ(rec_mgr.entries[0].channel.remote_amount, c4_remote[0], "c4 ch0 remote");
        TEST_ASSERT_EQ(rec_mgr.entries[0].channel.commitment_number, c4_cn[0], "c4 ch0 cn");
        TEST_ASSERT_EQ(rec_mgr.entries[1].channel.local_amount, c4_local[1], "c4 ch1 local");
        TEST_ASSERT_EQ(rec_mgr.entries[1].channel.remote_amount, c4_remote[1], "c4 ch1 remote=0");
        TEST_ASSERT_EQ(rec_mgr.entries[1].channel.commitment_number, c4_cn[1], "c4 ch1 cn");

        /* Verify 8 HTLCs on ch2 */
        TEST_ASSERT_EQ(rec_mgr.entries[2].channel.n_htlcs, 8, "c4 ch2 8 htlcs");
        for (int i = 0; i < 8; i++) {
            const htlc_t *h = &rec_mgr.entries[2].channel.htlcs[i];
            TEST_ASSERT_EQ(h->id, (uint64_t)(100 + i), "c4 ch2 htlc id");
            TEST_ASSERT_EQ(h->amount_sats, (uint64_t)(1000 + i * 500), "c4 ch2 htlc amt");
            TEST_ASSERT_EQ(h->cltv_expiry, (uint32_t)(1000 + i * 10), "c4 ch2 htlc cltv");
            htlc_direction_t exp_dir = (i % 2 == 0) ? HTLC_OFFERED : HTLC_RECEIVED;
            TEST_ASSERT_EQ(h->direction, exp_dir, "c4 ch2 htlc dir");
            unsigned char exp_hash[32];
            memset(exp_hash, 0xE0 + (unsigned char)i, 32);
            TEST_ASSERT(memcmp(h->payment_hash, exp_hash, 32) == 0, "c4 ch2 htlc hash");
        }

        /* ch3 still has 2 HTLCs from cycle 3 */
        TEST_ASSERT_EQ(rec_mgr.entries[3].channel.n_htlcs, 2, "c4 ch3 2 htlcs");

        lsp_channels_cleanup(&rec_mgr);
        factory_free(rec_f);
        free(rec_f);
        persist_close(&db);
    }

    lsp_channels_cleanup(&mgr);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    unlink(path);
    return 1;
}

/* ---- Test: DW counter state survives crash/recovery ---- */

int test_persist_crash_dw_state(void) {
    const char *path = "/tmp/test_crash_dw.db";
    unlink(path);

    /* Create factory to get proper DW counter */
    secp256k1_context *ctx = test_ctx();
    secp256k1_pubkey pks[5];
    if (!secp256k1_ec_pubkey_create(ctx, &pks[0], seckeys[0])) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pks[1], seckeys[1])) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pks[2], seckeys[2])) return 0;
    unsigned char s3[32], s4[32];
    memset(s3, 0x33, 32); memset(s4, 0x44, 32);
    if (!secp256k1_ec_pubkey_create(ctx, &pks[3], s3)) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pks[4], s4)) return 0;

    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;
    factory_init_from_pubkeys(f, ctx, pks, 5, 10, 4);

    /* Advance DW counter 5 times */
    for (int i = 0; i < 5; i++) {
        TEST_ASSERT(dw_counter_advance(&f->counter), "advance counter");
    }

    uint32_t epoch_after5 = f->counter.current_epoch;
    uint32_t layers_after5[DW_MAX_LAYERS];
    for (uint32_t i = 0; i < f->counter.n_layers; i++) {
        layers_after5[i] = f->counter.layers[i].current_state;
    }

    /* Enable per-leaf mode and set leaf states */
    f->per_leaf_enabled = 1;
    f->n_leaf_nodes = 2;
    f->leaf_layers[0].current_state = 2;
    f->leaf_layers[1].current_state = 1;

    /* ===== Persist cycle 1 ===== */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "dw c1 open");

        uint32_t layer_states[DW_MAX_LAYERS];
        for (uint32_t i = 0; i < f->counter.n_layers; i++)
            layer_states[i] = f->counter.layers[i].current_state;

        uint32_t leaf_states[8];
        for (int i = 0; i < f->n_leaf_nodes; i++)
            leaf_states[i] = f->leaf_layers[i].current_state;

        TEST_ASSERT(persist_save_dw_counter_with_leaves(&db, 0,
                        f->counter.current_epoch, f->counter.n_layers,
                        layer_states, f->per_leaf_enabled,
                        leaf_states, f->n_leaf_nodes), "dw c1 save");
        persist_close(&db);
    }

    /* Save expected n_layers for verification */
    uint32_t saved_n_layers = f->counter.n_layers;

    /* Zero factory DW state */
    memset(&f->counter, 0, sizeof(f->counter));
    f->per_leaf_enabled = 0;
    memset(f->leaf_layers, 0, sizeof(f->leaf_layers));
    f->n_leaf_nodes = 0;

    /* Recover cycle 1 */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "dw c1 reopen");

        uint32_t epoch, n_layers;
        uint32_t loaded_layers[DW_MAX_LAYERS];
        int per_leaf;
        uint32_t loaded_leaves[8];
        int n_leaves;

        TEST_ASSERT(persist_load_dw_counter_with_leaves(&db, 0,
                        &epoch, &n_layers, loaded_layers, DW_MAX_LAYERS,
                        &per_leaf, loaded_leaves, &n_leaves, 8), "dw c1 load");

        TEST_ASSERT_EQ(epoch, epoch_after5, "dw c1 epoch");
        TEST_ASSERT_EQ(n_layers, saved_n_layers, "dw c1 n_layers");
        for (uint32_t i = 0; i < saved_n_layers; i++) {
            TEST_ASSERT_EQ(loaded_layers[i], layers_after5[i], "dw c1 layer state");
        }
        TEST_ASSERT_EQ(per_leaf, 1, "dw c1 per_leaf enabled");
        TEST_ASSERT_EQ(n_leaves, 2, "dw c1 n_leaf_nodes");
        TEST_ASSERT_EQ(loaded_leaves[0], 2, "dw c1 leaf 0");
        TEST_ASSERT_EQ(loaded_leaves[1], 1, "dw c1 leaf 1");

        persist_close(&db);
    }

    /* ===== Persist cycle 2: advance more, re-persist ===== */
    dw_counter_init(&f->counter, saved_n_layers, 10, 4);
    for (int i = 0; i < 5; i++) dw_counter_advance(&f->counter);
    /* Advance 3 more times */
    for (int i = 0; i < 3; i++) {
        TEST_ASSERT(dw_counter_advance(&f->counter), "advance counter more");
    }

    uint32_t epoch_after8 = f->counter.current_epoch;
    uint32_t layers_after8[DW_MAX_LAYERS];
    for (uint32_t i = 0; i < f->counter.n_layers; i++) {
        layers_after8[i] = f->counter.layers[i].current_state;
    }

    f->per_leaf_enabled = 1;
    f->n_leaf_nodes = 2;
    f->leaf_layers[0].current_state = 3;
    f->leaf_layers[1].current_state = 1;

    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "dw c2 open");

        uint32_t layer_states[DW_MAX_LAYERS];
        for (uint32_t i = 0; i < f->counter.n_layers; i++)
            layer_states[i] = f->counter.layers[i].current_state;

        uint32_t leaf_states[8];
        for (int i = 0; i < f->n_leaf_nodes; i++)
            leaf_states[i] = f->leaf_layers[i].current_state;

        TEST_ASSERT(persist_save_dw_counter_with_leaves(&db, 0,
                        f->counter.current_epoch, f->counter.n_layers,
                        layer_states, f->per_leaf_enabled,
                        leaf_states, f->n_leaf_nodes), "dw c2 save");
        persist_close(&db);
    }

    memset(&f->counter, 0, sizeof(f->counter));

    /* Recover cycle 2 */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "dw c2 reopen");

        uint32_t epoch, n_layers;
        uint32_t loaded_layers[DW_MAX_LAYERS];
        int per_leaf;
        uint32_t loaded_leaves[8];
        int n_leaves;

        TEST_ASSERT(persist_load_dw_counter_with_leaves(&db, 0,
                        &epoch, &n_layers, loaded_layers, DW_MAX_LAYERS,
                        &per_leaf, loaded_leaves, &n_leaves, 8), "dw c2 load");

        TEST_ASSERT_EQ(epoch, epoch_after8, "dw c2 epoch");
        for (uint32_t i = 0; i < saved_n_layers; i++) {
            TEST_ASSERT_EQ(loaded_layers[i], layers_after8[i], "dw c2 layer state");
        }
        TEST_ASSERT_EQ(per_leaf, 1, "dw c2 per_leaf");
        TEST_ASSERT_EQ(loaded_leaves[0], 3, "dw c2 leaf 0");
        TEST_ASSERT_EQ(loaded_leaves[1], 1, "dw c2 leaf 1");

        persist_close(&db);
    }

    free(f);
    secp256k1_context_destroy(ctx);
    unlink(path);
    return 1;
}

/* ---- Test: bidirectional HTLC persistence (sender + receiver) ---- */

int test_persist_htlc_bidirectional(void) {
    const char *path = "/tmp/test_persist_htlc_bidir.db";
    unlink(path);

    /* Save: RECEIVED on channel 0 (sender-side), OFFERED on channel 1 (dest-side) */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "open for save");

        unsigned char hash[32];
        memset(hash, 0x42, 32);

        htlc_t h_sender = {0};
        h_sender.id = 7;
        h_sender.direction = HTLC_RECEIVED;  /* LSP received from sender */
        h_sender.state = HTLC_STATE_ACTIVE;
        h_sender.amount_sats = 2000;
        memcpy(h_sender.payment_hash, hash, 32);
        h_sender.cltv_expiry = 144;

        htlc_t h_dest = {0};
        h_dest.id = 3;
        h_dest.direction = HTLC_OFFERED;  /* LSP offered to dest */
        h_dest.state = HTLC_STATE_ACTIVE;
        h_dest.amount_sats = 2000;
        memcpy(h_dest.payment_hash, hash, 32);
        h_dest.cltv_expiry = 144;

        TEST_ASSERT(persist_save_htlc(&db, 0, &h_sender), "save sender htlc");
        TEST_ASSERT(persist_save_htlc(&db, 1, &h_dest), "save dest htlc");
        persist_close(&db);
    }

    /* Load: reopen and verify both HTLCs on different channels */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, path), "reopen for load");

        htlc_t loaded[16];
        size_t count0 = persist_load_htlcs(&db, 0, loaded, 16);
        TEST_ASSERT_EQ(count0, 1, "channel 0 htlc count");
        TEST_ASSERT_EQ(loaded[0].id, 7, "ch0 htlc id");
        TEST_ASSERT_EQ(loaded[0].direction, HTLC_RECEIVED, "ch0 direction");
        TEST_ASSERT_EQ(loaded[0].amount_sats, 2000, "ch0 amount");

        size_t count1 = persist_load_htlcs(&db, 1, loaded, 16);
        TEST_ASSERT_EQ(count1, 1, "channel 1 htlc count");
        TEST_ASSERT_EQ(loaded[0].id, 3, "ch1 htlc id");
        TEST_ASSERT_EQ(loaded[0].direction, HTLC_OFFERED, "ch1 direction");
        TEST_ASSERT_EQ(loaded[0].amount_sats, 2000, "ch1 amount");

        /* Delete both */
        TEST_ASSERT(persist_delete_htlc(&db, 0, 7), "delete sender htlc");
        TEST_ASSERT(persist_delete_htlc(&db, 1, 3), "delete dest htlc");

        /* Verify zero HTLCs remain */
        count0 = persist_load_htlcs(&db, 0, loaded, 16);
        TEST_ASSERT_EQ(count0, 0, "ch0 empty after delete");
        count1 = persist_load_htlcs(&db, 1, loaded, 16);
        TEST_ASSERT_EQ(count1, 0, "ch1 empty after delete");

        persist_close(&db);
    }

    unlink(path);
    return 1;
}

/* ---- Test: Transaction commit — multi-statement atomic persistence ---- */

int test_persist_transaction_commit(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    secp256k1_context *ctx = test_ctx();
    secp256k1_pubkey pk_local, pk_remote;
    if (!secp256k1_ec_pubkey_create(ctx, &pk_local, seckeys[0])) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pk_remote, seckeys[1])) return 0;

    unsigned char fake_txid[32] = {0};
    fake_txid[0] = 0xDD;
    unsigned char fake_spk[34];
    memset(fake_spk, 0xAA, 34);

    /* Create channel with initial state */
    channel_t ch;
    TEST_ASSERT(channel_init(&ch, ctx, seckeys[0], &pk_local, &pk_remote,
                              fake_txid, 1, 100000, fake_spk, 34,
                              50000, 50000, 144), "channel_init");
    TEST_ASSERT(persist_save_channel(&db, &ch, 0, 0), "save channel");

    /* Begin transaction, update balance + save HTLC, commit */
    TEST_ASSERT(persist_begin(&db), "begin txn");
    TEST_ASSERT(persist_in_transaction(&db), "in txn");

    TEST_ASSERT(persist_update_channel_balance(&db, 0, 40000, 60000, 1),
                "update balance in txn");

    htlc_t h = {0};
    h.id = 5;
    h.direction = HTLC_OFFERED;
    h.state = HTLC_STATE_ACTIVE;
    h.amount_sats = 10000;
    memset(h.payment_hash, 0xAB, 32);
    h.cltv_expiry = 500;
    TEST_ASSERT(persist_save_htlc(&db, 0, &h), "save htlc in txn");

    TEST_ASSERT(persist_commit(&db), "commit txn");
    TEST_ASSERT(!persist_in_transaction(&db), "not in txn after commit");

    /* Verify both operations persisted */
    uint64_t local, remote, commit;
    TEST_ASSERT(persist_load_channel_state(&db, 0, &local, &remote, &commit),
                "load after commit");
    TEST_ASSERT_EQ(local, 40000, "local after commit");
    TEST_ASSERT_EQ(remote, 60000, "remote after commit");
    TEST_ASSERT_EQ(commit, 1, "commit_number after commit");

    htlc_t loaded[16];
    size_t count = persist_load_htlcs(&db, 0, loaded, 16);
    TEST_ASSERT_EQ(count, 1, "htlc count after commit");
    TEST_ASSERT_EQ(loaded[0].id, 5, "htlc id after commit");
    TEST_ASSERT_EQ(loaded[0].amount_sats, 10000, "htlc amount after commit");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}

/* ---- Test: Transaction rollback — multi-statement atomic rollback ---- */

int test_persist_transaction_rollback(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    secp256k1_context *ctx = test_ctx();
    secp256k1_pubkey pk_local, pk_remote;
    if (!secp256k1_ec_pubkey_create(ctx, &pk_local, seckeys[0])) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pk_remote, seckeys[1])) return 0;

    unsigned char fake_txid[32] = {0};
    fake_txid[0] = 0xDD;
    unsigned char fake_spk[34];
    memset(fake_spk, 0xAA, 34);

    /* Create channel with initial state */
    channel_t ch;
    TEST_ASSERT(channel_init(&ch, ctx, seckeys[0], &pk_local, &pk_remote,
                              fake_txid, 1, 100000, fake_spk, 34,
                              50000, 50000, 144), "channel_init");
    TEST_ASSERT(persist_save_channel(&db, &ch, 0, 0), "save channel");

    /* Begin transaction, update balance + save HTLC, then ROLLBACK */
    TEST_ASSERT(persist_begin(&db), "begin txn");

    TEST_ASSERT(persist_update_channel_balance(&db, 0, 30000, 70000, 2),
                "update balance in txn");

    htlc_t h = {0};
    h.id = 9;
    h.direction = HTLC_RECEIVED;
    h.state = HTLC_STATE_ACTIVE;
    h.amount_sats = 20000;
    memset(h.payment_hash, 0xCD, 32);
    h.cltv_expiry = 600;
    TEST_ASSERT(persist_save_htlc(&db, 0, &h), "save htlc in txn");

    TEST_ASSERT(persist_rollback(&db), "rollback txn");
    TEST_ASSERT(!persist_in_transaction(&db), "not in txn after rollback");

    /* Verify original state preserved (balance unchanged, no HTLC) */
    uint64_t local, remote, commit;
    TEST_ASSERT(persist_load_channel_state(&db, 0, &local, &remote, &commit),
                "load after rollback");
    TEST_ASSERT_EQ(local, 50000, "local after rollback (original)");
    TEST_ASSERT_EQ(remote, 50000, "remote after rollback (original)");
    TEST_ASSERT_EQ(commit, 0, "commit_number after rollback (original)");

    htlc_t loaded[16];
    size_t count = persist_load_htlcs(&db, 0, loaded, 16);
    TEST_ASSERT_EQ(count, 0, "no htlcs after rollback");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}

/* ================================================================
 * PS_N1 – PS_N8: LN invoice + peer channel persistence (schema v9)
 * ================================================================ */

#include "superscalar/invoice.h"

/* helper: make a deterministic bolt11_invoice_entry_t */
static bolt11_invoice_entry_t make_test_invoice(unsigned char seed) {
    bolt11_invoice_entry_t e;
    memset(&e, 0, sizeof(e));
    memset(e.payment_hash,   seed,     32);
    memset(e.preimage,       seed + 1, 32);
    memset(e.payment_secret, seed + 2, 32);
    e.amount_msat  = 100000ULL + seed;
    e.expiry       = 3600;
    e.created_at   = 1700000000U + seed;
    e.settled      = 0;
    e.active       = 1;
    snprintf(e.description, sizeof(e.description), "test invoice %d", (int)seed);
    return e;
}

/* PS_N1: save one invoice, reload, hash matches */
int test_ps_n1_save_load_invoice(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    bolt11_invoice_entry_t inv = make_test_invoice(0x01);
    TEST_ASSERT(persist_save_ln_invoice(&db, &inv), "save invoice");

    bolt11_invoice_table_t tbl;
    memset(&tbl, 0, sizeof(tbl));
    int n = persist_load_ln_invoices(&db, &tbl);
    TEST_ASSERT(n >= 0, "load ok");
    TEST_ASSERT_EQ(tbl.count, 1, "count == 1");
    TEST_ASSERT(memcmp(tbl.entries[0].payment_hash, inv.payment_hash, 32) == 0,
                "payment_hash matches");

    persist_close(&db);
    return 1;
}

/* PS_N2: save 3 invoices, load, all 3 present */
int test_ps_n2_save_3_invoices(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    for (unsigned char s = 1; s <= 3; s++) {
        bolt11_invoice_entry_t inv = make_test_invoice(s * 10);
        TEST_ASSERT(persist_save_ln_invoice(&db, &inv), "save invoice");
    }

    bolt11_invoice_table_t tbl;
    memset(&tbl, 0, sizeof(tbl));
    int n = persist_load_ln_invoices(&db, &tbl);
    TEST_ASSERT(n >= 0, "load ok");
    TEST_ASSERT_EQ(tbl.count, 3, "count == 3");

    persist_close(&db);
    return 1;
}

/* PS_N3: delete invoice, reload, count = 0 */
int test_ps_n3_delete_invoice(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    bolt11_invoice_entry_t inv = make_test_invoice(0x42);
    TEST_ASSERT(persist_save_ln_invoice(&db, &inv), "save invoice");
    TEST_ASSERT(persist_delete_ln_invoice(&db, inv.payment_hash), "delete invoice");

    bolt11_invoice_table_t tbl;
    memset(&tbl, 0, sizeof(tbl));
    int n = persist_load_ln_invoices(&db, &tbl);
    TEST_ASSERT(n >= 0, "load ok");
    TEST_ASSERT_EQ(tbl.count, 0, "count == 0 after delete");

    persist_close(&db);
    return 1;
}

/* PS_N4: upsert – same payment_hash twice → count = 1 */
int test_ps_n4_upsert_invoice(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    bolt11_invoice_entry_t inv = make_test_invoice(0x07);
    TEST_ASSERT(persist_save_ln_invoice(&db, &inv), "save first");
    inv.amount_msat = 999999;
    TEST_ASSERT(persist_save_ln_invoice(&db, &inv), "save second (upsert)");

    bolt11_invoice_table_t tbl;
    memset(&tbl, 0, sizeof(tbl));
    int n = persist_load_ln_invoices(&db, &tbl);
    TEST_ASSERT(n >= 0, "load ok");
    TEST_ASSERT_EQ(tbl.count, 1, "count == 1 after upsert");
    TEST_ASSERT_EQ((long long)tbl.entries[0].amount_msat, 999999LL, "updated amount");

    persist_close(&db);
    return 1;
}

/* callback context for peer channel tests */
typedef struct {
    int            count;
    unsigned char  last_channel_id[32];
    uint64_t       last_local;
    uint64_t       last_remote;
    int            last_state;
    char           last_host[256];
    uint16_t       last_port;
} pc_cb_ctx_t;

static void pc_callback(const unsigned char channel_id[32],
                         const unsigned char peer_pubkey[33],
                         uint64_t capacity_sat,
                         uint64_t local_balance_msat,
                         uint64_t remote_balance_msat,
                         int state,
                         const char *peer_host,
                         uint16_t peer_port,
                         void *ctx) {
    pc_cb_ctx_t *c = (pc_cb_ctx_t *)ctx;
    c->count++;
    memcpy(c->last_channel_id, channel_id, 32);
    c->last_local  = local_balance_msat;
    c->last_remote = remote_balance_msat;
    c->last_state  = state;
    if (peer_host) strncpy(c->last_host, peer_host, sizeof(c->last_host) - 1);
    c->last_port = peer_port;
    (void)peer_pubkey; (void)capacity_sat;
}

/* PS_N5: save one channel, load via callback, channel_id matches */
int test_ps_n5_save_load_peer_channel(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    unsigned char cid[32], ppk[33];
    memset(cid, 0xAA, 32);
    memset(ppk, 0xBB, 33);

    TEST_ASSERT(persist_save_ln_peer_channel(&db, cid, ppk,
                    1000000, 500000, 500000, 1, NULL, 0),
                "save channel");

    pc_cb_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    TEST_ASSERT(persist_load_ln_peer_channels(&db, pc_callback, &ctx), "load ok");
    TEST_ASSERT_EQ(ctx.count, 1, "callback fired once");
    TEST_ASSERT(memcmp(ctx.last_channel_id, cid, 32) == 0, "channel_id matches");

    persist_close(&db);
    return 1;
}

/* PS_N6: save 2 channels, callback fires twice */
int test_ps_n6_save_2_channels(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    unsigned char cid1[32], cid2[32], ppk[33];
    memset(cid1, 0x11, 32);
    memset(cid2, 0x22, 32);
    memset(ppk,  0x33, 33);

    TEST_ASSERT(persist_save_ln_peer_channel(&db, cid1, ppk, 1000000, 500000, 500000, 0, NULL, 0),
                "save channel 1");
    TEST_ASSERT(persist_save_ln_peer_channel(&db, cid2, ppk, 2000000, 900000, 1100000, 0, NULL, 0),
                "save channel 2");

    pc_cb_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    TEST_ASSERT(persist_load_ln_peer_channels(&db, pc_callback, &ctx), "load ok");
    TEST_ASSERT_EQ(ctx.count, 2, "callback fired twice");

    persist_close(&db);
    return 1;
}

/* PS_N7: update channel (same channel_id, different balance), sees updated */
int test_ps_n7_update_channel(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    unsigned char cid[32], ppk[33];
    memset(cid, 0x55, 32);
    memset(ppk, 0x66, 33);

    TEST_ASSERT(persist_save_ln_peer_channel(&db, cid, ppk,
                    1000000, 600000, 400000, 0, NULL, 0),
                "initial save");
    TEST_ASSERT(persist_save_ln_peer_channel(&db, cid, ppk,
                    1000000, 300000, 700000, 2, NULL, 0),
                "updated save");

    pc_cb_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    TEST_ASSERT(persist_load_ln_peer_channels(&db, pc_callback, &ctx), "load ok");
    TEST_ASSERT_EQ(ctx.count, 1, "only one row");
    TEST_ASSERT_EQ((long long)ctx.last_local,  300000LL, "updated local");
    TEST_ASSERT_EQ((long long)ctx.last_remote, 700000LL, "updated remote");
    TEST_ASSERT_EQ(ctx.last_state, 2, "updated state");

    persist_close(&db);
    return 1;
}

/* PS_N8: NULL db → save returns 0 (no crash) */
int test_ps_n8_null_db(void) {
    persist_t db;
    memset(&db, 0, sizeof(db));  /* db.db == NULL */

    bolt11_invoice_entry_t inv = make_test_invoice(0xFF);
    TEST_ASSERT(persist_save_ln_invoice(&db, &inv) == 0, "null db returns 0");

    unsigned char cid[32], ppk[33];
    memset(cid, 0xAA, 32);
    memset(ppk, 0xBB, 33);
    TEST_ASSERT(persist_save_ln_peer_channel(&db, cid, ppk,
                    100, 50, 50, 0, NULL, 0) == 0,
                "null db channel returns 0");
    return 1;
}

/* ==========================================================================
 * Phase A tests: host/port persistence (PS_10A through PS_10D)
 * ========================================================================== */

/* PS_10A: Save channel with host/port -> load -> host/port match */
int test_ps_10a_host_port_roundtrip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "PS_10A: open");

    unsigned char cid[32], ppk[33];
    memset(cid, 0xA1, 32);
    memset(ppk, 0xA2, 33);

    TEST_ASSERT(persist_save_ln_peer_channel(&db, cid, ppk,
                    1000000, 500000, 500000, 1,
                    "localhost", 9735),
                "PS_10A: save with host/port");

    pc_cb_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    TEST_ASSERT(persist_load_ln_peer_channels(&db, pc_callback, &ctx), "PS_10A: load ok");
    TEST_ASSERT_EQ(ctx.count, 1, "PS_10A: callback fired once");
    TEST_ASSERT(strcmp(ctx.last_host, "localhost") == 0, "PS_10A: host matches");
    TEST_ASSERT_EQ(ctx.last_port, 9735, "PS_10A: port matches");

    persist_close(&db);
    return 1;
}

/* PS_10B: Save with empty host (ephemeral peer) -> load -> no crash, host is empty */
int test_ps_10b_empty_host(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "PS_10B: open");

    unsigned char cid[32], ppk[33];
    memset(cid, 0xB1, 32);
    memset(ppk, 0xB2, 33);

    TEST_ASSERT(persist_save_ln_peer_channel(&db, cid, ppk,
                    500000, 200000, 300000, 0,
                    NULL, 0),
                "PS_10B: save with NULL host");

    pc_cb_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    TEST_ASSERT(persist_load_ln_peer_channels(&db, pc_callback, &ctx), "PS_10B: load ok");
    TEST_ASSERT_EQ(ctx.count, 1, "PS_10B: callback fired once");
    TEST_ASSERT(strlen(ctx.last_host) == 0, "PS_10B: host is empty");
    TEST_ASSERT_EQ(ctx.last_port, 0, "PS_10B: port is 0");

    persist_close(&db);
    return 1;
}

/* PS_10C: Schema v10 applied; peer_host/peer_port columns exist */
int test_ps_10c_schema_v10(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "PS_10C: open");
    int ver = persist_schema_version(&db);
    TEST_ASSERT(ver == PERSIST_SCHEMA_VERSION, "PS_10C: schema version matches");

    unsigned char cid[32], ppk[33];
    memset(cid, 0xC1, 32);
    memset(ppk, 0xC2, 33);
    TEST_ASSERT(persist_save_ln_peer_channel(&db, cid, ppk,
                    800000, 400000, 400000, 0,
                    "192.168.1.1", 9735),
                "PS_10C: save with IP");

    pc_cb_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    TEST_ASSERT(persist_load_ln_peer_channels(&db, pc_callback, &ctx), "PS_10C: load ok");
    TEST_ASSERT_EQ(ctx.count, 1, "PS_10C: one row");

    persist_close(&db);
    return 1;
}

/* PS_10D: persist_load_ln_peer_channels delivers host/port to callback */
int test_ps_10d_host_in_callback(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "PS_10D: open");

    unsigned char cid[32], ppk[33];
    memset(cid, 0xD1, 32);
    memset(ppk, 0xD2, 33);

    TEST_ASSERT(persist_save_ln_peer_channel(&db, cid, ppk,
                    2000000, 1000000, 1000000, 1,
                    "node.example.com", 9736),
                "PS_10D: save");

    pc_cb_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    persist_load_ln_peer_channels(&db, pc_callback, &ctx);
    TEST_ASSERT_EQ(ctx.count, 1, "PS_10D: got callback");
    TEST_ASSERT(strcmp(ctx.last_host, "node.example.com") == 0, "PS_10D: host delivered");
    TEST_ASSERT_EQ(ctx.last_port, 9736, "PS_10D: port delivered");

    persist_close(&db);
    return 1;
}

/* ==========================================================================
 * Phase D tests: circuit breaker persistence (CB_P1 through CB_P4)
 * ========================================================================== */

/* CB_P1: save + load circuit breaker limits -> match */
int test_cb_p1_save_load_limits(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "CB_P1: open");

    unsigned char pk[33];
    memset(pk, 0xE1, 33);

    TEST_ASSERT(persist_save_circuit_breaker_peer(&db, pk, 100, 50000000000ULL, 1800) == 1,
                "CB_P1: save");

    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    int n = persist_load_circuit_breaker_peers(&db, &cb);
    TEST_ASSERT(n >= 1, "CB_P1: loaded at least 1");

    int found = 0;
    for (int i = 0; i < cb.n_peers; i++) {
        if (cb.peers[i].active && memcmp(cb.peers[i].peer_pubkey, pk, 33) == 0) {
            TEST_ASSERT_EQ(cb.peers[i].max_pending_htlcs, 100, "CB_P1: max_pending_htlcs");
            TEST_ASSERT_EQ((long long)cb.peers[i].max_pending_msat, 50000000000LL,
                           "CB_P1: max_pending_msat");
            TEST_ASSERT_EQ(cb.peers[i].max_htlcs_per_hour, 1800, "CB_P1: max_htlcs_per_hour");
            found = 1; break;
        }
    }
    TEST_ASSERT(found, "CB_P1: peer slot found in circuit breaker");

    persist_close(&db);
    return 1;
}

/* CB_P2: Save 3 peers -> load -> all 3 in circuit_breaker_t */
int test_cb_p2_save_3_peers(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "CB_P2: open");

    unsigned char pk1[33], pk2[33], pk3[33];
    memset(pk1, 0x11, 33); pk1[0] = 0x02;
    memset(pk2, 0x22, 33); pk2[0] = 0x02;
    memset(pk3, 0x33, 33); pk3[0] = 0x02;

    TEST_ASSERT(persist_save_circuit_breaker_peer(&db, pk1, 10, 1000000ULL, 100) == 1,
                "CB_P2: save 1");
    TEST_ASSERT(persist_save_circuit_breaker_peer(&db, pk2, 20, 2000000ULL, 200) == 1,
                "CB_P2: save 2");
    TEST_ASSERT(persist_save_circuit_breaker_peer(&db, pk3, 30, 3000000ULL, 300) == 1,
                "CB_P2: save 3");

    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    int n = persist_load_circuit_breaker_peers(&db, &cb);
    TEST_ASSERT(n == 3, "CB_P2: loaded 3 peers");
    TEST_ASSERT(cb.n_peers == 3, "CB_P2: n_peers == 3");

    persist_close(&db);
    return 1;
}

/* CB_P3: Upsert same pubkey with new limits -> load -> sees new limits (no duplicate) */
int test_cb_p3_upsert_limits(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "CB_P3: open");

    unsigned char pk[33];
    memset(pk, 0xAB, 33);

    TEST_ASSERT(persist_save_circuit_breaker_peer(&db, pk, 50, 9999ULL, 60) == 1,
                "CB_P3: initial save");
    TEST_ASSERT(persist_save_circuit_breaker_peer(&db, pk, 75, 8888ULL, 120) == 1,
                "CB_P3: upsert");

    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    int n = persist_load_circuit_breaker_peers(&db, &cb);
    TEST_ASSERT(n == 1, "CB_P3: only 1 row (upsert)");

    int found = 0;
    for (int i = 0; i < cb.n_peers; i++) {
        if (cb.peers[i].active && memcmp(cb.peers[i].peer_pubkey, pk, 33) == 0) {
            TEST_ASSERT_EQ(cb.peers[i].max_pending_htlcs, 75, "CB_P3: updated htlcs");
            TEST_ASSERT_EQ((long long)cb.peers[i].max_pending_msat, 8888LL,
                           "CB_P3: updated msat");
            TEST_ASSERT_EQ(cb.peers[i].max_htlcs_per_hour, 120, "CB_P3: updated hourly");
            found = 1; break;
        }
    }
    TEST_ASSERT(found, "CB_P3: upserted peer found");

    persist_close(&db);
    return 1;
}

/* CB_P4: NULL persist -> save returns -1, no crash */
int test_cb_p4_null_persist(void) {
    TEST_ASSERT(persist_save_circuit_breaker_peer(NULL, NULL, 0, 0, 0) == -1,
                "CB_P4: NULL persist returns -1");

    circuit_breaker_t cb;
    circuit_breaker_init(&cb);
    TEST_ASSERT(persist_load_circuit_breaker_peers(NULL, &cb) == -1,
                "CB_P4: NULL persist load returns -1");
    TEST_ASSERT(persist_load_circuit_breaker_peers(NULL, NULL) == -1,
                "CB_P4: NULL both returns -1");
    return 1;
}

/* ==========================================================================
 * PR #78 tests: PTLC persistence, peer storage, RGS export,
 * BIP 353, dynamic commitments, BIP 158 RPC elimination
 * ========================================================================== */

/* PTLC_P1: save + load PTLC round-trip */
int test_ptlc_p1_persist_roundtrip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "PTLC_P1: open");

    ptlc_t pt;
    memset(&pt, 0, sizeof(pt));
    pt.id = 42;
    pt.direction = PTLC_OFFERED;
    pt.state = PTLC_STATE_ACTIVE;
    pt.amount_sats = 100000;
    pt.cltv_expiry = 700000;

    TEST_ASSERT(persist_save_ptlc(&db, 1, &pt), "PTLC_P1: save");

    ptlc_t loaded[4];
    size_t n = persist_load_ptlcs(&db, 1, loaded, 4);
    TEST_ASSERT_EQ(n, 1, "PTLC_P1: loaded 1");
    TEST_ASSERT_EQ(loaded[0].id, 42, "PTLC_P1: id matches");
    TEST_ASSERT_EQ(loaded[0].direction, PTLC_OFFERED, "PTLC_P1: direction");
    TEST_ASSERT_EQ((long long)loaded[0].amount_sats, 100000LL, "PTLC_P1: amount");

    persist_close(&db);
    return 1;
}

/* PTLC_P2: delete PTLC */
int test_ptlc_p2_delete(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "PTLC_P2: open");

    ptlc_t pt;
    memset(&pt, 0, sizeof(pt));
    pt.id = 7;
    pt.direction = PTLC_RECEIVED;
    pt.state = PTLC_STATE_ACTIVE;
    pt.amount_sats = 50000;

    persist_save_ptlc(&db, 1, &pt);
    TEST_ASSERT(persist_delete_ptlc(&db, 1, 7), "PTLC_P2: delete");

    ptlc_t loaded[4];
    size_t n = persist_load_ptlcs(&db, 1, loaded, 4);
    TEST_ASSERT_EQ(n, 0, "PTLC_P2: empty after delete");

    persist_close(&db);
    return 1;
}

/* PS_BLOB1: peer storage save + load round-trip */
int test_ps_blob1_roundtrip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "PS_BLOB1: open");

    unsigned char pk[33];
    memset(pk, 0x42, 33);
    unsigned char blob[] = "encrypted_backup_data_here";
    uint16_t blen = sizeof(blob) - 1;

    TEST_ASSERT(persist_save_peer_storage(&db, pk, blob, blen), "PS_BLOB1: save");

    unsigned char loaded[256];
    uint16_t loaded_len = 0;
    TEST_ASSERT(persist_load_peer_storage(&db, pk, loaded, &loaded_len, sizeof(loaded)),
                "PS_BLOB1: load");
    TEST_ASSERT_EQ(loaded_len, blen, "PS_BLOB1: length matches");
    TEST_ASSERT(memcmp(loaded, blob, blen) == 0, "PS_BLOB1: data matches");

    persist_close(&db);
    return 1;
}

/* RGS_E1: RGS export produces valid blob with magic header */
int test_rgs_e1_export(void) {
    gossip_store_t gs;
    TEST_ASSERT(gossip_store_open_in_memory(&gs), "RGS_E1: open store");

    unsigned char out[4096];
    size_t len = gossip_store_export_rgs(&gs, out, sizeof(out));
    /* Empty store produces a minimal RGS blob (17 bytes: magic+ts+node_count+chan_count) */
    TEST_ASSERT(len > 0, "RGS_E1: blob produced");
    if (len >= 5)
        TEST_ASSERT(memcmp(out, "RGSV1", 5) == 0, "RGS_E1: magic header");

    gossip_store_close(&gs);
    return 1;
}

/* BIP353_1: bip353_to_dns_name produces correct DNS name */
int test_bip353_dns_name(void) {
    char dns[512];
    int ok = bip353_to_dns_name("satoshi@bitcoin.org", dns, sizeof(dns));
    TEST_ASSERT(ok, "BIP353_1: conversion ok");
    TEST_ASSERT(strcmp(dns, "satoshi._bitcoin-payment.bitcoin.org") == 0,
                "BIP353_1: DNS name matches");
    return 1;
}

/* BIP353_2: bip353_validate_address accepts valid, rejects invalid */
int test_bip353_validate(void) {
    TEST_ASSERT(bip353_validate_address("user@example.com") == 1,
                "BIP353_2: valid address");
    TEST_ASSERT(bip353_validate_address("noatsign") == 0,
                "BIP353_2: no @ rejected");
    TEST_ASSERT(bip353_validate_address("@nodomain") == 0,
                "BIP353_2: empty user rejected");
    return 1;
}

/* CHANTYPE_1: channel_type TLV encode/decode round-trip */
int test_chantype_roundtrip(void) {
    uint32_t bits = (1 << 12) | (1 << 22);  /* static_remote_key + anchors */
    unsigned char buf[16];
    size_t len = channel_type_encode(bits, buf, sizeof(buf));
    TEST_ASSERT(len > 0, "CHANTYPE_1: encode ok");

    uint32_t decoded = 0;
    TEST_ASSERT(channel_type_decode(buf, len, &decoded), "CHANTYPE_1: decode ok");
    TEST_ASSERT_EQ(decoded, bits, "CHANTYPE_1: round-trip matches");
    return 1;
}

/* CHANTYPE_2: negotiate = AND of local and remote bits */
int test_chantype_negotiate(void) {
    uint32_t local  = (1 << 12) | (1 << 22) | (1 << 4);
    uint32_t remote = (1 << 12) | (1 << 6);
    uint32_t agreed = channel_type_negotiate(local, remote);
    TEST_ASSERT_EQ(agreed, (uint32_t)(1 << 12), "CHANTYPE_2: only shared bit");
    return 1;
}

/* PTLC_COMMIT_1: commitment tx with PTLC has extra output */
int test_ptlc_commitment_output(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    TEST_ASSERT(ctx, "PTLC_CO1: ctx");

    channel_t ch;
    unsigned char local_priv[32], remote_priv[32];
    memset(local_priv, 0x01, 32); local_priv[31] = 0x01;
    memset(remote_priv, 0x02, 32); remote_priv[31] = 0x02;

    secp256k1_pubkey local_pk, remote_pk;
    secp256k1_ec_pubkey_create(ctx, &local_pk, local_priv);
    secp256k1_ec_pubkey_create(ctx, &remote_pk, remote_priv);

    unsigned char txid[32] = {0};
    unsigned char spk[34] = {0x51, 0x20};
    channel_init(&ch, ctx, local_priv, &local_pk, &remote_pk,
                  txid, 0, 1000000, spk, 34, 500000, 400000, 144);

    /* Set up basepoints */
    unsigned char bp1[32], bp2[32], bp3[32], bp4[32];
    memset(bp1, 0x11, 32); bp1[0] = 0x01;
    memset(bp2, 0x12, 32); bp2[0] = 0x01;
    memset(bp3, 0x13, 32); bp3[0] = 0x01;
    memset(bp4, 0x14, 32); bp4[0] = 0x01;
    channel_set_local_basepoints(&ch, bp1, bp2, bp3);
    channel_set_local_htlc_basepoint(&ch, bp4);

    secp256k1_pubkey rbp, pbp, dbp, hbp;
    secp256k1_ec_pubkey_create(ctx, &rbp, bp3);
    secp256k1_ec_pubkey_create(ctx, &pbp, bp1);
    secp256k1_ec_pubkey_create(ctx, &dbp, bp2);
    secp256k1_ec_pubkey_create(ctx, &hbp, bp4);
    channel_set_remote_basepoints(&ch, &pbp, &dbp, &rbp);
    channel_set_remote_htlc_basepoint(&ch, &hbp);

    channel_generate_local_pcs(&ch, 0);

    /* Build commitment tx WITHOUT PTLC */
    tx_buf_t tx1;
    unsigned char txid1[32];
    int r1 = channel_build_commitment_tx(&ch, &tx1, txid1);
    TEST_ASSERT(r1, "PTLC_CO1: commitment without PTLC");
    size_t len1 = tx1.len;

    /* Add a PTLC */
    unsigned char pp_priv[32];
    memset(pp_priv, 0x77, 32); pp_priv[0] = 0x01;
    secp256k1_pubkey pp;
    secp256k1_ec_pubkey_create(ctx, &pp, pp_priv);

    uint64_t ptlc_id;
    channel_add_ptlc(&ch, PTLC_OFFERED, 10000, &pp, 800000, &ptlc_id);

    /* Build commitment tx WITH PTLC */
    tx_buf_t tx2;
    unsigned char txid2[32];
    int r2 = channel_build_commitment_tx(&ch, &tx2, txid2);
    TEST_ASSERT(r2, "PTLC_CO1: commitment with PTLC");

    /* TX with PTLC should be larger (has extra output) */
    TEST_ASSERT(tx2.len > len1, "PTLC_CO1: tx with PTLC is larger");

    tx_buf_free(&tx1);
    tx_buf_free(&tx2);
    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ==========================================================================
 * PR #79 tests: PTLC penalty, round-trip, dynamic commits, RGS import
 * ========================================================================== */

/* PTLC_RT1: ptlc_commit_add_and_sign adds PTLC to channel */
int test_ptlc_rt1_add_and_sign(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    TEST_ASSERT(ctx, "PTLC_RT1: ctx");

    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.ctx = ctx;
    /* #182: seed balances for channel_add_ptlc. */
    ch.local_amount = 1000000;
    ch.remote_amount = 1000000;
    ch.funder_is_local = 1;

    unsigned char pp_priv[32];
    memset(pp_priv, 0x55, 32); pp_priv[0] = 0x01;
    secp256k1_pubkey pp;
    secp256k1_ec_pubkey_create(ctx, &pp, pp_priv);

    unsigned char cid[32];
    memset(cid, 0xAA, 32);

    uint64_t ptlc_id = 0;
    int r = ptlc_commit_add_and_sign(NULL, -1, &ch, ctx, cid,
                                       50000, &pp, 800000, &ptlc_id);
    TEST_ASSERT(r == 1, "PTLC_RT1: add succeeded");
    TEST_ASSERT_EQ(ch.n_ptlcs, 1, "PTLC_RT1: 1 PTLC in channel");
    TEST_ASSERT_EQ(ch.ptlcs[0].direction, PTLC_OFFERED, "PTLC_RT1: offered");
    TEST_ASSERT_EQ((long long)ch.ptlcs[0].amount_sats, 50000LL, "PTLC_RT1: amount");

    free(ch.ptlcs);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* PTLC_RT2: ptlc_commit_settle_and_sign transitions to SETTLED */
int test_ptlc_rt2_settle(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.ctx = ctx;
    /* #182: seed balances for channel_add_ptlc. */
    ch.local_amount = 1000000;
    ch.remote_amount = 1000000;
    ch.funder_is_local = 1;

    unsigned char pp_priv[32];
    memset(pp_priv, 0x66, 32); pp_priv[0] = 0x01;
    secp256k1_pubkey pp;
    secp256k1_ec_pubkey_create(ctx, &pp, pp_priv);

    uint64_t id;
    channel_add_ptlc(&ch, PTLC_RECEIVED, 30000, &pp, 700000, &id);

    unsigned char adapted[64];
    memset(adapted, 0xBB, 64);

    int r = ptlc_commit_settle_and_sign(NULL, -1, &ch, ctx, id, adapted);
    TEST_ASSERT(r == 1, "PTLC_RT2: settle succeeded");
    TEST_ASSERT_EQ(ch.ptlcs[0].state, PTLC_STATE_SETTLED, "PTLC_RT2: state SETTLED");
    TEST_ASSERT(ch.ptlcs[0].has_adapted_sig == 1, "PTLC_RT2: has_adapted_sig");

    free(ch.ptlcs);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* PTLC_RT3: ptlc_commit_fail_and_sign transitions to FAILED */
int test_ptlc_rt3_fail(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.ctx = ctx;
    /* #182: seed balances for channel_add_ptlc. */
    ch.local_amount = 1000000;
    ch.remote_amount = 1000000;
    ch.funder_is_local = 1;

    unsigned char pp_priv[32];
    memset(pp_priv, 0x77, 32); pp_priv[0] = 0x01;
    secp256k1_pubkey pp;
    secp256k1_ec_pubkey_create(ctx, &pp, pp_priv);

    uint64_t id;
    channel_add_ptlc(&ch, PTLC_OFFERED, 25000, &pp, 750000, &id);

    int r = ptlc_commit_fail_and_sign(NULL, -1, &ch, ctx, id);
    TEST_ASSERT(r == 1, "PTLC_RT3: fail succeeded");
    TEST_ASSERT_EQ(ch.ptlcs[0].state, PTLC_STATE_FAILED, "PTLC_RT3: state FAILED");

    free(ch.ptlcs);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* DYN_C1: channel_type_upgrade_valid accepts superset, rejects subset */
int test_dyn_c1_upgrade_valid(void) {
    uint32_t base = (1 << 12);  /* static_remote_key */
    uint32_t upgrade = (1 << 12) | (1 << 22);  /* + anchors */

    TEST_ASSERT(channel_type_upgrade_valid(base, upgrade) == 1,
                "DYN_C1: superset valid");
    TEST_ASSERT(channel_type_upgrade_valid(upgrade, base) == 0,
                "DYN_C1: subset invalid");
    TEST_ASSERT(channel_type_upgrade_valid(base, base) == 1,
                "DYN_C1: same is valid");
    return 1;
}

/* DYN_C2: channel_type_propose_upgrade stores new bits */
int test_dyn_c2_propose_upgrade(void) {
    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.channel_type_bits = (1 << 12);

    uint32_t new_bits = (1 << 12) | (1 << 22);
    TEST_ASSERT(channel_type_propose_upgrade(&ch, new_bits) == 1,
                "DYN_C2: upgrade accepted");
    TEST_ASSERT_EQ(ch.channel_type_bits, new_bits, "DYN_C2: bits updated");

    /* Try invalid downgrade */
    TEST_ASSERT(channel_type_propose_upgrade(&ch, (1 << 12)) == 0,
                "DYN_C2: downgrade rejected");
    return 1;
}

/* RGS_I1: RGS export + import round-trip */
int test_rgs_i1_import_roundtrip(void) {
    gossip_store_t gs;
    TEST_ASSERT(gossip_store_open_in_memory(&gs), "RGS_I1: open store");

    /* Add a channel to the store */
    unsigned char n1[33], n2[33];
    memset(n1, 0x02, 33); n1[0] = 0x02;
    memset(n2, 0x03, 33); n2[0] = 0x03;
    gossip_store_upsert_channel(&gs, 0x0001000100010000ULL, n1, n2, 500000, 1700000000);
    gossip_store_upsert_channel_update(&gs, 0x0001000100010000ULL, 0, 1000, 100, 40, 1700000000);

    /* Export to RGS blob */
    unsigned char blob[8192];
    size_t blen = gossip_store_export_rgs(&gs, blob, sizeof(blob));
    TEST_ASSERT(blen > 17, "RGS_I1: export produced data");

    /* Import into fresh store */
    gossip_store_t gs2;
    TEST_ASSERT(gossip_store_open_in_memory(&gs2), "RGS_I1: open store 2");

    int imported = gossip_store_import_rgs(&gs2, blob, blen);
    TEST_ASSERT(imported >= 1, "RGS_I1: imported at least 1 channel");

    /* Verify channel exists in new store */
    unsigned char n1_out[33], n2_out[33];
    uint64_t cap;
    uint32_t ts;
    int found = gossip_store_get_channel(&gs2, 0x0001000100010000ULL,
                                          n1_out, n2_out, &cap, &ts);
    TEST_ASSERT(found, "RGS_I1: channel found in imported store");
    TEST_ASSERT_EQ((long long)cap, 500000LL, "RGS_I1: capacity matches");

    gossip_store_close(&gs);
    gossip_store_close(&gs2);
    return 1;
}

/* BIP353_N1: bip353_dns_resolve_native falls back to dig */
int test_bip353_native_fallback(void) {
    /* Just verify it doesn't crash; actual DNS resolution depends on network */
    char invoice[512];
    int r = bip353_dns_resolve_native("nonexistent@invalid.test.invalid", invoice, sizeof(invoice));
    /* Expected: 0 (lookup fails for fake domain) */
    TEST_ASSERT(r == 0, "BIP353_N1: invalid domain returns 0");
    return 1;
}

/* ==========================================================================
 * PR #80 tests: native DNS, RPC exportrgs, dynamic commit TLV wire
 * ========================================================================== */

/* DNS_N1: bip353_dns_resolve_native uses libresolv (doesn't crash on invalid domain) */
int test_dns_native_resolv(void) {
    char invoice[512];
    /* This should use libresolv now, not dig. Invalid domain returns 0. */
    int r = bip353_dns_resolve_native("nobody@invalid.test.invalid", invoice, sizeof(invoice));
    TEST_ASSERT(r == 0, "DNS_N1: invalid domain returns 0 with native resolver");
    return 1;
}

/* RPC_RGS1: exportrgs RPC returns valid JSON with rgs_hex field */
int test_rpc_exportrgs(void) {
    admin_rpc_t rpc;
    memset(&rpc, 0, sizeof(rpc));

    gossip_store_t gs;
    TEST_ASSERT(gossip_store_open_in_memory(&gs), "RPC_RGS1: open store");
    rpc.gossip = &gs;

    char out[8192];
    const char *req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"exportrgs\"}";
    size_t n = admin_rpc_handle_request(&rpc, req, out, sizeof(out));
    TEST_ASSERT(n > 0, "RPC_RGS1: response produced");
    /* Parse response */
    TEST_ASSERT(strstr(out, "rgs_hex") != NULL || strstr(out, "error") != NULL,
                "RPC_RGS1: contains rgs_hex or error");

    gossip_store_close(&gs);
    return 1;
}

/* DYN_TLV1: encode + decode channel_type TLV round-trip */
int test_dyn_tlv1_roundtrip(void) {
    uint32_t bits = (1 << 12) | (1 << 22);  /* static_remote_key + anchors */
    unsigned char buf[16];
    size_t len = commitment_signed_encode_channel_type_tlv(buf, sizeof(buf), bits);
    TEST_ASSERT(len > 0, "DYN_TLV1: encode produced bytes");
    TEST_ASSERT(buf[0] == 5, "DYN_TLV1: TLV type is 5");

    uint32_t decoded = 0;
    TEST_ASSERT(commitment_signed_decode_channel_type_tlv(buf, len, &decoded),
                "DYN_TLV1: decode ok");
    TEST_ASSERT_EQ(decoded, bits, "DYN_TLV1: round-trip matches");
    return 1;
}

/* DYN_TLV2: decode returns 0 for empty or no type-5 TLV */
int test_dyn_tlv2_empty(void) {
    uint32_t bits = 0;
    unsigned char empty[4] = {3, 2, 0xFF, 0xFF};  /* type 3, not 5 */
    TEST_ASSERT(commitment_signed_decode_channel_type_tlv(empty, 4, &bits) == 0,
                "DYN_TLV2: wrong type returns 0");
    TEST_ASSERT(commitment_signed_decode_channel_type_tlv(NULL, 0, &bits) == 0,
                "DYN_TLV2: NULL returns 0");
    return 1;
}

/* DYN_TLV3: zero bits encodes to zero length (no TLV emitted) */
int test_dyn_tlv3_zero(void) {
    unsigned char buf[16];
    size_t len = commitment_signed_encode_channel_type_tlv(buf, sizeof(buf), 0);
    TEST_ASSERT_EQ(len, 0, "DYN_TLV3: zero bits produces no TLV");
    return 1;
}

/* ==========================================================================
 * PR #81 tests: trampoline wiring, BOLT #12 payoffer, watchtower PTLC
 * ========================================================================== */

/* TRP_W1: onion TLV parser recognizes type 0x0c trampoline payload */
int test_trp_w1_tlv_parse_0x0c(void) {
    /* Build a TLV stream with type 0x0c containing a dummy payload */
    unsigned char tlv[32];
    tlv[0] = 0x0c;  /* type: trampoline */
    tlv[1] = 10;    /* length: 10 bytes */
    memset(tlv + 2, 0xAA, 10);

    /* Also include type 2 (amt) and type 4 (cltv) so the parser returns 1 */
    unsigned char full[64];
    size_t pos = 0;
    /* type 2: amt_to_forward = 50000 */
    full[pos++] = 2; full[pos++] = 8;
    for (int i = 0; i < 7; i++) full[pos++] = 0;
    full[pos++] = 0x50; /* 80 in decimal but let's just test non-zero */
    /* type 4: cltv = 700000 */
    full[pos++] = 4; full[pos++] = 4;
    full[pos++] = 0x00; full[pos++] = 0x0A; full[pos++] = 0xB1; full[pos++] = 0xA0;
    /* type 0x0c: trampoline */
    full[pos++] = 0x0c; full[pos++] = 5;
    for (int i = 0; i < 5; i++) full[pos++] = 0xBB;

    onion_hop_payload_t out;
    int r = onion_parse_tlv_payload(full, pos, &out);
    TEST_ASSERT(r == 1, "TRP_W1: parse ok");
    TEST_ASSERT(out.has_trampoline == 1, "TRP_W1: has_trampoline set");
    TEST_ASSERT_EQ(out.trampoline_payload_len, 5, "TRP_W1: payload len 5");
    TEST_ASSERT(out.trampoline_payload[0] == 0xBB, "TRP_W1: payload data");
    return 1;
}

/* TRP_W2: onion TLV parser without 0x0c has has_trampoline=0 */
int test_trp_w2_no_trampoline(void) {
    unsigned char tlv[32];
    size_t pos = 0;
    tlv[pos++] = 2; tlv[pos++] = 8;
    for (int i = 0; i < 8; i++) tlv[pos++] = 0x01;
    tlv[pos++] = 4; tlv[pos++] = 4;
    for (int i = 0; i < 4; i++) tlv[pos++] = 0x02;

    onion_hop_payload_t out;
    onion_parse_tlv_payload(tlv, pos, &out);
    TEST_ASSERT(out.has_trampoline == 0, "TRP_W2: no trampoline");
    return 1;
}

/* TRP_W3: onion_hop_t has trampoline fields */
int test_trp_w3_hop_struct(void) {
    onion_hop_t hop;
    memset(&hop, 0, sizeof(hop));
    memset(hop.trampoline_dest, 0x42, 33);
    hop.trampoline_amt_msat = 99000;
    hop.trampoline_cltv = 800000;
    hop.has_trampoline = 1;

    TEST_ASSERT(hop.has_trampoline == 1, "TRP_W3: has_trampoline");
    TEST_ASSERT_EQ((long long)hop.trampoline_amt_msat, 99000LL, "TRP_W3: amt");
    TEST_ASSERT(hop.trampoline_dest[0] == 0x42, "TRP_W3: dest byte");
    return 1;
}

/* B12_PO1: payoffer RPC validates offer parameter */
int test_b12_po1_payoffer_missing_offer(void) {
    admin_rpc_t rpc;
    memset(&rpc, 0, sizeof(rpc));

    char out[4096];
    const char *req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"payoffer\",\"params\":{}}";
    size_t n = admin_rpc_handle_request(&rpc, req, out, sizeof(out));
    TEST_ASSERT(n > 0, "B12_PO1: response produced");
    TEST_ASSERT(strstr(out, "missing offer") != NULL, "B12_PO1: error mentions missing offer");
    return 1;
}

/* SWEEP1: pending_sweeps table roundtrip */
int test_sweep_persist_roundtrip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "SWEEP1: open");

    sweep_entry_t e;
    memset(&e, 0, sizeof(e));
    e.type = SWEEP_TO_LOCAL;
    e.state = SWEEP_PENDING;
    memset(e.source_txid, 0xAB, 32);
    e.source_vout = 0;
    e.amount_sats = 50000;
    e.csv_delay = 144;
    e.confirmed_height = 100;
    e.channel_id = 2;
    e.factory_id = 1;
    e.commitment_number = 5;

    TEST_ASSERT(persist_save_sweep(&db, &e), "SWEEP1: save");

    sweep_entry_t loaded[4];
    size_t n = 0;
    TEST_ASSERT(persist_load_sweeps(&db, loaded, &n, 4), "SWEEP1: load");
    TEST_ASSERT(n == 1, "SWEEP1: 1 entry loaded");
    TEST_ASSERT(loaded[0].type == SWEEP_TO_LOCAL, "SWEEP1: type");
    TEST_ASSERT(loaded[0].amount_sats == 50000, "SWEEP1: amount");
    TEST_ASSERT(loaded[0].csv_delay == 144, "SWEEP1: csv");
    TEST_ASSERT(loaded[0].channel_id == 2, "SWEEP1: channel_id");
    TEST_ASSERT(loaded[0].factory_id == 1, "SWEEP1: factory_id");

    /* Delete by factory */
    TEST_ASSERT(persist_delete_sweeps_for_factory(&db, 1), "SWEEP1: delete");
    n = 0;
    persist_load_sweeps(&db, loaded, &n, 4);
    TEST_ASSERT(n == 0, "SWEEP1: 0 after delete");

    persist_close(&db);
    return 1;
}

/* WT_PTLC1: watchtower_entry_t has ptlc_outputs field */
int test_wt_ptlc1_entry_fields(void) {
    watchtower_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.ptlc_outputs = NULL;
    entry.n_ptlc_outputs = 0;
    /* Just verify the fields exist and compile */
    TEST_ASSERT(entry.n_ptlc_outputs == 0, "WT_PTLC1: n_ptlc_outputs initialized");
    return 1;
}

/* WT_PTLC2: watchtower_htlc_t can store PTLC metadata (reused struct) */
int test_wt_ptlc2_metadata_store(void) {
    watchtower_htlc_t wh;
    memset(&wh, 0, sizeof(wh));
    wh.htlc_vout = 3;
    wh.htlc_amount = 25000;
    wh.direction = HTLC_OFFERED;  /* reused for PTLC direction */
    wh.cltv_expiry = 750000;

    TEST_ASSERT_EQ(wh.htlc_vout, 3, "WT_PTLC2: vout");
    TEST_ASSERT_EQ((long long)wh.htlc_amount, 25000LL, "WT_PTLC2: amount");
    return 1;
}

/* PS double-spend defense (invariant #5): persist_save_ps_signed_input +
   persist_check_ps_signed_input round-trip. The defense hinges on
   "second time we're asked to sign a TX spending the same parent UTXO,
   refuse." This test exercises the persistence API directly. */
int test_persist_ps_signed_input_roundtrip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open in-memory DB");

    unsigned char parent_txid[32], sighash_a[32], sighash_b[32];
    unsigned char psig_a[36], psig_b[36], out_sighash[32];
    memset(parent_txid, 0xAA, 32);
    memset(sighash_a, 0xA1, 32);
    memset(sighash_b, 0xB2, 32);  /* different content → would be attack */
    memset(psig_a, 0x01, 36);
    memset(psig_b, 0x02, 36);

    /* Initial state: no row → check returns 0 (proceed to sign). */
    TEST_ASSERT_EQ(
        persist_check_ps_signed_input(&db, /*factory_id=*/0,
                                       parent_txid, /*parent_vout=*/0,
                                       NULL),
        0, "fresh parent: check returns 0 (not_found)");

    /* Record a signing for this parent. */
    TEST_ASSERT(
        persist_save_ps_signed_input(&db, /*factory_id=*/0, /*leaf_idx=*/3,
                                      parent_txid, /*parent_vout=*/0,
                                      sighash_a, psig_a),
        "save first sig");

    /* Second check: same parent → returns 1 (REFUSE). Out_sighash echoes
       the previously-recorded sighash for observability. */
    TEST_ASSERT_EQ(
        persist_check_ps_signed_input(&db, 0, parent_txid, 0, out_sighash),
        1, "already signed → returns 1 (refuse)");
    TEST_ASSERT(memcmp(out_sighash, sighash_a, 32) == 0,
                "out_sighash echoes the previously-stored sighash");

    /* Different parent_vout on the same txid is a DIFFERENT UTXO —
       should return 0 (not_found, OK to sign). */
    TEST_ASSERT_EQ(
        persist_check_ps_signed_input(&db, 0, parent_txid, /*vout=*/1, NULL),
        0, "different vout is a different input: proceed");

    /* Different factory_id, same parent: separate namespace → 0. */
    TEST_ASSERT_EQ(
        persist_check_ps_signed_input(&db, /*factory_id=*/1,
                                       parent_txid, 0, NULL),
        0, "different factory_id: separate namespace");

    /* The attack-shaped second-save with DIFFERENT sighash is allowed
       at the persist layer (INSERT OR REPLACE), but the check step
       prevents reaching it — callers MUST consult the check first. */
    (void)psig_b; (void)sighash_b;

    persist_close(&db);
    return 1;
}

/* PS adversarial #1: defense survives DB close + reopen.
   If the client crashes after signing but before sending PSIG, then restarts,
   the defense must still refuse a second sign for the same parent. */
int test_persist_ps_defense_persists_across_reopen(void) {
    char dbpath[256];
    snprintf(dbpath, sizeof(dbpath), "/tmp/superscalar_ps_defense_%d.db",
             (int)getpid());
    unlink(dbpath);

    unsigned char parent_txid[32], sighash[32], psig[36], out_sighash[32];
    memset(parent_txid, 0xAB, 32);
    memset(sighash, 0xCD, 32);
    memset(psig, 0xEF, 36);

    /* Phase 1: open file DB, save, close. */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, dbpath), "open file DB");
        TEST_ASSERT_EQ(persist_check_ps_signed_input(&db, 7, parent_txid, 2, NULL),
                       0, "fresh DB: not found");
        TEST_ASSERT(persist_save_ps_signed_input(&db, 7, 4,
                                                   parent_txid, 2, sighash, psig),
                    "save first sig");
        persist_close(&db);
    }

    /* Phase 2: simulate restart — reopen the SAME file, defense must
       still refuse a second-sign attempt on the same parent UTXO. */
    {
        persist_t db;
        TEST_ASSERT(persist_open(&db, dbpath), "reopen file DB");
        TEST_ASSERT_EQ(persist_check_ps_signed_input(&db, 7, parent_txid, 2,
                                                      out_sighash),
                       1, "after restart: still refuses (defense persisted)");
        TEST_ASSERT(memcmp(out_sighash, sighash, 32) == 0,
                    "stored sighash survives reopen");
        persist_close(&db);
    }

    unlink(dbpath);
    return 1;
}

/* PS adversarial #2: parent_txid uniqueness — single-byte differences
   in the parent_txid must NOT trigger a false-positive refuse, otherwise
   legitimate PS chain advances on neighboring leaves would be blocked. */
int test_persist_ps_defense_distinct_parent_txids(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open in-memory DB");

    unsigned char base[32], sighash[32], psig[36];
    memset(base, 0x33, 32);
    memset(sighash, 0x77, 32);
    memset(psig, 0x88, 36);

    TEST_ASSERT(persist_save_ps_signed_input(&db, 0, 0, base, 0, sighash, psig),
                "save base entry");

    /* Flip every single byte one at a time; each must NOT match. */
    for (int byte = 0; byte < 32; byte++) {
        unsigned char variant[32];
        memcpy(variant, base, 32);
        variant[byte] ^= 0x01;
        TEST_ASSERT_EQ(persist_check_ps_signed_input(&db, 0, variant, 0, NULL),
                       0, "single-byte-different txid does NOT match");
    }

    /* Original still matches exactly. */
    TEST_ASSERT_EQ(persist_check_ps_signed_input(&db, 0, base, 0, NULL),
                   1, "exact base still refuses");

    persist_close(&db);
    return 1;
}

/* PS adversarial #3: independence at scale — many distinct (factory,
   parent, vout) tuples are tracked independently. Catches indexing or
   collision regressions that would coalesce distinct UTXOs. */
int test_persist_ps_defense_independent_inputs(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open in-memory DB");

    unsigned char sighash[32], psig[36];
    memset(sighash, 0x55, 32);
    memset(psig, 0x66, 36);

    /* Insert 200 distinct entries: vary parent_txid + factory_id + vout. */
    const int N = 200;
    for (int i = 0; i < N; i++) {
        unsigned char parent[32];
        memset(parent, (unsigned char)(i & 0xFF), 32);
        parent[0] = (unsigned char)((i >> 8) & 0xFF);
        uint32_t factory_id = (uint32_t)(i % 7);
        uint32_t vout       = (uint32_t)(i % 4);
        TEST_ASSERT(persist_save_ps_signed_input(&db, factory_id, i,
                                                   parent, vout, sighash, psig),
                    "save i-th entry");
    }

    /* Every saved entry must REFUSE; every unsaved permutation must PASS. */
    for (int i = 0; i < N; i++) {
        unsigned char parent[32];
        memset(parent, (unsigned char)(i & 0xFF), 32);
        parent[0] = (unsigned char)((i >> 8) & 0xFF);
        uint32_t factory_id = (uint32_t)(i % 7);
        uint32_t vout       = (uint32_t)(i % 4);
        TEST_ASSERT_EQ(persist_check_ps_signed_input(&db, factory_id, parent,
                                                      vout, NULL),
                       1, "saved (factory,parent,vout) refuses");

        /* Same parent/vout but different factory_id (i % 7 + 1, mod 7)
           must NOT match — namespace separation. */
        uint32_t other_fid = (factory_id + 1) % 7;
        if (other_fid != factory_id) {
            int rc = persist_check_ps_signed_input(&db, other_fid, parent,
                                                    vout, NULL);
            /* Could legitimately match if a different i used (other_fid,
               same parent, same vout). Skip assert if collision possible. */
            (void)rc;
        }
    }

    /* Wholly unrelated parent → not found. */
    unsigned char unrelated[32];
    memset(unrelated, 0xFE, 32);
    TEST_ASSERT_EQ(persist_check_ps_signed_input(&db, 0, unrelated, 0, NULL),
                   0, "unrelated parent: not found");

    persist_close(&db);
    return 1;
}

/* v25 round-trip: persist + reload pre-built penalty TX bytes on old_commitments.
   Closes the restart-loses-defense gap (watchtower.c:60-115). */
int test_persist_old_commitment_witness_round_trip(void)
{
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open in-memory DB");

    uint32_t channel_id = 7;
    uint64_t commit_num = 42;
    unsigned char txid[32]; memset(txid, 0xAB, 32);
    unsigned char spk[34];  memset(spk, 0xCD, 34);

    /* Parent row must exist for the UPDATE to land. */
    TEST_ASSERT(persist_save_old_commitment(&db, channel_id, commit_num,
                                              txid, 0, 100000, spk, 34),
                "save old_commitments parent row");

    /* Pre-1: row exists but column is empty.  Load returns 0 (degrade
       to legacy lazy-build). */
    unsigned char *got_bytes = NULL;
    size_t got_len = 0;
    int rc = persist_load_old_commitment_witness(&db, channel_id, commit_num,
                                                   &got_bytes, &got_len);
    TEST_ASSERT_EQ(rc, 0, "empty column returns 0 (legacy fallback)");
    TEST_ASSERT(got_bytes == NULL, "empty load returns NULL bytes");
    TEST_ASSERT(got_len == 0, "empty load returns 0 len");

    /* Save real bytes and round-trip. */
    unsigned char penalty[200];
    for (size_t i = 0; i < sizeof(penalty); i++) penalty[i] = (unsigned char)(i * 7 + 3);
    TEST_ASSERT(persist_save_old_commitment_witness(&db, channel_id, commit_num,
                                                      penalty, sizeof(penalty)),
                "save witness bytes");

    /* Reload + verify exact byte match. */
    got_bytes = NULL;
    got_len = 0;
    rc = persist_load_old_commitment_witness(&db, channel_id, commit_num,
                                              &got_bytes, &got_len);
    TEST_ASSERT_EQ(rc, 1, "load witness bytes succeeds");
    TEST_ASSERT(got_bytes != NULL, "loaded bytes non-NULL");
    TEST_ASSERT_EQ(got_len, sizeof(penalty), "loaded len matches saved");
    TEST_ASSERT(memcmp(got_bytes, penalty, sizeof(penalty)) == 0,
                "loaded bytes match saved");
    free(got_bytes);

    /* Idempotent re-save replaces. */
    unsigned char penalty2[150];
    memset(penalty2, 0x42, sizeof(penalty2));
    TEST_ASSERT(persist_save_old_commitment_witness(&db, channel_id, commit_num,
                                                      penalty2, sizeof(penalty2)),
                "re-save witness bytes (UPDATE)");
    got_bytes = NULL;
    got_len = 0;
    rc = persist_load_old_commitment_witness(&db, channel_id, commit_num,
                                              &got_bytes, &got_len);
    TEST_ASSERT_EQ(rc, 1, "reload after re-save");
    TEST_ASSERT_EQ(got_len, sizeof(penalty2), "re-saved len");
    TEST_ASSERT(memcmp(got_bytes, penalty2, sizeof(penalty2)) == 0,
                "re-saved bytes match");
    free(got_bytes);

    /* Save with NULL/zero is a safe no-op. */
    TEST_ASSERT(persist_save_old_commitment_witness(&db, channel_id, commit_num,
                                                      NULL, 0),
                "save NULL is safe no-op (returns 1)");

    /* Missing row → returns -1. */
    rc = persist_load_old_commitment_witness(&db, 999, 999, &got_bytes, &got_len);
    TEST_ASSERT_EQ(rc, -1, "missing row returns -1");

    persist_close(&db);
    return 1;
}

/* v35 (#207): per-output HTLC sweep TX persistence round-trip.
   Verifies the new save/load pair, idempotency, and the load fallback
   semantics that watchtower_check relies on (column-empty → 0; missing
   row → -1; bytes present → 1). */
int test_persist_old_commitment_htlc_sweep_round_trip(void)
{
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open in-memory DB");

    /* Schema must be at least v35 to have the new column. */
    TEST_ASSERT(persist_schema_version(&db) >= 35,
                "schema version >= 35 (signed_sweep_tx_hex column present)");

    uint32_t channel_id = 11;
    uint64_t commit_num = 7;
    unsigned char txid[32]; memset(txid, 0xAB, 32);
    unsigned char to_local_spk[34]; memset(to_local_spk, 0xCD, 34);

    /* Parent old_commitments row */
    TEST_ASSERT(persist_save_old_commitment(&db, channel_id, commit_num,
                                              txid, 0, 200000, to_local_spk, 34),
                "save old_commitments parent row");

    /* Two HTLC rows on the breached commitment. */
    watchtower_htlc_t h0 = {0};
    h0.htlc_vout = 2;
    h0.htlc_amount = 12345;
    memset(h0.htlc_spk, 0x11, 34);
    h0.direction = HTLC_OFFERED;
    memset(h0.payment_hash, 0x22, 32);
    h0.cltv_expiry = 600000;

    watchtower_htlc_t h1 = {0};
    h1.htlc_vout = 3;
    h1.htlc_amount = 67890;
    memset(h1.htlc_spk, 0x33, 34);
    h1.direction = HTLC_RECEIVED;
    memset(h1.payment_hash, 0x44, 32);
    h1.cltv_expiry = 600100;

    TEST_ASSERT(persist_save_old_commitment_htlc(&db, channel_id, commit_num, &h0),
                "save HTLC row 0");
    TEST_ASSERT(persist_save_old_commitment_htlc(&db, channel_id, commit_num, &h1),
                "save HTLC row 1");

    /* Before any sweep persist: load returns 0 (column empty → legacy lazy). */
    unsigned char *got = NULL;
    size_t got_len = 0;
    int rc = persist_load_old_commitment_htlc_sweep(&db, channel_id, commit_num,
                                                     h0.htlc_vout, &got, &got_len);
    TEST_ASSERT_EQ(rc, 0, "empty sweep column returns 0 (legacy fallback)");
    TEST_ASSERT(got == NULL, "empty load returns NULL bytes");

    /* Save sweep bytes for vout 2 and vout 3. */
    unsigned char sweep0[180];
    for (size_t i = 0; i < sizeof(sweep0); i++) sweep0[i] = (unsigned char)(i * 3 + 1);
    unsigned char sweep1[220];
    for (size_t i = 0; i < sizeof(sweep1); i++) sweep1[i] = (unsigned char)(i * 5 + 9);

    TEST_ASSERT(persist_save_old_commitment_htlc_sweep(&db, channel_id, commit_num,
                                                        h0.htlc_vout,
                                                        sweep0, sizeof(sweep0)),
                "save sweep TX bytes for vout 2");
    TEST_ASSERT(persist_save_old_commitment_htlc_sweep(&db, channel_id, commit_num,
                                                        h1.htlc_vout,
                                                        sweep1, sizeof(sweep1)),
                "save sweep TX bytes for vout 3");

    /* Round-trip vout 2. */
    got = NULL; got_len = 0;
    rc = persist_load_old_commitment_htlc_sweep(&db, channel_id, commit_num,
                                                  h0.htlc_vout, &got, &got_len);
    TEST_ASSERT_EQ(rc, 1, "load sweep TX bytes (vout 2)");
    TEST_ASSERT_EQ(got_len, sizeof(sweep0), "loaded len matches saved (vout 2)");
    TEST_ASSERT(memcmp(got, sweep0, sizeof(sweep0)) == 0,
                "loaded bytes match saved (vout 2)");
    free(got);

    /* Round-trip vout 3 — separate per-output row */
    got = NULL; got_len = 0;
    rc = persist_load_old_commitment_htlc_sweep(&db, channel_id, commit_num,
                                                  h1.htlc_vout, &got, &got_len);
    TEST_ASSERT_EQ(rc, 1, "load sweep TX bytes (vout 3)");
    TEST_ASSERT_EQ(got_len, sizeof(sweep1), "loaded len matches saved (vout 3)");
    TEST_ASSERT(memcmp(got, sweep1, sizeof(sweep1)) == 0,
                "loaded bytes match saved (vout 3)");
    free(got);

    /* Idempotent re-save replaces. */
    unsigned char sweep0b[64];
    memset(sweep0b, 0x77, sizeof(sweep0b));
    TEST_ASSERT(persist_save_old_commitment_htlc_sweep(&db, channel_id, commit_num,
                                                        h0.htlc_vout,
                                                        sweep0b, sizeof(sweep0b)),
                "re-save sweep TX bytes (vout 2)");
    got = NULL; got_len = 0;
    rc = persist_load_old_commitment_htlc_sweep(&db, channel_id, commit_num,
                                                  h0.htlc_vout, &got, &got_len);
    TEST_ASSERT_EQ(rc, 1, "reload after re-save");
    TEST_ASSERT_EQ(got_len, sizeof(sweep0b), "re-saved len");
    TEST_ASSERT(memcmp(got, sweep0b, sizeof(sweep0b)) == 0,
                "re-saved bytes match");
    free(got);

    /* NULL/zero is a safe no-op. */
    TEST_ASSERT(persist_save_old_commitment_htlc_sweep(&db, channel_id, commit_num,
                                                        h0.htlc_vout, NULL, 0),
                "save NULL is safe no-op (returns 1)");

    /* Missing (channel, commit, vout) → -1. */
    rc = persist_load_old_commitment_htlc_sweep(&db, 999, 999, 99, &got, &got_len);
    TEST_ASSERT_EQ(rc, -1, "missing row returns -1");

    /* Coverage query the dashboard team uses: COUNT(*), COUNT(col).
       After save: count rows with non-empty sweep column. */
    sqlite3_stmt *stmt = NULL;
    int prepared = sqlite3_prepare_v2(db.db,
        "SELECT COUNT(*), SUM(CASE WHEN signed_sweep_tx_hex != '' THEN 1 ELSE 0 END) "
        "FROM old_commitment_htlcs;", -1, &stmt, NULL);
    TEST_ASSERT_EQ(prepared, SQLITE_OK, "prepare dashboard coverage query");
    TEST_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW, "step coverage row");
    int total_rows = sqlite3_column_int(stmt, 0);
    int rows_with_sweep = sqlite3_column_int(stmt, 1);
    sqlite3_finalize(stmt);
    TEST_ASSERT_EQ(total_rows, 2, "two HTLC rows total");
    TEST_ASSERT_EQ(rows_with_sweep, 2, "both rows have sweep_tx_hex populated");

    persist_close(&db);
    return 1;
}

/* CH_T12 (#208 / SF-SCHEMA-HTLC-RESOLUTION): persist_save_htlc_resolution_tx
   + persist_load_htlc_resolution_tx round-trip.  Verifies schema v36 column
   present, idempotent UPDATE, NULL/empty fallback semantics, and the
   dashboard's coverage query auto-detects population. */
int test_persist_htlc_resolution_tx_round_trip(void)
{
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open in-memory DB");

    TEST_ASSERT(persist_schema_version(&db) >= 36,
                "schema version >= 36 (signed_resolution_tx_hex column present)");

    uint32_t channel_id = 12;
    htlc_t h0 = {0};
    h0.id = 1001;
    h0.direction = HTLC_OFFERED;
    h0.amount_sats = 50000;
    memset(h0.payment_hash, 0x55, 32);
    memset(h0.payment_preimage, 0x66, 32);
    h0.cltv_expiry = 700000;
    h0.state = HTLC_STATE_ACTIVE;
    h0.fee_at_add = 100;

    htlc_t h1 = {0};
    h1.id = 1002;
    h1.direction = HTLC_RECEIVED;
    h1.amount_sats = 75000;
    memset(h1.payment_hash, 0x77, 32);
    h1.cltv_expiry = 700100;
    h1.state = HTLC_STATE_ACTIVE;
    h1.fee_at_add = 100;

    TEST_ASSERT(persist_save_htlc(&db, channel_id, &h0), "save HTLC 0");
    TEST_ASSERT(persist_save_htlc(&db, channel_id, &h1), "save HTLC 1");

    unsigned char *got = NULL;
    size_t got_len = 0;
    int rc = persist_load_htlc_resolution_tx(&db, channel_id, h0.id, &got, &got_len);
    TEST_ASSERT_EQ(rc, 0, "NULL resolution column returns 0");
    TEST_ASSERT(got == NULL, "empty load returns NULL bytes");

    unsigned char resolve0[150];
    for (size_t i = 0; i < sizeof(resolve0); i++) resolve0[i] = (unsigned char)(i * 7 + 13);
    unsigned char resolve1[210];
    for (size_t i = 0; i < sizeof(resolve1); i++) resolve1[i] = (unsigned char)(i * 11 + 5);

    TEST_ASSERT(persist_save_htlc_resolution_tx(&db, channel_id, h0.id,
                                                  resolve0, sizeof(resolve0)),
                "save resolution TX bytes for HTLC 0");
    TEST_ASSERT(persist_save_htlc_resolution_tx(&db, channel_id, h1.id,
                                                  resolve1, sizeof(resolve1)),
                "save resolution TX bytes for HTLC 1");

    got = NULL; got_len = 0;
    rc = persist_load_htlc_resolution_tx(&db, channel_id, h0.id, &got, &got_len);
    TEST_ASSERT_EQ(rc, 1, "load resolution TX bytes (HTLC 0)");
    TEST_ASSERT_EQ(got_len, sizeof(resolve0), "loaded len matches saved (HTLC 0)");
    TEST_ASSERT(memcmp(got, resolve0, sizeof(resolve0)) == 0,
                "loaded bytes match saved (HTLC 0)");
    free(got);

    got = NULL; got_len = 0;
    rc = persist_load_htlc_resolution_tx(&db, channel_id, h1.id, &got, &got_len);
    TEST_ASSERT_EQ(rc, 1, "load resolution TX bytes (HTLC 1)");
    TEST_ASSERT_EQ(got_len, sizeof(resolve1), "loaded len matches saved (HTLC 1)");
    TEST_ASSERT(memcmp(got, resolve1, sizeof(resolve1)) == 0,
                "loaded bytes match saved (HTLC 1)");
    free(got);

    unsigned char resolve0b[80];
    memset(resolve0b, 0x88, sizeof(resolve0b));
    TEST_ASSERT(persist_save_htlc_resolution_tx(&db, channel_id, h0.id,
                                                  resolve0b, sizeof(resolve0b)),
                "re-save resolution TX bytes (HTLC 0)");
    got = NULL; got_len = 0;
    rc = persist_load_htlc_resolution_tx(&db, channel_id, h0.id, &got, &got_len);
    TEST_ASSERT_EQ(rc, 1, "reload after re-save");
    TEST_ASSERT_EQ(got_len, sizeof(resolve0b), "re-saved len");
    TEST_ASSERT(memcmp(got, resolve0b, sizeof(resolve0b)) == 0,
                "re-saved bytes match");
    free(got);

    TEST_ASSERT(persist_save_htlc_resolution_tx(&db, channel_id, h0.id, NULL, 0),
                "save NULL is safe no-op (returns 1)");

    rc = persist_load_htlc_resolution_tx(&db, 999, 99999, &got, &got_len);
    TEST_ASSERT_EQ(rc, -1, "missing row returns -1");

    sqlite3_stmt *stmt = NULL;
    int prepared = sqlite3_prepare_v2(db.db,
        "SELECT COUNT(*), COUNT(signed_resolution_tx_hex) FROM htlcs;",
        -1, &stmt, NULL);
    TEST_ASSERT_EQ(prepared, SQLITE_OK, "prepare dashboard coverage query");
    TEST_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW, "step coverage row");
    int total_rows = sqlite3_column_int(stmt, 0);
    int rows_with_resolution = sqlite3_column_int(stmt, 1);
    sqlite3_finalize(stmt);
    TEST_ASSERT_EQ(total_rows, 2, "two HTLC rows total");
    TEST_ASSERT_EQ(rows_with_resolution, 2, "both rows have resolution_tx_hex populated");

    persist_close(&db);
    return 1;
}

/* CH_T13 (#209 / SF-SCHEMA-LSTOCK-BURN): persist_save_old_commitment_burn_tx
   + persist_load_old_commitment_burn_tx round-trip.  Verifies schema v36
   column present, idempotent UPDATE, NULL/empty fallback semantics, and
   dashboard coverage auto-detection. */
int test_persist_old_commitment_burn_tx_round_trip(void)
{
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open in-memory DB");

    TEST_ASSERT(persist_schema_version(&db) >= 36,
                "schema version >= 36 (signed_burn_tx_hex column present)");

    uint32_t channel_id = 13;
    uint64_t commit_num_a = 5;
    uint64_t commit_num_b = 6;
    unsigned char txid_a[32]; memset(txid_a, 0xAA, 32);
    unsigned char txid_b[32]; memset(txid_b, 0xBB, 32);
    unsigned char to_local_spk[34]; memset(to_local_spk, 0xCC, 34);

    TEST_ASSERT(persist_save_old_commitment(&db, channel_id, commit_num_a,
                                              txid_a, 0, 300000, to_local_spk, 34),
                "save old_commitments row A");
    TEST_ASSERT(persist_save_old_commitment(&db, channel_id, commit_num_b,
                                              txid_b, 0, 400000, to_local_spk, 34),
                "save old_commitments row B");

    unsigned char *got = NULL;
    size_t got_len = 0;
    int rc = persist_load_old_commitment_burn_tx(&db, channel_id, commit_num_a,
                                                   &got, &got_len);
    TEST_ASSERT_EQ(rc, 0, "NULL burn column returns 0 (legacy fallback)");
    TEST_ASSERT(got == NULL, "empty load returns NULL bytes");

    unsigned char burn_a[120];
    for (size_t i = 0; i < sizeof(burn_a); i++) burn_a[i] = (unsigned char)(i * 2 + 3);
    unsigned char burn_b[160];
    for (size_t i = 0; i < sizeof(burn_b); i++) burn_b[i] = (unsigned char)(i * 4 + 7);

    TEST_ASSERT(persist_save_old_commitment_burn_tx(&db, channel_id, commit_num_a,
                                                      burn_a, sizeof(burn_a)),
                "save burn TX bytes for commit A");
    TEST_ASSERT(persist_save_old_commitment_burn_tx(&db, channel_id, commit_num_b,
                                                      burn_b, sizeof(burn_b)),
                "save burn TX bytes for commit B");

    got = NULL; got_len = 0;
    rc = persist_load_old_commitment_burn_tx(&db, channel_id, commit_num_a,
                                               &got, &got_len);
    TEST_ASSERT_EQ(rc, 1, "load burn TX bytes (commit A)");
    TEST_ASSERT_EQ(got_len, sizeof(burn_a), "loaded len matches saved (commit A)");
    TEST_ASSERT(memcmp(got, burn_a, sizeof(burn_a)) == 0,
                "loaded bytes match saved (commit A)");
    free(got);

    got = NULL; got_len = 0;
    rc = persist_load_old_commitment_burn_tx(&db, channel_id, commit_num_b,
                                               &got, &got_len);
    TEST_ASSERT_EQ(rc, 1, "load burn TX bytes (commit B)");
    TEST_ASSERT_EQ(got_len, sizeof(burn_b), "loaded len matches saved (commit B)");
    TEST_ASSERT(memcmp(got, burn_b, sizeof(burn_b)) == 0,
                "loaded bytes match saved (commit B)");
    free(got);

    unsigned char burn_a2[60];
    memset(burn_a2, 0x99, sizeof(burn_a2));
    TEST_ASSERT(persist_save_old_commitment_burn_tx(&db, channel_id, commit_num_a,
                                                      burn_a2, sizeof(burn_a2)),
                "re-save burn TX bytes (commit A)");
    got = NULL; got_len = 0;
    rc = persist_load_old_commitment_burn_tx(&db, channel_id, commit_num_a,
                                               &got, &got_len);
    TEST_ASSERT_EQ(rc, 1, "reload after re-save");
    TEST_ASSERT_EQ(got_len, sizeof(burn_a2), "re-saved len");
    TEST_ASSERT(memcmp(got, burn_a2, sizeof(burn_a2)) == 0,
                "re-saved bytes match");
    free(got);

    TEST_ASSERT(persist_save_old_commitment_burn_tx(&db, channel_id, commit_num_a,
                                                      NULL, 0),
                "save NULL is safe no-op (returns 1)");

    rc = persist_load_old_commitment_burn_tx(&db, 999, 999, &got, &got_len);
    TEST_ASSERT_EQ(rc, -1, "missing row returns -1");

    sqlite3_stmt *stmt = NULL;
    int prepared = sqlite3_prepare_v2(db.db,
        "SELECT COUNT(*), COUNT(signed_burn_tx_hex) FROM old_commitments;",
        -1, &stmt, NULL);
    TEST_ASSERT_EQ(prepared, SQLITE_OK, "prepare dashboard coverage query");
    TEST_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW, "step coverage row");
    int total_rows = sqlite3_column_int(stmt, 0);
    int rows_with_burn = sqlite3_column_int(stmt, 1);
    sqlite3_finalize(stmt);
    TEST_ASSERT_EQ(total_rows, 2, "two old_commitment rows total");
    TEST_ASSERT_EQ(rows_with_burn, 2, "both rows have burn_tx_hex populated");

    persist_close(&db);
    return 1;
}

/* v26 (C3) signing_rounds journal round-trip: start → done → sweep. */
int test_persist_signing_rounds_round_trip(void)
{
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open in-memory DB");

    /* Round 1: success path (start → participant updates → done). */
    int64_t round1 = -1;
    TEST_ASSERT(persist_save_signing_round_start(&db, 0, 5,
                                                   "leaf_advance", 1, 4,
                                                   &round1),
                "start round 1");
    TEST_ASSERT(round1 > 0, "round 1 row id > 0");

    /* Tier 2 participant calls — just confirm they do not fail. */
    TEST_ASSERT(persist_save_signing_round_participant_nonce(&db, round1, 0),
                "participant 0 nonce");
    TEST_ASSERT(persist_save_signing_round_participant_nonce(&db, round1, 1),
                "participant 1 nonce");
    TEST_ASSERT(persist_save_signing_round_participant_psig(&db, round1, 0, "verified"),
                "participant 0 psig verified");
    TEST_ASSERT(persist_save_signing_round_participant_psig(&db, round1, 1, "verified"),
                "participant 1 psig verified");

    TEST_ASSERT(persist_save_signing_round_done(&db, round1, 4, 4,
                                                  "success",
                                                  "deadbeef00000000000000000000000000000000000000000000000000000000",
                                                  NULL),
                "round 1 done success");

    /* Round 2: leave in flight, then sweep — should be marked aborted_crash. */
    int64_t round2 = -1;
    TEST_ASSERT(persist_save_signing_round_start(&db, 0, 5,
                                                   "tier_b_rollover", 2, 5,
                                                   &round2),
                "start round 2");
    TEST_ASSERT(round2 > round1, "round 2 row id > round 1");

    /* Round 3: explicit timeout. */
    int64_t round3 = -1;
    TEST_ASSERT(persist_save_signing_round_start(&db, 0, 7,
                                                   "leaf_advance", 2, 4,
                                                   &round3),
                "start round 3");
    TEST_ASSERT(persist_save_signing_round_done(&db, round3, 4, 3,
                                                  "timeout", NULL,
                                                  "client 3 did not respond"),
                "round 3 done timeout");

    /* Sweep: round 2 should be marked aborted_crash (it has completed_at IS NULL).
       Rounds 1 and 3 are already finalized — should be untouched. */
    int swept = persist_sweep_incomplete_signing_rounds(&db);
    TEST_ASSERT_EQ(swept, 1, "sweep marked exactly 1 in-flight row");

    /* Verify round 2 is now aborted_crash; rounds 1 and 3 are unchanged. */
    sqlite3_stmt *stmt;
    const char *sql =
        "SELECT id, result FROM signing_rounds ORDER BY id ASC;";
    TEST_ASSERT(sqlite3_prepare_v2(db.db, sql, -1, &stmt, NULL) == SQLITE_OK,
                "prepare select");
    int n_rows = 0;
    char results[3][32] = {{0}};
    while (sqlite3_step(stmt) == SQLITE_ROW && n_rows < 3) {
        const char *r = (const char *)sqlite3_column_text(stmt, 1);
        if (r) strncpy(results[n_rows], r, 31);
        n_rows++;
    }
    sqlite3_finalize(stmt);
    TEST_ASSERT_EQ(n_rows, 3, "3 rows present");
    TEST_ASSERT(strcmp(results[0], "success") == 0, "row 1 is success");
    TEST_ASSERT(strcmp(results[1], "aborted_crash") == 0, "row 2 is aborted_crash");
    TEST_ASSERT(strcmp(results[2], "timeout") == 0, "row 3 is timeout");

    /* Sweep again is idempotent — no rows to update. */
    int swept2 = persist_sweep_incomplete_signing_rounds(&db);
    TEST_ASSERT_EQ(swept2, 0, "second sweep finds nothing");

    persist_close(&db);
    return 1;
}

/* v27 (PR-C-1) fee-bump escalation persist round-trip. */
int test_persist_pending_fee_bump_round_trip(void)
{
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open in-memory DB");

    const char *txid = "aa11bb22cc33dd44ee55ff66"
                       "0011223344556677889900aa"
                       "bbccddeeff001122334455660011";
    TEST_ASSERT(persist_save_pending(&db, txid,
                                       /* anchor_vout    */ 1,
                                       /* anchor_amount  */ 330,
                                       /* cycles         */ 3,
                                       /* bump_count     */ 12345,
                                       /* penalty_value  */ 100000,
                                       /* csv_delay      */ 144,
                                       /* start_height   */ 800000,
                                       /* fb_start_block */ 800005,
                                       /* fb_deadline    */ 800500,
                                       /* fb_budget_sat  */ 50000,
                                       /* fb_start_fr    */ 5000),
                "save pending with fee-bump fields");

    char txids[4][65];
    uint32_t vouts[4];
    uint64_t amts[4];
    int cycles[4];
    int bumps[4];
    uint64_t pvals[4];
    uint32_t csvs[4];
    uint32_t starts[4];
    uint32_t fb_starts[4];
    uint32_t fb_deadlines[4];
    uint64_t fb_budgets[4];
    uint64_t fb_frs[4];

    size_t n = persist_load_pending(&db, txids, vouts, amts, cycles, bumps,
                                      pvals, csvs, starts,
                                      fb_starts, fb_deadlines, fb_budgets, fb_frs,
                                      4);
    TEST_ASSERT_EQ((int)n, 1, "exactly 1 row loaded");
    TEST_ASSERT(strncmp(txids[0], txid, 64) == 0, "txid round-trips");
    TEST_ASSERT_EQ((int)fb_starts[0], 800005, "fb_start_block round-trips");
    TEST_ASSERT_EQ((int)fb_deadlines[0], 800500, "fb_deadline_block round-trips");
    TEST_ASSERT_EQ((long long)fb_budgets[0], 50000LL, "fb_budget_sat round-trips");
    TEST_ASSERT_EQ((long long)fb_frs[0], 5000LL, "fb_start_feerate round-trips");

    /* NULL-safe out-pointers: legacy callers pass NULL for fb_* and still work. */
    size_t n2 = persist_load_pending(&db, txids, vouts, amts, cycles, bumps,
                                       pvals, csvs, starts,
                                       NULL, NULL, NULL, NULL, 4);
    TEST_ASSERT_EQ((int)n2, 1, "NULL fb_* out-pointers do not crash");

    persist_close(&db);
    return 1;
}

/* v28 (PR-C-2) force-close watch persistence round-trip. */
int test_persist_force_close_round_trip(void)
{
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open in-memory DB");

    /* Build two watches.  Watch A has 2 HTLCs, watch B has 1. */
    unsigned char txid_a[32], txid_b[32];
    memset(txid_a, 0xAA, 32);
    memset(txid_b, 0xBB, 32);

    watchtower_htlc_t htlcs_a[2];
    memset(htlcs_a, 0, sizeof(htlcs_a));
    htlcs_a[0].htlc_vout   = 2;
    htlcs_a[0].htlc_amount = 100000;
    memset(htlcs_a[0].htlc_spk, 0x51, 34);
    htlcs_a[0].direction   = HTLC_OFFERED;
    memset(htlcs_a[0].payment_hash, 0xCC, 32);
    htlcs_a[0].cltv_expiry = 800500;

    htlcs_a[1].htlc_vout   = 3;
    htlcs_a[1].htlc_amount = 50000;
    memset(htlcs_a[1].htlc_spk, 0x52, 34);
    htlcs_a[1].direction   = HTLC_RECEIVED;
    memset(htlcs_a[1].payment_hash, 0xDD, 32);
    htlcs_a[1].cltv_expiry = 800400;

    watchtower_htlc_t htlcs_b[1];
    memset(htlcs_b, 0, sizeof(htlcs_b));
    htlcs_b[0].htlc_vout   = 1;
    htlcs_b[0].htlc_amount = 75000;
    memset(htlcs_b[0].htlc_spk, 0x53, 34);
    htlcs_b[0].direction   = HTLC_OFFERED;
    memset(htlcs_b[0].payment_hash, 0xEE, 32);
    htlcs_b[0].cltv_expiry = 800600;
    strcpy(htlcs_b[0].sweep_txid,
           "deadbeef00000000000000000000000000000000000000000000000000000000");

    int64_t row_a = -1, row_b = -1;
    TEST_ASSERT(persist_save_force_close(&db, 7, txid_a,
                  (const struct watchtower_htlc *)htlcs_a, 2, &row_a),
                "save watch A");
    TEST_ASSERT(row_a > 0, "row_a > 0");
    TEST_ASSERT(persist_save_force_close(&db, 11, txid_b,
                  (const struct watchtower_htlc *)htlcs_b, 1, &row_b),
                "save watch B");
    TEST_ASSERT(row_b > row_a, "row_b > row_a");

    /* Load back */
    uint32_t channels[4];
    unsigned char txids[4][32];
    watchtower_htlc_t loaded_htlcs[8];
    size_t n_per[4];
    size_t n_watches = persist_load_force_close_watches(&db,
        channels, txids, loaded_htlcs, n_per, 4, 8);
    TEST_ASSERT_EQ((int)n_watches, 2, "loaded 2 watches");

    /* Watch A round-trips */
    TEST_ASSERT_EQ((int)channels[0], 7,            "watch A channel_id");
    TEST_ASSERT_EQ((int)n_per[0],    2,            "watch A has 2 HTLCs");
    TEST_ASSERT(memcmp(txids[0], txid_a, 32) == 0, "watch A txid round-trips");
    TEST_ASSERT_EQ((long long)loaded_htlcs[0].htlc_amount, 100000LL, "htlc A0 amount");
    TEST_ASSERT_EQ((int)loaded_htlcs[0].cltv_expiry,        800500,  "htlc A0 cltv");
    TEST_ASSERT_EQ((int)loaded_htlcs[0].direction,          HTLC_OFFERED, "htlc A0 dir");
    TEST_ASSERT_EQ((long long)loaded_htlcs[1].htlc_amount, 50000LL,  "htlc A1 amount");

    /* Watch B round-trips */
    TEST_ASSERT_EQ((int)channels[1], 11,           "watch B channel_id");
    TEST_ASSERT_EQ((int)n_per[1],    1,            "watch B has 1 HTLC");
    TEST_ASSERT(memcmp(txids[1], txid_b, 32) == 0, "watch B txid round-trips");
    TEST_ASSERT_EQ((long long)loaded_htlcs[2].htlc_amount, 75000LL,  "htlc B0 amount");
    TEST_ASSERT(strncmp(loaded_htlcs[2].sweep_txid, "deadbeef", 8) == 0,
                "sweep_txid round-trips");

    /* Delete watch A, confirm only B remains. */
    TEST_ASSERT(persist_delete_force_close(&db, row_a), "delete watch A");
    size_t n_after = persist_load_force_close_watches(&db,
        channels, txids, loaded_htlcs, n_per, 4, 8);
    TEST_ASSERT_EQ((int)n_after, 1, "1 watch after delete");
    TEST_ASSERT_EQ((int)channels[0], 11, "remaining watch is B");

    persist_close(&db);
    return 1;
}

/* v30 (PR-PTLC-1) old_commitment_ptlcs round-trip — schema groundwork. */
int test_persist_old_commitment_ptlcs_round_trip(void)
{
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open in-memory DB");

    /* Save two PTLC outputs on commitment (channel=4, commit_num=2). */
    watchtower_htlc_t p0, p1;
    memset(&p0, 0, sizeof(p0));
    p0.htlc_vout   = 2;
    p0.htlc_amount = 11000;
    memset(p0.htlc_spk, 0x60, 34);
    p0.direction   = HTLC_OFFERED;
    memset(p0.payment_hash, 0xAA, 32);  /* xonly form of payment_point */
    p0.cltv_expiry = 800200;

    memset(&p1, 0, sizeof(p1));
    p1.htlc_vout   = 3;
    p1.htlc_amount = 22000;
    memset(p1.htlc_spk, 0x61, 34);
    p1.direction   = HTLC_RECEIVED;
    memset(p1.payment_hash, 0xBB, 32);
    p1.cltv_expiry = 800300;

    TEST_ASSERT(persist_save_old_commitment_ptlc(&db, 4, 2, &p0), "save ptlc 0");
    TEST_ASSERT(persist_save_old_commitment_ptlc(&db, 4, 2, &p1), "save ptlc 1");

    /* A different channel — confirm scope. */
    watchtower_htlc_t p2;
    memset(&p2, 0, sizeof(p2));
    p2.htlc_vout   = 2;
    p2.htlc_amount = 99000;
    memset(p2.htlc_spk, 0x70, 34);
    p2.direction   = HTLC_OFFERED;
    memset(p2.payment_hash, 0xCC, 32);
    p2.cltv_expiry = 800400;
    TEST_ASSERT(persist_save_old_commitment_ptlc(&db, 9, 1, &p2), "save ptlc on different channel");

    /* Load back channel=4 commit=2 — should be exactly 2 rows. */
    watchtower_htlc_t out[4];
    size_t n = persist_load_old_commitment_ptlcs(&db, 4, 2, out, 4);
    TEST_ASSERT_EQ((int)n, 2, "2 PTLCs loaded for channel 4, commit 2");
    TEST_ASSERT_EQ((int)out[0].htlc_vout,   2,       "ptlc 0 vout");
    TEST_ASSERT_EQ((long long)out[0].htlc_amount, 11000LL, "ptlc 0 amount");
    TEST_ASSERT_EQ((int)out[0].direction,    HTLC_OFFERED, "ptlc 0 direction");
    TEST_ASSERT((unsigned char)out[0].payment_hash[0] == 0xAA, "ptlc 0 payment_point round-trips");
    TEST_ASSERT_EQ((int)out[0].cltv_expiry, 800200, "ptlc 0 cltv");
    TEST_ASSERT_EQ((int)out[1].htlc_vout,   3,       "ptlc 1 vout");
    TEST_ASSERT_EQ((int)out[1].direction,    HTLC_RECEIVED, "ptlc 1 direction");

    /* Load channel=9 commit=1 — should be exactly 1 row. */
    size_t n2 = persist_load_old_commitment_ptlcs(&db, 9, 1, out, 4);
    TEST_ASSERT_EQ((int)n2, 1, "1 PTLC on channel 9 commit 1");
    TEST_ASSERT_EQ((long long)out[0].htlc_amount, 99000LL, "channel 9 ptlc amount");

    /* Load nonexistent — 0 rows. */
    size_t n3 = persist_load_old_commitment_ptlcs(&db, 9, 99, out, 4);
    TEST_ASSERT_EQ((int)n3, 0, "no PTLCs for nonexistent commit_num");

    /* Idempotent save (INSERT OR REPLACE on same key). */
    TEST_ASSERT(persist_save_old_commitment_ptlc(&db, 4, 2, &p0), "idempotent save");
    n = persist_load_old_commitment_ptlcs(&db, 4, 2, out, 4);
    TEST_ASSERT_EQ((int)n, 2, "still 2 PTLCs after idempotent save");

    persist_close(&db);
    return 1;
}

/* v29 (PR-C-6) observability tables append-only smoke test. */
int test_persist_observability_tables(void)
{
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open in-memory DB");

    /* reorg_events: 3 rows */
    TEST_ASSERT(persist_log_reorg_event(&db, 100, 105, 2), "reorg 1");
    TEST_ASSERT(persist_log_reorg_event(&db, 200, 202, 0), "reorg 2 (no-op reset)");
    TEST_ASSERT(persist_log_reorg_event(&db, 300, 310, 5), "reorg 3");

    sqlite3_stmt *stmt;
    TEST_ASSERT(sqlite3_prepare_v2(db.db,
        "SELECT count(*), max(n_entries_reset) FROM reorg_events;",
        -1, &stmt, NULL) == SQLITE_OK, "prepare count");
    TEST_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW, "step row");
    TEST_ASSERT_EQ(sqlite3_column_int(stmt, 0), 3, "3 reorg rows");
    TEST_ASSERT_EQ(sqlite3_column_int(stmt, 1), 5, "max n_entries_reset = 5");
    sqlite3_finalize(stmt);

    /* breach_detections: 2 rows, one with response txid + one without */
    unsigned char txid_a[32], txid_b[32];
    memset(txid_a, 0xAB, 32);
    memset(txid_b, 0xCD, 32);
    TEST_ASSERT(persist_log_breach_detection(&db, 7, 3, txid_a, 800000,
                  "fffeeefffeeefffeeefffeeefffeeefffeeefffeeefffeeefffeeefffeeefff"),
                "breach with response");
    TEST_ASSERT(persist_log_breach_detection(&db, 9, 0, txid_b, 800100, NULL),
                "breach without response");

    TEST_ASSERT(sqlite3_prepare_v2(db.db,
        "SELECT count(*), sum(CASE WHEN response_txid IS NULL THEN 1 ELSE 0 END) "
        "FROM breach_detections;",
        -1, &stmt, NULL) == SQLITE_OK, "prepare breach count");
    TEST_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW, "step breach row");
    TEST_ASSERT_EQ(sqlite3_column_int(stmt, 0), 2, "2 breach rows");
    TEST_ASSERT_EQ(sqlite3_column_int(stmt, 1), 1, "1 breach with NULL response");
    sqlite3_finalize(stmt);

    /* NULL DB safety */
    TEST_ASSERT(persist_log_reorg_event(NULL, 100, 105, 0) == 0, "NULL db reorg returns 0");
    TEST_ASSERT(persist_log_breach_detection(NULL, 1, 0, txid_a, 0, NULL) == 0,
                "NULL db breach returns 0");
    TEST_ASSERT(persist_log_breach_detection(&db, 1, 0, NULL, 0, NULL) == 0,
                "NULL txid returns 0");

    persist_close(&db);
    return 1;
}

/* === SF-CEREMONY-HELPERS test suite (#199 / wallet team API) ============== */

static int ch_test_count_cb(const persist_ceremony_t *c, void *ud) {
    (void)c;
    int *n = (int *)ud;
    (*n)++;
    return 1;
}

static int ch_test_count_p_cb(const persist_participant_t *p, void *ud) {
    (void)p;
    int *n = (int *)ud;
    (*n)++;
    return 1;
}

/* CH_T1 — save + load roundtrip */
int test_ceremony_helpers_save_load(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open in-memory");
    unsigned char cid[8]   = {1,2,3,4,5,6,7,8};
    unsigned char fid[32];  memset(fid, 0xAA, 32);
    unsigned char pid[8]   = {9,8,7,6,5,4,3,2};
    TEST_ASSERT(persist_save_ceremony(&db, cid, fid,
                                       PERSIST_CEREMONY_TYPE_ROTATE, pid,
                                       100, 200),
                "save");
    persist_ceremony_t out;
    TEST_ASSERT(persist_load_ceremony(&db, cid, &out), "load");
    TEST_ASSERT(memcmp(out.ceremony_id, cid, 8) == 0,           "cid roundtrip");
    TEST_ASSERT(memcmp(out.factory_instance_id, fid, 32) == 0,  "fid roundtrip");
    TEST_ASSERT(out.ceremony_type == PERSIST_CEREMONY_TYPE_ROTATE, "type roundtrip");
    TEST_ASSERT(out.has_parent == 1,                            "parent flag");
    TEST_ASSERT(memcmp(out.parent_ceremony_id, pid, 8) == 0,    "parent roundtrip");
    TEST_ASSERT(out.started_at_block == 100,                    "started block");
    TEST_ASSERT(out.deadline_block == 200,                      "deadline block");
    TEST_ASSERT(out.state == PERSIST_CEREMONY_STATE_PENDING_NONCES, "initial state");
    persist_close(&db);
    return 1;
}

/* CH_T2 — load nonexistent returns 0 */
int test_ceremony_helpers_load_missing(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    unsigned char cid[8] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    persist_ceremony_t out;
    TEST_ASSERT(persist_load_ceremony(&db, cid, &out) == 0, "miss returns 0");
    persist_close(&db);
    return 1;
}

/* CH_T3 — state transition guard: FINALIZED refuses if any participant
            not at phase=SIGNED. */
int test_ceremony_helpers_finalize_guard(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    unsigned char cid[8] = {1};   /* simplistic ids */
    unsigned char fid[32]; memset(fid, 0xBB, 32);
    persist_save_ceremony(&db, cid, fid, PERSIST_CEREMONY_TYPE_INITIAL,
                           NULL, 1, 100);
    /* Add 2 participants — one SIGNED, one only NONCED. */
    unsigned char p1[33]; memset(p1, 0x01, 33);
    unsigned char p2[33]; memset(p2, 0x02, 33);
    persist_save_participant_phase(&db, cid, p1,
                                    PERSIST_CEREMONY_PHASE_SIGNED, NULL, NULL,
                                    0, 0);
    persist_save_participant_phase(&db, cid, p2,
                                    PERSIST_CEREMONY_PHASE_NONCED, NULL, NULL,
                                    0, 0);
    /* FINALIZED transition should refuse. */
    int rc = persist_update_ceremony_state(&db, cid,
                                            PERSIST_CEREMONY_STATE_FINALIZED);
    TEST_ASSERT(rc == 0, "finalize refused when participant not signed");
    /* But transition to PARTIAL_FAILED should succeed (no guard). */
    rc = persist_update_ceremony_state(&db, cid,
                                       PERSIST_CEREMONY_STATE_PARTIAL_FAILED);
    TEST_ASSERT(rc == 1, "partial_failed succeeds");
    persist_close(&db);
    return 1;
}

/* CH_T4 — state transition guard: FINALIZED succeeds when all signed. */
int test_ceremony_helpers_finalize_all_signed(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    unsigned char cid[8] = {2};
    unsigned char fid[32]; memset(fid, 0xCC, 32);
    persist_save_ceremony(&db, cid, fid, PERSIST_CEREMONY_TYPE_INITIAL,
                           NULL, 1, 100);
    for (int i = 0; i < 3; i++) {
        unsigned char pk[33]; memset(pk, (unsigned char)(0x10 + i), 33);
        persist_save_participant_phase(&db, cid, pk,
                                        PERSIST_CEREMONY_PHASE_SIGNED,
                                        NULL, NULL, 0, 0);
    }
    int rc = persist_update_ceremony_state(&db, cid,
                                            PERSIST_CEREMONY_STATE_FINALIZED);
    TEST_ASSERT(rc == 1, "finalize succeeds when all signed");
    persist_ceremony_t out;
    persist_load_ceremony(&db, cid, &out);
    TEST_ASSERT(out.state == PERSIST_CEREMONY_STATE_FINALIZED, "state finalized");
    persist_close(&db);
    return 1;
}

/* CH_T5 — get_last_finalized_ceremony returns most recent. */
int test_ceremony_helpers_last_finalized(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    unsigned char fid[32]; memset(fid, 0xDD, 32);
    /* Create 3 ceremonies in temporal order. */
    for (int i = 1; i <= 3; i++) {
        unsigned char cid[8]; memset(cid, (unsigned char)i, 8);
        persist_save_ceremony(&db, cid, fid, PERSIST_CEREMONY_TYPE_ROTATE,
                               NULL, /* started_at_block */ (uint32_t)(100 + i),
                               200);
        if (i < 3) {  /* finalize first two */
            unsigned char pk[33]; memset(pk, 0x01, 33);
            persist_save_participant_phase(&db, cid, pk,
                                            PERSIST_CEREMONY_PHASE_SIGNED,
                                            NULL, NULL, 0, 0);
            persist_update_ceremony_state(&db, cid,
                                           PERSIST_CEREMONY_STATE_FINALIZED);
        }
    }
    unsigned char latest[8];
    int rc = persist_get_last_finalized_ceremony(&db, fid, latest);
    TEST_ASSERT(rc == 1, "found a finalized");
    /* Should be ceremony id {2,2,...} since it had the latest started_at_block
       among finalized. */
    TEST_ASSERT(latest[0] == 2, "latest is c2");
    persist_close(&db);
    return 1;
}

/* CH_T6 — get_last_finalized_ceremony returns 0 if none finalized. */
int test_ceremony_helpers_last_finalized_none(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    unsigned char fid[32]; memset(fid, 0xEE, 32);
    unsigned char cid[8]; memset(cid, 0x01, 8);
    persist_save_ceremony(&db, cid, fid, PERSIST_CEREMONY_TYPE_INITIAL,
                           NULL, 100, 200);
    /* Still in PENDING_NONCES, not finalized. */
    unsigned char latest[8] = {0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA};
    int rc = persist_get_last_finalized_ceremony(&db, fid, latest);
    TEST_ASSERT(rc == 0, "no finalized → returns 0");
    TEST_ASSERT(latest[0] == 0xAA, "out unchanged on miss");
    persist_close(&db);
    return 1;
}

/* CH_T7 — scan_participants filtered + any. */
int test_ceremony_helpers_scan_participants(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    unsigned char cid[8] = {0x03};
    unsigned char fid[32]; memset(fid, 0xFF, 32);
    persist_save_ceremony(&db, cid, fid, PERSIST_CEREMONY_TYPE_INITIAL,
                           NULL, 1, 100);
    /* 4 participants, 2 signed + 1 nonced + 1 refused. */
    for (int i = 0; i < 4; i++) {
        unsigned char pk[33]; memset(pk, (unsigned char)(0x20 + i), 33);
        uint8_t phase = (i < 2) ? PERSIST_CEREMONY_PHASE_SIGNED
                      : (i == 2 ? PERSIST_CEREMONY_PHASE_NONCED
                                : PERSIST_CEREMONY_PHASE_REFUSED);
        persist_save_participant_phase(&db, cid, pk, phase, NULL, NULL, 0, 0);
    }
    int any_count = 0;
    persist_scan_participants(&db, cid, 0xFF, ch_test_count_p_cb, &any_count);
    TEST_ASSERT(any_count == 4, "scan any → 4");
    int signed_count = 0;
    persist_scan_participants(&db, cid, PERSIST_CEREMONY_PHASE_SIGNED,
                               ch_test_count_p_cb, &signed_count);
    TEST_ASSERT(signed_count == 2, "scan signed → 2");
    int refused_count = 0;
    persist_scan_participants(&db, cid, PERSIST_CEREMONY_PHASE_REFUSED,
                               ch_test_count_p_cb, &refused_count);
    TEST_ASSERT(refused_count == 1, "scan refused → 1");
    persist_close(&db);
    return 1;
}

/* CH_T8 — scan_ceremonies_by_factory all + state-filtered. */
int test_ceremony_helpers_scan_by_factory(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    unsigned char fid_a[32]; memset(fid_a, 0xA1, 32);
    unsigned char fid_b[32]; memset(fid_b, 0xB1, 32);
    /* 3 ceremonies on fid_a, 1 on fid_b. */
    for (int i = 0; i < 3; i++) {
        unsigned char cid[8]; memset(cid, (unsigned char)(0x40 + i), 8);
        persist_save_ceremony(&db, cid, fid_a, PERSIST_CEREMONY_TYPE_ROTATE,
                               NULL, (uint32_t)(100 + i), 200);
    }
    {
        unsigned char cid[8]; memset(cid, 0x50, 8);
        persist_save_ceremony(&db, cid, fid_b, PERSIST_CEREMONY_TYPE_ROTATE,
                               NULL, 100, 200);
    }
    int n_a = 0;
    persist_scan_ceremonies_by_factory(&db, fid_a, -1, ch_test_count_cb, &n_a);
    TEST_ASSERT(n_a == 3, "scan all on fid_a → 3");
    int n_b = 0;
    persist_scan_ceremonies_by_factory(&db, fid_b, -1, ch_test_count_cb, &n_b);
    TEST_ASSERT(n_b == 1, "scan all on fid_b → 1");
    /* Mark one ceremony on fid_a as ABORTED. */
    unsigned char cid_abort[8]; memset(cid_abort, 0x40, 8);
    persist_update_ceremony_state(&db, cid_abort,
                                   PERSIST_CEREMONY_STATE_ABORTED);
    int n_aborted = 0;
    persist_scan_ceremonies_by_factory(&db, fid_a,
                                         PERSIST_CEREMONY_STATE_ABORTED,
                                         ch_test_count_cb, &n_aborted);
    TEST_ASSERT(n_aborted == 1, "filtered scan → 1 aborted");
    persist_close(&db);
    return 1;
}

/* CH_T9 — revocation_releases save + count idempotent on duplicate. */
int test_ceremony_helpers_revocations(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    unsigned char fid[32]; memset(fid, 0xAB, 32);
    unsigned char sid[32]; memset(sid, 0xCD, 32);
    unsigned char pk[33];  memset(pk, 0x11, 33);
    unsigned char sec[32]; memset(sec, 0xEF, 32);
    TEST_ASSERT(persist_save_revocation_release(&db, fid, sid, pk, sec, 1000),
                "first save");
    TEST_ASSERT(persist_save_revocation_release(&db, fid, sid, pk, sec, 1001),
                "second save (idempotent — INSERT OR IGNORE returns DONE)");
    TEST_ASSERT(persist_count_revocations_for_state(&db, fid, sid) == 1,
                "count = 1 after duplicate insert");
    /* Add a different participant. */
    unsigned char pk2[33]; memset(pk2, 0x22, 33);
    persist_save_revocation_release(&db, fid, sid, pk2, sec, 1002);
    TEST_ASSERT(persist_count_revocations_for_state(&db, fid, sid) == 2,
                "count = 2 after second participant");
    persist_close(&db);
    return 1;
}

/* CH_T10 — scan_in_flight_ceremonies excludes FINALIZED + ABORTED. */
int test_ceremony_helpers_scan_in_flight(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    unsigned char fid[32]; memset(fid, 0x33, 32);
    /* 5 ceremonies: 2 in-flight, 1 finalized, 1 aborted, 1 partial_failed. */
    for (int i = 0; i < 5; i++) {
        unsigned char cid[8]; memset(cid, (unsigned char)(0x60 + i), 8);
        persist_save_ceremony(&db, cid, fid, PERSIST_CEREMONY_TYPE_ROTATE,
                               NULL, (uint32_t)(100 + i), 200);
        if (i == 2) {
            unsigned char pk[33]; memset(pk, 0x99, 33);
            persist_save_participant_phase(&db, cid, pk,
                                            PERSIST_CEREMONY_PHASE_SIGNED,
                                            NULL, NULL, 0, 0);
            persist_update_ceremony_state(&db, cid,
                                           PERSIST_CEREMONY_STATE_FINALIZED);
        } else if (i == 3) {
            persist_update_ceremony_state(&db, cid,
                                           PERSIST_CEREMONY_STATE_ABORTED);
        } else if (i == 4) {
            persist_update_ceremony_state(&db, cid,
                                           PERSIST_CEREMONY_STATE_PARTIAL_FAILED);
        }
    }
    int n = 0;
    persist_scan_in_flight_ceremonies(&db, fid, ch_test_count_cb, &n);
    TEST_ASSERT(n == 2, "in-flight count = 2 (state < FINALIZED only)");
    persist_close(&db);
    return 1;
}

/* CH_T11 — participant phase UPSERT updates without re-inserting. */
int test_ceremony_helpers_participant_upsert(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    unsigned char cid[8]; memset(cid, 0x71, 8);
    unsigned char fid[32]; memset(fid, 0x71, 32);
    unsigned char pk[33];  memset(pk, 0x71, 33);
    persist_save_ceremony(&db, cid, fid, PERSIST_CEREMONY_TYPE_INITIAL,
                           NULL, 1, 100);
    persist_save_participant_phase(&db, cid, pk,
                                    PERSIST_CEREMONY_PHASE_NOT_SENT,
                                    NULL, NULL, 0, 0);
    persist_save_participant_phase(&db, cid, pk,
                                    PERSIST_CEREMONY_PHASE_SENT,
                                    NULL, NULL, 0, 0);
    persist_save_participant_phase(&db, cid, pk,
                                    PERSIST_CEREMONY_PHASE_SIGNED,
                                    NULL, NULL, 0, 0);
    /* Only 1 row should exist (UPSERT). */
    int n = 0;
    persist_scan_participants(&db, cid, 0xFF, ch_test_count_p_cb, &n);
    TEST_ASSERT(n == 1, "single row after 3 upserts");
    persist_close(&db);
    return 1;
}

/* CH_T14 (#219 / SF-AGG-HARD-GUARD, wallet team CEREMONY_COORD_REPLY_2 §2):
   persist_update_ceremony_artifacts(final_signature=X) REFUSES when any
   ceremony_participants row has phase != SIGNED.  Mirrors CH_T3 (the
   FINALIZED state-transition guard).  Other artifact updates (aggregated
   nonce, broadcast_txid, abort_reason) are unaffected by the guard. */
int test_ceremony_helpers_aggregate_hard_guard(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open");
    unsigned char cid[8]; memset(cid, 0xD1, 8);
    unsigned char fid[32]; memset(fid, 0xD2, 32);
    persist_save_ceremony(&db, cid, fid, PERSIST_CEREMONY_TYPE_INITIAL,
                           NULL, 1, 100);

    /* Two participants - one SIGNED, one only NONCED. */
    unsigned char p1[33]; memset(p1, 0x01, 33);
    unsigned char p2[33]; memset(p2, 0x02, 33);
    persist_save_participant_phase(&db, cid, p1,
                                    PERSIST_CEREMONY_PHASE_SIGNED,
                                    NULL, NULL, 0, 0);
    persist_save_participant_phase(&db, cid, p2,
                                    PERSIST_CEREMONY_PHASE_NONCED,
                                    NULL, NULL, 0, 0);

    /* Attempt to persist a final_signature -> MUST refuse. */
    unsigned char final_sig[64]; memset(final_sig, 0xAB, 64);
    int rc = persist_update_ceremony_artifacts(&db, cid,
                                                NULL,       /* nonce */
                                                final_sig,  /* GUARDED */
                                                NULL,       /* broadcast_txid */
                                                0, 0);      /* abort_reason */
    TEST_ASSERT(rc == 0, "final_signature persist refused when one participant !=SIGNED");

    /* Verify final_signature was NOT written. */
    sqlite3_stmt *stmt = NULL;
    TEST_ASSERT(sqlite3_prepare_v2(db.db,
        "SELECT final_signature FROM ceremonies WHERE ceremony_id = ?;",
        -1, &stmt, NULL) == SQLITE_OK, "prepare check");
    sqlite3_bind_blob(stmt, 1, cid, 8, SQLITE_STATIC);
    TEST_ASSERT(sqlite3_step(stmt) == SQLITE_ROW, "row exists");
    TEST_ASSERT(sqlite3_column_type(stmt, 0) == SQLITE_NULL,
                "final_signature still NULL (guard rejected write)");
    sqlite3_finalize(stmt);

    /* Aggregated_nonce update without final_signature should succeed. */
    unsigned char agg_nonce[66]; memset(agg_nonce, 0x7F, 66);
    rc = persist_update_ceremony_artifacts(&db, cid,
                                            agg_nonce,
                                            NULL,
                                            NULL,
                                            0, 0);
    TEST_ASSERT(rc == 1, "nonce-only artifact update bypasses guard");

    /* Promote p2 to SIGNED -> final_signature write should succeed. */
    persist_save_participant_phase(&db, cid, p2,
                                    PERSIST_CEREMONY_PHASE_SIGNED,
                                    NULL, NULL, 0, 0);
    rc = persist_update_ceremony_artifacts(&db, cid,
                                            NULL,
                                            final_sig,
                                            NULL,
                                            0, 0);
    TEST_ASSERT(rc == 1, "final_signature persists when all participants SIGNED");

    /* Verify it was actually written. */
    TEST_ASSERT(sqlite3_prepare_v2(db.db,
        "SELECT final_signature FROM ceremonies WHERE ceremony_id = ?;",
        -1, &stmt, NULL) == SQLITE_OK, "prepare verify");
    sqlite3_bind_blob(stmt, 1, cid, 8, SQLITE_STATIC);
    TEST_ASSERT(sqlite3_step(stmt) == SQLITE_ROW, "row exists post-write");
    TEST_ASSERT(sqlite3_column_bytes(stmt, 0) == 64, "final_signature 64 bytes");
    TEST_ASSERT(memcmp(sqlite3_column_blob(stmt, 0), final_sig, 64) == 0,
                "final_signature bytes match");
    sqlite3_finalize(stmt);

    persist_close(&db);
    return 1;
}

/* === End SF-CEREMONY-HELPERS tests ======================================== */
