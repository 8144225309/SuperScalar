/*
 * test_spec_vectors.c — BOLT spec test vectors + integration tests
 *
 * SV1: test_bolt3_shachain_vector_zero_seed — BOLT #3 appendix A vector 1
 * SV2: test_bolt3_shachain_vector_ff_seed   — BOLT #3 appendix A vector 2
 * SV3: test_bolt3_shachain_vector_ff_aaa    — BOLT #3 appendix A vector 3
 * SV4: test_bolt3_shachain_vector_01_seed   — BOLT #3 appendix A vector 4
 * IT1: test_it_shutdown_roundtrip           — chan_close build → recv roundtrip
 * IT2: test_it_closing_signed_roundtrip     — closing_signed build → recv roundtrip
 * IT3: test_it_probe_peer_db_score          — probe failure → peer_db score delta
 * IT4: test_it_watchdog_expire_chain        — watchdog check + expire sequence
 */

#include "superscalar/shachain.h"
#include "superscalar/chan_close.h"
#include "superscalar/probe.h"
#include "superscalar/peer_db.h"
#include "superscalar/cltv_watchdog.h"
#include "superscalar/channel.h"
#include "superscalar/musig.h"
#include <secp256k1.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

static int hex2bin(const char *hex, unsigned char *out, size_t n) {
    if (strlen(hex) != n * 2) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned int b = 0;
        if (sscanf(hex + i * 2, "%02x", &b) != 1) return 0;
        out[i] = (unsigned char)b;
    }
    return 1;
}

/* ================================================================== */
/* SV1 — BOLT #3 shachain: seed=0x00..00, I=0xffffffffffff           */
/* ================================================================== */
int test_bolt3_shachain_vector_zero_seed(void)
{
    /*
     * From BOLT #3 Appendix A:
     *   seed   = 0x0000...0000 (32 zero bytes)
     *   I      = 281474976710655 = 0xffffffffffff
     *   result = 0x02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148
     */
    unsigned char seed[32]; memset(seed, 0x00, 32);
    unsigned char expected[32];
    ASSERT(hex2bin("02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148",
                    expected, 32), "parse expected vector 1");

    unsigned char result[32];
    shachain_from_seed(seed, 0xffffffffffffULL, result);

    ASSERT(memcmp(result, expected, 32) == 0,
           "shachain vector 1: all-zero seed, I=0xffffffffffff");
    return 1;
}

/* ================================================================== */
/* SV2 — BOLT #3 shachain: seed=0xFF..FF, I=0xffffffffffff           */
/* ================================================================== */
int test_bolt3_shachain_vector_ff_seed(void)
{
    /*
     * From BOLT #3 Appendix A:
     *   seed   = 0xffff...ffff (32 0xFF bytes)
     *   I      = 0xffffffffffff
     *   result = 0x7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc
     */
    unsigned char seed[32]; memset(seed, 0xFF, 32);
    unsigned char expected[32];
    ASSERT(hex2bin("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc",
                    expected, 32), "parse expected vector 2");

    unsigned char result[32];
    shachain_from_seed(seed, 0xffffffffffffULL, result);

    ASSERT(memcmp(result, expected, 32) == 0,
           "shachain vector 2: all-FF seed, I=0xffffffffffff");
    return 1;
}

/* ================================================================== */
/* SV3 — BOLT #3 shachain: seed=0xFF..FF, I=0x555555555555           */
/* ================================================================== */
int test_bolt3_shachain_vector_ff_aaa(void)
{
    /*
     * From BOLT #3 Appendix A (vector 3):
     *   seed   = 0xffff...ffff
     *   I      = 0x555555555555
     *   result = 0x9015daaeb06dba4ccc05b91b2f73bd54405f2be9f217fbacd3c5ac2e62327d31
     */
    unsigned char seed[32]; memset(seed, 0xFF, 32);
    unsigned char expected[32];
    ASSERT(hex2bin("9015daaeb06dba4ccc05b91b2f73bd54405f2be9f217fbacd3c5ac2e62327d31",
                    expected, 32), "parse expected vector 3");

    unsigned char result[32];
    shachain_from_seed(seed, 0x555555555555ULL, result);

    ASSERT(memcmp(result, expected, 32) == 0,
           "shachain vector 3: all-FF seed, I=0x555555555555");
    return 1;
}

/* ================================================================== */
/* SV4 — BOLT #3 shachain: seed=0x01..01, I=1                        */
/* ================================================================== */
int test_bolt3_shachain_vector_01_seed(void)
{
    /*
     * From BOLT #3 Appendix A:
     *   seed   = 0x0101...0101 (32 × 0x01)
     *   I      = 1
     *   result = 0x915c75942a26bb3a433a8ce2cb0427c29ec6c1775cfc78328b57f6ba7bfeaa9c
     */
    unsigned char seed[32]; memset(seed, 0x01, 32);
    unsigned char expected[32];
    ASSERT(hex2bin("915c75942a26bb3a433a8ce2cb0427c29ec6c1775cfc78328b57f6ba7bfeaa9c",
                    expected, 32), "parse expected vector 4");

    unsigned char result[32];
    shachain_from_seed(seed, 1ULL, result);

    ASSERT(memcmp(result, expected, 32) == 0,
           "shachain vector 4: seed=0x01..01, I=1");
    return 1;
}

/* ================================================================== */
/* IT1 — shutdown build → recv_shutdown roundtrip (multi-component)   */
/* ================================================================== */
int test_it_shutdown_roundtrip(void)
{
    /*
     * Integration test: chan_close_build_shutdown → chan_close_recv_shutdown
     * Verify full roundtrip with a P2TR scriptpubkey.
     */
    unsigned char channel_id[32]; memset(channel_id, 0x42, 32);
    /* P2TR: OP_1 PUSH32 <32 bytes> = 34 bytes */
    unsigned char spk[34];
    spk[0] = 0x51; spk[1] = 0x20;
    memset(spk + 2, 0xAA, 32);

    unsigned char buf[256];
    size_t msg_len = chan_close_build_shutdown(channel_id, spk, 34,
                                               buf, sizeof(buf));
    ASSERT(msg_len == 70, "shutdown is 2+32+2+34=70 bytes");

    unsigned char parsed_id[32];
    unsigned char parsed_spk[64];
    uint16_t parsed_spk_len = 0;

    ASSERT(chan_close_recv_shutdown(buf, msg_len, parsed_id,
                                    parsed_spk, &parsed_spk_len,
                                    sizeof(parsed_spk)),
           "recv_shutdown succeeds");
    ASSERT(memcmp(parsed_id, channel_id, 32) == 0, "channel_id intact");
    ASSERT(parsed_spk_len == 34, "spk_len intact");
    ASSERT(parsed_spk[0] == 0x51, "OP_1 preserved");
    ASSERT(memcmp(parsed_spk + 2, spk + 2, 32) == 0, "P2TR key preserved");

    return 1;
}

/* ================================================================== */
/* IT2 — closing_signed fee negotiation until agreement               */
/* ================================================================== */
int test_it_closing_signed_roundtrip(void)
{
    /*
     * Integration: two sides negotiate fees using chan_close_negotiate_fee.
     * Verify the closing_signed message at the agreed fee parses correctly.
     */
    uint64_t alice_fee = 800;
    uint64_t bob_fee   = 3200;

    /* Negotiate until agreement (max 100 rounds) */
    int rounds = 0;
    while (alice_fee != bob_fee && rounds < 100) {
        alice_fee = chan_close_negotiate_fee(alice_fee, bob_fee);
        if (alice_fee == bob_fee) break;
        bob_fee   = chan_close_negotiate_fee(bob_fee, alice_fee);
        rounds++;
    }
    ASSERT(alice_fee == bob_fee, "fees must agree");
    ASSERT(rounds < 100, "convergence in < 100 rounds");

    /* Build closing_signed with agreed fee */
    unsigned char channel_id[32]; memset(channel_id, 0x77, 32);
    unsigned char sig64[64];      memset(sig64, 0x55, 64);

    unsigned char buf[200];
    size_t len = chan_close_build_closing_signed(channel_id, alice_fee, sig64,
                                                  buf, sizeof(buf));
    ASSERT(len == 106, "closing_signed = 106 bytes");

    unsigned char parsed_id[32];
    unsigned char parsed_sig[64];
    uint64_t parsed_fee = 0;
    ASSERT(chan_close_recv_closing_signed(buf, len, parsed_id, &parsed_fee,
                                          parsed_sig),
           "recv_closing_signed succeeds");
    ASSERT(parsed_fee == alice_fee, "agreed fee preserved in message");
    ASSERT(memcmp(parsed_sig, sig64, 64) == 0, "sig preserved");

    return 1;
}

/* ================================================================== */
/* IT3 — probe failure → peer_db score delta integration              */
/* ================================================================== */
int test_it_probe_peer_db_score(void)
{
    /*
     * Integration: receive TEMPORARY_CHANNEL_FAILURE for a peer,
     * classify it, then penalise the peer's score in the DB.
     */
    peer_db_t db;
    ASSERT(peer_db_open_in_memory(&db), "open in-memory peer DB");

    unsigned char pk[33] = { [0 ... 31] = 0xBB, [32] = 0x02 };
    peer_db_entry_t entry;
    memcpy(entry.pubkey33, pk, 33);
    entry.address[0] = '\0'; entry.score = 500;
    entry.last_seen = 0; entry.n_channels = 1; entry.banned_until = 0;
    ASSERT(peer_db_upsert(&db, &entry), "insert peer");

    /* Simulate receiving TEMPORARY_CHANNEL_FAILURE from this peer's channel */
    uint16_t fail_code = PROBE_ERR_TEMPORARY_CHANNEL_FAILURE;
    probe_result_t result = probe_classify_failure(fail_code);
    ASSERT(result == PROBE_RESULT_LIQUIDITY_FAIL, "classified as liquidity failure");

    /* Penalise peer score by -50 for a liquidity failure */
    ASSERT(peer_db_update_score(&db, pk, -50), "score update succeeds");

    peer_db_entry_t got;
    ASSERT(peer_db_get(&db, pk, &got), "get peer after penalty");
    ASSERT(got.score == 450, "score reduced to 450");

    /* Channel disabled → heavier penalty -200 */
    fail_code = PROBE_ERR_CHANNEL_DISABLED;
    result = probe_classify_failure(fail_code);
    ASSERT(result == PROBE_RESULT_CHANNEL_FAIL, "classified as channel failure");

    ASSERT(peer_db_update_score(&db, pk, -200), "heavy penalty");
    ASSERT(peer_db_get(&db, pk, &got), "get after heavy penalty");
    ASSERT(got.score == 250, "score = 250 after heavy penalty");

    peer_db_close(&db);
    return 1;
}

/* ================================================================== */
/* IT4 — cltv_watchdog check → expire chain integration               */
/* ================================================================== */
int test_it_watchdog_expire_chain(void)
{
    /*
     * Integration: inject 3 HTLCs, run watchdog check, then expire.
     * Verify the state transitions are correct end-to-end.
     */
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                       SECP256K1_CONTEXT_VERIFY);

    /* Minimal channel setup */
    static const unsigned char lf[32] = { [0 ... 31] = 0x11 };
    static const unsigned char rf[32] = { [0 ... 31] = 0x22 };
    secp256k1_pubkey lfk, rfk;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &lfk, lf), "create lfk");
    ASSERT(secp256k1_ec_pubkey_create(ctx, &rfk, rf), "create rfk");

    unsigned char spk[34]; memset(spk, 0xAB, 34);
    unsigned char txid[32]; memset(txid, 0xCC, 32);

    channel_t ch;
    ASSERT(channel_init(&ch, ctx, lf, &lfk, &rfk,
                         txid, 0, 10000000, spk, 34,
                         5000000, 5000000,
                         CHANNEL_DEFAULT_CSV_DELAY), "channel_init");
    ch.funder_is_local = 1;

    /* Manually inject 3 inbound HTLCs at different expiry heights */
    /* HTLC 1: already expired (height 799900 < current 800000) */
    /* HTLC 2: within watchdog delta (800010 <= 800000+18=800018) */
    /* HTLC 3: safe (800200 > 800018) */
    if (ch.htlcs_cap < 3) {
        htlc_t *tmp = realloc(ch.htlcs, 8 * sizeof(htlc_t));
        if (tmp) { ch.htlcs = tmp; ch.htlcs_cap = 8; }
    }

    /* inject expired */
    ch.htlcs[0].direction = HTLC_RECEIVED; ch.htlcs[0].state = HTLC_STATE_ACTIVE;
    ch.htlcs[0].amount_sats = 100000; ch.htlcs[0].cltv_expiry = 799900;
    ch.htlcs[0].id = 1;
    memset(ch.htlcs[0].payment_hash, 0x01, 32);
    memset(ch.htlcs[0].payment_preimage, 0, 32);

    /* inject at-risk */
    ch.htlcs[1].direction = HTLC_RECEIVED; ch.htlcs[1].state = HTLC_STATE_ACTIVE;
    ch.htlcs[1].amount_sats = 100000; ch.htlcs[1].cltv_expiry = 800010;
    ch.htlcs[1].id = 2;
    memset(ch.htlcs[1].payment_hash, 0x02, 32);
    memset(ch.htlcs[1].payment_preimage, 0, 32);

    /* inject safe */
    ch.htlcs[2].direction = HTLC_RECEIVED; ch.htlcs[2].state = HTLC_STATE_ACTIVE;
    ch.htlcs[2].amount_sats = 100000; ch.htlcs[2].cltv_expiry = 800200;
    ch.htlcs[2].id = 3;
    memset(ch.htlcs[2].payment_hash, 0x03, 32);
    memset(ch.htlcs[2].payment_preimage, 0, 32);

    ch.n_htlcs = 3;
    /* credit balances so fail refunds work */
    ch.remote_amount += 3 * 100000;

    cltv_watchdog_t wd;
    cltv_watchdog_init(&wd, &ch, 0);  /* delta = 18 */

    /* Step 1: check at height 800000 → htlc 1 (expired) + htlc 2 (within 18) = 2 at risk */
    int at_risk = cltv_watchdog_check(&wd, 800000);
    ASSERT(at_risk == 2, "2 HTLCs at risk at height 800000");
    ASSERT(wd.triggered == 1, "watchdog triggered");

    /* Step 2: expire → htlc 1 (799900 <= 800000) should fail; htlc 2 (800010 > 800000) not yet */
    int expired = cltv_watchdog_expire(&wd, 800000);
    ASSERT(expired == 1, "1 HTLC expired at height 800000");

    /* After compact: htlc 1 removed, htlcs 2 and 3 remain */
    ASSERT(ch.n_htlcs == 2, "2 HTLCs remaining after compact");

    /* Step 3: check again at 800010 — htlc 2 (800010 <= 800010) now expired, htlc 3 safe */
    int at_risk2 = cltv_watchdog_check(&wd, 800010);
    ASSERT(at_risk2 == 1, "htlc 2 at risk at height 800010");

    int expired2 = cltv_watchdog_expire(&wd, 800010);
    ASSERT(expired2 == 1, "htlc 2 expired at height 800010");
    ASSERT(ch.n_htlcs == 1, "1 HTLC remaining (htlc 3)");

    /* Step 4: htlc 3 (800200) is safe at 800010 + 18 = 800028 < 800200 */
    cltv_watchdog_t wd2;
    cltv_watchdog_init(&wd2, &ch, 0);
    ASSERT(cltv_watchdog_check(&wd2, 800010) == 0, "htlc 3 still safe");

    channel_cleanup(&ch);
    secp256k1_context_destroy(ctx);
    return 1;
}
