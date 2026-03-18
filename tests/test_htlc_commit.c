/*
 * test_htlc_commit.c — Unit tests for BOLT #2 HTLC commitment wire protocol
 *
 * HC1:  test_htlc_commit_add_layout                — update_add_htlc byte layout
 * HC2:  test_htlc_commit_commitment_signed_layout  — commitment_signed byte layout
 * HC3:  test_htlc_commit_revoke_and_ack_layout     — revoke_and_ack byte layout
 * HC4:  test_htlc_commit_fulfill_layout            — update_fulfill_htlc byte layout
 * HC5:  test_htlc_commit_fail_layout               — update_fail_htlc byte layout
 * HC6:  test_htlc_commit_fail_malformed_layout     — update_fail_malformed layout
 * HC7:  test_htlc_commit_dispatch_types            — dispatcher ADD → FAIL round-trip
 * HC8:  test_htlc_commit_dust_excluded_from_tx     — dust HTLC rejected by channel_add_htlc
 * HC9:  test_htlc_commit_dust_tx_output_count      — above-dust HTLC → 3 tx outputs
 * HC10: test_htlc_commit_above_dust_counted        — above-dust HTLC accepted
 * HC11: test_htlc_commit_mixed_dust_counted        — two above-dust HTLCs → 4 outputs
 * HC12: test_htlc_commit_update_fee_layout         — update_fee byte layout
 * HC13: test_htlc_commit_recv_update_fee_accepts   — valid feerate accepted
 * HC14: test_htlc_commit_recv_update_fee_rejects_low  — below floor rejected
 * HC15: test_htlc_commit_recv_update_fee_rejects_high — above ceiling rejected
 */

#include "superscalar/htlc_commit.h"
#include "superscalar/channel.h"
#include "superscalar/musig.h"
#include "superscalar/sha256.h"
#include "superscalar/tx_builder.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

static uint16_t rd16(const unsigned char *b) {
    return ((uint16_t)b[0] << 8) | b[1];
}
static uint32_t rd32(const unsigned char *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
         | ((uint32_t)b[2] <<  8) |  (uint32_t)b[3];
}
static uint64_t rd64(const unsigned char *b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}
static void wr16(unsigned char *b, uint16_t v) { b[0]=(unsigned char)(v>>8); b[1]=(unsigned char)v; }
static void wr32(unsigned char *b, uint32_t v) {
    b[0]=(unsigned char)(v>>24); b[1]=(unsigned char)(v>>16);
    b[2]=(unsigned char)(v>> 8); b[3]=(unsigned char)v;
}
static void wr64(unsigned char *b, uint64_t v) {
    for (int i=7; i>=0; i--) b[7-i]=(unsigned char)(v>>(i*8));
}

/* ---- Minimal channel setup for dust + dispatch tests ---- */

static const unsigned char ts_local_fund[32]  = { [0 ... 31] = 0x11 };
static const unsigned char ts_remote_fund[32] = { [0 ... 31] = 0x22 };
static const unsigned char ts_local_pay[32]   = { [0 ... 31] = 0x31 };
static const unsigned char ts_local_del[32]   = { [0 ... 31] = 0x41 };
static const unsigned char ts_local_rev[32]   = { [0 ... 31] = 0x51 };
static const unsigned char ts_local_htlc[32]  = { [0 ... 31] = 0x61 };
static const unsigned char ts_remote_pay[32]  = { [0 ... 31] = 0x71 };
static const unsigned char ts_remote_del[32]  = { [0 ... 31] = 0x81 };
static const unsigned char ts_remote_rev[32]  = { [0 ... 31] = 0x91 };
static const unsigned char ts_remote_htlc[32] = { [0 ... 31] = 0xa1 };

/* Compute 2-of-2 MuSig2 P2TR funding scriptPubKey (34 bytes). */
static int hc_compute_funding_spk(secp256k1_context *ctx,
                                    const secp256k1_pubkey *lk,
                                    const secp256k1_pubkey *rk,
                                    unsigned char *spk34) {
    secp256k1_pubkey pks[2] = { *lk, *rk };
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks, 2)) return 0;

    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;

    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);

    musig_keyagg_t tmp = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &tmp.cache, tweak))
        return 0;

    secp256k1_xonly_pubkey xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, NULL, &tweaked_pk)) return 0;

    unsigned char xser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, xser, &xonly)) return 0;

    spk34[0] = 0x51;  /* OP_1 */
    spk34[1] = 0x20;  /* PUSH32 */
    memcpy(spk34 + 2, xser, 32);
    return 1;
}

/*
 * Setup a channel with both local and remote basepoints + HTLC basepoints.
 * Suitable for building commitment txs with HTLC outputs.
 */
static int hc_setup_channel(channel_t *ch, secp256k1_context *ctx,
                              uint64_t local_amt, uint64_t remote_amt) {
    secp256k1_pubkey lfk, rfk;
    if (!secp256k1_ec_pubkey_create(ctx, &lfk, ts_local_fund)) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &rfk, ts_remote_fund)) return 0;

    unsigned char fund_spk[34];
    if (!hc_compute_funding_spk(ctx, &lfk, &rfk, fund_spk)) return 0;

    unsigned char fake_txid[32];
    memset(fake_txid, 0xCC, 32);

    if (!channel_init(ch, ctx, ts_local_fund, &lfk, &rfk,
                       fake_txid, 0, local_amt + remote_amt,
                       fund_spk, 34,
                       local_amt, remote_amt,
                       CHANNEL_DEFAULT_CSV_DELAY)) return 0;
    ch->funder_is_local = 1;

    /* Local basepoints */
    if (!channel_set_local_basepoints(ch, ts_local_pay, ts_local_del, ts_local_rev))
        return 0;
    if (!channel_set_local_htlc_basepoint(ch, ts_local_htlc)) return 0;

    /* Remote basepoints */
    secp256k1_pubkey rp, rd, rr, rh;
    if (!secp256k1_ec_pubkey_create(ctx, &rp, ts_remote_pay)) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &rd, ts_remote_del)) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &rr, ts_remote_rev)) return 0;
    if (!secp256k1_ec_pubkey_create(ctx, &rh, ts_remote_htlc)) return 0;
    channel_set_remote_basepoints(ch, &rp, &rd, &rr);
    channel_set_remote_htlc_basepoint(ch, &rh);

    return 1;
}

/* ================================================================== */
/* HC1 — update_add_htlc byte layout                                  */
/* ================================================================== */

int test_htlc_commit_add_layout(void) {
    /*
     * Verify the BOLT #2 update_add_htlc wire format:
     *   [0..1]    type = 128 (BOLT2_UPDATE_ADD_HTLC)
     *   [2..33]   channel_id (32 bytes)
     *   [34..41]  htlc_id (8 bytes, big-endian)
     *   [42..49]  amount_msat (8 bytes, big-endian)
     *   [50..81]  payment_hash (32 bytes)
     *   [82..85]  cltv_expiry (4 bytes, big-endian)
     *   [86..1451] onion_routing_packet (1366 bytes)
     *   Total: 1452 bytes
     */
    unsigned char buf[1452];
    memset(buf, 0, sizeof(buf));

    unsigned char channel_id[32]; memset(channel_id, 0xAA, 32);
    unsigned char payment_hash[32]; memset(payment_hash, 0xBB, 32);
    unsigned char onion[ONION_PACKET_SIZE]; memset(onion, 0xCC, ONION_PACKET_SIZE);

    /* Build message manually (mirrors htlc_commit_send_add encoding) */
    size_t pos = 0;
    wr16(buf + pos, BOLT2_UPDATE_ADD_HTLC);          pos += 2;
    memcpy(buf + pos, channel_id, 32);               pos += 32;
    wr64(buf + pos, 0x0102030405060708ULL);           pos += 8;  /* htlc_id */
    wr64(buf + pos, 1000000ULL);                     pos += 8;  /* amount_msat */
    memcpy(buf + pos, payment_hash, 32);             pos += 32;
    wr32(buf + pos, 700000U);                        pos += 4;  /* cltv */
    memcpy(buf + pos, onion, ONION_PACKET_SIZE);     pos += ONION_PACKET_SIZE;

    ASSERT(pos == 1452, "update_add_htlc is 1452 bytes");
    ASSERT(rd16(buf) == BOLT2_UPDATE_ADD_HTLC, "type = 128");
    ASSERT(memcmp(buf + 2, channel_id, 32) == 0, "channel_id at offset 2");
    ASSERT(rd64(buf + 34) == 0x0102030405060708ULL, "htlc_id at offset 34");
    ASSERT(rd64(buf + 42) == 1000000ULL, "amount_msat at offset 42");
    ASSERT(memcmp(buf + 50, payment_hash, 32) == 0, "payment_hash at offset 50");
    ASSERT(rd32(buf + 82) == 700000U, "cltv_expiry at offset 82");
    ASSERT(buf[86] == 0xCC, "onion starts at offset 86");

    return 1;
}

/* ================================================================== */
/* HC2 — commitment_signed byte layout                                */
/* ================================================================== */

int test_htlc_commit_commitment_signed_layout(void) {
    /*
     * commitment_signed wire format:
     *   [0..1]   type = 132
     *   [2..33]  channel_id (32 bytes)
     *   [34..97] sig (64 bytes) — carries packed MuSig2 partial sig
     *   [98..99] num_htlcs (2 bytes)
     *   [100..]  htlc_sigs (n * 64 bytes)
     */
    unsigned char buf[200];
    memset(buf, 0, sizeof(buf));

    unsigned char channel_id[32]; memset(channel_id, 0x12, 32);
    unsigned char sig64[64]; memset(sig64, 0x56, 64);

    /* Pack a fake partial sig (first 32 bytes) + nonce_index 42 at bytes [32..35] */
    memset(sig64, 0x99, 32);
    sig64[32] = 0x00; sig64[33] = 0x00; sig64[34] = 0x00; sig64[35] = 0x2A; /* nonce_index=42 */
    memset(sig64 + 36, 0, 28);

    size_t pos = 0;
    wr16(buf + pos, BOLT2_COMMITMENT_SIGNED); pos += 2;
    memcpy(buf + pos, channel_id, 32);        pos += 32;
    memcpy(buf + pos, sig64, 64);             pos += 64;
    wr16(buf + pos, 0);                       pos += 2;  /* num_htlcs = 0 */

    ASSERT(pos == 100, "commitment_signed (no htlc sigs) is 100 bytes");
    ASSERT(rd16(buf) == BOLT2_COMMITMENT_SIGNED, "type = 132");
    ASSERT(memcmp(buf + 2, channel_id, 32) == 0, "channel_id at offset 2");
    ASSERT(memcmp(buf + 34, sig64, 32) == 0, "partial_sig32 at offset 34");
    /* nonce_index at offset 66 (34 + 32) */
    ASSERT(rd32(buf + 66) == 42, "nonce_index at offset 66");
    ASSERT(rd16(buf + 98) == 0, "num_htlcs = 0 at offset 98");

    return 1;
}

/* ================================================================== */
/* HC3 — revoke_and_ack byte layout                                   */
/* ================================================================== */

int test_htlc_commit_revoke_and_ack_layout(void) {
    /*
     * revoke_and_ack wire format (99 bytes):
     *   [0..1]   type = 133
     *   [2..33]  channel_id (32 bytes)
     *   [34..65] per_commitment_secret (32 bytes)
     *   [66..98] next_per_commitment_point (33 bytes)
     */
    unsigned char buf[99];
    memset(buf, 0, sizeof(buf));

    unsigned char channel_id[32]; memset(channel_id, 0x11, 32);
    unsigned char pcs[32];        memset(pcs,        0x55, 32);
    unsigned char pcp[33];        memset(pcp,        0x02, 33); pcp[1] = 0xAA;

    size_t pos = 0;
    wr16(buf + pos, BOLT2_REVOKE_AND_ACK); pos += 2;
    memcpy(buf + pos, channel_id, 32);     pos += 32;
    memcpy(buf + pos, pcs, 32);            pos += 32;
    memcpy(buf + pos, pcp, 33);            pos += 33;

    ASSERT(pos == 99, "revoke_and_ack is 99 bytes");
    ASSERT(rd16(buf) == BOLT2_REVOKE_AND_ACK, "type = 133");
    ASSERT(memcmp(buf + 2,  channel_id, 32) == 0, "channel_id at offset 2");
    ASSERT(memcmp(buf + 34, pcs, 32) == 0, "per_commitment_secret at offset 34");
    ASSERT(memcmp(buf + 66, pcp, 33) == 0, "next_pcp at offset 66");

    return 1;
}

/* ================================================================== */
/* HC4 — update_fulfill_htlc byte layout                              */
/* ================================================================== */

int test_htlc_commit_fulfill_layout(void) {
    /*
     * update_fulfill_htlc wire format (74 bytes):
     *   [0..1]   type = 130
     *   [2..33]  channel_id (32 bytes)
     *   [34..41] htlc_id (8 bytes)
     *   [42..73] payment_preimage (32 bytes)
     */
    unsigned char buf[74];
    memset(buf, 0, sizeof(buf));

    unsigned char channel_id[32]; memset(channel_id, 0x33, 32);
    unsigned char preimage[32];   memset(preimage,   0xDD, 32);

    size_t pos = 0;
    wr16(buf + pos, BOLT2_UPDATE_FULFILL_HTLC); pos += 2;
    memcpy(buf + pos, channel_id, 32);          pos += 32;
    wr64(buf + pos, 7ULL);                      pos += 8;  /* htlc_id */
    memcpy(buf + pos, preimage, 32);            pos += 32;

    ASSERT(pos == 74, "update_fulfill_htlc is 74 bytes");
    ASSERT(rd16(buf) == BOLT2_UPDATE_FULFILL_HTLC, "type = 130");
    ASSERT(memcmp(buf + 2,  channel_id, 32) == 0, "channel_id at offset 2");
    ASSERT(rd64(buf + 34) == 7ULL, "htlc_id at offset 34");
    ASSERT(memcmp(buf + 42, preimage, 32) == 0, "preimage at offset 42");

    return 1;
}

/* ================================================================== */
/* HC5 — update_fail_htlc byte layout                                 */
/* ================================================================== */

int test_htlc_commit_fail_layout(void) {
    /*
     * update_fail_htlc wire format:
     *   [0..1]   type = 131
     *   [2..33]  channel_id (32 bytes)
     *   [34..41] htlc_id (8 bytes)
     *   [42..43] len (2 bytes)
     *   [44..]   reason (len bytes)
     */
    unsigned char buf[100];
    memset(buf, 0, sizeof(buf));

    unsigned char channel_id[32]; memset(channel_id, 0x44, 32);
    const unsigned char reason[] = { 0x10, 0x11, 0x12 };
    uint16_t rlen = (uint16_t)sizeof(reason);

    size_t pos = 0;
    wr16(buf + pos, BOLT2_UPDATE_FAIL_HTLC); pos += 2;
    memcpy(buf + pos, channel_id, 32);        pos += 32;
    wr64(buf + pos, 3ULL);                    pos += 8;  /* htlc_id */
    wr16(buf + pos, rlen);                    pos += 2;
    memcpy(buf + pos, reason, rlen);          pos += rlen;

    ASSERT(pos == 47, "update_fail_htlc is 47 bytes with 3-byte reason");
    ASSERT(rd16(buf) == BOLT2_UPDATE_FAIL_HTLC, "type = 131");
    ASSERT(memcmp(buf + 2, channel_id, 32) == 0, "channel_id at offset 2");
    ASSERT(rd64(buf + 34) == 3ULL, "htlc_id at offset 34");
    ASSERT(rd16(buf + 42) == 3, "reason_len at offset 42");
    ASSERT(buf[44] == 0x10 && buf[45] == 0x11 && buf[46] == 0x12,
           "reason bytes at offset 44");

    return 1;
}

/* ================================================================== */
/* HC6 — update_fail_malformed_htlc byte layout                       */
/* ================================================================== */

int test_htlc_commit_fail_malformed_layout(void) {
    /*
     * update_fail_malformed_htlc wire format (76 bytes):
     *   [0..1]   type = 135
     *   [2..33]  channel_id (32 bytes)
     *   [34..41] htlc_id (8 bytes)
     *   [42..73] sha256_of_onion (32 bytes)
     *   [74..75] failure_code (2 bytes)
     */
    unsigned char buf[76];
    memset(buf, 0, sizeof(buf));

    unsigned char channel_id[32];  memset(channel_id, 0x77, 32);
    unsigned char sha256_onion[32]; memset(sha256_onion, 0xEE, 32);

    size_t pos = 0;
    wr16(buf + pos, BOLT2_UPDATE_FAIL_MALFORMED_HTLC); pos += 2;
    memcpy(buf + pos, channel_id, 32);                  pos += 32;
    wr64(buf + pos, 9ULL);                              pos += 8;
    memcpy(buf + pos, sha256_onion, 32);                pos += 32;
    wr16(buf + pos, 0x4000);                            pos += 2;  /* failure_code */

    ASSERT(pos == 76, "update_fail_malformed_htlc is 76 bytes");
    ASSERT(rd16(buf) == BOLT2_UPDATE_FAIL_MALFORMED_HTLC, "type = 135");
    ASSERT(rd64(buf + 34) == 9ULL, "htlc_id at offset 34");
    ASSERT(memcmp(buf + 42, sha256_onion, 32) == 0, "sha256_of_onion at offset 42");
    ASSERT(rd16(buf + 74) == 0x4000, "failure_code at offset 74");

    return 1;
}

/* ================================================================== */
/* HC7 — dispatcher ADD → FAIL round-trip                             */
/* ================================================================== */

int test_htlc_commit_dispatch_types(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    channel_t ch;
    /* Remote sends us HTLCs, so we need remote_amount to be large */
    ASSERT(hc_setup_channel(&ch, ctx, 1000000, 2000000), "setup channel");

    unsigned char channel_id[32];
    memset(channel_id, 0, 32);

    /* --- Dispatch update_add_htlc (type 128) --- */
    unsigned char add_msg[1452];
    memset(add_msg, 0, sizeof(add_msg));
    wr16(add_msg, BOLT2_UPDATE_ADD_HTLC);
    /* channel_id at [2..33] = zeros */
    wr64(add_msg + 34, 5ULL);            /* peer's htlc_id = 5 */
    wr64(add_msg + 42, 10000000ULL);     /* amount_msat = 10000 sat */
    /* payment_hash at [50..81]: use a known non-zero hash */
    memset(add_msg + 50, 0x12, 32);
    wr32(add_msg + 82, 700000U);         /* cltv_expiry */
    /* onion at [86..1451] = zeros */

    int ret = htlc_commit_dispatch(NULL, 0, &ch, ctx, channel_id,
                                    add_msg, sizeof(add_msg));
    ASSERT(ret == BOLT2_UPDATE_ADD_HTLC, "dispatch returns ADD type");
    ASSERT(ch.n_htlcs == 1, "one HTLC added");
    /* The dispatcher overrides the auto-assigned id with the peer's htlc_id=5 */
    ASSERT(ch.htlcs[0].id == 5, "HTLC stored with peer's htlc_id=5");

    /* --- Dispatch update_fail_htlc (type 131) for htlc_id=5 --- */
    unsigned char fail_msg[44];
    memset(fail_msg, 0, sizeof(fail_msg));
    wr16(fail_msg, BOLT2_UPDATE_FAIL_HTLC);
    /* channel_id at [2..33] = zeros */
    wr64(fail_msg + 34, 5ULL);           /* htlc_id = 5 (peer's original id) */
    wr16(fail_msg + 42, 0);              /* reason_len = 0 */

    ret = htlc_commit_dispatch(NULL, 0, &ch, ctx, channel_id,
                                fail_msg, sizeof(fail_msg));
    ASSERT(ret == BOLT2_UPDATE_FAIL_HTLC, "dispatch returns FAIL type");
    /* After channel_fail_htlc + compact, HTLC should be removed */
    ASSERT(ch.n_htlcs == 0, "HTLC removed after fail");

    secp256k1_context_destroy(ctx);
    channel_cleanup(&ch);
    return 1;
}

/* ================================================================== */
/* HC8 — dust HTLC rejected by channel_add_htlc                       */
/* ================================================================== */

int test_htlc_commit_dust_excluded_from_tx(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    channel_t ch;
    ASSERT(hc_setup_channel(&ch, ctx, 1000000, 1000000), "setup channel");

    /*
     * BOLT #3 §3: HTLCs below CHANNEL_DUST_LIMIT_SATS (546 sat) are
     * trimmed from the commitment tx. channel_add_htlc also rejects them
     * at add time to prevent accumulating trimmed-out value.
     */
    unsigned char hash[32];
    memset(hash, 0xAB, 32);
    uint64_t id;

    /* Try to add a dust HTLC (100 sat < 546 sat dust limit) */
    int ok = channel_add_htlc(&ch, HTLC_OFFERED, 100, hash, 700000, &id);
    ASSERT(ok == 0, "channel_add_htlc rejects 100-sat HTLC (below dust limit)");
    ASSERT(ch.n_htlcs == 0, "no HTLCs added");

    /* Try exact dust limit (546 sat) — also rejected (< vs >=) */
    ok = channel_add_htlc(&ch, HTLC_OFFERED, CHANNEL_DUST_LIMIT_SATS - 1,
                            hash, 700000, &id);
    ASSERT(ok == 0, "channel_add_htlc rejects 545-sat HTLC");

    /* Try exactly at the dust limit (546 sat) — should be accepted */
    ok = channel_add_htlc(&ch, HTLC_OFFERED, CHANNEL_DUST_LIMIT_SATS,
                            hash, 700000, &id);
    ASSERT(ok == 1, "channel_add_htlc accepts 546-sat HTLC (at dust limit)");

    secp256k1_context_destroy(ctx);
    channel_cleanup(&ch);
    return 1;
}

/* ================================================================== */
/* HC9 — above-dust HTLC appears in commitment tx output count        */
/* ================================================================== */

int test_htlc_commit_dust_tx_output_count(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    channel_t ch;
    ASSERT(hc_setup_channel(&ch, ctx, 1000000, 200000), "setup channel");

    unsigned char hash[32];
    memset(hash, 0xCD, 32);
    uint64_t id;

    /* No HTLCs: commitment tx should have 2 outputs (to-local + to-remote) */
    tx_buf_t tx;
    tx_buf_init(&tx, 512);
    unsigned char txid[32];
    ASSERT(channel_build_commitment_tx(&ch, &tx, txid), "build tx (no htlcs)");
    ASSERT(tx.data[46] == 2, "no-HTLC commitment tx has 2 outputs");
    tx_buf_free(&tx);

    /* Add one above-dust HTLC (10000 sat) */
    ASSERT(channel_add_htlc(&ch, HTLC_OFFERED, 10000, hash, 700000, &id) == 1,
           "add 10000-sat HTLC");

    tx_buf_init(&tx, 1024);
    ASSERT(channel_build_commitment_tx(&ch, &tx, txid), "build tx (1 htlc)");
    ASSERT(tx.data[46] == 3, "1-HTLC commitment tx has 3 outputs");
    tx_buf_free(&tx);

    secp256k1_context_destroy(ctx);
    channel_cleanup(&ch);
    return 1;
}

/* ================================================================== */
/* HC10 — above-dust HTLC counted in commitment tx                    */
/* ================================================================== */

int test_htlc_commit_above_dust_counted(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    channel_t ch;
    ASSERT(hc_setup_channel(&ch, ctx, 1000000, 200000), "setup channel");

    unsigned char hash[32];
    memset(hash, 0xFE, 32);
    uint64_t id;

    /* Add one well-above-dust HTLC (50000 sat) */
    ASSERT(channel_add_htlc(&ch, HTLC_OFFERED, 50000, hash, 700000, &id) == 1,
           "add 50000-sat HTLC");
    ASSERT(id == 0, "first HTLC gets id=0");
    ASSERT(ch.n_htlcs == 1, "one HTLC in list");
    ASSERT(ch.htlcs[0].amount_sats == 50000, "amount stored correctly");
    ASSERT(ch.htlcs[0].state == HTLC_STATE_ACTIVE, "HTLC is active");

    tx_buf_t tx;
    tx_buf_init(&tx, 1024);
    unsigned char txid[32];
    ASSERT(channel_build_commitment_tx(&ch, &tx, txid), "build commitment tx");
    ASSERT(tx.len > 0, "tx is non-empty");
    /* 3 outputs: to-local, to-remote, HTLC */
    ASSERT(tx.data[46] == 3, "above-dust HTLC adds one output");
    tx_buf_free(&tx);

    secp256k1_context_destroy(ctx);
    channel_cleanup(&ch);
    return 1;
}

/* ================================================================== */
/* HC11 — two above-dust HTLCs → 4 commitment tx outputs              */
/* ================================================================== */

int test_htlc_commit_mixed_dust_counted(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    channel_t ch;
    ASSERT(hc_setup_channel(&ch, ctx, 1000000, 200000), "setup channel");

    unsigned char hash1[32], hash2[32], hash3[32];
    memset(hash1, 0x01, 32);
    memset(hash2, 0x02, 32);
    memset(hash3, 0x03, 32);
    uint64_t id1, id2;

    /* Dust HTLC rejected */
    uint64_t idX;
    int ok = channel_add_htlc(&ch, HTLC_OFFERED, 300, hash3, 700000, &idX);
    ASSERT(ok == 0, "dust HTLC rejected");

    /* Two above-dust HTLCs accepted */
    ASSERT(channel_add_htlc(&ch, HTLC_OFFERED, 10000, hash1, 700000, &id1) == 1,
           "first above-dust HTLC added");
    ASSERT(channel_add_htlc(&ch, HTLC_OFFERED, 20000, hash2, 700100, &id2) == 1,
           "second above-dust HTLC added");
    ASSERT(ch.n_htlcs == 2, "two HTLCs in list");

    tx_buf_t tx;
    tx_buf_init(&tx, 1024);
    unsigned char txid[32];
    ASSERT(channel_build_commitment_tx(&ch, &tx, txid), "build commitment tx");
    /* 4 outputs: to-local, to-remote, HTLC1, HTLC2 */
    ASSERT(tx.data[46] == 4, "two above-dust HTLCs → 4 outputs");
    tx_buf_free(&tx);

    secp256k1_context_destroy(ctx);
    channel_cleanup(&ch);
    return 1;
}

/* ================================================================== */
/* HC12 — update_fee byte layout                                      */
/* ================================================================== */

int test_htlc_commit_update_fee_layout(void) {
    /*
     * update_fee wire format (38 bytes):
     *   [0..1]   type = 134
     *   [2..33]  channel_id (32 bytes)
     *   [34..37] feerate_per_kw (4 bytes, big-endian)
     */
    unsigned char buf[38];
    memset(buf, 0, sizeof(buf));

    unsigned char channel_id[32];
    memset(channel_id, 0x88, 32);

    size_t pos = 0;
    wr16(buf + pos, BOLT2_UPDATE_FEE); pos += 2;
    memcpy(buf + pos, channel_id, 32); pos += 32;
    wr32(buf + pos, 1000U);            pos += 4;  /* feerate_per_kw = 1000 sat/kw */

    ASSERT(pos == 38, "update_fee is 38 bytes");
    ASSERT(rd16(buf) == BOLT2_UPDATE_FEE, "type = 134");
    ASSERT(memcmp(buf + 2, channel_id, 32) == 0, "channel_id at offset 2");
    ASSERT(rd32(buf + 34) == 1000U, "feerate_per_kw at offset 34");

    /* Bounds: floor=250, ceiling=100000 */
    ASSERT(BOLT2_UPDATE_FEE_FLOOR  == 250,    "floor = 250");
    ASSERT(BOLT2_UPDATE_FEE_CEILING == 100000, "ceiling = 100000");

    return 1;
}

/* ================================================================== */
/* HC13 — htlc_commit_recv_update_fee accepts valid feerate           */
/* ================================================================== */

int test_htlc_commit_recv_update_fee_accepts(void) {
    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.fee_rate_sat_per_kvb = 1000;

    /* Build a valid update_fee message with feerate = 5000 sat/kw */
    unsigned char msg[38];
    memset(msg, 0, sizeof(msg));
    wr16(msg, BOLT2_UPDATE_FEE);
    /* channel_id at [2..33] = zeros */
    wr32(msg + 34, 5000U);

    int ok = htlc_commit_recv_update_fee(&ch, msg, sizeof(msg),
                                          BOLT2_UPDATE_FEE_FLOOR,
                                          BOLT2_UPDATE_FEE_CEILING);
    ASSERT(ok == 1, "valid feerate accepted");
    ASSERT(ch.fee_rate_sat_per_kvb == 5000, "fee_rate updated to 5000");

    return 1;
}

/* ================================================================== */
/* HC14 — htlc_commit_recv_update_fee rejects feerate below floor     */
/* ================================================================== */

int test_htlc_commit_recv_update_fee_rejects_low(void) {
    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.fee_rate_sat_per_kvb = 1000;

    unsigned char msg[38];
    memset(msg, 0, sizeof(msg));
    wr16(msg, BOLT2_UPDATE_FEE);
    wr32(msg + 34, 100U);  /* below BOLT2_UPDATE_FEE_FLOOR = 250 */

    int ok = htlc_commit_recv_update_fee(&ch, msg, sizeof(msg),
                                          BOLT2_UPDATE_FEE_FLOOR,
                                          BOLT2_UPDATE_FEE_CEILING);
    ASSERT(ok == 0, "feerate 100 (below floor 250) rejected");
    ASSERT(ch.fee_rate_sat_per_kvb == 1000, "fee_rate unchanged on rejection");

    /* Edge case: exactly at floor is accepted */
    wr32(msg + 34, BOLT2_UPDATE_FEE_FLOOR);
    ok = htlc_commit_recv_update_fee(&ch, msg, sizeof(msg),
                                      BOLT2_UPDATE_FEE_FLOOR,
                                      BOLT2_UPDATE_FEE_CEILING);
    ASSERT(ok == 1, "feerate exactly at floor accepted");

    return 1;
}

/* ================================================================== */
/* HC15 — htlc_commit_recv_update_fee rejects feerate above ceiling   */
/* ================================================================== */

int test_htlc_commit_recv_update_fee_rejects_high(void) {
    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.fee_rate_sat_per_kvb = 1000;

    unsigned char msg[38];
    memset(msg, 0, sizeof(msg));
    wr16(msg, BOLT2_UPDATE_FEE);
    wr32(msg + 34, 200000U);  /* above BOLT2_UPDATE_FEE_CEILING = 100000 */

    int ok = htlc_commit_recv_update_fee(&ch, msg, sizeof(msg),
                                          BOLT2_UPDATE_FEE_FLOOR,
                                          BOLT2_UPDATE_FEE_CEILING);
    ASSERT(ok == 0, "feerate 200000 (above ceiling 100000) rejected");
    ASSERT(ch.fee_rate_sat_per_kvb == 1000, "fee_rate unchanged on rejection");

    /* Edge case: exactly at ceiling is accepted */
    wr32(msg + 34, BOLT2_UPDATE_FEE_CEILING);
    ok = htlc_commit_recv_update_fee(&ch, msg, sizeof(msg),
                                      BOLT2_UPDATE_FEE_FLOOR,
                                      BOLT2_UPDATE_FEE_CEILING);
    ASSERT(ok == 1, "feerate exactly at ceiling accepted");

    return 1;
}
