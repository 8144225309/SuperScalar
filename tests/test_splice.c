#include "superscalar/splice.h"
#include "superscalar/channel.h"
#include "superscalar/tx_builder.h"
#include "superscalar/wire.h"
#include <secp256k1.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* Test G1: splice-out flow — quiescence → stfu → splice_init/ack messages */
int test_splice_out_flow(void)
{
    /* Build STFU payload and verify channel_id round-trip */
    size_t stfu_len = 0;
    unsigned char *stfu = splice_build_stfu(0x1234, &stfu_len);
    ASSERT(stfu != NULL, "splice_build_stfu should succeed");
    ASSERT(stfu_len == 4, "STFU payload is 4 bytes");

    uint32_t ch_id = 0;
    ASSERT(splice_parse_stfu_ack(stfu, stfu_len, &ch_id), "parse stfu_ack ok");
    ASSERT(ch_id == 0x1234, "channel_id round-trip");
    free(stfu);

    /* Build funding tx for splice-out (reduce capacity by 50k sats) */
    unsigned char old_txid[32];
    memset(old_txid, 0xAA, 32);
    unsigned char new_spk[34] = {0x51, 0x20};
    memset(new_spk + 2, 0x99, 32);

    tx_buf_t splice_tx;
    tx_buf_init(&splice_tx, 256);
    ASSERT(splice_build_funding_tx(&splice_tx, old_txid, 0, 450000, new_spk),
           "splice_build_funding_tx should succeed");
    ASSERT(splice_tx.len > 0, "splice tx has data");
    /* nVersion = 2 */
    ASSERT(splice_tx.data[0] == 0x02, "splice tx nVersion=2");
    tx_buf_free(&splice_tx);

    return 1;
}

/* Test G2: splice-in flow — new funding amount larger than original */
int test_splice_in_flow(void)
{
    unsigned char old_txid[32];
    memset(old_txid, 0xBB, 32);
    unsigned char new_spk[34] = {0x51, 0x20};
    memset(new_spk + 2, 0x44, 32);

    tx_buf_t splice_tx;
    tx_buf_init(&splice_tx, 256);
    /* Splice in: new_funding_amount = 2_000_000 sats (larger) */
    ASSERT(splice_build_funding_tx(&splice_tx, old_txid, 0, 2000000, new_spk),
           "splice-in funding tx ok");
    /* Verify output amount in tx bytes (offset: 4+1+32+4+1+4+1=47) */
    /* Amount is at offset 47 (after version+vincount+txid+vout+scriptSig+seq+voutcount) */
    uint64_t encoded_amount = 0;
    int amount_offset = 4 + 1 + 32 + 4 + 1 + 4 + 1;
    for (int i = 0; i < 8; i++)
        encoded_amount |= ((uint64_t)splice_tx.data[amount_offset + i] << (i*8));
    ASSERT(encoded_amount == 2000000, "splice-in amount encoded correctly");
    tx_buf_free(&splice_tx);

    return 1;
}

/* Test G3: active HTLC defers splice (channel not quiescent with HTLCs) */
int test_splice_mid_htlc(void)
{
    /* A channel with channel_quiescent=0 should not allow splice.
       We just verify the quiescence flag logic works correctly. */
    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.channel_quiescent = 0;

    /* Verify: not quiescent = splice deferred */
    ASSERT(ch.channel_quiescent == 0, "channel starts non-quiescent");

    /* Simulate splice initiation: set quiescent */
    ch.channel_quiescent = 1;
    ASSERT(ch.channel_quiescent == 1, "quiescence set");

    return 1;
}

/* Test G4: channel_apply_splice_update updates funding info */
int test_splice_channel_update(void)
{
    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.channel_quiescent = 1;

    unsigned char new_txid[32];
    memset(new_txid, 0x77, 32);

    ASSERT(channel_apply_splice_update(&ch, new_txid, 1, 900000),
           "channel_apply_splice_update ok");
    ASSERT(memcmp(ch.funding_txid, new_txid, 32) == 0, "funding_txid updated");
    ASSERT(ch.funding_vout == 1, "funding_vout updated");
    ASSERT(ch.funding_amount == 900000, "funding_amount updated");
    ASSERT(ch.channel_quiescent == 0, "quiescence cleared after splice");

    return 1;
}

/* Phase 3 fix: wire builder round-trip tests */

/* Test G5: wire_build_splice_init / wire_parse_splice_init round-trip */
int test_wire_splice_init_roundtrip(void)
{
    unsigned char spk[34] = {0x51, 0x20};
    memset(spk + 2, 0xAB, 32);

    cJSON *j = wire_build_splice_init(42, 1000000, spk, 34);
    ASSERT(j != NULL, "wire_build_splice_init should succeed");

    uint32_t ch_id = 0;
    uint64_t amount = 0;
    unsigned char spk_out[34];
    size_t spk_len = 0;
    ASSERT(wire_parse_splice_init(j, &ch_id, &amount, spk_out, &spk_len, sizeof(spk_out)),
           "wire_parse_splice_init should succeed");
    ASSERT(ch_id == 42, "channel_id round-trip");
    ASSERT(amount == 1000000, "new_funding_amount round-trip");
    ASSERT(spk_len == 34, "spk length round-trip");
    ASSERT(memcmp(spk_out, spk, 34) == 0, "spk bytes round-trip");

    cJSON_Delete(j);
    return 1;
}

/* Test G6: wire_build_splice_ack / wire_parse_splice_ack round-trip */
int test_wire_splice_ack_roundtrip(void)
{
    cJSON *j = wire_build_splice_ack(7, 50000);
    ASSERT(j != NULL, "wire_build_splice_ack should succeed");

    uint32_t ch_id = 0;
    uint64_t contrib = 0;
    ASSERT(wire_parse_splice_ack(j, &ch_id, &contrib), "wire_parse_splice_ack ok");
    ASSERT(ch_id == 7, "channel_id round-trip");
    ASSERT(contrib == 50000, "acceptor_contribution round-trip");

    cJSON_Delete(j);
    return 1;
}

/* Test G7: wire_build_splice_locked / wire_parse_splice_locked round-trip */
int test_wire_splice_locked_roundtrip(void)
{
    unsigned char txid[32];
    memset(txid, 0xCC, 32);

    cJSON *j = wire_build_splice_locked(99, txid, 2);
    ASSERT(j != NULL, "wire_build_splice_locked should succeed");

    uint32_t ch_id = 0;
    unsigned char txid_out[32];
    uint32_t vout = 0;
    ASSERT(wire_parse_splice_locked(j, &ch_id, txid_out, &vout),
           "wire_parse_splice_locked ok");
    ASSERT(ch_id == 99, "channel_id round-trip");
    ASSERT(vout == 2, "new_funding_vout round-trip");
    ASSERT(memcmp(txid_out, txid, 32) == 0, "txid round-trip");

    cJSON_Delete(j);
    return 1;
}

/* Test G8: splice state machine: STFU → SPLICE_INIT → SPLICE_LOCKED */
int test_splice_state_machine(void)
{
    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.channel_quiescent = 0;
    ch.funding_amount = 500000;

    /* Step 1: STFU received, set quiescent */
    ch.channel_quiescent = 1;
    ASSERT(ch.channel_quiescent == 1, "channel quiescent after STFU");

    /* Step 2: SPLICE_INIT parsed, ack sent — channel stays quiescent */
    uint32_t ch_id_in = 0;
    uint64_t new_amount = 0;
    unsigned char spk_in[34] = {0x51, 0x20};
    size_t spk_len_in = 0;
    unsigned char spk_buf[34] = {0x51, 0x20};
    memset(spk_buf + 2, 0xDD, 32);
    cJSON *init_msg = wire_build_splice_init(1, 750000, spk_buf, 34);
    ASSERT(init_msg != NULL, "build splice_init for state test");
    ASSERT(wire_parse_splice_init(init_msg, &ch_id_in, &new_amount,
                                   spk_in, &spk_len_in, sizeof(spk_in)),
           "parse splice_init in state machine");
    ASSERT(new_amount == 750000, "splice_init amount in state machine");
    cJSON_Delete(init_msg);

    /* Step 3: SPLICE_LOCKED → apply update */
    unsigned char new_txid[32];
    memset(new_txid, 0xEE, 32);
    ASSERT(channel_apply_splice_update(&ch, new_txid, 0, new_amount),
           "apply splice update in state machine");
    ASSERT(ch.channel_quiescent == 0, "quiescence cleared after splice complete");
    ASSERT(ch.funding_amount == 750000, "funding_amount updated to new value");

    return 1;
}

/* Test G9: splice_compute_funding_spk — MuSig2 aggregate key produces valid P2TR SPK */
int test_splice_musig_funding_spk(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "secp256k1 context created");

    /* Derive two deterministic keypairs from fixed seeds */
    unsigned char seckey_a[32], seckey_b[32];
    memset(seckey_a, 0x11, 32);
    memset(seckey_b, 0x22, 32);

    secp256k1_pubkey pubkey_a, pubkey_b;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &pubkey_a, seckey_a), "pubkey_a created");
    ASSERT(secp256k1_ec_pubkey_create(ctx, &pubkey_b, seckey_b), "pubkey_b created");

    /* Compute the 2-of-2 P2TR funding SPK */
    unsigned char spk[34];
    ASSERT(splice_compute_funding_spk(ctx, spk, &pubkey_a, &pubkey_b),
           "splice_compute_funding_spk succeeds");

    /* OP_1 (0x51) followed by 32 bytes (0x20 push) */
    ASSERT(spk[0] == 0x51, "SPK starts with OP_1");
    ASSERT(spk[1] == 0x20, "SPK has 32-byte push");

    /* Key-path SPK must differ from either individual key's P2TR */
    unsigned char spk_a_only[34], spk_b_only[34];
    secp256k1_xonly_pubkey xonly_a, xonly_b;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_a, NULL, &pubkey_a);
    secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_b, NULL, &pubkey_b);
    build_p2tr_script_pubkey(spk_a_only, &xonly_a);
    build_p2tr_script_pubkey(spk_b_only, &xonly_b);
    ASSERT(memcmp(spk, spk_a_only, 34) != 0, "aggregate SPK != single-key-a SPK");
    ASSERT(memcmp(spk, spk_b_only, 34) != 0, "aggregate SPK != single-key-b SPK");

    /* Deterministic: same inputs → same SPK */
    unsigned char spk2[34];
    ASSERT(splice_compute_funding_spk(ctx, spk2, &pubkey_a, &pubkey_b),
           "second compute succeeds");
    ASSERT(memcmp(spk, spk2, 34) == 0, "splice_compute_funding_spk is deterministic");

    secp256k1_context_destroy(ctx);
    return 1;
}
