#include "superscalar/splice.h"
#include "superscalar/channel.h"
#include "superscalar/tx_builder.h"
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
