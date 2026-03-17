/*
 * test_htlc_forward.c — Unit tests for HTLC forwarding engine
 */

#include "superscalar/htlc_forward.h"
#include "superscalar/onion.h"
#include "superscalar/mpp.h"
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

static void make_privkey(unsigned char priv[32], int seed) {
    memset(priv, seed & 0xff, 32);
    priv[0] = 0x01;
    if (priv[0] == 0) priv[0] = 1;
}

/* ---- Test HF1: final hop delivery ---- */
int test_htlc_forward_final(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char our_priv[32], our_pub[33];
    make_privkey(our_priv, 1);
    secp256k1_pubkey pub;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &pub, our_priv), "pub");
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, our_pub, &pub_len, &pub, SECP256K1_EC_COMPRESSED);

    unsigned char payment_secret[32];
    memset(payment_secret, 0xBB, 32);

    /* Build a final-hop onion */
    onion_hop_t hop;
    memset(&hop, 0, sizeof(hop));
    memcpy(hop.pubkey, our_pub, 33);
    hop.amount_msat = 10000;
    hop.cltv_expiry = 700000;
    hop.is_final    = 1;
    memcpy(hop.payment_secret, payment_secret, 32);
    hop.total_msat  = 10000;

    unsigned char session_key[32];
    memset(session_key, 0x44, 32);
    unsigned char onion_pkt[ONION_PACKET_SIZE];
    ASSERT(onion_build(&hop, 1, session_key, ctx, onion_pkt), "build onion");

    htlc_forward_table_t fwd;
    htlc_forward_init(&fwd);
    mpp_table_t mpp;
    mpp_init(&mpp);

    htlc_forward_entry_t out;
    int ret = htlc_forward_process(&fwd, &mpp, our_priv, ctx,
                                    onion_pkt, 1001, 555, 10000, 700000, &out);
    ASSERT(ret == FORWARD_FINAL, "recognized as final hop");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test HF2: settle propagation ---- */
int test_htlc_forward_settle(void)
{
    htlc_forward_table_t fwd;
    htlc_forward_init(&fwd);

    /* Manually add an in-flight entry */
    htlc_forward_entry_t *e = &fwd.entries[fwd.count++];
    memset(e, 0, sizeof(*e));
    e->in_htlc_id  = 100;
    e->in_chan_id  = 200;
    e->out_htlc_id = 300;
    e->out_chan_id = 400;
    e->state       = FORWARD_STATE_INFLIGHT;

    unsigned char preimage[32];
    memset(preimage, 0xAA, 32);
    htlc_forward_settle(&fwd, 300, 400, preimage);

    ASSERT(fwd.entries[0].state == FORWARD_STATE_SETTLED, "entry settled");
    return 1;
}

/* ---- Test HF3: fail propagation with error re-encryption ---- */
int test_htlc_forward_fail(void)
{
    htlc_forward_table_t fwd;
    htlc_forward_init(&fwd);

    htlc_forward_entry_t *e = &fwd.entries[fwd.count++];
    memset(e, 0, sizeof(*e));
    e->in_htlc_id  = 10;
    e->in_chan_id  = 20;
    e->out_htlc_id = 30;
    e->out_chan_id = 40;
    e->state       = FORWARD_STATE_INFLIGHT;
    memset(e->onion_shared_secret, 0x55, 32);

    unsigned char error_in[256];
    memset(error_in, 0x99, 256);
    unsigned char error_out[256];

    htlc_forward_fail(&fwd, 30, 40, error_in, 256, error_out);

    ASSERT(fwd.entries[0].state == FORWARD_STATE_FAILED, "entry failed");
    /* Error should be re-encrypted (different from input) */
    ASSERT(memcmp(error_in, error_out, 256) != 0, "error was re-encrypted");

    return 1;
}

/* ---- Test HF4: init clears table ---- */
int test_htlc_forward_init(void)
{
    htlc_forward_table_t fwd;
    /* Set some garbage */
    memset(&fwd, 0xFF, sizeof(fwd));
    htlc_forward_init(&fwd);
    ASSERT(fwd.count == 0, "count zeroed after init");
    return 1;
}
