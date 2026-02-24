/* Tests for client-side watchtower (bidirectional revocation).
   Verifies that:
   1. Watchtower initializes safely with NULL regtest
   2. Both sides can store each other's revocation secrets
   3. Client-side watchtower_watch_revoked_commitment works from client perspective
   4. MSG_LSP_REVOKE_AND_ACK wire message round-trips correctly
*/

#include "superscalar/channel.h"
#include "superscalar/watchtower.h"
#include "superscalar/wire.h"
#include "superscalar/fee.h"
#include "superscalar/regtest.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

extern void sha256(const unsigned char *, size_t, unsigned char *);

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

/* Helper: set up a pair of channels (LSP-side and client-side) for the same funding output */
static void setup_channel_pair(secp256k1_context *ctx,
                                 channel_t *lsp_ch, channel_t *client_ch,
                                 const unsigned char *lsp_sec,
                                 const unsigned char *client_sec) {
    secp256k1_pubkey lsp_pk, client_pk;
    secp256k1_ec_pubkey_create(ctx, &lsp_pk, lsp_sec);
    secp256k1_ec_pubkey_create(ctx, &client_pk, client_sec);

    unsigned char funding_txid[32];
    memset(funding_txid, 0xAA, 32);
    unsigned char funding_spk[34] = {0x51, 0x20};
    memset(funding_spk + 2, 0xBB, 32);

    /* LSP channel: LSP=local, client=remote */
    channel_init(lsp_ch, ctx, lsp_sec, &lsp_pk, &client_pk,
                   funding_txid, 0, 100000, funding_spk, 34,
                   50000, 49846, 144);
    channel_generate_random_basepoints(lsp_ch);

    /* Client channel: client=local, LSP=remote */
    channel_init(client_ch, ctx, client_sec, &client_pk, &lsp_pk,
                   funding_txid, 0, 100000, funding_spk, 34,
                   49846, 50000, 144);
    channel_generate_random_basepoints(client_ch);

    /* Exchange basepoints: set remote basepoints on each side */
    channel_set_remote_basepoints(lsp_ch,
        &client_ch->local_payment_basepoint,
        &client_ch->local_delayed_payment_basepoint,
        &client_ch->local_revocation_basepoint);
    channel_set_remote_basepoints(client_ch,
        &lsp_ch->local_payment_basepoint,
        &lsp_ch->local_delayed_payment_basepoint,
        &lsp_ch->local_revocation_basepoint);

    /* Exchange initial per-commitment points */
    secp256k1_pubkey lsp_pcp0, lsp_pcp1, client_pcp0, client_pcp1;
    channel_get_per_commitment_point(lsp_ch, 0, &lsp_pcp0);
    channel_get_per_commitment_point(lsp_ch, 1, &lsp_pcp1);
    channel_get_per_commitment_point(client_ch, 0, &client_pcp0);
    channel_get_per_commitment_point(client_ch, 1, &client_pcp1);

    channel_set_remote_pcp(lsp_ch, 0, &client_pcp0);
    channel_set_remote_pcp(lsp_ch, 1, &client_pcp1);
    channel_set_remote_pcp(client_ch, 0, &lsp_pcp0);
    channel_set_remote_pcp(client_ch, 1, &lsp_pcp1);

    /* Nonce pools not set up here — add via channel_init_nonce_pool
       if commitment signing is needed in specific tests. */
}

/* Test 1: watchtower init with NULL regtest doesn't crash */
int test_client_watchtower_init(void) {
    watchtower_t wt;
    fee_estimator_t fee;
    fee_init(&fee, 1000);

    int ok = watchtower_init(&wt, 1, NULL, &fee, NULL);
    TEST_ASSERT(ok == 1, "watchtower_init with NULL regtest should succeed");
    TEST_ASSERT(wt.n_channels == 1, "n_channels should be 1");
    TEST_ASSERT(wt.rt == NULL, "rt should be NULL");
    TEST_ASSERT(wt.n_entries == 0, "should start with 0 entries");

    return 1;
}

/* Test 2: bidirectional revocation — both sides store each other's secrets */
int test_bidirectional_revocation(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char lsp_sec[32], client_sec[32];
    memset(lsp_sec, 0x11, 32);
    memset(client_sec, 0x22, 32);

    channel_t lsp_ch, client_ch;
    setup_channel_pair(ctx, &lsp_ch, &client_ch, lsp_sec, client_sec);

    /* Simulate a payment: LSP sends commitment_signed to client, client revokes old */
    /* Both sides advance commitment_number */
    uint64_t old_cn = lsp_ch.commitment_number;
    lsp_ch.commitment_number++;
    channel_generate_local_pcs(&lsp_ch, lsp_ch.commitment_number);
    client_ch.commitment_number++;
    channel_generate_local_pcs(&client_ch, client_ch.commitment_number);

    /* Client reveals old PCS to LSP (normal REVOKE_AND_ACK) */
    unsigned char client_old_secret[32];
    TEST_ASSERT(channel_get_revocation_secret(&client_ch, old_cn, client_old_secret),
                "client should have old PCS");
    TEST_ASSERT(channel_receive_revocation(&lsp_ch, old_cn, client_old_secret),
                "LSP should store client's revocation");

    /* LSP reveals old PCS to client (new MSG_LSP_REVOKE_AND_ACK) */
    unsigned char lsp_old_secret[32];
    TEST_ASSERT(channel_get_revocation_secret(&lsp_ch, old_cn, lsp_old_secret),
                "LSP should have old PCS");
    TEST_ASSERT(channel_receive_revocation(&client_ch, old_cn, lsp_old_secret),
                "client should store LSP's revocation");

    /* Verify both sides can retrieve the stored secrets */
    unsigned char verify_client[32], verify_lsp[32];
    TEST_ASSERT(channel_get_received_revocation(&lsp_ch, old_cn, verify_client),
                "LSP should retrieve client's stored revocation");
    TEST_ASSERT(memcmp(verify_client, client_old_secret, 32) == 0,
                "stored client secret should match");

    TEST_ASSERT(channel_get_received_revocation(&client_ch, old_cn, verify_lsp),
                "client should retrieve LSP's stored revocation");
    TEST_ASSERT(memcmp(verify_lsp, lsp_old_secret, 32) == 0,
                "stored LSP secret should match");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 3: client-side watchtower_watch_revoked_commitment creates correct entry */
int test_client_watch_revoked_commitment(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char lsp_sec[32], client_sec[32];
    memset(lsp_sec, 0x11, 32);
    memset(client_sec, 0x22, 32);

    channel_t lsp_ch, client_ch;
    setup_channel_pair(ctx, &lsp_ch, &client_ch, lsp_sec, client_sec);

    /* Set up watchtower for client side */
    watchtower_t wt;
    fee_estimator_t fee;
    fee_init(&fee, 1000);
    watchtower_init(&wt, 1, NULL, &fee, NULL);
    watchtower_set_channel(&wt, 0, &client_ch);

    /* Advance commitment and do revocation */
    uint64_t old_cn = client_ch.commitment_number;
    uint64_t old_local = client_ch.local_amount;
    uint64_t old_remote = client_ch.remote_amount;
    lsp_ch.commitment_number++;
    channel_generate_local_pcs(&lsp_ch, lsp_ch.commitment_number);
    client_ch.commitment_number++;
    channel_generate_local_pcs(&client_ch, client_ch.commitment_number);

    /* LSP reveals its old secret to client */
    unsigned char lsp_old_secret[32];
    channel_get_revocation_secret(&lsp_ch, old_cn, lsp_old_secret);
    channel_receive_revocation(&client_ch, old_cn, lsp_old_secret);

    /* Exchange new PCPs */
    secp256k1_pubkey lsp_new_pcp;
    channel_get_per_commitment_point(&lsp_ch, lsp_ch.commitment_number + 1, &lsp_new_pcp);
    channel_set_remote_pcp(&client_ch, client_ch.commitment_number + 1, &lsp_new_pcp);

    /* Client registers the old LSP commitment with watchtower */
    size_t entries_before = wt.n_entries;
    watchtower_watch_revoked_commitment(&wt, &client_ch, 0, old_cn,
                                          old_local, old_remote,
                                          NULL, 0);

    TEST_ASSERT(wt.n_entries == entries_before + 1,
                "watchtower should have one more entry");
    TEST_ASSERT(wt.entries[entries_before].channel_id == 0,
                "entry channel_id should be 0");
    TEST_ASSERT(wt.entries[entries_before].commit_num == old_cn,
                "entry commit_num should match old_cn");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 4: MSG_LSP_REVOKE_AND_ACK wire message round-trip */
int test_lsp_revoke_and_ack_wire(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Build a MSG_LSP_REVOKE_AND_ACK message */
    unsigned char rev_secret[32];
    memset(rev_secret, 0x42, 32);
    secp256k1_pubkey next_pcp;
    unsigned char pcp_sec[32];
    memset(pcp_sec, 0x77, 32);
    secp256k1_ec_pubkey_create(ctx, &next_pcp, pcp_sec);

    cJSON *j = wire_build_revoke_and_ack(7, rev_secret, ctx, &next_pcp);
    TEST_ASSERT(j != NULL, "wire_build_revoke_and_ack should succeed");

    /* Parse back */
    uint32_t chan_id;
    unsigned char parsed_secret[32], parsed_point[33];
    int ok = wire_parse_revoke_and_ack(j, &chan_id, parsed_secret, parsed_point);
    TEST_ASSERT(ok == 1, "wire_parse_revoke_and_ack should succeed");
    TEST_ASSERT(chan_id == 7, "channel_id should be 7");
    TEST_ASSERT(memcmp(parsed_secret, rev_secret, 32) == 0,
                "revocation secret should round-trip");

    /* Verify the point parses back to the same pubkey */
    secp256k1_pubkey parsed_pk;
    TEST_ASSERT(secp256k1_ec_pubkey_parse(ctx, &parsed_pk, parsed_point, 33),
                "parsed point should be valid pubkey");

    unsigned char orig_ser[33], parsed_ser[33];
    size_t len1 = 33, len2 = 33;
    secp256k1_ec_pubkey_serialize(ctx, orig_ser, &len1, &next_pcp,
                                   SECP256K1_EC_COMPRESSED);
    secp256k1_ec_pubkey_serialize(ctx, parsed_ser, &len2, &parsed_pk,
                                   SECP256K1_EC_COMPRESSED);
    TEST_ASSERT(memcmp(orig_ser, parsed_ser, 33) == 0,
                "next PCP should round-trip");

    /* Verify the message type name */
    TEST_ASSERT(strcmp(wire_msg_type_name(MSG_LSP_REVOKE_AND_ACK),
                        "LSP_REVOKE_AND_ACK") == 0,
                "message type name should be LSP_REVOKE_AND_ACK");

    cJSON_Delete(j);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 5: watchtower_watch_factory_node creates entry with response tx */
int test_factory_node_watch(void) {
    watchtower_t wt;
    fee_estimator_t fee;
    fee_init(&fee, 1000);
    watchtower_init(&wt, 1, NULL, &fee, NULL);

    unsigned char old_txid[32];
    memset(old_txid, 0xCC, 32);

    /* Fake "latest state tx" as response */
    unsigned char response[64];
    memset(response, 0xDD, 64);

    int ok = watchtower_watch_factory_node(&wt, 2, old_txid, response, 64);
    TEST_ASSERT(ok == 1, "watchtower_watch_factory_node should succeed");
    TEST_ASSERT(wt.n_entries == 1, "should have 1 entry");
    TEST_ASSERT(wt.entries[0].type == WATCH_FACTORY_NODE,
                "entry type should be WATCH_FACTORY_NODE");
    TEST_ASSERT(wt.entries[0].channel_id == 2, "node_idx should be 2");
    TEST_ASSERT(memcmp(wt.entries[0].txid, old_txid, 32) == 0,
                "txid should match");
    TEST_ASSERT(wt.entries[0].response_tx != NULL, "response_tx should be allocated");
    TEST_ASSERT(wt.entries[0].response_tx_len == 64,
                "response_tx_len should be 64");
    TEST_ASSERT(memcmp(wt.entries[0].response_tx, response, 64) == 0,
                "response_tx data should match");

    watchtower_cleanup(&wt);
    return 1;
}

/* Test 6: factory node entry coexists with commitment entries */
int test_factory_and_commitment_entries(void) {
    watchtower_t wt;
    fee_estimator_t fee;
    fee_init(&fee, 1000);
    watchtower_init(&wt, 2, NULL, &fee, NULL);

    /* Add a commitment entry */
    unsigned char commit_txid[32];
    memset(commit_txid, 0xAA, 32);
    unsigned char commit_spk[34] = {0x51, 0x20};
    memset(commit_spk + 2, 0xBB, 32);
    watchtower_watch(&wt, 0, 5, commit_txid, 0, 50000, commit_spk, 34);
    TEST_ASSERT(wt.n_entries == 1, "should have 1 entry after commitment watch");
    TEST_ASSERT(wt.entries[0].type == WATCH_COMMITMENT,
                "first entry should be WATCH_COMMITMENT");

    /* Add a factory node entry */
    unsigned char factory_txid[32];
    memset(factory_txid, 0xCC, 32);
    unsigned char response[32];
    memset(response, 0xEE, 32);
    watchtower_watch_factory_node(&wt, 1, factory_txid, response, 32);
    TEST_ASSERT(wt.n_entries == 2, "should have 2 entries");
    TEST_ASSERT(wt.entries[1].type == WATCH_FACTORY_NODE,
                "second entry should be WATCH_FACTORY_NODE");

    /* Remove by channel_id = 0 should only remove commitment entry */
    watchtower_remove_channel(&wt, 0);
    TEST_ASSERT(wt.n_entries == 1, "should have 1 entry after remove");
    TEST_ASSERT(wt.entries[0].type == WATCH_FACTORY_NODE,
                "remaining entry should be WATCH_FACTORY_NODE");

    watchtower_cleanup(&wt);
    return 1;
}

/* Test 7: HTLC penalty watch — watchtower entry stores HTLC output info */
int test_htlc_penalty_watch(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char lsp_sec[32], client_sec[32];
    memset(lsp_sec, 0x11, 32);
    memset(client_sec, 0x22, 32);

    channel_t lsp_ch, client_ch;
    setup_channel_pair(ctx, &lsp_ch, &client_ch, lsp_sec, client_sec);

    /* Exchange HTLC basepoints (setup_channel_pair doesn't do this) */
    channel_set_remote_htlc_basepoint(&lsp_ch, &client_ch.local_htlc_basepoint);
    channel_set_remote_htlc_basepoint(&client_ch, &lsp_ch.local_htlc_basepoint);

    /* Set up watchtower for client side */
    watchtower_t wt;
    fee_estimator_t fee;
    fee_init(&fee, 1000);
    watchtower_init(&wt, 1, NULL, &fee, NULL);
    watchtower_set_channel(&wt, 0, &client_ch);

    /* Add 1 HTLC (5000 sats, offered from LSP to client) */
    unsigned char payment_hash[32];
    memset(payment_hash, 0x55, 32);
    uint64_t htlc_id;
    /* On lsp_ch: HTLC_OFFERED (LSP offers to client) */
    TEST_ASSERT(channel_add_htlc(&lsp_ch, HTLC_OFFERED, 5000, payment_hash, 500, &htlc_id),
                "add_htlc on LSP should succeed");
    /* On client_ch: HTLC_RECEIVED (client receives from LSP) */
    TEST_ASSERT(channel_add_htlc(&client_ch, HTLC_RECEIVED, 5000, payment_hash, 500, &htlc_id),
                "add_htlc on client should succeed");

    /* Snapshot the old state before advancing */
    uint64_t old_cn = client_ch.commitment_number;
    uint64_t old_local = client_ch.local_amount;
    uint64_t old_remote = client_ch.remote_amount;
    size_t old_n_htlcs = client_ch.n_htlcs;
    htlc_t old_htlcs[MAX_HTLCS];
    memcpy(old_htlcs, client_ch.htlcs, old_n_htlcs * sizeof(htlc_t));

    /* Advance commitment */
    lsp_ch.commitment_number++;
    channel_generate_local_pcs(&lsp_ch, lsp_ch.commitment_number);
    client_ch.commitment_number++;
    channel_generate_local_pcs(&client_ch, client_ch.commitment_number);

    /* LSP reveals old secret to client */
    unsigned char lsp_old_secret[32];
    channel_get_revocation_secret(&lsp_ch, old_cn, lsp_old_secret);
    channel_receive_revocation(&client_ch, old_cn, lsp_old_secret);

    /* Exchange new PCPs */
    secp256k1_pubkey lsp_new_pcp;
    channel_get_per_commitment_point(&lsp_ch, lsp_ch.commitment_number + 1, &lsp_new_pcp);
    channel_set_remote_pcp(&client_ch, client_ch.commitment_number + 1, &lsp_new_pcp);

    /* Register old commitment WITH HTLC state */
    size_t entries_before = wt.n_entries;
    watchtower_watch_revoked_commitment(&wt, &client_ch, 0, old_cn,
                                          old_local, old_remote,
                                          old_htlcs, old_n_htlcs);

    TEST_ASSERT(wt.n_entries == entries_before + 1,
                "watchtower should have one more entry");

    watchtower_entry_t *entry = &wt.entries[entries_before];
    TEST_ASSERT(entry->channel_id == 0, "entry channel_id should be 0");
    TEST_ASSERT(entry->commit_num == old_cn, "entry commit_num should match");

    /* Verify HTLC output was stored */
    TEST_ASSERT(entry->n_htlc_outputs == 1,
                "entry should have 1 HTLC output");
    TEST_ASSERT(entry->htlc_outputs[0].htlc_vout == 2,
                "HTLC output vout should be 2");
    TEST_ASSERT(entry->htlc_outputs[0].htlc_amount == 5000,
                "HTLC output amount should be 5000");
    TEST_ASSERT(entry->htlc_outputs[0].direction == HTLC_RECEIVED,
                "HTLC direction should be RECEIVED (client's perspective)");
    TEST_ASSERT(memcmp(entry->htlc_outputs[0].payment_hash, payment_hash, 32) == 0,
                "HTLC payment_hash should match");
    TEST_ASSERT(entry->htlc_outputs[0].cltv_expiry == 500,
                "HTLC cltv_expiry should be 500");

    secp256k1_context_destroy(ctx);
    return 1;
}
