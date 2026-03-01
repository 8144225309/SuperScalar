#include "superscalar/factory.h"
#include "superscalar/fee.h"
#include "superscalar/wire.h"
#include "superscalar/noise.h"
#include "superscalar/lsp.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/client.h"
#include "superscalar/musig.h"
#include "superscalar/regtest.h"
#include "superscalar/persist.h"
#include "cJSON.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);
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

/* Secret keys for 5 participants: LSP + 4 clients */
static const unsigned char seckeys[5][32] = {
    { [0 ... 31] = 0x10 },  /* LSP */
    { [0 ... 31] = 0x21 },  /* Client A */
    { [0 ... 31] = 0x32 },  /* Client B */
    { [0 ... 31] = 0x43 },  /* Client C */
    { [0 ... 31] = 0x54 },  /* Client D */
};

static secp256k1_context *test_ctx(void) {
    return secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

/* ---- Test 1: Channel message build/parse round-trip ---- */

int test_channel_msg_round_trip(void) {
    /* CHANNEL_READY */
    {
        cJSON *msg = wire_build_channel_ready(2, 50000000, 50000000);
        uint32_t ch_id;
        uint64_t bl, br;
        TEST_ASSERT(wire_parse_channel_ready(msg, &ch_id, &bl, &br),
                    "parse channel_ready");
        TEST_ASSERT_EQ(ch_id, 2, "channel_id");
        TEST_ASSERT_EQ(bl, 50000000, "balance_local");
        TEST_ASSERT_EQ(br, 50000000, "balance_remote");
        cJSON_Delete(msg);
    }

    /* UPDATE_ADD_HTLC */
    {
        unsigned char hash[32];
        memset(hash, 0xAB, 32);
        cJSON *msg = wire_build_update_add_htlc(42, 10000000, hash, 500);
        uint64_t htlc_id, amount;
        unsigned char parsed_hash[32];
        uint32_t cltv;
        TEST_ASSERT(wire_parse_update_add_htlc(msg, &htlc_id, &amount,
                                                  parsed_hash, &cltv),
                    "parse add_htlc");
        TEST_ASSERT_EQ(htlc_id, 42, "htlc_id");
        TEST_ASSERT_EQ(amount, 10000000, "amount");
        TEST_ASSERT_EQ(cltv, 500, "cltv");
        TEST_ASSERT(memcmp(hash, parsed_hash, 32) == 0, "payment_hash");
        cJSON_Delete(msg);
    }

    /* COMMITMENT_SIGNED (Phase 12: partial_sig32 + nonce_index) */
    {
        unsigned char psig[32];
        memset(psig, 0xCC, 32);
        cJSON *msg = wire_build_commitment_signed(1, 5, psig, 42);
        uint32_t ch_id;
        uint64_t commit_num;
        unsigned char parsed_psig[32];
        uint32_t parsed_nonce_idx;
        TEST_ASSERT(wire_parse_commitment_signed(msg, &ch_id, &commit_num,
                                                    parsed_psig, &parsed_nonce_idx),
                    "parse commitment_signed");
        TEST_ASSERT_EQ(ch_id, 1, "channel_id");
        TEST_ASSERT_EQ(commit_num, 5, "commitment_number");
        TEST_ASSERT(memcmp(psig, parsed_psig, 32) == 0, "partial_sig");
        TEST_ASSERT_EQ(parsed_nonce_idx, 42, "nonce_index");
        cJSON_Delete(msg);
    }

    /* REVOKE_AND_ACK */
    {
        secp256k1_context *ctx = test_ctx();
        unsigned char secret[32];
        memset(secret, 0xDD, 32);
        secp256k1_pubkey pk;
        if (!secp256k1_ec_pubkey_create(ctx, &pk, secret)) return 0;
        cJSON *msg = wire_build_revoke_and_ack(3, secret, ctx, &pk);
        uint32_t ch_id;
        unsigned char parsed_secret[32], parsed_point[33];
        TEST_ASSERT(wire_parse_revoke_and_ack(msg, &ch_id, parsed_secret,
                                                parsed_point),
                    "parse revoke_and_ack");
        TEST_ASSERT_EQ(ch_id, 3, "channel_id");
        TEST_ASSERT(memcmp(secret, parsed_secret, 32) == 0, "revocation_secret");
        cJSON_Delete(msg);
        secp256k1_context_destroy(ctx);
    }

    /* CHANNEL_NONCES (Phase 12) */
    {
        unsigned char nonces[3][66];
        memset(nonces[0], 0xAA, 66);
        memset(nonces[1], 0xBB, 66);
        memset(nonces[2], 0xCC, 66);
        cJSON *msg = wire_build_channel_nonces(7,
            (const unsigned char (*)[66])nonces, 3);
        uint32_t ch_id;
        unsigned char parsed_nonces[16][66];
        size_t parsed_count;
        TEST_ASSERT(wire_parse_channel_nonces(msg, &ch_id, parsed_nonces,
                                                16, &parsed_count),
                    "parse channel_nonces");
        TEST_ASSERT_EQ(ch_id, 7, "channel_id");
        TEST_ASSERT_EQ(parsed_count, 3, "nonce_count");
        TEST_ASSERT(memcmp(nonces[0], parsed_nonces[0], 66) == 0, "nonce[0]");
        TEST_ASSERT(memcmp(nonces[1], parsed_nonces[1], 66) == 0, "nonce[1]");
        TEST_ASSERT(memcmp(nonces[2], parsed_nonces[2], 66) == 0, "nonce[2]");
        cJSON_Delete(msg);
    }

    /* UPDATE_FULFILL_HTLC */
    {
        unsigned char preimage[32];
        memset(preimage, 0xEE, 32);
        cJSON *msg = wire_build_update_fulfill_htlc(7, preimage);
        uint64_t htlc_id;
        unsigned char parsed_preimage[32];
        TEST_ASSERT(wire_parse_update_fulfill_htlc(msg, &htlc_id, parsed_preimage),
                    "parse fulfill_htlc");
        TEST_ASSERT_EQ(htlc_id, 7, "htlc_id");
        TEST_ASSERT(memcmp(preimage, parsed_preimage, 32) == 0, "preimage");
        cJSON_Delete(msg);
    }

    /* UPDATE_FAIL_HTLC */
    {
        cJSON *msg = wire_build_update_fail_htlc(9, "insufficient_funds");
        uint64_t htlc_id;
        char reason[256];
        TEST_ASSERT(wire_parse_update_fail_htlc(msg, &htlc_id, reason, sizeof(reason)),
                    "parse fail_htlc");
        TEST_ASSERT_EQ(htlc_id, 9, "htlc_id");
        TEST_ASSERT(strcmp(reason, "insufficient_funds") == 0, "reason");
        cJSON_Delete(msg);
    }

    return 1;
}

/* ---- Test 2: LSP channel manager initialization ---- */

int test_lsp_channel_init(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_create(ctx, &kps[i], seckeys[i])) return 0;
    }

    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

    /* Build factory from pubkeys */
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

    factory_t f;
    factory_init_from_pubkeys(&f, ctx, pks, 5, 10, 4);
    unsigned char fake_txid[32] = {0};
    fake_txid[0] = 0xDD;
    factory_set_funding(&f, fake_txid, 0, 1000000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* Initialize channel manager */
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    TEST_ASSERT(lsp_channels_init(&mgr, ctx, &f, seckeys[0], 4),
                "lsp_channels_init");
    TEST_ASSERT_EQ(mgr.n_channels, 4, "n_channels");

    /* Check each channel has valid state */
    for (size_t c = 0; c < 4; c++) {
        lsp_channel_entry_t *entry = lsp_channels_get(&mgr, c);
        TEST_ASSERT(entry != NULL, "entry not null");
        TEST_ASSERT_EQ(entry->channel_id, c, "channel_id");
        TEST_ASSERT(entry->channel.funding_amount > 0, "funding_amount > 0");
        TEST_ASSERT(entry->channel.local_amount > 0, "local_amount > 0");
        TEST_ASSERT(entry->channel.remote_amount > 0, "remote_amount > 0");
        /* local + remote = funding_amount - commit_fee */
        fee_estimator_t _fe; fee_init(&_fe, 1000);
        uint64_t commit_fee = fee_for_commitment_tx(&_fe, 0);
        TEST_ASSERT_EQ(entry->channel.local_amount + entry->channel.remote_amount,
                        entry->channel.funding_amount - commit_fee, "balance sum");
    }

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test 3: Channel wire message framing over socketpair ---- */

int test_channel_wire_framing(void) {
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    /* Send CHANNEL_READY */
    cJSON *ready = wire_build_channel_ready(0, 50000000, 50000000);
    TEST_ASSERT(wire_send(sv[0], MSG_CHANNEL_READY, ready), "send channel_ready");
    cJSON_Delete(ready);

    /* Receive and verify */
    wire_msg_t msg;
    TEST_ASSERT(wire_recv(sv[1], &msg), "recv channel_ready");
    TEST_ASSERT_EQ(msg.msg_type, MSG_CHANNEL_READY, "msg type");

    uint32_t ch_id;
    uint64_t bl, br;
    TEST_ASSERT(wire_parse_channel_ready(msg.json, &ch_id, &bl, &br),
                "parse channel_ready");
    TEST_ASSERT_EQ(ch_id, 0, "channel_id");
    cJSON_Delete(msg.json);

    /* Send ADD_HTLC */
    unsigned char hash[32];
    memset(hash, 0x42, 32);
    cJSON *htlc = wire_build_update_add_htlc(1, 5000000, hash, 100);
    cJSON_AddNumberToObject(htlc, "dest_client", 1);
    TEST_ASSERT(wire_send(sv[0], MSG_UPDATE_ADD_HTLC, htlc), "send add_htlc");
    cJSON_Delete(htlc);

    TEST_ASSERT(wire_recv(sv[1], &msg), "recv add_htlc");
    TEST_ASSERT_EQ(msg.msg_type, MSG_UPDATE_ADD_HTLC, "msg type");
    cJSON_Delete(msg.json);

    close(sv[0]);
    close(sv[1]);
    return 1;
}

/* ---- Multi-payment callback types (used by test 5) ---- */

typedef enum {
    ACTION_SEND,   /* send ADD_HTLC, wait for COMMITMENT_SIGNED + FULFILL + COMMITMENT_SIGNED */
    ACTION_RECV,   /* wait for ADD_HTLC + COMMITMENT_SIGNED, then FULFILL + COMMITMENT_SIGNED */
} action_type_t;

typedef struct {
    action_type_t type;
    uint32_t dest_client;          /* for SEND: which client to pay (0-based) */
    uint64_t amount_sats;          /* for SEND: payment amount */
    unsigned char preimage[32];    /* for RECV: preimage to reveal */
    unsigned char payment_hash[32]; /* for SEND: hash to use */
} scripted_action_t;

typedef struct {
    scripted_action_t *actions;
    size_t n_actions;
    size_t current;
} multi_payment_data_t;

/* Helper: receive next non-revocation message, consuming any
   MSG_LSP_REVOKE_AND_ACK (0x50) along the way.  The LSP sends
   bidirectional revocations at 9 sites; test clients don't track
   watchtower state, so we simply skip them. */
static int recv_skip_revocations(int fd, wire_msg_t *out) {
    for (;;) {
        if (!wire_recv(fd, out)) return 0;
        if (out->msg_type != 0x50) return 1;  /* MSG_LSP_REVOKE_AND_ACK */
        cJSON_Delete(out->json);
    }
}

static int multi_payment_client_cb(int fd, channel_t *ch, uint32_t my_index,
                                     secp256k1_context *ctx,
                                     const secp256k1_keypair *keypair,
                                     factory_t *factory,
                                     size_t n_participants,
                                     void *user_data) {
    multi_payment_data_t *data = (multi_payment_data_t *)user_data;
    (void)ctx; (void)keypair; (void)factory; (void)n_participants;

    for (size_t i = 0; i < data->n_actions; i++) {
        scripted_action_t *act = &data->actions[i];

        if (act->type == ACTION_SEND) {
            printf("Client %u: SEND %llu sats to client %u\n",
                   my_index, (unsigned long long)act->amount_sats, act->dest_client);

            if (!client_send_payment(fd, ch, act->amount_sats, act->payment_hash,
                                       500, act->dest_client)) {
                fprintf(stderr, "Client %u: send_payment failed\n", my_index);
                return 0;
            }

            /* Wait for COMMITMENT_SIGNED (acknowledging HTLC) */
            wire_msg_t msg;
            if (!recv_skip_revocations(fd, &msg)) {
                fprintf(stderr, "Client %u: recv failed after send\n", my_index);
                return 0;
            }
            if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
                client_handle_commitment_signed(fd, ch, ctx, &msg);
                cJSON_Delete(msg.json);
            } else {
                fprintf(stderr, "Client %u: expected COMMIT_SIGNED, got 0x%02x\n",
                        my_index, msg.msg_type);
                cJSON_Delete(msg.json);
                return 0;
            }

            /* Wait for FULFILL_HTLC */
            if (!recv_skip_revocations(fd, &msg)) {
                fprintf(stderr, "Client %u: recv fulfill failed\n", my_index);
                return 0;
            }
            if (msg.msg_type == MSG_UPDATE_FULFILL_HTLC) {
                /* Update local channel state to match LSP */
                uint64_t fulfill_htlc_id;
                unsigned char fulfill_preimage[32];
                if (wire_parse_update_fulfill_htlc(msg.json, &fulfill_htlc_id,
                                                     fulfill_preimage)) {
                    channel_fulfill_htlc(ch, fulfill_htlc_id, fulfill_preimage);
                }
                printf("Client %u: payment fulfilled!\n", my_index);
                cJSON_Delete(msg.json);
            } else {
                fprintf(stderr, "Client %u: expected FULFILL, got 0x%02x\n",
                        my_index, msg.msg_type);
                cJSON_Delete(msg.json);
                return 0;
            }

            /* Handle COMMITMENT_SIGNED for the fulfill */
            if (!recv_skip_revocations(fd, &msg)) {
                fprintf(stderr, "Client %u: recv commit after fulfill failed\n", my_index);
                return 0;
            }
            if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
                client_handle_commitment_signed(fd, ch, ctx, &msg);
                cJSON_Delete(msg.json);
            } else {
                cJSON_Delete(msg.json);
            }

        } else { /* ACTION_RECV */
            printf("Client %u: RECV (waiting for ADD_HTLC)\n", my_index);

            /* Wait for ADD_HTLC from LSP */
            wire_msg_t msg;
            if (!recv_skip_revocations(fd, &msg)) {
                fprintf(stderr, "Client %u: recv ADD_HTLC failed\n", my_index);
                return 0;
            }
            if (msg.msg_type == MSG_UPDATE_ADD_HTLC) {
                client_handle_add_htlc(ch, &msg);
                cJSON_Delete(msg.json);
            } else {
                fprintf(stderr, "Client %u: expected ADD_HTLC, got 0x%02x\n",
                        my_index, msg.msg_type);
                cJSON_Delete(msg.json);
                return 0;
            }

            /* Handle COMMITMENT_SIGNED */
            if (!recv_skip_revocations(fd, &msg)) {
                fprintf(stderr, "Client %u: recv commit failed\n", my_index);
                return 0;
            }
            if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
                client_handle_commitment_signed(fd, ch, ctx, &msg);
                cJSON_Delete(msg.json);
            } else {
                cJSON_Delete(msg.json);
            }

            /* Find active received HTLC and fulfill it */
            uint64_t htlc_id = 0;
            int found = 0;
            for (size_t h = 0; h < ch->n_htlcs; h++) {
                if (ch->htlcs[h].state == HTLC_STATE_ACTIVE &&
                    ch->htlcs[h].direction == HTLC_RECEIVED) {
                    htlc_id = ch->htlcs[h].id;
                    found = 1;
                    break;
                }
            }
            if (!found) {
                fprintf(stderr, "Client %u: no active received HTLC to fulfill\n", my_index);
                return 0;
            }

            printf("Client %u: fulfilling HTLC %llu\n", my_index,
                   (unsigned long long)htlc_id);
            client_fulfill_payment(fd, ch, htlc_id, act->preimage);

            /* Handle COMMITMENT_SIGNED for the fulfill */
            if (!recv_skip_revocations(fd, &msg)) {
                fprintf(stderr, "Client %u: recv commit after fulfill failed\n", my_index);
                return 0;
            }
            if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
                client_handle_commitment_signed(fd, ch, ctx, &msg);
                cJSON_Delete(msg.json);
            } else {
                cJSON_Delete(msg.json);
            }
        }
    }

    return 1;
}

/* ---- Test 4: Full intra-factory payment via TCP (fork-based) ---- */

/* Shared state for client callbacks in the payment test */
typedef struct {
    unsigned char preimage[32];    /* known only to payee */
    unsigned char payment_hash[32];
    int is_sender;                 /* 1 = Client A (sender), 0 = others */
    int payment_done;
} payment_test_data_t;

static int payment_client_cb(int fd, channel_t *ch, uint32_t my_index,
                               secp256k1_context *ctx,
                               const secp256k1_keypair *keypair,
                               factory_t *factory,
                               size_t n_participants,
                               void *user_data) {
    payment_test_data_t *data = (payment_test_data_t *)user_data;
    (void)ctx; (void)keypair; (void)factory; (void)n_participants;

    if (data->is_sender) {
        /* Client A (index 1): send payment to Client B (index 2, = client_idx 1) */
        printf("Client %u: sending 5000 sats to client 1\n", my_index);

        if (!client_send_payment(fd, ch, 5000, data->payment_hash, 500, 1)) {
            fprintf(stderr, "Client %u: send_payment failed\n", my_index);
            return 0;
        }

        /* Wait for COMMITMENT_SIGNED from LSP (acknowledging the HTLC) */
        wire_msg_t msg;
        if (!recv_skip_revocations(fd, &msg)) {
            fprintf(stderr, "Client %u: recv failed\n", my_index);
            return 0;
        }
        if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
            client_handle_commitment_signed(fd, ch, ctx, &msg);
            cJSON_Delete(msg.json);
        } else {
            fprintf(stderr, "Client %u: unexpected msg 0x%02x\n", my_index, msg.msg_type);
            cJSON_Delete(msg.json);
            return 0;
        }

        /* Wait for FULFILL_HTLC from LSP (payment succeeded) */
        if (!recv_skip_revocations(fd, &msg)) {
            fprintf(stderr, "Client %u: recv fulfill failed\n", my_index);
            return 0;
        }
        if (msg.msg_type == MSG_UPDATE_FULFILL_HTLC) {
            /* Update local channel state to match LSP */
            uint64_t fulfill_htlc_id;
            unsigned char fulfill_preimage[32];
            if (wire_parse_update_fulfill_htlc(msg.json, &fulfill_htlc_id,
                                                 fulfill_preimage)) {
                channel_fulfill_htlc(ch, fulfill_htlc_id, fulfill_preimage);
            }
            printf("Client %u: payment fulfilled!\n", my_index);
            cJSON_Delete(msg.json);
        } else {
            fprintf(stderr, "Client %u: expected FULFILL, got 0x%02x\n",
                    my_index, msg.msg_type);
            cJSON_Delete(msg.json);
            return 0;
        }

        /* Handle COMMITMENT_SIGNED for the fulfill */
        if (!recv_skip_revocations(fd, &msg)) {
            fprintf(stderr, "Client %u: recv commit failed\n", my_index);
            return 0;
        }
        if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
            client_handle_commitment_signed(fd, ch, ctx, &msg);
            cJSON_Delete(msg.json);
        } else {
            cJSON_Delete(msg.json);
        }

    } else if (my_index == 2) {
        /* Client B (index 2): payee — wait for HTLC, then fulfill */

        /* Wait for ADD_HTLC from LSP */
        wire_msg_t msg;
        if (!recv_skip_revocations(fd, &msg)) {
            fprintf(stderr, "Client %u: recv failed\n", my_index);
            return 0;
        }
        if (msg.msg_type == MSG_UPDATE_ADD_HTLC) {
            client_handle_add_htlc(ch, &msg);
            cJSON_Delete(msg.json);
        } else {
            fprintf(stderr, "Client %u: expected ADD_HTLC, got 0x%02x\n",
                    my_index, msg.msg_type);
            cJSON_Delete(msg.json);
            return 0;
        }

        /* Handle COMMITMENT_SIGNED */
        if (!recv_skip_revocations(fd, &msg)) {
            fprintf(stderr, "Client %u: recv commit failed\n", my_index);
            return 0;
        }
        if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
            client_handle_commitment_signed(fd, ch, ctx, &msg);
            cJSON_Delete(msg.json);
        } else {
            cJSON_Delete(msg.json);
        }

        /* Reveal preimage */
        printf("Client %u: fulfilling HTLC with preimage\n", my_index);
        /* Find the received HTLC */
        uint64_t htlc_id = 0;
        for (size_t i = 0; i < ch->n_htlcs; i++) {
            if (ch->htlcs[i].state == HTLC_STATE_ACTIVE &&
                ch->htlcs[i].direction == HTLC_RECEIVED) {
                htlc_id = ch->htlcs[i].id;
                break;
            }
        }
        client_fulfill_payment(fd, ch, htlc_id, data->preimage);

        /* Handle COMMITMENT_SIGNED for the fulfill */
        if (!recv_skip_revocations(fd, &msg)) {
            fprintf(stderr, "Client %u: recv commit failed\n", my_index);
            return 0;
        }
        if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
            client_handle_commitment_signed(fd, ch, ctx, &msg);
            cJSON_Delete(msg.json);
        } else {
            cJSON_Delete(msg.json);
        }

    } else {
        /* Clients C and D: do nothing, just wait */
    }

    return 1;
}

int test_regtest_intra_factory_payment(void) {
    /* Initialize regtest */
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: regtest not available\n");
        return 0;
    }
    if (!regtest_create_wallet(&rt, "test_channels")) {
        char *lr = regtest_exec(&rt, "loadwallet", "\"test_channels\"");
        if (lr) free(lr);
        strncpy(rt.wallet, "test_channels", sizeof(rt.wallet) - 1);
    }

    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_create(ctx, &kps[i], seckeys[i])) return 0;
    }

    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

    /* Compute funding SPK */
    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, 5);

    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    unsigned char tweak_val[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak_val);
    musig_keyagg_t ka_copy = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &ka_copy.cache, tweak_val)) return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) return 0;
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tweaked_xonly);

    /* Derive bech32m address */
    unsigned char tweaked_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, tweaked_ser, &tweaked_xonly)) return 0;
    char tweaked_hex[65];
    hex_encode(tweaked_ser, 32, tweaked_hex);

    char params[512];
    snprintf(params, sizeof(params), "\"rawtr(%s)\"", tweaked_hex);
    char *desc_result = regtest_exec(&rt, "getdescriptorinfo", params);
    TEST_ASSERT(desc_result != NULL, "getdescriptorinfo");

    char checksummed_desc[256];
    char *dstart = strstr(desc_result, "\"descriptor\"");
    TEST_ASSERT(dstart != NULL, "parse descriptor");
    dstart = strchr(dstart + 12, '"'); dstart++;
    char *dend = strchr(dstart, '"');
    size_t dlen = (size_t)(dend - dstart);
    memcpy(checksummed_desc, dstart, dlen);
    checksummed_desc[dlen] = '\0';
    free(desc_result);

    snprintf(params, sizeof(params), "\"%s\"", checksummed_desc);
    char *addr_result = regtest_exec(&rt, "deriveaddresses", params);
    TEST_ASSERT(addr_result != NULL, "deriveaddresses");

    char fund_addr[128] = {0};
    char *astart = strchr(addr_result, '"'); astart++;
    char *aend = strchr(astart, '"');
    size_t alen = (size_t)(aend - astart);
    memcpy(fund_addr, astart, alen);
    fund_addr[alen] = '\0';
    free(addr_result);

    /* Mine and fund */
    char mine_addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)),
                "get mine address");
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    TEST_ASSERT(regtest_get_balance(&rt) >= 0.01, "factory setup for funding");

    char funding_txid_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, fund_addr, 0.01, funding_txid_hex),
                "fund factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    unsigned char funding_txid[32];
    hex_decode(funding_txid_hex, funding_txid, 32);
    reverse_bytes(funding_txid, 32);

    uint64_t funding_amount = 0;
    unsigned char actual_spk[256];
    size_t actual_spk_len = 0;
    uint32_t funding_vout = 0;
    for (uint32_t v = 0; v < 2; v++) {
        regtest_get_tx_output(&rt, funding_txid_hex, v,
                              &funding_amount, actual_spk, &actual_spk_len);
        if (actual_spk_len == 34 && memcmp(actual_spk, fund_spk, 34) == 0) {
            funding_vout = v;
            break;
        }
    }
    TEST_ASSERT(funding_amount > 0, "funding amount > 0");

    /* Generate payment preimage and hash */
    unsigned char preimage[32] = { [0 ... 31] = 0x77 };
    unsigned char payment_hash[32];
    sha256(preimage, 32, payment_hash);

    /* Use a fixed port with PID offset */
    int port = 19800 + (getpid() % 1000);

    /* Prepare per-client test data */
    payment_test_data_t sender_data, payee_data, idle_data;
    memcpy(sender_data.payment_hash, payment_hash, 32);
    memset(sender_data.preimage, 0, 32);
    sender_data.is_sender = 1;

    memcpy(payee_data.payment_hash, payment_hash, 32);
    memcpy(payee_data.preimage, preimage, 32);
    payee_data.is_sender = 0;

    memset(&idle_data, 0, sizeof(idle_data));
    idle_data.is_sender = 0;

    /* Fork 4 client processes */
    pid_t child_pids[4];
    for (int c = 0; c < 4; c++) {
        pid_t pid = fork();
        if (pid == 0) {
            usleep(100000 * (c + 1));
            secp256k1_context *child_ctx = test_ctx();
            secp256k1_keypair child_kp;
            if (!secp256k1_keypair_create(child_ctx, &child_kp, seckeys[c + 1])) return 0;

            void *cb_data;
            if (c == 0) cb_data = &sender_data;       /* Client A = sender */
            else if (c == 1) cb_data = &payee_data;    /* Client B = payee */
            else cb_data = &idle_data;                 /* C, D = idle */

            int ok = client_run_with_channels(child_ctx, &child_kp,
                                               "127.0.0.1", port,
                                               payment_client_cb, cb_data);
            secp256k1_context_destroy(child_ctx);
            _exit(ok ? 0 : 1);
        }
        child_pids[c] = pid;
    }

    /* Parent: run LSP */
    lsp_t lsp;
    lsp_init(&lsp, ctx, &kps[0], port, 4);
    int lsp_ok = 1;

    if (!lsp_accept_clients(&lsp)) {
        fprintf(stderr, "LSP: accept clients failed\n");
        lsp_ok = 0;
    }

    if (lsp_ok && !lsp_run_factory_creation(&lsp,
                                             funding_txid, funding_vout,
                                             funding_amount,
                                             fund_spk, 34, 10, 4, 0)) {
        fprintf(stderr, "LSP: factory creation failed\n");
        lsp_ok = 0;
    }

    /* Initialize channel manager, exchange basepoints, and send CHANNEL_READY */
    lsp_channel_mgr_t ch_mgr;
    memset(&ch_mgr, 0, sizeof(ch_mgr));
    if (lsp_ok) {
        if (!lsp_channels_init(&ch_mgr, ctx, &lsp.factory, seckeys[0], 4)) {
            fprintf(stderr, "LSP: channel init failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok) {
        if (!lsp_channels_exchange_basepoints(&ch_mgr, &lsp)) {
            fprintf(stderr, "LSP: basepoint exchange failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok) {
        if (!lsp_channels_send_ready(&ch_mgr, &lsp)) {
            fprintf(stderr, "LSP: send channel_ready failed\n");
            lsp_ok = 0;
        }
    }

    /* Handle channel messages.
       We know the flow: Client A sends ADD_HTLC (which triggers LSP to
       forward to B), then B sends FULFILL_HTLC (which triggers LSP to
       forward back to A). Then we close. */
    if (lsp_ok) {
        /* Step 1: Receive ADD_HTLC from Client A (index 0) */
        wire_msg_t msg;
        if (!wire_recv(lsp.client_fds[0], &msg)) {
            fprintf(stderr, "LSP: recv from client 0 failed\n");
            lsp_ok = 0;
        } else {
            if (msg.msg_type == MSG_UPDATE_ADD_HTLC) {
                if (!lsp_channels_handle_msg(&ch_mgr, &lsp, 0, &msg)) {
                    fprintf(stderr, "LSP: handle ADD_HTLC failed\n");
                    lsp_ok = 0;
                }
            } else {
                fprintf(stderr, "LSP: expected ADD_HTLC from client 0, got 0x%02x\n",
                        msg.msg_type);
                lsp_ok = 0;
            }
            cJSON_Delete(msg.json);
        }

        /* Step 2: Receive FULFILL_HTLC from Client B (index 1) */
        if (lsp_ok) {
            if (!wire_recv(lsp.client_fds[1], &msg)) {
                fprintf(stderr, "LSP: recv from client 1 failed\n");
                lsp_ok = 0;
            } else {
                if (msg.msg_type == MSG_UPDATE_FULFILL_HTLC) {
                    if (!lsp_channels_handle_msg(&ch_mgr, &lsp, 1, &msg)) {
                        fprintf(stderr, "LSP: handle FULFILL_HTLC failed\n");
                        lsp_ok = 0;
                    }
                } else {
                    fprintf(stderr, "LSP: expected FULFILL from client 1, got 0x%02x\n",
                            msg.msg_type);
                    lsp_ok = 0;
                }
                cJSON_Delete(msg.json);
            }
        }

        /* Verify channel balances updated correctly */
        if (lsp_ok) {
            channel_t *ch_a = &ch_mgr.entries[0].channel;
            channel_t *ch_b = &ch_mgr.entries[1].channel;

            printf("LSP: Channel A: local=%llu remote=%llu\n",
                   (unsigned long long)ch_a->local_amount,
                   (unsigned long long)ch_a->remote_amount);
            printf("LSP: Channel B: local=%llu remote=%llu\n",
                   (unsigned long long)ch_b->local_amount,
                   (unsigned long long)ch_b->remote_amount);

            /* After Client A pays Client B 5000 sats:
               Channel A (LSP view): LSP received 5000 from A
                 -> local increased by 5000, remote decreased by 5000
               Channel B (LSP view): LSP sent 5000 to B
                 -> local decreased by 5000, remote increased by 5000 */
            /* Initial amounts match lsp_channels_init: deduct commit_fee, split */
            fee_estimator_t _fe2; fee_init(&_fe2, 1000);
            uint64_t commit_fee_ab = fee_for_commitment_tx(&_fe2, 0);
            uint64_t usable_a = ch_a->funding_amount > commit_fee_ab ?
                                ch_a->funding_amount - commit_fee_ab : 0;
            uint64_t a_orig = usable_a / 2;
            uint64_t usable_b = ch_b->funding_amount > commit_fee_ab ?
                                ch_b->funding_amount - commit_fee_ab : 0;
            uint64_t b_orig = usable_b / 2;

            /* Check direction: on channel A, LSP received HTLC (local goes up) */
            if (ch_a->local_amount != a_orig + 5000) {
                fprintf(stderr, "LSP: Channel A local balance wrong: %llu vs expected %llu\n",
                        (unsigned long long)ch_a->local_amount,
                        (unsigned long long)(a_orig + 5000));
                lsp_ok = 0;
            }
            /* On channel B, LSP offered HTLC (local goes down) */
            if (ch_b->local_amount != b_orig - 5000) {
                fprintf(stderr, "LSP: Channel B local balance wrong: %llu vs expected %llu\n",
                        (unsigned long long)ch_b->local_amount,
                        (unsigned long long)(b_orig - 5000));
                lsp_ok = 0;
            }
        }
    }

    /* Cooperative close */
    if (lsp_ok) {
        uint64_t close_total = funding_amount - 500;
        size_t n_total = 5;
        uint64_t per_party = close_total / n_total;

        tx_output_t close_outputs[5];
        for (size_t i = 0; i < n_total; i++) {
            close_outputs[i].amount_sats = per_party;
            memcpy(close_outputs[i].script_pubkey, fund_spk, 34);
            close_outputs[i].script_pubkey_len = 34;
        }
        close_outputs[n_total - 1].amount_sats = close_total - per_party * (n_total - 1);

        tx_buf_t close_tx;
        tx_buf_init(&close_tx, 512);

        if (!lsp_run_cooperative_close(&lsp, &close_tx, close_outputs, n_total)) {
            fprintf(stderr, "LSP: cooperative close failed\n");
            lsp_ok = 0;
        } else {
            char close_hex[close_tx.len * 2 + 1];
            hex_encode(close_tx.data, close_tx.len, close_hex);
            char close_txid[65];
            if (regtest_send_raw_tx(&rt, close_hex, close_txid)) {
                regtest_mine_blocks(&rt, 1, mine_addr);
                int conf = regtest_get_confirmations(&rt, close_txid);
                if (conf < 1) {
                    fprintf(stderr, "LSP: close tx not confirmed\n");
                    lsp_ok = 0;
                }
            } else {
                fprintf(stderr, "LSP: broadcast close tx failed\n");
                lsp_ok = 0;
            }
        }
        tx_buf_free(&close_tx);
    }

    lsp_cleanup(&lsp);

    /* Wait for children */
    int all_children_ok = 1;
    for (int c = 0; c < 4; c++) {
        int status;
        waitpid(child_pids[c], &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "Client %d exited with status %d\n", c + 1,
                    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            all_children_ok = 0;
        }
    }

    secp256k1_context_destroy(ctx);

    TEST_ASSERT(lsp_ok, "LSP operations");
    TEST_ASSERT(all_children_ok, "all clients");
    return 1;
}

/* ---- Test 5: Multi-payment with balance-aware cooperative close ---- */

int test_regtest_multi_payment(void) {
    /* Initialize regtest */
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: regtest not available\n");
        return 0;
    }
    if (!regtest_create_wallet(&rt, "test_multi_pay")) {
        char *lr = regtest_exec(&rt, "loadwallet", "\"test_multi_pay\"");
        if (lr) free(lr);
        strncpy(rt.wallet, "test_multi_pay", sizeof(rt.wallet) - 1);
    }

    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_create(ctx, &kps[i], seckeys[i])) return 0;
    }

    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

    /* Compute funding SPK */
    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, 5);

    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    unsigned char tweak_val[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak_val);
    musig_keyagg_t ka_copy = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &ka_copy.cache, tweak_val)) return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) return 0;
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tweaked_xonly);

    /* Derive bech32m address */
    unsigned char tweaked_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, tweaked_ser, &tweaked_xonly)) return 0;
    char tweaked_hex[65];
    hex_encode(tweaked_ser, 32, tweaked_hex);

    char params[512];
    snprintf(params, sizeof(params), "\"rawtr(%s)\"", tweaked_hex);
    char *desc_result = regtest_exec(&rt, "getdescriptorinfo", params);
    TEST_ASSERT(desc_result != NULL, "getdescriptorinfo");

    char checksummed_desc[256];
    char *dstart = strstr(desc_result, "\"descriptor\"");
    TEST_ASSERT(dstart != NULL, "parse descriptor");
    dstart = strchr(dstart + 12, '"'); dstart++;
    char *dend = strchr(dstart, '"');
    size_t dlen = (size_t)(dend - dstart);
    memcpy(checksummed_desc, dstart, dlen);
    checksummed_desc[dlen] = '\0';
    free(desc_result);

    snprintf(params, sizeof(params), "\"%s\"", checksummed_desc);
    char *addr_result = regtest_exec(&rt, "deriveaddresses", params);
    TEST_ASSERT(addr_result != NULL, "deriveaddresses");

    char fund_addr[128] = {0};
    char *astart = strchr(addr_result, '"'); astart++;
    char *aend = strchr(astart, '"');
    size_t alen = (size_t)(aend - astart);
    memcpy(fund_addr, astart, alen);
    fund_addr[alen] = '\0';
    free(addr_result);

    /* Mine and fund */
    char mine_addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)),
                "get mine address");
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    TEST_ASSERT(regtest_get_balance(&rt) >= 0.01, "factory setup for funding");

    char funding_txid_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, fund_addr, 0.01, funding_txid_hex),
                "fund factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    unsigned char funding_txid[32];
    hex_decode(funding_txid_hex, funding_txid, 32);
    reverse_bytes(funding_txid, 32);

    uint64_t funding_amount = 0;
    unsigned char actual_spk[256];
    size_t actual_spk_len = 0;
    uint32_t funding_vout = 0;
    for (uint32_t v = 0; v < 2; v++) {
        regtest_get_tx_output(&rt, funding_txid_hex, v,
                              &funding_amount, actual_spk, &actual_spk_len);
        if (actual_spk_len == 34 && memcmp(actual_spk, fund_spk, 34) == 0) {
            funding_vout = v;
            break;
        }
    }
    TEST_ASSERT(funding_amount > 0, "funding amount > 0");

    /* Generate 4 payment preimages and hashes */
    unsigned char preimage1[32] = { [0 ... 31] = 0x11 };
    unsigned char preimage2[32] = { [0 ... 31] = 0x22 };
    unsigned char preimage3[32] = { [0 ... 31] = 0x33 };
    unsigned char preimage4[32] = { [0 ... 31] = 0x44 };
    unsigned char hash1[32], hash2[32], hash3[32], hash4[32];
    sha256(preimage1, 32, hash1);
    sha256(preimage2, 32, hash2);
    sha256(preimage3, 32, hash3);
    sha256(preimage4, 32, hash4);

    /* Build per-client action scripts:
       Client A (0): SEND(B,2000), RECV(preimage4)
       Client B (1): RECV(preimage1), SEND(C,1500)
       Client C (2): RECV(preimage2), SEND(D,1000)
       Client D (3): RECV(preimage3), SEND(A,600)
       (D→A changed from 500 to 600 to exceed CHANNEL_DUST_LIMIT_SATS=546) */

    /* Client A */
    scripted_action_t actions_a[2];
    memset(actions_a, 0, sizeof(actions_a));
    actions_a[0].type = ACTION_SEND;
    actions_a[0].dest_client = 1;  /* B */
    actions_a[0].amount_sats = 2000;
    memcpy(actions_a[0].payment_hash, hash1, 32);
    actions_a[1].type = ACTION_RECV;
    memcpy(actions_a[1].preimage, preimage4, 32);

    /* Client B */
    scripted_action_t actions_b[2];
    memset(actions_b, 0, sizeof(actions_b));
    actions_b[0].type = ACTION_RECV;
    memcpy(actions_b[0].preimage, preimage1, 32);
    actions_b[1].type = ACTION_SEND;
    actions_b[1].dest_client = 2;  /* C */
    actions_b[1].amount_sats = 1500;
    memcpy(actions_b[1].payment_hash, hash2, 32);

    /* Client C */
    scripted_action_t actions_c[2];
    memset(actions_c, 0, sizeof(actions_c));
    actions_c[0].type = ACTION_RECV;
    memcpy(actions_c[0].preimage, preimage2, 32);
    actions_c[1].type = ACTION_SEND;
    actions_c[1].dest_client = 3;  /* D */
    actions_c[1].amount_sats = 1000;
    memcpy(actions_c[1].payment_hash, hash3, 32);

    /* Client D */
    scripted_action_t actions_d[2];
    memset(actions_d, 0, sizeof(actions_d));
    actions_d[0].type = ACTION_RECV;
    memcpy(actions_d[0].preimage, preimage3, 32);
    actions_d[1].type = ACTION_SEND;
    actions_d[1].dest_client = 0;  /* A */
    actions_d[1].amount_sats = 600;
    memcpy(actions_d[1].payment_hash, hash4, 32);

    multi_payment_data_t mp_data[4];
    mp_data[0].actions = actions_a; mp_data[0].n_actions = 2; mp_data[0].current = 0;
    mp_data[1].actions = actions_b; mp_data[1].n_actions = 2; mp_data[1].current = 0;
    mp_data[2].actions = actions_c; mp_data[2].n_actions = 2; mp_data[2].current = 0;
    mp_data[3].actions = actions_d; mp_data[3].n_actions = 2; mp_data[3].current = 0;

    /* Use a fixed port with PID offset */
    int port = 19900 + (getpid() % 1000);

    /* Fork 4 client processes */
    pid_t child_pids[4];
    for (int c = 0; c < 4; c++) {
        pid_t pid = fork();
        if (pid == 0) {
            usleep(100000 * (c + 1));
            secp256k1_context *child_ctx = test_ctx();
            secp256k1_keypair child_kp;
            if (!secp256k1_keypair_create(child_ctx, &child_kp, seckeys[c + 1])) return 0;

            int ok = client_run_with_channels(child_ctx, &child_kp,
                                               "127.0.0.1", port,
                                               multi_payment_client_cb,
                                               &mp_data[c]);
            secp256k1_context_destroy(child_ctx);
            _exit(ok ? 0 : 1);
        }
        child_pids[c] = pid;
    }

    /* Parent: run LSP */
    lsp_t lsp;
    lsp_init(&lsp, ctx, &kps[0], port, 4);
    int lsp_ok = 1;

    if (!lsp_accept_clients(&lsp)) {
        fprintf(stderr, "LSP: accept clients failed\n");
        lsp_ok = 0;
    }

    if (lsp_ok && !lsp_run_factory_creation(&lsp,
                                             funding_txid, funding_vout,
                                             funding_amount,
                                             fund_spk, 34, 10, 4, 0)) {
        fprintf(stderr, "LSP: factory creation failed\n");
        lsp_ok = 0;
    }

    /* Initialize channel manager, exchange basepoints, and send CHANNEL_READY */
    lsp_channel_mgr_t ch_mgr;
    memset(&ch_mgr, 0, sizeof(ch_mgr));
    if (lsp_ok) {
        if (!lsp_channels_init(&ch_mgr, ctx, &lsp.factory, seckeys[0], 4)) {
            fprintf(stderr, "LSP: channel init failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok) {
        if (!lsp_channels_exchange_basepoints(&ch_mgr, &lsp)) {
            fprintf(stderr, "LSP: basepoint exchange failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok) {
        if (!lsp_channels_send_ready(&ch_mgr, &lsp)) {
            fprintf(stderr, "LSP: send channel_ready failed\n");
            lsp_ok = 0;
        }
    }

    /* Run event loop: 4 payments x 2 messages each = 8 messages */
    if (lsp_ok) {
        if (!lsp_channels_run_event_loop(&ch_mgr, &lsp, 8)) {
            fprintf(stderr, "LSP: event loop failed\n");
            lsp_ok = 0;
        }
    }

    /* Verify channel balances */
    if (lsp_ok) {
        /* Each channel starts at funding_amount/2 for local and remote.
           The leaf outputs split the factory funding among 4 channels + fees. */
        channel_t *ch_a = &ch_mgr.entries[0].channel;
        channel_t *ch_b = &ch_mgr.entries[1].channel;
        channel_t *ch_c = &ch_mgr.entries[2].channel;
        channel_t *ch_d = &ch_mgr.entries[3].channel;

        /* Initial amounts match lsp_channels_init: deduct commit_fee, split */
        fee_estimator_t _fe3; fee_init(&_fe3, 1000);
        uint64_t cfe = fee_for_commitment_tx(&_fe3, 0);
        uint64_t a_orig = (ch_a->funding_amount > cfe ?
                           ch_a->funding_amount - cfe : 0) / 2;
        uint64_t b_orig = (ch_b->funding_amount > cfe ?
                           ch_b->funding_amount - cfe : 0) / 2;
        uint64_t c_orig = (ch_c->funding_amount > cfe ?
                           ch_c->funding_amount - cfe : 0) / 2;
        uint64_t d_orig = (ch_d->funding_amount > cfe ?
                           ch_d->funding_amount - cfe : 0) / 2;

        /* A: +2000 local (received from A), -600 local (sent to A) = net +1400 */
        uint64_t exp_a_local = a_orig + 2000 - 600;
        uint64_t exp_a_remote = a_orig - 2000 + 600;
        /* B: -2000 local (sent to B), +1500 local (received from B) = net -500 */
        uint64_t exp_b_local = b_orig - 2000 + 1500;
        uint64_t exp_b_remote = b_orig + 2000 - 1500;
        /* C: -1500 local (sent to C), +1000 local (received from C) = net -500 */
        uint64_t exp_c_local = c_orig - 1500 + 1000;
        uint64_t exp_c_remote = c_orig + 1500 - 1000;
        /* D: -1000 local (sent to D), +600 local (received from D) = net -400 */
        uint64_t exp_d_local = d_orig - 1000 + 600;
        uint64_t exp_d_remote = d_orig + 1000 - 600;

        printf("LSP: Channel A: local=%llu remote=%llu (exp %llu/%llu)\n",
               (unsigned long long)ch_a->local_amount,
               (unsigned long long)ch_a->remote_amount,
               (unsigned long long)exp_a_local, (unsigned long long)exp_a_remote);
        printf("LSP: Channel B: local=%llu remote=%llu (exp %llu/%llu)\n",
               (unsigned long long)ch_b->local_amount,
               (unsigned long long)ch_b->remote_amount,
               (unsigned long long)exp_b_local, (unsigned long long)exp_b_remote);
        printf("LSP: Channel C: local=%llu remote=%llu (exp %llu/%llu)\n",
               (unsigned long long)ch_c->local_amount,
               (unsigned long long)ch_c->remote_amount,
               (unsigned long long)exp_c_local, (unsigned long long)exp_c_remote);
        printf("LSP: Channel D: local=%llu remote=%llu (exp %llu/%llu)\n",
               (unsigned long long)ch_d->local_amount,
               (unsigned long long)ch_d->remote_amount,
               (unsigned long long)exp_d_local, (unsigned long long)exp_d_remote);

        if (ch_a->local_amount != exp_a_local || ch_a->remote_amount != exp_a_remote) {
            fprintf(stderr, "Channel A balance mismatch\n");
            lsp_ok = 0;
        }
        if (ch_b->local_amount != exp_b_local || ch_b->remote_amount != exp_b_remote) {
            fprintf(stderr, "Channel B balance mismatch\n");
            lsp_ok = 0;
        }
        if (ch_c->local_amount != exp_c_local || ch_c->remote_amount != exp_c_remote) {
            fprintf(stderr, "Channel C balance mismatch\n");
            lsp_ok = 0;
        }
        if (ch_d->local_amount != exp_d_local || ch_d->remote_amount != exp_d_remote) {
            fprintf(stderr, "Channel D balance mismatch\n");
            lsp_ok = 0;
        }
    }

    /* Balance-aware cooperative close */
    if (lsp_ok) {
        uint64_t close_fee = 500;
        tx_output_t close_outputs[5];  /* 1 LSP + 4 clients */
        size_t n_close = lsp_channels_build_close_outputs(&ch_mgr, &lsp.factory,
                                                           close_outputs, close_fee);
        TEST_ASSERT(n_close == 5, "build close outputs returned 5");

        printf("LSP: Close outputs: LSP=%llu A=%llu B=%llu C=%llu D=%llu\n",
               (unsigned long long)close_outputs[0].amount_sats,
               (unsigned long long)close_outputs[1].amount_sats,
               (unsigned long long)close_outputs[2].amount_sats,
               (unsigned long long)close_outputs[3].amount_sats,
               (unsigned long long)close_outputs[4].amount_sats);

        tx_buf_t close_tx;
        tx_buf_init(&close_tx, 512);

        if (!lsp_run_cooperative_close(&lsp, &close_tx, close_outputs, n_close)) {
            fprintf(stderr, "LSP: cooperative close failed\n");
            lsp_ok = 0;
        } else {
            char close_hex[close_tx.len * 2 + 1];
            hex_encode(close_tx.data, close_tx.len, close_hex);
            char close_txid[65];
            if (regtest_send_raw_tx(&rt, close_hex, close_txid)) {
                regtest_mine_blocks(&rt, 1, mine_addr);
                int conf = regtest_get_confirmations(&rt, close_txid);
                if (conf < 1) {
                    fprintf(stderr, "LSP: close tx not confirmed\n");
                    lsp_ok = 0;
                } else {
                    /* Verify on-chain output amounts */
                    for (uint32_t v = 0; v < 5 && lsp_ok; v++) {
                        uint64_t onchain_amount = 0;
                        unsigned char onchain_spk[256];
                        size_t onchain_spk_len = 0;
                        regtest_get_tx_output(&rt, close_txid, v,
                                              &onchain_amount, onchain_spk,
                                              &onchain_spk_len);
                        if (onchain_amount != close_outputs[v].amount_sats) {
                            fprintf(stderr,
                                    "Close output %u: on-chain %llu != expected %llu\n",
                                    v, (unsigned long long)onchain_amount,
                                    (unsigned long long)close_outputs[v].amount_sats);
                            lsp_ok = 0;
                        }
                    }
                    if (lsp_ok)
                        printf("LSP: all close output amounts verified on-chain!\n");
                }
            } else {
                fprintf(stderr, "LSP: broadcast close tx failed\n");
                lsp_ok = 0;
            }
        }
        tx_buf_free(&close_tx);
    }

    lsp_cleanup(&lsp);

    /* Wait for children */
    int all_children_ok = 1;
    for (int c = 0; c < 4; c++) {
        int status;
        waitpid(child_pids[c], &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "Client %d exited with status %d\n", c + 1,
                    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            all_children_ok = 0;
        }
    }

    secp256k1_context_destroy(ctx);

    TEST_ASSERT(lsp_ok, "LSP multi-payment operations");
    TEST_ASSERT(all_children_ok, "all clients completed");
    return 1;
}

/* ---- Test: Fee policy balance split ---- */

int test_fee_policy_balance_split(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_create(ctx, &kps[i], seckeys[i])) return 0;
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
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

    factory_t f;
    factory_init_from_pubkeys(&f, ctx, pks, 5, 10, 4);
    unsigned char fake_txid[32] = {0};
    fake_txid[0] = 0xDD;
    factory_set_funding(&f, fake_txid, 0, 1000000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    fee_estimator_t fe;
    fee_init(&fe, 1000);
    uint64_t commit_fee = fee_for_commitment_tx(&fe, 0);

    /* Test 1: Default 50-50 split (pct=0 means default 50) */
    {
        lsp_channel_mgr_t mgr;
        memset(&mgr, 0, sizeof(mgr));
        TEST_ASSERT(lsp_channels_init(&mgr, ctx, &f, seckeys[0], 4), "init default");
        for (size_t c = 0; c < 4; c++) {
            channel_t *ch = &mgr.entries[c].channel;
            uint64_t usable = ch->funding_amount - commit_fee;
            TEST_ASSERT_EQ(ch->local_amount, usable / 2, "default 50% local");
            TEST_ASSERT_EQ(ch->remote_amount, usable - usable / 2, "default 50% remote");
        }
    }

    /* Test 2: Revenue-focused LSP with 70% share */
    {
        lsp_channel_mgr_t mgr;
        memset(&mgr, 0, sizeof(mgr));
        mgr.lsp_balance_pct = 70;
        TEST_ASSERT(lsp_channels_init(&mgr, ctx, &f, seckeys[0], 4), "init 70%");
        for (size_t c = 0; c < 4; c++) {
            channel_t *ch = &mgr.entries[c].channel;
            uint64_t usable = ch->funding_amount - commit_fee;
            uint64_t expected_local = (usable * 70) / 100;
            TEST_ASSERT_EQ(ch->local_amount, expected_local, "70% local");
            TEST_ASSERT_EQ(ch->remote_amount, usable - expected_local, "30% remote");
        }
    }

    /* Test 3: Generous LSP with 20% share */
    {
        lsp_channel_mgr_t mgr;
        memset(&mgr, 0, sizeof(mgr));
        mgr.lsp_balance_pct = 20;
        TEST_ASSERT(lsp_channels_init(&mgr, ctx, &f, seckeys[0], 4), "init 20%");
        for (size_t c = 0; c < 4; c++) {
            channel_t *ch = &mgr.entries[c].channel;
            uint64_t usable = ch->funding_amount - commit_fee;
            uint64_t expected_local = (usable * 20) / 100;
            TEST_ASSERT_EQ(ch->local_amount, expected_local, "20% local");
            TEST_ASSERT_EQ(ch->remote_amount, usable - expected_local, "80% remote");
        }
    }

    /* Test 4: pct > 100 clamped to 100 */
    {
        lsp_channel_mgr_t mgr;
        memset(&mgr, 0, sizeof(mgr));
        mgr.lsp_balance_pct = 150;
        TEST_ASSERT(lsp_channels_init(&mgr, ctx, &f, seckeys[0], 4), "init 150%");
        for (size_t c = 0; c < 4; c++) {
            channel_t *ch = &mgr.entries[c].channel;
            uint64_t usable = ch->funding_amount - commit_fee;
            TEST_ASSERT_EQ(ch->local_amount, usable, "clamped 100% local");
            TEST_ASSERT_EQ(ch->remote_amount, (uint64_t)0, "clamped 0% remote");
        }
    }

    /* Test 5: Fee policy fields survive init */
    {
        lsp_channel_mgr_t mgr;
        memset(&mgr, 0, sizeof(mgr));
        mgr.routing_fee_ppm = 1000;
        mgr.lsp_balance_pct = 60;
        TEST_ASSERT(lsp_channels_init(&mgr, ctx, &f, seckeys[0], 4), "init fee");
        TEST_ASSERT_EQ(mgr.routing_fee_ppm, 1000, "fee_ppm preserved");
        TEST_ASSERT_EQ(mgr.lsp_balance_pct, 60, "balance_pct preserved");
    }

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- CLTV Delta Enforcement (Phase 2: item 2.3) --- */

int test_cltv_delta_enforcement(void) {
    /* Test lsp_validate_cltv_for_forward — the production function used by
       handle_add_htlc to enforce the CLTV safety margin. */
    uint32_t fwd;

    /* cltv_expiry below delta: rejected */
    TEST_ASSERT(lsp_validate_cltv_for_forward(30, &fwd) == 0,
                "cltv 30 should be rejected");

    /* cltv_expiry == delta: rejected (need strictly >) */
    TEST_ASSERT(lsp_validate_cltv_for_forward(FACTORY_CLTV_DELTA, &fwd) == 0,
                "cltv == delta should be rejected");

    /* cltv_expiry == 0: rejected */
    TEST_ASSERT(lsp_validate_cltv_for_forward(0, &fwd) == 0,
                "cltv 0 should be rejected");

    /* cltv_expiry = delta + 1: passes, fwd = 1 */
    TEST_ASSERT(lsp_validate_cltv_for_forward(FACTORY_CLTV_DELTA + 1, &fwd) == 1,
                "cltv delta+1 should pass");
    TEST_ASSERT_EQ(fwd, (uint32_t)1, "fwd should be 1");

    /* cltv_expiry = 500: passes, fwd = 460 */
    TEST_ASSERT(lsp_validate_cltv_for_forward(500, &fwd) == 1,
                "cltv 500 should pass");
    TEST_ASSERT_EQ(fwd, (uint32_t)460, "fwd should be 460");

    /* NULL fwd_cltv_out: just validates without writing */
    TEST_ASSERT(lsp_validate_cltv_for_forward(500, NULL) == 1,
                "NULL out should still return 1");

    return 1;
}

/* --- Fee estimator integration tests (Phase 2: 2.1) --- */

int test_fee_estimator_wiring(void) {
    /* Non-default fee rate propagates through mgr to commitment fee */
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Create a fee estimator with 2000 sat/kvB (2x default) */
    fee_estimator_t fe;
    fee_init(&fe, 2000);

    /* Compute commitment fee at default (1000) and at 2000 */
    fee_estimator_t fe_default;
    fee_init(&fe_default, 1000);
    uint64_t fee_at_1000 = fee_for_commitment_tx(&fe_default, 0);
    uint64_t fee_at_2000 = fee_for_commitment_tx(&fe, 0);

    /* 2x rate should produce 2x fee */
    TEST_ASSERT_EQ(fee_at_2000, fee_at_1000 * 2, "2x rate = 2x fee");

    /* Verify channel_set_fee_rate works */
    unsigned char lsp_sec[32];
    memset(lsp_sec, 0x42, 32);
    secp256k1_keypair all_kps[5];
    if (!secp256k1_keypair_create(ctx, &all_kps[0], lsp_sec)) return 0;
    for (int i = 1; i < 5; i++) {
        unsigned char s[32];
        memset(s, 0x42 + (unsigned char)i, 32);
        if (!secp256k1_keypair_create(ctx, &all_kps[i], s)) return 0;
    }

    factory_t f;
    factory_init(&f, ctx, all_kps, 5, 10, 4);
    unsigned char fake_txid[32], fake_spk[34];
    memset(fake_txid, 0xBB, 32);
    memset(fake_spk, 0xCC, 34);
    factory_set_funding(&f, fake_txid, 0, 100000, fake_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* Init mgr with fee estimator */
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.fee = &fe;
    mgr.lsp_balance_pct = 50;
    TEST_ASSERT(lsp_channels_init(&mgr, ctx, &f, lsp_sec, 4), "init with fee");

    /* All channels should have the non-default fee rate */
    for (size_t c = 0; c < 4; c++) {
        TEST_ASSERT_EQ(mgr.entries[c].channel.fee_rate_sat_per_kvb, (uint64_t)2000,
                       "channel has 2000 sat/kvB");
    }

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_fee_estimator_null_fallback(void) {
    /* NULL fee pointer uses default 1000 sat/kvB */
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char lsp_sec[32];
    memset(lsp_sec, 0x52, 32);
    secp256k1_keypair all_kps[5];
    if (!secp256k1_keypair_create(ctx, &all_kps[0], lsp_sec)) return 0;
    for (int i = 1; i < 5; i++) {
        unsigned char s[32];
        memset(s, 0x52 + (unsigned char)i, 32);
        if (!secp256k1_keypair_create(ctx, &all_kps[i], s)) return 0;
    }

    factory_t f;
    factory_init(&f, ctx, all_kps, 5, 10, 4);
    unsigned char fake_txid[32], fake_spk[34];
    memset(fake_txid, 0xBB, 32);
    memset(fake_spk, 0xCC, 34);
    factory_set_funding(&f, fake_txid, 0, 100000, fake_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* Init mgr with NULL fee (should fallback to 1000) */
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.fee = NULL;
    mgr.lsp_balance_pct = 50;
    TEST_ASSERT(lsp_channels_init(&mgr, ctx, &f, lsp_sec, 4), "init with NULL fee");

    /* All channels should have default fee rate */
    for (size_t c = 0; c < 4; c++) {
        TEST_ASSERT_EQ(mgr.entries[c].channel.fee_rate_sat_per_kvb, (uint64_t)1000,
                       "channel has default 1000 sat/kvB");
    }

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_accept_timeout(void) {
    /* Test that lsp_accept_clients returns 0 when no client connects
       within the timeout period. Uses a real listen socket on a high port. */
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char sec[32];
    memset(sec, 0x77, 32);
    secp256k1_keypair kp;
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kp, sec), "keypair create");

    lsp_t lsp;
    memset(&lsp, 0, sizeof(lsp));
    TEST_ASSERT(lsp_init(&lsp, ctx, &kp, 19876, 1), "lsp_init");
    lsp.accept_timeout_sec = 1;

    /* No client connects — should timeout and return 0 */
    int ok = lsp_accept_clients(&lsp);
    TEST_ASSERT(ok == 0, "accept should timeout with no client");

    lsp_cleanup(&lsp);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_noise_nk_handshake(void) {
    /* End-to-end NK handshake over socketpair using fork.
       Same pattern as test_noise_handshake (NN) in test_reconnect.c. */
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Server static keypair */
    unsigned char server_sec[32];
    memset(server_sec, 0xAA, 32);
    secp256k1_pubkey server_pub;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &server_pub, server_sec),
                "server pubkey create");

    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: NK responder */
        close(sv[0]);
        secp256k1_context *child_ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        noise_state_t resp_ns;
        int ok = noise_handshake_nk_responder(&resp_ns, sv[1], child_ctx,
                                               server_sec);
        if (!ok) _exit(1);

        /* Write keys to parent for comparison */
        ssize_t w1 = write(sv[1], resp_ns.send_key, 32);
        ssize_t w2 = write(sv[1], resp_ns.recv_key, 32);
        if (w1 != 32 || w2 != 32) _exit(2);

        close(sv[1]);
        secp256k1_context_destroy(child_ctx);
        _exit(0);
    }

    /* Parent: NK initiator */
    close(sv[1]);
    noise_state_t init_ns;
    int ok = noise_handshake_nk_initiator(&init_ns, sv[0], ctx, &server_pub);
    TEST_ASSERT(ok, "NK initiator handshake failed");

    /* Read responder's keys */
    unsigned char resp_send[32], resp_recv[32];
    ssize_t r1 = read(sv[0], resp_send, 32);
    ssize_t r2 = read(sv[0], resp_recv, 32);
    TEST_ASSERT(r1 == 32 && r2 == 32, "failed to read responder keys");

    /* Initiator's send_key == Responder's recv_key */
    TEST_ASSERT(memcmp(init_ns.send_key, resp_recv, 32) == 0,
                "NK: initiator.send != responder.recv");
    /* Initiator's recv_key == Responder's send_key */
    TEST_ASSERT(memcmp(init_ns.recv_key, resp_send, 32) == 0,
                "NK: initiator.recv != responder.send");

    int status;
    waitpid(pid, &status, 0);
    TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "NK responder child failed");

    close(sv[0]);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_noise_nk_wrong_pubkey(void) {
    /* NK handshake where client pins the wrong server pubkey.
       The handshake completes but derived keys mismatch — MITM detected.
       Uses fork+socketpair like test_noise_nk_handshake. */
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Real server key */
    unsigned char server_sec[32];
    memset(server_sec, 0xBB, 32);

    /* Wrong key that client will pin */
    unsigned char wrong_sec[32];
    memset(wrong_sec, 0xCC, 32);
    secp256k1_pubkey wrong_pub;
    TEST_ASSERT(secp256k1_ec_pubkey_create(ctx, &wrong_pub, wrong_sec),
                "wrong pubkey create");

    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: NK responder with REAL server key */
        close(sv[0]);
        secp256k1_context *child_ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        noise_state_t resp_ns;
        int ok = noise_handshake_nk_responder(&resp_ns, sv[1], child_ctx,
                                               server_sec);
        if (!ok) _exit(1);

        /* Write keys to parent */
        ssize_t w1 = write(sv[1], resp_ns.send_key, 32);
        ssize_t w2 = write(sv[1], resp_ns.recv_key, 32);
        if (w1 != 32 || w2 != 32) _exit(2);

        close(sv[1]);
        secp256k1_context_destroy(child_ctx);
        _exit(0);
    }

    /* Parent: NK initiator with WRONG pinned pubkey */
    close(sv[1]);
    noise_state_t init_ns;
    int ok = noise_handshake_nk_initiator(&init_ns, sv[0], ctx, &wrong_pub);
    TEST_ASSERT(ok, "NK initiator handshake should succeed (key mismatch detected later)");

    /* Read responder's keys */
    unsigned char resp_send[32], resp_recv[32];
    ssize_t r1 = read(sv[0], resp_send, 32);
    ssize_t r2 = read(sv[0], resp_recv, 32);
    TEST_ASSERT(r1 == 32 && r2 == 32, "failed to read responder keys");

    /* Keys must NOT match — wrong pinned key means es DH diverges */
    TEST_ASSERT(memcmp(init_ns.send_key, resp_recv, 32) != 0,
                "NK keys should mismatch with wrong server pubkey");

    int status;
    waitpid(pid, &status, 0);
    /* Responder succeeds — it doesn't know the client pinned wrong key */
    TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "NK responder child failed");

    close(sv[0]);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Regtest: LSP crash recovery from SQLite ----
   Proves: after a payment, the LSP can persist channel state to SQLite,
   lose all in-memory state ("crash"), recover from the database, and the
   recovered channels have correct balances, commitment numbers, and
   basepoint secrets. Then cooperative close confirms on regtest. */

int test_regtest_lsp_restart_recovery(void) {
    /* Phase 1: Standard regtest factory setup */
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: regtest not available\n");
        return 0;
    }
    if (!regtest_create_wallet(&rt, "test_recovery")) {
        char *lr = regtest_exec(&rt, "loadwallet", "\"test_recovery\"");
        if (lr) free(lr);
        strncpy(rt.wallet, "test_recovery", sizeof(rt.wallet) - 1);
    }

    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_create(ctx, &kps[i], seckeys[i])) return 0;
    }
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

    /* Compute funding SPK */
    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, 5);
    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    unsigned char tweak_val[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak_val);
    musig_keyagg_t ka_copy = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &ka_copy.cache, tweak_val)) return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) return 0;
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tweaked_xonly);

    /* Derive bech32m address */
    unsigned char tweaked_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, tweaked_ser, &tweaked_xonly)) return 0;
    char tweaked_hex[65];
    hex_encode(tweaked_ser, 32, tweaked_hex);
    char params[512];
    snprintf(params, sizeof(params), "\"rawtr(%s)\"", tweaked_hex);
    char *desc_result = regtest_exec(&rt, "getdescriptorinfo", params);
    TEST_ASSERT(desc_result != NULL, "getdescriptorinfo");
    char checksummed_desc[256];
    char *dstart = strstr(desc_result, "\"descriptor\"");
    TEST_ASSERT(dstart != NULL, "parse descriptor");
    dstart = strchr(dstart + 12, '"'); dstart++;
    char *dend = strchr(dstart, '"');
    size_t dlen = (size_t)(dend - dstart);
    memcpy(checksummed_desc, dstart, dlen);
    checksummed_desc[dlen] = '\0';
    free(desc_result);

    snprintf(params, sizeof(params), "\"%s\"", checksummed_desc);
    char *addr_result = regtest_exec(&rt, "deriveaddresses", params);
    TEST_ASSERT(addr_result != NULL, "deriveaddresses");
    char fund_addr[128] = {0};
    char *astart = strchr(addr_result, '"'); astart++;
    char *aend = strchr(astart, '"');
    size_t alen = (size_t)(aend - astart);
    memcpy(fund_addr, astart, alen);
    fund_addr[alen] = '\0';
    free(addr_result);

    /* Mine and fund */
    char mine_addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)),
                "get mine address");
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    TEST_ASSERT(regtest_get_balance(&rt) >= 0.01, "balance for funding");

    char funding_txid_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, fund_addr, 0.01, funding_txid_hex),
                "fund factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    unsigned char funding_txid[32];
    hex_decode(funding_txid_hex, funding_txid, 32);
    reverse_bytes(funding_txid, 32);

    uint64_t funding_amount = 0;
    unsigned char actual_spk[256];
    size_t actual_spk_len = 0;
    uint32_t funding_vout = 0;
    for (uint32_t v = 0; v < 2; v++) {
        regtest_get_tx_output(&rt, funding_txid_hex, v,
                              &funding_amount, actual_spk, &actual_spk_len);
        if (actual_spk_len == 34 && memcmp(actual_spk, fund_spk, 34) == 0) {
            funding_vout = v;
            break;
        }
    }
    TEST_ASSERT(funding_amount > 0, "funding amount > 0");

    /* Generate payment preimage and hash */
    unsigned char preimage[32] = { [0 ... 31] = 0x77 };
    unsigned char payment_hash[32];
    sha256(preimage, 32, payment_hash);

    int port = 19700 + (getpid() % 1000);

    /* Prepare per-client test data (same as intra_factory_payment) */
    payment_test_data_t sender_data, payee_data, idle_data;
    memcpy(sender_data.payment_hash, payment_hash, 32);
    memset(sender_data.preimage, 0, 32);
    sender_data.is_sender = 1;
    sender_data.payment_done = 0;

    memcpy(payee_data.payment_hash, payment_hash, 32);
    memcpy(payee_data.preimage, preimage, 32);
    payee_data.is_sender = 0;
    payee_data.payment_done = 0;

    memset(&idle_data, 0, sizeof(idle_data));

    /* Fork 4 client processes */
    pid_t child_pids[4];
    for (int c = 0; c < 4; c++) {
        pid_t pid = fork();
        if (pid == 0) {
            usleep(100000 * (unsigned)(c + 1));
            secp256k1_context *child_ctx = test_ctx();
            secp256k1_keypair child_kp;
            if (!secp256k1_keypair_create(child_ctx, &child_kp, seckeys[c + 1]))
                _exit(1);
            void *cb_data;
            if (c == 0) cb_data = &sender_data;
            else if (c == 1) cb_data = &payee_data;
            else cb_data = &idle_data;
            int ok = client_run_with_channels(child_ctx, &child_kp,
                                               "127.0.0.1", port,
                                               payment_client_cb, cb_data);
            secp256k1_context_destroy(child_ctx);
            _exit(ok ? 0 : 1);
        }
        child_pids[c] = pid;
    }

    /* Parent: run LSP */
    lsp_t lsp;
    lsp_init(&lsp, ctx, &kps[0], port, 4);
    int lsp_ok = 1;

    if (!lsp_accept_clients(&lsp)) {
        fprintf(stderr, "LSP: accept clients failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok && !lsp_run_factory_creation(&lsp, funding_txid, funding_vout,
                                             funding_amount, fund_spk, 34,
                                             10, 4, 0)) {
        fprintf(stderr, "LSP: factory creation failed\n");
        lsp_ok = 0;
    }

    lsp_channel_mgr_t ch_mgr;
    memset(&ch_mgr, 0, sizeof(ch_mgr));
    if (lsp_ok && !lsp_channels_init(&ch_mgr, ctx, &lsp.factory, seckeys[0], 4)) {
        fprintf(stderr, "LSP: channel init failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok && !lsp_channels_exchange_basepoints(&ch_mgr, &lsp)) {
        fprintf(stderr, "LSP: basepoint exchange failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok && !lsp_channels_send_ready(&ch_mgr, &lsp)) {
        fprintf(stderr, "LSP: send channel_ready failed\n");
        lsp_ok = 0;
    }

    /* Phase 2: Process a payment (Client A → Client B, 5000 sats) */
    if (lsp_ok) {
        wire_msg_t msg;
        if (!wire_recv(lsp.client_fds[0], &msg)) {
            fprintf(stderr, "LSP: recv from client 0 failed\n");
            lsp_ok = 0;
        } else {
            if (msg.msg_type == MSG_UPDATE_ADD_HTLC) {
                if (!lsp_channels_handle_msg(&ch_mgr, &lsp, 0, &msg)) {
                    fprintf(stderr, "LSP: handle ADD_HTLC failed\n");
                    lsp_ok = 0;
                }
            } else {
                fprintf(stderr, "LSP: expected ADD_HTLC, got 0x%02x\n",
                        msg.msg_type);
                lsp_ok = 0;
            }
            cJSON_Delete(msg.json);
        }
        if (lsp_ok) {
            if (!wire_recv(lsp.client_fds[1], &msg)) {
                fprintf(stderr, "LSP: recv from client 1 failed\n");
                lsp_ok = 0;
            } else {
                if (msg.msg_type == MSG_UPDATE_FULFILL_HTLC) {
                    if (!lsp_channels_handle_msg(&ch_mgr, &lsp, 1, &msg)) {
                        fprintf(stderr, "LSP: handle FULFILL_HTLC failed\n");
                        lsp_ok = 0;
                    }
                } else {
                    fprintf(stderr, "LSP: expected FULFILL, got 0x%02x\n",
                            msg.msg_type);
                    lsp_ok = 0;
                }
                cJSON_Delete(msg.json);
            }
        }
    }

    /* Phase 3: Record pre-crash channel state */
    uint64_t pre_local[4], pre_remote[4], pre_commit[4];
    unsigned char pre_bp_pay[4][32], pre_bp_delay[4][32];
    unsigned char pre_bp_revoc[4][32], pre_bp_htlc[4][32];
    if (lsp_ok) {
        for (int c = 0; c < 4; c++) {
            const channel_t *ch = &ch_mgr.entries[c].channel;
            pre_local[c] = ch->local_amount;
            pre_remote[c] = ch->remote_amount;
            pre_commit[c] = ch->commitment_number;
            memcpy(pre_bp_pay[c],
                   ch->local_payment_basepoint_secret, 32);
            memcpy(pre_bp_delay[c],
                   ch->local_delayed_payment_basepoint_secret, 32);
            memcpy(pre_bp_revoc[c],
                   ch->local_revocation_basepoint_secret, 32);
            memcpy(pre_bp_htlc[c],
                   ch->local_htlc_basepoint_secret, 32);
        }
        printf("LSP: pre-crash state: ch0 local=%llu remote=%llu cn=%llu\n",
               (unsigned long long)pre_local[0],
               (unsigned long long)pre_remote[0],
               (unsigned long long)pre_commit[0]);
    }

    /* Phase 4: Persist to SQLite */
    const char *db_path = "/tmp/test_lsp_recovery.db";
    persist_t db;
    int db_open = 0;
    if (lsp_ok) {
        unlink(db_path);
        if (!persist_open(&db, db_path)) {
            fprintf(stderr, "LSP: persist_open failed\n");
            lsp_ok = 0;
        } else {
            db_open = 1;
        }
    }
    if (lsp_ok && !persist_begin(&db)) {
        fprintf(stderr, "LSP: persist_begin failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok && !persist_save_factory(&db, &lsp.factory, ctx, 0)) {
        fprintf(stderr, "LSP: persist_save_factory failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok) {
        for (int c = 0; c < 4; c++) {
            if (!persist_save_channel(&db, &ch_mgr.entries[c].channel,
                                        0, (uint32_t)c) ||
                !persist_save_basepoints(&db, (uint32_t)c,
                                           &ch_mgr.entries[c].channel) ||
                !persist_update_channel_balance(&db, (uint32_t)c,
                    ch_mgr.entries[c].channel.local_amount,
                    ch_mgr.entries[c].channel.remote_amount,
                    ch_mgr.entries[c].channel.commitment_number)) {
                fprintf(stderr, "LSP: persist channel %d failed\n", c);
                lsp_ok = 0;
                break;
            }
        }
    }
    if (lsp_ok && !persist_commit(&db)) {
        fprintf(stderr, "LSP: persist_commit failed\n");
        lsp_ok = 0;
    }

    /* Phase 5: "Crash" — zero out channel manager */
    if (lsp_ok) {
        printf("LSP: === SIMULATING CRASH ===\n");
        memset(&ch_mgr, 0, sizeof(ch_mgr));
    }

    /* Phase 6: Recover from SQLite */
    factory_t rec_f;
    lsp_channel_mgr_t rec_mgr;
    memset(&rec_f, 0, sizeof(rec_f));
    memset(&rec_mgr, 0, sizeof(rec_mgr));
    if (lsp_ok) {
        printf("LSP: === RECOVERING FROM SQLITE ===\n");
        if (!persist_load_factory(&db, 0, &rec_f, ctx)) {
            fprintf(stderr, "LSP: persist_load_factory failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok && rec_f.n_participants != 5) {
        fprintf(stderr, "LSP: recovered n_participants=%zu, expected 5\n",
                rec_f.n_participants);
        lsp_ok = 0;
    }
    if (lsp_ok) {
        if (!lsp_channels_init_from_db(&rec_mgr, ctx, &rec_f,
                                         seckeys[0], 4, &db)) {
            fprintf(stderr, "LSP: init_from_db failed\n");
            lsp_ok = 0;
        }
    }

    /* Phase 7: Verify recovered state matches pre-crash state */
    if (lsp_ok && rec_mgr.n_channels != 4) {
        fprintf(stderr, "LSP: recovered n_channels=%zu, expected 4\n",
                rec_mgr.n_channels);
        lsp_ok = 0;
    }
    if (lsp_ok) {
        for (int c = 0; c < 4; c++) {
            const channel_t *rec = &rec_mgr.entries[c].channel;
            if (rec->local_amount != pre_local[c]) {
                fprintf(stderr, "ch%d local %llu != %llu\n", c,
                        (unsigned long long)rec->local_amount,
                        (unsigned long long)pre_local[c]);
                lsp_ok = 0; break;
            }
            if (rec->remote_amount != pre_remote[c]) {
                fprintf(stderr, "ch%d remote %llu != %llu\n", c,
                        (unsigned long long)rec->remote_amount,
                        (unsigned long long)pre_remote[c]);
                lsp_ok = 0; break;
            }
            if (rec->commitment_number != pre_commit[c]) {
                fprintf(stderr, "ch%d commit_num %llu != %llu\n", c,
                        (unsigned long long)rec->commitment_number,
                        (unsigned long long)pre_commit[c]);
                lsp_ok = 0; break;
            }
            if (memcmp(rec->local_payment_basepoint_secret,
                       pre_bp_pay[c], 32) != 0 ||
                memcmp(rec->local_delayed_payment_basepoint_secret,
                       pre_bp_delay[c], 32) != 0 ||
                memcmp(rec->local_revocation_basepoint_secret,
                       pre_bp_revoc[c], 32) != 0 ||
                memcmp(rec->local_htlc_basepoint_secret,
                       pre_bp_htlc[c], 32) != 0) {
                fprintf(stderr, "ch%d basepoint secret mismatch\n", c);
                lsp_ok = 0; break;
            }
            if (!rec_mgr.entries[c].ready) {
                fprintf(stderr, "ch%d not marked ready\n", c);
                lsp_ok = 0; break;
            }
        }
    }
    if (lsp_ok) {
        printf("LSP: recovery verified — 4 channels match pre-crash state\n");
    }

    /* Clean up DB */
    if (db_open) {
        persist_close(&db);
        unlink(db_path);
    }

    /* Phase 8: Cooperative close on regtest */
    if (lsp_ok) {
        uint64_t close_total = funding_amount - 500;
        size_t n_total = 5;
        uint64_t per_party = close_total / n_total;

        tx_output_t close_outputs[5];
        for (size_t i = 0; i < n_total; i++) {
            close_outputs[i].amount_sats = per_party;
            memcpy(close_outputs[i].script_pubkey, fund_spk, 34);
            close_outputs[i].script_pubkey_len = 34;
        }
        close_outputs[n_total - 1].amount_sats =
            close_total - per_party * (n_total - 1);

        tx_buf_t close_tx;
        tx_buf_init(&close_tx, 512);

        if (!lsp_run_cooperative_close(&lsp, &close_tx, close_outputs,
                                        n_total)) {
            fprintf(stderr, "LSP: cooperative close failed\n");
            lsp_ok = 0;
        } else {
            char close_hex[close_tx.len * 2 + 1];
            hex_encode(close_tx.data, close_tx.len, close_hex);
            char close_txid[65];
            if (regtest_send_raw_tx(&rt, close_hex, close_txid)) {
                regtest_mine_blocks(&rt, 1, mine_addr);
                int conf = regtest_get_confirmations(&rt, close_txid);
                if (conf < 1) {
                    fprintf(stderr, "LSP: close tx not confirmed\n");
                    lsp_ok = 0;
                }
            } else {
                fprintf(stderr, "LSP: broadcast close tx failed\n");
                lsp_ok = 0;
            }
        }
        tx_buf_free(&close_tx);
    }

    lsp_cleanup(&lsp);

    /* Wait for children */
    int all_children_ok = 1;
    for (int c = 0; c < 4; c++) {
        int status;
        waitpid(child_pids[c], &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "Client %d failed (status %d)\n", c + 1,
                    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            all_children_ok = 0;
        }
    }

    secp256k1_context_destroy(ctx);
    return lsp_ok && all_children_ok;
}

/* Phase 7: Profit settlement calculation */
int test_profit_settlement_calculation(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));

    /* Set up 3 channels with known balances */
    mgr.n_channels = 3;
    for (size_t i = 0; i < 3; i++) {
        mgr.entries[i].channel.local_amount = 50000;
        mgr.entries[i].channel.remote_amount = 50000;
        mgr.entries[i].ready = 1;
    }

    /* Build a minimal factory with profit-shared economics */
    factory_t f;
    memset(&f, 0, sizeof(f));
    f.economic_mode = ECON_PROFIT_SHARED;
    f.n_participants = 4; /* LSP + 3 clients */
    /* LSP gets 40%, each client gets 20% = 2000 bps */
    f.profiles[0].profit_share_bps = 4000;
    f.profiles[1].profit_share_bps = 2000;
    f.profiles[2].profit_share_bps = 2000;
    f.profiles[3].profit_share_bps = 2000;

    /* Accumulate 10000 sats in fees */
    mgr.accumulated_fees_sats = 10000;
    mgr.economic_mode = ECON_PROFIT_SHARED;

    int settled = lsp_channels_settle_profits(&mgr, &f);
    TEST_ASSERT(settled > 0, "settlement happened");

    /* Each client should receive 2000 bps of 10000 = 2000 sats */
    for (size_t i = 0; i < 3; i++) {
        TEST_ASSERT_EQ(mgr.entries[i].channel.remote_amount, 52000,
                        "client remote_amount increased by share");
        TEST_ASSERT_EQ(mgr.entries[i].channel.local_amount, 48000,
                        "LSP local_amount decreased by share");
    }

    TEST_ASSERT_EQ(mgr.accumulated_fees_sats, 0, "fees reset after settlement");
    return 1;
}

int test_settlement_trigger_at_interval(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.n_channels = 2;
    mgr.entries[0].channel.local_amount = 50000;
    mgr.entries[0].channel.remote_amount = 50000;
    mgr.entries[1].channel.local_amount = 50000;
    mgr.entries[1].channel.remote_amount = 50000;

    factory_t f;
    memset(&f, 0, sizeof(f));
    f.n_participants = 3;
    f.profiles[0].profit_share_bps = 5000;
    f.profiles[1].profit_share_bps = 2500;
    f.profiles[2].profit_share_bps = 2500;

    /* LSP-takes-all mode: no settlement */
    mgr.economic_mode = ECON_LSP_TAKES_ALL;
    mgr.accumulated_fees_sats = 5000;
    f.economic_mode = ECON_LSP_TAKES_ALL;
    int settled = lsp_channels_settle_profits(&mgr, &f);
    TEST_ASSERT_EQ(settled, 0, "no settlement in LSP-takes-all mode");
    TEST_ASSERT_EQ(mgr.accumulated_fees_sats, 5000, "fees unchanged");

    /* Profit-shared but zero fees: no settlement */
    mgr.economic_mode = ECON_PROFIT_SHARED;
    mgr.accumulated_fees_sats = 0;
    f.economic_mode = ECON_PROFIT_SHARED;
    settled = lsp_channels_settle_profits(&mgr, &f);
    TEST_ASSERT_EQ(settled, 0, "no settlement with zero fees");

    return 1;
}

int test_on_close_includes_unsettled(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.n_channels = 2;
    mgr.accumulated_fees_sats = 8000;
    mgr.economic_mode = ECON_PROFIT_SHARED;

    factory_t f;
    memset(&f, 0, sizeof(f));
    f.economic_mode = ECON_PROFIT_SHARED;
    f.n_participants = 3;
    f.profiles[0].profit_share_bps = 4000; /* LSP */
    f.profiles[1].profit_share_bps = 3000; /* client 0 */
    f.profiles[2].profit_share_bps = 3000; /* client 1 */

    /* Client 0: 3000 bps of 8000 = 2400 sats */
    uint64_t share0 = lsp_channels_unsettled_share(&mgr, &f, 0);
    TEST_ASSERT_EQ(share0, 2400, "client 0 unsettled share");

    /* Client 1: 3000 bps of 8000 = 2400 sats */
    uint64_t share1 = lsp_channels_unsettled_share(&mgr, &f, 1);
    TEST_ASSERT_EQ(share1, 2400, "client 1 unsettled share");

    return 1;
}

/* ---- Test: Double crash/recovery + cooperative close on regtest ---- */

int test_regtest_crash_double_recovery(void) {
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: regtest not available\n");
        return 0;
    }
    if (!regtest_create_wallet(&rt, "test_dbl_recov")) {
        char *lr = regtest_exec(&rt, "loadwallet", "\"test_dbl_recov\"");
        if (lr) free(lr);
        strncpy(rt.wallet, "test_dbl_recov", sizeof(rt.wallet) - 1);
    }

    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_create(ctx, &kps[i], seckeys[i])) return 0;
    }
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

    /* Compute funding SPK */
    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, 5);
    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    unsigned char tweak_val[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak_val);
    musig_keyagg_t ka_copy = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &ka_copy.cache, tweak_val)) return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) return 0;
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tweaked_xonly);

    /* Derive bech32m address */
    unsigned char tweaked_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, tweaked_ser, &tweaked_xonly)) return 0;
    char tweaked_hex[65];
    hex_encode(tweaked_ser, 32, tweaked_hex);
    char params[512];
    snprintf(params, sizeof(params), "\"rawtr(%s)\"", tweaked_hex);
    char *desc_result = regtest_exec(&rt, "getdescriptorinfo", params);
    TEST_ASSERT(desc_result != NULL, "getdescriptorinfo");
    char checksummed_desc[256];
    char *dstart = strstr(desc_result, "\"descriptor\"");
    TEST_ASSERT(dstart != NULL, "parse descriptor");
    dstart = strchr(dstart + 12, '"'); dstart++;
    char *dend = strchr(dstart, '"');
    size_t dlen = (size_t)(dend - dstart);
    memcpy(checksummed_desc, dstart, dlen);
    checksummed_desc[dlen] = '\0';
    free(desc_result);

    snprintf(params, sizeof(params), "\"%s\"", checksummed_desc);
    char *addr_result = regtest_exec(&rt, "deriveaddresses", params);
    TEST_ASSERT(addr_result != NULL, "deriveaddresses");
    char fund_addr[128] = {0};
    char *astart = strchr(addr_result, '"'); astart++;
    char *aend = strchr(astart, '"');
    size_t alen = (size_t)(aend - astart);
    memcpy(fund_addr, astart, alen);
    fund_addr[alen] = '\0';
    free(addr_result);

    /* Mine and fund */
    char mine_addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)),
                "get mine address");
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    TEST_ASSERT(regtest_get_balance(&rt) >= 0.01, "balance for funding");

    char funding_txid_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, fund_addr, 0.01, funding_txid_hex),
                "fund factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    unsigned char funding_txid[32];
    hex_decode(funding_txid_hex, funding_txid, 32);
    reverse_bytes(funding_txid, 32);

    uint64_t funding_amount = 0;
    unsigned char actual_spk[256];
    size_t actual_spk_len = 0;
    uint32_t funding_vout = 0;
    for (uint32_t v = 0; v < 2; v++) {
        regtest_get_tx_output(&rt, funding_txid_hex, v,
                              &funding_amount, actual_spk, &actual_spk_len);
        if (actual_spk_len == 34 && memcmp(actual_spk, fund_spk, 34) == 0) {
            funding_vout = v;
            break;
        }
    }
    TEST_ASSERT(funding_amount > 0, "funding amount > 0");

    /* Generate payment preimage and hash */
    unsigned char preimage[32] = { [0 ... 31] = 0x77 };
    unsigned char payment_hash[32];
    sha256(preimage, 32, payment_hash);

    int port = 19800 + (getpid() % 1000);

    /* Prepare per-client test data */
    payment_test_data_t sender_data, payee_data, idle_data;
    memcpy(sender_data.payment_hash, payment_hash, 32);
    memset(sender_data.preimage, 0, 32);
    sender_data.is_sender = 1;
    sender_data.payment_done = 0;

    memcpy(payee_data.payment_hash, payment_hash, 32);
    memcpy(payee_data.preimage, preimage, 32);
    payee_data.is_sender = 0;
    payee_data.payment_done = 0;

    memset(&idle_data, 0, sizeof(idle_data));

    /* Fork 4 client processes */
    pid_t child_pids[4];
    for (int c = 0; c < 4; c++) {
        pid_t pid = fork();
        if (pid == 0) {
            usleep(100000 * (unsigned)(c + 1));
            secp256k1_context *child_ctx = test_ctx();
            secp256k1_keypair child_kp;
            if (!secp256k1_keypair_create(child_ctx, &child_kp, seckeys[c + 1]))
                _exit(1);
            void *cb_data;
            if (c == 0) cb_data = &sender_data;
            else if (c == 1) cb_data = &payee_data;
            else cb_data = &idle_data;
            int ok = client_run_with_channels(child_ctx, &child_kp,
                                               "127.0.0.1", port,
                                               payment_client_cb, cb_data);
            secp256k1_context_destroy(child_ctx);
            _exit(ok ? 0 : 1);
        }
        child_pids[c] = pid;
    }

    /* Parent: run LSP */
    lsp_t lsp;
    lsp_init(&lsp, ctx, &kps[0], port, 4);
    int lsp_ok = 1;

    if (!lsp_accept_clients(&lsp)) {
        fprintf(stderr, "LSP: accept clients failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok && !lsp_run_factory_creation(&lsp, funding_txid, funding_vout,
                                             funding_amount, fund_spk, 34,
                                             10, 4, 0)) {
        fprintf(stderr, "LSP: factory creation failed\n");
        lsp_ok = 0;
    }

    lsp_channel_mgr_t ch_mgr;
    memset(&ch_mgr, 0, sizeof(ch_mgr));
    if (lsp_ok && !lsp_channels_init(&ch_mgr, ctx, &lsp.factory, seckeys[0], 4)) {
        fprintf(stderr, "LSP: channel init failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok && !lsp_channels_exchange_basepoints(&ch_mgr, &lsp)) {
        fprintf(stderr, "LSP: basepoint exchange failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok && !lsp_channels_send_ready(&ch_mgr, &lsp)) {
        fprintf(stderr, "LSP: send channel_ready failed\n");
        lsp_ok = 0;
    }

    /* Process payment (Client A → Client B, 5000 sats) */
    if (lsp_ok) {
        wire_msg_t msg;
        if (!wire_recv(lsp.client_fds[0], &msg)) {
            fprintf(stderr, "LSP: recv from client 0 failed\n");
            lsp_ok = 0;
        } else {
            if (msg.msg_type == MSG_UPDATE_ADD_HTLC) {
                if (!lsp_channels_handle_msg(&ch_mgr, &lsp, 0, &msg)) {
                    fprintf(stderr, "LSP: handle ADD_HTLC failed\n");
                    lsp_ok = 0;
                }
            } else {
                fprintf(stderr, "LSP: expected ADD_HTLC, got 0x%02x\n",
                        msg.msg_type);
                lsp_ok = 0;
            }
            cJSON_Delete(msg.json);
        }
        if (lsp_ok) {
            if (!wire_recv(lsp.client_fds[1], &msg)) {
                fprintf(stderr, "LSP: recv from client 1 failed\n");
                lsp_ok = 0;
            } else {
                if (msg.msg_type == MSG_UPDATE_FULFILL_HTLC) {
                    if (!lsp_channels_handle_msg(&ch_mgr, &lsp, 1, &msg)) {
                        fprintf(stderr, "LSP: handle FULFILL_HTLC failed\n");
                        lsp_ok = 0;
                    }
                } else {
                    fprintf(stderr, "LSP: expected FULFILL, got 0x%02x\n",
                            msg.msg_type);
                    lsp_ok = 0;
                }
                cJSON_Delete(msg.json);
            }
        }
    }

    /* Record pre-crash state */
    uint64_t pre_local[4], pre_remote[4], pre_commit[4];
    unsigned char pre_bp_pay[4][32], pre_bp_delay[4][32];
    unsigned char pre_bp_revoc[4][32], pre_bp_htlc[4][32];
    if (lsp_ok) {
        for (int c = 0; c < 4; c++) {
            const channel_t *ch = &ch_mgr.entries[c].channel;
            pre_local[c] = ch->local_amount;
            pre_remote[c] = ch->remote_amount;
            pre_commit[c] = ch->commitment_number;
            memcpy(pre_bp_pay[c], ch->local_payment_basepoint_secret, 32);
            memcpy(pre_bp_delay[c], ch->local_delayed_payment_basepoint_secret, 32);
            memcpy(pre_bp_revoc[c], ch->local_revocation_basepoint_secret, 32);
            memcpy(pre_bp_htlc[c], ch->local_htlc_basepoint_secret, 32);
        }
    }

    /* ===== Crash #1: Persist → zero → recover ===== */
    const char *db_path = "/tmp/test_double_recovery.db";
    persist_t db;
    int db_open = 0;
    if (lsp_ok) {
        unlink(db_path);
        if (!persist_open(&db, db_path)) {
            fprintf(stderr, "LSP: persist_open failed\n");
            lsp_ok = 0;
        } else {
            db_open = 1;
        }
    }
    if (lsp_ok && !persist_begin(&db)) {
        fprintf(stderr, "LSP: persist_begin failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok && !persist_save_factory(&db, &lsp.factory, ctx, 0)) {
        fprintf(stderr, "LSP: persist_save_factory failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok) {
        for (int c = 0; c < 4; c++) {
            if (!persist_save_channel(&db, &ch_mgr.entries[c].channel,
                                        0, (uint32_t)c) ||
                !persist_save_basepoints(&db, (uint32_t)c,
                                           &ch_mgr.entries[c].channel) ||
                !persist_update_channel_balance(&db, (uint32_t)c,
                    ch_mgr.entries[c].channel.local_amount,
                    ch_mgr.entries[c].channel.remote_amount,
                    ch_mgr.entries[c].channel.commitment_number)) {
                fprintf(stderr, "LSP: persist channel %d failed\n", c);
                lsp_ok = 0;
                break;
            }
        }
    }
    if (lsp_ok && !persist_commit(&db)) {
        fprintf(stderr, "LSP: persist_commit failed\n");
        lsp_ok = 0;
    }

    if (lsp_ok) {
        printf("LSP: === CRASH #1 ===\n");
        memset(&ch_mgr, 0, sizeof(ch_mgr));
    }

    /* Recover #1 */
    factory_t rec_f;
    lsp_channel_mgr_t rec_mgr;
    memset(&rec_f, 0, sizeof(rec_f));
    memset(&rec_mgr, 0, sizeof(rec_mgr));
    if (lsp_ok) {
        if (!persist_load_factory(&db, 0, &rec_f, ctx)) {
            fprintf(stderr, "LSP: load factory #1 failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok && !lsp_channels_init_from_db(&rec_mgr, ctx, &rec_f,
                                               seckeys[0], 4, &db)) {
        fprintf(stderr, "LSP: init_from_db #1 failed\n");
        lsp_ok = 0;
    }

    /* Verify recovery #1 */
    if (lsp_ok) {
        for (int c = 0; c < 4; c++) {
            const channel_t *rec = &rec_mgr.entries[c].channel;
            if (rec->local_amount != pre_local[c] ||
                rec->remote_amount != pre_remote[c] ||
                rec->commitment_number != pre_commit[c]) {
                fprintf(stderr, "ch%d recovery #1 mismatch\n", c);
                lsp_ok = 0; break;
            }
            if (memcmp(rec->local_payment_basepoint_secret,
                       pre_bp_pay[c], 32) != 0 ||
                memcmp(rec->local_delayed_payment_basepoint_secret,
                       pre_bp_delay[c], 32) != 0 ||
                memcmp(rec->local_revocation_basepoint_secret,
                       pre_bp_revoc[c], 32) != 0 ||
                memcmp(rec->local_htlc_basepoint_secret,
                       pre_bp_htlc[c], 32) != 0) {
                fprintf(stderr, "ch%d basepoint #1 mismatch\n", c);
                lsp_ok = 0; break;
            }
        }
        if (lsp_ok)
            printf("LSP: recovery #1 verified\n");
    }

    /* ===== Crash #2: Re-persist recovered state → zero → recover again ===== */
    if (lsp_ok) {
        /* Re-persist into the SAME DB (tests INSERT OR REPLACE / UPDATE idempotency) */
        if (!persist_begin(&db)) {
            fprintf(stderr, "LSP: persist_begin #2 failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok) {
        for (int c = 0; c < 4; c++) {
            if (!persist_save_channel(&db, &rec_mgr.entries[c].channel,
                                        0, (uint32_t)c) ||
                !persist_save_basepoints(&db, (uint32_t)c,
                                           &rec_mgr.entries[c].channel) ||
                !persist_update_channel_balance(&db, (uint32_t)c,
                    rec_mgr.entries[c].channel.local_amount,
                    rec_mgr.entries[c].channel.remote_amount,
                    rec_mgr.entries[c].channel.commitment_number)) {
                fprintf(stderr, "LSP: re-persist channel %d failed\n", c);
                lsp_ok = 0;
                break;
            }
        }
    }
    if (lsp_ok && !persist_commit(&db)) {
        fprintf(stderr, "LSP: persist_commit #2 failed\n");
        lsp_ok = 0;
    }

    if (lsp_ok) {
        printf("LSP: === CRASH #2 ===\n");
        memset(&rec_mgr, 0, sizeof(rec_mgr));
    }

    /* Recover #2 */
    lsp_channel_mgr_t rec_mgr2;
    factory_t rec_f2;
    memset(&rec_f2, 0, sizeof(rec_f2));
    memset(&rec_mgr2, 0, sizeof(rec_mgr2));
    if (lsp_ok) {
        if (!persist_load_factory(&db, 0, &rec_f2, ctx)) {
            fprintf(stderr, "LSP: load factory #2 failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok && !lsp_channels_init_from_db(&rec_mgr2, ctx, &rec_f2,
                                               seckeys[0], 4, &db)) {
        fprintf(stderr, "LSP: init_from_db #2 failed\n");
        lsp_ok = 0;
    }

    /* Verify recovery #2 matches original pre-crash state (idempotent) */
    if (lsp_ok) {
        for (int c = 0; c < 4; c++) {
            const channel_t *rec = &rec_mgr2.entries[c].channel;
            if (rec->local_amount != pre_local[c] ||
                rec->remote_amount != pre_remote[c] ||
                rec->commitment_number != pre_commit[c]) {
                fprintf(stderr, "ch%d recovery #2 mismatch\n", c);
                lsp_ok = 0; break;
            }
            if (memcmp(rec->local_payment_basepoint_secret,
                       pre_bp_pay[c], 32) != 0 ||
                memcmp(rec->local_delayed_payment_basepoint_secret,
                       pre_bp_delay[c], 32) != 0 ||
                memcmp(rec->local_revocation_basepoint_secret,
                       pre_bp_revoc[c], 32) != 0 ||
                memcmp(rec->local_htlc_basepoint_secret,
                       pre_bp_htlc[c], 32) != 0) {
                fprintf(stderr, "ch%d basepoint #2 mismatch\n", c);
                lsp_ok = 0; break;
            }
        }
        if (lsp_ok)
            printf("LSP: recovery #2 verified — idempotent\n");
    }

    /* Clean up DB */
    if (db_open) {
        persist_close(&db);
        unlink(db_path);
    }

    /* Cooperative close on regtest */
    if (lsp_ok) {
        uint64_t close_total = funding_amount - 500;
        size_t n_total = 5;
        uint64_t per_party = close_total / n_total;

        tx_output_t close_outputs[5];
        for (size_t i = 0; i < n_total; i++) {
            close_outputs[i].amount_sats = per_party;
            memcpy(close_outputs[i].script_pubkey, fund_spk, 34);
            close_outputs[i].script_pubkey_len = 34;
        }
        close_outputs[n_total - 1].amount_sats =
            close_total - per_party * (n_total - 1);

        tx_buf_t close_tx;
        tx_buf_init(&close_tx, 512);

        if (!lsp_run_cooperative_close(&lsp, &close_tx, close_outputs,
                                        n_total)) {
            fprintf(stderr, "LSP: cooperative close failed\n");
            lsp_ok = 0;
        } else {
            char close_hex[close_tx.len * 2 + 1];
            hex_encode(close_tx.data, close_tx.len, close_hex);
            char close_txid[65];
            if (regtest_send_raw_tx(&rt, close_hex, close_txid)) {
                regtest_mine_blocks(&rt, 1, mine_addr);
                int conf = regtest_get_confirmations(&rt, close_txid);
                if (conf < 1) {
                    fprintf(stderr, "LSP: close tx not confirmed\n");
                    lsp_ok = 0;
                }
            } else {
                fprintf(stderr, "LSP: broadcast close tx failed\n");
                lsp_ok = 0;
            }
        }
        tx_buf_free(&close_tx);
    }

    lsp_cleanup(&lsp);

    /* Wait for children */
    int all_children_ok = 1;
    for (int c = 0; c < 4; c++) {
        int status;
        waitpid(child_pids[c], &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "Client %d failed (status %d)\n", c + 1,
                    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            all_children_ok = 0;
        }
    }

    secp256k1_context_destroy(ctx);
    return lsp_ok && all_children_ok;
}

/* ---- TCP Reconnection Integration Test ----
   Proves that a client can disconnect (process kill = real TCP close)
   and reconnect over real TCP with MSG_RECONNECT protocol.
   This is the single most important gap identified in the production roadmap. */

int test_regtest_tcp_reconnect(void) {
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: regtest not available\n");
        return 0;
    }
    if (!regtest_create_wallet(&rt, "test_tcp_reconn")) {
        char *lr = regtest_exec(&rt, "loadwallet", "\"test_tcp_reconn\"");
        if (lr) free(lr);
        strncpy(rt.wallet, "test_tcp_reconn", sizeof(rt.wallet) - 1);
    }

    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_create(ctx, &kps[i], seckeys[i])) return 0;
    }
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;
    }

    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, 5);
    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey)) return 0;
    unsigned char tweak_val[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak_val);
    musig_keyagg_t ka_copy = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &ka_copy.cache, tweak_val)) return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk)) return 0;
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tweaked_xonly);

    unsigned char tweaked_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, tweaked_ser, &tweaked_xonly)) return 0;
    char tweaked_hex[65];
    hex_encode(tweaked_ser, 32, tweaked_hex);
    char params[512];
    snprintf(params, sizeof(params), "\"rawtr(%s)\"", tweaked_hex);
    char *desc_result = regtest_exec(&rt, "getdescriptorinfo", params);
    TEST_ASSERT(desc_result != NULL, "getdescriptorinfo");
    char checksummed_desc[256];
    char *dstart = strstr(desc_result, "\"descriptor\"");
    TEST_ASSERT(dstart != NULL, "parse descriptor");
    dstart = strchr(dstart + 12, '"'); dstart++;
    char *dend = strchr(dstart, '"');
    size_t dlen = (size_t)(dend - dstart);
    memcpy(checksummed_desc, dstart, dlen);
    checksummed_desc[dlen] = '\0';
    free(desc_result);
    snprintf(params, sizeof(params), "\"%s\"", checksummed_desc);
    char *addr_result = regtest_exec(&rt, "deriveaddresses", params);
    TEST_ASSERT(addr_result != NULL, "deriveaddresses");
    char fund_addr[128] = {0};
    char *astart = strchr(addr_result, '"'); astart++;
    char *aend = strchr(astart, '"');
    size_t alen = (size_t)(aend - astart);
    memcpy(fund_addr, astart, alen);
    fund_addr[alen] = '\0';
    free(addr_result);

    char mine_addr[128];
    TEST_ASSERT(regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr)),
                "get mine address");
    if (!regtest_fund_from_faucet(&rt, 1.0))
        regtest_mine_blocks(&rt, 101, mine_addr);
    TEST_ASSERT(regtest_get_balance(&rt) >= 0.01, "balance for funding");

    char funding_txid_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, fund_addr, 0.01, funding_txid_hex),
                "fund factory");
    regtest_mine_blocks(&rt, 1, mine_addr);

    unsigned char funding_txid[32];
    hex_decode(funding_txid_hex, funding_txid, 32);
    reverse_bytes(funding_txid, 32);

    uint64_t funding_amount = 0;
    unsigned char actual_spk[256];
    size_t actual_spk_len = 0;
    uint32_t funding_vout = 0;
    for (uint32_t v = 0; v < 2; v++) {
        regtest_get_tx_output(&rt, funding_txid_hex, v,
                              &funding_amount, actual_spk, &actual_spk_len);
        if (actual_spk_len == 34 && memcmp(actual_spk, fund_spk, 34) == 0) {
            funding_vout = v;
            break;
        }
    }
    TEST_ASSERT(funding_amount > 0, "funding amount > 0");

    unsigned char preimage[32] = { [0 ... 31] = 0x77 };
    unsigned char payment_hash[32];
    sha256(preimage, 32, payment_hash);

    int port = 19600 + (getpid() % 1000);

    payment_test_data_t sender_data, payee_data, idle_data;
    memcpy(sender_data.payment_hash, payment_hash, 32);
    memset(sender_data.preimage, 0, 32);
    sender_data.is_sender = 1;
    sender_data.payment_done = 0;
    memcpy(payee_data.payment_hash, payment_hash, 32);
    memcpy(payee_data.preimage, preimage, 32);
    payee_data.is_sender = 0;
    payee_data.payment_done = 0;
    memset(&idle_data, 0, sizeof(idle_data));

    /* Fork 4 client processes */
    pid_t child_pids[4];
    for (int c = 0; c < 4; c++) {
        pid_t pid = fork();
        if (pid == 0) {
            usleep(100000 * (unsigned)(c + 1));
            secp256k1_context *child_ctx = test_ctx();
            secp256k1_keypair child_kp;
            if (!secp256k1_keypair_create(child_ctx, &child_kp, seckeys[c + 1]))
                _exit(1);
            void *cb_data;
            if (c == 0) cb_data = &sender_data;
            else if (c == 1) cb_data = &payee_data;
            else cb_data = &idle_data;
            int ok = client_run_with_channels(child_ctx, &child_kp,
                                               "127.0.0.1", port,
                                               payment_client_cb, cb_data);
            secp256k1_context_destroy(child_ctx);
            _exit(ok ? 0 : 1);
        }
        child_pids[c] = pid;
    }

    /* Parent: run LSP — factory creation + channels + one payment */
    lsp_t lsp;
    lsp_init(&lsp, ctx, &kps[0], port, 4);
    int lsp_ok = 1;

    if (!lsp_accept_clients(&lsp)) {
        fprintf(stderr, "LSP: accept clients failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok && !lsp_run_factory_creation(&lsp, funding_txid, funding_vout,
                                             funding_amount, fund_spk, 34,
                                             10, 4, 0)) {
        fprintf(stderr, "LSP: factory creation failed\n");
        lsp_ok = 0;
    }

    lsp_channel_mgr_t ch_mgr;
    memset(&ch_mgr, 0, sizeof(ch_mgr));
    if (lsp_ok && !lsp_channels_init(&ch_mgr, ctx, &lsp.factory, seckeys[0], 4)) {
        fprintf(stderr, "LSP: channel init failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok && !lsp_channels_exchange_basepoints(&ch_mgr, &lsp)) {
        fprintf(stderr, "LSP: basepoint exchange failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok && !lsp_channels_send_ready(&ch_mgr, &lsp)) {
        fprintf(stderr, "LSP: send channel_ready failed\n");
        lsp_ok = 0;
    }

    /* Process one payment: ADD_HTLC from sender + FULFILL from payee */
    if (lsp_ok && !lsp_channels_run_event_loop(&ch_mgr, &lsp, 2)) {
        fprintf(stderr, "LSP: event loop failed\n");
        lsp_ok = 0;
    }

    /* Record client B channel state before disconnect */
    uint64_t pre_local = ch_mgr.entries[1].channel.local_amount;
    uint64_t pre_remote = ch_mgr.entries[1].channel.remote_amount;
    uint64_t pre_commit = ch_mgr.entries[1].channel.commitment_number;
    printf("LSP: pre-reconnect B: local=%llu remote=%llu commit=%llu\n",
           (unsigned long long)pre_local, (unsigned long long)pre_remote,
           (unsigned long long)pre_commit);

    /* === KILL CLIENT B — real TCP close via SIGKILL === */
    if (lsp_ok) {
        printf("LSP: === KILLING CLIENT B (pid %d) ===\n", child_pids[1]);
        kill(child_pids[1], SIGKILL);
        int wst;
        waitpid(child_pids[1], &wst, 0);
        child_pids[1] = -1;

        if (lsp.client_fds[1] >= 0) {
            wire_close(lsp.client_fds[1]);
            lsp.client_fds[1] = -1;
        }
        ch_mgr.entries[1].offline_detected = 1;
        printf("LSP: client B killed, fd closed\n");
    }

    /* === Fork new client B that reconnects over real TCP === */
    pid_t reconn_pid = -1;
    if (lsp_ok) {
        reconn_pid = fork();
        if (reconn_pid == 0) {
            /* Reconnect child */
            usleep(200000);
            secp256k1_context *rc = test_ctx();
            secp256k1_keypair rk;
            if (!secp256k1_keypair_create(rc, &rk, seckeys[2])) _exit(10);
            secp256k1_pubkey rp;
            secp256k1_keypair_pub(rc, &rp, &rk);

            int rfd = wire_connect("127.0.0.1", port);
            if (rfd < 0) _exit(11);
            if (!wire_noise_handshake_initiator(rfd, rc)) { wire_close(rfd); _exit(12); }

            cJSON *rm = wire_build_reconnect(rc, &rp, pre_commit);
            if (!wire_send(rfd, MSG_RECONNECT, rm)) { cJSON_Delete(rm); wire_close(rfd); _exit(13); }
            cJSON_Delete(rm);

            /* Recv CHANNEL_NONCES */
            wire_msg_t nm;
            if (!wire_recv(rfd, &nm) || nm.msg_type != MSG_CHANNEL_NONCES) {
                if (nm.json) cJSON_Delete(nm.json);
                wire_close(rfd); _exit(14);
            }
            uint32_t nch;
            unsigned char ln[MUSIG_NONCE_POOL_MAX][66];
            size_t lnc;
            if (!wire_parse_channel_nonces(nm.json, &nch, ln, MUSIG_NONCE_POOL_MAX, &lnc)) {
                cJSON_Delete(nm.json); wire_close(rfd); _exit(15);
            }
            cJSON_Delete(nm.json);

            /* Generate + send client nonces */
            unsigned char cn[MUSIG_NONCE_POOL_MAX][66];
            for (size_t i = 0; i < lnc; i++) {
                secp256k1_musig_secnonce sn; secp256k1_musig_pubnonce pn;
                musig_keyagg_t nk; secp256k1_pubkey np[2] = {pks[0], rp};
                musig_aggregate_keys(rc, &nk, np, 2);
                musig_generate_nonce(rc, &sn, &pn, seckeys[2], &rp, &nk.cache);
                musig_pubnonce_serialize(rc, cn[i], &pn);
            }
            cJSON *nr = wire_build_channel_nonces(1, (const unsigned char (*)[66])cn, lnc);
            if (!wire_send(rfd, MSG_CHANNEL_NONCES, nr)) { cJSON_Delete(nr); wire_close(rfd); _exit(16); }
            cJSON_Delete(nr);

            /* Recv RECONNECT_ACK */
            wire_msg_t am;
            if (!wire_recv(rfd, &am) || am.msg_type != MSG_RECONNECT_ACK) {
                if (am.json) cJSON_Delete(am.json);
                wire_close(rfd); _exit(17);
            }
            uint32_t aci; uint64_t al, ar, ac;
            if (!wire_parse_reconnect_ack(am.json, &aci, &al, &ar, &ac)) {
                cJSON_Delete(am.json); wire_close(rfd); _exit(18);
            }
            cJSON_Delete(am.json);
            printf("Reconnect child: ACK ok (ch=%u commit=%llu)\n", aci, (unsigned long long)ac);
            if (aci != 1) _exit(19);

            wire_close(rfd);
            secp256k1_context_destroy(rc);
            _exit(0);
        }
    }

    /* Parent: accept and handle reconnection */
    if (lsp_ok && reconn_pid > 0) {
        int nfd = wire_accept(lsp.listen_fd);
        if (nfd < 0) { fprintf(stderr, "LSP: accept reconnect failed\n"); lsp_ok = 0; }

        if (lsp_ok && !wire_noise_handshake_responder(nfd, ctx)) {
            fprintf(stderr, "LSP: reconnect noise hs failed\n"); wire_close(nfd); lsp_ok = 0;
        }

        if (lsp_ok && !lsp_channels_handle_reconnect(&ch_mgr, &lsp, nfd)) {
            fprintf(stderr, "LSP: handle_reconnect failed\n"); lsp_ok = 0;
        }

        if (lsp_ok) {
            TEST_ASSERT(lsp.client_fds[1] >= 0, "client B fd reconnected");
            TEST_ASSERT_EQ((long)ch_mgr.entries[1].channel.local_amount,
                            (long)pre_local, "local preserved");
            TEST_ASSERT_EQ((long)ch_mgr.entries[1].channel.remote_amount,
                            (long)pre_remote, "remote preserved");
            TEST_ASSERT_EQ((long)ch_mgr.entries[1].channel.commitment_number,
                            (long)pre_commit, "commit preserved");
            TEST_ASSERT_EQ(ch_mgr.entries[1].offline_detected, 0,
                            "offline cleared");
            printf("LSP: client B reconnected over real TCP — state verified!\n");
        }
    }

    /* Wait for reconnect child */
    if (reconn_pid > 0) {
        int rs;
        waitpid(reconn_pid, &rs, 0);
        if (!WIFEXITED(rs) || WEXITSTATUS(rs) != 0) {
            fprintf(stderr, "Reconnect child failed (exit %d)\n",
                    WIFEXITED(rs) ? WEXITSTATUS(rs) : -1);
            lsp_ok = 0;
        }
    }

    lsp_cleanup(&lsp);

    /* Kill remaining children (blocked on close ceremony) */
    for (int c = 0; c < 4; c++) {
        if (child_pids[c] <= 0) continue;
        kill(child_pids[c], SIGKILL);
        int s; waitpid(child_pids[c], &s, 0);
    }

    secp256k1_context_destroy(ctx);
    TEST_ASSERT(lsp_ok, "TCP reconnect over real network");
    return 1;
}

/* --- CLI command parsing (Step 4) --- */

int test_cli_command_parsing(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.ctx = ctx;
    mgr.n_channels = 4;
    mgr.bridge_fd = -1;
    /* Set up some channel state for status command */
    mgr.entries[0].channel.local_amount = 50000;
    mgr.entries[0].channel.remote_amount = 50000;
    mgr.entries[1].channel.local_amount = 30000;
    mgr.entries[1].channel.remote_amount = 70000;

    lsp_t lsp;
    memset(&lsp, 0, sizeof(lsp));
    lsp.client_fds[0] = -1;
    lsp.client_fds[1] = -1;
    lsp.client_fds[2] = -1;
    lsp.client_fds[3] = -1;

    volatile sig_atomic_t shutdown_flag = 0;

    /* Test "help" — should be recognized */
    int ok = lsp_channels_handle_cli_line(&mgr, &lsp, "help", &shutdown_flag);
    TEST_ASSERT(ok, "help should be recognized");

    /* Test "status" — should be recognized */
    ok = lsp_channels_handle_cli_line(&mgr, &lsp, "status", &shutdown_flag);
    TEST_ASSERT(ok, "status should be recognized");

    /* Test "close" — should set shutdown flag */
    shutdown_flag = 0;
    ok = lsp_channels_handle_cli_line(&mgr, &lsp, "close", &shutdown_flag);
    TEST_ASSERT(ok, "close should be recognized");
    TEST_ASSERT(shutdown_flag == 1, "close should set shutdown flag");

    /* Test "rotate" — should be recognized (will fail but not crash) */
    ok = lsp_channels_handle_cli_line(&mgr, &lsp, "rotate", &shutdown_flag);
    TEST_ASSERT(ok, "rotate should be recognized");

    /* Test "pay" with invalid args — should be recognized */
    ok = lsp_channels_handle_cli_line(&mgr, &lsp, "pay 0 1 1000", &shutdown_flag);
    TEST_ASSERT(ok, "pay should be recognized");

    /* Test "pay" self-payment rejection */
    ok = lsp_channels_handle_cli_line(&mgr, &lsp, "pay 0 0 1000", &shutdown_flag);
    TEST_ASSERT(ok, "pay self should be recognized (prints error)");

    /* Test "pay" out-of-range index */
    ok = lsp_channels_handle_cli_line(&mgr, &lsp, "pay 99 0 1000", &shutdown_flag);
    TEST_ASSERT(ok, "pay out-of-range should be recognized");

    /* Test "pay" bad args */
    ok = lsp_channels_handle_cli_line(&mgr, &lsp, "pay badargs", &shutdown_flag);
    TEST_ASSERT(ok, "pay bad args should be recognized");

    /* Test "rebalance" — should be recognized (same as pay) */
    ok = lsp_channels_handle_cli_line(&mgr, &lsp, "rebalance 0 1 1000", &shutdown_flag);
    TEST_ASSERT(ok, "rebalance should be recognized");

    /* Test "rebalance" self-rejection */
    ok = lsp_channels_handle_cli_line(&mgr, &lsp, "rebalance 0 0 1000", &shutdown_flag);
    TEST_ASSERT(ok, "rebalance self should be recognized (prints error)");

    /* Test "rebalance" bad args */
    ok = lsp_channels_handle_cli_line(&mgr, &lsp, "rebalance badargs", &shutdown_flag);
    TEST_ASSERT(ok, "rebalance bad args should be recognized");

    /* Test unknown command — should return 0 */
    ok = lsp_channels_handle_cli_line(&mgr, &lsp, "foobar", &shutdown_flag);
    TEST_ASSERT(!ok, "unknown command should return 0");

    /* Test empty string — should return 1 (no-op) */
    ok = lsp_channels_handle_cli_line(&mgr, &lsp, "", &shutdown_flag);
    TEST_ASSERT(ok, "empty string should be recognized (no-op)");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Step 6: Verify fee accumulation + settlement end-to-end.
   Simulates the routing fee deduction logic (lsp_channels.c:644-655)
   and verifies accumulated_fees_sats feeds into settle_profits(). */
int test_fee_accumulation_and_settlement(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.economic_mode = ECON_PROFIT_SHARED;
    mgr.routing_fee_ppm = 1000; /* 0.1% = 1000 ppm */
    mgr.settlement_interval_blocks = 144;
    mgr.last_settlement_block = 100;

    /* 2 channels, each with 100k sats balance */
    mgr.n_channels = 2;
    for (size_t i = 0; i < 2; i++) {
        mgr.entries[i].channel.local_amount = 100000;
        mgr.entries[i].channel.remote_amount = 100000;
        mgr.entries[i].ready = 1;
    }

    factory_t f;
    memset(&f, 0, sizeof(f));
    f.economic_mode = ECON_PROFIT_SHARED;
    f.n_participants = 3; /* LSP + 2 clients */
    f.profiles[0].profit_share_bps = 5000; /* LSP: 50% */
    f.profiles[1].profit_share_bps = 2500; /* Client 0: 25% */
    f.profiles[2].profit_share_bps = 2500; /* Client 1: 25% */

    /* Simulate 3 routed payments using the same formula as production code */
    uint64_t payments_msat[] = { 1000000, 500000, 2000000 }; /* 1000, 500, 2000 sats */
    uint64_t total_fee_sats = 0;
    for (int i = 0; i < 3; i++) {
        uint64_t amount_msat = payments_msat[i];
        uint64_t fee_msat = (amount_msat * mgr.routing_fee_ppm + 999999) / 1000000;
        uint64_t fee_sats = (fee_msat + 999) / 1000;
        mgr.accumulated_fees_sats += fee_sats;
        total_fee_sats += fee_sats;
    }

    /* Verify fees accumulated (1000 ppm of 1000+500+2000 sats = ~3.5 sats) */
    TEST_ASSERT(mgr.accumulated_fees_sats > 0, "fees accumulated");
    TEST_ASSERT_EQ(mgr.accumulated_fees_sats, total_fee_sats,
                   "accumulated matches sum of individual fees");

    /* Verify settlement interval gate: too early (block 200, need 100+144=244) */
    uint32_t current_height = 200;
    int should_settle = (mgr.accumulated_fees_sats > 0 &&
                         mgr.settlement_interval_blocks > 0 &&
                         current_height - mgr.last_settlement_block >=
                             mgr.settlement_interval_blocks);
    TEST_ASSERT(!should_settle, "settlement not triggered before interval");

    /* At interval boundary (block 244) */
    current_height = 244;
    should_settle = (mgr.accumulated_fees_sats > 0 &&
                     mgr.settlement_interval_blocks > 0 &&
                     current_height - mgr.last_settlement_block >=
                         mgr.settlement_interval_blocks);
    TEST_ASSERT(should_settle, "settlement triggered at interval");

    /* Settle profits */
    uint64_t pre_local_0 = mgr.entries[0].channel.local_amount;
    uint64_t pre_remote_0 = mgr.entries[0].channel.remote_amount;
    int settled = lsp_channels_settle_profits(&mgr, &f);
    TEST_ASSERT(settled > 0, "settlement happened");
    TEST_ASSERT_EQ(mgr.accumulated_fees_sats, 0, "fees reset after settlement");

    /* Each client gets 2500 bps (25%) of accumulated fees */
    uint64_t expected_share = (total_fee_sats * 2500) / 10000;
    TEST_ASSERT_EQ(mgr.entries[0].channel.remote_amount,
                   pre_remote_0 + expected_share,
                   "client 0 received profit share");
    TEST_ASSERT_EQ(mgr.entries[0].channel.local_amount,
                   pre_local_0 - expected_share,
                   "LSP local decreased by share");

    return 1;
}
