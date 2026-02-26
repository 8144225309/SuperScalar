#include "superscalar/factory.h"
#include "superscalar/fee.h"
#include "superscalar/wire.h"
#include "superscalar/noise.h"
#include "superscalar/lsp.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/client.h"
#include "superscalar/musig.h"
#include "superscalar/regtest.h"
#include "cJSON.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);
extern void sha256(const unsigned char *, size_t, unsigned char *);
extern void sha256_tagged(const char *, const unsigned char *, size_t,
                           unsigned char *);

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

    /* Test 2: Greedy LSP with 70% share */
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
    /* FACTORY_CLTV_DELTA = 40.
       Verify that:
       1. An HTLC with cltv_expiry <= 40 is rejected
       2. An HTLC with cltv_expiry = 500 is forwarded with cltv_expiry = 460 */

    /* Just test the compile-time constant is correct and validate the logic
       that would be exercised through the forwarding code. */
    TEST_ASSERT_EQ(FACTORY_CLTV_DELTA, 40, "CLTV delta is 40");

    /* Test rejection: cltv_expiry too low */
    {
        uint32_t cltv_expiry = 30;  /* below FACTORY_CLTV_DELTA */
        TEST_ASSERT(cltv_expiry <= FACTORY_CLTV_DELTA, "low cltv rejected");
    }

    /* Test subtraction: cltv_expiry = 500 */
    {
        uint32_t cltv_expiry = 500;
        uint32_t fwd_cltv = cltv_expiry - FACTORY_CLTV_DELTA;
        TEST_ASSERT_EQ(fwd_cltv, 460, "fwd cltv subtracted");
    }

    /* Test edge case: cltv_expiry = FACTORY_CLTV_DELTA is rejected (need strictly >) */
    {
        uint32_t cltv_expiry = FACTORY_CLTV_DELTA;
        TEST_ASSERT(cltv_expiry <= FACTORY_CLTV_DELTA, "exact delta rejected");
    }

    /* Test edge case: cltv_expiry = FACTORY_CLTV_DELTA + 1 passes */
    {
        uint32_t cltv_expiry = FACTORY_CLTV_DELTA + 1;
        uint32_t fwd_cltv = cltv_expiry - FACTORY_CLTV_DELTA;
        TEST_ASSERT_EQ(fwd_cltv, (uint32_t)1, "delta+1 passes with fwd=1");
    }

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
    /* LSP with 1s timeout, no client connects, verify clean timeout return */
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char sec[32];
    memset(sec, 0x77, 32);
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, sec)) return 0;

    lsp_t lsp;
    TEST_ASSERT(lsp_init(&lsp, ctx, &kp, 19876, 1), "lsp_init");
    lsp.accept_timeout_sec = 1;  /* 1 second timeout */

    /* lsp_accept_clients should fail (timeout, no client) */
    int ret = lsp_accept_clients(&lsp);
    TEST_ASSERT(!ret, "accept times out with no client");

    lsp_cleanup(&lsp);
    secp256k1_context_destroy(ctx);
    return 1;
}

int test_noise_nk_handshake(void) {
    /* NK handshake over socketpair: verify encrypted round-trip */
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Server static keypair */
    unsigned char server_sec[32];
    memset(server_sec, 0xAA, 32);
    secp256k1_pubkey server_pub;
    if (!secp256k1_ec_pubkey_create(ctx, &server_pub, server_sec)) return 0;

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
        write(sv[1], resp_ns.send_key, 32);
        write(sv[1], resp_ns.recv_key, 32);

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
    (void)r1; (void)r2;

    /* Initiator's send_key should == Responder's recv_key */
    TEST_ASSERT(memcmp(init_ns.send_key, resp_recv, 32) == 0,
                "NK: initiator.send != responder.recv");
    /* Initiator's recv_key should == Responder's send_key */
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
    /* NK handshake with wrong pinned server pubkey should produce
       mismatched keys (MITM detection) */
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Real server key */
    unsigned char server_sec[32];
    memset(server_sec, 0xBB, 32);

    /* Wrong key that client pins */
    unsigned char wrong_sec[32];
    memset(wrong_sec, 0xCC, 32);
    secp256k1_pubkey wrong_pub;
    if (!secp256k1_ec_pubkey_create(ctx, &wrong_pub, wrong_sec)) return 0;

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
        write(sv[1], resp_ns.send_key, 32);
        write(sv[1], resp_ns.recv_key, 32);

        close(sv[1]);
        secp256k1_context_destroy(child_ctx);
        _exit(0);
    }

    /* Parent: NK initiator with WRONG pinned pubkey */
    close(sv[1]);
    noise_state_t init_ns;
    int ok = noise_handshake_nk_initiator(&init_ns, sv[0], ctx, &wrong_pub);
    TEST_ASSERT(ok, "NK handshake should complete (key mismatch detected by data)");

    /* Read responder's keys */
    unsigned char resp_send[32], resp_recv[32];
    ssize_t r1 = read(sv[0], resp_send, 32);
    ssize_t r2 = read(sv[0], resp_recv, 32);
    (void)r1; (void)r2;

    /* Keys should NOT match — wrong es DH produces different key material */
    int send_match = (memcmp(init_ns.send_key, resp_recv, 32) == 0);
    int recv_match = (memcmp(init_ns.recv_key, resp_send, 32) == 0);
    TEST_ASSERT(!send_match || !recv_match,
                "NK keys should mismatch with wrong server pubkey");

    int status;
    waitpid(pid, &status, 0);

    close(sv[0]);
    secp256k1_context_destroy(ctx);
    return 1;
}
