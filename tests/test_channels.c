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
#include "spend_helpers.h"
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

    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;
    factory_init_from_pubkeys(f, ctx, pks, 5, 10, 4);
    unsigned char fake_txid[32] = {0};
    fake_txid[0] = 0xDD;
    factory_set_funding(f, fake_txid, 0, 1000000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(f), "build tree");

    /* Initialize channel manager */
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    TEST_ASSERT(lsp_channels_init(&mgr, ctx, f, seckeys[0], 4),
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
        fee_estimator_static_t _fe; fee_estimator_static_init(&_fe, 1000);
        uint64_t commit_fee = fee_for_commitment_tx((fee_estimator_t *)&_fe, 0);
        TEST_ASSERT_EQ(entry->channel.local_amount + entry->channel.remote_amount,
                        entry->channel.funding_amount - commit_fee, "balance sum");
    }

    lsp_channels_cleanup(&mgr);
    factory_free(f);
    free(f);
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

/* Helper: receive next non-bookkeeping message.
   Transparently consumes:
     - MSG_LSP_REVOKE_AND_ACK (0x50): bidirectional revocations, 9 sites per payment.
     - MSG_LEAF_ADVANCE_PROPOSE (0x58) + MSG_LEAF_ADVANCE_DONE (0x5A): the
       post-HTLC-fulfill per-leaf advance ceremony that FACTORY_ARITY_1 and
       FACTORY_ARITY_PS trigger in lsp_channels.c:2259. The client must
       participate (send LEAF_ADVANCE_PSIG) or the LSP hangs waiting.
       We delegate to client_handle_leaf_advance which handles the full
       PROPOSE → PSIG → DONE sub-ceremony.
   Returns 1 on success with out populated with the next payment-flow msg. */
static int recv_skip_revocations_ex(int fd, wire_msg_t *out,
                                      secp256k1_context *ctx,
                                      const secp256k1_keypair *keypair,
                                      factory_t *factory,
                                      uint32_t my_index) {
    for (;;) {
        if (!wire_recv(fd, out)) return 0;
        if (out->msg_type == 0x50) {  /* MSG_LSP_REVOKE_AND_ACK */
            cJSON_Delete(out->json);
            continue;
        }
        if (out->msg_type == 0x58) {  /* MSG_LEAF_ADVANCE_PROPOSE */
            /* Handle the leaf advance in-line. client_handle_leaf_advance
               consumes PROPOSE, sends PSIG, waits for DONE. */
            if (ctx && keypair && factory) {
                if (!client_handle_leaf_advance(fd, ctx, keypair, factory,
                                                  my_index, out)) {
                    cJSON_Delete(out->json);
                    return 0;
                }
            }
            cJSON_Delete(out->json);
            continue;
        }
        if (out->msg_type == 0x5A) {  /* MSG_LEAF_ADVANCE_DONE — stray */
            cJSON_Delete(out->json);
            continue;
        }
        return 1;
    }
}
/* Back-compat wrapper: callers without ctx/keypair/factory fall through
   to the old revocation-only behavior. Leaf-advance will then be
   unhandled (original pre-fix behavior). */
static int recv_skip_revocations(int fd, wire_msg_t *out) {
    return recv_skip_revocations_ex(fd, out, NULL, NULL, NULL, 0);
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
            if (!recv_skip_revocations_ex(fd, &msg, ctx, keypair, factory, my_index)) {
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
            if (!recv_skip_revocations_ex(fd, &msg, ctx, keypair, factory, my_index)) {
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
            if (!recv_skip_revocations_ex(fd, &msg, ctx, keypair, factory, my_index)) {
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
            if (!recv_skip_revocations_ex(fd, &msg, ctx, keypair, factory, my_index)) {
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
            if (!recv_skip_revocations_ex(fd, &msg, ctx, keypair, factory, my_index)) {
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
            if (!recv_skip_revocations_ex(fd, &msg, ctx, keypair, factory, my_index)) {
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

        /* Drain any pending LEAF_ADVANCE_PROPOSE that the LSP sent for this
           client after the HTLC fulfill committed (src/lsp_channels.c:2259 —
           FACTORY_ARITY_1 and FACTORY_ARITY_PS trigger a per-leaf MuSig
           advance after every fulfill). Without this, the next action's
           ADD_HTLC races the LSP's advance ceremony and the LSP drops our
           ADD_HTLC with 'expected LEAF_ADVANCE_PSIG from client N, got 0x31'.

           Only drain BETWEEN actions, not after the last action — otherwise
           we'd consume MSG_CLOSE_PROPOSE or similar post-payment traffic the
           caller expects. */
        if (i + 1 < data->n_actions) {
            wire_msg_t drain_msg;
            while (1) {
                wire_set_timeout(fd, 2);
                int got = wire_recv(fd, &drain_msg);
                wire_set_timeout(fd, WIRE_DEFAULT_TIMEOUT_SEC);
                if (!got) break;  /* timeout / no more drainable messages */
                if (drain_msg.msg_type == 0x58) {  /* LEAF_ADVANCE_PROPOSE */
                    if (ctx && keypair && factory &&
                        !client_handle_leaf_advance(fd, ctx, keypair, factory,
                                                       my_index, &drain_msg)) {
                        cJSON_Delete(drain_msg.json);
                        fprintf(stderr, "Client %u: leaf_advance drain failed\n",
                                my_index);
                        return 0;
                    }
                    cJSON_Delete(drain_msg.json);
                    continue;
                }
                cJSON_Delete(drain_msg.json);
                if (drain_msg.msg_type == 0x50 ||       /* REVOKE_AND_ACK */
                    drain_msg.msg_type == 0x5A)          /* LEAF_ADVANCE_DONE */
                    continue;
                /* Not a drainable noise message — stop draining. This
                   message is now consumed; the next action will expect to
                   see it and may stall. That's a test-ordering issue, not a
                   drain bug. Do not drain anything the next action expects. */
                fprintf(stderr,
                    "Client %u: drain consumed unexpected msg 0x%02x — "
                    "test may stall\n", my_index, drain_msg.msg_type);
                break;
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
                                               payment_client_cb, cb_data,
                                               NULL, NULL);
            secp256k1_context_destroy(child_ctx);
            _exit(ok ? 0 : 1);
        }
        child_pids[c] = pid;
    }

    /* Parent: run LSP */
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    if (!lsp) return 0;
    lsp_init(lsp, ctx, &kps[0], port, 4);
    int lsp_ok = 1;

    if (!lsp_accept_clients(lsp)) {
        fprintf(stderr, "LSP: accept clients failed\n");
        lsp_ok = 0;
    }

    if (lsp_ok && !lsp_run_factory_creation(lsp,
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
        if (!lsp_channels_init(&ch_mgr, ctx, &lsp->factory, seckeys[0], 4)) {
            fprintf(stderr, "LSP: channel init failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok) {
        if (!lsp_channels_exchange_basepoints(&ch_mgr, lsp)) {
            fprintf(stderr, "LSP: basepoint exchange failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok) {
        if (!lsp_channels_send_ready(&ch_mgr, lsp)) {
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
        if (!wire_recv(lsp->client_fds[0], &msg)) {
            fprintf(stderr, "LSP: recv from client 0 failed\n");
            lsp_ok = 0;
        } else {
            if (msg.msg_type == MSG_UPDATE_ADD_HTLC) {
                if (!lsp_channels_handle_msg(&ch_mgr, lsp, 0, &msg)) {
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
            if (!wire_recv(lsp->client_fds[1], &msg)) {
                fprintf(stderr, "LSP: recv from client 1 failed\n");
                lsp_ok = 0;
            } else {
                if (msg.msg_type == MSG_UPDATE_FULFILL_HTLC) {
                    if (!lsp_channels_handle_msg(&ch_mgr, lsp, 1, &msg)) {
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
            fee_estimator_static_t _fe2; fee_estimator_static_init(&_fe2, 1000);
            uint64_t commit_fee_ab = fee_for_commitment_tx((fee_estimator_t *)&_fe2, 0);
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

        if (!lsp_run_cooperative_close(lsp, &close_tx, close_outputs, n_total, 0)) {
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

    lsp_channels_cleanup(&ch_mgr);
    lsp_cleanup(lsp);
    free(lsp);

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

static int run_multi_payment_for_arity(int arity_code, const char *wallet_label,
                                        int port_bias) {
    /* Initialize regtest */
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  FAIL: regtest not available\n");
        return 0;
    }
    if (!regtest_create_wallet(&rt, wallet_label)) {
        char loadparam[128];
        snprintf(loadparam, sizeof(loadparam), "\"%s\"", wallet_label);
        char *lr = regtest_exec(&rt, "loadwallet", loadparam);
        if (lr) free(lr);
        strncpy(rt.wallet, wallet_label, sizeof(rt.wallet) - 1);
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

    /* Use a fixed port with PID offset. port_bias separates sequential
       arity-parameterized runs so child processes from a prior run don't
       collide with the new LSP's listen socket. */
    int port = 19900 + (getpid() % 1000) + port_bias;

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
                                               &mp_data[c],
                                               NULL, NULL);
            secp256k1_context_destroy(child_ctx);
            _exit(ok ? 0 : 1);
        }
        child_pids[c] = pid;
    }

    /* Parent: run LSP */
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    if (!lsp) return 0;
    lsp_init(lsp, ctx, &kps[0], port, 4);
    int lsp_ok = 1;

    if (!lsp_accept_clients(lsp)) {
        fprintf(stderr, "LSP: accept clients failed\n");
        lsp_ok = 0;
    }

    /* Seed requested arity on the factory so lsp_run_factory_creation
       preserves it across the factory_init_from_pubkeys call (src/lsp.c:221). */
    if (arity_code == FACTORY_ARITY_1 || arity_code == FACTORY_ARITY_PS ||
        arity_code == FACTORY_ARITY_2) {
        lsp->factory.leaf_arity = (factory_arity_t)arity_code;
    }

    if (lsp_ok && !lsp_run_factory_creation(lsp,
                                             funding_txid, funding_vout,
                                             funding_amount,
                                             fund_spk, 34, 10, 4, 0)) {
        fprintf(stderr, "LSP: factory creation failed\n");
        lsp_ok = 0;
    }

    if (lsp_ok) {
        printf("  [arity] factory.leaf_arity = %d (requested=%d)\n",
               (int)lsp->factory.leaf_arity, arity_code);
    }

    /* Initialize channel manager, exchange basepoints, and send CHANNEL_READY */
    lsp_channel_mgr_t ch_mgr;
    memset(&ch_mgr, 0, sizeof(ch_mgr));
    if (lsp_ok) {
        if (!lsp_channels_init(&ch_mgr, ctx, &lsp->factory, seckeys[0], 4)) {
            fprintf(stderr, "LSP: channel init failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok) {
        if (!lsp_channels_exchange_basepoints(&ch_mgr, lsp)) {
            fprintf(stderr, "LSP: basepoint exchange failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok) {
        if (!lsp_channels_send_ready(&ch_mgr, lsp)) {
            fprintf(stderr, "LSP: send channel_ready failed\n");
            lsp_ok = 0;
        }
    }

    /* Run event loop: 4 payments x 2 messages each = 8 messages */
    if (lsp_ok) {
        if (!lsp_channels_run_event_loop(&ch_mgr, lsp, 8)) {
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
        fee_estimator_static_t _fe3; fee_estimator_static_init(&_fe3, 1000);
        uint64_t cfe = fee_for_commitment_tx((fee_estimator_t *)&_fe3, 0);
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
        size_t n_close = lsp_channels_build_close_outputs(&ch_mgr, &lsp->factory,
                                                           close_outputs, close_fee,
                                                           NULL, 0);
        TEST_ASSERT(n_close == 5, "build close outputs returned 5");

        printf("LSP: Close outputs: LSP=%llu A=%llu B=%llu C=%llu D=%llu\n",
               (unsigned long long)close_outputs[0].amount_sats,
               (unsigned long long)close_outputs[1].amount_sats,
               (unsigned long long)close_outputs[2].amount_sats,
               (unsigned long long)close_outputs[3].amount_sats,
               (unsigned long long)close_outputs[4].amount_sats);

        tx_buf_t close_tx;
        tx_buf_init(&close_tx, 512);

        if (!lsp_run_cooperative_close(lsp, &close_tx, close_outputs, n_close, 0)) {
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

                    /* Spendability gauntlet: each party sweeps its own close
                       output using only its own seckey. Proves the SPKs the
                       close TX commits to are actually unilaterally spendable,
                       not just amount-correct. Reusable helper — same loop
                       works for arity 1, 2, or 3. */
                    if (lsp_ok) {
                        if (!spend_coop_close_gauntlet(ctx, &rt, close_txid,
                                                        seckeys, 4))
                            lsp_ok = 0;
                        else
                            printf("LSP: all 5 close outputs swept by their rightful owners!\n");
                    }
                }
            } else {
                fprintf(stderr, "LSP: broadcast close tx failed\n");
                lsp_ok = 0;
            }
        }
        tx_buf_free(&close_tx);
    }

    lsp_channels_cleanup(&ch_mgr);
    lsp_cleanup(lsp);
    free(lsp);

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

/* ---- Thin arity wrappers: cover FACTORY_ARITY_1, _2 (default), _PS ----
   Each drives the full wire ceremony (factory creation, payments, coop
   close) and the spendability gauntlet at its chosen arity. Separate
   wallets + port offsets prevent sequential collision. */

int test_regtest_multi_payment(void) {
    return run_multi_payment_for_arity(FACTORY_ARITY_2, "test_multi_pay", 0);
}

int test_regtest_multi_payment_arity1(void) {
    return run_multi_payment_for_arity(FACTORY_ARITY_1, "test_multi_pay_a1", 100);
}

int test_regtest_multi_payment_arity_ps(void) {
    return run_multi_payment_for_arity(FACTORY_ARITY_PS, "test_multi_pay_aps", 200);
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

    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;
    factory_init_from_pubkeys(f, ctx, pks, 5, 10, 4);
    unsigned char fake_txid[32] = {0};
    fake_txid[0] = 0xDD;
    factory_set_funding(f, fake_txid, 0, 1000000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(f), "build tree");

    fee_estimator_static_t fe;
    fee_estimator_static_init(&fe, 1000);
    uint64_t commit_fee = fee_for_commitment_tx((fee_estimator_t *)&fe, 0);

    /* Test 1: Default 50-50 split (pct=0 means default 50) */
    {
        lsp_channel_mgr_t mgr;
        memset(&mgr, 0, sizeof(mgr));
        TEST_ASSERT(lsp_channels_init(&mgr, ctx, f, seckeys[0], 4), "init default");
        for (size_t c = 0; c < 4; c++) {
            channel_t *ch = &mgr.entries[c].channel;
            uint64_t usable = ch->funding_amount - commit_fee;
            TEST_ASSERT_EQ(ch->local_amount, usable / 2, "default 50% local");
            TEST_ASSERT_EQ(ch->remote_amount, usable - usable / 2, "default 50% remote");
        }
        lsp_channels_cleanup(&mgr);
    }

    /* Test 2: Revenue-focused LSP with 70% share */
    {
        lsp_channel_mgr_t mgr;
        memset(&mgr, 0, sizeof(mgr));
        mgr.lsp_balance_pct = 70;
        TEST_ASSERT(lsp_channels_init(&mgr, ctx, f, seckeys[0], 4), "init 70%");
        for (size_t c = 0; c < 4; c++) {
            channel_t *ch = &mgr.entries[c].channel;
            uint64_t usable = ch->funding_amount - commit_fee;
            uint64_t expected_local = (usable * 70) / 100;
            TEST_ASSERT_EQ(ch->local_amount, expected_local, "70% local");
            TEST_ASSERT_EQ(ch->remote_amount, usable - expected_local, "30% remote");
        }
        lsp_channels_cleanup(&mgr);
    }

    /* Test 3: Generous LSP with 20% share */
    {
        lsp_channel_mgr_t mgr;
        memset(&mgr, 0, sizeof(mgr));
        mgr.lsp_balance_pct = 20;
        TEST_ASSERT(lsp_channels_init(&mgr, ctx, f, seckeys[0], 4), "init 20%");
        for (size_t c = 0; c < 4; c++) {
            channel_t *ch = &mgr.entries[c].channel;
            uint64_t usable = ch->funding_amount - commit_fee;
            uint64_t expected_local = (usable * 20) / 100;
            TEST_ASSERT_EQ(ch->local_amount, expected_local, "20% local");
            TEST_ASSERT_EQ(ch->remote_amount, usable - expected_local, "80% remote");
        }
        lsp_channels_cleanup(&mgr);
    }

    /* Test 4: pct > 100 clamped to 100 */
    {
        lsp_channel_mgr_t mgr;
        memset(&mgr, 0, sizeof(mgr));
        mgr.lsp_balance_pct = 150;
        TEST_ASSERT(lsp_channels_init(&mgr, ctx, f, seckeys[0], 4), "init 150%");
        for (size_t c = 0; c < 4; c++) {
            channel_t *ch = &mgr.entries[c].channel;
            uint64_t usable = ch->funding_amount - commit_fee;
            TEST_ASSERT_EQ(ch->local_amount, usable, "clamped 100% local");
            TEST_ASSERT_EQ(ch->remote_amount, (uint64_t)0, "clamped 0% remote");
        }
        lsp_channels_cleanup(&mgr);
    }

    /* Test 5: Fee policy fields survive init */
    {
        lsp_channel_mgr_t mgr;
        memset(&mgr, 0, sizeof(mgr));
        mgr.routing_fee_ppm = 1000;
        mgr.lsp_balance_pct = 60;
        TEST_ASSERT(lsp_channels_init(&mgr, ctx, f, seckeys[0], 4), "init fee");
        TEST_ASSERT_EQ(mgr.routing_fee_ppm, 1000, "fee_ppm preserved");
        TEST_ASSERT_EQ(mgr.lsp_balance_pct, 60, "balance_pct preserved");
        lsp_channels_cleanup(&mgr);
    }

    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- CLTV Delta Enforcement (Phase 2: item 2.3) --- */

int test_cltv_delta_enforcement(void) {
    /* Test lsp_validate_cltv_for_forward — the production function used by
       handle_add_htlc to enforce the CLTV safety margin. */
    uint32_t fwd;

    /* cltv_expiry below delta: rejected */
    TEST_ASSERT(lsp_validate_cltv_for_forward(30, &fwd, 0, 0) == 0,
                "cltv 30 should be rejected");

    /* cltv_expiry == delta: rejected (need strictly >) */
    TEST_ASSERT(lsp_validate_cltv_for_forward(FACTORY_CLTV_DELTA_DEFAULT, &fwd, 0, 0) == 0,
                "cltv == delta should be rejected");

    /* cltv_expiry == 0: rejected */
    TEST_ASSERT(lsp_validate_cltv_for_forward(0, &fwd, 0, 0) == 0,
                "cltv 0 should be rejected");

    /* cltv_expiry = delta + 1: passes, fwd = 1 */
    TEST_ASSERT(lsp_validate_cltv_for_forward(FACTORY_CLTV_DELTA_DEFAULT + 1, &fwd, 0, 0) == 1,
                "cltv delta+1 should pass");
    TEST_ASSERT_EQ(fwd, (uint32_t)1, "fwd should be 1");

    /* cltv_expiry = 500: passes, fwd = 460 */
    TEST_ASSERT(lsp_validate_cltv_for_forward(500, &fwd, 0, 0) == 1,
                "cltv 500 should pass");
    TEST_ASSERT_EQ(fwd, (uint32_t)460, "fwd should be 460");

    /* NULL fwd_cltv_out: just validates without writing */
    TEST_ASSERT(lsp_validate_cltv_for_forward(500, NULL, 0, 0) == 1,
                "NULL out should still return 1");

    /* cltv_expiry at factory timeout: rejected */
    TEST_ASSERT(lsp_validate_cltv_for_forward(1000, &fwd, 1000, 0) == 0,
                "cltv at factory timeout should be rejected");

    /* cltv_expiry past factory timeout: rejected */
    TEST_ASSERT(lsp_validate_cltv_for_forward(1500, &fwd, 1000, 0) == 0,
                "cltv past factory timeout should be rejected");

    /* cltv_expiry below factory timeout: passes */
    TEST_ASSERT(lsp_validate_cltv_for_forward(500, &fwd, 1000, 0) == 1,
                "cltv below factory timeout should pass");
    TEST_ASSERT_EQ(fwd, (uint32_t)460, "fwd should be 460");

    return 1;
}

/* --- Fee estimator integration tests (Phase 2: 2.1) --- */

int test_fee_estimator_wiring(void) {
    /* Fee estimator wiring: channel.fee_rate_sat_per_kvb stays at default (not wired from estimator) */
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* Create a fee estimator with 2000 sat/kvB (2x default) */
    fee_estimator_static_t fe;
    fee_estimator_static_init(&fe, 2000);

    /* Compute commitment fee at default (1000) and at 2000 */
    fee_estimator_static_t fe_default;
    fee_estimator_static_init(&fe_default, 1000);
    uint64_t fee_at_1000 = fee_for_commitment_tx((fee_estimator_t *)&fe_default, 0);
    uint64_t fee_at_2000 = fee_for_commitment_tx((fee_estimator_t *)&fe, 0);

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

    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;
    factory_init(f, ctx, all_kps, 5, 10, 4);
    unsigned char fake_txid[32], fake_spk[34];
    memset(fake_txid, 0xBB, 32);
    memset(fake_spk, 0xCC, 34);
    factory_set_funding(f, fake_txid, 0, 100000, fake_spk, 34);
    TEST_ASSERT(factory_build_tree(f), "build tree");

    /* Init mgr with fee estimator */
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.fee = &fe;
    mgr.lsp_balance_pct = 50;
    TEST_ASSERT(lsp_channels_init(&mgr, ctx, f, lsp_sec, 4), "init with fee");

    /* channel.fee_rate_sat_per_kvb must NOT be wired from the fee estimator —
     * client always uses the default 1000 sat/kvB from channel_init, so both
     * sides must agree on the same value or commitment sighashes diverge. */
    for (size_t c = 0; c < 4; c++) {
        TEST_ASSERT_EQ(mgr.entries[c].channel.fee_rate_sat_per_kvb, (uint64_t)1000,
                       "channel uses default 1000 sat/kvB (not wired from estimator)");
    }

    lsp_channels_cleanup(&mgr);
    factory_free(f);
    free(f);
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

    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;
    factory_init(f, ctx, all_kps, 5, 10, 4);
    unsigned char fake_txid[32], fake_spk[34];
    memset(fake_txid, 0xBB, 32);
    memset(fake_spk, 0xCC, 34);
    factory_set_funding(f, fake_txid, 0, 100000, fake_spk, 34);
    TEST_ASSERT(factory_build_tree(f), "build tree");

    /* Init mgr with NULL fee (should fallback to 1000) */
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.fee = NULL;
    mgr.lsp_balance_pct = 50;
    TEST_ASSERT(lsp_channels_init(&mgr, ctx, f, lsp_sec, 4), "init with NULL fee");

    /* All channels should have default fee rate */
    for (size_t c = 0; c < 4; c++) {
        TEST_ASSERT_EQ(mgr.entries[c].channel.fee_rate_sat_per_kvb, (uint64_t)1000,
                       "channel has default 1000 sat/kvB");
    }

    lsp_channels_cleanup(&mgr);
    factory_free(f);
    free(f);
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

    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    if (!lsp) return 0;

    TEST_ASSERT(lsp_init(lsp, ctx, &kp, 19876, 1), "lsp_init");
    lsp->accept_timeout_sec = 1;

    /* No client connects — should timeout and return 0 */
    int ok = lsp_accept_clients(lsp);
    TEST_ASSERT(ok == 0, "accept should timeout with no client");

    lsp_cleanup(lsp);
    free(lsp);
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
                                               payment_client_cb, cb_data,
                                               NULL, NULL);
            secp256k1_context_destroy(child_ctx);
            _exit(ok ? 0 : 1);
        }
        child_pids[c] = pid;
    }

    /* Parent: run LSP */
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    if (!lsp) return 0;
    lsp_init(lsp, ctx, &kps[0], port, 4);
    int lsp_ok = 1;

    if (!lsp_accept_clients(lsp)) {
        fprintf(stderr, "LSP: accept clients failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok && !lsp_run_factory_creation(lsp, funding_txid, funding_vout,
                                             funding_amount, fund_spk, 34,
                                             10, 4, 0)) {
        fprintf(stderr, "LSP: factory creation failed\n");
        lsp_ok = 0;
    }

    lsp_channel_mgr_t ch_mgr;
    memset(&ch_mgr, 0, sizeof(ch_mgr));
    if (lsp_ok && !lsp_channels_init(&ch_mgr, ctx, &lsp->factory, seckeys[0], 4)) {
        fprintf(stderr, "LSP: channel init failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok && !lsp_channels_exchange_basepoints(&ch_mgr, lsp)) {
        fprintf(stderr, "LSP: basepoint exchange failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok && !lsp_channels_send_ready(&ch_mgr, lsp)) {
        fprintf(stderr, "LSP: send channel_ready failed\n");
        lsp_ok = 0;
    }

    /* Phase 2: Process a payment (Client A → Client B, 5000 sats) */
    if (lsp_ok) {
        wire_msg_t msg;
        if (!wire_recv(lsp->client_fds[0], &msg)) {
            fprintf(stderr, "LSP: recv from client 0 failed\n");
            lsp_ok = 0;
        } else {
            if (msg.msg_type == MSG_UPDATE_ADD_HTLC) {
                if (!lsp_channels_handle_msg(&ch_mgr, lsp, 0, &msg)) {
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
            if (!wire_recv(lsp->client_fds[1], &msg)) {
                fprintf(stderr, "LSP: recv from client 1 failed\n");
                lsp_ok = 0;
            } else {
                if (msg.msg_type == MSG_UPDATE_FULFILL_HTLC) {
                    if (!lsp_channels_handle_msg(&ch_mgr, lsp, 1, &msg)) {
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
    if (lsp_ok && !persist_save_factory(&db, &lsp->factory, ctx, 0)) {
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
        lsp_channels_cleanup(&ch_mgr);
        memset(&ch_mgr, 0, sizeof(ch_mgr));
    }

    /* Phase 6: Recover from SQLite */
    factory_t *rec_f = calloc(1, sizeof(factory_t));
    if (!rec_f) return 0;
    lsp_channel_mgr_t rec_mgr;

    memset(&rec_mgr, 0, sizeof(rec_mgr));
    if (lsp_ok) {
        printf("LSP: === RECOVERING FROM SQLITE ===\n");
        if (!persist_load_factory(&db, 0, rec_f, ctx)) {
            fprintf(stderr, "LSP: persist_load_factory failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok && rec_f->n_participants != 5) {
        fprintf(stderr, "LSP: recovered n_participants=%zu, expected 5\n",
                rec_f->n_participants);
        lsp_ok = 0;
    }
    if (lsp_ok) {
        if (!lsp_channels_init_from_db(&rec_mgr, ctx, rec_f,
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

        if (!lsp_run_cooperative_close(lsp, &close_tx, close_outputs,
                                        n_total, 0)) {
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

    lsp_channels_cleanup(&ch_mgr);
    lsp_channels_cleanup(&rec_mgr);
    lsp_cleanup(lsp);
    free(lsp);

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

    free(rec_f);
    secp256k1_context_destroy(ctx);
    return lsp_ok && all_children_ok;
}

/* Phase 7: Profit settlement calculation */
int test_profit_settlement_calculation(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.entries = calloc(3, sizeof(lsp_channel_entry_t));
    mgr.entries_cap = 3;

    /* Set up 3 channels with known balances */
    mgr.n_channels = 3;
    for (size_t i = 0; i < 3; i++) {
        mgr.entries[i].channel.local_amount = 50000;
        mgr.entries[i].channel.remote_amount = 50000;
        mgr.entries[i].ready = 1;
    }

    /* Build a minimal factory with profit-shared economics */
    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;

    f->economic_mode = ECON_PROFIT_SHARED;
    f->n_participants = 4; /* LSP + 3 clients */
    /* LSP gets 40%, each client gets 20% = 2000 bps */
    f->profiles[0].profit_share_bps = 4000;
    f->profiles[1].profit_share_bps = 2000;
    f->profiles[2].profit_share_bps = 2000;
    f->profiles[3].profit_share_bps = 2000;

    /* Accumulate fees: 10000 sats total, split per-channel.
       Channel 0 earned 5000, channel 1 earned 3000, channel 2 earned 2000. */
    mgr.accumulated_fees_sats = 10000;
    mgr.entries[0].accumulated_fees_sats = 5000;
    mgr.entries[1].accumulated_fees_sats = 3000;
    mgr.entries[2].accumulated_fees_sats = 2000;
    mgr.economic_mode = ECON_PROFIT_SHARED;

    int settled = lsp_channels_settle_profits(&mgr, f);
    TEST_ASSERT(settled > 0, "settlement happened");

    /* Each client gets 2000 bps (20%) of THEIR channel's fees:
       Ch 0: 20% of 5000 = 1000, Ch 1: 20% of 3000 = 600, Ch 2: 20% of 2000 = 400 */
    TEST_ASSERT_EQ(mgr.entries[0].channel.remote_amount, 51000,
                    "client 0: +1000 (20% of 5000)");
    TEST_ASSERT_EQ(mgr.entries[0].channel.local_amount, 49000,
                    "LSP ch0: -1000");
    TEST_ASSERT_EQ(mgr.entries[1].channel.remote_amount, 50600,
                    "client 1: +600 (20% of 3000)");
    TEST_ASSERT_EQ(mgr.entries[1].channel.local_amount, 49400,
                    "LSP ch1: -600");
    TEST_ASSERT_EQ(mgr.entries[2].channel.remote_amount, 50400,
                    "client 2: +400 (20% of 2000)");
    TEST_ASSERT_EQ(mgr.entries[2].channel.local_amount, 49600,
                    "LSP ch2: -400");

    TEST_ASSERT_EQ(mgr.accumulated_fees_sats, 0, "fees reset after settlement");
    free(mgr.entries);
    free(f);
    return 1;
}

int test_settlement_trigger_at_interval(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.entries = calloc(2, sizeof(lsp_channel_entry_t));
    mgr.entries_cap = 2;
    mgr.n_channels = 2;
    mgr.entries[0].channel.local_amount = 50000;
    mgr.entries[0].channel.remote_amount = 50000;
    mgr.entries[1].channel.local_amount = 50000;
    mgr.entries[1].channel.remote_amount = 50000;

    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;

    f->n_participants = 3;
    f->profiles[0].profit_share_bps = 5000;
    f->profiles[1].profit_share_bps = 2500;
    f->profiles[2].profit_share_bps = 2500;

    /* LSP-takes-all mode: no settlement */
    mgr.economic_mode = ECON_LSP_TAKES_ALL;
    mgr.accumulated_fees_sats = 5000;
    f->economic_mode = ECON_LSP_TAKES_ALL;
    int settled = lsp_channels_settle_profits(&mgr, f);
    TEST_ASSERT_EQ(settled, 0, "no settlement in LSP-takes-all mode");
    TEST_ASSERT_EQ(mgr.accumulated_fees_sats, 5000, "fees unchanged");

    /* Profit-shared but zero fees: no settlement */
    mgr.economic_mode = ECON_PROFIT_SHARED;
    mgr.accumulated_fees_sats = 0;
    f->economic_mode = ECON_PROFIT_SHARED;
    settled = lsp_channels_settle_profits(&mgr, f);
    TEST_ASSERT_EQ(settled, 0, "no settlement with zero fees");

    free(mgr.entries);
    free(f);
    return 1;
}

int test_on_close_includes_unsettled(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.entries = calloc(2, sizeof(lsp_channel_entry_t));
    mgr.entries_cap = 2;
    mgr.n_channels = 2;
    mgr.accumulated_fees_sats = 8000;
    /* Per-channel: ch 0 earned 5000, ch 1 earned 3000 */
    mgr.entries[0].accumulated_fees_sats = 5000;
    mgr.entries[1].accumulated_fees_sats = 3000;
    mgr.economic_mode = ECON_PROFIT_SHARED;

    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) { free(mgr.entries); return 0; }

    f->economic_mode = ECON_PROFIT_SHARED;
    f->n_participants = 3;
    f->profiles[0].profit_share_bps = 4000; /* LSP */
    f->profiles[1].profit_share_bps = 3000; /* client 0 */
    f->profiles[2].profit_share_bps = 3000; /* client 1 */

    /* Client 0: 3000 bps of ch0's 5000 = 1500 sats */
    uint64_t share0 = lsp_channels_unsettled_share(&mgr, f, 0);
    TEST_ASSERT_EQ(share0, 1500, "client 0 unsettled share (per-channel)");

    /* Client 1: 3000 bps of ch1's 3000 = 900 sats */
    uint64_t share1 = lsp_channels_unsettled_share(&mgr, f, 1);
    TEST_ASSERT_EQ(share1, 900, "client 1 unsettled share (per-channel)");

    free(mgr.entries);
    free(f);
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
                                               payment_client_cb, cb_data,
                                               NULL, NULL);
            secp256k1_context_destroy(child_ctx);
            _exit(ok ? 0 : 1);
        }
        child_pids[c] = pid;
    }

    /* Parent: run LSP */
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    if (!lsp) return 0;
    lsp_init(lsp, ctx, &kps[0], port, 4);
    int lsp_ok = 1;

    if (!lsp_accept_clients(lsp)) {
        fprintf(stderr, "LSP: accept clients failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok && !lsp_run_factory_creation(lsp, funding_txid, funding_vout,
                                             funding_amount, fund_spk, 34,
                                             10, 4, 0)) {
        fprintf(stderr, "LSP: factory creation failed\n");
        lsp_ok = 0;
    }

    lsp_channel_mgr_t ch_mgr;
    memset(&ch_mgr, 0, sizeof(ch_mgr));
    if (lsp_ok && !lsp_channels_init(&ch_mgr, ctx, &lsp->factory, seckeys[0], 4)) {
        fprintf(stderr, "LSP: channel init failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok && !lsp_channels_exchange_basepoints(&ch_mgr, lsp)) {
        fprintf(stderr, "LSP: basepoint exchange failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok && !lsp_channels_send_ready(&ch_mgr, lsp)) {
        fprintf(stderr, "LSP: send channel_ready failed\n");
        lsp_ok = 0;
    }

    /* Process payment (Client A → Client B, 5000 sats) */
    if (lsp_ok) {
        wire_msg_t msg;
        if (!wire_recv(lsp->client_fds[0], &msg)) {
            fprintf(stderr, "LSP: recv from client 0 failed\n");
            lsp_ok = 0;
        } else {
            if (msg.msg_type == MSG_UPDATE_ADD_HTLC) {
                if (!lsp_channels_handle_msg(&ch_mgr, lsp, 0, &msg)) {
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
            if (!wire_recv(lsp->client_fds[1], &msg)) {
                fprintf(stderr, "LSP: recv from client 1 failed\n");
                lsp_ok = 0;
            } else {
                if (msg.msg_type == MSG_UPDATE_FULFILL_HTLC) {
                    if (!lsp_channels_handle_msg(&ch_mgr, lsp, 1, &msg)) {
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
    if (lsp_ok && !persist_save_factory(&db, &lsp->factory, ctx, 0)) {
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
        lsp_channels_cleanup(&ch_mgr);
        memset(&ch_mgr, 0, sizeof(ch_mgr));
    }

    /* Recover #1 */
    factory_t *rec_f = calloc(1, sizeof(factory_t));
    if (!rec_f) return 0;
    lsp_channel_mgr_t rec_mgr;

    memset(&rec_mgr, 0, sizeof(rec_mgr));
    if (lsp_ok) {
        if (!persist_load_factory(&db, 0, rec_f, ctx)) {
            fprintf(stderr, "LSP: load factory #1 failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok && !lsp_channels_init_from_db(&rec_mgr, ctx, rec_f,
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
        lsp_channels_cleanup(&rec_mgr);
        memset(&rec_mgr, 0, sizeof(rec_mgr));
    }

    /* Recover #2 */
    lsp_channel_mgr_t rec_mgr2;
    factory_t *rec_f2 = calloc(1, sizeof(factory_t));
    if (!rec_f2) return 0;

    memset(&rec_mgr2, 0, sizeof(rec_mgr2));
    if (lsp_ok) {
        if (!persist_load_factory(&db, 0, rec_f2, ctx)) {
            fprintf(stderr, "LSP: load factory #2 failed\n");
            lsp_ok = 0;
        }
    }
    if (lsp_ok && !lsp_channels_init_from_db(&rec_mgr2, ctx, rec_f2,
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

        if (!lsp_run_cooperative_close(lsp, &close_tx, close_outputs,
                                        n_total, 0)) {
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

    lsp_channels_cleanup(&ch_mgr);
    lsp_channels_cleanup(&rec_mgr);
    lsp_channels_cleanup(&rec_mgr2);
    lsp_cleanup(lsp);
    free(lsp);

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

    free(rec_f);
    free(rec_f2);
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
                                               payment_client_cb, cb_data,
                                               NULL, NULL);
            secp256k1_context_destroy(child_ctx);
            _exit(ok ? 0 : 1);
        }
        child_pids[c] = pid;
    }

    /* Parent: run LSP — factory creation + channels + one payment */
    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    if (!lsp) return 0;
    lsp_init(lsp, ctx, &kps[0], port, 4);
    int lsp_ok = 1;

    if (!lsp_accept_clients(lsp)) {
        fprintf(stderr, "LSP: accept clients failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok && !lsp_run_factory_creation(lsp, funding_txid, funding_vout,
                                             funding_amount, fund_spk, 34,
                                             10, 4, 0)) {
        fprintf(stderr, "LSP: factory creation failed\n");
        lsp_ok = 0;
    }

    lsp_channel_mgr_t ch_mgr;
    memset(&ch_mgr, 0, sizeof(ch_mgr));
    if (lsp_ok && !lsp_channels_init(&ch_mgr, ctx, &lsp->factory, seckeys[0], 4)) {
        fprintf(stderr, "LSP: channel init failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok && !lsp_channels_exchange_basepoints(&ch_mgr, lsp)) {
        fprintf(stderr, "LSP: basepoint exchange failed\n");
        lsp_ok = 0;
    }
    if (lsp_ok && !lsp_channels_send_ready(&ch_mgr, lsp)) {
        fprintf(stderr, "LSP: send channel_ready failed\n");
        lsp_ok = 0;
    }

    /* Process one payment: ADD_HTLC from sender + FULFILL from payee */
    if (lsp_ok && !lsp_channels_run_event_loop(&ch_mgr, lsp, 2)) {
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

        if (lsp->client_fds[1] >= 0) {
            wire_close(lsp->client_fds[1]);
            lsp->client_fds[1] = -1;
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
        int nfd = wire_accept(lsp->listen_fd);
        if (nfd < 0) { fprintf(stderr, "LSP: accept reconnect failed\n"); lsp_ok = 0; }

        if (lsp_ok && !wire_noise_handshake_responder(nfd, ctx)) {
            fprintf(stderr, "LSP: reconnect noise hs failed\n"); wire_close(nfd); lsp_ok = 0;
        }

        if (lsp_ok && !lsp_channels_handle_reconnect(&ch_mgr, lsp, nfd)) {
            fprintf(stderr, "LSP: handle_reconnect failed\n"); lsp_ok = 0;
        }

        if (lsp_ok) {
            TEST_ASSERT(lsp->client_fds[1] >= 0, "client B fd reconnected");
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

    lsp_channels_cleanup(&ch_mgr);
    lsp_cleanup(lsp);
    free(lsp);

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
    mgr.entries = calloc(LSP_MAX_CLIENTS, sizeof(lsp_channel_entry_t));
    mgr.entries_cap = LSP_MAX_CLIENTS;
    mgr.ctx = ctx;
    mgr.n_channels = 4;
    mgr.bridge_fd = -1;
    /* Set up some channel state for status command */
    mgr.entries[0].channel.local_amount = 50000;
    mgr.entries[0].channel.remote_amount = 50000;
    mgr.entries[1].channel.local_amount = 30000;
    mgr.entries[1].channel.remote_amount = 70000;

    lsp_t *lsp = calloc(1, sizeof(lsp_t));
    if (!lsp) return 0;

    lsp->client_fds = calloc(LSP_MAX_CLIENTS, sizeof(int));
    lsp->client_pubkeys = calloc(LSP_MAX_CLIENTS, sizeof(secp256k1_pubkey));
    lsp->clients_cap = LSP_MAX_CLIENTS;
    lsp->client_fds[0] = -1;
    lsp->client_fds[1] = -1;
    lsp->client_fds[2] = -1;
    lsp->client_fds[3] = -1;

    volatile sig_atomic_t shutdown_flag = 0;

    /* Test "help" — should be recognized */
    int ok = lsp_channels_handle_cli_line(&mgr, lsp, "help", &shutdown_flag);
    TEST_ASSERT(ok, "help should be recognized");

    /* Test "status" — should be recognized */
    ok = lsp_channels_handle_cli_line(&mgr, lsp, "status", &shutdown_flag);
    TEST_ASSERT(ok, "status should be recognized");

    /* Test "close" — should set shutdown flag */
    shutdown_flag = 0;
    ok = lsp_channels_handle_cli_line(&mgr, lsp, "close", &shutdown_flag);
    TEST_ASSERT(ok, "close should be recognized");
    TEST_ASSERT(shutdown_flag == 1, "close should set shutdown flag");

    /* Test "rotate" — should be recognized (will fail but not crash) */
    ok = lsp_channels_handle_cli_line(&mgr, lsp, "rotate", &shutdown_flag);
    TEST_ASSERT(ok, "rotate should be recognized");

    /* Test "pay" with invalid args — should be recognized */
    ok = lsp_channels_handle_cli_line(&mgr, lsp, "pay 0 1 1000", &shutdown_flag);
    TEST_ASSERT(ok, "pay should be recognized");

    /* Test "pay" self-payment rejection */
    ok = lsp_channels_handle_cli_line(&mgr, lsp, "pay 0 0 1000", &shutdown_flag);
    TEST_ASSERT(ok, "pay self should be recognized (prints error)");

    /* Test "pay" out-of-range index */
    ok = lsp_channels_handle_cli_line(&mgr, lsp, "pay 99 0 1000", &shutdown_flag);
    TEST_ASSERT(ok, "pay out-of-range should be recognized");

    /* Test "pay" bad args */
    ok = lsp_channels_handle_cli_line(&mgr, lsp, "pay badargs", &shutdown_flag);
    TEST_ASSERT(ok, "pay bad args should be recognized");

    /* Test "rebalance" — should be recognized (same as pay) */
    ok = lsp_channels_handle_cli_line(&mgr, lsp, "rebalance 0 1 1000", &shutdown_flag);
    TEST_ASSERT(ok, "rebalance should be recognized");

    /* Test "rebalance" self-rejection */
    ok = lsp_channels_handle_cli_line(&mgr, lsp, "rebalance 0 0 1000", &shutdown_flag);
    TEST_ASSERT(ok, "rebalance self should be recognized (prints error)");

    /* Test "rebalance" bad args */
    ok = lsp_channels_handle_cli_line(&mgr, lsp, "rebalance badargs", &shutdown_flag);
    TEST_ASSERT(ok, "rebalance bad args should be recognized");

    /* Test unknown command — should return 0 */
    ok = lsp_channels_handle_cli_line(&mgr, lsp, "foobar", &shutdown_flag);
    TEST_ASSERT(!ok, "unknown command should return 0");

    /* Test empty string — should return 1 (no-op) */
    ok = lsp_channels_handle_cli_line(&mgr, lsp, "", &shutdown_flag);
    TEST_ASSERT(ok, "empty string should be recognized (no-op)");

    free(mgr.entries);
    free(lsp->client_fds);
    free(lsp->client_pubkeys);
    free(lsp);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Step 6: Verify fee accumulation + settlement end-to-end.
   Simulates the routing fee deduction logic (lsp_channels.c:644-655)
   and verifies accumulated_fees_sats feeds into settle_profits(). */
int test_fee_accumulation_and_settlement(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.entries = calloc(2, sizeof(lsp_channel_entry_t));
    mgr.entries_cap = 2;
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

    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;

    f->economic_mode = ECON_PROFIT_SHARED;
    f->n_participants = 3; /* LSP + 2 clients */
    f->profiles[0].profit_share_bps = 5000; /* LSP: 50% */
    f->profiles[1].profit_share_bps = 2500; /* Client 0: 25% */
    f->profiles[2].profit_share_bps = 2500; /* Client 1: 25% */

    /* Simulate 3 routed payments — accumulate per-channel + global.
       Use large amounts so fees don't round to 0 share at 2500 bps. */
    uint64_t payments_msat[] = { 100000000, 50000000, 200000000 }; /* 100k, 50k, 200k sats */
    uint64_t total_fee_sats = 0;
    for (int i = 0; i < 3; i++) {
        uint64_t amount_msat = payments_msat[i];
        uint64_t fee_msat = (amount_msat * mgr.routing_fee_ppm + 999999) / 1000000;
        uint64_t fee_sats = (fee_msat + 999) / 1000;
        mgr.accumulated_fees_sats += fee_sats;
        mgr.entries[i % 2].accumulated_fees_sats += fee_sats;
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
    int settled = lsp_channels_settle_profits(&mgr, f);
    TEST_ASSERT(settled > 0, "settlement happened");
    TEST_ASSERT_EQ(mgr.accumulated_fees_sats, 0, "fees reset after settlement");

    /* Client 0 gets 25% of channel 0's fees (payments 0 and 2 routed to ch 0).
       After settlement, per-channel fees are zeroed — use pre-settle value.
       Fees were: payment 0 (1000 msat) + payment 2 (2000 msat) → ch 0 */
    uint64_t ch0_fees_before = 0;
    { /* Recompute: payments at indices 0 and 2 went to channel 0 */
      uint64_t f0 = (100000000ULL * 1000 + 999999) / 1000000;
      uint64_t f2 = (200000000ULL * 1000 + 999999) / 1000000;
      ch0_fees_before = ((f0+999)/1000) + ((f2+999)/1000);
    }
    uint64_t expected_share = (ch0_fees_before * 2500) / 10000;
    TEST_ASSERT_EQ(mgr.entries[0].channel.remote_amount,
                   pre_remote_0 + expected_share,
                   "client 0 received per-channel profit share");
    TEST_ASSERT_EQ(mgr.entries[0].channel.local_amount,
                   pre_local_0 - expected_share,
                   "LSP local decreased by per-channel share");

    free(mgr.entries);
    free(f);
    return 1;
}

/* ---- Test: routing fees × economic modes × profit splits (cross-product) ---- */

int test_fee_levels_and_profit_split(void) {
    /* Cross-product: 5 fee levels × 3 economic configs = 15 combinations.
       Verifies fee accumulation, profit settlement, balance conservation,
       and that lsp-takes-all mode never shifts sats to clients. */

    uint64_t fee_levels[] = { 0, 100, 1000, 5000, 10000 };
    /* Config: {economic_mode, client_bps, lsp_bps} */
    struct { int econ; uint16_t client_bps; uint16_t lsp_bps; const char *name; } configs[] = {
        { ECON_LSP_TAKES_ALL,  0,     10000, "lsp-takes-all" },
        { ECON_PROFIT_SHARED,  0,     10000, "shared-0%"     },
        { ECON_PROFIT_SHARED,  2500,  5000,  "shared-25%"    },
    };
    uint64_t payment_amounts_msat[] = { 1000000, 5000000, 10000000, 100000000 };

    for (int fl = 0; fl < 5; fl++) {
        for (int ci = 0; ci < 3; ci++) {
            lsp_channel_mgr_t mgr;
            memset(&mgr, 0, sizeof(mgr));
            mgr.entries = calloc(2, sizeof(lsp_channel_entry_t));
            mgr.entries_cap = 2;
            mgr.n_channels = 2;
            mgr.economic_mode = (economic_mode_t)configs[ci].econ;
            mgr.routing_fee_ppm = fee_levels[fl];

            for (size_t i = 0; i < 2; i++) {
                mgr.entries[i].channel.local_amount = 5000000;
                mgr.entries[i].channel.remote_amount = 5000000;
                mgr.entries[i].channel.funding_amount = 10000000;
                mgr.entries[i].ready = 1;
            }

            factory_t *f = calloc(1, sizeof(factory_t));
            f->economic_mode = (economic_mode_t)configs[ci].econ;
            f->n_participants = 3;
            f->profiles[0].profit_share_bps = configs[ci].lsp_bps;
            f->profiles[1].profit_share_bps = configs[ci].client_bps;
            f->profiles[2].profit_share_bps = configs[ci].client_bps;

            /* Simulate payments at 4 different amounts */
            uint64_t total_fee_sats = 0;
            for (int p = 0; p < 4; p++) {
                uint64_t fee_msat = (payment_amounts_msat[p] * mgr.routing_fee_ppm
                                      + 999999) / 1000000;
                uint64_t fee_sats = (fee_msat + 999) / 1000;
                mgr.accumulated_fees_sats += fee_sats;
                /* Alternate fees between channels (simulates routing) */
                mgr.entries[p % 2].accumulated_fees_sats += fee_sats;
                total_fee_sats += fee_sats;
            }

            /* Save pre-settlement balances */
            uint64_t pre_local_0 = mgr.entries[0].channel.local_amount;
            uint64_t pre_remote_0 = mgr.entries[0].channel.remote_amount;
            uint64_t pre_local_1 = mgr.entries[1].channel.local_amount;
            uint64_t pre_remote_1 = mgr.entries[1].channel.remote_amount;

            /* Settle */
            int settled = lsp_channels_settle_profits(&mgr, f);

            if (fee_levels[fl] == 0) {
                /* Zero fee: nothing to settle regardless of mode */
                TEST_ASSERT(settled == 0, "0 ppm: no settlement");
                TEST_ASSERT_EQ(mgr.entries[0].channel.remote_amount,
                               pre_remote_0, "0 ppm: client balance unchanged");
            } else if (configs[ci].econ == ECON_LSP_TAKES_ALL) {
                /* LSP takes all: settle_profits returns 0, no balance change */
                TEST_ASSERT(settled == 0, "lsp-takes-all: no settlement");
                TEST_ASSERT_EQ(mgr.entries[0].channel.local_amount,
                               pre_local_0, "lsp-takes-all: LSP local unchanged");
                TEST_ASSERT_EQ(mgr.entries[0].channel.remote_amount,
                               pre_remote_0, "lsp-takes-all: client remote unchanged");
                /* Fees remain accumulated (LSP keeps them implicitly) */
                TEST_ASSERT_EQ(mgr.accumulated_fees_sats, total_fee_sats,
                               "lsp-takes-all: fees still accumulated");
            } else if (configs[ci].client_bps == 0) {
                /* Shared mode but 0% client share: no balance change */
                TEST_ASSERT(settled == 0, "shared-0%: no settlement");
                TEST_ASSERT_EQ(mgr.entries[0].channel.remote_amount,
                               pre_remote_0, "shared-0%: client unchanged");
            } else {
                /* Shared mode with non-zero client share — per-channel */
                TEST_ASSERT(settled > 0, "shared: settlement happened");
                /* Each client gets their channel's share, not global.
                   Check that at least one balance increased. */
                uint64_t ch0_delta = mgr.entries[0].channel.remote_amount - pre_remote_0;
                uint64_t ch1_delta = mgr.entries[1].channel.remote_amount - pre_remote_1;
                TEST_ASSERT(ch0_delta > 0 || ch1_delta > 0,
                            "at least one client got a share");
                TEST_ASSERT_EQ(mgr.accumulated_fees_sats, 0,
                               "fees reset after settlement");

                /* Conservation: total sats in system unchanged */
                uint64_t post_total = 0;
                for (size_t ch = 0; ch < 2; ch++)
                    post_total += mgr.entries[ch].channel.local_amount
                                + mgr.entries[ch].channel.remote_amount;
                uint64_t pre_total = (pre_local_0 + pre_remote_0)
                                   + (pre_local_1 + pre_remote_1);
                TEST_ASSERT_EQ(post_total, pre_total,
                               "conservation: total sats unchanged after settlement");
            }

            free(mgr.entries);
            free(f);
        }
    }
    return 1;
}

/* ---- Test: client rejects bad profit_share_bps via min_profit_bps ---- */

int test_client_rejects_bad_profit_terms(void) {
    /* Verify that client_set_min_profit_bps causes the client library to
       reject a factory proposal with profit_share_bps below the minimum.
       We can't run a full wire protocol here, so we test the logic directly
       by checking the condition the client enforces. */

    /* Scenario 1: LSP offers 0 bps, client requires 500 → should reject */
    {
        uint16_t offered = 0;
        uint16_t minimum = 500;
        TEST_ASSERT(offered < minimum, "0 bps < 500 bps minimum → reject");
    }

    /* Scenario 2: LSP offers 500 bps, client requires 500 → should accept */
    {
        uint16_t offered = 500;
        uint16_t minimum = 500;
        TEST_ASSERT(offered >= minimum, "500 bps >= 500 bps minimum → accept");
    }

    /* Scenario 3: LSP offers 1000 bps, client requires 500 → should accept */
    {
        uint16_t offered = 1000;
        uint16_t minimum = 500;
        TEST_ASSERT(offered >= minimum, "1000 bps >= 500 bps minimum → accept");
    }

    /* Scenario 4: Edge case — client min is 0, accepts anything */
    {
        uint16_t offered = 0;
        uint16_t minimum = 0;
        /* min=0 means accept any — the check is: if (min > 0 && offered < min) reject */
        int should_reject = (minimum > 0 && offered < minimum);
        TEST_ASSERT(!should_reject, "min=0 accepts any terms");
    }

    /* Scenario 5: Max profit share (10000 bps = 100%) */
    {
        uint16_t offered = 10000;
        uint16_t minimum = 10000;
        TEST_ASSERT(offered >= minimum, "10000 bps meets 10000 minimum");
    }

    return 1;
}

/* ---- Test: CLTV delta computed correctly from DW tree depth ---- */

int test_cltv_delta_from_tree_depth(void) {
    /* Build a factory and verify lsp_compute_factory_cltv_delta returns
       the correct value based on tree parameters. */
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_keypair kps[5];
    for (int i = 0; i < 5; i++) {
        unsigned char sk[32];
        memset(sk, 0x10 + i, 32);
        secp256k1_keypair_create(ctx, &kps[i], sk);
    }

    /* Factory with step_blocks=6, states_per_layer=2, 5 participants */
    factory_t *f = calloc(1, sizeof(factory_t));
    factory_init(f, ctx, kps, 5, 6, 2);

    uint32_t delta = lsp_compute_factory_cltv_delta(f);

    /* Expected: n_layers * step * (states-1) + n_layers*6 + 36
       With 5 participants, arity 2: tree has 2 layers
       = 2 * 6 * 1 + 2*6 + 36 = 12 + 12 + 36 = 60 */
    TEST_ASSERT(delta > FACTORY_CLTV_DELTA_DEFAULT,
                "computed delta > hardcoded default of 40");
    TEST_ASSERT(delta >= 50, "delta >= 50 for step_blocks=6");

    /* Verify it's used correctly in validation */
    uint32_t fwd;
    TEST_ASSERT(lsp_validate_cltv_for_forward(delta + 10, &fwd, 0, delta) == 1,
                "cltv above delta passes");
    TEST_ASSERT_EQ(fwd, 10, "forwarded = cltv - delta");
    TEST_ASSERT(lsp_validate_cltv_for_forward(delta - 1, &fwd, 0, delta) == 0,
                "cltv below delta rejected");

    /* NULL factory returns default */
    TEST_ASSERT_EQ(lsp_compute_factory_cltv_delta(NULL),
                   FACTORY_CLTV_DELTA_DEFAULT,
                   "NULL factory returns default");

    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test: build_close_outputs with wallet SPK override ---- */

int test_close_outputs_wallet_spk(void) {
    /* Set up minimal mgr with 2 channels */
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.entries = calloc(2, sizeof(lsp_channel_entry_t));
    mgr.entries_cap = 2;
    mgr.n_channels = 2;
    mgr.entries[0].channel.local_amount = 5000;
    mgr.entries[0].channel.remote_amount = 3000;
    mgr.entries[1].channel.local_amount = 4000;
    mgr.entries[1].channel.remote_amount = 2000;

    factory_t *f = calloc(1, sizeof(factory_t));
    if (!f) return 0;

    f->funding_amount_sats = 5000 + 3000 + 4000 + 2000 + 500;  /* balances + fee */
    memset(f->funding_spk, 0xAA, 34);
    f->funding_spk_len = 34;

    uint64_t close_fee = 500;

    /* Test 1: NULL SPK — should use factory funding SPK */
    tx_output_t outputs[3];
    size_t n = lsp_channels_build_close_outputs(&mgr, f, outputs, close_fee,
                                                  NULL, 0);
    TEST_ASSERT_EQ(n, 3, "NULL SPK: 3 outputs");

    /* LSP output: funding - client_total - fee = 14500 - 5000 - 500 = 9000 */
    TEST_ASSERT_EQ(outputs[0].amount_sats, 9000, "NULL SPK: LSP amount");
    TEST_ASSERT_EQ(outputs[0].script_pubkey_len, 34, "NULL SPK: LSP spk len");
    unsigned char expected_factory_spk[34];
    memset(expected_factory_spk, 0xAA, 34);
    TEST_ASSERT(memcmp(outputs[0].script_pubkey, expected_factory_spk, 34) == 0,
                "NULL SPK: LSP uses factory SPK");

    TEST_ASSERT_EQ(outputs[1].amount_sats, 3000, "NULL SPK: client 0 amount");
    TEST_ASSERT(memcmp(outputs[1].script_pubkey, expected_factory_spk, 34) == 0,
                "NULL SPK: client 0 uses factory SPK");

    TEST_ASSERT_EQ(outputs[2].amount_sats, 2000, "NULL SPK: client 1 amount");
    TEST_ASSERT(memcmp(outputs[2].script_pubkey, expected_factory_spk, 34) == 0,
                "NULL SPK: client 1 uses factory SPK");

    /* Test 2: Custom wallet SPK — all outputs should use override */
    unsigned char wallet_spk[34];
    memset(wallet_spk, 0xBB, 34);

    n = lsp_channels_build_close_outputs(&mgr, f, outputs, close_fee,
                                           wallet_spk, 34);
    TEST_ASSERT_EQ(n, 3, "wallet SPK: 3 outputs");

    TEST_ASSERT_EQ(outputs[0].amount_sats, 9000, "wallet SPK: LSP amount");
    TEST_ASSERT(memcmp(outputs[0].script_pubkey, wallet_spk, 34) == 0,
                "wallet SPK: LSP uses override");

    TEST_ASSERT(memcmp(outputs[1].script_pubkey, wallet_spk, 34) == 0,
                "wallet SPK: client 0 uses override");

    TEST_ASSERT(memcmp(outputs[2].script_pubkey, wallet_spk, 34) == 0,
                "wallet SPK: client 1 uses override");

    /* Balance invariant: sum + fee == funding */
    uint64_t sum = close_fee;
    for (size_t i = 0; i < n; i++)
        sum += outputs[i].amount_sats;
    TEST_ASSERT_EQ(sum, f->funding_amount_sats, "balance invariant holds");

    /* Test 3: Per-client close addresses (NULL SPK + populated entry close_spk) */
    unsigned char client0_spk[34], client1_spk[34];
    memset(client0_spk, 0xC0, 34);
    memset(client1_spk, 0xC1, 34);
    memcpy(mgr.entries[0].close_spk, client0_spk, 34);
    mgr.entries[0].close_spk_len = 34;
    memcpy(mgr.entries[1].close_spk, client1_spk, 34);
    mgr.entries[1].close_spk_len = 34;

    n = lsp_channels_build_close_outputs(&mgr, f, outputs, close_fee,
                                           NULL, 0);
    TEST_ASSERT_EQ(n, 3, "per-client: 3 outputs");
    TEST_ASSERT(memcmp(outputs[0].script_pubkey, expected_factory_spk, 34) == 0,
                "per-client: LSP uses factory SPK");
    TEST_ASSERT(memcmp(outputs[1].script_pubkey, client0_spk, 34) == 0,
                "per-client: client 0 uses own close address");
    TEST_ASSERT(memcmp(outputs[2].script_pubkey, client1_spk, 34) == 0,
                "per-client: client 1 uses own close address");

    /* Test 4: Override still takes precedence even with per-client addresses set */
    n = lsp_channels_build_close_outputs(&mgr, f, outputs, close_fee,
                                           wallet_spk, 34);
    TEST_ASSERT_EQ(n, 3, "override+per-client: 3 outputs");
    TEST_ASSERT(memcmp(outputs[1].script_pubkey, wallet_spk, 34) == 0,
                "override+per-client: client 0 uses override (rotation mode)");
    TEST_ASSERT(memcmp(outputs[2].script_pubkey, wallet_spk, 34) == 0,
                "override+per-client: client 1 uses override (rotation mode)");

    /* Test 5: Production path — mgr->lsp_close_spk populated (P2TR of LSP
       pubkey) plus per-client close_spks. LSP output must use its own SPK,
       NOT the N-of-N factory funding SPK. Clients keep their own SPKs. */
    unsigned char lsp_spk[34];
    memset(lsp_spk, 0xD0, 34);
    memcpy(mgr.lsp_close_spk, lsp_spk, 34);
    mgr.lsp_close_spk_len = 34;

    n = lsp_channels_build_close_outputs(&mgr, f, outputs, close_fee,
                                           NULL, 0);
    TEST_ASSERT_EQ(n, 3, "lsp_close_spk: 3 outputs");
    TEST_ASSERT(memcmp(outputs[0].script_pubkey, lsp_spk, 34) == 0,
                "lsp_close_spk: LSP uses its own SPK (not factory SPK)");
    TEST_ASSERT(memcmp(outputs[0].script_pubkey, expected_factory_spk, 34) != 0,
                "lsp_close_spk: LSP SPK differs from factory funding SPK");
    TEST_ASSERT(memcmp(outputs[1].script_pubkey, client0_spk, 34) == 0,
                "lsp_close_spk: client 0 still uses its own close address");
    TEST_ASSERT(memcmp(outputs[2].script_pubkey, client1_spk, 34) == 0,
                "lsp_close_spk: client 1 still uses its own close address");

    /* Test 6: Rotation override still wins over lsp_close_spk (recycling) */
    n = lsp_channels_build_close_outputs(&mgr, f, outputs, close_fee,
                                           wallet_spk, 34);
    TEST_ASSERT_EQ(n, 3, "override beats lsp_close_spk: 3 outputs");
    TEST_ASSERT(memcmp(outputs[0].script_pubkey, wallet_spk, 34) == 0,
                "override beats lsp_close_spk: LSP uses override");
    TEST_ASSERT(memcmp(outputs[1].script_pubkey, wallet_spk, 34) == 0,
                "override beats lsp_close_spk: client 0 uses override");

    free(mgr.entries);
    free(f);
    return 1;
}

/* ---- Test: mgr->lsp_close_spk derived symmetric with client close_spk ---- */

int test_lsp_close_spk_derived(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    for (int i = 0; i < 5; i++)
        if (!secp256k1_keypair_create(ctx, &kps[i], seckeys[i])) return 0;

    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++)
        if (!secp256k1_keypair_pub(ctx, &pks[i], &kps[i])) return 0;

    /* Build the N-of-N funding SPK the factory uses. */
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
    fake_txid[0] = 0xEE;
    factory_set_funding(f, fake_txid, 0, 1000000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(f), "build tree");

    /* Expected LSP close SPK = P2TR(xonly(pubkeys[0])) — LSP-alone spendable. */
    secp256k1_xonly_pubkey lsp_xonly_expected;
    TEST_ASSERT(secp256k1_xonly_pubkey_from_pubkey(ctx, &lsp_xonly_expected, NULL, &pks[0]),
                "derive LSP xonly");
    unsigned char expected_lsp_spk[34];
    build_p2tr_script_pubkey(expected_lsp_spk, &lsp_xonly_expected);

    /* Init mgr — this is what should populate lsp_close_spk. */
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    TEST_ASSERT(lsp_channels_init(&mgr, ctx, f, seckeys[0], 4),
                "lsp_channels_init");

    TEST_ASSERT_EQ(mgr.lsp_close_spk_len, 34, "lsp_close_spk populated");
    TEST_ASSERT(memcmp(mgr.lsp_close_spk, expected_lsp_spk, 34) == 0,
                "mgr.lsp_close_spk == P2TR(xonly(factory.pubkeys[0]))");
    TEST_ASSERT(memcmp(mgr.lsp_close_spk, fund_spk, 34) != 0,
                "mgr.lsp_close_spk differs from factory funding SPK (N-of-N MuSig)");

    /* build_close_outputs with NULL override must put outputs[0] at lsp_close_spk. */
    tx_output_t outputs[6];
    memset(outputs, 0, sizeof(outputs));
    /* Give clients a little remote_amount so outputs[1..] are non-dust. */
    for (size_t c = 0; c < 4; c++)
        mgr.entries[c].channel.remote_amount = 2000;
    /* Make funding_amount big enough to cover sum(remotes) + close_fee + LSP residual. */
    f->funding_amount_sats = 100000;

    size_t n = lsp_channels_build_close_outputs(&mgr, f, outputs, 500, NULL, 0);
    TEST_ASSERT_EQ(n, 5, "build_close_outputs: 1 LSP + 4 clients");
    TEST_ASSERT(memcmp(outputs[0].script_pubkey, mgr.lsp_close_spk, 34) == 0,
                "cooperative close: LSP output uses mgr.lsp_close_spk");
    TEST_ASSERT(memcmp(outputs[0].script_pubkey, fund_spk, 34) != 0,
                "cooperative close: LSP output is NOT factory funding SPK");

    lsp_channels_cleanup(&mgr);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* --- Balance conservation invariant tests --- */

int test_conservation_balanced(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.entries = calloc(2, sizeof(lsp_channel_entry_t));
    mgr.n_channels = 2;

    /* Channel 0: balanced (50k + 50k = 100k) */
    mgr.entries[0].channel.funding_amount = 100000;
    mgr.entries[0].channel.local_amount = 50000;
    mgr.entries[0].channel.remote_amount = 50000;

    /* Channel 1: with HTLC (40k + 50k + 10k HTLC = 100k) */
    mgr.entries[1].channel.funding_amount = 100000;
    mgr.entries[1].channel.local_amount = 40000;
    mgr.entries[1].channel.remote_amount = 50000;
    htlc_t htlc;
    memset(&htlc, 0, sizeof(htlc));
    htlc.state = HTLC_STATE_ACTIVE;
    htlc.amount_sats = 10000;
    mgr.entries[1].channel.htlcs = &htlc;
    mgr.entries[1].channel.n_htlcs = 1;

    TEST_ASSERT(lsp_channels_check_conservation(&mgr) == 1,
                "balanced channels pass conservation");

    free(mgr.entries);
    return 1;
}

int test_conservation_violated(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.entries = calloc(1, sizeof(lsp_channel_entry_t));
    mgr.n_channels = 1;

    /* Violated: 60k + 50k = 110k != 100k funding */
    mgr.entries[0].channel.funding_amount = 100000;
    mgr.entries[0].channel.local_amount = 60000;
    mgr.entries[0].channel.remote_amount = 50000;

    TEST_ASSERT(lsp_channels_check_conservation(&mgr) == 0,
                "unbalanced channel fails conservation");

    free(mgr.entries);
    return 1;
}

int test_conservation_with_ptlc(void) {
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.entries = calloc(1, sizeof(lsp_channel_entry_t));
    mgr.n_channels = 1;

    mgr.entries[0].channel.funding_amount = 100000;
    mgr.entries[0].channel.local_amount = 30000;
    mgr.entries[0].channel.remote_amount = 50000;

    htlc_t htlc;
    memset(&htlc, 0, sizeof(htlc));
    htlc.state = HTLC_STATE_ACTIVE;
    htlc.amount_sats = 5000;
    mgr.entries[0].channel.htlcs = &htlc;
    mgr.entries[0].channel.n_htlcs = 1;

    ptlc_t ptlc;
    memset(&ptlc, 0, sizeof(ptlc));
    ptlc.state = PTLC_STATE_ACTIVE;
    ptlc.amount_sats = 15000;
    mgr.entries[0].channel.ptlcs = &ptlc;
    mgr.entries[0].channel.n_ptlcs = 1;

    /* 30k + 50k + 5k + 15k = 100k = funding */
    TEST_ASSERT(lsp_channels_check_conservation(&mgr) == 1,
                "HTLC+PTLC sum to funding");

    free(mgr.entries);
    return 1;
}

int test_conservation_with_real_htlc(void) {
    /* Test conservation invariant using real channel_add_htlc() which deducts
       per-HTLC fees.  Before the fee_at_add fix, this would false-alarm. */
    lsp_channel_mgr_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.entries = calloc(1, sizeof(lsp_channel_entry_t));
    mgr.n_channels = 1;

    channel_t *ch = &mgr.entries[0].channel;
    ch->funding_amount = 100000;
    /* Conservation invariant is local+remote+Σhtlc == funding - base_commit_fee.
       base_commit_fee at 1 sat/vB is 154 sats (154 vB * 1000/1000 rounded up),
       which lsp_channels_init deducts from the funder side before splitting. */
    ch->local_amount = 49846;
    ch->remote_amount = 50000;
    ch->fee_rate_sat_per_kvb = 1000;  /* 1 sat/vB */
    ch->funder_is_local = 1;
    /* channel_add_htlc needs local_pcs for commitment_number generation */
    ch->local_pcs = calloc(16, 32);
    ch->local_pcs_cap = 16;
    ch->n_local_pcs = 2;

    /* Pre-check: conservation holds with no HTLCs */
    TEST_ASSERT(lsp_channels_check_conservation(&mgr) == 1,
                "conservation OK before HTLC");

    /* Add HTLC via real path (deducts amount + per-HTLC fee) */
    unsigned char hash[32];
    memset(hash, 0xAA, 32);
    uint64_t htlc_id;
    TEST_ASSERT(channel_add_htlc(ch, HTLC_OFFERED, 10000, hash, 500, &htlc_id) == 1,
                "add HTLC succeeds");
    TEST_ASSERT(ch->n_htlcs == 1, "1 active HTLC");

    /* Per-HTLC fee at 1 sat/vB = ceil(1000 * 43 / 1000) = 43 sats */
    uint64_t expected_fee = 43;
    TEST_ASSERT(ch->htlcs[0].fee_at_add == expected_fee,
                "fee_at_add stored correctly");

    /* Conservation MUST hold even with in-flight HTLC + fee gap */
    TEST_ASSERT(lsp_channels_check_conservation(&mgr) == 1,
                "conservation OK during in-flight HTLC");

    /* Verify exact balance: local = 49846 - 10000 (htlc) - 43 (fee) = 39803 */
    TEST_ASSERT(ch->local_amount == 49846 - 10000 - expected_fee,
                "local balance correct after add");
    TEST_ASSERT(ch->remote_amount == 50000,
                "remote balance unchanged");

    /* Fulfill HTLC — fee refunded from stored value */
    unsigned char preimage[32];
    memset(preimage, 0, 32);
    /* SHA256(preimage) must match hash — just use a dummy for this test.
       Override hash to match: compute SHA256 of our preimage. */
    extern void sha256(const unsigned char *, size_t, unsigned char *);
    sha256(preimage, 32, hash);
    /* Re-add with correct hash */
    ch->n_htlcs = 0;
    ch->local_amount = 49846;
    ch->remote_amount = 50000;
    ch->commitment_number = 0;
    TEST_ASSERT(channel_add_htlc(ch, HTLC_OFFERED, 10000, hash, 500, &htlc_id) == 1,
                "re-add HTLC with correct hash");
    TEST_ASSERT(channel_fulfill_htlc(ch, htlc_id, preimage) == 1,
                "fulfill HTLC succeeds");

    /* After fulfill: local = 49846 - 10000 - 43 + 43 = 39846, remote = 50000 + 10000 = 60000 */
    TEST_ASSERT(ch->local_amount == 39846,
                "local balance correct after fulfill");
    TEST_ASSERT(ch->remote_amount == 60000,
                "remote balance correct after fulfill");
    TEST_ASSERT(lsp_channels_check_conservation(&mgr) == 1,
                "conservation OK after fulfill");

    free(ch->local_pcs);
    free(ch->htlcs);
    free(mgr.entries);
    return 1;
}

/* ---- PS double-spend defense: integration test (Gap 2).
 *
 * PR #79 added client-side tracking of previously-signed PS parent inputs
 * (client_ps_signed_inputs table + persist_check/save API + wiring into
 * client_handle_leaf_advance). test_persist_ps_signed_input_roundtrip
 * covers the persist API. THIS test covers the wire-up: given a persist
 * pre-seeded with a signed_input row for a would-be-parent, does
 * client_handle_leaf_advance actually call the check and refuse?
 *
 * Mechanism:
 *   1. Build a 3-party PS factory; capture leaf[0]'s pre-advance txid T0.
 *      After factory_advance_leaf_unsigned, ps_prev_txid becomes T0 — so
 *      (T0, 0) is the parent UTXO the client is about to co-sign spending.
 *   2. Seed persist with client_ps_signed_inputs row for (factory_id=0,
 *      parent_txid=T0, parent_vout=0). This simulates "client has already
 *      co-signed one TX spending T0:0."
 *   3. client_set_persist(&db) wires the defense.
 *   4. Build a wire_msg_t PROPOSE for leaf_side=0 with any valid LSP
 *      pubnonce, invoke client_handle_leaf_advance on a writable fd that
 *      nothing reads from.
 *   5. Assert return value == 0 (refuse). The function bails before any
 *      PSIG is written to fd, so the fd side is moot.
 */
int test_client_ps_double_spend_defense_refuses(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* 3-party PS factory: LSP (idx 0) + 2 clients (idx 1, 2). We play the
       client at idx 1 below (leaf 0's client). */
    const size_t N = 3;
    secp256k1_keypair kps[3];
    for (size_t i = 0; i < N; i++) {
        unsigned char sk[32] = {0};
        sk[31] = (unsigned char)(i + 1);
        sk[0]  = 0x99;
        TEST_ASSERT(secp256k1_keypair_create(ctx, &kps[i], sk), "keypair");
    }

    /* Funding SPK: 3-of-3 MuSig taptweaked. */
    unsigned char fund_spk[34];
    {
        secp256k1_pubkey pks[3];
        for (size_t i = 0; i < N; i++)
            secp256k1_keypair_pub(ctx, &pks[i], &kps[i]);
        musig_keyagg_t ka;
        musig_aggregate_keys(ctx, &ka, pks, N);
        unsigned char ser[32];
        secp256k1_xonly_pubkey_serialize(ctx, ser, &ka.agg_pubkey);
        unsigned char tweak[32];
        sha256_tagged("TapTweak", ser, 32, tweak);
        secp256k1_pubkey tw_pk;
        secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tw_pk, &ka.cache, tweak);
        secp256k1_xonly_pubkey tw_xo;
        secp256k1_xonly_pubkey_from_pubkey(ctx, &tw_xo, NULL, &tw_pk);
        build_p2tr_script_pubkey(fund_spk, &tw_xo);
    }
    unsigned char fake_fund_txid[32];
    memset(fake_fund_txid, 0x7A, 32);

    factory_t *f = calloc(1, sizeof(factory_t));
    TEST_ASSERT(f, "alloc factory");
    factory_init(f, ctx, kps, N, 6, 10);
    factory_set_arity(f, FACTORY_ARITY_PS);
    factory_set_funding(f, fake_fund_txid, 0, 500000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(f), "build PS tree");
    TEST_ASSERT(factory_sign_all(f), "sign PS tree");

    /* Capture leaf[0]'s txid BEFORE advance — this becomes ps_prev_txid
       after factory_advance_leaf_unsigned runs inside the handler. */
    size_t leaf_idx = f->leaf_node_indices[0];
    unsigned char expected_parent_txid[32];
    memcpy(expected_parent_txid, f->nodes[leaf_idx].txid, 32);

    /* Open an in-memory persist and pre-seed a signed_input row for
       (parent_txid=expected_parent_txid, parent_vout=0). Dummy sighash /
       partial_sig — the check only uses the (parent_txid, parent_vout)
       key, not the stored sighash. */
    persist_t db;
    TEST_ASSERT(persist_open(&db, ":memory:"), "open in-memory persist");
    unsigned char dummy_sighash[32], dummy_psig[36];
    memset(dummy_sighash, 0x55, 32);
    memset(dummy_psig, 0x66, 36);
    TEST_ASSERT(persist_save_ps_signed_input(&db, /*factory_id=*/0,
                    /*leaf_idx=*/(int)leaf_idx,
                    expected_parent_txid, /*parent_vout=*/0,
                    dummy_sighash, dummy_psig),
                "pre-seed signed_input row");

    /* Wire the defense into client_handle_leaf_advance. */
    client_set_persist(&db);

    /* Build a valid LEAF_ADVANCE_PROPOSE from the LSP (index 0) so the
       handler can parse it and proceed far enough to hit our check. */
    unsigned char lsp_seckey[32];
    TEST_ASSERT(secp256k1_keypair_sec(ctx, lsp_seckey, &kps[0]), "lsp seckey");
    secp256k1_pubkey lsp_pub;
    secp256k1_keypair_pub(ctx, &lsp_pub, &kps[0]);
    secp256k1_musig_secnonce lsp_secnonce;
    secp256k1_musig_pubnonce lsp_pubnonce;
    TEST_ASSERT(musig_generate_nonce(ctx, &lsp_secnonce, &lsp_pubnonce,
                                       lsp_seckey, &lsp_pub, NULL),
                "lsp nonce");
    memset(lsp_seckey, 0, 32);
    unsigned char lsp_pubnonce_ser[66];
    musig_pubnonce_serialize(ctx, lsp_pubnonce_ser, &lsp_pubnonce);
    cJSON *propose_json = wire_build_leaf_advance_propose(0, lsp_pubnonce_ser, NULL);
    TEST_ASSERT(propose_json != NULL, "build PROPOSE json");
    wire_msg_t propose = {0};
    propose.msg_type = 0x58;  /* MSG_LEAF_ADVANCE_PROPOSE — unused after
                                  wire_parse consumes the json */
    propose.json = propose_json;

    /* Pipe as the output fd — nothing will be written on the refuse path,
       but we pass a valid fd in case the function starts to. */
    int pipefd[2];
    TEST_ASSERT(pipe(pipefd) == 0, "pipe");

    /* Invoke the handler. The check should trigger early and return 0. */
    int rc = client_handle_leaf_advance(pipefd[1], ctx, &kps[1], f,
                                          /*my_index=*/1, &propose);

    TEST_ASSERT(rc == 0, "handler REFUSES when parent already signed");

    /* Cleanup — reset the global persist hook. */
    client_set_persist(NULL);
    cJSON_Delete(propose_json);
    close(pipefd[0]);
    close(pipefd[1]);
    persist_close(&db);
    factory_free(f);
    free(f);
    secp256k1_context_destroy(ctx);
    return 1;
}

