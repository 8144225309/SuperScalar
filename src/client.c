#include "superscalar/client.h"
#include "superscalar/wire.h"
#include "superscalar/factory.h"
#include "superscalar/fee.h"
#include "superscalar/musig.h"
#include "superscalar/persist.h"
#include "superscalar/shachain.h"
#include "superscalar/tx_builder.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);
#include "superscalar/sha256.h"

/* Optional NK server authentication pubkey (set via client_set_lsp_pubkey) */
static secp256k1_pubkey g_nk_server_pubkey;
static int g_nk_server_pubkey_set = 0;

/* Optional persistence handle for PS double-spend defense (set via
   client_set_persist). NULL disables the check — only acceptable for
   in-process tests that don't exercise the attack. */
static persist_t *g_client_persist = NULL;

void client_set_persist(persist_t *p) {
    g_client_persist = p;
}

/* Minimum acceptable profit share in basis points (set via client_set_min_profit_bps).
   If > 0 and the LSP offers less, the client refuses to sign the factory tree. */
static uint16_t g_min_profit_bps = 0;

void client_set_min_profit_bps(uint16_t bps) {
    g_min_profit_bps = bps;
}

/* Optional slot hint sent in HELLO (1..n_clients). 0 = no hint. */
static int g_slot_hint = 0;

void client_set_slot_hint(int slot_hint) {
    g_slot_hint = slot_hint;
}

/* Routing fee rate from SCID_ASSIGN — set during factory creation,
   read by the daemon callback for fee tracking. */
uint32_t g_routing_fee_ppm = 0;

void client_set_lsp_pubkey(const secp256k1_pubkey *pubkey) {
    if (pubkey) {
        g_nk_server_pubkey = *pubkey;
        g_nk_server_pubkey_set = 1;
    } else {
        g_nk_server_pubkey_set = 0;
    }
}

/* Client-side conservation invariant check (defense-in-depth).
   The commitment signature already prevents exploitation, but this catches
   bugs in the balance arithmetic itself.

   Conservation: local + remote + Σ(htlc.amount + htlc.fee_at_add)
                 == funding − base_commit_fee
   The base commit-tx fee (154 vB × fee_rate) is deducted from the channel's
   usable balance at init time (lsp_channels_init, src/lsp_channels.c:203-204),
   so the invariant must account for it — otherwise the check trips by
   exactly base_commit_fee on every balanced channel. */
static void client_check_conservation(const channel_t *ch, const char *context) {
    if (!ch || ch->funding_amount == 0) return;
    uint64_t sum = ch->local_amount + ch->remote_amount;
    for (size_t h = 0; h < ch->n_htlcs; h++) {
        if (ch->htlcs[h].state == HTLC_STATE_ACTIVE) {
            sum += ch->htlcs[h].amount_sats;
            sum += ch->htlcs[h].fee_at_add;
        }
    }
    /* Base commit-tx fee: matches fee_for_commitment_tx(fe, 0) in src/fee.c
       (154 vB × fee_rate_sat_per_kvb, rounded up per compute_fee). */
    uint64_t base_commit_fee =
        (ch->fee_rate_sat_per_kvb * 154 + 999) / 1000;
    uint64_t expected = ch->funding_amount > base_commit_fee
                        ? ch->funding_amount - base_commit_fee : 0;
    if (sum != expected) {
        fprintf(stderr, "CLIENT CONSERVATION VIOLATION (%s): "
                "local=%llu remote=%llu htlc_sum=%llu total=%llu "
                "expected=%llu funding=%llu base_commit_fee=%llu "
                "(delta=%lld)\n",
                context,
                (unsigned long long)ch->local_amount,
                (unsigned long long)ch->remote_amount,
                (unsigned long long)(sum - ch->local_amount - ch->remote_amount),
                (unsigned long long)sum,
                (unsigned long long)expected,
                (unsigned long long)ch->funding_amount,
                (unsigned long long)base_commit_fee,
                (long long)(sum - expected));
    }
}

/* Returns 1 if message is MSG_ERROR (and prints it), 0 otherwise */
static int check_msg_error(const wire_msg_t *msg) {
    if (msg->msg_type == MSG_ERROR) {
        cJSON *m = cJSON_GetObjectItem(msg->json, "message");
        fprintf(stderr, "Client: LSP error: %s\n",
                (m && cJSON_IsString(m)) ? m->valuestring : "(unknown)");
        return 1;
    }
    return 0;
}

/* Send MSG_ERROR to LSP before disconnecting (best-effort, ignores send failures) */
static void client_send_error(int fd, const char *reason) {
    cJSON *err = wire_build_error(reason ? reason : "client error");
    wire_send(fd, MSG_ERROR, err);
    cJSON_Delete(err);
}

/* Wrapper around wire_recv_timeout that transparently handles
   MSG_PING (responds with MSG_PONG) and MSG_PONG (discards).
   Returns 1 on a real (non-keepalive) message, 0 on failure. */
static int wire_recv_handle_ping(int fd, wire_msg_t *msg, int timeout_sec) {
    for (;;) {
        if (!wire_recv_timeout(fd, msg, timeout_sec))
            return 0;
        if (msg->msg_type == MSG_PING) {
            cJSON *pong = cJSON_CreateObject();
            wire_send(fd, MSG_PONG, pong);
            cJSON_Delete(pong);
            if (msg->json) cJSON_Delete(msg->json);
            msg->json = NULL;
            continue;  /* wait for next real message */
        }
        if (msg->msg_type == MSG_PONG) {
            if (msg->json) cJSON_Delete(msg->json);
            msg->json = NULL;
            continue;  /* discard pong, wait for real message */
        }
        return 1;  /* real message */
    }
}

/* Initialize a client-side channel from factory leaf outputs.
   Mirrors the LSP's lsp_channels_init logic.
   remote_*_bp: remote (LSP) basepoint pubkeys received via MSG_CHANNEL_BASEPOINTS.
   local_*_sec32: 32-byte local basepoint secrets (random, not SHA256-derived). */
int client_init_channel(channel_t *ch, secp256k1_context *ctx,
                                 const factory_t *factory,
                                 const secp256k1_keypair *keypair,
                                 uint32_t my_index,
                                 const secp256k1_pubkey *remote_payment_bp,
                                 const secp256k1_pubkey *remote_delayed_bp,
                                 const secp256k1_pubkey *remote_revocation_bp,
                                 const secp256k1_pubkey *remote_htlc_bp,
                                 const unsigned char *local_pay_sec32,
                                 const unsigned char *local_delay_sec32,
                                 const unsigned char *local_revoc_sec32,
                                 const unsigned char *local_htlc_sec32,
                                 fee_estimator_t *fee_est) {
    /* Map client index to leaf output via the canonical helper.  See
       factory.h::factory_client_to_leaf for the arity-aware semantics
       (mixed-arity walks signer_indices; uniform arities use legacy
       formula).  Centralizing this keeps client.c and lsp_channels.c in
       sync — divergent open-coded copies caused the bug fixed in
       PR #117. */
    size_t client_idx = (size_t)(my_index - 1);  /* my_index is 1-based */
    size_t node_idx;
    uint32_t vout;
    if (!factory_client_to_leaf(factory, client_idx, &node_idx, &vout)) {
        fprintf(stderr, "Client %u: factory_client_to_leaf failed\n",
                my_index);
        return 0;
    }

    const factory_node_t *state_node = &factory->nodes[node_idx];
    if (vout >= state_node->n_outputs) return 0;

    const unsigned char *funding_txid = state_node->txid;
    uint64_t funding_amount = state_node->outputs[vout].amount_sats;
    const unsigned char *funding_spk = state_node->outputs[vout].script_pubkey;
    size_t funding_spk_len = state_node->outputs[vout].script_pubkey_len;

    /* Client is "local", LSP is "remote" (from client's perspective) */
    secp256k1_pubkey my_pubkey;
    secp256k1_keypair_pub(ctx, &my_pubkey, keypair);

    unsigned char my_seckey[32];
    secp256k1_keypair_sec(ctx, my_seckey, keypair);

    /* LSP pubkey (participant 0) */
    const secp256k1_pubkey *lsp_pubkey = &factory->pubkeys[0];

    /* Commitment tx fee: must match lsp_channels_init so both sides agree. */
    fee_estimator_static_t _fe_default;
    fee_estimator_t *_fe = fee_est;
    if (!_fe) { fee_estimator_static_init(&_fe_default, 1000); _fe = &_fe_default.base; }
    uint64_t commit_fee = fee_for_commitment_tx(_fe, 0);
    uint64_t usable = funding_amount > commit_fee ? funding_amount - commit_fee : 0;
    uint64_t local_amount = usable / 2;
    uint64_t remote_amount = usable - local_amount;

    /* From client perspective: local = client, remote = LSP.
       But channel balances should match LSP's view. The LSP has:
         lsp.local_amount = usable/2, lsp.remote_amount = usable - usable/2
       Client should have the mirror:
         client.local_amount = usable - usable/2 (= lsp.remote_amount)
         client.remote_amount = usable/2 (= lsp.local_amount) */

    if (!channel_init(ch, ctx, my_seckey, &my_pubkey, lsp_pubkey,
                       funding_txid, vout, funding_amount,
                       funding_spk, funding_spk_len,
                       remote_amount,   /* client's local = LSP's remote */
                       local_amount,    /* client's remote = LSP's local */
                       CHANNEL_DEFAULT_CSV_DELAY)) {
        memset(my_seckey, 0, 32);
        return 0;
    }
    ch->funder_is_local = 0;  /* LSP (remote) is the funder */

    /* Set local basepoints from caller-provided random secrets */
    channel_set_local_basepoints(ch, local_pay_sec32, local_delay_sec32, local_revoc_sec32);
    channel_set_local_htlc_basepoint(ch, local_htlc_sec32);

    /* Remote basepoints: received from LSP via MSG_CHANNEL_BASEPOINTS */
    channel_set_remote_basepoints(ch, remote_payment_bp, remote_delayed_bp, remote_revocation_bp);
    channel_set_remote_htlc_basepoint(ch, remote_htlc_bp);

    /* Fix keyagg: factory leaf outputs always use [client, lsp] key ordering.
       channel_init's SPK-match heuristic fails for CLTV-taptree outputs
       (cltv_timeout > 0), falling back to [local, remote] = [client, lsp] which
       is coincidentally correct here, but with wrong signer_idx vs LSP's fallback.
       Override explicitly to guarantee consistent ordering on both sides. */
    {
        secp256k1_pubkey ch_pks[2] = { my_pubkey, *lsp_pubkey };
        if (!musig_aggregate_keys(ctx, &ch->funding_keyagg, ch_pks, 2)) {
            memset(my_seckey, 0, 32);
            return 0;
        }
        ch->local_funding_signer_idx = 0;  /* client at index 0 */
    }
    /* Set CLTV taptree merkle root so MuSig2 session uses correct tweak */
    if (factory->cltv_timeout > 0)
        channel_set_cltv_merkle_root(ch, factory->cltv_timeout, lsp_pubkey);

    memset(my_seckey, 0, 32);
    return 1;
}

/* --- Channel message handlers --- */

int client_send_payment(int fd, channel_t *ch, uint64_t amount_sats,
                         const unsigned char *payment_hash32,
                         uint32_t cltv_expiry, uint32_t dest_client) {
    /* Add HTLC to local channel state (offered from our side) */
    uint64_t htlc_id;
    if (!channel_add_htlc(ch, HTLC_OFFERED, amount_sats, payment_hash32,
                           cltv_expiry, &htlc_id))
        return 0;

    cJSON *msg = wire_build_update_add_htlc(htlc_id, amount_sats * 1000,
                                              payment_hash32, cltv_expiry);
    /* Add dest_client extension field */
    cJSON_AddNumberToObject(msg, "dest_client", dest_client);
    int ok = wire_send(fd, MSG_UPDATE_ADD_HTLC, msg);
    cJSON_Delete(msg);
    return ok;
}

int client_handle_commitment_signed(int fd, channel_t *ch,
                                      secp256k1_context *ctx,
                                      const wire_msg_t *msg) {
    uint32_t channel_id;
    uint64_t commitment_number;
    unsigned char partial_sig32[32];
    uint32_t nonce_index;

    if (!wire_parse_commitment_signed(msg->json, &channel_id,
                                        &commitment_number, partial_sig32,
                                        &nonce_index)) {
        fprintf(stderr, "Client: wire_parse_commitment_signed failed (cn=%llu)\n",
                (unsigned long long)ch->commitment_number);
        return 0;
    }

    /* Phase 12: Verify LSP's partial sig and aggregate into full sig.
       The client now holds a valid, broadcastable commitment tx. */
    unsigned char full_sig64[64];
    if (!channel_verify_and_aggregate_commitment_sig(ch, partial_sig32,
                                                       nonce_index, full_sig64)) {
        fprintf(stderr, "Client: commitment sig verification/aggregation failed\n");
        return 0;
    }

    /* Store the aggregated signature so the client can broadcast the
       commitment TX independently (trustless force-close). */
    memcpy(ch->latest_commitment_sig, full_sig64, 64);
    ch->has_latest_commitment_sig = 1;

    /* Get revocation secret for the old commitment */
    unsigned char rev_secret[32];
    if (ch->commitment_number > 0) {
        channel_get_revocation_secret(ch, ch->commitment_number - 1, rev_secret);
    } else {
        memset(rev_secret, 0, 32);
    }

    /* Get next per-commitment point */
    secp256k1_pubkey next_pcp;
    channel_get_per_commitment_point(ch, ch->commitment_number + 1, &next_pcp);

    cJSON *ack = wire_build_revoke_and_ack(channel_id, rev_secret, ctx, &next_pcp);
    int ok = wire_send(fd, MSG_REVOKE_AND_ACK, ack);
    cJSON_Delete(ack);
    memset(rev_secret, 0, 32);
    if (!ok)
        fprintf(stderr, "Client: wire_send REVOKE_AND_ACK failed (cn=%llu)\n",
                (unsigned long long)ch->commitment_number);
    return ok;
}

int client_handle_add_htlc(channel_t *ch, const wire_msg_t *msg) {
    uint64_t htlc_id, amount_msat;
    unsigned char payment_hash[32];
    uint32_t cltv_expiry;

    if (!wire_parse_update_add_htlc(msg->json, &htlc_id, &amount_msat,
                                      payment_hash, &cltv_expiry))
        return 0;

    uint64_t amount_sats = amount_msat / 1000;
    uint64_t new_id;

    /* If dest_client field is present, we're the sender (LSP is routing
       our payment). Otherwise we're the receiver. */
    cJSON *dest = cJSON_GetObjectItem(msg->json, "dest_client");
    htlc_direction_t dir = dest ? HTLC_OFFERED : HTLC_RECEIVED;

    if (!channel_add_htlc(ch, dir, amount_sats, payment_hash,
                           cltv_expiry, &new_id))
        return 0;

    /* Override locally-assigned ID with the wire htlc_id so that when we
       send FULFILL_HTLC back, we reference the LSP's ID for this HTLC. */
    ch->htlcs[ch->n_htlcs - 1].id = htlc_id;

    client_check_conservation(ch, "after add_htlc");
    return 1;
}

int client_fulfill_payment(int fd, channel_t *ch,
                             uint64_t htlc_id,
                             const unsigned char *preimage32) {
    /* Fulfill locally */
    if (!channel_fulfill_htlc(ch, htlc_id, preimage32))
        return 0;

    client_check_conservation(ch, "after fulfill_htlc");

    /* Send FULFILL_HTLC to LSP */
    cJSON *msg = wire_build_update_fulfill_htlc(htlc_id, preimage32);
    int ok = wire_send(fd, MSG_UPDATE_FULFILL_HTLC, msg);
    cJSON_Delete(msg);
    return ok;
}

/* --- Cooperative close ceremony (extracted for reuse) --- */

int client_do_close_ceremony(int fd, secp256k1_context *ctx,
                               const secp256k1_keypair *keypair,
                               const secp256k1_pubkey *my_pubkey,
                               factory_t *factory,
                               size_t n_participants,
                               const wire_msg_t *initial_msg,
                               uint32_t current_height,
                               const channel_t *ch) {
    wire_msg_t msg;
    int got_propose = 0;

    if (initial_msg && initial_msg->msg_type == MSG_CLOSE_PROPOSE) {
        /* Use already-received CLOSE_PROPOSE */
        msg = *initial_msg;
        got_propose = 1;
    } else {
        /* Receive CLOSE_PROPOSE, skipping any LSP revocation messages
           and trailing leaf-advance traffic (per-leaf advance ceremonies
           trigger after HTLC fulfill in lsp_channels.c:2259; their
           PROPOSE/DONE messages may arrive just before CLOSE_PROPOSE). */
        for (;;) {
            if (!wire_recv(fd, &msg) || check_msg_error(&msg)) {
                fprintf(stderr, "Client: expected CLOSE_PROPOSE\n");
                if (msg.json) cJSON_Delete(msg.json);
                return 0;
            }
            if (msg.msg_type == 0x50) {  /* MSG_LSP_REVOKE_AND_ACK */
                cJSON_Delete(msg.json);
                continue;
            }
            if (msg.msg_type == MSG_LEAF_ADVANCE_PROPOSE ||
                msg.msg_type == MSG_STATE_ADVANCE_PROPOSE) {
                /* Participate in the (per-leaf or whole-tree state-advance)
                   ceremony inline.  Derive my_index from the factory's pubkey
                   list. */
                uint32_t my_idx = UINT32_MAX;
                for (size_t p = 0; p < factory->n_participants; p++) {
                    unsigned char a[33], b[33]; size_t la = 33, lb = 33;
                    if (secp256k1_ec_pubkey_serialize(ctx, a, &la,
                                                        &factory->pubkeys[p],
                                                        SECP256K1_EC_COMPRESSED) &&
                        secp256k1_ec_pubkey_serialize(ctx, b, &lb,
                                                        my_pubkey,
                                                        SECP256K1_EC_COMPRESSED) &&
                        la == lb && memcmp(a, b, la) == 0) {
                        my_idx = (uint32_t)p;
                        break;
                    }
                }
                int handled = 0;
                if (my_idx != UINT32_MAX) {
                    handled = (msg.msg_type == MSG_LEAF_ADVANCE_PROPOSE)
                        ? client_handle_leaf_advance(fd, ctx, keypair, factory,
                                                      my_idx, &msg)
                        : client_handle_state_advance(fd, ctx, keypair, factory,
                                                        my_idx, &msg);
                }
                if (!handled) {
                    cJSON_Delete(msg.json);
                    return 0;
                }
                cJSON_Delete(msg.json);
                continue;
            }
            if (msg.msg_type == MSG_LEAF_ADVANCE_DONE ||
                msg.msg_type == MSG_PATH_SIGN_DONE) {
                /* Stray DONE after an advance we already processed; skip. */
                cJSON_Delete(msg.json);
                continue;
            }
            if (msg.msg_type != MSG_CLOSE_PROPOSE) {
                fprintf(stderr, "Client: expected CLOSE_PROPOSE, got 0x%02x\n",
                        msg.msg_type);
                cJSON_Delete(msg.json);
                return 0;
            }
            break;
        }
        got_propose = 1;
    }

    cJSON *outputs_arr = cJSON_GetObjectItem(msg.json, "outputs");
    if (!outputs_arr || !cJSON_IsArray(outputs_arr)) {
        fprintf(stderr, "Client: malformed CLOSE_PROPOSE\n");
        if (!initial_msg) cJSON_Delete(msg.json);
        return 0;
    }

    /* Extract nLockTime height from CLOSE_PROPOSE (anti-fee-sniping). */
    cJSON *ht = cJSON_GetObjectItem(msg.json, "current_height");
    uint32_t close_height = (ht && cJSON_IsNumber(ht))
                            ? (uint32_t)ht->valuedouble : current_height;

    size_t n_outputs = (size_t)cJSON_GetArraySize(outputs_arr);
    if (n_outputs == 0 || n_outputs > FACTORY_MAX_SIGNERS) {
        fprintf(stderr, "Client: bad output count %zu\n", n_outputs);
        if (!initial_msg) cJSON_Delete(msg.json);
        return 0;
    }
    tx_output_t *close_outputs = (tx_output_t *)calloc(n_outputs, sizeof(tx_output_t));
    if (!close_outputs) {
        fprintf(stderr, "Client: alloc failed\n");
        if (!initial_msg) cJSON_Delete(msg.json);
        return 0;
    }

    for (size_t i = 0; i < n_outputs; i++) {
        cJSON *item = cJSON_GetArrayItem(outputs_arr, (int)i);
        cJSON *amt = item ? cJSON_GetObjectItem(item, "amount") : NULL;
        if (!amt || !cJSON_IsNumber(amt)) {
            fprintf(stderr, "Client: bad close output %zu\n", i);
            free(close_outputs);
            if (!initial_msg) cJSON_Delete(msg.json);
            return 0;
        }
        close_outputs[i].amount_sats = (uint64_t)amt->valuedouble;
        close_outputs[i].script_pubkey_len = (size_t)wire_json_get_hex(
            item, "spk", close_outputs[i].script_pubkey, 34);
    }
    if (!initial_msg) cJSON_Delete(msg.json);

    /* Verify cooperative close outputs before signing.
       The client must receive at least its channel balance.  If the LSP
       short-changes the close outputs, the client refuses to sign and
       can force-close instead (using the pre-signed commitment TX). */
    if (ch && ch->local_amount > 0) {
        uint64_t my_balance = ch->local_amount;
        int found = 0;
        for (size_t i = 0; i < n_outputs; i++) {
            if (close_outputs[i].amount_sats >= my_balance) {
                found = 1;
                break;
            }
        }
        if (!found) {
            fprintf(stderr, "Client: REFUSING cooperative close — no output "
                    ">= channel balance %llu sats (force-close instead)\n",
                    (unsigned long long)my_balance);
            free(close_outputs);
            return 0;
        }
    }

    tx_buf_t close_unsigned;
    tx_buf_init(&close_unsigned, 256);
    unsigned char close_sighash[32];

    if (!factory_build_cooperative_close_unsigned(factory, &close_unsigned,
                                                   close_sighash,
                                                   close_outputs, n_outputs,
                                                   close_height)) {
        fprintf(stderr, "Client: build close unsigned failed\n");
        tx_buf_free(&close_unsigned);
        free(close_outputs);
        return 0;
    }
    free(close_outputs);

    musig_keyagg_t close_keyagg = factory->nodes[0].keyagg;
    musig_signing_session_t close_session;
    musig_session_init(&close_session, &close_keyagg, n_participants);

    secp256k1_musig_secnonce close_secnonce;
    secp256k1_musig_pubnonce close_pubnonce;

    unsigned char close_seckey[32];
    secp256k1_keypair_sec(ctx, close_seckey, keypair);
    if (!musig_generate_nonce(ctx, &close_secnonce, &close_pubnonce,
                               close_seckey, my_pubkey, &close_keyagg.cache)) {
        fprintf(stderr, "Client: close nonce gen failed\n");
        memset(close_seckey, 0, 32);
        tx_buf_free(&close_unsigned);
        return 0;
    }
    memset(close_seckey, 0, 32);

    unsigned char nonce_ser[66];
    musig_pubnonce_serialize(ctx, nonce_ser, &close_pubnonce);
    cJSON *nonce_msg = wire_build_close_nonce(nonce_ser);
    if (!wire_send(fd, MSG_CLOSE_NONCE, nonce_msg)) {
        fprintf(stderr, "Client: send CLOSE_NONCE failed\n");
        cJSON_Delete(nonce_msg);
        tx_buf_free(&close_unsigned);
        return 0;
    }
    cJSON_Delete(nonce_msg);

    /* Receive CLOSE_ALL_NONCES, skipping stray leaf-advance / revoke noise. */
    wire_msg_t all_nonces_msg;
    for (;;) {
        if (!wire_recv(fd, &all_nonces_msg) || check_msg_error(&all_nonces_msg)) {
            fprintf(stderr, "Client: expected CLOSE_ALL_NONCES\n");
            if (all_nonces_msg.json) cJSON_Delete(all_nonces_msg.json);
            tx_buf_free(&close_unsigned);
            return 0;
        }
        if (all_nonces_msg.msg_type == 0x50 ||          /* REVOKE_AND_ACK */
            all_nonces_msg.msg_type == MSG_LEAF_ADVANCE_DONE) {
            cJSON_Delete(all_nonces_msg.json);
            continue;
        }
        if (all_nonces_msg.msg_type == MSG_LEAF_ADVANCE_PROPOSE ||
            all_nonces_msg.msg_type == MSG_STATE_ADVANCE_PROPOSE) {
            uint32_t my_idx = UINT32_MAX;
            for (size_t p = 0; p < factory->n_participants; p++) {
                unsigned char a[33], b[33]; size_t la = 33, lb = 33;
                if (secp256k1_ec_pubkey_serialize(ctx, a, &la,
                                                    &factory->pubkeys[p],
                                                    SECP256K1_EC_COMPRESSED) &&
                    secp256k1_ec_pubkey_serialize(ctx, b, &lb,
                                                    my_pubkey,
                                                    SECP256K1_EC_COMPRESSED) &&
                    la == lb && memcmp(a, b, la) == 0) {
                    my_idx = (uint32_t)p;
                    break;
                }
            }
            int handled = 0;
            if (my_idx != UINT32_MAX) {
                handled = (all_nonces_msg.msg_type == MSG_LEAF_ADVANCE_PROPOSE)
                    ? client_handle_leaf_advance(fd, ctx, keypair, factory,
                                                  my_idx, &all_nonces_msg)
                    : client_handle_state_advance(fd, ctx, keypair, factory,
                                                    my_idx, &all_nonces_msg);
            }
            if (!handled) {
                cJSON_Delete(all_nonces_msg.json);
                tx_buf_free(&close_unsigned);
                return 0;
            }
            cJSON_Delete(all_nonces_msg.json);
            continue;
        }
        if (all_nonces_msg.msg_type != MSG_CLOSE_ALL_NONCES) {
            fprintf(stderr, "Client: expected CLOSE_ALL_NONCES, got 0x%02x\n",
                    all_nonces_msg.msg_type);
            cJSON_Delete(all_nonces_msg.json);
            tx_buf_free(&close_unsigned);
            return 0;
        }
        break;
    }

    {
        cJSON *nonces_arr2 = cJSON_GetObjectItem(all_nonces_msg.json, "nonces");
        if (!nonces_arr2 || !cJSON_IsArray(nonces_arr2)) {
            fprintf(stderr, "Client: malformed CLOSE_ALL_NONCES\n");
            cJSON_Delete(all_nonces_msg.json);
            tx_buf_free(&close_unsigned);
            return 0;
        }
        size_t n_nonces = (size_t)cJSON_GetArraySize(nonces_arr2);
        for (size_t i = 0; i < n_nonces; i++) {
            cJSON *hex_item = cJSON_GetArrayItem(nonces_arr2, (int)i);
            if (!hex_item || !cJSON_IsString(hex_item)) continue;
            unsigned char nbuf[66];
            if (hex_decode(hex_item->valuestring, nbuf, 66) != 66) continue;
            secp256k1_musig_pubnonce pn;
            if (!musig_pubnonce_parse(ctx, &pn, nbuf)) continue;
            musig_session_set_pubnonce(&close_session, i, &pn);
        }
    }
    cJSON_Delete(all_nonces_msg.json);

    if (!musig_session_finalize_nonces(ctx, &close_session, close_sighash, NULL, NULL)) {
        fprintf(stderr, "Client: close session finalize failed\n");
        tx_buf_free(&close_unsigned);
        return 0;
    }

    secp256k1_musig_partial_sig close_psig;
    if (!musig_create_partial_sig(ctx, &close_psig, &close_secnonce,
                                   keypair, &close_session)) {
        fprintf(stderr, "Client: close partial sig failed\n");
        tx_buf_free(&close_unsigned);
        return 0;
    }

    unsigned char psig_ser[32];
    musig_partial_sig_serialize(ctx, psig_ser, &close_psig);

    cJSON *psig_msg = wire_build_close_psig(psig_ser);
    if (!wire_send(fd, MSG_CLOSE_PSIG, psig_msg)) {
        fprintf(stderr, "Client: send CLOSE_PSIG failed\n");
        cJSON_Delete(psig_msg);
        tx_buf_free(&close_unsigned);
        return 0;
    }
    cJSON_Delete(psig_msg);

    /* Receive CLOSE_DONE */
    wire_msg_t done_msg;
    if (!wire_recv(fd, &done_msg) || check_msg_error(&done_msg) ||
        done_msg.msg_type != MSG_CLOSE_DONE) {
        fprintf(stderr, "Client: expected CLOSE_DONE\n");
        if (done_msg.json) cJSON_Delete(done_msg.json);
        tx_buf_free(&close_unsigned);
        return 0;
    }
    cJSON_Delete(done_msg.json);

    tx_buf_free(&close_unsigned);
    (void)got_propose;
    return 1;
}

/* --- Apply signed tree nodes from MSG_FACTORY_READY --- */

static int client_apply_factory_ready(factory_t *f, const cJSON *json) {
    if (!f || !json) return 0;
    cJSON *signed_txs = cJSON_GetObjectItem(json, "signed_txs");
    if (!signed_txs || !cJSON_IsArray(signed_txs)) return 0;

    int count = 0;
    int arr_size = cJSON_GetArraySize(signed_txs);
    for (int i = 0; i < arr_size; i++) {
        cJSON *item = cJSON_GetArrayItem(signed_txs, i);
        if (!item) continue;
        cJSON *idx_j = cJSON_GetObjectItem(item, "node_idx");
        cJSON *hex_j = cJSON_GetObjectItem(item, "tx_hex");
        if (!idx_j || !cJSON_IsNumber(idx_j)) continue;
        if (!hex_j || !cJSON_IsString(hex_j)) continue;

        size_t node_idx = (size_t)idx_j->valuedouble;
        if (node_idx >= f->n_nodes) continue;

        const char *hex = hex_j->valuestring;
        size_t hex_len = strlen(hex);
        if (hex_len < 2 || hex_len % 2 != 0) continue;
        size_t raw_len = hex_len / 2;

        /* Free existing signed_tx if any, then allocate and decode */
        tx_buf_free(&f->nodes[node_idx].signed_tx);
        tx_buf_init(&f->nodes[node_idx].signed_tx, raw_len);
        f->nodes[node_idx].signed_tx.len = raw_len;
        if (hex_decode(hex, f->nodes[node_idx].signed_tx.data, raw_len)
                != (int)raw_len) {
            f->nodes[node_idx].signed_tx.len = 0;
            continue;
        }
        f->nodes[node_idx].is_signed = 1;
        count++;
    }

    if (count > 0)
        printf("Client: applied %d signed tree nodes from FACTORY_READY\n", count);

    /* Parse signed distribution TX if present */
    cJSON *dist_hex_j = cJSON_GetObjectItem(json, "distribution_tx_hex");
    if (dist_hex_j && cJSON_IsString(dist_hex_j)) {
        const char *dhex = dist_hex_j->valuestring;
        size_t dlen = strlen(dhex);
        if (dlen >= 2 && dlen % 2 == 0) {
            size_t draw = dlen / 2;
            tx_buf_free(&f->dist_unsigned_tx);
            tx_buf_init(&f->dist_unsigned_tx, draw);
            f->dist_unsigned_tx.len = draw;
            if (hex_decode(dhex, f->dist_unsigned_tx.data, draw) == (int)draw) {
                f->dist_tx_ready = 2;  /* 2 = signed distribution TX */
                printf("Client: stored signed distribution TX (%zu bytes)\n", draw);
            } else {
                f->dist_unsigned_tx.len = 0;
            }
        }
    }

    return count;
}

/* --- Factory rotation (condensed factory creation without HELLO) --- */

int client_do_factory_rotation(int fd, secp256k1_context *ctx,
                                const secp256k1_keypair *keypair,
                                uint32_t my_index,
                                size_t n_participants,
                                const secp256k1_pubkey *all_pubkeys,
                                factory_t *factory_out,
                                channel_t *channel_out,
                                const wire_msg_t *initial_propose) {
    secp256k1_pubkey my_pubkey;
    secp256k1_keypair_pub(ctx, &my_pubkey, keypair);
    wire_msg_t msg;

    /* Parse FACTORY_PROPOSE from initial_propose */
    const cJSON *pj = initial_propose->json;
    cJSON *fv = cJSON_GetObjectItem(pj, "funding_vout");
    cJSON *fa = cJSON_GetObjectItem(pj, "funding_amount");
    cJSON *sb = cJSON_GetObjectItem(pj, "step_blocks");
    cJSON *sp = cJSON_GetObjectItem(pj, "states_per_layer");
    cJSON *ct = cJSON_GetObjectItem(pj, "cltv_timeout");
    cJSON *fp = cJSON_GetObjectItem(pj, "fee_per_tx");
    if (!fv || !fa || !sb || !sp || !ct || !fp) {
        fprintf(stderr, "Client %u: malformed FACTORY_PROPOSE in rotation\n", my_index);
        return 0;
    }

    unsigned char funding_txid[32];
    wire_json_get_hex(pj, "funding_txid", funding_txid, 32);
    reverse_bytes(funding_txid, 32);
    uint32_t funding_vout = (uint32_t)fv->valuedouble;
    uint64_t funding_amount = (uint64_t)fa->valuedouble;
    unsigned char funding_spk[34];
    size_t spk_len = (size_t)wire_json_get_hex(pj, "funding_spk", funding_spk, 34);
    uint16_t step_blocks = (uint16_t)sb->valuedouble;
    uint32_t states_per_layer = (uint32_t)sp->valuedouble;
    uint32_t cltv_timeout = (uint32_t)ct->valuedouble;
    uint64_t fee_per_tx = (uint64_t)fp->valuedouble;
    cJSON *arity_item = cJSON_GetObjectItem(pj, "leaf_arity");
    int rot_leaf_arity = (arity_item && cJSON_IsNumber(arity_item)) ? (int)arity_item->valuedouble : 2;
    uint8_t rot_level_arities[FACTORY_MAX_LEVELS];
    size_t rot_n_level_arity = 0;
    cJSON *rla_arr = cJSON_GetObjectItem(pj, "level_arity");
    if (rla_arr && cJSON_IsArray(rla_arr)) {
        int rla_n = cJSON_GetArraySize(rla_arr);
        for (int rli = 0; rli < rla_n && rli < FACTORY_MAX_LEVELS; rli++) {
            cJSON *rlai = cJSON_GetArrayItem(rla_arr, rli);
            if (rlai && cJSON_IsNumber(rlai))
                rot_level_arities[rot_n_level_arity++] = (uint8_t)rlai->valuedouble;
        }
    }
    cJSON *rsnr_item = cJSON_GetObjectItem(pj, "static_threshold_depth");
    uint32_t rot_static_threshold =
        (rsnr_item && cJSON_IsNumber(rsnr_item)) ? (uint32_t)rsnr_item->valuedouble : 0;

    /* Parse placement + economic mode (optional, backward-compatible) */
    cJSON *rpm_item = cJSON_GetObjectItem(pj, "placement_mode");
    int rot_placement = (rpm_item && cJSON_IsNumber(rpm_item)) ? (int)rpm_item->valuedouble : 0;
    cJSON *rem_item = cJSON_GetObjectItem(pj, "economic_mode");
    int rot_econ = (rem_item && cJSON_IsNumber(rem_item)) ? (int)rem_item->valuedouble : 0;

    /* Parse participant profiles (optional) */
    participant_profile_t rot_profiles[FACTORY_MAX_SIGNERS];
    memset(rot_profiles, 0, sizeof(rot_profiles));
    cJSON *rprof_arr = cJSON_GetObjectItem(pj, "profiles");
    if (rprof_arr && cJSON_IsArray(rprof_arr)) {
        int n_prof = cJSON_GetArraySize(rprof_arr);
        for (int rpi = 0; rpi < n_prof && rpi < FACTORY_MAX_SIGNERS; rpi++) {
            cJSON *rpe = cJSON_GetArrayItem(rprof_arr, rpi);
            if (!rpe) continue;
            cJSON *rv;
            rv = cJSON_GetObjectItem(rpe, "idx");
            if (rv && cJSON_IsNumber(rv)) rot_profiles[rpi].participant_idx = (uint32_t)rv->valuedouble;
            rv = cJSON_GetObjectItem(rpe, "contribution");
            if (rv && cJSON_IsNumber(rv)) rot_profiles[rpi].contribution_sats = (uint64_t)rv->valuedouble;
            rv = cJSON_GetObjectItem(rpe, "profit_bps");
            if (rv && cJSON_IsNumber(rv)) rot_profiles[rpi].profit_share_bps = (uint16_t)rv->valuedouble;
            rv = cJSON_GetObjectItem(rpe, "uptime");
            if (rv && cJSON_IsNumber(rv)) rot_profiles[rpi].uptime_score = (float)rv->valuedouble;
            rv = cJSON_GetObjectItem(rpe, "tz_bucket");
            if (rv && cJSON_IsNumber(rv)) rot_profiles[rpi].timezone_bucket = (uint8_t)rv->valuedouble;
        }
    }

    /* Parse per-client distribution amounts (optional, for rotation) */
    uint64_t rot_dist_amounts[FACTORY_MAX_SIGNERS];
    size_t rot_n_dist_amounts = 0;
    cJSON *rda_arr = cJSON_GetObjectItem(pj, "dist_amounts");
    if (rda_arr && cJSON_IsArray(rda_arr)) {
        int rda_n = cJSON_GetArraySize(rda_arr);
        for (int rdi = 0; rdi < rda_n && rdi < FACTORY_MAX_SIGNERS; rdi++) {
            cJSON *rda = cJSON_GetArrayItem(rda_arr, rdi);
            if (rda && cJSON_IsNumber(rda))
                rot_dist_amounts[rot_n_dist_amounts++] = (uint64_t)rda->valuedouble;
        }
    }

    /* Parse L-stock hashlock hashes (optional) */
    unsigned char (*rot_hashes)[32] = (unsigned char (*)[32])calloc(FACTORY_MAX_EPOCHS, 32);
    size_t rot_n_hashes = 0;
    cJSON *rlsh_arr = cJSON_GetObjectItem(pj, "l_stock_hashes");
    if (rot_hashes && rlsh_arr && cJSON_IsArray(rlsh_arr)) {
        int rlsh_n = cJSON_GetArraySize(rlsh_arr);
        for (int rhi = 0; rhi < rlsh_n && rhi < FACTORY_MAX_EPOCHS; rhi++) {
            cJSON *rh = cJSON_GetArrayItem(rlsh_arr, rhi);
            if (rh && cJSON_IsString(rh) &&
                hex_decode(rh->valuestring, rot_hashes[rot_n_hashes], 32) == 32)
                rot_n_hashes++;
        }
    }

    /* Build factory locally */
    factory_init_from_pubkeys(factory_out, ctx, all_pubkeys, n_participants,
                              step_blocks, states_per_layer);
    factory_out->cltv_timeout = cltv_timeout;
    factory_out->fee_per_tx = fee_per_tx;
    factory_out->placement_mode = (placement_mode_t)rot_placement;
    factory_out->economic_mode = (economic_mode_t)rot_econ;
    memcpy(factory_out->profiles, rot_profiles, sizeof(rot_profiles));
    if (rot_n_level_arity > 0)
        factory_set_level_arity(factory_out, rot_level_arities, rot_n_level_arity);
    else if (rot_leaf_arity == 1)
        factory_set_arity(factory_out, FACTORY_ARITY_1);
    else if (rot_leaf_arity == 3)
        factory_set_arity(factory_out, FACTORY_ARITY_PS);
    if (rot_static_threshold > 0)
        factory_set_static_near_root(factory_out, rot_static_threshold);
    if (rot_n_hashes > 0)
        factory_set_l_stock_hashes(factory_out, rot_hashes, rot_n_hashes);
    free(rot_hashes);
    factory_set_funding(factory_out, funding_txid, funding_vout, funding_amount,
                        funding_spk, spk_len);

    if (!factory_build_tree(factory_out)) {
        printf("Client %u: ROTATION BUILD_TREE FAILED spk=%zu amt=%llu\n", my_index, spk_len, (unsigned long long)funding_amount);
        fflush(stdout);
        return 0;
    }
    printf("Client %u: rotation tree OK (%zu nodes)\n", my_index, factory_out->n_nodes);
    fflush(stdout);
    if (!factory_sessions_init(factory_out)) {
        printf("Client %u: ROTATION SESSIONS_INIT FAILED\n", my_index);
        fflush(stdout);
        return 0;
    }

    /* Generate nonces */
    unsigned char my_seckey[32];
    secp256k1_keypair_sec(ctx, my_seckey, keypair);

    size_t my_node_count = 0;
    for (size_t i = 0; i < factory_out->n_nodes; i++)
        if (factory_find_signer_slot(factory_out, i, my_index) >= 0)
            my_node_count++;

    secp256k1_musig_secnonce *secnonces =
        (secp256k1_musig_secnonce *)calloc(my_node_count, sizeof(secp256k1_musig_secnonce));
    wire_bundle_entry_t *nonce_entries =
        (wire_bundle_entry_t *)calloc(my_node_count + 1, sizeof(wire_bundle_entry_t));
    if (my_node_count > 0 && (!secnonces || !nonce_entries)) {
        free(secnonces); free(nonce_entries);
        memset(my_seckey, 0, 32);
        return 0;
    }

    size_t nonce_count = 0;
    for (size_t i = 0; i < factory_out->n_nodes; i++) {
        int slot = factory_find_signer_slot(factory_out, i, my_index);
        if (slot < 0) continue;
        secp256k1_musig_pubnonce pubnonce;
        if (!musig_generate_nonce(ctx, &secnonces[nonce_count], &pubnonce,
                                   my_seckey, &my_pubkey,
                                   &factory_out->nodes[i].keyagg.cache)) {
            fprintf(stderr, "Client %u: rotation nonce gen failed\n", my_index);
            free(secnonces); free(nonce_entries);
            memset(my_seckey, 0, 32);
            return 0;
        }
        unsigned char nonce_ser[66];
        musig_pubnonce_serialize(ctx, nonce_ser, &pubnonce);
        nonce_entries[nonce_count].node_idx = (uint32_t)i;
        nonce_entries[nonce_count].signer_slot = (uint32_t)slot;
        memcpy(nonce_entries[nonce_count].data, nonce_ser, 66);
        nonce_entries[nonce_count].data_len = 66;
        nonce_count++;
    }

    /* Verify distribution amounts: if the LSP provided per-client dist_amounts,
       check that this client's allocation is at least its old channel balance.
       Prevents the LSP from silently reducing the client's distribution output
       during rotation (balance theft). */
    if (rot_n_dist_amounts > 0 && my_index >= 1) {
        size_t ci = my_index - 1;  /* client index in dist_amounts array */
        uint64_t offered = (ci < rot_n_dist_amounts) ? rot_dist_amounts[ci] : 0;
        uint64_t expected = channel_out->local_amount;  /* client's balance */
        if (offered < expected) {
            fprintf(stderr, "Client %u: REFUSING rotation — distribution amount "
                    "%llu < channel balance %llu (balance theft attempt)\n",
                    my_index, (unsigned long long)offered,
                    (unsigned long long)expected);
            return 0;
        }
    }

    /* Distribution TX: build unsigned TX and generate nonce (same as initial) */
    int rot_has_dist = 0;
    uint32_t rot_dist_node_idx = (uint32_t)factory_out->n_nodes;
    musig_signing_session_t rot_dist_session;
    secp256k1_musig_secnonce rot_dist_secnonce;
    memset(&rot_dist_session, 0, sizeof(rot_dist_session));
    {
        int dist_slot = factory_find_signer_slot(factory_out, 0, my_index);
        if (dist_slot >= 0 && factory_out->cltv_timeout > 0) {
            tx_output_t dist_outputs[FACTORY_MAX_SIGNERS + 1];
            size_t n_dist = factory_compute_distribution_outputs_balanced(
                factory_out, dist_outputs, FACTORY_MAX_SIGNERS + 1, 500,
                rot_n_dist_amounts > 0 ? rot_dist_amounts : NULL,
                rot_n_dist_amounts);
            if (n_dist > 0 &&
                factory_build_distribution_tx_unsigned(factory_out, dist_outputs,
                    n_dist, factory_out->cltv_timeout)) {
                secp256k1_musig_pubnonce dist_pub;
                if (musig_generate_nonce(ctx, &rot_dist_secnonce, &dist_pub,
                                          my_seckey, &my_pubkey,
                                          &factory_out->nodes[0].keyagg.cache)) {
                    musig_session_init(&rot_dist_session,
                                        &factory_out->nodes[0].keyagg,
                                        factory_out->n_participants);
                    musig_session_set_pubnonce(&rot_dist_session,
                                                (size_t)dist_slot, &dist_pub);
                    unsigned char dist_nonce_ser[66];
                    musig_pubnonce_serialize(ctx, dist_nonce_ser, &dist_pub);
                    nonce_entries[nonce_count].node_idx = rot_dist_node_idx;
                    nonce_entries[nonce_count].signer_slot = (uint32_t)dist_slot;
                    memcpy(nonce_entries[nonce_count].data, dist_nonce_ser, 66);
                    nonce_entries[nonce_count].data_len = 66;
                    nonce_count++;
                    rot_has_dist = 1;
                }
            }
        }
    }
    memset(my_seckey, 0, 32);

    /* Send NONCE_BUNDLE */
    cJSON *bundle = wire_build_nonce_bundle(nonce_entries, nonce_count);
    if (!wire_send(fd, MSG_NONCE_BUNDLE, bundle)) {
        cJSON_Delete(bundle); free(secnonces); free(nonce_entries); return 0;
    }
    cJSON_Delete(bundle);

    /* Receive ALL_NONCES */
    if (!wire_recv(fd, &msg) || check_msg_error(&msg) || msg.msg_type != MSG_ALL_NONCES) {
        if (msg.json) cJSON_Delete(msg.json);
        free(secnonces); free(nonce_entries); return 0;
    }
    if (!factory_sessions_init(factory_out)) {
        cJSON_Delete(msg.json); free(secnonces); free(nonce_entries); return 0;
    }
    {
        cJSON *nonces_arr = cJSON_GetObjectItem(msg.json, "nonces");
        size_t cap = (size_t)FACTORY_MAX_NODES * FACTORY_MAX_SIGNERS;
        wire_bundle_entry_t *all_entries = calloc(cap, sizeof(wire_bundle_entry_t));
        if (!all_entries) {
            cJSON_Delete(msg.json); free(secnonces); free(nonce_entries); return 0;
        }
        size_t n_all = wire_parse_bundle(nonces_arr, all_entries, cap, 66);
        for (size_t e = 0; e < n_all; e++) {
            secp256k1_musig_pubnonce pn;
            if (!musig_pubnonce_parse(ctx, &pn, all_entries[e].data)) continue;
            if (rot_has_dist && all_entries[e].node_idx == rot_dist_node_idx) {
                musig_session_set_pubnonce(&rot_dist_session,
                    all_entries[e].signer_slot, &pn);
            } else {
                factory_session_set_nonce(factory_out, all_entries[e].node_idx,
                                         all_entries[e].signer_slot, &pn);
            }
        }
        free(all_entries);
    }
    cJSON_Delete(msg.json);

    if (!factory_sessions_finalize(factory_out)) {
        free(secnonces); free(nonce_entries); return 0;
    }

    /* Finalize distribution TX signing session */
    if (rot_has_dist && factory_out->dist_tx_ready) {
        if (!musig_session_finalize_nonces(ctx, &rot_dist_session,
                                            factory_out->dist_sighash, NULL, NULL)) {
            fprintf(stderr, "Client %u: rotation dist TX session finalize failed\n", my_index);
            rot_has_dist = 0;
        }
    }

    /* Create and send partial sigs */
    {
        wire_bundle_entry_t *psig_entries =
            (wire_bundle_entry_t *)calloc(my_node_count + 1, sizeof(wire_bundle_entry_t));
        size_t psig_count = 0, snidx = 0;
        for (size_t i = 0; i < factory_out->n_nodes; i++) {
            int slot = factory_find_signer_slot(factory_out, i, my_index);
            if (slot < 0) continue;
            secp256k1_musig_partial_sig psig;
            if (!musig_create_partial_sig(ctx, &psig, &secnonces[snidx],
                                           keypair, &factory_out->nodes[i].signing_session)) {
                free(psig_entries); free(secnonces); free(nonce_entries); return 0;
            }
            unsigned char psig_ser[32];
            musig_partial_sig_serialize(ctx, psig_ser, &psig);
            psig_entries[psig_count].node_idx = (uint32_t)i;
            psig_entries[psig_count].signer_slot = (uint32_t)slot;
            memcpy(psig_entries[psig_count].data, psig_ser, 32);
            psig_entries[psig_count].data_len = 32;
            psig_count++; snidx++;
        }

        /* Distribution TX partial sig */
        if (rot_has_dist && factory_out->dist_tx_ready) {
            secp256k1_musig_partial_sig dist_psig;
            if (musig_create_partial_sig(ctx, &dist_psig,
                                          &rot_dist_secnonce, keypair,
                                          &rot_dist_session)) {
                unsigned char dist_psig_ser[32];
                musig_partial_sig_serialize(ctx, dist_psig_ser, &dist_psig);
                int dist_slot = factory_find_signer_slot(factory_out, 0, my_index);
                psig_entries[psig_count].node_idx = rot_dist_node_idx;
                psig_entries[psig_count].signer_slot = (uint32_t)(dist_slot >= 0 ? dist_slot : 0);
                memcpy(psig_entries[psig_count].data, dist_psig_ser, 32);
                psig_entries[psig_count].data_len = 32;
                psig_count++;
            }
        }

        bundle = wire_build_psig_bundle(psig_entries, psig_count);
        int ok = wire_send(fd, MSG_PSIG_BUNDLE, bundle);
        cJSON_Delete(bundle); free(psig_entries);
        if (!ok) { free(secnonces); free(nonce_entries); return 0; }
    }

    /* Receive FACTORY_READY */
    if (!wire_recv(fd, &msg) || check_msg_error(&msg) || msg.msg_type != MSG_FACTORY_READY) {
        if (msg.json) cJSON_Delete(msg.json);
        free(secnonces); free(nonce_entries); return 0;
    }
    client_apply_factory_ready(factory_out, msg.json);
    cJSON_Delete(msg.json);

    /* Basepoint exchange: receive LSP's basepoints */
    secp256k1_pubkey rot_lsp_pay_bp, rot_lsp_delay_bp, rot_lsp_revoc_bp;
    secp256k1_pubkey rot_lsp_htlc_bp, rot_lsp_first_pcp, rot_lsp_second_pcp;
    if (!wire_recv(fd, &msg) || check_msg_error(&msg) || msg.msg_type != MSG_CHANNEL_BASEPOINTS) {
        if (msg.json) cJSON_Delete(msg.json);
        free(secnonces); free(nonce_entries); return 0;
    }
    {
        uint32_t bp_ch_id;
        if (!wire_parse_channel_basepoints(msg.json, &bp_ch_id, ctx,
                &rot_lsp_pay_bp, &rot_lsp_delay_bp, &rot_lsp_revoc_bp,
                &rot_lsp_htlc_bp, &rot_lsp_first_pcp, &rot_lsp_second_pcp)) {
            cJSON_Delete(msg.json); free(secnonces); free(nonce_entries); return 0;
        }
        cJSON_Delete(msg.json);
    }
    /* Pre-generated per-commitment secrets for rotation (cn=0 and cn=1) */
    unsigned char rot_pcs0[32], rot_pcs1[32];
    memset(rot_pcs0, 0, 32);
    memset(rot_pcs1, 0, 32);

    /* Send client's basepoints to LSP (random secrets) */
    unsigned char rot_bp_ps[32], rot_bp_ds[32], rot_bp_rs[32], rot_bp_hs[32];
    {
        secp256k1_pubkey cpay, cdel, crev, chtlc;
        if (!channel_read_random_bytes(rot_bp_ps, 32) || !channel_read_random_bytes(rot_bp_ds, 32) ||
            !channel_read_random_bytes(rot_bp_rs, 32) || !channel_read_random_bytes(rot_bp_hs, 32)) {
            fprintf(stderr, "Client %u: random rotation basepoint generation failed\n", my_index);
            free(secnonces); free(nonce_entries); return 0;
        }
        if (!secp256k1_ec_pubkey_create(ctx, &cpay, rot_bp_ps) ||
            !secp256k1_ec_pubkey_create(ctx, &cdel, rot_bp_ds) ||
            !secp256k1_ec_pubkey_create(ctx, &crev, rot_bp_rs) ||
            !secp256k1_ec_pubkey_create(ctx, &chtlc, rot_bp_hs)) {
            fprintf(stderr, "Client %u: rotation basepoint pubkey derivation failed\n", my_index);
            free(secnonces); free(nonce_entries); return 0;
        }
        /* Generate random per-commitment secrets for cn=0 and cn=1 (outer-scoped rot_pcs0, rot_pcs1) */
        if (!channel_read_random_bytes(rot_pcs0, 32) ||
            !channel_read_random_bytes(rot_pcs1, 32)) {
            fprintf(stderr, "Client %u: random rotation PCS generation failed\n", my_index);
            free(secnonces); free(nonce_entries); return 0;
        }
        secp256k1_pubkey cfpcp, cspcp;
        if (!secp256k1_ec_pubkey_create(ctx, &cfpcp, rot_pcs0) ||
            !secp256k1_ec_pubkey_create(ctx, &cspcp, rot_pcs1)) {
            fprintf(stderr, "Client %u: rotation PCS pubkey derivation failed\n", my_index);
            free(secnonces); free(nonce_entries); return 0;
        }

        uint32_t client_idx = my_index - 1;
        cJSON *bp_msg = wire_build_channel_basepoints(
            client_idx, ctx, &cpay, &cdel, &crev, &chtlc, &cfpcp, &cspcp);
        if (!wire_send(fd, MSG_CHANNEL_BASEPOINTS, bp_msg)) {
            cJSON_Delete(bp_msg); free(secnonces); free(nonce_entries); return 0;
        }
        cJSON_Delete(bp_msg);
    }
    printf("Client %u: rotation basepoint exchange complete\n", my_index);

    /* Receive CHANNEL_READY */
    if (!wire_recv(fd, &msg) || check_msg_error(&msg) || msg.msg_type != MSG_CHANNEL_READY) {
        if (msg.json) cJSON_Delete(msg.json);
        free(secnonces); free(nonce_entries); return 0;
    }
    uint64_t rot_bal_local = 0, rot_bal_remote = 0;
    {
        uint32_t channel_id;
        wire_parse_channel_ready(msg.json, &channel_id, &rot_bal_local, &rot_bal_remote);
        cJSON_Delete(msg.json);
        printf("Client %u: rotation channel %u ready (local=%llu, remote=%llu)\n",
               my_index, channel_id, (unsigned long long)rot_bal_local, (unsigned long long)rot_bal_remote);
    }

    /* Receive SCID_ASSIGN for route hints */
    if (!wire_recv(fd, &msg) || check_msg_error(&msg) ||
        msg.msg_type != MSG_SCID_ASSIGN) {
        if (msg.json) cJSON_Delete(msg.json);
        free(secnonces); free(nonce_entries); return 0;
    }
    {
        uint32_t scid_ch; uint64_t scid; uint32_t fb, fp; uint16_t cd;
        if (wire_parse_scid_assign(msg.json, &scid_ch, &scid, &fb, &fp, &cd)) {
            printf("Client %u: SCID=%016llx fee_base=%u fee_ppm=%u cltv=%u\n",
                   my_index, (unsigned long long)scid, fb, fp, cd);
            g_routing_fee_ppm = fp;
        }
        cJSON_Delete(msg.json);
    }

    /* Save old channel balance before client_init_channel overwrites it.
       Used below to verify the LSP carried the balance correctly. */
    uint64_t old_local_balance = channel_out->local_amount;

    /* Initialize client-side channel */
    if (!client_init_channel(channel_out, ctx, factory_out, keypair, my_index,
                              &rot_lsp_pay_bp, &rot_lsp_delay_bp,
                              &rot_lsp_revoc_bp, &rot_lsp_htlc_bp,
                              rot_bp_ps, rot_bp_ds, rot_bp_rs, rot_bp_hs, NULL)) {
        free(secnonces); free(nonce_entries); return 0;
    }
    memset(rot_bp_ps, 0, 32); memset(rot_bp_ds, 0, 32);
    memset(rot_bp_rs, 0, 32); memset(rot_bp_hs, 0, 32);

    /* Use LSP-provided initial amounts from CHANNEL_READY. */
    if (rot_bal_local > 0 || rot_bal_remote > 0) {
        channel_out->local_amount  = rot_bal_remote / 1000;
        channel_out->remote_amount = rot_bal_local  / 1000;
    }

    /* Verify the LSP carried the client's balance into the new factory.
       The client's local_amount in the new channel must be >= the old
       channel's local_amount.  A decrease without a corresponding payment
       means the LSP is stealing sats during rotation. */
    if (old_local_balance > 0 &&
        channel_out->local_amount < old_local_balance) {
        fprintf(stderr, "Client %u: REFUSING rotation — new channel balance "
                "%llu < old balance %llu (balance not carried)\n",
                my_index,
                (unsigned long long)channel_out->local_amount,
                (unsigned long long)old_local_balance);
        free(secnonces); free(nonce_entries); return 0;
    }

    /* Override local_pcs[0,1] with pre-generated secrets + store LSP PCPs */
    channel_set_local_pcs(channel_out, 0, rot_pcs0);
    channel_set_local_pcs(channel_out, 1, rot_pcs1);
    memset(rot_pcs0, 0, 32);
    memset(rot_pcs1, 0, 32);
    channel_set_remote_pcp(channel_out, 0, &rot_lsp_first_pcp);
    channel_set_remote_pcp(channel_out, 1, &rot_lsp_second_pcp);

    /* Nonce exchange */
    if (!wire_recv(fd, &msg) || check_msg_error(&msg) || msg.msg_type != MSG_CHANNEL_NONCES) {
        if (msg.json) cJSON_Delete(msg.json);
        free(secnonces); free(nonce_entries); return 0;
    }
    {
        uint32_t nonce_ch_id;
        unsigned char lsp_nonces[MUSIG_NONCE_POOL_MAX][66];
        size_t lsp_nonce_count;
        if (!wire_parse_channel_nonces(msg.json, &nonce_ch_id,
                                         lsp_nonces, MUSIG_NONCE_POOL_MAX,
                                         &lsp_nonce_count)) {
            cJSON_Delete(msg.json); free(secnonces); free(nonce_entries); return 0;
        }
        cJSON_Delete(msg.json);

        if (!channel_init_nonce_pool(channel_out, lsp_nonce_count)) {
            free(secnonces); free(nonce_entries); return 0;
        }

        size_t my_nonce_count = channel_out->local_nonce_pool.count;
        unsigned char (*my_pubnonces_ser)[66] =
            (unsigned char (*)[66])calloc(my_nonce_count, 66);
        for (size_t i = 0; i < my_nonce_count; i++)
            musig_pubnonce_serialize(ctx, my_pubnonces_ser[i],
                &channel_out->local_nonce_pool.nonces[i].pubnonce);

        cJSON *nonce_reply = wire_build_channel_nonces(
            0, (const unsigned char (*)[66])my_pubnonces_ser, my_nonce_count);
        int ok = wire_send(fd, MSG_CHANNEL_NONCES, nonce_reply);
        cJSON_Delete(nonce_reply); free(my_pubnonces_ser);
        if (!ok) { free(secnonces); free(nonce_entries); return 0; }

        channel_set_remote_pubnonces(channel_out,
            (const unsigned char (*)[66])lsp_nonces, lsp_nonce_count);
    }

    free(secnonces);
    free(nonce_entries);
    printf("Client %u: factory rotation complete\n", my_index);
    return 1;
}

/* --- Main ceremony (factory creation + optional channels + close) --- */

int client_run_with_channels(secp256k1_context *ctx,
                              const secp256k1_keypair *keypair,
                              const char *host, int port,
                              client_channel_cb_t channel_cb,
                              void *user_data,
                              client_verify_funding_fn verify_funding,
                              void *verify_ctx) {
    secp256k1_pubkey my_pubkey;
    secp256k1_keypair_pub(ctx, &my_pubkey, keypair);

    /* Connect to LSP */
    int fd = wire_connect(host, port);
    if (fd < 0) {
        fprintf(stderr, "Client: connect failed\n");
        return 0;
    }
    wire_set_peer_label(fd, "lsp");

    /* Encrypted transport handshake (NK if server pubkey pinned, NN fallback) */
    int hs_ok;
    if (g_nk_server_pubkey_set) {
        hs_ok = wire_noise_handshake_nk_initiator(fd, ctx, &g_nk_server_pubkey);
    } else {
        fprintf(stderr, "Client: WARNING — no --lsp-pubkey, using unauthenticated NN handshake\n");
        hs_ok = wire_noise_handshake_initiator(fd, ctx);
    }
    if (!hs_ok) {
        fprintf(stderr, "Client: noise handshake failed\n");
        wire_close(fd);
        return 0;
    }

    /* Send HELLO */
    cJSON *hello = wire_build_hello(ctx, &my_pubkey);
    wire_hello_set_slot_hint(hello, g_slot_hint);
    if (!wire_send(fd, MSG_HELLO, hello)) {
        fprintf(stderr, "Client: send HELLO failed\n");
        cJSON_Delete(hello);
        wire_close(fd);
        return 0;
    }
    cJSON_Delete(hello);

    /* Receive HELLO_ACK */
    wire_msg_t msg;
    if (!wire_recv(fd, &msg) || check_msg_error(&msg) || msg.msg_type != MSG_HELLO_ACK) {
        fprintf(stderr, "Client: expected HELLO_ACK\n");
        if (msg.json) cJSON_Delete(msg.json);
        wire_close(fd);
        return 0;
    }

    cJSON *pi_item = cJSON_GetObjectItem(msg.json, "participant_index");
    cJSON *all_pk_arr = cJSON_GetObjectItem(msg.json, "all_pubkeys");
    if (!pi_item || !cJSON_IsNumber(pi_item) ||
        !all_pk_arr || !cJSON_IsArray(all_pk_arr)) {
        fprintf(stderr, "Client: malformed HELLO_ACK\n");
        cJSON_Delete(msg.json);
        wire_close(fd);
        return 0;
    }
    uint32_t my_index = (uint32_t)pi_item->valuedouble;
    size_t n_participants = (size_t)cJSON_GetArraySize(all_pk_arr);
    if (n_participants < 2 || n_participants > FACTORY_MAX_SIGNERS) {
        fprintf(stderr, "Client: bad participant count %zu\n", n_participants);
        cJSON_Delete(msg.json);
        wire_close(fd);
        return 0;
    }

    secp256k1_pubkey all_pubkeys[FACTORY_MAX_SIGNERS];
    for (size_t i = 0; i < n_participants; i++) {
        cJSON *pk_hex = cJSON_GetArrayItem(all_pk_arr, (int)i);
        if (!pk_hex || !cJSON_IsString(pk_hex)) {
            fprintf(stderr, "Client: bad pubkey entry %zu\n", i);
            cJSON_Delete(msg.json);
            wire_close(fd);
            return 0;
        }
        unsigned char pk_buf[33];
        if (hex_decode(pk_hex->valuestring, pk_buf, 33) != 33 ||
            !secp256k1_ec_pubkey_parse(ctx, &all_pubkeys[i], pk_buf, 33)) {
            fprintf(stderr, "Client: invalid pubkey %zu\n", i);
            cJSON_Delete(msg.json);
            wire_close(fd);
            return 0;
        }
    }
    cJSON_Delete(msg.json);

    /* Verify our pubkey is at the assigned participant index.  If the LSP
       put a different key at our index, we'd sign a tree where our slot
       is controlled by someone else. */
    if (my_index >= n_participants) {
        fprintf(stderr, "Client: participant_index %u out of range (%zu)\n",
                my_index, n_participants);
        wire_close(fd);
        return 0;
    }
    {
        unsigned char my_ser[33], their_ser[33];
        size_t my_len = 33, their_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, my_ser, &my_len, &my_pubkey,
                                       SECP256K1_EC_COMPRESSED);
        secp256k1_ec_pubkey_serialize(ctx, their_ser, &their_len,
                                       &all_pubkeys[my_index],
                                       SECP256K1_EC_COMPRESSED);
        if (memcmp(my_ser, their_ser, 33) != 0) {
            fprintf(stderr, "Client: REFUSING — pubkey at index %u does not "
                    "match our key (identity mismatch)\n", my_index);
            wire_close(fd);
            return 0;
        }
    }

    /* Receive FACTORY_PROPOSE — disable timeout since LSP may be waiting for
       on-chain funding confirmation (up to ~10 min on signet/testnet) */
    if (!wire_recv_handle_ping(fd, &msg, 0) || check_msg_error(&msg) || msg.msg_type != MSG_FACTORY_PROPOSE) {
        fprintf(stderr, "Client: expected FACTORY_PROPOSE\n");
        if (msg.json) cJSON_Delete(msg.json);
        wire_close(fd);
        return 0;
    }

    /* Parse proposal */
    {
        cJSON *fv = cJSON_GetObjectItem(msg.json, "funding_vout");
        cJSON *fa = cJSON_GetObjectItem(msg.json, "funding_amount");
        cJSON *sb = cJSON_GetObjectItem(msg.json, "step_blocks");
        cJSON *sp = cJSON_GetObjectItem(msg.json, "states_per_layer");
        cJSON *ct = cJSON_GetObjectItem(msg.json, "cltv_timeout");
        cJSON *fp = cJSON_GetObjectItem(msg.json, "fee_per_tx");
        if (!fv || !cJSON_IsNumber(fv) || !fa || !cJSON_IsNumber(fa) ||
            !sb || !cJSON_IsNumber(sb) || !sp || !cJSON_IsNumber(sp) ||
            !ct || !cJSON_IsNumber(ct) || !fp || !cJSON_IsNumber(fp)) {
            fprintf(stderr, "Client: malformed FACTORY_PROPOSE\n");
            cJSON_Delete(msg.json);
            wire_close(fd);
            return 0;
        }
    }

    unsigned char funding_txid[32];
    wire_json_get_hex(msg.json, "funding_txid", funding_txid, 32);
    reverse_bytes(funding_txid, 32);
    cJSON *fv_item = cJSON_GetObjectItem(msg.json, "funding_vout");
    cJSON *fa_item = cJSON_GetObjectItem(msg.json, "funding_amount");
    cJSON *sb_item = cJSON_GetObjectItem(msg.json, "step_blocks");
    cJSON *spl_item = cJSON_GetObjectItem(msg.json, "states_per_layer");
    cJSON *ct_item = cJSON_GetObjectItem(msg.json, "cltv_timeout");
    cJSON *fpt_item = cJSON_GetObjectItem(msg.json, "fee_per_tx");
    if (!fv_item || !fa_item || !sb_item || !spl_item || !ct_item || !fpt_item) {
        fprintf(stderr, "Client: FACTORY_PROPOSE missing required fields\n");
        cJSON_Delete(msg.json);
        return 0;
    }
    uint32_t funding_vout = (uint32_t)fv_item->valuedouble;
    uint64_t funding_amount = (uint64_t)fa_item->valuedouble;
    unsigned char funding_spk[34];
    size_t spk_len = (size_t)wire_json_get_hex(msg.json, "funding_spk", funding_spk, 34);
    uint16_t step_blocks = (uint16_t)sb_item->valuedouble;
    uint32_t states_per_layer = (uint32_t)spl_item->valuedouble;
    uint32_t cltv_timeout = (uint32_t)ct_item->valuedouble;
    uint64_t fee_per_tx = (uint64_t)fpt_item->valuedouble;
    cJSON *arity_item = cJSON_GetObjectItem(msg.json, "leaf_arity");
    int leaf_arity = (arity_item && cJSON_IsNumber(arity_item)) ? (int)arity_item->valuedouble : 2;

    /* Parse variable level_arity array (4A), fall back to leaf_arity */
    uint8_t level_arities[FACTORY_MAX_LEVELS];
    size_t n_level_arity = 0;
    cJSON *la_arr = cJSON_GetObjectItem(msg.json, "level_arity");
    if (la_arr && cJSON_IsArray(la_arr)) {
        int la_n = cJSON_GetArraySize(la_arr);
        for (int li = 0; li < la_n && li < FACTORY_MAX_LEVELS; li++) {
            cJSON *lai = cJSON_GetArrayItem(la_arr, li);
            if (lai && cJSON_IsNumber(lai))
                level_arities[n_level_arity++] = (uint8_t)lai->valuedouble;
        }
    }

    /* Parse static-near-root threshold (Phase 3 mixed-arity).  Backward-
       compatible: missing field = 0 (no static layers).  Without this the
       client and LSP build divergent trees when the operator configured
       --static-near-root N. */
    cJSON *snr_item = cJSON_GetObjectItem(msg.json, "static_threshold_depth");
    uint32_t static_threshold_depth =
        (snr_item && cJSON_IsNumber(snr_item)) ? (uint32_t)snr_item->valuedouble : 0;

    /* PS k² sub-factory arity (Gap E followup, t/1242).  Backward-
       compatible: missing field = k=1 (legacy 1-client-per-PS-leaf).
       Without this the client builds a divergent tree when the LSP
       configured --ps-subfactory-arity K>1 — same divergence mode that
       broke --static-near-root before its FACTORY_PROPOSE field landed. */
    cJSON *psa_item = cJSON_GetObjectItem(msg.json, "ps_subfactory_arity");
    uint32_t ps_subfactory_arity_in =
        (psa_item && cJSON_IsNumber(psa_item)) ? (uint32_t)psa_item->valuedouble : 0;

    /* Parse placement + economic mode (optional, backward-compatible) */
    cJSON *pm_item = cJSON_GetObjectItem(msg.json, "placement_mode");
    int placement_mode = (pm_item && cJSON_IsNumber(pm_item)) ? (int)pm_item->valuedouble : 0;
    cJSON *em_item = cJSON_GetObjectItem(msg.json, "economic_mode");
    int economic_mode = (em_item && cJSON_IsNumber(em_item)) ? (int)em_item->valuedouble : 0;

    /* Parse participant profiles (optional) */
    participant_profile_t profiles[FACTORY_MAX_SIGNERS];
    memset(profiles, 0, sizeof(profiles));
    cJSON *prof_arr = cJSON_GetObjectItem(msg.json, "profiles");
    if (prof_arr && cJSON_IsArray(prof_arr)) {
        int n_prof = cJSON_GetArraySize(prof_arr);
        for (int pi = 0; pi < n_prof && pi < FACTORY_MAX_SIGNERS; pi++) {
            cJSON *pe = cJSON_GetArrayItem(prof_arr, pi);
            if (!pe) continue;
            cJSON *v;
            v = cJSON_GetObjectItem(pe, "idx");
            if (v && cJSON_IsNumber(v)) profiles[pi].participant_idx = (uint32_t)v->valuedouble;
            v = cJSON_GetObjectItem(pe, "contribution");
            if (v && cJSON_IsNumber(v)) profiles[pi].contribution_sats = (uint64_t)v->valuedouble;
            v = cJSON_GetObjectItem(pe, "profit_bps");
            if (v && cJSON_IsNumber(v)) profiles[pi].profit_share_bps = (uint16_t)v->valuedouble;
            v = cJSON_GetObjectItem(pe, "uptime");
            if (v && cJSON_IsNumber(v)) profiles[pi].uptime_score = (float)v->valuedouble;
            v = cJSON_GetObjectItem(pe, "tz_bucket");
            if (v && cJSON_IsNumber(v)) profiles[pi].timezone_bucket = (uint8_t)v->valuedouble;
        }
    }
    /* Parse per-client distribution amounts (optional, for rotation) */
    uint64_t init_dist_amounts[FACTORY_MAX_SIGNERS];
    size_t init_n_dist_amounts = 0;
    {
        cJSON *ida_arr = cJSON_GetObjectItem(msg.json, "dist_amounts");
        if (ida_arr && cJSON_IsArray(ida_arr)) {
            int ida_n = cJSON_GetArraySize(ida_arr);
            for (int idi = 0; idi < ida_n && idi < FACTORY_MAX_SIGNERS; idi++) {
                cJSON *ida = cJSON_GetArrayItem(ida_arr, idi);
                if (ida && cJSON_IsNumber(ida))
                    init_dist_amounts[init_n_dist_amounts++] = (uint64_t)ida->valuedouble;
            }
        }
    }

    /* Parse L-stock hashlock hashes (optional — present when LSP has
       revocation secrets for burn TX enforcement). */
    unsigned char (*parsed_l_stock_hashes)[32] = (unsigned char (*)[32])calloc(FACTORY_MAX_EPOCHS, 32);
    size_t n_parsed_hashes = 0;
    cJSON *lsh_arr = cJSON_GetObjectItem(msg.json, "l_stock_hashes");
    if (parsed_l_stock_hashes && lsh_arr && cJSON_IsArray(lsh_arr)) {
        int lsh_n = cJSON_GetArraySize(lsh_arr);
        for (int hi = 0; hi < lsh_n && hi < FACTORY_MAX_EPOCHS; hi++) {
            cJSON *h = cJSON_GetArrayItem(lsh_arr, hi);
            if (h && cJSON_IsString(h) &&
                hex_decode(h->valuestring, parsed_l_stock_hashes[n_parsed_hashes], 32) == 32)
                n_parsed_hashes++;
        }
    }

    cJSON_Delete(msg.json);

    /* Verify funding TX on-chain before signing anything.  If the caller
       provided a verify_funding callback (e.g. backed by RPC or BIP 158),
       query the chain for the actual output amount.  An adversarial LSP could
       claim a larger funding_amount than actually exists on-chain; without
       this check the client would sign a tree against phantom funds. */
    if (verify_funding) {
        if (!verify_funding(funding_txid, funding_vout, funding_amount,
                            verify_ctx)) {
            fprintf(stderr, "Client: funding TX verification FAILED — "
                    "on-chain output does not match claimed %llu sats. "
                    "Refusing to sign factory tree.\n",
                    (unsigned long long)funding_amount);
            client_send_error(fd, "funding_tx_verification_failed");
            wire_close(fd);
            return 0;
        }
    } else {
        fprintf(stderr, "Client: WARNING — funding TX not verified on-chain "
                "(no --rpcuser or --light-client). Trusting LSP claim of "
                "%llu sats.\n", (unsigned long long)funding_amount);
    }

    /* Build factory locally (heap — factory_t is ~3MB) */
    factory_t *factory = calloc(1, sizeof(factory_t));
    if (!factory) return 0;
    factory_init_from_pubkeys(factory, ctx, all_pubkeys, n_participants,
                              step_blocks, states_per_layer);
    factory->cltv_timeout = cltv_timeout;
    factory->fee_per_tx = fee_per_tx;
    factory->placement_mode = (placement_mode_t)placement_mode;
    factory->economic_mode = (economic_mode_t)economic_mode;
    memcpy(factory->profiles, profiles, sizeof(profiles));

    /* Log the economic terms the client is about to sign.  The client
       should review these before proceeding — once the tree is signed,
       the profit split is locked for this factory's lifetime. */
    {
        const char *econ_names[] = {"lsp-takes-all", "profit-shared"};
        const char *econ_str = (economic_mode >= 0 && economic_mode <= 1)
                               ? econ_names[economic_mode] : "unknown";
        printf("Client %u: factory terms — economic_mode=%s",
               my_index, econ_str);
        uint16_t my_bps = 0;
        if (my_index >= 1 && my_index < FACTORY_MAX_SIGNERS)
            my_bps = profiles[my_index].profit_share_bps;
        if (economic_mode == 1)
            printf(", my profit_share=%u bps (%.2f%%)", my_bps, my_bps / 100.0);
        printf(", funding=%llu sats, %zu participants\n",
               (unsigned long long)funding_amount, n_participants);

        /* Enforce minimum profit share if the client set --min-profit-bps */
        if (g_min_profit_bps > 0 && my_bps < g_min_profit_bps) {
            fprintf(stderr, "Client %u: REFUSING — profit_share %u bps < "
                    "minimum %u bps (use --min-profit-bps to adjust)\n",
                    my_index, my_bps, g_min_profit_bps);
            free(factory);
            client_send_error(fd, "profit_share_too_low");
            wire_close(fd);
            return 0;
        }
    }

    if (n_level_arity > 0)
        factory_set_level_arity(factory, level_arities, n_level_arity);
    else if (leaf_arity == 1)
        factory_set_arity(factory, FACTORY_ARITY_1);
    else if (leaf_arity == 3)
        factory_set_arity(factory, FACTORY_ARITY_PS);
    /* Apply static-near-root after the arity restore: it recomputes the
       DW counter shape based on f->level_arity / f->leaf_arity. */
    if (static_threshold_depth > 0)
        factory_set_static_near_root(factory, static_threshold_depth);
    /* Apply ps_subfactory_arity after the arity restore — the setter
       short-circuits when leaf_arity != FACTORY_ARITY_PS, so arity must
       come first.  k>1 reshapes the tree to the canonical k² PS shape
       from t/1242 (k sub-factories of k clients each per leaf). */
    if (ps_subfactory_arity_in > 1)
        factory_set_ps_subfactory_arity(factory, ps_subfactory_arity_in);
    if (n_parsed_hashes > 0)
        factory_set_l_stock_hashes(factory, parsed_l_stock_hashes, n_parsed_hashes);
    free(parsed_l_stock_hashes);
    factory_set_funding(factory, funding_txid, funding_vout, funding_amount,
                        funding_spk, spk_len);

    if (!factory_build_tree(factory)) {
        fprintf(stderr, "Client: factory_build_tree failed\n");
        client_send_error(fd, "factory_build_tree failed");
        factory_free(factory);
        free(factory);
        wire_close(fd);
        return 0;
    }

    /* Initialize signing sessions */
    if (!factory_sessions_init(factory)) {
        fprintf(stderr, "Client: factory_sessions_init failed\n");
        client_send_error(fd, "factory_sessions_init failed");
        factory_free(factory);
        free(factory);
        wire_close(fd);
        return 0;
    }

    /* Generate nonces via pool */
    unsigned char my_seckey[32];
    secp256k1_keypair_sec(ctx, my_seckey, keypair);

    size_t my_node_count = factory_count_nodes_for_participant(factory, my_index);

    /* Pre-generate nonce pool */
    musig_nonce_pool_t my_pool;
    if (!musig_nonce_pool_generate(ctx, &my_pool, my_node_count + 1,
                                    my_seckey, &my_pubkey, NULL)) {
        fprintf(stderr, "Client: nonce pool generation failed\n");
        client_send_error(fd, "nonce pool generation failed");
        memset(my_seckey, 0, 32);
        factory_free(factory);
        free(factory);
        wire_close(fd);
        return 0;
    }
    memset(my_seckey, 0, 32);

    secp256k1_musig_secnonce *my_secnonce_ptrs[FACTORY_MAX_NODES];
    wire_bundle_entry_t *nonce_entries =
        (wire_bundle_entry_t *)calloc(my_node_count + 1, sizeof(wire_bundle_entry_t));

    if (my_node_count > 0 && !nonce_entries) {
        fprintf(stderr, "Client: alloc failed\n");
        client_send_error(fd, "allocation failed");
        free(nonce_entries);
        factory_free(factory);
        free(factory);
        wire_close(fd);
        return 0;
    }

    size_t nonce_count = 0;
    for (size_t i = 0; i < factory->n_nodes; i++) {
        int slot = factory_find_signer_slot(factory, i, my_index);
        if (slot < 0) continue;

        secp256k1_musig_secnonce *sec;
        secp256k1_musig_pubnonce pubnonce;
        if (!musig_nonce_pool_next(&my_pool, &sec, &pubnonce)) {
            fprintf(stderr, "Client: nonce pool exhausted at node %zu\n", i);
            goto fail;
        }
        my_secnonce_ptrs[nonce_count] = sec;

        unsigned char nonce_ser[66];
        musig_pubnonce_serialize(ctx, nonce_ser, &pubnonce);

        nonce_entries[nonce_count].node_idx = (uint32_t)i;
        nonce_entries[nonce_count].signer_slot = (uint32_t)slot;
        memcpy(nonce_entries[nonce_count].data, nonce_ser, 66);
        nonce_entries[nonce_count].data_len = 66;
        nonce_count++;
    }

    /* Distribution TX: build unsigned TX and generate nonce.
       The distribution TX uses the same keyagg as node 0 (root). */
    int client_has_dist = 0;
    uint32_t client_dist_node_idx = (uint32_t)factory->n_nodes;
    musig_signing_session_t client_dist_session;
    secp256k1_musig_secnonce client_dist_secnonce;
    memset(&client_dist_session, 0, sizeof(client_dist_session));
    {
        int dist_slot = factory_find_signer_slot(factory, 0, my_index);
        if (dist_slot >= 0 && factory->cltv_timeout > 0) {
            tx_output_t dist_outputs[FACTORY_MAX_SIGNERS + 1];
            size_t n_dist = factory_compute_distribution_outputs_balanced(
                factory, dist_outputs, FACTORY_MAX_SIGNERS + 1, 500,
                init_n_dist_amounts > 0 ? init_dist_amounts : NULL,
                init_n_dist_amounts);
            if (n_dist > 0 &&
                factory_build_distribution_tx_unsigned(factory, dist_outputs,
                    n_dist, factory->cltv_timeout)) {
                /* Generate nonce for distribution TX */
                secp256k1_musig_secnonce *dist_sec;
                secp256k1_musig_pubnonce dist_pub;
                if (musig_nonce_pool_next(&my_pool, &dist_sec, &dist_pub)) {
                    client_dist_secnonce = *dist_sec;
                    musig_session_init(&client_dist_session,
                                        &factory->nodes[0].keyagg,
                                        factory->n_participants);
                    musig_session_set_pubnonce(&client_dist_session,
                                                (size_t)dist_slot, &dist_pub);

                    unsigned char dist_nonce_ser[66];
                    musig_pubnonce_serialize(ctx, dist_nonce_ser, &dist_pub);
                    nonce_entries[nonce_count].node_idx = client_dist_node_idx;
                    nonce_entries[nonce_count].signer_slot = (uint32_t)dist_slot;
                    memcpy(nonce_entries[nonce_count].data, dist_nonce_ser, 66);
                    nonce_entries[nonce_count].data_len = 66;
                    nonce_count++;
                    client_has_dist = 1;
                }
            }
        }
    }

    /* Send NONCE_BUNDLE */
    {
        cJSON *bundle = wire_build_nonce_bundle(nonce_entries, nonce_count);
        if (!wire_send(fd, MSG_NONCE_BUNDLE, bundle)) {
            fprintf(stderr, "Client: send NONCE_BUNDLE failed\n");
            cJSON_Delete(bundle);
            goto fail;
        }
        cJSON_Delete(bundle);
    }

    /* Receive ALL_NONCES */
    if (!wire_recv(fd, &msg) || check_msg_error(&msg) || msg.msg_type != MSG_ALL_NONCES) {
        fprintf(stderr, "Client: expected ALL_NONCES\n");
        if (msg.json) cJSON_Delete(msg.json);
        goto fail;
    }

    if (!factory_sessions_init(factory)) {
        fprintf(stderr, "Client: re-init sessions failed\n");
        cJSON_Delete(msg.json);
        goto fail;
    }

    {
        cJSON *nonces_arr = cJSON_GetObjectItem(msg.json, "nonces");
        size_t cap = (size_t)FACTORY_MAX_NODES * FACTORY_MAX_SIGNERS;
        wire_bundle_entry_t *all_entries = calloc(cap, sizeof(wire_bundle_entry_t));
        if (!all_entries) {
            cJSON_Delete(msg.json);
            goto fail;
        }
        size_t n_all = wire_parse_bundle(nonces_arr, all_entries, cap, 66);

        for (size_t e = 0; e < n_all; e++) {
            secp256k1_musig_pubnonce pn;
            if (!musig_pubnonce_parse(ctx, &pn, all_entries[e].data)) {
                fprintf(stderr, "Client: bad pubnonce in ALL_NONCES\n");
                free(all_entries);
                cJSON_Delete(msg.json);
                goto fail;
            }
            if (client_has_dist && all_entries[e].node_idx == client_dist_node_idx) {
                musig_session_set_pubnonce(&client_dist_session,
                    all_entries[e].signer_slot, &pn);
            } else if (!factory_session_set_nonce(factory, all_entries[e].node_idx,
                                            all_entries[e].signer_slot, &pn)) {
                fprintf(stderr, "Client: set nonce failed node %u slot %u\n",
                        all_entries[e].node_idx, all_entries[e].signer_slot);
                free(all_entries);
                cJSON_Delete(msg.json);
                goto fail;
            }
        }
        free(all_entries);
    }
    cJSON_Delete(msg.json);

    /* Finalize nonces */
    if (!factory_sessions_finalize(factory)) {
        fprintf(stderr, "Client: factory_sessions_finalize failed\n");
        goto fail;
    }

    /* Finalize distribution TX signing session */
    if (client_has_dist && factory->dist_tx_ready) {
        if (!musig_session_finalize_nonces(ctx, &client_dist_session,
                                            factory->dist_sighash, NULL, NULL)) {
            fprintf(stderr, "Client: dist TX session finalize failed\n");
            client_has_dist = 0;
        }
    }

    /* Create partial sigs */
    {
        wire_bundle_entry_t *psig_entries =
            (wire_bundle_entry_t *)calloc(my_node_count + 1, sizeof(wire_bundle_entry_t));
        if (my_node_count > 0 && !psig_entries) {
            fprintf(stderr, "Client: alloc failed\n");
            goto fail;
        }
        size_t psig_count = 0;

        size_t psig_nonce_idx = 0;
        for (size_t i = 0; i < factory->n_nodes; i++) {
            int slot = factory_find_signer_slot(factory, i, my_index);
            if (slot < 0) continue;

            secp256k1_musig_partial_sig psig;
            if (!musig_create_partial_sig(ctx, &psig, my_secnonce_ptrs[psig_nonce_idx],
                                           keypair, &factory->nodes[i].signing_session)) {
                fprintf(stderr, "Client: partial sig failed node %zu\n", i);
                free(psig_entries);
                goto fail;
            }

            unsigned char psig_ser[32];
            musig_partial_sig_serialize(ctx, psig_ser, &psig);

            psig_entries[psig_count].node_idx = (uint32_t)i;
            psig_entries[psig_count].signer_slot = (uint32_t)slot;
            memcpy(psig_entries[psig_count].data, psig_ser, 32);
            psig_entries[psig_count].data_len = 32;
            psig_count++;
            psig_nonce_idx++;
        }

        /* Distribution TX partial sig */
        if (client_has_dist && factory->dist_tx_ready) {
            secp256k1_musig_partial_sig dist_psig;
            if (musig_create_partial_sig(ctx, &dist_psig,
                                          &client_dist_secnonce, keypair,
                                          &client_dist_session)) {
                unsigned char dist_psig_ser[32];
                musig_partial_sig_serialize(ctx, dist_psig_ser, &dist_psig);
                int dist_slot = factory_find_signer_slot(factory, 0, my_index);
                psig_entries[psig_count].node_idx = client_dist_node_idx;
                psig_entries[psig_count].signer_slot = (uint32_t)(dist_slot >= 0 ? dist_slot : 0);
                memcpy(psig_entries[psig_count].data, dist_psig_ser, 32);
                psig_entries[psig_count].data_len = 32;
                psig_count++;
            }
        }

        cJSON *bundle = wire_build_psig_bundle(psig_entries, psig_count);
        if (!wire_send(fd, MSG_PSIG_BUNDLE, bundle)) {
            fprintf(stderr, "Client: send PSIG_BUNDLE failed\n");
            cJSON_Delete(bundle);
            free(psig_entries);
            goto fail;
        }
        cJSON_Delete(bundle);
        free(psig_entries);
    }

    /* Receive FACTORY_READY */
    if (!wire_recv(fd, &msg) || check_msg_error(&msg) || msg.msg_type != MSG_FACTORY_READY) {
        fprintf(stderr, "Client: expected FACTORY_READY\n");
        if (msg.json) cJSON_Delete(msg.json);
        goto fail;
    }
    client_apply_factory_ready(factory, msg.json);
    cJSON_Delete(msg.json);

    /* Log expected distribution amount.  The distribution TX is a fallback
       (used only if the factory expires without cooperative rotation), so
       this is informational.  The hard enforcement is in
       client_do_factory_rotation where the client REFUSES to sign if
       dist_amounts[my_index-1] < channel balance. */
    if (factory->dist_tx_ready && n_participants > 1 && my_index >= 1) {
        uint64_t expected_dist_sats = funding_amount / n_participants;
        printf("Client %u: distribution TX received — expected share "
               "~%llu sats (equal split of %llu / %zu participants)\n",
               my_index, (unsigned long long)expected_dist_sats,
               (unsigned long long)funding_amount, n_participants);
    }

    printf("Client %u: factory creation complete!\n", my_index);

    /* === Channel Operations Phase === */
    if (channel_cb) {
        /* Basepoint exchange: receive LSP's basepoints */
        secp256k1_pubkey lsp_pay_bp, lsp_delay_bp, lsp_revoc_bp, lsp_htlc_bp;
        secp256k1_pubkey lsp_first_pcp, lsp_second_pcp;
        if (!wire_recv(fd, &msg) || check_msg_error(&msg) ||
            msg.msg_type != MSG_CHANNEL_BASEPOINTS) {
            fprintf(stderr, "Client %u: expected CHANNEL_BASEPOINTS from LSP\n", my_index);
            if (msg.json) cJSON_Delete(msg.json);
            goto fail;
        }
        {
            uint32_t bp_ch_id;
            if (!wire_parse_channel_basepoints(msg.json, &bp_ch_id, ctx,
                    &lsp_pay_bp, &lsp_delay_bp, &lsp_revoc_bp,
                    &lsp_htlc_bp, &lsp_first_pcp, &lsp_second_pcp)) {
                fprintf(stderr, "Client %u: failed to parse LSP basepoints\n", my_index);
                cJSON_Delete(msg.json);
                goto fail;
            }
            cJSON_Delete(msg.json);
        }

        /* Pre-generated per-commitment secrets for cn=0 and cn=1 (before channel_init) */
        unsigned char pcs_secret0[32], pcs_secret1[32];
        memset(pcs_secret0, 0, 32);
        memset(pcs_secret1, 0, 32);

        /* Send client's basepoints to LSP (random secrets) */
        unsigned char bp_ps[32], bp_ds[32], bp_rs[32], bp_hs[32];
        {
            secp256k1_pubkey client_pay_bp, client_delay_bp, client_revoc_bp, client_htlc_bp;
            if (!channel_read_random_bytes(bp_ps, 32) || !channel_read_random_bytes(bp_ds, 32) ||
                !channel_read_random_bytes(bp_rs, 32) || !channel_read_random_bytes(bp_hs, 32)) {
                fprintf(stderr, "Client %u: random basepoint generation failed\n", my_index);
                goto fail;
            }
            if (!secp256k1_ec_pubkey_create(ctx, &client_pay_bp, bp_ps) ||
                !secp256k1_ec_pubkey_create(ctx, &client_delay_bp, bp_ds) ||
                !secp256k1_ec_pubkey_create(ctx, &client_revoc_bp, bp_rs) ||
                !secp256k1_ec_pubkey_create(ctx, &client_htlc_bp, bp_hs)) {
                fprintf(stderr, "Client %u: basepoint pubkey derivation failed\n", my_index);
                goto fail;
            }

            /* Generate random per-commitment secrets for cn=0 and cn=1.
               We generate them before channel_init so we can send the points,
               then override local_pcs[0,1] after channel_init.
               pcs_secret0, pcs_secret1 declared in outer scope. */
            if (!channel_read_random_bytes(pcs_secret0, 32) ||
                !channel_read_random_bytes(pcs_secret1, 32)) {
                fprintf(stderr, "Client %u: random PCS generation failed\n", my_index);
                goto fail;
            }
            secp256k1_pubkey client_first_pcp, client_second_pcp;
            if (!secp256k1_ec_pubkey_create(ctx, &client_first_pcp, pcs_secret0) ||
                !secp256k1_ec_pubkey_create(ctx, &client_second_pcp, pcs_secret1)) {
                fprintf(stderr, "Client %u: PCS pubkey derivation failed\n", my_index);
                goto fail;
            }

            uint32_t client_idx = my_index - 1;
            cJSON *bp_msg = wire_build_channel_basepoints(
                client_idx, ctx,
                &client_pay_bp, &client_delay_bp, &client_revoc_bp,
                &client_htlc_bp, &client_first_pcp, &client_second_pcp);
            if (!wire_send(fd, MSG_CHANNEL_BASEPOINTS, bp_msg)) {
                fprintf(stderr, "Client %u: send CHANNEL_BASEPOINTS failed\n", my_index);
                cJSON_Delete(bp_msg);
                memset(pcs_secret0, 0, 32);
                memset(pcs_secret1, 0, 32);
                memset(bp_ps, 0, 32); memset(bp_ds, 0, 32);
                memset(bp_rs, 0, 32); memset(bp_hs, 0, 32);
                goto fail;
            }
            cJSON_Delete(bp_msg);
        }
        printf("Client %u: basepoint exchange complete\n", my_index);

        /* Receive CHANNEL_READY */
        if (!wire_recv(fd, &msg) || check_msg_error(&msg) ||
            msg.msg_type != MSG_CHANNEL_READY) {
            fprintf(stderr, "Client %u: expected CHANNEL_READY\n", my_index);
            if (msg.json) cJSON_Delete(msg.json);
            goto fail;
        }

        uint32_t channel_id;
        uint64_t bal_local, bal_remote;
        wire_parse_channel_ready(msg.json, &channel_id, &bal_local, &bal_remote);
        cJSON_Delete(msg.json);

        printf("Client %u: channel %u ready (local=%llu msat, remote=%llu msat)\n",
               my_index, channel_id,
               (unsigned long long)bal_local, (unsigned long long)bal_remote);

        /* Receive SCID_ASSIGN for route hints */
        if (!wire_recv(fd, &msg) || check_msg_error(&msg) ||
            msg.msg_type != MSG_SCID_ASSIGN) {
            fprintf(stderr, "Client %u: expected SCID_ASSIGN\n", my_index);
            if (msg.json) cJSON_Delete(msg.json);
            goto fail;
        }
        {
            uint32_t scid_ch; uint64_t scid; uint32_t fb, fp; uint16_t cd;
            if (wire_parse_scid_assign(msg.json, &scid_ch, &scid, &fb, &fp, &cd)) {
                printf("Client %u: SCID=%016llx fee_base=%u fee_ppm=%u cltv=%u\n",
                       my_index, (unsigned long long)scid, fb, fp, cd);
                g_routing_fee_ppm = fp;
            }
            cJSON_Delete(msg.json);
        }

        /* Initialize client-side channel */
        channel_t channel;
        if (!client_init_channel(&channel, ctx, factory, keypair, my_index,
                                  &lsp_pay_bp, &lsp_delay_bp,
                                  &lsp_revoc_bp, &lsp_htlc_bp,
                                  bp_ps, bp_ds, bp_rs, bp_hs, NULL)) {
            fprintf(stderr, "Client %u: channel init failed\n", my_index);
            goto fail;
        }
        memset(bp_ps, 0, 32); memset(bp_ds, 0, 32);
        memset(bp_rs, 0, 32); memset(bp_hs, 0, 32);

        /* Use LSP-provided initial amounts from CHANNEL_READY.
           The LSP computes these with its own fee estimator (which may differ
           from the client's static default).  Trusting the LSP's split ensures
           both sides build identical commitment transactions. */
        if (bal_local > 0 || bal_remote > 0) {
            channel.local_amount  = bal_remote / 1000;  /* client balance = LSP remote */
            channel.remote_amount = bal_local  / 1000;  /* LSP balance   = LSP local  */
        }

        /* Override local_pcs[0,1] with the pre-generated secrets we already sent */
        channel_set_local_pcs(&channel, 0, pcs_secret0);
        channel_set_local_pcs(&channel, 1, pcs_secret1);
        memset(pcs_secret0, 0, 32);
        memset(pcs_secret1, 0, 32);

        /* Store LSP's first and second per-commitment points */
        channel_set_remote_pcp(&channel, 0, &lsp_first_pcp);
        channel_set_remote_pcp(&channel, 1, &lsp_second_pcp);

        /* Phase 12: Nonce exchange for commitment signing */
        /* Receive LSP's pubnonces */
        if (!wire_recv(fd, &msg) || check_msg_error(&msg) ||
            msg.msg_type != MSG_CHANNEL_NONCES) {
            fprintf(stderr, "Client %u: expected CHANNEL_NONCES from LSP\n", my_index);
            if (msg.json) cJSON_Delete(msg.json);
            goto fail;
        }
        {
            uint32_t nonce_ch_id;
            unsigned char lsp_nonces[MUSIG_NONCE_POOL_MAX][66];
            size_t lsp_nonce_count;
            if (!wire_parse_channel_nonces(msg.json, &nonce_ch_id,
                                             lsp_nonces, MUSIG_NONCE_POOL_MAX,
                                             &lsp_nonce_count)) {
                fprintf(stderr, "Client %u: failed to parse LSP nonces\n", my_index);
                cJSON_Delete(msg.json);
                goto fail;
            }
            cJSON_Delete(msg.json);

            /* Initialize client's nonce pool */
            if (!channel_init_nonce_pool(&channel, lsp_nonce_count)) {
                fprintf(stderr, "Client %u: nonce pool init failed\n", my_index);
                goto fail;
            }

            /* Send client's pubnonces back to LSP */
            size_t my_nonce_count = channel.local_nonce_pool.count;
            unsigned char (*my_pubnonces_ser)[66] =
                (unsigned char (*)[66])calloc(my_nonce_count, 66);
            if (!my_pubnonces_ser) {
                fprintf(stderr, "Client %u: alloc failed\n", my_index);
                goto fail;
            }
            for (size_t i = 0; i < my_nonce_count; i++) {
                musig_pubnonce_serialize(ctx,
                    my_pubnonces_ser[i],
                    &channel.local_nonce_pool.nonces[i].pubnonce);
            }

            cJSON *nonce_reply = wire_build_channel_nonces(
                channel_id,
                (const unsigned char (*)[66])my_pubnonces_ser,
                my_nonce_count);
            if (!wire_send(fd, MSG_CHANNEL_NONCES, nonce_reply)) {
                fprintf(stderr, "Client %u: send CHANNEL_NONCES failed\n", my_index);
                cJSON_Delete(nonce_reply);
                free(my_pubnonces_ser);
                goto fail;
            }
            cJSON_Delete(nonce_reply);
            free(my_pubnonces_ser);

            /* Store LSP's pubnonces */
            channel_set_remote_pubnonces(&channel,
                (const unsigned char (*)[66])lsp_nonces, lsp_nonce_count);
        }

        printf("Client %u: nonce exchange complete (%zu nonces)\n",
               my_index, channel.remote_nonce_count);

        /* Call the channel callback */
        int cb_ret = channel_cb(fd, &channel, my_index, ctx, keypair,
                                 factory, n_participants, user_data);
        if (cb_ret == 2) {
            /* Callback already handled close ceremony */
            goto done;
        }
        if (cb_ret == 0) {
            goto fail;
        }
    }

    /* === Cooperative Close Ceremony === */
    if (!client_do_close_ceremony(fd, ctx, keypair, &my_pubkey,
                                    factory, n_participants, NULL, 0,
                                    NULL)) {
        goto fail;
    }

    printf("Client %u: cooperative close complete!\n", my_index);

done:
    free(nonce_entries);
    factory_free(factory);
    free(factory);
    wire_close(fd);
    return 1;

fail:
    free(nonce_entries);
    factory_free(factory);
    free(factory);
    wire_close(fd);
    return 0;
}

int client_run_reconnect(secp256k1_context *ctx,
                           const secp256k1_keypair *keypair,
                           const char *host, int port,
                           persist_t *db,
                           client_channel_cb_t channel_cb,
                           void *user_data) {
    if (!ctx || !keypair || !db) return 0;

    secp256k1_pubkey my_pubkey;
    secp256k1_keypair_pub(ctx, &my_pubkey, keypair);

    /* 1. Load factory from DB (heap — factory_t is ~3MB) */
    factory_t *factory = calloc(1, sizeof(factory_t));
    if (!factory) return 0;
    if (!persist_load_factory(db, 0, factory, ctx)) {
        fprintf(stderr, "Client reconnect: failed to load factory from DB\n");
        free(factory);
        return 0;
    }

    /* 2. Determine my_index by matching pubkey against factory->pubkeys[] */
    uint32_t my_index = 0;
    {
        unsigned char my_ser[33], cmp_ser[33];
        size_t len1 = 33, len2 = 33;
        secp256k1_ec_pubkey_serialize(ctx, my_ser, &len1, &my_pubkey,
                                       SECP256K1_EC_COMPRESSED);
        for (size_t i = 0; i < factory->n_participants; i++) {
            len2 = 33;
            secp256k1_ec_pubkey_serialize(ctx, cmp_ser, &len2,
                                           &factory->pubkeys[i],
                                           SECP256K1_EC_COMPRESSED);
            if (memcmp(my_ser, cmp_ser, 33) == 0) {
                my_index = (uint32_t)i;
                break;
            }
        }
        if (my_index == 0) {
            fprintf(stderr, "Client reconnect: pubkey not found in factory\n");
            factory_free(factory);
            free(factory);
            return 0;
        }
    }

    size_t n_participants = factory->n_participants;

    /* 3. Connect to LSP */
    int fd = wire_connect(host, port);
    if (fd < 0) {
        fprintf(stderr, "Client reconnect: connect failed\n");
        factory_free(factory);
        free(factory);
        return 0;
    }
    wire_set_peer_label(fd, "lsp");

    /* Encrypted transport handshake (NK if server pubkey pinned) */
    int reconn_hs_ok;
    if (g_nk_server_pubkey_set)
        reconn_hs_ok = wire_noise_handshake_nk_initiator(fd, ctx, &g_nk_server_pubkey);
    else
        reconn_hs_ok = wire_noise_handshake_initiator(fd, ctx);
    if (!reconn_hs_ok) {
        fprintf(stderr, "Client reconnect: noise handshake failed\n");
        wire_close(fd);
        factory_free(factory);
        free(factory);
        return 0;
    }

    /* 4. Load persisted channel state to get commitment_number */
    uint32_t client_idx = my_index - 1;  /* 0-based client index */
    uint64_t local_amount = 0, remote_amount = 0, commitment_number = 0;
    persist_load_channel_state(db, client_idx, &local_amount, &remote_amount,
                                 &commitment_number);

    /* 5. Send MSG_RECONNECT */
    {
        cJSON *reconn = wire_build_reconnect(ctx, &my_pubkey, commitment_number);
        if (!wire_send(fd, MSG_RECONNECT, reconn)) {
            fprintf(stderr, "Client reconnect: send MSG_RECONNECT failed\n");
            cJSON_Delete(reconn);
            wire_close(fd);
            factory_free(factory); free(factory);
            return 0;
        }
        cJSON_Delete(reconn);
    }

    /* 6. Load basepoints from persistence */
    unsigned char local_secs[4][32];
    unsigned char remote_bps[4][33];
    if (!persist_load_basepoints(db, client_idx, local_secs, remote_bps)) {
        fprintf(stderr, "Client reconnect: no basepoints in DB for channel %u\n", client_idx);
        wire_close(fd);
        factory_free(factory);
        free(factory);
        return 0;
    }

    secp256k1_pubkey reconn_lsp_pay_bp, reconn_lsp_delay_bp, reconn_lsp_revoc_bp, reconn_lsp_htlc_bp;
    if (!secp256k1_ec_pubkey_parse(ctx, &reconn_lsp_pay_bp, remote_bps[0], 33) ||
        !secp256k1_ec_pubkey_parse(ctx, &reconn_lsp_delay_bp, remote_bps[1], 33) ||
        !secp256k1_ec_pubkey_parse(ctx, &reconn_lsp_revoc_bp, remote_bps[2], 33) ||
        !secp256k1_ec_pubkey_parse(ctx, &reconn_lsp_htlc_bp, remote_bps[3], 33)) {
        fprintf(stderr, "Client reconnect: failed to parse remote basepoints\n");
        wire_close(fd);
        factory_free(factory);
        free(factory);
        return 0;
    }

    channel_t channel;
    if (!client_init_channel(&channel, ctx, factory, keypair, my_index,
                              &reconn_lsp_pay_bp, &reconn_lsp_delay_bp,
                              &reconn_lsp_revoc_bp, &reconn_lsp_htlc_bp,
                              local_secs[0], local_secs[1], local_secs[2], local_secs[3], NULL)) {
        fprintf(stderr, "Client reconnect: channel init failed\n");
        memset(local_secs, 0, sizeof(local_secs));
        wire_close(fd);
        factory_free(factory);
        free(factory);
        return 0;
    }
    memset(local_secs, 0, sizeof(local_secs));

    /* 7. Overwrite channel state with persisted values */
    if (local_amount > 0 || remote_amount > 0) {
        channel.local_amount = local_amount;
        channel.remote_amount = remote_amount;
        channel.commitment_number = commitment_number;

        /* Restore local per-commitment secrets from DB.  These MUST match
           the per-commitment points the LSP has stored as our remote PCPs,
           otherwise commitment signature verification fails post-reconnect. */
        if (db) {
            size_t pcs_max = (size_t)(commitment_number + 2);
            unsigned char (*pcs_arr)[32] = calloc(pcs_max, 32);
            if (pcs_arr) {
                size_t pcs_loaded = 0;
                persist_load_local_pcs(db, 0, pcs_arr, pcs_max, &pcs_loaded);
                for (uint64_t cn = 0; cn < pcs_max; cn++) {
                    /* Check if entry was loaded (non-zero) */
                    int nonzero = 0;
                    for (int j = 0; j < 32; j++)
                        if (pcs_arr[cn][j]) { nonzero = 1; break; }
                    if (nonzero)
                        channel_set_local_pcs(&channel, cn, pcs_arr[cn]);
                }
                memset(pcs_arr, 0, pcs_max * 32);
                free(pcs_arr);
            }
        }

        /* Display any persisted in-flight HTLCs for user visibility */
        if (db) {
            htlc_t loaded_htlcs[16];
            size_t n_loaded = persist_load_htlcs(db, client_idx,
                                                   loaded_htlcs, 16);
            if (n_loaded > 0) {
                printf("Client reconnect: %zu persisted HTLC(s) from DB:\n",
                       n_loaded);
                for (size_t hi = 0; hi < n_loaded; hi++) {
                    printf("  HTLC #%llu: %llu sats (%s, %s)\n",
                           (unsigned long long)loaded_htlcs[hi].id,
                           (unsigned long long)loaded_htlcs[hi].amount_sats,
                           loaded_htlcs[hi].direction == HTLC_OFFERED
                               ? "offered" : "received",
                           loaded_htlcs[hi].state == HTLC_STATE_ACTIVE
                               ? "active"
                               : loaded_htlcs[hi].state == HTLC_STATE_FULFILLED
                                   ? "fulfilled" : "failed");
                }
            }
        }

        /* Generate random PCS only for commitment numbers not restored from DB */
        for (uint64_t cn = channel.n_local_pcs; cn <= commitment_number + 1; cn++)
            channel_generate_local_pcs(&channel, cn);

        /* Restore remote per-commitment points from DB so the channel
           can verify commitment signatures after reconnect. */
        if (db) {
            unsigned char pcp_ser[33];
            secp256k1_pubkey pcp;
            if (persist_load_remote_pcp(db, 0, commitment_number, pcp_ser) &&
                secp256k1_ec_pubkey_parse(ctx, &pcp, pcp_ser, 33))
                channel_set_remote_pcp(&channel, commitment_number, &pcp);
            if (persist_load_remote_pcp(db, 0, commitment_number + 1, pcp_ser) &&
                secp256k1_ec_pubkey_parse(ctx, &pcp, pcp_ser, 33))
                channel_set_remote_pcp(&channel, commitment_number + 1, &pcp);
        }
    }

    /* 7b. Restore latest commitment TX signature for force-close capability */
    if (db) {
        uint64_t sig_cn = 0;
        unsigned char sig64[64];
        if (persist_load_commitment_sig(db, client_idx, &sig_cn, sig64,
                                         NULL, NULL, 0) &&
            sig_cn == commitment_number) {
            memcpy(channel.latest_commitment_sig, sig64, 64);
            channel.has_latest_commitment_sig = 1;
        }
        memset(sig64, 0, 64);
    }

    /* 8. Nonce exchange — LSP sends CHANNEL_NONCES before RECONNECT_ACK */
    /* Receive LSP's pubnonces */
    {
        wire_msg_t msg;
        if (!wire_recv(fd, &msg) || msg.msg_type != MSG_CHANNEL_NONCES) {
            fprintf(stderr, "Client reconnect: expected CHANNEL_NONCES from LSP\n");
            if (msg.json) cJSON_Delete(msg.json);
            wire_close(fd);
            factory_free(factory); free(factory);
            return 0;
        }

        uint32_t nonce_ch_id;
        unsigned char lsp_nonces[MUSIG_NONCE_POOL_MAX][66];
        size_t lsp_nonce_count;
        if (!wire_parse_channel_nonces(msg.json, &nonce_ch_id,
                                         lsp_nonces, MUSIG_NONCE_POOL_MAX,
                                         &lsp_nonce_count)) {
            fprintf(stderr, "Client reconnect: failed to parse LSP nonces\n");
            cJSON_Delete(msg.json);
            wire_close(fd);
            factory_free(factory); free(factory);
            return 0;
        }
        cJSON_Delete(msg.json);

        /* Init client nonce pool */
        if (!channel_init_nonce_pool(&channel, lsp_nonce_count)) {
            fprintf(stderr, "Client reconnect: nonce pool init failed\n");
            wire_close(fd);
            factory_free(factory); free(factory);
            return 0;
        }

        /* Send client's pubnonces */
        size_t my_nonce_count = channel.local_nonce_pool.count;
        unsigned char (*my_pubnonces_ser)[66] =
            (unsigned char (*)[66])calloc(my_nonce_count, 66);
        if (!my_pubnonces_ser) {
            wire_close(fd);
            factory_free(factory); free(factory);
            return 0;
        }
        for (size_t i = 0; i < my_nonce_count; i++) {
            musig_pubnonce_serialize(ctx,
                my_pubnonces_ser[i],
                &channel.local_nonce_pool.nonces[i].pubnonce);
        }

        cJSON *nonce_reply = wire_build_channel_nonces(
            client_idx,
            (const unsigned char (*)[66])my_pubnonces_ser,
            my_nonce_count);
        if (!wire_send(fd, MSG_CHANNEL_NONCES, nonce_reply)) {
            fprintf(stderr, "Client reconnect: send CHANNEL_NONCES failed\n");
            cJSON_Delete(nonce_reply);
            free(my_pubnonces_ser);
            wire_close(fd);
            factory_free(factory); free(factory);
            return 0;
        }
        cJSON_Delete(nonce_reply);
        free(my_pubnonces_ser);

        /* Store LSP's pubnonces */
        channel_set_remote_pubnonces(&channel,
            (const unsigned char (*)[66])lsp_nonces, lsp_nonce_count);
    }

    printf("Client %u: nonce re-exchange complete (%zu nonces)\n",
           my_index, channel.remote_nonce_count);

    /* 9. Recv MSG_RECONNECT_ACK (sent by LSP after nonce exchange).
       Fix 5: LSP may send a pending COMMITMENT_SIGNED before RECONNECT_ACK
       if a CS was in-flight when the client disconnected. Handle it inline. */
    {
        wire_msg_t msg;
        if (!wire_recv(fd, &msg)) {
            fprintf(stderr, "Client reconnect: recv failed expecting RECONNECT_ACK\n");
            wire_close(fd);
            factory_free(factory); free(factory);
            return 0;
        }
        if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
            /* LSP retransmitting a pending CS -- handle it before RECONNECT_ACK */
            client_handle_commitment_signed(fd, &channel, ctx, &msg);
            cJSON_Delete(msg.json);
            /* Now read the actual RECONNECT_ACK */
            if (!wire_recv(fd, &msg)) {
                fprintf(stderr, "Client reconnect: recv failed after CS retransmit\n");
                wire_close(fd);
                factory_free(factory); free(factory);
                return 0;
            }
        }
        if (msg.msg_type != MSG_RECONNECT_ACK) {
            fprintf(stderr, "Client reconnect: expected RECONNECT_ACK, got 0x%02x\n",
                    msg.msg_type);
            if (msg.json) cJSON_Delete(msg.json);
            wire_close(fd);
            factory_free(factory); free(factory);
            return 0;
        }

        uint32_t ack_channel_id;
        uint64_t ack_local, ack_remote, ack_commit;
        if (!wire_parse_reconnect_ack(msg.json, &ack_channel_id,
                                        &ack_local, &ack_remote, &ack_commit)) {
            fprintf(stderr, "Client reconnect: failed to parse RECONNECT_ACK\n");
            cJSON_Delete(msg.json);
            wire_close(fd);
            factory_free(factory); free(factory);
            return 0;
        }
        cJSON_Delete(msg.json);

        /* Verify commitment_number matches (Gap 2B: client-side) */
        if (ack_commit != channel.commitment_number) {
            fprintf(stderr, "Client %u: commitment mismatch after reconnect "
                    "(ack=%llu, local=%llu) — reloading from DB\n",
                    my_index, (unsigned long long)ack_commit,
                    (unsigned long long)channel.commitment_number);
            if (db) {
                uint64_t db_l, db_r, db_cn;
                if (persist_load_channel_state(db, my_index - 1,
                        &db_l, &db_r, &db_cn)) {
                    channel.local_amount = db_l;
                    channel.remote_amount = db_r;
                    channel.commitment_number = db_cn;
                }
            }
        }

        printf("Client %u: reconnected (channel=%u, commit=%llu)\n",
               my_index, ack_channel_id,
               (unsigned long long)ack_commit);
    }

    /* 10. Call channel callback */
    int cb_ret = 0;
    if (channel_cb) {
        cb_ret = channel_cb(fd, &channel, my_index, ctx, keypair,
                              factory, n_participants, user_data);
    }

    if (cb_ret == 2) {
        /* Callback handled close */
        factory_free(factory); free(factory);
        wire_close(fd);
        return 1;
    }
    if (cb_ret == 1) {
        /* Run close ceremony */
        int close_ok = client_do_close_ceremony(fd, ctx, keypair, &my_pubkey,
                                                  factory, n_participants,
                                                  NULL, 0, &channel);
        factory_free(factory); free(factory);
        wire_close(fd);
        return close_ok;
    }

    /* cb_ret == 0: error or disconnect */
    factory_free(factory); free(factory);
    wire_close(fd);
    return 0;
}

int client_handle_leaf_realloc(int fd, secp256k1_context *ctx,
                                const secp256k1_keypair *keypair,
                                factory_t *factory,
                                uint32_t my_index,
                                const wire_msg_t *propose_msg) {
    /* Parse REALLOC_PROPOSE */
    int leaf_side;
    uint64_t amounts[FACTORY_MAX_OUTPUTS];
    size_t n_amounts;
    unsigned char lsp_pubnonce_ser[66];

    if (!wire_parse_leaf_realloc_propose(propose_msg->json, &leaf_side,
                                          amounts, FACTORY_MAX_OUTPUTS,
                                          &n_amounts, lsp_pubnonce_ser)) {
        fprintf(stderr, "Client %u: failed to parse REALLOC_PROPOSE\n", my_index);
        return 0;
    }

    /* Advance local DW + set amounts */
    int rc = factory_advance_leaf_unsigned(factory, leaf_side);
    if (rc <= 0) {
        fprintf(stderr, "Client %u: leaf advance for realloc failed\n", my_index);
        return 0;
    }
    if (!factory_set_leaf_amounts(factory, leaf_side, amounts, n_amounts)) {
        fprintf(stderr, "Client %u: set_leaf_amounts failed\n", my_index);
        return 0;
    }

    size_t node_idx = factory->leaf_node_indices[leaf_side];

    /* Init signing session for this node */
    if (!factory_session_init_node(factory, node_idx)) {
        fprintf(stderr, "Client %u: realloc session_init_node failed (node %zu)\n", my_index, node_idx);
        return 0;
    }

    /* NOTE: Do NOT set the LSP nonce here.  The ALL_NONCES message
       (received after we send our nonce) contains ALL signers' nonces
       including the LSP's.  Setting the LSP nonce early would increment
       nonces_collected, and the ALL_NONCES loop would set it again,
       pushing nonces_collected past n_signers and failing finalize. */

    /* Generate own nonce */
    int my_slot = factory_find_signer_slot(factory, node_idx, my_index);
    if (my_slot < 0) {
        fprintf(stderr, "Client %u: realloc self not signer on node %zu (pidx=%u)\n",
                my_index, node_idx, my_index);
        return 0;
    }

    unsigned char my_seckey[32];
    if (!secp256k1_keypair_sec(ctx, my_seckey, keypair)) {
        fprintf(stderr, "Client %u: realloc keypair_sec failed\n", my_index);
        return 0;
    }

    secp256k1_pubkey my_pubkey;
    secp256k1_keypair_pub(ctx, &my_pubkey, keypair);

    secp256k1_musig_secnonce my_secnonce;
    secp256k1_musig_pubnonce my_pubnonce;
    if (!musig_generate_nonce(ctx, &my_secnonce, &my_pubnonce,
                               my_seckey, &my_pubkey,
                               &factory->nodes[node_idx].keyagg.cache)) {
        fprintf(stderr, "Client %u: realloc nonce_gen failed\n", my_index);
        memset(my_seckey, 0, 32);
        return 0;
    }

    /* Send REALLOC_NONCE */
    unsigned char my_pubnonce_ser[66];
    musig_pubnonce_serialize(ctx, my_pubnonce_ser, &my_pubnonce);
    cJSON *nonce_msg = wire_build_leaf_realloc_nonce(my_pubnonce_ser);
    if (!wire_send(fd, MSG_LEAF_REALLOC_NONCE, nonce_msg)) {
        fprintf(stderr, "Client %u: realloc send NONCE failed\n", my_index);
        cJSON_Delete(nonce_msg);
        memset(my_seckey, 0, 32);
        return 0;
    }
    cJSON_Delete(nonce_msg);

    /* Receive REALLOC_ALL_NONCES */
    wire_msg_t all_msg;
    if (!wire_recv(fd, &all_msg) || all_msg.msg_type != MSG_LEAF_REALLOC_ALL_NONCES) {
        fprintf(stderr, "Client %u: expected REALLOC_ALL_NONCES, got 0x%02x\n",
                my_index, all_msg.msg_type);
        if (all_msg.json) cJSON_Delete(all_msg.json);
        memset(my_seckey, 0, 32);
        return 0;
    }

    unsigned char all_pubnonces[FACTORY_MAX_SIGNERS][66];
    size_t n_signers;
    if (!wire_parse_leaf_realloc_all_nonces(all_msg.json, all_pubnonces,
                                              FACTORY_MAX_SIGNERS, &n_signers)) {
        fprintf(stderr, "Client %u: realloc parse all_nonces failed\n", my_index);
        cJSON_Delete(all_msg.json);
        memset(my_seckey, 0, 32);
        return 0;
    }
    cJSON_Delete(all_msg.json);

    /* Set all nonces */
    for (size_t i = 0; i < n_signers; i++) {
        secp256k1_musig_pubnonce pn;
        if (!musig_pubnonce_parse(ctx, &pn, all_pubnonces[i])) {
            fprintf(stderr, "Client %u: realloc parse nonce[%zu] failed\n", my_index, i);
            memset(my_seckey, 0, 32);
            return 0;
        }
        if (!factory_session_set_nonce(factory, node_idx, i, &pn)) {
            fprintf(stderr, "Client %u: realloc set_nonce[%zu] failed\n", my_index, i);
            memset(my_seckey, 0, 32);
            return 0;
        }
    }

    /* Finalize */
    if (!factory_session_finalize_node(factory, node_idx)) {
        fprintf(stderr, "Client %u: realloc session_finalize failed (node %zu)\n", my_index, node_idx);
        memset(my_seckey, 0, 32);
        return 0;
    }

    /* Create partial sig */
    secp256k1_musig_partial_sig my_psig;
    if (!musig_create_partial_sig(ctx, &my_psig, &my_secnonce, keypair,
                                    &factory->nodes[node_idx].signing_session)) {
        fprintf(stderr, "Client %u: realloc partial_sig creation failed\n", my_index);
        memset(my_seckey, 0, 32);
        return 0;
    }
    memset(my_seckey, 0, 32);

    /* Send REALLOC_PSIG */
    unsigned char my_psig_ser[32];
    musig_partial_sig_serialize(ctx, my_psig_ser, &my_psig);
    cJSON *psig_json = wire_build_leaf_realloc_psig(my_psig_ser);
    if (!wire_send(fd, MSG_LEAF_REALLOC_PSIG, psig_json)) {
        fprintf(stderr, "Client %u: realloc wire_send PSIG failed\n", my_index);
        cJSON_Delete(psig_json);
        return 0;
    }
    cJSON_Delete(psig_json);

    /* Receive REALLOC_DONE */
    wire_msg_t done_msg;
    if (!wire_recv(fd, &done_msg) || done_msg.msg_type != MSG_LEAF_REALLOC_DONE) {
        fprintf(stderr, "Client %u: expected REALLOC_DONE, got 0x%02x\n",
                my_index, done_msg.msg_type);
        if (done_msg.json) cJSON_Delete(done_msg.json);
        return 0;
    }
    cJSON_Delete(done_msg.json);

    printf("Client %u: leaf %d realloc complete\n", my_index, leaf_side);
    return 1;
}

/* Sub-factory chain extension client handler (Gap E followup Phase 2b,
   t/1242 k² PS).  The client is a member of one of the leaf's k
   sub-factories; the LSP triggers a chain extension to "sell" some
   sales-stock to one of the sub-factory's clients.  All k clients in
   the sub-factory must co-sign the new state.

   Returns 1 on success, 0 on any failure. */
int client_handle_subfactory_advance(int fd, secp256k1_context *ctx,
                                       const secp256k1_keypair *keypair,
                                       factory_t *factory, uint32_t my_index,
                                       const wire_msg_t *propose_msg) {
    int leaf_side, sub_idx, channel_idx;
    uint64_t delta_sats;
    unsigned char lsp_pubnonce_ser[66];
    if (!wire_parse_subfactory_propose(propose_msg->json, &leaf_side, &sub_idx,
                                         &channel_idx, &delta_sats,
                                         lsp_pubnonce_ser)) {
        fprintf(stderr, "Client %u: failed to parse SUBFACTORY_PROPOSE\n", my_index);
        return 0;
    }

    /* Apply the chain advance locally so our unsigned_tx matches the LSP's. */
    if (!factory_subfactory_chain_advance_unsigned(factory, leaf_side, sub_idx,
                                                     channel_idx, delta_sats)) {
        fprintf(stderr, "Client %u: subfactory chain_advance_unsigned failed "
                "(leaf=%d sub=%d ch=%d delta=%llu)\n",
                my_index, leaf_side, sub_idx, channel_idx,
                (unsigned long long)delta_sats);
        return 0;
    }

    /* Locate the sub-factory node we just advanced. */
    if (leaf_side < 0 || leaf_side >= factory->n_leaf_nodes) return 0;
    size_t leaf_idx = factory->leaf_node_indices[leaf_side];
    factory_node_t *leaf = &factory->nodes[leaf_idx];
    if (sub_idx < 0 || sub_idx >= leaf->n_subfactories) return 0;
    int sub_node_i = leaf->subfactory_node_indices[sub_idx];
    if (sub_node_i < 0) return 0;
    factory_node_t *sub = &factory->nodes[sub_node_i];

    /* Init signing session for the sub-factory node. */
    if (!factory_session_init_node(factory, (size_t)sub_node_i)) {
        fprintf(stderr, "Client %u: subfactory session_init failed\n", my_index);
        return 0;
    }

    /* Find own slot and generate own nonce. */
    int my_slot = factory_find_signer_slot(factory, (size_t)sub_node_i, my_index);
    if (my_slot < 0) {
        fprintf(stderr, "Client %u: not a signer on sub-factory %d.%d\n",
                my_index, leaf_side, sub_idx);
        return 0;
    }
    unsigned char my_seckey[32];
    if (!secp256k1_keypair_sec(ctx, my_seckey, keypair)) return 0;
    secp256k1_pubkey my_pubkey;
    secp256k1_keypair_pub(ctx, &my_pubkey, keypair);
    secp256k1_musig_secnonce my_secnonce;
    secp256k1_musig_pubnonce my_pubnonce;
    if (!musig_generate_nonce(ctx, &my_secnonce, &my_pubnonce,
                               my_seckey, &my_pubkey,
                               &sub->keyagg.cache)) {
        memset(my_seckey, 0, 32);
        return 0;
    }

    /* Send NONCE. */
    unsigned char my_pn_ser[66];
    musig_pubnonce_serialize(ctx, my_pn_ser, &my_pubnonce);
    cJSON *nm = wire_build_subfactory_nonce(my_pn_ser, NULL);
    if (!wire_send(fd, MSG_SUBFACTORY_NONCE, nm)) {
        cJSON_Delete(nm);
        memset(my_seckey, 0, 32);
        return 0;
    }
    cJSON_Delete(nm);

    /* Receive ALL_NONCES, set every nonce on the session. */
    wire_msg_t am;
    if (!wire_recv(fd, &am) || am.msg_type != MSG_SUBFACTORY_ALL_NONCES) {
        fprintf(stderr, "Client %u: expected SUBFACTORY_ALL_NONCES, got 0x%02x\n",
                my_index, am.json ? am.msg_type : 0);
        if (am.json) cJSON_Delete(am.json);
        memset(my_seckey, 0, 32);
        return 0;
    }
    unsigned char all_pubnonces[FACTORY_MAX_SIGNERS][66];
    size_t n_pn;
    if (!wire_parse_subfactory_all_nonces(am.json, all_pubnonces, NULL,
                                            FACTORY_MAX_SIGNERS, &n_pn)) {
        cJSON_Delete(am.json);
        memset(my_seckey, 0, 32);
        return 0;
    }
    cJSON_Delete(am.json);
    for (size_t s = 0; s < n_pn; s++) {
        secp256k1_musig_pubnonce pn;
        if (!musig_pubnonce_parse(ctx, &pn, all_pubnonces[s])) {
            memset(my_seckey, 0, 32);
            return 0;
        }
        if (!factory_session_set_nonce(factory, (size_t)sub_node_i, s, &pn)) {
            memset(my_seckey, 0, 32);
            return 0;
        }
    }

    /* Finalize. */
    if (!factory_session_finalize_node(factory, (size_t)sub_node_i)) {
        fprintf(stderr, "Client %u: subfactory finalize failed\n", my_index);
        memset(my_seckey, 0, 32);
        return 0;
    }

    /* Create + send PSIG. */
    secp256k1_musig_partial_sig my_psig;
    if (!musig_create_partial_sig(ctx, &my_psig, &my_secnonce, keypair,
                                    &sub->signing_session)) {
        memset(my_seckey, 0, 32);
        return 0;
    }
    memset(my_seckey, 0, 32);
    unsigned char my_psig_ser[32];
    musig_partial_sig_serialize(ctx, my_psig_ser, &my_psig);
    cJSON *pm = wire_build_subfactory_psig(my_psig_ser, NULL);
    if (!wire_send(fd, MSG_SUBFACTORY_PSIG, pm)) {
        cJSON_Delete(pm);
        return 0;
    }
    cJSON_Delete(pm);

    /* Wait for DONE. */
    wire_msg_t dm;
    if (!wire_recv(fd, &dm) || dm.msg_type != MSG_SUBFACTORY_DONE) {
        fprintf(stderr, "Client %u: expected SUBFACTORY_DONE, got 0x%02x\n",
                my_index, dm.json ? dm.msg_type : 0);
        if (dm.json) cJSON_Delete(dm.json);
        return 0;
    }
    int dn_leaf, dn_sub;
    uint32_t dn_chain_len;
    wire_parse_subfactory_done(dm.json, &dn_leaf, &dn_sub, &dn_chain_len);
    cJSON_Delete(dm.json);
    /* Suppress -Wunused warnings on parsed-but-not-checked fields */
    (void)dn_leaf; (void)dn_sub;

    printf("Client %u: sub-factory %d.%d advanced to chain_len %u "
           "(channel[%d]+=%llu sats)\n",
           my_index, leaf_side, sub_idx, dn_chain_len,
           channel_idx, (unsigned long long)delta_sats);
    return 1;
}

int client_handle_leaf_advance(int fd, secp256k1_context *ctx,
                                 const secp256k1_keypair *keypair,
                                 factory_t *factory, uint32_t my_index,
                                 const wire_msg_t *propose_msg) {
    persist_t *persist = g_client_persist;
    int leaf_side;
    unsigned char lsp_pubnonce_ser[66];
    if (!wire_parse_leaf_advance_propose(propose_msg->json, &leaf_side, lsp_pubnonce_ser)) {
        fprintf(stderr, "Client %u: failed to parse LEAF_ADVANCE_PROPOSE\n", my_index);
        return 0;
    }

    int rc = factory_advance_leaf_unsigned(factory, leaf_side);
    if (rc <= 0) {
        fprintf(stderr, "Client %u: leaf %d advance_unsigned failed (rc=%d)\n",
                my_index, leaf_side, rc);
        return 0;
    }

    size_t node_idx = factory->leaf_node_indices[leaf_side];

    /* PS double-spend defense (ZmnSCPxj, "SuperScalar" Delving post §PS).
       For PS leaves, ps_prev_txid is now the txid of the chain element
       whose vout 0 the new TX will spend. If this client has already
       co-signed ANY TX spending that (parent_txid, 0) — whether a retry
       or a genuine attack — we refuse. Refusing network retries is the
       conservative choice; alternative replay-based idempotency risks
       MuSig nonce-reuse footguns. (DW leaves, arity_1, are protected by
       decrementing nSequence and do not need this check.) */
    factory_node_t *ps_node = &factory->nodes[node_idx];
    if (persist && ps_node->is_ps_leaf && ps_node->ps_chain_len > 0) {
        unsigned char prev_sighash[32];
        int already = persist_check_ps_signed_input(
            persist,
            /* factory_id = */ 0,   /* single-factory PoC convention */
            ps_node->ps_prev_txid,
            /* parent_vout = */ 0,
            prev_sighash);
        if (already) {
            char hex[65];
            for (int i = 0; i < 32; i++)
                snprintf(hex + 2 * i, 3, "%02x", ps_node->ps_prev_txid[i]);
            fprintf(stderr,
                    "Client %u: REFUSING PS double-spend — already signed "
                    "a TX spending (%s:0); not signing a second one.\n",
                    my_index, hex);
            return 0;
        }
    }

    if (!factory_session_init_node(factory, node_idx)) {
        fprintf(stderr, "Client %u: leaf %d session_init failed\n", my_index, leaf_side);
        return 0;
    }

    /* Set LSP nonce (participant 0) — received in PROPOSE */
    int lsp_slot = factory_find_signer_slot(factory, node_idx, 0);
    if (lsp_slot < 0) {
        fprintf(stderr, "Client %u: LSP not signer on leaf node %zu\n", my_index, node_idx);
        return 0;
    }
    secp256k1_musig_pubnonce lsp_pubnonce;
    if (!musig_pubnonce_parse(ctx, &lsp_pubnonce, lsp_pubnonce_ser)) {
        fprintf(stderr, "Client %u: parse LSP pubnonce failed\n", my_index);
        return 0;
    }
    if (!factory_session_set_nonce(factory, node_idx, (size_t)lsp_slot, &lsp_pubnonce)) {
        fprintf(stderr, "Client %u: set LSP nonce failed\n", my_index);
        return 0;
    }

    /* Generate own nonce */
    int my_slot = factory_find_signer_slot(factory, node_idx, my_index);
    if (my_slot < 0) {
        fprintf(stderr, "Client %u: self not signer on leaf node %zu\n", my_index, node_idx);
        return 0;
    }

    unsigned char my_seckey[32];
    secp256k1_pubkey my_pubkey;
    if (!secp256k1_keypair_sec(ctx, my_seckey, keypair)) {
        fprintf(stderr, "Client %u: keypair_sec failed\n", my_index);
        return 0;
    }
    secp256k1_keypair_pub(ctx, &my_pubkey, keypair);

    secp256k1_musig_secnonce my_secnonce;
    secp256k1_musig_pubnonce my_pubnonce;
    if (!musig_generate_nonce(ctx, &my_secnonce, &my_pubnonce,
                               my_seckey, &my_pubkey,
                               &factory->nodes[node_idx].keyagg.cache)) {
        fprintf(stderr, "Client %u: nonce gen failed\n", my_index);
        memset(my_seckey, 0, 32);
        return 0;
    }

    if (!factory_session_set_nonce(factory, node_idx, (size_t)my_slot, &my_pubnonce)) {
        memset(my_seckey, 0, 32);
        return 0;
    }

    if (!factory_session_finalize_node(factory, node_idx)) {
        fprintf(stderr, "Client %u: session finalize failed\n", my_index);
        memset(my_seckey, 0, 32);
        return 0;
    }

    /* Create partial sig */
    secp256k1_musig_partial_sig my_psig;
    if (!musig_create_partial_sig(ctx, &my_psig, &my_secnonce, keypair,
                                    &factory->nodes[node_idx].signing_session)) {
        fprintf(stderr, "Client %u: partial sig failed\n", my_index);
        memset(my_seckey, 0, 32);
        return 0;
    }
    memset(my_seckey, 0, 32);

    /* Serialize now so we can record + send. */
    unsigned char my_pubnonce_ser[66], my_psig_ser[32];
    musig_pubnonce_serialize(ctx, my_pubnonce_ser, &my_pubnonce);
    musig_partial_sig_serialize(ctx, my_psig_ser, &my_psig);

    /* PS defense: record what we just signed BEFORE releasing the partial
       sig over the wire. A crash after record + before send is safe —
       any retry will see the row and refuse to sign anew. */
    if (persist && ps_node->is_ps_leaf && ps_node->ps_chain_len > 0) {
        unsigned char sighash[32];
        if (compute_taproot_sighash(sighash,
                ps_node->unsigned_tx.data, ps_node->unsigned_tx.len,
                0,
                ps_node->outputs[0].script_pubkey,
                ps_node->outputs[0].script_pubkey_len,
                ps_node->ps_prev_chan_amount,
                ps_node->nsequence)) {
            /* partial_sig is 32 bytes on the wire (as serialized by
               musig_partial_sig_serialize) — pad to 36 to match our
               schema's fixed BLOB length. */
            unsigned char psig_buf[36];
            memset(psig_buf, 0, 36);
            memcpy(psig_buf, my_psig_ser, 32);
            persist_save_ps_signed_input(persist, /* factory_id = */ 0,
                (int)node_idx, ps_node->ps_prev_txid, 0,
                sighash, psig_buf);
        }
    }

    cJSON *psig_json = wire_build_leaf_advance_psig(my_pubnonce_ser, my_psig_ser);
    if (!wire_send(fd, MSG_LEAF_ADVANCE_PSIG, psig_json)) {
        fprintf(stderr, "Client %u: send LEAF_ADVANCE_PSIG failed\n", my_index);
        cJSON_Delete(psig_json);
        return 0;
    }
    cJSON_Delete(psig_json);

    /* Wait for LEAF_ADVANCE_DONE */
    wire_msg_t done_msg;
    if (!wire_recv(fd, &done_msg) || done_msg.msg_type != MSG_LEAF_ADVANCE_DONE) {
        fprintf(stderr, "Client %u: expected LEAF_ADVANCE_DONE, got 0x%02x\n",
                my_index, done_msg.json ? done_msg.msg_type : 0);
        if (done_msg.json) cJSON_Delete(done_msg.json);
        return 0;
    }
    if (done_msg.json) cJSON_Delete(done_msg.json);

    printf("Client %u: leaf %d advance complete\n", my_index, leaf_side);
    return 1;
}

int client_handle_state_advance(int fd, secp256k1_context *ctx,
                                  const secp256k1_keypair *keypair,
                                  factory_t *factory,
                                  uint32_t my_index,
                                  const wire_msg_t *propose_msg) {
    /* Parse propose */
    uint32_t epoch_in;
    int trigger_leaf;
    wire_bundle_entry_t lsp_nonces[FACTORY_MAX_NODES];
    size_t n_lsp_nonces = 0;
    if (!wire_parse_state_advance_propose(propose_msg->json, &epoch_in,
                                            &trigger_leaf,
                                            lsp_nonces, FACTORY_MAX_NODES,
                                            &n_lsp_nonces)) {
        fprintf(stderr, "Client %u: failed to parse STATE_ADVANCE_PROPOSE\n", my_index);
        return 0;
    }

    /* Advance local DW counter to root rollover.

       The LSP triggered Tier B because its OWN factory_advance_leaf_unsigned
       returned -1.  The client's counter is typically ONE step behind the
       LSP because the prior per-leaf-advance ceremony exited cleanly on
       the LSP side at rc=-1 without sending MSG_LEAF_ADVANCE_PROPOSE
       (the rc=-1 branch in lsp_advance_leaf hands off to Tier B
       directly).  So the client must drive its own advance until rc=-1
       fires too — at most one extra step in the lockstep case, but the
       loop also handles unsynchronized recovery scenarios.  Bounded by
       states_per_layer+2 as a safety cap. */
    int rc = 0;
    int max_steps = (int)(factory->states_per_layer + 2);
    if (max_steps < 4) max_steps = 4;
    for (int s = 0; s < max_steps; s++) {
        rc = factory_advance_leaf_unsigned(factory, trigger_leaf);
        if (rc == -1) break;
        if (rc != 1) {
            fprintf(stderr, "Client %u: state_advance: advance step %d returned %d\n",
                    my_index, s, rc);
            return 0;
        }
    }
    if (rc != -1) {
        fprintf(stderr, "Client %u: state advance: never hit rc=-1 within %d steps\n",
                my_index, max_steps);
        return 0;
    }

    /* Determine affected nodes — every non-PS-leaf node that's built
       and not yet signed (i.e., what factory_advance_leaf_unsigned
       just rebuilt). */
    size_t affected[FACTORY_MAX_NODES];
    size_t n_affected = 0;
    for (size_t i = 0; i < factory->n_nodes; i++) {
        const factory_node_t *n = &factory->nodes[i];
        if (n->is_ps_leaf) continue;
        if (!n->is_built) continue;
        if (n->is_signed) continue;
        affected[n_affected++] = i;
    }

    /* For each affected node where I'm a signer: init session, generate
       my nonce, save secnonce for later partial sig. */
    secp256k1_musig_secnonce my_secnonce_per_node[FACTORY_MAX_NODES];
    int my_slot_per_node[FACTORY_MAX_NODES];
    int has_my_nonce[FACTORY_MAX_NODES];
    wire_bundle_entry_t my_nonce_bundle[FACTORY_MAX_NODES];
    size_t my_bundle_count = 0;

    for (size_t k = 0; k < n_affected; k++) {
        my_slot_per_node[k] = -1;
        has_my_nonce[k] = 0;
    }

    unsigned char my_seckey[32];
    if (!secp256k1_keypair_sec(ctx, my_seckey, keypair)) {
        fprintf(stderr, "Client %u: keypair_sec failed\n", my_index);
        return 0;
    }
    secp256k1_pubkey my_pubkey;
    secp256k1_keypair_pub(ctx, &my_pubkey, keypair);

    for (size_t k = 0; k < n_affected; k++) {
        size_t ni = affected[k];
        int slot = factory_find_signer_slot(factory, ni, my_index);
        if (slot < 0) continue;  /* not a signer on this node */

        if (!factory_session_init_node(factory, ni)) {
            fprintf(stderr, "Client %u: state_advance session_init node %zu failed\n",
                    my_index, ni);
            memset(my_seckey, 0, 32);
            return 0;
        }

        secp256k1_musig_pubnonce my_pubnonce;
        if (!musig_generate_nonce(ctx, &my_secnonce_per_node[k], &my_pubnonce,
                                   my_seckey, &my_pubkey,
                                   &factory->nodes[ni].keyagg.cache)) {
            fprintf(stderr, "Client %u: state_advance nonce_gen node %zu failed\n",
                    my_index, ni);
            memset(my_seckey, 0, 32);
            return 0;
        }
        my_slot_per_node[k] = slot;
        has_my_nonce[k] = 1;

        unsigned char ser[66];
        musig_pubnonce_serialize(ctx, ser, &my_pubnonce);
        my_nonce_bundle[my_bundle_count].node_idx = (uint32_t)ni;
        my_nonce_bundle[my_bundle_count].signer_slot = (uint32_t)slot;
        memcpy(my_nonce_bundle[my_bundle_count].data, ser, 66);
        my_nonce_bundle[my_bundle_count].data_len = 66;
        my_bundle_count++;
    }
    memset(my_seckey, 0, 32);

    /* Send PATH_NONCE_BUNDLE */
    cJSON *nb = wire_build_nonce_bundle(my_nonce_bundle, my_bundle_count);
    /* Note: wire_build_nonce_bundle wraps with key "entries"; the LSP's
       state-advance receiver pulls the same key.  Reusing that builder
       saves us a duplicate JSON helper. */
    if (!wire_send(fd, MSG_PATH_NONCE_BUNDLE, nb)) {
        fprintf(stderr, "Client %u: send PATH_NONCE_BUNDLE failed\n", my_index);
        cJSON_Delete(nb);
        return 0;
    }
    cJSON_Delete(nb);

    /* Receive PATH_ALL_NONCES */
    wire_msg_t all_msg;
    if (!wire_recv(fd, &all_msg) || all_msg.msg_type != MSG_PATH_ALL_NONCES) {
        fprintf(stderr, "Client %u: expected PATH_ALL_NONCES, got 0x%02x\n",
                my_index, all_msg.json ? all_msg.msg_type : 0);
        if (all_msg.json) cJSON_Delete(all_msg.json);
        return 0;
    }
    cJSON *all_arr = cJSON_GetObjectItem(all_msg.json, "nonces");
    if (!all_arr) {
        fprintf(stderr, "Client %u: PATH_ALL_NONCES missing 'nonces' key\n", my_index);
        cJSON_Delete(all_msg.json);
        return 0;
    }
    size_t cap = (size_t)FACTORY_MAX_NODES * FACTORY_MAX_SIGNERS;
    wire_bundle_entry_t *all = calloc(cap, sizeof(wire_bundle_entry_t));
    if (!all) { cJSON_Delete(all_msg.json); return 0; }
    size_t n_all = wire_parse_bundle(all_arr, all, cap, 66);

    /* Set every nonce we DON'T already have (sessions reject double-set
       which would push nonces_collected past n_signers).  We already
       set our own nonces during nonce-gen via factory_session_set_nonce
       — but actually we did NOT set them on session, only generated.
       Re-check: musig_generate_nonce just produces sec/pub; it doesn't
       set on session.  We need to set every nonce here. */
    for (size_t e = 0; e < n_all; e++) {
        secp256k1_musig_pubnonce pn;
        if (!musig_pubnonce_parse(ctx, &pn, all[e].data)) {
            fprintf(stderr, "Client %u: bad pubnonce in ALL_NONCES\n", my_index);
            free(all); cJSON_Delete(all_msg.json);
            return 0;
        }
        if (!factory_session_set_nonce(factory, all[e].node_idx,
                                        all[e].signer_slot, &pn)) {
            fprintf(stderr, "Client %u: state_advance set_nonce node=%u slot=%u failed\n",
                    my_index, all[e].node_idx, all[e].signer_slot);
            free(all); cJSON_Delete(all_msg.json);
            return 0;
        }
    }
    free(all);
    cJSON_Delete(all_msg.json);

    /* Finalize sessions for every node we signed on */
    for (size_t k = 0; k < n_affected; k++) {
        if (!has_my_nonce[k]) continue;
        if (!factory_session_finalize_node(factory, affected[k])) {
            fprintf(stderr, "Client %u: state_advance finalize node %zu failed\n",
                    my_index, affected[k]);
            return 0;
        }
    }

    /* Generate partial sigs */
    wire_bundle_entry_t my_psig_bundle[FACTORY_MAX_NODES];
    size_t my_psig_count = 0;

    for (size_t k = 0; k < n_affected; k++) {
        if (!has_my_nonce[k]) continue;
        size_t ni = affected[k];
        secp256k1_musig_partial_sig psig;
        if (!musig_create_partial_sig(ctx, &psig, &my_secnonce_per_node[k],
                                        keypair,
                                        &factory->nodes[ni].signing_session)) {
            fprintf(stderr, "Client %u: state_advance create_partial_sig node %zu failed\n",
                    my_index, ni);
            return 0;
        }
        unsigned char psig_ser[32];
        musig_partial_sig_serialize(ctx, psig_ser, &psig);
        my_psig_bundle[my_psig_count].node_idx = (uint32_t)ni;
        my_psig_bundle[my_psig_count].signer_slot = (uint32_t)my_slot_per_node[k];
        memcpy(my_psig_bundle[my_psig_count].data, psig_ser, 32);
        my_psig_bundle[my_psig_count].data_len = 32;
        my_psig_count++;
    }

    /* Send PATH_PSIG_BUNDLE */
    cJSON *pb = wire_build_psig_bundle(my_psig_bundle, my_psig_count);
    if (!wire_send(fd, MSG_PATH_PSIG_BUNDLE, pb)) {
        fprintf(stderr, "Client %u: send PATH_PSIG_BUNDLE failed\n", my_index);
        cJSON_Delete(pb);
        return 0;
    }
    cJSON_Delete(pb);

    /* Receive PATH_SIGN_DONE */
    wire_msg_t done_msg;
    if (!wire_recv(fd, &done_msg) || done_msg.msg_type != MSG_PATH_SIGN_DONE) {
        fprintf(stderr, "Client %u: expected PATH_SIGN_DONE, got 0x%02x\n",
                my_index, done_msg.json ? done_msg.msg_type : 0);
        if (done_msg.json) cJSON_Delete(done_msg.json);
        return 0;
    }
    uint32_t epoch_done = 0;
    wire_parse_path_sign_done(done_msg.json, &epoch_done);
    cJSON_Delete(done_msg.json);

    printf("Client %u: state advance complete, epoch %u (%zu nodes signed)\n",
           my_index, epoch_done, my_psig_count);
    /* Suppress -Wunused warnings for fields we kept for future error paths */
    (void)trigger_leaf;
    (void)epoch_in;
    (void)n_lsp_nonces;  /* LSP nonces also arrive in ALL_NONCES; propose copy is informational */
    return 1;
}

int client_run_ceremony(secp256k1_context *ctx,
                        const secp256k1_keypair *keypair,
                        const char *host, int port) {
    return client_run_with_channels(ctx, keypair, host, port, NULL, NULL,
                                     NULL, NULL);
}
