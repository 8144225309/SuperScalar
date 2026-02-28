#include "superscalar/client.h"
#include "superscalar/wire.h"
#include "superscalar/factory.h"
#include "superscalar/fee.h"
#include "superscalar/musig.h"
#include "superscalar/persist.h"
#include "superscalar/shachain.h"
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

void client_set_lsp_pubkey(const secp256k1_pubkey *pubkey) {
    if (pubkey) {
        g_nk_server_pubkey = *pubkey;
        g_nk_server_pubkey_set = 1;
    } else {
        g_nk_server_pubkey_set = 0;
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

/* Initialize a client-side channel from factory leaf outputs.
   Mirrors the LSP's lsp_channels_init logic.
   remote_*_bp: remote (LSP) basepoint pubkeys received via MSG_CHANNEL_BASEPOINTS.
   local_*_sec32: 32-byte local basepoint secrets (random, not SHA256-derived). */
static int client_init_channel(channel_t *ch, secp256k1_context *ctx,
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
                                 const fee_estimator_t *fee_est) {
    /* Map client index to leaf output (arity-aware) */
    size_t client_idx = (size_t)(my_index - 1);  /* my_index is 1-based */
    size_t node_idx;
    uint32_t vout;
    if (factory->leaf_arity == FACTORY_ARITY_1) {
        if (client_idx >= (size_t)factory->n_leaf_nodes) return 0;
        node_idx = factory->leaf_node_indices[client_idx];
        vout = 0;
    } else {
        size_t leaf_idx = client_idx / 2;
        if (leaf_idx >= (size_t)factory->n_leaf_nodes) return 0;
        node_idx = factory->leaf_node_indices[leaf_idx];
        vout = (uint32_t)(client_idx % 2);
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
    fee_estimator_t _fe_default;
    const fee_estimator_t *_fe = fee_est;
    if (!_fe) { fee_init(&_fe_default, 1000); _fe = &_fe_default; }
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
                                        &nonce_index))
        return 0;

    /* Phase 12: Verify LSP's partial sig and aggregate into full sig.
       The client now holds a valid, broadcastable commitment tx. */
    unsigned char full_sig64[64];
    if (!channel_verify_and_aggregate_commitment_sig(ch, partial_sig32,
                                                       nonce_index, full_sig64)) {
        fprintf(stderr, "Client: commitment sig verification/aggregation failed\n");
        return 0;
    }

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

    return 1;
}

int client_fulfill_payment(int fd, channel_t *ch,
                             uint64_t htlc_id,
                             const unsigned char *preimage32) {
    /* Fulfill locally */
    if (!channel_fulfill_htlc(ch, htlc_id, preimage32))
        return 0;

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
                               const wire_msg_t *initial_msg) {
    wire_msg_t msg;
    int got_propose = 0;

    if (initial_msg && initial_msg->msg_type == MSG_CLOSE_PROPOSE) {
        /* Use already-received CLOSE_PROPOSE */
        msg = *initial_msg;
        got_propose = 1;
    } else {
        /* Receive CLOSE_PROPOSE, skipping any LSP revocation messages */
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
    size_t n_outputs = (size_t)cJSON_GetArraySize(outputs_arr);
    if (n_outputs == 0 || n_outputs > 32) {
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

    tx_buf_t close_unsigned;
    tx_buf_init(&close_unsigned, 256);
    unsigned char close_sighash[32];

    if (!factory_build_cooperative_close_unsigned(factory, &close_unsigned,
                                                   close_sighash,
                                                   close_outputs, n_outputs)) {
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

    /* Receive CLOSE_ALL_NONCES */
    wire_msg_t all_nonces_msg;
    if (!wire_recv(fd, &all_nonces_msg) || check_msg_error(&all_nonces_msg) ||
        all_nonces_msg.msg_type != MSG_CLOSE_ALL_NONCES) {
        fprintf(stderr, "Client: expected CLOSE_ALL_NONCES\n");
        if (all_nonces_msg.json) cJSON_Delete(all_nonces_msg.json);
        tx_buf_free(&close_unsigned);
        return 0;
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

    /* Build factory locally */
    factory_init_from_pubkeys(factory_out, ctx, all_pubkeys, n_participants,
                              step_blocks, states_per_layer);
    factory_out->cltv_timeout = cltv_timeout;
    factory_out->fee_per_tx = fee_per_tx;
    factory_out->placement_mode = (placement_mode_t)rot_placement;
    factory_out->economic_mode = (economic_mode_t)rot_econ;
    memcpy(factory_out->profiles, rot_profiles, sizeof(rot_profiles));
    if (rot_leaf_arity == 1)
        factory_set_arity(factory_out, FACTORY_ARITY_1);
    factory_set_funding(factory_out, funding_txid, funding_vout, funding_amount,
                        funding_spk, spk_len);

    if (!factory_build_tree(factory_out) || !factory_sessions_init(factory_out)) {
        fprintf(stderr, "Client %u: rotation factory build/init failed\n", my_index);
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
        (wire_bundle_entry_t *)calloc(my_node_count, sizeof(wire_bundle_entry_t));
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
        wire_bundle_entry_t all_entries[256];
        size_t n_all = wire_parse_bundle(nonces_arr, all_entries, 256, 66);
        for (size_t e = 0; e < n_all; e++) {
            secp256k1_musig_pubnonce pn;
            if (!musig_pubnonce_parse(ctx, &pn, all_entries[e].data)) continue;
            factory_session_set_nonce(factory_out, all_entries[e].node_idx,
                                     all_entries[e].signer_slot, &pn);
        }
    }
    cJSON_Delete(msg.json);

    if (!factory_sessions_finalize(factory_out)) {
        free(secnonces); free(nonce_entries); return 0;
    }

    /* Create and send partial sigs */
    {
        wire_bundle_entry_t *psig_entries =
            (wire_bundle_entry_t *)calloc(my_node_count, sizeof(wire_bundle_entry_t));
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
    {
        uint32_t channel_id;
        uint64_t bl, br;
        wire_parse_channel_ready(msg.json, &channel_id, &bl, &br);
        cJSON_Delete(msg.json);
        printf("Client %u: rotation channel %u ready (local=%llu, remote=%llu)\n",
               my_index, channel_id, (unsigned long long)bl, (unsigned long long)br);
    }

    /* Initialize client-side channel */
    if (!client_init_channel(channel_out, ctx, factory_out, keypair, my_index,
                              &rot_lsp_pay_bp, &rot_lsp_delay_bp,
                              &rot_lsp_revoc_bp, &rot_lsp_htlc_bp,
                              rot_bp_ps, rot_bp_ds, rot_bp_rs, rot_bp_hs, NULL)) {
        free(secnonces); free(nonce_entries); return 0;
    }
    memset(rot_bp_ps, 0, 32); memset(rot_bp_ds, 0, 32);
    memset(rot_bp_rs, 0, 32); memset(rot_bp_hs, 0, 32);

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
                              void *user_data) {
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

    /* Receive FACTORY_PROPOSE — disable timeout since LSP may be waiting for
       on-chain funding confirmation (up to ~10 min on signet/testnet) */
    if (!wire_recv_timeout(fd, &msg, 0) || check_msg_error(&msg) || msg.msg_type != MSG_FACTORY_PROPOSE) {
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
    uint32_t funding_vout = (uint32_t)cJSON_GetObjectItem(msg.json, "funding_vout")->valuedouble;
    uint64_t funding_amount = (uint64_t)cJSON_GetObjectItem(msg.json, "funding_amount")->valuedouble;
    unsigned char funding_spk[34];
    size_t spk_len = (size_t)wire_json_get_hex(msg.json, "funding_spk", funding_spk, 34);
    uint16_t step_blocks = (uint16_t)cJSON_GetObjectItem(msg.json, "step_blocks")->valuedouble;
    uint32_t states_per_layer = (uint32_t)cJSON_GetObjectItem(msg.json, "states_per_layer")->valuedouble;
    uint32_t cltv_timeout = (uint32_t)cJSON_GetObjectItem(msg.json, "cltv_timeout")->valuedouble;
    uint64_t fee_per_tx = (uint64_t)cJSON_GetObjectItem(msg.json, "fee_per_tx")->valuedouble;
    cJSON *arity_item = cJSON_GetObjectItem(msg.json, "leaf_arity");
    int leaf_arity = (arity_item && cJSON_IsNumber(arity_item)) ? (int)arity_item->valuedouble : 2;

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
    cJSON_Delete(msg.json);

    /* Build factory locally */
    factory_t factory;
    factory_init_from_pubkeys(&factory, ctx, all_pubkeys, n_participants,
                              step_blocks, states_per_layer);
    factory.cltv_timeout = cltv_timeout;
    factory.fee_per_tx = fee_per_tx;
    factory.placement_mode = (placement_mode_t)placement_mode;
    factory.economic_mode = (economic_mode_t)economic_mode;
    memcpy(factory.profiles, profiles, sizeof(profiles));
    if (leaf_arity == 1)
        factory_set_arity(&factory, FACTORY_ARITY_1);
    factory_set_funding(&factory, funding_txid, funding_vout, funding_amount,
                        funding_spk, spk_len);

    if (!factory_build_tree(&factory)) {
        fprintf(stderr, "Client: factory_build_tree failed\n");
        factory_free(&factory);
        wire_close(fd);
        return 0;
    }

    /* Initialize signing sessions */
    if (!factory_sessions_init(&factory)) {
        fprintf(stderr, "Client: factory_sessions_init failed\n");
        factory_free(&factory);
        wire_close(fd);
        return 0;
    }

    /* Generate nonces via pool */
    unsigned char my_seckey[32];
    secp256k1_keypair_sec(ctx, my_seckey, keypair);

    size_t my_node_count = factory_count_nodes_for_participant(&factory, my_index);

    /* Pre-generate nonce pool */
    musig_nonce_pool_t my_pool;
    if (!musig_nonce_pool_generate(ctx, &my_pool, my_node_count,
                                    my_seckey, &my_pubkey, NULL)) {
        fprintf(stderr, "Client: nonce pool generation failed\n");
        memset(my_seckey, 0, 32);
        factory_free(&factory);
        wire_close(fd);
        return 0;
    }
    memset(my_seckey, 0, 32);

    secp256k1_musig_secnonce *my_secnonce_ptrs[FACTORY_MAX_NODES];
    wire_bundle_entry_t *nonce_entries =
        (wire_bundle_entry_t *)calloc(my_node_count, sizeof(wire_bundle_entry_t));

    if (my_node_count > 0 && !nonce_entries) {
        fprintf(stderr, "Client: alloc failed\n");
        free(nonce_entries);
        factory_free(&factory);
        wire_close(fd);
        return 0;
    }

    size_t nonce_count = 0;
    for (size_t i = 0; i < factory.n_nodes; i++) {
        int slot = factory_find_signer_slot(&factory, i, my_index);
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

    if (!factory_sessions_init(&factory)) {
        fprintf(stderr, "Client: re-init sessions failed\n");
        cJSON_Delete(msg.json);
        goto fail;
    }

    {
        cJSON *nonces_arr = cJSON_GetObjectItem(msg.json, "nonces");
        wire_bundle_entry_t all_entries[256];
        size_t n_all = wire_parse_bundle(nonces_arr, all_entries, 256, 66);

        for (size_t e = 0; e < n_all; e++) {
            secp256k1_musig_pubnonce pn;
            if (!musig_pubnonce_parse(ctx, &pn, all_entries[e].data)) {
                fprintf(stderr, "Client: bad pubnonce in ALL_NONCES\n");
                cJSON_Delete(msg.json);
                goto fail;
            }
            if (!factory_session_set_nonce(&factory, all_entries[e].node_idx,
                                            all_entries[e].signer_slot, &pn)) {
                fprintf(stderr, "Client: set nonce failed node %u slot %u\n",
                        all_entries[e].node_idx, all_entries[e].signer_slot);
                cJSON_Delete(msg.json);
                goto fail;
            }
        }
    }
    cJSON_Delete(msg.json);

    /* Finalize nonces */
    if (!factory_sessions_finalize(&factory)) {
        fprintf(stderr, "Client: factory_sessions_finalize failed\n");
        goto fail;
    }

    /* Create partial sigs */
    {
        wire_bundle_entry_t *psig_entries =
            (wire_bundle_entry_t *)calloc(my_node_count, sizeof(wire_bundle_entry_t));
        if (my_node_count > 0 && !psig_entries) {
            fprintf(stderr, "Client: alloc failed\n");
            goto fail;
        }
        size_t psig_count = 0;

        size_t psig_nonce_idx = 0;
        for (size_t i = 0; i < factory.n_nodes; i++) {
            int slot = factory_find_signer_slot(&factory, i, my_index);
            if (slot < 0) continue;

            secp256k1_musig_partial_sig psig;
            if (!musig_create_partial_sig(ctx, &psig, my_secnonce_ptrs[psig_nonce_idx],
                                           keypair, &factory.nodes[i].signing_session)) {
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
    cJSON_Delete(msg.json);

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

        /* Initialize client-side channel */
        channel_t channel;
        if (!client_init_channel(&channel, ctx, &factory, keypair, my_index,
                                  &lsp_pay_bp, &lsp_delay_bp,
                                  &lsp_revoc_bp, &lsp_htlc_bp,
                                  bp_ps, bp_ds, bp_rs, bp_hs, NULL)) {
            fprintf(stderr, "Client %u: channel init failed\n", my_index);
            goto fail;
        }
        memset(bp_ps, 0, 32); memset(bp_ds, 0, 32);
        memset(bp_rs, 0, 32); memset(bp_hs, 0, 32);

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
                                 &factory, n_participants, user_data);
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
                                    &factory, n_participants, NULL)) {
        goto fail;
    }

    printf("Client %u: cooperative close complete!\n", my_index);

done:
    free(nonce_entries);
    factory_free(&factory);
    wire_close(fd);
    return 1;

fail:
    free(nonce_entries);
    factory_free(&factory);
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

    /* 1. Load factory from DB */
    factory_t factory;
    if (!persist_load_factory(db, 0, &factory, ctx)) {
        fprintf(stderr, "Client reconnect: failed to load factory from DB\n");
        return 0;
    }

    /* 2. Determine my_index by matching pubkey against factory.pubkeys[] */
    uint32_t my_index = 0;
    {
        unsigned char my_ser[33], cmp_ser[33];
        size_t len1 = 33, len2 = 33;
        secp256k1_ec_pubkey_serialize(ctx, my_ser, &len1, &my_pubkey,
                                       SECP256K1_EC_COMPRESSED);
        for (size_t i = 0; i < factory.n_participants; i++) {
            len2 = 33;
            secp256k1_ec_pubkey_serialize(ctx, cmp_ser, &len2,
                                           &factory.pubkeys[i],
                                           SECP256K1_EC_COMPRESSED);
            if (memcmp(my_ser, cmp_ser, 33) == 0) {
                my_index = (uint32_t)i;
                break;
            }
        }
        if (my_index == 0) {
            fprintf(stderr, "Client reconnect: pubkey not found in factory\n");
            factory_free(&factory);
            return 0;
        }
    }

    size_t n_participants = factory.n_participants;

    /* 3. Connect to LSP */
    int fd = wire_connect(host, port);
    if (fd < 0) {
        fprintf(stderr, "Client reconnect: connect failed\n");
        factory_free(&factory);
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
        factory_free(&factory);
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
            factory_free(&factory);
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
        factory_free(&factory);
        return 0;
    }

    secp256k1_pubkey reconn_lsp_pay_bp, reconn_lsp_delay_bp, reconn_lsp_revoc_bp, reconn_lsp_htlc_bp;
    if (!secp256k1_ec_pubkey_parse(ctx, &reconn_lsp_pay_bp, remote_bps[0], 33) ||
        !secp256k1_ec_pubkey_parse(ctx, &reconn_lsp_delay_bp, remote_bps[1], 33) ||
        !secp256k1_ec_pubkey_parse(ctx, &reconn_lsp_revoc_bp, remote_bps[2], 33) ||
        !secp256k1_ec_pubkey_parse(ctx, &reconn_lsp_htlc_bp, remote_bps[3], 33)) {
        fprintf(stderr, "Client reconnect: failed to parse remote basepoints\n");
        wire_close(fd);
        factory_free(&factory);
        return 0;
    }

    channel_t channel;
    if (!client_init_channel(&channel, ctx, &factory, keypair, my_index,
                              &reconn_lsp_pay_bp, &reconn_lsp_delay_bp,
                              &reconn_lsp_revoc_bp, &reconn_lsp_htlc_bp,
                              local_secs[0], local_secs[1], local_secs[2], local_secs[3], NULL)) {
        fprintf(stderr, "Client reconnect: channel init failed\n");
        memset(local_secs, 0, sizeof(local_secs));
        wire_close(fd);
        factory_free(&factory);
        return 0;
    }
    memset(local_secs, 0, sizeof(local_secs));

    /* 7. Overwrite channel state with persisted values */
    if (local_amount > 0 || remote_amount > 0) {
        channel.local_amount = local_amount;
        channel.remote_amount = remote_amount;
        channel.commitment_number = commitment_number;

        /* Ensure local PCS exist for the restored commitment number.
           channel_init generated PCS for cn=0 and cn=1; if commitment_number > 1,
           we need to generate PCS for the current and next commitment. */
        for (uint64_t cn = channel.n_local_pcs; cn <= commitment_number + 1; cn++)
            channel_generate_local_pcs(&channel, cn);
    }

    /* 8. Nonce exchange — LSP sends CHANNEL_NONCES before RECONNECT_ACK */
    /* Receive LSP's pubnonces */
    {
        wire_msg_t msg;
        if (!wire_recv(fd, &msg) || msg.msg_type != MSG_CHANNEL_NONCES) {
            fprintf(stderr, "Client reconnect: expected CHANNEL_NONCES from LSP\n");
            if (msg.json) cJSON_Delete(msg.json);
            wire_close(fd);
            factory_free(&factory);
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
            factory_free(&factory);
            return 0;
        }
        cJSON_Delete(msg.json);

        /* Init client nonce pool */
        if (!channel_init_nonce_pool(&channel, lsp_nonce_count)) {
            fprintf(stderr, "Client reconnect: nonce pool init failed\n");
            wire_close(fd);
            factory_free(&factory);
            return 0;
        }

        /* Send client's pubnonces */
        size_t my_nonce_count = channel.local_nonce_pool.count;
        unsigned char (*my_pubnonces_ser)[66] =
            (unsigned char (*)[66])calloc(my_nonce_count, 66);
        if (!my_pubnonces_ser) {
            wire_close(fd);
            factory_free(&factory);
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
            factory_free(&factory);
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

    /* 9. Recv MSG_RECONNECT_ACK (sent by LSP after nonce exchange) */
    {
        wire_msg_t msg;
        if (!wire_recv(fd, &msg) || msg.msg_type != MSG_RECONNECT_ACK) {
            fprintf(stderr, "Client reconnect: expected RECONNECT_ACK, got 0x%02x\n",
                    msg.msg_type);
            if (msg.json) cJSON_Delete(msg.json);
            wire_close(fd);
            factory_free(&factory);
            return 0;
        }

        uint32_t ack_channel_id;
        uint64_t ack_local, ack_remote, ack_commit;
        if (!wire_parse_reconnect_ack(msg.json, &ack_channel_id,
                                        &ack_local, &ack_remote, &ack_commit)) {
            fprintf(stderr, "Client reconnect: failed to parse RECONNECT_ACK\n");
            cJSON_Delete(msg.json);
            wire_close(fd);
            factory_free(&factory);
            return 0;
        }
        cJSON_Delete(msg.json);

        printf("Client %u: reconnected (channel=%u, commit=%llu)\n",
               my_index, ack_channel_id,
               (unsigned long long)ack_commit);
    }

    /* 10. Call channel callback */
    int cb_ret = 0;
    if (channel_cb) {
        cb_ret = channel_cb(fd, &channel, my_index, ctx, keypair,
                              &factory, n_participants, user_data);
    }

    if (cb_ret == 2) {
        /* Callback handled close */
        factory_free(&factory);
        wire_close(fd);
        return 1;
    }
    if (cb_ret == 1) {
        /* Run close ceremony */
        int close_ok = client_do_close_ceremony(fd, ctx, keypair, &my_pubkey,
                                                  &factory, n_participants, NULL);
        factory_free(&factory);
        wire_close(fd);
        return close_ok;
    }

    /* cb_ret == 0: error or disconnect */
    factory_free(&factory);
    wire_close(fd);
    return 0;
}

int client_run_ceremony(secp256k1_context *ctx,
                        const secp256k1_keypair *keypair,
                        const char *host, int port) {
    return client_run_with_channels(ctx, keypair, host, port, NULL, NULL);
}
