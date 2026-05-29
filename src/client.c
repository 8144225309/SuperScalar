#include "superscalar/client.h"
#include "superscalar/wire.h"
#include "superscalar/factory.h"
#include "superscalar/fee.h"
#include "superscalar/musig.h"
#include "superscalar/persist.h"
#include "superscalar/shachain.h"
#include "superscalar/tx_builder.h"
#include "superscalar/regtest.h"  /* CL7: regtest_send_raw_tx + regtest_t */
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
#define CL7_TX_HEX_MAX 200000  /* upper bound for tx hex; CL7 cheat broadcast */

static persist_t *g_client_persist = NULL;
static regtest_t *g_client_chain_rt = NULL;  /* CL7: for cheat-client broadcasts */

/* CL7: setter for the chain backend so client_handle_leaf_advance can
   broadcast pre-advance leaf state when --cheat-client is set. */
void client_set_chain_rt(regtest_t *rt) { g_client_chain_rt = rt; }

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

/* Client-side mirror of LSP's funding_pending_reorg flag.  When MSG_FUNDING_
   REORG arrives, we set this so future cooperative ops / add-htlc paths can
   check it and refuse.  Best-effort: LSP-side state is authoritative; this
   is just a UX hint so the client doesn't try to do anything that'll be
   rejected anyway. */
static int g_client_funding_pending_reorg = 0;

/* SF-followup #145: client-side mirror of LSP's factory_reset_all_subfactory_
   chains call from #208's reorg handler.  When MSG_FUNDING_REORG arrives with
   frozen=1 the LSP has already reset its in-memory ps_chain_len for advanced
   sub-factories; the client must do the same so subsequent recovery /
   force-close paths don't reference invalid chain[N] state whose parent
   chain[N-1] is no longer on chain.  Set at the entry of client_run_with_
   channels / client_run_reconnect to point at the active factory_t, cleared
   on exit.  When NULL (pre-factory bootstrap), the reorg notification is
   recorded in the freeze flag but no reset happens (there's nothing to
   reset). */
static factory_t *g_client_active_factory = NULL;

/* Wrapper around wire_recv_timeout that transparently handles
   MSG_PING (responds with MSG_PONG), MSG_PONG (discards), and
   MSG_FUNDING_REORG (updates local freeze mirror, discards).
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
        if (msg->msg_type == MSG_FUNDING_REORG) {
            int frozen = 0;
            const char *txid_hex = "?";
            if (msg->json) {
                cJSON *fr = cJSON_GetObjectItem(msg->json, "frozen");
                if (fr && cJSON_IsNumber(fr)) frozen = fr->valueint;
                cJSON *tx = cJSON_GetObjectItem(msg->json, "funding_txid");
                if (tx && cJSON_IsString(tx)) txid_hex = tx->valuestring;
            }
            g_client_funding_pending_reorg = frozen ? 1 : 0;
            fprintf(stderr, "Client: MSG_FUNDING_REORG funding=%.16s "
                    "frozen=%d (LSP says funding %s)\n",
                    txid_hex, frozen,
                    frozen ? "reorged out" : "back on chain");
            /* SF-followup #145: mirror LSP-side reset from PR #208.  When the
               funding is reported reorged out, any in-memory sub-factory
               chain advance state is stale and must not be referenced by
               subsequent operations.  Reset only on frozen=1; the unfreeze
               path (frozen=0, funding back on chain) leaves the now-empty
               chain in place — caller can re-advance from chain[0] if
               desired. */
            if (frozen && g_client_active_factory) {
                int n_reset = factory_reset_all_subfactory_chains(
                    g_client_active_factory);
                if (n_reset > 0)
                    fprintf(stderr, "Client: reset ps_chain_len on %d "
                            "sub-factor(ies) after funding reorg\n", n_reset);
            }
            if (msg->json) cJSON_Delete(msg->json);
            msg->json = NULL;
            continue;  /* notification, wait for next real message */
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

    /* SF-CH #154: factory leaf SPKs use different keyagg orderings + cltv
       sources depending on leaf type (PS leaves use [LSP, client] +
       node_cltv via setup_ps_leaf_outputs; non-PS leaves use [client, LSP] +
       factory_cltv via setup_*_leaf_outputs).  Auto-discover by reproducing
       the factory's P2TR construction (see channel_discover_funding_keyagg).
       Hard-fail if neither combination matches funding_spk — proceeding
       would leave on-chain spends unable to verify. */
    {
        musig_keyagg_t ka;
        uint32_t signer_idx;
        unsigned char merkle[32];
        int has_merkle = 0;
        if (!channel_discover_funding_keyagg(
                ctx, &my_pubkey, lsp_pubkey, lsp_pubkey,
                factory->cltv_timeout, state_node->cltv_timeout,
                funding_spk, funding_spk_len,
                &ka, &signer_idx, merkle, &has_merkle)) {
            fprintf(stderr,
                    "Client %u: funding_keyagg discovery failed for channel "
                    "(factory_cltv=%u, node_cltv=%u). Refusing to set up "
                    "channel — on-chain spends would fail Schnorr verify.\n",
                    my_index, factory->cltv_timeout, state_node->cltv_timeout);
            memset(my_seckey, 0, 32);
            return 0;
        }
        ch->funding_keyagg = ka;
        ch->local_funding_signer_idx = signer_idx;
        if (has_merkle) {
            memcpy(ch->chan_merkle_root, merkle, 32);
            ch->has_chan_merkle_root = 1;
        } else {
            ch->has_chan_merkle_root = 0;
        }
    }

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
                msg.msg_type == MSG_STATE_ADVANCE_PROPOSE ||
                msg.msg_type == MSG_STATE_ADV_PROPOSE_INTENT) {
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
            all_nonces_msg.msg_type == MSG_STATE_ADVANCE_PROPOSE ||
            all_nonces_msg.msg_type == MSG_STATE_ADV_PROPOSE_INTENT) {
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

/* Phase 1e.3.c (#271): client-side stateless factory-creation signing.

   Runs the reversed nonce/psig exchange for INITIAL factory creation, looped
   per NODE.  Called from client_run_with_channels after the client has built
   its factory from FACTORY_PROPOSE and run factory_sessions_init, when
   SS_MUSIG_STATELESS=1 and the LSP sent PROPOSE_INTENT (0x85).  On return the
   factory sessions are finalized + each node the client signs has its own
   partial sig sent to the LSP; the caller proceeds to recv FACTORY_READY
   exactly as the legacy path does.

   Per-node client secnonce is generated in the pubnonce phase and
   consumed/zeroed by musig_create_partial_sig before CLIENT_FINAL_PSIGS is
   sent, mirroring the validated sub-factory / leaf / state-advance client
   stateless paths.

   Returns 1 on success, 0 on failure. */
static int client_factory_creation_stateless_signing(
        int fd, secp256k1_context *ctx, const secp256k1_keypair *keypair,
        factory_t *factory, uint32_t my_index) {
    secp256k1_pubkey my_pubkey;
    secp256k1_keypair_pub(ctx, &my_pubkey, keypair);

    /* Recv PROPOSE_INTENT (0x85) -- begin reversed flow. */
    wire_msg_t imsg;
    if (!wire_recv_handle_ping(fd, &imsg, 0) || check_msg_error(&imsg) ||
        imsg.msg_type != MSG_FACTORY_PROPOSE_INTENT) {
        fprintf(stderr, "Client-stateless %u: expected PROPOSE_INTENT, got 0x%02x\n",
                my_index, imsg.json ? imsg.msg_type : 0);
        if (imsg.json) cJSON_Delete(imsg.json);
        return 0;
    }
    uint32_t intent_n_nodes = 0;
    if (!wire_parse_factory_propose_intent(imsg.json, &intent_n_nodes)) {
        fprintf(stderr, "Client-stateless %u: parse PROPOSE_INTENT failed\n", my_index);
        cJSON_Delete(imsg.json);
        return 0;
    }
    cJSON_Delete(imsg.json);
    if (intent_n_nodes != (uint32_t)factory->n_nodes) {
        fprintf(stderr, "Client-stateless %u: n_nodes mismatch (intent=%u local=%zu)\n",
                my_index, intent_n_nodes, factory->n_nodes);
        return 0;
    }

    size_t nn = factory->n_nodes;

    secp256k1_musig_secnonce *my_secnonces =
        calloc(nn, sizeof(secp256k1_musig_secnonce));
    int *my_slot = calloc(nn, sizeof(int));
    unsigned char *my_pn_per_node = calloc(nn, 66);
    if (!my_secnonces || !my_slot || !my_pn_per_node) {
        free(my_secnonces); free(my_slot); free(my_pn_per_node);
        return 0;
    }
    for (size_t i = 0; i < nn; i++) my_slot[i] = -1;

    unsigned char my_seckey[32];
    if (!secp256k1_keypair_sec(ctx, my_seckey, keypair)) {
        free(my_secnonces); free(my_slot); free(my_pn_per_node);
        return 0;
    }

    /* Step B: gen own per-node pubnonce for each node this client signs. */
    for (size_t nidx = 0; nidx < nn; nidx++) {
        int slot = factory_find_signer_slot(factory, nidx, my_index);
        if (slot < 0) continue;
        my_slot[nidx] = slot;
        secp256k1_musig_pubnonce my_pubnonce;
        if (!musig_generate_nonce(ctx, &my_secnonces[nidx], &my_pubnonce,
                                   my_seckey, &my_pubkey,
                                   &factory->nodes[nidx].keyagg.cache)) {
            fprintf(stderr, "Client-stateless %u: nonce gen node %zu failed\n", my_index, nidx);
            memset(my_seckey, 0, 32);
            free(my_secnonces); free(my_slot); free(my_pn_per_node);
            return 0;
        }
        musig_pubnonce_serialize(ctx, my_pn_per_node + nidx * 66, &my_pubnonce);
        if (!factory_session_set_nonce(factory, nidx, (size_t)slot, &my_pubnonce)) {
            fprintf(stderr, "Client-stateless %u: set own nonce node %zu failed\n", my_index, nidx);
            memset(my_seckey, 0, 32);
            free(my_secnonces); free(my_slot); free(my_pn_per_node);
            return 0;
        }
    }
    memset(my_seckey, 0, 32);

    /* Send CLIENT_PUBNONCES (per-node; unsigned nodes carry zero nonce). */
    {
        cJSON *cpn = wire_build_factory_client_pubnonces(my_pn_per_node, (uint32_t)nn);
        free(my_pn_per_node);
        if (!cpn || !wire_send(fd, MSG_FACTORY_CLIENT_PUBNONCES, cpn)) {
            fprintf(stderr, "Client-stateless %u: send CLIENT_PUBNONCES failed\n", my_index);
            if (cpn) cJSON_Delete(cpn);
            free(my_secnonces); free(my_slot);
            return 0;
        }
        cJSON_Delete(cpn);
    }

    /* Recv LSP_RESPONSE: per-node LSP nonces + psigs + full signer x node matrix. */
    wire_msg_t lr;
    if (!wire_recv(fd, &lr) || check_msg_error(&lr) ||
        lr.msg_type != MSG_FACTORY_LSP_RESPONSE) {
        fprintf(stderr, "Client-stateless %u: expected LSP_RESPONSE, got 0x%02x\n",
                my_index, lr.json ? lr.msg_type : 0);
        if (lr.json) cJSON_Delete(lr.json);
        free(my_secnonces); free(my_slot);
        return 0;
    }
    unsigned char *lsp_pn_per_node = calloc(nn, 66);
    unsigned char *lsp_psig_per_node = calloc(nn, 32);
    size_t mtx_stride = (size_t)FACTORY_MAX_SIGNERS * 66;
    unsigned char *all_pn = calloc(nn, mtx_stride);
    uint32_t got_matrix_len = 0;
    if (!lsp_pn_per_node || !lsp_psig_per_node || !all_pn) {
        cJSON_Delete(lr.json);
        free(lsp_pn_per_node); free(lsp_psig_per_node); free(all_pn);
        free(my_secnonces); free(my_slot);
        return 0;
    }
    if (!wire_parse_factory_lsp_response(lr.json, lsp_pn_per_node,
                                         lsp_psig_per_node, (uint32_t)nn,
                                         all_pn, (uint32_t)(nn * mtx_stride),
                                         &got_matrix_len)) {
        fprintf(stderr, "Client-stateless %u: parse LSP_RESPONSE failed\n", my_index);
        cJSON_Delete(lr.json);
        free(lsp_pn_per_node); free(lsp_psig_per_node); free(all_pn);
        free(my_secnonces); free(my_slot);
        return 0;
    }
    cJSON_Delete(lr.json);
    (void)lsp_psig_per_node;  /* LSP psigs are aggregated LSP-side, not by client. */

    int have_matrix = (got_matrix_len == (uint32_t)(nn * mtx_stride));

    /* For each node this client signs: set LSP nonce + every co-signer nonce
       from the matrix (skip own + LSP slots), finalize, create own psig. */
    for (size_t nidx = 0; nidx < nn; nidx++) {
        if (my_slot[nidx] < 0) continue;
        int lsp_slot = factory_find_signer_slot(factory, nidx, 0);
        if (lsp_slot < 0) {
            fprintf(stderr, "Client-stateless %u: no LSP slot node %zu\n", my_index, nidx);
            free(lsp_pn_per_node); free(lsp_psig_per_node); free(all_pn);
            free(my_secnonces); free(my_slot);
            return 0;
        }
        secp256k1_musig_pubnonce lsp_pn;
        if (!musig_pubnonce_parse(ctx, &lsp_pn, lsp_pn_per_node + nidx * 66) ||
            !factory_session_set_nonce(factory, nidx, (size_t)lsp_slot, &lsp_pn)) {
            fprintf(stderr, "Client-stateless %u: set LSP nonce node %zu failed\n", my_index, nidx);
            free(lsp_pn_per_node); free(lsp_psig_per_node); free(all_pn);
            free(my_secnonces); free(my_slot);
            return 0;
        }
        if (have_matrix) {
            size_t ns = factory->nodes[nidx].n_signers;
            for (size_t snum = 0; snum < ns; snum++) {
                if (snum == (size_t)my_slot[nidx] || snum == (size_t)lsp_slot) continue;
                const unsigned char *pn_ser =
                    all_pn + (nidx * (size_t)FACTORY_MAX_SIGNERS + snum) * 66;
                secp256k1_musig_pubnonce pn_s;
                if (!musig_pubnonce_parse(ctx, &pn_s, pn_ser) ||
                    !factory_session_set_nonce(factory, nidx, snum, &pn_s)) {
                    fprintf(stderr, "Client-stateless %u: set co-signer nonce node %zu slot %zu failed\n",
                            my_index, nidx, snum);
                    free(lsp_pn_per_node); free(lsp_psig_per_node); free(all_pn);
                    free(my_secnonces); free(my_slot);
                    return 0;
                }
            }
        }
        if (!factory_session_finalize_node(factory, nidx)) {
            fprintf(stderr, "Client-stateless %u: finalize_node %zu failed\n", my_index, nidx);
            free(lsp_pn_per_node); free(lsp_psig_per_node); free(all_pn);
            free(my_secnonces); free(my_slot);
            return 0;
        }
    }
    free(lsp_pn_per_node); free(lsp_psig_per_node); free(all_pn);

    /* Create own per-node psigs (zeroes each consumed secnonce). */
    unsigned char *my_psig_per_node = calloc(nn, 32);
    if (!my_psig_per_node) { free(my_secnonces); free(my_slot); return 0; }
    for (size_t nidx = 0; nidx < nn; nidx++) {
        if (my_slot[nidx] < 0) continue;
        secp256k1_musig_partial_sig my_psig;
        if (!musig_create_partial_sig(ctx, &my_psig, &my_secnonces[nidx],
                                       keypair,
                                       &factory->nodes[nidx].signing_session)) {
            fprintf(stderr, "Client-stateless %u: create_partial_sig node %zu failed\n", my_index, nidx);
            free(my_psig_per_node); free(my_secnonces); free(my_slot);
            return 0;
        }
        /* my_secnonces[nidx] zeroed by musig_create_partial_sig. */
        musig_partial_sig_serialize(ctx, my_psig_per_node + nidx * 32, &my_psig);
    }
    free(my_secnonces); free(my_slot);

    /* Send CLIENT_FINAL_PSIGS (per-node; unsigned nodes carry zero psig). */
    {
        cJSON *fp = wire_build_factory_client_final_psigs(my_psig_per_node, (uint32_t)nn);
        free(my_psig_per_node);
        if (!fp || !wire_send(fd, MSG_FACTORY_CLIENT_FINAL_PSIGS, fp)) {
            fprintf(stderr, "Client-stateless %u: send CLIENT_FINAL_PSIGS failed\n", my_index);
            if (fp) cJSON_Delete(fp);
            return 0;
        }
        cJSON_Delete(fp);
    }

    printf("Client-stateless %u: factory-creation signing done (%zu nodes)\n",
           my_index, nn);
    return 1;
}

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

    /* Receive HELLO_ACK.  Issue #3: LSP serial accept loop with N>=64
       clients can take >120s (default wire timeout) before our HELLO_ACK
       is sent.  10-minute window covers N=128 with 4s/client handshakes
       — bounded above by lsp->accept_timeout_sec on the LSP side. */
    wire_msg_t msg;
    if (!wire_recv_timeout(fd, &msg, 600) || check_msg_error(&msg) || msg.msg_type != MSG_HELLO_ACK) {
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
        /* SF-FUND-VERIFY-REFUSE #197: library-layer warning.  Hard refusal
           moved to the binary launch path in tools/superscalar_client.c
           (refuses startup on non-regtest networks without --rpcuser /
           --light-client).  Library callers that legitimately want to
           proceed without verification (in-process tests, regtest
           scaffolds) get this loud warning instead of an unconditional
           refusal. */
        fprintf(stderr, "Client: WARNING — funding TX NOT VERIFIED on-chain "
                "(no chain backend wired). Trusting LSP-supplied "
                "funding_amount of %llu sats. THIS IS UNSAFE ON ANY "
                "PRODUCTION NETWORK; see audit 2026-05-17.\n",
                (unsigned long long)funding_amount);
    }

    /* Build factory locally (heap — factory_t is ~3MB).
       SF-followup #145: factory ptr is registered with g_client_active_factory
       once it's initialized below, so MSG_FUNDING_REORG can find it. */
    factory_t *factory = calloc(1, sizeof(factory_t));
    if (!factory) return 0;
    factory_init_from_pubkeys(factory, ctx, all_pubkeys, n_participants,
                              step_blocks, states_per_layer);
    factory->cltv_timeout = cltv_timeout;
    factory->fee_per_tx = fee_per_tx;
    factory->placement_mode = (placement_mode_t)placement_mode;
    factory->economic_mode = (economic_mode_t)economic_mode;
    memcpy(factory->profiles, profiles, sizeof(profiles));
    /* SF-followup #145: register active factory so MSG_FUNDING_REORG handler
       can reset sub-factory chain state.  Cleared at all factory_free paths
       below. */
    g_client_active_factory = factory;

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

    /* Phase 1e.3.c (#271): stateless reversed-flow factory creation.  When
       SS_MUSIG_STATELESS=1 the LSP sends PROPOSE_INTENT (0x85) after
       FACTORY_PROPOSE; run the per-node reversed signing, then converge at the
       FACTORY_READY recv (post-creation steps unchanged).  The legacy
       round-1-first nonce/psig path is wrapped in the else branch so its
       function-scope locals stay confined. */
    int ss_stateless_creation = 0;
    {
        /* Phase 2 (#272): stateless is default-on; SS_MUSIG_LEGACY=1 opts out. */
        const char *legacy = getenv("SS_MUSIG_LEGACY");
        ss_stateless_creation = !(legacy && legacy[0] == '1');
    }
    /* Hoisted to function scope so done:/fail: can free it on either path.
       The stateless path leaves it NULL (free(NULL) is a no-op). */
    wire_bundle_entry_t *nonce_entries = NULL;
    if (ss_stateless_creation) {
        if (!client_factory_creation_stateless_signing(fd, ctx, keypair,
                                                        factory, my_index))
            goto fail;
    } else {
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
    nonce_entries =
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
    }  /* end else (legacy round-1-first nonce/psig path) */

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
    /* SF-followup #145: register active factory for MSG_FUNDING_REORG reset
       (mirror of LSP-side #208). */
    g_client_active_factory = factory;

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
    /* Parse REALLOC_PROPOSE (state + optional poison nonce) */
    int leaf_side;
    uint64_t amounts[FACTORY_MAX_OUTPUTS];
    size_t n_amounts;
    unsigned char lsp_pubnonce_ser[66], lsp_poison_pn_ser[66];

    int propose_rc = wire_parse_leaf_realloc_propose(propose_msg->json, &leaf_side,
                                                       amounts, FACTORY_MAX_OUTPUTS,
                                                       &n_amounts, lsp_pubnonce_ser,
                                                       lsp_poison_pn_ser);
    if (propose_rc == 0) {
        fprintf(stderr, "Client %u: failed to parse REALLOC_PROPOSE\n", my_index);
        return 0;
    }
    int wire_poison_offered = (propose_rc == 2);

    /* Snapshot OLD leaf state BEFORE the realloc — needed to deterministically
       prep the wire-ceremony poison TX in lockstep with the LSP. */
    if (leaf_side < 0 || leaf_side >= factory->n_leaf_nodes) return 0;
    size_t pre_node_idx_r = factory->leaf_node_indices[leaf_side];
    factory_node_t *pre_leaf_r = &factory->nodes[pre_node_idx_r];
    unsigned char pre_old_leaf_txid_r[32];
    memcpy(pre_old_leaf_txid_r, pre_leaf_r->txid, 32);
    int pre_old_n_outputs_r = pre_leaf_r->n_outputs;
    uint64_t pre_old_l_amount_r = (pre_old_n_outputs_r >= 2)
                                  ? pre_leaf_r->outputs[pre_old_n_outputs_r - 1].amount_sats
                                  : 0;
    int pre_had_signed_r = (pre_leaf_r->is_signed && pre_leaf_r->signed_tx.len > 0);

    const uint64_t REALLOC_POISON_FEE_SATS = 1000;
    int realloc_poison_prepared = 0;
    if (wire_poison_offered && pre_had_signed_r && pre_old_n_outputs_r >= 2 &&
        pre_old_l_amount_r > REALLOC_POISON_FEE_SATS +
                             (uint64_t)(pre_leaf_r->n_signers - 1) * 330u) {
        if (factory_session_prepare_poison_tx_leaf(
                factory, pre_node_idx_r,
                pre_old_leaf_txid_r, (uint32_t)(pre_old_n_outputs_r - 1),
                pre_old_l_amount_r, REALLOC_POISON_FEE_SATS)) {
            realloc_poison_prepared = 1;
        }
    }

    /* Advance local DW + set amounts */
    int rc = factory_advance_leaf_unsigned(factory, leaf_side);
    if (rc <= 0) {
        fprintf(stderr, "Client %u: leaf advance for realloc failed\n", my_index);
        factory_session_reset_poison(factory, pre_node_idx_r);
        return 0;
    }
    if (!factory_set_leaf_amounts(factory, leaf_side, amounts, n_amounts)) {
        fprintf(stderr, "Client %u: set_leaf_amounts failed\n", my_index);
        factory_session_reset_poison(factory, pre_node_idx_r);
        return 0;
    }

    size_t node_idx = factory->leaf_node_indices[leaf_side];

    /* Init both signing sessions */
    if (!factory_session_init_node(factory, node_idx)) {
        fprintf(stderr, "Client %u: realloc state session_init_node failed (node %zu)\n",
                my_index, node_idx);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }
    if (realloc_poison_prepared &&
        !factory_session_init_node_poison(factory, node_idx)) {
        fprintf(stderr, "Client %u: realloc poison session_init failed — degrading\n", my_index);
        factory_session_reset_poison(factory, node_idx);
        realloc_poison_prepared = 0;
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

    /* Set LSP nonces (state + poison if offered) */
    int lsp_slot_r = factory_find_signer_slot(factory, node_idx, 0);
    if (lsp_slot_r < 0) {
        memset(my_seckey, 0, 32);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }
    /* (LSP nonce will be set via ALL_NONCES below — same as before) */

    secp256k1_pubkey my_pubkey;
    secp256k1_keypair_pub(ctx, &my_pubkey, keypair);

    secp256k1_musig_secnonce my_secnonce, my_poison_secnonce;
    secp256k1_musig_pubnonce my_pubnonce, my_poison_pubnonce;
    if (!musig_generate_nonce(ctx, &my_secnonce, &my_pubnonce,
                               my_seckey, &my_pubkey,
                               &factory->nodes[node_idx].keyagg.cache)) {
        fprintf(stderr, "Client %u: realloc state nonce_gen failed\n", my_index);
        memset(my_seckey, 0, 32);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }
    if (realloc_poison_prepared &&
        !musig_generate_nonce(ctx, &my_poison_secnonce, &my_poison_pubnonce,
                                my_seckey, &my_pubkey,
                                &factory->nodes[node_idx].keyagg.cache)) {
        fprintf(stderr, "Client %u: realloc poison nonce_gen failed — degrading\n", my_index);
        factory_session_reset_poison(factory, node_idx);
        realloc_poison_prepared = 0;
    }

    /* Send REALLOC_NONCE (state + optional poison) */
    unsigned char my_pubnonce_ser[66], my_poison_pn_ser[66];
    musig_pubnonce_serialize(ctx, my_pubnonce_ser, &my_pubnonce);
    if (realloc_poison_prepared)
        musig_pubnonce_serialize(ctx, my_poison_pn_ser, &my_poison_pubnonce);
    cJSON *nonce_msg = wire_build_leaf_realloc_nonce(
        my_pubnonce_ser, realloc_poison_prepared ? my_poison_pn_ser : NULL);
    if (!wire_send(fd, MSG_LEAF_REALLOC_NONCE, nonce_msg)) {
        fprintf(stderr, "Client %u: realloc send NONCE failed\n", my_index);
        cJSON_Delete(nonce_msg);
        memset(my_seckey, 0, 32);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }
    cJSON_Delete(nonce_msg);

    /* Receive REALLOC_ALL_NONCES (state + optional poison) */
    wire_msg_t all_msg;
    if (!wire_recv(fd, &all_msg) || all_msg.msg_type != MSG_LEAF_REALLOC_ALL_NONCES) {
        fprintf(stderr, "Client %u: expected REALLOC_ALL_NONCES, got 0x%02x\n",
                my_index, all_msg.msg_type);
        if (all_msg.json) cJSON_Delete(all_msg.json);
        memset(my_seckey, 0, 32);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }

    unsigned char all_pubnonces[FACTORY_MAX_SIGNERS][66];
    unsigned char all_poison_pubnonces[FACTORY_MAX_SIGNERS][66];
    size_t n_signers;
    int an_parse_rc = wire_parse_leaf_realloc_all_nonces(
        all_msg.json, all_pubnonces,
        realloc_poison_prepared ? all_poison_pubnonces : NULL,
        FACTORY_MAX_SIGNERS, &n_signers);
    cJSON_Delete(all_msg.json);
    if (an_parse_rc == 0) {
        fprintf(stderr, "Client %u: realloc parse all_nonces failed\n", my_index);
        memset(my_seckey, 0, 32);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }
    if (realloc_poison_prepared && an_parse_rc < 2) {
        factory_session_reset_poison(factory, node_idx);
        realloc_poison_prepared = 0;
    }

    /* Set all nonces (state + poison if prepared) */
    for (size_t i = 0; i < n_signers; i++) {
        secp256k1_musig_pubnonce pn;
        if (!musig_pubnonce_parse(ctx, &pn, all_pubnonces[i])) {
            fprintf(stderr, "Client %u: realloc parse nonce[%zu] failed\n", my_index, i);
            memset(my_seckey, 0, 32);
            factory_session_reset_poison(factory, node_idx);
            return 0;
        }
        if (!factory_session_set_nonce(factory, node_idx, i, &pn)) {
            fprintf(stderr, "Client %u: realloc set_nonce[%zu] failed\n", my_index, i);
            memset(my_seckey, 0, 32);
            factory_session_reset_poison(factory, node_idx);
            return 0;
        }
        if (realloc_poison_prepared) {
            secp256k1_musig_pubnonce ppn;
            if (!musig_pubnonce_parse(ctx, &ppn, all_poison_pubnonces[i]) ||
                !factory_session_set_nonce_poison(factory, node_idx, i, &ppn)) {
                fprintf(stderr, "Client %u: realloc poison set_nonce[%zu] failed — degrading\n",
                        my_index, i);
                factory_session_reset_poison(factory, node_idx);
                realloc_poison_prepared = 0;
            }
        }
    }

    /* Finalize both sessions */
    if (!factory_session_finalize_node(factory, node_idx)) {
        fprintf(stderr, "Client %u: realloc state session_finalize failed (node %zu)\n",
                my_index, node_idx);
        memset(my_seckey, 0, 32);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }
    if (realloc_poison_prepared &&
        !factory_session_finalize_node_poison(factory, node_idx)) {
        fprintf(stderr, "Client %u: realloc poison session_finalize failed — degrading\n", my_index);
        factory_session_reset_poison(factory, node_idx);
        realloc_poison_prepared = 0;
    }

    /* Create partial sigs (state + poison if prepared) */
    secp256k1_musig_partial_sig my_psig, my_poison_psig;
    if (!musig_create_partial_sig(ctx, &my_psig, &my_secnonce, keypair,
                                    &factory->nodes[node_idx].signing_session)) {
        fprintf(stderr, "Client %u: realloc state partial_sig creation failed\n", my_index);
        memset(my_seckey, 0, 32);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }
    if (realloc_poison_prepared &&
        !musig_create_partial_sig(ctx, &my_poison_psig, &my_poison_secnonce, keypair,
                                    &factory->nodes[node_idx].poison_signing_session)) {
        fprintf(stderr, "Client %u: realloc poison partial_sig creation failed — degrading\n",
                my_index);
        factory_session_reset_poison(factory, node_idx);
        realloc_poison_prepared = 0;
    }
    memset(my_seckey, 0, 32);

    /* Send REALLOC_PSIG (state + poison if prepared) */
    unsigned char my_psig_ser[32], my_poison_psig_ser[32];
    musig_partial_sig_serialize(ctx, my_psig_ser, &my_psig);
    if (realloc_poison_prepared)
        musig_partial_sig_serialize(ctx, my_poison_psig_ser, &my_poison_psig);
    cJSON *psig_json = wire_build_leaf_realloc_psig(
        my_psig_ser, realloc_poison_prepared ? my_poison_psig_ser : NULL);
    if (!wire_send(fd, MSG_LEAF_REALLOC_PSIG, psig_json)) {
        fprintf(stderr, "Client %u: realloc wire_send PSIG failed\n", my_index);
        cJSON_Delete(psig_json);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }
    cJSON_Delete(psig_json);
    factory_session_reset_poison(factory, node_idx);

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
/* Phase 1e.1.c: client-side stateless subfactory advance.  Dispatched
   from the public function when SS_MUSIG_STATELESS=1 and the LSP sent a
   PROPOSE_INTENT (new opcode 0x7D) instead of legacy PROPOSE (0x73). */
/* Phase 1e.1.e: MULTI-INPUT stateless sub-factory advance (client side).
   Mirrors client_handle_subfactory_advance_stateless looped per input.
   STATELESS INVARIANT: each per-input client secnonce is generated once and
   consumed/zeroed by musig_create_partial_sig before the DONE recv. */
static int client_handle_subfactory_advance_stateless_multi(
        int fd, secp256k1_context *ctx, const secp256k1_keypair *keypair,
        factory_t *factory, uint32_t my_index, size_t sub_node_i,
        factory_node_t *sub, uint32_t n_inputs_u,
        int leaf_side, int sub_idx, int channel_idx, uint64_t delta_sats) {
    size_t n_inputs = (size_t)n_inputs_u;
    if (n_inputs < 1) {
        fprintf(stderr, "Client-stateless MULTI %u: n_inputs=%zu invalid\n",
                my_index, n_inputs);
        return 0;
    }

    /* Poison prep (deterministic; single-input side-channel mirroring the LSP).
       Snapshot the OLD chain[N-1] state BEFORE advance_unsigned mutates it. */
    const uint64_t POISON_FEE_SATS = 1000;
    int poison_prepared_c = 0;
    {
        size_t old_n_chans = (sub->n_outputs > 0) ? sub->n_outputs - 1 : 0;
        uint64_t old_sstock = (sub->n_outputs > 0)
            ? sub->outputs[sub->n_outputs - 1].amount_sats : 0;
        if (old_sstock > POISON_FEE_SATS + (uint64_t)old_n_chans * 330u) {
            unsigned char old_chain_txid[32];
            memcpy(old_chain_txid, sub->txid, 32);
            if (factory_session_prepare_poison_tx_subfactory(
                    factory, sub_node_i, old_chain_txid, (uint32_t)old_n_chans,
                    old_sstock, POISON_FEE_SATS))
                poison_prepared_c = 1;
        }
    }

    /* Apply the advance locally so unsigned_tx matches the LSP deterministically. */
    if (!factory_subfactory_chain_advance_unsigned(factory, leaf_side, sub_idx,
                                                     channel_idx, delta_sats)) {
        fprintf(stderr, "Client-stateless MULTI %u: chain_advance_unsigned failed\n",
                my_index);
        factory_session_reset_poison(factory, sub_node_i);
        return 0;
    }

    /* Init one state session per input + (when prepared) poison session. */
    for (size_t i = 0; i < n_inputs; i++) {
        if (!factory_session_init_node_input(factory, sub_node_i, i)) {
            fprintf(stderr, "Client-stateless MULTI %u: init input %zu failed\n",
                    my_index, i);
            factory_session_reset_poison(factory, sub_node_i);
            return 0;
        }
    }
    if (poison_prepared_c &&
        !factory_session_init_node_poison(factory, sub_node_i)) {
        factory_session_reset_poison(factory, sub_node_i);
        poison_prepared_c = 0;
    }

    int my_slot = factory_find_signer_slot(factory, sub_node_i, my_index);
    int lsp_slot = factory_find_signer_slot(factory, sub_node_i, 0);
    if (my_slot < 0 || lsp_slot < 0) {
        fprintf(stderr, "Client-stateless MULTI %u: slot lookup failed (my=%d lsp=%d)\n",
                my_index, my_slot, lsp_slot);
        return 0;
    }

    /* Gen own per-input secnonces + pubnonces; set own nonce on each input. */
    unsigned char my_seckey[32];
    secp256k1_pubkey my_pubkey;
    if (!secp256k1_keypair_sec(ctx, my_seckey, keypair)) {
        fprintf(stderr, "Client-stateless MULTI %u: keypair_sec failed\n", my_index);
        return 0;
    }
    secp256k1_keypair_pub(ctx, &my_pubkey, keypair);

    secp256k1_musig_secnonce *my_secnonces =
        calloc(n_inputs, sizeof(secp256k1_musig_secnonce));
    unsigned char *my_pn_flat = calloc(n_inputs, 66);
    if (!my_secnonces || !my_pn_flat) {
        memset(my_seckey, 0, 32);
        free(my_secnonces); free(my_pn_flat);
        return 0;
    }
    for (size_t i = 0; i < n_inputs; i++) {
        secp256k1_musig_pubnonce my_pubnonce_i;
        if (!musig_generate_nonce(ctx, &my_secnonces[i], &my_pubnonce_i,
                                   my_seckey, &my_pubkey, &sub->keyagg.cache)) {
            fprintf(stderr, "Client-stateless MULTI %u: nonce gen input %zu failed\n",
                    my_index, i);
            memset(my_seckey, 0, 32);
            free(my_secnonces); free(my_pn_flat);
            return 0;
        }
        musig_pubnonce_serialize(ctx, my_pn_flat + i * 66, &my_pubnonce_i);
        if (!factory_session_set_nonce_input(factory, sub_node_i, i,
                                             (size_t)my_slot, &my_pubnonce_i)) {
            fprintf(stderr, "Client-stateless MULTI %u: set own nonce input %zu failed\n",
                    my_index, i);
            memset(my_seckey, 0, 32);
            free(my_secnonces); free(my_pn_flat);
            factory_session_reset_poison(factory, sub_node_i);
            return 0;
        }
    }

    /* Poison (single-input side-channel): gen own poison secnonce + set own
       poison nonce while my_seckey is still live. */
    secp256k1_musig_secnonce my_poison_secnonce;
    unsigned char my_poison_pn_ser[66] = {0};
    if (poison_prepared_c) {
        secp256k1_musig_pubnonce my_poison_pubnonce;
        if (!musig_generate_nonce(ctx, &my_poison_secnonce, &my_poison_pubnonce,
                                    my_seckey, &my_pubkey, &sub->keyagg.cache) ||
            !factory_session_set_nonce_poison(factory, sub_node_i,
                                                (size_t)my_slot, &my_poison_pubnonce)) {
            memset(&my_poison_secnonce, 0, sizeof(my_poison_secnonce));
            factory_session_reset_poison(factory, sub_node_i);
            poison_prepared_c = 0;
        } else {
            musig_pubnonce_serialize(ctx, my_poison_pn_ser, &my_poison_pubnonce);
        }
    }
    memset(my_seckey, 0, 32);

    /* Send CLIENT_PUBNONCES with n_inputs own pubnonces (+ poison nonce). */
    cJSON *cpn_json = wire_build_subfactory_client_pubnonces(
        my_pn_flat, (uint32_t)n_inputs, poison_prepared_c ? my_poison_pn_ser : NULL);
    free(my_pn_flat);
    if (!wire_send(fd, MSG_SUBFACTORY_CLIENT_PUBNONCES, cpn_json)) {
        cJSON_Delete(cpn_json);
        fprintf(stderr, "Client-stateless MULTI %u: send CLIENT_PUBNONCES failed\n", my_index);
        if (poison_prepared_c) memset(&my_poison_secnonce, 0, sizeof(my_poison_secnonce));
        free(my_secnonces);
        factory_session_reset_poison(factory, sub_node_i);
        return 0;
    }
    cJSON_Delete(cpn_json);

    /* Wait for LSP_RESPONSE (per-input LSP nonces + psigs + signer x input matrix). */
    wire_msg_t lr_msg;
    if (!wire_recv(fd, &lr_msg) || lr_msg.msg_type != MSG_SUBFACTORY_LSP_RESPONSE) {
        fprintf(stderr, "Client-stateless MULTI %u: expected LSP_RESPONSE, got 0x%02x\n",
                my_index, lr_msg.json ? lr_msg.msg_type : 0);
        if (lr_msg.json) cJSON_Delete(lr_msg.json);
        if (poison_prepared_c) memset(&my_poison_secnonce, 0, sizeof(my_poison_secnonce));
        free(my_secnonces);
        factory_session_reset_poison(factory, sub_node_i);
        return 0;
    }
    unsigned char *lsp_pn_flat = calloc(n_inputs, 66);
    unsigned char *lsp_psig_flat = calloc(n_inputs, 32);
    /* all_pn_per_input: signer x input matrix, same layout as LSP. */
    size_t matrix_len = sub->n_signers * n_inputs * 66;
    unsigned char *all_pn_per_input = calloc(sub->n_signers * n_inputs, 66);
    if (!lsp_pn_flat || !lsp_psig_flat || !all_pn_per_input) {
        cJSON_Delete(lr_msg.json);
        free(lsp_pn_flat); free(lsp_psig_flat); free(all_pn_per_input);
        free(my_secnonces);
        return 0;
    }
    unsigned char all_poison_pn_sub[FACTORY_MAX_SIGNERS][66];
    unsigned char lsp_poison_psig_ser[32];
    uint32_t got_all_len = 0, got_poison_len = 0;
    memset(all_poison_pn_sub, 0, sizeof(all_poison_pn_sub));
    int lr_rc = wire_parse_subfactory_lsp_response(lr_msg.json, lsp_pn_flat, lsp_psig_flat,
                                              (uint32_t)n_inputs,
                                              all_pn_per_input, (uint32_t)matrix_len,
                                              &got_all_len,
                                              poison_prepared_c ? (unsigned char *)all_poison_pn_sub : NULL,
                                              poison_prepared_c ? (uint32_t)sizeof(all_poison_pn_sub) : 0,
                                              poison_prepared_c ? &got_poison_len : NULL,
                                              poison_prepared_c ? lsp_poison_psig_ser : NULL);
    if (lr_rc == 0) {
        cJSON_Delete(lr_msg.json);
        free(lsp_pn_flat); free(lsp_psig_flat); free(all_pn_per_input);
        if (poison_prepared_c) memset(&my_poison_secnonce, 0, sizeof(my_poison_secnonce));
        free(my_secnonces);
        factory_session_reset_poison(factory, sub_node_i);
        fprintf(stderr, "Client-stateless MULTI %u: parse LSP_RESPONSE failed\n", my_index);
        return 0;
    }
    cJSON_Delete(lr_msg.json);
    int have_matrix = (got_all_len == (uint32_t)matrix_len);
    if (poison_prepared_c &&
        (lr_rc < 2 || got_poison_len != (uint32_t)(sub->n_signers * 66))) {
        fprintf(stderr, "Client-stateless MULTI %u: LSP omitted poison fields -- "
                "degrading\n", my_index);
        memset(&my_poison_secnonce, 0, sizeof(my_poison_secnonce));
        factory_session_reset_poison(factory, sub_node_i);
        poison_prepared_c = 0;
    }

    /* Per input: set LSP nonce + every other co-signer's nonce (skip own and
       LSP slots, exactly like single-input), finalize, sign (zeros secnonce). */
    unsigned char *my_psig_flat = calloc(n_inputs, 32);
    if (!my_psig_flat) {
        free(lsp_pn_flat); free(lsp_psig_flat); free(all_pn_per_input);
        free(my_secnonces);
        return 0;
    }
    for (size_t i = 0; i < n_inputs; i++) {
        secp256k1_musig_pubnonce lsp_pubnonce_i;
        if (!musig_pubnonce_parse(ctx, &lsp_pubnonce_i, lsp_pn_flat + i * 66) ||
            !factory_session_set_nonce_input(factory, sub_node_i, i,
                                             (size_t)lsp_slot, &lsp_pubnonce_i)) {
            fprintf(stderr, "Client-stateless MULTI %u: set LSP nonce input %zu failed\n",
                    my_index, i);
            goto fail;
        }
        if (have_matrix) {
            for (size_t scs = 0; scs < sub->n_signers; scs++) {
                if (scs == (size_t)my_slot || scs == (size_t)lsp_slot) continue;
                secp256k1_musig_pubnonce pn_s;
                if (!musig_pubnonce_parse(ctx, &pn_s,
                        all_pn_per_input + (scs * n_inputs + i) * 66) ||
                    !factory_session_set_nonce_input(factory, sub_node_i, i, scs, &pn_s)) {
                    fprintf(stderr,
                            "Client-stateless MULTI %u: set co-signer nonce[%zu] input %zu failed\n",
                            my_index, scs, i);
                    goto fail;
                }
            }
        }
        if (!factory_session_finalize_node_input(factory, sub_node_i, i)) {
            fprintf(stderr, "Client-stateless MULTI %u: finalize input %zu failed\n",
                    my_index, i);
            goto fail;
        }
        secp256k1_musig_partial_sig my_psig_i;
        if (!musig_create_partial_sig(ctx, &my_psig_i, &my_secnonces[i], keypair,
                                       &sub->input_signing_sessions[i])) {
            fprintf(stderr, "Client-stateless MULTI %u: create_partial_sig input %zu failed\n",
                    my_index, i);
            goto fail;
        }
        /* my_secnonces[i] zeroed by musig_create_partial_sig. */
        musig_partial_sig_serialize(ctx, my_psig_flat + i * 32, &my_psig_i);
    }

    /* Poison (single-input): set every signer's poison nonce from the forwarded
       matrix (own already set), finalize, create own poison psig (zeros the
       poison secnonce before the DONE recv). */
    unsigned char my_poison_psig_ser[32] = {0};
    if (poison_prepared_c) {
        int pz_ok = 1;
        for (size_t scs = 0; scs < sub->n_signers && pz_ok; scs++) {
            if (scs == (size_t)my_slot) continue;  /* own already set */
            secp256k1_musig_pubnonce ppn;
            if (!musig_pubnonce_parse(ctx, &ppn, all_poison_pn_sub[scs]) ||
                !factory_session_set_nonce_poison(factory, sub_node_i, scs, &ppn))
                pz_ok = 0;
        }
        secp256k1_musig_partial_sig my_poison_psig;
        pz_ok = pz_ok &&
            factory_session_finalize_node_poison(factory, sub_node_i) &&
            musig_create_partial_sig(ctx, &my_poison_psig, &my_poison_secnonce,
                                       keypair, &sub->poison_signing_session);
        memset(&my_poison_secnonce, 0, sizeof(my_poison_secnonce));
        if (!pz_ok) {
            fprintf(stderr, "Client-stateless MULTI %u: poison sign failed -- "
                    "degrading\n", my_index);
            factory_session_reset_poison(factory, sub_node_i);
            poison_prepared_c = 0;
        } else {
            musig_partial_sig_serialize(ctx, my_poison_psig_ser, &my_poison_psig);
        }
    }

    free(lsp_pn_flat); free(lsp_psig_flat); free(all_pn_per_input);
    free(my_secnonces);  /* all entries already zeroed by create_partial_sig */

    /* Send CLIENT_FINAL_PSIGS with n_inputs psigs (+ poison psig). */
    cJSON *fp_json = wire_build_subfactory_client_final_psigs(
        my_psig_flat, (uint32_t)n_inputs, poison_prepared_c ? my_poison_psig_ser : NULL);
    free(my_psig_flat);
    if (!wire_send(fd, MSG_SUBFACTORY_CLIENT_FINAL_PSIGS, fp_json)) {
        cJSON_Delete(fp_json);
        fprintf(stderr, "Client-stateless MULTI %u: send CLIENT_FINAL_PSIGS failed\n", my_index);
        factory_session_reset_poison(factory, sub_node_i);
        return 0;
    }
    cJSON_Delete(fp_json);
    if (poison_prepared_c) factory_session_reset_poison(factory, sub_node_i);

    /* Wait for DONE. */
    wire_msg_t done_msg;
    if (!wire_recv(fd, &done_msg) || done_msg.msg_type != MSG_SUBFACTORY_DONE) {
        fprintf(stderr, "Client-stateless MULTI %u: expected DONE, got 0x%02x\n",
                my_index, done_msg.json ? done_msg.msg_type : 0);
        if (done_msg.json) cJSON_Delete(done_msg.json);
        return 0;
    }
    if (done_msg.json) cJSON_Delete(done_msg.json);

    printf("Client-stateless subfactory MULTI-INPUT %u: advance done (sub_node=%zu, n_inputs=%zu)\n",
           my_index, sub_node_i, n_inputs);
    return 1;

fail:
    free(lsp_pn_flat); free(lsp_psig_flat); free(all_pn_per_input);
    free(my_secnonces); free(my_psig_flat);
    if (poison_prepared_c) memset(&my_poison_secnonce, 0, sizeof(my_poison_secnonce));
    factory_session_reset_poison(factory, sub_node_i);
    return 0;
}

static int client_handle_subfactory_advance_stateless(int fd,
                                                        secp256k1_context *ctx,
                                                        const secp256k1_keypair *keypair,
                                                        factory_t *factory,
                                                        uint32_t my_index,
                                                        const wire_msg_t *propose_msg) {
    uint32_t sub_node_id, n_inputs;
    int leaf_side, sub_idx, channel_idx;
    uint64_t delta_sats;
    if (!wire_parse_subfactory_propose_intent(propose_msg->json,
                                                 &sub_node_id, &n_inputs,
                                                 &leaf_side, &sub_idx, &channel_idx,
                                                 &delta_sats)) {
        fprintf(stderr, "Client-stateless subfactory %u: parse PROPOSE_INTENT failed\n",
                my_index);
        return 0;
    }
    if (sub_node_id >= factory->n_nodes) {
        fprintf(stderr, "Client-stateless subfactory %u: bad sub_node_id %u\n",
                my_index, sub_node_id);
        return 0;
    }
    size_t sub_node_i = (size_t)sub_node_id;
    factory_node_t *sub = &factory->nodes[sub_node_i];

    /* Phase 1e.1.e: MULTI-INPUT now runs through the STATELESS path too.
       Dispatch to the looped-per-input handler; single-input keeps the
       existing flow below. */
    if (n_inputs > 1) {
        return client_handle_subfactory_advance_stateless_multi(
            fd, ctx, keypair, factory, my_index, sub_node_i, sub,
            n_inputs, leaf_side, sub_idx, channel_idx, delta_sats);
    }

    /* k>=2 (multi-client sub-factory) is supported: the LSP forwards the full
       all-signer pubnonce matrix in LSP_RESPONSE (Gap A), and the co-signer
       nonce loop below sets every other signer's nonce before finalize. The
       client sends its CLIENT_FINAL_PSIGS for the LSP to aggregate (no local
       complete, so no Gap B needed). Matching LSP-side refusal removed in
       d7bdfe4. */

    /* Poison prep (deterministic; matches the LSP minus the watchtower gate,
       which is LSP-only): snapshot the soon-to-be-stale chain[N-1] state
       BEFORE advance_unsigned mutates sub->txid / sub->outputs[], then build
       the same single-input L-stock poison TX so both sides reach a
       byte-identical sighash.  poison_prepared_c is cleared if anything
       degrades or the LSP fails to reciprocate poison fields. */
    const uint64_t POISON_FEE_SATS = 1000;
    int poison_prepared_c = 0;
    {
        size_t old_n_chans = (sub->n_outputs > 0) ? sub->n_outputs - 1 : 0;
        uint64_t old_sstock = (sub->n_outputs > 0)
            ? sub->outputs[sub->n_outputs - 1].amount_sats : 0;
        if (old_sstock > POISON_FEE_SATS + (uint64_t)old_n_chans * 330u) {
            unsigned char old_chain_txid[32];
            memcpy(old_chain_txid, sub->txid, 32);
            if (factory_session_prepare_poison_tx_subfactory(
                    factory, sub_node_i, old_chain_txid, (uint32_t)old_n_chans,
                    old_sstock, POISON_FEE_SATS)) {
                poison_prepared_c = 1;  /* init_node_poison after state init */
            }
        }
    }

    /* Phase 1e.1.b amendment: PROPOSE_INTENT now carries the advance params
       (leaf_side, sub_idx, channel_idx, delta_sats).  Apply the advance
       locally so unsigned_tx matches LSP's deterministically. */
    if (!factory_subfactory_chain_advance_unsigned(factory, leaf_side, sub_idx,
                                                     channel_idx, delta_sats)) {
        fprintf(stderr,
            "Client-stateless subfactory %u: chain_advance_unsigned failed "
            "(leaf=%d sub=%d ch=%d delta=%llu)\n",
            my_index, leaf_side, sub_idx, channel_idx,
            (unsigned long long)delta_sats);
        factory_session_reset_poison(factory, sub_node_i);
        return 0;
    }

    /* Init state session + (when prepared) poison session. */
    if (!factory_session_init_node(factory, sub_node_i)) {
        fprintf(stderr, "Client-stateless subfactory %u: session_init failed\n", my_index);
        factory_session_reset_poison(factory, sub_node_i);
        return 0;
    }
    if (poison_prepared_c &&
        !factory_session_init_node_poison(factory, sub_node_i)) {
        factory_session_reset_poison(factory, sub_node_i);
        poison_prepared_c = 0;
    }

    int my_slot = factory_find_signer_slot(factory, sub_node_i, my_index);
    int lsp_slot = factory_find_signer_slot(factory, sub_node_i, 0);
    if (my_slot < 0 || lsp_slot < 0) {
        fprintf(stderr, "Client-stateless subfactory %u: slot lookup failed (my=%d lsp=%d)\n",
                my_index, my_slot, lsp_slot);
        return 0;
    }

    /* Gen own secnonce + pubnonce. */
    unsigned char my_seckey[32];
    secp256k1_pubkey my_pubkey;
    if (!secp256k1_keypair_sec(ctx, my_seckey, keypair)) {
        fprintf(stderr, "Client-stateless subfactory %u: keypair_sec failed\n", my_index);
        return 0;
    }
    secp256k1_keypair_pub(ctx, &my_pubkey, keypair);

    secp256k1_musig_secnonce my_secnonce, my_poison_secnonce;
    secp256k1_musig_pubnonce my_pubnonce;
    if (!musig_generate_nonce(ctx, &my_secnonce, &my_pubnonce,
                                my_seckey, &my_pubkey,
                                &sub->keyagg.cache)) {
        memset(my_seckey, 0, 32);
        fprintf(stderr, "Client-stateless subfactory %u: nonce gen failed\n", my_index);
        factory_session_reset_poison(factory, sub_node_i);
        return 0;
    }
    /* Poison: own nonce (my_seckey still live this scope). */
    unsigned char my_poison_pn_ser[66] = {0};
    if (poison_prepared_c) {
        secp256k1_musig_pubnonce my_poison_pubnonce;
        if (!musig_generate_nonce(ctx, &my_poison_secnonce, &my_poison_pubnonce,
                                    my_seckey, &my_pubkey, &sub->keyagg.cache) ||
            !factory_session_set_nonce_poison(factory, sub_node_i,
                                                (size_t)my_slot, &my_poison_pubnonce)) {
            memset(&my_poison_secnonce, 0, sizeof(my_poison_secnonce));
            factory_session_reset_poison(factory, sub_node_i);
            poison_prepared_c = 0;
        } else {
            musig_pubnonce_serialize(ctx, my_poison_pn_ser, &my_poison_pubnonce);
        }
    }
    memset(my_seckey, 0, 32);
    if (!factory_session_set_nonce(factory, sub_node_i, (size_t)my_slot, &my_pubnonce)) {
        fprintf(stderr, "Client-stateless subfactory %u: set own nonce failed\n", my_index);
        if (poison_prepared_c) memset(&my_poison_secnonce, 0, sizeof(my_poison_secnonce));
        factory_session_reset_poison(factory, sub_node_i);
        return 0;
    }

    /* Send CLIENT_PUBNONCES with own pubnonce (+ poison nonce when prepared). */
    unsigned char my_pubnonce_ser[66];
    musig_pubnonce_serialize(ctx, my_pubnonce_ser, &my_pubnonce);
    cJSON *cpn_json = wire_build_subfactory_client_pubnonces(
        my_pubnonce_ser, 1, poison_prepared_c ? my_poison_pn_ser : NULL);
    if (!wire_send(fd, MSG_SUBFACTORY_CLIENT_PUBNONCES, cpn_json)) {
        cJSON_Delete(cpn_json);
        fprintf(stderr, "Client-stateless subfactory %u: send CLIENT_PUBNONCES failed\n",
                my_index);
        if (poison_prepared_c) memset(&my_poison_secnonce, 0, sizeof(my_poison_secnonce));
        factory_session_reset_poison(factory, sub_node_i);
        return 0;
    }
    cJSON_Delete(cpn_json);

    /* Wait for LSP_RESPONSE with lsp_pubnonce + lsp_psig. */
    wire_msg_t lr_msg;
    if (!wire_recv(fd, &lr_msg) || lr_msg.msg_type != MSG_SUBFACTORY_LSP_RESPONSE) {
        fprintf(stderr,
            "Client-stateless subfactory %u: expected LSP_RESPONSE, got 0x%02x\n",
            my_index, lr_msg.json ? lr_msg.msg_type : 0);
        if (lr_msg.json) cJSON_Delete(lr_msg.json);
        if (poison_prepared_c) memset(&my_poison_secnonce, 0, sizeof(my_poison_secnonce));
        factory_session_reset_poison(factory, sub_node_i);
        return 0;
    }
    unsigned char lsp_pubnonce_ser[66], lsp_psig_ser[32];
    unsigned char all_pn_sub[FACTORY_MAX_SIGNERS][66];
    unsigned char all_poison_pn_sub[FACTORY_MAX_SIGNERS][66];
    unsigned char lsp_poison_psig_ser[32];
    uint32_t got_all_pn_len = 0, got_poison_len = 0;
    memset(all_poison_pn_sub, 0, sizeof(all_poison_pn_sub));
    int lr_rc = wire_parse_subfactory_lsp_response(lr_msg.json,
                                              lsp_pubnonce_ser, lsp_psig_ser, 1,
                                              (unsigned char *)all_pn_sub,
                                              (uint32_t)sizeof(all_pn_sub),
                                              &got_all_pn_len,
                                              poison_prepared_c ? (unsigned char *)all_poison_pn_sub : NULL,
                                              poison_prepared_c ? (uint32_t)sizeof(all_poison_pn_sub) : 0,
                                              poison_prepared_c ? &got_poison_len : NULL,
                                              poison_prepared_c ? lsp_poison_psig_ser : NULL);
    if (lr_rc == 0) {
        cJSON_Delete(lr_msg.json);
        fprintf(stderr, "Client-stateless subfactory %u: parse LSP_RESPONSE failed\n",
                my_index);
        if (poison_prepared_c) memset(&my_poison_secnonce, 0, sizeof(my_poison_secnonce));
        factory_session_reset_poison(factory, sub_node_i);
        return 0;
    }
    cJSON_Delete(lr_msg.json);
    /* LSP did not reciprocate poison (rc<2 or wrong matrix length) -> degrade. */
    if (poison_prepared_c &&
        (lr_rc < 2 || got_poison_len != (uint32_t)(sub->n_signers * 66))) {
        fprintf(stderr, "Client-stateless subfactory %u: LSP omitted poison fields "
                "-- degrading local poison\n", my_index);
        memset(&my_poison_secnonce, 0, sizeof(my_poison_secnonce));
        factory_session_reset_poison(factory, sub_node_i);
        poison_prepared_c = 0;
    }

    /* Set LSP nonce, then (k>=2) every OTHER signer's nonce from the forwarded
       matrix (own already set in Step 5, LSP set just below), then finalize. */
    secp256k1_musig_pubnonce lsp_pubnonce;
    if (!musig_pubnonce_parse(ctx, &lsp_pubnonce, lsp_pubnonce_ser) ||
        !factory_session_set_nonce(factory, sub_node_i, (size_t)lsp_slot, &lsp_pubnonce)) {
        fprintf(stderr, "Client-stateless subfactory %u: set LSP nonce failed\n", my_index);
        return 0;
    }
    if (got_all_pn_len == (uint32_t)(sub->n_signers * 66)) {
        for (size_t s = 0; s < sub->n_signers; s++) {
            if (s == (size_t)my_slot || s == (size_t)lsp_slot) continue;
            secp256k1_musig_pubnonce pn_s;
            if (!musig_pubnonce_parse(ctx, &pn_s, all_pn_sub[s]) ||
                !factory_session_set_nonce(factory, sub_node_i, s, &pn_s)) {
                fprintf(stderr,
                    "Client-stateless subfactory %u: set co-signer nonce[%zu] failed\n",
                    my_index, s);
                return 0;
            }
        }
    }
    if (!factory_session_finalize_node(factory, sub_node_i)) {
        fprintf(stderr, "Client-stateless subfactory %u: finalize_node failed\n", my_index);
        if (poison_prepared_c) memset(&my_poison_secnonce, 0, sizeof(my_poison_secnonce));
        factory_session_reset_poison(factory, sub_node_i);
        return 0;
    }

    /* Poison: set every signer's poison nonce from the forwarded matrix (the
       poison session is N-of-N like state), finalize.  Own poison nonce was set
       in Step 5; set the rest here.  Degrade this leaf if any step fails. */
    unsigned char my_poison_psig_ser[32] = {0};
    if (poison_prepared_c) {
        int pz_ok = 1;
        for (size_t s = 0; s < sub->n_signers && pz_ok; s++) {
            if (s == (size_t)my_slot) continue;  /* own already set */
            secp256k1_musig_pubnonce ppn;
            if (!musig_pubnonce_parse(ctx, &ppn, all_poison_pn_sub[s]) ||
                !factory_session_set_nonce_poison(factory, sub_node_i, s, &ppn))
                pz_ok = 0;
        }
        secp256k1_musig_partial_sig my_poison_psig;
        pz_ok = pz_ok &&
            factory_session_finalize_node_poison(factory, sub_node_i) &&
            musig_create_partial_sig(ctx, &my_poison_psig, &my_poison_secnonce,
                                       keypair, &sub->poison_signing_session);
        /* Zero own poison secnonce on every path BEFORE the DONE recv. */
        memset(&my_poison_secnonce, 0, sizeof(my_poison_secnonce));
        if (!pz_ok) {
            fprintf(stderr, "Client-stateless subfactory %u: poison sign failed "
                    "-- degrading\n", my_index);
            factory_session_reset_poison(factory, sub_node_i);
            poison_prepared_c = 0;
        } else {
            musig_partial_sig_serialize(ctx, my_poison_psig_ser, &my_poison_psig);
        }
    }

    /* Create own partial_sig (zeros own secnonce). */
    secp256k1_musig_partial_sig my_psig;
    if (!musig_create_partial_sig(ctx, &my_psig, &my_secnonce, keypair,
                                    &sub->signing_session)) {
        fprintf(stderr, "Client-stateless subfactory %u: create_partial_sig failed\n",
                my_index);
        factory_session_reset_poison(factory, sub_node_i);
        return 0;
    }
    /* my_secnonce + my_poison_secnonce zeroed by musig_create_partial_sig.
       INVARIANT: we no longer hold any client secnonce (state or poison). */

    /* Send CLIENT_FINAL_PSIGS with own psig (+ poison psig).  LSP aggregates
       and completes both the state and poison sessions. */
    unsigned char my_psig_ser[32];
    musig_partial_sig_serialize(ctx, my_psig_ser, &my_psig);
    cJSON *fp_json = wire_build_subfactory_client_final_psigs(
        my_psig_ser, 1, poison_prepared_c ? my_poison_psig_ser : NULL);
    if (!wire_send(fd, MSG_SUBFACTORY_CLIENT_FINAL_PSIGS, fp_json)) {
        cJSON_Delete(fp_json);
        fprintf(stderr, "Client-stateless subfactory %u: send CLIENT_FINAL_PSIGS failed\n",
                my_index);
        factory_session_reset_poison(factory, sub_node_i);
        return 0;
    }
    cJSON_Delete(fp_json);
    /* Local poison state handed off via the wire; free our copy. */
    if (poison_prepared_c) factory_session_reset_poison(factory, sub_node_i);

    /* Wait for DONE. */
    wire_msg_t done_msg;
    if (!wire_recv(fd, &done_msg) || done_msg.msg_type != MSG_SUBFACTORY_DONE) {
        fprintf(stderr,
            "Client-stateless subfactory %u: expected DONE, got 0x%02x\n",
            my_index, done_msg.json ? done_msg.msg_type : 0);
        if (done_msg.json) cJSON_Delete(done_msg.json);
        return 0;
    }
    if (done_msg.json) cJSON_Delete(done_msg.json);

    printf("Client-stateless subfactory %u: advance done (sub_node=%u)\n",
           my_index, sub_node_id);
    return 1;
}

int client_handle_subfactory_advance(int fd, secp256k1_context *ctx,
                                       const secp256k1_keypair *keypair,
                                       factory_t *factory, uint32_t my_index,
                                       const wire_msg_t *propose_msg) {
    return client_handle_subfactory_advance_stateless(fd, ctx, keypair, factory, my_index, propose_msg);
}


/* --- Phase 1c (#271): MuSig2 stateless-signer client-side handler ---

   Mirrors lsp_advance_leaf_stateless in src/lsp_channels.c.  The client
   goes FIRST with its pubnonce; the LSP atomically generates its nonce
   + signs and replies with both lsp_pubnonce + lsp_psig in one message;
   the client then aggregates locally and ships the 64-byte final sig.

   Scope: state TX only.  Poison TX deferred (TODO).  See the LSP-side
   header for the full rationale. */
static int client_handle_leaf_advance_stateless(int fd,
                                                  secp256k1_context *ctx,
                                                  const secp256k1_keypair *keypair,
                                                  factory_t *factory,
                                                  uint32_t my_index,
                                                  const wire_msg_t *propose_msg) {
    persist_t *persist = g_client_persist;
    int leaf_side;
    /* Parse PROPOSE.  In stateless mode the parser returns 3 (no pubnonce
       field).  We accept that one return value; everything else is an
       error (we shouldn't be in this function if the LSP is sending the
       legacy shape). */
    unsigned char throwaway_pn[66], throwaway_poison_pn[66];
    int propose_rc = wire_parse_leaf_advance_propose(propose_msg->json,
                                                       &leaf_side,
                                                       throwaway_pn,
                                                       throwaway_poison_pn);
    if (propose_rc != 3) {
        fprintf(stderr,
                "Client-stateless %u: PROPOSE not in stateless shape (rc=%d) "
                "-- refusing.  Set SS_MUSIG_STATELESS on both ends or unset on both.\n",
                my_index, propose_rc);
        return 0;
    }
    if (leaf_side < 0 || leaf_side >= factory->n_leaf_nodes) {
        fprintf(stderr, "Client-stateless %u: bad leaf_side %d\n", my_index, leaf_side);
        return 0;
    }

    size_t node_idx = factory->leaf_node_indices[leaf_side];
    factory_node_t *ps_node = &factory->nodes[node_idx];

    /* Phase 1d.2: snapshot OLD state for deterministic poison prep. */
    unsigned char old_leaf_txid[32];
    int had_old_signed_c = (ps_node->is_signed && ps_node->signed_tx.len > 0);
    if (had_old_signed_c)
        memcpy(old_leaf_txid, ps_node->txid, 32);
    int old_n_outputs_c = ps_node->n_outputs;
    uint64_t old_l_amount_c = (old_n_outputs_c >= 2)
                              ? ps_node->outputs[old_n_outputs_c - 1].amount_sats
                              : 0;

    /* CL7: snapshot pre-advance leaf signed_tx for --cheat-client.
       Mirrors the legacy path in client_handle_leaf_advance below; the
       stateless dispatch in MuSig2 redesign #271/#330 bypassed the
       legacy CL7 hook so test_regtest_cheat_client failed under
       SS_MUSIG_STATELESS.  Broadcast lives after LEAF_ADVANCE_DONE. */
    tx_buf_t cl7_cheat_tx;
    tx_buf_init(&cl7_cheat_tx, 0);
    {
        const char *cheat_env = getenv("SS_CHEAT_CLIENT_SIDE");
        if (cheat_env && atoi(cheat_env) == leaf_side &&
            had_old_signed_c && ps_node->signed_tx.len > 0) {
            tx_buf_init(&cl7_cheat_tx, (int)ps_node->signed_tx.len);
            memcpy(cl7_cheat_tx.data, ps_node->signed_tx.data,
                   ps_node->signed_tx.len);
            cl7_cheat_tx.len = ps_node->signed_tx.len;
        }
    }

    /* Step 1: advance local state to mirror the LSP. */
    int rc = factory_advance_leaf_unsigned(factory, leaf_side);
    if (rc <= 0) {
        fprintf(stderr, "Client-stateless %u: leaf %d advance_unsigned failed (rc=%d)\n",
                my_index, leaf_side, rc);
        return 0;
    }

    /* PS double-spend defense -- same as legacy path. */
    if (persist && ps_node->is_ps_leaf && ps_node->ps_chain_len > 0) {
        unsigned char prev_sighash[32];
        int already = persist_check_ps_signed_input(
            persist, /* factory_id = */ 0,
            ps_node->ps_prev_txid, /* parent_vout = */ 0,
            prev_sighash);
        if (already) {
            char hex[65];
            for (int i = 0; i < 32; i++)
                snprintf(hex + 2 * i, 3, "%02x", ps_node->ps_prev_txid[i]);
            fprintf(stderr,
                    "Client-stateless %u: REFUSING PS double-spend -- already signed "
                    "a TX spending (%s:0).\n", my_index, hex);
            return 0;
        }
    }

    /* Phase 1d.2: prep poison TX (matches LSP side deterministically).
       Client doesn'''t have its own watchtower toggle -- it preps poison
       unconditionally if the amounts fit.  If the LSP didn'''t prep
       (e.g. no watchtower), the wire flow degrades naturally because
       the LSP won'''t send poison fields back. */
    const uint64_t LEAF_POISON_FEE_SATS_C = 1000;
    int leaf_poison_prepared_c = 0;
    if (had_old_signed_c && old_n_outputs_c >= 2 &&
        old_l_amount_c > LEAF_POISON_FEE_SATS_C +
                         (uint64_t)(ps_node->n_signers - 1) * 330u) {
        if (factory_session_prepare_poison_tx_leaf(
                factory, node_idx,
                old_leaf_txid, (uint32_t)(old_n_outputs_c - 1),
                old_l_amount_c, LEAF_POISON_FEE_SATS_C)) {
            leaf_poison_prepared_c = 1;
        }
    }

    if (!factory_session_init_node(factory, node_idx)) {
        fprintf(stderr, "Client-stateless %u: session_init failed\n", my_index);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }
    if (leaf_poison_prepared_c &&
        !factory_session_init_node_poison(factory, node_idx)) {
        fprintf(stderr, "Client-stateless %u: poison session init failed -- degrading\n",
                my_index);
        factory_session_reset_poison(factory, node_idx);
        leaf_poison_prepared_c = 0;
    }

    int my_slot = factory_find_signer_slot(factory, node_idx, my_index);
    int lsp_slot = factory_find_signer_slot(factory, node_idx, 0);
    if (my_slot < 0 || lsp_slot < 0) {
        fprintf(stderr, "Client-stateless %u: signer slot lookup failed (my=%d lsp=%d)\n",
                my_index, my_slot, lsp_slot);
        return 0;
    }

    /* Step 2: generate own nonce and ship MSG_LEAF_ADVANCE_CLIENT_PUBNONCE.
       Client secnonce lives on stack across the LSP_RESPONSE recv -- this
       is OK because Option G targets specifically the LSP's secnonce
       lifetime (LSP is the high-value, persistent, multi-tenant party).
       Client-side secnonce already exists on stack in the legacy flow too. */
    unsigned char my_seckey[32];
    secp256k1_pubkey my_pubkey;
    if (!secp256k1_keypair_sec(ctx, my_seckey, keypair)) {
        fprintf(stderr, "Client-stateless %u: keypair_sec failed\n", my_index);
        return 0;
    }
    secp256k1_keypair_pub(ctx, &my_pubkey, keypair);

    secp256k1_musig_secnonce my_secnonce;
    secp256k1_musig_pubnonce my_pubnonce;
    if (!musig_generate_nonce(ctx, &my_secnonce, &my_pubnonce,
                                my_seckey, &my_pubkey,
                                &factory->nodes[node_idx].keyagg.cache)) {
        memset(my_seckey, 0, 32);
        fprintf(stderr, "Client-stateless %u: nonce gen failed\n", my_index);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }
    secp256k1_musig_secnonce my_poison_secnonce;
    secp256k1_musig_pubnonce my_poison_pubnonce;
    if (leaf_poison_prepared_c &&
        !musig_generate_nonce(ctx, &my_poison_secnonce, &my_poison_pubnonce,
                                my_seckey, &my_pubkey,
                                &factory->nodes[node_idx].keyagg.cache)) {
        fprintf(stderr, "Client-stateless %u: poison nonce gen failed -- degrading\n",
                my_index);
        factory_session_reset_poison(factory, node_idx);
        leaf_poison_prepared_c = 0;
    }
    memset(my_seckey, 0, 32);
    if (!factory_session_set_nonce(factory, node_idx, (size_t)my_slot, &my_pubnonce)) {
        fprintf(stderr, "Client-stateless %u: set own nonce failed\n", my_index);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }
    if (leaf_poison_prepared_c &&
        !factory_session_set_nonce_poison(factory, node_idx, (size_t)my_slot,
                                            &my_poison_pubnonce)) {
        fprintf(stderr, "Client-stateless %u: set own poison nonce failed -- degrading\n",
                my_index);
        factory_session_reset_poison(factory, node_idx);
        leaf_poison_prepared_c = 0;
    }

    unsigned char my_pubnonce_ser[66], my_poison_pubnonce_ser[66];
    musig_pubnonce_serialize(ctx, my_pubnonce_ser, &my_pubnonce);
    if (leaf_poison_prepared_c)
        musig_pubnonce_serialize(ctx, my_poison_pubnonce_ser, &my_poison_pubnonce);
    cJSON *cpn_json = wire_build_leaf_advance_client_pubnonce(
        my_pubnonce_ser,
        leaf_poison_prepared_c ? my_poison_pubnonce_ser : NULL);
    if (!wire_send(fd, MSG_LEAF_ADVANCE_CLIENT_PUBNONCE, cpn_json)) {
        cJSON_Delete(cpn_json);
        fprintf(stderr, "Client-stateless %u: send CLIENT_PUBNONCE failed\n", my_index);
        return 0;
    }
    cJSON_Delete(cpn_json);

    /* Step 3: wait for LSP_RESPONSE with lsp_pubnonce + lsp_psig. */
    wire_msg_t lr_msg;
    if (!wire_recv(fd, &lr_msg) || lr_msg.msg_type != MSG_LEAF_ADVANCE_LSP_RESPONSE) {
        fprintf(stderr, "Client-stateless %u: expected LSP_RESPONSE, got 0x%02x\n",
                my_index, lr_msg.json ? lr_msg.msg_type : 0);
        if (lr_msg.json) cJSON_Delete(lr_msg.json);
        return 0;
    }
    unsigned char lsp_pubnonce_ser[66], lsp_psig_ser[32];
    unsigned char lsp_poison_pubnonce_ser[66], lsp_poison_psig_ser[32];
    int lrrc = wire_parse_leaf_advance_lsp_response(lr_msg.json,
                                                       lsp_pubnonce_ser,
                                                       lsp_psig_ser,
                                                       leaf_poison_prepared_c
                                                         ? lsp_poison_pubnonce_ser : NULL,
                                                       leaf_poison_prepared_c
                                                         ? lsp_poison_psig_ser : NULL);
    cJSON_Delete(lr_msg.json);
    if (!lrrc) {
        fprintf(stderr, "Client-stateless %u: parse LSP_RESPONSE failed\n", my_index);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }
    if (leaf_poison_prepared_c && lrrc < 2) {
        fprintf(stderr, "Client-stateless %u: LSP omitted poison fields -- degrading\n",
                my_index);
        factory_session_reset_poison(factory, node_idx);
        leaf_poison_prepared_c = 0;
    }

    /* Step 4: set LSP nonce, finalize session. */
    secp256k1_musig_pubnonce lsp_pubnonce;
    if (!musig_pubnonce_parse(ctx, &lsp_pubnonce, lsp_pubnonce_ser)) {
        fprintf(stderr, "Client-stateless %u: parse LSP pubnonce failed\n", my_index);
        return 0;
    }
    if (!factory_session_set_nonce(factory, node_idx, (size_t)lsp_slot, &lsp_pubnonce)) {
        fprintf(stderr, "Client-stateless %u: set LSP nonce failed\n", my_index);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }
    if (leaf_poison_prepared_c) {
        secp256k1_musig_pubnonce lsp_poison_pn;
        if (!musig_pubnonce_parse(ctx, &lsp_poison_pn, lsp_poison_pubnonce_ser) ||
            !factory_session_set_nonce_poison(factory, node_idx, (size_t)lsp_slot,
                                                &lsp_poison_pn)) {
            fprintf(stderr, "Client-stateless %u: LSP poison nonce parse/set failed -- degrading\n",
                    my_index);
            factory_session_reset_poison(factory, node_idx);
            leaf_poison_prepared_c = 0;
        }
    }
    if (!factory_session_finalize_node(factory, node_idx)) {
        fprintf(stderr, "Client-stateless %u: finalize_node failed\n", my_index);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }
    if (leaf_poison_prepared_c &&
        !factory_session_finalize_node_poison(factory, node_idx)) {
        fprintf(stderr, "Client-stateless %u: poison finalize failed -- degrading\n",
                my_index);
        factory_session_reset_poison(factory, node_idx);
        leaf_poison_prepared_c = 0;
    }

    /* Step 5: create own partial_sig (zeroes own secnonce, both state + poison). */
    secp256k1_musig_partial_sig my_psig;
    if (!musig_create_partial_sig(ctx, &my_psig, &my_secnonce, keypair,
                                    &factory->nodes[node_idx].signing_session)) {
        fprintf(stderr, "Client-stateless %u: create_partial_sig failed\n", my_index);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }
    secp256k1_musig_partial_sig my_poison_psig;
    if (leaf_poison_prepared_c &&
        !musig_create_partial_sig(ctx, &my_poison_psig, &my_poison_secnonce, keypair,
                                    &factory->nodes[node_idx].poison_signing_session)) {
        fprintf(stderr, "Client-stateless %u: poison partial_sig failed -- degrading\n",
                my_index);
        factory_session_reset_poison(factory, node_idx);
        leaf_poison_prepared_c = 0;
    }

    /* Step 6: parse LSP's psig and set both psigs into the session. */
    secp256k1_musig_partial_sig lsp_psig;
    if (!musig_partial_sig_parse(ctx, &lsp_psig, lsp_psig_ser)) {
        fprintf(stderr, "Client-stateless %u: parse LSP psig failed\n", my_index);
        return 0;
    }
    if (!factory_session_set_partial_sig(factory, node_idx, (size_t)my_slot, &my_psig)) {
        fprintf(stderr, "Client-stateless %u: set own partial_sig failed\n", my_index);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }
    if (!factory_session_set_partial_sig(factory, node_idx, (size_t)lsp_slot, &lsp_psig)) {
        fprintf(stderr, "Client-stateless %u: set LSP partial_sig failed\n", my_index);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }
    if (leaf_poison_prepared_c) {
        secp256k1_musig_partial_sig lsp_poison_psig;
        if (!musig_partial_sig_parse(ctx, &lsp_poison_psig, lsp_poison_psig_ser) ||
            !factory_session_set_partial_sig_poison(factory, node_idx,
                                                     (size_t)my_slot, &my_poison_psig) ||
            !factory_session_set_partial_sig_poison(factory, node_idx,
                                                     (size_t)lsp_slot, &lsp_poison_psig)) {
            fprintf(stderr, "Client-stateless %u: poison psig set failed -- degrading\n",
                    my_index);
            factory_session_reset_poison(factory, node_idx);
            leaf_poison_prepared_c = 0;
        }
    }

    /* PS defense: record what we just signed BEFORE shipping FINAL.  A
       crash after record + before send is safe -- a retry sees the row
       and refuses.  Same shape as legacy path. */
    if (persist && ps_node->is_ps_leaf && ps_node->ps_chain_len > 0) {
        unsigned char sighash[32];
        if (compute_taproot_sighash(sighash,
                ps_node->unsigned_tx.data, ps_node->unsigned_tx.len, 0,
                ps_node->outputs[0].script_pubkey,
                ps_node->outputs[0].script_pubkey_len,
                ps_node->ps_prev_chan_amount, ps_node->nsequence)) {
            unsigned char psig_buf[36];
            unsigned char my_psig_ser[32];
            musig_partial_sig_serialize(ctx, my_psig_ser, &my_psig);
            memset(psig_buf, 0, 36);
            memcpy(psig_buf, my_psig_ser, 32);
            persist_save_ps_signed_input(persist, /* factory_id = */ 0,
                (int)node_idx, ps_node->ps_prev_txid, 0,
                sighash, psig_buf);
        }
    }

    /* Step 7: complete_node aggregates both psigs + attaches the signed
       witness, populating node->signed_tx.  Phase 1d.2 also runs the
       parallel poison ceremony when prepared. */
    if (leaf_poison_prepared_c &&
        !factory_session_complete_node_poison(factory, node_idx)) {
        fprintf(stderr, "Client-stateless %u: poison complete failed -- degrading\n",
                my_index);
        factory_session_reset_poison(factory, node_idx);
        leaf_poison_prepared_c = 0;
    }
    if (!factory_session_complete_node(factory, node_idx)) {
        fprintf(stderr, "Client-stateless %u: complete_node failed\n", my_index);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }

    /* Extract the 64-byte aggregated sig so we can ship it to the LSP.
       The LSP needs the bare 64 bytes (not the segwit witness), so we
       re-aggregate explicitly from the session's slot-indexed
       partial_sigs buffer.  node->partial_sigs[0..n_signers-1] are set
       by factory_session_set_partial_sig in slot order. */
    factory_node_t *node = &factory->nodes[node_idx];
    unsigned char final_sig[64], final_poison_sig[64];
    if (!musig_aggregate_partial_sigs(ctx, final_sig,
                                        &node->signing_session,
                                        node->partial_sigs, node->n_signers)) {
        fprintf(stderr, "Client-stateless %u: aggregate_partial_sigs failed\n", my_index);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }
    if (leaf_poison_prepared_c &&
        !musig_aggregate_partial_sigs(ctx, final_poison_sig,
                                        &node->poison_signing_session,
                                        node->poison_partial_sigs, node->n_signers)) {
        fprintf(stderr, "Client-stateless %u: poison aggregate failed -- degrading\n",
                my_index);
        factory_session_reset_poison(factory, node_idx);
        leaf_poison_prepared_c = 0;
    }

    /* Step 8: ship FINAL with optional poison sig. */
    cJSON *fin_json = wire_build_leaf_advance_final(
        final_sig,
        leaf_poison_prepared_c ? final_poison_sig : NULL);
    if (!wire_send(fd, MSG_LEAF_ADVANCE_FINAL, fin_json)) {
        cJSON_Delete(fin_json);
        fprintf(stderr, "Client-stateless %u: send FINAL failed\n", my_index);
        return 0;
    }
    cJSON_Delete(fin_json);

    /* Step 9: wait for LEAF_ADVANCE_DONE (LSP's broadcast). */
    wire_msg_t done_msg;
    if (!wire_recv(fd, &done_msg) || done_msg.msg_type != MSG_LEAF_ADVANCE_DONE) {
        fprintf(stderr, "Client-stateless %u: expected LEAF_ADVANCE_DONE, got 0x%02x\n",
                my_index, done_msg.json ? done_msg.msg_type : 0);
        if (done_msg.json) cJSON_Delete(done_msg.json);
        return 0;
    }
    if (done_msg.json) cJSON_Delete(done_msg.json);

    /* CL7: broadcast the snapshotted stale leaf state now that the
       advance is recorded.  LSP/standalone WT must respond with
       response_tx + L-stock poison TX.  Mirrors the legacy path. */
    if (cl7_cheat_tx.len > 0 && g_client_chain_rt) {
        char hex[CL7_TX_HEX_MAX];
        char txid_str[65] = {0};
        if (cl7_cheat_tx.len * 2 + 1 < CL7_TX_HEX_MAX) {
            hex_encode(cl7_cheat_tx.data, cl7_cheat_tx.len, hex);
            int sent = regtest_send_raw_tx(g_client_chain_rt, hex, txid_str);
            fprintf(stderr, "CL7: client %u broadcast STALE leaf %d state: %s (sent=%d)\n",
                    my_index, leaf_side, txid_str, sent);
            if (persist && sent) {
                persist_log_broadcast(persist, txid_str,
                                       "cheat_client_stale", hex,
                                       "ok");
            }
        }
    }
    tx_buf_free(&cl7_cheat_tx);

    printf("Client-stateless %u: leaf %d advance complete\n", my_index, leaf_side);
    return 1;
}

int client_handle_leaf_advance(int fd, secp256k1_context *ctx,
                                 const secp256k1_keypair *keypair,
                                 factory_t *factory, uint32_t my_index,
                                 const wire_msg_t *propose_msg) {
    return client_handle_leaf_advance_stateless(fd, ctx, keypair, factory, my_index, propose_msg);
}

/* Phase 1e.2.d: client-side stateless Tier B handler.  Dispatched from
   client_handle_state_advance when the LSP sends PROPOSE_INTENT (0x81)
   instead of legacy STATE_ADVANCE_PROPOSE.  Mirrors lsp_run_state_advance_stateless
   from Phase 1e.2.c.  MVP scope:
     - multi-leaf state TX
     - single-input per leaf
     - no poison TX */
static int client_handle_state_advance_stateless(int fd,
                                                   secp256k1_context *ctx,
                                                   const secp256k1_keypair *keypair,
                                                   factory_t *factory,
                                                   uint32_t my_index,
                                                   const wire_msg_t *propose_msg) {
    /* Step 1: Parse PROPOSE_INTENT { epoch_after, n_affected_leaves, trigger_leaf_side }. */
    uint32_t epoch_after, n_affected_leaves;
    int trigger_leaf_side;
    if (!wire_parse_state_adv_propose_intent(propose_msg->json,
                                                &epoch_after, &n_affected_leaves,
                                                &trigger_leaf_side)) {
        fprintf(stderr,
            "Client-stateless Tier B %u: parse PROPOSE_INTENT failed\n", my_index);
        return 0;
    }

    /* Step 2: Advance local state to mirror the LSP-side rollover, using the
       same proven logic as the legacy client_handle_state_advance.  The client
       may be N ticks behind the LSP (the LSP doesn't send a per-tick PROPOSE
       before rollover), so loop until rc==-1 (rollover; trees rebuilt):
         - root-driven  (trigger_leaf_side < 0): factory_tick_root — PS Tier B
           block-height rollover; mirrors lsp_factory_tick_root.  Per-tick rc==0
           means advanced within the epoch (keep ticking).
         - leaf-driven  (>= 0): factory_advance_leaf_unsigned on the trigger
           leaf — DW counter exhaustion.  Per-step rc==1 means advanced (keep
           going). */
    int adv_rc = 0;
    {
        int max_steps = (int)(factory->states_per_layer + 2);
        if (max_steps < 4) max_steps = 4;
        if (trigger_leaf_side < 0) {
            for (int s = 0; s < max_steps; s++) {
                adv_rc = factory_tick_root(factory);
                if (adv_rc == -1) break;
                if (adv_rc != 0) {
                    fprintf(stderr, "Client-stateless Tier B %u: root tick step %d "
                            "returned unexpected %d\n", my_index, s, adv_rc);
                    return 0;
                }
            }
        } else {
            for (int s = 0; s < max_steps; s++) {
                adv_rc = factory_advance_leaf_unsigned(factory, trigger_leaf_side);
                if (adv_rc == -1) break;
                if (adv_rc != 1) {
                    fprintf(stderr, "Client-stateless Tier B %u: advance step %d "
                            "returned %d\n", my_index, s, adv_rc);
                    return 0;
                }
            }
        }
        if (adv_rc != -1) {
            fprintf(stderr, "Client-stateless Tier B %u: rollover not reached "
                    "within %d steps (trigger_leaf=%d)\n",
                    my_index, max_steps, trigger_leaf_side);
            return 0;
        }
    }

    /* Step 3: Build affected[] — SAME logic as LSP. */
    size_t affected[FACTORY_MAX_NODES];
    size_t n_affected = 0;
    for (size_t i = 0; i < factory->n_nodes; i++) {
        const factory_node_t *n = &factory->nodes[i];
        if (n->is_ps_leaf && trigger_leaf_side != -1) continue;
        if (!n->is_built) continue;
        if (n->is_signed) continue;
        affected[n_affected++] = i;
    }
    if (n_affected != n_affected_leaves) {
        fprintf(stderr,
            "Client-stateless Tier B %u: local n_affected=%zu mismatches LSP=%u\n",
            my_index, n_affected, n_affected_leaves);
        return 0;
    }

    /* MVP refusal: multi-input on any affected. */
    for (size_t k = 0; k < n_affected; k++) {
        if (factory_node_uses_multi_input(factory, affected[k])) {
            fprintf(stderr,
                "Client-stateless Tier B %u: affected %zu uses multi-input — refusing\n",
                my_index, affected[k]);
            return 0;
        }
    }

    /* Step 3.5 (Tier B poison): prepare the L-stock poison TX for each affected
       DW leaf with an old signed state (deterministic; matches the LSP minus
       the watchtower gate, which is LSP-only).  PS leaves carry no L-stock
       poison.  poison_prepared[k] is cleared per-leaf if anything degrades or
       if the LSP doesn't reciprocate poison fields. */
    const uint64_t TIERB_POISON_FEE_SATS = 1000;
    int poison_prepared_c[FACTORY_MAX_NODES];
    secp256k1_musig_secnonce my_poison_secnonces[FACTORY_MAX_NODES];
    unsigned char my_poison_pubnonces_per_node[FACTORY_MAX_NODES][66];
    unsigned char my_poison_psigs_per_node[FACTORY_MAX_NODES][32];
    for (size_t k = 0; k < n_affected; k++) {
        poison_prepared_c[k] = 0;
        memset(my_poison_pubnonces_per_node[k], 0, 66);
        memset(my_poison_psigs_per_node[k], 0, 32);
        factory_node_t *an = &factory->nodes[affected[k]];
        int had_old = (an->is_signed && an->signed_tx.len > 0);
        int old_no = an->n_outputs;
        uint64_t old_l = (old_no >= 2) ? an->outputs[old_no - 1].amount_sats : 0;
        if (!an->is_ps_leaf && had_old && old_no >= 2 &&
            old_l > TIERB_POISON_FEE_SATS +
                (uint64_t)(an->n_signers - 1) * 330u) {
            unsigned char old_txid[32];
            memcpy(old_txid, an->txid, 32);
            if (factory_session_prepare_poison_tx_leaf(
                    factory, affected[k], old_txid, (uint32_t)(old_no - 1),
                    old_l, TIERB_POISON_FEE_SATS)) {
                poison_prepared_c[k] = 1;  /* init_node_poison after state init */
            }
        }
    }

    /* Step 4: init MuSig session per affected (state + poison). */
    for (size_t k = 0; k < n_affected; k++) {
        if (!factory_session_init_node(factory, affected[k])) {
            fprintf(stderr,
                "Client-stateless Tier B %u: init_node[%zu] failed\n",
                my_index, affected[k]);
            return 0;
        }
        if (poison_prepared_c[k] &&
            !factory_session_init_node_poison(factory, affected[k])) {
            factory_session_reset_poison(factory, affected[k]);
            poison_prepared_c[k] = 0;
        }
    }

    /* Step 5: gen own pubnonces for each affected node where this client signs.
       For non-participating leaves: leave the buffer all-zeros (LSP detects). */
    unsigned char my_seckey[32];
    if (!secp256k1_keypair_sec(ctx, my_seckey, keypair)) {
        fprintf(stderr,
            "Client-stateless Tier B %u: keypair_sec failed\n", my_index);
        return 0;
    }
    secp256k1_pubkey my_pubkey;
    secp256k1_keypair_pub(ctx, &my_pubkey, keypair);

    unsigned char my_pubnonces_per_node[FACTORY_MAX_NODES][66];
    secp256k1_musig_secnonce my_secnonces[FACTORY_MAX_NODES];
    int my_slot_per_node[FACTORY_MAX_NODES];
    int my_signs_per_node[FACTORY_MAX_NODES];
    for (size_t k = 0; k < n_affected; k++) {
        memset(my_pubnonces_per_node[k], 0, 66);
        my_slot_per_node[k] = -1;
        my_signs_per_node[k] = 0;
    }

    for (size_t k = 0; k < n_affected; k++) {
        int slot = factory_find_signer_slot(factory, affected[k], my_index);
        if (slot < 0) continue;  /* this client doesn't sign this node */
        secp256k1_musig_pubnonce pn;
        if (!musig_generate_nonce(ctx, &my_secnonces[k], &pn,
                                    my_seckey, &my_pubkey,
                                    &factory->nodes[affected[k]].keyagg.cache)) {
            memset(my_seckey, 0, 32);
            fprintf(stderr,
                "Client-stateless Tier B %u: nonce gen for %zu failed\n",
                my_index, affected[k]);
            return 0;
        }
        my_slot_per_node[k] = slot;
        my_signs_per_node[k] = 1;
        musig_pubnonce_serialize(ctx, my_pubnonces_per_node[k], &pn);
        if (!factory_session_set_nonce(factory, affected[k], (size_t)slot, &pn)) {
            memset(my_seckey, 0, 32);
            fprintf(stderr,
                "Client-stateless Tier B %u: set own nonce for %zu failed\n",
                my_index, affected[k]);
            return 0;
        }
        /* Poison: own nonce for this leaf (my_seckey still live this loop). */
        if (poison_prepared_c[k]) {
            secp256k1_musig_pubnonce ppn;
            if (!musig_generate_nonce(ctx, &my_poison_secnonces[k], &ppn,
                                        my_seckey, &my_pubkey,
                                        &factory->nodes[affected[k]].keyagg.cache) ||
                !factory_session_set_nonce_poison(factory, affected[k],
                                                    (size_t)slot, &ppn)) {
                factory_session_reset_poison(factory, affected[k]);
                poison_prepared_c[k] = 0;
            } else {
                musig_pubnonce_serialize(ctx, my_poison_pubnonces_per_node[k], &ppn);
            }
        }
    }
    memset(my_seckey, 0, 32);

    /* Step 6: send CLIENT_PATH_NONCES. */
    cJSON *cpn = wire_build_state_adv_client_path_nonces(
        (const unsigned char *)my_pubnonces_per_node, (uint32_t)n_affected,
        (const unsigned char *)my_poison_pubnonces_per_node);
    if (!wire_send(fd, MSG_STATE_ADV_CLIENT_PATH_NONCES, cpn)) {
        cJSON_Delete(cpn);
        fprintf(stderr,
            "Client-stateless Tier B %u: send CLIENT_PATH_NONCES failed\n", my_index);
        return 0;
    }
    cJSON_Delete(cpn);

    /* Step 7: recv LSP_RESPONSE { lsp_pubnonces_per_leaf, lsp_psigs_per_leaf }. */
    wire_msg_t lr;
    if (!wire_recv(fd, &lr) || lr.msg_type != MSG_STATE_ADV_LSP_RESPONSE) {
        fprintf(stderr,
            "Client-stateless Tier B %u: expected LSP_RESPONSE, got 0x%02x\n",
            my_index, lr.json ? lr.msg_type : 0);
        if (lr.json) cJSON_Delete(lr.json);
        return 0;
    }
    unsigned char lsp_pubnonces_per_node[FACTORY_MAX_NODES][66];
    unsigned char lsp_psigs_per_node[FACTORY_MAX_NODES][32];
    unsigned char lsp_poison_pubnonces_per_node[FACTORY_MAX_NODES][66];
    unsigned char lsp_poison_psigs_per_node[FACTORY_MAX_NODES][32];
    memset(lsp_poison_pubnonces_per_node, 0, sizeof(lsp_poison_pubnonces_per_node));
    memset(lsp_poison_psigs_per_node, 0, sizeof(lsp_poison_psigs_per_node));
    /* Gap A: per-node base offset + total slots for the forwarded all-signer
       nonce matrix (must match the LSP's layout: nodes in affected[] order,
       each occupying n_signers slots of 66 bytes). */
    size_t node_nonce_base[FACTORY_MAX_NODES];
    size_t total_nonce_slots = 0;
    for (size_t k = 0; k < n_affected; k++) {
        node_nonce_base[k] = total_nonce_slots;
        total_nonce_slots += factory->nodes[affected[k]].n_signers;
    }
    unsigned char *all_pn_flat_c = calloc(total_nonce_slots ? total_nonce_slots : 1, 66);
    if (!all_pn_flat_c) {
        cJSON_Delete(lr.json);
        fprintf(stderr, "Client-stateless Tier B %u: alloc all_pn_flat_c failed\n", my_index);
        return 0;
    }
    uint32_t got_all_len = 0;
    if (!wire_parse_state_adv_lsp_response(lr.json,
                                             (unsigned char *)lsp_pubnonces_per_node,
                                             (unsigned char *)lsp_psigs_per_node,
                                             (uint32_t)n_affected,
                                             (unsigned char *)lsp_poison_pubnonces_per_node,
                                             (unsigned char *)lsp_poison_psigs_per_node,
                                             all_pn_flat_c,
                                             (uint32_t)(total_nonce_slots * 66),
                                             &got_all_len)) {
        cJSON_Delete(lr.json);
        free(all_pn_flat_c);
        fprintf(stderr,
            "Client-stateless Tier B %u: parse LSP_RESPONSE failed\n", my_index);
        return 0;
    }
    cJSON_Delete(lr.json);
    if (got_all_len != (uint32_t)(total_nonce_slots * 66)) {
        free(all_pn_flat_c);
        fprintf(stderr,
            "Client-stateless Tier B %u: all-signer nonce matrix len %u != expected %zu\n",
            my_index, got_all_len, total_nonce_slots * 66);
        return 0;
    }

    /* Step 8: for each affected node, set LSP nonce + finalize + set LSP psig +
       create own partial_sig (zeros own secnonce) + set own psig + complete. */
    unsigned char my_psigs_per_node[FACTORY_MAX_NODES][32];
    for (size_t k = 0; k < n_affected; k++) memset(my_psigs_per_node[k], 0, 32);

    for (size_t k = 0; k < n_affected; k++) {
        int lsp_slot = factory_find_signer_slot(factory, affected[k], 0);
        if (lsp_slot < 0) {
            fprintf(stderr,
                "Client-stateless Tier B %u: LSP not signer on %zu (invariant violation)\n",
                my_index, affected[k]);
            free(all_pn_flat_c);
            return 0;
        }
        if (!my_signs_per_node[k]) continue;  /* only nodes this client signs (mirror legacy) */
        /* Gap A: set EVERY signer's pubnonce (LSP slot 0 + all clients) from the
           forwarded matrix so the aggnonce can be built for multi-signer nodes. */
        {
            factory_node_t *an_k = &factory->nodes[affected[k]];
            int nonce_ok = 1;
            for (size_t s = 0; s < an_k->n_signers; s++) {
                /* Own slot was already set in Step 5 (when we generated the
                   secnonce); the matrix echoes it back -- re-setting would
                   double-count nonces_collected and fail finalize. */
                if (s == (size_t)my_slot_per_node[k]) continue;
                secp256k1_musig_pubnonce pn_s;
                if (!musig_pubnonce_parse(ctx, &pn_s,
                        all_pn_flat_c + (node_nonce_base[k] + s) * 66) ||
                    !factory_session_set_nonce(factory, affected[k], s, &pn_s)) {
                    nonce_ok = 0; break;
                }
            }
            if (!nonce_ok) {
                fprintf(stderr,
                    "Client-stateless Tier B %u: set all-signer nonces for %zu failed\n",
                    my_index, affected[k]);
                free(all_pn_flat_c);
                return 0;
            }
        }
        if (!factory_session_finalize_node(factory, affected[k])) {
            fprintf(stderr,
                "Client-stateless Tier B %u: finalize_node[%zu] failed\n",
                my_index, affected[k]);
            free(all_pn_flat_c);
            return 0;
        }
        /* Set LSP's psig into the session. */
        secp256k1_musig_partial_sig lsp_psig;
        if (!musig_partial_sig_parse(ctx, &lsp_psig, lsp_psigs_per_node[k]) ||
            !factory_session_set_partial_sig(factory, affected[k], (size_t)lsp_slot, &lsp_psig)) {
            fprintf(stderr,
                "Client-stateless Tier B %u: set LSP psig for %zu failed\n",
                my_index, affected[k]);
            free(all_pn_flat_c);
            return 0;
        }
        /* Create own partial_sig (zeros own secnonce).  Always runs: non-signed
           nodes were skipped above via `continue`. */
        {
            secp256k1_musig_partial_sig my_psig;
            if (!musig_create_partial_sig(ctx, &my_psig, &my_secnonces[k], keypair,
                                            &factory->nodes[affected[k]].signing_session)) {
                fprintf(stderr,
                    "Client-stateless Tier B %u: create_partial_sig[%zu] failed\n",
                    my_index, affected[k]);
                free(all_pn_flat_c);
                return 0;
            }
            musig_partial_sig_serialize(ctx, my_psigs_per_node[k], &my_psig);
            if (!factory_session_set_partial_sig(factory, affected[k],
                                                   (size_t)my_slot_per_node[k], &my_psig)) {
                fprintf(stderr,
                    "Client-stateless Tier B %u: set own psig[%zu] failed\n",
                    my_index, affected[k]);
                free(all_pn_flat_c);
                return 0;
            }
        }

        /* Poison (lockstep): set LSP poison nonce + finalize + set LSP poison
           psig + create own poison psig + complete.  Degrade this leaf if the
           LSP sent no poison (poison field all-zero) or any step fails. */
        if (poison_prepared_c[k]) {
            int lsp_pz_zero = 1;
            for (size_t b = 0; b < 66; b++)
                if (lsp_poison_pubnonces_per_node[k][b]) { lsp_pz_zero = 0; break; }
            secp256k1_musig_pubnonce lsp_ppn;
            secp256k1_musig_partial_sig lsp_ppsig, my_ppsig;
            if (lsp_pz_zero ||
                !musig_pubnonce_parse(ctx, &lsp_ppn, lsp_poison_pubnonces_per_node[k]) ||
                !factory_session_set_nonce_poison(factory, affected[k], (size_t)lsp_slot, &lsp_ppn) ||
                !factory_session_finalize_node_poison(factory, affected[k]) ||
                !musig_partial_sig_parse(ctx, &lsp_ppsig, lsp_poison_psigs_per_node[k]) ||
                !factory_session_set_partial_sig_poison(factory, affected[k], (size_t)lsp_slot, &lsp_ppsig) ||
                !musig_create_partial_sig(ctx, &my_ppsig, &my_poison_secnonces[k], keypair,
                                            &factory->nodes[affected[k]].poison_signing_session) ||
                !factory_session_set_partial_sig_poison(factory, affected[k],
                                                          (size_t)my_slot_per_node[k], &my_ppsig) ||
                !factory_session_complete_node_poison(factory, affected[k])) {
                factory_session_reset_poison(factory, affected[k]);
                poison_prepared_c[k] = 0;
            } else {
                musig_partial_sig_serialize(ctx, my_poison_psigs_per_node[k], &my_ppsig);
            }
            memset(&my_poison_secnonces[k], 0, sizeof(my_poison_secnonces[k]));
        }
    }
    /* INVARIANT: own state + poison secnonces zeroed by musig_create_partial_sig. */
    free(all_pn_flat_c);  /* all-signer nonce matrix no longer needed */

    /* Step 9: send CLIENT_FINAL_PSIGS. */
    cJSON *fp = wire_build_state_adv_client_final_psigs(
        (const unsigned char *)my_psigs_per_node, (uint32_t)n_affected,
        (const unsigned char *)my_poison_psigs_per_node);
    if (!wire_send(fd, MSG_STATE_ADV_CLIENT_FINAL_PSIGS, fp)) {
        cJSON_Delete(fp);
        fprintf(stderr,
            "Client-stateless Tier B %u: send CLIENT_FINAL_PSIGS failed\n", my_index);
        return 0;
    }
    cJSON_Delete(fp);

    /* Step 9b (Gap B): receive the full per-node signer-PSIG matrix so we can
       complete multi-signer nodes locally (we only hold our own + LSP psig).
       Reuses node_nonce_base[] (slot offsets) -- psigs are 32 bytes/slot. */
    wire_msg_t apm;
    if (!wire_recv(fd, &apm) || apm.msg_type != MSG_STATE_ADV_ALL_PSIGS) {
        fprintf(stderr,
            "Client-stateless Tier B %u: expected ALL_PSIGS, got 0x%02x\n",
            my_index, apm.json ? apm.msg_type : 0);
        if (apm.json) cJSON_Delete(apm.json);
        return 0;
    }
    unsigned char *all_psig_flat_c = calloc(total_nonce_slots ? total_nonce_slots : 1, 32);
    if (!all_psig_flat_c) {
        cJSON_Delete(apm.json);
        fprintf(stderr, "Client-stateless Tier B %u: alloc all_psig_flat_c failed\n", my_index);
        return 0;
    }
    uint32_t got_psig_len = 0;
    if (!wire_parse_state_adv_all_psigs(apm.json, all_psig_flat_c,
                                          (uint32_t)(total_nonce_slots * 32), &got_psig_len) ||
        got_psig_len != (uint32_t)(total_nonce_slots * 32)) {
        cJSON_Delete(apm.json);
        free(all_psig_flat_c);
        fprintf(stderr,
            "Client-stateless Tier B %u: parse ALL_PSIGS failed (len %u != %zu)\n",
            my_index, got_psig_len, total_nonce_slots * 32);
        return 0;
    }
    cJSON_Delete(apm.json);

    /* Step 10: for each node we sign, set the co-signer psigs (own + LSP were
       already set in Step 8) then complete_node locally.  Skip nodes we don't
       sign (mirror legacy). */
    for (size_t k = 0; k < n_affected; k++) {
        if (!my_signs_per_node[k]) continue;
        int lsp_slot10 = factory_find_signer_slot(factory, affected[k], 0);
        factory_node_t *an_k = &factory->nodes[affected[k]];
        int psig_ok = 1;
        for (size_t s = 0; s < an_k->n_signers; s++) {
            if (s == (size_t)my_slot_per_node[k] || (int)s == lsp_slot10)
                continue;  /* own + LSP psig already set in Step 8 */
            secp256k1_musig_partial_sig ps_s;
            if (!musig_partial_sig_parse(ctx, &ps_s,
                    all_psig_flat_c + (node_nonce_base[k] + s) * 32) ||
                !factory_session_set_partial_sig(factory, affected[k], s, &ps_s)) {
                psig_ok = 0; break;
            }
        }
        if (!psig_ok) {
            fprintf(stderr,
                "Client-stateless Tier B %u: set co-signer psigs for %zu failed\n",
                my_index, affected[k]);
            free(all_psig_flat_c);
            return 0;
        }
        if (!factory_session_complete_node(factory, affected[k])) {
            fprintf(stderr,
                "Client-stateless Tier B %u: complete_node[%zu] failed\n",
                my_index, affected[k]);
            free(all_psig_flat_c);
            return 0;
        }
    }
    free(all_psig_flat_c);

    /* Step 11: recv DONE (MSG_PATH_SIGN_DONE). */
    wire_msg_t done;
    if (!wire_recv(fd, &done) || done.msg_type != MSG_PATH_SIGN_DONE) {
        fprintf(stderr,
            "Client-stateless Tier B %u: expected PATH_SIGN_DONE, got 0x%02x\n",
            my_index, done.json ? done.msg_type : 0);
        if (done.json) cJSON_Delete(done.json);
        return 0;
    }
    if (done.json) cJSON_Delete(done.json);

    printf("Client-stateless Tier B %u: %zu affected nodes signed\n",
           my_index, n_affected);
    return 1;
}

int client_handle_state_advance(int fd, secp256k1_context *ctx,
                                  const secp256k1_keypair *keypair,
                                  factory_t *factory,
                                  uint32_t my_index,
                                  const wire_msg_t *propose_msg) {
    return client_handle_state_advance_stateless(fd, ctx, keypair, factory, my_index, propose_msg);
}

int client_run_ceremony(secp256k1_context *ctx,
                        const secp256k1_keypair *keypair,
                        const char *host, int port) {
    return client_run_with_channels(ctx, keypair, host, port, NULL, NULL,
                                     NULL, NULL);
}
