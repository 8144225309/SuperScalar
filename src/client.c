#include "superscalar/client.h"
#include "superscalar/cli_arity.h"
#include "superscalar/wire.h"
#include "superscalar/factory.h"
#include "superscalar/fee.h"
#include "superscalar/musig.h"
#include "superscalar/persist.h"
#include "superscalar/shachain.h"
#include "superscalar/tx_builder.h"
#include "superscalar/types.h"   /* secure_zero */
#include "superscalar/crash_inject.h"   /* #9 superscalar_cheat_allowed() */
#include "superscalar/regtest.h"  /* CL7: regtest_send_raw_tx + regtest_t */
#include <secp256k1_schnorrsig.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);
#include "superscalar/sha256.h"

/* Optional NK server authentication pubkey (set via client_set_lsp_pubkey).
 * SF-WT-TRUSTLESS Phase 2c PR-E.2 (#248): de-static'd as
 * g_client_nk_server_pubkey so the extracted client_run_reconnect() in
 * src/client_reconnect.c can read it via extern. */
secp256k1_pubkey g_client_nk_server_pubkey;
int g_client_nk_server_pubkey_set = 0;
#define g_nk_server_pubkey     g_client_nk_server_pubkey
#define g_nk_server_pubkey_set g_client_nk_server_pubkey_set

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

static client_chain_tip_fn g_client_chain_tip_fn = NULL;
static void *g_client_chain_tip_ctx = NULL;

void client_set_chain_tip_source(client_chain_tip_fn fn, void *ctx) {
    g_client_chain_tip_fn = fn;
    g_client_chain_tip_ctx = ctx;
}

uint32_t client_chain_tip(void) {
    return g_client_chain_tip_fn
           ? g_client_chain_tip_fn(g_client_chain_tip_ctx) : 0;
}

static unsigned g_client_chain_tip_attempts = CLIENT_CHAIN_TIP_ATTEMPTS;
static unsigned g_client_chain_tip_retry_ms = CLIENT_CHAIN_TIP_RETRY_MS;

void client_set_chain_tip_retry(unsigned attempts, unsigned delay_ms) {
    g_client_chain_tip_attempts = attempts ? attempts : 1;
    g_client_chain_tip_retry_ms = delay_ms;
}

/* Minimum acceptable profit share in basis points (set via client_set_min_profit_bps).
   If > 0 and the LSP offers less, the client refuses to sign the factory tree. */
static uint16_t g_min_profit_bps = 0;

void client_set_min_profit_bps(uint16_t bps) {
    g_min_profit_bps = bps;
}

/* Channel capacity terms (client_set_capacity_terms); 0 = not set. */
static uint64_t g_expect_capacity = 0;
static uint64_t g_min_capacity = 0;

void client_set_capacity_terms(uint64_t expect_sats, uint64_t min_sats) {
    g_expect_capacity = expect_sats;
    g_min_capacity = min_sats;
}

static uint16_t g_max_lsp_balance_pct = 100;

void client_set_max_lsp_balance_pct(uint16_t pct) {
    g_max_lsp_balance_pct = pct > 100 ? 100 : pct;
}

/* With member capacities the distribution TX follows the capacity rule
   (factory_compute_distribution_outputs_balanced without amounts): per-client
   amounts from the LSP are accepted only when they are exactly those. */
static int client_dist_amounts_acceptable(const factory_t *f, const uint64_t *amounts,
                                          size_t n_amounts, uint32_t my_index) {
    if (!f->member_capacity || n_amounts == 0) return 1;
    tx_output_t outs[FACTORY_MAX_SIGNERS + 1];
    size_t nd = factory_compute_distribution_outputs_balanced(
        f, outs, FACTORY_MAX_SIGNERS + 1,
        factory_distribution_fee(f, f->n_participants - 1), NULL, 0);
    int ok = nd > 0 && nd == n_amounts;
    for (size_t i = 0; ok && i < nd; i++)
        ok = amounts[i] == outs[i].amount_sats;
    if (!ok)
        fprintf(stderr, "Client %u: REFUSING — distribution amounts are not the "
                "capacity-rule amounts\n", my_index);
    return ok;
}

/* Per-member capacities and leaf stock from a FACTORY_PROPOSE. */
typedef struct {
    int present;
    size_t n;
    uint64_t caps[FACTORY_MAX_SIGNERS];
    uint64_t leaf_stock;
} client_capacity_terms_t;

static int client_json_sats(const cJSON *v, uint64_t *out) {
    if (!v || !cJSON_IsNumber(v)) return 0;
    double d = v->valuedouble;
    if (d < 0 || d > 2100000000000000.0 || d != (double)(uint64_t)d) return 0;
    *out = (uint64_t)d;
    return 1;
}

/* Returns 0 on a malformed list; absent fields leave t->present 0. */
static int client_parse_capacity_terms(const cJSON *j, client_capacity_terms_t *t) {
    memset(t, 0, sizeof(*t));
    const cJSON *caps = cJSON_GetObjectItem(j, "capacities");
    if (!caps) return 1;
    if (!cJSON_IsArray(caps)) return 0;
    int n = cJSON_GetArraySize(caps);
    if (n < 1 || n >= FACTORY_MAX_SIGNERS) return 0;
    for (int i = 0; i < n; i++)
        if (!client_json_sats(cJSON_GetArrayItem(caps, i), &t->caps[i])) return 0;
    if (!client_json_sats(cJSON_GetObjectItem(j, "leaf_stock"), &t->leaf_stock))
        return 0;
    t->n = (size_t)n;
    t->present = 1;
    return 1;
}

static int client_apply_capacity_terms(factory_t *f, const client_capacity_terms_t *t) {
    if (!t->present) return 1;
    return factory_set_member_capacities(f, t->caps, t->n) &&
           factory_set_leaf_stock(f, t->leaf_stock);
}

/* The member's own channel output in the built tree: logged, and checked
   against the capacity terms.  Returns 0 to refuse the factory. */
static int client_capacity_acceptable(const factory_t *f, uint32_t my_index) {
    size_t ni;
    uint32_t vout;
    if (my_index == 0 || !factory_client_to_leaf(f, my_index - 1, &ni, &vout) ||
        vout >= f->nodes[ni].n_outputs) {
        fprintf(stderr, "Client %u: no channel output for this member\n", my_index);
        return 0;
    }
    uint64_t cap = f->nodes[ni].outputs[vout].amount_sats;
    if (f->member_capacity && cap != f->member_capacity[my_index]) {
        fprintf(stderr, "Client %u: REFUSING — channel output %llu sats, proposed "
                "capacity %llu\n", my_index, (unsigned long long)cap,
                (unsigned long long)f->member_capacity[my_index]);
        return 0;
    }
    printf("Client %u: channel capacity %llu sats%s\n", my_index,
           (unsigned long long)cap, f->member_capacity ? " (proposed)" : "");
    if (g_expect_capacity > 0 && cap != g_expect_capacity) {
        fprintf(stderr, "Client %u: REFUSING — channel capacity %llu sats, expected "
                "%llu (--expect-capacity)\n", my_index, (unsigned long long)cap,
                (unsigned long long)g_expect_capacity);
        return 0;
    }
    if (g_min_capacity > 0 && cap < g_min_capacity) {
        fprintf(stderr, "Client %u: REFUSING — channel capacity %llu sats below "
                "minimum %llu (--min-capacity)\n", my_index, (unsigned long long)cap,
                (unsigned long long)g_min_capacity);
        return 0;
    }
    return 1;
}

static uint64_t g_max_tree_fee_rate = CLIENT_DEFAULT_MAX_TREE_FEE_RATE;

void client_set_max_tree_fee_rate(uint64_t sat_per_kvb) {
    g_max_tree_fee_rate = sat_per_kvb;
}

uint64_t client_max_tree_fee_rate(void) {
    return g_max_tree_fee_rate;
}

int client_tree_fee_rate_acceptable(uint64_t sat_per_kvb) {
    return g_max_tree_fee_rate == 0 || sat_per_kvb <= g_max_tree_fee_rate;
}

/* Fee check on a tree the client built from FACTORY_PROPOSE, before it signs
   anything: the proposed rate must be within the member's own ceiling, and
   every node (and the distribution TX once built) must pay exactly that rate
   for its exact size (factory_check_tree_fees). */
static int client_check_tree_fees(const factory_t *f, uint64_t proposed_rate,
                                  uint32_t my_index) {
    if (!client_tree_fee_rate_acceptable(proposed_rate)) {
        fprintf(stderr, "Client %u: REFUSING — tree fee rate %llu sat/kvB above this "
                "member's ceiling of %llu sat/kvB (--max-tree-fee-rate)\n", my_index,
                (unsigned long long)proposed_rate,
                (unsigned long long)g_max_tree_fee_rate);
        return 0;
    }
    if (f->cltv_timeout > 0 && f->n_participants - 1 > FACTORY_MAX_DIST_CLIENTS) {
        fprintf(stderr, "Client %u: REFUSING — %zu clients: the distribution TX "
                "would not fit a %d vB TRUC transaction (at most %d clients)\n",
                my_index, f->n_participants - 1, TRUC_MAX_VSIZE,
                FACTORY_MAX_DIST_CLIENTS);
        return 0;
    }
    char why[200];
    if (f->tree_fee_rate != proposed_rate || !factory_check_tree_fees(f, why, sizeof(why))) {
        if (f->tree_fee_rate != proposed_rate)
            snprintf(why, sizeof(why), "tree built at %llu sat/kvB, %llu proposed",
                     (unsigned long long)f->tree_fee_rate,
                     (unsigned long long)proposed_rate);
        fprintf(stderr, "Client %u: REFUSING — %s\n", my_index, why);
        return 0;
    }
    return 1;
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

/* Both sides of the conservation invariant for ch: what the channel state
   accounts for (balances plus every active HTLC and PTLC) and what the
   funding output holds once the base commitment fee is taken off.  Returns 1
   if they agree. */
static int client_channel_conserved(const channel_t *ch, uint64_t *sum_out,
                                     uint64_t *expected_out,
                                     uint64_t *base_commit_fee_out) {
    uint64_t sum = ch->local_amount + ch->remote_amount;
    for (size_t h = 0; h < ch->n_htlcs; h++) {
        if (ch->htlcs[h].state == HTLC_STATE_ACTIVE) {
            sum += ch->htlcs[h].amount_sats;
            sum += ch->htlcs[h].fee_at_add;
        }
    }
    for (size_t t = 0; t < ch->n_ptlcs; t++) {
        if (ch->ptlcs[t].state == PTLC_STATE_ACTIVE) {
            sum += ch->ptlcs[t].amount_sats;
            sum += ch->ptlcs[t].fee_at_add;
        }
    }
    /* Base commit-tx fee at the channel's agreed rate (fee_commitment_tx_at). */
    uint64_t base_commit_fee = fee_commitment_tx_at(ch->commit_fee_rate_sat_per_kvb, 0);
    uint64_t expected = ch->funding_amount > base_commit_fee
                        ? ch->funding_amount - base_commit_fee : 0;
    if (sum_out) *sum_out = sum;
    if (expected_out) *expected_out = expected;
    if (base_commit_fee_out) *base_commit_fee_out = base_commit_fee;
    return sum == expected;
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
int client_channel_balanced(const channel_t *ch) {
    return ch && ch->funding_amount != 0 &&
           client_channel_conserved(ch, NULL, NULL, NULL);
}

static void client_check_conservation(const channel_t *ch, const char *context) {
    if (!ch || ch->funding_amount == 0) return;
    uint64_t sum, expected, base_commit_fee;
    if (!client_channel_conserved(ch, &sum, &expected, &base_commit_fee)) {
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

/* SF-followup #145: the client's active factory_t.  Set at the entry of
   client_run_with_channels / client_run_reconnect, cleared on exit; NULL
   during pre-factory bootstrap.  (It used to let MSG_FUNDING_REORG wipe the
   sub-factory chain state, mirroring the LSP's reorg handler; neither side
   does that any more, since the chains are off-chain until a force-close.) */
/* SF-WT-TRUSTLESS Phase 2c PR-E.2 (#248): de-static'd so
 * src/client_reconnect.c (extracted) can write it on reconnect. */
factory_t *g_client_active_factory = NULL;

/* Handle async / unsolicited LSP->client notifications that can arrive at any
   time between (or during) request/response exchanges:
     - MSG_FUNDING_REORG: mirror the LSP's funding freeze state + reset stale
       sub-factory chains (SF-followup #145 / reorg PR #208).
     - MSG_CEREMONY_ABORT: advisory abort / intent-to-exit notice (#49/#51).
   Returns 1 if msg was one of these (caller treats it as consumed but must still
   free msg->json), 0 otherwise.  Shared by wire_recv_handle_ping (ceremony recv
   path) AND the client daemon dispatch in tools/superscalar_client.c so BOTH
   handle them identically.  Before this the daemon loop hit its "unexpected msg"
   default on FUNDING_REORG, desynced, and livelocked reconnecting -- breaking
   inbound bridge payments whenever the LSP sent a routine funding-reorg notice. */
int client_handle_async_msg(const wire_msg_t *msg) {
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
        /* Sub-factory chain state is kept: the LSP no longer wipes it on a
           reorg (chains are off-chain until a force-close), and wiping it
           here left chain[N] signed bytes without the chain state. */
        return 1;
    }
    if (msg->msg_type == MSG_CEREMONY_ABORT) {
        /* #49/#51: advisory abort / intent-to-exit notice.  The client's own
           persisted state + watchtower already protect its funds; log it loudly
           so the operator can stop waiting on a ceremony that will never finish. */
        unsigned char cer_id[8];
        unsigned char reason = CEREMONY_ABORT_OTHER;
        char *rtext = NULL;
        if (msg->json &&
            wire_parse_ceremony_abort(msg->json, cer_id, &reason, &rtext)) {
            fprintf(stderr, "Client: MSG_CEREMONY_ABORT reason=0x%02x%s%s\n",
                    reason, rtext ? " -- " : "", rtext ? rtext : "");
            free(rtext);
        } else {
            fprintf(stderr, "Client: MSG_CEREMONY_ABORT (unparseable)\n");
        }
        return 1;
    }
    return 0;
}

/* Wrapper around wire_recv_timeout that transparently handles keepalives
   (MSG_PING -> MSG_PONG, MSG_PONG discard) and async notifications (delegated to
   client_handle_async_msg).  Returns 1 on a real message, 0 on failure. */
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
        if (client_handle_async_msg(msg)) {
            if (msg->json) cJSON_Delete(msg->json);
            msg->json = NULL;
            continue;  /* async notification consumed; wait for real message */
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

    /* Commitment tx fee: the factory's agreed rate for the commitment's exact
       size, as lsp_channels_init computes it, so both sides agree. */
    (void)fee_est;
    uint64_t commit_fee = fee_commitment_tx_at(factory->tree_fee_rate, 0);
    if (commit_fee == FEE_INVALID) {
        fprintf(stderr, "client: commitment fee not computable at the agreed rate\n");
        return 0;
    }
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
    ch->use_cpfp_anchor = 1;  /* #56: P2A CPFP anchor on commitments (matches LSP side) */
    channel_set_commit_fee_rate(ch, factory->tree_fee_rate);  /* the agreed rate */

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
    /* Whatever this side offered is in a commitment the LSP has signed now:
       it can no longer be taken back as never committed. */
    ch->has_unsigned_offer = 0;

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

int client_handle_initial_commitment_signed(channel_t *ch, const wire_msg_t *msg) {
    if (!ch || !msg || msg->msg_type != MSG_COMMITMENT_SIGNED) return 0;

    uint32_t channel_id;
    uint64_t commitment_number;
    unsigned char partial_sig32[32];
    uint32_t nonce_index;
    if (!wire_parse_commitment_signed(msg->json, &channel_id,
                                        &commitment_number, partial_sig32,
                                        &nonce_index)) {
        fprintf(stderr, "Client: malformed initial COMMITMENT_SIGNED\n");
        return 0;
    }
    if (commitment_number != 0 || ch->commitment_number != 0) {
        fprintf(stderr, "Client: initial COMMITMENT_SIGNED is for commitment %llu "
                "(channel at %llu), expected 0\n",
                (unsigned long long)commitment_number,
                (unsigned long long)ch->commitment_number);
        return 0;
    }

    unsigned char full_sig64[64];
    if (!channel_verify_and_aggregate_commitment_sig(ch, partial_sig32,
                                                       nonce_index, full_sig64)) {
        fprintf(stderr, "Client: initial commitment sig verification/aggregation failed\n");
        return 0;
    }
    memcpy(ch->latest_commitment_sig, full_sig64, 64);
    ch->has_latest_commitment_sig = 1;
    return 1;
}

static int g_rotation_new_factory_saved = 0;

int client_rotation_new_factory_saved(void) {
    return g_rotation_new_factory_saved;
}

static client_verify_funding_fn g_client_verify_funding = NULL;
static void *g_client_verify_funding_ctx = NULL;
static int g_client_allow_unverified_funding = 0;
static int g_client_funding_min_confs = 1;
static int g_client_allow_rotation = 0;

void client_set_funding_min_confs(int confs) {
    g_client_funding_min_confs = confs > 0 ? confs : 1;
}

void client_set_allow_rotation(int allow) {
    g_client_allow_rotation = allow ? 1 : 0;
}

int client_rotation_allowed(void) {
    return g_client_allow_rotation;
}

void client_set_funding_verifier(client_verify_funding_fn fn, void *ctx) {
    g_client_verify_funding = fn;
    g_client_verify_funding_ctx = ctx;
}

void client_set_allow_unverified_funding(int allow) {
    g_client_allow_unverified_funding = allow ? 1 : 0;
}

int client_check_factory_funding(const factory_t *f, uint32_t my_index,
                                  const secp256k1_pubkey *my_pubkey) {
    if (!f || !my_pubkey || f->n_nodes == 0) return 0;

    /* Our own key must be the one at our index: the scripts below are
       derived from this participant set. */
    unsigned char a[33], b[33];
    size_t al = 33, bl = 33;
    if (my_index == 0 || my_index >= f->n_participants ||
        !secp256k1_ec_pubkey_serialize(f->ctx, a, &al, &f->pubkeys[my_index],
                                       SECP256K1_EC_COMPRESSED) ||
        !secp256k1_ec_pubkey_serialize(f->ctx, b, &bl, my_pubkey,
                                       SECP256K1_EC_COMPRESSED) ||
        memcmp(a, b, 33) != 0) {
        fprintf(stderr, "Client: REFUSING factory — this client's key is not at "
                "index %u of the participant set\n", my_index);
        return 0;
    }

    /* The funding script is not taken from the proposal: it is the script
       the root transaction spends, derived from the participant keys. */
    const factory_node_t *root = &f->nodes[0];
    if (root->spending_spk_len != 34 || f->funding_spk_len != 34 ||
        memcmp(root->spending_spk, f->funding_spk, 34) != 0) {
        fprintf(stderr, "Client: REFUSING factory — the proposed funding script is "
                "not the script of this participant set\n");
        return 0;
    }

    if (!g_client_verify_funding && g_client_allow_unverified_funding) {
        fprintf(stderr, "Client: funding output NOT looked up on chain (regtest "
                "without --rpcuser; harness only)\n");
        return 1;
    }
    if (!g_client_verify_funding) {
        fprintf(stderr, "Client: REFUSING factory — no chain lookup is available to "
                "verify the funding output (no working RPC connection; the "
                "light-client mode cannot verify a funding output)\n");
        return 0;
    }
    client_funding_output_t out;
    memset(&out, 0, sizeof(out));
    out.unspent = -1;
    if (!g_client_verify_funding(f->funding_txid, f->funding_vout, &out,
                                 g_client_verify_funding_ctx)) {
        fprintf(stderr, "Client: REFUSING factory — funding output not found on chain\n");
        return 0;
    }
    if (out.spk_len != 34 || memcmp(out.spk, root->spending_spk, 34) != 0) {
        fprintf(stderr, "Client: REFUSING factory — the funding output on chain does "
                "not pay to this participant set\n");
        return 0;
    }
    if (out.amount_sats != f->funding_amount_sats) {
        fprintf(stderr, "Client: REFUSING factory — funding output holds %llu sats, "
                "proposal says %llu (must be equal)\n",
                (unsigned long long)out.amount_sats,
                (unsigned long long)f->funding_amount_sats);
        return 0;
    }
    if (out.unspent != 1) {
        fprintf(stderr, "Client: REFUSING factory — funding output is %s\n",
                out.unspent == 0 ? "already spent" : "of unknown spent status");
        return 0;
    }
    if (out.confirmations < g_client_funding_min_confs) {
        fprintf(stderr, "Client: REFUSING factory — funding output has %d "
                "confirmation(s), %d required\n", out.confirmations,
                g_client_funding_min_confs);
        return 0;
    }
    printf("Client: funding output verified: script and amount (%llu sats) match, "
           "unspent, %d confirmation(s)\n",
           (unsigned long long)out.amount_sats, out.confirmations);
    return 1;
}

int client_dist_locktime_acceptable(const factory_t *f, uint32_t offered) {
    return f && offered != 0 && offered == factory_distribution_locktime(f);
}

uint64_t client_member_channel_capacity(const factory_t *f, uint32_t my_index) {
    if (!f || my_index == 0) return 0;
    /* Member capacities: the distribution owes the member its capacity-rule
       payout (full capacity + its leaf stock share + its share of the rest,
       factory_compute_distribution_outputs_balanced), which is never less
       than the capacity itself. */
    if (f->member_capacity) {
        if (my_index >= f->n_participants || f->n_participants - 1 > FACTORY_MAX_SIGNERS)
            return 0;
        tx_output_t outs[FACTORY_MAX_SIGNERS + 1];
        size_t nd = factory_compute_distribution_outputs_balanced(
            f, outs, FACTORY_MAX_SIGNERS + 1,
            factory_distribution_fee(f, f->n_participants - 1), NULL, 0);
        if (nd != f->n_participants - 1) return 0;
        /* output 0 carries the anchor the distribution TX takes from it */
        uint64_t pay = outs[my_index - 1].amount_sats -
                       (my_index == 1 ? factory_tree_anchor_sats(f) : 0);
        return pay >= f->member_capacity[my_index] ? pay : 0;
    }
    size_t lnode;
    uint32_t lvout;
    if (!factory_client_to_leaf(f, (size_t)(my_index - 1), &lnode, &lvout) ||
        lnode >= f->n_nodes || lvout >= f->nodes[lnode].n_outputs)
        return 0;
    uint64_t out = f->nodes[lnode].outputs[lvout].amount_sats;
    /* the base commitment fee every channel reserves at open: the factory's
       agreed rate for the commitment's size (client_init_channel) */
    uint64_t fee = fee_commitment_tx_at(f->tree_fee_rate, 0);
    if (fee == FEE_INVALID) return 0;
    return out > fee ? out - fee : 0;
}

int client_distribution_pays_member(const secp256k1_context *ctx,
                                     const unsigned char *tx, size_t tx_len,
                                     const secp256k1_pubkey *member_pubkey,
                                     uint64_t required_sats) {
    if (!ctx || !tx || !member_pubkey || tx_len == 0) return 0;
    return client_tx_amount_to_pubkey(ctx, tx, tx_len, member_pubkey) >= required_sats;
}

int client_factory_exit_acceptable(const secp256k1_context *ctx, const factory_t *f,
                                    uint32_t my_index,
                                    const secp256k1_pubkey *my_pubkey) {
    if (!ctx || !f || !my_pubkey) return 0;
    if (f->dist_tx_ready != 2 || f->dist_unsigned_tx.len == 0) {
        fprintf(stderr, "Client: no fully co-signed, verified distribution "
                "transaction for this factory\n");
        return 0;
    }
    uint64_t need = client_member_channel_capacity(f, my_index);
    if (need == 0) {
        fprintf(stderr, "Client: this member has no channel output in the factory\n");
        return 0;
    }
    if (!client_distribution_pays_member(ctx, f->dist_unsigned_tx.data,
                                         f->dist_unsigned_tx.len, my_pubkey, need)) {
        fprintf(stderr, "Client: the distribution transaction pays this member %llu "
                "sats, its channel capacity is %llu\n",
                (unsigned long long)client_tx_amount_to_pubkey(ctx,
                    f->dist_unsigned_tx.data, f->dist_unsigned_tx.len, my_pubkey),
                (unsigned long long)need);
        return 0;
    }
    return 1;
}

/* 1 if some output of a stored tree node of factory 0 is in the UTXO set (or
   the mempool): this client's own tree is on chain.  0 if none is, -1 if
   the chain source could not answer for an output it was asked about. */
static int client_own_tree_on_chain(persist_t *db, chain_backend_t *chain) {
    if (!chain->is_outpoint_unspent) return -1;
    int err = 0;
    for (uint32_t ni = 0; ni < 4096; ni++) {
        char txid[65];
        uint32_t n_out = 0;
        if (!persist_load_tree_node_txid(db, 0, ni, txid, &n_out)) break;
        for (uint32_t v = 0; v < n_out && v < 1024; v++) {
            int r = chain->is_outpoint_unspent(chain, txid, v);
            if (r == 1) return 1;
            if (r < 0) err = 1;
        }
    }
    return err ? -1 : 0;
}

int client_force_close_plan(persist_t *db, chain_backend_t *chain,
                             uint32_t *dist_factory_out, FILE *out) {
    if (!db || !chain || !dist_factory_out) return -1;
    if (!out) out = stderr;
    *dist_factory_out = 0;

    uint64_t cn = 0;
    size_t clen = 0;
    int has_commitment =
        persist_load_commitment_sig(db, CLIENT_DB_CHANNEL_ID, &cn, NULL, NULL, &clen, 0) && clen > 0;

    if (!persist_has_factory(db, CLIENT_ROTATION_PENDING_FACTORY_ID)) {
        if (has_commitment) return 1;
        fprintf(out, "Force-close: no signed commitment in DB; NOT publishing the "
                     "factory tree\n");
        return 0;
    }

    char txid[65] = {0};
    uint32_t vout = 0;
    int have_op = persist_load_factory_outpoint(db, 0, txid, &vout, NULL);
    int unspent = (have_op && chain->is_outpoint_unspent)
                  ? chain->is_outpoint_unspent(chain, txid, vout) : -1;
    if (unspent == 1 && has_commitment) {
        fprintf(out, "Force-close: rotation pending; the factory being left (%s:%u) "
                     "is unspent, exiting through it\n", txid, vout);
        return 1;
    }
    if (unspent == 1) {
        fprintf(out, "Force-close: rotation pending; the factory being left (%s:%u) "
                     "is unspent but no commitment for its channel is on disk; NOT "
                     "publishing its tree, offering its distribution transaction\n",
                txid, vout);
        return 0;
    }
    /* Funding output spent (or unknown).  If any output of this client's own
       tree of the factory being left is in the UTXO set, the exit through it
       is under way (an earlier pass published it) and has to be continued.
       gettxout-style lookups answer for outputs of any age; a confirmation
       count for the root would need an index. */
    int own = client_own_tree_on_chain(db, chain);
    if (own == 1 && has_commitment) {
        fprintf(out, "Force-close: rotation pending; this client's own tree of the "
                     "factory being left is on chain, continuing the exit through it\n");
        return 1;
    }
    if (unspent != 0 || own < 0) {
        fprintf(out, "Force-close: rotation pending and the chain source could not "
                     "say whether %s:%u is spent or by what; nothing published, try "
                     "again\n", txid, vout);
        return -1;
    }
    *dist_factory_out = CLIENT_ROTATION_PENDING_FACTORY_ID;
    fprintf(out, "Force-close: rotation pending and the factory being left was spent "
                 "by another transaction; NOT publishing the factory tree of the new "
                 "factory (no commitment for it)\n");
    return 0;
}

int client_verify_distribution_tx(const secp256k1_context *ctx,
                                   const unsigned char *unsigned_tx, size_t unsigned_len,
                                   const unsigned char *sighash32,
                                   const unsigned char *funding_spk34,
                                   const unsigned char *signed_tx, size_t signed_len) {
    if (!ctx || !unsigned_tx || !sighash32 || !funding_spk34 || !signed_tx) return 0;
    if (unsigned_len == 0 || signed_len < 4 + 64) return 0;
    if (funding_spk34[0] != 0x51 || funding_spk34[1] != 0x20) return 0;

    /* The only place a key-path signature can sit is right before nLockTime.
       Rebuild the signed form from our own bytes and that signature: anything
       else in the LSP's transaction that differs from ours shows up here. */
    const unsigned char *sig = signed_tx + signed_len - 4 - 64;
    tx_buf_t expect;
    tx_buf_init(&expect, unsigned_len + 80);
    int same = finalize_signed_tx(&expect, unsigned_tx, unsigned_len, sig) &&
               expect.len == signed_len &&
               memcmp(expect.data, signed_tx, signed_len) == 0;
    tx_buf_free(&expect);
    if (!same) return 0;

    secp256k1_xonly_pubkey key;
    return secp256k1_xonly_pubkey_parse(ctx, &key, funding_spk34 + 2) &&
           secp256k1_schnorrsig_verify(ctx, sig, sighash32, 32, &key);
}

uint64_t client_tx_amount_to_pubkey(const secp256k1_context *ctx,
                                     const unsigned char *tx, size_t len,
                                     const secp256k1_pubkey *pubkey) {
    if (!ctx || !tx || !pubkey || len < 60) return 0;
    unsigned char spk[34], ser[32], tweak[32];
    secp256k1_xonly_pubkey xonly, tweaked;
    secp256k1_pubkey full;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, NULL, pubkey) ||
        !secp256k1_xonly_pubkey_serialize(ctx, ser, &xonly)) return 0;
    sha256_tagged("TapTweak", ser, 32, tweak);
    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &full, &xonly, tweak) ||
        !secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked, NULL, &full)) return 0;
    build_p2tr_script_pubkey(spk, &tweaked);

    size_t off = 4;
    if (tx[4] == 0x00 && tx[5] == 0x01) off += 2;      /* segwit marker + flag */
    if (tx[off] != 1) return 0;                         /* one input */
    off += 1 + 36;
    if (off >= len || tx[off] != 0) return 0;           /* empty scriptSig */
    off += 1 + 4;
    if (off >= len || tx[off] >= 253) return 0;
    size_t n_out = tx[off++];
    uint64_t total = 0;
    for (size_t i = 0; i < n_out; i++) {
        if (off + 9 > len) return 0;
        uint64_t amt = 0;
        for (int b = 7; b >= 0; b--) amt = (amt << 8) | tx[off + b];
        size_t sl = tx[off + 8];
        if (sl >= 253 || off + 9 + sl > len) return 0;
        if (sl == 34 && memcmp(tx + off + 9, spk, 34) == 0) total += amt;
        off += 9 + sl;
    }
    return total;
}

int client_rotation_save_pending(persist_t *db, const factory_t *f,
                                  secp256k1_context *ctx) {
    if (!db || !f) return 0;
    if (!persist_begin(db)) return 0;
    int ok = persist_delete_factory_record(db, CLIENT_ROTATION_PENDING_FACTORY_ID) &&
             persist_save_factory(db, f, ctx, CLIENT_ROTATION_PENDING_FACTORY_ID) &&
             persist_save_tree_nodes(db, f, CLIENT_ROTATION_PENDING_FACTORY_ID);
    if (ok && f->dist_tx_ready == 2 && f->dist_unsigned_tx.len > 0)
        ok = persist_save_distribution_tx(db, CLIENT_ROTATION_PENDING_FACTORY_ID,
                                          f->dist_unsigned_tx.data,
                                          f->dist_unsigned_tx.len);
    if (!ok) { persist_rollback(db); return 0; }
    return persist_commit(db);
}

/* Rotation: put the new factory, its verified tree and its verified
   distribution transaction on disk next to the factory being left, before
   any channel set-up.  The old factory's rows and the old channel's
   commitment stay exactly as they are: until commitment 0 of the new channel
   is saved the client still has the old exit (for as long as the old funding
   output is unspent) and already has the new factory's distribution
   transaction.  Returns 0 if a database is attached and the write failed. */
static int client_rotation_save_factory(factory_t *f, secp256k1_context *ctx,
                                         uint32_t my_index) {
    persist_t *db = g_client_persist;
    if (!db) return 1;
    if (!client_rotation_save_pending(db, f, ctx)) return 0;
    g_rotation_new_factory_saved = 1;
    printf("Client %u: new factory, signed tree and distribution TX saved "
           "before channel set-up\n", my_index);
    return 1;
}

/* Channel open: receive the LSP's COMMITMENT_SIGNED for commitment 0, which
   the LSP sends right after the nonce exchange. */
int client_recv_initial_commitment(int fd, channel_t *ch, uint32_t my_index) {
    wire_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    if (!wire_recv_skip_ping(fd, &msg)) {
        fprintf(stderr, "Client %u: connection lost waiting for the initial "
                "COMMITMENT_SIGNED\n", my_index);
        return 0;
    }
    if (check_msg_error(&msg) || msg.msg_type != MSG_COMMITMENT_SIGNED) {
        fprintf(stderr, "Client %u: expected initial COMMITMENT_SIGNED, got 0x%02x\n",
                my_index, msg.msg_type);
        if (msg.json) cJSON_Delete(msg.json);
        return 0;
    }
    /* The commitment about to be signed must account for the whole funding
       output: balances == funding - base commitment fee.  The cooperative
       close check relies on that holding from the first state on. */
    uint64_t accounted = 0, expected = 0;
    if (!client_channel_conserved(ch, &accounted, &expected, NULL)) {
        fprintf(stderr, "Client %u: opening balances account for %llu sats, "
                "funding minus commitment fee is %llu\n", my_index,
                (unsigned long long)accounted, (unsigned long long)expected);
        cJSON_Delete(msg.json);
        return 0;
    }
    int ok = client_handle_initial_commitment_signed(ch, &msg);
    cJSON_Delete(msg.json);
    if (!ok)
        fprintf(stderr, "Client %u: initial commitment rejected, channel not usable\n",
                my_index);
    return ok;
}

int client_persist_latest_commitment(persist_t *db, uint32_t channel_id,
                                       const channel_t *ch) {
    if (!db || !ch || !ch->has_latest_commitment_sig) return 0;

    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 512);
    unsigned char txid[32];
    if (!channel_build_commitment_tx(ch, &unsigned_tx, txid)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }
    tx_buf_t signed_tx;
    tx_buf_init(&signed_tx, 512);
    if (!finalize_signed_tx(&signed_tx, unsigned_tx.data, unsigned_tx.len,
                             ch->latest_commitment_sig)) {
        tx_buf_free(&unsigned_tx);
        tx_buf_free(&signed_tx);
        return 0;
    }
    tx_buf_free(&unsigned_tx);

    int ok = persist_save_commitment_sig(db, channel_id, ch->commitment_number,
                                          ch->latest_commitment_sig,
                                          signed_tx.data, signed_tx.len);
    tx_buf_free(&signed_tx);
    return ok;
}

int client_handle_lsp_revoke_and_ack(channel_t *ch, secp256k1_context *ctx,
                                       const wire_msg_t *msg) {
    if (!ch || !msg) return 0;
    uint32_t cid;
    unsigned char rev_secret[32], next_point[33];
    if (!wire_parse_revoke_and_ack(msg->json, &cid, rev_secret, next_point))
        return 0;

    /* At commitment 0 there is no prior LSP commitment to revoke yet. */
    if (ch->commitment_number == 0) {
        volatile unsigned char *z = (volatile unsigned char *)rev_secret;
        for (int i = 0; i < 32; i++) z[i] = 0;
        return 1;
    }

    uint64_t old_cn = ch->commitment_number - 1;
    /* Verify the LSP's secret against the LSP's committed point (secret*G ==
       committed_PCP). channel_verify_revocation_secret consults the durable
       record, and the choke point re-verifies on store — fail closed. */
    if (!channel_verify_revocation_secret(ch, old_cn, rev_secret)) {
        fprintf(stderr, "Client: INVALID LSP revocation secret (commitment %llu) "
                "— rejecting (fail-closed)\n", (unsigned long long)old_cn);
        volatile unsigned char *z = (volatile unsigned char *)rev_secret;
        for (int i = 0; i < 32; i++) z[i] = 0;
        return 0;
    }
    channel_receive_revocation(ch, old_cn, rev_secret);
    { volatile unsigned char *z = (volatile unsigned char *)rev_secret;
      for (int i = 0; i < 32; i++) z[i] = 0; }

    /* Track the LSP's NEXT per-commitment point (carried in this message) so
       subsequent LSP revocations remain verifiable. The client used to discard
       this. */
    secp256k1_pubkey next_pcp;
    if (secp256k1_ec_pubkey_parse(ctx, &next_pcp, next_point, 33))
        channel_set_remote_pcp(ch, ch->commitment_number + 1, &next_pcp);
    return 1;
}

int client_parse_forgery_response(const char *s) {
    if (!s) return -1;
    if (strcmp(s, "continue") == 0) return LSP_FORGERY_CONTINUE;
    if (strcmp(s, "halt")     == 0) return LSP_FORGERY_HALT;
    if (strcmp(s, "close")    == 0) return LSP_FORGERY_CLOSE;
    return -1;
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

int client_handle_fail_htlc(channel_t *ch, const wire_msg_t *msg,
                             int *committed_out, uint64_t *htlc_id_out) {
    uint64_t htlc_id;
    char reason[128];
    if (!wire_parse_update_fail_htlc(msg->json, &htlc_id, reason, sizeof(reason)))
        return 0;
    int uncommitted = wire_update_fail_htlc_is_uncommitted(msg->json);
    if (committed_out) *committed_out = !uncommitted;
    if (htlc_id_out) *htlc_id_out = htlc_id;
    int ok = uncommitted ? channel_rollback_htlc(ch, htlc_id)
                         : channel_fail_htlc(ch, htlc_id);
    if (!ok)
        fprintf(stderr, "Client: PROTOCOL ERROR — UPDATE_FAIL_HTLC%s for HTLC "
                "%llu (%s) does not match the channel; nothing changed\n",
                uncommitted ? " (never committed)" : "",
                (unsigned long long)htlc_id, reason);
    else
        printf("Client: HTLC %llu %s: %s\n", (unsigned long long)htlc_id,
               uncommitted ? "refused" : "failed", reason);
    return ok;
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

int client_close_script(const secp256k1_context *ctx,
                         const secp256k1_pubkey *my_pubkey,
                         unsigned char *spk_out34) {
    secp256k1_xonly_pubkey xonly;
    if (!ctx || !my_pubkey || !spk_out34) return 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, NULL, my_pubkey))
        return 0;
    build_p2tr_script_pubkey(spk_out34, &xonly);
    return 1;
}

int client_close_amount_to_client(const secp256k1_context *ctx,
                                   const secp256k1_pubkey *my_pubkey,
                                   const tx_output_t *outputs,
                                   size_t n_outputs,
                                   uint64_t *paid_sats_out,
                                   size_t *n_paying_out) {
    /* Amounts sent to any other script are not the client's, however large,
       so only outputs carrying exactly its own script are counted.  An
       output below the dust limit is not counted either: it is not relayed
       as part of a standard transaction and costs more to spend than it
       holds, so a balance split into such outputs is not paid at all. */
    unsigned char my_spk[34];
    uint64_t paid = 0;
    size_t n_paying = 0;
    if (!paid_sats_out || (!outputs && n_outputs > 0)) return 0;
    if (!client_close_script(ctx, my_pubkey, my_spk)) return 0;
    for (size_t i = 0; i < n_outputs; i++) {
        if (outputs[i].script_pubkey_len != sizeof(my_spk) ||
            memcmp(outputs[i].script_pubkey, my_spk, sizeof(my_spk)) != 0)
            continue;
        if (outputs[i].amount_sats < CHANNEL_DUST_LIMIT_SATS) continue;
        if (outputs[i].amount_sats > UINT64_MAX - paid) return 0;
        paid += outputs[i].amount_sats;
        n_paying++;
    }
    *paid_sats_out = paid;
    if (n_paying_out) *n_paying_out = n_paying;
    return 1;
}

int client_close_locktime_acceptable(uint32_t locktime, uint32_t tip_height) {
    if (locktime == 0) return 1;             /* no lock at all */
    if (locktime >= 500000000u) return 0;    /* time-based lock */
    if (tip_height == 0) return 0;           /* nothing to judge a height by */
    if (locktime <= tip_height) return 1;
    return locktime - tip_height <= CLIENT_CLOSE_LOCKTIME_MARGIN;
}

void client_close_state_init(client_close_state_t *cs, persist_t *db,
                              const factory_t *factory) {
    if (!cs) return;
    memset(cs, 0, sizeof(*cs));
    cs->db = db;
    if (db && factory) {
        int r = persist_load_close_signed(db, factory->funding_txid,
                                           factory->funding_vout,
                                           &cs->paid_sats, cs->sighash);
        if (r > 0) cs->signed_close = 1;
        else if (r < 0) cs->record_error = 1;
    }
}

/* What this client's records say about a signed cooperative close of the
   factory: 1 signed, 0 not signed (or no database), -1 cannot be read.  A
   factory with a signed close is frozen: see client_close_state_t. */
static int client_factory_close_record(const factory_t *factory) {
    if (!g_client_persist || !factory) return 0;
    return persist_load_close_signed(g_client_persist, factory->funding_txid,
                                      factory->funding_vout, NULL, NULL);
}

int client_close_state_frozen(client_close_state_t *cs,
                               const factory_t *factory) {
    if (!cs) return 1;
    if (cs->signed_close) return 1;
    if (!cs->record_error) return 0;
    /* The record could not be read.  Look again: if the error has passed,
       the answer is whatever the record says; if not, the factory stays
       frozen, because a signed close cannot be ruled out. */
    int r = (cs->db && factory)
        ? persist_load_close_signed(cs->db, factory->funding_txid,
                                     factory->funding_vout,
                                     &cs->paid_sats, cs->sighash)
        : -1;
    if (r < 0) return 1;
    cs->record_error = 0;
    if (r > 0) cs->signed_close = 1;
    return cs->signed_close;
}

int client_close_signed_for_factory(const factory_t *factory) {
    client_close_state_t cs;
    client_close_state_init(&cs, g_client_persist, factory);
    return client_close_state_frozen(&cs, factory);
}

int client_close_frozen_allows_msg(uint8_t msg_type) {
    return msg_type == MSG_CLOSE_PROPOSE ||
           msg_type == MSG_PING || msg_type == MSG_PONG ||
           msg_type == MSG_LSP_REVOKE_AND_ACK;
}

/* Refuse a leaf or state advance of a factory whose close was signed, or
   whose close record cannot be read.  Returns 1 if the advance was refused
   (an error was sent to the LSP). */
static int client_refuse_advance_if_close_signed(int fd,
                                                  const factory_t *factory,
                                                  uint32_t my_index,
                                                  const char *what) {
    int r = client_factory_close_record(factory);
    if (r == 0) return 0;
    if (r > 0) {
        fprintf(stderr, "Client %u: REFUSING %s — a cooperative close of this "
                "factory was already signed\n", my_index, what);
        client_send_error(fd, "refused: this client already signed a "
                              "cooperative close of the factory");
    } else {
        fprintf(stderr, "Client %u: REFUSING %s — cannot read this client's "
                "record of signed closes\n", my_index, what);
        client_send_error(fd, "refused: client cannot read its close record");
    }
    return 1;
}

/* --- Tree advances are refused by default ---

   A leaf advance replaces the leaf transaction whose output funds this
   client's channel; a state advance replaces every state node on the path to
   it; a sub-factory advance replaces the sub-factory node the channel hangs
   from.  None of these ceremonies moves the channel onto the new outpoint or
   gives the client commitments that spend it, while the LSP ends up holding a
   newer tree than the one the client's commitments spend.  A client is in a
   factory only through its channel there, so co-signing any of them would
   leave it without a unilateral exit.  Every proposal is therefore refused
   before any local state changes and before any nonce is produced.

   client_set_allow_tree_advance(1) lifts the refusal.  It exists for
   harnesses that exercise the ceremonies with real clients
   (--test-allow-tree-advance, refused on mainnet); nothing holding real
   funds may set it. */
static int g_client_allow_tree_advance = 0;

void client_set_allow_tree_advance(int allow) {
    g_client_allow_tree_advance = allow ? 1 : 0;
}

/* Returns 1 if the advance was refused (an error was sent to the LSP). */
static int client_refuse_tree_advance(int fd, uint32_t my_index,
                                       const char *what) {
    if (g_client_allow_tree_advance) return 0;
    fprintf(stderr, "Client %u: REFUSING %s — the channel cannot be moved to "
            "an advanced tree\n", my_index, what);
    client_send_error(fd, "tree advance refused: client does not sign "
                          "leaf, state or sub-factory advances");
    return 1;
}

int client_close_outputs_acceptable(const secp256k1_context *ctx,
                                     const secp256k1_pubkey *my_pubkey,
                                     const channel_t *ch,
                                     const tx_output_t *outputs,
                                     size_t n_outputs) {
    /* No channel: the client never opened one in this factory, so it holds
       no commitment and no balance there and is owed nothing, whatever the
       outputs are.  This is only true if there really is no channel; the
       ceremony refuses when the client's own records say otherwise (see
       client_close_without_channel_ok). */
    if (!ch) return 1;
    if (!outputs) return 0;

    /* The proposed outputs settle balances only.  An HTLC or PTLC still in
       flight is not represented by any output, so signing now would forfeit
       it (an incoming one the client can claim, or an outgoing one that may
       yet be refunded).  Wait for it to resolve, or exit with the
       commitment. */
    size_t n_active = 0, n_active_ptlcs = 0;
    for (size_t i = 0; i < ch->n_htlcs; i++)
        if (ch->htlcs[i].state == HTLC_STATE_ACTIVE) n_active++;
    for (size_t i = 0; i < ch->n_ptlcs; i++)
        if (ch->ptlcs[i].state == PTLC_STATE_ACTIVE) n_active_ptlcs++;
    if (n_active > 0 || n_active_ptlcs > 0) {
        fprintf(stderr, "Client: REFUSING cooperative close — %zu HTLC(s) "
                "and %zu PTLC(s) still pending on the channel\n",
                n_active, n_active_ptlcs);
        return 0;
    }

    /* The balances must account for the whole funding output.  The HTLC and
       PTLC lists are not restored when a channel is reloaded, so one that was
       in flight then is invisible to the check above; what gives it away is
       that its amount is in neither balance.  A close paying local_amount
       would hand that amount to the LSP, so a channel whose state does not
       add up is never closed cooperatively. */
    uint64_t accounted = 0, expected = 0;
    if (ch->funding_amount == 0 ||
        !client_channel_conserved(ch, &accounted, &expected, NULL)) {
        fprintf(stderr, "Client: REFUSING cooperative close — channel state "
                "accounts for %llu sats (local %llu, remote %llu) but the "
                "funding output holds %llu after the commitment fee; an HTLC "
                "or PTLC may be unresolved\n",
                (unsigned long long)accounted,
                (unsigned long long)ch->local_amount,
                (unsigned long long)ch->remote_amount,
                (unsigned long long)expected);
        return 0;
    }

    /* A balance below the dust limit cannot be paid by a standard output. */
    uint64_t my_balance = ch->local_amount;
    if (my_balance < CHANNEL_DUST_LIMIT_SATS) return 1;

    /* The balance must be paid to the script this client derives from its own
       key, in one output: that is what the LSP builds for every client, and
       a payout spread over several outputs only costs the client fees to
       collect. */
    uint64_t paid_to_me = 0;
    size_t n_paying = 0;
    if (!client_close_amount_to_client(ctx, my_pubkey, outputs, n_outputs,
                                        &paid_to_me, &n_paying)) {
        fprintf(stderr, "Client: REFUSING cooperative close — cannot total "
                "the outputs paying this client's close script\n");
        return 0;
    }
    if (n_paying > 1) {
        fprintf(stderr, "Client: REFUSING cooperative close — the balance is "
                "split over %zu outputs to this client's script; it must be "
                "paid in one\n", n_paying);
        return 0;
    }
    if (paid_to_me < my_balance) {
        fprintf(stderr, "Client: REFUSING cooperative close — outputs pay %llu "
                "sats to this client's script, channel balance is %llu sats "
                "(force-close instead)\n",
                (unsigned long long)paid_to_me,
                (unsigned long long)my_balance);
        return 0;
    }
    return 1;
}

/* A close with no channel is signed only by a client that is owed nothing.
   If the client's own database holds a channel for this factory, it does
   have a balance and was merely started without it; signing would give that
   balance away.  With no database there is nothing that could have carried
   a channel over from an earlier run (reconnecting to a factory needs the
   database), so a client with neither is owed nothing.
   Returns 1 if a channel is on record, 0 if none is, -1 if the records
   cannot be read. */
static int client_close_channel_on_record(persist_t *db,
                                           const factory_t *factory) {
    if (!db) return 0;
    return persist_factory_has_channel(db, factory->funding_txid,
                                        factory->funding_vout);
}

/* End the ceremony by refusing what the LSP proposed.  The channel is left
   as it was; the client can still exit with its commitment. */
static void client_close_refuse(int fd, client_close_state_t *cs,
                                 const char *reason) {
    cs->refused = 1;
    client_send_error(fd, reason);
}

/* End the ceremony because the client could not check the proposal.  This
   is not a judgement of the terms: nothing is signed or recorded, the
   channel stays fully usable, and the LSP is told to try again. */
static void client_close_unverifiable(int fd, client_close_state_t *cs,
                                       const char *reason) {
    cs->unverifiable = 1;
    client_send_error(fd, reason);
}

/* The chain tip to judge a proposal's nLockTime by.  Starts from the tip the
   caller supplied; while that tip does not make the nLockTime acceptable and
   a height could become acceptable (the backend may have been unreachable,
   or be a few blocks behind), asks the tip source again for a bounded time. */
static uint32_t client_close_tip_for(uint32_t locktime, uint32_t tip) {
    if (!g_client_chain_tip_fn) return tip;
    if (locktime == 0 || locktime >= 500000000u) return tip;
    for (unsigned attempt = 1;
         !client_close_locktime_acceptable(locktime, tip) &&
         attempt <= g_client_chain_tip_attempts; attempt++) {
        if (attempt > 1 && g_client_chain_tip_retry_ms > 0)
            usleep((useconds_t)g_client_chain_tip_retry_ms * 1000);
        uint32_t now = client_chain_tip();
        if (now > tip) tip = now;
    }
    return tip;
}

/* MEDIUM-1: cap on LSP-driven re-PROPOSE recursion depth. The LSP is untrusted;
   without a cap a malicious/looping LSP that streams CLOSE_PROPOSE could exhaust
   the client's stack. On exceed, the client aborts the coop close and can still
   exit via --force-close. */
#define MAX_CLOSE_REPROPOSE 16

int client_do_close_ceremony(int fd, secp256k1_context *ctx,
                               const secp256k1_keypair *keypair,
                               const secp256k1_pubkey *my_pubkey,
                               factory_t *factory,
                               size_t n_participants,
                               const wire_msg_t *initial_msg,
                               uint32_t current_height,
                               const channel_t *ch,
                               client_close_state_t *cs,
                               int repropose_depth) {
    wire_msg_t msg;
    int got_propose = 0;

    client_close_state_t own_cs;
    if (!cs) {
        client_close_state_init(&own_cs, g_client_persist, factory);
        cs = &own_cs;
    }
    cs->refused = 0;
    cs->unverifiable = 0;

    /* The record of closes already signed decides what may be signed now.
       If it could not be read, try once more, and sign nothing without it. */
    if (cs->record_error) {
        int r = cs->db
            ? persist_load_close_signed(cs->db, factory->funding_txid,
                                         factory->funding_vout,
                                         &cs->paid_sats, cs->sighash)
            : -1;
        if (r < 0) {
            fprintf(stderr, "Client: cooperative close NOT signed — cannot "
                    "read this client's record of signed closes\n");
            client_close_unverifiable(fd, cs, "cooperative close not signed: "
                "client cannot read its close record, try again");
            return 0;
        }
        cs->record_error = 0;
        if (r > 0) cs->signed_close = 1;
    }

    if (initial_msg && initial_msg->msg_type == MSG_CLOSE_PROPOSE) {
        /* Use already-received CLOSE_PROPOSE */
        msg = *initial_msg;
        got_propose = 1;
    } else {
        /* Receive CLOSE_PROPOSE, skipping any LSP revocation messages and
           taking part in a leaf-advance or state-advance ceremony the LSP
           starts before the close.  Payments never start one; none has to
           arrive for the close to proceed. */
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
                if (cs->signed_close) {
                    fprintf(stderr, "Client: REFUSING leaf/state advance — a "
                            "cooperative close of this factory was already "
                            "signed\n");
                    cJSON_Delete(msg.json);
                    client_close_refuse(fd, cs, "refused: this client already "
                        "signed a cooperative close of the factory");
                    return 0;
                }
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

    /* nLockTime of the proposed close (the LSP sets it to its chain height
       against fee sniping).  It must be near the client's own tip: a close
       that cannot confirm for a long time is a signed transaction the LSP
       could hold back and use later. */
    cJSON *ht = cJSON_GetObjectItem(msg.json, "current_height");
    if (!ht || !cJSON_IsNumber(ht) || !(ht->valuedouble >= 0.0) ||
        ht->valuedouble > 4294967295.0) {
        fprintf(stderr, "Client: malformed CLOSE_PROPOSE (nLockTime)\n");
        if (!initial_msg) cJSON_Delete(msg.json);
        return 0;
    }
    uint32_t close_height = (uint32_t)ht->valuedouble;
    current_height = client_close_tip_for(close_height, current_height);
    if (!client_close_locktime_acceptable(close_height, current_height)) {
        if (!initial_msg) cJSON_Delete(msg.json);
        if (current_height == 0 && close_height < 500000000u) {
            /* No tip to judge the height by: the client cannot tell an
               honest nLockTime from a far-future one.  That says nothing
               about the proposal, so it is not a refusal of its terms. */
            fprintf(stderr, "Client: cooperative close NOT signed — nLockTime "
                    "%u cannot be verified: this client has no chain tip "
                    "right now\n", close_height);
            client_close_unverifiable(fd, cs, "cooperative close not signed: "
                "client cannot verify locktime, try again");
            return 0;
        }
        fprintf(stderr, "Client: REFUSING cooperative close — nLockTime "
                "%u is more than %d blocks above this client's chain "
                "tip %u\n", close_height, CLIENT_CLOSE_LOCKTIME_MARGIN,
                current_height);
        client_close_refuse(fd, cs, "cooperative close refused: nLockTime is "
                                    "not near this client's chain tip");
        return 0;
    }

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
        if (!(amt->valuedouble >= 0.0) || amt->valuedouble > 2.1e15) {
            fprintf(stderr, "Client: close output %zu amount out of range\n", i);
            free(close_outputs);
            if (!initial_msg) cJSON_Delete(msg.json);
            return 0;
        }
        close_outputs[i].amount_sats = (uint64_t)amt->valuedouble;
        close_outputs[i].script_pubkey_len = (size_t)wire_json_get_hex(
            item, "spk", close_outputs[i].script_pubkey, 34);
    }
    if (!initial_msg) cJSON_Delete(msg.json);

    /* Verify the proposed outputs before contributing a nonce or a signature.
       Refusing changes nothing on the channel: the client still holds its
       signed commitment and can exit unilaterally. */
    if (!ch) {
        int on_record = client_close_channel_on_record(cs->db, factory);
        if (on_record < 0) {
            fprintf(stderr, "Client: cooperative close NOT signed — cannot "
                    "read this client's channel records\n");
            free(close_outputs);
            client_close_unverifiable(fd, cs, "cooperative close not signed: "
                "client cannot read its channel records, try again");
            return 0;
        }
        if (on_record > 0) {
            fprintf(stderr, "Client: REFUSING cooperative close — a channel "
                    "is on record for this factory but this client was "
                    "started without it\n");
            free(close_outputs);
            client_close_refuse(fd, cs, "cooperative close refused: client "
                                        "was started without its channel state");
            return 0;
        }
    }
    if (!client_close_outputs_acceptable(ctx, my_pubkey, ch,
                                          close_outputs, n_outputs)) {
        free(close_outputs);
        client_close_refuse(fd, cs, "cooperative close refused: proposed "
            "outputs do not pay this client its channel balance");
        return 0;
    }

    /* If a close of this factory was signed before, the LSP may still hold
       it.  A replacement must pay this client at least as much, or the LSP
       could choose whichever of the two suits it. */
    uint64_t paid_to_me = 0;
    if (!client_close_amount_to_client(ctx, my_pubkey, close_outputs,
                                        n_outputs, &paid_to_me, NULL) ||
        (cs->signed_close && paid_to_me < cs->paid_sats)) {
        fprintf(stderr, "Client: REFUSING cooperative close — it pays this "
                "client %llu sats, a close signed earlier pays %llu\n",
                (unsigned long long)paid_to_me,
                (unsigned long long)cs->paid_sats);
        free(close_outputs);
        client_close_refuse(fd, cs, "cooperative close refused: an earlier "
                                    "signed close pays this client more");
        return 0;
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
            if (cs->signed_close) {
                fprintf(stderr, "Client: REFUSING leaf/state advance — a "
                        "cooperative close of this factory was already "
                        "signed\n");
                cJSON_Delete(all_nonces_msg.json);
                tx_buf_free(&close_unsigned);
                client_close_refuse(fd, cs, "refused: this client already "
                    "signed a cooperative close of the factory");
                return 0;
            }
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

    /* Record the close before the partial signature exists.  Once the
       signature is out, the LSP may be able to complete this close at any
       time, so from here on the factory is frozen for this client (see
       client_close_state_t).  If the record cannot be written, nothing is
       signed. */
    if (cs->db && !persist_save_close_signed(cs->db, factory->funding_txid,
                                              factory->funding_vout,
                                              paid_to_me, close_sighash)) {
        fprintf(stderr, "Client: REFUSING cooperative close — cannot record "
                "the close before signing it\n");
        tx_buf_free(&close_unsigned);
        client_close_refuse(fd, cs, "cooperative close refused: client could "
                                    "not record the close");
        return 0;
    }
    cs->signed_close = 1;
    cs->paid_sats = paid_to_me;
    memcpy(cs->sighash, close_sighash, 32);

    secp256k1_musig_partial_sig close_psig;
    if (!musig_create_partial_sig(ctx, &close_psig, &close_secnonce,
                                   keypair, &close_session)) {
        fprintf(stderr, "Client: close partial sig failed\n");
        tx_buf_free(&close_unsigned);
        return 0;
    }

    unsigned char psig_ser[32];
    musig_partial_sig_serialize(ctx, psig_ser, &close_psig);

    /* #48 Phase C test seam: fault-inject a bad close psig to exercise the LSP's
       bounded fresh-nonce retry. Gated on superscalar_cheat_allowed() (regtest
       only; #9 proves SS_CHEAT_* is inert on mainnet). =1 corrupts only the FIRST
       close attempt (transient -> the retry must recover); =2 corrupts every
       attempt (persistent -> the LSP must bound + abort). The static counter
       distinguishes attempts because each retry is a fresh ceremony call. */
    {
        const char *_bp = getenv("SS_CHEAT_CLOSE_BAD_PSIG");
        if (_bp && superscalar_cheat_allowed()) {
            static int _close_cheat_uses = 0;
            int _mode = atoi(_bp);
            if (_mode == 2 || (_mode == 1 && _close_cheat_uses == 0)) {
                psig_ser[31] ^= 0x01;   /* still a valid scalar, wrong value -> agg verify fails */
                fprintf(stderr, "Client: [CHEAT] corrupting close psig "
                        "(SS_CHEAT_CLOSE_BAD_PSIG=%d, use=%d)\n", _mode, _close_cheat_uses);
            }
            _close_cheat_uses++;
        }
    }

    cJSON *psig_msg = wire_build_close_psig(psig_ser);
    if (!wire_send(fd, MSG_CLOSE_PSIG, psig_msg)) {
        fprintf(stderr, "Client: send CLOSE_PSIG failed\n");
        cJSON_Delete(psig_msg);
        tx_buf_free(&close_unsigned);
        return 0;
    }
    cJSON_Delete(psig_msg);

    /* Receive CLOSE_DONE -- or a re-CLOSE_PROPOSE if the LSP is re-running the
       close with fresh nonces after an invalid aggregate (#48 Phase C). On a
       re-PROPOSE, re-run the close ceremony fresh (fresh nonce) by recursing with
       the new proposal; bounded by the LSP's retry cap (it sends finitely many
       re-PROPOSEs, then CLOSE_DONE or a terminal error -> MSG_ERROR). */
    wire_msg_t done_msg;
    if (!wire_recv(fd, &done_msg) || check_msg_error(&done_msg)) {
        fprintf(stderr, "Client: close failed (LSP error / no CLOSE_DONE)\n");
        if (done_msg.json) cJSON_Delete(done_msg.json);
        tx_buf_free(&close_unsigned);
        return 0;
    }
    if (done_msg.msg_type == MSG_CLOSE_PROPOSE) {
        if (repropose_depth + 1 > MAX_CLOSE_REPROPOSE) {
            fprintf(stderr, "Client: LSP exceeded %d cooperative-close re-proposes -- "
                    "aborting coop close (use --force-close to exit)\n", MAX_CLOSE_REPROPOSE);
            cJSON_Delete(done_msg.json);
            tx_buf_free(&close_unsigned);
            return 0;
        }
        fprintf(stderr, "Client: LSP re-proposing cooperative close -- retrying with a fresh nonce\n");
        tx_buf_free(&close_unsigned);
        int _r = client_do_close_ceremony(fd, ctx, keypair, my_pubkey, factory,
                                           n_participants, &done_msg, current_height, ch,
                                           cs, repropose_depth + 1);
        cJSON_Delete(done_msg.json);
        return _r;
    }
    if (done_msg.msg_type != MSG_CLOSE_DONE) {
        fprintf(stderr, "Client: expected CLOSE_DONE, got 0x%02x\n", done_msg.msg_type);
        cJSON_Delete(done_msg.json);
        tx_buf_free(&close_unsigned);
        return 0;
    }
    cJSON_Delete(done_msg.json);

    tx_buf_free(&close_unsigned);
    (void)got_propose;
    return 1;
}

/* Parse FACTORY_PROPOSE's per-level arity list.  Returns 0 for a list the
   factory cannot take as sent (more than FACTORY_MAX_LEVELS entries, or an
   entry that is not an arity 1..FACTORY_MAX_OUTPUTS); a shortened or altered
   list would build a different tree than the LSP's. */
static int client_parse_level_arity(const cJSON *arr,
                                    uint8_t out[FACTORY_MAX_LEVELS],
                                    size_t *n_out) {
    *n_out = 0;
    if (!arr || !cJSON_IsArray(arr)) return 1;
    int n = cJSON_GetArraySize(arr);
    if (n > FACTORY_MAX_LEVELS) return 0;
    for (int i = 0; i < n; i++) {
        const cJSON *v = cJSON_GetArrayItem(arr, i);
        if (!v || !cJSON_IsNumber(v) || v->valuedouble < 1 ||
            v->valuedouble > FACTORY_MAX_OUTPUTS)
            return 0;
        out[(*n_out)++] = (uint8_t)v->valuedouble;
    }
    return 1;
}

/* --- Apply signed tree nodes from MSG_FACTORY_READY --- */

int client_apply_factory_ready(factory_t *f, const cJSON *json, uint32_t my_index) {
    if (!f || !json) return -1;
    cJSON *signed_txs = cJSON_GetObjectItem(json, "signed_txs");
    if (!signed_txs || !cJSON_IsArray(signed_txs)) {
        fprintf(stderr, "Client: FACTORY_READY without signed tree nodes -- REFUSING factory\n");
        return -1;
    }

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
        factory_node_t *node = &f->nodes[node_idx];

        const char *hex = hex_j->valuestring;
        size_t hex_len = strlen(hex);
        size_t raw_len = hex_len / 2;
        unsigned char *raw = (hex_len >= 2 && hex_len % 2 == 0) ? malloc(raw_len) : NULL;
        tx_buf_t own;
        tx_buf_init(&own, raw_len + 8);
        /* The node as the LSP sent it must be our own transaction for this
           node with one signature in the witness.  Rebuild the signed form
           from our bytes and the trailing signature and compare: what is
           stored (and later broadcast) is our serialization, never the
           LSP's bytes. */
        int ok = raw && hex_decode(hex, raw, raw_len) == (int)raw_len &&
                 raw_len >= 4 + 64 && node->is_built && node->unsigned_tx.len > 0 &&
                 finalize_signed_tx(&own, node->unsigned_tx.data, node->unsigned_tx.len,
                                    raw + raw_len - 4 - 64) &&
                 own.len == raw_len && memcmp(own.data, raw, raw_len) == 0;
        free(raw);
        if (!ok) {
            tx_buf_free(&own);
            fprintf(stderr, "Client: FACTORY_READY node %zu is not this client's "
                            "transaction for that node -- REFUSING factory\n", node_idx);
            return -1;
        }
        tx_buf_free(&node->signed_tx);
        node->signed_tx = own;
        node->is_signed = 1;
        count++;
    }

    /* Every node this client signs for is on its way out of the factory. */
    for (size_t i = 0; my_index > 0 && i < f->n_nodes; i++) {
        if (factory_find_signer_slot(f, i, my_index) >= 0 && !f->nodes[i].is_signed) {
            fprintf(stderr, "Client: FACTORY_READY lacks signed node %zu on this "
                            "client's exit path -- REFUSING factory\n", i);
            return -1;
        }
    }
    if (count == 0) {
        fprintf(stderr, "Client: FACTORY_READY carries no signed tree node -- "
                        "REFUSING factory\n");
        return -1;
    }
    printf("Client: applied %d signed tree nodes from FACTORY_READY\n", count);

    /* Signatures: factory_verify_all recomputes each node's sighash and
       verifies the signature under the node's output key. */
    if (!factory_verify_all(f)) {
        fprintf(stderr, "Client: FACTORY_READY tree aggregate signatures INVALID "
                        "-- REFUSING factory (would be unrecoverable via self-exit)\n");
        return -1;
    }

    /* Signed distribution TX, if present.  It is the client's exit when the
       factory expires, so it is stored only after it has been checked against
       the client's own construction of that transaction; one that fails the
       check, or that cannot be checked because the client built none,
       refuses the factory. */
    cJSON *dist_hex_j = cJSON_GetObjectItem(json, "distribution_tx_hex");
    if (dist_hex_j && cJSON_IsString(dist_hex_j)) {
        const char *dhex = dist_hex_j->valuestring;
        size_t dlen = strlen(dhex);
        size_t draw = dlen / 2;
        unsigned char *raw = (dlen >= 2 && dlen % 2 == 0) ? malloc(draw) : NULL;
        int decoded = raw && hex_decode(dhex, raw, draw) == (int)draw;
        if (f->dist_tx_ready == 1 && f->dist_unsigned_tx.len > 0) {
            if (!decoded ||
                !client_verify_distribution_tx(f->ctx, f->dist_unsigned_tx.data,
                                               f->dist_unsigned_tx.len, f->dist_sighash,
                                               f->funding_spk, raw, draw)) {
                fprintf(stderr, "Client: FACTORY_READY distribution TX is not the "
                                "transaction this client built or is not validly "
                                "signed -- REFUSING factory\n");
                free(raw);
                return -1;
            }
            tx_buf_free(&f->dist_unsigned_tx);
            tx_buf_init(&f->dist_unsigned_tx, draw);
            memcpy(f->dist_unsigned_tx.data, raw, draw);
            f->dist_unsigned_tx.len = draw;
            f->dist_tx_ready = 2;  /* 2 = signed and verified distribution TX */
            printf("Client: verified and stored signed distribution TX (%zu bytes)\n", draw);
        } else {
            fprintf(stderr, "Client: FACTORY_READY distribution TX cannot be checked "
                            "(this client built none) -- REFUSING factory\n");
            free(raw);
            return -1;
        }
        free(raw);
    }

    return count;
}

/* --- Factory rotation (condensed factory creation without HELLO) --- */

/* Defined below (the initial-creation stateless signing engine).  The
   rotation re-entry ceremony reuses it so both creation paths speak the
   same (stateless, #272 default) protocol. */
static int client_factory_creation_stateless_signing(
        int fd, secp256k1_context *ctx, const secp256k1_keypair *keypair,
        factory_t *factory, uint32_t my_index, int intent_already_recvd);

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
    g_rotation_new_factory_saved = 0;
    if (!g_client_allow_rotation) {
        fprintf(stderr, "Client %u: REFUSING rotation proposal — factory rotation is "
                "not enabled (--enable-rotation-experimental)\n", my_index);
        client_send_error(fd, "rotation_not_enabled");
        return 0;
    }

    /* Parse FACTORY_PROPOSE from initial_propose */
    const cJSON *pj = initial_propose->json;
    cJSON *fv = cJSON_GetObjectItem(pj, "funding_vout");
    cJSON *fa = cJSON_GetObjectItem(pj, "funding_amount");
    cJSON *sb = cJSON_GetObjectItem(pj, "step_blocks");
    cJSON *sp = cJSON_GetObjectItem(pj, "states_per_layer");
    cJSON *ct = cJSON_GetObjectItem(pj, "cltv_timeout");
    cJSON *fp = cJSON_GetObjectItem(pj, "tree_fee_rate");
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
    uint64_t tree_fee_rate = (uint64_t)fp->valuedouble;
    cJSON *arity_item = cJSON_GetObjectItem(pj, "leaf_arity");
    int rot_leaf_arity = (arity_item && cJSON_IsNumber(arity_item)) ? (int)arity_item->valuedouble : 2;
    uint8_t rot_level_arities[FACTORY_MAX_LEVELS];
    size_t rot_n_level_arity = 0;
    if (!client_parse_level_arity(cJSON_GetObjectItem(pj, "level_arity"),
                                  rot_level_arities, &rot_n_level_arity)) {
        fprintf(stderr, "Client %u: FACTORY_PROPOSE in rotation has an invalid "
                "level_arity list\n", my_index);
        return 0;
    }
    cJSON *rsnr_item = cJSON_GetObjectItem(pj, "static_threshold_depth");
    uint32_t rot_static_threshold =
        (rsnr_item && cJSON_IsNumber(rsnr_item)) ? (uint32_t)rsnr_item->valuedouble : 0;
    {
        char cltv_err[320];
        uint32_t exit_blocks = cli_factory_exit_blocks(
            rot_n_level_arity > 0 ? rot_level_arities : NULL, rot_n_level_arity,
            (factory_arity_t)rot_leaf_arity, 1, n_participants - 1,
            rot_static_threshold, step_blocks, states_per_layer);
        if (!cli_validate_proposed_cltv(cltv_timeout, client_chain_tip(), exit_blocks,
                                        cltv_err, sizeof(cltv_err))) {
            fprintf(stderr, "Client %u: REFUSING rotation: %s\n", my_index, cltv_err);
            return 0;
        }
    }

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

    client_capacity_terms_t rot_caps;
    if (!client_parse_capacity_terms(pj, &rot_caps)) {
        fprintf(stderr, "Client %u: rotation FACTORY_PROPOSE has malformed capacities\n",
                my_index);
        free(rot_hashes);
        return 0;
    }

    /* Build factory locally */
    factory_init_from_pubkeys(factory_out, ctx, all_pubkeys, n_participants,
                              step_blocks, states_per_layer);
    factory_out->cltv_timeout = cltv_timeout;
    factory_out->use_tree_anchor = 1;  /* #56: P2A CPFP anchors on tree txs (matches LSP) */
    factory_out->tree_fee_rate = tree_fee_rate;
    if (!factory_set_placement_mode(factory_out, (placement_mode_t)rot_placement)) {
        free(rot_hashes);
        return 0;
    }
    factory_out->economic_mode = (economic_mode_t)rot_econ;
    memcpy(factory_out->profiles, rot_profiles, sizeof(rot_profiles));
    if (rot_n_level_arity > 0) {
        if (!factory_set_level_arity(factory_out, rot_level_arities, rot_n_level_arity)) {
            fprintf(stderr, "Client %u: rotation tree shape refused\n", my_index);
            free(rot_hashes);
            return 0;
        }
    } else if (rot_leaf_arity == 1)
        factory_set_arity(factory_out, FACTORY_ARITY_1);
    else if (rot_leaf_arity == 3)
        factory_set_arity(factory_out, FACTORY_ARITY_PS);
    if (rot_static_threshold > 0)
        factory_set_static_near_root(factory_out, rot_static_threshold);
    if (rot_n_hashes > 0)
        factory_set_l_stock_hashes(factory_out, rot_hashes, rot_n_hashes);
    free(rot_hashes);
    if (!client_apply_capacity_terms(factory_out, &rot_caps)) {
        fprintf(stderr, "Client %u: rotation capacities refused\n", my_index);
        return 0;
    }
    if (!factory_set_funding(factory_out, funding_txid, funding_vout, funding_amount,
                             funding_spk, spk_len)) {
        printf("Client %u: rotation funding script refused\n", my_index);
        fflush(stdout);
        return 0;
    }

    if (!factory_build_tree(factory_out)) {
        printf("Client %u: ROTATION BUILD_TREE FAILED spk=%zu amt=%llu\n", my_index, spk_len, (unsigned long long)funding_amount);
        fflush(stdout);
        return 0;
    }
    if (!client_check_tree_fees(factory_out, tree_fee_rate, my_index)) {
        client_send_error(fd, "tree_fee_rejected");
        return 0;
    }
    printf("Client %u: rotation tree OK (%zu nodes)\n", my_index, factory_out->n_nodes);
    fflush(stdout);
    if (!client_capacity_acceptable(factory_out, my_index) ||
        !client_dist_amounts_acceptable(factory_out, rot_dist_amounts,
                                        rot_n_dist_amounts, my_index))
        return 0;
    /* Nothing is signed for, or recorded about, a factory whose funding
       output has not been checked against the client's own derivation. */
    if (!client_check_factory_funding(factory_out, my_index, &my_pubkey)) {
        fprintf(stderr, "Client %u: REFUSING rotation — funding check failed\n", my_index);
        client_send_error(fd, "funding_tx_verification_failed");
        return 0;
    }
    if (!factory_sessions_init(factory_out)) {
        printf("Client %u: ROTATION SESSIONS_INIT FAILED\n", my_index);
        fflush(stdout);
        return 0;
    }

    /* Verify distribution amounts BEFORE any ceremony round: if the LSP
       provided per-client dist_amounts, this client's allocation must be at
       least its old channel balance.  Prevents the LSP from silently reducing
       the client's distribution output during rotation (balance theft).
       Protocol-agnostic — applies to the stateless AND legacy paths. */
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

    /* #332 rotation crash-drill finding: this re-entry ceremony previously
       spoke ONLY the legacy nonce-pool protocol (NONCE_BUNDLE 0x11 /
       ALL_NONCES / PSIG_BUNDLE), which the stateless LSP rejects
       ("LSP-stateless: expected CLIENT_PUBNONCES, got 0x11") — so production
       rotation Phase C could never create the new factory against current
       clients.  Mirror the initial-creation branch (client_run_with_channels):
       stateless engine by default, legacy pool path only under
       SS_MUSIG_LEGACY=1 (#272). */
    int rot_stateless = 1;
    {
        const char *legacy = getenv("SS_MUSIG_LEGACY");
        rot_stateless = !(legacy && legacy[0] == '1');
    }
    /* Hoisted so the post-ceremony tail's error paths can free on either
       path (the stateless arm leaves them NULL; free(NULL) is a no-op). */
    secp256k1_musig_secnonce *secnonces = NULL;
    wire_bundle_entry_t *nonce_entries = NULL;

    if (rot_stateless) {
        if (!client_factory_creation_stateless_signing(fd, ctx, keypair,
                                                        factory_out, my_index, 0))
            return 0;
    } else {
    /* Generate nonces */
    unsigned char my_seckey[32];
    secp256k1_keypair_sec(ctx, my_seckey, keypair);

    size_t my_node_count = 0;
    for (size_t i = 0; i < factory_out->n_nodes; i++)
        if (factory_find_signer_slot(factory_out, i, my_index) >= 0)
            my_node_count++;

    secnonces =
        (secp256k1_musig_secnonce *)calloc(my_node_count, sizeof(secp256k1_musig_secnonce));
    nonce_entries =
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

    /* Distribution TX: build unsigned TX and generate nonce (same as initial)
       — legacy path only; the stateless engine covers dist via the same
       mechanism as initial creation.  (Theft check moved above the branch.) */
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
                factory_out, dist_outputs, FACTORY_MAX_SIGNERS + 1,
                factory_distribution_fee(factory_out, factory_out->n_participants - 1),
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
    } /* end legacy (SS_MUSIG_LEGACY=1) rotation ceremony */

    /* Receive FACTORY_READY */
    if (!wire_recv(fd, &msg) || check_msg_error(&msg) || msg.msg_type != MSG_FACTORY_READY) {
        if (msg.json) cJSON_Delete(msg.json);
        free(secnonces); free(nonce_entries); return 0;
    }
    {
        int fr_apply = client_apply_factory_ready(factory_out, msg.json, my_index);
        cJSON_Delete(msg.json);
        if (fr_apply < 0) {   /* tree aggregate sigs invalid -- refuse (fund-safety) */
            fprintf(stderr, "Client: refusing rotation -- LSP factory tree failed "
                            "signature verification\n");
            free(secnonces); free(nonce_entries); return 0;
        }
    }

    /* The client leaves a factory only for one it can get out of on its own:
       the new factory must come with a verified, signed distribution
       transaction that pays this client at least its current balance. */
    if (!client_factory_exit_acceptable(ctx, factory_out, my_index, &my_pubkey)) {
        fprintf(stderr, "Client %u: REFUSING rotation — no acceptable exit from the "
                "new factory\n", my_index);
        free(secnonces); free(nonce_entries); return 0;
    }

    /* Durable before anything else can fail. */
    if (!client_rotation_save_factory(factory_out, ctx, my_index)) {
        fprintf(stderr, "Client %u: could not save the new factory; stopping the "
                "rotation\n", my_index);
        free(secnonces); free(nonce_entries); return 0;
    }

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

    /* Signed commitment 0 for the new channel, before it is used. */
    if (!client_recv_initial_commitment(fd, channel_out, my_index)) {
        free(secnonces); free(nonce_entries); return 0;
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
        factory_t *factory, uint32_t my_index, int intent_already_recvd) {
    secp256k1_pubkey my_pubkey;
    secp256k1_keypair_pub(ctx, &my_pubkey, keypair);

    /* Recv PROPOSE_INTENT (0x85) -- begin reversed flow.  On a #48 Phase D
       retry the caller has already consumed the re-sent PROPOSE_INTENT (to
       detect the retry) and validated n_nodes, so it passes
       intent_already_recvd=1 and we skip the recv here. */
    if (!intent_already_recvd) {
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
    /* #54 G1b: speculatively gen this client's distribution-TX dist nonce (fresh;
       independent of the per-node nonces).  Sent in CLIENT_PUBNONCES; ignored by
       the LSP if it isn't running dist co-signing.  Needs my_seckey -> before the
       wipe below. */
    secp256k1_musig_secnonce my_dist_secnonce;
    unsigned char my_dist_pn[66] = {0};
    unsigned char my_dist_psig[32] = {0};
    int my_dist_done = 0;
    int my_dist_gen = 0;
    {
        secp256k1_musig_pubnonce my_dist_pubnonce;
        if (factory->n_nodes > 0 &&
            musig_generate_nonce(ctx, &my_dist_secnonce, &my_dist_pubnonce,
                                 my_seckey, &my_pubkey,
                                 &factory->nodes[0].keyagg.cache)) {
            musig_pubnonce_serialize(ctx, my_dist_pn, &my_dist_pubnonce);
            my_dist_gen = 1;
        }
    }
    memset(my_seckey, 0, 32);

    /* Send CLIENT_PUBNONCES (per-node; unsigned nodes carry zero nonce). */
    {
        cJSON *cpn = wire_build_factory_client_pubnonces(my_pn_per_node, (uint32_t)nn);
        free(my_pn_per_node);
        if (cpn && my_dist_gen)   /* #54 G1b: include this client's dist pubnonce */
            wire_json_add_hex(cpn, "dist_pubnonce", my_dist_pn, 66);
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
    size_t mtx_stride = (size_t)factory->n_participants * 66;  /* match LSP: tight stride = actual signer count */
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
    /* #54 G1b: distribution-TX dist co-signing (self-contained; runs only if the
       LSP offered it via lsp_dist_pubnonce).  The client REBUILDS the dist TX from
       the LSP-sent per-client amounts, VERIFIES its own output is not shorted vs
       its channel balance, then co-signs.  Any mismatch/short -> skip (the factory
       is still created; just no signed dist TX = today's behaviour). */
    if (my_dist_gen) {
        unsigned char lsp_dist_pn[66];
        if (wire_json_get_hex(lr.json, "lsp_dist_pubnonce", lsp_dist_pn, 66) == 66) {
            unsigned char *all_dist_pn = calloc((size_t)factory->n_participants, 66);
            unsigned char *amt_le = calloc((size_t)factory->n_participants, 8);
            uint64_t dist_amounts[FACTORY_MAX_SIGNERS];
            int ok = (all_dist_pn && amt_le);
            size_t n_amt = 0;
            uint32_t dist_nlock = 0;
            if (ok) {
                cJSON *na = cJSON_GetObjectItem(lr.json, "dist_n_client_amounts");
                if (na && cJSON_IsNumber(na)) n_amt = (size_t)na->valuedouble;
                cJSON *nl = cJSON_GetObjectItem(lr.json, "dist_nlocktime");
                if (nl && cJSON_IsNumber(nl)) dist_nlock = (uint32_t)nl->valuedouble;
                if (wire_json_get_hex(lr.json, "all_dist_pubnonces", all_dist_pn,
                        (size_t)factory->n_participants * 66) !=
                    (int)((size_t)factory->n_participants * 66)) ok = 0;
                if (ok && n_amt > 0) {
                    if (n_amt > (size_t)factory->n_participants) ok = 0;
                    else if (wire_json_get_hex(lr.json, "dist_client_amounts", amt_le,
                                               n_amt * 8) != (int)(n_amt * 8)) ok = 0;
                    else for (size_t a = 0; a < n_amt; a++) {
                        uint64_t v = 0;
                        for (int b = 0; b < 8; b++)
                            v |= ((uint64_t)amt_le[a * 8 + b]) << (b * 8);
                        dist_amounts[a] = v;
                    }
                }
            }
            if (ok && !client_dist_amounts_acceptable(factory, dist_amounts, n_amt,
                                                      my_index))
                ok = 0;
            /* Rebuild the IDENTICAL unsigned dist TX from the LSP-sent amounts,
               then co-sign over our own computed sighash. */
            if (ok) {
                tx_output_t douts[FACTORY_MAX_SIGNERS + 1];
                size_t nd = factory_compute_distribution_outputs_balanced(
                    factory, douts, FACTORY_MAX_SIGNERS + 1,
                factory_distribution_fee(factory, factory->n_participants - 1),
                    (n_amt > 0) ? dist_amounts : NULL, n_amt);
                if (nd > 0 && !client_dist_locktime_acceptable(factory, dist_nlock))
                    fprintf(stderr, "Client-stateless %u: distribution locktime %u is "
                            "not this factory's (%u) -- refusing to co-sign dist TX\n",
                            my_index, dist_nlock, factory_distribution_locktime(factory));
                int built = nd > 0 && client_dist_locktime_acceptable(factory, dist_nlock) &&
                    factory_build_distribution_tx_unsigned(factory, douts, nd, dist_nlock);
                /* This member co-signs only a distribution TX that pays it its
                   full channel capacity (the same rule the factory is accepted
                   by, below). */
                if (built) {
                    secp256k1_pubkey me;
                    uint64_t need = client_member_channel_capacity(factory, my_index);
                    if (!secp256k1_keypair_pub(ctx, &me, keypair) || need == 0 ||
                        !client_distribution_pays_member(ctx, factory->dist_unsigned_tx.data,
                                                         factory->dist_unsigned_tx.len,
                                                         &me, need)) {
                        fprintf(stderr, "Client-stateless %u: distribution TX does not pay "
                                "this member its channel capacity (%llu) -- refusing to "
                                "co-sign dist TX\n", my_index, (unsigned long long)need);
                        built = 0;
                    }
                }
                if (built && factory_session_init_dist(factory)) {
                    int set_ok = 1;
                    secp256k1_musig_pubnonce pn0;
                    if (!musig_pubnonce_parse(ctx, &pn0, lsp_dist_pn) ||
                        !factory_session_set_nonce_dist(factory, 0, &pn0)) set_ok = 0;
                    for (size_t s = 1; set_ok && s < (size_t)factory->n_participants; s++) {
                        secp256k1_musig_pubnonce pns;
                        if (!musig_pubnonce_parse(ctx, &pns, all_dist_pn + s * 66) ||
                            !factory_session_set_nonce_dist(factory, s, &pns)) set_ok = 0;
                    }
                    if (set_ok && factory_session_finalize_dist(factory)) {
                        secp256k1_musig_partial_sig dps;
                        if (musig_create_partial_sig(ctx, &dps, &my_dist_secnonce,
                                                     keypair,
                                                     &factory->dist_signing_session)) {
                            musig_partial_sig_serialize(ctx, my_dist_psig, &dps);
                            my_dist_done = 1;
                        }
                    }
                }
            }
            free(all_dist_pn); free(amt_le);
        }
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
                    all_pn + (nidx * (size_t)factory->n_participants + snum) * 66;
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

    /* #48 Phase D test seam: fault-inject a bad CREATION psig to exercise the
       LSP's factory-creation bounded retry. Gated on superscalar_cheat_allowed()
       (regtest only; #9 proves SS_CHEAT_* is inert on mainnet). =1 corrupts only
       the FIRST creation ceremony (transient); =2 every ceremony (persistent).
       Corrupts the first signed node's psig (first non-zero 32B chunk).

       ONLY client my_index==1 corrupts.  If every client XORed the low bit of its
       OWN node-0 partial, the per-signer deltas (each +-1) can sum to zero in the
       MuSig2 aggregate (s_agg = sum of partials), leaving a VALID aggregate ~37%
       of the time -- a flaky no-op.  A single bad partial cannot cancel, so the
       aggregate is reliably invalid and the LSP's verify+retry always fires. */
    {
        const char *_cp = getenv("SS_CHEAT_CREATE_BAD_PSIG");
        if (_cp && superscalar_cheat_allowed() && my_index == 1) {
            static int _create_cheat_uses = 0;
            int _mode = atoi(_cp);
            if (_mode == 2 || (_mode == 1 && _create_cheat_uses == 0)) {
                for (size_t _n = 0; _n < nn; _n++) {
                    int _nz = 0;
                    for (int _b = 0; _b < 32; _b++) if (my_psig_per_node[_n*32+_b]) { _nz = 1; break; }
                    if (_nz) {
                        my_psig_per_node[_n*32+31] ^= 0x01;
                        fprintf(stderr, "Client-stateless %u: [CHEAT] corrupting creation psig "
                                "node %zu (SS_CHEAT_CREATE_BAD_PSIG=%d, use=%d)\n",
                                my_index, _n, _mode, _create_cheat_uses);
                        break;
                    }
                }
            }
            _create_cheat_uses++;
        }
    }

    /* Send CLIENT_FINAL_PSIGS (per-node; unsigned nodes carry zero psig). */
    {
        cJSON *fp = wire_build_factory_client_final_psigs(my_psig_per_node, (uint32_t)nn);
        free(my_psig_per_node);
        if (fp && my_dist_done)   /* #54 G1b: include this client's dist partial sig */
            wire_json_add_hex(fp, "dist_psig", my_dist_psig, 32);
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
    client_set_funding_verifier(verify_funding, verify_ctx);

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
        cJSON *fp = cJSON_GetObjectItem(msg.json, "tree_fee_rate");
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
    cJSON *fpt_item = cJSON_GetObjectItem(msg.json, "tree_fee_rate");
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
    uint64_t tree_fee_rate = (uint64_t)fpt_item->valuedouble;
    cJSON *arity_item = cJSON_GetObjectItem(msg.json, "leaf_arity");
    int leaf_arity = (arity_item && cJSON_IsNumber(arity_item)) ? (int)arity_item->valuedouble : 2;

    /* Parse variable level_arity array (4A), fall back to leaf_arity */
    uint8_t level_arities[FACTORY_MAX_LEVELS];
    size_t n_level_arity = 0;
    if (!client_parse_level_arity(cJSON_GetObjectItem(msg.json, "level_arity"),
                                  level_arities, &n_level_arity)) {
        fprintf(stderr, "Client: FACTORY_PROPOSE has an invalid level_arity list\n");
        cJSON_Delete(msg.json);
        return 0;
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

    /* The timeout must leave room for this member's exit from the proposed
       tree, computed from the proposal's shape as the builder does. */
    {
        char cltv_err[320];
        uint32_t exit_blocks = cli_factory_exit_blocks(
            n_level_arity > 0 ? level_arities : NULL, n_level_arity,
            (factory_arity_t)leaf_arity,
            ps_subfactory_arity_in > 1 ? ps_subfactory_arity_in : 1, n_participants - 1,
            static_threshold_depth, step_blocks, states_per_layer);
        if (!cli_validate_proposed_cltv(cltv_timeout, client_chain_tip(), exit_blocks,
                                        cltv_err, sizeof(cltv_err))) {
            fprintf(stderr, "Client: REFUSING factory: %s\n", cltv_err);
            client_send_error(fd, "factory CLTV timeout is not safely in the future");
            cJSON_Delete(msg.json);
            wire_close(fd);
            return 0;
        }
    }

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
    /* Channel terms fixed before signing: the per-member capacities and the
       opening balance split (the LSP's share of every channel, percent). */
    client_capacity_terms_t cap_terms;
    int cap_terms_ok = client_parse_capacity_terms(msg.json, &cap_terms);
    int open_lsp_pct = -1;
    {
        cJSON *bp = cJSON_GetObjectItem(msg.json, "lsp_balance_pct");
        if (bp && cJSON_IsNumber(bp) && bp->valuedouble >= 0 &&
            bp->valuedouble <= 100 && bp->valuedouble == (double)(int)bp->valuedouble)
            open_lsp_pct = (int)bp->valuedouble;
    }
    if (!cap_terms_ok || open_lsp_pct < 0) {
        fprintf(stderr, "Client: FACTORY_PROPOSE has malformed or missing channel "
                "terms (capacities / lsp_balance_pct)\n");
        client_send_error(fd, "malformed channel terms");
        cJSON_Delete(msg.json);
        wire_close(fd);
        return 0;
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

    /* #53-B3b: per-NODE L-stock hashes (present when the LSP runs hashlock poison).
       Parsed here into temp arrays (survive cJSON_Delete); applied to the factory
       after factory_init + before build_tree so the client builds the matching
       2-leaf L-stock SPK without the (LSP-private) seed. */
    uint32_t *parsed_node_h_idx = (uint32_t *)calloc(FACTORY_MAX_NODES, sizeof(uint32_t));
    unsigned char (*parsed_node_h)[32] = (unsigned char (*)[32])calloc(FACTORY_MAX_NODES, 32);
    size_t n_node_h = 0;
    cJSON *nlsh_arr = cJSON_GetObjectItem(msg.json, "node_l_stock_hashes");
    if (parsed_node_h_idx && parsed_node_h && nlsh_arr && cJSON_IsArray(nlsh_arr)) {
        int nn = cJSON_GetArraySize(nlsh_arr);
        for (int i = 0; i < nn && n_node_h < FACTORY_MAX_NODES; i++) {
            cJSON *o = cJSON_GetArrayItem(nlsh_arr, i);
            cJSON *no = o ? cJSON_GetObjectItem(o, "node") : NULL;
            cJSON *hh = o ? cJSON_GetObjectItem(o, "h") : NULL;
            if (no && cJSON_IsNumber(no) && hh && cJSON_IsString(hh) &&
                hex_decode(hh->valuestring, parsed_node_h[n_node_h], 32) == 32) {
                parsed_node_h_idx[n_node_h] = (uint32_t)no->valuedouble;
                n_node_h++;
            }
        }
    }

    cJSON_Delete(msg.json);

    /* The funding output is verified below, once the tree is built and the
       client's own derivation of the funding script exists. */
    /* Build factory locally (heap — factory_t is ~3MB).
       SF-followup #145: factory ptr is registered with g_client_active_factory
       once it's initialized below, so MSG_FUNDING_REORG can find it. */
    factory_t *factory = calloc(1, sizeof(factory_t));
    /* Set once the channel (declared below) is initialised; its heap arrays
       are then released on both exit paths. */
    int channel_ready = 0;
    if (!factory) return 0;
    factory_init_from_pubkeys(factory, ctx, all_pubkeys, n_participants,
                              step_blocks, states_per_layer);
    factory->cltv_timeout = cltv_timeout;
    factory->use_tree_anchor = 1;  /* #56: P2A CPFP anchors on tree txs (matches LSP) */
    factory->tree_fee_rate = tree_fee_rate;
    if (!factory_set_placement_mode(factory, (placement_mode_t)placement_mode)) {
        client_send_error(fd, "unknown placement mode");
        free(parsed_l_stock_hashes);
        free(parsed_node_h_idx);
        free(parsed_node_h);
        factory_free(factory);
        free(factory);
        wire_close(fd);
        return 0;
    }
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

    if (n_level_arity > 0 &&
        !factory_set_level_arity(factory, level_arities, n_level_arity)) {
        fprintf(stderr, "Client: FACTORY_PROPOSE tree shape refused\n");
        client_send_error(fd, "tree shape refused");
        free(parsed_l_stock_hashes);
        free(parsed_node_h_idx);
        free(parsed_node_h);
        factory_free(factory);
        free(factory);
        wire_close(fd);
        return 0;
    } else if (n_level_arity == 0 && leaf_arity == 1)
        factory_set_arity(factory, FACTORY_ARITY_1);
    else if (n_level_arity == 0 && leaf_arity == 3)
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
    /* #53-B3b: mirror the LSP's per-node L-stock hashes onto our nodes BEFORE
       build_tree, so the client builds the SAME 2-leaf L-stock SPK (it has no seed
       to derive them).  Inert when the LSP didn't ship any (hashlock off). */
    for (size_t nh = 0; nh < n_node_h; nh++)
        factory_set_node_l_stock_hash(factory, parsed_node_h_idx[nh], parsed_node_h[nh]);
    free(parsed_node_h_idx);
    free(parsed_node_h);
    if (!client_apply_capacity_terms(factory, &cap_terms) ||
        !factory_set_funding(factory, funding_txid, funding_vout, funding_amount,
                             funding_spk, spk_len) ||
        !factory_build_tree(factory)) {
        fprintf(stderr, "Client: factory_build_tree failed\n");
        client_send_error(fd, "factory_build_tree failed");
        factory_free(factory);
        free(factory);
        wire_close(fd);
        return 0;
    }
    if (open_lsp_pct > (int)g_max_lsp_balance_pct) {
        fprintf(stderr, "Client %u: REFUSING — opening split gives the LSP %d%% "
                "(maximum %u%%, --max-lsp-balance-pct)\n", my_index, open_lsp_pct,
                (unsigned)g_max_lsp_balance_pct);
        client_send_error(fd, "opening_split_refused");
        factory_free(factory);
        free(factory);
        wire_close(fd);
        return 0;
    }
    if (!client_check_tree_fees(factory, tree_fee_rate, my_index)) {
        client_send_error(fd, "tree_fee_rejected");
        factory_free(factory);
        free(factory);
        wire_close(fd);
        return 0;
    }
    if (!client_capacity_acceptable(factory, my_index) ||
        !client_dist_amounts_acceptable(factory, init_dist_amounts,
                                        init_n_dist_amounts, my_index)) {
        client_send_error(fd, "channel_capacity_refused");
        factory_free(factory);
        free(factory);
        wire_close(fd);
        return 0;
    }

    /* Before signing anything: the funding output must be on chain, unspent
       and confirmed, with exactly the script this participant set produces
       and exactly the proposed amount. */
    if (!client_check_factory_funding(factory, my_index, &my_pubkey)) {
        client_send_error(fd, "funding_tx_verification_failed");
        factory_free(factory);
        free(factory);
        wire_close(fd);
        return 0;
    }
    printf("Client %u: opening split — LSP %d%% of the channel\n", my_index, open_lsp_pct);

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
        /* #48 Phase D: bounded fresh-nonce retry for factory creation.  If the
           LSP's ceremony-time factory_verify_all fails (e.g. a bad client psig),
           it re-inits sessions and re-sends PROPOSE_INTENT instead of aborting;
           we mirror that -- re-init our sessions and re-sign with a FRESH nonce,
           up to SS_NONCE_RETRY_MAX times, then give up.  The signing function
           consumes the FIRST PROPOSE_INTENT itself; on a retry we have already
           consumed the re-sent one (to detect it), so we pass
           intent_already_recvd=1.  On success it also consumes + applies
           FACTORY_READY, so the shared recv below is skipped for this path. */
        int created = 0;
        int intent_held = 0;
        for (int fc_attempt = 0; fc_attempt <= SS_NONCE_RETRY_MAX; fc_attempt++) {
            if (fc_attempt > 0 && !factory_sessions_init(factory)) {
                fprintf(stderr, "Client %u: re-init sessions (creation retry) failed\n",
                        my_index);
                goto fail;
            }
            if (!client_factory_creation_stateless_signing(fd, ctx, keypair,
                                                            factory, my_index,
                                                            intent_held))
                goto fail;
            intent_held = 0;
            /* Result: FACTORY_READY (done) or a re-sent PROPOSE_INTENT (retry). */
            if (!wire_recv(fd, &msg) || check_msg_error(&msg)) {
                fprintf(stderr, "Client %u: recv after creation psigs failed\n", my_index);
                if (msg.json) cJSON_Delete(msg.json);
                goto fail;
            }
            if (msg.msg_type == MSG_FACTORY_READY) {
                int fr_apply = client_apply_factory_ready(factory, msg.json, my_index);
                cJSON_Delete(msg.json);
                if (fr_apply < 0) {   /* tree aggregate sigs invalid -- refuse */
                    fprintf(stderr, "Client: refusing factory -- tree failed "
                                    "signature verification\n");
                    goto fail;
                }
                created = 1;
                break;
            } else if (msg.msg_type == MSG_FACTORY_PROPOSE_INTENT &&
                       fc_attempt < SS_NONCE_RETRY_MAX) {
                uint32_t rn = 0;
                if (!wire_parse_factory_propose_intent(msg.json, &rn) ||
                    rn != (uint32_t)factory->n_nodes) {
                    fprintf(stderr, "Client %u: bad retry PROPOSE_INTENT\n", my_index);
                    cJSON_Delete(msg.json);
                    goto fail;
                }
                cJSON_Delete(msg.json);
                fprintf(stderr, "Client %u: factory creation retry %d/%d "
                        "(LSP requested fresh nonces)\n",
                        my_index, fc_attempt + 2, SS_NONCE_RETRY_MAX + 1);
                intent_held = 1;
                continue;
            } else {
                fprintf(stderr, "Client %u: expected FACTORY_READY, got 0x%02x\n",
                        my_index, msg.msg_type);
                if (msg.json) cJSON_Delete(msg.json);
                goto fail;
            }
        }
        if (!created) {
            fprintf(stderr, "Client %u: factory creation failed after %d attempts\n",
                    my_index, SS_NONCE_RETRY_MAX + 1);
            goto fail;
        }
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
                factory, dist_outputs, FACTORY_MAX_SIGNERS + 1,
                factory_distribution_fee(factory, factory->n_participants - 1),
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

    /* Receive FACTORY_READY.  The stateless creation path (above) already
       consumed + applied FACTORY_READY inside its bounded retry loop, so only
       the legacy path recvs it here. */
    if (!ss_stateless_creation) {
        if (!wire_recv(fd, &msg) || check_msg_error(&msg) || msg.msg_type != MSG_FACTORY_READY) {
            fprintf(stderr, "Client: expected FACTORY_READY\n");
            if (msg.json) cJSON_Delete(msg.json);
            goto fail;
        }
        {
            int fr_apply = client_apply_factory_ready(factory, msg.json, my_index);
            cJSON_Delete(msg.json);
            if (fr_apply < 0) {   /* tree aggregate sigs invalid -- refuse */
                fprintf(stderr, "Client: refusing factory -- tree failed "
                                "signature verification\n");
                goto fail;
            }
        }
    }

    /* The factory is accepted only with a fully co-signed, verified
       distribution transaction paying this member its channel capacity: the
       member's exit at the factory's end must not depend on the LSP.  Same
       rule as for a rotation. */
    if (!client_factory_exit_acceptable(ctx, factory, my_index, &my_pubkey)) {
        fprintf(stderr, "Client %u: REFUSING factory — no acceptable distribution "
                "transaction\n", my_index);
        client_send_error(fd, "distribution_tx_missing_or_invalid");
        goto fail;
    }
    printf("Client %u: distribution TX verified: pays this member %llu sats "
           "(channel capacity %llu), nLockTime %u\n", my_index,
           (unsigned long long)client_tx_amount_to_pubkey(ctx, factory->dist_unsigned_tx.data,
                                                          factory->dist_unsigned_tx.len,
                                                          &my_pubkey),
           (unsigned long long)client_member_channel_capacity(factory, my_index),
           factory_distribution_locktime(factory));

    printf("Client %u: factory creation complete!\n", my_index);

    /* === Channel Operations Phase === */
    channel_t channel;
    const channel_t *close_ch = NULL;   /* set once the channel is open */
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
        if (!client_init_channel(&channel, ctx, factory, keypair, my_index,
                                  &lsp_pay_bp, &lsp_delay_bp,
                                  &lsp_revoc_bp, &lsp_htlc_bp,
                                  bp_ps, bp_ds, bp_rs, bp_hs, NULL)) {
            fprintf(stderr, "Client %u: channel init failed\n", my_index);
            goto fail;
        }
        close_ch = &channel;
        channel_ready = 1;
        memset(bp_ps, 0, 32); memset(bp_ds, 0, 32);
        memset(bp_rs, 0, 32); memset(bp_hs, 0, 32);

        /* The opening split must be the one proposed before signing: the
           LSP's lsp_balance_pct share of the channel output less the
           commitment fee (as lsp_channels_init computes it), the rest the
           member's. */
        {
            uint64_t usable = channel.local_amount + channel.remote_amount;
            uint64_t want_lsp = usable * (uint64_t)open_lsp_pct / 100;
            uint64_t want_member = usable - want_lsp;
            if (bal_local != want_lsp * 1000 || bal_remote != want_member * 1000) {
                fprintf(stderr, "Client %u: REFUSING channel — opening split LSP %llu / "
                        "member %llu msat, proposed LSP %llu / member %llu sats "
                        "(%d%%)\n", my_index, (unsigned long long)bal_local,
                        (unsigned long long)bal_remote, (unsigned long long)want_lsp,
                        (unsigned long long)want_member, open_lsp_pct);
                client_send_error(fd, "opening_split_mismatch");
                goto fail;
            }
        }
        channel.local_amount  = bal_remote / 1000;  /* client balance = LSP remote */
        channel.remote_amount = bal_local  / 1000;  /* LSP balance   = LSP local  */

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

        /* The LSP now signs the client's commitment 0.  The channel is not
           handed to the callback (and so cannot send or receive) until the
           client holds a fully signed commitment paying its opening balance. */
        if (!client_recv_initial_commitment(fd, &channel, my_index))
            goto fail;
        printf("Client %u: initial commitment signed (local=%llu sats)\n",
               my_index, (unsigned long long)channel.local_amount);

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
                                    factory, n_participants, NULL,
                                    client_chain_tip(), close_ch, NULL, 0)) {
        goto fail;
    }

    printf("Client %u: cooperative close complete!\n", my_index);

done:
    if (channel_ready) channel_cleanup(&channel);
    free(nonce_entries);
    factory_free(factory);
    free(factory);
    wire_close(fd);
    return 1;

fail:
    if (channel_ready) channel_cleanup(&channel);
    free(nonce_entries);
    factory_free(factory);
    free(factory);
    wire_close(fd);
    return 0;
}


int client_leaf_realloc_acceptable(const factory_t *factory,
                                    uint32_t my_index, int leaf_side,
                                    const uint64_t *amounts, size_t n_amounts) {
    if (!factory || !amounts || my_index == 0) return 0;
    if (leaf_side < 0 || leaf_side >= factory->n_leaf_nodes) return 0;
    size_t node_idx = factory->leaf_node_indices[leaf_side];
    const factory_node_t *leaf = &factory->nodes[node_idx];

    /* Only a signer of this leaf is ever asked to sign it. */
    if (factory_find_signer_slot(factory, node_idx, my_index) < 0) {
        fprintf(stderr, "Client %u: REFUSING leaf realloc — not a signer of "
                "leaf %d\n", my_index, leaf_side);
        return 0;
    }

    /* A trailing P2A anchor is fixed and not part of the reallocation. */
    size_t n_realloc = leaf->n_outputs;
    if (n_realloc >= 1 &&
        leaf->outputs[n_realloc - 1].script_pubkey_len == P2A_SPK_LEN &&
        memcmp(leaf->outputs[n_realloc - 1].script_pubkey,
               P2A_SPK, P2A_SPK_LEN) == 0)
        n_realloc--;
    if (n_amounts != n_realloc) {
        fprintf(stderr, "Client %u: REFUSING leaf realloc — %zu amounts for "
                "%zu outputs\n", my_index, n_amounts, n_realloc);
        return 0;
    }

    /* The proposal may only redistribute what the leaf already holds. */
    uint64_t current_total = 0, new_total = 0;
    for (size_t i = 0; i < n_realloc; i++) {
        if (amounts[i] < CHANNEL_DUST_LIMIT_SATS ||
            amounts[i] > UINT64_MAX - new_total) {
            fprintf(stderr, "Client %u: REFUSING leaf realloc — output %zu "
                    "amount out of range\n", my_index, i);
            return 0;
        }
        new_total += amounts[i];
        current_total += leaf->outputs[i].amount_sats;
    }
    if (new_total != current_total) {
        fprintf(stderr, "Client %u: REFUSING leaf realloc — amounts sum to "
                "%llu, leaf holds %llu\n", my_index,
                (unsigned long long)new_total,
                (unsigned long long)current_total);
        return 0;
    }

    /* Locate this client's channel output from its own copy of the tree; the
       proposal carries amounts only and gets no say in which one is ours. */
    size_t my_node;
    uint32_t my_vout;
    if (!factory_client_to_leaf(factory, (size_t)(my_index - 1),
                                 &my_node, &my_vout) ||
        my_node != node_idx || my_vout >= n_realloc) {
        fprintf(stderr, "Client %u: REFUSING leaf realloc — own channel "
                "output is not on leaf %d\n", my_index, leaf_side);
        return 0;
    }

    /* A reallocation moves LSP liquidity stock toward channels.  It must
       never reduce the output that funds this client's channel: every
       commitment the client holds spends that output at its current value. */
    uint64_t my_current = leaf->outputs[my_vout].amount_sats;
    if (amounts[my_vout] < my_current) {
        fprintf(stderr, "Client %u: REFUSING leaf realloc — would shrink own "
                "channel output from %llu to %llu sats\n", my_index,
                (unsigned long long)my_current,
                (unsigned long long)amounts[my_vout]);
        return 0;
    }
    return 1;
}

int client_handle_leaf_realloc(int fd, secp256k1_context *ctx,
                                const secp256k1_keypair *keypair,
                                factory_t *factory,
                                uint32_t my_index,
                                const wire_msg_t *propose_msg) {
    (void)ctx; (void)keypair; (void)factory; (void)propose_msg;

    /* A reallocation replaces the leaf transaction, so the outpoint funding
       this client's channel changes.  The ceremony gives the client neither
       the completed signature of the new leaf nor commitments spending the
       new outpoint, while the LSP ends up holding a new leaf that supersedes
       the one the client's commitments spend.  Co-signing would leave the
       client without a unilateral exit whatever the amounts are, so every
       proposal is refused.  Nothing local is touched: the signed leaf, its
       state counter and the channel stay exactly as they were. */
    fprintf(stderr, "Client %u: REFUSING leaf realloc — the channel cannot "
            "be moved to a reallocated leaf\n", my_index);
    client_send_error(fd, "leaf reallocation refused: client does not sign "
                          "leaf reallocations");
    return 0;
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
   The only sub-factory advance ceremony: every sub chain tx is multi-input,
   and client_handle_subfactory_advance_stateless dispatches every accepted
   PROPOSE_INTENT here.
   STATELESS INVARIANT: each per-input client secnonce is generated once and
   consumed/zeroed by musig_create_partial_sig before the DONE recv.

   PS record-and-refuse, per input.  chain[N+1] spends EVERY output of
   chain[N] and nothing revokes it, so the only thing stopping the LSP from
   getting a second, different chain[N+1] co-signed (another delta_sats or
   channel_idx, proposed after this client restarted from chain[N]) is this
   client refusing to sign a different spend of an outpoint it has already
   signed a spend of.  Same rules as the leaf (docs/pseudo-spilman.md,
   "Record-and-refuse"), applied to every input this client signs (its own
   channel input and the N-of-N sales-stock input):
     sighash_i -> check_i, for every signed input, before any nonce
     -> nonces -> bind (input i's session message == sighash_i)
     -> partial sig i (kept in *sec) -> INSERT every signed input, ascending
     -> our psigs into the sessions -> CLIENT_FINAL_PSIGS.
   Any error refuses; a row with a different sighash refuses; a row with the
   same sighash is an idempotent retry.

   Multi-input atomicity: the INSERTs are separate autocommit statements, so
   a failure after input a was recorded but before input b was leaves a's
   row behind -- and aborts: nothing is sent.  That partial set is safe.
   Each per-input sighash (SIGHASH_DEFAULT) commits to the whole transaction,
   so a's row names exactly the transaction we were signing.  The identical
   retry passes a (same sighash) and records b.  Any different spend of
   chain[N] also spends a -- every sub chain tx spends all of chain[N]'s
   outputs -- and is refused at a's pre-sign check, before any nonce.
   Every ceremony inserts in ascending input order over the same input set,
   so one that loses an INSERT race to a different spend loses it at its
   first input and records nothing. */

/* The secrets of one stateless multi-input sub-factory ceremony: the
   per-input secnonces and our per-input partial sigs (n_inputs <=
   FACTORY_MAX_OUTPUTS, checked by the dispatcher), plus the poison
   side-channel's.  Owned by the wrapper below so that every exit zeroes
   them, as leaf_adv_secrets_t does for the leaf ceremony. */
typedef struct {
    secp256k1_musig_secnonce secnonces[FACTORY_MAX_OUTPUTS];
    secp256k1_musig_partial_sig psigs[FACTORY_MAX_OUTPUTS];
    unsigned char psig_ser[FACTORY_MAX_OUTPUTS * 32];
    secp256k1_musig_secnonce poison_secnonce;
    secp256k1_musig_partial_sig poison_psig;
    unsigned char poison_psig_ser[32];
} sf_adv_secrets_t;

/* Take back our own partial sigs from the per-input sessions of inputs
   [0, upto): used when placing them fails partway, so that no partial sig
   of ours is left in a session for a ceremony that sends nothing. */
static void sf_clear_own_psigs(factory_t *factory, size_t sub_node_i,
                               uint32_t my_index, size_t upto) {
    factory_node_t *sub = &factory->nodes[sub_node_i];
    for (size_t j = 0; j < upto && j < (size_t)FACTORY_MAX_OUTPUTS; j++) {
        int s = factory_session_get_input_signer_slot(factory, sub_node_i, j, my_index);
        if (s < 0) continue;
        secure_zero(&sub->input_partial_sigs[j * (size_t)FACTORY_MAX_SIGNERS + (size_t)s],
                    sizeof(secp256k1_musig_partial_sig));
        if (sub->input_partial_sigs_received[j] > 0)
            sub->input_partial_sigs_received[j]--;
    }
}

static int subfactory_advance_multi_ceremony(
        int fd, secp256k1_context *ctx, const secp256k1_keypair *keypair,
        factory_t *factory, uint32_t my_index, size_t sub_node_i,
        factory_node_t *sub, uint32_t n_inputs_u,
        int leaf_side, int sub_idx, int channel_idx, uint64_t delta_sats,
        sf_adv_secrets_t *sec) {
    persist_t *persist = g_client_persist;
    size_t n_inputs = (size_t)n_inputs_u;
    if (n_inputs < 2 || n_inputs > FACTORY_MAX_OUTPUTS) {
        fprintf(stderr, "Client-stateless MULTI %u: n_inputs=%zu invalid\n",
                my_index, n_inputs);
        return 0;
    }

    /* Poison prep (deterministic; single-input side-channel mirroring the LSP).
       Snapshot the OLD chain[N-1] state BEFORE advance_unsigned mutates it. */
    const uint64_t POISON_FEE_SATS = 1000;
    int poison_prepared_c = 0;
    /* #53 Phase 3: economic poison requirement (decoupled from prep), used by the
       fail-closed guard below — the OLD sub state has a non-dust sales-stock to protect. */
    int poison_required_c = 0;
    {
        size_t old_n_chans = (sub->n_outputs > 0) ? sub->n_outputs - 1 : 0;
        uint64_t old_sstock = (sub->n_outputs > 0)
            ? sub->outputs[sub->n_outputs - 1].amount_sats : 0;
        poison_required_c = (old_sstock > POISON_FEE_SATS + (uint64_t)old_n_chans * 330u);
        if (poison_required_c) {
            unsigned char old_chain_txid[32];
            memcpy(old_chain_txid, sub->txid, 32);
            if (factory_session_prepare_poison_tx_subfactory(
                    factory, sub_node_i, old_chain_txid, (uint32_t)old_n_chans,
                    old_sstock, POISON_FEE_SATS, NULL))
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
    /* The tx just built spends ps_n_prev_outputs inputs; we sign and record
       exactly the inputs it has, so the declared count must match it. */
    if (sub->ps_n_prev_outputs != n_inputs) {
        fprintf(stderr, "Client-stateless MULTI %u: chain tx spends %zu inputs, "
                "PROPOSE_INTENT declared %zu -- refusing\n",
                my_index, sub->ps_n_prev_outputs, n_inputs);
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

    /* PS record-and-refuse, part 1 of 2 (part 2 is the durable INSERT of
       every signed input right before CLIENT_FINAL_PSIGS).  For EVERY input
       this client signs, compute the BIP-341 sighash of the proposed spend
       of (chain[N] txid, i) and consult client_ps_signed_inputs -- all of
       them before any nonce exists.  The sighash comes from the unsigned tx
       and the per-input prevouts the local advance just captured; it is
       bound below to the message each input's session actually signs.  An
       input that cannot be checked, or of which we already signed a
       DIFFERENT spend, refuses the whole advance. */
    /* With a persist handle the record is mandatory.  If this node were not
       an advanced PS sub-factory chain (factory_session_init_node_input
       already requires one), refuse rather than skip the record silently. */
    if (persist && !(sub->is_ps_leaf && sub->ps_chain_len > 0 &&
                     factory_node_uses_multi_input(factory, sub_node_i))) {
        fprintf(stderr, "Client-stateless MULTI %u: sub node %zu is not an advanced PS "
                "sub-factory chain -- refusing to sign without a record\n",
                my_index, sub_node_i);
        factory_session_reset_poison(factory, sub_node_i);
        return 0;
    }
    const int ps_record_active = (persist != NULL);
    unsigned char ps_sighash[FACTORY_MAX_OUTPUTS][32];
    char ps_parent_hex[65] = {0};
    memset(ps_sighash, 0, sizeof ps_sighash);
    if (ps_record_active) {
        for (int b = 0; b < 32; b++)
            snprintf(ps_parent_hex + 2 * b, 3, "%02x", sub->ps_prev_txid[b]);
        const unsigned char *prev_spks[FACTORY_MAX_OUTPUTS];
        uint32_t prev_seqs[FACTORY_MAX_OUTPUTS];
        for (size_t j = 0; j < n_inputs; j++) {
            prev_spks[j] = sub->ps_prev_spks[j];
            prev_seqs[j] = sub->nsequence;  /* every input shares nsequence */
        }
        for (size_t i = 0; i < n_inputs; i++) {
            if (!factory_session_input_signs(factory, sub_node_i, i, my_index))
                continue;  /* not ours: nothing signed, nothing recorded */
            if (persist_test_ps_hook_fire(PERSIST_TEST_PS_SIGHASH) ||
                !compute_taproot_sighash_multi(ps_sighash[i],
                    sub->unsigned_tx.data, sub->unsigned_tx.len, (uint32_t)i,
                    n_inputs, prev_spks, sub->ps_prev_spk_lens,
                    sub->ps_prev_amounts, prev_seqs)) {
                fprintf(stderr,
                        "Client-stateless MULTI %u: cannot compute the sighash to record "
                        "for (%s:%zu) -- refusing to sign.\n", my_index, ps_parent_hex, i);
                factory_session_reset_poison(factory, sub_node_i);
                return 0;
            }
            unsigned char prev_sighash[32];
            int chk = persist_check_ps_signed_input(persist, /* factory_id = */ 0,
                                                    sub->ps_prev_txid, (uint32_t)i,
                                                    prev_sighash);
            if (chk == PS_SIGNED_INPUT_ERROR) {
                fprintf(stderr,
                        "Client-stateless MULTI %u: cannot read client_ps_signed_inputs for "
                        "(%s:%zu) -- refusing to sign (fail closed).\n",
                        my_index, ps_parent_hex, i);
                factory_session_reset_poison(factory, sub_node_i);
                return 0;
            }
            if (chk == PS_SIGNED_INPUT_FOUND) {
                if (memcmp(prev_sighash, ps_sighash[i], 32) != 0) {
                    fprintf(stderr,
                            "Client-stateless MULTI %u: REFUSING PS double-spend -- already "
                            "signed a DIFFERENT TX spending (%s:%zu) (sub node %zu).\n",
                            my_index, ps_parent_hex, i, sub_node_i);
                    factory_session_reset_poison(factory, sub_node_i);
                    return 0;
                }
                /* Same sighash: a retry of the identical chain tx (e.g. we
                   crashed after recording, before FINAL_PSIGS reached the
                   LSP).  Re-signed below with a fresh nonce; the stored
                   partial sig is never replayed. */
                printf("Client-stateless MULTI %u: input (%s:%zu) matches our recorded "
                       "signing -- idempotent retry, re-signing the same spend\n",
                       my_index, ps_parent_hex, i);
            }
        }
    }

    /* Gen own per-input secnonces + pubnonces; set own nonce on each input. */
    unsigned char my_seckey[32];
    secp256k1_pubkey my_pubkey;
    if (!secp256k1_keypair_sec(ctx, my_seckey, keypair)) {
        fprintf(stderr, "Client-stateless MULTI %u: keypair_sec failed\n", my_index);
        return 0;
    }
    secp256k1_keypair_pub(ctx, &my_pubkey, keypair);

    unsigned char *my_pn_flat = calloc(n_inputs, 66);
    if (!my_pn_flat) {
        secure_zero(my_seckey, sizeof my_seckey);
        factory_session_reset_poison(factory, sub_node_i);
        return 0;
    }
    /* SF-MULTI-KEYAGG (#283): gen nonce against per-input keyagg cache, but
       only for inputs this client signs.  Channel input j (0..k-1) is signed
       only by LSP + client at sub->signer_indices[j+1]; sales-stock (input k)
       is N-of-N.  For inputs we do NOT sign, write a 66-byte zero pubnonce as
       a skipped-input wire marker and leave sec->secnonces[i] zero so the
       later per-input loop also skips us. */
    for (size_t i = 0; i < n_inputs; i++) {
        if (!factory_session_input_signs(factory, sub_node_i, i, my_index)) {
            /* Skipped input: 66 zero bytes on wire, no musig nonce gen, no
               secnonce held to consume.  my_pn_flat slot already zero from
               calloc; sec->secnonces[i] already zero. */
            continue;
        }
        secp256k1_musig_pubnonce my_pubnonce_i;
        if (!musig_generate_nonce(ctx, &sec->secnonces[i], &my_pubnonce_i,
                                   my_seckey, &my_pubkey,
                                   &sub->input_keyaggs[i].cache)) {
            fprintf(stderr, "Client-stateless MULTI %u: nonce gen input %zu failed\n",
                    my_index, i);
            secure_zero(my_seckey, sizeof my_seckey);
            free(my_pn_flat);
            factory_session_reset_poison(factory, sub_node_i);
            return 0;
        }
        musig_pubnonce_serialize(ctx, my_pn_flat + i * 66, &my_pubnonce_i);
        int my_slot_i = factory_session_get_input_signer_slot(
            factory, sub_node_i, i, my_index);
        if (my_slot_i < 0 ||
            !factory_session_set_nonce_input(factory, sub_node_i, i,
                                             (size_t)my_slot_i, &my_pubnonce_i)) {
            fprintf(stderr, "Client-stateless MULTI %u: set own nonce input %zu (slot=%d) failed\n",
                    my_index, i, my_slot_i);
            secure_zero(my_seckey, sizeof my_seckey);
            free(my_pn_flat);
            factory_session_reset_poison(factory, sub_node_i);
            return 0;
        }
    }

    /* Poison (single-input side-channel): gen own poison secnonce + set own
       poison nonce while my_seckey is still live. */
    unsigned char my_poison_pn_ser[66] = {0};
    if (poison_prepared_c) {
        secp256k1_musig_pubnonce my_poison_pubnonce;
        if (!musig_generate_nonce(ctx, &sec->poison_secnonce, &my_poison_pubnonce,
                                    my_seckey, &my_pubkey, &sub->keyagg.cache) ||
            !factory_session_set_nonce_poison(factory, sub_node_i,
                                                (size_t)my_slot, &my_poison_pubnonce)) {
            secure_zero(&sec->poison_secnonce, sizeof sec->poison_secnonce);
            factory_session_reset_poison(factory, sub_node_i);
            poison_prepared_c = 0;
        } else {
            musig_pubnonce_serialize(ctx, my_poison_pn_ser, &my_poison_pubnonce);
        }
    }
    secure_zero(my_seckey, sizeof my_seckey);

    /* Send CLIENT_PUBNONCES with n_inputs own pubnonces (+ poison nonce). */
    cJSON *cpn_json = wire_build_subfactory_client_pubnonces(
        my_pn_flat, (uint32_t)n_inputs, poison_prepared_c ? my_poison_pn_ser : NULL);
    free(my_pn_flat);
    if (!wire_send(fd, MSG_SUBFACTORY_CLIENT_PUBNONCES, cpn_json)) {
        cJSON_Delete(cpn_json);
        fprintf(stderr, "Client-stateless MULTI %u: send CLIENT_PUBNONCES failed\n", my_index);
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
        factory_session_reset_poison(factory, sub_node_i);
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
        secure_zero(&sec->poison_secnonce, sizeof sec->poison_secnonce);
        factory_session_reset_poison(factory, sub_node_i);
        poison_prepared_c = 0;
    }

    /* SF-MULTI-KEYAGG (#283): per-input finalize+psig with per-input signer
       slot remapping.  For each input i:
         - If this client doesn't sign input i: skip the entire input (psig
           slot stays zero, no secnonce to consume).
         - Else: resolve own + LSP per-input slots, install LSP's nonce,
           install every other co-signer's nonce (resolve participant via
           node-level matrix row -> per-input slot; skip rows whose
           participant isn't in this input's signer set), finalize, create
           psig (zeros secnonce).
       The matrix is indexed [node-level slot s][input i] (unchanged wire
       layout); we translate each row's participant index through
       factory_session_get_input_signer_slot.  Rows for participants outside
       the per-input signer set carry zero placeholders and MUST be skipped.
       Our partial sigs stay in *sec -- not in the sessions, not on the wire
       -- until part 2 of the record-and-refuse has recorded them. */
    for (size_t i = 0; i < n_inputs; i++) {
        if (!factory_session_input_signs(factory, sub_node_i, i, my_index)) {
            /* Skipped input: nothing to sign, sec->psig_ser slot stays zero. */
            continue;
        }
        int my_slot_i = factory_session_get_input_signer_slot(
            factory, sub_node_i, i, my_index);
        int lsp_slot_i = factory_session_get_input_signer_slot(
            factory, sub_node_i, i, 0);
        if (my_slot_i < 0 || lsp_slot_i < 0) {
            fprintf(stderr, "Client-stateless MULTI %u: per-input slot lookup "
                    "failed input %zu (my=%d lsp=%d)\n",
                    my_index, i, my_slot_i, lsp_slot_i);
            goto fail;
        }
        secp256k1_musig_pubnonce lsp_pubnonce_i;
        if (!musig_pubnonce_parse(ctx, &lsp_pubnonce_i, lsp_pn_flat + i * 66) ||
            !factory_session_set_nonce_input(factory, sub_node_i, i,
                                             (size_t)lsp_slot_i, &lsp_pubnonce_i)) {
            fprintf(stderr, "Client-stateless MULTI %u: set LSP nonce input %zu "
                    "(per_input_slot=%d) failed\n", my_index, i, lsp_slot_i);
            goto fail;
        }
        if (have_matrix) {
            for (size_t scs = 0; scs < sub->n_signers; scs++) {
                uint32_t participant = sub->signer_indices[scs];
                /* Skip own + LSP (already set). */
                if (participant == my_index || participant == 0) continue;
                /* Skip co-signers who don't sign this input — their matrix
                   row carries a 66-byte zero placeholder. */
                int peer_slot_i = factory_session_get_input_signer_slot(
                    factory, sub_node_i, i, participant);
                if (peer_slot_i < 0) continue;
                secp256k1_musig_pubnonce pn_s;
                if (!musig_pubnonce_parse(ctx, &pn_s,
                        all_pn_per_input + (scs * n_inputs + i) * 66) ||
                    !factory_session_set_nonce_input(factory, sub_node_i, i,
                                                     (size_t)peer_slot_i, &pn_s)) {
                    fprintf(stderr,
                            "Client-stateless MULTI %u: set co-signer nonce "
                            "(participant=%u node_slot=%zu per_input_slot=%d) "
                            "input %zu failed\n",
                            my_index, participant, scs, peer_slot_i, i);
                    goto fail;
                }
            }
        }
        if (!factory_session_finalize_node_input(factory, sub_node_i, i)) {
            fprintf(stderr, "Client-stateless MULTI %u: finalize input %zu failed\n",
                    my_index, i);
            goto fail;
        }
        /* Bind the record to what is actually signed: the sighash checked in
           part 1, which part 2 records for this input, must be the message
           this input's MuSig2 session signs (fixed by
           factory_session_finalize_node_input).  If they differ, the record
           would describe a different spend than the signature -- refuse. */
        if (ps_record_active &&
            memcmp(ps_sighash[i], sub->input_signing_sessions[i].msg32, 32) != 0) {
            fprintf(stderr,
                    "Client-stateless MULTI %u: the sighash recorded for (%s:%zu) is not "
                    "the message this session signs -- refusing to sign.\n",
                    my_index, ps_parent_hex, i);
            goto fail;
        }
        if (!musig_create_partial_sig(ctx, &sec->psigs[i], &sec->secnonces[i], keypair,
                                       &sub->input_signing_sessions[i])) {
            fprintf(stderr, "Client-stateless MULTI %u: create_partial_sig input %zu failed\n",
                    my_index, i);
            goto fail;
        }
        /* sec->secnonces[i] consumed + zeroed by musig_create_partial_sig. */
    }

    /* Poison (single-input): set every signer's poison nonce from the forwarded
       matrix (own already set), finalize, create own poison psig (zeros the
       poison secnonce before the DONE recv).  The poison spends chain[N]'s
       sales-stock -- the same outpoint as our state input k -- on purpose
       (it is the penalty for broadcasting the superseded chain[N]), so it is
       neither checked nor recorded in client_ps_signed_inputs. */
    if (poison_prepared_c) {
        int pz_ok = 1;
        for (size_t scs = 0; scs < sub->n_signers && pz_ok; scs++) {
            if (scs == (size_t)my_slot) continue;  /* own already set */
            secp256k1_musig_pubnonce ppn;
            if (!musig_pubnonce_parse(ctx, &ppn, all_poison_pn_sub[scs]) ||
                !factory_session_set_nonce_poison(factory, sub_node_i, scs, &ppn))
                pz_ok = 0;
        }
        pz_ok = pz_ok &&
            factory_session_finalize_node_poison(factory, sub_node_i) &&
            musig_create_partial_sig(ctx, &sec->poison_psig, &sec->poison_secnonce,
                                       keypair, &sub->poison_signing_session);
        secure_zero(&sec->poison_secnonce, sizeof sec->poison_secnonce);
        if (!pz_ok) {
            fprintf(stderr, "Client-stateless MULTI %u: poison sign failed -- "
                    "degrading\n", my_index);
            factory_session_reset_poison(factory, sub_node_i);
            poison_prepared_c = 0;
        } else {
            musig_partial_sig_serialize(ctx, sec->poison_psig_ser, &sec->poison_psig);
        }
    }

    /* #53 Phase 3 fail-closed: hashlock ON + a sales-stock poison was economically
       REQUIRED but NOT co-signed -> do NOT ship FINAL.  Shipping would revoke the old
       sub state with no recourse against a cheating LSP that later broadcasts it
       (Scenario B at the sub level).  Stay on the old, still-recourse-able state.
       Mirrors the leaf client guard (client.c ~3947); non-hashlock subs unaffected.
       goto fail handles every free + the poison reset cleanly. */
    if (sub->has_l_stock_hash && poison_required_c && !poison_prepared_c) {
        fprintf(stderr, "Client-stateless MULTI %u: hashlock ON + sales-stock poison "
                        "REQUIRED but NOT co-signed -- ABORTING sub-advance (no revoke "
                        "without recourse)\n", my_index);
        goto fail;
    }

    free(lsp_pn_flat); free(lsp_psig_flat); free(all_pn_per_input);
    lsp_pn_flat = NULL; lsp_psig_flat = NULL; all_pn_per_input = NULL;  /* fail: frees again */

    /* PS record-and-refuse, part 2 of 2: durably record every input we signed
       BEFORE any of our partial sigs goes anywhere -- before they enter the
       per-input sessions, before CLIENT_FINAL_PSIGS.  One plain INSERT per
       signed input, ascending, each under the table's PRIMARY KEY (first
       record wins and is never overwritten; an identical row is an
       idempotent success).  Autocommit on WAL + synchronous=FULL, so
       PS_SAVE_RECORDED means the row is fsync'd.  Anything else on ANY input
       aborts right here: nothing is sent, and our partial sigs exist only in
       *sec, which the wrapper zeroes.  A row already written for an earlier
       input stays; it names exactly the transaction we were signing, so it
       lets the identical retry through and refuses every different spend of
       chain[N] (see the header comment). */
    lsp_crash_checkpoint("ps_sub_record_pre_save");
    if (ps_record_active) {
        for (size_t i = 0; i < n_inputs; i++) {
            if (!factory_session_input_signs(factory, sub_node_i, i, my_index))
                continue;
            unsigned char psig_buf[36];
            memset(psig_buf, 0, sizeof psig_buf);
            musig_partial_sig_serialize(ctx, psig_buf, &sec->psigs[i]);
            int saved = persist_save_ps_signed_input(persist, /* factory_id = */ 0,
                (int)sub_node_i, sub->ps_prev_txid, (uint32_t)i,
                ps_sighash[i], psig_buf);
            secure_zero(psig_buf, sizeof psig_buf);
            if (saved != PS_SAVE_RECORDED) {
                if (saved == PS_SAVE_CONFLICT)
                    fprintf(stderr,
                            "Client-stateless MULTI %u: REFUSING PS double-spend -- a "
                            "DIFFERENT spend of (%s:%zu) was recorded concurrently; "
                            "discarding our signatures, nothing sent.\n",
                            my_index, ps_parent_hex, i);
                else
                    fprintf(stderr,
                            "Client-stateless MULTI %u: could not durably record our "
                            "signature for (%s:%zu) (rc=%d) -- aborting before "
                            "CLIENT_FINAL_PSIGS, nothing sent.\n",
                            my_index, ps_parent_hex, i, saved);
                goto fail;
            }
        }
    }
    lsp_crash_checkpoint("ps_sub_record_post_save");

    /* Recorded: our partial sigs may now enter the sessions and leave. */
    for (size_t i = 0; i < n_inputs; i++) {
        if (!factory_session_input_signs(factory, sub_node_i, i, my_index))
            continue;  /* psig_ser slot stays zero: skipped-input marker */
        int my_slot_i = factory_session_get_input_signer_slot(
            factory, sub_node_i, i, my_index);
        if (my_slot_i < 0 ||
            !factory_session_set_partial_sig_input(factory, sub_node_i, i,
                                                    (size_t)my_slot_i, &sec->psigs[i])) {
            fprintf(stderr, "Client-stateless MULTI %u: set own psig input %zu "
                    "(per_input_slot=%d) failed\n", my_index, i, my_slot_i);
            sf_clear_own_psigs(factory, sub_node_i, my_index, i);
            goto fail;
        }
        musig_partial_sig_serialize(ctx, sec->psig_ser + i * 32, &sec->psigs[i]);
    }

    /* Send CLIENT_FINAL_PSIGS with n_inputs psigs (+ poison psig). */
    cJSON *fp_json = wire_build_subfactory_client_final_psigs(
        sec->psig_ser, (uint32_t)n_inputs, poison_prepared_c ? sec->poison_psig_ser : NULL);
    if (!wire_send(fd, MSG_SUBFACTORY_CLIENT_FINAL_PSIGS, fp_json)) {
        cJSON_Delete(fp_json);
        fprintf(stderr, "Client-stateless MULTI %u: send CLIENT_FINAL_PSIGS failed\n", my_index);
        factory_session_reset_poison(factory, sub_node_i);
        return 0;
    }
    cJSON_Delete(fp_json);
    lsp_crash_checkpoint("ps_sub_record_post_final");

    /* Wait for DONE.  #53: when this advance co-signed a script-path (hashlock) poison,
       DONE carries the LSP's AGGREGATED poison Schnorr sig -- the client cannot aggregate
       the N-party sub poison locally (unlike the 2-party leaf, which calls
       factory_session_complete_node_poison itself).  Capture it BEFORE persisting the
       recourse template; the secret follows in the reveal. */
    wire_msg_t done_msg;
    if (!wire_recv(fd, &done_msg) || done_msg.msg_type != MSG_SUBFACTORY_DONE) {
        fprintf(stderr, "Client-stateless MULTI %u: expected DONE, got 0x%02x\n",
                my_index, done_msg.json ? done_msg.msg_type : 0);
        if (done_msg.json) cJSON_Delete(done_msg.json);
        if (poison_prepared_c) factory_session_reset_poison(factory, sub_node_i);
        return 0;
    }
    if (sub->poison_is_scriptpath) {
        unsigned char agg64[64];
        if (wire_subfactory_done_get_poison_aggsig(done_msg.json, agg64)) {
            /* #53 verify-before-trust: the N-party sub poison agg-sig comes from the LSP
               over the wire (the client can't aggregate it locally).  VERIFY it against
               OUR own poison sighash + the untweaked sub agg key BEFORE persisting it as
               recourse -- else a malicious LSP (or a bad co-signer partial that the LSP
               aggregated) could hand us a WORTHLESS sig, silently neutering recourse for
               the superseded state.  The poison session is finalized + un-reset here, so
               its cache is the raw agg key and msg32 is the poison sighash (mirrors the
               leaf LSP verify at lsp_channels.c ~1782). */
            secp256k1_pubkey ppk; secp256k1_xonly_pubkey pxpk;
            if (secp256k1_musig_pubkey_get(ctx, &ppk, &sub->poison_signing_session.cache) &&
                secp256k1_xonly_pubkey_from_pubkey(ctx, &pxpk, NULL, &ppk) &&
                secp256k1_schnorrsig_verify(ctx, agg64,
                                            sub->poison_signing_session.msg32, 32, &pxpk)) {
                memcpy(sub->poison_agg_sig, agg64, 64);
                sub->poison_has_agg_sig = 1;
            } else {
                fprintf(stderr, "Client-stateless MULTI %u: LSP-supplied sub poison agg-sig "
                        "FAILED verify -- NOT persisting (recourse for the superseded sub "
                        "state is unavailable; LSP or a co-signer misbehaved)\n", my_index);
            }
        }
    }
    if (done_msg.json) cJSON_Delete(done_msg.json);

    /* #59/#53 Phase 2: the advance is committed + the old sub state superseded.  Persist
       the poison TEMPLATE now (agg-sig from DONE; revocation_secret still NULL), BEFORE
       awaiting the reveal that may never arrive (LSP crash / dropped link), so a restart
       can detect the missing secret and re-request it (0x8D).  Keyed by node_idx +
       superseded state.  Do NOT reset the poison session yet -- the template persist + the
       reveal persist below read sub->poison_* (the next advance's prep resets it,
       mirroring the leaf client). */
    if (persist && sub->poison_is_scriptpath && sub->poison_has_agg_sig) {
        uint32_t superseded_state = (sub->l_stock_state_counter > 0)
                                    ? sub->l_stock_state_counter - 1u : 0u;
        persist_save_l_stock_poison(persist, /* factory_id */ 0,
            (uint32_t)sub_node_i, superseded_state, sub->poison_l_stock_hash,
            sub->poison_agg_sig,
            sub->poison_unsigned_tx.data, sub->poison_unsigned_tx.len,
            sub->poison_leaf_script, sub->poison_leaf_script_len,
            sub->poison_control_block, sub->poison_control_block_len);
    }

    /* #53 Phase 2: receive + verify + persist the SUPERSEDED sub state's sales-stock
       revocation secret, so this client (or its standalone WT) can spend the Leaf-P sub
       poison if the LSP later broadcasts that stale sub state.  Recv whenever we prepped a
       script-path poison (hashlock on) -- the EXACT mirror of the LSP's reveal-send gate
       (use_hashlock_poison && poison_prepared) -- so the wire stays in sync even if the
       agg-sig was somehow absent from DONE; the persist below additionally requires the
       agg-sig.  Verify-before-persist (fail-closed), mirroring the leaf path (~3999). */
    if (sub->poison_is_scriptpath) {
        wire_msg_t rev_msg;
        if (wire_recv(fd, &rev_msg) && rev_msg.msg_type == MSG_LSTOCK_REVEAL) {
            uint32_t rn[1], rs[1];
            unsigned char rsec[1][32];
            size_t rcount = 0;
            if (wire_parse_lstock_reveal(rev_msg.json, rn, rs, rsec, 1, &rcount) &&
                rcount == 1) {
                unsigned char chk[32];
                sha256(rsec[0], 32, chk);
                if (persist && sub->poison_has_agg_sig &&
                    memcmp(chk, sub->poison_l_stock_hash, 32) == 0) {
                    persist_save_l_stock_poison(persist, /* factory_id */ 0,
                        (uint32_t)sub_node_i, rs[0], sub->poison_l_stock_hash,
                        sub->poison_agg_sig,
                        sub->poison_unsigned_tx.data, sub->poison_unsigned_tx.len,
                        sub->poison_leaf_script, sub->poison_leaf_script_len,
                        sub->poison_control_block, sub->poison_control_block_len);
                    persist_update_l_stock_secret(persist, 0, (uint32_t)sub_node_i, rs[0],
                                                  rsec[0]);
                    printf("Client-stateless MULTI %u: sub L-stock secret verified + "
                           "persisted (node %zu state %u) -> poison recourse durable\n",
                           my_index, sub_node_i, rs[0]);
                } else {
                    fprintf(stderr, "Client-stateless MULTI %u: sub L-stock reveal FAILED "
                            "verify (SHA256 != committed H_old) -- rejecting (LSP "
                            "misbehaving)\n", my_index);
                }
                memset(rsec, 0, sizeof(rsec));
            }
            if (rev_msg.json) cJSON_Delete(rev_msg.json);
        } else {
            if (rev_msg.json) cJSON_Delete(rev_msg.json);
            fprintf(stderr, "Client-stateless MULTI %u: expected MSG_LSTOCK_REVEAL after "
                    "DONE -- recourse for the superseded sub state NOT persisted\n",
                    my_index);
        }
    }
    if (poison_prepared_c) factory_session_reset_poison(factory, sub_node_i);

    printf("Client-stateless subfactory MULTI-INPUT %u: advance done (sub_node=%zu, n_inputs=%zu)\n",
           my_index, sub_node_i, n_inputs);
    return 1;

fail:
    /* Secrets (secnonces, our partial sigs) are zeroed by the wrapper. */
    free(lsp_pn_flat); free(lsp_psig_flat); free(all_pn_per_input);
    factory_session_reset_poison(factory, sub_node_i);
    return 0;
}

static int client_handle_subfactory_advance_stateless_multi(
        int fd, secp256k1_context *ctx, const secp256k1_keypair *keypair,
        factory_t *factory, uint32_t my_index, size_t sub_node_i,
        factory_node_t *sub, uint32_t n_inputs_u,
        int leaf_side, int sub_idx, int channel_idx, uint64_t delta_sats) {
    sf_adv_secrets_t sec;
    memset(&sec, 0, sizeof sec);
    int ok = subfactory_advance_multi_ceremony(fd, ctx, keypair, factory, my_index,
                                               sub_node_i, sub, n_inputs_u,
                                               leaf_side, sub_idx, channel_idx,
                                               delta_sats, &sec);
    /* The single exit for this ceremony's secrets (see sf_adv_secrets_t):
       every per-input secnonce and partial sig, and the poison's, on every
       path. */
    secure_zero(&sec, sizeof sec);
    return ok;
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

    /* PS record-and-refuse preconditions -- refuse before anything changes
       locally.

       1. Input count.  The chain tx a sub-factory advance builds spends EVERY
          output of chain[N] (factory_subfactory_chain_advance_unsigned ->
          rebuild_node_tx: one input per chain[N] output, i.e. sub->n_outputs
          of them, and an advance needs n_outputs >= 2), and this client signs
          and records it per input.  A PROPOSE_INTENT declaring any other input
          count does not describe the transaction we would build.  An honest
          LSP never sends one (lsp_subfactory_chain_advance_stateless sends
          every sub with n_outputs > 1 down its multi-input ceremony with
          n_inputs = n_outputs).  There is no single-input sub-factory
          ceremony: the one n_inputs == 1 used to select signed the
          node-level session, whose message (compute_node_sighash's
          single-prevout preimage) is not the BIP-341 sighash of any input of
          that tx, without any record, and was removed.

       2. Which sub-factory.  The local advance mutates the sub-factory that
          (leaf_side, sub_idx) names; the signing and the record use
          subfactory_id.  They must be the same node, or we would advance one
          sub-factory and sign another. */
    if (sub->type != NODE_PS_SUBFACTORY || n_inputs < 2 ||
        (size_t)n_inputs != sub->n_outputs) {
        fprintf(stderr, "Client-stateless subfactory %u: PROPOSE_INTENT declares "
                "n_inputs=%u but advancing sub node %u spends %zu outputs -- "
                "REFUSING (sub chain advances are signed and recorded per input)\n",
                my_index, n_inputs, sub_node_id, sub->n_outputs);
        return 0;
    }
    {
        int named = -1;
        if (leaf_side >= 0 && leaf_side < factory->n_leaf_nodes && sub_idx >= 0) {
            const factory_node_t *lf =
                &factory->nodes[factory->leaf_node_indices[leaf_side]];
            if (sub_idx < lf->n_subfactories && sub_idx < FACTORY_MAX_OUTPUTS)
                named = lf->subfactory_node_indices[sub_idx];
        }
        if (named < 0 || (uint32_t)named != sub_node_id) {
            fprintf(stderr, "Client-stateless subfactory %u: PROPOSE_INTENT names sub "
                    "node %u but leaf %d / sub %d is node %d -- REFUSING\n",
                    my_index, sub_node_id, leaf_side, sub_idx, named);
            return 0;
        }
    }

    /* #53 sub-factory hashlock: mirror the sub's NEW-state H from PROPOSE_INTENT (the
       client has no seed) BEFORE the local sub-advance.  The multi-input ceremony routes
       through factory_subfactory_chain_advance_unsigned -> Phase 0, which reads this via
       apply_l_stock_hashlock's client-mirror branch to build the SAME sales-stock SPK as
       the LSP (else the chain tx diverges + the co-sign fails).
       Set here, not in poison-prep: factory_set_node_l_stock_hash updates only
       f->node_l_stock_hashes[], NOT sub->l_stock_hash, so the poison-prep below still
       snapshots H_old.  Absent field (hashlock off) -> no-op.  Mirrors leaf client.c ~3607. */
    {
        cJSON *lh = cJSON_GetObjectItem(propose_msg->json, "l_stock_hash");
        unsigned char h_new[32];
        if (lh && cJSON_IsString(lh) && hex_decode(lh->valuestring, h_new, 32) == 32)
            factory_set_node_l_stock_hash(factory, sub_node_i, h_new);
    }

    /* Every accepted PROPOSE_INTENT is multi-input (checked above). */
    return client_handle_subfactory_advance_stateless_multi(
        fd, ctx, keypair, factory, my_index, sub_node_i, sub,
        n_inputs, leaf_side, sub_idx, channel_idx, delta_sats);
}

int client_handle_subfactory_advance(int fd, secp256k1_context *ctx,
                                       const secp256k1_keypair *keypair,
                                       factory_t *factory, uint32_t my_index,
                                       const wire_msg_t *propose_msg) {
    if (client_refuse_advance_if_close_signed(fd, factory, my_index,
                                               "sub-factory advance"))
        return 0;
    if (client_refuse_tree_advance(fd, my_index, "sub-factory advance"))
        return 0;
    return client_handle_subfactory_advance_stateless(fd, ctx, keypair, factory, my_index, propose_msg);
}


/* --- Phase 1c (#271): MuSig2 stateless-signer client-side handler ---

   Mirrors lsp_advance_leaf_stateless in src/lsp_channels.c.  The client
   goes FIRST with its pubnonce; the LSP atomically generates its nonce
   + signs and replies with both lsp_pubnonce + lsp_psig in one message;
   the client then aggregates locally and ships the 64-byte final sig.

   Scope: state TX only.  Poison TX deferred (TODO).  See the LSP-side
   header for the full rationale. */
/* The secrets of one stateless leaf-advance ceremony.  They live in the
   wrapper (client_handle_leaf_advance_stateless, below) rather than on the
   ceremony's own stack, so that EVERY exit -- success, refusal, or any of
   the failure returns -- goes through the one place that zeroes them.
   musig_create_partial_sig consumes the state secnonce, but the poison
   secnonce is consumed only if the poison is still prepared when we sign
   (it degrades on several earlier failures), and the returns between nonce
   generation and signing consume neither. */
typedef struct {
    secp256k1_musig_secnonce secnonce;
    secp256k1_musig_secnonce poison_secnonce;
    secp256k1_musig_partial_sig psig;
    secp256k1_musig_partial_sig poison_psig;
} leaf_adv_secrets_t;

static int leaf_advance_stateless_ceremony(int fd,
                                           secp256k1_context *ctx,
                                           const secp256k1_keypair *keypair,
                                           factory_t *factory,
                                           uint32_t my_index,
                                           const wire_msg_t *propose_msg,
                                           leaf_adv_secrets_t *sec) {
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
    /* #53 x P3: a P2A tree anchor (4-byte SPK 0x51024e73) is appended as the LAST
       output of every node when use_tree_anchor is on, shifting the L-stock to the
       second-to-last output.  Detect it by SPK (a real L-stock is a 34-byte P2TR) so
       the poison gate targets the L-stock, not the 240-sat anchor — else this client
       omits its poison pubnonce and the LSP fail-closes the advance.  Mirrors the LSP. */
    int old_anchor_outs_c = (old_n_outputs_c >= 2 &&
        ps_node->outputs[old_n_outputs_c - 1].script_pubkey_len == P2A_SPK_LEN &&
        memcmp(ps_node->outputs[old_n_outputs_c - 1].script_pubkey, P2A_SPK, P2A_SPK_LEN) == 0)
        ? 1 : 0;
    int old_l_vout_c = old_n_outputs_c - 1 - old_anchor_outs_c;
    uint64_t old_l_amount_c = (old_l_vout_c >= 0 && (old_n_outputs_c - old_anchor_outs_c) >= 2)
                              ? ps_node->outputs[old_l_vout_c].amount_sats
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
        /* #9: defense-bypass cheat (client broadcasts an OLD signed state).
           Gate on superscalar_cheat_allowed() -> inert on non-regtest networks. */
        if (superscalar_cheat_allowed() && cheat_env && atoi(cheat_env) == leaf_side &&
            had_old_signed_c && ps_node->signed_tx.len > 0) {
            tx_buf_init(&cl7_cheat_tx, (int)ps_node->signed_tx.len);
            memcpy(cl7_cheat_tx.data, ps_node->signed_tx.data,
                   ps_node->signed_tx.len);
            cl7_cheat_tx.len = ps_node->signed_tx.len;
        }
    }

    /* #53-B3b Phase 1: capture the OLD state's L-stock hash (H_old) BEFORE the local
       advance rebuilds the SPK to H_new — used as the poison override so the poison
       targets the SUPERSEDED state's output. */
    unsigned char old_l_stock_hash_c[32];
    int have_old_l_hash_c = ps_node->has_l_stock_hash;
    if (have_old_l_hash_c)
        memcpy(old_l_stock_hash_c, ps_node->l_stock_hash, 32);

    /* #53-B3b Phase 1: mirror the advancing leaf's NEW-state hash from PROPOSE (the
       client has no seed) so the local advance builds the IDENTICAL new leaf-state SPK
       as the LSP — else the MuSig co-sign of the new state mismatches.  Absent field
       (hashlock off) -> no-op. */
    {
        cJSON *lh = cJSON_GetObjectItem(propose_msg->json, "l_stock_hash");
        unsigned char h_new[32];
        if (lh && cJSON_IsString(lh) && hex_decode(lh->valuestring, h_new, 32) == 32)
            factory_set_node_l_stock_hash(factory, node_idx, h_new);
    }

    /* Step 1: advance local state to mirror the LSP. */
    int rc = factory_advance_leaf_unsigned(factory, leaf_side);
    if (rc <= 0) {
        fprintf(stderr, "Client-stateless %u: leaf %d advance_unsigned failed (rc=%d)\n",
                my_index, leaf_side, rc);
        return 0;
    }

    /* PS record-and-refuse, part 1 of 2 (part 2 is the durable INSERT right
       after we sign, before our partial sig enters the signing session).
       Order: sighash -> check -> nonces -> bind (session message == sighash)
       -> partial sig -> INSERT -> into session + complete -> FINAL send.
       PS leaves are non-revocable,
       so this client's refusal to co-sign a SECOND, DIFFERENT spend of the
       same chain parent (ps_prev_txid:0) is the only thing stopping the LSP
       from confirming a stale leaf state.  Every failure in here refuses.

       The sighash comes first: it needs only the unsigned tx and the prev
       output, both known right after the local advance, and it is what the
       record is compared on -- a retry of the identical spend (same sighash)
       is allowed, anything else on this parent is not.  If it cannot be
       computed there is nothing to record against, so nothing is signed. */
    const int ps_record_active =
        (persist && ps_node->is_ps_leaf && ps_node->ps_chain_len > 0);
    unsigned char ps_sighash[32] = {0};
    char ps_parent_hex[65] = {0};
    if (ps_record_active) {
        for (int i = 0; i < 32; i++)
            snprintf(ps_parent_hex + 2 * i, 3, "%02x", ps_node->ps_prev_txid[i]);
        if (persist_test_ps_hook_fire(PERSIST_TEST_PS_SIGHASH) ||
            !compute_taproot_sighash(ps_sighash,
                ps_node->unsigned_tx.data, ps_node->unsigned_tx.len, 0,
                ps_node->outputs[0].script_pubkey,
                ps_node->outputs[0].script_pubkey_len,
                ps_node->ps_prev_chan_amount, ps_node->nsequence)) {
            fprintf(stderr,
                    "Client-stateless %u: cannot compute the sighash to record for "
                    "(%s:0) -- refusing to sign.\n", my_index, ps_parent_hex);
            return 0;
        }
        unsigned char prev_sighash[32];
        int chk = persist_check_ps_signed_input(
            persist, /* factory_id = */ 0,
            ps_node->ps_prev_txid, /* parent_vout = */ 0,
            prev_sighash);
        if (chk == PS_SIGNED_INPUT_ERROR) {
            fprintf(stderr,
                    "Client-stateless %u: cannot read client_ps_signed_inputs for "
                    "(%s:0) -- refusing to sign (fail closed).\n",
                    my_index, ps_parent_hex);
            return 0;
        }
        if (chk == PS_SIGNED_INPUT_FOUND) {
            if (memcmp(prev_sighash, ps_sighash, 32) != 0) {
                fprintf(stderr,
                        "Client-stateless %u: REFUSING PS double-spend -- already "
                        "signed a DIFFERENT TX spending (%s:0).\n",
                        my_index, ps_parent_hex);
                return 0;
            }
            /* Same sighash: a retry of the identical spend (e.g. we crashed
               after recording but before FINAL reached the LSP).  Re-signing
               the same message with a fresh nonce is safe.  The stored
               partial sig is NOT replayed: it is bound to the old session's
               aggregate nonce and would not verify against the new one. */
            printf("Client-stateless %u: PS advance for (%s:0) matches our "
                   "recorded signing -- idempotent retry, re-signing the same "
                   "spend\n", my_index, ps_parent_hex);
        }
    }

    /* Phase 1d.2: prep poison TX (matches LSP side deterministically).
       Client doesn'''t have its own watchtower toggle -- it preps poison
       unconditionally if the amounts fit.  If the LSP didn'''t prep
       (e.g. no watchtower), the wire flow degrades naturally because
       the LSP won'''t send poison fields back. */
    const uint64_t LEAF_POISON_FEE_SATS_C = 1000;
    int leaf_poison_prepared_c = 0;
    /* #53 Phase 5: capture WHETHER a poison is economically required (the old
       state has a protectable, non-dust L-stock output) so the fail-closed guard
       below can tell "poison failed/degraded" (must abort) apart from "no poison
       was ever needed" (dust / no old state -> safe to advance, do not abort). */
    int poison_required_c = (had_old_signed_c && old_n_outputs_c >= 2 &&
        old_l_amount_c > LEAF_POISON_FEE_SATS_C +
                         (uint64_t)(ps_node->n_signers - 1) * 330u);
    if (poison_required_c) {
        if (factory_session_prepare_poison_tx_leaf(
                factory, node_idx,
                old_leaf_txid, (uint32_t)old_l_vout_c,
                old_l_amount_c, LEAF_POISON_FEE_SATS_C,
                /* #53-B3b Phase 1: target the SUPERSEDED state's output (H_old). */
                have_old_l_hash_c ? old_l_stock_hash_c : NULL)) {
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

    secp256k1_musig_pubnonce my_pubnonce;
    if (!musig_generate_nonce(ctx, &sec->secnonce, &my_pubnonce,
                                my_seckey, &my_pubkey,
                                &factory->nodes[node_idx].keyagg.cache)) {
        memset(my_seckey, 0, 32);
        fprintf(stderr, "Client-stateless %u: nonce gen failed\n", my_index);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }
    secp256k1_musig_pubnonce my_poison_pubnonce;
    if (leaf_poison_prepared_c &&
        !musig_generate_nonce(ctx, &sec->poison_secnonce, &my_poison_pubnonce,
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

    /* Bind the record to what is actually signed: the sighash we checked and
       are about to record must be the message this MuSig2 session signs
       (fixed by factory_session_finalize_node).  If they differ, the record
       would describe a different spend than the signature -- refuse. */
    if (ps_record_active &&
        memcmp(ps_sighash, factory->nodes[node_idx].signing_session.msg32, 32) != 0) {
        fprintf(stderr,
                "Client-stateless %u: the sighash recorded for (%s:0) is not the "
                "message this session signs -- refusing to sign.\n",
                my_index, ps_parent_hex);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }

    /* Step 5: create own partial_sig.  This consumes + zeroes the state
       secnonce, and the poison secnonce only if the poison is still
       prepared; the wrapper zeroes both on every exit regardless. */
    if (!musig_create_partial_sig(ctx, &sec->psig, &sec->secnonce, keypair,
                                    &factory->nodes[node_idx].signing_session)) {
        fprintf(stderr, "Client-stateless %u: create_partial_sig failed\n", my_index);
        factory_session_reset_poison(factory, node_idx);
        return 0;
    }
    if (leaf_poison_prepared_c &&
        !musig_create_partial_sig(ctx, &sec->poison_psig, &sec->poison_secnonce, keypair,
                                    &factory->nodes[node_idx].poison_signing_session)) {
        fprintf(stderr, "Client-stateless %u: poison partial_sig failed -- degrading\n",
                my_index);
        factory_session_reset_poison(factory, node_idx);
        leaf_poison_prepared_c = 0;
    }

    /* PS record-and-refuse, part 2 of 2: durably record what we just signed
       BEFORE our partial sig goes anywhere -- before it enters the signing
       session (set_partial_sig), before complete_node, before FINAL.  Plain
       INSERT under the table's PRIMARY KEY -- the arbiter between two
       ceremonies that both passed the pre-sign check for this parent: the
       first record wins and is never overwritten.  The connection is
       autocommit (this function opens no transaction) on WAL +
       synchronous=FULL, so PS_SAVE_RECORDED means the row is fsync'd.  Any
       other outcome aborts right here: our partial sig then exists only in
       *sec, which the wrapper zeroes on return, so it never leaves this
       process and is never left in the factory's session. */
    lsp_crash_checkpoint("ps_record_pre_save");
    if (ps_record_active) {
        unsigned char psig_buf[36];
        unsigned char my_psig_ser[32];
        musig_partial_sig_serialize(ctx, my_psig_ser, &sec->psig);
        memset(psig_buf, 0, 36);
        memcpy(psig_buf, my_psig_ser, 32);
        int saved = persist_save_ps_signed_input(persist, /* factory_id = */ 0,
            (int)node_idx, ps_node->ps_prev_txid, 0,
            ps_sighash, psig_buf);
        secure_zero(my_psig_ser, sizeof my_psig_ser);
        secure_zero(psig_buf, sizeof psig_buf);
        if (saved != PS_SAVE_RECORDED) {
            if (saved == PS_SAVE_CONFLICT)
                fprintf(stderr,
                        "Client-stateless %u: REFUSING PS double-spend -- a DIFFERENT "
                        "spend of (%s:0) was recorded concurrently; discarding our "
                        "signature, nothing sent.\n", my_index, ps_parent_hex);
            else
                fprintf(stderr,
                        "Client-stateless %u: could not durably record our signature "
                        "for (%s:0) (rc=%d) -- aborting before FINAL, nothing sent.\n",
                        my_index, ps_parent_hex, saved);
            factory_session_reset_poison(factory, node_idx);
            return 0;
        }
    }
    lsp_crash_checkpoint("ps_record_post_save");

    /* Step 6: parse LSP's psig and set both psigs into the session. */
    secp256k1_musig_partial_sig lsp_psig;
    if (!musig_partial_sig_parse(ctx, &lsp_psig, lsp_psig_ser)) {
        fprintf(stderr, "Client-stateless %u: parse LSP psig failed\n", my_index);
        return 0;
    }
    if (!factory_session_set_partial_sig(factory, node_idx, (size_t)my_slot, &sec->psig)) {
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
                                                     (size_t)my_slot, &sec->poison_psig) ||
            !factory_session_set_partial_sig_poison(factory, node_idx,
                                                     (size_t)lsp_slot, &lsp_poison_psig)) {
            fprintf(stderr, "Client-stateless %u: poison psig set failed -- degrading\n",
                    my_index);
            factory_session_reset_poison(factory, node_idx);
            leaf_poison_prepared_c = 0;
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

    /* #53 Phase 5 (B4): SECURITY-CRITICAL.  Shipping FINAL hands the LSP a
       complete new-state signature, revoking the old state.  When this leaf
       carries a hashlock (has_l_stock_hash => hashlock poison is on), REFUSE to
       ship FINAL unless the Leaf-P poison for the superseded state was fully
       co-signed (leaf_poison_prepared_c still set after every co-sign step).
       Revoking the old state without that poison would leave this client with NO
       recourse against a cheating LSP that later broadcasts the superseded state
       (Scenario A/B) — the exact hole #53 closes.  Fail-closed: stay on the old,
       still-recourse-able state.  Subsumes every degrade site above + the case
       where prep never ran.  Non-hashlock leaves are unaffected. */
    if (ps_node->has_l_stock_hash && poison_required_c && !leaf_poison_prepared_c) {
        fprintf(stderr, "Client-stateless %u: hashlock ON + L-stock poison REQUIRED "
                        "but NOT co-signed -- ABORTING advance (no revoke without "
                        "recourse)\n", my_index);
        factory_session_reset_poison(factory, node_idx);
        return 0;
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
    lsp_crash_checkpoint("ps_record_post_final");

    /* #59 Phase 1: FINAL is sent — the advance is committed and the old state is
       superseded.  Persist the poison TEMPLATE now (revocation_secret stays NULL),
       BEFORE we await DONE + the reveal that may never arrive (LSP crash / dropped
       link).  Without this, a never-revealed advance leaves NO row, so a restart
       cannot even detect the missing secret to re-request it (residual no-poison
       window).  Saved AFTER the commit so an aborted advance never persists a
       spurious poison.  Idempotent (INSERT OR REPLACE) with the reveal-time save. */
    if (persist && ps_node->poison_is_scriptpath && ps_node->poison_has_agg_sig) {
        uint32_t superseded_state = (ps_node->l_stock_state_counter > 0)
                                    ? ps_node->l_stock_state_counter - 1u : 0u;
        persist_save_l_stock_poison(persist, /* factory_id */ 0,
            (uint32_t)node_idx, superseded_state, ps_node->poison_l_stock_hash,
            ps_node->poison_agg_sig,
            ps_node->poison_unsigned_tx.data, ps_node->poison_unsigned_tx.len,
            ps_node->poison_leaf_script, ps_node->poison_leaf_script_len,
            ps_node->poison_control_block, ps_node->poison_control_block_len);
    }

    /* Step 9: wait for LEAF_ADVANCE_DONE (LSP's broadcast). */
    wire_msg_t done_msg;
    if (!wire_recv(fd, &done_msg) || done_msg.msg_type != MSG_LEAF_ADVANCE_DONE) {
        fprintf(stderr, "Client-stateless %u: expected LEAF_ADVANCE_DONE, got 0x%02x\n",
                my_index, done_msg.json ? done_msg.msg_type : 0);
        if (done_msg.json) cJSON_Delete(done_msg.json);
        return 0;
    }
    if (done_msg.json) cJSON_Delete(done_msg.json);

    /* #53-B3b Phase 2: receive + verify + persist the SUPERSEDED state's L-stock
       revocation secret, so this client (or its standalone watchtower) can spend the
       Leaf-P poison if the LSP later broadcasts that stale state.  Only when this
       advance co-signed a script-path poison (hashlock on).  Verify-before-persist
       (fail-closed), mirroring channel_receive_revocation_flat. */
    if (ps_node->poison_is_scriptpath && ps_node->poison_has_agg_sig) {
        wire_msg_t rev_msg;
        if (wire_recv(fd, &rev_msg) && rev_msg.msg_type == MSG_LSTOCK_REVEAL) {
            uint32_t rn[1], rs[1];
            unsigned char rsec[1][32];
            size_t rcount = 0;
            if (wire_parse_lstock_reveal(rev_msg.json, rn, rs, rsec, 1, &rcount) &&
                rcount == 1) {
                unsigned char chk[32];
                sha256(rsec[0], 32, chk);
                if (memcmp(chk, ps_node->poison_l_stock_hash, 32) == 0) {
                    persist_save_l_stock_poison(persist, /* factory_id */ 0,
                        (uint32_t)node_idx, rs[0], ps_node->poison_l_stock_hash,
                        ps_node->poison_agg_sig,
                        ps_node->poison_unsigned_tx.data, ps_node->poison_unsigned_tx.len,
                        ps_node->poison_leaf_script, ps_node->poison_leaf_script_len,
                        ps_node->poison_control_block, ps_node->poison_control_block_len);
                    persist_update_l_stock_secret(persist, 0, (uint32_t)node_idx, rs[0],
                                                  rsec[0]);
                    printf("Client-stateless %u: L-stock secret verified + persisted "
                           "(node %zu state %u) -> poison recourse durable\n",
                           my_index, node_idx, rs[0]);
                } else {
                    fprintf(stderr, "Client-stateless %u: L-stock reveal FAILED verify "
                            "(SHA256 != committed H_old) -- rejecting (LSP misbehaving)\n",
                            my_index);
                }
                memset(rsec, 0, sizeof(rsec));
            }
            if (rev_msg.json) cJSON_Delete(rev_msg.json);
        } else {
            if (rev_msg.json) cJSON_Delete(rev_msg.json);
            fprintf(stderr, "Client-stateless %u: expected MSG_LSTOCK_REVEAL after DONE "
                    "-- recourse for the superseded state NOT persisted\n", my_index);
        }
    }

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

static int client_handle_leaf_advance_stateless(int fd,
                                                  secp256k1_context *ctx,
                                                  const secp256k1_keypair *keypair,
                                                  factory_t *factory,
                                                  uint32_t my_index,
                                                  const wire_msg_t *propose_msg) {
    leaf_adv_secrets_t sec;
    memset(&sec, 0, sizeof sec);
    int ok = leaf_advance_stateless_ceremony(fd, ctx, keypair, factory, my_index,
                                             propose_msg, &sec);
    /* The single exit for this ceremony's secrets (see leaf_adv_secrets_t):
       both secnonces and both of our partial sigs, on every path. */
    secure_zero(&sec, sizeof sec);
    return ok;
}

int client_handle_leaf_advance(int fd, secp256k1_context *ctx,
                                 const secp256k1_keypair *keypair,
                                 factory_t *factory, uint32_t my_index,
                                 const wire_msg_t *propose_msg) {
    if (client_refuse_advance_if_close_signed(fd, factory, my_index,
                                               "leaf advance"))
        return 0;
    if (client_refuse_tree_advance(fd, my_index, "leaf advance"))
        return 0;
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
            if (factory_refuses_refresh_in_place(factory, "Client: root-driven Tier B")) {
                client_send_error(fd, "root advance refused: no DW state; rotate the factory");
                return 0;
            }
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
                    old_l, TIERB_POISON_FEE_SATS, NULL)) {
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
    if (client_refuse_advance_if_close_signed(fd, factory, my_index,
                                               "state advance"))
        return 0;
    if (client_refuse_tree_advance(fd, my_index, "state advance"))
        return 0;
    return client_handle_state_advance_stateless(fd, ctx, keypair, factory, my_index, propose_msg);
}

int client_run_ceremony(secp256k1_context *ctx,
                        const secp256k1_keypair *keypair,
                        const char *host, int port) {
    return client_run_with_channels(ctx, keypair, host, port, NULL, NULL,
                                     NULL, NULL);
}
