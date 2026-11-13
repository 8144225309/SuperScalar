/* End-date payouts (inversion of the timeout default).
 *
 * Every shared output of the factory tree whose value belongs to members at
 * the factory's end date T0 (f->cltv_timeout) has one pre-signed payout: a
 * transaction with nLockTime T0 that spends that output by key path and pays
 * the members under it, with no output for the host.  The funding output's
 * payout is the distribution transaction (factory_build_distribution_tx*);
 * this file covers the outputs inside the tree:
 *
 *   - a tree output that a child transaction spends: every output of a
 *     static kickoff and of a Decker-Wattenhofer state transaction.  A
 *     kickoff's output into its own state transaction has no payout: any
 *     member can publish the pre-signed state transaction, and a payout there
 *     would race the state's relative lock.
 *   - each channel output (MuSig2 of member and host).
 *   - each host liquidity (stock) output.  Its host-alone relative-delay leaf
 *     stays (the old-state poison needs it); the payout is the key-path spend
 *     that hands the stock to the leaf's members at T0.
 *
 * No shared output carries a script path the host alone can satisfy at an
 * absolute height.  From T0 on, the members' payouts are the only spends of
 * these outputs that need no member's signature to be valid, apart from the
 * stock's relative-delay leaf.
 *
 * Amounts (identical on every signer, rebuilt from the signer's own tree):
 *   - tree output of value V with members M: each member gets its channel
 *     capacity, plus an equal share of what is left after the capacities, the
 *     payout fee and the anchor (the subtree's stock and pre-signed fees).
 *     Leftover sats of the division go to the fee.  Never less than the
 *     capacity.
 *   - channel output: its one member gets V minus the fee and the anchor.
 *   - stock output: its members share V minus the fee and the anchor equally.
 *     A stock too small to pay every member above dust gets no payout.
 * Fee: the factory's tree_fee_rate for the payout's exact vsize; one P2A
 * anchor (zero-value at rate 0) last, for CPFP at broadcast.
 */
#include "superscalar/factory.h"
#include "superscalar/tx_builder.h"
#include "superscalar/tapscript.h"
#include "superscalar/channel.h"
#include "superscalar/fee.h"
#include <secp256k1_schnorrsig.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

extern void sha256_tagged(const char *, const unsigned char *, size_t, unsigned char *);

/* BIP-341 key-only output key: internal + H_TapTweak(internal) * G. */
static int keyonly_tweak(const secp256k1_context *ctx, secp256k1_xonly_pubkey *out,
                         const secp256k1_xonly_pubkey *internal) {
    unsigned char ser[32], tw[32];
    secp256k1_pubkey full;
    if (!secp256k1_xonly_pubkey_serialize(ctx, ser, internal)) return 0;
    sha256_tagged("TapTweak", ser, 32, tw);
    return secp256k1_xonly_pubkey_tweak_add(ctx, &full, internal, tw) &&
           secp256k1_xonly_pubkey_from_pubkey(ctx, out, NULL, &full);
}

static void payout_clear(factory_payout_t *p) {
    free(p->signer_indices);
    free(p->members);
    free(p->partial_sigs);
    tx_buf_free(&p->unsigned_tx);
    tx_buf_free(&p->signed_tx);
    musig_session_free(&p->session);
    memset(p, 0, sizeof(*p));
}

void factory_free_payouts(factory_t *f) {
    if (!f) return;
    for (size_t i = 0; i < f->n_payouts; i++)
        payout_clear(&f->payouts[i]);
    free(f->payouts);
    f->payouts = NULL;
    f->n_payouts = 0;
}

/* Key-path-only P2TR of the member's factory key: where every payout and the
   distribution transaction pay the member. */
int factory_member_payout_spk(const factory_t *f, uint32_t participant,
                              unsigned char spk_out[34]) {
    if (!f || participant == 0 || participant >= f->n_participants) return 0;
    secp256k1_xonly_pubkey xonly;
    unsigned char ser[32], tweak[32];
    if (!secp256k1_xonly_pubkey_from_pubkey(f->ctx, &xonly, NULL, &f->pubkeys[participant]) ||
        !secp256k1_xonly_pubkey_serialize(f->ctx, ser, &xonly))
        return 0;
    sha256_tagged("TapTweak", ser, 32, tweak);
    secp256k1_pubkey full;
    secp256k1_xonly_pubkey tweaked;
    if (!secp256k1_xonly_pubkey_tweak_add(f->ctx, &full, &xonly, tweak) ||
        !secp256k1_xonly_pubkey_from_pubkey(f->ctx, &tweaked, NULL, &full))
        return 0;
    build_p2tr_script_pubkey(spk_out, &tweaked);
    return 1;
}

/* Output key of MuSig2(pks), key path only. */
static int agg_output_key(const factory_t *f, const secp256k1_pubkey *pks, size_t n,
                          musig_keyagg_t *ka_out, secp256k1_xonly_pubkey *out_key) {
    if (!musig_aggregate_keys(f->ctx, ka_out, pks, n)) return 0;
    return keyonly_tweak(f->ctx, out_key, &ka_out->agg_pubkey);
}

static int spk_is_key(const factory_t *f, const unsigned char *spk, size_t spk_len,
                      const secp256k1_xonly_pubkey *key) {
    unsigned char ser[32];
    if (spk_len != 34 || spk[0] != 0x51 || spk[1] != 0x20) return 0;
    if (!secp256k1_xonly_pubkey_serialize(f->ctx, ser, key)) return 0;
    return memcmp(ser, spk + 2, 32) == 0;
}

static int is_anchor(const tx_output_t *o) {
    return o->script_pubkey_len == P2A_SPK_LEN &&
           memcmp(o->script_pubkey, P2A_SPK, P2A_SPK_LEN) == 0;
}

/* The node spending (node_idx, vout) inside the tree, or -1. */
static int child_at(const factory_t *f, size_t node_idx, uint32_t vout) {
    for (size_t i = 0; i < f->n_nodes; i++)
        if (f->nodes[i].parent_index == (int)node_idx && f->nodes[i].parent_vout == vout)
            return (int)i;
    return -1;
}

/* The channel capacity of member `participant`: its channel output amount. */
static uint64_t member_capacity(const factory_t *f, uint32_t participant) {
    size_t node = 0;
    uint32_t vout = 0;
    if (participant == 0 || !factory_client_to_leaf(f, participant - 1, &node, &vout) ||
        node >= f->n_nodes || vout >= f->nodes[node].n_outputs)
        return 0;
    return f->nodes[node].outputs[vout].amount_sats;
}

/* Members (participants != 0) of a signer list, ascending. */
static size_t members_of(const uint32_t *signers, size_t n, uint32_t *out) {
    size_t k = 0;
    for (size_t i = 0; i < n; i++)
        if (signers[i] != 0) out[k++] = signers[i];
    for (size_t i = 1; i < k; i++)
        for (size_t j = i; j > 0 && out[j - 1] > out[j]; j--) {
            uint32_t t = out[j]; out[j] = out[j - 1]; out[j - 1] = t;
        }
    return k;
}

uint64_t factory_payout_fee(const factory_t *f, size_t n_members) {
    return fee_at_rate(f ? f->tree_fee_rate : 0, fee_keypath_tx_vsize(1, n_members, 1));
}

/* Fill p's outputs and build its unsigned transaction and sighash. */
static int payout_build_tx(const factory_t *f, factory_payout_t *p, uint64_t value) {
    size_t n = p->n_members;
    if (n == 0) return 0;
    /* Same bound as the distribution TX: a payout must fit one TRUC
       transaction, or nobody could bump it. */
    if (n > FACTORY_MAX_DIST_CLIENTS) {
        fprintf(stderr, "factory: end-date payout of %u:%u would pay %zu members, more "
                "than the %d that fit in a %d vB TRUC transaction\n", p->node_idx, p->vout,
                n, FACTORY_MAX_DIST_CLIENTS, TRUC_MAX_VSIZE);
        return 0;
    }
    uint64_t fee = factory_payout_fee(f, n);
    uint64_t anchor = factory_tree_anchor_sats(f);
    if (fee == FEE_INVALID || value <= fee + anchor) return 0;
    uint64_t budget = value - fee - anchor;
    tx_output_t *outs = calloc(n + 1, sizeof(tx_output_t));
    if (!outs) return 0;
    uint64_t caps = 0;
    for (size_t i = 0; i < n; i++) {
        uint64_t c = (p->kind == PAYOUT_TREE) ? member_capacity(f, p->members[i]) : 0;
        if (p->kind == PAYOUT_TREE && c == 0) { free(outs); return 0; }
        outs[i].amount_sats = c;
        caps += c;
    }
    if (budget < caps) { free(outs); return 0; }
    uint64_t share = (budget - caps) / n;   /* remainder of the division: fee */
    for (size_t i = 0; i < n; i++) {
        outs[i].amount_sats += share;
        if (outs[i].amount_sats < CHANNEL_DUST_LIMIT_SATS ||
            !factory_member_payout_spk(f, p->members[i], outs[i].script_pubkey)) {
            free(outs);
            return 0;
        }
        outs[i].script_pubkey_len = 34;
    }
    memcpy(outs[n].script_pubkey, P2A_SPK, P2A_SPK_LEN);
    outs[n].script_pubkey_len = P2A_SPK_LEN;
    outs[n].amount_sats = anchor;

    const factory_node_t *node = &f->nodes[p->node_idx];
    const tx_output_t *prev = &node->outputs[p->vout];
    tx_buf_free(&p->unsigned_tx);
    tx_buf_init(&p->unsigned_tx, 128 + 43 * n);
    int ok = build_unsigned_tx_with_locktime_v(&p->unsigned_tx, NULL, node->txid, p->vout,
                                               0xFFFFFFFEu, f->cltv_timeout, outs, n + 1,
                                               FACTORY_TREE_TX_VERSION) &&
             compute_taproot_sighash(p->sighash, p->unsigned_tx.data, p->unsigned_tx.len, 0,
                                     prev->script_pubkey, prev->script_pubkey_len,
                                     prev->amount_sats, 0xFFFFFFFEu);
    free(outs);
    return ok;
}

/* Set up p for output (node_idx, vout).  Returns 1 = payout made, 0 = this
   output has none (kickoff into its state, anchor, dust stock), -1 = error. */
static int payout_setup(factory_t *f, factory_payout_t *p, size_t node_idx, uint32_t vout) {
    const factory_node_t *node = &f->nodes[node_idx];
    const tx_output_t *o = &node->outputs[vout];
    memset(p, 0, sizeof(*p));
    if (is_anchor(o)) return 0;
    p->node_idx = (uint32_t)node_idx;
    p->vout = vout;

    int c = child_at(f, node_idx, vout);
    if (c >= 0) {
        const factory_node_t *child = &f->nodes[c];
        /* A kickoff's output into its own (DW) state transaction: none. */
        if (node->type == NODE_KICKOFF && !node->is_static_only && child->type == NODE_STATE)
            return 0;
        /* An output holding more members than one TRUC payout can pay
           gets none: the members reach the first output below it through
           the pre-signed tree.  (Factories that large are refused anyway
           while the distribution TX has the same bound; owner question.) */
        if (child->n_signers - 1 > FACTORY_MAX_DIST_CLIENTS)
            return 0;
        p->kind = PAYOUT_TREE;
        p->n_signers = (uint32_t)child->n_signers;
        p->signer_indices = calloc(child->n_signers, sizeof(uint32_t));
        p->members = calloc(child->n_signers, sizeof(uint32_t));
        if (!p->signer_indices || !p->members) return -1;
        memcpy(p->signer_indices, child->signer_indices, child->n_signers * sizeof(uint32_t));
        p->n_members = (uint32_t)members_of(child->signer_indices, child->n_signers, p->members);
        p->keyagg = child->keyagg;
        p->has_merkle = 0;
        if (!spk_is_key(f, o->script_pubkey, o->script_pubkey_len, &child->tweaked_pubkey)) {
            fprintf(stderr, "factory: output %zu:%u is not its child's key-path key\n",
                    node_idx, vout);
            return -1;
        }
        p->output_key = child->tweaked_pubkey;
    } else {
        /* Leaf output: the stock, or a member's channel. */
        unsigned char stock_spk[34];
        if (build_l_stock_spk(f, node, stock_spk) && o->script_pubkey_len == 34 &&
            memcmp(stock_spk, o->script_pubkey, 34) == 0) {
            p->kind = PAYOUT_STOCK;
            p->n_signers = (uint32_t)node->n_signers;
            p->signer_indices = calloc(node->n_signers, sizeof(uint32_t));
            p->members = calloc(node->n_signers, sizeof(uint32_t));
            if (!p->signer_indices || !p->members) return -1;
            memcpy(p->signer_indices, node->signer_indices, node->n_signers * sizeof(uint32_t));
            p->n_members = (uint32_t)members_of(node->signer_indices, node->n_signers, p->members);
            p->keyagg = node->keyagg;
            if (!factory_l_stock_merkle(f, node, p->merkle_root)) return -1;
            p->has_merkle = 1;
            if (!tapscript_tweak_pubkey(f->ctx, &p->output_key, NULL, &p->keyagg.agg_pubkey,
                                        p->merkle_root))
                return -1;
            /* A stock that cannot pay each member above dust has no payout. */
            uint64_t need = factory_payout_fee(f, p->n_members) + factory_tree_anchor_sats(f) +
                            (uint64_t)p->n_members * CHANNEL_DUST_LIMIT_SATS;
            if (p->n_members == 0 || o->amount_sats < need) return 0;
        } else {
            /* Channel: MuSig2 of one leaf member and the host, either key order. */
            int found = 0;
            for (size_t s = 1; s < node->n_signers && !found; s++) {
                uint32_t m = node->signer_indices[s];
                secp256k1_pubkey orders[2][2] = {
                    { f->pubkeys[m], f->pubkeys[0] },
                    { f->pubkeys[0], f->pubkeys[m] },
                };
                for (int oi = 0; oi < 2 && !found; oi++) {
                    musig_keyagg_t ka;
                    secp256k1_xonly_pubkey key;
                    if (!agg_output_key(f, orders[oi], 2, &ka, &key)) return -1;
                    if (!spk_is_key(f, o->script_pubkey, o->script_pubkey_len, &key)) continue;
                    p->kind = PAYOUT_CHANNEL;
                    p->n_signers = 2;
                    p->signer_indices = calloc(2, sizeof(uint32_t));
                    p->members = calloc(1, sizeof(uint32_t));
                    if (!p->signer_indices || !p->members) return -1;
                    p->signer_indices[0] = oi == 0 ? m : 0;
                    p->signer_indices[1] = oi == 0 ? 0 : m;
                    p->members[0] = m;
                    p->n_members = 1;
                    p->keyagg = ka;
                    p->output_key = key;
                    found = 1;
                }
            }
            if (!found) {
                fprintf(stderr, "factory: leaf output %zu:%u is neither the stock nor the "
                        "key-path P2TR of MuSig2(member, host): no end-date payout can "
                        "be signed for it\n", node_idx, vout);
                return -1;
            }
        }
    }
    p->partial_sigs = calloc(p->n_signers, sizeof(secp256k1_musig_partial_sig));
    if (!p->partial_sigs) return -1;
    if (!payout_build_tx(f, p, o->amount_sats)) {
        fprintf(stderr, "factory: end-date payout of output %zu:%u (%llu sats, %u members) "
                "cannot pay every member its capacity above dust\n", node_idx, vout,
                (unsigned long long)o->amount_sats, p->n_members);
        return -1;
    }
    return 1;
}

int factory_build_payouts(factory_t *f) {
    if (!f) return 0;
    factory_free_payouts(f);
    /* No end date, no payouts: a factory proposed without one is refused by
       both sides (lsp_run_factory_creation, cli_validate_proposed_cltv), and
       a member refuses a tree whose payouts are missing. */
    if (f->cltv_timeout == 0) return 1;
    size_t cap = 0;
    for (size_t i = 0; i < f->n_nodes; i++) cap += f->nodes[i].n_outputs;
    if (cap == 0) return 1;
    f->payouts = calloc(cap, sizeof(factory_payout_t));
    if (!f->payouts) return 0;
    for (size_t i = 0; i < f->n_nodes; i++) {
        if (!f->nodes[i].is_built) { factory_free_payouts(f); return 0; }
        for (uint32_t v = 0; v < f->nodes[i].n_outputs; v++) {
            factory_payout_t *p = &f->payouts[f->n_payouts];
            int r = payout_setup(f, p, i, v);
            if (r <= 0) payout_clear(p);
            if (r < 0) { factory_free_payouts(f); return 0; }
            if (r > 0) f->n_payouts++;
        }
    }
    return 1;
}

int factory_find_payout(const factory_t *f, uint32_t node_idx, uint32_t vout) {
    for (size_t i = 0; f && i < f->n_payouts; i++)
        if (f->payouts[i].node_idx == node_idx && f->payouts[i].vout == vout)
            return (int)i;
    return -1;
}

int factory_payout_signer_slot(const factory_t *f, size_t pi, uint32_t participant) {
    if (!f || pi >= f->n_payouts) return -1;
    const factory_payout_t *p = &f->payouts[pi];
    for (uint32_t s = 0; s < p->n_signers; s++)
        if (p->signer_indices[s] == participant) return (int)s;
    return -1;
}

int factory_payout_on_path(const factory_t *f, size_t pi, uint32_t participant) {
    if (!f || pi >= f->n_payouts) return 0;
    const factory_payout_t *p = &f->payouts[pi];
    for (uint32_t m = 0; m < p->n_members; m++)
        if (p->members[m] == participant) return 1;
    return 0;
}

/* --- distributed signing (one MuSig2 session per payout) --- */

int factory_payout_session_init(factory_t *f, size_t pi) {
    if (!f || pi >= f->n_payouts) return 0;
    factory_payout_t *p = &f->payouts[pi];
    musig_session_free(&p->session);
    musig_session_init(&p->session, &p->keyagg, p->n_signers);
    p->partial_sigs_received = 0;
    return 1;
}

int factory_payout_session_set_nonce(factory_t *f, size_t pi, size_t slot,
                                     const secp256k1_musig_pubnonce *pn) {
    if (!f || pi >= f->n_payouts || slot >= f->payouts[pi].n_signers) return 0;
    return musig_session_set_pubnonce(&f->payouts[pi].session, slot, pn);
}

int factory_payout_session_finalize(factory_t *f, size_t pi) {
    if (!f || pi >= f->n_payouts) return 0;
    factory_payout_t *p = &f->payouts[pi];
    return musig_session_finalize_nonces(f->ctx, &p->session, p->sighash,
                                         p->has_merkle ? p->merkle_root : NULL, NULL);
}

int factory_payout_session_set_partial_sig(factory_t *f, size_t pi, size_t slot,
                                           const secp256k1_musig_partial_sig *ps) {
    if (!f || pi >= f->n_payouts || slot >= f->payouts[pi].n_signers || !ps) return 0;
    f->payouts[pi].partial_sigs[slot] = *ps;
    f->payouts[pi].partial_sigs_received++;
    return 1;
}

int factory_payout_attach_sig(factory_t *f, size_t pi, const unsigned char sig64[64]) {
    if (!f || pi >= f->n_payouts || !sig64) return 0;
    factory_payout_t *p = &f->payouts[pi];
    if (!secp256k1_schnorrsig_verify(f->ctx, sig64, p->sighash, 32, &p->output_key))
        return 0;
    if (!finalize_signed_tx(&p->signed_tx, p->unsigned_tx.data, p->unsigned_tx.len, sig64))
        return 0;
    memcpy(p->sig, sig64, 64);
    p->is_signed = 1;
    return 1;
}

int factory_payout_session_complete(factory_t *f, size_t pi) {
    if (!f || pi >= f->n_payouts) return 0;
    factory_payout_t *p = &f->payouts[pi];
    if (p->partial_sigs_received != (int)p->n_signers) return 0;
    unsigned char sig[64];
    if (!musig_aggregate_partial_sigs(f->ctx, sig, &p->session, p->partial_sigs, p->n_signers))
        return 0;
    return factory_payout_attach_sig(f, pi, sig);
}

/* Single process (every key held): sign every payout. */
int factory_sign_payouts_local(factory_t *f) {
    if (!f || !f->keypairs) return 0;
    for (size_t pi = 0; pi < f->n_payouts; pi++) {
        factory_payout_t *p = &f->payouts[pi];
        secp256k1_keypair *kps = calloc(p->n_signers, sizeof(secp256k1_keypair));
        if (!kps) return 0;
        for (uint32_t s = 0; s < p->n_signers; s++)
            kps[s] = f->keypairs[p->signer_indices[s]];
        musig_keyagg_t ka = p->keyagg;
        unsigned char sig[64];
        int ok = musig_sign_taproot(f->ctx, sig, p->sighash, kps, p->n_signers, &ka,
                                    p->has_merkle ? p->merkle_root : NULL) &&
                 factory_payout_attach_sig(f, pi, sig);
        free(kps);
        if (!ok) return 0;
    }
    return 1;
}

int factory_payouts_all_signed(const factory_t *f, uint32_t participant) {
    if (!f) return 0;
    for (size_t pi = 0; pi < f->n_payouts; pi++) {
        if (participant != 0 && !factory_payout_on_path(f, pi, participant)) continue;
        if (!f->payouts[pi].is_signed) return 0;
    }
    return 1;
}

size_t factory_payout_count_for_signer(const factory_t *f, uint32_t participant) {
    size_t n = 0;
    for (size_t pi = 0; f && pi < f->n_payouts; pi++)
        if (factory_payout_signer_slot(f, pi, participant) >= 0) n++;
    return n;
}

size_t factory_payout_nonce_offset(const factory_t *f, size_t pi) {
    size_t off = 0;
    for (size_t j = 0; f && j < pi && j < f->n_payouts; j++)
        off += (size_t)f->payouts[j].n_signers * 66;
    return off;
}

int factory_payout_sessions_init(factory_t *f) {
    for (size_t pi = 0; f && pi < f->n_payouts; pi++)
        if (!factory_payout_session_init(f, pi)) return 0;
    return f != NULL;
}
