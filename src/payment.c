/*
 * payment.c — Top-level payment state machine
 *
 * Integrates pathfinding, onion construction, and HTLC management
 * into a complete payment send/receive lifecycle.
 *
 * Reference: LDK ChannelManager::send_payment, CLN pay plugin.
 */

#include "superscalar/payment.h"
#include "superscalar/pathfind.h"
#include "superscalar/onion.h"
#include "superscalar/bolt11.h"
#include "superscalar/sha256.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

void payment_init(payment_table_t *pt) {
    if (!pt) return;
    memset(pt, 0, sizeof(*pt));
}

/* Build onion hops from a pathfind_route + invoice fields */
static int build_onion_hops(const pathfind_route_t *route,
                              uint64_t amount_msat,
                              uint32_t final_cltv,
                              const unsigned char payment_secret[32],
                              int is_keysend,
                              const unsigned char keysend_preimage[32],
                              onion_hop_t *hops_out) {
    if (!route || route->n_hops <= 0 || !hops_out) return 0;

    /* Compute per-hop amounts (BOLT #4: include fees from inner hops outward) */
    uint64_t amounts[PATHFIND_MAX_HOPS];
    uint32_t cltvs[PATHFIND_MAX_HOPS];

    /* Final hop gets the actual amount */
    amounts[route->n_hops - 1] = amount_msat;
    cltvs[route->n_hops - 1]   = final_cltv;

    /* Work backwards: each hop's amount includes the fee for the next hop */
    for (int i = route->n_hops - 2; i >= 0; i--) {
        const pathfind_hop_t *next = &route->hops[i + 1];
        uint64_t fee = (uint64_t)next->fee_base_msat +
                       (uint64_t)next->fee_ppm * amounts[i + 1] / 1000000ULL;
        amounts[i] = amounts[i + 1] + fee;
        cltvs[i]   = cltvs[i + 1] + next->cltv_expiry_delta;
    }

    for (int i = 0; i < route->n_hops; i++) {
        onion_hop_t *h = &hops_out[i];
        memset(h, 0, sizeof(*h));
        memcpy(h->pubkey, route->hops[i].node_id, 33);
        h->amount_msat      = amounts[i];
        h->cltv_expiry      = cltvs[i];
        h->short_channel_id = route->hops[i].scid;
        h->is_final         = (i == route->n_hops - 1) ? 1 : 0;
        if (h->is_final) {
            if (payment_secret)
                memcpy(h->payment_secret, payment_secret, 32);
            h->total_msat = amount_msat;
            if (is_keysend && keysend_preimage) {
                memcpy(h->keysend_preimage, keysend_preimage, 32);
                h->has_keysend = 1;
            }
        }
    }
    return 1;
}

/* ---- Internal: initiate a single payment shard ---- */
static int do_payment_send(payment_t *pay,
                            gossip_store_t *gs,
                            htlc_forward_table_t *fwd,
                            mpp_table_t *mpp,
                            peer_mgr_t *pmgr,
                            secp256k1_context *ctx,
                            const unsigned char our_priv[32],
                            const unsigned char our_node[33],
                            uint64_t shard_msat,
                            int route_idx) {
    (void)fwd; (void)mpp;

    pathfind_route_t *route = &pay->routes[route_idx];
    if (route->n_hops == 0) return 0;

    /* Build onion hops */
    onion_hop_t hops[PATHFIND_MAX_HOPS];
    if (!build_onion_hops(route, shard_msat,
                           /* final_cltv */ (uint32_t)(time(NULL) / 600) + 40,
                           pay->payment_secret, 0, NULL, hops)) return 0;

    /* Generate session key */
    unsigned char session_key[32];
    {
        FILE *f = fopen("/dev/urandom", "rb");
        if (!f || fread(session_key, 1, 32, f) != 32) {
            if (f) fclose(f);
            return 0;
        }
        fclose(f);
    }
    memcpy(pay->session_keys[route_idx], session_key, 32);

    /* Build onion */
    unsigned char onion_pkt[ONION_PACKET_SIZE];
    if (!onion_build(hops, route->n_hops, session_key, ctx, onion_pkt)) return 0;

    /* Find the first-hop peer and send update_add_htlc */
    /* BOLT #2 update_add_htlc: type(2) + chan_id(8) + htlc_id(8) +
                                 amount(8) + payment_hash(32) + cltv(4) + onion(1366) */
    int peer_idx = -1;
    if (pmgr) {
        for (int i = 0; i < pmgr->count; i++) {
            if (pmgr->peers[i].has_channel) { peer_idx = i; break; }
        }
    }

    if (peer_idx >= 0 && pmgr) {
        unsigned char htlc_msg[1440];
        size_t pos = 0;
        htlc_msg[pos++] = 0x00; htlc_msg[pos++] = 0x80; /* type 128: update_add_htlc */
        memset(htlc_msg + pos, 0, 8); pos += 8;          /* channel_id */
        memset(htlc_msg + pos, 0, 8); pos += 8;          /* htlc_id */
        for (int i = 7; i >= 0; i--) htlc_msg[pos++] = (unsigned char)(shard_msat >> (i*8));
        memcpy(htlc_msg + pos, pay->payment_hash, 32); pos += 32;
        htlc_msg[pos++] = 0; htlc_msg[pos++] = 0;
        htlc_msg[pos++] = 0; htlc_msg[pos++] = 40;     /* cltv_expiry placeholder */
        memcpy(htlc_msg + pos, onion_pkt, ONION_PACKET_SIZE); pos += ONION_PACKET_SIZE;
        peer_mgr_send(pmgr, peer_idx, htlc_msg, pos);
    }

    (void)our_node;
    (void)gs;
    (void)our_priv;
    return 1;
}

/* ---- payment_send ---- */

int payment_send(payment_table_t *pt,
                 gossip_store_t *gs,
                 htlc_forward_table_t *fwd,
                 mpp_table_t *mpp,
                 peer_mgr_t *pmgr,
                 secp256k1_context *ctx,
                 const unsigned char our_priv[32],
                 const bolt11_invoice_t *inv) {
    if (!pt || !gs || !ctx || !our_priv || !inv) return -1;
    if (pt->count >= PAYMENT_TABLE_MAX) return -1;

    /* Derive our node pubkey */
    unsigned char our_pub[33];
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(ctx, &pub, our_priv)) return -1;
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, our_pub, &pub_len, &pub, SECP256K1_EC_COMPRESSED);

    payment_t *pay = &pt->entries[pt->count];
    memset(pay, 0, sizeof(*pay));
    memcpy(pay->payment_hash, inv->payment_hash, 32);
    if (inv->has_payment_secret)
        memcpy(pay->payment_secret, inv->payment_secret, 32);
    pay->amount_msat    = inv->amount_msat;
    pay->max_cltv_delta = 2016; /* ~2 weeks */
    pay->state          = PAY_STATE_PENDING;
    pay->attempt_at     = (uint32_t)time(NULL);

    /* Find route to destination */
    int n_routes = pathfind_mpp_routes(gs, our_pub, inv->payee_pubkey,
                                        inv->amount_msat, 1,
                                        pay->routes, PAYMENT_MAX_ROUTES);
    if (n_routes <= 0) {
        snprintf(pay->last_error, sizeof(pay->last_error), "no route found");
        pay->state = PAY_STATE_FAILED;
        return pt->count++;
    }
    pay->n_routes = n_routes;

    /* Send each shard */
    uint64_t shard = inv->amount_msat / (uint64_t)n_routes;
    pay->state = PAY_STATE_INFLIGHT;
    pay->n_attempts++;

    for (int i = 0; i < n_routes; i++) {
        uint64_t s = (i == n_routes - 1) ?
                     inv->amount_msat - shard * (uint64_t)(n_routes - 1) : shard;
        if (!do_payment_send(pay, gs, fwd, mpp, pmgr, ctx, our_priv, our_pub, s, i)) {
            snprintf(pay->last_error, sizeof(pay->last_error), "onion build failed");
            pay->state = PAY_STATE_FAILED;
            return pt->count++;
        }
    }

    return pt->count++;
}

/* ---- payment_keysend ---- */

int payment_keysend(payment_table_t *pt,
                    gossip_store_t *gs,
                    htlc_forward_table_t *fwd,
                    mpp_table_t *mpp,
                    peer_mgr_t *pmgr,
                    secp256k1_context *ctx,
                    const unsigned char our_priv[32],
                    const unsigned char dest_pubkey[33],
                    uint64_t amount_msat,
                    const unsigned char preimage[32]) {
    if (!pt || !gs || !ctx || !our_priv || !dest_pubkey || !preimage) return -1;
    if (pt->count >= PAYMENT_TABLE_MAX) return -1;

    /* Compute payment_hash = SHA256(preimage) */
    unsigned char payment_hash[32];
    sha256(preimage, 32, payment_hash);

    unsigned char our_pub[33];
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(ctx, &pub, our_priv)) return -1;
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, our_pub, &pub_len, &pub, SECP256K1_EC_COMPRESSED);

    payment_t *pay = &pt->entries[pt->count];
    memset(pay, 0, sizeof(*pay));
    memcpy(pay->payment_hash, payment_hash, 32);
    memcpy(pay->payment_preimage, preimage, 32);
    pay->amount_msat = amount_msat;
    pay->state       = PAY_STATE_PENDING;
    pay->attempt_at  = (uint32_t)time(NULL);

    /* Find route */
    int n_routes = pathfind_route(gs, our_pub, dest_pubkey, amount_msat,
                                   &pay->routes[0]);
    if (!n_routes) {
        snprintf(pay->last_error, sizeof(pay->last_error), "keysend: no route");
        pay->state = PAY_STATE_FAILED;
        return pt->count++;
    }
    pay->n_routes = 1;

    /* Build onion with keysend preimage */
    onion_hop_t hops[PATHFIND_MAX_HOPS];
    if (!build_onion_hops(&pay->routes[0], amount_msat,
                           (uint32_t)(time(NULL) / 600) + 40,
                           NULL, 1, preimage, hops)) {
        pay->state = PAY_STATE_FAILED;
        return pt->count++;
    }

    unsigned char session_key[32];
    {
        FILE *f = fopen("/dev/urandom", "rb");
        if (!f || fread(session_key, 1, 32, f) != 32) {
            if (f) fclose(f);
            pay->state = PAY_STATE_FAILED;
            return pt->count++;
        }
        fclose(f);
    }
    memcpy(pay->session_keys[0], session_key, 32);

    unsigned char onion_pkt[ONION_PACKET_SIZE];
    if (!onion_build(hops, pay->routes[0].n_hops, session_key, ctx, onion_pkt)) {
        pay->state = PAY_STATE_FAILED;
        return pt->count++;
    }

    pay->state = PAY_STATE_INFLIGHT;
    pay->n_attempts++;

    /* Send to first-hop peer if connected */
    if (pmgr) {
        int peer_idx = -1;
        for (int i = 0; i < pmgr->count; i++) {
            if (pmgr->peers[i].has_channel) { peer_idx = i; break; }
        }
        if (peer_idx >= 0) {
            unsigned char htlc_msg[1440];
            size_t pos = 0;
            htlc_msg[pos++] = 0x00; htlc_msg[pos++] = 0x80;
            memset(htlc_msg + pos, 0, 8); pos += 8;
            memset(htlc_msg + pos, 0, 8); pos += 8;
            for (int i = 7; i >= 0; i--) htlc_msg[pos++] = (unsigned char)(amount_msat >> (i*8));
            memcpy(htlc_msg + pos, payment_hash, 32); pos += 32;
            htlc_msg[pos++] = 0; htlc_msg[pos++] = 0;
            htlc_msg[pos++] = 0; htlc_msg[pos++] = 40;
            memcpy(htlc_msg + pos, onion_pkt, ONION_PACKET_SIZE); pos += ONION_PACKET_SIZE;
            peer_mgr_send(pmgr, peer_idx, htlc_msg, pos);
        }
    }

    (void)fwd; (void)mpp;
    return pt->count++;
}

/* ---- payment_on_settle ---- */

void payment_on_settle(payment_table_t *pt,
                       const unsigned char payment_hash[32],
                       const unsigned char preimage[32]) {
    if (!pt || !payment_hash) return;
    for (int i = 0; i < pt->count; i++) {
        payment_t *p = &pt->entries[i];
        if (memcmp(p->payment_hash, payment_hash, 32) == 0 &&
            p->state == PAY_STATE_INFLIGHT) {
            p->state = PAY_STATE_SUCCESS;
            if (preimage) memcpy(p->payment_preimage, preimage, 32);
            return;
        }
    }
}

/* ---- payment_on_fail ---- */

int payment_on_fail(payment_table_t *pt,
                    gossip_store_t *gs,
                    htlc_forward_table_t *fwd,
                    mpp_table_t *mpp,
                    peer_mgr_t *pmgr,
                    secp256k1_context *ctx,
                    const unsigned char our_priv[32],
                    const unsigned char payment_hash[32],
                    const unsigned char *onion_error, size_t err_len) {
    if (!pt || !payment_hash) return 0;

    payment_t *pay = NULL;
    for (int i = 0; i < pt->count; i++) {
        if (memcmp(pt->entries[i].payment_hash, payment_hash, 32) == 0) {
            pay = &pt->entries[i];
            break;
        }
    }
    if (!pay || pay->state != PAY_STATE_INFLIGHT) return 0;

    /* Decrypt error to identify failing hop */
    if (onion_error && err_len >= 256 && ctx && pay->n_routes > 0) {
        unsigned char plaintext[256];
        int failing_hop = -1;
        onion_error_decrypt(
            (const unsigned char (*)[32])pay->session_keys,
            pay->routes[0].n_hops, ctx,
            onion_error, plaintext, &failing_hop);

        if (failing_hop >= 0 && failing_hop < pay->routes[0].n_hops) {
            /* Mark the failing channel as disabled in gossip store */
            uint64_t bad_scid = pay->routes[0].hops[failing_hop].scid;
            if (gs && bad_scid) {
                /* Mark as spent/disabled (soft-delete from routing) */
                gossip_store_mark_channel_spent(gs, bad_scid, (uint32_t)time(NULL));
            }
        }
    }

    /* Retry if attempts remain */
    if (pay->n_attempts < PAYMENT_MAX_ATTEMPTS) {
        pay->state = PAY_STATE_RETRYING;
        pay->n_attempts++;

        /* Re-find route excluding the failed channel */
        unsigned char our_pub[33];
        if (ctx && our_priv) {
            secp256k1_pubkey pub;
            if (secp256k1_ec_pubkey_create(ctx, &pub, our_priv)) {
                size_t pub_len = 33;
                secp256k1_ec_pubkey_serialize(ctx, our_pub, &pub_len,
                                               &pub, SECP256K1_EC_COMPRESSED);
                /* Try a fresh route */
                if (gs && pay->n_routes > 0) {
                    unsigned char dest[33];
                    memcpy(dest, pay->routes[0].hops[pay->routes[0].n_hops-1].node_id, 33);
                    pathfind_route_t new_route;
                    if (pathfind_route(gs, our_pub, dest, pay->amount_msat, &new_route)) {
                        pay->routes[0] = new_route;
                        pay->state = PAY_STATE_INFLIGHT;
                        do_payment_send(pay, gs, fwd, mpp, pmgr, ctx,
                                        our_priv, our_pub, pay->amount_msat, 0);
                        return 1;
                    }
                }
            }
        }
    }

    pay->state = PAY_STATE_FAILED;
    snprintf(pay->last_error, sizeof(pay->last_error), "payment failed after %d attempts",
             pay->n_attempts);
    return 0;
}

/* -----------------------------------------------------------------------
 * Phase P: payment timeout — retry or fail stale INFLIGHT payments
 * --------------------------------------------------------------------- */
int payment_check_timeouts(payment_table_t *pt,
                             gossip_store_t *gs,
                             htlc_forward_table_t *fwd,
                             mpp_table_t *mpp,
                             peer_mgr_t *pmgr,
                             secp256k1_context *ctx,
                             const unsigned char *our_priv,
                             uint32_t now)
{
    if (!pt) return 0;
    int expired = 0;
    for (int i = 0; i < pt->count; i++) {
        payment_t *p = &pt->entries[i];
        if (p->state != PAY_STATE_INFLIGHT) continue;
        if (now - p->attempt_at < PAYMENT_TIMEOUT_SECS) continue;
        expired++;
        if (p->n_attempts < PAYMENT_MAX_ATTEMPTS &&
            gs && fwd && mpp && pmgr && ctx && our_priv &&
            p->n_routes > 0) {
            /* Retry: re-find route and re-send */
            unsigned char our_pub[33];
            secp256k1_pubkey pub;
            if (secp256k1_ec_pubkey_create(ctx, &pub, our_priv)) {
                size_t plen = 33;
                secp256k1_ec_pubkey_serialize(ctx, our_pub, &plen,
                                               &pub, SECP256K1_EC_COMPRESSED);
                p->n_attempts++;
                p->attempt_at = now;
                p->state = PAY_STATE_RETRYING;
                unsigned char dest[33];
                int last = p->routes[0].n_hops - 1;
                if (last >= 0)
                    memcpy(dest, p->routes[0].hops[last].node_id, 33);
                pathfind_route_t new_route;
                if (last >= 0 && pathfind_route(gs, our_pub, dest,
                                                 p->amount_msat, &new_route)) {
                    p->routes[0] = new_route;
                    p->state = PAY_STATE_INFLIGHT;
                    do_payment_send(p, gs, fwd, mpp, pmgr, ctx,
                                    our_priv, our_pub, p->amount_msat, 0);
                } else {
                    p->state = PAY_STATE_FAILED;
                    snprintf(p->last_error, sizeof(p->last_error),
                             "timeout retry: no route");
                }
            } else {
                p->state = PAY_STATE_FAILED;
                snprintf(p->last_error, sizeof(p->last_error), "timeout");
            }
        } else {
            p->state = PAY_STATE_FAILED;
            snprintf(p->last_error, sizeof(p->last_error),
                     "timeout after %d attempt(s)", p->n_attempts);
        }
    }
    return expired;
}
