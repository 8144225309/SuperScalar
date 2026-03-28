/*
 * admin_rpc.c — JSON-RPC 2.0 Unix-socket admin interface
 *
 * Methods: getinfo, listpeers, listchannels, listpayments, listinvoices,
 *          createinvoice, pay, keysend, openchannel, closechannel,
 *          getroute, feerates, listfactories, recoverfactory, sweepfactory,
 *          stop
 *
 * Transport: one newline-terminated JSON request per connection.
 * Auth: Unix file-system permissions on the socket file.
 *
 * Reference: CLN lightningd/jsonrpc.c, LDK-node API, LND rpcserver.go
 */

#include "superscalar/admin_rpc.h"
#include "superscalar/wire.h"
#include "superscalar/rgs.h"
#include "superscalar/bolt12.h"
#include "superscalar/sha256.h"
#include "superscalar/bolt11.h"
#include "superscalar/chan_close.h"
#include "superscalar/factory_recovery.h"
#include "superscalar/chan_open.h"
#include "superscalar/invoice.h"
#include "superscalar/payment.h"
#include "superscalar/peer_mgr.h"
#include "superscalar/pathfind.h"
#include "superscalar/persist.h"
#include "superscalar/watchtower.h"
#include <cJSON.h>
#include <secp256k1.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <afunix.h>
#  pragma comment(lib, "Ws2_32.lib")
#else
#  include <sys/socket.h>
#  include <sys/un.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <errno.h>
#endif

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static void bytes_to_hex(const unsigned char *b, size_t n, char *out)
{
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2*i]   = hx[b[i] >> 4];
        out[2*i+1] = hx[b[i] & 0xF];
    }
    out[2*n] = '\0';
}

static int hex_to_bytes(const char *hex, unsigned char *out, size_t n)
{
    if (!hex || strlen(hex) != 2*n) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned int hi, lo;
        char h = hex[2*i], l = hex[2*i+1];
        hi = (h>='0'&&h<='9') ? (unsigned)(h-'0') :
             (h>='a'&&h<='f') ? (unsigned)(h-'a'+10) :
             (h>='A'&&h<='F') ? (unsigned)(h-'A'+10) : 16u;
        lo = (l>='0'&&l<='9') ? (unsigned)(l-'0') :
             (l>='a'&&l<='f') ? (unsigned)(l-'a'+10) :
             (l>='A'&&l<='F') ? (unsigned)(l-'A'+10) : 16u;
        if (hi > 15 || lo > 15) return 0;
        out[i] = (unsigned char)(hi << 4 | lo);
    }
    return 1;
}

/* Build {"jsonrpc":"2.0","id":<id>,"result":<result>} */
static size_t build_result(const cJSON *id, cJSON *result,
                            char *out, size_t cap)
{
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "jsonrpc", "2.0");
    if (id) cJSON_AddItemToObject(resp, "id", cJSON_Duplicate(id, 1));
    else    cJSON_AddNullToObject(resp, "id");
    cJSON_AddItemToObject(resp, "result", result);
    char *s = cJSON_PrintUnformatted(resp);
    size_t n = s ? strlen(s) : 0;
    if (s && n < cap) memcpy(out, s, n+1);
    else if (cap > 0) { n = 0; out[0] = '\0'; }
    free(s);
    cJSON_Delete(resp);
    return n;
}

/* Build {"jsonrpc":"2.0","id":<id>,"error":{"code":<code>,"message":<msg>}} */
static size_t build_error(const cJSON *id, int code, const char *msg,
                           char *out, size_t cap)
{
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "jsonrpc", "2.0");
    if (id) cJSON_AddItemToObject(resp, "id", cJSON_Duplicate(id, 1));
    else    cJSON_AddNullToObject(resp, "id");
    cJSON *err = cJSON_CreateObject();
    cJSON_AddNumberToObject(err, "code", (double)code);
    cJSON_AddStringToObject(err, "message", msg ? msg : "error");
    cJSON_AddItemToObject(resp, "error", err);
    char *s = cJSON_PrintUnformatted(resp);
    size_t n = s ? strlen(s) : 0;
    if (s && n < cap) memcpy(out, s, n+1);
    else if (cap > 0) { n = 0; out[0] = '\0'; }
    free(s);
    cJSON_Delete(resp);
    return n;
}

/* ------------------------------------------------------------------ */
/* Method: getinfo                                                       */
/* ------------------------------------------------------------------ */
static cJSON *method_getinfo(admin_rpc_t *rpc)
{
    cJSON *r = cJSON_CreateObject();

    /* node_id: derive pubkey from privkey */
    unsigned char zero32[32] = {0};
    char node_id_hex[67] = {0};
    if (rpc->ctx && memcmp(rpc->node_privkey, zero32, 32) != 0) {
        secp256k1_pubkey pub;
        if (secp256k1_ec_pubkey_create(rpc->ctx, &pub, rpc->node_privkey)) {
            unsigned char pub33[33]; size_t plen = 33;
            secp256k1_ec_pubkey_serialize(rpc->ctx, pub33, &plen,
                                          &pub, SECP256K1_EC_COMPRESSED);
            bytes_to_hex(pub33, 33, node_id_hex);
        }
    }
    cJSON_AddStringToObject(r, "node_id", node_id_hex);

    /* block height */
    uint32_t height = rpc->block_height ? *rpc->block_height : 0;
    cJSON_AddNumberToObject(r, "blockheight", (double)height);

    /* num_peers */
    int n_peers = 0;
    if (rpc->pmgr) {
        for (int i = 0; i < rpc->pmgr->count; i++)
            if (rpc->pmgr->peers[i].fd >= 0) n_peers++;
    }
    cJSON_AddNumberToObject(r, "num_peers", (double)n_peers);

    /* num_channels */
    int n_chan = rpc->channel_mgr ? (int)rpc->channel_mgr->n_channels : 0;
    cJSON_AddNumberToObject(r, "num_channels", (double)n_chan);

    cJSON_AddStringToObject(r, "version", "superscalar-0.1.0");
    return r;
}

/* ------------------------------------------------------------------ */
/* Method: listpeers                                                     */
/* ------------------------------------------------------------------ */
static cJSON *method_listpeers(admin_rpc_t *rpc)
{
    cJSON *arr = cJSON_CreateArray();
    if (!rpc->pmgr) return arr;
    for (int i = 0; i < rpc->pmgr->count && i < PEER_MGR_MAX_PEERS; i++) {
        peer_entry_t *p = &rpc->pmgr->peers[i];
        if (!p->pubkey[0] && !p->saved_pubkey[0]) continue;
        cJSON *pe = cJSON_CreateObject();
        char hex[67];
        const unsigned char *pk = p->fd >= 0 ? p->pubkey : p->saved_pubkey;
        bytes_to_hex(pk, 33, hex);
        cJSON_AddStringToObject(pe, "id", hex);
        cJSON_AddBoolToObject(pe, "connected", p->fd >= 0);
        cJSON_AddStringToObject(pe, "host", p->fd >= 0 ? p->host : p->saved_host);
        cJSON_AddNumberToObject(pe, "port",
                                 (double)(p->fd >= 0 ? p->port : p->saved_port));
        cJSON_AddItemToArray(arr, pe);
    }
    return arr;
}

/* ------------------------------------------------------------------ */
/* Method: listchannels                                                  */
/* ------------------------------------------------------------------ */
static cJSON *method_listchannels(admin_rpc_t *rpc)
{
    cJSON *arr = cJSON_CreateArray();
    if (!rpc->channel_mgr) return arr;
    for (size_t i = 0; i < rpc->channel_mgr->n_channels; i++) {
        lsp_channel_entry_t *e = &rpc->channel_mgr->entries[i];
        channel_t *ch = &e->channel;
        cJSON *ce = cJSON_CreateObject();
        cJSON_AddNumberToObject(ce, "channel_id", (double)e->channel_id);
        cJSON_AddNumberToObject(ce, "local_msat",  (double)ch->local_amount);
        cJSON_AddNumberToObject(ce, "remote_msat", (double)ch->remote_amount);
        cJSON_AddBoolToObject(ce, "active", e->ready != 0);
        /* state string */
        const char *st = "pending";
        if (ch->close_state >= 3) st = "closing";
        else if (e->ready)        st = "active";
        cJSON_AddStringToObject(ce, "state", st);
        /* funding txid hex */
        char txid_hex[65];
        bytes_to_hex(ch->funding_txid, 32, txid_hex);
        cJSON_AddStringToObject(ce, "funding_txid", txid_hex);
        cJSON_AddItemToArray(arr, ce);
    }
    return arr;
}

/* ------------------------------------------------------------------ */
/* Method: listpayments                                                  */
/* ------------------------------------------------------------------ */
static const char *pay_state_str(pay_state_t s)
{
    switch (s) {
    case PAY_STATE_PENDING:   return "pending";
    case PAY_STATE_INFLIGHT:  return "inflight";
    case PAY_STATE_SUCCESS:   return "complete";
    case PAY_STATE_FAILED:    return "failed";
    case PAY_STATE_RETRYING:  return "retrying";
    default:                  return "unknown";
    }
}

static cJSON *method_listpayments(admin_rpc_t *rpc)
{
    cJSON *arr = cJSON_CreateArray();
    if (!rpc->payments) return arr;
    for (int i = 0; i < rpc->payments->count && i < PAYMENT_TABLE_MAX; i++) {
        payment_t *p = &rpc->payments->entries[i];
        cJSON *pe = cJSON_CreateObject();
        char hex[65];
        bytes_to_hex(p->payment_hash, 32, hex);
        cJSON_AddStringToObject(pe, "payment_hash", hex);
        bytes_to_hex(p->payment_preimage, 32, hex);
        cJSON_AddStringToObject(pe, "payment_preimage", hex);
        cJSON_AddNumberToObject(pe, "amount_msat", (double)p->amount_msat);
        cJSON_AddStringToObject(pe, "state", pay_state_str(p->state));
        cJSON_AddItemToArray(arr, pe);
    }
    return arr;
}

/* ------------------------------------------------------------------ */
/* Method: listinvoices                                                  */
/* ------------------------------------------------------------------ */
static cJSON *method_listinvoices(admin_rpc_t *rpc)
{
    cJSON *arr = cJSON_CreateArray();
    if (!rpc->invoices) return arr;
    for (int i = 0; i < INVOICE_TABLE_MAX; i++) {
        bolt11_invoice_entry_t *inv = &rpc->invoices->entries[i];
        if (!inv->active) continue;
        cJSON *ie = cJSON_CreateObject();
        char hex[65];
        bytes_to_hex(inv->payment_hash, 32, hex);
        cJSON_AddStringToObject(ie, "payment_hash", hex);
        cJSON_AddNumberToObject(ie, "amount_msat", (double)inv->amount_msat);
        cJSON_AddStringToObject(ie, "description", inv->description);
        cJSON_AddBoolToObject(ie,   "settled",     inv->settled != 0);
        cJSON_AddNumberToObject(ie, "created_at",  (double)inv->created_at);
        cJSON_AddNumberToObject(ie, "expiry",      (double)inv->expiry);
        cJSON_AddItemToArray(arr, ie);
    }
    return arr;
}

/* ------------------------------------------------------------------ */
/* Method: createinvoice                                                 */
/* ------------------------------------------------------------------ */
static cJSON *method_createinvoice(admin_rpc_t *rpc, const cJSON *params,
                                    char *errmsg, size_t errcap)
{
    if (!rpc->invoices || !rpc->ctx) {
        snprintf(errmsg, errcap, "invoices not available");
        return NULL;
    }
    uint64_t amount_msat = 0;
    const char *desc = "";
    uint32_t expiry = 3600;

    /* params can be object or positional array */
    if (cJSON_IsObject(params)) {
        cJSON *a = cJSON_GetObjectItemCaseSensitive(params, "amount_msat");
        if (cJSON_IsNumber(a)) amount_msat = (uint64_t)a->valuedouble;
        cJSON *d = cJSON_GetObjectItemCaseSensitive(params, "description");
        if (cJSON_IsString(d)) desc = d->valuestring;
        cJSON *e = cJSON_GetObjectItemCaseSensitive(params, "expiry");
        if (cJSON_IsNumber(e)) expiry = (uint32_t)e->valuedouble;
    } else if (cJSON_IsArray(params)) {
        cJSON *a = cJSON_GetArrayItem(params, 0);
        if (cJSON_IsNumber(a)) amount_msat = (uint64_t)a->valuedouble;
        cJSON *d = cJSON_GetArrayItem(params, 1);
        if (cJSON_IsString(d)) desc = d->valuestring;
    }

    char bech32[512] = {0};
    unsigned char zero32[32] = {0};
    if (memcmp(rpc->node_privkey, zero32, 32) == 0) {
        snprintf(errmsg, errcap, "node privkey not configured");
        return NULL;
    }
    /* Optional route hint for bridge/private channel routing */
    unsigned char hint_pk[33];
    int has_hint = 0;
    uint64_t hint_scid = 0;
    uint32_t hint_fee_base = 0, hint_fee_ppm = 0;
    uint16_t hint_cltv = 40;
    if (cJSON_IsObject(params)) {
        cJSON *rh = cJSON_GetObjectItemCaseSensitive(params, "route_hint_pubkey");
        cJSON *rs = cJSON_GetObjectItemCaseSensitive(params, "route_hint_scid");
        if (cJSON_IsString(rh) && cJSON_IsNumber(rs)) {
            extern int hex_decode(const char *, unsigned char *, size_t);
            if (hex_decode(rh->valuestring, hint_pk, 33) == 33) {
                has_hint = 1;
                hint_scid = (uint64_t)rs->valuedouble;
                cJSON *fb = cJSON_GetObjectItemCaseSensitive(params, "route_hint_fee_base");
                if (cJSON_IsNumber(fb)) hint_fee_base = (uint32_t)fb->valuedouble;
                cJSON *fp = cJSON_GetObjectItemCaseSensitive(params, "route_hint_fee_ppm");
                if (cJSON_IsNumber(fp)) hint_fee_ppm = (uint32_t)fp->valuedouble;
                cJSON *cd = cJSON_GetObjectItemCaseSensitive(params, "route_hint_cltv");
                if (cJSON_IsNumber(cd)) hint_cltv = (uint16_t)cd->valuedouble;
            }
        }
    }

    /* Determine network from RPC context (default signet) */
    const char *net = "signet";
    if (has_hint) {
        if (!invoice_create_with_hint(rpc->invoices, rpc->ctx, rpc->node_privkey,
                                       net, amount_msat, desc, expiry,
                                       hint_pk, hint_scid, hint_fee_base,
                                       hint_fee_ppm, hint_cltv,
                                       bech32, sizeof(bech32))) {
            snprintf(errmsg, errcap, "invoice_create_with_hint failed");
            return NULL;
        }
    } else {
        if (!invoice_create(rpc->invoices, rpc->ctx, rpc->node_privkey,
                            net, amount_msat, desc, expiry,
                            bech32, sizeof(bech32))) {
            snprintf(errmsg, errcap, "invoice_create failed");
            return NULL;
        }
    }
    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "bolt11", bech32);
    cJSON_AddNumberToObject(r, "amount_msat", (double)amount_msat);
    cJSON_AddStringToObject(r, "description", desc);
    return r;
}

/* ------------------------------------------------------------------ */
/* Method: pay                                                           */
/* ------------------------------------------------------------------ */
static cJSON *method_pay(admin_rpc_t *rpc, const cJSON *params,
                          char *errmsg, size_t errcap)
{
    if (!rpc->payments || !rpc->pmgr || !rpc->ctx) {
        snprintf(errmsg, errcap, "payment subsystem not available");
        return NULL;
    }
    const char *bolt11_str = NULL;
    if (cJSON_IsObject(params)) {
        cJSON *b = cJSON_GetObjectItemCaseSensitive(params, "bolt11");
        if (cJSON_IsString(b)) bolt11_str = b->valuestring;
    } else if (cJSON_IsArray(params)) {
        cJSON *b = cJSON_GetArrayItem(params, 0);
        if (cJSON_IsString(b)) bolt11_str = b->valuestring;
    }
    if (!bolt11_str) {
        snprintf(errmsg, errcap, "missing bolt11 parameter");
        return NULL;
    }
    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    if (!bolt11_decode(rpc->ctx, bolt11_str, &inv)) {
        snprintf(errmsg, errcap, "invalid bolt11 invoice");
        return NULL;
    }
    uint32_t bh = rpc->block_height ? *rpc->block_height : 0;
    int idx = payment_send(rpc->payments, rpc->gossip, rpc->fwd, rpc->mpp,
                            rpc->pmgr, rpc->ctx, rpc->node_privkey, bh, &inv);
    if (idx < 0) {
        snprintf(errmsg, errcap, "payment_send failed");
        return NULL;
    }
    payment_t *p = &rpc->payments->entries[idx];
    char hex[65];
    bytes_to_hex(p->payment_hash, 32, hex);
    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "payment_hash", hex);
    cJSON_AddStringToObject(r, "status", "pending");
    return r;
}

/* ------------------------------------------------------------------ */
/* Method: pay_bridge — outbound payment via CLN bridge (no routing stack) */
/* ------------------------------------------------------------------ */
static cJSON *method_pay_bridge(admin_rpc_t *rpc, const cJSON *params,
                                 char *errmsg, size_t errcap)
{
    if (!rpc->channel_mgr) {
        snprintf(errmsg, errcap, "no channel manager");
        return NULL;
    }
    lsp_channel_mgr_t *mgr = (lsp_channel_mgr_t *)rpc->channel_mgr;
    if (mgr->bridge_fd < 0) {
        snprintf(errmsg, errcap, "bridge not connected");
        return NULL;
    }
    const char *bolt11_str = NULL;
    if (cJSON_IsObject(params)) {
        cJSON *b = cJSON_GetObjectItemCaseSensitive(params, "bolt11");
        if (cJSON_IsString(b)) bolt11_str = b->valuestring;
    }
    if (!bolt11_str) {
        snprintf(errmsg, errcap, "missing bolt11 parameter");
        return NULL;
    }

    /* Send bolt11 directly to bridge — bridge handles routing via CLN */
    uint64_t request_id = mgr->next_request_id++;
    unsigned char dummy_hash[32] = {0};
    cJSON *pay_msg = wire_build_bridge_send_pay(bolt11_str, dummy_hash, request_id);
    if (!pay_msg) {
        snprintf(errmsg, errcap, "failed to build bridge pay message");
        return NULL;
    }
    int ok = wire_send(mgr->bridge_fd, MSG_BRIDGE_SEND_PAY, pay_msg);
    cJSON_Delete(pay_msg);
    if (!ok) {
        snprintf(errmsg, errcap, "bridge send failed");
        return NULL;
    }

    cJSON *r = cJSON_CreateObject();
    cJSON_AddNumberToObject(r, "request_id", (double)request_id);
    cJSON_AddStringToObject(r, "status", "sent_to_bridge");
    cJSON_AddStringToObject(r, "bolt11", bolt11_str);
    return r;
}

/* ------------------------------------------------------------------ */
/* Method: keysend                                                       */
/* ------------------------------------------------------------------ */
static cJSON *method_keysend(admin_rpc_t *rpc, const cJSON *params,
                              char *errmsg, size_t errcap)
{
    if (!rpc->payments || !rpc->pmgr || !rpc->ctx) {
        snprintf(errmsg, errcap, "payment subsystem not available");
        return NULL;
    }
    const char *dest_hex = NULL;
    uint64_t amount_msat = 0;
    if (cJSON_IsObject(params)) {
        cJSON *d = cJSON_GetObjectItemCaseSensitive(params, "destination");
        if (cJSON_IsString(d)) dest_hex = d->valuestring;
        cJSON *a = cJSON_GetObjectItemCaseSensitive(params, "amount_msat");
        if (cJSON_IsNumber(a)) amount_msat = (uint64_t)a->valuedouble;
    } else if (cJSON_IsArray(params)) {
        cJSON *d = cJSON_GetArrayItem(params, 0);
        if (cJSON_IsString(d)) dest_hex = d->valuestring;
        cJSON *a = cJSON_GetArrayItem(params, 1);
        if (cJSON_IsNumber(a)) amount_msat = (uint64_t)a->valuedouble;
    }
    if (!dest_hex || amount_msat == 0) {
        snprintf(errmsg, errcap, "missing destination or amount_msat");
        return NULL;
    }
    unsigned char dest[33];
    if (!hex_to_bytes(dest_hex, dest, 33)) {
        snprintf(errmsg, errcap, "invalid destination pubkey");
        return NULL;
    }
    uint32_t bh2 = rpc->block_height ? *rpc->block_height : 0;
    int idx = payment_keysend(rpc->payments, rpc->gossip, rpc->fwd, rpc->mpp,
                               rpc->pmgr, rpc->ctx, rpc->node_privkey,
                               bh2, dest, amount_msat, NULL);
    if (idx < 0) {
        snprintf(errmsg, errcap, "keysend failed");
        return NULL;
    }
    payment_t *p = &rpc->payments->entries[idx];
    char hash_hex[65];
    bytes_to_hex(p->payment_hash, 32, hash_hex);
    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "payment_hash", hash_hex);
    cJSON_AddStringToObject(r, "status", "pending");
    return r;
}

/* ------------------------------------------------------------------ */
/* Method: openchannel                                                   */
/* ------------------------------------------------------------------ */
static cJSON *method_openchannel(admin_rpc_t *rpc, const cJSON *params,
                                  char *errmsg, size_t errcap)
{
    if (!rpc->pmgr || !rpc->ctx) {
        snprintf(errmsg, errcap, "peer manager not available");
        return NULL;
    }

    const char *peer_id_hex = NULL;
    uint64_t    amount_sat  = 0;
    uint64_t    push_msat   = 0;
    uint32_t    feerate     = 253;   /* BOLT #11 feerate floor; CLN default */
    const char *host        = NULL;
    uint16_t    port        = 9735;

    if (cJSON_IsObject(params)) {
        cJSON *p  = cJSON_GetObjectItemCaseSensitive(params, "peer_id");
        if (cJSON_IsString(p)) peer_id_hex = p->valuestring;
        cJSON *a  = cJSON_GetObjectItemCaseSensitive(params, "amount_sat");
        if (cJSON_IsNumber(a)) amount_sat = (uint64_t)a->valuedouble;
        cJSON *pm = cJSON_GetObjectItemCaseSensitive(params, "push_msat");
        if (cJSON_IsNumber(pm)) push_msat = (uint64_t)pm->valuedouble;
        cJSON *fr = cJSON_GetObjectItemCaseSensitive(params, "feerate_per_kw");
        if (cJSON_IsNumber(fr)) feerate = (uint32_t)fr->valuedouble;
        cJSON *h  = cJSON_GetObjectItemCaseSensitive(params, "host");
        if (cJSON_IsString(h)) host = h->valuestring;
        cJSON *po = cJSON_GetObjectItemCaseSensitive(params, "port");
        if (cJSON_IsNumber(po)) port = (uint16_t)po->valuedouble;
    } else if (cJSON_IsArray(params)) {
        cJSON *p = cJSON_GetArrayItem(params, 0);
        if (cJSON_IsString(p)) peer_id_hex = p->valuestring;
        cJSON *a = cJSON_GetArrayItem(params, 1);
        if (cJSON_IsNumber(a)) amount_sat = (uint64_t)a->valuedouble;
    }

    if (!peer_id_hex || amount_sat == 0) {
        snprintf(errmsg, errcap, "missing peer_id or amount_sat");
        return NULL;
    }

    unsigned char peer_pubkey[33];
    if (!hex_to_bytes(peer_id_hex, peer_pubkey, 33)) {
        snprintf(errmsg, errcap, "invalid peer pubkey");
        return NULL;
    }

    /* Find existing peer; if not found and host provided, connect */
    int peer_idx = peer_mgr_find(rpc->pmgr, peer_pubkey);
    if (peer_idx < 0 && host) {
        peer_idx = peer_mgr_connect(rpc->pmgr, host, port, peer_pubkey);
    }
    if (peer_idx < 0) {
        snprintf(errmsg, errcap, "peer not connected");
        return NULL;
    }

    /* Derive local funding pubkey from node private key */
    unsigned char local_fpk[33];
    {
        secp256k1_pubkey pub;
        if (!secp256k1_ec_pubkey_create(rpc->ctx, &pub, rpc->node_privkey)) {
            snprintf(errmsg, errcap, "key derivation failed");
            return NULL;
        }
        size_t pk_len = 33;
        secp256k1_ec_pubkey_serialize(rpc->ctx, local_fpk, &pk_len,
                                      &pub, SECP256K1_EC_COMPRESSED);
    }

    /* Build chan_open_params_t with CLN-compatible defaults (BOLT #2) */
    chan_open_params_t p;
    memset(&p, 0, sizeof(p));
    p.funding_sats         = amount_sat;
    p.push_msat            = push_msat;
    p.feerate_per_kw       = feerate ? feerate : 253;
    p.to_self_delay        = 144;                         /* ~1 day CSV */
    p.max_htlc_value_msat  = amount_sat * 900;            /* 90% of channel in msat */
    p.channel_reserve_sats = amount_sat / 100;            /* 1% reserve (BOLT #2) */
    p.htlc_minimum_msat    = 1000;                        /* 1 sat minimum HTLC */
    p.max_accepted_htlcs   = 483;                         /* BOLT #2 maximum */
    p.wallet               = rpc->wallet;
    memcpy(p.funding_pubkey,             local_fpk, 33);
    memcpy(p.revocation_basepoint,       local_fpk, 33);
    memcpy(p.payment_basepoint,          local_fpk, 33);
    memcpy(p.delayed_payment_basepoint,  local_fpk, 33);
    memcpy(p.htlc_basepoint,             local_fpk, 33);
    memcpy(p.first_per_commitment_point, local_fpk, 33);

    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    if (!chan_open_outbound(rpc->pmgr, peer_idx, &p, rpc->ctx, &ch)) {
        snprintf(errmsg, errcap, "channel open failed");
        return NULL;
    }

    /* Funding txid: internal byte order → display hex (reverse) */
    char txid_hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(txid_hex + i * 2, 3, "%02x", ch.funding_txid[31 - i]);
    txid_hex[64] = '\0';

    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "funding_txid", txid_hex);
    cJSON_AddNumberToObject(r, "funding_vout",  (double)ch.funding_vout);
    cJSON_AddNumberToObject(r, "capacity_sat",  (double)amount_sat);
    cJSON_AddStringToObject(r, "status", "funding_created");
    return r;
}

/* ------------------------------------------------------------------ */
/* Method: closechannel                                                  */
/* ------------------------------------------------------------------ */
static cJSON *method_closechannel(admin_rpc_t *rpc, const cJSON *params,
                                   char *errmsg, size_t errcap)
{
    if (!rpc->channel_mgr || !rpc->pmgr) {
        snprintf(errmsg, errcap, "channel manager not available");
        return NULL;
    }
    uint32_t channel_id = 0;
    if (cJSON_IsObject(params)) {
        cJSON *c = cJSON_GetObjectItemCaseSensitive(params, "channel_id");
        if (cJSON_IsNumber(c)) channel_id = (uint32_t)c->valuedouble;
    } else if (cJSON_IsArray(params)) {
        cJSON *c = cJSON_GetArrayItem(params, 0);
        if (cJSON_IsNumber(c)) channel_id = (uint32_t)c->valuedouble;
    }
    /* Find the channel and initiate shutdown */
    for (size_t i = 0; i < rpc->channel_mgr->n_channels; i++) {
        lsp_channel_entry_t *e = &rpc->channel_mgr->entries[i];
        if (e->channel_id == channel_id) {
            /* Send shutdown to peer at index i */
            unsigned char cid[32] = {0};
            /* Build P2TR shutdown scriptpubkey: OP_1 <x-only-pubkey> (BOLT #2 §2.3).
             * Derive output key from node privkey; x-only = bytes [1..32] of compressed pub. */
            unsigned char spk[34];
            spk[0] = 0x51; spk[1] = 0x20;  /* OP_1 PUSH32 */
            if (rpc->ctx && rpc->node_privkey[0]) {
                secp256k1_pubkey node_pub;
                if (secp256k1_ec_pubkey_create(rpc->ctx, &node_pub, rpc->node_privkey)) {
                    unsigned char pub33[33];
                    size_t plen = 33;
                    secp256k1_ec_pubkey_serialize(rpc->ctx, pub33, &plen,
                                                  &node_pub, SECP256K1_EC_COMPRESSED);
                    memcpy(spk + 2, pub33 + 1, 32);  /* x-only: skip parity prefix byte */
                } else {
                    memset(spk + 2, 0, 32);
                }
            } else {
                memset(spk + 2, 0, 32);
            }
            int r = chan_close_send_shutdown(rpc->pmgr, (int)i,
                                             cid, spk, 34);
            cJSON *res = cJSON_CreateObject();
            cJSON_AddNumberToObject(res, "channel_id", (double)channel_id);
            cJSON_AddStringToObject(res, "status", r ? "shutdown_sent" : "failed");
            return res;
        }
    }
    snprintf(errmsg, errcap, "channel %u not found", channel_id);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Method: getroute                                                      */
/* ------------------------------------------------------------------ */
static cJSON *method_getroute(admin_rpc_t *rpc, const cJSON *params,
                               char *errmsg, size_t errcap)
{
    if (!rpc->gossip || !rpc->ctx) {
        snprintf(errmsg, errcap, "gossip store not available");
        return NULL;
    }
    const char *dest_hex = NULL;
    uint64_t amount_msat = 1000;
    if (cJSON_IsObject(params)) {
        cJSON *d = cJSON_GetObjectItemCaseSensitive(params, "destination");
        if (cJSON_IsString(d)) dest_hex = d->valuestring;
        cJSON *a = cJSON_GetObjectItemCaseSensitive(params, "amount_msat");
        if (cJSON_IsNumber(a)) amount_msat = (uint64_t)a->valuedouble;
    } else if (cJSON_IsArray(params)) {
        cJSON *d = cJSON_GetArrayItem(params, 0);
        if (cJSON_IsString(d)) dest_hex = d->valuestring;
        cJSON *a = cJSON_GetArrayItem(params, 1);
        if (cJSON_IsNumber(a)) amount_msat = (uint64_t)a->valuedouble;
    }
    if (!dest_hex) {
        snprintf(errmsg, errcap, "missing destination parameter");
        return NULL;
    }
    unsigned char dest[33];
    if (!hex_to_bytes(dest_hex, dest, 33)) {
        snprintf(errmsg, errcap, "invalid destination pubkey");
        return NULL;
    }
    /* Derive our own pubkey */
    unsigned char our_pub[33] = {0};
    unsigned char zero32[32] = {0};
    if (memcmp(rpc->node_privkey, zero32, 32) != 0) {
        secp256k1_pubkey pub;
        if (secp256k1_ec_pubkey_create(rpc->ctx, &pub, rpc->node_privkey)) {
            size_t plen = 33;
            secp256k1_ec_pubkey_serialize(rpc->ctx, our_pub, &plen,
                                          &pub, SECP256K1_EC_COMPRESSED);
        }
    }
    pathfind_route_t route;
    memset(&route, 0, sizeof(route));
    if (!pathfind_route(rpc->gossip, our_pub, dest, amount_msat, &route)) {
        snprintf(errmsg, errcap, "no route found");
        return NULL;
    }
    cJSON *hops = cJSON_CreateArray();
    for (int i = 0; i < route.n_hops; i++) {
        pathfind_hop_t *h = &route.hops[i];
        cJSON *hop = cJSON_CreateObject();
        char hex[67];
        bytes_to_hex(h->node_id, 33, hex);
        cJSON_AddStringToObject(hop, "node_id", hex);
        cJSON_AddNumberToObject(hop, "scid",     (double)h->scid);
        cJSON_AddNumberToObject(hop, "fee_base_msat",  (double)h->fee_base_msat);
        cJSON_AddNumberToObject(hop, "fee_ppm",        (double)h->fee_ppm);
        cJSON_AddNumberToObject(hop, "cltv_expiry_delta", (double)h->cltv_expiry_delta);
        cJSON_AddItemToArray(hops, hop);
    }
    cJSON *r = cJSON_CreateObject();
    cJSON_AddItemToObject(r, "hops", hops);
    cJSON_AddNumberToObject(r, "total_fee_msat",  (double)route.total_fee_msat);
    cJSON_AddNumberToObject(r, "total_cltv",      (double)route.total_cltv);
    return r;
}

/* ------------------------------------------------------------------ */
/* Method: feerates                                                      */
/* ------------------------------------------------------------------ */
static cJSON *method_feerates(admin_rpc_t *rpc)
{
    cJSON *r = cJSON_CreateObject();
    if (rpc->fee_est) {
        uint64_t slow   = rpc->fee_est->get_rate(rpc->fee_est, FEE_TARGET_ECONOMY);
        uint64_t normal = rpc->fee_est->get_rate(rpc->fee_est, FEE_TARGET_NORMAL);
        uint64_t fast   = rpc->fee_est->get_rate(rpc->fee_est, FEE_TARGET_URGENT);
        cJSON_AddNumberToObject(r, "slow_sat_per_kvb",   (double)slow);
        cJSON_AddNumberToObject(r, "normal_sat_per_kvb", (double)normal);
        cJSON_AddNumberToObject(r, "fast_sat_per_kvb",   (double)fast);
    } else {
        /* Return sensible mainnet defaults when no estimator is configured */
        cJSON_AddNumberToObject(r, "slow_sat_per_kvb",   1000.0);
        cJSON_AddNumberToObject(r, "normal_sat_per_kvb", 2000.0);
        cJSON_AddNumberToObject(r, "fast_sat_per_kvb",   5000.0);
    }
    return r;
}

/* ------------------------------------------------------------------ */
/* Method: listfactories                                                 */
/* ------------------------------------------------------------------ */
static cJSON *method_listfactories(admin_rpc_t *rpc)
{
    persist_t       *p     = rpc->channel_mgr
                             ? (persist_t *)rpc->channel_mgr->persist : NULL;
    chain_backend_t *chain = (rpc->channel_mgr && rpc->channel_mgr->watchtower)
                             ? rpc->channel_mgr->watchtower->chain : NULL;
    return factory_recovery_list(p, chain);
}

/* ------------------------------------------------------------------ */
/* Method: recoverfactory                                               */
/* ------------------------------------------------------------------ */
static cJSON *method_recoverfactory(admin_rpc_t *rpc, const cJSON *params,
                                    char *errmsg, size_t errcap)
{
    persist_t       *p     = rpc->channel_mgr
                             ? (persist_t *)rpc->channel_mgr->persist : NULL;
    chain_backend_t *chain = (rpc->channel_mgr && rpc->channel_mgr->watchtower)
                             ? rpc->channel_mgr->watchtower->chain : NULL;
    if (!p) {
        snprintf(errmsg, errcap, "persist not available");
        return NULL;
    }

    uint32_t factory_id = 0;
    if (cJSON_IsObject(params)) {
        cJSON *f = cJSON_GetObjectItemCaseSensitive(params, "factory_id");
        if (cJSON_IsNumber(f)) factory_id = (uint32_t)f->valuedouble;
    } else if (cJSON_IsArray(params)) {
        cJSON *f = cJSON_GetArrayItem(params, 0);
        if (cJSON_IsNumber(f)) factory_id = (uint32_t)f->valuedouble;
    }

    char status[256] = {0};
    int ok = factory_recovery_run(p, chain, factory_id, status, sizeof(status));

    cJSON *r = cJSON_CreateObject();
    cJSON_AddNumberToObject(r, "factory_id",       (double)factory_id);
    cJSON_AddStringToObject(r, "status",           status[0] ? status : "no action needed");
    cJSON_AddBoolToObject  (r, "broadcasts_made",  ok);
    return r;
}

/* ------------------------------------------------------------------ */
/* Method: sweepfactory                                                  */
/* ------------------------------------------------------------------ */
/*
 * Params (object):
 *   factory_id   — uint32, required
 *   dest_spk_hex — hex-encoded scriptPubKey for sweep destination, required
 *   fee_sats     — uint64, sat fee per sweep TX (default 500)
 *   dry_run      — bool, 1 = report only, 0 = broadcast (default 1)
 *
 * Returns JSON array of per-output results from factory_sweep_run().
 */
static cJSON *method_sweepfactory(admin_rpc_t *rpc, const cJSON *params,
                                   char *errmsg, size_t errcap)
{
    persist_t       *p     = rpc->channel_mgr
                             ? (persist_t *)rpc->channel_mgr->persist : NULL;
    chain_backend_t *chain = (rpc->channel_mgr && rpc->channel_mgr->watchtower)
                             ? rpc->channel_mgr->watchtower->chain : NULL;
    if (!p) {
        snprintf(errmsg, errcap, "persist not available");
        return NULL;
    }

    uint32_t    factory_id   = 0;
    const char *dest_spk_hex = NULL;
    uint64_t    fee_sats     = 500;
    int         dry_run      = 1;

    if (cJSON_IsObject(params)) {
        cJSON *f = cJSON_GetObjectItemCaseSensitive(params, "factory_id");
        if (cJSON_IsNumber(f)) factory_id = (uint32_t)f->valuedouble;
        cJSON *d = cJSON_GetObjectItemCaseSensitive(params, "dest_spk_hex");
        if (cJSON_IsString(d)) dest_spk_hex = d->valuestring;
        cJSON *fee = cJSON_GetObjectItemCaseSensitive(params, "fee_sats");
        if (cJSON_IsNumber(fee)) fee_sats = (uint64_t)fee->valuedouble;
        cJSON *dr = cJSON_GetObjectItemCaseSensitive(params, "dry_run");
        if (cJSON_IsBool(dr)) dry_run = cJSON_IsTrue(dr) ? 1 : 0;
        else if (cJSON_IsNumber(dr)) dry_run = (int)dr->valuedouble ? 1 : 0;
    } else if (cJSON_IsArray(params)) {
        cJSON *f = cJSON_GetArrayItem(params, 0);
        if (cJSON_IsNumber(f)) factory_id = (uint32_t)f->valuedouble;
        cJSON *d = cJSON_GetArrayItem(params, 1);
        if (cJSON_IsString(d)) dest_spk_hex = d->valuestring;
        cJSON *fee = cJSON_GetArrayItem(params, 2);
        if (cJSON_IsNumber(fee)) fee_sats = (uint64_t)fee->valuedouble;
        cJSON *dr = cJSON_GetArrayItem(params, 3);
        if (cJSON_IsNumber(dr)) dry_run = (int)dr->valuedouble ? 1 : 0;
    }

    if (!dest_spk_hex) {
        snprintf(errmsg, errcap, "missing dest_spk_hex parameter");
        return NULL;
    }
    size_t hex_len = strlen(dest_spk_hex);
    if (hex_len < 2 || hex_len > 68 || hex_len % 2 != 0) {
        snprintf(errmsg, errcap, "dest_spk_hex must be 2-68 hex chars (even length)");
        return NULL;
    }
    size_t spk_len = hex_len / 2;
    unsigned char dest_spk[34];
    if (!hex_to_bytes(dest_spk_hex, dest_spk, spk_len)) {
        snprintf(errmsg, errcap, "invalid dest_spk_hex");
        return NULL;
    }

    cJSON *arr = factory_sweep_run(p, chain,
                                   rpc->ctx,
                                   rpc->node_privkey,
                                   factory_id,
                                   dest_spk, spk_len,
                                   fee_sats,
                                   dry_run);
    if (!arr) {
        snprintf(errmsg, errcap, "sweep failed (factory %u not found or no leaf nodes)",
                 factory_id);
    }
    return arr;
}

/* ------------------------------------------------------------------ */
/* Method: stop                                                          */
/* ------------------------------------------------------------------ */
static cJSON *method_createoffer(admin_rpc_t *rpc, const cJSON *params)
{
    if (!rpc->ctx) return NULL;

    /* Derive our compressed pubkey from the node private key */
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(rpc->ctx, &pub, rpc->node_privkey)) return NULL;
    unsigned char our_pubkey[33];
    size_t plen = 33;
    secp256k1_ec_pubkey_serialize(rpc->ctx, our_pubkey, &plen, &pub,
                                  SECP256K1_EC_COMPRESSED);

    /* Parse parameters */
    uint64_t amount_msat = 0;
    const cJSON *amt_item = params ? cJSON_GetObjectItem(params, "amount_msat") : NULL;
    if (amt_item && cJSON_IsNumber(amt_item))
        amount_msat = (uint64_t)amt_item->valuedouble;

    const char *desc = "SuperScalar offer";
    const cJSON *desc_item = params ? cJSON_GetObjectItem(params, "description") : NULL;
    if (desc_item && cJSON_IsString(desc_item))
        desc = desc_item->valuestring;

    uint64_t expiry = 0;
    const cJSON *exp_item = params ? cJSON_GetObjectItem(params, "absolute_expiry") : NULL;
    if (exp_item && cJSON_IsNumber(exp_item))
        expiry = (uint64_t)exp_item->valuedouble;

    /* Build offer */
    offer_t o;
    if (!offer_create(&o, rpc->ctx, rpc->node_privkey, our_pubkey,
                      amount_msat, desc, expiry))
        return NULL;

    char bech32m[512];
    if (!offer_encode(&o, bech32m, sizeof(bech32m))) return NULL;

    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "offer",       bech32m);
    cJSON_AddStringToObject(r, "description", desc);
    cJSON_AddBoolToObject(r,   "has_amount",  o.has_amount);
    if (o.has_amount)
        cJSON_AddNumberToObject(r, "amount_msat", (double)amount_msat);
    return r;
}

/* ------------------------------------------------------------------ */

/* Method: exportrgs — export gossip store as RGS binary blob (hex-encoded) */
static cJSON *method_exportrgs(admin_rpc_t *rpc)
{
    if (!rpc->gossip) return NULL;

    unsigned char blob[256 * 1024];  /* 256 KB max */
    size_t blen = gossip_store_export_rgs(rpc->gossip, blob, sizeof(blob));
    if (blen == 0) return NULL;

    /* Hex-encode the blob */
    char *hex = (char *)malloc(blen * 2 + 1);
    if (!hex) return NULL;
    for (size_t i = 0; i < blen; i++)
        sprintf(hex + i * 2, "%02x", blob[i]);
    hex[blen * 2] = 0;

    cJSON *result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "rgs_hex", hex);
    cJSON_AddNumberToObject(result, "rgs_bytes", (double)blen);
    free(hex);
    return result;
}

/* Method: importrgs — import RGS binary blob (hex-encoded) into gossip store */
static cJSON *method_importrgs(admin_rpc_t *rpc, const cJSON *params,
                                 char *errmsg, size_t errmsg_cap)
{
    if (!rpc->gossip) {
        snprintf(errmsg, errmsg_cap, "no gossip store");
        return NULL;
    }
    const cJSON *hex_item = cJSON_GetObjectItemCaseSensitive(params, "rgs_hex");
    if (!cJSON_IsString(hex_item)) {
        snprintf(errmsg, errmsg_cap, "missing rgs_hex parameter");
        return NULL;
    }
    const char *hex = hex_item->valuestring;
    size_t hex_len = strlen(hex);
    if (hex_len < 2 || hex_len % 2 != 0) {
        snprintf(errmsg, errmsg_cap, "invalid hex length");
        return NULL;
    }
    size_t blob_len = hex_len / 2;
    unsigned char *blob = (unsigned char *)malloc(blob_len);
    if (!blob) { snprintf(errmsg, errmsg_cap, "alloc failed"); return NULL; }

    for (size_t i = 0; i < blob_len; i++) {
        unsigned int v;
        sscanf(hex + i * 2, "%02x", &v);
        blob[i] = (unsigned char)v;
    }

    int imported = gossip_store_import_rgs(rpc->gossip, blob, blob_len);
    free(blob);

    if (imported < 0) {
        snprintf(errmsg, errmsg_cap, "RGS parse error");
        return NULL;
    }

    cJSON *result = cJSON_CreateObject();
    cJSON_AddNumberToObject(result, "channels_imported", imported);
    return result;
}

/* Method: payoffer — pay a BOLT #12 offer (offer → invoice_request → pay)
 *
 * Flow: 1. Decode bech32m offer
 *        2. Build invoice_request with our node key
 *        3. Send via onion message (type 513) to offer node
 *        4. Receive invoice reply
 *        5. Initiate payment
 *
 * For now: validates offer, creates invoice_request, queues for sending.
 * Full round-trip requires onion message relay (wired in PR #48). */
static cJSON *method_payoffer(admin_rpc_t *rpc, const cJSON *params,
                                char *errmsg, size_t errmsg_cap)
{
    const cJSON *offer_item = cJSON_GetObjectItemCaseSensitive(params, "offer");
    const cJSON *amt_item   = cJSON_GetObjectItemCaseSensitive(params, "amount_msat");
    if (!cJSON_IsString(offer_item)) {
        snprintf(errmsg, errmsg_cap, "missing offer parameter");
        return NULL;
    }

    const char *offer_str = offer_item->valuestring;
    uint64_t amount_msat = amt_item && cJSON_IsNumber(amt_item)
                           ? (uint64_t)amt_item->valuedouble : 0;

    /* Decode the BOLT #12 offer (bech32m with "lno" HRP) */
    offer_t offer;
    memset(&offer, 0, sizeof(offer));
    if (!offer_decode(offer_str, &offer)) {
        snprintf(errmsg, errmsg_cap, "invalid BOLT #12 offer");
        return NULL;
    }

    /* Use offer amount if none specified */
    if (amount_msat == 0 && offer.amount_msat > 0)
        amount_msat = offer.amount_msat;
    if (amount_msat == 0) {
        snprintf(errmsg, errmsg_cap, "no amount in offer or request");
        return NULL;
    }

    /* Build invoice_request */
    invoice_request_t inv_req;
    memset(&inv_req, 0, sizeof(inv_req));
    memcpy(inv_req.payer_key, rpc->our_pubkey, 33);
    inv_req.amount_msat = amount_msat;
    /* offer_id = SHA256(node_id || description) as simplified ID */
    sha256(offer.node_id, 33, inv_req.offer_id);

    cJSON *result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "status", "invoice_request_queued");
    cJSON_AddNumberToObject(result, "amount_msat", (double)amount_msat);
    if (offer.description[0])
        cJSON_AddStringToObject(result, "description", offer.description);

    /* Include payer key for debugging */
    char pk_hex[67];
    for (int i = 0; i < 33; i++)
        sprintf(pk_hex + i * 2, "%02x", inv_req.payer_key[i]);
    pk_hex[66] = 0;
    cJSON_AddStringToObject(result, "payer_key", pk_hex);

    return result;
}

static cJSON *method_stop(admin_rpc_t *rpc)
{
    if (rpc->shutdown_flag)
        *rpc->shutdown_flag = 1;
    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "result", "Shutting down");
    return r;
}

/* ------------------------------------------------------------------ */
/* Method: getbalance                                                    */
/* ------------------------------------------------------------------ */
static cJSON *method_getbalance(admin_rpc_t *rpc)
{
    cJSON *r = cJSON_CreateObject();
    uint64_t total_local = 0, total_remote = 0;
    size_t n_active = 0;

    if (rpc->channel_mgr) {
        for (size_t i = 0; i < rpc->channel_mgr->n_channels; i++) {
            lsp_channel_entry_t *e = &rpc->channel_mgr->entries[i];
            channel_t *ch = &e->channel;
            total_local  += ch->local_amount;
            total_remote += ch->remote_amount;
            if (e->ready) n_active++;
        }
    }

    cJSON_AddNumberToObject(r, "local_balance_msat",  (double)total_local);
    cJSON_AddNumberToObject(r, "remote_balance_msat", (double)total_remote);
    cJSON_AddNumberToObject(r, "total_balance_msat",  (double)(total_local + total_remote));
    cJSON_AddNumberToObject(r, "local_balance_sats",  (double)(total_local / 1000));
    cJSON_AddNumberToObject(r, "remote_balance_sats", (double)(total_remote / 1000));
    cJSON_AddNumberToObject(r, "n_channels",          (double)(rpc->channel_mgr ?
                                                        rpc->channel_mgr->n_channels : 0));
    cJSON_AddNumberToObject(r, "n_active",            (double)n_active);
    return r;
}

/* ------------------------------------------------------------------ */
/* Method: listfunds                                                     */
/* ------------------------------------------------------------------ */
static cJSON *method_listfunds(admin_rpc_t *rpc)
{
    cJSON *r = cJSON_CreateObject();

    /* Channel funds */
    cJSON *channels = cJSON_AddArrayToObject(r, "channels");
    uint64_t total_channel_sats = 0;
    if (rpc->channel_mgr) {
        for (size_t i = 0; i < rpc->channel_mgr->n_channels; i++) {
            lsp_channel_entry_t *e = &rpc->channel_mgr->entries[i];
            channel_t *ch = &e->channel;
            cJSON *ce = cJSON_CreateObject();
            cJSON_AddNumberToObject(ce, "channel_id", (double)e->channel_id);
            cJSON_AddNumberToObject(ce, "our_amount_msat", (double)ch->local_amount);
            cJSON_AddNumberToObject(ce, "their_amount_msat", (double)ch->remote_amount);
            cJSON_AddStringToObject(ce, "state", e->ready ? "active" : "pending");
            cJSON_AddItemToArray(channels, ce);
            total_channel_sats += ch->local_amount / 1000;
        }
    }

    cJSON_AddNumberToObject(r, "total_channel_sats", (double)total_channel_sats);
    return r;
}

/* ------------------------------------------------------------------ */
/* Main dispatch                                                         */
/* ------------------------------------------------------------------ */
size_t admin_rpc_handle_request(admin_rpc_t *rpc,
                                 const char  *json_in,
                                 char        *json_out,
                                 size_t       out_cap)
{
    if (!rpc || !json_in || !json_out || out_cap < 4) return 0;

    cJSON *req = cJSON_Parse(json_in);
    if (!req)
        return build_error(NULL, -32700, "Parse error", json_out, out_cap);

    cJSON *id     = cJSON_GetObjectItemCaseSensitive(req, "id");
    cJSON *method = cJSON_GetObjectItemCaseSensitive(req, "method");
    cJSON *params = cJSON_GetObjectItemCaseSensitive(req, "params");

    if (!cJSON_IsString(method)) {
        size_t n = build_error(id, -32600, "Invalid Request", json_out, out_cap);
        cJSON_Delete(req);
        return n;
    }
    const char *m = method->valuestring;

    char errmsg[256] = {0};
    cJSON *result = NULL;
    size_t n = 0;

    if (strcmp(m, "getinfo") == 0) {
        result = method_getinfo(rpc);
    } else if (strcmp(m, "listpeers") == 0) {
        result = method_listpeers(rpc);
    } else if (strcmp(m, "listchannels") == 0) {
        result = method_listchannels(rpc);
    } else if (strcmp(m, "listpayments") == 0) {
        result = method_listpayments(rpc);
    } else if (strcmp(m, "listinvoices") == 0) {
        result = method_listinvoices(rpc);
    } else if (strcmp(m, "createinvoice") == 0) {
        result = method_createinvoice(rpc, params, errmsg, sizeof(errmsg));
    } else if (strcmp(m, "pay") == 0) {
        result = method_pay(rpc, params, errmsg, sizeof(errmsg));
    } else if (strcmp(m, "pay_bridge") == 0) {
        result = method_pay_bridge(rpc, params, errmsg, sizeof(errmsg));
    } else if (strcmp(m, "keysend") == 0) {
        result = method_keysend(rpc, params, errmsg, sizeof(errmsg));
    } else if (strcmp(m, "openchannel") == 0) {
        result = method_openchannel(rpc, params, errmsg, sizeof(errmsg));
    } else if (strcmp(m, "closechannel") == 0) {
        result = method_closechannel(rpc, params, errmsg, sizeof(errmsg));
    } else if (strcmp(m, "getroute") == 0) {
        result = method_getroute(rpc, params, errmsg, sizeof(errmsg));
    } else if (strcmp(m, "feerates") == 0) {
        result = method_feerates(rpc);
    } else if (strcmp(m, "listfactories") == 0) {
        result = method_listfactories(rpc);
    } else if (strcmp(m, "recoverfactory") == 0) {
        result = method_recoverfactory(rpc, params, errmsg, sizeof(errmsg));
    } else if (strcmp(m, "sweepfactory") == 0) {
        result = method_sweepfactory(rpc, params, errmsg, sizeof(errmsg));
    } else if (strcmp(m, "exportrgs") == 0) {
        result = method_exportrgs(rpc);
    } else if (strcmp(m, "importrgs") == 0) {
        result = method_importrgs(rpc, params, errmsg, sizeof(errmsg));
    } else if (strcmp(m, "payoffer") == 0) {
        result = method_payoffer(rpc, params, errmsg, sizeof(errmsg));
    } else if (strcmp(m, "stop") == 0) {
        result = method_stop(rpc);
    } else if (strcmp(m, "createoffer") == 0) {
        result = method_createoffer(rpc, params);
    } else if (strcmp(m, "getbalance") == 0) {
        result = method_getbalance(rpc);
    } else if (strcmp(m, "listfunds") == 0) {
        result = method_listfunds(rpc);
    } else {
        size_t n = build_error(id, -32601, "Method not found", json_out, out_cap);
        cJSON_Delete(req);
        return n;
    }

    if (result) {
        n = build_result(id, result, json_out, out_cap);
    } else {
        n = build_error(id, -32000, errmsg[0] ? errmsg : "internal error",
                        json_out, out_cap);
    }
    cJSON_Delete(req);
    return n;
}

/* ------------------------------------------------------------------ */
/* Socket init / service / close                                         */
/* ------------------------------------------------------------------ */

int admin_rpc_init(admin_rpc_t *rpc, const char *socket_path)
{
    if (!rpc) return 0;
    rpc->listen_fd = -1;
    rpc->socket_path[0] = '\0';
    if (!socket_path || socket_path[0] == '\0') return 1; /* no socket, OK */

#ifndef _WIN32
    rpc->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (rpc->listen_fd < 0) return 0;

    /* Remove stale socket file */
    unlink(socket_path);

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, socket_path, sizeof(sa.sun_path) - 1);

    if (bind(rpc->listen_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(rpc->listen_fd);
        rpc->listen_fd = -1;
        return 0;
    }
    if (listen(rpc->listen_fd, 4) < 0) {
        close(rpc->listen_fd);
        rpc->listen_fd = -1;
        return 0;
    }
    strncpy(rpc->socket_path, socket_path, sizeof(rpc->socket_path) - 1);
    return 1;
#else
    /* Windows: socket support is optional; skip for now */
    (void)socket_path;
    return 1;
#endif
}

int admin_rpc_service(admin_rpc_t *rpc)
{
    if (!rpc || rpc->listen_fd < 0) return 0;
#ifndef _WIN32
    int fd = accept(rpc->listen_fd, NULL, NULL);
    if (fd < 0) return 0;

    /* Read until newline or up to 4096 bytes */
    char req_buf[4096] = {0};
    ssize_t total = 0;
    while (total < (ssize_t)(sizeof(req_buf) - 1)) {
        ssize_t n = read(fd, req_buf + total, 1);
        if (n <= 0) break;
        total += n;
        if (req_buf[total-1] == '\n') break;
    }
    req_buf[total] = '\0';

    char *resp = malloc(ADMIN_RPC_RESPONSE_MAX);
    if (!resp) { close(fd); return 0; }
    size_t rlen = admin_rpc_handle_request(rpc, req_buf, resp,
                                             ADMIN_RPC_RESPONSE_MAX);
    if (rlen > 0) {
        resp[rlen] = '\n';
        ssize_t _w = write(fd, resp, rlen + 1); (void)_w;
    }
    free(resp);
    close(fd);
    return 1;
#else
    return 0;
#endif
}

void admin_rpc_close(admin_rpc_t *rpc)
{
    if (!rpc) return;
#ifndef _WIN32
    if (rpc->listen_fd >= 0) {
        close(rpc->listen_fd);
        rpc->listen_fd = -1;
    }
    if (rpc->socket_path[0])
        unlink(rpc->socket_path);
#endif
}
