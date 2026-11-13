/* Test helpers: a BOLT 4 onion for a single final hop, built the way a
   payer's node builds the last layer (the payee's packet). */
#include "test_onion_util.h"
#include "superscalar/onion_last_hop.h"
#include "superscalar/noise.h"     /* hmac_sha256 */
#include <secp256k1_ecdh.h>
#include <string.h>
#include <stdlib.h>

static size_t put_tu(unsigned char *out, uint64_t v) {
    unsigned char be[8];
    size_t n = 0;
    for (int i = 7; i >= 0; i--) be[7 - i] = (unsigned char)(v >> (8 * i));
    size_t skip = 0;
    while (skip < 8 && be[skip] == 0) skip++;
    for (size_t i = skip; i < 8; i++) out[n++] = be[i];
    return n;
}

size_t test_final_hop_tlv(uint64_t amt_msat, uint32_t cltv,
                          const unsigned char *secret32, uint64_t total_msat,
                          unsigned char *out) {
    size_t o = 0;
    unsigned char v[40];
    size_t n;
    /* type 2: amt_to_forward */
    n = put_tu(v, amt_msat);
    out[o++] = 2; out[o++] = (unsigned char)n; memcpy(out + o, v, n); o += n;
    /* type 4: outgoing_cltv_value */
    n = put_tu(v, cltv);
    out[o++] = 4; out[o++] = (unsigned char)n; memcpy(out + o, v, n); o += n;
    if (secret32) {
        /* type 8: payment_data = payment_secret || total_msat (tu64) */
        memcpy(v, secret32, 32);
        n = 32 + put_tu(v + 32, total_msat);
        out[o++] = 8; out[o++] = (unsigned char)n; memcpy(out + o, v, n); o += n;
    }
    return o;
}

int test_build_final_onion(secp256k1_context *ctx,
                           const unsigned char session_key[32],
                           const secp256k1_pubkey *node_pk,
                           const unsigned char *tlv, size_t tlv_len,
                           const unsigned char *assoc, size_t assoc_len,
                           unsigned char onion[1366]) {
    if (tlv_len >= 0xfd || tlv_len + 1 + 32 > ONION_HOPS_DATA_SIZE) return 0;
    secp256k1_pubkey eph;
    size_t len = 33;
    unsigned char ss[32], rho[32], mu[32], pad_key[32];
    if (!secp256k1_ec_pubkey_create(ctx, &eph, session_key) ||
        !secp256k1_ec_pubkey_serialize(ctx, onion + 1, &len, &eph,
                                       SECP256K1_EC_COMPRESSED) ||
        !secp256k1_ecdh(ctx, ss, node_pk, session_key, NULL, NULL))
        return 0;
    onion[0] = 0x00;
    hmac_sha256(rho, (const unsigned char *)"rho", 3, ss, 32);
    hmac_sha256(mu, (const unsigned char *)"mu", 2, ss, 32);
    hmac_sha256(pad_key, (const unsigned char *)"pad", 3, session_key, 32);

    unsigned char zeros[ONION_HOPS_DATA_SIZE], hops[ONION_HOPS_DATA_SIZE];
    memset(zeros, 0, sizeof(zeros));
    /* start from the pad stream, then put this hop's payload in front */
    if (!onion_xor_stream(zeros, sizeof(zeros), pad_key, hops)) return 0;
    size_t hop_len = 1 + tlv_len + 32;
    memmove(hops + hop_len, hops, ONION_HOPS_DATA_SIZE - hop_len);
    hops[0] = (unsigned char)tlv_len;
    memcpy(hops + 1, tlv, tlv_len);
    memset(hops + 1 + tlv_len, 0, 32);   /* last hop: next HMAC is zero */
    unsigned char enc[ONION_HOPS_DATA_SIZE];
    if (!onion_xor_stream(hops, sizeof(hops), rho, enc)) return 0;
    memcpy(onion + 34, enc, ONION_HOPS_DATA_SIZE);

    unsigned char *mac_in = malloc(ONION_HOPS_DATA_SIZE + assoc_len);
    if (!mac_in) return 0;
    memcpy(mac_in, enc, ONION_HOPS_DATA_SIZE);
    if (assoc_len) memcpy(mac_in + ONION_HOPS_DATA_SIZE, assoc, assoc_len);
    hmac_sha256(onion + 34 + ONION_HOPS_DATA_SIZE, mu, 32, mac_in,
                ONION_HOPS_DATA_SIZE + assoc_len);
    free(mac_in);
    return 1;
}
