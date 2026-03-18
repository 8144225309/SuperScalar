/*
 * test_gossip_net.c — PR #19 gossip networking tests
 *
 * Tests added by commit:
 *   Commit 2 (base): timestamp strategy, reconnect backoff/jitter, peer parse
 *   Commit 3 (added via Edit): prune, rejection cache, 4-sig, waiting proof
 *   Commit 4 (added via Edit): rate limit, refill, embargo
 */

#include "superscalar/gossip_peer.h"
#include "superscalar/gossip_store.h"
#include "superscalar/gossip.h"
#include "superscalar/sha256.h"
#include "superscalar/bolt8.h"
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* -----------------------------------------------------------------------
 * Commit 2: Timestamp strategy
 * ----------------------------------------------------------------------- */

int test_gossip_peer_timestamp_strategy(void) {
    uint32_t now = 1800000000u;  /* well past 2 weeks */

    /* First GOSSIP_BOOTSTRAP_PEER_COUNT peers (0..4) get 2-week filter */
    for (int i = 0; i < GOSSIP_BOOTSTRAP_PEER_COUNT; i++) {
        uint32_t ts = gossip_timestamp_for_peer(i, now);
        ASSERT(ts == now - 1209600u,
               "bootstrap peer gets 2-week filter");
    }

    /* Peer at index GOSSIP_BOOTSTRAP_PEER_COUNT gets 1-hour filter */
    {
        uint32_t ts = gossip_timestamp_for_peer(GOSSIP_BOOTSTRAP_PEER_COUNT, now);
        ASSERT(ts == now - 3600u,
               "non-bootstrap peer gets 1-hour filter");
    }

    /* Peer at index GOSSIP_BOOTSTRAP_PEER_COUNT+2 also gets 1-hour filter */
    {
        uint32_t ts = gossip_timestamp_for_peer(GOSSIP_BOOTSTRAP_PEER_COUNT + 2, now);
        ASSERT(ts == now - 3600u,
               "subsequent non-bootstrap peer gets 1-hour filter");
    }

    /* Edge: now < 2 weeks should clamp to 0 for bootstrap */
    {
        uint32_t ts = gossip_timestamp_for_peer(0, 100u);
        ASSERT(ts == 0, "early now: bootstrap clamps to 0");
    }

    return 1;
}

/* -----------------------------------------------------------------------
 * Commit 2: Reconnect backoff doubling with cap
 * ----------------------------------------------------------------------- */

int test_gossip_reconnect_backoff(void) {
    ASSERT(GOSSIP_RECONNECT_INIT_MS == 1000, "initial backoff is 1s");

    /* At max, doubling stays within max + jitter */
    int result = gossip_next_backoff_ms(GOSSIP_RECONNECT_MAX_MS);
    ASSERT(result <= GOSSIP_RECONNECT_MAX_MS + 500,
           "at max, result never exceeds cap + 500ms jitter");

    /* Non-negative */
    ASSERT(gossip_next_backoff_ms(0) >= 0, "backoff from 0 is non-negative");

    return 1;
}

/* -----------------------------------------------------------------------
 * Commit 2: Reconnect jitter ±500ms
 * ----------------------------------------------------------------------- */

int test_gossip_reconnect_jitter(void) {
    int min_seen = 999999;
    int max_seen = -1;

    srand(12345);
    for (int i = 0; i < 100; i++) {
        int v = gossip_next_backoff_ms(GOSSIP_RECONNECT_MAX_MS);
        if (v < min_seen) min_seen = v;
        if (v > max_seen) max_seen = v;
    }

    ASSERT(min_seen >= GOSSIP_RECONNECT_MAX_MS - 500,
           "jitter lower bound: >= cap - 500ms");
    ASSERT(max_seen <= GOSSIP_RECONNECT_MAX_MS + 500,
           "jitter upper bound: <= cap + 500ms");
    ASSERT(max_seen > min_seen,
           "jitter produces actual variation across 100 calls");

    return 1;
}

/* -----------------------------------------------------------------------
 * Commit 2: Peer parse list
 * ----------------------------------------------------------------------- */

int test_gossip_peer_parse_list(void) {
    gossip_peer_cfg_t out[GOSSIP_PEER_MAX];
    memset(out, 0, sizeof(out));

    /* Two peers */
    int n = gossip_peer_parse_list("host1.example.com:9735,host2.example.com:9736",
                                    out, GOSSIP_PEER_MAX);
    ASSERT(n == 2, "parses 2 peers");
    ASSERT(strcmp(out[0].host, "host1.example.com") == 0, "first host");
    ASSERT(out[0].port == 9735, "first port");
    ASSERT(strcmp(out[1].host, "host2.example.com") == 0, "second host");
    ASSERT(out[1].port == 9736, "second port");

    /* Single peer */
    memset(out, 0, sizeof(out));
    n = gossip_peer_parse_list("127.0.0.1:1234", out, GOSSIP_PEER_MAX);
    ASSERT(n == 1, "parses single peer");
    ASSERT(out[0].port == 1234, "explicit port respected");

    /* Max cap */
    memset(out, 0, sizeof(out));
    n = gossip_peer_parse_list(
        "a:9735,b:9735,c:9735,d:9735,e:9735,f:9735,g:9735,h:9735,i:9735,j:9735",
        out, GOSSIP_PEER_MAX);
    ASSERT(n == GOSSIP_PEER_MAX, "capped at GOSSIP_PEER_MAX");

    /* Empty string */
    memset(out, 0, sizeof(out));
    n = gossip_peer_parse_list("", out, GOSSIP_PEER_MAX);
    ASSERT(n == 0, "empty list returns 0");

    return 1;
}

/* -----------------------------------------------------------------------
 * Commit 3 helpers: build + sign channel_announcement
 * ----------------------------------------------------------------------- */

/* Compute digest for channel_announcement signing:
 * SHA256(SHA256(msg[0..1] || msg[258..end])) */
static void ann_digest(const unsigned char *msg, size_t msg_len,
                       unsigned char digest[32]) {
    size_t tail_len = msg_len - 258;
    size_t buf_len  = 2 + tail_len;
    unsigned char *buf = (unsigned char *)malloc(buf_len);
    if (!buf) { memset(digest, 0, 32); return; }
    memcpy(buf, msg, 2);
    memcpy(buf + 2, msg + 258, tail_len);
    sha256_double(buf, buf_len, digest);
    free(buf);
}

/* Sign 32-byte digest with private key, write 64-byte sig at msg[offset]. */
static int sign_ann(secp256k1_context *ctx, unsigned char *msg, size_t offset,
                    const unsigned char *priv32, const unsigned char *digest32) {
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, priv32)) return 0;
    return secp256k1_schnorrsig_sign32(ctx, msg + offset, digest32, &kp, NULL);
}

/* Build a fully signed 4-sig channel_announcement.
 * Returns total message length, or 0 on error. */
static size_t build_signed_ann(secp256k1_context *ctx,
                                unsigned char *msg, size_t msg_cap,
                                const unsigned char *priv1,
                                const unsigned char *priv2,
                                const unsigned char *priv3,
                                const unsigned char *priv4,
                                uint64_t scid) {
    unsigned char pub1[33], pub2[33], pub3[33], pub4[33];
    size_t pub_len = 33;
    secp256k1_pubkey pk;

    if (!secp256k1_ec_pubkey_create(ctx, &pk, priv1)) return 0;
    secp256k1_ec_pubkey_serialize(ctx, pub1, &pub_len, &pk, SECP256K1_EC_COMPRESSED);
    if (!secp256k1_ec_pubkey_create(ctx, &pk, priv2)) return 0;
    secp256k1_ec_pubkey_serialize(ctx, pub2, &pub_len, &pk, SECP256K1_EC_COMPRESSED);
    if (!secp256k1_ec_pubkey_create(ctx, &pk, priv3)) return 0;
    secp256k1_ec_pubkey_serialize(ctx, pub3, &pub_len, &pk, SECP256K1_EC_COMPRESSED);
    if (!secp256k1_ec_pubkey_create(ctx, &pk, priv4)) return 0;
    secp256k1_ec_pubkey_serialize(ctx, pub4, &pub_len, &pk, SECP256K1_EC_COMPRESSED);

    size_t msg_len = gossip_build_channel_announcement_unsigned(
        msg, msg_cap, GOSSIP_CHAIN_HASH_MAINNET, scid,
        pub1, pub2, pub3, pub4);
    if (!msg_len) return 0;

    unsigned char digest[32];
    ann_digest(msg, msg_len, digest);

    if (!sign_ann(ctx, msg, 2,   priv1, digest)) return 0;
    if (!sign_ann(ctx, msg, 66,  priv2, digest)) return 0;
    if (!sign_ann(ctx, msg, 130, priv3, digest)) return 0;
    if (!sign_ann(ctx, msg, 194, priv4, digest)) return 0;

    return msg_len;
}

/* -----------------------------------------------------------------------
 * Commit 3: Stale channel pruning
 * ----------------------------------------------------------------------- */

int test_gossip_prune_stale_channel(void) {
    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open in-memory store");

    unsigned char n1[33], n2[33];
    memset(n1, 0x02, 33);  /* valid compressed pubkey prefix */
    memset(n2, 0x03, 33);
    uint64_t scid = 0x0001020304050607ULL;

    /* Insert channel + two stale updates at timestamp 0 */
    gossip_store_upsert_channel(&gs, scid, n1, n2, 100000, 0);
    gossip_store_upsert_channel_update(&gs, scid, 0, 1, 1, 40, 0);
    gossip_store_upsert_channel_update(&gs, scid, 1, 2, 2, 40, 0);

    /* Prune at t = GOSSIP_PRUNE_SECS + 1: updates are 14 days old → stale */
    uint32_t prune_time = GOSSIP_PRUNE_SECS + 1;
    int removed = gossip_store_prune_stale(&gs, prune_time);
    ASSERT(removed == 1, "one stale channel pruned");

    /* Channel entry should be gone */
    int found = gossip_store_get_channel(&gs, scid, NULL, NULL, NULL, NULL);
    ASSERT(found == 0, "stale channel removed from store");

    /* A fresh channel (updated 1 hour ago) must NOT be pruned */
    uint64_t scid2 = 0x0008090A0B0C0D0EULL;
    gossip_store_upsert_channel(&gs, scid2, n1, n2, 50000, prune_time - 3600);
    gossip_store_upsert_channel_update(&gs, scid2, 0, 100, 200, 40,
                                        prune_time - 3600);
    removed = gossip_store_prune_stale(&gs, prune_time);
    ASSERT(removed == 0, "fresh channel not pruned");

    gossip_store_close(&gs);
    return 1;
}

/* -----------------------------------------------------------------------
 * Commit 3: Rejection LRU cache
 * ----------------------------------------------------------------------- */

int test_gossip_rejection_cache(void) {
    gossip_reject_cache_t cache;
    memset(&cache, 0, sizeof(cache));

    /* Fill to capacity */
    for (int i = 0; i < GOSSIP_REJECT_CACHE_SIZE; i++) {
        gossip_reject_cache_add(&cache, (uint64_t)(i + 1));
    }
    ASSERT(cache.count == GOSSIP_REJECT_CACHE_SIZE, "cache filled to capacity");
    ASSERT(gossip_reject_cache_contains(&cache, 1), "entry 1 present");
    ASSERT(gossip_reject_cache_contains(&cache, GOSSIP_REJECT_CACHE_SIZE),
           "last entry present");

    /* Add 1025th entry — LRU (entry 1, added first) should be evicted */
    gossip_reject_cache_add(&cache, (uint64_t)(GOSSIP_REJECT_CACHE_SIZE + 1));
    ASSERT(gossip_reject_cache_contains(&cache, GOSSIP_REJECT_CACHE_SIZE + 1),
           "new entry present after LRU eviction");
    ASSERT(!gossip_reject_cache_contains(&cache, 1),
           "LRU entry (first inserted) evicted");

    /* Count must still be at capacity (no growth) */
    ASSERT(cache.count == GOSSIP_REJECT_CACHE_SIZE, "count stays at capacity");

    return 1;
}

/* -----------------------------------------------------------------------
 * Commit 3: 4-signature channel_announcement validation
 * ----------------------------------------------------------------------- */

int test_gossip_4sig_validation(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "secp256k1 context created");

    unsigned char priv1[32], priv2[32], priv3[32], priv4[32];
    memset(priv1, 1, 32);
    memset(priv2, 2, 32);
    memset(priv3, 3, 32);
    memset(priv4, 4, 32);

    unsigned char msg[512];
    size_t msg_len = build_signed_ann(ctx, msg, sizeof(msg),
                                      priv1, priv2, priv3, priv4,
                                      0xABCDEF0102030405ULL);
    ASSERT(msg_len >= 432, "built signed announcement");

    /* Valid: all 4 sigs correct */
    ASSERT(gossip_validate_channel_announcement(ctx, msg, msg_len) == 1,
           "valid 4-sig announcement passes");

    /* Tamper node_sig_1 (offset 2) */
    msg[2] ^= 0xFF;
    ASSERT(gossip_validate_channel_announcement(ctx, msg, msg_len) == 0,
           "tampered node_sig_1 fails");
    msg[2] ^= 0xFF;  /* restore */

    /* Tamper bitcoin_sig_1 (offset 130) */
    msg[130] ^= 0xFF;
    ASSERT(gossip_validate_channel_announcement(ctx, msg, msg_len) == 0,
           "tampered bitcoin_sig_1 fails");
    msg[130] ^= 0xFF;  /* restore */

    /* Too short: below minimum */
    ASSERT(gossip_validate_channel_announcement(ctx, msg, 431) == 0,
           "too-short message rejected");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * Commit 3: WaitingProofStore buffering + acceptance
 * ----------------------------------------------------------------------- */

int test_gossip_waiting_proof_buffer(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "secp256k1 context created");

    gossip_store_t gs;
    ASSERT(gossip_store_open_in_memory(&gs), "open in-memory store");

    gossip_waiting_proof_store_t store;
    memset(&store, 0, sizeof(store));

    unsigned char priv1[32], priv2[32], priv3[32], priv4[32];
    memset(priv1, 1, 32);
    memset(priv2, 2, 32);
    memset(priv3, 3, 32);
    memset(priv4, 4, 32);

    /* --- Test buffering: partial announcement (sig_2 zeroed out) --- */
    unsigned char partial[512];
    size_t partial_len = build_signed_ann(ctx, partial, sizeof(partial),
                                           priv1, priv2, priv3, priv4,
                                           0x0001020304050607ULL);
    ASSERT(partial_len > 0, "build partial base");
    /* Simulate "only node_sig_1 present": zero node_sig_2 at offset 66 */
    memset(partial + 66, 0, 64);

    int ret = gossip_waiting_proof_add(&store, &gs, ctx, partial, partial_len);
    ASSERT(ret == 2, "partial (sig1 only) returns 2 = buffered");

    /* --- Test acceptance: fully signed announcement (different scid) --- */
    unsigned char full[512];
    size_t full_len = build_signed_ann(ctx, full, sizeof(full),
                                        priv1, priv2, priv3, priv4,
                                        0x0008090A0B0C0D0EULL);
    ASSERT(full_len > 0, "build full signed announcement");

    ret = gossip_waiting_proof_add(&store, &gs, ctx, full, full_len);
    ASSERT(ret == 1, "full 4-sig announcement accepted");

    /* Verify channel was stored */
    int found = gossip_store_get_channel(&gs, 0x0008090A0B0C0D0EULL,
                                          NULL, NULL, NULL, NULL);
    ASSERT(found == 1, "accepted channel stored in gossip_store");

    gossip_store_close(&gs);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* -----------------------------------------------------------------------
 * Commit 4: Token-bucket rate limiting (10 burst, refill per 60s)
 * ----------------------------------------------------------------------- */

int test_gossip_rate_limit_token_bucket(void) {
    gossip_rate_table_t rt;
    memset(&rt, 0, sizeof(rt));

    uint64_t scid = 0x1234567890ABCDEFULL;
    uint32_t now  = 1800000000u;

    /* First GOSSIP_UPDATE_BURST updates must be allowed */
    for (int i = 0; i < GOSSIP_UPDATE_BURST; i++) {
        ASSERT(gossip_rate_allow_update(&rt, scid, 0, now) == 1,
               "burst update allowed");
    }

    /* (BURST+1)-th update must be blocked */
    ASSERT(gossip_rate_allow_update(&rt, scid, 0, now) == 0,
           "over-burst update blocked");

    return 1;
}

int test_gossip_rate_refill(void) {
    gossip_rate_table_t rt;
    memset(&rt, 0, sizeof(rt));

    uint64_t scid = 0xDEADBEEF00000001ULL;
    uint32_t now  = 1800000000u;

    /* Exhaust burst */
    for (int i = 0; i < GOSSIP_UPDATE_BURST; i++)
        gossip_rate_allow_update(&rt, scid, 0, now);
    ASSERT(gossip_rate_allow_update(&rt, scid, 0, now) == 0,
           "burst exhausted");

    /* After GOSSIP_UPDATE_REFILL_SECS seconds, tokens refilled */
    uint32_t later = now + GOSSIP_UPDATE_REFILL_SECS;
    ASSERT(gossip_rate_allow_update(&rt, scid, 0, later) == 1,
           "tokens refilled after refill interval");

    return 1;
}

/* -----------------------------------------------------------------------
 * Commit 4: 5-minute new-peer embargo constant
 * ----------------------------------------------------------------------- */

int test_gossip_peer_embargo(void) {
    /* The embargo constant must be 300s (5 min, Eclair production value) */
    ASSERT(GOSSIP_EMBARGO_SECS == 300, "embargo is 300s (5 min)");

    /* Sanity: embargo must be less than idle timeout (5min = 300s) */
    ASSERT(GOSSIP_EMBARGO_SECS <= BOLT8_IDLE_TIMEOUT_MS / 1000,
           "embargo fits within idle timeout window");

    return 1;
}
