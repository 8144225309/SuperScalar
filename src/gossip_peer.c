/*
 * gossip_peer.c — Outbound gossip peer connection + management
 *
 * Implements TCP→BOLT#8→init→timestamp_filter→recv→store pipeline with
 * exponential reconnect backoff (CLN values), two-tier timestamp strategy
 * (LDK values).
 *
 * Extended by PR #19 commits 3/4:
 *   Commit 3: rejection LRU cache, WaitingProofStore (4-sig validated),
 *             stale pruning integration
 *   Commit 4: per-channel token-bucket rate limiting, 5-min embargo,
 *             peer prioritization
 */

#include "superscalar/gossip_peer.h"
#include "superscalar/gossip.h"
#include "superscalar/gossip_store.h"
#include "superscalar/bolt8.h"
#include "superscalar/bolt8_server.h"
#include "superscalar/wire.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>

/* -----------------------------------------------------------------------
 * Timestamp filter strategy
 * --------------------------------------------------------------------- */

uint32_t gossip_timestamp_for_peer(int peer_index, uint32_t now_unix) {
    if (peer_index < GOSSIP_BOOTSTRAP_PEER_COUNT) {
        /* Bootstrap peers: 2 weeks of history (LDK) */
        return (now_unix > 1209600u) ? now_unix - 1209600u : 0;
    }
    /* Subsequent peers: 1 hour window (bandwidth saving) */
    return (now_unix > 3600u) ? now_unix - 3600u : 0;
}

/* -----------------------------------------------------------------------
 * Reconnect backoff
 * --------------------------------------------------------------------- */

int gossip_next_backoff_ms(int current_ms) {
    int next = current_ms * 2;
    if (next > GOSSIP_RECONNECT_MAX_MS)
        next = GOSSIP_RECONNECT_MAX_MS;
    /* ±500ms jitter to prevent thundering-herd reconnects */
    int jitter = (int)((unsigned)rand() % 1001u) - 500;
    next += jitter;
    if (next < 0) next = 0;
    return next;
}

/* -----------------------------------------------------------------------
 * Rejection LRU cache
 * --------------------------------------------------------------------- */

int gossip_reject_cache_contains(gossip_reject_cache_t *c, uint64_t scid) {
    if (!c) return 0;
    for (int i = 0; i < c->count; i++) {
        if (c->entries[i].scid == scid)
            return 1;
    }
    return 0;
}

void gossip_reject_cache_add(gossip_reject_cache_t *c, uint64_t scid) {
    if (!c) return;

    /* If already present, update clock */
    for (int i = 0; i < c->count; i++) {
        if (c->entries[i].scid == scid) {
            c->entries[i].evict_clock = ++c->clock;
            return;
        }
    }

    if (c->count < GOSSIP_REJECT_CACHE_SIZE) {
        c->entries[c->count].scid = scid;
        c->entries[c->count].evict_clock = ++c->clock;
        c->count++;
    } else {
        /* Evict LRU (lowest evict_clock) */
        int lru = 0;
        for (int i = 1; i < GOSSIP_REJECT_CACHE_SIZE; i++) {
            if (c->entries[i].evict_clock < c->entries[lru].evict_clock)
                lru = i;
        }
        c->entries[lru].scid = scid;
        c->entries[lru].evict_clock = ++c->clock;
    }
}

/* -----------------------------------------------------------------------
 * WaitingProofStore — buffers channel_announcement until both node sigs
 * present, then validates all 4 Schnorr sigs before accepting.
 * --------------------------------------------------------------------- */

static int sig_present(const unsigned char *msg, size_t msg_len, size_t offset) {
    if (msg_len < offset + 64) return 0;
    for (int i = 0; i < 64; i++) {
        if (msg[offset + i]) return 1;
    }
    return 0;
}

static uint64_t ann_extract_scid(const unsigned char *ann, size_t ann_len) {
    if (ann_len < 260) return 0;
    uint16_t flen = ((uint16_t)ann[258] << 8) | ann[259];
    size_t scid_off = 260 + flen + 32;
    if (ann_len < scid_off + 8) return 0;
    uint64_t scid = 0;
    for (int i = 0; i < 8; i++)
        scid = (scid << 8) | ann[scid_off + i];
    return scid;
}

int gossip_waiting_proof_add(gossip_waiting_proof_store_t *s,
                              gossip_store_t *gs,
                              secp256k1_context *ctx,
                              const unsigned char *ann, size_t ann_len) {
    if (!s || !ann || ann_len < 260) return 0;

    uint64_t scid = ann_extract_scid(ann, ann_len);
    if (!scid) return 0;

    int has_n1 = sig_present(ann, ann_len, 2);
    int has_n2 = sig_present(ann, ann_len, 66);

    gossip_waiting_proof_t *entry = NULL;
    for (int i = 0; i < s->count; i++) {
        if (s->entries[i].scid == scid) {
            entry = &s->entries[i];
            break;
        }
    }

    if (!entry) {
        if (s->count >= GOSSIP_WAITING_PROOF_MAX) return 0;
        entry = &s->entries[s->count++];
        memset(entry, 0, sizeof(*entry));
        entry->scid = scid;
        entry->received_at = (uint32_t)time(NULL);
    }

    if (ann_len <= sizeof(entry->ann)) {
        if (!entry->has_node1_sig && has_n1) {
            memcpy(entry->ann, ann, ann_len);
            entry->ann_len = ann_len;
            entry->has_node1_sig = 1;
        }
        if (!entry->has_node2_sig && has_n2) {
            if (entry->ann_len == ann_len)
                memcpy(entry->ann + 66, ann + 66, 64);
            else {
                memcpy(entry->ann, ann, ann_len);
                entry->ann_len = ann_len;
            }
            entry->has_node2_sig = 1;
        }
    }

    if (entry->has_node1_sig && entry->has_node2_sig && entry->ann_len >= 260) {
        /* 4-signature validation (Commit 3): reject if any Schnorr sig fails */
        if (!gossip_validate_channel_announcement(ctx, entry->ann, entry->ann_len))
            return 0;
        uint16_t flen = ((uint16_t)entry->ann[258] << 8) | entry->ann[259];
        size_t n1_off = 260 + flen + 32 + 8;
        if (entry->ann_len < n1_off + 33 + 33) return 0;

        const unsigned char *n1 = entry->ann + n1_off;
        const unsigned char *n2 = entry->ann + n1_off + 33;

        gossip_store_upsert_channel(gs, scid, n1, n2, 0, (uint32_t)time(NULL));
        return 1;
    }

    return 2; /* buffered */
}

/* -----------------------------------------------------------------------
 * Rate limiting
 * --------------------------------------------------------------------- */

int gossip_rate_allow_update(gossip_rate_table_t *rt,
                              uint64_t scid, int direction, uint32_t now_unix) {
    if (!rt) return 0;

    gossip_rate_entry_t *entry = NULL;
    for (int i = 0; i < rt->count; i++) {
        if (rt->entries[i].scid == scid && rt->entries[i].direction == direction) {
            entry = &rt->entries[i];
            break;
        }
    }

    if (!entry) {
        if (rt->count >= GOSSIP_RATE_TABLE_SIZE) return 1;  /* table full: allow */
        entry = &rt->entries[rt->count++];
        entry->scid = scid;
        entry->direction = direction;
        entry->tokens = GOSSIP_UPDATE_BURST;
        entry->last_refill_unix = now_unix;
    }

    uint32_t elapsed = now_unix - entry->last_refill_unix;
    if (elapsed >= (uint32_t)GOSSIP_UPDATE_REFILL_SECS) {
        entry->tokens = GOSSIP_UPDATE_BURST;
        entry->last_refill_unix = now_unix;
    }

    if (entry->tokens <= 0) return 0;

    entry->tokens--;
    return 1;
}

/* -----------------------------------------------------------------------
 * Peer priority
 * --------------------------------------------------------------------- */

int gossip_peer_is_important(const gossip_peer_mgr_cfg_t *cfg, int peer_index) {
    if (!cfg || peer_index < 0 || peer_index >= cfg->n_peers) return 0;
    return cfg->peers[peer_index].important;
}

/* -----------------------------------------------------------------------
 * Peer parse
 * --------------------------------------------------------------------- */

int gossip_peer_parse_list(const char *list, gossip_peer_cfg_t *out, int max) {
    if (!list || !out || max <= 0) return 0;

    int count = 0;
    char buf[2048];
    strncpy(buf, list, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *saveptr = NULL;
    char *tok = strtok_r(buf, ",", &saveptr);
    while (tok && count < max) {
        while (*tok == ' ') tok++;

        char *colon = strrchr(tok, ':');
        if (!colon) { tok = strtok_r(NULL, ",", &saveptr); continue; }

        size_t hlen = (size_t)(colon - tok);
        if (hlen == 0 || hlen >= sizeof(out[count].host)) {
            tok = strtok_r(NULL, ",", &saveptr);
            continue;
        }

        memcpy(out[count].host, tok, hlen);
        out[count].host[hlen] = '\0';
        out[count].port = (uint16_t)atoi(colon + 1);
        if (out[count].port == 0) out[count].port = 9735;
        memset(out[count].their_pub33, 0, 33);
        out[count].important = 0;
        count++;

        tok = strtok_r(NULL, ",", &saveptr);
    }
    return count;
}

/* -----------------------------------------------------------------------
 * Per-peer connection loop
 * --------------------------------------------------------------------- */

typedef struct {
    gossip_peer_mgr_cfg_t *cfg;
    int peer_index;
} peer_thread_arg_t;

int gossip_peer_run_once(const gossip_peer_cfg_t *peer,
                          const gossip_peer_mgr_cfg_t *cfg,
                          int peer_index) {
    if (!peer || !cfg || !cfg->store) return 0;

    int fd = wire_connect_direct_internal(peer->host, peer->port);
    if (fd < 0) return 0;

    unsigned char zero33[33] = {0};
    if (memcmp(peer->their_pub33, zero33, 33) == 0) {
        /* Plain TCP: no encrypted session */
        close(fd);
        return 0;
    }

    bolt8_state_t state;
    if (!bolt8_connect(fd, cfg->ctx, cfg->our_priv32, peer->their_pub33,
                       BOLT8_HANDSHAKE_TIMEOUT_MS, &state)) {
        close(fd);
        return 0;
    }

    if (!bolt8_init_exchange(&state, fd)) {
        close(fd);
        return 0;
    }

    uint32_t now = (uint32_t)time(NULL);
    uint32_t first_ts = gossip_timestamp_for_peer(peer_index, now);

    const unsigned char *chain_hash = GOSSIP_CHAIN_HASH_MAINNET;
    if (cfg->network) {
        if (strcmp(cfg->network, "signet") == 0)
            chain_hash = GOSSIP_CHAIN_HASH_SIGNET;
        else if (strcmp(cfg->network, "testnet") == 0)
            chain_hash = GOSSIP_CHAIN_HASH_TESTNET;
    }

    unsigned char filter_buf[50];
    size_t filter_len = gossip_build_timestamp_filter(filter_buf, sizeof(filter_buf),
                                                       chain_hash, first_ts, 0xFFFFFFFFu);
    if (filter_len > 0)
        bolt8_send(&state, fd, filter_buf, filter_len);

    gossip_reject_cache_t  reject_cache;
    gossip_waiting_proof_store_t waiting;
    gossip_rate_table_t    rate;
    memset(&reject_cache, 0, sizeof(reject_cache));
    memset(&waiting,      0, sizeof(waiting));
    memset(&rate,         0, sizeof(rate));

    /* 5-minute new-peer embargo */
    uint32_t embargo_until = now + GOSSIP_EMBARGO_SECS;

    struct timeval tv;
    tv.tv_sec  = (BOLT8_PING_INTERVAL_MS + BOLT8_PING_TIMEOUT_MS) / 1000;
    tv.tv_usec = ((BOLT8_PING_INTERVAL_MS + BOLT8_PING_TIMEOUT_MS) % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    unsigned char *msg_buf = (unsigned char *)malloc(65536);
    if (!msg_buf) { close(fd); return 0; }

    while (!(*cfg->shutdown_flag)) {
        size_t msg_len = 0;
        if (!bolt8_recv(&state, fd, msg_buf, &msg_len, 65536))
            break;
        if (msg_len < 2)
            continue;

        uint16_t wire_type = ((uint16_t)msg_buf[0] << 8) | msg_buf[1];
        uint32_t recv_now  = (uint32_t)time(NULL);
        int embargoing = (recv_now < embargo_until);

        switch (wire_type) {
        case GOSSIP_MSG_NODE_ANNOUNCEMENT:  /* 257 */
            if (!embargoing) {
                /* Verify and store node announcement */
                if (gossip_verify_node_announcement(cfg->ctx, msg_buf, msg_len)) {
                    /* Extract alias and address for storage (simplified) */
                    unsigned char zero_pub[33] = {0};
                    gossip_store_upsert_node(cfg->store, zero_pub, NULL, NULL,
                                              recv_now);
                }
            }
            break;

        case GOSSIP_MSG_CHANNEL_UPDATE: {  /* 258 */
            if (msg_len < 114) break;
            uint64_t scid = 0;
            for (int i = 0; i < 8; i++)
                scid = (scid << 8) | msg_buf[2 + 64 + 32 + i];
            int direction = (msg_buf[2 + 64 + 32 + 8 + 4 + 1] & 0x01);
            if (!embargoing && !gossip_reject_cache_contains(&reject_cache, scid)) {
                if (gossip_rate_allow_update(&rate, scid, direction, recv_now)) {
                    /* Parse fee_base, fee_ppm, cltv_delta, timestamp */
                    uint32_t ts = ((uint32_t)msg_buf[2+64+32+8] << 24) |
                                  ((uint32_t)msg_buf[2+64+32+9] << 16) |
                                  ((uint32_t)msg_buf[2+64+32+10] << 8) |
                                             msg_buf[2+64+32+11];
                    uint16_t cltv = ((uint16_t)msg_buf[2+64+32+8+4+2] << 8) |
                                               msg_buf[2+64+32+8+4+3];
                    if (msg_len >= 2+64+32+8+4+2+2+8+4+4) {
                        uint32_t fee_base = ((uint32_t)msg_buf[2+64+32+8+4+2+2+8] << 24) |
                                            ((uint32_t)msg_buf[2+64+32+8+4+2+2+9] << 16) |
                                            ((uint32_t)msg_buf[2+64+32+8+4+2+2+10] << 8) |
                                                       msg_buf[2+64+32+8+4+2+2+11];
                        uint32_t fee_ppm = ((uint32_t)msg_buf[2+64+32+8+4+2+2+12] << 24) |
                                           ((uint32_t)msg_buf[2+64+32+8+4+2+2+13] << 16) |
                                           ((uint32_t)msg_buf[2+64+32+8+4+2+2+14] << 8) |
                                                      msg_buf[2+64+32+8+4+2+2+15];
                        gossip_store_upsert_channel_update(cfg->store, scid, direction,
                                                            fee_base, fee_ppm, cltv, ts);
                    }
                }
            }
            break;
        }

        case GOSSIP_MSG_CHANNEL_ANNOUNCEMENT:  /* 256 */
            if (!embargoing) {
                gossip_waiting_proof_add(&waiting, cfg->store, cfg->ctx,
                                          msg_buf, msg_len);
            }
            break;

        case GOSSIP_MSG_TIMESTAMP_FILTER:  /* 265 */
            break;

        default:
            break;
        }
    }

    free(msg_buf);
    close(fd);
    return 1;
}

/* -----------------------------------------------------------------------
 * Thread: reconnect with backoff
 * --------------------------------------------------------------------- */

void *gossip_peer_thread(void *arg) {
    peer_thread_arg_t *parg = (peer_thread_arg_t *)arg;
    gossip_peer_mgr_cfg_t *cfg = parg->cfg;
    int idx = parg->peer_index;
    free(parg);

    int backoff_ms = GOSSIP_RECONNECT_INIT_MS;
    int retries = 0;

    while (!(*cfg->shutdown_flag)) {
        gossip_peer_run_once(&cfg->peers[idx], cfg, idx);

        if (*cfg->shutdown_flag) break;

        if (!gossip_peer_is_important(cfg, idx)) {
            retries++;
            if (retries >= GOSSIP_TRANSIENT_MAX_RETRIES) break;
        }

        int slept = 0;
        while (slept < backoff_ms && !(*cfg->shutdown_flag)) {
            usleep(10000);
            slept += 10;
        }

        backoff_ms = gossip_next_backoff_ms(backoff_ms);
    }

    return NULL;
}

/* -----------------------------------------------------------------------
 * Manager start
 * --------------------------------------------------------------------- */

int gossip_peer_mgr_start(gossip_peer_mgr_cfg_t *cfg, pthread_t *tids_out) {
    if (!cfg || !tids_out || cfg->n_peers <= 0) return 0;

    int started = 0;
    for (int i = 0; i < cfg->n_peers && i < GOSSIP_PEER_MAX; i++) {
        peer_thread_arg_t *arg = (peer_thread_arg_t *)malloc(sizeof(*arg));
        if (!arg) continue;
        arg->cfg = cfg;
        arg->peer_index = i;
        if (pthread_create(&tids_out[i], NULL, gossip_peer_thread, arg) == 0)
            started++;
        else
            free(arg);
    }
    return started;
}