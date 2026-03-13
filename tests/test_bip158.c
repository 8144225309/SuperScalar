#include "superscalar/bip158_backend.h"
#include "superscalar/persist.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/*
 * Unit tests for BIP 158 GCS filter decoder, SipHash-2-4, and script registry.
 *
 * Tests are self-contained — no network, no regtest node required.
 *
 * GCS round-trip uses a minimal hand-encoded filter with known content so we
 * can verify both the match and no-match paths without needing the encoder.
 */

/* -------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* -------------------------------------------------------------------------
 * Test 1: bip158_backend_init wires up the vtable and sets sensible defaults
 * ------------------------------------------------------------------------- */
int test_bip158_backend_init(void)
{
    bip158_backend_t b;
    int ok = bip158_backend_init(&b, "regtest");
    ASSERT(ok == 1, "init should succeed");
    ASSERT(b.base.get_block_height  != NULL, "get_block_height wired");
    ASSERT(b.base.get_confirmations != NULL, "get_confirmations wired");
    ASSERT(b.base.is_in_mempool     != NULL, "is_in_mempool wired");
    ASSERT(b.base.send_raw_tx       != NULL, "send_raw_tx wired");
    ASSERT(b.base.register_script   != NULL, "register_script wired");
    ASSERT(b.base.unregister_script != NULL, "unregister_script wired");
    ASSERT(b.tip_height == -1, "tip_height starts at -1 (unknown)");
    ASSERT(b.n_scripts  == 0,  "no scripts registered initially");
    bip158_backend_free(&b);
    return 1;
}

/* -------------------------------------------------------------------------
 * Test 2: script register / deduplicate / unregister
 * ------------------------------------------------------------------------- */
int test_bip158_script_registry(void)
{
    bip158_backend_t b;
    bip158_backend_init(&b, "regtest");

    unsigned char spk1[34] = {0x51, 0x20}; /* P2TR prefix, rest zeros */
    unsigned char spk2[34] = {0x51, 0x20, 0x01}; /* different */
    spk1[2] = 0xAA;

    /* Register two distinct scripts */
    ASSERT(b.base.register_script(&b.base, spk1, 34) == 1, "register spk1");
    ASSERT(b.base.register_script(&b.base, spk2, 34) == 1, "register spk2");
    ASSERT(b.n_scripts == 2, "two scripts registered");

    /* Registering the same script again should deduplicate */
    ASSERT(b.base.register_script(&b.base, spk1, 34) == 1, "re-register spk1 ok");
    ASSERT(b.n_scripts == 2, "dedup: still two scripts");

    /* Unregister one */
    ASSERT(b.base.unregister_script(&b.base, spk1, 34) == 1, "unregister spk1");
    ASSERT(b.n_scripts == 1, "one script remains");

    /* Unregistering non-existent returns 0 */
    ASSERT(b.base.unregister_script(&b.base, spk1, 34) == 0, "double-unregister returns 0");

    bip158_backend_free(&b);
    return 1;
}

/* -------------------------------------------------------------------------
 * Test 3: confirmed tx cache and get_confirmations
 * ------------------------------------------------------------------------- */
int test_bip158_tx_cache(void)
{
    bip158_backend_t b;
    bip158_backend_init(&b, "regtest");
    b.tip_height = 800000;

    /* Unknown txid returns -1 */
    const char *unknown = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    ASSERT(b.base.get_confirmations(&b.base, unknown) == -1, "unknown txid = -1");

    /* Cache a tx at height 799990 */
    unsigned char txid[32];
    memset(txid, 0xBB, 32);
    bip158_cache_tx(&b, txid, 799990);

    /* Convert to display-order hex (reversed) for get_confirmations.
       Write two chars per byte directly to avoid snprintf NUL-mid-string bug. */
    static const char hx[] = "0123456789abcdef";
    char txid_hex[65];
    for (int i = 0; i < 32; i++) {
        txid_hex[(31 - i) * 2]     = hx[(txid[i] >> 4) & 0xf];
        txid_hex[(31 - i) * 2 + 1] = hx[txid[i] & 0xf];
    }
    txid_hex[64] = '\0';

    int confs = b.base.get_confirmations(&b.base, txid_hex);
    /* tip=800000, height=799990 → confirmations = 800000 - 799990 + 1 = 11 */
    ASSERT(confs == 11, "confirmations = tip - height + 1");

    bip158_backend_free(&b);
    return 1;
}

/* -------------------------------------------------------------------------
 * Test 4: bip158_gcs_match_any — empty filter never matches
 * ------------------------------------------------------------------------- */
int test_bip158_gcs_empty_filter(void)
{
    bip158_script_t scripts[1];
    memset(scripts[0].spk, 0x51, 34);
    scripts[0].spk_len = 34;

    unsigned char key[16] = {0};

    /* n_items = 0 → function should return 0 immediately */
    int match = bip158_gcs_match_any(NULL, 0, 0, key, scripts, 1);
    ASSERT(match == 0, "empty filter has no matches");
    return 1;
}

/* -------------------------------------------------------------------------
 * Test 5: bip158_scan_filter handles the N varint header correctly.
 * A filter encoding N=0 (varint 0x00) with no GCS data should produce
 * no matches regardless of script registry contents.
 * ------------------------------------------------------------------------- */
int test_bip158_scan_filter_zero_items(void)
{
    bip158_backend_t b;
    bip158_backend_init(&b, "regtest");

    unsigned char spk[34] = {0x51, 0x20};
    b.base.register_script(&b.base, spk, 34);

    unsigned char key[16] = {0};
    unsigned char filter[1] = {0x00};  /* varint N=0 */
    int match = bip158_scan_filter(&b, filter, 1, key);
    ASSERT(match == 0, "N=0 filter has no matches");

    bip158_backend_free(&b);
    return 1;
}

/* -------------------------------------------------------------------------
 * Test 6: GCS match — hand-craft a minimal 1-element filter and verify
 * the target script matches while an unrelated script does not.
 *
 * Construction:
 *   N = 1, F = 1 * 784931 = 784931
 *   key = all zeros
 *   script = {0x51, 0x20, 0x01, 0x02, ...} (P2TR, 34 bytes)
 *
 *   hash(script) = (SipHash-2-4(key, script) * F) >> 64
 *
 *   GCS encodes [hash] as a single Golomb-Rice value:
 *     delta = hash (first element, previous value = 0)
 *     quotient = delta >> 19
 *     remainder = delta & 0x7ffff (19 bits)
 *     encode: q zeros + 1 one bit + 19-bit remainder, MSB-first
 *
 * We compute the expected hash at runtime using the same function,
 * then build the filter bytes and verify the round-trip.
 * ------------------------------------------------------------------------- */

/* Minimal GCS encoder for test purposes only */
typedef struct { unsigned char buf[64]; size_t bit_pos; } bit_writer_t;

static void write_bit(bit_writer_t *w, int bit) {
    size_t byte = w->bit_pos / 8;
    size_t off  = 7 - (w->bit_pos % 8);
    if (byte < sizeof(w->buf)) {
        if (bit) w->buf[byte] |= (1u << off);
        else     w->buf[byte] &= ~(1u << off);
    }
    w->bit_pos++;
}

static void write_golomb_rice(bit_writer_t *w, uint64_t value, int p) {
    uint64_t q   = value >> p;
    uint64_t rem = value & ((1u << p) - 1);
    /* BIP 158: unary quotient = q one-bits followed by a zero-bit */
    for (uint64_t i = 0; i < q; i++) write_bit(w, 1);
    write_bit(w, 0);
    for (int i = p - 1; i >= 0; i--) write_bit(w, (int)((rem >> i) & 1));
}

/* Exposed for test: the same hash function used internally */
extern uint64_t _bip158_test_hash(const unsigned char *key16,
                                   const unsigned char *spk, size_t spk_len,
                                   uint64_t F);

int test_bip158_gcs_round_trip(void)
{
    unsigned char key[16] = {0};  /* all-zero key */

    unsigned char target_spk[34], other_spk[34];
    memset(target_spk, 0, 34);
    memset(other_spk,  0, 34);
    target_spk[0] = 0x51; target_spk[1] = 0x20; target_spk[2] = 0xAB;
    other_spk[0]  = 0x51; other_spk[1]  = 0x20; other_spk[2]  = 0xCD;

    uint64_t N = 1;
    uint64_t F = N * BIP158_M;

    /* Compute the actual BIP 158 hash for target_spk */
    uint64_t target_hash = _bip158_test_hash(key, target_spk, 34, F);
    uint64_t other_hash  = _bip158_test_hash(key, other_spk,  34, F);
    ASSERT(target_hash != other_hash, "distinct scripts have distinct hashes");

    /* Build a 1-element GCS encoding target_hash */
    bit_writer_t bw;
    memset(&bw, 0, sizeof(bw));
    write_golomb_rice(&bw, target_hash, BIP158_P);
    size_t gcs_bytes = (bw.bit_pos + 7) / 8;

    unsigned char filter[66];
    filter[0] = 0x01;  /* varint N=1 */
    memcpy(filter + 1, bw.buf, gcs_bytes);

    /* target_spk must match */
    bip158_script_t scripts[1];
    memcpy(scripts[0].spk, target_spk, 34);
    scripts[0].spk_len = 34;
    ASSERT(bip158_gcs_match_any(filter + 1, gcs_bytes, N, key, scripts, 1) == 1,
           "target_spk matches filter containing its own hash");

    /* other_spk must not match (hash is different) */
    memcpy(scripts[0].spk, other_spk, 34);
    ASSERT(bip158_gcs_match_any(filter + 1, gcs_bytes, N, key, scripts, 1) == 0,
           "other_spk does not match filter containing target hash");

    /* delta=0 edge case: should not crash */
    bit_writer_t bw0;
    memset(&bw0, 0, sizeof(bw0));
    write_golomb_rice(&bw0, 0, BIP158_P);
    unsigned char filter0[66];
    filter0[0] = 0x01;
    memcpy(filter0 + 1, bw0.buf, (bw0.bit_pos + 7) / 8);
    bip158_gcs_match_any(filter0 + 1, (bw0.bit_pos + 7) / 8, N, key, scripts, 1);

    return 1;
}

/* -------------------------------------------------------------------------
 * Phase 4: BIP 158 checkpoint persistence round-trip
 * ------------------------------------------------------------------------- */

/* Test 7: persist_save_bip158_checkpoint / persist_load_bip158_checkpoint
 * Verifies that all three height integers and both ring buffer BLOBs survive
 * a save→load round-trip through an in-memory SQLite database.
 */
int test_bip158_checkpoint_round_trip(void)
{
    persist_t p;
    ASSERT(persist_open(&p, ":memory:"), "persist_open failed");

    /* Build distinguishable header and filter-header ring buffers */
    uint8_t hdr_in[BIP158_HEADER_WINDOW][32];
    uint8_t fhdr_in[BIP158_HEADER_WINDOW][32];
    for (int i = 0; i < BIP158_HEADER_WINDOW; i++) {
        memset(hdr_in[i],  (uint8_t)(i & 0xff),        32);
        memset(fhdr_in[i], (uint8_t)((i + 1) & 0xff),  32);
    }

    ASSERT(persist_save_bip158_checkpoint(&p,
        1234,   /* tip_height */
        2000,   /* headers_synced */
        1800,   /* filter_headers_synced */
        (const uint8_t *)hdr_in,  sizeof(hdr_in),
        (const uint8_t *)fhdr_in, sizeof(fhdr_in)),
        "save checkpoint failed");

    int32_t tip = 0, hdr = 0, fhdr = 0;
    uint8_t hdr_out[BIP158_HEADER_WINDOW][32];
    uint8_t fhdr_out[BIP158_HEADER_WINDOW][32];
    memset(hdr_out,  0, sizeof(hdr_out));
    memset(fhdr_out, 0, sizeof(fhdr_out));

    ASSERT(persist_load_bip158_checkpoint(&p,
        &tip, &hdr, &fhdr,
        (uint8_t *)hdr_out,  sizeof(hdr_out),
        (uint8_t *)fhdr_out, sizeof(fhdr_out)),
        "load checkpoint returned 0 (no row found)");

    ASSERT(tip  == 1234, "tip_height mismatch");
    ASSERT(hdr  == 2000, "headers_synced mismatch");
    ASSERT(fhdr == 1800, "filter_headers_synced mismatch");
    ASSERT(memcmp(hdr_out,  hdr_in,  sizeof(hdr_in))  == 0, "header_hashes blob mismatch");
    ASSERT(memcmp(fhdr_out, fhdr_in, sizeof(fhdr_in)) == 0, "filter_headers blob mismatch");

    persist_close(&p);
    return 1;
}

/* Test 8: bip158_backend_restore_checkpoint wires the DB values into the backend
 * Saves a checkpoint, then calls bip158_backend_restore_checkpoint() and
 * checks that tip_height and headers_synced are restored correctly.
 */
int test_bip158_backend_restore_checkpoint(void)
{
    persist_t p;
    ASSERT(persist_open(&p, ":memory:"), "persist_open failed");

    /* Write a checkpoint with known sentinel values (no ring buffers) */
    ASSERT(persist_save_bip158_checkpoint(&p,
        777, 999, 555, NULL, 0, NULL, 0),
        "save checkpoint failed");

    bip158_backend_t b;
    ASSERT(bip158_backend_init(&b, "mainnet"), "init failed");
    ASSERT(b.tip_height           == -1, "tip_height should start at -1");
    ASSERT(b.headers_synced       == -1, "headers_synced should start at -1");
    ASSERT(b.filter_headers_synced == -1, "filter_headers_synced should start at -1");

    bip158_backend_set_db(&b, &p);
    ASSERT(bip158_backend_restore_checkpoint(&b), "restore returned 0");

    ASSERT(b.tip_height            == 777, "tip_height not restored");
    ASSERT(b.headers_synced        == 999, "headers_synced not restored");
    ASSERT(b.filter_headers_synced == 555, "filter_headers_synced not restored");

    /* Load from empty DB returns 0 and leaves backend unchanged */
    persist_t p2;
    ASSERT(persist_open(&p2, ":memory:"), "persist_open p2 failed");
    bip158_backend_set_db(&b, &p2);
    ASSERT(!bip158_backend_restore_checkpoint(&b), "expected 0 on empty DB");
    ASSERT(b.tip_height == 777, "tip_height should not change on empty restore");

    bip158_backend_free(&b);
    persist_close(&p);
    persist_close(&p2);
    return 1;
}

/* -------------------------------------------------------------------------
 * Phase 6: Reconnect and peer rotation
 * ------------------------------------------------------------------------- */

/* Test 9: bip158_backend_add_peer populates the rotation list correctly */
int test_bip158_add_peer(void)
{
    bip158_backend_t b;
    ASSERT(bip158_backend_init(&b, "mainnet"), "init failed");

    ASSERT(b.n_peers == 0, "n_peers should be 0 after init");

    bip158_backend_add_peer(&b, "peer1.example.com", 8333);
    ASSERT(b.n_peers == 1, "n_peers should be 1 after first add");
    ASSERT(strcmp(b.peer_hosts[0], "peer1.example.com") == 0, "host[0] mismatch");
    ASSERT(b.peer_ports[0] == 8333, "port[0] mismatch");

    bip158_backend_add_peer(&b, "peer2.example.com", 18333);
    ASSERT(b.n_peers == 2, "n_peers should be 2");
    ASSERT(b.peer_ports[1] == 18333, "port[1] mismatch");

    /* Adding NULL host or port 0 should be ignored */
    bip158_backend_add_peer(&b, NULL, 8333);
    bip158_backend_add_peer(&b, "peer3.example.com", 0);
    ASSERT(b.n_peers == 2, "null/zero args should not add peers");

    /* Fill to max and verify overflow is ignored */
    for (int i = b.n_peers; i < BIP158_MAX_PEERS; i++)
        bip158_backend_add_peer(&b, "extra.example.com", 1000 + i);
    ASSERT(b.n_peers == BIP158_MAX_PEERS, "should have filled to max");
    bip158_backend_add_peer(&b, "overflow.example.com", 9999);
    ASSERT(b.n_peers == BIP158_MAX_PEERS, "overflow should be ignored");

    bip158_backend_free(&b);
    return 1;
}

/* Test 10: bip158_backend_reconnect returns 0 when all peers unavailable
 * (no real network sockets; this tests the failure path gracefully) */
int test_bip158_reconnect_no_peers(void)
{
    bip158_backend_t b;
    ASSERT(bip158_backend_init(&b, "regtest"), "init failed");

    /* No peers configured — reconnect should return 0 immediately */
    ASSERT(!bip158_backend_reconnect(&b), "expected 0 with no peers");

    /* Peer list configured but all point to unreachable addresses;
     * reconnect should return 0 rather than hang (ports 1-2 are reserved and
     * will be refused almost instantly, so this completes quickly). */
    bip158_backend_add_peer(&b, "127.0.0.1", 1);
    bip158_backend_add_peer(&b, "127.0.0.1", 2);
    b.current_peer = 0;

    int rc = bip158_backend_reconnect(&b);
    /* May succeed if those ports are bound locally, but failure is expected */
    (void)rc;  /* accept either result; main goal: no crash/hang */

    bip158_backend_free(&b);
    return 1;
}

/* -------------------------------------------------------------------------
 * Phase 7: Mempool callback API
 * ------------------------------------------------------------------------- */

/* Capture context for mempool callback */
typedef struct {
    char  txids[16][65];   /* display-order hex */
    int   count;
} mempool_capture_t;

static void mempool_capture_cb(const char *txid_hex, void *ctx)
{
    mempool_capture_t *mc = (mempool_capture_t *)ctx;
    if (mc->count < 16) {
        strncpy(mc->txids[mc->count], txid_hex, 64);
        mc->txids[mc->count][64] = '\0';
        mc->count++;
    }
}

/* Test 11: bip158_backend_set_mempool_cb wires the callback correctly;
 * bip158_backend_poll_mempool returns 0 without a real P2P connection */
int test_bip158_mempool_cb_wiring(void)
{
    bip158_backend_t b;
    ASSERT(bip158_backend_init(&b, "mainnet"), "init failed");

    ASSERT(b.mempool_cb  == NULL, "mempool_cb should start NULL");
    ASSERT(b.mempool_ctx == NULL, "mempool_ctx should start NULL");
    ASSERT(b.mempool_subscribed == 0, "mempool_subscribed should start 0");

    mempool_capture_t mc;
    mc.count = 0;
    bip158_backend_set_mempool_cb(&b, mempool_capture_cb, &mc);

    ASSERT(b.mempool_cb  == mempool_capture_cb, "mempool_cb not set");
    ASSERT(b.mempool_ctx == &mc, "mempool_ctx not set");

    /* Without a P2P connection, poll_mempool should return 0 immediately */
    ASSERT(b.p2p.fd == -1, "fd should be -1");
    int n = bip158_backend_poll_mempool(&b);
    ASSERT(n == 0, "expected 0 with no P2P connection");
    ASSERT(mc.count == 0, "no callbacks should fire without connection");

    /* Clear callback */
    bip158_backend_set_mempool_cb(&b, NULL, NULL);
    ASSERT(b.mempool_cb == NULL, "clearing callback failed");

    bip158_backend_free(&b);
    return 1;
}
