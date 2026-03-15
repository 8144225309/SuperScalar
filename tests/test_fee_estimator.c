#include "superscalar/fee_estimator.h"
#include "superscalar/wallet_source.h"
#include "superscalar/p2p_bitcoin.h"
#include "superscalar/sha256.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

/* write() return value is intentionally ignored in pipe-based tests */
#pragma GCC diagnostic ignored "-Wunused-result"

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* -----------------------------------------------------------------------
 * Test 1: fee_estimator_static_t — all targets return the same rate
 * --------------------------------------------------------------------- */
int test_fee_estimator_static_all_targets(void)
{
    fee_estimator_static_t fe;
    fee_estimator_static_init(&fe, 5000);

    ASSERT(fe.base.get_rate(&fe.base, FEE_TARGET_URGENT)  == 5000,
           "URGENT returns sat_per_kvb");
    ASSERT(fe.base.get_rate(&fe.base, FEE_TARGET_NORMAL)  == 5000,
           "NORMAL returns sat_per_kvb");
    ASSERT(fe.base.get_rate(&fe.base, FEE_TARGET_ECONOMY) == 5000,
           "ECONOMY returns sat_per_kvb");
    ASSERT(fe.base.get_rate(&fe.base, FEE_TARGET_MINIMUM) == 5000,
           "MINIMUM returns sat_per_kvb");

    /* update and free slots are NULL for static impl */
    ASSERT(fe.base.update == NULL, "update slot is NULL");
    ASSERT(fe.base.free   == NULL, "free slot is NULL");

    return 1;
}

/* -----------------------------------------------------------------------
 * Test 2: fee_estimator_t ordering via a simple mock implementation.
 *         A correct fee estimator must satisfy URGENT > NORMAL > ECONOMY.
 * --------------------------------------------------------------------- */

/* Mock: returns hard-coded tier rates */
static uint64_t mock_get_rate(fee_estimator_t *self, fee_target_t target)
{
    (void)self;
    switch (target) {
        case FEE_TARGET_URGENT:  return 30000;
        case FEE_TARGET_NORMAL:  return 10000;
        case FEE_TARGET_ECONOMY: return 3000;
        case FEE_TARGET_MINIMUM: return 1000;
        default:                 return 1000;
    }
}

int test_fee_estimator_target_ordering(void)
{
    fee_estimator_t mock = { .get_rate = mock_get_rate, .update = NULL, .free = NULL };

    uint64_t urgent  = mock.get_rate(&mock, FEE_TARGET_URGENT);
    uint64_t normal  = mock.get_rate(&mock, FEE_TARGET_NORMAL);
    uint64_t economy = mock.get_rate(&mock, FEE_TARGET_ECONOMY);
    uint64_t minimum = mock.get_rate(&mock, FEE_TARGET_MINIMUM);

    ASSERT(urgent  > normal,  "URGENT > NORMAL");
    ASSERT(normal  > economy, "NORMAL > ECONOMY");
    ASSERT(economy > minimum, "ECONOMY > MINIMUM");
    ASSERT(minimum >= 1000,   "MINIMUM >= 1000 sat/kvB floor");

    return 1;
}

/* -----------------------------------------------------------------------
 * Test 3: fee_estimator_blocks_t — no samples, floor only
 * --------------------------------------------------------------------- */
int test_fee_estimator_blocks_floor_only(void)
{
    fee_estimator_blocks_t fe;
    fee_estimator_blocks_init(&fe);

    /* Before any samples: everything returns the floor (default 1000) */
    ASSERT(fe.base.get_rate(&fe.base, FEE_TARGET_URGENT)  == 1000,
           "URGENT returns floor when no samples");
    ASSERT(fe.base.get_rate(&fe.base, FEE_TARGET_NORMAL)  == 1000,
           "NORMAL returns floor when no samples");
    ASSERT(fe.base.get_rate(&fe.base, FEE_TARGET_ECONOMY) == 1000,
           "ECONOMY returns floor when no samples");
    ASSERT(fe.base.get_rate(&fe.base, FEE_TARGET_MINIMUM) == 1000,
           "MINIMUM returns floor when no samples");

    /* After setting a higher floor, all targets reflect it */
    fee_estimator_blocks_set_floor(&fe, 5000);
    ASSERT(fe.base.get_rate(&fe.base, FEE_TARGET_MINIMUM) == 5000,
           "MINIMUM returns updated feefilter_floor");
    ASSERT(fe.base.get_rate(&fe.base, FEE_TARGET_NORMAL)  == 5000,
           "NORMAL returns updated feefilter_floor when no samples");

    return 1;
}

/* -----------------------------------------------------------------------
 * Test 4: fee_estimator_blocks_t — 6 known samples → target ordering
 * --------------------------------------------------------------------- */
int test_fee_estimator_blocks_target_ordering(void)
{
    fee_estimator_blocks_t fe;
    fee_estimator_blocks_init(&fe);

    /* Add 6 samples: 2000, 4000, 6000, 8000, 10000, 12000 sat/kvB */
    uint64_t samples[] = { 2000, 4000, 6000, 8000, 10000, 12000 };
    for (int i = 0; i < 6; i++)
        fee_estimator_blocks_add_sample(&fe, samples[i]);

    /* Set a floor below the lowest sample */
    fee_estimator_blocks_set_floor(&fe, 1000);

    uint64_t urgent  = fe.base.get_rate(&fe.base, FEE_TARGET_URGENT);
    uint64_t normal  = fe.base.get_rate(&fe.base, FEE_TARGET_NORMAL);
    uint64_t economy = fe.base.get_rate(&fe.base, FEE_TARGET_ECONOMY);
    uint64_t minimum = fe.base.get_rate(&fe.base, FEE_TARGET_MINIMUM);

    /* Sorted: 2000 4000 6000 8000 10000 12000
       median (n=6): sorted[3] = 8000
       25th pct:     sorted[1] = 4000
       urgent:       max(last 3) × 1.5 = max(8000,10000,12000) × 1.5 = 18000
       minimum:      floor = 1000 */
    ASSERT(urgent  == 18000, "URGENT = max(last 3) * 1.5 = 18000");
    ASSERT(normal  == 8000,  "NORMAL = median = 8000");
    ASSERT(economy == 4000,  "ECONOMY = 25th pct = 4000");
    ASSERT(minimum == 1000,  "MINIMUM = floor = 1000");

    ASSERT(urgent > normal,  "URGENT > NORMAL");
    ASSERT(normal > economy, "NORMAL > ECONOMY");
    ASSERT(economy > minimum,"ECONOMY > MINIMUM");

    return 1;
}

/* -----------------------------------------------------------------------
 * Test 5: feefilter P2P message parsing
 *         Build a mock handshake that includes a feefilter message, verify
 *         that p2p_do_version_handshake() stores the value in
 *         conn.peer_feefilter_sat_per_kvb.
 * --------------------------------------------------------------------- */

static const uint8_t REGTEST_MAGIC_FEE[4] = {0xFA, 0xBF, 0xB5, 0xDA};
static const uint64_t NODE_CF_BIT = (1ULL << 6);

static size_t build_p2p_msg(const uint8_t magic[4],
                             const char *command,
                             const uint8_t *payload, uint32_t plen,
                             uint8_t *out, size_t out_max)
{
    if (24 + plen > out_max) return 0;
    memcpy(out, magic, 4);
    memset(out + 4, 0, 12);
    strncpy((char *)(out + 4), command, 12);
    out[16] = (uint8_t)plen;
    out[17] = (uint8_t)(plen >> 8);
    out[18] = (uint8_t)(plen >> 16);
    out[19] = (uint8_t)(plen >> 24);
    if (plen == 0) {
        static const uint8_t cksum_empty[4] = {0x5d, 0xf6, 0xe0, 0xe2};
        memcpy(out + 20, cksum_empty, 4);
    } else {
        uint8_t h[32];
        sha256_double(payload, plen, h);
        memcpy(out + 20, h, 4);
        memcpy(out + 24, payload, plen);
    }
    return 24 + plen;
}

static void write_mock_version_cf(int fd)
{
    uint8_t payload[86];
    memset(payload, 0, sizeof(payload));
    /* version = 70016 LE */
    payload[0] = 0x80; payload[1] = 0x11; payload[2] = 0x01; payload[3] = 0x00;
    /* services = NODE_COMPACT_FILTERS (bit 6) */
    uint64_t svc = NODE_CF_BIT;
    for (int i = 0; i < 8; i++)
        payload[4 + i] = (uint8_t)(svc >> (i * 8));
    /* ua_len = 0, start_height = 0 */

    uint8_t msg[256];
    size_t n = build_p2p_msg(REGTEST_MAGIC_FEE, "version",
                              payload, (uint32_t)sizeof(payload),
                              msg, sizeof(msg));
    (void)write(fd, msg, n);
}

static void write_mock_verack_ff(int fd)
{
    uint8_t msg[256];
    size_t n = build_p2p_msg(REGTEST_MAGIC_FEE, "verack", NULL, 0, msg, sizeof(msg));
    (void)write(fd, msg, n);
}

static void write_mock_feefilter(int fd, uint64_t sat_per_kvb)
{
    uint8_t payload[8];
    for (int i = 0; i < 8; i++)
        payload[i] = (uint8_t)(sat_per_kvb >> (i * 8));
    uint8_t msg[256];
    size_t n = build_p2p_msg(REGTEST_MAGIC_FEE, "feefilter",
                              payload, 8, msg, sizeof(msg));
    (void)write(fd, msg, n);
}

int test_feefilter_p2p_parse(void)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return 2; /* SKIP */

    /* Peer sends: version, feefilter(3000 sat/kvB), verack */
    write_mock_version_cf(sv[1]);
    write_mock_feefilter(sv[1], 3000);
    write_mock_verack_ff(sv[1]);

    p2p_conn_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.fd = sv[0];
    memcpy(conn.magic, REGTEST_MAGIC_FEE, 4);

    int ok = p2p_do_version_handshake(&conn);

    if (conn.fd >= 0) close(conn.fd);
    close(sv[1]);

    ASSERT(ok == 1, "handshake with feefilter should succeed");
    ASSERT(conn.peer_feefilter_sat_per_kvb == 3000,
           "peer_feefilter_sat_per_kvb == 3000");

    return 1;
}

/* -----------------------------------------------------------------------
 * Test 6: fee_estimator_api_t — mock http_get returns canned JSON,
 *         verify per-target rates are parsed correctly.
 * --------------------------------------------------------------------- */

static const char *g_mock_json =
    "{\"fastestFee\":20,\"halfHourFee\":10,\"hourFee\":6,"
    "\"economyFee\":3,\"minimumFee\":1}";

static char *mock_http_get(const char *url, void *ctx)
{
    (void)url; (void)ctx;
    return strdup(g_mock_json);
}

int test_fee_estimator_api_parse(void)
{
    fee_estimator_api_t fe;
    fee_estimator_api_init(&fe, "http://mock.invalid/fees", mock_http_get, NULL);

    /* First call fetches via mock_http_get */
    uint64_t urgent  = fe.base.get_rate(&fe.base, FEE_TARGET_URGENT);
    uint64_t normal  = fe.base.get_rate(&fe.base, FEE_TARGET_NORMAL);
    uint64_t economy = fe.base.get_rate(&fe.base, FEE_TARGET_ECONOMY);
    uint64_t minimum = fe.base.get_rate(&fe.base, FEE_TARGET_MINIMUM);

    /* fastestFee=20 → 20*1000 = 20000 sat/kvB */
    ASSERT(urgent  == 20000, "URGENT = fastestFee * 1000 = 20000");
    /* halfHourFee=10 → 10000 */
    ASSERT(normal  == 10000, "NORMAL = halfHourFee * 1000 = 10000");
    /* economyFee=3 → 3000 */
    ASSERT(economy == 3000,  "ECONOMY = economyFee * 1000 = 3000");
    /* minimumFee=1 → 1000 */
    ASSERT(minimum == 1000,  "MINIMUM = minimumFee * 1000 = 1000");

    return 1;
}

/* -----------------------------------------------------------------------
 * Test 7: fee_estimator_api_t — cache hit within TTL; re-fetch after TTL.
 * --------------------------------------------------------------------- */

static int g_fetch_count = 0;

static char *counting_http_get(const char *url, void *ctx)
{
    (void)url; (void)ctx;
    g_fetch_count++;
    return strdup("{\"fastestFee\":5,\"halfHourFee\":5,"
                  "\"economyFee\":5,\"minimumFee\":1}");
}

int test_fee_estimator_api_ttl(void)
{
    g_fetch_count = 0;

    fee_estimator_api_t fe;
    fee_estimator_api_init(&fe, "http://mock.invalid/fees", counting_http_get, NULL);

    /* First get_rate should trigger a fetch */
    fe.base.get_rate(&fe.base, FEE_TARGET_NORMAL);
    ASSERT(g_fetch_count == 1, "first get_rate triggers fetch");

    /* Second get_rate within TTL should use cache */
    fe.base.get_rate(&fe.base, FEE_TARGET_NORMAL);
    ASSERT(g_fetch_count == 1, "second get_rate within TTL uses cache");

    /* Force TTL expiry by winding back last_updated */
    fe.last_updated = 0;
    fe.base.get_rate(&fe.base, FEE_TARGET_NORMAL);
    ASSERT(g_fetch_count == 2, "get_rate after TTL expiry triggers re-fetch");

    return 1;
}

/* -----------------------------------------------------------------------
 * Test 8: wallet_source_rpc_t stub — verify vtable slots are wired.
 *         (No real regtest_t; we just verify the struct is properly
 *          initialised by wallet_source_rpc_init.)
 * --------------------------------------------------------------------- */
int test_wallet_source_stub(void)
{
    wallet_source_rpc_t ws;
    wallet_source_rpc_init(&ws, NULL);  /* rt = NULL — no real RPC calls */

    ASSERT(ws.base.get_utxo       != NULL, "get_utxo slot wired");
    ASSERT(ws.base.get_change_spk != NULL, "get_change_spk slot wired");
    ASSERT(ws.base.sign_input     != NULL, "sign_input slot wired");
    ASSERT(ws.base.free           == NULL, "free slot is NULL (no heap)");
    ASSERT(ws.rt                  == NULL, "rt is NULL as passed");

    return 1;
}

/* -----------------------------------------------------------------------
 * Test 9: ss_config_default fills expected fields.
 * --------------------------------------------------------------------- */
#include "superscalar/superscalar_sdk.h"

int test_ss_config_default(void)
{
    ss_config_t cfg;
    ss_config_default(&cfg, "regtest");

    ASSERT(cfg.network            != NULL,       "network set");
    ASSERT(strcmp(cfg.network, "regtest") == 0,  "network = regtest");
    ASSERT(cfg.chain_mode         == SS_CHAIN_RPC,  "chain_mode default = RPC");
    ASSERT(cfg.fee_mode           == SS_FEE_RPC,    "fee_mode default = RPC");
    ASSERT(cfg.wallet_mode        == SS_WALLET_RPC, "wallet_mode default = RPC");
    ASSERT(cfg.fee_static_sat_per_kvb == 1000,   "default static rate = 1000");
    ASSERT(cfg.cli_path           != NULL,       "cli_path set");
    ASSERT(cfg.db_path            == NULL,       "db_path default = NULL");

    return 1;
}
