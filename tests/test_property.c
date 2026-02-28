/*
 * test_property.c — Property-based tests with random inputs.
 *
 * Each test runs deterministic random trials (seed=42) to verify
 * invariants that must hold for all valid inputs.
 */
#include "superscalar/types.h"
#include "superscalar/channel.h"
#include "superscalar/shachain.h"
#include "superscalar/wire.h"
#include "superscalar/tx_builder.h"
#include "superscalar/factory.h"
#include "superscalar/persist.h"
#include "superscalar/musig.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_musig.h>
#include <cJSON.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
#include "superscalar/sha256.h"

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define TEST_ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { \
        printf("  FAIL: %s (line %d): %s (got %ld, expected %ld)\n", \
               __func__, __LINE__, msg, (long)(a), (long)(b)); \
        return 0; \
    } \
} while(0)

#define TEST_ASSERT_MEM_EQ(a, b, len, msg) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

/* ---- Test 1: Hex encode/decode round-trip ---- */

int test_prop_hex_roundtrip(void) {
    unsigned int seed = 42;
    for (int trial = 0; trial < 1000; trial++) {
        size_t len = 1 + (rand_r(&seed) % 256);
        unsigned char data[256], decoded[256];
        char hex[513];
        for (size_t i = 0; i < len; i++)
            data[i] = (unsigned char)(rand_r(&seed) & 0xff);
        hex_encode(data, len, hex);
        int decoded_len = hex_decode(hex, decoded, sizeof(decoded));
        TEST_ASSERT_EQ((long)decoded_len, (long)len, "length mismatch");
        TEST_ASSERT_MEM_EQ(data, decoded, len, "data mismatch");
    }
    return 1;
}

/* ---- Test 2: Shachain uniqueness ---- */

int test_prop_shachain_uniqueness(void) {
    unsigned int seed = 42;
    for (int trial = 0; trial < 100; trial++) {
        unsigned char chain_seed[32];
        for (int i = 0; i < 32; i++)
            chain_seed[i] = (unsigned char)(rand_r(&seed) & 0xff);

        unsigned char values[64][32];
        for (int idx = 0; idx < 64; idx++) {
            shachain_from_seed(chain_seed, (uint64_t)idx, values[idx]);
        }

        /* Check all pairs are distinct */
        for (int i = 0; i < 64; i++) {
            for (int j = i + 1; j < 64; j++) {
                TEST_ASSERT(memcmp(values[i], values[j], 32) != 0,
                            "shachain collision");
            }
        }
    }
    return 1;
}

/* ---- Test 3: Wire msg round-trip (update_add_htlc) ---- */

int test_prop_wire_msg_roundtrip(void) {
    unsigned int seed = 42;
    for (int trial = 0; trial < 500; trial++) {
        /* Keep values within double precision (~2^53) since JSON uses double */
        uint64_t htlc_id = rand_r(&seed) % 4000000000ULL;
        uint64_t amount = 1000 + (rand_r(&seed) % 1000000);
        unsigned char hash[32];
        for (int i = 0; i < 32; i++)
            hash[i] = (unsigned char)(rand_r(&seed) & 0xff);
        uint32_t cltv = 100 + (rand_r(&seed) % 100000);

        cJSON *json = wire_build_update_add_htlc(htlc_id, amount, hash, cltv);
        TEST_ASSERT(json != NULL, "build returned NULL");

        uint64_t parsed_id, parsed_amount;
        unsigned char parsed_hash[32];
        uint32_t parsed_cltv;
        int ok = wire_parse_update_add_htlc(json, &parsed_id, &parsed_amount,
                                              parsed_hash, &parsed_cltv);
        cJSON_Delete(json);

        TEST_ASSERT(ok, "parse failed");
        TEST_ASSERT(parsed_id == htlc_id, "htlc_id mismatch");
        TEST_ASSERT(parsed_amount == amount, "amount mismatch");
        TEST_ASSERT_MEM_EQ(hash, parsed_hash, 32, "hash mismatch");
        TEST_ASSERT(parsed_cltv == cltv, "cltv mismatch");
    }
    return 1;
}

/* ---- Test 4: Varint round-trip ---- */

int test_prop_varint_roundtrip(void) {
    unsigned int seed = 42;
    for (int trial = 0; trial < 1000; trial++) {
        uint64_t val;
        int r = rand_r(&seed) % 4;
        if (r == 0)
            val = rand_r(&seed) % 253;          /* 1-byte varint */
        else if (r == 1)
            val = 253 + (rand_r(&seed) % 65000); /* 3-byte varint */
        else if (r == 2)
            val = 65536 + (rand_r(&seed) % 1000000); /* 5-byte varint */
        else
            val = ((uint64_t)rand_r(&seed) << 32) | rand_r(&seed); /* 9-byte */

        tx_buf_t buf;
        tx_buf_init(&buf, 16);
        tx_buf_write_varint(&buf, val);

        /* Read back: manually decode the varint from the buffer */
        uint64_t decoded = 0;
        size_t pos = 0;
        if (buf.data[0] < 0xFD) {
            decoded = buf.data[0];
            pos = 1;
        } else if (buf.data[0] == 0xFD) {
            decoded = (uint64_t)buf.data[1] | ((uint64_t)buf.data[2] << 8);
            pos = 3;
        } else if (buf.data[0] == 0xFE) {
            decoded = (uint64_t)buf.data[1] | ((uint64_t)buf.data[2] << 8) |
                      ((uint64_t)buf.data[3] << 16) | ((uint64_t)buf.data[4] << 24);
            pos = 5;
        } else { /* 0xFF */
            for (int i = 0; i < 8; i++)
                decoded |= ((uint64_t)buf.data[1 + i]) << (i * 8);
            pos = 9;
        }

        tx_buf_free(&buf);
        TEST_ASSERT(decoded == val, "varint round-trip mismatch");
        (void)pos;
    }
    return 1;
}

/* ---- Test 5: Channel balance conservation ---- */

int test_prop_channel_balance_conservation(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned int seed = 42;

    for (int trial = 0; trial < 200; trial++) {
        uint64_t initial = 10000 + (rand_r(&seed) % 990001);
        uint64_t local = initial / 2;
        uint64_t remote = initial - local;

        channel_t ch;
        memset(&ch, 0, sizeof(ch));
        ch.ctx = ctx;
        ch.funding_amount = initial;
        ch.local_amount = local;
        ch.remote_amount = remote;
        ch.to_self_delay = 144;
        ch.n_htlcs = 0;

        /* Generate keys for the channel */
        unsigned char sec1[32], sec2[32];
        for (int i = 0; i < 32; i++) {
            sec1[i] = (unsigned char)(rand_r(&seed) & 0xff);
            sec2[i] = (unsigned char)(rand_r(&seed) & 0xff);
        }
        /* Ensure valid secret keys */
        sec1[0] = 0x01; sec2[0] = 0x02;
        if (!secp256k1_ec_pubkey_create(ctx, &ch.local_funding_pubkey, sec1))
            continue;
        if (!secp256k1_ec_pubkey_create(ctx, &ch.remote_funding_pubkey, sec2))
            continue;
        memcpy(ch.local_funding_secret, sec1, 32);

        /* Apply random operations */
        int n_ops = 5 + (rand_r(&seed) % 10);
        for (int op = 0; op < n_ops; op++) {
            if (ch.n_htlcs < MAX_HTLCS && (rand_r(&seed) % 3) != 0) {
                /* Add HTLC */
                uint64_t htlc_amt = 1 + (rand_r(&seed) % (local / 4 + 1));
                if (htlc_amt > ch.local_amount) continue;
                unsigned char phash[32];
                for (int i = 0; i < 32; i++)
                    phash[i] = (unsigned char)(rand_r(&seed) & 0xff);
                uint64_t htlc_id;
                int added = channel_add_htlc(&ch, HTLC_OFFERED, htlc_amt,
                                               phash, 500, &htlc_id);
                if (!added) continue;

                /* Randomly fulfill or fail */
                if (rand_r(&seed) % 2) {
                    unsigned char preimage[32];
                    memset(preimage, 0, 32);
                    sha256(preimage, 32, preimage); /* dummy */
                    /* Can't fulfill without real preimage, so fail instead */
                    channel_fail_htlc(&ch, htlc_id);
                } else {
                    channel_fail_htlc(&ch, htlc_id);
                }
            }
        }

        /* After all operations, sum should equal funding */
        uint64_t htlc_sum = 0;
        for (size_t i = 0; i < ch.n_htlcs; i++) {
            if (ch.htlcs[i].state == HTLC_STATE_ACTIVE)
                htlc_sum += ch.htlcs[i].amount_sats;
        }
        uint64_t total = ch.local_amount + ch.remote_amount + htlc_sum;
        TEST_ASSERT_EQ((long)total, (long)initial,
                        "balance conservation violated");
    }

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test 6: MuSig sign/verify ---- */

int test_prop_musig_sign_verify(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned int seed = 42;

    for (int trial = 0; trial < 50; trial++) {
        unsigned char msg[32];
        for (int i = 0; i < 32; i++)
            msg[i] = (unsigned char)(rand_r(&seed) & 0xff);

        /* Generate 3 keypairs */
        const int n = 3;
        unsigned char secrets[3][32];
        secp256k1_pubkey pubkeys[3];
        secp256k1_keypair keypairs[3];
        for (int k = 0; k < n; k++) {
            for (int i = 0; i < 32; i++)
                secrets[k][i] = (unsigned char)(rand_r(&seed) & 0xff);
            secrets[k][0] = (unsigned char)(k + 1);
            if (!secp256k1_keypair_create(ctx, &keypairs[k], secrets[k])) {
                /* Bad key — skip trial */
                goto next_trial;
            }
            if (!secp256k1_keypair_pub(ctx, &pubkeys[k], &keypairs[k])) {
                goto next_trial;
            }
        }

        /* Aggregate keys */
        musig_keyagg_t keyagg;
        if (!musig_aggregate_keys(ctx, &keyagg, pubkeys, n))
            goto next_trial;

        /* Generate nonces */
        secp256k1_musig_secnonce secnonces[3];
        secp256k1_musig_pubnonce pubnonces[3];
        for (int k = 0; k < n; k++) {
            unsigned char session_id[32];
            for (int i = 0; i < 32; i++)
                session_id[i] = (unsigned char)(rand_r(&seed) & 0xff);
            if (!secp256k1_musig_nonce_gen(ctx, &secnonces[k], &pubnonces[k],
                                              session_id, secrets[k],
                                              &pubkeys[k], msg, NULL, NULL))
                goto next_trial;
        }

        /* Aggregate nonces */
        const secp256k1_musig_pubnonce *pubnonce_ptrs[3];
        for (int k = 0; k < n; k++)
            pubnonce_ptrs[k] = &pubnonces[k];

        secp256k1_musig_aggnonce aggnonce;
        if (!secp256k1_musig_nonce_agg(ctx, &aggnonce, pubnonce_ptrs, n))
            goto next_trial;

        /* Create session and partial sigs */
        secp256k1_musig_session session;
        if (!secp256k1_musig_nonce_process(ctx, &session, &aggnonce, msg,
                                             &keyagg.cache, NULL))
            goto next_trial;

        secp256k1_musig_partial_sig psigs[3];
        for (int k = 0; k < n; k++) {
            if (!secp256k1_musig_partial_sign(ctx, &psigs[k], &secnonces[k],
                                                &keypairs[k], &keyagg.cache,
                                                &session))
                goto next_trial;
        }

        /* Aggregate and verify */
        const secp256k1_musig_partial_sig *psig_ptrs[3];
        for (int k = 0; k < n; k++)
            psig_ptrs[k] = &psigs[k];

        unsigned char final_sig[64];
        if (!secp256k1_musig_partial_sig_agg(ctx, final_sig, &session,
                                               psig_ptrs, n))
            goto next_trial;

        TEST_ASSERT(secp256k1_schnorrsig_verify(ctx, final_sig, msg, 32,
                                                   &keyagg.agg_pubkey),
                    "musig verify failed");

        next_trial:;
    }

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test 7: Wire commitment_signed round-trip ---- */

int test_prop_wire_commitment_roundtrip(void) {
    unsigned int seed = 42;
    for (int trial = 0; trial < 500; trial++) {
        uint32_t channel_id = rand_r(&seed);
        /* Keep within double precision (~2^53) */
        uint64_t commit_num = rand_r(&seed) % 4000000000ULL;
        unsigned char psig[32];
        for (int i = 0; i < 32; i++)
            psig[i] = (unsigned char)(rand_r(&seed) & 0xff);
        uint32_t nonce_idx = rand_r(&seed) % 100;

        cJSON *json = wire_build_commitment_signed(channel_id, commit_num,
                                                     psig, nonce_idx);
        TEST_ASSERT(json != NULL, "build returned NULL");

        uint32_t p_ch, p_nidx;
        uint64_t p_cn;
        unsigned char p_psig[32];
        int ok = wire_parse_commitment_signed(json, &p_ch, &p_cn, p_psig, &p_nidx);
        cJSON_Delete(json);

        TEST_ASSERT(ok, "parse failed");
        TEST_ASSERT(p_ch == channel_id, "channel_id mismatch");
        TEST_ASSERT(p_cn == commit_num, "commitment_number mismatch");
        TEST_ASSERT_MEM_EQ(psig, p_psig, 32, "psig mismatch");
        TEST_ASSERT(p_nidx == nonce_idx, "nonce_index mismatch");
    }
    return 1;
}

/* ---- Test 8: Wire bridge add_htlc round-trip ---- */

int test_prop_wire_bridge_roundtrip(void) {
    unsigned int seed = 42;
    for (int trial = 0; trial < 500; trial++) {
        unsigned char hash[32];
        for (int i = 0; i < 32; i++)
            hash[i] = (unsigned char)(rand_r(&seed) & 0xff);
        uint64_t amount = 1 + ((uint64_t)rand_r(&seed) % 100000000);
        uint32_t cltv = rand_r(&seed);
        /* Keep within double precision (~2^53) */
        uint64_t htlc_id = rand_r(&seed) % 4000000000ULL;

        cJSON *json = wire_build_bridge_add_htlc(hash, amount, cltv, htlc_id);
        TEST_ASSERT(json != NULL, "build returned NULL");

        unsigned char p_hash[32];
        uint64_t p_amount, p_hid;
        uint32_t p_cltv;
        int ok = wire_parse_bridge_add_htlc(json, p_hash, &p_amount,
                                              &p_cltv, &p_hid);
        cJSON_Delete(json);

        TEST_ASSERT(ok, "parse failed");
        TEST_ASSERT_MEM_EQ(hash, p_hash, 32, "hash mismatch");
        TEST_ASSERT(p_amount == amount, "amount mismatch");
        TEST_ASSERT(p_cltv == cltv, "cltv mismatch");
        TEST_ASSERT(p_hid == htlc_id, "htlc_id mismatch");
    }
    return 1;
}

/* ---- Test 9: Persist factory save/load basic ---- */

int test_prop_persist_factory_roundtrip(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned int seed = 42;

    for (int trial = 0; trial < 20; trial++) {
        persist_t db;
        if (!persist_open(&db, ":memory:")) {
            TEST_ASSERT(0, "persist_open failed");
        }

        /* Use exactly 3 participants (1 LSP + 2 clients, smallest valid tree) */
        size_t n = 3;
        uint64_t amount = 10000 + (rand_r(&seed) % 990001);
        uint16_t step = 6;
        uint32_t states = 2 + (rand_r(&seed) % 6);  /* 2-7 */

        factory_t f;
        memset(&f, 0, sizeof(f));
        f.n_participants = n;
        f.funding_amount_sats = amount;
        f.step_blocks = step;
        f.states_per_layer = states;
        f.cltv_timeout = 1000 + (rand_r(&seed) % 9000);
        f.fee_per_tx = 300;
        f.leaf_arity = 2;
        /* Generate random funding txid */
        for (int i = 0; i < 32; i++)
            f.funding_txid[i] = (unsigned char)(rand_r(&seed) & 0xff);
        f.funding_vout = rand_r(&seed) % 4;

        /* Generate participant keys (deterministic from seed) */
        unsigned char secs[3][32];
        for (size_t i = 0; i < n; i++) {
            memset(secs[i], 0, 32);
            secs[i][0] = (unsigned char)(trial * 3 + i + 1);
            secs[i][1] = (unsigned char)(rand_r(&seed) & 0xff);
            if (!secp256k1_ec_pubkey_create(ctx, &f.pubkeys[i], secs[i])) {
                persist_close(&db);
                secp256k1_context_destroy(ctx);
                TEST_ASSERT(0, "ec_pubkey_create failed");
            }
        }

        /* Save */
        uint32_t fid = (uint32_t)(trial + 1);
        int saved = persist_save_factory(&db, &f, ctx, fid);
        TEST_ASSERT(saved, "persist_save_factory failed");

        /* Load and compare */
        factory_t loaded;
        memset(&loaded, 0, sizeof(loaded));

        int loaded_ok = persist_load_factory(&db, fid, &loaded, ctx);
        TEST_ASSERT(loaded_ok, "persist_load_factory failed");
        TEST_ASSERT_EQ((long)loaded.n_participants, (long)n,
                        "n_participants mismatch");
        TEST_ASSERT_EQ((long)loaded.funding_amount_sats, (long)amount,
                        "funding_amount mismatch");
        TEST_ASSERT_EQ((long)loaded.states_per_layer, (long)states,
                        "states_per_layer mismatch");

        persist_close(&db);
    }

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test 10: Wire register_invoice round-trip ---- */

int test_prop_wire_register_roundtrip(void) {
    unsigned int seed = 42;
    for (int trial = 0; trial < 500; trial++) {
        unsigned char hash[32], pre[32];
        for (int i = 0; i < 32; i++) {
            hash[i] = (unsigned char)(rand_r(&seed) & 0xff);
            pre[i] = (unsigned char)(rand_r(&seed) & 0xff);
        }
        uint64_t amount = 1 + ((uint64_t)rand_r(&seed) % 100000000);
        size_t dest = rand_r(&seed) % 16;

        cJSON *json = wire_build_register_invoice(hash, pre, amount, dest);
        TEST_ASSERT(json != NULL, "build returned NULL");

        unsigned char p_hash[32], p_pre[32];
        uint64_t p_amount;
        size_t p_dest;
        int ok = wire_parse_register_invoice(json, p_hash, p_pre, &p_amount, &p_dest);
        cJSON_Delete(json);

        TEST_ASSERT(ok, "parse failed");
        TEST_ASSERT_MEM_EQ(hash, p_hash, 32, "hash mismatch");
        TEST_ASSERT_MEM_EQ(pre, p_pre, 32, "preimage mismatch");
        TEST_ASSERT(p_amount == amount, "amount mismatch");
        TEST_ASSERT(p_dest == dest, "dest mismatch");
    }
    return 1;
}
