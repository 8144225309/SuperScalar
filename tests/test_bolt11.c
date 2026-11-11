/*
 * test_bolt11.c — Unit tests for BOLT #11 invoice decode/encode
 */

#include "superscalar/bolt11.h"
#include "superscalar/sha256.h"
#include <stdint.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while(0)

/* ---- Test B1: decode known good invoice ---- */
int test_bolt11_decode_known(void)
{
    /* Minimal lnbcrt invoice (regtest, any amount, known payment_hash) */
    /* This is a synthetically-constructed invoice for unit testing */
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx != NULL, "ctx");

    /* Build an invoice and then decode it to verify round-trip */
    unsigned char node_priv[32];
    memset(node_priv, 0x42, 32);

    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    strcpy(inv.network, "bcrt");
    inv.amount_msat = 50000;
    inv.has_amount  = 1;
    inv.timestamp   = (uint32_t)time(NULL);
    inv.expiry      = 3600;
    memset(inv.payment_hash,   0xAB, 32);
    memset(inv.payment_secret, 0xCD, 32);
    inv.has_payment_secret = 1;
    strcpy(inv.description, "Test invoice");

    /* Encode */
    char encoded[2048];
    ASSERT(bolt11_encode(&inv, node_priv, ctx, encoded, sizeof(encoded)),
           "encode should succeed");
    ASSERT(strncmp(encoded, "lnbcrt", 6) == 0, "should start with lnbcrt");

    /* Decode */
    bolt11_invoice_t dec;
    ASSERT(bolt11_decode(ctx, encoded, &dec), "decode should succeed");
    ASSERT(strcmp(dec.network, "bcrt") == 0, "network matches");
    ASSERT(dec.amount_msat == 50000, "amount matches");
    ASSERT(dec.has_amount, "has_amount flag");
    ASSERT(memcmp(dec.payment_hash, inv.payment_hash, 32) == 0, "payment_hash matches");
    ASSERT(dec.has_payment_secret, "has_payment_secret flag");
    ASSERT(memcmp(dec.payment_secret, inv.payment_secret, 32) == 0,
           "payment_secret matches");
    ASSERT(strcmp(dec.description, "Test invoice") == 0, "description matches");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test B2: zero-amount invoice ---- */
int test_bolt11_no_amount(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char node_priv[32];
    memset(node_priv, 0x33, 32);

    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    strcpy(inv.network, "bs"); /* signet */
    inv.has_amount  = 0;
    inv.amount_msat = 0;
    inv.timestamp   = 1700000000;
    inv.expiry      = 7200;
    memset(inv.payment_hash,   0x11, 32);
    memset(inv.payment_secret, 0x22, 32);
    inv.has_payment_secret = 1;
    strcpy(inv.description, "Any amount");

    char encoded[2048];
    ASSERT(bolt11_encode(&inv, node_priv, ctx, encoded, sizeof(encoded)),
           "encode no-amount");
    ASSERT(strncmp(encoded, "lnbs1", 5) == 0, "signet prefix");

    bolt11_invoice_t dec;
    ASSERT(bolt11_decode(ctx, encoded, &dec), "decode no-amount");
    ASSERT(!dec.has_amount || dec.amount_msat == 0, "no amount in decoded");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test B3: route hints round-trip ---- */
int test_bolt11_route_hints(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char node_priv[32];
    memset(node_priv, 0x77, 32);

    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    strcpy(inv.network, "bc");
    inv.amount_msat = 1000000; /* 1 sat */
    inv.has_amount  = 1;
    inv.timestamp   = 1700000000;
    memset(inv.payment_hash,   0xCC, 32);
    memset(inv.payment_secret, 0xDD, 32);
    inv.has_payment_secret = 1;
    strcpy(inv.description, "With hint");

    /* Add one route hint with one hop */
    inv.n_hints = 1;
    inv.hints[0].n_hops = 1;
    memset(inv.hints[0].hops[0].pubkey, 0x02, 33);
    inv.hints[0].hops[0].short_channel_id = 0x0001000000000001ULL;
    inv.hints[0].hops[0].fee_base_msat    = 1000;
    inv.hints[0].hops[0].fee_ppm          = 100;
    inv.hints[0].hops[0].cltv_expiry_delta = 40;

    char encoded[2048];
    ASSERT(bolt11_encode(&inv, node_priv, ctx, encoded, sizeof(encoded)),
           "encode with hint");

    bolt11_invoice_t dec;
    ASSERT(bolt11_decode(ctx, encoded, &dec), "decode with hint");
    ASSERT(dec.n_hints >= 1, "has route hint");
    ASSERT(dec.hints[0].n_hops >= 1, "hint has hops");
    ASSERT(dec.hints[0].hops[0].fee_base_msat == 1000, "fee_base matches");
    ASSERT(dec.hints[0].hops[0].fee_ppm == 100, "fee_ppm matches");
    ASSERT(dec.hints[0].hops[0].cltv_expiry_delta == 40, "cltv_delta matches");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Test B4: invalid invoice rejected ---- */
int test_bolt11_invalid_rejected(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    bolt11_invoice_t dec;

    /* Totally invalid string */
    ASSERT(!bolt11_decode(ctx, "notaninvoice", &dec), "invalid string rejected");

    /* Too short */
    ASSERT(!bolt11_decode(ctx, "lnbc1", &dec), "too short rejected");

    /* Truncated */
    ASSERT(!bolt11_decode(ctx, "lnbc10m1pvjluezpp5", &dec), "truncated rejected");

    secp256k1_context_destroy(ctx);
    return 1;
}


/* ================================================================== */
/* M1 — metadata round-trip encode/decode                             */
/* ================================================================== */
int test_bolt11_metadata_roundtrip(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char node_priv[32]; memset(node_priv, 0x42, 32);

    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    strcpy(inv.network, "bcrt");
    inv.amount_msat = 1000000;
    inv.has_amount  = 1;
    inv.timestamp   = 1700000000;
    memset(inv.payment_hash,   0xAA, 32);
    memset(inv.payment_secret, 0xBB, 32);
    inv.has_payment_secret = 1;
    strcpy(inv.description, "metadata test");

    /* Set metadata */
    inv.metadata[0] = 0x01; inv.metadata[1] = 0x02;
    inv.metadata[2] = 0x03; inv.metadata[3] = 0x04;
    inv.metadata_len = 4;
    inv.has_metadata = 1;

    char encoded[2048];
    ASSERT(bolt11_encode(&inv, node_priv, ctx, encoded, sizeof(encoded)),
           "M1: encode");

    bolt11_invoice_t dec;
    ASSERT(bolt11_decode(ctx, encoded, &dec), "M1: decode");
    ASSERT(dec.has_metadata,           "M1: has_metadata=1");
    ASSERT(dec.metadata_len == 4,      "M1: metadata_len=4");
    ASSERT(dec.metadata[0] == 0x01,    "M1: metadata[0]");
    ASSERT(dec.metadata[3] == 0x04,    "M1: metadata[3]");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* M2 — no metadata: has_metadata=0, no crash                        */
/* ================================================================== */
int test_bolt11_no_metadata(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char node_priv[32]; memset(node_priv, 0x55, 32);

    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    strcpy(inv.network, "bcrt");
    inv.amount_msat = 500; inv.has_amount = 1;
    inv.timestamp = 1700000001;
    memset(inv.payment_hash,   0xCC, 32);
    memset(inv.payment_secret, 0xDD, 32);
    inv.has_payment_secret = 1;
    inv.has_metadata = 0; /* no metadata */
    strcpy(inv.description, "no meta");

    char encoded[2048];
    ASSERT(bolt11_encode(&inv, node_priv, ctx, encoded, sizeof(encoded)),
           "M2: encode");

    bolt11_invoice_t dec;
    ASSERT(bolt11_decode(ctx, encoded, &dec), "M2: decode");
    ASSERT(!dec.has_metadata, "M2: has_metadata=0");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* M3 — metadata_len truncated to 64 on decode                       */
/* ================================================================== */
int test_bolt11_metadata_truncated(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char node_priv[32]; memset(node_priv, 0x66, 32);

    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    strcpy(inv.network, "bcrt");
    inv.amount_msat = 1000; inv.has_amount = 1;
    inv.timestamp = 1700000002;
    memset(inv.payment_hash,   0xEE, 32);
    memset(inv.payment_secret, 0xFF, 32);
    inv.has_payment_secret = 1;
    /* 64 bytes metadata (max) */
    memset(inv.metadata, 0x11, 64);
    inv.metadata_len = 64;
    inv.has_metadata = 1;
    strcpy(inv.description, "max meta");

    char encoded[4096];
    ASSERT(bolt11_encode(&inv, node_priv, ctx, encoded, sizeof(encoded)),
           "M3: encode");

    bolt11_invoice_t dec;
    ASSERT(bolt11_decode(ctx, encoded, &dec), "M3: decode");
    ASSERT(dec.has_metadata,      "M3: has_metadata");
    ASSERT(dec.metadata_len <= 64, "M3: truncated to 64");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ================================================================== */
/* M4 — full round-trip with all fields including metadata            */
/* ================================================================== */
int test_bolt11_full_roundtrip_with_metadata(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    unsigned char node_priv[32]; memset(node_priv, 0x77, 32);

    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    strcpy(inv.network, "bc");
    inv.amount_msat = 2000000; inv.has_amount = 1;
    inv.timestamp = 1700000003;
    memset(inv.payment_hash,   0x12, 32);
    memset(inv.payment_secret, 0x34, 32);
    inv.has_payment_secret = 1;
    strcpy(inv.description, "full roundtrip");
    inv.expiry = 7200;
    inv.min_final_cltv_expiry = 40;
    /* metadata */
    inv.metadata[0] = 0xDE; inv.metadata[1] = 0xAD;
    inv.metadata[2] = 0xBE; inv.metadata[3] = 0xEF;
    inv.metadata_len = 4; inv.has_metadata = 1;

    char encoded[4096];
    ASSERT(bolt11_encode(&inv, node_priv, ctx, encoded, sizeof(encoded)),
           "M4: encode");

    bolt11_invoice_t dec;
    ASSERT(bolt11_decode(ctx, encoded, &dec), "M4: decode");
    ASSERT(dec.amount_msat == 2000000,       "M4: amount");
    ASSERT(dec.has_payment_secret,           "M4: has_payment_secret");
    ASSERT(dec.has_metadata,                 "M4: has_metadata");
    ASSERT(dec.metadata[0] == 0xDE,          "M4: metadata[0]");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Amount units, expiry and min_final_cltv survive encode/decode ---- */
int test_bolt11_amount_units_and_fields(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");
    unsigned char node_priv[32]; memset(node_priv, 0x51, 32);

    static const struct { uint64_t msat; const char *prefix; } cases[] = {
        { 250000000ULL, "lnbc2500u1" },   /* 250,000 sat */
        { 100000000ULL, "lnbc1m1"    },   /* 0.001 BTC   */
        { 4000000ULL,   "lnbc40u1"   },   /* 4,000 sat   */
        { 1000ULL,      "lnbc10n1"   },   /* 1 sat       */
        { 1ULL,         "lnbc10p1"   },   /* 1 msat      */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        bolt11_invoice_t inv;
        memset(&inv, 0, sizeof(inv));
        strcpy(inv.network, "bc");
        inv.amount_msat = cases[i].msat; inv.has_amount = 1;
        inv.timestamp = 1700000100;
        memset(inv.payment_hash, 0x21, 32);
        memset(inv.payment_secret, 0x22, 32);
        inv.has_payment_secret = 1;
        strcpy(inv.description, "units");
        inv.expiry = 900;
        inv.min_final_cltv_expiry = 144;

        char enc[2048];
        ASSERT(bolt11_encode(&inv, node_priv, ctx, enc, sizeof(enc)), "encode");
        ASSERT(strncmp(enc, cases[i].prefix, strlen(cases[i].prefix)) == 0,
               "amount written in BOLT #11 units");

        bolt11_invoice_t dec;
        memset(&dec, 0, sizeof(dec));
        ASSERT(bolt11_decode(ctx, enc, &dec), "decode");
        ASSERT(dec.has_amount && dec.amount_msat == cases[i].msat,
               "amount round-trips");
        ASSERT(dec.expiry == 900, "expiry round-trips");
        ASSERT(dec.min_final_cltv_expiry == 144, "min_final_cltv round-trips");
    }

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- BOLT #11 specification examples ---- */

/* Every example invoice of the BOLT #11 specification, valid and invalid.
   The valid ones are signed with the key given there. */
static const struct { const char *name; const char *invoice; } spec_valid[] = {
    { "donation",
      "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsp"
      "p5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5s"
      "xxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2u"
      "eh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9z"
      "qt8r2t7mlcwspyetp5h2tztugp9lfyql"
    },
    { "coffee",
      "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3"
      "zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxa"
      "tsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhe"
      "dh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh"
    },
    { "nonsense",
      "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3"
      "zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4c"
      "urk03c9wlrswe78q4eyqc7d8d0xqzpu9qrsgqhtjpauu9ur7fw2thcl4y9vfvh4m9wlf"
      "yz2gem29g5ghe2aak2pm3ps8fdhtceqsaagty2vph7utlgj48u0ged6a337aewvraede"
      "ndscp573dxr"
    },
    { "hashed",
      "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zy"
      "gspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan7"
      "9s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrsgq7ea976txfraylvgzux"
      "s8kgcw23ezlrszfnh8r6qtfpr6cxga50aj6txm9rxrydzd06dfeawfk6swupvz4erwny"
      "utnjq7x39ymw6j38gp7ynn44"
    },
    { "testnet_fallback",
      "lntb20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zy"
      "gshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcy"
      "q5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9va"
      "x37wxq72un989qrsgqdj545axuxtnfemtpwkc45hx9d2ft7x04mt8q7y6t0k2dge9e7h"
      "8kpy9p34ytyslj3yu569aalz2xdk8xkd7ltxqld94u8h2esmsmacgpghe9k8"
    },
    { "route_hints",
      "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zy"
      "gspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan7"
      "9s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexv"
      "gpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92"
      "qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6j"
      "hphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzq9qrsgqdfjcdk6w3ak5pca9hwf"
      "wfh63zrrz06wwfya0ydlzpgzxkn5xagsqz7x9j4jwe7yj7vaf2k9lqsdk45kts2fd0fk"
      "r28am0u4w95tt2nsq76cqw0"
    },
    { "fallback_p2sh",
      "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zy"
      "gshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcy"
      "q5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppj3a24vwu6r8ejrss3axul"
      "8rxldph2q7z99qrsgqz6qsgww34xlatfj6e3sngrwfy3ytkt29d2qttr8qz2mnedfqys"
      "uqypgqex4haa2h8fx3wnypranf3pdwyluftwe680jjcfp438u82xqphf75ym"
    },
    { "fallback_p2wpkh",
      "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zy"
      "gshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcy"
      "q5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3za"
      "rvary0c5xw7k9qrsgqt29a0wturnys2hhxpner2e3plp6jyj8qx7548zr2z7ptgjjc7h"
      "ljm98xhjym0dg52sdrvqamxdezkmqg4gdrvwwnf0kv2jdfnl4xatsqmrnsse"
    },
    { "fallback_p2wsh",
      "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zy"
      "gshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcy"
      "q5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysr"
      "x4k6zdkfs4nce4xj0gdcccefvpysxf3q9qrsgq9vlvyj8cqvq6ggvpwd53jncp9nwc47"
      "xlrsnenq2zp70fq83qlgesn4u3uyf4tesfkkwwfg3qs54qe426hp3tz7z6sweqdjg05a"
      "xsrjqp9yrrwc"
    },
    { "fallback_p2tr",
      "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zy"
      "gspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan7"
      "9s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfp4pptdvg0d2nj99568qn6ss"
      "dy4cygnwuxgw2ukmnwgwz7jpqjz2kszs9qrsgqy606dznq28exnydt2r4c29y56xjtn3"
      "sk4mhgjtl4pg2y4ar3249rq4ajlmj9jy8zvlzw7cr8mggqzm842xfr0v72rswzq9xvr4"
      "hknfsqwmn6xd"
    },
    { "pico",
      "lnbc9678785340p1pwmna7lpp5gc3xfm08u9qy06djf8dfflhugl6p7lgza6dsjxq454"
      "gxhj9t7a0sd8dgfkx7cmtwd68yetpd5s9xar0wfjn5gpc8qhrsdfq24f5ggrxdaezqsn"
      "vda3kkum5wfjkzmfqf3jkgem9wgsyuctwdus9xgrcyqcjcgpzgfskx6eqf9hzqnteypz"
      "xz7fzypfhg6trddjhygrcyqezcgpzfysywmm5ypxxjemgw3hxjmn8yptk7untd9hxwg3"
      "q2d6xjcmtv4ezq7pqxgsxzmnyyqcjqmt0wfjjq6t5v4khxsp5zyg3zyg3zyg3zyg3zyg"
      "3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsxqyjw5qcqp2rzjq0gxwkzc8w6323m55m4jy"
      "xcjwmy7stt9hwkwe2qxmy8zpsgg7jcuwz87fcqqeuqqqyqqqqlgqqqqn3qq9q9qrsgqr"
      "vgkpnmps664wgkp43l22qsgdw4ve24aca4nymnxddlnp8vh9v2sdxlu5ywdxefsfvm0f"
      "q3sesf08uf6q9a2ke0hc9j6z6wlxg5z5kqpu2v9wz"
    },
    { "features",
      "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqy"
      "pqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3"
      "zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgq2a25dxl5hrntdtn6zvydt7d66hyzsyhqs"
      "4wdynavys42xgl6sgx9c4g7me86a27t07mdtfry458rtjr0v92cnmswpsjscgt2vcse3"
      "sgpz3uapa"
    },
    { "features_upper",
      "LNBC25M1PVJLUEZPP5QQQSYQCYQ5RQWZQFQQQSYQCYQ5RQWZQFQQQSYQCYQ5RQWZQFQY"
      "PQDQ5VDHKVEN9V5SXYETPDEESSP5ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3"
      "ZYG3ZYG3ZYGS9Q5SQQQQQQQQQQQQQQQQSGQ2A25DXL5HRNTDTN6ZVYDT7D66HYZSYHQS"
      "4WDYNAVYS42XGL6SGX9C4G7ME86A27T07MDTFRY458RTJR0V92CNMSWPSJSCGT2VCSE3"
      "SGPZ3UAPA"
    },
    { "features_unknown_fields",
      "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqy"
      "pqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3"
      "zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgq2qrqqqfppnqqqqqqqqqqqqqqqqqqqqqqq"
      "qqqqqqqqqcsenjd934c02h7v9deyju0t43ye2y38nd2h2wr0ykzlqs7v873jkvvg36kf"
      "wwmp9lftrn8a3gp4ax52zpvyc7quffgjjj7avx7we9zcp3dce9d"
    },
    { "metadata",
      "lnbc10m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqy"
      "pqdp9wpshjmt9de6zqmt9w3skgct5vysxjmnnd9jx2mq8q8a04uqsp5zyg3zyg3zyg3z"
      "yg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q2gqqqqqqsgq7hf8he7ecf7n4ffp"
      "hs6awl9t6676rrclv9ckg3d3ncn7fct63p6s365duk5wrk202cfy3aj5xnnp5gs3vrdv"
      "ruverwwq7yzhkf5a3xqpd05wjc"
    },
    { "high_s_recovery",
      "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsp"
      "p5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5s"
      "xxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2u"
      "eh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap2r09nt4ndd0unm3z9u5t48y6ucv"
      "4r5sg7lk98c77ctvjczkspk5qprc90gx"
    },
};

static const struct { const char *name; const char *invoice; } spec_invalid[] = {
    { "unknown_even_feature",
      "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqy"
      "pqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3"
      "zyg3zyg3zygs9q4psqqqqqqqqqqqqqqqqsgqtqyx5vggfcsll4wu246hz02kp85x4kat"
      "wsk9639we5n5yngc3yhqkm35jnjw4len8vrnqnf5ejh0mzj9n3vz2px97evektfm2l6w"
      "qccp3y7372"
    },
    { "n_wrong_length",
      "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqy"
      "pqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3"
      "zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgqnp5qqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
      "qqqqqqqqqqqqqqqqqqqqqqf9dt6rzhc3ynq3u7axf4xc3zaw3fy2kyqal6n86nh5j3lh"
      "gcutdjzhvswudd5l8ay9acgrrpd2e6vw9sdqxq6dzq983sgt7dpxk5wacqacdc2y"
    },
    { "missing_p",
      "lnbc25m1pvjluezdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg"
      "3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgqjy08jd52dtj25pefkh0e"
      "nc54lxtjtr8wnum2msrq2d8uztp9vhhpccq93ljpff0kkjgzkzcp2czlyenjphf6upaz"
      "jlc8uxw7za0ynusqrfhg8u"
    },
    { "two_distinct_p",
      "lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqp"
      "p5lllllllllllllllllllllllllllllllllllllllllllllllllllsdpyv36hqmrfvds"
      "hgefqwpshjmt9de6zq6rpwd5qsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3"
      "zyg3zyg3zygs9g3f93cqturay6zk2fyfcmeflphlzew9wfq0n5nf9hqnlwxthtzqcljc"
      "uurljyd2vngkya5hndakf33ghly97qm5nc3umj7jep22nfsq3nr0w8"
    },
    { "same_p_twice",
      "lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqp"
      "p5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpyv36hqmrfvds"
      "hgefqwpshjmt9de6zq6rpwd5qsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3"
      "zyg3zyg3zygs29wywgsx0wpv9t045f683nj97nnjk55wt0exe3eassl6smx60nk9hlaa"
      "e8vhe0hwv25s6fthcwqkxsw2hpjeptxz7xujtexa3l8jrkcqyn037r"
    },
    { "two_distinct_s",
      "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqy"
      "pqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3"
      "zyg3zyg3zygssp5yg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3q9"
      "q5sqqqqqqqqqqqqqqqqsgqy23f0q2mhf0mnhfesz2lt3j9n8negrgr2a7wd554fppeqn"
      "vwz9749j2zmp2jd2sfvn3lzlajhalyxlv2h6ccs6p3yg7wg43y22cazccp5vkkte"
    },
    { "bad_checksum",
      "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqf"
      "qypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62"
      "aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpn"
      "l2jfll544esqchsrnt"
    },
    { "no_separator",
      "pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwp"
      "c4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8e"
      "dtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544e"
      "sqchsrny"
    },
    { "mixed_case",
      "LNBC2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqf"
      "qypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62"
      "aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpn"
      "l2jfll544esqchsrny"
    },
    { "unrecoverable_signature",
      "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqf"
      "qypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3z"
      "yg3zyg3zyg3zyg3zygs9qrsgqwgt7mcn5yqw3yx0w94pswkpq6j9uh6xfqqqtsk4tnar"
      "ugeektd4hg5975x9am52rz4qskukxdmjemg92vvqz8nvmsye63r5ykel43pgz7zq0g2"
    },
    { "too_short",
      "lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqd"
      "pl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6na6hlh"
    },
    { "bad_multiplier",
      "lnbc2500x1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqf"
      "qypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3z"
      "yg3zyg3zyg3zyg3zygs9qrsgqrrzc4cvfue4zp3hggxp47ag7xnrlr8vgcmkjxk3j5jq"
      "ethnumgkpqp23z9jclu3v0a7e0aruz366e9wqdykw6dxhdzcjjhldxq0w6wgqcnu43j"
    },
    { "sub_msat_precision",
      "lnbc2500000001p1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5"
      "rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg"
      "3zyg3zyg3zyg3zyg3zyg3zygs9qrsgq0lzc236j96a95uv0m3umg28gclm5lqxtqqwk3"
      "2uuk4k6673k6n5kfvx3d2h8s295fad45fdhmusm8sjudfhlf6dcsxmfvkeywmjdkxcp9"
      "9202x"
    },
    { "missing_s",
      "lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqy"
      "pqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrsgq7ea97"
      "6txfraylvgzuxs8kgcw23ezlrszfnh8r6qtfpr6cxga50aj6txm9rxrydzd06dfeawfk"
      "6swupvz4erwnyutnjq7x39ymw6j38gp49qdkj"
    },
    { "high_s_with_n",
      "lnbc25m1p70xwfzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqy"
      "pqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq"
      "np4q0n326hr8v9zprg8gsvezcch06gfaqqhde2aj730yg0durunfhv66sp5zyg3zyg3z"
      "yg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgqsp5zyg3zyg3zyg3zyg3"
      "zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsp5cfzp9ugllvk03rltd6hvndxj26ux6g"
      "cxc5azyxk060rj9tzghct5zvjlps76gx8wpq5yuu79688k8gnm2c0al6v608s96l0xzr"
      "rlqqwnzxmu"
    },
};

static const unsigned char spec_privkey[32] = { 0xe1,0x26,0xf6,0x8f,0x7e,0xaf,0xcc,0x8b,0x74,0xf5,0x4d,0x26,0x9f,0xe2,0x06,0xbe,0x71,0x50,0x00,0xf9,0x4d,0xac,0x06,0x7d,0x1c,0x04,0xa8,0xca,0x3b,0x2d,0xb7,0x34 };
static const unsigned char spec_payee[33] = { 0x03,0xe7,0x15,0x6a,0xe3,0x3b,0x0a,0x20,0x8d,0x07,0x44,0x19,0x91,0x63,0x17,0x7e,0x90,0x9e,0x80,0x17,0x6e,0x55,0xd9,0x7a,0x2f,0x22,0x1e,0xde,0x0f,0x93,0x4d,0xd9,0xad };

static const bolt11_invoice_t *spec_decode(secp256k1_context *ctx, const char *name,
                                           bolt11_invoice_t *dec) {
    for (size_t i = 0; i < sizeof(spec_valid) / sizeof(spec_valid[0]); i++)
        if (strcmp(spec_valid[i].name, name) == 0)
            return bolt11_decode(ctx, spec_valid[i].invoice, dec) ? dec : NULL;
    return NULL;
}

int test_bolt11_spec_valid_examples(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    /* The payee key quoted by the specification belongs to its private key */
    secp256k1_pubkey pk;
    unsigned char ser[33]; size_t slen = 33;
    ASSERT(secp256k1_ec_pubkey_create(ctx, &pk, spec_privkey), "derive key");
    secp256k1_ec_pubkey_serialize(ctx, ser, &slen, &pk, SECP256K1_EC_COMPRESSED);
    ASSERT(memcmp(ser, spec_payee, 33) == 0, "spec payee key matches spec private key");

    static const unsigned char spec_hash[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,0x08,0x09,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x01,0x02 };
    unsigned char ones[32]; memset(ones, 0x11, 32);

    bolt11_invoice_t dec;
    for (size_t i = 0; i < sizeof(spec_valid) / sizeof(spec_valid[0]); i++) {
        if (!bolt11_decode(ctx, spec_valid[i].invoice, &dec)) {
            printf("  FAIL: valid spec example '%s' rejected\n", spec_valid[i].name);
            return 0;
        }
        ASSERT(dec.has_payment_secret && memcmp(dec.payment_secret, ones, 32) == 0,
               "payment secret");
        /* The signature recovers to the payee the specification names.  (It
           names none for the high-S example, whose signature is the first
           example's with S negated.) */
        if (strcmp(spec_valid[i].name, "high_s_recovery") != 0 &&
            memcmp(dec.payee_pubkey, spec_payee, 33) != 0) {
            printf("  FAIL: spec example '%s' recovers the wrong payee\n",
                   spec_valid[i].name);
            return 0;
        }
        if (strcmp(spec_valid[i].name, "pico") != 0)
            ASSERT(memcmp(dec.payment_hash, spec_hash, 32) == 0, "payment hash");
    }

    ASSERT(spec_decode(ctx, "donation", &dec), "donation");
    ASSERT(!dec.has_amount && dec.amount_msat == 0, "donation: no amount");
    ASSERT(dec.expiry == 3600 && dec.min_final_cltv_expiry == 18, "donation: defaults");
    ASSERT(strcmp(dec.description, "Please consider supporting this project") == 0,
           "donation: description");

    ASSERT(spec_decode(ctx, "coffee", &dec), "coffee");
    ASSERT(strcmp(dec.network, "bc") == 0, "coffee: mainnet");
    ASSERT(dec.has_amount && dec.amount_msat == 250000000ULL, "coffee: 2500u");
    ASSERT(dec.timestamp == 1496314658, "coffee: timestamp");
    ASSERT(dec.expiry == 60, "coffee: expiry 60 s");
    ASSERT(strcmp(dec.description, "1 cup coffee") == 0, "coffee: description");

    ASSERT(spec_decode(ctx, "hashed", &dec), "hashed");
    ASSERT(dec.amount_msat == 2000000000ULL, "hashed: 20m");
    ASSERT(dec.has_description_hash && dec.description_hash[0] == 0x39 &&
           dec.description_hash[31] == 0xc1, "hashed: description hash");

    ASSERT(spec_decode(ctx, "testnet_fallback", &dec), "testnet");
    ASSERT(strcmp(dec.network, "tb") == 0, "testnet: network");

    ASSERT(spec_decode(ctx, "route_hints", &dec), "route hints");
    ASSERT(dec.n_hints == 1 && dec.hints[0].n_hops == 2, "two private hops");
    ASSERT(dec.hints[0].hops[0].pubkey[0] == 0x02 &&
           dec.hints[0].hops[0].fee_base_msat == 1 &&
           dec.hints[0].hops[0].fee_ppm == 20 &&
           dec.hints[0].hops[0].cltv_expiry_delta == 3, "first hop");
    ASSERT(dec.hints[0].hops[1].pubkey[0] == 0x03 &&
           dec.hints[0].hops[1].fee_base_msat == 2 &&
           dec.hints[0].hops[1].fee_ppm == 30 &&
           dec.hints[0].hops[1].cltv_expiry_delta == 4, "second hop");

    ASSERT(spec_decode(ctx, "pico", &dec), "pico");
    ASSERT(dec.amount_msat == 967878534ULL, "pico: 9678785340p");
    ASSERT(dec.expiry == 604800, "pico: one week expiry");
    ASSERT(dec.min_final_cltv_expiry == 10, "pico: min_final_cltv 10");
    ASSERT(dec.n_hints == 1 && dec.hints[0].hops[0].fee_base_msat == 1000 &&
           dec.hints[0].hops[0].fee_ppm == 2500 &&
           dec.hints[0].hops[0].cltv_expiry_delta == 40, "pico: route hint");

    /* Feature bits 8, 14 and (odd, unknown) 99 */
    ASSERT(spec_decode(ctx, "features", &dec), "features");
    ASSERT(dec.amount_msat == 2500000000ULL, "features: 25m");
    ASSERT(dec.features == ((1u << 8) | (1u << 14)), "features: bits 8 and 14");
    ASSERT(spec_decode(ctx, "features_upper", &dec), "upper case");
    ASSERT(dec.amount_msat == 2500000000ULL, "upper case: 25m");
    ASSERT(spec_decode(ctx, "features_unknown_fields", &dec), "unknown fields ignored");

    ASSERT(spec_decode(ctx, "metadata", &dec), "metadata");
    static const unsigned char meta[4] = { 0x01, 0xfa, 0xfa, 0xf0 };
    ASSERT(dec.has_metadata && dec.metadata_len == 4 &&
           memcmp(dec.metadata, meta, 4) == 0, "metadata bytes");
    ASSERT(dec.amount_msat == 1000000000ULL, "metadata: 10m");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_bolt11_spec_invalid_examples(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");
    bolt11_invoice_t dec;
    for (size_t i = 0; i < sizeof(spec_invalid) / sizeof(spec_invalid[0]); i++) {
        if (bolt11_decode(ctx, spec_invalid[i].invoice, &dec)) {
            printf("  FAIL: invalid spec example '%s' accepted\n", spec_invalid[i].name);
            return 0;
        }
    }
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Hand-built invoices: fields the encoder never produces ---- */

static const char B32[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t t_polymod(const uint8_t *v, size_t n) {
    static const uint32_t G[5] = { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa,
                                   0x3d4233dd, 0x2a1462b3 };
    uint32_t c = 1;
    for (size_t i = 0; i < n; i++) {
        uint8_t b = (uint8_t)(c >> 25);
        c = ((c & 0x1ffffff) << 5) ^ v[i];
        for (int k = 0; k < 5; k++) if ((b >> k) & 1) c ^= G[k];
    }
    return c;
}

typedef struct { uint8_t g[2048]; size_t n; } groups_t;

static void g_put(groups_t *g, uint64_t v, int n_groups) {
    for (int k = n_groups - 1; k >= 0; k--)
        g->g[g->n++] = (uint8_t)((v >> (5 * k)) & 0x1f);
}
/* tag + length + `len` groups all equal to `fill`, except the last = `last` */
static void g_field(groups_t *g, int tag, size_t len, uint8_t fill, uint8_t last) {
    g_put(g, (uint64_t)tag, 1);
    g_put(g, len, 2);
    for (size_t k = 0; k < len; k++)
        g->g[g->n++] = (k + 1 == len) ? last : fill;
}
/* p (tag 1) and s (tag 16) with 52 zero groups */
static void g_hash_and_secret(groups_t *g) {
    g_field(g, 1, 52, 0, 0);
    g_field(g, 16, 52, 0, 0);
}

/* Sign and bech32-encode hrp + groups the way BOLT #11 prescribes. */
static int g_finish(secp256k1_context *ctx, const char *hrp, groups_t *g,
                    const unsigned char key[32], char *out, size_t out_cap) {
    unsigned char msg[4096]; size_t hl = strlen(hrp), m = hl;
    memcpy(msg, hrp, hl);
    uint32_t acc = 0; int bits = 0;
    for (size_t i = 0; i < g->n; i++) {
        acc = (acc << 5) | g->g[i]; bits += 5;
        if (bits >= 8) { bits -= 8; msg[m++] = (unsigned char)(acc >> bits); }
    }
    if (bits) msg[m++] = (unsigned char)(acc << (8 - bits));
    unsigned char h[32];
    sha256(msg, m, h);
    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_sign_recoverable(ctx, &sig, h, key, NULL, NULL)) return 0;
    unsigned char rs[65]; int recid;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, rs, &recid, &sig);
    rs[64] = (unsigned char)recid;
    acc = 0; bits = 0;
    for (int i = 0; i < 65; i++) {
        acc = (acc << 8) | rs[i]; bits += 8;
        while (bits >= 5) { bits -= 5; g->g[g->n++] = (acc >> bits) & 0x1f; }
    }
    uint8_t v[4096]; size_t vn = 0;
    for (size_t i = 0; i < hl; i++) v[vn++] = (uint8_t)(hrp[i] >> 5);
    v[vn++] = 0;
    for (size_t i = 0; i < hl; i++) v[vn++] = (uint8_t)(hrp[i] & 31);
    memcpy(v + vn, g->g, g->n); vn += g->n;
    memset(v + vn, 0, 6); vn += 6;
    uint32_t chk = t_polymod(v, vn) ^ 1;
    if (hl + 1 + g->n + 7 > out_cap) return 0;
    size_t o = 0;
    memcpy(out, hrp, hl); o = hl; out[o++] = '1';
    for (size_t i = 0; i < g->n; i++) out[o++] = B32[g->g[i]];
    for (int k = 5; k >= 0; k--) out[o++] = B32[(chk >> (5 * k)) & 31];
    out[o] = '\0';
    return 1;
}

/* Build "hrp + timestamp + p + s + one extra field" and decode it. */
static int decode_with_field(secp256k1_context *ctx, const char *hrp, int tag,
                             size_t len, uint8_t fill, uint8_t last,
                             bolt11_invoice_t *dec) {
    unsigned char key[32]; memset(key, 0x42, 32);
    groups_t g; g.n = 0;
    g_put(&g, 1700000000, 7);
    g_hash_and_secret(&g);
    if (tag >= 0) g_field(&g, tag, len, fill, last);
    char inv[4096];
    if (!g_finish(ctx, hrp, &g, key, inv, sizeof(inv))) return -1;
    return bolt11_decode(ctx, inv, dec);
}

int test_bolt11_reader_strictness(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");
    bolt11_invoice_t dec;

    /* The hand-built baseline is itself a valid invoice */
    ASSERT(decode_with_field(ctx, "lnbc", -1, 0, 0, 0, &dec) == 1, "baseline decodes");
    ASSERT(dec.timestamp == 1700000000 && dec.expiry == 3600, "baseline fields");

    /* x: leading zero groups are fine; a value that does not fit is not */
    ASSERT(decode_with_field(ctx, "lnbc", 6, 12, 0, 28, &dec) == 1, "padded x accepted");
    ASSERT(dec.expiry == 28, "padded x value");
    ASSERT(decode_with_field(ctx, "lnbc", 6, 7, 31, 31, &dec) == 0,
           "x above 32 bits rejected");
    ASSERT(decode_with_field(ctx, "lnbc", 6, 20, 31, 31, &dec) == 0,
           "x above 64 bits rejected");
    /* c likewise */
    ASSERT(decode_with_field(ctx, "lnbc", 24, 3, 0, 9, &dec) == 1, "padded c accepted");
    ASSERT(dec.min_final_cltv_expiry == 9, "padded c value");
    ASSERT(decode_with_field(ctx, "lnbc", 24, 7, 31, 31, &dec) == 0,
           "c above 31 bits rejected");
    ASSERT(decode_with_field(ctx, "lnbc", 24, 14, 31, 31, &dec) == 0,
           "c above 64 bits rejected");

    /* Fixed-length fields with another length */
    ASSERT(decode_with_field(ctx, "lnbc", 23, 51, 0, 0, &dec) == 0, "short h rejected");
    ASSERT(decode_with_field(ctx, "lnbc", 19, 54, 0, 0, &dec) == 0, "long n rejected");
    ASSERT(decode_with_field(ctx, "lnbc", 1, 52, 0, 0, &dec) == 0, "second p rejected");
    ASSERT(decode_with_field(ctx, "lnbc", 16, 52, 0, 0, &dec) == 0, "second s rejected");

    /* Feature bits: unknown odd is fine, unknown even is not.
       One group: bit 0 = 1, bit 1 = 2, bit 2 = 4, bit 3 = 8. */
    ASSERT(decode_with_field(ctx, "lnbc", 5, 1, 0, 2, &dec) == 1, "odd bit 1 accepted");
    ASSERT(decode_with_field(ctx, "lnbc", 5, 1, 0, 8, &dec) == 1, "odd bit 3 accepted");
    ASSERT(decode_with_field(ctx, "lnbc", 5, 1, 0, 1, &dec) == 0, "even bit 0 rejected");
    ASSERT(decode_with_field(ctx, "lnbc", 5, 1, 0, 4, &dec) == 0, "even bit 2 rejected");
    ASSERT(decode_with_field(ctx, "lnbc", 5, 2, 8, 0, &dec) == 1, "known bit 8 accepted");
    ASSERT(dec.features == (1u << 8), "bit 8 reported");

    /* An unknown tag is skipped */
    ASSERT(decode_with_field(ctx, "lnbc", 2, 30, 7, 7, &dec) == 1, "unknown tag skipped");

    /* Amounts */
    ASSERT(decode_with_field(ctx, "lnbc1500n", -1, 0, 0, 0, &dec) == 1, "1500n");
    ASSERT(dec.has_amount && dec.amount_msat == 150000, "1500n = 150,000 msat");
    ASSERT(decode_with_field(ctx, "lnbc2", -1, 0, 0, 0, &dec) == 1, "2 BTC");
    ASSERT(dec.amount_msat == 200000000000ULL, "2 BTC in msat");
    ASSERT(decode_with_field(ctx, "lnbc10p", -1, 0, 0, 0, &dec) == 1, "10p");
    ASSERT(dec.amount_msat == 1, "10p = 1 msat");
    ASSERT(decode_with_field(ctx, "lnbc01500n", -1, 0, 0, 0, &dec) == 0,
           "leading zero rejected");
    ASSERT(decode_with_field(ctx, "lnbc0", -1, 0, 0, 0, &dec) == 0, "zero rejected");
    ASSERT(decode_with_field(ctx, "lnbcu", -1, 0, 0, 0, &dec) == 0,
           "multiplier without digits rejected");
    ASSERT(decode_with_field(ctx, "lnbc15p", -1, 0, 0, 0, &dec) == 0,
           "sub-msat precision rejected");
    ASSERT(decode_with_field(ctx, "lnbc1500nn", -1, 0, 0, 0, &dec) == 0,
           "two multipliers rejected");
    ASSERT(decode_with_field(ctx, "lnbc99999999999999999999", -1, 0, 0, 0, &dec) == 0,
           "amount above 64 bits rejected");
    ASSERT(decode_with_field(ctx, "lnbc1000000000", -1, 0, 0, 0, &dec) == 0,
           "amount that overflows in msat rejected");
    ASSERT(decode_with_field(ctx, "lnbc184467440738m", -1, 0, 0, 0, &dec) == 0,
           "amount that overflows after scaling rejected");

    /* Missing p or s */
    {
        unsigned char key[32]; memset(key, 0x42, 32);
        char inv[4096];
        groups_t g; g.n = 0;
        g_put(&g, 1700000000, 7);
        g_field(&g, 16, 52, 0, 0);
        ASSERT(g_finish(ctx, "lnbc", &g, key, inv, sizeof(inv)), "build");
        ASSERT(!bolt11_decode(ctx, inv, &dec), "missing p rejected");
        g.n = 0;
        g_put(&g, 1700000000, 7);
        g_field(&g, 1, 52, 0, 0);
        ASSERT(g_finish(ctx, "lnbc", &g, key, inv, sizeof(inv)), "build");
        ASSERT(!bolt11_decode(ctx, inv, &dec), "missing s rejected");
        /* p or s present but with the wrong length */
        g.n = 0;
        g_put(&g, 1700000000, 7);
        g_field(&g, 1, 51, 0, 0);
        g_field(&g, 16, 52, 0, 0);
        ASSERT(g_finish(ctx, "lnbc", &g, key, inv, sizeof(inv)), "build");
        ASSERT(!bolt11_decode(ctx, inv, &dec), "short p rejected");
        g.n = 0;
        g_put(&g, 1700000000, 7);
        g_field(&g, 1, 52, 0, 0);
        g_field(&g, 16, 53, 0, 0);
        ASSERT(g_finish(ctx, "lnbc", &g, key, inv, sizeof(inv)), "build");
        ASSERT(!bolt11_decode(ctx, inv, &dec), "long s rejected");
        /* A field that runs past the data part */
        g.n = 0;
        g_put(&g, 1700000000, 7);
        g_hash_and_secret(&g);
        g_put(&g, 13, 1); g_put(&g, 900, 2);   /* d claiming 900 groups */
        ASSERT(g_finish(ctx, "lnbc", &g, key, inv, sizeof(inv)), "build");
        ASSERT(!bolt11_decode(ctx, inv, &dec), "truncated field rejected");
    }

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Encoder output is a BOLT #11 invoice; the n field is enforced ---- */
int test_bolt11_encode_signature_and_payee(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");

    bolt11_invoice_t inv;
    memset(&inv, 0, sizeof(inv));
    strcpy(inv.network, "bc");
    inv.amount_msat = 250000000ULL; inv.has_amount = 1;
    inv.timestamp = 1496314658;
    for (int i = 0; i < 32; i++) inv.payment_hash[i] = (unsigned char)i;
    memset(inv.payment_secret, 0x11, 32);
    inv.has_payment_secret = 1;
    strcpy(inv.description, "1 cup coffee");
    inv.expiry = 3000000;                 /* needs five 5-bit groups */
    inv.min_final_cltv_expiry = 40000;    /* needs four */
    inv.features = (1u << BOLT11_FEATURE_VAR_ONION) |
                   (1u << BOLT11_FEATURE_PAYMENT_SECRET);

    /* Signed with the specification's key, the invoice recovers to the
       specification's payee: the signature covers what BOLT #11 says. */
    char enc[2048];
    bolt11_invoice_t dec;
    ASSERT(bolt11_encode(&inv, spec_privkey, ctx, enc, sizeof(enc)), "encode");
    ASSERT(bolt11_decode(ctx, enc, &dec), "decode");
    ASSERT(memcmp(dec.payee_pubkey, spec_payee, 33) == 0, "recovered payee");
    ASSERT(dec.expiry == 3000000, "large expiry round-trips");
    ASSERT(dec.min_final_cltv_expiry == 40000, "large min_final_cltv round-trips");
    ASSERT(dec.features == inv.features, "feature bits round-trip");

    /* Signed by another key, it recovers to another payee */
    {
        unsigned char k2[32]; memset(k2, 0x07, 32);
        ASSERT(bolt11_encode(&inv, k2, ctx, enc, sizeof(enc)), "encode, other key");
        ASSERT(bolt11_decode(ctx, enc, &dec), "decode, other key");
        ASSERT(memcmp(dec.payee_pubkey, spec_payee, 33) != 0, "different payee");
    }

    /* With n naming the signer the invoice verifies... */
    memcpy(inv.payee_pubkey, spec_payee, 33);
    ASSERT(bolt11_encode(&inv, spec_privkey, ctx, enc, sizeof(enc)), "encode with n");
    ASSERT(bolt11_decode(ctx, enc, &dec), "decode with n");
    ASSERT(memcmp(dec.payee_pubkey, spec_payee, 33) == 0, "payee from n");

    /* ...and with n naming anyone else it does not. */
    unsigned char other[32]; memset(other, 0x07, 32);
    ASSERT(bolt11_encode(&inv, other, ctx, enc, sizeof(enc)), "encode, other signer");
    ASSERT(!bolt11_decode(ctx, enc, &dec), "signature not by the named payee rejected");

    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- The checksum of a long invoice is verified like any other ---- */
int test_bolt11_long_invoice_checksum(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    ASSERT(ctx, "ctx");
    unsigned char key[32]; memset(key, 0x42, 32);
    bolt11_invoice_t dec;

    /* Well over a thousand data characters: two unknown fields of 900
       groups each on top of the required ones */
    groups_t g; g.n = 0;
    g_put(&g, 1700000000, 7);
    g_hash_and_secret(&g);
    g_field(&g, 2, 900, 7, 7);
    g_field(&g, 2, 900, 9, 9);
    static char inv[4096];
    ASSERT(g_finish(ctx, "lnbc15u", &g, key, inv, sizeof(inv)), "build");
    size_t len = strlen(inv);
    ASSERT(len > 2000, "invoice is long");
    ASSERT(bolt11_decode(ctx, inv, &dec), "long invoice decodes");
    ASSERT(dec.amount_msat == 1500000, "amount");

    /* Any change to it is caught by the checksum */
    static char bad[4096];
    strcpy(bad, inv);
    bad[len / 2] = bad[len / 2] == 'q' ? 'p' : 'q';
    ASSERT(!bolt11_decode(ctx, bad, &dec), "altered long invoice rejected");

    /* Including a checksum of all zeros */
    strcpy(bad, inv);
    memset(bad + len - 6, 'q', 6);
    ASSERT(!bolt11_decode(ctx, bad, &dec), "zero checksum on a long invoice rejected");
    strcpy(bad, inv);
    bad[len - 1] = bad[len - 1] == 'q' ? 'p' : 'q';
    ASSERT(!bolt11_decode(ctx, bad, &dec), "wrong last checksum character rejected");

    secp256k1_context_destroy(ctx);
    return 1;
}
