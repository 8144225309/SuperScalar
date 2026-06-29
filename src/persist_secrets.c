/* SF-WT-TRUSTLESS Phase 2c PR-E.2 (#248) — secret-bearing persist readers.
 *
 * These functions read revocation secrets, channel basepoints, and other
 * key material from lsp.db.  They are extracted from src/persist.c into
 * their own translation unit so the standalone trustless watchtower
 * binary (superscalar_watchtower) can be built without linking these
 * symbols.  The CMake superscalar_secrets library bundles this TU + the
 * auto-settle TU; LSP/client/tests/bridge link superscalar_secrets,
 * superscalar_watchtower does not.
 *
 * After linking:
 *   $ nm -D --defined-only build-release/superscalar_watchtower \
 *       | grep -E "persist_load_(basepoints|revocations_flat|channel_for_watchtower|flat_secrets|commitment_sig)"
 *   (empty)
 *
 * Function declarations stay in include/superscalar/persist.h — only
 * the bodies move.  Callers (LSP, client, tests, bridge) continue to
 * use the same API.
 */

#include "superscalar/persist.h"
#include "superscalar/channel.h"
#include "superscalar/sha256.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifndef BASEPOINT_DIAG
#define BASEPOINT_DIAG 0
#endif

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);

int persist_load_revocations_flat(persist_t *p, uint32_t channel_id,
                                    unsigned char (*secrets_out)[32],
                                    uint8_t *valid_out, size_t max,
                                    size_t *count_out) {
    if (!p || !p->db || !secrets_out || !valid_out) return 0;

    memset(valid_out, 0, max);

    const char *sql =
        "SELECT commit_num, secret FROM revocation_secrets "
        "WHERE channel_id = ? ORDER BY commit_num ASC;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        uint64_t commit_num = (uint64_t)sqlite3_column_int64(stmt, 0);
        const char *stored = (const char *)sqlite3_column_text(stmt, 1);
        if (!stored || commit_num >= max) continue;
        char *hex = NULL;                                  /* #327b: open at rest */
        if (!persist_open_text(p, stored, &hex) || !hex) continue;
        if (hex_decode(hex, secrets_out[commit_num], 32) == 32) {
            valid_out[commit_num] = 1;
            count++;
        }
        memset(hex, 0, strlen(hex)); free(hex);
    }

    sqlite3_finalize(stmt);
    if (count_out) *count_out = count;
    return 1;
}
int persist_load_basepoints(persist_t *p, uint32_t channel_id,
                             unsigned char local_secrets[4][32],
                             unsigned char remote_bps[4][33]) {
    if (!p || !p->db || !local_secrets || !remote_bps) return 0;

    const char *sql =
        "SELECT local_payment_secret, local_delayed_secret, "
        "local_revocation_secret, local_htlc_secret, "
        "remote_payment_bp, remote_delayed_bp, "
        "remote_revocation_bp, remote_htlc_bp "
        "FROM channel_basepoints WHERE channel_id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return 0;
    }

    /* Decode 4 local secrets (#327b: opened from at-rest sealing; legacy
       plaintext passes through). */
    for (int i = 0; i < 4; i++) {
        const char *stored = (const char *)sqlite3_column_text(stmt, i);
        char *hex = NULL;
        if (!stored || !persist_open_text(p, stored, &hex) || !hex ||
            hex_decode(hex, local_secrets[i], 32) != 32) {
            if (hex) { memset(hex, 0, strlen(hex)); free(hex); }
            sqlite3_finalize(stmt);
            return 0;
        }
        memset(hex, 0, strlen(hex)); free(hex);
    }

    /* Decode 4 remote pubkeys */
    for (int i = 0; i < 4; i++) {
        const char *hex = (const char *)sqlite3_column_text(stmt, 4 + i);
        if (!hex || hex_decode(hex, remote_bps[i], 33) != 33) {
            sqlite3_finalize(stmt);
            return 0;
        }
    }

    sqlite3_finalize(stmt);

#if BASEPOINT_DIAG
    fprintf(stderr, "DIAG basepoint: loaded from DB channel_id=%u\n", channel_id);
#endif

    return 1;
}
int persist_load_channel_for_watchtower(persist_t *p, uint32_t channel_id,
                                         secp256k1_context *ctx,
                                         channel_t *out_ch) {
    if (!p || !p->db || !ctx || !out_ch) return 0;

    /* Per-channel balances + commitment number */
    uint64_t local_amt = 0, remote_amt = 0, cn = 0;
    if (!persist_load_channel_state(p, channel_id, &local_amt, &remote_amt, &cn))
        return 0;

    /* Local secrets + remote basepoints (all four categories) */
    unsigned char local_secrets[4][32];
    unsigned char remote_bps_ser[4][33];
    if (!persist_load_basepoints(p, channel_id, local_secrets, remote_bps_ser)) {
        memset(local_secrets, 0, sizeof(local_secrets));
        return 0;
    }

    /* Allocate the same dynamic arrays channel_init() sets up.  Doing this
       directly avoids reimplementing channel_init's full ceremony (funding
       keyagg, nonces, etc.) which is out of scope for penalty signing. */
    memset(out_ch, 0, sizeof(*out_ch));
    out_ch->ctx = ctx;

    out_ch->htlcs = calloc(DEFAULT_HTLCS_CAP, sizeof(htlc_t));
    out_ch->local_pcs = calloc(512, 32);
    out_ch->received_revocations = calloc(512, 32);
    out_ch->received_revocation_valid = calloc(512, 1);
    if (!out_ch->htlcs || !out_ch->local_pcs ||
        !out_ch->received_revocations || !out_ch->received_revocation_valid) {
        free(out_ch->htlcs);
        free(out_ch->local_pcs);
        free(out_ch->received_revocations);
        free(out_ch->received_revocation_valid);
        memset(out_ch, 0, sizeof(*out_ch));
        memset(local_secrets, 0, sizeof(local_secrets));
        return 0;
    }
    out_ch->htlcs_cap = DEFAULT_HTLCS_CAP;
    out_ch->local_pcs_cap = 512;
    out_ch->revocations_cap = 512;

    /* Install local basepoints (payment, delayed, revocation) + htlc.
       channel_set_local_basepoints derives the three pubkeys and zeroes
       on any failure. */
    if (!channel_set_local_basepoints(out_ch,
                                       local_secrets[0],
                                       local_secrets[1],
                                       local_secrets[2]) ||
        !channel_set_local_htlc_basepoint(out_ch, local_secrets[3])) {
        memset(local_secrets, 0, sizeof(local_secrets));
        free(out_ch->htlcs);
        free(out_ch->local_pcs);
        free(out_ch->received_revocations);
        free(out_ch->received_revocation_valid);
        memset(out_ch, 0, sizeof(*out_ch));
        return 0;
    }
    memset(local_secrets, 0, sizeof(local_secrets));

    /* Parse remote basepoint pubkeys from serialized form */
    secp256k1_pubkey remote_pay, remote_delay, remote_revoc, remote_htlc;
    if (!secp256k1_ec_pubkey_parse(ctx, &remote_pay, remote_bps_ser[0], 33) ||
        !secp256k1_ec_pubkey_parse(ctx, &remote_delay, remote_bps_ser[1], 33) ||
        !secp256k1_ec_pubkey_parse(ctx, &remote_revoc, remote_bps_ser[2], 33) ||
        !secp256k1_ec_pubkey_parse(ctx, &remote_htlc, remote_bps_ser[3], 33)) {
        free(out_ch->htlcs);
        free(out_ch->local_pcs);
        free(out_ch->received_revocations);
        free(out_ch->received_revocation_valid);
        memset(out_ch, 0, sizeof(*out_ch));
        return 0;
    }
    channel_set_remote_basepoints(out_ch, &remote_pay, &remote_delay,
                                   &remote_revoc);
    channel_set_remote_htlc_basepoint(out_ch, &remote_htlc);

    /* Received revocation secrets (for penalty signing on a breach) */
    size_t rev_count = 0;
    persist_load_revocations_flat(p, channel_id,
                                   out_ch->received_revocations,
                                   out_ch->received_revocation_valid,
                                   out_ch->revocations_cap, &rev_count);

    /* Balances + config from the channels table (schema v18+). */
    out_ch->local_amount = local_amt;
    out_ch->remote_amount = remote_amt;
    out_ch->commitment_number = cn;

    /* Load per-channel config (to_self_delay, fee_rate, use_revocation_leaf,
       funding_pending_reorg).  Schema v18 added the first three; v31 added
       the reorg flag.  Older DBs get the migration defaults (all zero/
       sentinel). */
    {
        const char *cfg_sql =
            "SELECT to_self_delay, fee_rate_sat_per_kvb, use_revocation_leaf, "
            "       funding_pending_reorg "
            "FROM channels WHERE id = ?;";
        sqlite3_stmt *cfg_stmt;
        if (sqlite3_prepare_v2(p->db, cfg_sql, -1, &cfg_stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int(cfg_stmt, 1, (int)channel_id);
            if (sqlite3_step(cfg_stmt) == SQLITE_ROW) {
                out_ch->to_self_delay = (uint32_t)sqlite3_column_int(cfg_stmt, 0);
                out_ch->fee_rate_sat_per_kvb = (uint64_t)sqlite3_column_int64(cfg_stmt, 1);
                out_ch->use_revocation_leaf = sqlite3_column_int(cfg_stmt, 2);
                out_ch->funding_pending_reorg = sqlite3_column_int(cfg_stmt, 3);
            } else {
                out_ch->to_self_delay = CHANNEL_DEFAULT_CSV_DELAY;
                out_ch->fee_rate_sat_per_kvb = 1000;
                out_ch->use_revocation_leaf = 0;
                out_ch->funding_pending_reorg = 0;
            }
            sqlite3_finalize(cfg_stmt);
        } else {
            out_ch->to_self_delay = CHANNEL_DEFAULT_CSV_DELAY;
            out_ch->fee_rate_sat_per_kvb = 1000;
            out_ch->use_revocation_leaf = 0;
            out_ch->funding_pending_reorg = 0;
        }
    }

    return 1;
}
size_t persist_load_flat_secrets(persist_t *p, uint32_t factory_id,
                                  unsigned char secrets_out[][32],
                                  size_t max_secrets) {
    if (!p || !p->db || !secrets_out || max_secrets == 0) return 0;

    const char *sql =
        "SELECT epoch, secret FROM factory_revocation_secrets "
        "WHERE factory_id = ? ORDER BY epoch;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)factory_id);

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_secrets) {
        int epoch = sqlite3_column_int(stmt, 0);
        const char *stored = (const char *)sqlite3_column_text(stmt, 1);
        if (!stored || epoch < 0 || (size_t)epoch >= max_secrets) continue;
        char *hex = NULL;                                  /* #327b: open at rest */
        if (!persist_open_text(p, stored, &hex) || !hex) continue;
        if (hex_decode(hex, secrets_out[epoch], 32) == 32) count++;
        memset(hex, 0, strlen(hex)); free(hex);
    }
    sqlite3_finalize(stmt);
    return count;
}
int persist_load_commitment_sig(persist_t *p, uint32_t channel_id,
                                 uint64_t *commitment_number_out,
                                 unsigned char *sig64_out,
                                 unsigned char *signed_tx_out,
                                 size_t *signed_tx_len_out,
                                 size_t max_tx_len)
{
    if (!p || !p->db) return 0;

    const char *sql =
        "SELECT commitment_number, sig64_hex, signed_tx_hex "
        "FROM signed_commitments WHERE channel_id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);

    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        if (commitment_number_out)
            *commitment_number_out = (uint64_t)sqlite3_column_int64(stmt, 0);

        const char *sig_hex = (const char *)sqlite3_column_text(stmt, 1);
        if (sig64_out && sig_hex && strlen(sig_hex) == 128)
            hex_decode(sig_hex, sig64_out, 64);

        const char *tx_hex = (const char *)sqlite3_column_text(stmt, 2);
        if (signed_tx_out && tx_hex) {
            size_t hex_len = strlen(tx_hex);
            size_t raw_len = hex_len / 2;
            if (raw_len <= max_tx_len) {
                hex_decode(tx_hex, signed_tx_out, raw_len);
                if (signed_tx_len_out) *signed_tx_len_out = raw_len;
            }
        } else if (signed_tx_len_out && !signed_tx_out) {
            const char *txh = (const char *)sqlite3_column_text(stmt, 2);
            if (txh) *signed_tx_len_out = strlen(txh) / 2;
        }

        found = 1;
    }
    sqlite3_finalize(stmt);
    return found;
}
