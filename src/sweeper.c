/*
 * sweeper.c — Automatic sweep of timelocked/intermediate outputs to wallet
 *
 * After a factory force-close, the recovery path broadcasts the tree but stops
 * at leaf outputs. The sweeper picks up from there:
 *   1. Broadcasts commitment TXs when leaf outputs confirm
 *   2. Sweeps to_local outputs after CSV delay
 *   3. Sweeps penalty TX outputs (immediate)
 *   4. Sweeps HTLC timeout TX outputs after CSV delay
 *
 * Runs inside the watchtower check cycle (every 60s in daemon mode).
 */

#include "superscalar/sweeper.h"
#include "superscalar/sha256.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

/* ------------------------------------------------------------------ */
/* Sweep TX builders                                                    */
/* ------------------------------------------------------------------ */

/*
 * Build a key-path-only P2TR spend.
 * Used for penalty outputs and HTLC timeout outputs, which both pay to
 * P2TR(tweaked local_payment_basepoint).
 */
static int build_p2tr_keypath_sweep(
    secp256k1_context *ctx,
    tx_buf_t *sweep_tx_out,
    const unsigned char *source_txid32,
    uint32_t source_vout,
    uint64_t source_amount,
    const unsigned char *source_spk,
    size_t source_spk_len,
    const unsigned char *internal_secret32,
    const secp256k1_pubkey *internal_pubkey,
    const unsigned char *dest_spk,
    size_t dest_spk_len,
    uint64_t fee_per_kvb)
{
    /* Key-path P2TR spend: ~112 vB (1-in key-path, 1-out P2TR) */
    uint64_t vsize = 112;
    uint64_t fee = (fee_per_kvb * vsize + 999) / 1000;
    if (source_amount <= fee + CHANNEL_DUST_LIMIT_SATS)
        return 0;  /* uneconomical */
    uint64_t out_amount = source_amount - fee;

    tx_output_t output;
    memcpy(output.script_pubkey, dest_spk, dest_spk_len);
    output.script_pubkey_len = dest_spk_len;
    output.amount_sats = out_amount;

    /* Build the tweaked keypair for signing */
    secp256k1_xonly_pubkey internal_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &internal_xonly, NULL,
                                             internal_pubkey))
        return 0;

    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &internal_xonly))
        return 0;

    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);

    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, internal_secret32))
        return 0;
    if (!secp256k1_keypair_xonly_tweak_add(ctx, &kp, tweak))
        return 0;

    /* Build unsigned TX */
    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 256);
    unsigned char txid[32];
    if (!build_unsigned_tx_v(&unsigned_tx, txid,
                              source_txid32, source_vout,
                              0xFFFFFFFD, &output, 1, 2)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* Sighash + sign */
    unsigned char sighash[32];
    if (!compute_taproot_sighash(sighash, unsigned_tx.data, unsigned_tx.len,
                                  0, source_spk, source_spk_len,
                                  source_amount, 0xFFFFFFFD)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    unsigned char sig[64];
    if (!secp256k1_schnorrsig_sign32(ctx, sig, sighash, &kp, NULL)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* Finalize with key-path witness */
    if (!finalize_signed_tx(sweep_tx_out, unsigned_tx.data, unsigned_tx.len, sig)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    tx_buf_free(&unsigned_tx);
    memset(&kp, 0, sizeof(kp));
    return 1;
}

int channel_build_penalty_output_sweep(const channel_t *ch,
    tx_buf_t *sweep_tx_out,
    const unsigned char *penalty_txid,
    uint32_t penalty_vout, uint64_t penalty_amount,
    const unsigned char *dest_spk, size_t dest_spk_len)
{
    /* Penalty TX output is P2TR(tweaked local_payment_basepoint).
       Reconstruct the source SPK to compute sighash. */
    secp256k1_xonly_pubkey xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &xonly, NULL,
                                             &ch->local_payment_basepoint))
        return 0;

    unsigned char ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ch->ctx, ser, &xonly))
        return 0;
    unsigned char tweak[32];
    sha256_tagged("TapTweak", ser, 32, tweak);

    secp256k1_pubkey tweaked_full;
    if (!secp256k1_xonly_pubkey_tweak_add(ch->ctx, &tweaked_full, &xonly, tweak))
        return 0;
    secp256k1_xonly_pubkey tweaked;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &tweaked, NULL, &tweaked_full))
        return 0;

    unsigned char source_spk[34];
    build_p2tr_script_pubkey(source_spk, &tweaked);

    return build_p2tr_keypath_sweep(ch->ctx, sweep_tx_out,
        penalty_txid, penalty_vout, penalty_amount,
        source_spk, 34,
        ch->local_payment_basepoint_secret,
        &ch->local_payment_basepoint,
        dest_spk, dest_spk_len,
        ch->fee_rate_sat_per_kvb);
}

int channel_build_htlc_output_sweep(const channel_t *ch,
    tx_buf_t *sweep_tx_out,
    const unsigned char *htlc_timeout_txid,
    uint32_t htlc_vout, uint64_t htlc_amount,
    const unsigned char *dest_spk, size_t dest_spk_len)
{
    /* HTLC timeout/success TX output is also P2TR(tweaked local_payment_basepoint).
       Same sweep pattern as penalty output. */
    return channel_build_penalty_output_sweep(ch, sweep_tx_out,
        htlc_timeout_txid, htlc_vout, htlc_amount,
        dest_spk, dest_spk_len);
}

int channel_build_to_local_sweep(const channel_t *ch, tx_buf_t *sweep_tx_out,
    const unsigned char *commitment_txid,
    uint32_t to_local_vout, uint64_t to_local_amount,
    const unsigned char *dest_spk, size_t dest_spk_len)
{
    /* The to_local output is P2TR(revocation_key, [csv_leaf, ...]).
       We spend via the csv_leaf script path after CSV delay.
       The script is: <delay> OP_CSV OP_DROP <delayed_payment_key> OP_CHECKSIG */

    /* Derive delayed_payment_key from basepoint + PCP */
    secp256k1_pubkey pcp;
    if (!channel_get_per_commitment_point(ch, ch->commitment_number, &pcp))
        return 0;

    secp256k1_pubkey delayed_pubkey;
    if (!channel_derive_pubkey(ch->ctx, &delayed_pubkey,
                                &ch->local_delayed_payment_basepoint, &pcp))
        return 0;

    secp256k1_xonly_pubkey delayed_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &delayed_xonly, NULL,
                                             &delayed_pubkey))
        return 0;

    /* Derive revocation pubkey (internal key for to_local) */
    secp256k1_pubkey revocation_pubkey;
    if (!channel_derive_revocation_pubkey(ch->ctx, &revocation_pubkey,
                                           &ch->remote_revocation_basepoint, &pcp))
        return 0;

    secp256k1_xonly_pubkey revocation_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &revocation_xonly, NULL,
                                             &revocation_pubkey))
        return 0;

    /* Build the csv_leaf exactly as commitment TX does */
    tapscript_leaf_t csv_leaf;
    if (!tapscript_build_csv_delay(&csv_leaf, ch->to_self_delay,
                                    &delayed_xonly, ch->ctx))
        return 0;

    /* Build taptree merkle root (must match commitment TX construction) */
    unsigned char merkle_root[32];
    tapscript_leaf_t revoc_leaf;
    int has_revoc_leaf = ch->use_revocation_leaf;
    if (has_revoc_leaf) {
        tapscript_leaf_t leaves[2];
        leaves[0] = csv_leaf;
        if (!tapscript_build_revocation_checksig(&leaves[1], &revocation_xonly,
                                                  ch->ctx))
            return 0;
        revoc_leaf = leaves[1];
        tapscript_merkle_root(merkle_root, leaves, 2);
    } else {
        tapscript_merkle_root(merkle_root, &csv_leaf, 1);
    }

    /* Compute tweaked output key + parity (for control block) */
    secp256k1_xonly_pubkey to_local_tweaked;
    int output_parity = 0;
    if (!tapscript_tweak_pubkey(ch->ctx, &to_local_tweaked, &output_parity,
                                 &revocation_xonly, merkle_root))
        return 0;

    /* Reconstruct to_local SPK for sighash */
    unsigned char source_spk[34];
    build_p2tr_script_pubkey(source_spk, &to_local_tweaked);

    /* Fee: ~200 vB (script-path spend with CSV) */
    uint64_t vsize = 200;
    uint64_t fee = (ch->fee_rate_sat_per_kvb * vsize + 999) / 1000;
    if (to_local_amount <= fee + CHANNEL_DUST_LIMIT_SATS)
        return 0;
    uint64_t out_amount = to_local_amount - fee;

    tx_output_t output;
    memcpy(output.script_pubkey, dest_spk, dest_spk_len);
    output.script_pubkey_len = dest_spk_len;
    output.amount_sats = out_amount;

    /* nSequence = to_self_delay (CSV) */
    uint32_t nsequence = ch->to_self_delay;

    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 256);
    unsigned char txid[32];
    if (!build_unsigned_tx_v(&unsigned_tx, txid,
                              commitment_txid, to_local_vout,
                              nsequence, &output, 1, 2)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* Tapscript sighash for csv_leaf */
    unsigned char sighash[32];
    if (!compute_tapscript_sighash(sighash, unsigned_tx.data, unsigned_tx.len,
                                    0, source_spk, 34,
                                    to_local_amount, nsequence,
                                    &csv_leaf)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* Derive delayed_payment private key for signing */
    unsigned char delayed_secret[32];
    if (!channel_derive_privkey(ch->ctx, delayed_secret,
                                 ch->local_delayed_payment_basepoint_secret, &pcp)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    secp256k1_keypair delayed_kp;
    if (!secp256k1_keypair_create(ch->ctx, &delayed_kp, delayed_secret)) {
        memset(delayed_secret, 0, 32);
        tx_buf_free(&unsigned_tx);
        return 0;
    }
    memset(delayed_secret, 0, 32);

    unsigned char sig[64];
    if (!secp256k1_schnorrsig_sign32(ch->ctx, sig, sighash, &delayed_kp, NULL)) {
        memset(&delayed_kp, 0, sizeof(delayed_kp));
        tx_buf_free(&unsigned_tx);
        return 0;
    }
    memset(&delayed_kp, 0, sizeof(delayed_kp));

    /* Build control block for script-path spend.
       1-leaf tree: 33 bytes.  2-leaf tree: 65 bytes (includes sibling hash). */
    unsigned char control_block[65];
    size_t cb_len = 0;
    if (has_revoc_leaf) {
        /* csv_leaf is leaf[0], spending it with sibling = revoc_leaf */
        if (!tapscript_build_control_block_2leaf(control_block, &cb_len,
                                                  output_parity, &revocation_xonly,
                                                  &revoc_leaf, ch->ctx)) {
            tx_buf_free(&unsigned_tx);
            return 0;
        }
    } else {
        if (!tapscript_build_control_block(control_block, &cb_len,
                                            output_parity, &revocation_xonly,
                                            ch->ctx)) {
            tx_buf_free(&unsigned_tx);
            return 0;
        }
    }

    /* Finalize: witness = [sig, script, control_block] */
    if (!finalize_script_path_tx(sweep_tx_out,
                                  unsigned_tx.data, unsigned_tx.len,
                                  sig, csv_leaf.script, csv_leaf.script_len,
                                  control_block, cb_len)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    tx_buf_free(&unsigned_tx);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Sweeper lifecycle                                                    */
/* ------------------------------------------------------------------ */

int sweeper_init(sweeper_t *sw, secp256k1_context *ctx,
                 const unsigned char *lsp_seckey32,
                 const unsigned char *dest_spk, size_t dest_spk_len,
                 chain_backend_t *chain, persist_t *db,
                 fee_estimator_t *fee)
{
    if (!sw || !ctx) return 0;
    memset(sw, 0, sizeof(*sw));

    sw->ctx = ctx;
    sw->chain = chain;
    sw->db = db;
    sw->fee = fee;

    if (lsp_seckey32)
        memcpy(sw->lsp_seckey, lsp_seckey32, 32);
    if (dest_spk && dest_spk_len <= 34) {
        memcpy(sw->dest_spk, dest_spk, dest_spk_len);
        sw->dest_spk_len = dest_spk_len;
    }

    sw->entries_cap = SWEEPER_MAX_ENTRIES;
    sw->entries = calloc(sw->entries_cap, sizeof(sweep_entry_t));
    if (!sw->entries) return 0;
    sw->n_entries = 0;

    /* Load pending sweeps from DB */
    if (db && db->db) {
        persist_load_sweeps(db, sw->entries, &sw->n_entries, sw->entries_cap);
    }

    return 1;
}

void sweeper_cleanup(sweeper_t *sw)
{
    if (!sw) return;
    free(sw->entries);
    sw->entries = NULL;
    sw->n_entries = 0;
    memset(sw->lsp_seckey, 0, 32);
}

int sweeper_add(sweeper_t *sw, sweep_type_t type,
                const unsigned char *source_txid32,
                uint32_t source_vout, uint64_t amount_sats,
                uint32_t csv_delay,
                uint32_t channel_id, uint32_t factory_id,
                uint64_t commitment_number)
{
    if (!sw || sw->n_entries >= sw->entries_cap) return 0;

    sweep_entry_t *e = &sw->entries[sw->n_entries];
    memset(e, 0, sizeof(*e));

    e->type = type;
    e->state = SWEEP_PENDING;
    memcpy(e->source_txid, source_txid32, 32);
    e->source_vout = source_vout;
    e->amount_sats = amount_sats;
    e->csv_delay = csv_delay;
    e->channel_id = channel_id;
    e->factory_id = factory_id;
    e->commitment_number = commitment_number;

    sw->n_entries++;

    /* Persist */
    if (sw->db)
        persist_save_sweep(sw->db, e);

    return 1;
}

void sweeper_remove_factory(sweeper_t *sw, uint32_t factory_id)
{
    if (!sw) return;
    size_t dst = 0;
    for (size_t i = 0; i < sw->n_entries; i++) {
        if (sw->entries[i].factory_id != factory_id) {
            if (dst != i)
                sw->entries[dst] = sw->entries[i];
            dst++;
        }
    }
    sw->n_entries = dst;

    if (sw->db)
        persist_delete_sweeps_for_factory(sw->db, factory_id);
}

/* ------------------------------------------------------------------ */
/* Sweep check cycle                                                    */
/* ------------------------------------------------------------------ */

int sweeper_check(sweeper_t *sw)
{
    if (!sw || !sw->chain || sw->n_entries == 0) return 0;

    int n_broadcast = 0;
    uint32_t current_height = sw->chain->get_block_height(sw->chain);

    for (size_t i = 0; i < sw->n_entries; ) {
        sweep_entry_t *e = &sw->entries[i];

        /* Check if sweep TX already confirmed → remove entry */
        if (e->state == SWEEP_BROADCAST && e->sweep_txid[0]) {
            int confs = sw->chain->get_confirmations(sw->chain, e->sweep_txid);
            if (confs >= 3) {
                /* Confirmed — remove entry */
                e->state = SWEEP_CONFIRMED;
                if (sw->db) persist_delete_sweep(sw->db, e->id);
                sw->entries[i] = sw->entries[--sw->n_entries];
                continue;  /* recheck this index */
            }
            if (confs < 0) {
                /* TX vanished (reorg?) — reset to pending for retry */
                e->state = SWEEP_PENDING;
                e->sweep_txid[0] = '\0';
                e->confirmed_height = 0;
            }
        }

        /* Check source TX confirmation status */
        if (e->confirmed_height == 0) {
            unsigned char txid_display[32];
            memcpy(txid_display, e->source_txid, 32);
            reverse_bytes(txid_display, 32);
            char txid_hex[65];
            hex_encode(txid_display, 32, txid_hex);

            int confs = sw->chain->get_confirmations(sw->chain, txid_hex);
            if (confs >= 1) {
                e->confirmed_height = current_height - (uint32_t)confs + 1;
            } else {
                i++;
                continue;  /* source not yet confirmed */
            }
        }

        /* Check CSV delay */
        if (e->csv_delay > 0) {
            uint32_t mature_height = e->confirmed_height + e->csv_delay;
            if (current_height < mature_height) {
                i++;
                continue;  /* CSV not yet expired */
            }
        }

        /* Ready to sweep */
        if (e->state == SWEEP_PENDING) {
            /* We don't build the actual sweep TX here — that requires
               channel context which the sweeper doesn't hold.  Instead,
               the sweeper is a tracking layer; the actual sweep TX is
               built by the integration point (watchtower / daemon loop)
               which has channel pointers.

               For now, mark as ready and log. The integration in
               watchtower_check() will call the channel_build_*_sweep()
               functions with proper channel context. */

            printf("sweeper: entry ready for sweep — type=%d source_vout=%u "
                   "amount=%llu csv=%u confirmed_at=%u current=%u\n",
                   e->type, e->source_vout,
                   (unsigned long long)e->amount_sats,
                   e->csv_delay, e->confirmed_height, current_height);
            fflush(stdout);
            n_broadcast++;
            /* Actual broadcast happens in watchtower integration */
        }

        i++;
    }

    return n_broadcast;
}

/* ------------------------------------------------------------------ */
/* Persistence helpers                                                  */
/* ------------------------------------------------------------------ */

static const char *sweep_type_str(sweep_type_t t) {
    switch (t) {
        case SWEEP_COMMITMENT_BROADCAST: return "commitment";
        case SWEEP_TO_LOCAL: return "to_local";
        case SWEEP_PENALTY_OUTPUT: return "penalty";
        case SWEEP_HTLC_TIMEOUT_OUTPUT: return "htlc_timeout";
    }
    return "unknown";
}

static sweep_type_t sweep_type_from_str(const char *s) {
    if (!s) return SWEEP_TO_LOCAL;
    if (strcmp(s, "commitment") == 0) return SWEEP_COMMITMENT_BROADCAST;
    if (strcmp(s, "penalty") == 0) return SWEEP_PENALTY_OUTPUT;
    if (strcmp(s, "htlc_timeout") == 0) return SWEEP_HTLC_TIMEOUT_OUTPUT;
    return SWEEP_TO_LOCAL;
}

int persist_save_sweep(persist_t *p, const sweep_entry_t *e)
{
    if (!p || !p->db || !e) return 0;

    const char *sql =
        "INSERT OR REPLACE INTO pending_sweeps "
        "(sweep_type, state, source_txid, source_vout, amount_sats, "
        " csv_delay, confirmed_height, channel_id, factory_id, "
        " commitment_number, sweep_txid) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    /* source txid → display-order hex */
    unsigned char txid_display[32];
    memcpy(txid_display, e->source_txid, 32);
    reverse_bytes(txid_display, 32);
    char txid_hex[65];
    hex_encode(txid_display, 32, txid_hex);

    sqlite3_bind_text(stmt, 1, sweep_type_str(e->type), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, (int)e->state);
    sqlite3_bind_text(stmt, 3, txid_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, (int)e->source_vout);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)e->amount_sats);
    sqlite3_bind_int(stmt, 6, (int)e->csv_delay);
    sqlite3_bind_int(stmt, 7, (int)e->confirmed_height);
    sqlite3_bind_int(stmt, 8, (int)e->channel_id);
    sqlite3_bind_int(stmt, 9, (int)e->factory_id);
    sqlite3_bind_int64(stmt, 10, (sqlite3_int64)e->commitment_number);
    sqlite3_bind_text(stmt, 11, e->sweep_txid[0] ? e->sweep_txid : "", -1, SQLITE_TRANSIENT);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

int persist_load_sweeps(persist_t *p, sweep_entry_t *entries,
                         size_t *n_entries, size_t max_entries)
{
    if (!p || !p->db || !entries || !n_entries) return 0;
    *n_entries = 0;

    const char *sql =
        "SELECT id, sweep_type, state, source_txid, source_vout, amount_sats, "
        "       csv_delay, confirmed_height, channel_id, factory_id, "
        "       commitment_number, sweep_txid "
        "FROM pending_sweeps WHERE state < 2 ORDER BY id;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    while (sqlite3_step(stmt) == SQLITE_ROW && *n_entries < max_entries) {
        sweep_entry_t *e = &entries[*n_entries];
        memset(e, 0, sizeof(*e));

        e->id = (uint32_t)sqlite3_column_int(stmt, 0);
        e->type = sweep_type_from_str((const char *)sqlite3_column_text(stmt, 1));
        e->state = (sweep_state_t)sqlite3_column_int(stmt, 2);

        /* Decode source txid (display-order hex → internal byte order) */
        const char *txid_hex = (const char *)sqlite3_column_text(stmt, 3);
        if (txid_hex && strlen(txid_hex) == 64) {
            hex_decode(txid_hex, e->source_txid, 32);
            reverse_bytes(e->source_txid, 32);
        }

        e->source_vout = (uint32_t)sqlite3_column_int(stmt, 4);
        e->amount_sats = (uint64_t)sqlite3_column_int64(stmt, 5);
        e->csv_delay = (uint32_t)sqlite3_column_int(stmt, 6);
        e->confirmed_height = (uint32_t)sqlite3_column_int(stmt, 7);
        e->channel_id = (uint32_t)sqlite3_column_int(stmt, 8);
        e->factory_id = (uint32_t)sqlite3_column_int(stmt, 9);
        e->commitment_number = (uint64_t)sqlite3_column_int64(stmt, 10);

        const char *stxid = (const char *)sqlite3_column_text(stmt, 11);
        if (stxid && stxid[0])
            strncpy(e->sweep_txid, stxid, 64);

        (*n_entries)++;
    }

    sqlite3_finalize(stmt);
    return 1;
}

int persist_delete_sweep(persist_t *p, uint32_t sweep_id)
{
    if (!p || !p->db) return 0;

    const char *sql = "DELETE FROM pending_sweeps WHERE id = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)sweep_id);
    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

int persist_delete_sweeps_for_factory(persist_t *p, uint32_t factory_id)
{
    if (!p || !p->db) return 0;

    const char *sql = "DELETE FROM pending_sweeps WHERE factory_id = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)factory_id);
    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}
