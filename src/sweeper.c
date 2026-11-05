/*
 * sweeper.c — Automatic sweep of timelocked/intermediate outputs to wallet
 *
 * After a factory force-close, the recovery path broadcasts the tree but stops
 * at leaf outputs. The sweeper picks up from there:
 *   1. Broadcasts commitment TXs when leaf outputs confirm
 *   2. Sweeps to_local outputs after CSV delay
 *   3. Sweeps penalty TX outputs (immediate)
 *   4. Sweeps HTLC timeout TX outputs after CSV delay
 *   5. Claims HTLCs we hold the preimage for when a commitment holding
 *      them confirms, then sweeps the claim's output
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

    /* SWEEPER_MAX_ENTRIES is the initial capacity; sweeper_add grows it.
       Size for every persisted row so none is silently left unloaded. */
    sw->entries_cap = SWEEPER_MAX_ENTRIES;
    if (db && db->db) {
        sqlite3_stmt *cs;
        if (sqlite3_prepare_v2(db->db,
                "SELECT COUNT(*) FROM pending_sweeps WHERE state < 2;",
                -1, &cs, NULL) == SQLITE_OK) {
            if (sqlite3_step(cs) == SQLITE_ROW) {
                size_t n = (size_t)sqlite3_column_int64(cs, 0);
                if (n > sw->entries_cap) sw->entries_cap = n;
            }
            sqlite3_finalize(cs);
        }
    }
    sw->entries = calloc(sw->entries_cap, sizeof(sweep_entry_t));
    if (!sw->entries) return 0;
    sw->n_entries = 0;

    /* Load pending sweeps from DB */
    if (db && db->db) {
        persist_load_sweeps(db, sw->entries, &sw->n_entries, sw->entries_cap);
    }

    /* Filter-based backends only see transactions paying a script they
       watch.  The HTLC script finds the commitment holding it; the claim's
       own output is watched once the claim is built. */
    if (chain && chain->register_script)
        for (size_t i = 0; i < sw->n_entries; i++)
            if (sw->entries[i].type == SWEEP_HTLC_SUCCESS)
                chain->register_script(chain, sw->entries[i].htlc_spk, 34);

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

/* Persist e and remember its row id, so later state changes update the
   same row and persist_delete_sweep removes it.  Returns 1 if the row is
   on disk (or there is no DB), 0 if it could not be written. */
static int sweeper_store(sweeper_t *sw, sweep_entry_t *e)
{
    if (!sw->db || !sw->db->db) return 1;
    if (!persist_save_sweep(sw->db, e)) {
        fprintf(stderr, "sweeper: failed to persist sweep entry (type=%d)\n",
                (int)e->type);
        return 0;
    }
    if (e->id == 0)
        e->id = (uint32_t)sqlite3_last_insert_rowid(sw->db->db);
    return 1;
}

/* Make room for one more entry.  Returns 0 if the array cannot grow. */
static int sweeper_reserve(sweeper_t *sw)
{
    if (sw->n_entries < sw->entries_cap) return 1;
    size_t new_cap = sw->entries_cap ? sw->entries_cap * 2
                                     : SWEEPER_MAX_ENTRIES;
    sweep_entry_t *tmp = realloc(sw->entries, new_cap * sizeof(sweep_entry_t));
    if (!tmp) return 0;
    sw->entries = tmp;
    sw->entries_cap = new_cap;
    return 1;
}

static int sweeper_append(sweeper_t *sw, const sweep_entry_t *tmpl)
{
    if (!sweeper_reserve(sw)) return 0;
    sweep_entry_t *e = &sw->entries[sw->n_entries++];
    *e = *tmpl;
    e->id = 0;
    e->state = SWEEP_PENDING;
    sweeper_store(sw, e);
    return 1;
}

/* Remove entry i (and its row), wiping any preimage it holds. */
static void sweeper_drop(sweeper_t *sw, size_t i)
{
    sweep_entry_t *e = &sw->entries[i];
    if (sw->db && e->id) persist_delete_sweep(sw->db, e->id);
    memset(e, 0, sizeof(*e));
    sw->entries[i] = sw->entries[--sw->n_entries];
    memset(&sw->entries[sw->n_entries], 0, sizeof(sweep_entry_t));
}

int sweeper_add(sweeper_t *sw, sweep_type_t type,
                const unsigned char *source_txid32,
                uint32_t source_vout, uint64_t amount_sats,
                uint32_t csv_delay,
                uint32_t channel_id, uint32_t factory_id,
                uint64_t commitment_number)
{
    if (!sw || !source_txid32) return 0;

    sweep_entry_t e;
    memset(&e, 0, sizeof(e));
    e.type = type;
    memcpy(e.source_txid, source_txid32, 32);
    e.source_vout = source_vout;
    e.amount_sats = amount_sats;
    e.csv_delay = csv_delay;
    e.channel_id = channel_id;
    e.factory_id = factory_id;
    e.commitment_number = commitment_number;
    return sweeper_append(sw, &e);
}

void sweeper_set_factory(sweeper_t *sw, uint32_t factory_id)
{
    if (sw) sw->factory_id = factory_id;
}

void sweeper_set_channel_lookup(sweeper_t *sw,
    channel_t *(*get_channel)(void *arg, uint32_t channel_id), void *arg)
{
    if (!sw) return;
    sw->get_channel = get_channel;
    sw->get_channel_arg = arg;
}

static int claim_has_preimage(const sweep_entry_t *e)
{
    for (size_t i = 0; i < 32; i++)
        if (e->preimage[i]) return 1;
    return 0;
}

/* Output vout of a serialized tx: amount and a pointer to its
   scriptPubKey.  Returns 0 if the tx is shorter than that. */
static int tx_output_at(const unsigned char *tx, size_t len, uint32_t vout,
                        uint64_t *amount_out, const unsigned char **spk_out,
                        size_t *spk_len_out)
{
    size_t ofs = 4;                         /* nVersion */
    if (ofs + 2 < len && tx[ofs] == 0x00 && tx[ofs + 1] == 0x01)
        ofs += 2;                           /* segwit marker + flag */
    if (ofs >= len || tx[ofs] >= 0xfd) return 0;
    size_t n_in = tx[ofs++];
    for (size_t i = 0; i < n_in; i++) {
        ofs += 36;                          /* prevout */
        if (ofs >= len || tx[ofs] >= 0xfd) return 0;
        ofs += 1 + tx[ofs];                 /* scriptSig */
        ofs += 4;                           /* nSequence */
    }
    if (ofs >= len || tx[ofs] >= 0xfd) return 0;
    size_t n_out = tx[ofs++];
    for (size_t v = 0; v < n_out; v++) {
        if (ofs + 9 > len) return 0;
        size_t slen = tx[ofs + 8];
        if (slen >= 0xfd || ofs + 9 + slen > len) return 0;
        if (v == vout) {
            uint64_t amt = 0;
            for (int b = 0; b < 8; b++)
                amt |= ((uint64_t)tx[ofs + b]) << (8 * b);
            *amount_out = amt;
            *spk_out = tx + ofs + 9;
            *spk_len_out = slen;
            return 1;
        }
        ofs += 9 + slen;
    }
    return 0;
}

/* The HTLC we received with this id, and the commitment output holding it:
   channel_build_commitment_tx_impl puts the active non-dust HTLCs in
   ch->htlcs order from vout 2.  Returns 0 if there is no such HTLC, 1 with
   *vout_out set, or 2 if the HTLC is trimmed (no output). */
static int claim_find_htlc(const channel_t *ch, uint64_t htlc_id,
                           const htlc_t **h_out, uint32_t *vout_out)
{
    uint32_t pos = 0;
    for (size_t i = 0; i < ch->n_htlcs; i++) {
        const htlc_t *h = &ch->htlcs[i];
        if (h->state != HTLC_STATE_ACTIVE) continue;
        int dust = h->amount_sats < CHANNEL_DUST_LIMIT_SATS;
        if (h->id == htlc_id && h->direction == HTLC_RECEIVED) {
            *h_out = h;
            if (dust) return 2;
            *vout_out = 2 + pos;
            return 1;
        }
        if (!dust) pos++;
    }
    return 0;
}

/* An HTLC entry of channel channel_id of the current factory. */
static int htlc_entry_of(const sweeper_t *sw, const sweep_entry_t *e,
                         uint32_t channel_id)
{
    return e->type == SWEEP_HTLC_SUCCESS && e->channel_id == channel_id &&
           e->factory_id == sw->factory_id;
}

/* An HTLC entry of a factory rotated away from: kept, not acted on. */
static int htlc_entry_dormant(const sweeper_t *sw, const sweep_entry_t *e)
{
    return (e->type == SWEEP_HTLC_SUCCESS ||
            e->type == SWEEP_HTLC_SUCCESS_OUTPUT) &&
           e->factory_id != sw->factory_id;
}

static size_t sweeper_count_claims(const sweeper_t *sw, uint32_t channel_id)
{
    size_t n = 0;
    for (size_t i = 0; i < sw->n_entries; i++)
        if (htlc_entry_of(sw, &sw->entries[i], channel_id))
            n++;
    return n;
}

/* A claim row must be on disk before the preimage it protects is revealed.
   Inside an open transaction the row would only become durable at that
   transaction's commit, which may come after the reveal, or never. */
static int sweeper_can_persist_now(const sweeper_t *sw)
{
    if (!sw->db || !sw->db->db) return 1;
    if (!sqlite3_get_autocommit(sw->db->db)) {
        fprintf(stderr, "sweeper: HTLC claim not registered: the database is "
                "inside an open transaction, so the claim would not be "
                "durable before the preimage goes out\n");
        return 0;
    }
    return 1;
}
/* The preimage of hash32 if an armed claim of channel_id holds it. */
static int sweeper_known_preimage(const sweeper_t *sw, uint32_t channel_id,
                                  const unsigned char *hash32,
                                  unsigned char *preimage_out)
{
    for (size_t i = 0; i < sw->n_entries; i++) {
        const sweep_entry_t *x = &sw->entries[i];
        if (htlc_entry_of(sw, x, channel_id) &&
            claim_has_preimage(x) && memcmp(x->payment_hash, hash32, 32) == 0) {
            memcpy(preimage_out, x->preimage, 32);
            return 1;
        }
    }
    return 0;
}

/* Register (preimage set) or watch (preimage NULL) the claim of HTLC
   htlc_id on ch's commitment at ch->commitment_number. */
static int sweeper_register_claim_on(sweeper_t *sw, const channel_t *ch,
                                     uint32_t channel_id, uint32_t factory_id,
                                     int side, uint64_t htlc_id,
                                     const unsigned char *preimage32)
{
    if (!sw || !ch) return -1;
    if (side != HTLC_CLAIM_LOCAL_COMMIT && side != HTLC_CLAIM_REMOTE_COMMIT)
        return -1;

    const htlc_t *h = NULL;
    uint32_t vout = 0;
    int found = claim_find_htlc(ch, htlc_id, &h, &vout);
    if (!found) return -1;

    if (preimage32) {
        unsigned char hash[32];
        sha256(preimage32, 32, hash);
        if (memcmp(hash, h->payment_hash, 32) != 0) return -1;
    }

    /* Trimmed HTLCs have no output: nothing to claim on chain. */
    if (found == 2) return 0;

    /* The claim pays the channel fee rule or the estimator rate for HTLC
       transactions, whichever is higher.  The fee is fixed here
       (claim_amount), so every rebuild of the claim is the same tx. */
    uint64_t fee = channel_htlc_claim_fee(ch);
    uint64_t est = sw->fee ? fee_for_htlc_tx(sw->fee) : 0;
    if (est > fee) fee = est;
    if (h->amount_sats <= fee ||
        h->amount_sats - fee < CHANNEL_DUST_LIMIT_SATS) {
        fprintf(stderr, "sweeper: HTLC %llu on channel %u (%llu sats) is not "
                "claimable on chain: after the %llu-sat fee its claim output "
                "would be dust, no claim armed\n",
                (unsigned long long)htlc_id, channel_id,
                (unsigned long long)h->amount_sats, (unsigned long long)fee);
        return 0;
    }
    uint64_t claim_amount = h->amount_sats - fee;

    uint64_t cn = ch->commitment_number;
    secp256k1_pubkey pcp;
    int have_pcp = (side == HTLC_CLAIM_REMOTE_COMMIT)
        ? channel_get_remote_pcp(ch, cn, &pcp)
        : channel_get_per_commitment_point(ch, cn, &pcp);
    if (!have_pcp) {
        fprintf(stderr, "sweeper: HTLC claim: no per-commitment point for "
                "channel %u commitment %llu\n", channel_id,
                (unsigned long long)cn);
        return -1;
    }

    unsigned char spk[34];
    if (!channel_htlc_claim_spk(ch, side, &pcp, h->payment_hash,
                                h->cltv_expiry, spk))
        return -1;

    /* The output at the HTLC position must be this HTLC: same script and
       amount.  Two HTLCs with the same hash and CLTV share a script, so the
       position, not the script, tells their outputs apart. */
    tx_buf_t commit;
    tx_buf_init(&commit, 512);
    unsigned char commit_txid[32];
    int built = (side == HTLC_CLAIM_REMOTE_COMMIT)
        ? channel_build_commitment_tx_for_remote(ch, &commit, commit_txid)
        : channel_build_commitment_tx(ch, &commit, commit_txid);
    uint64_t out_amt = 0;
    const unsigned char *out_spk = NULL;
    size_t out_spk_len = 0;
    int match = built &&
        tx_output_at(commit.data, commit.len, vout, &out_amt, &out_spk,
                     &out_spk_len) &&
        out_spk_len == 34 && memcmp(out_spk, spk, 34) == 0 &&
        out_amt == h->amount_sats;
    tx_buf_free(&commit);
    if (!match) {
        fprintf(stderr, "sweeper: HTLC claim: HTLC %llu not at output %u of "
                "channel %u commitment %llu\n", (unsigned long long)htlc_id,
                vout, channel_id, (unsigned long long)cn);
        return -1;
    }

    /* Already registered for this output? */
    for (size_t i = 0; i < sw->n_entries; i++) {
        sweep_entry_t *x = &sw->entries[i];
        if (x->type != SWEEP_HTLC_SUCCESS ||
            memcmp(x->source_txid, commit_txid, 32) != 0 ||
            x->source_vout != vout)
            continue;
        int dirty = (sw->db && sw->db->db && x->id == 0);
        if (preimage32 && !claim_has_preimage(x)) {
            memcpy(x->preimage, preimage32, 32);
            dirty = 1;
        }
        if (dirty && (!sweeper_can_persist_now(sw) || !sweeper_store(sw, x)))
            return -1;
        return 1;
    }

    if (sweeper_count_claims(sw, channel_id) >= SWEEPER_MAX_CLAIMS_PER_CHANNEL) {
        fprintf(stderr, "sweeper: channel %u already has %d HTLC claims, "
                "refusing more\n", channel_id, SWEEPER_MAX_CLAIMS_PER_CHANNEL);
        return -1;
    }
    if (!sweeper_can_persist_now(sw) || !sweeper_reserve(sw)) return -1;

    sweep_entry_t e;
    memset(&e, 0, sizeof(e));
    e.type = SWEEP_HTLC_SUCCESS;
    e.state = SWEEP_PENDING;
    memcpy(e.source_txid, commit_txid, 32);
    e.source_vout = vout;
    e.amount_sats = h->amount_sats;
    e.csv_delay = (side == HTLC_CLAIM_LOCAL_COMMIT) ? ch->to_self_delay : 0;
    e.channel_id = channel_id;
    e.factory_id = factory_id;
    e.commitment_number = cn;
    e.claim_side = (uint8_t)side;
    memcpy(e.payment_hash, h->payment_hash, 32);
    if (preimage32) memcpy(e.preimage, preimage32, 32);
    e.cltv_expiry = h->cltv_expiry;
    memcpy(e.htlc_spk, spk, 34);
    e.claim_amount = claim_amount;
    size_t pcp_len = 33;
    int ok = secp256k1_ec_pubkey_serialize(ch->ctx, e.commit_point, &pcp_len,
                                           &pcp, SECP256K1_EC_COMPRESSED);
    /* On disk first: an entry the DB does not hold is not a claim. */
    if (ok) ok = sweeper_store(sw, &e);
    if (ok) sw->entries[sw->n_entries++] = e;
    memset(&e, 0, sizeof(e));
    if (!ok) return -1;

    if (sw->chain && sw->chain->register_script)
        sw->chain->register_script(sw->chain, spk, 34);

    int height = (sw->chain && sw->chain->get_block_height)
                 ? sw->chain->get_block_height(sw->chain) : -1;
    printf("sweeper: %s HTLC-success claim channel=%u commitment=%llu "
           "(%s) vout=%u amount=%llu cltv=%u\n",
           preimage32 ? "registered" : "watching (no preimage yet)",
           channel_id, (unsigned long long)cn,
           side == HTLC_CLAIM_REMOTE_COMMIT ? "remote" : "local",
           vout, (unsigned long long)h->amount_sats, h->cltv_expiry);
    if (preimage32 && height >= 0 && (uint32_t)height >= h->cltv_expiry)
        fprintf(stderr, "sweeper: WARNING: HTLC claim registered at height "
                "%d, at or past its CLTV expiry %u: the counterparty can "
                "already time it out\n", height, h->cltv_expiry);
    fflush(stdout);
    return 1;
}

/* As sweeper_register_claim_on, but a watch whose preimage an armed claim
   of the channel already holds (the HTLC is on another commitment of it)
   is armed at once: a commitment signed after the preimage was learned is
   then as well covered as the ones before. */
static int sweeper_register_claim(sweeper_t *sw, const channel_t *ch,
                                  uint32_t channel_id, uint32_t factory_id,
                                  int side, uint64_t htlc_id,
                                  const unsigned char *preimage32)
{
    if (preimage32 || !sw || !ch)
        return sweeper_register_claim_on(sw, ch, channel_id, factory_id,
                                         side, htlc_id, preimage32);
    const htlc_t *h = NULL;
    uint32_t vout = 0;
    unsigned char known[32];
    int have = claim_find_htlc(ch, htlc_id, &h, &vout) &&
               sweeper_known_preimage(sw, channel_id, h->payment_hash, known);
    int r = sweeper_register_claim_on(sw, ch, channel_id, factory_id, side,
                                      htlc_id, have ? known : NULL);
    memset(known, 0, sizeof(known));
    return r;
}

int sweeper_add_htlc_success(sweeper_t *sw, const channel_t *ch,
                             uint32_t channel_id, uint32_t factory_id,
                             int side, uint64_t htlc_id,
                             const unsigned char *preimage32)
{
    if (!preimage32) return -1;
    return sweeper_register_claim(sw, ch, channel_id, factory_id, side,
                                  htlc_id, preimage32);
}

int sweeper_watch_htlc(sweeper_t *sw, const channel_t *ch,
                       uint32_t channel_id, uint32_t factory_id,
                       uint64_t htlc_id)
{
    return sweeper_register_claim(sw, ch, channel_id, factory_id,
                                  HTLC_CLAIM_REMOTE_COMMIT, htlc_id, NULL);
}

int sweeper_supply_preimage(sweeper_t *sw, uint32_t channel_id,
                            const unsigned char *preimage32)
{
    if (!sw || !preimage32) return -1;
    unsigned char hash[32];
    sha256(preimage32, 32, hash);
    int n = 0;
    for (size_t i = 0; i < sw->n_entries; i++) {
        sweep_entry_t *e = &sw->entries[i];
        if (!htlc_entry_of(sw, e, channel_id) ||
            claim_has_preimage(e) || memcmp(e->payment_hash, hash, 32) != 0)
            continue;
        if (!sweeper_can_persist_now(sw)) return -1;
        memcpy(e->preimage, preimage32, 32);
        if (!sweeper_store(sw, e)) return -1;
        printf("sweeper: armed watched HTLC-success claim channel=%u "
               "commitment=%llu vout=%u\n", channel_id,
               (unsigned long long)e->commitment_number, e->source_vout);
        n++;
    }
    fflush(stdout);
    return n;
}

int sweeper_cancel_htlc_success(sweeper_t *sw, uint32_t channel_id,
                                uint64_t commitment_number)
{
    if (!sw) return 0;
    int removed = 0;
    for (size_t i = 0; i < sw->n_entries; ) {
        sweep_entry_t *e = &sw->entries[i];
        if (htlc_entry_of(sw, e, channel_id) &&
            e->commitment_number == commitment_number &&
            e->state == SWEEP_PENDING && e->confirmed_height == 0) {
            sweeper_drop(sw, i);
            removed++;
            continue;
        }
        i++;
    }
    return removed;
}

size_t sweeper_pending_claims(const sweeper_t *sw)
{
    size_t n = 0;
    if (!sw) return 0;
    for (size_t i = 0; i < sw->n_entries; i++)
        if ((sw->entries[i].type == SWEEP_HTLC_SUCCESS &&
             claim_has_preimage(&sw->entries[i])) ||
            sw->entries[i].type == SWEEP_HTLC_SUCCESS_OUTPUT)
            n++;
    return n;
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

static int is_built_here(const sweep_entry_t *e)
{
    return e->type == SWEEP_HTLC_SUCCESS ||
           e->type == SWEEP_HTLC_SUCCESS_OUTPUT;
}

static void txid_to_hex(const unsigned char *txid32, char *hex65)
{
    unsigned char d[32];
    memcpy(d, txid32, 32);
    reverse_bytes(d, 32);
    hex_encode(d, 32, hex65);
}

/* Blocks past the CLTV after which an HTLC output spent by someone else is
   taken as lost to the timeout path, and an unarmed watch is dropped. */
static uint32_t claim_grace(const sweeper_t *sw)
{
    uint32_t g = (uint32_t)chain_sweep_confs(sw->chain, sw->chain->is_regtest);
    return g < 6 ? 6 : g;
}

/* Confirmations of the commitment holding a claim's HTLC output, looked up
   without searching for a transaction that is not there: a miss of
   get_confirmations on the bitcoin-cli backend scans up to scan_depth
   blocks, and most claims' commitments never reach the chain.  With an
   outpoint lookup, the HTLC output is checked first and the commitment is
   only looked up once that output exists.  An output that is not unspent
   may also be one already spent, in a block or in the mempool: then the
   commitment itself is looked up, at most every SWEEPER_REBROADCAST_BLOCKS
   blocks, so that the claim acts on it (or is dropped as spent) instead
   of waiting for a commitment it takes as absent.  Returns >= 1 if
   confirmed, 0 if in the mempool, -1 if not seen, -2 if the backend could
   not answer. */
static int claim_source_confs(sweeper_t *sw, sweep_entry_t *e,
                              const char *src_hex, uint32_t current_height)
{
    if (sw->chain->is_outpoint_unspent) {
        int u = sw->chain->is_outpoint_unspent(sw->chain, src_hex,
                                               e->source_vout);
        if (u < 0) return -2;
        if (u == 0) {
            if (e->last_lookup_height == 0 ||
                current_height < e->last_lookup_height +
                                 SWEEPER_REBROADCAST_BLOCKS) {
                if (e->last_lookup_height == 0)
                    e->last_lookup_height = current_height ? current_height : 1;
                return -1;
            }
            e->last_lookup_height = current_height;
            int c = sw->chain->get_confirmations(sw->chain, src_hex);
            return c >= 0 ? c : -1;
        }
    }
    return sw->chain->get_confirmations(sw->chain, src_hex);
}

/* Height from which an armed claim whose commitment was never seen on
   chain is dropped (see SWEEPER_REMOTE_CLAIM_HORIZON).  On our own
   commitment the success leaf waits to_self_delay after it confirms and
   the counterparty's timeout leaf does not, so past the CLTV the claim
   cannot win. */
static uint32_t claim_expiry_height(const sweeper_t *sw, const sweep_entry_t *e)
{
    if (e->claim_side == HTLC_CLAIM_LOCAL_COMMIT)
        return e->cltv_expiry + claim_grace(sw);
    return e->cltv_expiry + SWEEPER_REMOTE_CLAIM_HORIZON;
}

/* Has the counterparty validly revoked the commitment this claim targets? */
static int sweeper_claim_revoked(sweeper_t *sw, const sweep_entry_t *e)
{
    if (e->claim_side != HTLC_CLAIM_REMOTE_COMMIT) return 0;
    channel_t *ch = sw->get_channel
        ? sw->get_channel(sw->get_channel_arg, e->channel_id) : NULL;
    if (!ch) return 0;
    unsigned char secret[32];
    int revoked = channel_get_received_revocation(ch, e->commitment_number,
                                                  secret);
    memset(secret, 0, 32);
    return revoked;
}

uint32_t sweeper_final_depth(const sweeper_t *sw)
{
    int d = chain_close_confs(sw ? sw->chain : NULL, 0);
    return d < CONF_DEFAULT_CLOSE ? (uint32_t)CONF_DEFAULT_CLOSE : (uint32_t)d;
}

/* The commitments claims have seen confirmed, one per (channel, side,
   txid), sorted: built once per sweeper_check cycle. */
typedef struct {
    uint32_t      channel_id;
    uint8_t       side;
    unsigned char txid[32];
    uint32_t      confirmed_height;
    int           final;          /* -1 not looked up yet, 0 no, 1 yes */
} claim_seen_t;

static int claim_seen_cmp(const void *pa, const void *pb)
{
    const claim_seen_t *a = pa, *b = pb;
    if (a->channel_id != b->channel_id)
        return a->channel_id < b->channel_id ? -1 : 1;
    if (a->side != b->side) return a->side < b->side ? -1 : 1;
    return memcmp(a->txid, b->txid, 32);
}

static claim_seen_t *claim_seen_build(const sweeper_t *sw, size_t *n_out)
{
    *n_out = 0;
    size_t n = 0;
    for (size_t i = 0; i < sw->n_entries; i++)
        if (sw->entries[i].type == SWEEP_HTLC_SUCCESS &&
            sw->entries[i].confirmed_height > 0 &&
            !htlc_entry_dormant(sw, &sw->entries[i]))
            n++;
    if (n == 0) return NULL;
    claim_seen_t *s = calloc(n, sizeof(*s));
    if (!s) return NULL;
    size_t k = 0;
    for (size_t i = 0; i < sw->n_entries; i++) {
        const sweep_entry_t *e = &sw->entries[i];
        if (e->type != SWEEP_HTLC_SUCCESS || e->confirmed_height == 0 ||
            htlc_entry_dormant(sw, e))
            continue;
        s[k].channel_id = e->channel_id;
        s[k].side = e->claim_side;
        memcpy(s[k].txid, e->source_txid, 32);
        s[k].confirmed_height = e->confirmed_height;
        s[k].final = -1;
        k++;
    }
    qsort(s, k, sizeof(*s), claim_seen_cmp);
    size_t u = 0;
    for (size_t i = 0; i < k; i++)
        if (u == 0 || claim_seen_cmp(&s[u - 1], &s[i]) != 0)
            s[u++] = s[i];
    *n_out = u;
    return s;
}

/* Has another commitment of e's channel, on the same side, confirmed and
   been buried sweeper_final_depth() deep?  Then e's commitment can no
   longer confirm.  The depth is checked against the chain (once per
   commitment and cycle), not just the height it was first seen at, so a
   commitment a reorg took out does not count. */
static int sweeper_superseded(sweeper_t *sw, claim_seen_t *seen,
                              size_t n_seen, const sweep_entry_t *e,
                              uint32_t current_height)
{
    size_t lo = 0, hi = n_seen;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const claim_seen_t *m = &seen[mid];
        if (m->channel_id < e->channel_id ||
            (m->channel_id == e->channel_id && m->side < e->claim_side))
            lo = mid + 1;
        else
            hi = mid;
    }
    uint32_t depth = sweeper_final_depth(sw);
    for (size_t i = lo; i < n_seen && seen[i].channel_id == e->channel_id &&
                        seen[i].side == e->claim_side; i++) {
        claim_seen_t *c = &seen[i];
        if (memcmp(c->txid, e->source_txid, 32) == 0) continue;
        if ((uint64_t)current_height + 1 < (uint64_t)c->confirmed_height + depth)
            continue;
        if (c->final < 0) {
            char hex[65];
            txid_to_hex(c->txid, hex);
            c->final = sw->chain->get_confirmations(sw->chain, hex) >= (int)depth;
        }
        if (c->final) return 1;
    }
    return 0;
}

/* Build (deterministically) and broadcast the transaction for an entry the
   sweeper owns.  Returns 1 if broadcast, 0 if not (yet), -1 if the entry
   is dead and should be dropped. */
static int sweeper_build_and_send(sweeper_t *sw, sweep_entry_t *e,
                                  uint32_t current_height)
{
    int claim = (e->type == SWEEP_HTLC_SUCCESS);
    char src_hex[65];
    txid_to_hex(e->source_txid, src_hex);
    const char *what = claim ? "HTLC-success claim" : "claim output sweep";

    /* Source already spent (the check includes the mempool)?  Our own
       claim is recognised below by its txid. */
    int src_spent = sw->chain->is_outpoint_unspent &&
        sw->chain->is_outpoint_unspent(sw->chain, src_hex, e->source_vout) == 0;

    channel_t *ch = sw->get_channel
        ? sw->get_channel(sw->get_channel_arg, e->channel_id) : NULL;
    tx_buf_t tx;
    tx_buf_init(&tx, 512);
    int built = 0;
    uint64_t out_amount = 0;
    unsigned char claim_txid[32];
    if (!ch) {
        fprintf(stderr, "sweeper: no channel %u to build %s, retrying next "
                "cycle\n", e->channel_id, what);
    } else if (claim) {
        secp256k1_pubkey pcp;
        uint64_t fee = (e->claim_amount && e->claim_amount < e->amount_sats)
                       ? e->amount_sats - e->claim_amount : 0;
        if (secp256k1_ec_pubkey_parse(ch->ctx, &pcp, e->commit_point, 33))
            built = channel_build_htlc_claim_tx(ch, &tx, e->claim_side, &pcp,
                        e->source_txid, e->source_vout, e->amount_sats,
                        e->htlc_spk, e->payment_hash, e->preimage,
                        e->cltv_expiry, fee, &out_amount, claim_txid);
    } else if (sw->dest_spk_len > 0) {
        built = channel_build_htlc_output_sweep(ch, &tx, e->source_txid,
                    e->source_vout, e->amount_sats,
                    sw->dest_spk, sw->dest_spk_len);
    } else {
        tx_buf_free(&tx);
        return 0;       /* no destination: the output stays where it is */
    }

    char txid[65] = {0};
    if (built && claim) {
        hex_encode(claim_txid, 32, txid);
        /* A filter-based backend sees the claim only through a script it
           watches: watch the claim's output. */
        uint64_t a = 0;
        const unsigned char *ospk = NULL;
        size_t ol = 0;
        if (sw->chain->register_script &&
            tx_output_at(tx.data, tx.len, 0, &a, &ospk, &ol) && ol == 34) {
            unsigned char s[34];
            memcpy(s, ospk, 34);
            sw->chain->register_script(sw->chain, s, 34);
        }
        /* Our identical claim may already be out there (e.g. broadcast
           just before a restart): adopt it rather than resend.  Its own
           output tells, without a search for a tx that is not there. */
        if (src_spent &&
            sw->chain->is_outpoint_unspent(sw->chain, txid, 0) == 1) {
            tx_buf_free(&tx);
            e->state = SWEEP_BROADCAST;
            memcpy(e->sweep_txid, txid, 65);
            e->claim_amount = out_amount;
            e->last_broadcast_height = current_height;
            sweeper_store(sw, e);
            printf("sweeper: %s %s already known to the chain, tracking\n",
                   what, txid);
            fflush(stdout);
            return 0;
        }
    }

    if (src_spent) {
        tx_buf_free(&tx);
        /* Gone with a reorg rather than spent?  Wait to see it again. */
        if (claim && sw->chain->get_confirmations(sw->chain, src_hex) < 0) {
            fprintf(stderr, "sweeper: commitment %s holding HTLC (vout %u) "
                    "is no longer on chain\n", src_hex, e->source_vout);
            e->confirmed_height = 0;
            sweeper_store(sw, e);
            return 0;
        }
        /* On a revoked commitment our penalty spends the HTLC output. */
        if (claim && sweeper_claim_revoked(sw, e)) {
            printf("sweeper: HTLC output %s:%u spent after commitment %llu "
                   "was revoked: left to the penalty path\n", src_hex,
                   e->source_vout, (unsigned long long)e->commitment_number);
            fflush(stdout);
            return -1;
        }
        /* Before the CLTV only our success leaf can spend an HTLC output,
           so keep trying; well past it the spender is the counterparty's
           timeout and the entry is dead. */
        if (claim && current_height < e->cltv_expiry + claim_grace(sw)) {
            fprintf(stderr, "sweeper: HTLC output %s:%u already spent "
                    "(height %u, cltv %u), will keep retrying\n",
                    src_hex, e->source_vout, current_height, e->cltv_expiry);
            return 0;
        }
        fprintf(stderr, "sweeper: ALERT: %s %s:%u was spent by another "
                "transaction; dropping entry%s\n",
                claim ? "HTLC output" : "claim output",
                src_hex, e->source_vout,
                claim ? " (HTLC lost to the timeout path)" : "");
        return -1;
    }

    if (!built) {
        tx_buf_free(&tx);
        if (ch)
            fprintf(stderr, "sweeper: failed to build %s for %s:%u\n", what,
                    src_hex, e->source_vout);
        /* A claim that still cannot be built well past its CLTV never will
           be in time. */
        if (claim && ch && current_height >= e->cltv_expiry + claim_grace(sw)) {
            fprintf(stderr, "sweeper: ALERT: dropping %s for %s:%u, past CLTV "
                    "%u\n", what, src_hex, e->source_vout, e->cltv_expiry);
            return -1;
        }
        return 0;
    }

    char *hex = malloc(tx.len * 2 + 1);
    if (!hex) { tx_buf_free(&tx); return 0; }
    hex_encode(tx.data, tx.len, hex);
    tx_buf_free(&tx);

    /* Record a claim before sending it, so a crash right after the send
       cannot lose track of the transaction. */
    int resend = claim && e->sweep_txid[0] && strcmp(e->sweep_txid, txid) == 0;
    if (claim) {
        e->state = SWEEP_BROADCAST;
        memcpy(e->sweep_txid, txid, 65);
        e->claim_amount = out_amount;
        sweeper_store(sw, e);
    }

    char sent_txid[65] = {0};
    int sent = sw->chain->send_raw_tx(sw->chain, hex, sent_txid);
    if (sent && !resend && sw->db && sw->db->db)
        persist_log_broadcast(sw->db, sent_txid,
            claim ? "htlc_success" : "htlc_success_sweep", hex, "ok");
    free(hex);
    e->last_broadcast_height = current_height;
    if (!sent) {
        fprintf(stderr, "sweeper: broadcast of %s for %s:%u failed, "
                "retrying next cycle\n", what, src_hex, e->source_vout);
        if (claim) {
            e->state = SWEEP_PENDING;
            sweeper_store(sw, e);
        }
        return 0;
    }

    e->state = SWEEP_BROADCAST;
    memcpy(e->sweep_txid, sent_txid, 65);
    sweeper_store(sw, e);
    if (!resend) {
        printf("sweeper: %s broadcast: %s (source %s:%u, height %u, cltv %u)\n",
               what, sent_txid, src_hex, e->source_vout, current_height,
               e->cltv_expiry);
        if (claim && current_height >= e->cltv_expiry)
            fprintf(stderr, "sweeper: WARNING: HTLC claim broadcast at height "
                    "%u, past CLTV expiry %u: racing the counterparty's "
                    "timeout\n", current_height, e->cltv_expiry);
    }
    fflush(stdout);
    return 1;
}

int sweeper_check(sweeper_t *sw)
{
    if (!sw || !sw->chain || sw->n_entries == 0) return 0;

    int n_broadcast = 0;
    uint32_t current_height = sw->chain->get_block_height(sw->chain);
    size_t n_seen = 0;
    claim_seen_t *seen = claim_seen_build(sw, &n_seen);

    for (size_t i = 0; i < sw->n_entries; ) {
        sweep_entry_t *e = &sw->entries[i];

        if (htlc_entry_dormant(sw, e)) {
            i++;
            continue;
        }

        /* A watched claim (no preimage yet) costs no chain lookup.  It goes
           once its commitment is revoked or superseded, or its HTLC has
           expired. */
        if (e->type == SWEEP_HTLC_SUCCESS && !claim_has_preimage(e)) {
            if (sweeper_claim_revoked(sw, e) ||
                sweeper_superseded(sw, seen, n_seen, e, current_height) ||
                current_height >= e->cltv_expiry + claim_grace(sw)) {
                printf("sweeper: channel %u commitment %llu: watched HTLC "
                       "(cltv %u) no longer claimable, dropped\n",
                       e->channel_id, (unsigned long long)e->commitment_number,
                       e->cltv_expiry);
                fflush(stdout);
                sweeper_drop(sw, i);
                continue;
            }
            i++;
            continue;
        }

        /* Check if sweep TX already confirmed -> remove entry.
           #265: use network-safe sweep depth instead of hardcoded 3.
           chain_sweep_confs returns 1 on regtest and the configured
           target (default 3) on other networks. */
        if (e->state == SWEEP_BROADCAST && e->sweep_txid[0]) {
            int confs = sw->chain->get_confirmations(sw->chain, e->sweep_txid);
            if (confs >= chain_sweep_confs(sw->chain, sw->chain->is_regtest)) {
                /* Confirmed — remove entry */
                e->state = SWEEP_CONFIRMED;
                if (e->type == SWEEP_HTLC_SUCCESS) {
                    printf("sweeper: HTLC-success claim %s buried (%d confs) "
                           "— channel %u HTLC settled on chain\n",
                           e->sweep_txid, confs, e->channel_id);
                    fflush(stdout);
                    sweep_entry_t out;
                    memset(&out, 0, sizeof(out));
                    out.type = SWEEP_HTLC_SUCCESS_OUTPUT;
                    hex_decode(e->sweep_txid, out.source_txid, 32);
                    reverse_bytes(out.source_txid, 32);
                    out.source_vout = 0;
                    out.amount_sats = e->claim_amount;
                    out.channel_id = e->channel_id;
                    out.factory_id = e->factory_id;
                    out.commitment_number = e->commitment_number;
                    uint32_t del_id = e->id;
                    memset(e->preimage, 0, 32);
                    /* Append may move the array: e is not used after it. */
                    if (sw->dest_spk_len > 0 && out.amount_sats > 0)
                        sweeper_append(sw, &out);
                    if (sw->db) persist_delete_sweep(sw->db, del_id);
                } else {
                    if (sw->db) persist_delete_sweep(sw->db, e->id);
                }
                sw->entries[i] = sw->entries[--sw->n_entries];
                memset(&sw->entries[sw->n_entries], 0, sizeof(sweep_entry_t));
                continue;  /* recheck this index */
            }
            if (confs < 0) {
                /* TX vanished (evicted, reorg): retry.  A filter-based
                   backend (no outpoint lookup) does not see the mempool,
                   so there "not found" also means "not mined yet": resend
                   every few blocks rather than every cycle. */
                if (is_built_here(e) && !sw->chain->is_outpoint_unspent &&
                    current_height < e->last_broadcast_height +
                                     SWEEPER_REBROADCAST_BLOCKS) {
                    i++;
                    continue;
                }
                e->state = SWEEP_PENDING;
                if (is_built_here(e)) {
                    /* Keep the source as seen: rebuilding checks it. */
                    sweeper_store(sw, e);
                } else {
                    e->sweep_txid[0] = '\0';
                    e->confirmed_height = 0;
                }
            }
        }

        /* Check source TX confirmation status */
        if (e->confirmed_height == 0) {
            char txid_hex[65];
            txid_to_hex(e->source_txid, txid_hex);

            int confs;
            if (e->type == SWEEP_HTLC_SUCCESS) {
                /* A claim on a counterparty commitment it has since revoked
                   (through any revocation path) is moot: broadcasting that
                   commitment is now a breach, covered by the penalty.  A
                   claim on a commitment that lost to another commitment of
                   the same channel, now buried final, can never be used. */
                int revoked = sweeper_claim_revoked(sw, e);
                if (revoked ||
                    sweeper_superseded(sw, seen, n_seen, e, current_height)) {
                    printf("sweeper: channel %u commitment %llu %s: "
                           "HTLC-success claim no longer needed\n",
                           e->channel_id,
                           (unsigned long long)e->commitment_number,
                           revoked ? "revoked"
                                   : "superseded by a confirmed commitment");
                    fflush(stdout);
                    sweeper_drop(sw, i);
                    continue;
                }
                confs = claim_source_confs(sw, e, txid_hex, current_height);
            } else {
                confs = sw->chain->get_confirmations(sw->chain, txid_hex);
            }
            if (confs >= 1) {
                e->confirmed_height = current_height - (uint32_t)confs + 1;
                if (is_built_here(e)) sweeper_store(sw, e);
                if (e->type == SWEEP_HTLC_SUCCESS) {
                    printf("sweeper: commitment %s holding HTLC (vout %u) "
                           "confirmed at height %u\n", txid_hex,
                           e->source_vout, e->confirmed_height);
                    if (e->confirmed_height + e->csv_delay > e->cltv_expiry)
                        fprintf(stderr, "sweeper: WARNING: our claim matures "
                                "at %u, after CLTV expiry %u: the counterparty "
                                "can time this HTLC out first\n",
                                e->confirmed_height + e->csv_delay,
                                e->cltv_expiry);
                    fflush(stdout);
                }
            } else {
                /* An armed claim whose commitment never reached the chain
                   goes once it can no longer pay. */
                if (e->type == SWEEP_HTLC_SUCCESS && confs != -2 &&
                    current_height >= claim_expiry_height(sw, e)) {
                    printf("sweeper: channel %u commitment %llu: HTLC claim "
                           "(cltv %u) never seen on chain by height %u, "
                           "dropped\n", e->channel_id,
                           (unsigned long long)e->commitment_number,
                           e->cltv_expiry, current_height);
                    fflush(stdout);
                    sweeper_drop(sw, i);
                    continue;
                }
                i++;
                continue;  /* source not yet confirmed */
            }
        }

        /* Check CSV delay.  An entry built here may be broadcast one block
           early: BIP 68 checks the CSV against the next block's height. */
        if (e->csv_delay > 0) {
            uint32_t mature_height = e->confirmed_height + e->csv_delay;
            if (is_built_here(e)) mature_height -= 1;
            if (current_height < mature_height) {
                i++;
                continue;  /* CSV not yet expired */
            }
        }

        /* Entries the sweeper builds itself: claim as soon as possible. */
        if (is_built_here(e)) {
            if (e->state == SWEEP_PENDING) {
                int r = sweeper_build_and_send(sw, e, current_height);
                if (r < 0) {
                    sweeper_drop(sw, i);
                    continue;
                }
                if (r > 0) n_broadcast++;
            }
            i++;
            continue;
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

    free(seen);
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
        case SWEEP_HTLC_SUCCESS: return "htlc_success";
        case SWEEP_HTLC_SUCCESS_OUTPUT: return "htlc_success_output";
    }
    return "unknown";
}

static sweep_type_t sweep_type_from_str(const char *s) {
    if (!s) return SWEEP_TO_LOCAL;
    if (strcmp(s, "commitment") == 0) return SWEEP_COMMITMENT_BROADCAST;
    if (strcmp(s, "penalty") == 0) return SWEEP_PENALTY_OUTPUT;
    if (strcmp(s, "htlc_timeout") == 0) return SWEEP_HTLC_TIMEOUT_OUTPUT;
    if (strcmp(s, "htlc_success") == 0) return SWEEP_HTLC_SUCCESS;
    if (strcmp(s, "htlc_success_output") == 0) return SWEEP_HTLC_SUCCESS_OUTPUT;
    return SWEEP_TO_LOCAL;
}

int persist_save_sweep(persist_t *p, const sweep_entry_t *e)
{
    if (!p || !p->db || !e) return 0;

    /* id 0 = new row (autoincrement); otherwise replace that row. */
    const char *sql =
        "INSERT OR REPLACE INTO pending_sweeps "
        "(id, sweep_type, state, source_txid, source_vout, amount_sats, "
        " csv_delay, confirmed_height, channel_id, factory_id, "
        " commitment_number, sweep_txid, claim_side, payment_hash, "
        " preimage, cltv_expiry, htlc_spk, commit_point, claim_amount) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    /* source txid → display-order hex */
    unsigned char txid_display[32];
    memcpy(txid_display, e->source_txid, 32);
    reverse_bytes(txid_display, 32);
    char txid_hex[65];
    hex_encode(txid_display, 32, txid_hex);

    if (e->id) sqlite3_bind_int(stmt, 1, (int)e->id);
    else       sqlite3_bind_null(stmt, 1);
    sqlite3_bind_text(stmt, 2, sweep_type_str(e->type), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, (int)e->state);
    sqlite3_bind_text(stmt, 4, txid_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, (int)e->source_vout);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)e->amount_sats);
    sqlite3_bind_int(stmt, 7, (int)e->csv_delay);
    sqlite3_bind_int(stmt, 8, (int)e->confirmed_height);
    sqlite3_bind_int(stmt, 9, (int)e->channel_id);
    sqlite3_bind_int(stmt, 10, (int)e->factory_id);
    sqlite3_bind_int64(stmt, 11, (sqlite3_int64)e->commitment_number);
    sqlite3_bind_text(stmt, 12, e->sweep_txid[0] ? e->sweep_txid : "", -1, SQLITE_TRANSIENT);

    /* HTLC-success claim data (empty for other types).  The preimage is
       sealed at rest like the other secrets; a watched claim has none yet
       and stores an empty string. */
    char hash_hex[65] = "", pre_hex[65] = "", spk_hex[69] = "", pcp_hex[67] = "";
    char *pre_sealed = NULL;
    if (e->type == SWEEP_HTLC_SUCCESS) {
        hex_encode(e->payment_hash, 32, hash_hex);
        hex_encode(e->htlc_spk, 34, spk_hex);
        hex_encode(e->commit_point, 33, pcp_hex);
        int have_pre = 0;
        for (size_t k = 0; k < 32; k++) have_pre |= e->preimage[k];
        if (have_pre) {
            hex_encode(e->preimage, 32, pre_hex);
            pre_sealed = persist_seal_text(p, pre_hex);
            memset(pre_hex, 0, sizeof(pre_hex));
            if (!pre_sealed) {
                sqlite3_finalize(stmt);
                return 0;
            }
        }
    }
    sqlite3_bind_int(stmt, 13, (int)e->claim_side);
    sqlite3_bind_text(stmt, 14, hash_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 15, pre_sealed ? pre_sealed : "", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 16, (sqlite3_int64)e->cltv_expiry);
    sqlite3_bind_text(stmt, 17, spk_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 18, pcp_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 19, (sqlite3_int64)e->claim_amount);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    if (pre_sealed) {
        memset(pre_sealed, 0, strlen(pre_sealed));
        free(pre_sealed);
    }
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
        "       commitment_number, sweep_txid, claim_side, payment_hash, "
        "       preimage, cltv_expiry, htlc_spk, commit_point, claim_amount "
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

        if (e->type == SWEEP_HTLC_SUCCESS) {
            const char *hh = (const char *)sqlite3_column_text(stmt, 13);
            const char *ph = (const char *)sqlite3_column_text(stmt, 14);
            const char *sh = (const char *)sqlite3_column_text(stmt, 16);
            const char *ch = (const char *)sqlite3_column_text(stmt, 17);
            /* The preimage is sealed at rest (legacy plaintext opens as
               is); an empty one is a watched claim still waiting for it. */
            char *pre = NULL;
            int pre_ok = ph && persist_open_text(p, ph, &pre) && pre &&
                         (pre[0] == '\0' || strlen(pre) == 64);
            /* A claim row without its data cannot be acted on: skip it
               loudly rather than load a wrong one. */
            if (!pre_ok || !hh || strlen(hh) != 64 ||
                !sh || strlen(sh) != 68 || !ch || strlen(ch) != 66) {
                fprintf(stderr, "persist_load_sweeps: HTLC-success row %u "
                        "is incomplete or cannot be opened, skipped\n", e->id);
                if (pre) { memset(pre, 0, strlen(pre)); free(pre); }
                memset(e, 0, sizeof(*e));
                continue;
            }
            e->claim_side = (uint8_t)sqlite3_column_int(stmt, 12);
            hex_decode(hh, e->payment_hash, 32);
            if (pre[0]) hex_decode(pre, e->preimage, 32);
            memset(pre, 0, strlen(pre));
            free(pre);
            e->cltv_expiry = (uint32_t)sqlite3_column_int64(stmt, 15);
            hex_decode(sh, e->htlc_spk, 34);
            hex_decode(ch, e->commit_point, 33);
        }
        e->claim_amount = (uint64_t)sqlite3_column_int64(stmt, 18);

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
