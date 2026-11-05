/*
 * sweeper.h — Automatic sweep of timelocked/intermediate outputs to wallet
 *
 * After a factory force-close, funds end up in intermediate outputs:
 *   1. Leaf outputs → need commitment TX broadcast
 *   2. to_local outputs → need CSV-delayed sweep
 *   3. Penalty outputs → need key-path sweep
 *   4. HTLC timeout outputs → need CSV-delayed sweep
 *   5. HTLCs we hold the preimage for → claim via the success leaf before
 *      the CLTV expiry, then sweep the claim's output
 *
 * The sweeper runs inside the watchtower check cycle and handles all of these.
 */

#ifndef SUPERSCALAR_SWEEPER_H
#define SUPERSCALAR_SWEEPER_H

#include "channel.h"
#include "chain_backend.h"
#include "persist.h"
#include "fee.h"
#include <stdint.h>
#include <stddef.h>

/* Sweep entry types */
typedef enum {
    SWEEP_COMMITMENT_BROADCAST,  /* Leaf confirmed → broadcast commitment TX */
    SWEEP_TO_LOCAL,              /* Commitment confirmed + CSV → sweep to_local */
    SWEEP_PENALTY_OUTPUT,        /* Penalty TX confirmed → sweep output */
    SWEEP_HTLC_TIMEOUT_OUTPUT,   /* HTLC timeout TX confirmed + CSV → sweep output */
    SWEEP_HTLC_SUCCESS,          /* Commitment confirmed → claim HTLC with preimage */
    SWEEP_HTLC_SUCCESS_OUTPUT    /* HTLC-success claim confirmed → sweep output */
} sweep_type_t;

/* Sweep entry states */
typedef enum {
    SWEEP_PENDING,       /* Waiting for CSV/confirmation */
    SWEEP_BROADCAST,     /* Sweep TX broadcast, awaiting confirmation */
    SWEEP_CONFIRMED,     /* Sweep TX confirmed — done */
    SWEEP_FAILED         /* Broadcast failed — retry next cycle */
} sweep_state_t;

/* A pending sweep tracked by the sweeper */
typedef struct sweep_entry {
    uint32_t     id;               /* DB primary key */
    sweep_type_t type;
    sweep_state_t state;

    /* Source output to sweep */
    unsigned char source_txid[32]; /* internal byte order */
    uint32_t     source_vout;
    uint64_t     amount_sats;

    /* Timelock */
    uint32_t     csv_delay;        /* 0 = no CSV (immediate) */
    uint32_t     confirmed_height; /* block height when source confirmed (0 = unconfirmed) */

    /* Channel context (for building sweep TX) */
    uint32_t     channel_id;
    uint32_t     factory_id;
    uint64_t     commitment_number; /* for key derivation */

    /* Result */
    char         sweep_txid[65];   /* hex txid of broadcast sweep (empty = not yet) */

    /* SWEEP_HTLC_SUCCESS only: everything needed to rebuild the claim after
       a restart, when the HTLC is no longer in channel state. */
    uint8_t       claim_side;          /* HTLC_CLAIM_LOCAL/REMOTE_COMMIT */
    unsigned char payment_hash[32];
    unsigned char preimage[32];
    uint32_t      cltv_expiry;
    unsigned char htlc_spk[34];
    unsigned char commit_point[33];    /* compressed PCP of that commitment */
    uint64_t      claim_amount;        /* claim output value (fixes the fee) */

    /* In memory only: height of the last broadcast of the entry's tx, and
       of the last lookup of a commitment whose HTLC output is not unspent. */
    uint32_t      last_broadcast_height;
    uint32_t      last_lookup_height;
} sweep_entry_t;

#define SWEEPER_MAX_ENTRIES 64

/* HTLC-success claims per channel: an HTLC can sit on at most two live
   counterparty commitments (the current one and one never revoked). */
#define SWEEPER_MAX_CLAIMS_PER_CHANNEL (2 * MAX_HTLCS)

/* A backend that cannot see the mempool resends a claim at most this
   often (blocks) while waiting for it to confirm.  It is also the most
   often a claim whose HTLC output is not unspent looks its commitment up
   (absent, or already spent: the lookup tells, and can scan blocks). */
#define SWEEPER_REBROADCAST_BLOCKS 6

/* Blocks past its CLTV after which an armed claim on the counterparty's
   commitment, never seen on chain, is dropped.  Such a claim stays useful
   as long as that commitment can still be broadcast (the counterparty's
   timeout leaf waits to_self_delay after it confirms, our success leaf
   does not), and a factory bounds that: this is the default factory
   lifetime (4320 active + 432 dying blocks), so the claim outlives any
   commitment of a default-length factory holding the HTLC, whose CLTV is
   below the factory timeout. */
#define SWEEPER_REMOTE_CLAIM_HORIZON 4752

typedef struct {
    sweep_entry_t *entries;
    size_t         n_entries;
    size_t         entries_cap;

    chain_backend_t *chain;
    persist_t       *db;
    fee_estimator_t *fee;

    /* LSP key material for signing sweeps */
    secp256k1_context *ctx;
    unsigned char     lsp_seckey[32];

    /* Destination for swept funds */
    unsigned char     dest_spk[34];
    size_t            dest_spk_len;

    /* Channel lookup for entries the sweeper builds itself (HTLC-success
       claims and their output sweeps).  NULL = tracking only. */
    channel_t       *(*get_channel)(void *arg, uint32_t channel_id);
    void             *get_channel_arg;
} sweeper_t;

/* Initialize the sweeper. Loads pending sweeps from DB.
   lsp_seckey32: LSP's 32-byte secret key (for signing sweep TXs).
   dest_spk/len: P2TR scriptPubKey where swept funds are sent.
   Returns 1 on success. */
int sweeper_init(sweeper_t *sw, secp256k1_context *ctx,
                 const unsigned char *lsp_seckey32,
                 const unsigned char *dest_spk, size_t dest_spk_len,
                 chain_backend_t *chain, persist_t *db,
                 fee_estimator_t *fee);

/* Run one sweep cycle. Called from watchtower_check() or daemon loop.
   Checks each pending entry:
     - SWEEP_COMMITMENT_BROADCAST: build+broadcast commitment TX if leaf confirmed
     - SWEEP_TO_LOCAL: sweep after CSV expires
     - SWEEP_PENALTY_OUTPUT: sweep penalty output (no CSV)
     - SWEEP_HTLC_TIMEOUT_OUTPUT: sweep after CSV expires
     - SWEEP_HTLC_SUCCESS: build+broadcast the preimage claim once the
       commitment confirms (+ CSV on our own commitment); rebroadcast until
       buried; then register its output as SWEEP_HTLC_SUCCESS_OUTPUT.
       Pending claims are looked up by their HTLC outpoint when the backend
       can (no block scans for commitments that never reach the chain; an
       output that is not unspent has its commitment looked up at most
       every SWEEPER_REBROADCAST_BLOCKS blocks, to tell a spent output from
       an absent commitment).  Claims on a revoked commitment are dropped,
       and claims on one superseded by another commitment of the channel
       once that one is buried sweeper_final_depth() deep.  An armed claim
       never seen on chain expires: on our own commitment past CLTV plus a
       grace (our success leaf waits to_self_delay, the counterparty's
       timeout does not), on the counterparty's past CLTV plus
       SWEEPER_REMOTE_CLAIM_HORIZON
     - SWEEP_HTLC_SUCCESS_OUTPUT: sweep to dest_spk (needs a channel lookup)
   Returns number of entries ready or broadcast this cycle. */
int sweeper_check(sweeper_t *sw);

/* Register a new sweep. Returns 1 on success. */
int sweeper_add(sweeper_t *sw, sweep_type_t type,
                const unsigned char *source_txid32,
                uint32_t source_vout, uint64_t amount_sats,
                uint32_t csv_delay,
                uint32_t channel_id, uint32_t factory_id,
                uint64_t commitment_number);

/* Set the channel lookup used to build HTLC-success claims. */
void sweeper_set_channel_lookup(sweeper_t *sw,
    channel_t *(*get_channel)(void *arg, uint32_t channel_id), void *arg);

/* Register an on-chain HTLC-success claim before revealing a preimage.
   htlc_id must be an ACTIVE HTLC we received that is still in ch (call
   before channel_fulfill_htlc).  The claim targets the commitment ch
   describes, at ch->commitment_number:
     side = HTLC_CLAIM_REMOTE_COMMIT: the counterparty's commitment (the
            one they hold signed);
     side = HTLC_CLAIM_LOCAL_COMMIT:  our own commitment.
   The HTLC's output is the one at its position among the commitment's
   HTLC outputs, so HTLCs sharing a hash and CLTV get one claim each.
   The claim fee is fixed at registration: the channel fee rule or the
   estimator's HTLC rate, whichever is higher.
   The entry is on disk before this returns 1, so the claim survives a
   restart; registration fails (-1) rather than leave it memory-only,
   including while the DB is inside an open transaction.  sweeper_check
   broadcasts it once the commitment confirms (plus to_self_delay for
   LOCAL) and rebroadcasts it until it is buried.
   Returns 1 if registered (or already registered), 0 if the HTLC has no
   output on that commitment (trimmed) or a claim of it would leave a dust
   output (logged), -1 on error: the preimage must then not be revealed. */
int sweeper_add_htlc_success(sweeper_t *sw, const channel_t *ch,
                             uint32_t channel_id, uint32_t factory_id,
                             int side, uint64_t htlc_id,
                             const unsigned char *preimage32);

/* Watch HTLC htlc_id on the counterparty commitment ch describes, before
   its preimage is known (a commitment the counterparty never revoked).
   If an armed claim of channel_id already holds the HTLC's preimage (one
   on another commitment of the channel), the entry is armed at once.
   Otherwise it costs no chain lookups until sweeper_supply_preimage arms
   it; it is dropped once that commitment is revoked or superseded, or the
   HTLC has expired.  Returns as sweeper_add_htlc_success. */
int sweeper_watch_htlc(sweeper_t *sw, const channel_t *ch,
                       uint32_t channel_id, uint32_t factory_id,
                       uint64_t htlc_id);

/* Arm every watched claim of channel_id whose payment hash this preimage
   opens.  Returns the number armed, -1 if one could not be persisted (the
   preimage must then not be revealed). */
int sweeper_supply_preimage(sweeper_t *sw, uint32_t channel_id,
                            const unsigned char *preimage32);

/* Drop HTLC-success claims for channel_id on commitment number
   commitment_number exactly that have not been seen on chain.  Call once
   that commitment is validly revoked: broadcasting it is then a breach and
   the watchtower's penalty path covers the HTLC.  Returns entries removed. */
int sweeper_cancel_htlc_success(sweeper_t *sw, uint32_t channel_id,
                                uint64_t commitment_number);

/* Depth at which a confirmed commitment of a channel supersedes the
   others: claims on them are dropped once it is this deep.  It is the
   close depth (CONF_DEFAULT_CLOSE, LDK's ANTI_REORG_DELAY, unless set
   higher), on every network including regtest: a claim dropped before a
   reorg is lost, one kept costs one outpoint lookup per cycle. */
uint32_t sweeper_final_depth(const sweeper_t *sw);

/* Armed HTLC-success claims and claim-output sweeps still pending. */
size_t sweeper_pending_claims(const sweeper_t *sw);

/* Remove all entries for a factory (e.g., after cooperative close). */
void sweeper_remove_factory(sweeper_t *sw, uint32_t factory_id);

/* Free heap-allocated entries. */
void sweeper_cleanup(sweeper_t *sw);

/* --- Persistence (defined in sweeper.c) --- */

/* Save a pending sweep entry to DB. */
int persist_save_sweep(persist_t *p, const sweep_entry_t *e);

/* Load all non-confirmed sweep entries from DB. Returns 1 on success. */
int persist_load_sweeps(persist_t *p, sweep_entry_t *entries,
                         size_t *n_entries, size_t max_entries);

/* Build a to_local sweep TX.
   Spends the to_local output (P2TR with CSV tapscript) after CSV delay.
   ch: channel with basepoints and per-commitment secrets.
   commitment_txid: the commitment TX whose to_local we're sweeping.
   to_local_vout/amount: the output index and amount.
   dest_spk/len: destination P2TR scriptPubKey.
   Returns 1 on success. */
int channel_build_to_local_sweep(const channel_t *ch, tx_buf_t *sweep_tx_out,
    const unsigned char *commitment_txid,
    uint32_t to_local_vout, uint64_t to_local_amount,
    const unsigned char *dest_spk, size_t dest_spk_len);

/* Build a penalty output sweep TX.
   Spends the penalty TX output (P2TR key-path, local_payment_basepoint).
   No CSV delay — immediate spend.
   Returns 1 on success. */
int channel_build_penalty_output_sweep(const channel_t *ch,
    tx_buf_t *sweep_tx_out,
    const unsigned char *penalty_txid,
    uint32_t penalty_vout, uint64_t penalty_amount,
    const unsigned char *dest_spk, size_t dest_spk_len);

/* Build an HTLC timeout output sweep TX.
   Spends the HTLC timeout TX output after CSV delay.
   Returns 1 on success. */
int channel_build_htlc_output_sweep(const channel_t *ch,
    tx_buf_t *sweep_tx_out,
    const unsigned char *htlc_timeout_txid,
    uint32_t htlc_vout, uint64_t htlc_amount,
    const unsigned char *dest_spk, size_t dest_spk_len);

#endif /* SUPERSCALAR_SWEEPER_H */
