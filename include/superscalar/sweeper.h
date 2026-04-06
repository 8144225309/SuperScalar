/*
 * sweeper.h — Automatic sweep of timelocked/intermediate outputs to wallet
 *
 * After a factory force-close, funds end up in intermediate outputs:
 *   1. Leaf outputs → need commitment TX broadcast
 *   2. to_local outputs → need CSV-delayed sweep
 *   3. Penalty outputs → need key-path sweep
 *   4. HTLC timeout outputs → need CSV-delayed sweep
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
    SWEEP_HTLC_TIMEOUT_OUTPUT    /* HTLC timeout TX confirmed + CSV → sweep output */
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
} sweep_entry_t;

#define SWEEPER_MAX_ENTRIES 64

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
   Returns number of sweeps broadcast this cycle. */
int sweeper_check(sweeper_t *sw);

/* Register a new sweep. Returns 1 on success. */
int sweeper_add(sweeper_t *sw, sweep_type_t type,
                const unsigned char *source_txid32,
                uint32_t source_vout, uint64_t amount_sats,
                uint32_t csv_delay,
                uint32_t channel_id, uint32_t factory_id,
                uint64_t commitment_number);

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
