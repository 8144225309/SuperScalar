#ifndef SUPERSCALAR_LADDER_H
#define SUPERSCALAR_LADDER_H

#include "factory.h"
#include "adaptor.h"
#include <secp256k1.h>

#define LADDER_MAX_FACTORIES 8  /* demo: 3-4 overlapping is sufficient */

typedef struct {
    factory_t factory;
    uint32_t factory_id;           /* sequential: 0, 1, 2, ... */
    factory_state_t cached_state;  /* last computed state */
    int is_funded;                 /* funding confirmed on-chain */
    int is_initialized;            /* factory_init + build_tree done */
    tx_buf_t distribution_tx;      /* pre-signed nLockTime fallback */

    /* Per-client key turnover state */
    int client_departed[FACTORY_MAX_SIGNERS];     /* 1 if PTLC complete */
    unsigned char extracted_keys[FACTORY_MAX_SIGNERS][32]; /* revealed scalars */
    size_t n_departed;
} ladder_factory_t;

typedef struct {
    secp256k1_context *ctx;
    ladder_factory_t factories[LADDER_MAX_FACTORIES];
    size_t n_factories;
    uint32_t next_factory_id;

    /* LSP keypair (participant 0 in all factories) */
    secp256k1_keypair lsp_keypair;
    secp256k1_pubkey lsp_pubkey;

    /* Parameters */
    uint32_t active_blocks;    /* default: 4320 = 30 days */
    uint32_t dying_blocks;     /* default: 432 = 3 days */

    uint32_t current_block;
} ladder_t;

int ladder_init(ladder_t *lad, secp256k1_context *ctx,
                 const secp256k1_keypair *lsp_keypair,
                 uint32_t active_blocks, uint32_t dying_blocks);

/* Create a new factory with the given client keypairs.
   Automatically sets lifecycle parameters from ladder config.
   client_keypairs: array of n_clients keypairs (NOT including LSP).
   LSP keypair is added automatically as participant 0. */
int ladder_create_factory(ladder_t *lad,
                          const secp256k1_keypair *client_keypairs,
                          size_t n_clients,
                          uint64_t funding_amount_sats,
                          const unsigned char *funding_txid,
                          uint32_t funding_vout,
                          const unsigned char *funding_spk,
                          size_t funding_spk_len);

/* Advance block height, update all factory states. */
int ladder_advance_block(ladder_t *lad, uint32_t new_block);

/* Get factory by state. Returns NULL if none found. */
ladder_factory_t *ladder_get_active(ladder_t *lad);
ladder_factory_t *ladder_get_dying(ladder_t *lad);
ladder_factory_t *ladder_get_by_id(ladder_t *lad, uint32_t factory_id);

/* Record that a client departed via PTLC key turnover. */
int ladder_record_key_turnover(ladder_t *lad, uint32_t factory_id,
                                uint32_t client_idx,
                                const unsigned char *extracted_key32);

/* Check if LSP can now cooperative-close a factory (all clients departed). */
int ladder_can_close(const ladder_t *lad, uint32_t factory_id);

/* Build cooperative close using extracted keys for departed clients.
   This builds a new set of keypairs where departed client keys are replaced
   with extracted keys, then signs a cooperative close tx. */
int ladder_build_close(ladder_t *lad, uint32_t factory_id,
                       tx_buf_t *close_tx_out,
                       const tx_output_t *outputs, size_t n_outputs);

/* Remove all EXPIRED factories from the ladder array, compacting slots.
   Returns number of slots freed. */
size_t ladder_evict_expired(ladder_t *lad);

void ladder_free(ladder_t *lad);

#endif /* SUPERSCALAR_LADDER_H */
