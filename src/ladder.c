#include "superscalar/ladder.h"
#include <string.h>
#include <stdlib.h>

extern void reverse_bytes(unsigned char *, size_t);

int ladder_init(ladder_t *lad, secp256k1_context *ctx,
                const secp256k1_keypair *lsp_keypair,
                uint32_t active_blocks, uint32_t dying_blocks)
{
    memset(lad, 0, sizeof(*lad));
    lad->ctx = ctx;
    lad->lsp_keypair = *lsp_keypair;
    if (!secp256k1_keypair_pub(ctx, &lad->lsp_pubkey, lsp_keypair))
        return 0;
    lad->active_blocks = active_blocks;
    lad->dying_blocks = dying_blocks;
    lad->current_block = 0;
    lad->n_factories = 0;
    lad->next_factory_id = 0;
    return 1;
}

int ladder_create_factory(ladder_t *lad,
                          const secp256k1_keypair *client_keypairs,
                          size_t n_clients,
                          uint64_t funding_amount_sats,
                          const unsigned char *funding_txid,
                          uint32_t funding_vout,
                          const unsigned char *funding_spk,
                          size_t funding_spk_len)
{
    if (lad->n_factories >= LADDER_MAX_FACTORIES)
        return 0;
    if (n_clients + 1 > FACTORY_MAX_SIGNERS)
        return 0;

    size_t idx = lad->n_factories;
    ladder_factory_t *lf = &lad->factories[idx];
    memset(lf, 0, sizeof(*lf));

    lf->factory_id = lad->next_factory_id++;
    tx_buf_init(&lf->distribution_tx, 256);

    /* Build combined keypair array: LSP + clients */
    size_t n_participants = n_clients + 1;
    secp256k1_keypair all_keypairs[FACTORY_MAX_SIGNERS];
    all_keypairs[0] = lad->lsp_keypair;
    for (size_t i = 0; i < n_clients; i++)
        all_keypairs[i + 1] = client_keypairs[i];

    /* Initialize factory */
    if (!factory_init(&lf->factory, lad->ctx, all_keypairs, n_participants, 1, 4)) {
        tx_buf_free(&lf->distribution_tx);
        return 0;
    }

    /* Set lifecycle */
    factory_set_lifecycle(&lf->factory, lad->current_block,
                          lad->active_blocks, lad->dying_blocks);

    /* Set funding */
    factory_set_funding(&lf->factory, funding_txid, funding_vout,
                         funding_amount_sats, funding_spk, funding_spk_len);

    /* Build tree and sign */
    if (!factory_build_tree(&lf->factory)) {
        tx_buf_free(&lf->distribution_tx);
        return 0;
    }

    /* Advance counter to max state (all delays = 0) for initial signing */
    for (uint32_t i = 0; i < lf->factory.counter.total_states - 1; i++)
        dw_counter_advance(&lf->factory.counter);

    if (!factory_sign_all(&lf->factory)) {
        tx_buf_free(&lf->distribution_tx);
        return 0;
    }

    lf->is_initialized = 1;
    lf->is_funded = 1;
    lf->cached_state = factory_get_state(&lf->factory, lad->current_block);

    lad->n_factories++;
    return 1;
}

int ladder_advance_block(ladder_t *lad, uint32_t new_block)
{
    if (new_block < lad->current_block)
        return 0;

    lad->current_block = new_block;

    /* Update cached state for all factories */
    for (size_t i = 0; i < lad->n_factories; i++) {
        ladder_factory_t *lf = &lad->factories[i];
        if (lf->is_initialized)
            lf->cached_state = factory_get_state(&lf->factory, new_block);
    }
    return 1;
}

ladder_factory_t *ladder_get_active(ladder_t *lad)
{
    for (size_t i = 0; i < lad->n_factories; i++) {
        if (lad->factories[i].cached_state == FACTORY_ACTIVE &&
            lad->factories[i].is_initialized)
            return &lad->factories[i];
    }
    return NULL;
}

ladder_factory_t *ladder_get_dying(ladder_t *lad)
{
    for (size_t i = 0; i < lad->n_factories; i++) {
        if (lad->factories[i].cached_state == FACTORY_DYING &&
            lad->factories[i].is_initialized)
            return &lad->factories[i];
    }
    return NULL;
}

ladder_factory_t *ladder_get_by_id(ladder_t *lad, uint32_t factory_id)
{
    for (size_t i = 0; i < lad->n_factories; i++) {
        if (lad->factories[i].factory_id == factory_id)
            return &lad->factories[i];
    }
    return NULL;
}

int ladder_record_key_turnover(ladder_t *lad, uint32_t factory_id,
                                uint32_t client_idx,
                                const unsigned char *extracted_key32)
{
    ladder_factory_t *lf = ladder_get_by_id(lad, factory_id);
    if (!lf)
        return 0;
    if (client_idx >= lf->factory.n_participants)
        return 0;
    if (client_idx == 0)
        return 0;  /* Can't depart LSP */

    lf->client_departed[client_idx] = 1;
    memcpy(lf->extracted_keys[client_idx], extracted_key32, 32);
    lf->n_departed++;
    return 1;
}

int ladder_can_close(const ladder_t *lad, uint32_t factory_id)
{
    for (size_t i = 0; i < lad->n_factories; i++) {
        if (lad->factories[i].factory_id == factory_id) {
            const ladder_factory_t *lf = &lad->factories[i];
            /* All clients (indices 1..n_participants-1) must have departed */
            for (size_t j = 1; j < lf->factory.n_participants; j++) {
                if (!lf->client_departed[j])
                    return 0;
            }
            return 1;
        }
    }
    return 0;
}

int ladder_build_close(ladder_t *lad, uint32_t factory_id,
                       tx_buf_t *close_tx_out,
                       const tx_output_t *outputs, size_t n_outputs)
{
    ladder_factory_t *lf = ladder_get_by_id(lad, factory_id);
    if (!lf)
        return 0;

    /* Build a keypair array using extracted keys for departed clients */
    factory_t *f = &lf->factory;
    secp256k1_keypair close_keypairs[FACTORY_MAX_SIGNERS];

    for (size_t i = 0; i < f->n_participants; i++) {
        if (i == 0) {
            /* LSP uses its own keypair */
            close_keypairs[i] = lad->lsp_keypair;
        } else if (lf->client_departed[i]) {
            /* Use extracted key */
            if (!secp256k1_keypair_create(lad->ctx, &close_keypairs[i],
                                           lf->extracted_keys[i]))
                return 0;
        } else {
            /* Client hasn't departed -- can't close */
            return 0;
        }
    }

    /* Temporarily swap keypairs in factory for signing */
    secp256k1_keypair saved_keypairs[FACTORY_MAX_SIGNERS];
    memcpy(saved_keypairs, f->keypairs,
           f->n_participants * sizeof(secp256k1_keypair));
    /* cppcheck-suppress uninitvar ; loop above initializes all [0..n_participants) elements */
    memcpy(f->keypairs, close_keypairs,
           f->n_participants * sizeof(secp256k1_keypair));

    int ok = factory_build_cooperative_close(f, close_tx_out, NULL,
                                              outputs, n_outputs);

    /* Restore original keypairs */
    memcpy(f->keypairs, saved_keypairs,
           f->n_participants * sizeof(secp256k1_keypair));

    return ok;
}

size_t ladder_evict_expired(ladder_t *lad)
{
    if (!lad) return 0;
    size_t freed = 0;
    size_t write = 0;
    for (size_t read = 0; read < lad->n_factories; read++) {
        ladder_factory_t *lf = &lad->factories[read];
        if (lf->cached_state == FACTORY_EXPIRED) {
            /* Free resources for evicted entry */
            factory_free(&lf->factory);
            tx_buf_free(&lf->distribution_tx);
            freed++;
        } else {
            if (write != read)
                lad->factories[write] = lad->factories[read];
            write++;
        }
    }
    lad->n_factories = write;
    return freed;
}

void ladder_free(ladder_t *lad)
{
    for (size_t i = 0; i < lad->n_factories; i++) {
        factory_free(&lad->factories[i].factory);
        tx_buf_free(&lad->factories[i].distribution_tx);
    }
    lad->n_factories = 0;
}
