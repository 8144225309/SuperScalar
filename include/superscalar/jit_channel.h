#ifndef SUPERSCALAR_JIT_CHANNEL_H
#define SUPERSCALAR_JIT_CHANNEL_H

#include "channel.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* JIT channel lifecycle states */
typedef enum {
    JIT_STATE_NONE,      /* No JIT channel */
    JIT_STATE_FUNDING,   /* Funding tx created, awaiting confirmation */
    JIT_STATE_OPEN,      /* Channel operational */
    JIT_STATE_MIGRATING, /* Balance being moved to new factory */
    JIT_STATE_CLOSED     /* Cooperatively closed */
} jit_state_t;

/* JIT channel: a standalone 2-of-2 channel between LSP and one client,
   used when no factory channel is available (factory expired, client
   reconnects after death, not enough co-signers for rotation). */
typedef struct jit_channel {
    jit_state_t state;
    channel_t channel;          /* Reuses existing channel_t */
    uint32_t jit_channel_id;    /* 0x8000 | client_idx (avoids factory ID collisions) */
    size_t client_idx;
    char funding_txid_hex[65];
    uint32_t funding_vout;
    uint64_t funding_amount;
    int funding_confirmed;
    time_t created_at;
    uint32_t created_block;
    uint32_t target_factory_id; /* Factory to migrate into, or 0 */
    char funding_tx_hex[4096]; /* Signed funding tx hex for crash recovery */
} jit_channel_t;

#define JIT_MAX_CHANNELS 8
#define JIT_CHANNEL_ID_BASE 0x8000
#define JIT_OFFLINE_TIMEOUT_SEC 120  /* Seconds without message = offline */

/* Forward declarations to avoid circular includes */
struct lsp_channel_mgr;
struct lsp;

/* --- JIT channel lifecycle --- */

/* Initialize JIT channel subsystem.  Zeros out jit_channels array.
   Must be called before any other jit_channel_* function. */
int jit_channels_init(void *mgr_ptr);

/* Create a JIT channel for a specific online client.
   Funds on-chain, initializes channel_t, exchanges basepoints/nonces.
   Returns 1 on success. */
int jit_channel_create(void *mgr_ptr, void *lsp_ptr,
                        size_t client_idx, uint64_t funding_amount,
                        const char *reason);

/* Find JIT channel for a client, or NULL. */
jit_channel_t *jit_channel_find(void *mgr_ptr, size_t client_idx);

/* Check if a client has an active (OPEN) JIT channel. */
int jit_channel_is_active(void *mgr_ptr, size_t client_idx);

/* Get the effective channel for a client: factory channel if ready,
   otherwise JIT channel if open.
   Returns pointer to the channel_t and sets *channel_id_out.
   Returns NULL if no channel available. */
channel_t *jit_get_effective_channel(void *mgr_ptr, size_t client_idx,
                                      uint32_t *channel_id_out);

/* Migrate a JIT channel balance into a new factory channel.
   Cooperatively closes the JIT channel and adjusts factory channel balance.
   Returns 1 on success. */
int jit_channel_migrate(void *mgr_ptr, void *lsp_ptr,
                         size_t client_idx, uint32_t target_factory_id);

/* Check JIT channels in FUNDING state; transition to OPEN when confirmed.
   Returns number of channels that transitioned. */
int jit_channels_check_funding(void *mgr_ptr);

/* Clean up JIT channel resources. */
void jit_channels_cleanup(void *mgr_ptr);

/* --- JIT state string conversion --- */

const char *jit_state_to_str(jit_state_t state);
jit_state_t jit_state_from_str(const char *str);

#endif /* SUPERSCALAR_JIT_CHANNEL_H */
