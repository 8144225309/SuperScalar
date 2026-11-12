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
    char close_txid_hex[65];   /* Cooperative close this LSP broadcast for the
                                  channel, or empty.  Not persisted. */
} jit_channel_t;

#define JIT_MAX_CHANNELS 16
#define JIT_CHANNEL_ID_BASE 0x8000
#define JIT_OFFLINE_TIMEOUT_SEC 300  /* Seconds without message = offline */

/* Forward declarations to avoid circular includes */
struct lsp_channel_mgr;
struct lsp;

/* --- JIT channel lifecycle --- */

/* Initialize JIT channel subsystem.  Zeros out jit_channels array.
   Must be called before any other jit_channel_* function.
   Opening new JIT channels is left disabled: the caller turns it on by
   setting jit_enabled on the manager. */
int jit_channels_init(void *mgr_ptr);

/* 1 if this manager may open new JIT channels, 0 otherwise.  Opening is
   experimental and off unless the operator opted in.  Channels that already
   exist are tracked and closed regardless of this setting. */
int jit_channels_enabled(void *mgr_ptr);

/* Create a JIT channel for a specific online client.
   Funds on-chain, initializes channel_t, exchanges basepoints/nonces.
   Refuses (returns 0) before sending anything to the client or touching the
   wallet when jit_channels_enabled() is 0.
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

/* 1 if the chain backend (chain_backend_t *) shows that the JIT channel has
   been closed by close_txid: that transaction has at least the close depth
   (chain_close_confs) and the funding output is spent by a confirmed
   transaction.  0 otherwise, including when the backend cannot tell, has no
   such queries, is NULL, or close_txid is NULL or empty. */
int jit_close_confirmed(void *chain_be_ptr, const jit_channel_t *jit,
                        const char *close_txid);

/* Retire a JIT channel after a rotation.
   Only a channel closed by the cooperative close this LSP broadcast for it
   (jit->close_txid_hex) is retired, once jit_close_confirmed() holds: it is
   marked CLOSED, its record and watch entries are removed and the client is
   told with MSG_JIT_MIGRATE, which names the close.  Any other channel,
   including one whose output was spent by some other transaction (a
   commitment, say), stays OPEN with its record and watch entries, and the
   client is not told anything.
   Returns 1 if the channel was retired, 0 if it was kept (or none is open). */
int jit_channel_migrate(void *mgr_ptr, void *lsp_ptr,
                         size_t client_idx, uint32_t target_factory_id);

/* Client side of MSG_JIT_MIGRATE for the client's JIT channel record `jit`.
   The record is closed and its persisted row deleted only when the message
   names this channel and the client's own chain view (the watchtower's chain
   backend) confirms the close the message names (jit_close_confirmed);
   otherwise the record and its row are left as they are.  Watch entries are
   removed only under the JIT channel's own id, never the factory channel's.
   wt_ptr is a watchtower_t * (may be NULL), db_ptr a persist_t * (may be
   NULL).  Returns 1 if the record was closed, 0 if it was kept. */
int jit_client_handle_migrate(jit_channel_t *jit, uint32_t migrate_jit_id,
                               const char *close_txid,
                               void *wt_ptr, void *db_ptr);

/* Check JIT channels in FUNDING state; transition to OPEN when confirmed.
   Returns number of channels that transitioned. */
int jit_channels_check_funding(void *mgr_ptr);

/* Cooperatively close a JIT channel using an extracted client secret key.
   Used during rotation (Phase A.5) after PTLC turnover reveals the client key.
   Spends the JIT UTXO to the LSP wallet. Returns 1 on success. */
int jit_channel_cooperative_close(void *mgr_ptr, size_t client_idx,
                                   const unsigned char *extracted_client_key,
                                   void *chain_be);

/* Attempt to force-close a JIT channel.
   Since JIT uses MuSig2 2-of-2, the LSP can't unilaterally sign.
   This function detects if the commitment TX is already on-chain
   (client-initiated close) and handles tracking.
   Returns 1 if the channel was closed or is being tracked, 0 on error. */
int jit_channel_force_close(void *mgr_ptr, size_t client_idx,
                             void *chain_be_ptr);

/* Clean up JIT channel resources. */
void jit_channels_cleanup(void *mgr_ptr);

/* --- JIT state string conversion --- */

const char *jit_state_to_str(jit_state_t state);
jit_state_t jit_state_from_str(const char *str);

#endif /* SUPERSCALAR_JIT_CHANNEL_H */
