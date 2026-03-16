#ifndef SUPERSCALAR_PERSIST_H
#define SUPERSCALAR_PERSIST_H

#include "channel.h"
#include "factory.h"
#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

typedef struct {
    sqlite3 *db;
    char path[256];
    int in_transaction;  /* nonzero if BEGIN has been issued */
} persist_t;

/* Current schema version. Bump when adding migrations. */
#define PERSIST_SCHEMA_VERSION 4

/* Open or create database at path. Creates schema if needed.
   Runs migrations if DB version < code version.
   Rejects if DB version > code version (prevents old code on new DB).
   Pass NULL or ":memory:" for in-memory database.
   Returns 1 on success, 0 on error. */
int persist_open(persist_t *p, const char *path);

/* Open database read-only. No schema creation or migration.
   Writes will fail. For standalone watchtower / backup tools.
   Returns 1 on success, 0 on error. */
int persist_open_readonly(persist_t *p, const char *path);

/* Get the current schema version from the database. Returns 0 if unknown. */
int persist_schema_version(persist_t *p);

/* Close database. */
void persist_close(persist_t *p);

/* Begin a transaction. Returns 1 on success, 0 on error. */
int persist_begin(persist_t *p);

/* Commit the current transaction. Returns 1 on success, 0 on error. */
int persist_commit(persist_t *p);

/* Rollback the current transaction. Returns 1 on success, 0 on error. */
int persist_rollback(persist_t *p);

/* Check if a transaction is currently active. */
int persist_in_transaction(const persist_t *p);

/* --- Factory persistence --- */

/* Save factory metadata (funding info, participants, step_blocks, etc.).
   factory_id is caller-assigned (typically 0 for single-factory PoC). */
int persist_save_factory(persist_t *p, const factory_t *f,
                          secp256k1_context *ctx, uint32_t factory_id);

/* Check if a factory row exists in the database.  Returns 1 if present. */
int persist_has_factory(persist_t *p, uint32_t factory_id);

/* Load factory metadata. Caller must have initialized f->pubkeys with
   correct keys before calling (used to rebuild the tree).
   Returns 1 on success. */
int persist_load_factory(persist_t *p, uint32_t factory_id,
                          factory_t *f, secp256k1_context *ctx);

/* --- Channel persistence --- */

/* Save channel state (balances, commitment_number, funding info). */
int persist_save_channel(persist_t *p, const channel_t *ch,
                          uint32_t factory_id, uint32_t slot);

/* Load channel core state (balances, commitment_number).
   Channel must already be initialized via channel_init() with the correct
   keys. This overwrites balances and commitment_number. */
int persist_load_channel_state(persist_t *p, uint32_t channel_id,
                                 uint64_t *local_amount,
                                 uint64_t *remote_amount,
                                 uint64_t *commitment_number);

/* Update channel balances after a payment. */
int persist_update_channel_balance(persist_t *p, uint32_t channel_id,
                                     uint64_t local_amount,
                                     uint64_t remote_amount,
                                     uint64_t commitment_number);

/* --- Revocation secrets --- */

/* Save a revocation secret for a given channel and commitment number. */
int persist_save_revocation(persist_t *p, uint32_t channel_id,
                              uint64_t commitment_number,
                              const unsigned char *secret32);

/* Load revocation secrets into flat arrays. */
int persist_load_revocations_flat(persist_t *p, uint32_t channel_id,
                                    unsigned char (*secrets_out)[32],
                                    uint8_t *valid_out, size_t max,
                                    size_t *count_out);

/* --- Local per-commitment secrets --- */

/* Save a local per-commitment secret for a given channel and commitment number. */
int persist_save_local_pcs(persist_t *p, uint32_t channel_id,
                             uint64_t commit_num,
                             const unsigned char *secret32);

/* Load all local per-commitment secrets for a channel.
   Stores into secrets_out[commit_num]. Returns count loaded via count_out. */
int persist_load_local_pcs(persist_t *p, uint32_t channel_id,
                             unsigned char (*secrets_out)[32], size_t max,
                             size_t *count_out);

/* --- Remote per-commitment points --- */

/* Save a remote per-commitment point (33-byte compressed). */
int persist_save_remote_pcp(persist_t *p, uint32_t channel_id,
                              uint64_t commit_num,
                              const unsigned char *point33);

/* Load a remote per-commitment point. Returns 1 if found. */
int persist_load_remote_pcp(persist_t *p, uint32_t channel_id,
                              uint64_t commit_num,
                              unsigned char *point33_out);

/* --- HTLC persistence --- */

/* Save an HTLC entry. */
int persist_save_htlc(persist_t *p, uint32_t channel_id,
                        const htlc_t *htlc);

/* Load all HTLCs for a channel. Returns count loaded. */
size_t persist_load_htlcs(persist_t *p, uint32_t channel_id,
                            htlc_t *htlcs_out, size_t max_htlcs);

/* Delete an HTLC entry (after settle/fail). */
int persist_delete_htlc(persist_t *p, uint32_t channel_id, uint64_t htlc_id);

/* --- Nonce pool persistence --- */

/* Save serialized nonce pool state. */
int persist_save_nonce_pool(persist_t *p, uint32_t channel_id,
                              const char *side,
                              const unsigned char *pool_data,
                              size_t pool_data_len,
                              size_t next_index);

/* Load nonce pool state. Returns data in caller-allocated buffer. */
int persist_load_nonce_pool(persist_t *p, uint32_t channel_id,
                              const char *side,
                              unsigned char *pool_data_out,
                              size_t max_len,
                              size_t *data_len_out,
                              size_t *next_index_out);

/* --- Old commitment tracking (watchtower) --- */

/* Save an old commitment for watchtower monitoring. */
int persist_save_old_commitment(persist_t *p, uint32_t channel_id,
                                  uint64_t commit_num,
                                  const unsigned char *txid32,
                                  uint32_t to_local_vout,
                                  uint64_t to_local_amount,
                                  const unsigned char *to_local_spk,
                                  size_t spk_len);

/* Load old commitments for a channel. Returns count loaded. */
size_t persist_load_old_commitments(persist_t *p, uint32_t channel_id,
                                      uint64_t *commit_nums,
                                      unsigned char (*txids)[32],
                                      uint32_t *vouts,
                                      uint64_t *amounts,
                                      unsigned char (*spks)[34],
                                      size_t *spk_lens,
                                      size_t max_entries);

/* --- Old commitment HTLC outputs (watchtower) --- */

/* Forward declaration to avoid circular include with watchtower.h */
struct watchtower_htlc;
typedef struct watchtower_htlc watchtower_htlc_t;

/* Save HTLC output metadata for an old commitment. */
int persist_save_old_commitment_htlc(persist_t *p, uint32_t channel_id,
    uint64_t commit_num, const watchtower_htlc_t *htlc);

/* Load HTLC output metadata for an old commitment. Returns count loaded. */
size_t persist_load_old_commitment_htlcs(persist_t *p, uint32_t channel_id,
    uint64_t commit_num, watchtower_htlc_t *htlcs_out, size_t max_htlcs);

/* --- Wire message logging (Phase 22) --- */

/* Log a wire message to the wire_messages table. */
void persist_log_wire_message(persist_t *p, int direction, uint8_t msg_type,
                               const char *peer_label, const void *json);

/* --- Factory tree nodes (Phase 22) --- */

/* Save all tree nodes for a factory (includes signed_tx_hex if available). */
int persist_save_tree_nodes(persist_t *p, const factory_t *f, uint32_t factory_id);

/* --- Broadcast audit log --- */

/* Log a broadcast attempt (txid, source label, raw hex, result).
   source examples: "tree_node_0", "penalty", "cpfp", "jit_funding". */
int persist_log_broadcast(persist_t *p, const char *txid,
                           const char *source, const char *raw_hex,
                           const char *result);

/* --- Signing progress tracking --- */

/* Save nonce/partial-sig receipt for one signer on one tree node. */
int persist_save_signing_progress(persist_t *p, uint32_t factory_id,
                                    uint32_t node_index, uint32_t signer_slot,
                                    int has_nonce, int has_partial_sig);

/* Clear all signing progress for a factory (after successful aggregate). */
int persist_clear_signing_progress(persist_t *p, uint32_t factory_id);

/* --- Ladder factory state (Phase 22) --- */

/* Save ladder factory lifecycle state.
   state_str: "active", "dying", or "expired". */
int persist_save_ladder_factory(persist_t *p, uint32_t factory_id,
                                 const char *state_str,
                                 int is_funded, int is_initialized,
                                 size_t n_departed,
                                 uint32_t created_block,
                                 uint32_t active_blocks,
                                 uint32_t dying_blocks,
                                 int partial_rotation);

/* --- DW counter state (Phase 23) --- */

int persist_save_dw_counter(persist_t *p, uint32_t factory_id,
                             uint32_t current_epoch, uint32_t n_layers,
                             const uint32_t *layer_states);
int persist_load_dw_counter(persist_t *p, uint32_t factory_id,
                             uint32_t *epoch_out, uint32_t *n_layers_out,
                             uint32_t *layer_states_out, size_t max_layers);

/* Extended versions with per-leaf DW state (N leaf nodes) */
int persist_save_dw_counter_with_leaves(persist_t *p, uint32_t factory_id,
                                         uint32_t current_epoch, uint32_t n_layers,
                                         const uint32_t *layer_states,
                                         int per_leaf_enabled,
                                         const uint32_t *leaf_states,
                                         int n_leaf_nodes);
int persist_load_dw_counter_with_leaves(persist_t *p, uint32_t factory_id,
                                         uint32_t *epoch_out, uint32_t *n_layers_out,
                                         uint32_t *layer_states_out, size_t max_layers,
                                         int *per_leaf_enabled_out,
                                         uint32_t *leaf_states_out,
                                         int *n_leaf_nodes_out,
                                         size_t max_leaf_nodes);

/* --- Departed clients (Phase 23) --- */

int persist_save_departed_client(persist_t *p, uint32_t factory_id,
                                  uint32_t client_idx,
                                  const unsigned char *extracted_key32);
size_t persist_load_departed_clients(persist_t *p, uint32_t factory_id,
                                      int *departed_out,
                                      unsigned char (*keys_out)[32],
                                      size_t max_clients);

/* --- Invoice registry (Phase 23) --- */

int persist_save_invoice(persist_t *p,
                          const unsigned char *payment_hash32,
                          size_t dest_client, uint64_t amount_msat);
int persist_deactivate_invoice(persist_t *p,
                                const unsigned char *payment_hash32);
size_t persist_load_invoices(persist_t *p,
                              unsigned char (*hashes_out)[32],
                              size_t *dest_clients_out,
                              uint64_t *amounts_out,
                              size_t max_invoices);

/* --- HTLC origin tracking (Phase 23) --- */

int persist_save_htlc_origin(persist_t *p,
                              const unsigned char *payment_hash32,
                              uint64_t bridge_htlc_id, uint64_t request_id,
                              size_t sender_idx, uint64_t sender_htlc_id);
int persist_deactivate_htlc_origin(persist_t *p,
                                    const unsigned char *payment_hash32);
size_t persist_load_htlc_origins(persist_t *p,
                                  unsigned char (*hashes_out)[32],
                                  uint64_t *bridge_ids_out,
                                  uint64_t *request_ids_out,
                                  size_t *sender_idxs_out,
                                  uint64_t *sender_htlc_ids_out,
                                  size_t max_origins);

/* --- Client invoices (Phase 23) --- */

int persist_save_client_invoice(persist_t *p,
                                 const unsigned char *payment_hash32,
                                 const unsigned char *preimage32,
                                 uint64_t amount_msat);
int persist_deactivate_client_invoice(persist_t *p,
                                       const unsigned char *payment_hash32);
size_t persist_load_client_invoices(persist_t *p,
                                     unsigned char (*hashes_out)[32],
                                     unsigned char (*preimages_out)[32],
                                     uint64_t *amounts_out,
                                     size_t max_invoices);

/* --- Channel basepoints --- */

/* Save local basepoint secrets + remote basepoint pubkeys for a channel. */
int persist_save_basepoints(persist_t *p, uint32_t channel_id,
                             const channel_t *ch);

/* Load basepoints from DB. local_secrets[4][32] = pay/delay/revoc/htlc secrets.
   remote_bps[4][33] = compressed pubkeys in same order. Returns 1 on success. */
int persist_load_basepoints(persist_t *p, uint32_t channel_id,
                             unsigned char local_secrets[4][32],
                             unsigned char remote_bps[4][33]);

/* --- ID counters (Phase 23) --- */

int persist_save_counter(persist_t *p, const char *name, uint64_t value);
uint64_t persist_load_counter(persist_t *p, const char *name,
                               uint64_t default_val);

/* --- Watchtower anchor key persistence --- */

/* Save the anchor secret key (32 bytes) to the watchtower_keys table.
   On watchtower init, the anchor key is loaded if present; otherwise generated
   fresh and saved. This prevents loss of unspent anchor outputs across restarts. */
int persist_save_anchor_key(persist_t *p, const unsigned char *seckey32);

/* Load the anchor secret key. Returns 1 if found, 0 if not. */
int persist_load_anchor_key(persist_t *p, unsigned char *seckey32_out);

/* --- Watchtower pending entry persistence --- */

/* Save a pending penalty entry (for CPFP bump tracking across restarts). */
int persist_save_pending(persist_t *p, const char *txid,
                           uint32_t anchor_vout, uint64_t anchor_amount,
                           int cycles_in_mempool, int bump_count);

/* Load all pending entries. Returns count loaded. */
size_t persist_load_pending(persist_t *p, char (*txids_out)[65],
                              uint32_t *vouts_out, uint64_t *amounts_out,
                              int *cycles_out, int *bumps_out,
                              size_t max_entries);

/* Delete a pending entry by txid (e.g., after confirmation). */
int persist_delete_pending(persist_t *p, const char *txid);

/* --- JIT Channel persistence (Gap #2) --- */

/* Forward declaration */
struct jit_channel;
typedef struct jit_channel jit_channel_t;

/* Save a JIT channel entry to the database. */
int persist_save_jit_channel(persist_t *p, const void *jit_ptr);

/* Load all JIT channels. Returns count loaded. */
size_t persist_load_jit_channels(persist_t *p, void *out_ptr, size_t max,
                                   size_t *count_out);

/* Update JIT channel state. */
int persist_update_jit_state(persist_t *p, uint32_t jit_id, const char *state);

/* Update JIT channel balance. */
int persist_update_jit_balance(persist_t *p, uint32_t jit_id,
                                 uint64_t local, uint64_t remote, uint64_t cn);

/* Delete a JIT channel by ID. */
int persist_delete_jit_channel(persist_t *p, uint32_t jit_id);

/* --- BIP 158 scan checkpoint --- */

/*
 * Save (upsert) a singleton checkpoint row that records where the BIP 158
 * light client scan left off.  header_hashes / filter_headers are flat
 * arrays of BIP158_HEADER_WINDOW × 32 bytes; pass NULL / 0 to omit blobs.
 * Returns 1 on success.
 */
int persist_save_bip158_checkpoint(persist_t *p,
                                    int32_t tip_height,
                                    int32_t headers_synced,
                                    int32_t filter_headers_synced,
                                    const uint8_t *header_hashes,
                                    size_t header_hashes_len,
                                    const uint8_t *filter_headers,
                                    size_t filter_headers_len);

/*
 * Load the checkpoint saved by persist_save_bip158_checkpoint().
 * Out-parameters are filled only when non-NULL.  Ring buffer blobs are
 * copied into caller-supplied buffers up to _cap bytes.
 * Returns 1 if a checkpoint row was found, 0 if none exists yet.
 */
int persist_load_bip158_checkpoint(persist_t *p,
                                    int32_t *tip_height_out,
                                    int32_t *headers_synced_out,
                                    int32_t *filter_headers_synced_out,
                                    uint8_t *header_hashes_out,
                                    size_t header_hashes_cap,
                                    uint8_t *filter_headers_out,
                                    size_t filter_headers_cap);

/* --- Flat revocation secrets (Phase 2: item 2.8) --- */

/* Save flat revocation secrets for a factory. */
int persist_save_flat_secrets(persist_t *p, uint32_t factory_id,
                               const unsigned char secrets[][32],
                               size_t n_secrets);

/* Load flat revocation secrets. Returns count loaded. */
size_t persist_load_flat_secrets(persist_t *p, uint32_t factory_id,
                                  unsigned char secrets_out[][32],
                                  size_t max_secrets);

/* --- HD wallet UTXO tracking (schema v2) --- */

/* Save (insert) a new unspent UTXO discovered by the HD wallet scanner. */
int persist_save_hd_utxo(persist_t *p,
                           const char *txid,   /* 64-char display-order hex */
                           uint32_t vout,
                           uint64_t amount_sats,
                           uint32_t key_index);

/* Mark a UTXO as spent (called when input scanner detects the spend). */
int persist_mark_hd_utxo_spent(persist_t *p, const char *txid, uint32_t vout);

/*
 * Find the best unspent UTXO with amount >= min_sats.
 * Returns 1 if found, 0 otherwise.
 */
int persist_get_hd_utxo(persist_t *p,
                          uint64_t min_sats,
                          char txid_out[65],
                          uint32_t *vout_out,
                          uint64_t *amount_out,
                          uint32_t *key_index_out);

/* Save / load the HD wallet's next unused address index. */
int persist_save_hd_next_index(persist_t *p, uint32_t next_index);
uint32_t persist_load_hd_next_index(persist_t *p);

/*
 * Save / load the HD wallet's BIP 32 seed (up to 64 bytes).
 * The seed is stored as hex in the hd_wallet_state row (schema v2).
 * If no seed row exists, persist_load_hd_seed returns 0; the caller
 * should generate a fresh seed and save it.
 */
int persist_save_hd_seed(persist_t *p,
                           const unsigned char *seed, size_t seed_len);
int persist_load_hd_seed(persist_t *p,
                           unsigned char *seed_out, size_t *seed_len_out,
                           size_t seed_cap);

/* Save / load the HD wallet's lookahead window size. */
int persist_save_hd_lookahead(persist_t *p, uint32_t lookahead);
uint32_t persist_load_hd_lookahead(persist_t *p);

/* --- BOLT 12 Offers (schema v3) --- */

/* Save an offer (bech32m-encoded string).
 * offer_id: caller-assigned 32-byte identifier (e.g. SHA256 of offer bytes).
 * encoded: null-terminated bech32m offer string.
 * Returns 1 on success. */
int persist_save_offer(persist_t *p,
                        const unsigned char *offer_id32,
                        const char *encoded);

/* List all stored offers.
 * ids_out: array of 32-byte offer IDs (caller-allocated, max_offers entries)
 * encoded_out: array of char buffers, each BOLT12_OFFER_ENC_MAX bytes (caller-allocated)
 * Returns number of offers loaded. */
#define PERSIST_OFFER_ENC_MAX 512
size_t persist_list_offers(persist_t *p,
                            unsigned char (*ids_out)[32],
                            char (*encoded_out)[PERSIST_OFFER_ENC_MAX],
                            size_t max_offers);

/* Delete an offer by ID. Returns 1 if deleted, 0 if not found or error. */
int persist_delete_offer(persist_t *p, const unsigned char *offer_id32);

/* --- LSP endpoint cache (schema v4) ---
 *
 * Cache the resolved host/port/pubkey for a domain so clients don't need to
 * re-fetch /.well-known/lsps.json on every start.
 */
int persist_save_lsp_endpoint(persist_t *p,
                               const char *domain,
                               const char *host,
                               uint16_t    port,
                               const char *pubkey_hex);

/* Returns 1 if found, 0 otherwise. host_out/pubkey_out buffers are NUL-terminated. */
int persist_load_lsp_endpoint(persist_t *p,
                               const char *domain,
                               char *host_out,       size_t host_cap,
                               uint16_t   *port_out,
                               char *pubkey_hex_out, size_t pubkey_cap);

#endif /* SUPERSCALAR_PERSIST_H */
