#ifndef SUPERSCALAR_CHANNEL_H
#define SUPERSCALAR_CHANNEL_H

#include "types.h"
#include "musig.h"
#include "tapscript.h"
#include "tx_builder.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#define CHANNEL_DEFAULT_CSV_DELAY 144  /* ~1 day */
#define MAX_HTLCS 483              /* BOLT #2 maximum */
#define DEFAULT_HTLCS_CAP 64      /* initial allocation for dynamic htlc arrays */
#define CHANNEL_DUST_LIMIT_SATS  546   /* P2TR dust limit */
#define CHANNEL_RESERVE_SATS     5000  /* min balance to keep for fees */
#define ANCHOR_OUTPUT_AMOUNT     240   /* P2A anchor for CPFP fee bumping (sats) */

/* P2A (Pay-to-Anchor) scriptPubKey: OP_1 OP_PUSHBYTES_2 4e73 (anyone-can-spend) */
#define P2A_SPK_LEN  4
static const unsigned char P2A_SPK[4] = {0x51, 0x02, 0x4e, 0x73};

typedef enum { HTLC_OFFERED, HTLC_RECEIVED } htlc_direction_t;
typedef enum { HTLC_STATE_ACTIVE, HTLC_STATE_FULFILLED, HTLC_STATE_FAILED } htlc_state_t;

typedef struct {
    htlc_direction_t direction;
    htlc_state_t state;
    uint64_t amount_sats;
    unsigned char payment_hash[32];
    unsigned char payment_preimage[32];  /* filled on fulfill */
    uint32_t cltv_expiry;
    uint64_t id;
} htlc_t;

/* PTLC (Point Time-Locked Contract) — adaptor-signature based payment */
typedef enum { PTLC_OFFERED, PTLC_RECEIVED } ptlc_direction_t;
typedef enum { PTLC_STATE_ACTIVE, PTLC_STATE_SETTLED, PTLC_STATE_FAILED } ptlc_state_t;

typedef struct {
    ptlc_direction_t direction;
    ptlc_state_t     state;
    uint64_t         amount_sats;
    secp256k1_pubkey payment_point;   /* adaptor pubkey */
    uint64_t         id;
    uint32_t         cltv_expiry;
    unsigned char    pre_sig[64];     /* adaptor pre-signature from LSP */
    int              has_pre_sig;
    unsigned char    adapted_sig[64]; /* final adapted signature from client */
    int              has_adapted_sig;
} ptlc_t;

typedef struct {
    secp256k1_context *ctx;

    /* Funding output (from factory leaf state tx) */
    unsigned char funding_txid[32];
    uint32_t funding_vout;
    uint64_t funding_amount;
    unsigned char funding_spk[34];
    size_t funding_spk_len;

    /* Funding keys (order matters for MuSig keyagg) */
    secp256k1_pubkey local_funding_pubkey;
    secp256k1_pubkey remote_funding_pubkey;
    unsigned char local_funding_secret[32];
    musig_keyagg_t funding_keyagg;
    secp256k1_keypair local_funding_keypair;

    /* Local basepoints + secrets */
    secp256k1_pubkey local_payment_basepoint;
    unsigned char local_payment_basepoint_secret[32];
    secp256k1_pubkey local_delayed_payment_basepoint;
    unsigned char local_delayed_payment_basepoint_secret[32];
    secp256k1_pubkey local_revocation_basepoint;
    unsigned char local_revocation_basepoint_secret[32];
    secp256k1_pubkey local_htlc_basepoint;
    unsigned char local_htlc_basepoint_secret[32];

    /* Remote basepoints (public only) */
    secp256k1_pubkey remote_payment_basepoint;
    secp256k1_pubkey remote_delayed_payment_basepoint;
    secp256k1_pubkey remote_revocation_basepoint;
    secp256k1_pubkey remote_htlc_basepoint;

    uint64_t commitment_number;

    /* Per-commitment secrets (dynamically allocated, grows as needed) */
    unsigned char (*local_pcs)[32];    /* heap array of 32-byte secrets */
    size_t n_local_pcs;                /* count of stored secrets */
    size_t local_pcs_cap;              /* allocated capacity */

    /* Two-slot ring buffer for remote per-commitment points.
       Stores the two most recently received PCPs (e.g., cn=0 and cn=1 at init,
       then cn=N and cn=N+1 after revoke_and_ack). */
    secp256k1_pubkey remote_pcps[2];
    uint64_t remote_pcp_nums[2];
    uint8_t remote_pcp_valid[2];

    unsigned char (*received_revocations)[32];  /* heap array */
    uint8_t *received_revocation_valid;         /* heap validity flags */
    size_t revocations_cap;                     /* allocated capacity */

    /* Balance (satoshis) */
    uint64_t local_amount;
    uint64_t remote_amount;

    /* HTLCs (dynamically allocated, capacity htlcs_cap) */
    htlc_t *htlcs;
    size_t n_htlcs;
    size_t htlcs_cap;
    uint64_t next_htlc_id;

    /* PTLCs */
    ptlc_t          *ptlcs;
    size_t           n_ptlcs;
    size_t           ptlcs_cap;
    uint64_t         next_ptlc_id;

    /* Config */
    uint32_t to_self_delay;
    uint64_t fee_rate_sat_per_kvb;  /* sat/kvB for penalty/HTLC txs (default 1000) */
    int funder_is_local;  /* 1 if local side is the channel funder (pays commit fee) */
    int use_revocation_leaf;  /* 1 = 2-leaf taptree with revocation checksig script-path */

    /* Splicing state (Phase G) */
    int           channel_quiescent;       /* 1 if in quiescence for splice */
    unsigned char splice_pending_txid[32]; /* txid of pending splice tx (if any) */

    /* MuSig2 signer index: 0 or 1 in the canonical 2-of-2 keyagg order.
       Needed for distributed signing (Phase 12). */
    int local_funding_signer_idx;

    /* Nonce pools for commitment signing (Phase 12) */
    musig_nonce_pool_t  local_nonce_pool;
    unsigned char       remote_pubnonces_ser[MUSIG_NONCE_POOL_MAX][66];
    size_t              remote_nonce_count;
    size_t              remote_nonce_next;

    /* Cooperative close state (BOLT #2 §2.3) */
    int           close_state;      /* 0=none 1=sent_shutdown 2=recv_shutdown 3=both 4=negotiating 5=done */
    unsigned char close_our_spk[34]; /* our P2TR scriptpubkey for closing output */
    uint16_t      close_our_spk_len;
    uint64_t      close_our_fee_sat;   /* our preferred close fee */
    uint64_t      close_their_fee_sat; /* peer's last proposed fee */
    unsigned char close_remote_sig[64];  /* sig received in peer's closing_signed */
    unsigned char close_their_spk[34];  /* peer's scriptpubkey from shutdown */
    uint16_t      close_their_spk_len;

    /* Dynamic commitment: negotiated channel type (BOLT #2 PR #880) */
    uint32_t      channel_type_bits;         /* feature bits from channel_type TLV */

    /* announcement_signatures (BOLT #7 type 259) */
    uint64_t      short_channel_id;          /* block<<40 | tx_idx<<16 | vout */
    unsigned char local_node_sig[64];        /* our Schnorr sig over channel_announcement */
    unsigned char local_bitcoin_sig[64];     /* our bitcoin key sig over channel_announcement */
    unsigned char remote_node_sig[64];       /* peer's node key sig */
    unsigned char remote_bitcoin_sig[64];    /* peer's bitcoin key sig */
    int           ann_sigs_sent;             /* 1 = we sent announcement_signatures */
    int           ann_sigs_recv;             /* 1 = peer sent us announcement_signatures */
} channel_t;

/* --- Key derivation (BOLT #3) --- */

/* Simple: derived = basepoint + SHA256(per_commitment_point || basepoint) * G */
int channel_derive_pubkey(const secp256k1_context *ctx, secp256k1_pubkey *derived,
                           const secp256k1_pubkey *basepoint,
                           const secp256k1_pubkey *per_commitment_point);

/* Two-scalar: revocation_key = rb*H1 + pcp*H2 */
int channel_derive_revocation_pubkey(const secp256k1_context *ctx,
                                      secp256k1_pubkey *derived,
                                      const secp256k1_pubkey *revocation_basepoint,
                                      const secp256k1_pubkey *per_commitment_point);

/* Private key version of simple derivation */
int channel_derive_privkey(const secp256k1_context *ctx, unsigned char *derived32,
                            const unsigned char *base_secret32,
                            const secp256k1_pubkey *per_commitment_point);

/* Private key version of revocation derivation */
int channel_derive_revocation_privkey(const secp256k1_context *ctx,
                                       unsigned char *derived32,
                                       const unsigned char *revocation_basepoint_secret32,
                                       const unsigned char *per_commitment_secret32,
                                       const secp256k1_pubkey *revocation_basepoint,
                                       const secp256k1_pubkey *per_commitment_point);

/* --- Channel lifecycle --- */

int channel_init(channel_t *ch, secp256k1_context *ctx,
                  const unsigned char *local_funding_secret32,
                  const secp256k1_pubkey *local_funding_pubkey,
                  const secp256k1_pubkey *remote_funding_pubkey,
                  const unsigned char *funding_txid, uint32_t funding_vout,
                  uint64_t funding_amount,
                  const unsigned char *funding_spk, size_t funding_spk_len,
                  uint64_t local_amount, uint64_t remote_amount,
                  uint32_t to_self_delay);

void channel_cleanup(channel_t *ch);

int channel_set_local_basepoints(channel_t *ch,
                                   const unsigned char *payment_secret32,
                                   const unsigned char *delayed_payment_secret32,
                                   const unsigned char *revocation_secret32);

void channel_set_remote_basepoints(channel_t *ch,
                                     const secp256k1_pubkey *payment,
                                     const secp256k1_pubkey *delayed_payment,
                                     const secp256k1_pubkey *revocation);

/* --- Per-commitment secret (flat storage) --- */

/* Generate random per-commitment secret for commitment_num.
   Increments n_local_pcs. Returns 1 on success. */
int channel_generate_local_pcs(channel_t *ch, uint64_t commitment_num);

/* Retrieve local per-commitment secret for commitment_num.
   Returns 1 on success. */
int channel_get_local_pcs(const channel_t *ch, uint64_t commitment_num,
                           unsigned char *secret_out32);

/* Set a specific local per-commitment secret (for tests/persistence). */
void channel_set_local_pcs(channel_t *ch, uint64_t commitment_num,
                            const unsigned char *secret32);

/* Store remote's per-commitment point for a given commitment_num. */
void channel_set_remote_pcp(channel_t *ch, uint64_t commitment_num,
                             const secp256k1_pubkey *pcp);

/* Get remote's per-commitment point for commitment_num.
   For current: returns stored point.
   For old (< remote_current_pcp_num): derives from received revocation secret.
   Returns 1 on success. */
int channel_get_remote_pcp(const channel_t *ch, uint64_t commitment_num,
                            secp256k1_pubkey *pcp_out);

/* Store a received revocation secret at flat index. */
int channel_receive_revocation_flat(channel_t *ch, uint64_t commitment_num,
                                      const unsigned char *secret32);

/* Retrieve a received revocation secret. Returns 1 if valid. */
int channel_get_received_revocation(const channel_t *ch, uint64_t commitment_num,
                                      unsigned char *secret_out32);

int channel_get_per_commitment_point(const channel_t *ch, uint64_t commitment_num,
                                      secp256k1_pubkey *point_out);

int channel_get_per_commitment_secret(const channel_t *ch, uint64_t commitment_num,
                                       unsigned char *secret_out32);

/* --- Commitment TX --- */

int channel_build_commitment_tx(const channel_t *ch,
                                  tx_buf_t *unsigned_tx_out,
                                  unsigned char *txid_out32);

/* Build the remote party's commitment tx (for distributed signing).
   Swaps local/remote basepoints, amounts, HTLC directions, and uses
   the remote per-commitment point for key derivation. */
int channel_build_commitment_tx_for_remote(const channel_t *ch,
                                             tx_buf_t *unsigned_tx_out,
                                             unsigned char *txid_out32);

int channel_sign_commitment(const channel_t *ch,
                              tx_buf_t *signed_tx_out,
                              const tx_buf_t *unsigned_tx,
                              const secp256k1_keypair *remote_keypair);

/* --- Distributed commitment signing (Phase 12) --- */

/* Initialize nonce pool for channel commitment signing.
   Generates 'count' nonce pairs and stores in ch->local_nonce_pool. */
int channel_init_nonce_pool(channel_t *ch, size_t count);

/* Store peer's serialized pubnonces (received via MSG_CHANNEL_NONCES). */
int channel_set_remote_pubnonces(channel_t *ch,
                                   const unsigned char pubnonces[][66],
                                   size_t count);

/* Create partial sig for current commitment tx.
   Draws next nonce from local pool, uses peer's pubnonce at same index.
   Returns partial_sig (32 bytes serialized) and nonce_index used. */
int channel_create_commitment_partial_sig(
    channel_t *ch,
    unsigned char *partial_sig32_out,
    uint32_t *nonce_index_out);

/* Verify peer's partial sig and aggregate into full 64-byte Schnorr sig.
   Uses nonce at peer_nonce_index from both pools. */
int channel_verify_and_aggregate_commitment_sig(
    channel_t *ch,
    const unsigned char *peer_partial_sig32,
    uint32_t peer_nonce_index,
    unsigned char *full_sig64_out);

/* --- Revocation + Penalty --- */

int channel_get_revocation_secret(const channel_t *ch, uint64_t old_commitment_num,
                                    unsigned char *secret_out32);

int channel_receive_revocation(channel_t *ch, uint64_t commitment_num,
                                 const unsigned char *secret32);

int channel_build_penalty_tx(const channel_t *ch,
                               tx_buf_t *penalty_tx_out,
                               const unsigned char *commitment_txid,
                               uint32_t to_local_vout,
                               uint64_t to_local_amount,
                               const unsigned char *to_local_spk,
                               size_t to_local_spk_len,
                               uint64_t old_commitment_num,
                               const unsigned char *anchor_spk,
                               size_t anchor_spk_len);

/* Build penalty tx via script-path revocation (requires use_revocation_leaf=1).
   Uses the revocation checksig leaf in the 2-leaf taptree. */
int channel_build_penalty_tx_script_path(const channel_t *ch,
                                           tx_buf_t *penalty_tx_out,
                                           const unsigned char *commitment_txid,
                                           uint32_t to_local_vout,
                                           uint64_t to_local_amount,
                                           const unsigned char *to_local_spk,
                                           size_t to_local_spk_len,
                                           uint64_t old_commitment_num,
                                           const unsigned char *anchor_spk,
                                           size_t anchor_spk_len);

/* Set the fee rate (sat/kvB) used for penalty/HTLC transactions.
   Default is 1000 sat/kvB (1 sat/vB). */
void channel_set_fee_rate(channel_t *ch, uint64_t fee_rate_sat_per_kvb);

/* --- Cooperative close --- */

int channel_build_cooperative_close_tx(
    const channel_t *ch,
    tx_buf_t *close_tx_out,
    unsigned char *txid_out32,   /* can be NULL */
    const secp256k1_keypair *remote_keypair,
    const tx_output_t *outputs,
    size_t n_outputs);

/* --- Channel update --- */

int channel_update(channel_t *ch, int64_t delta_sats);

void channel_update_funding(channel_t *ch,
                              const unsigned char *new_funding_txid,
                              uint32_t new_funding_vout,
                              uint64_t new_funding_amount,
                              const unsigned char *new_funding_spk,
                              size_t new_funding_spk_len);

/* --- Random bytes utility --- */

int channel_read_random_bytes(unsigned char *buf, size_t len);

/* Generate random basepoint secrets and set local basepoints.
   Returns 1 on success, 0 on urandom failure. */
int channel_generate_random_basepoints(channel_t *ch);

/* --- HTLC basepoints --- */

int channel_set_local_htlc_basepoint(channel_t *ch,
                                       const unsigned char *htlc_secret32);

void channel_set_remote_htlc_basepoint(channel_t *ch,
                                         const secp256k1_pubkey *htlc_basepoint);

/* --- HTLC operations --- */

int channel_add_htlc(channel_t *ch, htlc_direction_t direction,
                      uint64_t amount_sats, const unsigned char *payment_hash32,
                      uint32_t cltv_expiry, uint64_t *htlc_id_out);

int channel_fulfill_htlc(channel_t *ch, uint64_t htlc_id,
                           const unsigned char *preimage32);

int channel_fail_htlc(channel_t *ch, uint64_t htlc_id);

/* Fail all HTLCs whose cltv_expiry <= current_height. Returns count failed. */
int channel_check_htlc_timeouts(channel_t *ch, uint32_t current_height);

/* --- HTLC resolution transactions --- */

int channel_build_htlc_success_tx(const channel_t *ch, tx_buf_t *signed_tx_out,
    const unsigned char *commitment_txid, uint32_t htlc_vout,
    uint64_t htlc_amount, const unsigned char *htlc_spk, size_t htlc_spk_len,
    size_t htlc_index);

int channel_build_htlc_timeout_tx(const channel_t *ch, tx_buf_t *signed_tx_out,
    const unsigned char *commitment_txid, uint32_t htlc_vout,
    uint64_t htlc_amount, const unsigned char *htlc_spk, size_t htlc_spk_len,
    size_t htlc_index);

int channel_build_htlc_penalty_tx(const channel_t *ch, tx_buf_t *penalty_tx_out,
    const unsigned char *commitment_txid, uint32_t htlc_vout,
    uint64_t htlc_amount, const unsigned char *htlc_spk, size_t htlc_spk_len,
    uint64_t old_commitment_num, size_t htlc_index,
    const unsigned char *anchor_spk, size_t anchor_spk_len);

/* --- PTLC resolution transactions (Phase 5: production wiring) --- */

int channel_build_ptlc_success_tx(const channel_t *ch, tx_buf_t *signed_tx_out,
    const unsigned char *commitment_txid, uint32_t ptlc_vout,
    uint64_t ptlc_amount, const unsigned char *ptlc_spk, size_t ptlc_spk_len,
    size_t ptlc_index);

int channel_build_ptlc_timeout_tx(const channel_t *ch, tx_buf_t *signed_tx_out,
    const unsigned char *commitment_txid, uint32_t ptlc_vout,
    uint64_t ptlc_amount, const unsigned char *ptlc_spk, size_t ptlc_spk_len,
    size_t ptlc_index);

#endif /* SUPERSCALAR_CHANNEL_H */
