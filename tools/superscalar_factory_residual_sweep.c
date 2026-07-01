/*
 * superscalar_factory_residual_sweep: recover the MuSig/CLTV/L-stock residual
 * outputs of a (test) factory whose tree was broadcast (e.g. after a breach),
 * by reconstructing the factory IN-PROCESS from the seckeys + funding + params,
 * matching each on-chain output to its tree node, and producing a BIP-341
 * key-path MuSig2 signature with the node's exact keyagg + taptweak.
 *
 * We hold every participant's seckey (test factories), so each N-of-N / 2-of-2
 * key-path is signable offline.  The merkle/taptweak per output type:
 *   - node funding (sub spending_spk): keyagg = node signers, merkle = node->merkle_root
 *   - channel output i               : keyagg = [client_i, LSP], merkle = factory-CLTV leaf
 *   - L-stock (last output)          : keyagg = node signers, merkle = L-stock taptree
 * The reconstructed SPK is ASSERTED == the on-chain SPK BEFORE signing, so a
 * wrong key/merkle/funding-order fails safe (no wasted fee), never a bad sig.
 *
 * Usage:
 *   superscalar_factory_residual_sweep \
 *     --lsp-seckey HEX64 --client-seckeys HEX64,HEX64,... \
 *     --funding-txid HEX64 --funding-vout N --funding-amount SATS \
 *     --cltv-timeout N --ps-sub-arity K [--step-blocks S --states-per-layer L] \
 *     --dest-spk HEX --fee SATS \
 *     --sweep TXID:VOUT:AMOUNT:SPKHEX  [--sweep ...] \
 *     [--broadcast] [--network signet|regtest]
 */
#include "superscalar/factory.h"
#include "superscalar/musig.h"
#include "superscalar/tapscript.h"
#include "superscalar/tx_builder.h"
#include "superscalar/sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int  hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);
extern void build_p2tr_script_pubkey(unsigned char *spk_out34,
                                     const secp256k1_xonly_pubkey *output_key);

#define MAXSW 32

static int parse_hex32(const char *h, unsigned char out[32]) {
    return h && strlen(h) == 64 && hex_decode(h, out, 32) == 32;
}

/* Find the tree output matching spk34.  On success fill signer participant
   indices (into f->pubkeys) + the merkle root (has_merkle=0 -> empty). */
static int match_output(const factory_t *f, const unsigned char *spk34,
                        uint32_t *signers_out, size_t *n_signers_out,
                        unsigned char merkle_out[32], int *has_merkle_out,
                        char *what, size_t whatcap) {
    /* Pass 1: node funding outputs (spending_spk) -- N-of-N, the node's own merkle.
       Done across ALL nodes FIRST so a leaf's sub-funding output (which equals the sub
       node's spending_spk) matches the SUB node's N-of-N here, instead of being
       mis-classified as a channel by the leaf's output loop in pass 2. */
    for (size_t ni = 0; ni < f->n_nodes; ni++) {
        const factory_node_t *n = &f->nodes[ni];
        if (n->spending_spk_len == 34 && memcmp(spk34, n->spending_spk, 34) == 0) {
            memcpy(signers_out, n->signer_indices, n->n_signers * sizeof(uint32_t));
            *n_signers_out = n->n_signers;
            if (n->has_taptree) { memcpy(merkle_out, n->merkle_root, 32); *has_merkle_out = 1; }
            else *has_merkle_out = 0;
            snprintf(what, whatcap, "node %zu funding (n_signers=%zu)", ni, n->n_signers);
            return 1;
        }
    }
    /* Pass 2: each node's own outputs -- channels (v<last) + L-stock (last). */
    for (size_t ni = 0; ni < f->n_nodes; ni++) {
        const factory_node_t *n = &f->nodes[ni];
        for (size_t v = 0; v < n->n_outputs; v++) {
            if (n->outputs[v].script_pubkey_len != 34 ||
                memcmp(spk34, n->outputs[v].script_pubkey, 34) != 0) continue;
            if (v == n->n_outputs - 1) {
                /* L-stock: N-of-N keyagg + L-stock taptree */
                memcpy(signers_out, n->signer_indices, n->n_signers * sizeof(uint32_t));
                *n_signers_out = n->n_signers;
                if (!factory_l_stock_merkle(f, n, merkle_out)) return -1;
                *has_merkle_out = 1;
                snprintf(what, whatcap, "node %zu L-stock", ni);
            } else {
                /* channel v: keyagg = [client_v, LSP], merkle = factory CLTV leaf */
                signers_out[0] = n->signer_indices[1 + v];
                signers_out[1] = n->signer_indices[0];
                *n_signers_out = 2;
                if (f->cltv_timeout > 0) {
                    secp256k1_xonly_pubkey lsp_xonly;
                    tapscript_leaf_t cltv_leaf;
                    if (!secp256k1_xonly_pubkey_from_pubkey(f->ctx, &lsp_xonly, NULL, &f->pubkeys[0]) ||
                        !tapscript_build_cltv_timeout(&cltv_leaf, f->cltv_timeout, &lsp_xonly, f->ctx) ||
                        !tapscript_merkle_root(merkle_out, &cltv_leaf, 1)) return -1;
                    *has_merkle_out = 1;
                } else *has_merkle_out = 0;
                snprintf(what, whatcap, "node %zu channel vout %zu", ni, v);
            }
            return 1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *lsp_sk_hex = NULL, *clients_csv = NULL, *fund_txid_hex = NULL;
    const char *dest_spk_hex = NULL, *network = "signet";
    uint32_t fund_vout = 0, ps_sub_arity = 2; long cltv_timeout = 0;
    uint16_t step_blocks_arg = 0; uint32_t states_per_layer_arg = 0;
    uint64_t fund_amount = 0, fee = 0;
    int do_broadcast = 0, enable_hashlock = 0, do_dump = 0;
    char *sweeps[MAXSW]; size_t n_sweeps = 0;
    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i],"--lsp-seckey")    && i+1<argc) lsp_sk_hex = argv[++i];
        else if (!strcmp(argv[i],"--client-seckeys")&& i+1<argc) clients_csv = argv[++i];
        else if (!strcmp(argv[i],"--funding-txid")  && i+1<argc) fund_txid_hex = argv[++i];
        else if (!strcmp(argv[i],"--funding-vout")  && i+1<argc) fund_vout = (uint32_t)strtoul(argv[++i],NULL,10);
        else if (!strcmp(argv[i],"--funding-amount")&& i+1<argc) fund_amount = strtoull(argv[++i],NULL,10);
        else if (!strcmp(argv[i],"--cltv-timeout")  && i+1<argc) cltv_timeout = strtol(argv[++i],NULL,10);
        else if (!strcmp(argv[i],"--ps-sub-arity")  && i+1<argc) ps_sub_arity = (uint32_t)strtoul(argv[++i],NULL,10);
        else if (!strcmp(argv[i],"--step-blocks")   && i+1<argc) step_blocks_arg = (uint16_t)strtoul(argv[++i],NULL,10);
        else if (!strcmp(argv[i],"--states-per-layer")&& i+1<argc) states_per_layer_arg = (uint32_t)strtoul(argv[++i],NULL,10);
        else if (!strcmp(argv[i],"--dest-spk")      && i+1<argc) dest_spk_hex = argv[++i];
        else if (!strcmp(argv[i],"--fee")           && i+1<argc) fee = strtoull(argv[++i],NULL,10);
        else if (!strcmp(argv[i],"--sweep")         && i+1<argc && n_sweeps<MAXSW) sweeps[n_sweeps++] = argv[++i];
        else if (!strcmp(argv[i],"--broadcast")) do_broadcast = 1;
        else if (!strcmp(argv[i],"--hashlock")) enable_hashlock = 1;
        else if (!strcmp(argv[i],"--dump")) do_dump = 1;
        else if (!strcmp(argv[i],"--network")       && i+1<argc) network = argv[++i];
        else { fprintf(stderr,"unknown arg %s\n", argv[i]); return 2; }
    }
    if (!lsp_sk_hex || !clients_csv || !fund_txid_hex || !dest_spk_hex || !n_sweeps) {
        fprintf(stderr,"missing required args\n"); return 2;
    }

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);

    /* keys: [0]=LSP, [1..]=clients */
    unsigned char sk[64][32]; secp256k1_keypair kps[64]; size_t n_part = 0;
    if (!parse_hex32(lsp_sk_hex, sk[0]) || !secp256k1_keypair_create(ctx, &kps[0], sk[0])) {
        fprintf(stderr,"bad lsp seckey\n"); return 2; }
    n_part = 1;
    { char *csv = strdup(clients_csv), *tok = strtok(csv, ",");
      while (tok && n_part < 64) {
        if (!parse_hex32(tok, sk[n_part]) || !secp256k1_keypair_create(ctx, &kps[n_part], sk[n_part])) {
            fprintf(stderr,"bad client seckey %zu\n", n_part-1); return 2; }
        n_part++; tok = strtok(NULL, ",");
      } free(csv); }
    size_t n_clients = n_part - 1;
    printf("participants: %zu (1 LSP + %zu clients)\n", n_part, n_clients);

    unsigned char fund_txid[32];
    if (!parse_hex32(fund_txid_hex, fund_txid)) { fprintf(stderr,"bad funding-txid\n"); return 2; }

    /* Rebuild the factory deterministically (same keys/arity/cltv/funding/hashlock
       -> identical keyaggs/merkles/SPKs as on-chain). */
    factory_t *f = calloc(1, sizeof(factory_t));
    factory_init(f, ctx, kps, n_part, 64, 16);
    factory_set_arity(f, FACTORY_ARITY_PS);
    if (ps_sub_arity > 0) factory_set_ps_subfactory_arity(f, ps_sub_arity);
    unsigned char fund_spk_dummy[34] = {0x51,0x20};
    factory_set_funding(f, fund_txid, fund_vout, fund_amount, fund_spk_dummy, 34);
    f->cltv_timeout = (uint32_t)cltv_timeout;
    /* DW tree shape: the LSP built the tree via lsp_run_factory_creation(step_blocks,
       states_per_layer,...); factory_build_tree reads f->step_blocks + f->states_per_layer,
       so set them here or the rebuilt tree has the wrong node count and NO output matches. */
    if (step_blocks_arg > 0) f->step_blocks = step_blocks_arg;
    if (states_per_layer_arg > 0) f->states_per_layer = states_per_layer_arg;
    /* hashlock: derive the per-factory seed from the LSP master key + funding (the
       same derivation the LSP used), enable, so L-stock SPKs reproduce. */
    unsigned char seed[32];
    factory_derive_lstock_seed(sk[0], fund_txid, fund_vout, seed);
    factory_set_shachain_seed(f, seed);
    if (enable_hashlock) factory_enable_hashlock_poison(f);
    if (!factory_build_tree(f)) { fprintf(stderr,"factory_build_tree failed\n"); return 1; }
    printf("rebuilt tree: %zu nodes, cltv_timeout=%u\n", f->n_nodes, f->cltv_timeout);
    if (do_dump) {
        for (size_t ni=0; ni<f->n_nodes; ni++){
            const factory_node_t *nd=&f->nodes[ni];
            char sb[69]; if(nd->spending_spk_len==34){hex_encode(nd->spending_spk,34,sb);sb[68]=0;} else {sb[0]=0;}
            printf("  node %zu: n_signers=%zu n_outputs=%zu spending_spk=%.24s\n", ni, nd->n_signers, nd->n_outputs, sb[0]?sb:"(none)");
            for (size_t v=0; v<nd->n_outputs; v++){
                char ob[69]; if(nd->outputs[v].script_pubkey_len==34){hex_encode(nd->outputs[v].script_pubkey,34,ob);ob[68]=0;} else {strcpy(ob,"(non-p2tr)");}
                printf("     out[%zu] %.24s\n", v, ob);
            }
        }
    }

    size_t dest_len = strlen(dest_spk_hex)/2; unsigned char dest_spk[64];
    if (dest_len > 64 || !hex_decode(dest_spk_hex, dest_spk, dest_len)) { fprintf(stderr,"bad dest-spk\n"); return 2; }

    int n_ok = 0, n_bcast = 0;
    for (size_t s = 0; s < n_sweeps; s++) {
        /* parse TXID:VOUT:AMOUNT:SPK */
        char *d = strdup(sweeps[s]);
        char *p_txid = strtok(d, ":"), *p_vout = strtok(NULL, ":");
        char *p_amt = strtok(NULL, ":"), *p_spk = strtok(NULL, ":");
        if (!p_txid || !p_vout || !p_amt || !p_spk) { fprintf(stderr,"bad --sweep %s\n", sweeps[s]); free(d); continue; }
        unsigned char in_txid[32]; uint32_t in_vout = (uint32_t)strtoul(p_vout,NULL,10);
        uint64_t in_amt = strtoull(p_amt,NULL,10);
        unsigned char spk[34];
        if (!parse_hex32(p_txid, in_txid) || strlen(p_spk)!=68 || hex_decode(p_spk, spk, 34)!=34) {
            fprintf(stderr,"bad --sweep fields %s\n", sweeps[s]); free(d); continue; }

        uint32_t signers[64]; size_t n_sig=0; unsigned char merkle[32]; int has_merkle=0; char what[64];
        int m = match_output(f, spk, signers, &n_sig, merkle, &has_merkle, what, sizeof(what));
        if (m != 1) { printf("[%s:%u] NO MATCH in tree (%d sats) spk=%s -- skipping\n", p_txid, in_vout, (int)in_amt, p_spk); free(d); continue; }

        /* tweaked output key parsed from the matched on-chain SPK (P2TR 0x5120||xonly).
           match_output already confirmed spk == a rebuilt tree output (identifies the
           output); the MuSig self-verify below confirms our (participants,merkle)
           reproduce a VALID key-path sig for it -> a wrong derivation fails the verify
           and is NEVER broadcast (no wasted fee). */
        secp256k1_pubkey pks[64]; secp256k1_keypair sgn_kps[64];
        for (size_t k=0;k<n_sig;k++){ pks[k]=f->pubkeys[signers[k]]; sgn_kps[k]=kps[signers[k]]; }
        musig_keyagg_t ka; if (!musig_aggregate_keys(ctx,&ka,pks,n_sig)){fprintf(stderr,"keyagg fail\n");free(d);continue;}
        secp256k1_xonly_pubkey tw;
        if (spk[0]!=0x51 || spk[1]!=0x20 || !secp256k1_xonly_pubkey_parse(ctx,&tw,spk+2)){fprintf(stderr,"  not a p2tr spk\n");free(d);continue;}
        char b[69]; hex_encode(spk,34,b); b[68]=0;
        printf("[%s:%u] %s  signers=%zu merkle=%d  amount=%llu  spk=%s\n",
               p_txid,in_vout,what,n_sig,has_merkle,(unsigned long long)in_amt,b);

        /* build sweep tx + key-path MuSig sign with the taptweak (always; the system()
           broadcast at the end is gated by --broadcast, so dry-run = sign + self-verify). */
        unsigned char in_txid_le[32]; memcpy(in_txid_le,in_txid,32); reverse_bytes(in_txid_le,32);
        tx_output_t o; memset(&o,0,sizeof o); o.amount_sats = in_amt - fee;
        memcpy(o.script_pubkey,dest_spk,dest_len); o.script_pubkey_len=dest_len;
        tx_buf_t utx; tx_buf_init(&utx,256);
        if (!build_unsigned_tx(&utx,NULL,in_txid_le,in_vout,0xFFFFFFFEu,&o,1)){fprintf(stderr,"  build_unsigned fail\n");free(d);continue;}
        unsigned char sighash[32];
        if (!compute_taproot_sighash(sighash,utx.data,utx.len,0,spk,34,in_amt,0xFFFFFFFEu)){fprintf(stderr,"  sighash fail\n");free(d);continue;}
        unsigned char sig[64];
        if (!musig_sign_taproot(ctx,sig,sighash,sgn_kps,n_sig,&ka, has_merkle?merkle:NULL)){fprintf(stderr,"  musig_sign fail\n");free(d);continue;}
        if (!secp256k1_schnorrsig_verify(ctx,sig,sighash,32,&tw)){printf("  SELF-VERIFY FAIL -> (participants,merkle) wrong, NOT broadcasting\n");free(d);continue;}
        printf("  self-verify OK\n");
        n_ok++;
        tx_buf_t stx; tx_buf_init(&stx,256);
        if (!finalize_signed_tx(&stx,utx.data,utx.len,sig)){fprintf(stderr,"  finalize fail\n");free(d);continue;}
        char *txh = malloc(stx.len*2+1); hex_encode(stx.data,stx.len,txh); txh[stx.len*2]=0;
        printf("  signed (%zu B)\n  hex: %s\n", stx.len, txh);
        if (!do_broadcast) { free(txh); free(d); continue; }
        char cmd[200000];
        const char *rpc = !strcmp(network,"signet") ? "-signet -rpcuser=signetrpc -stdinrpcpass -rpcport=38332"
                        : "-regtest -rpcuser=rpcuser -rpcpassword=rpcpass -rpcport=18443";
        if (!strcmp(network,"signet")) {
            const char *pw = getenv("SIGNET_RPCPASS");
            snprintf(cmd,sizeof cmd,"echo '%s' | bitcoin-cli %s sendrawtransaction %s", pw?pw:"", rpc, txh);
        } else {
            snprintf(cmd,sizeof cmd,"bitcoin-cli %s sendrawtransaction %s", rpc, txh);
        }
        int rc = system(cmd);
        if (rc==0) { printf("  BROADCAST ok\n"); n_bcast++; } else printf("  broadcast rc=%d\n", rc);
        free(txh); free(d);
    }
    printf("\nSUMMARY: %zu sweeps, %d SPK-matched, %d broadcast\n", n_sweeps, n_ok, n_bcast);
    return (n_ok == (int)n_sweeps) ? 0 : 1;
}
