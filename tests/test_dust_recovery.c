/*
 * test_dust_recovery.c — #257 SF-CHEAT-DUST-RACE unit suite
 *
 * Validates both halves of the dust-race contract:
 *
 *   DR1: htlc_commit_recv_update_fee REJECTS feerates that would push an
 *        active above-dust HTLC's sweep amount below CHANNEL_DUST_LIMIT_SATS.
 *        This is the honest defense — without it, a peer can strand the
 *        counterparty's HTLC at force-close.
 *
 *   DR2: htlc_commit_recv_update_fee REJECTS feerates that would push an
 *        active PTLC's sweep amount below dust (PTLC counterpart of DR1).
 *
 *   DR3: With SS_CHEAT_DUST_RACE=1 in the environment, the same abusive
 *        feerate is ACCEPTED. This is the SF-CHEAT-DUST-RACE bypass: an
 *        attacker LSP turns off the defense and the strand-the-sweep theft
 *        becomes possible. Used by tools/test_regtest_cheat_dust_race.sh.
 *
 *   DR4: With SS_CHEAT_DUST_RACE=0 (explicit disable), the defense fires
 *        normally — proves the env var is opt-in, not opt-out.
 *
 *   DR5: Boundary — exactly at htlc_safe_floor (sweep_fee + dust) is
 *        accepted by the defense (the check is strict <, not <=).
 *
 *   DR6: Cheat bypass DOES NOT mask the basic floor/ceiling checks — a
 *        below-floor feerate is still rejected even with cheat armed.
 *
 *   DR7: With cheat armed, a feerate that is safe for one HTLC but unsafe
 *        for a second smaller HTLC still updates ch->fee_rate_sat_per_kvb
 *        (verifying that the cheat applies per-HTLC and reaches the final
 *        commit-assignment).
 *
 * These tests do NOT exercise on-chain TX construction — that path is
 * covered by the regtest script. They exercise the wire-level decision
 * point where the cheat is wired.
 */

#include "superscalar/htlc_commit.h"
#include "superscalar/channel.h"
#include "superscalar/crash_inject.h"   /* #9 cheat-gate: cheats are inert unless armed */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, (msg)); \
        return 0; \
    } \
} while (0)

/* Local big-endian write helpers (avoid name collision with test_htlc_commit). */
static void dr_wr16(unsigned char *b, uint16_t v) {
    b[0] = (unsigned char)(v >> 8); b[1] = (unsigned char)v;
}
static void dr_wr32(unsigned char *b, uint32_t v) {
    b[0] = (unsigned char)(v >> 24); b[1] = (unsigned char)(v >> 16);
    b[2] = (unsigned char)(v >> 8);  b[3] = (unsigned char)v;
}

static void dr_build_update_fee(unsigned char msg[38], uint32_t feerate) {
    memset(msg, 0, 38);
    dr_wr16(msg, BOLT2_UPDATE_FEE);
    dr_wr32(msg + 34, feerate);
}

/* ------------------------------------------------------------------ */
/* Borderline HTLC fixture                                             */
/* ------------------------------------------------------------------ */
/*
 * Pick an HTLC amount that is safely above dust at the channel's starting
 * 1000 sat/kvb but stranded at BOLT2_UPDATE_FEE_CEILING.
 *
 * htlc_sweep_fee at 1000 sat/kvb     = (1000*180+999)/1000 = 180
 * htlc_safe_floor at 1000 sat/kvb    = 180 + 546 = 726
 * htlc_sweep_fee at ceiling (4*ceiling) = ((BOLT2_UPDATE_FEE_CEILING*4)*180+999)/1000
 * htlc_safe_floor at ceiling         = sweep_fee + 546
 *
 * We pick amount = 5000 sat: well above 726 (safe at 1000 sat/kvb), well
 * below htlc_safe_floor at ceiling (which approaches 72546 for the test's
 * BOLT2_UPDATE_FEE_CEILING). This mirrors HC16 in test_htlc_commit.c.
 */
#define BORDERLINE_HTLC_AMOUNT 5000ULL

/* ------------------------------------------------------------------ */
/* DR1 — honest defense rejects abusive HTLC feerate                   */
/* ------------------------------------------------------------------ */
int test_dust_race_defense_rejects_htlc(void) {
    /* Make sure cheat is OFF for this test, regardless of process env. */
    unsetenv("SS_CHEAT_DUST_RACE");

    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.fee_rate_sat_per_kvb = 1000;

    htlc_t htlcs[1];
    memset(htlcs, 0, sizeof(htlcs));
    htlcs[0].state = HTLC_STATE_ACTIVE;
    htlcs[0].direction = HTLC_OFFERED;
    htlcs[0].amount_sats = BORDERLINE_HTLC_AMOUNT;
    ch.htlcs = htlcs;
    ch.n_htlcs = 1;

    unsigned char msg[38];
    dr_build_update_fee(msg, BOLT2_UPDATE_FEE_CEILING);

    int ok = htlc_commit_recv_update_fee(&ch, msg, sizeof(msg),
                                          BOLT2_UPDATE_FEE_FLOOR,
                                          BOLT2_UPDATE_FEE_CEILING);
    ASSERT(ok == 0, "DR1: defense rejects abusive feerate against borderline HTLC");
    ASSERT(ch.fee_rate_sat_per_kvb == 1000,
           "DR1: fee_rate unchanged after rejection");
    return 1;
}

/* ------------------------------------------------------------------ */
/* DR2 — honest defense rejects abusive PTLC feerate                   */
/* ------------------------------------------------------------------ */
int test_dust_race_defense_rejects_ptlc(void) {
    unsetenv("SS_CHEAT_DUST_RACE");

    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.fee_rate_sat_per_kvb = 1000;

    ptlc_t ptlcs[1];
    memset(ptlcs, 0, sizeof(ptlcs));
    ptlcs[0].state = PTLC_STATE_ACTIVE;
    ptlcs[0].direction = PTLC_OFFERED;
    ptlcs[0].amount_sats = BORDERLINE_HTLC_AMOUNT;
    ch.ptlcs = ptlcs;
    ch.n_ptlcs = 1;

    unsigned char msg[38];
    dr_build_update_fee(msg, BOLT2_UPDATE_FEE_CEILING);

    int ok = htlc_commit_recv_update_fee(&ch, msg, sizeof(msg),
                                          BOLT2_UPDATE_FEE_FLOOR,
                                          BOLT2_UPDATE_FEE_CEILING);
    ASSERT(ok == 0, "DR2: defense rejects abusive feerate against borderline PTLC");
    ASSERT(ch.fee_rate_sat_per_kvb == 1000,
           "DR2: fee_rate unchanged after PTLC rejection");
    return 1;
}

/* ------------------------------------------------------------------ */
/* DR3 — SS_CHEAT_DUST_RACE=1 ACCEPTS the otherwise-rejected feerate   */
/* ------------------------------------------------------------------ */
int test_dust_race_cheat_bypass(void) {
    /* #9: defense-bypass cheats require BOTH the env flag AND the regtest
       cheat-gate. This test exercises the cheat's bypass behavior, so it must
       arm the gate (as the regtest binary does); it is reset before return. */
    superscalar_set_cheat_gate(1);
    setenv("SS_CHEAT_DUST_RACE", "1", 1);

    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.fee_rate_sat_per_kvb = 1000;

    htlc_t htlcs[1];
    memset(htlcs, 0, sizeof(htlcs));
    htlcs[0].state = HTLC_STATE_ACTIVE;
    htlcs[0].direction = HTLC_OFFERED;
    htlcs[0].amount_sats = BORDERLINE_HTLC_AMOUNT;
    ch.htlcs = htlcs;
    ch.n_htlcs = 1;

    unsigned char msg[38];
    dr_build_update_fee(msg, BOLT2_UPDATE_FEE_CEILING);

    int ok = htlc_commit_recv_update_fee(&ch, msg, sizeof(msg),
                                          BOLT2_UPDATE_FEE_FLOOR,
                                          BOLT2_UPDATE_FEE_CEILING);
    ASSERT(ok == 1, "DR3: cheat ACCEPTS abusive feerate");
    ASSERT(ch.fee_rate_sat_per_kvb == (uint64_t)BOLT2_UPDATE_FEE_CEILING * 4,
           "DR3: fee_rate updated to attacker-chosen ceiling");

    unsetenv("SS_CHEAT_DUST_RACE");
    superscalar_set_cheat_gate(0);
    return 1;
}

/* ------------------------------------------------------------------ */
/* DR4 — SS_CHEAT_DUST_RACE=0 explicitly disabled → defense fires      */
/* ------------------------------------------------------------------ */
int test_dust_race_cheat_disabled_explicit(void) {
    setenv("SS_CHEAT_DUST_RACE", "0", 1);

    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.fee_rate_sat_per_kvb = 1000;

    htlc_t htlcs[1];
    memset(htlcs, 0, sizeof(htlcs));
    htlcs[0].state = HTLC_STATE_ACTIVE;
    htlcs[0].direction = HTLC_OFFERED;
    htlcs[0].amount_sats = BORDERLINE_HTLC_AMOUNT;
    ch.htlcs = htlcs;
    ch.n_htlcs = 1;

    unsigned char msg[38];
    dr_build_update_fee(msg, BOLT2_UPDATE_FEE_CEILING);

    int ok = htlc_commit_recv_update_fee(&ch, msg, sizeof(msg),
                                          BOLT2_UPDATE_FEE_FLOOR,
                                          BOLT2_UPDATE_FEE_CEILING);
    ASSERT(ok == 0, "DR4: explicit '0' is opt-out; defense still rejects");
    ASSERT(ch.fee_rate_sat_per_kvb == 1000, "DR4: fee_rate unchanged");

    unsetenv("SS_CHEAT_DUST_RACE");
    return 1;
}

/* ------------------------------------------------------------------ */
/* DR5 — boundary: amount == htlc_safe_floor is ACCEPTED               */
/* ------------------------------------------------------------------ */
int test_dust_race_boundary_accept(void) {
    unsetenv("SS_CHEAT_DUST_RACE");

    /* Compute exact htlc_safe_floor at the ceiling. */
    uint64_t kvb = (uint64_t)BOLT2_UPDATE_FEE_CEILING * 4;
    uint64_t sweep_fee = (kvb * 180 + 999) / 1000;
    uint64_t safe_floor = sweep_fee + CHANNEL_DUST_LIMIT_SATS;

    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.fee_rate_sat_per_kvb = 1000;

    htlc_t htlcs[1];
    memset(htlcs, 0, sizeof(htlcs));
    htlcs[0].state = HTLC_STATE_ACTIVE;
    htlcs[0].direction = HTLC_OFFERED;
    htlcs[0].amount_sats = safe_floor;  /* exactly at the boundary */
    ch.htlcs = htlcs;
    ch.n_htlcs = 1;

    unsigned char msg[38];
    dr_build_update_fee(msg, BOLT2_UPDATE_FEE_CEILING);

    int ok = htlc_commit_recv_update_fee(&ch, msg, sizeof(msg),
                                          BOLT2_UPDATE_FEE_FLOOR,
                                          BOLT2_UPDATE_FEE_CEILING);
    ASSERT(ok == 1, "DR5: HTLC exactly at safe_floor is accepted (strict < check)");
    ASSERT(ch.fee_rate_sat_per_kvb == kvb,
           "DR5: fee_rate updated when exactly at boundary");

    /* One sat below the boundary is rejected. */
    ch.fee_rate_sat_per_kvb = 1000;
    htlcs[0].amount_sats = safe_floor - 1;
    ok = htlc_commit_recv_update_fee(&ch, msg, sizeof(msg),
                                      BOLT2_UPDATE_FEE_FLOOR,
                                      BOLT2_UPDATE_FEE_CEILING);
    ASSERT(ok == 0, "DR5: one sat below safe_floor is rejected");
    ASSERT(ch.fee_rate_sat_per_kvb == 1000, "DR5: fee_rate unchanged on reject");
    return 1;
}

/* ------------------------------------------------------------------ */
/* DR6 — cheat does NOT bypass floor/ceiling checks                    */
/* ------------------------------------------------------------------ */
int test_dust_race_cheat_does_not_bypass_floor(void) {
    /* #9: arm the cheat-gate so the cheat is genuinely active — proving the
       floor/ceiling bounds hold EVEN against an armed cheat (not trivially
       because the cheat was inert). */
    superscalar_set_cheat_gate(1);
    setenv("SS_CHEAT_DUST_RACE", "1", 1);

    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.fee_rate_sat_per_kvb = 1000;

    htlc_t htlcs[1];
    memset(htlcs, 0, sizeof(htlcs));
    htlcs[0].state = HTLC_STATE_ACTIVE;
    htlcs[0].direction = HTLC_OFFERED;
    htlcs[0].amount_sats = BORDERLINE_HTLC_AMOUNT;
    ch.htlcs = htlcs;
    ch.n_htlcs = 1;

    /* Build a below-floor feerate. */
    uint32_t below_floor = (BOLT2_UPDATE_FEE_FLOOR > 0)
                           ? (BOLT2_UPDATE_FEE_FLOOR - 1) : 0;
    unsigned char msg[38];
    dr_build_update_fee(msg, below_floor);

    int ok = htlc_commit_recv_update_fee(&ch, msg, sizeof(msg),
                                          BOLT2_UPDATE_FEE_FLOOR,
                                          BOLT2_UPDATE_FEE_CEILING);
    ASSERT(ok == 0, "DR6: cheat does not bypass below-floor feerate rejection");
    ASSERT(ch.fee_rate_sat_per_kvb == 1000, "DR6: fee_rate unchanged");

    /* Above-ceiling should also be rejected with cheat armed. */
    dr_build_update_fee(msg, BOLT2_UPDATE_FEE_CEILING + 1);
    ok = htlc_commit_recv_update_fee(&ch, msg, sizeof(msg),
                                      BOLT2_UPDATE_FEE_FLOOR,
                                      BOLT2_UPDATE_FEE_CEILING);
    ASSERT(ok == 0, "DR6: cheat does not bypass above-ceiling rejection");
    ASSERT(ch.fee_rate_sat_per_kvb == 1000, "DR6: fee_rate unchanged");

    unsetenv("SS_CHEAT_DUST_RACE");
    superscalar_set_cheat_gate(0);
    return 1;
}

/* ------------------------------------------------------------------ */
/* DR7 — cheat applies per-HTLC and still updates ch->fee_rate          */
/* ------------------------------------------------------------------ */
int test_dust_race_cheat_per_htlc(void) {
    /* #9: arm the regtest cheat-gate so the bypass behavior is reachable. */
    superscalar_set_cheat_gate(1);
    setenv("SS_CHEAT_DUST_RACE", "1", 1);

    channel_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.fee_rate_sat_per_kvb = 1000;

    /* Two HTLCs: one large (safe at ceiling), one small (would normally be
       rejected). With cheat armed, both pass and ch->fee_rate updates. */
    htlc_t htlcs[2];
    memset(htlcs, 0, sizeof(htlcs));
    htlcs[0].state = HTLC_STATE_ACTIVE;
    htlcs[0].direction = HTLC_OFFERED;
    htlcs[0].amount_sats = 500000;  /* safely above any reachable sweep_fee */
    htlcs[1].state = HTLC_STATE_ACTIVE;
    htlcs[1].direction = HTLC_RECEIVED;
    htlcs[1].amount_sats = BORDERLINE_HTLC_AMOUNT;  /* would be stranded */
    ch.htlcs = htlcs;
    ch.n_htlcs = 2;

    unsigned char msg[38];
    dr_build_update_fee(msg, BOLT2_UPDATE_FEE_CEILING);

    int ok = htlc_commit_recv_update_fee(&ch, msg, sizeof(msg),
                                          BOLT2_UPDATE_FEE_FLOOR,
                                          BOLT2_UPDATE_FEE_CEILING);
    ASSERT(ok == 1, "DR7: cheat accepts even with one borderline + one safe HTLC");
    ASSERT(ch.fee_rate_sat_per_kvb == (uint64_t)BOLT2_UPDATE_FEE_CEILING * 4,
           "DR7: fee_rate updated to attacker-chosen ceiling");

    unsetenv("SS_CHEAT_DUST_RACE");
    superscalar_set_cheat_gate(0);
    return 1;
}
